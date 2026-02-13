use crate::{
    application::{
        app_error::AppResult,
        dto::session::{GetSessionStatusDTO, SessionDTO, SessionValidationResult},
        interface::{
            db::DBSession,
            gateway::session::{SessionReader, SessionWriter},
        },
    },
    domain::entities::{id::Id, session::Session},
};
use chrono::{Duration, Utc};
use std::sync::Arc;

#[derive(Debug, Clone)]
struct SessionTimeouts {
    pub default_max_lifetime: i64,
    pub default_idle_timeout: i64,
    pub remembered_max_lifetime: i64,
    pub remembered_idle_timeout: i64,
}

#[derive(Clone)]
pub struct ValidateSessionInteractor {
    db_session: Arc<dyn DBSession>,
    session_reader: Arc<dyn SessionReader>,
    session_writer: Arc<dyn SessionWriter>,
}

impl ValidateSessionInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        session_reader: Arc<dyn SessionReader>,
        session_writer: Arc<dyn SessionWriter>,
    ) -> Self {
        Self {
            db_session,
            session_reader,
            session_writer,
        }
    }

    fn get_timeouts(timeouts: SessionTimeouts, remember_me: bool) -> (Duration, Duration) {
        if remember_me {
            return (
                Duration::seconds(timeouts.remembered_max_lifetime),
                Duration::seconds(timeouts.remembered_idle_timeout),
            );
        }
        return (
            Duration::seconds(timeouts.default_max_lifetime),
            Duration::seconds(timeouts.default_idle_timeout),
        );
    }

    pub async fn execute(&self, dto: SessionDTO) -> AppResult<GetSessionStatusDTO> {
        let session_id: Id<Session> = dto.id.try_into()?;
        let session = match self.session_reader.find_by_id(&session_id).await? {
            Some(s) => s,
            None => {
                return Ok(GetSessionStatusDTO {
                    status: SessionValidationResult::Invalid,
                });
            }
        };
        let now = Utc::now();
        let timeouts = SessionTimeouts {
            default_max_lifetime: dto.default_max_lifetime,
            default_idle_timeout: dto.default_idle_timeout,
            remembered_max_lifetime: dto.remembered_max_lifetime,
            remembered_idle_timeout: dto.remembered_idle_timeout,
        };
        let (max_lifetime, idle_timeout) = Self::get_timeouts(timeouts, session.remember_me);

        if now - session.created_at > max_lifetime {
            self.session_writer.delete(&session_id).await?;
            self.db_session.commit().await?;
            return Ok(GetSessionStatusDTO {
                status: SessionValidationResult::Expired,
            });
        }

        if now - session.last_activity > idle_timeout {
            self.session_writer.delete(&session_id).await?;
            self.db_session.commit().await?;
            return Ok(GetSessionStatusDTO {
                status: SessionValidationResult::Expired,
            });
        }

        let rotation_interval = Duration::seconds(dto.rotation_interval);
        let needs_rotation = now - session.last_rotation > rotation_interval;
        if needs_rotation {
            let new_session = Session {
                id: Id::generate(),
                user_id: session.user_id.clone(),
                created_at: session.created_at,
                last_activity: now,
                last_rotation: now,
                remember_me: session.remember_me,
            };
            let new_session_id = self.session_writer.rotate(&session_id, new_session).await?;
            self.db_session.commit().await?;
            return Ok(GetSessionStatusDTO {
                status: SessionValidationResult::Rotated {
                    user_id: session.user_id,
                    new_session_id,
                },
            });
        }
        self.session_writer
            .update_activity(&session_id, now)
            .await?;
        self.db_session.commit().await?;
        Ok(GetSessionStatusDTO {
            status: SessionValidationResult::Valid(session.user_id),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        application::{
            app_error::{AppError, AppResult},
            dto::session::{SessionDTO, SessionValidationResult},
            interactors::session::ValidateSessionInteractor,
            interface::{
                db::DBSession,
                gateway::session::{SessionReader, SessionWriter},
            },
        },
        domain::entities::{id::Id, session::Session, user::User},
    };
    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use mockall::mock;
    use rstest::{fixture, rstest};
    use std::sync::Arc;

    // Mocks
    mock! {
        pub DBSessionMock {}

        #[async_trait]
        impl DBSession for DBSessionMock {
            async fn commit(&self) -> AppResult<()>;
        }
    }

    mock! {
        pub SessionReaderMock {}

        #[async_trait]
        impl SessionReader for SessionReaderMock {
            async fn find_by_id(&self, session_id: &Id<Session>) -> AppResult<Option<Session>>;
        }
    }

    mock! {
        pub SessionWriterMock {}

        #[async_trait]
        impl SessionWriter for SessionWriterMock {
            async fn insert(&self, session: Session) -> AppResult<Id<Session>>;
            async fn update_activity(&self, session_id: &Id<Session>, now: chrono::DateTime<Utc>) -> AppResult<()>;
            async fn rotate(&self, old_session_id: &Id<Session>, new_session: Session) -> AppResult<Id<Session>>;
            async fn delete(&self, session_id: &Id<Session>) -> AppResult<()>;
            async fn delete_by_user_id(&self, user_id: &Id<User>) -> AppResult<()>;
        }
    }

    // Constants
    const USER_ID: &str = "019c47ec-183d-744e-b11d-cd409015bf13";
    const SESSION_ID: &str = "019c47ec-2160-7e53-bf7e-06db2a1bad85";
    const NEW_SESSION_ID: &str = "019c47ec-29d3-72c4-ba24-a32534f95a71";

    // Fixtures
    #[fixture]
    fn session_dto() -> SessionDTO {
        SessionDTO {
            id: SESSION_ID.to_string(),
            default_max_lifetime: 60,
            default_idle_timeout: 30,
            remembered_max_lifetime: 120,
            remembered_idle_timeout: 90,
            rotation_interval: 20,
        }
    }

    fn active_session(remember_me: bool) -> Session {
        let now = Utc::now();
        Session {
            id: SESSION_ID.to_string().try_into().unwrap(),
            user_id: USER_ID.to_string().try_into().unwrap(),
            created_at: now - Duration::seconds(10),
            last_activity: now - Duration::seconds(5),
            last_rotation: now - Duration::seconds(5),
            remember_me,
        }
    }

    // ValidateSessionInteractor tests
    #[rstest]
    #[tokio::test]
    async fn test_validate_session_invalid_when_not_found(session_dto: SessionDTO) {
        let db_session = MockDBSessionMock::new();
        let mut session_reader = MockSessionReaderMock::new();
        let session_writer = MockSessionWriterMock::new();

        session_reader.expect_find_by_id().returning(|_| Ok(None));

        let interactor = ValidateSessionInteractor::new(
            Arc::new(db_session),
            Arc::new(session_reader),
            Arc::new(session_writer),
        );

        let result = interactor.execute(session_dto).await.unwrap();
        assert!(matches!(result.status, SessionValidationResult::Invalid));
    }

    #[rstest]
    #[tokio::test]
    async fn test_validate_session_valid_updates_activity(session_dto: SessionDTO) {
        let mut db_session = MockDBSessionMock::new();
        let mut session_reader = MockSessionReaderMock::new();
        let mut session_writer = MockSessionWriterMock::new();

        let session = active_session(false);
        let expected_user_id = session.user_id.clone();
        session_reader
            .expect_find_by_id()
            .returning(move |_| Ok(Some(session.clone())));
        session_writer
            .expect_update_activity()
            .returning(|_, _| Ok(()));
        db_session.expect_commit().returning(|| Ok(()));

        let interactor = ValidateSessionInteractor::new(
            Arc::new(db_session),
            Arc::new(session_reader),
            Arc::new(session_writer),
        );

        let result = interactor.execute(session_dto).await.unwrap();
        match result.status {
            SessionValidationResult::Valid(user_id) => {
                assert_eq!(user_id.value, expected_user_id.value)
            }
            _ => panic!("expected valid status"),
        }
    }

    #[rstest]
    #[tokio::test]
    async fn test_validate_session_expired_by_max_lifetime(mut session_dto: SessionDTO) {
        let mut db_session = MockDBSessionMock::new();
        let mut session_reader = MockSessionReaderMock::new();
        let mut session_writer = MockSessionWriterMock::new();

        let mut session = active_session(false);
        session.created_at = Utc::now() - Duration::seconds(120);
        session_dto.default_max_lifetime = 60;
        session_reader
            .expect_find_by_id()
            .returning(move |_| Ok(Some(session.clone())));
        session_writer.expect_delete().returning(|_| Ok(()));
        db_session.expect_commit().returning(|| Ok(()));

        let interactor = ValidateSessionInteractor::new(
            Arc::new(db_session),
            Arc::new(session_reader),
            Arc::new(session_writer),
        );

        let result = interactor.execute(session_dto).await.unwrap();
        assert!(matches!(result.status, SessionValidationResult::Expired));
    }

    #[rstest]
    #[tokio::test]
    async fn test_validate_session_rotates(mut session_dto: SessionDTO) {
        let mut db_session = MockDBSessionMock::new();
        let mut session_reader = MockSessionReaderMock::new();
        let mut session_writer = MockSessionWriterMock::new();

        let mut session = active_session(false);
        session.last_rotation = Utc::now() - Duration::seconds(40);
        session_dto.rotation_interval = 20;
        let expected_user_id = session.user_id.clone();

        session_reader
            .expect_find_by_id()
            .returning(move |_| Ok(Some(session.clone())));
        session_writer
            .expect_rotate()
            .returning(|_, _| Ok(NEW_SESSION_ID.to_string().try_into().unwrap()));
        db_session.expect_commit().returning(|| Ok(()));

        let interactor = ValidateSessionInteractor::new(
            Arc::new(db_session),
            Arc::new(session_reader),
            Arc::new(session_writer),
        );

        let result = interactor.execute(session_dto).await.unwrap();
        match result.status {
            SessionValidationResult::Rotated {
                user_id,
                new_session_id,
            } => {
                assert_eq!(user_id.value, expected_user_id.value);
                assert_eq!(new_session_id.value.to_string(), NEW_SESSION_ID);
            }
            _ => panic!("expected rotated status"),
        }
    }

    #[rstest]
    #[tokio::test]
    async fn test_validate_session_invalid_id() {
        let db_session = MockDBSessionMock::new();
        let session_reader = MockSessionReaderMock::new();
        let session_writer = MockSessionWriterMock::new();
        let dto = SessionDTO {
            id: "invalid-id".to_string(),
            default_max_lifetime: 60,
            default_idle_timeout: 30,
            remembered_max_lifetime: 120,
            remembered_idle_timeout: 90,
            rotation_interval: 20,
        };

        let interactor = ValidateSessionInteractor::new(
            Arc::new(db_session),
            Arc::new(session_reader),
            Arc::new(session_writer),
        );

        let result = interactor.execute(dto).await;
        assert!(matches!(result.unwrap_err(), AppError::InvalidId(_)));
    }
}
