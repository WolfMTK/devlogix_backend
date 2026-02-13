use crate::application::{
    app_error::{AppError, AppResult},
    dto::email_confirmation::ConfirmEmailDTO,
    interface::{
        db::DBSession,
        gateway::{
            email_confirmation::{
                EmailConfirmationReader, EmailConfirmationWriter,
            },
            user::{UserReader, UserWriter}
        }
    }
};
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Clone)]
pub struct ConfirmEmailInteractor {
    db_session: Arc<dyn DBSession>,
    email_confirmation_reader: Arc<dyn EmailConfirmationReader>,
    email_confirmation_writer: Arc<dyn EmailConfirmationWriter>,
    user_reader: Arc<dyn UserReader>,
    user_writer: Arc<dyn UserWriter>,
}

impl ConfirmEmailInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        email_confirmation_reader: Arc<dyn EmailConfirmationReader>,
        email_confirmation_writer: Arc<dyn EmailConfirmationWriter>,
        user_reader: Arc<dyn UserReader>,
        user_writer: Arc<dyn UserWriter>,
    ) -> Self {
        Self {
            db_session,
            email_confirmation_reader,
            email_confirmation_writer,
            user_reader,
            user_writer,
        }
    }

    pub async fn execute(&self, dto: ConfirmEmailDTO) -> AppResult<()> {
        let confirmation = self
            .email_confirmation_reader
            .find_by_token(&dto.token)
            .await?
            .ok_or_else(|| {
                warn!("Confirmation attempt with invalid token");
                AppError::InvalidConfirmationToken
            })?;
        if confirmation.is_confirmed() {
            return Err(AppError::EmailAlreadyConfirmed);
        }
        if confirmation.is_expired() {
            return Err(AppError::ConfirmationTokenExpired);
        }
        let mut user = self
            .user_reader
            .find_by_id(&confirmation.user_id)
            .await?
            .ok_or_else(|| {
                warn!("User not found for confirmation token");
                AppError::InvalidConfirmationToken
            })?;
        user.is_confirmed = true;
        self.email_confirmation_writer
            .confirm(&confirmation.id)
            .await?;
        self.user_writer.update(user).await?;
        self.db_session.commit().await?;
        info!("Email confirmed for user {}", confirmation.user_id.value);
        Ok(())
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

    // ConfirmEmailInteractor tests
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
