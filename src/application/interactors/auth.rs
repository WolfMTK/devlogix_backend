use std::sync::Arc;

use chrono::Utc;
use tracing::{info, warn};

use crate::application::app_error::{AppError, AppResult};
use crate::application::dto::auth::{GetSessionIdDTO, LoginDTO};
use crate::application::dto::id::IdDTO;
use crate::application::interface::crypto::CredentialsHasher;
use crate::application::interface::db::DBSession;
use crate::application::interface::gateway::session::SessionWriter;
use crate::application::interface::gateway::user::UserReader;
use crate::domain::entities::id::Id;
use crate::domain::entities::session::Session;
use crate::domain::entities::user::User;

#[derive(Clone)]
pub struct LoginInteractor {
    db_session: Arc<dyn DBSession>,
    user_reader: Arc<dyn UserReader>,
    session_writer: Arc<dyn SessionWriter>,
    hasher: Arc<dyn CredentialsHasher>,
}

impl LoginInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        user_reader: Arc<dyn UserReader>,
        session_writer: Arc<dyn SessionWriter>,
        hasher: Arc<dyn CredentialsHasher>,
    ) -> Self {
        Self {
            db_session,
            user_reader,
            session_writer,
            hasher,
        }
    }

    pub async fn execute(&self, dto: LoginDTO) -> AppResult<GetSessionIdDTO> {
        let user = self.user_reader.find_by_email(&dto.email).await?.ok_or_else(|| {
            warn!("Login attempt with non-existent email: {}", dto.email);
            AppError::InvalidCredentials
        })?;
        let is_valid = self.hasher.verify_password(&dto.password, &user.password).await?;
        if !is_valid {
            warn!("Invalid password for user: {}", user.username);
            return Err(AppError::InvalidCredentials);
        }
        if !user.is_confirmed {
            return Err(AppError::EmailNotConfirmed);
        }
        let now = Utc::now();
        let session = Session {
            id: Id::generate(),
            user_id: user.id.clone(),
            created_at: now,
            last_activity: now,
            last_rotation: now,
            remember_me: dto.remember_me,
        };
        let session_id = self.session_writer.insert(session).await?;
        self.db_session.commit().await?;
        info!("User {} logged in successfully", user.username);
        Ok(GetSessionIdDTO {
            session_id: session_id.value.to_string(),
            remember_me: dto.remember_me,
        })
    }
}

#[derive(Clone)]
pub struct LogoutInteractor {
    db_session: Arc<dyn DBSession>,
    session_writer: Arc<dyn SessionWriter>,
}

impl LogoutInteractor {
    pub fn new(db_session: Arc<dyn DBSession>, session_writer: Arc<dyn SessionWriter>) -> Self {
        Self {
            db_session,
            session_writer,
        }
    }

    pub async fn execute(&self, user_id: IdDTO) -> AppResult<()> {
        let user_id: Id<User> = user_id.id.try_into()?;
        self.session_writer.delete_by_user_id(&user_id).await?;
        self.db_session.commit().await?;
        info!("User {} logged out", user_id.value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use chrono::Utc;
    use mockall::mock;
    use rstest::{fixture, rstest};

    use crate::application::app_error::{AppError, AppResult};
    use crate::application::dto::auth::LoginDTO;
    use crate::application::dto::id::IdDTO;
    use crate::application::interactors::auth::{LoginInteractor, LogoutInteractor};
    use crate::application::interface::crypto::CredentialsHasher;
    use crate::application::interface::db::DBSession;
    use crate::application::interface::gateway::session::SessionWriter;
    use crate::application::interface::gateway::user::UserReader;
    use crate::domain::entities::id::Id;
    use crate::domain::entities::session::Session;
    use crate::domain::entities::user::User;

    // Mocks
    mock! {
        pub DBSessionMock {}

        #[async_trait]
        impl DBSession for DBSessionMock {
            async fn commit(&self) -> AppResult<()>;
        }
    }

    type BoxFn<A, R> = Box<dyn Fn(A) -> R + Send + Sync>;

    struct MockUserReader {
        find_by_email_fn: Option<BoxFn<String, AppResult<Option<User>>>>,
    }

    impl MockUserReader {
        fn new() -> Self {
            Self { find_by_email_fn: None }
        }

        fn expect_find_by_email(&mut self, f: impl Fn(&str) -> AppResult<Option<User>> + Send + Sync + 'static) {
            self.find_by_email_fn = Some(Box::new(move |e| f(&e)));
        }
    }

    #[async_trait]
    impl UserReader for MockUserReader {
        async fn find_by_email(&self, email: &str) -> AppResult<Option<User>> {
            (self.find_by_email_fn.as_ref().expect("find_by_email not mocked"))(email.to_string())
        }

        async fn is_user(&self, _username: &str, _email: &str) -> AppResult<bool> {
            Ok(false)
        }

        async fn find_by_id(&self, _user_id: &Id<User>) -> AppResult<Option<User>> {
            Ok(None)
        }

        async fn is_username_or_email_unique(
            &self,
            _user_id: &Id<User>,
            _username: Option<&str>,
            _email: Option<&str>,
        ) -> AppResult<bool> {
            Ok(false)
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

    mock! {
        pub HasherMock {}

        #[async_trait]
        impl CredentialsHasher for HasherMock {
            async fn hash_password(&self, password: &str) -> AppResult<String>;
            async fn verify_password(&self, password: &str, hashed: &str) -> AppResult<bool>;
        }
    }

    // Constants
    const USER_ID: &str = "019c47ec-183d-744e-b11d-cd409015bf13";
    const SESSION_ID: &str = "019c47ec-2160-7e53-bf7e-06db2a1bad85";
    const EMAIL: &str = "john@example.com";
    const PASSWORD: &str = "Password123!";
    const HASH: &str = "$argon2id$v=19$m=16384,t=2,p=1$testsalt$testhash";

    // Fixtures
    #[fixture]
    fn valid_login_dto() -> LoginDTO {
        LoginDTO {
            email: EMAIL.to_string(),
            password: PASSWORD.to_string(),
            remember_me: true,
        }
    }

    fn build_user(is_confirmed: bool) -> User {
        let mut user = User::new("john".to_string(), EMAIL.to_string(), HASH.to_string());
        user.id = USER_ID.to_string().try_into().unwrap();
        user.is_confirmed = is_confirmed;
        user
    }

    // LoginInteractor tests
    #[rstest]
    #[tokio::test]
    async fn test_login_success(valid_login_dto: LoginDTO) {
        let mut db_session = MockDBSessionMock::new();
        let mut user_reader = MockUserReader::new();
        let mut session_writer = MockSessionWriterMock::new();
        let mut hasher = MockHasherMock::new();

        user_reader.expect_find_by_email(|_| Ok(Some(build_user(true))));
        hasher.expect_verify_password().returning(|_, _| Ok(true));
        session_writer
            .expect_insert()
            .returning(|_| Ok(SESSION_ID.to_string().try_into().unwrap()));
        db_session.expect_commit().returning(|| Ok(()));

        let interactor = LoginInteractor::new(
            Arc::new(db_session),
            Arc::new(user_reader),
            Arc::new(session_writer),
            Arc::new(hasher),
        );

        let result = interactor.execute(valid_login_dto).await;

        assert!(result.is_ok());
        let dto = result.unwrap();
        assert_eq!(dto.session_id, SESSION_ID);
        assert!(dto.remember_me);
    }

    #[rstest]
    #[tokio::test]
    async fn test_login_user_not_found(valid_login_dto: LoginDTO) {
        let db_session = MockDBSessionMock::new();
        let mut user_reader = MockUserReader::new();
        let session_writer = MockSessionWriterMock::new();
        let hasher = MockHasherMock::new();

        user_reader.expect_find_by_email(|_| Ok(None));

        let interactor = LoginInteractor::new(
            Arc::new(db_session),
            Arc::new(user_reader),
            Arc::new(session_writer),
            Arc::new(hasher),
        );

        let result = interactor.execute(valid_login_dto).await;
        assert!(matches!(result.unwrap_err(), AppError::InvalidCredentials));
    }

    #[rstest]
    #[tokio::test]
    async fn test_login_invalid_password(valid_login_dto: LoginDTO) {
        let db_session = MockDBSessionMock::new();
        let mut user_reader = MockUserReader::new();
        let session_writer = MockSessionWriterMock::new();
        let mut hasher = MockHasherMock::new();

        user_reader.expect_find_by_email(|_| Ok(Some(build_user(true))));
        hasher.expect_verify_password().returning(|_, _| Ok(false));

        let interactor = LoginInteractor::new(
            Arc::new(db_session),
            Arc::new(user_reader),
            Arc::new(session_writer),
            Arc::new(hasher),
        );

        let result = interactor.execute(valid_login_dto).await;
        assert!(matches!(result.unwrap_err(), AppError::InvalidCredentials));
    }

    #[rstest]
    #[tokio::test]
    async fn test_login_email_not_confirmed(valid_login_dto: LoginDTO) {
        let db_session = MockDBSessionMock::new();
        let mut user_reader = MockUserReader::new();
        let session_writer = MockSessionWriterMock::new();
        let mut hasher = MockHasherMock::new();

        user_reader.expect_find_by_email(|_| Ok(Some(build_user(false))));
        hasher.expect_verify_password().returning(|_, _| Ok(true));

        let interactor = LoginInteractor::new(
            Arc::new(db_session),
            Arc::new(user_reader),
            Arc::new(session_writer),
            Arc::new(hasher),
        );

        let result = interactor.execute(valid_login_dto).await;
        assert!(matches!(result.unwrap_err(), AppError::EmailNotConfirmed));
    }

    // LogoutInteractor tests
    #[rstest]
    #[tokio::test]
    async fn test_logout_success() {
        let mut db_session = MockDBSessionMock::new();
        let mut session_writer = MockSessionWriterMock::new();
        let user_id = IdDTO {
            id: USER_ID.to_string(),
        };

        session_writer.expect_delete_by_user_id().returning(|_| Ok(()));
        db_session.expect_commit().returning(|| Ok(()));

        let interactor = LogoutInteractor::new(Arc::new(db_session), Arc::new(session_writer));
        let result = interactor.execute(user_id).await;

        assert!(result.is_ok());
    }

    #[rstest]
    #[tokio::test]
    async fn test_logout_invalid_id() {
        let db_session = MockDBSessionMock::new();
        let session_writer = MockSessionWriterMock::new();
        let user_id = IdDTO { id: "uuid".to_string() };

        let interactor = LogoutInteractor::new(Arc::new(db_session), Arc::new(session_writer));
        let result = interactor.execute(user_id).await;

        assert!(matches!(result.unwrap_err(), AppError::InvalidId(_)));
    }
}
