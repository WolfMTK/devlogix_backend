use std::sync::Arc;

use tracing::{error, info, warn};
use uuid::Uuid;

use crate::application::app_error::{AppError, AppResult};
use crate::application::dto::password_reset::{RequestPasswordResetDTO, ResetPasswordDTO};
use crate::application::interface::crypto::CredentialsHasher;
use crate::application::interface::db::DBSession;
use crate::application::interface::email::EmailSender;
use crate::application::interface::gateway::password_reset::{PasswordResetTokenReader, PasswordResetTokenWriter};
use crate::application::interface::gateway::user::{UserReader, UserWriter};
use crate::domain::entities::password_reset::PasswordResetToken;

#[derive(Clone)]
pub struct RequestPasswordResetInteractor {
    db_session: Arc<dyn DBSession>,
    password_reset_writer: Arc<dyn PasswordResetTokenWriter>,
    user_reader: Arc<dyn UserReader>,
    email_sender: Arc<dyn EmailSender>,
}

impl RequestPasswordResetInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        password_reset_writer: Arc<dyn PasswordResetTokenWriter>,
        user_reader: Arc<dyn UserReader>,
        email_sender: Arc<dyn EmailSender>,
    ) -> Self {
        Self {
            db_session,
            password_reset_writer,
            user_reader,
            email_sender,
        }
    }

    pub async fn execute(&self, dto: RequestPasswordResetDTO) -> AppResult<()> {
        let user = match self.user_reader.find_by_email(&dto.email).await? {
            Some(user) => user,
            None => {
                warn!("Password reset requested for non-existent email: {}", dto.email);
                return Ok(());
            }
        };
        self.password_reset_writer.delete(&user.id).await?;

        let token = Uuid::now_v7();
        let reset_token = PasswordResetToken::new(user.id, token.to_string(), dto.ttl);
        self.password_reset_writer.insert(reset_token).await?;
        self.db_session.commit().await?;

        let reset_link = format!("{}?token={}", dto.reset_url, token);
        let email_sender = Arc::clone(&self.email_sender);
        let user_email = user.email.clone();

        tokio::spawn(async move {
            let subject = "Восстановление пароля";
            let body = format!("Для сброса пароля перейдите по ссылке: {}", reset_link);
            info!("Sending password reset email to {}", user_email);
            if let Err(err) = email_sender.send(&user_email, subject, &body).await {
                error!("Failed to send password reset email to {}: {}", user_email, err);
                return;
            }
            info!("Password reset email sent to {}", user_email);
        });

        Ok(())
    }
}

#[derive(Clone)]
pub struct ResetPasswordInteractor {
    db_session: Arc<dyn DBSession>,
    password_reset_reader: Arc<dyn PasswordResetTokenReader>,
    password_reset_writer: Arc<dyn PasswordResetTokenWriter>,
    user_reader: Arc<dyn UserReader>,
    user_writer: Arc<dyn UserWriter>,
    hasher: Arc<dyn CredentialsHasher>,
}

impl ResetPasswordInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        password_reset_reader: Arc<dyn PasswordResetTokenReader>,
        password_reset_writer: Arc<dyn PasswordResetTokenWriter>,
        user_reader: Arc<dyn UserReader>,
        user_writer: Arc<dyn UserWriter>,
        hasher: Arc<dyn CredentialsHasher>,
    ) -> Self {
        Self {
            db_session,
            password_reset_reader,
            password_reset_writer,
            user_reader,
            user_writer,
            hasher,
        }
    }

    pub async fn execute(&self, dto: ResetPasswordDTO) -> AppResult<()> {
        let reset_token = self
            .password_reset_reader
            .find_by_token(&dto.token)
            .await?
            .ok_or_else(|| {
                warn!("Password reset attempt with invalid token");
                AppError::InvalidResetToken
            })?;

        if reset_token.is_used() {
            return Err(AppError::ResetTokenAlreadyUsed);
        }

        if reset_token.is_expired() {
            return Err(AppError::ResetTokenExpired);
        }

        let mut user = self
            .user_reader
            .find_by_id(&reset_token.user_id)
            .await?
            .ok_or_else(|| {
                warn!("User not found for password reset token");
                AppError::InvalidResetToken
            })?;

        let hash = self.hasher.hash_password(&dto.password).await?;
        user.password = hash;

        self.password_reset_writer.mark_as_used(&reset_token.id).await?;
        self.user_writer.update(user).await?;
        self.db_session.commit().await?;

        info!("Password reset successfully for user {}", reset_token.user_id.value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use chrono::Utc;
    use mockall::mock;
    use rstest::rstest;

    use crate::application::app_error::{AppError, AppResult};
    use crate::application::dto::password_reset::{RequestPasswordResetDTO, ResetPasswordDTO};
    use crate::application::interactors::password_reset::{RequestPasswordResetInteractor, ResetPasswordInteractor};
    use crate::application::interface::crypto::CredentialsHasher;
    use crate::application::interface::db::DBSession;
    use crate::application::interface::email::EmailSender;
    use crate::application::interface::gateway::password_reset::{PasswordResetTokenReader, PasswordResetTokenWriter};
    use crate::application::interface::gateway::user::{UserReader, UserWriter};
    use crate::domain::entities::id::Id;
    use crate::domain::entities::password_reset::PasswordResetToken;
    use crate::domain::entities::user::User;

    // Mocks
    mock! {
        pub DBSessionMock {}
        #[async_trait]
        impl DBSession for DBSessionMock {
            async fn commit(&self) -> AppResult<()>;
        }
    }

    mock! {
        pub PasswordResetTokenWriterMock {}
        #[async_trait]
        impl PasswordResetTokenWriter for PasswordResetTokenWriterMock {
            async fn insert(&self, token: PasswordResetToken) -> AppResult<Id<PasswordResetToken>>;
            async fn mark_as_used(&self, token_id: &Id<PasswordResetToken>) -> AppResult<()>;
            async fn delete(&self, user_id: &Id<User>) -> AppResult<()>;
        }
    }

    mock! {
        pub PasswordResetTokenReaderMock {}
        #[async_trait]
        impl PasswordResetTokenReader for PasswordResetTokenReaderMock {
            async fn find_by_token(&self, token: &str) -> AppResult<Option<PasswordResetToken>>;
        }
    }

    mock! {
        pub UserWriterMock {}
        #[async_trait]
        impl UserWriter for UserWriterMock {
            async fn insert(&self, user: User) -> AppResult<Id<User>>;
            async fn update(&self, user: User) -> AppResult<Id<User>>;
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

    mock! {
        pub EmailSenderMock {}
        #[async_trait]
        impl EmailSender for EmailSenderMock {
            async fn send(&self, to: &str, subject: &str, body: &str) -> AppResult<()>;
        }
    }

    type BoxFn<A, R> = Box<dyn Fn(A) -> R + Send + Sync>;

    struct MockUserReader {
        find_by_email_fn: Option<BoxFn<String, AppResult<Option<User>>>>,
        find_by_id_fn: Option<BoxFn<String, AppResult<Option<User>>>>,
    }

    impl MockUserReader {
        fn new() -> Self {
            Self {
                find_by_email_fn: None,
                find_by_id_fn: None,
            }
        }

        fn expect_find_by_email(&mut self, f: impl Fn(&str) -> AppResult<Option<User>> + Send + Sync + 'static) {
            self.find_by_email_fn = Some(Box::new(move |e| f(&e)));
        }

        fn expect_find_by_id(&mut self, f: impl Fn(&Id<User>) -> AppResult<Option<User>> + Send + Sync + 'static) {
            self.find_by_id_fn = Some(Box::new(move |id| {
                let user_id: Id<User> = id.try_into().expect("valid uuid");
                f(&user_id)
            }));
        }
    }

    #[async_trait]
    impl UserReader for MockUserReader {
        async fn find_by_email(&self, email: &str) -> AppResult<Option<User>> {
            match &self.find_by_email_fn {
                Some(f) => f(email.to_string()),
                None => Ok(None),
            }
        }

        async fn is_user(&self, _username: &str, _email: &str) -> AppResult<bool> {
            Ok(false)
        }

        async fn find_by_id(&self, user_id: &Id<User>) -> AppResult<Option<User>> {
            match &self.find_by_id_fn {
                Some(f) => f(user_id.value.to_string()),
                None => Ok(None),
            }
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

    // Fixtures
    fn sample_user() -> User {
        User::new("test".to_string(), "test@example.com".to_string(), "hashed".to_string())
    }

    fn valid_reset_token(user_id: Id<User>) -> PasswordResetToken {
        PasswordResetToken::new(user_id, "valid-token".to_string(), 3600)
    }

    fn expired_reset_token(user_id: Id<User>) -> PasswordResetToken {
        PasswordResetToken::new(user_id, "expired-token".to_string(), -1)
    }

    fn used_reset_token(user_id: Id<User>) -> PasswordResetToken {
        let mut token = valid_reset_token(user_id);
        token.used_at = Some(Utc::now());
        token
    }

    // RequestPasswordResetInteractor tests
    #[rstest]
    #[tokio::test]
    async fn test_request_password_reset_success() {
        let mut db_session = MockDBSessionMock::new();
        let mut token_writer = MockPasswordResetTokenWriterMock::new();
        let mut user_reader = MockUserReader::new();
        let mut email_sender = MockEmailSenderMock::new();

        user_reader.expect_find_by_email(|_| Ok(Some(sample_user())));
        token_writer.expect_delete().returning(|_| Ok(()));
        token_writer.expect_insert().returning(|t| Ok(t.id));
        email_sender.expect_send().times(0..=1).returning(|_, _, _| Ok(()));
        db_session.expect_commit().returning(|| Ok(()));

        let interactor = RequestPasswordResetInteractor::new(
            Arc::new(db_session),
            Arc::new(token_writer),
            Arc::new(user_reader),
            Arc::new(email_sender),
        );

        let result = interactor
            .execute(RequestPasswordResetDTO {
                email: "test@example.com".to_string(),
                ttl: 3600,
                reset_url: "http://localhost/reset-password".to_string(),
            })
            .await;

        assert!(result.is_ok());
    }

    #[rstest]
    #[tokio::test]
    async fn test_request_password_reset_user_not_found_returns_ok() {
        let db_session = MockDBSessionMock::new();
        let token_writer = MockPasswordResetTokenWriterMock::new();
        let mut user_reader = MockUserReader::new();
        let email_sender = MockEmailSenderMock::new();

        user_reader.expect_find_by_email(|_| Ok(None));

        let interactor = RequestPasswordResetInteractor::new(
            Arc::new(db_session),
            Arc::new(token_writer),
            Arc::new(user_reader),
            Arc::new(email_sender),
        );

        let result = interactor
            .execute(RequestPasswordResetDTO {
                email: "nonexistent@example.com".to_string(),
                ttl: 3600,
                reset_url: "http://localhost/reset-password".to_string(),
            })
            .await;

        assert!(result.is_ok());
    }

    // ResetPasswordInteractor tests
    #[rstest]
    #[tokio::test]
    async fn test_reset_password_success() {
        let mut db_session = MockDBSessionMock::new();
        let mut token_reader = MockPasswordResetTokenReaderMock::new();
        let mut token_writer = MockPasswordResetTokenWriterMock::new();
        let mut user_reader = MockUserReader::new();
        let mut user_writer = MockUserWriterMock::new();
        let mut hasher = MockHasherMock::new();

        let user = sample_user();
        let user_id = user.id.clone();

        token_reader
            .expect_find_by_token()
            .returning(move |_| Ok(Some(valid_reset_token(user_id.clone()))));
        user_reader.expect_find_by_id(move |_| Ok(Some(user.clone())));
        hasher
            .expect_hash_password()
            .returning(|_| Ok("new_hashed_password".to_string()));
        token_writer.expect_mark_as_used().returning(|_| Ok(()));
        user_writer.expect_update().returning(|u| Ok(u.id));
        db_session.expect_commit().returning(|| Ok(()));

        let interactor = ResetPasswordInteractor::new(
            Arc::new(db_session),
            Arc::new(token_reader),
            Arc::new(token_writer),
            Arc::new(user_reader),
            Arc::new(user_writer),
            Arc::new(hasher),
        );

        let result = interactor
            .execute(ResetPasswordDTO {
                token: "valid-token".to_string(),
                password: "NewPassword123!".to_string(),
            })
            .await;

        assert!(result.is_ok());
    }

    #[rstest]
    #[tokio::test]
    async fn test_reset_password_invalid_token() {
        let db_session = MockDBSessionMock::new();
        let mut token_reader = MockPasswordResetTokenReaderMock::new();
        let token_writer = MockPasswordResetTokenWriterMock::new();
        let user_reader = MockUserReader::new();
        let user_writer = MockUserWriterMock::new();
        let hasher = MockHasherMock::new();

        token_reader.expect_find_by_token().returning(|_| Ok(None));

        let interactor = ResetPasswordInteractor::new(
            Arc::new(db_session),
            Arc::new(token_reader),
            Arc::new(token_writer),
            Arc::new(user_reader),
            Arc::new(user_writer),
            Arc::new(hasher),
        );

        let result = interactor
            .execute(ResetPasswordDTO {
                token: "invalid-token".to_string(),
                password: "NewPassword123!".to_string(),
            })
            .await;

        assert!(matches!(result.unwrap_err(), AppError::InvalidResetToken));
    }

    #[rstest]
    #[tokio::test]
    async fn test_reset_password_expired_token() {
        let db_session = MockDBSessionMock::new();
        let mut token_reader = MockPasswordResetTokenReaderMock::new();
        let token_writer = MockPasswordResetTokenWriterMock::new();
        let user_reader = MockUserReader::new();
        let user_writer = MockUserWriterMock::new();
        let hasher = MockHasherMock::new();

        let user_id: Id<User> = Id::generate();
        token_reader
            .expect_find_by_token()
            .returning(move |_| Ok(Some(expired_reset_token(user_id.clone()))));

        let interactor = ResetPasswordInteractor::new(
            Arc::new(db_session),
            Arc::new(token_reader),
            Arc::new(token_writer),
            Arc::new(user_reader),
            Arc::new(user_writer),
            Arc::new(hasher),
        );

        let result = interactor
            .execute(ResetPasswordDTO {
                token: "expired-token".to_string(),
                password: "NewPassword123!".to_string(),
            })
            .await;

        assert!(matches!(result.unwrap_err(), AppError::ResetTokenExpired));
    }

    #[rstest]
    #[tokio::test]
    async fn test_reset_password_used_token() {
        let db_session = MockDBSessionMock::new();
        let mut token_reader = MockPasswordResetTokenReaderMock::new();
        let token_writer = MockPasswordResetTokenWriterMock::new();
        let user_reader = MockUserReader::new();
        let user_writer = MockUserWriterMock::new();
        let hasher = MockHasherMock::new();

        let user_id: Id<User> = Id::generate();
        token_reader
            .expect_find_by_token()
            .returning(move |_| Ok(Some(used_reset_token(user_id.clone()))));

        let interactor = ResetPasswordInteractor::new(
            Arc::new(db_session),
            Arc::new(token_reader),
            Arc::new(token_writer),
            Arc::new(user_reader),
            Arc::new(user_writer),
            Arc::new(hasher),
        );

        let result = interactor
            .execute(ResetPasswordDTO {
                token: "used-token".to_string(),
                password: "NewPassword123!".to_string(),
            })
            .await;

        assert!(matches!(result.unwrap_err(), AppError::ResetTokenAlreadyUsed));
    }
}
