use crate::application::interface::email::EmailSender;
use crate::{
    application::{
        app_error::{AppError, AppResult},
        dto::email_confirmation::{ConfirmEmailDTO, ResendConfirmationDTO},
        interface::{
            db::DBSession,
            gateway::{
                email_confirmation::{EmailConfirmationReader, EmailConfirmationWriter},
                user::{UserReader, UserWriter},
            },
        },
    },
    domain::entities::email_confirmation::EmailConfirmation,
};
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

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

#[derive(Clone)]
pub struct ResendConfirmationInteractor {
    db_session: Arc<dyn DBSession>,
    email_confirmation_writer: Arc<dyn EmailConfirmationWriter>,
    user_reader: Arc<dyn UserReader>,
    email_sender: Arc<dyn EmailSender>,
}

impl ResendConfirmationInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        email_confirmation_writer: Arc<dyn EmailConfirmationWriter>,
        user_reader: Arc<dyn UserReader>,
        email_sender: Arc<dyn EmailSender>,
    ) -> Self {
        Self {
            db_session,
            email_confirmation_writer,
            user_reader,
            email_sender,
        }
    }

    pub async fn execute(&self, dto: ResendConfirmationDTO) -> AppResult<()> {
        let user = self
            .user_reader
            .find_by_email(&dto.email)
            .await?
            .ok_or(AppError::InvalidConfirmationToken)?;
        if user.is_confirmed {
            return Err(AppError::EmailAlreadyConfirmed);
        }
        self.email_confirmation_writer
            .delete(&user.id.clone())
            .await?;
        let token = Uuid::now_v7();
        let confirmation = EmailConfirmation::new(user.id, token.to_string().clone(), dto.ttl);
        self.email_confirmation_writer.insert(confirmation).await?;
        let confirmation_link = format!("{}?token={}", dto.confirmation_url, token);
        let email_sender = Arc::clone(&self.email_sender);
        let user_email = user.email.clone();
        // TODO: add email template
        tokio::spawn(async move {
            let subject = "Подтверждение аккаунте";
            let body = format!(
                "Пожалуйста, подтвердите свой аккаунт по ссылке: {}",
                confirmation_link
            );
            info!("Sending confirmation email to {}", user_email);
            if let Err(err) = email_sender.send(&user_email, subject, &body).await {
                error!(
                    "Failed to send confirmation email to {}: {}",
                    user_email, err
                );
                return;
            }
            info!("Confirmation email sent to {}", user_email);
        });
        self.db_session.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        application::{
            app_error::{AppError, AppResult},
            dto::email_confirmation::{ConfirmEmailDTO, ResendConfirmationDTO},
            interactors::email_confirmation::{
                ConfirmEmailInteractor, ResendConfirmationInteractor,
            },
            interface::{
                db::DBSession,
                email::EmailSender,
                gateway::{
                    email_confirmation::{EmailConfirmationReader, EmailConfirmationWriter},
                    user::{UserReader, UserWriter},
                },
            },
        },
        domain::entities::{email_confirmation::EmailConfirmation, id::Id, user::User},
    };
    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use mockall::mock;
    use rstest::rstest;
    use std::sync::Arc;

    mock! {
        pub EmailSenderMock {}

        #[async_trait]
        impl EmailSender for EmailSenderMock {
            async fn send(&self, to: &str, subject: &str, body: &str) -> AppResult<()>;
        }
    }

    mock! {
        pub DBSessionMock {}

        #[async_trait]
        impl DBSession for DBSessionMock {
            async fn commit(&self) -> AppResult<()>;
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

        fn expect_find_by_email(
            &mut self,
            f: impl Fn(&str) -> AppResult<Option<User>> + Send + Sync + 'static,
        ) {
            self.find_by_email_fn = Some(Box::new(move |email| f(&email)));
        }

        fn expect_find_by_id(
            &mut self,
            f: impl Fn(&Id<User>) -> AppResult<Option<User>> + Send + Sync + 'static,
        ) {
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

    mock! {
        pub EmailConfirmationReaderMock {}

        #[async_trait]
        impl EmailConfirmationReader for EmailConfirmationReaderMock {
            async fn find_by_token(&self, token: &str) -> AppResult<Option<EmailConfirmation>>;
        }
    }

    mock! {
        pub EmailConfirmationWriterMock {}

        #[async_trait]
        impl EmailConfirmationWriter for EmailConfirmationWriterMock {
            async fn insert(&self, email_confirmation: EmailConfirmation) -> AppResult<Id<EmailConfirmation>>;
            async fn confirm(&self, confirmation_id: &Id<EmailConfirmation>) -> AppResult<()>;
        }
    }

    fn unconfirmed_user() -> User {
        User::new(
            "Test".to_string(),
            "ex@example.com".to_string(),
            "hash".to_string(),
        )
    }

    fn confirmation_for(user_id: Id<User>) -> EmailConfirmation {
        let now = Utc::now();
        EmailConfirmation {
            id: Id::generate(),
            user_id,
            token: "token-123".to_string(),
            expires_at: now + Duration::hours(1),
            confirmed_at: None,
            created_at: now,
        }
    }

    #[rstest]
    #[tokio::test]
    async fn test_confirm_email_success() {
        let mut db_session = MockDBSessionMock::new();
        let mut reader = MockEmailConfirmationReaderMock::new();
        let mut writer = MockEmailConfirmationWriterMock::new();
        let mut user_reader = MockUserReader::new();
        let mut user_writer = MockUserWriterMock::new();

        let user = unconfirmed_user();
        let user_id = user.id.clone();

        reader
            .expect_find_by_token()
            .returning(move |_| Ok(Some(confirmation_for(user_id.clone()))));
        user_reader.expect_find_by_id(move |_| Ok(Some(user.clone())));
        writer.expect_confirm().returning(|_| Ok(()));
        user_writer.expect_update().returning(|u| Ok(u.id));
        db_session.expect_commit().returning(|| Ok(()));

        let interactor = ConfirmEmailInteractor::new(
            Arc::new(db_session),
            Arc::new(reader),
            Arc::new(writer),
            Arc::new(user_reader),
            Arc::new(user_writer),
        );

        let result = interactor
            .execute(ConfirmEmailDTO {
                token: "token-123".to_string(),
            })
            .await;

        assert!(result.is_ok());
    }

    #[rstest]
    #[tokio::test]
    async fn test_confirm_email_invalid_token() {
        let db_session = MockDBSessionMock::new();
        let mut reader = MockEmailConfirmationReaderMock::new();
        let writer = MockEmailConfirmationWriterMock::new();
        let user_reader = MockUserReader::new();
        let user_writer = MockUserWriterMock::new();

        reader.expect_find_by_token().returning(|_| Ok(None));

        let interactor = ConfirmEmailInteractor::new(
            Arc::new(db_session),
            Arc::new(reader),
            Arc::new(writer),
            Arc::new(user_reader),
            Arc::new(user_writer),
        );

        let result = interactor
            .execute(ConfirmEmailDTO {
                token: "missing".to_string(),
            })
            .await;

        assert!(matches!(
            result.unwrap_err(),
            AppError::InvalidConfirmationToken
        ));
    }

    #[rstest]
    #[tokio::test]
    async fn test_resend_confirmation_success() {
        let mut db_session = MockDBSessionMock::new();
        let mut writer = MockEmailConfirmationWriterMock::new();
        let mut user_reader = MockUserReader::new();
        let mut email_sender = MockEmailSenderMock::new();

        user_reader.expect_find_by_email(|_| Ok(Some(unconfirmed_user())));
        writer.expect_insert().returning(|e| Ok(e.id));
        email_sender
            .expect_send()
            .times(0..=1)
            .returning(|_, _, _| Ok(()));
        db_session.expect_commit().returning(|| Ok(()));

        let interactor = ResendConfirmationInteractor::new(
            Arc::new(db_session),
            Arc::new(writer),
            Arc::new(user_reader),
            Arc::new(email_sender),
        );

        let result = interactor
            .execute(ResendConfirmationDTO {
                email: "ex@example.com".to_string(),
                ttl: 3600,
                confirmation_url: "http://localhost/confirm-email".to_string(),
            })
            .await;

        assert!(result.is_ok());
    }

    #[rstest]
    #[tokio::test]
    async fn test_resend_confirmation_already_confirmed() {
        let db_session = MockDBSessionMock::new();
        let writer = MockEmailConfirmationWriterMock::new();
        let mut user_reader = MockUserReader::new();
        let email_sender = MockEmailSenderMock::new();

        user_reader.expect_find_by_email(|_| {
            let mut user = unconfirmed_user();
            user.is_confirmed = true;
            Ok(Some(user))
        });

        let interactor = ResendConfirmationInteractor::new(
            Arc::new(db_session),
            Arc::new(writer),
            Arc::new(user_reader),
            Arc::new(email_sender),
        );

        let result = interactor
            .execute(ResendConfirmationDTO {
                email: "ex@example.com".to_string(),
                ttl: 3600,
                confirmation_url: "http://localhost/confirm-email".to_string(),
            })
            .await;

        assert!(matches!(
            result.unwrap_err(),
            AppError::EmailAlreadyConfirmed
        ));
    }
}
