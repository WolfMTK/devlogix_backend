use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;

use crate::adapter::http::app_error_impl::ErrorResponse;
use crate::adapter::http::middleware::auth::{build_logout_cookie, build_session_cookie};
use crate::adapter::http::middleware::extractor::AuthUser;
use crate::adapter::http::schema::auth::{LoginRequest, MessageResponse, ResendConfirmationRequest};
use crate::adapter::http::schema::email_confirmation::ConfirmEmailQuery;
use crate::application::app_error::AppResult;
use crate::application::dto::auth::LoginDTO;
use crate::application::dto::email_confirmation::{ConfirmEmailDTO, ResendConfirmationDTO};
use crate::application::dto::id::IdDTO;
use crate::application::interactors::auth::{LoginInteractor, LogoutInteractor};
use crate::application::interactors::email_confirmation::{ConfirmEmailInteractor, ResendConfirmationInteractor};
use crate::infra::config::AppConfig;

#[utoipa::path(
    post,
    path = "/auth/login",
    tag = "Auth",
    request_body(
        content = LoginRequest,
        example = json!(
            {
                "email": "user@example.com",
                "password": "Password123!",
                "remember_me": true
            }
        )
    ),
    responses(
        (
            status = 200,
            description = "Login successful",
            body = MessageResponse,
            example = json!(
                {
                    "message": "Login successful"
                }
            )
        ),
        (
            status = 401,
            description = "Invalid email, password or session",
            body = ErrorResponse,
            example = json!(
                {
                    "error": "Invalid Credentials"
                }
            )
        ),
        (
            status = 403,
            description = "Email is not confirmed",
            body = ErrorResponse,
            example = json!(
                {
                    "error": "Email is not confirmed"
                }
            )
        ),
        (
            status = 500,
            description = "Internal server error",
            body = ErrorResponse,
            example = json!(
                {
                    "error": "Internal Server Error"
                }
            )
        )
    )
)]
pub async fn login(
    interactor: LoginInteractor,
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<LoginRequest>,
) -> AppResult<impl IntoResponse> {
    let dto = LoginDTO {
        email: payload.email.to_string(),
        password: payload.password,
        remember_me: payload.remember_me,
    };
    let result = interactor.execute(dto).await?;
    let cookie = build_session_cookie(&result.session_id, result.remember_me, &config.session);
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, HeaderValue::from_str(&cookie)?);
    Ok((
        StatusCode::OK,
        headers,
        Json(MessageResponse {
            message: "Login successful".to_string(),
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/auth/logout",
    tag = "Auth",
    responses(
        (
            status = 200,
            description = "Logged out successfully",
            body = MessageResponse,
            example = json!(
                {
                    "message": "Logged out successfully"
                }
            )
        ),
        (
            status = 401,
            description = "Missing or invalid session",
            body = ErrorResponse,
            example = json!(
                {
                    "error": "Invalid Credentials"
                }
            )
        ),
        (
            status = 500,
            description = "Internal server error",
            body = ErrorResponse,
            example = json!(
                {
                    "error": "Internal Server Error"
                }
            )
        )
    ),
    security(("cookieAuth" = []))
)]
pub async fn logout(
    auth_user: AuthUser,
    interactor: LogoutInteractor,
    State(config): State<Arc<AppConfig>>,
) -> AppResult<impl IntoResponse> {
    let cookie = build_logout_cookie(&config.session);
    let dto = IdDTO { id: auth_user.user_id };
    interactor.execute(dto).await?;
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, HeaderValue::from_str(&cookie)?);
    Ok((
        StatusCode::OK,
        headers,
        Json(MessageResponse {
            message: "Logged out successfully".to_string(),
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/auth/confirm-email",
    tag = "Auth",
    params(ConfirmEmailQuery),
    responses(
        (
            status = 200,
            description = "Email confirmed",
            body = MessageResponse,
            example = json!(
                {
                    "message": "Email confirmed successfully"
                }
            )
        ),
        (
            status = 400,
            description = "Invalid or expired confirmation token",
            body = ErrorResponse,
            example = json!(
                {
                    "error": "Invalid or expired confirmation token"
                }
            )
        ),
        (
            status = 409,
            description = "Email already confirmed",
            body = ErrorResponse,
            example = json!(
                {
                    "error": "Email is already confirmed"
                }
            )
        ),
        (
            status = 500,
            description = "Internal server error",
            body = ErrorResponse,
            example = json!(
                {
                    "error": "Internal Server Error"
                }
            )
        )
    )
)]
pub async fn confirm_email(
    interactor: ConfirmEmailInteractor,
    Query(query): Query<ConfirmEmailQuery>,
) -> AppResult<impl IntoResponse> {
    interactor.execute(ConfirmEmailDTO { token: query.token }).await?;
    Ok((
        StatusCode::OK,
        Json(MessageResponse {
            message: "Email confirmed successfully".to_string(),
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/auth/resend-confirmation",
    tag = "Auth",
    request_body(
        content = ResendConfirmationRequest,
        example = json!(
        {
                "email": "user@example.com"
            }
        )
    ),
    responses(
        (
            status = 200,
            description = "Confirmation code resent",
            body = MessageResponse,
            example = json!(
                {
                    "message": "Confirmation code has been resent"
                }
            )
        ),
        (
            status = 400,
            description = "Invalid request payload or unknown email",
            body = ErrorResponse,
            example = json!(
                {
                    "error": "Invalid or expired confirmation token"
                }
            )
        ),
        (
            status = 409,
            description = "Email already confirmed",
            body = ErrorResponse,
            example = json!(
                {
                    "error": "Email is already confirmed"
                }
            )
        ),
        (
            status = 500,
            description = "Internal server error",
            body = ErrorResponse,
            example = json!(
                {
                    "error": "Internal Server Error"
                }
            )
        )
    )
)]
pub async fn resend_confirmation(
    interactor: ResendConfirmationInteractor,
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<ResendConfirmationRequest>,
) -> AppResult<impl IntoResponse> {
    interactor
        .execute(ResendConfirmationDTO {
            email: payload.email.to_string(),
            ttl: config.email_confirmation.ttl,
            confirmation_url: config.email_confirmation.confirmation_url.clone(),
        })
        .await?;

    Ok((
        StatusCode::OK,
        Json(MessageResponse {
            message: "Confirmation code has been resent".to_string(),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use axum::Json;
    use axum::extract::{Query, State};
    use axum::http::StatusCode;
    use axum::http::header::SET_COOKIE;
    use axum::response::IntoResponse;
    use chrono::Utc;
    use mockall::mock;
    use serde_json::json;

    use super::{confirm_email, login, logout, resend_confirmation};
    use crate::adapter::http::middleware::extractor::AuthUser;
    use crate::adapter::http::schema::auth::{LoginRequest, ResendConfirmationRequest};
    use crate::adapter::http::schema::email_confirmation::ConfirmEmailQuery;
    use crate::application::app_error::AppResult;
    use crate::application::interactors::auth::{LoginInteractor, LogoutInteractor};
    use crate::application::interactors::email_confirmation::{ConfirmEmailInteractor, ResendConfirmationInteractor};
    use crate::application::interface::crypto::CredentialsHasher;
    use crate::application::interface::db::DBSession;
    use crate::application::interface::email::EmailSender;
    use crate::application::interface::gateway::email_confirmation::{
        EmailConfirmationReader, EmailConfirmationWriter,
    };
    use crate::application::interface::gateway::session::SessionWriter;
    use crate::application::interface::gateway::user::{UserReader, UserWriter};
    use crate::domain::entities::email_confirmation::EmailConfirmation;
    use crate::domain::entities::id::Id;
    use crate::domain::entities::session::Session;
    use crate::domain::entities::user::User;
    use crate::infra::config::{
        AppConfig, ApplicationConfig, DatabaseConfig, EmailConfig, EmailConfirmationConfig, LoggerConfig, SMTPConfig,
        SessionConfig,
    };

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
            self.find_by_email_fn = Some(Box::new(move |email| f(&email)));
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
            (self.find_by_email_fn.as_ref().expect("find_by_email must be mocked"))(email.to_string())
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
            async fn delete(&self, user_id: &Id<User>) -> AppResult<()>;
        }
    }

    mock! {
        pub EmailSenderMock {}

        #[async_trait]
        impl EmailSender for EmailSenderMock {
            async fn send(&self, to: &str, subject: &str, body: &str) -> AppResult<()>;
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

    fn test_config() -> Arc<AppConfig> {
        Arc::new(AppConfig {
            db: DatabaseConfig {
                url: "postgres://local/test".to_string(),
                max_connections: 5,
            },
            logger: LoggerConfig {
                log_path: "./test.log".to_string(),
            },
            application: ApplicationConfig {
                allow_origins: vec!["*".to_string()],
                address: "127.0.0.1:3000".to_string(),
            },
            session: SessionConfig {
                default_max_lifetime: 86_400,
                default_idle_timeout: 3_600,
                remembered_max_lifetime: 2_592_000,
                remembered_idle_timeout: 86_400,
                rotation_interval: 900,
                cookie_name: "session_id".to_string(),
                cookie_secure: true,
                cookie_http_only: true,
            },
            email_confirmation: EmailConfirmationConfig {
                ttl: 86_400,
                confirmation_url: "http://localhost/confirm".to_string(),
            },
            email: EmailConfig {
                provider: "local".to_string(),
                local_output_dir: "./tmp/test-emails".to_string(),
            },
            smtp: SMTPConfig {
                host: "smtp.example.com".to_string(),
                port: 587,
                username: "user".to_string(),
                password: "pass".to_string(),
                from: "noreply@example.com".to_string(),
            },
        })
    }

    fn confirmed_user() -> User {
        let mut user = User::new("Test".to_string(), "ex@example.com".to_string(), "password".to_string());
        user.is_confirmed = true;
        user
    }

    fn unconfirmed_user() -> User {
        User::new("Test".to_string(), "ex@example.com".to_string(), "password".to_string())
    }

    #[tokio::test]
    async fn test_login_handler_sets_cookie_and_returns_ok() {
        let mut db_session = MockDBSessionMock::new();
        let mut user_reader = MockUserReader::new();
        let mut session_writer = MockSessionWriterMock::new();
        let mut hasher = MockHasherMock::new();

        user_reader.expect_find_by_email(|_| Ok(Some(confirmed_user())));
        hasher.expect_verify_password().returning(|_, _| Ok(true));
        session_writer.expect_insert().returning(|_| Ok(Id::generate()));
        db_session.expect_commit().returning(|| Ok(()));

        let interactor = LoginInteractor::new(
            Arc::new(db_session),
            Arc::new(user_reader),
            Arc::new(session_writer),
            Arc::new(hasher),
        );
        let payload: LoginRequest = serde_json::from_value(json!({
            "email": "ex@example.com",
            "password": "Password123!",
            "remember_me": true
        }))
        .expect("valid login payload");

        let response = login(interactor, State(test_config()), Json(payload))
            .await
            .expect("login should pass")
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(SET_COOKIE).is_some());
    }

    #[tokio::test]
    async fn test_logout_handler_sets_expired_cookie_and_returns_ok() {
        let mut db_session = MockDBSessionMock::new();
        let mut session_writer = MockSessionWriterMock::new();
        session_writer.expect_delete_by_user_id().returning(|_| Ok(()));
        db_session.expect_commit().returning(|| Ok(()));

        let interactor = LogoutInteractor::new(Arc::new(db_session), Arc::new(session_writer));
        let auth_user = AuthUser {
            user_id: Id::<User>::generate().value.to_string(),
        };

        let response = logout(auth_user, interactor, State(test_config()))
            .await
            .expect("logout should pass")
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get(SET_COOKIE)
            .expect("cookie header should be present")
            .to_str()
            .expect("cookie should be valid header");
        assert!(cookie.contains("Max-Age=0"));
    }

    #[tokio::test]
    async fn test_confirm_email_handler_returns_ok() {
        let mut db_session = MockDBSessionMock::new();
        let mut confirmation_reader = MockEmailConfirmationReaderMock::new();
        let mut confirmation_writer = MockEmailConfirmationWriterMock::new();
        let mut user_reader = MockUserReader::new();
        let mut user_writer = MockUserWriterMock::new();

        let user = confirmed_user();
        let user_id = user.id.clone();

        confirmation_reader.expect_find_by_token().returning(move |_| {
            Ok(Some(EmailConfirmation::new(
                user_id.clone(),
                "confirmation-token".to_string(),
                3600,
            )))
        });
        user_reader.expect_find_by_id(move |_| Ok(Some(user.clone())));
        confirmation_writer.expect_confirm().returning(|_| Ok(()));
        user_writer.expect_update().returning(|u| Ok(u.id));
        db_session.expect_commit().returning(|| Ok(()));

        let interactor = ConfirmEmailInteractor::new(
            Arc::new(db_session),
            Arc::new(confirmation_reader),
            Arc::new(confirmation_writer),
            Arc::new(user_reader),
            Arc::new(user_writer),
        );

        let response = confirm_email(
            interactor,
            Query(ConfirmEmailQuery {
                token: "confirmation-token".to_string(),
            }),
        )
        .await
        .expect("confirm email should pass")
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_resend_confirmation_handler_returns_ok() {
        let mut db_session = MockDBSessionMock::new();
        let mut confirmation_writer = MockEmailConfirmationWriterMock::new();
        let mut user_reader = MockUserReader::new();
        let mut email_sender = MockEmailSenderMock::new();

        user_reader.expect_find_by_email(|_| Ok(Some(unconfirmed_user())));
        confirmation_writer.expect_delete().returning(|_| Ok(()));
        confirmation_writer.expect_insert().returning(|_| Ok(Id::generate()));
        db_session.expect_commit().returning(|| Ok(()));
        email_sender.expect_send().returning(|_, _, _| Ok(()));

        let interactor = ResendConfirmationInteractor::new(
            Arc::new(db_session),
            Arc::new(confirmation_writer),
            Arc::new(user_reader),
            Arc::new(email_sender),
        );

        let payload: ResendConfirmationRequest = serde_json::from_value(json!({
            "email": "ex@example.com"
        }))
        .expect("valid resend payload");

        let response = resend_confirmation(interactor, State(test_config()), Json(payload))
            .await
            .expect("resend confirmation should pass")
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
