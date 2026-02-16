use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::adapter::http::app_error_impl::ErrorResponse;
use crate::adapter::http::middleware::extractor::AuthUser;
use crate::adapter::http::schema::auth::MessageResponse;
use crate::adapter::http::schema::id::IdResponse;
use crate::adapter::http::schema::user::{CreateUserRequest, GetUserResponse, UpdateUserRequest};
use crate::adapter::http::validation::ValidJson;
use crate::application::app_error::AppResult;
use crate::application::dto::id::IdDTO;
use crate::application::dto::user::{CreateUserDTO, UpdateUserDTO};
use crate::application::interactors::users::{CreateUserInteractor, GetMeInteractor, UpdateUserInteractor};

#[utoipa::path(
    post,
    path = "/users/register",
    tag = "Users",
    request_body(
        content = CreateUserRequest,
        example = json!(
            {
                "username": "new_user",
                "email": "user@example.com",
                "password1": "Password123!",
                "password2": "Password123!"
            }
        )
    ),
    responses(
        (
            status = 200,
            description = "User registered",
            body = IdResponse,
            example = json!(
                {
                    "id": "0191f1d3-7bcb-7f2d-b74a-8a6826c8761a"
                }
            )
        ),
        (
            status = 400,
            description = "User exists or validation error. Multiple field errors return as field-to-message map in `error`.",
            body = ErrorResponse,
            example = json!(
                {
                    "error": {
                        "password": [
                            "Password must contain at least one uppercase letter (A-Z)",
                            "Passwords does not match"
                        ]
                    }
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
pub async fn register(
    interactor: CreateUserInteractor,
    ValidJson(payload): ValidJson<CreateUserRequest>,
) -> AppResult<impl IntoResponse> {
    let dto = CreateUserDTO {
        username: payload.username,
        email: payload.email.to_string(),
        password1: payload.password1.value().to_string(),
        password2: payload.password2.value().to_string(),
    };
    let user_id = interactor.execute(dto).await?;
    let response = IdResponse { id: user_id.id };
    Ok((StatusCode::OK, Json(response)))
}

#[utoipa::path(
    get,
    path = "/users/me",
    tag = "Users",
    responses(
        (
            status = 200,
            description = "Current user profile",
            body = GetUserResponse,
            example = json!(
                {
                    "id": "0191f1d3-7bcb-7f2d-b74a-8a6826c8761a",
                    "username": "existing_user",
                    "email": "user@example.com",
                    "created_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-01T00:00:00Z"
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
pub async fn get_me(auth_user: AuthUser, interactor: GetMeInteractor) -> AppResult<impl IntoResponse> {
    let dto = IdDTO { id: auth_user.user_id };
    let user = interactor.execute(dto).await?;
    let response = GetUserResponse {
        id: user.id,
        username: user.username,
        email: user.email,
        created_at: user.created_at,
        updated_at: user.updated_at,
    };
    Ok((StatusCode::OK, Json(response)))
}

#[utoipa::path(
    patch,
    path = "/users/",
    tag = "Users",
    request_body(
        content = UpdateUserRequest,
        example = json!(
            {
                "username": "updated_user",
                "email": "updated@example.com",
                "old_password": "OldPassword123!",
                "password1": "Password123!",
                "password2": "Password123!"
            }
        )
    ),
    responses(
        (
            status = 200,
            description = "User updated",
            body = MessageResponse,
            example = json!(
                {
                    "message": "success"
                }
            )
        ),
        (
            status = 400,
            description = "Validation error, wrong old password or duplicate user data",
            body = ErrorResponse,
            example = json!(
                    {
                        "error": {
                            "password": [
                                "Password must be at least 8 characters long",
                                "Passwords does not match"
                            ]
                        }
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
pub async fn update_user(
    auth_user: AuthUser,
    interactor: UpdateUserInteractor,
    ValidJson(payload): ValidJson<UpdateUserRequest>,
) -> AppResult<impl IntoResponse> {
    let dto = UpdateUserDTO {
        id: auth_user.user_id,
        username: payload.username,
        email: payload.email.map(|email| email.to_string()),
        old_password: payload.old_password.map(|password| password.value().to_string()),
        password1: payload.password1.map(|password| password.value().to_string()),
        password2: payload.password2.map(|password| password.value().to_string()),
    };
    interactor.execute(dto).await?;
    Ok((
        StatusCode::OK,
        Json(MessageResponse {
            message: "success".to_string(),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use mockall::mock;
    use serde_json::json;

    use super::{get_me, register, update_user};
    use crate::adapter::http::middleware::extractor::AuthUser;
    use crate::adapter::http::schema::user::{CreateUserRequest, UpdateUserRequest};
    use crate::adapter::http::validation::ValidJson;
    use crate::application::app_error::AppResult;
    use crate::application::interactors::users::{CreateUserInteractor, GetMeInteractor, UpdateUserInteractor};
    use crate::application::interface::crypto::CredentialsHasher;
    use crate::application::interface::db::DBSession;
    use crate::application::interface::gateway::user::{UserReader, UserWriter};
    use crate::domain::entities::id::Id;
    use crate::domain::entities::user::User;

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

    mock! {
        pub HasherMock {}

        #[async_trait]
        impl CredentialsHasher for HasherMock {
            async fn hash_password(&self, password: &str) -> AppResult<String>;
            async fn verify_password(&self, password: &str, hashed: &str) -> AppResult<bool>;
        }
    }

    type BoxFn<A, R> = Box<dyn Fn(A) -> R + Send + Sync>;

    struct MockUserReader {
        is_user_fn: Option<BoxFn<(String, String), AppResult<bool>>>,
        find_by_id_fn: Option<BoxFn<String, AppResult<Option<User>>>>,
        is_unique_fn: Option<BoxFn<(String, Option<String>, Option<String>), AppResult<bool>>>,
    }

    impl MockUserReader {
        fn new() -> Self {
            Self {
                is_user_fn: None,
                find_by_id_fn: None,
                is_unique_fn: None,
            }
        }

        fn expect_is_user(&mut self, f: impl Fn(&str, &str) -> AppResult<bool> + Send + Sync + 'static) {
            self.is_user_fn = Some(Box::new(move |(u, e)| f(&u, &e)));
        }

        fn expect_find_by_id(&mut self, f: impl Fn(&Id<User>) -> AppResult<Option<User>> + Send + Sync + 'static) {
            self.find_by_id_fn = Some(Box::new(move |id| {
                let user_id: Id<User> = id.try_into().expect("valid uuid");
                f(&user_id)
            }));
        }

        fn expect_is_unique(
            &mut self,
            f: impl Fn(&Id<User>, Option<&str>, Option<&str>) -> AppResult<bool> + Send + Sync + 'static,
        ) {
            self.is_unique_fn = Some(Box::new(move |(id, u, e)| {
                let user_id: Id<User> = id.try_into().expect("valid uuid");
                f(&user_id, u.as_deref(), e.as_deref())
            }));
        }
    }

    #[async_trait]
    impl UserReader for MockUserReader {
        async fn find_by_email(&self, _email: &str) -> AppResult<Option<User>> {
            Ok(None)
        }

        async fn is_user(&self, username: &str, email: &str) -> AppResult<bool> {
            (self.is_user_fn.as_ref().expect("is_user must be mocked"))((username.to_string(), email.to_string()))
        }

        async fn find_by_id(&self, user_id: &Id<User>) -> AppResult<Option<User>> {
            (self.find_by_id_fn.as_ref().expect("find_by_id must be mocked"))(user_id.value.to_string())
        }

        async fn is_username_or_email_unique(
            &self,
            user_id: &Id<User>,
            username: Option<&str>,
            email: Option<&str>,
        ) -> AppResult<bool> {
            (self
                .is_unique_fn
                .as_ref()
                .expect("is_username_or_email_unique must be mocked"))((
                user_id.value.to_string(),
                username.map(ToString::to_string),
                email.map(ToString::to_string),
            ))
        }
    }

    fn sample_user() -> User {
        let mut user = User::new("Test".to_string(), "ex@example.com".to_string(), "hashed_password".to_string());
        user.id = Id::<User>::generate();
        user
    }

    #[tokio::test]
    async fn test_register_handler_returns_user_id() {
        let mut db_session = MockDBSessionMock::new();
        let mut user_writer = MockUserWriterMock::new();
        let mut user_reader = MockUserReader::new();
        let mut hasher = MockHasherMock::new();

        user_reader.expect_is_user(|_, _| Ok(false));
        hasher.expect_hash_password().returning(|_| Ok("password".to_string()));
        user_writer.expect_insert().returning(|user| Ok(user.id));
        db_session.expect_commit().returning(|| Ok(()));

        let interactor = CreateUserInteractor::new(
            Arc::new(db_session),
            Arc::new(user_writer),
            Arc::new(user_reader),
            Arc::new(hasher),
        );

        let payload: CreateUserRequest = serde_json::from_value(json!({
            "username": "Test",
            "email": "ex@example.com",
            "password1": "Password123!",
            "password2": "Password123!"
        }))
        .expect("valid create-user payload");

        let response = register(interactor, ValidJson(payload))
            .await
            .expect("register should pass")
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_me_handler_returns_ok() {
        let mut user_reader = MockUserReader::new();
        let user = sample_user();
        let expected_user_id = user.id.value.to_string();

        let expected_user_id_for_closure = expected_user_id.clone();
        user_reader.expect_find_by_id(move |_| {
            let mut user = User::new("Test".to_string(), "ex@example.com".to_string(), "hashed_password".to_string());
            user.id = expected_user_id_for_closure.clone().try_into().unwrap();
            Ok(Some(user))
        });

        let interactor = GetMeInteractor::new(Arc::new(user_reader));
        let auth_user = AuthUser {
            user_id: expected_user_id,
        };

        let response = get_me(auth_user, interactor)
            .await
            .expect("get_me should pass")
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_update_user_handler_returns_ok() {
        let mut db_session = MockDBSessionMock::new();
        let mut user_writer = MockUserWriterMock::new();
        let mut user_reader = MockUserReader::new();
        let mut hasher = MockHasherMock::new();

        let existing_user = sample_user();
        let existing_user_id = existing_user.id.value.to_string();

        user_reader.expect_is_unique(|_, _, _| Ok(false));
        user_reader.expect_find_by_id(move |_| {
            let mut user = User::new("Test".to_string(), "ex@example.com".to_string(), "password".to_string());
            user.id = existing_user_id.clone().try_into().unwrap();
            Ok(Some(user))
        });
        hasher.expect_verify_password().returning(|_, _| Ok(true));
        hasher
            .expect_hash_password()
            .returning(|_| Ok("new_hashed_password".to_string()));
        user_writer.expect_update().returning(|user| Ok(user.id));
        db_session.expect_commit().returning(|| Ok(()));

        let interactor = UpdateUserInteractor::new(
            Arc::new(db_session),
            Arc::new(user_writer),
            Arc::new(user_reader),
            Arc::new(hasher),
        );
        let auth_user = AuthUser {
            user_id: existing_user.id.value.to_string(),
        };
        let payload: UpdateUserRequest = serde_json::from_value(json!({
            "username": "updated_user",
            "email": "updated@example.com",
            "old_password": "Password123!",
            "password1": "NewPassword123!",
            "password2": "NewPassword123!"
        }))
        .expect("valid update payload");

        let response = update_user(auth_user, interactor, ValidJson(payload))
            .await
            .expect("update_user should pass")
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
