// TODO: add integration tests for handler `update_user`
use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::adapter::http::app_error_impl::ErrorResponse;
use crate::adapter::http::middleware::extractor::AuthUser;
use crate::adapter::http::schema::auth::MessageResponse;
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
            status = 201,
            description = "User registered",
            body = MessageResponse,
            example = json!(
                {
                    "message": "The user has been created"
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
    interactor.execute(dto).await?;
    Ok((
        StatusCode::CREATED,
        Json(MessageResponse {
            message: "The user has been created".to_string(),
        }),
    ))
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
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use rstest::rstest;
    use serde_json::Value;
    use serial_test::serial;
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::infra::app::create_app;
    use crate::infra::state::AppState;
    use crate::tests::fixtures::init_test_app_state;
    use crate::tests::helpers::{
        delete_user, find_user_by_email, hash_password, insert_confirmed_user, insert_session, session_cookie,
        unique_credentials,
    };

    // === register ===
    fn get_request_register(body: &Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/users/register")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    // Tests successful registration of a new user with valid credentials
    // Verifies:
    // - Endpoint returns 201 CREATED status
    // - Response contains the expected success message
    // - User is properly saved in the database (implicitly verified via find/delete operations)
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_register_successfully(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let password = "Password123!";
        let (username, email) = unique_credentials();
        let body = serde_json::json!({
            "username": username,
            "email": email,
            "password1": password,
            "password2": password,
        });

        let request = get_request_register(&body);
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        if let Some(user_id) = find_user_by_email(&state.pool, &email).await {
            delete_user(&state.pool, user_id).await
        }

        assert_eq!(status, StatusCode::CREATED);
        assert!(json["message"].is_string(), "response must contain an 'id' field");
        assert_eq!(json["message"], "The user has been created".to_string());
    }

    // Tests that registration fails with BAD_REQUEST when attempting to use an email that already exists
    // Verifies:
    // - Endpoint returns 400 BAD_REQUEST status when email is already taken
    // - Prevents duplicate user registration with the same email address
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_register_duplicate_email(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let password = "Password123!";
        let hashed_password = hash_password(&state, password).await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed_password).await;

        let body = serde_json::json!({
            "username": format!("other_{}", username),
            "email": email,
            "password1": password,
            "password2": password,
        });

        let request = get_request_register(&body);
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // Tests that registration fails with BAD_REQUEST for various invalid input scenarios
    // Verifies:
    // - Endpoint returns 400 BAD_REQUEST for:
    //   - Password too short
    //   - Password without numbers
    //   - Password without uppercase letters
    //   - Password without special characters
    //   - Passwords that don't match
    //   - Username too short
    //   - Invalid email format
    #[rstest]
    #[case(
        serde_json::json!({
            "username": "username",
            "email": "ex@example.com",
            "password1": "1234567",
            "password2": "1234567"
        })
    )]
    #[case(
        serde_json::json!({
            "username": "username",
            "email": "ex@example.com",
            "password1": "12345678",
            "password2": "12345678"
        })
    )]
    #[case(
        serde_json::json!({
            "username": "username",
            "email": "ex@example.com",
            "password1": "password",
            "password2": "password"
        })
    )]
    #[case(
        serde_json::json!({
            "username": "username",
            "email": "ex@example.com",
            "password1": "12345678!",
            "password2": "12345678!"
        })
    )]
    #[case(
        serde_json::json!({
            "username": "username",
            "email": "ex@example.com",
            "password1": "Password",
            "password2": "Password"
        })
    )]
    #[case(
        serde_json::json!({
            "username": "username",
            "email": "ex@example.com",
            "password1": "password!",
            "password2": "password!"
        })
    )]
    #[case(
        serde_json::json!({
            "username": "username",
            "email": "ex@example.com",
            "password1": "Password!",
            "password2": "Password!"
        })
    )]
    #[case(
        serde_json::json!({
            "username": "username",
            "email": "ex@example.com",
            "password1": "Password123!",
            "password2": "InvalidPassword123!"
        })
    )]
    #[case(
        serde_json::json!({
            "username": "usern",
            "email": "ex@example.com",
            "password1": "Password123!",
            "password2": "Password123!"
        })
    )]
    #[case(
        serde_json::json!({
            "username": "username",
            "email": "exexample.com",
            "password1": "Password123!",
            "password2": "Password123!"
        })
    )]
    #[tokio::test]
    #[serial]
    async fn test_register_invalid_data(#[case] body: Value, #[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let request = get_request_register(&body);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // === get_me ===
    fn get_request_get_me(session_id: Uuid, cookie_name: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri("/users/me")
            .header("cookie", session_cookie(session_id, cookie_name))
            .body(Body::empty())
            .unwrap()
    }

    // Tests successful retrieval of current user profile with valid session
    // Verifies:
    // - Endpoint returns 200 OK status when authenticated with valid session cookie
    // - Response contains correct user data
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_get_me_successfully(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed_password = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed_password).await;
        let session_id = insert_session(&state.pool, user_id).await;

        let cookie_name = &state.config.session.cookie_name;

        let request = get_request_get_me(session_id, cookie_name);

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["email"], email);
        assert_eq!(json["username"], username);
    }

    // Tests that accessing current user profile fails when no session cookie is provided
    // Verifies:
    // - Endpoint returns 401 UNAUTHORIZED status for unauthenticated requests
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_get_me_with_invalid_session(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let request = Request::builder()
            .method("GET")
            .uri("/users/me")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // === update_user ===
    fn get_request_update_user(body: &Value, session_id: Uuid, cookie_name: &str) -> Request<Body> {
        Request::builder()
            .method("PATCH")
            .uri("/users")
            .header("content-type", "application/json")
            .header("cookie", session_cookie(session_id, cookie_name))
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    // Tests successful username update
    // Verifies:
    // - Endpoint returns 200 OK when updating username with valid data
    // - Response contains success message "success"
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_update_user_username(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed_password = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed_password).await;
        let session_id = insert_session(&state.pool, user_id).await;
        let cookie_name = &state.config.session.cookie_name;

        let body = serde_json::json!({ "username": "new_username_ok" });
        let request = get_request_update_user(&body, session_id, cookie_name);

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes: bytes::Bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["message"], "success");
    }

    // Tests successful password update
    // Verifies:
    // - Endpoint returns 200 OK when updating password with valid old and new passwords
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_update_user_password(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let old_password = "Password123!";
        let hashed_password = hash_password(&state, old_password).await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed_password).await;
        let session_id = insert_session(&state.pool, user_id).await;
        let cookie_name = &state.config.session.cookie_name;

        let body = serde_json::json!({
            "old_password": old_password,
            "password1": "NewPassword123!",
            "password2": "NewPassword123!"
        });
        let request = get_request_update_user(&body, session_id, cookie_name);
        let status = app.oneshot(request).await.unwrap().status();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::OK);
    }

    // Tests that update fails with invalid data
    // Verifies:
    // - Returns 400 when username is too short
    // - Returns 400 when passwords don't match
    // - Returns 400 when new password is provided without old_password
    // - Returns 400 when new password fails validation rules
    #[rstest]
    #[case(serde_json::json!({ "username": "ab" }))]
    #[case(serde_json::json!({ "old_password": "Password123!", "password1": "NewPassword123!", "password2": "OtherPassword123!" }))]
    #[case(serde_json::json!({ "password1": "NewPassword123!", "password2": "NewPassword123!" }))]
    #[case(serde_json::json!({ "old_password": "Password123!", "password1": "weak", "password2": "weak" }))]
    #[tokio::test]
    #[serial]
    async fn test_update_user_invalid_data(
        #[case] body: Value,
        #[future] init_test_app_state: anyhow::Result<AppState>,
    ) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed_password = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed_password).await;
        let session_id = insert_session(&state.pool, user_id).await;
        let cookie_name = &state.config.session.cookie_name;

        let request = get_request_update_user(&body, session_id, cookie_name);
        let status = app.oneshot(request).await.unwrap().status();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // Tests that update fails for unauthenticated requests
    // Verifies:
    // - Endpoint returns 401 UNAUTHORIZED when no session cookie is provided
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_update_user_unauthorized(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let body = serde_json::json!({ "username": "new_username_ok" });
        let request = Request::builder()
            .method("PATCH")
            .uri("/users")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }
}
