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
use crate::adapter::http::schema::password_reset::{ForgotPasswordResetRequest, ResetPasswordRequest};
use crate::adapter::http::validation::ValidJson;
use crate::application::app_error::AppResult;
use crate::application::dto::auth::LoginDTO;
use crate::application::dto::email_confirmation::{ConfirmEmailDTO, ResendConfirmationDTO};
use crate::application::dto::id::IdDTO;
use crate::application::dto::password_reset::{RequestPasswordResetDTO, ResetPasswordDTO};
use crate::application::interactors::auth::{LoginInteractor, LogoutInteractor};
use crate::application::interactors::email_confirmation::{ConfirmEmailInteractor, ResendConfirmationInteractor};
use crate::application::interactors::password_reset::{RequestPasswordResetInteractor, ResetPasswordInteractor};
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

#[utoipa::path(
    post,
    path = "/auth/forgot-password",
    tag = "Auth",
    request_body(
        content = ForgotPasswordResetRequest,
        example = json!(
            {
                "email": "user@example.com"
            }
        )
    ),
    responses(
        (
            status = 200,
            description = "Sending a password reset link",
            body = MessageResponse,
            example = json!(
                {
                    "message": "The link with password reset has been sent to the email"
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
pub async fn forgot_password(
    interactor: RequestPasswordResetInteractor,
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<ForgotPasswordResetRequest>,
) -> AppResult<impl IntoResponse> {
    interactor
        .execute(RequestPasswordResetDTO {
            email: payload.email.to_string(),
            ttl: config.password_reset.ttl,
            reset_url: config.password_reset.reset_url.clone(),
        })
        .await?;

    Ok((
        StatusCode::OK,
        Json(MessageResponse {
            message: "The link with password reset has been sent to the email".to_string(),
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/auth/reset-password",
    tag = "Auth",
    request_body(
        content = ResetPasswordRequest,
        example = json!(
            {
                "token": "019c47ec-2160-7e53-bf7e-06db2a1bad85",
                "password": "NewPassword123!"
            }
        )
    ),
    responses(
        (
            status = 200,
            description = "Password reset successfully",
            body = MessageResponse,
            example = json!(
                {
                    "message": "Password has been reset successfully"
                }
            )
        ),
        (
            status = 400,
            description = "Invalid, expired or already used token",
            body = ErrorResponse,
            example = json!(
                {
                    "error": "Invalid or expired password reset token"
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
pub async fn reset_password(
    interactor: ResetPasswordInteractor,
    ValidJson(payload): ValidJson<ResetPasswordRequest>,
) -> AppResult<impl IntoResponse> {
    interactor
        .execute(ResetPasswordDTO {
            token: payload.token,
            password: payload.password.value().to_string(),
        })
        .await?;

    Ok((
        StatusCode::OK,
        Json(MessageResponse {
            message: "Password has been reset successfully".to_string(),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::header::SET_COOKIE;
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
        delete_user, hash_password, insert_confirmed_user, insert_email_confirmation, insert_password_reset_token,
        insert_session, insert_unconfirmed_user, session_cookie, unique_credentials,
    };

    // === login ===
    fn get_request_login(body: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    // Tests successful login with valid credentials
    // Verifies:
    // - Endpoint returns 200 OK status when email and password are correct
    // - Response includes SET_COOKIE header with session cookie for authentication
    // - Response contains success message "Login successful"
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_login_success(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let password = "Password123!";
        let hashed_password = hash_password(&state, password).await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed_password).await;

        let body = serde_json::json!({ "email": email, "password": password, "remember_me": false });

        let request = get_request_login(body);

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let has_cookie = response.headers().get(SET_COOKIE).is_some();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::OK);
        assert!(has_cookie, "SET_COOKIE header expected on successful login");
        assert_eq!(json["message"], "Login successful");
    }

    // Tests that login fails with incorrect password
    // Verifies:
    // - Endpoint returns 401 UNAUTHORIZED status when password is wrong
    // - No session cookie is set for failed authentication attempts
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_login_invalid_password(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed_password = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed_password).await;

        let body = serde_json::json!({ "email": email, "password": "WrongPassword1!", "remember_me": false });

        let request = get_request_login(body);

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // Tests that login fails for unconfirmed email accounts
    // Verifies:
    // - Endpoint returns 403 FORBIDDEN status when user exists but email is not confirmed
    // - Prevents authentication for accounts that haven't completed email verification
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_login_unconfirmed_user(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let password = "Password123!";
        let hashed_password = hash_password(&state, password).await;
        let user_id = insert_unconfirmed_user(&state.pool, &username, &email, &hashed_password).await;

        let body = serde_json::json!({ "email": email, "password": password, "remember_me": false });

        let request = get_request_login(body);

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    // Tests that login fails for non-existent user accounts
    // Verifies:
    // - Endpoint returns 401 UNAUTHORIZED status when email is not registered
    // - Maintains consistent error response to prevent user enumeration
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_login_nonexistent_user(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let body = serde_json::json!({
            "email": "nobody_exists_xyz@auth.example",
            "password": "Password123!",
            "remember_me": false
        });

        let request = get_request_login(body);

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // === logout ===
    fn get_request_logout(session_id: Uuid, cookie_name: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/auth/logout")
            .header("cookie", session_cookie(session_id, cookie_name))
            .body(Body::empty())
            .unwrap()
    }

    // Tests successful logout with valid session
    // Verifies:
    // - Endpoint returns 200 OK status when authenticated with valid session cookie
    // - Response includes SET_COOKIE header with expired session cookie
    // - Session is properly terminated by clearing the cookie
    // - Response contains success message "Logged out successfully"
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_logout_success(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed_password = hash_password(&state, "Password123!").await;
        let user_id = insert_unconfirmed_user(&state.pool, &username, &email, &hashed_password).await;
        let session_id = insert_session(&state.pool, user_id).await;

        let cookie_name = &state.config.session.cookie_name;

        let request = get_request_logout(session_id, cookie_name);

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let cookie_value = response
            .headers()
            .get(SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            cookie_value.contains("Max-Age=0"),
            "logout cookie must expire the session, got: {cookie_value}"
        );
        assert_eq!(json["message"], "Logged out successfully");
    }

    // Tests that logout fails when no valid session cookie is provided
    // Verifies:
    // - Endpoint returns 401 UNAUTHORIZED status for unauthenticated logout attempts
    // - Prevents session termination without proper authentication
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_logout_invalid(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let request = Request::builder()
            .method("POST")
            .uri("/auth/logout")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // === confirm_email ===
    fn get_request_confirm_email(token: String) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(format!("/auth/confirm-email?token={}", token))
            .body(Body::empty())
            .unwrap()
    }

    // Tests successful email confirmation with valid token
    // Verifies:
    // - Endpoint returns 200 OK status when valid confirmation token is provided
    // - Email confirmation token is properly processed for unconfirmed user
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_confirm_email_success(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_unconfirmed_user(&state.pool, &username, &email, &hashed).await;
        let token = format!("confirm-{}", Uuid::now_v7().as_simple());
        insert_email_confirmation(&state.pool, user_id, &token).await;

        let request = get_request_confirm_email(token);

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::OK);
    }

    // Tests that email confirmation fails with invalid token
    // Verifies:
    // - Endpoint returns 400 BAD_REQUEST status when confirmation token is malformed or doesn't exist
    // - Prevents email confirmation with invalid or tampered tokens
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_confirm_email_invalid_token(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let request = get_request_confirm_email("invalid".to_string());

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();

        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // === resend_confirmation ===
    fn get_request_resend_confirmation(body: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/auth/resend-confirmation")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    // Tests successful resend of confirmation email for unconfirmed user
    // Verifies:
    // - Endpoint returns 200 OK status when requesting resend for existing unconfirmed email
    // - New confirmation token is generated and sent for unconfirmed account
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_resend_confirmation_success(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_unconfirmed_user(&state.pool, &username, &email, &hashed).await;

        let body = serde_json::json!({ "email": email });

        let request = get_request_resend_confirmation(body);

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::OK);
    }

    // Tests that resend confirmation fails for already confirmed accounts
    // Verifies:
    // - Endpoint returns 409 CONFLICT status when requesting resend for already confirmed email
    // - Prevents sending confirmation emails to already active accounts
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_resend_confirmation_already_confirmed(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed).await;

        let body = serde_json::json!({ "email": email });

        let request = get_request_resend_confirmation(body);

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::CONFLICT);
    }

    // === forgot_password ===
    fn get_request_forgot_password(body: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/auth/forgot-password")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    // Tests successful password reset request for confirmed user
    // Verifies:
    // - Endpoint returns 200 OK status when requesting password reset for existing confirmed email
    // - Password reset token is generated and sent to the user's email
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_forgot_password_success(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed).await;

        let body = serde_json::json!({ "email": email });

        let request = get_request_forgot_password(body);

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::OK);
    }

    // Tests that forgot password returns OK even for non-existent users (security measure)
    // Verifies:
    // - Endpoint returns 200 OK status even when email is not registered
    // - Prevents user enumeration by maintaining consistent response regardless of email existence
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_forgot_password_nonexistent_user_still(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let body = serde_json::json!({ "email": "ex@ex.example" });

        let request = get_request_forgot_password(body);

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();

        assert_eq!(status, StatusCode::OK);
    }

    // === reset_password ===
    fn get_request_reset_password(body: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/auth/reset-password")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    // Tests successful password reset with valid token
    // Verifies:
    // - Endpoint returns 200 OK status when valid reset token and new password are provided
    // - Password is successfully updated for the user associated with the reset token
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_reset_password_success(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed).await;
        let token = format!("reset-{}", Uuid::now_v7().as_simple());
        insert_password_reset_token(&state.pool, user_id, &token).await;

        let body = serde_json::json!({ "token": token, "password": "NewPassword123!" });

        let request = get_request_reset_password(body);

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::OK);
    }

    // Tests that password reset fails with invalid token
    // Verifies:
    // - Endpoint returns 400 BAD_REQUEST status when reset token is invalid or doesn't exist
    // - Prevents password reset with invalid, expired, or tampered tokens
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_reset_password_invalid_token(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let body = serde_json::json!({ "token": "invalid", "password": "NewPassword123!" });

        let request = get_request_reset_password(body);

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();

        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
