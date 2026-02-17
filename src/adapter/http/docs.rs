use axum::Json;
use axum::response::Html;
use utoipa::openapi::OpenApi as OpenApiDoc;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::adapter::http::app_error_impl::ErrorResponse;
use crate::adapter::http::routes::{auth, user};
use crate::adapter::http::schema::ValidPassword;
use crate::adapter::http::schema::auth::{LoginRequest, MessageResponse, ResendConfirmationRequest};
use crate::adapter::http::schema::id::IdResponse;
use crate::adapter::http::schema::password_reset::{ForgotPasswordResetRequest, ResetPasswordRequest};
use crate::adapter::http::schema::user::{CreateUserRequest, GetUserResponse, UpdateUserRequest};

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut OpenApiDoc) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "cookieAuth",
                SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new("session_id"))),
            );
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    modifiers(&SecurityAddon),
    paths(
        user::register,
        user::get_me,
        user::update_user,
        auth::login,
        auth::logout,
        auth::confirm_email,
        auth::resend_confirmation,
        auth::forgot_password,
        auth::reset_password
    ),
    components(
        schemas(
            ErrorResponse,
            LoginRequest,
            MessageResponse,
            ResendConfirmationRequest,
            IdResponse,
            CreateUserRequest,
            GetUserResponse,
            UpdateUserRequest,
            ValidPassword,
            ForgotPasswordResetRequest,
            ResetPasswordRequest
        )
    )
)]
pub struct ApiDoc;

pub async fn openapi_json() -> Json<OpenApiDoc> {
    Json(ApiDoc::openapi())
}

pub async fn docs_ui() -> Html<&'static str> {
    Html(
        r#"
            <!doctype html>
            <html>
              <head>
                <title>API docs</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <script src="https://unpkg.com/@stoplight/elements/web-components.min.js"></script>
                <link rel="stylesheet" href="https://unpkg.com/@stoplight/elements/styles.min.css">
              </head>
              <body style="height: 100%; margin: 0;">
                <elements-api
                  apiDescriptionUrl="openapi.json"
                  basePath="/"
                  router="hash"
                />
              </body>
            </html>
        "#,
    )
}
