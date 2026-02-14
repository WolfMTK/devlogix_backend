use axum::{response::Html, Json};
use utoipa::{
    openapi::{
        security::{ApiKey, ApiKeyValue, SecurityScheme},
        OpenApi as OpenApiDoc,
    }, Modify,
    OpenApi,
};

use crate::adapter::http::{
    app_error_impl::ErrorResponse,
    routes::{auth, user},
    schema::{
        auth::{LoginRequest, MessageResponse, ResendConfirmationRequest},
        id::IdResponse,
        user::{CreateUserRequest, GetUserResponse, UpdateUserRequest, ValidPassword},
    },
};

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
        auth::resend_confirmation
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
            ValidPassword
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
