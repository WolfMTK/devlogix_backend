use axum::response::Html;
use axum::Json;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::openapi::OpenApi as OpenApiDoc;
use utoipa::{Modify, OpenApi};

use crate::adapter::http::app_error_impl::ErrorResponse;
use crate::adapter::http::routes::{auth, project, user, workspace};
use crate::adapter::http::schema::auth::{LoginRequest, MessageResponse, ResendConfirmationRequest};
use crate::adapter::http::schema::id::IdResponse;
use crate::adapter::http::schema::password_reset::{ForgotPasswordResetRequest, ResetPasswordRequest};
use crate::adapter::http::schema::project::CreateProjectRequest;
use crate::adapter::http::schema::user::{CreateUserRequest, GetUserResponse, UpdateUserRequest};
use crate::adapter::http::schema::workspace::{
    CreateWorkspaceRequest, GetWorkspaceResponse, InviteWorkspaceMemberRequest, WorkspaceListResponse,
};
use crate::adapter::http::schema::ValidPassword;

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
        auth::reset_password,
        workspace::create_workspace,
        workspace::get_workspace_list,
        workspace::get_workspace,
        workspace::get_owner_workspace,
        workspace::update_workspace,
        workspace::delete_workspace,
        workspace::check_workspace_owner,
        workspace::invite_workspace_member,
        workspace::accept_workspace_invite,
        workspace::get_workspace_logo,
        project::create_project
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
            ResetPasswordRequest,
            CreateWorkspaceRequest,
            GetWorkspaceResponse,
            WorkspaceListResponse,
            InviteWorkspaceMemberRequest,
            CreateProjectRequest
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
