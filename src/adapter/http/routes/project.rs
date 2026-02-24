use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::adapter::http::app_error_impl::ErrorResponse;
use crate::adapter::http::middleware::extractor::AuthUser;
use crate::adapter::http::schema::auth::MessageResponse;
use crate::adapter::http::schema::project::CreateProjectRequest;
use crate::application::app_error::AppResult;
use crate::application::dto::project::CreateProjectDTO;
use crate::application::interactors::project::CreateProjectInteractor;

#[utoipa::path(
    post,
    path = "/projects",
    tag = "Projects",
    request_body(
        content = CreateProjectRequest,
        example = json!(
            {
                "workspace_id": "019c47ec-183d-744e-b11d-cd409015bf13",
                "name": "My Project",
                "description": "A sample project",
                "project_key": "MYPROJ",
                "type_project": "software",
                "visibility": "private"
            }
        )
    ),
    responses(
        (
            status = 201,
            description = "Project created successfully",
            body = MessageResponse,
            example = json!(
                {
                    "message": "Project created successfully"
                }
            )
        ),
        (
            status = 400,
            description = "Validation error, project key already exists, or invalid field values",
            body = ErrorResponse,
            example = json!(
                {
                    "error": "Project already exists"
                }
            )
        ),
        (
            status = 401,
            description = "Not authenticated or no access to the workspace",
            body = ErrorResponse,
            example = json!(
                {
                    "error": "Invalid Credentials"
                }
            )
        ),
        (
            status = 403,
            description = "Workspace not found or access denied",
            body = ErrorResponse,
            example = json!(
                {
                    "error": "Workspace not found"
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
pub async fn create_project(
    auth_user: AuthUser,
    interactor: CreateProjectInteractor,
    Json(paload): Json<CreateProjectRequest>,
) -> AppResult<impl IntoResponse> {
    let dto = CreateProjectDTO {
        user_id: auth_user.user_id,
        workspace_id: paload.workspace_id,
        name: paload.name,
        description: paload.description,
        project_key: paload.project_key,
        type_project: paload.type_project,
        visibility: paload.visibility,
    };
    interactor.execute(dto).await?;
    Ok((
        StatusCode::CREATED,
        Json(MessageResponse {
            message: "Project created successfully".to_string(),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use rstest::rstest;
    use serde_json::Value;
    use serial_test::serial;
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::infra::app::create_app;
    use crate::infra::state::AppState;
    use crate::tests::fixtures::init_test_app_state;
    use crate::tests::helpers::{
        delete_user, hash_password, insert_confirmed_user, insert_session, insert_workspace, session_cookie,
        unique_credentials, unique_project_key,
    };

    // === create_project ===
    fn get_request_create_project(body: &Value, session_id: Uuid, cookie_name: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/projects")
            .header("content-type", "application/json")
            .header("cookie", session_cookie(session_id, cookie_name))
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap()
    }

    // Tests successful project creation inside an accessible workspace
    // Verifies:
    // - Endpoint returns 201 CREATED
    // - Response contains success message "Project created successfully"
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_create_project_success(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed).await;
        let session_id = insert_session(&state.pool, user_id).await;
        let cookie_name = state.config.session.cookie_name.clone();

        let workspace_id = insert_workspace(&state.pool, user_id, "Test Workspace").await;

        let body = serde_json::json!({
            "workspace_id": workspace_id.to_string(),
            "name": "Test Project",
            "description": "A test project",
            "project_key": unique_project_key(),
            "type_project": "scrum",
            "visibility": "private"
        });

        let req = get_request_create_project(&body, session_id, &cookie_name);
        let status = app.oneshot(req).await.unwrap().status();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::CREATED);
    }

    // Tests that project creation fails without authentication
    // Verifies:
    // - Endpoint returns 401 UNAUTHORIZED when no session cookie is provided
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_create_project_unauthorized(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let body = serde_json::json!({
            "workspace_id": Uuid::now_v7().to_string(),
            "name": "Test Project",
            "project_key": unique_project_key(),
            "type_project": "scrum",
            "visibility": "private"
        });

        let req = Request::builder()
            .method("POST")
            .uri("/projects")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }

    // Tests that project creation fails when user has no access to the workspace
    // Verifies:
    // - Endpoint returns 401 UNAUTHORIZED when workspace belongs to another user
    //   (CreateProjectInteractor returns AppError::InvalidCredentials for inaccessible workspaces)
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_create_project_no_workspace_access(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username_owner, email_owner) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let owner_id = insert_confirmed_user(&state.pool, &username_owner, &email_owner, &hashed).await;
        let workspace_id = insert_workspace(&state.pool, owner_id, "Owner Workspace").await;

        let (username_other, email_other) = unique_credentials();
        let other_id = insert_confirmed_user(&state.pool, &username_other, &email_other, &hashed).await;
        let other_session = insert_session(&state.pool, other_id).await;
        let cookie_name = state.config.session.cookie_name.clone();

        let body = serde_json::json!({
            "workspace_id": workspace_id.to_string(),
            "name": "Intruder Project",
            "project_key": unique_project_key(),
            "type_project": "kanban",
            "visibility": "private"
        });

        let req = get_request_create_project(&body, other_session, &cookie_name);
        let status = app.oneshot(req).await.unwrap().status();

        delete_user(&state.pool, owner_id).await;
        delete_user(&state.pool, other_id).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // Tests that project creation fails when project_key is already taken
    // Verifies:
    // - Endpoint returns 400 BAD_REQUEST when the same project_key is used twice
    //   (AppError::ProjectAlreadyExists => 400)
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_create_project_duplicate_key(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed).await;
        let session_id = insert_session(&state.pool, user_id).await;
        let cookie_name = state.config.session.cookie_name.clone();

        let workspace_id = insert_workspace(&state.pool, user_id, "Dup Key Workspace").await;

        let project_key = unique_project_key();
        let body = serde_json::json!({
            "workspace_id": workspace_id.to_string(),
            "name": "First Project",
            "project_key": project_key,
            "type_project": "kanban",
            "visibility": "private"
        });

        app.clone()
            .oneshot(get_request_create_project(&body, session_id, &cookie_name))
            .await
            .unwrap();

        let status = app
            .oneshot(get_request_create_project(&body, session_id, &cookie_name))
            .await
            .unwrap()
            .status();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // Tests that project creation fails for non-existent workspace
    // Verifies:
    // - Endpoint returns 401 UNAUTHORIZED when workspace_id does not exist
    //   (WorkspaceReader::is_accessible_by_user returns false => AppError::InvalidCredentials => 401)
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_create_project_nonexistent_workspace(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed).await;
        let session_id = insert_session(&state.pool, user_id).await;
        let cookie_name = state.config.session.cookie_name.clone();

        let body = serde_json::json!({
            "workspace_id": Uuid::now_v7().to_string(),
            "name": "Ghost Project",
            "project_key": unique_project_key(),
            "type_project": "scrum",
            "visibility": "private"
        });

        let status = app
            .oneshot(get_request_create_project(&body, session_id, &cookie_name))
            .await
            .unwrap()
            .status();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
