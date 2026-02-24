use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::adapter::http::middleware::extractor::AuthUser;
use crate::adapter::http::schema::auth::MessageResponse;
use crate::adapter::http::schema::project::CreateProjectRequest;
use crate::application::app_error::AppResult;
use crate::application::dto::project::CreateProjectDTO;
use crate::application::interactors::project::CreateProjectInteractor;

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
