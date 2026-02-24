use serde::Deserialize;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateProjectRequest {
    pub workspace_id: String,
    pub name: String,
    pub description: Option<String>,
    pub project_key: String,
    pub type_project: String,
    pub visibility: String,
}
