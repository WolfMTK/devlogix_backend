use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "workspace_id": "019c47ec-183d-744e-b11d-cd409015bf13",
    "name": "My Project",
    "description": "A project for tracking tasks",
    "project_key": "MYPROJ",
    "type_project": "scrum",
    "visibility": "private"
}))]
pub struct CreateProjectRequest {
    #[schema(example = "019c47ec-183d-744e-b11d-cd409015bf13")]
    pub workspace_id: String,
    #[schema(example = "My Project")]
    pub name: String,
    #[schema(example = "A project for tracking tasks")]
    pub description: Option<String>,
    #[schema(example = "MYPROJ")]
    pub project_key: String,
    #[schema(example = "scrum", value_type = String)]
    pub type_project: String,
    #[schema(example = "private", value_type = String)]
    pub visibility: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ProjectListResponse {
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
    pub items: Vec<GetProjectResponse>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct GetProjectResponse {
    pub id: String,
    pub workspace_id: String,
    pub name: String,
    pub description: Option<String>,
    pub project_key: String,
    pub type_project: String,
    pub visibility: String,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
