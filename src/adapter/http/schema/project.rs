use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use serde_json::json;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "workspace_id": "019c47ec-183d-744e-b11d-cd409015bf13",
    "name": "My Project",
    "description": "A project for tracking tasks",
    "project_key": "MYPROJ",
    "type_project": "scrum",
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
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "total": 2,
    "page": 1,
    "per_page": 20,
    "items": [
        {
            "id": "019c47ec-183d-744e-b11d-cd409015bf14",
            "workspace_id": "019c47ec-183d-744e-b11d-cd409015bf13",
            "name": "My Project",
            "description": null,
            "project_key": "MYPROJ",
            "type_project": "scrum",
            "visibility": "private",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z"
        }
    ]
}))]
pub struct ProjectListResponse {
    #[schema(example = 2)]
    pub total: i64,
    #[schema(example = 1)]
    pub page: i64,
    #[schema(example = 20)]
    pub per_page: i64,
    pub items: Vec<GetProjectResponse>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": "019c47ec-183d-744e-b11d-cd409015bf14",
    "workspace_id": "019c47ec-183d-744e-b11d-cd409015bf13",
    "name": "My Project",
    "description": "A project for tracking tasks",
    "project_key": "MYPROJ",
    "type_project": "scrum",
    "visibility": "private",
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z"
}))]
pub struct GetProjectResponse {
    #[schema(example = "019c47ec-183d-744e-b11d-cd409015bf14")]
    pub id: String,
    #[schema(example = "019c47ec-183d-744e-b11d-cd409015bf13")]
    pub workspace_id: String,
    #[schema(example = "My Project")]
    pub name: String,
    #[schema(example = "A project for tracking tasks")]
    pub description: Option<String>,
    #[schema(example = "MYPROJ")]
    pub project_key: String,
    #[schema(example = "scrum")]
    pub type_project: String,
    #[schema(example = "private")]
    pub visibility: String,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
