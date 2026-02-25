use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct CreateProjectDTO {
    pub user_id: String,
    pub workspace_id: String,
    pub name: String,
    pub description: Option<String>,
    pub project_key: String,
    pub type_project: String,
    pub visibility: String,
}

#[derive(Debug, Clone)]
pub struct GetProjectListDTO {
    pub user_id: String,
    pub workspace_id: String,
    pub page: i64,
    pub per_page: i64,
}

#[derive(Debug, Clone)]
pub struct ProjectDTO {
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

#[derive(Debug, Clone)]
pub struct ProjectListDTO {
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
    pub items: Vec<ProjectDTO>,
}

#[derive(Debug, Clone)]
pub struct GetProjectDTO {
    pub user_id: String,
    pub workspace_id: String,
    pub project_id: String,
}

#[derive(Debug, Clone)]
pub struct UpdateProjectDTO {
    pub user_id: String,
    pub workspace_id: String,
    pub project_id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub type_project: Option<String>,
    pub visibility: Option<String>,
}
