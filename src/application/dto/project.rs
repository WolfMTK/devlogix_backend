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
