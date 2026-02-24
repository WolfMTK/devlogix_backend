use async_trait::async_trait;

use crate::application::app_error::AppResult;
use crate::domain::entities::id::Id;
use crate::domain::entities::project::Project;
use crate::domain::entities::workspace::Workspace;

#[async_trait]
pub trait ProjectWriter: Send + Sync {
    async fn insert(&self, project: Project) -> AppResult<Id<Project>>;
}

#[async_trait]
pub trait ProjectReader: Send + Sync {
    async fn check_project_key(&self, project_key: &str) -> AppResult<bool>;
    async fn get_all(&self, workspace_id: &Id<Workspace>, limit: i64, offset: i64) -> AppResult<Vec<Project>>;
    async fn count_projects(&self, workspace_id: &Id<Workspace>) -> AppResult<i64>;
    async fn get(&self, workspace_id: &Id<Workspace>, project_id: &Id<Project>) -> AppResult<Option<Project>>;
}
