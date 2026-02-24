use async_trait::async_trait;

use crate::application::app_error::AppResult;
use crate::domain::entities::id::Id;
use crate::domain::entities::project::Project;

#[async_trait]
pub trait ProjectWriter: Send + Sync {
    async fn insert(&self, project: Project) -> AppResult<Id<Project>>;
}

#[async_trait]
pub trait ProjectReader: Send + Sync {
    async fn check_project_key(&self, project_key: &str) -> AppResult<bool>;
}
