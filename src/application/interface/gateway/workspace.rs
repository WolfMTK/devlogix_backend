use async_trait::async_trait;

use crate::application::app_error::AppResult;
use crate::domain::entities::id::Id;
use crate::domain::entities::workspace::Workspace;

#[async_trait]
pub trait WorkspaceWriter: Send + Sync {
    async fn insert(&self, workspace: Workspace) -> AppResult<Id<Workspace>>;
}
