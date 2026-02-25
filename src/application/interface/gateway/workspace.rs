use async_trait::async_trait;

use crate::application::app_error::AppResult;
use crate::domain::entities::id::Id;
use crate::domain::entities::user::User;
use crate::domain::entities::workspace::{Workspace, WorkspaceInvite, WorkspaceMember, WorkspacePin, WorkspaceView};

#[async_trait]
pub trait WorkspaceWriter: Send + Sync {
    async fn insert(&self, workspace: Workspace) -> AppResult<Id<Workspace>>;
    async fn update(&self, workspace: Workspace) -> AppResult<()>;
    async fn delete(&self, workspace_id: &Id<Workspace>) -> AppResult<()>;
}

#[async_trait]
pub trait WorkspaceReader: Send + Sync {
    async fn get(&self, workspace_id: &Id<Workspace>, user_id: &Id<User>) -> AppResult<Option<WorkspaceView>>;
    async fn find_accessible_by_user(
        &self,
        user_id: &Id<User>,
        limit: i64,
        offset: i64,
    ) -> AppResult<Vec<WorkspaceView>>;
    async fn count_accessible_by_user(&self, user_id: &Id<User>) -> AppResult<i64>;
    async fn is_accessible_by_user(&self, workspace_id: &Id<Workspace>, user_id: &Id<User>) -> AppResult<bool>;
    async fn find_by_id_and_slug(
        &self,
        workspace_id: &Id<Workspace>,
        user_id: &Id<User>,
        slug: &str,
    ) -> AppResult<Option<WorkspaceView>>;
}

#[async_trait]
pub trait WorkspaceInviteWriter: Send + Sync {
    async fn insert(&self, workspace_invite: WorkspaceInvite) -> AppResult<Id<WorkspaceInvite>>;
    async fn accept(&self, workspace_invite_id: &Id<WorkspaceInvite>) -> AppResult<()>;
    async fn delete_by_email(&self, workspace_id: &Id<Workspace>, email: &str) -> AppResult<()>;
}

#[async_trait]
pub trait WorkspaceInviteReader: Send + Sync {
    async fn find_by_token(&self, token: &str) -> AppResult<Option<WorkspaceInvite>>;
    async fn find_by_email(&self, workspace_id: &Id<Workspace>, email: &str) -> AppResult<Option<WorkspaceInvite>>;
}

#[async_trait]
pub trait WorkspaceMemberWriter: Send + Sync {
    async fn insert(&self, workspace_member: WorkspaceMember) -> AppResult<Id<WorkspaceMember>>;
}

#[async_trait]
pub trait WorkspaceMemberReader: Send + Sync {
    async fn get(&self, workspace_id: &Id<Workspace>, user_id: &Id<User>) -> AppResult<Option<WorkspaceMember>>;
}

#[async_trait]
pub trait WorkspacePinReader: Send + Sync {
    async fn get(&self, user_id: &Id<User>) -> AppResult<Option<WorkspacePin>>;
}

#[async_trait]
pub trait WorkspacePinWriter: Send + Sync {
    async fn set_workspace_pin(&self, workspace_id: &Id<Workspace>, user_id: &Id<User>) -> AppResult<()>;
}
