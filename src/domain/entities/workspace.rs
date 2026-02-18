use chrono::{DateTime, Utc};

use crate::domain::entities::id::Id;
use crate::domain::entities::user::User;

#[derive(Debug, Clone)]
pub enum WorkspaceVisibility {
    Private,
    Public,
}

#[derive(Debug, Clone)]
pub struct Workspace {
    pub id: Id<Workspace>,
    pub owner_user_id: Id<User>,
    pub name: String,
    pub description: Option<String>,
    pub slug: String,
    pub logo: Option<String>,
    pub primary_color: String,
    pub visibility: WorkspaceVisibility,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub enum WorkspaceMemberRole {
    Admin,
    Member,
}

#[derive(Debug, Clone)]
pub enum WorkspaceMemberStatus {
    Awaiting,
    Active,
    Inactive,
}

#[derive(Debug, Clone)]
pub struct WorkspaceMember {
    pub id: Id<WorkspaceMember>,
    pub workspace_id: Id<Workspace>,
    pub user_id: Id<User>,
    pub role: WorkspaceMemberRole,
    pub joined_at: Option<DateTime<Utc>>,
    pub invited_by: Id<User>,
    pub status: WorkspaceMemberStatus,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct WorkspaceInvite {
    pub id: Id<WorkspaceInvite>,
    pub workspace_id: Id<Workspace>,
    pub email: String,
    pub status: String,
    pub invite_token: String,
    pub invited_by: Id<User>,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
