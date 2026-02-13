use crate::domain::entities::{
    id::Id,
    user::User
};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct Workspace {
    id: Id<Workspace>,
    owner_user_id: Id<User>,
    name: String,
    slug: String,
    description: String,
    logo: String,
    primary_color: String,
    visibility: String,
    updated_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct WorkspaceMember {
    id: Id<WorkspaceMember>,
    workspace_id: Id<Workspace>,
    user_id: Id<User>,
    role: String,
    joined_at: DateTime<Utc>,
    invited_by: Id<User>,
    status: String,
}

#[derive(Debug, Clone)]
pub struct WorkspaceInvite {
    id: Id<WorkspaceInvite>,
    workspace_id: Id<Workspace>,
    email: String,
    role: String,
    invite_token: String,
    invited_by: Id<User>,
    expires_at: DateTime<Utc>,
    accepted_at: DateTime<Utc>,
    revoked_at: DateTime<Utc>,
}
