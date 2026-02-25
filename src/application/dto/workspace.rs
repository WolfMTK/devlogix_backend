use bytes::Bytes;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct CreateWorkspaceDTO {
    pub owner_user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub logo: Option<Bytes>,
    pub primary_color: String,
    pub visibility: String,
}

#[derive(Debug, Clone)]
pub struct WorkspaceDTO {
    pub id: String,
    pub owner_user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub slug: String,
    pub logo: Option<String>,
    pub primary_color: String,
    pub visibility: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub total_members: i64,
    pub total_projects: i64,
    pub user_role: String,
}

#[derive(Debug, Clone)]
pub struct GetWorkspaceListDTO {
    pub user_id: String,
    pub page: i64,
    pub per_page: i64,
}

#[derive(Debug, Clone)]
pub struct WorkspaceListDTO {
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
    pub items: Vec<WorkspaceDTO>,
}

#[derive(Debug, Clone)]
pub struct GetWorkspaceLogoDTO {
    pub user_id: String,
    pub workspace_id: String,
    pub file_name: String,
}

#[derive(Debug, Clone)]
pub struct WorkspaceLogoDTO {
    pub data: Bytes,
    pub content_type: String,
}

#[derive(Debug, Clone)]
pub struct UpdateWorkspaceDTO {
    pub user_id: String,
    pub workspace_id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub primary_color: Option<String>,
    pub visibility: Option<String>,
    pub logo: Option<Bytes>,
}

#[derive(Debug, Clone)]
pub struct DeleteWorkspaceDTO {
    pub user_id: String,
    pub workspace_id: String,
}

#[derive(Debug, Clone)]
pub struct CheckWorkspaceOwnerDTO {
    pub user_id: String,
    pub workspace_id: String,
}

#[derive(Debug, Clone)]
pub struct InviteWorkspaceMemberDTO {
    pub user_id: String,
    pub workspace_id: String,
    pub email: String,
    pub ttl: i64,
    pub invite_url: String,
}

#[derive(Debug, Clone)]
pub struct AcceptWorkspaceInviteDTO {
    pub user_id: String,
    pub token: String,
}

#[derive(Debug, Clone)]
pub struct GetWorkspaceDTO {
    pub user_id: String,
    pub workspace_id: String,
    pub slug: String,
}

#[derive(Debug, Clone)]
pub struct SetWorkspacePinDTO {
    pub user_id: String,
    pub workspace_id: String,
}
