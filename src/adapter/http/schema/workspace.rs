use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_email::Email;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

#[derive(Debug, Deserialize, ToSchema)]
#[allow(dead_code)]
pub struct CreateWorkspaceRequest {
    pub name: String,
    pub description: Option<String>,
    pub primary_color: String,
    pub visibility: String,
    #[schema(value_type = String, format = Binary, required = false)]
    pub logo: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GetWorkspaceResponse {
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
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WorkspaceListResponse {
    pub page: i64,
    pub total: i64,
    pub per_page: i64,
    pub items: Vec<GetWorkspaceResponse>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct InviteWorkspaceMemberRequest {
    #[schema(value_type = String, format = Email, example = "user@example.com")]
    pub email: Email,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct AcceptInviteQuery {
    pub token: String,
}
