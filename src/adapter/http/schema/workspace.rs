use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_email::Email;
#[allow(unused_imports)]
use serde_json::json;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

#[derive(Debug, Deserialize, ToSchema)]
#[allow(dead_code)]
#[schema(example = json!({
    "name": "My Workspace",
    "description": "A workspace for my team",
    "primary_color": "FF5733",
    "visibility": "private"
}))]
pub struct CreateWorkspaceRequest {
    #[schema(example = "My Workspace")]
    pub name: String,
    #[schema(example = "A workspace for my team")]
    pub description: Option<String>,
    #[schema(example = "FF5733")]
    pub primary_color: String,
    #[schema(example = "private")]
    pub visibility: String,
    #[schema(value_type = String, format = Binary, required = false)]
    pub logo: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({
    "id": "019c47ec-183d-744e-b11d-cd409015bf13",
    "owner_user_id": "019c47ec-183d-744e-b11d-cd409015bf14",
    "name": "My Workspace",
    "description": "A workspace for my team",
    "slug": "my-workspace",
    "logo": null,
    "primary_color": "FF5733",
    "visibility": "private",
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
    "total_members": 3,
    "total_projects": 5,
    "user_role": "owner"
}))]
pub struct GetWorkspaceResponse {
    #[schema(example = "019c47ec-183d-744e-b11d-cd409015bf13")]
    pub id: String,
    #[schema(example = "019c47ec-183d-744e-b11d-cd409015bf14")]
    pub owner_user_id: String,
    #[schema(example = "My Workspace")]
    pub name: String,
    #[schema(example = "A workspace for my team")]
    pub description: Option<String>,
    #[schema(example = "my-workspace")]
    pub slug: String,
    #[schema(example = json!(null))]
    pub logo: Option<String>,
    #[schema(example = "FF5733")]
    pub primary_color: String,
    #[schema(example = "private")]
    pub visibility: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[schema(example = 3)]
    pub total_members: i64,
    #[schema(example = 5)]
    pub total_projects: i64,
    #[schema(example = "owner")]
    pub user_role: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({
    "page": 1,
    "total": 2,
    "per_page": 20,
    "items": [
        {
            "id": "019c47ec-183d-744e-b11d-cd409015bf13",
            "owner_user_id": "019c47ec-183d-744e-b11d-cd409015bf14",
            "name": "My Workspace",
            "description": null,
            "slug": "my-workspace",
            "logo": null,
            "primary_color": "FF5733",
            "visibility": "private",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "total_members": 1,
            "total_projects": 0,
            "user_role": "owner"
        }
    ]
}))]
pub struct WorkspaceListResponse {
    #[schema(example = 1)]
    pub page: i64,
    #[schema(example = 2)]
    pub total: i64,
    #[schema(example = 20)]
    pub per_page: i64,
    pub items: Vec<GetWorkspaceResponse>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
#[schema(example = json!({ "email": "invitee@example.com" }))]
pub struct InviteWorkspaceMemberRequest {
    #[schema(value_type = String, format = Email, example = "invitee@example.com")]
    pub email: Email,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct AcceptInviteQuery {
    #[param(example = "a1b2c3d4e5f6")]
    pub token: String,
}
