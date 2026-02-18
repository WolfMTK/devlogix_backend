use bytes::Bytes;

#[derive(Debug, Clone)]
pub struct CreateWorkspaceDTO {
    pub owner_user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub logo: Option<Bytes>,
    pub primary_color: String,
    pub visibility: String,
}
