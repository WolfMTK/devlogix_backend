use serde::Deserialize;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWorkspaceRequest {
    pub name: String,
    pub description: Option<String>,
    pub primary_color: String,
    pub visibility: String,
    #[schema(value_type = String, format = Binary, required = false)]
    pub logo: Option<Vec<u8>>,
}
