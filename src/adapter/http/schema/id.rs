use serde::Serialize;
#[allow(unused_imports)]
use serde_json::json;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "id": "019c47ec-183d-744e-b11d-cd409015bf13" }))]
pub struct IdResponse {
    #[schema(example = "019c47ec-183d-744e-b11d-cd409015bf13")]
    pub id: String,
}
