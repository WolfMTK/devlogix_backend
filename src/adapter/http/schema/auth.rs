use serde::{Deserialize, Serialize};
use serde_email::Email;
#[allow(unused_imports)]
use serde_json::json;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    #[schema(value_type = String, format = Email)]
    pub email: Email,
    pub password: String,
    pub remember_me: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({ "message": "Operation completed successfully" }))]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({ "email": "user@example.com" }))]
pub struct ResendConfirmationRequest {
    #[schema(value_type = String, format = Email)]
    pub email: Email,
}
