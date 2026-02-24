use serde::{Deserialize, Serialize};
use serde_email::Email;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    #[schema(value_type = String, format = Email)]
    pub email: Email,
    pub password: String,
    pub remember_me: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ResendConfirmationRequest {
    #[schema(value_type = String, format = Email)]
    pub email: Email,
}
