use serde::{Deserialize, Serialize};
use serde_email::Email;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: Email,
    pub password: String,
    pub remember_me: bool,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct ResendConfirmationRequest {
    pub email: Email,
}
