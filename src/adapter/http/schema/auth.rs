use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub remember_me: bool,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}
