#[derive(Debug)]
pub struct RequestPasswordResetDTO {
    pub email: String,
    pub ttl: i64,
    pub reset_url: String,
}

#[derive(Debug)]
pub struct ResetPasswordDTO {
    pub token: String,
    pub password: String,
}
