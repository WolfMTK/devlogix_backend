#[derive(Debug)]
pub struct LoginDTO {
    pub email: String,
    pub password: String,
    pub remember_me: bool,
}

#[derive(Debug, Clone)]
pub struct GetSessionIdDTO {
    pub session_id: String,
    pub remember_me: bool,
}
