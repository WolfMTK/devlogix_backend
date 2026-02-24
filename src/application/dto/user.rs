use chrono::{DateTime, Utc};

#[derive(Debug)]
pub struct CreateUserDTO {
    pub username: String,
    pub email: String,
    pub password1: String,
    pub password2: String,
}

#[derive(Debug, Clone)]
pub struct UserDTO {
    pub id: String,
    pub username: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct UpdateUserDTO {
    pub id: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub old_password: Option<String>,
    pub password1: Option<String>,
    #[allow(dead_code)]
    pub password2: Option<String>,
}
