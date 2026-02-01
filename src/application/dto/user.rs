use chrono::{DateTime, Utc};

#[derive(Debug)]
pub struct CreateUserDTO {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct UserDTO {
    pub id: String,
    pub username: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
