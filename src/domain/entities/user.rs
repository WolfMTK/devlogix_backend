use crate::domain::entities::id::Id;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct User {
    pub id: Id<User>,
    pub username: String,
    pub email: String,
    pub password: String,
    pub is_confirmed: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn new(username: String, email: String, password: String) -> Self {
        let now = Utc::now();
        Self {
            id: Id::generate(),
            username,
            email,
            password,
            is_confirmed: false,
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UserInput {
    pub id: Id<UserInput>,
    pub user_id: Id<User>,
    device_name: String,
    device_type: String,
    browser: String,
    ip_address: String,
    country: String,
    city: String,
    is_current: bool,
    is_suspicious: bool,
    suspicious_reason: String,
    updated_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

