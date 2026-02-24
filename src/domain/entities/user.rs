use chrono::{DateTime, Utc};

use crate::domain::entities::id::Id;

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
