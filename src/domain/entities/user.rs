use crate::domain::entities::id::Id;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct User {
    pub id: Id<User>,
    pub username: String,
    pub email: String,
    pub password: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
