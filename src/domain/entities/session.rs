use crate::domain::entities::{
    id::Id,
    user::User
};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct Session {
    pub id: Id<Session>,
    pub user_id: Id<User>,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub last_rotation: DateTime<Utc>,
    pub remember_me: bool,
}
