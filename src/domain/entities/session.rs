use chrono::{DateTime, Utc};

use crate::domain::entities::id::Id;
use crate::domain::entities::user::User;

#[derive(Debug, Clone)]
pub struct Session {
    pub id: Id<Session>,
    pub user_id: Id<User>,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub last_rotation: DateTime<Utc>,
    pub remember_me: bool,
}
