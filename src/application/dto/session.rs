use crate::domain::entities::id::Id;
use crate::domain::entities::session::Session;
use crate::domain::entities::user::User;

#[derive(Debug)]
pub struct SessionDTO {
    pub id: String,
    pub default_max_lifetime: i64,
    pub default_idle_timeout: i64,
    pub remembered_max_lifetime: i64,
    pub remembered_idle_timeout: i64,
    pub rotation_interval: i64,
}

#[derive(Debug, Clone)]
pub struct GetSessionStatusDTO {
    pub status: SessionValidationResult,
}

#[derive(Debug, Clone)]
pub enum SessionValidationResult {
    Valid(Id<User>),
    Rotated {
        user_id: Id<User>,
        new_session_id: Id<Session>,
    },
    Expired,
    Invalid,
}
