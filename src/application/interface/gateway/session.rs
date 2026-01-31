use crate::{
    application::app_error::AppResult,
    domain::entities::{
        id::Id,
        session::Session,
        user::User
    }
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
pub trait SessionWriter: Send + Sync {
    async fn insert(&self, session: Session) -> AppResult<Id<Session>>;
    async fn update_activity(&self, session_id: &Id<Session>, now: DateTime<Utc>) -> AppResult<()>;
    async fn rotate(
        &self,
        old_session_id: &Id<Session>,
        new_session: Session,
    ) -> AppResult<Id<Session>>;
    async fn delete(&self, session_id: &Id<Session>) -> AppResult<()>;
    async fn delete_by_user_id(&self, user_id: &Id<User>) -> AppResult<()>;
}

#[async_trait]
pub trait SessionReader: Send + Sync {
    async fn find_by_id(&self, session_id: &Id<Session>) -> AppResult<Option<Session>>;
}
