use crate::{
    application::app_error::AppResult,
    domain::entities::{id::Id, user::User},
};
use async_trait::async_trait;

#[async_trait]
pub trait UserWriter: Send + Sync {
    async fn insert(&self, user: User) -> AppResult<Id<User>>;
}

#[async_trait]
pub trait UserReader: Send + Sync {
    async fn find_by_email(&self, email: &str) -> AppResult<Option<User>>;
    async fn find_by_id(&self, user_id: &Id<User>) -> AppResult<Option<User>>;
}
