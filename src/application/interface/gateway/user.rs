use crate::{
    application::app_error::AppResult,
    domain::entities::{id::Id, user::User},
};
use async_trait::async_trait;

#[async_trait]
pub trait UserWriter: Send + Sync {
    async fn insert(&self, user: User) -> AppResult<Id<User>>;
    async fn update(&self, user: User) -> AppResult<Id<User>>;
}

#[async_trait]
pub trait UserReader: Send + Sync {
    async fn find_by_email(&self, email: &str) -> AppResult<Option<User>>;
    async fn is_user(&self, username: &str, email: &str) -> AppResult<bool>;
    async fn find_by_id(&self, user_id: &Id<User>) -> AppResult<Option<User>>;
    async fn is_username_or_email_unique(
        &self,
        user_id: &Id<User>,
        username: &str,
        email: &str,
    ) -> AppResult<bool>;
}
