use crate::{
    application::app_error::AppResult,
    domain::entities::{
        id::Id,
        user::User
    }
};
use async_trait::async_trait;

#[async_trait]
pub trait UserWriter: Send + Sync {
    async fn insert(&self, user: User) -> AppResult<Id<User>>;
}
