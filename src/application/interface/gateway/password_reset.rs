use async_trait::async_trait;

use crate::application::app_error::AppResult;
use crate::domain::entities::id::Id;
use crate::domain::entities::password_reset::PasswordResetToken;
use crate::domain::entities::user::User;

#[async_trait]
pub trait PasswordResetTokenWriter: Send + Sync {
    async fn insert(&self, token: PasswordResetToken) -> AppResult<Id<PasswordResetToken>>;
    async fn mark_as_used(&self, token_id: &Id<PasswordResetToken>) -> AppResult<()>;
    async fn delete(&self, user_id: &Id<User>) -> AppResult<()>;
}

#[async_trait]
pub trait PasswordResetTokenReader: Send + Sync {
    async fn find_by_token(&self, token: &str) -> AppResult<Option<PasswordResetToken>>;
}
