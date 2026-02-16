use async_trait::async_trait;

use crate::application::app_error::AppResult;
use crate::domain::entities::email_confirmation::EmailConfirmation;
use crate::domain::entities::id::Id;
use crate::domain::entities::user::User;

#[async_trait]
pub trait EmailConfirmationWriter: Send + Sync {
    async fn insert(&self, email_confirmation: EmailConfirmation) -> AppResult<Id<EmailConfirmation>>;
    async fn confirm(&self, confirmation_id: &Id<EmailConfirmation>) -> AppResult<()>;
    async fn delete(&self, user_id: &Id<User>) -> AppResult<()>;
}

#[async_trait]
pub trait EmailConfirmationReader: Send + Sync {
    async fn find_by_token(&self, token: &str) -> AppResult<Option<EmailConfirmation>>;
}
