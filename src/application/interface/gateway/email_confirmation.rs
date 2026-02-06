use crate::{
    application::app_error::AppResult,
    domain::entities::{email_confirmation::EmailConfirmation, id::Id},
};
use async_trait::async_trait;

#[async_trait]
pub trait EmailConfirmationWriter: Send + Sync {
    async fn insert(
        &self,
        email_confirmation: EmailConfirmation,
    ) -> AppResult<Id<EmailConfirmation>>;
    async fn confirm(&self, confirmation_id: &Id<EmailConfirmation>) -> AppResult<()>;
}

#[async_trait]
pub trait EmailConfirmationReader: Send + Sync {
    async fn find_by_token(&self, token: &str) -> AppResult<Option<EmailConfirmation>>;
}
