use crate::application::app_error::AppResult;
use async_trait::async_trait;

#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send(&self, to: &str, subject: &str, body: &str) -> AppResult<()>;
}
