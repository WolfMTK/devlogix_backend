use crate::application::app_error::AppResult;
use async_trait::async_trait;

#[async_trait]
pub trait DBSession: Send + Sync {
    async fn commit(&self) -> AppResult<()>;
}
