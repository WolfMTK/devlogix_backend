use async_trait::async_trait;

use crate::application::app_error::AppResult;

#[async_trait]
pub trait DBSession: Send + Sync {
    async fn commit(&self) -> AppResult<()>;
}
