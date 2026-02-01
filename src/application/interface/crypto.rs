use crate::application::app_error::AppResult;
use async_trait::async_trait;

#[async_trait]
pub trait CredentialsHasher: Send + Sync {
    async fn hash_password(&self, password: &str) -> AppResult<String>;
    async fn verify_password(&self, password: &str, hashed: &str) -> AppResult<bool>;
}
