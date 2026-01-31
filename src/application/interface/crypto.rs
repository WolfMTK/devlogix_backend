use crate::application::app_error::AppResult;

pub trait CredentialsHasher: Send + Sync {
    fn hash_password(&self, password: &str) -> AppResult<String>;
    fn verify_password(&self, password: &str, hashed: &str) -> AppResult<bool>;
}
