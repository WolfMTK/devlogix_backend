use crate::application::{
    app_error::{AppError, AppResult},
    interface::crypto::CredentialsHasher,
};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use async_trait::async_trait;

#[derive(Default, Clone)]
pub struct ArgonPasswordHasher {
    hasher: Argon2<'static>,
}

#[async_trait]
impl CredentialsHasher for ArgonPasswordHasher {
    async fn hash_password(&self, password: &str) -> AppResult<String> {
        let password = password.to_owned();
        let hasher = self.hasher.clone();
        tokio::task::spawn_blocking(move || {
            let salt = SaltString::generate(&mut OsRng);
            hasher
                .hash_password(password.as_bytes(), &salt)
                .map(|h| h.to_string())
                .map_err(|_| AppError::PasswordHashError)
        })
            .await
            .map_err(|_| AppError::PasswordHashError)?
    }

    async fn verify_password(&self, password: &str, hashed: &str) -> AppResult<bool> {
        let password = password.to_owned();
        let hashed = hashed.to_owned();
        let hasher = self.hasher.clone();
        tokio::task::spawn_blocking(move || {
            let parsed_hash = PasswordHash::new(&hashed).map_err(|_| AppError::InvalidCredentials)?;
            match hasher.verify_password(password.as_bytes(), &parsed_hash) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        ).await.map_err(|_|AppError::InvalidCredentials)?
    }
}
