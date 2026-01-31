use crate::application::{
    app_error::{AppError, AppResult},
    interface::crypto::CredentialsHasher,
};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString}, Argon2, PasswordHash, PasswordHasher,
    PasswordVerifier,
};

#[derive(Default, Clone)]
pub struct ArgonPasswordHasher {
    hasher: Argon2<'static>,
}

impl CredentialsHasher for ArgonPasswordHasher {
    fn hash_password(&self, password: &str) -> AppResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = self
            .hasher
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| AppError::PasswordHashError)?
            .to_string();

        Ok(hash)
    }

    fn verify_password(&self, password: &str, hashed: &str) -> AppResult<bool> {
        let parsed_hash = PasswordHash::new(hashed).map_err(|_| AppError::InvalidCredentials)?;

        match self
            .hasher
            .verify_password(password.as_bytes(), &parsed_hash)
        {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
