use crate::application::{
    app_error::{AppError, AppResult},
    interface::crypto::CredentialsHasher,
};
use argon2::{
    password_hash::{
        rand_core::OsRng,
        SaltString
    },
    Argon2,
    PasswordHash,
    PasswordHasher,
    PasswordVerifier
};
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
            let parsed_hash =
                PasswordHash::new(&hashed).map_err(|_| AppError::InvalidCredentials)?;
            match hasher.verify_password(password.as_bytes(), &parsed_hash) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        })
        .await
        .map_err(|_| AppError::InvalidCredentials)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "Password123!";

    #[tokio::test]
    async fn test_hash_password_success() {
        let hasher = ArgonPasswordHasher::default();
        let hash = hasher.hash_password(&PASSWORD).await;
        match hash {
            Ok(val) => {
                assert!(!val.is_empty(), "Hashed password should not be empty");
                let result = hasher.verify_password(&PASSWORD, &val).await;
                assert!(result.is_ok(), "Verification should succeed");
                assert_eq!(
                    result.unwrap(),
                    true,
                    "Verification should return true for correct password"
                );
            }
            Err(e) => panic!("Hashing should not fail for a valid password: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_verify_password_incorrect() {
        let hasher = ArgonPasswordHasher::default();
        let hash = hasher.hash_password(&PASSWORD).await;
        let invalid_password = "InvalidPassword123!";
        let is_valid = hasher
            .verify_password(invalid_password, &hash.unwrap())
            .await;
        assert!(
            !is_valid.unwrap(),
            "Password should be verified as incorrect"
        );
    }

    #[tokio::test]
    async fn test_verify_password_invalid_format() {
        let hasher = ArgonPasswordHasher::default();
        let invalid_hash = "invalid";
        let result = hasher.verify_password(PASSWORD, invalid_hash).await;
        assert!(
            result.is_err(),
            "Verification should fail with invalid hash format"
        );
        assert!(
            matches!(result, Err(AppError::InvalidCredentials)),
            "Error should be InvalidCredentials"
        );
    }

    #[tokio::test]
    async fn test_hash_password_error_handling() {
        let hasher = ArgonPasswordHasher::default();
        let empty_password = "";
        match hasher.hash_password(empty_password).await {
            Ok(_) => assert!(true, "Hashing empty password should not panic"),
            Err(e) => assert!(
                matches!(e, AppError::PasswordHashError),
                "Expected PasswordHashError for hashing failure"
            ),
        }
    }
}
