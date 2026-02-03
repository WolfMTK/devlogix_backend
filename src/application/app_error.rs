use axum::http::header::InvalidHeaderValue;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Invalid Id: {0}")]
    InvalidId(String),

    #[error("Session has already been committed")]
    SessionAlreadyCommitted,

    #[error("Session has already been rolled back")]
    SessionAlreadyRolledBack,

    #[error("Failed to hash password")]
    PasswordHashError,

    #[error("Invalid Credentials")]
    InvalidCredentials,

    #[error("Invalid header value: {0}")]
    InvalidHeader(#[from] InvalidHeaderValue),
}

pub type AppResult<T> = Result<T, AppError>;
