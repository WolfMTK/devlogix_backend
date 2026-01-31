use thiserror::Error;

// TODO: Add new exceptions and a description
#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Invalid Id: {0}")]
    InvalidId(String),

    #[error("")]
    SessionAlreadyCommitted,

    #[error("")]
    SessionAlreadyRolledBack,
}

pub type AppResult<T> = Result<T, AppError>;
