use axum::extract::rejection::JsonRejection;
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

    #[error(transparent)]
    ValidationError(#[from] validator::ValidationErrors),

    #[error("Invalid json")]
    AxumJsonRejection(#[from] JsonRejection),

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("Passwords does not match")]
    InvalidPassword,

    #[error("The old password field is empty")]
    OldPasswordEmpty,

    #[error("The old password is incorrect")]
    InvalidOldPassword,

    #[error("Email is not confirmed")]
    EmailNotConfirmed,

    #[error("Invalid or expired confirmation token")]
    InvalidConfirmationToken,

    #[error("Email is already confirmed")]
    EmailAlreadyConfirmed,

    #[error("Confirmation token has expired")]
    ConfirmationTokenExpired,

    #[error("Email send error: {0}")]
    EmailSendError(String),

    #[error("Invalid or expired password reset token")]
    InvalidResetToken,

    #[error("Password reset token has already has been used")]
    ResetTokenAlreadyUsed,

    #[error("Password reset token has expired")]
    ResetTokenExpired,

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("File not found")]
    StorageNotFound,

    #[error("Invalid visibility value: '{0}'. Expected 'public' or 'private'.")]
    InvalidVisibility(String),

    #[error("Workspace creation error")]
    CreatedWorkspaceError,

    #[error("Unsupported image format")]
    UnsupportedImageFormat,

    #[error("Workspace not found")]
    WorkspaceNotFound,

    #[error("Access denied")]
    AccessDenied,

    #[error("Invite not found")]
    InviteNotFound,

    #[error("Invite already sent to this email")]
    InviteAlreadyExists,

    #[error("Invite has expired")]
    InviteExpired,

    #[error("Invite is not pending")]
    InviteInvalid,

    #[error("Invalid project type value: '{0}'. Expected 'kanban' or 'scrum'.")]
    InvalidProjectType(String),

    #[error("Project already exists")]
    ProjectAlreadyExists,

    #[error("Invalid user role")]
    InvalidWorkspaceUserRole,

    #[error("Project not found")]
    ProjectNotFound,

    #[error("Workspace pin not found")]
    WorkspacePinNotFound,
}

pub type AppResult<T> = Result<T, AppError>;
