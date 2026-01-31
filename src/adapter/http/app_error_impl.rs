use crate::application::app_error::AppError;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json
};
use serde_json::json;

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::DatabaseError(_) => (StatusCode::INTERNAL_SERVER_ERROR, None),
            AppError::InvalidId(_) => (StatusCode::BAD_REQUEST, None),
            AppError::SessionAlreadyCommitted => (StatusCode::INTERNAL_SERVER_ERROR, None),
            AppError::SessionAlreadyRolledBack => (StatusCode::INTERNAL_SERVER_ERROR, None),
            AppError::PasswordHashError => (StatusCode::INTERNAL_SERVER_ERROR, None),
            AppError::InvalidCredentials => (StatusCode::UNAUTHORIZED, Some("Invalid username or password")),
        };

        let message = match message {
            Some(msg) => msg,
            None => status.canonical_reason().unwrap_or_else(|| "Unknown error"),
        };

        let body = Json(json!({
            "error": message
        }));

        (status, body).into_response()
    }
}
