use crate::application::app_error::AppError;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::InvalidId(_) => (StatusCode::BAD_REQUEST, None),
            AppError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                Some("Invalid Credentials".to_string()),
            ),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, None),
        };

        let message = match message {
            Some(msg) => msg,
            None => status
                .canonical_reason()
                .unwrap_or_else(|| "Unknown error")
                .to_string(),
        };

        let body = Json(json!({
            "error": message
        }));

        (status, body).into_response()
    }
}
