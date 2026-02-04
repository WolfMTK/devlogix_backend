use crate::application::app_error::AppError;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::InvalidId(_) => (StatusCode::BAD_REQUEST, None),
            AppError::AxumJsonRejection(_) => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::UserAlreadyExists => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::DatabaseError(_) => (StatusCode::BAD_REQUEST, None),
            AppError::ValidationError(_) => {
                let message = format!("Input validation error: [{self}]").replace('\n', ", ");
                (StatusCode::BAD_REQUEST, Some(message))
            }
            AppError::InvalidPassword => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::OldPasswordEmpty => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::InvalidOldPassword => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::InvalidCredentials => (StatusCode::UNAUTHORIZED, Some(self.to_string())),
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
