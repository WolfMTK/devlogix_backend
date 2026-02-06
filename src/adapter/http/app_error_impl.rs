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
            // BAD REQUEST
            AppError::InvalidId(_) => (StatusCode::BAD_REQUEST, None),
            AppError::AxumJsonRejection(_) => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::UserAlreadyExists => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::DatabaseError(_) => (StatusCode::BAD_REQUEST, None),
            AppError::ValidationError(_) => {
                let message = format!("Input validation error: [{self}]")
                    .replace("\n", ", ")
                    .replace(".value", "");
                (StatusCode::BAD_REQUEST, Some(message))
            }
            AppError::InvalidPassword => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::OldPasswordEmpty => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::InvalidOldPassword => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::InvalidConfirmationToken => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::ConfirmationTokenExpired => (StatusCode::BAD_REQUEST, Some(self.to_string())),

            // FORBIDDEN
            AppError::EmailNotConfirmed => (StatusCode::FORBIDDEN, Some(self.to_string())),

            // UNAUTHORIZED
            AppError::InvalidCredentials => (StatusCode::UNAUTHORIZED, Some(self.to_string())),

            // CONFLICT
            AppError::EmailAlreadyConfirmed => (StatusCode::CONFLICT, Some(self.to_string())),

            // INTERNAL_SERVER_ERROR
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
