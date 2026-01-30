use crate::application::app_error::AppError;
use axum::response::{IntoResponse, Response};

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        todo!()
    }
}
