use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::application::app_error::{AppError, AppResult};

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: String,
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> AppResult<Self> {
        match parts.extensions.get::<AuthUser>().cloned() {
            Some(user) => Ok(user),
            None => Err(AppError::InvalidCredentials),
        }
    }
}
