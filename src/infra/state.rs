use crate::{
    adapter::db::{
        gateway::user::UserGateway,
        session::SqlxSession
    },
    application::{
        app_error::{AppError, AppResult},
        interactors::users::CreateUserInteractor
    }
};
use async_trait::async_trait;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts
};
use sqlx::{Pool, Postgres};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub pool: Pool<Postgres>,
}

#[async_trait]
pub trait FromAppState: Sized {
    async fn from_app_state(state: &AppState) -> AppResult<Self>;
}

#[async_trait]
impl FromAppState for CreateUserInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new(state.pool.clone()).await?;
        let user_gateway = UserGateway::new(session.clone());

        Ok(CreateUserInteractor::new(
            Arc::new(session),
            Arc::new(user_gateway),
        ))
    }
}

impl<S> FromRequestParts<S> for CreateUserInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        CreateUserInteractor::from_app_state(&app_state).await
    }
}
