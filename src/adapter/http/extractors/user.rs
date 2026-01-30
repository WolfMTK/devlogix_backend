use crate::{
    application::{
        app_error::AppError,
        interactors::users::CreateUserInteractor
    },
    infra::state::AppState
};
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;

pub struct CreateUserInteractorExt(pub CreateUserInteractor);

impl<S> FromRequestParts<S> for CreateUserInteractorExt
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let use_cases = app_state.create_user_interactor().await?;
        Ok(CreateUserInteractorExt(use_cases))
    }
}
