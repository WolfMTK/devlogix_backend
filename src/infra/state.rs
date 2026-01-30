use crate::adapter::db::session::SqlxSession;
use crate::application::app_error::AppResult;
use crate::application::interactors::users::CreateUserInteractor;
use sqlx::{Pool, Postgres};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub pool: Pool<Postgres>,
}

impl AppState {
    pub async fn create_user_interactor(&self) -> AppResult<CreateUserInteractor> {
        let session = SqlxSession::new(self.pool.clone()).await?;

        Ok(CreateUserInteractor::new(Arc::new(session)))
    }
}
