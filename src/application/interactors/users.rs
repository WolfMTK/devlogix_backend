use crate::application::app_error::AppResult;
use crate::application::interface::db::DBSession;
use std::sync::Arc;

#[derive(Clone)]
pub struct CreateUserInteractor {
    db_session: Arc<dyn DBSession>,
}

impl CreateUserInteractor {
    pub fn new(db_session: Arc<dyn DBSession>) -> Self {
        Self { db_session }
    }

    pub async fn execute(&self) -> AppResult<()> {
        self.db_session.commit().await?;
        Ok(())
    }
}
