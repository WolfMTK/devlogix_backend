use crate::{
    application::{
        app_error::AppResult,
        dto::{
            id::IdDTO,
            user::CreateUserDTO
        },
        interface::{
            db::DBSession,
            gateway::user::UserWriter
        }
    },
    domain::entities::{
        id::Id,
        user::User
    }
};
use chrono::Utc;
use std::sync::Arc;

#[derive(Clone)]
pub struct CreateUserInteractor {
    db_session: Arc<dyn DBSession>,
    user_writer: Arc<dyn UserWriter>,
}

// TODO: Add password hashing
impl CreateUserInteractor {
    pub fn new(db_session: Arc<dyn DBSession>, user_writer: Arc<dyn UserWriter>) -> Self {
        Self {
            db_session,
            user_writer,
        }
    }

    pub async fn execute(&self, dto: CreateUserDTO) -> AppResult<IdDTO> {
        let user = User {
            id: Id::generate(),
            username: dto.username,
            email: dto.email,
            password: dto.password,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let user_id = self.user_writer.insert(user).await?;
        self.db_session.commit().await?;
        Ok(IdDTO {
            id: user_id.value.to_string(),
        })
    }
}
