use crate::{
    application::{
        app_error::AppResult,
        dto::{id::IdDTO, user::CreateUserDTO},
        interface::{crypto::CredentialsHasher, db::DBSession, gateway::user::UserWriter},
    },
    domain::entities::{id::Id, user::User},
};
use chrono::Utc;
use std::sync::Arc;
use tracing::{error, info};

#[derive(Clone)]
pub struct CreateUserInteractor {
    db_session: Arc<dyn DBSession>,
    user_writer: Arc<dyn UserWriter>,
    hasher: Arc<dyn CredentialsHasher>,
}

// TODO: Add password hashing
impl CreateUserInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        user_writer: Arc<dyn UserWriter>,
        hasher: Arc<dyn CredentialsHasher>,
    ) -> Self {
        Self {
            db_session,
            user_writer,
            hasher,
        }
    }

    pub async fn execute(&self, dto: CreateUserDTO) -> AppResult<IdDTO> {
        let hash = &self.hasher.hash_password(dto.password.as_str())?;
        let username = dto.username.clone();
        let user = User {
            id: Id::generate(),
            username: dto.username,
            email: dto.email,
            password: hash.into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let user_id = match self.user_writer.insert(user).await {
            Ok(id) => id.value.to_string(),
            Err(err) => {
                error!("The {} has not been created created. Error: {}", username, err);
                return Err(err);
            }
        };
        self.db_session.commit().await?;
        info!("The {} has been created", username);
        Ok(IdDTO { id: user_id })
    }
}
