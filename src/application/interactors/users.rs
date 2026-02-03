use crate::{
    application::{
        app_error::{
            AppError,
            AppResult
        },
        dto::{
            id::IdDTO,
            user::{
                CreateUserDTO,
                UserDTO
            },
        },
        interface::{
            crypto::CredentialsHasher,
            db::DBSession,
            gateway::user::{
                UserReader,
                UserWriter
            },
        }
    },
    domain::entities::{id::Id, user::User}
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
        let hash = &self.hasher.hash_password(dto.password.as_str()).await?;
        let username = dto.username.clone();
        let now = Utc::now();
        let user = User {
            id: Id::generate(),
            username: dto.username,
            email: dto.email,
            password: hash.into(),
            created_at: now,
            updated_at: now,
        };
        let user_id = match self.user_writer.insert(user).await {
            Ok(id) => id.value.to_string(),
            Err(err) => {
                error!(
                    "The {} has not been created created. Error: {}",
                    username, err
                );
                return Err(err);
            }
        };
        self.db_session.commit().await?;
        info!("The {} has been created", username);
        Ok(IdDTO { id: user_id })
    }
}

#[derive(Clone)]
pub struct GetMeInteractor {
    user_reader: Arc<dyn UserReader>,
}

impl GetMeInteractor {
    pub fn new(user_reader: Arc<dyn UserReader>) -> Self {
        Self { user_reader }
    }

    pub async fn execute(&self, dto: IdDTO) -> AppResult<UserDTO> {
        let user_id: Id<User> = dto.id.try_into()?;
        let user = self
            .user_reader
            .find_by_id(&user_id)
            .await?
            .ok_or_else(|| {
                error!("User not found for authenticated session {:?}", user_id);
                AppError::InvalidCredentials
            })?;
        Ok(UserDTO {
            id: user.id.value.to_string(),
            username: user.username,
            email: user.email,
            created_at: user.created_at,
            updated_at: user.updated_at,
        })
    }
}
