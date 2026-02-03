use crate::{
    application::{
        app_error::{AppError, AppResult},
        dto::{
            id::IdDTO,
            user::{CreateUserDTO, UpdateUserDTO, UserDTO},
        },
        interface::{
            crypto::CredentialsHasher,
            db::DBSession,
            gateway::user::{UserReader, UserWriter},
        },
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
    user_reader: Arc<dyn UserReader>,
    hasher: Arc<dyn CredentialsHasher>,
}

impl CreateUserInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        user_writer: Arc<dyn UserWriter>,
        user_reader: Arc<dyn UserReader>,
        hasher: Arc<dyn CredentialsHasher>,
    ) -> Self {
        Self {
            db_session,
            user_writer,
            user_reader,
            hasher,
        }
    }

    pub async fn execute(&self, dto: CreateUserDTO) -> AppResult<IdDTO> {
        let is_user = self
            .user_reader
            .is_user(&dto.username.clone(), &dto.email.clone())
            .await?;
        if is_user {
            return Err(AppError::UserAlreadyExists);
        }
        let hash = self.hasher.hash_password(dto.password.as_str()).await?;
        let username = dto.username.clone();
        let now = Utc::now();
        let user = User {
            id: Id::generate(),
            username: dto.username,
            email: dto.email,
            password: hash,
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

#[derive(Clone)]
pub struct UpdateUserInteractor {
    db_session: Arc<dyn DBSession>,
    user_writer: Arc<dyn UserWriter>,
    user_reader: Arc<dyn UserReader>,
    hasher: Arc<dyn CredentialsHasher>,
}

impl UpdateUserInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        user_writer: Arc<dyn UserWriter>,
        user_reader: Arc<dyn UserReader>,
        hasher: Arc<dyn CredentialsHasher>,
    ) -> Self {
        Self {
            db_session,
            user_writer,
            user_reader,
            hasher,
        }
    }

    pub async fn execute(&self, dto: UpdateUserDTO) -> AppResult<()> {
        let user_id: Id<User> = dto.id.try_into()?;

        let is_username_or_email = self
            .user_reader
            .is_username_or_email_unique(&user_id, dto.username.as_deref(), dto.email.as_deref())
            .await?;
        if is_username_or_email {
            return Err(AppError::UserAlreadyExists);
        }
        let user = self.user_reader.find_by_id(&user_id).await?;
        match user {
            Some(mut user) => {
                if let Some(username) = dto.username {
                    user.username = username;
                }
                if let Some(email) = dto.email {
                    user.email = email;
                }
                if let Some(password) = dto.password {
                    let hash = self.hasher.hash_password(password.as_str()).await?;
                    user.password = hash;
                }
                self.user_writer.update(user).await?;
                self.db_session.commit().await?;
                Ok(())
            }
            None => Ok(()),
        }
    }
}
