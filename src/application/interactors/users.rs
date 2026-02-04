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
        Self::check_password(&dto.password1, &dto.password2)?;
        self.check_user_exists(&dto.username, &dto.email).await?;
        let hash = self.hasher.hash_password(dto.password1.as_str()).await?;
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

    fn check_password(password1: &str, password2: &str) -> AppResult<()> {
        if password1 != password2 {
            return Err(AppError::InvalidPassword);
        }
        Ok(())
    }

    async fn check_user_exists(&self, username: &str, email: &str) -> AppResult<()> {
        let is_user = self.user_reader.is_user(username, email).await?;
        if is_user {
            return Err(AppError::UserAlreadyExists);
        }
        Ok(())
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
        Self::check_passwords(&dto)?;
        let user_id: Id<User> = dto.id.try_into()?;
        self.check_username_or_email(&user_id, dto.username.as_deref(), dto.email.as_deref())
            .await?;
        let user = self.user_reader.find_by_id(&user_id).await?;
        match user {
            Some(mut user) => {
                self.check_old_password(dto.old_password, &user.password)
                    .await?;
                if let Some(username) = dto.username {
                    user.username = username;
                }
                if let Some(email) = dto.email {
                    user.email = email;
                }
                if let Some(password) = dto.password1 {
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

    async fn check_username_or_email(
        &self,
        user_id: &Id<User>,
        username: Option<&str>,
        email: Option<&str>,
    ) -> AppResult<()> {
        let is_username_or_email = self
            .user_reader
            .is_username_or_email_unique(&user_id, username, email)
            .await?;
        if is_username_or_email {
            return Err(AppError::UserAlreadyExists);
        }
        Ok(())
    }

    async fn check_old_password(
        &self,
        old_password: Option<String>,
        password: &str,
    ) -> AppResult<()> {
        if let Some(pwd) = old_password {
            if !self.hasher.verify_password(&pwd, password).await? {
                return Err(AppError::InvalidOldPassword);
            }
        }
        Ok(())
    }

    fn check_passwords(dto: &UpdateUserDTO) -> AppResult<()> {
        if !dto.password1.is_none() {
            if dto.old_password.is_none() {
                return Err(AppError::OldPasswordEmpty);
            }

            if dto.password1 != dto.password2 {
                return Err(AppError::InvalidPassword);
            }
        }
        Ok(())
    }
}
