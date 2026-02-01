use crate::{
    application::{
        app_error::{AppError, AppResult},
        dto::auth::{GetSessionIdDTO, LoginDTO},
        interface::{
            crypto::CredentialsHasher,
            db::DBSession,
            gateway::{
                session::SessionWriter,
                user::UserReader
            }
        }
    },
    domain::entities::{
        id::Id,
        session::Session
    }
};
use chrono::Utc;
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Clone)]
pub struct LoginInteractor {
    db_session: Arc<dyn DBSession>,
    user_reader: Arc<dyn UserReader>,
    session_writer: Arc<dyn SessionWriter>,
    hasher: Arc<dyn CredentialsHasher>,
}

impl LoginInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        user_reader: Arc<dyn UserReader>,
        session_writer: Arc<dyn SessionWriter>,
        hasher: Arc<dyn CredentialsHasher>,
    ) -> Self {
        Self {
            db_session,
            user_reader,
            session_writer,
            hasher,
        }
    }

    pub async fn execute(&self, dto: LoginDTO) -> AppResult<GetSessionIdDTO> {
        let user = self
            .user_reader
            .find_by_email(&dto.email)
            .await?
            .ok_or_else(|| {
                warn!("Login attempt with non-existent email: {}", dto.email);
                AppError::InvalidCredentials
            })?;
        let is_valid = self.hasher.verify_password(&dto.password, &user.password).await?;
        if !is_valid {
            warn!("Invalid password for user: {}", user.username);
            return Err(AppError::InvalidCredentials);
        }
        let now = Utc::now();
        let session = Session {
            id: Id::generate(),
            user_id: user.id.clone(),
            created_at: now,
            last_activity: now,
            last_rotation: now,
            remember_me: dto.remember_me,
        };
        let session_id = self.session_writer.insert(session).await?;
        self.db_session.commit().await?;
        info!("User {} logged in successfully", user.username);
        Ok(GetSessionIdDTO {
            session_id: session_id.value.to_string(),
            remember_me: dto.remember_me,
        })
    }
}
