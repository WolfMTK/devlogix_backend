use crate::application::{
    app_error::{AppError, AppResult},
    dto::email_confirmation::ConfirmEmailDTO,
    interface::{
        db::DBSession,
        gateway::{
            email_confirmation::{
                EmailConfirmationReader, EmailConfirmationWriter,
            },
            user::{UserReader, UserWriter}
        }
    }
};
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Clone)]
pub struct ConfirmEmailInteractor {
    db_session: Arc<dyn DBSession>,
    email_confirmation_reader: Arc<dyn EmailConfirmationReader>,
    email_confirmation_writer: Arc<dyn EmailConfirmationWriter>,
    user_reader: Arc<dyn UserReader>,
    user_writer: Arc<dyn UserWriter>,
}

impl ConfirmEmailInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        email_confirmation_reader: Arc<dyn EmailConfirmationReader>,
        email_confirmation_writer: Arc<dyn EmailConfirmationWriter>,
        user_reader: Arc<dyn UserReader>,
        user_writer: Arc<dyn UserWriter>,
    ) -> Self {
        Self {
            db_session,
            email_confirmation_reader,
            email_confirmation_writer,
            user_reader,
            user_writer,
        }
    }

    pub async fn execute(&self, dto: ConfirmEmailDTO) -> AppResult<()> {
        let confirmation = self
            .email_confirmation_reader
            .find_by_token(&dto.token)
            .await?
            .ok_or_else(|| {
                warn!("Confirmation attempt with invalid token");
                AppError::InvalidConfirmationToken
            })?;
        if confirmation.is_confirmed() {
            return Err(AppError::EmailAlreadyConfirmed);
        }
        if confirmation.is_expired() {
            return Err(AppError::ConfirmationTokenExpired);
        }
        let mut user = self
            .user_reader
            .find_by_id(&confirmation.user_id)
            .await?
            .ok_or_else(|| {
                warn!("User not found for confirmation token");
                AppError::InvalidConfirmationToken
            })?;
        user.is_confirmed = true;
        self.email_confirmation_writer
            .confirm(&confirmation.id)
            .await?;
        self.user_writer.update(user).await?;
        self.db_session.commit().await?;
        info!("Email confirmed for user {}", confirmation.user_id.value);
        Ok(())
    }
}
