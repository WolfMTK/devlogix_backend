use async_trait::async_trait;
use futures::FutureExt;
use sqlx::Row;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::adapter::db::session::SqlxSession;
use crate::application::app_error::AppResult;
use crate::application::interface::gateway::email_confirmation::{EmailConfirmationReader, EmailConfirmationWriter};
use crate::domain::entities::email_confirmation::EmailConfirmation;
use crate::domain::entities::id::Id;
use crate::domain::entities::user::User;

#[derive(Clone)]
pub struct EmailConfirmationGateway {
    session: SqlxSession,
}

impl EmailConfirmationGateway {
    pub fn new(session: SqlxSession) -> Self {
        Self { session }
    }

    fn get_email_confirmation(row: Option<PgRow>) -> AppResult<Option<EmailConfirmation>> {
        match row {
            Some(row) => Ok(Some(EmailConfirmation {
                id: Id::new(row.try_get("id")?),
                user_id: Id::new(row.try_get("user_id")?),
                token: row.try_get("token")?,
                expires_at: row.try_get("expires_at")?,
                confirmed_at: row.try_get("confirmed_at")?,
                created_at: row.try_get("created_at")?,
            })),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl EmailConfirmationWriter for EmailConfirmationGateway {
    async fn insert(&self, email_confirmation: EmailConfirmation) -> AppResult<Id<EmailConfirmation>> {
        self.session
            .with_tx(|tx| {
                let email_confirmation = email_confirmation.clone();
                async move {
                    let row = sqlx::query(
                        r#"
                        INSERT INTO email_confirmations
                            (id, user_id, token, expires_at, confirmed_at, created_at)
                        VALUES
                            ($1, $2, $3, $4, $5, $6)
                        RETURNING id
                    "#,
                    )
                    .bind(email_confirmation.id.value)
                    .bind(email_confirmation.user_id.value)
                    .bind(email_confirmation.token)
                    .bind(email_confirmation.expires_at)
                    .bind(email_confirmation.confirmed_at)
                    .bind(email_confirmation.created_at)
                    .fetch_one(tx.as_mut())
                    .await?;

                    let id: Uuid = row.try_get("id")?;
                    Ok(Id::new(id))
                }
                .boxed()
            })
            .await
    }

    async fn confirm(&self, confirmation_id: &Id<EmailConfirmation>) -> AppResult<()> {
        self.session
            .with_tx(|tx| {
                let confirmation_id = confirmation_id.value;
                async move {
                    sqlx::query(
                        r#"
                        UPDATE email_confirmations
                        SET confirmed_at = now()
                        WHERE id = $1
                    "#,
                    )
                    .bind(confirmation_id)
                    .execute(tx.as_mut())
                    .await?;
                    Ok(())
                }
                .boxed()
            })
            .await
    }
    async fn delete(&self, user_id: &Id<User>) -> AppResult<()> {
        self.session
            .with_tx(|tx| {
                let user_id = user_id.value.clone();
                async move {
                    sqlx::query(
                        r#"
                            DELETE FROM email_confirmations
                            WHERE user_id = $1
                        "#,
                    )
                    .bind(user_id)
                    .execute(tx.as_mut())
                    .await?;
                    Ok(())
                }
                .boxed()
            })
            .await
    }
}

#[async_trait]
impl EmailConfirmationReader for EmailConfirmationGateway {
    async fn find_by_token(&self, token: &str) -> AppResult<Option<EmailConfirmation>> {
        self.session
            .with_tx(|tx| {
                let token = token.to_owned();
                async move {
                    let row = sqlx::query(
                        r#"
                        SELECT id, user_id, token, expires_at, confirmed_at, created_at
                        FROM email_confirmations
                        WHERE token = $1
                    "#,
                    )
                    .bind(token)
                    .fetch_optional(tx.as_mut())
                    .await?;

                    Self::get_email_confirmation(row)
                }
                .boxed()
            })
            .await
    }
}
