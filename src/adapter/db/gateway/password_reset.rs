use async_trait::async_trait;
use futures::FutureExt;
use sqlx::Row;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::adapter::db::session::SqlxSession;
use crate::application::app_error::AppResult;
use crate::application::interface::gateway::password_reset::{PasswordResetTokenReader, PasswordResetTokenWriter};
use crate::domain::entities::id::Id;
use crate::domain::entities::password_reset::PasswordResetToken;
use crate::domain::entities::user::User;

#[derive(Clone)]
pub struct PasswordResetTokenGateway {
    session: SqlxSession,
}

impl PasswordResetTokenGateway {
    pub fn new(session: SqlxSession) -> Self {
        Self { session }
    }

    fn get_password_reset(row: Option<PgRow>) -> AppResult<Option<PasswordResetToken>> {
        match row {
            Some(row) => Ok(Some(PasswordResetToken {
                id: Id::new(row.try_get("id")?),
                user_id: Id::new(row.try_get("user_id")?),
                token: row.try_get("token")?,
                expires_at: row.try_get("expires_at")?,
                used_at: row.try_get("used_at")?,
                created_at: row.try_get("created_at")?,
            })),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl PasswordResetTokenWriter for PasswordResetTokenGateway {
    async fn insert(&self, token: PasswordResetToken) -> AppResult<Id<PasswordResetToken>> {
        self.session
            .with_tx(|tx| {
                let token = token.clone();
                async move {
                    let row = sqlx::query(
                        r#"
                        INSERT INTO password_reset_tokens
                            (id, user_id, token, expires_at, used_at, created_at)
                        VALUES
                            ($1, $2, $3, $4, $5, $6)
                        RETURNING id
                    "#,
                    )
                    .bind(token.id.value)
                    .bind(token.user_id.value)
                    .bind(token.token)
                    .bind(token.expires_at)
                    .bind(token.used_at)
                    .bind(token.created_at)
                    .fetch_one(tx.as_mut())
                    .await?;

                    let id: Uuid = row.try_get("id")?;
                    Ok(Id::new(id))
                }
                .boxed()
            })
            .await
    }

    async fn mark_as_used(&self, token_id: &Id<PasswordResetToken>) -> AppResult<()> {
        self.session
            .with_tx(|tx| {
                let token_id = token_id.value;
                async move {
                    sqlx::query(
                        r#"
                        UPDATE password_reset_tokens
                        SET used_at = now()
                        WHERE id = $1
                    "#,
                    )
                    .bind(token_id)
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
                let user_id = user_id.value;
                async move {
                    sqlx::query(
                        r#"
                        DELETE FROM password_reset_tokens
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
impl PasswordResetTokenReader for PasswordResetTokenGateway {
    async fn find_by_token(&self, token: &str) -> AppResult<Option<PasswordResetToken>> {
        self.session
            .with_tx(|tx| {
                let token = token.to_owned();
                async move {
                    let row = sqlx::query(
                        r#"
                            SELECT id, user_id, token, expires_at, used_at, created_at
                            FROM password_reset_tokens
                            WHERE token = $1
                        "#,
                    )
                    .bind(token)
                    .fetch_optional(tx.as_mut())
                    .await?;

                    Self::get_password_reset(row)
                }
                .boxed()
            })
            .await
    }
}
