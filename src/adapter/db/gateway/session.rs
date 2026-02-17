use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::FutureExt;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::adapter::db::session::SqlxSession;
use crate::application::app_error::AppResult;
use crate::application::interface::gateway::session::{SessionReader, SessionWriter};
use crate::domain::entities::id::Id;
use crate::domain::entities::session::Session;
use crate::domain::entities::user::User;

pub struct SessionGateway {
    session: SqlxSession,
}

impl SessionGateway {
    pub fn new(session: SqlxSession) -> Self {
        Self { session }
    }

    async fn insert_session(tx: &mut Transaction<'_, Postgres>, session: Session) -> AppResult<Id<Session>> {
        let result = sqlx::query(
            r#"
                INSERT INTO sessions
                    (id, user_id, created_at, last_activity, last_rotation, remember_me)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id
            "#,
        )
        .bind(session.id.value)
        .bind(session.user_id.value)
        .bind(session.created_at)
        .bind(session.last_activity)
        .bind(session.last_rotation)
        .bind(session.remember_me)
        .fetch_one(tx.as_mut())
        .await?;

        let id: Uuid = result.try_get("id")?;
        Ok(Id::new(id))
    }
}

#[async_trait]
impl SessionWriter for SessionGateway {
    async fn insert(&self, session: Session) -> AppResult<Id<Session>> {
        self.session
            .with_tx(|tx| {
                let session = session.clone();
                async move { Self::insert_session(tx, session).await }.boxed()
            })
            .await
    }

    async fn update_activity(&self, session_id: &Id<Session>, now: DateTime<Utc>) -> AppResult<()> {
        self.session
            .with_tx(|tx| {
                let session_id = session_id.value;
                async move {
                    sqlx::query(
                        r#"
                            UPDATE sessions
                            SET last_activity = $2
                            WHERE id = $1
                        "#,
                    )
                    .bind(session_id)
                    .bind(now)
                    .execute(tx.as_mut())
                    .await?;
                    Ok(())
                }
                .boxed()
            })
            .await
    }

    async fn rotate(&self, old_session_id: &Id<Session>, new_session: Session) -> AppResult<Id<Session>> {
        self.session
            .with_tx(|tx| {
                let old_id = old_session_id.value;
                let new_session = new_session.clone();
                async move {
                    sqlx::query("DELETE FROM sessions WHERE id = $1")
                        .bind(old_id)
                        .execute(tx.as_mut())
                        .await?;
                    Self::insert_session(tx, new_session).await
                }
                .boxed()
            })
            .await
    }

    async fn delete(&self, session_id: &Id<Session>) -> AppResult<()> {
        self.session
            .with_tx(|tx| {
                let session_id = session_id.value;
                async move {
                    sqlx::query("DELETE FROM sessions WHERE id = $1")
                        .bind(session_id)
                        .execute(tx.as_mut())
                        .await?;
                    Ok(())
                }
                .boxed()
            })
            .await
    }

    async fn delete_by_user_id(&self, user_id: &Id<User>) -> AppResult<()> {
        self.session
            .with_tx(|tx| {
                let user_id = user_id.value;
                async move {
                    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
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
impl SessionReader for SessionGateway {
    async fn find_by_id(&self, session_id: &Id<Session>) -> AppResult<Option<Session>> {
        self.session
            .with_tx(|tx| {
                let session_id = session_id.value;
                async move {
                    let result = sqlx::query(
                        r#"
                        SELECT
                            id, user_id, created_at, last_activity, last_rotation, remember_me
                        FROM
                            sessions
                        WHERE 
                            id = $1
                    "#,
                    )
                    .bind(session_id)
                    .fetch_optional(tx.as_mut())
                    .await?;
                    match result {
                        Some(row) => Ok(Some(Session {
                            id: Id::new(row.try_get("id")?),
                            user_id: Id::new(row.try_get("user_id")?),
                            created_at: row.try_get("created_at")?,
                            last_activity: row.try_get("last_activity")?,
                            last_rotation: row.try_get("last_rotation")?,
                            remember_me: row.try_get("remember_me")?,
                        })),
                        None => Ok(None),
                    }
                }
                .boxed()
            })
            .await
    }
}
