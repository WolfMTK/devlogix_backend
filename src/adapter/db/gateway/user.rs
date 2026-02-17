use async_trait::async_trait;
use futures::FutureExt;
use sqlx::Row;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::adapter::db::session::SqlxSession;
use crate::application::app_error::AppResult;
use crate::application::interface::gateway::user::{UserReader, UserWriter};
use crate::domain::entities::id::Id;
use crate::domain::entities::user::User;

#[derive(Clone)]
pub struct UserGateway {
    session: SqlxSession,
}

impl UserGateway {
    pub fn new(session: SqlxSession) -> Self {
        Self { session }
    }

    fn find_user(result: Option<PgRow>) -> AppResult<Option<User>> {
        match result {
            Some(row) => Ok(Some(User {
                id: Id::new(row.try_get("id")?),
                username: row.try_get("username")?,
                email: row.try_get("email")?,
                password: row.try_get("password")?,
                is_confirmed: row.try_get("is_confirmed")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
            })),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl UserWriter for UserGateway {
    async fn insert(&self, user: User) -> AppResult<Id<User>> {
        self.session
            .with_tx(|tx| {
                let user = user.clone();
                async move {
                    let result = sqlx::query(
                        r#"
                            INSERT INTO users
                                (id, username, email, password, created_at, updated_at)
                            VALUES
                                ($1, $2, $3, $4, $5, $6)
                            RETURNING
                                id
                        "#,
                    )
                    .bind(&user.id.value)
                    .bind(&user.username)
                    .bind(&user.email)
                    .bind(&user.password)
                    .bind(&user.created_at)
                    .bind(&user.updated_at)
                    .fetch_one(tx.as_mut())
                    .await?;
                    let id: Uuid = result.try_get("id")?;
                    Ok(Id::new(id))
                }
                .boxed()
            })
            .await
    }

    async fn update(&self, user: User) -> AppResult<Id<User>> {
        self.session
            .with_tx(|tx| {
                let user = user.clone();
                async move {
                    let result = sqlx::query(
                        r#"
                            UPDATE
                                users
                            SET
                                username = $2, email = $3, password = $4, is_confirmed = $5
                            WHERE
                                id = $1
                            RETURNING
                                id
                        "#,
                    )
                    .bind(&user.id.value)
                    .bind(&user.username)
                    .bind(&user.email)
                    .bind(&user.password)
                    .bind(&user.is_confirmed)
                    .fetch_one(tx.as_mut())
                    .await?;
                    let id: Uuid = result.try_get("id")?;
                    Ok(Id::new(id))
                }
                .boxed()
            })
            .await
    }
}

#[async_trait]
impl UserReader for UserGateway {
    async fn find_by_email(&self, email: &str) -> AppResult<Option<User>> {
        self.session
            .with_tx(|tx| {
                let email = email.to_owned();
                async move {
                    let result = sqlx::query(
                        r#"
                            SELECT 
                                id, username, email, password, is_confirmed, created_at, updated_at
                            FROM 
                                users
                            WHERE email = $1
                        "#,
                    )
                    .bind(&email)
                    .fetch_optional(tx.as_mut())
                    .await?;

                    Self::find_user(result)
                }
                .boxed()
            })
            .await
    }

    async fn is_user(&self, username: &str, email: &str) -> AppResult<bool> {
        self.session
            .with_tx(|tx| {
                let username = username.to_owned();
                let email = email.to_owned();
                async move {
                    let result = sqlx::query(
                        r#"
                            SELECT EXISTS(
                                SELECT
                                    id
                                FROM
                                    users
                                WHERE username = $1 OR email = $2
                            ) AS is_user
                        "#,
                    )
                    .bind(&username)
                    .bind(&email)
                    .fetch_one(tx.as_mut())
                    .await?;
                    let is_user: bool = result.try_get("is_user")?;
                    Ok(is_user)
                }
                .boxed()
            })
            .await
    }

    async fn find_by_id(&self, user_id: &Id<User>) -> AppResult<Option<User>> {
        self.session
            .with_tx(|tx| {
                let user_id = user_id.value;
                async move {
                    let result = sqlx::query(
                        r#"
                            SELECT
                                id, username, email, password, is_confirmed, created_at, updated_at
                            FROM
                                users
                            WHERE id = $1
                        "#,
                    )
                    .bind(&user_id)
                    .fetch_optional(tx.as_mut())
                    .await?;

                    Self::find_user(result)
                }
                .boxed()
            })
            .await
    }

    async fn is_username_or_email_unique(
        &self,
        user_id: &Id<User>,
        username: Option<&str>,
        email: Option<&str>,
    ) -> AppResult<bool> {
        self.session
            .with_tx(|tx| {
                let user_id = user_id.value;
                let username = username.map(String::from);
                let email = email.map(String::from);
                async move {
                    let result = sqlx::query(
                        r#"
                            SELECT EXISTS (
                                SELECT
                                    id
                                FROM
                                    users
                                WHERE
                                    id <> $1
                                  AND (
                                      ($2 IS NOT NULL AND username = $2)
                                          OR ($3 IS NOT NULL AND email = $3)
                                  )
                            ) AS is_user
                        "#,
                    )
                    .bind(&user_id)
                    .bind(&username)
                    .bind(&email)
                    .fetch_one(tx.as_mut())
                    .await?;
                    let is_user: bool = result.try_get("is_user")?;
                    Ok(is_user)
                }
                .boxed()
            })
            .await
    }
}
