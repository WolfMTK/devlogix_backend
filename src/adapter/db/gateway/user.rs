use crate::{
    adapter::db::session::SqlxSession,
    application::{
        app_error::AppResult,
        interface::gateway::user::UserWriter
    },
    domain::entities::{
        id::Id,
        user::User
    }
};
use async_trait::async_trait;
use futures::FutureExt;
use sqlx::Row;
use uuid::Uuid;

pub struct UserGateway {
    session: SqlxSession,
}

impl UserGateway {
    pub fn new(session: SqlxSession) -> Self {
        Self { session }
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
                            VALUES ($1, $2, $3, $4, $5, $6)
                            RETURNING id
                        "#,
                    )
                    .bind(user.id.value)
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
}
