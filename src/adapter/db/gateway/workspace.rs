use async_trait::async_trait;
use futures::FutureExt;
use sqlx::Row;
use uuid::Uuid;

use crate::adapter::db::session::SqlxSession;
use crate::application::app_error::AppResult;
use crate::application::interface::gateway::workspace::WorkspaceWriter;
use crate::domain::entities::id::Id;
use crate::domain::entities::workspace::{Workspace, WorkspaceVisibility};

#[derive(Clone)]
pub struct WorkspaceGateway {
    session: SqlxSession,
}

impl WorkspaceGateway {
    pub fn new(session: SqlxSession) -> Self {
        Self { session }
    }
}

#[async_trait]
impl WorkspaceWriter for WorkspaceGateway {
    async fn insert(&self, workspace: Workspace) -> AppResult<Id<Workspace>> {
        self.session.with_tx(|tx| {
            let workspace = workspace.clone();
            async move {
                let visibility = match workspace.visibility {
                    WorkspaceVisibility::Private => "private",
                    WorkspaceVisibility::Public => "public",
                };

                let row = sqlx::query(
                    r#"
                        INSERT INTO workspaces
                            (id, owner_user_id, name, description, slug, logo, primary_color, visibility, created_at, updated_at)
                        VALUES
                            ($1, $2, $3, $4, $5, $6, $7, $8::workspace_visibility, $9, $10)
                    "#,
                )
                    .bind(workspace.id.value)
                    .bind(workspace.owner_user_id.value)
                    .bind(workspace.name)
                    .bind(workspace.description)
                    .bind(workspace.slug)
                    .bind(workspace.logo)
                    .bind(workspace.primary_color)
                    .bind(visibility)
                    .bind(workspace.created_at)
                    .bind(workspace.updated_at)
                    .fetch_one(tx.as_mut())
                    .await?;

                let id: Uuid = row.try_get("id")?;
                Ok(Id::new(id))
            }.boxed()
        }).await
    }
}
