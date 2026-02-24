use async_trait::async_trait;
use futures::FutureExt;
use sqlx::Row;
use uuid::Uuid;

use crate::adapter::db::session::SqlxSession;
use crate::application::app_error::AppResult;
use crate::application::interface::gateway::project::{ProjectReader, ProjectWriter};
use crate::domain::entities::id::Id;
use crate::domain::entities::project::{Project, ProjectType, ProjectVisibility};

#[derive(Clone)]
pub struct ProjectGateway {
    session: SqlxSession,
}

impl ProjectGateway {
    pub fn new(session: SqlxSession) -> Self {
        Self { session }
    }
}

#[async_trait]
impl ProjectWriter for ProjectGateway {
    async fn insert(&self, project: Project) -> AppResult<Id<Project>> {
        self.session
            .with_tx(|tx| {
                let project = project.clone();
                async move {
                    let type_project = match project.type_project {
                        ProjectType::Kanban => "kanban",
                        ProjectType::Scrum => "scrum",
                    };
                    let visibility = match project.visibility {
                        ProjectVisibility::Private => "private",
                        ProjectVisibility::Public => "public",
                    };
                    let row = sqlx::query(
                        r#"
                            INSERT INTO projects
                                (
                                    id,
                                    workspace_id,
                                    name,
                                    description,
                                    project_key,
                                    type_project,
                                    visibility,
                                    created_at,
                                    updated_at
                                )
                            VALUES
                                ($1, $2, $3, $4, $5, $6::projects_type_project, $7::projects_visibility, $8, $9)
                            RETURNING id
                        "#,
                    )
                    .bind(project.id.value)
                    .bind(project.workspace_id.value)
                    .bind(project.name)
                    .bind(project.description)
                    .bind(project.project_key)
                    .bind(type_project)
                    .bind(visibility)
                    .bind(project.created_at)
                    .bind(project.updated_at)
                    .fetch_one(tx.as_mut())
                    .await?;

                    let id: Uuid = row.try_get("id")?;
                    Ok(Id::new(id))
                }
                .boxed()
            })
            .await
    }
}

#[async_trait]
impl ProjectReader for ProjectGateway {
    async fn check_project_key(&self, project_key: &str) -> AppResult<bool> {
        self.session
            .with_tx(|tx| {
                let project_key = project_key.to_owned();
                async move {
                    let row = sqlx::query(
                        r#"
                        SELECT EXISTS (
                            SELECT 1
                            FROM projects
                            WHERE projects.project_key = $1
                        ) as is_project_key
                    "#,
                    )
                    .bind(project_key)
                    .fetch_one(tx.as_mut())
                    .await?;

                    Ok(row.try_get("is_project_key")?)
                }
                .boxed()
            })
            .await
    }
}
