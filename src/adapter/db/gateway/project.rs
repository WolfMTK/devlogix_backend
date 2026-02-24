use async_trait::async_trait;
use futures::FutureExt;
use sqlx::postgres::PgRow;
use sqlx::Row;
use uuid::Uuid;

use crate::adapter::db::session::SqlxSession;
use crate::application::app_error::{AppError, AppResult};
use crate::application::interface::gateway::project::{ProjectReader, ProjectWriter};
use crate::domain::entities::id::Id;
use crate::domain::entities::project::{Project, ProjectType, ProjectVisibility};
use crate::domain::entities::workspace::Workspace;

#[derive(Clone)]
pub struct ProjectGateway {
    session: SqlxSession,
}

impl ProjectGateway {
    pub fn new(session: SqlxSession) -> Self {
        Self { session }
    }

    fn get_project(row: &PgRow) -> AppResult<Project> {
        let type_project_str: String = row.try_get("type_project")?;
        let type_project = type_project_str.parse::<ProjectType>().map_err(|_| AppError::InvalidProjectType(type_project_str))?;

        let visibility_str: String = row.try_get("visibility")?;
        let visibility = visibility_str.parse::<ProjectVisibility>().map_err(|_| AppError::InvalidVisibility(visibility_str))?;

        Ok({
            Project {
                id: Id::new(row.try_get("id")?),
                workspace_id: Id::new(row.try_get("workspace_id")?),
                name: row.try_get("name")?,
                description: row.try_get("description")?,
                project_key: row.try_get("project_key")?,
                type_project,
                visibility,
                updated_at: row.try_get("updated_at")?,
                created_at: row.try_get("created_at")?
            }
        })
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

    async fn get_all(&self, workspace_id: &Id<Workspace>, limit: i64, offset: i64) -> AppResult<Vec<Project>> {
        self.session.with_tx(|tx| {
            let workspace_id = workspace_id.value;
            async move {
                let rows = sqlx::query(
                    r#"
                            SELECT
                                id,
                                workspace_id,
                                name,
                                description,
                                project_key,
                                type_project,
                                visibility,
                                created_at,
                                updated_at
                            FROM projects
                            WHERE id = $1
                            LIMIT $2 OFFSET $3
                    "#
                )
                    .bind(workspace_id)
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(tx.as_mut())
                    .await?;

                rows.iter().map(Self::get_project).collect()
            }.boxed()
        }).await
    }
    async fn count_projects(&self, workspace_id: &Id<Workspace>) -> AppResult<i64> {
        self.session.with_tx(|tx| {
            let workspace_id = workspace_id.value;
            async move {
                let row = sqlx::query(
                    r#"
                        SELECT COUNT(id) AS total
                        FROM projects
                        WHERE workspace_id = $1
                    "#
                )
                    .bind(workspace_id)
                    .fetch_one(tx.as_mut())
                    .await?;

                Ok(row.try_get("total")?)
            }.boxed()
        }).await
    }

    async fn get(&self, workspace_id: &Id<Workspace>, project_id: &Id<Project>) -> AppResult<Option<Project>> {
        self.session.with_tx(|tx| {
            let workspace_id = workspace_id.value;
            let project_id = project_id.value;
            async move {
                let row = sqlx::query(
                    r#"
                        SELECT
                            id,
                            workspace_id,
                            name,
                            description,
                            project_key,
                            type_project,
                            visibility,
                            created_at,
                            updated_at
                        FROM projects
                        WHERE workspace_id = $1 AND id = $2
                    "#
                )
                    .bind(workspace_id)
                    .bind(project_id)
                    .fetch_optional(tx.as_mut())
                    .await?;

                match row {
                    Some(row) => Ok(Some(Self::get_project(&row)?)),
                    None => Ok(None)
                }
            }.boxed()
        }).await
    }
}
