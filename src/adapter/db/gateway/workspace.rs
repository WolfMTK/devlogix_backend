use async_trait::async_trait;
use futures::FutureExt;
use sqlx::Row;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::adapter::db::session::SqlxSession;
use crate::application::app_error::{AppError, AppResult};
use crate::application::interface::gateway::workspace::{WorkspaceInviteWriter, WorkspaceReader, WorkspaceWriter};
use crate::domain::entities::id::Id;
use crate::domain::entities::user::User;
use crate::domain::entities::workspace::{Workspace, WorkspaceInvite, WorkspaceVisibility};

#[derive(Clone)]
pub struct WorkspaceGateway {
    session: SqlxSession,
}

impl WorkspaceGateway {
    pub fn new(session: SqlxSession) -> Self {
        Self { session }
    }

    fn get_workspace(row: &PgRow) -> AppResult<Workspace> {
        let visibility_str: String = row.try_get("visibility")?;
        let visibility = visibility_str
            .parse::<WorkspaceVisibility>()
            .map_err(|_| AppError::InvalidVisibility(visibility_str))?;

        Ok(Workspace {
            id: Id::new(row.try_get("id")?),
            owner_user_id: Id::new(row.try_get("owner_user_id")?),
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            slug: row.try_get("slug")?,
            logo: row.try_get("logo")?,
            primary_color: row.try_get("primary_logo")?,
            visibility,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
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
                println!("{}", &visibility);

                let row = sqlx::query(
                    r#"
                        INSERT INTO workspaces
                            (id, owner_user_id, name, description, slug, logo, primary_color, visibility, created_at, updated_at)
                        VALUES
                            ($1, $2, $3, $4, $5, $6, $7, $8::workspace_visibility, $9, $10)
                        RETURNING id
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

    async fn update(&self, workspace: Workspace) -> AppResult<()> {
        self.session
            .with_tx(|tx| {
                let workspace = workspace.clone();
                async move {
                    let visibility = match workspace.visibility {
                        WorkspaceVisibility::Private => "private",
                        WorkspaceVisibility::Public => "public",
                    };

                    sqlx::query(
                        r#"
                        UPDATE workspaces
                        SET
                            name = $2,
                            description = $3,
                            primary_color = $4,
                            visibility = $5,
                            logo = $6,
                            slug = $6,
                            updated_at = now()
                        WHERE id = $1
                    "#,
                    )
                    .bind(workspace.id.value)
                    .bind(workspace.name)
                    .bind(workspace.description)
                    .bind(visibility)
                    .bind(workspace.logo)
                    .bind(workspace.slug)
                    .execute(tx.as_mut())
                    .await?;

                    Ok(())
                }
                .boxed()
            })
            .await
    }

    async fn delete(&self, workspace_id: &Id<Workspace>) -> AppResult<()> {
        self.session
            .with_tx(|tx| {
                let workspace_id = workspace_id.value;

                async move {
                    sqlx::query(
                        r#"
                            DELETE FROM workspaces
                            WHERE id = $1
                        "#,
                    )
                    .bind(workspace_id)
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
impl WorkspaceReader for WorkspaceGateway {
    async fn get(&self, workspace_id: &Id<Workspace>) -> AppResult<Option<Workspace>> {
        self.session
            .with_tx(|tx| {
                let workspace_id = workspace_id.value;
                async move {
                    let row = sqlx::query(
                        r#"
                        SELECT
                            id,
                            owner_user_id,
                            name,
                            description,
                            slug,
                            logo,
                            primary_color,
                            visibility::TEXT,
                            created_at,
                            updated_at
                        FROM workspaces
                        WHERE id = $1
                    "#,
                    )
                    .bind(workspace_id)
                    .fetch_optional(tx.as_mut())
                    .await?;

                    match row {
                        Some(row) => Ok(Some(Self::get_workspace(&row)?)),
                        None => Ok(None),
                    }
                }
                .boxed()
            })
            .await
    }
    async fn find_accessible_by_user(&self, user_id: &Id<User>, limit: i64, offset: i64) -> AppResult<Vec<Workspace>> {
        self.session
            .with_tx(|tx| {
                let user_id = user_id.value;
                async move {
                    let rows = sqlx::query(
                        r#"
                            SELECT
                                w.id,
                                w.owner_user_id,
                                w.name,
                                w.description,
                                w.slug,
                                w.logo,
                                w.primary_color,
                                w.visibility::TEXT,
                                w.created_at,
                                w.updated_at
                            FROM
                                workspaces AS w
                            WHERE
                                w.owner_user_id= $1
                                OR EXISTS (
                                    SELECT 1
                                    FROM
                                        workspace_members AS wm
                                    WHERE wm.workspace_id = w.id
                                        AND wm.user_id = $1
                                        AND wm.status = 'active'
                                )
                            ORDER BY
                                w.created_at DESC
                            LIMIT $2 OFFSET $3
                        "#,
                    )
                    .bind(user_id)
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(tx.as_mut())
                    .await?;

                    rows.iter().map(Self::get_workspace).collect()
                }
                .boxed()
            })
            .await
    }

    async fn count_accessible_by_user(&self, user_id: &Id<User>) -> AppResult<i64> {
        self.session
            .with_tx(|tx| {
                let user_id = user_id.value;
                async move {
                    let row = sqlx::query(
                        r#"
                                SELECT COUNT(w.id) AS total
                                FROM
                                    workspaces AS w
                                WHERE
                                    w.owner_user_id= $1
                                    OR EXISTS(
                                        SELECT 1
                                        FROM
                                            workspace_members AS wm
                                        WHERE wm.workspace_id = w.id
                                            AND wm.user_id = $1
                                            AND wm.status = 'active'
                                    )
                            "#,
                    )
                    .bind(user_id)
                    .fetch_one(tx.as_mut())
                    .await?;

                    Ok(row.try_get("total")?)
                }
                .boxed()
            })
            .await
    }

    async fn is_accessible_by_user(&self, workspace_id: &Id<Workspace>, user_id: &Id<User>) -> AppResult<bool> {
        self.session
            .with_tx(|tx| {
                let workspace_id = workspace_id.value;
                let user_id = user_id.value;
                async move {
                    let row = sqlx::query(
                        r#"
                        SELECT EXISTS (
                            SELECT 1
                            FROM
                                workspaces AS w
                            WHERE
                                w.id = $1
                                AND (
                                    w.owner_user_id = $2
                                    OR EXISTS(
                                        SELECT 1
                                        FROM
                                            workspace_members AS wm
                                        WHERE wm.workspace_id = w.id
                                            AND wm.user_id = $1
                                            AND wm.status = 'active'
                                    )
                                )
                        ) AS accessible
                    "#,
                    )
                    .bind(workspace_id)
                    .bind(user_id)
                    .fetch_one(tx.as_mut())
                    .await?;

                    Ok(row.try_get("accessible")?)
                }
                .boxed()
            })
            .await
    }
}

#[derive(Clone)]
pub struct WorkspaceInviteGateway {
    session: SqlxSession,
}

impl WorkspaceInviteGateway {
    pub fn new(session: SqlxSession) -> Self {
        Self { session }
    }

    fn get_workspace_invite(row: &PgRow) -> AppResult<WorkspaceInvite> {
        Ok(WorkspaceInvite {
            id: Id::new(row.try_get("id")?),
            workspace_id: Id::new(row.try_get("workspace_id")?),
            email: row.try_get("email")?,
            invite_token: row.try_get("invite_token")?,
            invited_by: Id::new(row.try_get("invited_by")?),
            expires_at: row.try_get("expites_at")?,
            accepted_at: row.try_get("accepted_at")?,
            revoked_at: row.try_get("revoked_at")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[async_trait]
impl WorkspaceInviteWriter for WorkspaceInviteGateway {
    async fn insert(&self, workspace_invite: WorkspaceInvite) -> AppResult<Id<WorkspaceInvite>> {
        self.session.with_tx(|tx| {
            let workspace_invite = workspace_invite.clone();
            async move {
                let row = sqlx::query(
                    r#"
                        INSERT INTO workspace_invites
                            (id, workspace_id, invite_token, invited_by, expires_at, accepted_at, revoked_at, created_at)
                        VALUES
                            ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                        RETURNING id
                    "#
                )
                .bind(workspace_invite.id.value)
                .bind(workspace_invite.workspace_id.value)
                .bind(workspace_invite.email)
                .bind(workspace_invite.invite_token)
                .bind(workspace_invite.invited_by.value)
                .bind(workspace_invite.expires_at)
                .bind(workspace_invite.accepted_at)
                .bind(workspace_invite.revoked_at)
                .bind(workspace_invite.created_at)
                .fetch_one(tx.as_mut())
                .await?;

                let id: Uuid = row.try_get("id")?;
                Ok(Id::new(id))
            }.boxed()
        }).await
    }
    async fn accept(&self, workspace_invite_id: &Id<WorkspaceInvite>) -> AppResult<()> {
        self.session
            .with_tx(|tx| {
                let workspace_invite_id = workspace_invite_id.value;
                async move {
                    sqlx::query(
                        r#"
                        UPDATE workspace_invites
                        SET accepted_at = now()
                        WHERE id = $1
                    "#,
                    )
                    .bind(workspace_invite_id)
                    .execute(tx.as_mut())
                    .await?;

                    Ok(())
                }
                .boxed()
            })
            .await
    }
    async fn delete_by_email(&self, workspace_id: &Id<Workspace>, email: &str) -> AppResult<()> {
        self.session
            .with_tx(|tx| {
                let workspace_id = workspace_id.value;
                let email = email.to_owned();
                async move {
                    sqlx::query(
                        r#"
                        DELETE FROM workspace_invites
                        WHERE workspace_id = $1 AND email = $2
                    "#,
                    )
                    .bind(workspace_id)
                    .bind(email)
                    .execute(tx.as_mut())
                    .await?;

                    Ok(())
                }
                .boxed()
            })
            .await
    }
}
