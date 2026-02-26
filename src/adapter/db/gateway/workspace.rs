use async_trait::async_trait;
use futures::FutureExt;
use sqlx::Row;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::adapter::db::session::SqlxSession;
use crate::application::app_error::{AppError, AppResult};
use crate::application::interface::gateway::workspace::{
    WorkspaceInviteReader, WorkspaceInviteWriter, WorkspaceMemberReader, WorkspaceMemberWriter, WorkspacePinReader,
    WorkspacePinWriter, WorkspaceReader, WorkspaceWriter,
};
use crate::domain::entities::id::Id;
use crate::domain::entities::user::User;
use crate::domain::entities::workspace::{
    Workspace, WorkspaceInvite, WorkspaceMember, WorkspaceMemberRole, WorkspaceMemberStatus, WorkspacePin,
    WorkspaceUserRole, WorkspaceView, WorkspaceVisibility,
};

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
            primary_color: row.try_get("primary_color")?,
            visibility,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }

    fn get_workspace_view(row: &PgRow) -> AppResult<WorkspaceView> {
        let workspace = Self::get_workspace(&row)?;
        let role_str: String = row.try_get("user_role")?;
        let role = role_str
            .parse::<WorkspaceUserRole>()
            .map_err(|_| AppError::InvalidWorkspaceUserRole)?;

        Ok(WorkspaceView {
            workspace,
            total_members: row.try_get("total_members")?,
            total_projects: row.try_get("total_projects")?,
            user_role: role,
        })
    }
}

#[async_trait]
impl WorkspaceWriter for WorkspaceGateway {
    async fn insert(&self, workspace: Workspace) -> AppResult<Id<Workspace>> {
        self.session
            .with_tx(|tx| {
                let workspace = workspace.clone();
                async move {
                    let visibility = match workspace.visibility {
                        WorkspaceVisibility::Private => "private",
                        WorkspaceVisibility::Public => "public",
                    };
                    let row = sqlx::query(
                        r#"
                            INSERT INTO workspaces
                                (
                                    id,
                                    owner_user_id,
                                    name,
                                    description,
                                    slug,
                                    logo,
                                    primary_color,
                                    visibility,
                                    created_at,
                                    updated_at
                                )
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
                }
                .boxed()
            })
            .await
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
                                visibility = $5::workspace_visibility,
                                logo = $6,
                                slug = $7,
                                updated_at = now()
                            WHERE id = $1
                        "#,
                    )
                    .bind(workspace.id.value)
                    .bind(workspace.name)
                    .bind(workspace.description)
                    .bind(workspace.primary_color)
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
    async fn get(&self, workspace_id: &Id<Workspace>, user_id: &Id<User>) -> AppResult<Option<WorkspaceView>> {
        self.session
            .with_tx(|tx| {
                let workspace_id = workspace_id.value;
                let user_id = user_id.value;
                async move {
                    let row = sqlx::query(
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
                                w.updated_at,
                                (
                                    SELECT COUNT(user_id)
                                    FROM (
                                        SELECT owner_user_id AS user_id
                                        FROM workspaces WHERE id = w.id
                                        UNION
                                        SELECT user_id FROM workspace_members
                                        WHERE workspace_id = w.id AND status = 'active'
                                    ) AS members
                                ) AS total_members,
                                (
                                    SELECT COUNT(id) FROM projects WHERE workspace_id = w.id
                                ) AS total_projects,
                                CASE
                                    WHEN w.owner_user_id = $2 THEN 'owner'
                                    WHEN wm.role = 'admin'::workspace_members_role THEN 'admin'
                                    ELSE 'member'
                                END AS user_role
                            FROM workspaces AS w
                            LEFT JOIN workspace_members AS wm ON w.id = wm.workspace_id AND wm.user_id = $1
                            WHERE w.id = $1
                        "#,
                    )
                    .bind(workspace_id)
                    .bind(user_id)
                    .fetch_optional(tx.as_mut())
                    .await?;

                    match row {
                        Some(row) => Ok(Some(Self::get_workspace_view(&row)?)),
                        None => Ok(None),
                    }
                }
                .boxed()
            })
            .await
    }

    async fn find_accessible_by_user(
        &self,
        user_id: &Id<User>,
        limit: i64,
        offset: i64,
    ) -> AppResult<Vec<WorkspaceView>> {
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
                                w.updated_at,
                                (
                                    SELECT COUNT(user_id)
                                    FROM (
                                        SELECT owner_user_id AS user_id
                                        FROM workspaces WHERE id = w.id
                                        UNION
                                        SELECT user_id FROM workspace_members
                                        WHERE workspace_id = w.id AND status = 'active'
                                    ) AS members
                                ) AS total_members,
                                (
                                    SELECT COUNT(id) FROM projects WHERE workspace_id = w.id
                                ) AS total_projects,
                                CASE
                                    WHEN w.owner_user_id = $1 THEN 'owner'
                                    WHEN wm.role = 'admin'::workspace_members_role THEN 'admin'
                                    ELSE 'member'
                                END AS user_role
                            FROM workspaces AS w
                            LEFT JOIN workspace_members AS wm ON w.id = wm.workspace_id AND wm.user_id = $1
                            WHERE
                                w.owner_user_id = $1
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

                    rows.iter().map(Self::get_workspace_view).collect()
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
                                w.owner_user_id = $1
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
                                                AND wm.user_id = $2
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

    async fn find_by_id_and_slug(
        &self,
        workspace_id: &Id<Workspace>,
        user_id: &Id<User>,
        slug: &str,
    ) -> AppResult<Option<WorkspaceView>> {
        self.session
            .with_tx(|tx| {
                let workspace_id = workspace_id.value;
                let slug = slug.to_owned();
                let user_id = user_id.value;
                async move {
                    let row = sqlx::query(
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
                                w.updated_at,
                                w.created_at,
                                (
                                    SELECT COUNT(user_id)
                                    FROM (
                                        SELECT owner_user_id AS user_id
                                        FROM workspaces WHERE id = w.id
                                        UNION
                                        SELECT user_id FROM workspace_members
                                        WHERE workspace_id = w.id AND status = 'active'
                                    ) AS members
                                ) AS total_members,
                                (
                                    SELECT COUNT(id) FROM projects WHERE workspace_id = w.id
                                ) AS total_projects,
                                CASE
                                    WHEN w.owner_user_id = $3 THEN 'owner'
                                    WHEN wm.role = 'admin'::workspace_members_role THEN 'admin'
                                    ELSE 'member'
                                END AS user_role
                            FROM workspaces AS w
                            LEFT JOIN workspace_members AS wm ON w.id = wm.workspace_id AND wm.user_id = $3
                            WHERE w.id = $1 AND w.slug = $2
                        "#,
                    )
                    .bind(workspace_id)
                    .bind(slug)
                    .bind(user_id)
                    .fetch_optional(tx.as_mut())
                    .await?;

                    match row {
                        Some(row) => Ok(Some(Self::get_workspace_view(&row)?)),
                        None => Ok(None),
                    }
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
            expires_at: row.try_get("expires_at")?,
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
                            (id, workspace_id, email, invite_token, invited_by, expires_at, accepted_at, revoked_at, created_at)
                        VALUES
                            ($1, $2, $3, $4, $5, $6, $7, $8, $9)
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

#[async_trait]
impl WorkspaceInviteReader for WorkspaceInviteGateway {
    async fn find_by_token(&self, token: &str) -> AppResult<Option<WorkspaceInvite>> {
        self.session
            .with_tx(|tx| {
                let token = token.to_owned();
                async move {
                    let row = sqlx::query(
                        r#"
                            SELECT
                                id,
                                workspace_id,
                                email,
                                invite_token,
                                invited_by,
                                expires_at,
                                accepted_at,
                                revoked_at,
                                created_at
                            FROM workspace_invites
                            WHERE workspace_invites.invite_token = $1
                        "#,
                    )
                    .bind(token)
                    .fetch_optional(tx.as_mut())
                    .await?;

                    match row {
                        Some(row) => Ok(Some(Self::get_workspace_invite(&row)?)),
                        None => Ok(None),
                    }
                }
                .boxed()
            })
            .await
    }

    async fn find_by_email(&self, workspace_id: &Id<Workspace>, email: &str) -> AppResult<Option<WorkspaceInvite>> {
        self.session
            .with_tx(|tx| {
                let email = email.to_owned();
                let workspace_id = workspace_id.value;
                async move {
                    let row = sqlx::query(
                        r#"
                            SELECT
                                id,
                                workspace_id,
                                email,
                                invite_token,
                                invited_by,
                                expires_at,
                                accepted_at,
                                revoked_at,
                                created_at
                            FROM workspace_invites
                            WHERE workspace_invites.email = $1
                                AND workspace_invites.workspace_id = $2
                        "#,
                    )
                    .bind(email)
                    .bind(workspace_id)
                    .fetch_optional(tx.as_mut())
                    .await?;

                    match row {
                        Some(row) => Ok(Some(Self::get_workspace_invite(&row)?)),
                        None => Ok(None),
                    }
                }
                .boxed()
            })
            .await
    }
}

#[derive(Clone)]
pub struct WorkspaceMemberGateway {
    session: SqlxSession,
}

impl WorkspaceMemberGateway {
    pub fn new(session: SqlxSession) -> Self {
        Self { session }
    }

    fn get_workspace_member(row: &PgRow) -> AppResult<WorkspaceMember> {
        let role = match row.try_get::<String, _>("role")?.as_str() {
            "admin" => WorkspaceMemberRole::Admin,
            _ => WorkspaceMemberRole::Member,
        };
        let status = match row.try_get::<String, _>("status")?.as_str() {
            "active" => WorkspaceMemberStatus::Active,
            "inactive" => WorkspaceMemberStatus::Inactive,
            _ => WorkspaceMemberStatus::Awaiting,
        };
        Ok(WorkspaceMember {
            id: Id::new(row.try_get("id")?),
            workspace_id: Id::new(row.try_get("workspace_id")?),
            user_id: Id::new(row.try_get("user_id")?),
            role,
            joined_at: row.try_get("joined_at")?,
            invited_by: Id::new(row.try_get("invited_by")?),
            status,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[async_trait]
impl WorkspaceMemberWriter for WorkspaceMemberGateway {
    async fn insert(&self, workspace_member: WorkspaceMember) -> AppResult<Id<WorkspaceMember>> {
        self.session
            .with_tx(|tx| {
                let workspace_member = workspace_member.clone();
                async move {
                    let role = match workspace_member.role {
                        WorkspaceMemberRole::Admin => "admin",
                        WorkspaceMemberRole::Member => "member",
                    };
                    let row = sqlx::query(
                        r#"
                            INSERT INTO workspace_members
                                (id, workspace_id, user_id, role, joined_at, invited_by, status, created_at)
                            VALUES
                                ($1, $2, $3, $4::workspace_members_role, now(), $5, 'active', now())
                            RETURNING id
                        "#,
                    )
                    .bind(workspace_member.id.value)
                    .bind(workspace_member.workspace_id.value)
                    .bind(workspace_member.user_id.value)
                    .bind(role)
                    .bind(workspace_member.invited_by.value)
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
impl WorkspaceMemberReader for WorkspaceMemberGateway {
    async fn get(&self, workspace_id: &Id<Workspace>, user_id: &Id<User>) -> AppResult<Option<WorkspaceMember>> {
        self.session
            .with_tx(|tx| {
                let workspace_id = workspace_id.value;
                let user_id = user_id.value;
                async move {
                    let row = sqlx::query(
                        r#"
                            SELECT
                                id,
                                workspace_id,
                                user_id,
                                role,
                                joined_at,
                                invited_by,
                                status,
                                created_at
                            FROM workspace_members
                            WHERE workspace_id = $1 AND user_id = $2
                        "#,
                    )
                    .bind(workspace_id)
                    .bind(user_id)
                    .fetch_optional(tx.as_mut())
                    .await?;

                    match row {
                        Some(row) => Ok(Some(Self::get_workspace_member(&row)?)),
                        None => Ok(None),
                    }
                }
                .boxed()
            })
            .await
    }
}

#[derive(Clone)]
pub struct WorkspacePinGateway {
    session: SqlxSession,
}

impl WorkspacePinGateway {
    pub fn new(session: SqlxSession) -> Self {
        Self { session }
    }

    fn get_workspace_pin(row: &PgRow) -> AppResult<WorkspacePin> {
        Ok(WorkspacePin {
            user_id: Id::new(row.try_get("user_id")?),
            workspace_id: Id::new(row.try_get("workspace_id")?),
        })
    }
}

#[async_trait]
impl WorkspacePinWriter for WorkspacePinGateway {
    async fn set_workspace_pin(&self, workspace_id: &Id<Workspace>, user_id: &Id<User>) -> AppResult<()> {
        self.session
            .with_tx(|tx| {
                let workspace_id = workspace_id.value;
                let user_id = user_id.value;
                async move {
                    sqlx::query(
                        r#"
                        INSERT INTO workspace_pins (workspace_id, user_id)
                        VALUES ($1, $2)
                        ON CONFLICT (user_id) DO UPDATE SET
                            workspace_id = EXCLUDED.workspace_id
                    "#,
                    )
                    .bind(workspace_id)
                    .bind(user_id)
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
                        DELETE FROM workspace_pins
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
impl WorkspacePinReader for WorkspacePinGateway {
    async fn get(&self, user_id: &Id<User>) -> AppResult<Option<WorkspacePin>> {
        self.session
            .with_tx(|tx| {
                let user_id = user_id.value;
                async move {
                    let row = sqlx::query(
                        r#"
                        SELECT user_id, workspace_id
                        FROM workspace_pins
                        WHERE user_id = $1
                    "#,
                    )
                    .bind(user_id)
                    .fetch_optional(tx.as_mut())
                    .await?;

                    match row {
                        Some(row) => Ok(Some(Self::get_workspace_pin(&row)?)),
                        None => Ok(None),
                    }
                }
                .boxed()
            })
            .await
    }
}
