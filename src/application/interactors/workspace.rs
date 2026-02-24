use std::sync::Arc;

use tracing::{error, info};

use crate::application::app_error::{AppError, AppResult};
use crate::application::dto::user::UserDTO;
use crate::application::dto::workspace::{
    AcceptWorkspaceInviteDTO, CheckWorkspaceOwnerDTO, CreateWorkspaceDTO, DeleteWorkspaceDTO, GetWorkspaceDTO,
    GetWorkspaceListDTO, GetWorkspaceLogoDTO, InviteWorkspaceMemberDTO, UpdateWorkspaceDTO, WorkspaceDTO,
    WorkspaceListDTO, WorkspaceLogoDTO,
};
use crate::application::interface::db::DBSession;
use crate::application::interface::email::EmailSender;
use crate::application::interface::gateway::user::UserReader;
use crate::application::interface::gateway::workspace::{
    WorkspaceInviteReader, WorkspaceInviteWriter, WorkspaceMemberReader, WorkspaceMemberWriter, WorkspaceReader,
    WorkspaceWriter,
};
use crate::application::interface::s3::StorageClient;
use crate::domain::entities::id::Id;
use crate::domain::entities::user::User;
use crate::domain::entities::workspace::{
    Workspace, WorkspaceInvite, WorkspaceMember, WorkspaceMemberRole, WorkspaceMemberStatus, WorkspaceUserRole,
    WorkspaceVisibility,
};
use crate::infra::constants::MAX_PER_PAGE;

#[derive(Clone)]
pub struct CreateWorkspaceInteractor {
    db_session: Arc<dyn DBSession>,
    workspace_writer: Arc<dyn WorkspaceWriter>,
    storage: Arc<dyn StorageClient>,
}

impl CreateWorkspaceInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        workspace_writer: Arc<dyn WorkspaceWriter>,
        storage: Arc<dyn StorageClient>,
    ) -> Self {
        Self {
            db_session,
            workspace_writer,
            storage,
        }
    }

    pub async fn execute(&self, dto: CreateWorkspaceDTO) -> AppResult<()> {
        let owner_user_id: Id<User> = dto.owner_user_id.try_into()?;
        let visibility: WorkspaceVisibility = dto.visibility.parse()?;

        let mut workspace = Workspace::new(owner_user_id, dto.name, dto.description, dto.primary_color, visibility);

        let bucket = workspace.id.value.to_string();

        self.storage
            .ensure_bucket(&bucket)
            .await
            .map_err(|_| AppError::CreatedWorkspaceError)?;

        if let Some(logo_bytes) = dto.logo {
            let detected = self
                .storage
                .detect_image(&logo_bytes)
                .ok_or(AppError::UnsupportedImageFormat)?;

            let key = format!("logo.{}", detected.ext);

            self.storage
                .upload(&bucket, &key, logo_bytes, detected.content_type)
                .await
                .map_err(|_| AppError::CreatedWorkspaceError)?;

            workspace.logo = Some(format!("/workspaces/{}/storage/{}", bucket, key));
        }

        self.workspace_writer.insert(workspace).await?;
        self.db_session.commit().await?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct GetWorkspaceListInteractor {
    workspace_reader: Arc<dyn WorkspaceReader>,
}

impl GetWorkspaceListInteractor {
    pub fn new(workspace_reader: Arc<dyn WorkspaceReader>) -> Self {
        Self { workspace_reader }
    }

    pub async fn execute(&self, dto: GetWorkspaceListDTO) -> AppResult<WorkspaceListDTO> {
        let user_id: Id<User> = dto.user_id.try_into()?;

        let per_page = dto.per_page.clamp(1, MAX_PER_PAGE);
        let page = dto.page.max(1);
        let offset = (page - 1) * per_page;

        let total = self.workspace_reader.count_accessible_by_user(&user_id).await?;
        let workspaces = self
            .workspace_reader
            .find_accessible_by_user(&user_id, per_page, offset)
            .await?;

        let items = workspaces
            .into_iter()
            .map(|workspace_view| {
                let workspace = workspace_view.workspace;
                WorkspaceDTO {
                    id: workspace.id.value.to_string(),
                    owner_user_id: workspace.owner_user_id.value.to_string(),
                    name: workspace.name,
                    description: workspace.description,
                    slug: workspace.slug,
                    logo: workspace.logo,
                    primary_color: workspace.primary_color,
                    visibility: match workspace.visibility {
                        WorkspaceVisibility::Public => "public".to_string(),
                        WorkspaceVisibility::Private => "private".to_string(),
                    },
                    created_at: workspace.created_at,
                    updated_at: workspace.updated_at,
                    total_members: workspace_view.total_members,
                    total_projects: workspace_view.total_projects,
                    user_role: match workspace_view.user_role {
                        WorkspaceUserRole::Owner => "owner".to_string(),
                        WorkspaceUserRole::Admin => "admin".to_string(),
                        WorkspaceUserRole::Member => "member".to_string(),
                    },
                }
            })
            .collect();

        Ok(WorkspaceListDTO {
            page,
            per_page,
            total,
            items,
        })
    }
}

#[derive(Clone)]
pub struct GetWorkspaceLogoInteractor {
    workspace_reader: Arc<dyn WorkspaceReader>,
    storage: Arc<dyn StorageClient>,
}

impl GetWorkspaceLogoInteractor {
    pub fn new(workspace_reader: Arc<dyn WorkspaceReader>, storage: Arc<dyn StorageClient>) -> Self {
        Self {
            workspace_reader,
            storage,
        }
    }

    pub async fn execute(&self, dto: GetWorkspaceLogoDTO) -> AppResult<WorkspaceLogoDTO> {
        let workspace_id: Id<Workspace> = dto.workspace_id.try_into()?;
        let user_id: Id<User> = dto.user_id.try_into()?;

        let accessible = self
            .workspace_reader
            .is_accessible_by_user(&workspace_id, &user_id)
            .await?;

        if !accessible {
            return Err(AppError::InvalidCredentials);
        }

        let file = self
            .storage
            .download(&workspace_id.value.to_string(), &dto.file_name)
            .await?;

        Ok(WorkspaceLogoDTO {
            data: file.data,
            content_type: file.content_type,
        })
    }
}

#[derive(Clone)]
pub struct UpdateWorkspaceInteractor {
    db_session: Arc<dyn DBSession>,
    workspace_writer: Arc<dyn WorkspaceWriter>,
    workspace_reader: Arc<dyn WorkspaceReader>,
    storage: Arc<dyn StorageClient>,
}

impl UpdateWorkspaceInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        workspace_writer: Arc<dyn WorkspaceWriter>,
        workspace_reader: Arc<dyn WorkspaceReader>,
        storage: Arc<dyn StorageClient>,
    ) -> Self {
        Self {
            db_session,
            workspace_writer,
            workspace_reader,
            storage,
        }
    }

    pub async fn execute(&self, dto: UpdateWorkspaceDTO) -> AppResult<()> {
        let user_id: Id<User> = dto.user_id.try_into()?;
        let workspace_id: Id<Workspace> = dto.workspace_id.try_into()?;

        let workspace_view = self
            .workspace_reader
            .get(&workspace_id, &user_id)
            .await?
            .ok_or(AppError::WorkspaceNotFound)?;

        let mut workspace = workspace_view.workspace;

        if workspace.owner_user_id.value != user_id.value {
            return Err(AppError::AccessDenied);
        }

        if let Some(name) = dto.name {
            workspace.set_slug(&name);
            workspace.name = name;
        }

        if let Some(description) = dto.description {
            workspace.description = Some(description);
        }

        if let Some(primary_color) = dto.primary_color {
            workspace.primary_color = primary_color;
        }

        if let Some(visibility) = dto.visibility {
            workspace.visibility = visibility.parse()?;
        }

        if let Some(logo_bytes) = dto.logo {
            let detected = self
                .storage
                .detect_image(&logo_bytes)
                .ok_or(AppError::UnsupportedImageFormat)?;

            let bucket = workspace_id.value.to_string();
            let key = format!("logo.{}", detected.ext);

            self.storage
                .upload(&bucket, &key, logo_bytes, detected.content_type)
                .await
                .map_err(|_| AppError::CreatedWorkspaceError)?;

            workspace.logo = Some(format!("/workspaces/{}/storage/{}", bucket, key));
        }

        self.workspace_writer.update(workspace).await?;
        self.db_session.commit().await?;

        Ok(())
    }
}

pub struct DeleteWorkspaceInteractor {
    db_session: Arc<dyn DBSession>,
    workspace_reader: Arc<dyn WorkspaceReader>,
    workspace_writer: Arc<dyn WorkspaceWriter>,
    storage: Arc<dyn StorageClient>,
}

impl DeleteWorkspaceInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        workspace_reader: Arc<dyn WorkspaceReader>,
        workspace_writer: Arc<dyn WorkspaceWriter>,
        storage: Arc<dyn StorageClient>,
    ) -> Self {
        Self {
            db_session,
            workspace_reader,
            workspace_writer,
            storage,
        }
    }

    pub async fn execute(&self, dto: DeleteWorkspaceDTO) -> AppResult<()> {
        let user_id: Id<User> = dto.user_id.try_into()?;
        let workspace_id: Id<Workspace> = dto.workspace_id.try_into()?;

        let workspace = self
            .workspace_reader
            .get(&workspace_id, &user_id)
            .await?
            .ok_or(AppError::WorkspaceNotFound)?
            .workspace;

        if workspace.owner_user_id.value != user_id.value {
            return Err(AppError::AccessDenied);
        }

        self.storage.delete_bucket(&workspace_id.value.to_string()).await?;

        self.workspace_writer.delete(&workspace_id).await?;
        self.db_session.commit().await?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct CheckWorkspaceOwnerInteractor {
    workspace_reader: Arc<dyn WorkspaceReader>,
}

impl CheckWorkspaceOwnerInteractor {
    pub fn new(workspace_reader: Arc<dyn WorkspaceReader>) -> Self {
        Self { workspace_reader }
    }

    pub async fn execute(&self, dto: CheckWorkspaceOwnerDTO) -> AppResult<()> {
        let user_id: Id<User> = dto.user_id.try_into()?;
        let workspace_id: Id<Workspace> = dto.workspace_id.try_into()?;

        let workspace = self
            .workspace_reader
            .get(&workspace_id, &user_id)
            .await?
            .ok_or(AppError::WorkspaceNotFound)?
            .workspace;

        if workspace.owner_user_id.value != user_id.value {
            return Err(AppError::AccessDenied);
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct InviteWorkspaceMemberInteractor {
    db_session: Arc<dyn DBSession>,
    workspace_reader: Arc<dyn WorkspaceReader>,
    workspace_member_reader: Arc<dyn WorkspaceMemberReader>,
    workspace_invite_reader: Arc<dyn WorkspaceInviteReader>,
    workspace_invite_writer: Arc<dyn WorkspaceInviteWriter>,
    email_sender: Arc<dyn EmailSender>,
}

impl InviteWorkspaceMemberInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        workspace_reader: Arc<dyn WorkspaceReader>,
        workspace_member_reader: Arc<dyn WorkspaceMemberReader>,
        workspace_invite_reader: Arc<dyn WorkspaceInviteReader>,
        workspace_invite_writer: Arc<dyn WorkspaceInviteWriter>,
        email_sender: Arc<dyn EmailSender>,
    ) -> Self {
        Self {
            db_session,
            workspace_reader,
            workspace_member_reader,
            workspace_invite_reader,
            workspace_invite_writer,
            email_sender,
        }
    }

    pub async fn execute(&self, dto: InviteWorkspaceMemberDTO) -> AppResult<()> {
        let user_id: Id<User> = dto.user_id.try_into()?;
        let workspace_id: Id<Workspace> = dto.workspace_id.try_into()?;

        let workspace = self
            .workspace_reader
            .get(&workspace_id, &user_id)
            .await?
            .ok_or(AppError::WorkspaceNotFound)?
            .workspace;

        let is_owner = workspace.owner_user_id.value == user_id.value;
        if !is_owner {
            let workspace_member = self
                .workspace_member_reader
                .get(&workspace_id, &user_id)
                .await?
                .ok_or(AppError::AccessDenied)?;

            if !matches!(workspace_member.role, WorkspaceMemberRole::Admin)
                || !matches!(workspace_member.status, WorkspaceMemberStatus::Active)
            {
                return Err(AppError::AccessDenied);
            }
        }

        let existing_invite = self
            .workspace_invite_reader
            .find_by_email(&workspace_id, &dto.email)
            .await?;

        if let Some(invite) = existing_invite {
            if invite.is_pending() {
                return Err(AppError::InviteAlreadyExists);
            }
            self.workspace_invite_writer
                .delete_by_email(&workspace_id, &dto.email)
                .await?;
        }

        let workspace_invite = WorkspaceInvite::new(workspace_id, dto.email.clone(), user_id, dto.ttl);
        let invite_token = workspace_invite.invite_token.clone();

        self.workspace_invite_writer.insert(workspace_invite).await?;
        self.db_session.commit().await?;

        let email_sender = Arc::clone(&self.email_sender);
        let invite_link = format!("{}?token={}", dto.invite_url, invite_token);
        let workspace_name = workspace.name.clone();
        let email = dto.email.clone();

        tokio::spawn(async move {
            let subject = format!("Приглашение в рабочее пространство {}", workspace_name);
            let body = format!(
                "Вас пригласили в рабочее пространство {}, \
             Перейдите по ссылке для принятия приглашения: {}",
                workspace_name, invite_link
            );
            info!("Sending workspace invite to {}", email);
            if let Err(err) = email_sender.send(&email, &subject, &body).await {
                error!("Failed to send workspace invite to {}: {}", email, err);
                return;
            }
            info!("Workspace invite sent to {}", email);
        });

        Ok(())
    }
}

#[derive(Clone)]
pub struct AcceptWorkspaceInviteInteractor {
    db_session: Arc<dyn DBSession>,
    workspace_invite_reader: Arc<dyn WorkspaceInviteReader>,
    workspace_invite_writer: Arc<dyn WorkspaceInviteWriter>,
    workspace_member_reader: Arc<dyn WorkspaceMemberReader>,
    workspace_member_writer: Arc<dyn WorkspaceMemberWriter>,
}

impl AcceptWorkspaceInviteInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        workspace_invite_reader: Arc<dyn WorkspaceInviteReader>,
        workspace_invite_writer: Arc<dyn WorkspaceInviteWriter>,
        workspace_member_reader: Arc<dyn WorkspaceMemberReader>,
        workspace_member_writer: Arc<dyn WorkspaceMemberWriter>,
    ) -> Self {
        Self {
            db_session,
            workspace_invite_reader,
            workspace_invite_writer,
            workspace_member_reader,
            workspace_member_writer,
        }
    }

    pub async fn execute(&self, dto: AcceptWorkspaceInviteDTO) -> AppResult<()> {
        let user_id: Id<User> = dto.user_id.try_into()?;

        let invite = self
            .workspace_invite_reader
            .find_by_token(&dto.token)
            .await?
            .ok_or(AppError::InviteNotFound)?;

        if invite.is_expired() {
            return Err(AppError::InviteExpired);
        }

        if !invite.is_pending() {
            return Err(AppError::InviteInvalid);
        }

        let existing_member = self.workspace_member_reader.get(&invite.workspace_id, &user_id).await?;

        if existing_member.is_none() {
            let member = WorkspaceMember::new(
                invite.workspace_id.clone(),
                user_id,
                invite.invited_by.clone(),
                WorkspaceMemberRole::Member,
            );
            self.workspace_member_writer.insert(member).await?;
        }

        self.workspace_invite_writer.accept(&invite.id).await?;
        self.db_session.commit().await?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct GetWorkspaceInteractor {
    workspace_reader: Arc<dyn WorkspaceReader>,
}

impl GetWorkspaceInteractor {
    pub fn new(workspace_reader: Arc<dyn WorkspaceReader>) -> Self {
        Self { workspace_reader }
    }

    pub async fn execute(&self, dto: GetWorkspaceDTO) -> AppResult<WorkspaceDTO> {
        let user_id: Id<User> = dto.user_id.try_into()?;
        let workspace_id: Id<Workspace> = dto.workspace_id.try_into()?;

        let workspace_view = self
            .workspace_reader
            .find_by_id_and_slug(&workspace_id, &user_id, &dto.slug)
            .await?
            .ok_or(AppError::WorkspaceNotFound)?;
        let workspace = workspace_view.workspace;

        let accessible = self
            .workspace_reader
            .is_accessible_by_user(&workspace_id, &user_id)
            .await?;

        if !accessible {
            return Err(AppError::AccessDenied);
        }

        Ok(WorkspaceDTO {
            id: workspace.id.value.to_string(),
            owner_user_id: workspace.owner_user_id.value.to_string(),
            name: workspace.name,
            description: workspace.description,
            slug: workspace.slug,
            logo: workspace.logo,
            primary_color: workspace.primary_color,
            visibility: match workspace.visibility {
                WorkspaceVisibility::Private => "private".to_string(),
                WorkspaceVisibility::Public => "public".to_string(),
            },
            created_at: workspace.created_at,
            updated_at: workspace.updated_at,
            total_members: workspace_view.total_members,
            total_projects: workspace_view.total_projects,
            user_role: match workspace_view.user_role {
                WorkspaceUserRole::Owner => "owner".to_string(),
                WorkspaceUserRole::Admin => "admin".to_string(),
                WorkspaceUserRole::Member => "member".to_string(),
            },
        })
    }
}

#[derive(Clone)]
pub struct GetOwnerWorkspaceInteractor {
    workspace_reader: Arc<dyn WorkspaceReader>,
    user_reader: Arc<dyn UserReader>,
}

impl GetOwnerWorkspaceInteractor {
    pub fn new(workspace_reader: Arc<dyn WorkspaceReader>, user_reader: Arc<dyn UserReader>) -> Self {
        Self {
            workspace_reader,
            user_reader,
        }
    }

    pub async fn execute(&self, dto: GetWorkspaceDTO) -> AppResult<UserDTO> {
        let user_id: Id<User> = dto.user_id.try_into()?;
        let workspace_id: Id<Workspace> = dto.workspace_id.try_into()?;

        let workspace = self
            .workspace_reader
            .find_by_id_and_slug(&workspace_id, &user_id, &dto.slug)
            .await?
            .ok_or(AppError::WorkspaceNotFound)?
            .workspace;

        let accessible = self
            .workspace_reader
            .is_accessible_by_user(&workspace_id, &user_id)
            .await?;

        if !accessible {
            return Err(AppError::AccessDenied);
        }

        let user = self.user_reader.find_by_id(&workspace.owner_user_id).await?;

        match user {
            Some(user) => Ok(UserDTO {
                id: user.id.value.to_string(),
                username: user.username,
                email: user.email,
                created_at: user.created_at,
                updated_at: user.updated_at,
            }),
            None => Err(AppError::AccessDenied),
        }
    }
}
