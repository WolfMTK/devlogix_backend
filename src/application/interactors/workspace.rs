use std::sync::Arc;

use slug::slugify;
use tracing::{error, info};
use uuid::Uuid;

use crate::application::app_error::{AppError, AppResult};
use crate::application::dto::workspace::{
    AcceptWorkspaceInviteDTO, CheckWorkspaceOwnerDTO, CreateWorkspaceDTO, DeleteWorkspaceDTO, GetWorkspaceDTO,
    GetWorkspaceListDTO, GetWorkspaceLogoDTO, InviteWorkspaceMemberDTO, UpdateWorkspaceDTO, WorkspaceDTO,
    WorkspaceListDTO, WorkspaceLogoDTO,
};
use crate::application::interface::db::DBSession;
use crate::application::interface::email::EmailSender;
use crate::application::interface::gateway::workspace::{
    WorkspaceInviteReader, WorkspaceInviteWriter, WorkspaceMemberReader, WorkspaceMemberWriter, WorkspaceReader,
    WorkspaceWriter,
};
use crate::application::interface::s3::StorageClient;
use crate::domain::entities::id::Id;
use crate::domain::entities::user::User;
use crate::domain::entities::workspace::{
    Workspace, WorkspaceInvite, WorkspaceMember, WorkspaceMemberRole, WorkspaceMemberStatus, WorkspaceVisibility,
};

const MAX_PER_PAGE: i64 = 100;

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
        info!("{:?}", total);
        let workspaces = self
            .workspace_reader
            .find_accessible_by_user(&user_id, per_page, offset)
            .await?;

        let items = workspaces
            .into_iter()
            .map(|w| WorkspaceDTO {
                id: w.id.value.to_string(),
                owner_user_id: w.owner_user_id.value.to_string(),
                name: w.name,
                description: w.description,
                slug: w.slug,
                logo: w.logo,
                primary_color: w.primary_color,
                visibility: match w.visibility {
                    WorkspaceVisibility::Public => "public".to_string(),
                    WorkspaceVisibility::Private => "private".to_string(),
                },
                created_at: w.created_at,
                updated_at: w.updated_at,
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

        let mut workspace = self
            .workspace_reader
            .get(&workspace_id)
            .await?
            .ok_or(AppError::WorkspaceNotFound)?;

        if workspace.owner_user_id.value != user_id.value {
            return Err(AppError::AccessDenied);
        }

        if let Some(name) = dto.name {
            // TODO: transfer slug creation to Workspace
            workspace.slug = slugify(&name);
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
            .get(&workspace_id)
            .await?
            .ok_or(AppError::WorkspaceNotFound)?;

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
            .get(&workspace_id)
            .await?
            .ok_or(AppError::WorkspaceNotFound)?;

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
            .get(&workspace_id)
            .await?
            .ok_or(AppError::WorkspaceNotFound)?;

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

        self.workspace_invite_writer
            .delete_by_email(&workspace_id, &dto.email)
            .await?;

        let token = Uuid::now_v7();
        let workspace_invite =
            WorkspaceInvite::new(workspace_id, dto.email.clone(), token.to_string(), user_id, dto.ttl);
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
pub struct AcceptWorkpspaceInviteIneractor {
    db_session: Arc<dyn DBSession>,
    workspace_invite_reader: Arc<dyn WorkspaceInviteReader>,
    workspace_invite_writer: Arc<dyn WorkspaceInviteWriter>,
    workspace_member_reader: Arc<dyn WorkspaceMemberReader>,
    workspace_member_writer: Arc<dyn WorkspaceMemberWriter>,
}

impl AcceptWorkpspaceInviteIneractor {
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

        let workspace = self
            .workspace_reader
            .find_by_id_and_slug(&workspace_id, &dto.slug)
            .await?
            .ok_or(AppError::WorkspaceNotFound)?;

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
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use bytes::Bytes;
    use mockall::mock;
    use rstest::{fixture, rstest};

    use crate::application::app_error::{AppError, AppResult};
    use crate::application::dto::workspace::CreateWorkspaceDTO;
    use crate::application::interactors::workspace::CreateWorkspaceInteractor;
    use crate::application::interface::db::DBSession;
    use crate::application::interface::gateway::workspace::WorkspaceWriter;
    use crate::application::interface::s3::{DetectedImage, DownloadedFile, StorageClient};
    use crate::domain::entities::id::Id;
    use crate::domain::entities::workspace::Workspace;

    // Mocks
    mock! {
        pub DBSessionMock {}

        #[async_trait]
        impl DBSession for DBSessionMock {
            async fn commit(&self) -> AppResult<()>;
        }
    }

    mock! {
        pub WorkspaceWriterMock {}

        #[async_trait]
        impl WorkspaceWriter for WorkspaceWriterMock {
            async fn insert(&self, workspace: Workspace) -> AppResult<Id<Workspace>>;
            async fn update(&self, workspace: Workspace) -> AppResult<()>;
            async fn delete(&self, workspace_id: &Id<Workspace>) -> AppResult<()>;
        }
    }

    mock! {
        pub StorageClientMock {}

        #[async_trait]
        impl StorageClient for StorageClientMock {
            async fn ensure_bucket(&self, bucket: &str) -> AppResult<()>;
            async fn upload(&self, bucket: &str, key: &str, data: Bytes, content_type: &str) -> AppResult<()>;
            async fn download(&self, bucket: &str, key: &str) -> AppResult<DownloadedFile>;
            async fn delete(&self, bucket: &str, key: &str) -> AppResult<()>;
            async fn delete_bucket(&self, bucket: &str) -> AppResult<()>;
            fn detect_image(&self, data: &[u8]) -> Option<DetectedImage>;
        }
    }

    // Constants
    const OWNER_USER_ID: &str = "019c47ec-183d-744e-b11d-cd409015bf13";

    const PNG_BYTES: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    // Fixtures
    #[fixture]
    fn dto_without_logo() -> CreateWorkspaceDTO {
        CreateWorkspaceDTO {
            owner_user_id: OWNER_USER_ID.to_string(),
            name: "My Workspace".to_string(),
            description: None,
            logo: None,
            primary_color: "#ffffff".to_string(),
            visibility: "private".to_string(),
        }
    }

    #[fixture]
    fn dto_with_logo() -> CreateWorkspaceDTO {
        CreateWorkspaceDTO {
            logo: Some(Bytes::from_static(PNG_BYTES)),
            ..dto_without_logo()
        }
    }

    // Helpers
    fn setup_storage_ok(storage: &mut MockStorageClientMock) {
        storage.expect_ensure_bucket().returning(|_| Ok(()));
    }

    fn setup_happy_path(
        db_session: &mut MockDBSessionMock,
        workspace_writer: &mut MockWorkspaceWriterMock,
        storage: &mut MockStorageClientMock,
    ) {
        setup_storage_ok(storage);
        workspace_writer.expect_insert().returning(|w| Ok(w.id));
        db_session.expect_commit().returning(|| Ok(()));
    }

    fn make_interactor(
        db_session: MockDBSessionMock,
        workspace_writer: MockWorkspaceWriterMock,
        storage: MockStorageClientMock,
    ) -> CreateWorkspaceInteractor {
        CreateWorkspaceInteractor::new(Arc::new(db_session), Arc::new(workspace_writer), Arc::new(storage))
    }

    // CreateWorkspaceInteractor tests
    #[rstest]
    #[tokio::test]
    async fn test_create_workspace_success_without_logo(dto_without_logo: CreateWorkspaceDTO) {
        let mut db_session = MockDBSessionMock::new();
        let mut workspace_writer = MockWorkspaceWriterMock::new();
        let mut storage = MockStorageClientMock::new();

        setup_happy_path(&mut db_session, &mut workspace_writer, &mut storage);

        let result = make_interactor(db_session, workspace_writer, storage)
            .execute(dto_without_logo)
            .await;

        assert!(result.is_ok());
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_workspace_success_with_logo(dto_with_logo: CreateWorkspaceDTO) {
        let mut db_session = MockDBSessionMock::new();
        let mut workspace_writer = MockWorkspaceWriterMock::new();
        let mut storage = MockStorageClientMock::new();

        setup_storage_ok(&mut storage);
        storage.expect_detect_image().returning(|_| {
            Some(DetectedImage {
                content_type: "image/png",
                ext: "png",
            })
        });
        storage.expect_upload().returning(|_, _, _, _| Ok(()));
        workspace_writer.expect_insert().returning(|w| Ok(w.id));
        db_session.expect_commit().returning(|| Ok(()));

        let result = make_interactor(db_session, workspace_writer, storage)
            .execute(dto_with_logo)
            .await;

        assert!(result.is_ok());
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_workspace_logo_url_contains_workspace_id(dto_with_logo: CreateWorkspaceDTO) {
        let mut db_session = MockDBSessionMock::new();
        let mut workspace_writer = MockWorkspaceWriterMock::new();
        let mut storage = MockStorageClientMock::new();

        setup_storage_ok(&mut storage);
        storage.expect_detect_image().returning(|_| {
            Some(DetectedImage {
                content_type: "image/png",
                ext: "png",
            })
        });
        storage.expect_upload().returning(|_, _, _, _| Ok(()));
        workspace_writer.expect_insert().returning(|w| {
            let workspace_id = w.id.value.to_string();
            let logo = w.logo.clone().expect("logo should be set");
            assert!(logo.contains(&workspace_id), "logo URL must contain workspace id");
            assert!(logo.ends_with("logo.png"), "logo URL must end with logo.png");
            assert!(logo.starts_with("/workspaces/"), "logo URL must be a backend path");
            Ok(w.id)
        });
        db_session.expect_commit().returning(|| Ok(()));

        make_interactor(db_session, workspace_writer, storage)
            .execute(dto_with_logo)
            .await
            .unwrap();
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_workspace_unsupported_image_format(mut dto_with_logo: CreateWorkspaceDTO) {
        let db_session = MockDBSessionMock::new();
        let workspace_writer = MockWorkspaceWriterMock::new();
        let mut storage = MockStorageClientMock::new();

        dto_with_logo.logo = Some(Bytes::from_static(b"not-an-image"));

        setup_storage_ok(&mut storage);
        storage.expect_detect_image().returning(|_| None);

        let result = make_interactor(db_session, workspace_writer, storage)
            .execute(dto_with_logo)
            .await;

        assert!(matches!(result.unwrap_err(), AppError::UnsupportedImageFormat));
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_workspace_ensure_bucket_fails(dto_without_logo: CreateWorkspaceDTO) {
        let db_session = MockDBSessionMock::new();
        let workspace_writer = MockWorkspaceWriterMock::new();
        let mut storage = MockStorageClientMock::new();

        storage
            .expect_ensure_bucket()
            .returning(|_| Err(AppError::StorageError("connection refused".to_string())));

        let result = make_interactor(db_session, workspace_writer, storage)
            .execute(dto_without_logo)
            .await;

        assert!(matches!(result.unwrap_err(), AppError::CreatedWorkspaceError));
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_workspace_upload_fails(dto_with_logo: CreateWorkspaceDTO) {
        let db_session = MockDBSessionMock::new();
        let workspace_writer = MockWorkspaceWriterMock::new();
        let mut storage = MockStorageClientMock::new();

        setup_storage_ok(&mut storage);
        storage.expect_detect_image().returning(|_| {
            Some(DetectedImage {
                content_type: "image/png",
                ext: "png",
            })
        });
        storage
            .expect_upload()
            .returning(|_, _, _, _| Err(AppError::StorageError("upload failed".to_string())));

        let result = make_interactor(db_session, workspace_writer, storage)
            .execute(dto_with_logo)
            .await;

        assert!(matches!(result.unwrap_err(), AppError::CreatedWorkspaceError));
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_workspace_writer_fails(dto_without_logo: CreateWorkspaceDTO) {
        let db_session = MockDBSessionMock::new();
        let mut workspace_writer = MockWorkspaceWriterMock::new();
        let mut storage = MockStorageClientMock::new();

        setup_storage_ok(&mut storage);
        workspace_writer
            .expect_insert()
            .returning(|_| Err(AppError::DatabaseError(sqlx::Error::PoolClosed)));

        let result = make_interactor(db_session, workspace_writer, storage)
            .execute(dto_without_logo)
            .await;

        assert!(matches!(result.unwrap_err(), AppError::DatabaseError(_)));
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_workspace_commit_fails(dto_without_logo: CreateWorkspaceDTO) {
        let mut db_session = MockDBSessionMock::new();
        let mut workspace_writer = MockWorkspaceWriterMock::new();
        let mut storage = MockStorageClientMock::new();

        setup_storage_ok(&mut storage);
        workspace_writer.expect_insert().returning(|w| Ok(w.id));
        db_session
            .expect_commit()
            .returning(|| Err(AppError::SessionAlreadyCommitted));

        let result = make_interactor(db_session, workspace_writer, storage)
            .execute(dto_without_logo)
            .await;

        assert!(matches!(result.unwrap_err(), AppError::SessionAlreadyCommitted));
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_workspace_invalid_owner_id() {
        let db_session = MockDBSessionMock::new();
        let workspace_writer = MockWorkspaceWriterMock::new();
        let storage = MockStorageClientMock::new();

        let dto = CreateWorkspaceDTO {
            owner_user_id: "not-a-uuid".to_string(),
            name: "Test".to_string(),
            description: None,
            logo: None,
            primary_color: "#000000".to_string(),
            visibility: "private".to_string(),
        };

        let result = make_interactor(db_session, workspace_writer, storage)
            .execute(dto)
            .await;

        assert!(matches!(result.unwrap_err(), AppError::InvalidId(_)));
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_workspace_invalid_visibility() {
        let db_session = MockDBSessionMock::new();
        let workspace_writer = MockWorkspaceWriterMock::new();
        let storage = MockStorageClientMock::new();

        let dto = CreateWorkspaceDTO {
            owner_user_id: OWNER_USER_ID.to_string(),
            name: "Test".to_string(),
            description: None,
            logo: None,
            primary_color: "#000000".to_string(),
            visibility: "unknown".to_string(),
        };

        let result = make_interactor(db_session, workspace_writer, storage)
            .execute(dto)
            .await;

        assert!(matches!(result.unwrap_err(), AppError::InvalidVisibility(_)));
    }
}
