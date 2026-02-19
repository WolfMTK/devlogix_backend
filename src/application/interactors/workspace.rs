use std::sync::Arc;

use crate::application::app_error::{AppError, AppResult};
use crate::application::dto::workspace::CreateWorkspaceDTO;
use crate::application::interface::db::DBSession;
use crate::application::interface::gateway::workspace::WorkspaceWriter;
use crate::application::interface::s3::StorageClient;
use crate::domain::entities::id::Id;
use crate::domain::entities::user::User;
use crate::domain::entities::workspace::{Workspace, WorkspaceVisibility};

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
