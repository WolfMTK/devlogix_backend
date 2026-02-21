use std::sync::Arc;

use axum::Json;
use axum::body::Body;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use bytes::Bytes;

use crate::adapter::http::app_error_impl::ErrorResponse;
use crate::adapter::http::middleware::extractor::AuthUser;
use crate::adapter::http::schema::auth::MessageResponse;
use crate::adapter::http::schema::pagination::PaginationQuery;
use crate::adapter::http::schema::user::GetUserResponse;
use crate::adapter::http::schema::workspace::{
    AcceptInviteQuery, CreateWorkspaceRequest, GetWorkspaceResponse, InviteWorkspaceMemberRequest,
    WorkspaceListResponse,
};
use crate::application::app_error::{AppError, AppResult};
use crate::application::dto::workspace::{
    AcceptWorkspaceInviteDTO, CheckWorkspaceOwnerDTO, CreateWorkspaceDTO, DeleteWorkspaceDTO, GetWorkspaceDTO,
    GetWorkspaceListDTO, GetWorkspaceLogoDTO, InviteWorkspaceMemberDTO, UpdateWorkspaceDTO,
};
use crate::application::interactors::workspace::{
    AcceptWorkpspaceInviteIneractor, CheckWorkspaceOwnerInteractor, CreateWorkspaceInteractor,
    DeleteWorkspaceInteractor, GetOwnerWorkspaceInteractor, GetWorkspaceInteractor, GetWorkspaceListInteractor,
    GetWorkspaceLogoInteractor, InviteWorkspaceMemberInteractor, UpdateWorkspaceInteractor,
};
use crate::infra::config::AppConfig;

const DEFAULT_PAGE: i64 = 1;
const DEFAULT_PER_PAGE: i64 = 20;

#[utoipa::path(
    post,
    path = "/workspaces",
    tag = "Workspaces",
    request_body(
        content_type = "multipart/form-data",
        content = CreateWorkspaceRequest,
        description = "Workspace fields + optional logo image"
    ),
    responses(
        (
            status = 200,
            description = "Workspace created",
            body = MessageResponse,
            example = json!({ "message": "Workspace created successfully" })
        ),
        (
            status = 400,
            description = "Validation error or unsupported image format",
            body = ErrorResponse,
            example = json!({ "error": "Unsupported image format" })
        ),
        (
            status = 401,
            description = "Not authenticated",
            body = ErrorResponse,
            example = json!({ "error": "Invalid Credentials" })
        ),
        (
            status = 500,
            description = "Internal server error",
            body = ErrorResponse,
            example = json!({ "error": "Internal Server Error" })
        )
    ),
    security(("cookieAuth" = []))
)]
pub async fn create_workspace(
    auth_user: AuthUser,
    interactor: CreateWorkspaceInteractor,
    mut multipart: Multipart,
) -> AppResult<impl IntoResponse> {
    let mut name: Option<String> = None;
    let mut description: Option<String> = None;
    let mut primary_color: Option<String> = None;
    let mut visibility: Option<String> = None;
    let mut logo: Option<Bytes> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::StorageError(e.to_string()))?
    {
        match field.name() {
            Some("name") => {
                name = Some(field.text().await.map_err(|e| AppError::StorageError(e.to_string()))?);
            }
            Some("description") => {
                let text = field.text().await.map_err(|e| AppError::StorageError(e.to_string()))?;
                if !text.is_empty() {
                    description = Some(text);
                }
            }
            Some("primary_color") => {
                primary_color = Some(field.text().await.map_err(|e| AppError::StorageError(e.to_string()))?);
            }
            Some("visibility") => {
                visibility = Some(field.text().await.map_err(|e| AppError::StorageError(e.to_string()))?);
            }
            Some("logo") => {
                let bytes = field.bytes().await.map_err(|e| AppError::StorageError(e.to_string()))?;
                if !bytes.is_empty() {
                    logo = Some(bytes);
                }
            }
            _ => {}
        }
    }

    let name = name.ok_or_else(|| AppError::StorageError("Field `name` is required".to_string()))?;
    let primary_color =
        primary_color.ok_or_else(|| AppError::StorageError("Field `primary_color` is required".to_string()))?;
    let visibility = visibility.ok_or_else(|| AppError::StorageError("Field `visibility` is required".to_string()))?;

    let dto = CreateWorkspaceDTO {
        owner_user_id: auth_user.user_id,
        name,
        description,
        logo,
        primary_color,
        visibility,
    };
    interactor.execute(dto).await?;
    Ok((
        StatusCode::OK,
        Json(MessageResponse {
            message: "Workspace created successfully".to_string(),
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/workspaces",
    tag = "Workspaces",
    params(PaginationQuery),
    responses(
        (
            status = 200,
            description = "Workspace list",
            body = WorkspaceListResponse
        ),
        (
            status = 401,
            description = "Not authenticated",
            body = ErrorResponse,
            example = json!(
                {
                    "error": "Invalid Credentials"
                }
            )
        ),
        (
            status = 500,
            description = "Internal server error",
            body = ErrorResponse,
            example = json!(
                {
                    "error": "Internal Server Error"
                }
            )
        )
    ),
    security(("cookieAuth" = []))
)]
pub async fn get_workspace_list(
    auth_user: AuthUser,
    interactor: GetWorkspaceListInteractor,
    Query(query): Query<PaginationQuery>,
) -> AppResult<impl IntoResponse> {
    let dto = GetWorkspaceListDTO {
        user_id: auth_user.user_id,
        page: query.page.unwrap_or(DEFAULT_PAGE),
        per_page: query.per_page.unwrap_or(DEFAULT_PER_PAGE),
    };
    let result = interactor.execute(dto).await?;

    Ok((
        StatusCode::OK,
        Json(WorkspaceListResponse {
            items: result
                .items
                .into_iter()
                .map(|w| GetWorkspaceResponse {
                    id: w.id,
                    owner_user_id: w.owner_user_id,
                    name: w.name,
                    description: w.description,
                    slug: w.slug,
                    logo: w.logo,
                    primary_color: w.primary_color,
                    visibility: w.visibility,
                    created_at: w.created_at,
                    updated_at: w.updated_at,
                })
                .collect(),
            total: result.total,
            page: result.page,
            per_page: result.per_page,
        }),
    ))
}

pub async fn get_workspace_logo(
    auth_user: AuthUser,
    interactor: GetWorkspaceLogoInteractor,
    Path((workspace_id, file_name)): Path<(String, String)>,
) -> AppResult<impl IntoResponse> {
    let dto = GetWorkspaceLogoDTO {
        user_id: auth_user.user_id,
        workspace_id: workspace_id,
        file_name: file_name,
    };
    let logo = interactor.execute(dto).await?;

    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(&logo.content_type)
            .map_err(|_| AppError::StorageError("Invalid content type".to_string()))?,
    );

    Ok((StatusCode::OK, headers, Body::from(logo.data)))
}

pub async fn update_workspace(
    auth_user: AuthUser,
    interactor: UpdateWorkspaceInteractor,
    Path(workspace_id): Path<String>,
    mut multipart: Multipart,
) -> AppResult<impl IntoResponse> {
    let mut name: Option<String> = None;
    let mut description: Option<String> = None;
    let mut primary_color: Option<String> = None;
    let mut visibility: Option<String> = None;
    let mut logo: Option<Bytes> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::StorageError(e.to_string()))?
    {
        match field.name() {
            Some("name") => {
                let text = field.text().await.map_err(|e| AppError::StorageError(e.to_string()))?;
                if !text.is_empty() {
                    name = Some(text);
                }
            }
            Some("description") => {
                let text = field.text().await.map_err(|e| AppError::StorageError(e.to_string()))?;
                if !text.is_empty() {
                    description = Some(text);
                }
            }
            Some("primary_color") => {
                let text = field.text().await.map_err(|e| AppError::StorageError(e.to_string()))?;
                if !text.is_empty() {
                    primary_color = Some(text);
                }
            }
            Some("visibility") => {
                let text = field.text().await.map_err(|e| AppError::StorageError(e.to_string()))?;
                if !text.is_empty() {
                    visibility = Some(text);
                }
            }
            Some("logo") => {
                let bytes = field.bytes().await.map_err(|e| AppError::StorageError(e.to_string()))?;
                if !bytes.is_empty() {
                    logo = Some(bytes);
                }
            }
            _ => {}
        }
    }

    let dto = UpdateWorkspaceDTO {
        user_id: auth_user.user_id,
        workspace_id,
        name,
        description,
        primary_color,
        logo,
        visibility,
    };
    interactor.execute(dto).await?;

    Ok((
        StatusCode::OK,
        Json(MessageResponse {
            message: "Workspace updated successfully".to_string(),
        }),
    ))
}

pub async fn delete_workspace(
    auth_user: AuthUser,
    interactor: DeleteWorkspaceInteractor,
    Path(workspace_id): Path<String>,
) -> AppResult<impl IntoResponse> {
    let dto = DeleteWorkspaceDTO {
        user_id: auth_user.user_id,
        workspace_id,
    };
    interactor.execute(dto).await?;

    Ok((
        StatusCode::OK,
        Json(MessageResponse {
            message: "Workspace deleted successfully".to_string(),
        }),
    ))
}

pub async fn check_workspace_owner(
    auth_user: AuthUser,
    interactor: CheckWorkspaceOwnerInteractor,
    Path(workspace_id): Path<String>,
) -> AppResult<impl IntoResponse> {
    let dto = CheckWorkspaceOwnerDTO {
        user_id: auth_user.user_id,
        workspace_id,
    };
    interactor.execute(dto).await?;

    Ok((
        StatusCode::OK,
        Json(MessageResponse {
            message: "Access granted".to_string(),
        }),
    ))
}

pub async fn invite_workspace_member(
    auth_user: AuthUser,
    interactor: InviteWorkspaceMemberInteractor,
    State(config): State<Arc<AppConfig>>,
    Path(workspace_id): Path<String>,
    Json(payload): Json<InviteWorkspaceMemberRequest>,
) -> AppResult<impl IntoResponse> {
    let dto = InviteWorkspaceMemberDTO {
        user_id: auth_user.user_id,
        workspace_id,
        email: payload.email.to_string(),
        ttl: config.workspace_invite.ttl,
        invite_url: config.workspace_invite.invite_url.clone(),
    };
    interactor.execute(dto).await?;

    Ok((
        StatusCode::OK,
        Json(MessageResponse {
            message: "Invite sent successfully".to_string(),
        }),
    ))
}

pub async fn accept_workpsace_invite(
    auth_user: AuthUser,
    interactor: AcceptWorkpspaceInviteIneractor,
    Query(query): Query<AcceptInviteQuery>,
) -> AppResult<impl IntoResponse> {
    let dto = AcceptWorkspaceInviteDTO {
        user_id: auth_user.user_id,
        token: query.token,
    };
    interactor.execute(dto).await?;

    Ok((
        StatusCode::OK,
        Json(MessageResponse {
            message: "Invite accepted successfully".to_string(),
        }),
    ))
}

pub async fn get_workspace(
    auth_user: AuthUser,
    interactor: GetWorkspaceInteractor,
    Path((workspace_id, slug)): Path<(String, String)>,
) -> AppResult<impl IntoResponse> {
    let dto = GetWorkspaceDTO {
        user_id: auth_user.user_id,
        workspace_id,
        slug,
    };
    let workspace = interactor.execute(dto).await?;

    Ok((
        StatusCode::OK,
        Json(GetWorkspaceResponse {
            id: workspace.id,
            owner_user_id: workspace.owner_user_id,
            name: workspace.name,
            description: workspace.description,
            slug: workspace.slug,
            logo: workspace.logo,
            primary_color: workspace.primary_color,
            visibility: workspace.visibility,
            created_at: workspace.created_at,
            updated_at: workspace.updated_at,
        }),
    ))
}

pub async fn get_owner_workspace(
    auth_user: AuthUser,
    intearctor: GetOwnerWorkspaceInteractor,
    Path((workspace_id, slug)): Path<(String, String)>,
) -> AppResult<impl IntoResponse> {
    let dto = GetWorkspaceDTO {
        user_id: auth_user.user_id,
        workspace_id: workspace_id,
        slug: slug,
    };
    let user = intearctor.execute(dto).await?;

    Ok((
        StatusCode::OK,
        Json(GetUserResponse {
            id: user.id,
            username: user.username,
            email: user.email,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use axum::{Extension, Router};
    use bytes::{Bytes, BytesMut};
    use http_body_util::BodyExt;
    use mockall::mock;
    use tower::ServiceExt;

    use crate::adapter::http::middleware::extractor::AuthUser;
    use crate::adapter::http::routes::workspace::create_workspace;
    use crate::adapter::http::schema::auth::MessageResponse;
    use crate::application::app_error::{AppError, AppResult};
    use crate::application::interactors::workspace::CreateWorkspaceInteractor;
    use crate::application::interface::db::DBSession;
    use crate::application::interface::gateway::workspace::WorkspaceWriter;
    use crate::application::interface::s3::{DetectedImage, DownloadedFile, StorageClient};
    use crate::domain::entities::id::Id;
    use crate::domain::entities::workspace::Workspace;

    const OWNER_USER_ID: &str = "019c47ec-183d-744e-b11d-cd409015bf13";
    const BOUNDARY: &str = "TestBoundary1234";

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

    fn build_multipart_body(fields: &[(&str, &str)], file: Option<Bytes>) -> Bytes {
        let mut body = BytesMut::new();
        for (name, value) in fields {
            body.extend_from_slice(format!("--{}\r\n", BOUNDARY).as_bytes());
            body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{}\"\r\n\r\n", name).as_bytes());
            body.extend_from_slice(format!("{}\r\n", value).as_bytes());
        }
        if let Some(data) = file {
            body.extend_from_slice(format!("--{}\r\n", BOUNDARY).as_bytes());
            body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"logo\"; filename=\"logo.png\"\r\nContent-Type: image/png\r\n\r\n"
                )
                    .as_bytes(),
            );
            body.extend_from_slice(&data);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{}--\r\n", BOUNDARY).as_bytes());
        body.freeze()
    }

    fn make_interactor(
        db: MockDBSessionMock,
        workspace_writer: MockWorkspaceWriterMock,
        storage: MockStorageClientMock,
    ) -> CreateWorkspaceInteractor {
        CreateWorkspaceInteractor::new(Arc::new(db), Arc::new(workspace_writer), Arc::new(storage))
    }

    fn build_router(interactor: CreateWorkspaceInteractor) -> Router {
        let interactor = Arc::new(interactor);
        Router::new()
            .route(
                "/workspaces",
                post(move |auth: AuthUser, mp: axum::extract::Multipart| {
                    let i = Arc::clone(&interactor);
                    async move { create_workspace(auth, (*i).clone(), mp).await }
                }),
            )
            .layer(Extension(AuthUser {
                user_id: OWNER_USER_ID.to_string(),
            }))
    }

    async fn send(router: Router, body: Bytes) -> axum::response::Response {
        let req = Request::builder()
            .method("POST")
            .uri("/workspaces")
            .header("content-type", format!("multipart/form-data; boundary={}", BOUNDARY))
            .body(Body::from(body))
            .unwrap();
        router.oneshot(req).await.unwrap()
    }

    fn setup_storage_ok(storage: &mut MockStorageClientMock) {
        storage.expect_ensure_bucket().returning(|_| Ok(()));
    }

    fn setup_happy_path(
        db: &mut MockDBSessionMock,
        workspace_writer: &mut MockWorkspaceWriterMock,
        storage: &mut MockStorageClientMock,
    ) {
        setup_storage_ok(storage);
        workspace_writer.expect_insert().returning(|w| Ok(w.id));
        db.expect_commit().returning(|| Ok(()));
    }

    #[tokio::test]
    async fn test_create_workspace_success_without_logo() {
        let mut db = MockDBSessionMock::new();
        let mut workspace_writer = MockWorkspaceWriterMock::new();
        let mut storage = MockStorageClientMock::new();
        setup_happy_path(&mut db, &mut workspace_writer, &mut storage);

        let body = build_multipart_body(
            &[
                ("name", "My Workspace"),
                ("primary_color", "#FF5733"),
                ("visibility", "private"),
            ],
            None,
        );
        let resp = send(build_router(make_interactor(db, workspace_writer, storage)), body).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_workspace_success_with_description() {
        let mut db = MockDBSessionMock::new();
        let mut workspace_writer = MockWorkspaceWriterMock::new();
        let mut storage = MockStorageClientMock::new();
        setup_happy_path(&mut db, &mut workspace_writer, &mut storage);

        let body = build_multipart_body(
            &[
                ("name", "My Workspace"),
                ("primary_color", "#FF5733"),
                ("visibility", "private"),
                ("description", "A cool workspace"),
            ],
            None,
        );
        let resp = send(build_router(make_interactor(db, workspace_writer, storage)), body).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_workspace_success_with_logo() {
        let mut db = MockDBSessionMock::new();
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
        db.expect_commit().returning(|| Ok(()));

        let logo = Bytes::from_static(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        let body = build_multipart_body(
            &[
                ("name", "My Workspace"),
                ("primary_color", "#FF5733"),
                ("visibility", "private"),
            ],
            Some(logo),
        );
        let resp = send(build_router(make_interactor(db, workspace_writer, storage)), body).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_workspace_empty_description_treated_as_none() {
        let mut db = MockDBSessionMock::new();
        let mut workspace_writer = MockWorkspaceWriterMock::new();
        let mut storage = MockStorageClientMock::new();
        setup_storage_ok(&mut storage);
        workspace_writer
            .expect_insert()
            .withf(|w| w.description.is_none())
            .returning(|w| Ok(w.id));
        db.expect_commit().returning(|| Ok(()));

        let body = build_multipart_body(
            &[
                ("name", "My Workspace"),
                ("primary_color", "#FF5733"),
                ("visibility", "private"),
                ("description", ""),
            ],
            None,
        );
        let resp = send(build_router(make_interactor(db, workspace_writer, storage)), body).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_workspace_empty_logo_treated_as_none() {
        let mut db = MockDBSessionMock::new();
        let mut workspace_writer = MockWorkspaceWriterMock::new();
        let mut storage = MockStorageClientMock::new();
        setup_storage_ok(&mut storage);
        workspace_writer
            .expect_insert()
            .withf(|w| w.logo.is_none())
            .returning(|w| Ok(w.id));
        db.expect_commit().returning(|| Ok(()));

        let body = build_multipart_body(
            &[
                ("name", "My Workspace"),
                ("primary_color", "#FF5733"),
                ("visibility", "private"),
            ],
            Some(Bytes::new()),
        );
        let resp = send(build_router(make_interactor(db, workspace_writer, storage)), body).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_workspace_missing_name_returns_error() {
        let db = MockDBSessionMock::new();
        let workspace_writer = MockWorkspaceWriterMock::new();
        let storage = MockStorageClientMock::new();

        let body = build_multipart_body(&[("primary_color", "#FF5733"), ("visibility", "private")], None);
        let resp = send(build_router(make_interactor(db, workspace_writer, storage)), body).await;
        assert_ne!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_workspace_missing_primary_color_returns_error() {
        let db = MockDBSessionMock::new();
        let workspace_writer = MockWorkspaceWriterMock::new();
        let storage = MockStorageClientMock::new();

        let body = build_multipart_body(&[("name", "Test"), ("visibility", "private")], None);
        let resp = send(build_router(make_interactor(db, workspace_writer, storage)), body).await;
        assert_ne!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_workspace_missing_visibility_returns_error() {
        let db = MockDBSessionMock::new();
        let workspace_writer = MockWorkspaceWriterMock::new();
        let storage = MockStorageClientMock::new();

        let body = build_multipart_body(&[("name", "Test"), ("primary_color", "#000000")], None);
        let resp = send(build_router(make_interactor(db, workspace_writer, storage)), body).await;
        assert_ne!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_workspace_unknown_fields_ignored() {
        let mut db = MockDBSessionMock::new();
        let mut workspace_writer = MockWorkspaceWriterMock::new();
        let mut storage = MockStorageClientMock::new();
        setup_happy_path(&mut db, &mut workspace_writer, &mut storage);

        let body = build_multipart_body(
            &[
                ("name", "My Workspace"),
                ("primary_color", "#FF5733"),
                ("visibility", "private"),
                ("unknown_field", "some_value"),
            ],
            None,
        );
        let resp = send(build_router(make_interactor(db, workspace_writer, storage)), body).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_workspace_response_body_contains_message() {
        let mut db = MockDBSessionMock::new();
        let mut workspace_writer = MockWorkspaceWriterMock::new();
        let mut storage = MockStorageClientMock::new();
        setup_happy_path(&mut db, &mut workspace_writer, &mut storage);

        let body = build_multipart_body(
            &[
                ("name", "My Workspace"),
                ("primary_color", "#FF5733"),
                ("visibility", "private"),
            ],
            None,
        );
        let resp = send(build_router(make_interactor(db, workspace_writer, storage)), body).await;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let msg: MessageResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(msg.message, "Workspace created successfully");
    }

    #[tokio::test]
    async fn test_create_workspace_bucket_error_returns_error() {
        let db = MockDBSessionMock::new();
        let workspace_writer = MockWorkspaceWriterMock::new();
        let mut storage = MockStorageClientMock::new();
        storage
            .expect_ensure_bucket()
            .returning(|_| Err(AppError::StorageError("connection refused".to_string())));

        let body = build_multipart_body(
            &[
                ("name", "My Workspace"),
                ("primary_color", "#FF5733"),
                ("visibility", "private"),
            ],
            None,
        );
        let resp = send(build_router(make_interactor(db, workspace_writer, storage)), body).await;
        assert_ne!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_workspace_db_error_returns_error() {
        let db = MockDBSessionMock::new();
        let mut workspace_writer = MockWorkspaceWriterMock::new();
        let mut storage = MockStorageClientMock::new();
        setup_storage_ok(&mut storage);
        workspace_writer
            .expect_insert()
            .returning(|_| Err(AppError::DatabaseError(sqlx::Error::PoolClosed)));

        let body = build_multipart_body(
            &[
                ("name", "My Workspace"),
                ("primary_color", "#FF5733"),
                ("visibility", "private"),
            ],
            None,
        );
        let resp = send(build_router(make_interactor(db, workspace_writer, storage)), body).await;
        assert_ne!(resp.status(), StatusCode::OK);
    }
}
