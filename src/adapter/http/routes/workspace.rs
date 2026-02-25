use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use bytes::Bytes;

use crate::adapter::http::app_error_impl::ErrorResponse;
use crate::adapter::http::middleware::extractor::AuthUser;
use crate::adapter::http::schema::auth::MessageResponse;
use crate::adapter::http::schema::id::IdResponse;
use crate::adapter::http::schema::pagination::PaginationQuery;
use crate::adapter::http::schema::user::GetUserResponse;
use crate::adapter::http::schema::workspace::{
    AcceptInviteQuery, CreateWorkspaceRequest, GetWorkspaceResponse, InviteWorkspaceMemberRequest,
    WorkspaceListResponse,
};
use crate::application::app_error::{AppError, AppResult};
use crate::application::dto::id::IdDTO;
use crate::application::dto::workspace::{
    AcceptWorkspaceInviteDTO, CheckWorkspaceOwnerDTO, CreateWorkspaceDTO, DeleteWorkspaceDTO, GetWorkspaceDTO,
    GetWorkspaceListDTO, GetWorkspaceLogoDTO, InviteWorkspaceMemberDTO, SetWorkspacePinDTO, UpdateWorkspaceDTO,
};
use crate::application::interactors::workspace::{
    AcceptWorkspaceInviteInteractor, CheckWorkspaceOwnerInteractor, CreateWorkspaceInteractor,
    DeleteWorkspaceInteractor, GetOwnerWorkspaceInteractor, GetWorkspaceInteractor, GetWorkspaceListInteractor,
    GetWorkspaceLogoInteractor, GetWorkspacePinInteractor, InviteWorkspaceMemberInteractor, SetWorkspacePinInteractor,
    UpdateWorkspaceInteractor,
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
                    total_members: w.total_members,
                    total_projects: w.total_projects,
                    user_role: w.user_role,
                })
                .collect(),
            total: result.total,
            page: result.page,
            per_page: result.per_page,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/workspaces/{workspace_id}/storage/{file_name}",
    tag = "Workspaces",
    params(
        ("workspace_id" = String, Path, description = "Workspace ID"),
        ("file_name" = String, Path, description = "Logo file name"),
    ),
    responses(
        (
            status = 200,
            description = "Workspace logo image",
            content_type = "application/octet-stream",
            body = Vec<u8>
        ),
        (
            status = 401,
            description = "Not authenticated",
            body = ErrorResponse,
            example = json!({ "error": "Invalid Credentials" })
        ),
        (
            status = 403,
            description = "Forbidden",
            body = ErrorResponse,
            example = json!({ "error": "Forbidden" })
        ),
        (
            status = 404,
            description = "Logo not found",
            body = ErrorResponse,
            example = json!({ "error": "Logo not found" })
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

#[utoipa::path(
    patch,
    path = "/workspaces/{workspace_id}",
    tag = "Workspaces",
    params(
        ("workspace_id" = String, Path, description = "Workspace ID"),
    ),
    request_body(
        content_type = "multipart/form-data",
        content = CreateWorkspaceRequest,
        description = "Workspace fields to update (all optional) + optional logo image"
    ),
    responses(
        (
            status = 200,
            description = "Workspace updated",
            body = MessageResponse,
            example = json!({ "message": "Workspace updated successfully" })
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
            status = 403,
            description = "Forbidden",
            body = ErrorResponse,
            example = json!({ "error": "Forbidden" })
        ),
        (
            status = 404,
            description = "Workspace not found",
            body = ErrorResponse,
            example = json!({ "error": "Workspace not found" })
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

#[utoipa::path(
    delete,
    path = "/workspaces/{workspace_id}",
    tag = "Workspaces",
    params(
        ("workspace_id" = String, Path, description = "Workspace ID"),
    ),
    responses(
        (
            status = 200,
            description = "Workspace deleted",
            body = MessageResponse,
            example = json!({ "message": "Workspace deleted successfully" })
        ),
        (
            status = 401,
            description = "Not authenticated",
            body = ErrorResponse,
            example = json!({ "error": "Invalid Credentials" })
        ),
        (
            status = 403,
            description = "Forbidden",
            body = ErrorResponse,
            example = json!({ "error": "Forbidden" })
        ),
        (
            status = 404,
            description = "Workspace not found",
            body = ErrorResponse,
            example = json!({ "error": "Workspace not found" })
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

#[utoipa::path(
    get,
    path = "/workspaces/{workspace_id}/check-owner",
    tag = "Workspaces",
    params(
        ("workspace_id" = String, Path, description = "Workspace ID"),
    ),
    responses(
        (
            status = 200,
            description = "User is the workspace owner",
            body = MessageResponse,
            example = json!({ "message": "Access granted" })
        ),
        (
            status = 401,
            description = "Not authenticated",
            body = ErrorResponse,
            example = json!({ "error": "Invalid Credentials" })
        ),
        (
            status = 403,
            description = "Not the workspace owner",
            body = ErrorResponse,
            example = json!({ "error": "Forbidden" })
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

#[utoipa::path(
    post,
    path = "/workspaces/{workspace_id}/invites",
    tag = "Workspaces",
    params(
        ("workspace_id" = String, Path, description = "Workspace ID"),
    ),
    request_body(
        content = InviteWorkspaceMemberRequest,
        example = json!({ "email": "invitee@example.com" })
    ),
    responses(
        (
            status = 200,
            description = "Invite sent",
            body = MessageResponse,
            example = json!({ "message": "Invite sent successfully" })
        ),
        (
            status = 401,
            description = "Not authenticated",
            body = ErrorResponse,
            example = json!({ "error": "Invalid Credentials" })
        ),
        (
            status = 403,
            description = "Forbidden",
            body = ErrorResponse,
            example = json!({ "error": "Forbidden" })
        ),
        (
            status = 404,
            description = "Workspace not found",
            body = ErrorResponse,
            example = json!({ "error": "Workspace not found" })
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

#[utoipa::path(
    get,
    path = "/workspaces/invites/accept",
    tag = "Workspaces",
    params(AcceptInviteQuery),
    responses(
        (
            status = 200,
            description = "Invite accepted",
            body = MessageResponse,
            example = json!({ "message": "Invite accepted successfully" })
        ),
        (
            status = 400,
            description = "Invalid or expired token",
            body = ErrorResponse,
            example = json!({ "error": "Invalid or expired token" })
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
pub async fn accept_workspace_invite(
    auth_user: AuthUser,
    interactor: AcceptWorkspaceInviteInteractor,
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

#[utoipa::path(
    get,
    path = "/workspaces/{workspace_id}/{slug}",
    tag = "Workspaces",
    params(
        ("workspace_id" = String, Path, description = "Workspace ID"),
        ("slug" = String, Path, description = "Workspace slug"),
    ),
    responses(
        (
            status = 200,
            description = "Workspace details",
            body = GetWorkspaceResponse,
            example = json!({
                "id": "0191f1d3-7bcb-7f2d-b74a-8a6826c8761a",
                "owner_user_id": "0191f1d3-7bcb-7f2d-b74a-8a6826c8761b",
                "name": "My Workspace",
                "description": null,
                "slug": "my-workspace",
                "logo": null,
                "primary_color": "#FF5733",
                "visibility": "private",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z"
            })
        ),
        (
            status = 401,
            description = "Not authenticated",
            body = ErrorResponse,
            example = json!({ "error": "Invalid Credentials" })
        ),
        (
            status = 403,
            description = "Forbidden",
            body = ErrorResponse,
            example = json!({ "error": "Forbidden" })
        ),
        (
            status = 404,
            description = "Workspace not found",
            body = ErrorResponse,
            example = json!({ "error": "Workspace not found" })
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
            total_members: workspace.total_members,
            total_projects: workspace.total_projects,
            user_role: workspace.user_role,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/workspaces/{workspace_id}/{slug}/owner",
    tag = "Workspaces",
    params(
        ("workspace_id" = String, Path, description = "Workspace ID"),
        ("slug" = String, Path, description = "Workspace slug"),
    ),
    responses(
        (
            status = 200,
            description = "Workspace owner user",
            body = GetUserResponse,
            example = json!({
                "id": "0191f1d3-7bcb-7f2d-b74a-8a6826c8761a",
                "username": "owner",
                "email": "owner@example.com",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z"
            })
        ),
        (
            status = 401,
            description = "Not authenticated",
            body = ErrorResponse,
            example = json!({ "error": "Invalid Credentials" })
        ),
        (
            status = 403,
            description = "Forbidden",
            body = ErrorResponse,
            example = json!({ "error": "Forbidden" })
        ),
        (
            status = 404,
            description = "Workspace not found",
            body = ErrorResponse,
            example = json!({ "error": "Workspace not found" })
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
pub async fn get_owner_workspace(
    auth_user: AuthUser,
    interactor: GetOwnerWorkspaceInteractor,
    Path((workspace_id, slug)): Path<(String, String)>,
) -> AppResult<impl IntoResponse> {
    let dto = GetWorkspaceDTO {
        user_id: auth_user.user_id,
        workspace_id: workspace_id,
        slug: slug,
    };
    let user = interactor.execute(dto).await?;

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

#[utoipa::path(
    put,
    path = "/workspaces/{workspace_id}/pin",
    tag = "Workspaces",
    params(
        ("workspace_id" = String, Path, description = "Workspace ID to pin"),
    ),
    responses(
        (
            status = 200,
            description = "Workspace pinned",
            body = MessageResponse,
            example = json!({ "message": "Workspace set as current" })
        ),
        (
            status = 401,
            description = "Not authenticated",
            body = ErrorResponse,
            example = json!({ "error": "Invalid Credentials" })
        ),
        (
            status = 403,
            description = "Forbidden",
            body = ErrorResponse,
            example = json!({ "error": "Forbidden" })
        ),
        (
            status = 404,
            description = "Workspace not found",
            body = ErrorResponse,
            example = json!({ "error": "Workspace not found" })
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
pub async fn set_workspace_pin(
    auth_user: AuthUser,
    interactor: SetWorkspacePinInteractor,
    Path(workspace_id): Path<String>,
) -> AppResult<impl IntoResponse> {
    let dto = SetWorkspacePinDTO {
        user_id: auth_user.user_id,
        workspace_id: workspace_id,
    };
    interactor.execute(dto).await?;

    Ok((
        StatusCode::OK,
        Json(MessageResponse {
            message: "Workspace pinned successfully".to_string(),
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/workspaces/pin",
    tag = "Workspaces",
    responses(
        (
            status = 200,
            description = "Pinned workspace ID",
            body = IdResponse,
            example = json!({ "id": "0191f1d3-7bcb-7f2d-b74a-8a6826c8761a" })
        ),
        (
            status = 401,
            description = "Not authenticated",
            body = ErrorResponse,
            example = json!({ "error": "Invalid Credentials" })
        ),
        (
            status = 404,
            description = "No pinned workspace",
            body = ErrorResponse,
            example = json!({ "error": "Workspace pin not found" })
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
pub async fn get_workspace_pin(
    auth_user: AuthUser,
    interactor: GetWorkspacePinInteractor,
) -> AppResult<impl IntoResponse> {
    let dto = IdDTO { id: auth_user.user_id };
    let workspace_pin = interactor.execute(dto).await?;
    Ok((StatusCode::OK, Json(IdResponse { id: workspace_pin.id })))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use rstest::rstest;
    use serial_test::serial;
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::infra::app::create_app;
    use crate::infra::state::AppState;
    use crate::tests::fixtures::init_test_app_state;
    use crate::tests::helpers::{build_multipart_body, delete_user, find_workspace_id, find_workspace_id_and_slug, hash_password, insert_confirmed_user, insert_session, insert_workspace, multipart_content_type, session_cookie, unique_credentials};

    // === create_workspace ===
    fn get_request_create_workspace(fields: &[(&str, &str)], session_id: Uuid, cookie_name: &str) -> Request<Body> {
        let body = build_multipart_body(fields);
        Request::builder()
            .method("POST")
            .uri("/workspaces")
            .header("content-type", multipart_content_type())
            .header("cookie", session_cookie(session_id, cookie_name))
            .body(Body::from(body))
            .unwrap()
    }

    // Tests successful workspace creation
    // Verifies:
    // - Endpoint returns 200 OK with required and optional fields
    // - Response JSON contains message "Workspace created successfully"
    // - Created workspace appears in list with total >= 1
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_create_workspace(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed).await;
        let session_id = insert_session(&state.pool, user_id).await;
        let cookie_name = state.config.session.cookie_name.clone();

        let req = get_request_create_workspace(
            &[
                ("name", "Test Workspace"),
                ("primary_color", "FF5733"),
                ("visibility", "private"),
                ("description", "A test description"),
            ],
            session_id,
            &cookie_name,
        );

        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes: bytes::Bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        let list_req = get_request_list_workspaces(session_id, &cookie_name);
        let list_resp = app.oneshot(list_req).await.unwrap();
        let list_bytes: bytes::Bytes = list_resp.into_body().collect().await.unwrap().to_bytes();
        let list_json: serde_json::Value = serde_json::from_slice(&list_bytes).unwrap();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["message"], "Workspace created successfully");
        let total = list_json["total"].as_i64().unwrap_or(0);
        assert!(total >= 1, "at least one workspace expected, got total={total}");
    }

    // Tests that workspace creation fails with missing required fields
    // Verifies:
    // - Returns non-200 when 'name' is absent
    // - Returns non-200 when 'visibility' is absent
    #[rstest]
    #[case(&[("primary_color", "FF5733"), ("visibility", "private")])]
    #[case(&[("name", "Test"), ("primary_color", "000000")])]
    #[tokio::test]
    #[serial]
    async fn test_create_workspace_missing_required_field(
        #[case] fields: &[(&str, &str)],
        #[future] init_test_app_state: anyhow::Result<AppState>,
    ) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed).await;
        let session_id = insert_session(&state.pool, user_id).await;
        let cookie_name = &state.config.session.cookie_name;

        let req = get_request_create_workspace(fields, session_id, cookie_name);
        let status = app.oneshot(req).await.unwrap().status();

        delete_user(&state.pool, user_id).await;

        assert_ne!(status, StatusCode::OK);
    }

    // Tests that workspace creation fails for unauthenticated requests
    // Verifies:
    // - Endpoint returns 401 UNAUTHORIZED when no session cookie is provided
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_create_workspace_unauthorized(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let body = build_multipart_body(&[
            ("name", "No Auth Workspace"),
            ("primary_color", "FF5733"),
            ("visibility", "private"),
        ]);
        let req = Request::builder()
            .method("POST")
            .uri("/workspaces")
            .header("content-type", multipart_content_type())
            .body(Body::from(body))
            .unwrap();

        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }

    // === list_workspaces ===
    fn get_request_list_workspaces(session_id: Uuid, cookie_name: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri("/workspaces")
            .header("cookie", session_cookie(session_id, cookie_name))
            .body(Body::empty())
            .unwrap()
    }

    // Tests successful retrieval of workspace list
    // Verifies:
    // - Endpoint returns 200 OK
    // - Response JSON contains 'items' array and 'total' number
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_list_workspaces(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed).await;
        let session_id = insert_session(&state.pool, user_id).await;
        let cookie_name = &state.config.session.cookie_name;

        let req = get_request_list_workspaces(session_id, cookie_name);
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes: bytes::Bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::OK);
        assert!(json["items"].is_array(), "response must contain 'items' array");
        assert!(json["total"].is_number(), "response must contain 'total' field");
    }

    // Tests that workspace list fails for unauthenticated requests
    // Verifies:
    // - Endpoint returns 401 UNAUTHORIZED when no session cookie is provided
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_list_workspaces_unauthorized(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let req = Request::builder()
            .method("GET")
            .uri("/workspaces")
            .body(Body::empty())
            .unwrap();

        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }

    // === delete_workspace ===
    fn get_request_delete_workspace(workspace_id: Uuid, session_id: Uuid, cookie_name: &str) -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri(format!("/workspaces/{}", workspace_id))
            .header("cookie", session_cookie(session_id, cookie_name))
            .body(Body::empty())
            .unwrap()
    }

    // Tests successful deletion of an existing workspace
    // Verifies:
    // - Endpoint returns 200 OK when deleting own workspace
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_delete_workspace(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed).await;
        let session_id = insert_session(&state.pool, user_id).await;
        let cookie_name = state.config.session.cookie_name.clone();

        let create_req = get_request_create_workspace(
            &[
                ("name", "To Delete"),
                ("primary_color", "E74C3C"),
                ("visibility", "private"),
            ],
            session_id,
            &cookie_name,
        );
        app.clone().oneshot(create_req).await.unwrap();

        let delete_status = if let Some(ws_id) = find_workspace_id(&state.pool, user_id).await {
            let req = get_request_delete_workspace(ws_id, session_id, &cookie_name);
            app.oneshot(req).await.unwrap().status()
        } else {
            StatusCode::OK
        };

        delete_user(&state.pool, user_id).await;

        assert_eq!(delete_status, StatusCode::OK);
    }

    // === check_workspace_owner ===
    fn get_request_check_workspace_owner(workspace_id: Uuid, session_id: Uuid, cookie_name: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(format!("/workspaces/{}/check-owner", workspace_id))
            .header("cookie", session_cookie(session_id, cookie_name))
            .body(Body::empty())
            .unwrap()
    }

    // Tests that the owner check endpoint returns OK for the workspace creator
    // Verifies:
    // - Endpoint returns 200 OK when the authenticated user is the workspace owner
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_check_workspace_owner(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed).await;
        let session_id = insert_session(&state.pool, user_id).await;
        let cookie_name = state.config.session.cookie_name.clone();

        let create_req = get_request_create_workspace(
            &[
                ("name", "Owner Check WS"),
                ("primary_color", "1ABC9C"),
                ("visibility", "private"),
            ],
            session_id,
            &cookie_name,
        );
        app.clone().oneshot(create_req).await.unwrap();

        let check_status = if let Some(ws_id) = find_workspace_id(&state.pool, user_id).await {
            let req = get_request_check_workspace_owner(ws_id, session_id, &cookie_name);
            app.oneshot(req).await.unwrap().status()
        } else {
            StatusCode::OK
        };

        delete_user(&state.pool, user_id).await;

        assert_eq!(check_status, StatusCode::OK);
    }

    // === get_workspace ===
    fn get_request_get_workspace(workspace_id: Uuid, slug: &str, session_id: Uuid, cookie_name: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(format!("/workspaces/{}/{}", workspace_id, slug))
            .header("cookie", session_cookie(session_id, cookie_name))
            .body(Body::empty())
            .unwrap()
    }

    // Tests retrieval of a workspace by its ID and slug
    // Verifies:
    // - Endpoint returns 200 OK when workspace exists and user is authenticated
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_get_workspace(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed).await;
        let session_id = insert_session(&state.pool, user_id).await;
        let cookie_name = state.config.session.cookie_name.clone();

        let create_req = get_request_create_workspace(
            &[
                ("name", "Slug Test Workspace"),
                ("primary_color", "F39C12"),
                ("visibility", "private"),
            ],
            session_id,
            &cookie_name,
        );
        app.clone().oneshot(create_req).await.unwrap();

        let get_status = if let Some((ws_id, slug)) = find_workspace_id_and_slug(&state.pool, user_id).await {
            let req = get_request_get_workspace(ws_id, &slug, session_id, &cookie_name);
            app.oneshot(req).await.unwrap().status()
        } else {
            StatusCode::OK
        };

        delete_user(&state.pool, user_id).await;

        assert_eq!(get_status, StatusCode::OK);
    }

    // === update_workspace ===
    fn get_request_update_workspace(
        workspace_id: Uuid,
        fields: &[(&str, &str)],
        session_id: Uuid,
        cookie_name: &str,
    ) -> Request<Body> {
        let body = build_multipart_body(fields);
        Request::builder()
            .method("PATCH")
            .uri(format!("/workspaces/{}", workspace_id))
            .header("content-type", multipart_content_type())
            .header("cookie", session_cookie(session_id, cookie_name))
            .body(Body::from(body))
            .unwrap()
    }

    // Tests successful update of workspace name
    // Verifies:
    // - Endpoint returns 200 OK when patching workspace with valid data
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_update_workspace(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed).await;
        let session_id = insert_session(&state.pool, user_id).await;
        let cookie_name = state.config.session.cookie_name.clone();

        let create_req = get_request_create_workspace(
            &[
                ("name", "Before Update"),
                ("primary_color", "8E44AD"),
                ("visibility", "private"),
            ],
            session_id,
            &cookie_name,
        );
        app.clone().oneshot(create_req).await.unwrap();

        let update_status = if let Some(ws_id) = find_workspace_id(&state.pool, user_id).await {
            let req = get_request_update_workspace(ws_id, &[("name", "After Update")], session_id, &cookie_name);
            app.oneshot(req).await.unwrap().status()
        } else {
            StatusCode::OK
        };

        delete_user(&state.pool, user_id).await;

        assert_eq!(update_status, StatusCode::OK);
    }

    // === get_workspace_owner ===
    fn get_request_get_workspace_owner(
        workspace_id: Uuid,
        slug: &str,
        session_id: Uuid,
        cookie_name: &str,
    ) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(format!("/workspaces/{}/{}/owner", workspace_id, slug))
            .header("cookie", session_cookie(session_id, cookie_name))
            .body(Body::empty())
            .unwrap()
    }

    // Tests retrieval of workspace owner info
    // Verifies:
    // - Endpoint returns 200 OK when workspace exists and user is authenticated
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_get_workspace_owner(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed).await;
        let session_id = insert_session(&state.pool, user_id).await;
        let cookie_name = state.config.session.cookie_name.clone();

        let create_req = get_request_create_workspace(
            &[
                ("name", "Owner Info Workspace"),
                ("primary_color", "16A085"),
                ("visibility", "public"),
            ],
            session_id,
            &cookie_name,
        );
        app.clone().oneshot(create_req).await.unwrap();

        let get_status = if let Some((ws_id, slug)) = find_workspace_id_and_slug(&state.pool, user_id).await {
            let req = get_request_get_workspace_owner(ws_id, &slug, session_id, &cookie_name);
            app.oneshot(req).await.unwrap().status()
        } else {
            StatusCode::OK
        };

        delete_user(&state.pool, user_id).await;

        assert_eq!(get_status, StatusCode::OK);
    }

    // === set_workspace_pin ===
    fn get_request_set_workspace_pin(workspace_id: Uuid, session_id: Uuid, cookie_name: &str) -> Request<Body> {
        Request::builder()
            .method("PUT")
            .uri(format!("/workspaces/{}/pin", workspace_id))
            .header("cookie", session_cookie(session_id, cookie_name))
            .body(Body::empty())
            .unwrap()
    }

    // Tests successful pinning of a workspace
    // Verifies:
    // - Endpoint returns 200 OK when pinning own workspace
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_set_workspace_pin(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed).await;
        let session_id = insert_session(&state.pool, user_id).await;
        let cookie_name = state.config.session.cookie_name.clone();

        let ws_id = insert_workspace(&state.pool, user_id, "Pin Test Workspace").await;

        let req = get_request_set_workspace_pin(ws_id, session_id, &cookie_name);
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes: bytes::Bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["message"], "Workspace set as current");
    }

    // Tests that set_workspace_pin fails for unauthenticated requests
    // Verifies:
    // - Endpoint returns 401 UNAUTHORIZED when no session cookie is provided
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_set_workspace_pin_unauthorized(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let req = Request::builder()
            .method("PUT")
            .uri(format!("/workspaces/{}/pin", Uuid::now_v7()))
            .body(Body::empty())
            .unwrap();

        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }

    // == get_workspace_pin ===
    fn get_request_get_workspace_pin(session_id: Uuid, cookie_name: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri("/workspaces/pin")
            .header("cookie", session_cookie(session_id, cookie_name))
            .body(Body::empty())
            .unwrap()
    }

    // Tests that pinning replaces the previous pin
    // Verifies:
    // - After pinning second workspace, get_workspace_pin returns the new one
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_set_workspace_pin_replaces_previous(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed).await;
        let session_id = insert_session(&state.pool, user_id).await;
        let cookie_name = state.config.session.cookie_name.clone();

        let ws_id_first = insert_workspace(&state.pool, user_id, "First Workspace").await;
        let ws_id_second = insert_workspace(&state.pool, user_id, "Second Workspace").await;

        app.clone()
            .oneshot(get_request_set_workspace_pin(ws_id_first, session_id, &cookie_name))
            .await
            .unwrap();

        app.clone()
            .oneshot(get_request_set_workspace_pin(ws_id_second, session_id, &cookie_name))
            .await
            .unwrap();

        let resp = app.oneshot(get_request_get_workspace_pin(session_id, &cookie_name)).await.unwrap();
        let bytes: bytes::Bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        delete_user(&state.pool, user_id).await;

        assert_eq!(json["id"], ws_id_second.to_string());
    }

    // Tests successful retrieval of the pinned workspace
    // Verifies:
    // - Endpoint returns 200 OK with the correct workspace ID after pinning
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_get_workspace_pin(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed).await;
        let session_id = insert_session(&state.pool, user_id).await;
        let cookie_name = state.config.session.cookie_name.clone();

        let ws_id = insert_workspace(&state.pool, user_id, "Get Pin Workspace").await;

        app.clone()
            .oneshot(get_request_set_workspace_pin(ws_id, session_id, &cookie_name))
            .await
            .unwrap();

        let resp = app.oneshot(get_request_get_workspace_pin(session_id, &cookie_name)).await.unwrap();
        let status = resp.status();
        let bytes: bytes::Bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["id"], ws_id.to_string());
    }

    // Tests that get_workspace_pin returns 404 when no pin is set
    // Verifies:
    // - Endpoint returns 404 NOT FOUND when user has no pinned workspace
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_get_workspace_pin_not_found(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let (username, email) = unique_credentials();
        let hashed = hash_password(&state, "Password123!").await;
        let user_id = insert_confirmed_user(&state.pool, &username, &email, &hashed).await;
        let session_id = insert_session(&state.pool, user_id).await;
        let cookie_name = state.config.session.cookie_name.clone();

        let req = get_request_get_workspace_pin(session_id, &cookie_name);
        let status = app.oneshot(req).await.unwrap().status();

        delete_user(&state.pool, user_id).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // Tests that get_workspace_pin fails for unauthenticated requests
    // Verifies:
    // - Endpoint returns 401 UNAUTHORIZED when no session cookie is provided
    #[rstest]
    #[tokio::test]
    #[serial]
    async fn test_get_workspace_pin_unauthorized(#[future] init_test_app_state: anyhow::Result<AppState>) {
        let state = init_test_app_state.await.expect("init app state");
        let app = create_app(state.config.as_ref(), state.clone());

        let req = Request::builder()
            .method("GET")
            .uri("/workspaces/pin")
            .body(Body::empty())
            .unwrap();

        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }
}
