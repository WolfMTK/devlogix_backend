use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use sqlx::{Pool, Postgres};

use crate::adapter::db::gateway::email_confirmation::EmailConfirmationGateway;
use crate::adapter::db::gateway::password_reset::PasswordResetTokenGateway;
use crate::adapter::db::gateway::session::SessionGateway;
use crate::adapter::db::gateway::user::UserGateway;
use crate::adapter::db::gateway::workspace::{WorkspaceGateway, WorkspaceInviteGateway, WorkspaceMemberGateway};
use crate::adapter::db::session::SqlxSession;
use crate::application::app_error::{AppError, AppResult};
use crate::application::interactors::auth::{LoginInteractor, LogoutInteractor};
use crate::application::interactors::email_confirmation::{ConfirmEmailInteractor, ResendConfirmationInteractor};
use crate::application::interactors::password_reset::{RequestPasswordResetInteractor, ResetPasswordInteractor};
use crate::application::interactors::session::ValidateSessionInteractor;
use crate::application::interactors::users::{CreateUserInteractor, GetMeInteractor, UpdateUserInteractor};
use crate::application::interactors::workspace::{
    AcceptWorkspaceInviteInteractor, CheckWorkspaceOwnerInteractor, CreateWorkspaceInteractor,
    DeleteWorkspaceInteractor, GetOwnerWorkspaceInteractor, GetWorkspaceInteractor, GetWorkspaceListInteractor,
    GetWorkspaceLogoInteractor, InviteWorkspaceMemberInteractor, UpdateWorkspaceInteractor,
};
use crate::application::interface::crypto::CredentialsHasher;
use crate::application::interface::email::EmailSender;
use crate::application::interface::s3::StorageClient;
use crate::infra::config::AppConfig;

#[derive(Clone)]
pub struct AppState {
    pub pool: Pool<Postgres>,
    pub hasher: Arc<dyn CredentialsHasher>,
    pub config: Arc<AppConfig>,
    pub email_sender: Arc<dyn EmailSender>,
    pub storage: Arc<dyn StorageClient>,
}

impl FromRef<AppState> for Arc<AppConfig> {
    fn from_ref(state: &AppState) -> Self {
        state.config.clone()
    }
}

#[async_trait]
pub trait FromAppState: Sized {
    async fn from_app_state(state: &AppState) -> AppResult<Self>;
}

// CreateUserInteractor
#[async_trait]
impl FromAppState for CreateUserInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let user_gateway = UserGateway::new(session.clone());

        // TODO: think about a better implementation.
        Ok(CreateUserInteractor::new(
            Arc::new(session),
            Arc::new(user_gateway.clone()),
            Arc::new(user_gateway.clone()),
            state.hasher.clone(),
        ))
    }
}

impl<S> FromRequestParts<S> for CreateUserInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        CreateUserInteractor::from_app_state(&app_state).await
    }
}

// LoginInteractor
#[async_trait]
impl FromAppState for LoginInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let user_gateway = UserGateway::new(session.clone());
        let session_gateway = SessionGateway::new(session.clone());

        Ok(LoginInteractor::new(
            Arc::new(session),
            Arc::new(user_gateway),
            Arc::new(session_gateway),
            state.hasher.clone(),
        ))
    }
}

impl<S> FromRequestParts<S> for LoginInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        LoginInteractor::from_app_state(&app_state).await
    }
}

// GetMeInteractor
#[async_trait]
impl FromAppState for GetMeInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let user_gateway = Arc::new(UserGateway::new(session));

        Ok(GetMeInteractor::new(user_gateway))
    }
}

impl<S> FromRequestParts<S> for GetMeInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        GetMeInteractor::from_app_state(&app_state).await
    }
}

// LogoutInteractor
#[async_trait]
impl FromAppState for LogoutInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let session_gateway = Arc::new(SessionGateway::new(session.clone()));

        Ok(LogoutInteractor::new(Arc::new(session), session_gateway))
    }
}

impl<S> FromRequestParts<S> for LogoutInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        LogoutInteractor::from_app_state(&app_state).await
    }
}

// ValidationSessionInteractor
#[async_trait]
impl FromAppState for ValidateSessionInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let session_gateway = Arc::new(SessionGateway::new(session.clone()));

        Ok(ValidateSessionInteractor::new(
            Arc::new(session),
            session_gateway.clone(),
            session_gateway,
        ))
    }
}

impl<S> FromRequestParts<S> for ValidateSessionInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        ValidateSessionInteractor::from_app_state(&app_state).await
    }
}

// UpdateUserInteractor
#[async_trait]
impl FromAppState for UpdateUserInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let user_gateway = UserGateway::new(session.clone());

        Ok(UpdateUserInteractor::new(
            Arc::new(session),
            Arc::new(user_gateway.clone()),
            Arc::new(user_gateway.clone()),
            state.hasher.clone(),
        ))
    }
}

impl<S> FromRequestParts<S> for UpdateUserInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> AppResult<Self> {
        let app_state = AppState::from_ref(state);
        UpdateUserInteractor::from_app_state(&app_state).await
    }
}

// ConfirmEmailInteractor
#[async_trait]
impl FromAppState for ConfirmEmailInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let user_gateway = UserGateway::new(session.clone());
        let email_confirmation_gateway = EmailConfirmationGateway::new(session.clone());

        Ok(ConfirmEmailInteractor::new(
            Arc::new(session),
            Arc::new(email_confirmation_gateway.clone()),
            Arc::new(email_confirmation_gateway),
            Arc::new(user_gateway.clone()),
            Arc::new(user_gateway),
        ))
    }
}

impl<S> FromRequestParts<S> for ConfirmEmailInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> AppResult<Self> {
        let app_state = AppState::from_ref(state);
        ConfirmEmailInteractor::from_app_state(&app_state).await
    }
}

// ResendConfirmationInteractor
#[async_trait]
impl FromAppState for ResendConfirmationInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let user_gateway = UserGateway::new(session.clone());
        let email_confirmation_gateway = EmailConfirmationGateway::new(session.clone());

        Ok(ResendConfirmationInteractor::new(
            Arc::new(session),
            Arc::new(email_confirmation_gateway),
            Arc::new(user_gateway),
            state.email_sender.clone(),
        ))
    }
}

impl<S> FromRequestParts<S> for ResendConfirmationInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> AppResult<Self> {
        let app_state = AppState::from_ref(state);
        ResendConfirmationInteractor::from_app_state(&app_state).await
    }
}

// RequestPasswordResetInteractor
#[async_trait]
impl FromAppState for RequestPasswordResetInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let password_reset_token_gateway = PasswordResetTokenGateway::new(session.clone());
        let user_gateway = UserGateway::new(session.clone());

        Ok(RequestPasswordResetInteractor::new(
            Arc::new(session),
            Arc::new(password_reset_token_gateway),
            Arc::new(user_gateway),
            state.email_sender.clone(),
        ))
    }
}

impl<S> FromRequestParts<S> for RequestPasswordResetInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> AppResult<Self> {
        let app_state = AppState::from_ref(state);
        RequestPasswordResetInteractor::from_app_state(&app_state).await
    }
}

// ResetPasswordInteractor
#[async_trait]
impl FromAppState for ResetPasswordInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let password_reset_token_gateway = PasswordResetTokenGateway::new(session.clone());
        let user_gateway = UserGateway::new(session.clone());

        Ok(ResetPasswordInteractor::new(
            Arc::new(session),
            Arc::new(password_reset_token_gateway.clone()),
            Arc::new(password_reset_token_gateway),
            Arc::new(user_gateway.clone()),
            Arc::new(user_gateway),
            state.hasher.clone(),
        ))
    }
}

impl<S> FromRequestParts<S> for ResetPasswordInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> AppResult<Self> {
        let app_state = AppState::from_ref(state);
        ResetPasswordInteractor::from_app_state(&app_state).await
    }
}

// CreateWorkspaceInteractor
#[async_trait]
impl FromAppState for CreateWorkspaceInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let workspace_gateway = WorkspaceGateway::new(session.clone());

        Ok(CreateWorkspaceInteractor::new(
            Arc::new(session),
            Arc::new(workspace_gateway),
            state.storage.clone(),
        ))
    }
}

impl<S> FromRequestParts<S> for CreateWorkspaceInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> AppResult<Self> {
        let app_state = AppState::from_ref(state);
        CreateWorkspaceInteractor::from_app_state(&app_state).await
    }
}

// GetWorkspaceListInteractor
#[async_trait]
impl FromAppState for GetWorkspaceListInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let workspace_gateway = WorkspaceGateway::new(session);
        Ok(GetWorkspaceListInteractor::new(Arc::new(workspace_gateway)))
    }
}

impl<S> FromRequestParts<S> for GetWorkspaceListInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> AppResult<Self> {
        let app_state = AppState::from_ref(state);
        GetWorkspaceListInteractor::from_app_state(&app_state).await
    }
}

// GetWorkspaceLogoInteractor
#[async_trait]
impl FromAppState for GetWorkspaceLogoInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let workspace_gateway = WorkspaceGateway::new(session);
        Ok(GetWorkspaceLogoInteractor::new(
            Arc::new(workspace_gateway),
            state.storage.clone(),
        ))
    }
}

impl<S> FromRequestParts<S> for GetWorkspaceLogoInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> AppResult<Self> {
        let app_state = AppState::from_ref(state);
        GetWorkspaceLogoInteractor::from_app_state(&app_state).await
    }
}

// UpdateWorkspaceInteractor
#[async_trait]
impl FromAppState for UpdateWorkspaceInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let workspace_gateway = WorkspaceGateway::new(session.clone());
        Ok(UpdateWorkspaceInteractor::new(
            Arc::new(session),
            Arc::new(workspace_gateway.clone()),
            Arc::new(workspace_gateway),
            state.storage.clone(),
        ))
    }
}

impl<S> FromRequestParts<S> for UpdateWorkspaceInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> AppResult<Self> {
        let app_state = AppState::from_ref(state);
        UpdateWorkspaceInteractor::from_app_state(&app_state).await
    }
}

// DeleteWorkspaceInteractor
#[async_trait]
impl FromAppState for DeleteWorkspaceInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let workspace_gateway = WorkspaceGateway::new(session.clone());
        Ok(DeleteWorkspaceInteractor::new(
            Arc::new(session),
            Arc::new(workspace_gateway.clone()),
            Arc::new(workspace_gateway),
            state.storage.clone(),
        ))
    }
}

impl<S> FromRequestParts<S> for DeleteWorkspaceInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> AppResult<Self> {
        let app_state = AppState::from_ref(state);
        DeleteWorkspaceInteractor::from_app_state(&app_state).await
    }
}

// CheckWorkspaceOwnerInteractor
#[async_trait]
impl FromAppState for CheckWorkspaceOwnerInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let workspace_gateway = WorkspaceGateway::new(session.clone());
        Ok(CheckWorkspaceOwnerInteractor::new(Arc::new(workspace_gateway)))
    }
}

impl<S> FromRequestParts<S> for CheckWorkspaceOwnerInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> AppResult<Self> {
        let app_state = AppState::from_ref(state);
        CheckWorkspaceOwnerInteractor::from_app_state(&app_state).await
    }
}

// InviteWorkspaceMemberInteractor
#[async_trait]
impl FromAppState for InviteWorkspaceMemberInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let workspace_gateway = WorkspaceGateway::new(session.clone());
        let workspace_member_gateway = WorkspaceMemberGateway::new(session.clone());
        let workspace_invite_gateway = WorkspaceInviteGateway::new(session.clone());

        Ok(InviteWorkspaceMemberInteractor::new(
            Arc::new(session),
            Arc::new(workspace_gateway),
            Arc::new(workspace_member_gateway),
            Arc::new(workspace_invite_gateway.clone()),
            Arc::new(workspace_invite_gateway),
            state.email_sender.clone(),
        ))
    }
}

impl<S> FromRequestParts<S> for InviteWorkspaceMemberInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> AppResult<Self> {
        let app_state = AppState::from_ref(state);
        InviteWorkspaceMemberInteractor::from_app_state(&app_state).await
    }
}

// AcceptWorkpspaceInviteIneractor
#[async_trait]
impl FromAppState for AcceptWorkspaceInviteInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let workspace_member_gateway = WorkspaceMemberGateway::new(session.clone());
        let workspace_invite_gateway = WorkspaceInviteGateway::new(session.clone());

        Ok(AcceptWorkspaceInviteInteractor::new(
            Arc::new(session),
            Arc::new(workspace_invite_gateway.clone()),
            Arc::new(workspace_invite_gateway),
            Arc::new(workspace_member_gateway.clone()),
            Arc::new(workspace_member_gateway),
        ))
    }
}

impl<S> FromRequestParts<S> for AcceptWorkspaceInviteInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> AppResult<Self> {
        let app_state = AppState::from_ref(state);
        AcceptWorkspaceInviteInteractor::from_app_state(&app_state).await
    }
}

// GetWorkspaceInteractor
#[async_trait]
impl FromAppState for GetWorkspaceInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let workspace_gateway = WorkspaceGateway::new(session);

        Ok(GetWorkspaceInteractor::new(Arc::new(workspace_gateway)))
    }
}

impl<S> FromRequestParts<S> for GetWorkspaceInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> AppResult<Self> {
        let app_state = AppState::from_ref(state);
        GetWorkspaceInteractor::from_app_state(&app_state).await
    }
}

// GetOwnerWorkspaceInteractor
#[async_trait]
impl FromAppState for GetOwnerWorkspaceInteractor {
    async fn from_app_state(state: &AppState) -> AppResult<Self> {
        let session = SqlxSession::new_lazy(state.pool.clone());
        let workspace_gateway = WorkspaceGateway::new(session.clone());
        let user_gateway = UserGateway::new(session);

        Ok(GetOwnerWorkspaceInteractor::new(
            Arc::new(workspace_gateway),
            Arc::new(user_gateway),
        ))
    }
}

impl<S> FromRequestParts<S> for GetOwnerWorkspaceInteractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> AppResult<Self> {
        let app_state = AppState::from_ref(state);
        GetOwnerWorkspaceInteractor::from_app_state(&app_state).await
    }
}
