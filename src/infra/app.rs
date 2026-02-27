use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{self};
use axum::routing::{delete, get, patch, post, put};
use axum::{middleware, Router};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;
use uuid::Uuid;

use crate::adapter::http::docs::{docs_ui, openapi_json};
use crate::adapter::http::middleware::auth::{auth_middleware, session_cookie_middleware};
use crate::adapter::http::routes::auth::{
    confirm_email, forgot_password, login, logout, resend_confirmation, reset_password,
};
use crate::adapter::http::routes::project::{create_project, get_project, get_projects};
use crate::adapter::http::routes::user::{get_me, register, update_user};
use crate::adapter::http::routes::workspace::{
    accept_workspace_invite, check_workspace_owner, create_workspace, delete_workspace, delete_workspace_pin,
    get_owner_workspace, get_workspace, get_workspace_list, get_workspace_logo, get_workspace_pin,
    invite_workspace_member, set_workspace_pin, update_workspace,
};
use crate::infra::config::AppConfig;
use crate::infra::state::AppState;

fn build_cors(config: &AppConfig) -> CorsLayer {
    let has_wildcard = config.application.allow_origins.iter().any(|s| s == "*");

    if has_wildcard {
        return CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([
                http::Method::POST,
                http::Method::GET,
                http::Method::PATCH,
                http::Method::DELETE,
                http::Method::PUT,
            ])
            .allow_headers([CONTENT_TYPE, AUTHORIZATION]);
    }
    let origins: Vec<http::HeaderValue> = config
        .application
        .allow_origins
        .iter()
        .filter_map(|s| {
            s.parse::<http::HeaderValue>()
                .map_err(|e| {
                    tracing::warn!("Failed to parse origin '{}': {}", s, e);
                })
                .ok()
        })
        .collect();

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            http::Method::POST,
            http::Method::GET,
            http::Method::PATCH,
            http::Method::DELETE,
            http::Method::PUT,
        ])
        .allow_headers([CONTENT_TYPE, AUTHORIZATION])
        .allow_credentials(true)
}

pub fn user_router(state: AppState) -> Router<AppState> {
    let public_routes = Router::new().route("/register", post(register));

    let protected_routes = Router::new()
        .route("/", patch(update_user))
        .route("/me", get(get_me))
        .route_layer(middleware::from_fn_with_state(state.clone(), session_cookie_middleware))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    Router::new().merge(public_routes).merge(protected_routes)
}

pub fn auth_router(state: AppState) -> Router<AppState> {
    let public_routes = Router::new()
        .route("/login", post(login))
        .route("/resend-confirmation", post(resend_confirmation))
        .route("/confirm-email", get(confirm_email))
        .route("/forgot-password", post(forgot_password))
        .route("/reset-password", post(reset_password));

    let protected_routes = Router::new()
        .route("/logout", post(logout))
        .route_layer(middleware::from_fn_with_state(state.clone(), session_cookie_middleware))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware));
    Router::new().merge(public_routes).merge(protected_routes)
}

pub fn workspace_router(state: AppState) -> Router<AppState> {
    let protected_routes = Router::new()
        .route("/", post(create_workspace))
        .route("/", get(get_workspace_list))
        .route("/{workspace_id}/{slug}", get(get_workspace))
        .route("/{workspace_id}/{slug}/owner", get(get_owner_workspace))
        .route("/{workspace_id}", patch(update_workspace))
        .route("/{workspace_id}", delete(delete_workspace))
        .route("/{workspace_id}/pin", put(set_workspace_pin))
        .route("/pin", get(get_workspace_pin))
        .route("/pin", delete(delete_workspace_pin))
        .route("/{workspace_id}/check-owner", get(check_workspace_owner))
        .route("/{workspace_id}/invites", post(invite_workspace_member))
        .route("/invites/accept", get(accept_workspace_invite))
        .route("/{workspace_id}/storage/{file_name}", get(get_workspace_logo))
        .route_layer(middleware::from_fn_with_state(state.clone(), session_cookie_middleware))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    Router::new().merge(protected_routes)
}

pub fn project_router(state: AppState) -> Router<AppState> {
    let protected_routes = Router::new()
        .route("/", post(create_project))
        .route("/{workspace_id}", get(get_projects))
        .route("/{workspace_id}/{project_id}", get(get_project))
        .route_layer(middleware::from_fn_with_state(state.clone(), session_cookie_middleware))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    Router::new().merge(protected_routes)
}

pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .nest("/users", user_router(state.clone()))
        .nest("/auth", auth_router(state.clone()))
        .nest("/workspaces", workspace_router(state.clone()))
        .nest("/projects", project_router(state.clone()))
        .route("/openapi.json", get(openapi_json))
        .route("/docs", get(docs_ui))
}

pub fn create_app(config: &AppConfig, state: AppState) -> Router {
    let cors = build_cors(config);
    Router::new()
        .merge(router(state.clone()))
        .with_state(state.clone())
        .layer(cors)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &http::Request<_>| {
                    let request_id = Uuid::now_v7();
                    tracing::info_span!(
                        "http-request",
                        method = %request.method(),
                        uri = %request.uri(),
                        version = ?request.version(),
                        request_id = %request_id
                    )
                })
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
}
