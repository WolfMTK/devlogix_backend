use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{self};
use axum::routing::{get, patch, post};
use axum::{Router, middleware};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;
use uuid::Uuid;

use crate::adapter::http::docs::{docs_ui, openapi_json};
use crate::adapter::http::middleware::auth::{auth_middleware, session_cookie_middleware};
use crate::adapter::http::routes::auth::{confirm_email, login, logout, resend_confirmation};
use crate::adapter::http::routes::user::{get_me, register, update_user};
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
        ])
        .allow_headers([CONTENT_TYPE, AUTHORIZATION])
        .allow_credentials(true)
}

pub fn user_router(state: AppState) -> Router<AppState> {
    let public_routes = Router::new().route("/register", post(register));

    let protected_routes = Router::new()
        .route("/me", get(get_me))
        .route("/", patch(update_user))
        .route_layer(middleware::from_fn_with_state(state.clone(), session_cookie_middleware))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    Router::new().merge(public_routes).merge(protected_routes)
}

pub fn auth_router(state: AppState) -> Router<AppState> {
    let public_routes = Router::new()
        .route("/login", post(login))
        .route("/resend-confirmation", post(resend_confirmation))
        .route("/confirm-email", get(confirm_email));

    let protected_routes = Router::new()
        .route("/logout", post(logout))
        .route_layer(middleware::from_fn_with_state(state.clone(), session_cookie_middleware))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware));
    Router::new().merge(public_routes).merge(protected_routes)
}

pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .nest("/users", user_router(state.clone()))
        .nest("/auth", auth_router(state.clone()))
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
