use crate::infra::config::AppConfig;
use crate::infra::state::AppState;
use axum::{
    Router, http,
    http::header::{AUTHORIZATION, CONTENT_TYPE},
};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use tracing::Level;
use uuid::Uuid;

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

pub fn create_app(config: &AppConfig, state: AppState) -> Router {
    let cors = build_cors(config);

    Router::new().with_state(state).layer(cors).layer(
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
