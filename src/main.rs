mod adapter;
mod application;
mod infra;

use crate::infra::init_app_state;
use crate::{infra::app::create_app, infra::config::AppConfig, infra::setup::init_tracing};
use std::env;
use tower_http::trace::TraceLayer;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path_config = env::var("BASE_CONFIG").expect("Key `BASE_CONFIG` not set");
    let config = AppConfig::from_file(path_config)?;
    let _guards = init_tracing(&config);
    let state = init_app_state(&config).await?;
    info!("Start server...");
    let app = create_app(&config, state).layer(TraceLayer::new_for_http());
    let listener = tokio::net::TcpListener::bind(&config.application.address).await?;
    info!("Backend listening at {}", &listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}
