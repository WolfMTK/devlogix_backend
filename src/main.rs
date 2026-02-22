mod adapter;
mod application;
mod domain;
mod infra;
#[cfg(test)]
mod tests;

use std::env;

use tracing::info;

use crate::infra::app::create_app;
use crate::infra::config::AppConfig;
use crate::infra::init_app_state;
use crate::infra::setup::init_tracing;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path_config = env::var("BASE_CONFIG").expect("Key `BASE_CONFIG` not set");
    let config = AppConfig::from_file(path_config)?;
    let _guards = init_tracing(&config);
    let state = init_app_state(&config).await?;
    info!("Start server...");
    let app = create_app(&config, state);
    let listener = tokio::net::TcpListener::bind(&config.application.address).await?;
    info!("Backend listening at {}", &listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}
