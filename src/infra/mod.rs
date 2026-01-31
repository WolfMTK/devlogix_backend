use crate::adapter::crypto::argon2::ArgonPasswordHasher;
use crate::infra::config::AppConfig;
use crate::infra::db::init_db;
use crate::infra::state::AppState;
use std::sync::Arc;

pub mod config;
pub mod setup;
pub mod app;
pub mod db;
pub mod state;


fn argon2_password_hasher() -> ArgonPasswordHasher {
    ArgonPasswordHasher::default()
}

pub async fn init_app_state(config: &AppConfig) -> anyhow::Result<AppState>  {
    let pool = init_db(&config).await?;
    let password_hasher = argon2_password_hasher();

    Ok(AppState {
        pool,
        hasher: Arc::new(password_hasher),
    })
}
