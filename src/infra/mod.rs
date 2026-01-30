use crate::infra::config::AppConfig;
use crate::infra::db::init_db;
use crate::infra::state::AppState;

pub mod config;
pub mod setup;
pub mod app;
pub mod db;
pub mod state;


pub async fn init_app_state(config: &AppConfig) -> anyhow::Result<(AppState)>  {
    let pool = init_db(&config).await?;
    Ok(AppState {
        pool,
    })
}
