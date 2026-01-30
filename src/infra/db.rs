use crate::infra::config::AppConfig;
use sqlx::{
    postgres::PgPoolOptions,
    PgPool
};
use tracing::info;

pub async fn init_db(config: &AppConfig) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(config.db.max_connections as u32)
        .connect(config.db.url.as_str())
        .await?;
    info!("Connected to database!");
    Ok(pool)
}
