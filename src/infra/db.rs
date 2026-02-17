use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tracing::info;

use crate::infra::config::AppConfig;

pub async fn init_db(config: &AppConfig) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(config.db.max_connections as u32)
        .connect(config.db.url.as_str())
        .await?;
    info!("Connected to database!");
    Ok(pool)
}
