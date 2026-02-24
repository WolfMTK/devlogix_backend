use std::sync::Arc;

use crate::adapter::crypto::argon2::ArgonPasswordHasher;
use crate::adapter::email::local::LocalEmailSender;
use crate::adapter::email::smtp::SMTPEmailSender;
use crate::adapter::storage::s3::S3StorageClient;
use crate::application::interface::email::EmailSender;
use crate::infra::config::AppConfig;
use crate::infra::db::init_db;
use crate::infra::state::AppState;

pub mod app;
pub mod config;
pub mod db;
pub mod setup;
pub mod state;

pub fn argon2_password_hasher() -> ArgonPasswordHasher {
    ArgonPasswordHasher::default()
}

pub async fn init_app_state(config: &AppConfig) -> anyhow::Result<AppState> {
    let pool = init_db(&config).await?;
    let password_hasher = argon2_password_hasher();
    let email_sender: Arc<dyn EmailSender> = match config.email.provider.as_str() {
        "local" => Arc::new(LocalEmailSender::new(config.email.local_output_dir.clone())),
        _ => Arc::new(SMTPEmailSender::new(&config.smtp)),
    };
    let storage = S3StorageClient::new(&config.s3);

    Ok(AppState {
        pool,
        hasher: Arc::new(password_hasher),
        config: Arc::new(config.clone()),
        email_sender,
        storage: Arc::new(storage),
    })
}
