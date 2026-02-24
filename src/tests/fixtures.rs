#![cfg(test)]

use std::fs;
use std::path::Path;
use std::sync::Arc;

use rstest::fixture;

use crate::adapter::email::local::LocalEmailSender;
use crate::adapter::storage::s3::S3StorageClient;
use crate::application::interface::email::EmailSender;
use crate::infra::argon2_password_hasher;
use crate::infra::config::{
    AppConfig, ApplicationConfig, DatabaseConfig, EmailConfig, EmailConfirmationConfig, LoggerConfig,
    PasswordResetConfig, S3Config, SMTPConfig, SessionConfig, WorkspaceInviteConfig,
};
use crate::infra::db::init_db;
use crate::infra::state::AppState;

#[fixture]
pub fn test_config() -> AppConfig {
    AppConfig {
        db: DatabaseConfig {
            url: std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set"),
            max_connections: 5,
        },
        logger: LoggerConfig {
            log_path: "./test_logs".to_string(),
        },
        application: ApplicationConfig {
            allow_origins: vec!["*".to_string()],
            address: std::env::var("TEST_APP_ADDRESS").expect("TEST_APP_ADDRESS must be set"),
        },
        session: SessionConfig {
            default_max_lifetime: 86_400,
            default_idle_timeout: 3_600,
            remembered_max_lifetime: 2_592_000,
            remembered_idle_timeout: 86_400,
            rotation_interval: 900,
            cookie_name: std::env::var("TEST_COOKIE_NAME").expect("TEST_COOKIE_NAME must be set"),
            cookie_secure: false,
            cookie_http_only: true,
        },
        email_confirmation: EmailConfirmationConfig {
            ttl: 86_400,
            confirmation_url: "http://localhost/confirm".to_string(),
        },
        email: EmailConfig {
            provider: "local".to_string(),
            local_output_dir: "./tmp/test-integration-emails".to_string(),
        },
        smtp: SMTPConfig {
            host: std::env::var("TEST_SMTP_HOST").expect("TEST_SMTP_HOST must be set"),
            port: std::env::var("TEST_SMTP_PORT")
                .expect("TEST_SMTP_PORT must be set")
                .parse::<u16>()
                .expect("TEST_SMTP_PORT must be a number"),
            username: std::env::var("TEST_SMTP_USERNAME").expect("TEST_SMTP_USERNAME must be set"),
            password: std::env::var("TEST_SMTP_PASSWORD").expect("TEST_SMTP_PASSWORD must be set"),
            from: std::env::var("TEST_SMTP_FROM").expect("TEST_SMTP_FROM must be set"),
        },
        password_reset: PasswordResetConfig {
            ttl: 3_600,
            reset_url: "http://localhost/reset-password".to_string(),
        },
        s3: S3Config {
            access_key: std::env::var("TEST_S3_ACCESS_KEY").expect("TEST_S3_ACCESS_KEY must be set"),
            secret_key: std::env::var("TEST_S3_SECRET_KEY").expect("TEST_S3_SECRET_KEY must be set"),
            endpoint: std::env::var("TEST_S3_ENDPOINT").expect("TEST_S3_ENDPOINT must be set"),
            region: std::env::var("TEST_S3_REGION").expect("TEST_S3_REGION must be set"),
        },
        workspace_invite: WorkspaceInviteConfig {
            ttl: 86_400,
            invite_url: "http://localhost/workspaces/invites/accept".to_string(),
        },
    }
}

#[fixture]
pub async fn init_test_app_state(test_config: AppConfig) -> anyhow::Result<AppState> {
    let pool = init_db(&test_config).await?;

    let email_dir = Path::new(&test_config.email.local_output_dir);
    if email_dir.exists() {
        fs::remove_dir_all(email_dir)?;
    }
    fs::create_dir_all(email_dir)?;

    let password_hasher = argon2_password_hasher();

    let email_sender: Arc<dyn EmailSender> =
        Arc::new(LocalEmailSender::new(test_config.email.local_output_dir.clone()));

    let storage = S3StorageClient::new(&test_config.s3);

    Ok(AppState {
        pool,
        hasher: Arc::new(password_hasher),
        config: Arc::new(test_config.clone()),
        email_sender,
        storage: Arc::new(storage),
    })
}
