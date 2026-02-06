use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggerConfig {
    pub log_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationConfig {
    pub allow_origins: Vec<String>,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub default_max_lifetime: i64,
    pub default_idle_timeout: i64,
    pub remembered_max_lifetime: i64,
    pub remembered_idle_timeout: i64,
    pub rotation_interval: i64,
    pub cookie_name: String,
    pub cookie_secure: bool,
    pub cookie_http_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfirmationConfig {
    pub ttl: i64,
    pub confirmation_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub db: DatabaseConfig,
    pub logger: LoggerConfig,
    pub application: ApplicationConfig,
    pub session: SessionConfig,
    pub email_confirmation: EmailConfirmationConfig,
}

impl AppConfig {
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<AppConfig> {
        let contents = std::fs::read_to_string(path)?;
        let config = toml::from_str(&contents)?;
        Ok(config)
    }
}
