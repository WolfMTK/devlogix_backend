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
pub struct AppConfig {
    pub db: DatabaseConfig,
    pub logger: LoggerConfig,
    pub allow_origins: Vec<String>,
    pub address: String,
}

impl AppConfig {
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<AppConfig> {
        let contents = std::fs::read_to_string(path)?;
        let config = toml::from_str(&contents)?;
        Ok(config)
    }
}
