use async_trait::async_trait;
use bytes::Bytes;

use crate::application::app_error::AppResult;

pub struct DownloadedFile {
    pub data: Bytes,
    pub content_type: String,
}

#[async_trait]
pub trait StorageClient: Send + Sync {
    async fn ensure_bucket(&self, bucket: &str) -> AppResult<()>;
    async fn upload(&self, bucket: &str, key: &str, data: Bytes, content_type: &str) -> AppResult<()>;
    async fn download(&self, bucket: &str, key: &str) -> AppResult<DownloadedFile>;
    async fn delete(&self, bucket: &str, key: &str) -> AppResult<()>;
}
