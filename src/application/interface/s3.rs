use async_trait::async_trait;
use bytes::Bytes;

use crate::application::app_error::AppResult;

pub struct DownloadedFile {
    pub data: Bytes,
    pub content_type: String,
}

pub struct DetectedImage {
    pub content_type: &'static str,
    pub ext: &'static str,
}

#[async_trait]
pub trait StorageClient: Send + Sync {
    async fn ensure_bucket(&self, bucket: &str) -> AppResult<()>;
    async fn upload(&self, bucket: &str, key: &str, data: Bytes, content_type: &str) -> AppResult<()>;
    async fn download(&self, bucket: &str, key: &str) -> AppResult<DownloadedFile>;
    async fn delete(&self, bucket: &str, key: &str) -> AppResult<()>;
    async fn delete_bucket(&self, bucket: &str) -> AppResult<()>;

    fn detect_image(&self, data: &[u8]) -> Option<DetectedImage> {
        // PNG: 89 50 4E 47
        if data.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
            return Some(DetectedImage {
                content_type: "image/png",
                ext: "png",
            });
        }
        // JPEG: FF D8 FF
        if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
            return Some(DetectedImage {
                content_type: "image/jpeg",
                ext: "jpg",
            });
        }

        None
    }
}
