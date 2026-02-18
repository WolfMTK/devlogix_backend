use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region};
use aws_credential_types::Credentials;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::Builder;
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::operation::create_bucket::CreateBucketError;
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::primitives::ByteStream;
use bytes::Bytes;
use tracing::{info, warn};

use crate::application::app_error::{AppError, AppResult};
use crate::application::interface::s3::{DownloadedFile, StorageClient};
use crate::infra::config::S3Config;

pub struct S3StorageClient {
    client: Client,
}

impl S3StorageClient {
    pub fn new(config: &S3Config) -> Self {
        let credentials = Credentials::new(&config.access_key, &config.secret_key, None, None, "rustfs");
        let s3_config = Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .endpoint_url(&config.endpoint)
            .region(Region::new(config.region.clone()))
            .credentials_provider(credentials)
            .force_path_style(true)
            .build();

        Self {
            client: Client::from_conf(s3_config),
        }
    }
}

#[async_trait]
impl StorageClient for S3StorageClient {
    async fn ensure_bucket(&self, bucket: &str) -> AppResult<()> {
        let exists = self.client.head_bucket().bucket(bucket).send().await;

        if exists.is_ok() {
            return Ok(());
        }

        let result = self.client.create_bucket().bucket(bucket).send().await;

        match result {
            Ok(_) => {
                info!("Bucket '{}' created (private)", bucket);
                Ok(())
            }
            Err(SdkError::ServiceError(err)) => match err.err() {
                CreateBucketError::BucketAlreadyExists(_) | CreateBucketError::BucketAlreadyOwnedByYou(_) => Ok(()),
                other => {
                    warn!("Failed to create bucket '{}': {:?}", bucket, other);
                    Err(AppError::StorageError(other.to_string()))
                }
            },
            Err(e) => Err(AppError::StorageError(e.to_string())),
        }
    }

    async fn upload(&self, bucket: &str, key: &str, data: Bytes, content_type: &str) -> AppResult<()> {
        self.client
            .put_object()
            .bucket(bucket)
            .key(key)
            .content_type(content_type)
            .body(ByteStream::from(data))
            .send()
            .await
            .map_err(|e| {
                warn!("S3 upload error bucket={} key={}: {:?}", bucket, key, e);
                AppError::StorageError(e.to_string())
            })?;

        info!("Uploaded s3://{}/{}", bucket, key);
        Ok(())
    }

    async fn download(&self, bucket: &str, key: &str) -> AppResult<DownloadedFile> {
        let response = self
            .client
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| match e {
                SdkError::ServiceError(ref err) if matches!(err.err(), GetObjectError::NoSuchKey(_)) => {
                    AppError::StorageNotFound
                }
                other => {
                    warn!("S3 download error bucket={} key={}: {:?}", bucket, key, other);
                    AppError::StorageError(other.to_string())
                }
            })?;

        let content_type = response
            .content_type()
            .unwrap_or("application/octet-stream")
            .to_string();
        let data = response
            .body
            .collect()
            .await
            .map(|b| b.into_bytes())
            .map_err(|e| AppError::StorageError(e.to_string()))?;

        Ok(DownloadedFile { data, content_type })
    }

    async fn delete(&self, bucket: &str, key: &str) -> AppResult<()> {
        self.client
            .delete_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| {
                warn!("S3 delete error bucket={} key={}: {:?}", bucket, key, e);
                AppError::StorageError(e.to_string())
            })?;

        info!("Deleted s3://{}/{}", bucket, key);
        Ok(())
    }
}
