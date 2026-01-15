//! COS存储提供者实现
//! 实现StorageProvider trait以集成到CloudRaver系统

use async_trait::async_trait;
use bytes::Bytes;
use std::time::Duration;
use crate::error::{AppError, Result};
use crate::models::CosStorageConfig;
use crate::storage::StorageProvider;

use super::client::Client;
use super::request::ErrNo;
use super::objects::StorageClassEnum;

/// Tencent Cloud COS storage provider
pub struct CosStorage {
    config: CosStorageConfig,
    client: Client,
}

impl CosStorage {
    pub fn new(config: CosStorageConfig) -> Self {
        let client = Client::new(
            &config.secret_id,
            &config.secret_key,
            &config.bucket,
            &config.region,
        );
        Self {
            config,
            client,
        }
    }

    /// Get the full object key with base path
    fn get_object_key(&self, path: &str) -> String {
        let clean_path = path.trim_start_matches('/');
        
        if self.config.base_path.is_empty() {
            clean_path.to_string()
        } else {
            format!("{}/{}", self.config.base_path.trim_end_matches('/'), clean_path)
        }
    }
}

#[async_trait]
impl StorageProvider for CosStorage {
    async fn put(&self, path: &str, data: Bytes) -> Result<()> {
        let object_key = self.get_object_key(path);
        
        // Guess mime type from path
        let mime_type = mime_guess::from_path(path).first_or_octet_stream();
        
        let res = self.client.put_object_binary(
            data,
            &object_key,
            Some(mime_type),
            None
        ).await;

        if res.error_no != ErrNo::SUCCESS {
            return Err(AppError::Storage(format!(
                "COS upload failed: [{}] {}",
                res.error_no, res.error_message
            )));
        }

        tracing::info!("Successfully uploaded to COS: {}", object_key);
        Ok(())
    }

    async fn put_file(&self, path: &str, local_path: &std::path::Path) -> Result<()> {
        let object_key = self.get_object_key(path);
        let metadata = tokio::fs::metadata(local_path).await?;
        let size = metadata.len();
        
        // Guess mime type
        let mime_type = mime_guess::from_path(local_path).first_or_octet_stream();
        
        tracing::info!("Uploading file to COS: {} (size: {} bytes)", object_key, size);

        // Threshold: 500MB
        let threshold = 500 * 1024 * 1024;

        let res = if size > threshold {
            tracing::info!("Using multipart upload for {}", object_key);
            self.client.clone().put_big_object(
                &local_path.to_path_buf(),
                &object_key,
                Some(mime_type),
                Some(StorageClassEnum::STANDARD),
                None,
                None, // default part size
                None, // default threads
            ).await
        } else {
            self.client.put_object(
                &local_path.to_path_buf(),
                &object_key,
                Some(mime_type),
                None
            ).await
        };

        if res.error_no != ErrNo::SUCCESS {
            return Err(AppError::Storage(format!(
                "COS upload failed: [{}] {}",
                res.error_no, res.error_message
            )));
        }

        tracing::info!("Successfully uploaded file to COS: {}", object_key);
        Ok(())
    }

    async fn get(&self, path: &str) -> Result<Bytes> {
        let object_key = self.get_object_key(path);
        
        let res = self.client.get_object_binary(&object_key, None).await;
        
        if res.error_no != ErrNo::SUCCESS {
            if res.error_no == ErrNo::STATUS && res.error_message.contains("404") {
                 return Err(AppError::NotFound(format!("Object not found: {}", path)));
            }
            return Err(AppError::Storage(format!(
                "COS download failed: [{}] {}",
                res.error_no, res.error_message
            )));
        }

        Ok(Bytes::from(res.result))
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let object_key = self.get_object_key(path);
        
        let res = self.client.delete_object(&object_key).await;
        
        // COS delete is idempotent usually, but let's check error
        if res.error_no != ErrNo::SUCCESS {
             // 404 is fine
             if res.error_no == ErrNo::STATUS && res.error_message.contains("404") {
                 return Ok(());
             }
             return Err(AppError::Storage(format!(
                "COS delete failed: [{}] {}",
                res.error_no, res.error_message
            )));
        }

        tracing::debug!("Deleted from COS: {}", object_key);
        Ok(())
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        let object_key = self.get_object_key(path);
        let size = self.client.get_object_size(&object_key).await;
        Ok(size >= 0)
    }

    async fn get_download_url(&self, path: &str, expires: Duration) -> Result<Option<String>> {
        let object_key = self.get_object_key(path);
        let expires_secs = expires.as_secs().max(1) as u32;
        
        let url = self.client.get_presigned_download_url(&object_key, expires_secs);
        Ok(Some(url))
    }

    fn storage_type(&self) -> &'static str {
        "cos"
    }
}
