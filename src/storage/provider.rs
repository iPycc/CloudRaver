use async_trait::async_trait;
use bytes::Bytes;
use std::time::Duration;

use crate::error::Result;

/// Storage provider trait
#[async_trait]
pub trait StorageProvider: Send + Sync {
    /// Upload data to storage
    async fn put(&self, path: &str, data: Bytes) -> Result<()>;

    /// Upload file from local path
    /// Default implementation reads file to memory and calls put (not efficient for large files)
    async fn put_file(&self, path: &str, local_path: &std::path::Path) -> Result<()> {
        let data = tokio::fs::read(local_path).await?;
        self.put(path, Bytes::from(data)).await
    }

    /// Download data from storage
    async fn get(&self, path: &str) -> Result<Bytes>;

    /// Delete data from storage
    async fn delete(&self, path: &str) -> Result<()>;

    /// Check if a file exists
    async fn exists(&self, path: &str) -> Result<bool>;

    /// Get a signed URL for downloading (for remote storage)
    /// For local storage, this might return a relative path or None
    async fn get_download_url(&self, path: &str, expires: Duration) -> Result<Option<String>>;

    /// Get the storage type name
    fn storage_type(&self) -> &'static str;
}

