use async_trait::async_trait;
use bytes::Bytes;
use std::path::PathBuf;
use std::time::Duration;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::error::{AppError, Result};
use crate::models::LocalStorageConfig;
use crate::storage::StorageProvider;

/// Local file system storage provider
pub struct LocalStorage {
    base_path: PathBuf,
}

impl LocalStorage {
    pub fn new(config: LocalStorageConfig) -> Self {
        Self {
            base_path: PathBuf::from(config.base_path),
        }
    }

    fn get_full_path(&self, path: &str) -> PathBuf {
        self.base_path.join(path)
    }
}

#[async_trait]
impl StorageProvider for LocalStorage {
    async fn put(&self, path: &str, data: Bytes) -> Result<()> {
        let full_path = self.get_full_path(path);

        // Ensure parent directory exists
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Write file
        let mut file = fs::File::create(&full_path).await?;
        file.write_all(&data).await?;
        file.flush().await?;

        tracing::debug!("Saved file to {:?}", full_path);
        Ok(())
    }

    async fn put_file(&self, path: &str, local_path: &std::path::Path) -> Result<()> {
        let full_path = self.get_full_path(path);

        // Ensure parent directory exists
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Copy file
        fs::copy(local_path, &full_path).await?;
        tracing::debug!("Copied file from {:?} to {:?}", local_path, full_path);
        Ok(())
    }

    async fn get(&self, path: &str) -> Result<Bytes> {
        let full_path = self.get_full_path(path);

        let data = fs::read(&full_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::NotFound(format!("File not found: {}", path))
            } else {
                AppError::Storage(format!("Failed to read file: {}", e))
            }
        })?;

        Ok(Bytes::from(data))
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let full_path = self.get_full_path(path);

        if full_path.exists() {
            fs::remove_file(&full_path).await?;
            tracing::debug!("Deleted file {:?}", full_path);

            // Try to remove empty parent directories
            let mut current_dir = full_path.parent().map(|p| p.to_path_buf());
            while let Some(dir) = current_dir {
                if dir == self.base_path {
                    break;
                }
                // Check if directory is empty
                match fs::read_dir(&dir).await {
                    Ok(mut entries) => {
                        if entries.next_entry().await?.is_some() {
                            break; // Not empty
                        }
                        // Empty, try to remove
                        let _ = fs::remove_dir(&dir).await;
                    }
                    Err(_) => break,
                }
                current_dir = dir.parent().map(|p| p.to_path_buf());
            }
        }

        Ok(())
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        let full_path = self.get_full_path(path);
        Ok(full_path.exists())
    }

    async fn get_download_url(&self, _path: &str, _expires: Duration) -> Result<Option<String>> {
        // Local storage doesn't use signed URLs
        // The file will be served directly by the application
        Ok(None)
    }

    fn storage_type(&self) -> &'static str {
        "local"
    }
}

