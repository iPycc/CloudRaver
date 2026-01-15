pub mod provider;
pub mod local;
pub mod cos;

pub use provider::*;
pub use local::*;
pub use cos::*;

use crate::error::{AppError, Result};
use crate::models::{PolicyType, StoragePolicy};

/// Storage manager that creates providers based on policy type
pub struct StorageManager {
    // In a more complex setup, we might cache providers here
}

impl StorageManager {
    pub fn new() -> Self {
        Self {}
    }

    /// Get a storage provider for the given policy
    pub fn get_provider(&self, policy: &StoragePolicy) -> Result<Box<dyn StorageProvider>> {
        let policy_type = policy.get_type()
            .ok_or_else(|| AppError::BadRequest("Invalid storage policy type".to_string()))?;

        match policy_type {
            PolicyType::Local => {
                let config: crate::models::LocalStorageConfig = 
                    serde_json::from_str(&policy.config)
                        .unwrap_or_default();
                Ok(Box::new(LocalStorage::new(config)))
            }
            PolicyType::Cos => {
                let config: crate::models::CosStorageConfig = 
                    serde_json::from_str(&policy.config)
                        .map_err(|e| AppError::BadRequest(format!("Invalid COS config: {}", e)))?;
                Ok(Box::new(CosStorage::new(config)))
            }
        }
    }
}

impl Default for StorageManager {
    fn default() -> Self {
        Self::new()
    }
}

