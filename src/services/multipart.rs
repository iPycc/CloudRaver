use std::collections::HashMap;
use crate::storage::cos::client::Client as CosClient;
use reqwest::header::{HeaderMap, HeaderValue, HOST};
use urlencoding::encode;

use crate::models::CosStorageConfig;
use crate::error::{AppError, Result};

pub struct MultipartService;

impl MultipartService {
    fn get_client(config: &CosStorageConfig) -> CosClient {
        CosClient::new(
            &config.secret_id,
            &config.secret_key,
            &config.bucket,
            &config.region,
        )
    }

    pub async fn initiate_multipart(
        config: &CosStorageConfig,
        key: &str,
        mime_type: Option<String>,
    ) -> Result<String> {
        let client = Self::get_client(config);
        let content_type = mime_type.and_then(|s| s.parse().ok());
        
        let resp = client.put_object_get_upload_id(
            key, 
            content_type, 
            None, 
            None
        ).await;

        if resp.error_no != crate::storage::cos::request::ErrNo::SUCCESS {
             return Err(AppError::Storage(format!("COS 初始化分片上传失败: {}", resp.error_message)));
        }

        let upload_id = String::from_utf8(resp.result)
            .map_err(|e| AppError::Internal(format!("Invalid upload_id: {}", e)))?;
            
        Ok(upload_id)
    }

    pub fn sign_part(
        config: &CosStorageConfig,
        key: &str,
        upload_id: &str,
        part_number: u64,
    ) -> Result<(String, String)> {
        let client = Self::get_client(config);
        
        let url_path = client.get_path_from_object_key(key);
        let mut query = HashMap::new();
        query.insert("partNumber".to_string(), part_number.to_string());
        query.insert("uploadId".to_string(), upload_id.to_string());
        
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_str(&client.get_host()).unwrap());
        
        let auth_headers = client.get_headers_with_auth(
            "put",
            &url_path,
            None,
            Some(headers),
            Some(query),
        );
        
        let auth = auth_headers.get(reqwest::header::AUTHORIZATION)
            .ok_or_else(|| AppError::Internal("Failed to generate signature".to_string()))?
            .to_str()
            .map_err(|_| AppError::Internal("Invalid authorization header".to_string()))?
            .to_string();
            
        let url = format!(
            "{}?partNumber={}&uploadId={}",
            client.get_full_url_from_path(&url_path),
            part_number,
            encode(upload_id)
        );
        
        Ok((url, auth))
    }

    pub async fn complete_multipart(
        config: &CosStorageConfig,
        key: &str,
        upload_id: &str,
        etags: HashMap<u64, String>,
    ) -> Result<()> {
        let client = Self::get_client(config);
        
        let resp = client.put_object_complete_part(
            key,
            etags,
            upload_id
        ).await;

        if resp.error_no != crate::storage::cos::request::ErrNo::SUCCESS {
            return Err(AppError::Storage(format!("COS 合并分片失败: {}", resp.error_message)));
        }
        
        Ok(())
    }

    pub async fn abort_multipart(config: &CosStorageConfig, key: &str, upload_id: &str) -> Result<()> {
        let client = Self::get_client(config);
        let resp = client.abort_object_part(key, upload_id).await;
        if resp.error_no != crate::storage::cos::request::ErrNo::SUCCESS {
            return Err(AppError::Storage(format!("COS 终止分片上传失败: {}", resp.error_message)));
        }
        Ok(())
    }
}
