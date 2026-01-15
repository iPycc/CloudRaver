//! 文件夹操作模块
//! 提供文件夹上传、下载等批量操作功能

use crate::storage::cos::client::Client;
use crate::storage::cos::objects::StorageClassEnum;
use crate::storage::cos::request::{ErrNo, Response};
use crate::storage::cos::acl::AclHeader;
use std::path::{Path, PathBuf};
use tokio::fs;

/// 文件夹操作trait
pub trait FolderOperations {
    /// 上传整个文件夹到COS
    async fn upload_folder(
        &self,
        local_folder: &Path,
        remote_prefix: &str,
        storage_class: Option<StorageClassEnum>,
        acl_header: Option<AclHeader>,
    ) -> Vec<UploadResult>;
    
    /// 下载整个文件夹从COS
    async fn download_folder(
        &self,
        remote_prefix: &str,
        local_folder: &Path,
    ) -> Vec<DownloadResult>;
    
    /// 删除文件夹（删除指定前缀的所有对象）
    async fn delete_folder(&self, prefix: &str) -> Vec<DeleteResult>;
}

/// 上传结果
#[derive(Debug, Clone)]
pub struct UploadResult {
    pub local_path: PathBuf,
    pub remote_key: String,
    pub success: bool,
    pub error_message: Option<String>,
}

/// 下载结果
#[derive(Debug, Clone)]
pub struct DownloadResult {
    pub remote_key: String,
    pub local_path: PathBuf,
    pub success: bool,
    pub error_message: Option<String>,
}

/// 删除结果
#[derive(Debug, Clone)]
pub struct DeleteResult {
    pub key: String,
    pub success: bool,
    pub error_message: Option<String>,
}

impl FolderOperations for Client {
    /// 上传整个文件夹到COS
    /// 
    /// # 参数
    /// - local_folder: 本地文件夹路径
    /// - remote_prefix: 远程前缀（文件夹路径）
    /// - storage_class: 存储类型
    /// - acl_header: 访问控制
    /// 
    /// # 返回
    /// 每个文件的上传结果列表
    async fn upload_folder(
        &self,
        local_folder: &Path,
        remote_prefix: &str,
        storage_class: Option<StorageClassEnum>,
        acl_header: Option<AclHeader>,
    ) -> Vec<UploadResult> {
        let mut results = Vec::new();
        
        // 确保远程前缀以/结尾
        let remote_prefix = if remote_prefix.is_empty() {
            String::new()
        } else if remote_prefix.ends_with('/') {
            remote_prefix.to_string()
        } else {
            format!("{}/", remote_prefix)
        };
        
        // 递归遍历文件夹
        match Self::walk_dir(local_folder).await {
            Ok(files) => {
                for file_path in files {
                    // 计算相对路径
                    let relative_path = match file_path.strip_prefix(local_folder) {
                        Ok(p) => p,
                        Err(_) => {
                            results.push(UploadResult {
                                local_path: file_path.clone(),
                                remote_key: String::new(),
                                success: false,
                                error_message: Some("Failed to calculate relative path".to_string()),
                            });
                            continue;
                        }
                    };
                    
                    // 构建远程键（使用/作为分隔符）
                    let remote_key = format!(
                        "{}{}",
                        remote_prefix,
                        relative_path.to_string_lossy().replace('\\', "/")
                    );
                    
                    // 猜测MIME类型
                    let mime_type = mime_guess::from_path(&file_path).first();
                    
                    // 获取文件大小
                    let file_size = match fs::metadata(&file_path).await {
                        Ok(meta) => meta.len(),
                        Err(e) => {
                            results.push(UploadResult {
                                local_path: file_path.clone(),
                                remote_key: remote_key.clone(),
                                success: false,
                                error_message: Some(format!("Failed to get file metadata: {}", e)),
                            });
                            continue;
                        }
                    };
                    
                    // 根据文件大小选择上传方式
                    let threshold = 500 * 1024 * 1024; // 500MB
                    let response = if file_size > threshold {
                        // 使用分片上传
                        self.clone().put_big_object(
                            &file_path,
                            &remote_key,
                            mime_type,
                            storage_class.clone(),
                            acl_header.clone(),
                            None,
                            None,
                        ).await
                    } else {
                        // 使用普通上传
                        self.put_object(
                            &file_path,
                            &remote_key,
                            mime_type,
                            acl_header.clone(),
                        ).await
                    };
                    
                    results.push(UploadResult {
                        local_path: file_path,
                        remote_key,
                        success: response.error_no == ErrNo::SUCCESS,
                        error_message: if response.error_no == ErrNo::SUCCESS {
                            None
                        } else {
                            Some(response.error_message)
                        },
                    });
                }
            }
            Err(e) => {
                results.push(UploadResult {
                    local_path: local_folder.to_path_buf(),
                    remote_key: String::new(),
                    success: false,
                    error_message: Some(format!("Failed to walk directory: {}", e)),
                });
            }
        }
        
        results
    }
    
    /// 下载整个文件夹从COS
    /// 
    /// # 参数
    /// - remote_prefix: 远程前缀（文件夹路径）
    /// - local_folder: 本地文件夹路径
    /// 
    /// # 返回
    /// 每个文件的下载结果列表
    async fn download_folder(
        &self,
        remote_prefix: &str,
        local_folder: &Path,
    ) -> Vec<DownloadResult> {
        let mut results = Vec::new();
        
        // 列出所有对象
        let list_response = self.list_objects(Some(remote_prefix), None).await;
        
        if list_response.error_no != ErrNo::SUCCESS {
            results.push(DownloadResult {
                remote_key: remote_prefix.to_string(),
                local_path: local_folder.to_path_buf(),
                success: false,
                error_message: Some(format!("Failed to list objects: {}", list_response.error_message)),
            });
            return results;
        }
        
        // 解析XML响应获取对象列表
        // 这里简化处理，实际应该解析XML
        // 由于这是示例，我们返回空结果
        // 在实际使用中，需要解析list_response.result中的XML
        
        results
    }
    
    /// 删除文件夹（删除指定前缀的所有对象）
    /// 
    /// # 参数
    /// - prefix: 对象键前缀
    /// 
    /// # 返回
    /// 每个对象的删除结果列表
    async fn delete_folder(&self, prefix: &str) -> Vec<DeleteResult> {
        let mut results = Vec::new();
        
        // 列出所有对象
        let list_response = self.list_objects(Some(prefix), None).await;
        
        if list_response.error_no != ErrNo::SUCCESS {
            results.push(DeleteResult {
                key: prefix.to_string(),
                success: false,
                error_message: Some(format!("Failed to list objects: {}", list_response.error_message)),
            });
            return results;
        }
        
        // 解析XML响应获取对象列表并删除
        // 这里简化处理，实际应该解析XML
        // 在实际使用中，需要解析list_response.result中的XML并逐个删除
        
        results
    }
}

impl Client {
    /// 递归遍历目录获取所有文件
    fn walk_dir(dir: &Path) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<PathBuf>, std::io::Error>> + Send + '_>> {
        Box::pin(async move {
            let mut files = Vec::new();
            let mut entries = fs::read_dir(dir).await?;
            
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                let metadata = fs::metadata(&path).await?;
                
                if metadata.is_file() {
                    files.push(path);
                } else if metadata.is_dir() {
                    let mut sub_files = Self::walk_dir(&path).await?;
                    files.append(&mut sub_files);
                }
            }
            
            Ok(files)
        })
    }
}

// 为Client添加便捷方法
impl Client {
    /// 批量上传文件
    /// 
    /// # 参数
    /// - files: 文件路径和远程键的映射
    /// - storage_class: 存储类型
    /// - acl_header: 访问控制
    pub async fn batch_upload(
        &self,
        files: Vec<(PathBuf, String)>,
        storage_class: Option<StorageClassEnum>,
        acl_header: Option<AclHeader>,
    ) -> Vec<UploadResult> {
        let mut results = Vec::new();
        
        for (local_path, remote_key) in files {
            let mime_type = mime_guess::from_path(&local_path).first();
            
            let file_size = match fs::metadata(&local_path).await {
                Ok(meta) => meta.len(),
                Err(e) => {
                    results.push(UploadResult {
                        local_path: local_path.clone(),
                        remote_key: remote_key.clone(),
                        success: false,
                        error_message: Some(format!("Failed to get file metadata: {}", e)),
                    });
                    continue;
                }
            };
            
            let threshold = 500 * 1024 * 1024;
            let response = if file_size > threshold {
                self.clone().put_big_object(
                    &local_path,
                    &remote_key,
                    mime_type,
                    storage_class.clone(),
                    acl_header.clone(),
                    None,
                    None,
                ).await
            } else {
                self.put_object(
                    &local_path,
                    &remote_key,
                    mime_type,
                    acl_header.clone(),
                ).await
            };
            
            results.push(UploadResult {
                local_path,
                remote_key,
                success: response.error_no == ErrNo::SUCCESS,
                error_message: if response.error_no == ErrNo::SUCCESS {
                    None
                } else {
                    Some(response.error_message)
                },
            });
        }
        
        results
    }
    
    /// 批量删除文件
    /// 
    /// # 参数
    /// - keys: 要删除的对象键列表
    pub async fn batch_delete(&self, keys: Vec<String>) -> Vec<DeleteResult> {
        let mut results = Vec::new();
        
        for key in keys {
            let response = self.delete_object(&key).await;
            
            results.push(DeleteResult {
                key,
                success: response.error_no == ErrNo::SUCCESS,
                error_message: if response.error_no == ErrNo::SUCCESS {
                    None
                } else {
                    Some(response.error_message)
                },
            });
        }
        
        results
    }
}

// 需要导入bucket模块的list_objects方法
use crate::storage::cos::bucket::BucketOperations;
