//! 存储桶操作模块
//! 提供存储桶相关的操作功能

use crate::storage::cos::client::Client;
use crate::storage::cos::request::{ErrNo, Request, Response};
use std::collections::HashMap;

/// 存储桶操作trait
pub trait BucketOperations {
    /// 列出存储桶中的对象
    async fn list_objects(&self, prefix: Option<&str>, max_keys: Option<u32>) -> Response;
    
    /// 检查存储桶是否存在
    async fn bucket_exists(&self) -> bool;
    
    /// 获取存储桶信息
    async fn get_bucket_info(&self) -> Response;
}

impl BucketOperations for Client {
    /// 列出存储桶中的对象
    /// 
    /// # 参数
    /// - prefix: 对象键前缀
    /// - max_keys: 最大返回数量
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/7734
    async fn list_objects(&self, prefix: Option<&str>, max_keys: Option<u32>) -> Response {
        let mut query = HashMap::new();
        
        if let Some(prefix) = prefix {
            query.insert("prefix".to_string(), prefix.to_string());
        }
        
        if let Some(max_keys) = max_keys {
            query.insert("max-keys".to_string(), max_keys.to_string());
        }
        
        let url_path = "/";
        let headers = self.get_headers_with_auth(
            "get",
            url_path,
            None,
            None,
            if query.is_empty() { None } else { Some(query.clone()) },
        );
        
        let resp = Request::get(
            &self.get_full_url_from_path(url_path),
            if query.is_empty() { None } else { Some(&query) },
            Some(&headers),
        )
        .await;
        
        self.make_response(resp)
    }
    
    /// 检查存储桶是否存在
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/7735
    async fn bucket_exists(&self) -> bool {
        let url_path = "/";
        let headers = self.get_headers_with_auth("head", url_path, None, None, None);
        
        let response = reqwest::Client::new()
            .head(self.get_full_url_from_path(url_path))
            .headers(headers)
            .send()
            .await;
        
        match response {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }
    
    /// 获取存储桶信息
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/7735
    async fn get_bucket_info(&self) -> Response {
        let url_path = "/";
        let headers = self.get_headers_with_auth("head", url_path, None, None, None);
        
        let resp = Request::head(&self.get_full_url_from_path(url_path), None, Some(&headers)).await;
        
        self.make_response(resp)
    }
}

impl Client {
    /// 创建存储桶
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/7738
    pub async fn create_bucket(&self) -> Response {
        let url_path = "/";
        let headers = self.get_headers_with_auth("put", url_path, None, None, None);
        
        let resp = Request::put(
            &self.get_full_url_from_path(url_path),
            None,
            Some(&headers),
            None,
            None,
            None as Option<reqwest::Body>,
        )
        .await;
        
        self.make_response(resp)
    }
    
    /// 删除存储桶
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/7732
    pub async fn delete_bucket(&self) -> Response {
        let url_path = "/";
        let headers = self.get_headers_with_auth("delete", url_path, None, None, None);
        
        let resp = Request::delete(&self.get_full_url_from_path(url_path), None, Some(&headers), None, None).await;
        
        self.make_response(resp)
    }
}
