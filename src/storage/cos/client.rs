//! COS客户端模块
//! 提供COS操作的核心客户端功能

use crate::storage::cos::acl::AclHeader;
use crate::storage::cos::request::Response;
use crate::storage::cos::signer::Signer;
use chrono::Utc;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, DATE, HOST};
use std::collections::HashMap;
use std::str::FromStr;

/// COS客户端
#[derive(Debug, Clone)]
pub struct Client {
    secret_id: String,
    secret_key: String,
    bucket: String,
    region: String,
}

impl Client {
    /// 创建新的COS客户端
    /// 
    /// # 参数
    /// - secret_id: 腾讯云密钥ID
    /// - secret_key: 腾讯云密钥Key
    /// - bucket: 存储桶名称
    /// - region: 地域，如ap-guangzhou
    pub fn new(
        secret_id: impl Into<String>,
        secret_key: impl Into<String>,
        bucket: impl Into<String>,
        region: impl Into<String>,
    ) -> Self {
        Self {
            secret_id: secret_id.into(),
            secret_key: secret_key.into(),
            bucket: bucket.into(),
            region: region.into(),
        }
    }

    /// 获取COS主机地址
    pub fn get_host(&self) -> String {
        format!("{}.cos.{}.myqcloud.com", self.bucket, self.region)
    }

    /// 获取密钥
    pub fn get_secret_key(&self) -> &str {
        &self.secret_key
    }

    /// 获取密钥ID
    pub fn get_secret_id(&self) -> &str {
        &self.secret_id
    }

    /// 生成通用的请求头部，包含Host和Date
    pub fn get_common_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_str(&self.get_host()).unwrap());
        let now_str = Utc::now().format("%a, %d %b %Y %T GMT").to_string();
        headers.insert(DATE, HeaderValue::from_str(&now_str).unwrap());
        headers
    }

    /// 从路径生成完整URL
    pub fn get_full_url_from_path(&self, path: &str) -> String {
        format!("https://{}{}", self.get_host(), path)
    }

    /// 从对象键生成路径
    pub fn get_path_from_object_key(&self, key: &str) -> String {
        let mut url_path = key.to_string();
        if !url_path.starts_with('/') {
            url_path = format!("/{}", url_path);
        }
        url_path
    }

    /// 生成查询bucket列表的host
    pub fn get_host_for_bucket_query(&self) -> String {
        if self.region.is_empty() {
            return "service.cos.myqcloud.com".to_string();
        }
        format!("cos.{}.myqcloud.com", self.region)
    }

    /// 返回带有Authorization的headers
    /// 
    /// # 参数
    /// - method: HTTP方法
    /// - url_path: URL路径
    /// - acl_header: ACL头部（可选）
    /// - origin_headers: 原始头部（可选）
    /// - query: 查询参数（可选）
    pub fn get_headers_with_auth(
        &self,
        method: &str,
        url_path: &str,
        acl_header: Option<AclHeader>,
        origin_headers: Option<HeaderMap>,
        query: Option<HashMap<String, String>>,
    ) -> HeaderMap {
        let mut headers = match origin_headers {
            Some(header) => header,
            None => self.get_common_headers(),
        };

        // 添加ACL头部
        if let Some(acl_header) = acl_header {
            for (k, v) in acl_header.get_headers() {
                headers.insert(
                    HeaderName::from_str(k).unwrap(),
                    HeaderValue::from_str(v).unwrap(),
                );
            }
        }

        // 生成签名
        let signature = Signer::new(method, url_path, Some(headers.clone()), query).get_signature(
            self.get_secret_key(),
            self.get_secret_id(),
            7200, // 2小时有效期
        );

        headers.insert(AUTHORIZATION, HeaderValue::from_str(&signature).unwrap());
        headers
    }

    /// 处理响应
    pub fn make_response(&self, resp: Result<Response, Response>) -> Response {
        resp.unwrap_or_else(|x| x)
    }

    /// 获取预签名下载URL
    /// 
    /// # 参数
    /// - object_key: 对象键
    /// - expire: 过期时间（秒）
    /// 
    /// # 返回
    /// 带签名的完整URL
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/35153
    pub fn get_presigned_download_url(&self, object_key: &str, expire: u32) -> String {
        let url_path = self.get_path_from_object_key(object_key);
        let full_url = self.get_full_url_from_path(url_path.as_str());
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_str(&self.get_host()).unwrap());
        
        let signature = Signer::new("get", &url_path, Some(headers), None).get_signature(
            self.get_secret_key(),
            self.get_secret_id(),
            expire,
        );
        
        format!("{}?{}", full_url, signature)
    }

    /// 获取web直传签名
    /// 
    /// # 参数
    /// - object_key: 对象键
    /// - acl_header: ACL头部（可选）
    /// - origin_headers: 原始头部（可选）
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/9067
    pub fn get_upload_signature(
        &self,
        object_key: &str,
        acl_header: Option<AclHeader>,
        origin_headers: Option<HeaderMap>,
    ) -> String {
        // H5默认只传host请求头
        let headers = if origin_headers.is_none() {
            let mut headers = HeaderMap::new();
            headers.insert(HOST, HeaderValue::from_str(&self.get_host()).unwrap());
            Some(headers)
        } else {
            origin_headers
        };

        let url_path = self.get_path_from_object_key(object_key);
        let header = self.get_headers_with_auth("put", &url_path, acl_header, headers, None);
        
        header
            .get(AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = Client::new("test_id", "test_key", "test-bucket", "ap-guangzhou");
        assert_eq!(client.get_host(), "test-bucket.cos.ap-guangzhou.myqcloud.com");
    }

    #[test]
    fn test_path_generation() {
        let client = Client::new("test_id", "test_key", "test-bucket", "ap-guangzhou");
        assert_eq!(client.get_path_from_object_key("test.txt"), "/test.txt");
        assert_eq!(client.get_path_from_object_key("/test.txt"), "/test.txt");
    }
}
