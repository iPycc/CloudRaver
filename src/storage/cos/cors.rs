//! 跨域资源共享(CORS)配置模块
//! 提供COS跨域配置功能

use crate::storage::cos::client::Client;
use crate::storage::cos::request::{Request, Response};
use serde::{Deserialize, Serialize};

/// CORS规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsRule {
    /// 规则ID
    #[serde(rename = "ID")]
    pub id: String,
    
    /// 允许的HTTP方法
    #[serde(rename = "AllowedMethod")]
    pub allowed_methods: Vec<String>,
    
    /// 允许的来源
    #[serde(rename = "AllowedOrigin")]
    pub allowed_origins: Vec<String>,
    
    /// 允许的头部
    #[serde(rename = "AllowedHeader", skip_serializing_if = "Option::is_none")]
    pub allowed_headers: Option<Vec<String>>,
    
    /// 暴露的头部
    #[serde(rename = "ExposeHeader", skip_serializing_if = "Option::is_none")]
    pub expose_headers: Option<Vec<String>>,
    
    /// 预检请求的有效期（秒）
    #[serde(rename = "MaxAgeSeconds", skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<u32>,
}

/// CORS配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    /// CORS规则列表
    #[serde(rename = "CORSRule")]
    pub rules: Vec<CorsRule>,
}

impl CorsConfig {
    /// 创建新的CORS配置
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }
    
    /// 添加CORS规则
    pub fn add_rule(&mut self, rule: CorsRule) -> &mut Self {
        self.rules.push(rule);
        self
    }
    
    /// 创建默认的CORS配置（允许所有来源）
    pub fn default_permissive() -> Self {
        let rule = CorsRule {
            id: "default-cors-rule".to_string(),
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "HEAD".to_string(),
            ],
            allowed_origins: vec!["*".to_string()],
            allowed_headers: Some(vec!["*".to_string()]),
            expose_headers: Some(vec![
                "ETag".to_string(),
                "Content-Length".to_string(),
                "x-cos-request-id".to_string(),
            ]),
            max_age_seconds: Some(3600),
        };
        
        let mut config = Self::new();
        config.add_rule(rule);
        config
    }
    
    /// 创建用于Web应用的CORS配置
    pub fn for_web_app(allowed_origins: Vec<String>) -> Self {
        let rule = CorsRule {
            id: "web-app-cors-rule".to_string(),
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
            ],
            allowed_origins,
            allowed_headers: Some(vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
                "x-cos-*".to_string(),
            ]),
            expose_headers: Some(vec![
                "ETag".to_string(),
                "Content-Length".to_string(),
            ]),
            max_age_seconds: Some(1800),
        };
        
        let mut config = Self::new();
        config.add_rule(rule);
        config
    }
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// 设置存储桶的CORS配置
    /// 
    /// # 参数
    /// - config: CORS配置
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/8279
    pub async fn put_bucket_cors(&self, config: &CorsConfig) -> Response {
        let url_path = "/?cors";
        
        // 序列化CORS配置为XML
        let xml_body = match quick_xml::se::to_string(config) {
            Ok(xml) => {
                // 添加XML声明和根元素包装
                format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?><CORSConfiguration>{}</CORSConfiguration>"#,
                    xml.replace("<CorsConfig>", "").replace("</CorsConfig>", "")
                )
            }
            Err(e) => {
                return Response::new(
                    crate::storage::cos::request::ErrNo::ENCODE,
                    format!("Failed to serialize CORS config: {}", e),
                    Vec::new(),
                );
            }
        };
        
        let mut headers = self.get_common_headers();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/xml"),
        );
        
        let headers = self.get_headers_with_auth("put", url_path, None, Some(headers), None);
        
        let resp = Request::put(
            &self.get_full_url_from_path(url_path),
            None,
            Some(&headers),
            None,
            None,
            Some(xml_body),
        )
        .await;
        
        self.make_response(resp)
    }
    
    /// 获取存储桶的CORS配置
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/8274
    pub async fn get_bucket_cors(&self) -> Response {
        let url_path = "/?cors";
        let headers = self.get_headers_with_auth("get", url_path, None, None, None);
        
        let resp = Request::get(&self.get_full_url_from_path(url_path), None, Some(&headers)).await;
        
        self.make_response(resp)
    }
    
    /// 删除存储桶的CORS配置
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/8283
    pub async fn delete_bucket_cors(&self) -> Response {
        let url_path = "/?cors";
        let headers = self.get_headers_with_auth("delete", url_path, None, None, None);
        
        let resp = Request::delete(&self.get_full_url_from_path(url_path), None, Some(&headers), None, None).await;
        
        self.make_response(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cors_config_creation() {
        let config = CorsConfig::default_permissive();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].id, "default-cors-rule");
    }
    
    #[test]
    fn test_web_app_cors_config() {
        let origins = vec!["https://example.com".to_string()];
        let config = CorsConfig::for_web_app(origins);
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].allowed_origins[0], "https://example.com");
    }
}
