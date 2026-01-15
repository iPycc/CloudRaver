//! HTTP请求封装模块
//! 提供统一的HTTP请求接口

use reqwest::header::HeaderMap;
use reqwest::Body;
use serde_json::value::Value;
use std::collections::HashMap;
use std::convert::From;
use std::fmt::Display;
use std::time::Duration;

/// 错误码
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ErrNo {
    /// 操作成功
    SUCCESS = 0,
    /// 其他错误
    OTHER = 10000,
    /// HTTP状态码相关错误
    STATUS = 10001,
    /// 解码相关错误
    DECODE = 10002,
    /// 连接相关错误
    CONNECT = 10003,
    /// 编码相关错误
    ENCODE = 20001,
    /// IO错误
    IO = 20002,
}

impl Display for ErrNo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#?}", self)
    }
}

/// HTTP请求返回类型
#[derive(Debug, Clone)]
pub struct Response {
    /// 错误码
    pub error_no: ErrNo,
    /// 错误信息
    pub error_message: String,
    /// 接口返回信息
    pub result: Vec<u8>,
    /// 接口返回的headers
    pub headers: HashMap<String, String>,
}

impl From<reqwest::Error> for Response {
    fn from(value: reqwest::Error) -> Self {
        let mut e = ErrNo::OTHER;
        if value.is_status() {
            e = ErrNo::STATUS;
        } else if value.is_connect() {
            e = ErrNo::CONNECT;
        } else if value.is_decode() {
            e = ErrNo::DECODE;
        }
        Response {
            error_no: e,
            error_message: value.to_string(),
            result: Vec::new(),
            headers: HashMap::new(),
        }
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"{{"error_no": "{}","error_message": "{}","result": "{}"}}"#,
            self.error_no as i32,
            self.error_message,
            String::from_utf8_lossy(&self.result)
        )
    }
}

impl Default for Response {
    fn default() -> Self {
        Self {
            error_no: ErrNo::SUCCESS,
            error_message: Default::default(),
            result: Default::default(),
            headers: Default::default(),
        }
    }
}

impl Response {
    pub fn new(error_no: ErrNo, error_message: String, result: Vec<u8>) -> Self {
        Self {
            error_no,
            error_message,
            result,
            headers: HashMap::new(),
        }
    }

    pub fn data_success(result: Vec<u8>) -> Self {
        Self {
            error_no: ErrNo::SUCCESS,
            error_message: Default::default(),
            result,
            headers: Default::default(),
        }
    }
}

/// 请求方法
#[derive(Debug, Eq, PartialEq)]
pub enum Method {
    Get,
    Post,
    Delete,
    Put,
    Head,
}

type Data = Value;

/// HTTP请求封装
pub struct Request;

impl Request {
    /// 从传入的headers参数生成reqwest::ClientBuilder
    fn get_builder_with_headers(headers: Option<&HeaderMap>) -> reqwest::ClientBuilder {
        let mut builder = reqwest::ClientBuilder::new();
        if let Some(headers) = headers {
            builder = builder.default_headers(headers.clone());
        }
        builder
    }

    /// 发送HEAD请求
    pub async fn head(
        url: &str,
        query: Option<&HashMap<String, String>>,
        headers: Option<&HeaderMap>,
    ) -> Result<Response, Response> {
        Request::do_req(
            Method::Head,
            url,
            query,
            headers,
            None,
            None,
            None as Option<Body>,
        )
        .await
    }

    /// 发送GET请求
    pub async fn get(
        url: &str,
        query: Option<&HashMap<String, String>>,
        headers: Option<&HeaderMap>,
    ) -> Result<Response, Response> {
        Request::do_req(
            Method::Get,
            url,
            query,
            headers,
            None,
            None,
            None as Option<Body>,
        )
        .await
    }

    /// 发送POST请求
    pub async fn post<T: Into<Body>>(
        url: &str,
        query: Option<&HashMap<String, String>>,
        headers: Option<&HeaderMap>,
        form: Option<&HashMap<&str, Data>>,
        json: Option<&HashMap<&str, Data>>,
        body_data: Option<T>,
    ) -> Result<Response, Response> {
        Request::do_req(Method::Post, url, query, headers, form, json, body_data).await
    }

    /// 发送PUT请求
    pub async fn put<T: Into<Body>>(
        url: &str,
        query: Option<&HashMap<String, String>>,
        headers: Option<&HeaderMap>,
        form: Option<&HashMap<&str, Data>>,
        json: Option<&HashMap<&str, Data>>,
        body_data: Option<T>,
    ) -> Result<Response, Response> {
        Request::do_req(Method::Put, url, query, headers, form, json, body_data).await
    }

    /// 发送DELETE请求
    pub async fn delete(
        url: &str,
        query: Option<&HashMap<String, String>>,
        headers: Option<&HeaderMap>,
        form: Option<&HashMap<&str, Data>>,
        json: Option<&HashMap<&str, Data>>,
    ) -> Result<Response, Response> {
        Request::do_req(
            Method::Delete,
            url,
            query,
            headers,
            form,
            json,
            None as Option<Body>,
        )
        .await
    }

    /// 执行HTTP请求
    async fn do_req<T: Into<Body>>(
        method: Method,
        url: &str,
        query: Option<&HashMap<String, String>>,
        headers: Option<&HeaderMap>,
        form: Option<&HashMap<&str, Data>>,
        json: Option<&HashMap<&str, Data>>,
        body_data: Option<T>,
    ) -> Result<Response, Response> {
        let builder = Self::get_builder_with_headers(headers);
        let client = builder.timeout(Duration::from_secs(24 * 3600)).build()?;
        
        let mut req = match method {
            Method::Get => client.get(url),
            Method::Delete => client.delete(url),
            Method::Post => client.post(url),
            Method::Put => client.put(url),
            Method::Head => client.head(url),
        };

        if let Some(v) = query {
            req = req.query(v);
        }
        if let Some(v) = form {
            req = req.form(v);
        }
        if let Some(v) = json {
            req = req.json(v);
        }
        if let Some(v) = body_data {
            req = req.body(v.into());
        }

        let resp = req.send().await?;
        let status_code = resp.status();
        let mut error_no = ErrNo::SUCCESS;
        let mut message = String::new();
        
        if status_code.is_client_error() || status_code.is_server_error() {
            error_no = ErrNo::STATUS;
            message = status_code.to_string();
        }

        let mut headers = HashMap::new();
        for (k, v) in resp.headers() {
            headers.insert(k.to_string(), String::from_utf8_lossy(v.as_bytes()).into());
        }

        Ok(Response {
            error_no,
            error_message: message,
            result: resp.bytes().await?.to_vec(),
            headers,
        })
    }
}

/// 分片上传初始化结果
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct InitiateMultipartUploadResult {
    #[serde(rename(deserialize = "Bucket"))]
    pub bucket: String,
    #[serde(rename(deserialize = "Key"))]
    pub key: String,
    #[serde(rename(deserialize = "UploadId"))]
    pub upload_id: String,
}

/// 分片信息
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq, Clone)]
pub struct Part {
    #[serde(rename = "PartNumber")]
    pub part_number: u64,
    #[serde(rename = "ETag")]
    pub etag: String,
}

/// 完成分片上传请求
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CompleteMultipartUpload {
    #[serde(rename(serialize = "Part"))]
    pub part: Vec<Part>,
}
