//! COS签名模块
//! 实现腾讯云COS的签名算法
//! 参考文档: https://cloud.tencent.com/document/product/436/7778

use chrono::Utc;
use reqwest::header::HeaderMap;
use sha1::{Digest, Sha1};
use hmac::{Hmac, Mac};
use std::collections::HashMap;
use urlencoding::{decode, encode};

type HmacSha1 = Hmac<Sha1>;

/// COS签名器
pub struct Signer<'a> {
    method: &'a str,
    url_path: &'a str,
    headers: Option<HeaderMap>,
    query: Option<HashMap<String, String>>,
}

impl<'a> Signer<'a> {
    /// 创建新的签名器
    pub fn new(
        method: &'a str,
        url_path: &'a str,
        headers: Option<HeaderMap>,
        query: Option<HashMap<String, String>>,
    ) -> Self {
        Self {
            method,
            url_path,
            headers,
            query,
        }
    }

    /// 获取密钥时间
    fn get_key_time(&self, valid_seconds: u32) -> String {
        let start = Utc::now().timestamp();
        let end = start + valid_seconds as i64;
        format!("{};{}", start, end)
    }

    /// 生成签名密钥
    fn get_sign_key(&self, key_time: &str, secret_key: &str) -> String {
        let mut mac = HmacSha1::new_from_slice(secret_key.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(key_time.as_bytes());
        let result = mac.finalize();
        let code_bytes = result.into_bytes();
        
        code_bytes.iter()
            .map(|x| format!("{:02x}", x))
            .collect::<Vec<String>>()
            .join("")
    }

    /// URL编码数据
    fn encode_data(&self, data: HashMap<String, String>) -> HashMap<String, String> {
        let mut res = HashMap::new();
        for (k, v) in data.iter() {
            res.insert(encode(k).to_string().to_lowercase(), encode(v).to_string());
        }
        res
    }

    /// 获取URL参数列表
    fn get_url_param_list(&self) -> String {
        if let Some(query) = self.query.clone() {
            let mut keys: Vec<String> = Vec::new();
            let encoded_data = self.encode_data(query);
            for k in encoded_data.keys() {
                keys.push(k.to_string());
            }
            keys.sort();
            return keys.join(";");
        }
        String::new()
    }

    /// 获取HTTP参数
    fn get_http_parameters(&self) -> String {
        if let Some(query) = self.query.clone() {
            let mut keys: Vec<String> = Vec::new();
            let encoded_data = self.encode_data(query);
            for k in encoded_data.keys() {
                keys.push(k.to_string());
            }
            keys.sort();
            let mut res: Vec<String> = Vec::new();
            for key in keys {
                let v = encoded_data.get(&key).unwrap();
                res.push([key, v.to_string()].join("="));
            }
            return res.join("&");
        }
        String::new()
    }

    /// 将HeaderMap转换为HashMap
    fn header_map_to_hash_map(&self, headers: HeaderMap) -> HashMap<String, String> {
        let mut res = HashMap::new();
        for (k, v) in headers {
            res.insert(
                k.unwrap().to_string().to_lowercase(),
                v.to_str().unwrap().to_string(),
            );
        }
        res
    }

    /// 获取头部列表
    fn get_header_list(&self) -> String {
        if let Some(headers) = self.headers.clone() {
            let mut keys: Vec<String> = Vec::new();
            let encoded_data = self.encode_data(self.header_map_to_hash_map(headers));
            for k in encoded_data.keys() {
                keys.push(k.to_string());
            }
            keys.sort();
            return keys.join(";");
        }
        String::new()
    }

    /// 获取头部信息
    fn get_headers(&self) -> String {
        if let Some(headers) = self.headers.clone() {
            let mut keys: Vec<String> = Vec::new();
            let encoded_data = self.encode_data(self.header_map_to_hash_map(headers));
            for k in encoded_data.keys() {
                keys.push(k.to_string());
            }
            keys.sort();
            let mut res: Vec<String> = Vec::new();
            for key in keys {
                let v = encoded_data.get(&key).unwrap();
                res.push([key, v.to_string()].join("="));
            }
            return res.join("&");
        }
        String::new()
    }

    /// 获取HTTP字符串
    fn get_http_string(&self) -> String {
        let s = [
            self.method.to_string(),
            decode(self.url_path).unwrap().to_string(),
            self.get_http_parameters(),
            self.get_headers(),
        ];
        s.join("\n") + "\n"
    }

    /// 获取待签名字符串
    fn get_string_to_sign(&self, key_time: &'a str) -> String {
        let mut s = vec!["sha1".to_string(), key_time.to_string()];
        let http_string = self.get_http_string();
        let mut hasher = Sha1::new();
        hasher.update(&http_string);
        let result = hasher.finalize();
        let digest: Vec<String> = result
            .as_slice()
            .iter()
            .map(|x| format!("{:02x?}", x))
            .collect();
        s.push(digest.join(""));
        s.join("\n") + "\n"
    }

    /// 生成签名
    /// 
    /// # 参数
    /// - secret_key: 密钥
    /// - secret_id: 密钥ID
    /// - valid_seconds: 有效时间（秒）
    pub fn get_signature(&self, secret_key: &str, secret_id: &str, valid_seconds: u32) -> String {
        let key_time = self.get_key_time(valid_seconds);
        let string_to_sign = self.get_string_to_sign(&key_time);
        let sign_key = self.get_sign_key(&key_time, secret_key);
        let signature = self.get_sign_key(&string_to_sign, &sign_key);
        let header_list = self.get_header_list();
        let param_list = self.get_url_param_list();
        format!(
            "q-sign-algorithm=sha1&q-ak={}&q-sign-time={}&q-key-time={}&q-header-list={}&q-url-param-list={}&q-signature={}",
            secret_id, key_time, key_time, header_list, param_list, signature
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    use std::str::FromStr;

    #[test]
    fn test_get_url_param_list() {
        let mut query = HashMap::new();
        query.insert("a".to_string(), "a ".to_string());
        query.insert("B".to_string(), " b".to_string());
        let signer = Signer::new("", "", None, Some(query));
        let s = signer.get_url_param_list();
        assert_eq!(s, "a;b");
        let s = signer.get_http_parameters();
        assert_eq!(s, "a=a%20&b=%20b");
    }

    #[test]
    fn test_get_http_string() {
        let mut query = HashMap::new();
        query.insert("a".to_string(), "a ".to_string());
        query.insert("B".to_string(), " b".to_string());
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_str("h").unwrap(),
            HeaderValue::from_str("h").unwrap(),
        );
        let signer = Signer::new("get", "/path", Some(headers), Some(query));
        assert_eq!(
            signer.get_http_string(),
            "get\n/path\na=a%20&b=%20b\nh=h\n"
        );
    }
}
