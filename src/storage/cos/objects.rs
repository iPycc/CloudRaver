//! COS对象操作模块
//! 提供文件上传、下载、删除等核心功能

use crate::storage::cos::acl::AclHeader;
use crate::storage::cos::client::Client;
use crate::storage::cos::request::{
    CompleteMultipartUpload, ErrNo, InitiateMultipartUploadResult, Part, Request, Response,
};
use reqwest::header::{HeaderName, HeaderValue, CONTENT_LENGTH, CONTENT_TYPE, RANGE};
use reqwest::Body;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use tokio::fs;
use tokio::io::AsyncReadExt;

// 最小上传分片大小 1MB
const PART_MIN_SIZE: u64 = 1024 * 1024;

// 最大上传分片大小 1GB
const PART_MAX_SIZE: u64 = 1024 * 1024 * 1024;

/// 存储类型
/// 参考文档: https://cloud.tencent.com/document/product/436/33417
#[derive(Debug, Clone)]
pub enum StorageClassEnum {
    /// 多AZ标准存储
    MazStandard,
    /// 多AZ低频存储
    MazStandardIa,
    /// 智能分层存储
    IntelligentTiering,
    /// 多AZ智能分层存储
    MazIntelligentTiering,
    /// 标准存储IA
    StandardIa,
    /// 归档存储
    Archive,
    /// 深度归档存储
    DeepArchive,
    /// 标准存储
    STANDARD,
}

impl From<StorageClassEnum> for String {
    fn from(value: StorageClassEnum) -> Self {
        match value {
            StorageClassEnum::Archive => String::from("ARCHIVE"),
            StorageClassEnum::STANDARD => String::from("STANDARD"),
            StorageClassEnum::StandardIa => String::from("STANDARD_IA"),
            StorageClassEnum::MazStandard => String::from("MAZ_STANDARD"),
            StorageClassEnum::DeepArchive => String::from("DEEP_ARCHIVE"),
            StorageClassEnum::MazStandardIa => String::from("MAZ_STANDARD_IA"),
            StorageClassEnum::IntelligentTiering => String::from("INTELLIGENT_TIERING"),
            StorageClassEnum::MazIntelligentTiering => String::from("MAZ_INTELLIGENT_TIERING"),
        }
    }
}


impl Client {
    /// 上传二进制数据
    /// 
    /// # 参数
    /// - file: 文件数据
    /// - key: 上传文件的key
    /// - content_type: 文件类型
    /// - acl_header: 访问控制
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/7749
    pub async fn put_object_binary<T: Into<Body> + Send>(
        &self,
        file: T,
        key: &str,
        content_type: Option<mime::Mime>,
        acl_header: Option<AclHeader>,
    ) -> Response {
        let body: Body = file.into();
        let bytes = body.as_bytes();
        if bytes.is_none() {
            return Response::new(ErrNo::IO, "不是内存对象".to_owned(), Default::default());
        }
        let file_size = bytes.unwrap().len();
        
        let mut headers = self.get_common_headers();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(
                content_type
                    .unwrap_or(mime::APPLICATION_OCTET_STREAM)
                    .as_ref(),
            )
            .unwrap(),
        );
        headers.insert(CONTENT_LENGTH, HeaderValue::from(file_size));
        
        let url_path = self.get_path_from_object_key(key);
        headers = self.get_headers_with_auth("put", url_path.as_str(), acl_header, Some(headers), None);
        
        let resp = Request::put(
            self.get_full_url_from_path(url_path.as_str()).as_str(),
            None,
            Some(&headers),
            None,
            None,
            Some(body),
        )
        .await;
        
        self.make_response(resp)
    }

    /// 上传本地文件
    /// 
    /// # 参数
    /// - file_path: 文件路径
    /// - key: 上传文件的key
    /// - content_type: 文件类型
    /// - acl_header: 访问控制
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/7749
    pub async fn put_object(
        &self,
        file_path: &PathBuf,
        key: &str,
        content_type: Option<mime::Mime>,
        acl_header: Option<AclHeader>,
    ) -> Response {
        let buf = match tokio::fs::read(file_path).await {
            Ok(file) => file,
            Err(e) => {
                return Response::new(
                    ErrNo::IO,
                    format!("读取文件失败: {:?}, {}", file_path, e),
                    Default::default(),
                )
            }
        };
        self.put_object_binary(buf, key, content_type, acl_header).await
    }

    /// 上传大文件（分片上传）
    /// 
    /// # 参数
    /// - file_path: 文件路径
    /// - key: 上传文件的key
    /// - content_type: 文件类型
    /// - storage_class: 存储类型
    /// - acl_header: 访问控制
    /// - part_size: 分片大小（字节），默认50MB
    /// - max_threads: 最大线程数，默认20
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/7749
    pub async fn put_big_object(
        self,
        file_path: &PathBuf,
        key: &str,
        content_type: Option<mime::Mime>,
        storage_class: Option<StorageClassEnum>,
        acl_header: Option<AclHeader>,
        part_size: Option<u64>,
        max_threads: Option<u64>,
    ) -> Response {
        let part_size = part_size.unwrap_or(PART_MAX_SIZE / 10 / 2);
        assert!((PART_MIN_SIZE..PART_MAX_SIZE).contains(&part_size));
        assert!(max_threads.unwrap_or(20) <= 1000);
        
        let mut file = match tokio::fs::File::open(file_path).await {
            Ok(file) => file,
            Err(e) => {
                return Response::new(
                    ErrNo::IO,
                    format!("打开文件失败: {:?}, {}", file_path, e),
                    Default::default(),
                )
            }
        };
        
        let file_size = match file.metadata().await {
            Ok(meta) => meta.len(),
            Err(e) => {
                return Response::new(
                    ErrNo::IO,
                    format!("获取文件大小失败: {:?}, {}", file_path, e),
                    Default::default(),
                )
            }
        };
        
        let mut part_number = 1;
        let mut etag_map = HashMap::new();
        
        // 初始化分片上传
        let upload_id_response = self
            .put_object_get_upload_id(key, content_type.clone(), storage_class, acl_header.clone())
            .await;
        
        if upload_id_response.error_no != ErrNo::SUCCESS {
            return upload_id_response;
        }
        
        let upload_id = String::from_utf8_lossy(&upload_id_response.result[..]).to_string();
        let max_threads = max_threads.unwrap_or(20);
        let mut tasks = Vec::new();
        let mut upload_bytes = 0;
        let mut part_number1 = 1;
        
        loop {
            if upload_bytes >= file_size {
                break;
            }
            
            let mut part_size1 = part_size;
            let last_bytes = file_size - upload_bytes;
            
            // 倒数第二次上传后剩余小于1M，附加到倒数第二次上传
            if last_bytes < part_size + PART_MIN_SIZE && last_bytes < PART_MAX_SIZE {
                part_size1 = last_bytes;
            }
            
            let mut body: Vec<u8> = vec![0; part_size1 as usize];
            if let Err(e) = file.read_exact(&mut body).await {
                self.abort_object_part(key, &upload_id).await;
                return Response::new(
                    ErrNo::IO,
                    format!("读取文件失败: {:?}, {}", file_path, e),
                    Default::default(),
                );
            }
            
            upload_bytes += part_size1;
            
            if tasks.len() < max_threads as usize {
                let key = key.to_string();
                let upload_id = upload_id.clone();
                let this = self.clone();
                let acl_header = acl_header.clone();
                let content_type = content_type.clone();
                
                let handle = tokio::spawn(async move {
                    let mut resp = Response::default();
                    let mut try_times = 10;
                    
                    while try_times > 0 {
                        try_times -= 1;
                        resp = this
                            .clone()
                            .put_object_part(
                                &key,
                                &upload_id,
                                part_number,
                                body.clone(),
                                part_size1,
                                content_type.clone(),
                                acl_header.clone(),
                            )
                            .await;
                        
                        if resp.error_no != ErrNo::SUCCESS {
                            if try_times == 0 {
                                this.abort_object_part(&key, upload_id.as_str()).await;
                            }
                        } else {
                            break;
                        }
                    }
                    resp
                });
                
                tasks.push(handle);
                part_number += 1;
            } else {
                for task in tasks {
                    let response = task.await.unwrap();
                    if response.error_no != ErrNo::SUCCESS {
                        return response;
                    }
                    etag_map.insert(part_number1, response.headers["etag"].clone());
                    part_number1 += 1;
                }
                tasks = Vec::new();
            }
        }
        
        if !tasks.is_empty() {
            for task in tasks {
                let response = task.await.unwrap();
                if response.error_no != ErrNo::SUCCESS {
                    return response;
                }
                etag_map.insert(part_number1, response.headers["etag"].clone());
                part_number1 += 1;
            }
        }
        
        // 完成分片上传
        let resp = self
            .put_object_complete_part(key, etag_map, upload_id.as_str())
            .await;
        
        if resp.error_no != ErrNo::SUCCESS {
            self.abort_object_part(key, upload_id.as_str()).await;
        }
        
        resp
    }

    /// 初始化分片上传
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/7746
    pub async fn put_object_get_upload_id(
        &self,
        key: &str,
        content_type: Option<mime::Mime>,
        storage_class: Option<StorageClassEnum>,
        acl_header: Option<AclHeader>,
    ) -> Response {
        let mut query = HashMap::new();
        query.insert("uploads".to_string(), String::new());
        
        let url_path = self.get_path_from_object_key(key);
        let mut headers = self.get_common_headers();
        
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(
                content_type
                    .unwrap_or(mime::APPLICATION_OCTET_STREAM)
                    .as_ref(),
            )
            .unwrap(),
        );
        
        headers.insert(
            HeaderName::from_str("x-cos-storage-class").unwrap(),
            HeaderValue::from_str(&String::from(
                storage_class.unwrap_or(StorageClassEnum::STANDARD),
            ))
            .unwrap(),
        );
        
        let headers = self.get_headers_with_auth(
            "post",
            url_path.as_str(),
            acl_header,
            Some(headers),
            Some(query.clone()),
        );
        
        let resp = Request::post(
            self.get_full_url_from_path(url_path.as_str()).as_str(),
            Some(&query),
            Some(&headers),
            None,
            None,
            None as Option<Body>,
        )
        .await;
        
        match resp {
            Ok(res) => {
                if res.error_no != ErrNo::SUCCESS {
                    return res;
                }
                match quick_xml::de::from_reader::<&[u8], InitiateMultipartUploadResult>(
                    &res.result[..],
                ) {
                    Ok(res) => Response::new(ErrNo::SUCCESS, String::new(), res.upload_id.into()),
                    Err(e) => Response::new(ErrNo::DECODE, e.to_string(), Default::default()),
                }
            }
            Err(e) => e,
        }
    }

    /// 上传分片
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/7750
    pub async fn put_object_part<T: Into<Body> + Send>(
        self,
        key: &str,
        upload_id: &str,
        part_number: u64,
        body: T,
        file_size: u64,
        content_type: Option<mime::Mime>,
        acl_header: Option<AclHeader>,
    ) -> Response {
        let mut headers = self.get_common_headers();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(
                content_type
                    .unwrap_or(mime::APPLICATION_OCTET_STREAM)
                    .as_ref(),
            )
            .unwrap(),
        );
        headers.insert(CONTENT_LENGTH, HeaderValue::from(file_size));
        
        let url_path = self.get_path_from_object_key(key);
        let mut query = HashMap::new();
        query.insert("partNumber".to_string(), part_number.to_string());
        query.insert("uploadId".to_string(), upload_id.to_string());
        
        headers = self.get_headers_with_auth(
            "put",
            url_path.as_str(),
            acl_header,
            Some(headers),
            Some(query.clone()),
        );
        
        let body: Body = body.into();
        let resp = Request::put(
            self.get_full_url_from_path(url_path.as_str()).as_str(),
            Some(&query),
            Some(&headers),
            None,
            None,
            Some(body),
        )
        .await;
        
        self.make_response(resp)
    }

    /// 完成分片上传
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/7742
    pub async fn put_object_complete_part(
        &self,
        key: &str,
        etag_map: HashMap<u64, String>,
        upload_id: &str,
    ) -> Response {
        let url_path = self.get_path_from_object_key(key);
        let mut query = HashMap::new();
        query.insert("uploadId".to_string(), upload_id.to_string());
        
        let mut headers = self.get_common_headers();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str("application/xml").unwrap(),
        );
        
        let headers = self.get_headers_with_auth(
            "post",
            url_path.as_str(),
            None,
            Some(headers),
            Some(query.clone()),
        );
        
        let mut parts = Vec::new();
        let mut etag_map_tuple: Vec<(&u64, &String)> = etag_map.iter().collect();
        etag_map_tuple.sort_by(|a, b| a.0.cmp(b.0));
        
        for (k, v) in etag_map_tuple {
            parts.push(Part {
                part_number: *k,
                etag: v.to_string(),
            })
        }
        
        let complete = CompleteMultipartUpload { part: parts };
        let serialized_str = match quick_xml::se::to_string(&complete) {
            Ok(s) => s,
            Err(e) => return Response::new(ErrNo::ENCODE, e.to_string(), Default::default()),
        };
        
        let resp = Request::post(
            self.get_full_url_from_path(url_path.as_str()).as_str(),
            Some(&query),
            Some(&headers),
            None,
            None,
            Some(serialized_str),
        )
        .await;
        
        self.make_response(resp)
    }

    /// 终止分片上传
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/7740
    pub async fn abort_object_part(&self, key: &str, upload_id: &str) -> Response {
        let url_path = self.get_path_from_object_key(key);
        let mut query = HashMap::new();
        query.insert("uploadId".to_string(), upload_id.to_string());
        
        let headers = self.get_headers_with_auth(
            "delete",
            url_path.as_str(),
            None,
            None,
            Some(query.clone()),
        );
        
        let resp = Request::delete(
            self.get_full_url_from_path(url_path.as_str()).as_str(),
            Some(&query),
            Some(&headers),
            None,
            None,
        )
        .await;
        
        self.make_response(resp)
    }

    /// 删除文件
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/7743
    pub async fn delete_object(&self, key: &str) -> Response {
        let url_path = self.get_path_from_object_key(key);
        let headers = self.get_headers_with_auth("delete", url_path.as_str(), None, None, None);
        
        let resp = Request::delete(
            self.get_full_url_from_path(url_path.as_str()).as_str(),
            None,
            Some(&headers),
            None,
            None,
        )
        .await;
        
        match resp {
            Ok(e) => e,
            Err(e) => e,
        }
    }

    /// 获取对象大小（字节）
    /// 返回-1表示文件不存在
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/7745
    pub async fn get_object_size(&self, key: &str) -> i64 {
        let url_path = self.get_path_from_object_key(key);
        let url = self.get_full_url_from_path(url_path.as_str());
        let headers = self.get_headers_with_auth("head", url_path.as_str(), None, None, None);
        
        let response = reqwest::Client::new()
            .head(url)
            .headers(headers)
            .send()
            .await
            .unwrap();
        
        if response.status().as_u16() == 404 {
            return -1;
        }
        
        let size = match response.headers().get("content-length") {
            Some(v) => v.to_str().unwrap_or("0").parse().unwrap(),
            None => 0,
        };
        
        size
    }

    /// 下载文件二进制数据（多线程）
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/7753
    pub async fn get_object_binary(&self, key: &str, threads: Option<u8>) -> Response {
        let size = self.get_object_size(key).await;
        if size < 0 {
            return Response::new(ErrNo::STATUS, String::from("object not exist"), Vec::new());
        }
        
        let size = size as usize;
        let mut threads = threads.unwrap_or(5) as usize;
        
        // 小于1KB只启用1个线程
        if size < 1024 {
            threads = 1;
        }
        
        let url_path = self.get_path_from_object_key(key);
        let headers = self.get_headers_with_auth("get", url_path.as_str(), None, None, None);
        let url = self.get_full_url_from_path(url_path.as_str());
        let part_size = size / threads;
        let mut handles = Vec::new();
        
        for i in 0..threads {
            let mut headers = headers.clone();
            let url = url.clone();
            
            let handle = tokio::spawn(async move {
                let range = if i == threads - 1 {
                    String::new()
                } else {
                    ((i + 1) * part_size - 1).to_string()
                };
                let range = format!("bytes={}-{}", i * part_size, range);
                headers.insert(RANGE, HeaderValue::from_str(&range).unwrap());
                Request::get(&url, None, Some(&headers)).await
            });
            
            handles.push(handle);
        }
        
        let mut data = Vec::new();
        for handle in handles {
            let response: Response = self.make_response(handle.await.unwrap());
            if response.error_no != ErrNo::SUCCESS {
                return response;
            }
            data.extend(response.result);
        }
        
        Response::data_success(data)
    }

    /// 下载文件到本地
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/7753
    pub async fn get_object(&self, key: &str, file_name: &str, threads: Option<u8>) -> Response {
        let size = self.get_object_size(key).await;
        if size < 0 {
            return Response::new(ErrNo::STATUS, String::from("object not exist"), Vec::new());
        }
        
        let file_path = PathBuf::from(file_name);
        if let Some(parent_file_path) = file_path.parent() {
            if !parent_file_path.exists() {
                fs::create_dir_all(parent_file_path).await.unwrap();
            }
        }
        
        let mut output_file = match fs::File::create(file_name).await {
            Ok(e) => e,
            Err(e) => {
                return Response::new(
                    ErrNo::OTHER,
                    format!("create file failed: {}", e),
                    Vec::new(),
                );
            }
        };
        
        let size = size as usize;
        let mut threads = threads.unwrap_or(5) as usize;
        
        if size < 1024 {
            threads = 1;
        }
        
        let url_path = self.get_path_from_object_key(key);
        let headers = self.get_headers_with_auth("get", url_path.as_str(), None, None, None);
        let url = self.get_full_url_from_path(url_path.as_str());
        let part_size = size / threads;
        let mut handles = Vec::new();
        
        for i in 0..threads {
            let mut headers = headers.clone();
            let url = url.clone();
            
            let handle = tokio::spawn(async move {
                let range = if i == threads - 1 {
                    String::new()
                } else {
                    ((i + 1) * part_size - 1).to_string()
                };
                let range = format!("bytes={}-{}", i * part_size, range);
                headers.insert(RANGE, HeaderValue::from_str(&range).unwrap());
                Request::get(&url, None, Some(&headers)).await
            });
            
            handles.push(handle);
        }
        
        use tokio::io::{AsyncWriteExt, self};
        use std::io::Cursor;
        
        for handle in handles {
            let response: Response = self.make_response(handle.await.unwrap());
            if response.error_no != ErrNo::SUCCESS {
                return response;
            }
            match io::copy(&mut Cursor::new(response.result), &mut output_file).await {
                Ok(_) => {
                    if part_size > (PART_MAX_SIZE / 5) as usize {
                        output_file.flush().await.unwrap();
                    }
                }
                Err(e) => {
                    return Response::new(
                        ErrNo::IO,
                        format!("save file failed: {}", e),
                        Vec::new(),
                    );
                }
            }
        }
        
        Response::default()
    }

    /// 分块获取文件二进制数据
    /// 
    /// 参考文档: https://cloud.tencent.com/document/product/436/7753
    pub async fn get_object_binary_range(
        &self,
        key: &str,
        range_start: usize,
        range_end: Option<usize>,
    ) -> Response {
        let url_path = self.get_path_from_object_key(key);
        let mut headers = self.get_headers_with_auth("get", url_path.as_str(), None, None, None);
        let url = self.get_full_url_from_path(url_path.as_str());
        
        let start = range_start.to_string();
        let end = match range_end {
            Some(e) => e.to_string(),
            None => String::new(),
        };
        let range = format!("bytes={}-{}", start, end);
        headers.insert(RANGE, HeaderValue::from_str(&range).unwrap());
        
        self.make_response(Request::get(&url, None, Some(&headers)).await)
    }
}
