//! 腾讯云COS存储模块
//! 
//! 本模块提供完整的腾讯云对象存储(COS)功能，包括：
//! - 签名认证
//! - 文件上传/下载
//! - 分片上传
//! - 预签名URL生成
//! - 文件夹操作
//! - 跨域配置
//! 
//! 所有代码均已移植到项目内部，不依赖外部SDK

pub mod acl;
pub mod client;
pub mod objects;
pub mod request;
pub mod signer;
pub mod bucket;
pub mod cors;
pub mod folder;
pub mod provider;

pub use acl::{AclHeader, BucketAcl, ObjectAcl};
pub use client::Client;
pub use request::{ErrNo, Response};
pub use objects::StorageClassEnum;
pub use signer::Signer;
pub use bucket::BucketOperations;
pub use cors::CorsConfig;
pub use folder::FolderOperations;
pub use provider::CosStorage;
