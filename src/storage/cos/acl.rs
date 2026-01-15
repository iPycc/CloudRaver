//! 访问控制列表（ACL）模块
//! 参考文档: https://cloud.tencent.com/document/product/436/30752

use std::collections::HashMap;

/// 对象的预设ACL
#[derive(Debug, PartialEq, Clone)]
pub enum ObjectAcl {
    /// 空描述，根据各级目录的显式设置及存储桶的设置来确定是否允许请求（默认）
    Default,
    /// 创建者（主账号）具备FULL_CONTROL权限，其他人没有权限
    Private,
    /// 创建者具备FULL_CONTROL权限，匿名用户组具备READ权限
    PublicRead,
    /// 创建者具备FULL_CONTROL权限，认证用户组具备READ权限
    AuthenticatedRead,
    /// 创建者具备FULL_CONTROL权限，存储桶拥有者具备READ权限
    BucketOwnerRead,
    /// 创建者和存储桶拥有者都具备FULL_CONTROL权限
    BucketOwnerFullControl,
}

impl From<ObjectAcl> for String {
    fn from(val: ObjectAcl) -> Self {
        match val {
            ObjectAcl::Default => String::from("default"),
            ObjectAcl::Private => String::from("private"),
            ObjectAcl::PublicRead => String::from("public-read"),
            ObjectAcl::BucketOwnerRead => String::from("bucket-owner-read"),
            ObjectAcl::AuthenticatedRead => String::from("authenticated-read"),
            ObjectAcl::BucketOwnerFullControl => String::from("bucket-owner-full-control"),
        }
    }
}

/// 存储桶的预设ACL
#[derive(Debug, PartialEq, Clone)]
pub enum BucketAcl {
    /// 创建者（主账号）具备FULL_CONTROL权限，其他人没有权限（默认）
    Private,
    /// 创建者具备FULL_CONTROL权限，匿名用户组具备READ权限
    PublicRead,
    /// 创建者和匿名用户组都具备FULL_CONTROL权限，通常不建议授予此权限
    PublicReadWrite,
    /// 创建者具备FULL_CONTROL权限，认证用户组具备READ权限
    AuthenticatedRead,
}

impl From<BucketAcl> for String {
    fn from(value: BucketAcl) -> Self {
        match value {
            BucketAcl::Private => String::from("private"),
            BucketAcl::PublicRead => String::from("public-read"),
            BucketAcl::PublicReadWrite => String::from("public-read-write"),
            BucketAcl::AuthenticatedRead => String::from("authenticated-read"),
        }
    }
}

/// ACL头部信息
#[derive(Debug, Clone)]
pub struct AclHeader {
    headers: HashMap<String, String>,
}

impl Default for AclHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl AclHeader {
    /// 创建新的ACL头部
    pub fn new() -> Self {
        AclHeader {
            headers: HashMap::new(),
        }
    }

    /// 获取头部信息
    pub fn get_headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// 设置对象的ACL
    pub fn insert_object_x_cos_acl(&mut self, x_cos_acl: ObjectAcl) -> &mut Self {
        self.headers
            .insert("x-cos-acl".to_string(), x_cos_acl.into());
        self
    }

    /// 赋予被授权者读取对象(桶)的权限
    /// 格式: id="[OwnerUin]"，例如 id="100000000001"
    pub fn insert_x_cos_grant_read(&mut self, x_cos_grant_read: String) -> &mut Self {
        self.headers
            .insert("x-cos-grant-read".to_string(), x_cos_grant_read);
        self
    }

    /// 赋予被授权者读取对象(桶)的访问控制列表（ACL）的权限
    pub fn insert_x_cos_grant_read_acp(&mut self, x_cos_grant_read_acp: String) -> &mut Self {
        self.headers
            .insert("x-cos-grant-read-acp".to_string(), x_cos_grant_read_acp);
        self
    }

    /// 赋予被授权者写入对象(桶)的访问控制列表（ACL）的权限
    pub fn insert_x_cos_grant_write_acp(&mut self, x_cos_grant_write_acp: String) -> &mut Self {
        self.headers
            .insert("x-cos-grant-write-acp".to_string(), x_cos_grant_write_acp);
        self
    }

    /// 赋予被授权者操作对象(桶)的所有权限
    pub fn insert_x_cos_grant_full_control(
        &mut self,
        x_cos_grant_full_control: String,
    ) -> &mut Self {
        self.headers.insert(
            "x-cos-grant-full-control".to_string(),
            x_cos_grant_full_control,
        );
        self
    }

    /// 设置存储桶的ACL
    pub fn insert_bucket_x_cos_acl(&mut self, x_cos_acl: BucketAcl) -> &mut Self {
        self.headers
            .insert("x-cos-acl".to_string(), x_cos_acl.into());
        self
    }

    /// 赋予被授权者写入存储桶的权限
    pub fn insert_bucket_x_cos_grant_write(&mut self, x_cos_grant_write: String) -> &mut Self {
        self.headers
            .insert("x-cos-grant-write".to_string(), x_cos_grant_write);
        self
    }
}
