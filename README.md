# CloudRaver Backend

CloudRaver 是一个**私有云存储中枢**，它不只是一个简单的文件管理器，而是一个能够统一纳管你所有存储资源（本地硬盘、腾讯云 COS、以及未来更多云存储）的控制台。

简单来说，你可以把它理解为**你自己的百度网盘+阿里云盘聚合版**，但是数据完全掌握在你自己手里。

## 核心特性

*   **统一存储管理**：
    *   **本地存储**：直接利用服务器硬盘，适合存大文件、电影、备份。
    *   **腾讯云 COS 集成**：原生支持腾讯云对象存储，支持大文件分片上传、断点续传。你可以像操作本地文件一样操作云端文件。
    *   **存储策略（Storage Policy）**：你可以定义不同的存储策略，比如“图片存 COS，电影存本地”，或者“公开分享的文件走 COS，私密文档走本地”。

*   **安全与隐私**：
    *   **强鉴权系统**：基于 JWT + HttpOnly Cookie 的双 token 机制（Access + Refresh），支持多设备登录管理、强制下线。
    *   **文件分享**：生成带密码和有效期的分享链接，不再依赖第三方网盘。
    *   **私有部署**：所有元数据存放在本地 SQLite 数据库中，只有你能看到。

*   **高性能后端**：
    *   基于 **Rust (Axum + Tokio)** 构建，极低的内存占用，极高的并发处理能力。
    *   利用 `qcos` SDK 实现高效的 COS 操作。

## 快速开始

### 1. 环境准备

确保你已经安装了：
*   Rust (Cargo)
*   SQLite

### 2. 配置

在 `backend` 目录下创建 `config.toml` 或使用环境变量。

```toml
[server]
host = "0.0.0.0"
port = 1309

[database]
path = "data/cloudraver.db"

[jwt]
secret = "your-super-secret-key-change-it"
access_token_expire_minutes = 60
refresh_token_expire_days = 7

[storage]
local_path = "data/uploads"
```

### 3. 运行

```bash
# 开发模式
cargo run

# 生产构建
cargo build --release
./target/release/cloudraver
```

## 目录结构

*   `src/handlers`: 处理 HTTP 请求的接口逻辑（路由对应的 controller）。
*   `src/services`: 核心业务逻辑，比如用户认证、文件操作、存储策略调度。
*   `src/storage`: 存储适配器层，把本地文件系统和 COS 的差异抹平，对外提供统一接口。
*   `src/models`: 数据库表结构定义。

## 常见问题

*   **Q: 为什么上传大文件不卡？**
    *   A: 我们对大文件做了特殊处理，针对 COS 实现了并发分片上传，针对本地存储使用了流式写入，不会一次性把文件吃进内存。

*   **Q: 头像存在哪？**
    *   A: 头像文件存放在 `data/uploads/avatar/{user_id}/` 下，通过 `/api/v1/avatar/{key}` 短链接对外服务，方便前端缓存和调用。
