# CloudRaver Backend

CloudRaver 是一个**私有云存储中枢**，它不只是一个简单的文件管理器，而是一个能够统一纳管你所有存储资源（本地硬盘、腾讯云 COS、以及未来更多云存储）的控制台。

简单来说，你可以把它理解为**你自己的百度网盘+阿里云盘聚合版**，但是数据完全掌握在你自己手里。

## 更新日志

### v1.0.2 Beta
- 新增前端静态文件嵌入功能，单端口部署
- 修复iOS Chrome设备识别问题
- 会话支持即时失效，无需手动刷新
- 新增IP地址显示和LAN网络检测

### v1.0.1 Beta  
- 新增回收站功能，支持文件恢复
- 支持批量操作和永久删除

### v1.0.0 Beta
- 支持本地存储和腾讯云COS
- JWT双Token认证系统
- 文件分享功能

## 快速开始

### 基本运行
```bash
cargo build --release
./target/release/cloudraver
```

### 单端口部署（嵌入前端）
```bash
# 先构建前端
cd ../frontend && npm run build

# 构建带嵌入前端的版本
cd ../backend
cargo build --release --features embed-frontend

# 运行
./target/release/cloudraver
```

访问 http://localhost:1309

### Windows编译Linux版本
```bash
# 安装Linux目标
rustup target add x86_64-unknown-linux-gnu

# 编译Linux版本
cargo build --release --target x86_64-unknown-linux-gnu --features embed-frontend
```

## 配置

创建 `config.toml`：
```toml
[server]
host = "0.0.0.0"
port = 1309

[database]
path = "data/cloudraver.db"

[jwt]
secret = "your-secret-key"
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

## License

MIT License © 2026 CloudRaver
