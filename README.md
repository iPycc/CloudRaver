# CloudRaver Backend

CloudRaver 是一个**私有云存储中枢**，它不只是一个简单的文件管理器，而是一个能够统一纳管你所有存储资源（本地硬盘、腾讯云 COS、以及未来更多云存储）的控制台。

简单来说，你可以把它理解为**你自己的百度网盘+阿里云盘聚合版**，但是数据完全掌握在你自己手里。

## 更新日志
### v1.11 Beta - 2026.1.22
- 添加 两步验证2FA

### v1.1 Beta - 2026.1.21
- 添加 通行证密钥Passkeys
- 修复 文件夹在中文路径编码映射错误

### v1.0.2 Beta - 2026.1.20
- 重构 设置页面
- 新增 会话管理、支持查看登录设备
- 添加 会话历史记录
- 优化 多标签页刷新逻辑

### v1.0.1 Beta - 2026.1.17
- 添加 回收站功能
- 文件恢复和批量操作

### v1.0.0 Beta - 2026.1.15
- 首次提交
- 文件管理界面
- 拖拽上传和预览功能
- JWT认证系统
- 下载文件
- 用户操作

## 快速开始

### 基本运行
```bash
cargo build --release
./target/release/cloudraver
```

### 单端口部署（嵌入前端）
```bash
# 先构建前端
cd ../frontend && pnpm run build

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

## License

MIT License © 2026 CloudRaver & iPycc
