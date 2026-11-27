# 安全架构与策略说明（SECURITY.md）

> 🌐 **Language:** 简体中文（当前） · [English](SECURITY_EN.md)

本文档说明 Cosmos MCP `v1.2.1` 的身份鉴权机制、跨端点受众隔离、本地状态与凭据存储边界、文件快照恢复机制以及按需降级与容器沙盒隔离方式。

## 一、OAuth 2.1 鉴权与 RFC 8707 跨端点受众隔离

### 1. 网页连接器 OAuth 2.1 + PKCE 与三层授权校验机制
- 公网或远程连接默认启用 OAuth 2.1 授权码流程，强制校验 `PKCE S256`（`code_challenge_method=S256`）与回调域名白名单（仅放行受信任的官方 AI 平台回调域名与本机回环地址）。
- 授权同意页（`/consent`）采用三层防钓鱼与分级在场校验机制：
  1. **同机浏览器顶层 `302` 回环免密一键授权**：同一台电脑浏览器点击「本机一键允许连接（免输口令）」时，经 `POST /consent` -> `GET http://127.0.0.1:<port>/oauth/local-bridge` -> `GET /consent/complete` 完成校验，同时核验浏览器绑定的 `HttpOnly` 会话 Cookie、`Origin` 同源头以及服务端 HMAC-SHA256 签名的单次 30 秒消费票据，零浏览器权限弹窗且阻断代理伪造回环；
  2. **4 位防钓鱼核对码**：`/consent` 页面显著展示实时 **4 位防伪核对码**（仅用于肉眼对比，无需输入），与本机 `Cosmos Studio` 首页及 `cosmos-mcp status` 同步，防止跨会话钓鱼链接诱导授权；
  3. **异地、手机或云端受控浏览器 6 位动态配对码（含 20 位备用口令）**：手机端、异地电脑浏览器、网页版 ChatGPT `Work` 云端受控浏览器接管授权页或本地代理接管 `127.0.0.1` 回环请求时，支持输入本机 `Cosmos Studio` 面板实时生成的 **6 位纯数字动态配对码**或 20 位固定备用连接口令完成授权。
- 本机管理口令使用 `hashlib.scrypt`（`N=16384, r=8, p=1`）加随机 16 字节盐值保存在 `<状态目录>/secrets/auth.json`，OAuth 访问令牌与刷新令牌在 SQLite 中以 SHA-256 哈希键存储，并对连续口令与配对码错误实施退避限流。

### 2. 遵循 [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 的 `/mcp` 与 `/mcp/readonly` 端点隔离
- 服务端同时挂载主端点 `/mcp` 与纯只读端点 `/mcp/readonly`，并分别发布独立的受保护资源元数据（`/.well-known/oauth-protected-resource/mcp` 与 `/.well-known/oauth-protected-resource/mcp/readonly`）。
- 依据 [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707)（OAuth 2.0 Resource Indicators），授权请求携带并核验目标 `resource` URI，签发令牌绑定对应的受众资源，跨端点混用令牌直接返回 `HTTP 403`。
- `/mcp/readonly` 在工具枚举与调用两层固定只读权限，仅暴露只读工具（`get_status`、`find_files`、`search_code`、`code_intel` 只读子动作、`read_file`、`batch_probe`、`web_research`、`skill_hub`）及混合工具只读查询动作（如 `manage_files(action="list")`、`bg_command(action="status"|"list")`、`workspace_memory(action="read"|"search")`、`skill_manage(action="list")`），拦截一切写入与命令执行请求。

### 3. 本机回环与远程来源校验
- 本机控制面板与本地管理命令使用独立的 `local_api_token`（`Authorization: Bearer <token>`），服务端同时核验 TCP 来源 IP 为 `127.0.0.1`/`::1`、`Host` 头为本机回环且不含反向代理转发头（如 `CF-Connecting-IP`、`X-Forwarded-For`），防止公网隧道伪造回环请求。
- 本地管理接口启用 `Origin` 同源检查与 `HMAC` 会话级 CSRF 令牌保护；浏览器 Cookie 会话强制核验随机 `csrf_token`，而来自严格本机回环且通过常量时间 `Authorization: Bearer <local_api_token>` 校验的 CLI 或本地自动化请求免填表单 `csrf_token`。

## 二、状态目录隔离、写前快照与安全回收箱

### 1. 状态目录与凭据保护
- 默认状态根目录：Windows 为 `%LOCALAPPDATA%\CosmosMCP`，macOS 与 Linux 为 `~/.cosmos-mcp`（首次无配置启动默认将工作区设在 `~/CosmosWorkspace`，不会将软件解压目录本身设为工作区）。
- `WorkspaceGuard` 路径守卫在所有安全模式下（含 `L4`）均拦截读取或修改 `<状态目录>/secrets`、`<状态目录>/state` 及系统核心受保护目录，并阻止通过符号链接或目录联接点越界访问工作区外文件。

### 2. 写前自动快照与可恢复回收箱
- **修改前快照**：`edit_file` 与 `write_file` 在覆盖或修改已有文件前，自动将原文件备份至历史快照库，并在临时文件通过语法预检后再原子替换目标文件，支持通过 `manage_files(action="undo")` 或面板一键回退。
- **禁裸删与回收箱恢复**：删除操作统一由 `manage_files(action="trash")` 移入可恢复回收箱，卸载命令 `cosmos-mcp uninstall` 默认保留历史快照与回收箱数据（仅在显式传入 `--purge` 时彻底清空）。

## 三、按需降级、外设边界与 `sandbox/` 容器隔离

### 1. 在线按需降级与进程生命周期管理
- 支持通过本地控制台主控首页左栏「当前权限设置」4 档切换条点选「只读」（或「设置 -> 工具与扩展」页、系统托盘右键菜单「切换为只读安全模式」）及 `cosmos-mcp permissions --tier L1`（或 `L2`）实时收紧权限；降级或执行 `--revoke-all` 时，`KillSignalWatchdog` 在 0.1 秒内终止全部在途前台/后台子进程树并关闭外设会话。
- Windows 后台守护进程通过 `JobObject`（`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`）管理 `uvicorn`、`cloudflared` 与 `ssh` 子进程，守护进程退出时同步回收子进程，避免残留孤儿进程占用端口。

### 2. 外设扩展包与系统级沙盒（`sandbox/`）
- **受管浏览器包（`browser`）**：固定使用 `<状态目录>/browser_profile` 独立目录运行并内置同步 SSRF 守卫。
- **桌面窗口操控包（`desktop`，仅 Windows）**：`L1`/`L2` 下禁用，`L3` 下严格限制在开放工作目录关联窗口内操作，`L4` 下具备键鼠活跃自动礼让与未保存窗口关闭保护。
- **操作系统级容器与沙盒配置（`sandbox/`）**：默认 `L1..L4` 属于应用层路径与命令护栏；针对不可信输入或高隔离需求，仓库提供 `sandbox/Dockerfile`、`sandbox/docker-compose.yml`（非 `root` `uid=1000`、`cap_drop: ALL`）及 `sandbox/CosmosMCP_WindowsSandbox.wsb` 供开箱运行。

## 四、安全问题报告

如发现权限绕过、路径逃逸、OAuth 鉴权缺陷或 SSRF 绕过问题，请勿在公开讨论区直接贴出含真实令牌或未修复利用链的细节：
1. 运行 `cosmos-mcp doctor --bundle` 生成自动脱敏的诊断信息包。
2. 通过仓库的 GitHub Security Advisories（Private Vulnerability Reporting）提交复现步骤、影响范围与修复建议。
