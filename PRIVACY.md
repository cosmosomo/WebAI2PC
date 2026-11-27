# 隐私政策与零遥测声明（PRIVACY.md）

## 一、产品定位与默认零遥测声明

Cosmos MCP 面向 **网页版 Google Gemini（任务模式，含同账号手机端 Gemini App）** 与 **网页版 ChatGPT（首次代连用 `Work` 模式受控浏览器或本机手动装插件，安装后支持普通 `Chat` 模式日常开发与 `Work` 模式长程/定时任务；工作区全功能 `/mcp` 与个人订阅只读 `/mcp/readonly`）** 提供受控的本地工作区连接服务。

程序默认不收集、不统计、不向软件维护者或任何第三方统计机构上传使用遥测、设备指纹、主机名、目录路径、工具调用记录或工作区文件内容，并遵循系统环境变量 `DO_NOT_TRACK=1`。

## 二、多网关可选并存与不同通道的数据流向

本项目维护者不自建集中式业务中转服务器留存用户流量。控制台提供 3 类远程 HTTPS 加密网关，支持按需单开或多路网关独立开关同时并存，也可关闭全部公网网关仅在本机回环自检：

1. **方式 1：`srv.us` 免登录固定通道与快速回退（首次启动默认开启，`--mode public_gateway` 及 `--mode cloudflare`）**：
   - 默认优先使用本机生成的 Ed25519 持久密钥（`<状态目录>/secrets/srvus_ed25519`）向公共 SSH 反向隧道服务 `srv.us:22` 发起远程端口转发，获取跨关机重启不变的 `https://xxxxx.srv.us` 固定 HTTPS 地址；若当前网络限制 22 端口，4 秒内自动切换至本机 `cloudflared` 客户端建立 Cloudflare Quick Tunnel（`https://*.trycloudflare.com`）。
   - 该通道用于免注册接通网页版 Google Gemini 与网页版 ChatGPT，TLS 流量经所选隧道转发至本机监听端口，并由本机执行 OAuth 2.1 与 [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 资源受众校验。
2. **方式 2：`Cloudflare Workers` 专属固定网关（`--mode workers_dev`）**：
   - 使用用户本人一次性提供的最小权限 Cloudflare API 令牌，在用户自有 Cloudflare 账号下部署免费 SQLite Durable Object 休眠中继网关（如 `https://your-worker.your-subdomain.workers.dev` 或同账号自定义域名）；部署完成后 API 令牌立即在内存与临时缓存中全零覆写销毁，本机磁盘零明文 API Token 留存。日常运行通过出站 443 WebSocket 直连用户自有网关，可与方式 1 或方式 3 同时在线并存。
3. **方式 3：`24h Linux VPS` 常驻主站与自有固定域名（`--mode vps_hub`、`vps`、`cloudflare_token`、`custom`）**：
   - 支持通过 SSH 密码（仅当次内存握手使用，不落盘保存）或本地 SSH 私钥在用户自有 Linux 云服务器一键部署 24 小时常驻主站并经加密 WSS 挂载本机，或经由用户自有 Cloudflare Named Tunnel 固定令牌、自有反向代理域名（如 `https://mcp.example.com`）直连转发。
4. **本机回环隔离自检模式（关闭全部公网网关开关或指定 `--mode local`）**：
   - 关闭全部 3 类公网网关开关或显式传入 `--mode local` 时，服务端仅监听本机回环地址 `127.0.0.1` 供本地控制台查看与自动化自检；除首次准备运行环境及用户主动调用 `pc_web_research`、`pc_browser_use` 访问外部公开网页外，服务端不发起外网隧道连接。
5. **口令哈希与零明文 Token 留存边界**：
   - 本机管理与授权口令以随机 16 字节盐值加 `hashlib.scrypt` 哈希形式保存在 `<状态目录>/secrets/auth.json`（权限 `0600`），仅在本机完成校验。
   - 网页版 Google Gemini 与网页版 ChatGPT 仅接收绑定当前网关受众的 OAuth 2.1 令牌（个人版 ChatGPT 绑定的 `/mcp/readonly` 令牌物理隔离锁定为 `server:read` 只读受众），不接触本机明文口令；本地 `state/oauth.sqlite3` 仅保存访问令牌与刷新令牌的 SHA-256 哈希摘要主键，零明文 OAuth Token 落盘。

## 三、本机留存文件与清除方式

为支持用户本人查看审计记录、撤回文件修改与恢复误删文件，程序仅在本机状态目录（Windows 默认 `%LOCALAPPDATA%\CosmosMCP`，macOS 与 Linux 默认 `~/.cosmos-mcp`）内保存以下本地数据：

- `logs/audit.jsonl`：记录本地工具调用时间、工具名称、耗时与执行状态。
- `logs/server.log` 与 `logs/supervisor.log`：记录本地服务与后台守护进程运行日志，按文件大小自动轮转覆盖旧日志。
- `history/` 与 `.undo_history/`：保存修改前自动备份的文件快照与移入安全回收箱的文件。
- `secrets/auth.json`、`secrets/master_seed`、`secrets/srvus_ed25519`、`secrets/workers_tunnel_secret.txt`、`secrets/tunnel_token.txt` 与 `state/oauth.sqlite3`：保存口令哈希、本机确定性种子、SSH 隧道持久密钥、Workers 网关握手密钥、Named Tunnel 令牌及 SHA-256 哈希化 OAuth 令牌记录（不保存明文 OAuth 访问令牌、Cloudflare API 部署令牌或 VPS SSH 密码）。

导出诊断信息时，执行 `cosmos-mcp doctor --bundle` 会自动隐去口令、令牌、隧道子域名、邮箱及操作系统个人目录用户名。如需停止后台进程并清除状态目录内全部本地记录，可执行：

```bash
cosmos-mcp uninstall --purge --json
```
