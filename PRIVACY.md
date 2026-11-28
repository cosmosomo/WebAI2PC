# 隐私政策与零遥测声明（PRIVACY.md）

> 🌐 **Language:** 简体中文（当前） · [English](PRIVACY_EN.md)

## 一、产品定位与默认零遥测声明

Cosmos MCP 面向 **网页版 Google Gemini（任务模式，含同账号手机端 Gemini App）** 与 **网页版 ChatGPT（首次代连用 `Work` 模式受控浏览器或本机手动装插件，安装后支持普通 `Chat` 模式日常开发与 `Work` 模式长程/定时任务；工作区全功能 `/mcp` 与个人订阅只读 `/mcp/readonly`）** 提供受控的本地工作区连接服务。

程序默认不收集、不统计、不向软件维护者或任何第三方统计机构上传使用遥测、设备指纹、主机名、目录路径、工具调用记录或工作区文件内容，并遵循系统环境变量 `DO_NOT_TRACK=1`。

## 二、多网关可选并存与不同通道的数据流向

本项目维护者不自建集中式业务中转服务器留存用户流量。控制台提供 3 类远程 HTTPS 加密网关，支持按需单开或多路网关独立开关同时并存，也可关闭全部公网网关仅在本机回环自检：

1. **方式 1：系统内置 OpenSSH 免登录直连与 Cloudflare 临时加密通道备用（首次启动默认开启，`--mode openssh` / `--mode public_gateway` 及 `--mode cloudflare` / `--mode trycloudflare`）**：
   - **首选通道（`--mode openssh`）**：直接调用操作系统自带的 OpenSSH（`ssh`）客户端，使用本机生成的 `Ed25519` 持久非对称密钥（`<状态目录>/secrets/srvus_ed25519`，私钥仅留存本机并限制当前用户访问权限，不上传至任何远端）向公共 SSH 反向隧道中继 `srv.us:22` 建立 `SSHv2` 加密反向隧道（优先协商 `chacha20-poly1305@openssh.com` 或 `aes256-gcm@openssh.com` 对称认证加密与 `curve25519-sha256` 密钥交换，并以 `User=nomatch` 与 `IdentitiesOnly=yes` 隔离本机系统用户名及其他 SSH 密钥），获取跨关机重启不变的 `https://xxxxx.srv.us` 固定 HTTPS 地址。
   - **备用通道 `Cloudflare 临时加密通道（trycloudflare 备用）`（`--mode cloudflare` / `--mode trycloudflare`）**：若当前网络限制 `22` 端口（或手动开启独立开关并存），程序调用官方 `cloudflared` 客户端（首次自动下载强制执行 **`SHA-256`** 校验和核验），经出站 `443` 端口建立 **`TLS + HTTP/2`**（`--protocol http2`）加密隧道生成临时 `https://*.trycloudflare.com` 地址。
   - **加密链路与边缘终结边界**：网页版 Google Gemini 与网页版 ChatGPT 访问公网网关时全程走标准 `HTTPS/TLS` 加密；公网 TLS 在 `srv.us`（或 Cloudflare）公共边缘节点终结后，请求经上述 OpenSSH `SSHv2` 反向隧道（或 `cloudflared` 出站 `TLS + HTTP/2` 隧道）回源至本机 `127.0.0.1`（非端到端零知识盲转），由本机回环入站垫片（`_LocalTunnelIngressShim`）与 `GatewayContextASGI` 回环校验（识别 `Cf-Ray` / `X-Forwarded-*` 转发头）直接以 HTTP `403` 阻断公网访问 `/studio`、`/api/studio`、`/oauth/local-bridge` 等本地管理面，再配合 `/u/<endpoint_secret>/mcp` 隐身路径、本地 `OAuth 2.1 + PKCE S256`（SHA-256）及 [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 资源受众隔离放行（令牌仅存 `SHA-256` 摘要；若需公网 TLS 直接在本人名下服务器终结，可选用方式 3 自有 Linux 云服务器主站）。可选导出的身份恢复卡 PNG 采用 `scrypt`（`N=16384, r=8, p=1`）+ `AES-256-GCM` 认证加密。
2. **方式 2：`Cloudflare 专属固定网关`（`--mode workers_dev` / `cf_workers`）**：
   - **部署与 API 令牌即毁机制**：使用用户本人一次性提供的最小权限 Cloudflare API Token，在用户自有 Cloudflare 账号下部署免费 `Worker + SQLite Hibernation Durable Object` 休眠中继网关（如 `https://your-worker.your-subdomain.workers.dev` 或同账号自定义域名）；部署完成后立即调用 `shred_cloudflare_api_token` 在内存与临时缓存中全零覆写、刷盘截断并销毁该 API Token，本机磁盘零明文留存，同时支持导出 `scrypt`（`N=16384, r=8, p=1`）+ `AES-256-GCM` 加密恢复卡 PNG。
   - **加密链路与边缘终结边界**：日常运行采用纯 Python 标准库 `ssl.create_default_context()` 校验证书链，建立出站 **`443 WSS`（`TLS 1.2 / TLS 1.3` 加密 WebSocket）** 二进制多路复用长连接（零外部二进制依赖）；本机自动生成 **`256-bit`（64 位十六进制）`workers_tunnel_secret`**（Windows `icacls` / Unix `0600` 当前用户独占权限），Worker 端 `/_cosmos_tunnel` 采用常量时间比对（`constantTimeEqual`）校验 `Bearer` 隧道密钥防伪造挂载。公网 `HTTPS/TLS` 在**用户本人名下的 Cloudflare 账号边缘**终结（Worker 入口白名单仅放行 OAuth 与 `/mcp*` 路由，直接拦截管理路径），经 `443 WSS` 回源后本机二次拦截 `/studio` 等管理路径，并强制执行 `OAuth 2.1 + PKCE（SHA-256）` 与 [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 受众隔离。
3. **方式 3：自有云服务器 `24h` 主站 或 自有固定域名（`self_hosted`：`--mode vps_hub`、`vps`、`cloudflare_token`、`custom` / `reverse_proxy`）**：
   - **子项 A `自有云服务器 24h 主站`（`--mode vps_hub`）与 `自有服务器 SSH 反向隧道`（`--mode vps`）**：一键在**用户自己的 Linux 云服务器**部署 **Caddy v2.11+**，自动签发并续期 **`TLS 1.2 / TLS 1.3` ACME 证书**（绑域名签发 Let's Encrypt 证书，未填域名自动签发公网 IP 短期 ACME 证书 + `sslip.io` 备用证书），**公网 TLS 完全在用户自有服务器上终结，零第三方云平台过境解密**。部署优先使用本机独立生成的 **`Ed25519`** SSH 密钥对（`<状态目录>/secrets/vps_id_ed25519`，`0600` / 当前用户独占 ACL），首次一键部署填写的 SSH 密码**仅在当次内存握手使用、绝不落盘**。`vps_hub` 模式下本机经 CA 校验的出站 **`443 WSS`（`TLS 1.2/1.3`）** 挂载 `/_cosmos_node`，凭 **`256-bit`（64 位十六进制）`vps_node_secret`** 执行 `hmac.compare_digest` 常量时间鉴权，Caddy 拦截外网访问 `/studio` 与非 WebSocket `/_cosmos_node`，同步至云端的 `auth.json` 自动剥离 `local_api_token` 并设 `0600`；`vps` 模式下调用系统内置 OpenSSH 建立 **`SSHv2`**（`ChaCha20-Poly1305` / `AES-256-GCM`）`-R` 加密反向隧道；全程执行 `OAuth 2.1 + PKCE（SHA-256）` 与 [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 受众隔离。
   - **子项 B `Cloudflare Named Tunnel`（`--mode cloudflare_token`）与 `通用自建 HTTPS 反代`（`--mode custom` / `reverse_proxy`）**：`cloudflare_token` 由经 **`SHA-256`** 校验的 `cloudflared` 建立出站 `443` **`TLS + HTTP/2`**（`--protocol http2`）加密隧道，令牌按用户独占权限存于 `secrets/tunnel_token.txt` 并在日志脱敏为 `[REDACTED_TUNNEL_TOKEN]`，公网 `HTTPS/TLS` 在用户自己的 Cloudflare Zero Trust 边缘终结后回源本机；`custom` / `reverse_proxy` 公网 **`HTTPS / TLS 1.2/1.3`** 在用户自控的 Caddy / Nginx 反代终结（或经 FRP TLS SNI 透传），本机 `GatewayContextASGI` 校验受信任 `Host` 白名单（未知域名返 `421`）；两者回源后本机均阻断 `/studio` 管理面并强制执行 `OAuth 2.1 + PKCE（SHA-256）` 与 [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 受众隔离。
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
- `secrets/auth.json`、`secrets/master_seed`、`secrets/srvus_ed25519`、`secrets/vps_id_ed25519`、`secrets/workers_tunnel_secret.txt`、`secrets/vps_node_secret.txt`、`secrets/tunnel_token.txt` 与 `state/oauth.sqlite3`：保存口令哈希、本机确定性种子、OpenSSH / VPS 持久密钥对（当前用户独占权限）、`256-bit` Workers 网关与 VPS 子节点握手密钥、Named Tunnel 令牌（诊断日志脱敏为 `[REDACTED_TUNNEL_TOKEN]`）及 SHA-256 哈希化 OAuth 令牌记录（不保存明文 OAuth 访问令牌、Cloudflare API 部署令牌或 VPS SSH 密码）。

导出诊断信息时，执行 `cosmos-mcp doctor --bundle` 会自动隐去口令、令牌、隧道子域名、邮箱及操作系统个人目录用户名。如需停止后台进程并清除状态目录内全部本地记录，可执行：

```bash
cosmos-mcp uninstall --purge --json
```
