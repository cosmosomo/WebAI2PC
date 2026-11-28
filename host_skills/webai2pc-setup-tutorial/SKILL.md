---
name: webai2pc-setup-tutorial
description: WebAI2PC (Cosmos MCP) 本地控制台配置、Cloudflare 免费固定网址部署、24h 服务器主站、四档权限切换、Gemini/ChatGPT 接入与排障分步教学指南。当用户询问如何使用、如何改工作目录或权限、如何配置 Cloudflare 固定网址或请求打开本地配置页面时加载。
---

# WebAI2PC (Cosmos MCP) 本地配置与接入分步教学指南

本技能面向已连接本 MCP 服务的网页版 Gemini 或网页版 ChatGPT。当用户询问如何使用、如何添加工作目录或切换安全权限、如何配置 Cloudflare 终身固定网址、如何接入 24 小时云服务器主站、如何开启扩展包，或要求在电脑上直接打开对应配置页时，按本指南分步引导。

## 1. 为同机用户直接打开本地配置页（优先调用 `pc_get_status`）

当用户在本地电脑浏览器使用网页端 AI 时，优先调用状态工具（默认前缀为 `pc_`，若用户自定义了 `tool_prefix` 则以当前工具列表前缀为准）读取实时配置并直接打开对应本地页面：

- **调用格式**：
  `pc_get_status(guide="cloudflare"|"gateways"|"permissions"|"gemini_chatgpt"|"packs_and_skills"|"troubleshooting"|"all", open_page="gateways"|"studio"|"runtime"|"tools"|"skills"|"tutorials")`
- **`open_page` 页面路由对照**（默认本地端口 `8096`，实际端口以服务运行状态为准）：
  - `open_page="studio"`：打开本地控制台主控首页（`http://127.0.0.1:8096/`）
  - `open_page="gateways"`：打开连接与网关设置页（`http://127.0.0.1:8096/#settings/gateways`）
  - `open_page="runtime"`：打开环境与系统设置页（`http://127.0.0.1:8096/#settings/runtime`）
  - `open_page="tools"`：打开工具与扩展设置页（`http://127.0.0.1:8096/#settings/tools`）
  - `open_page="skills"`：打开技能管理设置页（`http://127.0.0.1:8096/#settings/skills`）
  - `open_page="tutorials"`：打开本地 6 模块交互式实战教程页（`http://127.0.0.1:8096/tutorials`）
- **引导节奏**：打开页面后，对照返回的当前配置状态与下方真实界面按钮名称，每次只讲当前需要用户点击的那一步，等用户确认完成后再继续下一步。若连接的是远端服务器且本地电脑不在线，或旧版服务未识别上述可选参数，直接告知用户对应的本地网址与按钮位置即可。

## 2. 主控首页：修改工作目录、四档安全权限与撤回保护

打开主控首页（`open_page="studio"`）后，界面分为顶栏、顶部宿主连接卡与下方左右双栏：

- **顶栏右侧快捷按钮**：
  - `实战教程`：进入本地交互式图文教程页（`/tutorials`），自动带入当前就绪的 `/mcp` 与 `/mcp/readonly` 地址。
  - 语言切换与深浅色切换按钮。
  - `设置`（快捷键 `Ctrl+,`）：进入左侧五分类设置中心（`连接与网关`、`环境与系统`、`工具与扩展`、`技能管理`、`外观与图标`），点击左上或顶栏 `← 返回主控台` 回到首页。
  - 需要免口令快速切入只读或切回工作区开发时，直接在下方左栏 `当前权限设置` 4 档切换条或系统托盘右键菜单点击即可（`0.1` 秒内生效）。
- **左栏「开放工作目录」与只读分层**：
  - 添加目录：点击 `选文件夹` 调起操作系统原生文件夹选择框，或在输入框粘贴路径点击 `添加`（也可点 `浏览目录树` 或 `常用目录快选 ▸`）。
  - 父只读子读写分层：打开输入框下方的 `以只读参考目录添加` 开关再添加目录，即可将其设为只读参考目录（`readonly_workspace_roots`）。支持将外层总目录设为只读参考、将内部当前开发的子项目设为可读写目录（`workspace_roots`），系统按最长路径前缀自动匹配读写权限。
- **左栏「当前权限设置」（点击即生效，对应 `L1` 至 `L4`）**：
  - `只读`（`L1`）：仅开放只读查询工具（含 `pc_skill_hub`），禁止改文件与运行命令。
  - `仅改文件`（`L2`）：允许在可读写工作目录内查阅与修改文件，禁止运行终端命令、Python 脚本与外设扩展包。
  - `工作区开发`（`L3`，默认推荐）：允许在已开放的可读写工作目录内修改文件、移入安全回收箱、无窗口运行终端命令与 Python 脚本，只读参考目录内仅允许读取。
  - `全盘开发`（`L4`）：允许跨本机任意目录读写与运行命令，同时保留系统敏感凭据目录隔离、安全回收箱与键鼠活跃自动礼让。
- **右栏「实时动态与撤回」**：
  - 包含 `在途任务`（查看后台任务实时日志或终止进程）、`修改撤回`（所有写文件操作前自动留存快照，点 `查看对比 Diff` 审阅后可一键回退）、`回收箱`（还原被 `trash` 清理的文件）与 `调用记录`。

## 3. 连接与网关（`#settings/gateways`）：3 类通道与 Cloudflare 固定网址部署

点击顶栏 `设置`（或顶部连接卡右上角 `配置连接通道 ▸`）进入 `连接与网关`（可调用 `pc_get_status(guide="cloudflare", open_page="gateways")` 直接打开）。3 张网关卡片右上角均带独立开关，**支持多路网关同时开启在线**，测试新网关时不会断开当前已连会话。

### （1）第 1 类 · 默认免配置：`系统内置 OpenSSH 免登录直连`（`--mode openssh`，兼容 `public_gateway` / `srv_us`）
- **首选系统 OpenSSH 固定地址通道（`*.srv.us` 中继，10 秒启动等待预算）**：直接调用操作系统自带 OpenSSH（`ssh`）客户端与出站 TCP `22` 端口（零额外二进制、零注册，启动等待预算 `10` 秒），具备四重加密与鉴权保护：本机持久 `Ed25519` 非对称密钥认证（私钥留存本机不上传）+ OpenSSH `SSHv2` 加密反向隧道（`ChaCha20-Poly1305` / `AES-256-GCM` 对称认证加密 + `curve25519-sha256` 密钥交换）+ 公网 `HTTPS/TLS` 传输（在开源公共中继 `srv.us` 边缘终结后经 `SSHv2` 隧道回源）+ 本机隔离垫片与 `OAuth 2.1 + PKCE S256` 二次鉴权及 RFC `8707` 受众隔离，分配跨关机重启不变的固定 HTTPS 地址，中国大陆家庭宽带通常可**免代理直连**。
- **备用 `Cloudflare 临时加密通道（trycloudflare 备用）`（独立开关并存 / `--mode cloudflare`，兼容别名 `--mode trycloudflare`）**：在卡片展开区配有独立开关 `开启备用（可与 OpenSSH 固定通道同时在线）`，既可与 OpenSSH 固定通道同时在线热备，也可在校园网/企业网拦截 `22` 端口导致 `srv.us` 超过 `10` 秒未连通时启用。官方 `cloudflared` 客户端首次从 GitHub Releases 或 `COSMOS_CLOUDFLARED_MIRROR` HTTPS 镜像下载时强制通过 **`SHA-256`** 校验和核验（存至状态目录 `bin/`；国内无代理拉取 GitHub 慢时需开系统代理、设 `COSMOS_CLOUDFLARED_MIRROR` 或预装 `cloudflared`）；通过出站 `443` 端口建立 **`TLS + HTTP/2`**（`--protocol http2`）加密隧道，公网 **`HTTPS / TLS`** 在 Cloudflare 边缘终结后经出站 TLS 隧道回源本机 `127.0.0.1`（非端到端零知识盲转），本机识别 `Cf-Ray` / `X-Forwarded-*` 阻断公网访问 `/studio` 管理面，强制执行本地 **`OAuth 2.1 + PKCE（SHA-256）`** 与 RFC `8707` 读写/只读受众隔离。注意该通道重启必换域名、无在线率 SLA、单控制流（`ha-connections:1`）重连有 `4–21` 秒空窗（返 HTTP `530`/`1033`）、限 `200` 并发在途请求且受边缘 `125` 秒（`125s`）读超时约束，跨境高丢包建议开系统 HTTP 代理。

### （2）第 2 类 · 无服务器固定网址：`Cloudflare 专属固定网关`（`--mode workers_dev`，兼容 `cf_workers` / `cloudflare_workers`）
本通道采用纯 Python 标准库 `ssl.create_default_context()` 校验证书链，建立出站 **`443 WSS`（`TLS 1.2/1.3` 加密 WebSocket）** 多路复用长连接，**零外部二进制依赖**（无需安装 `Node.js`、`wrangler` 或 `cloudflared`），本机自动生成当前用户独占权限的 **`256-bit`（64 位十六进制）`workers_tunnel_secret`** 并在 Worker 端 `/_cosmos_tunnel` 执行常量时间比对防伪造挂载；公网 **`HTTPS / TLS`** 在**用户自己名下的 Cloudflare 账号边缘（Worker + SQLite Hibernation Durable Object，路由白名单仅放行 OAuth 与 `/mcp*`）**终结，回源后本机拦截 `/studio` 等管理路径并执行 **`OAuth 2.1 + PKCE（SHA-256）`** 与 RFC `8707` 受众隔离（受 Cloudflare Workers Free 每日 `100,000` 次请求上限，超限返 `1027`，以及边缘默认反代读取超时 `125` 秒即 `125s` 约束）。引导用户点击第 2 张卡片右侧 `配置 ▾` 展开面板，按三步完成部署：
1. **获取一次性 API 令牌**：点击卡片内的 `第 1 步：打开 Cloudflare 预填权限页（支持 Google 快捷登录）`。在打开的 Cloudflare 页面登录免费账号（权限模板已自动预填），滑到页面底部点击 `Continue to summary` -> `Create Token`，复制生成的 API 令牌。
2. **粘贴令牌与选填域名**：回到本地控制台，将令牌粘贴进 `第 2 步：粘贴 API 令牌（部署后立即销毁）` 输入框。若用户在同 Cloudflare 账号下已有激活域名（Active Zone），可在右侧 `选填：自定义域名（Active Zone，国内免切代理）` 填入子域名（如 `mcp.yourdomain.dpdns.org`）；若检测到多个账号，在下拉框选择目标账号。
3. **3 秒一键部署与自动销毁令牌**：点击 `一键部署并开启（约 3 秒）`，自动生成终身固定的 `https://*.workers.dev/mcp`（及 `/mcp/readonly`）。
   - **密钥安全与后续启停**：一次性最小权限 API 令牌在部署完成瞬间自动全零覆写销毁（`shred_cloudflare_api_token`，零明文落盘），并支持导出 **`scrypt + AES-256-GCM`** 加密恢复卡 PNG；后续开关连接只需拨动第 2 张卡片右上角开关，无需重填令牌。
   - **中国大陆代理依赖边界（重点提示用户）**：`*.workers.dev` 在国内运营商与公共 DNS 下存在全量 DNS 污染（无代理裸连 `100%` 超时）。若未绑定自定义域名，**本机运行期间必须保持系统 HTTP/HTTPS 代理（Clash / Mihomo / v2rayN 或 `HTTPS_PROXY` / `WSS_PROXY`）常开且分流规则覆盖 `*.workers.dev`**（首次打开 `/consent` 授权页时浏览器亦需走代理，若分流漏掉 `*.workers.dev` 可临时切全局完成授权，但切回规则模式后日常仍须确保规则代理 `*.workers.dev`；若设 `NO_PROXY` 须保留 `127.0.0.1,localhost,::1`）。**国内免代理方案**：绑定同账号 Active Zone 自定义域名即可免代理直连（自定义域名须关闭 `Bot Fight Mode` 并对 `/mcp*` 与 OAuth 路径跳过托管质询；或改用第 1 类 `*.srv.us` / 第 3 类自有云服务器）。

### （3）第 3 类 · 自有资产合一：`自有云服务器 24h 主站 或 自有固定域名`（`self_hosted`）
点击第 3 张卡片右侧 `配置 ▾`，按两个子标签选型：
- **`自有服务器建 24h 主站`（`--mode vps_hub`）与 `SSH 反向隧道`（`--mode vps`）**：依赖开放 `80`/`443` 端口的 Linux 服务器与本机 `ssh` 客户端，**零 Cloudflare 依赖、零单日请求上限、零 `125s` 边缘超时限制**，国内（配已备案域名）或港新服务器全程免代理直连。一键在**用户自有 Linux 云服务器**部署 **Caddy v2.11+**，自动签发续期 **`TLS 1.2/1.3` ACME 证书**（有域名签 Let's Encrypt 证书，无域名自动签公网 IP 短期 ACME 证书 + `sslip.io` 备用证书），**公网 TLS 完全在用户自有服务器上终结，零第三方云平台过境解密**；优先使用本机独立生成的 **`Ed25519`** 密钥对（`secrets/vps_id_ed25519`，`0600` / 用户独占 ACL），首次填写的 SSH 密码**仅当次内存握手使用、绝不落盘**。`vps_hub` 模式下本机通过 CA 校验的出站 **`443 WSS`（`TLS 1.2/1.3`）** 挂载 `/_cosmos_node` 并经 **`256-bit` `vps_node_secret`**（`hmac.compare_digest` 常量时间校验）双向防伪，Caddy 拦截外网访问 `/studio` 与非 WebSocket `/_cosmos_node`，云端 `auth.json` 自动剥离 `local_api_token` 并设 `0600`；`vps` 模式下通过系统内置 OpenSSH 建立 **`SSHv2`**（`ChaCha20-Poly1305 / AES-256-GCM`）`-R` 加密反向隧道；全程强制 **`OAuth 2.1 + PKCE（SHA-256）`** 与 RFC `8707`。填入 `服务器公网 IP（必填）` 与 SSH 密码或密钥点击 `一键部署 24h 主站并开启`，单个连接器可通过 `target="auto"` 自动按路径操作云服务器或本地电脑；电脑关机时云服务器仍 24 小时在线。
- **`自有固定域名 / Cloudflare Named Tunnel / 通用 HTTPS 反代`（`--mode cloudflare_token` / `--mode custom` / `--mode reverse_proxy`）**：填写 `固定公网 HTTPS 域名`。选填 `Cloudflare Named Tunnel 令牌`（`--mode cloudflare_token`）时，经 **`SHA-256`** 校验的官方 `cloudflared`（支持自动下载与 `COSMOS_CLOUDFLARED_MIRROR`）建立出站 `443` **`TLS + HTTP/2`** 隧道，令牌按用户独占权限存于 `secrets/` 并在日志脱敏为 `[REDACTED_TUNNEL_TOKEN]`，公网 TLS 在用户自己的 Cloudflare Zero Trust 边缘终结（需 Active Zone 域名、后台指向 `http://127.0.0.1:8096` 的 Public Hostname 转发，且须关闭 `Bot Fight Mode` 并对 `/mcp*` 与 OAuth 路径跳过托管质询）；使用自建 Caddy / Nginx / FRP 反代时（`--mode custom` / `--mode reverse_proxy`），公网 **`HTTPS / TLS 1.2/1.3`** 在用户自控反代终结（或经 FRP TLS SNI 透传），本机校验受信任 `Host` 白名单（未知域名返 `421`）、阻断 `/studio` 并执行 **`OAuth 2.1 + PKCE（SHA-256）`** 与 RFC `8707`，点击 `保存并开启此网关`。

## 4. 换机免重绑：身份恢复卡 PNG 导出与导入

当用户准备重装系统或迁移到新电脑时，可在 `#settings/gateways` 第 1 张卡片展开区底部使用加密图片备份节点身份：
- **导出备份**：点击 `导出身份恢复卡 PNG`，在弹窗输入加密保护口令，点击 `生成并下载身份恢复卡 PNG` 保存图片（采用 `scrypt + AES-256-GCM` 认证加密，内含固定节点身份、`srv.us` `Ed25519` 私钥、Cloudflare 网关与服务器节点配置）。
- **换机恢复**：在新电脑启动控制台后进入同一位置，点击 `导入恢复卡 PNG`，选择备份的 PNG 图片并输入导出时设置的口令，点击 `解密并恢复固定节点身份`，即可恢复原有固定连接网址，网页端连接器无需重新绑定。

## 5. 网页版 Gemini / ChatGPT 绑定、扩展包与系统设置

- **网页版 Gemini（任务模式与手机端同步）**：
  - **明确提醒用户**：`https://<域名>/mcp` **不是从浏览器地址栏直接打开的网址**，而是要粘贴进 Gemini 连接器配置栏里的 MCP 服务器地址。
- 引导用户直接打开 `https://gemini.google.com/customize/connectors`（或从 Gemini 首页左下角菜单点 `Personal Intelligence -> Connected Apps`），点击右上角 `+ Custom`，在 `Connect to an MCP server` 弹窗把 `https://<域名>/mcp` 粘贴到 **`MCP Server URL`** 配置栏（`Additional settings` 保持默认折叠），点击 **`Next`**。
- 跳转授权页后，同机浏览器直接点 `本机一键允许连接`；完成后回到 `https://gemini.google.com/customize/connectors` 点开连接器，将 `App actions` 总开关设为 `Always allow`。新建对话首句输入 `@你在连接器里填写的名称`（例如 `@WebAI2PC` 或 `@Cosmos`）点选连接器标签即可唤醒，同账号手机端 Gemini App 自动同步。
- **网页版 ChatGPT（`Work` 模式 `@Plugin Creator` 一键配置 · 装好后日常用 `Chat` 模式省额度）**：
  - **首次一键配置与授权**：本地控制台在公网网关就绪后开放主按钮 `复制一键配置提示词（发给 Work）`（个人 Plus / Pro 只读账号点击 `复制只读配置提示词（发给 Work）`，或点 `仅复制地址` 手动填写）。引导用户将复制出的提示词粘贴发送给网页版 ChatGPT 的 `Work` 模式，由 `@Plugin Creator` 按标准 OAuth 2.1 自动接入 `/mcp`（Team / Business / Enterprise / Edu 工作区全功能）或 `/mcp/readonly`（个人 Plus / Pro 受平台限制写工具时只读），无需手动填写 Client ID / Secret 或额外部署中转服务；弹出 `/consent` 授权页时，同机浏览器命中 `127.0.0.1` 回环直接点 `本机一键允许连接`（若在网页版 `Work` 云端受控浏览器内点 `Take over` 打开 `/consent` 则输入主控首页 `6` 位动态配对码）。
  - **日常调用分工与守则存放**：连接器安装后全账号共享（唤醒时输入 `@你在连接器里填写的名称`，默认 `@WebAI2PC`），以调用 `pc_get_status`（`get_status`）实际成功作为接通标准。日常查改本地代码、修 Office 与跑无窗口测试推荐切回 `Chat` 模式调用（响应快，走普通对话限额，零消耗 `Work / Codex` 智能体额度）；需要结合受控浏览器、跨邮件/Slack/网盘做长程交付或设置 `Scheduled Tasks` 定时任务时切 `Work` 模式调用（消耗 `Work / Codex` 智能体额度）。操作守则在工作区/桌面端可存入原生 `Skills`，网页版 `Chat` 与 `Work` 模式均可放入 `Project Instructions` 或自定义指令。
- **开启可选扩展包与多机前缀（`#settings/tools`，传 `open_page="tools"`）**：
  - `受管浏览器包`（`browser` -> `pc_browser_use`）：在独立 `browser_profile` 目录运行隔离浏览器查阅网页与截图，不触碰用户个人浏览器窗口。
  - `桌面窗口操控包`（`desktop` -> `pc_cua_window`，仅 Windows）：基于离屏截图与后台消息辅助操作桌面窗口，检测到键鼠活跃时自动礼让。
  - `多设备工具前缀`：多台电脑同时接入同一聊天窗口时，可将 `tool_prefix` 分别改为 `desk`、`laptop` 等并点击 `保存工具前缀`。
- **Python 解释器、开机自启与外观（`#settings/runtime` 与 `#settings/appearance`）**：
  - 在 `环境与系统`（`open_page="runtime"`）可选择默认 Python / Conda 解释器、开启 `开机自动启动`、`插电防自动休眠` 与 `显示系统托盘状态图标`。
  - 在 `外观与图标`（`open_page="appearance"`）可切换浅深模式、4 套主题风格包与 4 套图标转向姿态。

## 6. 常见排障核对清单

- **国内 `*.workers.dev` 无法连通或自定义域名报 `403`**：核对本机 HTTP/HTTPS 代理是否常开且规则覆盖 `*.workers.dev`（`NO_PROXY` 保留 `127.0.0.1,localhost,::1` 且不含 `*.workers.dev`）；使用 Cloudflare 自定义域名或 `Named Tunnel` 报 `403`/无法拉取 OAuth 元数据时，引导用户在 Cloudflare 后台 `Security -> Bots` 关闭 `Bot Fight Mode` 并为 `/mcp*` 及 OAuth 路径配置 WAF `Skip` 跳过托管质询。
- **缺少写入或执行工具**：核对主控首页左栏 `当前权限设置` 4 档切换条是否处于 `只读` 或 `仅改文件`（需要恢复时直接在 `当前权限设置` 点回 `工作区开发` 或通过系统托盘右键菜单切换）；个人版 ChatGPT 绑定 `/mcp/readonly` 时仅暴露只读工具属于平台规则限制。
- **同机授权页未自动通过回环验证**：若在网页版 ChatGPT `Work` 模式的云端受控浏览器内点 `Take over` 打开授权页，或同机浏览器开启严格隐私隔离插件拦截了本地 `127.0.0.1` 回环跳转，引导用户在主控首页展开 `配对与已连会话`，复制 6 位动态配对码或 20 位固定备用口令填入授权页即可。
- **Gemini 频繁弹出单次工具确认框**：提醒用户打开 `https://gemini.google.com/customize/connectors`（或左下角菜单 `Personal Intelligence -> Connected Apps`）点开连接器开启 `Always allow` 总开关，不要在聊天流单张确认卡上点单次允许；需要查公开网页时使用本连接器的 `pc_web_research`，避免混调宿主内置搜索触发权限降级。
