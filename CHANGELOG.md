# 版本变更记录（CHANGELOG.md）

本项目遵循语义化版本号（Semantic Versioning）规范。

## [1.2.1] - 2026-11-27

围绕三路多网关独立开关并存、第 4 档 `L4` 全盘顺畅开发模式、内置 `/tutorials` 交互式教程中心、4 套可替换主题与 4 朝向 IP 图标包、`.env` 外置配置治理、进程守护加固以及新手首屏与授权页无障碍体验做升级收口。

### 新增与升级功能（Added & Changed）
- **三路多网关独立开关同时在线并存**：
  - `Cosmos Studio` 3 张连接卡片（`instant` 免登录 `srv.us`/`trycloudflare`、`workers_dev` Cloudflare 休眠网关、`self_hosted` 自有云服务器 24h 主站或固定域名）右上角均升级为独立启停开关，支持多路网关同时连通在线、互不挤占断连，并在顶部连接栏与教程页提供多网关实时状态切换条；第 2 类网关保存地址后支持免重填 API 令牌直接开关重连。
- **新增第 4 档 `L4` 全盘顺畅开发（不限目录）安全模式**：
  - 在 `L1` 只读浏览、`L2` 仅改文件禁跑命令、`L3` 工作区内顺畅开发基础上新增 `L4`（`tier4_full_power`），允许跨本机任意目录读写文件与执行命令，同时保留 `.undo_history` 写前快照、安全回收箱防物理直删、只读参考目录保护及 `<状态目录>/secrets` 凭据隔离。
- **内置 `/tutorials` 交互式教程中心、4 套明暗风格包与 4 朝向 IP 图标体系**：
  - 新增本地 `http://127.0.0.1:8096/tutorials` 6 章 24 步交互式教程页，自动读取并注入本机当前就绪网关的 `/mcp` 与 `/mcp/readonly` 真实地址及配对码，支持关键词即时检索与学习进度本地保存。
  - 新增 `themes.css` 与 `brand-packs.js` 可替换视觉层，提供 `warm-paper`、`obsidian-emerald`、`cupertino-frost`、`graphite-mono` 4 套明暗双模风格包与 4 套 IP 图标包（支持朝右、正面、朝左与活跃任务自动切换 `working` 专注姿态）。
- **`.env` 外置配置治理、进程守护加固与启动脚本透传保护**：
  - 支持本地未入库 `.env` 外置环境变量加载与 `.env.example` 占位模板治理；加固 `daemon.py` 多网关状态同步、子进程树回收、无弹窗静默重连与 Windows 托盘状态提示。
  - `一键启动_Cosmos_MCP.bat` 与 `start_cosmos_mcp.sh` 新增未解压直接在压缩包预览窗口双击运行时的中文拦截指引，并支持 `start`、`stop`、`restart`、`status`、`doctor`、`permissions`、`agent-setup`、`reset-password`、`uninstall`、`--help` 等子命令原样透传。

### 修复与改进（Fixed & Improved）
- **修复前端首屏对比度、同步打开手势、冷启动引导与本地 Bearer 自动化鉴权**：
  - 修复 `#copy-wake-prompt-btn` 与深色模式下 `/consent` 主按钮 `#local-bridge-approve-btn` 的文字背景对比度，确保 4 套风格浅/深 8 种组合下对比度全部 `>= 4.5:1`；点击 `#open-gemini-connectors-btn` 时立即同步打开新标签页保留浏览器 `userActivation` 手势，后台异步探测 `*.workers.dev` 仅做页面代理提示而不阻断跳转。
  - 收紧 `1280x720` 首屏纵向间距并保持冷启动握手等待期两步引导常驻；在「网页版 ChatGPT」面板补齐操作守则与首句测试词复制按钮；修正 `#theme-toggle-btn` 切换文案并隐藏非调试态下的内部属性与宣传片导出按钮；对齐 `tutorials.html` 按钮名称、中英文菜单对照与 `Cosmos MCP · WebAI2PC 本地控制台` 品牌标识。
  - `studio/routes.py` 支持本机回环请求携带合法 `Authorization: Bearer <local_api_token>` 时免除浏览器随机 `csrf_token` 校验（Cookie 会话仍强制校验 CSRF），便于 CLI 与本地自动化脚本调用 `/api/studio/identity/export_png` 等管理接口。
- **修复真实 Chromium 公网 `/consent` 同机一键放行 `403 origin_mismatch`**：
  - `protocol/oauth.py` 将 `GET /consent` 页面响应头调整为 `Referrer-Policy: same-origin`（仅在带票据或授权码的 `302` 重定向响应保留 `no-referrer`），消除浏览器因 `no-referrer` 将同源表单提交置为 `Origin: null` 的问题。
  - 当同站浏览器因隐私扩展剥离 `Origin` 头时，自动保留所选权限并展开 6 位动态配对码输入框供手动核验；异源请求与 `Sec-Fetch-Site: cross-site` 请求继续返回 `403`。
- **修复首次冷启动默认通道、PNG 恢复卡导入覆盖与自有服务器主站（`vps_hub`）路由**：
  - `launcher/cli.py` 首次冷启动默认使用 `public_gateway`；第 1 类卡片补充临时快速通道与免登录固定网址双向切换按钮；导入恢复卡后先刷新磁盘配置再持久化以保留 `workers_dev` 地址，并支持 `secrets/srvus_ed25519` 变更自动重连。
  - `vps_hub` 模式下默认展开 6 位动态配对码输入框并加密同步本机 `secrets/auth.json`；`dispatcher.py` 在 `target="auto"` 下将相对路径默认路由至在线本地电脑工作区；修正文档中 `--tool-prefix` 与 `scan_host_global_skills` 参数说明及双发行包选择指引。

## [1.2.0] - 2026-11-26

围绕零登录固定连接体验、全链路零回环地址泄露、真实唤醒词复制与离线绿色包做收口加固。

### 新增与升级功能（Added & Changed）
- **第 1 类默认免登录连接支持持久化 `srv.us` 固定网址与 4 秒无感降级**：
  - `launcher/tunnels.py` 新增 `SrvUsSshTunnelSupervisor`，使用本机持久化的 `secrets/srvus_ed25519` 密钥连接 `srv.us:22`，获取跨关机重启不变的 `https://<hash>.srv.us/mcp` 地址；若当前网络封锁 `:22` 端口或节点维护，`launcher/daemon.py` 在 4 秒内无感降级至 `trycloudflare.com` 快速通道。
  - Studio 面板如实区分显示「免登录固定网址（`*.srv.us`）」与「免登录临时网址（`*.trycloudflare.com`，重启会变）」，临时态自动隐藏无效恢复卡导出按钮，并在首次完成网页端 OAuth 绑定后在顶部成功横幅提供一键开启开机自启开关。
- **Cloudflare 网关确定性命名、v2 全量恢复卡与代理切换 2 秒重连**：
  - `launcher/cf_workers_gateway.py` 由本机 `master_seed` 确定性派生默认 Worker 脚本名与子域，并将 `workers_dev_url`、`workers_tunnel_secret` 与 `srvus_ed25519` 私钥一并加密写入 PNG 身份恢复卡（兼容 v1 读取）；代理状态轮询缩短至 2 秒内自动重连。
  - `studio.js` 在点击连接地址复制按钮及切换至网页版 ChatGPT 视图时，对 `*.workers.dev` 地址同步执行浏览器 `/healthz` 直连预检并给出代理分流提示；第 2 类自定义域名框注明 `*.dpdns.org` 需先加入当前 Cloudflare 账号 Active Zone。
- **自有服务器 24 小时常驻主站完整工具包部署与回环桥接容错**：
  - `provision_vps_hub_oneclick` 升级为同步完整 16 核心工具包 `cosmos_mcp` 至 `/opt/cosmos-mcp-hub/` 常驻运行 `cosmos_mcp.launcher.app`（补齐增量 Caddy 配置裸 IP `default_sni`），本地电脑关机时服务器仍独立响应 Linux 工具与令牌续期。
  - `protocol/oauth.py` 当浏览器全局代理误将 `127.0.0.1` 送入代理时，验签通过后自动 `302` 跳回公网 `/consent` 页面并展开 6 位动态配对码输入框。
- **修复首句唤醒词字面量、消除建连期 `127.0.0.1` 泄露与实时安装进度展示**：
  - 修复 `studio.js` 首句唤醒测试词复制字面量问题，输出真实 `@Cosmos` 前缀以触发网页版 Gemini 连接器菜单；修正面板防休眠说明为「插电防自动休眠（笔记本合盖仍会断网）」，明确本地管理口令面板边界。
  - `daemon.py`、`tray.py`、`cli.py`、`app.py` 与 `server.json` 全面移除远程模式建连期间对 `http://127.0.0.1:8096/mcp` 的回退展示与剪贴板复制，未就绪前统一显示「正在建立加密连接…」。
  - `cli.py` 生成的 `一键启动_Cosmos_MCP.bat` 同步内置防 `WindowsApps\python.exe` 空壳多路径探测并清理残留客户端文案；`bootstrap.py` 改为实时输出中文依赖安装进度；`scripts/build_release.py` 支持 `--embed-python-dir` 与 `--wheels-dir` 离线绿色打包。

## [1.1.0] - 2026-11-26

围绕网页版 Google Gemini（含手机端）与网页版 ChatGPT 两个远程连接场景升级三类极简连接架构、裸机防劫持自举、工作区读写分层与 Office 文档安全修订能力。

### 新增与升级功能（Added & Changed）
- **定版 2 类网页宿主 × 3 类连接模式与同机免输口令授权**：
  - 统一收敛至网页版 Google Gemini（任务模式与同账号手机端，绑 `/mcp`）与网页版 ChatGPT（工作区账号绑 `/mcp`，个人账号绑只读 `/mcp/readonly`），清理面板与文档中将 `127.0.0.1` 或桌面 IDE 作为主入口的引导。
  - 新增第 1 类「一键上手就能用」（默认零登录开箱即连，公共网关未配置时自动回退免注册加密通道，同机浏览器通过 `/consent` -> `/oauth/local-bridge` -> `/consent/complete` 三步顶层回环桥接支持一键点击允许免输口令；授权成功即展示首句 `@连接器名` 测试口令一键复制横幅）。
  - 新增第 2 类「登录 Cloudflare 注册一下就行」（点击预填权限链接粘贴一次 API 令牌，约 3 秒自动认领 `*.workers.dev` 并部署免费 SQLite Durable Object 休眠中继网关与 17 字节二进制帧多路复用通道，获得终身固定 HTTPS 网址，令牌部署完即刻清零销毁）。
  - 升级第 3 类「自己的服务器和域名」（支持填写 Linux 服务器 IP 与 SSH 密码一键免明文植钥部署 24 小时常驻主站并自动签发证书，同时管理服务器与挂接的本地电脑，本地电脑关机时返回 `ERR_NODE_OFFLINE`；同时保留 Cloudflare Named Tunnel Token 与自有反向代理固定域名接入）。
- **裸机启动防微软商店 `WindowsApps\python.exe` 劫持与嵌入式绿色包支持**：
  - 升级 `一键启动_Cosmos_MCP.bat`、`start_cosmos_mcp.sh` 与 `launcher/bootstrap.py`：优先使用随包附带的 `python-embed` 绿色解释器或状态目录 `.venv`，严格剔除路径含 `\Microsoft\WindowsApps\` 的微软商店假空壳，自动扫描官方 Python `3.10` 至 `3.14`、Anaconda/Miniconda 及 `uv` 安装目录。
  - `scripts/build_release.py` 新增 `--embed-python-dir <PATH>` 可选参数，支持将解压后的官方 `python-embed` 打包进发行 ZIP 的 `python-embed/` 目录并自动开启 `._pth` 中的 `import site` 与源码检索路径。
- **原生文件夹选择框、目录父只读子读写分层与宿主技能默认隔离**：
  - 新增跨平台无阻塞原生文件夹选择框（Windows 64 位 `IFileOpenDialog`、macOS `osascript`、Linux `zenity`/`kdialog`）与常见代码目录自动发现。
  - 新增只读工作目录列表 `readonly_workspace_roots`，与可读写目录 `workspace_roots` 按最长路径前缀匹配权限（子进程沙盒同步校验并拦截只读目录写入返回 `ERR_READONLY_WORKSPACE`），支持外层总目录只读查阅、内部子项目正常读写。
  - 默认关闭宿主全局技能目录扫描开关（`scan_host_global_skills=False`），隔离本机 `~/.claude/skills`、`~/.codex/skills` 等外部目录，防止串读或污染宿主机全局技能。
- **零 C 扩展 `.docx` 与 `.xlsx` 安全修订能力**：
  - `edit_file` 新增纯标准库 `.docx` 跨 `<w:r>` 节点段落与表格文字替换（保留原有字体样式）及按需加载 `openpyxl` 的 `.xlsx` 单元格坐标修订；检测到文档正被 Word 或 Excel 打开锁表（如 `~$` 锁文件）时返回 `ERR_OFFICE_FILE_LOCKED` 自动保护，写前留存完整二进制快照并支持 `manage_files(action="undo")` 撤回。
- **多设备 `tool_prefix` 热更新、单入口 `target="auto"` 路由、Windows 托盘与笔记本电池保护**：
  - 解耦实例标识与可热更新的 `tool_prefix`，并在全量工具注入 `target="auto"` 参数支持服务器主站与本地电脑子节点按路径自动路由。
  - 新增纯标准库 `ctypes` 实现的 Windows 系统托盘四色状态圆点与快捷菜单，连续重连失败时发送无焦点抢占状态提示；`SleepInhibitor` 新增笔记本电源状态感知，交流电下保持防休眠在线，切换电池供电时自动解除防休眠并在唤醒或切网后约 1.5 秒自动重连。

## [1.0.0] - 2026-11-25

Cosmos MCP 首个公开正式版本发布。

### 新增功能（Added）
- **核心 16 项本地工具集**：内置默认开放的 16 项标准工具（`get_status`、`find_files`、`search_code`、`code_intel`、`read_file`、`batch_probe`、`web_research`、`skill_hub`、`edit_file`、`write_file`、`manage_files`、`workspace_memory`、`skill_manage`、`run_command`、`run_python`、`bg_command`），覆盖代码定位、AST 符号分析、只读批量探针、多处原子编辑、安全回收箱、无窗口命令与 Python 执行、跨会话记忆及本地技能管理。
- **网页端 OAuth 2.1 连接器与 `/mcp/readonly` 只读端点**：支持动态客户端注册（DCR）、`PKCE S256`、移动端友好的中文授权同意页与授权核对码；提供遵循 [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 受众隔离的 `/mcp/readonly` 纯只读端点，以及面向 Google 客户端的 `EmbeddedResource` 原生图片查看能力。
- **自包含运行环境与多模式启动器（`cosmos-mcp`）**：
  - 支持免注册 Cloudflare 临时加密通道（`--mode cloudflare`，默认 `--protocol http2` 兼容代理与校园网，支持 `COSMOS_CLOUDFLARED_MIRROR` 与 `COSMOS_CLOUDFLARED_BIN`）、Cloudflare Named Tunnel 固定域名通道（`--mode cloudflare_token --tunnel-token`）及自有服务器 SSH 反向隧道（`--mode vps`）。
  - 从免安装解压目录启动时自动同步源码至 `<状态目录>/app_src` 并创建 `<状态目录>/.venv`（支持 `COSMOS_WHEELHOUSE` 离线安装与可选 `docs` 依赖失败自动降级），移走原下载目录仍可正常开机自启与运行。
  - Windows 后台守护进程为 `uvicorn`、`cloudflared` 与 `ssh` 绑定父子同生共死 `JobObject`，并配置 `RotatingFileHandler` 轮转写入 `logs/server.log` 与 `logs/supervisor.log`。
- **一键启动脚本与容器沙盒隔离套件**：随仓库提供 `一键启动_Cosmos_MCP.bat`、`start_cosmos_mcp.sh`、`AGENTS.md`、`PRIVACY.md`、`manifest.json`、`server.json` 及 `sandbox/`（Docker 与 Windows Sandbox）隔离配置。
- **Cosmos Studio 本地可视化控制台与可选外设包**：提供五大功能页、单次口令会话解锁与本机一键切只读按钮；内置独立隔离配置目录的 `browser_use` 受管浏览器包与零焦点抢占的 Windows `cua_window` 桌面窗口操控包（非 Windows 平台自动跳过注册）。
- **全仓发行打包与隐私门禁（`scripts/build_release.py`）**：支持生成发行压缩包并对全仓代码、测试、脚本与文档执行 SHA-256 一致性及用户名、主机名、私人路径、私有扩展残留硬拦截检查。
