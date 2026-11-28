# AGENTS.md（项目架构与网页连接器维护规范）

> **帮用户安装 / 配置 WebAI2PC 的 AI Agent 请先读**：[`docs/AI_SETUP_GUIDE.md`](docs/AI_SETUP_GUIDE.md)（含本地 Agent 自动下载启动流程与网页版 Gemini `https://gemini.google.com/customize/connectors` / ChatGPT `Plugins` 零分叉绑定步骤）。


本文档说明 Cosmos MCP 的目标宿主范围、多网关与安全分层契约、四层模块职责以及非交互运维与测试门禁。

## 一、目标宿主与产品边界

- **唯一目标宿主场景**：聚焦 **网页版 Google Gemini（任务模式，含同账号手机端 Gemini App）** 与 **网页版 ChatGPT（通过 `Plugins -> + -> Add custom MCP server` 创建并 `Install` 安装 `WebAI2PC` 插件：首次自动代填仅限具备受控浏览器的 `Work` 模式，`Chat` 模式无受控浏览器不可代连；装好后全账号互通，日常本地开发在 `Chat` 模式输入 `@WebAI2PC` 调用不扣减 `Work / Codex` 智能体额度，跨应用长程交付与定时任务在 `Work` 模式调用）** 两个远程 HTTPS 场景，不面向本地桌面 CLI 或 IDE 客户端做配置导流。
- **双端点受众隔离与零明文 Token 留存**：主端点 `https://<域名>/mcp` 提供工作区读写与无窗口执行能力（供网页版 Gemini 任务模式及网页版 ChatGPT Team / Business / Enterprise / Edu 工作区账号绑定，在 `Chat` 模式下作为本地 Agent 运行不扣 `Work / Codex` 额度）；纯只读端点 `https://<域名>/mcp/readonly` 按 [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 受众隔离固定暴露 `server:read` 只读工具集（供网页版 ChatGPT 个人 Plus / Pro 账号在平台限制写操作时挂载）。`oauth.sqlite3` 仅保存令牌 SHA-256 摘要主键，Cloudflare 部署 API Token 部署后即刻清零销毁，零明文 Token 落盘。
- **多网关独立开关并存**：内置「系统内置 OpenSSH 免登录直连」（`--mode openssh`，兼容 `public_gateway`：本机持久 `Ed25519` 密钥 + OpenSSH `SSHv2` `ChaCha20-Poly1305 / AES-256-GCM` 加密反向隧道 + `srv.us` 公网 `HTTPS/TLS` 固定地址 + 本地隔离垫片与 `OAuth 2.1 PKCE S256` 二次鉴权，22 端口受阻 10 秒自动回退 `trycloudflare.com`）、`Cloudflare Workers` SQLite Durable Object 固定网关与 `24h Linux VPS` 常驻主站 / 自有固定域名三类连接方式，支持在控制台独立开关同时在线并存。
- **四档安全模式与只读参考目录**：支持 `L3` 工作区内顺畅开发（默认）、`L4` 全盘顺畅开发（不限目录）、`L2` 仅改文件禁跑命令、`L1` 只读浏览模式，并支持外层只读参考目录（`readonly_workspace_roots`）与内部可读写工作目录（`workspace_roots`）按最长路径前缀匹配权限。
- **无窗口静默执行**：Windows 平台子进程统一附带 `CREATE_NO_WINDOW`（`0x08000000`）与 `stdin=subprocess.DEVNULL`，全程保持零系统弹窗与零前台焦点抢占。

## 二、四层单向模块结构与 16 项核心工具

1. `src/cosmos_mcp/core/`：纯标准库底层能力，包含四档安全策略与只读参考目录护栏（`guard.py` / `config.py`）、写前自动快照与安全回收箱（`fs_tx.py`）、代码检索与符号大纲（`code.py` / `search_nav.py`）、图片缩放与 PDF / `.docx` / `.xlsx` / `.pptx` 文档提取及修订（`fs.py`）与无窗口后台进程管理（`proc.py`）。
2. `src/cosmos_mcp/protocol/`：Streamable HTTP 无状态传输层、OAuth 2.1 动态客户端注册（DCR）与 `PKCE S256`、中文 `/consent` 本机回环免密放行与配对码确认页、Google 客户端 `EmbeddedResource` 二进制图片封装及 16 项标准工具分发（`get_status`、`find_files`、`search_code`、`code_intel`、`read_file`、`batch_probe`、`web_research`、`skill_hub`、`edit_file`、`write_file`、`manage_files`、`workspace_memory`、`skill_manage`、`run_command`、`run_python`、`bg_command`）。
3. `src/cosmos_mcp/capabilities/` 与 `src/cosmos_mcp/packs/`：开放工作区 `.agents/skills` 与受管技能库检索、三级 AST 供应链安全体检，以及按需热开启的受管浏览器扩展包（`browser_use`）和 Windows 离屏窗口操控包（`cua_window`）。
4. `src/cosmos_mcp/studio/` 与 `src/cosmos_mcp/launcher/`：本地 `Cosmos Studio` 控制台、内置交互式教程中心（`/tutorials`）、四轴可替换外观风格层与 4 套 IP 图标转向包（`static/themes.css`、`static/brand-packs.js` 与 `.interface-design/system.md`）、自包含 `<状态目录>/.venv` 启动环境及多网关守护进程。

## 三、非交互通道部署与发版门禁命令

在未安装的源码目录或解压目录内运行时，设置 `PYTHONPATH=src` 与 `PYTHONDONTWRITEBYTECODE=1` 后调用 `python -B -m cosmos_mcp.launcher.cli <子命令> --json`：

```bash
# 1. 环境预检与运行状态查看（--prefix 用于多实例配置槽位隔离，默认 pc）
cosmos-mcp doctor --json
cosmos-mcp status --json

# 2. 启动面向网页版 Gemini / ChatGPT 的加密 HTTPS 连接通道（首次默认系统内置 OpenSSH 免登录直连：--mode openssh，兼容 public_gateway，Ed25519 + SSHv2/TLS + OAuth 2.1 PKCE S256）
cosmos-mcp agent-setup --mode openssh --workspace "<目标项目绝对路径>" --no-browser --json
cosmos-mcp agent-setup --mode cloudflare --workspace "<目标项目绝对路径>" --no-browser --json
cosmos-mcp agent-setup --mode cloudflare_token --tunnel-token "<TUNNEL_TOKEN>" --public-url "https://mcp.example.com" --workspace "<目标项目绝对路径>" --autostart --no-browser --json
cosmos-mcp agent-setup --mode vps --vps-ssh user@vps.example.com --vps-remote-port 18096 --public-url "https://mcp.example.com" --workspace "<目标项目绝对路径>" --autostart --no-browser --json
cosmos-mcp agent-setup --mode custom --public-url "https://mcp.example.com" --workspace "<目标项目绝对路径>" --no-browser --json
# 已在 Studio 或恢复卡完成 Cloudflare Workers / 自有服务器 24h 主站部署并保存密钥后，可按模式启动：
cosmos-mcp agent-setup --mode workers_dev --public-url "https://your-worker.your-subdomain.workers.dev" --workspace "<目标项目绝对路径>" --autostart --no-browser --json
cosmos-mcp agent-setup --mode vps_hub --public-url "https://mcp.example.com" --workspace "<目标项目绝对路径>" --autostart --no-browser --json

# 仅本机回环隔离自检（指定独立端口、禁用托盘且不打开浏览器，不用于网页端绑定）
cosmos-mcp agent-setup --mode local --port 18596 --workspace "<目标项目绝对路径>" --no-browser --no-tray --json

# 3. 四档权限、工具前缀、只读参考目录与全局技能扫描热切换，以及令牌吊销与卸载
cosmos-mcp permissions --tier L4 --json
cosmos-mcp permissions --tier L1 --json
cosmos-mcp permissions --tool-prefix desk --json
cosmos-mcp permissions --readonly-workspace "<只读参考目录绝对路径>" --scan-host-global-skills false --json
cosmos-mcp permissions --enable-pack browser,desktop --json
cosmos-mcp permissions --reset-password --json
cosmos-mcp permissions --revoke-all --json
cosmos-mcp stop --json
# 常规卸载（默认保留 .undo_history 与回收箱） / 彻底销毁凭据并清空状态目录（--purge -y）
cosmos-mcp uninstall -y --json
cosmos-mcp uninstall --purge -y --json

# 本地自动化调用身份恢复卡导出 / 导入接口（本机回环携带 Bearer local_api_token 免随机 CSRF 校验）
# POST http://127.0.0.1:8096/api/studio/identity/export_png  Header: Authorization: Bearer <local_api_token>

# 4a. 日常小改动与并行子任务（默认仅跑本改动直接对应的定向单测，不跑全仓 tests/ 与 build_release.py）
python -B -m pytest -p no:cacheprovider tests/<受影响测试文件>.py -k "<目标用例关键词>"

# 4b. 全仓测试套件与发行包一致性检查（仅在合流主干或公开发版前由主控统一执行一次，禁止每个小任务/子任务重复跑）
python -B -m pytest -p no:cacheprovider tests/
python -B scripts/build_release.py --check
python -B scripts/build_release.py --embed-python-dir "<官方python-embed目录>" --output dist/Cosmos-MCP-v1.2.1-win64-full.zip --check
```
