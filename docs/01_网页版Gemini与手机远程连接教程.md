# 01. 网页版 Gemini 与网页版 ChatGPT 连接指南（含手机端远控）

本指南说明如何启动 Cosmos MCP，按需开启 3 类连接方式接入 **网页版 Google Gemini（任务模式，含同账号手机端 Gemini App）** 与 **网页版 ChatGPT（对话模式）**，以及绑定完成后的首句唤醒与多设备协同方法。启动本地服务后也可直接打开内置交互式教程页 `http://127.0.0.1:8096/tutorials` 一键复制当前生效地址。

## 一、接入前确认宿主与账号条件

1. **网页版 Google Gemini（任务模式，含 Android / iOS 手机端 Gemini App）**：
   - 需要年满 `18+` 周岁的 Google AI Pro 或 Ultra 订阅账号，或已开启自定义连接器权限的 Google Workspace 账号（免费个人 Google 账号暂未开放网页端自定义连接器入口）。
   - 绑定主连接地址 `https://<域名>/mcp`。电脑端绑定一次后，登录同一 Google 账号的手机端 Gemini App 自动同步该连接器。
2. **网页版 ChatGPT（对话模式）**：
   - **工作区账号（Team / Business / Enterprise / Edu）**：绑定主连接地址 `https://<域名>/mcp`，可调用读写与命令执行工具。
   - **个人订阅账号（Plus / Pro）**：受平台策略限制仅支持只读工具，请绑定纯只读连接地址 `https://<域名>/mcp/readonly`。该端点按 [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 受众隔离固定开放只读查询能力，拒绝任何写入与执行请求。

## 二、裸机启动与 3 类连接方式选择

Windows 用户双击 `一键启动_Cosmos_MCP.bat`，macOS 与 Linux 用户运行 `./start_cosmos_mcp.sh`。启动器会优先使用随包附带的 `python-embed` 免安装解释器或已就绪的 `.venv`，自动跳过 Windows 11 默认 `PATH` 下的微软商店 `WindowsApps\python.exe` 空壳，扫描本机官方 Python `3.10` 至 `3.14`、Conda 与 `uv` 解释器，自动打开本地 `Cosmos Studio` 控制台。

网页端 AI 运行在云端机房，需通过标准 HTTPS 443 地址访问本机服务。控制台内 3 张连接卡片右上角均配独立开关，支持单开或多网关同时在线并存（互不中断），顶部连接栏自动展示当前选中的就绪网关 URL：

### 方式 1：一键上手就能用（零登录开箱即连）

适合首次体验与同机快速验证，无需注册云账号或准备域名：
- 启动后默认优先使用本机持久密钥连接免登录固定网址（如 `https://xxxxx.srv.us/mcp`，关机重启网址不变）；若当前网络限制 22 端口，4 秒内自动切换至内置快速通道（`https://*.trycloudflare.com`）生成可用 HTTPS 地址，也可在卡片内手动切换。
- 在同一台电脑的浏览器中从网页版 Gemini 或 ChatGPT 跳转到授权页时，系统通过本机顶层回环桥接校验同机身份，直接点击「本机一键允许连接（免输口令）」即可完成绑定，免去复制粘贴连接口令；若在手机或另一台电脑上授权，核对页面配对码或粘贴口令即可。
- 若当前通道处于 `*.trycloudflare.com` 临时地址，电脑关机重启后域名会变化；可点击卡片按钮重试或恢复连接免登录固定网址，或切换至方式 2、方式 3。

命令行启动示例（内网或离线环境可通过 `COSMOS_CLOUDFLARED_BIN`、`COSMOS_CLOUDFLARED_MIRROR`、`COSMOS_WHEELHOUSE` 指定本地缓存）：

```bash
cosmos-mcp start --workspace D:\Projects\my-app
```

### 方式 2：登录 Cloudflare 注册一下就行（3 秒自动部署终身固定网址）

适合没有自有服务器与域名的长期日常使用及手机远程控机：
1. 在本地 `Cosmos Studio` 控制台选择第 2 类连接卡片，点击页面预填好最小权限的 Cloudflare 令牌创建链接并登录账号。
2. 生成 API 令牌后复制粘贴回控制台输入框并点击部署。
3. 后台在约 3 秒内自动认领账号下的 `*.workers.dev` 子域，部署免费 SQLite Durable Object 休眠中继网关并生成固定 HTTPS 地址（如 `https://your-worker.your-subdomain.workers.dev/mcp`）；部署完成后 API 令牌立即清零销毁，不在磁盘留存明文。
4. 后续可直接拨动卡片右上角独立开关启停连接（无需重填令牌），可与方式 1 或方式 3 同时开启；电脑重启、休眠唤醒或切换手机热点时，本机通过纯标准库出站 443 WebSocket 自动重连网关，网页版 Gemini 与 ChatGPT 中的连接器地址终身无需重填。

### 方式 3：自己的服务器和域名（一键部署 24 小时主站或绑定自有域名）

适合拥有 Linux 云服务器或自有域名的用户，合并提供两种接入路径：
1. **填写服务器 IP 与 SSH 密码或私钥一键建站**：
   - 在控制台填写云服务器公网 IP 与 SSH 端口，支持使用 SSH 密码（仅当次内存使用不落盘）、填写本地 SSH 私钥路径（如 `~/.ssh/id_ed25519`）或勾选本机默认 SSH 密钥免密登录（有域名可一并填写，无域名时自动签发公网访问证书）。
   - 系统自动通过一次性免明文密钥交换在服务器上部署 24 小时常驻主站（内存小于 256MB 的轻量实例自动补充交换分区），同时纳管服务器目录与本地电脑目录；本地电脑关机期间，网页端仍可正常操作服务器文件，访问本地电脑路径时返回清晰的离线提示（`ERR_NODE_OFFLINE`）。
2. **绑定自有固定域名（Cloudflare Named Tunnel 或自有反向代理）**：
   - 拥有托管在 Cloudflare 的域名时，可在面板填入固定隧道令牌，或通过命令行传入 `--tunnel-token` 并开启登录自启：
     ```bash
     cosmos-mcp start --mode cloudflare_token --tunnel-token <粘贴你的TOKEN> --public-url https://mcp.example.com --autostart
     ```
   - 若服务器已自行配置反向代理或 SSH 反向映射，也可使用 `--mode vps` 或填入自有固定 HTTPS 地址：
     ```bash
     cosmos-mcp start --mode vps --vps-ssh user@vps.example.com --vps-remote-port 18096 --public-url https://mcp.example.com --autostart
     ```

## 三、绑定完成后的设置与首句唤醒方法

### 1. 网页版 Google Gemini（任务模式与手机端 App）

1. 打开网页版 Gemini，在左侧栏依次点击 `Customize（自定义） -> Connectors（连接器） -> + Custom（添加自定义）`。
2. `Name` 填写 `Cosmos`，`URL` 粘贴控制台顶部显示的 `https://<你的域名>/mcp`（若展开 `Additional settings`，`Client ID` 与 `Client Secret` 均保持留空），点击连接并在弹出的授权页确认允许。
3. **开启免审批总开关**：在 `Connectors（连接器）` 列表点开 `Cosmos`，将 `App actions` 总开关设为 `Always allow（始终允许）`。请勿在聊天对话流弹出的单张工具确认卡片上单独点允许，单卡点击会按单工具覆盖并导致其余工具退回逐次确认。
4. **导入操作守则**：在控制台点击「复制 AI 操作守则（推荐存入 Skills）」（或复制仓库 `host_skills/SKILL.md` 全文），保存到网页版 Gemini 左侧栏 `Customize（自定义） -> Skills（技能）`。
5. **首句敲 `@Cosmos` 唤醒**：新建对话后，在输入框首句敲 `@Cosmos` 并选中弹出的 `Cosmos` 标签，例如发送：
   ```text
   @Cosmos 帮我看看当前工作目录里有哪些文件
   ```
   授权刚完成时，控制台顶部绿色已连接横幅提供「一键复制首句唤醒测试词」按钮（Windows 托盘右键菜单提供「复制首句唤醒词」），可直接复制粘贴发送。

### 2. 网页版 ChatGPT（`Chat` 模式与 `Work` 模式通用）

1. **一键引导或手动添加插件**：在本地控制台 `网页版 ChatGPT` 页签等待网关就绪后，可直接点 **「复制给 ChatGPT 帮我连接」** 发给当前对话（含实际可用地址，不含配对码与本机路径）；或手动在网页版 ChatGPT 左侧栏打开 `Plugins -> + -> Add custom MCP server`，名称填 `WebAI2PC`，工作区账号（Team / Business / Enterprise / Edu）填入 `https://<你的域名>/mcp`，个人 Plus / Pro 账号受平台限制写工具时填入 `https://<你的域名>/mcp/readonly`，点击 `Create as a plugin` 并完成安装与本机一键允许授权。
2. **输入 `@WebAI2PC` 唤醒并以 `pc_get_status` 验证**：新建 `Chat`（日常交互开发不扣 `Work / Codex` 智能体额度）或 `Work` 对话，在输入框键入 `@WebAI2PC` 选中插件，调用一次 `pc_get_status` 确认已接通电脑。

## 四、手机远控、多设备前缀与跨机路由

1. **手机远程控机与笔记本电源管理**：
   - 使用免登录固定网址、方式 2 或方式 3 固定网址并开启开机自启后，外出时打开同账号手机端 Gemini App 发送 `@Cosmos 运行测试套件并汇报失败项`，耗时任务会自动转为 `pc_bg_command` 后台运行。
   - Windows 笔记本接入交流电时默认开启防休眠保持在线；拔掉电源使用电池供电时自动解除防休眠保护电池续航，开盖唤醒或切换网络后在约 1.5 秒内自动恢复连接。
2. **多连接器 `tool_prefix` 与单入口 `target="auto"` 跨机路由**：
   - **多连接器前缀区分**：单台电脑保持默认 `pc` 即可；多台独立电脑接入同一对话时，可在控制台或启动参数设置不同的 `tool_prefix`（如 `--tool-prefix desk`、`--tool-prefix laptop`，注：`--prefix` 参数用于同一台电脑运行多实例时的配置槽位隔离），在同一聊天窗口分别调用 `desk_read_file` 与 `laptop_run_python`。
   - **单入口自动路由**：采用方式 3 自有服务器 24 小时主站挂接本地电脑子节点时，只需在网页端绑定主站一个连接器；所有工具默认带 `target="auto"`，按传入路径自动路由到服务器或对应本地电脑，也可显式传 `target="server"`、`target="local"` 或节点名称定向执行。
