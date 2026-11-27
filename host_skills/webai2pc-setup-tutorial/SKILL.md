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
  - `一键只读`：免口令立即切入只读保护模式；切入后按钮变为 `恢复开发`，点击即可回到原开发档位。
  - `实战教程`：进入本地交互式图文教程页（`/tutorials`），自动带入当前就绪的 `/mcp` 与 `/mcp/readonly` 地址。
  - `设置`（快捷键 `Ctrl+,`）：进入左侧五分类设置中心（`连接与网关`、`环境与系统`、`工具与扩展`、`技能管理`、`外观与图标`），点击左上或顶栏 `← 返回主控台` 回到首页。
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

### （1）第 1 类 · 默认免配置：`一键上手免登录直连`
- 零注册零输入，默认通过本机持久 SSH 密钥连接免登录固定网址 `https://*.srv.us/mcp`（关机重启网址保持不变）。
- 若当前网络拦截 22 端口，4 秒内自动切换至内置临时快速通道 `https://*.trycloudflare.com/mcp`（电脑重启后域名会更新，可在卡片展开区内点 `使用一键上手模式` 或 `改用临时快速通道`）。

### （2）第 2 类 · 无服务器固定网址：`Cloudflare 专属固定网关`（免费终身固定推荐）
引导用户点击第 2 张卡片右侧 `配置 ▾` 展开面板，按三步完成部署：
1. **获取一次性 API 令牌**：点击卡片内的 `第 1 步：打开 Cloudflare 预填权限页（支持 Google 快捷登录）`。在打开的 Cloudflare 页面登录账号（权限模板已自动预填），滑到页面底部点击 `Continue to summary` -> `Create Token`，复制生成的 API 令牌。
2. **粘贴令牌与选填域名**：回到本地控制台，将令牌粘贴进 `第 2 步：粘贴 API 令牌（部署后立即销毁）` 输入框。若用户在 Cloudflare 已有激活域名（Active Zone），可在右侧 `选填：自定义域名（Active Zone，国内免切代理）` 填入子域名（如 `mcp.yourdomain.dpdns.org`）；若检测到多个 Cloudflare 账号，在下拉框选择目标账号。
3. **3 秒一键部署与自动销毁令牌**：点击 `一键部署并开启（约 3 秒）`。系统自动认领 `*.workers.dev` 子域并部署免费 Cloudflare Workers + SQLite Durable Object 休眠网关，生成终身固定的 `https://*.workers.dev/mcp`（及 `/mcp/readonly`）。
   - **安全与后续启停**：API 令牌在部署完成瞬间自动从内存与磁盘清零粉碎；后续开关连接只需拨动第 2 张卡片右上角开关，无需重填令牌。
   - **规则代理分流提示**：部分网络环境下浏览器直连 `*.workers.dev` 较慢；若首次在网页端跳转授权页加载缓慢，可将本机代理软件临时切为全局模式 10 秒完成首次授权绑定，或在卡片内填写自定义域名。

### （3）第 3 类 · 自有资产合一：`自有云服务器 24h 主站 或 自有固定域名`
点击第 3 张卡片右侧 `配置 ▾`，按两个子标签选型：
- **`自有服务器建 24h 主站`**：填入 `服务器公网 IP（必填）`，输入 `SSH 密码（已配密钥可留空，不落盘）` 或勾选 `使用本机默认 SSH 密钥免密登录`（展开高级项可填私钥路径、端口、用户名、选填绑定域名），点击 `一键部署 24h 主站并开启`。部署后单个连接器可通过 `target="auto"` 自动按路径操作 Linux 云服务器或本地电脑；本地电脑关机时云服务器仍 24 小时独立在线处理服务器任务并续期 OAuth。
- **`自有固定域名 / 通用 HTTPS 反代`**：填写 `固定公网 HTTPS 域名`，选填 `Cloudflare Named Tunnel 令牌` 或已有 SSH 反向隧道参数，点击 `保存并开启此网关`。

## 4. 换机免重绑：身份恢复卡 PNG 导出与导入

当用户准备重装系统或迁移到新电脑时，可在 `#settings/gateways` 第 1 张卡片展开区底部使用加密图片备份节点身份：
- **导出备份**：点击 `导出身份恢复卡 PNG`，在弹窗输入加密保护口令，点击 `生成并下载身份恢复卡 PNG` 保存图片（内含加密后的固定节点身份、`srv.us` 密钥、Cloudflare 网关与服务器节点配置）。
- **换机恢复**：在新电脑启动控制台后进入同一位置，点击 `导入恢复卡 PNG`，选择备份的 PNG 图片并输入导出时设置的口令，点击 `解密并恢复固定节点身份`，即可恢复原有固定连接网址，网页端连接器无需重新绑定。

## 5. 网页版 Gemini / ChatGPT 绑定、扩展包与系统设置

- **网页版 Gemini（任务模式与手机端同步）**：
  - **明确提醒用户**：`https://<域名>/mcp` **不是从浏览器地址栏直接打开的网址**，而是要粘贴进 Gemini 连接器配置栏里的 MCP 服务器地址。
- 引导用户直接打开 `https://gemini.google.com/customize/connectors`（或从 Gemini 首页左下角菜单点 `Personal Intelligence -> Connected Apps`），点击右上角 `+ Custom`，在 `Connect to an MCP server` 弹窗把 `https://<域名>/mcp` 粘贴到 **`MCP Server URL`** 配置栏（`Additional settings` 保持默认折叠），点击 **`Next`**。
- 跳转授权页后，同机浏览器直接点 `本机一键允许连接`；完成后回到 `https://gemini.google.com/customize/connectors` 点开连接器，将 `App actions` 总开关设为 `Always allow`。新建对话首句输入 `@Cosmos ...` 点选连接器标签即可唤醒，同账号手机端 Gemini App 自动同步。
- **网页版 ChatGPT（首次代连找 `Work` 模式 · 装好后日常用 `Chat` 模式省额度）**：
  - **首次添加与代填边界**：本地控制台在公网网关就绪后开放 `复制给 Work 模式帮我连接` 按钮（自动填入当前实际可用的 `/mcp` 或 `/mcp/readonly` 地址，严禁包含配对码、口令、令牌与本机路径）。用户需先在 ChatGPT 顶部切到 `Work` 模式再粘贴发送，由受控浏览器代填 `Plugins` 页面（`Chat` 模式无受控浏览器，无法操作 `chatgpt.com/plugins`，只能输出文字步骤供手动点击）。若在网页版 `Work` 云端受控浏览器内点 `Take over` 打开 `/consent` 授权页，因浏览器在 OpenAI 云端不在本机，需输入主控首页 `6` 位动态配对码并点 `Return control` 交回；若在本机浏览器手动打开左侧 `Plugins -> + -> Add custom MCP server`（或桌面版 `Work` 调本机 `@Chrome` / `@Edge` 扩展），名称填 `WebAI2PC`，粘贴地址（Team / Business / Enterprise / Edu 工作区填 `/mcp` 全功能，个人 Plus / Pro 受平台限制写工具时填 `/mcp/readonly` 只读），认证选 `OAuth`，点 `Create as a plugin` 后跳转 `/consent` 命中 `127.0.0.1` 回环直接点 `本机一键允许连接`，最后点击 `Install` 完成安装。
  - **日常调用分工与守则存放**：插件安装后全账号共享 `@WebAI2PC`，以调用 `pc_get_status`（`get_status`）实际成功作为接通标准。日常查改本地代码、修 Office 与跑无窗口测试推荐切回 `Chat` 模式输入 `@WebAI2PC`（响应快，走普通对话限额，零消耗 `Work / Codex` 智能体额度）；需要结合受控浏览器、跨邮件/Slack/网盘做长程交付或设置 `Scheduled Tasks` 定时任务时切 `Work` 模式输入 `@WebAI2PC`（消耗 `Work / Codex` 智能体额度）。操作守则在工作区/桌面端可存入原生 `Skills`，网页版 `Chat` 与 `Work` 模式均可放入 `Project Instructions` 或自定义指令。
- **开启可选扩展包与多机前缀（`#settings/tools`，传 `open_page="tools"`）**：
  - `受管浏览器包`（`browser` -> `pc_browser_use`）：在独立 `browser_profile` 目录运行隔离浏览器查阅网页与截图，不触碰用户个人浏览器窗口。
  - `桌面窗口操控包`（`desktop` -> `pc_cua_window`，仅 Windows）：基于离屏截图与后台消息辅助操作桌面窗口，检测到键鼠活跃时自动礼让。
  - `多设备工具前缀`：多台电脑同时接入同一聊天窗口时，可将 `tool_prefix` 分别改为 `desk`、`laptop` 等并点击 `保存工具前缀`。
- **Python 解释器、开机自启与外观（`#settings/runtime` 与 `#settings/appearance`）**：
  - 在 `环境与系统`（`open_page="runtime"`）可选择默认 Python / Conda 解释器、开启 `开机自动启动`、`插电防自动休眠` 与 `显示系统托盘状态图标`。
  - 在 `外观与图标`（`open_page="appearance"`）可切换浅深模式、4 套主题风格包与 4 套图标转向姿态。

## 6. 常见排障核对清单

- **缺少写入或执行工具**：核对主控首页左栏 `当前权限设置` 是否处于 `只读` 或 `仅改文件`，以及顶栏右侧是否显示 `恢复开发`；个人版 ChatGPT 绑定 `/mcp/readonly` 时仅暴露只读工具属于平台规则限制。
- **同机授权页未自动通过回环验证**：若在网页版 ChatGPT `Work` 模式的云端受控浏览器内点 `Take over` 打开授权页，或同机浏览器开启严格隐私隔离插件拦截了本地 `127.0.0.1` 回环跳转，引导用户在主控首页展开 `配对与已连会话`，复制 6 位动态配对码或 20 位固定备用口令填入授权页即可。
- **Gemini 频繁弹出单次工具确认框**：提醒用户打开 `https://gemini.google.com/customize/connectors`（或左下角菜单 `Personal Intelligence -> Connected Apps`）点开连接器开启 `Always allow` 总开关，不要在聊天流单张确认卡上点单次允许；需要查公开网页时使用本连接器的 `pc_web_research`，避免混调宿主内置搜索触发权限降级。
