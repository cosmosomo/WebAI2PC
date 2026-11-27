# 02. 网页版 ChatGPT 工作区与个人只读接入教程

本教程说明如何将本地 WebAI2PC（Cosmos MCP `v1.2.1`）接入网页版 ChatGPT，明确拆解**本机已登录浏览器插件页直绑**与**装好后 `Chat` / `Work` 模式日常干活分工**，涵盖工作区账号与个人 `Plus / Pro` 订阅账号的端点选择、控制台主按钮 **「复制地址并打开 ChatGPT 插件页」** 与旁侧 **「复制给 ChatGPT 接入 / 排障」** 的就绪门禁与零密钥边界、为什么旧 `ChatGPT Sites` 发布自动派生插件无需外部权限而对话内用 ZIP 新建外部 MCP 私有插件会报 `403`、[RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 受众隔离机制、`stateless_http` 无状态会话保持及常见报错处理。

## 一、两阶段能力边界：本机已登录浏览器直绑最快，日常干活优先 `Chat` 模式

根据 OpenAI 官方文档（[Browser 受控浏览器说明](https://learn.chatgpt.com/docs/browser)、[Chrome 浏览器扩展说明](https://learn.chatgpt.com/docs/chrome-extension)、[ChatGPT 使用指南](https://learn.chatgpt.com/docs/use-chatgpt)、[自定义 MCP 连接指南](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt) 与 [ChatGPT Work 与 Codex 额度说明](https://help.openai.com/en/articles/20001275-chatgpt-work-and-codex)）及真机实测，`Work` 模式与 `Chat` 模式在连接阶段和日常调用阶段职责不同：

1. **阶段一：首次添加自定义 MCP 插件（为什么本机浏览器直绑最快、为什么不要传外部 MCP ZIP）**
   - **首选在已登录本机浏览器直绑（免重登 Google、免配对码）**：网关就绪后点击本地控制台主按钮 **「复制地址并打开 ChatGPT 插件页」**，直接在你当前已登录 ChatGPT 的本机浏览器打开 `https://chatgpt.com/plugins` -> `＋ -> 添加自定义 MCP 服务器`（`Add custom MCP server`），名称填 `WebAI2PC`、认证选 `OAuth`、粘贴地址创建并点 `Install`。跳转 `/consent` 授权页时命中同机 `127.0.0.1` 回环，首屏直接点「本机一键允许连接（免输口令）」即可完成，无需搭建 `ChatGPT Sites` 中转，也避开了网页版 `Work` 模式云端隔离浏览器未登录需重过 Google 登录墙及无 `127.0.0.1` 回环的问题。
   - **实证对比：为什么旧 `ChatGPT Sites` 自动生成的插件无需外部 MCP 权限，而对话内 `@Plugin Creator` 用 ZIP 新建私有插件会报 `403`**：发布 `ChatGPT Sites` 时平台自动派生的插件连接的是同域受托端点（`*.chatgpt.site/mcp`），不走外部自定义 MCP 权限校验；而在聊天对话内让 `@Plugin Creator` 用 ZIP 新建绑定外部自定义 MCP 地址（如 `*.srv.us/mcp` 或 `*.workers.dev/mcp`）的私有插件受工作区外部 MCP 策略独立管控，未开启权限时会直接触发平台 `403`（`没有使用带 MCP 的插件权限`）拒绝。排查时应先在已登录本机浏览器打开 `https://chatgpt.com/plugins` 点 `＋ -> 添加自定义 MCP 服务器` 验证网页直绑路径；若网页端同样看不到该入口或仍报 `403`，再联系工作区管理员开启 **`Create plugins with MCPs`** 权限。
   - **委托探测或排障点「复制给 ChatGPT 接入 / 排障」**：该指令引导 ChatGPT 直接使用当前会话的原生插件管理/连接工具检查复用、协商 OAuth 元数据并调用 `pc_get_status` 核验（默认不拉起未登录云浏览器，也不新建中转服务，无需预设必须切到 `Work` 模式）；仅在若改用网页版 `Work` 云端浏览器 `Take over` 打开 `/consent` 授权页时才需手动填入本地控制台显示的 `6` 位动态配对码。
2. **阶段二：插件绑定安装完成后的日常调用（谁能调 `@WebAI2PC` 干活）**
   - 插件在 `Plugins` 创建并点 `Install` 安装完成后，同账号下 **`Chat` 模式与 `Work` 模式共享该已安装插件**，均可输入 `@WebAI2PC` 调用本机 MCP 工具：
   - **`Chat` 模式调 `@WebAI2PC`（日常本地开发首选）**：适合日常查改本地代码、原样修订 Word / Excel、跑无窗口命令与 Python 测试；响应快，走普通对话限额，**完全不扣减 `Work / Codex` 共享的智能体 Token 额度**。
   - **`Work` 模式调 `@WebAI2PC`（跨应用长程交付与定时任务）**：适合结合云端受控浏览器、跨邮件 / Slack / 网盘等多源信息生成长程多步交付物（PPT / 表格 / 报告），或设置定时与事件触发任务（`Scheduled Tasks`），消耗 `Work / Codex` 智能体额度。
   - **操作守则（`Skills` / `Instructions`）存放差异**：OpenAI 原生 `Skills` 在工作区、桌面端或插件包中可用；网页版 `Chat` 模式与 `Work` 模式均可将操作守则直接粘贴进 `Project（项目）Instructions` 或自定义指令中长期复用。

OpenAI 平台按**账号订阅档位**区分未上架自建远程 MCP 服务器的写入动作（`write actions`）放行规则，接入前按下表选择对应地址：

| 网页版 ChatGPT 账号类型 | 绑定连接地址 | 可用工具范围 | OAuth 权限范围与平台规则 |
| :- | :- | :- | :- |
| **工作区账号（Team / Business / Enterprise / Edu）** | `https://<域名>/mcp` | 默认开放全部 `16` 项核心工具（含代码与文本读写、PDF / `.pptx` 提取、`.docx` / `.xlsx` 原样修订、无窗口终端命令、Python 执行与后台任务管理；`L3` 工作区开发与 `L4` 全盘开发模式下可热开启 `browser` 与 `cua` 扩展包） | 平台对工作区开放完整自定义 MCP 读写支持（Full MCP），支持在 `Chat` 或 `Work` 模式下完整读写本地工程与运行测试 |
| **个人订阅账号（Plus / Pro）** | `https://<域名>/mcp/readonly` | 固定开放 `12` 项只读工具（全部声明 `readOnlyHint=True`），隐藏 `pc_edit_file`、`pc_write_file`、`pc_run_command`、`pc_run_python` 四项写入与执行工具 | 当平台策略对个人号自建远程 MCP 仅放行 `read/fetch` 权限时使用（若账号已获平台写权限灰度放行，也可先试 `/mcp`），权限范围锁定为 `server:read` |
| **免费个人账号（Free）** | 暂不支持 | 无 | 网页端暂未开放自定义远程 MCP 服务器添加入口 |

在 `/mcp/readonly` 只读端点下，服务端自动提供 `7` 项纯只读查询工具（`pc_get_status`、`pc_find_files`、`pc_search_code`、`pc_read_file`、`pc_batch_probe`、`pc_web_research`、`pc_skill_hub`），并将 `5` 项复合工具收窄为只读子动作投影：
1. `pc_code_intel`：保留 `outline`、`overview`、`repo_map`、`symbol`、`refs`、`diagnostics`（隐藏 `rename_symbol`）。
2. `pc_manage_files`：仅保留 `list` 查看回收箱与快照列表（隐藏移动、重命名、回收箱清理与撤回修改）。
3. `pc_bg_command`：仅保留 `status` 与 `list` 查看任务进度（隐藏启动与终止任务）。
4. `pc_workspace_memory`：仅保留 `read` 与 `search` 读取跨会话交接记录（隐藏写入记录）。
5. `pc_skill_manage`：仅保留 `list` 与 `trash_list` 列出技能清单（隐藏创建、安装与启停）。

## 二、标准直绑流程与零密钥排障协助

### 方式 A（推荐首选）：网关就绪后点「复制地址并打开 ChatGPT 插件页」在本机浏览器直绑

1. **一键复制地址并打开插件页（勿直接浏览器打开 `/mcp`）**：在本地控制台 `网页版 ChatGPT` 页签（或 `/tutorials` 第 2 章）等待网关就绪，工作区账号点击全功能栏的 **「复制地址并打开 ChatGPT 插件页」**（自动复制 `https://<域名>/mcp`），个人 `Plus / Pro` 只读点击只读栏的 **「复制地址并打开 ChatGPT 插件页」**（自动复制 `https://<域名>/mcp/readonly`；也可点 `仅复制地址` / `仅复制只读`）。**不要把 `/mcp` 地址直接粘贴到浏览器地址栏里打开**。
2. **添加自定义 MCP 服务器并点 `Install`**：在自动打开的已登录本机浏览器 `https://chatgpt.com/plugins` 页面点击 **`＋ -> 添加自定义 MCP 服务器`**（`Add custom MCP server`，无需开启旧版 `Developer Mode`），名称填写 `WebAI2PC`，`Connection` 粘贴刚才复制的 HTTPS 地址，认证保持 `OAuth`（服务端通过动态客户端注册自动协商，无需手动填写 Client ID 或密钥），勾选确认框创建插件，并在插件列表中点击 **`Install`（安装）**。
3. **同机浏览器 800ms 回环一键允许**：本机浏览器跳转到 `/consent` 授权页时，会在 `800ms` 内通过 `127.0.0.1` 回环桥接接口（`/oauth/local-bridge`）校验网关签名票据与 `Origin`，首屏直接展示 **「本机一键允许连接（免输口令）」**；异地浏览器、网页版 `Work` 云端浏览器或开启严格本地网络拦截的浏览器会自动展开输入框，填入本地控制台显示的 `6` 位动态配对码（或 `20` 位备用口令）即可完成授权。
4. **装好后切回 `Chat` 模式（或按需在 `Work` 模式）输入 `@WebAI2PC` 验证**：日常改代码跑脚本推荐新建 **`Chat` 模式**对话（不扣 `Work / Codex` 额度；跨应用长程交付与定时任务新建 `Work` 模式对话），在输入框键入 `@WebAI2PC` 选中插件，发送验证指令：
   ```text
   @WebAI2PC 请调用 pc_get_status 确认连接状态，并查看当前开放的工作目录与文件结构。
   ```
   写操作默认弹出确认卡片，在同一对话中可勾选记住批准，避免同会话后续步骤重复弹窗；长耗时命令（超过 `20` 秒）会自动转为 `pc_bg_command` 后台任务返回 `job_id` 供分段轮询。

### 方式 B（让 ChatGPT 原生探测接入 / 排障）：点击旁侧「复制给 ChatGPT 接入 / 排障」

本地控制台在公网 HTTPS 网关就绪后同步开放 **「复制给 ChatGPT 接入 / 排障」** 按钮，生成经真机验证的 4 步指令（无需预设切换到 `Work` 模式，引导 ChatGPT 优先使用当前会话原生插件管理/连接工具探测并核验，以工作区 `/mcp` 为例）：

```text
请帮我把 WebAI2PC 接入我当前选中的 ChatGPT 工作区/账号，并完成首次真实调用。

插件名称：WebAI2PC
MCP 地址：https://<本机生成的实际域名>/mcp
认证方式：OAuth
使用目标：ChatGPT Team / Business / Enterprise / Edu 工作区，授权后可在 Chat 和 Work 中通过 @WebAI2PC 使用该服务提供、且工作区允许的读写工具（日常在 Chat 调用不扣 Work / Codex 额度）。
本地控制台通道状态：公网 HTTPS 已就绪（通道：srv_us）

请按以下顺序执行：

1. 先检查当前工作区是否已经有指向这个 MCP 地址的 WebAI2PC 连接。有就复用，没有就优先用当前会话可用的插件管理、连接或创建工具接入现有 MCP 服务。不要默认打开云浏览器，也不要新建中转服务。只有原生工具无法完成某一步时，才说明卡点和可用的替代入口（例如让我在已登录本机浏览器打开 https://chatgpt.com/plugins 点 ＋ -> 添加自定义 MCP 服务器，或找管理员开启 Create plugins with MCPs 权限）。

2. 使用 OAuth，按服务端实际公布的元数据配置认证。如果需要我选择账号、同意授权，或由工作区管理员批准，请先完成你能做的配置，再把我带到需要操作的那一步。不要让我在聊天里粘贴密码、令牌或授权码。如果自动发现失败，告诉我具体失败在哪一步。

3. 授权并安装后，读取 WebAI2PC 实际公布的工具和参数。找到 pc_get_status 或 get_status，用实际参数调用一次，确认是否返回我电脑的主机名和系统。必须通过 WebAI2PC 调用，旧插件的结果或历史状态不能作为这次验收结果。

4. 最后分别告诉我：连接是否创建或复用、OAuth 是否完成、状态工具是否真实调用成功、在哪个模式完成验证。能分别在 Chat 和 Work 验证就分别验证，无法验证的模式标为未验证。列出已发现的工具和已知权限限制，首次验收只读状态，不改文件或系统设置。

请直接执行你能完成的步骤。只有遇到必须由我操作的步骤时才暂停，并告诉我在哪个页面、点哪个按钮。最后附上插件链接（如果有）和实际工具调用结果。
```

**信息最小化与原生探测边界**：
- **零敏感凭据外发**：复制文本仅包含可用 HTTPS 地址、通道状态与 4 步执行顺序，**严禁写入配对码、连接口令、令牌或本机文件路径**。
- **优先会话原生工具探测，不默认拉起云浏览器或建中转服务**：引导 ChatGPT 先检查复用或用原生插件连接工具探测 OAuth 元数据，遇到需用户授权或工作区 `403` 卡点时精准停在对应步骤并给出 `https://chatgpt.com/plugins` 本机直绑或开启 `Create plugins with MCPs` 权限指引。

## 三、RFC 8707 受众隔离与 stateless_http 免重复弹窗机制

1. **RFC 8707 双端点受众隔离**：服务端为 `/mcp` 与 `/mcp/readonly` 分别建立独立会话管理器与受保护资源元数据（`/.well-known/oauth-protected-resource/mcp` 与 `/.well-known/oauth-protected-resource/mcp/readonly`）。`/mcp/readonly` 签发的令牌在 `oauth.sqlite3`（仅存 SHA-256 摘要，零明文落盘）中锁定 `server:read` 作用域；若客户端持只读令牌向上访问 `/mcp`，鉴权层直接返回 HTTP `403`（`forbidden_cross_resource`）。
2. **`stateless_http` 无状态传输与并发刷新宽限**：两个端点均启用 `StreamableHTTPSessionManager(stateless=True, json_response=True)`，不依赖服务端内存会话 ID；内置原子刷新轮换与 `3600` 秒并发重放宽限缓存（`refresh_replay`），本地服务重启或 Cloudflare 休眠网关唤醒后原对话可直接继续调用。

## 四、常见报错与排查方法

| 报错现象或状态码 | 产生原因 | 排查与解决步骤 |
| :- | :- | :- |
| **「复制地址并打开 ChatGPT 插件页」与「复制给 ChatGPT 接入 / 排障」按钮置灰不可点** | 本地尚未开启公网 HTTPS 通道，或通道正在握手中 | 点击顶部连接卡「一键开启默认连接网关」（或前往 `#settings/gateways` 打开任一通道开关），待地址栏显示真实 `https://` 地址后按钮自动开放 |
| **对话内让 `@Plugin Creator` 传 ZIP 新建插件报 `403`（`没有使用带 MCP 的插件权限`），但旧 `ChatGPT Sites` 插件却能自动生成** | 旧 `ChatGPT Sites` 发布自动生成的插件绑定平台同域 `*.chatgpt.site/mcp`，无需外部自定义 MCP 权限；而用 ZIP 新建绑定外部域名（如 `*.srv.us/mcp`、`*.workers.dev/mcp`）的私有插件受外部 MCP 权限策略拦截 | 不要用 ZIP 上传外部 MCP 私有插件：先在已登录本机浏览器打开 `https://chatgpt.com/plugins` 点 `＋ -> 添加自定义 MCP 服务器` 粘贴地址验证网页直绑路径；若网页端同样无添加入口或仍报 `403`，请联系工作区管理员开启 **`Create plugins with MCPs`** 权限 |
| **需要 AI 操作浏览器代填时只回复文字步骤** | 当前处于 `Chat` 模式（无受控浏览器，无法操作页面） | 优先直接点控制台「复制地址并打开 ChatGPT 插件页」在本机浏览器粘贴完成；若确需受控浏览器代填，在 ChatGPT 顶部切到 `Work` 模式发送 |
| **在网页版 `Work` 云端浏览器 `Take over` 打开授权页提示输配对码或提示重登账号** | 网页版 `Work` 的受控浏览器是运行在 OpenAI 云端的独立未登录会话，既无本机登录态也无法访问本机 `127.0.0.1` 回环 | 推荐改在本机已登录浏览器打开 `https://chatgpt.com/plugins` 直绑（免输码）；若继续在云端浏览器授权，展开本地控制台首页 `配对与已连会话` 复制 `6` 位动态配对码填入，完成后点 `Return control` 交回 |
| **HTTP 401 Unauthorized / 提示重新授权** | 在本地控制台点击过「全部断开」、更换了临时隧道域名（如重启后 `*.trycloudflare.com` 变更），或重置了状态目录密钥 | 若临时域名已变，在 `Plugins` 打开 `WebAI2PC` 更新 URL（推荐升级 Cloudflare `*.workers.dev` 固定网关）；若固定域名未变，重新触发一次连接并点「本机一键允许连接」 |
| **开启扩展包或改前缀后未看到新工具** | ChatGPT 缓存了创建或会话初始化时的工具元数据快照 | 前往 `ChatGPT Plugins` 打开 `WebAI2PC` 详情点击 **Refresh（刷新）**（工作区已发布应用需管理员在工作区插件设置刷新），随后**新建对话**再输入 `@WebAI2PC` |
| **个人 Plus / Pro 账号测试 `/mcp` 时写操作被平台拦截** | 当前账号受 OpenAI 平台策略限制，自建 MCP 仅放行 `read/fetch` 工具 | 将连接地址改为只读端点 `https://<域名>/mcp/readonly` 重新保存并完成一次授权 |
| **HTTP 403 `forbidden_cross_resource`** | 持 `/mcp/readonly` 签发的只读令牌访问了 `/mcp` 主端点，触发 [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 受众不匹配拦截 | 核对插件配置的 URL 后缀与授权时一致；删除原连接后使用目标 URL 重新完成一次 OAuth 授权 |
| **返回 `ERR_READONLY_WORKSPACE` 或 `ERR_OFFICE_FILE_LOCKED`** | 目标路径位于只读参考目录（`readonly_workspace_roots`），或目标 `.docx` / `.xlsx` 正被本地 Word / Excel 打开占用 | 在本地控制台左栏将该目录设为「可读写」（或切至 `L4` 全盘开发）；遇到 Office 锁表时先保存关闭本地文档窗口再重试 |
