# 02. 网页版 ChatGPT 工作区与个人只读接入教程

本教程说明如何将本地 WebAI2PC（Cosmos MCP `v1.2.1`）接入网页版 ChatGPT，拆解**`Work` 模式一键配置**与**装好后 `Chat` / `Work` 模式日常分工**，涵盖工作区账号与个人 `Plus / Pro` 订阅账号的端点选择、预授权私密能力路径 `/c/<token>/mcp` 与 `/c/<token>/mcp/readonly` 的一键作废机制、[RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 受众隔离、`stateless_http` 无状态传输及常见报错处理。

## 一、两阶段能力边界：首次在 `Work` 模式一键配置，日常优先用 `Chat` 模式

1. **阶段一：在 `Work` 模式一键创建并安装 `WebAI2PC` 插件**
   - 网关就绪后，在本机控制台 `网页版 ChatGPT` 页签点击主按钮 **「复制一键配置提示词（发给 Work）」**（个人只读账号点 **「复制只读配置提示词（发给 Work）」**）。
   - 控制台会向本机回环接口 `POST /api/studio/chatgpt-oneclick` 申请高熵预授权私密连接地址（`https://<网关域名>/c/<token>/mcp` 或 `/c/<token>/mcp/readonly`），并生成包含 `@Plugin Creator` 指向的一键配置提示词。
   - 将复制的提示词粘贴发送给网页版 ChatGPT 的 **`Work` 模式**，由 `@Plugin Creator` 直接接入并安装 `WebAI2PC` 插件；如果当前工作区限制直接绑定外部域名 MCP（例如返回 `403`），提示词会自动引导 ChatGPT 通过私有 `ChatGPT Sites` 部署轻量 MCP 转发服务指向该预授权地址，自动生成同域配套插件并完成首次 `pc_get_status` 验证，全程零 `401` 且免手动配 OAuth 密钥。
   - 每枚一键连接地址仅在本地 `oauth.sqlite3` 中保存 SHA-256 哈希，并自动登记在控制台 **「已连会话」** 列表（标识为 `ChatGPT 一键连接` 或 `ChatGPT 一键连接（只读）`）。若不慎外发或需停用，点对应行 **「断开」**、**「全部断开」** 或执行 **「更换私密地址」** 均会在 1 秒内立即作废。
2. **阶段二：插件安装完成后的日常调用（`Chat` 与 `Work` 分工）**
   - 插件安装完成后，同账号下 **`Chat` 模式与 `Work` 模式共享该已安装插件**，均可输入 `@WebAI2PC` 调用本机 MCP 工具。
   - **`Chat` 模式调 `@WebAI2PC`（日常本地开发首选）**：适合日常查改本地代码、原样修订 Word / Excel、跑无窗口命令与 Python 测试；响应快，走普通对话限额，**不扣减 `Work / Codex` 智能体额度**。
   - **`Work` 模式调 `@WebAI2PC`（跨应用长程交付与定时任务）**：适合结合多源信息生成长程多步交付物（PPT / 表格 / 报告），或设置定时与事件触发任务（`Scheduled Tasks`），消耗 `Work / Codex` 额度。
   - **操作守则存放位置**：OpenAI 原生 `Skills` 在工作区、桌面端或插件包中可用；网页版 `Chat` 模式与 `Work` 模式均可将操作守则直接粘贴进 `Project Instructions` 或自定义指令中长期复用。

按账号订阅档位选择对应的端点与按钮：

| 网页版 ChatGPT 账号类型 | 控制台按钮与端点 | 可用工具范围 | 说明 |
| :- | :- | :- | :- |
| **工作区账号（Team / Business / Enterprise / Edu）** | 点「复制一键配置提示词（发给 Work）」生成 `/c/<token>/mcp`（标准 OAuth 端点为 `/mcp`） | 开放全部 `16` 项核心工具（含代码与文本读写、PDF / `.pptx` 提取、`.docx` / `.xlsx` 原样修订、无窗口终端命令、Python 执行与后台任务管理；`L3` 工作区开发与 `L4` 全盘开发模式下可热开启 `browser` 与 `cua` 扩展包） | 支持在 `Chat` 或 `Work` 模式下完整读写本地工程与运行测试 |
| **个人订阅账号（Plus / Pro）** | 点「复制只读配置提示词（发给 Work）」生成 `/c/<token>/mcp/readonly`（标准 OAuth 端点为 `/mcp/readonly`） | 固定开放 `12` 项只读工具（全部声明 `readOnlyHint=True`），隐藏 `pc_edit_file`、`pc_write_file`、`pc_run_command`、`pc_run_python` 四项写入与执行工具 | 适用于平台策略对自建远程 MCP 仅放行 `read/fetch` 的个人号，权限范围锁定为 `server:read` |
| **免费个人账号（Free）** | 暂不支持 | 无 | 网页端暂未开放自定义远程 MCP 接入 |

在 `/mcp/readonly`（含 `/c/<token>/mcp/readonly`）只读端点下，服务端自动提供 `7` 项纯只读查询工具（`pc_get_status`、`pc_find_files`、`pc_search_code`、`pc_read_file`、`pc_batch_probe`、`pc_web_research`、`pc_skill_hub`），并将 `5` 项复合工具收窄为只读子动作投影：
1. `pc_code_intel`：保留 `outline`、`overview`、`repo_map`、`symbol`、`refs`、`diagnostics`（隐藏 `rename_symbol`）。
2. `pc_manage_files`：仅保留 `list` 查看回收箱与快照列表（隐藏移动、重命名、回收箱清理与撤回修改）。
3. `pc_bg_command`：仅保留 `status` 与 `list` 查看任务进度（隐藏启动与终止任务）。
4. `pc_workspace_memory`：仅保留 `read` 与 `search` 读取跨会话交接记录（隐藏写入记录）。
5. `pc_skill_manage`：仅保留 `list` 与 `trash_list` 列出技能清单（隐藏创建、安装与启停）。

## 二、一键配置步骤与复制提示词说明

1. **等待网关就绪**：启动 WebAI2PC 并打开本地控制台 `http://127.0.0.1:8096`，切到 `网页版 ChatGPT` 页签，待地址栏显示真实 `https://` 公网地址后主按钮自动亮起。
2. **复制一键配置提示词**：工作区账号点击 **「复制一键配置提示词（发给 Work）」**，个人只读账号点击 **「复制只读配置提示词（发给 Work）」**。重复点击默认复用当前未过期、未吊销的同一枚高熵令牌，不会刷出重复会话。
3. **粘贴发给 ChatGPT `Work` 模式**：打开网页版 ChatGPT 切换到 `Work` 模式，直接粘贴发送。提示词内容如下（以工作区读写为例）：

```text
[@Plugin Creator](plugin://plugin-creator@openai-curated-remote?remotePluginId=plugin_connector_1p_e1a10c53223481918a42f1510ec46c1e) 帮我创建一个插件，把我的本地电脑服务 WebAI2PC 接入当前 ChatGPT 账号，并完成首次调用验证（请在 Work 模式下执行；装好后日常可在 Chat 模式通过 @WebAI2PC 直接调用，不扣 Work/Codex 额度）。

插件名称：WebAI2PC
MCP 地址：https://<本机网关域名>/c/<高熵预授权令牌>/mcp
服务说明：标准 Streamable HTTP MCP 服务（JSON-RPC 2.0），用于读写我本地授权目录的文件并执行本地开发工具；该专属地址已预授权，支持标准 Streamable HTTP（无状态 JSON-RPC 2.0 POST，无需额外配置 OAuth 令牌或密钥）；首次验证工具为 pc_get_status。

执行要求：
1. 请优先用 @Plugin Creator 直接接入上述 MCP 地址创建并安装 WebAI2PC 插件（如该地址启用了 OAuth 则按服务端公布的元数据自动协商，需要我点授权确认时提示我操作）。
2. 如果当前工作区限制直接绑定外部域名 MCP（例如返回 403），请直接通过私有 ChatGPT Sites 部署轻量 MCP 转发服务指向上述地址，用自动生成的同域配套插件完成接入（把上述专属地址保存在你的服务端配置中，不要对外公开）。
3. 插件就绪后，实际调用一次 pc_get_status，确认返回我电脑的主机名与当前工作区状态即可。

安全提醒：上方包含本机专属连接地址，仅限发给本人登录的 ChatGPT 账号，请勿发往群聊、论坛、公开 Issue 或转给他人（若不慎外发可在本地控制台一键更换作废）。
```

4. **装好后切回 `Chat` 模式日常调用**：确认首次 `pc_get_status` 返回本机主机名与工作目录后，日常写代码、修文档与跑测试可直接新建 **`Chat` 模式** 对话，输入 `@WebAI2PC` 调用本机工具（不消耗 `Work / Codex` 额度）。
5. **高级场景（本地 CLI 专用密钥）**：如需在无浏览器的本地 CLI 或自定义脚本中使用标准 `Authorization: Bearer` 访问，可展开控制台底部 **「已连会话 -> 高级：本地 CLI 专用密钥」** 在本机 `127.0.0.1` 单独签发 `cmcp_` 密钥，并可随时在会话列表中一键断开。

## 三、安全隔离与协议兼容机制

1. **高熵能力路径隔离与隐身 404**：`/c/<token>/mcp` 与 `/c/<token>/mcp/readonly` 仅允许访问 MCP 协议端点，严禁通过 `/c/<token>/` 访问 `/studio`、`/api/studio/*`、`/oauth/*` 等任何管理与认证路由（一律返回隐身纯文本 `404 Not Found`）。无效或已吊销令牌同样返回隐身 `404`。
2. **RFC 8707 双端点受众隔离**：只读一键令牌（或 `/mcp/readonly` OAuth 令牌）在 `oauth.sqlite3` 中锁定 `server:read` 作用域；若尝试访问全权限 `/c/<ro_token>/mcp` 或 `/mcp`，鉴权层直接返回 HTTP `403`（`forbidden_cross_resource`）。
3. **无状态传输与轻量转发兼容**：两个端点均启用 `StreamableHTTPSessionManager(stateless=True, json_response=True)`，不依赖服务端内存会话 ID；网关对已验签的 `/c/<token>/mcp` `POST` 请求在缺失 `Accept` 头时自动补齐 `Accept: application/json, text/event-stream`，避免轻量转发脚本触发 `406 Not Acceptable`。
4. **一键断开与轮换作废**：即使本机开启了 `/u/<24位私密路径>` 隐身模式，合法的 `/c/<token>/mcp` 仍平滑可用；当你在控制台点击对应会话 **「断开」**、**「全部断开」** 或执行 **「更换私密地址」** 时，所有旧 `/c/` 令牌立刻失效。

## 四、常见报错与排查方法

| 报错现象或状态码 | 产生原因 | 排查与解决步骤 |
| :- | :- | :- |
| **「复制一键配置提示词（发给 Work）」按钮置灰不可点** | 本地尚未开启公网 HTTPS 通道，或通道正在握手中 | 点击顶部连接卡「一键开启默认连接网关」（或前往 `#settings/gateways` 打开任一通道开关），待地址栏显示真实 `https://` 地址后按钮自动开放 |
| **HTTP 404 Not Found（访问 `/c/<token>/mcp`）** | 该一键连接令牌已在控制台被「断开」、「全部断开」或执行过「更换私密地址」 | 回到本机控制台重新点击「复制一键配置提示词（发给 Work）」生成新专属地址并更新插件 |
| **HTTP 403 `forbidden_cross_resource`** | 持只读令牌访问了全权限 `/mcp` 或 `/c/<ro_token>/mcp` 端点 | 工作区账号请点「复制一键配置提示词（发给 Work）」获取读写地址；个人只读账号保持使用 `/mcp/readonly` |
| **开启扩展包或改前缀后未看到新工具** | ChatGPT 缓存了创建或会话初始化时的工具元数据快照 | 在插件详情页点击 **Refresh（刷新）** 后新建对话再输入 `@WebAI2PC` |
| **返回 `ERR_READONLY_WORKSPACE` 或 `ERR_OFFICE_FILE_LOCKED`** | 目标路径位于只读参考目录（`readonly_workspace_roots`），或目标 `.docx` / `.xlsx` 正被本地 Word / Excel 打开占用 | 在本地控制台左栏将该目录设为「可读写」（或切至 `L4` 全盘开发）；遇到 Office 锁表时先保存关闭本地文档窗口再重试 |
