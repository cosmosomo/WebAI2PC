# 02. 网页版 ChatGPT 工作区与个人只读接入教程

本教程说明如何将本地 WebAI2PC（Cosmos MCP `v1.2.1`）接入网页版 ChatGPT，拆解 **`Work` 模式 `@Plugin Creator` 标准 OAuth 2.1 一键接入** 与 **装好后 `Chat` / `Work` 模式日常分工**，涵盖工作区账号与个人 `Plus / Pro` 订阅账号的端点选择（`/mcp` 与 `/mcp/readonly`）、同机与云端受控浏览器授权差异、[RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 受众隔离、`stateless_http` 无状态传输及常见报错处理。

## 一、两阶段能力边界：首次在 `Work` 模式一键配置，日常优先用 `Chat` 模式

1. **阶段一：在 `Work` 模式通过 `@Plugin Creator` 按标准 OAuth 2.1 接入 `WebAI2PC`**
   - 公网网关就绪后，在本机控制台 `网页版 ChatGPT` 页签点击主按钮 **「复制一键配置提示词（发给 Work）」**（个人只读账号点击 **「复制只读配置提示词（发给 Work）」**，也可点击旁侧 `仅复制地址` 手动配置）。
   - 控制台基于当前选中的就绪公网网关生成指向标准 OAuth 2.1 端点（`https://<网关域名>/mcp` 或 `https://<网关域名>/mcp/readonly`）的 `@Plugin Creator` 一键配置提示词（不含任何配对码、口令、密钥或本地文件路径，无需手动填写 Client ID / Secret 或额外部署中转服务）。
   - 将复制的提示词粘贴发送给网页版 ChatGPT 的 **`Work` 模式**，由 `@Plugin Creator` 读取服务端公布的 `/.well-known/oauth-protected-resource` 与 `/.well-known/oauth-authorization-server` 元数据，通过动态客户端注册（DCR）与 `PKCE S256` 自动协商 OAuth 2.1 认证并创建安装 `WebAI2PC`。
   - **同机浏览器与 `Work` 云端浏览器授权差异**：弹出 `/consent` 授权确认页时，若在同机浏览器打开，页面命中 `127.0.0.1` 回环桥接并直接显示 **「本机一键允许连接（免输口令）」**；若在网页版 `Work` 云端受控浏览器内点击 `Take over` 打开授权页，因云端浏览器不在本机，需展开本地控制台主控首页 **「配对与已连会话」** 填入显示的 `6` 位动态配对码，授权后点 `Return control` 交回并完成首次 `pc_get_status` 验证。
2. **阶段二：安装完成后的日常调用（`Chat` 与 `Work` 分工）**
   - 连接器安装完成后，同账号下 **`Chat` 模式与 `Work` 模式共享该连接器**，均可输入 `@你在连接器里填写的名称`（默认 `@WebAI2PC`）调用本机 MCP 工具。
   - **`Chat` 模式日常调用（本地开发首选）**：适合日常查改本地代码、原样修订 Word / Excel、跑无窗口命令与 Python 测试；响应快，走普通对话限额，**不扣减 `Work / Codex` 智能体额度**。
   - **`Work` 模式调用（跨应用长程交付与定时任务）**：适合结合多源信息生成长程多步交付物（PPT / 表格 / 报告），或设置定时与事件触发任务（`Scheduled Tasks`），消耗 `Work / Codex` 额度。
   - **操作守则存放位置**：OpenAI 原生 `Skills` 在工作区、桌面端或插件包中可用；网页版 `Chat` 模式与 `Work` 模式均可将操作守则直接粘贴进 `Project Instructions` 或自定义指令中长期复用。

按账号订阅档位选择对应的端点与按钮：

| 网页版 ChatGPT 账号类型 | 控制台按钮与标准 OAuth 端点 | 可用工具范围 | 说明 |
| :- | :- | :- | :- |
| **工作区账号（Team / Business / Enterprise / Edu）** | 点「复制一键配置提示词（发给 Work）」绑定 `https://<域名>/mcp` | 开放全部 `16` 项核心工具（含代码与文本读写、PDF / `.pptx` 提取、`.docx` / `.xlsx` 原样修订、无窗口终端命令、Python 执行与后台任务管理；`L3` 工作区开发与 `L4` 全盘开发模式下可热开启 `browser` 与 `cua` 扩展包） | 支持在 `Chat` 或 `Work` 模式下完整读写本地工程与运行测试 |
| **个人订阅账号（Plus / Pro）** | 点「复制只读配置提示词（发给 Work）」绑定 `https://<域名>/mcp/readonly` | 固定开放 `12` 项只读工具（全部声明 `readOnlyHint=True`），隐藏 `pc_edit_file`、`pc_write_file`、`pc_run_command`、`pc_run_python` 四项写入与执行工具 | 适用于平台策略对自建远程 MCP 仅放行 `read/fetch` 的个人号（若账号已获写工具放行也可试 `/mcp`），权限范围锁定为 `server:read` |
| **免费个人账号（Free）** | 暂不支持 | 无 | 网页端暂未开放自定义远程 MCP 接入 |

在 `/mcp/readonly` 只读端点下，服务端共开放 `12` 项只读工具（`7` 项纯只读查询工具 + `5` 项收窄为只读子动作的复合工具）：其中 `7` 项纯只读查询工具为（`pc_get_status`、`pc_find_files`、`pc_search_code`、`pc_read_file`、`pc_batch_probe`、`pc_web_research`、`pc_skill_hub`），并将 `5` 项复合工具收窄为只读子动作投影：
1. `pc_code_intel`：保留 `outline`、`overview`、`repo_map`、`symbol`、`refs`、`diagnostics`（隐藏 `rename_symbol`）。
2. `pc_manage_files`：仅保留 `list` 查看回收箱与快照列表（隐藏移动、重命名、回收箱清理与撤回修改）。
3. `pc_bg_command`：仅保留 `status` 与 `list` 查看任务进度（隐藏启动与终止任务）。
4. `pc_workspace_memory`：仅保留 `read` 与 `search` 读取跨会话交接记录（隐藏写入记录）。
5. `pc_skill_manage`：仅保留 `list` 与 `trash_list` 列出技能清单（隐藏创建、安装与启停）。

## 二、一键配置步骤与复制提示词说明

1. **等待网关就绪**：启动 WebAI2PC 并打开本地控制台 `http://127.0.0.1:8096`，切到 `网页版 ChatGPT` 页签，待地址栏显示真实 `https://` 公网地址后主按钮自动亮起。
2. **复制一键配置提示词**：工作区账号点击 **「复制一键配置提示词（发给 Work）」**，个人只读账号点击 **「复制只读配置提示词（发给 Work）」**。
3. **粘贴发给 ChatGPT `Work` 模式**：打开网页版 ChatGPT 切换到 `Work` 模式，直接粘贴发送。提示词内容如下（以工作区读写 `/mcp` 为例）：

```text
[@Plugin Creator](plugin://plugin-creator@openai-curated-remote?remotePluginId=plugin_connector_1p_e1a10c53223481918a42f1510ec46c1e) 帮我把本地电脑的 WebAI2PC 服务接入当前 ChatGPT 账号，并完成首次调用验证（请在 Work 模式下执行；安装完成后日常可在 Chat 模式通过 @WebAI2PC 直接调用，不扣 Work/Codex 额度）。

插件名称：WebAI2PC
MCP 地址：https://<本机网关域名>/mcp
认证方式：标准 OAuth 2.1（服务端已发布 /.well-known/oauth-protected-resource 与 /.well-known/oauth-authorization-server 元数据，支持动态客户端注册与 PKCE，无需手动填写 Client ID / Secret）
服务说明：标准 Streamable HTTP MCP 服务（JSON-RPC 2.0），用于读写我本地授权目录的文件并执行本地开发工具；首次验证工具为 pc_get_status。

执行步骤：
1. 使用 @Plugin Creator 直接连接上述 MCP 地址，选择标准 OAuth 认证创建并安装 WebAI2PC 插件。
2. 弹出 OAuth 授权确认页时提示我点击允许（同机浏览器可直接点「本机一键允许连接」）。
3. 授权安装完成后，实际调用一次 pc_get_status，确认返回我电脑的主机名与当前工作区状态即可。

安全提醒：上方包含本机连接地址，仅限在本人登录的 ChatGPT 账号中使用，请勿转发至群聊、论坛或公开 Issue。
```

4. **装好后切回 `Chat` 模式日常调用**：确认首次 `pc_get_status` 返回本机主机名与工作目录后，日常写代码、修文档与跑测试可直接新建 **`Chat` 模式** 对话，输入 `@你在连接器里填写的名称`（默认 `@WebAI2PC`）调用本机工具（不消耗 `Work / Codex` 额度）。
5. **高级场景（本地 CLI 专用密钥）**：如需在无浏览器的本地 CLI 或受限环境中通过标准 `Authorization: Bearer` 访问，可展开主控首页 **「配对与已连会话 -> 高级：本地 CLI 专用密钥」** 在本机 `127.0.0.1` 单独签发可吊销 `cmcp_` 密钥，并可随时在会话列表中一键撤销。

## 三、安全隔离与协议兼容机制

1. **OAuth 2.1 + PKCE 与哈希存储**：公网连接强制核验 `PKCE S256` 与受信任回调域名白名单，访问令牌与刷新令牌在 `oauth.sqlite3` 中仅保存 SHA-256 摘要（磁盘零明文令牌留存）。
2. **RFC 8707 双端点受众隔离**：`/mcp` 与 `/mcp/readonly` 分别发布独立的受保护资源元数据；`/mcp/readonly` 签发的令牌锁定 `server:read` 作用域，若尝试跨端点请求全权限 `/mcp`，鉴权层直接返回 HTTP `403`（`forbidden_cross_resource`）。
3. **无状态传输与并发刷新宽限**：两个端点均启用 `StreamableHTTPSessionManager(stateless=True, json_response=True)`，不依赖服务端内存会话 ID；内置刷新令牌并发重放宽限缓存（`refresh_replay`），本地服务重启或 Cloudflare 休眠网关唤醒后原对话可直接继续使用。
4. **会话可视化与一键撤销**：所有已授权会话均显示在主控首页 **「配对与已连会话」** 列表中，支持按单条会话撤销或点击 **「全部断开」** 立即吊销令牌。

## 四、常见报错与排查方法

| 报错现象或状态码 | 产生原因 | 排查与解决步骤 |
| :- | :- | :- |
| **「复制一键配置提示词（发给 Work）」按钮置灰不可点** | 本地尚未开启公网 HTTPS 通道，或通道正在握手中 | 点击顶部连接卡开启默认网关（或前往 `#settings/gateways` 打开任一通道开关），待地址栏显示真实 `https://` 地址后按钮自动开放 |
| **在 `Work` 云端浏览器点 `Take over` 打开授权页提示输入配对码** | `Work` 云端受控浏览器运行在云端机房而非本机，无法访问 `127.0.0.1` 回环桥接 | 展开主控首页 `配对与已连会话`，复制 6 位动态配对码填入授权页即可通过 |
| **工作区接入外部自定义 MCP 返回权限受限（如 403）** | 所在企业/团队工作区管理员未开启自定义外部 MCP 连接器权限 | 联系工作区管理员放开自定义 MCP 权限，或改用个人账号配合 `/mcp/readonly` 接入 |
| **HTTP 403 `forbidden_cross_resource`** | 持 `/mcp/readonly` 签发的只读令牌访问了全权限 `/mcp` 端点 | 工作区账号请点「复制一键配置提示词（发给 Work）」绑定 `/mcp`；个人只读账号保持使用 `/mcp/readonly` |
| **开启扩展包或改前缀后未看到新工具** | ChatGPT 缓存了会话初始化时的工具元数据快照 | 在连接器详情页点击 **Refresh（刷新）** 后新建对话再输入 `@你在连接器里填写的名称`（默认 `@WebAI2PC`） |
| **返回 `ERR_READONLY_WORKSPACE` 或 `ERR_OFFICE_FILE_LOCKED`** | 目标路径位于只读参考目录（`readonly_workspace_roots`），或目标 `.docx` / `.xlsx` 正被本地 Word / Excel 打开占用 | 在本地控制台左栏将该目录设为「可读写」（或在「当前权限设置」切至 `全盘开发`）；遇到 Office 锁表时先保存关闭本地文档窗口再重试 |
