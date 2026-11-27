# 02. 网页版 ChatGPT 工作区与个人只读接入教程

本教程说明如何将本地 WebAI2PC（Cosmos MCP `v1.2.1`）接入网页版 ChatGPT，明确拆解 **`Work` 模式与 `Chat` 模式在「首次代连」与「装好后日常干活」两阶段的能力差异**，涵盖工作区账号与个人 `Plus / Pro` 订阅账号的端点选择、控制台「复制给 Work 模式帮我连接」门禁与代办边界、云端浏览器与本机浏览器授权页差异、[RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 受众隔离机制、`stateless_http` 无状态会话保持及常见报错处理。

## 一、两阶段能力边界：首次代连找 `Work` 模式，日常干活优先 `Chat` 模式

根据 OpenAI 官方文档（[Browser 受控浏览器说明](https://learn.chatgpt.com/docs/browser)、[Chrome 浏览器扩展说明](https://learn.chatgpt.com/docs/chrome-extension)、[ChatGPT 使用指南](https://learn.chatgpt.com/docs/use-chatgpt)、[自定义 MCP 连接指南](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt) 与 [ChatGPT Work 与 Codex 额度说明](https://help.openai.com/en/articles/20001275-chatgpt-work-and-codex)），`Work` 模式与 `Chat` 模式在连接阶段和日常调用阶段职责不同：

1. **阶段一：首次添加/代填自定义 MCP 插件（谁能帮用户连）**
   - **`Chat` 模式无法代填新插件**：`Chat` 模式没有受控浏览器（无云端 Browser，也不支持桌面端 `@Chrome` 浏览器扩展与 Computer Use），把连接请求发给 `Chat` 模式无法操作 `chatgpt.com/plugins` 页面，只能回复文字步骤供用户手动点击。
   - **只有 `Work` 模式能操作浏览器代填配置**：网页版 `Work` 模式自带云端受控浏览器，支持打开 `Plugins` 页面填写表单；遇到登录或 `/consent` 授权确认时支持用户点 `Take over` 接管操作，完成后点 `Return control` 交回；桌面版 `Work` 还支持通过浏览器扩展 `@Chrome` / `@Edge` 操作本机已登录标签页。
   - **云端受控浏览器与本机浏览器的授权页差异**：若用户在网页版 `Work` 的云端浏览器里点 `Take over` 打开 `/consent` 授权页，因该浏览器运行在 OpenAI 云端不在本机，无法访问本机 `127.0.0.1` 回环，授权页会提示输入本地控制台显示的 `6` 位动态配对码；若在本机浏览器手动打开 `Plugins -> + -> Add custom MCP server`（或桌面版 `Work` 调本机浏览器扩展），跳转 `/consent` 命中 `127.0.0.1` 回环，首屏直接点「本机一键允许连接」。
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

## 二、两种绑定路径：切 `Work` 模式代填连接 vs 本机浏览器手动添加

### 方式 A：网关就绪后点「复制给 Work 模式帮我连接」切到 `Work` 模式发送

本地控制台（`http://127.0.0.1:8096/` 切到 `网页版 ChatGPT` 页签，或打开 `/tutorials` 第 2 章）在**公网 HTTPS 网关就绪后**开放 **「复制给 Work 模式帮我连接」** 按钮，自动填入当前实际可用的 `/mcp` 或 `/mcp/readonly` 地址与目标说明（以 `Plus / Pro` 只读为例）：

```text
【请先在 ChatGPT 顶部切换到 Work 模式再发送；Chat 模式无受控浏览器，无法代填插件页面】
请帮我把 WebAI2PC 连接到当前 ChatGPT 账号，并验证首次调用。
请用你的浏览器打开我的 ChatGPT Plugins 页面填写配置；需要我登录或完成授权确认时请让我接管（Take over），或告诉我当前要点哪里。

插件名称：WebAI2PC
MCP 地址：https://<本机生成的实际域名>/mcp/readonly
目标：ChatGPT Plus / Pro，只读（装好后可切回 Chat 模式或留在 Work 模式通过 @WebAI2PC 调用）
认证：OAuth，由 WebAI2PC 自动协商
验证：授权并安装插件后调用 pc_get_status（get_status），确认能连接到我的电脑。
```

**信息最小化与双模式代办边界**：
- **零敏感凭据外发**：复制文本仅包含可用 HTTPS 地址与配置说明，**严禁写入配对码、连接口令、令牌或本机文件路径**。
- **必须发给 `Work` 模式才能操作浏览器代填**：网页版 `Work` 模式通过云端受控浏览器打开 `Plugins` 填写配置（桌面版 `Work` 也可通过 `@Chrome` / `@Edge` 浏览器扩展操作本机标签页）；若误粘到 `Chat` 模式，因 `Chat` 无受控浏览器，仅能输出文字步骤供手动点击。
- **本人接管完成授权并点 `Install`**：遇到账号登录或 `/consent` 授权确认时，在网页版 `Work` 云端浏览器点击 `Take over` 接管并填入本地控制台显示的 `6` 位动态配对码（因云端浏览器不在本机），完成后点 `Return control` 交回并点击 `Install` 安装插件，最终以 **`pc_get_status` 实际调用成功**作为接通标准。

### 方式 B：在本机浏览器手动打开 `Plugins` 添加并一键允许

1. **复制对应地址**：在本地控制台 `网页版 ChatGPT` 页签等待网关就绪，工作区账号点 `复制地址`（`https://<域名>/mcp`），个人 `Plus / Pro` 只读点 `复制只读`（`https://<域名>/mcp/readonly`）。
2. **创建并安装插件**：在本机浏览器打开网页版 ChatGPT 左侧栏 **`Plugins -> + -> Add custom MCP server`**（无需开启旧版 `Developer Mode`），名称填写 `WebAI2PC`，`Connection` 粘贴上一步复制的 HTTPS 地址，认证保持 `OAuth`（服务端通过动态客户端注册自动协商，无需手动填写 Client ID 或密钥），勾选风险提示确认框后点击 **`Create as a plugin`**，并在插件列表中点击 **`Install`（安装）**。
3. **同机浏览器 800ms 回环一键允许**：本机浏览器跳转到 `/consent` 授权页时，会在 `800ms` 内通过 `127.0.0.1` 回环桥接接口（`/oauth/local-bridge`）校验网关签名票据与 `Origin`，首屏直接展示 **「本机一键允许连接（免输口令）」**；异地浏览器、网页版 `Work` 云端浏览器或开启严格本地网络拦截的浏览器会自动展开输入框，填入本地控制台显示的 `6` 位动态配对码（或 `20` 位备用口令）即可完成授权。
4. **装好后切回 `Chat` 模式（或按需在 `Work` 模式）输入 `@WebAI2PC` 验证**：日常改代码跑脚本推荐新建 **`Chat` 模式**对话（不扣 `Work / Codex` 额度；跨应用长程交付与定时任务新建 `Work` 模式对话），在输入框键入 `@WebAI2PC` 选中插件，发送验证指令：
   ```text
   @WebAI2PC 请调用 pc_get_status 确认连接状态，并查看当前开放的工作目录与文件结构。
   ```
   写操作默认弹出确认卡片，在同一对话中可勾选记住批准，避免同会话后续步骤重复弹窗；长耗时命令（超过 `20` 秒）会自动转为 `pc_bg_command` 后台任务返回 `job_id` 供分段轮询。

## 三、RFC 8707 受众隔离与 stateless_http 免重复弹窗机制

1. **RFC 8707 双端点受众隔离**：服务端为 `/mcp` 与 `/mcp/readonly` 分别建立独立会话管理器与受保护资源元数据（`/.well-known/oauth-protected-resource/mcp` 与 `/.well-known/oauth-protected-resource/mcp/readonly`）。`/mcp/readonly` 签发的令牌在 `oauth.sqlite3`（仅存 SHA-256 摘要，零明文落盘）中锁定 `server:read` 作用域；若客户端持只读令牌向上访问 `/mcp`，鉴权层直接返回 HTTP `403`（`forbidden_cross_resource`）。
2. **`stateless_http` 无状态传输与并发刷新宽限**：两个端点均启用 `StreamableHTTPSessionManager(stateless=True, json_response=True)`，不依赖服务端内存会话 ID；内置原子刷新轮换与 `3600` 秒并发重放宽限缓存（`refresh_replay`），本地服务重启或 Cloudflare 休眠网关唤醒后原对话可直接继续调用。

## 四、常见报错与排查方法

| 报错现象或状态码 | 产生原因 | 排查与解决步骤 |
| :- | :- | :- |
| **「复制给 Work 模式帮我连接」按钮置灰不可点** | 本地尚未开启公网 HTTPS 通道，或通道正在握手中 | 点击顶部连接卡「一键开启默认连接网关」（或前往 `#settings/gateways` 打开任一通道开关），待地址栏显示真实 `https://` 地址后按钮自动开放 |
| **把连接请求发给 ChatGPT 后只回复文字步骤未自动填表** | 当前处于 `Chat` 模式（无受控浏览器，无法操作 `chatgpt.com/plugins`） | 在 ChatGPT 顶部切换到 `Work` 模式重新粘贴发送，或直接按文字步骤在本机浏览器左侧 `Plugins -> + -> Add custom MCP server` 手动创建并安装 |
| **在网页版 `Work` 云端浏览器 `Take over` 打开授权页提示输配对码** | 网页版 `Work` 的受控浏览器运行在 OpenAI 云端不在本机，无法命中本机 `127.0.0.1` 回环 | 展开本地控制台首页 `配对与已连会话`，复制 `6` 位动态配对码填入云端浏览器授权页，完成后点 `Return control` 交回即可 |
| **HTTP 401 Unauthorized / 提示重新授权** | 在本地控制台点击过「全部断开」、更换了临时隧道域名（如重启后 `*.trycloudflare.com` 变更），或重置了状态目录密钥 | 若临时域名已变，在 `Plugins` 打开 `WebAI2PC` 更新 URL（推荐升级 Cloudflare `*.workers.dev` 固定网关）；若固定域名未变，重新触发一次连接并点「本机一键允许连接」 |
| **开启扩展包或改前缀后未看到新工具** | ChatGPT 缓存了创建或会话初始化时的工具元数据快照 | 前往 `ChatGPT Plugins` 打开 `WebAI2PC` 详情点击 **Refresh（刷新）**（工作区已发布应用需管理员在工作区插件设置刷新），随后**新建对话**再输入 `@WebAI2PC` |
| **个人 Plus / Pro 账号测试 `/mcp` 时写操作被平台拦截** | 当前账号受 OpenAI 平台策略限制，自建 MCP 仅放行 `read/fetch` 工具 | 将连接地址改为只读端点 `https://<域名>/mcp/readonly` 重新保存并完成一次授权 |
| **HTTP 403 `forbidden_cross_resource`** | 持 `/mcp/readonly` 签发的只读令牌访问了 `/mcp` 主端点，触发 [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 受众不匹配拦截 | 核对插件配置的 URL 后缀与授权时一致；删除原连接后使用目标 URL 重新完成一次 OAuth 授权 |
| **返回 `ERR_READONLY_WORKSPACE` 或 `ERR_OFFICE_FILE_LOCKED`** | 目标路径位于只读参考目录（`readonly_workspace_roots`），或目标 `.docx` / `.xlsx` 正被本地 Word / Excel 打开占用 | 在本地控制台左栏将该目录设为「可读写」（或切至 `L4` 全盘开发）；遇到 Office 锁表时先保存关闭本地文档窗口再重试 |
