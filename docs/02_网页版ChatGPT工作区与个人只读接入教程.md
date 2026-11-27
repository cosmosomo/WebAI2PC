# 02. 网页版 ChatGPT 工作区与个人只读接入教程

本教程说明如何将本地 WebAI2PC（Cosmos MCP `v1.2.1`）接入 **网页版 ChatGPT（`Chat` 模式与 `Work` 模式通用）**，涵盖工作区账号与个人 `Plus / Pro` 订阅账号的端点选择、控制台「复制给 ChatGPT 帮我连接」一键引导与代填边界、[RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 受众隔离机制、`stateless_http` 无状态会话保持、同机浏览器 `800ms` 回环免输口令放行及常见报错处理。

## 一、`Chat` / `Work` 双模式用法与账号端点对比

网页版 ChatGPT 的 `Chat` 模式与 `Work` 模式共用同一套 `Plugins` 插件目录（见 [OpenAI 自定义 MCP 连接官方文档](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt) 与 [ChatGPT Work 与 Codex 官方说明](https://help.openai.com/en/articles/20001275-chatgpt-work-and-codex)），绑定一次即可在两个模式下输入 `@WebAI2PC` 作为本地 Agent 调用：

- **网页版 `Chat` 模式（日常本地开发首选）**：原生支持连续多步调用 MCP 读写与执行工具；交互响应快，且消耗日常 `Chat` 对话限额，**不扣减 `Work` 与 `Codex` 共享的智能体 Token 额度**。
- **网页版 `Work` 模式（长程交付与自动任务）**：运行在云端（原生无法直接访问本机硬盘，通过 `WebAI2PC` 接通本机），适合跨邮件、文档与本地工程做多步核对交付，或配置定时与事件触发任务（`Scheduled Tasks`）。

OpenAI 平台按**账号订阅档位**（而非 `Chat / Work` 模式）对未上架自建远程 MCP 服务器的写入动作（`write actions`）执行不同放行规则，接入前按下表选择对应地址：

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

## 二、两种绑定路径：一键发给 ChatGPT 连接 vs 手动添加插件

### 方式 A（推荐）：网关就绪后点「复制给 ChatGPT 帮我连接」

本地控制台（`http://127.0.0.1:8096/` 切到 `网页版 ChatGPT` 页签，或打开 `/tutorials` 第 2 章）在**公网 HTTPS 网关就绪后**开放 **「复制给 ChatGPT 帮我连接」** 按钮，自动填入当前实际可用的 `/mcp` 或 `/mcp/readonly` 地址与账号目标说明（以 `Plus / Pro` 只读为例）：

```text
请帮我把 WebAI2PC 连接到当前 ChatGPT 账号，并验证首次调用。
如果你能操作我的 ChatGPT 插件页面，请帮我填写配置。
如果需要我点击，请告诉我当前要点哪里。

插件名称：WebAI2PC
MCP 地址：https://<本机生成的实际域名>/mcp/readonly
目标：ChatGPT Plus / Pro，只读（Chat 与 Work 模式通用）
认证：OAuth，由 WebAI2PC 自动协商
验证：授权后调用 pc_get_status（get_status），确认能连接到我的电脑。
```

**信息最小化与代办边界**：
- **零敏感凭据外发**：复制文本仅包含可用 HTTPS 地址与配置说明，**不复制配对码、连接口令、令牌或本机文件路径**。
- **区分当前对话执行能力**：当所处会话具备可操作的受控浏览器、你已明确委托且当前账号具备插件创建权限时，ChatGPT 可尝试代填表单；在普通网页聊天中，粘贴文字本身不会赋予修改账号设置的权限，ChatGPT 会按你当前界面一步步指引点击位置。
- **本人完成授权与接通标准**：账号登录与 OAuth 授权确认始终由你本人在对应页面完成（同一台电脑浏览器直接点 **「本机一键允许连接」**，异地设备输入本地控制台显示的配对码），最终以 **`pc_get_status` 实际调用成功**作为接通标准。

### 方式 B：手动在 `Plugins` 添加自定义 MCP 服务器

1. **复制对应地址**：在本地控制台 `网页版 ChatGPT` 页签等待网关就绪，工作区账号点 `复制地址`（`https://<域名>/mcp`），个人 `Plus / Pro` 只读点 `复制只读`（`https://<域名>/mcp/readonly`）。
2. **创建并安装插件**：打开网页版 ChatGPT 左侧栏 **`Plugins -> + -> Add custom MCP server`**（无需先开启旧版 `Developer Mode`），名称填写 `WebAI2PC`，`Connection` 粘贴上一步复制的 HTTPS 地址，认证保持 `OAuth`（无需手动填写静态 Client ID 或密钥，服务端通过动态客户端注册自动协商），勾选风险提示确认框后点击 **`Create as a plugin`**，并在个人或工作区插件列表中完成 **Install（安装）**。
3. **同机浏览器 800ms 回环一键允许**：跳转到 `/consent` 授权页时，同一台电脑的浏览器会在 `800ms` 内通过 `127.0.0.1` 回环桥接接口（`/oauth/local-bridge`）校验网关签名票据与 `Origin`，首屏直接展示 **「本机一键允许连接（免输口令）」**；异地浏览器或开启严格本地网络拦截的浏览器会自动展开输入框，填入本地控制台显示的 `6` 位动态配对码（或 `20` 位备用口令）即可完成授权。
4. **对话中 `@WebAI2PC` 调用验证**：新建 `Chat` 或 `Work` 对话，在输入框键入 `@WebAI2PC` 选中插件，发送验证指令：
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
| **「复制给 ChatGPT 帮我连接」按钮置灰不可点** | 本地尚未开启公网 HTTPS 通道，或通道正在握手中 | 点击顶部连接卡「一键开启默认连接网关」（或前往 `#settings/gateways` 打开任一通道开关），待地址栏显示真实 `https://` 地址后按钮自动开放 |
| **HTTP 401 Unauthorized / 提示重新授权** | 在本地控制台点击过「全部断开」、更换了临时隧道域名（如重启后 `*.trycloudflare.com` 变更），或重置了状态目录密钥 | 若临时域名已变，在 `Plugins` 打开 `WebAI2PC` 更新 URL（推荐升级 Cloudflare `*.workers.dev` 固定网关）；若固定域名未变，重新触发一次连接并点「本机一键允许连接」 |
| **开启扩展包或改前缀后未看到新工具** | ChatGPT 缓存了创建或会话初始化时的工具元数据快照 | 前往 `ChatGPT Plugins` 打开 `WebAI2PC` 详情点击 **Refresh（刷新）**（工作区已发布应用需管理员在工作区插件设置刷新），随后**新建对话**再输入 `@WebAI2PC` |
| **个人 Plus / Pro 账号测试 `/mcp` 时写操作被平台拦截** | 当前账号受 OpenAI 平台策略限制，自建 MCP 仅放行 `read/fetch` 工具 | 将连接地址改为只读端点 `https://<域名>/mcp/readonly` 重新保存并完成一次授权 |
| **HTTP 403 `forbidden_cross_resource`** | 持 `/mcp/readonly` 签发的只读令牌访问了 `/mcp` 主端点，触发 [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 受众不匹配拦截 | 核对插件配置的 URL 后缀与授权时一致；删除原连接后使用目标 URL 重新完成一次 OAuth 授权 |
| **返回 `ERR_READONLY_WORKSPACE` 或 `ERR_OFFICE_FILE_LOCKED`** | 目标路径位于只读参考目录（`readonly_workspace_roots`），或目标 `.docx` / `.xlsx` 正被本地 Word / Excel 打开占用 | 在本地控制台左栏将该目录设为「可读写」（或切至 `L4` 全盘开发）；遇到 Office 锁表时先保存关闭本地文档窗口再重试 |
