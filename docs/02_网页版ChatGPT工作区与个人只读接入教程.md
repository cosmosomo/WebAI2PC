# 02. 网页版 ChatGPT 工作区与个人只读接入教程

本教程说明如何将本地 Cosmos MCP（`v1.2.1`）接入 **网页版 ChatGPT（对话模式）**，涵盖工作区账号与个人 Plus / Pro 订阅账号的端点选择、[RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 受众隔离机制、`stateless_http` 无状态会话保持、同机浏览器 `800ms` 回环免输口令放行步骤、聊天框勾选调用方法及常见报错处理。

## 一、工作区账号与个人订阅账号端点对比

网页版 ChatGPT 对不同订阅类型的自定义 MCP 连接器执行不同的工具读写校验规则。接入前请按下表选择对应的 HTTPS 端点地址：

| 网页版 ChatGPT 账号类型 | 绑定连接地址 | 可用工具范围 | OAuth 权限范围与平台边界 |
| :- | :- | :- | :- |
| **工作区账号（Team / Business / Enterprise / Edu）** | `https://<域名>/mcp` | 默认开放全部 `16` 项核心工具（含代码与文本读写、PDF / `.pptx` 提取、`.docx` / `.xlsx` 修订、无窗口终端命令、Python 执行与后台任务管理；`L3` 工作区内顺畅开发与 `L4` 全盘顺畅开发（不限目录）模式下可按需热开启 `browser` 与 `cua` 扩展包） | 授予工作区读写与执行权限，支持完整本地工程开发、文档修改与测试运行 |
| **个人订阅账号（Plus / Pro）** | `https://<域名>/mcp/readonly` | 固定开放 `12` 项只读工具（全部声明 `readOnlyHint=True`），屏蔽 `pc_edit_file`、`pc_write_file`、`pc_run_command`、`pc_run_python` 四项写入与执行工具 | 平台策略仅允许自定义连接器注册只读工具，权限范围强制锁定为 `server:read`，适合代码走读、架构分析与文档审阅 |
| **免费个人账号（Free）** | 暂不支持 | 无 | 网页端暂未开放自定义 MCP 连接器配置入口 |

在 `/mcp/readonly` 只读端点下，服务端自动提供 `7` 项纯只读查询工具（`pc_get_status`、`pc_find_files`、`pc_search_code`、`pc_read_file`、`pc_batch_probe`、`pc_web_research`、`pc_skill_hub`），并将 `5` 项复合工具收窄为只读子动作投影：
1. `pc_code_intel`：保留 `outline`、`overview`、`repo_map`、`symbol`、`refs`、`diagnostics`（隐藏 `rename_symbol`）。
2. `pc_manage_files`：仅保留 `list` 查看回收箱与快照列表（隐藏移动、重命名、回收箱清理与撤回修改）。
3. `pc_bg_command`：仅保留 `status` 与 `list` 查看任务进度（隐藏启动与终止任务）。
4. `pc_workspace_memory`：仅保留 `read` 与 `search` 读取跨会话交接记录（隐藏写入记录）。
5. `pc_skill_manage`：仅保留 `list` 与 `trash_list` 列出技能清单（隐藏创建、安装与启停）。

## 二、RFC 8707 受众隔离与 stateless_http 免重复弹窗机制

### 1. RFC 8707 双端点受众隔离

服务端在传输层为 `/mcp` 与 `/mcp/readonly` 分别建立物理隔离的 `LowLevelServer` 与会话管理器实例，并独立发布受保护资源元数据（`/.well-known/oauth-protected-resource/mcp` 与 `/.well-known/oauth-protected-resource/mcp/readonly`）：

- **令牌受众与权限收窄**：通过 `/mcp/readonly` 发起 OAuth 2.1（DCR + PKCE）授权时，授权确认页固定锁定「仅授予只读权限」，签发的访问令牌与刷新令牌在本地 `oauth.sqlite3`（仅存储令牌 SHA-256 摘要主键，无明文落盘）中严格绑定受众 `https://<域名>/mcp/readonly` 与 `server:read` 作用域。
- **跨端点越权硬阻断**：按 [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 资源指示符规范，若客户端携带 `/mcp/readonly` 签发的只读令牌尝试向上请求全权限 `/mcp` 端点，鉴权中间件直接拦截并返回 HTTP `403` 与错误码 `{"error": "forbidden_cross_resource", "reason": "resource_mismatch"}`；若在 `/mcp/readonly` 端点强行传入写入或执行动作参数，分发层直接返回 `ERR_READONLY_ACTION_BLOCKED`。全权限 `/mcp` 令牌向下访问 `/mcp/readonly` 则正常兼容放行。

### 2. stateless_http 无状态传输与并发刷新宽限

网页端 AI 与本地电脑之间常经历网络切换、电脑休眠唤醒或后台进程重启，Cosmos MCP 通过两项机制消除会话断连后的重复登录弹窗：

- **`stateless_http` 免会话丢失**：两个端点均启用 `StreamableHTTPSessionManager(stateless=True, json_response=True)` 无状态 HTTP JSON 模式，每次请求凭 OAuth Bearer 令牌独立完成校验与响应，不依赖保存在服务端内存中的 `mcp-session-id`；本地服务重启或 Cloudflare 休眠网关唤醒后，已打开的网页版 ChatGPT 对话可直接继续调用工具。
- **单次刷新轮换与并发宽限缓存**：网页版 ChatGPT 并发执行多个工具调用时，多条请求可能在同一秒携带同一枚刷新令牌请求 `/token`。服务端内置原子刷新轮换与 `3600` 秒重放宽限缓存（`refresh_replay`），并对活跃访问令牌自动执行 `1800` 秒滑动有效期顺延，防止并发刷新竞争引发假性失效重登。

## 三、同机浏览器 800ms 回环免输口令放行步骤

1. **启动服务并复制对应地址**：
   双击 `一键启动_Cosmos_MCP.bat`（macOS / Linux 运行 `./start_cosmos_mcp.sh`），在自动打开的本地 `Cosmos Studio` 控制台（默认 `http://127.0.0.1:8096`，或内置交互式教程页 `http://127.0.0.1:8096/tutorials`）开启任一 HTTPS 连接卡片（3 张连接卡片支持独立开关同时并存，自动展示当前选中的就绪网关 URL）：
   - 工作区账号复制主地址：`https://<你的域名>/mcp`
   - 个人 Plus / Pro 账号复制只读地址：`https://<你的域名>/mcp/readonly`
2. **在网页版 ChatGPT 添加自定义连接器**：
   打开网页版 ChatGPT `Settings（设置） -> Connectors（连接器）` 管理页，点击新增自定义 MCP 连接器，名称填写 `Cosmos`，连接地址粘贴上一步复制的 HTTPS URL（无需手动填写静态 Client ID 或密钥，系统通过动态客户端注册自动协商），点击连接跳转授权。
3. **同机浏览器 800ms 回环一键允许**：
   当你在运行 Cosmos MCP 的同一台电脑浏览器中跳转到 `/consent` 授权页时，页面前端会在 `800ms` 内向本机 `127.0.0.1` 回环桥接接口（`/oauth/local-bridge`）发起在场校验，核对网关签发的 `{oauth_state, client_id, redirect_uri}` 签名票据及请求 `Origin`。校验通过后，页面首屏直接展示主按钮 **「本机一键允许连接（免输口令）」**，点击一次即可完成绑定并跳回 ChatGPT。
4. **异地浏览器或隐私拦截回退方式**：
   若在另一台电脑或平板浏览器上完成绑定，或当前浏览器（如开启严格本地网络拦截的 Brave、Safari）及全局 TUN 代理阻断了 `127.0.0.1` 回环请求，授权页零等待展开备用验证框：对照本地控制台显示的 `6` 位动态配对码（或 `20` 位本机连接口令）填入并提交即可完成授权。

## 四、聊天框勾选连接器与首句提问验证方法

1. **导入操作守则（可选但推荐）**：
   在本地控制台点击「复制 AI 操作守则（推荐存入 Skills）」，将其粘贴到网页版 ChatGPT 对应 Project（项目）的自定义指令（Instructions）中，帮助模型熟悉 `16` 项工具分工与文件保护约定。
2. **新建对话并勾选连接器**：
   打开网页版 ChatGPT 新建对话窗口，点击聊天输入框下方的 **工具（连接器）图标**，在弹出列表中勾选已绑定的 `Cosmos` 连接器。
3. **发送首句提问验证连通性**：
   - **工作区账号（`/mcp`）验证提问**：
     ```text
     调用 pc_get_status 查看当前开放的工作目录与 Python 环境，列出 D:\Work\my-project 顶层文件并读取 README 前 60 行。
     ```
   - **个人 Plus / Pro 账号（`/mcp/readonly`）验证提问**：
     ```text
     查看当前工作区包含哪些源码目录，并用 pc_code_intel 提取核心入口模块的函数与类大纲。
     ```
4. **核对预期返回结果**：
   聊天界面展开 `Cosmos` 工具调用记录，返回真实的本地操作系统信息、工作区路径读写权限及代码行号大纲。网页版 ChatGPT 单次工具请求超时通常约为 `60` 秒；工作区账号运行超过 `20` 秒（`DEFAULT_SYNC_WAIT_CAP_SEC = 20.0`）的构建或测试时，`pc_run_command` 与 `pc_run_python` 会自动转为 `pc_bg_command` 后台任务并返回 `job_id`，随后模型可通过 `pc_bg_command(action="status", job_id="...")` 分段查询日志。

## 五、常见报错与排查方法

| 报错现象或状态码 | 产生原因 | 排查与解决步骤 |
| :- | :- | :- |
| **HTTP 401 Unauthorized / 提示重新登录连接器** | 在本地控制台点击过「全部断开」或单客户端断开、更换了临时隧道域名（如重启后 `*.trycloudflare.com` 变更），或重置了状态目录密钥 | 若使用临时通道且域名已变，从控制台复制最新 HTTPS 地址更新到连接器设置；若使用固定域名，在 ChatGPT 连接器详情页点击 **Reconnect（重新连接）**，再次点击「本机一键允许连接」即可恢复 |
| **新增扩展包或改前缀后工具未刷新** | 网页版 ChatGPT 在会话建立时缓存了当时的 `tools/list` 工具清单，热开启 `browser` / `cua` 扩展包、切换 `L1`~`L4` 安全档位或修改 `tool_prefix` 后旧对话不会自动拉取新清单 | 进入网页版 ChatGPT 连接器管理页点击 **Refresh（刷新工具）**，随后**新建一个对话窗口**并勾选 `Cosmos` 连接器 |
| **个人 Plus / Pro 账号保存连接器时报含写权限工具被拒** | 连接地址误填了全权限主端点 `https://<域名>/mcp` | 将连接器 URL 改为只读端点 `https://<域名>/mcp/readonly` 重新保存并完成授权 |
| **HTTP 403 `forbidden_cross_resource`** | 客户端持 `/mcp/readonly` 签发的只读令牌访问了 `/mcp` 主端点，触发 [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) 受众不匹配拦截 | 核对连接器配置的 URL 与授权时绑定的端点后缀一致；删除原连接器条目后使用目标 URL 重新完成一次 OAuth 授权 |
| **调用工具返回 `ERR_READONLY_WORKSPACE` 或 `ERR_OFFICE_FILE_LOCKED`** | 目标路径位于只读参考目录（`readonly_workspace_roots`），或目标 `.docx` / `.xlsx` 文档正被本地 Word / Excel 打开锁表 | 前往本地控制台「工作区与 Python 环境」将该子项目设为「可读写」（或切至 `L4` 全盘顺畅开发模式处理跨目录任务）；遇到 Office 占用锁表时先在本地保存并关闭对应文档窗口再重试 |
