# WebAI2PC 公开安装与配置教程（供任意 AI 助手 / 本地 Agent 直读执行）

本文档采用固定英文文件名，方便 **Cursor、Claude Code、Codex、Windsurf、Trae、GitHub Copilot、Cline / Roo Code、Antigravity、Qoder、通义灵码、OpenCode、豆包电脑版 / 豆包工作、WorkBuddy、OpenClaw、Manus、网页版 Google Gemini、网页版 ChatGPT** 等任意 AI 助手直接读取并帮用户完成安装、启动与绑定：
- GitHub 页面链接：`https://github.com/cosmosomo/WebAI2PC/blob/main/docs/AI_SETUP_GUIDE.md`
- Raw 纯文本链接：`https://raw.githubusercontent.com/cosmosomo/WebAI2PC/main/docs/AI_SETUP_GUIDE.md`

## 一、给当前 AI 助手 / Agent 的执行分工（先判断你有没有本机命令权限）

### 模式 A：你具备本机文件与终端执行权限（Cursor、Claude Code、Codex、Windsurf、Trae、Cline / Roo Code、豆包工作、WorkBuddy、OpenClaw、OpenCode 等）
请**直接替用户完成本机源码拉取、启动与健康检查**，把需要用户手动操作的步骤压缩到最后 2 次点击：
1. **统一采用源码安装（与 `main` 单一真源同步）**：检测操作系统（Windows / macOS / Linux）、`git` 与 Python 3.10+ 环境：
   - **首选（推荐）**：直接 `git clone https://github.com/cosmosomo/WebAI2PC.git <目标目录>`（如 `D:\WebAI2PC` 或 `~/WebAI2PC`；若目标目录已存在则执行 `git pull --ff-only` 更新到最新 `main`）。
   - **本机无 `git` 时**：直接下载源码归档 `https://github.com/cosmosomo/WebAI2PC/archive/refs/heads/main.zip` 并完整解压到普通目录。
   - **仅当 Windows 完全无 Python 且无法安装时**：才从 Releases 兜底拉取带内置 Python 的 `*win64-full.zip`。
2. **后台启动并核验就绪**：
   - Windows：在源码目录后台运行 `一键启动_Cosmos_MCP.bat`（启动脚本会自动创建独立 `.venv` 并安装依赖，或在已有 Python 环境下直接拉起服务）；
   - macOS / Linux：执行 `chmod +x start_cosmos_mcp.sh && ./start_cosmos_mcp.sh`。
   - 轮询 `http://127.0.0.1:8096/healthz` 确认本地控制台已就绪，并读取已生成的公网 `/mcp`（及 `/mcp/readonly`）地址返回给用户。
3. **安全红线（严禁越权）**：
   - **不要**在聊天记录或外部日志里打印用户的 6 位配对码、20 位备用口令、管理令牌或 Cloudflare API Token；
   - 网页端登录和 OAuth 授权确认页的「本机一键允许连接」**必须由用户本人点击确认**。
4. **交接最后一步**：把拿到的 `https://<域名>/mcp` 交给用户，并**明确提醒：不要把这个 `/mcp` 地址直接粘贴到浏览器地址栏里打开**，按下方第三节把地址粘进网页版 Gemini（`https://gemini.google.com/customize/connectors`）配置栏，或在本地控制台复制 `@Plugin Creator` 一键配置提示词发给网页版 ChatGPT 的 `Work` 模式完成标准 OAuth 2.1 绑定。

### 模式 B：你是纯网页聊天 AI（无本机终端权限，如网页版 Gemini、网页版 ChatGPT `Chat` 模式、豆包网页版等）
请遵守以下分步陪配原则：
1. **先问清 3 项基本情况**：若用户尚未说明，先用简短列表问清：① 电脑系统是 Windows、macOS 还是 Linux；② 本机是否已装 `git` / Python `3.10+`，或是否已拉取源码目录；③ 准备连接网页版 Gemini 还是网页版 ChatGPT（Team / Enterprise 工作区账号还是个人 Plus / Pro 账号）。
2. **每次只教当前这一步**：每次只给出当前步骤的 3 至 5 行具体操作与按钮名称，等用户回复「好了」或发来报错截图后再讲下一步，不要一次性把全文刷满屏幕。
3. **已连上连接器时直接接管打开设置页**：一旦用户已经绑定好连接器（例如命名为 `@WebAI2PC` 或 `@Cosmos`），提示用户可以直接发：`@你在连接器里填写的名称 帮我在电脑上打开网关设置页，教我怎么配 Cloudflare 固定网址`。已连上的 AI 可直接调用本地工具帮用户在电脑浏览器弹出对应配置页并核对实时状态。

## 二、获取源码与启动本地控制台（`git clone` 源码安装首选 · 离线压缩包兜底）

1. **首选方式：从 GitHub 拉取最新源码（推荐单一真源）**：
   - **已装 `git` 与 Python `3.10~3.14`（Windows / macOS / Linux 通用首选）**：在终端执行以下命令拉取主分支源码（若目录已存在则执行 `git pull --ff-only`）：
     ```bash
     git clone https://github.com/cosmosomo/WebAI2PC.git
     ```
   - **未安装 `git` 但已有 Python `3.10+`**：直接下载主分支源码归档 `https://github.com/cosmosomo/WebAI2PC/archive/refs/heads/main.zip`，右键「全部解压缩」到普通文件夹（启动脚本会自动识别系统 Python、Conda 或 `uv` 环境并跳过 Windows 商店空壳，自动创建 `.venv`）。
2. **兜底选项：目标 Windows 电脑无 Python/Git 且无法安装时的离线包**：
   - **仅当目标 Windows 机器没有安装 Python 与 Git 且受环境限制无法安装时**，前往 `https://github.com/cosmosomo/WebAI2PC/releases` 下载内置免安装 Python 3.12 运行环境的完整离线压缩包 `*win64-full.zip`，**先完整解压到普通文件夹**（切勿直接在 WinRAR / 7-Zip / 资源管理器压缩包预览窗口里双击运行脚本）。
3. **启动本地控制台**：
   - **Windows**：进入源码或解压后的文件夹，双击 `一键启动_Cosmos_MCP.bat`。
   - **macOS / Linux**：在终端进入目录，执行 `chmod +x start_cosmos_mcp.sh && ./start_cosmos_mcp.sh`。
   - 服务会在后台无窗口启动，并自动用浏览器打开本地控制台 `http://127.0.0.1:8096/`（页面标题为 `WebAI2PC · 本地控制台`）。

## 三、首次免注册连上网页版 Gemini / ChatGPT（三步走）

首次启动无需注册任何第三方账号即可连上测试：

1. **第 1 步：在本地控制台复制连接地址或一键配置提示词**
   - 控制台默认开启第 1 类通道「系统内置 OpenSSH 免登录直连」（命令行等效 `--mode openssh`，兼容 `public_gateway`）：直接调用操作系统自带的 OpenSSH（`ssh`）客户端经 `srv.us` 公共中继生成免登录固定网址 `https://*.srv.us/mcp`（零额外二进制安装，启动等待预算 `10` 秒，跨重启不变），卡片内同时提供备用 `https://*.trycloudflare.com/mcp` 独立开关（可与 OpenSSH 固定通道同时在线，或在出站 `22` 端口受阻时启用）。
   - 若连 **网页版 Gemini**，保持顶部选中 `网页版 Gemini`，点击蓝色按钮 `复制连接地址`。
   - 若连 **网页版 ChatGPT**，点击顶部切换到 `网页版 ChatGPT`（公网网关就绪后按钮自动开放）：Team / Business / Enterprise / Edu 工作区账号点击主按钮 **「复制一键配置提示词（发给 Work）」**（绑定全功能 `/mcp`），个人 Plus / Pro 只读账号点击 **「复制只读配置提示词（发给 Work）」**（绑定只读 `/mcp/readonly`），也可点击旁侧 `仅复制地址` 手动配置。
2. **第 2 步：添加到网页端并完成 OAuth 2.1 授权**
   - **网页版 Gemini（需 18+ Google AI Pro / Ultra 或已开启权限的 Workspace 账号）**：
     1. **明确提醒用户**：刚才复制的 `https://.../mcp` **不是从浏览器地址栏直接打开访问的网址**，而是要粘贴进 Gemini 连接器配置栏里的 MCP 服务器地址。
     2. 让用户直接打开 **`https://gemini.google.com/customize/connectors`**（或从 Gemini 首页左下角菜单依次点击 `Personal Intelligence -> Connected Apps` 进入 `Connectors` 页面），点击右上角 **`+ Custom`**。
     3. 在弹出的 `Connect to an MCP server` 窗口中，把 `https://.../mcp` 粘贴到 **`MCP Server URL`** 配置栏（`Additional settings` 保持默认折叠，无需填写 Client ID / Secret），点击 **`Next`** 跳转到本地授权确认页。
     4. 在同一台电脑的浏览器上直接点击 `本机一键允许连接` 即可完成绑定。
     5. 绑定成功后，回到 `https://gemini.google.com/customize/connectors` 点开刚添加的连接器，将 **`App actions` 总开关设为 `Always allow（始终允许）`**（建议顺手在本地控制台点 `复制 AI 守则` 粘贴保存到 Gemini 的 `Skills` 中）。
   - **网页版 ChatGPT（`Work` 模式 `@Plugin Creator` 标准 OAuth 接入）**：
     1. **发送一键配置提示词到 `Work` 模式**：打开网页版 ChatGPT 切换到顶部 **`Work` 模式**，直接粘贴刚才复制的一键配置提示词并发送，由 `@Plugin Creator` 按服务端公布的标准 OAuth 2.1 元数据自动接入 `/mcp` 或 `/mcp/readonly` 并创建安装 `WebAI2PC`（无需手动填写 Client ID / Secret 或额外部署中转服务；若企业工作区管理员关闭了外部自定义 MCP 权限，需联系管理员放开或改用个人账号）。
     2. **完成授权确认**：弹出 `/consent` 授权确认页时，同机浏览器命中 `127.0.0.1` 回环直接点击 **`本机一键允许连接`**；若在网页版 `Work` 云端受控浏览器内点 `Take over` 打开 `/consent`，则展开本地控制台主控首页 `配对与已连会话`，输入显示的 `6` 位动态配对码后点 `Return control` 交回。
3. **第 3 步：首句唤醒并以 `pc_get_status` 成功作为接通标准**
   - **网页版 Gemini**：新建对话（建议开启任务模式），首句输入 `@你在连接器里填写的名称`（例如 `@WebAI2PC` 或 `@Cosmos`）并点选弹出的连接器标签，发送如：`@WebAI2PC 帮我调用 pc_get_status 看看当前工作目录里有哪些文件`。同账号手机端 Gemini App 也会自动同步该连接器。
   - **网页版 ChatGPT（装好后日常用 `Chat` 省额度，长任务用 `Work`）**：连接器安装后全账号共享。日常查改本地代码、修 Office、跑无窗口命令与测试推荐切回 **`Chat` 模式**输入 `@你在连接器里填写的名称`（默认 `@WebAI2PC`，响应快，走普通对话限额，零消耗 `Work / Codex` 智能体额度）；需要结合云端浏览器、跨邮件/Slack/网盘做长程交付或配置 `Scheduled Tasks` 定时任务时切 **`Work` 模式**调用，首次调用 `pc_get_status`（`get_status`）成功返回本机状态与目录即接通完成。操作守则在工作区/桌面端可存入原生 `Skills`，网页版 `Chat` 与 `Work` 均可粘贴到 `Project Instructions` 或自定义指令。

## 四、进阶配置 Cloudflare 免费终身固定网址（`#settings/gateways` 方式 2 三步走）

若用户希望配置免费、无服务器账单且终身不变的专属 HTTPS 网址（或绑定自己的域名），引导用户按以下三步操作：

1. **进入网关设置页展开第 2 张卡片**：
   - 在本地控制台右上角点击 `设置` -> 左侧栏选择 `连接与网关`（浏览器地址为 `http://127.0.0.1:8096/#settings/gateways`；若已连上 `@Cosmos`，可直接让 AI 帮忙打开此页）。
   - 找到 **第 2 类 · 无服务器固定网址：`Cloudflare 专属固定网关`**，点击卡片右侧的 `配置 ▾`（3 张网关卡片支持独立开关同时在线，部署期间不会断开正在使用的第 1 类通道）。
2. **三步完成 3 秒一键部署**：
   - **① 打开预填权限页生成令牌**：点击卡片内的 `第 1 步：打开 Cloudflare 预填权限页（支持 Google 快捷登录）`。在打开的 Cloudflare 网页登录账号（所需 Workers 权限已自动勾选），滚动到底部点击 `Continue to summary` -> `Create Token`，复制生成的 API 令牌。
   - **② 粘贴令牌（可选填自有域名）**：回到本地控制台，把令牌粘贴进 `第 2 步：粘贴 API 令牌（部署后立即销毁）` 输入框。若用户在 Cloudflare 名下有已激活的域名（Active Zone），可在右侧 `选填：自定义域名（Active Zone，国内免切代理）` 填入子域名（例如 `mcp.yourdomain.dpdns.org`）；若账号下有多个 Cloudflare 账户，在下拉框选定目标账户。
   - **③ 点击部署并替换网址**：点击蓝色按钮 `一键部署并开启（约 3 秒）`。系统会自动认领子域并部署免费 Cloudflare Workers + SQLite Durable Object 休眠网关，生成终身固定的 `https://*.workers.dev/mcp`（及 `/mcp/readonly`）。
3. **部署后的令牌安全、通道依赖与国内代理边界**：
   - 部署完成瞬间，刚才粘贴的 Cloudflare API 令牌会自动从内存与磁盘清零销毁；点击 `复制此卡地址`（个人版 ChatGPT 点 `复制 Plus/Pro 只读`）更新一次网页端连接器 URL 后即可长期使用，后续拨动卡片右上角开关即可启停。
   - **通道 2（`workers_dev`）依赖与代理要求**：本机采用纯 Python 标准库 `443 WSS` 客户端（**零外部二进制依赖**，免装 `Node.js`、`wrangler` 或 `cloudflared`），受 Cloudflare Workers Free 每日 `100,000` 次请求上限（超限返 `1027`）与边缘默认 `125` 秒反代读超时约束。**中国大陆网络特别注意**：`*.workers.dev` 在国内存在全量 DNS 污染（裸连 `100%` 超时），若未绑定自定义域名，**本机运行期间必须保持系统 HTTP/HTTPS 代理（Clash / Mihomo / v2rayN 或 `HTTPS_PROXY` / `WSS_PROXY`）常开且分流规则覆盖 `*.workers.dev`**（若设 `NO_PROXY` 须保留 `127.0.0.1,localhost,::1`）；绑定同账号下自定义域名（Active Zone）后可实现国内免代理直连。
   - **与通道 1 / 通道 3 的依赖对照**：通道 1 首选「系统内置 OpenSSH 免登录直连」（`*.srv.us`）仅依赖系统自带 `ssh` 与出站 TCP `22` 端口（启动等待预算 `10` 秒，国内家庭宽带通常免代理直连）；卡片内配独立开关并存的备用 `*.trycloudflare.com` 及通道 3 子项 `--mode cloudflare_token` 均依赖 `cloudflared` 二进制（未装时首次从 GitHub Releases 或 `COSMOS_CLOUDFLARED_MIRROR` 自动下载至 `bin/`；其中 `*.trycloudflare.com` 重启必换域名、无 SLA、单控制流重连有 `4–21s` 空窗返 `530`/`1033` 且限 `200` 并发，`cloudflare_token` 额外需 Zero Trust 指向 `http://127.0.0.1:8096` 的转发并关闭自定义域 `Bot Fight Mode`）；通道 3 `自有云服务器 24h 主站`（`vps_hub` / `vps`）仅依赖开放 `80`/`443` 的 Linux 服务器与本机 `ssh`，零 Cloudflare 依赖、零日请求上限与 `125s` 超时限制，国内或港新机房全程免代理直连。

## 五、4 档安全权限与父目录只读分层

在本地控制台主控首页左栏「开放工作目录」卡片中，用户可以随时调整开放范围与权限档位（点击即生效，无需重启）：

1. **4 档安全权限说明**：
   - **`只读`（`L1`）**：仅允许读取文件、检索代码与查阅内置技能，禁止修改任何文件或执行命令。在主控台「当前权限设置」4 档切换条或系统托盘右键菜单可随时切入只读。
   - **`仅改文件`（`L2`）**：允许在可读写工作目录内读取和修改代码及 `.docx` / `.xlsx` 文档，禁止执行终端命令、Python 脚本和外设扩展包。
   - **`工作区开发`（`L3`，默认推荐）**：允许在已开放的可读写工作目录内读写文件、移入安全回收箱、后台无窗口执行命令与 Python 脚本；只读参考目录内仅允许读取。
   - **`全盘开发`（`L4`）**：允许跨本机任意路径读写与运行命令，同时保留系统敏感密钥目录隔离、写前快照与安全回收箱保护。
2. **添加工作目录与父只读子读写分层**：
   - 点击 `选文件夹`（或粘贴路径点 `添加`）即可增加工作目录。
   - 若希望让 AI 参考整个大仓库但只修改其中某个子目录，可先勾选 `以只读参考目录添加` 添加外层父目录，再关闭该开关添加内部子项目目录；系统按最长路径前缀自动匹配读写权限。
   - 所有文件修改与清理均可在主控首页右栏 `实时动态与撤回` 的 `修改撤回`（查看 Diff 一键回退）与 `回收箱` 中恢复。

## 六、已连上连接器后直接让 AI 打开对应设置页的方法

一旦用户完成了首次绑定，后续任何配置都无需自己翻找菜单，直接在网页聊天框输入 `@你在连接器里填写的名称`（例如 `@WebAI2PC` 或 `@Cosmos`）发送自然语言指令即可：
- 说：`@WebAI2PC 帮我在电脑上打开网关设置页，一步步教我配置 Cloudflare 固定网址`
- 说：`@WebAI2PC 帮我打开工具扩展设置页，我想开启受管浏览器和桌面窗口操控`
- 说：`@WebAI2PC 帮我看看现在开放了哪些文件夹、当前是什么权限档位`

此时已连接 MCP 的 AI 会调用以下内置能力配合引导：
- 调用 `pc_get_status(guide="cloudflare"|"gateways"|"permissions"|"gemini_chatgpt"|"packs_and_skills"|"troubleshooting"|"all", open_page="gateways"|"studio"|"runtime"|"tools"|"skills"|"tutorials")`，直接在同机电脑浏览器弹出对应本地设置页并读取当前状态；
- 调用 `pc_skill_hub(action="load", skill="webai2pc-setup-tutorial")`（在 `L1` 只读档位与 `/mcp/readonly` 端点下同样可用），加载完整的内置界面按钮对照教程。

## 七、常见卡点排障速查

1. **Windows 双击启动脚本没反应或提示找不到文件**：
   - 常见原因是直接在 WinRAR / 7-Zip / 系统压缩包预览窗口里双击了脚本。优先推荐使用 `git clone https://github.com/cosmosomo/WebAI2PC.git` 源码目录运行 `一键启动_Cosmos_MCP.bat`；若使用 `.zip` 归档，请先完整解压到普通文件夹后再双击（目标 Windows 电脑无 Python 且无法安装时再选用 `*win64-full.zip` 离线兜底包）。
2. **中国大陆使用 `*.workers.dev` 时授权页打不开或后台隧道反复超时重连**：
   - `*.workers.dev` 在中国大陆运营商与公共 DNS 下存在全量 DNS 污染（无代理裸连 `100%` 超时）。若未绑定自定义域名，**本机后台运行期间必须保持系统 HTTP/HTTPS 代理常开且规则允许代理访问 `*.workers.dev`**（首次打开 `/consent` 授权页若规则漏掉 `*.workers.dev` 可临时切全局完成授权，但切回规则模式后日常仍须让规则覆盖 `*.workers.dev`，关闭代理或直连会导致 `443 WSS` 断连；若设了 `NO_PROXY` 务必保留 `127.0.0.1,localhost,::1`）。若需国内免代理直连，请在第 2 张卡片绑定同 Cloudflare 账号下的自定义域名（Active Zone，并关闭该域 `Bot Fight Mode`），或使用第 1 张卡片 `*.srv.us` / 第 3 张卡片自有云服务器。
3. **点击授权页时未出现一键允许，或提示需要输入口令**：
   - 当在网页版 ChatGPT `Work` 模式的云端受控浏览器内点 `Take over` 打开授权页、在手机异地绑定，或同机浏览器隐私插件拦截了 `127.0.0.1` 回环跳转时，回到本地控制台主控首页展开 `配对与已连会话`，复制 6 位动态配对码（或点开复制 20 位固定备用口令）填入授权页即可通过。
4. **ChatGPT 个人 Plus / Pro 订阅测试 `/mcp` 时写操作受限**：
   - 当个人订阅受 OpenAI 平台策略限制仅放行自定义连接器的 `read/fetch` 工具时，请在控制台顶部切到 `网页版 ChatGPT`，点击只读栏的 **「复制只读配置提示词（发给 Work）」**（或点 `仅复制地址` 复制 `https://<域名>/mcp/readonly`）重新完成只读接入。
5. **Gemini 每次运行工具都弹出确认卡片**：
   - 请直接打开 `https://gemini.google.com/customize/connectors`（或左下角菜单 `Personal Intelligence -> Connected Apps`）点开对应连接器，把 `App actions` 改为 `Always allow`；不要在聊天流里的单张工具卡片上单独点允许（会冲掉连接器级免审批），查网页资料时让连接器调用内置 `pc_web_research`。
6. **换新电脑或重装系统后想保留原固定网址**：
   - 在旧电脑打开 `#settings/gateways` 第 1 张卡片底部点击 `导出身份恢复卡 PNG` 设口令保存图片；新电脑点击 `导入恢复卡 PNG` 上传图片并输入口令，即可原样恢复固定网址，无需重绑网页端连接器。
