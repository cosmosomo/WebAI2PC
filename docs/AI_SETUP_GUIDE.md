# WebAI2PC (Cosmos MCP) 公开配置教程（供任意网页版 Gemini / ChatGPT 直读陪配）

本文档采用固定英文文件名，方便任何网页版 Google Gemini 或网页版 ChatGPT 直接读取并一步步指导用户完成下载、首次连接与 Cloudflare 固定网址配置：
- GitHub 页面链接：`https://github.com/cosmosomo/WebAI2PC/blob/main/docs/AI_SETUP_GUIDE.md`
- Raw 纯文本链接：`https://raw.githubusercontent.com/cosmosomo/WebAI2PC/main/docs/AI_SETUP_GUIDE.md`

## 一、给当前 AI 助手的陪配引导职责

如果你正在对话中协助用户安装或配置 WebAI2PC（Cosmos MCP），请遵守以下交互原则：
1. **先问清 3 项基本情况**：若用户尚未说明，先用简短列表问清：① 电脑系统是 Windows、macOS 还是 Linux；② 是否已经下载并解压缩发行包；③ 准备连接网页版 Gemini，还是网页版 ChatGPT（Team / Enterprise 工作区账号还是个人 Plus / Pro 账号，以及当前处于 `Chat` 模式还是 `Work` 模式）。
2. **每次只教当前这一步**：根据用户的回答，每次只给出当前步骤的 3 至 5 行具体操作与按钮名称，等用户回复「好了」或发来报错截图后再讲下一步，不要一次性把全文刷满屏幕。
3. **如实说明 ChatGPT `Work` 与 `Chat` 的代连边界**：若用户正在 ChatGPT 对话中找你帮忙连接，先说明只有 `Work` 模式具备受控浏览器可代填 `Plugins` 页面（`Chat` 模式无受控浏览器，只能一步步提示点击位置，或请用户切换到顶部 `Work` 模式）；且配对码、口令、令牌与本机路径切勿发进聊天框。
4. **已连上 `[at]Cosmos` 或 `@WebAI2PC` 时直接接管打开设置页**：一旦用户已经绑定好连接器，提示用户可以直接在对话里说：`[at]Cosmos 帮我在电脑上打开网关设置页，教我怎么配 Cloudflare 固定网址`（ChatGPT 用 `@WebAI2PC`）。已连上的 AI 可直接调用本地工具帮用户在电脑浏览器弹出对应配置页并核对实时状态。

## 二、下载选包与完整解压启动

发布页下载地址：`https://github.com/cosmosomo/WebAI2PC/releases`

1. **按电脑环境选包**：
   - **Windows 普通用户（推荐首选）**：下载完整离线绿色包 `Cosmos-MCP-v1.2.1-win64-full.zip`。包内已自带免安装 Python 3.12 运行环境与全部核心依赖，电脑无需安装 Python。
   - **已安装 Python 3.10~3.14 的开发者，或 macOS / Linux 用户**：下载标准轻量包 `Cosmos-MCP-v1.2.1.zip`，启动脚本会自动识别系统 Python、Conda 或 `uv` 环境并跳过 Windows 商店空壳。
2. **先完整解压再运行（必看防错点）**：
   - 下载完成后，请右键 `.zip` 压缩包选择「全部解压缩」到桌面或任意普通文件夹，**切勿直接在压缩软件预览窗口里双击运行脚本**。
3. **启动本地控制台**：
   - **Windows**：进入解压后的文件夹，双击 `一键启动_Cosmos_MCP.bat`。
   - **macOS / Linux**：在终端进入解压目录，执行 `./start_cosmos_mcp.sh`。
   - 服务会在后台无窗口启动，并自动用浏览器打开本地控制台 `http://127.0.0.1:8096/`（页面标题为 `WebAI2PC · 本地控制台`）。

## 三、首次免注册连上网页版 Gemini / ChatGPT（三步走）

首次启动无需注册任何第三方账号即可连上测试：

1. **第 1 步：在本地控制台复制连接地址**
   - 控制台默认开启第 1 类通道「一键上手免登录直连」，自动生成 `https://*.srv.us/mcp`（免登录固定网址，重启不变）或 `https://*.trycloudflare.com/mcp`（免注册快速通道）。
   - 若连 **网页版 Gemini**，保持顶部选中 `网页版 Gemini`，点击蓝色按钮 `复制连接地址`。
   - 若连 **网页版 ChatGPT**，点击顶部切换到 `网页版 ChatGPT`（网关就绪后按钮自动开放）：若准备让 `Work` 模式受控浏览器代填，点击 **「复制给 Work 模式帮我连接」**（仅生成含真实 `/mcp` 或 `/mcp/readonly` 地址的配置请求，不含配对码、口令、令牌与本机路径）；若在本机浏览器手动添加，点击 `复制地址`（Team / Business / Enterprise / Edu 工作区全功能 `/mcp`）或 `复制只读`（个人 Plus / Pro 只读 `/mcp/readonly`）。
2. **第 2 步：添加到网页端并点允许**
   - **网页版 Gemini（需 18+ Google AI Pro / Ultra 或已开启权限的 Workspace 账号）**：
     1. 打开网页版 Gemini，在左侧栏依次点击 `Customize（自定义） -> Connectors（连接器） -> + Custom（添加自定义）`。
     2. 名称填写 `Cosmos`，URL 粘贴刚才复制的 `https://.../mcp`（`Client ID` 与 `Client Secret` 留空不填），提交后会跳转到本地授权确认页。
     3. 在同一台电脑的浏览器上直接点击 `本机一键允许连接` 即可完成绑定。
     4. 绑定成功后，点进 `Cosmos` 连接器详情页，将 **`App actions` 总开关设为 `Always allow（始终允许）`**（建议顺手在本地控制台点 `复制 AI 守则` 粘贴到 Gemini 左侧栏 `Customize -> Skills` 保存）。
   - **网页版 ChatGPT（严格区分 `Work` 代连与本机手动添加）**：
     1. **发给 `Work` 模式代填配置**：只有 `Work` 模式具备受控浏览器（网页版 `Work` 自带云端受控浏览器并支持 `Take over` 接管，桌面版 `Work` 支持通过 `@Chrome` / `@Edge` 扩展操作本机标签页），请先在 ChatGPT 顶部切到 `Work` 模式再粘贴发送连接请求；`Chat` 模式没有受控浏览器，无法操作 `chatgpt.com/plugins`，只能输出文字步骤供用户手点。
     2. **手动或按文字引导点击位置**：打开左侧栏 `Plugins -> + -> Add custom MCP server`，名称填 `WebAI2PC`，`Connection` 粘贴对应 HTTPS 地址，认证选 `OAuth`（自动协商，无需填 Client ID / Secret），勾选风险提示确认框后点 `Create as a plugin`，并在插件列表中点击 **`Install`** 完成安装。
     3. **云端浏览器与本机浏览器的授权确认差异**：在本机浏览器手动添加（或桌面版 `Work` 调本机浏览器扩展）跳转 `/consent` 时命中 `127.0.0.1` 回环，直接点 `本机一键允许连接`；若在网页版 `Work` 云端浏览器里点 `Take over` 打开 `/consent`，因浏览器运行在 OpenAI 云端不在本机，页面会提示输入本地控制台 `配对与已连会话` 显示的 `6` 位动态配对码，填好允许后点 `Return control` 交回。
3. **第 3 步：首句唤醒并以 `pc_get_status` 成功作为接通标准**
   - **网页版 Gemini**：新建对话（建议开启任务模式），首句输入 `[at]Cosmos 帮我调用 pc_get_status 看看当前工作目录里有哪些文件`（输入 `[at]Cosmos` 时点选弹出的连接器标签）。同账号手机端 Gemini App 也会自动同步该连接器。
   - **网页版 ChatGPT（装好后日常用 `Chat` 省额度，长任务用 `Work`）**：插件点 `Install` 安装后全账号共享。日常查改本地代码、修 Office、跑无窗口命令与测试推荐切回 **`Chat` 模式**输入 `@WebAI2PC`（响应快，走普通对话限额，零消耗 `Work / Codex` 智能体额度）；需要结合云端浏览器、跨邮件/Slack/网盘做长程交付或配置 `Scheduled Tasks` 定时任务时切 **`Work` 模式**输入 `@WebAI2PC`，首次调用 `pc_get_status`（`get_status`）成功返回本机状态与目录即接通完成。操作守则在工作区/桌面端可存入原生 `Skills`，网页版 `Chat` 与 `Work` 均可粘贴到 `Project Instructions` 或自定义指令。

## 四、进阶配置 Cloudflare 免费终身固定网址（`#settings/gateways` 方式 2 三步走）

若用户希望配置免费、无服务器账单且终身不变的专属 HTTPS 网址（或绑定自己的域名），引导用户按以下三步操作：

1. **进入网关设置页展开第 2 张卡片**：
   - 在本地控制台右上角点击 `设置` -> 左侧栏选择 `连接与网关`（浏览器地址为 `http://127.0.0.1:8096/#settings/gateways`；若已连上 `@Cosmos`，可直接让 AI 帮忙打开此页）。
   - 找到 **第 2 类 · 无服务器固定网址：`Cloudflare 专属固定网关`**，点击卡片右侧的 `配置 ▾`（3 张网关卡片支持独立开关同时在线，部署期间不会断开正在使用的第 1 类通道）。
2. **三步完成 3 秒一键部署**：
   - **① 打开预填权限页生成令牌**：点击卡片内的 `第 1 步：打开 Cloudflare 预填权限页（支持 Google 快捷登录）`。在打开的 Cloudflare 网页登录账号（所需 Workers 权限已自动勾选），滚动到底部点击 `Continue to summary` -> `Create Token`，复制生成的 API 令牌。
   - **② 粘贴令牌（可选填自有域名）**：回到本地控制台，把令牌粘贴进 `第 2 步：粘贴 API 令牌（部署后立即销毁）` 输入框。若用户在 Cloudflare 名下有已激活的域名（Active Zone），可在右侧 `选填：自定义域名（Active Zone，国内免切代理）` 填入子域名（例如 `mcp.yourdomain.dpdns.org`）；若账号下有多个 Cloudflare 账户，在下拉框选定目标账户。
   - **③ 点击部署并替换网址**：点击蓝色按钮 `一键部署并开启（约 3 秒）`。系统会自动认领子域并部署免费 Cloudflare Workers + SQLite Durable Object 休眠网关，生成终身固定的 `https://*.workers.dev/mcp`（及 `/mcp/readonly`）。
3. **部署后的令牌安全与日常使用**：
   - 部署完成瞬间，刚才粘贴的 Cloudflare API 令牌会自动从内存与磁盘清零销毁。
   - 点击卡片上的 `复制此卡地址`（个人版 ChatGPT 点 `复制 Plus/Pro 只读`），到网页端连接器更新一次 URL 后即可永久固定使用；后续只需拨动第 2 张卡片右上角开关即可随时启停，无需再次填写令牌。
   - *附：自有云服务器用户* 可展开第 3 张卡片 `自有云服务器 24h 主站 或 自有固定域名`，填写 Linux 服务器公网 IP 与 SSH 密码（或勾选 `使用本机默认 SSH 密钥免密登录`），点击 `一键部署 24h 主站并开启`，即可通过单连接器 `target="auto"` 同时管理云服务器与本地电脑。

## 五、4 档安全权限与父目录只读分层

在本地控制台主控首页左栏「开放工作目录」卡片中，用户可以随时调整开放范围与权限档位（点击即生效，无需重启）：

1. **4 档安全权限说明**：
   - **`只读`（`L1`）**：仅允许读取文件、检索代码与查阅内置技能，禁止修改任何文件或执行命令。顶栏右侧也提供 `一键只读` 按钮供随时应急切换。
   - **`仅改文件`（`L2`）**：允许在可读写工作目录内读取和修改代码及 `.docx` / `.xlsx` 文档，禁止执行终端命令、Python 脚本和外设扩展包。
   - **`工作区开发`（`L3`，默认推荐）**：允许在已开放的可读写工作目录内读写文件、移入安全回收箱、后台无窗口执行命令与 Python 脚本；只读参考目录内仅允许读取。
   - **`全盘开发`（`L4`）**：允许跨本机任意路径读写与运行命令，同时保留系统敏感密钥目录隔离、写前快照与安全回收箱保护。
2. **添加工作目录与父只读子读写分层**：
   - 点击 `选文件夹`（或粘贴路径点 `添加`）即可增加工作目录。
   - 若希望让 AI 参考整个大仓库但只修改其中某个子目录，可先勾选 `以只读参考目录添加` 添加外层父目录，再关闭该开关添加内部子项目目录；系统按最长路径前缀自动匹配读写权限。
   - 所有文件修改与清理均可在主控首页右栏 `实时动态与撤回` 的 `修改撤回`（查看 Diff 一键回退）与 `回收箱` 中恢复。

## 六、已连上 `@Cosmos` 后直接让 AI 打开对应设置页的方法

一旦用户完成了首次绑定，后续任何配置都无需自己翻找菜单，直接在网页聊天框对 `@Cosmos` 发送自然语言指令即可：
- 说：`@Cosmos 帮我在电脑上打开网关设置页，一步步教我配置 Cloudflare 固定网址`
- 说：`@Cosmos 帮我打开工具扩展设置页，我想开启受管浏览器和桌面窗口操控`
- 说：`@Cosmos 帮我看看现在开放了哪些文件夹、当前是什么权限档位`

此时已连接 MCP 的 AI 会调用以下内置能力配合引导：
- 调用 `pc_get_status(guide="cloudflare"|"gateways"|"permissions"|"gemini_chatgpt"|"packs_and_skills"|"troubleshooting"|"all", open_page="gateways"|"studio"|"runtime"|"tools"|"skills"|"tutorials")`，直接在同机电脑浏览器弹出对应本地设置页并读取当前状态；
- 调用 `pc_skill_hub(action="load", skill="webai2pc-setup-tutorial")`（在 `L1` 只读档位与 `/mcp/readonly` 端点下同样可用），加载完整的内置界面按钮对照教程。

## 七、常见卡点排障速查

1. **Windows 双击启动脚本没反应或提示找不到文件**：
   - 90% 是因为直接在 WinRAR / 7-Zip / 系统压缩包预览窗口里双击了脚本。请先把整个 `.zip` 完整解压到桌面文件夹后再双击 `一键启动_Cosmos_MCP.bat`；未装 Python 的电脑请下载 `win64-full.zip`。
2. **首次绑定 `*.workers.dev` 地址时浏览器打开授权页很慢或超时**：
   - 部分网络下规则代理未将 `*.workers.dev` 纳入代理。将本机代理软件临时切换为「全局模式」约 10 秒，点完 `本机一键允许连接` 后即可切回原规则模式；或者在第 2 张卡片选填已托管在 Cloudflare 的自定义域名。
3. **点击授权页时未出现一键允许，或提示需要输入口令**：
   - 当在网页版 ChatGPT `Work` 模式的云端受控浏览器内点 `Take over` 打开授权页、在手机异地绑定，或同机浏览器隐私插件拦截了 `127.0.0.1` 回环跳转时，回到本地控制台主控首页展开 `配对与已连会话`，复制 6 位动态配对码（或点开复制 20 位固定备用口令）填入授权页即可通过。
4. **ChatGPT 个人 Plus / Pro 订阅测试 `/mcp` 时写操作受限**：
   - 当个人订阅受 OpenAI 平台策略限制仅放行自定义连接器的 `read/fetch` 工具时，请在控制台顶部切到 `网页版 ChatGPT`，点击 `复制只读`（或右侧只读栏的 `复制给 Work 模式帮我连接`）使用 `https://<域名>/mcp/readonly` 地址绑定。
5. **Gemini 每次运行工具都弹出确认卡片**：
   - 请到 Gemini 左侧栏 `Customize -> Connectors -> Cosmos` 详情页把 `App actions` 改为 `Always allow`；不要在聊天流里的单张工具卡片上单独点允许（会冲掉连接器级免审批），查网页资料时让 `@Cosmos` 用内置 `pc_web_research`。
6. **换新电脑或重装系统后想保留原固定网址**：
   - 在旧电脑打开 `#settings/gateways` 第 1 张卡片底部点击 `导出身份恢复卡 PNG` 设口令保存图片；新电脑点击 `导入恢复卡 PNG` 上传图片并输入口令，即可原样恢复固定网址，无需重绑网页端连接器。
