# 03. Cosmos Studio 面板、Windows 托盘与扩展包指南

`Cosmos Studio` 是随服务内置启动的可视化控制台，用于复制网页端 Gemini 与 ChatGPT 所需的 HTTPS 连接地址、打开内置交互式教程页（`/tutorials`）、切换 4 套明暗双模风格包与 4 套 IP 图标转向姿态、独立开关并存管理 3 类连接网关、管理读写分层工作区与 4 档安全模式、热启停外设扩展包以及恢复文件快照。

## 一、Windows 系统托盘、电源策略与紧急只读切换

- **Windows 托盘四色状态灯与快捷菜单**：在 Windows 桌面会话下启动服务后，任务栏通知区域常驻状态圆点图标（绿色表示公网网关已连接且已有网页会话就绪，蓝色表示本地服务就绪，橙色表示通道正在重连，红色表示连接异常；网络异常时静默更新托盘图标颜色、悬停提示与控制台状态横幅指明本地代理关闭或断网原因，全程零系统气泡弹窗打扰焦点）。右键托盘图标可一键打开控制台面板、复制 MCP 连接地址、复制首句唤醒词或切换为只读浏览模式，也可在控制台热开关托盘图标（`tray_enabled`）。
- **笔记本交流电与电池智能防休眠**：开启首屏右上角「插电防自动休眠（笔记本合盖仍会断网）」开关后，台式机与插交流电源的笔记本会自动维持系统唤醒防止 15 分钟息屏断连；笔记本拔掉电源改用电池供电时自动解除防休眠以节省电量，唤醒后约 1.5 秒内自动重连网关。
- **单次口令会话解锁与免口令切只读**：远程访问修改配置前在控制台顶部输入一次本机口令解锁（签发 12 小时有效的 `HttpOnly` 会话 Cookie，本机直连自动授权）；在控制台顶部点击「一键切换只读保护」（或「工具中心与安全开关」页的「切为只读浏览」、托盘菜单「切换为只读浏览模式」）无需输入口令即可立即切至 `L1` 只读档位，并在 0.1 秒内终止所有在途命令与外设会话。

## 二、控制台五大功能页说明

1. **总览与网页连接**：
   - 面向网页版 Gemini（绑 `/mcp`）与网页版 ChatGPT（Team / Enterprise 工作区账号绑 `/mcp`，个人 Plus / Pro 账号绑 `/mcp/readonly`）展示当前可用的 HTTPS 连接地址、6 位动态配对码与连接口令；提供「复制 AI 操作守则（推荐存入 Skills）」按钮一键复制当前工具守则；自定义连接器名称建议填写 `Cosmos`，授权刚完成时弹出绿色已连接横幅及「一键复制首句唤醒测试词」按钮（自动生成 `@Cosmos 帮我看看当前工作目录里有哪些文件`）。
   - **多网关独立开关并存**：3 张连接卡片右上角均配独立开关与实时状态标签，支持同时开启多路网关（如同时开启 `srv.us` 与 `Cloudflare Workers` 互不断连），点击任一已连通卡片即可切换顶部展示与复制的网关地址：① **一键上手就能用**（零登录开箱即连，默认优先连接 `https://xxxxx.srv.us` 持久固定网址，22 端口受阻自动切换 `*.trycloudflare.com` 临时通道，同机浏览器点击「本机一键允许连接（免输口令）」直接放行）；② **登录 Cloudflare 注册一下就行**（点预填链接贴一次令牌，约 3 秒自动部署免费 SQLite Durable Object 休眠网关如 `https://your-worker.your-subdomain.workers.dev` 获得终身固定网址，令牌即刻清零，后续直接拨开关启停免重填令牌）；③ **自己的服务器和域名**（填服务器 IP，支持使用 SSH 密码、填写本地 SSH 私钥路径或勾选本机默认 SSH 密钥免密登录一键部署 24 小时常驻主站同时管服务器与本地电脑，或绑定 Cloudflare Named Tunnel 固定令牌 / 自有反代域名）。
   - **顶栏交互式教程与可换风格切换器**：顶栏右侧提供「实战教程」按钮直达 `/tutorials` 6 章 24 步交互式教程中心、「深色模式 / 浅色模式」快捷切换按钮，以及「外观」浮层开关（支持切换 `warm-paper`、`obsidian-emerald`、`cupertino-frost`、`graphite-mono` 4 套明暗双模风格包、4 款 IP 图标包与 4 种视线朝向姿态；URL 附带 `?debug=1` 时可额外显示宣传片 `StylePack JSON` 导出按钮，详见 `.interface-design/system.md`）。
   - 查看已连接网页会话列表并支持单个断开或点击「全部断开」吊销。
2. **工作区与 Python 环境**：
   - **原生文件夹选择框与常见目录快选**：点击「选择本地文件夹」可调起操作系统原生目录选择框（Windows 64 位 `IFileOpenDialog`、macOS `osascript`、Linux `zenity` / `kdialog`，无图形会话自动回退「打开页内目录树选择文件夹」），并自动扫描本机常见代码目录供一键添加；首次无配置启动默认创建并开放 `~/CosmosWorkspace`。
   - **只读参考目录 + 子项目读写分层**：支持单独添加只读参考目录，或将每个已添加目录独立设为「可读写」（`workspace_roots`）或「只读父目录 / 参考目录」（`readonly_workspace_roots`）。把外层代码总目录设为只读参考、把内部当前开发的子项目设为可读写时，服务端与子进程沙盒均按最长路径前缀匹配权限，跨项目查阅参考代码时若误写外层其他仓库会返回 `ERR_READONLY_WORKSPACE` 拦截。
   - **Python 环境选择**：自动扫描已缓存 `.venv`、`python-embed`、官方 Python、Conda 与 `uv` 环境供 `pc_run_python` 与 `pc_bg_command` 调用。
3. **工具中心与安全开关**：
   - 支持在 **4 档安全权限**之间即时热切换：`L3` 工作区内顺畅开发（默认推荐，点击「切为工作区内开发」）、`L4` 全盘顺畅开发（不限目录）（允许跨任意本地目录读写与运行命令，保留回收箱与密钥隔离，点击「开启全盘顺畅开发」）、`L2` 仅改文件禁跑命令（点击「切为仅改文件」）、`L1` 只读浏览模式（点击「切为只读浏览」）；支持按需开启「受管浏览器包」、「桌面窗口操控包」、修改工具前缀（点击「保存工具前缀」），或开关「扫描本机全局技能目录（如 .claude / .codex）」（默认关闭，隔离外部客户端目录）。
   - 内置多格式只读提取与零 C 扩展依赖的 `.docx` / `.xlsx` 安全修订能力：`pc_read_file` 支持直接查看本地图片并提取 PDF、`.docx`、`.xlsx`、`.pptx` 文本；`pc_edit_file` 可直接跨 `<w:r>` 样式节点替换 `.docx` 段落与表格文字（保留首段字体样式），或按 `Sheet!A1` 坐标更新 `.xlsx` 单元格与公式；当目标文档正被 Word 或 Excel 打开锁表（存在 `~$` 锁文件或句柄占用）时自动返回 `ERR_OFFICE_FILE_LOCKED` 保护原文件，写前自动保存二进制快照并支持在面板或通过 `pc_manage_files(action="undo")` 原样撤回。
4. **实时任务与修改恢复**：实时查看后台任务（`pc_bg_command`）运行状态与尾部输出日志、一键点击「终止全部在途任务」；列出写前自动留存的文件与 Office 文档历史快照供对比 Diff 与撤回修改，并展示操作审计记录。
5. **技能中心**：
   - 包含「本机技能与详情」、「在线市场与体检安装」、「新建技能」与「安全回收箱」四个子页，支持执行三级 AST 安全体检后安装或创建受管技能；默认仅加载开放工作区 `.agents/skills`、内置 `cosmos-mcp-guide` 守则与受管 `skills_store`。

## 三、受管浏览器扩展包（`browser` -> `pc_browser_use`）

开启「受管浏览器包」（或运行 `cosmos-mcp permissions --enable-pack browser`）后，在 `L3` 与 `L4` 模式下可使用 `pc_browser_use`（可选安装 `pip install ".[browser]"` 使用 Playwright，未安装时自动复用本机 Edge / Chrome / Chromium 无头 CDP 协议）。

- **独立配置隔离与下载路由**：固定使用 `<状态目录>/browser_profile` 独立目录运行，不读取或干扰个人日常浏览器窗口；内置同步 SSRF 守卫拦截 `file://`、云厂商元数据地址及本机受保护端口，网页下载文件默认保存至当前可读写工作目录。
- **真实 DOM 可见性过滤**：`snapshot`、`click`、`fill`、`select` 会检查元素及祖先节点的 `display`、`visibility`、`opacity` 与非零包围盒尺寸；同名隐藏移动端表单与可见桌面端表单并存时自动命中可见控件，全部不可见时返回 `ok=False` 与 `ERR_ELEMENT_HIDDEN`。
- **支持动作清单**：`open`、`snapshot`（返回可见交互节点引用如 `e1`、当前 `scroll_y` 与总高度 `scroll_height`）、`click`、`fill`、`select`、`scroll`、`list_tabs`、`switch_tab`、`open_login_window`（以 `SW_SHOWNOACTIVATE` 无焦点抢占方式打开受管登录窗口供人工扫码）、`screenshot`、`evaluate`、`close`。

## 四、Windows 桌面窗口操控扩展包（`desktop` -> `pc_cua_window`）

在 Windows 系统开启「桌面窗口操控包」（或运行 `cosmos-mcp permissions --enable-pack desktop`）后，在 `L3` 与 `L4` 模式下可使用 `pc_cua_window`。在 macOS 与 Linux 系统上启动服务时自动跳过注册该扩展包。

- **零抢焦点与作用域围栏**：全程采用离屏 `PrintWindow(2)` 抓图与后台窗口消息，每次调用核验前台焦点未变、物理光标未动、剪贴板零增量。`L3` 模式下仅允许枚举和操作归属当前开放工作目录或当前会话启动的窗口；遇到锁屏或黑屏返回 `ERR_SCREEN_LOCKED_OR_BLACK_FRAME`；关闭含未保存标记的窗口时自动拦截保护。
- **缩放坐标反算与按键合成**：长边超过 `1440px` 的大窗口抓图自动按句柄缓存 `scale_factor`，后续 `click`、`double_click`、`right_click`、`type_text`、`scroll` 在默认 `coord_space="auto"` 下自动反算回真实客户区像素坐标；多输入框按坐标递归定位目标子控件句柄写入文本；`send_keys` 支持解析 `ctrl+s`、`ctrl+shift+z`、`alt+f4` 及方向键与功能键组合。

## 五、使用 `sandbox/` 运行容器或系统沙盒隔离

除应用层读写目录护栏外，仓库根目录 `sandbox/` 提供两套系统级隔离配置：

1. **Docker 非特权容器（Linux / macOS / Windows Docker Desktop）**：
   ```bash
   COSMOS_HOST_WORKSPACE=/path/to/project docker compose -f sandbox/docker-compose.yml up -d --build
   ```
   容器以非特权用户 `cosmos`（`1000:1000`）运行，启用 `no-new-privileges:true` 与 `cap_drop: ALL`，仅挂载指定项目目录。
2. **Windows Sandbox 一次性轻量虚拟机（Windows 10/11 专业版或企业版）**：
   在项目旁创建 `workspace` 文件夹后双击 `sandbox/CosmosMCP_WindowsSandbox.wsb`，即可在独立虚拟机内只读挂载程序目录并启动服务，关闭沙盒窗口后运行环境自动销毁。
