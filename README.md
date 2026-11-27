<div align="center">

<img alt="WebAI2PC" src="assets/brand/webai2pc-logo-dark.svg#gh-dark-mode-only" width="360" />
<img alt="WebAI2PC" src="assets/brand/webai2pc-logo-light.svg#gh-light-mode-only" width="360" />

<p><strong>把网页版 Gemini 与 ChatGPT（连普通 Chat 模式也能直接干活）接进本地电脑 · 避开客户端代理与智能体额度折腾 · $0 额外 API 账单</strong></p>

<p>
  <a href="https://github.com/cosmosomo/WebAI2PC/releases"><img alt="Latest Release" src="https://img.shields.io/github/v/release/cosmosomo/WebAI2PC?color=10B981&label=Release" /></a>
  <a href="LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/License-MIT-2563EB.svg" /></a>
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-475569.svg" />
  <img alt="Hosts" src="https://img.shields.io/badge/Hosts-Web%20Gemini%20%26%20ChatGPT-0F766E.svg" />
</p>

<p><strong>简体中文</strong> · <a href="README_EN.md">English</a> · <a href="docs/README.md">文档中心 (docs/)</a></p>

</div>

<p align="center">
  <img alt="WebAI2PC 三步接入示意图：启动复制、粘贴进网页 AI、直接操作本地电脑" src="assets/readme/quickstart-flow-dark.svg#gh-dark-mode-only" width="100%" />
  <img alt="WebAI2PC 三步接入示意图：启动复制、粘贴进网页 AI、直接操作本地电脑" src="assets/readme/quickstart-flow-light.svg#gh-light-mode-only" width="100%" />
</p>

**WebAI2PC** 是一个运行在个人电脑上的本地 MCP 服务端与可视化控制台。把启动后生成的 HTTPS 地址粘贴进 **网页版 Google Gemini**（含同账号手机端 Gemini App）或 **网页版 ChatGPT** 的自定义连接器，无需另买 API 密钥即可直接复用已有网页会员：接入网页版 ChatGPT 后，除 `Work` 模式长程与定时任务外，**连日常普通 `Chat` 模式也能直接调本地工具改多文件工程、原样修订 Word / Excel / PPT、跑测试脚本，不消耗 `Work / Codex` 智能体额度**。

## 为什么用 WebAI2PC

| 对比维度 | 传统桌面客户端 / API 工具 | WebAI2PC（开源直连） |
| :- | :- | :- |
| **模型与费用** | 另买 API Key 每月多花 `$30–$100`，或受限于客户端额度 | **直接复用已有网页会员**（如 Gemini 4 系列、ChatGPT Team/Business 在 `Chat` 模式零智能体额度损耗直连），**`$0` 额外 API 费** |
| **安装与网络** | 卡代理、地区限制、配环境变量、换网断流 | **30 秒双击启动**，浏览器自带网络即开即用，免命令行 |
| **本地干活能力** | 网页 Chat 模式只能贴代码片段（或耗费 Work / Codex 额度），改文档易丢排版与公式 | **让 ChatGPT 普通 Chat 模式也能实跑本地多文件工程 + Office 原样保留排版/公式 + 定时任务推手机** |
| **安全边界** | 全盘高权限读写，误删改乱难回退 | **单目录隔离 · 改前自动快照一键撤回 · 删文件进回收站 · 托盘 0.1s 只读急停** |

## 30 秒上手

1. **下载并完整解压**：前往 [Releases 发布页](https://github.com/cosmosomo/WebAI2PC/releases) 下载发行包（Windows 免装 Python 选 `win64-full.zip`，其余环境选标准 `zip`），完整解压到普通文件夹。
2. **双击启动并复制地址**：Windows 双击 `一键启动_Cosmos_MCP.bat`（macOS / Linux 运行 `./start_cosmos_mcp.sh`），自动打开本地控制台 `http://127.0.0.1:8096/` 并生成免登录固定地址 `https://<域名>/mcp`。
3. **粘贴到网页端并点允许**：
   - **网页版 Gemini**：`Customize -> Connectors -> + Custom` 粘贴 `/mcp` 地址并授权，将 `App actions` 设为 `Always allow`，新对话首句输入 `[at]Cosmos` 唤醒；同账号手机端 Gemini App 自动同步可用。
   - **网页版 ChatGPT（首次代连找 `Work`，日常干活用 `Chat`）**：首次添加插件时，在控制台网关就绪后点 **「复制给 Work 模式帮我连接」** 切换到 ChatGPT 顶部 `Work` 模式发送由受控浏览器代填（网页版 `Work` 云端浏览器内点 `Take over` 打开授权页需输控制台 `6` 位动态配对码；`Chat` 模式无受控浏览器不能自动代连），或在本机浏览器左侧 `Plugins -> + -> Add custom MCP server` 填入 `/mcp`（工作区全功能）或 `/mcp/readonly`（个人 Plus / Pro 只读）创建并点 `Install` 安装 `WebAI2PC`（本机浏览器授权页直接点「本机一键允许连接」）。装好后同账号互通：日常改代码修文档切回 `Chat` 模式发 `@WebAI2PC`（响应快，不扣 `Work / Codex` 额度），跨应用长程交付与定时任务用 `Work` 模式发 `@WebAI2PC`，首次调用 `pc_get_status` 验证。

<details>
<summary><strong>懒得看教程？点此复制提示词发给任意 Gemini / ChatGPT，让 AI 手把手带你配好</strong></summary>

```text
请做我的 WebAI2PC 配置向导，先读取官方公开配置教程全文（支持联网请直接访问 https://raw.githubusercontent.com/cosmosomo/WebAI2PC/main/docs/AI_SETUP_GUIDE.md 或 https://github.com/cosmosomo/WebAI2PC/blob/main/docs/AI_SETUP_GUIDE.md ），再按以下核实摘要一步步带我配通（先问清我的电脑系统、是否已下载解压、准备连网页版 Gemini 还是 ChatGPT，每次只教当前这一步，不要一次刷满屏）：
1. 下载解压：去 https://github.com/cosmosomo/WebAI2PC/releases 下载（Windows 免装 Python 选 win64-full.zip，已装 Python 3.10+ 或 macOS/Linux 选标准 zip），必须先完整解压缩到普通文件夹，再双击 一键启动_Cosmos_MCP.bat（macOS/Linux 运行 ./start_cosmos_mcp.sh），浏览器会自动打开本地控制台 http://127.0.0.1:8096/ 。
2. 首次免注册直连：控制台默认开启「第 1 类：一键上手免登录直连」（自动生成 https://*.srv.us/mcp 或 *.trycloudflare.com/mcp）；若连 ChatGPT 且想让 AI 代填插件页面，网关就绪后点控制台「复制给 Work 模式帮我连接」，必须切换到 ChatGPT 顶部的 Work 模式再发送（Chat 模式无受控浏览器无法代填，只能输出文字步骤供手动点击；复制文本不含配对码与本机路径）。
3. 绑定与日常使用：Gemini 打开左侧 Customize -> Connectors -> + Custom，名称填 Cosmos 并粘贴 /mcp 地址（Client ID/Secret 留空），授权页点「本机一键允许连接」，再进连接器详情把 App actions 设为 Always allow，新对话首句发 [at]Cosmos 唤醒；ChatGPT 由 Work 模式受控浏览器代填（网页版 Work 云端浏览器内 Take over 打开授权页需输本地控制台 6 位动态配对码）或在本机浏览器打开左侧 Plugins -> + -> Add custom MCP server 填名称 WebAI2PC 与对应地址（工作区 /mcp，个人只读 /mcp/readonly）创建并点 Install 安装（本机浏览器授权页直接点「本机一键允许连接」）。安装完成后全账号互通：日常改代码跑测试切回 Chat 模式发 @WebAI2PC（快且不扣 Work/Codex 智能体额度），跨应用长程交付与定时任务切 Work 模式发 @WebAI2PC，首次调用 pc_get_status 确认接通。
4. 升级 Cloudflare 免费终身固定网址：点控制台右上角「设置 -> 连接与网关」（http://127.0.0.1:8096/#settings/gateways）展开第 2 类「Cloudflare 专属固定网关」，按两步部署免费 *.workers.dev/mcp 地址（令牌部署后自动销毁）。
5. 目录与 4 档权限：在主控首页左栏点「选文件夹」改工作目录，按需点选「只读 / 仅改文件 / 工作区开发 / 全盘开发」四档权限。
现在请先问我 3 个简短问题确认起点，带我开始第 1 步。
```

</details>

## 支持宿主范围

| 目标网页宿主 | 账号条件与模式分工 | 连接端点 |
| :- | :- | :- |
| **网页版 Google Gemini & 手机 App** | 年满 18 岁的 Google AI Pro / Ultra 或已开连接器权限的 Workspace 账号 | `https://<域名>/mcp`（全功能） |
| **网页版 ChatGPT（工作区账号）** | Team / Business / Enterprise / Edu（首次代连用 `Work` 或本机手动装插件；装好后日常用 `Chat` 零扣 `Work / Codex` 额度，长程/定时任务用 `Work`） | `https://<域名>/mcp`（全功能） |
| **网页版 ChatGPT（个人订阅账号）** | 个人 Plus / Pro（平台对自建 MCP 仅开放 `read/fetch` 时绑此地址；装好后 `Chat` 与 `Work` 均可调 `@WebAI2PC`） | `https://<域名>/mcp/readonly`（只读） |

## 本地可视化控制台

<p align="center">
  <img src="assets/readme/studio-console.png" alt="WebAI2PC 本地可视化控制台" width="100%" />
</p>

> 想看 **连接原理图、安全兜底图、16 项内置工具清单与移动端实拍**？请进入 **[二级文档中心（docs/）](docs/README.md)**。

## 二级教程与文档中心（[`docs/`](docs/README.md)）

| 文档 | 内容 |
| :- | :- |
| [01. 网页版 Gemini 与手机远程连接教程](docs/01_网页版Gemini与手机远程连接教程.md) | 下载启动、免审批总开关与手机端同步控机 |
| [02. 网页版 ChatGPT 工作区与个人只读接入教程](docs/02_网页版ChatGPT工作区与个人只读接入教程.md) | `/mcp` 全量模式与 `/mcp/readonly` 只读模式配置 |
| [03. 本地控制台面板与扩展包指南](docs/03_Cosmos_Studio面板与扩展包指南.md) | 4 档安全模式、目录分层、浏览器与桌面扩展包、Docker / Windows Sandbox |
| [04. 三大连接通道选型与网络排障手册](docs/04_三大连接通道选型与网络排障手册.md) | 免登录通道、Cloudflare 3 秒固定网关、自有 VPS 主站与排障 |
| [05. 多智能体并行与实战工作流教程](docs/05_多智能体并行子任务与实战工作流教程.md) | Skills 守则导入、Office 修订、多路并行子任务实战 |
| [AI 陪配单文件教程](docs/AI_SETUP_GUIDE.md) | 面向网页 AI 直读的公开配置教程 |

更多工程文档：[AGENTS.md](AGENTS.md) · [host_skills/SKILL.md](host_skills/SKILL.md) · [PRIVACY.md](PRIVACY.md) · [SECURITY.md](SECURITY.md) · [CHANGELOG.md](CHANGELOG.md)

## 开源许可

本项目基于 [MIT License](LICENSE) 开源发布。
