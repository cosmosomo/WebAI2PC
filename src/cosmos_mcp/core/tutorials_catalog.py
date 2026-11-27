"""Pure-stdlib AI-accessible setup & Studio tutorial catalog + safe loopback UI launcher.

Zero third-party dependencies (`core` layer contract). Provides:
1. `TUTORIAL_TOPICS` & `get_tutorial_guide`: structured step-by-step instructions aligned 100%
   with the WebAI2PC Local Console (`v1.2.1` `index.html` & `/tutorials`).
2. `render_public_tutorials_markdown`: pure static Markdown manual for `GET /tutorials.md` and
   `GET /llms.txt` with ZERO host paths, usernames, ports, or runtime state.
3. `resolve_local_studio_page` & `open_local_studio_page_safely`: strict allowlist-only local
   `http://127.0.0.1:<port>/...` URL resolver and windowless browser launcher.
"""
from __future__ import annotations

import os
import subprocess
import sys
from typing import Any, Callable, Dict, Tuple
from urllib.parse import urlsplit
import webbrowser

from cosmos_mcp.core.config import PRODUCT_VERSION

CREATE_NO_WINDOW = 0x08000000

CANONICAL_GUIDE_TOPICS: Tuple[str, ...] = (
    "overview",
    "cloudflare",
    "gateways",
    "permissions",
    "gemini_chatgpt",
    "packs_and_skills",
    "troubleshooting",
    "all",
)

ALLOWED_STUDIO_PAGE_KEYS: Tuple[str, ...] = (
    "studio",
    "workbench",
    "home",
    "permissions",
    "workspace",
    "gateways",
    "cloudflare",
    "workers_dev",
    "vps",
    "runtime",
    "system",
    "autostart",
    "tools",
    "packs",
    "skills",
    "appearance",
    "theme",
    "tutorials",
    "docs",
)

# Strict allowlist mapping: key -> (canonical_page, path_or_hash_suffix, default_guide_topic)
_STUDIO_PAGE_MAP: Dict[str, Tuple[str, str, str]] = {
    "studio": ("studio", "/", "overview"),
    "workbench": ("studio", "/", "overview"),
    "home": ("studio", "/", "overview"),
    "permissions": ("permissions", "/", "permissions"),
    "workspace": ("permissions", "/", "permissions"),
    "gateways": ("gateways", "/#settings/gateways", "gateways"),
    "cloudflare": ("cloudflare", "/#settings/gateways", "cloudflare"),
    "workers_dev": ("cloudflare", "/#settings/gateways", "cloudflare"),
    "vps": ("gateways", "/#settings/gateways", "gateways"),
    "runtime": ("runtime", "/#settings/runtime", "troubleshooting"),
    "system": ("runtime", "/#settings/runtime", "troubleshooting"),
    "autostart": ("runtime", "/#settings/runtime", "troubleshooting"),
    "tools": ("tools", "/#settings/tools", "packs_and_skills"),
    "packs": ("tools", "/#settings/tools", "packs_and_skills"),
    "skills": ("skills", "/#settings/skills", "packs_and_skills"),
    "appearance": ("appearance", "/#settings/appearance", "overview"),
    "theme": ("appearance", "/#settings/appearance", "overview"),
    "tutorials": ("tutorials", "/tutorials", "overview"),
    "docs": ("tutorials", "/tutorials", "overview"),
}

_GUIDE_ALIASES: Dict[str, str] = {
    "overview": "overview",
    "quickstart": "overview",
    "start": "overview",
    "intro": "overview",
    "studio": "overview",
    "workbench": "overview",
    "home": "overview",
    "appearance": "overview",
    "theme": "overview",
    "cloudflare": "cloudflare",
    "workers": "cloudflare",
    "workers_dev": "cloudflare",
    "cf": "cloudflare",
    "gateways": "gateways",
    "gateway": "gateways",
    "vps": "gateways",
    "vps_hub": "gateways",
    "srv_us": "gateways",
    "self_hosted": "gateways",
    "tunnels": "gateways",
    "permissions": "permissions",
    "permission": "permissions",
    "workspace": "permissions",
    "workspaces": "permissions",
    "tiers": "permissions",
    "tier": "permissions",
    "safety": "permissions",
    "undo": "permissions",
    "trash": "permissions",
    "gemini_chatgpt": "gemini_chatgpt",
    "gemini": "gemini_chatgpt",
    "chatgpt": "gemini_chatgpt",
    "host": "gemini_chatgpt",
    "connectors": "gemini_chatgpt",
    "connector": "gemini_chatgpt",
    "mobile": "gemini_chatgpt",
    "packs_and_skills": "packs_and_skills",
    "tools": "packs_and_skills",
    "packs": "packs_and_skills",
    "skills": "packs_and_skills",
    "browser": "packs_and_skills",
    "desktop": "packs_and_skills",
    "prefix": "packs_and_skills",
    "recovery_card": "packs_and_skills",
    "troubleshooting": "troubleshooting",
    "troubleshoot": "troubleshooting",
    "faq": "troubleshooting",
    "proxy": "troubleshooting",
    "autostart": "troubleshooting",
    "runtime": "troubleshooting",
    "pair_code": "troubleshooting",
    "all": "all",
    "full": "all",
    "manual": "all",
    "tutorials": "all",
    "llms": "all",
}


def _sanitize_port(port: Any) -> int:
    try:
        val = int(port)
    except (TypeError, ValueError):
        val = 8096
    if val < 1 or val > 65535:
        return 8096
    return val


def build_studio_deep_links(port: int = 8096) -> Dict[str, str]:
    """Return canonical loopback Studio deep links for a given local `port`."""
    eff_port = _sanitize_port(port)
    base = f"http://127.0.0.1:{eff_port}"
    return {
        "studio": f"{base}/",
        "gateways": f"{base}/#settings/gateways",
        "cloudflare": f"{base}/#settings/gateways",
        "permissions": f"{base}/",
        "runtime": f"{base}/#settings/runtime",
        "tools": f"{base}/#settings/tools",
        "skills": f"{base}/#settings/skills",
        "appearance": f"{base}/#settings/appearance",
        "tutorials": f"{base}/tutorials",
    }


def _build_topic_templates(port_placeholder: str) -> Dict[str, Dict[str, Any]]:
    base = f"http://127.0.0.1:{port_placeholder}"
    return {
        "overview": {
            "topic": "overview",
            "title": "快速上手与 WebAI2PC 本地控制台界面导览",
            "aliases": ("overview", "quickstart"),
            "recommended_page": "studio",
            "markdown": (
                "### 快速上手与本地控制台界面导览\n\n"
                "1. **三步连上网页端 AI**：\n"
                f"   - **第 1 步（启动并打开控制台）**：双击启动脚本后，本机浏览器打开主控首页 `{base}/`。\n"
                "   - **第 2 步（复制 HTTPS 地址并绑定）**：在主控首页顶部连接卡选择 `网页版 Gemini` 或 `网页版 ChatGPT`（ChatGPT 首次添加插件时，网关就绪后首选点 `复制地址并打开 ChatGPT 插件页` 在已登录本机浏览器打开 `https://chatgpt.com/plugins` -> `＋ -> 添加自定义 MCP 服务器`，填 `WebAI2PC` 粘贴 `/mcp` 或 `/mcp/readonly`，授权页点 `本机一键允许连接` 并点 `Install` 安装；遇到连接或 `403` 权限问题点旁侧 `复制给 ChatGPT 接入 / 排障`；若在网页版 `Work` 云端浏览器内点 `Take over` 打开授权页则输控制台 `6` 位动态配对码），以调用 `pc_get_status` 成功作为接通标准。\n"
                "   - **第 3 步（开启免审批与按场景唤醒）**：Gemini 在网页端连接器设置中将 `App actions` 设为 `Always allow`，回到聊天框首句输入 `@Cosmos`；ChatGPT 安装插件后同账号共享，日常改代码跑脚本切回 `Chat` 模式输入 `@WebAI2PC`（响应快且不扣 `Work / Codex` 额度），跨应用长程交付与定时任务用 `Work` 模式输入 `@WebAI2PC`。\n"
                "2. **三个本地页面分工**：\n"
                f"   - **主控首页**（`{base}/`，对应 `#workbench-view`）：顶部切换 `网页版 Gemini` / `网页版 ChatGPT` 并复制地址，可展开 `首次绑定步骤与唤醒词` 与 `配对与已连会话`；左下 `开放工作目录` 卡片管理目录与 `当前权限设置`（`只读` / `仅改文件` / `工作区开发` / `全盘开发`）；右下 `实时动态与撤回` 卡片查看 `在途任务`、`修改撤回`、`回收箱`、`调用记录`。顶栏右侧提供 `一键只读`、`实战教程` 与 `设置` 按钮。\n"
                f"   - **系统设置页**（`{base}/#settings/gateways`，对应 `#settings-view`，支持 URL Hash 直达）：左侧含 5 个分类页签：`连接与网关`（`#settings/gateways`）、`环境与系统`（`#settings/runtime`）、`工具与扩展`（`#settings/tools`）、`技能管理`（`#settings/skills`）、`外观与图标`（`#settings/appearance`）；点击左上或右上 `← 返回主控台` 回到首页。\n"
                f"   - **交互式图文教程页**（`{base}/tutorials`）：分场景展示图文配置步骤与常见问题排查。"
            ),
        },
        "cloudflare": {
            "topic": "cloudflare",
            "title": "配置第 2 类 Cloudflare 免费终身固定网址与代理依赖说明",
            "aliases": ("cloudflare", "workers", "workers_dev", "cf"),
            "recommended_page": "cloudflare",
            "markdown": (
                "### 配置第 2 类：Cloudflare 专属固定网关（免费终身固定网址与依赖边界）\n\n"
                f"1. **打开连接与网关设置页**：在本地浏览器打开 `{base}/#settings/gateways`（或在主控首页点击右上 `设置` -> `连接与网关`，或点击连接卡右上 `配置连接通道 ▸`），找到第 2 类卡片 **「Cloudflare 专属固定网关」**，点击卡片右侧 `配置 ▾` 展开详情。\n"
                "2. **生成 Cloudflare API 令牌**：点击卡片内的 `第 1 步：打开 Cloudflare 预填权限页（支持 Google 快捷登录）`（跳转到 `https://dash.cloudflare.com/profile/api-tokens`），登录免费 Cloudflare 账号（无需绑信用卡），按页面预填的 Workers 脚本与账号读取权限生成并复制一次性 API Token。\n"
                "3. **一键部署固定网关（约 3 秒 · 零外部二进制依赖）**：回到本地控制台，将令牌粘贴到 `第 2 步：粘贴 API 令牌（部署后立即销毁）` 输入框（多账户时在下拉框选择目标账户），点击 `一键部署并开启（约 3 秒）`。\n"
                "   - **本机环境与配额依赖**：采用纯 Python 标准库 `443 WSS` 客户端，**零外部二进制依赖**（无需安装 `Node.js`、`wrangler` 或 `cloudflared`），自动生成形如 `https://cosmos-mcp-xxxx.<子域>.workers.dev/mcp` 的终身固定地址；受 Cloudflare Workers Free 每日 `100,000` 次请求上限（超限返 `1027`）及边缘默认反代读取超时 `125` 秒约束。\n"
                "   - **令牌即刻清零销毁**：部署完成后本机立即清零销毁所填 API Token，不留存明文令牌；后续只需拨动卡片右上角开关即可启停，且可与第 1 类或第 3 类通道同时在线。\n"
                "4. **中国大陆默认 `*.workers.dev` 常驻代理要求（重点）**：`*.workers.dev` 在国内运营商与公共 DNS 下存在全量 DNS 污染（无代理裸连 `100%` 超时）。若未绑定自定义域名，**本机运行期间必须保持系统 HTTP/HTTPS 代理（如 Clash / Mihomo / v2rayN，或环境变量 `HTTPS_PROXY` / `WSS_PROXY`）常开且分流规则覆盖 `*.workers.dev`**，以维持本机后台到边缘的 `443 WSS` 隧道；首次在浏览器打开 `/consent` 授权页时同样需走代理访问 `*.workers.dev`（若分流规则漏掉 `*.workers.dev` 可临时切全局完成首次授权，但切回规则模式后日常后台运行仍须保持代理规则覆盖 `*.workers.dev`）；若设置了 `NO_PROXY`，必须保留 `127.0.0.1,localhost,::1`。\n"
                "5. **国内免代理方案（绑定 Active Zone 自定义域名）**：在 `选填：自定义域名（Active Zone，国内免切代理）` 填入同一 Cloudflare 账号下已激活托管的域名（如 `mcp.yourdomain.dpdns.org`）保存部署，即可走未受 `workers.dev` 污染的边缘节点实现免代理直连（自定义域名请在 Cloudflare 后台关闭 `Bot Fight Mode` 并对 `/mcp*` 与 OAuth 路径跳过托管质询；或直接改用第 1 类默认 `*.srv.us` / 第 3 类自有云服务器）。"
            ),
        },
        "gateways": {
            "topic": "gateways",
            "title": "3 类连接通道依赖对比、独立开关并存与自有云服务器 24h 主站",
            "aliases": ("gateways", "vps", "vps_hub", "srv_us"),
            "recommended_page": "gateways",
            "markdown": (
                "### 3 类连接通道前置依赖对比与多网关并存说明\n\n"
                f"打开 `{base}/#settings/gateways` 可管理全部 3 类连接通道；每张卡片右上角均有独立开关，支持多条通道同时在线，主控首页顶部可一键切换当前复制的网关地址：\n\n"
                "1. **第 1 类 · 默认免配置「一键上手免登录直连」**：\n"
                "   - **默认 `*.srv.us` 通道**：仅依赖操作系统自带 OpenSSH（`ssh`）客户端与出站 TCP `22` 端口（零额外二进制、零注册），跨关机重启网址固定不变，国内家庭宽带通常可**免代理直连**；支持通过 `导出身份恢复卡 PNG` / `导入恢复卡 PNG` 备份迁移本机固定节点身份。\n"
                "   - **回退 `*.trycloudflare.com` 快速通道（`--mode cloudflare`）**：当校园网/企业网封禁出站 `22` 端口时在 `4` 秒内自动切换（也可点 `改用临时快速通道` 手动切换）。依赖官方 `cloudflared` 客户端二进制（系统 `PATH` 未预装时首次自动从 `https://github.com/cloudflare/cloudflared/releases/latest` 或 `COSMOS_CLOUDFLARED_MIRROR` HTTPS 镜像校验下载至状态目录 `bin/`；国内无代理拉取 GitHub 慢时可开代理、设 `COSMOS_CLOUDFLARED_MIRROR` 或预装 `cloudflared`）。注意该通道每次重启必换域名、无在线率 SLA、单控制流（`ha-connections:1`）重连有 `4–21` 秒空窗（返 HTTP `530`/`1033`）、限 `200` 并发在途请求与 `125` 秒边缘读超时，跨境高丢包环境建议开启系统 HTTP 代理。\n"
                "2. **第 2 类 · 无服务器固定网址「Cloudflare 专属固定网关」（`workers_dev`）**：\n"
                "   - 纯 Python 标准库 `443 WSS` 客户端，**零外部二进制依赖**（无需 `Node.js`、`wrangler` 或 `cloudflared`）；依赖免费 Cloudflare 账号与一次性 API Token（部署后即刻清零销毁），受 Workers Free 每日 `100,000` 次请求上限（超限返 `1027`）与边缘 `125` 秒读超时约束。\n"
                "   - **国内代理边界**：默认 `*.workers.dev` 在中国大陆遭全量 DNS 污染，未绑自定义域名时运行期间须保持系统 HTTP/HTTPS 代理常开且规则覆盖 `*.workers.dev`；绑定同账号 Active Zone 自定义域名后可国内免代理直连。\n"
                "3. **第 3 类 · 自有资产合一「自有云服务器 24h 主站 或 自有固定域名」**：\n"
                "   - **子页签 A `自有服务器建 24h 主站`（`vps_hub` / `vps`）**：依赖一台开放 `80`/`443` 端口的 Linux 服务器与本机 `ssh` 客户端，**零 Cloudflare 依赖、零单日请求上限、零 `125s` 边缘超时限制**，国内（配已备案域名）或港新服务器全程免代理直连；填写 `服务器公网 IP（必填）` 与 SSH 密码或密钥点击 `一键部署 24h 主站并开启`，工具调用支持 `target=\"auto\"` 跨机路由，本地电脑关机时云服务器主站仍保持 24 小时在线。\n"
                "   - **子页签 B `自有固定域名 / 通用 HTTPS 反代`**：支持通用反向代理（Caddy / Nginx / FRP）或 `Cloudflare Named Tunnel`（`--mode cloudflare_token`）。其中 `cloudflare_token` 依赖官方 `cloudflared` 二进制（同第 1 类支持首次自动下载或 `COSMOS_CLOUDFLARED_MIRROR`）、Cloudflare Zero Trust 账号、Active Zone 域名及后台指向 `http://127.0.0.1:8096` 的 Public Hostname 转发，且须在 Cloudflare 后台关闭 `Bot Fight Mode` 并对 `/mcp*` 与 OAuth 路径跳过托管质询。"
            ),
        },
        "permissions": {
            "topic": "permissions",
            "title": "开放工作目录、读写分层与 4 档权限实时切换",
            "aliases": ("permissions", "workspace", "tiers", "safety"),
            "recommended_page": "permissions",
            "markdown": (
                "### 工作目录管理、只读参考分层与 4 档安全权限\n\n"
                f"打开本地控制台首页 `{base}/`，在左下 **「开放工作目录」** 与右下 **「实时动态与撤回」** 卡片直接配置，无需重启服务：\n\n"
                "1. **添加主读写目录与只读参考目录**：\n"
                "   - 在输入框粘贴文件夹路径点 `添加`，或点击 `选文件夹` 调用系统目录选择框；也可点 `浏览目录树`（支持 `添加当前目录`、`设为主目录`、`新建` 子文件夹）或展开 `常用目录快选 ▸` 一键添加。\n"
                "   - **父只读 + 子读写分层**：添加前若打开 `以只读参考目录添加` 开关（或在已添加目录行切换读写/只读状态），该目录仅允许读取与检索；系统按最长路径前缀匹配权限，因此可将大仓库父目录设为只读参考，同时将其下某个子目录单独设为主读写目录。\n"
                "2. **主控首页左侧 `当前权限设置`（4 档单选，点击即生效）**：\n"
                "   - **`只读`（`L1`）**：仅允许读取文件、列目录与代码搜索，禁止修改任何文件或运行命令（同时保护 `.env` 等敏感凭据文件，仅放行 `.env.example` / `.env.template`）；顶栏右侧也提供 `一键只读` 应急按钮。\n"
                "   - **`仅改文件`（`L2`）**：允许在开放工作目录内读取和修改文件，禁止执行终端命令与脚本。\n"
                "   - **`工作区开发`（`L3`，默认推荐）**：允许在开放工作目录内读写代码与无窗口运行命令/Python 脚本，越界路径与系统凭据目录自动拦截。\n"
                "   - **`全盘开发`（`L4`）**：允许跨目录读写文件与运行命令（本机服务自身密钥目录 `secrets/state/config` 仍保持隔离保护，文件清理依然进入安全回收箱）。\n"
                "3. **写前快照撤回与安全回收箱兜底**：\n"
                "   - AI 每次修改文件前均自动保存历史快照；在首页右下卡片切到 `修改撤回` 页签，可点击 `查看对比 Diff` 审阅变更并点击 `撤回此修改` 一键还原。\n"
                "   - AI 禁止执行永久物理删除命令，被清理的文件统一移入 `回收箱` 页签，可随时一键原位恢复。"
            ),
        },
        "gemini_chatgpt": {
            "topic": "gemini_chatgpt",
            "title": "绑定网页版 Gemini（含手机端）与网页版 ChatGPT 操作指南",
            "aliases": ("gemini_chatgpt", "gemini", "chatgpt", "host"),
            "recommended_page": "studio",
            "markdown": (
                "### 网页版 Gemini 与网页版 ChatGPT 绑定及日常使用指南\n\n"
                f"在本地控制台首页 `{base}/` 顶部卡片可切换目标宿主并一键复制对应 HTTPS 地址：\n\n"
                "1. **网页版 Google Gemini（含同账号手机端 Gemini App）**：\n"
                "   - 在主控首页选中 `网页版 Gemini`，点击 `复制连接地址`（形如 `https://<域名>/mcp`）。**注意：不要把这个 `/mcp` 地址直接粘贴到浏览器地址栏里打开**，而是点 `打开 Gemini 连接器` 直接访问 **`https://gemini.google.com/customize/connectors`**（或从 Gemini 首页左下角菜单依次点击 `Personal Intelligence -> Connected Apps`）。\n"
                "   - 在 `Connectors` 页面点击右上角 **`+ Custom`**，在 `Connect to an MCP server` 窗口的 **`MCP Server URL`** 配置栏粘贴刚才复制的 `https://<域名>/mcp`（`Additional settings` 保持默认折叠，无需填写 Client ID / Secret），点击 **`Next`** 进入授权确认页。\n"
                "   - 同机浏览器打开授权确认页时会自动完成本机回环核验，核对 4 位防钓鱼码一致后点击 **「本机一键允许连接」**（若在手机或异地浏览器绑定，展开主控首页 `配对与已连会话` 查看并输入 **6 位动态配对码**）。\n"
                "   - **关键设置**：绑定成功后，回到 `https://gemini.google.com/customize/connectors` 点开刚添加的连接器，将 **`App actions`** 设为 **`Always allow`**（切勿在聊天框单张工具确认卡上点单次允许，以免覆盖整组免审批设置）。\n"
                "   - **推荐存入 Skills**：在主控首页展开 `首次绑定步骤与唤醒词` 点击 `复制 AI 守则`（或连接成功后复制顶部横幅的 `复制 AI 操作守则（推荐存入 Skills）`），粘贴保存到 Gemini 的 `Skills` 中。\n"
                "   - **唤醒与手机同步**：新开对话首句输入 `@Cosmos`（例如：`@Cosmos 查看当前电脑状态与工作区文件`）。同一 Google 账号登录手机端 Gemini App 后无需重复配置即可直接调用。\n"
            "2. **网页版 ChatGPT（本机插件页直绑最快 · 装好后日常用 `Chat` 模式省额度 · 读写与只读双地址隔离）**：\n"
            "   - **按账号类型选择端点**（按钮在公网网关就绪后自动开放）：\n"
            "     - **Team / Business / Enterprise / Edu 工作区账号**：绑定全功能主地址 `https://<域名>/mcp`（开放全部 16 项代码读写、Office 修订与无窗口命令执行）。\n"
            "     - **个人 Plus / Pro 订阅账号**：当平台策略对自建远程 MCP 仅放行 `read/fetch` 权限时，绑定只读地址 `https://<域名>/mcp/readonly`（开放 12 项只读分析工具，若账号已获写工具放行也可先试 `/mcp`）。\n"
            "   - **阶段一 · 首次添加与排障边界**：首选点击主控首页 **「复制地址并打开 ChatGPT 插件页」**，在已登录本机浏览器打开 `https://chatgpt.com/plugins` 点 `＋ -> 添加自定义 MCP 服务器`（名称填 `WebAI2PC`，认证选 `OAuth`，无需搭 `ChatGPT Sites` 中转，也勿用 ZIP 上传外部 MCP 私有插件以免触发工作区 `403`；若无入口或报 `403` 请管理员开启 `Create plugins with MCPs` 权限），跳转 `/consent` 命中 `127.0.0.1` 回环直接点 `本机一键允许连接`，最后点击 `Install` 完成安装。也可点旁侧 **「复制给 ChatGPT 接入 / 排障」** 发送 4 步指令让 ChatGPT 用会话原生插件连接工具探测复用、协商 OAuth 并调用 `pc_get_status` 核验（不含配对码、口令、令牌与本机路径，默认不拉起未登录云浏览器或建中转服务；若在 `Work` 云端浏览器 `Take over` 打开 `/consent` 则需输入主控首页 `6` 位动态配对码）。\n"
            "   - **阶段二 · 日常使用分工与守则存放**：插件安装后同账号下 `Chat` 模式与 `Work` 模式共享 `@WebAI2PC`，以 **`pc_get_status`（`get_status`）实际调用成功**作为接通标准。日常查改本地代码、修 Office、跑无窗口命令与 Python 测试优先切回 **`Chat` 模式**发 `@WebAI2PC`（响应快，走普通对话限额，零消耗 `Work / Codex` 智能体额度）；需要结合受控浏览器、跨邮件/Slack/网盘做长程多步交付或配置 `Scheduled Tasks` 定时任务时用 **`Work` 模式**发 `@WebAI2PC`（消耗 `Work / Codex` 智能体额度）。操作守则在工作区/桌面端/插件包可存入原生 `Skills`，网页版 `Chat` 与 `Work` 模式均可粘贴进 `Project（项目）Instructions` 或自定义指令复用。"
            ),
        },
        "packs_and_skills": {
            "topic": "packs_and_skills",
            "title": "开启受管浏览器/桌面扩展包、多设备前缀与技能管理",
            "aliases": ("packs_and_skills", "tools", "skills", "browser", "desktop"),
            "recommended_page": "tools",
            "markdown": (
                "### 扩展工具包、多机前缀、技能管理与身份恢复卡\n\n"
                f"1. **开启 `browser` 与 `desktop` 扩展包（工具数 `16 -> 18`）**：\n"
                f"   - 打开 `{base}/#settings/tools`（设置 -> `工具与扩展`）。\n"
                "   - 打开 **「受管浏览器包」**（`browser`）：AI 可启动独立隔离浏览器完成网页查阅与截图，不触碰你的个人浏览器窗口。\n"
                "   - 打开 **「桌面窗口操控包」**（`desktop`）：提供离屏窗口画面感知与受控界面辅助，检测到你正在操作键鼠时自动礼让（注：切入 `只读` 档位时扩展包会自动暂时关闭以保障只读边界）。\n"
                "   - 网页端连接器会在会话初始化时缓存工具列表；新开启扩展包后，在 Gemini 或 ChatGPT 新开一个对话（或在连接器设置点刷新）即可看到新增工具（由默认 16 项增至最多 18 项）。\n"
                "2. **修改多设备工具前缀（`tool_prefix`）**：\n"
                f"   - 单台电脑保持默认 `pc`（工具名形如 `pc_read_file`）即可；若需要将多台电脑同时接入同一个网页对话，可在 `{base}/#settings/tools` 的 **「多设备工具前缀」** 输入如 `desk` 或 `laptop` 并点击 `保存工具前缀` 加以区分。\n"
                "3. **技能管理与三级 AST 安全体检**：\n"
                f"   - 打开 `{base}/#settings/skills`（设置 -> `技能管理`），可切换 `本机技能与详情`、`在线市场与体检安装`、`新建技能`、`安全回收箱` 四个子页签。\n"
                "   - 安装外部 GitHub / ClawHub / 本地目录技能时，先点 `执行 AST 体检` 审阅静态语法树安全报告，通过后再点 `确认安装此技能`。\n"
                "4. **换机或重装备份（身份恢复卡 PNG）**：\n"
                f"   - 在 `{base}/#settings/gateways` 第 1 类卡片内点击 `导出身份恢复卡 PNG`，设置加密口令即可下载包含固定节点密钥与网关配置的加密 PNG 图片；换电脑或重装系统后点击 `导入恢复卡 PNG` 输入口令即可恢复原有固定网址。"
            ),
        },
        "troubleshooting": {
            "topic": "troubleshooting",
            "title": "常见连接、代理依赖与运行问题排查速查",
            "aliases": ("troubleshooting",),
            "recommended_page": "runtime",
            "markdown": (
                "### 常见问题排查速查\n\n"
                "1. **双击启动脚本提示缺少文件或无法自举**：\n"
                "   - 下载 `.zip` 压缩包后，请先 **右键「全部解压缩」到普通文件夹**（如 `D:\\WebAI2PC`），再进入解压后的文件夹双击 `一键启动_Cosmos_MCP.bat`，不要在压缩软件预览窗口内直接双击运行。\n"
                "2. **中国大陆使用 `*.workers.dev` 授权页打不开、后台隧道超时重连或 `NO_PROXY` 冲突**：\n"
                "   - `*.workers.dev` 在国内存在全量 DNS 污染（裸连 `100%` 超时）。未绑自定义域名时，**本机运行期间须保持系统 HTTP/HTTPS 代理（Clash / Mihomo / v2rayN 或 `HTTPS_PROXY` / `WSS_PROXY`）常开且分流规则覆盖 `*.workers.dev`**（首次 `/consent` 授权若规则漏掉 `*.workers.dev` 可临时切全局完成授权，但切回规则模式后日常仍须确保 `*.workers.dev` 走代理；若配置了 `NO_PROXY` 必须保留 `127.0.0.1,localhost,::1` 且勿写入 `*` 或 `*.workers.dev`）。国内免代理方案：在 `#settings/gateways` 第 2 类卡片绑定同账号下 Cloudflare Active Zone 自定义域名（并关闭该域名 `Bot Fight Mode`、跳过 `/mcp*` 与 OAuth 托管质询），或改用第 1 类 `*.srv.us` / 第 3 类自有云服务器。\n"
                "3. **首次启用 `*.trycloudflare.com` 或 `cloudflare_token` 下载 `cloudflared` 缓慢**：\n"
                "   - 两条隧道均需官方 `cloudflared` 二进制（首次自动从 GitHub Releases 下载至状态目录 `bin/`）；国内无代理环境可开启系统代理、配置环境变量 `COSMOS_CLOUDFLARED_MIRROR` 指向 HTTPS 镜像前缀，或预先将 `cloudflared` 装入系统 `PATH`（通道 2 `workers_dev` 与通道 1 `*.srv.us` 均无需 `cloudflared`）。\n"
                "4. **授权页上的「4 位核对码」与「6 位动态配对码」有什么区别**：\n"
                "   - **4 位核对码**：防钓鱼核对标识，同机浏览器自动回环验证时用于肉眼确认当前授权页确实连向你自己的电脑，无需手输密码。\n"
                "   - **6 位动态配对码**：当你在网页版 ChatGPT `Work` 模式的云端受控浏览器内点 `Take over` 打开授权页、在手机浏览器或异地电脑绑定，或使用开启严格隐私拦截的浏览器（如 Brave / Safari）无法走本机 `127.0.0.1` 回环时，展开主控首页 `配对与已连会话` 复制当前的 **6 位码** 填入授权页即可通过验证（若均受阻也可填下方的 20 位固定备用口令）。\n"
                "5. **配置开机自启、防休眠与默认 Python 环境**：\n"
                f"   - 打开 `{base}/#settings/runtime`（设置 -> `环境与系统`），可开启 **「开机自动启动」**、**「插电防自动休眠」**（注意笔记本物理合盖仍会触发硬件休眠断网，合盖使用需在系统电源设置将合盖动作改为「不采取任何操作」）与 **「显示系统托盘状态图标」**，也可在此指定项目默认 Python / Conda 解释器路径。"
            ),
        },
    }


def _compose_all_tutorials_markdown(topics_map: Dict[str, Dict[str, Any]], *, port_note: str) -> str:
    sections = [
        f"# WebAI2PC (Cosmos MCP v{PRODUCT_VERSION}) AI 可读配置与使用教程\n\n"
        f"> 本手册面向 AI 助手（Gemini / ChatGPT）与用户，涵盖本地控制台页面导航、Cloudflare 免费终身固定网址配置、3 类网关对比、工作目录与 4 档权限切换、双宿主绑定步骤及常见排障。{port_note}",
        topics_map["overview"]["markdown"],
        topics_map["cloudflare"]["markdown"],
        topics_map["gateways"]["markdown"],
        topics_map["permissions"]["markdown"],
        topics_map["gemini_chatgpt"]["markdown"],
        topics_map["packs_and_skills"]["markdown"],
        topics_map["troubleshooting"]["markdown"],
        (
            "### 附：给任何未连接 MCP 的 AI 助手的快捷引导提示词\n\n"
            "若用户尚未完成首次连接，可将本手册链接（`<网关或仓库地址>/tutorials.md`）或全文发给任意 Gemini / ChatGPT，并附上需求（例如：「请阅读这份 WebAI2PC 教程，一步步教我配置 Cloudflare 固定网址并连上 Gemini」）；若 AI 已连接本机 MCP，可直接调用 `pc_get_status(guide=\"cloudflare\", open_page=\"cloudflare\")` 一边为用户打开本地对应设置页，一边按步骤指导操作。"
        ),
    ]
    return "\n\n".join(sections) + "\n"


def _build_catalog_for_port(port_str: str, *, is_public_static: bool = False) -> Dict[str, Dict[str, Any]]:
    base_topics = _build_topic_templates(port_str)
    note = (
        "（默认本地控制台地址为 `http://127.0.0.1:8096/`；若本地自定义过监听端口，请将 `8096` 替换为实际端口。）"
        if is_public_static
        else f"（当前实例本地控制台地址：`http://127.0.0.1:{port_str}/`）"
    )
    base_topics["all"] = {
        "topic": "all",
        "title": f"WebAI2PC (Cosmos MCP v{PRODUCT_VERSION}) 完整配置与排障手册",
        "aliases": ("all", "full", "manual", "tutorials", "llms"),
        "recommended_page": "tutorials",
        "markdown": _compose_all_tutorials_markdown(base_topics, port_note=note),
    }
    return base_topics


# Canonical static catalog (default port 8096, zero runtime/host/user/path state)
TUTORIAL_TOPICS: Dict[str, Dict[str, Any]] = _build_catalog_for_port("8096", is_public_static=True)
_PUBLIC_STATIC_MARKDOWN: str = TUTORIAL_TOPICS["all"]["markdown"]


def render_public_tutorials_markdown() -> str:
    """Return 100% static, zero-instance-state Markdown manual for `/tutorials.md` and `/llms.txt`."""
    return _PUBLIC_STATIC_MARKDOWN


def normalize_guide_topic(guide: str) -> str:
    """Resolve a guide topic or alias to its canonical key in `CANONICAL_GUIDE_TOPICS` (or `""` if empty/unknown)."""
    clean = str(guide or "").strip().lower().replace("-", "_")
    if not clean:
        return ""
    return _GUIDE_ALIASES.get(clean, "")


def get_tutorial_guide(guide: str, port: int = 8096) -> Dict[str, Any]:
    """Return `{topic, title, recommended_page, markdown, available_guides}` formatted with local `port`."""
    eff_port = _sanitize_port(port)
    canonical = normalize_guide_topic(guide)
    catalog = _build_catalog_for_port(str(eff_port), is_public_static=False)
    if not canonical:
        entry = catalog["overview"]
        return {
            "topic": "overview",
            "requested_guide": str(guide or "").strip(),
            "unknown_guide_fallback": True,
            "title": entry["title"],
            "recommended_page": entry["recommended_page"],
            "markdown": entry["markdown"],
            "available_guides": list(CANONICAL_GUIDE_TOPICS),
        }
    entry = catalog[canonical]
    return {
        "topic": canonical,
        "title": entry["title"],
        "recommended_page": entry["recommended_page"],
        "markdown": entry["markdown"],
        "available_guides": list(CANONICAL_GUIDE_TOPICS),
    }


def resolve_local_studio_page(page_key: str, port: int = 8096) -> Dict[str, str]:
    """Strictly resolve `page_key` against the hardcoded loopback Studio allowlist.

    Never accepts arbitrary URLs, external hosts, or path traversal strings.
    """
    eff_port = _sanitize_port(port)
    raw = str(page_key or "").strip()
    clean = raw.lower().lstrip("#/").replace("-", "_")
    if clean.startswith("settings/"):
        clean = clean.split("/", 1)[1].strip()
    hit = _STUDIO_PAGE_MAP.get(clean)
    if hit is None:
        return {
            "page_key": raw,
            "canonical_page": "",
            "url": "",
            "guide_topic": "",
            "error": f"Unsupported local Studio page key {raw!r}. Allowed keys: {', '.join(ALLOWED_STUDIO_PAGE_KEYS)}",
        }
    canonical_page, suffix, default_guide = hit
    target_url = f"http://127.0.0.1:{eff_port}{suffix}"
    return {
        "page_key": clean,
        "canonical_page": canonical_page,
        "url": target_url,
        "guide_topic": default_guide,
    }


def _is_headless_or_browser_disabled() -> bool:
    dis = os.environ.get("COSMOS_DISABLE_BROWSER_OPEN", "").strip().lower()
    if dis in ("1", "true", "yes", "on"):
        return True
    if sys.platform.startswith("linux"):
        if not os.environ.get("DISPLAY", "").strip() and not os.environ.get("WAYLAND_DISPLAY", "").strip():
            return True
    return False


def _launch_loopback_url_windowless(target_url: str) -> bool:
    """Open validated `http://127.0.0.1:<port>/...` URL preserving `#hash` with zero console window."""
    parsed = urlsplit(target_url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port:
        return False

    opened = False
    try:
        opened = bool(webbrowser.open(target_url, new=2))
    except Exception:
        opened = False

    if not opened and sys.platform == "win32":
        try:
            subprocess.Popen(
                ["cmd.exe", "/c", "start", "", target_url],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=CREATE_NO_WINDOW,
            )
            opened = True
        except Exception:
            opened = False
    return opened


def open_local_studio_page_safely(
    page_key: str,
    port: int = 8096,
    *,
    opener: Callable[[str], bool] | None = None,
) -> Dict[str, Any]:
    """Validate `page_key` against strict loopback allowlist and open in the local browser if supported."""
    eff_port = _sanitize_port(port)
    resolved = resolve_local_studio_page(page_key, port=eff_port)
    target_url = resolved.get("url", "")
    if not target_url:
        return {
            "ok": False,
            "opened": False,
            "reason": "invalid_page_key",
            "error_code": "ERR_INVALID_STUDIO_PAGE",
            "requested_page": str(page_key or "").strip(),
            "url": "",
            "allowed_pages": list(ALLOWED_STUDIO_PAGE_KEYS),
        }

    parsed = urlsplit(target_url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port != eff_port:
        return {
            "ok": False,
            "opened": False,
            "reason": "non_loopback_rejected",
            "url": "",
        }

    if _is_headless_or_browser_disabled():
        return {
            "ok": True,
            "opened": False,
            "reason": "headless_or_disabled",
            "page": resolved["canonical_page"],
            "guide_topic": resolved["guide_topic"],
            "url": target_url,
        }

    eff_opener = opener if opener is not None else _launch_loopback_url_windowless
    was_opened = bool(eff_opener(target_url))
    return {
        "ok": True,
        "opened": was_opened,
        "reason": "" if was_opened else "browser_open_failed",
        "page": resolved["canonical_page"],
        "guide_topic": resolved["guide_topic"],
        "url": target_url,
    }
