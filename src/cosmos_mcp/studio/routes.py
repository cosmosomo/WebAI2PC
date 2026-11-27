"""Cosmos Studio 1.0 local visual control center (`routes.py`), session cookie auth,
directory tree JSON browser, recovery & live task APIs, `/consent` rendering, and `/mcp` browser guide.

Enforces:
- Clean separation of HTML/CSS/JS into `studio/static/{index.html,studio.css,studio.js}`.
- Zero internal benchmark/config jargon: unified 12 core tools display, plain Chinese safety modes.
- Enter management password once per session (`HttpOnly` signed session cookie `cosmos_studio_sid`),
  working across both local loopback (`127.0.0.1`) and password-unlocked mobile/remote sessions.
- Targeted per-pack shutdown (`_shutdown_disabled_packs`): disabling `browser` while keeping `desktop` (`cua`)
  immediately shuts down `BrowserPackPlugin` and closes isolated browser sessions with zero process leak.
- Real `.agents/skills/` filesystem scan (never fabricates fake counts).
"""
from __future__ import annotations

import asyncio
import base64
from datetime import datetime
import hashlib
import hmac
import html
import inspect
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import string
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlencode, urlsplit

try:
    from starlette.requests import Request
    from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
except ImportError:
    Request = Any  # type: ignore[assignment,misc]
    HTMLResponse = Any  # type: ignore[assignment,misc]
    JSONResponse = Any  # type: ignore[assignment,misc]
    RedirectResponse = Any  # type: ignore[assignment,misc]
    Response = Any  # type: ignore[assignment,misc]

from cosmos_mcp.core.config import (
    DEFAULT_PUBLIC_GATEWAY_BASE,
    PRODUCT_VERSION,
    UNAMBIGUOUS_PW_ALPHABET,
    LiveRuntimePolicy,
    apply_endpoint_secret_to_url,
    clear_endpoint_secret,
    conn_info_filename_for_prefix,
    discover_common_code_directories,
    emit_kill_signal,
    ensure_initialized,
    expand_env_and_tilde,
    generate_endpoint_secret,
    is_plaintext_connection_password_wiped,
    load_encrypted_connection_password,
    load_endpoint_secret,
    normalize_prefix,
    parse_bool_flag,
    parse_pack_spec,
    parse_strict_tier,
    parse_strict_toolset_profile,
    resolve_service_cfg_path,
    save_endpoint_secret,
    strip_endpoint_secret_from_url,
    wipe_plaintext_connection_password,
)
import difflib
import threading

from cosmos_mcp.capabilities.skills import (
    SkillsCapabilityProvider,
    SkillsMcpService,
    WRITABLE_HOST_IDS,
    audit_skill_directory,
)
from cosmos_mcp.core.fs_tx import (
    _candidate_undo_bases,
    atomic_write_json,
    list_undo_snapshots,
    restore_from_trash,
    restore_trash_item,
    undo_last_edit,
)
import cosmos_mcp.core.config as _core_cfg
from cosmos_mcp.launcher import cf_workers_gateway as cfgw
from cosmos_mcp.launcher.autostart import disable_autostart, enable_autostart, get_autostart_status
from cosmos_mcp.launcher.bootstrap import find_suitable_python
from cosmos_mcp.launcher.daemon import daemon_stop_flag_path
from cosmos_mcp.launcher.doctor import run_connectivity_check
from cosmos_mcp.launcher.folder_picker import pick_directory_native
from cosmos_mcp.launcher.tunnels import (
    QUICK_TUNNEL_REBOOT_NOTICE_ZH,
    hot_refresh_public_url,
    load_or_create_vps_node_secret,
    load_tunnel_token,
    normalize_tunnel_token,
    provision_vps_hub_oneclick,
    save_tunnel_token,
)
from cosmos_mcp.packs import close_all_browser_sessions
from cosmos_mcp.protocol.dispatcher import KernelDispatcher
from cosmos_mcp.protocol.skill_renderer import render_skill_markdown

CLOUDFLARE_TOKEN_TEMPLATE_URL: str = str(
    getattr(
        cfgw,
        "CLOUDFLARE_TOKEN_TEMPLATE_URL",
        (
            "https://dash.cloudflare.com/profile/api-tokens"
            "?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D"
            "%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%5D"
            "&accountId=*&zoneId=all&name=Cosmos-MCP-Gateway"
        ),
    )
)
ensure_master_seed_identity = cfgw.ensure_master_seed_identity
export_identity_recovery_png = cfgw.export_identity_recovery_png
import_identity_recovery_png = cfgw.import_identity_recovery_png
deploy_cloudflare_workers_gateway = cfgw.deploy_cloudflare_workers_gateway
probe_public_gateway_online = getattr(cfgw, "probe_public_gateway_online", None)

try:
    from cosmos_mcp.protocol.transport import is_strict_direct_loopback
except ImportError:
    def is_strict_direct_loopback(conn: Any, port: int) -> bool:
        client = getattr(conn, "client", None)
        client_host = getattr(client, "host", "") if client else ""
        if client_host not in ("127.0.0.1", "::1"):
            return False
        headers = getattr(conn, "headers", {}) or {}
        host_hdr = str(headers.get("host") or "").strip().lower()
        if host_hdr not in {
            f"127.0.0.1:{port}",
            f"localhost:{port}",
            f"[::1]:{port}",
            "127.0.0.1",
            "localhost",
            "[::1]",
        }:
            return False
        for k in headers.keys():
            kl = str(k).lower()
            if kl in {
                "cf-connecting-ip",
                "cf-ray",
                "x-forwarded-for",
                "x-forwarded-host",
                "x-real-ip",
                "forwarded",
                "true-client-ip",
                "via",
                "x-original-host",
            } or kl.startswith(("x-forwarded-", "cf-", "ngrok-")):
                return False
        return True

try:
    from cosmos_mcp.protocol.oauth import (
        OAuthProvider,
        OAuthSQLiteStore,
        derive_consent_pair_code,
        get_current_request_gateway,
        load_consent_template_html,
        render_consent_template_html,
        resolve_request_client_ip,
    )
    from cosmos_mcp.protocol.oauth_web import (
        handle_consent_complete_request,
        handle_oauth_local_bridge_request,
        handle_web_consent_request,
        is_current_request_pure_local,
        is_verified_local_fast_approve,
        mint_local_consent_fast_token,
        render_web_consent_html,
    )
except ImportError:
    OAuthProvider = object  # type: ignore[assignment,misc]
    OAuthSQLiteStore = Any  # type: ignore[assignment,misc]
    get_current_request_gateway = lambda: None  # type: ignore[assignment]
    handle_consent_complete_request = None  # type: ignore[assignment]
    handle_oauth_local_bridge_request = None  # type: ignore[assignment]
    handle_web_consent_request = None  # type: ignore[assignment]
    is_current_request_pure_local = lambda: False  # type: ignore[assignment]
    is_verified_local_fast_approve = lambda: False  # type: ignore[assignment]
    mint_local_consent_fast_token = None  # type: ignore[assignment]
    render_web_consent_html = None  # type: ignore[assignment]

    def derive_consent_pair_code(ticket: str) -> str:
        clean = (ticket or "").strip()
        if not clean:
            return "----"
        digest = hashlib.sha256(f"localpc-consent-pair:{clean}".encode("utf-8")).digest()
        return "".join(UNAMBIGUOUS_PW_ALPHABET[b & 31] for b in digest[:4])

    def load_consent_template_html() -> str:
        tpl_p = Path(__file__).resolve().parents[1] / "protocol" / "templates" / "consent.html"
        return tpl_p.read_text(encoding="utf-8") if tpl_p.is_file() else ""

    def render_consent_template_html(**kwargs: Any) -> str:
        return str(kwargs.get("client_name") or "")

    def resolve_request_client_ip(request: Any, tunnel_mode: str = "") -> Tuple[str, bool]:
        _ = tunnel_mode
        client = getattr(request, "client", None)
        host = getattr(client, "host", "global") if client else "global"
        return str(host or "global"), True


STUDIO_VERSION = "1.2"
STUDIO_SESSION_COOKIE = "cosmos_studio_sid"
STUDIO_SESSION_TTL_SEC = 12 * 3600
ASSETS_PACKAGE = "cosmos_mcp.studio"
_STUDIO_AUTH_SCRYPT_SEMAPHORE = threading.BoundedSemaphore(4)

# Plain Chinese metadata for the 12 default core tools (zero exposed snake_case keys required in UI)
CORE_12_TOOLS_CATALOG: Tuple[Dict[str, str], ...] = (
    {
        "base": "get_status",
        "title_zh": "环境与任务状态查询",
        "category_zh": "只读查询",
        "band": "readonly",
        "desc_zh": "读取本机系统概况、当前开放工作目录、磁盘空间及后台任务的实时进度。",
    },
    {
        "base": "find_files",
        "title_zh": "文件与目录查找",
        "category_zh": "只读查询",
        "band": "readonly",
        "desc_zh": "按文件名关键词、后缀类型或目录层级快速定位工作区内的文件与子文件夹。",
    },
    {
        "base": "search_code",
        "title_zh": "跨文件全文与正则搜索",
        "category_zh": "只读查询",
        "band": "readonly",
        "desc_zh": "在项目源码中高速搜索关键字或正则表达式，并附带所在函数与类上下文。",
    },
    {
        "base": "code_intel",
        "title_zh": "代码结构与引用分析",
        "category_zh": "只读查询",
        "band": "readonly",
        "desc_zh": "提取文件大纲、查找函数与类定义位置、跨文件引用关系及基础语法检查。",
    },
    {
        "base": "read_file",
        "title_zh": "读取文件、图片与文档",
        "category_zh": "只读查询",
        "band": "readonly",
        "desc_zh": "按行分段读取代码文本、直接查看本地图片，并支持提取 .docx、.xlsx、.pptx、.pdf 等办公文档文字内容。",
    },
    {
        "base": "web_research",
        "title_zh": "网页与开源资料检索",
        "category_zh": "只读查询",
        "band": "readonly",
        "desc_zh": "检索公开技术网页与开源代码库文档，自动过滤内网私有地址保障安全。",
    },
    {
        "base": "edit_file",
        "title_zh": "精准局部修改文件",
        "category_zh": "文件修改",
        "band": "write",
        "desc_zh": "对已有文件执行单处或多处上下文匹配修改，支持直接修订 .docx 与 .xlsx 文档，修改前自动保存可撤回快照。",
    },
    {
        "base": "write_file",
        "title_zh": "新建与写入文件",
        "category_zh": "文件修改",
        "band": "write",
        "desc_zh": "创建新文件或追加写入文本内容，内置防误清空保护并自动记录修改历史。",
    },
    {
        "base": "manage_files",
        "title_zh": "文件管理与安全回收箱",
        "category_zh": "文件修改",
        "band": "write",
        "desc_zh": "新建目录、移动重命名、撤回重做最近改动，或将废弃文件移入可恢复回收箱。",
    },
    {
        "base": "run_command",
        "title_zh": "运行终端命令",
        "category_zh": "命令运行",
        "band": "exec",
        "desc_zh": "在后台静默无弹窗运行编译、测试或构建命令，耗时任务自动转为后台跟进。",
    },
    {
        "base": "run_python",
        "title_zh": "运行 Python 脚本代码",
        "category_zh": "命令运行",
        "band": "exec",
        "desc_zh": "通过标准输入直接运行多行 Python 分析或验证代码，不在项目目录遗留临时脚本。",
    },
    {
        "base": "bg_command",
        "title_zh": "后台长任务管理",
        "category_zh": "命令运行",
        "band": "exec",
        "desc_zh": "启动、查询进度、读取实时尾部日志或随时终止长时间运行的训练与构建任务。",
    },
    {
        "base": "batch_probe",
        "title_zh": "批量只读代码探针",
        "category_zh": "只读查询",
        "band": "readonly",
        "desc_zh": "在隔离只读子进程中一次组合执行多步搜索、大纲提取与结构盘点。",
    },
    {
        "base": "workspace_memory",
        "title_zh": "跨会话项目共享记录",
        "category_zh": "文件修改",
        "band": "write",
        "desc_zh": "读取、检索或写入项目工作区持久共享便签，方便多智能体衔接进度。",
    },
    {
        "base": "skill_hub",
        "title_zh": "技能检索、加载与审计",
        "category_zh": "只读查询",
        "band": "readonly",
        "desc_zh": "搜索本地与公开市场技能包，渐进式加载说明或执行三层静态安全审查。",
    },
    {
        "base": "skill_manage",
        "title_zh": "技能安装、创建与管理",
        "category_zh": "文件修改",
        "band": "write",
        "desc_zh": "新建、安装、启停、同步技能包，并通过可恢复回收箱安全移除与还原。",
    },
)

SAFETY_MODE_LABELS_ZH: Dict[str, str] = {
    "tier1_readonly": "只读浏览模式",
    "tier2_workspace_edit": "仅改文件模式（禁跑命令）",
    "tier3_workspace_dev": "工作区内顺畅开发",
    "tier4_full_power": "全盘顺畅开发（不限目录）",
}

TUNNEL_MODE_LABELS_ZH: Dict[str, str] = {
    "public_gateway": "一键上手默认通道",
    "cloudflare": "免登录快速体验通道",
    "workers_dev": "Cloudflare 固定网关",
    "cloudflare_token": "Cloudflare 固定隧道令牌",
    "vps_hub": "自有服务器 24h 主站",
    "vps": "自有服务器反向隧道",
    "custom": "自有固定域名接入",
    "reverse_proxy": "自有固定域名接入",
    "local": "本机回环调试（未开公网通道）",
}

ALL_SUPPORTED_TUNNEL_MODES: Tuple[str, ...] = (
    "public_gateway",
    "cloudflare",
    "workers_dev",
    "vps_hub",
    "vps",
    "cloudflare_token",
    "custom",
    "local",
)

STUDIO_GATEWAY_IDS: Tuple[str, ...] = ("instant", "workers_dev", "self_hosted")
GATEWAY_SLOT_LABELS_ZH: Dict[str, str] = {
    "instant": "方式 1 · 一键上手",
    "workers_dev": "方式 2 · Cloudflare 固定网关",
    "self_hosted": "方式 3 · 自有服务器/域名",
}

_PLACEHOLDER_DEAD_GATEWAY_HOSTS = frozenset(
    {
        "gw.cosmos-mcp.org",
        "gw.cosmos-mcp.workers.dev",
    }
)
_PUBLIC_GW_PROBE_CACHE: Dict[str, Tuple[float, bool]] = {}
_PUBLIC_GW_PROBE_LOCK = threading.Lock()


def _slot_and_submode_for_tunnel_mode(raw_mode: str) -> Tuple[str, str]:
    m = (raw_mode or "").strip().lower()
    if m in ("", "local", "disabled"):
        return ("", "local")
    if m in ("public_gateway", "srv_us"):
        return ("instant", "public_gateway")
    if m == "cloudflare":
        return ("instant", "cloudflare")
    if m in ("workers_dev", "cf_workers"):
        return ("workers_dev", "workers_dev")
    if m == "vps_hub":
        return ("self_hosted", "vps_hub")
    if m == "vps":
        return ("self_hosted", "vps")
    if m == "cloudflare_token":
        return ("self_hosted", "cloudflare_token")
    if m in ("custom", "reverse_proxy"):
        return ("self_hosted", "custom")
    return ("instant", "public_gateway")


def _clean_https_candidate(raw_u: Any) -> str:
    cand = str(raw_u or "").strip().rstrip("/")
    if not cand.startswith("https://"):
        return ""
    host = (urlsplit(cand).hostname or "").strip().lower()
    if not host or host in ("127.0.0.1", "localhost", "::1"):
        return ""
    return cand


def _normalize_studio_gateways_cfg(
    policy: LiveRuntimePolicy,
    extra_cfg: Dict[str, Any],
    raw_live_pub: str = "",
) -> Tuple[Dict[str, Dict[str, Any]], str, str]:
    """Normalize `gateways` 3-slot config with 100% lossless migration from legacy `service.json`."""
    prev_bases = [str(x).strip().rstrip("/") for x in (extra_cfg.get("previous_public_bases") or []) if str(x).strip()]
    pinned_bases = [str(x).strip().rstrip("/") for x in (extra_cfg.get("pinned_gateway_urls") or []) if str(x).strip()]
    all_hist = [*pinned_bases, *prev_bases]
    hist_srvus = next((u for u in reversed(all_hist) if u.lower().endswith(".srv.us") and u.startswith("https://")), "")

    saved_pub = _clean_https_candidate(extra_cfg.get("public_base") or extra_cfg.get("public_base_url") or raw_live_pub)
    wd_dom = str(
        getattr(policy, "workers_dev_custom_domain", "") or extra_cfg.get("workers_dev_custom_domain") or ""
    ).strip()
    wd_dom_url = _clean_https_candidate(f"https://{wd_dom}" if wd_dom and "://" not in wd_dom else wd_dom)
    wd_raw_url = _clean_https_candidate(extra_cfg.get("workers_dev_url"))
    wd_saved_url = wd_dom_url or wd_raw_url
    vps_saved_url = _clean_https_candidate(extra_cfg.get("vps_hub_url"))

    raw_gws = extra_cfg.get("gateways")
    if not isinstance(raw_gws, dict):
        pol_gws = getattr(policy, "gateways", None)
        if isinstance(pol_gws, dict) and pol_gws:
            raw_gws = pol_gws

    core_norm_fn = getattr(_core_cfg, "normalize_gateways_config", None)
    mirrored_mismatch = bool(
        extra_cfg.get("_gateways_mirrored_mode")
        and extra_cfg.get("tunnel_mode")
        and str(extra_cfg.get("tunnel_mode")).strip().lower()
        != str(extra_cfg.get("_gateways_mirrored_mode")).strip().lower()
    )
    if (not isinstance(raw_gws, dict) or mirrored_mismatch) and callable(core_norm_fn) and extra_cfg:
        try:
            norm_res = core_norm_fn(dict(extra_cfg))
            if isinstance(norm_res, tuple) and len(norm_res) >= 2 and isinstance(norm_res[0], dict):
                raw_gws = norm_res[0]
        except Exception:
            if not isinstance(raw_gws, dict):
                raw_gws = None

    slots: Dict[str, Dict[str, Any]] = {
        "instant": {
            "enabled": False,
            "submode": "public_gateway",
            "public_url": "",
            "updated_at": 0.0,
        },
        "workers_dev": {
            "enabled": False,
            "submode": "workers_dev",
            "public_url": wd_saved_url,
            "script_name": str(
                getattr(policy, "workers_dev_script_name", "") or extra_cfg.get("workers_dev_script_name") or ""
            ).strip(),
            "account_id": str(
                getattr(policy, "workers_dev_account_id", "") or extra_cfg.get("workers_dev_account_id") or ""
            ).strip(),
            "subdomain": str(
                getattr(policy, "workers_dev_subdomain", "") or extra_cfg.get("workers_dev_subdomain") or ""
            ).strip(),
            "custom_domain": wd_dom,
            "updated_at": 0.0,
        },
        "self_hosted": {
            "enabled": False,
            "submode": "vps_hub",
            "public_url": vps_saved_url,
            "custom_domain": "",
            "vps_ssh_target": str(extra_cfg.get("vps_ssh") or "").strip(),
            "vps_ssh_port": int(extra_cfg.get("vps_ssh_port") or 22),
            "vps_remote_port": int(extra_cfg.get("vps_remote_port") or 18096),
            "vps_identity_file": str(extra_cfg.get("vps_identity_file") or "").strip(),
            "updated_at": 0.0,
        },
    }

    if isinstance(raw_gws, dict):
        g_inst = raw_gws.get("instant") if isinstance(raw_gws.get("instant"), dict) else {}
        inst_sub = str(g_inst.get("submode") or "public_gateway").strip().lower()
        if inst_sub not in ("public_gateway", "cloudflare"):
            inst_sub = "public_gateway"
        inst_pub = _clean_https_candidate(g_inst.get("public_url"))
        if not inst_pub and bool(g_inst.get("enabled")) and saved_pub and (
            saved_pub.lower().endswith(".srv.us") or ".trycloudflare.com" in saved_pub.lower()
        ):
            inst_pub = saved_pub
        slots["instant"].update(
            {
                "enabled": bool(g_inst.get("enabled", False)),
                "submode": inst_sub,
                "public_url": "" if (inst_sub == "cloudflare" and inst_pub.lower().endswith(".srv.us")) else inst_pub,
                "updated_at": float(g_inst.get("updated_at") or 0.0),
            }
        )

        g_wd = raw_gws.get("workers_dev") if isinstance(raw_gws.get("workers_dev"), dict) else {}
        wd_pub = _clean_https_candidate(g_wd.get("public_url")) or wd_saved_url
        slots["workers_dev"].update(
            {
                "enabled": bool(g_wd.get("enabled", False)),
                "submode": "workers_dev",
                "public_url": wd_pub,
                "script_name": str(g_wd.get("script_name") or slots["workers_dev"]["script_name"]).strip(),
                "account_id": str(g_wd.get("account_id") or slots["workers_dev"]["account_id"]).strip(),
                "subdomain": str(g_wd.get("subdomain") or slots["workers_dev"]["subdomain"]).strip(),
                "custom_domain": str(g_wd.get("custom_domain") or wd_dom).strip(),
                "updated_at": float(g_wd.get("updated_at") or 0.0),
            }
        )

        g_sh = raw_gws.get("self_hosted") if isinstance(raw_gws.get("self_hosted"), dict) else {}
        sh_sub = str(g_sh.get("submode") or "vps_hub").strip().lower()
        if sh_sub == "reverse_proxy":
            sh_sub = "custom"
        if sh_sub not in ("vps_hub", "vps", "cloudflare_token", "custom"):
            sh_sub = "vps_hub"
        sh_pub = _clean_https_candidate(g_sh.get("public_url")) or (vps_saved_url if sh_sub == "vps_hub" else "")
        slots["self_hosted"].update(
            {
                "enabled": bool(g_sh.get("enabled", False)),
                "submode": sh_sub,
                "public_url": sh_pub,
                "custom_domain": str(g_sh.get("custom_domain") or "").strip(),
                "vps_ssh_target": str(g_sh.get("vps_ssh_target") or slots["self_hosted"]["vps_ssh_target"]).strip(),
                "vps_ssh_port": int(g_sh.get("vps_ssh_port") or slots["self_hosted"]["vps_ssh_port"] or 22),
                "vps_remote_port": int(g_sh.get("vps_remote_port") or slots["self_hosted"]["vps_remote_port"] or 18096),
                "vps_identity_file": str(g_sh.get("vps_identity_file") or slots["self_hosted"]["vps_identity_file"]).strip(),
                "updated_at": float(g_sh.get("updated_at") or 0.0),
            }
        )
    else:
        legacy_tm = str(
            extra_cfg.get("tunnel_mode")
            or getattr(policy, "tunnel_mode", "")
            or ("custom" if saved_pub else "local")
        ).strip().lower()
        act_slot, act_sub = _slot_and_submode_for_tunnel_mode(legacy_tm)
        if act_slot == "instant":
            slots["instant"]["enabled"] = True
            slots["instant"]["submode"] = "cloudflare" if extra_cfg.get("prefer_quick_tunnel") else act_sub
            if saved_pub and not (slots["instant"]["submode"] == "cloudflare" and saved_pub.lower().endswith(".srv.us")):
                slots["instant"]["public_url"] = saved_pub
        elif hist_srvus:
            slots["instant"]["public_url"] = hist_srvus

        if act_slot == "workers_dev":
            slots["workers_dev"]["enabled"] = True
            slots["workers_dev"]["public_url"] = wd_saved_url or saved_pub

        if act_slot == "self_hosted":
            slots["self_hosted"]["enabled"] = True
            slots["self_hosted"]["submode"] = act_sub
            slots["self_hosted"]["public_url"] = saved_pub or (vps_saved_url if act_sub == "vps_hub" else "")

    # Sync unedited (`updated_at == 0`) slots with live running `daemon_status.json` so Studio never drops active daemon tunnels
    d_status_file = policy.state_root / "state" / (
        f"daemon_status_{policy.eff_prefix}.json" if policy.eff_prefix != "pc" else "daemon_status.json"
    )
    if d_status_file.is_file():
        try:
            live_d = json.loads(d_status_file.read_text(encoding="utf-8-sig"))
            if isinstance(live_d, dict) and str(live_d.get("status") or "") not in ("", "stopped"):
                live_gws = live_d.get("gateways")
                if isinstance(live_gws, dict):
                    for gid in STUDIO_GATEWAY_IDS:
                        gd = live_gws.get(gid)
                        if isinstance(gd, dict) and gd.get("enabled") is True and float(slots[gid].get("updated_at") or 0.0) <= 0.0:
                            slots[gid]["enabled"] = True
                            d_sub = str(gd.get("submode") or "").strip().lower()
                            if d_sub and (gid != "instant" or d_sub in ("public_gateway", "cloudflare")):
                                slots[gid]["submode"] = d_sub
                            d_u = _clean_https_candidate(gd.get("public_url"))
                            if d_u and not slots[gid].get("public_url"):
                                slots[gid]["public_url"] = d_u
                else:
                    d_m = str(live_d.get("mode") or "").strip().lower()
                    d_sl, d_sb = _slot_and_submode_for_tunnel_mode(d_m)
                    if d_sl in STUDIO_GATEWAY_IDS and float(slots[d_sl].get("updated_at") or 0.0) <= 0.0:
                        slots[d_sl]["enabled"] = True
                        if d_sb:
                            slots[d_sl]["submode"] = d_sb
                        d_u = _clean_https_candidate(live_d.get("public_url"))
                        if d_u and not slots[d_sl].get("public_url"):
                            slots[d_sl]["public_url"] = d_u
        except Exception:
            pass

    enabled_ids = [gid for gid in STUDIO_GATEWAY_IDS if slots[gid]["enabled"]]
    raw_sel = str(extra_cfg.get("selected_gateway") or getattr(policy, "selected_gateway", "") or "").strip()
    if raw_sel not in STUDIO_GATEWAY_IDS:
        raw_sel = enabled_ids[0] if enabled_ids else "instant"
    if enabled_ids and raw_sel not in enabled_ids:
        raw_sel = enabled_ids[0]

    user_pinned = str(extra_cfg.get("user_selected_gateway") or "").strip()
    if user_pinned not in enabled_ids:
        user_pinned = ""

    return slots, raw_sel, user_pinned


def _safe_hot_refresh_gateway_url(
    state_root: Path,
    new_public_url: str,
    *,
    port: int,
    prefix: str,
    tunnel_mode: str,
    gateway_id: str,
    other_enabled_count: int = 0,
) -> None:
    """Invoke `hot_refresh_public_url` only when no sibling gateway is active so top-level `d_doc` is never clobbered."""
    if other_enabled_count > 0:
        return
    try:
        sig_params = set(inspect.signature(hot_refresh_public_url).parameters.keys())
    except Exception:
        sig_params = set()

    if "gateway_id" in sig_params:
        hot_refresh_public_url(
            state_root,
            new_public_url,
            port=port,
            prefix=prefix,
            tunnel_mode=tunnel_mode,
            gateway_id=gateway_id,
        )
    else:
        hot_refresh_public_url(
            state_root,
            new_public_url,
            port=port,
            prefix=prefix,
            tunnel_mode=tunnel_mode,
        )


def _update_studio_gateway_slot(
    policy: LiveRuntimePolicy,
    gateway_id: str,
    *,
    enabled: Optional[bool] = None,
    submode: Optional[str] = None,
    public_url: Optional[str] = None,
    select: bool = False,
    user_pin: Optional[str] = None,
    exclusive: bool = False,
    extra_slot_fields: Optional[Dict[str, Any]] = None,
    port: int = 8096,
    set_public_url: Optional[Callable[[str], None]] = None,
) -> Tuple[Dict[str, Dict[str, Any]], str]:
    """Update a single gateway slot in `service.json` & `daemon_status.json` without killing sibling gateways."""
    extra_cfg = _read_saved_extra_cfg(policy)
    slots, selected_gw, user_pinned_gw = _normalize_studio_gateways_cfg(policy, extra_cfg)

    if exclusive:
        for other_id in STUDIO_GATEWAY_IDS:
            if other_id != gateway_id:
                slots[other_id]["enabled"] = False
        user_pinned_gw = ""

    if gateway_id in STUDIO_GATEWAY_IDS:
        target = slots[gateway_id]
        if enabled is not None:
            target["enabled"] = bool(enabled)
        if submode:
            target["submode"] = str(submode).strip().lower()
        if public_url is not None:
            target["public_url"] = _clean_https_candidate(public_url)
        if extra_slot_fields:
            for fk, fv in extra_slot_fields.items():
                if fv is not None:
                    target[fk] = fv
        target["updated_at"] = round(time.time(), 3)

        pol_upd_slot = getattr(policy, "update_gateway_slot", None)
        if callable(pol_upd_slot) and not exclusive:
            try:
                pol_upd_slot(
                    gateway_id,
                    enabled=enabled,
                    submode=submode,
                    public_url=_clean_https_candidate(public_url) if public_url is not None else None,
                    select=select,
                    extra_fields=extra_slot_fields,
                )
            except Exception:
                pass

    enabled_ids = [gid for gid in STUDIO_GATEWAY_IDS if slots[gid]["enabled"]]
    if not enabled_ids:
        selected_gw = "instant"
        user_pinned_gw = ""
        mirror_tm = "local"
        mirror_pub = ""
    else:
        if user_pin is not None:
            user_pinned_gw = user_pin if user_pin in enabled_ids else ""
        elif user_pinned_gw and user_pinned_gw not in enabled_ids:
            user_pinned_gw = ""

        if select and gateway_id in enabled_ids:
            selected_gw = gateway_id
        elif selected_gw not in enabled_ids:
            selected_gw = enabled_ids[0]

        mirror_tm = str(slots[selected_gw].get("submode") or "public_gateway")
        mirror_pub = str(slots[selected_gw].get("public_url") or "")
        if not mirror_pub:
            mirror_pub = next(
                (str(slots[g].get("public_url") or "") for g in enabled_ids if slots[g].get("public_url")),
                "",
            )

    pinned_urls: List[str] = [
        str(x).strip().rstrip("/")
        for x in (extra_cfg.get("pinned_gateway_urls") or [])
        if str(x).strip().startswith("https://")
    ]
    for gid in STUDIO_GATEWAY_IDS:
        cand_u = _clean_https_candidate(slots[gid].get("public_url"))
        if cand_u and ".trycloudflare.com" not in cand_u.lower() and cand_u not in pinned_urls:
            pinned_urls.append(cand_u)

    try:
        setattr(policy, "gateways", slots)
        setattr(policy, "selected_gateway", selected_gw)
        setattr(policy, "tunnel_mode", mirror_tm)
    except Exception:
        pass

    svc_json_name = f"service_{policy.eff_prefix}.json" if policy.eff_prefix != "pc" else "service.json"
    svc_json_path = policy.state_root / "state" / svc_json_name
    cfg_dir_svc_path = resolve_service_cfg_path(policy.state_root, policy.eff_prefix)
    cand_cfg_files: List[Path] = []
    for p in (policy.cfg_path, cfg_dir_svc_path, svc_json_path, policy.state_root / "config.json"):
        if p is not None and all(os.path.normcase(str(x)) != os.path.normcase(str(p)) for x in cand_cfg_files):
            cand_cfg_files.append(p)

    for cfg_file in cand_cfg_files:
        doc: Dict[str, Any] = {}
        if cfg_file.is_file():
            try:
                loaded = json.loads(cfg_file.read_text(encoding="utf-8-sig"))
                if isinstance(loaded, dict):
                    doc = loaded
            except Exception:
                doc = {}
        if cfg_file == policy.state_root / "config.json" and not doc:
            continue
        doc["gateways"] = slots
        doc["selected_gateway"] = selected_gw
        doc["user_selected_gateway"] = user_pinned_gw
        doc["pinned_gateway_urls"] = pinned_urls[-16:]
        doc["tunnel_mode"] = mirror_tm
        doc["_gateways_mirrored_mode"] = mirror_tm
        if exclusive or not enabled_ids or mirror_pub:
            doc["public_base"] = mirror_pub
            doc["public_base_url"] = mirror_pub
        if slots["instant"]["submode"] == "cloudflare":
            doc["prefer_quick_tunnel"] = True
        elif gateway_id == "instant" and submode == "public_gateway":
            doc["prefer_quick_tunnel"] = False
        doc["policy_updated_at"] = round(time.time(), 6)
        atomic_write_json(cfg_file, doc)

    policy._last_cfg_sig = policy._file_sig(policy.cfg_path)

    # Surgical `daemon_status.json` update: NEVER clear sibling active gateways!
    d_status_file = policy.state_root / "state" / (
        f"daemon_status_{policy.eff_prefix}.json" if policy.eff_prefix != "pc" else "daemon_status.json"
    )
    if d_status_file.is_file():
        try:
            d_doc = json.loads(d_status_file.read_text(encoding="utf-8-sig"))
            if isinstance(d_doc, dict):
                changed_d = False
                d_gws = d_doc.get("gateways")
                if isinstance(d_gws, dict) and gateway_id in d_gws and isinstance(d_gws[gateway_id], dict):
                    if enabled is False:
                        d_gws[gateway_id]["enabled"] = False
                        d_gws[gateway_id]["phase"] = "disabled"
                        d_gws[gateway_id]["tunnel_ready"] = False
                        d_gws[gateway_id]["last_error"] = ""
                        d_gws[gateway_id]["last_disconnect_reason_zh"] = ""
                        changed_d = True
                    elif enabled is True and (
                        d_gws[gateway_id].get("enabled") is False or d_gws[gateway_id].get("phase") == "disabled"
                    ):
                        d_gws[gateway_id]["enabled"] = True
                        d_gws[gateway_id]["phase"] = "starting"
                        d_gws[gateway_id]["tunnel_ready"] = False
                        changed_d = True
                    elif gateway_id == "instant" and submode == "cloudflare":
                        if str(d_gws["instant"].get("public_url") or "").lower().endswith(".srv.us"):
                            d_gws["instant"]["public_url"] = ""
                            d_gws["instant"]["tunnel_ready"] = False
                            d_gws["instant"]["srvus_fixed_active"] = False
                            d_gws["instant"]["phase"] = "starting"
                            changed_d = True
                if not enabled_ids and d_doc.get("supervisor_pid"):
                    if callable(set_public_url):
                        set_public_url(f"http://127.0.0.1:{port}")
                    d_doc["mode"] = "local"
                    d_doc["effective_tunnel_mode"] = "local"
                    d_doc["public_url"] = ""
                    d_doc["mcp_url"] = ""
                    d_doc["readonly_mcp_url"] = ""
                    d_doc["tunnel_ready"] = True
                    d_doc["srvus_fixed_active"] = False
                    changed_d = True
                elif exclusive and d_doc.get("supervisor_pid") and gateway_id in STUDIO_GATEWAY_IDS:
                    slot_pub = str(slots[gateway_id].get("public_url") or "")
                    if not slot_pub:
                        if callable(set_public_url):
                            set_public_url(f"http://127.0.0.1:{port}")
                        d_doc["mode"] = mirror_tm
                        d_doc["effective_tunnel_mode"] = mirror_tm
                        d_doc["public_url"] = ""
                        d_doc["public_base_url"] = ""
                        d_doc["mcp_url"] = ""
                        d_doc["readonly_mcp_url"] = ""
                        d_doc["tunnel_ready"] = False
                        d_doc["srvus_fixed_active"] = False
                        d_doc["instant_fallback_active"] = bool(mirror_tm == "cloudflare")
                        changed_d = True
                if changed_d:
                    d_doc["tunnel_updated_at"] = round(time.time(), 3)
                    atomic_write_json(d_status_file, d_doc)
        except Exception:
            pass

    return slots, selected_gw


def _resolve_studio_gateways_view(
    *,
    policy: LiveRuntimePolicy,
    extra_cfg: Dict[str, Any],
    d_doc: Optional[Dict[str, Any]],
    raw_live_pub: str = "",
) -> Dict[str, Any]:
    """Build independent live status views for `instant`, `workers_dev`, and `self_hosted` plus anti-flush top display."""
    slots_cfg, selected_gw, user_pinned_gw = _normalize_studio_gateways_cfg(policy, extra_cfg, raw_live_pub=raw_live_pub)
    d_running = isinstance(d_doc, dict) and str(d_doc.get("status") or "") not in ("", "stopped")
    d_gateways = d_doc.get("gateways") if (d_running and isinstance(d_doc, dict) and isinstance(d_doc.get("gateways"), dict)) else None
    d_legacy_mode = str((d_doc or {}).get("mode") or "").strip().lower() if d_running else ""
    d_legacy_slot, _ = _slot_and_submode_for_tunnel_mode(d_legacy_mode) if d_running else ("", "")

    gw_base = str(extra_cfg.get("public_gateway_base") or DEFAULT_PUBLIC_GATEWAY_BASE or "").strip().rstrip("/")
    ep_sec = load_endpoint_secret(policy.state_root, prefix=policy.eff_prefix)
    gateways_view: Dict[str, Dict[str, Any]] = {}

    for gid in STUDIO_GATEWAY_IDS:
        scfg = slots_cfg[gid]
        enabled = bool(scfg.get("enabled", False))
        submode = str(
            scfg.get("submode")
            or ("public_gateway" if gid == "instant" else ("workers_dev" if gid == "workers_dev" else "vps_hub"))
        ).strip().lower()

        slot_d: Optional[Dict[str, Any]] = None
        if d_gateways is not None:
            cand_d = d_gateways.get(gid)
            if isinstance(cand_d, dict):
                slot_d = cand_d
        elif d_running and d_legacy_slot == gid and isinstance(d_doc, dict):
            # Ignore stale `public_gateway` `.srv.us` daemon status if user explicitly switched `instant` to `cloudflare`
            if gid == "instant" and submode == "cloudflare" and d_legacy_mode in ("public_gateway", "srv_us"):
                slot_d = None
            elif gid == "self_hosted" and d_legacy_mode and d_legacy_mode != submode:
                slot_d = None
            else:
                slot_d = d_doc

        cfg_url = _clean_https_candidate(scfg.get("public_url"))
        if gid == "instant" and submode == "cloudflare" and cfg_url.lower().endswith(".srv.us"):
            cfg_url = ""

        d_slot_pub = _clean_https_candidate((slot_d or {}).get("public_url"))
        if gid == "instant" and submode == "cloudflare" and d_slot_pub.lower().endswith(".srv.us"):
            d_slot_pub = ""

        cand_url = (d_slot_pub or cfg_url) if enabled else cfg_url
        cand_host = (urlsplit(cand_url).hostname or "").strip().lower()

        if (gid == "instant" and submode == "public_gateway") or (cand_host in _PLACEHOLDER_DEAD_GATEWAY_HOSTS):
            pub_gw_online = _probe_public_gateway_cached(gw_base)
        else:
            pub_gw_online = False

        if cand_host in _PLACEHOLDER_DEAD_GATEWAY_HOSTS and not pub_gw_online:
            cand_url = ""
            cand_host = ""
        if (urlsplit(cfg_url).hostname or "").strip().lower() in _PLACEHOLDER_DEAD_GATEWAY_HOSTS and not pub_gw_online:
            cfg_url = ""

        consec_f = 0
        slot_err = ""
        public_https_ready = False

        if not enabled:
            status = "disabled"
            status_label_zh = "未开启"
        else:
            if slot_d is not None:
                consec_f = int(slot_d.get("consecutive_failures") or 0)
                raw_le = str(slot_d.get("last_error") or "").strip()
                raw_disc = str(slot_d.get("last_disconnect_reason_zh") or "").strip()
                d_phase = str(slot_d.get("phase") or "").strip().lower()
                d_tready = slot_d.get("tunnel_ready")
                if slot_d.get("enabled") is False or d_phase == "disabled":
                    public_https_ready = False
                    slot_err = raw_le or raw_disc
                elif d_tready is True and d_phase not in ("reconnecting", "error", "starting", "probing") and bool(cand_url):
                    public_https_ready = True
                    slot_err = ""
                elif d_tready is False or d_phase in ("reconnecting", "error", "starting", "probing") or not cand_url:
                    public_https_ready = False
                    slot_err = raw_le or raw_disc
                else:
                    slot_err = raw_le or (raw_disc if consec_f >= 1 else "")
                    public_https_ready = bool(cand_url and not slot_err)
            elif d_running:
                if gid == "self_hosted" and submode == "custom" and bool(cand_url):
                    public_https_ready = True
                else:
                    public_https_ready = False
            else:
                public_https_ready = bool(cand_url)

            if public_https_ready:
                status = "ready"
                status_label_zh = "已连通"
            elif slot_err:
                status = "error"
                status_label_zh = "异常"
            else:
                status = "connecting"
                status_label_zh = "连接中"

        if gid == "instant":
            is_srvus_host = cand_host.endswith(".srv.us") and public_https_ready
            srvus_fixed_active = bool(
                enabled
                and submode == "public_gateway"
                and (
                    (slot_d is not None and bool(slot_d.get("srvus_fixed_active")) and public_https_ready)
                    or is_srvus_host
                )
            )
            is_ephemeral = any(
                cand_host.endswith(sfx) for sfx in (".trycloudflare.com", ".lhr.life", ".localhost.run")
            )
            instant_fallback_active = bool(
                enabled
                and not srvus_fixed_active
                and (
                    (slot_d is not None and bool(slot_d.get("instant_fallback_active")))
                    or submode == "cloudflare"
                    or is_ephemeral
                    or (submode == "public_gateway" and not pub_gw_online)
                )
            )
            eff_mode = (
                str(
                    (slot_d or {}).get("effective_mode")
                    or (slot_d or {}).get("effective_tunnel_mode")
                    or ("srv_us" if srvus_fixed_active else ("cloudflare" if instant_fallback_active else submode))
                )
                if enabled
                else "disabled"
            )
        else:
            srvus_fixed_active = False
            instant_fallback_active = False
            eff_mode = submode if enabled else "disabled"

        eff_ready_pub = cand_url if public_https_ready else ""
        eff_ready_disp = (
            apply_endpoint_secret_to_url(eff_ready_pub, ep_sec)
            if (ep_sec and eff_ready_pub)
            else eff_ready_pub
        )
        disp_cfg_pub = cand_url or cfg_url
        disp_cfg_with_sec = (
            apply_endpoint_secret_to_url(disp_cfg_pub, ep_sec)
            if (ep_sec and disp_cfg_pub)
            else disp_cfg_pub
        )
        gateways_view[gid] = {
            "gateway_id": gid,
            "label_zh": GATEWAY_SLOT_LABELS_ZH[gid],
            "enabled": enabled,
            "submode": submode,
            "effective_mode": eff_mode,
            "status": status,
            "status_label_zh": status_label_zh,
            "public_https_ready": public_https_ready,
            "public_url": eff_ready_disp or (disp_cfg_with_sec if enabled else ""),
            "configured_url": disp_cfg_pub,
            "mcp_url": f"{eff_ready_disp}/mcp" if public_https_ready else "",
            "readonly_mcp_url": f"{eff_ready_disp}/mcp/readonly" if public_https_ready else "",
            "mcp_readonly_url": f"{eff_ready_disp}/mcp/readonly" if public_https_ready else "",
            "chatgpt_mcp_url": f"{eff_ready_disp}/mcp" if public_https_ready else "",
            "skill_url": f"{eff_ready_disp}/skill" if public_https_ready else "",
            "srvus_fixed_active": srvus_fixed_active,
            "instant_fallback_active": instant_fallback_active,
            "public_gateway_online": pub_gw_online if gid == "instant" else False,
            "consecutive_failures": consec_f,
            "last_error": slot_err,
        }

    enabled_gateway_ids = [gid for gid in STUDIO_GATEWAY_IDS if gateways_view[gid]["enabled"]]
    ready_gateway_ids = [
        gid for gid in STUDIO_GATEWAY_IDS if gateways_view[gid]["enabled"] and gateways_view[gid]["status"] == "ready"
    ]

    if not enabled_gateway_ids:
        display_gateway_id = ""
        top_tunnel_mode = "local"
        top_eff_mode = "local"
        top_ready = False
        top_pub = ""
        top_mcp = ""
        top_ro = ""
        top_skill = ""
        top_err = ""
        top_connecting = False
        top_fallback = False
    else:
        if user_pinned_gw and user_pinned_gw in enabled_gateway_ids:
            display_gateway_id = user_pinned_gw
        elif selected_gw in ready_gateway_ids:
            display_gateway_id = selected_gw
        elif ready_gateway_ids:
            display_gateway_id = ready_gateway_ids[0]
        elif selected_gw in enabled_gateway_ids:
            display_gateway_id = selected_gw
        else:
            display_gateway_id = enabled_gateway_ids[0]

        disp_slot = gateways_view[display_gateway_id]
        top_tunnel_mode = str(disp_slot["submode"])
        top_eff_mode = str(disp_slot["effective_mode"])
        top_ready = bool(disp_slot["public_https_ready"])
        top_pub = str(disp_slot["public_url"]) if top_ready else ""
        top_mcp = str(disp_slot["mcp_url"])
        top_ro = str(disp_slot["readonly_mcp_url"])
        top_skill = str(disp_slot["skill_url"])
        top_err = str(disp_slot["last_error"] or "")
        top_connecting = bool(not top_ready and not top_err)
        top_fallback = bool(disp_slot["instant_fallback_active"]) if display_gateway_id == "instant" else False

    inst_view = gateways_view["instant"]
    return {
        "gateways": gateways_view,
        "selected_gateway": selected_gw,
        "user_selected_gateway": user_pinned_gw,
        "display_gateway_id": display_gateway_id,
        "enabled_gateway_ids": enabled_gateway_ids,
        "ready_gateway_ids": ready_gateway_ids,
        "tunnel_mode": top_tunnel_mode,
        "effective_tunnel_mode": top_eff_mode,
        "public_https_ready": top_ready,
        "is_loopback_url": not top_ready,
        "public_url": top_pub,
        "mcp_url": top_mcp,
        "mcp_readonly_url": top_ro,
        "readonly_mcp_url": top_ro,
        "skill_url": top_skill,
        "srvus_fixed_active": bool(inst_view["srvus_fixed_active"]),
        "instant_fallback_active": top_fallback if enabled_gateway_ids else False,
        "public_gateway_online": bool(inst_view["public_gateway_online"]),
        "tunnel_connecting": top_connecting,
        "tunnel_error": top_err,
        "reboot_notice": QUICK_TUNNEL_REBOOT_NOTICE_ZH if top_fallback else "",
    }


def _probe_public_gateway_cached(base_url: str = "", ttl_sec: float = 15.0) -> bool:
    """Check whether the public fixed gateway is actually online (with `getattr` fallback for W2A concurrency)."""
    eff_base = (base_url or DEFAULT_PUBLIC_GATEWAY_BASE or "").strip().rstrip("/")
    if not eff_base.startswith("https://"):
        return False
    now = time.monotonic()
    with _PUBLIC_GW_PROBE_LOCK:
        cached = _PUBLIC_GW_PROBE_CACHE.get(eff_base)
        if cached is not None and (now - cached[0]) < ttl_sec:
            return cached[1]

    probe_fn = getattr(cfgw, "probe_public_gateway_online", None) or probe_public_gateway_online
    online = False
    if callable(probe_fn):
        try:
            res = probe_fn(eff_base, timeout_sec=1.2)
            if isinstance(res, dict):
                online = bool(res.get("online") if "online" in res else res.get("ok"))
            else:
                online = bool(res)
        except Exception:
            online = False
    else:
        host = (urlsplit(eff_base).hostname or "").strip().lower()
        online = host not in _PLACEHOLDER_DEAD_GATEWAY_HOSTS and host not in ("127.0.0.1", "localhost", "::1", "")

    with _PUBLIC_GW_PROBE_LOCK:
        _PUBLIC_GW_PROBE_CACHE[eff_base] = (time.monotonic(), online)
    return online


def _resolve_studio_public_https_urls(
    *,
    raw_public_url: str,
    tunnel_mode: str,
    extra_cfg: Dict[str, Any],
    d_doc: Optional[Dict[str, Any]],
    policy: Optional[LiveRuntimePolicy] = None,
    state_root: Optional[Path] = None,
    prefix: str = "pc",
    endpoint_secret: str = "",
) -> Dict[str, Any]:
    """Assemble Studio connection URLs without ever leaking `http://127.0.0.1` or unprovisioned placeholder domains."""
    cand = (raw_public_url or "").strip().rstrip("/")
    d_running = isinstance(d_doc, dict) and str(d_doc.get("status") or "") not in ("", "stopped")
    d_mode = str((d_doc or {}).get("mode") or "").strip().lower() if d_running else ""
    d_mode_matches = (not d_mode) or (d_mode == tunnel_mode)
    eff_d_doc = d_doc if (d_running and d_mode_matches and isinstance(d_doc, dict)) else None
    d_pub = str((eff_d_doc or {}).get("public_url") or "").strip().rstrip("/") if eff_d_doc is not None else ""
    cand_host = (urlsplit(cand).hostname or "").strip().lower()
    if (not cand.startswith("https://") or cand_host in ("127.0.0.1", "localhost", "::1")) and d_pub.startswith("https://"):
        cand = d_pub
        cand_host = (urlsplit(cand).hostname or "").strip().lower()

    gw_base = str(extra_cfg.get("public_gateway_base") or DEFAULT_PUBLIC_GATEWAY_BASE or "").strip().rstrip("/")
    # Only probe network when mode is `public_gateway` or `cand_host` matches placeholder host
    if tunnel_mode == "public_gateway" or cand_host in _PLACEHOLDER_DEAD_GATEWAY_HOSTS:
        pub_gw_online = _probe_public_gateway_cached(gw_base)
    else:
        pub_gw_online = False

    is_loopback_cand = (not cand) or (not cand.startswith("https://")) or cand_host in ("127.0.0.1", "localhost", "::1")
    is_dead_placeholder = bool(cand_host in _PLACEHOLDER_DEAD_GATEWAY_HOSTS and not pub_gw_online)
    daemon_explicit_not_ready = bool(
        eff_d_doc is not None
        and d_pub
        and d_pub == cand
        and eff_d_doc.get("tunnel_ready") is False
    )

    public_https_ready = bool(
        tunnel_mode != "local"
        and cand.startswith("https://")
        and not is_loopback_cand
        and not is_dead_placeholder
        and not daemon_explicit_not_ready
    )
    eff_ep_sec = str(endpoint_secret or "").strip().lower()
    if not eff_ep_sec:
        sr_cand = policy.state_root if policy is not None else state_root
        pfx_cand = policy.eff_prefix if policy is not None else prefix
        if sr_cand is not None:
            eff_ep_sec = load_endpoint_secret(sr_cand, prefix=pfx_cand)
    eff_clean_pub = cand if public_https_ready else ""
    if eff_clean_pub and eff_ep_sec:
        eff_clean_pub = apply_endpoint_secret_to_url(eff_clean_pub, eff_ep_sec)
    is_srvus_host = cand_host.endswith(".srv.us")
    srvus_fixed_active = bool(
        tunnel_mode == "public_gateway"
        and (
            (eff_d_doc is not None and eff_d_doc.get("srvus_fixed_active"))
            or is_srvus_host
        )
    )
    is_ephemeral_host = any(
        cand_host.endswith(sfx)
        for sfx in (".trycloudflare.com", ".lhr.life", ".localhost.run")
    )
    instant_fallback_active = bool(
        (
            (eff_d_doc is not None and eff_d_doc.get("instant_fallback_active"))
            or tunnel_mode == "cloudflare"
            or is_ephemeral_host
            or (tunnel_mode == "public_gateway" and not pub_gw_online and not srvus_fixed_active)
        )
        and not srvus_fixed_active
    )
    effective_tunnel_mode = str(
        (eff_d_doc or {}).get("effective_tunnel_mode")
        or ("srv_us" if srvus_fixed_active else ("cloudflare" if instant_fallback_active else tunnel_mode))
    )

    return {
        "public_https_ready": public_https_ready,
        "is_loopback_url": not public_https_ready,
        "public_url": eff_clean_pub,
        "mcp_url": f"{eff_clean_pub}/mcp" if public_https_ready else "",
        "mcp_readonly_url": f"{eff_clean_pub}/mcp/readonly" if public_https_ready else "",
        "readonly_mcp_url": f"{eff_clean_pub}/mcp/readonly" if public_https_ready else "",
        "skill_url": f"{eff_clean_pub}/skill" if public_https_ready else "",
        "public_gateway_online": pub_gw_online,
        "srvus_fixed_active": srvus_fixed_active,
        "instant_fallback_active": instant_fallback_active,
        "effective_tunnel_mode": effective_tunnel_mode,
        "is_dead_placeholder": is_dead_placeholder,
    }

_FRONTMATTER_RE = re.compile(r"\A---\r?\n[\s\S]*?\r?\n---\r?\n*")


def _extract_skill_description(head_txt: str) -> str:
    """Extract single-line or YAML folded/literal (`>-`, `>`, `|`) `description` from `SKILL.md`."""
    lines = head_txt.splitlines()
    if lines and lines[0].strip() == "---":
        fm_end = -1
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                fm_end = i
                break
        if fm_end > 1:
            fm_lines = lines[1:fm_end]
            for idx, ln in enumerate(fm_lines):
                m_key = re.match(r"^description\s*:\s*(.*)$", ln, flags=re.IGNORECASE)
                if not m_key:
                    continue
                inline_val = m_key.group(1).strip()
                if inline_val in (">", ">-", ">+", "|", "|-", "|+", ""):
                    parts: List[str] = []
                    for sub_ln in fm_lines[idx + 1 :]:
                        if not sub_ln.strip():
                            continue
                        if len(sub_ln) > len(sub_ln.lstrip(" \t")):
                            parts.append(sub_ln.strip())
                        else:
                            break
                    joined = " ".join(parts).strip().strip("\"'")
                    if joined:
                        return joined[:160]
                else:
                    cleaned = inline_val.strip("\"'").strip()
                    if cleaned and cleaned not in (">", ">-", "|", "|-"):
                        return cleaned[:160]
        body_lines = lines[fm_end + 1 :] if fm_end > 0 else lines
    else:
        body_lines = lines

    for ln in body_lines:
        s_ln = ln.strip().lstrip("#").strip()
        if s_ln and not s_ln.startswith("---"):
            return s_ln[:160]
    return ""


def read_asset_text(filename: str, package: str = ASSETS_PACKAGE) -> str:
    _ = package
    name = "index.html" if filename == "status.html" else filename
    clean = name.strip().lstrip("/\\")
    if not clean or ".." in clean:
        raise ValueError(f"Invalid studio asset filename: {filename!r}")
    if clean == "consent.html":
        return load_consent_template_html()
    static_p = Path(__file__).resolve().parent / "static" / clean
    return static_p.read_text(encoding="utf-8")


def _norm_tier_label_zh(label: str) -> str:
    txt = (label or "").replace("L3 工作区开发标准档", "工作区内顺畅开发")
    for k, v in (
        ("L1 只读浏览档", "只读浏览模式"),
        ("L2 工作区读写档", "仅改文件模式（禁跑命令）"),
        ("L3 工作区标准开发档", "工作区内顺畅开发"),
        ("全权限顺畅开发模式", "工作区内顺畅开发"),
        ("L4 全盘最高权限档", "全盘顺畅开发（不限目录）"),
        ("全盘最高权限模式", "全盘顺畅开发（不限目录）"),
    ):
        txt = txt.replace(k, v)
    return txt


def _status_indicator_for_tier(tier_key: str) -> Tuple[str, str]:
    tk = (tier_key or "tier3_workspace_dev").strip()
    if tk == "tier1_readonly":
        return ("readonly", "在线运行 · 只读浏览模式")
    if tk == "tier2_workspace_edit":
        return ("editonly", "在线运行 · 仅改文件（禁跑命令）")
    if tk == "tier4_full_power":
        return ("online", "在线运行 · 全盘顺畅开发（不限目录）")
    return ("online", "在线运行 · 工作区内顺畅开发")


def _safety_mode_code(tier_key: str) -> str:
    tk = (tier_key or "tier3_workspace_dev").strip()
    if tk == "tier1_readonly":
        return "readonly"
    if tk == "tier2_workspace_edit":
        return "edit_only"
    if tk == "tier4_full_power":
        return "full_power"
    return "full_dev"


def _tier_from_safety_mode(raw_mode: str) -> str:
    m = (raw_mode or "").strip().lower()
    mapping = {
        "readonly": "tier1_readonly",
        "read_only": "tier1_readonly",
        "edit_only": "tier2_workspace_edit",
        "edit": "tier2_workspace_edit",
        "full_dev": "tier3_workspace_dev",
        "dev": "tier3_workspace_dev",
        "full_power": "tier4_full_power",
        "unrestricted": "tier4_full_power",
    }
    if m in mapping:
        return mapping[m]
    return parse_strict_tier(raw_mode)


def _emit_kill_signal_resilient(state_root: Path, *, reason: str, prefix_filter: str) -> None:
    """Emit `kill_signal.json` with brief Windows sharing-violation retry when `KillSignalWatchdog` is concurrently polling."""
    for attempt in range(5):
        try:
            emit_kill_signal(state_root, reason=reason, prefix_filter=prefix_filter)
            return
        except PermissionError:
            if attempt < 4:
                time.sleep(0.03 * (attempt + 1))
            else:
                return
        except OSError:
            return


def _shutdown_disabled_packs(
    dispatcher: KernelDispatcher,
    previous_packs: Sequence[str],
    current_packs: Sequence[str],
    prefix_filter: str,
) -> List[str]:
    """Targeted pack cleanup fixing the bug where disabling `browser` alone while keeping `desktop`/`cua` skipped cleanup."""
    _ = previous_packs
    cur_norm = {str(p).strip().lower() for p in current_packs if str(p).strip()}
    browser_enabled = "browser" in cur_norm
    desktop_enabled = bool(cur_norm & {"cua", "desktop"})

    packs_map: Dict[str, Any] = getattr(dispatcher, "_packs", {}) or {}
    cleaned: List[str] = []

    if not cur_norm:
        try:
            dispatcher.shutdown_packs(prefix_filter=prefix_filter)
        except Exception:
            pass
        try:
            close_all_browser_sessions(prefix_filter=prefix_filter)
        except Exception:
            pass
        return ["browser", "desktop"]

    if not browser_enabled:
        b_pk = packs_map.get("browser")
        if b_pk is not None and hasattr(b_pk, "shutdown"):
            try:
                b_pk.shutdown(prefix_filter=prefix_filter)
            except Exception:
                pass
        try:
            close_all_browser_sessions(prefix_filter=prefix_filter)
        except Exception:
            pass
        cleaned.append("browser")

    if not desktop_enabled:
        for dk in ("cua", "desktop"):
            d_pk = packs_map.get(dk)
            if d_pk is not None and hasattr(d_pk, "shutdown"):
                try:
                    d_pk.shutdown(prefix_filter=prefix_filter)
                except Exception:
                    pass
        cleaned.append("desktop")

    return cleaned


def _persist_extra_studio_config(
    policy: LiveRuntimePolicy,
    *,
    python_path: Optional[str] = None,
    annotation_mode: Optional[str] = None,
    tunnel_mode: Optional[str] = None,
    public_url: Optional[str] = None,
    prefer_quick_tunnel: Optional[bool] = None,
    srvus_retry_requested_at: Optional[float] = None,
    readonly_workspace_roots: Optional[Sequence[Any]] = None,
    scan_host_global_skills: Optional[bool] = None,
    tool_prefix: Optional[str] = None,
    tray_enabled: Optional[bool] = None,
    workers_dev_custom_domain: Optional[str] = None,
    workers_dev_account_id: Optional[str] = None,
    workers_dev_script_name: Optional[str] = None,
    workers_dev_subdomain: Optional[str] = None,
    workers_dev_url: Optional[str] = None,
    vps_hub_url: Optional[str] = None,
    vps_node_secret: Optional[str] = None,
    vps_ssh: Optional[str] = None,
    vps_remote_port: Optional[int] = None,
    vps_ssh_port: Optional[int] = None,
    vps_identity_file: Optional[str] = None,
) -> None:
    """Sync Studio runtime & connection fields onto `policy`, `service.json`, and `state_root/config.json`."""
    sig_params = set()
    try:
        sig_params = set(inspect.signature(policy.persist_changes).parameters.keys())
    except Exception:
        sig_params = set()

    persist_kwargs: Dict[str, Any] = {}
    if python_path is not None:
        clean_py = str(python_path).strip()
        try:
            setattr(policy, "python_path", clean_py)
        except Exception:
            pass
        if clean_py:
            os.environ["COSMOS_PYTHON_PATH"] = clean_py
            os.environ["LOCALPC_PYTHON_PATH"] = clean_py
        else:
            os.environ.pop("COSMOS_PYTHON_PATH", None)
            os.environ.pop("LOCALPC_PYTHON_PATH", None)
        if "python_path" in sig_params:
            persist_kwargs["python_path"] = clean_py

    if annotation_mode is not None:
        clean_ann = str(annotation_mode).strip().lower() or ("honest" if policy.approval_popups else "compat")
        try:
            setattr(policy, "annotation_mode", clean_ann)
        except Exception:
            pass
        if "annotation_mode" in sig_params:
            persist_kwargs["annotation_mode"] = clean_ann

    if tunnel_mode is not None and str(tunnel_mode).strip():
        clean_tm = str(tunnel_mode).strip().lower()
        if "tunnel_mode" in sig_params:
            persist_kwargs["tunnel_mode"] = clean_tm
        else:
            try:
                setattr(policy, "tunnel_mode", clean_tm)
            except Exception:
                pass

    if readonly_workspace_roots is not None and "readonly_workspace_roots" in sig_params:
        persist_kwargs["readonly_workspace_roots"] = list(readonly_workspace_roots)
    if scan_host_global_skills is not None:
        clean_scan = parse_bool_flag(scan_host_global_skills, default=False)
        if "scan_host_global_skills" in sig_params:
            persist_kwargs["scan_host_global_skills"] = clean_scan
        else:
            try:
                setattr(policy, "scan_host_global_skills", clean_scan)
            except Exception:
                pass
    if tool_prefix is not None and str(tool_prefix).strip():
        clean_tp = normalize_prefix(str(tool_prefix).strip())
        if "tool_prefix" in sig_params:
            persist_kwargs["tool_prefix"] = clean_tp
        else:
            try:
                setattr(policy, "tool_prefix", clean_tp)
            except Exception:
                pass
    if tray_enabled is not None:
        clean_tray = parse_bool_flag(tray_enabled, default=True)
        if "tray_enabled" in sig_params:
            persist_kwargs["tray_enabled"] = clean_tray
        else:
            try:
                setattr(policy, "tray_enabled", clean_tray)
            except Exception:
                pass
    if workers_dev_custom_domain is not None and "workers_dev_custom_domain" in sig_params:
        persist_kwargs["workers_dev_custom_domain"] = str(workers_dev_custom_domain).strip()
    if workers_dev_account_id is not None and "workers_dev_account_id" in sig_params:
        persist_kwargs["workers_dev_account_id"] = str(workers_dev_account_id).strip()
    if workers_dev_script_name is not None and "workers_dev_script_name" in sig_params:
        persist_kwargs["workers_dev_script_name"] = str(workers_dev_script_name).strip()
    if workers_dev_subdomain is not None and "workers_dev_subdomain" in sig_params:
        persist_kwargs["workers_dev_subdomain"] = str(workers_dev_subdomain).strip()

    if persist_kwargs:
        try:
            policy.persist_changes(**persist_kwargs)
        except Exception:
            pass

    eff_py = str(getattr(policy, "python_path", "") or "").strip()
    eff_ann = str(getattr(policy, "annotation_mode", "") or ("honest" if policy.approval_popups else "compat")).strip()

    svc_json_name = f"service_{policy.eff_prefix}.json" if policy.eff_prefix != "pc" else "service.json"
    svc_json_path = policy.state_root / "state" / svc_json_name
    cfg_dir_svc_path = resolve_service_cfg_path(policy.state_root, policy.eff_prefix)
    cand_cfg_files: List[Path] = []
    for p in (policy.cfg_path, cfg_dir_svc_path, svc_json_path, policy.state_root / "config.json"):
        if p is not None and all(os.path.normcase(str(x)) != os.path.normcase(str(p)) for x in cand_cfg_files):
            cand_cfg_files.append(p)

    has_explicit_extra = any(
        x is not None
        for x in (
            python_path,
            annotation_mode,
            tunnel_mode,
            public_url,
            prefer_quick_tunnel,
            srvus_retry_requested_at,
            readonly_workspace_roots,
            scan_host_global_skills,
            tool_prefix,
            tray_enabled,
            workers_dev_custom_domain,
            workers_dev_url,
            vps_hub_url,
            vps_ssh,
            vps_remote_port,
        )
    )
    for cfg_file in cand_cfg_files:
        doc: Dict[str, Any] = {}
        if cfg_file.is_file():
            try:
                loaded = json.loads(cfg_file.read_text(encoding="utf-8-sig"))
                if isinstance(loaded, dict):
                    doc = loaded
            except Exception:
                doc = {}
        if cfg_file == policy.state_root / "config.json" and not doc and not has_explicit_extra:
            continue
        doc["python_path"] = eff_py
        doc["annotation_mode"] = eff_ann
        doc["approval_popups"] = bool(policy.approval_popups)
        doc["permission_tier"] = policy.tier_key
        doc["workspace_roots"] = [str(p) for p in policy.workspace_roots]
        doc["readonly_workspace_roots"] = [str(p) for p in getattr(policy, "readonly_workspace_roots", ())]
        doc["scan_host_global_skills"] = bool(getattr(policy, "scan_host_global_skills", False))
        doc["tray_enabled"] = bool(getattr(policy, "tray_enabled", True))
        doc["tool_prefix"] = str(getattr(policy, "tool_prefix", policy.eff_prefix) or policy.eff_prefix)
        doc["instance_id"] = str(getattr(policy, "instance_id", policy.eff_prefix) or policy.eff_prefix)
        doc["enabled_packs"] = list(policy.enabled_packs)
        doc["keep_awake"] = bool(policy.keep_awake)
        if tunnel_mode is not None and tunnel_mode != "":
            doc["tunnel_mode"] = tunnel_mode
        if prefer_quick_tunnel is not None:
            doc["prefer_quick_tunnel"] = bool(prefer_quick_tunnel)
        if srvus_retry_requested_at is not None:
            doc["srvus_retry_requested_at"] = float(srvus_retry_requested_at)
        if public_url is not None:
            doc["public_base"] = public_url
            doc["public_base_url"] = public_url
        if workers_dev_custom_domain is not None:
            doc["workers_dev_custom_domain"] = str(workers_dev_custom_domain).strip()
        if workers_dev_account_id is not None:
            doc["workers_dev_account_id"] = str(workers_dev_account_id).strip()
            doc["workers_account_id"] = str(workers_dev_account_id).strip()
        if workers_dev_script_name is not None:
            doc["workers_dev_script_name"] = str(workers_dev_script_name).strip()
            doc["workers_script_name"] = str(workers_dev_script_name).strip()
        if workers_dev_subdomain is not None:
            doc["workers_dev_subdomain"] = str(workers_dev_subdomain).strip()
            doc["workers_subdomain"] = str(workers_dev_subdomain).strip()
        if workers_dev_url is not None:
            doc["workers_dev_url"] = str(workers_dev_url).strip()
        if vps_hub_url is not None:
            doc["vps_hub_url"] = str(vps_hub_url).strip()
            doc["vps_hub_mode"] = bool(str(vps_hub_url).strip())
        if vps_node_secret is not None:
            doc["vps_node_secret"] = str(vps_node_secret).strip()
        if vps_ssh is not None:
            doc["vps_ssh"] = str(vps_ssh).strip()
        if vps_remote_port is not None:
            doc["vps_remote_port"] = int(vps_remote_port)
        if vps_ssh_port is not None:
            doc["vps_ssh_port"] = int(vps_ssh_port)
        if vps_identity_file is not None:
            doc["vps_identity_file"] = str(vps_identity_file).strip()
        doc["policy_updated_at"] = round(time.time(), 6)
        atomic_write_json(cfg_file, doc)
    policy._last_cfg_sig = policy._file_sig(policy.cfg_path)


def _read_saved_extra_cfg(policy: LiveRuntimePolicy) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    svc_json_name = f"service_{policy.eff_prefix}.json" if policy.eff_prefix != "pc" else "service.json"
    svc_json_path = policy.state_root / "state" / svc_json_name
    cfg_dir_svc_path = resolve_service_cfg_path(policy.state_root, policy.eff_prefix)
    for cfg_file in (policy.state_root / "config.json", svc_json_path, cfg_dir_svc_path, policy.cfg_path):
        if cfg_file is not None and cfg_file.is_file():
            try:
                loaded = json.loads(cfg_file.read_text(encoding="utf-8-sig"))
                if isinstance(loaded, dict):
                    merged.update(loaded)
            except Exception:
                continue
    return merged


def _detect_python_candidates(policy: LiveRuntimePolicy) -> List[Dict[str, str]]:
    seen: set[str] = set()
    out: List[Dict[str, str]] = []

    def _add(p_str: str, label: str) -> None:
        s = (p_str or "").strip()
        if not s:
            return
        p = Path(s)
        if not p.is_file():
            return
        nk = os.path.normcase(str(p.resolve()))
        if nk in seen:
            return
        seen.add(nk)
        out.append({"path": str(p.resolve()), "label": label})

    cur_saved = str(getattr(policy, "python_path", "") or _read_saved_extra_cfg(policy).get("python_path") or "").strip()
    if cur_saved:
        _add(cur_saved, "当前已配置的解释器")

    for ws in policy.workspace_roots:
        for sub in (".venv", "venv", ".conda"):
            cand = (ws / sub / "Scripts" / "python.exe") if sys.platform == "win32" else (ws / sub / "bin" / "python")
            _add(str(cand), f"项目虚拟环境 ({ws.name}/{sub})")

    home = Path.home()
    if sys.platform == "win32":
        prog_data = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        for conda_p, lbl in (
            (home / "miniconda3" / "python.exe", "Miniconda 基础环境"),
            (home / "anaconda3" / "python.exe", "Anaconda 基础环境"),
            (prog_data / "miniconda3" / "python.exe", "Miniconda 系统环境"),
            (prog_data / "anaconda3" / "python.exe", "Anaconda 系统环境"),
        ):
            _add(str(conda_p), lbl)
    else:
        for conda_p, lbl in (
            (home / "miniconda3" / "bin" / "python3", "Miniconda 基础环境"),
            (home / "anaconda3" / "bin" / "python3", "Anaconda 基础环境"),
        ):
            _add(str(conda_p), lbl)

    found_sys = find_suitable_python()
    if found_sys:
        ver_s = ".".join(str(x) for x in found_sys[1])
        _add(found_sys[0], f"系统 Python {ver_s}")

    return out[:12]


_SCOPE_LABELS_ZH: Dict[str, str] = {
    "workspace": "项目工作区 (.agents/skills)",
    "workspace_claude": "项目工作区 (.claude/skills)",
    "project": "项目工作区",
    "managed": "受管技能库",
    "cosmos_skills_store": "历史技能库 (只读)",
    "universal_agents": "通用 Agents 目录",
    "cc_switch": "CC-Switch 技能库 (只读)",
    "claude_code": "Claude Code",
    "cursor": "Cursor",
    "windsurf": "Windsurf",
    "codex": "Codex",
    "gemini_cli": "Gemini CLI",
    "antigravity_global": "Antigravity 全局",
    "hermes": "Hermes",
    "hermes_appdata": "Hermes AppData",
    "hermes_posix": "Hermes",
    "opencode": "OpenCode",
    "grok": "Grok",
    "kimi_code": "Kimi Code",
    "copilot": "GitHub Copilot",
    "antigravity_builtin": "内置技能 (只读)",
}


def _scope_label_zh(scope: str) -> str:
    s = (scope or "").strip()
    if s in _SCOPE_LABELS_ZH:
        return _SCOPE_LABELS_ZH[s]
    if s.startswith("plugin:"):
        return f"插件技能 ({s.split(':', 1)[1]})"
    return s or "本地目录"


def _scan_local_skills(
    policy_or_roots: Any,
    *,
    skills_service: Optional[SkillsMcpService] = None,
) -> Dict[str, Any]:
    """Scan local skills via native `SkillsMcpService` across workspaces, managed store, and local host roots."""
    svc = skills_service
    if svc is None:
        if hasattr(policy_or_roots, "tier_key") and hasattr(policy_or_roots, "workspace_roots"):
            svc = SkillsMcpService(policy_or_roots)
        else:
            from cosmos_mcp.capabilities.skills import SkillsConfig

            svc = SkillsMcpService(SkillsConfig(workspace_roots=list(policy_or_roots or ()), auto_discover_host_roots=True))

    cfg = svc.config
    scan_roots = cfg.ordered_scan_roots()
    checked_dirs = [str(rp) for _, rp in scan_roots]
    if str(cfg.managed_skills_store()) not in checked_dirs:
        checked_dirs.insert(0, str(cfg.managed_skills_store()))
    existing_dirs = [d for d in checked_dirs if Path(d).is_dir()]

    list_res = svc.handle_skill_manage(action="list", limit=200)
    raw_items = list(list_res.get("skills") or [])
    items_out: List[Dict[str, Any]] = []
    for it in raw_items:
        sc = str(it.get("source_scope") or "")
        items_out.append(
            {
                **it,
                "scope_label": _scope_label_zh(sc),
                "source_dir": str(it.get("source_root") or it.get("skill_dir") or ""),
            }
        )
    total_all = int(list_res.get("total", len(items_out)))
    return {
        "count": total_all,
        "total_all_count": total_all,
        "matched_count": total_all,
        "is_filtered": False,
        "enabled_count": int(list_res.get("enabled_count", sum(1 for x in items_out if x.get("enabled") is not False))),
        "disabled_count": int(list_res.get("disabled_count", sum(1 for x in items_out if x.get("enabled") is False))),
        "managed_store": str(cfg.managed_skills_store()),
        "checked_dirs": checked_dirs,
        "existing_dirs": existing_dirs,
        "items": items_out[:200],
    }


_TOOL_TITLE_ZH_MAP: Dict[str, str] = {
    **{item["base"]: item["title_zh"] for item in CORE_12_TOOLS_CATALOG},
    "manage_files": "修改撤回与安全回收箱",
    "browser_use": "受管浏览器操作",
    "cua_window": "桌面窗口操控",
    "workspace_memory": "工作区共享备忘录",
    "skill_hub": "本地与在线技能检索",
    "skill_manage": "技能创建安装与管理",
}


def _scrub_ui_internal_jargon(text: str) -> str:
    if not text:
        return ""
    out = _norm_tier_label_zh(text)
    for k, v in SAFETY_MODE_LABELS_ZH.items():
        out = out.replace(k, v)
    for raw_k, clean_v in (
        ("cua_window", "desktop_window"),
        ("toolset_profile", "工具配置"),
        ("annotation_mode", "弹窗模式"),
        ("workspace_roots", "开放目录"),
    ):
        out = out.replace(raw_k, clean_v)
    return out


def _format_epoch_local(epoch_ts: Any, *, with_seconds: bool = False) -> str:
    try:
        val = float(epoch_ts)
        if val <= 0:
            return "-"
        if val > 1e14:
            val = val / 1_000_000.0
        elif val > 1e11:
            val = val / 1000.0
        fmt = "%Y-%m-%d %H:%M:%S" if with_seconds else "%Y-%m-%d %H:%M"
        return datetime.fromtimestamp(val).strftime(fmt)
    except Exception:
        return "-"


def _session_tier_scope_label_zh(
    *,
    is_ro: bool,
    is_temp: bool,
    scopes: Sequence[Any],
    raw_scope_label: str,
    tier_key: str,
) -> str:
    sc_tokens = {str(s or "").strip().lower() for s in (scopes or ()) if str(s or "").strip()}
    if is_ro or ("readonly" in sc_tokens) or ("mcp:readonly" in sc_tokens) or ("read_only" in sc_tokens):
        base = "仅只读权限"
    elif ("edit_only" in sc_tokens) or ("mcp:edit_only" in sc_tokens):
        base = "仅改文件（禁跑命令）"
    elif ("full_power" in sc_tokens) or ("mcp:full_power" in sc_tokens):
        base = "全盘顺畅开发（不限目录）"
    elif raw_scope_label and raw_scope_label not in ("工作区标准权限", "读写与执行权限", "标准权限"):
        base = _norm_tier_label_zh(_scrub_ui_internal_jargon(raw_scope_label))
    else:
        tk = (tier_key or "tier3_workspace_dev").strip()
        if tk == "tier1_readonly":
            base = "仅只读权限"
        elif tk == "tier2_workspace_edit":
            base = "仅改文件（禁跑命令）"
        elif tk == "tier4_full_power":
            base = "全盘顺畅开发（不限目录）"
        else:
            base = "工作区内顺畅开发"
    if is_temp and "临时" not in base:
        return f"{base} · 临时会话"
    return base


def _format_authorized_sessions_for_ui(
    raw_sessions: Sequence[Dict[str, Any]],
    *,
    tier_key: str = "tier3_workspace_dev",
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for sess in raw_sessions or ():
        if not isinstance(sess, dict):
            continue
        cid = str(sess.get("client_id") or "").strip()
        if not cid:
            continue
        plat = str(sess.get("platform") or "Custom MCP Client").strip()
        cname = str(sess.get("client_name") or cid).strip()
        scopes_list = list(sess.get("scopes") or [])
        sc_low = {str(s or "").strip().lower() for s in scopes_list}
        is_ro = bool(sess.get("readonly") or ("readonly" in sc_low) or ("mcp:readonly" in sc_low))
        is_temp = bool(sess.get("temporary_session"))
        scope_lbl = _session_tier_scope_label_zh(
            is_ro=is_ro,
            is_temp=is_temp,
            scopes=scopes_list,
            raw_scope_label=str(sess.get("scope_label") or "").strip(),
            tier_key=tier_key,
        )
        latest_exp = float(sess.get("latest_expiry") or 0.0)
        earliest_exp = float(sess.get("earliest_expiry") or 0.0)
        out.append(
            {
                "client_id": cid,
                "client_name": _scrub_ui_internal_jargon(cname),
                "platform": _scrub_ui_internal_jargon(plat),
                "readonly": is_ro,
                "temporary_session": is_temp,
                "scope_label": _scrub_ui_internal_jargon(scope_lbl),
                "scopes": scopes_list,
                "active_access_count": int(sess.get("active_access_count") or 0),
                "active_refresh_count": int(sess.get("active_refresh_count") or 0),
                "earliest_expiry": earliest_exp,
                "latest_expiry": latest_exp,
                "expires_at_text": _format_epoch_local(latest_exp, with_seconds=False),
            }
        )
    return out


def _read_recent_audit_events(
    policy: LiveRuntimePolicy,
    dispatcher: Optional[KernelDispatcher] = None,
    limit: int = 25,
) -> List[Dict[str, Any]]:
    """Read recent tool call audit records from `<state_root>/logs/audit.jsonl` (plus live memory buffer)."""
    cap = max(1, min(100, int(limit or 25)))
    raw_items: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()

    if dispatcher is not None:
        try:
            for ev in dispatcher.recent_audit_events(limit=cap):
                cid = str(ev.get("call_id") or "")
                if cid and cid not in seen_ids:
                    seen_ids.add(cid)
                    raw_items.append(dict(ev))
        except Exception:
            pass

    for fn in ("audit.jsonl", "mcp_audit.jsonl"):
        ap = policy.state_root / "logs" / fn
        if not ap.is_file():
            continue
        try:
            sz = ap.stat().st_size
            with ap.open("rb") as fh:
                if sz > 65536:
                    fh.seek(sz - 65536)
                    _ = fh.readline()
                chunk = fh.read().decode("utf-8", errors="replace")
            for ln in reversed(chunk.splitlines()):
                s = ln.strip()
                if not s:
                    continue
                try:
                    doc = json.loads(s)
                except Exception:
                    continue
                if not isinstance(doc, dict):
                    continue
                cid = str(doc.get("call_id") or "")
                if cid and cid in seen_ids:
                    continue
                if cid:
                    seen_ids.add(cid)
                raw_items.append(doc)
                if len(raw_items) >= cap * 2:
                    break
        except Exception:
            continue

    def _sort_ts(item: Dict[str, Any]) -> float:
        for k in ("epoch_ts", "ts"):
            v = item.get(k)
            if isinstance(v, (int, float)):
                return float(v)
            if isinstance(v, str) and v.strip():
                try:
                    return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
                except Exception:
                    continue
        return 0.0

    raw_items.sort(key=_sort_ts, reverse=True)
    formatted: List[Dict[str, Any]] = []
    for doc in raw_items[:cap]:
        ts_num = _sort_ts(doc)
        time_str = _format_epoch_local(ts_num, with_seconds=True) if ts_num > 0 else str(doc.get("ts") or "-")[:19]
        raw_tool = str(doc.get("resolved_tool") or doc.get("tool") or "-")
        base_nm = str(doc.get("base_name") or "").strip()
        if not base_nm and "_" in raw_tool:
            base_nm = raw_tool.split("_", 1)[1]
        title_zh = _TOOL_TITLE_ZH_MAP.get(base_nm) or _scrub_ui_internal_jargon(raw_tool)
        ok_flag = bool(doc.get("ok", True))
        blocked_tag = str(doc.get("blocked_reason") or "").strip()
        dur_ms = doc.get("duration_ms")
        dur_val = round(float(dur_ms), 1) if isinstance(dur_ms, (int, float)) else 0.0
        err_txt = _scrub_ui_internal_jargon(str(doc.get("error") or "")[:160])
        formatted.append(
            {
                "call_id": str(doc.get("call_id") or ""),
                "time_text": time_str,
                "tool": _scrub_ui_internal_jargon(raw_tool),
                "title_zh": title_zh,
                "caller": _scrub_ui_internal_jargon(str(doc.get("caller") or "")),
                "ok": ok_flag,
                "blocked": bool(blocked_tag),
                "status_label": "正常完成" if ok_flag else ("安全拦截" if blocked_tag else "执行异常"),
                "duration_ms": dur_val,
                "error": err_txt,
            }
        )
    return formatted


def _format_any_ts_local(raw_ts: Any) -> str:
    if isinstance(raw_ts, (int, float)):
        return _format_epoch_local(raw_ts, with_seconds=True)
    s = str(raw_ts or "").strip()
    if not s or s == "-":
        return "-"
    if re.fullmatch(r"\d+(\.\d+)?", s):
        return _format_epoch_local(float(s), with_seconds=True)
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone()
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return s[:19]


def _collect_recovery_state(
    policy: LiveRuntimePolicy,
    limit: int = 25,
    *,
    dispatcher: Optional[KernelDispatcher] = None,
) -> Dict[str, Any]:
    """Aggregate recent file snapshots, trash items, and `audit.jsonl` events."""
    ws_roots = list(policy.workspace_roots)
    scope_roots = ws_roots if policy.restrict_to_workspace else None
    extra_undo_dirs = [
        policy.state_root / "history",
        policy.state_root / ".undo_history",
    ]
    for w in ws_roots:
        extra_undo_dirs.append(w / "history")

    snapshots: List[Dict[str, Any]] = []
    seen_paths: set[str] = set()
    base_snaps = list_undo_snapshots(limit=limit, workspace_roots=scope_roots, state_root=policy.state_root)
    for item in base_snaps:
        nk = os.path.normcase(str(item.get("path") or ""))
        if nk and nk not in seen_paths:
            seen_paths.add(nk)
            norm_it = dict(item)
            if norm_it.get("latest_at"):
                norm_it["latest_at"] = _format_any_ts_local(norm_it["latest_at"])
            snapshots.append(norm_it)

    for ud in extra_undo_dirs:
        if (ud / "index.json").is_file():
            for item in list_undo_snapshots(limit=limit, workspace_roots=scope_roots, undo_dir=ud, state_root=policy.state_root):
                nk = os.path.normcase(str(item.get("path") or ""))
                if nk and nk not in seen_paths:
                    seen_paths.add(nk)
                    norm_it = dict(item)
                    if norm_it.get("latest_at"):
                        norm_it["latest_at"] = _format_any_ts_local(norm_it["latest_at"])
                    snapshots.append(norm_it)

    trash_items: List[Dict[str, Any]] = []
    seen_tids: set[str] = set()
    base_tr = restore_trash_item(action="list", limit=limit, workspace_roots=scope_roots, state_root=policy.state_root)
    for item in (base_tr.get("items") or []):
        tid = str(item.get("trash_id") or "")
        if tid and tid not in seen_tids:
            seen_tids.add(tid)
            norm_tr = dict(item)
            if norm_tr.get("trashed_at"):
                norm_tr["trashed_at"] = _format_any_ts_local(norm_tr["trashed_at"])
            trash_items.append(norm_tr)

    for ud in extra_undo_dirs:
        if (ud / "trash_index.json").is_file():
            extra_tr = restore_trash_item(action="list", limit=limit, workspace_roots=scope_roots, undo_dir=ud, state_root=policy.state_root)
            for item in (extra_tr.get("items") or []):
                tid = str(item.get("trash_id") or "")
                if tid and tid not in seen_tids:
                    seen_tids.add(tid)
                    norm_tr = dict(item)
                    if norm_tr.get("trashed_at"):
                        norm_tr["trashed_at"] = _format_any_ts_local(norm_tr["trashed_at"])
                    trash_items.append(norm_tr)

    return {
        "snapshots": snapshots[:limit],
        "trash_items": trash_items[:limit],
        "audit_events": _read_recent_audit_events(policy, dispatcher=dispatcher, limit=limit),
    }


def _execute_studio_undo(policy: LiveRuntimePolicy, path_str: str) -> Dict[str, Any]:
    scope_roots = list(policy.workspace_roots) if policy.restrict_to_workspace else None
    res = undo_last_edit(path_str, action="undo", workspace_roots=scope_roots, state_root=policy.state_root)
    if res.get("ok"):
        return res
    for ud in (policy.state_root / "history", policy.state_root / ".undo_history"):
        if (ud / "index.json").is_file():
            alt = undo_last_edit(path_str, action="undo", workspace_roots=scope_roots, undo_dir=ud, state_root=policy.state_root)
            if alt.get("ok"):
                return alt
    return res


def _execute_studio_restore_trash(policy: LiveRuntimePolicy, trash_id: str) -> Dict[str, Any]:
    scope_roots = list(policy.workspace_roots) if policy.restrict_to_workspace else None
    eff_tid = (trash_id or "").strip() or "latest"
    res = restore_from_trash(eff_tid, action="restore", workspace_roots=scope_roots, state_root=policy.state_root)
    if res.get("ok"):
        return res
    for ud in (policy.state_root / "history", policy.state_root / ".undo_history"):
        if (ud / "trash_index.json").is_file():
            alt = restore_from_trash(eff_tid, action="restore", workspace_roots=scope_roots, undo_dir=ud, state_root=policy.state_root)
            if alt.get("ok"):
                return alt
    return res


def _decode_snapshot_preview_bytes(raw_bytes: bytes, max_chars: int = 32000) -> Tuple[Optional[str], bool]:
    """Return `(decoded_text_or_None_if_binary, was_truncated)`."""
    if not raw_bytes:
        return "", False
    sample = raw_bytes[:1024]
    has_utf16_bom = raw_bytes.startswith((b"\xff\xfe", b"\xfe\xff"))
    if not has_utf16_bom and b"\x00" in sample:
        return None, False
    if raw_bytes.startswith(b"\xff\xfe"):
        txt = raw_bytes[2:].decode("utf-16-le", errors="replace")
    elif raw_bytes.startswith(b"\xfe\xff"):
        txt = raw_bytes[2:].decode("utf-16-be", errors="replace")
    else:
        txt = raw_bytes.decode("utf-8-sig", errors="replace")
    txt = txt.replace("\r\n", "\n").replace("\r", "\n")
    if len(txt) > max_chars:
        return txt[:max_chars], True
    return txt, False


def _build_studio_snapshot_diff(policy: LiveRuntimePolicy, raw_target_path: str) -> Dict[str, Any]:
    """Build a unified before/after diff preview from `.undo_history` / `history` `index.json`."""
    clean_p = (raw_target_path or "").strip()
    if not clean_p:
        return {"ok": False, "error": "请指定要预览对比的文件路径。"}
    try:
        target_p = Path(expand_env_and_tilde(clean_p)).expanduser().resolve()
    except Exception as exc:
        return {"ok": False, "error": f"文件路径解析失败：{exc}"}

    ws_roots = list(policy.workspace_roots)
    cand_bases = list(
        _candidate_undo_bases(
            target_p,
            workspace_roots=ws_roots,
            state_root=policy.state_root,
        )
    )
    for extra_ud in (
        policy.state_root / "history",
        policy.state_root / ".undo_history",
        *(w / "history" for w in ws_roots),
        *(w / ".undo_history" for w in ws_roots),
    ):
        if extra_ud not in cand_bases:
            cand_bases.append(extra_ud)

    target_norm = os.path.normcase(str(target_p))
    matched_entry: Optional[Dict[str, Any]] = None
    for base in cand_bases:
        idx_file = base / "index.json"
        if not idx_file.is_file():
            continue
        try:
            raw_map = json.loads(idx_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(raw_map, dict):
            continue
        for raw_k, h_list in raw_map.items():
            if not isinstance(h_list, list) or not h_list:
                continue
            try:
                cand_resolved = os.path.normcase(str(Path(str(raw_k)).resolve()))
            except Exception:
                continue
            if cand_resolved == target_norm and isinstance(h_list[0], dict):
                matched_entry = dict(h_list[0])
                break
        if matched_entry is not None:
            break

    if matched_entry is None:
        return {"ok": False, "error": f"未找到该文件的历史修改快照：{target_p.name}"}

    op_kind = str(matched_entry.get("op") or ("edit" if matched_entry.get("existed_before", True) else "create"))
    existed_before = bool(matched_entry.get("existed_before", op_kind != "create"))
    snap_str = str(matched_entry.get("snap_path") or matched_entry.get("trash_path") or "").strip()

    before_bytes = b""
    if existed_before and snap_str and Path(snap_str).is_file():
        try:
            before_bytes = Path(snap_str).read_bytes()
        except OSError:
            before_bytes = b""

    after_exists = target_p.is_file()
    after_bytes = b""
    if after_exists:
        try:
            after_bytes = target_p.read_bytes()
        except OSError:
            after_bytes = b""

    before_text, trunc_b = _decode_snapshot_preview_bytes(before_bytes)
    after_text, trunc_a = _decode_snapshot_preview_bytes(after_bytes)

    raw_snap_ts: Any = (
        matched_entry.get("ts")
        or matched_entry.get("created_at")
        or matched_entry.get("mtime_str")
        or matched_entry.get("latest_at")
        or ""
    )
    if not raw_snap_ts and snap_str and Path(snap_str).is_file():
        try:
            raw_snap_ts = Path(snap_str).stat().st_mtime
        except OSError:
            raw_snap_ts = ""
    if not raw_snap_ts and after_exists:
        try:
            raw_snap_ts = target_p.stat().st_mtime
        except OSError:
            raw_snap_ts = ""
    snap_time_str = _format_any_ts_local(raw_snap_ts)

    if before_text is None or after_text is None:
        return {
            "ok": True,
            "path": str(target_p),
            "file_name": target_p.name,
            "op": op_kind,
            "existed_before": existed_before,
            "after_exists": after_exists,
            "is_binary": True,
            "before_bytes": len(before_bytes),
            "after_bytes": len(after_bytes),
            "latest_at": snap_time_str,
            "added_lines": 0,
            "removed_lines": 0,
            "diff_text": f"[二进制文件对比] 修改前 {len(before_bytes)} 字节 -> 当前 {len(after_bytes)} 字节",
        }

    b_lines = before_text.splitlines()
    a_lines = after_text.splitlines()
    diff_lines = list(
        difflib.unified_diff(
            b_lines,
            a_lines,
            fromfile=f"修改前快照 ({target_p.name})" if existed_before else "修改前 (新建文件前不存在)",
            tofile=f"当前磁盘文件 ({target_p.name})" if after_exists else "当前磁盘文件 (已移出)",
            lineterm="",
            n=3,
        )
    )
    added_cnt = sum(1 for ln in diff_lines if ln.startswith("+") and not ln.startswith("+++"))
    removed_cnt = sum(1 for ln in diff_lines if ln.startswith("-") and not ln.startswith("---"))
    diff_str = "\n".join(diff_lines[:600]) if diff_lines else "(快照内容与当前磁盘文件内容一致，无差异行)"
    if len(diff_lines) > 600 or trunc_b or trunc_a:
        diff_str += "\n... [内容较长，已截断预览]"

    return {
        "ok": True,
        "path": str(target_p),
        "file_name": target_p.name,
        "op": op_kind,
        "existed_before": existed_before,
        "after_exists": after_exists,
        "is_binary": False,
        "latest_at": snap_time_str,
        "added_lines": added_cnt,
        "removed_lines": removed_cnt,
        "diff_text": diff_str,
        "before_preview": before_text[:4000],
        "after_preview": after_text[:4000],
    }


def _list_fs_tree(raw_path: str, policy: LiveRuntimePolicy) -> Dict[str, Any]:
    """Return local drives (when `raw_path == ''`) or subdirectories for the Studio directory picker."""
    clean = (raw_path or "").strip()
    sec_norm = os.path.normcase(str((policy.state_root / "secrets").resolve()))
    st_norm = os.path.normcase(str((policy.state_root / "state").resolve()))

    def _is_hidden_or_internal(cand: Path) -> bool:
        nm = cand.name
        if nm in ("$Recycle.Bin", "System Volume Information", "$WinREAgent", "Recovery"):
            return True
        try:
            cn = os.path.normcase(str(cand.resolve()))
            if cn in (sec_norm, st_norm) or cn.startswith(sec_norm + os.sep) or cn.startswith(st_norm + os.sep):
                return True
        except OSError:
            return True
        return False

    shortcuts: List[Dict[str, str]] = [
        {"label": "当前主工作目录", "path": str(policy.primary_workspace)},
    ]
    try:
        home_p = Path.home().resolve()
        shortcuts.append({"label": "用户个人目录", "path": str(home_p)})
        desk_p = home_p / "Desktop"
        if desk_p.is_dir():
            shortcuts.append({"label": "系统桌面", "path": str(desk_p)})
    except Exception:
        pass

    if not clean:
        drives: List[Dict[str, Any]] = []
        if sys.platform == "win32":
            drive_roots: List[str] = []
            if hasattr(os, "listdrives"):
                try:
                    drive_roots = list(os.listdrives())
                except Exception:
                    drive_roots = []
            if not drive_roots:
                for ch in string.ascii_uppercase:
                    dp = f"{ch}:\\"
                    if os.path.exists(dp):
                        drive_roots.append(dp)
            for dr in drive_roots:
                dr_label = dr.rstrip("\\")
                drives.append({"name": f"本地磁盘 ({dr_label})", "path": dr, "is_drive": True})
        else:
            drives.append({"name": "系统根目录 (/)", "path": "/", "is_drive": True})
            drives.append({"name": "用户主目录 (~)", "path": str(Path.home()), "is_drive": True})
        return {
            "ok": True,
            "current_path": "",
            "parent_path": "",
            "shortcuts": shortcuts,
            "entries": drives,
        }

    target = Path(expand_env_and_tilde(clean)).expanduser().resolve()
    if not target.exists() or not target.is_dir():
        raise ValueError(f"目录不存在或无法访问：{clean}")
    if _is_hidden_or_internal(target):
        raise ValueError("内部受保护目录不支持浏览。")

    parent_str = "" if target.parent == target else str(target.parent)
    entries: List[Dict[str, Any]] = []
    try:
        with os.scandir(str(target)) as it:
            raw_dirs = []
            for de in it:
                try:
                    if not de.is_dir(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                p_obj = Path(de.path)
                if _is_hidden_or_internal(p_obj):
                    continue
                raw_dirs.append(p_obj)
        raw_dirs.sort(key=lambda p: (p.name.startswith("."), p.name.lower()))
        for p_obj in raw_dirs[:300]:
            entries.append(
                {
                    "name": p_obj.name,
                    "path": str(p_obj),
                    "is_drive": False,
                }
            )
    except PermissionError as exc:
        raise ValueError(f"当前系统账户无权读取该目录：{target}") from exc
    except OSError as exc:
        raise ValueError(f"读取目录失败：{exc}") from exc

    return {
        "ok": True,
        "current_path": str(target),
        "parent_path": parent_str,
        "shortcuts": shortcuts,
        "entries": entries,
    }


def _build_resource_metadata_url_fallback(resource_url: str) -> str:
    u = urlsplit(resource_url)
    path_s = (u.path or "").rstrip("/")
    return f"{u.scheme}://{u.netloc}/.well-known/oauth-protected-resource{path_s}"


class StandaloneOAuthProvider(OAuthProvider):  # type: ignore[misc]
    """`OAuthProvider` subclass sharing `protocol/templates/consent.html` and `protocol/oauth_web.py`."""

    def _get_local_fast_secret(self) -> bytes:
        sec = getattr(self, "_local_fast_secret", None)
        if isinstance(sec, bytes) and len(sec) >= 16:
            return sec

        st_root: Optional[Path] = getattr(self, "_state_root", None) or getattr(self, "state_root", None)
        if st_root is None:
            store_obj = getattr(self, "store", None)
            db_p = getattr(store_obj, "db_path", None)
            if db_p is not None:
                try:
                    cand_db = Path(db_p).resolve()
                    st_root = (
                        cand_db.parent.parent
                        if cand_db.parent.name in ("state", "secrets", "data")
                        else cand_db.parent
                    )
                except Exception:
                    st_root = None

        eff_pfx = str(getattr(self, "_eff_prefix", None) or getattr(self, "tool_prefix", "pc") or "pc").strip() or "pc"
        if st_root is not None:
            try:
                seed_info = ensure_master_seed_identity(Path(st_root), prefix=eff_pfx)
                seed_p_str = str(seed_info.get("seed_path") or "").strip()
                if seed_p_str and Path(seed_p_str).is_file():
                    raw_seed = Path(seed_p_str).read_bytes()
                    if len(raw_seed) >= 16:
                        sec = hmac.new(
                            raw_seed,
                            f"cosmos-local-fast-secret:v1:{eff_pfx}".encode("utf-8"),
                            hashlib.sha256,
                        ).digest()
                        self._local_fast_secret = sec
                        return sec
            except Exception:
                pass

        sec = secrets.token_bytes(32)
        self._local_fast_secret = sec
        return sec

    def authenticate_owner(self, password: str) -> bool:
        if not (password or "").strip() and is_verified_local_fast_approve():
            return True
        return bool(super().authenticate_owner(password))

    def _render_consent_html(
        self,
        *,
        client_name: str,
        consent_path: str,
        ticket: str,
        csrf: str,
        nonce: str,
        pair_code: str,
        error_banner: str = "",
        is_readonly_resource: bool = False,
        selected_scope: str = "default",
        selected_ttl: str = "30d",
        local_fast_token: str = "",
    ) -> str:
        tier_key_s = str(getattr(self, "tier_key", "tier3_workspace_dev"))
        tier_lbl_clean = _norm_tier_label_zh(str(getattr(self, "tier_label", ""))) or SAFETY_MODE_LABELS_ZH.get(
            tier_key_s, "工作区内顺畅开发"
        )
        perm_desc = self._consent_permission_desc_zh(tier_key_s, tier_lbl_clean)
        eff_fast_tok = local_fast_token
        if not eff_fast_tok and is_current_request_pure_local() and mint_local_consent_fast_token is not None and ticket and csrf:
            eff_fast_tok = mint_local_consent_fast_token(self._get_local_fast_secret(), ticket=ticket, csrf=csrf)
        if render_web_consent_html is not None:
            return render_web_consent_html(
                tier_key=tier_key_s,
                tier_label=tier_lbl_clean,
                permission_desc_zh=perm_desc,
                pair_code=pair_code,
                client_name=client_name or "AI 客户端",
                consent_path=consent_path,
                ticket=ticket,
                csrf=csrf,
                nonce=nonce,
                error_banner=error_banner,
                is_readonly_resource=is_readonly_resource,
                selected_scope=selected_scope,
                selected_ttl=selected_ttl,
                local_fast_token=eff_fast_tok,
            )
        prefix_s = str(getattr(self, "tool_prefix", "pc") or "pc")
        conn_fn = conn_info_filename_for_prefix(prefix_s)
        return render_consent_template_html(
            tier_key=tier_key_s,
            tier_label=tier_lbl_clean,
            permission_desc_zh=perm_desc,
            pair_code=pair_code,
            pair_code_path="",
            client_name=client_name or "AI 客户端",
            conn_filename=conn_fn,
            consent_path=consent_path,
            ticket=ticket,
            csrf=csrf,
            nonce=nonce,
            error_banner=error_banner,
            is_readonly_resource=is_readonly_resource,
            selected_scope=selected_scope,
            selected_ttl=selected_ttl,
        )

    async def consent(self, request: Request) -> RedirectResponse | HTMLResponse | JSONResponse:
        if handle_web_consent_request is not None:
            return await handle_web_consent_request(
                self,
                request,
                super_consent_fn=super().consent,
                local_fast_secret=self._get_local_fast_secret(),
                expected_port=getattr(self, "local_port", None),
            )
        return await super().consent(request)


def _extract_saved_connection_password(state_root: Path, eff_prefix: str) -> str:
    conn_fn = conn_info_filename_for_prefix(eff_prefix)
    sec_fn = f"connection_{eff_prefix}.txt" if eff_prefix != "pc" else "connection.txt"
    for cand in (
        state_root / "secrets" / sec_fn,
        state_root / "secrets" / "connection.txt",
        state_root / conn_fn,
        state_root / "连接信息_CONNECTION_INFO.txt",
    ):
        if cand.is_file():
            try:
                m = re.search(r"授权页连接口令\s*:\s*([^\r\n]+)", cand.read_text(encoding="utf-8", errors="replace"))
                if m:
                    val = m.group(1).strip()
                    if val and not val.startswith("("):
                        return val
            except Exception:
                continue
    return load_encrypted_connection_password(state_root, prefix=eff_prefix)


def _read_pair_code(state_root: Path, eff_prefix: str, fallback_seed: str) -> str:
    st_dir = state_root / "state"
    cands = [st_dir / "latest_consent_pair_code.txt"]
    if eff_prefix != "pc":
        cands.append(st_dir / f"latest_consent_pair_code_{eff_prefix}.txt")
    found: List[Tuple[int, int, str]] = []
    for idx, p in enumerate(cands):
        if p.is_file():
            try:
                st = p.stat()
                val = p.read_text(encoding="utf-8", errors="replace").strip()
                if val and len(val) == 4:
                    mtime_ns = int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))
                    found.append((mtime_ns, -idx, val))
            except Exception:
                continue
    if found:
        found.sort(reverse=True)
        return found[0][2]
    return derive_consent_pair_code(fallback_seed or f"cosmos-{eff_prefix}")


def _validate_workspace_candidate(raw_path: str, state_root: Path) -> Path:
    cleaned = (raw_path or "").replace("\r", "").replace("\n", "").strip().strip("\"'")
    if not cleaned or "\x00" in cleaned:
        raise ValueError("工作目录路径不能为空。")
    resolved = Path(expand_env_and_tilde(cleaned)).expanduser().resolve()
    cand_norm = Path(os.path.normcase(str(resolved)))
    for sub in ("secrets", "state"):
        sec_norm = Path(os.path.normcase(str((state_root / sub).resolve())))
        if cand_norm == sec_norm or cand_norm.is_relative_to(sec_norm):
            raise ValueError("禁止将内部凭据或状态目录加入开放工作目录。")
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


class AuthorizeBrowserGuideASGI:
    """Render a Chinese guide page when a human opens `GET /authorize` directly without `client_id=`."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") == "http" and str(scope.get("method") or "GET").upper() == "GET":
            qs = (scope.get("query_string") or b"").decode("latin-1", errors="replace")
            hdrs = {k.decode("latin-1").lower(): v.decode("latin-1", errors="replace").lower() for k, v in (scope.get("headers") or [])}
            acc = hdrs.get("accept", "")
            if "client_id=" not in qs and "application/json" not in acc:
                html_doc = (
                    '<!doctype html><html lang="zh-CN"><meta charset="utf-8">'
                    '<meta name="viewport" content="width=device-width,initial-scale=1">'
                    "<title>Cosmos MCP OAuth 授权跳转说明</title>"
                    '<body style="background:#f4f6f9;color:#0f172a;font:15px/1.65 system-ui,sans-serif;max-width:580px;margin:8vh auto;padding:20px">'
                    '<div style="background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:24px;box-shadow:0 8px 24px rgba(15,23,42,.05)">'
                    '<h1 style="font-size:19px;margin:0 0 10px">这是自动授权跳转入口（/authorize）</h1>'
                    '<p style="color:#475569;margin:8px 0">本地址由网页版 Gemini 或网页版 ChatGPT 在绑定连接器时自动携带参数跳转访问，无需在浏览器空参数直接打开。</p>'
                    '<p style="margin:16px 0 0"><a href="/" style="display:inline-block;background:#2563eb;color:#fff;text-decoration:none;padding:9px 16px;border-radius:8px;font-weight:600">返回 Cosmos Studio 首页</a></p>'
                    "</div></body></html>"
                )
                resp = HTMLResponse(html_doc, status_code=400, headers={"Cache-Control": "no-store"})
                await resp(scope, receive, send)
                return
        await self.inner(scope, receive, send)


class McpBrowserGuideASGI:
    """Render a Chinese guide page on direct unauthenticated browser `GET /mcp` while preserving `WWW-Authenticate`."""

    def __init__(self, inner: Any, get_resource_meta_url: Callable[[], str]) -> None:
        self.inner = inner
        self.get_resource_meta_url = get_resource_meta_url

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") == "http" and str(scope.get("method") or "GET").upper() == "GET":
            hdrs = {k.decode("latin-1").lower(): v.decode("latin-1", errors="replace").lower() for k, v in (scope.get("headers") or [])}
            acc = hdrs.get("accept", "")
            has_auth = bool(hdrs.get("authorization", "").strip())
            if not has_auth and "text/event-stream" not in acc and "application/json" not in acc:
                res_meta = self.get_resource_meta_url()
                html_doc = (
                    '<!doctype html><html lang="zh-CN"><meta charset="utf-8">'
                    '<meta name="viewport" content="width=device-width,initial-scale=1">'
                    "<title>Cosmos MCP 连接器地址说明（/mcp）</title>"
                    '<body style="background:#f4f6f9;color:#0f172a;font:15px/1.65 system-ui,sans-serif;max-width:600px;margin:8vh auto;padding:20px">'
                    '<div style="background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:24px;box-shadow:0 8px 24px rgba(15,23,42,.05)">'
                    '<h1 style="font-size:19px;margin:0 0 10px">这是填写到 AI 平台的连接器接口（/mcp）</h1>'
                    '<p style="color:#475569;margin:8px 0">请复制当前完整 <code>/mcp</code> 地址，粘贴到网页版 Gemini 或网页版 ChatGPT 的自定义连接器地址栏完成绑定，无需在浏览器直接打开。</p>'
                    '<p style="margin:16px 0 0"><a href="/" style="display:inline-block;background:#2563eb;color:#fff;text-decoration:none;padding:9px 16px;border-radius:8px;font-weight:600">打开 Cosmos Studio 查看连接口令</a></p>'
                    "</div></body></html>"
                )
                resp = HTMLResponse(
                    html_doc,
                    status_code=401,
                    headers={
                        "WWW-Authenticate": f'Bearer error="invalid_token", error_description="Authentication required", resource_metadata="{res_meta}"',
                        "Cache-Control": "no-store",
                    },
                )
                await resp(scope, receive, send)
                return
        await self.inner(scope, receive, send)


class _StudioSessionManager:
    """In-memory HMAC-SHA256 session cookie signer (`cosmos_studio_sid`) bound to current password hash."""

    def __init__(self) -> None:
        self._secret = secrets.token_bytes(32)

    def _pw_fp(self, provider: Any) -> str:
        pw_h = str(getattr(provider, "password_hash", "") or "")
        return hashlib.sha256(pw_h.encode("utf-8")).hexdigest()[:16]

    def mint_token(self, provider: Any, *, is_loopback: bool) -> str:
        exp = int(time.time()) + STUDIO_SESSION_TTL_SEC
        scope = "loopback" if is_loopback else "remote"
        payload = f"{exp}.{scope}.{self._pw_fp(provider)}"
        sig = hmac.new(self._secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{payload}.{sig}"

    def verify_token(self, token: str, provider: Any) -> bool:
        if not token or token.count(".") != 3:
            return False
        exp_s, _scope, fp, sig = token.split(".", 3)
        try:
            exp = int(exp_s)
        except ValueError:
            return False
        if exp < int(time.time()):
            return False
        payload = f"{exp_s}.{_scope}.{fp}"
        expected_sig = hmac.new(self._secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return False
        return hmac.compare_digest(fp, self._pw_fp(provider))

    def attach_cookie(self, resp: Response, provider: Any, *, is_loopback: bool, is_https: bool = False) -> None:
        tok = self.mint_token(provider, is_loopback=is_loopback)
        resp.set_cookie(
            STUDIO_SESSION_COOKIE,
            tok,
            max_age=STUDIO_SESSION_TTL_SEC,
            httponly=True,
            samesite="lax",
            secure=bool(is_https and not is_loopback),
            path="/",
        )

    def clear_cookie(self, resp: Response) -> None:
        resp.delete_cookie(STUDIO_SESSION_COOKIE, path="/")


def _build_studio_state_payload(
    request: Request,
    *,
    policy: LiveRuntimePolicy,
    dispatcher: KernelDispatcher,
    store: OAuthSQLiteStore,
    provider: Any,
    proc_mgr: Any,
    port: int,
    get_public_url: Callable[[], str],
    local_admin_csrf: str,
    local_api_token: str,
    session_mgr: _StudioSessionManager,
    skills_service: Optional[SkillsMcpService] = None,
    unlock_csrf: str = "",
) -> Dict[str, Any]:
    policy.refresh()
    if provider is not None:
        provider.tier_key = policy.tier_key
        provider.tier_label = _norm_tier_label_zh(policy.dynamic_tier_label())
    is_loopback = is_strict_direct_loopback(request, port)
    cookie_tok = request.cookies.get(STUDIO_SESSION_COOKIE, "")
    has_session_cookie = session_mgr.verify_token(cookie_tok, provider)
    is_unlocked = bool(is_loopback or has_session_cookie)

    if not is_loopback and not is_unlocked:
        eff_unlock_csrf = unlock_csrf or hashlib.sha256(
            f"cosmos-studio-unlock-csrf:{local_admin_csrf}".encode("utf-8")
        ).hexdigest()[:43]
        return {
            "ok": True,
            "studio_version": STUDIO_VERSION,
            "locked": True,
            "unlocked": False,
            "is_loopback": False,
            "csrf_token": eff_unlock_csrf,
            "status_kind": "online",
            "status_text": "在线运行 · 输入管理口令解锁控制面板",
        }

    eff_pub = get_public_url().rstrip("/")
    eff_host = (urlsplit(eff_pub).hostname or "").strip().lower()
    is_loopback_pub = eff_host in ("127.0.0.1", "localhost", "::1")

    extra_cfg = _read_saved_extra_cfg(policy)
    tunnel_mode = str(
        extra_cfg.get("tunnel_mode")
        or getattr(policy, "tunnel_mode", "")
        or getattr(provider, "tunnel_mode", "")
        or ("local" if is_loopback_pub else "custom")
    ).strip().lower()
    if tunnel_mode not in TUNNEL_MODE_LABELS_ZH:
        tunnel_mode = "local" if is_loopback_pub else "custom"

    status_kind, status_text = _status_indicator_for_tier(policy.tier_key)
    mode_code = _safety_mode_code(policy.tier_key)
    allow_edit = bool(policy.allow_edit)
    allow_exec = bool(policy.allow_exec)

    core_tools_ui: List[Dict[str, Any]] = []
    for item in CORE_12_TOOLS_CATALOG:
        band = item["band"]
        enabled_now = True
        if band == "write" and not allow_edit:
            enabled_now = False
        elif band == "exec" and not allow_exec:
            enabled_now = False
        core_tools_ui.append(
            {
                "title": item["title_zh"],
                "category": item["category_zh"],
                "band": band,
                "description": item["desc_zh"],
                "enabled": enabled_now,
            }
        )

    has_browser = "browser" in policy.enabled_packs
    has_desktop = ("cua" in policy.enabled_packs) or ("desktop" in policy.enabled_packs)
    ann_mode = str(
        getattr(policy, "annotation_mode", "")
        or extra_cfg.get("annotation_mode")
        or ("honest" if policy.approval_popups else "compat")
    ).strip().lower()
    confirm_popups = bool(policy.approval_popups or ann_mode in ("honest", "confirm", "prompt"))
    eff_confirm_popups = bool(confirm_popups and allow_edit)
    eff_pack_browser = bool(has_browser and allow_exec)
    eff_pack_desktop = bool(has_desktop and allow_exec)

    pw_plain = _extract_saved_connection_password(policy.state_root, policy.eff_prefix)
    has_saved_pw = bool(pw_plain)
    eff_conn_pw = pw_plain if is_loopback else ""
    ep_sec_cur = load_endpoint_secret(policy.state_root, prefix=policy.eff_prefix)
    ep_sec_masked = (ep_sec_cur[:4] + "••••" + ep_sec_cur[-4:]) if len(ep_sec_cur) >= 10 else ""
    pw_wiped_flag = is_plaintext_connection_password_wiped(policy.state_root, prefix=policy.eff_prefix)
    pair_code = _read_pair_code(policy.state_root, policy.eff_prefix, fallback_seed=local_api_token)
    dynamic_pair_code = ""
    if provider is not None and hasattr(provider, "get_dynamic_pair_code"):
        try:
            dynamic_pair_code = str(provider.get_dynamic_pair_code() or "").strip()
        except Exception:
            dynamic_pair_code = ""

    seed_identity: Dict[str, Any] = {}
    try:
        seed_identity = ensure_master_seed_identity(policy.state_root, prefix=policy.eff_prefix)
    except Exception:
        seed_identity = {}
    node_id = str(
        seed_identity.get("node_id")
        or getattr(policy, "public_gateway_node_id", "")
        or extra_cfg.get("public_gateway_node_id")
        or ""
    ).strip()
    tool_prefix_val = str(getattr(policy, "tool_prefix", policy.eff_prefix) or policy.eff_prefix).strip()
    instance_id_val = str(getattr(policy, "instance_id", policy.eff_prefix) or policy.eff_prefix).strip()
    ro_ws_roots = [str(p) for p in getattr(policy, "readonly_workspace_roots", ())]
    scan_host_global = bool(getattr(policy, "scan_host_global_skills", False))
    tray_enabled_val = bool(getattr(policy, "tray_enabled", True))
    workers_custom_dom = str(
        getattr(policy, "workers_dev_custom_domain", "")
        or extra_cfg.get("workers_dev_custom_domain")
        or ""
    ).strip()

    py_saved = str(getattr(policy, "python_path", "") or extra_cfg.get("python_path") or "").strip()
    py_candidates = _detect_python_candidates(policy)

    jobs_list: List[Dict[str, Any]] = []
    if proc_mgr is not None:
        try:
            j_res = proc_mgr.manage_bg_command(action="list")
            jobs_list = list(j_res.get("jobs") or [])[:20]
        except Exception:
            jobs_list = []

    recovery_data = _collect_recovery_state(policy, limit=20, dispatcher=dispatcher)
    skills_data = _scan_local_skills(policy, skills_service=skills_service)
    autostart_st = get_autostart_status(prefix=policy.eff_prefix)
    sessions = store.list_authorized_sessions() if store is not None else []
    ui_sessions = _format_authorized_sessions_for_ui(sessions, tier_key=policy.tier_key)
    has_cf_tok = bool(load_tunnel_token(policy.state_root, prefix=policy.eff_prefix))

    d_status_file = policy.state_root / "state" / (
        f"daemon_status_{policy.eff_prefix}.json" if policy.eff_prefix != "pc" else "daemon_status.json"
    )
    d_doc_parsed: Optional[Dict[str, Any]] = None
    if d_status_file.is_file():
        try:
            d_doc = json.loads(d_status_file.read_text(encoding="utf-8-sig"))
            if isinstance(d_doc, dict):
                d_doc_parsed = d_doc
        except Exception:
            d_doc_parsed = None

    gw_view = _resolve_studio_gateways_view(
        policy=policy,
        extra_cfg=extra_cfg,
        d_doc=d_doc_parsed,
        raw_live_pub=eff_pub,
    )
    tunnel_mode = str(gw_view["tunnel_mode"])
    public_https_ready = bool(gw_view["public_https_ready"])
    tunnel_connecting = bool(gw_view["tunnel_connecting"])
    tunnel_err = str(gw_view["tunnel_error"] or "")

    raw_skill_zh = render_skill_markdown(dispatcher, policy, port=port, lang="zh", include_frontmatter=False)
    skill_zh = _norm_tier_label_zh(_FRONTMATTER_RE.sub("", raw_skill_zh or "").lstrip())
    raw_skill_full_zh = render_skill_markdown(dispatcher, policy, port=port, lang="zh", include_frontmatter=True)
    skill_full_zh = _norm_tier_label_zh((raw_skill_full_zh or "").strip()) + "\n"

    saved_pub_base = str(extra_cfg.get("public_base") or "").strip().rstrip("/")
    saved_pub_host = (urlsplit(saved_pub_base).hostname or "").strip().lower()
    if saved_pub_host in ("127.0.0.1", "localhost", "::1") or (
        saved_pub_host in _PLACEHOLDER_DEAD_GATEWAY_HOSTS and not gw_view["public_gateway_online"]
    ):
        saved_pub_base = ""

    wd_slot_cfg = gw_view["gateways"]["workers_dev"]
    sh_slot_cfg = gw_view["gateways"]["self_hosted"]
    eff_wd_url = str(extra_cfg.get("workers_dev_url") or wd_slot_cfg.get("configured_url") or "").strip()
    eff_vps_hub_url = str(extra_cfg.get("vps_hub_url") or (sh_slot_cfg.get("configured_url") if sh_slot_cfg.get("submode") == "vps_hub" else "") or "").strip()

    return {
        "ok": True,
        "studio_version": STUDIO_VERSION,
        "product_version": PRODUCT_VERSION,
        "locked": False,
        "unlocked": is_unlocked,
        "is_loopback": is_loopback,
        "csrf_token": local_admin_csrf,
        "device_label": policy.device_label,
        "port": port,
        "node_id": node_id,
        "tool_prefix": tool_prefix_val,
        "instance_id": instance_id_val,
        "gateways": gw_view["gateways"],
        "selected_gateway": gw_view["selected_gateway"],
        "display_gateway_id": gw_view["display_gateway_id"],
        "enabled_gateway_ids": gw_view["enabled_gateway_ids"],
        "ready_gateway_ids": gw_view["ready_gateway_ids"],
        "public_https_ready": public_https_ready,
        "mcp_url": gw_view["mcp_url"],
        "mcp_readonly_url": gw_view["mcp_readonly_url"],
        "readonly_mcp_url": gw_view["readonly_mcp_url"],
        "dynamic_pair_code": dynamic_pair_code,
        "cloudflare_token_template_url": CLOUDFLARE_TOKEN_TEMPLATE_URL,
        "srvus_fixed_active": gw_view["srvus_fixed_active"],
        "instant_fallback_active": gw_view["instant_fallback_active"],
        "effective_tunnel_mode": gw_view["effective_tunnel_mode"],
        "public_gateway_online": gw_view["public_gateway_online"],
        "tunnel_connecting": tunnel_connecting,
        "tunnel_error": tunnel_err,
        "readonly_workspace_roots": ro_ws_roots,
        "scan_host_global_skills": scan_host_global,
        "tray_enabled": tray_enabled_val,
        "status_kind": status_kind,
        "status_text": status_text,
        "safety_mode": mode_code,
        "safety_mode_label": SAFETY_MODE_LABELS_ZH.get(policy.tier_key, "工作区内顺畅开发"),
        "restrict_to_workspace": bool(policy.restrict_to_workspace),
        "consent_pair_code": pair_code,
        "authorized_sessions_count": len(ui_sessions),
        "authorized_sessions": ui_sessions,
        "connection": {
            "connector_name": "Cosmos",
            "gateways": gw_view["gateways"],
            "selected_gateway": gw_view["selected_gateway"],
            "user_selected_gateway": gw_view["user_selected_gateway"],
            "display_gateway_id": gw_view["display_gateway_id"],
            "enabled_gateway_ids": gw_view["enabled_gateway_ids"],
            "ready_gateway_ids": gw_view["ready_gateway_ids"],
            "tunnel_mode": tunnel_mode,
            "effective_tunnel_mode": gw_view["effective_tunnel_mode"],
            "tunnel_mode_label": TUNNEL_MODE_LABELS_ZH.get(tunnel_mode, "一键上手默认通道"),
            "public_https_ready": public_https_ready,
            "is_loopback_url": bool(gw_view["is_loopback_url"]),
            "public_url": gw_view["public_url"],
            "public_base": saved_pub_base or gw_view["public_url"],
            "workers_dev_url": eff_wd_url,
            "workers_dev_custom_domain": workers_custom_dom,
            "workers_dev_subdomain": str(
                getattr(policy, "workers_dev_subdomain", "") or extra_cfg.get("workers_dev_subdomain") or ""
            ),
            "vps_hub_url": eff_vps_hub_url,
            "vps_ssh": str(extra_cfg.get("vps_ssh") or ""),
            "vps_remote_port": int(extra_cfg.get("vps_remote_port") or 18096),
            "vps_ssh_port": int(extra_cfg.get("vps_ssh_port") or 22),
            "vps_identity_file": str(extra_cfg.get("vps_identity_file") or ""),
            "mcp_url": gw_view["mcp_url"],
            "mcp_readonly_url": gw_view["mcp_readonly_url"],
            "readonly_mcp_url": gw_view["readonly_mcp_url"],
            "skill_url": gw_view["skill_url"],
            "cloudflare_token_template_url": CLOUDFLARE_TOKEN_TEMPLATE_URL,
            "srvus_fixed_active": gw_view["srvus_fixed_active"],
            "instant_fallback_active": gw_view["instant_fallback_active"],
            "public_gateway_online": gw_view["public_gateway_online"],
            "node_id": node_id,
            "tunnel_token_configured": has_cf_tok,
            "tunnel_connecting": tunnel_connecting,
            "tunnel_error": tunnel_err,
            "reboot_notice": gw_view["reboot_notice"],
            "connection_password": eff_conn_pw,
            "has_saved_password": has_saved_pw,
            "endpoint_secret_enabled": bool(ep_sec_cur),
            "endpoint_secret_masked": ep_sec_masked,
            "plaintext_password_wiped": bool(pw_wiped_flag),
            "pair_code": pair_code,
            "consent_pair_code": pair_code,
            "dynamic_pair_code": dynamic_pair_code,
            "authorized_sessions_count": len(ui_sessions),
            "authorized_sessions": ui_sessions,
            "keep_awake": bool(policy.keep_awake),
            "tray_enabled": tray_enabled_val,
            "autostart_enabled": bool(autostart_st.get("enabled")),
            "autostart_notice": str(autostart_st.get("boundary_notice") or ""),
        },
        "workspaces": {
            "primary": str(policy.primary_workspace),
            "roots": [str(p) for p in policy.workspace_roots],
            "readonly_roots": ro_ws_roots,
            "readonly_workspace_roots": ro_ws_roots,
            "access_modes": {
                str(p): (
                    "readonly"
                    if idx > 0
                    and any(
                        os.path.normcase(str(ro)) == os.path.normcase(str(p))
                        for ro in getattr(policy, "readonly_workspace_roots", ())
                    )
                    else "readwrite"
                )
                for idx, p in enumerate(policy.workspace_roots)
            },
            "python_path": py_saved,
            "python_candidates": py_candidates,
        },
        "tools_center": {
            "core_count": len(core_tools_ui),
            "active_total_count": len(dispatcher.active_tool_specs()),
            "core_tools": core_tools_ui,
            "safety_modes": [
                {
                    "code": "full_dev",
                    "tier_key": "tier3_workspace_dev",
                    "label": SAFETY_MODE_LABELS_ZH["tier3_workspace_dev"],
                    "active": bool(mode_code == "full_dev"),
                },
                {
                    "code": "full_power",
                    "tier_key": "tier4_full_power",
                    "label": SAFETY_MODE_LABELS_ZH["tier4_full_power"],
                    "active": bool(mode_code == "full_power"),
                },
                {
                    "code": "edit_only",
                    "tier_key": "tier2_workspace_edit",
                    "label": SAFETY_MODE_LABELS_ZH["tier2_workspace_edit"],
                    "active": bool(mode_code == "edit_only"),
                },
                {
                    "code": "readonly",
                    "tier_key": "tier1_readonly",
                    "label": SAFETY_MODE_LABELS_ZH["tier1_readonly"],
                    "active": bool(mode_code == "readonly"),
                },
            ],
            "pack_browser": eff_pack_browser,
            "pack_desktop": eff_pack_desktop,
            "confirm_popups": eff_confirm_popups,
            "scan_host_global_skills": scan_host_global,
            "tool_prefix": tool_prefix_val,
            "tray_enabled": tray_enabled_val,
            "readonly_locked": bool(mode_code == "readonly"),
            "exec_locked": bool(not allow_exec),
            "skill_preview": skill_zh[:3000],
            "skill_markdown": skill_full_zh,
        },
        "tasks": {
            "jobs": jobs_list,
            "running_count": sum(1 for j in jobs_list if j.get("running")),
        },
        "recovery": recovery_data,
        "skills": skills_data,
    }


def render_admin_status_html(
    request: Request,
    *,
    policy: LiveRuntimePolicy,
    dispatcher: KernelDispatcher,
    store: OAuthSQLiteStore,
    provider: Any = None,
    proc_mgr: Any = None,
    port: int,
    get_public_url: Callable[[], str],
    local_admin_csrf: str,
    local_api_token: str,
    session_mgr: Optional[_StudioSessionManager] = None,
    admin_notice: str = "",
    admin_error: str = "",
    http_status: int = 200,
    unlock_csrf: str = "",
) -> HTMLResponse:
    eff_sess_mgr = session_mgr or _StudioSessionManager()
    boot = _build_studio_state_payload(
        request,
        policy=policy,
        dispatcher=dispatcher,
        store=store,
        provider=provider,
        proc_mgr=proc_mgr,
        port=port,
        get_public_url=get_public_url,
        local_admin_csrf=local_admin_csrf,
        local_api_token=local_api_token,
        session_mgr=eff_sess_mgr,
        unlock_csrf=unlock_csrf,
    )
    q_notice = (request.query_params.get("admin_notice") or "").strip()
    if admin_notice or q_notice:
        boot["flash_notice"] = admin_notice or q_notice
    if admin_error:
        boot["flash_error"] = admin_error

    boot_for_html = dict(boot)
    if isinstance(boot.get("connection"), dict):
        conn_copy = dict(boot["connection"])
        orig_pw = str(conn_copy.get("connection_password") or "")
        conn_copy["has_saved_password"] = bool(
            conn_copy.get("has_saved_password")
            or orig_pw
            or _extract_saved_connection_password(policy.state_root, policy.eff_prefix)
        )
        conn_copy["connection_password"] = ""
        boot_for_html["connection"] = conn_copy

    tpl = read_asset_text("index.html")
    safe_boot_json = json.dumps(boot_for_html, ensure_ascii=False).replace("</", "<\\/")
    status_kind = str(boot.get("status_kind") or "online")
    status_text = str(boot.get("status_text") or "在线运行 · 工作区内顺畅开发")
    dev_lbl = str(boot.get("device_label") or policy.device_label)

    replacements = {
        "__STUDIO_BOOT_JSON__": safe_boot_json,
        "__STATUS_KIND__": html.escape(status_kind),
        "__STATUS_TEXT__": html.escape(status_text),
        "__DEVICE_LABEL__": html.escape(dev_lbl),
        "__VERSION__": html.escape(PRODUCT_VERSION),
    }
    rendered = tpl
    for k, v in replacements.items():
        rendered = rendered.replace(k, v)
    if "/static/security-uninstall.js" not in rendered and "</body>" in rendered:
        rendered = rendered.replace("</body>", '  <script src="/static/security-uninstall.js" defer></script>\n</body>', 1)
    return HTMLResponse(
        rendered,
        status_code=http_status,
        headers={
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "frame-ancestors 'none'",
        },
    )


async def _parse_request_data(request: Request) -> Tuple[Optional[Dict[str, Any]], bool]:
    ctype = (request.headers.get("content-type") or "").lower()
    accept = (request.headers.get("accept") or "").lower()
    wants_html = ("text/html" in accept) and ("application/json" not in ctype) and ("application/json" not in accept)
    if "application/json" in ctype:
        try:
            raw_j = await request.json()
            return (raw_j if isinstance(raw_j, dict) else {}), wants_html
        except Exception:
            return None, wants_html
    form = await request.form()
    return {str(k): v for k, v in form.items()}, wants_html


def _has_valid_local_bearer_token(request: Request, port: int, local_api_token: str) -> bool:
    if not local_api_token or not port or not is_strict_direct_loopback(request, port):
        return False
    auth_hdr = (request.headers.get("authorization") or "").strip()
    if len(auth_hdr) <= 7 or not auth_hdr[:7].lower().startswith("bearer "):
        return False
    cand = auth_hdr[7:].strip()
    return bool(cand and hmac.compare_digest(cand, local_api_token))


def _verify_same_origin_and_csrf(
    request: Request,
    data: Dict[str, Any],
    local_admin_csrf: str,
    *,
    strict_loopback_only: bool = False,
    port: int = 0,
    local_api_token: str = "",
    extra_allowed_csrf: str = "",
) -> Optional[JSONResponse]:
    sec_fetch_site = (request.headers.get("sec-fetch-site") or "").strip().lower()
    if sec_fetch_site == "cross-site":
        return JSONResponse(
            {"ok": False, "error": "拒绝跨站来源请求。"},
            status_code=403,
            headers={"Cache-Control": "no-store"},
        )

    origin_hdr = (request.headers.get("origin") or "").strip()
    if origin_hdr:
        if origin_hdr.lower() == "null":
            return JSONResponse(
                {"ok": False, "error": "拒绝跨站来源请求。"},
                status_code=403,
                headers={"Cache-Control": "no-store"},
            )
        try:
            orig_parsed = urlsplit(origin_hdr)
            orig_host = (orig_parsed.hostname or "").strip().lower()
            orig_port = orig_parsed.port
        except ValueError:
            return JSONResponse(
                {"ok": False, "error": "拒绝跨站来源请求。"},
                status_code=403,
                headers={"Cache-Control": "no-store"},
            )
        req_host_full = (request.headers.get("host") or "").strip()
        try:
            req_parsed = urlsplit(f"http://{req_host_full}") if req_host_full else None
            req_host = (req_parsed.hostname or "").strip().lower() if req_parsed else ""
            req_port = req_parsed.port if req_parsed else None
        except ValueError:
            return JSONResponse(
                {"ok": False, "error": "拒绝跨站来源请求。"},
                status_code=403,
                headers={"Cache-Control": "no-store"},
            )
        if not orig_host:
            return JSONResponse(
                {"ok": False, "error": "拒绝跨站来源请求。"},
                status_code=403,
                headers={"Cache-Control": "no-store"},
            )
        if strict_loopback_only:
            if orig_host not in ("127.0.0.1", "localhost", "::1"):
                return JSONResponse(
                    {"ok": False, "error": "Forbidden: untrusted Origin for local admin."},
                    status_code=403,
                    headers={"Cache-Control": "no-store"},
                )
        else:
            allowed_hosts = {"127.0.0.1", "localhost", "::1"}
            if req_host:
                allowed_hosts.add(req_host)
            if orig_host not in allowed_hosts:
                return JSONResponse(
                    {"ok": False, "error": "拒绝跨站来源请求。"},
                    status_code=403,
                    headers={"Cache-Control": "no-store"},
                )
        if orig_port is not None and req_port is not None and orig_port != req_port:
            return JSONResponse(
                {"ok": False, "error": "拒绝跨端口来源请求。"},
                status_code=403,
                headers={"Cache-Control": "no-store"},
            )

    # CLI / local AI automation carrying a valid `Authorization: Bearer <local_api_token>` over strict loopback
    # is already authenticated via secret token and exempt from browser-form random `csrf_token` checks.
    if _has_valid_local_bearer_token(request, port, local_api_token):
        return None

    csrf_val = str(
        data.get("csrf")
        or data.get("csrf_token")
        or request.headers.get("x-studio-csrf")
        or request.headers.get("x-localpc-csrf")
        or ""
    ).strip()
    csrf_ok = bool(csrf_val and hmac.compare_digest(csrf_val, local_admin_csrf))
    if not csrf_ok and extra_allowed_csrf and csrf_val:
        csrf_ok = hmac.compare_digest(csrf_val, extra_allowed_csrf)
    if not csrf_ok:
        return JSONResponse(
            {"ok": False, "error": "会话安全校验令牌无效，请刷新页面后重试。"},
            status_code=403,
            headers={"Cache-Control": "no-store"},
        )
    return None


async def handle_local_admin_permissions(
    request: Request,
    *,
    policy: LiveRuntimePolicy,
    dispatcher: KernelDispatcher,
    store: OAuthSQLiteStore,
    provider: OAuthProvider,
    port: int,
    get_public_url: Callable[[], str],
    local_admin_csrf: str,
    local_api_token: str,
    session_mgr: Optional[_StudioSessionManager] = None,
) -> Response:
    """Handle CSRF-protected `/local-admin/permissions` mutations with session cookie reuse & targeted pack shutdown."""
    if not is_strict_direct_loopback(request, port):
        return JSONResponse(
            {"ok": False, "error": "Forbidden: strict local loopback access required."},
            status_code=403,
            headers={"Cache-Control": "no-store"},
        )
    data, wants_html = await _parse_request_data(request)
    if data is None:
        return JSONResponse({"ok": False, "error": "Invalid JSON body."}, status_code=400)

    csrf_err = _verify_same_origin_and_csrf(
        request,
        data,
        local_admin_csrf,
        strict_loopback_only=True,
        port=port,
        local_api_token=local_api_token,
    )
    if csrf_err is not None:
        return csrf_err

    action = str(data.get("action") or "").strip().lower()
    if not action:
        if "tier" in data or "permission_tier" in data:
            action = "set_tier"
        elif "add_workspace" in data:
            action = "add_workspace"
        elif "remove_workspace" in data:
            action = "remove_workspace"
        elif "workspace" in data or "workspace_roots" in data:
            action = "set_workspace"
        elif "toolset_profile" in data or "toolset" in data:
            action = "set_toolset"
        elif "enabled_packs" in data or "enable_pack" in data:
            action = "set_enabled_packs"
        elif "keep_awake" in data:
            action = "set_keep_awake"
        elif "approval_popups" in data or "annotation_mode" in data:
            action = "set_approval_popups"

    policy.refresh()
    eff_sess = session_mgr or _StudioSessionManager()
    cookie_valid = eff_sess.verify_token(request.cookies.get(STUDIO_SESSION_COOKIE, ""), provider)
    bearer_valid = _has_valid_local_bearer_token(request, port, local_api_token)
    mint_cookie_on_success = False

    is_l1_emergency_downgrade = False
    if action == "set_tier":
        raw_t_cand = str(data.get("tier") or data.get("permission_tier") or "").strip()
        try:
            is_l1_emergency_downgrade = _tier_from_safety_mode(raw_t_cand) == "tier1_readonly"
        except ValueError:
            is_l1_emergency_downgrade = False

    if not is_l1_emergency_downgrade and not cookie_valid and not bearer_valid:
        locked, wait_sec = store.check_auth_lockout(bucket_key="local_admin")
        glob_locked, glob_wait = (
            store.check_global_auth_lockout() if hasattr(store, "check_global_auth_lockout") else (False, 0)
        )
        if locked or glob_locked:
            eff_wait = max(int(wait_sec or 0), int(glob_wait or 0), 1)
            msg_lock = f"管理口令连续错误次数过多，请等待 {eff_wait} 秒后重试。"
            if wants_html:
                return render_admin_status_html(
                    request, policy=policy, dispatcher=dispatcher, store=store, provider=provider,
                    port=port, get_public_url=get_public_url, local_admin_csrf=local_admin_csrf,
                    local_api_token=local_api_token, session_mgr=eff_sess, admin_error=msg_lock, http_status=429,
                )
            return JSONResponse({"ok": False, "error": "rate_limited", "detail": msg_lock}, status_code=429)

        raw_pw = str(data.get("owner_password") or data.get("password") or request.headers.get("x-cosmos-password") or "").strip()
        if not raw_pw:
            err_msg = "操作需要验证管理口令（未填写或口令不正确）。"
            if wants_html:
                return render_admin_status_html(
                    request, policy=policy, dispatcher=dispatcher, store=store, provider=provider,
                    port=port, get_public_url=get_public_url, local_admin_csrf=local_admin_csrf,
                    local_api_token=local_api_token, session_mgr=eff_sess, admin_error=err_msg, http_status=403,
                )
            return JSONResponse(
                {"ok": False, "error": "Forbidden: invalid or missing owner_password.", "detail": err_msg},
                status_code=403,
                headers={"Cache-Control": "no-store"},
            )
        if not _STUDIO_AUTH_SCRYPT_SEMAPHORE.acquire(timeout=1.5):
            return JSONResponse({"ok": False, "error": "rate_limited", "detail": "认证请求过于密集，请稍后重试。"}, status_code=429)
        try:
            pw_valid = provider.authenticate_owner(raw_pw)
        finally:
            _STUDIO_AUTH_SCRYPT_SEMAPHORE.release()
        if not pw_valid:
            now_l, rem_l = store.record_auth_result(False, bucket_key="local_admin")
            glob_l, rem_g = (
                store.record_global_auth_result(False, max_failures=8, window_sec=30, lockout_sec=60)
                if hasattr(store, "record_global_auth_result")
                else (False, 0)
            )
            if now_l or glob_l:
                eff_w = max(int(rem_l or 0), int(rem_g or 0), 1)
                msg_lock = f"管理口令连续错误次数过多，请等待 {eff_w} 秒后重试。"
                if wants_html:
                    return render_admin_status_html(
                        request, policy=policy, dispatcher=dispatcher, store=store, provider=provider,
                        port=port, get_public_url=get_public_url, local_admin_csrf=local_admin_csrf,
                        local_api_token=local_api_token, session_mgr=eff_sess, admin_error=msg_lock, http_status=429,
                    )
                return JSONResponse(
                    {
                        "ok": False,
                        "error": "rate_limited",
                        "reason": "global_auth_cooldown" if glob_l else "ip_password_lockout",
                        "detail": msg_lock,
                    },
                    status_code=429,
                    headers={"Cache-Control": "no-store"},
                )
            err_msg = "操作需要验证管理口令（未填写或口令不正确）。"
            if wants_html:
                return render_admin_status_html(
                    request, policy=policy, dispatcher=dispatcher, store=store, provider=provider,
                    port=port, get_public_url=get_public_url, local_admin_csrf=local_admin_csrf,
                    local_api_token=local_api_token, session_mgr=eff_sess, admin_error=err_msg, http_status=403,
                )
            return JSONResponse(
                {"ok": False, "error": "Forbidden: invalid or missing owner_password.", "detail": err_msg},
                status_code=403,
                headers={"Cache-Control": "no-store"},
            )
        store.record_auth_result(True, bucket_key="local_admin")
        if hasattr(store, "record_global_auth_result"):
            store.record_global_auth_result(True)
        mint_cookie_on_success = True

    app_state = getattr(getattr(request, "app", None), "state", None)
    proc_mgr = getattr(app_state, "proc_mgr", None) if app_state is not None else None
    revocation: Optional[Dict[str, Any]] = None
    prev_packs = list(policy.enabled_packs)

    try:
        if action == "set_tier":
            target_tier = _tier_from_safety_mode(str(data.get("tier") or data.get("permission_tier") or ""))
            policy.persist_changes(tier_key=target_tier)
            if not policy.allow_exec:
                if proc_mgr is not None:
                    proc_mgr.kill_all_active_commands(
                        reason=f"tier_downgrade:{target_tier}",
                        include_persisted_bg=True,
                        prefix_filter=policy.eff_prefix,
                    )
                dispatcher.shutdown_packs(prefix_filter=policy.eff_prefix)
                close_all_browser_sessions(prefix_filter=policy.eff_prefix)
                _emit_kill_signal_resilient(policy.state_root, reason=f"tier_downgrade:{target_tier}", prefix_filter=policy.eff_prefix)
            notice = (
                "已切换至只读浏览模式（即时生效）。"
                if is_l1_emergency_downgrade
                else f"已切换至 {SAFETY_MODE_LABELS_ZH.get(policy.tier_key, '工作区内顺畅开发')}。"
            )
        elif action == "set_workspace":
            if "workspace_roots" in data and isinstance(data["workspace_roots"], list):
                new_roots = [_validate_workspace_candidate(str(x), policy.state_root) for x in data["workspace_roots"] if str(x).strip()]
                if not new_roots:
                    raise ValueError("工作目录列表不能为空。")
            else:
                new_roots = [_validate_workspace_candidate(str(data.get("workspace") or ""), policy.state_root)]
            policy.persist_changes(workspace_roots=new_roots)
            notice = f"已更新开放工作目录：{', '.join(str(p) for p in policy.workspace_roots)}"
        elif action == "add_workspace":
            raw_add = str(data.get("workspace") or data.get("add_workspace") or "")
            cand_p = _validate_workspace_candidate(raw_add, policy.state_root)
            merged_roots = list(policy.workspace_roots)
            if all(os.path.normcase(str(p)) != os.path.normcase(str(cand_p)) for p in merged_roots):
                merged_roots.append(cand_p)
            policy.persist_changes(workspace_roots=merged_roots)
            notice = f"已添加开放工作目录：{cand_p}"
        elif action == "remove_workspace":
            raw_rem = str(data.get("workspace") or data.get("remove_workspace") or "").strip()
            rem_norm = os.path.normcase(str(Path(expand_env_and_tilde(raw_rem)).expanduser().resolve()))
            kept = [p for p in policy.workspace_roots if os.path.normcase(str(p)) != rem_norm]
            if not kept:
                raise ValueError("不能移除最后一个开放工作目录。")
            policy.persist_changes(workspace_roots=kept)
            notice = f"已移除工作目录：{raw_rem}"
        elif action == "set_toolset":
            raw_ts = str(data.get("toolset_profile") or data.get("toolset") or "standard")
            parsed_ts = parse_strict_toolset_profile(raw_ts)
            policy.persist_changes(toolset_profile=parsed_ts)
            notice = "已更新核心工具预设。"
        elif action == "set_enabled_packs":
            raw_pk = data.get("enabled_packs") if "enabled_packs" in data else data.get("enable_pack")
            if isinstance(raw_pk, str):
                raw_pk = raw_pk.replace("desktop", "cua")
            elif isinstance(raw_pk, list):
                raw_pk = ["cua" if str(x).lower() == "desktop" else x for x in raw_pk]
            parsed_pk = parse_pack_spec(raw_pk, strict=True)
            policy.persist_changes(enabled_packs=parsed_pk)
            _shutdown_disabled_packs(dispatcher, prev_packs, policy.enabled_packs, policy.eff_prefix)
            _pk_zh = {"browser": "受管浏览器包", "cua": "桌面窗口操控包"}
            _pk_names = [_pk_zh.get(x, x) for x in policy.enabled_packs]
            notice = f"已更新扩展能力包：{'、'.join(_pk_names) if _pk_names else '全部关闭'}"
        elif action == "set_keep_awake":
            ka = parse_bool_flag(data.get("keep_awake"), default=True)
            policy.persist_changes(keep_awake=ka)
            notice = f"保持电脑唤醒防休眠已{'开启' if ka else '关闭'}。"
        elif action == "set_approval_popups":
            if "annotation_mode" in data and "approval_popups" not in data:
                ann_in = str(data.get("annotation_mode") or "").strip().lower()
                ap = ann_in in ("honest", "confirm", "prompt", "true", "1")
            else:
                ap = parse_bool_flag(data.get("approval_popups"), default=False)
            ann_mode = "honest" if ap else "compat"
            policy.persist_changes(approval_popups=ap)
            _persist_extra_studio_config(policy, annotation_mode=ann_mode)
            notice = f"写/执行宿主确认弹窗已{'开启' if ap else '关闭'}。"
        elif action == "set_options":
            packs: List[str] = []
            if parse_bool_flag(data.get("pack_browser"), default=False):
                packs.append("browser")
            if parse_bool_flag(data.get("pack_cua") if "pack_cua" in data else data.get("pack_desktop"), default=False):
                packs.append("cua")
            ka = parse_bool_flag(data.get("keep_awake"), default=policy.keep_awake)
            ap = parse_bool_flag(data.get("approval_popups"), default=policy.approval_popups)
            policy.persist_changes(enabled_packs=packs, keep_awake=ka, approval_popups=ap)
            _persist_extra_studio_config(policy, annotation_mode="honest" if ap else "compat")
            _shutdown_disabled_packs(dispatcher, prev_packs, policy.enabled_packs, policy.eff_prefix)
            notice = "扩展能力包与安全开关已实时生效。"
        elif action == "revoke_client":
            cid = str(data.get("client_id") or "").strip()
            if not cid:
                raise ValueError("客户端标识不能为空。")
            revocation = store.revoke_client(cid, delete_client=bool(data.get("delete_client")))
            if proc_mgr is not None:
                proc_mgr.kill_all_active_commands(
                    reason=f"revoke_client:{cid}",
                    include_persisted_bg=True,
                    prefix_filter=policy.eff_prefix,
                )
            dispatcher.shutdown_packs(prefix_filter=policy.eff_prefix)
            close_all_browser_sessions(prefix_filter=policy.eff_prefix)
            _emit_kill_signal_resilient(policy.state_root, reason=f"revoke_client:{cid}", prefix_filter=policy.eff_prefix)
            notice = f"已断开客户端 {cid}。"
        elif action == "revoke_all":
            revocation = store.revoke_all_tokens(delete_clients=bool(data.get("delete_clients")))
            if proc_mgr is not None:
                bg_reap = proc_mgr.kill_all_active_commands(
                    reason="revoke_all",
                    include_persisted_bg=True,
                    prefix_filter=policy.eff_prefix,
                )
                if isinstance(revocation, dict):
                    revocation["bg_killed"] = bg_reap.get("bg_killed", [])
            dispatcher.shutdown_packs(prefix_filter=policy.eff_prefix)
            close_all_browser_sessions(prefix_filter=policy.eff_prefix)
            _emit_kill_signal_resilient(policy.state_root, reason="revoke_all", prefix_filter=policy.eff_prefix)
            notice = "已收回全部网页端授权令牌并终止在途任务。"
        else:
            return JSONResponse({"ok": False, "error": f"Unsupported action `{action}`."}, status_code=400)
    except ValueError as exc:
        if wants_html:
            return render_admin_status_html(
                request, policy=policy, dispatcher=dispatcher, store=store, provider=provider,
                port=port, get_public_url=get_public_url, local_admin_csrf=local_admin_csrf,
                local_api_token=local_api_token, session_mgr=eff_sess, admin_error=str(exc), http_status=400,
            )
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    provider.tier_key = policy.tier_key
    provider.tier_label = _norm_tier_label_zh(policy.dynamic_tier_label())
    provider.toolset_profile = policy.toolset_profile
    try:
        ensure_initialized(
            product_root=policy.state_root,
            public_url=get_public_url(),
            port=port,
            cli_state_dir=str(policy.state_root),
            tier_key=policy.tier_key,
            prefix=policy.eff_prefix,
            device_label=policy.device_label,
            toolset_profile=policy.toolset_profile,
            workspace_roots=policy.workspace_roots,
            enabled_packs=policy.enabled_packs,
            keep_awake=policy.keep_awake,
            approval_popups=policy.approval_popups,
        )
    except Exception:
        pass

    if wants_html:
        redir = RedirectResponse("/?" + urlencode({"admin_notice": notice}), status_code=303)
        if mint_cookie_on_success:
            eff_sess.attach_cookie(redir, provider, is_loopback=True)
        return redir

    specs_now = dispatcher.active_tool_specs()
    resp_doc: Dict[str, Any] = {
        "ok": True,
        "action": action,
        "message": notice,
        "permission_tier": policy.tier_key,
        "permission_label": SAFETY_MODE_LABELS_ZH.get(policy.tier_key, "工作区内顺畅开发"),
        "toolset_profile": policy.toolset_profile,
        "workspace": policy.workspace,
        "workspace_roots": [str(p) for p in policy.workspace_roots],
        "enabled_packs": list(policy.enabled_packs),
        "keep_awake": policy.keep_awake,
        "approval_popups": policy.approval_popups,
        "annotation_mode": str(getattr(policy, "annotation_mode", "") or ("honest" if policy.approval_popups else "compat")),
        "tool_count": len(specs_now),
        "exposed_tools": [dispatcher.prefixed_name(sp.base_name) for sp in specs_now],
    }
    if revocation is not None:
        resp_doc["revocation"] = revocation
    resp = JSONResponse(resp_doc, status_code=200, headers={"Cache-Control": "no-store"})
    if mint_cookie_on_success:
        eff_sess.attach_cookie(resp, provider, is_loopback=True)
    return resp


def mount_standalone_status_ui(
    app: Any,
    *,
    policy: LiveRuntimePolicy,
    dispatcher: KernelDispatcher,
    store: OAuthSQLiteStore,
    provider: OAuthProvider,
    port: int,
    get_public_url: Callable[[], str],
    local_api_token: str,
    set_public_url: Optional[Callable[[str], None]] = None,
) -> Tuple[str, List[Any], List[Any]]:
    """Mount Cosmos Studio 1.0 (`/` + `/static/*` + `/api/studio/*`), `/local-admin/permissions`, and `/mcp` guides."""
    try:
        from mcp.server.auth.routes import build_resource_metadata_url
        from pydantic import AnyHttpUrl
    except ImportError:
        build_resource_metadata_url = None  # type: ignore[assignment]
        AnyHttpUrl = str  # type: ignore[assignment,misc]

    from starlette.routing import Route
    from cosmos_mcp.protocol.transport import OriginGuardASGI

    def _res_meta_for(sfx: str) -> str:
        cur_gw = get_current_request_gateway()
        base_u = (
            cur_gw.base_url
            if (cur_gw is not None and not cur_gw.is_loopback and cur_gw.base_url)
            else get_public_url()
        ).rstrip("/")
        ep_sec_meta = load_endpoint_secret(policy.state_root, prefix=policy.eff_prefix)
        if ep_sec_meta:
            base_u = apply_endpoint_secret_to_url(base_u, ep_sec_meta)
        full_u = base_u + sfx
        if build_resource_metadata_url is not None:
            return str(build_resource_metadata_url(AnyHttpUrl(full_u)))
        return _build_resource_metadata_url_fallback(full_u)

    if getattr(provider, "local_port", None) in (None, 0):
        try:
            provider.local_port = int(port)
        except Exception:
            pass
    try:
        provider._state_root = policy.state_root
        provider._eff_prefix = policy.eff_prefix
    except Exception:
        pass

    local_admin_csrf = secrets.token_urlsafe(32)
    unlock_csrf = secrets.token_urlsafe(32)
    session_mgr = _StudioSessionManager()
    origin_guards: List[Any] = []
    issuer_middlewares: List[Any] = []
    orig_root_ep: Optional[Callable[..., Any]] = None
    skills_service = SkillsMcpService(policy)
    if dispatcher.get_spec("skill_hub") is None:
        dispatcher.register_capability_provider(SkillsCapabilityProvider(policy, service=skills_service))

    def _get_proc_mgr() -> Any:
        st = getattr(app, "state", None)
        return getattr(st, "proc_mgr", None) if st is not None else None

    def _check_studio_auth(
        request: Request,
        data: Dict[str, Any],
        *,
        allow_passwordless_loopback: bool = True,
        allow_unlock_csrf: bool = False,
    ) -> Tuple[Optional[JSONResponse], bool]:
        """Return `(error_response_or_None, newly_authenticated_via_password)`."""
        csrf_err = _verify_same_origin_and_csrf(
            request,
            data,
            local_admin_csrf,
            strict_loopback_only=False,
            port=port,
            local_api_token=local_api_token,
            extra_allowed_csrf=unlock_csrf if allow_unlock_csrf else "",
        )
        if csrf_err is not None:
            return csrf_err, False

        if _has_valid_local_bearer_token(request, port, local_api_token):
            return None, False

        is_lb = is_strict_direct_loopback(request, port)
        cookie_tok = request.cookies.get(STUDIO_SESSION_COOKIE, "")
        if session_mgr.verify_token(cookie_tok, provider):
            return None, False

        csrf_cand = str(
            data.get("csrf")
            or data.get("csrf_token")
            or request.headers.get("x-studio-csrf")
            or request.headers.get("x-localpc-csrf")
            or ""
        ).strip()
        used_local_csrf = bool(csrf_cand and hmac.compare_digest(csrf_cand, local_admin_csrf))

        raw_pw = str(
            data.get("owner_password")
            or data.get("password")
            or request.headers.get("x-cosmos-password")
            or ""
        ).strip()

        if allow_passwordless_loopback and is_lb and not raw_pw and used_local_csrf:
            return None, False

        ip_bucket = "local_admin" if is_lb else f"studio_remote:{resolve_request_client_ip(request, getattr(provider, 'tunnel_mode', ''))[0]}"
        locked, wait_sec = store.check_auth_lockout(bucket_key=ip_bucket)
        if locked:
            return JSONResponse(
                {
                    "ok": False,
                    "error": f"管理口令尝试次数过多，请等待 {wait_sec} 秒后重试。",
                    "reason": "ip_password_lockout",
                    "retry_after": wait_sec,
                },
                status_code=429,
                headers={"Cache-Control": "no-store"},
            ), False

        glob_locked, glob_wait = (
            store.check_global_auth_lockout() if hasattr(store, "check_global_auth_lockout") else (False, 0)
        )
        if glob_locked:
            return JSONResponse(
                {
                    "ok": False,
                    "error": f"管理口令尝试次数过多，请等待 {glob_wait} 秒后重试。",
                    "reason": "global_auth_cooldown",
                    "retry_after": glob_wait,
                },
                status_code=429,
                headers={"Cache-Control": "no-store"},
            ), False

        if not raw_pw:
            return JSONResponse(
                {
                    "ok": False,
                    "need_unlock": True,
                    "error": "请先在顶部输入一次管理口令解锁会话（解锁后本窗口所有操作免重复输入）。",
                },
                status_code=403,
                headers={"Cache-Control": "no-store"},
            ), False

        if not _STUDIO_AUTH_SCRYPT_SEMAPHORE.acquire(timeout=1.5):
            return JSONResponse(
                {
                    "ok": False,
                    "error": "认证请求过于密集，请稍后重试。",
                    "reason": "auth_busy",
                    "retry_after": 2,
                },
                status_code=429,
                headers={"Cache-Control": "no-store"},
            ), False
        try:
            glob_locked_recheck, glob_wait_recheck = (
                store.check_global_auth_lockout() if hasattr(store, "check_global_auth_lockout") else (False, 0)
            )
            if glob_locked_recheck:
                return JSONResponse(
                    {
                        "ok": False,
                        "error": f"管理口令尝试次数过多，请等待 {glob_wait_recheck} 秒后重试。",
                        "reason": "global_auth_cooldown",
                        "retry_after": glob_wait_recheck,
                    },
                    status_code=429,
                    headers={"Cache-Control": "no-store"},
                ), False
            pw_ok = provider.authenticate_owner(raw_pw)
        finally:
            _STUDIO_AUTH_SCRYPT_SEMAPHORE.release()

        if not pw_ok:
            now_locked, rem_ip = store.record_auth_result(False, bucket_key=ip_bucket)
            glob_now_locked, rem_glob = (
                store.record_global_auth_result(False, max_failures=8, window_sec=30, lockout_sec=60)
                if hasattr(store, "record_global_auth_result")
                else (False, 0)
            )
            if now_locked or glob_now_locked:
                eff_wait_s = max(int(rem_ip or 0), int(rem_glob or 0), 1)
                return JSONResponse(
                    {
                        "ok": False,
                        "error": f"管理口令尝试次数过多，请等待 {eff_wait_s} 秒后重试。",
                        "reason": "global_auth_cooldown" if glob_now_locked else "ip_password_lockout",
                        "retry_after": eff_wait_s,
                    },
                    status_code=429,
                    headers={"Cache-Control": "no-store"},
                ), False
            return JSONResponse(
                {
                    "ok": False,
                    "need_unlock": True,
                    "error": "请先在顶部输入一次管理口令解锁会话（解锁后本窗口所有操作免重复输入）。",
                },
                status_code=403,
                headers={"Cache-Control": "no-store"},
            ), False

        store.record_auth_result(True, bucket_key=ip_bucket)
        if hasattr(store, "record_global_auth_result"):
            store.record_global_auth_result(True)
        return None, True

    def _json_with_optional_cookie(payload: Dict[str, Any], request: Request, mint_cookie: bool, status_code: int = 200) -> JSONResponse:
        resp = JSONResponse(payload, status_code=status_code, headers={"Cache-Control": "no-store"})
        if mint_cookie:
            is_lb = is_strict_direct_loopback(request, port)
            is_https = get_public_url().startswith("https://")
            session_mgr.attach_cookie(resp, provider, is_loopback=is_lb, is_https=is_https)
        return resp

    def _state_snapshot(request: Request) -> Dict[str, Any]:
        snap = _build_studio_state_payload(
            request,
            policy=policy,
            dispatcher=dispatcher,
            store=store,
            provider=provider,
            proc_mgr=_get_proc_mgr(),
            port=port,
            get_public_url=get_public_url,
            local_admin_csrf=local_admin_csrf,
            local_api_token=local_api_token,
            session_mgr=session_mgr,
            skills_service=skills_service,
            unlock_csrf=unlock_csrf,
        )
        if not is_strict_direct_loopback(request, port):
            conn_d = snap.get("connection")
            if isinstance(conn_d, dict):
                conn_d["connection_password"] = ""
        return snap

    async def standalone_root(request: Request) -> Response:
        policy.refresh()
        accept = (request.headers.get("accept") or "").lower()
        wants_json = request.query_params.get("format") == "json" or (
            "application/json" in accept and "text/html" not in accept
        )
        is_lb = is_strict_direct_loopback(request, port)
        has_studio_cookie = session_mgr.verify_token(request.cookies.get(STUDIO_SESSION_COOKIE, ""), provider)
        if wants_json or (not is_lb and not has_studio_cookie and request.url.path != "/studio"):
            resp = await orig_root_ep(request)  # type: ignore[misc]
            if is_lb and wants_json:
                body = json.loads(resp.body.decode("utf-8"))
                body["local_admin_csrf"] = local_admin_csrf
                body["public_url"] = get_public_url()
                return JSONResponse(body, headers={"Cache-Control": "no-store"})
            return resp
        return render_admin_status_html(
            request,
            policy=policy,
            dispatcher=dispatcher,
            store=store,
            provider=provider,
            proc_mgr=_get_proc_mgr(),
            port=port,
            get_public_url=get_public_url,
            local_admin_csrf=local_admin_csrf,
            local_api_token=local_api_token,
            session_mgr=session_mgr,
            unlock_csrf=unlock_csrf,
        )

    async def studio_page_ep(request: Request) -> Response:
        return render_admin_status_html(
            request,
            policy=policy,
            dispatcher=dispatcher,
            store=store,
            provider=provider,
            proc_mgr=_get_proc_mgr(),
            port=port,
            get_public_url=get_public_url,
            local_admin_csrf=local_admin_csrf,
            local_api_token=local_api_token,
            session_mgr=session_mgr,
            unlock_csrf=unlock_csrf,
        )

    async def tutorials_page_ep(request: Request) -> Response:
        _ = request
        html_doc = read_asset_text("tutorials.html")
        if "/static/security-uninstall.js" not in html_doc and "</body>" in html_doc:
            html_doc = html_doc.replace("</body>", '  <script src="/static/security-uninstall.js" defer></script>\n</body>', 1)
        return HTMLResponse(
            html_doc,
            headers={
                "Cache-Control": "no-store",
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "frame-ancestors 'none'",
            },
        )

    async def favicon_ep(request: Request) -> Response:
        _ = request
        svg_doc = read_asset_text("favicon.svg")
        return Response(svg_doc, media_type="image/svg+xml", headers={"Cache-Control": "public, max-age=3600"})

    _allowed_brand_svg_files = frozenset(
        {
            "webai2pc-icon-v2-light.svg",
            "webai2pc-icon-v2-dark.svg",
            "webai2pc-logo-v2-light.svg",
            "webai2pc-logo-v2-dark.svg",
            "webai2pc-mark-v2-light.svg",
            "webai2pc-mark-v2-dark.svg",
        }
    )

    async def static_brand_asset_ep(request: Request) -> Response:
        brand_file = str(request.path_params.get("brand_file", "") or "").strip()
        if brand_file not in _allowed_brand_svg_files:
            return Response("Not Found", status_code=404)
        svg_doc = read_asset_text(f"brand/{brand_file}")
        return Response(
            svg_doc,
            media_type="image/svg+xml",
            headers={"Cache-Control": "public, max-age=3600", "X-Content-Type-Options": "nosniff"},
        )

    _allowed_showcase_png_files = frozenset(
        {
            "case-01-blackhole.png",
            "case-02-holo-cards.png",
            "case-03-neon-canyon.png",
        }
    )

    async def static_showcase_asset_ep(request: Request) -> Response:
        showcase_file = str(request.path_params.get("showcase_file", "") or "").strip()
        if showcase_file not in _allowed_showcase_png_files:
            return Response("Not Found", status_code=404)
        base_dir = Path(__file__).resolve().parent
        candidates = [
            base_dir / "static" / "showcase" / showcase_file,
            base_dir.parent.parent / "assets" / "tutorials" / showcase_file,
            base_dir.parent.parent.parent / "assets" / "tutorials" / showcase_file,
        ]
        for cand in candidates:
            if cand.is_file():
                return Response(
                    cand.read_bytes(),
                    media_type="image/png",
                    headers={"Cache-Control": "public, max-age=3600", "X-Content-Type-Options": "nosniff"},
                )
        return Response("Not Found", status_code=404)

    _allowed_tutorial_png_files = frozenset(
        {
            "gemini-step1-personal-intelligence.png",
            "gemini-step2-connected-apps.png",
            "gemini-step3-connectors-custom.png",
            "gemini-step4-mcp-server-url.png",
        }
    )

    async def static_tutorial_img_ep(request: Request) -> Response:
        tut_file = str(request.path_params.get("tut_file", "") or "").strip()
        if tut_file not in _allowed_tutorial_png_files:
            return Response("Not Found", status_code=404)
        base_dir = Path(__file__).resolve().parent
        candidates = [
            base_dir.parent.parent / "assets" / "tutorials" / tut_file,
            base_dir.parent.parent.parent / "assets" / "tutorials" / tut_file,
            base_dir / "static" / "showcase" / tut_file,
        ]
        for cand in candidates:
            if cand.is_file():
                return Response(
                    cand.read_bytes(),
                    media_type="image/png",
                    headers={"Cache-Control": "public, max-age=3600", "X-Content-Type-Options": "nosniff"},
                )
        return Response("Not Found", status_code=404)

    async def tutorials_md_ep(request: Request) -> Response:
        _ = request
        from cosmos_mcp.core.tutorials_catalog import render_public_tutorials_markdown

        return Response(
            render_public_tutorials_markdown(),
            status_code=200,
            media_type="text/markdown; charset=utf-8",
            headers={
                "Cache-Control": "public, max-age=300",
                "X-Content-Type-Options": "nosniff",
                "Access-Control-Allow-Origin": "*",
            },
        )

    async def static_asset_ep(request: Request) -> Response:
        asset_name = request.path_params.get("asset_name", "")
        media_map = {
            "studio.css": "text/css; charset=utf-8",
            "themes.css": "text/css; charset=utf-8",
            "studio.js": "application/javascript; charset=utf-8",
            "brand-packs.js": "application/javascript; charset=utf-8",
            "tutorials.js": "application/javascript; charset=utf-8",
            "security-uninstall.js": "application/javascript; charset=utf-8",
            "index.html": "text/html; charset=utf-8",
            "tutorials.html": "text/html; charset=utf-8",
            "favicon.svg": "image/svg+xml",
        }
        if asset_name not in media_map:
            return Response("Not Found", status_code=404)
        content = read_asset_text(asset_name)
        return Response(content, media_type=media_map[asset_name], headers={"Cache-Control": "no-store"})

    async def studio_state_ep(request: Request) -> Response:
        return JSONResponse(_state_snapshot(request), headers={"Cache-Control": "no-store"})

    async def studio_unlock_ep(request: Request) -> Response:
        data, _ = await _parse_request_data(request)
        if data is None:
            return JSONResponse({"ok": False, "error": "请求格式无效。"}, status_code=400)
        err_resp, _ = _check_studio_auth(request, data, allow_unlock_csrf=True)
        if err_resp is not None:
            return err_resp
        is_lb = is_strict_direct_loopback(request, port)
        is_https = get_public_url().startswith("https://")
        if not is_lb:
            cookie_tok = session_mgr.mint_token(provider, is_loopback=False)
            request._cookies = {**dict(request.cookies), STUDIO_SESSION_COOKIE: cookie_tok}
        snap = _state_snapshot(request)
        snap["locked"] = False
        snap["unlocked"] = True
        snap["message"] = "管理会话已解锁，本窗口后续操作无需重复输入口令。" if is_lb else "远程管理会话已解锁。"
        resp = JSONResponse(snap, status_code=200, headers={"Cache-Control": "no-store"})
        session_mgr.attach_cookie(resp, provider, is_loopback=is_lb, is_https=is_https)
        return resp

    async def studio_lock_ep(request: Request) -> Response:
        resp = JSONResponse({"ok": True, "unlocked": False, "message": "已锁定当前管理会话。"}, headers={"Cache-Control": "no-store"})
        session_mgr.clear_cookie(resp)
        return resp

    async def studio_fs_tree_ep(request: Request) -> Response:
        cookie_ok = session_mgr.verify_token(request.cookies.get(STUDIO_SESSION_COOKIE, ""), provider)
        if not cookie_ok:
            err_resp, minted = _check_studio_auth(request, {"csrf": request.headers.get("x-studio-csrf", "")})
            if err_resp is not None:
                return err_resp
        else:
            minted = False
        raw_p = (request.query_params.get("path") or "").strip()
        try:
            tree_doc = _list_fs_tree(raw_p, policy)
            return _json_with_optional_cookie(tree_doc, request, minted)
        except ValueError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400, headers={"Cache-Control": "no-store"})

    async def studio_workspace_ep(request: Request) -> Response:
        data, _ = await _parse_request_data(request)
        if data is None:
            return JSONResponse({"ok": False, "error": "请求格式无效。"}, status_code=400)
        err_resp, minted = _check_studio_auth(request, data)
        if err_resp is not None:
            return err_resp

        sub_act = str(data.get("action") or "add").strip().lower()
        try:
            if sub_act in ("add", "add_workspace"):
                cand = _validate_workspace_candidate(str(data.get("path") or data.get("workspace") or ""), policy.state_root)
                roots = list(policy.workspace_roots)
                if all(os.path.normcase(str(r)) != os.path.normcase(str(cand)) for r in roots):
                    roots.append(cand)
                if parse_bool_flag(data.get("as_primary"), default=False):
                    roots = [cand] + [r for r in roots if os.path.normcase(str(r)) != os.path.normcase(str(cand))]
                ro_roots = list(getattr(policy, "readonly_workspace_roots", ()))
                req_acc = str(data.get("access") or data.get("access_mode") or "").strip().lower()
                is_ro_added = False
                if req_acc == "readonly" and len(roots) > 1 and os.path.normcase(str(roots[0])) != os.path.normcase(str(cand)):
                    if all(os.path.normcase(str(x)) != os.path.normcase(str(cand)) for x in ro_roots):
                        ro_roots.append(cand)
                    is_ro_added = True
                policy.persist_changes(workspace_roots=roots, readonly_workspace_roots=ro_roots)
                _persist_extra_studio_config(policy, readonly_workspace_roots=ro_roots)
                msg = f"已添加只读参考目录：{cand}" if is_ro_added else f"已添加工作目录：{cand}"
            elif sub_act in ("set_access", "set_workspace_access"):
                cand = _validate_workspace_candidate(str(data.get("path") or data.get("workspace") or ""), policy.state_root)
                cand_norm = os.path.normcase(str(cand))
                if not any(os.path.normcase(str(r)) == cand_norm for r in policy.workspace_roots):
                    raise ValueError(f"工作目录未在开放列表中：{cand}")
                acc = str(data.get("access") or data.get("access_mode") or "readwrite").strip().lower()
                if acc not in ("readwrite", "readonly"):
                    raise ValueError("访问权限仅支持 readwrite 或 readonly。")
                cur_roots = list(policy.workspace_roots)
                if os.path.normcase(str(policy.primary_workspace)) == cand_norm:
                    if acc == "readonly":
                        if len(cur_roots) < 2:
                            raise ValueError("请先添加一个子项目目录作为主读写目录，再将外层总目录设为只读父目录。")
                        # Promote the next workspace root to primary read-write so outer parent can become readonly
                        cur_roots = [cur_roots[1], cur_roots[0], *cur_roots[2:]]
                        ro_kept = [
                            r for r in getattr(policy, "readonly_workspace_roots", ())
                            if os.path.normcase(str(r)) != os.path.normcase(str(cur_roots[0]))
                            and os.path.normcase(str(r)) != cand_norm
                        ]
                        ro_kept.append(cand)
                        policy.persist_changes(workspace_roots=cur_roots, readonly_workspace_roots=ro_kept)
                        _persist_extra_studio_config(policy, readonly_workspace_roots=ro_kept)
                        msg = f"已将外层目录设为只读父目录：{cand}（主读写目录已切换为 {cur_roots[0]}）"
                    else:
                        msg = f"主工作目录保持读写访问权限：{cand}"
                else:
                    ro_kept = [
                        r for r in getattr(policy, "readonly_workspace_roots", ())
                        if os.path.normcase(str(r)) != cand_norm
                    ]
                    if acc == "readonly":
                        ro_kept.append(cand)
                    policy.persist_changes(readonly_workspace_roots=ro_kept)
                    _persist_extra_studio_config(policy, readonly_workspace_roots=ro_kept)
                    msg = f"已将工作目录权限更新为{'只读父目录' if acc == 'readonly' else '读写访问'}：{cand}"
            elif sub_act in ("set_readonly_roots", "set_readonly_workspace_roots"):
                raw_ro_list = data.get("readonly_workspace_roots")
                if raw_ro_list is None:
                    raw_ro_list = data.get("readonly_roots") or []
                if not isinstance(raw_ro_list, list):
                    raise ValueError("readonly_workspace_roots 必须是路径列表。")
                ro_validated = [_validate_workspace_candidate(str(x), policy.state_root) for x in raw_ro_list if str(x).strip()]
                policy.persist_changes(readonly_workspace_roots=ro_validated)
                _persist_extra_studio_config(policy, readonly_workspace_roots=list(policy.readonly_workspace_roots))
                msg = "已更新只读目录列表。"
            elif sub_act == "set_primary":
                cand = _validate_workspace_candidate(str(data.get("path") or data.get("workspace") or ""), policy.state_root)
                roots = [cand] + [r for r in policy.workspace_roots if os.path.normcase(str(r)) != os.path.normcase(str(cand))]
                ro_kept = [
                    r for r in getattr(policy, "readonly_workspace_roots", ())
                    if os.path.normcase(str(r)) != os.path.normcase(str(cand))
                ]
                policy.persist_changes(workspace_roots=roots, readonly_workspace_roots=ro_kept)
                _persist_extra_studio_config(policy, readonly_workspace_roots=ro_kept)
                msg = f"已切换主工作目录为：{cand}"
            elif sub_act in ("remove", "remove_workspace"):
                raw_rem = str(data.get("path") or data.get("workspace") or "").strip()
                rem_norm = os.path.normcase(str(Path(expand_env_and_tilde(raw_rem)).expanduser().resolve()))
                kept = [r for r in policy.workspace_roots if os.path.normcase(str(r)) != rem_norm]
                if not kept:
                    raise ValueError("至少需要保留一个开放工作目录。")
                policy.persist_changes(workspace_roots=kept)
                _persist_extra_studio_config(policy, readonly_workspace_roots=list(getattr(policy, "readonly_workspace_roots", ())))
                msg = f"已移除工作目录：{raw_rem}"
            elif sub_act == "mkdir":
                parent_p = _validate_workspace_candidate(str(data.get("parent") or ""), policy.state_root)
                name_s = str(data.get("name") or "").strip().strip("/\\")
                if not name_s or ".." in name_s or any(c in name_s for c in '<>:"|?*'):
                    raise ValueError("请输入合法的新文件夹名称。")
                new_dir = (parent_p / name_s).resolve()
                new_dir.mkdir(parents=True, exist_ok=True)
                return _json_with_optional_cookie(
                    {"ok": True, "created_path": str(new_dir), "message": f"已创建文件夹：{new_dir.name}"},
                    request,
                    minted,
                )
            elif sub_act == "set_python":
                raw_py = str(data.get("python_path") or "").strip().strip("\"'")
                if raw_py:
                    exp_py = Path(expand_env_and_tilde(raw_py)).expanduser().resolve()
                    if exp_py.is_dir():
                        cand_exe = (exp_py / "Scripts" / "python.exe") if sys.platform == "win32" else (exp_py / "bin" / "python")
                        cand_conda = (exp_py / "python.exe") if sys.platform == "win32" else (exp_py / "bin" / "python3")
                        if cand_exe.is_file():
                            exp_py = cand_exe
                        elif cand_conda.is_file():
                            exp_py = cand_conda
                    if not exp_py.is_file():
                        raise ValueError(f"未找到指定的 Python 解释器文件：{raw_py}")
                    clean_py = str(exp_py)
                else:
                    clean_py = ""
                _persist_extra_studio_config(policy, python_path=clean_py)
                msg = f"已保存默认 Python 解释器：{clean_py}" if clean_py else "已恢复自动探测项目与系统 Python 解释器。"
            else:
                return JSONResponse({"ok": False, "error": f"未知工作区操作：{sub_act}"}, status_code=400)
        except ValueError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400, headers={"Cache-Control": "no-store"})

        snap = _state_snapshot(request)
        snap["message"] = msg
        return _json_with_optional_cookie(snap, request, minted)

    async def studio_tools_safety_ep(request: Request) -> Response:
        data, _ = await _parse_request_data(request)
        if data is None:
            return JSONResponse({"ok": False, "error": "请求格式无效。"}, status_code=400)

        req_safety = str(data.get("safety_mode") or data.get("tier") or "").strip().lower()
        err_resp, minted = _check_studio_auth(request, data)
        if err_resp is not None:
            return err_resp

        prev_packs = list(policy.enabled_packs)
        proc_mgr = _get_proc_mgr()
        messages: List[str] = []

        try:
            if req_safety:
                target_tier = _tier_from_safety_mode(req_safety)
                policy.persist_changes(tier_key=target_tier, toolset_profile="standard")
                if not policy.allow_exec:
                    if proc_mgr is not None:
                        proc_mgr.kill_all_active_commands(
                            reason=f"studio_downgrade:{target_tier}",
                            include_persisted_bg=True,
                            prefix_filter=policy.eff_prefix,
                        )
                    dispatcher.shutdown_packs(prefix_filter=policy.eff_prefix)
                    close_all_browser_sessions(prefix_filter=policy.eff_prefix)
                    _emit_kill_signal_resilient(policy.state_root, reason=f"studio_downgrade:{target_tier}", prefix_filter=policy.eff_prefix)
                messages.append(f"安全模式已切换为「{SAFETY_MODE_LABELS_ZH.get(policy.tier_key, '工作区内顺畅开发')}」")

            if "pack_browser" in data or "pack_desktop" in data:
                want_browser = parse_bool_flag(data.get("pack_browser"), default=("browser" in prev_packs))
                want_desktop = parse_bool_flag(data.get("pack_desktop"), default=("cua" in prev_packs or "desktop" in prev_packs))
                new_packs: List[str] = []
                if want_browser:
                    new_packs.append("browser")
                if want_desktop:
                    new_packs.append("cua")
                policy.persist_changes(enabled_packs=new_packs, toolset_profile="standard")
                _shutdown_disabled_packs(dispatcher, prev_packs, policy.enabled_packs, policy.eff_prefix)
                pk_labels = []
                if want_browser:
                    pk_labels.append("受管浏览器包")
                if want_desktop:
                    pk_labels.append("桌面窗口操控包")
                messages.append(f"扩展能力包已更新（{'、'.join(pk_labels) if pk_labels else '已全部关闭'}）")

            if "confirm_popups" in data or "annotation_mode" in data:
                if "confirm_popups" in data:
                    ap = parse_bool_flag(data.get("confirm_popups"), default=False)
                else:
                    ann_raw = str(data.get("annotation_mode") or "").strip().lower()
                    ap = ann_raw in ("honest", "confirm", "prompt", "true", "1")
                ann_mode = "honest" if ap else "compat"
                policy.persist_changes(approval_popups=ap)
                _persist_extra_studio_config(policy, annotation_mode=ann_mode)
                messages.append(f"写/执行确认弹窗已{'开启' if ap else '关闭'}")

            if "scan_host_global_skills" in data:
                want_scan = parse_bool_flag(data.get("scan_host_global_skills"), default=False)
                _persist_extra_studio_config(policy, scan_host_global_skills=want_scan)
                messages.append(f"扫描本机全局技能目录已{'开启' if want_scan else '关闭（仅使用工作区与受管技能库）'}")

            if "tool_prefix" in data:
                raw_tp = str(data.get("tool_prefix") or "").strip()
                clean_tp = normalize_prefix(raw_tp)
                _persist_extra_studio_config(policy, tool_prefix=clean_tp)
                if hasattr(provider, "tool_prefix"):
                    provider.tool_prefix = clean_tp
                messages.append(f"本机工具前缀已更新为「{clean_tp}」")

            if "tray_enabled" in data:
                want_tray = parse_bool_flag(data.get("tray_enabled"), default=True)
                _persist_extra_studio_config(policy, tray_enabled=want_tray)
                messages.append(f"系统托盘常驻图标已{'开启' if want_tray else '关闭'}")
        except ValueError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

        provider.tier_key = policy.tier_key
        provider.tier_label = _norm_tier_label_zh(policy.dynamic_tier_label())
        provider.toolset_profile = policy.toolset_profile
        snap = _state_snapshot(request)
        snap["message"] = "；".join(messages) + "。" if messages else "设置已更新。"
        return _json_with_optional_cookie(snap, request, minted)

    async def studio_connection_ep(request: Request) -> Response:
        data, _ = await _parse_request_data(request)
        if data is None:
            return JSONResponse({"ok": False, "error": "请求格式无效。"}, status_code=400)
        err_resp, minted = _check_studio_auth(request, data)
        if err_resp is not None:
            return err_resp

        sub_act = str(data.get("action") or "save_tunnel").strip().lower()
        msg = "连接设置已保存。"

        def _sync_provider_endpoint_state() -> None:
            st_obj = getattr(app, "state", None)
            sync_box = getattr(st_obj, "gateway_sync_hook_box", None) if st_obj is not None else None
            if isinstance(sync_box, list) and sync_box and callable(sync_box[0]):
                try:
                    sync_box[0](True)
                except Exception:
                    pass
            if provider is not None:
                try:
                    provider.get_effective_trusted_gateways()
                except Exception:
                    pass
                for cb in list(getattr(provider, "_gateway_sync_listeners", ())):
                    try:
                        cb()
                    except Exception:
                        pass

        try:
            if sub_act == "reveal_password":
                if not is_strict_direct_loopback(request, port):
                    return JSONResponse(
                        {"ok": False, "error": "安全限制：仅允许在本机浏览器查看连接口令。"},
                        status_code=403,
                        headers={"Cache-Control": "no-store"},
                    )
                pw_rev = _extract_saved_connection_password(policy.state_root, policy.eff_prefix)
                return _json_with_optional_cookie(
                    {
                        "ok": True,
                        "connection_password": pw_rev,
                        "has_saved_password": bool(pw_rev),
                    },
                    request,
                    minted,
                )
            elif sub_act == "rotate_password":
                had_valid_cookie = session_mgr.verify_token(request.cookies.get(STUDIO_SESSION_COOKIE, ""), provider)
                rot_creds = ensure_initialized(
                    product_root=policy.state_root,
                    cli_state_dir=str(policy.state_root),
                    port=port,
                    tier_key=policy.tier_key,
                    reset_password=True,
                    prefix=policy.eff_prefix,
                    tool_prefix=policy.tool_prefix,
                    device_label=policy.device_label,
                    toolset_profile=policy.toolset_profile,
                    workspace_roots=policy.workspace_roots,
                    readonly_workspace_roots=getattr(policy, "readonly_workspace_roots", ()),
                    enabled_packs=policy.enabled_packs,
                    keep_awake=policy.keep_awake,
                    approval_popups=policy.approval_popups,
                    annotation_mode=policy.annotation_mode,
                    python_path=policy.python_path,
                    scan_host_global_skills=getattr(policy, "scan_host_global_skills", False),
                    tray_enabled=getattr(policy, "tray_enabled", True),
                )
                if provider is not None:
                    provider.password_hash = str(rot_creds["password_hash"])
                    provider.salt = str(rot_creds["salt"])
                policy.refresh(force=True)
                want_rev_pw = parse_bool_flag(data.get("revoke_sessions"), default=False)
                if want_rev_pw:
                    store.revoke_all_tokens(delete_clients=False)
                    pm = _get_proc_mgr()
                    if pm is not None:
                        pm.kill_all_active_commands(
                            reason="studio_rotate_password_revoke",
                            include_persisted_bg=True,
                            prefix_filter=policy.eff_prefix,
                        )
                    dispatcher.shutdown_packs(prefix_filter=policy.eff_prefix)
                    close_all_browser_sessions(prefix_filter=policy.eff_prefix)
                    _emit_kill_signal_resilient(
                        policy.state_root,
                        reason="studio_rotate_password_revoke",
                        prefix_filter=policy.eff_prefix,
                    )
                is_lb_rot = is_strict_direct_loopback(request, port)
                if not is_lb_rot and (minted or had_valid_cookie):
                    new_sid_tok = session_mgr.mint_token(provider, is_loopback=False)
                    request._cookies = {**dict(request.cookies), STUDIO_SESSION_COOKIE: new_sid_tok}
                    minted = True
                msg = (
                    "已生成全新高熵连接口令并吊销全部旧授权会话。"
                    if want_rev_pw
                    else "已生成全新高熵连接口令（旧口令已失效）。"
                )
            elif sub_act == "wipe_plaintext_password":
                wipe_res = wipe_plaintext_connection_password(policy.state_root, prefix=policy.eff_prefix)
                if not wipe_res.get("ok"):
                    raise ValueError(str(wipe_res.get("error") or "擦除明文口令文件失败。"))
                snap = _state_snapshot(request)
                snap["wiped_files"] = wipe_res.get("wiped_files", [])
                snap["message"] = "已擦除本地文本文件中的明文口令（口令已受本机加密保险箱保护）。"
                return _json_with_optional_cookie(snap, request, minted)
            elif sub_act == "rotate_endpoint_secret":
                prev_sec = load_endpoint_secret(policy.state_root, prefix=policy.eff_prefix)
                new_sec = save_endpoint_secret(
                    policy.state_root,
                    generate_endpoint_secret(24),
                    prefix=policy.eff_prefix,
                )
                saved_extra_rot = _read_saved_extra_cfg(policy)
                cur_slots_rot, _, _ = _normalize_studio_gateways_cfg(policy, saved_extra_rot)
                raw_wd_rot = str(
                    cur_slots_rot["workers_dev"].get("public_url")
                    or saved_extra_rot.get("workers_dev_url")
                    or ""
                ).strip()
                if raw_wd_rot:
                    next_wd_rot = apply_endpoint_secret_to_url(raw_wd_rot, new_sec, previous_secret=prev_sec)
                    _persist_extra_studio_config(policy, workers_dev_url=next_wd_rot)
                    _update_studio_gateway_slot(
                        policy,
                        "workers_dev",
                        public_url=next_wd_rot,
                        port=port,
                        set_public_url=set_public_url,
                    )
                want_rev_ep = parse_bool_flag(data.get("revoke_sessions"), default=False)
                if hasattr(store, "revoke_oneclick_tokens"):
                    store.revoke_oneclick_tokens()
                if want_rev_ep:
                    store.revoke_all_tokens(delete_clients=False)
                    if provider is not None and hasattr(provider, "allowed_resources"):
                        stale_res = {
                            r for r in list(provider.allowed_resources)
                            if (prev_sec and f"/u/{prev_sec}" in r.lower())
                        }
                        provider.allowed_resources.difference_update(stale_res)
                        st_obj = getattr(app, "state", None)
                        bb_obj = getattr(st_obj, "bearer_backend", None) if st_obj is not None else None
                        if bb_obj is not None and hasattr(bb_obj, "allowed_resources"):
                            bb_obj.allowed_resources.difference_update(stale_res)
                    pm = _get_proc_mgr()
                    if pm is not None:
                        pm.kill_all_active_commands(
                            reason="studio_rotate_endpoint_secret_revoke",
                            include_persisted_bg=True,
                            prefix_filter=policy.eff_prefix,
                        )
                    dispatcher.shutdown_packs(prefix_filter=policy.eff_prefix)
                    close_all_browser_sessions(prefix_filter=policy.eff_prefix)
                    _emit_kill_signal_resilient(
                        policy.state_root,
                        reason="studio_rotate_endpoint_secret_revoke",
                        prefix_filter=policy.eff_prefix,
                    )
                policy.refresh(force=True)
                _sync_provider_endpoint_state()
                msg = (
                    "已轮换私密连接路径并吊销旧授权令牌。"
                    if want_rev_ep
                    else "已启用/轮换 24 位私密连接路径（裸路径已隐身返回 404，已连接会话保持平滑不断线）。"
                )
            elif sub_act == "disable_endpoint_secret":
                prev_sec_dis = load_endpoint_secret(policy.state_root, prefix=policy.eff_prefix)
                clear_endpoint_secret(policy.state_root, prefix=policy.eff_prefix)
                if prev_sec_dis:
                    saved_extra_dis = _read_saved_extra_cfg(policy)
                    cur_slots_dis, _, _ = _normalize_studio_gateways_cfg(policy, saved_extra_dis)
                    raw_wd_dis = str(
                        cur_slots_dis["workers_dev"].get("public_url")
                        or saved_extra_dis.get("workers_dev_url")
                        or ""
                    ).strip()
                    if raw_wd_dis and f"/u/{prev_sec_dis}" in raw_wd_dis.lower():
                        clean_wd_dis = strip_endpoint_secret_from_url(raw_wd_dis, old_secret=prev_sec_dis)
                        _persist_extra_studio_config(policy, workers_dev_url=clean_wd_dis)
                        _update_studio_gateway_slot(
                            policy,
                            "workers_dev",
                            public_url=clean_wd_dis,
                            port=port,
                            set_public_url=set_public_url,
                        )
                    if provider is not None and hasattr(provider, "allowed_resources"):
                        stale_dis = {r for r in list(provider.allowed_resources) if f"/u/{prev_sec_dis}" in r.lower()}
                        provider.allowed_resources.difference_update(stale_dis)
                policy.refresh(force=True)
                _sync_provider_endpoint_state()
                msg = "已关闭私密连接路径并恢复默认短路径 /mcp。"
            elif sub_act in ("revoke_client", "disconnect_client"):
                cid = str(data.get("client_id") or "").strip()
                if not cid:
                    raise ValueError("客户端标识不能为空。")
                rev_single = store.revoke_client(cid, delete_client=bool(data.get("delete_client")))
                snap = _state_snapshot(request)
                snap["revocation"] = rev_single
                snap["message"] = f"已断开客户端 {cid} 的连接授权。"
                return _json_with_optional_cookie(snap, request, minted)
            elif sub_act == "revoke_sessions":
                store.revoke_all_tokens(delete_clients=False)
                pm = _get_proc_mgr()
                if pm is not None:
                    pm.kill_all_active_commands(reason="studio_revoke_all", include_persisted_bg=True, prefix_filter=policy.eff_prefix)
                dispatcher.shutdown_packs(prefix_filter=policy.eff_prefix)
                close_all_browser_sessions(prefix_filter=policy.eff_prefix)
                _emit_kill_signal_resilient(policy.state_root, reason="studio_revoke_all", prefix_filter=policy.eff_prefix)
                msg = "已断开全部网页端授权会话并终止在途任务。"
            elif sub_act == "set_runtime_prefs":
                if "keep_awake" in data:
                    ka = parse_bool_flag(data.get("keep_awake"), default=True)
                    policy.persist_changes(keep_awake=ka)
                if "tray_enabled" in data:
                    want_tray = parse_bool_flag(data.get("tray_enabled"), default=True)
                    _persist_extra_studio_config(policy, tray_enabled=want_tray)
                if "scan_host_global_skills" in data:
                    want_scan = parse_bool_flag(data.get("scan_host_global_skills"), default=False)
                    _persist_extra_studio_config(policy, scan_host_global_skills=want_scan)
                if "tool_prefix" in data:
                    clean_tp = normalize_prefix(str(data.get("tool_prefix") or "").strip())
                    _persist_extra_studio_config(policy, tool_prefix=clean_tp)
                    if hasattr(provider, "tool_prefix"):
                        provider.tool_prefix = clean_tp
                if "autostart" in data:
                    want_as = parse_bool_flag(data.get("autostart"), default=False)
                    if want_as:
                        py_found = find_suitable_python()
                        py_exe = py_found[0] if py_found else sys.executable
                        cur_tm = str(_read_saved_extra_cfg(policy).get("tunnel_mode") or "public_gateway")
                        enable_autostart(
                            python_exe=py_exe,
                            state_root=policy.state_root,
                            prefix=policy.eff_prefix,
                            mode=cur_tm,
                            port=port,
                        )
                    else:
                        disable_autostart(state_root=policy.state_root, prefix=policy.eff_prefix)
                msg = "系统运行与常驻开关已更新。"
            elif sub_act == "select_copy_gateway":
                gw_id = str(data.get("gateway_id") or "").strip().lower()
                if gw_id not in STUDIO_GATEWAY_IDS:
                    raise ValueError(f"不支持的网关槽位：{gw_id}")
                cur_slots, _, _ = _normalize_studio_gateways_cfg(policy, _read_saved_extra_cfg(policy))
                if not cur_slots[gw_id]["enabled"]:
                    raise ValueError(f"「{GATEWAY_SLOT_LABELS_ZH[gw_id]}」尚未开启，请先打开对应卡片右上角开关。")
                _update_studio_gateway_slot(
                    policy,
                    gw_id,
                    select=True,
                    user_pin=gw_id,
                    port=port,
                    set_public_url=set_public_url,
                )
                policy.refresh(force=True)
                msg = f"顶部复制栏已切换为「{GATEWAY_SLOT_LABELS_ZH[gw_id]}」。"
            elif sub_act == "toggle_gateway":
                gw_id = str(data.get("gateway_id") or "").strip().lower()
                if gw_id not in STUDIO_GATEWAY_IDS:
                    raise ValueError(f"不支持的网关槽位：{gw_id}")
                saved_extra = _read_saved_extra_cfg(policy)
                cur_slots, _, _ = _normalize_studio_gateways_cfg(policy, saved_extra)
                want_en = (
                    parse_bool_flag(data.get("enabled"), default=True)
                    if "enabled" in data
                    else (not bool(cur_slots[gw_id]["enabled"]))
                )
                other_en_cnt = sum(1 for g in STUDIO_GATEWAY_IDS if g != gw_id and cur_slots[g]["enabled"])
                req_sub = str(data.get("submode") or cur_slots[gw_id].get("submode") or "").strip().lower()

                if want_en:
                    eff_slot_pub: Optional[str] = None
                    extra_fields: Dict[str, Any] = {}
                    if gw_id == "instant":
                        if req_sub not in ("public_gateway", "cloudflare"):
                            req_sub = "public_gateway"
                        if req_sub == "public_gateway":
                            seed_info = ensure_master_seed_identity(policy.state_root, prefix=policy.eff_prefix)
                            gw_base = str(saved_extra.get("public_gateway_base") or DEFAULT_PUBLIC_GATEWAY_BASE or "").strip().rstrip("/")
                            gw_online = _probe_public_gateway_cached(gw_base)
                            if gw_online and gw_base.startswith("https://"):
                                eff_slot_pub = f"{gw_base}/u/{seed_info['node_id']}"
                                _safe_hot_refresh_gateway_url(
                                    policy.state_root,
                                    eff_slot_pub,
                                    port=port,
                                    prefix=policy.eff_prefix,
                                    tunnel_mode="public_gateway",
                                    gateway_id="instant",
                                    other_enabled_count=other_en_cnt,
                                )
                            _persist_extra_studio_config(
                                policy,
                                prefer_quick_tunnel=False,
                                srvus_retry_requested_at=round(time.time(), 3),
                            )
                    elif gw_id == "workers_dev":
                        req_sub = "workers_dev"
                        wd_cand = _clean_https_candidate(
                            data.get("public_url")
                            or data.get("workers_dev_url")
                            or cur_slots["workers_dev"].get("public_url")
                            or saved_extra.get("workers_dev_url")
                        )
                        if not wd_cand:
                            raise ValueError("尚未部署 Cloudflare 固定网关，请先填写一次 API 令牌点击「一键部署并开启」。")
                        eff_slot_pub = wd_cand
                        _safe_hot_refresh_gateway_url(
                            policy.state_root,
                            eff_slot_pub,
                            port=port,
                            prefix=policy.eff_prefix,
                            tunnel_mode="workers_dev",
                            gateway_id="workers_dev",
                            other_enabled_count=other_en_cnt,
                        )
                    elif gw_id == "self_hosted":
                        if req_sub == "reverse_proxy":
                            req_sub = "custom"
                        if req_sub not in ("vps_hub", "vps", "cloudflare_token", "custom"):
                            req_sub = str(cur_slots["self_hosted"].get("submode") or "vps_hub")
                        sh_cand = _clean_https_candidate(
                            data.get("public_url")
                            or cur_slots["self_hosted"].get("public_url")
                            or saved_extra.get("vps_hub_url")
                        )
                        has_tok = bool(load_tunnel_token(policy.state_root, prefix=policy.eff_prefix))
                        has_ssh = bool(cur_slots["self_hosted"].get("vps_ssh_target") or saved_extra.get("vps_ssh"))
                        if not sh_cand and not has_tok and not has_ssh:
                            raise ValueError("请先在第 3 类卡片中部署 24h 主站或填写自有固定域名后再开启。")
                        if sh_cand:
                            eff_slot_pub = sh_cand
                            _safe_hot_refresh_gateway_url(
                                policy.state_root,
                                eff_slot_pub,
                                port=port,
                                prefix=policy.eff_prefix,
                                tunnel_mode=req_sub,
                                gateway_id="self_hosted",
                                other_enabled_count=other_en_cnt,
                            )

                    _update_studio_gateway_slot(
                        policy,
                        gw_id,
                        enabled=True,
                        submode=req_sub,
                        public_url=eff_slot_pub,
                        select=True,
                        extra_slot_fields=extra_fields or None,
                        port=port,
                        set_public_url=set_public_url,
                    )
                    msg = f"已开启「{GATEWAY_SLOT_LABELS_ZH[gw_id]}」（不影响其他已开启网关）。"
                else:
                    _update_studio_gateway_slot(
                        policy,
                        gw_id,
                        enabled=False,
                        port=port,
                        set_public_url=set_public_url,
                    )
                    msg = (
                        f"已关闭「{GATEWAY_SLOT_LABELS_ZH[gw_id]}」。"
                        if other_en_cnt > 0
                        else f"已关闭「{GATEWAY_SLOT_LABELS_ZH[gw_id]}」（当前仅保留本机回环访问）。"
                    )
                policy.refresh(force=True)
            elif sub_act == "save_gateway_config":
                gw_id = str(data.get("gateway_id") or "").strip().lower()
                raw_sub = str(data.get("submode") or data.get("tunnel_mode") or "").strip().lower()
                if raw_sub == "reverse_proxy":
                    raw_sub = "custom"
                if gw_id not in STUDIO_GATEWAY_IDS:
                    gw_id, mapped_sub = _slot_and_submode_for_tunnel_mode(raw_sub or "public_gateway")
                    if not gw_id:
                        gw_id = "instant"
                    if not raw_sub:
                        raw_sub = mapped_sub
                saved_extra = _read_saved_extra_cfg(policy)
                cur_slots, _, _ = _normalize_studio_gateways_cfg(policy, saved_extra)
                other_en_cnt = sum(1 for g in STUDIO_GATEWAY_IDS if g != gw_id and cur_slots[g]["enabled"])
                want_en = parse_bool_flag(data.get("enabled"), default=True) if "enabled" in data else True
                raw_pub = str(data.get("public_url") or data.get("public_base") or "").strip().rstrip("/")
                raw_tok = str(data.get("tunnel_token") or "").strip()

                if gw_id == "instant":
                    eff_sub = raw_sub if raw_sub in ("public_gateway", "cloudflare") else "public_gateway"
                    if eff_sub == "cloudflare":
                        cur_inst_pub = str(cur_slots["instant"].get("public_url") or "").strip()
                        kept_q = cur_inst_pub if ".trycloudflare.com" in cur_inst_pub.lower() else ""
                        _persist_extra_studio_config(policy, prefer_quick_tunnel=True)
                        _update_studio_gateway_slot(
                            policy,
                            "instant",
                            enabled=want_en,
                            submode="cloudflare",
                            public_url=kept_q,
                            select=True,
                            port=port,
                            set_public_url=set_public_url,
                        )
                        msg = f"第 1 类网关已切换为临时快速通道（{QUICK_TUNNEL_REBOOT_NOTICE_ZH}）"
                    else:
                        seed_info = ensure_master_seed_identity(policy.state_root, prefix=policy.eff_prefix)
                        gw_base = str(saved_extra.get("public_gateway_base") or DEFAULT_PUBLIC_GATEWAY_BASE or "").strip().rstrip("/")
                        gw_online = _probe_public_gateway_cached(gw_base)
                        eff_gw_pub = f"{gw_base}/u/{seed_info['node_id']}" if gw_online and gw_base.startswith("https://") else ""
                        cur_inst_pub = str(cur_slots["instant"].get("public_url") or "").strip()
                        next_inst_pub = eff_gw_pub or (cur_inst_pub if cur_inst_pub.lower().endswith(".srv.us") else "")
                        if eff_gw_pub:
                            _safe_hot_refresh_gateway_url(
                                policy.state_root,
                                eff_gw_pub,
                                port=port,
                                prefix=policy.eff_prefix,
                                tunnel_mode="public_gateway",
                                gateway_id="instant",
                                other_enabled_count=other_en_cnt,
                            )
                        _persist_extra_studio_config(
                            policy,
                            prefer_quick_tunnel=False,
                            srvus_retry_requested_at=round(time.time(), 3) if bool(data.get("retry_fixed")) else None,
                        )
                        _update_studio_gateway_slot(
                            policy,
                            "instant",
                            enabled=want_en,
                            submode="public_gateway",
                            public_url=next_inst_pub,
                            select=True,
                            port=port,
                            set_public_url=set_public_url,
                        )
                        msg = "第 1 类网关已开启免登录固定网址模式。"
                elif gw_id == "workers_dev":
                    raw_wd_dom = str(
                        data.get("workers_dev_custom_domain")
                        if "workers_dev_custom_domain" in data
                        else (saved_extra.get("workers_dev_custom_domain") or "")
                    ).strip()
                    cand_wd = _clean_https_candidate(
                        raw_pub or data.get("workers_dev_url") or cur_slots["workers_dev"].get("public_url") or saved_extra.get("workers_dev_url")
                    )
                    if cand_wd:
                        _safe_hot_refresh_gateway_url(
                            policy.state_root,
                            cand_wd,
                            port=port,
                            prefix=policy.eff_prefix,
                            tunnel_mode="workers_dev",
                            gateway_id="workers_dev",
                            other_enabled_count=other_en_cnt,
                        )
                    _persist_extra_studio_config(
                        policy,
                        workers_dev_url=cand_wd or None,
                        workers_dev_custom_domain=raw_wd_dom,
                    )
                    _update_studio_gateway_slot(
                        policy,
                        "workers_dev",
                        enabled=want_en,
                        submode="workers_dev",
                        public_url=cand_wd,
                        select=True,
                        extra_slot_fields={"custom_domain": raw_wd_dom},
                        port=port,
                        set_public_url=set_public_url,
                    )
                    msg = f"已更新并开启 Cloudflare 固定网关：{cand_wd}" if cand_wd else "已更新 Cloudflare 固定网关配置。"
                else:
                    eff_sub = raw_sub if raw_sub in ("vps_hub", "vps", "cloudflare_token", "custom") else "custom"
                    slot_extra: Dict[str, Any] = {}
                    if eff_sub == "vps":
                        raw_vps_ssh = str(data.get("vps_ssh") or saved_extra.get("vps_ssh") or "").strip()
                        if not raw_vps_ssh:
                            raise ValueError("请填写自有云服务器 SSH 地址（例如 root@vps.example.com）。")
                        raw_rport = data.get("vps_remote_port")
                        if raw_rport is None or str(raw_rport).strip() == "":
                            raw_rport = saved_extra.get("vps_remote_port") or 18096
                        try:
                            eff_vps_port = int(str(raw_rport).strip())
                        except (TypeError, ValueError):
                            raise ValueError("云服务器远端转发端口必须是 1~65535 的整数。")
                        if not (1 <= eff_vps_port <= 65535):
                            raise ValueError("云服务器远端转发端口必须在 1~65535 范围内。")
                        if raw_pub and not raw_pub.startswith(("https://", "http://")):
                            raw_pub = "https://" + raw_pub
                        eff_sh_pub = _clean_https_candidate(raw_pub or cur_slots["self_hosted"].get("public_url"))
                        if eff_sh_pub:
                            _safe_hot_refresh_gateway_url(
                                policy.state_root,
                                eff_sh_pub,
                                port=port,
                                prefix=policy.eff_prefix,
                                tunnel_mode="vps",
                                gateway_id="self_hosted",
                                other_enabled_count=other_en_cnt,
                            )
                        _persist_extra_studio_config(policy, vps_ssh=raw_vps_ssh, vps_remote_port=eff_vps_port)
                        slot_extra = {"vps_ssh_target": raw_vps_ssh, "vps_remote_port": eff_vps_port}
                        msg = (
                            f"已保存并开启自有云服务器 SSH 隧道（{raw_vps_ssh} -> 端口 {eff_vps_port}"
                            + (f"，公网地址 {eff_sh_pub}）" if eff_sh_pub else "）")
                        )
                    elif eff_sub == "cloudflare_token":
                        if raw_tok:
                            save_tunnel_token(policy.state_root, raw_tok, prefix=policy.eff_prefix)
                        elif not load_tunnel_token(policy.state_root, prefix=policy.eff_prefix):
                            raise ValueError("请粘贴 Cloudflare Named Tunnel 固定 Token。")
                        if raw_pub and not raw_pub.startswith(("https://", "http://")):
                            raw_pub = "https://" + raw_pub
                        eff_sh_pub = _clean_https_candidate(raw_pub or cur_slots["self_hosted"].get("public_url"))
                        if eff_sh_pub:
                            _safe_hot_refresh_gateway_url(
                                policy.state_root,
                                eff_sh_pub,
                                port=port,
                                prefix=policy.eff_prefix,
                                tunnel_mode="cloudflare_token",
                                gateway_id="self_hosted",
                                other_enabled_count=other_en_cnt,
                            )
                        slot_extra = {"custom_domain": eff_sh_pub}
                        msg = "已保存并开启 Cloudflare Named Tunnel 固定域名通道。"
                    elif eff_sub == "vps_hub":
                        if raw_pub and not raw_pub.startswith(("https://", "http://")):
                            raw_pub = "https://" + raw_pub
                        eff_sh_pub = _clean_https_candidate(raw_pub or saved_extra.get("vps_hub_url") or cur_slots["self_hosted"].get("public_url"))
                        if eff_sh_pub:
                            _safe_hot_refresh_gateway_url(
                                policy.state_root,
                                eff_sh_pub,
                                port=port,
                                prefix=policy.eff_prefix,
                                tunnel_mode="vps_hub",
                                gateway_id="self_hosted",
                                other_enabled_count=other_en_cnt,
                            )
                            _persist_extra_studio_config(policy, vps_hub_url=eff_sh_pub)
                        msg = f"已保存并开启自有服务器 24h 主站：{eff_sh_pub}" if eff_sh_pub else "已开启自有服务器 24h 主站网关。"
                    else:
                        if not raw_pub:
                            raise ValueError("请填写自有反代 HTTPS 域名地址（如 https://mcp.example.com）。")
                        if not raw_pub.startswith(("https://", "http://")):
                            raw_pub = "https://" + raw_pub
                        eff_sh_pub = _clean_https_candidate(raw_pub)
                        if not eff_sh_pub:
                            raise ValueError("自有固定域名必须为公网 https:// 地址。")
                        _safe_hot_refresh_gateway_url(
                            policy.state_root,
                            eff_sh_pub,
                            port=port,
                            prefix=policy.eff_prefix,
                            tunnel_mode="custom",
                            gateway_id="self_hosted",
                            other_enabled_count=other_en_cnt,
                        )
                        slot_extra = {"custom_domain": eff_sh_pub}
                        msg = f"已保存并开启自有固定域名：{eff_sh_pub}"

                    _update_studio_gateway_slot(
                        policy,
                        "self_hosted",
                        enabled=want_en,
                        submode=eff_sub,
                        public_url=eff_sh_pub,
                        select=True,
                        extra_slot_fields=slot_extra or None,
                        port=port,
                        set_public_url=set_public_url,
                    )
                policy.refresh(force=True)
            else:
                new_mode = str(data.get("tunnel_mode") or "public_gateway").strip().lower()
                if new_mode == "reverse_proxy":
                    new_mode = "custom"
                if new_mode not in ALL_SUPPORTED_TUNNEL_MODES:
                    raise ValueError(f"不支持的连接通道类型：{new_mode}")
                raw_tok = str(data.get("tunnel_token") or "").strip()
                raw_pub = str(data.get("public_url") or "").strip().rstrip("/")

                def _clear_transient_public_url(target_mode: str) -> None:
                    if callable(set_public_url):
                        set_public_url(f"http://127.0.0.1:{port}")
                    d_status_file = policy.state_root / "state" / (
                        f"daemon_status_{policy.eff_prefix}.json" if policy.eff_prefix != "pc" else "daemon_status.json"
                    )
                    if d_status_file.is_file():
                        try:
                            d_doc = json.loads(d_status_file.read_text(encoding="utf-8-sig"))
                            if isinstance(d_doc, dict) and d_doc.get("supervisor_pid"):
                                d_doc["mode"] = target_mode
                                d_doc["effective_tunnel_mode"] = target_mode
                                d_doc["public_url"] = ""
                                d_doc["public_base_url"] = ""
                                d_doc["mcp_url"] = ""
                                d_doc["readonly_mcp_url"] = ""
                                d_doc["tunnel_ready"] = False
                                d_doc["srvus_fixed_active"] = False
                                d_doc["instant_fallback_active"] = bool(target_mode == "cloudflare")
                                d_doc["tunnel_updated_at"] = round(time.time(), 3)
                                atomic_write_json(d_status_file, d_doc)
                        except Exception:
                            pass

                if new_mode == "public_gateway":
                    saved_extra = _read_saved_extra_cfg(policy)
                    seed_info = ensure_master_seed_identity(policy.state_root, prefix=policy.eff_prefix)
                    gw_base = str(saved_extra.get("public_gateway_base") or DEFAULT_PUBLIC_GATEWAY_BASE or "").strip().rstrip("/")
                    gw_online = _probe_public_gateway_cached(gw_base)
                    eff_gw_pub = f"{gw_base}/u/{seed_info['node_id']}" if gw_online and gw_base.startswith("https://") else ""
                    cur_saved_pub = str(saved_extra.get("public_base") or "").strip().rstrip("/")
                    retry_fixed_req = bool(data.get("retry_fixed"))
                    is_cur_srvus = cur_saved_pub.lower().endswith(".srv.us")
                    if eff_gw_pub:
                        hot_refresh_public_url(
                            policy.state_root,
                            eff_gw_pub,
                            port=port,
                            prefix=policy.eff_prefix,
                            tunnel_mode="public_gateway",
                        )
                        next_pub = eff_gw_pub
                    else:
                        next_pub = cur_saved_pub if is_cur_srvus else ""
                        if not next_pub:
                            _clear_transient_public_url("public_gateway")
                    _persist_extra_studio_config(
                        policy,
                        tunnel_mode="public_gateway",
                        public_url=next_pub,
                        prefer_quick_tunnel=False,
                        srvus_retry_requested_at=round(time.time(), 3) if (retry_fixed_req and not is_cur_srvus) else None,
                    )
                    _update_studio_gateway_slot(
                        policy,
                        "instant",
                        enabled=True,
                        submode="public_gateway",
                        public_url=next_pub,
                        select=True,
                        exclusive=True,
                        port=port,
                        set_public_url=set_public_url,
                    )
                    msg = (
                        "已切换为一键上手公共固定网关。"
                        if gw_online
                        else "已切换为一键上手连接模式（优先建立免登录固定网址，不可达时自动切换临时快速通道）。"
                    )
                elif new_mode == "workers_dev":
                    saved_extra = _read_saved_extra_cfg(policy)
                    raw_wd_dom = str(
                        data.get("workers_dev_custom_domain")
                        if "workers_dev_custom_domain" in data
                        else (saved_extra.get("workers_dev_custom_domain") or "")
                    ).strip()
                    eff_wd_pub = str(
                        raw_pub
                        or data.get("workers_dev_url")
                        or saved_extra.get("workers_dev_url")
                        or (saved_extra.get("public_base") if saved_extra.get("tunnel_mode") == "workers_dev" else "")
                        or ""
                    ).strip().rstrip("/")
                    if eff_wd_pub and not eff_wd_pub.startswith(("https://", "http://")):
                        eff_wd_pub = "https://" + eff_wd_pub
                    if eff_wd_pub:
                        hot_refresh_public_url(
                            policy.state_root,
                            eff_wd_pub,
                            port=port,
                            prefix=policy.eff_prefix,
                            tunnel_mode="workers_dev",
                        )
                    else:
                        _clear_transient_public_url("workers_dev")
                    _persist_extra_studio_config(
                        policy,
                        tunnel_mode="workers_dev",
                        public_url=eff_wd_pub or "",
                        workers_dev_url=eff_wd_pub or None,
                        workers_dev_custom_domain=raw_wd_dom,
                    )
                    _update_studio_gateway_slot(
                        policy,
                        "workers_dev",
                        enabled=True,
                        submode="workers_dev",
                        public_url=eff_wd_pub or "",
                        select=True,
                        exclusive=True,
                        extra_slot_fields={"custom_domain": raw_wd_dom},
                        port=port,
                        set_public_url=set_public_url,
                    )
                    msg = f"已切换至 Cloudflare 固定网关：{eff_wd_pub}" if eff_wd_pub else "已切换至 Cloudflare 固定网关模式。"
                elif new_mode == "vps_hub":
                    saved_extra = _read_saved_extra_cfg(policy)
                    eff_hub_pub = str(
                        raw_pub
                        or data.get("vps_hub_url")
                        or saved_extra.get("vps_hub_url")
                        or (saved_extra.get("public_base") if saved_extra.get("tunnel_mode") == "vps_hub" else "")
                        or ""
                    ).strip().rstrip("/")
                    if eff_hub_pub and not eff_hub_pub.startswith(("https://", "http://")):
                        eff_hub_pub = "https://" + eff_hub_pub
                    if eff_hub_pub:
                        hot_refresh_public_url(
                            policy.state_root,
                            eff_hub_pub,
                            port=port,
                            prefix=policy.eff_prefix,
                            tunnel_mode="vps_hub",
                        )
                    else:
                        _clear_transient_public_url("vps_hub")
                    _persist_extra_studio_config(
                        policy,
                        tunnel_mode="vps_hub",
                        public_url=eff_hub_pub or "",
                        vps_hub_url=eff_hub_pub or None,
                    )
                    _update_studio_gateway_slot(
                        policy,
                        "self_hosted",
                        enabled=True,
                        submode="vps_hub",
                        public_url=eff_hub_pub or "",
                        select=True,
                        exclusive=True,
                        port=port,
                        set_public_url=set_public_url,
                    )
                    msg = f"已切换至自有服务器 24h 主站：{eff_hub_pub}" if eff_hub_pub else "已切换至自有服务器 24h 主站模式。"
                elif new_mode == "cloudflare_token":
                    if raw_tok:
                        save_tunnel_token(policy.state_root, raw_tok, prefix=policy.eff_prefix)
                    elif not load_tunnel_token(policy.state_root, prefix=policy.eff_prefix):
                        raise ValueError("请粘贴 Cloudflare Named Tunnel 固定 Token。")
                    if raw_pub and not raw_pub.startswith(("https://", "http://")):
                        raw_pub = "https://" + raw_pub
                    saved_cf_extra = _read_saved_extra_cfg(policy)
                    eff_pub_save = raw_pub or str(
                        saved_cf_extra.get("public_base") if saved_cf_extra.get("tunnel_mode") == "cloudflare_token" else ""
                    )
                    if eff_pub_save:
                        hot_refresh_public_url(policy.state_root, eff_pub_save, port=port, prefix=policy.eff_prefix, tunnel_mode="cloudflare_token")
                    else:
                        _clear_transient_public_url("cloudflare_token")
                    _persist_extra_studio_config(policy, tunnel_mode="cloudflare_token", public_url=eff_pub_save or "")
                    _update_studio_gateway_slot(
                        policy,
                        "self_hosted",
                        enabled=True,
                        submode="cloudflare_token",
                        public_url=eff_pub_save or "",
                        select=True,
                        exclusive=True,
                        port=port,
                        set_public_url=set_public_url,
                    )
                    msg = "已切换为 Cloudflare 固定域名通道（开机自启保持永久固定域名不断联）。"
                elif new_mode == "vps":
                    saved_extra = _read_saved_extra_cfg(policy)
                    raw_vps_ssh = str(data.get("vps_ssh") or saved_extra.get("vps_ssh") or "").strip()
                    if not raw_vps_ssh:
                        raise ValueError("请填写自有云服务器 SSH 地址（例如 root@vps.example.com）。")
                    raw_rport = data.get("vps_remote_port")
                    if raw_rport is None or str(raw_rport).strip() == "":
                        raw_rport = saved_extra.get("vps_remote_port") or 18096
                    try:
                        eff_vps_port = int(str(raw_rport).strip())
                    except (TypeError, ValueError):
                        raise ValueError("云服务器远端转发端口必须是 1~65535 的整数。")
                    if not (1 <= eff_vps_port <= 65535):
                        raise ValueError("云服务器远端转发端口必须在 1~65535 范围内。")
                    raw_vps_pub = str(
                        raw_pub
                        or data.get("public_base")
                        or (saved_extra.get("public_base") if saved_extra.get("tunnel_mode") == "vps" else "")
                        or ""
                    ).strip().rstrip("/")
                    if raw_vps_pub and not raw_vps_pub.startswith(("https://", "http://")):
                        raw_vps_pub = "https://" + raw_vps_pub
                    if raw_vps_pub:
                        hot_refresh_public_url(
                            policy.state_root,
                            raw_vps_pub,
                            port=port,
                            prefix=policy.eff_prefix,
                            tunnel_mode="vps",
                        )
                    else:
                        _clear_transient_public_url("vps")
                    _persist_extra_studio_config(
                        policy,
                        tunnel_mode="vps",
                        public_url=raw_vps_pub,
                        vps_ssh=raw_vps_ssh,
                        vps_remote_port=eff_vps_port,
                    )
                    _update_studio_gateway_slot(
                        policy,
                        "self_hosted",
                        enabled=True,
                        submode="vps",
                        public_url=raw_vps_pub,
                        select=True,
                        exclusive=True,
                        extra_slot_fields={"vps_ssh_target": raw_vps_ssh, "vps_remote_port": eff_vps_port},
                        port=port,
                        set_public_url=set_public_url,
                    )
                    msg = (
                        f"已切换至自有云服务器 SSH 反向隧道（{raw_vps_ssh} -> 远端端口 {eff_vps_port}"
                        + (f"，公网地址 {raw_vps_pub}）" if raw_vps_pub else "）")
                    )
                elif new_mode == "custom":
                    if not raw_pub:
                        raise ValueError("请填写自有反代 HTTPS 域名地址（如 https://mcp.example.com）。")
                    if not raw_pub.startswith(("https://", "http://")):
                        raw_pub = "https://" + raw_pub
                    hot_refresh_public_url(policy.state_root, raw_pub, port=port, prefix=policy.eff_prefix, tunnel_mode="custom")
                    _persist_extra_studio_config(policy, tunnel_mode="custom", public_url=raw_pub)
                    _update_studio_gateway_slot(
                        policy,
                        "self_hosted",
                        enabled=True,
                        submode="custom",
                        public_url=raw_pub,
                        select=True,
                        exclusive=True,
                        extra_slot_fields={"custom_domain": raw_pub},
                        port=port,
                        set_public_url=set_public_url,
                    )
                    msg = f"已切换至自有固定域名：{raw_pub}"
                elif new_mode == "cloudflare":
                    cur_saved_pub = str(_read_saved_extra_cfg(policy).get("public_base") or "").strip().rstrip("/")
                    kept_quick_pub = cur_saved_pub if "trycloudflare.com" in cur_saved_pub.lower() else ""
                    if not kept_quick_pub:
                        _clear_transient_public_url("cloudflare")
                    _persist_extra_studio_config(
                        policy,
                        tunnel_mode="cloudflare",
                        public_url=kept_quick_pub,
                        prefer_quick_tunnel=True,
                    )
                    _update_studio_gateway_slot(
                        policy,
                        "instant",
                        enabled=True,
                        submode="cloudflare",
                        public_url=kept_quick_pub,
                        select=True,
                        exclusive=True,
                        port=port,
                        set_public_url=set_public_url,
                    )
                    msg = f"已切换为临时快速通道（{QUICK_TUNNEL_REBOOT_NOTICE_ZH}）"
                else:
                    local_u = f"http://127.0.0.1:{port}"
                    hot_refresh_public_url(policy.state_root, local_u, port=port, prefix=policy.eff_prefix, tunnel_mode="local")
                    _persist_extra_studio_config(policy, tunnel_mode="local", public_url="")
                    _update_studio_gateway_slot(
                        policy,
                        "instant",
                        enabled=False,
                        exclusive=True,
                        port=port,
                        set_public_url=set_public_url,
                    )
                    msg = "已切换为本机回环调试状态。"
                policy.refresh(force=True)
        except ValueError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

        snap = _state_snapshot(request)
        snap["message"] = msg
        return _json_with_optional_cookie(snap, request, minted)

    async def studio_tasks_ep(request: Request) -> Response:
        pm = _get_proc_mgr()
        if request.method == "GET":
            cookie_ok = session_mgr.verify_token(request.cookies.get(STUDIO_SESSION_COOKIE, ""), provider)
            is_lb = is_strict_direct_loopback(request, port)
            if not is_lb and not cookie_ok:
                return JSONResponse({"ok": False, "need_unlock": True, "error": "请先解锁管理会话。"}, status_code=403)
            jid = (request.query_params.get("job_id") or "").strip()
            if pm is None:
                return JSONResponse({"ok": True, "jobs": [], "selected": None}, headers={"Cache-Control": "no-store"})
            list_res = pm.manage_bg_command(action="list")
            selected_detail = None
            if jid:
                st_res = pm.manage_bg_command(action="status", job_id=jid, tail_lines=80)
                if st_res.get("ok"):
                    selected_detail = st_res
            return JSONResponse(
                {
                    "ok": True,
                    "jobs": list_res.get("jobs") or [],
                    "selected": selected_detail,
                },
                headers={"Cache-Control": "no-store"},
            )

        data, _ = await _parse_request_data(request)
        if data is None:
            return JSONResponse({"ok": False, "error": "请求格式无效。"}, status_code=400)
        err_resp, minted = _check_studio_auth(request, data)
        if err_resp is not None:
            return err_resp
        if pm is None:
            return _json_with_optional_cookie({"ok": False, "error": "进程管理器未就绪。"}, request, minted, status_code=400)

        act = str(data.get("action") or "kill").strip().lower()
        if act == "kill_all":
            k_all = pm.kill_all_active_commands(reason="studio_kill_all", include_persisted_bg=True, prefix_filter=policy.eff_prefix)
            snap = _state_snapshot(request)
            snap["message"] = f"已终止全部在途任务（共停止 {len(k_all.get('bg_killed') or []) + len(k_all.get('fg_killed') or [])} 个进程）。"
            return _json_with_optional_cookie(snap, request, minted)

        jid = str(data.get("job_id") or "").strip()
        if not jid:
            return JSONResponse({"ok": False, "error": "缺少任务编号。"}, status_code=400)
        k_res = pm.manage_bg_command(action="kill", job_id=jid, tail_lines=60)
        if not k_res.get("ok"):
            return JSONResponse({"ok": False, "error": str(k_res.get("error") or "终止任务失败")}, status_code=400)
        snap = _state_snapshot(request)
        snap["message"] = f"已终止后台任务 {jid}。"
        snap["task_detail"] = k_res
        return _json_with_optional_cookie(snap, request, minted)

    async def studio_recovery_ep(request: Request) -> Response:
        if request.method == "GET":
            cookie_ok = session_mgr.verify_token(request.cookies.get(STUDIO_SESSION_COOKIE, ""), provider)
            is_lb = is_strict_direct_loopback(request, port)
            if not is_lb and not cookie_ok:
                return JSONResponse({"ok": False, "need_unlock": True, "error": "请先解锁管理会话。"}, status_code=403)
            rec_data = _collect_recovery_state(policy, limit=25, dispatcher=dispatcher)
            return JSONResponse({"ok": True, **rec_data}, headers={"Cache-Control": "no-store"})

        data, _ = await _parse_request_data(request)
        if data is None:
            return JSONResponse({"ok": False, "error": "请求格式无效。"}, status_code=400)
        err_resp, minted = _check_studio_auth(request, data)
        if err_resp is not None:
            return err_resp

        act = str(data.get("action") or "").strip().lower()
        if act == "undo":
            target_p = str(data.get("path") or "").strip()
            if not target_p:
                return JSONResponse({"ok": False, "error": "请指定要撤回修改的文件路径。"}, status_code=400)
            u_res = _execute_studio_undo(policy, target_p)
            if not u_res.get("ok"):
                return JSONResponse({"ok": False, "error": str(u_res.get("error") or "撤回修改失败")}, status_code=400)
            snap = _state_snapshot(request)
            snap["message"] = f"已成功撤回文件修改：{Path(target_p).name}"
            return _json_with_optional_cookie(snap, request, minted)

        if act == "diff":
            diff_doc = _build_studio_snapshot_diff(policy, str(data.get("path") or ""))
            status_c = 200 if diff_doc.get("ok") else 400
            return _json_with_optional_cookie(diff_doc, request, minted, status_code=status_c)

        if act == "restore_trash":
            tid = str(data.get("trash_id") or "latest").strip()
            r_res = _execute_studio_restore_trash(policy, tid)
            if not r_res.get("ok"):
                return JSONResponse({"ok": False, "error": str(r_res.get("error") or "从回收箱恢复失败")}, status_code=400)
            restored_p = str(r_res.get("restored_path") or r_res.get("original_path") or "")
            snap = _state_snapshot(request)
            snap["message"] = f"已从回收箱恢复：{Path(restored_p).name if restored_p else tid}"
            return _json_with_optional_cookie(snap, request, minted)

        return JSONResponse({"ok": False, "error": f"不支持的恢复操作：{act}"}, status_code=400)

    async def studio_recovery_diff_ep(request: Request) -> Response:
        cookie_ok = session_mgr.verify_token(request.cookies.get(STUDIO_SESSION_COOKIE, ""), provider)
        if not cookie_ok:
            err_resp, minted = _check_studio_auth(request, {"csrf": request.headers.get("x-studio-csrf", "")})
            if err_resp is not None:
                return err_resp
        else:
            minted = False
        raw_p = (request.query_params.get("path") or "").strip()
        diff_doc = _build_studio_snapshot_diff(policy, raw_p)
        return _json_with_optional_cookie(diff_doc, request, minted, status_code=200 if diff_doc.get("ok") else 400)

    async def studio_poll_ep(request: Request) -> Response:
        policy.refresh()
        if provider is not None:
            provider.tier_key = policy.tier_key
            provider.tier_label = _norm_tier_label_zh(policy.dynamic_tier_label())
        is_lb = is_strict_direct_loopback(request, port)
        cookie_ok = session_mgr.verify_token(request.cookies.get(STUDIO_SESSION_COOKIE, ""), provider)
        if not is_lb and not cookie_ok:
            return JSONResponse(
                {"ok": False, "locked": True, "need_unlock": True, "error": "请先解锁管理会话。"},
                status_code=403,
                headers={"Cache-Control": "no-store"},
            )
        eff_pub = get_public_url().rstrip("/")
        extra_cfg = _read_saved_extra_cfg(policy)

        status_kind, status_text = _status_indicator_for_tier(policy.tier_key)
        pair_code = _read_pair_code(policy.state_root, policy.eff_prefix, fallback_seed=local_api_token)
        dynamic_pair_code = ""
        if provider is not None and hasattr(provider, "get_dynamic_pair_code"):
            try:
                dynamic_pair_code = str(provider.get_dynamic_pair_code() or "").strip()
            except Exception:
                dynamic_pair_code = ""
        sessions = store.list_authorized_sessions() if store is not None else []
        ui_sessions = _format_authorized_sessions_for_ui(sessions, tier_key=policy.tier_key)

        d_status_file = policy.state_root / "state" / (
            f"daemon_status_{policy.eff_prefix}.json" if policy.eff_prefix != "pc" else "daemon_status.json"
        )
        d_doc_parsed: Optional[Dict[str, Any]] = None
        if d_status_file.is_file():
            try:
                d_doc = json.loads(d_status_file.read_text(encoding="utf-8-sig"))
                if isinstance(d_doc, dict):
                    d_doc_parsed = d_doc
            except Exception:
                d_doc_parsed = None

        gw_view = _resolve_studio_gateways_view(
            policy=policy,
            extra_cfg=extra_cfg,
            d_doc=d_doc_parsed,
            raw_live_pub=eff_pub,
        )

        running_cnt = 0
        pm = _get_proc_mgr()
        if pm is not None:
            try:
                j_res = pm.manage_bg_command(action="list")
                running_cnt = sum(1 for j in (j_res.get("jobs") or []) if j.get("running"))
            except Exception:
                running_cnt = 0

        return JSONResponse(
            {
                "ok": True,
                "consent_pair_code": pair_code,
                "pair_code": pair_code,
                "dynamic_pair_code": dynamic_pair_code,
                "authorized_sessions_count": len(ui_sessions),
                "authorized_sessions": ui_sessions,
                "status_kind": status_kind,
                "status_text": status_text,
                "safety_mode": _safety_mode_code(policy.tier_key),
                "safety_mode_label": SAFETY_MODE_LABELS_ZH.get(policy.tier_key, "工作区内顺畅开发"),
                "restrict_to_workspace": bool(policy.restrict_to_workspace),
                "gateways": gw_view["gateways"],
                "selected_gateway": gw_view["selected_gateway"],
                "user_selected_gateway": gw_view["user_selected_gateway"],
                "display_gateway_id": gw_view["display_gateway_id"],
                "enabled_gateway_ids": gw_view["enabled_gateway_ids"],
                "ready_gateway_ids": gw_view["ready_gateway_ids"],
                "tunnel_mode": gw_view["tunnel_mode"],
                "effective_tunnel_mode": gw_view["effective_tunnel_mode"],
                "public_https_ready": bool(gw_view["public_https_ready"]),
                "is_loopback_url": bool(gw_view["is_loopback_url"]),
                "public_url": gw_view["public_url"],
                "mcp_url": gw_view["mcp_url"],
                "mcp_readonly_url": gw_view["mcp_readonly_url"],
                "endpoint_secret_enabled": bool(load_endpoint_secret(policy.state_root, prefix=policy.eff_prefix)),
                "readonly_mcp_url": gw_view["readonly_mcp_url"],
                "skill_url": gw_view["skill_url"],
                "srvus_fixed_active": gw_view["srvus_fixed_active"],
                "instant_fallback_active": gw_view["instant_fallback_active"],
                "public_gateway_online": gw_view["public_gateway_online"],
                "reboot_notice": gw_view["reboot_notice"],
                "tunnel_connecting": bool(gw_view["tunnel_connecting"]),
                "tunnel_error": gw_view["tunnel_error"],
                "running_tasks_count": running_cnt,
            },
            headers={"Cache-Control": "no-store"},
        )

    async def studio_connectivity_check_ep(request: Request) -> Response:
        raw_body = await request.body()
        if not raw_body or not raw_body.strip():
            data: Optional[Dict[str, Any]] = {}
        else:
            data, _ = await _parse_request_data(request)
        if data is None:
            return JSONResponse({"ok": False, "error": "请求格式无效。"}, status_code=400, headers={"Cache-Control": "no-store"})
        err_resp, minted = _check_studio_auth(request, data)
        if err_resp is not None:
            return err_resp

        raw_gw = str(data.get("gateway_id") or "").strip().lower()
        if raw_gw and raw_gw not in STUDIO_GATEWAY_IDS:
            return JSONResponse(
                {"ok": False, "error": f"未知网关通道标识：{raw_gw}"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )
        policy.refresh()
        res = await asyncio.to_thread(
            run_connectivity_check,
            policy.state_root,
            prefix=policy.eff_prefix,
            local_port=port,
            gateway_id=raw_gw,
            timeout_sec=3.5,
        )
        return _json_with_optional_cookie(res, request, minted)

    async def studio_service_control_ep(request: Request) -> Response:
        data, _ = await _parse_request_data(request)
        if data is None:
            return JSONResponse({"ok": False, "error": "请求格式无效。"}, status_code=400)
        err_resp, minted = _check_studio_auth(request, data)
        if err_resp is not None:
            return err_resp

        act = str(data.get("action") or "").strip().lower()
        if act not in ("stop", "restart"):
            return JSONResponse({"ok": False, "error": f"不支持的服务控制指令：{act!r}"}, status_code=400)

        pm = _get_proc_mgr()
        if pm is not None:
            try:
                pm.kill_all_active_commands(
                    reason=f"studio_service_{act}",
                    include_persisted_bg=True,
                    prefix_filter=policy.eff_prefix,
                )
            except Exception:
                pass
        dispatcher.shutdown_packs(prefix_filter=policy.eff_prefix)
        close_all_browser_sessions(prefix_filter=policy.eff_prefix)
        _emit_kill_signal_resilient(
            policy.state_root,
            reason=f"studio_service_{act}",
            prefix_filter=policy.eff_prefix,
        )

        stop_flag = daemon_stop_flag_path(policy.state_root, policy.eff_prefix)
        stop_flag.parent.mkdir(parents=True, exist_ok=True)
        now_ts = round(time.time(), 3)

        if act == "stop":
            stop_flag.write_text(f"STOP:{now_ts}\n", encoding="utf-8")
            ctrl_msg = "已发出停止服务信号：在途任务与扩展包已清理，守护进程即将安全停止。"
        else:
            stop_flag.write_text(f"CLEAR:{now_ts}\n", encoding="utf-8")
            policy.refresh(force=True)
            ctrl_msg = "已发出重启服务信号：配置已重新加载，守护进程即将拉起新工作进程。"

        ctrl_record_p = policy.state_root / "state" / "service_control_last.json"
        atomic_write_json(
            ctrl_record_p,
            {
                "action": act,
                "ts": now_ts,
                "prefix": policy.eff_prefix,
            },
        )

        is_test_env = bool(os.environ.get("PYTEST_CURRENT_TEST") or parse_bool_flag(data.get("signal_only"), default=False))
        d_status_file = policy.state_root / "state" / (
            f"daemon_status_{policy.eff_prefix}.json" if policy.eff_prefix != "pc" else "daemon_status.json"
        )
        supervised = False
        if d_status_file.is_file():
            try:
                d_doc = json.loads(d_status_file.read_text(encoding="utf-8-sig"))
                supervised = isinstance(d_doc, dict) and str(d_doc.get("status") or "") == "running"
            except Exception:
                supervised = False

        if not is_test_env and (act == "stop" or (act == "restart" and supervised)):
            threading.Timer(0.35, lambda: os._exit(0)).start()

        return _json_with_optional_cookie(
            {
                "ok": True,
                "action": act,
                "stop_flag_path": str(stop_flag),
                "message": ctrl_msg,
            },
            request,
            minted,
        )

    async def studio_uninstall_ep(request: Request) -> Response:
        data, _ = await _parse_request_data(request)
        if data is None:
            return JSONResponse({"ok": False, "error": "请求格式无效。"}, status_code=400)
        if not is_strict_direct_loopback(request, port):
            return JSONResponse(
                {"ok": False, "error": "安全限制：仅允许在本机浏览器执行一键卸载。"},
                status_code=403,
                headers={"Cache-Control": "no-store"},
            )
        err_resp, minted = _check_studio_auth(request, data)
        if err_resp is not None:
            return err_resp

        purge = parse_bool_flag(data.get("purge"), default=True)
        dry_run = parse_bool_flag(data.get("dry_run"), default=False)
        cf_api_token = str(data.get("cf_api_token") or "").strip()

        from cosmos_mcp.launcher.doctor import run_uninstall

        if dry_run:
            preview_res = await asyncio.to_thread(
                run_uninstall,
                policy.state_root,
                prefix=policy.eff_prefix,
                purge=purge,
                dry_run=True,
            )
            return _json_with_optional_cookie(preview_res, request, minted)

        cf_cleanup_res: Optional[Dict[str, Any]] = None
        if cf_api_token:
            del_cf_fn = getattr(cfgw, "delete_cloudflare_workers_gateway", None)
            if callable(del_cf_fn):
                try:
                    sig_cf = inspect.signature(del_cf_fn).parameters
                    cf_kw: Dict[str, Any] = {}
                    if "api_token" in sig_cf:
                        cf_kw["api_token"] = cf_api_token
                    elif "cf_api_token" in sig_cf:
                        cf_kw["cf_api_token"] = cf_api_token
                    if "state_root" in sig_cf:
                        cf_kw["state_root"] = policy.state_root
                    if "prefix" in sig_cf:
                        cf_kw["prefix"] = policy.eff_prefix
                    cf_cleanup_res = await asyncio.to_thread(del_cf_fn, **cf_kw)
                except Exception as exc:
                    cf_cleanup_res = {"ok": False, "error": str(exc)}
            else:
                cf_cleanup_res = {"ok": False, "skipped": True, "reason": "delete_cloudflare_workers_gateway_unavailable"}

        if store is not None:
            try:
                store.revoke_all_tokens(delete_clients=True)
            except Exception:
                pass
        pm = _get_proc_mgr()
        if pm is not None:
            try:
                pm.kill_all_active_commands(
                    reason="studio_uninstall",
                    include_persisted_bg=True,
                    prefix_filter=policy.eff_prefix,
                )
            except Exception:
                pass
        dispatcher.shutdown_packs(prefix_filter=policy.eff_prefix)
        close_all_browser_sessions(prefix_filter=policy.eff_prefix)
        _emit_kill_signal_resilient(
            policy.state_root,
            reason="studio_uninstall",
            prefix_filter=policy.eff_prefix,
        )
        try:
            stop_flag_u = daemon_stop_flag_path(policy.state_root, policy.eff_prefix)
            stop_flag_u.parent.mkdir(parents=True, exist_ok=True)
            stop_flag_u.write_text(f"STOP:{round(time.time(), 3)}\n", encoding="utf-8")
        except Exception:
            pass

        sync_mode = bool(
            os.environ.get("PYTEST_CURRENT_TEST")
            or parse_bool_flag(data.get("sync_for_test"), default=False)
        )
        if sync_mode:
            final_res = await asyncio.to_thread(
                run_uninstall,
                policy.state_root,
                prefix=policy.eff_prefix,
                purge=purge,
                dry_run=False,
            )
            if cf_cleanup_res is not None:
                final_res["cf_worker_cleanup"] = cf_cleanup_res
            final_res.setdefault("message", "已完成一键卸载与本地状态清理。")
            return _json_with_optional_cookie(final_res, request, minted)

        plan_preview = await asyncio.to_thread(
            run_uninstall,
            policy.state_root,
            prefix=policy.eff_prefix,
            purge=purge,
            dry_run=True,
        )

        def _bg_uninstall_and_exit() -> None:
            time.sleep(0.45)
            try:
                run_uninstall(policy.state_root, prefix=policy.eff_prefix, purge=purge, dry_run=False)
            except Exception:
                pass
            os._exit(0)

        threading.Thread(target=_bg_uninstall_and_exit, name="cosmos-studio-uninstall", daemon=True).start()
        out_async: Dict[str, Any] = {
            **plan_preview,
            "ok": True,
            "dry_run": False,
            "scheduled_async": True,
            "purge": purge,
            "message": "已启动后台一键卸载，正在清理本地文件并退出服务。",
        }
        if cf_cleanup_res is not None:
            out_async["cf_worker_cleanup"] = cf_cleanup_res
        return _json_with_optional_cookie(out_async, request, minted)

    async def studio_skills_ep(request: Request) -> Response:
        subpath = (request.path_params.get("subpath") or "").strip("/").lower()
        if request.method == "GET":
            cookie_ok = session_mgr.verify_token(request.cookies.get(STUDIO_SESSION_COOKIE, ""), provider)
            if not cookie_ok:
                err_resp, minted = _check_studio_auth(request, {"csrf": request.headers.get("x-studio-csrf", "")})
                if err_resp is not None:
                    return err_resp
            else:
                minted = False

            qp = request.query_params
            q_str = (qp.get("q") or qp.get("query") or "").strip()
            scope_str = (qp.get("scope") or "all").strip()
            cwd_str = (qp.get("cwd") or qp.get("workspace") or "").strip()

            if subpath in ("", "local", "list"):
                all_res = skills_service.handle_skill_manage(
                    action="list",
                    scope="all",
                    cwd=cwd_str,
                    limit=200,
                )
                total_all_count = int(all_res.get("total", len(all_res.get("skills") or [])))
                total_enabled_count = int(all_res.get("enabled_count", 0))
                total_disabled_count = int(all_res.get("disabled_count", 0))

                if q_str:
                    res_s = skills_service.handle_skill_hub(
                        action="search",
                        query=q_str,
                        scope=scope_str,
                        cwd=cwd_str or None,
                        include_disabled=True,
                        limit=int(qp.get("limit") or 200),
                    )
                    raw_rows = list(res_s.get("results") or [])
                    matched_count = int(res_s.get("count", len(raw_rows)))
                else:
                    res_s = skills_service.handle_skill_manage(
                        action="list",
                        scope=scope_str,
                        cwd=cwd_str,
                        limit=int(qp.get("limit") or 200),
                    )
                    raw_rows = list(res_s.get("skills") or [])
                    matched_count = int(res_s.get("total", len(raw_rows)))

                if not res_s.get("ok"):
                    return _json_with_optional_cookie(res_s, request, minted, status_code=400)

                enriched_rows: List[Dict[str, Any]] = []
                for row in raw_rows:
                    sc = str(row.get("source_scope") or "")
                    enriched_rows.append(
                        {
                            **row,
                            "scope_label": _scope_label_zh(sc),
                            "source_dir": str(row.get("source_root") or row.get("skill_dir") or ""),
                        }
                    )

                is_filtered = bool(q_str or (scope_str and scope_str != "all"))
                scan_roots = skills_service.config.ordered_scan_roots(cwd=cwd_str or None)
                hosts_meta = [
                    {
                        "host_id": hid,
                        "label": _scope_label_zh(hid),
                        "path": str(hp),
                        "exists": hp.is_dir(),
                        "writable": hid in WRITABLE_HOST_IDS,
                    }
                    for hid, hp in skills_service.config.host_skill_roots()
                ]
                return _json_with_optional_cookie(
                    {
                        "ok": True,
                        "query": q_str,
                        "scope": scope_str,
                        "is_filtered": is_filtered,
                        "count": total_all_count,
                        "total_all_count": total_all_count,
                        "matched_count": matched_count,
                        "enabled_count": total_enabled_count,
                        "disabled_count": total_disabled_count,
                        "managed_store": str(skills_service.config.managed_skills_store()),
                        "checked_dirs": [str(rp) for _, rp in scan_roots],
                        "hosts": hosts_meta,
                        "items": enriched_rows,
                    },
                    request,
                    minted,
                )

            if subpath == "detail":
                sk_name = (qp.get("skill") or qp.get("name") or "").strip()
                rel_f = (qp.get("file") or qp.get("rel_path") or "SKILL.md").strip() or "SKILL.md"
                if not sk_name:
                    return JSONResponse({"ok": False, "error": "请指定要查看的技能名称。"}, status_code=400)
                load_res = skills_service.handle_skill_hub(
                    action="load" if rel_f.lower() in ("skill.md", "skills.md") else "read_file",
                    skill=sk_name,
                    rel_path=rel_f,
                    cwd=cwd_str or None,
                    include_disabled=True,
                    wrap_untrusted=False,
                    max_chars=48000,
                )
                if not load_res.get("ok"):
                    return _json_with_optional_cookie(load_res, request, minted, status_code=404)

                rec = skills_service._get_index().get_skill(sk_name, cwd=cwd_str or None, include_disabled=True)
                audit_dict: Dict[str, Any] = {}
                host_states: List[Dict[str, Any]] = []
                skill_dir_str = ""
                if rec is not None and Path(rec.skill_dir).is_dir():
                    skill_dir_str = rec.skill_dir
                    rep = audit_skill_directory(Path(rec.skill_dir), skill_name=rec.name, config=skills_service.config)
                    audit_dict = rep.to_dict()
                    if rec.source_scope == "managed":
                        raw_hs = skills_service.package_manager.get_skill_host_states(rec.dir_name)
                        host_states = [
                            {**hs, "label": _scope_label_zh(str(hs.get("host_id") or ""))}
                            for hs in raw_hs
                        ]

                out_det = {
                    **load_res,
                    "skill_dir": skill_dir_str,
                    "scope_label": _scope_label_zh(str(load_res.get("source_scope") or "")),
                    "audit": audit_dict,
                    "host_states": host_states,
                }
                return _json_with_optional_cookie(out_det, request, minted)

            if subpath == "market":
                if not q_str:
                    return JSONResponse({"ok": False, "error": "请输入要搜索的技能关键词。"}, status_code=400)
                srcs_raw = (qp.get("sources") or "").strip()
                srcs_list = [s.strip() for s in srcs_raw.split(",") if s.strip()] if srcs_raw else None
                m_res = skills_service.handle_skill_hub(
                    action="market_search",
                    query=q_str,
                    sources=srcs_list,
                    limit=int(qp.get("limit") or 20),
                )
                return _json_with_optional_cookie(m_res, request, minted, status_code=200 if m_res.get("ok") else 400)

            if subpath in ("trash", "trash_list"):
                tr_res = skills_service.handle_skill_manage(
                    action="trash_list",
                    limit=int(qp.get("limit") or 50),
                )
                if isinstance(tr_res, dict) and tr_res.get("ok"):
                    raw_tr_items = list(tr_res.get("items") or tr_res.get("trashed_skills") or [])
                    fmt_tr_items: List[Dict[str, Any]] = []
                    for it in raw_tr_items:
                        if isinstance(it, dict):
                            raw_t = it.get("removed_at") or it.get("trashed_at") or ""
                            loc_t = _format_any_ts_local(raw_t)
                            fmt_tr_items.append({**it, "removed_at_local": loc_t, "trashed_at_local": loc_t})
                    tr_res = {**tr_res, "items": fmt_tr_items, "trashed_skills": fmt_tr_items}
                return _json_with_optional_cookie(tr_res, request, minted)

            if subpath == "unmanaged":
                un_res = skills_service.handle_skill_manage(action="scan_unmanaged")
                if un_res.get("ok"):
                    un_items = [
                        {**u, "host_label": _scope_label_zh(str(u.get("host_id") or ""))}
                        for u in (un_res.get("unmanaged_skills") or [])
                    ]
                    un_res = {**un_res, "unmanaged_skills": un_items}
                return _json_with_optional_cookie(un_res, request, minted, status_code=200 if un_res.get("ok") else 400)

            return JSONResponse({"ok": False, "error": f"未知技能查询接口：{subpath}"}, status_code=404)

        # POST /api/studio/skills/*
        data, _ = await _parse_request_data(request)
        if data is None:
            return JSONResponse({"ok": False, "error": "请求格式无效。"}, status_code=400)
        err_resp, minted = _check_studio_auth(request, data)
        if err_resp is not None:
            return err_resp

        if subpath in ("vet", "preview"):
            vet_res = skills_service.handle_skill_hub(
                action="vet",
                source=str(data.get("source") or data.get("source_ref") or data.get("install_ref") or "").strip(),
                skill=str(data.get("skill") or data.get("name") or "").strip(),
                scope=str(data.get("scope") or "").strip() or None,
                cwd=str(data.get("cwd") or data.get("workspace") or "").strip() or None,
            )
            status_c = 200 if (vet_res.get("ok") or vet_res.get("verdict") == "BLOCK") else 400
            return _json_with_optional_cookie(vet_res, request, minted, status_code=status_c)

        if subpath == "install":
            inst_res = skills_service.handle_skill_manage(
                action="install",
                preview_token=str(data.get("preview_token") or "").strip(),
                source=str(data.get("source") or data.get("source_ref") or data.get("install_ref") or "").strip(),
                skill=str(data.get("skill") or data.get("name") or "").strip(),
                scope=str(data.get("scope") or "").strip() or None,
                cwd=str(data.get("cwd") or data.get("workspace") or "").strip(),
                confirm_warn=parse_bool_flag(data.get("confirm_warn"), default=False),
                force=parse_bool_flag(data.get("force") if "force" in data else data.get("overwrite"), default=False),
                dry_run=parse_bool_flag(data.get("dry_run"), default=False) if "dry_run" in data else False,
                sync_hosts=parse_bool_flag(data.get("sync_hosts"), default=False) if "sync_hosts" in data else None,
            )
            status_c = 200 if (inst_res.get("ok") or inst_res.get("requires_confirmation")) else 400
            return _json_with_optional_cookie(inst_res, request, minted, status_code=status_c)

        if subpath == "create":
            cr_res = skills_service.handle_skill_manage(
                action="create",
                skill=str(data.get("skill") or data.get("name") or "").strip(),
                content=str(data.get("content") or ""),
                scope=str(data.get("scope") or "managed").strip(),
                cwd=str(data.get("cwd") or data.get("workspace") or "").strip(),
                confirm_warn=parse_bool_flag(data.get("confirm_warn"), default=False),
                force=parse_bool_flag(data.get("force") if "force" in data else data.get("overwrite"), default=False),
                sync_hosts=parse_bool_flag(data.get("sync_hosts"), default=False) if "sync_hosts" in data else None,
            )
            status_c = 200 if (cr_res.get("ok") or cr_res.get("requires_confirmation")) else 400
            return _json_with_optional_cookie(cr_res, request, minted, status_code=status_c)

        if subpath in ("toggle", "enable", "disable"):
            if subpath == "enable":
                want_en = True
            elif subpath == "disable":
                want_en = False
            else:
                want_en = parse_bool_flag(data.get("enabled"), default=True)
            tg_res = skills_service.handle_skill_manage(
                action="enable" if want_en else "disable",
                skill=str(data.get("skill") or data.get("name") or "").strip(),
                scope=str(data.get("scope") or "").strip() or None,
                cwd=str(data.get("cwd") or data.get("workspace") or "").strip(),
                host_id=str(data.get("host_id") or "").strip(),
                sync_hosts=parse_bool_flag(data.get("sync_hosts"), default=False) if "sync_hosts" in data else None,
            )
            return _json_with_optional_cookie(tg_res, request, minted, status_code=200 if tg_res.get("ok") else 400)

        if subpath == "sync":
            raw_hosts = data.get("hosts")
            hosts_seq = [str(x).strip() for x in raw_hosts if str(x).strip()] if isinstance(raw_hosts, list) else None
            sy_res = skills_service.handle_skill_manage(
                action="sync",
                skill=str(data.get("skill") or data.get("name") or "").strip(),
                hosts=hosts_seq,
                host_id=str(data.get("host_id") or "").strip(),
                force=parse_bool_flag(data.get("force") if "force" in data else data.get("overwrite"), default=False),
            )
            return _json_with_optional_cookie(sy_res, request, minted, status_code=200 if sy_res.get("ok") else 400)

        if subpath in ("trash", "remove"):
            rm_res = skills_service.handle_skill_manage(
                action="trash",
                skill=str(data.get("skill") or data.get("name") or "").strip(),
                scope=str(data.get("scope") or "").strip() or None,
                cwd=str(data.get("cwd") or data.get("workspace") or "").strip(),
                force=parse_bool_flag(data.get("force") if "force" in data else data.get("overwrite"), default=False),
            )
            return _json_with_optional_cookie(rm_res, request, minted, status_code=200 if rm_res.get("ok") else 400)

        if subpath == "restore":
            rs_res = skills_service.handle_skill_manage(
                action="restore",
                trash_id=str(data.get("trash_id") or "latest").strip(),
                force=parse_bool_flag(data.get("force") if "force" in data else data.get("overwrite"), default=False),
            )
            return _json_with_optional_cookie(rs_res, request, minted, status_code=200 if rs_res.get("ok") else 400)

        if subpath in ("check", "relock"):
            ck_res = skills_service.handle_skill_manage(
                action=subpath,
                skill=str(data.get("skill") or data.get("name") or "").strip(),
                scope=str(data.get("scope") or "managed").strip(),
                cwd=str(data.get("cwd") or data.get("workspace") or "").strip(),
            )
            return _json_with_optional_cookie(ck_res, request, minted, status_code=200 if ck_res.get("ok") else 400)

        if subpath == "adopt":
            ad_res = skills_service.handle_skill_manage(
                action="adopt",
                skill=str(data.get("skill") or data.get("name") or "").strip(),
                source=str(data.get("source") or data.get("source_path") or "").strip(),
                host_id=str(data.get("host_id") or "").strip(),
                confirm_warn=parse_bool_flag(data.get("confirm_warn"), default=False),
            )
            return _json_with_optional_cookie(ad_res, request, minted, status_code=200 if ad_res.get("ok") else 400)

        return JSONResponse({"ok": False, "error": f"未知技能管理操作：{subpath}"}, status_code=404)

    async def studio_gateway_cf_deploy_ep(request: Request) -> Response:
        data, _ = await _parse_request_data(request)
        if data is None:
            return JSONResponse({"ok": False, "error": "请求格式无效。"}, status_code=400)
        err_resp, minted = _check_studio_auth(request, data)
        if err_resp is not None:
            return err_resp

        raw_tok = str(data.get("api_token") or "").strip()
        raw_acc = str(data.get("account_id") or "").strip()
        raw_dom = str(data.get("custom_domain") or "").strip()
        raw_script = str(data.get("script_name") or "cosmos-mcp-gateway").strip() or "cosmos-mcp-gateway"

        res = await asyncio.to_thread(
            deploy_cloudflare_workers_gateway,
            api_token=raw_tok,
            state_root=policy.state_root,
            prefix=policy.eff_prefix,
            account_id=raw_acc,
            script_name=raw_script,
            custom_domain=raw_dom,
        )
        if res.get("error") == "multiple_accounts_select_required":
            return _json_with_optional_cookie(
                {
                    **res,
                    "multiple_accounts_select_required": True,
                },
                request,
                minted,
                status_code=200,
            )
        if not res.get("ok"):
            err_msg = str(res.get("message") or res.get("error") or "Cloudflare 固定网关部署失败。")
            return _json_with_optional_cookie(
                {**res, "ok": False, "error": err_msg, "error_code": res.get("error") or "deploy_failed"},
                request,
                minted,
                status_code=400,
            )

        pub_url = str(res.get("public_url") or "").strip().rstrip("/")
        wd_url = str(res.get("workers_dev_url") or pub_url).strip().rstrip("/")
        acc_id = str(res.get("account_id") or raw_acc).strip()
        subdom = str(res.get("subdomain") or "").strip()
        scr_nm = str(res.get("script_name") or raw_script).strip()
        cus_dom = str(res.get("custom_domain") or "").strip()

        cur_slots, _, _ = _normalize_studio_gateways_cfg(policy, _read_saved_extra_cfg(policy))
        other_en_cnt = sum(1 for g in STUDIO_GATEWAY_IDS if g != "workers_dev" and cur_slots[g]["enabled"])

        if pub_url:
            _safe_hot_refresh_gateway_url(
                policy.state_root,
                pub_url,
                port=port,
                prefix=policy.eff_prefix,
                tunnel_mode="workers_dev",
                gateway_id="workers_dev",
                other_enabled_count=other_en_cnt,
            )
        _persist_extra_studio_config(
            policy,
            workers_dev_url=wd_url,
            workers_dev_account_id=acc_id,
            workers_dev_script_name=scr_nm,
            workers_dev_subdomain=subdom,
            workers_dev_custom_domain=cus_dom,
        )
        _update_studio_gateway_slot(
            policy,
            "workers_dev",
            enabled=True,
            submode="workers_dev",
            public_url=pub_url,
            select=True,
            extra_slot_fields={
                "script_name": scr_nm,
                "account_id": acc_id,
                "subdomain": subdom,
                "custom_domain": cus_dom,
            },
            port=port,
            set_public_url=set_public_url,
        )
        policy.refresh(force=True)
        snap = _state_snapshot(request)
        snap["deploy_result"] = res
        snap["api_token_shredded"] = bool(res.get("api_token_shredded", True))
        snap["message"] = f"已部署并开启 Cloudflare 固定网关（{pub_url}），API 令牌已自动销毁。"
        return _json_with_optional_cookie(snap, request, minted)

    async def studio_gateway_vps_provision_ep(request: Request) -> Response:
        data, _ = await _parse_request_data(request)
        if data is None:
            return JSONResponse({"ok": False, "error": "请求格式无效。"}, status_code=400)
        err_resp, minted = _check_studio_auth(request, data)
        if err_resp is not None:
            return err_resp

        raw_host = str(data.get("host") or data.get("vps_host") or "").strip()
        raw_pw = str(data.get("ssh_password") or "").strip()
        raw_user = str(data.get("ssh_user") or "root").strip() or "root"
        raw_id_file = str(data.get("identity_file") or data.get("ssh_key_path") or "").strip().strip("\"'")
        use_ssh_key = parse_bool_flag(data.get("use_ssh_key"), default=False)
        raw_dom = str(data.get("custom_domain") or "").strip()
        raw_port = data.get("ssh_port")
        if not raw_host:
            return JSONResponse({"ok": False, "error": "请填写服务器公网 IP。"}, status_code=400)
        try:
            eff_ssh_port = int(str(raw_port).strip()) if raw_port is not None and str(raw_port).strip() else 22
        except ValueError:
            return JSONResponse({"ok": False, "error": "SSH 端口必须是 1~65535 的整数。"}, status_code=400)
        if not (1 <= eff_ssh_port <= 65535):
            return JSONResponse({"ok": False, "error": "SSH 端口必须在 1~65535 范围内。"}, status_code=400)

        eff_id_file = ""
        if raw_id_file:
            exp_key = Path(expand_env_and_tilde(raw_id_file)).expanduser()
            if not exp_key.is_file():
                return JSONResponse({"ok": False, "error": f"未找到指定的 SSH 私钥文件：{raw_id_file}"}, status_code=400)
            eff_id_file = str(exp_key.resolve())
        elif not raw_pw or use_ssh_key:
            ssh_dir = Path.home() / ".ssh"
            for key_nm in ("id_ed25519", "id_ecdsa", "id_rsa"):
                cand_k = ssh_dir / key_nm
                if cand_k.is_file():
                    eff_id_file = str(cand_k.resolve())
                    break
            if not raw_pw and not eff_id_file and not use_ssh_key:
                return JSONResponse(
                    {"ok": False, "error": "请填写 SSH 登录密码，或在高级项中勾选使用本机 SSH 密钥 / 填写私钥路径。"},
                    status_code=400,
                )

        res = await asyncio.to_thread(
            provision_vps_hub_oneclick,
            host=raw_host,
            ssh_password=raw_pw,
            ssh_user=raw_user,
            ssh_port=eff_ssh_port,
            identity_file=eff_id_file,
            custom_domain=raw_dom,
            local_port=port,
            state_root=policy.state_root,
            prefix=policy.eff_prefix,
        )
        if not res.get("ok"):
            err_msg = str(
                res.get("message")
                or res.get("firewall_guide")
                or res.get("error")
                or "自有服务器 24h 主站部署失败。"
            )
            return _json_with_optional_cookie(
                {**res, "ok": False, "error": err_msg, "error_code": res.get("error") or "vps_provision_failed"},
                request,
                minted,
                status_code=400,
            )

        pub_url = str(res.get("public_url") or "").strip().rstrip("/")
        node_sec = load_or_create_vps_node_secret(policy.state_root, prefix=policy.eff_prefix)
        clean_host_only = raw_host
        if "://" in clean_host_only:
            clean_host_only = (urlsplit(clean_host_only).hostname or clean_host_only).strip()
        if "@" in clean_host_only:
            clean_host_only = clean_host_only.rsplit("@", 1)[-1].strip()

        cur_slots, _, _ = _normalize_studio_gateways_cfg(policy, _read_saved_extra_cfg(policy))
        other_en_cnt = sum(1 for g in STUDIO_GATEWAY_IDS if g != "self_hosted" and cur_slots[g]["enabled"])
        saved_key_p = str(res.get("ssh_key_path") or eff_id_file or "")

        if pub_url:
            _safe_hot_refresh_gateway_url(
                policy.state_root,
                pub_url,
                port=port,
                prefix=policy.eff_prefix,
                tunnel_mode="vps_hub",
                gateway_id="self_hosted",
                other_enabled_count=other_en_cnt,
            )
        _persist_extra_studio_config(
            policy,
            vps_hub_url=pub_url,
            vps_node_secret=node_sec,
            vps_ssh=f"{raw_user}@{clean_host_only}",
            vps_ssh_port=eff_ssh_port,
            vps_identity_file=saved_key_p,
        )
        _update_studio_gateway_slot(
            policy,
            "self_hosted",
            enabled=True,
            submode="vps_hub",
            public_url=pub_url,
            select=True,
            extra_slot_fields={
                "custom_domain": raw_dom,
                "vps_ssh_target": f"{raw_user}@{clean_host_only}",
                "vps_ssh_port": eff_ssh_port,
                "vps_identity_file": saved_key_p,
            },
            port=port,
            set_public_url=set_public_url,
        )
        policy.refresh(force=True)
        snap = _state_snapshot(request)
        safe_prov = {k: v for k, v in res.items() if k not in ("caddyfile", "systemd_unit")}
        snap["provision_result"] = safe_prov
        snap["message"] = f"已在自有服务器部署 24h 主站并开启此网关：{pub_url}"
        return _json_with_optional_cookie(snap, request, minted)

    async def studio_tokens_mint_ep(request: Request) -> Response:
        if not is_strict_direct_loopback(request, port):
            return JSONResponse(
                {
                    "ok": False,
                    "error": "forbidden_non_loopback",
                    "message": "专用访问密钥仅允许在本机 127.0.0.1 控制台直接生成，禁止通过远程隧道或代理签发。",
                },
                status_code=403,
                headers={"Cache-Control": "no-store"},
            )
        data, _ = await _parse_request_data(request)
        if data is None:
            return JSONResponse(
                {"ok": False, "error": "请求格式无效。"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )
        csrf_err = _verify_same_origin_and_csrf(
            request,
            data,
            local_admin_csrf,
            strict_loopback_only=True,
            port=port,
            local_api_token=local_api_token,
        )
        if csrf_err is not None:
            return csrf_err

        raw_label = str(data.get("label") or "").strip()
        is_ro = parse_bool_flag(data.get("readonly"), default=True)
        raw_ttl = data.get("ttl_days", 30)
        if isinstance(raw_ttl, bool):
            return JSONResponse(
                {"ok": False, "error": "密钥有效天数格式无效。"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )
        try:
            ttl_days_val = int(str(raw_ttl).strip() or "30")
        except (TypeError, ValueError):
            return JSONResponse(
                {"ok": False, "error": "密钥有效天数格式无效。"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )
        try:
            if hasattr(provider, "mint_personal_access_token"):
                minted_pat = provider.mint_personal_access_token(
                    label=raw_label,
                    readonly=is_ro,
                    ttl_days=ttl_days_val,
                )
            else:
                minted_pat = store.mint_personal_access_token(
                    label=raw_label,
                    readonly=is_ro,
                    ttl_days=ttl_days_val,
                )
        except ValueError as exc:
            return JSONResponse(
                {"ok": False, "error": str(exc)},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )

        snap = _state_snapshot(request)
        exp_ts = int(minted_pat.get("expires_at") or 0)
        snap["minted_token"] = {
            "token": str(minted_pat["token"]),
            "client_id": str(minted_pat["client_id"]),
            "client_name": str(minted_pat["client_name"]),
            "platform": str(minted_pat["platform"]),
            "readonly": bool(minted_pat["readonly"]),
            "scopes": list(minted_pat.get("scopes") or []),
            "ttl_days": int(minted_pat["ttl_days"]),
            "expires_at": exp_ts,
            "expires_at_text": _format_epoch_local(exp_ts, with_seconds=False),
        }
        snap["message"] = (
            "已在本机签发专用访问密钥（仅本次显示明文，严禁发进聊天对话框、微信群或公开页面；"
            "仅限填入 ChatGPT Sites 后台环境变量 Secrets 或本地 CLI 配置）。"
        )
        return JSONResponse(snap, status_code=200, headers={"Cache-Control": "no-store"})

    async def studio_chatgpt_oneclick_ep(request: Request) -> Response:
        if not is_strict_direct_loopback(request, port):
            return JSONResponse(
                {
                    "ok": False,
                    "error": "forbidden_non_loopback",
                    "message": "ChatGPT 一键连接专属地址仅允许在本机 127.0.0.1 控制台生成，禁止远程请求。",
                },
                status_code=403,
                headers={"Cache-Control": "no-store"},
            )
        data, _ = await _parse_request_data(request)
        if data is None:
            return JSONResponse(
                {"ok": False, "error": "请求格式无效。"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )
        csrf_err = _verify_same_origin_and_csrf(
            request,
            data,
            local_admin_csrf,
            strict_loopback_only=True,
            port=port,
            local_api_token=local_api_token,
        )
        if csrf_err is not None:
            return csrf_err

        kind = str(data.get("kind") or "mcp").strip().lower()
        if kind not in ("mcp", "readonly"):
            return JSONResponse(
                {"ok": False, "error": "invalid_kind", "message": "kind 仅支持 mcp 或 readonly。"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )
        rotate_flag = parse_bool_flag(data.get("rotate"), default=False)
        snap = _state_snapshot(request)
        if not snap.get("public_https_ready"):
            return JSONResponse(
                {
                    "ok": False,
                    "error": "gateway_not_ready",
                    "message": "公网 HTTPS 通道尚未就绪，请等待连接就绪后再生成一键配置地址。",
                },
                status_code=409,
                headers={"Cache-Control": "no-store"},
            )
        raw_mcp_url = str(snap.get("mcp_url") or "").strip()
        parsed_u = urlsplit(raw_mcp_url)
        host_only = (parsed_u.hostname or "").strip().lower()
        if parsed_u.scheme.lower() != "https" or not parsed_u.netloc or host_only in ("127.0.0.1", "localhost", "::1"):
            return JSONResponse(
                {
                    "ok": False,
                    "error": "gateway_not_ready",
                    "message": "当前未检测到可用的公网 HTTPS 网关地址。",
                },
                status_code=409,
                headers={"Cache-Control": "no-store"},
            )
        is_ro = kind == "readonly"
        if hasattr(provider, "get_or_mint_oneclick_capability_token"):
            minted_oc = provider.get_or_mint_oneclick_capability_token(readonly=is_ro, rotate=rotate_flag)
        else:
            minted_oc = store.get_or_mint_oneclick_capability_token(readonly=is_ro, rotate=rotate_flag)
        ep_suffix = "/mcp/readonly" if is_ro else "/mcp"
        oneclick_url = f"https://{parsed_u.netloc}/c/{minted_oc['token']}{ep_suffix}"
        return JSONResponse(
            {
                "ok": True,
                "oneclick_url": oneclick_url,
                "client_id": str(minted_oc["client_id"]),
                "client_name": str(minted_oc["client_name"]),
                "readonly": is_ro,
                "reused": bool(minted_oc.get("reused", False)),
                "expires_at": int(minted_oc.get("expires_at") or 0),
            },
            status_code=200,
            headers={"Cache-Control": "no-store"},
        )

    async def studio_identity_export_png_ep(request: Request) -> Response:
        data, _ = await _parse_request_data(request)
        if data is None:
            return JSONResponse({"ok": False, "error": "请求格式无效。"}, status_code=400)
        err_resp, minted = _check_studio_auth(request, data)
        if err_resp is not None:
            return err_resp

        passphrase = str(data.get("passphrase") or "").strip()
        if not passphrase:
            return JSONResponse({"ok": False, "error": "请设置身份恢复卡加密口令。"}, status_code=400)
        try:
            png_bytes = await asyncio.to_thread(
                export_identity_recovery_png,
                policy.state_root,
                passphrase,
                prefix=policy.eff_prefix,
            )
            seed_info = ensure_master_seed_identity(policy.state_root, prefix=policy.eff_prefix)
            node_id = str(seed_info.get("node_id") or "node")
        except ValueError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

        filename = f"cosmos-identity-{node_id}.png"
        wants_binary = (
            str(data.get("format") or "").strip().lower() in ("binary", "png", "raw")
            or "image/png" in (request.headers.get("accept") or "").lower()
        )
        if wants_binary:
            resp = Response(
                png_bytes,
                status_code=200,
                media_type="image/png",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Cache-Control": "no-store",
                },
            )
            if minted:
                is_lb = is_strict_direct_loopback(request, port)
                session_mgr.attach_cookie(resp, provider, is_loopback=is_lb, is_https=get_public_url().startswith("https://"))
            return resp

        return _json_with_optional_cookie(
            {
                "ok": True,
                "node_id": node_id,
                "filename": filename,
                "mime_type": "image/png",
                "png_base64": base64.b64encode(png_bytes).decode("ascii"),
                "message": "已生成加密节点身份恢复卡 PNG。",
            },
            request,
            minted,
        )

    async def studio_identity_import_png_ep(request: Request) -> Response:
        ctype = (request.headers.get("content-type") or "").lower()
        png_bytes = b""
        if "multipart/form-data" in ctype:
            form = await request.form()
            data: Dict[str, Any] = {}
            for fk, fv in form.items():
                if hasattr(fv, "read"):
                    png_bytes = await fv.read()  # type: ignore[misc]
                else:
                    data[str(fk)] = str(fv)
        else:
            parsed_d, _ = await _parse_request_data(request)
            if parsed_d is None:
                return JSONResponse({"ok": False, "error": "请求格式无效。"}, status_code=400)
            data = parsed_d
            raw_b64 = str(data.get("png_base64") or data.get("png_data") or "").strip()
            if "," in raw_b64 and raw_b64.lower().startswith("data:"):
                raw_b64 = raw_b64.split(",", 1)[1].strip()
            if raw_b64:
                try:
                    png_bytes = base64.b64decode(raw_b64)
                except Exception:
                    return JSONResponse({"ok": False, "error": "PNG Base64 数据解码失败。"}, status_code=400)

        err_resp, minted = _check_studio_auth(request, data)
        if err_resp is not None:
            return err_resp

        passphrase = str(data.get("passphrase") or "").strip()
        if not passphrase:
            return JSONResponse({"ok": False, "error": "请输入导出该身份恢复卡时设置的口令。"}, status_code=400)
        if not png_bytes:
            return JSONResponse({"ok": False, "error": "请上传有效的身份恢复卡 PNG 图片。"}, status_code=400)

        try:
            restored = await asyncio.to_thread(
                import_identity_recovery_png,
                png_bytes,
                passphrase,
                policy.state_root,
                prefix=policy.eff_prefix,
            )
        except ValueError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

        restored_node_id = str(restored.get("node_id") or "")
        restored_tm = str(restored.get("restored_tunnel_mode") or "").strip().lower()
        restored_dom = str(restored.get("workers_custom_domain") or "").strip()
        restored_wurl = str(restored.get("workers_dev_url") or "").strip().rstrip("/")
        if policy.cfg_path is None:
            cand_cfg_p = resolve_service_cfg_path(policy.state_root, policy.eff_prefix)
            if cand_cfg_p.is_file():
                policy.cfg_path = cand_cfg_p
        policy.refresh(force=True)
        if restored_tm == "workers_dev" and (restored_dom or restored_wurl):
            eff_restored_pub = (
                f"https://{restored_dom}"
                if restored_dom and "://" not in restored_dom
                else (restored_dom or restored_wurl)
            ).strip().rstrip("/")
            cur_slots_imp, _, _ = _normalize_studio_gateways_cfg(policy, _read_saved_extra_cfg(policy))
            other_en_imp = sum(1 for g in STUDIO_GATEWAY_IDS if g != "workers_dev" and cur_slots_imp[g]["enabled"])
            if eff_restored_pub.startswith("https://"):
                _safe_hot_refresh_gateway_url(
                    policy.state_root,
                    eff_restored_pub,
                    port=port,
                    prefix=policy.eff_prefix,
                    tunnel_mode="workers_dev",
                    gateway_id="workers_dev",
                    other_enabled_count=other_en_imp,
                )
            _persist_extra_studio_config(
                policy,
                workers_dev_url=restored_wurl or eff_restored_pub,
                workers_dev_custom_domain=restored_dom,
            )
            _update_studio_gateway_slot(
                policy,
                "workers_dev",
                enabled=True,
                submode="workers_dev",
                public_url=eff_restored_pub,
                select=True,
                extra_slot_fields={"custom_domain": restored_dom},
                port=port,
                set_public_url=set_public_url,
            )
        elif restored.get("has_srvus_key") and getattr(policy, "tunnel_mode", "") == "public_gateway":
            _persist_extra_studio_config(policy, public_url="", prefer_quick_tunnel=False)
            _update_studio_gateway_slot(
                policy,
                "instant",
                enabled=True,
                submode="public_gateway",
                public_url="",
                port=port,
                set_public_url=set_public_url,
            )
        policy.refresh(force=True)
        try:
            policy.persist_changes(public_gateway_node_id=restored_node_id)
        except Exception:
            pass
        snap = _state_snapshot(request)
        snap["restored_identity"] = {
            "node_id": restored_node_id,
            "restored": True,
            "restored_tunnel_mode": restored_tm,
            "has_srvus_key": bool(restored.get("has_srvus_key")),
        }
        snap["message"] = f"已恢复固定节点身份：{restored_node_id}"
        return _json_with_optional_cookie(snap, request, minted)

    async def studio_workspaces_pick_native_ep(request: Request) -> Response:
        data, _ = await _parse_request_data(request)
        if data is None:
            return JSONResponse({"ok": False, "error": "请求格式无效。"}, status_code=400)
        err_resp, minted = _check_studio_auth(request, data)
        if err_resp is not None:
            return err_resp

        raw_title = str(data.get("title") or "选择授权编程目录").strip() or "选择授权编程目录"
        raw_init = str(data.get("initial_dir") or policy.primary_workspace or "").strip()
        add_now = parse_bool_flag(data.get("add_immediately"), default=True)

        pick_res = await asyncio.to_thread(
            pick_directory_native,
            title=raw_title,
            initial_dir=raw_init,
        )
        if not pick_res.get("ok") or not pick_res.get("path"):
            return _json_with_optional_cookie(dict(pick_res), request, minted, status_code=200)

        try:
            cand = _validate_workspace_candidate(str(pick_res["path"]), policy.state_root)
        except ValueError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

        if add_now:
            roots = list(policy.workspace_roots)
            if all(os.path.normcase(str(r)) != os.path.normcase(str(cand)) for r in roots):
                roots.append(cand)
            ro_roots = list(getattr(policy, "readonly_workspace_roots", ()))
            req_acc = str(data.get("access") or "").strip().lower()
            if req_acc == "readonly" and len(roots) > 1 and os.path.normcase(str(roots[0])) != os.path.normcase(str(cand)):
                if all(os.path.normcase(str(x)) != os.path.normcase(str(cand)) for x in ro_roots):
                    ro_roots.append(cand)
            policy.persist_changes(workspace_roots=roots, readonly_workspace_roots=ro_roots)
            _persist_extra_studio_config(policy, readonly_workspace_roots=ro_roots)
            snap = _state_snapshot(request)
            snap["selected_path"] = str(cand)
            snap["path"] = str(cand)
            snap["added"] = True
            snap["message"] = f"已选择并添加工作目录：{cand}"
            return _json_with_optional_cookie(snap, request, minted)

        return _json_with_optional_cookie(
            {"ok": True, "path": str(cand), "selected_path": str(cand), "added": False},
            request,
            minted,
        )

    async def studio_workspaces_discover_ep(request: Request) -> Response:
        cookie_ok = session_mgr.verify_token(request.cookies.get(STUDIO_SESSION_COOKIE, ""), provider)
        if not cookie_ok:
            err_resp, minted = _check_studio_auth(request, {"csrf": request.headers.get("x-studio-csrf", "")})
            if err_resp is not None:
                return err_resp
        else:
            minted = False

        raw_max = request.query_params.get("max_results")
        try:
            cap = max(1, min(48, int(raw_max))) if raw_max else 24
        except ValueError:
            cap = 24
        found = await asyncio.to_thread(
            discover_common_code_directories,
            state_root=policy.state_root,
            max_results=cap,
        )
        cur_norms = {os.path.normcase(str(p.resolve())) for p in policy.workspace_roots}
        items: List[Dict[str, Any]] = []
        for entry in found or ():
            p_str = str(entry.get("path") or "").strip()
            if not p_str:
                continue
            try:
                p_norm = os.path.normcase(str(Path(p_str).resolve()))
            except OSError:
                p_norm = os.path.normcase(p_str)
            items.append(
                {
                    **entry,
                    "already_added": p_norm in cur_norms,
                }
            )
        return _json_with_optional_cookie(
            {"ok": True, "count": len(items), "directories": items},
            request,
            minted,
        )

    async def oauth_local_bridge_fallback_ep(request: Request) -> Response:
        if handle_oauth_local_bridge_request is not None:
            return await handle_oauth_local_bridge_request(provider, request, expected_port=port)
        return await provider.local_bridge(request, expected_port=port)  # type: ignore[attr-defined]

    async def consent_complete_fallback_ep(request: Request) -> Response:
        if handle_consent_complete_request is not None:
            return await handle_consent_complete_request(provider, request)
        return await provider.consent_complete(request)  # type: ignore[attr-defined]

    async def local_admin_ep(request: Request) -> Response:
        return await handle_local_admin_permissions(
            request,
            policy=policy,
            dispatcher=dispatcher,
            store=store,
            provider=provider,
            port=port,
            get_public_url=get_public_url,
            local_admin_csrf=local_admin_csrf,
            local_api_token=local_api_token,
            session_mgr=session_mgr,
        )

    rebuilt_routes: List[Any] = [
        Route("/favicon.ico", endpoint=favicon_ep, methods=["GET"]),
        Route("/static/brand/{brand_file}", endpoint=static_brand_asset_ep, methods=["GET"]),
        Route("/static/showcase/{showcase_file}", endpoint=static_showcase_asset_ep, methods=["GET"]),
        Route("/static/tutorials/{tut_file}", endpoint=static_tutorial_img_ep, methods=["GET"]),
        Route("/static/{asset_name}", endpoint=static_asset_ep, methods=["GET"]),
        Route("/studio", endpoint=studio_page_ep, methods=["GET"]),
        Route("/tutorials", endpoint=tutorials_page_ep, methods=["GET"]),
        Route("/tutorials.md", endpoint=tutorials_md_ep, methods=["GET", "HEAD"]),
        Route("/llms.txt", endpoint=tutorials_md_ep, methods=["GET", "HEAD"]),
        Route("/api/studio/state", endpoint=studio_state_ep, methods=["GET"]),
        Route("/api/studio/poll", endpoint=studio_poll_ep, methods=["GET"]),
        Route("/api/studio/unlock", endpoint=studio_unlock_ep, methods=["POST"]),
        Route("/api/studio/lock", endpoint=studio_lock_ep, methods=["POST"]),
        Route("/api/studio/fs-tree", endpoint=studio_fs_tree_ep, methods=["GET"]),
        Route("/api/studio/workspace", endpoint=studio_workspace_ep, methods=["POST"]),
        Route("/api/studio/workspaces/pick_native", endpoint=studio_workspaces_pick_native_ep, methods=["POST"]),
        Route("/api/studio/workspaces/discover", endpoint=studio_workspaces_discover_ep, methods=["GET"]),
        Route("/api/studio/gateway/cloudflare/deploy", endpoint=studio_gateway_cf_deploy_ep, methods=["POST"]),
        Route("/api/studio/gateway/vps/provision", endpoint=studio_gateway_vps_provision_ep, methods=["POST"]),
        Route("/api/studio/identity/export_png", endpoint=studio_identity_export_png_ep, methods=["POST"]),
        Route("/api/studio/identity/import_png", endpoint=studio_identity_import_png_ep, methods=["POST"]),
        Route("/api/studio/tokens/mint", endpoint=studio_tokens_mint_ep, methods=["POST"]),
        Route("/api/studio/chatgpt-oneclick", endpoint=studio_chatgpt_oneclick_ep, methods=["POST"]),
        Route("/api/studio/tools-safety", endpoint=studio_tools_safety_ep, methods=["POST"]),
        Route("/api/studio/connection", endpoint=studio_connection_ep, methods=["POST"]),
        Route("/api/studio/connectivity-check", endpoint=studio_connectivity_check_ep, methods=["POST"]),
        Route("/api/studio/tasks", endpoint=studio_tasks_ep, methods=["GET", "POST"]),
        Route("/api/studio/recovery", endpoint=studio_recovery_ep, methods=["GET", "POST"]),
        Route("/api/studio/recovery/diff", endpoint=studio_recovery_diff_ep, methods=["GET"]),
        Route("/api/studio/service-control", endpoint=studio_service_control_ep, methods=["POST"]),
        Route("/api/studio/uninstall", endpoint=studio_uninstall_ep, methods=["POST"]),
        Route("/api/studio/skills/{subpath:path}", endpoint=studio_skills_ep, methods=["GET", "POST"]),
    ]
    has_status_route = False
    has_local_bridge_route = False
    has_consent_complete_route = False
    for r in app.router.routes:
        if isinstance(r, Route) and r.path == "/":
            orig_root_ep = r.endpoint
            rebuilt_routes.append(Route("/", endpoint=standalone_root, methods=r.methods))
            rebuilt_routes.append(Route("/status", endpoint=standalone_root, methods=r.methods))
            has_status_route = True
        elif isinstance(r, Route) and r.path == "/status":
            if not has_status_route:
                rebuilt_routes.append(Route("/status", endpoint=standalone_root, methods=r.methods))
                has_status_route = True
        elif isinstance(r, Route) and r.path == "/local-admin/permissions":
            rebuilt_routes.append(Route("/local-admin/permissions", endpoint=local_admin_ep, methods=r.methods))
        elif isinstance(r, Route) and r.path in ("/mcp", "/mcp/readonly"):
            if isinstance(r.endpoint, OriginGuardASGI):
                origin_guards.append(r.endpoint)
            sfx = "/mcp/readonly" if r.path == "/mcp/readonly" else "/mcp"
            wrapped_mcp = McpBrowserGuideASGI(
                r.app,
                lambda s=sfx: _res_meta_for(s),
            )
            rebuilt_routes.append(Route(r.path, endpoint=wrapped_mcp, methods=r.methods))
        elif isinstance(r, Route) and r.path == "/authorize":
            issuer_middlewares.append(r.endpoint)
            rebuilt_routes.append(Route("/authorize", endpoint=AuthorizeBrowserGuideASGI(r.app), methods=r.methods))
        else:
            if isinstance(r, Route) and r.path in ("/tutorials.md", "/llms.txt"):
                continue
            if isinstance(r, Route) and r.path == "/oauth/local-bridge":
                has_local_bridge_route = True
            elif isinstance(r, Route) and r.path == "/consent/complete":
                has_consent_complete_route = True
            rebuilt_routes.append(r)
    if not has_local_bridge_route:
        rebuilt_routes.append(Route("/oauth/local-bridge", endpoint=oauth_local_bridge_fallback_ep, methods=["GET"]))
    if not has_consent_complete_route:
        rebuilt_routes.append(Route("/consent/complete", endpoint=consent_complete_fallback_ep, methods=["GET"]))
        rebuilt_routes.append(Route("/u/{node_id}/consent/complete", endpoint=consent_complete_fallback_ep, methods=["GET"]))
    app.router.routes[:] = rebuilt_routes
    app.state.local_admin_csrf = local_admin_csrf
    app.state.unlock_csrf = unlock_csrf
    app.state.studio_session_mgr = session_mgr
    app.state.get_public_url = get_public_url
    return local_admin_csrf, origin_guards, issuer_middlewares
