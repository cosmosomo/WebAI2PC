"""Deep-redacting `doctor [--bundle]` diagnostics and idempotent `uninstall [--purge] [--dry-run]`.

Enforces:
- 100% pure Python stdlib + `cosmos_mcp.core` + sibling cold-start modules.
- Recursive dictionary + string privacy scrubbing (`password`, `local_api_token`, `tunnel_token`,
  `proxy_endpoint` userinfo credentials, `master_seed`, `vps_host`, `socket.gethostname()`,
  `Bearer`, `lpcmcp_*`, `trycloudflare.com` / `srv.us` / `workers.dev` subdomains, email addresses,
  OS username, home paths, and non-`Users` workspace drive paths).
- Honest `service_online` & `gateway_healthy` diagnostics and `state_root`-scoped autostart lookup.
- `uninstall` stops running services, cleans autostart, unbinds desktop configs with zero neighbor damage,
  isolates non-default `--prefix <name>` cleanup without breaking shared `.venv`, and BY DEFAULT
  preserves `.undo_history` / `history` / `trash` recovery directories (prompting `--purge` for full shred).
"""
from __future__ import annotations

import concurrent.futures
import contextlib
import getpass
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple
import urllib.error
from urllib.parse import urlsplit
import urllib.request
import zipfile

from cosmos_mcp.core.fs_tx import safe_trash_file
from cosmos_mcp.core.net_power import detect_configured_proxy
from cosmos_mcp.core.proc import CREATE_NO_WINDOW, read_log_tail_bounded
from cosmos_mcp.launcher.autostart import (
    disable_autostart,
    get_autostart_status,
    unregister_windows_uninstall_entry,
)
from cosmos_mcp.launcher.bootstrap import (
    check_runtime_deps_ready,
    find_embedded_python_exe,
    find_suitable_python,
    resolve_windows_system_exe,
    venv_python_path,
)
from cosmos_mcp.launcher.clients import unbind_desktop_clients
from cosmos_mcp.launcher.daemon import detect_running_instance, stop_daemon
from cosmos_mcp.launcher.tunnels import load_tunnel_token, probe_public_healthz_end_to_end

DETACHED_PROCESS = 0x00000008

UNINSTALL_PURGE_HINT_ZH = (
    "提示：默认卸载已将文件移入可恢复回收箱并保留共享 .venv；"
    "如需彻底粉碎全部凭据、OAuth 令牌与 .venv 运行环境，请使用 `cosmos-mcp uninstall --purge -y`。"
)

SENSITIVE_DICT_KEYS: Set[str] = {
    "password",
    "owner_password",
    "connection_password",
    "password_hash",
    "salt",
    "local_api_token",
    "admin_token",
    "access_token",
    "refresh_token",
    "tunnel_token",
    "cloudflare_api_token",
    "workers_tunnel_secret",
    "public_gateway_secret",
    "endpoint_secret",
    "master_seed",
    "master_seed_hex",
    "master_seed_b64",
    "client_secret",
    "secret",
    "authorization",
    "cookie",
    "set-cookie",
    "csrf",
    "csrf_token",
    "local_admin_csrf",
    "account_id",
    "workers_account_id",
    "workers_dev_account_id",
    "vps_ssh",
    "vps_ssh_target",
    "vps_host",
    "vps_node_secret",
}

WORKSPACE_PATH_DICT_KEYS: Set[str] = {
    "workspace",
    "default_workspace",
    "workspace_roots",
    "readonly_workspace_roots",
}

_GENERIC_HOST_USER_NAMES: Set[str] = {
    "localhost",
    "runner",
    "root",
    "user",
    "admin",
    "ubuntu",
    "cosmos",
    "pc",
    "test",
}

_URL_USERINFO_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://)([^/@\s\"']+):([^@\s\"']+)@")
_BEARER_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
_LPCMCP_TOK_RE = re.compile(r"\b(?:lpcmcp|cmcp)_[A-Za-z0-9_-]{8,}\b")
_CF_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_+/-])(?:eyJ[A-Za-z0-9_+/=-]{24,}|cfut_[A-Za-z0-9_-]{16,})(?![A-Za-z0-9_+/=-])")
_ACCOUNT_ID_KV_RE = re.compile(r'((?:"account_id"|account_id)\s*[:=]\s*"?)[0-9a-fA-F]{32}("?)', re.IGNORECASE)
_MASTER_SEED_HEX_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
_READABLE_PW_RE = re.compile(r"\b[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{5}(?:-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{5}){3}\b")
_CONN_PW_LINE_RE = re.compile(r"(授权页?连接口令\s*:\s*)([^\r\n]+)")
_TRYCF_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com", re.IGNORECASE)
_SRVUS_RE = re.compile(r"https://[a-z0-9-]+\.srv\.us", re.IGNORECASE)
_WORKERS_DEV_RE = re.compile(r"https://[a-z0-9.-]+\.workers\.dev", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_WIN_USER_RE = re.compile(r"[A-Za-z]:\\Users\\[^\\\s\"']+", re.IGNORECASE)
_WIN_USER_SLASH_RE = re.compile(r"[A-Za-z]:/Users/[^/\s\"']+", re.IGNORECASE)
_POSIX_USER_RE = re.compile(r"/(?:Users|home)/[^/\s\"']+")
_NON_USER_WIN_DRIVE_RE = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z]):[\\/](?!(?:Users|Windows|Program Files|Program Files \(x86\)|ProgramData)(?:[\\/]|$))[^\s\"',;<>|]+",
    re.IGNORECASE,
)


def redact_text(raw: str, *, extra_secrets: Sequence[str] = ()) -> str:
    if not raw:
        return raw
    text = str(raw)
    for sec in extra_secrets:
        if sec and len(sec) >= 4:
            text = text.replace(sec, "[REDACTED]")
    text = _URL_USERINFO_RE.sub(r"\1[REDACTED_AUTH]@", text)
    text = _BEARER_RE.sub(r"\1[REDACTED_TOKEN]", text)
    text = _LPCMCP_TOK_RE.sub("cmcp_[REDACTED]", text)
    text = _CF_TOKEN_RE.sub("[REDACTED_TUNNEL_TOKEN]", text)
    text = _ACCOUNT_ID_KV_RE.sub(r"\1[REDACTED_ACCOUNT_ID]\2", text)
    text = _CONN_PW_LINE_RE.sub(r"\1[REDACTED_PASSWORD]", text)
    text = _READABLE_PW_RE.sub("[REDACTED_PASSWORD]", text)
    text = _MASTER_SEED_HEX_RE.sub("[REDACTED_HEX_SECRET]", text)
    text = _TRYCF_RE.sub("https://[REDACTED-TUNNEL].trycloudflare.com", text)
    text = _SRVUS_RE.sub("https://[REDACTED-TUNNEL].srv.us", text)
    text = _WORKERS_DEV_RE.sub("https://[REDACTED-GATEWAY].workers.dev", text)
    text = _EMAIL_RE.sub("[REDACTED_EMAIL]", text)

    try:
        home_str = str(Path.home())
        if home_str and len(home_str) > 3:
            text = text.replace(home_str, "<USER_HOME>")
            text = text.replace(home_str.replace("\\", "/"), "<USER_HOME>")
    except Exception:
        pass

    text = _WIN_USER_RE.sub("<USER_HOME>", text)
    text = _WIN_USER_SLASH_RE.sub("<USER_HOME>", text)
    text = _POSIX_USER_RE.sub("<USER_HOME>", text)
    text = _NON_USER_WIN_DRIVE_RE.sub("<WORKSPACE_PATH>", text)

    try:
        uname = (getpass.getuser() or "").strip()
        if uname and len(uname) >= 3 and uname.lower() not in _GENERIC_HOST_USER_NAMES:
            text = re.sub(re.escape(uname), "<USER>", text, flags=re.IGNORECASE)
    except Exception:
        pass

    try:
        hname = (socket.gethostname() or "").strip()
        if hname and len(hname) >= 3 and hname.lower() not in _GENERIC_HOST_USER_NAMES:
            text = re.sub(re.escape(hname), "<HOSTNAME>", text, flags=re.IGNORECASE)
    except Exception:
        pass
    return text


_redact_text = redact_text


def _redact_workspace_value(val: Any) -> Any:
    if isinstance(val, str):
        return "<WORKSPACE_PATH>" if val.strip() else ""
    if isinstance(val, (list, tuple)):
        return ["<WORKSPACE_PATH>" for x in val if str(x or "").strip()]
    return val


def redact_diagnostic_data(obj: Any, *, extra_secrets: Sequence[str] = (), _depth: int = 0) -> Any:
    """Recursively scrub secrets, proxy credentials, hostnames, and workspace paths from `obj`."""
    if _depth > 12:
        return "[MAX_DEPTH]"
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            k_str = str(k)
            k_low = k_str.strip().lower()
            if k_low in SENSITIVE_DICT_KEYS or any(
                k_low.endswith(sfx) for sfx in ("_password", "_secret", "_token", "password_hash")
            ):
                out[k_str] = "[REDACTED]"
            elif k_low in WORKSPACE_PATH_DICT_KEYS:
                out[k_str] = _redact_workspace_value(v)
            else:
                out[k_str] = redact_diagnostic_data(v, extra_secrets=extra_secrets, _depth=_depth + 1)
        return out
    if isinstance(obj, list):
        return [redact_diagnostic_data(x, extra_secrets=extra_secrets, _depth=_depth + 1) for x in obj]
    if isinstance(obj, tuple):
        return [redact_diagnostic_data(x, extra_secrets=extra_secrets, _depth=_depth + 1) for x in obj]
    if isinstance(obj, str):
        stripped = obj.strip()
        if _depth < 4 and len(stripped) <= 262_144 and stripped[:1] in ("{", "["):
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, (dict, list)):
                    red_inner = redact_diagnostic_data(parsed, extra_secrets=extra_secrets, _depth=_depth + 1)
                    return json.dumps(red_inner, ensure_ascii=False)
            except Exception:
                pass
        return redact_text(obj, extra_secrets=extra_secrets)
    return obj


def _collect_known_secrets(state_root: Path) -> tuple[str, ...]:
    found: List[str] = []
    sec_dir = state_root / "secrets"
    auth_p = sec_dir / "auth.json"
    if auth_p.is_file():
        try:
            doc = json.loads(auth_p.read_text(encoding="utf-8-sig"))
            if isinstance(doc, dict):
                for k in ("local_api_token", "password_hash", "salt"):
                    val = str(doc.get(k) or "").strip()
                    if val:
                        found.append(val)
        except Exception:
            pass
    if sec_dir.is_dir():
        for sec_pat in (
            "tunnel_token*.txt",
            "cloudflare_api_token*.txt",
            "workers_tunnel_secret*.txt",
            "public_gateway_secret*.txt",
            "vps_node_secret*.txt",
            "endpoint_secret*.txt",
            "local_vault*.key",
            "master_seed*",
        ):
            for tf in sec_dir.glob(sec_pat):
                if not tf.is_file():
                    continue
                try:
                    if tf.suffix.lower() == ".bin":
                        raw_b = tf.read_bytes()
                        if raw_b:
                            found.append(raw_b.hex())
                    else:
                        tok = tf.read_text(encoding="utf-8", errors="replace").strip()
                        if tok:
                            found.append(tok)
                except Exception:
                    pass
    dotenv_p = state_root / ".env"
    if dotenv_p.is_file():
        try:
            for raw_ln in dotenv_p.read_text(encoding="utf-8", errors="replace").splitlines():
                s_ln = raw_ln.strip()
                if not s_ln or s_ln.startswith("#") or "=" not in s_ln:
                    continue
                _, raw_v = s_ln.split("=", 1)
                clean_v = raw_v.strip().strip("\"'")
                if len(clean_v) >= 6 and clean_v.lower() not in ("true", "false", "tier1_readonly", "tier2_workspace_edit", "tier3_workspace_dev", "tier4_full_power"):
                    found.append(clean_v)
        except Exception:
            pass
    cfg_dir = state_root / "config"
    if cfg_dir.is_dir():
        for cf in cfg_dir.glob("service*.json"):
            try:
                cdoc = json.loads(cf.read_text(encoding="utf-8-sig"))
                if isinstance(cdoc, dict):
                    for k_sec in ("vps_host", "vps_ssh", "vps_node_secret"):
                        vv = str(cdoc.get(k_sec) or "").strip()
                        if vv and len(vv) >= 4:
                            found.append(vv)
                    for w_val in (cdoc.get("workspace_roots") or []) + (cdoc.get("readonly_workspace_roots") or []):
                        ws_s = str(w_val or "").strip()
                        if ws_s and len(ws_s) >= 4:
                            found.append(ws_s)
                    ws_single = str(cdoc.get("workspace") or "").strip()
                    if ws_single and len(ws_single) >= 4:
                        found.append(ws_single)
            except Exception:
                continue
    for conn_f in state_root.glob("*CONNECTION_INFO*.txt"):
        try:
            m = _CONN_PW_LINE_RE.search(conn_f.read_text(encoding="utf-8", errors="replace"))
            if m and m.group(2).strip() and not m.group(2).strip().startswith("("):
                found.append(m.group(2).strip())
        except Exception:
            pass
    # Sort longest-first so full strings replace before substrings
    deduped = sorted({s for s in found if s and len(s) >= 4}, key=len, reverse=True)
    return tuple(deduped)


def _has_secret_file(state_root: Path, base_stem: str, prefix: str) -> bool:
    sec_dir = state_root / "secrets"
    cands = [sec_dir / f"{base_stem}_{prefix}.txt", sec_dir / f"{base_stem}.txt"] if prefix != "pc" else [sec_dir / f"{base_stem}.txt"]
    for cp in cands:
        if cp.is_file():
            try:
                if cp.read_text(encoding="utf-8", errors="replace").strip():
                    return True
            except OSError:
                continue
    return False


def _assess_gateway_health(
    state_root: Path,
    prefix: str,
    cfg_doc: Dict[str, Any],
    live: Dict[str, Any],
    *,
    has_cf_token: bool,
) -> Tuple[bool, List[str]]:
    issues: List[str] = []
    eff_mode = str(live.get("mode") or cfg_doc.get("tunnel_mode") or "local").strip().lower()

    if eff_mode == "vps_hub":
        vps_u = str(cfg_doc.get("vps_hub_url") or cfg_doc.get("public_base") or live.get("public_url") or "").strip()
        has_vps_sec = _has_secret_file(state_root, "vps_node_secret", prefix) or bool(str(cfg_doc.get("vps_node_secret") or "").strip())
        if not vps_u:
            issues.append("vps_hub_url_missing")
        if not has_vps_sec:
            issues.append("vps_node_secret_missing")
    elif eff_mode in ("workers_dev", "cf_workers", "cloudflare_workers"):
        wd_u = str(cfg_doc.get("workers_dev_url") or cfg_doc.get("public_base") or live.get("public_url") or "").strip()
        has_wt_sec = _has_secret_file(state_root, "workers_tunnel_secret", prefix)
        if not wd_u:
            issues.append("workers_dev_url_missing")
        if not has_wt_sec:
            issues.append("workers_tunnel_secret_missing")
    elif eff_mode == "cloudflare_token":
        if not has_cf_token:
            issues.append("tunnel_token_missing")
    elif eff_mode == "vps":
        if not str(cfg_doc.get("vps_ssh") or "").strip():
            issues.append("vps_ssh_missing")
    elif eff_mode in ("custom", "reverse_proxy"):
        if not str(cfg_doc.get("public_base") or cfg_doc.get("public_base_url") or live.get("public_url") or "").strip():
            issues.append("public_url_missing")

    last_err = str(live.get("last_error") or "").strip()
    if last_err and ("error" in last_err.lower() or "失败" in last_err or "未配置" in last_err):
        issues.append("daemon_tunnel_error")

    live_gws = live.get("gateways")
    if isinstance(live_gws, dict):
        for gw_id, gw_st in live_gws.items():
            if isinstance(gw_st, dict) and gw_st.get("enabled") and str(gw_st.get("state") or "").lower() == "error":
                issues.append(f"gateway_{gw_id}_error")

    return len(issues) == 0, issues


_GATEWAY_LABELS_ZH: Dict[str, str] = {
    "instant": "第 1 类 · 免登录直连",
    "workers_dev": "第 2 类 · Cloudflare 固定网关",
    "self_hosted": "第 3 类 · 自有服务器 / 域名",
}

_GATEWAY_LABELS_EN: Dict[str, str] = {
    "instant": "Channel 1 · Direct Tunnel",
    "workers_dev": "Channel 2 · Cloudflare Gateway",
    "self_hosted": "Channel 3 · Custom Server / Domain",
}

_PLACEHOLDER_GW_HOSTS: Set[str] = {
    "gw.cosmos-mcp.org",
    "gw.cosmos-mcp.workers.dev",
}


def mask_public_url_for_display(raw_url: str, *, full_subdomain_mask: bool = False) -> str:
    """Mask gateway hostnames and `/u/<secret>` stealth prefixes so URLs are safe to display or share."""
    clean = (raw_url or "").strip()
    if not clean or "://" not in clean:
        return ""
    u = urlsplit(clean)
    scheme = (u.scheme or "https").lower()
    host = (u.hostname or "").strip().lower()
    if not host:
        return ""
    try:
        port = u.port
    except ValueError:
        port = None

    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        octs = host.split(".")
        masked_host = "***.***.***.***" if full_subdomain_mask else f"{octs[0]}.***.***.{octs[3]}"
    elif host in ("127.0.0.1", "localhost", "::1"):
        masked_host = "***" if full_subdomain_mask else host
    elif host.endswith(".srv.us"):
        sub = host[: -len(".srv.us")]
        masked_host = "***.srv.us" if (full_subdomain_mask or len(sub) <= 4) else f"{sub[:4]}***.srv.us"
    elif host.endswith(".trycloudflare.com"):
        sub = host[: -len(".trycloudflare.com")]
        masked_host = (
            "***.trycloudflare.com"
            if (full_subdomain_mask or len(sub) <= 4)
            else f"{sub[:4]}***.trycloudflare.com"
        )
    elif host.endswith(".workers.dev"):
        sub = host[: -len(".workers.dev")]
        first_seg = sub.split(".", 1)[0]
        masked_host = (
            "***.workers.dev"
            if (full_subdomain_mask or len(first_seg) <= 4)
            else f"{first_seg[:4]}***.workers.dev"
        )
    elif "." in host:
        labels = host.split(".")
        if full_subdomain_mask:
            masked_host = f"***.{labels[-1]}"
        else:
            lead = labels[0][:3] if len(labels[0]) > 3 else ""
            masked_host = f"{lead}***.{labels[-1]}" if lead else f"***.{labels[-1]}"
    else:
        masked_host = "***"

    host_fmt = f"[{masked_host}]" if ":" in masked_host and not masked_host.startswith("[") else masked_host
    port_sfx = f":{port}" if (port is not None and port not in (80, 443)) else ""
    if full_subdomain_mask and host in ("127.0.0.1", "localhost", "::1"):
        port_sfx = ""
    raw_path = u.path or ""
    safe_path = re.sub(r"/u/[^/]+", "/u/***", raw_path)
    return f"{scheme}://{host_fmt}{port_sfx}{safe_path}"


def _load_optional_endpoint_secret(state_root: Path, prefix: str, cfg_doc: Dict[str, Any]) -> str:
    cfg_sec = str(cfg_doc.get("endpoint_secret") or "").strip()
    if cfg_sec:
        return cfg_sec
    raw_pfx = str(cfg_doc.get("gateway_path_prefix") or "").strip().strip("/")
    if raw_pfx.lower().startswith("u/") and len(raw_pfx) > 2:
        return raw_pfx[2:].strip("/")
    sec_dir = state_root / "secrets"
    cands = (
        [sec_dir / f"endpoint_secret_{prefix}.txt", sec_dir / "endpoint_secret.txt"]
        if prefix != "pc"
        else [sec_dir / "endpoint_secret.txt"]
    )
    for sp in cands:
        if sp.is_file():
            try:
                val = sp.read_text(encoding="utf-8", errors="replace").strip()
                if val:
                    return val
            except OSError:
                continue
    return ""


def _resolve_gateway_target_urls(raw_url: str, endpoint_secret: str = "") -> Tuple[str, str, str, str]:
    """Return `(origin, public_base, mcp_url, path_prefix)` for a gateway candidate URL."""
    clean = (raw_url or "").strip().rstrip("/")
    if not clean.startswith("https://"):
        return "", "", "", ""
    u0 = urlsplit(clean)
    host0 = (u0.hostname or "").strip().lower()
    if not host0 or host0 in _PLACEHOLDER_GW_HOSTS:
        return "", "", "", ""
    if clean.endswith("/mcp/readonly"):
        base = clean[: -len("/mcp/readonly")].rstrip("/")
    elif clean.endswith("/mcp"):
        base = clean[: -len("/mcp")].rstrip("/")
    else:
        base = clean

    ub = urlsplit(base)
    path_now = (ub.path or "").rstrip("/")
    if endpoint_secret and "/u/" not in path_now.lower():
        public_base = f"{base}/u/{endpoint_secret}"
    else:
        public_base = base
    up = urlsplit(public_base)
    origin = f"{up.scheme}://{up.netloc}"
    path_prefix = (up.path or "").rstrip("/")
    mcp_url = f"{public_base}/mcp"
    return origin, public_base, mcp_url, path_prefix


def _discover_gateway_slots_for_probe(
    state_root: Path,
    prefix: str,
    cfg_doc: Dict[str, Any],
    d_doc: Dict[str, Any],
    *,
    endpoint_secret: str = "",
) -> List[Dict[str, Any]]:
    raw_cfg_gws = cfg_doc.get("gateways") if isinstance(cfg_doc.get("gateways"), dict) else None
    d_running = bool(d_doc and str(d_doc.get("status") or "") not in ("", "stopped"))
    raw_d_gws = d_doc.get("gateways") if (d_running and isinstance(d_doc.get("gateways"), dict)) else None
    legacy_mode = str(d_doc.get("mode") or cfg_doc.get("tunnel_mode") or "local").strip().lower()

    def _legacy_slot_for_mode(m: str) -> Tuple[str, str]:
        if m in ("public_gateway", "srv_us", "cloudflare"):
            return "instant", ("cloudflare" if m == "cloudflare" else "public_gateway")
        if m in ("workers_dev", "cf_workers", "cloudflare_workers"):
            return "workers_dev", "workers_dev"
        if m in ("vps_hub", "vps", "cloudflare_token", "custom", "reverse_proxy"):
            return "self_hosted", ("custom" if m == "reverse_proxy" else m)
        return "", ""

    leg_slot, leg_sub = _legacy_slot_for_mode(legacy_mode)
    slots_out: List[Dict[str, Any]] = []

    for gid, default_sub in (
        ("instant", "public_gateway"),
        ("workers_dev", "workers_dev"),
        ("self_hosted", "vps_hub"),
    ):
        c_slot = (raw_cfg_gws or {}).get(gid) if isinstance(raw_cfg_gws, dict) else None
        d_slot = (raw_d_gws or {}).get(gid) if isinstance(raw_d_gws, dict) else None

        if isinstance(c_slot, dict):
            enabled = bool(c_slot.get("enabled", False))
            submode = str(c_slot.get("submode") or default_sub).strip().lower()
            cfg_u = str(c_slot.get("public_url") or "").strip()
            custom_dom = str(c_slot.get("custom_domain") or cfg_doc.get("workers_dev_custom_domain") or "").strip()
        else:
            enabled = bool(leg_slot == gid and legacy_mode != "local")
            submode = leg_sub if leg_slot == gid and leg_sub else default_sub
            if gid == "workers_dev":
                cfg_u = str(cfg_doc.get("workers_dev_url") or (cfg_doc.get("public_base") if enabled else "") or "").strip()
            elif gid == "self_hosted":
                cfg_u = str(cfg_doc.get("vps_hub_url") or (cfg_doc.get("public_base") if enabled else "") or "").strip()
            else:
                cfg_u = str((cfg_doc.get("public_base") if enabled else "") or "").strip()
            custom_dom = str(cfg_doc.get("workers_dev_custom_domain") or "").strip()

        if isinstance(d_slot, dict) and c_slot is None and d_slot.get("enabled") is True:
            enabled = True
            if d_slot.get("submode"):
                submode = str(d_slot["submode"]).strip().lower()

        d_pub = ""
        last_err = ""
        if isinstance(d_slot, dict):
            d_pub = str(d_slot.get("public_url") or "").strip()
            last_err = str(d_slot.get("last_error") or d_slot.get("last_disconnect_reason_zh") or "").strip()
        elif d_running and leg_slot == gid:
            d_pub = str(d_doc.get("public_url") or "").strip()
            last_err = str(d_doc.get("last_error") or "").strip()

        cand_raw = (d_pub or cfg_u) if enabled else cfg_u
        origin, pub_base, mcp_u, path_pfx = _resolve_gateway_target_urls(cand_raw, endpoint_secret=endpoint_secret)
        slots_out.append(
            {
                "gateway_id": gid,
                "label_zh": _GATEWAY_LABELS_ZH[gid],
                "label_en": _GATEWAY_LABELS_EN[gid],
                "enabled": enabled,
                "submode": submode,
                "origin": origin,
                "public_base": pub_base,
                "mcp_url": mcp_u,
                "path_prefix": path_pfx,
                "custom_domain": custom_dom,
                "daemon_last_error": last_err,
            }
        )
    return slots_out


def _build_ssl_context(custom_ctx: Optional[ssl.SSLContext] = None) -> ssl.SSLContext:
    if custom_ctx is not None:
        return custom_ctx
    ctx = ssl.create_default_context()
    env_cafile = (os.environ.get("SSL_CERT_FILE") or "").strip()
    if env_cafile and Path(env_cafile).is_file():
        with contextlib.suppress(Exception):
            ctx.load_verify_locations(cafile=env_cafile)
    return ctx


def _timed_http_request(
    opener: urllib.request.OpenerDirector,
    url: str,
    *,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
    timeout_sec: float = 2.5,
) -> Dict[str, Any]:
    req_hdrs = {"User-Agent": "Cosmos-MCP-Probe/1.2"}
    if headers:
        req_hdrs.update(headers)
    req = urllib.request.Request(url, data=body, headers=req_hdrs, method=method)
    t0 = time.perf_counter()
    try:
        with opener.open(req, timeout=max(0.3, float(timeout_sec))) as resp:
            status_code = int(getattr(resp, "status", 200))
            resp_headers = {str(k).lower(): str(v) for k, v in resp.headers.items()}
            raw_bytes = resp.read(16384)
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 1)
        return {
            "transport_ok": True,
            "http_status": status_code,
            "headers": resp_headers,
            "body": raw_bytes.decode("utf-8", errors="replace"),
            "raw_bytes": raw_bytes,
            "latency_ms": elapsed_ms,
            "error": "",
        }
    except urllib.error.HTTPError as he:
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 1)
        err_bytes = b""
        with contextlib.suppress(Exception):
            err_bytes = he.read(16384)
        resp_headers = {str(k).lower(): str(v) for k, v in he.headers.items()} if he.headers else {}
        return {
            "transport_ok": True,
            "http_status": int(he.code),
            "headers": resp_headers,
            "body": err_bytes.decode("utf-8", errors="replace"),
            "raw_bytes": err_bytes,
            "latency_ms": elapsed_ms,
            "error": f"HTTP {int(he.code)}",
        }
    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 1)
        return {
            "transport_ok": False,
            "http_status": 0,
            "headers": {},
            "body": "",
            "raw_bytes": b"",
            "latency_ms": elapsed_ms,
            "error": str(exc),
        }


def _classify_gateway_healthz_probe(
    base_for_healthz: str,
    opener_director: urllib.request.OpenerDirector,
    timeout_sec: float,
) -> Dict[str, Any]:
    """Run `probe_public_healthz_end_to_end` with timing + header capture and classify Cloudflare/tunnel errors."""
    captured: Dict[str, Any] = {}

    def _opener_cb(req: urllib.request.Request, t_sec: float) -> Tuple[int, bytes]:
        hdr_dict = {str(k): str(v) for k, v in req.header_items()}
        r = _timed_http_request(
            opener_director,
            req.full_url,
            method=req.get_method(),
            headers=hdr_dict,
            timeout_sec=t_sec,
        )
        captured.update(r)
        if not r["transport_ok"]:
            raise urllib.error.URLError(r["error"] or "connection_failed")
        return int(r["http_status"]), bytes(r["raw_bytes"])

    e2e = probe_public_healthz_end_to_end(base_for_healthz, timeout_sec=timeout_sec, opener=_opener_cb)
    code = int(captured.get("http_status") or e2e.get("status_code") or 0)
    body_txt = str(captured.get("body") or e2e.get("body") or "")
    body_low = body_txt.lower()
    hdrs = captured.get("headers") or {}
    lat_ms = float(captured.get("latency_ms") or 0.0)

    if e2e.get("ok") and 200 <= code < 300:
        is_json_ok = True
        if body_txt.strip().startswith("{"):
            with contextlib.suppress(Exception):
                jdoc = json.loads(body_txt)
                if isinstance(jdoc, dict) and jdoc.get("status") not in (None, "ok"):
                    is_json_ok = False
        if is_json_ok:
            return {
                "attempted": True,
                "ok": True,
                "http_status": code,
                "latency_ms": lat_ms,
                "error_code": "",
                "reason_zh": "",
                "reason_en": "",
            }

    is_1027 = bool(e2e.get("cf_error_code") == 1027 or code == 1027 or "error 1027" in body_low or ("1027" in body_low and code >= 400))
    if is_1027:
        return {
            "attempted": True,
            "ok": False,
            "http_status": code,
            "latency_ms": lat_ms,
            "error_code": "cf_1027",
            "reason_zh": "Cloudflare Workers 免费层当日 100,000 次请求额度已耗尽（Error 1027）",
            "reason_en": "Cloudflare Workers Free daily 100,000 request quota is exhausted (Error 1027).",
        }
    if code == 530 or "1033" in body_low:
        return {
            "attempted": True,
            "ok": False,
            "http_status": code,
            "latency_ms": lat_ms,
            "error_code": "cf_530_1033",
            "reason_zh": "隧道边缘暂未连上本机子进程（HTTP 530 / 1033），请等待自动重连或重开该通道",
            "reason_en": "Tunnel edge has not connected to the local subprocess yet (HTTP 530 / 1033). Wait for auto-reconnect or toggle this gateway.",
        }
    if code == 403 and ("cf-mitigated" in hdrs or "just a moment" in body_low or "challenge" in body_low):
        return {
            "attempted": True,
            "ok": False,
            "http_status": code,
            "latency_ms": lat_ms,
            "error_code": "cf_waf_challenge_403",
            "reason_zh": "Cloudflare Bot Fight Mode 或 WAF 托管质询拦截了网关请求（HTTP 403），请在域名后台跳过质询",
            "reason_en": "Cloudflare Bot Fight Mode or WAF Managed Challenge intercepted the gateway request (HTTP 403).",
        }
    if code in (502, 504):
        return {
            "attempted": True,
            "ok": False,
            "http_status": code,
            "latency_ms": lat_ms,
            "error_code": f"http_{code}",
            "reason_zh": f"公网网关可达但回源本机失败（HTTP {code}）",
            "reason_en": f"Public gateway is reachable, but upstream forwarding to local PC failed (HTTP {code}).",
        }
    if code == 503 and "tunnel_offline" in body_low:
        return {
            "attempted": True,
            "ok": False,
            "http_status": code,
            "latency_ms": lat_ms,
            "error_code": "tunnel_offline_503",
            "reason_zh": "云端中继网关在线，但本机 443 WSS 隧道暂未连上（HTTP 503），正在后台自动重连",
            "reason_en": "Cloud relay is online, but local 443 WSS tunnel is disconnected (HTTP 503).",
        }
    if code > 0:
        return {
            "attempted": True,
            "ok": False,
            "http_status": code,
            "latency_ms": lat_ms,
            "error_code": f"http_{code}",
            "reason_zh": f"公网 /healthz 返回异常状态码（HTTP {code}）",
            "reason_en": f"Public /healthz returned unexpected HTTP {code}.",
        }
    raw_err = str(captured.get("error") or e2e.get("error") or "timeout").lower()
    if "1027" in raw_err:
        return {
            "attempted": True,
            "ok": False,
            "http_status": 1027,
            "latency_ms": lat_ms,
            "error_code": "cf_1027",
            "reason_zh": "Cloudflare Workers 免费层当日 100,000 次请求额度已耗尽（Error 1027）",
            "reason_en": "Cloudflare Workers Free daily 100,000 request quota is exhausted (Error 1027).",
        }
    is_timeout = "timed out" in raw_err or "timeout" in raw_err
    return {
        "attempted": True,
        "ok": False,
        "http_status": 0,
        "latency_ms": lat_ms,
        "error_code": "timeout" if is_timeout else "network_unreachable",
        "reason_zh": "请求超时" if is_timeout else "网络连接失败",
        "reason_en": "Request timed out" if is_timeout else "Network connection failed",
    }


def _probe_mcp_protocol_for_gateway(
    slot: Dict[str, Any],
    opener_director: urllib.request.OpenerDirector,
    timeout_sec: float,
) -> Dict[str, Any]:
    """Verify OAuth discovery (`/.well-known/oauth-authorization-server`) and unauthenticated `POST /mcp` 401 Bearer gate."""
    origin = str(slot["origin"])
    pub_base = str(slot["public_base"])
    mcp_url = str(slot["mcp_url"])
    path_pfx = str(slot["path_prefix"])
    masked_u = mask_public_url_for_display(mcp_url, full_subdomain_mask=False)

    wk_primary = f"{pub_base}/.well-known/oauth-authorization-server"
    wk_rfc8414 = f"{origin}/.well-known/oauth-authorization-server{path_pfx}" if path_pfx else ""

    def _run_oauth_meta() -> Dict[str, Any]:
        r = _timed_http_request(
            opener_director,
            wk_primary,
            method="GET",
            headers={"Accept": "application/json"},
            timeout_sec=timeout_sec,
        )
        if r["http_status"] == 404 and wk_rfc8414 and wk_rfc8414 != wk_primary:
            r2 = _timed_http_request(
                opener_director,
                wk_rfc8414,
                method="GET",
                headers={"Accept": "application/json"},
                timeout_sec=timeout_sec,
            )
            if r2["http_status"] != 404:
                return r2
        return r

    def _run_mcp_post() -> Dict[str, Any]:
        ping_body = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
        return _timed_http_request(
            opener_director,
            mcp_url,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            body=ping_body,
            timeout_sec=timeout_sec,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        fut_wk = pool.submit(_run_oauth_meta)
        fut_mcp = pool.submit(_run_mcp_post)
        wk_res = fut_wk.result()
        mcp_res = fut_mcp.result()

    wk_code = int(wk_res["http_status"])
    wk_body_low = str(wk_res["body"] or "").lower()
    wk_hdrs = wk_res["headers"]
    wk_cf_waf = bool(
        wk_code == 403
        and ("cf-mitigated" in wk_hdrs or "just a moment" in wk_body_low or "challenge" in wk_body_low or "cf-chl" in wk_body_low)
    )

    wk_json_ok = False
    if wk_code == 200:
        with contextlib.suppress(Exception):
            wk_doc = json.loads(wk_res["body"])
            if isinstance(wk_doc, dict) and all(
                bool(wk_doc.get(k))
                for k in ("authorization_endpoint", "token_endpoint", "registration_endpoint")
            ):
                wk_json_ok = True

    mcp_code = int(mcp_res["http_status"])
    mcp_hdrs = mcp_res["headers"]
    mcp_body_low = str(mcp_res["body"] or "").lower()
    mcp_cf_waf = bool(
        mcp_code == 403
        and ("cf-mitigated" in mcp_hdrs or "just a moment" in mcp_body_low or "challenge" in mcp_body_low or "cf-chl" in mcp_body_low)
    )
    www_auth = str(mcp_hdrs.get("www-authenticate") or "")
    has_bearer = "bearer" in www_auth.lower()
    mcp_gate_ok = bool(mcp_code == 401 and has_bearer)

    if wk_cf_waf or mcp_cf_waf:
        return {
            "gateway_id": slot["gateway_id"],
            "masked_url": masked_u,
            "status": "error",
            "error_code": "cf_waf_challenge_403",
            "oauth_metadata_ok": False,
            "oauth_http_status": wk_code,
            "oauth_latency_ms": wk_res["latency_ms"],
            "mcp_auth_gate_ok": False,
            "mcp_http_status": mcp_code,
            "mcp_latency_ms": mcp_res["latency_ms"],
            "message_zh": "Cloudflare Bot Fight Mode 或 WAF 托管质询拦截了云端 AI 的 OAuth 自动发现请求（HTTP 403），请在域名后台对 /.well-known/*、/register、/token、/mcp* 跳过质询",
            "message_en": "Cloudflare Bot Fight Mode or WAF Managed Challenge blocked cloud AI OAuth discovery (HTTP 403). Add a WAF Skip rule for /.well-known/*, /register, /token, and /mcp*.",
        }

    if mcp_code == 404:
        return {
            "gateway_id": slot["gateway_id"],
            "masked_url": masked_u,
            "status": "error",
            "error_code": "mcp_route_404",
            "oauth_metadata_ok": wk_json_ok,
            "oauth_http_status": wk_code,
            "oauth_latency_ms": wk_res["latency_ms"],
            "mcp_auth_gate_ok": False,
            "mcp_http_status": mcp_code,
            "mcp_latency_ms": mcp_res["latency_ms"],
            "message_zh": "公网 /mcp 端点返回 HTTP 404，反向代理转发路径或 /u/<secret> 私密路径前缀不匹配",
            "message_en": "Public /mcp endpoint returned HTTP 404. Reverse proxy path or /u/<secret> stealth prefix does not match.",
        }

    if mcp_code == 200:
        return {
            "gateway_id": slot["gateway_id"],
            "masked_url": masked_u,
            "status": "error",
            "error_code": "mcp_unauthenticated_200",
            "oauth_metadata_ok": wk_json_ok,
            "oauth_http_status": wk_code,
            "oauth_latency_ms": wk_res["latency_ms"],
            "mcp_auth_gate_ok": False,
            "mcp_http_status": mcp_code,
            "mcp_latency_ms": mcp_res["latency_ms"],
            "message_zh": "公网 /mcp 在未携带令牌时意外返回 HTTP 200，公网鉴权门禁异常，请立即检查反向代理配置",
            "message_en": "Public /mcp unexpectedly returned HTTP 200 without a token. Check reverse proxy authentication settings immediately.",
        }

    if mcp_code == 421 or wk_code == 421:
        return {
            "gateway_id": slot["gateway_id"],
            "masked_url": masked_u,
            "status": "error",
            "error_code": "untrusted_host_421",
            "oauth_metadata_ok": False,
            "oauth_http_status": wk_code,
            "oauth_latency_ms": wk_res["latency_ms"],
            "mcp_auth_gate_ok": False,
            "mcp_http_status": mcp_code,
            "mcp_latency_ms": mcp_res["latency_ms"],
            "message_zh": "公网网关返回 HTTP 421（域名尚未同步进本机受信任 Host 列表），请在通道设置重新保存该域名",
            "message_en": "Public gateway returned HTTP 421 (Host not yet in local trusted allowlist). Re-save this domain in Gateway Settings.",
        }

    if not wk_json_ok:
        return {
            "gateway_id": slot["gateway_id"],
            "masked_url": masked_u,
            "status": "error",
            "error_code": f"oauth_metadata_http_{wk_code}",
            "oauth_metadata_ok": False,
            "oauth_http_status": wk_code,
            "oauth_latency_ms": wk_res["latency_ms"],
            "mcp_auth_gate_ok": mcp_gate_ok,
            "mcp_http_status": mcp_code,
            "mcp_latency_ms": mcp_res["latency_ms"],
            "message_zh": f"OAuth 自动发现端点 (/.well-known/oauth-authorization-server) 校验未通过（HTTP {wk_code}），请确认反代未拦截 /.well-known/* 路径",
            "message_en": f"OAuth metadata discovery endpoint check failed (HTTP {wk_code}). Ensure /.well-known/* routes are forwarded.",
        }

    if mcp_code == 401 and not has_bearer:
        return {
            "gateway_id": slot["gateway_id"],
            "masked_url": masked_u,
            "status": "warn",
            "error_code": "mcp_missing_bearer_header",
            "oauth_metadata_ok": True,
            "oauth_http_status": wk_code,
            "oauth_latency_ms": wk_res["latency_ms"],
            "mcp_auth_gate_ok": False,
            "mcp_http_status": mcp_code,
            "mcp_latency_ms": mcp_res["latency_ms"],
            "message_zh": "OAuth 元数据正常，但 /mcp 的 401 响应缺少 WWW-Authenticate: Bearer 头（反向代理可能过滤了认证响应头）",
            "message_en": "OAuth metadata OK, but /mcp HTTP 401 response is missing WWW-Authenticate: Bearer header.",
        }

    if not mcp_gate_ok:
        return {
            "gateway_id": slot["gateway_id"],
            "masked_url": masked_u,
            "status": "error",
            "error_code": f"mcp_unexpected_http_{mcp_code}",
            "oauth_metadata_ok": True,
            "oauth_http_status": wk_code,
            "oauth_latency_ms": wk_res["latency_ms"],
            "mcp_auth_gate_ok": False,
            "mcp_http_status": mcp_code,
            "mcp_latency_ms": mcp_res["latency_ms"],
            "message_zh": f"公网 /mcp 协议握手预期返回 401 Bearer 鉴权质询，实际返回 HTTP {mcp_code}",
            "message_en": f"Expected HTTP 401 Bearer challenge on /mcp, got HTTP {mcp_code}.",
        }

    return {
        "gateway_id": slot["gateway_id"],
        "masked_url": masked_u,
        "status": "ok",
        "error_code": "",
        "oauth_metadata_ok": True,
        "oauth_http_status": wk_code,
        "oauth_latency_ms": wk_res["latency_ms"],
        "mcp_auth_gate_ok": True,
        "mcp_http_status": mcp_code,
        "mcp_latency_ms": mcp_res["latency_ms"],
        "message_zh": f"OAuth 自动发现 (200 · {wk_res['latency_ms']}ms) 与 /mcp 鉴权门禁 (401 Bearer · {mcp_res['latency_ms']}ms) 校验通过",
        "message_en": f"OAuth discovery (200 · {wk_res['latency_ms']}ms) and /mcp auth gate (401 Bearer · {mcp_res['latency_ms']}ms) verified.",
    }


def run_connectivity_check(
    state_root: Path,
    *,
    prefix: str = "pc",
    local_port: Optional[int] = None,
    gateway_id: str = "",
    timeout_sec: float = 3.5,
    ssl_context: Optional[ssl.SSLContext] = None,
) -> Dict[str, Any]:
    """Run end-to-end 4-layer backend connectivity diagnostics (loopback -> proxy/deps -> gateways -> OAuth/MCP)."""
    t_start = time.perf_counter()
    st_root = Path(state_root).expanduser().resolve()
    eff_p = (prefix or "pc").strip().lower() or "pc"
    req_gw_id = (gateway_id or "").strip().lower()
    budget_sec = max(0.8, min(float(timeout_sec or 3.5), 3.8))
    extra_sec = _collect_known_secrets(st_root)

    cfg_doc: Dict[str, Any] = {}
    for cfg_cand in (
        st_root / "config" / (f"service_{eff_p}.json" if eff_p != "pc" else "service.json"),
        st_root / "state" / (f"service_{eff_p}.json" if eff_p != "pc" else "service.json"),
        st_root / "config.json",
    ):
        if cfg_cand.is_file():
            try:
                loaded_c = json.loads(cfg_cand.read_text(encoding="utf-8-sig"))
                if isinstance(loaded_c, dict) and loaded_c:
                    cfg_doc = loaded_c
                    break
            except Exception:
                continue

    d_doc: Dict[str, Any] = {}
    d_path = st_root / "state" / (f"daemon_status_{eff_p}.json" if eff_p != "pc" else "daemon_status.json")
    if d_path.is_file():
        try:
            loaded_d = json.loads(d_path.read_text(encoding="utf-8-sig"))
            if isinstance(loaded_d, dict) and str(loaded_d.get("status") or "") != "stopped":
                d_doc = loaded_d
        except Exception:
            d_doc = {}

    eff_port = int(local_port or d_doc.get("port") or cfg_doc.get("port") or 8096)
    ep_secret = _load_optional_endpoint_secret(st_root, eff_p, cfg_doc)

    # ------------------------------------------------------------------
    # Layer 1: Local Loopback `/healthz` + `NO_PROXY` Loopback Guard
    # ------------------------------------------------------------------
    direct_plain_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    lb_res = _timed_http_request(
        direct_plain_opener,
        f"http://127.0.0.1:{eff_port}/healthz",
        method="GET",
        headers={"Accept": "application/json"},
        timeout_sec=min(2.0, budget_sec),
    )
    lb_doc: Dict[str, Any] = {}
    if lb_res["http_status"] == 200 and lb_res["body"]:
        with contextlib.suppress(Exception):
            parsed_lb = json.loads(lb_res["body"])
            if isinstance(parsed_lb, dict):
                lb_doc = parsed_lb
    lb_ok = bool(lb_res["http_status"] == 200 and lb_doc.get("status") == "ok")

    proxy_env_keys = ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy")
    has_env_proxy = any(bool((os.environ.get(k) or "").strip()) for k in proxy_env_keys)
    raw_no_proxy = ",".join(
        val.strip()
        for val in (os.environ.get("NO_PROXY") or "", os.environ.get("no_proxy") or "")
        if val and val.strip()
    )
    np_tokens = {tok.strip().lower().rstrip(".") for tok in re.split(r"[,\s;]+", raw_no_proxy) if tok.strip()}
    has_127 = bool("*" in np_tokens or "127.0.0.1" in np_tokens or "127.0.0.0/8" in np_tokens)
    has_localhost = bool("*" in np_tokens or "localhost" in np_tokens)
    no_proxy_missing_loopback = bool(has_env_proxy and not (has_127 and has_localhost))

    if not lb_ok:
        local_service: Dict[str, Any] = {
            "status": "error",
            "ok": False,
            "port": eff_port,
            "latency_ms": lb_res["latency_ms"],
            "version": "",
            "tool_count": 0,
            "no_proxy_ok": not no_proxy_missing_loopback,
            "error_code": "local_service_unreachable",
            "message_zh": f"本机回环服务 (127.0.0.1:{eff_port}) 未响应，请确认本地服务正在运行",
            "message_en": f"Local loopback service (127.0.0.1:{eff_port}) is not responding. Verify the local service is running.",
        }
    elif no_proxy_missing_loopback:
        local_service = {
            "status": "warn",
            "ok": True,
            "port": eff_port,
            "latency_ms": lb_res["latency_ms"],
            "version": str(lb_doc.get("version") or ""),
            "tool_count": int(lb_doc.get("tool_count") or 0),
            "no_proxy_ok": False,
            "error_code": "no_proxy_missing_loopback",
            "message_zh": "环境变量配置了代理但 NO_PROXY 缺少 127.0.0.1,localhost,::1，同机一键免密授权可能被代理拦截",
            "message_en": "Proxy environment variables are set without 127.0.0.1,localhost,::1 in NO_PROXY; local 1-click consent may be intercepted.",
        }
    else:
        ver_s = str(lb_doc.get("version") or "")
        tc_n = int(lb_doc.get("tool_count") or 0)
        local_service = {
            "status": "ok",
            "ok": True,
            "port": eff_port,
            "latency_ms": lb_res["latency_ms"],
            "version": ver_s,
            "tool_count": tc_n,
            "no_proxy_ok": True,
            "error_code": "",
            "message_zh": f"本机服务在线（127.0.0.1:{eff_port} · {lb_res['latency_ms']}ms · {tc_n} 个工具就绪）",
            "message_en": f"Local service online (127.0.0.1:{eff_port} · {lb_res['latency_ms']}ms · {tc_n} tools ready).",
        }

    # ------------------------------------------------------------------
    # Layer 2: Configured Proxy TCP Liveness + Channel Binary Dependencies
    # ------------------------------------------------------------------
    raw_proxy = detect_configured_proxy("https") or detect_configured_proxy("http")
    proxy_configured = bool(raw_proxy and raw_proxy.strip())
    proxy_endpoint = ""
    proxy_reachable = False
    proxy_latency_ms: Optional[float] = None
    px_host_port_label = ""
    clean_http_proxy_url = ""

    if proxy_configured:
        p_norm = raw_proxy.strip()
        if "://" not in p_norm:
            p_norm = f"http://{p_norm}"
        upx = urlsplit(p_norm)
        px_scheme = (upx.scheme or "http").lower()
        px_host = (upx.hostname or "").strip()
        try:
            px_port = upx.port
        except ValueError:
            px_port = None
        if px_port is None:
            px_port = 1080 if px_scheme.startswith("socks") else (443 if px_scheme == "https" else 8080)
        if px_host:
            px_host_fmt = f"[{px_host}]" if ":" in px_host and not px_host.startswith("[") else px_host
            px_host_port_label = f"{px_host_fmt}:{px_port}"
            proxy_endpoint = f"{px_scheme}://{px_host_port_label}"
            if px_scheme in ("http", "https"):
                clean_http_proxy_url = p_norm
            t_px = time.perf_counter()
            try:
                with socket.create_connection((px_host, int(px_port)), timeout=min(1.5, budget_sec)):
                    proxy_reachable = True
                proxy_latency_ms = round((time.perf_counter() - t_px) * 1000.0, 1)
            except OSError:
                proxy_reachable = False
                proxy_latency_ms = round((time.perf_counter() - t_px) * 1000.0, 1)

    cf_local = st_root / "bin" / ("cloudflared.exe" if sys.platform == "win32" else "cloudflared")
    cf_bin = str(cf_local) if cf_local.is_file() else (shutil.which("cloudflared") or "")
    cf_ok = bool(cf_bin)
    ssh_cand = shutil.which("ssh") or (resolve_windows_system_exe("ssh.exe") if sys.platform == "win32" else "")
    ssh_ok = bool(ssh_cand and (shutil.which(ssh_cand) or Path(ssh_cand).is_file()))

    all_slots = _discover_gateway_slots_for_probe(
        st_root,
        eff_p,
        cfg_doc,
        d_doc,
        endpoint_secret=ep_secret,
    )
    target_slots = [s for s in all_slots if not req_gw_id or s["gateway_id"] == req_gw_id]

    dep_status = "ok"
    dep_err_code = ""
    dep_msg_zh = ""
    dep_msg_en = ""

    if proxy_configured and not proxy_reachable:
        dep_status = "error"
        dep_err_code = "dead_proxy_port"
        dep_msg_zh = f"检测到的本机代理端口 ({px_host_port_label}) 未响应，请启动代理软件或关闭残留系统代理开关"
        dep_msg_en = f"Configured local proxy port ({px_host_port_label}) is not responding. Start your proxy software or turn off residual system proxy settings."
    else:
        for sl in target_slots:
            if not sl["enabled"]:
                continue
            sm = sl["submode"]
            if sl["gateway_id"] == "self_hosted" and sm == "cloudflare_token" and not cf_ok:
                dep_status = "error"
                dep_err_code = "cloudflared_missing"
                dep_msg_zh = "当前启用了 Cloudflare Tunnel 令牌通道，但未检测到 cloudflared 客户端组件"
                dep_msg_en = "Cloudflare Named Tunnel is enabled, but the cloudflared binary was not found."
                break
            if sl["gateway_id"] == "self_hosted" and sm == "vps" and not ssh_ok:
                dep_status = "error"
                dep_err_code = "ssh_missing"
                dep_msg_zh = "当前启用了 SSH 反向隧道模式，但系统未找到 ssh 客户端"
                dep_msg_en = "SSH reverse tunnel mode is enabled, but the system ssh client was not found."
                break
            if sl["gateway_id"] == "instant" and not ssh_ok and not cf_ok and dep_status == "ok":
                dep_status = "warn"
                dep_err_code = "instant_deps_missing"
                dep_msg_zh = "未找到系统 ssh 与 cloudflared 组件，首次开启通道时将尝试自动下载 cloudflared"
                dep_msg_en = "Neither ssh nor cloudflared was found locally; cloudflared will be downloaded on first start."

    # ------------------------------------------------------------------
    # Layer 3 & Layer 4: Concurrent Gateway `/healthz` + OAuth/MCP Handshake
    # ------------------------------------------------------------------
    eff_ssl_ctx = _build_ssl_context(ssl_context)
    https_handler = urllib.request.HTTPSHandler(context=eff_ssl_ctx)
    direct_https_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), https_handler)
    proxy_https_opener: Optional[urllib.request.OpenerDirector] = None
    if proxy_configured and proxy_reachable and clean_http_proxy_url:
        proxy_https_opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": clean_http_proxy_url, "https": clean_http_proxy_url}),
            https_handler,
        )

    rem_budget = max(0.8, budget_sec - (time.perf_counter() - t_start))
    per_leg_timeout = max(0.6, min(1.8, rem_budget * 0.55))

    def _probe_single_gateway(slot: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        gid = slot["gateway_id"]
        enabled = bool(slot["enabled"])
        origin = str(slot["origin"])
        pub_base = str(slot["public_base"])
        mcp_url = str(slot["mcp_url"])
        masked_u = mask_public_url_for_display(mcp_url, full_subdomain_mask=False) if mcp_url else ""
        share_u = mask_public_url_for_display(mcp_url, full_subdomain_mask=True) if mcp_url else ""

        if not enabled:
            return (
                {
                    "gateway_id": gid,
                    "label_zh": slot["label_zh"],
                    "label_en": slot["label_en"],
                    "enabled": False,
                    "submode": slot["submode"],
                    "status": "disabled",
                    "masked_url": masked_u,
                    "_share_url": share_u,
                    "via_proxy": {"attempted": False, "ok": False, "http_status": 0, "latency_ms": None, "error_code": ""},
                    "direct": {"attempted": False, "ok": False, "http_status": 0, "latency_ms": None, "error_code": ""},
                    "latency_ms": None,
                    "error_code": "",
                    "message_zh": "该通道当前未开启",
                    "message_en": "This gateway channel is currently disabled.",
                },
                {
                    "gateway_id": gid,
                    "masked_url": masked_u,
                    "status": "skipped",
                    "error_code": "",
                    "oauth_metadata_ok": False,
                    "oauth_http_status": 0,
                    "oauth_latency_ms": None,
                    "mcp_auth_gate_ok": False,
                    "mcp_http_status": 0,
                    "mcp_latency_ms": None,
                    "message_zh": "通道未开启，跳过协议握手校验",
                    "message_en": "Gateway disabled; protocol check skipped.",
                },
            )

        if not origin:
            d_err = str(slot.get("daemon_last_error") or "").strip()
            is_err = bool(d_err)
            return (
                {
                    "gateway_id": gid,
                    "label_zh": slot["label_zh"],
                    "label_en": slot["label_en"],
                    "enabled": True,
                    "submode": slot["submode"],
                    "status": "error" if is_err else "connecting",
                    "masked_url": "",
                    "_share_url": "",
                    "via_proxy": {"attempted": False, "ok": False, "http_status": 0, "latency_ms": None, "error_code": ""},
                    "direct": {"attempted": False, "ok": False, "http_status": 0, "latency_ms": None, "error_code": ""},
                    "latency_ms": None,
                    "error_code": "daemon_tunnel_error" if is_err else "url_pending",
                    "message_zh": d_err if is_err else "正在建立加密连接通道，尚未生成公网 HTTPS 地址",
                    "message_en": d_err if is_err else "Establishing encrypted tunnel; public HTTPS URL is not ready yet.",
                },
                {
                    "gateway_id": gid,
                    "masked_url": "",
                    "status": "skipped",
                    "error_code": "",
                    "oauth_metadata_ok": False,
                    "oauth_http_status": 0,
                    "oauth_latency_ms": None,
                    "mcp_auth_gate_ok": False,
                    "mcp_http_status": 0,
                    "mcp_latency_ms": None,
                    "message_zh": "等待公网地址就绪后再执行协议握手检测",
                    "message_en": "Waiting for public HTTPS URL before running MCP protocol checks.",
                },
            )

        host_low = (urlsplit(origin).hostname or "").strip().lower()
        is_default_workers_dev = bool(host_low.endswith(".workers.dev") and not slot.get("custom_domain"))

        def _probe_leg(op_dir: urllib.request.OpenerDirector) -> Dict[str, Any]:
            primary_hz = pub_base if pub_base != origin else origin
            r1 = _classify_gateway_healthz_probe(primary_hz, op_dir, per_leg_timeout)
            if not r1["ok"] and pub_base != origin and r1["http_status"] in (404, 503):
                r2 = _classify_gateway_healthz_probe(origin, op_dir, per_leg_timeout)
                if r2["ok"]:
                    return r2
            return r1

        if proxy_https_opener is not None:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as leg_pool:
                fut_px = leg_pool.submit(_probe_leg, proxy_https_opener)
                fut_dir = leg_pool.submit(_probe_leg, direct_https_opener)
                px_leg = fut_px.result()
                dir_leg = fut_dir.result()
        else:
            px_leg = {"attempted": False, "ok": False, "http_status": 0, "latency_ms": None, "error_code": "", "reason_zh": "", "reason_en": ""}
            dir_leg = _probe_leg(direct_https_opener)

        best_opener: Optional[urllib.request.OpenerDirector] = None
        if px_leg["ok"] and dir_leg["ok"]:
            best_opener = direct_https_opener
            best_lat = min(float(px_leg["latency_ms"] or 0.0), float(dir_leg["latency_ms"] or 0.0))
            gw_status = "ok"
            gw_err_code = ""
            gw_msg_zh = f"公网 /healthz 连通正常（直连 {dir_leg['latency_ms']}ms / 代理 {px_leg['latency_ms']}ms）"
            gw_msg_en = f"Public /healthz reachable (direct {dir_leg['latency_ms']}ms / proxy {px_leg['latency_ms']}ms)."
        elif px_leg["ok"] and not dir_leg["ok"]:
            best_opener = proxy_https_opener
            best_lat = float(px_leg["latency_ms"] or 0.0)
            gw_status = "ok"
            gw_err_code = ""
            if host_low.endswith(".workers.dev"):
                gw_msg_zh = f"经代理连通正常 ({px_leg['latency_ms']}ms)；无代理直连超时（国内默认 *.workers.dev 需保持代理常开）"
                gw_msg_en = f"Connected via proxy ({px_leg['latency_ms']}ms); direct connection timed out (*.workers.dev requires keeping local proxy active)."
            else:
                gw_msg_zh = f"经代理连通正常 ({px_leg['latency_ms']}ms)；无代理直连未通"
                gw_msg_en = f"Connected via proxy ({px_leg['latency_ms']}ms); direct connection failed."
        elif dir_leg["ok"]:
            best_opener = direct_https_opener
            best_lat = float(dir_leg["latency_ms"] or 0.0)
            gw_status = "ok"
            gw_err_code = ""
            gw_msg_zh = f"公网 /healthz 直连正常 ({dir_leg['latency_ms']}ms)"
            gw_msg_en = f"Public /healthz direct connection OK ({dir_leg['latency_ms']}ms)."
        else:
            best_lat = None
            gw_status = "error"
            chosen_fail = px_leg if (px_leg["attempted"] and px_leg["http_status"] > 0) else dir_leg
            if px_leg["attempted"] and px_leg["error_code"] in ("cf_1027", "cf_530_1033", "cf_waf_challenge_403"):
                chosen_fail = px_leg
            elif dir_leg["error_code"] in ("cf_1027", "cf_530_1033", "cf_waf_challenge_403"):
                chosen_fail = dir_leg

            if is_default_workers_dev and not (proxy_configured and proxy_reachable) and chosen_fail["error_code"] in ("timeout", "network_unreachable"):
                gw_err_code = "workers_dev_dns_proxy_required"
                gw_msg_zh = "默认 *.workers.dev 在国内网络存在 DNS 污染，使用期间需保持本机 HTTP/HTTPS 代理常开，或在通道 2 绑定自定义域名"
                gw_msg_en = "Default *.workers.dev suffers from DNS poisoning in Mainland China. Keep your local HTTP/HTTPS proxy on, or bind a custom domain on Channel 2."
            else:
                gw_err_code = str(chosen_fail.get("error_code") or "gateway_unreachable")
                gw_msg_zh = str(chosen_fail.get("reason_zh") or "公网网关 /healthz 无法访问，请检查隧道进程或域名解析")
                gw_msg_en = str(chosen_fail.get("reason_en") or "Public gateway /healthz is unreachable. Check tunnel status or DNS.")

        gw_entry = {
            "gateway_id": gid,
            "label_zh": slot["label_zh"],
            "label_en": slot["label_en"],
            "enabled": True,
            "submode": slot["submode"],
            "status": gw_status,
            "masked_url": masked_u,
            "_share_url": share_u,
            "via_proxy": {
                "attempted": bool(px_leg["attempted"]),
                "ok": bool(px_leg["ok"]),
                "http_status": int(px_leg["http_status"]),
                "latency_ms": px_leg["latency_ms"],
                "error_code": str(px_leg.get("error_code") or ""),
            },
            "direct": {
                "attempted": bool(dir_leg["attempted"]),
                "ok": bool(dir_leg["ok"]),
                "http_status": int(dir_leg["http_status"]),
                "latency_ms": dir_leg["latency_ms"],
                "error_code": str(dir_leg.get("error_code") or ""),
            },
            "latency_ms": best_lat,
            "error_code": gw_err_code,
            "message_zh": gw_msg_zh,
            "message_en": gw_msg_en,
        }

        if best_opener is None:
            return (
                gw_entry,
                {
                    "gateway_id": gid,
                    "masked_url": masked_u,
                    "status": "skipped",
                    "error_code": gw_err_code,
                    "oauth_metadata_ok": False,
                    "oauth_http_status": 0,
                    "oauth_latency_ms": None,
                    "mcp_auth_gate_ok": False,
                    "mcp_http_status": 0,
                    "mcp_latency_ms": None,
                    "message_zh": "因公网 /healthz 未通，已跳过后续 OAuth 与 /mcp 协议握手检测",
                    "message_en": "Skipped OAuth and /mcp protocol checks because public /healthz is unreachable.",
                },
            )

        proto_timeout = max(0.6, min(1.8, budget_sec - (time.perf_counter() - t_start) + 0.4))
        proto_entry = _probe_mcp_protocol_for_gateway(slot, best_opener, proto_timeout)
        return gw_entry, proto_entry

    gateways_results: List[Dict[str, Any]] = []
    proto_results: List[Dict[str, Any]] = []
    if target_slots:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(target_slots))) as gw_pool:
            pair_list = list(gw_pool.map(_probe_single_gateway, target_slots))
        for g_item, p_item in pair_list:
            gateways_results.append(g_item)
            proto_results.append(p_item)

    # Back-fill Layer 2 workers.dev proxy dependency hint if default workers.dev failed without proxy
    if dep_status == "ok":
        for g_item in gateways_results:
            if g_item.get("error_code") == "workers_dev_dns_proxy_required":
                dep_status = "warn"
                dep_err_code = "workers_dev_dns_proxy_required"
                dep_msg_zh = "默认 *.workers.dev 在国内网络存在 DNS 污染，使用期间需保持本机 HTTP/HTTPS 代理常开，或在通道 2 绑定自定义域名"
                dep_msg_en = "Default *.workers.dev requires keeping a local HTTP/HTTPS proxy active in Mainland China, or binding a custom domain on Channel 2."
                break

    if not dep_msg_zh:
        if proxy_configured and proxy_reachable:
            dep_msg_zh = f"系统代理连通正常 ({proxy_endpoint} · {proxy_latency_ms}ms)；ssh={'就绪' if ssh_ok else '未装'}，cloudflared={'就绪' if cf_ok else '未装'}"
            dep_msg_en = f"System proxy reachable ({proxy_endpoint} · {proxy_latency_ms}ms); ssh={'ready' if ssh_ok else 'missing'}, cloudflared={'ready' if cf_ok else 'missing'}."
        else:
            dep_msg_zh = f"未开启系统代理（直连模式）；ssh={'就绪' if ssh_ok else '未装'}，cloudflared={'就绪' if cf_ok else '未装'}"
            dep_msg_en = f"No system proxy configured (direct mode); ssh={'ready' if ssh_ok else 'missing'}, cloudflared={'ready' if cf_ok else 'missing'}."

    proxy_and_deps: Dict[str, Any] = {
        "status": dep_status,
        "proxy_configured": proxy_configured,
        "proxy_endpoint": proxy_endpoint,
        "proxy_reachable": proxy_reachable if proxy_configured else None,
        "latency_ms": proxy_latency_ms,
        "ssh_available": ssh_ok,
        "cloudflared_available": cf_ok,
        "error_code": dep_err_code,
        "message_zh": dep_msg_zh,
        "message_en": dep_msg_en,
    }

    enabled_gw_items = [g for g in gateways_results if g["enabled"]]
    ok_proto_items = [p for p in proto_results if p["status"] == "ok"]
    err_gw_items = [g for g in enabled_gw_items if g["status"] == "error"]
    conn_gw_items = [g for g in enabled_gw_items if g["status"] == "connecting"]
    err_proto_items = [p for p in proto_results if p["status"] == "error"]
    warn_proto_items = [p for p in proto_results if p["status"] == "warn"]

    if not enabled_gw_items:
        mcp_proto_status = "warn"
        mcp_proto_msg_zh = "当前未开启任何公网 HTTPS 网关，请先开启至少一条连接通道"
        mcp_proto_msg_en = "No public HTTPS gateway is enabled yet. Turn on at least one gateway channel first."
    elif err_proto_items:
        mcp_proto_status = "error"
        mcp_proto_msg_zh = str(err_proto_items[0]["message_zh"])
        mcp_proto_msg_en = str(err_proto_items[0]["message_en"])
    elif warn_proto_items:
        mcp_proto_status = "warn"
        mcp_proto_msg_zh = str(warn_proto_items[0]["message_zh"])
        mcp_proto_msg_en = str(warn_proto_items[0]["message_en"])
    elif ok_proto_items:
        mcp_proto_status = "ok"
        mcp_proto_msg_zh = str(ok_proto_items[0]["message_zh"])
        mcp_proto_msg_en = str(ok_proto_items[0]["message_en"])
    else:
        mcp_proto_status = "error" if err_gw_items else "warn"
        mcp_proto_msg_zh = "等待公网网关 /healthz 连通后验证 OAuth 与 /mcp 鉴权门禁"
        mcp_proto_msg_en = "Waiting for public gateway /healthz before verifying OAuth and /mcp auth gate."

    mcp_protocol: Dict[str, Any] = {
        "status": mcp_proto_status,
        "message_zh": mcp_proto_msg_zh,
        "message_en": mcp_proto_msg_en,
        "items": proto_results,
    }

    # Compute overall_status & plain summary
    if local_service["status"] == "error":
        overall_status = "error"
        summary_zh = str(local_service["message_zh"])
        summary_en = str(local_service["message_en"])
    elif proxy_and_deps["status"] == "error" and (not ok_proto_items or req_gw_id):
        overall_status = "error"
        summary_zh = str(proxy_and_deps["message_zh"])
        summary_en = str(proxy_and_deps["message_en"])
    elif not enabled_gw_items:
        overall_status = "warn"
        summary_zh = (
            "该通道当前未开启，打开右上角开关后即可实测公网连通性"
            if req_gw_id
            else "本机服务正常，当前尚未开启任何公网 HTTPS 连接网关"
        )
        summary_en = (
            "This gateway channel is currently disabled. Enable its switch to test public connectivity."
            if req_gw_id
            else "Local service is healthy, but no public HTTPS gateway channel is enabled yet."
        )
    elif err_proto_items:
        overall_status = "error"
        summary_zh = str(err_proto_items[0]["message_zh"])
        summary_en = str(err_proto_items[0]["message_en"])
    elif err_gw_items and not ok_proto_items:
        overall_status = "error"
        summary_zh = str(err_gw_items[0]["message_zh"])
        summary_en = str(err_gw_items[0]["message_en"])
    elif (
        local_service["status"] == "warn"
        or proxy_and_deps["status"] in ("warn", "error")
        or bool(err_gw_items)
        or bool(conn_gw_items)
        or bool(warn_proto_items)
    ):
        overall_status = "warn"
        if local_service["status"] == "warn":
            summary_zh = str(local_service["message_zh"])
            summary_en = str(local_service["message_en"])
        elif err_gw_items:
            summary_zh = f"主通道已畅通，另有通道异常：{err_gw_items[0]['message_zh']}"
            summary_en = f"Primary gateway is healthy, while another channel reported an error: {err_gw_items[0]['message_en']}"
        elif conn_gw_items:
            summary_zh = str(conn_gw_items[0]["message_zh"])
            summary_en = str(conn_gw_items[0]["message_en"])
        elif warn_proto_items:
            summary_zh = str(warn_proto_items[0]["message_zh"])
            summary_en = str(warn_proto_items[0]["message_en"])
        else:
            summary_zh = str(proxy_and_deps["message_zh"])
            summary_en = str(proxy_and_deps["message_en"])
    else:
        overall_status = "ok"
        best_gw = next((g for g in enabled_gw_items if g["status"] == "ok"), enabled_gw_items[0])
        lat_tag = f"{best_gw['latency_ms']}ms" if best_gw.get("latency_ms") is not None else "OK"
        summary_zh = f"本机服务、公网网关 ({lat_tag}) 与 OAuth / MCP 鉴权握手全部畅通"
        summary_en = f"Local service, public gateway ({lat_tag}), and OAuth / MCP protocol handshake are all healthy."

    duration_ms = round((time.perf_counter() - t_start) * 1000.0, 1)
    checked_at = round(time.time(), 3)

    # Build zero-leak `redacted_share_text` with full `https://***...` domain & `/u/***` masking
    share_lines: List[str] = [
        f"[WebAI2PC 连通性诊断摘要] 状态={overall_status.upper()} | 总耗时={duration_ms}ms",
        f"1. 本机服务: [{local_service['status'].upper()}] {local_service['message_zh']}",
        f"2. 代理与组件: [{proxy_and_deps['status'].upper()}] {proxy_and_deps['message_zh']}",
    ]
    for g in gateways_results:
        sh_u = str(g.pop("_share_url", "") or "")
        u_part = f" ({sh_u})" if sh_u else ""
        share_lines.append(f"3. 网关[{g['gateway_id']}]{u_part}: [{g['status'].upper()}] {g['message_zh']}")
    for p in proto_results:
        if p["status"] != "skipped":
            share_lines.append(f"4. 协议握手[{p['gateway_id']}]: [{p['status'].upper()}] {p['message_zh']}")
    raw_share_text = "\n".join(share_lines)
    # Enforce strict full-host masking on any remaining URL in share text
    safe_share_text = redact_text(raw_share_text, extra_secrets=extra_sec)
    safe_share_text = re.sub(r"https://\[REDACTED-(?:TUNNEL|GATEWAY)\]", "https://***", safe_share_text)
    safe_share_text = re.sub(r"/u/[^/\s)\]]+", "/u/***", safe_share_text)

    raw_payload: Dict[str, Any] = {
        "ok": overall_status != "error",
        "overall_status": overall_status,
        "summary": summary_zh,
        "summary_zh": summary_zh,
        "summary_en": summary_en,
        "gateway_filter": req_gw_id,
        "checked_at": checked_at,
        "duration_ms": duration_ms,
        "local_service": local_service,
        "proxy_and_deps": proxy_and_deps,
        "gateways": gateways_results,
        "mcp_protocol": mcp_protocol,
        "redacted_share_text": safe_share_text,
    }
    redacted_payload: Dict[str, Any] = redact_diagnostic_data(raw_payload, extra_secrets=extra_sec)
    redacted_payload["redacted_share_text"] = safe_share_text
    return redacted_payload


def run_doctor(
    state_root: Path,
    *,
    prefix: str = "pc",
    bundle: bool = False,
    bundle_output: Optional[Path] = None,
    probe: bool = False,
    gateway_id: str = "",
    local_port: Optional[int] = None,
) -> Dict[str, Any]:
    """Run non-intrusive health & environment diagnostics with deep privacy redaction."""
    st_root = Path(state_root).expanduser().resolve()
    eff_p = (prefix or "pc").strip().lower() or "pc"
    extra_sec = _collect_known_secrets(st_root)

    py_found = find_suitable_python()
    venv_py = venv_python_path(st_root / ".venv")
    embed_py = find_embedded_python_exe(state_root=st_root)
    venv_ready = check_runtime_deps_ready(venv_py, require_cosmos_mcp=True, inject_repo_src=False) if venv_py.is_file() else False
    embed_ready = check_runtime_deps_ready(embed_py) if (embed_py is not None and embed_py.is_file()) else False
    ambient_ready = check_runtime_deps_ready(py_found[0]) if py_found else False
    runtime_ready = bool((py_found is not None or embed_py is not None) and (venv_ready or embed_ready or ambient_ready))

    eff_home = Path(os.environ.get("USERPROFILE") or os.environ.get("HOME") or str(Path.home())).expanduser()
    primary_norms, primary_state_exists = _resolve_primary_state_roots(eff_home)
    is_default_st = os.path.normcase(str(st_root)) in primary_norms

    live = detect_running_instance(st_root, eff_p)
    autostart_info = get_autostart_status(
        prefix=eff_p,
        state_root=st_root,
        is_default_state_root=is_default_st,
        primary_state_exists=primary_state_exists,
    )
    proxy_url = detect_configured_proxy()

    cfg_path = st_root / "config" / (f"service_{eff_p}.json" if eff_p != "pc" else "service.json")
    cfg_doc: Dict[str, Any] = {}
    if cfg_path.is_file():
        try:
            loaded = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
            if isinstance(loaded, dict):
                cfg_doc = loaded
        except Exception:
            cfg_doc = {}

    cf_local = st_root / "bin" / ("cloudflared.exe" if sys.platform == "win32" else "cloudflared")
    cf_bin = str(cf_local) if cf_local.is_file() else (shutil.which("cloudflared") or "")
    ssh_cand = shutil.which("ssh") or (resolve_windows_system_exe("ssh.exe") if sys.platform == "win32" else "")
    ssh_ok = bool(ssh_cand and (shutil.which(ssh_cand) or Path(ssh_cand).is_file()))
    has_cf_token = bool(load_tunnel_token(st_root, prefix=eff_p))

    service_online = bool(live.get("online"))
    gateway_healthy, gateway_issues = _assess_gateway_health(
        st_root,
        eff_p,
        cfg_doc,
        live,
        has_cf_token=has_cf_token,
    )

    logs_summary: Dict[str, str] = {}
    logs_dir = st_root / "logs"
    if logs_dir.is_dir():
        for lf in sorted(logs_dir.glob("*.log"))[:6]:
            tail, _ = read_log_tail_bounded(lf, tail_lines=40, max_bytes=8192)
            logs_summary[lf.name] = redact_text(tail, extra_secrets=extra_sec)

    raw_report: Dict[str, Any] = {
        "ok": bool(runtime_ready and service_online and gateway_healthy),
        "runtime_ready": runtime_ready,
        "service_online": service_online,
        "gateway_healthy": gateway_healthy,
        "gateway_issues": gateway_issues,
        "timestamp": round(time.time(), 3),
        "platform": {
            "sys_platform": sys.platform,
            "os": platform.platform(),
            "machine": platform.machine(),
            "cli_python_version": platform.python_version(),
        },
        "runtime": {
            "suitable_python_found": bool(py_found or embed_py),
            "suitable_python_version": ".".join(str(x) for x in py_found[1]) if py_found else "",
            "venv_exists": venv_py.is_file(),
            "venv_deps_ready": venv_ready,
            "python_embed_exists": bool(embed_py and embed_py.is_file()),
            "python_embed_deps_ready": embed_ready,
            "ambient_deps_ready": ambient_ready,
        },
        "network": {
            "proxy_detected": bool(proxy_url),
            "proxy_endpoint": proxy_url or "",
            "cloudflared_available": bool(cf_bin),
            "ssh_available": ssh_ok,
            "tunnel_token_configured": has_cf_token,
        },
        "service": live,
        "autostart": autostart_info,
        "config": cfg_doc,
        "log_tails": logs_summary,
    }

    redacted_report: Dict[str, Any] = redact_diagnostic_data(raw_report, extra_secrets=extra_sec)
    if probe:
        conn_check = run_connectivity_check(
            st_root,
            prefix=eff_p,
            local_port=local_port,
            gateway_id=gateway_id,
        )
        redacted_report["connectivity_check"] = conn_check
        if conn_check.get("overall_status") == "error":
            redacted_report["ok"] = False

    if bundle:
        out_zip = (
            Path(bundle_output).expanduser().resolve()
            if bundle_output is not None
            else (st_root / f"cosmos_doctor_bundle_{int(time.time())}.zip")
        )
        out_zip.parent.mkdir(parents=True, exist_ok=True)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("doctor_report.json", json.dumps(redacted_report, ensure_ascii=False, indent=2) + "\n")
            zf.writestr("service_redacted.json", json.dumps(redacted_report.get("config", {}), ensure_ascii=False, indent=2) + "\n")
            for lname, lcontent in logs_summary.items():
                zf.writestr(f"logs/{lname}", lcontent)
        out_zip.write_bytes(buf.getvalue())
        redacted_report["bundle_path"] = str(out_zip)

    return redacted_report


def _shred_file_in_place(file_path: Path) -> None:
    """Overwrite a sensitive file with zero bytes and truncate to 0 before unlinking during `--purge`."""
    try:
        if file_path.is_symlink():
            file_path.unlink(missing_ok=True)
            return
        if not file_path.is_file():
            return
        try:
            os.chmod(file_path, 0o600)
        except OSError:
            pass
        size = max(int(file_path.stat().st_size), 64)
        zero_buf = b"\x00" * min(size, 65536)
        with file_path.open("r+b") as fh:
            fh.seek(0)
            rem = size
            while rem > 0:
                step = min(rem, len(zero_buf))
                fh.write(zero_buf[:step])
                rem -= step
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
            fh.seek(0)
            fh.truncate(0)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        file_path.unlink(missing_ok=True)
    except OSError:
        try:
            file_path.unlink(missing_ok=True)
        except OSError:
            pass


def _shred_sensitive_state_files(st_root: Path, *, prefix_filter: str = "") -> List[str]:
    """Overwrite and destroy `secrets/`, `state/oauth*.sqlite3*` (+ WAL/SHM), and connection info files."""
    shredded: List[str] = []
    seen: Set[str] = set()
    scoped_p = (prefix_filter or "").strip().lower()
    is_scoped_non_default = bool(scoped_p and scoped_p != "pc")

    def _wipe_one(p: Path) -> None:
        if not p.exists() and not p.is_symlink():
            return
        norm = os.path.normcase(str(p))
        if norm in seen:
            return
        seen.add(norm)
        _shred_file_in_place(p)
        shredded.append(str(p))

    sec_dir = st_root / "secrets"
    if is_scoped_non_default:
        if sec_dir.is_dir():
            for pat in (f"*_{scoped_p}.*", f"*_{scoped_p}"):
                for item in list(sec_dir.glob(pat)):
                    if item.is_file() or item.is_symlink():
                        _wipe_one(item)
        st_dir_sc = st_root / "state"
        if st_dir_sc.is_dir():
            for pat in (
                f"oauth_{scoped_p}.sqlite3*",
                f"*_{scoped_p}.txt",
                f"*_{scoped_p}.json",
                f"*_{scoped_p}.dpapi",
                f"*_{scoped_p}.enc",
                f"*_{scoped_p}.key",
            ):
                for item in list(st_dir_sc.glob(pat)):
                    if item.is_file() or item.is_symlink():
                        _wipe_one(item)
        for root_sc_name in (
            f"连接信息_CONNECTION_INFO_{scoped_p}.txt",
            f"connection_{scoped_p}.dpapi",
            f"connection_{scoped_p}.enc",
            f"endpoint_secret_{scoped_p}.txt",
            f"local_vault_{scoped_p}.key",
        ):
            conn_sc = st_root / root_sc_name
            if conn_sc.is_file() or conn_sc.is_symlink():
                _wipe_one(conn_sc)
        return shredded

    if sec_dir.is_dir():
        for explicit_pat in (
            "auth.json",
            "master_seed*.bin",
            "master_seed*",
            "cloudflare_api_token*.txt",
            "workers_tunnel_secret*.txt",
            "public_gateway_secret*.txt",
            "vps_node_secret*.txt",
            "endpoint_secret*.txt",
            "local_vault*.key",
            "srvus_ed25519*",
            "vps_id_ed25519*",
            "tunnel_token*.txt",
            "connection*.txt",
            "connection*.dpapi",
            "connection*.enc",
        ):
            for item in list(sec_dir.glob(explicit_pat)):
                if item.is_file() or item.is_symlink():
                    _wipe_one(item)
        for item in list(sec_dir.rglob("*")):
            if item.is_file() or item.is_symlink():
                _wipe_one(item)

    st_dir = st_root / "state"
    if st_dir.is_dir():
        for pat in (
            "oauth*.sqlite3*",
            "oauth*",
            "chatgpt_oneclick_vault*.json",
            "latest_consent_pair_code*",
            "latest_dynamic_pair_code*",
            "connection*.dpapi",
            "connection*.enc",
            "endpoint_secret*.txt",
            "local_vault*.key",
            "*secret*",
            "*token*",
            "*.dpapi",
            "*.key",
        ):
            for item in list(st_dir.glob(pat)):
                if item.is_file() or item.is_symlink():
                    _wipe_one(item)

    if st_root.is_dir():
        dotenv_f = st_root / ".env"
        if dotenv_f.is_file() or dotenv_f.is_symlink():
            _wipe_one(dotenv_f)
        for root_sec_pat in (
            "*CONNECTION_INFO*.txt",
            "chatgpt_oneclick_vault*.json",
            "connection*.dpapi",
            "connection*.enc",
            "endpoint_secret*.txt",
            "local_vault*.key",
        ):
            for conn_f in list(st_root.glob(root_sec_pat)):
                if conn_f.is_file() or conn_f.is_symlink():
                    _wipe_one(conn_f)
        for vault_sub in (".undo_history", "history", "trash", ".trash", ".localpc_trash"):
            v_dir = st_root / vault_sub
            if v_dir.is_dir():
                for item in list(v_dir.rglob("*")):
                    if not (item.is_file() or item.is_symlink()):
                        continue
                    low_n = item.name.lower()
                    if (
                        "auth.json" in low_n
                        or "oauth" in low_n
                        or "chatgpt_oneclick_vault" in low_n
                        or "connection" in low_n
                        or "tunnel_" in low_n
                        or "cloudflare_api_token" in low_n
                        or "workers_tunnel_secret" in low_n
                        or "public_gateway_secret" in low_n
                        or "vps_node_secret" in low_n
                        or "endpoint_secret" in low_n
                        or "local_vault" in low_n
                        or "master_seed" in low_n
                        or "srvus_ed25519" in low_n
                        or "vps_id_ed25519" in low_n
                        or "_secret" in low_n
                        or "_token" in low_n
                        or low_n.endswith((".dpapi", ".enc", ".key"))
                    ):
                        _wipe_one(item)
    return shredded


def _purge_path_permanently(target: Path, *, retries: int = 5) -> bool:
    """Permanently delete a file or directory tree without copying secrets into `%TEMP%`."""
    def _on_rm_error(func: Any, path_str: str, _exc_info: Any) -> None:
        try:
            os.chmod(path_str, 0o700)
            func(path_str)
        except OSError:
            pass

    for attempt in range(max(1, retries)):
        if not target.exists() and not target.is_symlink():
            return True
        try:
            if target.is_symlink() or target.is_file():
                try:
                    os.chmod(target, 0o600)
                except OSError:
                    pass
                target.unlink(missing_ok=True)
            elif target.is_dir():
                shutil.rmtree(target, onerror=_on_rm_error)
            if not target.exists() and not target.is_symlink():
                return True
        except OSError:
            pass
        if attempt + 1 < retries:
            time.sleep(0.12 * (attempt + 1))
    return not target.exists() and not target.is_symlink()


RECOVERY_PRESERVE_NAMES: Set[str] = {
    ".undo_history",
    "history",
    ".trash",
    "trash",
    ".localpc_trash",
}


def _is_cosmos_mcp_shortcut_file(path: Path) -> bool:
    """Match only Cosmos MCP / WebAI2PC / Cosmos Studio / LocalPC-MCP `.lnk`, `.bat`, `.url`, `.command` shortcut files."""
    if not path.is_file():
        return False
    low = path.name.lower()
    if not low.endswith((".lnk", ".bat", ".url", ".command")):
        return False
    stem = path.stem.lower()
    exact_prefixes = (
        "一键启动_cosmos_mcp",
        "一键卸载_cosmos_mcp",
        "一键启动_localpc",
        "cosmos_mcp",
        "cosmos-mcp",
        "cosmos studio",
        "cosmos_studio",
        "webai2pc",
        "localpc-mcp",
        "localpc_mcp",
    )
    return any(stem.startswith(p) or p in stem for p in exact_prefixes)


def _shortcut_matches_nondefault_prefix(path: Path, prefix: str) -> bool:
    """Return True if `path` specifically belongs to non-default instance `prefix` (never matching shared `pc` shortcut)."""
    p_low = prefix.strip().lower()
    stem_low = path.stem.lower()
    if stem_low.endswith((f"_{p_low}", f"-{p_low}")):
        return True
    try:
        txt_low = path.read_bytes()[:65536].decode("utf-8", errors="ignore").lower()
        if f"--prefix {p_low}" in txt_low or f"--prefix={p_low}" in txt_low:
            return True
    except OSError:
        pass
    return False


def _resolve_primary_state_roots(
    home_dir: Path,
    appdata_dir: Optional[Path] = None,
    platform_name: Optional[str] = None,
) -> tuple[Set[str], bool]:
    plat = platform_name or sys.platform
    eff_home = Path(home_dir).expanduser()
    candidates: List[Path] = []
    if plat == "win32":
        if appdata_dir is not None:
            local_base = Path(appdata_dir).expanduser().parent / "Local"
            if not local_base.exists():
                local_base = eff_home / "AppData" / "Local"
        elif home_dir is not None and os.path.normcase(str(eff_home.resolve())) != os.path.normcase(str(Path.home().resolve())):
            local_base = eff_home / "AppData" / "Local"
        else:
            env_la = (os.environ.get("LOCALAPPDATA") or "").strip()
            local_base = Path(env_la).expanduser() if env_la else (eff_home / "AppData" / "Local")
        candidates.extend([local_base / "CosmosMCP", local_base / "LocalPC-MCP"])
    else:
        candidates.extend([eff_home / ".cosmos-mcp", eff_home / ".localpc-mcp"])

    norms: Set[str] = set()
    any_exists = False
    for c in candidates:
        try:
            norms.add(os.path.normcase(str(c.resolve())))
            if (c / "config").is_dir() or (c / "secrets").is_dir() or (c / "config.json").is_file():
                any_exists = True
        except OSError:
            norms.add(os.path.normcase(str(c)))
    return norms, any_exists


def _shortcut_belongs_to_state_root(
    shortcut_path: Path,
    state_root: Path,
    *,
    is_default_state_root: bool,
    primary_state_exists: bool,
    configured_ports: Set[int],
) -> bool:
    st_norm_slash = os.path.normcase(str(state_root.resolve())).replace("/", "\\")
    sc_norm_slash = os.path.normcase(str(shortcut_path.resolve())).replace("/", "\\")
    if sc_norm_slash.startswith(st_norm_slash.rstrip("\\") + "\\"):
        return True

    try:
        raw = shortcut_path.read_bytes()[:131072]
    except OSError:
        return is_default_state_root

    decoded_blobs = [raw.decode("utf-8", errors="ignore")]
    if b"\x00" in raw:
        decoded_blobs.append(raw.decode("utf-16le", errors="ignore"))
        decoded_blobs.append(raw.decode("latin-1", errors="ignore"))
    combined_norm = "\n".join(os.path.normcase(b).replace("/", "\\") for b in decoded_blobs)

    st_clean = st_norm_slash.rstrip("\\")
    if st_clean and re.search(re.escape(st_clean) + r"(?:\\|['\"\s]|$)", combined_norm):
        return True

    low = combined_norm.lower()
    has_explicit_other_target = bool(
        "--state-dir" in low
        or "cosmos_mcp_state_dir=" in low
        or "localpc_mcp_state_dir=" in low
        or "\\cosmosmcp" in low
        or "\\localpc-mcp" in low
        or "\\.cosmos-mcp" in low
        or "\\.localpc-mcp" in low
        or "\\.venv\\" in low
        or "\\app_src" in low
        or "\\bin\\uninstall_cosmos_mcp" in low
        or re.search(r"[a-z]:\\", low)
        or re.search(r"\\(?:users|home|tmp|var|private|opt|srv)\\", low)
    )

    if is_default_state_root:
        if "--state-dir" in low or "cosmos_mcp_state_dir=" in low:
            return False
        return True

    if has_explicit_other_target:
        return False

    if shortcut_path.name.lower().endswith(".url"):
        m_port = re.search(r"127\.0\.0\.1:(\d+)", low)
        if m_port:
            url_port = int(m_port.group(1))
            if configured_ports and url_port in configured_ports and not primary_state_exists:
                return True
            return False
        if primary_state_exists:
            return False

    if primary_state_exists:
        return False
    return True


def _resolve_windows_start_menu_dirs(
    eff_home: Path,
    *,
    home_dir: Optional[Path] = None,
    appdata_dir: Optional[Path] = None,
    platform_name: Optional[str] = None,
) -> List[Path]:
    plat = platform_name or sys.platform
    if plat != "win32":
        return []
    roaming_base: Optional[Path] = None
    if appdata_dir is not None:
        roaming_base = Path(appdata_dir).expanduser()
    elif home_dir is not None:
        roaming_base = Path(home_dir).expanduser() / "AppData" / "Roaming"
    elif not os.environ.get("PYTEST_CURRENT_TEST"):
        env_ap = (os.environ.get("APPDATA") or "").strip()
        roaming_base = Path(env_ap).expanduser() if env_ap else (eff_home / "AppData" / "Roaming")
    if roaming_base is None:
        return []
    prog_dir = roaming_base / "Microsoft" / "Windows" / "Start Menu" / "Programs"
    if not prog_dir.is_dir():
        return []
    dirs: List[Path] = [prog_dir]
    for sub_nm in ("WebAI2PC", "Cosmos MCP", "LocalPC-MCP"):
        sub_p = prog_dir / sub_nm
        if sub_p.is_dir():
            dirs.append(sub_p)
    return dirs


def _find_shortcut_files(
    state_root: Path,
    desktop_dir: Optional[Path],
    *,
    extra_shortcut_dirs: Sequence[Path] = (),
    is_default_state_root: bool = True,
    primary_state_exists: bool = False,
    configured_ports: Optional[Set[int]] = None,
    prefix_filter: str = "",
) -> List[str]:
    found: List[str] = []
    seen: Set[str] = set()
    ports = configured_ports or set()
    scoped_p = (prefix_filter or "").strip().lower()
    is_scoped_non_default = bool(scoped_p and scoped_p != "pc")
    search_dirs: List[Optional[Path]] = [state_root, desktop_dir, *extra_shortcut_dirs]
    for d in search_dirs:
        if d is None or not d.is_dir():
            continue
        try:
            for item in d.iterdir():
                if _is_cosmos_mcp_shortcut_file(item):
                    if is_scoped_non_default and not _shortcut_matches_nondefault_prefix(item, scoped_p):
                        continue
                    if d is not state_root and not _shortcut_belongs_to_state_root(
                        item,
                        state_root,
                        is_default_state_root=is_default_state_root,
                        primary_state_exists=primary_state_exists,
                        configured_ports=ports,
                    ):
                        continue
                    norm = os.path.normcase(str(item.resolve()))
                    if norm not in seen:
                        seen.add(norm)
                        found.append(str(item))
        except OSError:
            continue
    return found


def _schedule_windows_deferred_self_cleanup(st_root: Path) -> bool:
    """Spawn windowless detached `cmd.exe` to clean residual locked `.venv` shell dir after Python exits."""
    st_str = str(st_root)
    if not st_str or any(ch in st_str for ch in ('"', "&", "|", ";", "\r", "\n")):
        return False
    cmd_exe = resolve_windows_system_exe("cmd.exe") or "cmd.exe"
    cmdline = f'"{cmd_exe}" /s /d /c "ping -n 3 127.0.0.1 >nul & rmdir /s /q "{st_str}""'
    try:
        subprocess.Popen(
            cmdline,
            cwd=tempfile.gettempdir(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS,
        )
        return True
    except OSError:
        return False


def _find_recovery_dirs(state_root: Path, workspace_roots: List[str]) -> List[str]:
    found: List[str] = []
    seen: Set[str] = set()
    search_bases = [state_root] + [Path(w) for w in workspace_roots if w]
    for base in search_bases:
        if not base.is_dir():
            continue
        for rname in RECOVERY_PRESERVE_NAMES:
            cand = base / rname
            if cand.exists():
                norm = os.path.normcase(str(cand.resolve()))
                if norm not in seen:
                    seen.add(norm)
                    found.append(str(cand))
    return found


def run_uninstall(
    state_root: Path,
    *,
    prefix: str = "",
    purge: bool = False,
    dry_run: bool = False,
    home_dir: Optional[Path] = None,
    appdata_dir: Optional[Path] = None,
    platform_name: Optional[str] = None,
    desktop_dir: Optional[Path] = None,
    winreg_store: Optional[Dict[str, str]] = None,
    uninstall_reg_store: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Idempotently uninstall Cosmos MCP while isolating non-default `--prefix` and preserving recovery vaults."""
    st_root = Path(state_root).expanduser().resolve()
    eff_p = (prefix or "").strip().lower()
    is_scoped_non_default = bool(eff_p and eff_p != "pc")
    eff_home = Path(home_dir).expanduser() if home_dir is not None else Path(
        os.environ.get("USERPROFILE") or os.environ.get("HOME") or str(Path.home())
    ).expanduser()
    eff_desktop = Path(desktop_dir).expanduser() if desktop_dir is not None else (eff_home / "Desktop")

    ws_roots: List[str] = []
    configured_ports: Set[int] = set()
    cfg_dir = st_root / "config"
    if cfg_dir.is_dir():
        cfg_glob = f"service_{eff_p}.json" if is_scoped_non_default else "service*.json"
        for cf in cfg_dir.glob(cfg_glob):
            try:
                doc = json.loads(cf.read_text(encoding="utf-8-sig"))
                if isinstance(doc, dict):
                    for w in (doc.get("workspace_roots") or []):
                        if w and str(w) not in ws_roots:
                            ws_roots.append(str(w))
                    if doc.get("workspace") and str(doc["workspace"]) not in ws_roots:
                        ws_roots.append(str(doc["workspace"]))
                    if doc.get("port"):
                        try:
                            configured_ports.add(int(doc["port"]))
                        except (TypeError, ValueError):
                            pass
            except Exception:
                continue

    primary_norms, primary_state_exists = _resolve_primary_state_roots(
        eff_home,
        appdata_dir=appdata_dir,
        platform_name=platform_name,
    )
    is_default_state_root = os.path.normcase(str(st_root)) in primary_norms

    managed_subdirs = [
        "secrets",
        "state",
        "logs",
        "config",
        "bin",
        ".venv",
        "app_src",
        "app_src_prev",
        "browser_profile",
        "locks",
        "skills_store",
        "staging",
        "python-embed",
    ]
    extra_purge_names = ("history", "trash", *RECOVERY_PRESERVE_NAMES)

    def _collect_planned_removals() -> List[str]:
        items: List[str] = []
        if is_scoped_non_default:
            for sub_name, pats in (
                ("config", (f"service_{eff_p}.json",)),
                (
                    "state",
                    (
                        f"service_{eff_p}.json",
                        f"daemon_status_{eff_p}.json",
                        f"oauth_{eff_p}.sqlite3*",
                        f"latest_consent_pair_code_{eff_p}.txt",
                        f"latest_dynamic_pair_code_{eff_p}.txt",
                    ),
                ),
                ("secrets", (f"*_{eff_p}.*", f"*_{eff_p}")),
                ("logs", (f"*_{eff_p}.log", f"*_{eff_p}.out.log", f"*_{eff_p}.err.log")),
            ):
                sd = st_root / sub_name
                if sd.is_dir():
                    for pat in pats:
                        for match_p in sorted(sd.glob(pat)):
                            if match_p.exists() and str(match_p) not in items:
                                items.append(str(match_p))
            conn_sc = st_root / f"连接信息_CONNECTION_INFO_{eff_p}.txt"
            if conn_sc.exists() and str(conn_sc) not in items:
                items.append(str(conn_sc))
            return items

        for sub in managed_subdirs:
            cand = st_root / sub
            if cand.exists() and str(cand) not in items:
                items.append(str(cand))
        root_cfg_json = st_root / "config.json"
        if root_cfg_json.is_file() and str(root_cfg_json) not in items:
            items.append(str(root_cfg_json))
        if st_root.is_dir():
            if purge and (st_root / ".env").is_file():
                items.append(str(st_root / ".env"))
            for txt_f in st_root.glob("*CONNECTION_INFO*.txt"):
                if str(txt_f) not in items:
                    items.append(str(txt_f))
            if purge:
                for rec_name in extra_purge_names:
                    rc = st_root / rec_name
                    if rc.exists() and str(rc) not in items:
                        items.append(str(rc))
        return items

    planned_removals = _collect_planned_removals()
    start_menu_dirs = _resolve_windows_start_menu_dirs(
        eff_home,
        home_dir=home_dir,
        appdata_dir=appdata_dir,
        platform_name=platform_name,
    )

    shortcut_removals = _find_shortcut_files(
        st_root,
        eff_desktop,
        extra_shortcut_dirs=start_menu_dirs,
        is_default_state_root=is_default_state_root,
        primary_state_exists=primary_state_exists,
        configured_ports=configured_ports,
        prefix_filter=eff_p if is_scoped_non_default else "",
    )
    for sc_str in shortcut_removals:
        if sc_str not in planned_removals:
            planned_removals.append(sc_str)

    desktop_res = unbind_desktop_clients(
        state_root=st_root,
        prefix=eff_p,
        dry_run=dry_run,
        home_dir=eff_home,
        appdata_dir=appdata_dir,
        platform_name=platform_name,
    )

    if dry_run:
        preserved_pre = _find_recovery_dirs(st_root, ws_roots) if not purge else [
            p for p in _find_recovery_dirs(st_root, ws_roots)
            if not Path(os.path.normcase(p)).is_relative_to(Path(os.path.normcase(str(st_root))))
        ]
        out_dry: Dict[str, Any] = {
            "ok": True,
            "dry_run": True,
            "purge": purge,
            "prefix": eff_p or "pc",
            "scoped_instance_only": is_scoped_non_default,
            "state_root": str(st_root),
            "planned_removals": planned_removals,
            "shortcuts_planned": shortcut_removals,
            "desktop_unbind": desktop_res,
            "preserved_recovery_dirs": preserved_pre,
        }
        if not purge:
            out_dry["purge_hint"] = UNINSTALL_PURGE_HINT_ZH
        return out_dry

    prefixes_to_stop = [eff_p] if eff_p else ["pc"]
    state_d = st_root / "state"
    cfg_d = st_root / "config"
    if not is_scoped_non_default:
        if state_d.is_dir():
            for df in state_d.glob("daemon_status_*.json"):
                p_cand = df.stem.replace("daemon_status_", "").strip()
                if p_cand and p_cand not in prefixes_to_stop:
                    prefixes_to_stop.append(p_cand)
        if cfg_d.is_dir():
            for cf in cfg_d.glob("service_*.json"):
                p_cand = cf.stem.replace("service_", "").strip()
                if p_cand and p_cand not in prefixes_to_stop:
                    prefixes_to_stop.append(p_cand)
    stopped: List[Dict[str, Any]] = []
    for p_item in prefixes_to_stop:
        stopped.append(stop_daemon(st_root, prefix=p_item))

    autostart_removed: List[Dict[str, Any]] = []
    windows_uninstall_removed: List[Dict[str, Any]] = []
    for p_item in prefixes_to_stop:
        autostart_removed.append(
            disable_autostart(
                state_root=st_root,
                prefix=p_item,
                platform_name=platform_name,
                home_dir=eff_home,
                winreg_store=winreg_store,
                run_ctl=(platform_name is None),
                is_default_state_root=is_default_state_root,
                primary_state_exists=primary_state_exists,
            )
        )
        windows_uninstall_removed.append(
            unregister_windows_uninstall_entry(
                state_root=st_root,
                prefix=p_item,
                platform_name=platform_name,
                uninstall_reg_store=uninstall_reg_store,
                is_default_state_root=is_default_state_root,
                primary_state_exists=primary_state_exists,
            )
        )

    removed_paths: List[str] = []
    shortcuts_removed: List[str] = []
    deferred_self_cleanup_scheduled = False
    shortcut_norm_set = {os.path.normcase(x) for x in shortcut_removals}
    post_stop_removals = _collect_planned_removals()
    for sc_str in shortcut_removals:
        if sc_str not in post_stop_removals:
            post_stop_removals.append(sc_str)

    if purge:
        existed_set = {
            os.path.normcase(p_str)
            for p_str in post_stop_removals
            if Path(p_str).exists() or Path(p_str).is_symlink()
        }
        _shred_sensitive_state_files(st_root, prefix_filter=eff_p if is_scoped_non_default else "")
        for p_str in post_stop_removals:
            target = Path(p_str)
            norm_p = os.path.normcase(p_str)
            if _purge_path_permanently(target) and norm_p in existed_set:
                removed_paths.append(p_str)
                if norm_p in shortcut_norm_set:
                    shortcuts_removed.append(p_str)
        if not is_scoped_non_default:
            st_norm = Path(os.path.normcase(str(st_root)))
            protected_norms = {
                os.path.normcase(str(eff_home.resolve())),
                os.path.normcase(str(eff_desktop.resolve())) if eff_desktop.exists() else os.path.normcase(str(eff_desktop)),
            }
            has_ws_inside_state = any(
                Path(os.path.normcase(str(Path(w).resolve()))).is_relative_to(st_norm)
                for w in ws_roots
                if w and Path(w).exists() and os.path.normcase(str(Path(w).resolve())) != str(st_norm)
            )
            is_safe_state_root = (
                st_root.parent != st_root
                and str(st_norm) not in protected_norms
                and not has_ws_inside_state
            )
            if st_root.exists() and is_safe_state_root:
                if _purge_path_permanently(st_root) and str(st_root) not in removed_paths:
                    removed_paths.append(str(st_root))
            if (
                st_root.exists()
                and is_safe_state_root
                and sys.platform == "win32"
                and platform_name is None
                and not os.environ.get("PYTEST_CURRENT_TEST")
            ):
                try:
                    exe_norm = Path(os.path.normcase(str(Path(sys.executable).resolve())))
                    exe_inside_st = exe_norm.is_relative_to(st_norm)
                except OSError:
                    exe_inside_st = False
                if exe_inside_st and _schedule_windows_deferred_self_cleanup(st_root):
                    deferred_self_cleanup_scheduled = True
    else:
        trash_undo_base = st_root / ".undo_history"
        for p_str in post_stop_removals:
            target = Path(p_str)
            if not target.exists():
                continue
            res_tr = safe_trash_file(target, reason="uninstall", undo_dir=trash_undo_base)
            if res_tr.get("ok") or not target.exists():
                removed_paths.append(p_str)
                if os.path.normcase(p_str) in shortcut_norm_set:
                    shortcuts_removed.append(p_str)
            else:
                dest = trash_undo_base / "trash" / f"{int(time.time() * 1000)}_{target.name}"
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(target), str(dest))
                removed_paths.append(p_str)
                if os.path.normcase(p_str) in shortcut_norm_set:
                    shortcuts_removed.append(p_str)

    preserved_after = _find_recovery_dirs(st_root, ws_roots)
    out_final: Dict[str, Any] = {
        "ok": True,
        "dry_run": False,
        "purge": purge,
        "prefix": eff_p or "pc",
        "scoped_instance_only": is_scoped_non_default,
        "state_root": str(st_root),
        "stopped": stopped,
        "autostart_removed": autostart_removed,
        "windows_uninstall_removed": windows_uninstall_removed,
        "desktop_unbind": desktop_res,
        "removed_paths": removed_paths,
        "shortcuts_removed": shortcuts_removed,
        "preserved_recovery_dirs": preserved_after,
        "deferred_self_cleanup_scheduled": deferred_self_cleanup_scheduled,
    }
    if not purge:
        out_final["purge_hint"] = UNINSTALL_PURGE_HINT_ZH
    return out_final
