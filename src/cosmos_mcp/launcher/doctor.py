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

import getpass
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
import zipfile

from cosmos_mcp.core.fs_tx import safe_trash_file
from cosmos_mcp.core.net_power import detect_configured_proxy
from cosmos_mcp.core.proc import read_log_tail_bounded
from cosmos_mcp.launcher.autostart import disable_autostart, get_autostart_status
from cosmos_mcp.launcher.bootstrap import (
    check_runtime_deps_ready,
    find_embedded_python_exe,
    find_suitable_python,
    resolve_windows_system_exe,
    venv_python_path,
)
from cosmos_mcp.launcher.clients import unbind_desktop_clients
from cosmos_mcp.launcher.daemon import detect_running_instance, stop_daemon
from cosmos_mcp.launcher.tunnels import load_tunnel_token

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


def run_doctor(
    state_root: Path,
    *,
    prefix: str = "pc",
    bundle: bool = False,
    bundle_output: Optional[Path] = None,
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
            for pat in (f"oauth_{scoped_p}.sqlite3*", f"*_{scoped_p}.txt", f"*_{scoped_p}.json"):
                for item in list(st_dir_sc.glob(pat)):
                    if item.is_file() or item.is_symlink():
                        _wipe_one(item)
        conn_sc = st_root / f"连接信息_CONNECTION_INFO_{scoped_p}.txt"
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
            "srvus_ed25519*",
            "vps_id_ed25519*",
            "tunnel_token*.txt",
            "connection*.txt",
        ):
            for item in list(sec_dir.glob(explicit_pat)):
                if item.is_file() or item.is_symlink():
                    _wipe_one(item)
        for item in list(sec_dir.rglob("*")):
            if item.is_file() or item.is_symlink():
                _wipe_one(item)

    st_dir = st_root / "state"
    if st_dir.is_dir():
        for pat in ("oauth*.sqlite3*", "oauth*", "latest_consent_pair_code*", "latest_dynamic_pair_code*", "*secret*", "*token*"):
            for item in list(st_dir.glob(pat)):
                if item.is_file() or item.is_symlink():
                    _wipe_one(item)

    if st_root.is_dir():
        dotenv_f = st_root / ".env"
        if dotenv_f.is_file() or dotenv_f.is_symlink():
            _wipe_one(dotenv_f)
        for conn_f in list(st_root.glob("*CONNECTION_INFO*.txt")):
            if conn_f.is_file() or conn_f.is_symlink():
                _wipe_one(conn_f)
        for vault_sub in (".undo_history", "trash", ".trash", ".localpc_trash"):
            v_dir = st_root / vault_sub
            if v_dir.is_dir():
                for item in list(v_dir.rglob("*")):
                    if not (item.is_file() or item.is_symlink()):
                        continue
                    low_n = item.name.lower()
                    if (
                        "auth.json" in low_n
                        or "oauth" in low_n
                        or "connection" in low_n
                        or "tunnel_" in low_n
                        or "cloudflare_api_token" in low_n
                        or "workers_tunnel_secret" in low_n
                        or "public_gateway_secret" in low_n
                        or "vps_node_secret" in low_n
                        or "master_seed" in low_n
                        or "srvus_ed25519" in low_n
                        or "vps_id_ed25519" in low_n
                        or "_secret" in low_n
                        or "_token" in low_n
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
    """Match only Cosmos MCP / Cosmos Studio / LocalPC-MCP `.lnk`, `.bat`, `.url`, `.command` shortcut files."""
    if not path.is_file():
        return False
    low = path.name.lower()
    if not low.endswith((".lnk", ".bat", ".url", ".command")):
        return False
    stem = path.stem.lower()
    exact_prefixes = (
        "一键启动_cosmos_mcp",
        "一键启动_localpc",
        "cosmos_mcp",
        "cosmos-mcp",
        "cosmos studio",
        "cosmos_studio",
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

    if st_norm_slash and st_norm_slash in combined_norm:
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
        or re.search(r"[a-z]:\\", low)
        or re.search(r"\\(?:users|home)\\", low)
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


def _find_shortcut_files(
    state_root: Path,
    desktop_dir: Optional[Path],
    *,
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
    for d in (state_root, desktop_dir):
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

    shortcut_removals = _find_shortcut_files(
        st_root,
        eff_desktop,
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

    removed_paths: List[str] = []
    shortcuts_removed: List[str] = []
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
            if (
                st_root.exists()
                and st_root.parent != st_root
                and str(st_norm) not in protected_norms
                and not has_ws_inside_state
            ):
                if _purge_path_permanently(st_root) and str(st_root) not in removed_paths:
                    removed_paths.append(str(st_root))
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
        "desktop_unbind": desktop_res,
        "removed_paths": removed_paths,
        "shortcuts_removed": shortcuts_removed,
        "preserved_recovery_dirs": preserved_after,
    }
    if not purge:
        out_final["purge_hint"] = UNINSTALL_PURGE_HINT_ZH
    return out_final
