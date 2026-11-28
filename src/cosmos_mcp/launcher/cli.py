"""Unified pure-stdlib CLI entry (`cosmos-mcp` / `localpc-mcp`) for Cosmos MCP Standalone Surface.

Subcommands:
- `setup`            : Interactive human wizard or non-interactive one-shot setup (`--mode`, `--workspace`, `--tunnel-token`, ...)
- `start` / `daemon` : Start background resident daemon supervisor (preserving saved remote tunnel mode when `--mode` omitted)
- `status`           : Inspect live online state, public URL, connection password, 4-char pair code & 6-digit dynamic pair code (`--json`)
- `permissions`      : Hot-switch safety mode, multi-workspace / readonly roots, capability packs, or revoke tokens (`--json`)
- `export-identity`  : Export encrypted PNG identity & workspace policy recovery card (`--out`, `--passphrase`, `--json`)
- `import-identity`  : Import encrypted PNG identity & workspace policy recovery card (`--in`, `--passphrase`, `--json`)
- `identity`         : Unified alias (`--export <png>` / `--import <png>`) for identity recovery card management
- `doctor`           : Deep-redacted diagnostics (`--bundle`, `--json`)
- `agent-setup`      : Non-interactive deployment (`--json`); explicit instructions only with `--guide`
- `bind-desktop`     : Opt-in lossless desktop IDE/CLI binding & unbinding (`--clients`, `--unbind`, `--json`)
- `vps-caddy-snippet`: Output Caddy reverse-proxy config for `--mode vps` (`--domain`, `--remote-port`)
- `stop`             : Gracefully stop resident supervisor, tunnel & server (`--json`)
- `uninstall`        : Idempotent uninstall cleaning desktop `.lnk`/`.bat` shortcuts while preserving `.undo_history` & `trash`
- `stdio`            : Zero-daemon `--stdio` server bound to parent IDE lifecycle
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit
import zlib

from cosmos_mcp.core.config import (
    _clean_public_https_url,
    collect_pinned_gateway_urls,
    mode_to_gateway_slot,
    normalize_gateways_config,
    normalize_readonly_workspace_roots,
)
from cosmos_mcp.core.contracts import (
    CANONICAL_TIER_MAP,
    TIER_NUMERIC_LEVEL,
    TIER_ORDER,
    UNAMBIGUOUS_PW_ALPHABET,
    UNAMBIGUOUS_PW_PREFIX_RE,
)
from cosmos_mcp.core.fs_tx import atomic_write_json
from cosmos_mcp.core.guard import expand_env_and_tilde
from cosmos_mcp.core.proc import CREATE_NO_WINDOW, resolve_console_python
from cosmos_mcp.launcher.autostart import (
    enable_autostart,
    get_autostart_status,
    register_windows_uninstall_entry,
)
from cosmos_mcp.launcher.bootstrap import (
    atomic_write_text,
    ensure_runtime_environment,
    find_repo_root,
    find_repo_src_dir,
    find_suitable_python,
    resolve_persisted_src_dir,
    venv_python_path,
)
from cosmos_mcp.launcher.clients import (
    DESKTOP_CLIENT_SPECS,
    bind_desktop_clients,
    detect_installed_clients,
    unbind_desktop_clients,
)
from cosmos_mcp.launcher.daemon import (
    bind_stdio_to_parent_lifecycle,
    detect_running_instance,
    interactive_hot_switch_menu,
    service_cfg_path,
    spawn_detached_daemon,
    stop_daemon,
)
from cosmos_mcp.launcher.cf_workers_gateway import (
    PNG_SIGNATURE,
    _decrypt_recovery_bytes_scrypt_aesgcm,
    _encrypt_recovery_bytes_scrypt_aesgcm,
    delete_cloudflare_workers_gateway,
    ensure_master_seed_identity,
    probe_public_gateway_online,
)
from cosmos_mcp.launcher.doctor import (
    UNINSTALL_PURGE_HINT_ZH,
    _resolve_primary_state_roots,
    run_doctor,
    run_uninstall,
)
from cosmos_mcp.launcher.updater import (
    check_for_updates,
    check_pyproject_deps_satisfied,
    last_update_status_path,
    stage_and_apply_update,
)
from cosmos_mcp.launcher.tunnels import (
    QUICK_TUNNEL_REBOOT_NOTICE_ZH,
    export_identity_recovery_png,
    generate_vps_caddy_snippet,
    import_identity_recovery_png,
    load_tunnel_token,
    normalize_tunnel_token,
    save_tunnel_token,
)
from cosmos_mcp.protocol.oauth import derive_dynamic_pair_code

CLI_VERSION = "1.2.1"
PREFIX_RE = UNAMBIGUOUS_PW_PREFIX_RE
TIER_MAP = CANONICAL_TIER_MAP
_ = (TIER_NUMERIC_LEVEL, TIER_ORDER)

SUPPORTED_TUNNEL_MODES: Tuple[str, ...] = (
    "local",
    "cloudflare",
    "cloudflare_token",
    "workers_dev",
    "cf_workers",
    "cloudflare_workers",
    "public_gateway",
    "openssh",
    "srv_us",
    "vps",
    "vps_hub",
    "reverse_proxy",
    "custom",
)

TOOLSET_MAP: Dict[str, str] = {
    "standard": "standard",
    "default": "standard",
    "recommended": "standard",
    "core": "standard",
    "core_16": "standard",
    "minimal": "minimal",
    "lean": "minimal",
    "compact": "minimal",
    "symbol": "symbol",
    "hybrid": "hybrid",
    "full": "full",
    "all": "full",
}

TOOLSET_DISPLAY_ZH: Dict[str, str] = {
    "standard": "核心工具 16 项",
    "minimal": "精简工具 7 项",
    "symbol": "符号工具 16 项",
    "hybrid": "协作工具 11 项",
    "full": "完整工具 16 项",
}

TIER_DISPLAY_ZH: Dict[str, str] = {
    "tier1_readonly": "只读浏览模式",
    "tier2_workspace_edit": "仅修改文件（禁运行命令）",
    "tier3_workspace_dev": "工作区内顺畅开发",
    "tier4_full_power": "全盘顺畅开发（不限目录）",
}


def _format_tier_zh(tier_key: str) -> str:
    tk = str(tier_key or "tier3_workspace_dev").strip()
    return TIER_DISPLAY_ZH.get(tk, tk)


DEFAULT_REDIRECT_HOSTS: Tuple[str, ...] = (
    "oauth-redirect.googleusercontent.com",
    "oauth-redirect-sandbox.googleusercontent.com",
    "oauth-redirect-test.googleusercontent.com",
    "vertexaisearch.cloud.google.com",
    "chatgpt.com",
)


def is_protected_system_dir(cand: Path, *, state_root: Optional[Path] = None) -> bool:
    """Return True if `cand` is a drive/filesystem root or protected OS system directory."""
    try:
        resolved = cand.expanduser().resolve()
    except OSError:
        return True

    if resolved.parent == resolved:
        return True

    norm_s = os.path.normcase(str(resolved)).rstrip("\\/")
    if state_root is not None:
        try:
            st_res = Path(state_root).expanduser().resolve()
            for sub in ("secrets", "state"):
                sec_norm = os.path.normcase(str((st_res / sub).resolve())).rstrip("\\/")
                if norm_s == sec_norm or norm_s.startswith(sec_norm + os.sep):
                    return True
        except OSError:
            pass

    if sys.platform == "win32":
        protected_roots: List[str] = []
        for env_key, fallback in (
            ("SystemRoot", r"C:\Windows"),
            ("WINDIR", r"C:\Windows"),
            ("ProgramFiles", r"C:\Program Files"),
            ("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            ("ProgramData", r"C:\ProgramData"),
        ):
            val = (os.environ.get(env_key) or fallback).strip()
            if val:
                protected_roots.append(os.path.normcase(str(Path(val))).rstrip("\\/"))
        for pr in protected_roots:
            if norm_s == pr or norm_s.startswith(pr + "\\"):
                return True
        parts_low = [p.lower() for p in resolved.parts]
        if any(seg in ("system32", "syswow64", "$recycle.bin", "system volume information") for seg in parts_low):
            return True
    else:
        posix_protected = ("/bin", "/sbin", "/usr", "/etc", "/var", "/proc", "/sys", "/dev", "/boot", "/System", "/Library")
        for pr in posix_protected:
            if norm_s == pr or norm_s.startswith(pr + "/"):
                return True
    return False


def _is_cosmos_software_dir(cand: Path, *, state_root: Optional[Path] = None) -> bool:
    """Return True if `cand` is the unpacked Cosmos MCP software bundle or state directory itself."""
    try:
        resolved = cand.expanduser().resolve()
    except OSError:
        return True
    norm_s = os.path.normcase(str(resolved)).rstrip("\\/")

    if state_root is not None:
        try:
            st_norm = os.path.normcase(str(Path(state_root).expanduser().resolve())).rstrip("\\/")
            if norm_s == st_norm or norm_s.startswith(st_norm + os.sep):
                return True
        except OSError:
            pass

    for own_dir in (find_repo_root(), find_repo_src_dir()):
        if own_dir is not None:
            try:
                own_norm = os.path.normcase(str(own_dir.resolve())).rstrip("\\/")
                if norm_s == own_norm or norm_s.startswith(own_norm + os.sep):
                    return True
            except OSError:
                continue

    if (
        (resolved / "src" / "cosmos_mcp" / "__init__.py").is_file()
        or (resolved / "cosmos_mcp" / "__init__.py").is_file()
        or (resolved / "一键启动_Cosmos_MCP.bat").is_file()
        or (resolved / "start_cosmos_mcp.sh").is_file()
    ):
        return True
    return False


def resolve_default_workspace(
    cwd: Optional[Path] = None,
    *,
    home: Optional[Path] = None,
    state_root: Optional[Path] = None,
) -> Path:
    """Default unconfigured first-run workspace to `~/CosmosWorkspace` (never the unpacked software dir)."""
    if cwd is not None:
        eff_cwd: Optional[Path] = None
        try:
            eff_cwd = Path(cwd).expanduser().resolve()
        except OSError:
            eff_cwd = None
        if (
            eff_cwd is not None
            and eff_cwd.is_dir()
            and not is_protected_system_dir(eff_cwd, state_root=state_root)
            and not _is_cosmos_software_dir(eff_cwd, state_root=state_root)
        ):
            return eff_cwd

    eff_home = (
        Path(home).expanduser().resolve()
        if home is not None
        else Path(os.environ.get("USERPROFILE") or os.environ.get("HOME") or str(Path.home())).expanduser().resolve()
    )
    fallback_ws = (eff_home / "CosmosWorkspace").resolve()
    fallback_ws.mkdir(parents=True, exist_ok=True)
    return fallback_ws


def _norm_prefix(raw: str) -> str:
    val = (raw or "").strip()
    if not val:
        return "pc"
    if not PREFIX_RE.fullmatch(val):
        raise ValueError(f"Invalid --prefix `{val}`: must match ^[a-z][a-z0-9_]{{0,15}}$.")
    return val


def _parse_tier(raw: str) -> str:
    t = (raw or "").strip().lower()
    friendly_alias = {
        "dev": "l3",
        "full_dev": "l3",
        "edit": "l2",
        "edit_only": "l2",
        "readonly": "l1",
        "read_only": "l1",
    }
    t = friendly_alias.get(t, t)
    if t not in TIER_MAP:
        raise ValueError(f"Unknown permission tier `{raw}` (expected L1, L2, L3, or L4).")
    return TIER_MAP[t]


def _parse_toolset(raw: str) -> str:
    val = (raw or "").strip().lower()
    if val not in TOOLSET_MAP:
        raise ValueError(f"Unknown toolset `{raw}` (expected standard, minimal, symbol, hybrid, or full).")
    return TOOLSET_MAP[val]


def _parse_packs(raw: Any) -> List[str]:
    if raw is None or raw == "":
        return []
    items = [x.strip().lower() for x in str(raw).split(",") if x.strip()]
    out: List[str] = []
    alias = {
        "browser": "browser",
        "browser_use": "browser",
        "playwright": "browser",
        "desktop": "cua",
        "cua": "cua",
        "cua_window": "cua",
        "gui": "cua",
    }
    for it in items:
        if it in ("none", "off", "clear", "false"):
            return []
        if it == "all":
            for pk in ("browser", "cua"):
                if pk not in out:
                    out.append(pk)
            continue
        mapped = alias.get(it)
        if not mapped:
            raise ValueError(f"Unknown capability pack `{it}` (expected browser, desktop, or none).")
        if mapped not in out:
            out.append(mapped)
    return out


def _format_cli_packs(packs: Sequence[str]) -> List[str]:
    """Echo user-facing canonical pack names (`desktop` instead of internal `cua`)."""
    out: List[str] = []
    for p in packs:
        val = "desktop" if str(p).strip().lower() == "cua" else str(p).strip()
        if val and val not in out:
            out.append(val)
    return out


def _parse_cli_bool_choice(raw: Any) -> bool:
    if isinstance(raw, bool):
        return raw
    s = str(raw or "").strip().lower()
    if s in ("true", "1", "yes", "on"):
        return True
    if s in ("false", "0", "no", "off"):
        return False
    raise argparse.ArgumentTypeError(f"Expected true or false, got {raw!r}.")


def _parse_readonly_workspaces_arg(raw_items: Optional[Sequence[str]]) -> Optional[List[str]]:
    if raw_items is None:
        return None
    tokens: List[str] = []
    for item in raw_items:
        s = str(item or "").strip()
        if not s:
            continue
        if s.lower() in ("none", "clear", "off", "false", "[]"):
            return []
        cand_whole = Path(expand_env_and_tilde(s)).expanduser()
        if "," in s and not cand_whole.exists():
            for part in s.split(","):
                p_clean = part.strip()
                if p_clean:
                    tokens.append(p_clean)
        else:
            tokens.append(s)
    resolved: List[str] = []
    seen: set[str] = set()
    for tok in tokens:
        if tok.lower() in ("none", "clear", "off", "false", "[]"):
            return []
        rp = Path(expand_env_and_tilde(tok)).expanduser().resolve()
        rp.mkdir(parents=True, exist_ok=True)
        nk = os.path.normcase(str(rp))
        if nk not in seen:
            seen.add(nk)
            resolved.append(str(rp))
    return resolved


def _strip_mcp_url_suffix(raw_url: str) -> str:
    val = str(raw_url or "").strip().rstrip("/")
    while val:
        low = val.lower()
        if low.endswith("/mcp/readonly"):
            val = val[: -len("/mcp/readonly")].rstrip("/")
        elif low.endswith("/mcp"):
            val = val[: -len("/mcp")].rstrip("/")
        else:
            break
    return val


def _normalize_cli_public_url(raw_url: Any, *, explicit: bool = False, tunnel_mode: str = "") -> str:
    val = _strip_mcp_url_suffix(str(raw_url or ""))
    if not val:
        return ""
    eff_tm = (tunnel_mode or "").strip().lower()
    if explicit:
        sp = urlsplit(val)
        scheme = (sp.scheme or "").strip().lower()
        host = (sp.hostname or "").strip().lower()
        is_loopback = host in ("127.0.0.1", "localhost", "::1")
        if eff_tm == "local":
            if scheme in ("http", "https") and is_loopback:
                return val
            if scheme == "http" and not is_loopback:
                raise ValueError(f"无效的 --public-url `{raw_url}`：不支持明文 http:// 非回环地址。")
        if scheme != "https" or not host or is_loopback:
            raise ValueError(
                f"无效的 --public-url `{raw_url}`：公网连接地址必须使用 https:// 协议且不能为本机回环或明文 http:// 地址。"
            )
        cleaned = _clean_public_https_url(val)
        if not cleaned:
            raise ValueError(f"无效的 --public-url `{raw_url}`：请提供有效的公网 https:// 域名。")
        return cleaned
    return _clean_public_https_url(val)


def _detect_cli_gateway_warning(state_root: Path, prefix: str, eff_mode: str, cfg_doc: Dict[str, Any]) -> str:
    eff = _norm_prefix(prefix)
    sec_dir = state_root / "secrets"
    tm = (eff_mode or "").strip().lower()
    if tm == "vps_hub":
        cands = [sec_dir / f"vps_node_secret_{eff}.txt", sec_dir / "vps_node_secret.txt"] if eff != "pc" else [sec_dir / "vps_node_secret.txt"]
        has_sec = bool(str(cfg_doc.get("vps_node_secret") or "").strip())
        for cp in cands:
            if cp.is_file():
                try:
                    if cp.read_text(encoding="utf-8", errors="replace").strip():
                        has_sec = True
                        break
                except OSError:
                    continue
        if not has_sec:
            return "vps_node_secret_missing"
    elif tm in ("workers_dev", "cf_workers", "cloudflare_workers"):
        cands_w = [sec_dir / f"workers_tunnel_secret_{eff}.txt", sec_dir / "workers_tunnel_secret.txt"] if eff != "pc" else [sec_dir / "workers_tunnel_secret.txt"]
        has_wt = False
        for cp in cands_w:
            if cp.is_file():
                try:
                    if cp.read_text(encoding="utf-8", errors="replace").strip():
                        has_wt = True
                        break
                except OSError:
                    continue
        if not has_wt:
            return "workers_tunnel_secret_missing"
    return ""


RECOVERY_POLICY_PNG_CHUNK = b"cPol"


def _inject_policy_chunk_into_png(png_bytes: bytes, policy_doc: Dict[str, Any], passphrase: str) -> bytes:
    """Embed encrypted `cPol` policy metadata chunk right before `IEND` inside a valid recovery PNG."""
    raw = bytes(png_bytes)
    if len(raw) < 20 or raw[:8] != PNG_SIGNATURE:
        return raw
    plain_bytes = json.dumps(policy_doc, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    env = _encrypt_recovery_bytes_scrypt_aesgcm(plain_bytes, passphrase, version=2)
    cdata = json.dumps(env, separators=(",", ":"), sort_keys=True).encode("utf-8")
    crc = zlib.crc32(RECOVERY_POLICY_PNG_CHUNK + cdata) & 0xFFFFFFFF
    custom_chunk = struct.pack("!I", len(cdata)) + RECOVERY_POLICY_PNG_CHUNK + cdata + struct.pack("!I", crc)

    pos = 8
    while pos + 8 <= len(raw):
        length = struct.unpack("!I", raw[pos : pos + 4])[0]
        ctype = raw[pos + 4 : pos + 8]
        crc_end = pos + 8 + length + 4
        if crc_end > len(raw):
            break
        if ctype == b"IEND":
            return raw[:pos] + custom_chunk + raw[pos:]
        pos = crc_end
    return raw


def _extract_policy_chunk_from_png(png_bytes: bytes, passphrase: str) -> Dict[str, Any]:
    """Read and decrypt optional `cPol` policy chunk from a recovery PNG if present."""
    raw = bytes(png_bytes)
    if len(raw) < 20 or raw[:8] != PNG_SIGNATURE:
        return {}
    pos = 8
    cpol_payload: Optional[bytes] = None
    while pos + 8 <= len(raw):
        length = struct.unpack("!I", raw[pos : pos + 4])[0]
        ctype = raw[pos + 4 : pos + 8]
        data_start = pos + 8
        data_end = data_start + length
        crc_end = data_end + 4
        if crc_end > len(raw):
            break
        cdata = raw[data_start:data_end]
        if ctype == RECOVERY_POLICY_PNG_CHUNK:
            expected_crc = struct.unpack("!I", raw[data_end:crc_end])[0]
            actual_crc = zlib.crc32(ctype + cdata) & 0xFFFFFFFF
            if actual_crc != expected_crc:
                raise ValueError("PNG CRC mismatch in `cPol` policy recovery chunk.")
            cpol_payload = cdata
            break
        if ctype == b"IEND":
            break
        pos = crc_end
    if cpol_payload is None:
        return {}
    env = json.loads(cpol_payload.decode("utf-8"))
    _, plain = _decrypt_recovery_bytes_scrypt_aesgcm(env, passphrase)
    doc = json.loads(plain.decode("utf-8"))
    return doc if isinstance(doc, dict) else {}


def resolve_cli_state_root(cli_state_dir: str = "", env: Optional[Dict[str, str]] = None) -> Path:
    from cosmos_mcp.core.config import default_user_state_dir

    eff_env = env if env is not None else os.environ
    explicit = (
        cli_state_dir
        or eff_env.get("COSMOS_MCP_STATE_DIR")
        or eff_env.get("LOCALPC_MCP_STATE_DIR")
        or ""
    ).strip()
    if explicit:
        return Path(expand_env_and_tilde(explicit)).expanduser().resolve()
    return default_user_state_dir(env=eff_env).resolve()


def _derive_pair_code(seed: str) -> str:
    clean = (seed or "").strip()
    if not clean:
        return "----"
    digest = hashlib.sha256(f"localpc-consent-pair:{clean}".encode("utf-8")).digest()
    return "".join(UNAMBIGUOUS_PW_ALPHABET[b & 31] for b in digest[:4])


def _generate_password() -> str:
    return "-".join("".join(secrets.choice(UNAMBIGUOUS_PW_ALPHABET) for _ in range(5)) for _ in range(4))


def _conn_filenames(prefix: str) -> Tuple[str, str]:
    eff = _norm_prefix(prefix)
    root_fn = f"连接信息_CONNECTION_INFO_{eff}.txt" if eff != "pc" else "连接信息_CONNECTION_INFO.txt"
    sec_fn = f"connection_{eff}.txt" if eff != "pc" else "connection.txt"
    return root_fn, sec_fn


def _extract_saved_password(state_root: Path, prefix: str = "pc") -> str:
    root_fn, sec_fn = _conn_filenames(prefix)
    for cand in (
        state_root / "secrets" / sec_fn,
        state_root / "secrets" / "connection.txt",
        state_root / root_fn,
        state_root / "连接信息_CONNECTION_INFO.txt",
    ):
        if cand.is_file():
            try:
                m = re.search(r"授权页连接口令\s*:\s*([^\r\n]+)", cand.read_text(encoding="utf-8", errors="replace"))
                if m:
                    pw = m.group(1).strip()
                    if pw and not pw.startswith("("):
                        return pw
            except Exception:
                continue
    return ""


def read_current_pair_code(state_root: Path, prefix: str = "pc", fallback_token: str = "") -> str:
    eff = _norm_prefix(prefix)
    st_dir = state_root / "state"
    candidates = (
        [st_dir / f"latest_consent_pair_code_{eff}.txt", st_dir / "latest_consent_pair_code.txt"]
        if eff != "pc"
        else [st_dir / "latest_consent_pair_code.txt"]
    )
    for p in candidates:
        if p.is_file():
            try:
                code = p.read_text(encoding="utf-8", errors="replace").strip()
                if code and len(code) == 4:
                    return code
            except Exception:
                continue
    return _derive_pair_code(fallback_token or f"device-{eff}")


def read_current_dynamic_pair_code(state_root: Path, prefix: str = "pc") -> str:
    """Compute live 6-digit dynamic pairing code using the same HMAC-SHA256 derivation as Studio/OAuth."""
    eff = _norm_prefix(prefix)
    auth_p = state_root / "secrets" / "auth.json"
    if auth_p.is_file():
        try:
            doc = json.loads(auth_p.read_text(encoding="utf-8-sig"))
            pw_hash = str(doc.get("password_hash") or "").strip()
            salt_hex = str(doc.get("salt") or "").strip()
            if pw_hash and salt_hex:
                return derive_dynamic_pair_code(pw_hash, salt_hex)
        except Exception:
            pass
    st_dir = state_root / "state"
    candidates = (
        [st_dir / f"latest_dynamic_pair_code_{eff}.txt", st_dir / "latest_dynamic_pair_code.txt"]
        if eff != "pc"
        else [st_dir / "latest_dynamic_pair_code.txt"]
    )
    for p in candidates:
        if p.is_file():
            try:
                code = p.read_text(encoding="utf-8", errors="replace").strip()
                if len(code) == 6 and code.isdigit():
                    return code
            except Exception:
                continue
    return ""


def create_oneclick_bat(
    state_root: Path,
    *,
    python_exe: Optional[str | Path] = None,
    port: int = 8096,
    prefix: str = "pc",
    target_dir: Optional[Path] = None,
) -> Path:
    """Generate zero-CLI `一键启动_Cosmos_MCP.bat` preferring `<state_root>/.venv` and `<state_root>/app_src`."""
    st_root = Path(state_root).expanduser().resolve()
    eff_p = _norm_prefix(prefix)
    dest_dir = Path(target_dir).expanduser().resolve() if target_dir is not None else st_root
    dest_dir.mkdir(parents=True, exist_ok=True)

    bat_name = "一键启动_Cosmos_MCP.bat" if eff_p == "pc" else f"一键启动_Cosmos_MCP_{eff_p}.bat"
    bat_path = dest_dir / bat_name

    venv_py = venv_python_path(st_root / ".venv", windowless=False)
    py_cand = str(python_exe or "").strip()
    if py_cand and Path(py_cand).is_file():
        py_console = resolve_console_python(py_cand)
    elif venv_py.is_file():
        py_console = resolve_console_python(str(venv_py))
    else:
        found = find_suitable_python()
        py_console = found[0] if found else resolve_console_python(sys.executable)

    persisted_src = resolve_persisted_src_dir(st_root)
    pypath_line = f'set "PYTHONPATH={persisted_src};%PYTHONPATH%"\r\n' if persisted_src is not None else ""
    prefix_arg = f" --prefix {eff_p}" if eff_p != "pc" else ""
    port_arg = f" --port {int(port)}" if int(port) != 8096 else ""

    bat_content = (
        "@echo off\r\n"
        "chcp 65001 >nul\r\n"
        "setlocal EnableExtensions\r\n"
        'set "PYTHONDONTWRITEBYTECODE=1"\r\n'
        'set "PYTHONUTF8=1"\r\n'
        f'set "COSMOS_MCP_STATE_DIR={st_root}"\r\n'
        f'set "LOCALPC_MCP_STATE_DIR={st_root}"\r\n'
        f"{pypath_line}"
        "echo 正在启动 Cosmos MCP 后台服务与本地控制面板...\r\n"
        'set "COSMOS_BAT_PY="\r\n'
        f'if exist "{st_root}\\python-embed\\python.exe" set "COSMOS_BAT_PY={st_root}\\python-embed\\python.exe"\r\n'
        f'if not defined COSMOS_BAT_PY if exist "{st_root}\\.venv\\Scripts\\python.exe" set "COSMOS_BAT_PY={st_root}\\.venv\\Scripts\\python.exe"\r\n'
        f'if not defined COSMOS_BAT_PY call :probe_py_cand "{py_console}"\r\n'
        "if not defined COSMOS_BAT_PY (\r\n"
        "    for /f \"delims=\" %%P in ('where python 2^>nul') do (\r\n"
        '        if not defined COSMOS_BAT_PY call :probe_py_cand "%%~fP"\r\n'
        "    )\r\n"
        ")\r\n"
        "if not defined COSMOS_BAT_PY (\r\n"
        "    for %%V in (313 312 311 310 314) do (\r\n"
        '        if not defined COSMOS_BAT_PY if defined LOCALAPPDATA call :probe_py_cand "%LOCALAPPDATA%\\Programs\\Python\\Python%%V\\python.exe"\r\n'
        '        if not defined COSMOS_BAT_PY if defined ProgramFiles call :probe_py_cand "%ProgramFiles%\\Python%%V\\python.exe"\r\n'
        '        if not defined COSMOS_BAT_PY call :probe_py_cand "C:\\Python%%V\\python.exe"\r\n'
        "    )\r\n"
        ")\r\n"
        "if not defined COSMOS_BAT_PY (\r\n"
        "    echo 未检测到可用的真实 Python 3.10~3.14 环境（已自动跳过 WindowsApps 空壳）。\r\n"
        "    if not defined COSMOS_NO_PAUSE pause\r\n"
        "    exit /b 1\r\n"
        ")\r\n"
        f'"%COSMOS_BAT_PY%" -B -m cosmos_mcp.launcher.cli start --state-dir "{st_root}"{port_arg}{prefix_arg} --open-browser %*\r\n'
        "if errorlevel 1 (\r\n"
        "    echo 启动遇到问题，请查看上方提示信息。\r\n"
        "    if not defined COSMOS_NO_PAUSE pause\r\n"
        "    exit /b 1\r\n"
        ")\r\n"
        "exit /b 0\r\n\r\n"
        ":probe_py_cand\r\n"
        'set "_CAND=%~1"\r\n'
        'if "%_CAND%"=="" exit /b 0\r\n'
        'if not exist "%_CAND%" exit /b 0\r\n'
        'echo "%_CAND%" | findstr /I "\\Microsoft\\WindowsApps\\" >nul && exit /b 0\r\n'
        '"%_CAND%" -B -c "import sys; raise SystemExit(0 if (3,10)<=sys.version_info[:2]<(3,15) else 1)" >nul 2>nul\r\n'
        'if not errorlevel 1 set "COSMOS_BAT_PY=%_CAND%"\r\n'
        "exit /b 0\r\n"
    )
    atomic_write_text(bat_path, bat_content)
    return bat_path


def create_desktop_shortcut(
    state_root: Path,
    port: int = 8096,
    desktop_dir: Optional[Path] = None,
    *,
    python_exe: Optional[str | Path] = None,
    prefix: str = "pc",
) -> Optional[Path]:
    """Create `一键启动_Cosmos_MCP.bat` (Windows) or `.url` shortcut on Desktop / `state_root`."""
    home = Path(os.environ.get("USERPROFILE") or os.environ.get("HOME") or str(Path.home())).expanduser()
    desk = Path(desktop_dir) if desktop_dir is not None else (home / "Desktop")
    target_dir = desk if desk.is_dir() else Path(state_root).expanduser().resolve()
    if sys.platform == "win32":
        return create_oneclick_bat(
            state_root,
            python_exe=python_exe,
            port=port,
            prefix=prefix,
            target_dir=target_dir,
        )
    shortcut_path = target_dir / "Cosmos Studio 本地控制台.url"
    content = f"[InternetShortcut]\nURL=http://127.0.0.1:{int(port)}/\n"
    atomic_write_text(shortcut_path, content)
    return shortcut_path


def ensure_standalone_state(
    state_root: Path,
    *,
    port: int = 8096,
    prefix: str = "pc",
    tool_prefix: str = "",
    device_label: str = "",
    tier_key: str = "",
    toolset_profile: str = "",
    workspace_roots: Optional[Sequence[str]] = None,
    readonly_workspace_roots: Optional[Sequence[str]] = None,
    scan_host_global_skills: Optional[bool] = None,
    tray_enabled: Optional[bool] = None,
    enabled_packs: Optional[Sequence[str]] = None,
    keep_awake: Optional[bool] = None,
    approval_popups: Optional[bool] = None,
    public_url: str = "",
    tunnel_mode: str = "",
    tunnel_token: Optional[str] = None,
    vps_ssh: Optional[str] = None,
    vps_remote_port: Optional[int] = None,
    vps_ssh_port: Optional[int] = None,
    vps_identity_file: Optional[str] = None,
    python_path: Optional[str] = None,
    cwd: Optional[Path] = None,
    reset_password: bool = False,
) -> Dict[str, Any]:
    """Pure-stdlib state/config/credential initializer preserving saved remote modes and extended policy fields."""
    st_root = Path(state_root).expanduser().resolve()
    eff_p = _norm_prefix(prefix)
    secrets_dir = st_root / "secrets"
    state_dir = st_root / "state"
    cfg_dir = st_root / "config"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    cfg_dir.mkdir(parents=True, exist_ok=True)

    cfg_path = service_cfg_path(st_root, eff_p)
    state_svc_path = state_dir / cfg_path.name
    cfg_candidates: List[Tuple[float, Dict[str, Any]]] = []
    for cand_p in (cfg_path, state_svc_path):
        if cand_p.is_file():
            try:
                loaded = json.loads(cand_p.read_text(encoding="utf-8-sig"))
                if isinstance(loaded, dict):
                    stamp = float(loaded.get("policy_updated_at") or cand_p.stat().st_mtime)
                    cfg_candidates.append((stamp, loaded))
            except Exception:
                continue
    cfg_candidates.sort(key=lambda item: item[0])
    cfg_doc: Dict[str, Any] = {}
    for _, d_item in cfg_candidates:
        cfg_doc.update(d_item)

    if tool_prefix:
        eff_tool_prefix = _norm_prefix(tool_prefix)
    else:
        saved_tp = str(cfg_doc.get("tool_prefix") or "").strip()
        if saved_tp and PREFIX_RE.fullmatch(saved_tp):
            eff_tool_prefix = saved_tp
        else:
            eff_tool_prefix = eff_p

    eff_tier = _parse_tier(tier_key) if tier_key else str(cfg_doc.get("permission_tier") or "tier3_workspace_dev")
    eff_toolset = _parse_toolset(toolset_profile) if toolset_profile else str(cfg_doc.get("toolset_profile") or "standard")
    eff_toolset = TOOLSET_MAP.get(eff_toolset.lower(), "standard")
    eff_label = (device_label or str(cfg_doc.get("device_label") or "")).strip() or (
        "Cosmos-PC" if eff_tool_prefix == "pc" else f"Cosmos-{eff_tool_prefix}"
    )

    if workspace_roots is not None and len(workspace_roots) > 0:
        resolved_roots: List[str] = []
        seen_w: set[str] = set()
        for raw_w in workspace_roots:
            wp = Path(expand_env_and_tilde(str(raw_w).strip())).expanduser().resolve()
            wp.mkdir(parents=True, exist_ok=True)
            nk = os.path.normcase(str(wp))
            if nk not in seen_w:
                seen_w.add(nk)
                resolved_roots.append(str(wp))
    else:
        saved_roots = cfg_doc.get("workspace_roots") or ([cfg_doc["workspace"]] if cfg_doc.get("workspace") else [])
        if saved_roots:
            resolved_roots = []
            for raw_w in saved_roots:
                wp = Path(expand_env_and_tilde(str(raw_w).strip())).expanduser().resolve()
                wp.mkdir(parents=True, exist_ok=True)
                resolved_roots.append(str(wp))
        else:
            default_ws = resolve_default_workspace(cwd=cwd, state_root=st_root)
            resolved_roots = [str(default_ws)]

    raw_ro_roots = readonly_workspace_roots if readonly_workspace_roots is not None else cfg_doc.get("readonly_workspace_roots")
    if readonly_workspace_roots is not None:
        seen_active = {os.path.normcase(x) for x in resolved_roots}
        for raw_ro in readonly_workspace_roots:
            ro_s = str(raw_ro or "").strip()
            if not ro_s:
                continue
            ro_p = Path(expand_env_and_tilde(ro_s)).expanduser().resolve()
            ro_p.mkdir(parents=True, exist_ok=True)
            nk_ro = os.path.normcase(str(ro_p))
            if nk_ro not in seen_active:
                seen_active.add(nk_ro)
                resolved_roots.append(str(ro_p))
    eff_ro_roots = [
        str(p)
        for p in normalize_readonly_workspace_roots(raw_ro_roots, [Path(p) for p in resolved_roots])
    ]
    eff_scan_host_skills = (
        bool(scan_host_global_skills)
        if scan_host_global_skills is not None
        else bool(cfg_doc.get("scan_host_global_skills", False))
    )
    eff_tray_enabled = (
        bool(tray_enabled)
        if tray_enabled is not None
        else bool(cfg_doc.get("tray_enabled", True))
    )

    eff_packs = list(enabled_packs) if enabled_packs is not None else list(cfg_doc.get("enabled_packs") or [])
    eff_awake = bool(keep_awake) if keep_awake is not None else bool(cfg_doc.get("keep_awake", True))
    eff_popups = bool(approval_popups) if approval_popups is not None else bool(cfg_doc.get("approval_popups", False))
    eff_port = int(port or cfg_doc.get("port") or 8096)

    if tunnel_token is not None:
        clean_tok = normalize_tunnel_token(tunnel_token)
        if clean_tok:
            save_tunnel_token(st_root, clean_tok, prefix=eff_p)
    saved_tok = load_tunnel_token(st_root, prefix=eff_p)

    explicit_mode = (tunnel_mode or "").strip().lower()
    saved_mode = str(cfg_doc.get("tunnel_mode") or "").strip().lower()
    has_explicit_pub = bool((public_url or "").strip())
    clean_explicit_pub = _normalize_cli_public_url(public_url, explicit=has_explicit_pub, tunnel_mode=explicit_mode)
    if explicit_mode:
        eff_mode = explicit_mode
    elif tunnel_token and normalize_tunnel_token(tunnel_token):
        eff_mode = "cloudflare_token"
    elif vps_ssh and str(vps_ssh).strip():
        eff_mode = "vps"
    elif saved_mode:
        eff_mode = saved_mode
    else:
        saved_pub_raw = clean_explicit_pub or _normalize_cli_public_url(cfg_doc.get("public_base"), explicit=False)
        eff_mode = "custom" if saved_pub_raw else "public_gateway"

    if eff_mode not in SUPPORTED_TUNNEL_MODES:
        eff_mode = "public_gateway"

    pg_online_flag: Optional[bool] = None
    instant_fb_flag: Optional[bool] = None
    eff_tm_out: str = eff_mode

    if explicit_mode == "local":
        eff_pub = ""
    elif eff_mode in ("public_gateway", "openssh", "srv_us"):
        pg_base = str(
            os.environ.get("COSMOS_PUBLIC_GATEWAY_BASE")
            or cfg_doc.get("public_gateway_base")
            or ""
        ).strip().rstrip("/")
        pg_probe = probe_public_gateway_online(pg_base, timeout_sec=1.5)
        if pg_probe.get("online"):
            pg_online_flag = True
            instant_fb_flag = False
            eff_tm_out = "public_gateway"
            seed_info = ensure_master_seed_identity(st_root, prefix=eff_p, gateway_base=str(pg_probe.get("base_url") or pg_base))
            eff_pub = clean_explicit_pub or _normalize_cli_public_url(seed_info.get("public_url"), explicit=False)
        else:
            pg_online_flag = False
            cand_inst_u = ""
            if isinstance(cfg_doc.get("gateways"), dict) and isinstance(cfg_doc["gateways"].get("instant"), dict):
                cand_inst_u = _normalize_cli_public_url(cfg_doc["gateways"]["instant"].get("public_url"), explicit=False)
            cand_saved = _normalize_cli_public_url(
                cfg_doc.get("public_base")
                or cfg_doc.get("public_base_url")
                or cand_inst_u
                or "",
                explicit=False,
            )
            explicit_pub = clean_explicit_pub
            if explicit_pub:
                eff_pub = explicit_pub
                if ".srv.us" in eff_pub.lower():
                    instant_fb_flag = False
                    eff_tm_out = "srv_us"
                else:
                    instant_fb_flag = "trycloudflare.com" in eff_pub.lower()
                    eff_tm_out = "cloudflare" if instant_fb_flag else "public_gateway"
            elif cand_saved and ".srv.us" in cand_saved.lower():
                eff_pub = cand_saved
                instant_fb_flag = False
                eff_tm_out = "srv_us"
            elif cand_saved and "trycloudflare.com" in cand_saved.lower():
                eff_pub = cand_saved
                instant_fb_flag = True
                eff_tm_out = "cloudflare"
            else:
                eff_pub = ""
                instant_fb_flag = True
                eff_tm_out = "cloudflare"
    else:
        mode_specific_pub = ""
        if eff_mode == "workers_dev":
            mode_specific_pub = _normalize_cli_public_url(cfg_doc.get("workers_dev_url"), explicit=False)
        elif eff_mode in ("vps", "vps_hub"):
            mode_specific_pub = _normalize_cli_public_url(cfg_doc.get("vps_hub_url"), explicit=False)
        eff_pub = clean_explicit_pub or _normalize_cli_public_url(cfg_doc.get("public_base"), explicit=False) or mode_specific_pub
        if eff_mode == "local":
            eff_pub = ""

    if python_path is not None:
        raw_pp = str(python_path).strip()
        eff_py_path = "" if raw_pp.lower() in ("none", "clear", "default", "") else expand_env_and_tilde(raw_pp)
    else:
        eff_py_path = str(cfg_doc.get("python_path") or "").strip()
    eff_vps_ssh = (
        str(vps_ssh).strip()
        if (vps_ssh is not None and str(vps_ssh).strip())
        else str(cfg_doc.get("vps_ssh") or "").strip()
    )
    eff_vps_rport = int(
        vps_remote_port
        if (vps_remote_port is not None and int(vps_remote_port) > 0)
        else (cfg_doc.get("vps_remote_port") or 18096)
    )
    eff_vps_sport = int(
        vps_ssh_port
        if (vps_ssh_port is not None and int(vps_ssh_port) > 0)
        else (cfg_doc.get("vps_ssh_port") or 22)
    )
    eff_vps_id = (
        str(vps_identity_file).strip()
        if (vps_identity_file is not None and str(vps_identity_file).strip())
        else str(cfg_doc.get("vps_identity_file") or "").strip()
    )
    eff_ann_mode = "strict" if eff_popups else "seamless"

    # Preserve any existing `workers_dev_*` / `public_gateway_*` metadata keys intact
    preserved_gw_fields: Dict[str, Any] = {
        k: v
        for k, v in cfg_doc.items()
        if k.startswith("workers_dev_") or k.startswith("public_gateway_")
    }
    if eff_mode == "workers_dev" and eff_pub and not preserved_gw_fields.get("workers_dev_url"):
        preserved_gw_fields["workers_dev_url"] = eff_pub
    elif eff_mode in ("public_gateway", "openssh", "srv_us") and eff_pub and ".srv.us" not in eff_pub.lower() and not preserved_gw_fields.get("public_gateway_url"):
        preserved_gw_fields["public_gateway_url"] = eff_pub

    gws_norm, sel_gw_norm = normalize_gateways_config(cfg_doc)
    had_saved_gateways = isinstance(cfg_doc.get("gateways"), dict) and bool(cfg_doc.get("gateways"))
    if explicit_mode or (tunnel_token and normalize_tunnel_token(tunnel_token)) or (vps_ssh and str(vps_ssh).strip()) or not had_saved_gateways:
        if eff_mode == "local":
            for _gid in gws_norm:
                gws_norm[_gid]["enabled"] = False
            sel_gw_norm = ""
        else:
            slot_id, sub_m = mode_to_gateway_slot(eff_mode)
            if slot_id:
                if explicit_mode:
                    for _gid in gws_norm:
                        gws_norm[_gid]["enabled"] = _gid == slot_id
                else:
                    gws_norm[slot_id]["enabled"] = True
                gws_norm[slot_id]["submode"] = sub_m
                if eff_pub:
                    gws_norm[slot_id]["public_url"] = eff_pub
                sel_gw_norm = slot_id
    else:
        if sel_gw_norm in gws_norm and eff_pub and not gws_norm[sel_gw_norm].get("public_url"):
            gws_norm[sel_gw_norm]["public_url"] = eff_pub
    pinned_gw_urls = collect_pinned_gateway_urls(gws_norm, {**cfg_doc, **preserved_gw_fields, "public_base": eff_pub})

    prev_non_ro_saved = str(cfg_doc.get("previous_non_readonly_tier") or "").strip().lower()
    if eff_tier in ("tier2_workspace_edit", "tier3_workspace_dev", "tier4_full_power"):
        eff_prev_non_ro = eff_tier
    elif prev_non_ro_saved in ("tier2_workspace_edit", "tier3_workspace_dev", "tier4_full_power"):
        eff_prev_non_ro = prev_non_ro_saved
    else:
        eff_prev_non_ro = "tier3_workspace_dev"

    cfg_doc.update(
        {
            **preserved_gw_fields,
            "host": "127.0.0.1",
            "port": eff_port,
            "permission_tier": eff_tier,
            "previous_non_readonly_tier": eff_prev_non_ro,
            "tool_prefix": eff_tool_prefix,
            "device_label": eff_label,
            "toolset_profile": eff_toolset,
            "prompt_profile": str(cfg_doc.get("prompt_profile") or "lean"),
            "workspace": resolved_roots[0],
            "workspace_roots": resolved_roots,
            "readonly_workspace_roots": eff_ro_roots,
            "scan_host_global_skills": eff_scan_host_skills,
            "tray_enabled": eff_tray_enabled,
            "enabled_packs": eff_packs,
            "keep_awake": eff_awake,
            "approval_popups": eff_popups,
            "annotation_mode": eff_ann_mode,
            "python_path": eff_py_path,
            "public_base": eff_pub,
            "public_base_url": eff_pub,
            "tunnel_mode": eff_mode,
            "_gateways_mirrored_mode": eff_mode,
            "gateways": gws_norm,
            "selected_gateway": sel_gw_norm,
            "pinned_gateway_urls": pinned_gw_urls,
            "vps_ssh": eff_vps_ssh,
            "vps_remote_port": eff_vps_rport,
            "vps_ssh_port": eff_vps_sport,
            "vps_identity_file": eff_vps_id,
            "redirect_hosts": list(cfg_doc.get("redirect_hosts") or DEFAULT_REDIRECT_HOSTS),
            "policy_updated_at": round(time.time(), 6),
        }
    )
    atomic_write_json(cfg_path, cfg_doc)
    if state_svc_path.is_file():
        atomic_write_json(state_svc_path, cfg_doc)

    auth_path = secrets_dir / "auth.json"
    password_plain = _extract_saved_password(st_root, eff_p)
    creds: Dict[str, Any] = {}
    if auth_path.is_file() and not reset_password:
        try:
            creds = json.loads(auth_path.read_text(encoding="utf-8-sig"))
        except Exception:
            creds = {}

    if not creds.get("password_hash") or not creds.get("salt") or not creds.get("local_api_token") or reset_password:
        password_plain = _generate_password()
        salt = secrets.token_bytes(16)
        existing_tok = str(creds.get("local_api_token") or "") if not reset_password else ""
        local_tok = existing_tok or ("lpcmcp_" + secrets.token_urlsafe(24))
        creds = {
            "salt": salt.hex(),
            "password_hash": hashlib.scrypt(password_plain.encode("utf-8"), salt=salt, n=16384, r=8, p=1).hex(),
            "local_api_token": local_tok,
        }
        atomic_write_text(auth_path, json.dumps(creds, indent=2) + "\n", mode_override=0o600)
        if reset_password:
            atomic_write_json(
                state_dir / "kill_signal.json",
                {
                    "ts": time.time(),
                    "ts_ns": time.time_ns(),
                    "reason": "reset_password",
                    "prefix_filter": eff_p,
                    "emitter_pid": os.getpid(),
                },
            )

    if eff_mode == "local":
        disp_url = f"http://127.0.0.1:{eff_port}"
    else:
        disp_url = eff_pub if eff_pub.startswith("https://") else ""
    disp_label_url = disp_url or "(正在建立加密连接… 启动后自动生成公网 HTTPS 地址)"
    pw_for_file = password_plain or "(已初始化，如需重置请运行 cosmos-mcp permissions --reset-password)"
    cf_notice_line = (
        f"  [临时地址提示] : {QUICK_TUNNEL_REBOOT_NOTICE_ZH}\n"
        if (eff_mode == "cloudflare" or instant_fb_flag is True)
        else ""
    )
    info_txt = (
        "====================================================================\n"
        " Cosmos MCP 连接信息（含本机专属授权口令与管理令牌，请勿外传）\n"
        "====================================================================\n"
        f" 当前安全模式   : {_format_tier_zh(eff_tier)}\n"
        f" 当前核心工具   : {TOOLSET_DISPLAY_ZH.get(eff_toolset, eff_toolset)}\n"
        f" 当前设备标识   : {eff_label} (工具前缀: {eff_tool_prefix}_*)\n\n"
        "【网页版 Gemini / 网页版 ChatGPT 连接参数】\n"
        f"  主连接器地址   : {f'{disp_url}/mcp' if disp_url else disp_label_url}\n"
        f"  纯只读端点地址 : {f'{disp_url}/mcp/readonly' if disp_url else disp_label_url}  (供网页版 ChatGPT 个人 Plus / Pro 账号安全挂载)\n"
        f"  动态守则地址   : {f'{disp_url}/skill' if disp_url else disp_label_url}\n"
        f"{cf_notice_line}"
        f"  6 位动态配对码 : 本机浏览器打开 http://127.0.0.1:{eff_port}/ 实时查看（本机默认免输口令一键通过）\n"
        f"  授权页连接口令 : {pw_for_file}\n"
        f"  本地控制中心   : http://127.0.0.1:{eff_port}/\n"
    )
    root_fn, sec_fn = _conn_filenames(eff_p)
    atomic_write_text(st_root / root_fn, info_txt, mode_override=0o600)
    atomic_write_text(secrets_dir / sec_fn, info_txt, mode_override=0o600)

    venv_py = venv_python_path(st_root / ".venv", windowless=False)
    bat_p = create_oneclick_bat(
        st_root,
        python_exe=venv_py if venv_py.is_file() else None,
        port=eff_port,
        prefix=eff_p,
    )
    if sys.platform == "win32":
        register_windows_uninstall_entry(
            st_root,
            python_exe=venv_py if venv_py.is_file() else None,
            prefix=eff_p,
            display_version=CLI_VERSION,
        )
    pair_code = read_current_pair_code(st_root, eff_p, fallback_token=str(creds["local_api_token"]))
    dynamic_pair_code = derive_dynamic_pair_code(str(creds.get("password_hash") or ""), str(creds.get("salt") or ""))
    studio_local_url = f"http://127.0.0.1:{eff_port}/"
    gw_warn = _detect_cli_gateway_warning(st_root, eff_p, eff_mode, cfg_doc)
    extra_pg_state: Dict[str, Any] = {}
    if pg_online_flag is not None:
        extra_pg_state["public_gateway_online"] = pg_online_flag
        extra_pg_state["instant_fallback_active"] = bool(instant_fb_flag)
        extra_pg_state["effective_tunnel_mode"] = eff_tm_out
    if cfg_doc.get("vps_hub_mode") or eff_mode == "vps_hub":
        extra_pg_state["vps_hub_mode"] = bool(cfg_doc.get("vps_hub_mode") or eff_mode == "vps_hub")
    if cfg_doc.get("vps_hub_url") or (eff_mode == "vps_hub" and eff_pub):
        extra_pg_state["vps_hub_url"] = cfg_doc.get("vps_hub_url") or eff_pub
    if gw_warn:
        extra_pg_state["gateway_warning"] = gw_warn
    return {
        **preserved_gw_fields,
        **extra_pg_state,
        "state_root": str(st_root),
        "state_dir": str(st_root),
        "cfg_path": str(cfg_path),
        "oneclick_bat": str(bat_p),
        "port": eff_port,
        "prefix": eff_p,
        "tool_prefix": eff_tool_prefix,
        "device_label": eff_label,
        "default_workspace": resolved_roots[0],
        "permission_tier": eff_tier,
        "toolset_profile": eff_toolset,
        "toolset_label_zh": TOOLSET_DISPLAY_ZH.get(eff_toolset, eff_toolset),
        "workspace_roots": resolved_roots,
        "readonly_workspace_roots": eff_ro_roots,
        "scan_host_global_skills": eff_scan_host_skills,
        "tray_enabled": eff_tray_enabled,
        "enabled_packs": _format_cli_packs(eff_packs),
        "keep_awake": eff_awake,
        "approval_popups": eff_popups,
        "annotation_mode": eff_ann_mode,
        "python_path": eff_py_path,
        "tunnel_mode": eff_mode,
        "mode": eff_mode,
        "vps_ssh": eff_vps_ssh,
        "vps_remote_port": eff_vps_rport,
        "vps_ssh_port": eff_vps_sport,
        "vps_identity_file": eff_vps_id,
        "tunnel_token_configured": bool(saved_tok),
        "public_url": disp_url,
        "mcp_url": f"{disp_url}/mcp" if disp_url else "",
        "readonly_mcp_url": f"{disp_url}/mcp/readonly" if disp_url else "",
        "skill_url": f"{disp_url}/skill" if disp_url else "",
        "studio_url": studio_local_url,
        "local_admin_url": studio_local_url,
        "connection_password": password_plain,
        "pair_code": pair_code,
        "dynamic_pair_code": dynamic_pair_code,
        "local_api_token": str(creds["local_api_token"]),
    }


def _revoke_sqlite_oauth_tokens(state_root: Path, prefix: str = "pc", client_id: str = "") -> Dict[str, Any]:
    eff = _norm_prefix(prefix)
    state_dir = state_root / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    db_path = state_dir / (f"oauth_{eff}.sqlite3" if eff != "pc" else "oauth.sqlite3")
    deleted = 0
    if db_path.is_file():
        conn = sqlite3.connect(str(db_path), timeout=10.0)
        try:
            with conn:
                if client_id:
                    cur = conn.execute(
                        "DELETE FROM records WHERE kind IN ('access','refresh','refresh_replay','authz_done','code','consent','consent_result','ticket') "
                        "AND json_extract(value,'$.client_id')=?",
                        (client_id,),
                    )
                else:
                    cur = conn.execute(
                        "DELETE FROM records WHERE kind IN ('access','refresh','refresh_replay','authz_done','code','consent','consent_result','ticket')"
                    )
                deleted = max(0, int(cur.rowcount or 0))
        except sqlite3.OperationalError:
            deleted = 0
        finally:
            conn.close()
    reason_tag = f"revoke_client:{client_id}" if client_id else "revoke_all"
    atomic_write_json(
        state_dir / "kill_signal.json",
        {
            "ts": time.time(),
            "ts_ns": time.time_ns(),
            "reason": reason_tag,
            "prefix_filter": eff,
            "emitter_pid": os.getpid(),
        },
    )
    bg_reap: Dict[str, Any] = {}
    if not client_id:
        from cosmos_mcp.core.guard import WorkspaceGuard
        from cosmos_mcp.core.proc import ProcessManager

        reap_guard = WorkspaceGuard(restrict_to_workspace=False, state_root=state_root, tool_prefix=eff)
        bg_reap = ProcessManager(guard=reap_guard, state_root=state_root).kill_all_active_commands(
            reason="revoke_all",
            include_persisted_bg=True,
            prefix_filter=eff,
        )
    return {"ok": True, "deleted_tokens": deleted, "bg_killed": bg_reap.get("bg_killed", [])}


def _is_local_port_free(port: int) -> bool:
    if int(port) <= 0 or int(port) > 65535:
        return False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        if sys.platform != "win32":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", int(port)))
            return True
        except OSError:
            return False


def _select_free_local_port(preferred: int = 8096, max_probes: int = 40) -> int:
    start_p = int(preferred or 8096)
    if _is_local_port_free(start_p):
        return start_p
    for cand in range(start_p + 1, min(65535, start_p + max_probes + 1)):
        if _is_local_port_free(cand):
            return cand
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _is_interactive_human_tty() -> bool:
    if os.environ.get("PYTEST_CURRENT_TEST") or os.environ.get("CI") or os.environ.get("LOCALPC_NO_BROWSER"):
        return False
    try:
        return bool(sys.stdin and sys.stdin.isatty() and sys.stdout and sys.stdout.isatty())
    except Exception:
        return False


def _copy_to_clipboard_explicit(text: str) -> bool:
    """Copy `text` to OS clipboard ONLY when explicitly requested via `--copy-password`."""
    if not text:
        return False
    flags = CREATE_NO_WINDOW if sys.platform == "win32" else 0
    cmds: List[List[str]] = []
    if sys.platform == "win32":
        cmds.append(["clip"])
    elif sys.platform == "darwin":
        cmds.append(["pbcopy"])
    else:
        cmds.extend([["wl-copy"], ["xclip", "-selection", "clipboard"]])
    for cmd in cmds:
        try:
            proc = subprocess.run(cmd, input=text, text=True, timeout=4.0, creationflags=flags, capture_output=True)
            if proc.returncode == 0:
                return True
        except Exception:
            continue
    return False


def _cmd_status(args: argparse.Namespace) -> int:
    st_root = resolve_cli_state_root(args.state_dir)
    try:
        eff_p = _norm_prefix(args.prefix)
    except ValueError as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        else:
            print(f"参数错误: {exc}", file=sys.stderr)
        return 2
    live = detect_running_instance(st_root, eff_p)
    pw = _extract_saved_password(st_root, eff_p)
    auth_p = st_root / "secrets" / "auth.json"
    local_tok = ""
    if auth_p.is_file():
        try:
            local_tok = str(json.loads(auth_p.read_text(encoding="utf-8-sig")).get("local_api_token") or "")
        except Exception:
            local_tok = ""
    pair_code = read_current_pair_code(st_root, eff_p, fallback_token=local_tok)
    dynamic_pair_code = read_current_dynamic_pair_code(st_root, eff_p)
    copied = False
    if getattr(args, "copy_password", False) and pw:
        copied = _copy_to_clipboard_explicit(pw)

    show_pw = bool(getattr(args, "show_password", True))
    masked_pw = (f"{pw[:4]}••••••••••••{pw[-4:]}" if len(pw) >= 8 else "••••••••••••••••••••") if pw else ""
    disp_pw = pw if show_pw else masked_pw
    tier_raw = str(live.get("permission_tier") or "tier3_workspace_dev")
    tier_fmt = _format_tier_zh(tier_raw)

    cfg_p = service_cfg_path(st_root, eff_p)
    cfg_doc: Dict[str, Any] = {}
    if cfg_p.is_file():
        try:
            loaded_c = json.loads(cfg_p.read_text(encoding="utf-8-sig"))
            if isinstance(loaded_c, dict):
                cfg_doc = loaded_c
        except Exception:
            cfg_doc = {}
    gw_warn = _detect_cli_gateway_warning(st_root, eff_p, str(live.get("mode") or ""), cfg_doc)
    primary_norms, primary_state_exists = _resolve_primary_state_roots(Path.home())
    is_default_st = os.path.normcase(str(st_root)) in primary_norms

    pub_u = str(live.get("public_url") or "").rstrip("/")
    payload: Dict[str, Any] = {
        "ok": True,
        "state_root": str(st_root),
        "prefix": eff_p,
        **live,
        "enabled_packs": _format_cli_packs(live.get("enabled_packs") or []),
        "python_path": str(cfg_doc.get("python_path") or ""),
        "skill_url": str(live.get("skill_url") or (f"{pub_u}/skill" if pub_u else "")),
        "studio_url": str(live.get("studio_url") or live.get("local_admin_url") or f"http://127.0.0.1:{live.get('port')}/"),
        "permission_tier_label_zh": TIER_DISPLAY_ZH.get(tier_raw, tier_raw),
        "permission_tier_display": tier_fmt,
        "toolset_label_zh": TOOLSET_DISPLAY_ZH.get(str(live.get("toolset_profile") or "standard"), "核心工具 16 项"),
        "connection_password": disp_pw,
        "password_masked": not show_pw,
        "pair_code": pair_code,
        "dynamic_pair_code": dynamic_pair_code,
        "password_copied": copied,
        "autostart": get_autostart_status(
            prefix=eff_p,
            state_root=st_root,
            is_default_state_root=is_default_st,
            primary_state_exists=primary_state_exists,
        ),
    }
    if gw_warn:
        payload["gateway_warning"] = gw_warn
    if live.get("mode") == "cloudflare":
        payload["reboot_notice"] = QUICK_TUNNEL_REBOOT_NOTICE_ZH
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    state_txt = "运行中 (在线)" if live.get("online") else "未启动 (离线)"
    pw_txt = (disp_pw or "(未初始化)") if show_pw else (f"{disp_pw} (加 --show-password 查看明文)" if pw else "(未初始化)")
    print(f"服务状态     : {state_txt}")
    print(f"监听端口     : 127.0.0.1:{live.get('port')}")
    print(f"控制面板     : {live.get('local_admin_url')}")
    print(f"通道模式     : {live.get('mode')}")
    print(f"主连接地址   : {live.get('mcp_url')}")
    print(f"只读连接地址 : {live.get('readonly_mcp_url')}")
    if gw_warn:
        print(f"网关配置提示 : {gw_warn}")
    if live.get("mode") == "cloudflare":
        print(f"通道提示     : {QUICK_TUNNEL_REBOOT_NOTICE_ZH}")
    print(f"当前安全模式 : {tier_fmt} ({payload['toolset_label_zh']})")
    print(f"开放工作目录 : {', '.join(str(x) for x in (live.get('workspace_roots') or []))}")
    if live.get("readonly_workspace_roots"):
        print(f"只读参考目录 : {', '.join(str(x) for x in (live.get('readonly_workspace_roots') or []))}")
    print(f"授权连接口令 : {pw_txt}")
    print(f"4 位核对码   : {pair_code}")
    print(f"6 位动态配对码: {dynamic_pair_code or '(未初始化)'}")
    if copied:
        print("剪贴板提示   : 已按请求复制连接口令到系统剪贴板。")
    return 0


def _apply_permissions_update(
    st_root: Path,
    *,
    prefix: str = "pc",
    tool_prefix: str = "",
    tier: str = "",
    set_workspace: str = "",
    add_workspaces: Sequence[str] = (),
    remove_workspaces: Sequence[str] = (),
    readonly_workspaces: Optional[Sequence[str]] = None,
    add_readonly_workspaces: Sequence[str] = (),
    remove_readonly_workspaces: Sequence[str] = (),
    scan_host_global_skills: Optional[bool] = None,
    python_path: Optional[str] = None,
    toolset: str = "",
    enable_pack: Optional[str] = None,
    keep_awake: Optional[bool] = None,
    approval_popups: Optional[bool] = None,
    tray_enabled: Optional[bool] = None,
    tunnel_mode: str = "",
    tunnel_token: Optional[str] = None,
    public_url: str = "",
    vps_ssh: Optional[str] = None,
    vps_remote_port: Optional[int] = None,
    vps_ssh_port: Optional[int] = None,
    vps_identity_file: Optional[str] = None,
    revoke_all: bool = False,
    revoke_client: str = "",
    reset_password: bool = False,
) -> Dict[str, Any]:
    eff_p = _norm_prefix(prefix)
    cfg_p = service_cfg_path(st_root, eff_p)
    cur_cfg: Dict[str, Any] = {}
    if cfg_p.is_file():
        try:
            loaded = json.loads(cfg_p.read_text(encoding="utf-8-sig"))
            if isinstance(loaded, dict):
                cur_cfg = loaded
        except Exception:
            cur_cfg = {}

    cur_roots: List[str] = [
        str(x) for x in (cur_cfg.get("workspace_roots") or ([cur_cfg["workspace"]] if cfg_p.is_file() and cur_cfg.get("workspace") else []))
    ]
    if set_workspace:
        cur_roots = [set_workspace]
    for add_w in add_workspaces:
        if add_w:
            resolved_add = str(Path(expand_env_and_tilde(add_w)).expanduser().resolve())
            if all(os.path.normcase(x) != os.path.normcase(resolved_add) for x in cur_roots):
                cur_roots.append(resolved_add)
    for rem_w in remove_workspaces:
        if rem_w:
            resolved_rem = os.path.normcase(str(Path(expand_env_and_tilde(rem_w)).expanduser().resolve()))
            filtered = [x for x in cur_roots if os.path.normcase(str(Path(expand_env_and_tilde(x)).expanduser().resolve())) != resolved_rem]
            if not filtered:
                raise ValueError("不能移除最后一个开放工作目录。")
            cur_roots = filtered

    eff_ro_list: Optional[List[str]] = None
    if readonly_workspaces is not None:
        eff_ro_list = _parse_readonly_workspaces_arg(readonly_workspaces)
    elif add_readonly_workspaces or remove_readonly_workspaces:
        base_ro = [str(x) for x in (cur_cfg.get("readonly_workspace_roots") or [])]
        add_ro_parsed = _parse_readonly_workspaces_arg(add_readonly_workspaces) or []
        for aro in add_ro_parsed:
            if all(os.path.normcase(x) != os.path.normcase(aro) for x in base_ro):
                base_ro.append(aro)
        for rro in remove_readonly_workspaces:
            if rro:
                rem_norm = os.path.normcase(str(Path(expand_env_and_tilde(rro)).expanduser().resolve()))
                base_ro = [x for x in base_ro if os.path.normcase(str(Path(expand_env_and_tilde(x)).expanduser().resolve())) != rem_norm]
        eff_ro_list = base_ro

    packs_list: Optional[List[str]] = None
    if enable_pack is not None:
        packs_list = _parse_packs(enable_pack)

    state_res = ensure_standalone_state(
        st_root,
        port=int(cur_cfg.get("port") or 8096),
        prefix=eff_p,
        tool_prefix=tool_prefix,
        tier_key=tier,
        toolset_profile=toolset,
        workspace_roots=cur_roots if (set_workspace or add_workspaces or remove_workspaces) else None,
        readonly_workspace_roots=eff_ro_list,
        scan_host_global_skills=scan_host_global_skills,
        python_path=python_path,
        tray_enabled=tray_enabled,
        enabled_packs=packs_list,
        keep_awake=keep_awake,
        approval_popups=approval_popups,
        tunnel_mode=tunnel_mode,
        tunnel_token=tunnel_token,
        public_url=public_url,
        vps_ssh=vps_ssh,
        vps_remote_port=vps_remote_port,
        vps_ssh_port=vps_ssh_port,
        vps_identity_file=vps_identity_file,
        reset_password=reset_password,
    )

    if state_res["permission_tier"] in ("tier1_readonly", "tier2_workspace_edit"):
        atomic_write_json(
            st_root / "state" / "kill_signal.json",
            {
                "ts": time.time(),
                "ts_ns": time.time_ns(),
                "reason": f"tier_downgrade:{state_res['permission_tier']}",
                "prefix_filter": eff_p,
                "emitter_pid": os.getpid(),
            },
        )

    rev_res: Optional[Dict[str, Any]] = None
    if revoke_all:
        rev_res = _revoke_sqlite_oauth_tokens(st_root, prefix=eff_p)
    elif revoke_client:
        rev_res = _revoke_sqlite_oauth_tokens(st_root, prefix=eff_p, client_id=revoke_client)

    live = detect_running_instance(st_root, eff_p)
    eff_pub_out = str((live.get("public_url") if live.get("online") else "") or state_res["public_url"]).rstrip("/")
    out: Dict[str, Any] = {
        "ok": True,
        "hot_reloaded": bool(live.get("online")),
        "online": bool(live.get("online")),
        "mode": state_res["tunnel_mode"],
        "tunnel_mode": state_res["tunnel_mode"],
        "tool_prefix": state_res["tool_prefix"],
        "permission_tier": state_res["permission_tier"],
        "toolset_profile": state_res["toolset_profile"],
        "toolset_label_zh": state_res["toolset_label_zh"],
        "workspace_roots": state_res["workspace_roots"],
        "readonly_workspace_roots": state_res["readonly_workspace_roots"],
        "scan_host_global_skills": state_res["scan_host_global_skills"],
        "python_path": state_res["python_path"],
        "tray_enabled": state_res["tray_enabled"],
        "enabled_packs": state_res["enabled_packs"],
        "keep_awake": state_res["keep_awake"],
        "approval_popups": state_res["approval_popups"],
        "public_url": eff_pub_out,
        "mcp_url": f"{eff_pub_out}/mcp" if eff_pub_out else "",
        "readonly_mcp_url": f"{eff_pub_out}/mcp/readonly" if eff_pub_out else "",
        "skill_url": f"{eff_pub_out}/skill" if eff_pub_out else "",
        "studio_url": state_res["studio_url"],
        "local_admin_url": state_res["local_admin_url"],
        "connection_password": state_res["connection_password"],
        "pair_code": state_res["pair_code"],
        "dynamic_pair_code": state_res["dynamic_pair_code"],
    }
    if state_res.get("gateway_warning"):
        out["gateway_warning"] = state_res["gateway_warning"]
    if rev_res is not None:
        out["revocation"] = rev_res
    return out


def _cmd_permissions(args: argparse.Namespace) -> int:
    st_root = resolve_cli_state_root(args.state_dir)
    try:
        res = _apply_permissions_update(
            st_root,
            prefix=args.prefix,
            tool_prefix=getattr(args, "tool_prefix", "") or "",
            tier=args.tier or "",
            set_workspace=args.workspace or "",
            add_workspaces=args.add_workspace or [],
            remove_workspaces=args.remove_workspace or [],
            readonly_workspaces=getattr(args, "readonly_workspace", None),
            add_readonly_workspaces=getattr(args, "add_readonly_workspace", None) or [],
            remove_readonly_workspaces=getattr(args, "remove_readonly_workspace", None) or [],
            scan_host_global_skills=getattr(args, "scan_host_global_skills", None),
            python_path=getattr(args, "python_path", None),
            toolset=args.toolset or "",
            enable_pack=args.enable_pack,
            keep_awake=args.keep_awake,
            approval_popups=args.approval_popups,
            tray_enabled=getattr(args, "tray_enabled", None),
            tunnel_mode=getattr(args, "mode", "") or "",
            tunnel_token=getattr(args, "tunnel_token", None),
            public_url=getattr(args, "public_url", "") or "",
            vps_ssh=getattr(args, "vps_ssh", None),
            vps_remote_port=getattr(args, "vps_remote_port", None),
            vps_ssh_port=getattr(args, "vps_ssh_port", None),
            vps_identity_file=getattr(args, "vps_identity_file", None),
            revoke_all=bool(args.revoke_all),
            revoke_client=args.revoke_client or "",
            reset_password=bool(args.reset_password),
        )
    except ValueError as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        else:
            print(f"参数错误: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0
    print(f"配置已更新（在线热生效: {'是' if res['hot_reloaded'] else '待下次启动'}）")
    print(f"  安全模式 : {_format_tier_zh(res['permission_tier'])} ({res['toolset_label_zh']})")
    print(f"  开放目录 : {', '.join(res['workspace_roots'])}")
    if res.get("readonly_workspace_roots"):
        print(f"  只读目录 : {', '.join(res['readonly_workspace_roots'])}")
    print(f"  扩展包   : {', '.join(res['enabled_packs']) if res['enabled_packs'] else '未开启'}")
    return 0


def _cmd_setup_or_start(args: argparse.Namespace, *, is_setup: bool) -> int:
    st_root = resolve_cli_state_root(args.state_dir)
    try:
        eff_p = _norm_prefix(args.prefix)
        raw_tool_prefix = (getattr(args, "tool_prefix", "") or "").strip()
        if raw_tool_prefix:
            raw_tool_prefix = _norm_prefix(raw_tool_prefix)
    except ValueError as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        else:
            print(f"参数错误: {exc}", file=sys.stderr)
        return 2

    no_tray_flag = bool(getattr(args, "no_tray", False))
    ro_arg = getattr(args, "readonly_workspace", None)
    scan_skills_arg = getattr(args, "scan_host_global_skills", None)
    py_path_arg = getattr(args, "python_path", None)
    live = detect_running_instance(st_root, eff_p)
    is_agent_setup = getattr(args, "subcommand", "") == "agent-setup"

    raw_mode_arg = (getattr(args, "mode", "") or "").strip().lower()
    raw_tok_arg = getattr(args, "tunnel_token", None)
    raw_pub_arg = (getattr(args, "public_url", "") or "").strip()
    raw_vps_ssh = (getattr(args, "vps_ssh", "") or "").strip()
    raw_vps_rport = getattr(args, "vps_remote_port", None)
    raw_vps_sport = getattr(args, "vps_ssh_port", None)
    raw_vps_id = (getattr(args, "vps_identity_file", "") or "").strip()

    if is_agent_setup and not raw_mode_arg:
        if raw_tok_arg and normalize_tunnel_token(raw_tok_arg):
            raw_mode_arg = "cloudflare_token"
        elif raw_vps_ssh:
            raw_mode_arg = "vps"
        elif raw_pub_arg:
            raw_mode_arg = "custom"
        else:
            saved_cfg_p = service_cfg_path(st_root, eff_p)
            saved_tm = ""
            if saved_cfg_p.is_file():
                try:
                    saved_tm = str(json.loads(saved_cfg_p.read_text(encoding="utf-8-sig")).get("tunnel_mode") or "").strip().lower()
                except Exception:
                    saved_tm = ""
            raw_mode_arg = (
                saved_tm
                if saved_tm in (
                    "cloudflare_token",
                    "workers_dev",
                    "public_gateway",
                    "openssh",
                    "srv_us",
                    "vps",
                    "vps_hub",
                    "reverse_proxy",
                    "custom",
                    "cloudflare",
                )
                else "public_gateway"
            )

    if live.get("online") and not getattr(args, "restart", False):
        has_mutation_flags = any(
            [
                getattr(args, "tier", ""),
                getattr(args, "workspace", ""),
                getattr(args, "add_workspace", None),
                ro_arg is not None,
                scan_skills_arg is not None,
                py_path_arg is not None,
                getattr(args, "toolset", ""),
                getattr(args, "enable_pack", None) is not None,
                getattr(args, "keep_awake", None) is not None,
                raw_tool_prefix,
                no_tray_flag,
                raw_mode_arg,
                raw_tok_arg is not None,
                raw_pub_arg,
                raw_vps_ssh,
            ]
        )
        if has_mutation_flags or args.json or is_agent_setup or getattr(args, "open_browser", False) or not _is_interactive_human_tty():
            prev_mode = str(live.get("mode") or "local").strip().lower()
            try:
                upd = _apply_permissions_update(
                    st_root,
                    prefix=eff_p,
                    tool_prefix=raw_tool_prefix,
                    tier=getattr(args, "tier", "") or "",
                    set_workspace=getattr(args, "workspace", "") or "",
                    add_workspaces=getattr(args, "add_workspace", None) or [],
                    readonly_workspaces=ro_arg,
                    scan_host_global_skills=scan_skills_arg,
                    python_path=py_path_arg,
                    toolset=getattr(args, "toolset", "") or "",
                    enable_pack=getattr(args, "enable_pack", None),
                    keep_awake=getattr(args, "keep_awake", None),
                    tray_enabled=(False if no_tray_flag else None),
                    tunnel_mode=raw_mode_arg,
                    tunnel_token=raw_tok_arg,
                    public_url=raw_pub_arg,
                    vps_ssh=raw_vps_ssh or None,
                    vps_remote_port=raw_vps_rport,
                    vps_ssh_port=raw_vps_sport,
                    vps_identity_file=raw_vps_id or None,
                )
            except ValueError as exc:
                if args.json:
                    print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
                else:
                    print(f"参数错误: {exc}", file=sys.stderr)
                return 2
            if raw_mode_arg in ("cloudflare", "cloudflare_token", "workers_dev", "public_gateway", "openssh", "srv_us") and prev_mode == "local":
                wait_end = time.monotonic() + 25.0
                while time.monotonic() < wait_end:
                    live = detect_running_instance(st_root, eff_p)
                    if str(live.get("public_url") or "").startswith("https://"):
                        break
                    time.sleep(0.5)
            else:
                live = detect_running_instance(st_root, eff_p)

            if getattr(args, "bind_desktop", ""):
                venv_py_cand = venv_python_path(st_root / ".venv", windowless=False)
                py_info = find_suitable_python()
                eff_bind_py = str(venv_py_cand) if venv_py_cand.is_file() else (py_info[0] if py_info else sys.executable)
                bind_desktop_clients(
                    clients=args.bind_desktop,
                    state_root=st_root,
                    python_exe=eff_bind_py,
                    port=int(live.get("port") or 8096),
                    local_api_token=str(json.loads((st_root / "secrets" / "auth.json").read_text(encoding="utf-8")).get("local_api_token") or ""),
                    prefix=eff_p,
                    repo_src=resolve_persisted_src_dir(st_root),
                )
            live_mode = str(live.get("mode") or upd.get("tunnel_mode") or "public_gateway").strip().lower()
            raw_live_pub = str(live.get("public_url") or upd.get("public_url") or "").strip().rstrip("/")
            if live_mode == "local":
                eff_pub_live = raw_live_pub or f"http://127.0.0.1:{live.get('port')}"
            else:
                eff_pub_live = raw_live_pub if raw_live_pub.startswith("https://") else ""
            studio_u = str(live.get("local_admin_url") or f"http://127.0.0.1:{live.get('port')}/")
            merged: Dict[str, Any] = {
                **live,
                **upd,
                "enabled_packs": _format_cli_packs(upd.get("enabled_packs") or live.get("enabled_packs") or []),
                "public_url": eff_pub_live,
                "mcp_url": f"{eff_pub_live}/mcp" if eff_pub_live else "",
                "readonly_mcp_url": f"{eff_pub_live}/mcp/readonly" if eff_pub_live else "",
                "skill_url": f"{eff_pub_live}/skill" if eff_pub_live else "",
                "studio_url": studio_u,
                "local_admin_url": studio_u,
                "pair_code": read_current_pair_code(st_root, eff_p, fallback_token=str(upd.get("pair_code") or "")),
                "dynamic_pair_code": read_current_dynamic_pair_code(st_root, eff_p) or str(upd.get("dynamic_pair_code") or ""),
                "already_running": True,
                "server_restarted": False,
            }
            if (
                getattr(args, "open_browser", False)
                and not getattr(args, "no_browser", False)
                and not os.environ.get("LOCALPC_NO_BROWSER")
                and not os.environ.get("PYTEST_CURRENT_TEST")
            ):
                import webbrowser

                webbrowser.open(studio_u)
            if args.json:
                print(json.dumps(merged, ensure_ascii=False, indent=2))
            else:
                print(f"检测到在线实例（端口 {live.get('port')}），已热更新配置，公网通道与在途任务保持不断流。")
            return 0

        menu_res = interactive_hot_switch_menu(
            live_info=live,
            on_set_tier=lambda t: _apply_permissions_update(st_root, prefix=eff_p, tier=t),
            on_add_workspace=lambda w: _apply_permissions_update(st_root, prefix=eff_p, add_workspaces=[w]),
            on_toggle_pack=lambda p: _apply_permissions_update(st_root, prefix=eff_p, enable_pack=p),
            on_show_credentials=lambda: ensure_standalone_state(st_root, prefix=eff_p),
            on_stop=lambda: stop_daemon(st_root, prefix=eff_p),
        )
        return 0 if menu_res.get("ok") else 1

    if getattr(args, "restart", False) and live.get("online"):
        stop_daemon(st_root, prefix=eff_p)

    mode = raw_mode_arg
    if not mode and raw_tok_arg:
        mode = "cloudflare_token"
    elif not mode and raw_vps_ssh:
        mode = "vps"

    ws_arg = (getattr(args, "workspace", "") or os.environ.get("COSMOS_MCP_WORKSPACE", "") or "").strip()
    tier_arg = (getattr(args, "tier", "") or "").strip()
    bind_clients_arg = getattr(args, "bind_desktop", "") or ""
    tok_arg: Optional[str] = raw_tok_arg
    pub_arg: str = raw_pub_arg
    vps_ssh_val: Optional[str] = raw_vps_ssh or None
    vps_rport_val: Optional[int] = int(raw_vps_rport) if raw_vps_rport else None
    vps_sport_val: Optional[int] = int(raw_vps_sport) if raw_vps_sport else None
    vps_id_val: Optional[str] = raw_vps_id or None
    is_interactive = is_setup and _is_interactive_human_tty() and not args.json and not mode

    if is_interactive:
        print("\n=== Cosmos MCP 连接向导 ===")
        print(" [1] 系统内置 OpenSSH 免登录直连（本机 Ed25519 密钥 + SSHv2/TLS 加密，经 srv.us 生成固定 HTTPS 地址，22 端口受阻自动切换 Cloudflare 临时通道）")
        print(" [2] Cloudflare 固定域名通道（粘贴 Named Tunnel 固定 Token，开机自启永久固定域名）")
        print(" [3] 自有云服务器 SSH 反向隧道（自动维护 ssh -R 反向转发）")
        print(" [4] 自有 HTTPS 反代固定域名（外部已配置网关转发）")
        print(" [5] 仅本机回环调试（不开启公网 HTTPS 通道）")
        m_sel = (input("请选择连接方式 [1-5] (默认 1): ") or "1").strip()
        mode = {
            "1": "public_gateway",
            "2": "cloudflare_token",
            "3": "vps",
            "4": "custom",
            "5": "local",
        }.get(m_sel, "public_gateway")
        if mode == "cloudflare_token" and not tok_arg:
            tok_arg = (input("请粘贴 Cloudflare Tunnel Token: ") or "").strip()
            pub_arg = pub_arg or (input("请输入绑定的固定 HTTPS 域名（如 https://mcp.example.com）: ") or "").strip()
        elif mode == "vps":
            if not vps_ssh_val:
                vps_ssh_val = (input("请输入 VPS SSH 目标（如 root@203.0.113.10）: ") or "").strip() or None
            if vps_rport_val is None:
                rp_in = (input("请输入 VPS 远端反向监听端口 (回车默认 18096): ") or "").strip()
                vps_rport_val = int(rp_in) if rp_in.isdigit() else 18096
            if vps_sport_val is None:
                sp_in = (input("请输入 VPS SSH 端口 (回车默认 22): ") or "").strip()
                vps_sport_val = int(sp_in) if sp_in.isdigit() else 22
            if not vps_id_val:
                id_in = (input("请输入 SSH 私钥路径 (免密默认已配可直接回车留空): ") or "").strip()
                vps_id_val = id_in or None
            if not pub_arg:
                pub_arg = (input("请输入绑定的公网 HTTPS 域名（如 https://mcp.example.com）: ") or "").strip()
        elif mode == "custom" and not pub_arg:
            pub_arg = (input("请输入自有 HTTPS 反代域名（如 https://mcp.example.com）: ") or "").strip()
        if not ws_arg:
            default_w = str(resolve_default_workspace(cwd=None, state_root=st_root))
            ws_in = (input(f"开放工作目录 (回车默认 {default_w}): ") or "").strip()
            ws_arg = ws_in or default_w
        if mode == "local" and not bind_clients_arg:
            detected = detect_installed_clients()
            if detected:
                ans_b = (input(f"检测到已安装桌面客户端 {', '.join(detected)}，是否自动写入连接配置？[Y/n]: ") or "y").strip().lower()
                if ans_b in ("y", "yes", ""):
                    bind_clients_arg = ",".join(detected)

    ws_list: List[str] = []
    if ws_arg:
        ws_list.append(ws_arg)
    for extra_w in (getattr(args, "add_workspace", None) or []):
        if extra_w and extra_w not in ws_list:
            ws_list.append(extra_w)

    try:
        ro_parsed = _parse_readonly_workspaces_arg(ro_arg)
        packs_parsed = _parse_packs(args.enable_pack) if getattr(args, "enable_pack", None) is not None else None
        init_info = ensure_standalone_state(
            st_root,
            port=int(args.port or 0),
            prefix=eff_p,
            tool_prefix=raw_tool_prefix,
            device_label=getattr(args, "device_label", "") or "",
            tier_key=tier_arg,
            toolset_profile=getattr(args, "toolset", "") or "",
            workspace_roots=ws_list if ws_list else None,
            readonly_workspace_roots=ro_parsed,
            scan_host_global_skills=scan_skills_arg,
            tray_enabled=(False if no_tray_flag else None),
            enabled_packs=packs_parsed,
            keep_awake=getattr(args, "keep_awake", None),
            approval_popups=getattr(args, "approval_popups", None),
            public_url=pub_arg,
            tunnel_mode=mode,
            tunnel_token=tok_arg,
            vps_ssh=vps_ssh_val,
            vps_remote_port=vps_rport_val,
            vps_ssh_port=vps_sport_val,
            vps_identity_file=vps_id_val,
            python_path=py_path_arg,
        )
    except ValueError as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        else:
            print(f"参数错误: {exc}", file=sys.stderr)
        return 2
    eff_mode = str(init_info["tunnel_mode"])

    if getattr(args, "prepare_only", False):
        env_prep = ensure_runtime_environment(st_root)
        if not env_prep.get("ok"):
            if args.json:
                print(json.dumps(env_prep, ensure_ascii=False, indent=2))
            else:
                print(f"运行环境准备失败: {env_prep.get('detail') or env_prep.get('error')}", file=sys.stderr)
            return 1
        py_exe = str(env_prep["python_exe"])
        create_oneclick_bat(st_root, python_exe=py_exe, port=init_info["port"], prefix=eff_p)
        bound_res: Dict[str, Any] = {"bound_clients": []}
        if bind_clients_arg:
            bound_res = bind_desktop_clients(
                clients=bind_clients_arg,
                state_root=st_root,
                python_exe=py_exe,
                port=init_info["port"],
                local_api_token=init_info["local_api_token"],
                prefix=eff_p,
                repo_src=resolve_persisted_src_dir(st_root),
            )
        autostart_res = None
        if getattr(args, "autostart", False):
            autostart_res = enable_autostart(
                python_exe=py_exe,
                state_root=st_root,
                prefix=eff_p,
                mode=eff_mode,
                port=init_info["port"],
            )
        shortcut_p = (
            create_desktop_shortcut(st_root, port=init_info["port"], python_exe=py_exe, prefix=eff_p)
            if getattr(args, "shortcut", False)
            else None
        )
        out_prep = {
            "ok": True,
            "prepared_only": True,
            "status": "prepared_only",
            "deployment_started": False,
            "runtime_ready": True,
            "runtime_mode": env_prep.get("mode"),
            "runtime_python": py_exe,
            "mode": eff_mode,
            **init_info,
            "desktop_binding": bound_res,
            "autostart": autostart_res,
            "shortcut": str(shortcut_p) if shortcut_p else None,
        }
        if eff_mode == "cloudflare":
            out_prep["reboot_notice"] = QUICK_TUNNEL_REBOOT_NOTICE_ZH
        if args.json:
            print(json.dumps(out_prep, ensure_ascii=False, indent=2))
        else:
            print(f"配置与运行环境已就绪: {init_info['cfg_path']}")
            if eff_mode == "cloudflare":
                print(f"  {QUICK_TUNNEL_REBOOT_NOTICE_ZH}")
        return 0

    if (
        eff_mode == "vps"
        and init_info.get("vps_ssh")
        and not init_info.get("vps_hub_mode")
        and not init_info.get("vps_hub_url")
        and shutil.which("ssh") is None
    ):
        ssh_err = {
            "ok": False,
            "error": "ssh_binary_not_found",
            "detail": "未检测到系统 ssh 客户端，请先安装 OpenSSH Client 后再使用 --mode vps。",
        }
        if args.json:
            print(json.dumps(ssh_err, ensure_ascii=False, indent=2))
        else:
            print(f"启动检查失败: {ssh_err['detail']}", file=sys.stderr)
        return 1

    env_res = ensure_runtime_environment(st_root)
    if not env_res.get("ok"):
        if args.json:
            print(json.dumps(env_res, ensure_ascii=False, indent=2))
        else:
            print(f"运行环境准备失败: {env_res.get('detail') or env_res.get('error')}", file=sys.stderr)
        return 1
    runtime_py = str(env_res["python_exe"])

    if not _is_local_port_free(int(init_info["port"])):
        free_port = _select_free_local_port(int(init_info["port"]))
        if free_port != int(init_info["port"]):
            init_info = ensure_standalone_state(
                st_root,
                port=free_port,
                prefix=eff_p,
                tool_prefix=raw_tool_prefix,
                device_label=getattr(args, "device_label", "") or "",
                tier_key=tier_arg,
                toolset_profile=getattr(args, "toolset", "") or "",
                workspace_roots=ws_list if ws_list else None,
                readonly_workspace_roots=ro_parsed,
                scan_host_global_skills=scan_skills_arg,
                tray_enabled=(False if no_tray_flag else None),
                enabled_packs=packs_parsed,
                keep_awake=getattr(args, "keep_awake", None),
                approval_popups=getattr(args, "approval_popups", None),
                public_url=pub_arg,
                tunnel_mode=mode,
                tunnel_token=tok_arg,
                vps_ssh=vps_ssh_val,
                vps_remote_port=vps_rport_val,
                vps_ssh_port=vps_sport_val,
                vps_identity_file=vps_id_val,
                python_path=py_path_arg,
            )

    create_oneclick_bat(st_root, python_exe=runtime_py, port=init_info["port"], prefix=eff_p)

    bound_res = {"bound_clients": []}
    if bind_clients_arg:
        bound_res = bind_desktop_clients(
            clients=bind_clients_arg,
            state_root=st_root,
            python_exe=runtime_py,
            port=init_info["port"],
            local_api_token=init_info["local_api_token"],
            prefix=eff_p,
            repo_src=resolve_persisted_src_dir(st_root),
        )

    autostart_res = None
    if getattr(args, "autostart", False):
        autostart_res = enable_autostart(
            python_exe=runtime_py,
            state_root=st_root,
            prefix=eff_p,
            mode=eff_mode,
            port=init_info["port"],
        )

    shortcut_p = (
        create_desktop_shortcut(st_root, port=init_info["port"], python_exe=runtime_py, prefix=eff_p)
        if getattr(args, "shortcut", False)
        else None
    )

    clean_pub_for_daemon = str(init_info.get("public_url") or "") if eff_mode != "local" else ""
    if getattr(args, "foreground", False):
        from cosmos_mcp.launcher.daemon import StandaloneSupervisorLoop

        sup = StandaloneSupervisorLoop(
            state_root=st_root,
            runtime_python=runtime_py,
            port=init_info["port"],
            mode=eff_mode,
            prefix=eff_p,
            tool_prefix=str(init_info.get("tool_prefix") or eff_p),
            no_tray=no_tray_flag,
            public_url=clean_pub_for_daemon,
            tunnel_token=tok_arg or "",
            vps_ssh=str(init_info.get("vps_ssh") or ""),
            vps_remote_port=int(init_info.get("vps_remote_port") or 18096),
            vps_ssh_port=int(init_info.get("vps_ssh_port") or 22),
            vps_identity_file=str(init_info.get("vps_identity_file") or ""),
        )
        return sup.run_forever()

    daemon_res = spawn_detached_daemon(
        python_exe=runtime_py,
        state_root=st_root,
        port=init_info["port"],
        mode=eff_mode,
        prefix=eff_p,
        tool_prefix=str(init_info.get("tool_prefix") or eff_p),
        no_tray=no_tray_flag,
        public_url=clean_pub_for_daemon,
        tunnel_token=tok_arg or "",
        vps_ssh=str(init_info.get("vps_ssh") or ""),
        vps_remote_port=int(init_info.get("vps_remote_port") or 18096),
        vps_ssh_port=int(init_info.get("vps_ssh_port") or 22),
        vps_identity_file=str(init_info.get("vps_identity_file") or ""),
        clear_user_stop=True,
    )

    if daemon_res.get("ok"):
        poll_deadline = time.monotonic() + 1.5
        while True:
            live_post = detect_running_instance(st_root, eff_p)
            daemon_res = {**daemon_res, **live_post, "ok": True}
            if live_post.get("supervisor_alive") and live_post.get("supervisor_pid") and live_post.get("server_pid"):
                break
            if time.monotonic() >= poll_deadline:
                break
            time.sleep(0.1)

    eff_pub_final = str(daemon_res.get("public_url") or init_info["public_url"]).rstrip("/")
    studio_final = str(daemon_res.get("local_admin_url") or init_info["local_admin_url"])
    pair_final = read_current_pair_code(st_root, eff_p, fallback_token=str(init_info["local_api_token"]))
    dyn_pair_final = read_current_dynamic_pair_code(st_root, eff_p) or str(init_info.get("dynamic_pair_code") or "")
    final_payload: Dict[str, Any] = {
        **init_info,
        **daemon_res,
        "enabled_packs": _format_cli_packs(daemon_res.get("enabled_packs") or init_info.get("enabled_packs") or []),
        "public_url": eff_pub_final,
        "mcp_url": f"{eff_pub_final}/mcp" if eff_pub_final else "",
        "readonly_mcp_url": f"{eff_pub_final}/mcp/readonly" if eff_pub_final else "",
        "skill_url": f"{eff_pub_final}/skill" if eff_pub_final else "",
        "studio_url": studio_final,
        "local_admin_url": studio_final,
        "pair_code": pair_final,
        "dynamic_pair_code": dyn_pair_final,
        "desktop_binding": bound_res,
        "autostart": autostart_res,
        "shortcut": str(shortcut_p) if shortcut_p else None,
    }
    if init_info.get("gateway_warning"):
        final_payload["gateway_warning"] = init_info["gateway_warning"]
    if eff_mode == "cloudflare":
        final_payload["reboot_notice"] = QUICK_TUNNEL_REBOOT_NOTICE_ZH
    if args.json:
        print(json.dumps(final_payload, ensure_ascii=False, indent=2))
        return 0 if daemon_res.get("ok") else 1

    if not daemon_res.get("ok"):
        reason = daemon_res.get("detail") or daemon_res.get("error") or "未通过启动检查"
        print(f"Cosmos MCP 后台启动失败: {reason}", file=sys.stderr)
        return 1

    print("\nCosmos MCP 已在后台常驻启动（关闭当前命令行窗口不会中断服务）")
    print(f"  Cosmos Studio : {final_payload.get('local_admin_url')}")
    print(f"  主连接地址    : {final_payload.get('mcp_url') or '正在建立加密连接…（请在上方 Cosmos Studio 面板查看）'}")
    print(f"  6 位动态配对码: {dyn_pair_final or '请在 Cosmos Studio 面板实时查看'}（本机浏览器默认一键免输口令通过）")
    print(f"  授权连接口令  : {init_info['connection_password']}")
    print(f"  4 位核对码    : {pair_final}")
    if final_payload.get("gateway_warning"):
        print(f"  网关配置提示  : {final_payload['gateway_warning']}")
    if eff_mode == "cloudflare":
        print(f"  {QUICK_TUNNEL_REBOOT_NOTICE_ZH}")
    if autostart_res and autostart_res.get("boundary_notice"):
        print(f"  {autostart_res['boundary_notice']}")

    can_open_browser = (
        not getattr(args, "no_browser", False)
        and not os.environ.get("LOCALPC_NO_BROWSER")
        and not os.environ.get("PYTEST_CURRENT_TEST")
    )
    if getattr(args, "open_browser", False) and can_open_browser:
        import webbrowser

        webbrowser.open(str(final_payload.get("local_admin_url")))
    elif is_interactive and can_open_browser:
        ans_open = (input("是否在默认浏览器中打开 Cosmos Studio 控制面板？[Y/n]: ") or "y").strip().lower()
        if ans_open in ("y", "yes", ""):
            import webbrowser

            webbrowser.open(str(final_payload.get("local_admin_url")))
    return 0 if daemon_res.get("ok") else 1


def _cmd_doctor(args: argparse.Namespace) -> int:
    st_root = resolve_cli_state_root(args.state_dir)
    out_p = Path(args.output) if getattr(args, "output", "") else None
    want_probe = bool(getattr(args, "probe", False))
    gw_filter = str(getattr(args, "gateway_id", "") or "").strip()
    rep = run_doctor(
        st_root,
        prefix=args.prefix,
        bundle=bool(args.bundle),
        bundle_output=out_p,
        probe=want_probe,
        gateway_id=gw_filter,
    )
    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
        return 0 if rep.get("ok") else 1
    print(f"体检结论       : {'通过' if rep.get('ok') else '存在待处理项'}")
    rt = rep.get("runtime") or {}
    print(f"Python 运行时  : {rt.get('suitable_python_version') or '未找到 3.10~3.14'} (核心依赖就绪: {rt.get('venv_deps_ready') or rt.get('ambient_deps_ready')})")
    srv = rep.get("service") or {}
    print(f"在线状态       : {'在线' if srv.get('online') else '离线'} (端口 {srv.get('port')}, 网关健康: {rep.get('gateway_healthy')})")
    conn_chk = rep.get("connectivity_check")
    if isinstance(conn_chk, dict):
        print(f"\n端到端连通性实测 ({conn_chk.get('overall_status', '').upper()} · {conn_chk.get('duration_ms')}ms)：{conn_chk.get('summary')}")
        ls = conn_chk.get("local_service") or {}
        print(f"  [1] 本机回环服务 : [{str(ls.get('status', '')).upper()}] {ls.get('message_zh')}")
        pd = conn_chk.get("proxy_and_deps") or {}
        print(f"  [2] 代理与组件   : [{str(pd.get('status', '')).upper()}] {pd.get('message_zh')}")
        for gw_it in (conn_chk.get("gateways") or []):
            m_url = f" ({gw_it.get('masked_url')})" if gw_it.get("masked_url") else ""
            print(f"  [3] 网关[{gw_it.get('gateway_id')}]{m_url} : [{str(gw_it.get('status', '')).upper()}] {gw_it.get('message_zh')}")
        mp = conn_chk.get("mcp_protocol") or {}
        for pr_it in (mp.get("items") or []):
            if pr_it.get("status") != "skipped":
                print(f"  [4] 协议[{pr_it.get('gateway_id')}] : [{str(pr_it.get('status', '')).upper()}] {pr_it.get('message_zh')}")
    if rep.get("bundle_path"):
        print(f"脱敏诊断包已导出: {rep['bundle_path']}")
    return 0 if rep.get("ok") else 1


def _cmd_update(args: argparse.Namespace) -> int:
    """Check for updates or stage and apply a zero-drop self-update."""
    st_root = resolve_cli_state_root(args.state_dir)
    eff_prefix = _norm_prefix(args.prefix)
    channel = str(getattr(args, "channel", "release") or "release").strip().lower()
    if channel not in ("release", "main"):
        channel = "release"
    want_check = bool(getattr(args, "check", False))
    raw_archive = str(getattr(args, "archive", "") or "").strip()
    arc_path = Path(raw_archive).expanduser().resolve() if raw_archive else None

    if want_check:
        res = check_for_updates(st_root, prefix=eff_prefix, channel=channel)
        dep_info: Optional[Dict[str, Any]] = None
        cand_pyproj = st_root / "app_src" / "pyproject.toml"
        if not cand_pyproj.is_file():
            repo_r = find_repo_root()
            if repo_r is not None and (repo_r / "pyproject.toml").is_file():
                cand_pyproj = repo_r / "pyproject.toml"
        if cand_pyproj.is_file():
            try:
                vp = venv_python_path(st_root)
                py_target = str(vp) if vp.is_file() else sys.executable
                dep_info = check_pyproject_deps_satisfied(
                    cand_pyproj.read_text(encoding="utf-8", errors="replace"),
                    python_exe=py_target,
                )
            except Exception:
                dep_info = None
        if dep_info is not None and isinstance(res, dict):
            res = {**res, "dependency_check": dep_info}
        st_fp = last_update_status_path(st_root, prefix=eff_prefix)
        if st_fp.is_file():
            try:
                loaded_last = json.loads(st_fp.read_text(encoding="utf-8-sig"))
                if isinstance(loaded_last, dict):
                    res = {**res, "last_update_status": loaded_last}
            except Exception:
                pass

        if args.json:
            print(json.dumps(res, ensure_ascii=False, indent=2))
            return 0 if res.get("ok") else 1

        if not res.get("ok"):
            print(f"检查更新失败   : {res.get('error') or res.get('error_code') or '未知错误'}")
            return 1
        cur_v = str(res.get("current_version") or "未知")
        lat_v = str(res.get("latest_version") or cur_v)
        cur_rev = str(res.get("current_revision") or "")
        lat_c = str(res.get("latest_commit") or "")[:12]
        upd_avail = bool(res.get("update_available"))
        print(f"更新通道       : {res.get('channel') or channel}" + ("（已自动回退到 main）" if res.get("fallback_to_main") else ""))
        print(f"当前版本       : {cur_v}" + (f" ({cur_rev})" if cur_rev else ""))
        print(f"最新版本       : {lat_v}" + (f" ({lat_c})" if lat_c else ""))
        print(f"检查结论       : {'发现可用更新' if upd_avail else '当前已是最新版本'}")
        if isinstance(dep_info, dict):
            missing = dep_info.get("missing_or_outdated") or []
            print(f"依赖满足状态   : {'全部满足' if dep_info.get('satisfied') else '存在缺失或版本偏低: ' + ', '.join(str(x) for x in missing)}")
        ti = res.get("tunnel_impact") if isinstance(res.get("tunnel_impact"), dict) else {}
        if ti.get("only_ephemeral_trycloudflare"):
            print("隧道提示       : 当前仅使用临时 trycloudflare 链接；常规更新会保留现有隧道不断连。")
        if res.get("release_notes"):
            first_line = str(res["release_notes"]).splitlines()[0].strip()
            if first_line:
                print(f"更新说明       : {first_line}")
        return 0

    res_apply = stage_and_apply_update(
        st_root,
        prefix=eff_prefix,
        channel=channel,
        archive_path=arc_path,
        allow_tunnel_restart=bool(getattr(args, "allow_tunnel_restart", False)),
        force_active_tasks=bool(getattr(args, "force", False)),
        defer_restart_sec=0.0,
    )
    if args.json:
        print(json.dumps(res_apply, ensure_ascii=False, indent=2))
        return 0 if res_apply.get("ok") else 1

    if not res_apply.get("ok"):
        print(f"更新未完成     : {res_apply.get('error') or res_apply.get('error_code') or '未知错误'}")
        if res_apply.get("status") == "rolled_back":
            print(f"自动回滚结果   : 已恢复到 {res_apply.get('restored_version') or '上一版本'}")
        return 1

    from_v = str(res_apply.get("from_version") or "未知")
    to_v = str(res_apply.get("to_version") or from_v)
    mode_lbl = str(res_apply.get("restart_mode") or "")
    print(f"更新结果       : 成功 ({from_v} -> {to_v})")
    if mode_lbl:
        print(f"切换方式       : {mode_lbl}")
    if res_apply.get("deferred_daemon_restart_note"):
        print("隧道保留提示   : 为保留当前临时公网地址，本次仅热重载工作进程；如需更新隧道组件可加 --allow-tunnel-restart。")
    return 0


def _cmd_agent_setup(args: argparse.Namespace) -> int:
    """Non-interactive deployment command; `--guide` prints recommended commands without starting."""
    if not getattr(args, "guide", False):
        return _cmd_setup_or_start(args, is_setup=False)

    st_root = resolve_cli_state_root(args.state_dir)
    guide = {
        "ok": True,
        "product": "cosmos-mcp",
        "guide_only": True,
        "deployment_started": False,
        "version": CLI_VERSION,
        "state_root": str(st_root),
        "recommended_commands": {
            "agent_setup_openssh": "cosmos-mcp agent-setup --mode openssh --no-browser --json",
            "agent_setup_public_gateway": "cosmos-mcp agent-setup --mode public_gateway --no-browser --json",
            "agent_setup_cloudflare": "cosmos-mcp agent-setup --mode cloudflare --no-browser --json",
            "non_interactive_local_start": "cosmos-mcp agent-setup --mode local --no-browser --json",
            "non_interactive_named_tunnel": "cosmos-mcp agent-setup --mode cloudflare_token --tunnel-token <TOKEN> --public-url https://<DOMAIN> --no-browser --json",
            "status_json": "cosmos-mcp status --json",
            "hot_switch_tier": "cosmos-mcp permissions --tier L3 --readonly-workspace <DIR> --json",
            "export_identity_card": "cosmos-mcp export-identity --out cosmos_recovery.png --passphrase <SECRET> --json",
            "import_identity_card": "cosmos-mcp import-identity --in cosmos_recovery.png --passphrase <SECRET> --json",
            "doctor_json": "cosmos-mcp doctor --json",
            "stop_json": "cosmos-mcp stop --json",
            "uninstall_purge": "cosmos-mcp uninstall --purge -y --json",
            "bind_specific_client": "cosmos-mcp bind-desktop --clients installed --json",
            "stdio_entry": "cosmos-mcp stdio",
        },
        "permission_tiers": {
            "L1": "tier1_readonly (只读浏览模式：仅允许目录读取与搜索，拦截一切文件修改与命令执行)",
            "L2": "tier2_workspace_edit (仅修改文件：允许在开放工作区内修改文件，拦截一切命令与脚本执行)",
            "L3": "tier3_workspace_dev (工作区内顺畅开发：默认档，允许在开放工作区内读写文件与无窗口执行命令，只读目录仅可读)",
            "L4": "tier4_full_power (全盘顺畅开发：不限工作区目录，仍保留系统核心目录与自身凭据目录写入拦截)",
        },
        "supported_clients": list(DESKTOP_CLIENT_SPECS.keys()),
    }
    if args.json:
        print(json.dumps(guide, ensure_ascii=False, indent=2))
    else:
        print("Cosmos MCP 自动化配置命令速查：")
        for k, cmd_s in guide["recommended_commands"].items():
            print(f"  {k:<32}: {cmd_s}")
        print("\n安全档位说明 (L1..L4)：")
        for tk, desc_s in guide["permission_tiers"].items():
            print(f"  {tk}: {desc_s}")
    return 0


_LEGACY_V2_CLI_RECOVERY_PASSPHRASE_READONLY = "cosmos-mcp-cli-default-recovery-v2"


def _resolve_local_cli_recovery_key_path(st_root: Path) -> Path:
    st_resolved = Path(st_root).expanduser().resolve()
    home_resolved = Path.home().expanduser().resolve()
    if os.environ.get("PYTEST_CURRENT_TEST"):
        temp_root_norm = os.path.normcase(str(Path(tempfile.gettempdir()).resolve()))
        st_norm = os.path.normcase(str(st_resolved))
        if st_norm.startswith(temp_root_norm + os.sep) or st_resolved.parent != home_resolved:
            return st_resolved.parent / ".cosmos-mcp-cli-recovery.key"
    return home_resolved / ".cosmos-mcp-cli-recovery.key"


def _get_or_create_local_cli_recovery_secret(st_root: Path) -> str:
    key_path = _resolve_local_cli_recovery_key_path(st_root)
    if key_path.is_file():
        try:
            existing = key_path.read_text(encoding="utf-8", errors="replace").strip()
            if len(existing) >= 32:
                return existing
        except OSError:
            pass
    generated = secrets.token_urlsafe(32)
    atomic_write_text(key_path, generated + "\n", mode_override=0o600)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return generated


def _resolve_recovery_passphrase(
    args: argparse.Namespace,
    *,
    prompt_label: str,
    st_root: Optional[Path] = None,
) -> Tuple[str, str]:
    raw_pw = getattr(args, "passphrase", None)
    if raw_pw is not None and str(raw_pw).strip():
        return str(raw_pw).strip(), "explicit"
    if getattr(args, "passphrase_stdin", False):
        stdin_pw = sys.stdin.readline().rstrip("\r\n")
        if not stdin_pw:
            raise ValueError("--passphrase-stdin 未从标准输入读到有效口令。")
        return stdin_pw, "stdin"
    env_pw = (os.environ.get("COSMOS_RECOVERY_PASSPHRASE") or "").strip()
    if env_pw:
        return env_pw, "env"
    if _is_interactive_human_tty() and not getattr(args, "json", False):
        entered = getpass.getpass(prompt_label).strip()
        if entered:
            return entered, "interactive"
    eff_st = st_root if st_root is not None else resolve_cli_state_root(getattr(args, "state_dir", ""))
    return _get_or_create_local_cli_recovery_secret(eff_st), "local_machine_key"


def _run_export_identity(
    st_root: Path,
    *,
    prefix: str,
    out_path: Path,
    passphrase: str,
    passphrase_mode: str,
) -> Dict[str, Any]:
    eff_p = _norm_prefix(prefix)
    cfg_p = service_cfg_path(st_root, eff_p)
    cfg_doc: Dict[str, Any] = {}
    if cfg_p.is_file():
        try:
            loaded = json.loads(cfg_p.read_text(encoding="utf-8-sig"))
            if isinstance(loaded, dict):
                cfg_doc = loaded
        except Exception:
            cfg_doc = {}
    if not cfg_doc:
        cfg_doc = ensure_standalone_state(st_root, prefix=eff_p)

    ws_roots = list(
        cfg_doc.get("workspace_roots")
        or ([cfg_doc["workspace"]] if cfg_doc.get("workspace") else [])
    )
    ro_roots = list(cfg_doc.get("readonly_workspace_roots") or [])
    raw_packs = list(cfg_doc.get("enabled_packs") or [])
    policy_doc: Dict[str, Any] = {
        "v": 1,
        "prefix": eff_p,
        "tool_prefix": str(cfg_doc.get("tool_prefix") or eff_p),
        "device_label": str(cfg_doc.get("device_label") or ""),
        "permission_tier": str(cfg_doc.get("permission_tier") or "tier3_workspace_dev"),
        "toolset_profile": str(cfg_doc.get("toolset_profile") or "standard"),
        "workspace_roots": ws_roots,
        "readonly_workspace_roots": ro_roots,
        "enabled_packs": raw_packs,
        "scan_host_global_skills": bool(cfg_doc.get("scan_host_global_skills", False)),
        "python_path": str(cfg_doc.get("python_path") or ""),
    }
    base_png = export_identity_recovery_png(st_root, passphrase, prefix=eff_p)
    full_png = _inject_policy_chunk_into_png(base_png, policy_doc, passphrase)
    dest = Path(expand_env_and_tilde(str(out_path))).expanduser().resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp_dest = dest.parent / f".{dest.name}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
    try:
        tmp_dest.write_bytes(full_png)
        try:
            os.chmod(tmp_dest, 0o600)
        except OSError:
            pass
        os.replace(tmp_dest, dest)
    finally:
        if tmp_dest.exists():
            try:
                tmp_dest.unlink()
            except OSError:
                pass
    id_info = ensure_master_seed_identity(st_root, prefix=eff_p)
    res: Dict[str, Any] = {
        "ok": True,
        "exported": True,
        "output_path": str(dest),
        "bytes": len(full_png),
        "prefix": eff_p,
        "node_id": id_info.get("node_id"),
        "tool_prefix": policy_doc["tool_prefix"],
        "permission_tier": policy_doc["permission_tier"],
        "workspace_roots": ws_roots,
        "readonly_workspace_roots": ro_roots,
        "enabled_packs": _format_cli_packs(raw_packs),
        "scan_host_global_skills": policy_doc["scan_host_global_skills"],
        "passphrase_mode": passphrase_mode,
    }
    if passphrase_mode == "local_machine_key":
        res["security_notice_zh"] = (
            "当前未传入 --passphrase，已使用本机专属随机密钥（.cosmos-mcp-cli-recovery.key）加密；"
            "若需跨设备迁移恢复，请附加 --passphrase <自定义口令>。"
        )
    return res


def _run_import_identity(
    st_root: Path,
    *,
    prefix: str,
    in_path: Path,
    passphrase: str,
    passphrase_mode: str,
) -> Dict[str, Any]:
    eff_p = _norm_prefix(prefix)
    src = Path(expand_env_and_tilde(str(in_path))).expanduser().resolve()
    if not src.is_file():
        raise ValueError(f"未找到身份恢复卡文件: {src}")
    png_bytes = src.read_bytes()
    eff_used_passphrase = passphrase
    try:
        restored = import_identity_recovery_png(png_bytes, passphrase, st_root, prefix=eff_p)
    except ValueError as exc:
        if passphrase_mode in ("local_machine_key", "default_cli") and "passphrase" in str(exc).lower():
            try:
                restored = import_identity_recovery_png(
                    png_bytes,
                    _LEGACY_V2_CLI_RECOVERY_PASSPHRASE_READONLY,
                    st_root,
                    prefix=eff_p,
                )
                eff_used_passphrase = _LEGACY_V2_CLI_RECOVERY_PASSPHRASE_READONLY
            except ValueError:
                raise ValueError(
                    "身份恢复卡解密失败：该恢复卡由其他设备密钥或自定义加密口令保护，请通过 `--passphrase <口令>` 传入。"
                ) from exc
        else:
            raise

    policy_doc = _extract_policy_chunk_from_png(png_bytes, eff_used_passphrase)
    skipped_ws: List[str] = []
    valid_ws: List[str] = []
    valid_ro: List[str] = []

    if policy_doc:
        for raw_w in (policy_doc.get("workspace_roots") or []):
            w_str = str(raw_w or "").strip()
            if not w_str:
                continue
            try:
                wp = Path(expand_env_and_tilde(w_str)).expanduser().resolve()
                wp.mkdir(parents=True, exist_ok=True)
                valid_ws.append(str(wp))
            except OSError:
                skipped_ws.append(w_str)
        for raw_ro in (policy_doc.get("readonly_workspace_roots") or []):
            ro_str = str(raw_ro or "").strip()
            if not ro_str:
                continue
            try:
                rop = Path(expand_env_and_tilde(ro_str)).expanduser().resolve()
                rop.mkdir(parents=True, exist_ok=True)
                valid_ro.append(str(rop))
            except OSError:
                skipped_ws.append(ro_str)

        raw_packs_in = policy_doc.get("enabled_packs")
        packs_norm = _parse_packs(",".join(str(x) for x in raw_packs_in)) if isinstance(raw_packs_in, list) else None
        state_sync = ensure_standalone_state(
            st_root,
            prefix=eff_p,
            tool_prefix=str(policy_doc.get("tool_prefix") or ""),
            device_label=str(policy_doc.get("device_label") or ""),
            tier_key=str(policy_doc.get("permission_tier") or ""),
            toolset_profile=str(policy_doc.get("toolset_profile") or ""),
            workspace_roots=valid_ws if valid_ws else None,
            readonly_workspace_roots=valid_ro if "readonly_workspace_roots" in policy_doc else None,
            scan_host_global_skills=policy_doc.get("scan_host_global_skills") if "scan_host_global_skills" in policy_doc else None,
            enabled_packs=packs_norm,
            python_path=policy_doc.get("python_path") if "python_path" in policy_doc else None,
            tunnel_mode=str(restored.get("restored_tunnel_mode") or ""),
        )
    else:
        state_sync = ensure_standalone_state(
            st_root,
            prefix=eff_p,
            tunnel_mode=str(restored.get("restored_tunnel_mode") or ""),
        )

    out_res: Dict[str, Any] = {
        "ok": True,
        "imported": True,
        "input_path": str(src),
        "prefix": eff_p,
        **restored,
        "policy_restored": bool(policy_doc),
        "tool_prefix": state_sync["tool_prefix"],
        "permission_tier": state_sync["permission_tier"],
        "workspace_roots": state_sync["workspace_roots"],
        "readonly_workspace_roots": state_sync["readonly_workspace_roots"],
        "enabled_packs": state_sync["enabled_packs"],
        "scan_host_global_skills": state_sync["scan_host_global_skills"],
        "python_path": state_sync["python_path"],
        "pair_code": state_sync["pair_code"],
        "dynamic_pair_code": state_sync["dynamic_pair_code"],
    }
    if skipped_ws:
        out_res["skipped_unreachable_workspaces"] = skipped_ws
    return out_res


def _cmd_export_identity(args: argparse.Namespace) -> int:
    st_root = resolve_cli_state_root(args.state_dir)
    out_raw = (getattr(args, "out", "") or "").strip()
    if not out_raw:
        msg = "请通过 `--out <png_path>` 指定身份恢复卡 PNG 导出路径。"
        if args.json:
            print(json.dumps({"ok": False, "error": msg}, ensure_ascii=False))
        else:
            print(msg, file=sys.stderr)
        return 2
    try:
        pw, pw_mode = _resolve_recovery_passphrase(
            args,
            prompt_label="请输入恢复卡加密口令 (回车使用本机专属随机密钥): ",
            st_root=st_root,
        )
        res = _run_export_identity(st_root, prefix=args.prefix, out_path=Path(out_raw), passphrase=pw, passphrase_mode=pw_mode)
    except ValueError as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        else:
            print(f"导出失败: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print(f"身份与工作区策略恢复卡已导出: {res['output_path']} (node_id={res.get('node_id')})")
        if res.get("security_notice_zh"):
            print(f"  {res['security_notice_zh']}")
    return 0


def _cmd_import_identity(args: argparse.Namespace) -> int:
    st_root = resolve_cli_state_root(args.state_dir)
    in_raw = (getattr(args, "in_path", "") or "").strip()
    if not in_raw:
        msg = "请通过 `--in <png_path>` 指定要导入的身份恢复卡 PNG 路径。"
        if args.json:
            print(json.dumps({"ok": False, "error": msg}, ensure_ascii=False))
        else:
            print(msg, file=sys.stderr)
        return 2
    try:
        pw, pw_mode = _resolve_recovery_passphrase(
            args,
            prompt_label="请输入恢复卡解密口令 (若在本机导出且未设口令可直接回车): ",
            st_root=st_root,
        )
        res = _run_import_identity(st_root, prefix=args.prefix, in_path=Path(in_raw), passphrase=pw, passphrase_mode=pw_mode)
    except ValueError as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        else:
            print(f"导入失败: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print(
            f"身份与工作区策略恢复已完成 (node_id={res.get('node_id')}, "
            f"安全档位={_format_tier_zh(res['permission_tier'])}, 工具前缀={res['tool_prefix']}_*)"
        )
    return 0


def _cmd_identity(args: argparse.Namespace) -> int:
    exp_p = (getattr(args, "export_path", "") or "").strip()
    imp_p = (getattr(args, "import_path", "") or "").strip()
    if exp_p and imp_p:
        msg = "`--export` 与 `--import` 不能同时传入。"
        if args.json:
            print(json.dumps({"ok": False, "error": msg}, ensure_ascii=False))
        else:
            print(msg, file=sys.stderr)
        return 2
    if exp_p:
        args.out = exp_p
        return _cmd_export_identity(args)
    if imp_p:
        args.in_path = imp_p
        return _cmd_import_identity(args)
    msg = "请指定 `cosmos-mcp identity --export <png_path>` 或 `cosmos-mcp identity --import <png_path>`。"
    if args.json:
        print(json.dumps({"ok": False, "error": msg}, ensure_ascii=False))
    else:
        print(msg, file=sys.stderr)
    return 2


def _cmd_bind_desktop(args: argparse.Namespace) -> int:
    st_root = resolve_cli_state_root(args.state_dir)
    eff_p = _norm_prefix(args.prefix)
    if args.unbind:
        res = unbind_desktop_clients(state_root=st_root, clients=args.clients or None, prefix=eff_p)
        if args.json:
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            print(f"已解绑 {len(res.get('unbound') or [])} 个桌面客户端配置（保留原有其他服务与注释格式）。")
        return 0

    if not args.clients:
        msg = "请通过 `--clients <客户端名>` 显式指定要绑定的桌面客户端（可选: " + ", ".join(DESKTOP_CLIENT_SPECS) + " 或 installed）。"
        if args.json:
            print(json.dumps({"ok": False, "error": msg}, ensure_ascii=False))
        else:
            print(msg, file=sys.stderr)
        return 2

    init_info = ensure_standalone_state(st_root, port=int(args.port or 0), prefix=eff_p)
    venv_py_bind = venv_python_path(st_root / ".venv", windowless=False)
    py_cand = find_suitable_python()
    py_exe = str(venv_py_bind) if venv_py_bind.is_file() else (py_cand[0] if py_cand else sys.executable)
    res = bind_desktop_clients(
        clients=args.clients,
        state_root=st_root,
        python_exe=py_exe,
        port=init_info["port"],
        local_api_token=init_info["local_api_token"],
        prefix=eff_p,
        migrate_from_prefix=args.migrate_from_prefix or "",
        transport_override=args.transport or "",
        repo_src=resolve_persisted_src_dir(st_root),
    )
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        names = [c["client_id"] for c in (res.get("bound_clients") or [])]
        print(f"已完成桌面客户端绑定: {', '.join(names) if names else '无匹配已安装客户端'}")
    return 0


def _cmd_vps_caddy(args: argparse.Namespace) -> int:
    snippet = generate_vps_caddy_snippet(args.domain or "mcp.example.com", remote_port=int(args.remote_port or 18096))
    if args.json:
        print(
            json.dumps(
                {
                    "ok": True,
                    "domain": args.domain or "mcp.example.com",
                    "remote_port": int(args.remote_port or 18096),
                    "caddyfile": snippet,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print(snippet, end="")
    return 0


def _cmd_stop(args: argparse.Namespace) -> int:
    st_root = resolve_cli_state_root(args.state_dir)
    res = stop_daemon(st_root, prefix=args.prefix)
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print("Cosmos MCP 后台服务与隧道已停止。")
    return 0


def _cmd_uninstall(args: argparse.Namespace) -> int:
    st_root = resolve_cli_state_root(args.state_dir)
    cf_tok = (getattr(args, "cf_api_token", "") or os.environ.get("COSMOS_CF_API_TOKEN") or "").strip()
    cf_cleanup_res: Optional[Dict[str, Any]] = None
    if cf_tok:
        if args.dry_run:
            cf_cleanup_res = {"ok": True, "dry_run": True, "planned": True}
        else:
            cf_cleanup_res = delete_cloudflare_workers_gateway(
                api_token=cf_tok,
                state_root=st_root,
                prefix=args.prefix or "pc",
            )
    res = run_uninstall(st_root, prefix=args.prefix or "", purge=bool(args.purge), dry_run=bool(args.dry_run))
    if cf_cleanup_res is not None:
        res["cloudflare_worker_cleanup"] = cf_cleanup_res
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        if args.dry_run:
            print(
                f"[预演模式] 将清理 {len(res.get('planned_removals') or [])} 项运行文件与快捷入口，"
                f"默认保留回收站/撤销记录: {res.get('preserved_recovery_dirs')}"
            )
            if not args.purge:
                print(f"  {UNINSTALL_PURGE_HINT_ZH}")
        else:
            print(
                f"卸载清理已完成（已移除 {len(res.get('removed_paths') or [])} 项，"
                f"保留恢复目录: {len(res.get('preserved_recovery_dirs') or [])} 项）。"
            )
            if not args.purge:
                print(f"  {UNINSTALL_PURGE_HINT_ZH}")
    return 0


def _cmd_stdio(args: argparse.Namespace) -> int:
    st_root = resolve_cli_state_root(args.state_dir)
    os.environ["COSMOS_MCP_STATE_DIR"] = str(st_root)
    os.environ["LOCALPC_MCP_STATE_DIR"] = str(st_root)
    bind_stdio_to_parent_lifecycle()

    env_res = ensure_runtime_environment(st_root)
    if not env_res.get("ok"):
        print(str(env_res.get("detail") or env_res.get("error")), file=sys.stderr)
        return 1
    py_exe = str(env_res["python_exe"])
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONUTF8"] = "1"
    env["COSMOS_MCP_STATE_DIR"] = str(st_root)
    env["LOCALPC_MCP_STATE_DIR"] = str(st_root)
    persisted_src = resolve_persisted_src_dir(st_root)
    if persisted_src is not None:
        env["PYTHONPATH"] = f"{persisted_src}{os.pathsep}{env.get('PYTHONPATH', '')}".rstrip(os.pathsep)
    cmd = [py_exe, "-B", "-m", "cosmos_mcp.launcher.app", "--stdio", "--state-dir", str(st_root)]
    if args.workspace:
        cmd.extend(["--workspace", args.workspace])
    if args.tier:
        cmd.extend(["--tier", args.tier])
    if args.prefix:
        cmd.extend(["--prefix", args.prefix])
    if getattr(args, "tool_prefix", ""):
        cmd.extend(["--tool-prefix", getattr(args, "tool_prefix")])
    if getattr(args, "device_label", ""):
        cmd.extend(["--device-label", args.device_label])
    if args.toolset:
        cmd.extend(["--toolset", args.toolset])
    if getattr(args, "enable_pack", None):
        cmd.extend(["--enable-pack", str(args.enable_pack)])
    from cosmos_mcp.core.proc import assign_win32_job_kill_on_close

    proc = subprocess.Popen(
        cmd,
        stdin=sys.stdin,
        stdout=sys.stdout,
        stderr=sys.stderr,
        env=env,
        creationflags=(CREATE_NO_WINDOW if sys.platform == "win32" else 0),
    )
    job = assign_win32_job_kill_on_close(proc.pid)
    try:
        return int(proc.wait())
    finally:
        if job is not None:
            job.close()


def build_cli_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--state-dir", default="", help="自定义状态与配置根目录")
    common.add_argument("--prefix", default="pc", help="实例与配置槽名前缀（默认 pc）")
    common.add_argument("--tool-prefix", default="", help="MCP 工具名前缀覆盖（默认沿用已保存前缀或 pc）")
    common.add_argument("--json", action="store_true", help="输出结构化 JSON（非交互模式）")
    common.add_argument("--no-browser", action="store_true", help="禁止打开系统浏览器")
    common.add_argument("--open-browser", action="store_true", help="启动就绪后自动在浏览器打开实际控制面板地址")
    common.add_argument("--no-tray", action="store_true", help="禁用系统托盘状态图标")

    sub_common = argparse.ArgumentParser(add_help=False)
    sub_common.add_argument("--state-dir", default=argparse.SUPPRESS, help="自定义状态与配置根目录")
    sub_common.add_argument("--prefix", default=argparse.SUPPRESS, help="实例与配置槽名前缀（默认 pc）")
    sub_common.add_argument("--tool-prefix", default=argparse.SUPPRESS, help="MCP 工具名前缀覆盖")
    sub_common.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="输出结构化 JSON（非交互模式）")
    sub_common.add_argument("--no-browser", action="store_true", default=argparse.SUPPRESS, help="禁止打开系统浏览器")
    sub_common.add_argument("--open-browser", action="store_true", default=argparse.SUPPRESS, help="启动就绪后自动在浏览器打开实际控制面板地址")
    sub_common.add_argument("--no-tray", action="store_true", default=argparse.SUPPRESS, help="禁用系统托盘状态图标")

    parser = argparse.ArgumentParser(
        prog="cosmos-mcp",
        description="Cosmos MCP 本地服务端与控制面板启动器（面向网页版 Gemini 与网页版 ChatGPT 的 OAuth 2.1 连接器）",
        parents=[common],
    )
    parser.add_argument("--version", action="version", version=f"cosmos-mcp {CLI_VERSION}")
    parser.add_argument("--stdio", action="store_true", help="以零守护进程 Stdio 模式运行")

    sub = parser.add_subparsers(dest="subcommand")

    for sub_name, desc in (
        ("setup", "运行配置向导或非交互初始化启动"),
        ("start", "启动后台常驻服务与连接通道"),
        ("daemon", "启动后台常驻守护服务与连接通道"),
        ("agent-setup", "非交互部署并启动后台服务；--guide 仅输出配置说明"),
    ):
        sp = sub.add_parser(sub_name, help=desc, parents=[sub_common])
        sp.add_argument(
            "--mode",
            choices=list(SUPPORTED_TUNNEL_MODES),
            default="",
            help="连接通道：openssh（或 public_gateway，首次默认：调用系统内置 OpenSSH 以 Ed25519 + SSHv2/TLS 加密生成免登录固定地址） / cloudflare / workers_dev / vps_hub / cloudflare_token / vps / custom / local",
        )
        sp.add_argument("--tunnel-token", default=None, help="Cloudflare Named Tunnel 固定域名 Token（配合 --public-url 永久固定域名）")
        sp.add_argument("--port", type=int, default=0, help="本地监听端口（默认沿用已保存端口或 8096）")
        sp.add_argument("--workspace", default="", help="主开放工作目录（默认绑定当前终端项目目录）")
        sp.add_argument("--add-workspace", action="append", default=[], help="追加额外开放工作目录（可重复传参）")
        sp.add_argument(
            "--readonly-workspace",
            action="append",
            default=None,
            help="设置只读参考工作目录（可重复传参或逗号分隔；传 none 清空）",
        )
        sp.add_argument(
            "--scan-host-global-skills",
            type=_parse_cli_bool_choice,
            metavar="{true,false}",
            default=None,
            help="是否自动扫描宿主机全局技能目录（true/false）",
        )
        sp.add_argument("--python-path", default=None, help="指定 run_python 使用的 Python 解释器路径")
        sp.add_argument("--tier", default="", help="安全模式：L3 工作区内顺畅开发 / L2 仅修改文件（禁运行命令） / L1 只读浏览模式 / L4 全盘顺畅开发（不限目录）")
        sp.add_argument("--toolset", "--set-toolset", dest="toolset", default="", help="核心工具预设（默认 standard 16 项）")
        sp.add_argument("--enable-pack", default=None, help="开启扩展能力包：browser / desktop / browser,desktop / none")
        sp.add_argument("--keep-awake", dest="keep_awake", action="store_true", default=None, help="开启系统防休眠锁（默认开启）")
        sp.add_argument("--no-keep-awake", dest="keep_awake", action="store_false", help="关闭系统防休眠锁")
        sp.add_argument("--approval-popups", dest="approval_popups", action="store_true", default=None, help="开启写/执行宿主确认弹窗")
        sp.add_argument("--no-approval-popups", dest="approval_popups", action="store_false", help="关闭确认弹窗（默认免打扰）")
        sp.add_argument("--device-label", default="", help="设备显示名称")
        sp.add_argument("--public-url", default="", help="自定义或固定公网 HTTPS 地址")
        sp.add_argument("--vps-ssh", default="", help="VPS SSH 目标（如 user@vps.example.com）")
        sp.add_argument("--vps-remote-port", type=int, default=None, help="VPS 远端反向监听端口（默认 18096）")
        sp.add_argument("--vps-ssh-port", "--vps-port", dest="vps_ssh_port", type=int, default=None, help="VPS SSH 端口（默认 22）")
        sp.add_argument("--vps-identity-file", default="", help="VPS SSH 私钥文件路径")
        sp.add_argument("--bind-desktop", default="", help="绑定桌面客户端（逗号分隔，如 cursor,vscode,codex 或 installed）")
        sp.add_argument("--autostart", action="store_true", help="注册当前系统用户登录后自动启动")
        sp.add_argument("--shortcut", action="store_true", help="在桌面生成 一键启动_Cosmos_MCP.bat 快捷入口")
        sp.add_argument("--daemon", action="store_true", default=True, help="脱离终端后台常驻运行（默认）")
        sp.add_argument("--foreground", action="store_true", help="前台阻塞运行（供调试使用）")
        sp.add_argument("--restart", action="store_true", help="若已有在线实例则显式平滑重启")
        sp.add_argument("--prepare-only", action="store_true", help="写入初始化配置与凭据并完成虚拟环境/依赖自举检查，不拉起守护进程")
        if sub_name == "agent-setup":
            sp.add_argument("--guide", action="store_true", help="仅输出自动化配置说明，不初始化或启动服务")

    sp_status = sub.add_parser("status", help="查看在线状态、连接地址、明文连接口令、4 位核对码与 6 位动态配对码", parents=[sub_common])
    sp_status.add_argument("--show-password", dest="show_password", action="store_true", default=True, help="明文显示连接口令（默认开启）")
    sp_status.add_argument("--hide-password", "--no-show-password", dest="show_password", action="store_false", help="隐藏明文连接口令")
    sp_status.add_argument("--copy-password", action="store_true", help="将当前连接口令复制到系统剪贴板")

    sp_perm = sub.add_parser("permissions", help="在线热切换安全模式、多工作目录、只读参考目录、扩展能力包与令牌吊销", parents=[sub_common])
    sp_perm.add_argument("--tier", "--set-tier", dest="tier", default="", help="目标安全模式：L1 / L2 / L3 / L4")
    sp_perm.add_argument("--workspace", "--set-workspace", dest="workspace", default="", help="重设主工作目录")
    sp_perm.add_argument("--add-workspace", action="append", default=[], help="追加开放工作目录")
    sp_perm.add_argument("--remove-workspace", action="append", default=[], help="移除指定开放工作目录")
    sp_perm.add_argument(
        "--readonly-workspace",
        action="append",
        default=None,
        help="设置只读参考工作目录（可多次传入或逗号分隔；传 none 清空）",
    )
    sp_perm.add_argument("--add-readonly-workspace", action="append", default=[], help="追加只读参考工作目录")
    sp_perm.add_argument("--remove-readonly-workspace", action="append", default=[], help="移除只读参考工作目录")
    sp_perm.add_argument(
        "--scan-host-global-skills",
        type=_parse_cli_bool_choice,
        metavar="{true,false}",
        default=None,
        help="是否自动扫描宿主机全局技能目录（true/false）",
    )
    sp_perm.add_argument("--python-path", default=None, help="指定 run_python 使用的 Python 解释器路径")
    sp_perm.add_argument("--toolset", "--set-toolset", dest="toolset", default="", help="核心工具预设")
    sp_perm.add_argument("--enable-pack", "--enable-packs", dest="enable_pack", default=None, help="开启扩展包：browser / desktop / none")
    sp_perm.add_argument("--mode", choices=["", *SUPPORTED_TUNNEL_MODES], default="", help="切换连接通道模式")
    sp_perm.add_argument("--tunnel-token", default=None, help="设置 Cloudflare Named Tunnel 固定 Token")
    sp_perm.add_argument("--public-url", default="", help="设置固定公网 HTTPS 域名")
    sp_perm.add_argument("--vps-ssh", default=None, help="设置 VPS SSH 目标")
    sp_perm.add_argument("--vps-remote-port", type=int, default=None, help="设置 VPS 远端反向监听端口")
    sp_perm.add_argument("--vps-ssh-port", type=int, default=None, help="设置 VPS SSH 端口")
    sp_perm.add_argument("--vps-identity-file", default=None, help="设置 VPS SSH 私钥文件路径")
    sp_perm.add_argument("--keep-awake", dest="keep_awake", action="store_true", default=None, help="开启防休眠")
    sp_perm.add_argument("--no-keep-awake", dest="keep_awake", action="store_false", help="关闭防休眠")
    sp_perm.add_argument("--approval-popups", dest="approval_popups", action="store_true", default=None, help="开启确认弹窗")
    sp_perm.add_argument("--no-approval-popups", dest="approval_popups", action="store_false", help="关闭确认弹窗")
    sp_perm.add_argument("--tray", dest="tray_enabled", action="store_true", default=None, help="开启系统托盘图标")
    sp_perm.add_argument("--disable-tray", dest="tray_enabled", action="store_false", help="关闭系统托盘图标")
    sp_perm.add_argument("--revoke-all", action="store_true", help="一键吊销全部已授权网页端令牌并终止在途命令")
    sp_perm.add_argument("--revoke-client", default="", help="吊销指定 client_id 的令牌")
    sp_perm.add_argument("--reset-password", action="store_true", help="重新生成本机连接口令")

    sp_exp_id = sub.add_parser("export-identity", help="导出加密 PNG 身份恢复卡（含固定网址密钥与工作区策略）", parents=[sub_common])
    sp_exp_id.add_argument("--out", "--output", dest="out", required=True, help="导出恢复卡 PNG 文件路径")
    sp_exp_id.add_argument("--passphrase", default=None, help="恢复卡加密口令（也可通过环境变量 COSMOS_RECOVERY_PASSPHRASE 传入）")
    sp_exp_id.add_argument("--passphrase-stdin", action="store_true", help="从标准输入读取首行加密口令")

    sp_imp_id = sub.add_parser("import-identity", help="从加密 PNG 身份恢复卡恢复固定网址密钥与工作区策略", parents=[sub_common])
    sp_imp_id.add_argument("--in", "--input", dest="in_path", required=True, help="待导入的恢复卡 PNG 文件路径")
    sp_imp_id.add_argument("--passphrase", default=None, help="恢复卡解密口令（也可通过环境变量 COSMOS_RECOVERY_PASSPHRASE 传入）")
    sp_imp_id.add_argument("--passphrase-stdin", action="store_true", help="从标准输入读取首行解密口令")

    sp_ident = sub.add_parser("identity", help="换机身份恢复卡导出/导入入口（--export <path> / --import <path>）", parents=[sub_common])
    sp_ident.add_argument("--export", dest="export_path", default="", help="导出恢复卡 PNG 路径")
    sp_ident.add_argument("--import", dest="import_path", default="", help="导入恢复卡 PNG 路径")
    sp_ident.add_argument("--passphrase", default=None, help="恢复卡加解密口令")
    sp_ident.add_argument("--passphrase-stdin", action="store_true", help="从标准输入读取首行口令")

    sp_doc = sub.add_parser("doctor", help="运行深度隐私脱敏环境诊断", parents=[sub_common])
    sp_doc.add_argument("--probe", action="store_true", help="实测本机服务、代理、公网 HTTPS 网关及 OAuth/MCP 协议全链路连通性")
    sp_doc.add_argument("--gateway", dest="gateway_id", default="", help="仅探测指定网关槽位 (instant | workers_dev | self_hosted)")
    sp_doc.add_argument("--bundle", action="store_true", help="导出深度脱敏 ZIP 诊断包")
    sp_doc.add_argument("--output", default="", help="指定诊断包输出路径")

    sp_upd = sub.add_parser("update", help="检查更新或无感应用一键更新（支持 --check 仅检查与本地离线 ZIP 包）", parents=[sub_common])
    sp_upd.add_argument("--check", action="store_true", help="仅检查版本与依赖差异，不修改本地文件")
    sp_upd.add_argument(
        "--channel",
        choices=("release", "main"),
        default="release",
        help="更新通道：release（正式版，无发布时自动回退 main）或 main（主干提交）",
    )
    sp_upd.add_argument("--allow-tunnel-restart", action="store_true", help="当守护或隧道文件变动时允许重建临时公网隧道")
    sp_upd.add_argument("--force", "--force-active-tasks", dest="force", action="store_true", help="忽略在途前台任务检查并强制应用更新")
    sp_upd.add_argument("--archive", default="", help="指定本地更新 ZIP 压缩包路径")

    sp_bind = sub.add_parser("bind-desktop", help="按需显式绑定或解绑桌面客户端配置", parents=[sub_common])
    sp_bind.add_argument(
        "--clients",
        default="",
        help="客户端列表（claude_desktop,claude_code,cursor,windsurf,vscode,codex,gemini_cli,antigravity 或 installed）",
    )
    sp_bind.add_argument("--port", type=int, default=0, help="本地 HTTP 端口（默认沿用已保存端口或 8096）")
    sp_bind.add_argument("--migrate-from-prefix", default="", help="迁移旧前缀键名（如 pc -> work）")
    sp_bind.add_argument("--transport", choices=["", "http", "stdio"], default="", help="覆盖传输协议类型")
    sp_bind.add_argument("--unbind", action="store_true", help="无损摘除已写入的客户端配置")

    sp_caddy = sub.add_parser("vps-caddy-snippet", help="生成 VPS Caddy 反向代理配置片段", parents=[sub_common])
    sp_caddy.add_argument("--domain", default="mcp.example.com", help="公网域名")
    sp_caddy.add_argument("--remote-port", type=int, default=18096, help="SSH -R 远端监听端口")

    sub.add_parser("stop", help="停止后台常驻服务与隧道", parents=[sub_common])

    sp_un = sub.add_parser("uninstall", help="幂等卸载清理（清理快捷入口，默认保留 .undo_history 与回收站；加 --purge 彻底粉碎全部凭据与 .venv）", parents=[sub_common])
    sp_un.add_argument("--purge", action="store_true", help="彻底粉碎状态目录内全部凭据、令牌、回收站与 .venv")
    sp_un.add_argument("--dry-run", action="store_true", help="仅预演将清理的路径，不执行修改")
    sp_un.add_argument("-y", "--yes", action="store_true", help="跳过确认提示（兼容无人值守命令行调用）")
    sp_un.add_argument("--cf-api-token", default="", help="卸载前可选同步销毁云端 Cloudflare Worker 中继（或设环境变量 COSMOS_CF_API_TOKEN）")

    sp_stdio = sub.add_parser("stdio", help="运行绑定父进程生命周期的 Stdio MCP 服务", parents=[sub_common])
    sp_stdio.add_argument("--workspace", default="", help="工作目录")
    sp_stdio.add_argument("--tier", default="", help="安全模式")
    sp_stdio.add_argument("--device-label", default="", help="设备显示名")
    sp_stdio.add_argument("--toolset", default="", help="核心工具预设")
    sp_stdio.add_argument("--enable-pack", default=None, help="扩展能力包")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_cli_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if getattr(args, "stdio", False) and not args.subcommand:
        args.workspace = ""
        args.tier = ""
        args.device_label = ""
        args.toolset = ""
        args.enable_pack = None
        return _cmd_stdio(args)

    cmd = args.subcommand or "setup"
    if cmd == "setup":
        if not args.subcommand:
            for attr, val in (
                ("mode", ""),
                ("tunnel_token", None),
                ("port", 0),
                ("workspace", ""),
                ("add_workspace", []),
                ("readonly_workspace", None),
                ("scan_host_global_skills", None),
                ("python_path", None),
                ("tier", ""),
                ("toolset", ""),
                ("enable_pack", None),
                ("keep_awake", None),
                ("approval_popups", None),
                ("device_label", ""),
                ("public_url", ""),
                ("vps_ssh", ""),
                ("vps_remote_port", None),
                ("vps_ssh_port", None),
                ("vps_identity_file", ""),
                ("bind_desktop", ""),
                ("autostart", False),
                ("shortcut", False),
                ("foreground", False),
                ("restart", False),
                ("prepare_only", False),
            ):
                if not hasattr(args, attr):
                    setattr(args, attr, val)
        return _cmd_setup_or_start(args, is_setup=True)
    if cmd in ("start", "daemon"):
        return _cmd_setup_or_start(args, is_setup=False)
    if cmd == "status":
        return _cmd_status(args)
    if cmd == "permissions":
        return _cmd_permissions(args)
    if cmd == "export-identity":
        return _cmd_export_identity(args)
    if cmd == "import-identity":
        return _cmd_import_identity(args)
    if cmd == "identity":
        return _cmd_identity(args)
    if cmd == "doctor":
        return _cmd_doctor(args)
    if cmd == "update":
        return _cmd_update(args)
    if cmd == "agent-setup":
        return _cmd_agent_setup(args)
    if cmd == "bind-desktop":
        return _cmd_bind_desktop(args)
    if cmd == "vps-caddy-snippet":
        return _cmd_vps_caddy(args)
    if cmd == "stop":
        return _cmd_stop(args)
    if cmd == "uninstall":
        return _cmd_uninstall(args)
    if cmd == "stdio":
        return _cmd_stdio(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
