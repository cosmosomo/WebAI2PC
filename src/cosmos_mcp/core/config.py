"""Unified runtime policy, state-directory resolution, multi-workspace whitelist, and kill-signal watchdog."""
from __future__ import annotations

import atexit
import base64
import contextlib
import ctypes
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sys
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit

from cosmos_mcp.core.fs_tx import apply_current_user_only_acl, atomic_write_json, atomic_write_text, get_file_lock
from cosmos_mcp.core.guard import (
    DEFAULT_GUARD,
    READONLY_PACKAGE_MARKERS,
    WorkspaceGuard,
    expand_env_and_tilde,
    is_readonly_or_package_install_path,
    to_short_tier_code,
)
from cosmos_mcp.core.net_power import SleepInhibitor

PRODUCT_VERSION = "1.2.1"
UNAMBIGUOUS_PW_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
PREFIX_RE = re.compile(r"^[a-z][a-z0-9_]{0,15}$")
DEFAULT_TUNNEL_MODE = "public_gateway"
DEFAULT_PUBLIC_GATEWAY_BASE = ""
DEFAULT_WORKERS_DEV_SCRIPT_NAME = "cosmos-mcp-gateway"

GATEWAY_IDS: Tuple[str, ...] = ("instant", "workers_dev", "self_hosted")
INSTANT_SUBMODES: Tuple[str, ...] = ("public_gateway", "cloudflare")
SELF_HOSTED_SUBMODES: Tuple[str, ...] = ("vps_hub", "vps", "cloudflare_token", "custom")

TIER_DISPLAY_ZH: Dict[str, str] = {
    "tier1_readonly": "只读浏览模式",
    "tier2_workspace_edit": "仅修改文件（禁运行命令）",
    "tier3_workspace_dev": "工作区内顺畅开发",
    "tier4_full_power": "全盘顺畅开发（不限目录）",
}

_POLICY_SLEEP_INHIBITOR = SleepInhibitor(reason="Cosmos MCP runtime keep_awake policy")
atexit.register(_POLICY_SLEEP_INHIBITOR.disable)

ANNOTATION_MODES: Tuple[str, ...] = ("seamless", "strict")
DEFAULT_ANNOTATION_MODE: str = "seamless"


def _has_existing_state_config(dir_path: Path) -> bool:
    try:
        return (
            (dir_path / "config.json").is_file()
            or (dir_path / "config" / "config.json").is_file()
            or (dir_path / "config" / "service.json").is_file()
        )
    except OSError:
        return False


def default_user_state_dir(
    platform_name: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
) -> Path:
    """Return `%LOCALAPPDATA%\\CosmosMCP` on Windows or `~/.cosmos-mcp` on POSIX.

    Smoothly falls back to the legacy default state directory (`%LOCALAPPDATA%\\LocalPC-MCP` or
    `~/.localpc-mcp`) if `config.json` (or `config/service.json`) already exists there and the
    new directory has not been initialized yet.
    """
    eff_plat = platform_name if platform_name is not None else sys.platform
    eff_env = env if env is not None else os.environ
    home_override = (eff_env.get("HOME") or eff_env.get("USERPROFILE") or "").strip() if env is not None else ""
    home = Path(home_override).expanduser() if home_override else Path.home()

    if eff_plat == "win32":
        local_app = (eff_env.get("LOCALAPPDATA") or "").strip()
        base = Path(local_app) if local_app else (home / "AppData" / "Local")
        new_dir = (base / "CosmosMCP").expanduser()
        legacy_dir = (base / "LocalPC-MCP").expanduser()
    else:
        new_dir = (home / ".cosmos-mcp").expanduser()
        legacy_dir = (home / ".localpc-mcp").expanduser()

    if _has_existing_state_config(new_dir):
        return new_dir
    if _has_existing_state_config(legacy_dir):
        return legacy_dir
    return new_dir


def resolve_state_root(
    product_root: Optional[Union[str, Path]] = None,
    cli_state_dir: str = "",
    *,
    env: Optional[Mapping[str, str]] = None,
    platform_name: Optional[str] = None,
) -> Path:
    """Unified state directory resolver with `%LOCALAPPDATA%\\CosmosMCP` / `~/.cosmos-mcp` default."""
    eff_env = env if env is not None else os.environ
    explicit = (
        cli_state_dir
        or eff_env.get("COSMOS_MCP_STATE_DIR")
        or eff_env.get("LOCALPC_MCP_STATE_DIR")
        or ""
    ).strip()
    if explicit:
        expanded = expand_env_and_tilde(explicit)
        return Path(expanded).expanduser().resolve()

    if product_root is not None:
        anchor = Path(product_root)
        if is_readonly_or_package_install_path(anchor):
            target = default_user_state_dir(platform_name=platform_name, env=eff_env)
            try:
                return target.resolve()
            except OSError:
                return target
        return anchor.expanduser().resolve()

    here = Path(__file__).resolve()
    cand_src = here.parents[2]
    repo_anchor = here.parents[3] if cand_src.name.lower() == "src" and len(here.parents) >= 4 else cand_src
    if not is_readonly_or_package_install_path(repo_anchor) and (
        _has_existing_state_config(repo_anchor) or (repo_anchor / "secrets" / "auth.json").is_file()
    ):
        return repo_anchor.expanduser().resolve()

    target = default_user_state_dir(platform_name=platform_name, env=eff_env)
    try:
        return target.resolve()
    except OSError:
        return target


DEFAULT_REDIRECT_HOSTS: Tuple[str, ...] = (
    "oauth-redirect.googleusercontent.com",
    "oauth-redirect-sandbox.googleusercontent.com",
    "oauth-redirect-test.googleusercontent.com",
    "vertexaisearch.cloud.google.com",
    "chatgpt.com",
)

PERMISSION_TIERS: Dict[str, Dict[str, Any]] = {
    "tier1_readonly": {
        "short": "L1",
        "restrict_to_workspace": True,
        "allow_edit": False,
        "allow_exec": False,
        "allow_host_admin": False,
    },
    "tier2_workspace_edit": {
        "short": "L2",
        "restrict_to_workspace": True,
        "allow_edit": True,
        "allow_exec": False,
        "allow_host_admin": False,
    },
    "tier3_workspace_dev": {
        "short": "L3",
        "restrict_to_workspace": True,
        "allow_edit": True,
        "allow_exec": True,
        "allow_host_admin": False,
    },
    "tier4_full_power": {
        "short": "L4",
        "restrict_to_workspace": False,
        "allow_edit": True,
        "allow_exec": True,
        "allow_host_admin": True,
    },
}
DEFAULT_TIER = "tier3_workspace_dev"

_TIER_ALIASES: Dict[str, str] = {
    "1": "tier1_readonly",
    "l1": "tier1_readonly",
    "readonly": "tier1_readonly",
    "tier1": "tier1_readonly",
    "tier1_readonly": "tier1_readonly",
    "2": "tier2_workspace_edit",
    "l2": "tier2_workspace_edit",
    "edit": "tier2_workspace_edit",
    "tier2": "tier2_workspace_edit",
    "tier2_workspace_edit": "tier2_workspace_edit",
    "3": "tier3_workspace_dev",
    "l3": "tier3_workspace_dev",
    "dev": "tier3_workspace_dev",
    "standard": "tier3_workspace_dev",
    "tier3": "tier3_workspace_dev",
    "tier3_workspace_dev": "tier3_workspace_dev",
    "4": "tier4_full_power",
    "l4": "tier4_full_power",
    "full": "tier4_full_power",
    "max": "tier4_full_power",
    "agent": "tier4_full_power",
    "tier4": "tier4_full_power",
    "tier4_full_agent": "tier4_full_power",
    "tier4_full_access": "tier4_full_power",
    "tier4_full_power": "tier4_full_power",
}

DEFAULT_TOOLSET_PROFILE = "standard"

DEFAULT_CORE_TOOLS: Tuple[str, ...] = (
    "get_status",
    "find_files",
    "search_code",
    "code_intel",
    "read_file",
    "edit_file",
    "write_file",
    "manage_files",
    "run_command",
    "run_python",
    "bg_command",
    "batch_probe",
    "web_research",
    "workspace_memory",
    "skill_hub",
    "skill_manage",
)

# Mixed tools that expose strictly read-only query sub-actions under `L1` (`tier1_readonly`) and `/mcp/readonly`
MIXED_TOOL_READONLY_ACTIONS: Dict[str, Tuple[str, ...]] = {
    "code_intel": ("outline", "overview", "repo_map", "symbol", "refs", "diagnostics"),
    "manage_files": ("list",),
    "undo_or_trash": ("list",),
    "restore_trash": ("list",),
    "bg_command": ("status", "list"),
    "workspace_memory": ("read", "search"),
    "skill_manage": ("list", "trash_list"),
}

MIXED_TOOL_DEFAULT_ACTIONS: Dict[str, str] = {
    "code_intel": "outline",
    "manage_files": "list",
    "undo_or_trash": "undo",
    "restore_trash": "list",
    "bg_command": "list",
    "workspace_memory": "read",
    "skill_manage": "list",
}


def resolve_mixed_tool_effective_action(
    base_name: str,
    arguments: Optional[Dict[str, Any]] = None,
    action_param: str = "action",
) -> str:
    """Resolve effective sub-action for mixed read/write tools (preventing `bg_command(action='list', command=...)` promotion)."""
    args = arguments or {}
    raw = str(args.get(action_param) or "").strip().lower()
    if base_name == "bg_command":
        cmd = str(args.get("command") or args.get("cmd") or "").strip()
        jid = str(args.get("job_id") or "").strip()
        if (not raw or raw == "list") and cmd and not jid:
            return "start"
        return raw or "list"
    return raw or MIXED_TOOL_DEFAULT_ACTIONS.get(base_name, "")


def is_mixed_tool_readonly_action(
    base_name: str,
    arguments: Optional[Dict[str, Any]] = None,
    action_param: str = "action",
) -> Tuple[bool, str]:
    """Return `(is_readonly_action, effective_action)` for mixed tools in `MIXED_TOOL_READONLY_ACTIONS`."""
    ro_actions = MIXED_TOOL_READONLY_ACTIONS.get(base_name)
    if not ro_actions:
        return False, ""
    eff_act = resolve_mixed_tool_effective_action(base_name, arguments, action_param=action_param)
    return eff_act in ro_actions, eff_act


TOOLSET_PROFILES: Dict[str, Tuple[str, ...]] = {
    "standard": DEFAULT_CORE_TOOLS,
    "minimal": (
        "get_status",
        "find_files",
        "search_code",
        "read_file",
        "edit_file",
        "run_command",
        "bg_command",
    ),
}

_TOOLSET_ALIASES: Dict[str, str] = {
    "standard": "standard",
    "default": "standard",
    "recommended": "standard",
    "core": "standard",
    "core_12": "standard",
    "core_16": "standard",
    "full": "standard",
    "all": "standard",
    "symbol": "standard",
    "hybrid": "standard",
    "minimal": "minimal",
    "lean": "minimal",
    "compact": "minimal",
}

TOOLSET_PUBLIC_LABELS_ZH: Dict[str, str] = {
    "standard": "标准开发工具组（standard · 默认完整核心工具）",
    "minimal": "精简核心工具组（minimal · 7 项基础工具）",
}

PROMPT_PROFILES: Tuple[str, ...] = ("lean", "minimal", "workflow", "detailed")
DEFAULT_PROMPT_PROFILE = "lean"
_PROMPT_ALIASES: Dict[str, str] = {
    "lean": "lean",
    "lean_nudge": "lean",
    "minimal": "minimal",
    "workflow": "workflow",
    "detailed": "detailed",
    "nudge": "detailed",
    "per_tool_nudge": "detailed",
}

OPTIONAL_PACK_SPECS: Dict[str, Tuple[str, ...]] = {
    "browser": ("browser_use",),
    "cua": ("cua_window",),
}
_PACK_ALIASES: Dict[str, str] = {
    "browser": "browser",
    "browser_use": "browser",
    "playwright": "browser",
    "cua": "cua",
    "cua_window": "cua",
    "desktop": "cua",
    "desktop_window": "cua",
    "gui": "cua",
}


def parse_bool_flag(val: Any, default: bool = False) -> bool:
    if isinstance(val, bool):
        return val
    if val is None:
        return default
    s = str(val).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    return default


def parse_strict_annotation_mode(raw: Any) -> str:
    if isinstance(raw, bool):
        return "strict" if raw else "seamless"
    s = str(raw or "").strip().lower()
    if s in ("seamless", "compat", "auto", "zero_popup", "silent"):
        return "seamless"
    if s in ("strict", "honest", "confirm", "prompt", "popups"):
        return "strict"
    raise ValueError(f"Unknown annotation_mode `{raw}` (expected 'seamless' or 'strict').")


def normalize_annotation_mode(
    raw: Any = None,
    *,
    approval_popups: Optional[bool] = None,
    default: str = DEFAULT_ANNOTATION_MODE,
) -> str:
    if raw is not None and str(raw).strip() != "":
        try:
            return parse_strict_annotation_mode(raw)
        except ValueError:
            pass
    if approval_popups is not None:
        return "strict" if bool(approval_popups) else "seamless"
    return default if default in ANNOTATION_MODES else DEFAULT_ANNOTATION_MODE


def normalize_python_path(raw: Any) -> str:
    if raw is None:
        return ""
    cleaned = str(raw).replace("\r", "").replace("\n", "").strip().strip("\"'")
    if not cleaned or "\x00" in cleaned:
        return ""
    return expand_env_and_tilde(cleaned)


def normalize_prefix(raw: str) -> str:
    val = (raw or "").strip()
    if not val:
        return "pc"
    if not PREFIX_RE.fullmatch(val):
        raise ValueError(
            f"Invalid --prefix `{val}`: must match ^[a-z][a-z0-9_]{{0,15}}$ (e.g. pc, desk, laptop, vps)."
        )
    return val


def _resolve_safe_tool_prefix(raw: Any, fallback: str = "pc") -> str:
    val = str(raw or "").strip()
    if val and PREFIX_RE.fullmatch(val):
        return val
    fb = str(fallback or "pc").strip()
    return fb if (fb and PREFIX_RE.fullmatch(fb)) else "pc"


def resolve_device_label(prefix: str, raw_label: str = "") -> str:
    lbl = (raw_label or "").strip()
    if lbl:
        return lbl
    eff_p = normalize_prefix(prefix)
    return "Cosmos-Desktop" if eff_p == "pc" else f"Cosmos-{eff_p}"


def parse_strict_tier(raw: str) -> str:
    t = (raw or "").strip().lower()
    mapped = _TIER_ALIASES.get(t, t)
    if mapped not in PERMISSION_TIERS:
        raise ValueError(
            f"Unknown permission tier `{raw}` (expected L1 / L2 / L3 / L4 or tier1_readonly..tier4_full_power)."
        )
    return mapped


def normalize_tier(raw: str, default: str = DEFAULT_TIER) -> str:
    """Return full canonical tier key (`tier1_readonly`..`tier4_full_power`); see `to_short_tier_code` for `L1`..`L4`."""
    t = (raw or "").strip().lower()
    if not t:
        return default
    mapped = _TIER_ALIASES.get(t, t)
    return mapped if mapped in PERMISSION_TIERS else default


def parse_strict_toolset_profile(raw: str) -> str:
    val = (raw or "").strip()
    mapped = _TOOLSET_ALIASES.get(val.lower(), val)
    if mapped not in TOOLSET_PROFILES:
        raise ValueError(
            f"Unknown toolset profile `{raw}` (expected standard, full, or minimal)."
        )
    return mapped


def normalize_toolset_profile(raw: str, default: str = DEFAULT_TOOLSET_PROFILE) -> str:
    val = (raw or "").strip()
    if not val:
        return default
    mapped = _TOOLSET_ALIASES.get(val.lower(), val)
    return mapped if mapped in TOOLSET_PROFILES else default


def parse_strict_prompt_profile(raw: str) -> str:
    val = (raw or "").strip()
    mapped = _PROMPT_ALIASES.get(val.lower(), val)
    if mapped not in PROMPT_PROFILES:
        raise ValueError(
            f"Unknown prompt profile `{raw}` (expected lean, minimal, workflow, or detailed)."
        )
    return mapped


def normalize_prompt_profile(raw: str, default: str = DEFAULT_PROMPT_PROFILE) -> str:
    val = (raw or "").strip()
    if not val:
        return default
    mapped = _PROMPT_ALIASES.get(val.lower(), val)
    return mapped if mapped in PROMPT_PROFILES else default


def parse_pack_spec(raw: Any, strict: bool = False) -> Tuple[str, ...]:
    if raw is None or raw == "":
        return ()
    tokens: List[str] = []
    if isinstance(raw, str):
        s = raw.strip()
        if not s or s.lower() in ("none", "clear", "off", "false", "[]"):
            return ()
        if s.startswith("["):
            try:
                arr = json.loads(s)
                if isinstance(arr, list):
                    tokens = [str(x).strip() for x in arr if str(x).strip()]
            except Exception:
                tokens = [x.strip() for x in s.split(",") if x.strip()]
        else:
            tokens = [x.strip() for x in s.split(",") if x.strip()]
    elif isinstance(raw, Iterable):
        tokens = [str(x).strip() for x in raw if str(x).strip()]

    out: List[str] = []
    for tok in tokens:
        low = tok.lower()
        if low in ("none", "clear", "off"):
            continue
        if low == "all":
            for pk in OPTIONAL_PACK_SPECS:
                if pk not in out:
                    out.append(pk)
            continue
        mapped = _PACK_ALIASES.get(low, "")
        if not mapped or mapped not in OPTIONAL_PACK_SPECS:
            if strict:
                raise ValueError(
                    f"Unknown capability pack `{tok}` (expected 'browser', 'desktop', or 'browser,desktop')."
                )
            continue
        if mapped not in out:
            out.append(mapped)
    return tuple(out)


def parse_tool_filter_spec(
    raw: Any,
    active_prefix: str = "pc",
    known_base_tools: Optional[Iterable[str]] = None,
    strict: bool = False,
) -> Tuple[str, ...]:
    if raw is None or raw == "":
        return ()
    tokens: List[str] = []
    if isinstance(raw, str):
        s = raw.strip()
        if not s or s.lower() in ("none", "clear", "[]"):
            return ()
        if s.startswith("["):
            try:
                arr = json.loads(s)
                if isinstance(arr, list):
                    tokens = [str(x).strip() for x in arr if str(x).strip()]
            except Exception:
                tokens = [x.strip() for x in s.split(",") if x.strip()]
        else:
            tokens = [x.strip() for x in s.split(",") if x.strip()]
    elif isinstance(raw, Iterable):
        tokens = [str(x).strip() for x in raw if str(x).strip()]

    eff_p = (active_prefix or "pc").strip() or "pc"
    known_set = set(known_base_tools) if known_base_tools is not None else None
    out: List[str] = []
    for tok in tokens:
        clean = tok.strip()
        if not clean:
            continue
        base = clean
        for pfx in (eff_p, "pc"):
            if pfx and base.startswith(f"{pfx}_"):
                cand = base[len(pfx) + 1 :]
                if known_set is None or cand in known_set:
                    base = cand
                    break
        if known_set is not None and base not in known_set:
            if strict:
                raise ValueError(f"Unknown tool `{tok}` in tool filter.")
            continue
        if base not in out:
            out.append(base)
    return tuple(out)


def resolve_service_cfg_path(state_root: Path, eff_prefix: str = "pc") -> Path:
    norm_p = normalize_prefix(eff_prefix)
    if norm_p != "pc":
        return state_root / "config" / f"service_{norm_p}.json"
    return state_root / "config" / "service.json"


def conn_info_filename_for_prefix(eff_prefix: str = "pc") -> str:
    norm_p = normalize_prefix(eff_prefix)
    return f"连接信息_CONNECTION_INFO_{norm_p}.txt" if norm_p != "pc" else "连接信息_CONNECTION_INFO.txt"


def _split_workspace_string(raw_s: str) -> List[str]:
    """Split serialized workspace roots via JSON array, newlines, or `os.pathsep` (never `,`, preserving comma directory names)."""
    s = raw_s.strip()
    if not s:
        return []
    if s.startswith("["):
        try:
            parsed = json.loads(s)
            if isinstance(parsed, list):
                return [str(x).strip() for x in parsed if str(x).strip()]
        except Exception:
            pass
    if "\n" in s:
        return [x.strip() for x in s.splitlines() if x.strip()]
    if os.pathsep in s:
        if os.pathsep == ":" and re.match(r"^[A-Za-z]:[\\/]", s) and s.count(":") == 1:
            return [s]
        return [x.strip() for x in s.split(os.pathsep) if x.strip()]
    return [s]


def normalize_workspace_roots(
    workspace_roots: Any = None,
    legacy_workspace: str = "",
    *,
    create_missing: bool = True,
) -> Tuple[Path, ...]:
    """Normalize multi-directory `workspace_roots` with seamless single `workspace` fallback (preserving commas in folder names)."""
    candidates: List[str] = []
    if workspace_roots is not None:
        if isinstance(workspace_roots, Path):
            raw_p = str(workspace_roots).strip()
            if raw_p:
                candidates.append(raw_p)
        elif isinstance(workspace_roots, str):
            candidates.extend(_split_workspace_string(workspace_roots))
        elif isinstance(workspace_roots, Iterable):
            for item in workspace_roots:
                s = str(item or "").strip()
                if s:
                    candidates.append(s)

    if legacy_workspace and str(legacy_workspace).strip():
        lw = str(legacy_workspace).strip()
        if lw not in candidates:
            candidates.insert(0, lw)

    if not candidates:
        default_dir = (Path.home() / "CosmosWorkspace").resolve()
        legacy_default_dir = (Path.home() / "LocalPCWorkspace").resolve()
        chosen_default = legacy_default_dir if (legacy_default_dir.is_dir() and not default_dir.exists()) else default_dir
        if create_missing:
            chosen_default.mkdir(parents=True, exist_ok=True)
        return (chosen_default,)

    resolved_list: List[Path] = []
    seen_norm: set[str] = set()
    for raw_item in candidates:
        cleaned = raw_item.replace("\r", "").replace("\n", "").strip().strip("\"'")
        if not cleaned or "\x00" in cleaned:
            continue
        exp = expand_env_and_tilde(cleaned)
        p = Path(exp).expanduser().resolve()
        if create_missing:
            p.mkdir(parents=True, exist_ok=True)
        nk = os.path.normcase(str(p))
        if nk not in seen_norm:
            seen_norm.add(nk)
            resolved_list.append(p)

    if not resolved_list:
        fallback = (Path.home() / "CosmosWorkspace").resolve()
        if create_missing:
            fallback.mkdir(parents=True, exist_ok=True)
        return (fallback,)
    return tuple(resolved_list)


def normalize_readonly_workspace_roots(
    readonly_roots: Any,
    active_roots: Sequence[Path],
    *,
    strict: bool = False,
) -> Tuple[Path, ...]:
    """Filter `readonly_roots` against mounted `active_roots` (allowing single or primary root to stay read-only).

    When `strict=True`, invalid container types, NUL-containing entries, or paths outside `active_roots`
    raise `ValueError` instead of being silently dropped.
    """
    if readonly_roots is None:
        return ()
    raw_items: List[str] = []
    if isinstance(readonly_roots, Path):
        s = str(readonly_roots).strip()
        if s:
            raw_items.append(s)
    elif isinstance(readonly_roots, str):
        if strict and "\x00" in readonly_roots:
            raise ValueError("Invalid readonly_workspace_roots: path contains NUL byte.")
        raw_items.extend(_split_workspace_string(readonly_roots))
    elif isinstance(readonly_roots, (bytes, bytearray, Mapping)):
        if strict:
            raise ValueError(f"Invalid readonly_workspace_roots type: {type(readonly_roots).__name__}.")
        return ()
    elif isinstance(readonly_roots, Iterable):
        for it in readonly_roots:
            if strict and not isinstance(it, (str, Path)):
                raise ValueError(f"Invalid readonly_workspace_roots entry type: {type(it).__name__}.")
            s = str(it or "").strip()
            if s:
                raw_items.append(s)
    else:
        if strict:
            raise ValueError(f"Invalid readonly_workspace_roots type: {type(readonly_roots).__name__}.")
        return ()
    if not raw_items:
        return ()
    if not active_roots:
        if strict:
            raise ValueError("readonly_workspace_roots requires at least one mounted workspace root.")
        return ()
    act_map = {os.path.normcase(str(p.resolve())): p for p in active_roots}
    out: List[Path] = []
    seen: set[str] = set()
    for raw_it in raw_items:
        if strict and "\x00" in raw_it:
            raise ValueError(f"Invalid readonly_workspace_roots entry `{raw_it!r}`: contains NUL byte.")
        cleaned = raw_it.replace("\r", "").replace("\n", "").strip().strip("\"'")
        if not cleaned or "\x00" in cleaned:
            if strict:
                raise ValueError(f"Invalid readonly_workspace_roots entry `{raw_it!r}`.")
            continue
        nk = os.path.normcase(str(Path(expand_env_and_tilde(cleaned)).expanduser().resolve()))
        if nk not in act_map:
            if strict:
                raise ValueError(
                    f"readonly_workspace_roots entry `{raw_it}` is not among mounted workspace_roots."
                )
            continue
        if nk not in seen:
            seen.add(nk)
            out.append(act_map[nk])
    return tuple(out)


def record_known_workspaces(state_root: Path, roots: Iterable[Path | str]) -> None:
    try:
        st_dir = state_root / "state"
        st_dir.mkdir(parents=True, exist_ok=True)
        kw_file = st_dir / "known_workspaces.json"
        items: List[str] = []
        if kw_file.is_file():
            try:
                raw_items = json.loads(kw_file.read_text(encoding="utf-8-sig"))
                if isinstance(raw_items, list):
                    items = [str(x) for x in raw_items if isinstance(x, str) and x.strip()]
            except Exception:
                items = []
        norm_set = {os.path.normcase(x) for x in items}
        changed = False
        for r in roots:
            rs = str(Path(r).expanduser().resolve())
            nk = os.path.normcase(rs)
            if nk not in norm_set:
                norm_set.add(nk)
                items.append(rs)
                changed = True
        if changed:
            atomic_write_text(kw_file, json.dumps(items[-100:], ensure_ascii=False, indent=2) + "\n")
    except Exception:
        pass


_CODE_EXACT_MARKERS: Dict[str, str] = {
    ".git": ".git",
    "pyproject.toml": "pyproject.toml",
    "package.json": "package.json",
    "cargo.toml": "Cargo.toml",
    "go.mod": "go.mod",
    "pom.xml": "pom.xml",
}
_SKIP_SCAN_SUBDIRS: frozenset[str] = frozenset({
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    "$recycle.bin",
    "system volume information",
})


def _scan_dir_markers_and_children(dir_path: Path, *, max_entries: int = 320) -> Optional[Tuple[List[str], List[Path]]]:
    """Single-pass `os.scandir` returning `(markers, child_dirs)` or `None` if inaccessible."""
    markers: List[str] = []
    subdirs: List[Path] = []
    saw_sln = False
    try:
        with os.scandir(dir_path) as it:
            for idx, entry in enumerate(it):
                if idx >= max_entries:
                    break
                nm = entry.name
                nm_low = nm.lower()
                if nm_low in _CODE_EXACT_MARKERS:
                    canon_m = _CODE_EXACT_MARKERS[nm_low]
                    if canon_m not in markers:
                        markers.append(canon_m)
                elif not saw_sln and nm_low.endswith(".sln"):
                    saw_sln = True
                    markers.append(".sln")
                if nm.startswith(".") or nm_low in _SKIP_SCAN_SUBDIRS:
                    continue
                try:
                    if entry.is_dir(follow_symlinks=False):
                        subdirs.append(Path(entry.path))
                except OSError:
                    continue
    except OSError:
        return None
    subdirs.sort(key=lambda p: p.name.lower())
    return markers, subdirs


def discover_common_code_directories(
    home_dir: Optional[Path] = None,
    state_root: Optional[Path] = None,
    max_results: int = 24,
) -> List[Dict[str, Any]]:
    """
    Fast read-only stdlib scanner (depth <= 2, <150ms budget) discovering common code parent folders,
    Git repositories, and project directories without raising on permission-denied directories.
    """
    cap = max(1, int(max_results))
    deadline = time.monotonic() + 0.12
    eff_home = Path(home_dir).expanduser() if home_dir is not None else Path.home()

    seed_dirs: List[Path] = []
    if state_root is not None:
        kw_file = Path(state_root) / "state" / "known_workspaces.json"
        if kw_file.is_file():
            try:
                raw_kw = json.loads(kw_file.read_text(encoding="utf-8-sig"))
                if isinstance(raw_kw, list):
                    for item in raw_kw:
                        if isinstance(item, str) and item.strip():
                            seed_dirs.append(Path(item.strip()).expanduser())
            except Exception:
                pass

    for rel_home in (
        ("Projects",),
        ("Repos",),
        ("Code",),
        ("workspace",),
        ("Documents", "GitHub"),
    ):
        seed_dirs.append(eff_home.joinpath(*rel_home))

    if sys.platform == "win32":
        for drv in ("C", "D", "E", "F", "G"):
            drv_root = Path(f"{drv}:\\")
            try:
                if not drv_root.exists():
                    continue
            except OSError:
                continue
            for rel_drv in (
                ("Projects",),
                ("GIT",),
                ("Git",),
                ("code",),
                ("program", "GIT"),
            ):
                seed_dirs.append(drv_root.joinpath(*rel_drv))

    results: List[Dict[str, Any]] = []
    seen_keys: set[str] = set()
    inspected_cache: Dict[str, Optional[Tuple[List[str], List[Path]]]] = {}

    def _cached_inspect(p: Path) -> Optional[Tuple[List[str], List[Path]]]:
        k = os.path.normcase(os.path.abspath(str(p)))
        if k not in inspected_cache:
            inspected_cache[k] = _scan_dir_markers_and_children(p)
        return inspected_cache[k]

    def _emit_entry(p: Path, kind: str, markers: List[str], child_repo_count: int) -> None:
        if len(results) >= cap:
            return
        try:
            norm_p = os.path.abspath(str(p))
        except OSError:
            norm_p = str(p)
        nk = os.path.normcase(norm_p.rstrip("\\/"))
        if not nk or nk in seen_keys:
            return
        seen_keys.add(nk)
        results.append(
            {
                "path": norm_p,
                "name": Path(norm_p).name or norm_p,
                "kind": kind,
                "markers": list(markers),
                "child_repo_count": int(child_repo_count),
            }
        )

    for seed in seed_dirs:
        if len(results) >= cap or time.monotonic() >= deadline:
            break
        lvl0 = _cached_inspect(seed)
        if lvl0 is None:
            continue
        m0, children1 = lvl0
        d1_repo_entries: List[Tuple[Path, str, List[str], int]] = []
        d2_repo_entries: List[Tuple[Path, str, List[str], int]] = []

        for ch1 in children1[:48]:
            if time.monotonic() >= deadline:
                break
            lvl1 = _cached_inspect(ch1)
            if lvl1 is None:
                continue
            m1, children2 = lvl1
            ch1_child_repos = 0
            for ch2 in children2[:24]:
                if time.monotonic() >= deadline:
                    break
                lvl2 = _cached_inspect(ch2)
                if lvl2 is None:
                    continue
                m2, _ = lvl2
                if m2:
                    ch1_child_repos += 1
                    k2 = "git_repo" if ".git" in m2 else "project"
                    d2_repo_entries.append((ch2, k2, m2, 0))
            if m1:
                k1 = "git_repo" if ".git" in m1 else "project"
                d1_repo_entries.append((ch1, k1, m1, ch1_child_repos))
            elif ch1_child_repos > 0:
                d1_repo_entries.append((ch1, "code_parent", [], ch1_child_repos))

        seed_child_repos = sum(1 for _, k, _, _ in d1_repo_entries if k in ("git_repo", "project"))
        if m0:
            k0 = "git_repo" if ".git" in m0 else "project"
            _emit_entry(seed, k0, m0, seed_child_repos)
        elif seed_child_repos > 0 or d1_repo_entries:
            _emit_entry(seed, "code_parent", [], seed_child_repos or len(d1_repo_entries))

        for ep, ek, em, ec in d1_repo_entries:
            if len(results) >= cap:
                break
            _emit_entry(ep, ek, em, ec)
        for ep, ek, em, ec in d2_repo_entries:
            if len(results) >= cap:
                break
            _emit_entry(ep, ek, em, ec)

    return results


def emit_kill_signal(
    state_root: Path,
    reason: str = "manual_stop",
    prefix_filter: str = "",
) -> Dict[str, Any]:
    """Write an atomic `state/kill_signal.json` frame detected within <=0.1s by active server watchdogs."""
    sig_file = Path(state_root) / "state" / "kill_signal.json"
    payload: Dict[str, Any] = {
        "ts": time.time(),
        "ts_ns": time.time_ns(),
        "reason": str(reason or "manual_stop"),
        "prefix_filter": str(prefix_filter or "").strip(),
        "emitter_pid": os.getpid(),
    }
    atomic_write_json(sig_file, payload)
    return payload


def read_kill_signal(state_root: Path) -> Optional[Dict[str, Any]]:
    sig_file = Path(state_root) / "state" / "kill_signal.json"
    if not sig_file.is_file():
        return None
    try:
        doc = json.loads(sig_file.read_text(encoding="utf-8-sig"))
        return doc if isinstance(doc, dict) else None
    except Exception:
        return None


class KillSignalWatchdog:
    """Polls `state/kill_signal.json` every <=0.1s (default 0.08s) and fires registered emergency stop callbacks."""

    def __init__(
        self,
        state_root: Path,
        eff_prefix: str = "pc",
        *,
        poll_interval_sec: float = 0.08,
        policy: Optional["LiveRuntimePolicy"] = None,
        on_kill_callbacks: Optional[Sequence[Callable[[Dict[str, Any]], None]]] = None,
        ignore_same_pid: bool = False,
    ) -> None:
        self.state_root = Path(state_root)
        self.eff_prefix = normalize_prefix(eff_prefix)
        self.poll_interval_sec = max(0.02, min(0.1, float(poll_interval_sec)))
        self.policy = policy
        self.ignore_same_pid = ignore_same_pid
        self._callbacks: List[Callable[[Dict[str, Any]], None]] = list(on_kill_callbacks or [])
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        sig_file = self.state_root / "state" / "kill_signal.json"
        init_doc = read_kill_signal(self.state_root)
        self._last_ts_ns = int((init_doc or {}).get("ts_ns") or 0)
        self._last_mtime_ns = sig_file.stat().st_mtime_ns if sig_file.is_file() else 0
        self.triggered_count = 0

    def add_callback(self, fn: Callable[[Dict[str, Any]], None]) -> None:
        if fn not in self._callbacks:
            self._callbacks.append(fn)

    def poll_once(self) -> bool:
        if self.policy is not None:
            self.policy.refresh()
        sig_file = self.state_root / "state" / "kill_signal.json"
        if not sig_file.is_file():
            return False
        try:
            cur_mtime = sig_file.stat().st_mtime_ns
        except OSError:
            return False
        if cur_mtime == self._last_mtime_ns:
            doc = read_kill_signal(self.state_root)
            if not doc or int(doc.get("ts_ns") or 0) <= self._last_ts_ns:
                return False
        else:
            self._last_mtime_ns = cur_mtime
            doc = read_kill_signal(self.state_root)
            if not doc:
                return False
        ts_ns = int(doc.get("ts_ns") or 0)
        if ts_ns <= self._last_ts_ns:
            return False
        self._last_ts_ns = ts_ns
        p_filt = str(doc.get("prefix_filter") or "").strip()
        if p_filt and p_filt != self.eff_prefix:
            return False
        if self.ignore_same_pid and int(doc.get("emitter_pid") or 0) == os.getpid():
            return False
        self.triggered_count += 1
        for cb in list(self._callbacks):
            try:
                cb(doc)
            except Exception:
                pass
        return True

    def start(self) -> threading.Thread:
        if self._thread is not None and self._thread.is_alive():
            return self._thread
        self._stop_event.clear()

        def _loop() -> None:
            while not self._stop_event.wait(self.poll_interval_sec):
                try:
                    self.poll_once()
                except Exception:
                    pass

        th = threading.Thread(target=_loop, name=f"cosmos-kill-watchdog-{self.eff_prefix}", daemon=True)
        th.start()
        self._thread = th
        return th

    def stop(self, timeout: float = 1.0) -> None:
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)


PACK_DISPLAY_ZH: Dict[str, str] = {
    "browser": "受管浏览器",
    "browser_use": "受管浏览器",
    "cua": "桌面窗口感知",
    "cua_window": "桌面窗口感知",
    "desktop": "桌面窗口感知",
    "desktop_window": "桌面窗口感知",
}


def format_pack_labels_zh(enabled_packs: Iterable[str] = ()) -> List[str]:
    seen: List[str] = []
    for raw in enabled_packs:
        key = str(raw or "").strip()
        if not key:
            continue
        lbl = PACK_DISPLAY_ZH.get(key, key)
        if lbl not in seen:
            seen.append(lbl)
    return seen


def format_dynamic_tier_label(
    tier_key: str,
    *,
    tool_count: Optional[int] = None,
    enabled_packs: Iterable[str] = (),
    approval_popups: bool = False,
    annotation_mode: str = "",
    keep_awake: bool = False,
) -> str:
    t_norm = normalize_tier(tier_key)
    eff_strict = normalize_annotation_mode(annotation_mode, approval_popups=approval_popups) == "strict"
    cnt_part = f"，{tool_count} 个工具" if tool_count is not None else ""
    pack_labels = format_pack_labels_zh(enabled_packs)
    pack_part = f"，已开启扩展包：{'、'.join(pack_labels)}" if pack_labels else ""
    awake_part = "，防休眠开启" if keep_awake else ""
    if t_norm == "tier1_readonly":
        return f"L1 只读浏览模式（仅白名单工作区内只读查看与检索{cnt_part}{awake_part}）"
    if t_norm == "tier2_workspace_edit":
        return f"L2 仅修改文件（禁运行命令）（白名单工作区内读写修改与回收站保护，禁命令执行{cnt_part}{awake_part}）"
    if t_norm == "tier3_workspace_dev":
        mode_s = "写/执行确认" if eff_strict else "免弹窗执行"
        return f"L3 工作区内顺畅开发（白名单目录隔离 + 读写修改 + 回收站保护 + 命令/Python {mode_s}{pack_part}{cnt_part}{awake_part}）"
    mode_l4 = "已开启确认弹窗" if eff_strict else "免弹窗执行"
    return f"L4 全盘顺畅开发（不限目录）（跨目录读写与代码执行·{mode_l4}，保留回收站与密钥隔离{pack_part}{cnt_part}{awake_part}）"


WIPED_PASSWORD_PLACEHOLDER_ZH = "(已受本机加密保险箱保护，请在本地控制台按需查看或重置)"
ENDPOINT_SECRET_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
ENDPOINT_SECRET_RE = re.compile(r"^[a-z0-9]{24}$")
_VALID_ENDPOINT_SECRET_RE = re.compile(r"^[a-z0-9]{16,64}$")
_EP_SECRET_CACHE_LOCK = threading.Lock()
_EP_SECRET_CACHE: Dict[str, Tuple[int, int, str]] = {}


def generate_readable_password(length: int = 20) -> str:
    eff_len = max(16, int(length))
    if eff_len == 20:
        return "-".join("".join(secrets.choice(UNAMBIGUOUS_PW_ALPHABET) for _ in range(5)) for _ in range(4))
    if eff_len == 24:
        return "-".join("".join(secrets.choice(UNAMBIGUOUS_PW_ALPHABET) for _ in range(6)) for _ in range(4))
    raw_chars = "".join(secrets.choice(UNAMBIGUOUS_PW_ALPHABET) for _ in range(eff_len))
    return "-".join(raw_chars[idx : idx + 5] for idx in range(0, eff_len, 5))


def dpapi_connection_vault_path(state_root: Path, prefix: str = "pc") -> Path:
    eff_p = normalize_prefix(prefix)
    fname = f"connection_{eff_p}.dpapi" if eff_p != "pc" else "connection.dpapi"
    return Path(state_root) / "secrets" / fname


def enc_connection_vault_path(state_root: Path, prefix: str = "pc") -> Path:
    eff_p = normalize_prefix(prefix)
    fname = f"connection_{eff_p}.enc" if eff_p != "pc" else "connection.enc"
    return Path(state_root) / "secrets" / fname


def plaintext_wiped_flag_path(state_root: Path, prefix: str = "pc") -> Path:
    eff_p = normalize_prefix(prefix)
    fname = f"plaintext_pw_wiped_{eff_p}.flag" if eff_p != "pc" else "plaintext_pw_wiped.flag"
    return Path(state_root) / "secrets" / fname


def _dpapi_protect_bytes(plain_bytes: bytes, entropy_bytes: bytes = b"") -> bytes:
    """Encrypt `plain_bytes` with Windows `CryptProtectData` (`CRYPTPROTECT_UI_FORBIDDEN = 0x1`, 64-bit safe)."""
    if sys.platform != "win32":
        raise OSError("Windows DPAPI is only available on win32")
    from ctypes import wintypes

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),
        wintypes.LPCWSTR,
        ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DATA_BLOB),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL

    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    in_buf = ctypes.create_string_buffer(plain_bytes, len(plain_bytes))
    in_blob = _DATA_BLOB(len(plain_bytes), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_char)))

    ent_buf = ctypes.create_string_buffer(entropy_bytes, len(entropy_bytes)) if entropy_bytes else None
    ent_blob = (
        _DATA_BLOB(len(entropy_bytes), ctypes.cast(ent_buf, ctypes.POINTER(ctypes.c_char)))
        if ent_buf is not None
        else None
    )
    out_blob = _DATA_BLOB(0, None)
    CRYPTPROTECT_UI_FORBIDDEN = 0x1

    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "CosmosMCP-ConnectionPassword",
        ctypes.byref(ent_blob) if ent_blob is not None else None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        err_code = ctypes.get_last_error()
        raise OSError(err_code, f"CryptProtectData failed with error {err_code}")
    try:
        return ctypes.string_at(out_blob.pbData, int(out_blob.cbData)) if out_blob.cbData else b""
    finally:
        if out_blob.pbData:
            kernel32.LocalFree(ctypes.cast(out_blob.pbData, wintypes.HLOCAL))


def _dpapi_unprotect_bytes(cipher_bytes: bytes, entropy_bytes: bytes = b"") -> bytes:
    """Decrypt `cipher_bytes` with Windows `CryptUnprotectData` (`CRYPTPROTECT_UI_FORBIDDEN = 0x1`, 64-bit safe)."""
    if sys.platform != "win32":
        raise OSError("Windows DPAPI is only available on win32")
    if not cipher_bytes:
        raise ValueError("Empty DPAPI ciphertext")
    from ctypes import wintypes

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p,
        ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DATA_BLOB),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL

    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    in_buf = ctypes.create_string_buffer(cipher_bytes, len(cipher_bytes))
    in_blob = _DATA_BLOB(len(cipher_bytes), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_char)))

    ent_buf = ctypes.create_string_buffer(entropy_bytes, len(entropy_bytes)) if entropy_bytes else None
    ent_blob = (
        _DATA_BLOB(len(entropy_bytes), ctypes.cast(ent_buf, ctypes.POINTER(ctypes.c_char)))
        if ent_buf is not None
        else None
    )
    out_blob = _DATA_BLOB(0, None)
    CRYPTPROTECT_UI_FORBIDDEN = 0x1

    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(ent_blob) if ent_blob is not None else None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        err_code = ctypes.get_last_error()
        raise OSError(err_code, f"CryptUnprotectData failed with error {err_code}")
    try:
        return ctypes.string_at(out_blob.pbData, int(out_blob.cbData)) if out_blob.cbData else b""
    finally:
        if out_blob.pbData:
            kernel32.LocalFree(ctypes.cast(out_blob.pbData, wintypes.HLOCAL))


def _load_or_create_local_vault_key(secrets_dir: Path, eff_prefix: str = "pc") -> bytes:
    """Resolve 32-byte key material for pure-stdlib encrypted vault (`master_seed*.bin` or `local_vault.key`)."""
    secrets_dir.mkdir(parents=True, exist_ok=True)
    apply_current_user_only_acl(secrets_dir)
    cands = []
    if eff_prefix != "pc":
        cands.append(secrets_dir / f"master_seed_{eff_prefix}.bin")
    cands.append(secrets_dir / "master_seed.bin")
    for bp in cands:
        if bp.is_file():
            try:
                raw_b = bp.read_bytes()
                if len(raw_b) == 32:
                    return raw_b
            except OSError:
                pass
    seed_hex_p = secrets_dir / "master_seed"
    if seed_hex_p.is_file():
        try:
            raw_h = seed_hex_p.read_text(encoding="utf-8").strip()
            if len(raw_h) >= 64:
                return bytes.fromhex(raw_h[:64])
        except Exception:
            pass
    vault_k_p = secrets_dir / "local_vault.key"
    if vault_k_p.is_file():
        try:
            kb = vault_k_p.read_bytes()
            if len(kb) == 32:
                return kb
            if len(kb) >= 64:
                return bytes.fromhex(kb.decode("ascii", errors="ignore").strip()[:64])
        except Exception:
            pass
    fresh_k = secrets.token_bytes(32)
    atomic_write_text(vault_k_p, fresh_k.hex() + "\n", mode_override=0o600)
    apply_current_user_only_acl(vault_k_p)
    return fresh_k


def _vault_ctr_stream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hmac.new(enc_key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest())
        counter += 1
    return bytes(out[:length])


def _stdlib_vault_encrypt(plain_text: str, key_bytes: bytes, aad_str: str) -> Dict[str, Any]:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", key_bytes, salt, 60000, dklen=64)
    enc_key, mac_key = dk[:32], dk[32:]
    pt_bytes = plain_text.encode("utf-8")
    ks = _vault_ctr_stream(enc_key, nonce, len(pt_bytes))
    ct = bytes(a ^ b for a, b in zip(pt_bytes, ks))
    aad_b = aad_str.encode("utf-8")
    mac = hmac.new(mac_key, aad_b + salt + nonce + ct, hashlib.sha256).hexdigest()
    return {
        "v": 1,
        "alg": "pbkdf2-hmac-ctr-sha256",
        "salt": base64.urlsafe_b64encode(salt).decode("ascii").rstrip("="),
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("="),
        "ct": base64.urlsafe_b64encode(ct).decode("ascii").rstrip("="),
        "tag": mac,
    }


def _stdlib_vault_decrypt(doc: Mapping[str, Any], key_bytes: bytes, aad_str: str) -> str:
    def _b64d(val: str) -> bytes:
        s = str(val or "").strip()
        pad = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s + pad)

    salt = _b64d(str(doc.get("salt") or ""))
    nonce = _b64d(str(doc.get("nonce") or ""))
    ct = _b64d(str(doc.get("ct") or ""))
    tag = str(doc.get("tag") or "").strip()
    if len(salt) != 16 or len(nonce) != 16 or not tag:
        raise ValueError("Invalid vault envelope")
    dk = hashlib.pbkdf2_hmac("sha256", key_bytes, salt, 60000, dklen=64)
    enc_key, mac_key = dk[:32], dk[32:]
    aad_b = aad_str.encode("utf-8")
    exp_tag = hmac.new(mac_key, aad_b + salt + nonce + ct, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(tag, exp_tag):
        raise ValueError("Vault authentication tag mismatch")
    ks = _vault_ctr_stream(enc_key, nonce, len(ct))
    pt_bytes = bytes(a ^ b for a, b in zip(ct, ks))
    return pt_bytes.decode("utf-8")


def save_encrypted_connection_password(
    state_root: Union[str, Path],
    password_plain: str,
    prefix: str = "pc",
    *,
    force_stdlib_enc: bool = False,
) -> Path:
    """Persist `password_plain` in OS-bound DPAPI (`connection.dpapi`) on Windows or stdlib AEAD (`connection.enc`)."""
    clean_pw = str(password_plain or "").strip()
    if not clean_pw or clean_pw.startswith("("):
        raise ValueError("Refusing to store empty or placeholder password in encrypted vault")
    st_root = Path(state_root).expanduser().resolve()
    eff_p = normalize_prefix(prefix)
    sec_dir = st_root / "secrets"
    sec_dir.mkdir(parents=True, exist_ok=True)
    apply_current_user_only_acl(sec_dir)

    entropy = f"cosmos-mcp:connection-password:v1:{eff_p}".encode("utf-8")
    if sys.platform == "win32" and not force_stdlib_enc:
        try:
            ct_bytes = _dpapi_protect_bytes(clean_pw.encode("utf-8"), entropy)
            dpapi_p = dpapi_connection_vault_path(st_root, eff_p)
            env_doc = {
                "v": 1,
                "alg": "win32-dpapi",
                "ct": base64.b64encode(ct_bytes).decode("ascii"),
            }
            atomic_write_json(dpapi_p, env_doc, mode_override=0o600)
            apply_current_user_only_acl(dpapi_p)
            return dpapi_p
        except Exception:
            pass

    key_b = _load_or_create_local_vault_key(sec_dir, eff_prefix=eff_p)
    enc_p = enc_connection_vault_path(st_root, eff_p)
    aad = f"cosmos-vault-v1:{eff_p}"
    enc_doc = _stdlib_vault_encrypt(clean_pw, key_b, aad)
    atomic_write_json(enc_p, enc_doc, mode_override=0o600)
    apply_current_user_only_acl(enc_p)
    return enc_p


def load_encrypted_connection_password(state_root: Union[str, Path], prefix: str = "pc") -> str:
    """Decrypt and return the stored owner connection password from `connection.dpapi` or `connection.enc`."""
    st_root = Path(state_root).expanduser().resolve()
    eff_p = normalize_prefix(prefix)
    sec_dir = st_root / "secrets"
    entropy = f"cosmos-mcp:connection-password:v1:{eff_p}".encode("utf-8")

    if sys.platform == "win32":
        for cand_p, cand_ent in (
            (dpapi_connection_vault_path(st_root, eff_p), entropy),
            (dpapi_connection_vault_path(st_root, "pc"), b"cosmos-mcp:connection-password:v1:pc"),
        ):
            if cand_p != dpapi_connection_vault_path(st_root, eff_p) and eff_p != "pc":
                continue
            if cand_p.is_file():
                try:
                    raw_b = cand_p.read_bytes()
                    ct_b = raw_b
                    if raw_b.lstrip().startswith(b"{"):
                        parsed = json.loads(raw_b.decode("utf-8"))
                        if isinstance(parsed, dict) and parsed.get("ct"):
                            ct_b = base64.b64decode(str(parsed["ct"]))
                    pt = _dpapi_unprotect_bytes(ct_b, cand_ent).decode("utf-8").strip()
                    if pt and not pt.startswith("("):
                        return pt
                except Exception:
                    pass

    enc_p = enc_connection_vault_path(st_root, eff_p)
    if enc_p.is_file():
        try:
            doc = json.loads(enc_p.read_text(encoding="utf-8"))
            if isinstance(doc, Mapping):
                key_b = _load_or_create_local_vault_key(sec_dir, eff_prefix=eff_p)
                pt = _stdlib_vault_decrypt(doc, key_b, f"cosmos-vault-v1:{eff_p}").strip()
                if pt and not pt.startswith("("):
                    return pt
        except Exception:
            pass
    return ""


def is_plaintext_connection_password_wiped(state_root: Union[str, Path], prefix: str = "pc") -> bool:
    st_root = Path(state_root).expanduser().resolve()
    eff_p = normalize_prefix(prefix)
    if plaintext_wiped_flag_path(st_root, eff_p).is_file():
        return True
    conn_fn = conn_info_filename_for_prefix(eff_p)
    sec_fn = f"connection_{eff_p}.txt" if eff_p != "pc" else "connection.txt"
    for fp in (st_root / conn_fn, st_root / "secrets" / sec_fn):
        if fp.is_file():
            try:
                txt = fp.read_text(encoding="utf-8", errors="replace")
                if WIPED_PASSWORD_PLACEHOLDER_ZH in txt:
                    return True
            except Exception:
                pass
    return False


def wipe_plaintext_connection_password(state_root: Union[str, Path], prefix: str = "pc") -> Dict[str, Any]:
    """Ensure encrypted vault holds the recoverable password, then scrub plaintext password lines on disk."""
    st_root = Path(state_root).expanduser().resolve()
    eff_p = normalize_prefix(prefix)
    sec_dir = st_root / "secrets"
    conn_fn = conn_info_filename_for_prefix(eff_p)
    sec_fn = f"connection_{eff_p}.txt" if eff_p != "pc" else "connection.txt"

    cand_files = [st_root / conn_fn, sec_dir / sec_fn]
    if eff_p == "pc":
        legacy_f = st_root / "CONNECTION_INFO.txt"
        if legacy_f.is_file():
            cand_files.append(legacy_f)

    vault_pw = load_encrypted_connection_password(st_root, prefix=eff_p)
    if not vault_pw:
        for cf in cand_files:
            found_pw = _extract_existing_password_line(cf)
            if found_pw:
                save_encrypted_connection_password(st_root, found_pw, prefix=eff_p)
                vault_pw = load_encrypted_connection_password(st_root, prefix=eff_p)
                if vault_pw:
                    break

    if not vault_pw:
        return {
            "ok": False,
            "error": "本机加密保险箱中未找到可恢复的连接口令，已拒绝擦除文本文件以防口令丢失。",
            "wiped_files": [],
        }

    sec_dir.mkdir(parents=True, exist_ok=True)
    flag_p = plaintext_wiped_flag_path(st_root, eff_p)
    atomic_write_text(flag_p, "1\n", mode_override=0o600)
    apply_current_user_only_acl(flag_p)

    wiped_files: List[str] = []
    for cf in cand_files:
        if not cf.is_file():
            continue
        try:
            old_txt = cf.read_text(encoding="utf-8", errors="replace")
            new_txt = re.sub(
                r"(授权页连接口令\s*:\s*)([^\r\n]+)",
                lambda m: f"{m.group(1)}{WIPED_PASSWORD_PLACEHOLDER_ZH}",
                old_txt,
            )
            if new_txt != old_txt:
                atomic_write_text(cf, new_txt, mode_override=0o600)
                apply_current_user_only_acl(cf)
            wiped_files.append(str(cf))
        except Exception:
            pass

    return {
        "ok": True,
        "plaintext_password_wiped": True,
        "wiped_files": wiped_files,
    }


def generate_endpoint_secret(length: int = 24) -> str:
    """Generate high-entropy lowercase alphanumeric endpoint secret (`>=124 bits` at default `length=24`)."""
    eff_len = max(16, int(length))
    return "".join(secrets.choice(ENDPOINT_SECRET_ALPHABET) for _ in range(eff_len))


def endpoint_secret_path(state_root: Path, prefix: str = "pc") -> Path:
    eff_p = normalize_prefix(prefix)
    fname = f"endpoint_secret_{eff_p}.txt" if eff_p != "pc" else "endpoint_secret.txt"
    return Path(state_root) / "secrets" / fname


def load_endpoint_secret(state_root: Union[str, Path], prefix: str = "pc") -> str:
    st_root = Path(state_root)
    ep_p = endpoint_secret_path(st_root, prefix=prefix)
    norm_k = os.path.normcase(str(ep_p))
    try:
        st = ep_p.stat()
    except OSError:
        with _EP_SECRET_CACHE_LOCK:
            _EP_SECRET_CACHE.pop(norm_k, None)
        return ""
    mtime_ns = int(getattr(st, "st_mtime_ns", 0))
    fsize = int(st.st_size)
    with _EP_SECRET_CACHE_LOCK:
        cached = _EP_SECRET_CACHE.get(norm_k)
        if cached is not None and cached[0] == mtime_ns and cached[1] == fsize:
            return cached[2]
    try:
        raw_val = ep_p.read_text(encoding="utf-8", errors="replace").strip().lower()
    except OSError:
        return ""
    clean_val = raw_val if _VALID_ENDPOINT_SECRET_RE.fullmatch(raw_val) else ""
    with _EP_SECRET_CACHE_LOCK:
        _EP_SECRET_CACHE[norm_k] = (mtime_ns, fsize, clean_val)
    return clean_val


def save_endpoint_secret(state_root: Union[str, Path], secret: str, prefix: str = "pc") -> str:
    clean = str(secret or "").strip().lower()
    if not _VALID_ENDPOINT_SECRET_RE.fullmatch(clean):
        raise ValueError("Invalid endpoint_secret: expected 16..64 lowercase [a-z0-9] characters")
    st_root = Path(state_root).expanduser().resolve()
    ep_p = endpoint_secret_path(st_root, prefix=prefix)
    ep_p.parent.mkdir(parents=True, exist_ok=True)
    apply_current_user_only_acl(ep_p.parent)
    atomic_write_text(ep_p, clean + "\n", mode_override=0o600)
    apply_current_user_only_acl(ep_p)
    norm_k = os.path.normcase(str(ep_p))
    try:
        st = ep_p.stat()
        with _EP_SECRET_CACHE_LOCK:
            _EP_SECRET_CACHE[norm_k] = (int(getattr(st, "st_mtime_ns", 0)), int(st.st_size), clean)
    except OSError:
        with _EP_SECRET_CACHE_LOCK:
            _EP_SECRET_CACHE.pop(norm_k, None)
    return clean


def clear_endpoint_secret(state_root: Union[str, Path], prefix: str = "pc") -> None:
    st_root = Path(state_root).expanduser().resolve()
    ep_p = endpoint_secret_path(st_root, prefix=prefix)
    norm_k = os.path.normcase(str(ep_p))
    if ep_p.exists():
        try:
            sz = max(32, int(ep_p.stat().st_size))
            ep_p.write_bytes(b"\x00" * sz)
        except OSError:
            pass
        try:
            ep_p.unlink()
        except OSError:
            pass
    with _EP_SECRET_CACHE_LOCK:
        _EP_SECRET_CACHE.pop(norm_k, None)


def _is_ip_or_single_tenant_gateway_host(host: str) -> bool:
    h = (host or "").strip().lower().strip("[]")
    if not h:
        return False
    if any(
        h.endswith(sfx)
        for sfx in (".srv.us", ".workers.dev", ".trycloudflare.com", ".sslip.io", ".lhr.life", ".localhost.run")
    ):
        return True
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def apply_endpoint_secret_to_url(raw_public_url: str, endpoint_secret: str, *, previous_secret: str = "") -> str:
    """Attach `/u/<endpoint_secret>` to non-loopback `https://` gateway URLs while preserving shared hub `/u/<node_id>`."""
    raw = str(raw_public_url or "").strip().rstrip("/")
    sec = str(endpoint_secret or "").strip().lower()
    if not raw or not sec or not _VALID_ENDPOINT_SECRET_RE.fullmatch(sec):
        return raw
    u = urlsplit(raw)
    scheme = (u.scheme or "").strip().lower()
    host = (u.hostname or "").strip().lower()
    if scheme != "https" or not u.netloc or host in ("", "127.0.0.1", "localhost", "::1"):
        return raw

    path_s = (u.path or "").rstrip("/")
    had_mcp_ro = False
    had_mcp = False
    if path_s.endswith("/mcp/readonly"):
        path_s = path_s[: -len("/mcp/readonly")].rstrip("/")
        had_mcp_ro = True
    elif path_s.endswith("/mcp"):
        path_s = path_s[: -len("/mcp")].rstrip("/")
        had_mcp = True

    prev_clean = str(previous_secret or "").strip().lower()
    m_u = re.fullmatch(r"/u/([a-zA-Z0-9_-]{2,64})", path_s)
    if m_u:
        existing_seg = m_u.group(1).lower()
        is_single_tenant = _is_ip_or_single_tenant_gateway_host(host)
        is_prev_or_24sec = (prev_clean and existing_seg == prev_clean) or bool(ENDPOINT_SECRET_RE.fullmatch(existing_seg))
        if not is_single_tenant and not is_prev_or_24sec:
            base_out = f"https://{u.netloc}{path_s}"
        else:
            base_out = f"https://{u.netloc}/u/{sec}"
    elif not path_s:
        base_out = f"https://{u.netloc}/u/{sec}"
    else:
        base_out = f"https://{u.netloc}{path_s}/u/{sec}"

    if had_mcp_ro:
        return f"{base_out}/mcp/readonly"
    if had_mcp:
        return f"{base_out}/mcp"
    return base_out


def strip_endpoint_secret_from_url(raw_public_url: str, old_secret: str = "") -> str:
    """Remove `/u/<old_secret>` (or 24-char endpoint secret) from a gateway base URL when disabling secret path."""
    raw = str(raw_public_url or "").strip().rstrip("/")
    if not raw:
        return ""
    u = urlsplit(raw)
    if (u.scheme or "").lower() != "https" or not u.netloc:
        return raw
    path_s = (u.path or "").rstrip("/")
    m_u = re.fullmatch(r"(.*)/u/([a-zA-Z0-9_-]{2,64})", path_s)
    if not m_u:
        return raw
    prefix_before, seg = m_u.group(1), m_u.group(2).lower()
    old_clean = str(old_secret or "").strip().lower()
    host = (u.hostname or "").strip().lower()
    if (old_clean and seg == old_clean) or ENDPOINT_SECRET_RE.fullmatch(seg) or _is_ip_or_single_tenant_gateway_host(host):
        return f"https://{u.netloc}{prefix_before}".rstrip("/")
    return raw


def _extract_existing_password_line(info_path: Path) -> str:
    if not info_path.is_file():
        return ""
    try:
        m = re.search(r"授权页连接口令\s*:\s*([^\r\n]+)", info_path.read_text(encoding="utf-8", errors="replace"))
        val = m.group(1).strip() if m else ""
        if not val or val.startswith("("):
            return ""
        return val
    except Exception:
        return ""


def _parse_dotenv_file(dotenv_path: Path) -> Dict[str, str]:
    """Minimal stdlib `.env` parser (`KEY=VALUE`, strips optional quotes, ignores comments)."""
    out: Dict[str, str] = {}
    if not dotenv_path.is_file():
        return out
    try:
        raw = dotenv_path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return out
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("export "):
            s = s[7:].strip()
        if "=" not in s:
            continue
        k, v = s.split("=", 1)
        key = k.strip()
        if not key or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            continue
        val = v.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        out[key] = val
    return out


_SECURITY_SENSITIVE_DOTENV_KEYS: frozenset[str] = frozenset(
    {
        "COSMOS_PERMISSION_TIER",
        "LOCALPC_PERMISSION_TIER",
        "COSMOS_WORKSPACE_ROOTS",
        "LOCALPC_WORKSPACE_ROOTS",
        "COSMOS_MCP_WORKSPACE",
        "LOCALPC_MCP_WORKSPACE",
        "COSMOS_WORKSPACE",
        "LOCALPC_WORKSPACE",
    }
)


def load_safe_state_dotenv(state_root: Optional[Path] = None) -> Dict[str, str]:
    """Load non-empty `.env` defaults from `<state_root>/.env` (or `COSMOS_DOTENV_FILE`) without overriding OS env."""
    loaded: Dict[str, str] = {}
    explicit_file = (os.environ.get("COSMOS_DOTENV_FILE") or "").strip()
    if explicit_file:
        ef_p = Path(expand_env_and_tilde(explicit_file)).expanduser()
        for k, v in _parse_dotenv_file(ef_p).items():
            loaded[k] = v
    if state_root is not None:
        st_env_p = Path(state_root).expanduser() / ".env"
        for k, v in _parse_dotenv_file(st_env_p).items():
            loaded.setdefault(k, v)
            if k not in os.environ and v != "":
                if k in ("COSMOS_DEV_PROXY",):
                    os.environ[k] = v
    return loaded


def _load_or_create_master_seed(secrets_dir: Path) -> bytes:
    bin_file = secrets_dir / "master_seed.bin"
    if bin_file.is_file():
        try:
            raw_b = bin_file.read_bytes()
            if len(raw_b) == 32:
                return raw_b
        except Exception:
            pass
    seed_file = secrets_dir / "master_seed"
    if seed_file.is_file():
        try:
            raw_hex = seed_file.read_text(encoding="utf-8").strip()
            if len(raw_hex) >= 64:
                sb = bytes.fromhex(raw_hex[:64])
                try:
                    bin_file.write_bytes(sb)
                except Exception:
                    pass
                return sb
        except Exception:
            pass
    seed_bytes = secrets.token_bytes(32)
    try:
        atomic_write_text(seed_file, seed_bytes.hex() + "\n", mode_override=0o600)
        bin_file.write_bytes(seed_bytes)
    except Exception:
        pass
    return seed_bytes


def derive_public_gateway_node_id(master_seed: bytes, instance_id: str = "pc") -> str:
    inst = normalize_prefix(instance_id)
    return hmac.new(master_seed, f"cosmos-public-gateway-node:{inst}".encode("utf-8"), hashlib.sha256).hexdigest()[:16]


_DEPRECATED_PLACEHOLDER_GATEWAY_HOSTS = frozenset({"gw.cosmos-mcp.org", "gw.cosmos-mcp.workers.dev"})


def _sanitize_public_gateway_base(raw: Any) -> str:
    val = str(raw or "").strip().rstrip("/")
    if not val:
        return ""
    host = (urlsplit(val if "://" in val else f"https://{val}").hostname or "").strip().lower()
    if host in _DEPRECATED_PLACEHOLDER_GATEWAY_HOSTS:
        return ""
    return val


def _default_public_gateway_base() -> str:
    env_b = _sanitize_public_gateway_base(os.environ.get("COSMOS_PUBLIC_GATEWAY_BASE"))
    return env_b if env_b else DEFAULT_PUBLIC_GATEWAY_BASE


def _clean_public_https_url(raw: Any) -> str:
    val = str(raw or "").strip().rstrip("/")
    if not val:
        return ""
    if val.endswith("/mcp"):
        val = val[:-4].rstrip("/")
    if not val.startswith(("https://", "http://")):
        return ""
    host = (urlsplit(val).hostname or "").strip().lower()
    if not host or host in ("127.0.0.1", "localhost", "::1") or host in _DEPRECATED_PLACEHOLDER_GATEWAY_HOSTS:
        return ""
    return val


def is_pinned_gateway_url(raw_url: Any) -> bool:
    """Return True if `raw_url` is a permanent/fixed public HTTPS gateway URL (never evicted by Quick Tunnel rotation)."""
    clean = _clean_public_https_url(raw_url)
    if not clean or not clean.startswith("https://"):
        return False
    host = (urlsplit(clean).hostname or "").strip().lower()
    if "trycloudflare.com" in host:
        return False
    return True


def mode_to_gateway_slot(tunnel_mode: str) -> Tuple[str, str]:
    """Map scalar `tunnel_mode` to `(gateway_id, submode)`; `'local'` returns `('', 'local')`."""
    tm = (tunnel_mode or "").strip().lower()
    if not tm or tm == "local":
        return ("", "local")
    if tm == "cloudflare":
        return ("instant", "cloudflare")
    if tm in ("public_gateway", "srv_us"):
        return ("instant", "public_gateway")
    if tm in ("workers_dev", "cf_workers", "cloudflare_workers"):
        return ("workers_dev", "workers_dev")
    if tm == "reverse_proxy":
        return ("self_hosted", "custom")
    if tm in SELF_HOSTED_SUBMODES:
        return ("self_hosted", tm)
    return ("instant", "public_gateway")


def _build_default_gateway_slots(cfg_doc: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    wd_script = str(
        cfg_doc.get("workers_script_name") or cfg_doc.get("workers_dev_script_name") or ""
    ).strip()
    wd_acc = str(
        cfg_doc.get("workers_account_id") or cfg_doc.get("workers_dev_account_id") or ""
    ).strip()
    wd_sub = str(
        cfg_doc.get("workers_subdomain") or cfg_doc.get("workers_dev_subdomain") or ""
    ).strip()
    wd_dom = str(
        cfg_doc.get("workers_custom_domain") or cfg_doc.get("workers_dev_custom_domain") or ""
    ).strip()
    wd_url = _clean_public_https_url(cfg_doc.get("workers_dev_url"))
    vps_url = _clean_public_https_url(cfg_doc.get("vps_hub_url"))
    try:
        vps_sport = int(cfg_doc.get("vps_ssh_port") or 22)
    except (TypeError, ValueError):
        vps_sport = 22
    try:
        vps_rport = int(cfg_doc.get("vps_remote_port") or 18096)
    except (TypeError, ValueError):
        vps_rport = 18096

    wd_slot: Dict[str, Any] = {
        "enabled": False,
        "submode": "workers_dev",
        "public_url": wd_url,
        "script_name": wd_script,
        "account_id": wd_acc,
        "subdomain": wd_sub,
        "updated_at": 0.0,
    }
    if wd_dom:
        wd_slot["custom_domain"] = wd_dom

    return {
        "instant": {
            "enabled": False,
            "submode": "public_gateway",
            "public_url": "",
            "updated_at": 0.0,
        },
        "workers_dev": wd_slot,
        "self_hosted": {
            "enabled": False,
            "submode": "vps_hub",
            "public_url": vps_url,
            "custom_domain": "",
            "vps_ssh_target": str(cfg_doc.get("vps_ssh") or "").strip(),
            "vps_ssh_port": vps_sport,
            "vps_remote_port": vps_rport,
            "vps_identity_file": str(cfg_doc.get("vps_identity_file") or "").strip(),
            "updated_at": 0.0,
        },
    }


def _find_historical_srvus_url(cfg_doc: Mapping[str, Any]) -> str:
    for seq_key in ("pinned_gateway_urls", "previous_public_bases"):
        raw_seq = cfg_doc.get(seq_key)
        if isinstance(raw_seq, (list, tuple)):
            for raw_u in reversed(list(raw_seq)):
                clean_u = _clean_public_https_url(raw_u)
                if clean_u and clean_u.lower().endswith(".srv.us"):
                    return clean_u
    return ""


def _apply_legacy_mode_to_slots(
    slots: Dict[str, Dict[str, Any]],
    raw_mode: str,
    cfg_doc: Mapping[str, Any],
) -> str:
    """Apply legacy single-select `tunnel_mode` onto `slots` while preserving historical slot URLs."""
    tm = (raw_mode or DEFAULT_TUNNEL_MODE).strip().lower() or DEFAULT_TUNNEL_MODE
    pub_base = _clean_public_https_url(cfg_doc.get("public_base") or cfg_doc.get("public_base_url"))
    wd_url = _clean_public_https_url(cfg_doc.get("workers_dev_url"))
    vps_url = _clean_public_https_url(cfg_doc.get("vps_hub_url"))
    pg_url = _clean_public_https_url(cfg_doc.get("public_gateway_url"))
    hist_srvus = _find_historical_srvus_url(cfg_doc)

    for gid in GATEWAY_IDS:
        slots[gid]["enabled"] = False

    if wd_url and not slots["workers_dev"].get("public_url"):
        slots["workers_dev"]["public_url"] = wd_url
    if vps_url and not slots["self_hosted"].get("public_url"):
        slots["self_hosted"]["public_url"] = vps_url
    if hist_srvus and not slots["instant"].get("public_url"):
        slots["instant"]["public_url"] = hist_srvus

    if tm == "local":
        if pub_base and (pub_base.lower().endswith(".srv.us") or "trycloudflare.com" in pub_base.lower()):
            if not slots["instant"].get("public_url"):
                slots["instant"]["public_url"] = pub_base
        return "instant"

    gw_id, submode = mode_to_gateway_slot(tm)
    if gw_id == "instant":
        slots["instant"]["enabled"] = True
        slots["instant"]["submode"] = submode
        if pub_base and (
            pub_base.lower().endswith(".srv.us")
            or "trycloudflare.com" in pub_base.lower()
            or "/u/" in pub_base.lower()
            or pub_base == pg_url
        ):
            slots["instant"]["public_url"] = pub_base
        elif pg_url and not slots["instant"].get("public_url"):
            slots["instant"]["public_url"] = pg_url
        return "instant"

    if gw_id == "workers_dev":
        slots["workers_dev"]["enabled"] = True
        slots["workers_dev"]["submode"] = "workers_dev"
        eff_wd = wd_url or (pub_base if (pub_base and "trycloudflare.com" not in pub_base.lower() and not pub_base.lower().endswith(".srv.us")) else "")
        if eff_wd:
            slots["workers_dev"]["public_url"] = eff_wd
        if pub_base and pub_base.lower().endswith(".srv.us") and not slots["instant"].get("public_url"):
            slots["instant"]["public_url"] = pub_base
        return "workers_dev"

    slots["self_hosted"]["enabled"] = True
    slots["self_hosted"]["submode"] = submode
    eff_sh = vps_url if submode in ("vps_hub", "vps") and vps_url else pub_base
    if not eff_sh:
        eff_sh = pub_base
    if eff_sh and "trycloudflare.com" not in eff_sh.lower():
        slots["self_hosted"]["public_url"] = eff_sh
    return "self_hosted"


def collect_pinned_gateway_urls(
    gateways: Mapping[str, Mapping[str, Any]],
    cfg_doc: Optional[Mapping[str, Any]] = None,
) -> List[str]:
    """Collect deduplicated permanent/fixed gateway HTTPS URLs (never evicted by Quick Tunnel rotation)."""
    out: List[str] = []
    seen: set[str] = set()

    def _add(u: Any) -> None:
        clean = _clean_public_https_url(u)
        if not clean or not is_pinned_gateway_url(clean):
            return
        k = clean.lower()
        if k not in seen:
            seen.add(k)
            out.append(clean)

    if cfg_doc is not None:
        raw_pinned = cfg_doc.get("pinned_gateway_urls")
        if isinstance(raw_pinned, (list, tuple)):
            for item in raw_pinned:
                _add(item)
        for k_hint in ("workers_dev_url", "vps_hub_url"):
            _add(cfg_doc.get(k_hint))
        for dom_k in ("workers_custom_domain", "workers_dev_custom_domain"):
            raw_cd = str(cfg_doc.get(dom_k) or "").strip().strip("/")
            if raw_cd:
                _add(raw_cd if "://" in raw_cd else f"https://{raw_cd}")
        raw_extra_trusted = cfg_doc.get("extra_trusted_urls")
        if isinstance(raw_extra_trusted, (list, tuple)):
            for ex_u in raw_extra_trusted:
                _add(ex_u)
        raw_prev = cfg_doc.get("previous_public_bases")
        if isinstance(raw_prev, (list, tuple)):
            for prev_u in raw_prev:
                cu = _clean_public_https_url(prev_u)
                if cu and (cu.lower().endswith(".srv.us") or ".workers.dev" in cu.lower()):
                    _add(cu)

    for gid in GATEWAY_IDS:
        g_obj = gateways.get(gid)
        if isinstance(g_obj, Mapping):
            _add(g_obj.get("public_url"))
            slot_cd = str(g_obj.get("custom_domain") or "").strip().strip("/")
            if slot_cd:
                _add(slot_cd if "://" in slot_cd else f"https://{slot_cd}")
    return out


def normalize_gateways_config(cfg_doc: Mapping[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], str]:
    """Losslessly migrate legacy `service.json` or normalize 3-slot `gateways` config + bidirectional top-level mirrors."""
    slots = _build_default_gateway_slots(cfg_doc)
    raw_gateways = cfg_doc.get("gateways")
    raw_tm = str(cfg_doc.get("tunnel_mode") or "").strip().lower()
    mirrored_tm = str(cfg_doc.get("_gateways_mirrored_mode") or "").strip().lower()

    if not isinstance(raw_gateways, Mapping) or not raw_gateways:
        selected = _apply_legacy_mode_to_slots(slots, raw_tm or DEFAULT_TUNNEL_MODE, cfg_doc)
    else:
        for gid in GATEWAY_IDS:
            in_slot = raw_gateways.get(gid)
            if isinstance(in_slot, Mapping):
                dst = slots[gid]
                if "enabled" in in_slot:
                    dst["enabled"] = parse_bool_flag(in_slot.get("enabled"), default=False)
                raw_sub = str(in_slot.get("submode") or "").strip().lower()
                if gid == "instant" and raw_sub in INSTANT_SUBMODES:
                    dst["submode"] = raw_sub
                elif gid == "workers_dev":
                    dst["submode"] = "workers_dev"
                elif gid == "self_hosted":
                    if raw_sub == "reverse_proxy":
                        dst["submode"] = "custom"
                    elif raw_sub in SELF_HOSTED_SUBMODES:
                        dst["submode"] = raw_sub
                clean_su = _clean_public_https_url(in_slot.get("public_url"))
                if clean_su:
                    dst["public_url"] = clean_su
                elif "public_url" in in_slot and str(in_slot.get("public_url") or "").strip() == "":
                    # Keep fallback URL from workers_dev_url/vps_hub_url only when slot was empty
                    pass
                for k_ex, v_ex in in_slot.items():
                    if k_ex not in ("enabled", "submode", "public_url") and v_ex is not None:
                        dst[k_ex] = v_ex

        raw_sel = str(cfg_doc.get("selected_gateway") or "").strip().lower()
        selected = raw_sel if raw_sel in GATEWAY_IDS else "instant"

        # Backward compatibility when a legacy caller mutates scalar `cfg_doc["tunnel_mode"]` on disk without updating `gateways`
        if mirrored_tm and raw_tm and raw_tm != mirrored_tm:
            if raw_tm == "local":
                if any(slots[g]["enabled"] for g in GATEWAY_IDS):
                    selected = _apply_legacy_mode_to_slots(slots, "local", cfg_doc)
            else:
                tgt_gw, tgt_sub = mode_to_gateway_slot(raw_tm)
                if tgt_gw in GATEWAY_IDS and (
                    not slots[tgt_gw]["enabled"] or slots[tgt_gw]["submode"] != tgt_sub
                ):
                    selected = _apply_legacy_mode_to_slots(slots, raw_tm, cfg_doc)
                elif tgt_gw in GATEWAY_IDS:
                    selected = tgt_gw

    enabled_ids = [gid for gid in GATEWAY_IDS if bool(slots[gid].get("enabled"))]
    if enabled_ids:
        if selected not in enabled_ids:
            selected = enabled_ids[0]
        mirrored_mode_out = str(slots[selected].get("submode") or DEFAULT_TUNNEL_MODE)
        sel_pub = _clean_public_https_url(slots[selected].get("public_url"))
        if not sel_pub:
            for eid in enabled_ids:
                cand_u = _clean_public_https_url(slots[eid].get("public_url"))
                if cand_u:
                    sel_pub = cand_u
                    break
        mirrored_pub_out = sel_pub
    else:
        if selected not in GATEWAY_IDS:
            selected = "instant"
        mirrored_mode_out = "local"
        mirrored_pub_out = ""

    pinned_urls = collect_pinned_gateway_urls(slots, cfg_doc)

    if isinstance(cfg_doc, MutableMapping):
        cfg_doc["gateways"] = {gid: dict(slots[gid]) for gid in GATEWAY_IDS}
        cfg_doc["selected_gateway"] = selected
        cfg_doc["tunnel_mode"] = mirrored_mode_out
        cfg_doc["_gateways_mirrored_mode"] = mirrored_mode_out
        cfg_doc["pinned_gateway_urls"] = pinned_urls
        if not enabled_ids:
            cfg_doc["public_base"] = ""
            if "public_base_url" in cfg_doc:
                cfg_doc["public_base_url"] = ""
        elif mirrored_pub_out:
            cfg_doc["public_base"] = mirrored_pub_out
            if "public_base_url" in cfg_doc:
                cfg_doc["public_base_url"] = mirrored_pub_out

    return ({gid: dict(slots[gid]) for gid in GATEWAY_IDS}, selected)


def ensure_initialized(
    product_root: Optional[Path] = None,
    public_url: str = "",
    port: int = 8096,
    *,
    cli_state_dir: str = "",
    tier_key: str = DEFAULT_TIER,
    reset_password: bool = False,
    prefix: str = "pc",
    tool_prefix: str = "",
    device_label: str = "",
    toolset_profile: str = "",
    workspace_roots: Any = None,
    readonly_workspace_roots: Any = None,
    workspace: str = "",
    enabled_packs: Any = None,
    keep_awake: Optional[bool] = None,
    approval_popups: Optional[bool] = None,
    annotation_mode: str = "",
    python_path: Optional[str] = None,
    scan_host_global_skills: Optional[bool] = None,
    redact_project_secrets: Optional[bool] = None,
    enable_oneclick_token_route: Optional[bool] = None,
    tray_enabled: Optional[bool] = None,
    tunnel_mode: Optional[str] = None,
    public_gateway_base: Optional[str] = None,
    public_gateway_node_id: Optional[str] = None,
    workers_dev_account_id: Optional[str] = None,
    workers_dev_script_name: Optional[str] = None,
    workers_dev_subdomain: Optional[str] = None,
    workers_dev_custom_domain: Optional[str] = None,
) -> Dict[str, Any]:
    """Single-source stdlib credential, config, and connection-guide initializer."""
    state_root = resolve_state_root(product_root=product_root, cli_state_dir=cli_state_dir)
    secrets_dir = state_root / "secrets"
    state_dir = state_root / "state"
    cfg_dir = state_root / "config"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    cfg_dir.mkdir(parents=True, exist_ok=True)
    apply_current_user_only_acl(secrets_dir)
    apply_current_user_only_acl(state_dir)

    eff_prefix = normalize_prefix(prefix)
    cfg_path = resolve_service_cfg_path(state_root, eff_prefix)
    norm_tier = normalize_tier(tier_key)

    saved_cfg: Dict[str, Any] = {}
    if cfg_path.is_file():
        try:
            loaded = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
            if isinstance(loaded, dict):
                saved_cfg = loaded
        except Exception:
            saved_cfg = {}
    elif eff_prefix == "pc" and (state_root / "config.json").is_file():
        try:
            loaded_legacy = json.loads((state_root / "config.json").read_text(encoding="utf-8-sig"))
            if isinstance(loaded_legacy, dict):
                saved_cfg = loaded_legacy
        except Exception:
            saved_cfg = {}

    eff_tool_prefix = _resolve_safe_tool_prefix(
        tool_prefix if (tool_prefix and str(tool_prefix).strip()) else saved_cfg.get("tool_prefix"),
        fallback=eff_prefix,
    )
    eff_label = resolve_device_label(eff_prefix, device_label or str(saved_cfg.get("device_label") or ""))

    roots_tuple = normalize_workspace_roots(
        workspace_roots if workspace_roots is not None else saved_cfg.get("workspace_roots"),
        legacy_workspace=workspace or str(saved_cfg.get("workspace") or saved_cfg.get("workspace_root") or ""),
    )
    ro_roots_tuple = normalize_readonly_workspace_roots(
        readonly_workspace_roots if readonly_workspace_roots is not None else saved_cfg.get("readonly_workspace_roots"),
        roots_tuple,
    )
    eff_toolset = normalize_toolset_profile(
        toolset_profile or os.environ.get("LOCALPC_TOOLSET_PROFILE", "") or str(saved_cfg.get("toolset_profile") or ""),
        default=DEFAULT_TOOLSET_PROFILE,
    )
    eff_packs = parse_pack_spec(
        enabled_packs if enabled_packs is not None else (os.environ.get("LOCALPC_ENABLED_PACKS") or saved_cfg.get("enabled_packs")),
        strict=False,
    )
    eff_awake = (
        bool(keep_awake)
        if keep_awake is not None
        else parse_bool_flag(saved_cfg.get("keep_awake"), default=True)
    )
    eff_scan_host_skills = (
        bool(scan_host_global_skills)
        if scan_host_global_skills is not None
        else parse_bool_flag(saved_cfg.get("scan_host_global_skills"), default=False)
    )
    eff_redact_project_secrets = (
        bool(redact_project_secrets)
        if redact_project_secrets is not None
        else parse_bool_flag(saved_cfg.get("redact_project_secrets"), default=False)
    )
    eff_enable_oneclick_route = (
        bool(enable_oneclick_token_route)
        if enable_oneclick_token_route is not None
        else parse_bool_flag(saved_cfg.get("enable_oneclick_token_route"), default=False)
    )
    eff_tray_enabled = (
        bool(tray_enabled)
        if tray_enabled is not None
        else parse_bool_flag(saved_cfg.get("tray_enabled"), default=True)
    )

    seed_bytes = _load_or_create_master_seed(secrets_dir)
    raw_tm = tunnel_mode if (tunnel_mode is not None and str(tunnel_mode).strip()) else saved_cfg.get("tunnel_mode")
    eff_tunnel_mode = str(raw_tm or DEFAULT_TUNNEL_MODE).strip() or DEFAULT_TUNNEL_MODE

    raw_pg_base = (
        public_gateway_base
        if (public_gateway_base is not None and str(public_gateway_base).strip())
        else (os.environ.get("COSMOS_PUBLIC_GATEWAY_BASE") or saved_cfg.get("public_gateway_base") or DEFAULT_PUBLIC_GATEWAY_BASE)
    )
    eff_pg_base = _sanitize_public_gateway_base(raw_pg_base) or DEFAULT_PUBLIC_GATEWAY_BASE

    raw_pg_nid = (
        public_gateway_node_id
        if (public_gateway_node_id is not None and str(public_gateway_node_id).strip())
        else saved_cfg.get("public_gateway_node_id")
    )
    eff_pg_node_id = str(raw_pg_nid).strip() if (raw_pg_nid is not None and str(raw_pg_nid).strip()) else derive_public_gateway_node_id(seed_bytes, eff_prefix)

    eff_wd_account_id = str(
        workers_dev_account_id if workers_dev_account_id is not None else (saved_cfg.get("workers_dev_account_id") or "")
    ).strip()
    raw_wd_script = workers_dev_script_name if workers_dev_script_name is not None else saved_cfg.get("workers_dev_script_name")
    eff_wd_script_name = (
        str(raw_wd_script).strip()
        if (raw_wd_script is not None and str(raw_wd_script).strip())
        else DEFAULT_WORKERS_DEV_SCRIPT_NAME
    )
    eff_wd_subdomain = str(
        workers_dev_subdomain if workers_dev_subdomain is not None else (saved_cfg.get("workers_dev_subdomain") or "")
    ).strip()
    eff_wd_custom_domain = str(
        workers_dev_custom_domain if workers_dev_custom_domain is not None else (saved_cfg.get("workers_dev_custom_domain") or "")
    ).strip()

    raw_env_ann = os.environ.get("COSMOS_ANNOTATION_MODE") or os.environ.get("LOCALPC_ANNOTATION_MODE") or ""
    raw_env_ap = os.environ.get("LOCALPC_APPROVAL_POPUPS")
    if annotation_mode:
        eff_ann_mode = normalize_annotation_mode(annotation_mode)
    elif approval_popups is not None:
        eff_ann_mode = "strict" if bool(approval_popups) else "seamless"
    elif raw_env_ann.strip():
        eff_ann_mode = normalize_annotation_mode(raw_env_ann)
    elif raw_env_ap is not None and raw_env_ap.strip() != "":
        eff_ann_mode = "strict" if parse_bool_flag(raw_env_ap, default=False) else "seamless"
    else:
        saved_ap = saved_cfg.get("approval_popups")
        eff_ann_mode = normalize_annotation_mode(
            saved_cfg.get("annotation_mode"),
            approval_popups=(parse_bool_flag(saved_ap) if saved_ap is not None else None),
            default=DEFAULT_ANNOTATION_MODE,
        )
    eff_popups = eff_ann_mode == "strict"

    eff_py_path = normalize_python_path(
        python_path
        if python_path is not None
        else (os.environ.get("COSMOS_PYTHON_PATH") or os.environ.get("LOCALPC_PYTHON_PATH") or saved_cfg.get("python_path") or "")
    )

    saved_pub_clean = str(saved_cfg.get("public_base") or "").strip().rstrip("/")
    if saved_pub_clean:
        saved_pub_host = (urlsplit(saved_pub_clean if "://" in saved_pub_clean else f"https://{saved_pub_clean}").hostname or "").strip().lower()
        if saved_pub_host in _DEPRECATED_PLACEHOLDER_GATEWAY_HOSTS:
            saved_pub_clean = ""
        elif eff_tunnel_mode != "local" and saved_pub_host in ("127.0.0.1", "localhost", "::1"):
            saved_pub_clean = ""

    if public_url and public_url.strip():
        cand_pub = public_url.strip().rstrip("/")
        cand_host = (urlsplit(cand_pub if "://" in cand_pub else f"https://{cand_pub}").hostname or "").strip().lower()
        if eff_tunnel_mode == "public_gateway" and cand_host in (
            "127.0.0.1",
            "localhost",
            "::1",
            *_DEPRECATED_PLACEHOLDER_GATEWAY_HOSTS,
        ):
            eff_public_base = f"{eff_pg_base}/u/{eff_pg_node_id}" if eff_pg_base else ""
        else:
            eff_public_base = cand_pub
    elif saved_pub_clean:
        eff_public_base = saved_pub_clean
    elif eff_tunnel_mode == "public_gateway":
        eff_public_base = f"{eff_pg_base}/u/{eff_pg_node_id}" if eff_pg_base else ""
    else:
        eff_public_base = ""

    if not cfg_path.is_file():
        default_cfg: Dict[str, Any] = {
            "host": "127.0.0.1",
            "port": int(port),
            "permission_tier": norm_tier,
            "instance_id": eff_prefix,
            "tool_prefix": eff_tool_prefix,
            "device_label": eff_label,
            "toolset_profile": eff_toolset,
            "prompt_profile": DEFAULT_PROMPT_PROFILE,
            "workspace": str(roots_tuple[0]),
            "workspace_roots": [str(p) for p in roots_tuple],
            "readonly_workspace_roots": [str(p) for p in ro_roots_tuple],
            "scan_host_global_skills": eff_scan_host_skills,
            "redact_project_secrets": eff_redact_project_secrets,
            "enable_oneclick_token_route": eff_enable_oneclick_route,
            "tray_enabled": eff_tray_enabled,
            "enabled_packs": list(eff_packs),
            "keep_awake": eff_awake,
            "annotation_mode": eff_ann_mode,
            "approval_popups": eff_popups,
            "python_path": eff_py_path,
            "tunnel_mode": eff_tunnel_mode,
            "public_gateway_base": eff_pg_base,
            "public_gateway_node_id": eff_pg_node_id,
            "workers_dev_account_id": eff_wd_account_id,
            "workers_dev_script_name": eff_wd_script_name,
            "workers_dev_subdomain": eff_wd_subdomain,
            "workers_dev_custom_domain": eff_wd_custom_domain,
            "public_base": eff_public_base,
            "redirect_hosts": list(DEFAULT_REDIRECT_HOSTS),
        }
        if norm_tier != "tier1_readonly":
            default_cfg["previous_non_readonly_tier"] = norm_tier
        normalize_gateways_config(default_cfg)
        atomic_write_json(cfg_path, default_cfg)
    record_known_workspaces(state_root, roots_tuple)

    isolate_by_prefix = eff_prefix != "pc"
    conn_filename = conn_info_filename_for_prefix(eff_prefix)
    sec_filename = f"connection_{eff_prefix}.txt" if isolate_by_prefix else "connection.txt"
    auth_path = secrets_dir / "auth.json"
    root_info_path = state_root / conn_filename
    sec_info_path = secrets_dir / sec_filename

    was_pw_wiped = is_plaintext_connection_password_wiped(state_root, eff_prefix)
    if auth_path.is_file() and not reset_password:
        apply_current_user_only_acl(auth_path)
        creds = json.loads(auth_path.read_text(encoding="utf-8"))
        pw_found = ""
        for cand_f in (
            sec_info_path,
            secrets_dir / "connection.txt",
            root_info_path,
            state_root / "连接信息_CONNECTION_INFO.txt",
        ):
            cand_pw = _extract_existing_password_line(cand_f)
            if cand_pw:
                pw_found = cand_pw
                break
        if pw_found:
            try:
                save_encrypted_connection_password(state_root, pw_found, prefix=eff_prefix)
            except Exception:
                pass
        vault_pw = load_encrypted_connection_password(state_root, prefix=eff_prefix)
        if was_pw_wiped:
            password_display = WIPED_PASSWORD_PLACEHOLDER_ZH
        elif pw_found:
            password_display = pw_found
        elif vault_pw:
            password_display = vault_pw
        else:
            password_display = "(已初始化，如需重置请运行 cosmos-mcp --reset-password)"
    else:
        raw_new_pw = generate_readable_password()
        salt = secrets.token_bytes(16)
        existing_tok = ""
        if auth_path.is_file() and not reset_password:
            try:
                existing_tok = str(json.loads(auth_path.read_text(encoding="utf-8")).get("local_api_token") or "")
            except Exception:
                existing_tok = ""
        local_api_token = existing_tok or ("cmcp_" + secrets.token_urlsafe(24))
        creds = {
            "salt": salt.hex(),
            "password_hash": hashlib.scrypt(raw_new_pw.encode("utf-8"), salt=salt, n=16384, r=8, p=1).hex(),
            "local_api_token": local_api_token,
        }
        atomic_write_json(auth_path, creds, mode_override=0o600)
        apply_current_user_only_acl(auth_path)
        try:
            save_encrypted_connection_password(state_root, raw_new_pw, prefix=eff_prefix)
        except Exception:
            pass
        password_display = WIPED_PASSWORD_PLACEHOLDER_ZH if was_pw_wiped else raw_new_pw
        if reset_password:
            emit_kill_signal(state_root=state_root, reason="reset_password", prefix_filter=eff_prefix)

    active_ep_sec = load_endpoint_secret(state_root, prefix=eff_prefix)
    if eff_tunnel_mode == "public_gateway" and not eff_public_base:
        eff_url = ""
        eff_disp_url = ""
        is_loopback_url = False
        mcp_endpoint = "(启动后由内置加密通道自动分配 HTTPS 地址)"
        readonly_endpoint = "(启动后由内置加密通道自动分配 HTTPS 地址)"
        skill_endpoint = "(启动后由内置加密通道自动分配 HTTPS 地址)"
    else:
        eff_url = (eff_public_base or f"http://127.0.0.1:{port}").rstrip("/")
        eff_host = (urlsplit(eff_url).hostname or "").strip().lower()
        is_loopback_url = eff_host in ("127.0.0.1", "localhost", "::1")
        eff_disp_url = (
            apply_endpoint_secret_to_url(eff_url, active_ep_sec)
            if (active_ep_sec and not is_loopback_url)
            else eff_url
        )
        mcp_endpoint = f"{eff_disp_url}/mcp"
        readonly_endpoint = f"{eff_disp_url}/mcp/readonly"
        skill_endpoint = f"{eff_disp_url}/skill"
    local_endpoint = f"http://127.0.0.1:{port}/mcp"
    tier_lbl = format_dynamic_tier_label(
        norm_tier,
        enabled_packs=eff_packs,
        approval_popups=eff_popups,
        annotation_mode=eff_ann_mode,
        keep_awake=eff_awake,
    )
    loopback_notice = (
        "  [边界说明]   : 127.0.0.1 仅供本机回环调试；网页版 Google Gemini 与网页版 ChatGPT 需开启 HTTPS 隧道后填写公网地址\n"
        if is_loopback_url
        else ""
    )
    info_text = (
        "====================================================================\n"
        " Cosmos MCP 连接信息（含本机专属授权口令与管理令牌，请勿外传）\n"
        "====================================================================\n"
        f" 当前权限档位   : {tier_lbl}\n"
        f" 当前工具配置   : {eff_toolset}\n"
        f" 注解确认模式   : {eff_ann_mode}\n"
        f" 当前设备标识   : {eff_label} (工具前缀: {eff_tool_prefix}_*)\n\n"
        "【网页版 Google Gemini（任务模式）/ 网页版 ChatGPT 连接参数】\n"
        "  [防外发提醒] : 复制下方的连接地址或口令后，仅限粘贴到您本人的网页端账号，切勿发往微信群、公开论坛、GitHub Issue 或截图外传！\n"
        f"  主连接器地址   : {mcp_endpoint}\n"
        f"  纯只读端点地址 : {readonly_endpoint}  (供个人订阅只读连接器或只读检索会话安全挂载)\n"
        f"  动态守则地址   : {skill_endpoint}\n"
        f"{loopback_notice}"
        f"  授权页连接口令 : {password_display}\n"
        "  免审批正确开启 : 请打开 https://gemini.google.com/customize/connectors（或左下角菜单 Personal Intelligence -> Connected Apps）点开连接器将 App actions 设为 Always allow；\n"
        "                   请勿在对话气泡的单次工具确认卡上单点允许，以免冲掉同一连接器下其他工具的免审批设置。\n\n"
        "【本机回环管理参数】\n"
        f"  Streamable HTTP URL : {local_endpoint}\n"
        f"  Authorization Header: Bearer {creds['local_api_token']}\n"
    )
    for info_t in (root_info_path, sec_info_path):
        atomic_write_text(info_t, info_text, mode_override=0o600)
        apply_current_user_only_acl(info_t)

    return {
        **creds,
        "state_root": str(state_root),
        "cfg_path": str(cfg_path),
        "auth_path": str(auth_path),
        "instance_id": eff_prefix,
        "tool_prefix": eff_tool_prefix,
        "workspace_roots": [str(p) for p in roots_tuple],
        "readonly_workspace_roots": [str(p) for p in ro_roots_tuple],
        "scan_host_global_skills": eff_scan_host_skills,
        "redact_project_secrets": eff_redact_project_secrets,
        "enable_oneclick_token_route": eff_enable_oneclick_route,
        "tray_enabled": eff_tray_enabled,
        "tunnel_mode": eff_tunnel_mode,
        "public_gateway_base": eff_pg_base,
        "public_gateway_node_id": eff_pg_node_id,
        "workers_dev_account_id": eff_wd_account_id,
        "workers_dev_script_name": eff_wd_script_name,
        "workers_dev_subdomain": eff_wd_subdomain,
        "workers_dev_custom_domain": eff_wd_custom_domain,
        "public_base": eff_public_base,
        "public_url": eff_disp_url,
        "mcp_url": f"{eff_disp_url}/mcp" if eff_disp_url else "",
        "readonly_mcp_url": f"{eff_disp_url}/mcp/readonly" if eff_disp_url else "",
        "toolset_profile": eff_toolset,
        "annotation_mode": eff_ann_mode,
        "python_path": eff_py_path,
    }


class LiveRuntimePolicy:
    """Thread-safe, mtime-driven hot-reloading runtime policy supporting multi-root workspaces and L1..L4."""

    def __init__(
        self,
        tier_key: str = "",
        workspace: str = "",
        *,
        workspace_roots: Any = None,
        readonly_workspace_roots: Any = None,
        cfg_path: Optional[Path] = None,
        state_root: Optional[Path] = None,
        auth_path: Optional[Path] = None,
        product_root: Optional[Path] = None,
        toolset_profile: str = "",
        prompt_profile: str = "",
        enabled_tools: Any = None,
        disabled_tools: Any = None,
        eff_prefix: str = "pc",
        tool_prefix: str = "",
        device_label: str = "",
        approval_popups: Optional[bool] = None,
        annotation_mode: str = "",
        python_path: Optional[str] = None,
        enabled_packs: Any = None,
        keep_awake: Optional[bool] = None,
        scan_host_global_skills: Optional[bool] = None,
        redact_project_secrets: Optional[bool] = None,
        enable_oneclick_token_route: Optional[bool] = None,
        allow_loopback_dev: Optional[bool] = None,
        protect_dotenv_files: Optional[bool] = None,
        protect_host_credentials: Optional[bool] = None,
        block_destructive_commands: Optional[bool] = None,
        tray_enabled: Optional[bool] = None,
        tunnel_mode: Optional[str] = None,
        public_gateway_base: Optional[str] = None,
        public_gateway_node_id: Optional[str] = None,
        workers_dev_account_id: Optional[str] = None,
        workers_dev_script_name: Optional[str] = None,
        workers_dev_subdomain: Optional[str] = None,
        workers_dev_custom_domain: Optional[str] = None,
        guard: Optional[WorkspaceGuard] = None,
        sleep_inhibitor: Optional[SleepInhibitor] = None,
        on_workspace_policy_change: Optional[Callable[[Tuple[Path, ...], bool, str], None]] = None,
        on_keep_awake_change: Optional[Callable[[bool], None]] = None,
    ) -> None:
        self._lock = threading.RLock()
        self.eff_prefix: str = normalize_prefix(eff_prefix)
        self._instance_id: str = self.eff_prefix
        self._product_root: Optional[Path] = Path(product_root).expanduser().resolve() if product_root is not None else None
        self.state_root: Path = (
            Path(state_root).expanduser().resolve()
            if state_root is not None
            else resolve_state_root(product_root=product_root)
        )
        if cfg_path is None and state_root is not None:
            self.cfg_path: Optional[Path] = resolve_service_cfg_path(self.state_root, self.eff_prefix)
        else:
            self.cfg_path = cfg_path
        self.auth_path: Optional[Path] = auth_path
        self.guard: WorkspaceGuard = guard if guard is not None else DEFAULT_GUARD
        self.sleep_inhibitor: SleepInhibitor = sleep_inhibitor if sleep_inhibitor is not None else _POLICY_SLEEP_INHIBITOR
        self._on_ws_change = on_workspace_policy_change
        self._on_awake_change = on_keep_awake_change or (
            lambda flag: bool((self.sleep_inhibitor.enable() if flag else self.sleep_inhibitor.disable()).get("enabled"))
        )

        file_cfg: Dict[str, Any] = {}
        if self.cfg_path is not None and self.cfg_path.is_file():
            try:
                loaded = json.loads(self.cfg_path.read_text(encoding="utf-8-sig"))
                if isinstance(loaded, dict):
                    file_cfg = loaded
            except Exception:
                file_cfg = {}
        elif (
            self.cfg_path is not None
            and not self.cfg_path.is_file()
            and self.eff_prefix == "pc"
            and (self.state_root / "config.json").is_file()
        ):
            try:
                loaded_legacy = json.loads((self.state_root / "config.json").read_text(encoding="utf-8-sig"))
                if isinstance(loaded_legacy, dict):
                    file_cfg = loaded_legacy
            except Exception:
                file_cfg = {}

        raw_tp = tool_prefix if (tool_prefix and str(tool_prefix).strip()) else file_cfg.get("tool_prefix")
        self.tool_prefix: str = _resolve_safe_tool_prefix(raw_tp, fallback=self.eff_prefix)
        self.device_label: str = resolve_device_label(
            self.eff_prefix, device_label or str(file_cfg.get("device_label") or "")
        )

        dotenv_vals = load_safe_state_dotenv(self.state_root)

        def _env_or_dotenv_with_source(*names: str) -> Tuple[str, str]:
            for nm in names:
                ev = os.environ.get(nm)
                if ev is not None and str(ev).strip() != "":
                    return str(ev).strip(), nm
            for nm in names:
                dv = dotenv_vals.get(nm)
                if dv is not None and str(dv).strip() != "":
                    return str(dv).strip(), nm
            return "", ""

        self._startup_env_locks: set[str] = set()
        self._startup_env_lock_details: Dict[str, Dict[str, str]] = {}
        env_tier_val, env_tier_var = _env_or_dotenv_with_source(
            "COSMOS_MCP_PERMISSION_TIER", "COSMOS_PERMISSION_TIER", "LOCALPC_PERMISSION_TIER"
        )
        if env_tier_val:
            self._startup_env_locks.add("tier_key")
            self._startup_env_lock_details["permission_tier"] = {
                "env_var": env_tier_var,
                "reason": "由启动环境变量锁定",
            }
        eff_tier_raw = env_tier_val or tier_key or str(file_cfg.get("permission_tier") or DEFAULT_TIER)
        self.tier_key: str = normalize_tier(eff_tier_raw)
        self.tier_cfg: Dict[str, Any] = dict(PERMISSION_TIERS[self.tier_key])

        env_ws_roots, env_ws_roots_var = _env_or_dotenv_with_source(
            "COSMOS_MCP_WORKSPACE_ROOTS", "COSMOS_WORKSPACE_ROOTS", "LOCALPC_WORKSPACE_ROOTS"
        )
        env_ws_single, env_ws_single_var = _env_or_dotenv_with_source(
            "COSMOS_MCP_WORKSPACE", "COSMOS_WORKSPACE", "LOCALPC_MCP_WORKSPACE", "LOCALPC_WORKSPACE"
        )
        if env_ws_roots or env_ws_single:
            self._startup_env_locks.add("workspace_roots")
            self._startup_env_lock_details["workspace_roots"] = {
                "env_var": env_ws_roots_var or env_ws_single_var,
                "reason": "由启动环境变量锁定",
            }
        raw_roots = (
            env_ws_roots
            if env_ws_roots
            else (workspace_roots if workspace_roots is not None else file_cfg.get("workspace_roots"))
        )
        raw_legacy_ws = (
            env_ws_single
            or workspace
            or str(file_cfg.get("workspace") or file_cfg.get("workspace_root") or "")
        )
        self.workspace_roots: Tuple[Path, ...] = normalize_workspace_roots(raw_roots, legacy_workspace=raw_legacy_ws)
        raw_ro_roots = (
            readonly_workspace_roots
            if readonly_workspace_roots is not None
            else file_cfg.get("readonly_workspace_roots")
        )
        self.readonly_workspace_roots: Tuple[Path, ...] = normalize_readonly_workspace_roots(raw_ro_roots, self.workspace_roots)

        env_ts, env_ts_var = _env_or_dotenv_with_source(
            "COSMOS_MCP_TOOLSET_PROFILE", "COSMOS_TOOLSET_PROFILE", "LOCALPC_TOOLSET_PROFILE"
        )
        env_pr, env_pr_var = _env_or_dotenv_with_source(
            "COSMOS_MCP_PROMPT_PROFILE", "COSMOS_PROMPT_PROFILE", "LOCALPC_PROMPT_PROFILE"
        )
        env_en, env_en_var = _env_or_dotenv_with_source(
            "COSMOS_MCP_ENABLED_TOOLS", "COSMOS_ENABLED_TOOLS", "LOCALPC_ENABLED_TOOLS"
        )
        env_dis, env_dis_var = _env_or_dotenv_with_source(
            "COSMOS_MCP_DISABLED_TOOLS", "COSMOS_DISABLED_TOOLS", "LOCALPC_DISABLED_TOOLS"
        )
        env_packs, env_packs_var = _env_or_dotenv_with_source(
            "COSMOS_MCP_ENABLED_PACKS", "COSMOS_ENABLED_PACKS", "LOCALPC_ENABLED_PACKS"
        )
        if env_ts:
            self._startup_env_locks.add("toolset_profile")
            self._startup_env_lock_details["toolset_profile"] = {
                "env_var": env_ts_var,
                "reason": "由启动环境变量锁定",
            }
        if env_pr:
            self._startup_env_locks.add("prompt_profile")
            self._startup_env_lock_details["prompt_profile"] = {
                "env_var": env_pr_var,
                "reason": "由启动环境变量锁定",
            }
        if env_en:
            self._startup_env_locks.add("enabled_tools")
            self._startup_env_lock_details["enabled_tools"] = {
                "env_var": env_en_var,
                "reason": "由启动环境变量锁定",
            }
        if env_dis:
            self._startup_env_locks.add("disabled_tools")
            self._startup_env_lock_details["disabled_tools"] = {
                "env_var": env_dis_var,
                "reason": "由启动环境变量锁定",
            }
        if env_packs:
            self._startup_env_locks.add("enabled_packs")
            self._startup_env_lock_details["enabled_packs"] = {
                "env_var": env_packs_var,
                "reason": "由启动环境变量锁定",
            }

        raw_ts = env_ts or toolset_profile or str(file_cfg.get("toolset_profile") or "")
        raw_pr = env_pr or prompt_profile or str(file_cfg.get("prompt_profile") or "")
        raw_en = env_en if env_en else (enabled_tools if enabled_tools is not None else file_cfg.get("enabled_tools"))
        raw_dis = env_dis if env_dis else (disabled_tools if disabled_tools is not None else file_cfg.get("disabled_tools"))
        raw_packs = env_packs if env_packs else (enabled_packs if enabled_packs is not None else file_cfg.get("enabled_packs"))

        self.toolset_profile: str = normalize_toolset_profile(raw_ts, default=DEFAULT_TOOLSET_PROFILE)
        self.prompt_profile: str = normalize_prompt_profile(raw_pr, default=DEFAULT_PROMPT_PROFILE)
        self.enabled_tools: Tuple[str, ...] = parse_tool_filter_spec(raw_en, active_prefix=self.tool_prefix, strict=False)
        self.disabled_tools: Tuple[str, ...] = parse_tool_filter_spec(raw_dis, active_prefix=self.tool_prefix, strict=False)
        self.enabled_packs: Tuple[str, ...] = parse_pack_spec(raw_packs, strict=False)

        env_ann = (os.environ.get("COSMOS_ANNOTATION_MODE") or os.environ.get("LOCALPC_ANNOTATION_MODE") or "").strip()
        env_ap = os.environ.get("LOCALPC_APPROVAL_POPUPS")
        if annotation_mode:
            self._annotation_mode: str = parse_strict_annotation_mode(annotation_mode)
        elif approval_popups is not None:
            self._annotation_mode = "strict" if bool(approval_popups) else "seamless"
        elif env_ann:
            self._annotation_mode = normalize_annotation_mode(env_ann)
        elif env_ap is not None and env_ap.strip() != "":
            self._annotation_mode = "strict" if parse_bool_flag(env_ap, default=False) else "seamless"
        else:
            file_ap = file_cfg.get("approval_popups")
            self._annotation_mode = normalize_annotation_mode(
                file_cfg.get("annotation_mode"),
                approval_popups=(parse_bool_flag(file_ap, default=False) if file_ap is not None else None),
                default=DEFAULT_ANNOTATION_MODE,
            )

        env_py = os.environ.get("COSMOS_PYTHON_PATH") or os.environ.get("LOCALPC_PYTHON_PATH") or ""
        if python_path is not None:
            self.python_path: str = normalize_python_path(python_path)
        elif env_py.strip():
            self.python_path = normalize_python_path(env_py)
        else:
            self.python_path = normalize_python_path(file_cfg.get("python_path"))

        env_ka = os.environ.get("LOCALPC_KEEP_AWAKE")
        if keep_awake is not None:
            self.keep_awake: bool = bool(keep_awake)
        elif env_ka is not None and env_ka.strip() != "":
            self.keep_awake = parse_bool_flag(env_ka, default=True)
        else:
            self.keep_awake = parse_bool_flag(file_cfg.get("keep_awake"), default=True)

        self.scan_host_global_skills: bool = (
            bool(scan_host_global_skills)
            if scan_host_global_skills is not None
            else parse_bool_flag(file_cfg.get("scan_host_global_skills"), default=False)
        )
        self.redact_project_secrets: bool = (
            bool(redact_project_secrets)
            if redact_project_secrets is not None
            else parse_bool_flag(file_cfg.get("redact_project_secrets"), default=False)
        )
        self.enable_oneclick_token_route: bool = (
            bool(enable_oneclick_token_route)
            if enable_oneclick_token_route is not None
            else parse_bool_flag(file_cfg.get("enable_oneclick_token_route"), default=False)
        )
        self.allow_loopback_dev: bool = (
            bool(allow_loopback_dev)
            if allow_loopback_dev is not None
            else parse_bool_flag(file_cfg.get("allow_loopback_dev"), default=True)
        )
        self.protect_dotenv_files: bool = (
            bool(protect_dotenv_files)
            if protect_dotenv_files is not None
            else parse_bool_flag(file_cfg.get("protect_dotenv_files"), default=False)
        )
        self.protect_host_credentials: bool = (
            bool(protect_host_credentials)
            if protect_host_credentials is not None
            else parse_bool_flag(file_cfg.get("protect_host_credentials"), default=True)
        )
        self.block_destructive_commands: bool = (
            bool(block_destructive_commands)
            if block_destructive_commands is not None
            else parse_bool_flag(file_cfg.get("block_destructive_commands"), default=True)
        )
        self.tray_enabled: bool = (
            bool(tray_enabled)
            if tray_enabled is not None
            else parse_bool_flag(file_cfg.get("tray_enabled"), default=True)
        )
        self.tunnel_mode: str = str(
            tunnel_mode if (tunnel_mode is not None and str(tunnel_mode).strip()) else (file_cfg.get("tunnel_mode") or DEFAULT_TUNNEL_MODE)
        ).strip() or DEFAULT_TUNNEL_MODE
        raw_pg_b = (
            public_gateway_base
            if (public_gateway_base is not None and str(public_gateway_base).strip())
            else (os.environ.get("COSMOS_PUBLIC_GATEWAY_BASE") or file_cfg.get("public_gateway_base") or DEFAULT_PUBLIC_GATEWAY_BASE)
        )
        self.public_gateway_base: str = _sanitize_public_gateway_base(raw_pg_b) or DEFAULT_PUBLIC_GATEWAY_BASE
        self.public_gateway_node_id: str = str(
            public_gateway_node_id if public_gateway_node_id is not None else (file_cfg.get("public_gateway_node_id") or "")
        ).strip()
        self.workers_dev_account_id: str = str(
            workers_dev_account_id if workers_dev_account_id is not None else (file_cfg.get("workers_dev_account_id") or "")
        ).strip()
        raw_wds = workers_dev_script_name if workers_dev_script_name is not None else file_cfg.get("workers_dev_script_name")
        self.workers_dev_script_name: str = (
            str(raw_wds).strip() if (raw_wds is not None and str(raw_wds).strip()) else DEFAULT_WORKERS_DEV_SCRIPT_NAME
        )
        self.workers_dev_subdomain: str = str(
            workers_dev_subdomain if workers_dev_subdomain is not None else (file_cfg.get("workers_dev_subdomain") or "")
        ).strip()
        self.workers_dev_custom_domain: str = str(
            workers_dev_custom_domain if workers_dev_custom_domain is not None else (file_cfg.get("workers_dev_custom_domain") or "")
        ).strip()

        init_gw_doc: Dict[str, Any] = dict(file_cfg)
        if tunnel_mode is not None and str(tunnel_mode).strip():
            init_gw_doc["tunnel_mode"] = self.tunnel_mode
            init_gw_doc.pop("gateways", None)
            init_gw_doc.pop("_gateways_mirrored_mode", None)
        elif not file_cfg:
            init_gw_doc["tunnel_mode"] = self.tunnel_mode
        self.gateways, self.selected_gateway = normalize_gateways_config(init_gw_doc)
        self.tunnel_mode = str(init_gw_doc.get("tunnel_mode") or self.tunnel_mode)
        self.pinned_gateway_urls: Tuple[str, ...] = tuple(init_gw_doc.get("pinned_gateway_urls") or ())
        raw_prev_non_ro = str(file_cfg.get("previous_non_readonly_tier") or "").strip().lower()
        if self.tier_key != "tier1_readonly":
            self.previous_non_readonly_tier: str = self.tier_key
        elif raw_prev_non_ro in ("tier2_workspace_edit", "tier3_workspace_dev", "tier4_full_power"):
            self.previous_non_readonly_tier = raw_prev_non_ro
        else:
            self.previous_non_readonly_tier = DEFAULT_TIER

        self.tier_epoch: int = 0
        self.workspace_epoch: int = 0
        try:
            self.policy_revision: int = max(0, int(file_cfg.get("policy_revision") or 0))
        except (TypeError, ValueError):
            self.policy_revision = 0
        try:
            self.policy_updated_at: float = float(file_cfg.get("policy_updated_at") or 0.0)
        except (TypeError, ValueError):
            self.policy_updated_at = 0.0
        self._auth_listeners: List[Callable[[Dict[str, Any]], None]] = []
        self._policy_listeners: List[Callable[["LiveRuntimePolicy"], None]] = []
        self._last_cfg_sig: Optional[Tuple[int, int]] = self._file_sig(self.cfg_path)
        self._last_auth_sig: Optional[Tuple[int, int]] = self._file_sig(auth_path)

        if self.keep_awake:
            self._safe_apply_keep_awake(True)
        self._notify_workspace_hook()

    @property
    def instance_id(self) -> str:
        return self._instance_id

    @property
    def annotation_mode(self) -> str:
        return self._annotation_mode

    @annotation_mode.setter
    def annotation_mode(self, value: Any) -> None:
        self._annotation_mode = parse_strict_annotation_mode(value)

    @property
    def approval_popups(self) -> bool:
        return self._annotation_mode == "strict"

    @approval_popups.setter
    def approval_popups(self, flag: Any) -> None:
        self._annotation_mode = "strict" if parse_bool_flag(flag, default=False) else "seamless"

    @property
    def primary_workspace(self) -> Path:
        return self.workspace_roots[0]

    @property
    def workspace(self) -> str:
        return str(self.workspace_roots[0])

    @property
    def short_tier_code(self) -> str:
        return to_short_tier_code(self.tier_key)

    @property
    def restrict_to_workspace(self) -> bool:
        return bool(self.tier_cfg.get("restrict_to_workspace", True))

    @property
    def allow_edit(self) -> bool:
        return bool(self.tier_cfg.get("allow_edit", False))

    @property
    def allow_exec(self) -> bool:
        return bool(self.tier_cfg.get("allow_exec", False))

    @property
    def allow_host_admin(self) -> bool:
        return bool(self.tier_cfg.get("allow_host_admin", False))

    def is_path_allowed(self, target: Path | str) -> bool:
        """Return True if `target` is inside any `workspace_roots` entry (or tier is L4 unrestricted)."""
        if not self.restrict_to_workspace:
            return True
        raw_s = str(target or "").strip()
        if not raw_s:
            return True
        cand = Path(expand_env_and_tilde(raw_s)).expanduser()
        if not cand.is_absolute():
            cand = (self.primary_workspace / cand).resolve()
        else:
            cand = cand.resolve()
        cand_norm = Path(os.path.normcase(str(cand)))
        for root in self.workspace_roots:
            root_norm = Path(os.path.normcase(str(root.resolve())))
            if cand_norm == root_norm or cand_norm.is_relative_to(root_norm):
                return True
        return False

    @classmethod
    def from_disk(cls, state_root: Path, eff_prefix: str = "pc") -> "LiveRuntimePolicy":
        st = Path(state_root).expanduser().resolve()
        eff_p = normalize_prefix(eff_prefix)
        cfg_p = resolve_service_cfg_path(st, eff_p)
        ws_roots: List[Path] = []
        if cfg_p.is_file():
            try:
                doc = json.loads(cfg_p.read_text(encoding="utf-8-sig"))
                if isinstance(doc, Mapping):
                    raw_ws = doc.get("workspace_roots") or ([doc["workspace"]] if doc.get("workspace") else [])
                    if isinstance(raw_ws, Iterable) and not isinstance(raw_ws, (str, bytes)):
                        ws_roots = [Path(str(p)).expanduser().resolve() for p in raw_ws if str(p).strip()]
            except Exception:
                ws_roots = []
        if not ws_roots:
            ws_roots = [st]
        inst = cls(
            workspace_roots=ws_roots,
            cfg_path=cfg_p,
            state_root=st,
            eff_prefix=eff_p,
        )
        inst.refresh()
        return inst

    def dynamic_tier_label(self, tier_override: str = "", tool_count: Optional[int] = None) -> str:
        t_eff = normalize_tier(tier_override) if tier_override else self.tier_key
        return format_dynamic_tier_label(
            t_eff,
            tool_count=tool_count,
            enabled_packs=self.enabled_packs,
            approval_popups=self.approval_popups,
            annotation_mode=self.annotation_mode,
            keep_awake=self.keep_awake,
        )

    def get_env_locks(self) -> Dict[str, Dict[str, str]]:
        """Return startup environment-locked policy fields (`{field: {'env_var': ..., 'reason': ...}}`)."""
        with self._lock:
            raw_locks = getattr(self, "_startup_env_locks", set()) or set()
            if not raw_locks:
                return {}
            details = getattr(self, "_startup_env_lock_details", {}) or {}
            default_vars = {
                "permission_tier": "COSMOS_MCP_PERMISSION_TIER",
                "workspace_roots": "COSMOS_MCP_WORKSPACE_ROOTS",
                "toolset_profile": "COSMOS_MCP_TOOLSET_PROFILE",
                "prompt_profile": "COSMOS_MCP_PROMPT_PROFILE",
                "enabled_tools": "COSMOS_MCP_ENABLED_TOOLS",
                "disabled_tools": "COSMOS_MCP_DISABLED_TOOLS",
                "enabled_packs": "COSMOS_MCP_ENABLED_PACKS",
            }
            out: Dict[str, Dict[str, str]] = {}
            for lk in sorted(raw_locks):
                pub_key = "permission_tier" if lk == "tier_key" else str(lk)
                det = details.get(pub_key)
                if isinstance(det, Mapping) and det.get("env_var"):
                    out[pub_key] = {
                        "env_var": str(det["env_var"]),
                        "reason": str(det.get("reason") or "由启动环境变量锁定"),
                    }
                else:
                    out[pub_key] = {
                        "env_var": default_vars.get(pub_key, f"COSMOS_MCP_{pub_key.upper()}"),
                        "reason": "由启动环境变量锁定",
                    }
            return out

    def _sync_secondary_config_projections_locked(self, authoritative_doc: Mapping[str, Any]) -> None:
        """One-way project authoritative `self.cfg_path` doc onto legacy `state/service.json`, `config/service_config.json`, & `config.json`.

        MUST ONLY be called inside `with get_file_lock(self.cfg_path):`. Never reads secondary files back into
        authoritative policy state and never swallows disk write errors.
        """
        if self.cfg_path is None:
            return
        auth_norm = os.path.normcase(str(self.cfg_path.resolve()))
        proj_doc: Dict[str, Any] = dict(authoritative_doc)
        if proj_doc.get("public_base") == "":
            proj_doc["public_url"] = ""
            proj_doc["public_base_url"] = ""
        if "workers_dev_custom_domain" in proj_doc:
            proj_doc["workers_custom_domain"] = proj_doc["workers_dev_custom_domain"]

        svc_name = f"service_{self.eff_prefix}.json" if self.eff_prefix != "pc" else "service.json"
        legacy_svc_cfg_name = (
            f"service_config_{self.eff_prefix}.json" if self.eff_prefix != "pc" else "service_config.json"
        )
        secondary_full_files: List[Path] = [
            self.state_root / "state" / svc_name,
            self.state_root / "config" / legacy_svc_cfg_name,
        ]
        if self.eff_prefix == "pc":
            secondary_full_files.append(self.state_root / "config" / "config.json")
        for sec_p in secondary_full_files:
            if sec_p.is_file() and os.path.normcase(str(sec_p.resolve())) != auth_norm:
                atomic_write_json(sec_p, dict(proj_doc))

        root_cfg = self.state_root / "config.json"
        if self.eff_prefix == "pc" and root_cfg.is_file() and os.path.normcase(str(root_cfg.resolve())) != auth_norm:
            root_doc: Dict[str, Any] = {}
            try:
                loaded_r = json.loads(root_cfg.read_text(encoding="utf-8-sig"))
                if isinstance(loaded_r, dict):
                    root_doc = dict(loaded_r)
            except Exception:
                root_doc = {}
            root_doc.update(proj_doc)
            atomic_write_json(root_cfg, root_doc)

    def to_status_dict(
        self,
        *,
        tool_count: Optional[int] = None,
        exposed_tools: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Return serialized runtime policy snapshot for Cosmos Studio and `/healthz` / status surfaces."""
        with self._lock:
            doc: Dict[str, Any] = {
                "version": PRODUCT_VERSION,
                "permission_tier": self.tier_key,
                "short_tier": self.short_tier_code,
                "permission_label": self.dynamic_tier_label(tool_count=tool_count),
                "policy_revision": int(getattr(self, "policy_revision", 0) or 0),
                "policy_updated_at": float(getattr(self, "policy_updated_at", 0.0) or 0.0),
                "env_locks": self.get_env_locks(),
                "toolset_profile": self.toolset_profile,
                "prompt_profile": self.prompt_profile,
                "instance_id": self.instance_id,
                "tool_prefix": self.tool_prefix,
                "device_label": self.device_label,
                "workspace": self.workspace,
                "workspace_roots": [str(p) for p in self.workspace_roots],
                "readonly_workspace_roots": [str(p) for p in self.readonly_workspace_roots],
                "scan_host_global_skills": self.scan_host_global_skills,
                "redact_project_secrets": self.redact_project_secrets,
                "enable_oneclick_token_route": self.enable_oneclick_token_route,
                "allow_loopback_dev": self.allow_loopback_dev,
                "protect_dotenv_files": self.protect_dotenv_files,
                "protect_host_credentials": self.protect_host_credentials,
                "block_destructive_commands": self.block_destructive_commands,
                "tray_enabled": self.tray_enabled,
                "tunnel_mode": self.tunnel_mode,
                "selected_gateway": self.selected_gateway,
                "gateways": {gid: dict(self.gateways[gid]) for gid in GATEWAY_IDS if gid in self.gateways},
                "pinned_gateway_urls": list(self.pinned_gateway_urls),
                "public_gateway_base": self.public_gateway_base,
                "public_gateway_node_id": self.public_gateway_node_id,
                "workers_dev_account_id": self.workers_dev_account_id,
                "workers_dev_script_name": self.workers_dev_script_name,
                "workers_dev_subdomain": self.workers_dev_subdomain,
                "workers_dev_custom_domain": self.workers_dev_custom_domain,
                "enabled_tools": list(self.enabled_tools),
                "disabled_tools": list(self.disabled_tools),
                "enabled_packs": list(self.enabled_packs),
                "keep_awake": self.keep_awake,
                "annotation_mode": self.annotation_mode,
                "approval_popups": self.approval_popups,
                "python_path": self.python_path,
                "state_root": str(self.state_root),
            }
            if tool_count is not None:
                doc["tool_count"] = int(tool_count)
            if exposed_tools is not None:
                doc["exposed_tools"] = list(exposed_tools)
            return doc

    def add_policy_listener(self, fn: Callable[["LiveRuntimePolicy"], None]) -> None:
        with self._lock:
            if fn not in self._policy_listeners:
                self._policy_listeners.append(fn)

    def add_auth_listener(self, fn: Callable[[Dict[str, Any]], None]) -> None:
        with self._lock:
            if fn not in self._auth_listeners:
                self._auth_listeners.append(fn)

    @staticmethod
    def _file_sig(fp: Optional[Path]) -> Optional[Tuple[int, int]]:
        if fp is None:
            return None
        try:
            st = fp.stat()
            return (int(st.st_mtime_ns), int(st.st_size))
        except OSError:
            return None

    def _safe_apply_keep_awake(self, enabled: bool) -> None:
        if self._on_awake_change is not None:
            try:
                self._on_awake_change(bool(enabled))
            except Exception:
                pass

    def _sync_conn_info_prefix_text(self) -> None:
        isolate = self.eff_prefix != "pc"
        conn_fn = conn_info_filename_for_prefix(self.eff_prefix)
        sec_fn = f"connection_{self.eff_prefix}.txt" if isolate else "connection.txt"
        for info_p in (self.state_root / conn_fn, self.state_root / "secrets" / sec_fn):
            if not info_p.is_file():
                continue
            try:
                old_txt = info_p.read_text(encoding="utf-8", errors="replace")
                new_txt = re.sub(
                    r"(当前设备标识\s*:\s*)([^\r\n(]+?)\s*\(工具前缀:\s*[a-zA-Z0-9_]+_\*\)",
                    lambda m: f"{m.group(1)}{self.device_label} (工具前缀: {self.tool_prefix}_*)",
                    old_txt,
                )
                if new_txt != old_txt:
                    atomic_write_text(info_p, new_txt, mode_override=0o600)
            except Exception:
                pass

    def _notify_workspace_hook(self) -> None:
        if self.guard is not None:
            self.guard.tool_prefix = self.tool_prefix
            try:
                setattr(self.guard, "redact_project_secrets", bool(self.redact_project_secrets))
            except Exception:
                pass
            try:
                extra_guard_kw: Dict[str, Any] = {}
                try:
                    sig_p = inspect.signature(self.guard.set_workspace_policy).parameters
                    if "redact_project_secrets" in sig_p:
                        extra_guard_kw["redact_project_secrets"] = self.redact_project_secrets
                except Exception:
                    pass
                self.guard.set_workspace_policy(
                    self.workspace_roots,
                    restrict_to_workspace=self.restrict_to_workspace,
                    tier_key=to_short_tier_code(self.tier_key),
                    readonly_workspace_roots=self.readonly_workspace_roots,
                    allow_host_global_skills=self.scan_host_global_skills,
                    protect_host_credentials=self.protect_host_credentials,
                    protect_dotenv_files=self.protect_dotenv_files,
                    block_destructive_commands=self.block_destructive_commands,
                    state_root=self.state_root,
                    product_root=self._product_root,
                    **extra_guard_kw,
                )
            except TypeError as exc:
                msg = str(exc)
                if "allow_host_global_skills" in msg or "unexpected keyword" in msg:
                    self.guard.set_workspace_policy(
                        self.workspace_roots,
                        restrict_to_workspace=self.restrict_to_workspace,
                        tier_key=to_short_tier_code(self.tier_key),
                        readonly_workspace_roots=self.readonly_workspace_roots,
                        state_root=self.state_root,
                        product_root=self._product_root,
                    )
                else:
                    raise
        if self._on_ws_change is not None:
            try:
                self._on_ws_change(self.workspace_roots, self.restrict_to_workspace, self.tier_key)
            except Exception:
                pass

    def _notify_policy_listeners(self) -> None:
        for fn in list(self._policy_listeners):
            try:
                fn(self)
            except Exception:
                pass

    def get_enabled_gateways(self) -> Dict[str, Dict[str, Any]]:
        """Return shallow copies of all currently enabled gateway slot configurations."""
        with self._lock:
            return {
                gid: dict(self.gateways[gid])
                for gid in GATEWAY_IDS
                if gid in self.gateways and bool(self.gateways[gid].get("enabled"))
            }

    def update_gateway_slot(
        self,
        gateway_id: str,
        *,
        enabled: Optional[bool] = None,
        submode: Optional[str] = None,
        public_url: Optional[str] = None,
        select: bool = False,
        make_selected: bool = False,
        extra_fields: Optional[Mapping[str, Any]] = None,
        persist: bool = True,
    ) -> Dict[str, Any]:
        """Thread-safely update ONLY `gateway_id` without disabling or wiping any other gateway slot."""
        gw_id = str(gateway_id or "").strip().lower()
        if gw_id not in GATEWAY_IDS:
            raise ValueError(f"Unknown gateway_id `{gateway_id}` (expected one of {GATEWAY_IDS}).")

        with self._lock:
            cur_doc: Dict[str, Any] = {}
            if self.cfg_path is not None and self.cfg_path.is_file():
                try:
                    loaded = json.loads(self.cfg_path.read_text(encoding="utf-8-sig"))
                    if isinstance(loaded, dict):
                        cur_doc = loaded
                except Exception:
                    cur_doc = {}

            next_gateways: Dict[str, Dict[str, Any]] = {
                gid: dict(self.gateways.get(gid) or {}) for gid in GATEWAY_IDS
            }
            if cur_doc:
                disk_gws, _ = normalize_gateways_config(dict(cur_doc))
                for gid in GATEWAY_IDS:
                    if not next_gateways.get(gid):
                        next_gateways[gid] = dict(disk_gws[gid])
                    elif gid != gw_id:
                        # Preserve URLs hot-refreshed by background tunnel supervisors on other slots
                        if disk_gws[gid].get("public_url") and not next_gateways[gid].get("public_url"):
                            next_gateways[gid]["public_url"] = disk_gws[gid]["public_url"]

            slot = dict(next_gateways.get(gw_id) or {})
            slot.setdefault("enabled", False)
            if gw_id == "instant":
                slot.setdefault("submode", "public_gateway")
            elif gw_id == "workers_dev":
                slot.setdefault("submode", "workers_dev")
            else:
                slot.setdefault("submode", "vps_hub")
            slot.setdefault("public_url", "")

            if enabled is not None:
                slot["enabled"] = bool(enabled)
            if submode is not None and str(submode).strip():
                clean_sub = str(submode).strip().lower()
                if gw_id == "instant":
                    if clean_sub == "srv_us":
                        clean_sub = "public_gateway"
                    if clean_sub not in INSTANT_SUBMODES:
                        raise ValueError(f"Invalid instant submode `{submode}` (expected {INSTANT_SUBMODES}).")
                    slot["submode"] = clean_sub
                elif gw_id == "workers_dev":
                    slot["submode"] = "workers_dev"
                else:
                    if clean_sub == "reverse_proxy":
                        clean_sub = "custom"
                    if clean_sub not in SELF_HOSTED_SUBMODES:
                        raise ValueError(f"Invalid self_hosted submode `{submode}` (expected {SELF_HOSTED_SUBMODES}).")
                    slot["submode"] = clean_sub
            if public_url is not None:
                raw_pu = str(public_url).strip().rstrip("/")
                slot["public_url"] = _clean_public_https_url(raw_pu) if raw_pu else ""
            if extra_fields:
                for ek, ev in extra_fields.items():
                    if ek not in ("gateway_id", "enabled", "submode", "public_url") and ev is not None:
                        slot[ek] = ev
                if gw_id == "workers_dev":
                    if extra_fields.get("account_id"):
                        self.workers_dev_account_id = str(extra_fields["account_id"]).strip()
                    if extra_fields.get("script_name"):
                        self.workers_dev_script_name = str(extra_fields["script_name"]).strip()
                    if extra_fields.get("subdomain"):
                        self.workers_dev_subdomain = str(extra_fields["subdomain"]).strip()
                    if extra_fields.get("custom_domain") is not None:
                        self.workers_dev_custom_domain = str(extra_fields["custom_domain"]).strip()

            slot["updated_at"] = round(time.time(), 3)
            next_gateways[gw_id] = slot

            next_sel = self.selected_gateway if self.selected_gateway in GATEWAY_IDS else "instant"
            if (select or make_selected) and slot["enabled"]:
                next_sel = gw_id

            en_ids = [gid for gid in GATEWAY_IDS if bool(next_gateways[gid].get("enabled"))]
            if en_ids:
                if next_sel not in en_ids:
                    next_sel = en_ids[0]
                self.tunnel_mode = str(next_gateways[next_sel].get("submode") or DEFAULT_TUNNEL_MODE)
            else:
                self.tunnel_mode = "local"

            self.gateways = next_gateways
            self.selected_gateway = next_sel
            merged_pin_src: Dict[str, Any] = dict(cur_doc)
            merged_pin_src["pinned_gateway_urls"] = list(
                dict.fromkeys([*self.pinned_gateway_urls, *(cur_doc.get("pinned_gateway_urls") or [])])
            )
            self.pinned_gateway_urls = tuple(collect_pinned_gateway_urls(self.gateways, merged_pin_src))

            if persist and self.cfg_path is not None:
                with get_file_lock(self.cfg_path):
                    if self.cfg_path.is_file():
                        try:
                            latest_loaded = json.loads(self.cfg_path.read_text(encoding="utf-8-sig"))
                            if isinstance(latest_loaded, dict):
                                cur_doc = latest_loaded
                        except Exception:
                            pass
                    cur_doc["gateways"] = {gid: dict(self.gateways[gid]) for gid in GATEWAY_IDS}
                    cur_doc["selected_gateway"] = self.selected_gateway
                    cur_doc["tunnel_mode"] = self.tunnel_mode
                    cur_doc["_gateways_mirrored_mode"] = self.tunnel_mode
                    cur_doc["pinned_gateway_urls"] = list(self.pinned_gateway_urls)
                    if gw_id == "workers_dev":
                        slot_raw_wd = _clean_public_https_url(slot.get("workers_dev_url"))
                        slot_pub = _clean_public_https_url(slot.get("public_url"))
                        existing_wd = _clean_public_https_url(cur_doc.get("workers_dev_url"))
                        if slot_raw_wd and ".workers.dev" in (urlsplit(slot_raw_wd).hostname or "").lower():
                            cur_doc["workers_dev_url"] = slot_raw_wd
                        elif slot_pub and (
                            ".workers.dev" in (urlsplit(slot_pub).hostname or "").lower()
                            or not existing_wd
                        ):
                            cur_doc["workers_dev_url"] = slot_pub
                        cur_doc["workers_dev_account_id"] = self.workers_dev_account_id
                        cur_doc["workers_dev_script_name"] = self.workers_dev_script_name
                        cur_doc["workers_dev_subdomain"] = self.workers_dev_subdomain
                        cur_doc["workers_dev_custom_domain"] = self.workers_dev_custom_domain
                    elif gw_id == "self_hosted":
                        if slot.get("submode") in ("vps_hub", "vps") and slot.get("public_url"):
                            cur_doc["vps_hub_url"] = slot["public_url"]
                        if slot.get("vps_ssh_target"):
                            cur_doc["vps_ssh"] = str(slot["vps_ssh_target"])
                        if slot.get("vps_ssh_port"):
                            cur_doc["vps_ssh_port"] = int(slot["vps_ssh_port"])
                        if slot.get("vps_remote_port"):
                            cur_doc["vps_remote_port"] = int(slot["vps_remote_port"])
                        if slot.get("vps_identity_file") is not None:
                            cur_doc["vps_identity_file"] = str(slot["vps_identity_file"])

                    if not en_ids:
                        cur_doc["public_base"] = ""
                        if "public_base_url" in cur_doc:
                            cur_doc["public_base_url"] = ""
                    else:
                        existing_top = _clean_public_https_url(cur_doc.get("public_base") or cur_doc.get("public_base_url"))
                        sel_url = _clean_public_https_url(self.gateways[self.selected_gateway].get("public_url"))
                        any_en_url = next(
                            (
                                _clean_public_https_url(self.gateways[eid].get("public_url"))
                                for eid in en_ids
                                if _clean_public_https_url(self.gateways[eid].get("public_url"))
                            ),
                            "",
                        )
                        # Never overwrite an active ready slot's public_base with an empty URL from a newly enabled secondary slot
                        enabled_urls = {
                            _clean_public_https_url(self.gateways[eid].get("public_url"))
                            for eid in en_ids
                            if _clean_public_https_url(self.gateways[eid].get("public_url"))
                        }
                        if sel_url and (gw_id == self.selected_gateway or not existing_top or existing_top not in enabled_urls):
                            cur_doc["public_base"] = sel_url
                            cur_doc["public_base_url"] = sel_url
                        elif (not existing_top or existing_top not in enabled_urls) and any_en_url:
                            cur_doc["public_base"] = any_en_url
                            cur_doc["public_base_url"] = any_en_url

                    now_ts = round(time.time(), 6)
                    next_rev = int(cur_doc.get("policy_revision") or 0) + 1
                    cur_doc["policy_revision"] = next_rev
                    cur_doc["policy_updated_at"] = now_ts
                    atomic_write_json(self.cfg_path, cur_doc)
                    self._sync_secondary_config_projections_locked(cur_doc)
                    self.policy_revision = next_rev
                    self.policy_updated_at = now_ts
                    self._last_cfg_sig = self._file_sig(self.cfg_path)

            self._notify_policy_listeners()
            return {
                "ok": True,
                "gateway_id": gw_id,
                **dict(self.gateways[gw_id]),
                "slot": dict(self.gateways[gw_id]),
                "selected_gateway": self.selected_gateway,
                "tunnel_mode": self.tunnel_mode,
                "gateways": {gid: dict(self.gateways[gid]) for gid in GATEWAY_IDS},
                "pinned_gateway_urls": list(self.pinned_gateway_urls),
            }

    @staticmethod
    def _roots_norm_tuple(roots: Tuple[Path, ...]) -> Tuple[str, ...]:
        return tuple(os.path.normcase(str(p)) for p in roots)

    def _enforce_startup_env_locks(
        self,
        *,
        tier_key: str = "",
        workspace: str = "",
        workspace_roots: Any = None,
        toolset_profile: str = "",
        prompt_profile: str = "",
        tool_prefix: str = "",
        enabled_tools: Any = None,
        disabled_tools: Any = None,
        enabled_packs: Any = None,
    ) -> None:
        env_locks = getattr(self, "_startup_env_locks", set())
        if not env_locks:
            return
        if tier_key and "tier_key" in env_locks:
            nt = parse_strict_tier(tier_key)
            if nt != self.tier_key:
                raise ValueError(
                    f"ERR_STARTUP_ENV_LOCKED: `permission_tier` is locked to `{self.tier_key}` by startup environment variable."
                )
        if (workspace_roots is not None or workspace) and "workspace_roots" in env_locks:
            cand_roots = normalize_workspace_roots(workspace_roots, legacy_workspace=workspace, create_missing=False)
            if self._roots_norm_tuple(cand_roots) != self._roots_norm_tuple(self.workspace_roots):
                raise ValueError(
                    "ERR_STARTUP_ENV_LOCKED: `workspace_roots` is locked by startup environment variable."
                )
        if toolset_profile and "toolset_profile" in env_locks:
            cand_ts = parse_strict_toolset_profile(toolset_profile)
            if cand_ts != self.toolset_profile:
                raise ValueError(
                    f"ERR_STARTUP_ENV_LOCKED: `toolset_profile` is locked to `{self.toolset_profile}` by startup environment variable."
                )
        if prompt_profile and "prompt_profile" in env_locks:
            cand_pr = parse_strict_prompt_profile(prompt_profile)
            if cand_pr != self.prompt_profile:
                raise ValueError(
                    f"ERR_STARTUP_ENV_LOCKED: `prompt_profile` is locked to `{self.prompt_profile}` by startup environment variable."
                )
        eff_pref = normalize_prefix(str(tool_prefix)) if (tool_prefix is not None and str(tool_prefix).strip()) else self.tool_prefix
        if enabled_tools is not None and "enabled_tools" in env_locks:
            cand_en = parse_tool_filter_spec(enabled_tools, active_prefix=eff_pref, strict=False)
            if tuple(cand_en) != tuple(self.enabled_tools):
                raise ValueError(
                    "ERR_STARTUP_ENV_LOCKED: `enabled_tools` is locked by startup environment variable."
                )
        if disabled_tools is not None and "disabled_tools" in env_locks:
            cand_dis = parse_tool_filter_spec(disabled_tools, active_prefix=eff_pref, strict=False)
            if tuple(cand_dis) != tuple(self.disabled_tools):
                raise ValueError(
                    "ERR_STARTUP_ENV_LOCKED: `disabled_tools` is locked by startup environment variable."
                )
        if enabled_packs is not None and "enabled_packs" in env_locks:
            cand_pk = parse_pack_spec(enabled_packs, strict=True)
            if tuple(cand_pk) != tuple(self.enabled_packs):
                raise ValueError(
                    "ERR_STARTUP_ENV_LOCKED: `enabled_packs` is locked by startup environment variable."
                )

    def _capture_state_snapshot(self) -> Dict[str, Any]:
        return {
            "tool_prefix": self.tool_prefix,
            "device_label": self.device_label,
            "tier_key": self.tier_key,
            "tier_cfg": dict(self.tier_cfg),
            "previous_non_readonly_tier": self.previous_non_readonly_tier,
            "tier_epoch": self.tier_epoch,
            "policy_revision": int(getattr(self, "policy_revision", 0) or 0),
            "policy_updated_at": float(getattr(self, "policy_updated_at", 0.0) or 0.0),
            "workspace_roots": self.workspace_roots,
            "readonly_workspace_roots": self.readonly_workspace_roots,
            "workspace_epoch": self.workspace_epoch,
            "toolset_profile": self.toolset_profile,
            "prompt_profile": self.prompt_profile,
            "enabled_tools": self.enabled_tools,
            "disabled_tools": self.disabled_tools,
            "_annotation_mode": self._annotation_mode,
            "python_path": self.python_path,
            "enabled_packs": self.enabled_packs,
            "keep_awake": self.keep_awake,
            "scan_host_global_skills": self.scan_host_global_skills,
            "redact_project_secrets": self.redact_project_secrets,
            "enable_oneclick_token_route": self.enable_oneclick_token_route,
            "allow_loopback_dev": self.allow_loopback_dev,
            "protect_dotenv_files": self.protect_dotenv_files,
            "protect_host_credentials": self.protect_host_credentials,
            "block_destructive_commands": self.block_destructive_commands,
            "tray_enabled": self.tray_enabled,
            "tunnel_mode": self.tunnel_mode,
            "gateways": {gid: dict(self.gateways[gid]) for gid in GATEWAY_IDS if gid in self.gateways},
            "selected_gateway": self.selected_gateway,
            "pinned_gateway_urls": self.pinned_gateway_urls,
            "public_gateway_base": self.public_gateway_base,
            "public_gateway_node_id": self.public_gateway_node_id,
            "workers_dev_account_id": self.workers_dev_account_id,
            "workers_dev_script_name": self.workers_dev_script_name,
            "workers_dev_subdomain": self.workers_dev_subdomain,
            "workers_dev_custom_domain": self.workers_dev_custom_domain,
            "_last_cfg_sig": self._last_cfg_sig,
            "_guard_tool_prefix": getattr(self.guard, "tool_prefix", None) if self.guard is not None else None,
        }

    def _restore_state_snapshot(self, snap: Mapping[str, Any]) -> None:
        self.tool_prefix = snap["tool_prefix"]
        self.device_label = snap["device_label"]
        self.tier_key = snap["tier_key"]
        self.tier_cfg = dict(snap["tier_cfg"])
        self.previous_non_readonly_tier = snap["previous_non_readonly_tier"]
        self.tier_epoch = snap["tier_epoch"]
        self.policy_revision = int(snap.get("policy_revision") or 0)
        self.policy_updated_at = float(snap.get("policy_updated_at") or 0.0)
        self.workspace_roots = snap["workspace_roots"]
        self.readonly_workspace_roots = snap["readonly_workspace_roots"]
        self.workspace_epoch = snap["workspace_epoch"]
        self.toolset_profile = snap["toolset_profile"]
        self.prompt_profile = snap["prompt_profile"]
        self.enabled_tools = snap["enabled_tools"]
        self.disabled_tools = snap["disabled_tools"]
        self._annotation_mode = snap["_annotation_mode"]
        self.python_path = snap["python_path"]
        self.enabled_packs = snap["enabled_packs"]
        self.keep_awake = snap["keep_awake"]
        self.scan_host_global_skills = snap["scan_host_global_skills"]
        self.redact_project_secrets = snap["redact_project_secrets"]
        self.enable_oneclick_token_route = snap["enable_oneclick_token_route"]
        self.allow_loopback_dev = snap["allow_loopback_dev"]
        self.protect_dotenv_files = snap["protect_dotenv_files"]
        self.protect_host_credentials = snap["protect_host_credentials"]
        self.block_destructive_commands = snap["block_destructive_commands"]
        self.tray_enabled = snap["tray_enabled"]
        self.tunnel_mode = snap["tunnel_mode"]
        self.gateways = {gid: dict(v) for gid, v in snap["gateways"].items()}
        self.selected_gateway = snap["selected_gateway"]
        self.pinned_gateway_urls = snap["pinned_gateway_urls"]
        self.public_gateway_base = snap["public_gateway_base"]
        self.public_gateway_node_id = snap["public_gateway_node_id"]
        self.workers_dev_account_id = snap["workers_dev_account_id"]
        self.workers_dev_script_name = snap["workers_dev_script_name"]
        self.workers_dev_subdomain = snap["workers_dev_subdomain"]
        self.workers_dev_custom_domain = snap["workers_dev_custom_domain"]
        self._last_cfg_sig = snap["_last_cfg_sig"]
        if self.guard is not None and snap["_guard_tool_prefix"] is not None:
            self.guard.tool_prefix = snap["_guard_tool_prefix"]

    @staticmethod
    def _validate_strict_workspace_roots(
        workspace_roots: Any = None,
        legacy_workspace: str = "",
    ) -> Tuple[Path, ...]:
        """Strictly validate explicit `workspace_roots` / `workspace` inputs without touching disk."""
        candidates: List[str] = []
        if workspace_roots is not None:
            if isinstance(workspace_roots, Path):
                raw_p = str(workspace_roots).strip()
                if "\x00" in raw_p:
                    raise ValueError("Invalid workspace_roots: path contains NUL byte.")
                if raw_p:
                    candidates.append(raw_p)
            elif isinstance(workspace_roots, str):
                if "\x00" in workspace_roots:
                    raise ValueError("Invalid workspace_roots: path contains NUL byte.")
                candidates.extend(_split_workspace_string(workspace_roots))
            elif isinstance(workspace_roots, (bytes, bytearray, Mapping)):
                raise ValueError(f"Invalid workspace_roots type: {type(workspace_roots).__name__}.")
            elif isinstance(workspace_roots, Iterable):
                for item in workspace_roots:
                    if not isinstance(item, (str, Path)):
                        raise ValueError(f"Invalid workspace_roots entry type: {type(item).__name__}.")
                    s = str(item).strip()
                    if "\x00" in s:
                        raise ValueError(f"Invalid workspace_roots entry `{s!r}`: contains NUL byte.")
                    if s:
                        candidates.append(s)
            else:
                raise ValueError(f"Invalid workspace_roots type: {type(workspace_roots).__name__}.")

        if legacy_workspace:
            if not isinstance(legacy_workspace, (str, Path)):
                raise ValueError(f"Invalid workspace type: {type(legacy_workspace).__name__}.")
            lw = str(legacy_workspace).strip()
            if "\x00" in lw:
                raise ValueError("Invalid workspace: path contains NUL byte.")
            if lw and lw not in candidates:
                candidates.insert(0, lw)

        cleaned_count = 0
        for raw_item in candidates:
            cleaned = raw_item.replace("\r", "").replace("\n", "").strip().strip("\"'")
            if not cleaned or "\x00" in cleaned:
                raise ValueError(f"Invalid workspace_roots entry `{raw_item!r}`.")
            cleaned_count += 1
        if cleaned_count == 0:
            raise ValueError("workspace_roots must contain at least one valid directory path.")

        return normalize_workspace_roots(
            workspace_roots,
            legacy_workspace=legacy_workspace,
            create_missing=False,
        )

    def _build_full_disk_doc(self) -> Dict[str, Any]:
        return {
            "permission_tier": self.tier_key,
            "previous_non_readonly_tier": self.previous_non_readonly_tier,
            "instance_id": self.instance_id,
            "tool_prefix": self.tool_prefix,
            "device_label": self.device_label,
            "toolset_profile": self.toolset_profile,
            "prompt_profile": self.prompt_profile,
            "workspace": self.workspace,
            "workspace_roots": [str(p) for p in self.workspace_roots],
            "readonly_workspace_roots": [str(p) for p in self.readonly_workspace_roots],
            "scan_host_global_skills": self.scan_host_global_skills,
            "redact_project_secrets": self.redact_project_secrets,
            "enable_oneclick_token_route": self.enable_oneclick_token_route,
            "allow_loopback_dev": self.allow_loopback_dev,
            "protect_dotenv_files": self.protect_dotenv_files,
            "protect_host_credentials": self.protect_host_credentials,
            "block_destructive_commands": self.block_destructive_commands,
            "tray_enabled": self.tray_enabled,
            "gateways": {gid: dict(self.gateways[gid]) for gid in GATEWAY_IDS if gid in self.gateways},
            "selected_gateway": self.selected_gateway,
            "tunnel_mode": self.tunnel_mode,
            "_gateways_mirrored_mode": self.tunnel_mode,
            "pinned_gateway_urls": list(self.pinned_gateway_urls),
            "public_gateway_base": self.public_gateway_base,
            "public_gateway_node_id": self.public_gateway_node_id,
            "workers_dev_account_id": self.workers_dev_account_id,
            "workers_dev_script_name": self.workers_dev_script_name,
            "workers_dev_subdomain": self.workers_dev_subdomain,
            "workers_dev_custom_domain": self.workers_dev_custom_domain,
            "enabled_tools": list(self.enabled_tools),
            "disabled_tools": list(self.disabled_tools),
            "enabled_packs": list(self.enabled_packs),
            "annotation_mode": self.annotation_mode,
            "approval_popups": self.approval_popups,
            "python_path": self.python_path,
            "keep_awake": self.keep_awake,
        }

    def _validate_and_plan_updates(
        self,
        *,
        tier_key: str = "",
        workspace: str = "",
        workspace_roots: Any = None,
        readonly_workspace_roots: Any = None,
        tool_prefix: str = "",
        device_label: str = "",
        toolset_profile: str = "",
        prompt_profile: str = "",
        enabled_tools: Any = None,
        disabled_tools: Any = None,
        approval_popups: Optional[bool] = None,
        annotation_mode: str = "",
        python_path: Optional[str] = None,
        enabled_packs: Any = None,
        keep_awake: Optional[bool] = None,
        scan_host_global_skills: Optional[bool] = None,
        redact_project_secrets: Optional[bool] = None,
        enable_oneclick_token_route: Optional[bool] = None,
        allow_loopback_dev: Optional[bool] = None,
        protect_dotenv_files: Optional[bool] = None,
        protect_host_credentials: Optional[bool] = None,
        block_destructive_commands: Optional[bool] = None,
        tray_enabled: Optional[bool] = None,
        tunnel_mode: Optional[str] = None,
        gateways: Optional[Mapping[str, Any]] = None,
        selected_gateway: Optional[str] = None,
        public_gateway_base: Optional[str] = None,
        public_gateway_node_id: Optional[str] = None,
        workers_dev_account_id: Optional[str] = None,
        workers_dev_script_name: Optional[str] = None,
        workers_dev_subdomain: Optional[str] = None,
        workers_dev_custom_domain: Optional[str] = None,
        extra_patch: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Validate every requested field upfront (zero memory/guard/disk side effects) and return a mutation plan."""
        plan: Dict[str, Any] = {}

        if extra_patch is not None:
            if not isinstance(extra_patch, Mapping):
                raise ValueError(f"Invalid extra_patch type: {type(extra_patch).__name__} (expected mapping).")
            plan["extra_patch"] = dict(extra_patch)
            if not tier_key and extra_patch.get("permission_tier"):
                tier_key = str(extra_patch["permission_tier"])

        if tool_prefix is not None and str(tool_prefix).strip():
            plan["tool_prefix"] = normalize_prefix(str(tool_prefix))
        if device_label is not None and str(device_label).strip():
            plan["device_label"] = str(device_label).strip()
        if tier_key:
            plan["tier_key"] = parse_strict_tier(tier_key)

        if workspace_roots is not None or workspace:
            plan["workspace_roots"] = self._validate_strict_workspace_roots(
                workspace_roots, legacy_workspace=workspace
            )

        eff_ws_roots = plan.get("workspace_roots", self.workspace_roots)
        if readonly_workspace_roots is not None:
            plan["readonly_workspace_roots"] = normalize_readonly_workspace_roots(
                readonly_workspace_roots, eff_ws_roots, strict=True
            )
            plan["_raw_readonly_workspace_roots"] = readonly_workspace_roots

        if toolset_profile:
            plan["toolset_profile"] = parse_strict_toolset_profile(toolset_profile)
        if prompt_profile:
            plan["prompt_profile"] = parse_strict_prompt_profile(prompt_profile)

        eff_prefix = plan.get("tool_prefix", self.tool_prefix)
        if enabled_tools is not None:
            plan["enabled_tools"] = parse_tool_filter_spec(enabled_tools, active_prefix=eff_prefix, strict=False)
        if disabled_tools is not None:
            plan["disabled_tools"] = parse_tool_filter_spec(disabled_tools, active_prefix=eff_prefix, strict=False)

        if annotation_mode:
            plan["annotation_mode"] = parse_strict_annotation_mode(annotation_mode)
        elif approval_popups is not None:
            plan["annotation_mode"] = "strict" if bool(approval_popups) else "seamless"

        if python_path is not None:
            plan["python_path"] = normalize_python_path(python_path)
        if enabled_packs is not None:
            plan["enabled_packs"] = parse_pack_spec(enabled_packs, strict=True)
        if keep_awake is not None:
            plan["keep_awake"] = bool(keep_awake)
        if scan_host_global_skills is not None:
            plan["scan_host_global_skills"] = parse_bool_flag(scan_host_global_skills, default=False)
        if redact_project_secrets is not None:
            plan["redact_project_secrets"] = parse_bool_flag(redact_project_secrets, default=False)
        if enable_oneclick_token_route is not None:
            plan["enable_oneclick_token_route"] = parse_bool_flag(enable_oneclick_token_route, default=False)
        if allow_loopback_dev is not None:
            plan["allow_loopback_dev"] = parse_bool_flag(allow_loopback_dev, default=True)
        if protect_dotenv_files is not None:
            plan["protect_dotenv_files"] = parse_bool_flag(protect_dotenv_files, default=False)
        if protect_host_credentials is not None:
            plan["protect_host_credentials"] = parse_bool_flag(protect_host_credentials, default=True)
        if block_destructive_commands is not None:
            plan["block_destructive_commands"] = parse_bool_flag(block_destructive_commands, default=True)
        if tray_enabled is not None:
            plan["tray_enabled"] = parse_bool_flag(tray_enabled, default=True)
        if public_gateway_base is not None:
            pg_b = str(public_gateway_base).strip().rstrip("/")
            plan["public_gateway_base"] = pg_b if pg_b else _default_public_gateway_base()
        if public_gateway_node_id is not None:
            plan["public_gateway_node_id"] = str(public_gateway_node_id).strip()
        if workers_dev_account_id is not None:
            plan["workers_dev_account_id"] = str(workers_dev_account_id).strip()
        if workers_dev_script_name is not None:
            wds = str(workers_dev_script_name).strip()
            plan["workers_dev_script_name"] = wds if wds else DEFAULT_WORKERS_DEV_SCRIPT_NAME
        if workers_dev_subdomain is not None:
            plan["workers_dev_subdomain"] = str(workers_dev_subdomain).strip()
        if workers_dev_custom_domain is not None:
            plan["workers_dev_custom_domain"] = str(workers_dev_custom_domain).strip()

        if selected_gateway is not None and str(selected_gateway).strip():
            cand_sel = str(selected_gateway).strip().lower()
            if cand_sel not in GATEWAY_IDS:
                raise ValueError(f"Unknown selected_gateway `{selected_gateway}` (expected one of {GATEWAY_IDS}).")
            plan["selected_gateway"] = cand_sel
        if gateways is not None:
            if not isinstance(gateways, Mapping):
                raise ValueError(f"Invalid gateways type: {type(gateways).__name__} (expected mapping).")
            plan["gateways"] = dict(gateways)
        if tunnel_mode is not None and str(tunnel_mode).strip():
            plan["tunnel_mode"] = str(tunnel_mode).strip()

        self._enforce_startup_env_locks(
            tier_key=tier_key,
            workspace=workspace,
            workspace_roots=workspace_roots,
            toolset_profile=toolset_profile,
            prompt_profile=prompt_profile,
            tool_prefix=tool_prefix,
            enabled_tools=enabled_tools,
            disabled_tools=disabled_tools,
            enabled_packs=enabled_packs,
        )
        return plan

    def _compute_gateway_update(
        self,
        plan: Mapping[str, Any],
        *,
        base_gateways: Mapping[str, Mapping[str, Any]],
        base_selected: str,
        base_tunnel_mode: str,
        base_pinned: Sequence[str],
        wd_account_id: str,
        wd_script_name: str,
        wd_subdomain: str,
        wd_custom_domain: str,
    ) -> Tuple[Dict[str, Dict[str, Any]], str, str, Tuple[str, ...]]:
        if "gateways" in plan:
            synth_doc: Dict[str, Any] = {
                "gateways": dict(plan["gateways"]),
                "selected_gateway": plan.get("selected_gateway", base_selected),
                "pinned_gateway_urls": list(base_pinned),
                "workers_dev_account_id": wd_account_id,
                "workers_dev_script_name": wd_script_name,
                "workers_dev_subdomain": wd_subdomain,
                "workers_dev_custom_domain": wd_custom_domain,
            }
            next_gws, next_sel = normalize_gateways_config(synth_doc)
            next_tm = str(synth_doc.get("tunnel_mode") or base_tunnel_mode)
            next_pinned = tuple(synth_doc.get("pinned_gateway_urls") or ())
            return next_gws, next_sel, next_tm, next_pinned

        if "tunnel_mode" in plan:
            new_tm = str(plan["tunnel_mode"])
            legacy_ctx: Dict[str, Any] = {"pinned_gateway_urls": list(base_pinned)}
            next_slots = {gid: dict(base_gateways.get(gid) or {}) for gid in GATEWAY_IDS}
            next_sel = _apply_legacy_mode_to_slots(next_slots, new_tm, legacy_ctx)
            next_pinned = tuple(collect_pinned_gateway_urls(next_slots, legacy_ctx))
            return next_slots, next_sel, new_tm, next_pinned

        if "selected_gateway" in plan:
            cand_sel = str(plan["selected_gateway"])
            next_slots = {gid: dict(base_gateways.get(gid) or {}) for gid in GATEWAY_IDS}
            en_ids = [gid for gid in GATEWAY_IDS if bool(next_slots.get(gid, {}).get("enabled"))]
            next_sel = base_selected
            next_tm = base_tunnel_mode
            if not en_ids or cand_sel in en_ids:
                next_sel = cand_sel
                if en_ids:
                    next_tm = str(next_slots[cand_sel].get("submode") or base_tunnel_mode)
            return next_slots, next_sel, next_tm, tuple(base_pinned)

        return (
            {gid: dict(base_gateways.get(gid) or {}) for gid in GATEWAY_IDS if gid in base_gateways},
            base_selected,
            base_tunnel_mode,
            tuple(base_pinned),
        )

    def _apply_plan_to_memory(
        self,
        plan: Mapping[str, Any],
        *,
        merged_doc: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[bool, Optional[bool], bool]:
        """Commit validated `plan` (and optional disk-merged fields) into in-memory attributes.

        Returns `(conn_info_dirty, keep_awake_changed_to, workspace_changed)`.
        """
        conn_info_dirty = False
        keep_awake_changed_to: Optional[bool] = None
        workspace_changed = False
        env_locks = getattr(self, "_startup_env_locks", set())

        if merged_doc is not None:
            if "tool_prefix" in merged_doc and "tool_prefix" not in plan:
                new_tp = _resolve_safe_tool_prefix(merged_doc.get("tool_prefix"), fallback=self.eff_prefix)
                if new_tp != self.tool_prefix:
                    self.tool_prefix = new_tp
                    conn_info_dirty = True
            if "device_label" in merged_doc and "device_label" not in plan:
                raw_lbl = str(merged_doc.get("device_label") or "").strip()
                if raw_lbl and raw_lbl != self.device_label:
                    self.device_label = raw_lbl
                    conn_info_dirty = True
            if "permission_tier" in merged_doc and "tier_key" not in plan and "tier_key" not in env_locks:
                disk_tier = normalize_tier(str(merged_doc.get("permission_tier") or self.tier_key))
                if disk_tier != self.tier_key:
                    if self.tier_key != "tier1_readonly" and disk_tier == "tier1_readonly":
                        self.previous_non_readonly_tier = self.tier_key
                    elif disk_tier != "tier1_readonly":
                        self.previous_non_readonly_tier = disk_tier
                    self.tier_epoch += 1
                    self.tier_key = disk_tier
                    self.tier_cfg = dict(PERMISSION_TIERS[disk_tier])
            if "previous_non_readonly_tier" in merged_doc and "tier_key" not in plan:
                cand_prev = str(merged_doc.get("previous_non_readonly_tier") or "").strip().lower()
                if cand_prev in ("tier2_workspace_edit", "tier3_workspace_dev", "tier4_full_power"):
                    self.previous_non_readonly_tier = cand_prev
            has_ws_disk = (
                ("workspace_roots" in merged_doc)
                or ("workspace" in merged_doc)
                or ("workspace_root" in merged_doc)
            )
            if has_ws_disk and "workspace_roots" not in plan and "workspace_roots" not in env_locks:
                disk_roots = normalize_workspace_roots(
                    merged_doc.get("workspace_roots"),
                    legacy_workspace=str(merged_doc.get("workspace") or merged_doc.get("workspace_root") or ""),
                    create_missing=False,
                )
                if self._roots_norm_tuple(disk_roots) != self._roots_norm_tuple(self.workspace_roots):
                    self.workspace_epoch += 1
                    workspace_changed = True
                self.workspace_roots = disk_roots
            if "readonly_workspace_roots" in merged_doc and "readonly_workspace_roots" not in plan:
                self.readonly_workspace_roots = normalize_readonly_workspace_roots(
                    merged_doc.get("readonly_workspace_roots"), self.workspace_roots
                )
            if "toolset_profile" in merged_doc and "toolset_profile" not in plan and "toolset_profile" not in env_locks:
                self.toolset_profile = normalize_toolset_profile(str(merged_doc.get("toolset_profile") or ""))
            if "prompt_profile" in merged_doc and "prompt_profile" not in plan and "prompt_profile" not in env_locks:
                self.prompt_profile = normalize_prompt_profile(str(merged_doc.get("prompt_profile") or ""))
            if "enabled_tools" in merged_doc and "enabled_tools" not in plan and "enabled_tools" not in env_locks:
                self.enabled_tools = parse_tool_filter_spec(merged_doc.get("enabled_tools"), active_prefix=self.tool_prefix)
            if "disabled_tools" in merged_doc and "disabled_tools" not in plan and "disabled_tools" not in env_locks:
                self.disabled_tools = parse_tool_filter_spec(merged_doc.get("disabled_tools"), active_prefix=self.tool_prefix)
            if "enabled_packs" in merged_doc and "enabled_packs" not in plan and "enabled_packs" not in env_locks:
                self.enabled_packs = parse_pack_spec(merged_doc.get("enabled_packs"), strict=False)
            if "scan_host_global_skills" in merged_doc and "scan_host_global_skills" not in plan:
                self.scan_host_global_skills = parse_bool_flag(merged_doc.get("scan_host_global_skills"), default=False)
            if "redact_project_secrets" in merged_doc and "redact_project_secrets" not in plan:
                self.redact_project_secrets = parse_bool_flag(merged_doc.get("redact_project_secrets"), default=False)
            if "enable_oneclick_token_route" in merged_doc and "enable_oneclick_token_route" not in plan:
                self.enable_oneclick_token_route = parse_bool_flag(
                    merged_doc.get("enable_oneclick_token_route"), default=False
                )
            if "allow_loopback_dev" in merged_doc and "allow_loopback_dev" not in plan:
                self.allow_loopback_dev = parse_bool_flag(merged_doc.get("allow_loopback_dev"), default=True)
            if "protect_dotenv_files" in merged_doc and "protect_dotenv_files" not in plan:
                self.protect_dotenv_files = parse_bool_flag(merged_doc.get("protect_dotenv_files"), default=False)
            if "protect_host_credentials" in merged_doc and "protect_host_credentials" not in plan:
                self.protect_host_credentials = parse_bool_flag(merged_doc.get("protect_host_credentials"), default=True)
            if "block_destructive_commands" in merged_doc and "block_destructive_commands" not in plan:
                self.block_destructive_commands = parse_bool_flag(merged_doc.get("block_destructive_commands"), default=True)
            if "tray_enabled" in merged_doc and "tray_enabled" not in plan:
                self.tray_enabled = parse_bool_flag(merged_doc.get("tray_enabled"), default=True)
            if "annotation_mode" in merged_doc and "annotation_mode" not in plan:
                raw_ann = str(merged_doc.get("annotation_mode") or "").strip()
                if raw_ann:
                    self._annotation_mode = normalize_annotation_mode(raw_ann)
            elif "approval_popups" in merged_doc and "annotation_mode" not in plan:
                self._annotation_mode = (
                    "strict" if parse_bool_flag(merged_doc.get("approval_popups"), default=False) else "seamless"
                )
            if "python_path" in merged_doc and "python_path" not in plan:
                self.python_path = normalize_python_path(merged_doc.get("python_path"))
            if "keep_awake" in merged_doc and "keep_awake" not in plan:
                new_ka_d = parse_bool_flag(merged_doc.get("keep_awake"), default=True)
                if new_ka_d != self.keep_awake:
                    self.keep_awake = new_ka_d
                    keep_awake_changed_to = new_ka_d
            if "public_gateway_base" in merged_doc and "public_gateway_base" not in plan:
                pg_d = str(merged_doc.get("public_gateway_base") or "").strip().rstrip("/")
                if pg_d:
                    self.public_gateway_base = pg_d
            if "public_gateway_node_id" in merged_doc and "public_gateway_node_id" not in plan:
                self.public_gateway_node_id = str(merged_doc.get("public_gateway_node_id") or "").strip()
            if "workers_dev_account_id" in merged_doc and "workers_dev_account_id" not in plan:
                self.workers_dev_account_id = str(merged_doc.get("workers_dev_account_id") or "").strip()
            if "workers_dev_script_name" in merged_doc and "workers_dev_script_name" not in plan:
                sn_d = str(merged_doc.get("workers_dev_script_name") or "").strip()
                self.workers_dev_script_name = sn_d if sn_d else DEFAULT_WORKERS_DEV_SCRIPT_NAME
            if "workers_dev_subdomain" in merged_doc and "workers_dev_subdomain" not in plan:
                self.workers_dev_subdomain = str(merged_doc.get("workers_dev_subdomain") or "").strip()
            if "workers_dev_custom_domain" in merged_doc and "workers_dev_custom_domain" not in plan:
                self.workers_dev_custom_domain = str(merged_doc.get("workers_dev_custom_domain") or "").strip()
            if (
                "gateways" not in plan
                and "tunnel_mode" not in plan
                and "selected_gateway" not in plan
                and ("gateways" in merged_doc or "tunnel_mode" in merged_doc)
            ):
                gw_copy = dict(merged_doc)
                self.gateways, self.selected_gateway = normalize_gateways_config(gw_copy)
                self.tunnel_mode = str(gw_copy.get("tunnel_mode") or self.tunnel_mode)
                self.pinned_gateway_urls = tuple(gw_copy.get("pinned_gateway_urls") or ())

        if "tool_prefix" in plan:
            new_tp = plan["tool_prefix"]
            if new_tp != self.tool_prefix:
                self.tool_prefix = new_tp
                conn_info_dirty = True
            if self.guard is not None:
                self.guard.tool_prefix = self.tool_prefix
        if "device_label" in plan:
            new_lbl = plan["device_label"]
            if new_lbl != self.device_label:
                self.device_label = new_lbl
                conn_info_dirty = True
        if "tier_key" in plan:
            nt = plan["tier_key"]
            if nt != self.tier_key:
                if self.tier_key != "tier1_readonly" and nt == "tier1_readonly":
                    self.previous_non_readonly_tier = self.tier_key
                elif nt != "tier1_readonly":
                    self.previous_non_readonly_tier = nt
                self.tier_epoch += 1
            elif nt != "tier1_readonly":
                self.previous_non_readonly_tier = nt
            self.tier_key = nt
            self.tier_cfg = dict(PERMISSION_TIERS[nt])
        if "workspace_roots" in plan:
            new_roots = plan["workspace_roots"]
            if self._roots_norm_tuple(new_roots) != self._roots_norm_tuple(self.workspace_roots):
                self.workspace_epoch += 1
            self.workspace_roots = new_roots
            workspace_changed = True
            if "readonly_workspace_roots" not in plan:
                self.readonly_workspace_roots = normalize_readonly_workspace_roots(
                    self.readonly_workspace_roots, self.workspace_roots
                )
        if "readonly_workspace_roots" in plan:
            self.readonly_workspace_roots = normalize_readonly_workspace_roots(
                plan["readonly_workspace_roots"], self.workspace_roots, strict=True
            )
        if "toolset_profile" in plan:
            self.toolset_profile = plan["toolset_profile"]
        if "prompt_profile" in plan:
            self.prompt_profile = plan["prompt_profile"]
        if "enabled_tools" in plan:
            self.enabled_tools = plan["enabled_tools"]
        if "disabled_tools" in plan:
            self.disabled_tools = plan["disabled_tools"]
        if "annotation_mode" in plan:
            self._annotation_mode = plan["annotation_mode"]
        if "python_path" in plan:
            self.python_path = plan["python_path"]
        if "enabled_packs" in plan:
            self.enabled_packs = plan["enabled_packs"]
        if "keep_awake" in plan:
            new_ka = bool(plan["keep_awake"])
            if new_ka != self.keep_awake:
                self.keep_awake = new_ka
                keep_awake_changed_to = new_ka
        if "scan_host_global_skills" in plan:
            self.scan_host_global_skills = plan["scan_host_global_skills"]
        if "redact_project_secrets" in plan:
            self.redact_project_secrets = plan["redact_project_secrets"]
        if "enable_oneclick_token_route" in plan:
            self.enable_oneclick_token_route = plan["enable_oneclick_token_route"]
        if "allow_loopback_dev" in plan:
            self.allow_loopback_dev = plan["allow_loopback_dev"]
        if "protect_dotenv_files" in plan:
            self.protect_dotenv_files = plan["protect_dotenv_files"]
        if "protect_host_credentials" in plan:
            self.protect_host_credentials = plan["protect_host_credentials"]
        if "block_destructive_commands" in plan:
            self.block_destructive_commands = plan["block_destructive_commands"]
        if "tray_enabled" in plan:
            self.tray_enabled = plan["tray_enabled"]
        if "public_gateway_base" in plan:
            self.public_gateway_base = plan["public_gateway_base"]
        if "public_gateway_node_id" in plan:
            self.public_gateway_node_id = plan["public_gateway_node_id"]
        if "workers_dev_account_id" in plan:
            self.workers_dev_account_id = plan["workers_dev_account_id"]
        if "workers_dev_script_name" in plan:
            self.workers_dev_script_name = plan["workers_dev_script_name"]
        if "workers_dev_subdomain" in plan:
            self.workers_dev_subdomain = plan["workers_dev_subdomain"]
        if "workers_dev_custom_domain" in plan:
            self.workers_dev_custom_domain = plan["workers_dev_custom_domain"]

        if "gateways" in plan or "tunnel_mode" in plan or "selected_gateway" in plan:
            next_gws, next_sel, next_tm, next_pinned = self._compute_gateway_update(
                plan,
                base_gateways=self.gateways,
                base_selected=self.selected_gateway,
                base_tunnel_mode=self.tunnel_mode,
                base_pinned=self.pinned_gateway_urls,
                wd_account_id=self.workers_dev_account_id,
                wd_script_name=self.workers_dev_script_name,
                wd_subdomain=self.workers_dev_subdomain,
                wd_custom_domain=self.workers_dev_custom_domain,
            )
            self.gateways = next_gws
            self.selected_gateway = next_sel
            self.tunnel_mode = next_tm
            self.pinned_gateway_urls = next_pinned

        extra_p = plan.get("extra_patch")
        if isinstance(extra_p, Mapping):
            ep_gws = extra_p.get("gateways")
            if isinstance(ep_gws, Mapping):
                for gid, g_sub in ep_gws.items():
                    if gid in GATEWAY_IDS and isinstance(g_sub, Mapping):
                        slot_m = dict(self.gateways.get(gid) or {})
                        for fk, fv in g_sub.items():
                            if fv is not None:
                                slot_m[fk] = fv
                        self.gateways[gid] = slot_m
            if extra_p.get("selected_gateway") in GATEWAY_IDS:
                self.selected_gateway = str(extra_p["selected_gateway"])
            if extra_p.get("tunnel_mode"):
                self.tunnel_mode = str(extra_p["tunnel_mode"])
            if isinstance(extra_p.get("pinned_gateway_urls"), (list, tuple)):
                self.pinned_gateway_urls = tuple(str(x) for x in extra_p["pinned_gateway_urls"] if str(x).strip())

        if merged_doc is not None:
            if isinstance(merged_doc.get("gateways"), Mapping):
                for gid, g_disk in merged_doc["gateways"].items():
                    if gid in GATEWAY_IDS and isinstance(g_disk, Mapping):
                        slot_m = dict(self.gateways.get(gid) or {})
                        for fk, fv in g_disk.items():
                            if fv is not None:
                                slot_m[fk] = fv
                        self.gateways[gid] = slot_m
            if "policy_revision" in merged_doc:
                with contextlib.suppress(TypeError, ValueError):
                    self.policy_revision = max(0, int(merged_doc["policy_revision"]))
            if "policy_updated_at" in merged_doc:
                with contextlib.suppress(TypeError, ValueError):
                    self.policy_updated_at = float(merged_doc["policy_updated_at"])

        return conn_info_dirty, keep_awake_changed_to, workspace_changed

    def apply_direct(
        self,
        *,
        tier_key: str = "",
        workspace: str = "",
        workspace_roots: Any = None,
        readonly_workspace_roots: Any = None,
        tool_prefix: str = "",
        device_label: str = "",
        toolset_profile: str = "",
        prompt_profile: str = "",
        enabled_tools: Any = None,
        disabled_tools: Any = None,
        approval_popups: Optional[bool] = None,
        annotation_mode: str = "",
        python_path: Optional[str] = None,
        enabled_packs: Any = None,
        keep_awake: Optional[bool] = None,
        scan_host_global_skills: Optional[bool] = None,
        redact_project_secrets: Optional[bool] = None,
        enable_oneclick_token_route: Optional[bool] = None,
        allow_loopback_dev: Optional[bool] = None,
        protect_dotenv_files: Optional[bool] = None,
        protect_host_credentials: Optional[bool] = None,
        block_destructive_commands: Optional[bool] = None,
        tray_enabled: Optional[bool] = None,
        tunnel_mode: Optional[str] = None,
        gateways: Optional[Mapping[str, Any]] = None,
        selected_gateway: Optional[str] = None,
        public_gateway_base: Optional[str] = None,
        public_gateway_node_id: Optional[str] = None,
        workers_dev_account_id: Optional[str] = None,
        workers_dev_script_name: Optional[str] = None,
        workers_dev_subdomain: Optional[str] = None,
        workers_dev_custom_domain: Optional[str] = None,
        extra_patch: Optional[Mapping[str, Any]] = None,
        _notify_listeners: bool = True,
    ) -> Tuple[str, Dict[str, Any], str]:
        with self._lock:
            plan = self._validate_and_plan_updates(
                tier_key=tier_key,
                workspace=workspace,
                workspace_roots=workspace_roots,
                readonly_workspace_roots=readonly_workspace_roots,
                tool_prefix=tool_prefix,
                device_label=device_label,
                toolset_profile=toolset_profile,
                prompt_profile=prompt_profile,
                enabled_tools=enabled_tools,
                disabled_tools=disabled_tools,
                approval_popups=approval_popups,
                annotation_mode=annotation_mode,
                python_path=python_path,
                enabled_packs=enabled_packs,
                keep_awake=keep_awake,
                scan_host_global_skills=scan_host_global_skills,
                redact_project_secrets=redact_project_secrets,
                enable_oneclick_token_route=enable_oneclick_token_route,
                allow_loopback_dev=allow_loopback_dev,
                protect_dotenv_files=protect_dotenv_files,
                protect_host_credentials=protect_host_credentials,
                block_destructive_commands=block_destructive_commands,
                tray_enabled=tray_enabled,
                tunnel_mode=tunnel_mode,
                gateways=gateways,
                selected_gateway=selected_gateway,
                public_gateway_base=public_gateway_base,
                public_gateway_node_id=public_gateway_node_id,
                workers_dev_account_id=workers_dev_account_id,
                workers_dev_script_name=workers_dev_script_name,
                workers_dev_subdomain=workers_dev_subdomain,
                workers_dev_custom_domain=workers_dev_custom_domain,
                extra_patch=extra_patch,
            )
            prev_snap = self._capture_state_snapshot()
            try:
                if "workspace_roots" in plan:
                    for root_p in plan["workspace_roots"]:
                        root_p.mkdir(parents=True, exist_ok=True)
                conn_info_dirty, keep_awake_changed_to, workspace_changed = self._apply_plan_to_memory(plan)
                self.policy_revision = int(getattr(self, "policy_revision", 0) or 0) + 1
                self.policy_updated_at = round(time.time(), 6)
                self._notify_workspace_hook()
            except BaseException:
                self._restore_state_snapshot(prev_snap)
                raise

            if workspace_changed:
                record_known_workspaces(self.state_root, self.workspace_roots)
            if keep_awake_changed_to is not None:
                self._safe_apply_keep_awake(keep_awake_changed_to)
            if conn_info_dirty:
                self._sync_conn_info_prefix_text()
            if _notify_listeners:
                self._notify_policy_listeners()
            self._last_cfg_sig = self._file_sig(self.cfg_path)
            return self.tier_key, dict(self.tier_cfg), self.workspace

    def persist_changes(
        self,
        *,
        tier_key: str = "",
        workspace: str = "",
        workspace_roots: Any = None,
        readonly_workspace_roots: Any = None,
        tool_prefix: str = "",
        device_label: str = "",
        toolset_profile: str = "",
        prompt_profile: str = "",
        enabled_tools: Any = None,
        disabled_tools: Any = None,
        approval_popups: Optional[bool] = None,
        annotation_mode: str = "",
        python_path: Optional[str] = None,
        enabled_packs: Any = None,
        keep_awake: Optional[bool] = None,
        scan_host_global_skills: Optional[bool] = None,
        redact_project_secrets: Optional[bool] = None,
        enable_oneclick_token_route: Optional[bool] = None,
        allow_loopback_dev: Optional[bool] = None,
        protect_dotenv_files: Optional[bool] = None,
        protect_host_credentials: Optional[bool] = None,
        block_destructive_commands: Optional[bool] = None,
        tray_enabled: Optional[bool] = None,
        tunnel_mode: Optional[str] = None,
        gateways: Optional[Mapping[str, Any]] = None,
        selected_gateway: Optional[str] = None,
        public_gateway_base: Optional[str] = None,
        public_gateway_node_id: Optional[str] = None,
        workers_dev_account_id: Optional[str] = None,
        workers_dev_script_name: Optional[str] = None,
        workers_dev_subdomain: Optional[str] = None,
        workers_dev_custom_domain: Optional[str] = None,
        extra_patch: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[str, Dict[str, Any], str]:
        """Validate upfront, atomically patch-merge & persist under CrossProcessFileLock, then commit memory & guard."""
        with self._lock:
            plan = self._validate_and_plan_updates(
                tier_key=tier_key,
                workspace=workspace,
                workspace_roots=workspace_roots,
                readonly_workspace_roots=readonly_workspace_roots,
                tool_prefix=tool_prefix,
                device_label=device_label,
                toolset_profile=toolset_profile,
                prompt_profile=prompt_profile,
                enabled_tools=enabled_tools,
                disabled_tools=disabled_tools,
                approval_popups=approval_popups,
                annotation_mode=annotation_mode,
                python_path=python_path,
                enabled_packs=enabled_packs,
                keep_awake=keep_awake,
                scan_host_global_skills=scan_host_global_skills,
                redact_project_secrets=redact_project_secrets,
                enable_oneclick_token_route=enable_oneclick_token_route,
                allow_loopback_dev=allow_loopback_dev,
                protect_dotenv_files=protect_dotenv_files,
                protect_host_credentials=protect_host_credentials,
                block_destructive_commands=block_destructive_commands,
                tray_enabled=tray_enabled,
                tunnel_mode=tunnel_mode,
                gateways=gateways,
                selected_gateway=selected_gateway,
                public_gateway_base=public_gateway_base,
                public_gateway_node_id=public_gateway_node_id,
                workers_dev_account_id=workers_dev_account_id,
                workers_dev_script_name=workers_dev_script_name,
                workers_dev_subdomain=workers_dev_subdomain,
                workers_dev_custom_domain=workers_dev_custom_domain,
                extra_patch=extra_patch,
            )

            if self.cfg_path is None:
                return self.apply_direct(
                    tier_key=tier_key,
                    workspace=workspace,
                    workspace_roots=workspace_roots,
                    readonly_workspace_roots=readonly_workspace_roots,
                    tool_prefix=tool_prefix,
                    device_label=device_label,
                    toolset_profile=toolset_profile,
                    prompt_profile=prompt_profile,
                    enabled_tools=enabled_tools,
                    disabled_tools=disabled_tools,
                    approval_popups=approval_popups,
                    annotation_mode=annotation_mode,
                    python_path=python_path,
                    enabled_packs=enabled_packs,
                    keep_awake=keep_awake,
                    scan_host_global_skills=scan_host_global_skills,
                    redact_project_secrets=redact_project_secrets,
                    enable_oneclick_token_route=enable_oneclick_token_route,
                    allow_loopback_dev=allow_loopback_dev,
                    protect_dotenv_files=protect_dotenv_files,
                    protect_host_credentials=protect_host_credentials,
                    block_destructive_commands=block_destructive_commands,
                    tray_enabled=tray_enabled,
                    tunnel_mode=tunnel_mode,
                    gateways=gateways,
                    selected_gateway=selected_gateway,
                    public_gateway_base=public_gateway_base,
                    public_gateway_node_id=public_gateway_node_id,
                    workers_dev_account_id=workers_dev_account_id,
                    workers_dev_script_name=workers_dev_script_name,
                    workers_dev_subdomain=workers_dev_subdomain,
                    workers_dev_custom_domain=workers_dev_custom_domain,
                    extra_patch=extra_patch,
                )

            conn_info_dirty = False
            keep_awake_changed_to: Optional[bool] = None
            workspace_changed = False
            with get_file_lock(self.cfg_path):
                had_file = self.cfg_path.is_file()
                pre_write_bytes: Optional[bytes] = None
                disk_doc: Dict[str, Any] = {}
                if had_file:
                    pre_write_bytes = self.cfg_path.read_bytes()
                    raw_txt = pre_write_bytes.decode("utf-8-sig")
                    if raw_txt.strip():
                        loaded = json.loads(raw_txt)
                        if isinstance(loaded, dict):
                            disk_doc = loaded

                merged_doc: Dict[str, Any] = dict(disk_doc) if had_file else self._build_full_disk_doc()

                # Patch ONLY fields explicitly requested in `plan` onto latest disk state (A1)
                if "tool_prefix" in plan:
                    merged_doc["tool_prefix"] = plan["tool_prefix"]
                    merged_doc.setdefault("instance_id", self.instance_id)
                if "device_label" in plan:
                    merged_doc["device_label"] = plan["device_label"]
                if "tier_key" in plan:
                    nt = plan["tier_key"]
                    base_tier = normalize_tier(str(disk_doc.get("permission_tier") or self.tier_key))
                    base_prev = str(
                        disk_doc.get("previous_non_readonly_tier") or self.previous_non_readonly_tier
                    ).strip().lower()
                    if base_tier != "tier1_readonly" and nt == "tier1_readonly":
                        next_prev = base_tier
                    elif nt != "tier1_readonly":
                        next_prev = nt
                    else:
                        next_prev = (
                            base_prev
                            if base_prev in ("tier2_workspace_edit", "tier3_workspace_dev", "tier4_full_power")
                            else DEFAULT_TIER
                        )
                    merged_doc["permission_tier"] = nt
                    merged_doc["previous_non_readonly_tier"] = next_prev

                if "workspace_roots" in plan:
                    ws_tuple = plan["workspace_roots"]
                    merged_doc["workspace"] = str(ws_tuple[0])
                    merged_doc["workspace_roots"] = [str(p) for p in ws_tuple]
                    if "readonly_workspace_roots" not in plan:
                        existing_ro = (
                            disk_doc.get("readonly_workspace_roots")
                            if (had_file and "readonly_workspace_roots" in disk_doc)
                            else self.readonly_workspace_roots
                        )
                        trimmed_ro = normalize_readonly_workspace_roots(existing_ro, ws_tuple, strict=False)
                        merged_doc["readonly_workspace_roots"] = [str(p) for p in trimmed_ro]

                if "readonly_workspace_roots" in plan:
                    if "workspace_roots" in plan:
                        eff_disk_roots = plan["workspace_roots"]
                    elif had_file and (
                        "workspace_roots" in disk_doc or "workspace" in disk_doc or "workspace_root" in disk_doc
                    ):
                        eff_disk_roots = normalize_workspace_roots(
                            disk_doc.get("workspace_roots"),
                            legacy_workspace=str(disk_doc.get("workspace") or disk_doc.get("workspace_root") or ""),
                            create_missing=False,
                        )
                    else:
                        eff_disk_roots = self.workspace_roots
                    ro_tuple = normalize_readonly_workspace_roots(
                        plan["_raw_readonly_workspace_roots"], eff_disk_roots, strict=True
                    )
                    plan["readonly_workspace_roots"] = ro_tuple
                    merged_doc["readonly_workspace_roots"] = [str(p) for p in ro_tuple]

                if "toolset_profile" in plan:
                    merged_doc["toolset_profile"] = plan["toolset_profile"]
                if "prompt_profile" in plan:
                    merged_doc["prompt_profile"] = plan["prompt_profile"]
                if "enabled_tools" in plan:
                    merged_doc["enabled_tools"] = list(plan["enabled_tools"])
                if "disabled_tools" in plan:
                    merged_doc["disabled_tools"] = list(plan["disabled_tools"])
                if "enabled_packs" in plan:
                    merged_doc["enabled_packs"] = list(plan["enabled_packs"])
                if "annotation_mode" in plan:
                    merged_doc["annotation_mode"] = plan["annotation_mode"]
                    merged_doc["approval_popups"] = plan["annotation_mode"] == "strict"
                if "python_path" in plan:
                    merged_doc["python_path"] = plan["python_path"]
                if "keep_awake" in plan:
                    merged_doc["keep_awake"] = plan["keep_awake"]
                if "scan_host_global_skills" in plan:
                    merged_doc["scan_host_global_skills"] = plan["scan_host_global_skills"]
                if "redact_project_secrets" in plan:
                    merged_doc["redact_project_secrets"] = plan["redact_project_secrets"]
                if "enable_oneclick_token_route" in plan:
                    merged_doc["enable_oneclick_token_route"] = plan["enable_oneclick_token_route"]
                if "allow_loopback_dev" in plan:
                    merged_doc["allow_loopback_dev"] = plan["allow_loopback_dev"]
                if "protect_dotenv_files" in plan:
                    merged_doc["protect_dotenv_files"] = plan["protect_dotenv_files"]
                if "protect_host_credentials" in plan:
                    merged_doc["protect_host_credentials"] = plan["protect_host_credentials"]
                if "block_destructive_commands" in plan:
                    merged_doc["block_destructive_commands"] = plan["block_destructive_commands"]
                if "tray_enabled" in plan:
                    merged_doc["tray_enabled"] = plan["tray_enabled"]
                if "public_gateway_base" in plan:
                    merged_doc["public_gateway_base"] = plan["public_gateway_base"]
                if "public_gateway_node_id" in plan:
                    merged_doc["public_gateway_node_id"] = plan["public_gateway_node_id"]
                if "workers_dev_account_id" in plan:
                    merged_doc["workers_dev_account_id"] = plan["workers_dev_account_id"]
                if "workers_dev_script_name" in plan:
                    merged_doc["workers_dev_script_name"] = plan["workers_dev_script_name"]
                if "workers_dev_subdomain" in plan:
                    merged_doc["workers_dev_subdomain"] = plan["workers_dev_subdomain"]
                if "workers_dev_custom_domain" in plan:
                    merged_doc["workers_dev_custom_domain"] = plan["workers_dev_custom_domain"]

                if "gateways" in plan or "tunnel_mode" in plan or "selected_gateway" in plan:
                    base_gws, base_sel = (
                        normalize_gateways_config(dict(disk_doc))
                        if (had_file and ("gateways" in disk_doc or "tunnel_mode" in disk_doc))
                        else (self.gateways, self.selected_gateway)
                    )
                    base_tm = str(disk_doc.get("tunnel_mode") or self.tunnel_mode) if had_file else self.tunnel_mode
                    base_pin = (
                        tuple(disk_doc.get("pinned_gateway_urls") or ())
                        if (had_file and "pinned_gateway_urls" in disk_doc)
                        else self.pinned_gateway_urls
                    )
                    next_gws, next_sel, next_tm, next_pin = self._compute_gateway_update(
                        plan,
                        base_gateways=base_gws,
                        base_selected=base_sel,
                        base_tunnel_mode=base_tm,
                        base_pinned=base_pin,
                        wd_account_id=str(merged_doc.get("workers_dev_account_id") or self.workers_dev_account_id),
                        wd_script_name=str(merged_doc.get("workers_dev_script_name") or self.workers_dev_script_name),
                        wd_subdomain=str(merged_doc.get("workers_dev_subdomain") or self.workers_dev_subdomain),
                        wd_custom_domain=str(merged_doc.get("workers_dev_custom_domain") or self.workers_dev_custom_domain),
                    )
                    merged_doc["gateways"] = {gid: dict(next_gws[gid]) for gid in GATEWAY_IDS}
                    merged_doc["selected_gateway"] = next_sel
                    merged_doc["tunnel_mode"] = next_tm
                    merged_doc["_gateways_mirrored_mode"] = next_tm
                    merged_doc["pinned_gateway_urls"] = list(collect_pinned_gateway_urls(next_gws, merged_doc))

                if "extra_patch" in plan and isinstance(plan["extra_patch"], Mapping):
                    for ek, ev in plan["extra_patch"].items():
                        if ev is None:
                            continue
                        if ek == "gateways" and isinstance(ev, Mapping):
                            if not isinstance(merged_doc.get("gateways"), dict):
                                init_gws, _ = normalize_gateways_config(dict(merged_doc))
                                merged_doc["gateways"] = {gid: dict(init_gws[gid]) for gid in GATEWAY_IDS}
                            for gid, g_subpatch in ev.items():
                                if isinstance(g_subpatch, Mapping):
                                    slot_d = dict(merged_doc["gateways"].get(gid) or {})
                                    for fk, fv in g_subpatch.items():
                                        if fv is not None:
                                            slot_d[fk] = fv
                                    merged_doc["gateways"][gid] = slot_d
                                else:
                                    merged_doc["gateways"][gid] = g_subpatch
                        elif ek in ("gateway_reconnect_requested_at", "subchannel_reconnect_requested_at") and isinstance(ev, Mapping):
                            cur_map = merged_doc.get(ek)
                            next_map = dict(cur_map) if isinstance(cur_map, Mapping) else {}
                            for sk, sv in ev.items():
                                if sv is not None:
                                    next_map[str(sk)] = sv
                            merged_doc[ek] = next_map
                        else:
                            merged_doc[ek] = ev

                next_rev = int(merged_doc.get("policy_revision") or 0) + 1
                now_ts = round(time.time(), 6)
                merged_doc["policy_revision"] = next_rev
                merged_doc["policy_updated_at"] = now_ts

                # Durability BEFORE in-memory & guard privilege mutation (A2)
                atomic_write_json(self.cfg_path, merged_doc)
                try:
                    self._sync_secondary_config_projections_locked(merged_doc)
                    prev_snap = self._capture_state_snapshot()
                    try:
                        if "workspace_roots" in plan:
                            for root_p in plan["workspace_roots"]:
                                root_p.mkdir(parents=True, exist_ok=True)
                        conn_info_dirty, keep_awake_changed_to, workspace_changed = self._apply_plan_to_memory(
                            plan, merged_doc=merged_doc if had_file else {
                                "policy_revision": next_rev,
                                "policy_updated_at": now_ts,
                                **({"gateways": merged_doc["gateways"]} if "gateways" in merged_doc else {}),
                            }
                        )
                        self._notify_workspace_hook()
                    except BaseException:
                        self._restore_state_snapshot(prev_snap)
                        raise
                except BaseException:
                    try:
                        if had_file and pre_write_bytes is not None:
                            atomic_write_text(self.cfg_path, pre_write_bytes.decode("utf-8"))
                        elif not had_file and self.cfg_path.exists():
                            self.cfg_path.unlink()
                    except Exception:
                        pass
                    self._last_cfg_sig = self._file_sig(self.cfg_path)
                    raise

                self._last_cfg_sig = self._file_sig(self.cfg_path)

            if workspace_changed:
                record_known_workspaces(self.state_root, self.workspace_roots)
            if keep_awake_changed_to is not None:
                self._safe_apply_keep_awake(keep_awake_changed_to)
            if conn_info_dirty:
                self._sync_conn_info_prefix_text()
            self._notify_policy_listeners()
            return self.tier_key, dict(self.tier_cfg), self.workspace

    def update_config(
        self,
        updates: Optional[Mapping[str, Any]] = None,
        *,
        persist: bool = True,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Update policy fields from a Studio/API dict or keyword args and return `to_status_dict()`."""
        merged: Dict[str, Any] = {}
        if updates:
            merged.update(dict(updates))
        merged.update(kwargs)

        tier_val = str(merged.get("permission_tier") or merged.get("tier") or merged.get("tier_key") or "")
        ws_val = str(merged.get("workspace") or "")
        ws_roots_val = merged.get("workspace_roots")
        ro_roots_val = (
            merged["readonly_workspace_roots"]
            if "readonly_workspace_roots" in merged
            else (merged["readonly_roots"] if "readonly_roots" in merged else None)
        )
        tp_val = str(merged["tool_prefix"]).strip() if "tool_prefix" in merged and merged["tool_prefix"] is not None else ""
        lbl_val = str(merged["device_label"]).strip() if "device_label" in merged and merged["device_label"] is not None else ""
        ts_val = str(merged.get("toolset_profile") or merged.get("toolset") or "")
        pr_val = str(merged.get("prompt_profile") or "")
        en_tools = merged.get("enabled_tools") if "enabled_tools" in merged else None
        dis_tools = merged.get("disabled_tools") if "disabled_tools" in merged else None
        en_packs = merged.get("enabled_packs") if "enabled_packs" in merged else None
        ann_val = str(merged.get("annotation_mode") or "")
        ap_val = parse_bool_flag(merged["approval_popups"]) if "approval_popups" in merged and merged["approval_popups"] is not None else None
        py_val = str(merged["python_path"]) if "python_path" in merged and merged["python_path"] is not None else None
        ka_val = parse_bool_flag(merged["keep_awake"]) if "keep_awake" in merged and merged["keep_awake"] is not None else None
        scan_sk_val = (
            parse_bool_flag(merged["scan_host_global_skills"], default=False)
            if "scan_host_global_skills" in merged and merged["scan_host_global_skills"] is not None
            else None
        )
        redact_sec_val = (
            parse_bool_flag(merged["redact_project_secrets"], default=False)
            if "redact_project_secrets" in merged and merged["redact_project_secrets"] is not None
            else None
        )
        en_oc_val = (
            parse_bool_flag(merged["enable_oneclick_token_route"], default=False)
            if "enable_oneclick_token_route" in merged and merged["enable_oneclick_token_route"] is not None
            else None
        )
        allow_lb_val = (
            parse_bool_flag(merged["allow_loopback_dev"], default=True)
            if "allow_loopback_dev" in merged and merged["allow_loopback_dev"] is not None
            else None
        )
        prot_env_val = (
            parse_bool_flag(merged["protect_dotenv_files"], default=False)
            if "protect_dotenv_files" in merged and merged["protect_dotenv_files"] is not None
            else None
        )
        prot_cred_val = (
            parse_bool_flag(merged["protect_host_credentials"], default=True)
            if "protect_host_credentials" in merged and merged["protect_host_credentials"] is not None
            else None
        )
        blk_dest_val = (
            parse_bool_flag(merged["block_destructive_commands"], default=True)
            if "block_destructive_commands" in merged and merged["block_destructive_commands"] is not None
            else None
        )
        tray_val = (
            parse_bool_flag(merged["tray_enabled"], default=True)
            if "tray_enabled" in merged and merged["tray_enabled"] is not None
            else None
        )
        tm_val = str(merged["tunnel_mode"]).strip() if "tunnel_mode" in merged and merged["tunnel_mode"] is not None else None
        gws_val = merged["gateways"] if "gateways" in merged and isinstance(merged["gateways"], Mapping) else None
        sel_gw_val = (
            str(merged["selected_gateway"]).strip()
            if "selected_gateway" in merged and merged["selected_gateway"] is not None
            else None
        )
        pg_base_val = (
            str(merged["public_gateway_base"])
            if "public_gateway_base" in merged and merged["public_gateway_base"] is not None
            else None
        )
        pg_nid_val = (
            str(merged["public_gateway_node_id"])
            if "public_gateway_node_id" in merged and merged["public_gateway_node_id"] is not None
            else None
        )
        wd_acc_val = (
            str(merged["workers_dev_account_id"])
            if "workers_dev_account_id" in merged and merged["workers_dev_account_id"] is not None
            else None
        )
        wd_scr_val = (
            str(merged["workers_dev_script_name"])
            if "workers_dev_script_name" in merged and merged["workers_dev_script_name"] is not None
            else None
        )
        wd_sub_val = (
            str(merged["workers_dev_subdomain"])
            if "workers_dev_subdomain" in merged and merged["workers_dev_subdomain"] is not None
            else None
        )
        wd_dom_val = (
            str(merged["workers_dev_custom_domain"])
            if "workers_dev_custom_domain" in merged and merged["workers_dev_custom_domain"] is not None
            else None
        )
        extra_patch_val = (
            merged["extra_patch"]
            if "extra_patch" in merged and isinstance(merged["extra_patch"], Mapping)
            else None
        )

        fn = self.persist_changes if persist else self.apply_direct
        fn(
            tier_key=tier_val,
            workspace=ws_val,
            workspace_roots=ws_roots_val,
            readonly_workspace_roots=ro_roots_val,
            tool_prefix=tp_val,
            device_label=lbl_val,
            toolset_profile=ts_val,
            prompt_profile=pr_val,
            enabled_tools=en_tools,
            disabled_tools=dis_tools,
            approval_popups=ap_val,
            annotation_mode=ann_val,
            python_path=py_val,
            enabled_packs=en_packs,
            keep_awake=ka_val,
            scan_host_global_skills=scan_sk_val,
            redact_project_secrets=redact_sec_val,
            enable_oneclick_token_route=en_oc_val,
            allow_loopback_dev=allow_lb_val,
            protect_dotenv_files=prot_env_val,
            protect_host_credentials=prot_cred_val,
            block_destructive_commands=blk_dest_val,
            tray_enabled=tray_val,
            tunnel_mode=tm_val,
            gateways=gws_val,
            selected_gateway=sel_gw_val,
            public_gateway_base=pg_base_val,
            public_gateway_node_id=pg_nid_val,
            workers_dev_account_id=wd_acc_val,
            workers_dev_script_name=wd_scr_val,
            workers_dev_subdomain=wd_sub_val,
            workers_dev_custom_domain=wd_dom_val,
            extra_patch=extra_patch_val,
        )
        return self.to_status_dict()

    def refresh(self, force: bool = False) -> Tuple[str, Dict[str, Any], str]:
        cfg_sig = self._file_sig(self.cfg_path)
        auth_sig = self._file_sig(self.auth_path)
        need_cfg = force or (self.cfg_path is not None and cfg_sig is not None and cfg_sig != self._last_cfg_sig)
        need_auth = force or (self.auth_path is not None and auth_sig is not None and auth_sig != self._last_auth_sig)
        if not need_cfg and not need_auth:
            return self.tier_key, dict(self.tier_cfg), self.workspace

        with self._lock:
            if need_cfg and self.cfg_path is not None and self.cfg_path.is_file():
                try:
                    raw_cfg = json.loads(self.cfg_path.read_text(encoding="utf-8-sig"))
                    if isinstance(raw_cfg, dict):
                        conn_info_dirty = False
                        if "tool_prefix" in raw_cfg:
                            new_tp = _resolve_safe_tool_prefix(raw_cfg.get("tool_prefix"), fallback=self.eff_prefix)
                            if new_tp != self.tool_prefix:
                                self.tool_prefix = new_tp
                                conn_info_dirty = True
                        if "device_label" in raw_cfg and str(raw_cfg.get("device_label") or "").strip():
                            new_lbl = str(raw_cfg.get("device_label")).strip()
                            if new_lbl != self.device_label:
                                self.device_label = new_lbl
                                conn_info_dirty = True

                        env_locks = getattr(self, "_startup_env_locks", set())
                        new_tier = (
                            self.tier_key
                            if "tier_key" in env_locks
                            else normalize_tier(str(raw_cfg.get("permission_tier") or self.tier_key))
                        )
                        has_ws_cfg = ("workspace_roots" in raw_cfg) or ("workspace" in raw_cfg) or ("workspace_root" in raw_cfg)
                        if has_ws_cfg and "workspace_roots" not in env_locks:
                            new_roots = normalize_workspace_roots(
                                raw_cfg.get("workspace_roots"),
                                legacy_workspace=str(raw_cfg.get("workspace") or raw_cfg.get("workspace_root") or ""),
                            )
                        else:
                            new_roots = self.workspace_roots
                        if new_tier != self.tier_key:
                            if self.tier_key != "tier1_readonly" and new_tier == "tier1_readonly":
                                self.previous_non_readonly_tier = self.tier_key
                            elif new_tier != "tier1_readonly":
                                self.previous_non_readonly_tier = new_tier
                            self.tier_epoch += 1
                        if "previous_non_readonly_tier" in raw_cfg:
                            cand_prev = str(raw_cfg.get("previous_non_readonly_tier") or "").strip().lower()
                            if cand_prev in ("tier2_workspace_edit", "tier3_workspace_dev", "tier4_full_power"):
                                self.previous_non_readonly_tier = cand_prev
                        if self._roots_norm_tuple(new_roots) != self._roots_norm_tuple(self.workspace_roots):
                            self.workspace_epoch += 1
                            record_known_workspaces(self.state_root, new_roots)
                        self.tier_key = new_tier
                        self.tier_cfg = dict(PERMISSION_TIERS[new_tier])
                        self.workspace_roots = new_roots
                        if "readonly_workspace_roots" in raw_cfg:
                            self.readonly_workspace_roots = normalize_readonly_workspace_roots(
                                raw_cfg.get("readonly_workspace_roots"), new_roots
                            )
                        else:
                            self.readonly_workspace_roots = normalize_readonly_workspace_roots(
                                self.readonly_workspace_roots, new_roots
                            )
                        if "toolset_profile" in raw_cfg and "toolset_profile" not in env_locks:
                            self.toolset_profile = normalize_toolset_profile(str(raw_cfg.get("toolset_profile") or ""))
                        if "prompt_profile" in raw_cfg and "prompt_profile" not in env_locks:
                            self.prompt_profile = normalize_prompt_profile(str(raw_cfg.get("prompt_profile") or ""))
                        if "enabled_tools" in raw_cfg and "enabled_tools" not in env_locks:
                            self.enabled_tools = parse_tool_filter_spec(raw_cfg.get("enabled_tools"), active_prefix=self.tool_prefix)
                        if "disabled_tools" in raw_cfg and "disabled_tools" not in env_locks:
                            self.disabled_tools = parse_tool_filter_spec(raw_cfg.get("disabled_tools"), active_prefix=self.tool_prefix)
                        if "enabled_packs" in raw_cfg and "enabled_packs" not in env_locks:
                            self.enabled_packs = parse_pack_spec(raw_cfg.get("enabled_packs"), strict=False)
                        if "scan_host_global_skills" in raw_cfg:
                            self.scan_host_global_skills = parse_bool_flag(raw_cfg.get("scan_host_global_skills"), default=False)
                        if "redact_project_secrets" in raw_cfg:
                            self.redact_project_secrets = parse_bool_flag(raw_cfg.get("redact_project_secrets"), default=False)
                        if "enable_oneclick_token_route" in raw_cfg:
                            self.enable_oneclick_token_route = parse_bool_flag(
                                raw_cfg.get("enable_oneclick_token_route"), default=False
                            )
                        if "allow_loopback_dev" in raw_cfg:
                            self.allow_loopback_dev = parse_bool_flag(raw_cfg.get("allow_loopback_dev"), default=True)
                        if "protect_dotenv_files" in raw_cfg:
                            self.protect_dotenv_files = parse_bool_flag(raw_cfg.get("protect_dotenv_files"), default=False)
                        if "protect_host_credentials" in raw_cfg:
                            self.protect_host_credentials = parse_bool_flag(raw_cfg.get("protect_host_credentials"), default=True)
                        if "block_destructive_commands" in raw_cfg:
                            self.block_destructive_commands = parse_bool_flag(raw_cfg.get("block_destructive_commands"), default=True)
                        if "tray_enabled" in raw_cfg:
                            self.tray_enabled = parse_bool_flag(raw_cfg.get("tray_enabled"), default=True)
                        refreshed_gw_doc = dict(raw_cfg)
                        self.gateways, self.selected_gateway = normalize_gateways_config(refreshed_gw_doc)
                        self.pinned_gateway_urls = tuple(refreshed_gw_doc.get("pinned_gateway_urls") or ())
                        if refreshed_gw_doc.get("tunnel_mode"):
                            self.tunnel_mode = str(refreshed_gw_doc["tunnel_mode"]).strip()
                        elif "tunnel_mode" in raw_cfg and str(raw_cfg.get("tunnel_mode") or "").strip():
                            self.tunnel_mode = str(raw_cfg.get("tunnel_mode")).strip()
                        if "public_gateway_base" in raw_cfg and not (os.environ.get("COSMOS_PUBLIC_GATEWAY_BASE") or "").strip():
                            pg_b = str(raw_cfg.get("public_gateway_base") or "").strip().rstrip("/")
                            if pg_b:
                                self.public_gateway_base = pg_b
                        if "public_gateway_node_id" in raw_cfg:
                            self.public_gateway_node_id = str(raw_cfg.get("public_gateway_node_id") or "").strip()
                        if "workers_dev_account_id" in raw_cfg:
                            self.workers_dev_account_id = str(raw_cfg.get("workers_dev_account_id") or "").strip()
                        if "workers_dev_script_name" in raw_cfg:
                            s_n = str(raw_cfg.get("workers_dev_script_name") or "").strip()
                            self.workers_dev_script_name = s_n if s_n else DEFAULT_WORKERS_DEV_SCRIPT_NAME
                        if "workers_dev_subdomain" in raw_cfg:
                            self.workers_dev_subdomain = str(raw_cfg.get("workers_dev_subdomain") or "").strip()
                        if "workers_dev_custom_domain" in raw_cfg:
                            self.workers_dev_custom_domain = str(raw_cfg.get("workers_dev_custom_domain") or "").strip()

                        has_env_ann = bool((os.environ.get("COSMOS_ANNOTATION_MODE") or os.environ.get("LOCALPC_ANNOTATION_MODE") or "").strip())
                        has_env_ap = bool((os.environ.get("LOCALPC_APPROVAL_POPUPS") or "").strip())
                        if not has_env_ann and not has_env_ap:
                            if "annotation_mode" in raw_cfg and str(raw_cfg.get("annotation_mode") or "").strip():
                                self._annotation_mode = normalize_annotation_mode(raw_cfg.get("annotation_mode"))
                            elif "approval_popups" in raw_cfg:
                                self._annotation_mode = (
                                    "strict" if parse_bool_flag(raw_cfg.get("approval_popups"), default=False) else "seamless"
                                )
                        has_env_py = bool((os.environ.get("COSMOS_PYTHON_PATH") or os.environ.get("LOCALPC_PYTHON_PATH") or "").strip())
                        if "python_path" in raw_cfg and not has_env_py:
                            self.python_path = normalize_python_path(raw_cfg.get("python_path"))
                        if "keep_awake" in raw_cfg and not (os.environ.get("LOCALPC_KEEP_AWAKE") or "").strip():
                            new_ka = parse_bool_flag(raw_cfg.get("keep_awake"), default=True)
                            if new_ka != self.keep_awake:
                                self.keep_awake = new_ka
                                self._safe_apply_keep_awake(new_ka)
                        if "policy_revision" in raw_cfg:
                            with contextlib.suppress(TypeError, ValueError):
                                self.policy_revision = max(0, int(raw_cfg["policy_revision"]))
                        if "policy_updated_at" in raw_cfg:
                            with contextlib.suppress(TypeError, ValueError):
                                self.policy_updated_at = float(raw_cfg["policy_updated_at"])
                        self._last_cfg_sig = self._file_sig(self.cfg_path)
                        if conn_info_dirty:
                            self._sync_conn_info_prefix_text()
                        self._notify_workspace_hook()
                        self._notify_policy_listeners()
                    else:
                        self._last_cfg_sig = self._file_sig(self.cfg_path)
                except Exception:
                    pass

            if need_auth and self.auth_path is not None and self.auth_path.is_file():
                try:
                    creds_doc = json.loads(self.auth_path.read_text(encoding="utf-8-sig"))
                    self._last_auth_sig = self._file_sig(self.auth_path)
                    if isinstance(creds_doc, dict):
                        for fn in list(self._auth_listeners):
                            try:
                                fn(creds_doc)
                            except Exception:
                                pass
                except Exception:
                    pass

            return self.tier_key, dict(self.tier_cfg), self.workspace


def register_active_server_pid(
    state_root: Path,
    transport: str,
    eff_prefix: str = "pc",
    port: int = 0,
    workspace_roots: Sequence[Path | str] = (),
    on_exit_cleanup: Optional[Callable[[], None]] = None,
) -> Path:
    """Register active server PID metadata under `<state_root>/state/active_pids/<pid>.json` with exit cleanup."""
    pid = os.getpid()
    active_dir = Path(state_root) / "state" / "active_pids"
    pid_file = active_dir / f"{pid}.json"
    norm_p = normalize_prefix(eff_prefix)
    ws_strs = [str(p) for p in workspace_roots] if workspace_roots else []
    try:
        pgid = os.getpgid(0) if hasattr(os, "getpgid") else None
        atomic_write_json(
            pid_file,
            {
                "pid": pid,
                "pgid": int(pgid) if pgid else None,
                "transport": transport,
                "tool_prefix": norm_p,
                "port": int(port),
                "workspace": ws_strs[0] if ws_strs else "",
                "workspace_roots": ws_strs,
                "started_at": time.time(),
            },
        )
    except Exception:
        pass

    def _cleanup() -> None:
        if on_exit_cleanup is not None:
            try:
                on_exit_cleanup()
            except Exception:
                pass
        try:
            if pid_file.exists():
                pid_file.unlink()
        except OSError:
            pass

    atexit.register(_cleanup)
    if ws_strs:
        record_known_workspaces(Path(state_root), ws_strs)
    return pid_file


RuntimePolicy = LiveRuntimePolicy
