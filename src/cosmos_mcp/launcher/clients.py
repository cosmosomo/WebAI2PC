"""Legacy local client config cleanup & CLI compatibility helper.

Product positioning note:
- Cosmos MCP exclusively targets **Web Google Gemini (Task Mode + Mobile App)** and
  **Web ChatGPT (Workspace `/mcp` + Personal `/mcp/readonly`)** via remote HTTPS OAuth 2.1 connectors,
  rather than local desktop IDE/CLI config injection.
- During normal web-connector startup and Studio operation, zero local desktop client configs are touched.
- Function signatures in this module (`DESKTOP_CLIENT_SPECS`, `detect_installed_clients`, `strip_jsonc`,
  `bind_desktop_clients`, `unbind_desktop_clients`) are preserved strictly for `doctor`/`uninstall` cleanup
  of historical bindings and CLI backward compatibility, with lossless JSON/JSONC comment preservation.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from cosmos_mcp.core.fs_tx import atomic_write_json, safe_trash_file
from cosmos_mcp.launcher.bootstrap import (
    atomic_write_text,
    resolve_persisted_src_dir,
    venv_python_path,
)


@dataclass(frozen=True)
class DesktopClientSpec:
    client_id: str
    display_name: str
    format_kind: str  # "json" | "toml"
    container_key: str  # "mcpServers" | "servers" | "mcp_servers"
    transport_kind: str  # "stdio" | "http"


DESKTOP_CLIENT_SPECS: Dict[str, DesktopClientSpec] = {
    "claude_desktop": DesktopClientSpec("claude_desktop", "Claude Desktop", "json", "mcpServers", "stdio"),
    "claude_code": DesktopClientSpec("claude_code", "Claude Code", "json", "mcpServers", "http"),
    "cursor": DesktopClientSpec("cursor", "Cursor", "json", "mcpServers", "http"),
    "windsurf": DesktopClientSpec("windsurf", "Windsurf", "json", "mcpServers", "http"),
    "vscode": DesktopClientSpec("vscode", "VS Code", "json", "servers", "http"),
    "codex": DesktopClientSpec("codex", "Codex CLI", "toml", "mcp_servers", "http"),
    "gemini_cli": DesktopClientSpec("gemini_cli", "Gemini CLI", "json", "mcpServers", "http"),
    "antigravity": DesktopClientSpec("antigravity", "Antigravity", "json", "mcpServers", "http"),
}

_CLIENT_ALIASES: Dict[str, str] = {
    "claude": "claude_desktop",
    "claude-desktop": "claude_desktop",
    "claude_desktop": "claude_desktop",
    "claudecode": "claude_code",
    "claude-code": "claude_code",
    "claude_code": "claude_code",
    "cursor": "cursor",
    "windsurf": "windsurf",
    "code": "vscode",
    "vscode": "vscode",
    "vs-code": "vscode",
    "vs_code": "vscode",
    "codex": "codex",
    "openai-codex": "codex",
    "gemini": "gemini_cli",
    "gemini-cli": "gemini_cli",
    "gemini_cli": "gemini_cli",
    "antigravity": "antigravity",
    "agy": "antigravity",
}


def server_key_for_prefix(prefix: str = "pc") -> str:
    eff = (prefix or "pc").strip().lower() or "pc"
    return "local-pc-mcp" if eff == "pc" else f"local-{eff}-mcp"


def resolve_client_config_path(
    client_id: str,
    *,
    home_dir: Optional[Path] = None,
    appdata_dir: Optional[Path] = None,
    platform_name: Optional[str] = None,
) -> Path:
    plat = platform_name or sys.platform
    home = Path(home_dir).expanduser() if home_dir is not None else Path.home()
    if appdata_dir is not None:
        appdata = Path(appdata_dir).expanduser()
    elif plat == "win32":
        env_ad = os.environ.get("APPDATA", "").strip()
        appdata = Path(env_ad) if env_ad else (home / "AppData" / "Roaming")
    elif plat == "darwin":
        appdata = home / "Library" / "Application Support"
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
        appdata = Path(xdg) if xdg else (home / ".config")

    cid = _CLIENT_ALIASES.get(client_id.strip().lower(), client_id.strip().lower())
    if cid == "claude_desktop":
        return appdata / "Claude" / "claude_desktop_config.json"
    if cid == "claude_code":
        return home / ".claude.json"
    if cid == "cursor":
        return home / ".cursor" / "mcp.json"
    if cid == "windsurf":
        return home / ".codeium" / "windsurf" / "mcp_config.json"
    if cid == "vscode":
        return appdata / "Code" / "User" / "mcp.json"
    if cid == "codex":
        return home / ".codex" / "config.toml"
    if cid == "gemini_cli":
        return home / ".gemini" / "settings.json"
    if cid == "antigravity":
        return home / ".gemini" / "antigravity" / "mcp_config.json"
    raise ValueError(f"Unsupported desktop client `{client_id}` (expected one of {', '.join(DESKTOP_CLIENT_SPECS)}).")


def detect_installed_clients(
    *,
    home_dir: Optional[Path] = None,
    appdata_dir: Optional[Path] = None,
    platform_name: Optional[str] = None,
) -> List[str]:
    """Return clients whose config file or parent app directory already exists on disk (never creates dirs)."""
    installed: List[str] = []
    for cid in DESKTOP_CLIENT_SPECS:
        cfg_p = resolve_client_config_path(
            cid,
            home_dir=home_dir,
            appdata_dir=appdata_dir,
            platform_name=platform_name,
        )
        if cid == "claude_code":
            if cfg_p.is_file() or (cfg_p.parent / ".claude").is_dir():
                installed.append(cid)
        elif cid == "gemini_cli":
            if (
                cfg_p.is_file()
                or (cfg_p.parent / "oauth_creds.json").is_file()
                or (home_dir is None and shutil.which("gemini") is not None)
            ):
                installed.append(cid)
        else:
            if cfg_p.is_file() or cfg_p.parent.is_dir():
                installed.append(cid)
    return installed


def parse_client_selection(
    raw_selection: Any,
    *,
    home_dir: Optional[Path] = None,
    appdata_dir: Optional[Path] = None,
    platform_name: Optional[str] = None,
) -> List[str]:
    """Parse explicit desktop client selection.

    - Empty / `None` / `"none"` / `"off"` -> `[]` (strictly zero desktop config writes).
    - `"installed"` / `"auto"` / `"all"` -> ONLY clients already present on disk (`detect_installed_clients`).
    - Explicit names (e.g. `"cursor,vscode"` or `["cursor", "codex"]`) -> validated canonical client IDs.
    """
    if raw_selection is None or raw_selection == "":
        return []
    tokens: List[str] = []
    if isinstance(raw_selection, str):
        s = raw_selection.strip()
        if not s or s.lower() in ("none", "off", "false", "0", "[]"):
            return []
        tokens = [t.strip() for t in s.split(",") if t.strip()]
    elif isinstance(raw_selection, Iterable):
        tokens = [str(t).strip() for t in raw_selection if str(t).strip()]

    out: List[str] = []
    for tok in tokens:
        low = tok.lower()
        if low in ("none", "off"):
            continue
        if low in ("installed", "auto", "all"):
            for inst in detect_installed_clients(
                home_dir=home_dir,
                appdata_dir=appdata_dir,
                platform_name=platform_name,
            ):
                if inst not in out:
                    out.append(inst)
            continue
        mapped = _CLIENT_ALIASES.get(low, "")
        if not mapped or mapped not in DESKTOP_CLIENT_SPECS:
            raise ValueError(
                f"Unknown desktop client `{tok}` (supported: {', '.join(DESKTOP_CLIENT_SPECS)})."
            )
        if mapped not in out:
            out.append(mapped)
    return out


# ---------------------------------------------------------------------------
# JSON / JSONC Indentation & Comment-Preserving Helpers
# ---------------------------------------------------------------------------

def detect_indent_and_newline(text: str) -> Tuple[str, str]:
    newline = "\r\n" if "\r\n" in text else "\n"
    for line in text.splitlines():
        if not line or not line[0].isspace():
            continue
        ws = line[: len(line) - len(line.lstrip(" \t"))]
        if ws.startswith("\t"):
            return ("\t", newline)
        if len(ws) in (2, 4):
            return (ws, newline)
    for line in text.splitlines():
        ws = line[: len(line) - len(line.lstrip(" "))]
        if len(ws) >= 2:
            return ("    " if len(ws) >= 4 else "  ", newline)
    return ("  ", newline)


def has_jsonc_comments(text: str) -> bool:
    i = 0
    n = len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] in ("/", "*"):
            return True
        i += 1
    return False


def strip_jsonc(text: str) -> str:
    """Strip `//` and `/* ... */` comments and trailing commas outside JSON string literals."""
    out: List[str] = []
    i = 0
    n = len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            i += 2
            while i < n and text[i] not in ("\r", "\n"):
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                if text[i] in ("\r", "\n"):
                    out.append(text[i])
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1

    no_comments = "".join(out)
    # Remove trailing commas before `}` or `]` outside strings
    res: List[str] = []
    j = 0
    m = len(no_comments)
    in_s2 = False
    while j < m:
        c = no_comments[j]
        if in_s2:
            res.append(c)
            if c == "\\" and j + 1 < m:
                res.append(no_comments[j + 1])
                j += 2
                continue
            if c == '"':
                in_s2 = False
            j += 1
            continue
        if c == '"':
            in_s2 = True
            res.append(c)
            j += 1
            continue
        if c == ",":
            k = j + 1
            while k < m and no_comments[k] in (" ", "\t", "\r", "\n"):
                k += 1
            if k < m and no_comments[k] in ("}", "]"):
                j += 1
                continue
        res.append(c)
        j += 1
    return "".join(res)


def _skip_ws_and_comments(text: str, idx: int) -> int:
    n = len(text)
    while idx < n:
        ch = text[idx]
        if ch in (" ", "\t", "\r", "\n"):
            idx += 1
            continue
        if ch == "/" and idx + 1 < n and text[idx + 1] == "/":
            idx += 2
            while idx < n and text[idx] not in ("\r", "\n"):
                idx += 1
            continue
        if ch == "/" and idx + 1 < n and text[idx + 1] == "*":
            idx += 2
            while idx + 1 < n and not (text[idx] == "*" and text[idx + 1] == "/"):
                idx += 1
            idx += 2
            continue
        break
    return idx


def _scan_json_string_end(text: str, quote_idx: int) -> int:
    i = quote_idx + 1
    n = len(text)
    while i < n:
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == '"':
            return i + 1
        i += 1
    return n


def _scan_json_value_end(text: str, start_idx: int) -> int:
    i = _skip_ws_and_comments(text, start_idx)
    n = len(text)
    if i >= n:
        return n
    ch = text[i]
    if ch == '"':
        return _scan_json_string_end(text, i)
    if ch in ("{", "["):
        close_ch = "}" if ch == "{" else "]"
        depth = 0
        while i < n:
            c = text[i]
            if c == '"':
                i = _scan_json_string_end(text, i)
                continue
            if c == "/" and i + 1 < n and text[i + 1] in ("/", "*"):
                i = _skip_ws_and_comments(text, i)
                continue
            if c == ch:
                depth += 1
            elif c == close_ch:
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return n
    while i < n and text[i] not in (",", "}", "]", " ", "\t", "\r", "\n", "/"):
        i += 1
    return i


def _iter_object_entries(text: str, obj_open_idx: int) -> Tuple[List[Tuple[str, int, int, int, int]], int]:
    """Return `[(key, key_start, val_start, val_end, comma_end), ...]` and `obj_close_idx`."""
    entries: List[Tuple[str, int, int, int, int]] = []
    i = _skip_ws_and_comments(text, obj_open_idx + 1)
    n = len(text)
    while i < n:
        i = _skip_ws_and_comments(text, i)
        if i >= n or text[i] == "}":
            return entries, i
        if text[i] == ",":
            i += 1
            continue
        if text[i] != '"':
            break
        k_start = i
        k_end = _scan_json_string_end(text, k_start)
        key_name = json.loads(text[k_start:k_end])
        colon = _skip_ws_and_comments(text, k_end)
        if colon >= n or text[colon] != ":":
            break
        v_start = _skip_ws_and_comments(text, colon + 1)
        v_end = _scan_json_value_end(text, v_start)
        after_v = _skip_ws_and_comments(text, v_end)
        c_end = after_v + 1 if (after_v < n and text[after_v] == ",") else v_end
        entries.append((key_name, k_start, v_start, v_end, c_end))
        i = c_end
    return entries, i


def _format_json_fragment(obj: Any, indent_unit: str, base_depth: int, newline: str) -> str:
    raw = json.dumps(obj, indent=indent_unit, ensure_ascii=False)
    lines = raw.splitlines()
    if len(lines) <= 1:
        return raw
    prefix = indent_unit * base_depth
    return newline.join([lines[0]] + [prefix + ln for ln in lines[1:]])


def upsert_json_or_jsonc_server(
    existing_text: str,
    *,
    container_key: str,
    server_key: str,
    entry_doc: Dict[str, Any],
    remove_keys: Sequence[str] = (),
) -> str:
    """Losslessly upsert `server_key` (and optionally remove `remove_keys`) preserving comments & indentation."""
    has_bom = existing_text.startswith("\ufeff")
    body = existing_text[1:] if has_bom else existing_text
    indent_unit, nl = detect_indent_and_newline(body)

    if not body.strip():
        doc = {container_key: {server_key: entry_doc}}
        rendered = json.dumps(doc, indent=indent_unit, ensure_ascii=False).replace("\n", nl) + nl
        return ("\ufeff" + rendered) if has_bom else rendered

    if not has_jsonc_comments(body):
        parsed = json.loads(strip_jsonc(body))
        if not isinstance(parsed, dict):
            raise ValueError("Root of desktop MCP config must be a JSON object.")
        container = parsed.get(container_key)
        if not isinstance(container, dict):
            container = {}
            parsed[container_key] = container
        for rk in remove_keys:
            if rk and rk != server_key:
                container.pop(rk, None)
        container[server_key] = entry_doc
        rendered = json.dumps(parsed, indent=indent_unit, ensure_ascii=False).replace("\n", nl) + nl
        return ("\ufeff" + rendered) if has_bom else rendered

    # Surgical JSONC comment-preserving path
    for rk in remove_keys:
        if rk and rk != server_key:
            body = remove_json_or_jsonc_server(body, container_key=container_key, server_keys=[rk])

    root_open = _skip_ws_and_comments(body, 0)
    if root_open >= len(body) or body[root_open] != "{":
        raise ValueError("Invalid JSONC root object.")
    root_entries, root_close = _iter_object_entries(body, root_open)
    cont_entry = next((e for e in root_entries if e[0] == container_key), None)

    if cont_entry is None:
        frag = _format_json_fragment({server_key: entry_doc}, indent_unit, 1, nl)
        prop_str = f'{indent_unit}"{container_key}": {frag}'
        if not root_entries:
            new_body = body[: root_open + 1] + nl + prop_str + nl + body[root_close:]
        else:
            last_v_end = root_entries[-1][3]
            after_last = _skip_ws_and_comments(body, last_v_end)
            needs_comma = after_last >= len(body) or body[after_last] != ","
            ins_pos = last_v_end
            comma_s = "," if needs_comma else ""
            new_body = body[:ins_pos] + comma_s + nl + prop_str + body[ins_pos:]
        return ("\ufeff" + new_body) if has_bom else new_body

    _, _, c_val_start, c_val_end, _ = cont_entry
    if body[c_val_start] != "{":
        raise ValueError(f"`{container_key}` in JSONC config is not an object.")
    sub_entries, sub_close = _iter_object_entries(body, c_val_start)
    existing_srv = next((e for e in sub_entries if e[0] == server_key), None)
    val_frag = _format_json_fragment(entry_doc, indent_unit, 2, nl)
    if existing_srv is not None:
        _, _, sv_start, sv_end, _ = existing_srv
        new_body = body[:sv_start] + val_frag + body[sv_end:]
    elif not sub_entries:
        prop_line = f'{indent_unit * 2}"{server_key}": {val_frag}'
        new_body = body[: c_val_start + 1] + nl + prop_line + nl + indent_unit + body[sub_close:]
    else:
        last_sv_end = sub_entries[-1][3]
        after_sv = _skip_ws_and_comments(body, last_sv_end)
        comma_s = "," if (after_sv >= len(body) or body[after_sv] != ",") else ""
        prop_line = f'{indent_unit * 2}"{server_key}": {val_frag}'
        new_body = body[:last_sv_end] + comma_s + nl + prop_line + body[last_sv_end:]
    return ("\ufeff" + new_body) if has_bom else new_body


def remove_json_or_jsonc_server(
    existing_text: str,
    *,
    container_key: str,
    server_keys: Sequence[str],
) -> str:
    """Remove only `server_keys` from `container_key` without touching sibling entries or comments."""
    targets = {k for k in server_keys if k}
    if not targets or not existing_text.strip():
        return existing_text
    has_bom = existing_text.startswith("\ufeff")
    body = existing_text[1:] if has_bom else existing_text
    indent_unit, nl = detect_indent_and_newline(body)

    if not has_jsonc_comments(body):
        parsed = json.loads(strip_jsonc(body))
        if not isinstance(parsed, dict):
            return existing_text
        container = parsed.get(container_key)
        if isinstance(container, dict):
            changed = False
            for k in targets:
                if k in container:
                    container.pop(k, None)
                    changed = True
            if not changed:
                return existing_text
        rendered = json.dumps(parsed, indent=indent_unit, ensure_ascii=False).replace("\n", nl) + nl
        return ("\ufeff" + rendered) if has_bom else rendered

    cur = body
    for target_key in targets:
        root_open = _skip_ws_and_comments(cur, 0)
        if root_open >= len(cur) or cur[root_open] != "{":
            break
        root_entries, _ = _iter_object_entries(cur, root_open)
        cont_entry = next((e for e in root_entries if e[0] == container_key), None)
        if cont_entry is None:
            break
        _, _, c_val_start, _, _ = cont_entry
        if cur[c_val_start] != "{":
            break
        sub_entries, _ = _iter_object_entries(cur, c_val_start)
        idx_match = next((idx for idx, e in enumerate(sub_entries) if e[0] == target_key), None)
        if idx_match is None:
            continue
        _, k_start, _, v_end, c_end = sub_entries[idx_match]
        # Expand backwards across same-line indentation
        del_start = k_start
        while del_start > 0 and cur[del_start - 1] in (" ", "\t"):
            del_start -= 1
        if del_start > 0 and cur[del_start - 1] == "\n":
            del_start -= 1
            if del_start > 0 and cur[del_start - 1] == "\r":
                del_start -= 1
        del_end = c_end
        # If removing the last entry and the previous entry has a trailing comma, strip that trailing comma
        if idx_match == len(sub_entries) - 1 and idx_match > 0:
            prev_v_end = sub_entries[idx_match - 1][3]
            prev_c_end = sub_entries[idx_match - 1][4]
            if prev_c_end > prev_v_end:
                cur = cur[:prev_v_end] + cur[prev_c_end:del_start] + cur[del_end:]
                continue
        cur = cur[:del_start] + cur[del_end:]
    return ("\ufeff" + cur) if has_bom else cur


# ---------------------------------------------------------------------------
# Codex CLI (`~/.codex/config.toml`) Lossless Section Upsert & Remove
# ---------------------------------------------------------------------------

def _toml_quote(val: str) -> str:
    escaped = val.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _build_codex_toml_block(
    server_key: str,
    *,
    transport_kind: str,
    mcp_url: str,
    bearer_token: str,
    stdio_cmd: Sequence[str],
    repo_src: Optional[Path] = None,
    state_root: Optional[Path] = None,
    nl: str = "\n",
) -> str:
    hdr = f"[mcp_servers.{server_key}]"
    if transport_kind == "http":
        lines = [
            hdr,
            f"url = {_toml_quote(mcp_url)}",
        ]
        if bearer_token:
            lines.append(f"http_headers = {{ Authorization = {_toml_quote('Bearer ' + bearer_token)} }}")
        return nl.join(lines) + nl
    cmd_exe = stdio_cmd[0] if stdio_cmd else "cosmos-mcp"
    args_list = ", ".join(_toml_quote(a) for a in stdio_cmd[1:])
    lines = [
        hdr,
        f"command = {_toml_quote(cmd_exe)}",
        f"args = [{args_list}]",
        "",
        f"[mcp_servers.{server_key}.env]",
        'PYTHONDONTWRITEBYTECODE = "1"',
        'PYTHONUTF8 = "1"',
    ]
    if state_root is not None:
        lines.append(f"COSMOS_MCP_STATE_DIR = {_toml_quote(str(state_root))}")
    if repo_src is not None:
        lines.append(f"PYTHONPATH = {_toml_quote(str(repo_src))}")
    return nl.join(lines) + nl


def _strip_toml_server_sections(existing_toml: str, server_keys: Sequence[str]) -> str:
    targets = {f"mcp_servers.{k}" for k in server_keys if k} | {
        f"mcp_servers.{k}.env" for k in server_keys if k
    } | {
        f"mcp_servers.{k}.http_headers" for k in server_keys if k
    }
    if not targets or not existing_toml:
        return existing_toml
    header_re = re.compile(r"^\s*\[([^\]]+)\]\s*(?:#.*)?$")
    out_lines: List[str] = []
    skip_section = False
    for line in existing_toml.splitlines(keepends=True):
        m = header_re.match(line.rstrip("\r\n"))
        if m:
            sec_name = m.group(1).strip().strip('"').strip("'")
            # Also match quoted keys like `mcp_servers."local-pc-mcp"`
            sec_clean = sec_name.replace('"', "").replace("'", "")
            skip_section = sec_clean in targets
        if not skip_section:
            out_lines.append(line)
    return "".join(out_lines)


def upsert_codex_toml_server(
    existing_toml: str,
    *,
    server_key: str,
    transport_kind: str,
    mcp_url: str,
    bearer_token: str,
    stdio_cmd: Sequence[str],
    repo_src: Optional[Path] = None,
    state_root: Optional[Path] = None,
    remove_keys: Sequence[str] = (),
) -> str:
    nl = "\r\n" if "\r\n" in existing_toml else "\n"
    keys_to_clean = list({server_key, *[k for k in remove_keys if k]})
    cleaned = _strip_toml_server_sections(existing_toml, keys_to_clean).rstrip()
    block = _build_codex_toml_block(
        server_key,
        transport_kind=transport_kind,
        mcp_url=mcp_url,
        bearer_token=bearer_token,
        stdio_cmd=stdio_cmd,
        repo_src=repo_src,
        state_root=state_root,
        nl=nl,
    )
    if not cleaned:
        return block
    return cleaned + nl + nl + block


# ---------------------------------------------------------------------------
# Public Bind / Unbind API
# ---------------------------------------------------------------------------

def build_stdio_command_args(
    python_exe: str | Path,
    state_root: Path,
    *,
    prefix: str = "pc",
) -> List[str]:
    args = [
        str(python_exe),
        "-B",
        "-m",
        "cosmos_mcp.launcher.cli",
        "stdio",
        "--state-dir",
        str(Path(state_root).expanduser().resolve()),
    ]
    eff_p = (prefix or "pc").strip().lower() or "pc"
    if eff_p != "pc":
        args.extend(["--prefix", eff_p])
    return args


def _build_json_entry(
    spec: DesktopClientSpec,
    *,
    transport_override: str,
    mcp_url: str,
    bearer_token: str,
    stdio_argv: Sequence[str],
    repo_src: Optional[Path] = None,
) -> Dict[str, Any]:
    eff_transport = transport_override or spec.transport_kind
    if eff_transport == "stdio":
        env_map: Dict[str, str] = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"}
        if repo_src is not None:
            env_map["PYTHONPATH"] = str(repo_src)
        entry: Dict[str, Any] = {
            "command": str(stdio_argv[0]),
            "args": [str(x) for x in stdio_argv[1:]],
            "env": env_map,
        }
        if spec.client_id == "vscode":
            entry = {"type": "stdio", **entry}
        return entry

    headers: Dict[str, str] = {}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    if spec.client_id == "vscode":
        doc: Dict[str, Any] = {"type": "http", "url": mcp_url}
        if headers:
            doc["headers"] = headers
        return doc
    if spec.client_id == "claude_code":
        doc = {"type": "http", "url": mcp_url}
        if headers:
            doc["headers"] = headers
        return doc
    if spec.client_id == "gemini_cli":
        doc = {"httpUrl": mcp_url}
        if headers:
            doc["headers"] = headers
        return doc
    if spec.client_id == "windsurf":
        doc = {"serverUrl": mcp_url}
        if headers:
            doc["headers"] = headers
        return doc
    # Cursor / Antigravity standard HTTP MCP config
    doc = {"url": mcp_url}
    if headers:
        doc["headers"] = headers
    return doc


def _bindings_ledger_path(state_root: Path) -> Path:
    return Path(state_root).expanduser().resolve() / "state" / "desktop_bindings.json"


def _load_bindings_ledger(state_root: Path) -> Dict[str, Any]:
    p = _bindings_ledger_path(state_root)
    if p.is_file():
        try:
            doc = json.loads(p.read_text(encoding="utf-8-sig"))
            if isinstance(doc, dict):
                return doc
        except Exception:
            pass
    return {"bindings": {}}


def bind_desktop_clients(
    *,
    clients: Any,
    state_root: Path,
    python_exe: str | Path,
    port: int = 8096,
    local_api_token: str = "",
    prefix: str = "pc",
    migrate_from_prefix: str = "",
    transport_override: str = "",
    home_dir: Optional[Path] = None,
    appdata_dir: Optional[Path] = None,
    platform_name: Optional[str] = None,
    repo_src: Optional[Path] = None,
) -> Dict[str, Any]:
    """Legacy CLI compatibility helper: bind explicitly selected local client configs (not used by Web Studio)."""
    selected = parse_client_selection(
        clients,
        home_dir=home_dir,
        appdata_dir=appdata_dir,
        platform_name=platform_name,
    )
    if not selected:
        return {"ok": True, "bound_clients": [], "skipped": True}

    st_root = Path(state_root).expanduser().resolve()
    eff_repo_src = resolve_persisted_src_dir(st_root) or repo_src
    venv_py = venv_python_path(st_root / ".venv", windowless=False)
    eff_py: str | Path = venv_py if venv_py.is_file() else python_exe

    srv_key = server_key_for_prefix(prefix)
    old_keys: List[str] = []
    if migrate_from_prefix and migrate_from_prefix.strip().lower() != (prefix or "pc").strip().lower():
        old_keys.append(server_key_for_prefix(migrate_from_prefix))

    mcp_url = f"http://127.0.0.1:{int(port)}/mcp"
    stdio_argv = build_stdio_command_args(eff_py, st_root, prefix=prefix)
    ledger = _load_bindings_ledger(st_root)
    bindings_map: Dict[str, Any] = ledger.setdefault("bindings", {})

    results: List[Dict[str, Any]] = []
    for cid in selected:
        spec = DESKTOP_CLIENT_SPECS[cid]
        cfg_path = resolve_client_config_path(
            cid,
            home_dir=home_dir,
            appdata_dir=appdata_dir,
            platform_name=platform_name,
        )
        existed_before = cfg_path.is_file()
        missing_parents: List[str] = []
        if not existed_before:
            cur_p = cfg_path.parent
            while not cur_p.exists() and cur_p != cur_p.parent:
                missing_parents.append(str(cur_p))
                cur_p = cur_p.parent

        prev_record = bindings_map.get(f"{cid}:{srv_key}") or bindings_map.get(cid) or {}
        if "existed_before" in prev_record:
            orig_existed = bool(prev_record["existed_before"])
            orig_created_dirs = list(prev_record.get("created_dirs") or [])
        else:
            orig_existed = existed_before
            orig_created_dirs = missing_parents

        backup_path_str = str(prev_record.get("backup_path") or "")
        existing_text = ""
        if existed_before:
            existing_text = cfg_path.read_text(encoding="utf-8", errors="replace")
            bak_cand = cfg_path.with_name(cfg_path.name + ".localpc.bak")
            if not bak_cand.exists():
                bak_cand.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(cfg_path, bak_cand)
            backup_path_str = str(bak_cand)

        if spec.format_kind == "toml":
            eff_tr = transport_override or spec.transport_kind
            new_text = upsert_codex_toml_server(
                existing_text,
                server_key=srv_key,
                transport_kind=eff_tr,
                mcp_url=mcp_url,
                bearer_token=local_api_token,
                stdio_cmd=stdio_argv,
                repo_src=eff_repo_src,
                state_root=st_root,
                remove_keys=old_keys,
            )
        else:
            entry_doc = _build_json_entry(
                spec,
                transport_override=transport_override,
                mcp_url=mcp_url,
                bearer_token=local_api_token,
                stdio_argv=stdio_argv,
                repo_src=eff_repo_src,
            )
            new_text = upsert_json_or_jsonc_server(
                existing_text,
                container_key=spec.container_key,
                server_key=srv_key,
                entry_doc=entry_doc,
                remove_keys=old_keys,
            )

        atomic_write_text(cfg_path, new_text)
        rec = {
            "client_id": cid,
            "config_path": str(cfg_path),
            "server_key": srv_key,
            "prefix": (prefix or "pc").strip() or "pc",
            "existed_before": orig_existed,
            "created_dirs": orig_created_dirs,
            "backup_path": backup_path_str,
            "updated_at": round(time.time(), 3),
        }
        bindings_map[f"{cid}:{srv_key}"] = rec
        for ok_old in old_keys:
            bindings_map.pop(f"{cid}:{ok_old}", None)
        results.append(rec)

    atomic_write_json(_bindings_ledger_path(st_root), ledger)
    return {
        "ok": True,
        "server_key": srv_key,
        "migrated_from": old_keys,
        "bound_clients": results,
    }


def _is_json_effectively_empty(text: str, container_key: str) -> bool:
    if not text.strip():
        return True
    try:
        doc = json.loads(strip_jsonc(text))
        if not isinstance(doc, dict):
            return False
        if not doc:
            return True
        if set(doc.keys()) == {container_key} and isinstance(doc.get(container_key), dict) and not doc[container_key]:
            return not has_jsonc_comments(text)
    except Exception:
        return False
    return False


def unbind_desktop_clients(
    *,
    state_root: Path,
    clients: Any = None,
    prefix: str = "",
    dry_run: bool = False,
    home_dir: Optional[Path] = None,
    appdata_dir: Optional[Path] = None,
    platform_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Remove only Cosmos MCP entries from bound desktop configs with zero neighbor damage."""
    st_root = Path(state_root).expanduser().resolve()
    ledger = _load_bindings_ledger(st_root)
    bindings_map: Dict[str, Any] = ledger.get("bindings") or {}

    target_records: List[Tuple[str, Dict[str, Any]]] = []
    if clients:
        explicit_cids = parse_client_selection(
            clients,
            home_dir=home_dir,
            appdata_dir=appdata_dir,
            platform_name=platform_name,
        )
        srv_key = server_key_for_prefix(prefix or "pc")
        for cid in explicit_cids:
            rec_key = f"{cid}:{srv_key}"
            rec = bindings_map.get(rec_key) or {
                "client_id": cid,
                "config_path": str(
                    resolve_client_config_path(
                        cid,
                        home_dir=home_dir,
                        appdata_dir=appdata_dir,
                        platform_name=platform_name,
                    )
                ),
                "server_key": srv_key,
                "existed_before": True,
                "created_dirs": [],
                "backup_path": "",
            }
            target_records.append((rec_key, rec))
    else:
        for rec_key, rec in list(bindings_map.items()):
            if not isinstance(rec, dict):
                continue
            if prefix and str(rec.get("prefix") or "pc") != prefix.strip().lower():
                continue
            target_records.append((rec_key, rec))

    unbound: List[Dict[str, Any]] = []
    for rec_key, rec in target_records:
        cid = str(rec.get("client_id") or "")
        spec = DESKTOP_CLIENT_SPECS.get(cid)
        if spec is None:
            continue
        cfg_path = Path(str(rec.get("config_path") or ""))
        srv_key = str(rec.get("server_key") or server_key_for_prefix(prefix or "pc"))
        if not cfg_path.is_file():
            if not dry_run:
                bindings_map.pop(rec_key, None)
            continue

        cur_text = cfg_path.read_text(encoding="utf-8", errors="replace")
        if spec.format_kind == "toml":
            updated_text = _strip_toml_server_sections(cur_text, [srv_key])
            empty_now = not updated_text.strip()
        else:
            updated_text = remove_json_or_jsonc_server(
                cur_text,
                container_key=spec.container_key,
                server_keys=[srv_key],
            )
            empty_now = _is_json_effectively_empty(updated_text, spec.container_key)

        existed_before = bool(rec.get("existed_before", True))
        bak_p = Path(str(rec.get("backup_path") or "")) if rec.get("backup_path") else None
        action_taken = "unchanged"
        if updated_text != cur_text:
            if not existed_before and empty_now:
                action_taken = "removed_created_file"
                if not dry_run:
                    safe_trash_file(cfg_path, reason="unbind_created_config", undo_dir=st_root / ".undo_history")
                    for d_str in (rec.get("created_dirs") or []):
                        dp = Path(d_str)
                        if dp.is_dir() and not any(dp.iterdir()):
                            safe_trash_file(dp, reason="unbind_empty_created_dir", undo_dir=st_root / ".undo_history")
            else:
                action_taken = "removed_entry_preserved_neighbors"
                if not dry_run:
                    atomic_write_text(cfg_path, updated_text)

        if not dry_run:
            if bak_p is not None and bak_p.is_file():
                safe_trash_file(bak_p, reason="unbind_cleanup_backup", undo_dir=st_root / ".undo_history")
            bindings_map.pop(rec_key, None)

        unbound.append(
            {
                "client_id": cid,
                "config_path": str(cfg_path),
                "server_key": srv_key,
                "action": action_taken,
            }
        )

    if not dry_run and _bindings_ledger_path(st_root).parent.is_dir():
        atomic_write_json(_bindings_ledger_path(st_root), ledger)
    return {"ok": True, "dry_run": dry_run, "unbound": unbound}
