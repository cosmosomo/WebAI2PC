"""
Core Security Guardrail Module (`cosmos_mcp.core.guard`).

Pure Python >=3.9 standard-library implementation providing:
1. Multi-workspace root sandboxing (`workspace_roots: Sequence[Path]`) with symlink,
   junction, and Windows 8.3 short-filename canonicalization (`GetLongPathNameW` + `realpath`).
2. NTFS Alternate Data Stream (`::$DATA`, `file:stream`) & PowerShell backtick obfuscation blocking.
3. Hard credential & persistence isolation across all tiers (`L1..L4`): SSH/GPG keys,
   browser Cookie/Login Data stores, cloud/registry tokens, MCP own secrets/state/logs,
   and persistence vectors (`.git/hooks`, `.git/config`, shell profiles, Startup folders, Run keys).
4. Tokenize-based Python comment stripping (eliminating comment false positives) combined with
   flow-sensitive AST taint tracking (variable reassignment clears taint; sinks catch indirect writes).
5. Pluggable `extra_access_gate` callback slot for upper-layer capability extensions.
"""
from __future__ import annotations

import ast
import contextvars
import ctypes
from datetime import datetime, timezone
import inspect
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tokenize
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple, Union

CREATE_NO_WINDOW: int = 0x08000000
ERR_HUMAN_MODE_LOCKED = "ERR_HUMAN_MODE_LOCKED"
_READONLY_CALL_CTX: contextvars.ContextVar[bool] = contextvars.ContextVar("cosmos_readonly_call_ctx", default=False)

READONLY_PACKAGE_MARKERS: Tuple[str, ...] = (
    "site-packages",
    "dist-packages",
    "/uv/cache/",
    "/uv/archive",
    "/uv/tools/",
    "/pipx/venvs/",
    "/program files/",
    "/program files (x86)/",
    "/windowsapps/",
)

HOST_CREDENTIAL_PATH_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (
        r"(?i)[\\/]\.ssh[\\/](?:id_[a-z0-9_.-]+|authorized_keys|known_hosts|config|[^\\/\"'\s;|&><)`]*\.(?:pem|key))(?:$|[\\/\"'\s;|&><)`])",
        "SSH private keys and configuration files are isolated by Guard.",
    ),
    (
        r"(?i)[\\/]appdata[\\/]local[\\/](?:google[\\/]chrome|microsoft[\\/]edge|bravesoftware[\\/]brave-browser|chromium)[\\/]user data(?:$|[\\/\"'\s;|&><)`])",
        "Windows browser User Data / Cookie / Login Data stores are isolated by Guard.",
    ),
    (
        r"(?i)[\\/]appdata[\\/]roaming[\\/]mozilla[\\/]firefox[\\/]profiles(?:$|[\\/\"'\s;|&><)`])",
        "Firefox profile credential stores are isolated by Guard.",
    ),
    (
        r"(?i)[\\/]library[\\/]application support[\\/](?:google[\\/]chrome|microsoft edge|bravesoftware|firefox)(?:$|[\\/\"'\s;|&><)`])",
        "macOS browser User Data / Cookie stores are isolated by Guard.",
    ),
    (
        r"(?i)[\\/](?:\.config[\\/](?:google-chrome|microsoft-edge|chromium|brave)|\.mozilla[\\/]firefox)(?:$|[\\/\"'\s;|&><)`])",
        "Linux browser User Data / Cookie stores are isolated by Guard.",
    ),
    (
        r"(?i)[\\/]\.(?:aws|kube|gnupg|azure)(?:$|[\\/\"'\s;|&><)`])|[\\/]\.config[\\/]gcloud(?:$|[\\/\"'\s;|&><)`])",
        "Cloud provider and GPG key directories are isolated by Guard.",
    ),
    (
        r"(?i)(?:[\\/]\.(?:pypirc|netrc|git-credentials|docker[\\/]config\.json)|[\\/]\.cargo[\\/]credentials(?:\.toml)?|[\\/]\.?huggingface[\\/](?:token|stored_tokens))(?:$|[\\/\"'\s;|&><)`:])",
        "Package registry and container credential files are isolated by Guard.",
    ),
)

_NPMRC_TOKEN_RE = re.compile(r"(?i)(?:^|[\\/\"'\s=(;|&><])([^\s\"'|&;<>()`]*[\\/]\.npmrc|\.npmrc)(?=$|[\\/\"'\s;|&><)`:])")

DOTENV_PATH_PATTERN: Tuple[str, str] = (
    r"(?i)(?:^|[\\/])\.env(?:\.(?!(?:example|template|sample|dist|defaults)(?:$|[\\/\"'\s;|&><)`:]))[a-z0-9_.-]+)?(?:$|[\\/\"'\s;|&><)`:])",
    "Private .env environment files are isolated by Guard (.env.example and .env.template remain accessible).",
)

MCP_OWN_SECRET_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (
        r"(?i)(?:^|[\\/])\.cosmos-mcp[\\/](?:secrets|state|config|\.env(?:\.[a-z0-9_.-]+)?)(?:$|[\\/\"'\s;|&><)`:])",
        "MCP state root secrets and configuration files are isolated by Guard.",
    ),
    (
        r"(?i)(?:^|[\\/])\.(?:human_ui_secret|peer_hmac_secret)(?:$|[\\/\"'\s;|&><)`:])",
        "MCP session secret files are isolated by Guard.",
    ),
)

SENSITIVE_PATH_PATTERNS: Tuple[Tuple[str, str], ...] = HOST_CREDENTIAL_PATH_PATTERNS + MCP_OWN_SECRET_PATTERNS

WINDOWS_OS_DIRS: Tuple[str, ...] = (
    r"c:\windows",
    r"c:\program files",
    r"c:\program files (x86)",
    r"c:\programdata\microsoft",
)

POSIX_OS_DIRS: Tuple[str, ...] = (
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/etc",
    "/boot",
    "/system",
)

SSRF_CMD_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (
        r"(?i)\b(?:169\.254\.169\.254|100\.100\.100\.200|metadata\.google\.internal)\b",
        "Access to cloud metadata SSRF addresses is blocked by Guard.",
    ),
    (
        r"(?i)(?:curl|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|wget)\b[^\n;]*(?:\.ssh|CONNECTION_INFO|owner_password\.txt|Login\s*Data|Cookies|\.human_ui_secret|\.peer_hmac_secret)",
        "Network exfiltration of protected local credential files is blocked by Guard.",
    ),
)

_CLAUSE_HEAD_DELETE_VERB_RE = re.compile(
    r"(?i)^\s*(?:[(&{]\s*)*(?:(?:call|sudo|nohup|command|builtin)\s+|&+\s+|[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*"
    r"(?:[^\s\"'|&;<>()`]*[\\/])?(?:rm|del|erase|rd|rmdir|Remove-Item|ri|unlink|rimraf|Clear-Content|clc)(?:\.exe)?\b"
)
_CLAUSE_HEAD_KILL_VERB_RE = re.compile(
    r"(?i)^\s*(?:[(&{]\s*)*(?:(?:call|sudo|nohup|command|builtin)\s+|&+\s+|[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*"
    r"(?:[^\s\"'|&;<>()`]*[\\/])?(?:taskkill|Stop-Process|kill|spps|pkill|killall)(?:\.exe)?\b"
)
_PROTECTED_HOST_PROC_KILL_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"  (?:^|[\s\"'=/\\,])(?:explorer|chrome|msedge|firefox|safari|code|cursor|antigravity|windsurf|pwsh|powershell|lsass|csrss|svchost|wininit)\.exe\b"
    r"  | /im\s+[\"']?(?:explorer|chrome|msedge|firefox|safari|code|cursor|antigravity|windsurf|pwsh|powershell|lsass|csrss|svchost|wininit)(?:\.exe)?[\"']?(?=$|[\s;|&)])"
    r"  | \b(?:Stop-Process|spps)\b[^\n;|&]*?(?:-Name\s+|\s)[\"']?(?:explorer|chrome|msedge|firefox|safari|code|cursor|antigravity|windsurf|pwsh|powershell|lsass|csrss|svchost|wininit)[\"']?(?=$|[\s,;|&)])"
    r"  | \b(?:pkill|killall)\b(?:(?!-f\b)\s+-[A-Za-z0-9]+)*\s+[\"']?(?:explorer|chrome|msedge|firefox|safari|code|cursor|antigravity|windsurf|pwsh|powershell|lsass|csrss|svchost|wininit)(?:\.exe)?[\"']?(?=$|[\s;|&)])"
    r")"
)

USER_CONFIGURABLE_DESTRUCTIVE_CMD_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (
        _CLAUSE_HEAD_DELETE_VERB_RE.pattern,
        "Direct permanent file deletion (rm / del / rd / Remove-Item / Clear-Content) is blocked; move files to recoverable trash instead.",
    ),
    (
        r"(?i)\b(?:shutil\.rmtree|os\.remove|os\.unlink|os\.rmdir|os\.removedirs|\.unlink\s*\(|\.rmdir\s*\(|fs\.rmSync|fs\.unlinkSync|fs\.rmdirSync)\b",
        "Direct permanent file deletion in scripts (rmtree / os.remove / unlink) is blocked; use trash_file instead.",
    ),
    (
        r"(?i)\bgit\s+(?:reset\s+--(?!soft\b)\S+|clean\b[^\n;]*-[a-zA-Z]*[fdFD]|checkout\s+(?:--|-[fF]\b)|restore\s+(?!--staged\b)|push\s+[^\n;]*(?:--force(?!-with-lease\b|-if-includes\b)\b|-f\b)|branch\s+-D\b|stash\s+(?:drop|clear)\b)",
        "Destructive Git commands that erase uncommitted work or history are blocked.",
    ),
    (
        r"(?i)\b(?:Format-Volume|Clear-Disk|Initialize-Disk|diskpart|mkfs|dd\s+if=|cipher\s+/w|bcdedit|bootrec|fsutil|vssadmin\s+delete|wbadmin\s+delete|shutdown|reboot|Restart-Computer|Stop-Computer|logoff)\b",
        "Disk formatting, boot modification, or system shutdown/reboot commands are blocked.",
    ),
    (
        _PROTECTED_HOST_PROC_KILL_RE.pattern,
        "Terminating user browsers, IDEs, shells, or OS system processes is blocked.",
    ),
    (
        r"(?i)(?:\breg(?:\.exe)?\s+(?:add|delete|import)\b[^\n;]*\\currentversion\\run(?:once)?\b|\b(?:Set-ItemProperty|New-ItemProperty|Remove-ItemProperty)\b[^\n;]*\\currentversion\\run(?:once)?\b|\bschtasks(?:\.exe)?\s+/create\b|\bRegister-ScheduledTask\b)",
        "Modifying startup registry Run keys or creating scheduled tasks via MCP is blocked.",
    ),
)

MCP_SELF_PROTECT_CMD_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (
        r"(?i)\b(?:Stop-Process|spps|kill|taskkill|pkill|killall)\b[^\n;]*(?:launcher\.py|server\.py|cosmos_mcp|cloudflared|ngrok)",
        "Terminating MCP daemon or active tunnel processes is blocked.",
    ),
)

DESTRUCTIVE_CMD_PATTERNS: Tuple[Tuple[str, str], ...] = USER_CONFIGURABLE_DESTRUCTIVE_CMD_PATTERNS + MCP_SELF_PROTECT_CMD_PATTERNS

_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----")
MCP_SELF_REDACT_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bcmcp_[A-Za-z0-9_\-]{16,}\b"), "[REDACTED_MCP_TOKEN]"),
    (re.compile(r"\blpcmcp_[A-Za-z0-9_-]{16,}\b"), "[REDACTED_MCP_TOKEN]"),
)
PROJECT_SECRET_REDACT_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (_PRIVATE_KEY_RE, "[REDACTED_PRIVATE_KEY_BY_GUARD]"),
    (
        re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{16,})\b"),
        "[REDACTED_API_CREDENTIAL]",
    ),
)
SECRET_REDACT_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = MCP_SELF_REDACT_PATTERNS + PROJECT_SECRET_REDACT_PATTERNS

_SHELL_RC_NAMES = frozenset({
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".zshrc",
    ".zprofile",
    ".profile",
})

_PROTECTED_SECRET_BASENAMES = frozenset({
    ".human_ui_secret",
    ".peer_hmac_secret",
})

_PROTECTED_AUDIT_NAMES = ("mcp_audit.jsonl", "security_events.jsonl", "mcp_wire.jsonl")
_PROTECTED_GUARD_NAMES = (
    "desired_mode.json",
    "custom_profiles.json",
    "kill_signal.json",
    "bg_jobs.json",
)
_STATE_SENSITIVE_TOKEN_RE = re.compile(
    r"(?i)^(?:auth\.json|owner_password\.txt|connection(?:_[a-z0-9_.-]+)?\.txt|.*connection_info.*\.txt|latest_consent_pair_code.*\.txt|oauth(?:_[a-z0-9_.-]+)?\.sqlite3(?:-wal|-shm)?|\.(?:human_ui_secret|peer_hmac_secret))$"
)
_ALL_TAMPER_NAMES = (
    _PROTECTED_AUDIT_NAMES
    + tuple(f"mcp_audit.jsonl.{i}" for i in range(1, 10))
    + tuple(f"security_events.jsonl.{i}" for i in range(1, 10))
    + _PROTECTED_GUARD_NAMES
)
_PROTECTED_NAME_ALT = (
    r"(?:mcp_audit|security_events|mcp_wire)\.jsonl(?:\.\d+)?|"
    + "|".join(re.escape(n) for n in (_PROTECTED_GUARD_NAMES + ("auth.json", "owner_password.txt")))
)
_PROTECTED_SECRET_FILE_RE = re.compile(
    r"(?i)^\.(?:human_ui_secret|peer_hmac_secret)$"
)

_PS_BRACED_ENV_RE = re.compile(r"\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}", re.IGNORECASE)
_PS_ENV_RE = re.compile(r"\$env:([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)
_WIN_PCT_ENV_RE = re.compile(r"%([A-Za-z_][A-Za-z0-9_()]*)%")
_POSIX_BRACED_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_POSIX_ENV_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")
_CMD_TILDE_RE = re.compile(r"""(^|[\s"'=(;|&><])~(?=$|[/\\\s"');|&><])""")
_CMD_TOKEN_RE = re.compile(r'''"([^"\r\n]{1,512})"|'([^'\r\n]{1,512})'|([^\s"'|&;<>()`]{1,512})''')
_URL_SCHEME_RE = re.compile(r"^(?:https?|wss?|ftp|ssh|git|mailto)://|^git@", re.IGNORECASE)
_FILE_URI_RE = re.compile(r"^file://+", re.IGNORECASE)
_NTFS_ADS_STREAM_TYPE_RE = re.compile(r"::\$[A-Za-z0-9_]+")
_WIN_EXT_PREFIX_RE = re.compile(r"^\\\\[?.]\\(?:UNC\\)?", re.IGNORECASE)
_WIN_DRIVE_ABS_RE = re.compile(r"^[A-Za-z]:(?:$|[\\/])")
_UNC_ABS_RE = re.compile(r"^\\\\[A-Za-z0-9_.?-]+\\[A-Za-z0-9_.$ -]+")
_PARENT_TRAVERSAL_RE = re.compile(r"(?:^|[\\/])\.\.(?:$|[\\/])")
_HOME_ENV_TOKEN_RE = re.compile(
    r"(?i)(?:^~(?=$|[\\/])|%(?:USERPROFILE|APPDATA|LOCALAPPDATA|HOMEPATH|TEMP|TMP|WINDIR|SYSTEMROOT|PROGRAMDATA|PUBLIC)%|\$\{?(?:env:)?(?:HOME|USERPROFILE|APPDATA|LOCALAPPDATA|TEMP|TMP|TMPDIR)\}?)"
)
_SHELL_CLAUSE_SPLIT_RE = re.compile(r"(?:\r?\n|&&|\|\||[;|])")
_SHELL_WRITE_CMD_RE = re.compile(
    r"(?i)(?:>|>>|\b(?:Out-File|Set-Content|Add-Content|Clear-Content|Remove-Item|Move-Item|Copy-Item|Rename-Item|New-Item|sc|ac|clc|ri|mi|cpi|rni|ni|rm|mv|cp|del|erase|rmdir|rd|tee|truncate)\b)"
)
_INLINE_PY_DASH_C_RE = re.compile(
    r"""(?is)(?:^|[\s;|&("'\\/])(?:python[0-9.]*|py)(?:\.exe)?["']?(?:\s+-[A-Za-z0-9_=-]+)*\s+-c\s+(?:"((?:[^"\\]|\\.)*)"|'([^']*)')"""
)
_L3_PY_ISOLATED_FLAG_RE = re.compile(
    r"""(?i)(?:^|[\s;|&("'\\/])(?:python[0-9.]*|py)(?:\.exe)?["']?(?:\s+-[A-Za-z0-9_=-]+)*\s+-(?=[A-Za-z]*[IES])[A-Za-z]+\b"""
)
_SAFE_PY_ISOLATED_PIP_INSTALL_RE = re.compile(
    r"""(?ix)^\s*(?:&\s*)?(?:"[^"\r\n]*?(?:python[0-9.]*|py)(?:\.exe)?"|'[^'\r\n]*?(?:python[0-9.]*|py)(?:\.exe)?'|(?:[^\s"'|&;<>()`]*[\\/])?(?:python[0-9.]*|py)(?:\.exe)?)(?:\s+(?:-[0-9]+|-[IsuBbv]+|-W\s*\S+|-X\s*\S+|--isolated))*\s+-I(?:\s+(?:-[IsuBbv]+|-W\s*\S+|-X\s*\S+|--isolated))*\s+-m\s+pip\s+install\b"""
)
_SAFE_BUILD_CLEAN_NAMES = frozenset({
    "build",
    "dist",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    ".next",
    ".nuxt",
    ".vite",
    ".turbo",
    "target",
    "coverage",
})
_STANDARD_TOOLCHAIN_BIN_RE = re.compile(
    r"^(?:python(?:\d+(?:\.\d+)*)?|py|pytest|ruff|node|npm|npx|pnpm|yarn|bun|go|gofmt|cargo|rustc|rust-analyzer|ast-grep|sg|tsc|git|rg|uv|uvx)$",
    re.IGNORECASE,
)
_EMBEDDED_WIN_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z]:[\\/][^\s\"'<>|;,()\[\]{}`]{1,480})")
_EMBEDDED_POSIX_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_.:/-])(/(?:home|Users|root|tmp|var|etc|opt|srv|mnt|media|private|proc|sys|dev|run|boot)(?:[\\/][^\s\"'<>|;,()\[\]{}`]{1,480})?)"
)

HOST_TOOLCHAIN_PROBE_NAMES: Tuple[str, ...] = (
    "python", "python3", "py", "pytest", "ruff", "uv", "uvx",
    "node", "npm", "npx", "pnpm", "yarn", "bun",
    "go", "gofmt", "cargo", "rustc", "rust-analyzer",
    "ast-grep", "sg", "git", "rg",
)


def strip_file_uri(raw_s: str) -> str:
    if not _FILE_URI_RE.match(raw_s):
        return raw_s
    rest = _FILE_URI_RE.sub("", raw_s)
    if _WIN_DRIVE_ABS_RE.match(rest):
        return rest
    return "/" + rest.lstrip("/")


def _win32_long_path(path_str: str) -> str:
    if sys.platform != "win32" or "~" not in path_str:
        return path_str
    try:
        kernel32 = ctypes.windll.kernel32
        GetLongPathNameW = kernel32.GetLongPathNameW
        GetLongPathNameW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
        GetLongPathNameW.restype = ctypes.c_uint32
        needed = GetLongPathNameW(path_str, None, 0)
        if needed > 0:
            buf = ctypes.create_unicode_buffer(needed + 2)
            written = GetLongPathNameW(path_str, buf, needed + 2)
            if 0 < written <= needed + 2:
                return buf.value
    except Exception:
        pass
    return path_str


def canonical_realpath(raw_p: Union[str, Path]) -> Path:
    """Resolve `~`, symlinks/junctions, and Windows 8.3 short names even when leaf segments do not exist yet."""
    s = strip_file_uri(str(raw_p or "").strip())
    if not s:
        return Path("")
    expanded = os.path.expanduser(os.path.expandvars(s))
    norm_s = os.path.normpath(os.path.abspath(expanded))
    if sys.platform == "win32":
        drv, tail = os.path.splitdrive(norm_s)
        if tail:
            cleaned = [
                (pt.rstrip(". ") if pt not in ("", ".", "..") and ":" not in pt else pt)
                for pt in tail.split("\\")
            ]
            norm_s = drv + "\\".join(cleaned)
    try:
        p_cur = Path(norm_s)
        if p_cur.exists() or os.path.lexists(str(p_cur)):
            rp = os.path.realpath(str(p_cur))
            return Path(_win32_long_path(rp))
        # Walk up to deepest existing ancestor so 8.3 short dirs or symlinked parent dirs still resolve
        missing_tail: List[str] = []
        probe = p_cur
        while probe != probe.parent and not (probe.exists() or os.path.lexists(str(probe))):
            missing_tail.append(probe.name)
            probe = probe.parent
        if probe.exists() or os.path.lexists(str(probe)):
            base_real = Path(_win32_long_path(os.path.realpath(str(probe))))
            for seg in reversed(missing_tail):
                base_real = base_real / seg
            return Path(os.path.normpath(str(base_real)))
        return Path(os.path.realpath(norm_s))
    except Exception:
        return Path(norm_s)


def _is_under_prefix(cand_low: str, prefix_low: str) -> bool:
    if not cand_low or not prefix_low:
        return False
    sep = "\\" if sys.platform == "win32" else "/"
    c_clean = cand_low.rstrip("\\/")
    p_clean = prefix_low.rstrip("\\/")
    if not p_clean:
        return cand_low.startswith("/")
    return c_clean == p_clean or c_clean.startswith(p_clean + sep)


def _build_env_lookup() -> Dict[str, str]:
    home = str(Path.home())
    lookup = {k.lower(): v for k, v in os.environ.items() if isinstance(v, str)}
    lookup.setdefault("home", home)
    lookup.setdefault("userprofile", home)
    lookup.setdefault("appdata", str(Path(home) / "AppData" / "Roaming"))
    lookup.setdefault("localappdata", str(Path(home) / "AppData" / "Local"))
    lookup.setdefault("systemroot", os.environ.get("SystemRoot") or r"C:\Windows")
    lookup.setdefault("windir", os.environ.get("WINDIR") or r"C:\Windows")
    lookup.setdefault("programdata", os.environ.get("ProgramData") or r"C:\ProgramData")
    return lookup


def expand_env_and_tilde(raw_text: str) -> str:
    """Expand `%VAR%`, `$VAR`, `${VAR}`, `$env:VAR`, and `~` across Windows and POSIX."""
    if not raw_text:
        return ""
    env_map = _build_env_lookup()
    home = env_map["home"]

    def _sub_var(match: re.Match[str]) -> str:
        key = match.group(1).lower()
        return env_map.get(key, match.group(0))

    out = _PS_BRACED_ENV_RE.sub(_sub_var, raw_text)
    out = _PS_ENV_RE.sub(_sub_var, out)
    out = _WIN_PCT_ENV_RE.sub(_sub_var, out)
    out = _POSIX_BRACED_ENV_RE.sub(_sub_var, out)
    out = _POSIX_ENV_RE.sub(_sub_var, out)
    if out == "~":
        return home
    if out.startswith(("~/", "~\\")):
        return str(Path(home) / out[2:])
    return _CMD_TILDE_RE.sub(lambda m: m.group(1) + home, out)


def strip_powershell_backticks(raw_text: str) -> str:
    """Strip PowerShell escape backticks (`) outside single-quoted literal segments."""
    if not raw_text or "`" not in raw_text:
        return raw_text
    out_chars: List[str] = []
    in_sq = False
    n = len(raw_text)
    i = 0
    while i < n:
        ch = raw_text[i]
        if ch == "'":
            if in_sq and i + 1 < n and raw_text[i + 1] == "'":
                out_chars.append("''")
                i += 2
                continue
            in_sq = not in_sq
            out_chars.append(ch)
            i += 1
            continue
        if ch == "`" and not in_sq:
            if i + 1 < n:
                nxt = raw_text[i + 1]
                if nxt == "`":
                    out_chars.append("`")
                elif nxt not in ("\r", "\n", "0"):
                    out_chars.append(nxt)
                i += 2
                continue
            i += 1
            continue
        out_chars.append(ch)
        i += 1
    return "".join(out_chars)


def strip_shell_comments(raw_cmd: str) -> str:
    """Strip PowerShell `<# ... #>` block comments and unquoted `# ...` / `rem` comments."""
    if not raw_cmd:
        return ""
    cleaned = re.sub(r"<#[\s\S]*?#>", " ", raw_cmd)
    out: List[str] = []
    in_sq = False
    in_dq = False
    i = 0
    n = len(cleaned)
    while i < n:
        ch = cleaned[i]
        if in_sq:
            out.append(ch)
            if ch == "'":
                if i + 1 < n and cleaned[i + 1] == "'":
                    out.append("'")
                    i += 2
                    continue
                in_sq = False
            i += 1
            continue
        if in_dq:
            out.append(ch)
            if ch in ("`", "\\") and i + 1 < n:
                out.append(cleaned[i + 1])
                i += 2
                continue
            if ch == '"':
                in_dq = False
            i += 1
            continue
        if ch == "'":
            in_sq = True
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            in_dq = True
            out.append(ch)
            i += 1
            continue
        if ch == "#" and (i == 0 or cleaned[i - 1] in (" ", "\t", "\r", "\n", ";", "|", "&", "(")):
            while i < n and cleaned[i] != "\n":
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def strip_python_comments_tokenize(code: str) -> str:
    """Strip Python `# ...` comments via stdlib `tokenize` while preserving strings and line offsets."""
    if not code or "#" not in code:
        return code
    out_parts: List[str] = []
    last_end = (1, 0)
    try:
        for tok in tokenize.generate_tokens(io.StringIO(code).readline):
            ttype, tstr, start, end, _ = tok
            if ttype in (tokenize.ENCODING, tokenize.ENDMARKER):
                continue
            s_row, s_col = start
            l_row, l_col = last_end
            if s_row == l_row:
                if s_col > l_col:
                    out_parts.append(" " * (s_col - l_col))
            else:
                out_parts.append("\n" * (s_row - l_row) + (" " * s_col))
            if ttype == tokenize.COMMENT:
                out_parts.append("")
            else:
                out_parts.append(tstr)
            last_end = end
        return "".join(out_parts)
    except Exception:
        return "\n".join(ln for ln in code.splitlines() if not ln.lstrip().startswith("#"))


def _strip_python_strings_and_comments(code: str) -> str:
    out_parts: List[str] = []
    last_end = (1, 0)
    try:
        for tok in tokenize.generate_tokens(io.StringIO(code).readline):
            ttype, tstr, start, end, _ = tok
            if ttype in (tokenize.ENCODING, tokenize.ENDMARKER):
                continue
            s_row, s_col = start
            l_row, l_col = last_end
            if s_row == l_row:
                if s_col > l_col:
                    out_parts.append(" " * (s_col - l_col))
            else:
                out_parts.append("\n" * (s_row - l_row) + (" " * s_col))
            if ttype == tokenize.STRING:
                out_parts.append('""')
            elif ttype == tokenize.COMMENT:
                out_parts.append("")
            else:
                out_parts.append(tstr)
            last_end = end
        return "".join(out_parts)
    except Exception:
        return "\n".join(ln for ln in code.splitlines() if not ln.lstrip().startswith("#"))


def _mask_shell_quoted_literals(raw_cmd: str) -> str:
    """Replace contents inside single-quoted and double-quoted shell strings with benign placeholders."""
    if not raw_cmd or ("'" not in raw_cmd and '"' not in raw_cmd):
        return raw_cmd
    out: List[str] = []
    i = 0
    n = len(raw_cmd)
    while i < n:
        ch = raw_cmd[i]
        if ch == "'":
            out.append("'")
            i += 1
            while i < n:
                if raw_cmd[i] == "'":
                    if i + 1 < n and raw_cmd[i + 1] == "'":
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            out.append("__COSMOS_QUOTED__'")
            continue
        if ch == '"':
            out.append('"')
            i += 1
            while i < n:
                if raw_cmd[i] in ("\\", "`") and i + 1 < n:
                    i += 2
                    continue
                if raw_cmd[i] == '"':
                    i += 1
                    break
                i += 1
            out.append('__COSMOS_QUOTED__"')
            continue
        out.append(ch)
        i += 1
    return "".join(out)


_INLINE_SUBSHELL_RE = re.compile(
    r"""(?is)(?:^|[\s;|&(\"'\\/])(?:cmd(?:\.exe)?\s+/[ck]|(?:powershell|pwsh)(?:\.exe)?(?:\s+-[A-Za-z0-9_-]+(?:\s+(?![-\"'])\S+)?)*\s+(?:-Command|-c)|(?:ba|z|da|k)?sh(?:\.exe)?\s+-c)\s+(?:"((?:[^"\\]|\\.)*)"|'((?:[^']|'')*)')"""
)
_DOCKER_BIND_VOL_RE = re.compile(
    r"^(?P<host>(?:[A-Za-z]:[\\/][^\r\n:]*|\.{1,2}(?:$|[\\/][^\r\n:]*)|~(?:$|[\\/][^\r\n:]*)|/[^\r\n:]+)):(?P<container>/[^\r\n:]*)(?::[A-Za-z0-9_,=-]+)?$"
)


def has_ntfs_ads_stream(raw_path: str, *, for_command_token: bool = False) -> bool:
    """Detect Windows NTFS Alternate Data Streams (`file.txt:stream`, `::$DATA`)."""
    s = str(raw_path or "").strip().strip("\"'")
    if not s or _URL_SCHEME_RE.match(s):
        return False
    if for_command_token and s.startswith("$"):
        return False
    if _NTFS_ADS_STREAM_TYPE_RE.search(s):
        return True
    s_clean = strip_file_uri(s)
    s_clean = _WIN_EXT_PREFIX_RE.sub("", s_clean)
    if re.match(r"^[A-Za-z]:$", s_clean):
        return False
    has_win_drive = bool(re.match(r"^[A-Za-z]:[\\/]", s_clean))
    rest = s_clean[2:] if has_win_drive else s_clean
    if ":" not in rest:
        return False
    if not for_command_token:
        if sys.platform != "win32" and not has_win_drive:
            return False
        return ":" in rest

    # `for_command_token=True`: exclude `HEAD:refs/heads/main`, `main:src/app.py`, `./data:/data`, ports, etc.
    rest_no_pytest = re.sub(r"::(?!\$)[A-Za-z0-9_\[\].,/*+-]+", "", rest)
    if ":" not in rest_no_pytest:
        return False
    file_part, stream_part = rest_no_pytest.split(":", 1)
    if not file_part or not stream_part:
        return False
    # NTFS ADS stream names cannot contain path slashes `/`/`\`, extra colons, whitespace, or be pure port digits
    if stream_part.isdigit() or not re.fullmatch(r"[A-Za-z0-9_.$+-]{1,128}", stream_part):
        return False
    if has_win_drive:
        return bool(re.search(r"[\\/][^\\/:]+$", file_part))
    if "\\" in file_part:
        return not file_part.endswith("\\")
    # Relative slash-containing prefixes like `origin/main:foo` or `ghcr.io/org/img:tag` are not local files unless `./` or `../` or existing on disk
    try:
        if Path(file_part).exists():
            return True
    except OSError:
        pass
    if "/" in file_part and not file_part.startswith(("./", "../")):
        return False
    return bool(re.search(r"(?:^|[\\/])[A-Za-z0-9_.-]+\.[A-Za-z][A-Za-z0-9]{0,11}$", file_part))


def check_persistence_components(p: Path, *, check_git_repo_meta: bool = True) -> Optional[str]:
    parts_low = [pt.lower() for pt in p.parts]
    name_low = p.name.lower()
    if name_low in _SHELL_RC_NAMES:
        return "Modifying user shell profile startup files is prohibited."
    if (
        name_low == "profile.ps1"
        or name_low.endswith("_profile.ps1")
        or (name_low.endswith("profile.ps1") and any(x in parts_low for x in ("powershell", "windowspowershell")))
    ):
        return "Modifying PowerShell profile startup scripts is prohibited."
    for i in range(len(parts_low) - 2):
        if parts_low[i] == "start menu" and parts_low[i + 1] == "programs" and parts_low[i + 2] == "startup":
            return "Writing to Windows Startup folder is prohibited."
    if "startup" in parts_low and any(x in parts_low for x in ("microsoft", "start menu", "programs")):
        return "Writing to Windows Startup folder is prohibited."
    for i in range(len(parts_low) - 1):
        if parts_low[i] == "library" and parts_low[i + 1] in ("launchagents", "launchdaemons"):
            return "Writing to macOS LaunchAgents/LaunchDaemons is prohibited."
        if parts_low[i] == ".config" and parts_low[i + 1] == "autostart":
            return "Writing to Linux autostart directory is prohibited."
        if check_git_repo_meta and parts_low[i] == ".git" and parts_low[i + 1] in ("hooks", "config"):
            return "Modifying Git repository hooks or .git/config via MCP is prohibited."
    return None


def is_readonly_or_package_install_path(install_path: Union[str, Path]) -> bool:
    """Detect whether `install_path` lives inside `site-packages`, `dist-packages`, `uv` cache/archive, or a read-only dir."""
    norm = "/" + str(install_path).replace("\\", "/").lower().strip("/") + "/"
    for seg in (
        "/site-packages/",
        "/dist-packages/",
        "/uv/cache/",
        "/uv/tools/",
        "/pipx/venvs/",
        "/program files/",
        "/program files (x86)/",
        "/windowsapps/",
    ):
        if seg in norm:
            return True
    if "/uv/archive" in norm:
        return True
    try:
        p_obj = Path(install_path)
        probe_dir = p_obj if p_obj.is_dir() else p_obj.parent
        if probe_dir.exists() and not os.access(str(probe_dir), os.W_OK):
            return True
    except OSError:
        return True
    return False


def _has_initialized_state_files(dir_path: Path) -> bool:
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
    """Return `%LOCALAPPDATA%\\CosmosMCP` on Windows or `~/.cosmos-mcp` on POSIX (with legacy fallback)."""
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
    if _has_initialized_state_files(new_dir):
        return new_dir
    if _has_initialized_state_files(legacy_dir):
        return legacy_dir
    return new_dir


def resolve_state_root(
    product_root: Optional[Union[str, Path]] = None,
    cli_state_dir: str = "",
    *,
    env: Optional[Mapping[str, str]] = None,
    platform_name: Optional[str] = None,
) -> Path:
    """Unified state directory resolver shared across core guardrails, runtime policy, and CLI launcher."""
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
        _has_initialized_state_files(repo_anchor) or (repo_anchor / "secrets" / "auth.json").is_file()
    ):
        return repo_anchor.expanduser().resolve()

    target = default_user_state_dir(platform_name=platform_name, env=eff_env)
    try:
        return target.resolve()
    except OSError:
        return target


def to_short_tier_code(raw_tier: Union[str, int, None], restrict_to_workspace: bool = True) -> str:
    """Normalize any tier representation into short L0 tier code (`"L1"`, `"L2"`, `"L3"`, `"L4"`)."""
    if raw_tier is None or str(raw_tier).strip() == "":
        return "L3" if restrict_to_workspace else "L4"
    s = str(raw_tier).strip().lower()
    mapping = {
        "1": "L1",
        "l1": "L1",
        "readonly": "L1",
        "tier1": "L1",
        "tier1_readonly": "L1",
        "2": "L2",
        "l2": "L2",
        "edit": "L2",
        "tier2": "L2",
        "tier2_workspace_edit": "L2",
        "3": "L3",
        "l3": "L3",
        "dev": "L3",
        "standard": "L3",
        "tier3": "L3",
        "tier3_workspace_dev": "L3",
        "4": "L4",
        "l4": "L4",
        "full": "L4",
        "max": "L4",
        "agent": "L4",
        "tier4": "L4",
        "tier4_full_agent": "L4",
        "tier4_full_access": "L4",
        "tier4_full_power": "L4",
    }
    return mapping.get(s, "L3" if restrict_to_workspace else "L4")


normalize_tier = to_short_tier_code


def _parse_workspace_roots_input(
    roots_or_dir: Union[str, Path, Sequence[Union[str, Path]], None],
) -> Tuple[Path, ...]:
    if roots_or_dir is None:
        return ()
    raw_items: List[Union[str, Path]] = []
    if isinstance(roots_or_dir, Path):
        raw_items.append(roots_or_dir)
    elif isinstance(roots_or_dir, str):
        s = roots_or_dir.strip()
        if not s:
            return ()
        for part in s.split(os.pathsep):
            pt = part.strip()
            if pt:
                raw_items.append(pt)
    else:
        for item in roots_or_dir:
            if item is not None and str(item).strip():
                raw_items.append(item)

    resolved_list: List[Path] = []
    seen_low: Set[str] = set()
    for raw in raw_items:
        expanded = expand_env_and_tilde(str(raw).strip())
        if not expanded:
            continue
        rp = canonical_realpath(expanded)
        k = os.path.normcase(str(rp)).rstrip("\\/")
        if k and k not in seen_low:
            seen_low.add(k)
            resolved_list.append(rp)
    return tuple(resolved_list)


def _norm_host_dir_key(raw_p: str) -> str:
    return os.path.normcase(os.path.normpath(raw_p.strip().strip('"'))).rstrip("\\/")


def get_stripped_host_path(
    raw_path: Optional[str] = None,
    *,
    exclude_venv: Optional[Path] = None,
    state_root: Optional[Path] = None,
    product_root: Optional[Path] = None,
) -> str:
    """Return host `PATH` after stripping MCP's own internal `.venv` and inherited `VIRTUAL_ENV`."""
    src_path = os.environ.get("PATH", "") if raw_path is None else raw_path
    if not src_path:
        return ""
    sep = os.pathsep
    slash_sep = "\\" if sys.platform == "win32" else "/"
    excl_keys: Set[str] = set()
    if exclude_venv is not None:
        excl_keys.add(_norm_host_dir_key(str(exclude_venv)))
        excl_keys.add(_norm_host_dir_key(str(canonical_realpath(exclude_venv))))
    base_keys: Set[str] = {
        _norm_host_dir_key(sys.base_prefix),
        _norm_host_dir_key(str(canonical_realpath(sys.base_prefix))),
    }
    internal_cands: List[Path] = []
    if state_root is not None:
        internal_cands.append(state_root / ".venv")
    if product_root is not None:
        internal_cands.append(product_root / ".venv")
    if sys.prefix != sys.base_prefix:
        internal_cands.append(Path(sys.prefix))
    inh_venv = os.environ.get("VIRTUAL_ENV", "").strip()
    if inh_venv:
        internal_cands.append(Path(inh_venv))

    strip_prefixes: List[str] = []
    for cand in internal_cands:
        for k in (_norm_host_dir_key(str(cand)), _norm_host_dir_key(str(canonical_realpath(cand)))):
            if k and k not in base_keys and k not in excl_keys and k not in strip_prefixes:
                strip_prefixes.append(k)

    kept: List[str] = []
    for entry in src_path.split(sep):
        tok = entry.strip()
        if not tok:
            continue
        ck = _norm_host_dir_key(tok)
        if any(ck == pref or ck.startswith(pref + slash_sep) for pref in strip_prefixes):
            continue
        kept.append(entry)
    return sep.join(kept)


def _discover_host_toolchains_once() -> Tuple[Dict[str, str], frozenset[str], Tuple[str, ...]]:
    stripped_path = get_stripped_host_path()
    home = Path.home()
    extra_bins: List[str] = []
    for extra_d in (
        home / ".cargo" / "bin",
        home / ".bun" / "bin",
        home / "scoop" / "shims",
        home / ".local" / "bin",
        Path(r"C:\Program Files\Go\bin") if sys.platform == "win32" else Path("/usr/local/go/bin"),
        Path(r"C:\Program Files (x86)\Go\bin") if sys.platform == "win32" else Path("/opt/homebrew/bin"),
    ):
        if extra_d.is_dir():
            extra_bins.append(str(extra_d))
    probe_path = os.pathsep.join([p for p in ([stripped_path] + extra_bins) if p])

    by_name: Dict[str, str] = {}
    exe_set: Set[str] = set()
    dir_list: List[str] = []
    broad_dirs = {
        _norm_host_dir_key(str(home)),
        _norm_host_dir_key(str(home / "Desktop")),
        _norm_host_dir_key(str(home / "Documents")),
        _norm_host_dir_key(str(home / "Downloads")),
    }
    for env_t in ("TEMP", "TMP", "TMPDIR"):
        tv = os.environ.get(env_t, "").strip()
        if tv:
            broad_dirs.add(_norm_host_dir_key(tv))

    def _register_exe(p_raw: Path) -> None:
        raw_low = str(p_raw).lower()
        if sys.platform == "win32" and "\\microsoft\\windowsapps\\" in raw_low:
            return
        exe_set.add(raw_low)
        rp = canonical_realpath(p_raw)
        exe_set.add(str(rp).lower())
        for d_cand in (p_raw.parent, rp.parent):
            if d_cand.parent == d_cand:
                continue
            dk = _norm_host_dir_key(str(d_cand))
            if dk and dk not in broad_dirs and dk not in dir_list:
                dir_list.append(dk)

    for tool_name in HOST_TOOLCHAIN_PROBE_NAMES:
        found = shutil.which(tool_name, path=probe_path)
        if not found:
            continue
        if sys.platform == "win32" and "\\microsoft\\windowsapps\\" in found.lower():
            continue
        fp = Path(found)
        by_name[tool_name] = str(fp)
        _register_exe(fp)
    return by_name, frozenset(exe_set), tuple(dir_list)


_DISCOVERED_TOOLCHAINS_MAP, _DISCOVERED_TOOLCHAIN_EXES, _DISCOVERED_TOOLCHAIN_DIRS = _discover_host_toolchains_once()


def get_discovered_toolchain_dirs() -> Tuple[str, ...]:
    return _DISCOVERED_TOOLCHAIN_DIRS


_DOTENV_EXEMPT_NAMES = frozenset({
    ".env.example",
    ".env.template",
    ".env.sample",
    ".env.dist",
    ".env.defaults",
})


def _is_private_dotenv_name(name: str) -> bool:
    nm_low = (name or "").strip().lower()
    if nm_low == ".env":
        return True
    if nm_low.startswith(".env.") and len(nm_low) > 5 and nm_low not in _DOTENV_EXEMPT_NAMES:
        return True
    return False


def _is_protected_secret_file(cand_path: Path) -> bool:
    nm = cand_path.name
    if _is_private_dotenv_name(nm):
        return True
    if _PROTECTED_SECRET_FILE_RE.match(nm):
        return True
    par_low = cand_path.parent.name.lower()
    if par_low == ".cargo" and nm.lower() in ("credentials", "credentials.toml"):
        return True
    return False


# --- Flow-Sensitive AST Taint Analysis ---

def _extract_target_names(target_node: ast.AST) -> Set[str]:
    names: Set[str] = set()
    if isinstance(target_node, ast.Name):
        names.add(target_node.id)
    elif isinstance(target_node, (ast.Tuple, ast.List)):
        for elt in target_node.elts:
            names.update(_extract_target_names(elt))
    elif isinstance(target_node, ast.Starred):
        names.update(_extract_target_names(target_node.value))
    return names


def _mode_node_is_mutating(mode_node: Optional[ast.AST]) -> bool:
    if mode_node is None:
        return False
    if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
        m_low = mode_node.value.lower()
        return any(ch in m_low for ch in ("w", "a", "x", "+"))
    return True


def _collect_string_literals(node: ast.AST) -> List[str]:
    return [sub.value for sub in ast.walk(node) if isinstance(sub, ast.Constant) and isinstance(sub.value, str)]


def _eval_static_path_str(
    node: Optional[ast.AST],
    var_str_vals: Optional[Dict[str, str]] = None,
    cwd_base: str = "",
) -> Optional[str]:
    if node is None:
        return None
    vmap = var_str_vals or {}
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return vmap.get(node.id)
    if isinstance(node, ast.JoinedStr):
        parts: List[str] = []
        for v in node.values:
            sv = _eval_static_path_str(v, vmap, cwd_base=cwd_base)
            if sv is None:
                return None
            parts.append(sv)
        return "".join(parts)
    if isinstance(node, ast.FormattedValue):
        return _eval_static_path_str(node.value, vmap, cwd_base=cwd_base)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.Add)):
        ls = _eval_static_path_str(node.left, vmap, cwd_base=cwd_base)
        rs = _eval_static_path_str(node.right, vmap, cwd_base=cwd_base)
        if ls is not None and rs is not None:
            return (ls.rstrip("\\/") + "\\" + rs.lstrip("\\/")) if isinstance(node.op, ast.Div) else (ls + rs)
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        base_p = _eval_static_path_str(node.value, vmap, cwd_base=cwd_base)
        if base_p is not None:
            return str(Path(expand_env_and_tilde(base_p)).parent)
    if isinstance(node, ast.Subscript):
        if (
            isinstance(node.value, ast.Attribute)
            and node.value.attr == "environ"
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "os"
        ):
            ek = _eval_static_path_str(node.slice, vmap, cwd_base=cwd_base)
            if ek and re.match(
                r"^(?:HOME|USERPROFILE|APPDATA|LOCALAPPDATA|PUBLIC|PROGRAMDATA|TEMP|TMP|TMPDIR|WINDIR|SYSTEMROOT)$",
                ek.strip(),
                re.IGNORECASE,
            ):
                return expand_env_and_tilde(f"${ek.strip()}")
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Name) and f.id in ("Path", "PurePath", "PureWindowsPath", "WindowsPath", "PosixPath", "str"):
            if node.args:
                folded = [_eval_static_path_str(a, vmap, cwd_base=cwd_base) for a in node.args]
                if all(x is not None for x in folded):
                    return "\\".join(str(x).strip("\\/") if idx > 0 else str(x).rstrip("\\/") for idx, x in enumerate(folded))
        if isinstance(f, ast.Attribute):
            if f.attr == "home" and isinstance(f.value, ast.Name) and f.value.id in ("Path", "WindowsPath", "PosixPath"):
                return str(Path.home())
            if f.attr in ("cwd", "getcwd"):
                return cwd_base or str(Path.cwd())
            if f.attr in ("getenv", "get") and node.args:
                is_env_call = (isinstance(f.value, ast.Name) and f.value.id == "os" and f.attr == "getenv") or (
                    isinstance(f.value, ast.Attribute)
                    and f.value.attr == "environ"
                    and isinstance(f.value.value, ast.Name)
                    and f.value.value.id == "os"
                )
                if is_env_call:
                    ek = _eval_static_path_str(node.args[0], vmap, cwd_base=cwd_base)
                    if ek and re.match(
                        r"^(?:HOME|USERPROFILE|APPDATA|LOCALAPPDATA|PUBLIC|PROGRAMDATA|TEMP|TMP|TMPDIR|WINDIR|SYSTEMROOT)$",
                        ek.strip(),
                        re.IGNORECASE,
                    ):
                        return expand_env_and_tilde(f"${ek.strip()}")
            if f.attr in ("expanduser", "expandvars", "abspath", "normpath", "realpath", "fspath") and node.args:
                return _eval_static_path_str(node.args[0], vmap, cwd_base=cwd_base)
            if f.attr in ("resolve", "absolute", "expanduser"):
                return _eval_static_path_str(f.value, vmap, cwd_base=cwd_base)
            if f.attr == "join" and node.args:
                folded = [_eval_static_path_str(a, vmap, cwd_base=cwd_base) for a in node.args]
                if all(x is not None for x in folded):
                    return "\\".join(str(x).strip("\\/") if idx > 0 else str(x).rstrip("\\/") for idx, x in enumerate(folded))
            if f.attr == "joinpath":
                base_s = _eval_static_path_str(f.value, vmap, cwd_base=cwd_base)
                folded = [_eval_static_path_str(a, vmap, cwd_base=cwd_base) for a in node.args]
                if base_s is not None and all(x is not None for x in folded):
                    return "\\".join([base_s.rstrip("\\/")] + [str(x).strip("\\/") for x in folded])
            if f.attr == "with_name" and len(node.args) == 1:
                base_s = _eval_static_path_str(f.value, vmap, cwd_base=cwd_base)
                nm_s = _eval_static_path_str(node.args[0], vmap, cwd_base=cwd_base)
                if base_s is not None and nm_s is not None:
                    norm_b = base_s.replace("/", "\\")
                    parent_s = norm_b.rsplit("\\", 1)[0] if "\\" in norm_b else ""
                    return f"{parent_s}\\{nm_s}" if parent_s else nm_s
    return None


def _python_ast_flow_has_forbidden_write(
    tree: ast.Module,
    is_forbidden_write_target: Callable[[str], bool],
    recursive_cmd_checker: Optional[Callable[[str], Optional[str]]] = None,
    depth: int = 0,
) -> bool:
    """Flow-sensitive AST taint analyzer: variable reassignment to a safe path immediately clears taint."""
    taint_sink_funcs: Dict[str, Set[int]] = {}
    taint_sink_kw: Dict[str, Set[str]] = {}

    def _expr_tainted(
        node: Optional[ast.AST],
        tainted_vars: Set[str],
        var_str_vals: Dict[str, str],
    ) -> bool:
        if node is None:
            return False
        folded = _eval_static_path_str(node, var_str_vals)
        if folded is not None:
            return is_forbidden_write_target(folded)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return is_forbidden_write_target(node.value)
        if isinstance(node, ast.Name):
            return node.id in tainted_vars
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            cand = f"{node.value.id}.{node.attr}".lower()
            if cand in _ALL_TAMPER_NAMES:
                return True
        if isinstance(node, ast.JoinedStr):
            return any(_expr_tainted(v, tainted_vars, var_str_vals) for v in node.values)
        if isinstance(node, ast.FormattedValue):
            return _expr_tainted(node.value, tainted_vars, var_str_vals)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.Add, ast.Mod)):
            return _expr_tainted(node.left, tainted_vars, var_str_vals) or _expr_tainted(node.right, tainted_vars, var_str_vals)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(_expr_tainted(e, tainted_vars, var_str_vals) for e in node.elts)
        if isinstance(node, ast.IfExp):
            return _expr_tainted(node.body, tainted_vars, var_str_vals) or _expr_tainted(node.orelse, tainted_vars, var_str_vals)
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id in ("Path", "PurePath", "PureWindowsPath", "WindowsPath", "PosixPath", "str"):
                return any(_expr_tainted(a, tainted_vars, var_str_vals) for a in node.args)
            if isinstance(f, ast.Attribute):
                if f.attr in ("Path", "PurePath", "WindowsPath", "fspath", "abspath", "normpath", "realpath", "expanduser", "expandvars", "join"):
                    return any(_expr_tainted(a, tainted_vars, var_str_vals) for a in node.args)
                if f.attr in ("resolve", "absolute", "expanduser"):
                    return _expr_tainted(f.value, tainted_vars, var_str_vals)
                if f.attr in ("joinpath", "with_name"):
                    return _expr_tainted(f.value, tainted_vars, var_str_vals) or any(
                        _expr_tainted(a, tainted_vars, var_str_vals) for a in node.args
                    )
        return False

    def _call_is_tainted_write_open(
        call_node: ast.Call,
        tainted_vars: Set[str],
        var_str_vals: Dict[str, str],
    ) -> bool:
        fn = call_node.func
        is_builtin_open = (
            (isinstance(fn, ast.Name) and fn.id in ("open", "FileIO"))
            or (
                isinstance(fn, ast.Attribute)
                and isinstance(fn.value, ast.Name)
                and fn.value.id in ("io", "codecs", "builtins")
                and fn.attr in ("open", "FileIO")
            )
        )
        if is_builtin_open:
            file_arg = call_node.args[0] if call_node.args else next((kw.value for kw in call_node.keywords if kw.arg == "file"), None)
            if _expr_tainted(file_arg, tainted_vars, var_str_vals):
                mode_arg = call_node.args[1] if len(call_node.args) >= 2 else next((kw.value for kw in call_node.keywords if kw.arg == "mode"), None)
                return _mode_node_is_mutating(mode_arg)
        if isinstance(fn, ast.Attribute) and fn.attr == "open":
            if _expr_tainted(fn.value, tainted_vars, var_str_vals):
                mode_arg = call_node.args[0] if call_node.args else next((kw.value for kw in call_node.keywords if kw.arg == "mode"), None)
                return _mode_node_is_mutating(mode_arg)
        return False

    def _expr_has_sink(
        expr: Optional[ast.AST],
        tainted_vars: Set[str],
        writable_handles: Set[str],
        var_str_vals: Dict[str, str],
    ) -> bool:
        if expr is None:
            return False
        for node in ast.walk(expr):
            if isinstance(node, ast.NamedExpr):
                if _expr_tainted(node.value, tainted_vars, var_str_vals):
                    tainted_vars.update(_extract_target_names(node.target))
                else:
                    for v in _extract_target_names(node.target):
                        tainted_vars.discard(v)
            if not isinstance(node, ast.Call):
                continue
            if _call_is_tainted_write_open(node, tainted_vars, var_str_vals):
                return True
            fn = node.func
            if isinstance(fn, ast.Attribute):
                if fn.attr in ("write_text", "write_bytes", "truncate", "unlink", "replace", "rename", "rmdir", "touch"):
                    if _expr_tainted(fn.value, tainted_vars, var_str_vals):
                        return True
                if fn.attr in ("write", "writelines", "truncate") and isinstance(fn.value, ast.Name) and fn.value.id in writable_handles:
                    return True

            mod_name = fn.value.id if (isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name)) else ""
            attr_name = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")

            if mod_name in ("os", "nt", "posix") or (isinstance(fn, ast.Name) and attr_name in ("remove", "unlink", "truncate", "replace", "rename", "renames")):
                if attr_name in ("remove", "unlink", "truncate", "rmdir", "removedirs"):
                    t_arg = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == "path"), None)
                    if _expr_tainted(t_arg, tainted_vars, var_str_vals):
                        return True
                elif attr_name in ("replace", "rename", "renames"):
                    all_vals = list(node.args) + [kw.value for kw in node.keywords]
                    if any(_expr_tainted(v, tainted_vars, var_str_vals) for v in all_vals):
                        return True
                elif mod_name in ("os", "nt", "posix") and attr_name == "open":
                    t_arg = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == "path"), None)
                    if _expr_tainted(t_arg, tainted_vars, var_str_vals):
                        fl_arg = node.args[1] if len(node.args) >= 2 else next((kw.value for kw in node.keywords if kw.arg == "flags"), None)
                        is_ro = (isinstance(fl_arg, ast.Constant) and fl_arg.value == 0) or (
                            isinstance(fl_arg, ast.Attribute) and fl_arg.attr == "O_RDONLY"
                        )
                        if not is_ro:
                            return True

            if mod_name == "shutil" or (isinstance(fn, ast.Name) and attr_name in ("rmtree", "move", "copy", "copy2", "copyfile")):
                if attr_name in ("rmtree", "move"):
                    all_vals = list(node.args) + [kw.value for kw in node.keywords]
                    if any(_expr_tainted(v, tainted_vars, var_str_vals) for v in all_vals):
                        return True
                elif attr_name in ("copy", "copy2", "copyfile"):
                    dst_arg = node.args[1] if len(node.args) >= 2 else next((kw.value for kw in node.keywords if kw.arg == "dst"), None)
                    if _expr_tainted(dst_arg, tainted_vars, var_str_vals):
                        return True

            is_subproc = (
                (mod_name == "subprocess" and attr_name in ("run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput"))
                or (mod_name == "os" and attr_name in ("system", "popen"))
                or (mod_name == "asyncio" and attr_name in ("create_subprocess_shell", "create_subprocess_exec"))
            )
            if is_subproc and recursive_cmd_checker is not None and depth < 2:
                lits: List[str] = []
                for a in list(node.args) + [kw.value for kw in node.keywords]:
                    lits.extend(_collect_string_literals(a))
                joined = " ".join(lits)
                if joined and recursive_cmd_checker(joined) is not None:
                    return True

            if isinstance(fn, ast.Name) and (fn.id in taint_sink_funcs or fn.id in taint_sink_kw):
                s_idxs = taint_sink_funcs.get(fn.id, set())
                s_kws = taint_sink_kw.get(fn.id, set())
                for i_a, a_nd in enumerate(node.args):
                    if (i_a in s_idxs or -1 in s_idxs) and _expr_tainted(a_nd, tainted_vars, var_str_vals):
                        return True
                for kw_nd in node.keywords:
                    if kw_nd.arg and (kw_nd.arg in s_kws or -1 in s_idxs) and _expr_tainted(kw_nd.value, tainted_vars, var_str_vals):
                        return True
        return False

    def _apply_assign(
        target_node: ast.AST,
        value_node: ast.AST,
        tainted_vars: Set[str],
        writable_handles: Set[str],
        var_str_vals: Dict[str, str],
    ) -> None:
        if isinstance(target_node, (ast.Tuple, ast.List)) and isinstance(value_node, (ast.Tuple, ast.List)) and len(target_node.elts) == len(value_node.elts):
            for t_elt, v_elt in zip(target_node.elts, value_node.elts):
                _apply_assign(t_elt, v_elt, tainted_vars, writable_handles, var_str_vals)
            return
        val_tainted = _expr_tainted(value_node, tainted_vars, var_str_vals)
        val_handle = isinstance(value_node, ast.Call) and _call_is_tainted_write_open(value_node, tainted_vars, var_str_vals)
        folded_s = _eval_static_path_str(value_node, var_str_vals)
        for v in _extract_target_names(target_node):
            if isinstance(value_node, ast.Lambda):
                lam_pos = [a.arg for a in getattr(value_node.args, "posonlyargs", [])] + [a.arg for a in value_node.args.args]
                for l_idx, l_nm in enumerate(lam_pos):
                    if _expr_has_sink(value_node.body, {l_nm}, set(), {}):
                        taint_sink_funcs.setdefault(v, set()).add(l_idx)
                        taint_sink_kw.setdefault(v, set()).add(l_nm)
            if val_tainted:
                tainted_vars.add(v)
            else:
                tainted_vars.discard(v)
            if val_handle:
                writable_handles.add(v)
            else:
                writable_handles.discard(v)
            if folded_s is not None:
                var_str_vals[v] = folded_s
            else:
                var_str_vals.pop(v, None)

    def _scan_stmts(
        stmts: Sequence[ast.stmt],
        tainted_vars: Set[str],
        writable_handles: Set[str],
        var_str_vals: Dict[str, str],
    ) -> bool:
        for stmt in stmts:
            if isinstance(stmt, ast.Assign):
                if _expr_has_sink(stmt.value, tainted_vars, writable_handles, var_str_vals):
                    return True
                for t in stmt.targets:
                    _apply_assign(t, stmt.value, tainted_vars, writable_handles, var_str_vals)
            elif isinstance(stmt, ast.AnnAssign):
                if stmt.value is not None:
                    if _expr_has_sink(stmt.value, tainted_vars, writable_handles, var_str_vals):
                        return True
                    _apply_assign(stmt.target, stmt.value, tainted_vars, writable_handles, var_str_vals)
            elif isinstance(stmt, ast.AugAssign):
                if _expr_has_sink(stmt.value, tainted_vars, writable_handles, var_str_vals):
                    return True
                if _expr_tainted(stmt.value, tainted_vars, var_str_vals):
                    tainted_vars.update(_extract_target_names(stmt.target))
                for v in _extract_target_names(stmt.target):
                    var_str_vals.pop(v, None)
            elif isinstance(stmt, ast.Delete):
                for t in stmt.targets:
                    for v in _extract_target_names(t):
                        tainted_vars.discard(v)
                        writable_handles.discard(v)
                        var_str_vals.pop(v, None)
            elif isinstance(stmt, ast.Expr):
                if _expr_has_sink(stmt.value, tainted_vars, writable_handles, var_str_vals):
                    return True
            elif isinstance(stmt, (ast.Return, ast.Yield, ast.YieldFrom)):
                if _expr_has_sink(getattr(stmt, "value", None), tainted_vars, writable_handles, var_str_vals):
                    return True
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    if _expr_has_sink(item.context_expr, tainted_vars, writable_handles, var_str_vals):
                        return True
                    if item.optional_vars is not None:
                        is_wh = isinstance(item.context_expr, ast.Call) and _call_is_tainted_write_open(
                            item.context_expr, tainted_vars, var_str_vals
                        )
                        for v in _extract_target_names(item.optional_vars):
                            if is_wh:
                                writable_handles.add(v)
                            else:
                                writable_handles.discard(v)
                            tainted_vars.discard(v)
                            var_str_vals.pop(v, None)
                if _scan_stmts(stmt.body, tainted_vars, writable_handles, var_str_vals):
                    return True
            elif isinstance(stmt, ast.If):
                if _expr_has_sink(stmt.test, tainted_vars, writable_handles, var_str_vals):
                    return True
                tv_b, wh_b, vs_b = set(tainted_vars), set(writable_handles), dict(var_str_vals)
                tv_e, wh_e, vs_e = set(tainted_vars), set(writable_handles), dict(var_str_vals)
                if _scan_stmts(stmt.body, tv_b, wh_b, vs_b) or _scan_stmts(stmt.orelse, tv_e, wh_e, vs_e):
                    return True
                tainted_vars.clear()
                tainted_vars.update(tv_b | tv_e)
                writable_handles.clear()
                writable_handles.update(wh_b | wh_e)
                var_str_vals.clear()
                for k, v in vs_b.items():
                    if vs_e.get(k) == v:
                        var_str_vals[k] = v
            elif isinstance(stmt, (ast.For, ast.AsyncFor)):
                if _expr_has_sink(stmt.iter, tainted_vars, writable_handles, var_str_vals):
                    return True
                it_tainted = _expr_tainted(stmt.iter, tainted_vars, var_str_vals)
                for _ in range(2):
                    for v in _extract_target_names(stmt.target):
                        if it_tainted:
                            tainted_vars.add(v)
                        else:
                            tainted_vars.discard(v)
                        writable_handles.discard(v)
                        var_str_vals.pop(v, None)
                    if _scan_stmts(stmt.body, tainted_vars, writable_handles, var_str_vals):
                        return True
                if _scan_stmts(stmt.orelse, tainted_vars, writable_handles, var_str_vals):
                    return True
            elif isinstance(stmt, ast.While):
                for _ in range(2):
                    if _expr_has_sink(stmt.test, tainted_vars, writable_handles, var_str_vals):
                        return True
                    if _scan_stmts(stmt.body, tainted_vars, writable_handles, var_str_vals):
                        return True
                if _scan_stmts(stmt.orelse, tainted_vars, writable_handles, var_str_vals):
                    return True
            elif isinstance(stmt, ast.Try):
                tv_t, wh_t, vs_t = set(tainted_vars), set(writable_handles), dict(var_str_vals)
                if _scan_stmts(stmt.body, tv_t, wh_t, vs_t):
                    return True
                tv_acc, wh_acc = set(tv_t), set(wh_t)
                for h in stmt.handlers:
                    tv_h, wh_h, vs_h = set(tainted_vars) | tv_t, set(writable_handles) | wh_t, dict(var_str_vals)
                    if _scan_stmts(h.body, tv_h, wh_h, vs_h):
                        return True
                    tv_acc.update(tv_h)
                    wh_acc.update(wh_h)
                if _scan_stmts(stmt.orelse, tv_t, wh_t, vs_t):
                    return True
                tainted_vars.clear()
                tainted_vars.update(tv_acc | tv_t)
                writable_handles.clear()
                writable_handles.update(wh_acc | wh_t)
                var_str_vals.clear()
                if _scan_stmts(stmt.finalbody, tainted_vars, writable_handles, var_str_vals):
                    return True
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                pos_args = [a.arg for a in getattr(stmt.args, "posonlyargs", [])] + [a.arg for a in stmt.args.args]
                for idx_p, p_nm in enumerate(pos_args):
                    if _scan_stmts(stmt.body, {p_nm}, set(), {}):
                        taint_sink_funcs.setdefault(stmt.name, set()).add(idx_p)
                        taint_sink_kw.setdefault(stmt.name, set()).add(p_nm)
                local_params = set(pos_args) | {a.arg for a in stmt.args.kwonlyargs}
                if stmt.args.vararg:
                    local_params.add(stmt.args.vararg.arg)
                if stmt.args.kwarg:
                    local_params.add(stmt.args.kwarg.arg)
                if _scan_stmts(
                    stmt.body,
                    set(tainted_vars) - local_params,
                    set(writable_handles) - local_params,
                    {k: v for k, v in var_str_vals.items() if k not in local_params},
                ):
                    return True
            elif isinstance(stmt, ast.ClassDef):
                if _scan_stmts(stmt.body, set(tainted_vars), set(writable_handles), dict(var_str_vals)):
                    return True
            else:
                if _expr_has_sink(stmt, tainted_vars, writable_handles, var_str_vals):
                    return True
        return False

    return _scan_stmts(tree.body, set(), set(), {})


_SHELL_REDIRECT_TAMPER_RE = re.compile(
    r"(?i)(?:(?:^|[\s;|()])\d*|[&*]|(?<![-\w=>]))>{1,2}\s*['\"]?([^\s'\";|<>]*(?:" + _PROTECTED_NAME_ALT + r"))"
)
_SHELL_CMDLET_TAMPER_RE = re.compile(
    r"(?i)(?:^|[\s;|(&])(?:Set-Content|sc|Out-File|Add-Content|ac|Clear-Content|clc|Tee-Object|"
    r"Remove-Item|ri|del|erase|rm|Move-Item|mi|move|Rename-Item|rni|ren|truncate)\b[^\n;|]*?([^\s'\";|(),]*(?:"
    + _PROTECTED_NAME_ALT
    + r"))"
)
_PS_VAR_ASSIGN_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['\"]?([^\s'\";|(),]+)['\"]?")


def _invoke_extra_access_gate(
    gate_fn: Optional[Callable[..., Optional[str]]],
    *,
    kind: str,
    target_path: str = "",
    mode: str = "read",
    command_or_code: str = "",
    cwd: str = "",
    is_python_code: bool = False,
    tool_name: str = "",
    extra_args: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    if gate_fn is None:
        return None
    ctx: Dict[str, Any] = {
        "kind": kind,
        "path": target_path,
        "mode": mode,
        "command": command_or_code,
        "cwd": cwd,
        "is_python_code": is_python_code,
        "tool_name": tool_name or ("run_python" if is_python_code else ("run_command" if command_or_code else f"{mode}_file")),
        "extra_args": extra_args or {},
    }
    try:
        sig = inspect.signature(gate_fn)
        params = list(sig.parameters.values())
        has_var_pos = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)
        pos_params = [
            p for p in params if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
        if len(pos_params) == 1 and not has_var_pos:
            return gate_fn(ctx)
        if len(pos_params) == 2 and not has_var_pos:
            return gate_fn(target_path or command_or_code, mode)
        if len(pos_params) >= 3 or has_var_pos:
            eff_tool = ctx["tool_name"]
            if len(pos_params) == 3 and not has_var_pos:
                return gate_fn(eff_tool, target_path, command_or_code)
            return gate_fn(eff_tool, target_path, command_or_code, extra_args)
        return gate_fn(ctx)
    except TypeError:
        return gate_fn(ctx)


class WorkspaceGuard:
    """Configurable multi-workspace L0 security guardrail with zero third-party dependencies."""

    def __init__(
        self,
        workspace_roots: Union[str, Path, Sequence[Union[str, Path]], None] = None,
        *,
        readonly_workspace_roots: Union[str, Path, Sequence[Union[str, Path]], None] = None,
        allow_host_global_skills: Optional[bool] = None,
        protect_host_credentials: Optional[bool] = None,
        protect_dotenv_files: Optional[bool] = None,
        block_destructive_commands: Optional[bool] = None,
        redact_project_secrets: Optional[bool] = None,
        policy: Optional[Any] = None,
        restrict_to_workspace: bool = True,
        tier: Union[str, int] = "L3",
        state_root: Optional[Union[str, Path]] = None,
        product_root: Optional[Union[str, Path]] = None,
        tool_prefix: str = "pc",
        extra_access_gate: Optional[Callable[..., Optional[str]]] = None,
    ) -> None:
        self.workspace_roots: Tuple[Path, ...] = ()
        self.readonly_workspace_roots: Tuple[Path, ...] = ()
        self.allow_host_global_skills: bool = bool(allow_host_global_skills) if allow_host_global_skills is not None else False
        self.protect_host_credentials: bool = bool(protect_host_credentials) if protect_host_credentials is not None else True
        self.protect_dotenv_files: bool = bool(protect_dotenv_files) if protect_dotenv_files is not None else False
        self.block_destructive_commands: bool = bool(block_destructive_commands) if block_destructive_commands is not None else True
        self.redact_project_secrets: bool = bool(redact_project_secrets) if redact_project_secrets is not None else False
        self.policy: Optional[Any] = policy
        self.tier: str = to_short_tier_code(tier, restrict_to_workspace=bool(restrict_to_workspace))
        self.restrict_to_workspace: bool = False if self.tier == "L4" else bool(restrict_to_workspace)
        self.state_root: Optional[Path] = canonical_realpath(state_root) if state_root else None
        self.product_root: Optional[Path] = canonical_realpath(product_root) if product_root else None
        self.tool_prefix: str = (tool_prefix or "pc").strip() or "pc"
        self.extra_access_gate: Optional[Callable[..., Optional[str]]] = extra_access_gate
        self._extra_secret_literals: List[str] = []
        if workspace_roots is not None or readonly_workspace_roots is not None:
            self.set_workspace_policy(
                workspace_roots if workspace_roots is not None else (),
                restrict_to_workspace=restrict_to_workspace,
                tier_key=str(tier),
                readonly_workspace_roots=readonly_workspace_roots,
                allow_host_global_skills=allow_host_global_skills,
                protect_host_credentials=protect_host_credentials,
                protect_dotenv_files=protect_dotenv_files,
                block_destructive_commands=block_destructive_commands,
                redact_project_secrets=redact_project_secrets,
                policy=policy,
                state_root=state_root,
                product_root=product_root,
                extra_access_gate=extra_access_gate,
            )

    def effective_state_root(self) -> Path:
        if self.state_root is not None:
            return self.state_root
        return canonical_realpath(resolve_state_root(product_root=self.product_root))

    def set_extra_access_gate(self, gate_fn: Optional[Callable[..., Optional[str]]]) -> None:
        self.extra_access_gate = gate_fn

    def register_secret_literal(self, secret_value: str) -> None:
        s = (secret_value or "").strip()
        if len(s) >= 12 and s not in self._extra_secret_literals:
            self._extra_secret_literals.append(s)

    def set_workspace_policy(
        self,
        workspace_roots: Union[str, Path, Sequence[Union[str, Path]], None],
        restrict_to_workspace: bool = True,
        tier_key: str = "",
        *,
        readonly_workspace_roots: Union[str, Path, Sequence[Union[str, Path]], None] = None,
        allow_host_global_skills: Optional[bool] = None,
        protect_host_credentials: Optional[bool] = None,
        protect_dotenv_files: Optional[bool] = None,
        block_destructive_commands: Optional[bool] = None,
        redact_project_secrets: Optional[bool] = None,
        policy: Optional[Any] = None,
        state_root: Optional[Union[str, Path]] = None,
        product_root: Optional[Union[str, Path]] = None,
        extra_access_gate: Optional[Callable[..., Optional[str]]] = None,
    ) -> None:
        if policy is not None:
            self.policy = policy
        elif self.policy is None:
            frm = inspect.currentframe()
            try:
                caller_obj = frm.f_back.f_locals.get("self") if (frm is not None and frm.f_back is not None) else None
                if caller_obj is not None and type(caller_obj).__name__ == "LiveRuntimePolicy":
                    self.policy = caller_obj
            finally:
                del frm
        parsed_roots = list(_parse_workspace_roots_input(workspace_roots))
        all_norms = {str(p).lower().rstrip("\\/") for p in parsed_roots}
        if readonly_workspace_roots is not None:
            raw_ro = _parse_workspace_roots_input(readonly_workspace_roots)
            for p in raw_ro:
                p_norm = str(p).lower().rstrip("\\/")
                if p_norm not in all_norms:
                    parsed_roots.append(p)
                    all_norms.add(p_norm)
            self.workspace_roots = tuple(parsed_roots)
            self.readonly_workspace_roots = tuple(raw_ro)
        else:
            self.workspace_roots = tuple(parsed_roots)
            self.readonly_workspace_roots = tuple(
                p for p in self.readonly_workspace_roots if str(p).lower().rstrip("\\/") in all_norms
            )
        if allow_host_global_skills is not None:
            self.allow_host_global_skills = bool(allow_host_global_skills)
        if protect_host_credentials is not None:
            self.protect_host_credentials = bool(protect_host_credentials)
        if protect_dotenv_files is not None:
            self.protect_dotenv_files = bool(protect_dotenv_files)
        if block_destructive_commands is not None:
            self.block_destructive_commands = bool(block_destructive_commands)
        if redact_project_secrets is not None:
            self.redact_project_secrets = bool(redact_project_secrets)
        eff_tier = to_short_tier_code(tier_key, restrict_to_workspace=bool(restrict_to_workspace))
        if eff_tier == "L4":
            self.restrict_to_workspace = False
        else:
            self.restrict_to_workspace = bool(restrict_to_workspace)
        self.tier = eff_tier
        if state_root is not None:
            self.state_root = canonical_realpath(state_root)
        if product_root is not None:
            self.product_root = canonical_realpath(product_root)
        if extra_access_gate is not None:
            self.extra_access_gate = extra_access_gate

    def get_workspace_policy(self) -> Dict[str, Any]:
        primary = str(self.workspace_roots[0]) if self.workspace_roots else ""
        return {
            "workspace_root": primary,
            "workspace_roots": [str(p) for p in self.workspace_roots],
            "readonly_workspace_roots": [str(p) for p in self.readonly_workspace_roots],
            "allow_host_global_skills": self.allow_host_global_skills,
            "protect_host_credentials": self.protect_host_credentials,
            "protect_dotenv_files": self.protect_dotenv_files,
            "block_destructive_commands": self.block_destructive_commands,
            "redact_project_secrets": bool(getattr(self.policy, "redact_project_secrets", False)) or self.redact_project_secrets,
            "restrict_to_workspace": self.restrict_to_workspace,
            "tier": self.tier,
            "state_root": str(self.effective_state_root()),
        }

    def _effective_protect_host_credentials(self) -> bool:
        if self.policy is not None and hasattr(self.policy, "protect_host_credentials"):
            return bool(getattr(self.policy, "protect_host_credentials"))
        return bool(self.protect_host_credentials)

    def _effective_block_destructive_commands(self) -> bool:
        if self.policy is not None and hasattr(self.policy, "block_destructive_commands"):
            return bool(getattr(self.policy, "block_destructive_commands"))
        return bool(self.block_destructive_commands)

    def _should_block_git_repo_meta(self) -> bool:
        if self.tier == "L4":
            return False
        if not self._effective_protect_host_credentials():
            return False
        if not self._effective_block_destructive_commands():
            return False
        return True

    def _is_blocked_npmrc_target(self, cand_path: Path, raw_hint: str = "") -> Optional[str]:
        if not self._effective_protect_host_credentials():
            return None
        if cand_path.name.lower() != ".npmrc":
            return None
        reason = "Package registry and container credential files are isolated by Guard."
        home_real = canonical_realpath(Path.home())
        cand_par_norm = os.path.normcase(str(cand_path.parent).rstrip("\\/"))
        home_norm = os.path.normcase(str(home_real).rstrip("\\/"))
        if cand_par_norm == home_norm or cand_par_norm in ("/etc", r"c:\etc"):
            return reason
        if raw_hint and re.search(
            r"(?i)(?:^|[\s\"'=(;|&><])(?:~|\$\{?(?:env:)?(?:HOME|USERPROFILE)\}?|%(?:USERPROFILE|HOMEPATH)%)[\\/]\.npmrc(?=$|[\\/\"'\s;|&><)`:])",
            raw_hint,
        ):
            return reason
        is_ro_ctx = (self.tier == "L1") or bool(_READONLY_CALL_CTX.get())
        if is_ro_ctx:
            return reason
        if self.tier == "L4" or self._is_under_any_workspace(cand_path):
            return None
        return reason

    def _check_readonly_workspace_write(self, cand_path: Path) -> Optional[str]:
        if not self.readonly_workspace_roots:
            return None
        cand_low = str(cand_path).lower().rstrip("\\/")
        ro_norms = {str(r).lower().rstrip("\\/") for r in self.readonly_workspace_roots}
        best_root: Optional[Path] = None
        best_len = -1
        for ws in (*self.workspace_roots, *self.readonly_workspace_roots):
            ws_low = str(ws).lower().rstrip("\\/")
            if _is_under_prefix(cand_low, ws_low) and len(ws_low) > best_len:
                best_root = ws
                best_len = len(ws_low)
        if best_root is not None and str(best_root).lower().rstrip("\\/") in ro_norms:
            return f"ERR_READONLY_WORKSPACE: Secondary workspace `{best_root}` is mounted as read-only; write access to `{cand_path}` is prohibited."
        return None

    def _active_sensitive_path_patterns(self) -> Tuple[Tuple[str, str], ...]:
        pats: List[Tuple[str, str], ...] = list(MCP_OWN_SECRET_PATTERNS)  # type: ignore[assignment]
        if self._effective_protect_host_credentials():
            pats.extend(HOST_CREDENTIAL_PATH_PATTERNS)
        is_ro_ctx = (self.tier == "L1") or bool(_READONLY_CALL_CTX.get())
        eff_dotenv = (
            bool(getattr(self.policy, "protect_dotenv_files", self.protect_dotenv_files))
            if self.policy is not None
            else self.protect_dotenv_files
        )
        if eff_dotenv or is_ro_ctx:
            pats.append(DOTENV_PATH_PATTERN)
        return tuple(pats)

    def _active_destructive_cmd_patterns(self) -> Tuple[Tuple[str, str], ...]:
        if self._effective_block_destructive_commands():
            return USER_CONFIGURABLE_DESTRUCTIVE_CMD_PATTERNS + MCP_SELF_PROTECT_CMD_PATTERNS
        return MCP_SELF_PROTECT_CMD_PATTERNS

    def record_security_event(self, event_type: str, target: str, reason: str) -> None:
        try:
            log_file = self.effective_state_root() / "logs" / "security_events.jsonl"
            log_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": event_type,
                "tier": self.tier,
                "target": str(target)[:400],
                "reason": reason,
            }
            with log_file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def normalize_target_path(self, path_str: Union[str, Path], base_dir: Optional[Union[str, Path]] = None) -> Path:
        raw_in = strip_file_uri(str(path_str or "").strip())
        expanded = expand_env_and_tilde(raw_in)
        if not expanded:
            return Path("")
        if sys.platform == "win32":
            expanded = expanded.replace("/", "\\")
        p = Path(expanded)
        if not p.is_absolute():
            if base_dir is not None and str(base_dir).strip():
                anchor = Path(expand_env_and_tilde(str(base_dir).strip()))
            elif self.workspace_roots:
                anchor = self.workspace_roots[0]
            else:
                anchor = Path.cwd()
            p = anchor / p
        return canonical_realpath(p)

    def _state_guard_roots(self) -> List[Path]:
        roots: List[Path] = [self.effective_state_root()]
        ws_low_set = {str(w).lower().rstrip("\\/") for w in self.workspace_roots}
        if self.product_root is not None and self.product_root not in roots:
            pr_low = str(self.product_root).lower().rstrip("\\/")
            if not any(_is_under_prefix(pr_low, wl) or _is_under_prefix(wl, pr_low) for wl in ws_low_set):
                roots.append(self.product_root)
        return roots

    def _is_state_secret_or_conn_file(self, cand_path: Path) -> bool:
        if cand_path.name.lower() in _PROTECTED_SECRET_BASENAMES or bool(_PROTECTED_SECRET_FILE_RE.match(cand_path.name)):
            return True
        c_low = str(cand_path).lower().rstrip("\\/")
        nm_low = cand_path.name.lower()
        par_low = str(cand_path.parent).lower().rstrip("\\/")
        for r in self._state_guard_roots():
            r_real = canonical_realpath(r)
            r_low = str(r_real).lower().rstrip("\\/")
            for sub in ("secrets", "state", "config"):
                if _is_under_prefix(c_low, str(r_real / sub).lower().rstrip("\\/")):
                    return True
            if par_low == r_low and (
                "connection_info" in nm_low
                or nm_low.startswith("latest_consent_pair_code")
                or nm_low == ".env"
                or nm_low.startswith(".env.")
            ):
                return True
        return False

    def _read_blocked_prefixes(self) -> Tuple[str, ...]:
        roots = self._state_guard_roots()
        out: List[str] = []

        def _add(p_obj: Path) -> None:
            val = str(canonical_realpath(p_obj)).lower().rstrip("\\/")
            if val and val not in out:
                out.append(val)

        for r in roots:
            for rel in ("secrets", "state", "config", ".env", "连接信息_CONNECTION_INFO.txt", "latest_consent_pair_code.txt"):
                _add(r / rel)
        home = Path.home()
        generic_state_home = Path(
            os.environ.get("COSMOS_MCP_STATE_DIR")
            or os.environ.get("LOCALPC_MCP_STATE_DIR")
            or (home / ".cosmos-mcp")
        )
        for sh in (home / ".cosmos-mcp", generic_state_home):
            for sub_rel in ("secrets", "state", "config", ".env"):
                _add(sh / sub_rel)
        if self.protect_host_credentials:
            for cr in (home / ".cargo", Path(os.environ["CARGO_HOME"]) if os.environ.get("CARGO_HOME") else None):
                if cr is not None:
                    _add(cr / "credentials")
                    _add(cr / "credentials.toml")
        return tuple(out)

    def _write_blocked_prefixes(self) -> Tuple[str, ...]:
        sr = self.effective_state_root()
        items: List[Path] = [
            sr / "secrets",
            sr / "state",
            sr / "state" / "bg_jobs.json",
            sr / "bg_jobs.json",
            sr / "config",
            sr / ".env",
            sr / "logs",
            sr / "locks",
            sr / "app_src",
            sr / ".undo_history",
            sr / "browser_profile",
            sr / "连接信息_CONNECTION_INFO.txt",
        ]
        ws_low_set = {str(w).lower().rstrip("\\/") for w in self.workspace_roots}
        if self.product_root is not None:
            pr_low = str(self.product_root).lower().rstrip("\\/")
            if not any(_is_under_prefix(pr_low, wl) or _is_under_prefix(wl, pr_low) for wl in ws_low_set):
                items.extend([
                    self.product_root / "src",
                    self.product_root / "secrets",
                    self.product_root / "state",
                    self.product_root / "state" / "bg_jobs.json",
                    self.product_root / "bg_jobs.json",
                    self.product_root / "config",
                    self.product_root / ".env",
                    self.product_root / "logs",
                    self.product_root / "launcher.py",
                ])
        home = Path.home()
        generic_state_home = Path(
            os.environ.get("COSMOS_MCP_STATE_DIR")
            or os.environ.get("LOCALPC_MCP_STATE_DIR")
            or (home / ".cosmos-mcp")
        )
        for sh in (home / ".cosmos-mcp", generic_state_home):
            items.extend([
                sh / "secrets",
                sh / "state",
                sh / "config",
                sh / ".env",
                sh / "logs",
                sh / "locks",
                sh / "app_src",
                sh / ".undo_history",
                sh / "browser_profile",
            ])
        out: List[str] = []
        for it in items:
            low = str(canonical_realpath(it)).lower().rstrip("\\/")
            if low and low not in out:
                out.append(low)
        return tuple(out)

    def _is_under_any_workspace(self, resolved_path: Path) -> bool:
        if not self.workspace_roots:
            return False
        cand_low = str(resolved_path).lower().rstrip("\\/")
        return any(_is_under_prefix(cand_low, str(ws).lower().rstrip("\\/")) for ws in self.workspace_roots)

    def _is_allowed_readonly_toolchain_path(self, resolved_path: Path) -> bool:
        rp = canonical_realpath(resolved_path)
        if _PROTECTED_SECRET_FILE_RE.match(rp.name):
            return False
        if (self.protect_dotenv_files or self.tier == "L1" or bool(_READONLY_CALL_CTX.get())) and _is_private_dotenv_name(rp.name):
            return False
        if self.protect_host_credentials and rp.parent.name.lower() == ".cargo" and rp.name.lower() in ("credentials", "credentials.toml"):
            return False
        res_low = str(rp).lower().rstrip("\\/")
        if not res_low:
            return False
        for rd_blk in self._read_blocked_prefixes():
            if _is_under_prefix(res_low, rd_blk):
                return False
        sr = self.effective_state_root()
        home = Path.home()
        here_file = Path(__file__).resolve()
        builtin_hs_cands: List[Path] = []
        for up_idx in (2, 3):
            if len(here_file.parents) > up_idx:
                hs_p = here_file.parents[up_idx] / "host_skills"
                if hs_p.is_dir():
                    builtin_hs_cands.append(hs_p)
        allowed_roots: List[Path] = [
            sr / "logs" / "spill",
            sr / "logs" / "bg_jobs",
            sr / "skills_store",
            sr / "host_skills",
            sr / "app_src" / "host_skills",
            *builtin_hs_cands,
            home / ".cache",
            home / ".huggingface",
            home / ".matplotlib",
            home / ".config" / "matplotlib",
            home / ".cargo" / "bin",
            home / ".cargo" / "registry",
            home / ".rustup",
            home / ".pyenv",
            Path(sys.base_prefix),
            Path(sys.prefix),
        ]
        if self.allow_host_global_skills:
            allowed_roots.extend([
                home / ".agents" / "skills",
                home / ".claude" / "skills",
                home / ".cursor" / "skills",
                home / ".codeium" / "windsurf" / "skills",
                home / ".codex" / "skills",
                home / ".gemini" / "skills",
                home / ".gemini" / "config" / "skills",
                home / ".cc-switch" / "skills",
                home / ".cosmos-skills" / "skills_store",
            ])
        if self.product_root is not None:
            allowed_roots.extend([
                self.product_root / "logs" / "spill",
                self.product_root / "logs" / "bg_jobs",
                self.product_root / "skills_store",
                self.product_root / "host_skills",
                self.product_root / "app_src" / "host_skills",
            ])
        if sys.platform == "win32":
            allowed_roots.extend([Path(r"C:\Program Files\Go"), Path(r"C:\Program Files (x86)\Go"), Path(r"C:\Go")])
        else:
            allowed_roots.extend([Path("/usr/local/go"), Path("/usr/lib/go"), Path("/usr/lib/rustlib")])
        for env_k in ("GOROOT", "RUSTUP_HOME", "PYENV_ROOT", "XDG_CACHE_HOME", "HF_HOME", "TORCH_HOME"):
            ev = (os.environ.get(env_k) or "").strip()
            if ev:
                allowed_roots.append(Path(ev))
        return any(_is_under_prefix(res_low, str(canonical_realpath(rt)).lower()) for rt in allowed_roots)

    def _is_allowed_runtime_executable(self, resolved_path: Path) -> bool:
        if sys.platform == "win32":
            if resolved_path.suffix.lower() not in (".exe", ".cmd", ".bat", ".com"):
                return False
            bin_name = resolved_path.stem.lower()
        else:
            if resolved_path.suffix.lower() in (".txt", ".env", ".json", ".csv", ".py", ".sh", ".js", ".ts", ".db", ".sqlite", ".pem", ".key"):
                return False
            bin_name = resolved_path.name.lower()

        p_low = str(resolved_path).lower()
        if p_low in _DISCOVERED_TOOLCHAIN_EXES:
            return True
        if any(_is_under_prefix(p_low, td) for td in _DISCOVERED_TOOLCHAIN_DIRS) and _STANDARD_TOOLCHAIN_BIN_RE.match(bin_name):
            return True
        trusted_roots: List[str] = [
            str(canonical_realpath(Path(sys.executable).parent)).lower(),
            str(canonical_realpath(sys.prefix)).lower(),
            str(canonical_realpath(sys.base_prefix)).lower(),
        ]
        if sys.platform == "win32":
            trusted_roots.extend([r"c:\windows\system32", r"c:\windows\syswow64", r"c:\program files", r"c:\program files (x86)"])
            if p_low == r"c:\windows\py.exe":
                return True
        else:
            trusted_roots.extend(["/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/local/bin", "/opt/homebrew", "/opt/conda", "/usr/lib"])
        return any(_is_under_prefix(p_low, tr) for tr in trusted_roots if tr)

    def check_path_access(
        self,
        path_str: Union[str, Path],
        mode: str = "read",
        *,
        tool_name: str = "",
        extra_args: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        raw_clean = str(path_str or "").strip()
        if not raw_clean:
            reason = "Empty target file path is prohibited."
            self.record_security_event(f"empty_path_{mode}_blocked", str(path_str), reason)
            return f"[GUARD WORKSPACE SANDBOX]: {reason}"

        expanded = expand_env_and_tilde(raw_clean)
        if has_ntfs_ads_stream(raw_clean, for_command_token=False) or has_ntfs_ads_stream(expanded, for_command_token=False):
            reason = "NTFS Alternate Data Streams (ADS) in file paths are prohibited."
            self.record_security_event(f"ntfs_ads_{mode}_blocked", raw_clean, reason)
            return f"[GUARD WORKSPACE SANDBOX]: {reason}"

        resolved = self.normalize_target_path(raw_clean)
        norm = str(resolved)
        candidates: List[Path] = [resolved]
        if not Path(expanded).is_absolute() and _PARENT_TRAVERSAL_RE.search(expanded):
            cwd_cand = self.normalize_target_path(raw_clean, base_dir=Path.cwd())
            if str(cwd_cand).lower() != norm.lower():
                candidates.append(cwd_cand)

        read_blocked = self._read_blocked_prefixes()
        active_sens_patterns = self._active_sensitive_path_patterns()
        for cand in candidates:
            c_str = str(cand)
            c_low = c_str.lower()
            if self._is_state_secret_or_conn_file(cand):
                reason = "MCP authentication secrets, OAuth stores, and mode secret files are isolated."
                self.record_security_event(f"self_secret_{mode}_blocked", c_str, reason)
                return f"[GUARD CREDENTIAL ISOLATION]: {reason}"
            for prot in read_blocked:
                if _is_under_prefix(c_low, prot):
                    reason = "MCP secrets, state directory, and connection info files are isolated."
                    self.record_security_event(f"self_secret_{mode}_blocked", c_str, reason)
                    return f"[GUARD CREDENTIAL ISOLATION]: {reason}"
            for pat, reason in active_sens_patterns:
                if re.search(pat, c_str) or re.search(pat, expanded) or re.search(pat, raw_clean):
                    self.record_security_event(f"path_{mode}_blocked", c_str, reason)
                    return f"[GUARD CREDENTIAL ISOLATION]: {reason}"
            npmrc_err = self._is_blocked_npmrc_target(cand, raw_clean)
            if npmrc_err:
                self.record_security_event(f"path_{mode}_blocked", c_str, npmrc_err)
                return f"[GUARD CREDENTIAL ISOLATION]: {npmrc_err}"

        if mode == "write" and self.tier == "L1":
            reason = f"Tier L1 is strictly read-only; write access to `{norm}` is prohibited."
            self.record_security_event("tier_l1_write_blocked", norm, reason)
            return f"[GUARD TIER POLICY]: {reason}"

        if mode == "write":
            write_blocked = self._write_blocked_prefixes()
            eff_block_destr = self._effective_block_destructive_commands()
            block_git_meta = self._should_block_git_repo_meta()
            for cand in candidates:
                c_str = str(cand)
                c_low = c_str.lower()
                if any(cand.name.lower() == an or cand.name.lower().startswith(an + ".") for an in _PROTECTED_AUDIT_NAMES):
                    reason = "Modifying MCP audit or security event logs is prohibited."
                    self.record_security_event("self_tamper_blocked", c_str, reason)
                    return f"[GUARD ANTI-TAMPER]: {reason}"
                for prot in write_blocked:
                    if _is_under_prefix(c_low, prot):
                        reason = "Modifying MCP server code, configuration, logs, or secrets is prohibited."
                        self.record_security_event("self_tamper_blocked", c_str, reason)
                        return f"[GUARD ANTI-TAMPER]: {reason}"
                if eff_block_destr or block_git_meta:
                    pers_err = check_persistence_components(cand, check_git_repo_meta=block_git_meta)
                    if pers_err and (eff_block_destr or "Git repository" in pers_err):
                        self.record_security_event("persistence_write_blocked", c_str, pers_err)
                        return f"[GUARD PERSISTENCE ISOLATION]: {pers_err}"
                if eff_block_destr:
                    os_dirs = WINDOWS_OS_DIRS if sys.platform == "win32" else POSIX_OS_DIRS
                    for sys_dir in os_dirs:
                        if _is_under_prefix(c_low, sys_dir):
                            reason = f"Writing to OS system directory `{sys_dir}` is prohibited."
                            self.record_security_event("os_dir_write_blocked", c_str, reason)
                            return f"[GUARD OS ISOLATION]: {reason}"

        if self.restrict_to_workspace and self.workspace_roots:
            if not self._is_under_any_workspace(resolved):
                if mode == "read" and self._is_allowed_readonly_toolchain_path(resolved):
                    pass
                else:
                    roots_disp = ", ".join(f"`{r}`" for r in self.workspace_roots)
                    reason = f"Tier {self.tier} restricts file access to authorized workspace roots [{roots_disp}] (got `{norm}`)."
                    self.record_security_event(f"workspace_boundary_{mode}_blocked", norm, reason)
                    return f"[GUARD WORKSPACE SANDBOX]: {reason}"

        if mode == "write" and self.readonly_workspace_roots:
            ro_reason = self._check_readonly_workspace_write(resolved)
            if ro_reason:
                self.record_security_event("readonly_workspace_write_blocked", norm, ro_reason)
                return f"[GUARD WORKSPACE SANDBOX]: {ro_reason}"

        gate_err = _invoke_extra_access_gate(
            self.extra_access_gate,
            kind="path",
            target_path=norm,
            mode=mode,
            tool_name=tool_name,
            extra_args=extra_args,
        )
        if gate_err:
            self.record_security_event("extra_gate_path_blocked", norm, gate_err)
            return gate_err

        return None

    def _is_forbidden_write_str(self, raw_s: str, eff_base: str) -> bool:
        s = (raw_s or "").strip().strip("'\"")
        if not s:
            return False
        low = s.lower().replace("/", "\\")
        if any(a in low for a in _PROTECTED_AUDIT_NAMES):
            return True
        expanded = expand_env_and_tilde(s)
        if not Path(expanded).is_absolute() and eff_base:
            cand = self.normalize_target_path(s, base_dir=eff_base)
            return self.check_path_access(cand, mode="write") is not None
        return self.check_path_access(s, mode="write") is not None

    def _extract_command_path_items(self, text: str, is_python_code: bool) -> List[Tuple[str, bool]]:
        items: List[Tuple[str, bool]] = []
        seen: Set[Tuple[str, bool]] = set()

        def _is_cand_tok(cand: str) -> bool:
            if not cand or _URL_SCHEME_RE.match(cand):
                return False
            if sys.platform == "win32" and not is_python_code and re.fullmatch(r"/[A-Za-z0-9?]{1,3}", cand):
                return False
            low = cand.lower()
            cand_basename = Path(cand).name
            if (
                cand == ".."
                or low in _ALL_TAMPER_NAMES
                or bool(_STATE_SENSITIVE_TOKEN_RE.match(cand_basename))
                or has_ntfs_ads_stream(cand, for_command_token=True)
                or _PARENT_TRAVERSAL_RE.search(cand)
                or _HOME_ENV_TOKEN_RE.search(cand)
                or _WIN_DRIVE_ABS_RE.match(cand)
                or _UNC_ABS_RE.match(cand)
            ):
                return True
            if cand.startswith("/") and not cand.startswith("//") and len(cand) > 1:
                if sys.platform != "win32":
                    return True
                if re.match(r"^/(?:Windows|Users|Program Files|ProgramData|Temp|tmp|etc|var|home|root)(?:$|[\\/])", cand, re.IGNORECASE):
                    return True
            if ("/" in cand or "\\" in cand) and not cand.startswith(("/", "\\", "<")):
                if not is_python_code:
                    return True
                if ".git/" in low or ".git\\" in low or "startup/" in low or "startup\\" in low or "profile.ps1" in low or any(rc in low for rc in _SHELL_RC_NAMES):
                    return True
            return False

        def _push(raw_c: str, is_exec: bool) -> None:
            c = strip_file_uri(raw_c.strip().strip(",;"))
            while c.startswith("(") and c.endswith(")"):
                c = c[1:-1].strip()
            if c.startswith("@") and len(c) > 1 and not is_exec:
                c = c[1:].strip()
            if not c or not _is_cand_tok(c):
                return
            k = (c, bool(is_exec))
            if k not in seen:
                seen.add(k)
                items.append(k)

        if is_python_code:
            try:
                tree = ast.parse(text)
                for node in ast.walk(tree):
                    folded = _eval_static_path_str(node)
                    if folded:
                        for lp in folded.splitlines():
                            if lp.strip():
                                _push(lp.strip(), False)
                    if isinstance(node, ast.Attribute) and node.attr in ("parent", "parents"):
                        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and node.value.func.attr in ("cwd", "getcwd"):
                            _push("..", False)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                        if node.func.attr in ("getenv", "get") and node.args:
                            ek = _eval_static_path_str(node.args[0])
                            if ek and re.match(r"^(?:HOME|USERPROFILE|APPDATA|LOCALAPPDATA|PUBLIC|PROGRAMDATA|TEMP|TMP|TMPDIR|WINDIR|SYSTEMROOT)$", ek.strip(), re.IGNORECASE):
                                _push(f"${ek.strip()}", False)
            except Exception:
                pass
            for rx in (_EMBEDDED_WIN_PATH_RE, _EMBEDDED_POSIX_PATH_RE):
                for m in rx.finditer(text):
                    _push(m.group(1).strip().rstrip(".,;:'\")]}"), False)
            return items

        for clause in _SHELL_CLAUSE_SPLIT_RE.split(text):
            if not clause or not clause.strip():
                continue
            seen_exec = False
            prev_end = 0
            for m in _CMD_TOKEN_RE.finditer(clause):
                inter = clause[prev_end : m.start()]
                prev_end = m.end()
                is_redir = (">" in inter) or ("<" in inter)
                raw_unq = m.group(3)
                tok = (m.group(1) or m.group(2) or raw_unq or "").strip()
                if not tok:
                    continue
                if not seen_exec and not is_redir and tok.lower() in ("&", ".", "call", "env", "time", "nohup"):
                    continue
                has_eq = bool(raw_unq and "=" in tok and not tok.startswith(("=", "/")))
                tok_is_exec = (not seen_exec) and (not is_redir) and (not has_eq)
                if not has_eq and not is_redir:
                    seen_exec = True
                _push(tok, tok_is_exec)
                if has_eq:
                    rhs = tok.split("=", 1)[1].strip("\\\"'")
                    if rhs:
                        _push(rhs, False)
        return items

    def _check_python_ast_path_expr(
        self,
        expr: Optional[ast.AST],
        mode: str,
        var_str_vals: Dict[str, str],
        eff_base: str,
    ) -> Optional[Tuple[str, str]]:
        if expr is None:
            return None
        cand_strs: List[str] = []
        folded = _eval_static_path_str(expr, var_str_vals, cwd_base=eff_base)
        if folded is not None:
            cand_strs.append(folded)
        elif isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            for elt in expr.elts:
                sub_s = _eval_static_path_str(elt, var_str_vals, cwd_base=eff_base)
                if sub_s is not None:
                    cand_strs.append(sub_s)

        null_devs = frozenset({"/dev/null", "nul", "//./nul", "con", "conin$", "conout$"})
        for raw_s in cand_strs:
            s = (raw_s or "").strip().strip("'\"")
            if not s or s.lower().replace("\\", "/") in null_devs:
                continue
            if re.search(r"(?i)(?:^|[\\/])\.(?:human_ui_secret|peer_hmac_secret)(?:$|[\\/])", s) or s.lower() in (
                ".human_ui_secret",
                ".peer_hmac_secret",
            ):
                reason = f"{ERR_HUMAN_MODE_LOCKED}: Accessing .human_ui_secret / .peer_hmac_secret in scripts or commands is prohibited."
                return ("cmd_secret_probe_blocked", f"[GUARD CREDENTIAL ISOLATION]: {reason}")
            if has_ntfs_ads_stream(s, for_command_token=False):
                return ("cmd_ntfs_ads_blocked", "[GUARD WORKSPACE SANDBOX]: NTFS Alternate Data Streams (ADS) in file paths are prohibited.")
            expanded_s = expand_env_and_tilde(s)
            target_p: Union[str, Path] = (
                self.normalize_target_path(s, base_dir=eff_base)
                if (not Path(expanded_s).is_absolute() and eff_base)
                else s
            )
            acc_err = self.check_path_access(target_p, mode=mode)
            if acc_err is not None:
                return (f"py_ast_path_{mode}_blocked", acc_err)
        return None

    def _analyze_python_ast_call_sites(
        self,
        tree: ast.Module,
        eff_base: str,
    ) -> Optional[Tuple[str, str]]:
        """Flow-sensitive AST call-site analyzer for Python file/dir, subprocess, and network operations."""
        net_func_names = frozenset({
            "urlopen",
            "urlretrieve",
            "Request",
            "HTTPConnection",
            "HTTPSConnection",
            "create_connection",
            "connect",
            "connect_ex",
            "sendto",
            "getaddrinfo",
            "gethostbyname",
            "gethostbyname_ex",
        })
        net_mod_names = frozenset({
            "urllib",
            "request",
            "httpx",
            "requests",
            "aiohttp",
            "socket",
            "websocket",
            "websockets",
            "http",
        })
        http_verb_attrs = frozenset({"get", "post", "put", "delete", "patch", "head", "options", "request", "stream"})

        def _kw_val(call_nd: ast.Call, name: str) -> Optional[ast.AST]:
            for kw in call_nd.keywords:
                if kw.arg == name:
                    return kw.value
            return None

        def _collect_call_strs(nodes: Sequence[Optional[ast.AST]], vmap: Dict[str, str]) -> List[str]:
            out_s: List[str] = []
            for nd in nodes:
                if nd is None:
                    continue
                fs = _eval_static_path_str(nd, vmap, cwd_base=eff_base)
                if fs is not None:
                    out_s.append(fs)
                else:
                    for sub in ast.walk(nd):
                        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                            out_s.append(sub.value)
                        elif isinstance(sub, ast.Name) and sub.id in vmap:
                            out_s.append(vmap[sub.id])
            return out_s

        def _check_expr_calls(expr: Optional[ast.AST], vmap: Dict[str, str]) -> Optional[Tuple[str, str]]:
            if expr is None:
                return None
            for node in ast.walk(expr):
                if not isinstance(node, ast.Call):
                    continue
                fn = node.func
                mod_name = ""
                if isinstance(fn, ast.Attribute):
                    if isinstance(fn.value, ast.Name):
                        mod_name = fn.value.id
                    elif isinstance(fn.value, ast.Attribute) and isinstance(fn.value.value, ast.Name):
                        mod_name = fn.value.value.id
                attr_name = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")

                # 1. Builtin / io / codecs open & FileIO
                is_open_fn = (isinstance(fn, ast.Name) and fn.id in ("open", "FileIO")) or (
                    isinstance(fn, ast.Attribute)
                    and mod_name in ("io", "codecs", "builtins")
                    and fn.attr in ("open", "FileIO")
                )
                if is_open_fn:
                    f_arg = node.args[0] if node.args else _kw_val(node, "file")
                    m_arg = node.args[1] if len(node.args) >= 2 else _kw_val(node, "mode")
                    m_str = "write" if _mode_node_is_mutating(m_arg) else "read"
                    hit = self._check_python_ast_path_expr(f_arg, m_str, vmap, eff_base)
                    if hit is not None:
                        return hit
                    continue

                # 2. Path / object filesystem methods (only path receiver/target, NEVER write_text content!)
                if isinstance(fn, ast.Attribute) and mod_name not in ("os", "nt", "posix", "shutil", "glob", "sqlite3", "zipfile", "tarfile", "subprocess", "asyncio", "urllib", "httpx", "requests", "socket", "http"):
                    if fn.attr in ("read_text", "read_bytes", "iterdir", "glob", "rglob", "stat", "lstat", "exists", "is_file", "is_dir", "readlink"):
                        hit = self._check_python_ast_path_expr(fn.value, "read", vmap, eff_base)
                        if hit is not None:
                            return hit
                    elif fn.attr == "open":
                        m_arg = node.args[0] if node.args else _kw_val(node, "mode")
                        hit = self._check_python_ast_path_expr(fn.value, "write" if _mode_node_is_mutating(m_arg) else "read", vmap, eff_base)
                        if hit is not None:
                            return hit
                    elif fn.attr in ("write_text", "write_bytes", "touch", "mkdir", "unlink", "rmdir", "chmod", "lchmod"):
                        hit = self._check_python_ast_path_expr(fn.value, "write", vmap, eff_base)
                        if hit is not None:
                            return hit
                    elif fn.attr in ("replace", "rename", "symlink_to", "hardlink_to", "link_to"):
                        # Exclude str.replace(old, new) which takes 2+ args and is non-path when receiver isn't a forbidden path;
                        # note str.replace has >=2 args while Path.replace/rename takes exactly 1 target arg!
                        if fn.attr == "replace" and len(node.args) >= 2:
                            pass
                        else:
                            t2 = node.args[0] if node.args else _kw_val(node, "target")
                            for p_nd in (fn.value, t2):
                                hit = self._check_python_ast_path_expr(p_nd, "write", vmap, eff_base)
                                if hit is not None:
                                    return hit

                # 3. stdlib os / shutil / glob / sqlite3 / zipfile / tarfile
                if mod_name in ("os", "nt", "posix") or (isinstance(fn, ast.Name) and attr_name in ("listdir", "scandir", "chdir", "mkdir", "makedirs", "remove", "unlink", "rmdir", "removedirs", "rename", "renames")):
                    if attr_name == "open":
                        p_arg = node.args[0] if node.args else _kw_val(node, "path")
                        fl_arg = node.args[1] if len(node.args) >= 2 else _kw_val(node, "flags")
                        is_ro = (isinstance(fl_arg, ast.Constant) and fl_arg.value == 0) or (
                            isinstance(fl_arg, ast.Attribute) and fl_arg.attr == "O_RDONLY"
                        )
                        hit = self._check_python_ast_path_expr(p_arg, "read" if is_ro else "write", vmap, eff_base)
                        if hit is not None:
                            return hit
                    elif attr_name in ("listdir", "scandir", "walk", "chdir", "stat", "lstat", "access", "readlink"):
                        p_arg = node.args[0] if node.args else (_kw_val(node, "path") or _kw_val(node, "top"))
                        hit = self._check_python_ast_path_expr(p_arg, "read", vmap, eff_base)
                        if hit is not None:
                            return hit
                    elif attr_name in ("mkdir", "makedirs", "remove", "unlink", "rmdir", "removedirs", "truncate", "chmod", "chown", "utime"):
                        p_arg = node.args[0] if node.args else (_kw_val(node, "path") or _kw_val(node, "name"))
                        hit = self._check_python_ast_path_expr(p_arg, "write", vmap, eff_base)
                        if hit is not None:
                            return hit
                    elif attr_name in ("rename", "renames", "replace", "link", "symlink"):
                        s_arg = node.args[0] if node.args else _kw_val(node, "src")
                        d_arg = node.args[1] if len(node.args) >= 2 else _kw_val(node, "dst")
                        for p_nd in (s_arg, d_arg):
                            hit = self._check_python_ast_path_expr(p_nd, "write", vmap, eff_base)
                            if hit is not None:
                                return hit

                if mod_name == "glob" and attr_name in ("glob", "iglob"):
                    p_arg = node.args[0] if node.args else _kw_val(node, "pathname")
                    hit = self._check_python_ast_path_expr(p_arg, "read", vmap, eff_base)
                    if hit is not None:
                        return hit

                if mod_name == "shutil" or (isinstance(fn, ast.Name) and attr_name in ("rmtree", "copy", "copy2", "copyfile", "copytree", "move")):
                    if attr_name in ("copy", "copy2", "copyfile", "copytree"):
                        s_arg = node.args[0] if node.args else _kw_val(node, "src")
                        d_arg = node.args[1] if len(node.args) >= 2 else _kw_val(node, "dst")
                        for p_nd, m_s in ((s_arg, "read"), (d_arg, "write")):
                            hit = self._check_python_ast_path_expr(p_nd, m_s, vmap, eff_base)
                            if hit is not None:
                                return hit
                    elif attr_name in ("move", "rmtree"):
                        for a_nd in list(node.args[:2]) + [kw.value for kw in node.keywords if kw.arg in ("src", "dst", "path")]:
                            hit = self._check_python_ast_path_expr(a_nd, "write", vmap, eff_base)
                            if hit is not None:
                                return hit

                if mod_name == "sqlite3" and attr_name == "connect":
                    db_arg = node.args[0] if node.args else _kw_val(node, "database")
                    db_s = _eval_static_path_str(db_arg, vmap, cwd_base=eff_base)
                    if db_s and db_s.strip() != ":memory:" and "mode=memory" not in db_s.lower():
                        is_ro_db = "mode=ro" in db_s.lower()
                        clean_db = re.sub(r"(?i)^file:", "", db_s).split("?", 1)[0]
                        if clean_db and clean_db != ":memory:":
                            hit = self._check_python_ast_path_expr(ast.Constant(value=clean_db), "read" if is_ro_db else "write", vmap, eff_base)
                            if hit is not None:
                                return hit

                if (mod_name == "zipfile" and attr_name == "ZipFile") or (mod_name == "tarfile" and attr_name == "open"):
                    f_arg = node.args[0] if node.args else (_kw_val(node, "file") or _kw_val(node, "name"))
                    m_arg = node.args[1] if len(node.args) >= 2 else _kw_val(node, "mode")
                    hit = self._check_python_ast_path_expr(f_arg, "write" if _mode_node_is_mutating(m_arg) else "read", vmap, eff_base)
                    if hit is not None:
                        return hit

                # 4. Subprocess / OS command execution call sites
                is_subproc = (
                    (mod_name == "subprocess" and attr_name in ("run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput"))
                    or (mod_name == "os" and (attr_name in ("system", "popen", "startfile") or attr_name.startswith(("spawn", "exec"))))
                    or (mod_name == "asyncio" and attr_name in ("create_subprocess_shell", "create_subprocess_exec"))
                )
                if is_subproc:
                    cwd_kw = _kw_val(node, "cwd")
                    if cwd_kw is not None:
                        hit_cwd = self._check_python_ast_path_expr(cwd_kw, "read", vmap, eff_base)
                        if hit_cwd is not None:
                            return hit_cwd
                    cmd_nodes: List[Optional[ast.AST]] = list(node.args) + [
                        kw.value for kw in node.keywords if kw.arg in ("args", "cmd", "executable")
                    ]
                    cmd_strs = _collect_call_strs(cmd_nodes, vmap)
                    if cmd_strs:
                        joined_sub = " ".join(cmd_strs)
                        sub_err = self.check_destructive_command(joined_sub, cwd=eff_base)
                        if sub_err is not None:
                            return ("py_ast_subproc_blocked", sub_err)

                # 5. Network / SSRF call sites
                is_net_call = (
                    attr_name in net_func_names
                    or mod_name in net_mod_names
                    or (attr_name in http_verb_attrs and mod_name not in ("os", "environ"))
                )
                if is_net_call:
                    net_strs = _collect_call_strs(list(node.args) + [kw.value for kw in node.keywords], vmap)
                    for ns in net_strs:
                        if attr_name in http_verb_attrs and mod_name not in net_mod_names:
                            if not re.match(r"^(?:https?|wss?)://", ns.strip(), re.IGNORECASE):
                                continue
                        exp_ns = expand_env_and_tilde(ns)
                        for pat, reason in SSRF_CMD_PATTERNS:
                            if re.search(pat, ns) or re.search(pat, exp_ns):
                                return ("cmd_ssrf_blocked", f"[GUARD NETWORK ISOLATION]: {reason}")
            return None

        def _assign_vmap(target_nd: ast.AST, val_nd: ast.AST, vmap: Dict[str, str]) -> None:
            if isinstance(target_nd, (ast.Tuple, ast.List)) and isinstance(val_nd, (ast.Tuple, ast.List)) and len(target_nd.elts) == len(val_nd.elts):
                for te, ve in zip(target_nd.elts, val_nd.elts):
                    _assign_vmap(te, ve, vmap)
                return
            folded_v = _eval_static_path_str(val_nd, vmap, cwd_base=eff_base)
            for nm in _extract_target_names(target_nd):
                if folded_v is not None:
                    vmap[nm] = folded_v
                else:
                    vmap.pop(nm, None)

        def _walk_stmts(stmts: Sequence[ast.stmt], vmap: Dict[str, str]) -> Optional[Tuple[str, str]]:
            for st in stmts:
                if isinstance(st, ast.Assign):
                    hit = _check_expr_calls(st.value, vmap)
                    if hit is not None:
                        return hit
                    for t in st.targets:
                        _assign_vmap(t, st.value, vmap)
                elif isinstance(st, ast.AnnAssign):
                    if st.value is not None:
                        hit = _check_expr_calls(st.value, vmap)
                        if hit is not None:
                            return hit
                        _assign_vmap(st.target, st.value, vmap)
                elif isinstance(st, ast.AugAssign):
                    hit = _check_expr_calls(st.value, vmap)
                    if hit is not None:
                        return hit
                    for nm in _extract_target_names(st.target):
                        vmap.pop(nm, None)
                elif isinstance(st, ast.Delete):
                    for t in st.targets:
                        for nm in _extract_target_names(t):
                            vmap.pop(nm, None)
                elif isinstance(st, (ast.With, ast.AsyncWith)):
                    for item in st.items:
                        hit = _check_expr_calls(item.context_expr, vmap)
                        if hit is not None:
                            return hit
                        if item.optional_vars is not None:
                            for nm in _extract_target_names(item.optional_vars):
                                vmap.pop(nm, None)
                    hit_b = _walk_stmts(st.body, vmap)
                    if hit_b is not None:
                        return hit_b
                elif isinstance(st, ast.If):
                    hit_t = _check_expr_calls(st.test, vmap)
                    if hit_t is not None:
                        return hit_t
                    vm_b, vm_e = dict(vmap), dict(vmap)
                    hit_b = _walk_stmts(st.body, vm_b)
                    if hit_b is not None:
                        return hit_b
                    hit_e = _walk_stmts(st.orelse, vm_e)
                    if hit_e is not None:
                        return hit_e
                    vmap.clear()
                    for k, v in vm_b.items():
                        if vm_e.get(k) == v:
                            vmap[k] = v
                elif isinstance(st, (ast.For, ast.AsyncFor)):
                    hit_i = _check_expr_calls(st.iter, vmap)
                    if hit_i is not None:
                        return hit_i
                    for nm in _extract_target_names(st.target):
                        vmap.pop(nm, None)
                    hit_b = _walk_stmts(st.body, vmap)
                    if hit_b is not None:
                        return hit_b
                    hit_o = _walk_stmts(st.orelse, vmap)
                    if hit_o is not None:
                        return hit_o
                elif isinstance(st, ast.While):
                    hit_t = _check_expr_calls(st.test, vmap)
                    if hit_t is not None:
                        return hit_t
                    hit_b = _walk_stmts(st.body, vmap)
                    if hit_b is not None:
                        return hit_b
                    hit_o = _walk_stmts(st.orelse, vmap)
                    if hit_o is not None:
                        return hit_o
                elif isinstance(st, ast.Try):
                    vm_t = dict(vmap)
                    hit_b = _walk_stmts(st.body, vm_t)
                    if hit_b is not None:
                        return hit_b
                    for h in st.handlers:
                        vm_h = dict(vmap)
                        hit_h = _walk_stmts(h.body, vm_h)
                        if hit_h is not None:
                            return hit_h
                    hit_o = _walk_stmts(st.orelse, vm_t)
                    if hit_o is not None:
                        return hit_o
                    vmap.clear()
                    hit_f = _walk_stmts(st.finalbody, vmap)
                    if hit_f is not None:
                        return hit_f
                elif isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    local_params = (
                        {a.arg for a in getattr(st.args, "posonlyargs", [])}
                        | {a.arg for a in st.args.args}
                        | {a.arg for a in st.args.kwonlyargs}
                    )
                    if st.args.vararg:
                        local_params.add(st.args.vararg.arg)
                    if st.args.kwarg:
                        local_params.add(st.args.kwarg.arg)
                    fn_vmap = {k: v for k, v in vmap.items() if k not in local_params}
                    hit_fn = _walk_stmts(st.body, fn_vmap)
                    if hit_fn is not None:
                        return hit_fn
                elif isinstance(st, ast.ClassDef):
                    hit_cl = _walk_stmts(st.body, dict(vmap))
                    if hit_cl is not None:
                        return hit_cl
                else:
                    hit_ex = _check_expr_calls(st, vmap)
                    if hit_ex is not None:
                        return hit_ex
            return None

        return _walk_stmts(tree.body, {})

    def check_command_pipelock(
        self,
        command: str,
        cwd: Optional[str] = None,
        is_python_code: bool = False,
        *,
        tool_name: str = "",
        extra_args: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        if not command or not command.strip():
            return None

        if is_python_code:
            eff_cmd = strip_python_comments_tokenize(command)
        else:
            eff_cmd = strip_shell_comments(strip_powershell_backticks(command))

        eff_base = (
            str(cwd or "").strip()
            or (str(self.workspace_roots[0]) if self.workspace_roots else "")
            or str(Path.cwd())
        )

        # When `is_python_code=True` and code parses into valid Python AST, evaluate
        # sensitive paths, mode secrets, workspace boundaries, subprocesses, and SSRF strictly
        # at flow-sensitive AST call sites rather than raw string-literal regexes.
        if is_python_code:
            try:
                py_tree = ast.parse(eff_cmd)
            except SyntaxError:
                py_tree = None
            if py_tree is not None:
                if _python_ast_flow_has_forbidden_write(
                    py_tree,
                    lambda s: self._is_forbidden_write_str(s, eff_base),
                    recursive_cmd_checker=lambda sub_c: self.check_destructive_command(sub_c, cwd=eff_base),
                ):
                    reason = "Mutating protected files, persistence hooks, or outside-workspace paths via Python AST is prohibited."
                    self.record_security_event("py_ast_taint_blocked", command, reason)
                    return f"[GUARD AST TAINT]: {reason}"
                ast_hit = self._analyze_python_ast_call_sites(py_tree, eff_base)
                if ast_hit is not None:
                    ev_type, err_msg = ast_hit
                    self.record_security_event(ev_type, command[:240], err_msg)
                    return err_msg
                gate_err = _invoke_extra_access_gate(
                    self.extra_access_gate,
                    kind="command",
                    command_or_code=command,
                    cwd=eff_base,
                    is_python_code=True,
                    tool_name=tool_name,
                    extra_args=extra_args,
                )
                if gate_err:
                    self.record_security_event("extra_gate_cmd_blocked", command[:240], gate_err)
                    return gate_err
                return None

        expanded_cmd = expand_env_and_tilde(eff_cmd)
        active_sens_patterns = self._active_sensitive_path_patterns()

        for pat, reason in active_sens_patterns:
            if re.search(pat, eff_cmd) or re.search(pat, expanded_cmd):
                self.record_security_event("cmd_credential_access_blocked", command, reason)
                return f"[GUARD CREDENTIAL ISOLATION]: {reason}"

        if re.search(r"(?i)(?:human_ui_secret|peer_hmac_secret)", eff_cmd):
            reason = f"{ERR_HUMAN_MODE_LOCKED}: Accessing .human_ui_secret / .peer_hmac_secret in scripts or commands is prohibited."
            self.record_security_event("cmd_secret_probe_blocked", command, reason)
            return f"[GUARD CREDENTIAL ISOLATION]: {reason}"

        for pat, reason in SSRF_CMD_PATTERNS:
            if re.search(pat, eff_cmd) or re.search(pat, expanded_cmd):
                self.record_security_event("cmd_ssrf_blocked", command, reason)
                return f"[GUARD NETWORK ISOLATION]: {reason}"

        # Flow-sensitive Python AST taint check (or shell tamper check)
        try:
            tree = ast.parse(eff_cmd)
            skeleton = _strip_python_strings_and_comments(eff_cmd)
            if _SHELL_REDIRECT_TAMPER_RE.search(skeleton):
                reason = "Overwriting MCP audit logs or guardrail files via redirection is prohibited."
                self.record_security_event("cmd_self_tamper_blocked", command, reason)
                return f"[GUARD ANTI-TAMPER]: {reason}"
            if _python_ast_flow_has_forbidden_write(
                tree,
                lambda s: self._is_forbidden_write_str(s, eff_base),
                recursive_cmd_checker=lambda sub_c: self.check_command_pipelock(sub_c, cwd=eff_base, is_python_code=False),
            ):
                reason = "Mutating protected files, persistence hooks, or outside-workspace paths via Python AST is prohibited."
                self.record_security_event("py_ast_taint_blocked", command, reason)
                return f"[GUARD AST TAINT]: {reason}"
        except SyntaxError:
            if not is_python_code:
                for rx in (_SHELL_REDIRECT_TAMPER_RE, _SHELL_CMDLET_TAMPER_RE):
                    for m_sh in rx.finditer(eff_cmd):
                        if self._is_forbidden_write_str(m_sh.group(1), eff_base):
                            reason = "Modifying protected MCP files via shell commands is prohibited."
                            self.record_security_event("cmd_self_tamper_blocked", command, reason)
                            return f"[GUARD ANTI-TAMPER]: {reason}"
                tainted_ps: Set[str] = set()
                for seg in re.split(r"[\n;|]+", eff_cmd):
                    for mv in _PS_VAR_ASSIGN_RE.finditer(seg):
                        vn = mv.group(1).lower()
                        if self._is_forbidden_write_str(mv.group(2), eff_base):
                            tainted_ps.add(vn)
                        else:
                            tainted_ps.discard(vn)
                    if tainted_ps and _SHELL_WRITE_CMD_RE.search(seg):
                        for ref_m in re.finditer(r"\$([A-Za-z_][A-Za-z0-9_]*)\b", seg):
                            if ref_m.group(1).lower() in tainted_ps:
                                reason = "Modifying protected target via tainted shell variable is prohibited."
                                self.record_security_event("cmd_ps_taint_blocked", command, reason)
                                return f"[GUARD ANTI-TAMPER]: {reason}"

        restrict_ws = bool(self.restrict_to_workspace and self.workspace_roots)
        if restrict_ws and not is_python_code:
            if re.search(
                r"(?i)(?:(?:^|[\s;|&(])(?:cmd(?:\.exe)?\s+/c\s+)?mklink\b|\b(?:New-Item|ni)\b[^\r\n;|&]*-(?:ItemType|Type)\s+['\"]?(?:Junction|SymbolicLink|HardLink)\b|::\s*Create(?:SymbolicLink|Junction)\s*\(|\bfsutil(?:\.exe)?\s+(?:reparsepoint|hardlink)\b)",
                eff_cmd,
            ):
                reason = f"Creating filesystem junctions, symbolic links, or hard links is prohibited in Tier {self.tier}."
                self.record_security_event("cmd_link_creation_blocked", command, reason)
                return f"[GUARD WORKSPACE SANDBOX]: {reason}"

            if re.search(r"(?i)(?:\bWin32_Process\b|\bwmic(?:\.exe)?\b[^\r\n;|&]*\bprocess\b[^\r\n;|&]*\bcreate\b)", eff_cmd):
                reason = "Spawning detached WMI/CIM processes (`Win32_Process` / `wmic process create`) is prohibited in workspace-restricted tier."
                self.record_security_event("cmd_wmi_spawn_blocked", command, reason)
                return f"[GUARD WORKSPACE SANDBOX]: {reason}"

            for cl_sp in _SHELL_CLAUSE_SPLIT_RE.split(eff_cmd):
                if re.search(r"(?i)(?:^|[\s;|&(])(?:Start-Process|saps)\b", cl_sp) and not re.search(
                    r"(?i)(?:-NoNewWindow\b|-WindowStyle\s+['\"]?Hidden\b)", cl_sp
                ):
                    reason = "Start-Process without `-NoNewWindow` or `-WindowStyle Hidden` is prohibited (zero-popup L0 rule)."
                    self.record_security_event("cmd_start_process_popup_blocked", command, reason)
                    return f"[GUARD WORKSPACE SANDBOX]: {reason}"

            for cl_iso in _SHELL_CLAUSE_SPLIT_RE.split(eff_cmd):
                if _L3_PY_ISOLATED_FLAG_RE.search(cl_iso) and not _SAFE_PY_ISOLATED_PIP_INSTALL_RE.match(cl_iso):
                    reason = f"Python `-I`/`-E`/`-S` flags that bypass L3 workspace audit hooks are prohibited in Tier {self.tier}."
                    self.record_security_event("cmd_py_isolated_flag_blocked", command, reason)
                    return f"[GUARD WORKSPACE SANDBOX]: {reason}"

            for m_pyc in _INLINE_PY_DASH_C_RE.finditer(eff_cmd):
                raw_inline = m_pyc.group(1) if m_pyc.group(1) is not None else (m_pyc.group(2) or "")
                py_inline = raw_inline.replace('\\"', '"').replace("\\\\", "\\") if m_pyc.group(1) is not None else raw_inline
                if py_inline.strip():
                    inline_err = self.check_command_pipelock(py_inline, cwd=eff_base, is_python_code=True)
                    if inline_err:
                        return inline_err

        masked_eff_cmd = _mask_shell_quoted_literals(eff_cmd) if not is_python_code else eff_cmd
        has_shell_write = (not is_python_code) and bool(_SHELL_WRITE_CMD_RE.search(masked_eff_cmd))
        null_devs = frozenset({"/dev/null", "nul", "//./nul"})
        read_blocked = self._read_blocked_prefixes()
        write_blocked = self._write_blocked_prefixes()
        eff_block_destr = self._effective_block_destructive_commands()
        block_git_meta = self._should_block_git_repo_meta()

        if not is_python_code and self._effective_protect_host_credentials():
            for m_npm in _NPMRC_TOKEN_RE.finditer(eff_cmd):
                npm_tok = m_npm.group(1).strip()
                npm_cand = self.normalize_target_path(npm_tok, base_dir=eff_base)
                npm_err = self._is_blocked_npmrc_target(npm_cand, npm_tok)
                if npm_err:
                    self.record_security_event("cmd_credential_access_blocked", command, npm_err)
                    return f"[GUARD CREDENTIAL ISOLATION]: {npm_err}"

        # Collect redirection target tokens in shell clauses so `readonly_workspace_roots` blocks `> ro/file` even in L4
        redir_write_tokens: Set[str] = set()
        if not is_python_code and self.readonly_workspace_roots:
            for m_rd in re.finditer(r"(?:^|[\s;|(&])\d*>{1,2}\s*(?:\"([^\"\r\n]+)\"|'([^'\r\n]+)'|([^\s\"'|&;<>()`]+))", eff_cmd):
                rt = (m_rd.group(1) or m_rd.group(2) or m_rd.group(3) or "").strip()
                if rt:
                    redir_write_tokens.add(rt)

        for tok, is_exec_pos in self._extract_command_path_items(eff_cmd, is_python_code=is_python_code):
            raw_tok_norm = tok.strip().strip("\"'").replace("\\", "/").lower()
            if raw_tok_norm in null_devs:
                continue
            if has_ntfs_ads_stream(tok, for_command_token=True):
                reason = "NTFS Alternate Data Streams (ADS) in command paths are prohibited."
                self.record_security_event("cmd_ntfs_ads_blocked", command, reason)
                return f"[GUARD WORKSPACE SANDBOX]: {reason}"

            tok_for_norm = re.sub(r"::(?!\$).*$", "", tok) if "::" in tok and not _NTFS_ADS_STREAM_TYPE_RE.search(tok) else tok
            if not is_python_code and ":" in tok_for_norm:
                m_vol = _DOCKER_BIND_VOL_RE.match(tok_for_norm)
                if m_vol is not None:
                    tok_for_norm = m_vol.group("host")
                elif not _WIN_DRIVE_ABS_RE.match(tok_for_norm):
                    # Non-ADS colon-separated CLI spec such as `HEAD:refs/heads/main`, `main:src/app.py`, or `image:tag`
                    rhs_part = tok_for_norm.split(":", 1)[1]
                    if not _PARENT_TRAVERSAL_RE.search(rhs_part) and not _HOME_ENV_TOKEN_RE.search(tok_for_norm):
                        continue

            base_cand = self.normalize_target_path(tok_for_norm, base_dir=eff_base)
            if str(base_cand).replace("\\", "/").lower() in null_devs:
                continue

            nc_str = str(base_cand)
            nc_low = nc_str.lower()
            if self._is_state_secret_or_conn_file(base_cand) or any(_is_under_prefix(nc_low, p) for p in read_blocked):
                reason = "MCP secrets, OAuth database, and connection info files are isolated."
                self.record_security_event("cmd_credential_access_blocked", command, reason)
                return f"[GUARD CREDENTIAL ISOLATION]: {reason}"
            for pat, reason in active_sens_patterns:
                if re.search(pat, nc_str):
                    self.record_security_event("cmd_credential_access_blocked", command, reason)
                    return f"[GUARD CREDENTIAL ISOLATION]: {reason}"
            npm_tok_err = self._is_blocked_npmrc_target(base_cand, tok_for_norm)
            if npm_tok_err:
                self.record_security_event("cmd_credential_access_blocked", command, npm_tok_err)
                return f"[GUARD CREDENTIAL ISOLATION]: {npm_tok_err}"
            if has_shell_write and (eff_block_destr or block_git_meta):
                pers_err = check_persistence_components(base_cand, check_git_repo_meta=block_git_meta)
                if pers_err and (eff_block_destr or "Git repository" in pers_err):
                    self.record_security_event("cmd_persistence_blocked", command, pers_err)
                    return f"[GUARD PERSISTENCE ISOLATION]: {pers_err}"
            if has_shell_write and any(_is_under_prefix(nc_low, w) for w in write_blocked):
                reason = "Modifying MCP server code, config, or audit logs via shell is prohibited."
                self.record_security_event("cmd_self_tamper_blocked", command, reason)
                return f"[GUARD ANTI-TAMPER]: {reason}"
            if self.readonly_workspace_roots and not is_exec_pos and (
                tok in redir_write_tokens
                or (
                    has_shell_write
                    and not re.search(r"(?i)\b(?:cp|Copy-Item|cpi)\b", masked_eff_cmd)
                )
            ):
                ro_cmd_err = self._check_readonly_workspace_write(base_cand)
                if ro_cmd_err:
                    self.record_security_event("readonly_workspace_write_blocked", command, ro_cmd_err)
                    return f"[GUARD WORKSPACE SANDBOX]: {ro_cmd_err}"

            if restrict_ws and not self._is_under_any_workspace(base_cand):
                if (not is_python_code) and is_exec_pos and self._is_allowed_runtime_executable(base_cand):
                    continue
                if self._is_allowed_readonly_toolchain_path(base_cand) and not has_shell_write:
                    continue
                roots_disp = ", ".join(f"`{r}`" for r in self.workspace_roots)
                reason = f"Tier {self.tier} restricts command/script file access to [{roots_disp}] (got `{base_cand}` from `{tok}`)."
                self.record_security_event("cmd_workspace_escape_blocked", command, reason)
                return f"[GUARD WORKSPACE SANDBOX]: {reason}"

        gate_err = _invoke_extra_access_gate(
            self.extra_access_gate,
            kind="command",
            command_or_code=command,
            cwd=eff_base,
            is_python_code=is_python_code,
            tool_name=tool_name,
            extra_args=extra_args,
        )
        if gate_err:
            self.record_security_event("extra_gate_cmd_blocked", command[:240], gate_err)
            return gate_err

        return None

    def _is_safe_workspace_build_clean_clause(self, clause: str, eff_base: str) -> bool:
        s = (clause or "").strip()
        if not s or any(ch in s for ch in ("`", ">", "<", "(", ")")) or "$(" in s:
            return False
        raw_tokens: List[str] = []
        pos = 0
        for m in _CMD_TOKEN_RE.finditer(s):
            gap = s[pos : m.start()]
            if gap.strip(" \t,"):
                return False
            pos = m.end()
            tok = (m.group(1) or m.group(2) or m.group(3) or "").strip()
            if tok:
                for part in (tok.split(",") if m.group(3) else [tok]):
                    pt = part.strip()
                    if pt:
                        raw_tokens.append(pt)
        if s[pos:].strip(" \t,") or not raw_tokens:
            return False

        idx = 0
        if raw_tokens[0].lower() in ("&", "call") and len(raw_tokens) > 1:
            idx = 1
        raw_cmd_tok = raw_tokens[idx].lower()
        cmd_tok = Path(raw_cmd_tok).stem.lower() if raw_cmd_tok.endswith(".exe") else raw_cmd_tok
        if cmd_tok not in ("rm", "rmdir", "rd", "remove-item", "ri", "rimraf"):
            return False

        targets: List[str] = []
        end_flags = False
        j = idx + 1
        while j < len(raw_tokens):
            tk = raw_tokens[j]
            tk_low = tk.lower()
            if not end_flags and tk == "--":
                end_flags = True
                j += 1
                continue
            if not end_flags and cmd_tok in ("rm", "rimraf", "rmdir") and (
                re.fullmatch(r"-[rRfFiIvVdp]+", tk) or tk_low in ("--recursive", "--force", "--dir")
            ):
                j += 1
                continue
            if not end_flags and cmd_tok in ("rd", "rmdir") and tk_low in ("/s", "/q"):
                j += 1
                continue
            if not end_flags and cmd_tok in ("remove-item", "ri") and tk.startswith("-"):
                if tk_low in ("-recurse", "-force", "-r", "-fo", "-path", "-literalpath"):
                    j += 1
                    continue
                if tk_low in ("-erroraction", "-ea") and j + 1 < len(raw_tokens):
                    j += 2
                    continue
                return False
            if not end_flags and tk.startswith("-"):
                return False
            targets.append(tk)
            j += 1

        if not targets:
            return False
        base_real = canonical_realpath(eff_base)
        base_low = str(base_real).lower().rstrip("\\/")
        if not base_low:
            return False
        allowed_ancestors: List[str] = [str(w).lower().rstrip("\\/") for w in self.workspace_roots if str(w).strip()]
        if not allowed_ancestors or (not self.restrict_to_workspace and base_real.parent != base_real):
            if base_low not in allowed_ancestors:
                allowed_ancestors.append(base_low)

        for tgt in targets:
            if any(ch in tgt for ch in ("*", "?", "[", "]", "~", "$", "%")) or _PARENT_TRAVERSAL_RE.search(tgt):
                return False
            if has_ntfs_ads_stream(tgt, for_command_token=True):
                return False
            raw_p = Path(tgt)
            unres = raw_p if raw_p.is_absolute() else (Path(eff_base) / raw_p)
            try:
                if os.path.islink(unres) or (callable(getattr(unres, "is_junction", None)) and unres.is_junction()):
                    return False
                st_u = os.lstat(unres)
                tag_u = int(getattr(st_u, "st_reparse_tag", 0) or 0)
                if tag_u != 0:
                    if tag_u in (0xA000000C, 0xA0000003):
                        return False
                elif bool(getattr(st_u, "st_file_attributes", 0) & 0x0400):
                    return False
            except FileNotFoundError:
                pass
            except OSError:
                return False
            cand = self.normalize_target_path(tgt, base_dir=eff_base)
            if cand.name.lower() not in _SAFE_BUILD_CLEAN_NAMES:
                return False
            if self.check_path_access(cand, mode="write") is not None:
                return False
            cand_ancestors = list(allowed_ancestors)
            if not self.restrict_to_workspace and cand.parent != cand and cand.parent.parent != cand.parent:
                par_low = str(cand.parent).lower().rstrip("\\/")
                if par_low and par_low not in cand_ancestors:
                    cand_ancestors.append(par_low)
            c_low = str(cand).lower().rstrip("\\/")
            if c_low in cand_ancestors or c_low == base_low:
                return False
            if not any(_is_under_prefix(c_low, anc) and c_low != anc for anc in cand_ancestors):
                return False
        return True

    def check_destructive_command(self, command: str, cwd: Optional[str] = None, *, _depth: int = 0) -> Optional[str]:
        pipelock_err = self.check_command_pipelock(command, cwd=cwd, is_python_code=False)
        if pipelock_err:
            return pipelock_err
        cleaned = strip_shell_comments(strip_powershell_backticks(command or ""))
        eff_base = (
            str(cwd or "").strip()
            or (str(self.workspace_roots[0]) if self.workspace_roots else "")
            or str(Path.cwd())
        )
        # Inspect inline `python -c "..."` and subshell `-c`/`/c`/`-Command` payloads before masking quoted strings
        if _depth < 2:
            for m_pyc in _INLINE_PY_DASH_C_RE.finditer(cleaned):
                raw_inline = m_pyc.group(1) if m_pyc.group(1) is not None else (m_pyc.group(2) or "")
                py_inline = raw_inline.replace('\\"', '"').replace("\\\\", "\\") if m_pyc.group(1) is not None else raw_inline
                if py_inline.strip():
                    py_err = self.check_python_code_safety(py_inline, cwd=eff_base)
                    if py_err:
                        return py_err
            for m_sub in _INLINE_SUBSHELL_RE.finditer(cleaned):
                raw_sub = m_sub.group(1) if m_sub.group(1) is not None else (m_sub.group(2) or "").replace("''", "'")
                sub_sh = raw_sub.replace('\\"', '"').replace("\\\\", "\\") if m_sub.group(1) is not None else raw_sub
                if sub_sh.strip():
                    sub_err = self.check_destructive_command(sub_sh, cwd=eff_base, _depth=_depth + 1)
                    if sub_err:
                        return sub_err

        masked = _mask_shell_quoted_literals(cleaned)
        raw_clauses = [c for c in _SHELL_CLAUSE_SPLIT_RE.split(cleaned) if c and c.strip()]
        masked_clauses = [c for c in _SHELL_CLAUSE_SPLIT_RE.split(masked) if c and c.strip()]
        eff_block_destr = self._effective_block_destructive_commands()

        if eff_block_destr:
            del_pat, del_reason = USER_CONFIGURABLE_DESTRUCTIVE_CMD_PATTERNS[0]
            # Pair masked and raw clauses if split counts align (fallback to raw_clauses with per-clause masking)
            clause_pairs = (
                list(zip(masked_clauses, raw_clauses))
                if len(masked_clauses) == len(raw_clauses)
                else [(_mask_shell_quoted_literals(rc), rc) for rc in raw_clauses]
            )
            for m_cl, r_cl in clause_pairs:
                if re.search(del_pat, m_cl) and not self._is_safe_workspace_build_clean_clause(r_cl, eff_base):
                    self.record_security_event("destructive_cmd_blocked", command, del_reason)
                    return f"[GUARD DANGEROUS COMMAND BLOCKED]: {del_reason}"

            for idx_u, (pat, reason) in enumerate(USER_CONFIGURABLE_DESTRUCTIVE_CMD_PATTERNS[1:], start=1):
                if idx_u == 4:
                    for m_cl, r_cl in clause_pairs:
                        if _CLAUSE_HEAD_KILL_VERB_RE.search(m_cl) and re.search(pat, r_cl):
                            self.record_security_event("destructive_cmd_blocked", command, reason)
                            return f"[GUARD DANGEROUS COMMAND BLOCKED]: {reason}"
                    continue
                if re.search(pat, masked):
                    self.record_security_event("destructive_cmd_blocked", command, reason)
                    return f"[GUARD DANGEROUS COMMAND BLOCKED]: {reason}"

        clause_pairs_self = (
            list(zip(masked_clauses, raw_clauses))
            if len(masked_clauses) == len(raw_clauses)
            else [(_mask_shell_quoted_literals(rc), rc) for rc in raw_clauses]
        )
        for pat_s, reason_s in MCP_SELF_PROTECT_CMD_PATTERNS:
            for m_cl, r_cl in clause_pairs_self:
                if _CLAUSE_HEAD_KILL_VERB_RE.search(m_cl) and re.search(pat_s, r_cl):
                    self.record_security_event("destructive_cmd_blocked", command, reason_s)
                    return f"[GUARD DANGEROUS COMMAND BLOCKED]: {reason_s}"
        return None

    def check_python_code_safety(self, code: str, cwd: Optional[str] = None) -> Optional[str]:
        code_no_comments = strip_python_comments_tokenize(code)
        pipelock_err = self.check_command_pipelock(code_no_comments, cwd=cwd, is_python_code=True)
        if pipelock_err:
            return pipelock_err
        if not self._effective_block_destructive_commands():
            if re.search(
                r"(?i)\b(?:Stop-Process|taskkill)\b[^\n]*(?:launcher\.py|server\.py|cosmos_mcp|cloudflared|ngrok)",
                code_no_comments,
            ):
                kill_mcp_reason = "Terminating MCP daemon or active tunnel processes is blocked."
                self.record_security_event("python_code_blocked", code_no_comments[:240], kill_mcp_reason)
                return f"[GUARD PYTHON SAFETY]: {kill_mcp_reason}"
            return None
        del_reason = "Direct permanent file deletion in Python (rmtree / os.remove / unlink) is blocked; use trash_file instead."
        kill_reason = "Terminating host browsers, IDEs, or MCP daemon processes is blocked."
        try:
            tree = ast.parse(code_no_comments)
        except SyntaxError:
            tree = None

        if tree is not None:
            danger_del_attrs = {"rmtree", "remove", "unlink", "rmdir", "removedirs"}
            os_aliases: Set[str] = {"os", "nt", "posix"}
            for nd_imp in ast.walk(tree):
                if isinstance(nd_imp, ast.Import):
                    for alias in nd_imp.names:
                        if alias.name in ("os", "nt", "posix") and alias.asname:
                            os_aliases.add(alias.asname)
            for nd in ast.walk(tree):
                if isinstance(nd, ast.ImportFrom) and (nd.module or "") in ("os", "nt", "posix", "shutil", "pathlib"):
                    for alias in nd.names:
                        if alias.name in danger_del_attrs:
                            self.record_security_event("python_code_blocked", code_no_comments[:240], del_reason)
                            return f"[GUARD PYTHON SAFETY]: {del_reason}"
                elif isinstance(nd, ast.Call):
                    fn = nd.func
                    if isinstance(fn, ast.Attribute) and fn.attr in danger_del_attrs:
                        if fn.attr in ("remove", "removedirs"):
                            is_os_receiver = (
                                (isinstance(fn.value, ast.Name) and fn.value.id in os_aliases)
                                or (
                                    isinstance(fn.value, ast.Call)
                                    and isinstance(fn.value.func, ast.Name)
                                    and fn.value.func.id == "__import__"
                                    and bool(fn.value.args)
                                    and isinstance(fn.value.args[0], ast.Constant)
                                    and str(fn.value.args[0].value) in ("os", "nt", "posix")
                                )
                            )
                            if not is_os_receiver:
                                continue
                        self.record_security_event("python_code_blocked", code_no_comments[:240], del_reason)
                        return f"[GUARD PYTHON SAFETY]: {del_reason}"
                    elif isinstance(fn, ast.Name) and fn.id == "getattr" and len(nd.args) >= 2:
                        arg1 = nd.args[1]
                        if isinstance(arg1, ast.Constant) and str(arg1.value) in danger_del_attrs:
                            attr_s = str(arg1.value)
                            if attr_s in ("remove", "removedirs"):
                                arg0 = nd.args[0]
                                is_os_arg0 = isinstance(arg0, ast.Name) and arg0.id in os_aliases
                                if not is_os_arg0:
                                    continue
                            self.record_security_event("python_code_blocked", code_no_comments[:240], del_reason)
                            return f"[GUARD PYTHON SAFETY]: {del_reason}"
        else:
            if re.search(r"(?i)\b(?:shutil\.rmtree|os\.remove|os\.unlink|os\.rmdir|os\.removedirs|\.unlink\s*\(|\.rmdir\s*\()\b", code_no_comments):
                self.record_security_event("python_code_blocked", code_no_comments[:240], del_reason)
                return f"[GUARD PYTHON SAFETY]: {del_reason}"
            if re.search(
                r"(?i)\b(?:Stop-Process|taskkill)\b[^\n]*(?:launcher\.py|server\.py|cosmos_mcp|cloudflared|ngrok|chrome|explorer)",
                code_no_comments,
            ):
                self.record_security_event("python_code_blocked", code_no_comments[:240], kill_reason)
                return f"[GUARD PYTHON SAFETY]: {kill_reason}"
        return None

    def redact_sensitive_output(self, text: str) -> str:
        if not text:
            return text
        out = text
        for regex, repl in MCP_SELF_REDACT_PATTERNS:
            out = regex.sub(repl, out)
        should_redact_project = (
            bool(getattr(self.policy, "redact_project_secrets", False))
            or bool(getattr(self, "redact_project_secrets", False))
            or self.tier == "L1"
            or bool(_READONLY_CALL_CTX.get())
        )
        if should_redact_project:
            for regex, repl in PROJECT_SECRET_REDACT_PATTERNS:
                out = regex.sub(repl, out)
        for sec in self._extra_secret_literals:
            if sec in out:
                out = out.replace(sec, "[REDACTED_SECRET_BY_GUARD]")
        return out


# --- Default Module-Level Singleton & Convenience Wrappers ---

_DEFAULT_RAW_ROOTS = os.environ.get("COSMOS_WORKSPACE_ROOTS") or os.environ.get("LOCALPC_WORKSPACE_ROOT") or ""
_DEFAULT_RESTRICT = os.environ.get("LOCALPC_RESTRICT_WORKSPACE", "1") != "0"
_DEFAULT_TIER = os.environ.get("LOCALPC_PERMISSION_TIER", "L3")

DEFAULT_GUARD = WorkspaceGuard(
    _DEFAULT_RAW_ROOTS if _DEFAULT_RAW_ROOTS else None,
    restrict_to_workspace=_DEFAULT_RESTRICT,
    tier=_DEFAULT_TIER,
)


def set_workspace_policy(
    workspace_roots: Union[str, Path, Sequence[Union[str, Path]], None],
    restrict_to_workspace: bool = True,
    tier_key: str = "",
    *,
    readonly_workspace_roots: Union[str, Path, Sequence[Union[str, Path]], None] = None,
    allow_host_global_skills: Optional[bool] = None,
    protect_host_credentials: Optional[bool] = None,
    protect_dotenv_files: Optional[bool] = None,
    block_destructive_commands: Optional[bool] = None,
    state_root: Optional[Union[str, Path]] = None,
    product_root: Optional[Union[str, Path]] = None,
    extra_access_gate: Optional[Callable[..., Optional[str]]] = None,
) -> None:
    DEFAULT_GUARD.set_workspace_policy(
        workspace_roots,
        restrict_to_workspace=restrict_to_workspace,
        tier_key=tier_key,
        readonly_workspace_roots=readonly_workspace_roots,
        allow_host_global_skills=allow_host_global_skills,
        protect_host_credentials=protect_host_credentials,
        protect_dotenv_files=protect_dotenv_files,
        block_destructive_commands=block_destructive_commands,
        state_root=state_root,
        product_root=product_root,
        extra_access_gate=extra_access_gate,
    )


def get_workspace_policy() -> Dict[str, Any]:
    return DEFAULT_GUARD.get_workspace_policy()


def set_extra_access_gate(gate_fn: Optional[Callable[..., Optional[str]]]) -> None:
    DEFAULT_GUARD.set_extra_access_gate(gate_fn)


def normalize_target_path(path_str: Union[str, Path], base_dir: Optional[Union[str, Path]] = None) -> Path:
    return DEFAULT_GUARD.normalize_target_path(path_str, base_dir=base_dir)


def record_security_event(event_type: str, target: str, reason: str) -> None:
    DEFAULT_GUARD.record_security_event(event_type, target, reason)


def check_path_access(
    path_str: Union[str, Path],
    mode: str = "read",
    *,
    tool_name: str = "",
    extra_args: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    return DEFAULT_GUARD.check_path_access(path_str, mode=mode, tool_name=tool_name, extra_args=extra_args)


def check_command_pipelock(
    command: str,
    cwd: Optional[str] = None,
    is_python_code: bool = False,
    *,
    tool_name: str = "",
    extra_args: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    return DEFAULT_GUARD.check_command_pipelock(
        command,
        cwd=cwd,
        is_python_code=is_python_code,
        tool_name=tool_name,
        extra_args=extra_args,
    )


def check_destructive_command(command: str, cwd: Optional[str] = None) -> Optional[str]:
    return DEFAULT_GUARD.check_destructive_command(command, cwd=cwd)


def check_python_code_safety(code: str, cwd: Optional[str] = None) -> Optional[str]:
    return DEFAULT_GUARD.check_python_code_safety(code, cwd=cwd)


def redact_sensitive_output(text: str) -> str:
    return DEFAULT_GUARD.redact_sensitive_output(text)
