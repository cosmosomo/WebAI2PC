"""Build `dist/Cosmos-MCP-v<version>.zip` and run repo-wide + archive byte-level release hygiene gates (`--check`)."""
from __future__ import annotations

import argparse
import getpass
import hashlib
import io
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VERSION = "1.2.1"
QUICKSTART_TXT_NAME = "01_新手三步上手.txt"

EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {
        "build",
        "dist",
        "__pycache__",
        ".git",
        ".worktrees",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".undo_history",
        ".venv",
        "venv",
        "wheels",
        "python-embed",
        ".benchmarks",
    }
)
EXCLUDED_SUFFIXES: Tuple[str, ...] = (".pyc", ".pyo", ".pyd", ".bak")

REQUIRED_ROOT_FILES: Tuple[str, ...] = (
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "CONTRIBUTING.md",
    ".env.example",
    ".gitattributes",
    "pyproject.toml",
    "README.md",
    "README_EN.md",
    "AGENTS.md",
    "PRIVACY.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "manifest.json",
    "server.json",
)
# Internal design drafts under `.interface-design/` are intentionally excluded from public release bundles.
REQUIRED_DESIGN_FILES: Tuple[str, ...] = ()
REQUIRED_DOC_FILES: Tuple[str, ...] = (
    "docs/01_网页版Gemini与手机远程连接教程.md",
    "docs/02_网页版ChatGPT工作区与个人只读接入教程.md",
    "docs/03_Cosmos_Studio面板与扩展包指南.md",
    "docs/04_三大连接通道选型与网络排障手册.md",
    "docs/05_多智能体并行子任务与实战工作流教程.md",
    "docs/AI_SETUP_GUIDE.md",
    "host_skills/SKILL.md",
    "host_skills/webai2pc-setup-tutorial/SKILL.md",
)
REQUIRED_STUDIO_STATIC_FILES: Tuple[str, ...] = (
    "src/cosmos_mcp/studio/static/index.html",
    "src/cosmos_mcp/studio/static/studio.css",
    "src/cosmos_mcp/studio/static/studio.js",
    "src/cosmos_mcp/studio/static/brand-packs.js",
    "src/cosmos_mcp/studio/static/themes.css",
    "src/cosmos_mcp/studio/static/tutorials.html",
    "src/cosmos_mcp/studio/static/tutorials.js",
    "src/cosmos_mcp/studio/static/favicon.svg",
    "src/cosmos_mcp/studio/static/brand/webai2pc-icon-v2-dark.svg",
    "src/cosmos_mcp/studio/static/brand/webai2pc-icon-v2-light.svg",
    "src/cosmos_mcp/studio/static/brand/webai2pc-logo-v2-dark.svg",
    "src/cosmos_mcp/studio/static/brand/webai2pc-logo-v2-light.svg",
    "src/cosmos_mcp/studio/static/brand/webai2pc-mark-v2-dark.svg",
    "src/cosmos_mcp/studio/static/brand/webai2pc-mark-v2-light.svg",
)
REQUIRED_SANDBOX_FILES: Tuple[str, ...] = (
    "sandbox/Dockerfile",
    "sandbox/docker-compose.yml",
    "sandbox/CosmosMCP_WindowsSandbox.wsb",
)
REQUIRED_ASSET_FILES: Tuple[str, ...] = (
    "assets/readme/cases-trio-banner-dark.png",
)
GENERATED_LAUNCHERS: Tuple[str, str] = (
    "一键启动_Cosmos_MCP.bat",
    "start_cosmos_mcp.sh",
)
REQUIRED_EMBED_PACKAGES: Tuple[str, ...] = (
    "mcp",
    "uvicorn",
    "starlette",
    "pydantic",
    "cryptography",
    "websockets",
    "PIL",
    "openpyxl",
    "docx",
    "pptx",
    "pypdf",
)

_EMBED_REDUNDANT_SP_PREFIXES: Tuple[str, ...] = (
    "pywin32",
)
_EMBED_REDUNDANT_SP_EXACT: frozenset[str] = frozenset(
    {
        "bin",
        ".lock",
        "cosmos_mcp_src.pth",
        "adodbapi",
        "pythonwin",
        "isapi",
        "win32",
        "win32com",
        "win32comext",
        "pythoncom.py",
        "pywin32.chm",
    }
)

# Constructed dynamically so this script file itself contains zero literal forbidden tokens
_OFFLINE_GOPROXY_RE = re.compile(r"GOPROXY\s*=\s*['\"]?" + "off" + r"\b", re.IGNORECASE)
_OFFLINE_CARGO_RE = re.compile(r"CARGO_NET_OFFLINE\s*=\s*['\"]?" + "true" + r"\b", re.IGNORECASE)
_ENV_ASSIGN_OFFLINE_RE = re.compile(
    r"(?:os\.environ|env)\s*\[\s*['\"](?:GOPROXY|CARGO_NET_OFFLINE)['\"]\s*\]\s*=",
    re.IGNORECASE,
)
_BRACKET_AT_RE = re.compile(r"\[" + "at" + r"\]", re.IGNORECASE)
_EMAIL_ADDR_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]{1,64})"
    + chr(64)
    + r"([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24})\b"
)
_ALLOWED_DOC_EMAIL_DOMAINS: frozenset[str] = frozenset(
    {
        "example.com",
        "example.org",
        "example.net",
        "yourdomain.com",
        "yourdomain.org",
        "dpdns.org",
        "cosmos-mcp.local",
        "localhost.localdomain",
    }
)
_ALLOWED_TEST_SYNTHETIC_EMAILS: frozenset[str] = frozenset(
    {
        "zhang_lab" + chr(64) + "gmail.com",
        "user.tag+1" + chr(64) + "google.com",
        "support" + chr(64) + "cosmos.io",
    }
)
_INTERNAL_CODENAME_RE = re.compile(
    r"\b(?:t5_champion_12|t2_unix_lean_7|t3_serena_symbol_14|t4_agy_hybrid_10|t1_baseline_19|HD-\d+|MCP-FB-v?\d+|"
    + "web"
    + r"[-_]?taint)\b",
    re.IGNORECASE,
)
_PRIVATE_CONDA_PATH_RE = re.compile(
    r"[A-Z]:(?:\\+|/+)(?:" + "Anaconda" + r"\d*|" + "Miniconda" + r"\d*)(?:\\|/|['\"\s]|$)",
    re.IGNORECASE,
)
_PRIVATE_DEV_DRIVE_RE = re.compile(
    r"[C-Z]:(?:\\+|/+)" + "program" + r"[0-9_]*(?:\\+|/+|['\"]|$)",
    re.IGNORECASE,
)
_PRIVATE_PAD_PACK_RE = re.compile(
    r"['\"]" + "pad" + r"['\"]\s*:\s*['\"(\[{]|\b" + "pad" + r"_(?:adb|fleet|gui_action|reverse_engineer)\b"
)

# Constructed dynamically so this script file itself contains zero literal forbidden tokens
_CREDENTIAL_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    (
        "github_token",
        re.compile(
            r"\b(?:"
            + "gh" + "p|" + "gh" + "o|" + "gh" + "u|" + "gh" + "s|" + "gh" + "r"
            + r")_[A-Za-z0-9]{20,}\b|\b"
            + "github_" + "pat_"
            + r"[A-Za-z0-9_]{20,}\b"
        ),
    ),
    (
        "api_sk_token",
        re.compile(r"\b" + "sk" + r"-(?:proj-|ant-|live-|test-)?[A-Za-z0-9\-_]{20,}\b"),
    ),
    (
        "google_api_key",
        re.compile(r"\b" + "AI" + "za" + r"[0-9A-Za-z\-_]{30,}\b"),
    ),
    (
        "slack_token",
        re.compile(r"\b" + "xox" + r"[baprs]-[0-9A-Za-z\-]{10,}\b"),
    ),
    (
        "cf_tunnel_token",
        re.compile(r"\b" + "eyJ" + "hIjoi" + r"[A-Za-z0-9+/=_-]{20,}"),
    ),
    (
        "jwt_token",
        re.compile(r"\b" + "eyJ" + r"[A-Za-z0-9_-]{10,}\." + "eyJ" + r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    (
        "private_key_block",
        re.compile(r"-----" + "BEGIN " + r"[A-Z0-9 ]*" + "PRIVATE KEY" + r"-----"),
    ),
    (
        "im_webhook_url",
        re.compile(
            r"https?://(?:"
            + "hooks\\.slack\\.com|"
            + "discord\\.com/api/webhooks|"
            + "oapi\\.dingtalk\\.com|"
            + "qyapi\\.weixin\\.qq\\.com|"
            + "open\\.feishu\\.cn/open-apis/bot"
            + r")[^\s'\"`]+"
        ),
    ),
)
_USER_HOME_PATH_RE = re.compile(
    r"(?:" + r"[A-Z]:(?:\\+|/+)" + "Users" + r"(?:\\+|/+)|/" + "Users" + r"/)([A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)
_ALLOWED_PLACEHOLDER_USERNAMES: frozenset[str] = frozenset(
    {"alice", "user", "yourname", "username", "public", "default", "shared"}
)
_WINDOWS_AUTO_HOSTNAME_RE = re.compile(
    r"\b(?:" + "DESK" + "TOP|" + "LAP" + "TOP" + r")-(?=[A-Z0-9]{5,}\b)(?=[A-Z0-9]*\d)[A-Z0-9]{5,}\b",
    re.IGNORECASE,
)
_INTERNAL_AGENT_LEAK_RE = re.compile(
    r"\b" + "HUB-" + "EXP-" + r"[A-Z0-9]+\b"
    + r"|\b" + "custom_" + "mcp__" + r"[0-9a-f]{16,}\b"
    + r"|" + "_work" + "trees"
    + r"|" + r"\.run" + "time" + r"[/\\]",
    re.IGNORECASE,
)
_FORBIDDEN_TRACKED_DIRS: Tuple[str, ...] = (
    ".interface-design/",
    ".audit_screenshots/",
    ".benchmarks/",
)
_ALLOWED_PNG_TEXT_KEYS: frozenset[str] = frozenset()


def scan_text_credential_leaks(txt: str) -> List[str]:
    """Return high-risk credential pattern names matched in `txt` (excluding obvious placeholder strings)."""
    hits: List[str] = []
    for name, rx in _CREDENTIAL_PATTERNS:
        for m in rx.finditer(txt):
            val_low = m.group(0).lower()
            if name == "api_sk_token" and any(p in val_low for p in ("xxxx", "example", "placeholder", "your_")):
                continue
            if name not in hits:
                hits.append(name)
            break
    return hits


def scan_text_cross_machine_and_internal_leaks(txt: str) -> List[str]:
    """Return cross-machine user path or internal agent/worktree leak tags matched in `txt`."""
    hits: List[str] = []
    for m in _USER_HOME_PATH_RE.finditer(txt):
        uname = m.group(1).strip().lower()
        if uname and uname not in _ALLOWED_PLACEHOLDER_USERNAMES:
            tag = f"user_home_path:{m.group(1)[:2]}****"
            if tag not in hits:
                hits.append(tag)
    if _WINDOWS_AUTO_HOSTNAME_RE.search(txt):
        hits.append("windows_auto_hostname")
    if _INTERNAL_AGENT_LEAK_RE.search(txt):
        hits.append("internal_agent_or_worktree_ref")
    return hits


def scan_image_bytes_integrity_and_metadata(data: bytes, *, rel_path: str = "") -> List[str]:
    """Verify PNG/JPEG decodability (`verify` + full `load`) and reject non-whitelisted metadata chunks."""
    import struct
    from PIL import Image, ImageFile

    issues: List[str] = []
    low = rel_path.lower()
    if low.endswith(".png") or data.startswith(b"\x89PNG\r\n\x1a\n"):
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            return [f"Invalid PNG header in `{rel_path}`"]
        pos = 8
        has_iend = False
        while pos + 8 <= len(data):
            clen = struct.unpack(">I", data[pos : pos + 4])[0]
            ctype = data[pos + 4 : pos + 8].decode("latin1", errors="replace")
            cdata = data[pos + 8 : pos + 8 + clen]
            if pos + 12 + clen > len(data):
                issues.append(f"Truncated PNG chunk `{ctype}` in `{rel_path}`")
                break
            if ctype == "IEND":
                has_iend = True
            elif ctype in ("tEXt", "iTXt", "zTXt", "eXIf"):
                key = cdata.split(b"\x00", 1)[0].decode("latin1", errors="replace").strip() if ctype != "eXIf" else "eXIf"
                if key.lower() not in _ALLOWED_PNG_TEXT_KEYS:
                    issues.append(f"Forbidden PNG metadata chunk `{ctype}` (`{key}`) in `{rel_path}`")
            pos += 12 + clen
        if not has_iend:
            issues.append(f"Missing PNG IEND chunk in `{rel_path}`")

    prev_trunc = ImageFile.LOAD_TRUNCATED_IMAGES
    try:
        ImageFile.LOAD_TRUNCATED_IMAGES = False
        with Image.open(io.BytesIO(data)) as im:
            im.verify()
        with Image.open(io.BytesIO(data)) as im2:
            im2.load()
            if low.endswith((".jpg", ".jpeg")):
                exif = im2.getexif()
                if exif and len(exif) > 0:
                    issues.append(f"Forbidden JPEG EXIF metadata ({len(exif)} tag(s)) in `{rel_path}`")
    except Exception as exc:
        issues.append(f"Corrupted/unreadable image `{rel_path}`: {exc}")
    finally:
        ImageFile.LOAD_TRUNCATED_IMAGES = prev_trunc
    return issues


def scan_git_diff_range(repo_root: Path, diff_range: str) -> List[str]:
    """Scan added lines in `git diff --unified=0 <diff_range>` for secrets, PII paths, and internal IDs."""
    errors: List[str] = []
    res = subprocess.run(
        ["git", "diff", "--unified=0", diff_range],
        cwd=repo_root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        creationflags=0x08000000 if os.name == "nt" else 0,
    )
    if res.returncode != 0:
        return [f"git diff `{diff_range}` failed: {res.stderr.strip()[:200]}"]
    cur_file = ""
    cur_line = 0
    for raw_ln in res.stdout.splitlines():
        if raw_ln.startswith("+++ b/"):
            cur_file = raw_ln[6:].strip()
            continue
        if raw_ln.startswith("@@ "):
            m_ln = re.search(r"\+(\d+)", raw_ln)
            if m_ln:
                cur_line = int(m_ln.group(1))
            continue
        if raw_ln.startswith("+") and not raw_ln.startswith("+++"):
            added = raw_ln[1:]
            is_test = cur_file.startswith("tests/")
            if not is_test:
                for cred_tag in scan_text_credential_leaks(added):
                    errors.append(f"Diff credential leak (`{cred_tag}`) in `{cur_file}:{cur_line}`")
            for leak_tag in scan_text_cross_machine_and_internal_leaks(added):
                errors.append(f"Diff path/internal leak (`{leak_tag}`) in `{cur_file}:{cur_line}`")
            for em in scan_text_email_leaks(added, is_test_file=is_test):
                errors.append(f"Diff unredacted email `{em}` in `{cur_file}:{cur_line}`")
            cur_line += 1
    return errors

_SENSITIVE_TOKEN_SALT: bytes = b"cosmos-mcp-release-gate-v1:"
# Never commit hardcoded hashes of short personal usernames/hostnames to a public repo
# (public salt + short identifier is offline dictionary-guessable). Local dev machines
# supply extra tokens via gitignored `.env` (`COSMOS_EXTRA_FORBIDDEN_TOKENS=...`).
_FORBIDDEN_IDENTIFIER_SHA256: frozenset[str] = frozenset()
_ASCII_IDENT_BYTES_RE = re.compile(
    rb"(?:[A-Za-z0-9]{6,64}(?:-[A-Za-z0-9]{2,64})*|[A-Za-z0-9]{2,5}(?:-[A-Za-z0-9]{2,64})+)"
)
_UTF16LE_IDENT_BYTES_RE = re.compile(rb"(?:[A-Za-z0-9-]\x00){6,64}")
_TEXT_IDENT_TOKEN_RE = re.compile(
    r"(?:[A-Za-z0-9]{6,64}(?:-[A-Za-z0-9]{2,64})*|[A-Za-z0-9]{2,5}(?:-[A-Za-z0-9]{2,64})+)"
)
_SAFE_IDENT_BYTES_CACHE: Set[bytes] = set()


def hash_sensitive_identifier(token: str, *, salt: bytes = _SENSITIVE_TOKEN_SALT) -> str:
    """Compute salted lowercase SHA-256 digest for identifier-level leak gating without storing plaintext."""
    return hashlib.sha256(salt + token.strip().lower().encode("utf-8")).hexdigest()


def _expand_identifier_candidates(raw_lower: bytes) -> List[bytes]:
    cleaned = raw_lower.strip(b"-")
    if not cleaned:
        return []
    out: List[bytes] = []
    if 6 <= len(cleaned) <= 64:
        out.append(cleaned)
    if b"-" in cleaned:
        parts = [p for p in cleaned.split(b"-") if p]
        for part in parts:
            if 6 <= len(part) <= 64:
                out.append(part)
        if len(parts) >= 3:
            for idx in range(len(parts) - 1):
                pair = parts[idx] + b"-" + parts[idx + 1]
                if 6 <= len(pair) <= 64:
                    out.append(pair)
    return out


def scan_bytes_forbidden_identifier_hashes(
    data: bytes,
    forbidden_hashes: frozenset[str] = _FORBIDDEN_IDENTIFIER_SHA256,
) -> List[str]:
    """Scan ASCII/UTF-8 and UTF-16LE identifier tokens in raw bytes against salted SHA-256 digests."""
    if not data or not forbidden_hashes:
        return []
    use_default_cache = forbidden_hashes is _FORBIDDEN_IDENTIFIER_SHA256
    if use_default_cache and len(_SAFE_IDENT_BYTES_CACHE) > 4096:
        _SAFE_IDENT_BYTES_CACHE.clear()
    candidates: Set[bytes] = set()
    for m in _ASCII_IDENT_BYTES_RE.finditer(data):
        candidates.update(_expand_identifier_candidates(m.group(0).lower()))
    for m in _UTF16LE_IDENT_BYTES_RE.finditer(data):
        candidates.update(_expand_identifier_candidates(m.group(0)[::2].lower()))
    matched: Set[str] = set()
    for tok in candidates:
        if use_default_cache and tok in _SAFE_IDENT_BYTES_CACHE:
            continue
        digest = hashlib.sha256(_SENSITIVE_TOKEN_SALT + tok).hexdigest()
        if digest in forbidden_hashes:
            matched.add(f"sha256:{digest[:12]}")
        elif use_default_cache and len(_SAFE_IDENT_BYTES_CACHE) < 4096:
            _SAFE_IDENT_BYTES_CACHE.add(tok)
    return sorted(matched)


def scan_text_forbidden_identifier_hashes(
    txt: str,
    forbidden_hashes: frozenset[str] = _FORBIDDEN_IDENTIFIER_SHA256,
) -> List[str]:
    """Scan text identifier tokens against salted SHA-256 digests."""
    if not txt or not forbidden_hashes:
        return []
    candidates: Set[bytes] = set()
    for m in _TEXT_IDENT_TOKEN_RE.finditer(txt):
        candidates.update(_expand_identifier_candidates(m.group(0).lower().encode("utf-8")))
    matched: Set[str] = set()
    for tok in candidates:
        digest = hashlib.sha256(_SENSITIVE_TOKEN_SALT + tok).hexdigest()
        if digest in forbidden_hashes:
            matched.add(f"sha256:{digest[:12]}")
    return sorted(matched)


def _build_forbidden_archive_tokens(
    runtime_hostname: Optional[str] = None,
    runtime_username: Optional[str] = None,
    generic_names: Optional[Set[str]] = None,
) -> Tuple[str, ...]:
    eff_generic = (
        {g.lower() for g in generic_names}
        if generic_names is not None
        else {"localhost", "runner", "root", "user", "admin", "ubuntu", "cosmos", "pc", "test"}
    )
    eff_host = (socket.gethostname() or "").strip() if runtime_hostname is None else runtime_hostname.strip()
    eff_user = (getpass.getuser() or "").strip() if runtime_username is None else runtime_username.strip()
    tokens: List[str] = [
        ":\\" + "Anaconda",
        ":/" + "Anaconda",
        ":\\" + "Miniconda",
        ":/" + "Miniconda",
        "\\" + ".py" + "env",
        "/." + "py" + "env/",
        "py" + "env-win",
    ]
    extra_parts: List[str] = [os.environ.get("COSMOS_EXTRA_FORBIDDEN_TOKENS", "")]
    dotenv_path = REPO_ROOT / ".env"
    if dotenv_path.is_file():
        for raw_ln in dotenv_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            ln_s = raw_ln.strip()
            if ln_s.startswith("COSMOS_EXTRA_FORBIDDEN_TOKENS="):
                extra_parts.append(ln_s.split("=", 1)[1].strip().strip("'").strip('"'))
    for extra_raw in extra_parts:
        for extra in extra_raw.split(","):
            tok = extra.strip()
            if len(tok) >= 4 and tok.lower() not in eff_generic and tok not in tokens:
                tokens.append(tok)
    if eff_host and len(eff_host) >= 4 and eff_host.lower() not in eff_generic:
        if eff_host not in tokens:
            tokens.append(eff_host)
    if eff_user and len(eff_user) >= 4 and eff_user.lower() not in eff_generic:
        if eff_user not in tokens:
            tokens.append(eff_user)
    return tuple(tokens)


def scan_archive_entry_sensitive_bytes(
    data: bytes,
    forbidden_tokens: Sequence[str],
    *,
    arc_name: str = "",
) -> List[str]:
    """Scan raw archive entry bytes (including `.exe`/`.dll`/`.pyd` binaries) across ASCII/UTF-8 and UTF-16LE."""
    if not data:
        return []
    low_arc = (arc_name or "").lower()
    eff_tokens = list(forbidden_tokens)
    if (
        not low_arc
        or low_arc.startswith(("python-embed/", "wheels/"))
        or low_arc.endswith((".exe", ".dll", ".pyd", ".so", ".dylib", ".whl"))
    ):
        bare_pyenv = "." + "py" + "env"
        if bare_pyenv not in eff_tokens:
            eff_tokens.append(bare_pyenv)
    low_ascii = data.lower()
    matched: List[str] = []
    for tok in eff_tokens:
        t_low = tok.lower()
        pat_utf8 = t_low.encode("utf-8")
        pat_u16 = t_low.encode("utf-16le")
        if pat_utf8 in low_ascii:
            matched.append(tok)
            continue
        # Case-insensitive UTF-16LE scan for ASCII tokens embedded in Windows PE resources
        if len(pat_u16) >= 6 and tok.isascii():
            # Fold ASCII uppercase A-Z (0x41..0x5A) followed by 0x00 if needed via regex on bytes
            u16_re = b"".join(
                (
                    b"[" + bytes([ ord(ch.lower()), ord(ch.upper()) ]) + b"]\\x00"
                    if ch.isalpha()
                    else re.escape(bytes([ord(ch)])) + b"\\x00"
                )
                for ch in tok
            )
            if re.search(u16_re, data):
                matched.append(tok)
    covered_prefixes = {f"sha256:{hash_sensitive_identifier(tok)[:12]}" for tok in matched}
    for h_tag in scan_bytes_forbidden_identifier_hashes(data):
        if h_tag not in covered_prefixes:
            matched.append(h_tag)
    return matched


def render_quickstart_txt(version: str) -> bytes:
    """Render beginner-friendly CRLF plain-text `01_新手三步上手.txt` at archive root."""
    lines = [
        f"====================================================================",
        f" Cosmos MCP v{version} — Windows 新手三步上手说明",
        f"====================================================================",
        "",
        "第 ① 步：先解压压缩包",
        "  请右键本压缩包选择「全部解压缩」到本地任意文件夹（不要直接在压缩软件预览窗里双击）。",
        "",
        "第 ② 步：双击启动本地控制台",
        "  进入解压后的文件夹，双击运行「一键启动_Cosmos_MCP.bat」",
        "  （macOS / Linux 用户请在终端运行 ./start_cosmos_mcp.sh）。",
        "  服务将在后台静默拉起，并自动在浏览器打开本地控制台 http://127.0.0.1:8096/ 。",
        "",
        "第 ③ 步：复制网址粘贴到网页版 Gemini 或 ChatGPT",
        "  复制本地控制台里显示的 https://.../mcp 加密连接网址，粘贴到：",
        "  - 网页版 Google Gemini（勿直接浏览器打开 /mcp，请访问 https://gemini.google.com/customize/connectors 点 + Custom 粘贴到 MCP Server URL）",
        "  - 网页版 ChatGPT：",
        "    · 首次添加插件：网关就绪后首选点「复制地址并打开 ChatGPT 插件页」，在已登录本机浏览器",
        "      打开 https://chatgpt.com/plugins 点 ＋ -> 添加自定义 MCP 服务器，名称填 WebAI2PC，",
        "      粘贴 /mcp（个人只读填 /mcp/readonly），授权页点「本机一键允许连接」并点 Install 安装",
        "      （遇到连接或 403 权限问题点旁侧「复制给 ChatGPT 接入 / 排障」）。",
        "    · 日常使用分工：装好后切回 Chat 模式发 @WebAI2PC 改代码跑脚本（快且不扣 Work/Codex 额度），",
        "      跨应用长程交付与定时任务用 Work 模式发 @WebAI2PC。",
        "",
        "连接通道前置依赖与国内代理速查：",
        "  · 通道 1 默认 *.srv.us：仅用系统自带 ssh（出站 22 端口），免注册、重启网址不变，",
        "    国内家庭宽带通常免代理直连；22 端口受阻时 4 秒自动回退 *.trycloudflare.com",
        "    （需自动下载 cloudflared，国内慢可开代理或设 COSMOS_CLOUDFLARED_MIRROR，重启换域名）。",
        "  · 通道 2 Cloudflare 专属固定网关（workers_dev）：纯 Python 零外部二进制依赖，",
        "    免费层每日 100,000 次请求上限（超限返 1027）与 125 秒边缘读超时；",
        "    注意国内 *.workers.dev 存在全量 DNS 污染，未绑自定义域名时运行期间必须保持",
        "    系统 HTTP/HTTPS 代理常开且规则覆盖 *.workers.dev（NO_PROXY 保留 127.0.0.1,localhost,::1），",
        "    绑定同账号自定义域名（Active Zone）后可免代理直连。",
        "  · 通道 3 自有云服务器 24h 主站：开放 80/443 的 Linux 服务器 + 本机 ssh，零配额与",
        "    125 秒超时限制，国内或港新服务器全程免代理直连（Named Tunnel 子项需 cloudflared",
        "    及 Zero Trust 指向 http://127.0.0.1:8096 转发并关闭 Bot Fight Mode）。",
        "",
        "更多图文指引请打开控制面板右上角「实战教程」，或参阅 docs/ 目录下的分步说明。",
        "",
        "想让 AI 手把手教你配置或升级 Cloudflare 固定网址？",
        "  直接复制 README.md 里的『AI 陪配提示词』发给网页版 Gemini / ChatGPT，",
        "  或连上 @Cosmos 后直接说：@Cosmos 帮我打开设置页教我怎么配 Cloudflare",
        "",
    ]
    return "\r\n".join(lines).encode("utf-8")


class _Utf8ZipInfo(zipfile.ZipInfo):
    """Ensure UTF-8 filename flag (bit 11 = 0x800) is preserved across Python 3.9..3.14."""

    def _encodeFilenameFlags(self) -> Tuple[bytes, int]:  # type: ignore[override]
        return self.filename.encode("utf-8"), self.flag_bits | 0x800


def read_project_version(repo_root: Path = REPO_ROOT) -> str:
    pyproject = repo_root / "pyproject.toml"
    if pyproject.is_file():
        txt = pyproject.read_text(encoding="utf-8", errors="replace")
        m = re.search(r'^version\s*=\s*"([^"]+)"', txt, flags=re.MULTILINE)
        if m:
            return m.group(1).strip()
    return DEFAULT_VERSION


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().lower()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().lower()


def _is_excluded_rel_parts(parts: Sequence[str]) -> bool:
    for idx, part in enumerate(parts):
        low = part.lower()
        if part in EXCLUDED_DIR_NAMES or low in EXCLUDED_DIR_NAMES:
            return True
        if low == ".interface-design":
            return True
        if low.endswith(".egg-info"):
            return True
        if idx == len(parts) - 1:
            if low == ".env" or (
                low.startswith(".env.")
                and low not in {".env.example", ".env.sample", ".env.template"}
            ):
                return True
            if any(low.endswith(sfx) for sfx in EXCLUDED_SUFFIXES):
                return True
    return False


def iter_clean_tree_files(base_dir: Path, rel_prefix: str, repo_root: Path = REPO_ROOT) -> List[Tuple[str, Path]]:
    """Return sorted `(posix_arcname, abs_path)` entries under `base_dir`, strictly excluding build/cache artifacts."""
    out: List[Tuple[str, Path]] = []
    if not base_dir.is_dir():
        return out
    for root, dirs, files in os.walk(base_dir):
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in EXCLUDED_DIR_NAMES
            and d.lower() not in EXCLUDED_DIR_NAMES
            and not d.lower().endswith(".egg-info")
        )
        for fname in sorted(files):
            fp = Path(root) / fname
            rel_to_repo = fp.relative_to(repo_root)
            if _is_excluded_rel_parts(rel_to_repo.parts):
                continue
            arc = rel_to_repo.as_posix()
            if rel_prefix and not arc.startswith(rel_prefix):
                continue
            out.append((arc, fp))
    out.sort(key=lambda item: item[0])
    return out


def collect_release_manifest(repo_root: Path = REPO_ROOT) -> List[Tuple[str, Path]]:
    entries: List[Tuple[str, Path]] = []
    for rf in REQUIRED_ROOT_FILES:
        p = repo_root / rf
        if not p.is_file():
            raise FileNotFoundError(f"Missing required release file: {rf}")
        entries.append((rf, p))

    entries.extend(iter_clean_tree_files(repo_root / "src" / "cosmos_mcp", "src/cosmos_mcp/", repo_root=repo_root))
    entries.extend(iter_clean_tree_files(repo_root / "docs", "docs/", repo_root=repo_root))
    entries.extend(iter_clean_tree_files(repo_root / "host_skills", "host_skills/", repo_root=repo_root))
    entries.extend(iter_clean_tree_files(repo_root / "sandbox", "sandbox/", repo_root=repo_root))
    entries.extend(iter_clean_tree_files(repo_root / "assets", "assets/", repo_root=repo_root))

    github_ci = repo_root / ".github" / "workflows" / "ci.yml"
    if github_ci.is_file():
        entries.append((".github/workflows/ci.yml", github_ci))

    script_self = repo_root / "scripts" / "build_release.py"
    if script_self.is_file():
        entries.append(("scripts/build_release.py", script_self))

    seen: Set[str] = set()
    deduped: List[Tuple[str, Path]] = []
    for arc, fp in entries:
        if arc not in seen:
            seen.add(arc)
            deduped.append((arc, fp))
    deduped.sort(key=lambda x: x[0])
    return deduped


def _write_zip_entry(zf: zipfile.ZipFile, arcname: str, payload: bytes, *, executable: bool = False) -> None:
    zi = _Utf8ZipInfo(filename=arcname, date_time=(2026, 11, 27, 0, 0, 0))
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.flag_bits |= 0x800
    perm = 0o755 if executable else 0o644
    zi.external_attr = (0o100000 | perm) << 16
    zf.writestr(zi, payload, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def _should_skip_site_packages_rel(sp_rel_parts: Sequence[str]) -> bool:
    if not sp_rel_parts:
        return False
    top_low = sp_rel_parts[0].lower()
    if top_low in _EMBED_REDUNDANT_SP_EXACT:
        return True
    if any(top_low.startswith(pfx) for pfx in _EMBED_REDUNDANT_SP_PREFIXES):
        return True
    if sp_rel_parts[-1].lower() == "direct_url.json":
        return True
    return False


def _patch_mcp_win32_optional_imports(payload: bytes) -> bytes:
    txt = payload.decode("utf-8", errors="replace")
    old_blk = (
        'if sys.platform == "win32":\n'
        "    import pywintypes\n"
        "    import win32api\n"
        "    import win32con\n"
        "    import win32job\n"
    )
    new_blk = (
        'if sys.platform == "win32":\n'
        "    try:\n"
        "        import pywintypes\n"
        "        import win32api\n"
        "        import win32con\n"
        "        import win32job\n"
        "    except ImportError:\n"
        "        win32api = None\n"
        "        win32con = None\n"
        "        win32job = None\n"
        "        pywintypes = None\n"
    )
    if old_blk in txt:
        return txt.replace(old_blk, new_blk, 1).encode("utf-8")
    return payload


def prepare_embedded_python_entries(embed_dir: Path) -> List[Tuple[str, bytes, bool]]:
    """Collect purified `python-embed/*` archive entries and auto-enable `import site` in `python*._pth`."""
    resolved = Path(embed_dir).expanduser().resolve()
    if not resolved.is_dir():
        raise FileNotFoundError(f"Embedded Python directory does not exist: {resolved}")
    has_win_exe = (resolved / "python.exe").is_file()
    has_posix_exe = (resolved / "bin" / "python3").is_file() or (resolved / "bin" / "python").is_file()
    if not (has_win_exe or has_posix_exe):
        raise FileNotFoundError(
            f"Embedded Python directory `{resolved}` is missing `python.exe` (or `bin/python3`)."
        )

    skip_dirs = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".undo_history", ".git"}
    skip_suffixes = (".pyc", ".pyo", ".bak")
    entries: List[Tuple[str, bytes, bool]] = []

    for root, dirs, files in os.walk(resolved):
        rel_dir = Path(root).relative_to(resolved)
        rel_parts = rel_dir.parts
        in_sp = len(rel_parts) >= 2 and rel_parts[0].lower() == "lib" and rel_parts[1].lower() == "site-packages"
        if in_sp and len(rel_parts) > 2 and _should_skip_site_packages_rel(rel_parts[2:]):
            dirs[:] = []
            continue
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in skip_dirs
            and d.lower() not in skip_dirs
            and not (in_sp and len(rel_parts) == 2 and _should_skip_site_packages_rel((d,)))
        )
        for fname in sorted(files):
            low_f = fname.lower()
            if any(low_f.endswith(sfx) for sfx in skip_suffixes):
                continue
            if in_sp:
                sp_sub_parts = (*rel_parts[2:], fname)
                if _should_skip_site_packages_rel(sp_sub_parts):
                    continue
            fp = Path(root) / fname
            rel_posix = (rel_dir / fname).as_posix() if rel_dir != Path(".") else fname
            arc = f"python-embed/{rel_posix}"
            payload = fp.read_bytes()
            if rel_posix.lower() == "lib/site-packages/mcp/os/win32/utilities.py":
                payload = _patch_mcp_win32_optional_imports(payload)
            if rel_dir == Path(".") and re.fullmatch(r"python[^/\\]*\._pth", low_f):
                raw_txt = payload.decode("utf-8", errors="replace")
                out_lines: List[str] = []
                seen_paths: Set[str] = set()
                for raw_ln in raw_txt.splitlines():
                    s_ln = raw_ln.strip()
                    if not s_ln:
                        continue
                    low_ln = s_ln.lower()
                    if re.fullmatch(r"#\s*import\s+site", low_ln) or low_ln == "import site":
                        continue
                    if s_ln.startswith("#"):
                        out_lines.append(raw_ln)
                        continue
                    nk = s_ln.replace("\\", "/").rstrip("/").lower()
                    if nk not in seen_paths:
                        seen_paths.add(nk)
                        out_lines.append(s_ln)
                for req_p in ("Lib/site-packages", "../src", "../app_src"):
                    nk = req_p.lower()
                    if nk not in seen_paths:
                        seen_paths.add(nk)
                        out_lines.append(req_p)
                out_lines.append("import site")
                payload = ("\r\n".join(out_lines) + "\r\n").encode("utf-8")
            is_exec = low_f.endswith((".sh", ".exe", ".dll", ".pyd")) or "/bin/" in f"/{rel_posix}"
            entries.append((arc, payload, is_exec))

    entries.sort(key=lambda item: item[0])
    return entries


def prepare_wheels_entries(wheels_dir: Path) -> List[Tuple[str, bytes, bool]]:
    """Collect offline `.whl` packages under `wheels/` for zero-network portable bundles."""
    resolved = Path(wheels_dir).expanduser().resolve()
    if not resolved.is_dir():
        raise FileNotFoundError(f"Wheels directory does not exist: {resolved}")
    entries: List[Tuple[str, bytes, bool]] = []
    for fp in sorted(resolved.iterdir()):
        if fp.is_file() and fp.suffix.lower() == ".whl":
            entries.append((f"wheels/{fp.name}", fp.read_bytes(), False))
    if not entries:
        raise FileNotFoundError(f"Wheels directory `{resolved}` contains no `.whl` files.")
    return entries


def write_dist_sha256sums(dist_dir: Path, version: Optional[str] = None) -> Optional[Path]:
    """Generate `dist/SHA256SUMS.txt` covering current release `.zip` artifacts in `dist/`."""
    if not dist_dir.is_dir():
        return None
    pattern = f"Cosmos-MCP-v{version}*.zip" if version else "Cosmos-MCP-v*.zip"
    zips = sorted(p for p in dist_dir.glob(pattern) if p.is_file())
    if not zips:
        return None
    lines = [f"{sha256_file(zp)}  {zp.name}\n" for zp in zips]
    sums_path = dist_dir / "SHA256SUMS.txt"
    tmp_sums = dist_dir / ".SHA256SUMS.txt.tmp"
    tmp_sums.write_text("".join(lines), encoding="utf-8", newline="\n")
    os.replace(tmp_sums, sums_path)
    return sums_path


def build_release_zip(
    repo_root: Path = REPO_ROOT,
    out_zip: Path | None = None,
    *,
    embed_python_dir: Path | None = None,
    wheels_dir: Path | None = None,
) -> Dict[str, object]:
    version = read_project_version(repo_root)
    default_dist_dir = (repo_root / "dist").resolve()
    target_zip = (out_zip or (default_dist_dir / f"Cosmos-MCP-v{version}.zip")).resolve()
    target_zip.parent.mkdir(parents=True, exist_ok=True)

    manifest = collect_release_manifest(repo_root)
    win_bat_p = repo_root / GENERATED_LAUNCHERS[0]
    sh_p = repo_root / GENERATED_LAUNCHERS[1]
    if not win_bat_p.is_file():
        raise FileNotFoundError(f"Missing required launcher script: {GENERATED_LAUNCHERS[0]}")
    if not sh_p.is_file():
        raise FileNotFoundError(f"Missing required launcher script: {GENERATED_LAUNCHERS[1]}")
    win_bat_bytes = win_bat_p.read_bytes()
    sh_bytes = sh_p.read_bytes()
    quickstart_bytes = render_quickstart_txt(version)

    embed_entries: List[Tuple[str, bytes, bool]] = []
    if embed_python_dir is not None:
        embed_entries = prepare_embedded_python_entries(embed_python_dir)

    wheel_entries: List[Tuple[str, bytes, bool]] = []
    if wheels_dir is not None:
        wheel_entries = prepare_wheels_entries(wheels_dir)

    tmp_zip = target_zip.with_name(f".{target_zip.name}.tmp")
    with zipfile.ZipFile(tmp_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        _write_zip_entry(zf, QUICKSTART_TXT_NAME, quickstart_bytes, executable=False)
        for arc, fp in manifest:
            _write_zip_entry(zf, arc, fp.read_bytes(), executable=arc.endswith(".sh"))
        _write_zip_entry(zf, GENERATED_LAUNCHERS[0], win_bat_bytes, executable=False)
        _write_zip_entry(zf, GENERATED_LAUNCHERS[1], sh_bytes, executable=True)
        for arc, payload, is_exec in embed_entries:
            _write_zip_entry(zf, arc, payload, executable=is_exec)
        for arc, payload, is_exec in wheel_entries:
            _write_zip_entry(zf, arc, payload, executable=is_exec)

    os.replace(tmp_zip, target_zip)
    sums_file: Optional[Path] = None
    if os.path.normcase(str(target_zip.parent)) == os.path.normcase(str(default_dist_dir)):
        sums_file = write_dist_sha256sums(default_dist_dir, version=version)

    return {
        "ok": True,
        "version": version,
        "zip_path": str(target_zip),
        "size_bytes": target_zip.stat().st_size,
        "sha256": sha256_file(target_zip),
        "sha256sums_path": str(sums_file) if sums_file else "",
        "file_count": 1 + len(manifest) + len(GENERATED_LAUNCHERS) + len(embed_entries) + len(wheel_entries),
        "embedded_python_files": len(embed_entries),
        "bundled_wheels": len(wheel_entries),
    }


def scan_text_email_leaks(txt: str, *, is_test_file: bool = False) -> List[str]:
    """Return unredacted personal email addresses found in `txt` while allowing connector mentions & doc placeholders."""
    leaked: List[str] = []
    for em_match in _EMAIL_ADDR_RE.finditer(txt):
        full_em = em_match.group(0).lower()
        em_dom = em_match.group(2).lower()
        is_placeholder_dom = em_dom in _ALLOWED_DOC_EMAIL_DOMAINS or any(
            em_dom.endswith("." + d) for d in _ALLOWED_DOC_EMAIL_DOMAINS
        )
        if is_placeholder_dom:
            continue
        if is_test_file and full_em in _ALLOWED_TEST_SYNTHETIC_EMAILS:
            continue
        leaked.append(em_match.group(0))
    return leaked


def _iter_repo_files_for_hygiene(repo_root: Path) -> Iterable[Tuple[str, Path]]:
    for root, dirs, files in os.walk(repo_root):
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in EXCLUDED_DIR_NAMES
            and d.lower() not in EXCLUDED_DIR_NAMES
            and not d.lower().endswith(".egg-info")
        )
        for fname in sorted(files):
            fp = Path(root) / fname
            rel = fp.relative_to(repo_root)
            if _is_excluded_rel_parts(rel.parts):
                continue
            yield rel.as_posix(), fp


def run_release_checks(
    repo_root: Path = REPO_ROOT,
    zip_path: Path | None = None,
    *,
    diff_range: str = "",
) -> Tuple[bool, List[str], Dict[str, object]]:
    version = read_project_version(repo_root)
    eff_zip = (zip_path or (repo_root / "dist" / f"Cosmos-MCP-v{version}.zip")).resolve()
    errors: List[str] = []

    if not eff_zip.is_file():
        errors.append(f"Release archive does not exist: {eff_zip}")
        return False, errors, {"zip_path": str(eff_zip)}

    # 1. Check workspace for duplicate build/lib residue, tracked .env/internal dirs, and required repo-root launchers
    if (repo_root / "build" / "lib").exists():
        errors.append("Duplicate `build/lib/` residue exists in workspace.")
    if (repo_root / ".git").exists():
        try:
            ls_res = subprocess.run(
                ["git", "ls-files"],
                cwd=repo_root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                creationflags=0x08000000 if os.name == "nt" else 0,
            )
            if ls_res.returncode == 0:
                for tracked_rel in ls_res.stdout.splitlines():
                    norm_rel = tracked_rel.strip().replace("\\", "/")
                    norm_low = norm_rel.lower()
                    base_low = Path(norm_rel).name.lower()
                    if base_low == ".env" or (
                        base_low.startswith(".env.")
                        and base_low not in {".env.example", ".env.sample", ".env.template"}
                    ):
                        errors.append(f"Git-tracked local env file must not exist in repository: `{norm_rel}`")
                    if any(norm_low.startswith(pfx) for pfx in _FORBIDDEN_TRACKED_DIRS):
                        errors.append(f"Git-tracked internal directory file must not exist in repository: `{norm_rel}`")
        except OSError:
            pass
    for gl in GENERATED_LAUNCHERS:
        if not (repo_root / gl).is_file():
            errors.append(f"Missing required launcher script in repository root: `{gl}`")

    runtime_hostname = (socket.gethostname() or "").strip()
    runtime_username = (getpass.getuser() or "").strip()
    generic_names = {"localhost", "runner", "root", "user", "admin", "ubuntu", "cosmos", "pc", "test"}
    forbidden_archive_tokens = _build_forbidden_archive_tokens(runtime_hostname, runtime_username, generic_names)

    # 2. Inspect ZIP entries, exclusions, required entries, byte-level privacy & 100% SHA-256 parity
    expected_src = dict(iter_clean_tree_files(repo_root / "src" / "cosmos_mcp", "src/cosmos_mcp/", repo_root=repo_root))
    expected_all = dict(collect_release_manifest(repo_root))
    for gl in GENERATED_LAUNCHERS:
        gl_p = repo_root / gl
        if gl_p.is_file():
            expected_all[gl] = gl_p

    zip_src_hashes: Dict[str, str] = {}
    zip_names: List[str] = []
    embed_pth_checked: int = 0
    has_embed_entries: bool = False
    has_bundled_wheels: bool = False
    byte_scanned_entries: int = 0

    with zipfile.ZipFile(eff_zip, "r") as zf:
        for info in zf.infolist():
            arc = info.filename
            zip_names.append(arc)
            norm_parts = [p for p in arc.split("/") if p]
            low_arc = arc.lower()
            is_embed_entry = low_arc.startswith("python-embed/")
            is_bundled_wheel = len(norm_parts) == 2 and norm_parts[0].lower() == "wheels" and low_arc.endswith(".whl")
            if is_embed_entry:
                has_embed_entries = True
            if is_bundled_wheel:
                has_bundled_wheels = True
            if low_arc.startswith(".interface-design/"):
                errors.append(f"Internal design draft must not be distributed in release ZIP: {arc}")
            if is_embed_entry and low_arc.startswith("python-embed/lib/site-packages/bin/") and low_arc.endswith(".exe"):
                errors.append(f"Forbidden pip/uv `.exe` script wrapper inside `python-embed`: {arc}")
            if is_embed_entry and low_arc == "python-embed/lib/site-packages/.lock":
                errors.append(f"Forbidden `.lock` residue inside `python-embed`: {arc}")
            if "build/lib" in low_arc or (
                not is_bundled_wheel
                and not is_embed_entry
                and any(
                    p in EXCLUDED_DIR_NAMES or p.lower() in EXCLUDED_DIR_NAMES or p.lower().endswith(".egg-info")
                    for p in norm_parts
                )
            ):
                errors.append(f"Forbidden build/cache/vcs path inside ZIP: {arc}")
            disallowed_sfx = (".pyc", ".pyo", ".bak") if is_embed_entry else EXCLUDED_SUFFIXES
            if any(low_arc.endswith(sfx) for sfx in disallowed_sfx):
                errors.append(f"Forbidden compiled/backup file inside ZIP: {arc}")

            data = zf.read(arc)
            byte_scanned_entries += 1
            hit_tokens = scan_archive_entry_sensitive_bytes(data, forbidden_archive_tokens, arc_name=arc)
            if hit_tokens:
                errors.append(f"Byte-level sensitive token leaked in ZIP entry `{arc}` (matched {len(hit_tokens)} token(s))")

            if not is_embed_entry and not is_bundled_wheel:
                if low_arc.startswith("assets/") and low_arc.endswith((".png", ".jpg", ".jpeg")):
                    errors.extend(scan_image_bytes_integrity_and_metadata(data, rel_path=f"zip:{arc}"))
                elif b"\x00" not in data[:4096]:
                    arc_txt = data.decode("utf-8", errors="replace")
                    for cred_tag in scan_text_credential_leaks(arc_txt):
                        errors.append(f"High-risk credential pattern (`{cred_tag}`) leaked in ZIP entry `{arc}`")
                    for leak_tag in scan_text_cross_machine_and_internal_leaks(arc_txt):
                        errors.append(f"Cross-machine path or internal reference (`{leak_tag}`) leaked in ZIP entry `{arc}`")

            if low_arc.endswith((".whl", ".zip")) and not low_arc.endswith("python312.zip"):
                try:
                    with zipfile.ZipFile(io.BytesIO(data), "r") as nested_zf:
                        for n_info in nested_zf.infolist():
                            n_hits = scan_archive_entry_sensitive_bytes(
                                nested_zf.read(n_info.filename),
                                forbidden_archive_tokens,
                                arc_name=f"{arc}!{n_info.filename}",
                            )
                            if n_hits:
                                errors.append(
                                    f"Byte-level sensitive token leaked in nested archive `{arc}!{n_info.filename}`"
                                )
                except Exception:
                    pass

            if arc == QUICKSTART_TXT_NAME and b"\r\n" not in data:
                errors.append(f"`{QUICKSTART_TXT_NAME}` must use Windows CRLF line endings.")

            if is_embed_entry and len(norm_parts) == 2 and re.fullmatch(r"python[^/\\]*\._pth", norm_parts[1].lower()):
                embed_pth_checked += 1
                pth_lines = [ln.strip().lower() for ln in data.decode("utf-8", errors="replace").splitlines()]
                if "import site" not in pth_lines:
                    errors.append(f"Embedded Python `{arc}` is missing active `import site` support")
            digest = sha256_bytes(data)
            if arc.startswith("src/cosmos_mcp/") and not arc.endswith("/"):
                zip_src_hashes[arc] = digest
            if arc in expected_all:
                disk_digest = sha256_file(expected_all[arc])
                if digest != disk_digest:
                    errors.append(f"SHA-256 mismatch for `{arc}`: zip={digest} vs disk={disk_digest}")

    zip_name_set = set(zip_names)
    if has_embed_entries:
        if not (
            "python-embed/python.exe" in zip_name_set
            or "python-embed/bin/python3" in zip_name_set
            or "python-embed/bin/python" in zip_name_set
        ):
            errors.append("Release ZIP contains `python-embed/` without `python-embed/python.exe` (or `bin/python3`)")
        if not has_bundled_wheels:
            for req_pkg in REQUIRED_EMBED_PACKAGES:
                pkg_init = f"python-embed/Lib/site-packages/{req_pkg}/__init__.py"
                pkg_mod = f"python-embed/Lib/site-packages/{req_pkg}.py"
                if pkg_init not in zip_name_set and pkg_mod not in zip_name_set:
                    errors.append(
                        f"Embedded Python `win64-full` archive is missing required package `{req_pkg}` under `python-embed/Lib/site-packages/`"
                    )

    for req in (
        QUICKSTART_TXT_NAME,
        *REQUIRED_ROOT_FILES,
        *REQUIRED_DOC_FILES,
        *REQUIRED_STUDIO_STATIC_FILES,
        *REQUIRED_SANDBOX_FILES,
        *REQUIRED_ASSET_FILES,
        *GENERATED_LAUNCHERS,
    ):
        if req not in zip_name_set:
            errors.append(f"Missing required entry in release ZIP: `{req}`")

    missing_src = sorted(set(expected_src.keys()) - set(zip_src_hashes.keys()))
    extra_src = sorted(set(zip_src_hashes.keys()) - set(expected_src.keys()))
    if missing_src:
        errors.append(f"Missing `src/cosmos_mcp` files in ZIP: {missing_src[:10]}")
    if extra_src:
        errors.append(f"Unexpected extra `src/cosmos_mcp` files in ZIP: {extra_src[:10]}")

    for arc, src_fp in expected_src.items():
        if arc in zip_src_hashes:
            ws_sha = sha256_file(src_fp)
            if zip_src_hashes[arc] != ws_sha:
                errors.append(f"`src/cosmos_mcp` SHA-256 mismatch on `{arc}`: zip={zip_src_hashes[arc]} != ws={ws_sha}")

    # 3. Repo-wide privacy, private path, private pack, image integrity, and public documentation hygiene checks
    doc_checked_count = 0
    repo_checked_count = 0
    code_web_checked_count = 0
    image_checked_count = 0
    binary_suffixes = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".whl", ".sqlite3", ".exe", ".dll", ".pyd")
    code_web_suffixes = (".py", ".js", ".mjs", ".html", ".css", ".svg")
    for rel_arc, fp in _iter_repo_files_for_hygiene(repo_root):
        low_sfx = fp.suffix.lower()
        if low_sfx in (".png", ".jpg", ".jpeg") and rel_arc.startswith("assets/"):
            image_checked_count += 1
            errors.extend(scan_image_bytes_integrity_and_metadata(fp.read_bytes(), rel_path=rel_arc))
            continue
        if low_sfx in binary_suffixes:
            continue
        txt = fp.read_text(encoding="utf-8", errors="replace")
        repo_checked_count += 1
        if low_sfx in code_web_suffixes:
            code_web_checked_count += 1

        if (
            runtime_hostname
            and len(runtime_hostname) >= 4
            and runtime_hostname.lower() not in generic_names
            and runtime_hostname.lower() in txt.lower()
        ):
            errors.append(f"Local machine hostname leaked in repo file `{rel_arc}`")
        if (
            runtime_username
            and len(runtime_username) >= 4
            and runtime_username.lower() not in generic_names
            and runtime_username.lower() in txt.lower()
        ):
            errors.append(f"Local OS username leaked in repo file `{rel_arc}`")
        if scan_text_forbidden_identifier_hashes(txt):
            errors.append(f"Forbidden sensitive identifier hash matched in repo file `{rel_arc}`")
        if _PRIVATE_CONDA_PATH_RE.search(txt) or _PRIVATE_DEV_DRIVE_RE.search(txt):
            errors.append(f"Private local path (e.g. Anaconda / private drive path) leaked in repo file `{rel_arc}`")
        if _PRIVATE_PAD_PACK_RE.search(txt):
            errors.append(f"Private `pad` pack residue found in repo file `{rel_arc}`")

        is_test_file = rel_arc.startswith("tests/")
        if not is_test_file:
            for cred_tag in scan_text_credential_leaks(txt):
                errors.append(f"High-risk credential pattern (`{cred_tag}`) leaked in repo file `{rel_arc}`")
        for leak_tag in scan_text_cross_machine_and_internal_leaks(txt):
            errors.append(f"Cross-machine path or internal reference (`{leak_tag}`) leaked in repo file `{rel_arc}`")
        for leaked_em in scan_text_email_leaks(txt, is_test_file=is_test_file):
            errors.append(f"Unredacted email address `{leaked_em}` leaked in repo file `{rel_arc}`")

        if not is_test_file:
            if _OFFLINE_GOPROXY_RE.search(txt):
                errors.append(f"Forbidden offline GOPROXY setting found in `{rel_arc}`")
            if _OFFLINE_CARGO_RE.search(txt):
                errors.append(f"Forbidden offline CARGO_NET_OFFLINE setting found in `{rel_arc}`")
        else:
            if _ENV_ASSIGN_OFFLINE_RE.search(txt):
                errors.append(f"Forbidden offline env assignment in test file `{rel_arc}`")

        is_public_doc = (
            rel_arc
            in (
                "README.md",
                "README_EN.md",
                "PRIVACY_EN.md",
                "SECURITY_EN.md",
                "AGENTS.md",
                "PRIVACY.md",
                "SECURITY.md",
                "CHANGELOG.md",
                "THIRD_PARTY_NOTICES.md",
                "CONTRIBUTING.md",
            )
            or rel_arc.startswith(("docs/", "host_skills/"))
        )
        is_user_facing_ui_catalog = rel_arc in (
            "src/cosmos_mcp/core/tutorials_catalog.py",
            "src/cosmos_mcp/studio/static/index.html",
            "src/cosmos_mcp/studio/static/tutorials.html",
        )
        if is_public_doc:
            doc_checked_count += 1
            if _BRACKET_AT_RE.search(txt):
                errors.append(f"Escaped bracket-at typo found in doc `{rel_arc}` (use `{chr(64)}Cosmos`)")
            if _INTERNAL_CODENAME_RE.search(txt):
                errors.append(f"Internal experiment codename leaked in doc `{rel_arc}`")
        elif is_user_facing_ui_catalog and _BRACKET_AT_RE.search(txt):
            errors.append(f"Escaped bracket-at typo found in UI/tutorial source `{rel_arc}` (use `{chr(64)}Cosmos`)")

    if diff_range.strip():
        errors.extend(scan_git_diff_range(repo_root, diff_range.strip()))

    summary = {
        "ok": len(errors) == 0,
        "version": version,
        "zip_path": str(eff_zip),
        "zip_entries": len(zip_names),
        "byte_scanned_entries": byte_scanned_entries,
        "verified_src_files": len(expected_src),
        "verified_docs": doc_checked_count,
        "scanned_repo_files": repo_checked_count,
        "scanned_code_web_files": code_web_checked_count,
        "scanned_image_assets": image_checked_count,
        "embedded_pth_checked": embed_pth_checked,
        "error_count": len(errors),
    }
    return len(errors) == 0, errors, summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build Cosmos MCP release archive and run consistency checks.")
    parser.add_argument("--output", default="", help="Custom output ZIP path")
    parser.add_argument(
        "--embed-python-dir",
        default="",
        help="Optional unpacked Windows official python-embed directory to bundle under python-embed/ with import site enabled",
    )
    parser.add_argument(
        "--wheels-dir",
        default="",
        help="Optional offline wheelhouse directory (*.whl) to bundle under wheels/ for zero-network portable installation",
    )
    parser.add_argument("--check", action="store_true", help="Run SHA-256 parity and repo/archive byte hygiene verification gates")
    parser.add_argument("--no-build", action="store_true", help="Verify an existing archive without rebuilding")
    parser.add_argument(
        "--diff-range",
        default="",
        help="Optional git diff range (e.g. origin/main..HEAD) whose added lines are scanned for secrets and PII",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    out_zip = Path(args.output).resolve() if args.output else None
    embed_py_dir = Path(args.embed_python_dir).expanduser().resolve() if args.embed_python_dir else None
    wh_dir = Path(args.wheels_dir).expanduser().resolve() if args.wheels_dir else None
    if not args.no_build or (out_zip is not None and not out_zip.is_file()):
        build_info = build_release_zip(
            REPO_ROOT,
            out_zip=out_zip,
            embed_python_dir=embed_py_dir,
            wheels_dir=wh_dir,
        )
        eff_zip = Path(str(build_info["zip_path"]))
        print(
            f"[BUILD] Created {eff_zip.name} ({build_info['size_bytes']} bytes, "
            f"{build_info['file_count']} files, sha256={str(build_info['sha256'])[:16]}...)"
        )
    else:
        eff_zip = out_zip or (REPO_ROOT / "dist" / f"Cosmos-MCP-v{read_project_version(REPO_ROOT)}.zip")

    if args.check:
        ok, errs, summary = run_release_checks(REPO_ROOT, zip_path=eff_zip, diff_range=args.diff_range)
        if not ok:
            print(f"[CHECK FAILED] {len(errs)} issue(s) detected:", file=sys.stderr)
            for item in errs:
                print(f"  - {item}", file=sys.stderr)
            return 1
        print(
            f"[CHECK PASSED] {summary['verified_src_files']} src/cosmos_mcp files 100% SHA-256 matched, "
            f"{summary['byte_scanned_entries']} archive entries byte-scanned, "
            f"{summary['verified_docs']} docs clean, {summary['scanned_repo_files']} repo files verified."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
