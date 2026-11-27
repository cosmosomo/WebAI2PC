"""Single-pass in-memory 3-tier supply-chain security vetter for Agent Skills.

Implements context-aware security inspection across archive structure, executable
scripts, primary SKILL.md instructions, and passive reference files using only
the Python >= 3.9 standard library.
"""
from __future__ import annotations

import ast
import codecs
import io
import math
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Dict, List, Optional, Pattern, Sequence, Set, Tuple, Union
import zipfile

from cosmos_mcp.capabilities.skills.models import (
    SecurityAuditReport,
    SkillsConfig,
    VirtualFileEntry,
    is_link_or_junction,
    is_subpath,
)

__all__ = [
    "ZipSecurityLimitError",
    "audit_package_entries",
    "audit_skill_directory",
    "decode_text_with_bom_and_cookie",
    "extract_zip_to_virtual_entries",
]


class ZipSecurityLimitError(ValueError):
    """Raised when an archive violates size, entry-count, or format safety limits."""


_NATIVE_BIN_EXTS: Set[str] = {
    ".exe",
    ".dll",
    ".pyd",
    ".so",
    ".dylib",
    ".wasm",
    ".sys",
    ".scr",
    ".com",
    ".msi",
    ".ko",
    ".node",
}

_CODE_EXTS: Set[str] = {
    ".py",
    ".pyw",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".psm1",
    ".psd1",
    ".cmd",
    ".bat",
    ".js",
    ".mjs",
    ".cjs",
    ".jsx",
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
    ".vbs",
    ".vbe",
    ".jse",
    ".wsf",
    ".hta",
    ".rb",
    ".pl",
    ".php",
    ".lua",
}

_PASSIVE_DATA_EXTS: Set[str] = {
    ".md",
    ".mdx",
    ".markdown",
    ".txt",
    ".rst",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".xml",
    ".csv",
    ".tsv",
    ".svg",
}

_SKIP_TEXT_SCAN_EXTS: Set[str] = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".bmp",
    ".ico",
    ".pdf",
    ".ttf",
    ".otf",
    ".woff",
    ".woff2",
    ".sqlite",
    ".sqlite3",
    ".db",
}

_KNOWN_BINARY_ASSET_HEADERS: Tuple[bytes, ...] = (
    b"%PDF-",
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"GIF87a",
    b"GIF89a",
    b"RIFF",
    b"BM",
    b"\x00\x00\x01\x00",
    b"\x00\x00\x02\x00",
    b"SQLite format 3\x00",
    b"\x00\x01\x00\x00",
    b"OTTO",
    b"wOFF",
    b"wOF2",
)

_RESERVED_SKILL_SUBDIRS: Set[str] = {
    "scripts",
    "references",
    "reference",
    "assets",
    "src",
    "hooks",
    "templates",
    "agents",
    "examples",
    "__pycache__",
    ".clawhub",
}

_LOCAL_WALK_SKIP_DIRS: Set[str] = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    ".undo_history",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}

_MAGIC_HEADERS: Tuple[Tuple[bytes, str], ...] = (
    (b"\x7fELF", "Linux ELF binary"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit binary"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit LE binary"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit binary"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit LE binary"),
    (b"\x00asm", "WebAssembly binary"),
)

_PEP263_COOKIE_BYTES_RE: Pattern[bytes] = re.compile(rb"^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)")
_PEP263_COOKIE_TEXT_RE: Pattern[str] = re.compile(r"^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)", re.IGNORECASE)

_OBFUSCATED_PY_CODECS: Set[str] = {
    "unicode_escape",
    "raw_unicode_escape",
    "rot_13",
    "rot13",
    "punycode",
    "hex",
    "hex_codec",
    "base64",
    "base64_codec",
    "quopri",
    "quopri_codec",
    "uu",
    "uu_codec",
    "zlib",
    "zlib_codec",
    "bz2",
    "bz2_codec",
    "string_escape",
    "palmos",
    "undefined",
}

# Requires BOTH `-----BEGIN ... PRIVATE KEY-----` AND `-----END ... PRIVATE KEY-----`
# so single-line defensive documentation examples do not trigger false blocks.
_PRIV_KEY_BLOCK_RE: Pattern[str] = re.compile(
    r"-----BEGIN (?:[A-Z0-9 _-]{1,32} )?PRIVATE KEY-----[\s\S]{8,16384}?-----END (?:[A-Z0-9 _-]{1,32} )?PRIVATE KEY-----"
)

_LIVE_KEY_PATTERNS: Tuple[Tuple[str, Pattern[str]], ...] = (
    ("OPENAI_OR_SK_KEY", re.compile(r"\bsk-(?:proj-|live-|ant-)?[A-Za-z0-9_-]{20,}\b")),
    ("GOOGLE_AIZA_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{32,}\b")),
    ("GITHUB_PAT", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{24,}\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b")),
)

_PLACEHOLDER_HINTS: Tuple[str, ...] = (
    "xxxx",
    "yyyy",
    "zzzz",
    "your_",
    "your-",
    "example",
    "placeholder",
    "dummy",
    "replace_me",
    "replace-me",
    "test_key",
    "test-key",
    "sk-test-",
    "sample_key",
    "changeme",
    "fake_",
    "fake-",
    "mock_",
    "mock-",
    "redacted",
    "00000000",
    "11111111",
    "123456789",
)

_SENSITIVE_DOTENV_KEY_RE: Pattern[str] = re.compile(
    r"(?i)(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL)"
)

_BENIGN_CONFIG_VALUES: Set[str] = {
    "warning",
    "warn",
    "debug",
    "info",
    "error",
    "trace",
    "fatal",
    "production",
    "prod",
    "development",
    "dev",
    "staging",
    "test",
    "testing",
    "local",
    "true",
    "false",
    "yes",
    "no",
    "on",
    "off",
    "none",
    "null",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "utf-8",
    "utf8",
    "json",
    "text",
}

_REMOTE_URL_PIPE_EXEC_RE: Pattern[str] = re.compile(
    r"(?i)\b(?:curl|wget)\b[^\n|;`\"']{0,200}\bhttps?://[^\s|;`\"')]+[^\n|;]{0,80}\|\s*(?:sudo\s+)?(?:env\s+)?(?:ba|z|da|k)?sh\b"
    r"|\b(?:curl|wget)\b[^\n|;`\"']{0,200}\bhttps?://[^\s|;`\"')]+[^\n|;]{0,80}\|\s*(?:sudo\s+)?python3?\b"
    r"|\b(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\b[^\n|;`\"']{0,200}\bhttps?://[^\s|;`\"')]+[^\n|;]{0,80}\|\s*(?:iex|Invoke-Expression)\b"
    r"|(?:\biex\b|\bInvoke-Expression\b)\s*\(\s*(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\b[^\n)]{0,200}\bhttps?://[^\s)\"']+"
    r"|\b(?:(?:ba|z|da|k)?sh\s+-c|eval)\s+[\"']?\$\(\s*(?:curl|wget)\b[^\n)]{0,200}\bhttps?://[^\s)\"']+"
    r"|\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,120}\b(?:-c|-command)\b[^\n]{0,200}\b(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\b[^\n]{0,200}\bhttps?://[^\s\"'|)]+\s*\|\s*(?:iex|Invoke-Expression)\b"
)

_SHELL_OR_SCRIPT_B64_EXEC_RE: Pattern[str] = re.compile(
    r"(?i)(?:base64\s+(?:-d|--decode|-D)|FromBase64String|atob\s*\()[^\n]{0,200}"
    r"(?:\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\|\s*(?:iex|Invoke-Expression)\b|(?:^|[^\w.])(?:eval|exec)\s*\()"
    r"|(?:(?:^|[^\w.])(?:eval|exec)\s*\(|\bInvoke-Expression\b|\biex\b)[^\n]{0,160}"
    r"(?:base64\s+(?:-d|--decode|-D)|(?:b64decode|urlsafe_b64decode)\s*\(\s*(?!['\"]?[\$\{])|FromBase64String|atob\s*\()"
    r"|\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,120}\s-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/]{20,}={0,2}\b"
)

_SCRIPT_CRED_HARVEST_RE: Pattern[str] = re.compile(
    r"(?i)(?:(?:^|[\s/\\'',(])\.ssh\s*['\"]?\s*(?:[/\\,]\s*['\"]?)(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|config)\b"
    r"|~[/\\]\.ssh[/\\](?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys)\b"
    r"|(?:^|[\s/\\'',(])\.aws\s*['\"]?\s*(?:[/\\,]\s*['\"]?)credentials\b"
    r"|~[/\\]\.aws[/\\]credentials\b"
    r"|(?:^|[\s/\\'',(])\.claude\s*['\"]?\s*(?:[/\\,]\s*['\"]?)\.credentials\.json\b"
    r"|~[/\\]\.claude[/\\]\.credentials\.json\b"
    r"|(?:^|[\s/\\'',(])secrets\s*['\"]?\s*(?:[/\\,]\s*['\"]?)auth\.json\b"
    r"|(?:~|\$HOME|\$env:USERPROFILE|USERPROFILE|expanduser|Path\.home\(\))[^\n]{0,80}?[/\\'\"]\.(?:netrc|npmrc)(?:['\"\s/\\)]|$)"
    r"|(?:^|[\s/\\'',(])~[/\\]\.(?:netrc|npmrc)\b"
    r"|\bCryptUnprotectData\b"
    r"|\bwin32crypt\b"
    r"|\bSecKeychainFind(?:Generic|Internet)Password\b"
    r"|\bsecurity\s+(?:find-(?:generic|internet)-password|dump-keychain|export\b[^\n]{0,60}keychain)\b"
    r"|Library[/\\]Keychains[/\\]"
    r"|(?:User\s+Data|Chrome|Edge|Brave|Chromium|Firefox|Profiles)[/\\'',\s][^\n]{0,100}?(?:Login\s+Data|Cookies|cookies\.sqlite|key4\.db)\b)"
)

_FENCED_BLOCK_RE: Pattern[str] = re.compile(r"(?:```[\s\S]*?```|~~~[\s\S]*?~~~)")
_INLINE_CODE_RE: Pattern[str] = re.compile(r"`[^`\n]+`")
# Non-greedy unbounded HTML comment scan (defeats >4,000 whitespace padding bypasses)
_HTML_COMMENT_RE: Pattern[str] = re.compile(r"<!--([\s\S]*?)(?:-->|\Z)")
_ZERO_WIDTH_OBFUSCATION_RE: Pattern[str] = re.compile(r"[\u200b-\u200f\u2060-\u2064\ufeff\u00ad]")

_HIDDEN_COMMENT_DIRECTIVE_RE: Pattern[str] = re.compile(
    r"(?i)(?:ignore\s+(?:all\s+)?(?:previous|prior|above|system)"
    r"|disregard\s+(?:all\s+)?(?:previous|prior|above)"
    r"|system\s+(?:override|prompt|instruction)"
    r"|you\s+are\s+now\s+(?:a|an|in)\b"
    r"|new\s+instructions?\s*:"
    r"|do\s+not\s+(?:tell|inform|mention|reveal|disclose)"
    r"|\b(?:curl|wget|irm|iwr|Invoke-WebRequest|Invoke-RestMethod)\s+[^\n]{0,80}https?://"
    r"|\b(?:cat|type|read|get-content|head|tail|exfil\w*)\s+[^\n]{0,60}(?:\.ssh|\.env|\.aws|\.claude|auth\.json|\.netrc|\.npmrc|id_rsa|id_ed25519|API_KEY|SECRET|Login\s+Data|Cookies)"
    r"|\b(?:pc_run_command|pc_run_python|pc_write_file|send_message|execute_bash)\b)"
)

_BIDI_AND_UNICODE_TAG_RE: Pattern[str] = re.compile(
    r"[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f]"
)

_SHELL_INTERPRETER_NAMES: Set[str] = {
    "powershell",
    "pwsh",
    "cmd",
    "bash",
    "sh",
    "zsh",
    "dash",
    "ksh",
    "cscript",
    "wscript",
    "mshta",
}

_SHELL_EXEC_FLAGS: Set[str] = {
    "-c",
    "/c",
    "/k",
    "-command",
    "-encodedcommand",
    "-enc",
    "-ec",
    "-e",
}

_OBFUSCATED_CODECS_DECODE_NAMES: Set[str] = {
    "base64",
    "base64_codec",
    "hex",
    "hex_codec",
    "rot_13",
    "rot13",
    "zlib",
    "zlib_codec",
    "bz2",
    "bz2_codec",
    "uu",
    "uu_codec",
    "quopri",
    "quopri_codec",
    "unicode_escape",
    "raw_unicode_escape",
}


def decode_text_with_bom_and_cookie(raw_bytes: bytes, ext: str = "") -> str:
    """Decode text/script bytes across UTF-8/UTF-16/UTF-32 BOMs, BOM-less UTF-16, and PEP 263 cookies."""
    if not raw_bytes:
        return ""

    # 1. Explicit BOM headers (check 4-byte UTF-32 before 2-byte UTF-16LE)
    if raw_bytes.startswith(b"\xff\xfe\x00\x00"):
        return raw_bytes[4:].decode("utf-32-le", errors="replace")
    if raw_bytes.startswith(b"\x00\x00\xfe\xff"):
        return raw_bytes[4:].decode("utf-32-be", errors="replace")
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        raw_no_bom = raw_bytes[3:]
        if ext.lower() in (".py", ".pyw"):
            return _decode_python_cookie_bytes(raw_no_bom)
        return raw_no_bom.decode("utf-8", errors="replace")
    if raw_bytes.startswith(b"\xff\xfe"):
        return raw_bytes[2:].decode("utf-16-le", errors="replace")
    if raw_bytes.startswith(b"\xfe\xff"):
        return raw_bytes[2:].decode("utf-16-be", errors="replace")

    # 2. BOM-less UTF-16LE / UTF-16BE detection via alternating NUL-byte ratio
    sample = raw_bytes[:4096]
    if len(sample) >= 4 and b"\x00" in sample:
        pairs = len(sample) // 2
        even_zeros = sum(1 for b in sample[0 : pairs * 2 : 2] if b == 0)
        odd_zeros = sum(1 for b in sample[1 : pairs * 2 : 2] if b == 0)
        if odd_zeros / pairs >= 0.30 and even_zeros / pairs <= 0.05:
            return raw_bytes.decode("utf-16-le", errors="replace")
        if even_zeros / pairs >= 0.30 and odd_zeros / pairs <= 0.05:
            return raw_bytes.decode("utf-16-be", errors="replace")

    # 3. Python PEP 263 source encoding cookie on first two lines
    if ext.lower() in (".py", ".pyw"):
        return _decode_python_cookie_bytes(raw_bytes)

    return raw_bytes.decode("utf-8", errors="replace")


def _decode_python_cookie_bytes(raw_bytes: bytes) -> str:
    lines = raw_bytes.splitlines(keepends=True)
    for idx, line in enumerate(lines[:2]):
        m = _PEP263_COOKIE_BYTES_RE.match(line)
        if m:
            cookie = m.group(1).decode("ascii", errors="ignore").strip()
            norm = cookie.lower().replace("-", "_")
            if norm in ("unicode_escape", "raw_unicode_escape"):
                head_txt = b"".join(lines[: idx + 1]).decode("ascii", errors="replace")
                body_bytes = b"".join(lines[idx + 1 :])
                try:
                    body_txt = codecs.decode(body_bytes, cookie, errors="replace")
                    if isinstance(body_txt, str):
                        return head_txt + body_txt
                except Exception:
                    pass
            try:
                info = codecs.lookup(cookie)
                decoded = codecs.decode(raw_bytes, info.name, errors="replace")
                if isinstance(decoded, str):
                    return decoded
            except Exception:
                break
    return raw_bytes.decode("utf-8", errors="replace")


def _detect_obfuscated_python_encoding(raw_bytes: bytes, decoded_text: str) -> Optional[str]:
    """Return offending PEP 263 encoding name if obfuscated/transform codec is declared in lines 1..2."""
    for line_b in raw_bytes.splitlines()[:2]:
        m_b = _PEP263_COOKIE_BYTES_RE.match(line_b)
        if m_b:
            enc_raw = m_b.group(1).decode("ascii", errors="ignore").strip()
            if _is_obfuscated_py_codec_name(enc_raw):
                return enc_raw
    for line_t in decoded_text.splitlines()[:2]:
        m_t = _PEP263_COOKIE_TEXT_RE.match(line_t)
        if m_t:
            enc_raw = m_t.group(1).strip()
            if _is_obfuscated_py_codec_name(enc_raw):
                return enc_raw
    return None


def _is_obfuscated_py_codec_name(enc_raw: str) -> bool:
    norm = enc_raw.strip().lower().replace("-", "_")
    if not norm:
        return False
    if norm in _OBFUSCATED_PY_CODECS:
        return True
    for bad_frag in ("escape", "rot_13", "rot13", "punycode", "base64", "hex", "zlib", "bz2", "quopri", "uu_"):
        if bad_frag in norm:
            return True
    return False


def _is_unsafe_rel_path(raw_name: str) -> bool:
    """Return True if path attempts traversal, absolute escape, Windows drive, or NUL injection."""
    if not raw_name or "\x00" in raw_name:
        return True
    if raw_name.startswith(("/", "\\")) or ":" in raw_name:
        return True
    norm = raw_name.replace("\\", "/")
    parts = norm.split("/")
    return any(part == ".." for part in parts)


def _does_symlink_escape_root(entry_rel_path: str, target_str: str) -> bool:
    """Verify whether a relative symlink target stays strictly inside the virtual skill root."""
    cleaned = target_str.strip("\r\n\x00")
    if not cleaned or "\x00" in cleaned:
        return True
    if cleaned.startswith(("/", "\\")) or ":" in cleaned:
        return True

    parent_posix = PurePosixPath(entry_rel_path.replace("\\", "/")).parent
    stack: List[str] = [p for p in parent_posix.parts if p not in ("", ".")]
    for seg in cleaned.replace("\\", "/").split("/"):
        if not seg or seg == ".":
            continue
        if seg == "..":
            if not stack:
                return True
            stack.pop()
        else:
            stack.append(seg)
    return False


def _matches_pe_magic(raw_bytes: bytes) -> bool:
    """Detect Windows PE 'MZ' binaries without false-flagging plain ASCII text starting with 'MZ'."""
    if not raw_bytes.startswith(b"MZ"):
        return False
    if len(raw_bytes) < 4:
        return True
    probe = raw_bytes[2:64]
    if b"\x00" in probe:
        return True
    return any((b < 0x09 or (0x0E <= b < 0x20) or b >= 0x7F) for b in probe[:16])


def _is_genuine_binary_asset(raw_bytes: bytes) -> bool:
    """Verify whether a file with a skipped asset extension is actually binary rather than disguised text."""
    for hdr in _KNOWN_BINARY_ASSET_HEADERS:
        if raw_bytes.startswith(hdr):
            return True
    if raw_bytes.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
        return False
    sample = raw_bytes[:1024]
    if not sample:
        return True
    # Check if BOM-less UTF-16 text
    if len(sample) >= 4 and b"\x00" in sample:
        pairs = len(sample) // 2
        even_zeros = sum(1 for b in sample[0 : pairs * 2 : 2] if b == 0)
        odd_zeros = sum(1 for b in sample[1 : pairs * 2 : 2] if b == 0)
        if (odd_zeros / pairs >= 0.30 and even_zeros / pairs <= 0.05) or (
            even_zeros / pairs >= 0.30 and odd_zeros / pairs <= 0.05
        ):
            return False
        return True
    non_text = sum(1 for b in sample if b < 0x09 or (0x0E <= b < 0x20))
    return (non_text / len(sample)) > 0.10


def has_sequential_stub_run(s: str, min_run: int = 6) -> bool:
    """Detect case-sensitive ascending sequential test stubs such as `abcdef...`, `ABCDEF...`, or `123456...`."""
    if len(s) < min_run:
        return False
    run = 1
    for i in range(len(s) - 1):
        a = s[i]
        b = s[i + 1]
        if a.isalnum() and b.isalnum() and (ord(b) - ord(a) == 1):
            run += 1
            if run >= min_run:
                return True
        else:
            run = 1
    return False


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(s))
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _strip_secret_prefix(token: str) -> str:
    for pfx in (
        "sk-proj-",
        "sk-live-",
        "sk-ant-",
        "sk-",
        "github_pat_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "AIza",
        "AKIA",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxr-",
        "xoxs-",
    ):
        if token.startswith(pfx):
            return token[len(pfx) :]
    return token[4:]


def _looks_like_real_secret(token: str) -> bool:
    low = token.lower()
    if any(hint in low for hint in _PLACEHOLDER_HINTS):
        return False
    body = _strip_secret_prefix(token).strip("_-")
    if len(set(body)) < 6:
        return False
    if has_sequential_stub_run(body, min_run=6):
        return False
    if _shannon_entropy(body) < 2.5:
        return False
    return True


def _has_populated_dotenv_secret(env_text: str, fname_low: str = ".env") -> bool:
    is_exact_dotenv = fname_low == ".env"
    for raw_line in env_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key_raw, val = line.split("=", 1)
        key_clean = key_raw.strip()
        val_clean = val.strip().strip("\"'").strip()
        if len(val_clean) < 6:
            continue
        val_low = val_clean.lower()
        if (
            val_low in _BENIGN_CONFIG_VALUES
            or val_clean.isdigit()
            or val_low.startswith(("http://localhost", "http://127.0.0.1", "https://localhost"))
            or val_clean.startswith(("$", "${", "<", "{{"))
            or any(h in val_low for h in _PLACEHOLDER_HINTS)
            or has_sequential_stub_run(val_clean, min_run=6)
        ):
            continue
        has_sensitive_key = bool(_SENSITIVE_DOTENV_KEY_RE.search(key_clean))
        if has_sensitive_key:
            return True
        if is_exact_dotenv and _shannon_entropy(val_clean) >= 3.0 and any(ch.isdigit() or ch.isupper() for ch in val_clean):
            return True
    return False


def _strip_visible_markdown_code(md_text: str) -> str:
    no_fences = _FENCED_BLOCK_RE.sub(" ", md_text)
    return _INLINE_CODE_RE.sub(" ", no_fences)


def _append_unique(items: List[str], val: str) -> None:
    if val not in items:
        items.append(val)


def _eval_static_str(node: Optional[ast.AST]) -> Optional[str]:
    """Fold constant string literals and `'ex' + 'ec'` string concatenations."""
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _eval_static_str(node.left)
        right = _eval_static_str(node.right)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.JoinedStr):
        parts: List[str] = []
        for v in node.values:
            s = _eval_static_str(v)
            if s is None:
                return None
            parts.append(s)
        return "".join(parts)
    return None


def _extract_imported_module_from_call(
    call_node: ast.Call,
    symbol_imports: Dict[str, str],
    module_aliases: Dict[str, str],
) -> Optional[str]:
    fn = ""
    if isinstance(call_node.func, ast.Name):
        fn = symbol_imports.get(call_node.func.id, call_node.func.id)
    elif isinstance(call_node.func, ast.Attribute) and isinstance(call_node.func.value, ast.Name):
        base = module_aliases.get(call_node.func.value.id, call_node.func.value.id)
        fn = f"{base}.{call_node.func.attr}"
    if fn in ("__import__", "builtins.__import__", "importlib.import_module") and call_node.args:
        return _eval_static_str(call_node.args[0])
    return None


def _analyze_python_ast(
    raw_bytes: Optional[bytes],
    code_text: str,
    rel_path: str,
    report: SecurityAuditReport,
) -> bool:
    """Parse and inspect Python AST; returns True if parsed, False if unparseable (emitting WARN)."""
    tree: Optional[ast.AST] = None
    parse_err: Optional[BaseException] = None

    # Prefer `ast.parse(raw_bytes)` when no UTF-16/UTF-32 NUL framing is present so PEP 263 cookies parse natively.
    if raw_bytes is not None and b"\x00" not in raw_bytes[:256] and not raw_bytes.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            tree = ast.parse(raw_bytes, filename=rel_path)
        except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError) as exc:
            parse_err = exc

    if tree is None:
        try:
            tree = ast.parse(code_text, filename=rel_path)
            parse_err = None
        except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError) as exc:
            if parse_err is None:
                parse_err = exc

    if tree is None:
        err_desc = f"{type(parse_err).__name__}: {getattr(parse_err, 'msg', parse_err)}" if parse_err else "SyntaxError"
        report.add(
            "WARN",
            "PY_SYNTAX_UNPARSEABLE",
            rel_path,
            f"Python script could not be parsed into AST ({err_desc})",
            "Fix Python syntax errors or manually audit the script before confirming installation.",
        )
        return False

    # Pass 1: resolve imports, module aliases, `__import__` bindings, and `getattr` bindings
    module_aliases: Dict[str, str] = {}
    symbol_imports: Dict[str, str] = {}
    dynamic_exec_vars: Set[str] = set()
    dynamic_shell_vars: Set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module_aliases[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                symbol_imports[local] = f"{mod}.{alias.name}" if mod else alias.name
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_id = node.targets[0].id
            if isinstance(node.value, ast.Call):
                imp_mod = _extract_imported_module_from_call(node.value, symbol_imports, module_aliases)
                if imp_mod:
                    module_aliases[var_id] = imp_mod
                elif isinstance(node.value.func, ast.Name) and symbol_imports.get(node.value.func.id, node.value.func.id) in (
                    "getattr",
                    "builtins.getattr",
                ):
                    if len(node.value.args) >= 2:
                        ga = _eval_static_str(node.value.args[1])
                        if ga in ("eval", "exec"):
                            dynamic_exec_vars.add(var_id)
                        elif ga in ("system", "popen", "spawn"):
                            dynamic_shell_vars.add(var_id)

    has_b64_or_decompress = False
    has_dynamic_exec = False
    exec_lines: List[int] = []
    shell_true_lines: List[int] = []
    net_call_lines: List[int] = []
    env_or_cred_lines: List[int] = []

    store_subscript_value_ids: Set[int] = {
        id(tgt.value)
        for assign_n in ast.walk(tree)
        if isinstance(assign_n, ast.Assign)
        for tgt in assign_n.targets
        if isinstance(tgt, ast.Subscript)
    }

    cred_ast_str_re = re.compile(
        r"(?i)(?:(?:^|[/\\])\.env(?:\.[A-Za-z0-9_-]+)?$"
        r"|(?:^|[/\\])(?:\.netrc|\.npmrc|id_rsa|id_ed25519|id_ecdsa|authorized_keys|oauth\.sqlite3)$"
        r"|(?:\.aws[/\\]credentials|\.claude[/\\]\.credentials\.json|secrets[/\\]auth\.json|CONNECTION_INFO))"
    )

    for node in ast.walk(tree):
        n_line = int(getattr(node, "lineno", 0) or 0)
        if isinstance(node, ast.Attribute) and isinstance(getattr(node, "ctx", None), ast.Load):
            if id(node) not in store_subscript_value_ids and node.attr == "environ" and isinstance(node.value, ast.Name):
                base_mod = module_aliases.get(node.value.id, symbol_imports.get(node.value.id, node.value.id))
                if base_mod in ("os", "posix", "nt"):
                    env_or_cred_lines.append(n_line)
        elif isinstance(node, ast.Name) and isinstance(getattr(node, "ctx", None), ast.Load):
            if id(node) not in store_subscript_value_ids:
                resolved_sym = symbol_imports.get(node.id, "")
                if resolved_sym in ("os.environ", "posix.environ", "nt.environ"):
                    env_or_cred_lines.append(n_line)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            s_val = node.value.strip()
            if s_val and (_SCRIPT_CRED_HARVEST_RE.search(s_val) or cred_ast_str_re.search(s_val)):
                env_or_cred_lines.append(n_line)

    decode_attrs = {
        "b64decode",
        "urlsafe_b64decode",
        "b32decode",
        "b16decode",
        "a85decode",
        "b85decode",
        "decodebytes",
        "decompress",
        "decompressobj",
    }

    subprocess_funcs = {
        "subprocess.Popen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
    }
    subprocess_attrs = {"Popen", "run", "call", "check_call", "check_output"}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = ""
        attr_name = ""
        if isinstance(node.func, ast.Name):
            nid = node.func.id
            if nid in dynamic_exec_vars:
                func_name = "builtins.exec"
            elif nid in dynamic_shell_vars:
                func_name = "os.system"
            else:
                func_name = symbol_imports.get(nid, nid)
            if "." in func_name:
                attr_name = func_name.rsplit(".", 1)[-1]
        elif isinstance(node.func, ast.Attribute):
            attr_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                vname = node.func.value.id
                base = module_aliases.get(vname, symbol_imports.get(vname, vname))
                func_name = f"{base}.{attr_name}"
            elif isinstance(node.func.value, ast.Call):
                imp_mod = _extract_imported_module_from_call(node.func.value, symbol_imports, module_aliases)
                if imp_mod:
                    func_name = f"{imp_mod}.{attr_name}"

        lineno = int(getattr(node, "lineno", 0) or 0)

        # `getattr(builtins, 'ex' + 'ec')` / `getattr(os, 'system')`
        if func_name in ("getattr", "builtins.getattr") and len(node.args) >= 2:
            target_attr = _eval_static_str(node.args[1])
            if target_attr in ("eval", "exec"):
                has_dynamic_exec = True
                exec_lines.append(lineno)
            elif target_attr in ("system", "popen", "spawn"):
                shell_true_lines.append(lineno)

        # Dynamic `__import__('os')` / `__import__('subprocess')` / `__import__('pty')`
        if func_name in ("__import__", "builtins.__import__", "importlib.import_module") and node.args:
            imp_target = _eval_static_str(node.args[0])
            if imp_target in ("os", "subprocess", "pty") and func_name in ("__import__", "builtins.__import__"):
                shell_true_lines.append(lineno)

        # Builtin eval / exec (explicitly excludes ast.literal_eval)
        if func_name in ("eval", "exec", "builtins.eval", "builtins.exec", "__builtins__.eval", "__builtins__.exec"):
            has_dynamic_exec = True
            exec_lines.append(lineno)

        # Payload decoding / decompression including `codecs.decode(..., 'base64')`
        if attr_name in decode_attrs or func_name in decode_attrs or func_name.rsplit(".", 1)[-1] in decode_attrs:
            has_b64_or_decompress = True
        elif func_name == "bytes.fromhex" or (attr_name == "fromhex" and func_name.endswith(".fromhex")):
            has_b64_or_decompress = True
        elif func_name in ("codecs.decode", "codecs.getdecoder"):
            enc_arg: Optional[ast.AST] = node.args[1] if len(node.args) >= 2 else (
                node.args[0] if func_name == "codecs.getdecoder" and node.args else None
            )
            for kw in node.keywords:
                if kw.arg == "encoding":
                    enc_arg = kw.value
            if enc_arg is not None:
                enc_val = _eval_static_str(enc_arg)
                if enc_val is None or enc_val.strip().lower().replace("-", "_") in _OBFUSCATED_CODECS_DECODE_NAMES:
                    has_b64_or_decompress = True

        # Subprocess shell=truthy and shell-interpreter array invocation (`powershell -Command`, `sh -c`, etc.)
        is_subproc_call = (
            attr_name in subprocess_attrs
            or func_name in subprocess_funcs
            or func_name.startswith("subprocess.")
        )
        if is_subproc_call:
            for kw in node.keywords:
                if kw.arg == "shell":
                    if isinstance(kw.value, ast.Constant):
                        if bool(kw.value.value):
                            shell_true_lines.append(lineno)
                    else:
                        shell_true_lines.append(lineno)

            cmd_arg: Optional[ast.AST] = node.args[0] if node.args else None
            for kw in node.keywords:
                if kw.arg in ("args", "executable") and cmd_arg is None:
                    cmd_arg = kw.value
            if isinstance(cmd_arg, (ast.List, ast.Tuple)) and cmd_arg.elts:
                static_parts = [_eval_static_str(elt) for elt in cmd_arg.elts]
                first_tok = static_parts[0]
                if first_tok:
                    prog_name = PurePosixPath(first_tok.replace("\\", "/")).name.lower()
                    if prog_name.endswith(".exe"):
                        prog_name = prog_name[:-4]
                    if prog_name in _SHELL_INTERPRETER_NAMES:
                        lower_flags = [p.strip().lower() for p in static_parts[1:] if p]
                        if any(
                            fl in _SHELL_EXEC_FLAGS or fl.startswith(("-enc", "-com"))
                            for fl in lower_flags
                        ):
                            shell_true_lines.append(lineno)
                        if any(fl in ("-encodedcommand", "-enc", "-ec") or fl.startswith("-enc") for fl in lower_flags):
                            has_b64_or_decompress = True
            elif isinstance(cmd_arg, ast.AST):
                cmd_str = _eval_static_str(cmd_arg)
                if cmd_str:
                    low_cmd = cmd_str.strip().lower()
                    for sh_name in ("powershell", "pwsh", "cmd.exe", "cmd ", "/bin/sh", "/bin/bash", "bash ", "sh "):
                        if low_cmd.startswith(sh_name) and any(
                            fl in low_cmd.split() for fl in _SHELL_EXEC_FLAGS
                        ):
                            shell_true_lines.append(lineno)
                            break

        if func_name in (
            "os.system",
            "os.popen",
            "pty.spawn",
            "posix.system",
            "nt.system",
            "subprocess.getoutput",
            "subprocess.getstatusoutput",
            "asyncio.create_subprocess_shell",
        ) or attr_name == "create_subprocess_shell":
            shell_true_lines.append(lineno)

        if func_name in ("os.getenv", "posix.getenv", "nt.getenv", "dotenv.dotenv_values", "dotenv.load_dotenv") or (
            attr_name in ("getenv", "dotenv_values", "load_dotenv")
        ):
            env_or_cred_lines.append(lineno)

        if (
            attr_name in ("urlopen", "urlretrieve", "HTTPConnection", "HTTPSConnection", "create_connection")
            or func_name
            in (
                "urllib.request.Request",
                "requests.get",
                "requests.post",
                "requests.put",
                "requests.delete",
                "requests.patch",
                "requests.request",
                "httpx.get",
                "httpx.post",
                "httpx.put",
                "httpx.request",
                "httpx.Client",
                "httpx.AsyncClient",
                "aiohttp.ClientSession",
                "socket.socket",
                "socket.create_connection",
            )
        ):
            net_call_lines.append(lineno)

    if has_b64_or_decompress and has_dynamic_exec:
        report.add(
            "BLOCK",
            "PY_AST_B64_EXEC_CHAIN",
            rel_path,
            f"Python AST combines payload decode/decompression and dynamic eval/exec (lines {exec_lines[:5]})",
            "Remove obfuscated payload execution; keep script logic inspectable.",
        )
    elif has_dynamic_exec:
        report.add(
            "WARN",
            "PY_AST_DYNAMIC_EXEC",
            rel_path,
            f"Python script calls dynamic eval/exec at lines {exec_lines[:5]}",
            "Review script source and confirm dynamic execution is expected.",
        )

    if shell_true_lines:
        dedup_lines = list(dict.fromkeys(shell_true_lines))
        report.add(
            "WARN",
            "PY_AST_SHELL_EXEC",
            rel_path,
            f"Python script invokes OS shell or command interpreter at lines {dedup_lines[:5]}",
            "Prefer direct argument-array subprocess calls without shell interpreters or confirm execution.",
        )

    if env_or_cred_lines and net_call_lines:
        dedup_env = list(dict.fromkeys(env_or_cred_lines))
        dedup_net = list(dict.fromkeys(net_call_lines))
        report.add(
            "BLOCK",
            "PY_AST_ENV_NETWORK_EXFIL",
            rel_path,
            f"Python AST combines environment/credential access (lines {dedup_env[:5]}) with outbound network I/O (lines {dedup_net[:5]})",
            "Remove combined environment/credential reads and outbound network transmission.",
        )

    if net_call_lines:
        report.add(
            "INFO",
            "PY_AST_NETWORK_IO",
            rel_path,
            f"Script performs outbound HTTP/network calls at lines {net_call_lines[:5]}",
        )
    return True


def _coerce_virtual_entry(item: Union[VirtualFileEntry, Dict[str, Any]]) -> VirtualFileEntry:
    if isinstance(item, VirtualFileEntry):
        return item
    return VirtualFileEntry(
        rel_path=str(item.get("rel_path", "")),
        raw_bytes=item.get("raw_bytes"),
        is_symlink=bool(item.get("is_symlink", False)),
        symlink_escapes=bool(item.get("symlink_escapes", False)),
        path_traversal=bool(item.get("path_traversal", False)),
        oversized=bool(item.get("oversized", False)),
        actual_size=int(item.get("actual_size", 0) or 0),
    )


def audit_package_entries(
    skill_name: Union[str, Sequence[VirtualFileEntry]],
    entries: Union[Sequence[VirtualFileEntry], str] = (),
    config: Optional[SkillsConfig] = None,
) -> SecurityAuditReport:
    """Perform 3-tier context-aware supply-chain vetting over virtual package entries."""
    _ = config
    if isinstance(skill_name, str):
        resolved_name = skill_name or "unknown-skill"
        resolved_entries: Sequence[Any] = () if isinstance(entries, str) else entries
    else:
        resolved_entries = skill_name
        resolved_name = entries if (isinstance(entries, str) and entries) else "unknown-skill"

    report = SecurityAuditReport(skill_name=resolved_name, verdict="INFO")

    for raw_entry in resolved_entries:
        entry = _coerce_virtual_entry(raw_entry)
        raw_rel = entry.rel_path
        rel = raw_rel.replace("\\", "/")

        if entry.path_traversal or _is_unsafe_rel_path(raw_rel):
            report.add(
                "BLOCK",
                "ARCHIVE_PATH_TRAVERSAL",
                rel,
                "Path contains '..', leading root slash, drive qualifier, or invalid control character",
                "Repackage skill with clean relative paths strictly inside the skill directory.",
            )
            continue

        if entry.is_symlink:
            sym_esc = entry.symlink_escapes
            if not sym_esc and entry.raw_bytes is not None:
                target_guess = decode_text_with_bom_and_cookie(entry.raw_bytes)
                sym_esc = _does_symlink_escape_root(rel, target_guess)
            if sym_esc:
                report.add(
                    "BLOCK",
                    "SYMLINK_ESCAPE",
                    rel,
                    "Symlink or junction inside package resolves outside the skill root",
                    "Replace external symlinks with self-contained files inside the skill package.",
                )
                continue
            report.add(
                "INFO",
                "INTERNAL_SYMLINK_ENTRY",
                rel,
                "Internal relative symlink detected within skill root",
            )
            continue

        p = PurePosixPath(rel)
        parts = p.parts
        fname = p.name
        fname_low = fname.lower()
        ext = p.suffix.lower()
        rel_low = rel.lower()

        if entry.oversized:
            report.add(
                "WARN",
                "OVERSIZED_FILE_PARTIAL_SCAN",
                rel,
                f"File size ({entry.actual_size or len(entry.raw_bytes or b'')} bytes) exceeds single-file scan limit; head/tail partial scan performed",
                "Inspect oversized file manually or move large binary data outside skill scripts.",
            )

        # Runtime bytecode & cache artifacts
        if "__pycache__" in parts:
            _append_unique(report.stripped_files, rel)
            report.add(
                "INFO",
                "STRIP_PYCACHE_ON_INSTALL",
                rel,
                "Runtime __pycache__ artifact; queued in stripped_files for automatic cleanup",
            )
            continue

        if ext in (".pyc", ".pyo"):
            report.add(
                "BLOCK",
                "SOURCELESS_BYTECODE_SMUGGLING",
                rel,
                f"Compiled Python bytecode '{ext}' placed outside __pycache__",
                "Ship inspectable .py source files instead of precompiled bytecode.",
            )
            continue

        # ClawHub injected _meta.json & top-level redundant repo docs -> stripped_files (INFO)
        if len(parts) == 1 and fname_low == "_meta.json":
            _append_unique(report.stripped_files, rel)
            report.add(
                "INFO",
                "STRIP_CLAWHUB_META",
                rel,
                "Registry-injected _meta.json queued in stripped_files to preserve clean tree fingerprint",
            )
            continue

        if len(parts) == 1 and fname_low in ("readme.md", "changelog.md"):
            _append_unique(report.stripped_files, rel)
            report.add(
                "INFO",
                "REDUNDANT_REPO_DOC",
                rel,
                "Top-level repository doc queued in stripped_files for canonical install",
            )

        # Bundled .env credential check
        if fname_low == ".env" or (
            fname_low.startswith(".env.")
            and not fname_low.endswith((".example", ".sample", ".template", ".dist"))
        ):
            txt_env = decode_text_with_bom_and_cookie(entry.raw_bytes or b"", ext)
            if _has_populated_dotenv_secret(txt_env, fname_low=fname_low):
                report.add(
                    "BLOCK",
                    "BUNDLED_DOTENV_SECRET",
                    rel,
                    "Skill package bundles a populated .env credential file",
                    "Remove .env secrets and declare required variable names in SKILL.md metadata.",
                )
            else:
                _append_unique(report.stripped_files, rel)
                report.add("INFO", "EMPTY_OR_TEMPLATE_DOTENV", rel, "Empty/non-secret .env noted for cleanup")
            continue

        # Native binary extension gate
        if ext in _NATIVE_BIN_EXTS:
            report.add(
                "BLOCK",
                "NATIVE_BINARY_FORBIDDEN",
                rel,
                f"Native binary extension '{ext}' is forbidden in portable skill packages",
                "Remove compiled native binaries and use standard runtime scripts or declared dependencies.",
            )
            continue

        raw_bytes = entry.raw_bytes
        has_shebang = bool(raw_bytes and raw_bytes.startswith(b"#!"))
        in_exec_folder = rel_low.startswith(("scripts/", "bin/", "hooks/"))
        is_code_file = (
            ext in _CODE_EXTS
            or has_shebang
            or (in_exec_folder and ext not in _PASSIVE_DATA_EXTS and not (raw_bytes and _is_genuine_binary_asset(raw_bytes)))
            or (rel_low.startswith("src/") and ext not in _PASSIVE_DATA_EXTS and ext not in _SKIP_TEXT_SCAN_EXTS)
        )
        if is_code_file:
            _append_unique(report.scripts_detected, rel)

        if not raw_bytes:
            continue

        # Magic header binary smuggling gate (PE / ELF / Mach-O / Wasm)
        matched_magic: Optional[str] = None
        if _matches_pe_magic(raw_bytes):
            matched_magic = "Windows PE binary (MZ header)"
        else:
            for magic, desc in _MAGIC_HEADERS:
                if raw_bytes.startswith(magic):
                    matched_magic = desc
                    break

        if matched_magic is not None:
            report.add(
                "BLOCK",
                "BINARY_MAGIC_HEADER",
                rel,
                f"File header matches {matched_magic}",
                "Remove disguised native binary executables from the skill package.",
            )
            continue

        # Only skip text scanning for passive asset extensions when outside script folders AND genuinely binary
        if ext in _SKIP_TEXT_SCAN_EXTS and not in_exec_folder and _is_genuine_binary_asset(raw_bytes):
            continue

        text = decode_text_with_bom_and_cookie(raw_bytes, ext)

        is_python_file = ext in (".py", ".pyw") or (has_shebang and b"python" in raw_bytes[:80].lower())
        if is_python_file:
            bad_py_enc = _detect_obfuscated_python_encoding(raw_bytes, text)
            if bad_py_enc:
                report.add(
                    "BLOCK",
                    "OBFUSCATED_PYTHON_ENCODING",
                    rel,
                    f"Python file declares obfuscated PEP 263 encoding cookie '{bad_py_enc}'",
                    "Encode Python scripts as plain UTF-8 without obfuscated codec headers.",
                )

        # Invisible Unicode BiDi / Tag block steganography
        if _BIDI_AND_UNICODE_TAG_RE.search(text):
            report.add(
                "BLOCK",
                "UNICODE_BIDI_OR_TAG_STEALTH",
                rel,
                "Invisible BiDi control or Unicode Tag block characters detected",
                "Strip invisible directional override and U+E0000 tag characters.",
            )

        # Covert directives hidden inside rendered-invisible HTML comments
        unquoted_surface = (
            _strip_visible_markdown_code(text)
            if ext in {".md", ".mdx", ".markdown", ".html", ".htm"}
            else text
        )
        for cm in _HTML_COMMENT_RE.finditer(unquoted_surface):
            normalized_comment = _ZERO_WIDTH_OBFUSCATION_RE.sub("", cm.group(1))
            if _HIDDEN_COMMENT_DIRECTIVE_RE.search(normalized_comment):
                report.add(
                    "BLOCK",
                    "HIDDEN_HTML_COMMENT_DIRECTIVE",
                    rel,
                    "Invisible HTML comment contains covert prompt override, secret read, or remote URL",
                    "Remove hidden instructions from HTML comments.",
                )
                break

        # Plaintext private keys & live API tokens
        if _PRIV_KEY_BLOCK_RE.search(text):
            report.add(
                "BLOCK",
                "PLAINTEXT_PRIVATE_KEY",
                rel,
                "PEM/OpenSSH private key block detected",
                "Remove private keys from skill files immediately.",
            )
        for key_label, key_re in _LIVE_KEY_PATTERNS:
            for km in key_re.finditer(text):
                tok = km.group(0)
                if _looks_like_real_secret(tok):
                    report.add(
                        "BLOCK",
                        f"PLAINTEXT_{key_label}",
                        rel,
                        f"Non-placeholder {key_label} credential detected (len={len(tok)})",
                        "Replace hardcoded credentials with environment variable lookups.",
                    )
                    break

        is_skill_md = fname_low in ("skill.md", "skills.md")

        if is_code_file:
            if _REMOTE_URL_PIPE_EXEC_RE.search(text):
                report.add(
                    "BLOCK",
                    "SCRIPT_REMOTE_PIPE_EXEC",
                    rel,
                    "Executable script pipes or substitutes a remote HTTP(S) URL directly into shell/iex",
                    "Download static verified artifacts or declare dependencies explicitly instead of remote pipe-to-shell.",
                )
            if _SCRIPT_CRED_HARVEST_RE.search(text):
                report.add(
                    "BLOCK",
                    "SCRIPT_CREDENTIAL_HARVEST",
                    rel,
                    "Executable script accesses SSH/Claude/MCP/AWS/npmrc/netrc credentials, browser Login Data/Cookies, or OS Keychain",
                    "Remove host credential store reads from skill scripts.",
                )
            if is_python_file:
                parsed_ok = _analyze_python_ast(
                    None if entry.oversized else raw_bytes,
                    text,
                    rel,
                    report,
                )
                if not parsed_ok and _SHELL_OR_SCRIPT_B64_EXEC_RE.search(text):
                    report.add(
                        "BLOCK",
                        "SCRIPT_B64_EXEC_CHAIN",
                        rel,
                        "Executable script decodes Base64 payload directly into shell/eval/exec/iex",
                        "Remove Base64-obfuscated execution chains.",
                    )
            else:
                if _SHELL_OR_SCRIPT_B64_EXEC_RE.search(text):
                    report.add(
                        "BLOCK",
                        "SCRIPT_B64_EXEC_CHAIN",
                        rel,
                        "Executable script decodes Base64 payload directly into shell/eval/exec/iex",
                        "Remove Base64-obfuscated execution chains.",
                    )

        elif is_skill_md:
            if _REMOTE_URL_PIPE_EXEC_RE.search(text):
                report.add(
                    "WARN",
                    "SKILL_MD_REMOTE_INSTALLER",
                    rel,
                    "SKILL.md contains a concrete remote HTTP(S) shell/PowerShell installer command; user confirmation required",
                    "Verify the installer domain and command before enabling or running setup.",
                )
            if _SHELL_OR_SCRIPT_B64_EXEC_RE.search(text):
                report.add(
                    "BLOCK",
                    "SKILL_MD_OBFUSCATED_EXEC",
                    rel,
                    "SKILL.md instructs decoding a Base64 payload directly into shell/eval/exec",
                    "Remove obfuscated Base64 execution instructions from SKILL.md.",
                )

    if report.scripts_detected:
        preview_list = ", ".join(report.scripts_detected[:5])
        report.add(
            "WARN",
            "BUNDLED_EXECUTABLE_SCRIPT",
            report.scripts_detected[0],
            f"Skill package includes executable script(s) ({len(report.scripts_detected)}: {preview_list}); user confirmation required",
            "Review bundled scripts before confirming installation.",
        )

    return report


def _detect_zip_strip_prefix(safe_file_paths: Sequence[str], subpath: str) -> Optional[str]:
    """Resolve optional archive wrapper prefix (e.g. GitHub codeload `<repo>-<sha>/`) + `subpath`."""
    sub_clean = subpath.strip().replace("\\", "/").strip("/")
    if sub_clean:
        if _is_unsafe_rel_path(sub_clean):
            raise ZipSecurityLimitError(f"Unsafe archive subpath requested: {subpath!r}")

    if not safe_file_paths:
        return f"{sub_clean}/" if sub_clean else ""

    # Determine if all safe files share a single top-level wrapper folder (like `repo-main/...`)
    first_segs: Set[str] = set()
    all_nested = True
    has_root_skill_md = False
    for p in safe_file_paths:
        parts = [seg for seg in p.split("/") if seg and seg != "."]
        if not parts:
            continue
        if len(parts) == 1 and parts[0].lower() in ("skill.md", "skills.md"):
            has_root_skill_md = True
        if len(parts) < 2:
            all_nested = False
        first_segs.add(parts[0])

    common_top: Optional[str] = None
    if all_nested and len(first_segs) == 1:
        candidate = next(iter(first_segs))
        if candidate.lower() not in _RESERVED_SKILL_SUBDIRS:
            common_top = candidate

    if sub_clean:
        direct_prefix = f"{sub_clean}/"
        if any(p.startswith(direct_prefix) for p in safe_file_paths):
            return direct_prefix
        if common_top is not None:
            wrapped_prefix = f"{common_top}/{sub_clean}/"
            if any(p.startswith(wrapped_prefix) for p in safe_file_paths):
                return wrapped_prefix
        return None

    if not has_root_skill_md and common_top is not None:
        return f"{common_top}/"
    return ""


def _strip_dot_slash(path_str: str) -> str:
    out = path_str
    while out.startswith("./"):
        out = out[2:]
    return out


def extract_zip_to_virtual_entries(
    zip_bytes: bytes,
    subpath: str = "",
    config: Optional[SkillsConfig] = None,
) -> List[VirtualFileEntry]:
    """Safely unpack a ZIP archive in memory into VirtualFileEntry items with ZipBomb/ZipSlip/Symlink guards."""
    cfg = config or SkillsConfig()
    if len(zip_bytes) > cfg.max_archive_bytes:
        raise ZipSecurityLimitError(
            f"Archive size {len(zip_bytes)} bytes exceeds max_archive_bytes ({cfg.max_archive_bytes})"
        )

    try:
        zf_ctx = zipfile.ZipFile(io.BytesIO(zip_bytes), "r")
    except (zipfile.BadZipFile, OSError) as exc:
        raise ZipSecurityLimitError(f"Invalid or corrupted ZIP archive: {exc}") from exc

    with zf_ctx as zf:
        infos = zf.infolist()
        sub_clean = subpath.strip().replace("\\", "/").strip("/")
        if sub_clean and _is_unsafe_rel_path(sub_clean):
            raise ZipSecurityLimitError(f"Unsafe archive subpath requested: {subpath!r}")

        # Hard ceiling on raw central-directory headers even when filtering a monorepo subpath
        header_ceiling = cfg.max_file_count if not sub_clean else max(cfg.max_file_count * 40, 20_000)
        non_dir_infos: List[zipfile.ZipInfo] = [
            inf for inf in infos if not inf.filename.endswith(("/", "\\")) and not inf.is_dir()
        ]
        if not sub_clean and len(non_dir_infos) > cfg.max_file_count:
            raise ZipSecurityLimitError(
                f"ZIP entry count {len(non_dir_infos)} exceeds max_file_count ({cfg.max_file_count})"
            )
        if len(infos) > max(header_ceiling * 2, cfg.max_file_count + 64):
            raise ZipSecurityLimitError(
                f"ZIP central directory count {len(infos)} exceeds safety ceiling"
            )

        safe_paths: List[str] = []
        for inf in non_dir_infos:
            if not _is_unsafe_rel_path(inf.filename):
                safe_paths.append(_strip_dot_slash(inf.filename.replace("\\", "/")))

        strip_prefix = _detect_zip_strip_prefix(safe_paths, sub_clean)
        entries: List[VirtualFileEntry] = []
        extracted_count = 0
        total_extracted_bytes = 0

        for inf in non_dir_infos:
            raw_name = inf.filename
            trav = _is_unsafe_rel_path(raw_name)
            norm_name = raw_name.replace("\\", "/")

            if not trav:
                clean_norm = _strip_dot_slash(norm_name)
                if strip_prefix is None:
                    continue
                if strip_prefix:
                    if not clean_norm.startswith(strip_prefix):
                        continue
                    rel_out = clean_norm[len(strip_prefix) :]
                    if not rel_out:
                        continue
                else:
                    rel_out = clean_norm
            else:
                # Never hide traversal entries behind subpath filtering; preserve for BLOCK report
                rel_out = norm_name

            extracted_count += 1
            if extracted_count > cfg.max_file_count:
                raise ZipSecurityLimitError(
                    f"Extracted file count {extracted_count} exceeds max_file_count ({cfg.max_file_count})"
                )

            if inf.file_size > cfg.max_single_file_bytes:
                raise ZipSecurityLimitError(
                    f"Entry '{rel_out}' declared size {inf.file_size} exceeds max_single_file_bytes ({cfg.max_single_file_bytes})"
                )
            if total_extracted_bytes + inf.file_size > cfg.max_extracted_bytes:
                raise ZipSecurityLimitError(
                    f"Cumulative declared archive bytes exceed max_extracted_bytes ({cfg.max_extracted_bytes})"
                )

            # Stream-read with +1 byte sentinel to defeat spoofed ZipInfo.file_size headers
            with zf.open(inf, "r") as member_fp:
                data = member_fp.read(cfg.max_single_file_bytes + 1)
            if len(data) > cfg.max_single_file_bytes:
                raise ZipSecurityLimitError(
                    f"Entry '{rel_out}' decompressed size exceeds max_single_file_bytes ({cfg.max_single_file_bytes})"
                )

            total_extracted_bytes += len(data)
            if total_extracted_bytes > cfg.max_extracted_bytes:
                raise ZipSecurityLimitError(
                    f"Cumulative extracted bytes {total_extracted_bytes} exceed max_extracted_bytes ({cfg.max_extracted_bytes})"
                )

            unix_mode = (inf.external_attr >> 16) & 0o170000
            is_sym = unix_mode == 0o120000
            sym_esc = False
            if is_sym:
                target_str = decode_text_with_bom_and_cookie(data)
                sym_esc = trav or _does_symlink_escape_root(rel_out, target_str)

            entries.append(
                VirtualFileEntry(
                    rel_path=rel_out,
                    raw_bytes=data,
                    is_symlink=is_sym,
                    symlink_escapes=sym_esc,
                    path_traversal=trav,
                )
            )

    return entries


def _read_partial_head_tail(fp: Path, file_size: int, window_bytes: int) -> bytes:
    """Read head and tail slices of an oversized local file so tail-appended payloads are still scanned."""
    half = max(4096, min(window_bytes // 2, 262_144))
    with fp.open("rb") as fh:
        head = fh.read(half)
        if file_size <= half:
            return head
        seek_pos = max(half, file_size - half)
        fh.seek(seek_pos)
        tail = fh.read(half)
    return head + b"\n" + tail


def _collect_local_dir_entries(
    skill_dir: Path,
    config: Optional[SkillsConfig] = None,
) -> List[VirtualFileEntry]:
    cfg = config or SkillsConfig()
    base = Path(skill_dir)
    if not base.exists() or not base.is_dir():
        raise FileNotFoundError(f"Skill directory does not exist: {base}")

    root_real = os.path.realpath(str(base))
    entries: List[VirtualFileEntry] = []
    total_bytes = 0

    for cur_root, dirnames, filenames in os.walk(str(base), topdown=True, followlinks=False):
        cur_path = Path(cur_root)

        # Inspect directory symlinks / NTFS junctions before pruning descent
        kept_dirs: List[str] = []
        for dname in sorted(dirnames):
            if dname in _LOCAL_WALK_SKIP_DIRS:
                continue
            dp = cur_path / dname
            rel_dir = dp.relative_to(base).as_posix()
            if is_link_or_junction(dp):
                esc = not is_subpath(dp, root_real)
                entries.append(
                    VirtualFileEntry(
                        rel_path=rel_dir,
                        raw_bytes=None,
                        is_symlink=True,
                        symlink_escapes=esc,
                        path_traversal=False,
                    )
                )
                continue
            kept_dirs.append(dname)
        dirnames[:] = kept_dirs

        for fname in sorted(filenames):
            fp = cur_path / fname
            rel_file = fp.relative_to(base).as_posix()
            is_lnk = is_link_or_junction(fp)
            esc = False
            if is_lnk:
                esc = not is_subpath(fp, root_real)
                entries.append(
                    VirtualFileEntry(
                        rel_path=rel_file,
                        raw_bytes=None,
                        is_symlink=True,
                        symlink_escapes=esc,
                        path_traversal=False,
                    )
                )
                continue

            raw_b: Optional[bytes] = None
            is_oversized = False
            f_size = 0
            try:
                st = fp.stat()
                f_size = int(st.st_size)
                if f_size <= cfg.max_single_file_bytes and (total_bytes + f_size) <= cfg.max_extracted_bytes:
                    raw_b = fp.read_bytes()
                    total_bytes += len(raw_b)
                else:
                    is_oversized = True
                    raw_b = _read_partial_head_tail(fp, f_size, cfg.max_single_file_bytes)
                    total_bytes += len(raw_b)
            except OSError:
                raw_b = None

            entries.append(
                VirtualFileEntry(
                    rel_path=rel_file,
                    raw_bytes=raw_b,
                    is_symlink=False,
                    symlink_escapes=False,
                    path_traversal=False,
                    oversized=is_oversized,
                    actual_size=f_size,
                )
            )

    return entries


def audit_skill_directory(
    skill_dir: Path,
    skill_name: str = "",
    config: Optional[SkillsConfig] = None,
) -> SecurityAuditReport:
    """Scan a local skill directory into VirtualFileEntry items and run 3-tier vetting."""
    target = Path(skill_dir)
    resolved_name = skill_name.strip() or target.name
    entries = _collect_local_dir_entries(target, config=config)
    return audit_package_entries(resolved_name, entries, config=config)
