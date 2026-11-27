#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Filesystem I/O, encoding & CRLF fidelity, staged syntax guard, large-file streaming, and image header primitives.

Pure Python >=3.9 standard-library implementation:
1. Multi-encoding detection & round-trip writeback (`UTF-8`, `UTF-8-BOM`, `UTF-16LE/BE` with/without BOM, `GB18030`),
   plus explicit `encoding="base64"` binary decode writeback.
2. Dominant line-ending & per-line mixed `CRLF/LF` preservation without collateral diffs.
3. Office exclusive lock (`~$*`, `.~lock.*#`) & OS `PermissionError` sharing-violation clear Chinese diagnostics.
4. Same-volume externalized staging syntax precheck (`.py` `compile`+`ast.parse`, `.json`/JSONC comment stripping,
   `.toml`, optional Node ESM `node --check` with `CREATE_NO_WINDOW`) & 6-retry backoff `os.replace` preserving `0o755`.
5. >50% single-overwrite shrinkage truncation guard (`allow_shrink=False` default).
6. Constant-memory `start_line`/`end_line` (and negative tail) streaming slice reader for >2 MiB files.
7. Pure-stdlib PNG / JPEG / WebP / GIF / BMP header width & height parser.
"""
from __future__ import annotations

import ast
import base64
import binascii
import codecs
import contextlib
import ctypes
import difflib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
import zlib

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

from .fs_tx import (
    OFFICE_DOC_EXTS,
    _ensure_undo_dir,
    _find_office_temp_lock_file,
    check_office_or_os_file_lock,
    find_office_temp_lock_file,
    get_file_lock,
    pop_latest_undo_entry_quiet,
    record_file_creation_undo,
    resolve_same_volume_staging_dir,
    resolve_undo_dir,
    save_undo_snapshot,
    should_skip_undo_snapshot,
)

from .guard import CREATE_NO_WINDOW

_SUBPROCESS_FLAGS: int = CREATE_NO_WINDOW if sys.platform == "win32" else 0


def _ensure_win_error_mode() -> None:
    if sys.platform == "win32":
        with contextlib.suppress(Exception):
            ctypes.windll.kernel32.SetErrorMode(0x8003)

UTF8_BOM: bytes = b"\xef\xbb\xbf"
UTF16_LE_BOM: bytes = b"\xff\xfe"
UTF16_BE_BOM: bytes = b"\xfe\xff"

MAX_DEFAULT_READ_BYTES: int = 2 * 1024 * 1024  # 2 MiB
MIN_SHRINK_GUARD_BYTES: int = 200

IMAGE_EXTENSIONS: frozenset[str] = frozenset({".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"})
MAX_RAW_IMAGE_BYTES: int = 2 * 1024 * 1024
MAX_IMAGE_HEADER_SCAN_BYTES: int = 512 * 1024


# ---------------------------------------------------------------------------
# 1. Multi-Encoding Detection & Round-Trip Encoding
# ---------------------------------------------------------------------------


def _is_plausible_utf16_text(txt_cand: str) -> bool:
    if not txt_cand or "\x00" in txt_cand:
        return False
    sample = txt_cand[:2048]
    good = 0
    for ch in sample:
        cp = ord(ch)
        if (
            ch in ("\r", "\n", "\t")
            or 0x20 <= cp <= 0x7E
            or 0x00A0 <= cp <= 0x024F
            or 0x3000 <= cp <= 0x303F
            or 0x4E00 <= cp <= 0x9FFF
            or 0xFF00 <= cp <= 0xFFEF
        ):
            good += 1
    return good >= max(1, int(len(sample) * 0.85))


def detect_and_decode_bytes(raw_bytes: bytes, strict_for_edit: bool = False) -> Tuple[str, str]:
    """
    Auto-detect `utf-8-sig` (UTF-8-BOM), `utf-8`, `utf-16-le-bom`, `utf-16-be-bom`,
    `utf-16-le`, `utf-16-be`, or `gb18030` without silent U+FFFD corruption.
    """
    if not raw_bytes:
        return "", "utf-8"
    if raw_bytes.startswith(UTF8_BOM):
        try:
            return raw_bytes[len(UTF8_BOM) :].decode("utf-8"), "utf-8-sig"
        except UnicodeDecodeError:
            pass
    if raw_bytes.startswith(UTF16_LE_BOM):
        try:
            return raw_bytes[len(UTF16_LE_BOM) :].decode("utf-16-le"), "utf-16-le-bom"
        except UnicodeDecodeError:
            pass
    if raw_bytes.startswith(UTF16_BE_BOM):
        try:
            return raw_bytes[len(UTF16_BE_BOM) :].decode("utf-16-be"), "utf-16-be-bom"
        except UnicodeDecodeError:
            pass

    # Pure UTF-8 text never contains NUL bytes; BOM-less UTF-16LE/BE ASCII contains NUL in every character.
    has_nul_head = b"\x00" in raw_bytes[:8192]
    if not has_nul_head:
        try:
            return raw_bytes.decode("utf-8"), "utf-8"
        except UnicodeDecodeError:
            pass

    if len(raw_bytes) >= 2 and len(raw_bytes) % 2 == 0:
        sample = raw_bytes[:4096]
        half_n = max(1, len(sample) // 2)
        even_nuls = sum(1 for b in sample[0::2] if b == 0)
        odd_nuls = sum(1 for b in sample[1::2] if b == 0)

        if (odd_nuls >= half_n * 0.20 and even_nuls <= half_n * 0.10) or (
            odd_nuls >= 1 and odd_nuls > even_nuls
        ):
            try:
                dec_le = raw_bytes.decode("utf-16-le")
                if _is_plausible_utf16_text(dec_le):
                    return dec_le, "utf-16-le"
            except UnicodeDecodeError:
                pass
        if (even_nuls >= half_n * 0.20 and odd_nuls <= half_n * 0.10) or (
            even_nuls >= 1 and even_nuls > odd_nuls
        ):
            try:
                dec_be = raw_bytes.decode("utf-16-be")
                if _is_plausible_utf16_text(dec_be):
                    return dec_be, "utf-16-be"
            except UnicodeDecodeError:
                pass

    if not has_nul_head:
        try:
            return raw_bytes.decode("gb18030"), "gb18030"
        except UnicodeDecodeError:
            pass

    if strict_for_edit:
        raise ValueError(
            "File contains non-text binary or undecodable bytes (failed UTF-8, UTF-16, and GB18030 decoding); "
            "refusing text modification to prevent silent character corruption."
        )
    return raw_bytes.decode("utf-8", errors="replace"), "binary-fallback"


def encode_with_detected_encoding(text: str, encoding_tag: str) -> bytes:
    """Encode `text` back into `encoding_tag`, preserving BOMs accurately without duplication."""
    tag = (encoding_tag or "utf-8").strip().lower()
    clean = text[1:] if text.startswith("\ufeff") else text
    if tag in ("utf-8-sig", "utf-8-bom"):
        return UTF8_BOM + clean.encode("utf-8")
    if tag == "utf-16-le-bom":
        return UTF16_LE_BOM + clean.encode("utf-16-le")
    if tag == "utf-16-be-bom":
        return UTF16_BE_BOM + clean.encode("utf-16-be")
    if tag in ("utf-16-le", "utf-16le"):
        return clean.encode("utf-16-le")
    if tag in ("utf-16-be", "utf-16be"):
        return clean.encode("utf-16-be")
    if tag in ("gb18030", "gbk", "gb2312"):
        return clean.encode("gb18030")
    if tag in ("", "utf-8", "utf8"):
        return clean.encode("utf-8")
    return clean.encode(tag)


def decode_base64_payload(content: str) -> bytes:
    """Decode standard or data-URI Base64 string into raw binary bytes."""
    raw_b64 = (content or "").strip()
    if raw_b64.startswith("data:") and ";base64," in raw_b64[:160]:
        raw_b64 = raw_b64.split(";base64,", 1)[1]
    compact = re.sub(r"\s+", "", raw_b64)
    if not compact:
        return b""
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"Invalid base64 content: {exc}") from exc


# ---------------------------------------------------------------------------
# 2. Dominant & Mixed CRLF/LF Line-Ending Preservation
# ---------------------------------------------------------------------------


def detect_dominant_crlf(text: str) -> bool:
    crlf_n = text.count("\r\n")
    lf_only_n = text.count("\n") - crlf_n
    return crlf_n > 0 and crlf_n >= lf_only_n


_detect_dominant_crlf = detect_dominant_crlf


def restore_line_endings(lf_text: str, use_crlf: bool) -> str:
    norm = lf_text.replace("\r\n", "\n")
    return norm.replace("\n", "\r\n") if use_crlf else norm


_restore_line_endings = restore_line_endings


def split_lines_exact_nl(text: str) -> List[str]:
    if not text:
        return []
    return re.findall(r"[^\n]*\n|[^\n]+", text)


_split_lines_exact_nl = split_lines_exact_nl


def preserve_line_endings_for_edit(raw_text: str, new_content_lf: str) -> str:
    """
    Preserve per-line CRLF/LF on untouched lines (zero collateral git diff on mixed CRLF/LF files)
    and apply local/dominant line ending on modified or inserted lines.
    """
    norm_new = new_content_lf.replace("\r\n", "\n")
    if not raw_text:
        return norm_new
    crlf_n = raw_text.count("\r\n")
    lf_only_n = raw_text.count("\n") - crlf_n
    dominant_crlf = crlf_n > 0 and crlf_n >= lf_only_n
    if crlf_n == 0:
        return norm_new
    if lf_only_n == 0:
        return norm_new.replace("\n", "\r\n")

    orig_raw_lines = split_lines_exact_nl(raw_text)
    orig_lf_lines = [ln.replace("\r\n", "\n") for ln in orig_raw_lines]
    new_lf_lines = split_lines_exact_nl(norm_new)
    sm = difflib.SequenceMatcher(None, orig_lf_lines, new_lf_lines, autojunk=False)
    out_parts: List[str] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            out_parts.extend(orig_raw_lines[i1:i2])
        elif j2 > j1:
            ctx_slice = orig_raw_lines[i1:i2]
            if not ctx_slice and orig_raw_lines:
                neighbor_idx = min(max(0, i1 - 1), len(orig_raw_lines) - 1)
                ctx_slice = [orig_raw_lines[neighbor_idx]]
            c_crlf = sum(1 for x in ctx_slice if x.endswith("\r\n"))
            c_lf = sum(1 for x in ctx_slice if x.endswith("\n") and not x.endswith("\r\n"))
            local_crlf = (c_crlf >= c_lf) if (c_crlf + c_lf) > 0 else dominant_crlf
            for nln in new_lf_lines[j1:j2]:
                if local_crlf and nln.endswith("\n") and not nln.endswith("\r\n"):
                    out_parts.append(nln[:-1] + "\r\n")
                else:
                    out_parts.append(nln)
    return "".join(out_parts)


def prepare_write_file_bytes(
    old_raw: bytes,
    existed_before: bool,
    content: str,
    mode: str = "overwrite",
    encoding: str = "",
) -> Dict[str, Any]:
    """Encode `write_file` payload preserving original encoding/CRLF or decoding `encoding='base64'` binary bytes."""
    explicit_enc = (encoding or "").strip().lower()
    if explicit_enc == "base64":
        decoded = decode_base64_payload(content)
        if mode == "overwrite":
            final_payload = decoded
        elif mode == "append":
            final_payload = (old_raw + decoded) if existed_before else decoded
        else:
            raise ValueError(f"Unsupported write mode {mode!r}: expected 'overwrite' or 'append'")
        return {
            "final_payload": final_payload,
            "encoding": "base64",
            "is_binary": True,
            "chunk_bytes": len(decoded),
            "bom_preserved": False,
        }

    if existed_before and old_raw:
        old_txt, detected_enc = detect_and_decode_bytes(old_raw, strict_for_edit=False)
    else:
        old_txt = ""
        detected_enc = "utf-8-sig" if content.startswith("\ufeff") else "utf-8"

    enc_tag = explicit_enc if explicit_enc else detected_enc

    if mode == "overwrite":
        if not explicit_enc and content.startswith("\ufeff") and enc_tag == "utf-8":
            enc_tag = "utf-8-sig"
        clean_in = content.removeprefix("\ufeff")
        if existed_before and old_txt:
            formatted = preserve_line_endings_for_edit(old_txt, clean_in)
        else:
            formatted = clean_in
        final_payload = encode_with_detected_encoding(formatted, enc_tag)
        chunk_len = len(final_payload)
    elif mode == "append":
        clean_append = content.removeprefix("\ufeff")
        use_crlf = detect_dominant_crlf(old_txt) or old_txt.endswith("\r\n")
        norm_append = restore_line_endings(clean_append, use_crlf)
        sep_s = ""
        if (
            old_txt
            and not old_txt.endswith(("\n", "\r"))
            and norm_append
            and not norm_append.startswith(("\n", "\r"))
        ):
            sep_s = "\r\n" if use_crlf else "\n"
        merged_txt = old_txt + sep_s + norm_append
        final_payload = encode_with_detected_encoding(merged_txt, enc_tag)
        chunk_len = max(0, len(final_payload) - len(old_raw))
    else:
        raise ValueError(f"Unsupported write mode {mode!r}: expected 'overwrite' or 'append'")

    return {
        "final_payload": final_payload,
        "encoding": enc_tag,
        "is_binary": False,
        "chunk_bytes": chunk_len,
        "bom_preserved": final_payload.startswith(UTF8_BOM) or enc_tag.endswith("-bom") or enc_tag == "utf-8-sig",
    }


# ---------------------------------------------------------------------------
# 3. Optimistic SHA-256 Lock Verification (Office/OS Lock Helpers Imported from `fs_tx`)
# ---------------------------------------------------------------------------


def verify_expected_sha256(file_bytes: bytes, expected_sha256: str) -> Optional[str]:
    exp = (expected_sha256 or "").strip().lower()
    if not exp:
        return None
    actual = hashlib.sha256(file_bytes).hexdigest().lower()
    if actual == exp or (len(exp) >= 8 and actual.startswith(exp)):
        return None
    return (
        f"[OPTIMISTIC LOCK CONFLICT]: File content changed since last read "
        f"(expected_sha256={exp}, actual_sha256={actual[:12]}). Re-read the target lines before editing."
    )


_verify_expected_sha256 = verify_expected_sha256


# ---------------------------------------------------------------------------
# 4. Syntax Validation (`.py` compile, `.json`/JSONC, `.toml`, Optional Node ESM) & Atomic Staging
# ---------------------------------------------------------------------------


def strip_jsonc_comments(text: str) -> str:
    """Strip `//` and `/* ... */` comments (preserving line numbers) and trailing commas outside JSON strings."""
    out: List[str] = []
    i, n, in_s = 0, len(text), False
    while i < n:
        ch = text[i]
        if in_s:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_s = False
            i += 1
            continue
        if ch == '"':
            in_s = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            i += 2
            while i < n and text[i] not in ("\n", "\r"):
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                if text[i] in ("\n", "\r"):
                    out.append(text[i])
                i += 1
            i = min(n, i + 2)
            continue
        out.append(ch)
        i += 1
    s2 = "".join(out)
    res: List[str] = []
    j, m, in_s2 = 0, len(s2), False
    while j < m:
        c = s2[j]
        if in_s2:
            res.append(c)
            if c == "\\" and j + 1 < m:
                res.append(s2[j + 1])
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
            while k < m and s2[k] in (" ", "\t", "\r", "\n"):
                k += 1
            if k < m and s2[k] in ("}", "]"):
                j += 1
                continue
        res.append(c)
        j += 1
    return "".join(res)


_strip_jsonc_for_syntax_check = strip_jsonc_comments


def _is_jsonc_config_path(p: Path) -> bool:
    name_l = p.name.lower()
    if p.suffix.lower() == ".jsonc":
        return True
    if name_l in (
        "tsconfig.json",
        "jsconfig.json",
        "devcontainer.json",
        "biome.json",
        "deno.json",
        "turbo.json",
        "tslint.json",
        "nx.json",
        "rush.json",
        ".eslintrc.json",
        ".babelrc.json",
    ):
        return True
    if name_l.startswith(("tsconfig.", "jsconfig.")) and name_l.endswith(".json"):
        return True
    parts_l = {pt.lower() for pt in p.parts}
    return bool(parts_l & {".vscode", ".devcontainer", ".zed"})


_ESM_SYNTAX_RE = re.compile(
    r"(?m)(?:^\s*import\s+(?:[\w*{]|['\"])|^\s*export\s+(?:default\b|const\b|let\b|var\b|function\b|async\b|class\b|\*|\{)|\bimport\.meta\b)"
)


def _strip_js_comments_light(src: str) -> str:
    def _repl(m: re.Match[str]) -> str:
        s = m.group(0)
        if s.startswith(('"', "'", "`")):
            return s
        return "\n" * s.count("\n")

    return re.sub(
        r"""(?:"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|`(?:\\.|[^`\\])*`|/\*[\s\S]*?\*/|//[^\r\n]*)""",
        _repl,
        src,
    )


def _nearest_package_json_type(target_p: Path) -> str:
    cur = target_p.parent
    for _ in range(8):
        pkg_f = cur / "package.json"
        with contextlib.suppress(Exception):
            if pkg_f.is_file() and pkg_f.stat().st_size <= 262144:
                doc = json.loads(pkg_f.read_text(encoding="utf-8-sig"))
                if isinstance(doc, dict) and isinstance(doc.get("type"), str):
                    return doc["type"].strip().lower()
        if cur.parent == cur:
            break
        cur = cur.parent
    return ""


def _detect_js_check_ext(target_p: Path, source_text: str) -> str:
    ext = target_p.suffix.lower()
    if ext == ".mjs":
        return ".mjs"
    if ext == ".cjs":
        return ".cjs"
    if _nearest_package_json_type(target_p) == "module":
        return ".mjs"
    if _ESM_SYNTAX_RE.search(_strip_js_comments_light(source_text)):
        return ".mjs"
    return ".js"


def _parse_and_clean_node_stderr(stderr_raw: str, display_label: str, line_offset_0based: int = 0) -> Tuple[int, int, str]:
    raw_lines = (stderr_raw or "").strip().splitlines()
    if not raw_lines:
        return 1 + line_offset_0based, 1, f"{display_label}: SyntaxError"

    js_line = 1
    js_col = 1
    header_idx = -1
    for idx, ln_s in enumerate(raw_lines[:4]):
        m_hdr = re.match(r"^(.+?):(\d+)(?::(\d+))?\s*$", ln_s.strip())
        if m_hdr and not ln_s.lstrip().startswith("at "):
            js_line = max(1, int(m_hdr.group(2)))
            if m_hdr.group(3):
                js_col = max(1, int(m_hdr.group(3)))
            header_idx = idx
            break

    if header_idx >= 0:
        for c_ln in raw_lines[header_idx + 1 : header_idx + 5]:
            if "^" in c_ln and c_ln.strip().startswith("^") and set(c_ln.strip()) <= {"^", "~"}:
                js_col = c_ln.index("^") + 1
                break

    eff_line = line_offset_0based + js_line
    cleaned_lines: List[str] = []
    for idx, ln_s in enumerate(raw_lines):
        st = ln_s.strip()
        if idx == header_idx:
            cleaned_lines.append(f"{display_label}:{eff_line}")
            continue
        if st.startswith("at ") or st.startswith("Node.js v"):
            continue
        cleaned_lines.append(ln_s)
    return eff_line, js_col, "\n".join(cleaned_lines).strip()[:360]


def check_js_syntax_with_node(
    target_p: Path,
    source_text: str,
    *,
    staged_file: Optional[Path] = None,
    display_path: Optional[str] = None,
    check_node: bool = True,
) -> Dict[str, Any]:
    """Validate JS / ESM syntax via `node --check` (with `CREATE_NO_WINDOW` and `.mjs` ESM auto-detection)."""
    if not check_node:
        return {"valid": True, "checker": "skipped_node_disabled", "skipped": True}
    node_bin = shutil.which("node")
    if not node_bin:
        return {"valid": True, "checker": "skipped_no_node", "skipped": True, "reason": "node not found in PATH"}

    disp = display_path or target_p.name
    clean_src = source_text.removeprefix("\ufeff")
    check_ext = _detect_js_check_ext(target_p, clean_src)
    cand_on_disk = staged_file.resolve() if staged_file is not None else target_p.resolve()
    _ensure_win_error_mode()

    if cand_on_disk.exists() and cand_on_disk.suffix.lower() == check_ext:
        r = subprocess.run(
            [node_bin, "--check", str(cand_on_disk)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            creationflags=_SUBPROCESS_FLAGS,
        )
    else:
        with tempfile.TemporaryDirectory() as tmp_dir:
            safe_stem = re.sub(r"[^A-Za-z0-9_.-]", "_", target_p.stem or "script")[:40]
            tmp_js = Path(tmp_dir) / f"check_{safe_stem}{check_ext}"
            tmp_js.write_bytes(clean_src.encode("utf-8"))
            r = subprocess.run(
                [node_bin, "--check", str(tmp_js)],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
                creationflags=_SUBPROCESS_FLAGS,
            )

    if r.returncode != 0:
        ln, col, clean_err = _parse_and_clean_node_stderr(r.stderr or "", disp)
        return {
            "valid": False,
            "checker": "node --check",
            "line": ln,
            "column": col,
            "error": clean_err,
        }
    return {"valid": True, "checker": "node --check"}


def auto_check_syntax(
    path_str: str | Path,
    content: Optional[str] = None,
    *,
    raw_bytes: Optional[bytes] = None,
    staged_file: Optional[Path] = None,
    display_path: Optional[str] = None,
    check_node: bool = True,
    allow_jsonc: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Fast syntax precheck on candidate text/bytes or staged file:
    - `.py` / `.pyi`: `ast.parse` + `compile(..., 'exec')`
    - `.json` / `.jsonc` (and JSONC config files): `json.loads` + comment/trailing-comma stripping
    - `.toml`: `tomllib.loads` (Python >=3.11)
    - `.js` / `.mjs` / `.cjs`: optional `node --check` with ESM `.mjs` detection & `CREATE_NO_WINDOW`
    """
    p = Path(path_str).resolve()
    ext = p.suffix.lower()
    check_file = staged_file.resolve() if staged_file is not None else p
    disp_label = display_path or p.name
    if content is None and raw_bytes is None and not check_file.exists():
        return {"valid": False, "error": "File does not exist for syntax check"}

    try:
        if ext in (".py", ".pyi"):
            if content is not None:
                source_text = content
            elif raw_bytes is not None:
                source_text, _ = detect_and_decode_bytes(raw_bytes, strict_for_edit=False)
            else:
                source_text, _ = detect_and_decode_bytes(check_file.read_bytes(), strict_for_edit=False)
            source_text = source_text.removeprefix("\ufeff")
            try:
                ast.parse(source_text, filename=str(p))
                compile(source_text, str(p), "exec")
            except SyntaxError as exc:
                ln_py = int(exc.lineno or 1)
                col_py = int(exc.offset or 1)
                return {
                    "valid": False,
                    "checker": "ast_compile",
                    "line": ln_py,
                    "column": col_py,
                    "error": f"{type(exc).__name__}: {exc.msg} (line {ln_py}, offset {col_py})",
                }
            except ValueError as exc:
                return {"valid": False, "checker": "ast_compile", "line": 1, "column": 1, "error": str(exc)}
            except RecursionError as exc:
                return {"valid": False, "checker": "ast_compile", "line": 1, "column": 1, "error": f"RecursionError: {exc}"}
            return {"valid": True, "checker": "ast_compile"}

        if ext in (".json", ".jsonc"):
            if content is not None:
                json_text = content.removeprefix("\ufeff")
            elif raw_bytes is not None:
                dec_txt, _ = detect_and_decode_bytes(raw_bytes, strict_for_edit=True)
                json_text = dec_txt.removeprefix("\ufeff")
            else:
                dec_txt, _ = detect_and_decode_bytes(check_file.read_bytes(), strict_for_edit=True)
                json_text = dec_txt.removeprefix("\ufeff")
            try:
                json.loads(json_text)
                return {"valid": True, "checker": "json.loads"}
            except json.JSONDecodeError as jexc:
                use_jsonc = bool(allow_jsonc) if allow_jsonc is not None else (ext == ".jsonc" or _is_jsonc_config_path(p))
                if use_jsonc:
                    try:
                        json.loads(strip_jsonc_comments(json_text))
                        return {"valid": True, "checker": "jsonc.loads"}
                    except json.JSONDecodeError as jexc2:
                        return {
                            "valid": False,
                            "checker": "jsonc.loads",
                            "line": int(jexc2.lineno or 1),
                            "column": int(jexc2.colno or 1),
                            "error": f"{jexc2.msg} (line {jexc2.lineno}, column {jexc2.colno})",
                        }
                return {
                    "valid": False,
                    "checker": "json.loads",
                    "line": int(jexc.lineno or 1),
                    "column": int(jexc.colno or 1),
                    "error": f"{jexc.msg} (line {jexc.lineno}, column {jexc.colno})",
                }

        if ext == ".toml" and tomllib is not None:
            if content is not None:
                toml_text = content.removeprefix("\ufeff")
            elif raw_bytes is not None:
                dec_t, _ = detect_and_decode_bytes(raw_bytes, strict_for_edit=False)
                toml_text = dec_t.removeprefix("\ufeff")
            else:
                dec_t, _ = detect_and_decode_bytes(check_file.read_bytes(), strict_for_edit=False)
                toml_text = dec_t.removeprefix("\ufeff")
            try:
                tomllib.loads(toml_text)
                return {"valid": True, "checker": "tomllib.loads"}
            except Exception as texc:
                return {"valid": False, "checker": "tomllib.loads", "line": 1, "column": 1, "error": f"TOMLDecodeError: {texc}"}

        if ext in (".js", ".mjs", ".cjs"):
            if content is not None:
                js_text = content
            elif raw_bytes is not None:
                js_text, _ = detect_and_decode_bytes(raw_bytes, strict_for_edit=False)
            else:
                js_text, _ = detect_and_decode_bytes(check_file.read_bytes(), strict_for_edit=False)
            return check_js_syntax_with_node(
                p, js_text, staged_file=staged_file, display_path=disp_label, check_node=check_node
            )

        return {"valid": True, "checker": "none", "skipped": True}
    except (UnicodeDecodeError, ValueError) as exc:
        return {"valid": False, "checker": "encoding", "line": 1, "column": 1, "error": str(exc)}
    except subprocess.TimeoutExpired as exc:
        return {"valid": False, "checker": "external_checker_timeout", "error": f"Syntax checker timed out ({exc})"}
    except OSError as exc:
        return {"valid": False, "checker": "io_error", "error": f"OSError: {exc}"}


def _same_filesystem(dir_a: Path, dir_b: Path) -> bool:
    from .fs_tx import _same_volume_st_dev

    return _same_volume_st_dev(dir_a, dir_b)


def atomic_validate_and_replace(
    target_p: str | Path,
    new_bytes: bytes,
    *,
    enforce_syntax: bool = True,
    check_node: bool = True,
    allow_jsonc: Optional[bool] = None,
    save_snapshot: bool = True,
    workspace_root: Optional[str | Path] = None,
    workspace_roots: Optional[Any] = None,
    undo_dir: Optional[str | Path] = None,
    state_root: Optional[str | Path] = None,
    guard: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Stage `new_bytes` in a same-volume directory outside user Git repositories, validate syntax BEFORE touching `target_p`,
    record externalized snapshot in `<state_root>/history/<workspace_hash>`, preserve executable permission bits (`0o755`),
    and commit with 6-retry backoff `os.replace`.
    """
    tp = Path(target_p).expanduser().resolve()
    with get_file_lock(tp):
        lock_block = check_office_or_os_file_lock(tp, exc=None, for_write=True)
        if lock_block is not None:
            return lock_block

        text_for_check, _ = detect_and_decode_bytes(new_bytes, strict_for_edit=False)
        ext = tp.suffix.lower()

        # 1) Fast in-memory syntax precheck BEFORE creating parent dirs, staging files, or snapshots
        syntax: Optional[Dict[str, Any]] = {"valid": True, "checker": "skipped"} if not enforce_syntax else None
        if enforce_syntax and ext in (".py", ".pyi", ".json", ".jsonc", ".toml"):
            syntax = auto_check_syntax(
                tp,
                content=text_for_check,
                raw_bytes=new_bytes,
                check_node=check_node,
                allow_jsonc=allow_jsonc,
            )
            if not syntax.get("valid", True):
                return {"ok": False, "auto_rolled_back": True, "syntax_check": syntax, "undo_snapshot": None}

        tp.parent.mkdir(parents=True, exist_ok=True)

        # 2) Same-volume externalized staging temp file preserving target suffix (never creating `.undo_history/` in workspace)
        stage_dir_opt = resolve_same_volume_staging_dir(
            tp,
            state_root=state_root,
            guard=guard,
            undo_dir=undo_dir,
        )
        stage_dir = stage_dir_opt if stage_dir_opt is not None else tp.parent
        stage_dir.mkdir(parents=True, exist_ok=True)

        stage_suffix = ext if re.fullmatch(r"\.[a-z0-9_]{1,16}", ext) else ".tmp"
        stage_file = stage_dir / f".cosmos_stage_{os.getpid()}_{threading.get_ident()}_{time.time_ns()}{stage_suffix}"

        orig_imode: Optional[int] = None
        with contextlib.suppress(OSError):
            st_orig = tp.lstat()
            if stat.S_ISREG(st_orig.st_mode):
                orig_imode = stat.S_IMODE(st_orig.st_mode)

        try:
            with stage_file.open("wb") as sf:
                sf.write(new_bytes)
                sf.flush()
                os.fsync(sf.fileno())
            if orig_imode is not None:
                if sys.platform != "win32" or (orig_imode & stat.S_IWRITE):
                    with contextlib.suppress(OSError):
                        os.chmod(str(stage_file), orig_imode)

            # 3) Validate external-checked formats (.js / .mjs / .cjs) on staged file BEFORE touching target_p
            if syntax is None:
                syntax = auto_check_syntax(
                    tp,
                    content=text_for_check,
                    raw_bytes=new_bytes,
                    staged_file=stage_file,
                    check_node=check_node,
                    allow_jsonc=allow_jsonc,
                )
                if enforce_syntax and not syntax.get("valid", True):
                    return {"ok": False, "auto_rolled_back": True, "syntax_check": syntax, "undo_snapshot": None}

            # 4) Save pre-edit externalized snapshot (unless inside skipped build/venv dirs)
            existed_before = tp.exists() and tp.is_file()
            new_sha = hashlib.sha256(new_bytes).hexdigest().lower()
            snap_path: Optional[str] = None
            skip_snap = should_skip_undo_snapshot(tp, workspace_root=workspace_root, workspace_roots=workspace_roots)
            if save_snapshot and not skip_snap:
                if existed_before:
                    snap_path = save_undo_snapshot(
                        tp,
                        workspace_root=workspace_root,
                        workspace_roots=workspace_roots,
                        undo_dir=undo_dir,
                        state_root=state_root,
                        guard=guard,
                    )
                    if snap_path is None:
                        return {
                            "ok": False,
                            "backup_failed": True,
                            "syntax_check": syntax,
                            "undo_snapshot": None,
                            "error": f"Failed to write pre-edit backup snapshot for {tp.name}; aborted write.",
                        }
                else:
                    record_file_creation_undo(
                        tp,
                        created_sha256=new_sha,
                        workspace_root=workspace_root,
                        workspace_roots=workspace_roots,
                        undo_dir=undo_dir,
                        state_root=state_root,
                        guard=guard,
                    )

            # 5) 6-retry backoff atomic `os.replace`
            try:
                for rep_try in range(6):
                    try:
                        os.replace(str(stage_file), str(tp))
                        break
                    except PermissionError:
                        if rep_try == 5 or find_office_temp_lock_file(tp) is not None:
                            raise
                        time.sleep(0.012 * (rep_try + 1))
                if orig_imode is not None and sys.platform != "win32":
                    with contextlib.suppress(OSError):
                        os.chmod(str(tp), orig_imode)
            except OSError as rep_exc:
                if save_snapshot and not skip_snap:
                    pop_latest_undo_entry_quiet(
                        tp,
                        workspace_root=workspace_root,
                        workspace_roots=workspace_roots,
                        undo_dir=undo_dir,
                        state_root=state_root,
                        guard=guard,
                    )
                    if snap_path:
                        with contextlib.suppress(OSError):
                            Path(snap_path).unlink(missing_ok=True)
                lock_err_d = check_office_or_os_file_lock(tp, exc=rep_exc, for_write=True)
                if lock_err_d is not None:
                    return lock_err_d
                raise

            return {
                "ok": True,
                "path": str(tp),
                "existed_before": existed_before,
                "undo_snapshot": snap_path,
                "snapshot_skipped": skip_snap,
                "preserved_mode": orig_imode,
                "syntax_check": syntax,
                "final_bytes": len(new_bytes),
                "sha256": new_sha,
                "sha256_prefix": new_sha[:12],
            }
        finally:
            if stage_file.exists():
                with contextlib.suppress(OSError):
                    stage_file.unlink()


# ---------------------------------------------------------------------------
# 5. >50% Shrinkage Truncation Guard & High-Level `write_file`
# ---------------------------------------------------------------------------


def check_shrink_guard(
    target_p: Path,
    old_bytes: int,
    new_bytes: int,
    *,
    existed_before: bool = True,
    mode: str = "overwrite",
    allow_shrink: bool = False,
    strict_shrink_guard: bool = False,
    min_guard_bytes: int = MIN_SHRINK_GUARD_BYTES,
) -> Optional[Dict[str, Any]]:
    """Detect >50% file shrinkage on files >200 bytes; warn with snapshot rollback hint by default, or block only when `strict_shrink_guard=True`."""
    if (
        mode == "overwrite"
        and existed_before
        and not allow_shrink
        and old_bytes > min_guard_bytes
        and new_bytes * 2 < old_bytes
    ):
        if strict_shrink_guard:
            return {
                "ok": False,
                "blocked_shrink": True,
                "path": str(target_p),
                "old_bytes": old_bytes,
                "new_bytes": new_bytes,
                "error": (
                    f"[TRUNCATION GUARD]: Refused to shrink existing file {target_p.name} "
                    f"from {old_bytes}B to {new_bytes}B (>50% reduction) with strict_shrink_guard=True. "
                    f"Pass allow_shrink=True if intentional."
                ),
            }
        return {
            "ok": True,
            "blocked_shrink": False,
            "shrink_warning": True,
            "path": str(target_p),
            "old_bytes": old_bytes,
            "new_bytes": new_bytes,
            "warning": (
                f"File `{target_p.name}` shrunk from {old_bytes}B to {new_bytes}B (>50% reduction); "
                f"pre-edit backup snapshot was saved automatically and can be restored in one step via "
                f"manage_files(action='undo', path='{target_p}')."
            ),
        }
    return None


def write_file(
    path_str: str | Path,
    content: str,
    *,
    mode: str = "overwrite",
    encoding: str = "",
    allow_shrink: bool = False,
    strict_shrink_guard: bool = False,
    disallow_overwrite: bool = False,
    expected_sha256: str = "",
    check_syntax: bool = True,
    check_node: bool = True,
    allow_jsonc: Optional[bool] = None,
    save_snapshot: bool = True,
    workspace_root: Optional[str | Path] = None,
    workspace_roots: Optional[Any] = None,
    undo_dir: Optional[str | Path] = None,
    state_root: Optional[str | Path] = None,
    guard: Optional[Any] = None,
    min_shrink_guard_bytes: int = MIN_SHRINK_GUARD_BYTES,
) -> Dict[str, Any]:
    """
    Core file writer combining:
    - Cross-process lock + Office `~$*`/OS sharing-violation Chinese diagnostics
    - Original encoding (`UTF-8`, `UTF-8-BOM`, `UTF-16LE/BE`, `GB18030`), explicit text codec, or `encoding='base64'` binary decode
    - >50% truncation guard (`allow_shrink=False` default) + optional `disallow_overwrite` (`overwrite=False` guard)
    - Staged syntax precheck + externalized history snapshot + 6-retry backoff `os.replace`
    """
    if mode not in ("overwrite", "append"):
        return {"ok": False, "path": str(path_str), "error": "mode must be 'overwrite' or 'append'"}

    file_p = Path(path_str).expanduser().resolve()
    target_s = str(file_p)

    with get_file_lock(file_p):
        ext_lock = check_office_or_os_file_lock(file_p, exc=None, for_write=True)
        if ext_lock is not None:
            return ext_lock

        if disallow_overwrite and mode == "overwrite" and (file_p.exists() or file_p.is_symlink()):
            return {
                "ok": False,
                "already_exists": True,
                "path": target_s,
                "error": (
                    f"Refused to overwrite existing file `{file_p.name}` because overwrite=False. "
                    f"Pass overwrite=True or use edit_file/patch_file instead."
                ),
            }

        existed_before = file_p.exists() and file_p.is_file()
        old_raw = b""
        if existed_before:
            try:
                old_raw = file_p.read_bytes()
            except OSError as rd_exc:
                lk_d = check_office_or_os_file_lock(file_p, exc=rd_exc, for_write=True)
                if lk_d is not None:
                    return lk_d
                return {"ok": False, "path": target_s, "error": f"{type(rd_exc).__name__}: {rd_exc}"}

        old_bytes = len(old_raw)
        lock_err = verify_expected_sha256(old_raw, expected_sha256)
        if lock_err:
            return {
                "ok": False,
                "optimistic_lock_conflict": True,
                "path": target_s,
                "error": lock_err,
            }

        try:
            prep_res = prepare_write_file_bytes(
                old_raw,
                existed_before,
                content,
                mode=mode,
                encoding=encoding,
            )
        except (LookupError, UnicodeEncodeError, ValueError) as enc_exc:
            return {"ok": False, "path": target_s, "error": f"{type(enc_exc).__name__}: {enc_exc}"}

        final_payload: bytes = prep_res["final_payload"]
        is_binary_write = bool(prep_res.get("is_binary"))

        shrink_notice = check_shrink_guard(
            file_p,
            old_bytes,
            len(final_payload),
            existed_before=existed_before,
            mode=mode,
            allow_shrink=allow_shrink,
            strict_shrink_guard=strict_shrink_guard,
            min_guard_bytes=min_shrink_guard_bytes,
        )
        if shrink_notice is not None and not shrink_notice.get("ok", True):
            return shrink_notice

        commit = atomic_validate_and_replace(
            file_p,
            final_payload,
            enforce_syntax=bool(check_syntax) and not is_binary_write,
            check_node=bool(check_node) and not is_binary_write,
            allow_jsonc=allow_jsonc,
            save_snapshot=bool(save_snapshot),
            workspace_root=workspace_root,
            workspace_roots=workspace_roots,
            undo_dir=undo_dir,
            state_root=state_root,
            guard=guard,
        )

    if not commit["ok"]:
        if commit.get("file_locked_by_external_app") or commit.get("backup_failed"):
            out_err = dict(commit)
            out_err.setdefault("path", target_s)
            return out_err
        syntax = commit.get("syntax_check") or {}
        return {
            "ok": False,
            "auto_rolled_back": True,
            "path": target_s,
            "undo_snapshot": None,
            "syntax_check": syntax,
            "error": f"Syntax error in {file_p.name} ({syntax.get('error')}); rejected during staging before modifying target file.",
        }

    out_ok: Dict[str, Any] = {
        "ok": True,
        "path": target_s,
        "mode": mode,
        "encoding": prep_res["encoding"],
        "existed_before": existed_before,
        "bom_preserved": prep_res["bom_preserved"],
        "chunk_bytes": prep_res["chunk_bytes"],
        "final_bytes": commit["final_bytes"],
        "preserved_mode": commit.get("preserved_mode"),
        "undo_snapshot": commit["undo_snapshot"],
        "sha256": commit["sha256"],
        "sha256_prefix": commit["sha256_prefix"],
        "syntax_check": commit["syntax_check"],
    }
    if shrink_notice is not None and shrink_notice.get("shrink_warning"):
        out_ok["shrink_warning"] = True
        out_ok["old_bytes"] = old_bytes
        out_ok["warning"] = str(shrink_notice["warning"])
        out_ok["undo_hint"] = f"manage_files(action='undo', path='{target_s}')"
    if is_binary_write:
        out_ok["is_binary"] = True
    return out_ok


# ---------------------------------------------------------------------------
# 6. Pure-Stdlib Image Header Parser (PNG / JPEG / WebP / GIF / BMP)
# ---------------------------------------------------------------------------


def detect_image_magic(head: bytes) -> Optional[str]:
    """Identify image MIME type from raw magic bytes."""
    if len(head) >= 8 and head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if len(head) >= 3 and head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if len(head) >= 6 and head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if len(head) >= 22 and head[:2] == b"BM":
        return "image/bmp"
    return None


def parse_image_dimensions_stdlib(raw_bytes: bytes, mime: Optional[str] = None) -> Tuple[int, int]:
    """Parse `(width, height)` from PNG, JPEG, WebP (`VP8X`/`VP8L`/`VP8 `), GIF, or BMP headers using pure `struct`."""
    eff_mime = mime or detect_image_magic(raw_bytes[:32])
    if eff_mime == "image/png" and len(raw_bytes) >= 24 and raw_bytes[12:16] == b"IHDR":
        w, h = struct.unpack(">II", raw_bytes[16:24])
        return int(w), int(h)

    if eff_mime == "image/gif" and len(raw_bytes) >= 10:
        w, h = struct.unpack("<HH", raw_bytes[6:10])
        return int(w), int(h)

    if eff_mime == "image/bmp" and len(raw_bytes) >= 22:
        dib_sz = struct.unpack("<I", raw_bytes[14:18])[0]
        if dib_sz == 12 and len(raw_bytes) >= 22:
            w, h = struct.unpack("<HH", raw_bytes[18:22])
            return int(w), int(h)
        if len(raw_bytes) >= 26:
            w, raw_h = struct.unpack("<ii", raw_bytes[18:26])
            return abs(int(w)), abs(int(raw_h))

    if eff_mime == "image/webp" and len(raw_bytes) >= 16:
        pos = 12
        n = len(raw_bytes)
        while pos + 8 <= n:
            chunk = raw_bytes[pos : pos + 4]
            chunk_sz = struct.unpack("<I", raw_bytes[pos + 4 : pos + 8])[0]
            data_off = pos + 8
            if chunk == b"VP8X" and data_off + 10 <= n:
                w = 1 + int.from_bytes(raw_bytes[data_off + 4 : data_off + 7], "little")
                h = 1 + int.from_bytes(raw_bytes[data_off + 7 : data_off + 10], "little")
                return int(w), int(h)
            if chunk == b"VP8L" and data_off + 5 <= n and raw_bytes[data_off] == 0x2F:
                bits = struct.unpack("<I", raw_bytes[data_off + 1 : data_off + 5])[0]
                return int((bits & 0x3FFF) + 1), int(((bits >> 14) & 0x3FFF) + 1)
            if chunk == b"VP8 " and data_off + 10 <= n and raw_bytes[data_off + 3 : data_off + 6] == b"\x9d\x01\x2a":
                w = struct.unpack("<H", raw_bytes[data_off + 6 : data_off + 8])[0] & 0x3FFF
                h = struct.unpack("<H", raw_bytes[data_off + 8 : data_off + 10])[0] & 0x3FFF
                return int(w), int(h)
            pos = data_off + chunk_sz + (chunk_sz & 1)

    if eff_mime == "image/jpeg" and len(raw_bytes) >= 4:
        sof_markers = {
            0xC0,
            0xC1,
            0xC2,
            0xC3,
            0xC5,
            0xC6,
            0xC7,
            0xC9,
            0xCA,
            0xCB,
            0xCD,
            0xCE,
            0xCF,
        }
        pos = 2
        n = len(raw_bytes)
        while pos + 1 < n:
            if raw_bytes[pos] != 0xFF:
                pos += 1
                continue
            while pos < n and raw_bytes[pos] == 0xFF:
                pos += 1
            if pos >= n:
                break
            marker = raw_bytes[pos]
            pos += 1
            if marker in (0xD8, 0xD9, 0x01) or (0xD0 <= marker <= 0xD7):
                continue
            if pos + 2 > n:
                break
            seg_len = struct.unpack(">H", raw_bytes[pos : pos + 2])[0]
            if seg_len < 2:
                break
            if marker in sof_markers and pos + 7 <= n and seg_len >= 7:
                h, w = struct.unpack(">HH", raw_bytes[pos + 3 : pos + 7])
                return int(w), int(h)
            if pos + seg_len > n:
                break
            pos += seg_len
    return 0, 0


def read_image_header_info(file_path: str | Path) -> Dict[str, Any]:
    """Read image MIME type, `(width, height)`, and file byte size using pure stdlib header inspection."""
    fp = Path(file_path).expanduser().resolve()
    if not fp.is_file():
        return {"ok": False, "path": str(fp), "error": f"File not found: {fp}"}
    file_size = fp.stat().st_size
    with fp.open("rb") as fh:
        head = fh.read(min(file_size, 65536))
        mime = detect_image_magic(head[:32])
        if mime is None:
            return {"ok": False, "path": str(fp), "error": f"Not a recognized PNG/JPEG/WebP/GIF/BMP image: {fp.name}"}
        w, h = parse_image_dimensions_stdlib(head, mime)
        if w == 0 and h == 0 and mime in ("image/jpeg", "image/webp") and file_size > len(head):
            fh.seek(0)
            larger = fh.read(min(file_size, MAX_IMAGE_HEADER_SCAN_BYTES))
            w, h = parse_image_dimensions_stdlib(larger, mime)
    return {
        "ok": True,
        "path": str(fp),
        "is_image": True,
        "mime_type": mime,
        "width": w,
        "height": h,
        "byte_size": file_size,
    }


def read_local_image_payload(file_path: str | Path, max_raw_bytes: int = MAX_RAW_IMAGE_BYTES) -> Dict[str, Any]:
    """Pure-stdlib image payload loader returning base64 data + parsed `(width, height)` metadata."""
    fp = Path(file_path).expanduser().resolve()
    info = read_image_header_info(fp)
    if not info.get("ok"):
        raise ValueError(str(info.get("error") or f"Invalid image: {fp}"))
    if int(info["byte_size"]) > max_raw_bytes:
        raise ValueError(f"Image file `{fp.name}` ({info['byte_size']} bytes) exceeds {max_raw_bytes} bytes raw limit.")
    raw_bytes = fp.read_bytes()
    sha = hashlib.sha256(raw_bytes).hexdigest().lower()
    meta = {
        **info,
        "sha256": sha,
        "sha256_prefix": sha[:12],
    }
    return {
        "meta": meta,
        "b64_data": base64.b64encode(raw_bytes).decode("ascii"),
        "mime": info["mime_type"],
    }


def encode_rgb_png_stdlib(rgb_bytes: bytes, width: int, height: int) -> bytes:
    """Encode packed 24-bit RGB scanlines (`width * height * 3`) into standard PNG bytes using pure stdlib (`zlib` + `struct`)."""
    if isinstance(rgb_bytes, int) and isinstance(height, (bytes, bytearray, memoryview)):
        w_in, h_in, buf_in = int(rgb_bytes), int(width), bytes(height)
    else:
        w_in, h_in, buf_in = int(width), int(height), bytes(rgb_bytes)
    if w_in <= 0 or h_in <= 0:
        raise ValueError(f"PNG dimensions must be positive, got {w_in}x{h_in}")
    stride = w_in * 3
    if len(buf_in) != stride * h_in:
        raise ValueError(f"Expected {stride * h_in} RGB bytes for {w_in}x{h_in}, got {len(buf_in)}")

    scanlines = bytearray((stride + 1) * h_in)
    pos = 0
    for row_idx in range(h_in):
        scanlines[pos] = 0  # PNG filter type 0 (None)
        pos += 1
        off = row_idx * stride
        scanlines[pos : pos + stride] = buf_in[off : off + stride]
        pos += stride

    def _png_chunk(tag: bytes, payload: bytes) -> bytes:
        crc = zlib.crc32(tag + payload) & 0xFFFFFFFF
        return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", w_in, h_in, 8, 2, 0, 0, 0)
    idat = zlib.compress(bytes(scanlines), level=6)
    return b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IDAT", idat) + _png_chunk(b"IEND", b"")


# ---------------------------------------------------------------------------
# 7. Constant-Memory >2 MiB Streaming Line-Slice Reader & Unified `read_file`
# ---------------------------------------------------------------------------


def _decode_stream_slice(raw_b: bytes) -> Tuple[str, str]:
    if not raw_b:
        return "", "utf-8"
    return detect_and_decode_bytes(raw_b, strict_for_edit=False)


def _scan_stream_text_encoding(stream: Any) -> Tuple[str, str, bytes, bool, int, str]:
    """Validate one encoding, count logical lines, and hash using bounded chunks.

    An explicit BOM is authoritative: malformed BOM-tagged input must not be
    reinterpreted as another encoding. BOM-less input uses the existing UTF-16
    NUL-parity convention, otherwise strict UTF-8 then GB18030 validation.
    """
    head = stream.read(8192)
    if head.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        raise ValueError("Unsupported text encoding UTF-32; convert to UTF-8 or UTF-16.")
    has_utf8_bom = head.startswith(UTF8_BOM)
    if head.startswith(UTF16_LE_BOM):
        choices = [("utf-16", "utf-16-le", UTF16_LE_BOM)]
    elif head.startswith(UTF16_BE_BOM):
        choices = [("utf-16", "utf-16-be", UTF16_BE_BOM)]
    elif has_utf8_bom:
        choices = [("utf-8-sig", "utf-8", b"")]
    elif b"\x00" in head:
        even_nuls, odd_nuls = head[0::2].count(0), head[1::2].count(0)
        if odd_nuls > even_nuls:
            choices = [("utf-16-le", "utf-16-le", UTF16_LE_BOM)]
        elif even_nuls > odd_nuls:
            choices = [("utf-16-be", "utf-16-be", UTF16_BE_BOM)]
        else:
            raise ValueError("Unsupported or ambiguous text encoding; supply an explicit BOM.")
    else:
        choices = [("utf-8", "utf-8", b""), ("gb18030", "gb18030", b"")]

    states: Dict[str, Dict[str, Any]] = {
        codec: {
            "decoder": codecs.getincrementaldecoder(codec)(errors="strict"),
            "breaks": 0,
            "last": "",
            "saw_text": False,
        }
        for codec, _, _ in choices
    }
    hasher = hashlib.sha256()

    def feed(chunk: bytes, *, final: bool = False) -> None:
        for codec, state in list(states.items()):
            try:
                text = state["decoder"].decode(chunk, final=final)
            except UnicodeError:
                del states[codec]
                continue
            if "\x00" in text:
                del states[codec]
                continue
            if text:
                state["breaks"] += text.count("\n") + text.count("\r") - text.count("\r\n")
                if state["last"] == "\r" and text.startswith("\n"):
                    state["breaks"] -= 1
                state["last"], state["saw_text"] = text[-1], True
        if not states:
            raise ValueError("Unsupported or malformed text encoding; no silent encoding fallback is permitted.")

    chunk = head
    while chunk:
        hasher.update(chunk)
        feed(chunk)
        chunk = stream.read(65536)
    feed(b"", final=True)
    for codec, output_codec, slice_bom in choices:
        if codec in states:
            state = states[codec]
            total = int(state["breaks"]) + int(bool(state["saw_text"]) and state["last"] not in ("\n", "\r"))
            return codec, output_codec, slice_bom, has_utf8_bom, total, hasher.hexdigest().lower()
    raise ValueError("Unsupported text encoding.")


def _stream_text_line_window(
    file_path: str | Path,
    start_line: int,
    end_line: int,
    max_slice_bytes: int,
    *,
    tail_count: Optional[int] = None,
) -> Tuple[List[str], str, bytes, bool, int, str, str]:
    """Read a bounded window after a streaming hash/encoding pass; never read the whole file into memory."""
    fp = Path(file_path).expanduser().resolve()
    budget = int(max_slice_bytes)
    if budget < 1:
        raise ValueError("max_slice_bytes must be positive.")
    selected: List[str] = []
    with fp.open("rb") as raw:
        before = os.fstat(raw.fileno())
        codec, output_codec, slice_bom, has_bom, total, sha = _scan_stream_text_encoding(raw)
        if tail_count is not None:
            start_line, end_line = max(1, total - tail_count + 1), total
        end_line = min(end_line, total)
        raw.seek(0)
        with io.TextIOWrapper(raw, encoding=codec, errors="strict", newline="") as stream:
            # UTF-16 slices carry their own BOM so callers cannot guess the wrong
            # byte order after cutting away the source header. The bool remains
            # the historical UTF-8-BOM flag used by existing callers.
            used_bytes = len(slice_bom) if start_line <= end_line else 0
            try:
                for line_index in range(1, end_line + 1):
                    line = stream.readline(budget + 1)
                    if not line:
                        raise ValueError("File changed while streaming its line window; retry the read.")
                    line_bytes = len(line.encode(output_codec))
                    if line_bytes > budget:
                        raise ValueError("Single line in file exceeds max_slice_bytes; use search tools instead.")
                    if line_index >= start_line:
                        used_bytes += line_bytes
                        if used_bytes > budget:
                            raise ValueError("Requested line slice exceeds max_slice_bytes; request fewer lines.")
                        selected.append(line)
            except UnicodeError as exc:
                raise ValueError("File encoding changed while reading its line window.") from exc
            after = os.fstat(stream.buffer.fileno())
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError("File changed while streaming its line window; retry the read.")
    encoding_tag = "utf-8-sig" if has_bom else output_codec
    if codec == "utf-16":
        encoding_tag = output_codec + "-bom"
    return selected, output_codec, slice_bom, has_bom, total, sha, encoding_tag


def stream_read_text_window(
    file_path: str | Path,
    start_line: int = 1,
    end_line: int = 0,
    max_slice_bytes: int = MAX_DEFAULT_READ_BYTES,
    *,
    tail_count: Optional[int] = None,
) -> Tuple[List[str], str, int, str]:
    """Return decoded lines, source encoding, total lines, and full-file SHA-256.

    Consumers must keep this file-wide encoding decision instead of guessing
    again from a selected byte slice, which may be valid in multiple encodings.
    The legacy byte-slice and tail tuple interfaces remain available separately.
    """
    if tail_count is None:
        eff_start, eff_end = max(1, int(start_line)), int(end_line)
        if eff_end < eff_start:
            raise ValueError(f"Invalid line slice {start_line}..{end_line}: end_line must be >= start_line")
    else:
        tail_count = max(1, min(2000, abs(int(tail_count))))
        eff_start, eff_end = 1, 0
    lines, _, _, _, total, sha, encoding_tag = _stream_text_line_window(
        file_path, eff_start, eff_end, max_slice_bytes, tail_count=tail_count
    )
    return lines, encoding_tag, total, sha


def stream_read_line_slice(
    file_path: str | Path,
    start_line: int,
    end_line: int,
    max_slice_bytes: int = MAX_DEFAULT_READ_BYTES,
) -> Tuple[bytes, bool, int, str]:
    """Stream a 1-based inclusive line window, preserving text and the full-file SHA-256."""
    eff_start, eff_end = max(1, int(start_line)), int(end_line)
    if eff_end < eff_start:
        raise ValueError(f"Invalid line slice {start_line}..{end_line}: end_line must be >= start_line")
    lines, codec, slice_bom, has_bom, total, sha, _ = _stream_text_line_window(
        file_path, eff_start, eff_end, max_slice_bytes
    )
    payload = "".join(lines).encode(codec)
    return (slice_bom + payload if payload else b""), has_bom, total, sha


def stream_tail_lines(
    file_path: str | Path,
    tail_count: int,
    max_slice_bytes: int = MAX_DEFAULT_READ_BYTES,
) -> Tuple[List[str], bool, int, str]:
    """Stream the final lines with a byte budget, without an unbounded tail ring."""
    cap = max(1, min(2000, abs(int(tail_count))))
    lines, _, _, has_bom, total, sha, _ = _stream_text_line_window(
        file_path, 1, 0, max_slice_bytes, tail_count=cap
    )
    return lines, has_bom, total, sha


def read_file(
    path_str: str | Path,
    *,
    start_line: int = 1,
    end_line: int = 0,
    max_file_bytes: int = MAX_DEFAULT_READ_BYTES,
    include_line_numbers: bool = False,
) -> Dict[str, Any]:
    """
    Unified file reader supporting:
    - Multi-encoding auto-detection (`UTF-8`, `UTF-8-BOM`, `UTF-16LE/BE`, `GB18030`)
    - Pure-stdlib image header metadata (`PNG`, `JPEG`, `WebP`, `GIF`, `BMP`)
    - Constant-memory `start_line`/`end_line` (and negative `start_line` tail) streaming for `>2 MiB` files
    - Clear Chinese diagnostics on OS/Office exclusive file locks
    """
    fp = Path(path_str).expanduser().resolve()
    s_in, e_in = int(start_line), int(end_line)
    if s_in == 0 or e_in < 0 or (s_in > 0 and e_in > 0 and e_in < s_in):
        return {"ok": False, "path": str(fp), "error": f"Invalid line range: start_line={start_line}, end_line={end_line}."}
    if not fp.exists():
        return {"ok": False, "path": str(fp), "error": f"File not found: {fp}"}
    if fp.is_dir():
        return {"ok": False, "path": str(fp), "error": f"Path is a directory, not a file: {fp}"}

    if fp.suffix.lower() in IMAGE_EXTENSIONS:
        img_info = read_image_header_info(fp)
        if img_info.get("ok"):
            return img_info

    try:
        file_sz = fp.stat().st_size
    except OSError as exc:
        return {"ok": False, "path": str(fp), "error": str(exc)}

    if file_sz > max_file_bytes:
        try:
            if s_in < 0:
                t_lines_raw, enc_tag, tlines, sha = stream_read_text_window(
                    fp, max_slice_bytes=max_file_bytes, tail_count=abs(s_in)
                )
                hbom = enc_tag.endswith("-bom") or enc_tag == "utf-8-sig"
                eff_s = max(1, tlines - len(t_lines_raw) + 1)
                eff_e = min(tlines, e_in) if e_in >= eff_s else tlines
                sliced = t_lines_raw[: max(0, eff_e - eff_s + 1)]
                txt_out = (
                    "".join(f"{eff_s + idx}| {ln}" for idx, ln in enumerate(sliced))
                    if include_line_numbers
                    else "".join(sliced)
                )
                return {
                    "ok": True,
                    "path": str(fp),
                    "content": txt_out,
                    "encoding": enc_tag,
                    "has_bom": hbom,
                    "start_line": eff_s,
                    "end_line": eff_e,
                    "total_lines": tlines,
                    "streamed_slice": True,
                    "sha256": sha,
                    "sha256_prefix": sha[:12],
                }
            if s_in >= 1 and e_in >= s_in:
                slice_lines, enc_tag, tlines, sha = stream_read_text_window(
                    fp, s_in, e_in, max_file_bytes
                )
                hbom = enc_tag.endswith("-bom") or enc_tag == "utf-8-sig"
                dec_txt = "".join(slice_lines)
                if include_line_numbers:
                    dec_txt = "".join(
                        f"{s_in + idx}| {ln}" for idx, ln in enumerate(slice_lines)
                    )
                return {
                    "ok": True,
                    "path": str(fp),
                    "content": dec_txt,
                    "encoding": enc_tag,
                    "has_bom": hbom,
                    "start_line": s_in,
                    "end_line": min(e_in, tlines),
                    "total_lines": tlines,
                    "streamed_slice": True,
                    "sha256": sha,
                    "sha256_prefix": sha[:12],
                }
        except ValueError as vexc:
            return {"ok": False, "path": str(fp), "error": str(vexc)}
        except OSError as io_exc:
            lk_d = check_office_or_os_file_lock(fp, exc=io_exc, for_write=False)
            if lk_d is not None:
                return lk_d
            return {"ok": False, "path": str(fp), "error": f"{type(io_exc).__name__}: {io_exc}"}
        return {
            "ok": False,
            "too_large": True,
            "path": str(fp),
            "file_bytes": file_sz,
            "error": "File exceeds 2 MiB; pass start_line and end_line (or negative start_line for tail) to stream a slice.",
        }

    try:
        raw = fp.read_bytes()
    except OSError as io_exc:
        lk_d = check_office_or_os_file_lock(fp, exc=io_exc, for_write=False)
        if lk_d is not None:
            return lk_d
        return {"ok": False, "path": str(fp), "error": f"{type(io_exc).__name__}: {io_exc}"}

    magic = detect_image_magic(raw[:32])
    if magic is not None:
        w, h = parse_image_dimensions_stdlib(raw, magic)
        sha_im = hashlib.sha256(raw).hexdigest().lower()
        return {
            "ok": True,
            "path": str(fp),
            "is_image": True,
            "mime_type": magic,
            "width": w,
            "height": h,
            "byte_size": len(raw),
            "sha256": sha_im,
            "sha256_prefix": sha_im[:12],
        }

    sha = hashlib.sha256(raw).hexdigest().lower()
    txt, enc_tag = detect_and_decode_bytes(raw, strict_for_edit=False)
    has_bom = enc_tag.endswith("-bom") or enc_tag == "utf-8-sig"
    lines = txt.splitlines(keepends=True)
    tlines = len(lines)

    eff_s = max(1, tlines + s_in + 1) if s_in < 0 else max(1, s_in)
    if e_in > 0 and e_in < eff_s:
        return {"ok": False, "path": str(fp), "error": f"Invalid line range: end_line ({e_in}) < start_line ({eff_s})."}
    eff_e = min(tlines, e_in) if e_in > 0 else tlines

    if tlines == 0:
        sliced_txt = ""
    elif eff_s == 1 and eff_e == tlines and not include_line_numbers:
        sliced_txt = txt
    else:
        seg = lines[eff_s - 1 : eff_e]
        sliced_txt = (
            "".join(f"{eff_s + idx}| {ln}" for idx, ln in enumerate(seg))
            if include_line_numbers
            else "".join(seg)
        )

    return {
        "ok": True,
        "path": str(fp),
        "content": sliced_txt,
        "encoding": enc_tag,
        "has_bom": has_bom,
        "start_line": eff_s if tlines > 0 else 1,
        "end_line": eff_e,
        "total_lines": tlines,
        "sha256": sha,
        "sha256_prefix": sha[:12],
    }


__all__ = [
    "CREATE_NO_WINDOW",
    "IMAGE_EXTENSIONS",
    "MAX_DEFAULT_READ_BYTES",
    "MAX_IMAGE_HEADER_SCAN_BYTES",
    "MAX_RAW_IMAGE_BYTES",
    "MIN_SHRINK_GUARD_BYTES",
    "OFFICE_DOC_EXTS",
    "UTF16_BE_BOM",
    "UTF16_LE_BOM",
    "UTF8_BOM",
    "atomic_validate_and_replace",
    "auto_check_syntax",
    "check_js_syntax_with_node",
    "check_office_or_os_file_lock",
    "check_shrink_guard",
    "detect_and_decode_bytes",
    "detect_dominant_crlf",
    "detect_image_magic",
    "encode_rgb_png_stdlib",
    "encode_with_detected_encoding",
    "find_office_temp_lock_file",
    "get_file_lock",
    "parse_image_dimensions_stdlib",
    "pop_latest_undo_entry_quiet",
    "prepare_write_file_bytes",
    "preserve_line_endings_for_edit",
    "read_file",
    "read_image_header_info",
    "read_local_image_payload",
    "record_file_creation_undo",
    "resolve_undo_dir",
    "restore_line_endings",
    "save_undo_snapshot",
    "should_skip_undo_snapshot",
    "split_lines_exact_nl",
    "stream_read_line_slice",
    "stream_read_text_window",
    "stream_tail_lines",
    "strip_jsonc_comments",
    "verify_expected_sha256",
    "write_file",
]
