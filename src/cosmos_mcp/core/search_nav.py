from __future__ import annotations

"""
Workspace directory navigation, file discovery, and byte-safe ripgrep / pure-Python
code & document search (`search_nav.py`).

Strictly depends only on Python >=3.9 stdlib and `cosmos_mcp.core.*`.
"""

import contextlib
import ctypes
import fnmatch
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from cosmos_mcp.core.code import (
    REPO_MAP_SOURCE_EXTS,
    derive_cross_case_variants,
    extract_symbols_from_text,
    find_enclosing_symbol,
    get_repo_map,
    repo_map,
)
from cosmos_mcp.core.fs import (
    MAX_DOC_EXTRACT_BYTES,
    extract_document_lines,
)
from cosmos_mcp.core.fs_io import (
    CREATE_NO_WINDOW,
    MAX_DEFAULT_READ_BYTES,
    detect_and_decode_bytes,
)
from cosmos_mcp.core.guard import WorkspaceGuard
from cosmos_mcp.core.path_heal import (
    has_link_or_junction_in_rel,
    heal_and_resolve_path,
    is_link_or_junction,
    is_noise_dir_name,
)

PROSE_DOC_EXTS: Set[str] = {".md", ".markdown", ".rst", ".txt"}
STRUCTURED_DOC_EXTS: Set[str] = {".docx", ".xlsx", ".pdf", ".pptx", ".ipynb"}

BINARY_SEARCH_EXTS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico",
    ".pdf", ".docx", ".xlsx", ".pptx", ".ipynb",
    ".zip", ".tar", ".gz", ".7z", ".rar", ".whl", ".mcpb",
    ".exe", ".dll", ".so", ".dylib", ".pyd", ".pyc", ".pyo",
    ".sqlite", ".sqlite3", ".db", ".woff", ".woff2", ".ttf", ".mp3", ".mp4",
}

RG_EXCLUDE_GLOBS: Tuple[str, ...] = (
    "!node_modules", "!.git", "!__pycache__", "!.venv", "!venv",
    "!.undo_history", "!.cosmos_mcp_state", "!.cosmos_mcp_trash", "!.runtime", "!backups*",
    "!*.pyc", "!*.pyo", "!*.pyd", "!*.dll", "!*.exe", "!*.so", "!*.dylib",
    "!*.sqlite3", "!*.db", "!*.png", "!*.jpg", "!*.jpeg", "!*.webp", "!*.gif",
    "!*.pdf", "!*.docx", "!*.xlsx", "!*.pptx", "!*.ipynb", "!*.zip", "!*.mcpb", "!*.whl",
)

RG_DOC_EXCLUDE_GLOBS: Tuple[str, ...] = (
    "!*.md", "!*.markdown", "!*.rst", "!*.txt",
)

_CACHED_RG_BIN: Optional[str] = None
_RG_RAW_LINE_RE = re.compile(rb"^((?:[A-Za-z]:[\\/])?[^:]+):(\d+):(.*)$")
_RG_STR_LINE_RE = re.compile(r"^((?:[A-Za-z]:[\\/])?[^:]+):(\d+):(.*)$")


def _default_guard(guard: Optional[WorkspaceGuard]) -> WorkspaceGuard:
    return guard if guard is not None else WorkspaceGuard(restrict_to_workspace=False, tier="L3")


def _win_no_window_flags() -> int:
    if sys.platform == "win32":
        with contextlib.suppress(Exception):
            ctypes.windll.kernel32.SetErrorMode(0x8003)
        return CREATE_NO_WINDOW
    return 0


def _coerce_str_list(val: Any) -> List[str]:
    if val is None:
        return []
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return []
        if s.startswith("["):
            try:
                arr = json.loads(s)
                if isinstance(arr, list):
                    return [str(x).strip() for x in arr if str(x).strip()]
            except Exception:
                pass
        return [x.strip() for x in s.split(",") if x.strip()]
    if isinstance(val, (list, tuple, set)):
        return [str(x).strip() for x in val if str(x).strip()]
    return [str(val).strip()] if str(val).strip() else []


def _safe_immediate_child_count(dir_p: Path, max_scan: int = 5000) -> int:
    cnt = 0
    try:
        with os.scandir(dir_p) as it:
            for _ in it:
                cnt += 1
                if cnt >= max_scan:
                    break
    except OSError:
        return 0
    return cnt


def list_dir(
    path: Union[Path, str] = ".",
    max_entries: int = 200,
    max_depth: int = 1,
    *,
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    """
    List files and directories with symlink/junction loop protection.
    When `max_depth == 1`, attaches `child_count` to each directory entry.
    """
    g = _default_guard(guard)
    r_info = heal_and_resolve_path(
        str(path or "."), g, mode="read", must_exist=True, expect_dir=True, tool_name="list_dir"
    )
    if not r_info["ok"]:
        return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}

    base: Path = r_info["path"]
    if is_link_or_junction(base):
        return {"ok": False, "path": str(base), "error": f"Refusing symlink or junction directory: {base}"}

    cap = max(1, min(1000, int(max_entries or 200)))
    eff_depth = max(1, min(6, int(max_depth or 1)))
    items: List[Dict[str, Any]] = []
    total_seen = 0
    visited_realpaths: Set[str] = {os.path.normcase(os.path.realpath(str(base)))}

    def _walk_level(cur_dir: Path, depth: int, rel_prefix: str) -> None:
        nonlocal total_seen
        try:
            with os.scandir(cur_dir) as it:
                raw_entries = list(it)
        except OSError:
            return
        raw_entries.sort(key=lambda de: (not de.is_dir(follow_symlinks=False), de.name.lower()))
        for de in raw_entries:
            ep = Path(de.path)
            if is_link_or_junction(ep) or g.check_path_access(str(ep), mode="read") is not None:
                continue
            is_d = de.is_dir(follow_symlinks=False)
            if depth > 1 and is_d and is_noise_dir_name(de.name):
                continue
            total_seen += 1
            if len(items) < cap:
                info: Dict[str, Any] = {
                    "name": f"{rel_prefix}{de.name}" + ("/" if is_d else ""),
                    "type": "dir" if is_d else "file",
                }
                try:
                    st = de.stat(follow_symlinks=False)
                    if not is_d:
                        info["bytes"] = int(st.st_size)
                        info["size_bytes"] = int(st.st_size)
                    else:
                        info["size_bytes"] = 0
                    info["mtime"] = int(st.st_mtime)
                except OSError:
                    pass
                if is_d and eff_depth == 1:
                    info["child_count"] = _safe_immediate_child_count(ep)
                items.append(info)
            if is_d and depth < eff_depth and not is_noise_dir_name(de.name):
                real_k = os.path.normcase(os.path.realpath(str(ep)))
                if real_k in visited_realpaths:
                    continue
                visited_realpaths.add(real_k)
                try:
                    _walk_level(ep, depth + 1, f"{rel_prefix}{de.name}/")
                finally:
                    visited_realpaths.discard(real_k)

    _walk_level(base, 1, "")
    out: Dict[str, Any] = {
        "ok": True,
        "path": str(base),
        "max_depth": eff_depth,
        "total_entries": total_seen,
        "returned_entries": len(items),
        "entries": items,
    }
    if r_info.get("healed_note"):
        out["healed_note"] = r_info["healed_note"]
    return out


def _sort_found_entries(entries: List[Dict[str, Any]], sort_by: str) -> None:
    sb = (sort_by or "").strip().lower()
    if not sb:
        return
    if sb in ("mtime", "modified", "mtime_desc"):
        entries.sort(key=lambda it: (float(it.get("mtime") or 0.0), str(it.get("rel_path") or "")), reverse=True)
    elif sb == "mtime_asc":
        entries.sort(key=lambda it: (float(it.get("mtime") or 0.0), str(it.get("rel_path") or "")))
    elif sb in ("size", "size_bytes", "size_desc"):
        entries.sort(key=lambda it: (int(it.get("size_bytes") or 0), float(it.get("mtime") or 0.0)), reverse=True)
    elif sb == "size_asc":
        entries.sort(key=lambda it: (int(it.get("size_bytes") or 0), str(it.get("rel_path") or "")))
    elif sb == "name":
        entries.sort(key=lambda it: str(it.get("name") or "").lower())
    elif sb in ("path", "rel_path"):
        entries.sort(key=lambda it: str(it.get("rel_path") or "").lower())


def find_files(
    path: Union[Path, str] = ".",
    pattern: str = "",
    extensions: Any = None,
    excludes: Any = None,
    entry_type: str = "any",
    max_depth: int = 8,
    limit: int = 60,
    sort_by: str = "",
    *,
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    """
    Find files and directories by glob/substring, extension filter, entry_type, max_depth (default 8),
    and `sort_by` (`"mtime"`, `"size"`, `"name"`, `"path"`), populating `size_bytes` and `mtime` on every entry.
    """
    g = _default_guard(guard)
    r_info = heal_and_resolve_path(str(path or "."), g, mode="read", must_exist=True, tool_name="find_files")
    if not r_info["ok"]:
        return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}

    base: Path = r_info["path"]
    if is_link_or_junction(base):
        return {"ok": False, "path": str(base), "error": f"Refusing symlink or junction path: {base}"}
    if base.is_file():
        st_f = base.stat()
        sz_f = int(st_f.st_size)
        mt_f = round(float(st_f.st_mtime), 6)
        return {
            "ok": True,
            "path": str(base),
            "count": 1,
            "entries": [
                {
                    "name": base.name,
                    "rel_path": base.name,
                    "type": "file",
                    "bytes": sz_f,
                    "size_bytes": sz_f,
                    "mtime": mt_f,
                }
            ],
        }

    eff_depth = max(1, min(20, int(max_depth or 8)))
    cap = max(1, min(500, int(limit or 60)))
    sb = (sort_by or "").strip().lower()
    scan_cap = max(cap * 50, 5000) if sb else cap

    pat_str = (pattern or "").strip()
    has_glob = any(ch in pat_str for ch in ("*", "?", "["))
    ext_filters = {("." + e.lstrip(".").lower()) for e in _coerce_str_list(extensions)}
    excl_globs = _coerce_str_list(excludes)
    etype = (entry_type or "any").strip().lower()

    results: List[Dict[str, Any]] = []
    visited_realpaths: Set[str] = {os.path.normcase(os.path.realpath(str(base)))}

    def _matches(rel_posix: str, name: str, is_dir: bool) -> bool:
        if etype == "file" and is_dir:
            return False
        if etype in ("dir", "directory") and not is_dir:
            return False
        if ext_filters and (is_dir or Path(name).suffix.lower() not in ext_filters):
            return False
        for ex in excl_globs:
            if fnmatch.fnmatch(name, ex) or fnmatch.fnmatch(rel_posix, ex):
                return False
        if not pat_str:
            return True
        if has_glob:
            return fnmatch.fnmatch(name.lower(), pat_str.lower()) or fnmatch.fnmatch(rel_posix.lower(), pat_str.lower())
        return pat_str.lower() in name.lower() or pat_str.lower() in rel_posix.lower()

    def _scan(cur_dir: Path, depth: int) -> None:
        if len(results) >= scan_cap:
            return
        try:
            with os.scandir(cur_dir) as it:
                entries = sorted(list(it), key=lambda de: (not de.is_dir(follow_symlinks=False), de.name.lower()))
        except OSError:
            return
        for de in entries:
            if len(results) >= scan_cap:
                return
            ep = Path(de.path)
            if is_link_or_junction(ep) or is_noise_dir_name(de.name) or g.check_path_access(str(ep), mode="read") is not None:
                continue
            is_d = de.is_dir(follow_symlinks=False)
            rel_posix = ep.relative_to(base).as_posix()
            if _matches(rel_posix, de.name, is_d):
                item: Dict[str, Any] = {
                    "name": de.name + ("/" if is_d else ""),
                    "rel_path": rel_posix + ("/" if is_d else ""),
                    "type": "dir" if is_d else "file",
                    "size_bytes": 0,
                    "mtime": 0.0,
                }
                try:
                    st = de.stat(follow_symlinks=False)
                    if not is_d:
                        sz = int(st.st_size)
                        item["bytes"] = sz
                        item["size_bytes"] = sz
                    item["mtime"] = round(float(st.st_mtime), 6)
                except OSError:
                    pass
                if is_d and eff_depth == 1 and not pat_str:
                    item["child_count"] = _safe_immediate_child_count(ep)
                results.append(item)
            if is_d and depth < eff_depth:
                real_k = os.path.normcase(os.path.realpath(str(ep)))
                if real_k in visited_realpaths:
                    continue
                visited_realpaths.add(real_k)
                try:
                    _scan(ep, depth + 1)
                finally:
                    visited_realpaths.discard(real_k)

    _scan(base, 1)
    if sb:
        _sort_found_entries(results, sb)
    sliced = results[:cap]

    out: Dict[str, Any] = {
        "ok": True,
        "path": str(base),
        "max_depth": eff_depth,
        "count": len(sliced),
        "entries": sliced,
    }
    if sb:
        out["sort_by"] = sb
        out["total_matched"] = len(results)
    if r_info.get("healed_note"):
        out["healed_note"] = r_info["healed_note"]
    return out


def find_ripgrep_binary() -> Optional[str]:
    global _CACHED_RG_BIN
    if _CACHED_RG_BIN is not None:
        return _CACHED_RG_BIN or None
    found = shutil.which("rg")
    if found:
        _CACHED_RG_BIN = found
        return found
    home = Path.home()
    candidates: List[Path] = []
    if sys.platform == "win32":
        local_app = Path(os.environ.get("LOCALAPPDATA") or (home / "AppData" / "Local"))
        prog_files = Path(os.environ.get("ProgramFiles") or r"C:\Program Files")
        candidates.extend([
            local_app / "Programs" / "Microsoft VS Code" / "resources" / "app" / "node_modules.asar.unpacked" / "@vscode" / "ripgrep" / "bin" / "rg.exe",
            local_app / "Programs" / "cursor" / "resources" / "app" / "node_modules.asar.unpacked" / "@vscode" / "ripgrep" / "bin" / "rg.exe",
            prog_files / "Microsoft VS Code" / "resources" / "app" / "node_modules.asar.unpacked" / "@vscode" / "ripgrep" / "bin" / "rg.exe",
            home / ".cargo" / "bin" / "rg.exe",
            home / "scoop" / "shims" / "rg.exe",
        ])
    else:
        candidates.extend([Path("/opt/homebrew/bin/rg"), Path("/usr/local/bin/rg"), Path("/usr/bin/rg"), home / ".cargo" / "bin" / "rg"])
    for cand in candidates:
        if cand.is_file():
            _CACHED_RG_BIN = str(cand)
            return _CACHED_RG_BIN
    _CACHED_RG_BIN = ""
    return None


def _decode_rg_segment_bytes(raw_b: bytes) -> str:
    if not raw_b:
        return ""
    if raw_b.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return raw_b.decode("utf-16")
        except UnicodeDecodeError:
            pass
    if b"\x00" not in raw_b:
        try:
            return raw_b.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return raw_b.decode("gb18030")
            except UnicodeDecodeError:
                return raw_b.decode("utf-8", errors="replace")
    even_zeros = sum(1 for i in range(0, len(raw_b), 2) if raw_b[i] == 0)
    odd_zeros = sum(1 for i in range(1, len(raw_b), 2) if raw_b[i] == 0)
    enc_try = ("utf-16-be", "utf-16-le") if even_zeros > odd_zeros else ("utf-16-le", "utf-16-be")
    for enc in enc_try:
        try:
            cand = raw_b.decode(enc)
            if "\x00" not in cand:
                return cand
        except UnicodeDecodeError:
            continue
    return raw_b.replace(b"\x00", b"").decode("utf-8", errors="replace")


def _decode_rg_stdout_line(raw_line: bytes) -> str:
    clean_b = raw_line.rstrip(b"\r\n")
    if not clean_b:
        return ""
    m_b = _RG_RAW_LINE_RE.match(clean_b)
    if m_b:
        return f"{_decode_rg_segment_bytes(m_b.group(1))}:{m_b.group(2).decode('ascii', errors='ignore')}:{_decode_rg_segment_bytes(m_b.group(3))}"
    return _decode_rg_segment_bytes(clean_b)


def _dir_has_utf16_candidate(base: Path, max_probe: int = 60) -> bool:
    if base.is_file():
        if base.suffix.lower() in BINARY_SEARCH_EXTS:
            return False
        try:
            return b"\x00" in base.read_bytes()[:256]
        except OSError:
            return False
    checked = 0
    for rd, dirs, fns in os.walk(base, followlinks=False):
        rp = Path(rd)
        dirs[:] = [d for d in dirs if not is_noise_dir_name(d) and not is_link_or_junction(rp / d)]
        for fn in fns:
            fp = rp / fn
            if fp.suffix.lower() in BINARY_SEARCH_EXTS:
                continue
            checked += 1
            if checked > max_probe:
                return False
            try:
                if b"\x00" in fp.read_bytes()[:256]:
                    return True
            except OSError:
                continue
    return False


def _match_glob_filter(fp: Path, base: Path, glob_filter: str) -> bool:
    gf = (glob_filter or "").strip()
    if not gf:
        return True
    neg = gf.startswith("!")
    pat = gf[1:].strip() if neg else gf
    rel_posix = fp.relative_to(base).as_posix() if base.is_dir() and fp != base else fp.name
    matched = fnmatch.fnmatch(fp.name, pat) or fnmatch.fnmatch(rel_posix, pat)
    if pat.startswith("**/"):
        matched = matched or fnmatch.fnmatch(fp.name, pat[3:]) or fnmatch.fnmatch(rel_posix, pat[3:])
    return (not matched) if neg else matched


def _glob_explicitly_targets_docs(glob_filter: str) -> bool:
    gf = (glob_filter or "").strip().lower()
    if not gf or gf.startswith("!"):
        return False
    return any(ext in gf for ext in (*PROSE_DOC_EXTS, *STRUCTURED_DOC_EXTS))


def _scan_pure_python(
    base: Path,
    rx: re.Pattern[str],
    glob_filter: str,
    files_only: bool,
    cap: int,
    guard: WorkspaceGuard,
    *,
    include_prose_docs: bool = False,
) -> Tuple[List[Tuple[Path, int, str]], List[Path], int]:
    hits: List[Tuple[Path, int, str]] = []
    matched_files: List[Path] = []
    scanned = 0
    deadline = time.monotonic() + 7.5
    is_single_file = base.is_file()
    cand_files: List[Path] = [base] if is_single_file else []
    if not cand_files:
        for rd, dirs, fns in os.walk(base, followlinks=False):
            if time.monotonic() > deadline:
                break
            rp = Path(rd)
            dirs[:] = [
                d for d in sorted(dirs)
                if not is_noise_dir_name(d) and not is_link_or_junction(rp / d) and guard.check_path_access(str(rp / d), mode="read") is None
            ]
            for fn in sorted(fns):
                cand_files.append(rp / fn)
    for fp in cand_files:
        if time.monotonic() > deadline:
            break
        ext_l = fp.suffix.lower()
        if ext_l in BINARY_SEARCH_EXTS or is_link_or_junction(fp) or not _match_glob_filter(fp, base, glob_filter):
            continue
        if not is_single_file and not include_prose_docs and ext_l in PROSE_DOC_EXTS:
            continue
        if guard.check_path_access(str(fp), mode="read") is not None:
            continue
        scanned += 1
        try:
            if fp.stat().st_size > MAX_DEFAULT_READ_BYTES:
                continue
            txt, _ = detect_and_decode_bytes(fp.read_bytes(), strict_for_edit=False)
        except Exception:
            continue
        if files_only:
            if rx.search(txt):
                matched_files.append(fp.resolve())
                if len(matched_files) >= cap:
                    break
        else:
            for ln_no, ln in enumerate(txt.splitlines(), start=1):
                if rx.search(ln):
                    hits.append((fp.resolve(), ln_no, ln[:220]))
                    if len(hits) >= cap:
                        break
            if len(hits) >= cap:
                break
    return hits, matched_files, scanned


def _scan_structured_docs(
    base: Path,
    rx: re.Pattern[str],
    glob_filter: str,
    files_only: bool,
    cap: int,
    guard: WorkspaceGuard,
) -> Tuple[List[Tuple[Path, int, str]], List[Path], int]:
    """Search extracted plain text across `.docx`, `.xlsx`, `.pdf`, `.pptx`, and `.ipynb`."""
    hits: List[Tuple[Path, int, str]] = []
    matched_files: List[Path] = []
    scanned = 0
    if cap <= 0:
        return hits, matched_files, scanned

    deadline = time.monotonic() + 7.5
    cand_docs: List[Path] = []
    if base.is_file():
        if base.suffix.lower() in STRUCTURED_DOC_EXTS:
            cand_docs.append(base)
    else:
        for rd, dirs, fns in os.walk(base, followlinks=False):
            if time.monotonic() > deadline:
                break
            rp = Path(rd)
            dirs[:] = [
                d for d in sorted(dirs)
                if not is_noise_dir_name(d) and not is_link_or_junction(rp / d) and guard.check_path_access(str(rp / d), mode="read") is None
            ]
            for fn in sorted(fns):
                fp = rp / fn
                if fp.suffix.lower() in STRUCTURED_DOC_EXTS:
                    cand_docs.append(fp)

    for fp in cand_docs:
        if time.monotonic() > deadline:
            break
        if is_link_or_junction(fp) or not _match_glob_filter(fp, base, glob_filter):
            continue
        if guard.check_path_access(str(fp), mode="read") is not None:
            continue
        try:
            if fp.stat().st_size > MAX_DOC_EXTRACT_BYTES:
                continue
            doc_lines = extract_document_lines(fp)
        except Exception:
            continue
        scanned += 1
        fp_res = fp.resolve()
        if files_only:
            if any(rx.search(ln) for ln in doc_lines):
                matched_files.append(fp_res)
                if len(matched_files) >= cap:
                    break
        else:
            for ln_no, ln in enumerate(doc_lines, start=1):
                if rx.search(ln):
                    hits.append((fp_res, ln_no, ln[:220]))
                    if len(hits) >= cap:
                        break
            if len(hits) >= cap:
                break
    return hits, matched_files, scanned


def _enrich_hits_with_enclosing_symbols(
    raw_tuples: Sequence[Tuple[Path, int, str]],
    anchor_dir: Path,
    guard: WorkspaceGuard,
) -> List[Dict[str, Any]]:
    outline_cache: Dict[str, List[Dict[str, Any]]] = {}
    enriched: List[Dict[str, Any]] = []
    for fp, ln_no, line_txt in raw_tuples:
        fk = os.path.normcase(str(fp))
        if fk not in outline_cache:
            if fp.suffix.lower() in STRUCTURED_DOC_EXTS:
                outline_cache[fk] = []
            else:
                try:
                    if fp.is_file() and fp.stat().st_size <= MAX_DEFAULT_READ_BYTES:
                        txt, _ = detect_and_decode_bytes(fp.read_bytes(), strict_for_edit=False)
                        outline_cache[fk] = extract_symbols_from_text(txt, str(fp))
                    else:
                        outline_cache[fk] = []
                except Exception:
                    outline_cache[fk] = []
        enc = find_enclosing_symbol(outline_cache[fk], ln_no)
        try:
            rel_s = fp.relative_to(anchor_dir).as_posix()
        except ValueError:
            rel_s = str(fp)
        enriched.append({
            "file": str(fp),
            "rel_path": rel_s,
            "line": ln_no,
            "text": guard.redact_sensitive_output(line_txt),
            "symbol": enc.get("qualname") if enc else None,
            "signature": enc.get("signature") if enc else None,
        })
    return enriched


def search_code(
    pattern: str = "",
    path: Union[Path, str] = ".",
    glob_filter: str = "",
    files_only: bool = False,
    case_insensitive: bool = False,
    fixed_strings: bool = False,
    max_results: int = 40,
    include_docs: bool = False,
    *,
    query: str = "",
    keyword: str = "",
    glob: str = "",
    allow_subprocess: bool = True,
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    """
    Fast `rg` + multi-encoding pure-Python fallback code & optional document search:
    - Accepts `pattern` / `query` / `keyword` and `glob_filter` / `glob` aliases.
    - When `include_docs=True`, also searches `.docx`, `.xlsx`, `.pdf`, `.pptx`, `.ipynb`, and prose docs.
    - Attaches enclosing function/class signature (`symbol` + `signature`) to every code match.
    - Automatically probes `snake_case <-> camelCase` variants when primary search returns 0 hits.
    """
    g = _default_guard(guard)
    eff_pattern = (pattern or query or keyword or "").strip() if (pattern or query or keyword) else ""
    eff_glob = (glob_filter or glob or "").strip()

    r_info = heal_and_resolve_path(str(path or "."), g, mode="read", must_exist=True, tool_name="search_code")
    if not r_info["ok"]:
        return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}

    base: Path = r_info["path"]
    if is_link_or_junction(base):
        return {"ok": False, "path": str(base), "error": f"Refusing symlink or junction path: {base}"}
    if not eff_pattern:
        return {"ok": False, "path": str(base), "error": "Please provide `pattern` (or `query` / `keyword`)."}

    eff_fixed = bool(fixed_strings)
    auto_fallback_fixed = False
    if not eff_fixed:
        try:
            re.compile(eff_pattern)
        except re.error:
            eff_fixed = True
            auto_fallback_fixed = True

    rx = re.compile(
        re.escape(eff_pattern) if eff_fixed else eff_pattern,
        re.IGNORECASE if case_insensitive else 0,
    )
    eff_inc_docs = bool(include_docs) or _glob_explicitly_targets_docs(eff_glob) or (
        base.is_file() and base.suffix.lower() in (PROSE_DOC_EXTS | STRUCTURED_DOC_EXTS)
    )

    cap = max(1, min(200, int(max_results or 40)))
    hit_tuples: List[Tuple[Path, int, str]] = []
    matched_files: List[Path] = []
    scanned_files = 0
    used_rg = False

    is_single_structured_doc = base.is_file() and base.suffix.lower() in STRUCTURED_DOC_EXTS
    rg_bin = (find_ripgrep_binary() if allow_subprocess else None) if not is_single_structured_doc else None

    if rg_bin:
        cmd = [rg_bin, "--color=never", "--max-filesize", "2M"]
        cmd.append("-l") if files_only else cmd.extend(["-n", "--with-filename", "--no-heading", "-m", str(cap)])
        if case_insensitive:
            cmd.append("-i")
        if eff_fixed:
            cmd.append("-F")
        for ex_g in RG_EXCLUDE_GLOBS:
            cmd.extend(["-g", ex_g])
        if not eff_inc_docs and base.is_dir():
            for doc_ex in RG_DOC_EXCLUDE_GLOBS:
                cmd.extend(["-g", doc_ex])
        if eff_glob:
            cmd.extend(["-g", eff_glob])
        cmd.extend(["--", eff_pattern, str(base)])
        try:
            r = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=False,
                timeout=8,
                creationflags=_win_no_window_flags(),
            )
            if r.returncode in (0, 1):
                used_rg = True
                for raw_b_ln in (r.stdout or b"").splitlines():
                    if not raw_b_ln.strip():
                        continue
                    if files_only:
                        p_str = _decode_rg_segment_bytes(raw_b_ln.rstrip(b"\r\n")).strip()
                        if not p_str:
                            continue
                        cp = Path(p_str) if Path(p_str).is_absolute() else (base / p_str)
                        if (base.is_dir() and has_link_or_junction_in_rel(cp, base)) or is_link_or_junction(cp):
                            continue
                        cp_res = cp.resolve()
                        if g.check_path_access(str(cp_res), mode="read") is not None:
                            continue
                        matched_files.append(cp_res)
                        if len(matched_files) >= cap:
                            break
                    else:
                        dec_ln = _decode_rg_stdout_line(raw_b_ln)
                        m_ln = _RG_STR_LINE_RE.match(dec_ln)
                        if not m_ln:
                            continue
                        cp = Path(m_ln.group(1)) if Path(m_ln.group(1)).is_absolute() else (base / m_ln.group(1))
                        if (base.is_dir() and has_link_or_junction_in_rel(cp, base)) or is_link_or_junction(cp):
                            continue
                        cp_res = cp.resolve()
                        if g.check_path_access(str(cp_res), mode="read") is not None:
                            continue
                        hit_tuples.append((cp_res, int(m_ln.group(2)), m_ln.group(3)[:220]))
                        if len(hit_tuples) >= cap:
                            break
                if not matched_files and not hit_tuples and (any(ord(ch) > 127 for ch in eff_pattern) or _dir_has_utf16_candidate(base)):
                    used_rg = False
        except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired, OSError):
            used_rg = False

    if not used_rg and not is_single_structured_doc:
        hit_tuples, matched_files, scanned_files = _scan_pure_python(
            base,
            rx,
            eff_glob,
            files_only,
            cap,
            g,
            include_prose_docs=eff_inc_docs,
        )

    if eff_inc_docs:
        rem_cap = cap - (len(matched_files) if files_only else len(hit_tuples))
        if rem_cap > 0:
            doc_hits, doc_files, doc_scanned = _scan_structured_docs(base, rx, eff_glob, files_only, rem_cap, g)
            scanned_files += doc_scanned
            if files_only:
                seen_f = {os.path.normcase(str(p)) for p in matched_files}
                for df in doc_files:
                    if os.path.normcase(str(df)) not in seen_f:
                        matched_files.append(df)
                        if len(matched_files) >= cap:
                            break
            else:
                hit_tuples.extend(doc_hits[:rem_cap])

    anchor_dir = base if base.is_dir() else base.parent
    cross_case_probe: Optional[Dict[str, Any]] = None
    if (len(matched_files) if files_only else len(hit_tuples)) == 0:
        for var_pat in derive_cross_case_variants(eff_pattern):
            var_rx = re.compile(re.escape(var_pat), re.IGNORECASE if case_insensitive else 0)
            v_hits, v_files, _ = _scan_pure_python(
                base,
                var_rx,
                eff_glob,
                files_only,
                min(15, cap),
                g,
                include_prose_docs=eff_inc_docs,
            )
            if files_only and v_files:
                rel_vf: List[str] = []
                for vf in v_files:
                    try:
                        rel_vf.append(vf.relative_to(anchor_dir).as_posix())
                    except ValueError:
                        rel_vf.append(str(vf))
                cross_case_probe = {"variant": var_pat, "count": len(rel_vf), "files": rel_vf}
                break
            if not files_only and v_hits:
                v_enriched = _enrich_hits_with_enclosing_symbols(v_hits, anchor_dir, g)
                cross_case_probe = {"variant": var_pat, "count": len(v_enriched), "matches": v_enriched}
                break

    if files_only:
        rel_files: List[str] = []
        for mf in matched_files:
            try:
                rel_files.append(mf.relative_to(anchor_dir).as_posix())
            except ValueError:
                rel_files.append(str(mf))
        out_f: Dict[str, Any] = {
            "ok": True,
            "pattern": eff_pattern,
            "path": str(base),
            "files_only": True,
            "include_docs": bool(include_docs),
            "engine": "ripgrep" if used_rg else "python_multi_encoding",
            "count": len(rel_files),
            "files": rel_files,
            "matches": rel_files,
        }
        if eff_glob:
            out_f["glob_filter"] = eff_glob
        if auto_fallback_fixed:
            out_f["auto_fallback_fixed_strings"] = True
        if cross_case_probe is not None:
            out_f["cross_case_variant_matches"] = cross_case_probe
        if r_info.get("healed_note"):
            out_f["healed_note"] = r_info["healed_note"]
        return out_f

    enriched_matches = _enrich_hits_with_enclosing_symbols(hit_tuples, anchor_dir, g)
    out: Dict[str, Any] = {
        "ok": True,
        "pattern": eff_pattern,
        "path": str(base),
        "include_docs": bool(include_docs),
        "engine": "ripgrep" if used_rg else "python_multi_encoding",
        "count": len(enriched_matches),
        "matches": enriched_matches,
    }
    if eff_glob:
        out["glob_filter"] = eff_glob
    if auto_fallback_fixed:
        out["auto_fallback_fixed_strings"] = True
    if cross_case_probe is not None:
        out["cross_case_variant_matches"] = cross_case_probe
    if len(enriched_matches) == 0:
        gf_s = f" (glob={eff_glob})" if eff_glob else ""
        sc_s = f" across {scanned_files} files" if scanned_files else ""
        out["zero_results_reason"] = f"0 hits for `{eff_pattern[:40]}` in `{base.name}`{sc_s}{gf_s}."
    if r_info.get("healed_note"):
        out["healed_note"] = r_info["healed_note"]
    return out


def search_code_ripgrep(
    pattern: str = "",
    path_str: str = ".",
    glob_filter: str = "",
    max_results: int = 40,
    allow_subprocess: bool = True,
    *,
    include_docs: bool = False,
    query: str = "",
    keyword: str = "",
    glob: str = "",
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    return search_code(
        pattern=pattern,
        path=path_str,
        glob_filter=glob_filter,
        max_results=max_results,
        include_docs=include_docs,
        query=query,
        keyword=keyword,
        glob=glob,
        allow_subprocess=allow_subprocess,
        guard=guard,
    )


__all__ = [
    "BINARY_SEARCH_EXTS",
    "PROSE_DOC_EXTS",
    "REPO_MAP_SOURCE_EXTS",
    "RG_DOC_EXCLUDE_GLOBS",
    "RG_EXCLUDE_GLOBS",
    "STRUCTURED_DOC_EXTS",
    "find_files",
    "find_ripgrep_binary",
    "get_repo_map",
    "list_dir",
    "repo_map",
    "search_code",
    "search_code_ripgrep",
]
