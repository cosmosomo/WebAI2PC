from __future__ import annotations

"""
AST/lexical symbol intelligence, Git-aware project RepoMap, symbol editing/refactoring,
and Rust `serde` / Go `json` / TypeScript wire-field reverse lookup (`code.py`).

All file reads, staged syntax validation, cross-process locks, and externalized history
snapshots delegate directly to `cosmos_mcp.core.{fs_io,fs_tx,patch}`.
Strictly depends only on Python >=3.9 stdlib and `cosmos_mcp.core.*`.
"""

import ast
import contextlib
import ctypes
import difflib
import hashlib
import importlib
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tokenize
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from cosmos_mcp.core.fs_io import (
    CREATE_NO_WINDOW,
    MAX_DEFAULT_READ_BYTES,
    atomic_validate_and_replace,
    auto_check_syntax,
    check_office_or_os_file_lock,
    detect_and_decode_bytes,
    encode_with_detected_encoding,
    preserve_line_endings_for_edit,
    split_lines_exact_nl,
    verify_expected_sha256,
)
from cosmos_mcp.core.fs_tx import (
    MultiFileLock,
    get_file_lock,
    pop_latest_undo_entry_quiet,
)
from cosmos_mcp.core.guard import WorkspaceGuard
from cosmos_mcp.core.patch import make_compact_diff
from cosmos_mcp.core.path_heal import (
    check_object_literal_mapping_consistency,
    has_link_or_junction_in_rel,
    heal_and_resolve_path,
    is_link_or_junction,
    is_noise_dir_name,
)

CODE_OUTLINE_EXTS: Set[str] = {
    ".py", ".pyi", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".rs", ".go", ".java", ".kt", ".c", ".h", ".cpp", ".hpp", ".cs",
    ".md", ".markdown", ".html", ".htm", ".css",
}

REPO_MAP_SOURCE_EXTS: Set[str] = {
    ".py", ".pyi", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".rs", ".go", ".java", ".kt", ".c", ".h", ".cpp", ".hpp", ".cs",
    ".html", ".css", ".json", ".md", ".ps1", ".sh",
}

RENAMEABLE_CODE_EXTS: Set[str] = {
    ".py", ".pyi", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".rs", ".go", ".java", ".kt", ".c", ".h", ".cpp", ".hpp", ".cs",
}

WIRE_CONTRACT_EXTS: Set[str] = {".rs", ".go", ".ts", ".tsx"}

_JS_CONTROL_KEYWORDS: frozenset[str] = frozenset(
    {
        "if", "for", "while", "switch", "catch", "function", "return",
        "new", "super", "import", "export", "typeof", "delete", "void",
    }
)

_COMMON_STDLIB_MODULES: frozenset[str] = frozenset(
    getattr(
        sys,
        "stdlib_module_names",
        {
            "ast", "base64", "collections", "contextlib", "copy", "csv", "ctypes",
            "datetime", "difflib", " functools", "glob", "hashlib", " inspect", "io",
            "itertools", "json", "logging", "math", "os", "pathlib", "pickle", "platform",
            "random", "re", "shutil", "socket", "sqlite3", "stat", "string", "struct",
            "subprocess", "sys", "tempfile", "threading", "time", "tokenize", "traceback",
            "typing", "unittest", "urllib", "uuid", "warnings", "xml", "zipfile", "zlib",
        },
    )
)


def _default_guard(guard: Optional[WorkspaceGuard]) -> WorkspaceGuard:
    return guard if guard is not None else WorkspaceGuard(restrict_to_workspace=False, tier="L3")


def _win_subprocess_flags() -> int:
    if sys.platform == "win32":
        with contextlib.suppress(Exception):
            ctypes.windll.kernel32.SetErrorMode(0x8003)
        return CREATE_NO_WINDOW
    return 0


def _matching_ws_root(target: Path, guard: WorkspaceGuard) -> Optional[Path]:
    roots = [Path(r) for r in getattr(guard, "workspace_roots", ()) or []]
    if not roots:
        return None
    with contextlib.suppress(Exception):
        tp = Path(target).expanduser().resolve()
        tp_full = os.path.normcase(str(tp))
        tp_norm = tp_full.rstrip("\\/")
        sep = "\\" if os.name == "nt" else "/"
        matches: List[Tuple[str, Path]] = []
        for r in roots:
            r_res = r.expanduser().resolve()
            r_norm = os.path.normcase(str(r_res)).rstrip("\\/")
            if tp_norm == r_norm or tp_full.startswith(r_norm + sep):
                matches.append((r_norm, r_res))
        if matches:
            return max(matches, key=lambda item: len(item[0]))[1]
    return roots[0]


def _split_words(ident: str) -> List[str]:
    clean = ident.strip("_")
    if not clean:
        return []
    parts: List[str] = []
    for seg in re.split(r"[-_]+", clean):
        if not seg:
            continue
        sub = re.findall(r"[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+", seg)
        parts.extend(w.lower() for w in sub) if sub else parts.append(seg.lower())
    return parts


def apply_serde_rename_rule(field_name: str, rule: str) -> str:
    """Apply Rust `#[serde(rename_all = "...")]` transformation to a source field identifier."""
    r = (rule or "").strip()
    if not r:
        return field_name
    words = _split_words(field_name)
    if not words:
        return field_name
    if r == "lowercase":
        return "".join(words).lower()
    if r == "UPPERCASE":
        return "".join(words).upper()
    if r == "camelCase":
        return words[0].lower() + "".join(w.capitalize() for w in words[1:])
    if r == "PascalCase":
        return "".join(w.capitalize() for w in words)
    if r == "snake_case":
        return "_".join(words)
    if r in ("SCREAMING_SNAKE_CASE", "UPPER_SNAKE_CASE"):
        return "_".join(w.upper() for w in words)
    if r == "kebab-case":
        return "-".join(words)
    if r == "SCREAMING-KEBAB-CASE":
        return "-".join(w.upper() for w in words)
    return field_name


def derive_cross_case_variants(identifier: str) -> List[str]:
    """Derive `snake_case` <-> `camelCase` / `PascalCase` variants for 0-hit probing."""
    s = (identifier or "").strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s):
        return []
    words = _split_words(s)
    if len(words) < 2:
        return []
    snake = "_".join(words)
    camel = words[0] + "".join(w.capitalize() for w in words[1:])
    pascal = "".join(w.capitalize() for w in words)
    out: List[str] = []
    for cand in (snake, camel, pascal):
        if cand != s and cand not in out:
            out.append(cand)
    return out


def _iter_markdown_headings(lines: Sequence[str]) -> List[Tuple[int, int, str]]:
    heading_re = re.compile(r"^\s*(#{1,6})\s+(.+?)\s*$")
    fence_re = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")
    headings: List[Tuple[int, int, str]] = []
    in_fence = False
    fence_ch = ""
    fence_len = 0
    for idx, ln in enumerate(lines):
        stripped = ln.rstrip("\r\n")
        mf = fence_re.match(stripped)
        if mf:
            marker, rest = mf.group(1), mf.group(2)
            ch, mlen = marker[0], len(marker)
            if not in_fence:
                if not (ch == "`" and "`" in rest):
                    in_fence, fence_ch, fence_len = True, ch, mlen
                    continue
            else:
                if ch == fence_ch and mlen >= fence_len and not rest.strip():
                    in_fence, fence_ch, fence_len = False, "", 0
                continue
        if in_fence:
            continue
        mh = heading_re.match(stripped)
        if mh:
            headings.append((idx, len(mh.group(1)), mh.group(2).strip()))
    return headings


def _find_brace_block_end(lines: Sequence[str], start_idx0: int) -> int:
    depth = 0
    saw_open = False
    in_block_comment = False
    n = len(lines)
    for idx in range(start_idx0, min(n, start_idx0 + 2500)):
        ln = lines[idx]
        i, m = 0, len(ln)
        while i < m:
            ch = ln[i]
            nxt = ln[i + 1] if i + 1 < m else ""
            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue
            if ch == "/" and nxt == "/":
                break
            if ch == "/" and nxt == "*":
                in_block_comment = True
                i += 2
                continue
            if ch in ("'", '"', "`"):
                q = ch
                i += 1
                while i < m:
                    if ln[i] == "\\":
                        i += 2
                        continue
                    if ln[i] == q:
                        i += 1
                        break
                    i += 1
                continue
            if ch == "{":
                depth += 1
                saw_open = True
            elif ch == "}":
                depth -= 1
                if saw_open and depth <= 0:
                    return idx + 1
            elif ch == ";" and not saw_open:
                return idx + 1
            i += 1
    return start_idx0 + 1


def _extract_level2_python_ast(content: str, lines: Sequence[str]) -> List[Dict[str, Any]]:
    clean = content[1:] if content.startswith("\ufeff") else content
    tree = ast.parse(clean)
    symbols: List[Dict[str, Any]] = []

    def _visit(nodes: Sequence[ast.AST], parent_qual: str = "") -> None:
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                def_ln = int(getattr(node, "lineno", 1))
                deco_list = getattr(node, "decorator_list", ()) or ()
                deco_ln = min([def_ln] + [int(getattr(d, "lineno", def_ln)) for d in deco_list])
                end_ln = int(getattr(node, "end_lineno", def_ln) or def_ln)
                kind = "class" if isinstance(node, ast.ClassDef) else ("method" if parent_qual else "function")
                qual = f"{parent_qual}.{node.name}" if parent_qual else node.name
                sig = lines[def_ln - 1].strip()[:120] if 1 <= def_ln <= len(lines) else node.name
                entry: Dict[str, Any] = {
                    "name": node.name,
                    "qualname": qual,
                    "kind": kind,
                    "line": deco_ln,
                    "def_line": def_ln,
                    "end_line": end_ln,
                    "signature": sig,
                }
                if parent_qual:
                    entry["parent"] = parent_qual
                symbols.append(entry)
                _visit(node.body, parent_qual=qual)

    _visit(tree.body)
    symbols.sort(key=lambda item: (item["line"], item["end_line"]))
    return symbols


def _extract_level3_brace_and_headings(lines: Sequence[str], ext: str) -> List[Dict[str, Any]]:
    symbols: List[Dict[str, Any]] = []
    if ext in (".md", ".markdown"):
        headings = _iter_markdown_headings(lines)
        for pos, (idx0, lvl, htitle) in enumerate(headings):
            end_idx0 = len(lines)
            for next_idx0, next_lvl, _ in headings[pos + 1 :]:
                if next_lvl <= lvl:
                    end_idx0 = next_idx0
                    break
            symbols.append({
                "name": htitle[:80], "qualname": htitle[:80], "kind": "markdown_heading",
                "level": lvl, "line": idx0 + 1, "end_line": max(idx0 + 1, end_idx0),
                "signature": lines[idx0].strip()[:120],
            })
        return symbols

    go_method_re = re.compile(r"^\s*func\s+\(\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)?\*?([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    js_method_re = re.compile(
        r"^\s*(?:(?:public|private|protected|static|readonly|override|abstract|async|get|set)\s+)*([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:<[^>]*>)?\s*\([^;]*\{\s*$"
    )
    lang_patterns: List[Tuple[re.Pattern[str], str]] = [
        (re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)"), "function"),
        (re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)"), "struct"),
        (re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?enum\s+([A-Za-z_][A-Za-z0-9_]*)"), "enum"),
        (re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?trait\s+([A-Za-z_][A-Za-z0-9_]*)"), "trait"),
        (re.compile(r"^\s*impl(?:<[^>]*>)?\s+(?:[A-Za-z0-9_:<>]+\s+for\s+)?([A-Za-z_][A-Za-z0-9_]*)"), "impl"),
        (re.compile(r"^\s*func\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("), "function"),
        (re.compile(r"^\s*type\s+([A-Za-z_][A-Za-z0-9_]*)\s+struct\b"), "struct"),
        (re.compile(r"^\s*type\s+([A-Za-z_][A-Za-z0-9_]*)\s+interface\b"), "interface"),
        (re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)"), "function"),
        (re.compile(r"^\s*(?:export\s+)?(?:public\s+|private\s+|protected\s+)?(?:abstract\s+|final\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)"), "class"),
        (re.compile(r"^\s*(?:export\s+)?(?:public\s+)?interface\s+([A-Za-z_$][A-Za-z0-9_$]*)"), "interface"),
        (re.compile(r"^\s*(?:export\s+)?type\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:<[^>]*>)?\s*="), "type_alias"),
        (re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>"), "arrow_function"),
        (re.compile(r"^\s*(?:module\.exports|exports)\.([A-Za-z_$][A-Za-z0-9_$]*)\s*="), "cjs_export"),
        (re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("), "function"),
        (re.compile(r"^\s*<(header|nav|main|section|footer|script|style|svg)\b[^>]*>", re.IGNORECASE), "html_section"),
    ]

    active_containers: List[Tuple[str, int]] = []  # (container_name, end_line_1based)

    for idx0, ln in enumerate(lines):
        ln_1 = idx0 + 1
        while active_containers and active_containers[-1][1] < ln_1:
            active_containers.pop()

        if ext == ".go":
            m_go = go_method_re.match(ln)
            if m_go:
                recv_type, meth_nm = m_go.group(1), m_go.group(2)
                end_ln = _find_brace_block_end(lines, idx0)
                symbols.append({
                    "name": meth_nm,
                    "qualname": f"{recv_type}.{meth_nm}",
                    "parent": recv_type,
                    "kind": "method",
                    "line": ln_1,
                    "end_line": max(ln_1, end_ln),
                    "signature": ln.strip()[:120],
                })
                continue

        matched_top = False
        for rx, kind in lang_patterns:
            m = rx.search(ln)
            if m:
                nm = m.group(1)
                if ext in (".py", ".pyi"):
                    base_indent = len(ln) - len(ln.lstrip(" \t"))
                    end_ln = ln_1
                    for j in range(idx0 + 1, len(lines)):
                        s_j = lines[j].strip()
                        if not s_j or s_j.startswith("#"):
                            continue
                        if (len(lines[j]) - len(lines[j].lstrip(" \t"))) <= base_indent and not s_j.startswith(("elif ", "else:", "except", "finally:")):
                            break
                        end_ln = j + 1
                else:
                    end_ln = _find_brace_block_end(lines, idx0)

                parent_nm = active_containers[-1][0] if (active_containers and kind == "function") else ""
                eff_kind = "method" if parent_nm else kind
                qual = f"{parent_nm}.{nm}" if parent_nm else nm
                entry: Dict[str, Any] = {
                    "name": nm,
                    "qualname": qual,
                    "kind": eff_kind,
                    "line": ln_1,
                    "end_line": max(ln_1, end_ln),
                    "signature": ln.strip()[:120],
                }
                if parent_nm:
                    entry["parent"] = parent_nm
                symbols.append(entry)
                if kind in ("class", "impl", "trait") and end_ln > ln_1:
                    active_containers.append((nm, end_ln))
                matched_top = True
                break

        if not matched_top and active_containers and ext in (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".java", ".kt", ".cs"):
            m_meth = js_method_re.match(ln)
            if m_meth:
                meth_nm = m_meth.group(1)
                if meth_nm not in _JS_CONTROL_KEYWORDS:
                    parent_nm = active_containers[-1][0]
                    end_ln = _find_brace_block_end(lines, idx0)
                    symbols.append({
                        "name": meth_nm,
                        "qualname": f"{parent_nm}.{meth_nm}",
                        "parent": parent_nm,
                        "kind": "method",
                        "line": ln_1,
                        "end_line": max(ln_1, end_ln),
                        "signature": ln.strip()[:120],
                    })

    return symbols


def _extract_level4_regex_fallback(lines: Sequence[str]) -> List[Dict[str, Any]]:
    rx = re.compile(r"^\s*(?:pub\s+|export\s+|async\s+)*(?:def|fn|func|class|struct|interface)\s+([A-Za-z_$][A-Za-z0-9_$]*)")
    out: List[Dict[str, Any]] = []
    for idx0, ln in enumerate(lines):
        m = rx.search(ln)
        if m:
            out.append({"name": m.group(1), "qualname": m.group(1), "kind": "symbol", "line": idx0 + 1, "end_line": idx0 + 1, "signature": ln.strip()[:120]})
    return out


def extract_symbols_from_text(content: str, path_str: str = "") -> List[Dict[str, Any]]:
    lines = content.splitlines()
    ext = Path(path_str).suffix.lower() if path_str else ""
    if ext in (".py", ".pyi"):
        try:
            syms = _extract_level2_python_ast(content, lines)
            if syms:
                return syms
        except SyntaxError:
            pass
    syms_l3 = _extract_level3_brace_and_headings(lines, ext)
    if syms_l3:
        return syms_l3
    return _extract_level4_regex_fallback(lines)


def _parse_rust_wire_contracts(lines: Sequence[str], file_str: str) -> List[Dict[str, Any]]:
    contracts: List[Dict[str, Any]] = []
    n, idx = len(lines), 0
    pending_rename_all = ""
    rename_all_re = re.compile(r'rename_all\s*=\s*"([^"]+)"')
    field_rename_re = re.compile(r'\brename\s*=\s*"([^"]+)"')
    field_alias_re = re.compile(r'\balias\s*=\s*"([^"]+)"')
    struct_re = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(struct|enum)\s+([A-Za-z_][A-Za-z0-9_]*)")
    field_re = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([^,/{]+)")
    while idx < n:
        ln = lines[idx]
        if "#[serde(" in ln:
            m_ra = rename_all_re.search(ln)
            if m_ra:
                pending_rename_all = m_ra.group(1)
        m_st = struct_re.match(ln)
        if m_st:
            kind_kw, type_name = m_st.group(1), m_st.group(2)
            end_ln = _find_brace_block_end(lines, idx)
            eff_rule = pending_rename_all
            pending_rename_all = ""
            fields: List[Dict[str, Any]] = []
            f_attr_rename, f_aliases = "", []
            for f_idx in range(idx + 1, min(n, end_ln)):
                fln = lines[f_idx]
                if "#[serde(" in fln:
                    m_fr = field_rename_re.search(fln)
                    if m_fr:
                        f_attr_rename = m_fr.group(1)
                    f_aliases.extend(field_alias_re.findall(fln))
                    continue
                if kind_kw == "struct":
                    m_f = field_re.match(fln)
                    if m_f:
                        src_f = m_f.group(1)
                        wire_f = f_attr_rename or apply_serde_rename_rule(src_f, eff_rule)
                        fields.append({"source_field": src_f, "wire_field": wire_f, "aliases": list(f_aliases), "line": f_idx + 1, "type": m_f.group(2).strip()})
                        f_attr_rename, f_aliases = "", []
                else:
                    m_var = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:[\({,=]|$)", fln)
                    if m_var and not fln.strip().startswith(("//", "}", "#")):
                        src_v = m_var.group(1)
                        wire_v = f_attr_rename or apply_serde_rename_rule(src_v, eff_rule)
                        fields.append({"source_field": src_v, "wire_field": wire_v, "aliases": list(f_aliases), "line": f_idx + 1, "type": "enum_variant"})
                        f_attr_rename, f_aliases = "", []
            contracts.append({"language": "rust", "file": file_str, "container": type_name, "kind": kind_kw, "line": idx + 1, "end_line": end_ln, "rename_all": eff_rule, "fields": fields})
            idx = max(idx + 1, end_ln)
            continue
        if ln.strip() and not ln.strip().startswith(("#[", "//", "///")):
            pending_rename_all = ""
        idx += 1
    return contracts


def _parse_go_wire_contracts(lines: Sequence[str], file_str: str) -> List[Dict[str, Any]]:
    contracts: List[Dict[str, Any]] = []
    struct_re = re.compile(r"^\s*type\s+([A-Za-z_][A-Za-z0-9_]*)\s+struct\s*\{")
    field_re = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s+([^\s`]+)(?:\s+`([^`]*)`)?')
    json_tag_re = re.compile(r'\bjson:"([^"]*)"')
    n, idx = len(lines), 0
    while idx < n:
        m_st = struct_re.match(lines[idx])
        if m_st:
            type_name = m_st.group(1)
            end_ln = _find_brace_block_end(lines, idx)
            fields: List[Dict[str, Any]] = []
            for f_idx in range(idx + 1, min(n, end_ln - 1)):
                fln = lines[f_idx]
                if fln.strip().startswith("//"):
                    continue
                m_f = field_re.match(fln)
                if m_f:
                    src_f, f_type, raw_tag = m_f.group(1), m_f.group(2), m_f.group(3) or ""
                    wire_f = src_f
                    m_jt = json_tag_re.search(raw_tag)
                    if m_jt:
                        tag_name = m_jt.group(1).split(",", 1)[0].strip()
                        if tag_name == "-":
                            continue
                        if tag_name:
                            wire_f = tag_name
                    fields.append({"source_field": src_f, "wire_field": wire_f, "aliases": [], "line": f_idx + 1, "type": f_type})
            contracts.append({"language": "go", "file": file_str, "container": type_name, "kind": "struct", "line": idx + 1, "end_line": end_ln, "rename_all": "", "fields": fields})
            idx = max(idx + 1, end_ln)
            continue
        idx += 1
    return contracts


def _parse_ts_wire_contracts(lines: Sequence[str], file_str: str) -> List[Dict[str, Any]]:
    contracts: List[Dict[str, Any]] = []
    hdr_re = re.compile(r"^\s*(?:export\s+)?(?:(interface)\s+([A-Za-z_$][A-Za-z0-9_$]*)|(type)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:<[^>]*>)?\s*=\s*\{)")
    prop_re = re.compile(r'^\s*(?:readonly\s+)?(?:"([^"]+)"|\'([^\']+)\'|([A-Za-z_$][A-Za-z0-9_$]*))\??\s*:\s*([^;,]+)')
    n, idx = len(lines), 0
    while idx < n:
        m_h = hdr_re.match(lines[idx])
        if m_h:
            kind_kw = m_h.group(1) or m_h.group(3) or "interface"
            type_name = m_h.group(2) or m_h.group(4) or ""
            end_ln = _find_brace_block_end(lines, idx)
            fields: List[Dict[str, Any]] = []
            for f_idx in range(idx + 1, min(n, end_ln - 1)):
                fln = lines[f_idx]
                if fln.strip().startswith(("//", "/*")):
                    continue
                m_p = prop_re.match(fln)
                if m_p:
                    pname = m_p.group(1) or m_p.group(2) or m_p.group(3) or ""
                    if pname:
                        fields.append({"source_field": pname, "wire_field": pname, "aliases": [], "line": f_idx + 1, "type": m_p.group(4).strip()})
            contracts.append({"language": "typescript", "file": file_str, "container": type_name, "kind": kind_kw, "line": idx + 1, "end_line": end_ln, "rename_all": "", "fields": fields})
            idx = max(idx + 1, end_ln)
            continue
        idx += 1
    return contracts


def parse_file_wire_contracts(file_path: Union[Path, str], text: Optional[str] = None) -> List[Dict[str, Any]]:
    fp = Path(file_path)
    ext = fp.suffix.lower()
    if ext not in WIRE_CONTRACT_EXTS:
        return []
    if text is None:
        if not fp.is_file() or fp.stat().st_size > MAX_DEFAULT_READ_BYTES:
            return []
        text, _ = detect_and_decode_bytes(fp.read_bytes(), strict_for_edit=False)
    lines = text.splitlines()
    f_str = str(fp)
    if ext == ".rs":
        return _parse_rust_wire_contracts(lines, f_str)
    if ext == ".go":
        return _parse_go_wire_contracts(lines, f_str)
    return _parse_ts_wire_contracts(lines, f_str)


def _iter_workspace_code_files(
    base: Path,
    guard: WorkspaceGuard,
    *,
    exts: Set[str] = CODE_OUTLINE_EXTS,
    max_files: int = 500,
) -> List[Path]:
    if base.is_file():
        return [base] if not is_link_or_junction(base) else []
    files: List[Path] = []
    if not base.is_dir():
        return files
    for rd, dirs, fns in os.walk(base, followlinks=False):
        rp = Path(rd)
        dirs[:] = [
            d for d in sorted(dirs)
            if not is_noise_dir_name(d) and not is_link_or_junction(rp / d) and guard.check_path_access(str(rp / d), mode="read") is None
        ]
        for fn in sorted(fns):
            if fn.startswith("."):
                continue
            fp = rp / fn
            if fp.suffix.lower() in exts and not is_link_or_junction(fp) and guard.check_path_access(str(fp), mode="read") is None:
                files.append(fp)
                if len(files) >= max_files:
                    return files
    return files


def match_wire_field_symbols(
    root_path: Union[Path, str],
    query: str,
    *,
    guard: Optional[WorkspaceGuard] = None,
    max_results: int = 30,
) -> List[Dict[str, Any]]:
    q = (query or "").strip()
    if not q:
        return []
    q_low = q.lower()
    g = _default_guard(guard)
    base = Path(root_path).resolve()
    files = _iter_workspace_code_files(base, g, exts=WIRE_CONTRACT_EXTS, max_files=400)
    hits: List[Dict[str, Any]] = []
    for fp in files:
        for contract in parse_file_wire_contracts(fp):
            for fld in contract.get("fields", ()):
                wf, sf = str(fld.get("wire_field") or ""), str(fld.get("source_field") or "")
                aliases = [str(a) for a in (fld.get("aliases") or ())]
                if q in (wf, sf) or q in aliases or q_low in (wf.lower(), sf.lower()) or any(q_low == a.lower() for a in aliases):
                    hits.append({
                        "file": contract["file"], "language": contract["language"],
                        "container": contract["container"], "container_line": contract["line"],
                        "container_end_line": contract["end_line"], "source_field": sf,
                        "wire_field": wf, "aliases": aliases, "rename_all": contract.get("rename_all") or "",
                        "line": fld["line"], "field_type": fld.get("type") or "",
                    })
                    if len(hits) >= max_results:
                        return hits
    return hits


def check_struct_field_naming_consistency(path_str: str, content: str) -> List[Dict[str, Any]]:
    contracts = parse_file_wire_contracts(path_str, text=content)
    diags: List[Dict[str, Any]] = []
    for c in contracts:
        if c.get("rename_all"):
            continue
        snake_fields = [str(f["wire_field"]) for f in c.get("fields", ()) if "_" in str(f.get("wire_field") or "") and str(f["wire_field"]) == str(f["wire_field"]).lower()]
        camel_fields = [
            str(f["wire_field"]) for f in c.get("fields", ())
            if str(f.get("wire_field") or "") and str(f["wire_field"])[0].islower() and "_" not in str(f["wire_field"]) and any(ch.isupper() for ch in str(f["wire_field"])[1:])
        ]
        if snake_fields and camel_fields:
            diags.append({
                "line": c["line"], "kind": "mixed_wire_field_casing", "container": c["container"],
                "snake_case_sample": snake_fields[:3], "camel_case_sample": camel_fields[:3],
                "detail": f"`{c['container']}` mixes snake_case ({', '.join(snake_fields[:2])}) and camelCase ({', '.join(camel_fields[:2])}) wire fields.",
            })
    return diags


def extract_outline(path: Union[Path, str], *, guard: Optional[WorkspaceGuard] = None) -> Dict[str, Any]:
    g = _default_guard(guard)
    r_info = heal_and_resolve_path(str(path), g, mode="read", must_exist=True, tool_name="code_outline")
    if not r_info["ok"]:
        return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}
    fp: Path = r_info["path"]
    if fp.is_dir():
        return {"ok": False, "path": str(fp), "error": f"Expected a file path for code_outline, got directory: {fp}"}
    if is_link_or_junction(fp):
        return {"ok": False, "path": str(fp), "error": f"Refusing symlink or junction file: {fp}"}
    raw_bytes = fp.read_bytes()
    sha = hashlib.sha256(raw_bytes).hexdigest().lower()
    content, enc_tag = detect_and_decode_bytes(raw_bytes, strict_for_edit=False)
    lines = content.splitlines()
    symbols = extract_symbols_from_text(content, str(fp))
    out: Dict[str, Any] = {
        "ok": True, "path": str(fp), "encoding": enc_tag, "total_lines": len(lines),
        "total_bytes": len(raw_bytes), "sha256": sha, "sha256_prefix": sha[:12],
        "symbol_count": len(symbols), "symbols": symbols[:300],
    }
    if r_info.get("healed_note"):
        out["healed_note"] = r_info["healed_note"]
    return out


code_outline = extract_outline
get_code_outline = extract_outline
extract_code_outline = extract_outline


def get_symbols_overview(
    path: Union[Path, str] = ".",
    *,
    max_files: int = 40,
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    """Extract recursive symbol outlines across project files (including `src/` subdirectories)."""
    g = _default_guard(guard)
    r_info = heal_and_resolve_path(str(path or "."), g, mode="read", must_exist=True, tool_name="get_symbols_overview")
    if not r_info["ok"]:
        return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}
    fp: Path = r_info["path"]
    if fp.is_file():
        return extract_outline(fp, guard=g)
    if is_link_or_junction(fp):
        return {"ok": False, "path": str(fp), "error": f"Refusing symlink or junction directory: {fp}"}

    cap = max(1, min(150, int(max_files or 40)))
    candidates = _iter_workspace_code_files(fp, g, exts=CODE_OUTLINE_EXTS, max_files=max(cap * 4, 240))
    doc_like = {".md", ".markdown", ".html", ".htm", ".css"}
    candidates.sort(
        key=lambda p: (
            p.suffix.lower() in doc_like,
            len(p.relative_to(fp).parts),
            p.relative_to(fp).as_posix().lower(),
        )
    )

    overview: List[Dict[str, Any]] = []
    for entry in candidates:
        try:
            if entry.stat().st_size > MAX_DEFAULT_READ_BYTES:
                continue
        except OSError:
            continue
        ol = extract_outline(entry, guard=g)
        if ol.get("ok"):
            rel_posix = entry.relative_to(fp).as_posix()
            overview.append(
                {
                    "file": rel_posix,
                    "path": str(entry),
                    "symbol_count": ol["symbol_count"],
                    "symbols": ol["symbols"][:40],
                }
            )
        if len(overview) >= cap:
            break
    out: Dict[str, Any] = {"ok": True, "path": str(fp), "file_count": len(overview), "files": overview}
    if r_info.get("healed_note"):
        out["healed_note"] = r_info["healed_note"]
    return out


def repo_map(
    project_path: Union[Path, str] = ".",
    max_files: int = 60,
    *,
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    """
    Generate a Git-aware project RepoMap filtering noise directories,
    with top symbol signatures and reverse `imported_by` dependencies.
    """
    g = _default_guard(guard)
    r_info = heal_and_resolve_path(
        str(project_path or "."), g, mode="read", must_exist=True, expect_dir=True, tool_name="repo_map"
    )
    if not r_info["ok"]:
        return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}

    base: Path = r_info["path"]
    if is_link_or_junction(base):
        return {"ok": False, "error": f"Refusing symlink or junction project root: {base}"}
    if len(base.parts) <= 1:
        return {"ok": False, "error": f"Refusing filesystem drive root `{base}`; pass a project directory."}

    cap = max(5, min(150, int(max_files or 60)))
    candidates: List[Path] = []
    used_git = False

    git_dir = base / ".git"
    if git_dir.exists() and not is_link_or_junction(git_dir):
        try:
            r_git = subprocess.run(
                ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                cwd=str(base),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=4,
                creationflags=_win_subprocess_flags(),
            )
            if r_git.returncode == 0:
                used_git = True
                for rel_ln in r_git.stdout.splitlines():
                    rel_s = rel_ln.strip()
                    if not rel_s:
                        continue
                    fp = base / rel_s
                    if has_link_or_junction_in_rel(fp, base) or not fp.is_file() or fp.suffix.lower() not in REPO_MAP_SOURCE_EXTS:
                        continue
                    rel_parts = fp.relative_to(base).parts
                    if any(is_noise_dir_name(pt) for pt in rel_parts[:-1]) or rel_parts[-1].startswith("."):
                        continue
                    if g.check_path_access(str(fp), mode="read") is not None:
                        continue
                    candidates.append(fp)
        except Exception:
            used_git = False

    if not used_git:
        for root_dir, dirs, files in os.walk(base, followlinks=False):
            rp = Path(root_dir)
            dirs[:] = [
                d for d in sorted(dirs)
                if not is_noise_dir_name(d) and not is_link_or_junction(rp / d) and g.check_path_access(str(rp / d), mode="read") is None
            ]
            for fn in sorted(files):
                if fn.startswith("."):
                    continue
                fp = rp / fn
                if is_link_or_junction(fp) or fp.suffix.lower() not in REPO_MAP_SOURCE_EXTS or g.check_path_access(str(fp), mode="read") is not None:
                    continue
                if fp.is_file():
                    candidates.append(fp)
                    if len(candidates) >= max(cap * 8, 320):
                        break
            if len(candidates) >= max(cap * 8, 320):
                break

    candidates.sort(key=lambda p: (len(p.relative_to(base).parts), p.relative_to(base).as_posix().lower()))
    selected = candidates[:cap]

    code_texts: Dict[str, str] = {}
    for fp in candidates[:240]:
        if fp.suffix.lower() in (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".rs", ".go"):
            try:
                if fp.stat().st_size <= 512 * 1024:
                    txt, _ = detect_and_decode_bytes(fp.read_bytes(), strict_for_edit=False)
                    code_texts[fp.relative_to(base).as_posix()] = txt
            except Exception:
                continue

    entries: List[Dict[str, Any]] = []
    for fp in selected:
        rel_str = str(fp.relative_to(base))
        rel_posix = fp.relative_to(base).as_posix()
        ol = extract_outline(fp, guard=g)
        syms = list(ol.get("symbols") or [])
        top_syms = [f"{s['kind']}:{s['signature'][:60]} (L{s['line']})" for s in syms[:8]]

        importers: List[str] = []
        if fp.suffix.lower() in (".py", ".js", ".mjs", ".ts", ".tsx", ".rs"):
            needle = fp.stem if fp.suffix.lower() in (".py", ".rs") else fp.name
            tok_re = re.compile(rf"\b{re.escape(needle)}\b")
            for other_rel, other_txt in code_texts.items():
                if other_rel != rel_posix and needle in other_txt and tok_re.search(other_txt):
                    importers.append(other_rel)
            importers.sort()

        entries.append({
            "file": rel_str,
            "rel_path": rel_posix,
            "lines": int(ol.get("total_lines") or 0),
            "bytes": int(ol.get("total_bytes") or 0),
            "imported_by": importers[:20],
            "top_symbols": top_syms,
        })

    out: Dict[str, Any] = {
        "ok": True,
        "path": str(base),
        "project_path": str(base),
        "file_count": len(entries),
        "repo_map": entries,
    }
    if r_info.get("healed_note"):
        out["healed_note"] = r_info["healed_note"]
    return out


get_repo_map = repo_map


def find_enclosing_symbol(symbols: Sequence[Dict[str, Any]], line_1based: int) -> Optional[Dict[str, Any]]:
    best: Optional[Dict[str, Any]] = None
    best_span = 10**9
    for sym in symbols:
        s_ln = int(sym.get("line", 0))
        e_ln = int(sym.get("end_line", s_ln))
        if s_ln <= line_1based <= e_ln and (e_ln - s_ln) <= best_span:
            best = sym
            best_span = e_ln - s_ln
    return best


def compute_symbol_candidates(
    symbols: Sequence[Dict[str, Any]],
    target_symbol: str,
    *,
    min_ratio: float = 0.40,
    max_candidates: int = 8,
) -> List[Dict[str, Any]]:
    norm_q = (target_symbol or "").strip().replace("/", ".").replace("::", ".")
    q_low = norm_q.lower()
    leaf_low = q_low.split(".")[-1]
    scored: List[Tuple[float, Dict[str, Any]]] = []
    for sym in symbols:
        nm = str(sym.get("name") or "")
        qn = str(sym.get("qualname") or nm)
        ratio = max(
            difflib.SequenceMatcher(None, q_low, qn.lower()).ratio(),
            difflib.SequenceMatcher(None, leaf_low, nm.lower()).ratio(),
        )
        if leaf_low and (leaf_low in nm.lower() or nm.lower() in leaf_low):
            ratio = max(ratio, 0.65)
        if ratio >= min_ratio:
            scored.append((ratio, {
                "name": qn, "kind": sym.get("kind", "symbol"),
                "line": sym.get("line", 1), "end_line": sym.get("end_line", 1),
                "similarity": round(ratio, 3), "signature": sym.get("signature", ""),
            }))
    scored.sort(key=lambda item: (-item[0], int(item[1]["line"])))
    return [c for _, c in scored[:max_candidates]]


def resolve_symbol_in_outline(
    symbols: Sequence[Dict[str, Any]],
    symbol_query: str,
) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    norm_q = (symbol_query or "").strip().replace("/", ".").replace("::", ".")
    if not norm_q:
        return None, []
    exact = [s for s in symbols if s.get("qualname") == norm_q or s.get("name") == norm_q]
    if exact:
        qual_exact = [s for s in exact if s.get("qualname") == norm_q]
        return (qual_exact[0] if qual_exact else exact[0]), []
    q_low = norm_q.lower()
    ci_matches = [s for s in symbols if str(s.get("qualname") or "").lower() == q_low or str(s.get("name") or "").lower() == q_low]
    if ci_matches:
        return ci_matches[0], []
    return None, compute_symbol_candidates(symbols, norm_q, min_ratio=0.40)


def _load_optional_jedi() -> Any:
    try:
        return importlib.import_module("jedi")
    except Exception:
        return None


def _is_path_under_dir(child: Path, parent: Path) -> bool:
    with contextlib.suppress(Exception):
        c_norm = os.path.normcase(str(child.resolve()))
        p_norm = os.path.normcase(str(parent.resolve())).rstrip("\\/")
        sep = "\\" if os.name == "nt" else "/"
        return c_norm == p_norm or c_norm.startswith(p_norm + sep)
    return False


def _resolve_jedi_project_root(base: Path, guard: WorkspaceGuard) -> Optional[Path]:
    with contextlib.suppress(Exception):
        b_res = base.expanduser().resolve()
        if b_res.is_dir():
            cur_d = b_res
            for _ in range(6):
                if not (cur_d / "__init__.py").exists():
                    break
                parent_d = cur_d.parent
                if parent_d == cur_d or len(parent_d.parts) < 3:
                    break
                if guard.check_path_access(str(parent_d), mode="read", tool_name="code_intel") is not None:
                    break
                cur_d = parent_d
            return cur_d if len(cur_d.parts) >= 3 else None
        ws = _matching_ws_root(b_res, guard)
        if ws is not None and ws.exists() and len(ws.parts) >= 3:
            return ws.expanduser().resolve()
        cur = b_res.parent
        for _ in range(6):
            if len(cur.parts) < 3:
                break
            if guard.check_path_access(str(cur), mode="read", tool_name="code_intel") is not None:
                break
            if any((cur / m).exists() for m in ("pyproject.toml", "setup.py", ".git")):
                return cur
            if cur.parent == cur:
                break
            cur = cur.parent
        return b_res.parent if len(b_res.parent.parts) >= 3 else None
    return None


def _build_jedi_project(jedi_mod: Any, proj_root: Path) -> Any:
    extra_sys: List[str] = []
    src_sub = proj_root / "src"
    if src_sub.is_dir() and not is_link_or_junction(src_sub):
        extra_sys.append(str(src_sub))
    if extra_sys:
        try:
            return jedi_mod.Project(path=str(proj_root), added_sys_path=extra_sys)
        except TypeError:
            pass
    return jedi_mod.Project(path=str(proj_root))


_JEDI_KIND_MAP: Dict[str, str] = {
    "class": "class",
    "function": "function",
    "module": "module",
    "instance": "variable",
    "statement": "variable",
    "param": "param",
}


def _jedi_find_symbol(
    jedi_mod: Any,
    norm_q: str,
    base: Path,
    guard: WorkspaceGuard,
    *,
    include_body: bool,
    include_line_numbers: bool,
    substring_matching: bool,
    max_results: int,
) -> Optional[List[Dict[str, Any]]]:
    if base.is_file() and base.suffix.lower() not in (".py", ".pyi"):
        return None
    proj_root = _resolve_jedi_project_root(base, guard)
    if proj_root is None:
        return None

    q_low = norm_q.lower()
    leaf = norm_q.split(".")[-1].strip()
    leaf_low = leaf.lower()
    if not leaf:
        return None

    try:
        jedi_proj = _build_jedi_project(jedi_mod, proj_root)
        raw_defs: List[Any] = []
        if base.is_file():
            if base.stat().st_size > MAX_DEFAULT_READ_BYTES:
                return None
            src_txt, _ = detect_and_decode_bytes(base.read_bytes(), strict_for_edit=False)
            script = jedi_mod.Script(code=src_txt, path=str(base), project=jedi_proj)
            for n in script.get_names(all_scopes=True, definitions=True, references=True):
                nm = str(getattr(n, "name", "") or "")
                fn = str(getattr(n, "full_name", "") or nm)
                nm_l, fn_l = nm.lower(), fn.lower()
                hit = (
                    nm == norm_q
                    or fn == norm_q
                    or fn.endswith("." + norm_q)
                    or nm_l == q_low
                    or fn_l == q_low
                    or fn_l.endswith("." + q_low)
                    or nm_l == leaf_low
                    or (substring_matching and (q_low in nm_l or q_low in fn_l))
                )
                if not hit:
                    continue
                desc = str(getattr(n, "description", "") or "")
                if n.is_definition() and not desc.startswith(("import ", "from ")):
                    raw_defs.append(n)
                else:
                    for gd in n.goto(follow_imports=True, follow_builtin_imports=False):
                        if getattr(gd, "module_path", None):
                            raw_defs.append(gd)
        else:
            try:
                searched = list(jedi_proj.search(leaf, all_scopes=True))
            except TypeError:
                searched = list(jedi_proj.search(leaf))
            cross_file_fallbacks: List[Any] = []
            for n in searched:
                mp = getattr(n, "module_path", None)
                if not mp:
                    continue
                mfp = Path(mp).resolve()
                desc = str(getattr(n, "description", "") or "")
                if desc.startswith(("import ", "from ")):
                    if _is_path_under_dir(mfp, base):
                        for gd in n.goto(follow_imports=True, follow_builtin_imports=False):
                            if getattr(gd, "module_path", None):
                                cross_file_fallbacks.append(gd)
                    continue
                if _is_path_under_dir(mfp, base):
                    raw_defs.append(n)
                else:
                    cross_file_fallbacks.append(n)
            if not raw_defs and cross_file_fallbacks:
                raw_defs.extend(cross_file_fallbacks)

        file_cache: Dict[str, Tuple[List[str], List[Dict[str, Any]]]] = {}
        seen: Set[Tuple[str, int, str]] = set()
        matches: List[Dict[str, Any]] = []

        for d in raw_defs:
            mp = getattr(d, "module_path", None)
            mfp = Path(mp).resolve() if mp else (base if base.is_file() else None)
            if mfp is None or not mfp.exists() or not mfp.is_file():
                continue
            if is_link_or_junction(mfp):
                continue
            if guard.check_path_access(str(mfp), mode="read", tool_name="find_symbol") is not None:
                continue
            if mfp.stat().st_size > MAX_DEFAULT_READ_BYTES:
                continue

            nm = str(getattr(d, "name", "") or "")
            fn = str(getattr(d, "full_name", "") or nm)
            nm_l, fn_l = nm.lower(), fn.lower()
            is_hit = (
                nm == norm_q
                or fn == norm_q
                or fn.endswith("." + norm_q)
                or nm_l == q_low
                or fn_l == q_low
                or fn_l.endswith("." + q_low)
                or (substring_matching and (q_low in nm_l or q_low in fn_l))
            )
            if not is_hit:
                continue

            f_key = os.path.normcase(str(mfp))
            if f_key not in file_cache:
                f_txt, _ = detect_and_decode_bytes(mfp.read_bytes(), strict_for_edit=False)
                file_cache[f_key] = (f_txt.splitlines(), extract_symbols_from_text(f_txt, str(mfp)))
            f_lines, f_syms = file_cache[f_key]

            d_line = int(getattr(d, "line", 1) or 1)
            matched_sym: Optional[Dict[str, Any]] = None
            for s in f_syms:
                if int(s.get("def_line") or s.get("line") or 0) == d_line or (
                    str(s.get("name") or "") == nm and int(s.get("line") or 0) <= d_line <= int(s.get("end_line") or 0)
                ):
                    matched_sym = s
                    break

            if matched_sym is not None:
                s_ln = int(matched_sym["line"])
                e_ln = int(matched_sym["end_line"])
                qn = str(matched_sym.get("qualname") or nm)
                kind = str(matched_sym.get("kind") or "symbol")
                sig = str(matched_sym.get("signature") or "")
            else:
                s_ln = d_line
                e_ln = d_line
                with contextlib.suppress(Exception):
                    end_pos = d.get_definition_end_position()
                    if end_pos and end_pos[0]:
                        e_ln = max(s_ln, int(end_pos[0]))
                qn = nm
                kind = _JEDI_KIND_MAP.get(str(getattr(d, "type", "") or "").lower(), "symbol")
                sig = f_lines[s_ln - 1].strip() if 1 <= s_ln <= len(f_lines) else str(getattr(d, "description", "") or nm)

            dedup_k = (f_key, s_ln, qn)
            if dedup_k in seen:
                continue
            seen.add(dedup_k)

            item: Dict[str, Any] = {
                "file": str(mfp),
                "name": nm,
                "qualname": qn,
                "full_name": fn,
                "kind": kind,
                "line": s_ln,
                "end_line": e_ln,
                "signature": sig,
                "engine": "jedi",
            }
            if include_body:
                body_slice = f_lines[max(0, s_ln - 1) : min(len(f_lines), e_ln)]
                item["body"] = "\n".join(
                    (f"{s_ln + i}| {guard.redact_sensitive_output(ln)}" if include_line_numbers else guard.redact_sensitive_output(ln))
                    for i, ln in enumerate(body_slice)
                )
            matches.append(item)
            if len(matches) >= max_results:
                break
        return matches
    except Exception:
        return None


def _jedi_find_references(
    jedi_mod: Any,
    norm_q: str,
    leaf: str,
    base: Path,
    guard: WorkspaceGuard,
    *,
    max_results: int,
) -> Optional[List[Dict[str, Any]]]:
    if base.is_file() and base.suffix.lower() not in (".py", ".pyi"):
        return None
    proj_root = _resolve_jedi_project_root(base, guard)
    if proj_root is None:
        return None

    q_low = norm_q.lower()
    leaf_low = leaf.lower()
    try:
        jedi_proj = _build_jedi_project(jedi_mod, proj_root)
        seeds: List[Tuple[Path, int, int]] = []
        if base.is_file():
            if base.stat().st_size > MAX_DEFAULT_READ_BYTES:
                return None
            src_txt, _ = detect_and_decode_bytes(base.read_bytes(), strict_for_edit=False)
            script = jedi_mod.Script(code=src_txt, path=str(base), project=jedi_proj)
            for n in script.get_names(all_scopes=True, definitions=True, references=True):
                nm = str(getattr(n, "name", "") or "")
                fn = str(getattr(n, "full_name", "") or nm)
                if (
                    fn == norm_q
                    or fn.endswith("." + norm_q)
                    or fn.lower() == q_low
                    or fn.lower().endswith("." + q_low)
                    or nm == leaf
                    or nm.lower() == leaf_low
                ):
                    if getattr(n, "line", None) is not None:
                        seeds.append((base, int(n.line), int(getattr(n, "column", 0) or 0)))
                        break
        else:
            try:
                searched = list(jedi_proj.search(leaf, all_scopes=True))
            except TypeError:
                searched = list(jedi_proj.search(leaf))
            exact_seeds: List[Tuple[Path, int, int]] = []
            fallback_seeds: List[Tuple[Path, int, int]] = []
            for n in searched:
                mp = getattr(n, "module_path", None)
                if not mp or getattr(n, "line", None) is None:
                    continue
                desc = str(getattr(n, "description", "") or "")
                if desc.startswith(("import ", "from ")):
                    continue
                mfp = Path(mp).resolve()
                if is_link_or_junction(mfp):
                    continue
                if guard.check_path_access(str(mfp), mode="read", tool_name="find_referencing_symbols") is not None:
                    continue
                nm = str(getattr(n, "name", "") or "")
                fn = str(getattr(n, "full_name", "") or nm)
                cand = (mfp, int(n.line), int(getattr(n, "column", 0) or 0))
                if fn == norm_q or fn.endswith("." + norm_q) or fn.lower() == q_low or fn.lower().endswith("." + q_low):
                    if _is_path_under_dir(mfp, base):
                        exact_seeds.insert(0, cand)
                    else:
                        exact_seeds.append(cand)
                elif nm == leaf or nm.lower() == leaf_low:
                    if _is_path_under_dir(mfp, base):
                        fallback_seeds.insert(0, cand)
                    else:
                        fallback_seeds.append(cand)
            seeds = (exact_seeds or fallback_seeds)[:3]

        if not seeds:
            return None

        file_cache: Dict[str, Tuple[List[str], List[Dict[str, Any]]]] = {}
        seen_locs: Set[Tuple[str, int]] = set()
        refs: List[Dict[str, Any]] = []
        base_norm = os.path.normcase(str(base.resolve()))

        for seed_fp, seed_ln, seed_col in seeds:
            s_key = os.path.normcase(str(seed_fp))
            if s_key not in file_cache:
                s_txt, _ = detect_and_decode_bytes(seed_fp.read_bytes(), strict_for_edit=False)
                file_cache[s_key] = (s_txt.splitlines(), extract_symbols_from_text(s_txt, str(seed_fp)))
            seed_src = "\n".join(file_cache[s_key][0])
            script = jedi_mod.Script(code=seed_src, path=str(seed_fp), project=jedi_proj)
            j_refs = script.get_references(line=seed_ln, column=seed_col, include_builtins=False)
            for r in j_refs:
                mp = getattr(r, "module_path", None)
                rfp = Path(mp).resolve() if mp else seed_fp
                r_key = os.path.normcase(str(rfp))
                if base.is_file():
                    if r_key != base_norm:
                        continue
                elif not _is_path_under_dir(rfp, base):
                    continue
                if not rfp.exists() or not rfp.is_file() or is_link_or_junction(rfp):
                    continue
                if guard.check_path_access(str(rfp), mode="read", tool_name="find_referencing_symbols") is not None:
                    continue
                if rfp.stat().st_size > MAX_DEFAULT_READ_BYTES:
                    continue
                idx1 = int(getattr(r, "line", 0) or 0)
                if idx1 <= 0 or (r_key, idx1) in seen_locs:
                    continue
                seen_locs.add((r_key, idx1))
                if r_key not in file_cache:
                    r_txt, _ = detect_and_decode_bytes(rfp.read_bytes(), strict_for_edit=False)
                    file_cache[r_key] = (r_txt.splitlines(), extract_symbols_from_text(r_txt, str(rfp)))
                r_lines, r_syms = file_cache[r_key]
                ln_txt = r_lines[idx1 - 1] if 1 <= idx1 <= len(r_lines) else ""
                enc = find_enclosing_symbol(r_syms, idx1)
                refs.append(
                    {
                        "file": str(rfp),
                        "line": idx1,
                        "column": int(getattr(r, "column", 0) or 0),
                        "is_definition": bool(r.is_definition()),
                        "enclosing_symbol": enc.get("qualname") if enc else None,
                        "enclosing_kind": enc.get("kind") if enc else None,
                        "snippet": guard.redact_sensitive_output(ln_txt.strip()[:200]),
                        "engine": "jedi",
                    }
                )
                if len(refs) >= max_results:
                    break
            if len(refs) >= max_results:
                break
        return refs if refs else None
    except Exception:
        return None


def find_symbol(
    symbol: str,
    path: Union[Path, str] = ".",
    *,
    include_body: bool = True,
    include_line_numbers: bool = True,
    substring_matching: bool = False,
    max_results: int = 30,
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    g = _default_guard(guard)
    q = (symbol or "").strip()
    if not q:
        return {"ok": False, "error": "`symbol` is required for find_symbol."}
    r_info = heal_and_resolve_path(str(path or "."), g, mode="read", must_exist=True, tool_name="find_symbol")
    if not r_info["ok"]:
        return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}
    base: Path = r_info["path"]
    norm_q = q.replace("/", ".").replace("::", ".")
    q_low = norm_q.lower()
    matches: List[Dict[str, Any]] = []
    pool: List[Tuple[Path, Dict[str, Any]]] = []
    used_jedi = False

    jedi_mod = _load_optional_jedi()
    if jedi_mod is not None:
        j_matches = _jedi_find_symbol(
            jedi_mod,
            norm_q,
            base,
            g,
            include_body=include_body,
            include_line_numbers=include_line_numbers,
            substring_matching=substring_matching,
            max_results=max_results,
        )
        if j_matches:
            matches.extend(j_matches[:max_results])
            used_jedi = True

    seen_keys: Set[Tuple[str, int, str]] = {
        (os.path.normcase(str(m["file"])), int(m["line"]), str(m["qualname"])) for m in matches
    }
    if len(matches) < max_results:
        for fp in _iter_workspace_code_files(base, g):
            if used_jedi and not substring_matching and fp.suffix.lower() in (".py", ".pyi"):
                continue
            try:
                if fp.stat().st_size > MAX_DEFAULT_READ_BYTES:
                    continue
                txt, _ = detect_and_decode_bytes(fp.read_bytes(), strict_for_edit=False)
            except Exception:
                continue
            lines = txt.splitlines()
            for s in extract_symbols_from_text(txt, str(fp)):
                nm, qn = str(s.get("name") or ""), str(s.get("qualname") or s.get("name") or "")
                is_hit = qn == norm_q or nm == norm_q or qn.lower() == q_low or nm.lower() == q_low or (substring_matching and (q_low in qn.lower() or q_low in nm.lower()))
                if is_hit:
                    s_ln, e_ln = int(s["line"]), int(s["end_line"])
                    dk = (os.path.normcase(str(fp)), s_ln, qn)
                    if dk in seen_keys:
                        continue
                    seen_keys.add(dk)
                    item: Dict[str, Any] = {"file": str(fp), "name": nm, "qualname": qn, "kind": s["kind"], "line": s_ln, "end_line": e_ln, "signature": s.get("signature", "")}
                    if include_body:
                        body_slice = lines[max(0, s_ln - 1) : min(len(lines), e_ln)]
                        item["body"] = "\n".join(
                            (f"{s_ln + i}| {g.redact_sensitive_output(ln)}" if include_line_numbers else g.redact_sensitive_output(ln))
                            for i, ln in enumerate(body_slice)
                        )
                    matches.append(item)
                    if len(matches) >= max_results:
                        break
                else:
                    pool.append((fp, s))
            if len(matches) >= max_results:
                break
    wire_matches = match_wire_field_symbols(base, q, guard=g, max_results=15)
    out: Dict[str, Any] = {
        "ok": True,
        "symbol": q,
        "path": str(base),
        "engine": "jedi" if used_jedi else "ast",
        "count": len(matches),
        "matches": matches,
    }
    if wire_matches:
        out["wire_field_matches"] = wire_matches
    if not matches and not wire_matches:
        scored: List[Tuple[float, Dict[str, Any]]] = []
        leaf_low = q_low.split(".")[-1]
        for fp, s in pool:
            nm, qn = str(s.get("name") or ""), str(s.get("qualname") or s.get("name") or "")
            ratio = max(difflib.SequenceMatcher(None, q_low, qn.lower()).ratio(), difflib.SequenceMatcher(None, leaf_low, nm.lower()).ratio())
            if leaf_low and (leaf_low in nm.lower() or nm.lower() in leaf_low):
                ratio = max(ratio, 0.65)
            if ratio >= 0.40:
                scored.append((ratio, {"file": str(fp), "name": qn, "kind": s.get("kind", "symbol"), "line": s.get("line", 1), "end_line": s.get("end_line", 1), "similarity": round(ratio, 3), "signature": s.get("signature", "")}))
        scored.sort(key=lambda it: (-it[0], it[1]["file"], int(it[1]["line"])))
        out["symbol_candidates"] = [c for _, c in scored[:8]]
    return out


def find_referencing_symbols(
    symbol: str,
    path: Union[Path, str] = ".",
    *,
    max_results: int = 50,
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    g = _default_guard(guard)
    q = (symbol or "").strip()
    if not q:
        return {"ok": False, "error": "`symbol` is required for find_referencing_symbols."}
    norm_q = q.replace("/", ".").replace("::", ".")
    leaf = norm_q.split(".")[-1].strip()
    if not leaf:
        return {"ok": False, "error": f"Invalid symbol `{symbol}`."}
    r_info = heal_and_resolve_path(str(path or "."), g, mode="read", must_exist=True, tool_name="find_referencing_symbols")
    if not r_info["ok"]:
        return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}
    base: Path = r_info["path"]
    cap = max(1, min(200, int(max_results or 50)))
    refs: List[Dict[str, Any]] = []
    used_jedi = False

    jedi_mod = _load_optional_jedi()
    if jedi_mod is not None:
        j_refs = _jedi_find_references(jedi_mod, norm_q, leaf, base, g, max_results=cap)
        if j_refs is not None:
            refs.extend(j_refs[:cap])
            used_jedi = True

    if len(refs) < cap:
        tok_re = re.compile(rf"\b{re.escape(leaf)}\b")
        seen_ref_locs: Set[Tuple[str, int]] = {(os.path.normcase(str(r["file"])), int(r["line"])) for r in refs}
        for fp in _iter_workspace_code_files(base, g):
            if used_jedi and fp.suffix.lower() in (".py", ".pyi"):
                continue
            try:
                if fp.stat().st_size > MAX_DEFAULT_READ_BYTES:
                    continue
                txt, _ = detect_and_decode_bytes(fp.read_bytes(), strict_for_edit=False)
            except Exception:
                continue
            if not tok_re.search(txt):
                continue
            syms = extract_symbols_from_text(txt, str(fp))
            def_lines = {int(s.get("def_line") or s.get("line") or 0) for s in syms if s.get("name") == leaf}
            fp_norm = os.path.normcase(str(fp))
            for idx1, ln in enumerate(txt.splitlines(), start=1):
                if not tok_re.search(ln):
                    continue
                if (fp_norm, idx1) in seen_ref_locs:
                    continue
                seen_ref_locs.add((fp_norm, idx1))
                enc = find_enclosing_symbol(syms, idx1)
                refs.append({
                    "file": str(fp), "line": idx1, "is_definition": idx1 in def_lines,
                    "enclosing_symbol": enc.get("qualname") if enc else None,
                    "enclosing_kind": enc.get("kind") if enc else None,
                    "snippet": g.redact_sensitive_output(ln.strip()[:200]),
                })
                if len(refs) >= cap:
                    break
            if len(refs) >= cap:
                break
    wire_refs = match_wire_field_symbols(base, leaf, guard=g, max_results=10)
    out: Dict[str, Any] = {
        "ok": True,
        "symbol": q,
        "path": str(base),
        "engine": "jedi" if used_jedi else "ast",
        "count": len(refs),
        "references": refs,
    }
    if wire_refs:
        out["wire_field_matches"] = wire_refs
    return out


def replace_symbol_body(
    path: Union[Path, str],
    symbol: str,
    new_body: str,
    *,
    expected_sha256: str = "",
    check_syntax: bool = True,
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    g = _default_guard(guard)
    sym_q = (symbol or "").strip()
    if not sym_q:
        return {"ok": False, "path": str(path), "error": "`symbol` is required for replace_symbol_body."}
    r_info = heal_and_resolve_path(str(path), g, mode="write", must_exist=True, tool_name="replace_symbol_body")
    if not r_info["ok"]:
        return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}
    fp: Path = r_info["path"]
    ws_root = _matching_ws_root(fp, g)
    ws_roots = [Path(r) for r in getattr(g, "workspace_roots", ()) or []]
    with get_file_lock(fp):
        pre_lk = check_office_or_os_file_lock(fp, for_write=True)
        if pre_lk is not None:
            return pre_lk
        raw_bytes = fp.read_bytes()
        sha_err = verify_expected_sha256(raw_bytes, expected_sha256)
        if sha_err:
            return {"ok": False, "optimistic_lock_conflict": True, "path": str(fp), "error": sha_err}
        raw_text, enc_tag = detect_and_decode_bytes(raw_bytes, strict_for_edit=True)
        lf_text = raw_text.replace("\r\n", "\n")
        syms = extract_symbols_from_text(lf_text, str(fp))
        target_sym, cands = resolve_symbol_in_outline(syms, sym_q)
        if target_sym is None:
            return {"ok": False, "path": str(fp), "symbol": sym_q, "symbol_candidates": cands, "error": f"Symbol `{sym_q}` not found in {fp.name}."}
        s_ln, e_ln = int(target_sym["line"]), int(target_sym["end_line"])
        lf_lines = split_lines_exact_nl(lf_text)
        orig_first = lf_lines[s_ln - 1] if 1 <= s_ln <= len(lf_lines) else ""
        orig_indent = orig_first[: len(orig_first) - len(orig_first.lstrip(" \t"))]
        new_lines = new_body.replace("\r\n", "\n").splitlines()
        if new_lines and orig_indent and not new_lines[0].startswith((" ", "\t")):
            new_lines = [(orig_indent + ln if ln.strip() else ln) for ln in new_lines]
        rep_block = "\n".join(new_lines)
        if rep_block and not rep_block.endswith("\n"):
            rep_block += "\n"
        updated_lf = "".join(lf_lines[: s_ln - 1]) + rep_block + "".join(lf_lines[e_ln:])
        final_bytes = encode_with_detected_encoding(preserve_line_endings_for_edit(raw_text, updated_lf), enc_tag)
        commit = atomic_validate_and_replace(
            fp,
            final_bytes,
            enforce_syntax=bool(check_syntax),
            save_snapshot=True,
            workspace_root=ws_root,
            workspace_roots=ws_roots,
            state_root=g.effective_state_root(),
            guard=g,
        )
        if not commit.get("ok"):
            if commit.get("file_locked_by_external_app"):
                return commit
            return {"ok": False, "auto_rolled_back": True, "path": str(fp), "symbol": target_sym["qualname"], "syntax_check": commit.get("syntax_check"), "error": f"Replacing symbol `{target_sym['qualname']}` introduced a syntax error; original file untouched."}
        return {
            "ok": True, "path": str(fp), "symbol": target_sym["qualname"], "replaced_lines": f"{s_ln}..{e_ln}",
            "sha256": commit["sha256"], "sha256_prefix": commit["sha256_prefix"], "undo_snapshot": commit.get("undo_snapshot"),
            "diff_preview": make_compact_diff(lf_text, updated_lf, filename=fp.name, max_lines=30),
        }


def insert_after_symbol(
    path: Union[Path, str],
    symbol: str,
    code: str,
    *,
    position: str = "after",
    expected_sha256: str = "",
    check_syntax: bool = True,
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    g = _default_guard(guard)
    sym_q = (symbol or "").strip()
    if not sym_q:
        return {"ok": False, "path": str(path), "error": "`symbol` is required for insert_after_symbol."}
    pos = (position or "after").strip().lower()
    if pos not in ("after", "before"):
        return {"ok": False, "path": str(path), "error": "`position` must be 'after' or 'before'."}
    r_info = heal_and_resolve_path(str(path), g, mode="write", must_exist=True, tool_name="insert_after_symbol")
    if not r_info["ok"]:
        return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}
    fp: Path = r_info["path"]
    ws_root = _matching_ws_root(fp, g)
    ws_roots = [Path(r) for r in getattr(g, "workspace_roots", ()) or []]
    with get_file_lock(fp):
        pre_lk = check_office_or_os_file_lock(fp, for_write=True)
        if pre_lk is not None:
            return pre_lk
        raw_bytes = fp.read_bytes()
        sha_err = verify_expected_sha256(raw_bytes, expected_sha256)
        if sha_err:
            return {"ok": False, "optimistic_lock_conflict": True, "path": str(fp), "error": sha_err}
        raw_text, enc_tag = detect_and_decode_bytes(raw_bytes, strict_for_edit=True)
        lf_text = raw_text.replace("\r\n", "\n")
        syms = extract_symbols_from_text(lf_text, str(fp))
        target_sym, cands = resolve_symbol_in_outline(syms, sym_q)
        if target_sym is None:
            return {"ok": False, "path": str(fp), "symbol": sym_q, "symbol_candidates": cands, "error": f"Symbol `{sym_q}` not found in {fp.name}."}
        s_ln, e_ln = int(target_sym["line"]), int(target_sym["end_line"])
        lf_lines = split_lines_exact_nl(lf_text)
        ins_block = code.replace("\r\n", "\n").strip("\n") + "\n"
        if pos == "before":
            updated_lf = "".join(lf_lines[: s_ln - 1]) + ins_block + "\n" + "".join(lf_lines[s_ln - 1 :])
            inserted_at = s_ln
        else:
            prefix = "".join(lf_lines[:e_ln])
            if prefix and not prefix.endswith("\n"):
                prefix += "\n"
            updated_lf = prefix + "\n" + ins_block + "".join(lf_lines[e_ln:])
            inserted_at = e_ln + 1
        final_bytes = encode_with_detected_encoding(preserve_line_endings_for_edit(raw_text, updated_lf), enc_tag)
        commit = atomic_validate_and_replace(
            fp,
            final_bytes,
            enforce_syntax=bool(check_syntax),
            save_snapshot=True,
            workspace_root=ws_root,
            workspace_roots=ws_roots,
            state_root=g.effective_state_root(),
            guard=g,
        )
        if not commit.get("ok"):
            if commit.get("file_locked_by_external_app"):
                return commit
            return {"ok": False, "auto_rolled_back": True, "path": str(fp), "symbol": target_sym["qualname"], "syntax_check": commit.get("syntax_check"), "error": f"Inserting {pos} `{target_sym['qualname']}` introduced a syntax error; original file untouched."}
        return {
            "ok": True, "path": str(fp), "symbol": target_sym["qualname"], "position": pos, "inserted_at_line": inserted_at,
            "sha256": commit["sha256"], "sha256_prefix": commit["sha256_prefix"], "undo_snapshot": commit.get("undo_snapshot"),
            "diff_preview": make_compact_diff(lf_text, updated_lf, filename=fp.name, max_lines=30),
        }


def _apply_token_spans(source_lf: str, spans: Set[Tuple[int, int, int]], new_ident: str) -> Tuple[str, int]:
    if not spans:
        return source_lf, 0
    lines = source_lf.splitlines(keepends=True)
    ordered = sorted(spans, reverse=True)
    applied = 0
    for row0, s_col, e_col in ordered:
        if 0 <= row0 < len(lines):
            ln = lines[row0]
            lines[row0] = ln[:s_col] + new_ident + ln[e_col:]
            applied += 1
    return "".join(lines), applied


def _collect_ident_tokens(source_lf: str, ident: str) -> List[tokenize.TokenInfo]:
    out: List[tokenize.TokenInfo] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source_lf).readline):
            if tok.type == tokenize.NAME and tok.string == ident and tok.start[0] == tok.end[0]:
                out.append(tok)
    except tokenize.TokenError:
        pass
    return out


def _find_def_name_span(
    tokens: Sequence[tokenize.TokenInfo],
    def_line_1based: int,
    old_ident: str,
) -> Optional[Tuple[int, int, int]]:
    for tok in tokens:
        if tok.start[0] >= def_line_1based and tok.string == old_ident:
            return (tok.start[0] - 1, tok.start[1], tok.end[1])
    return None


def _find_attr_name_span(
    all_tokens: Sequence[tokenize.TokenInfo],
    attr_node: ast.Attribute,
    old_ident: str,
) -> Optional[Tuple[int, int, int]]:
    val_end_ln = int(getattr(attr_node.value, "end_lineno", getattr(attr_node, "lineno", 1)) or 1)
    val_end_col = int(getattr(attr_node.value, "end_col_offset", 0) or 0)
    node_end_ln = int(getattr(attr_node, "end_lineno", val_end_ln) or val_end_ln)
    node_end_col = int(getattr(attr_node, "end_col_offset", 10**6) or 10**6)

    saw_dot = False
    for tok in all_tokens:
        r1, c0 = tok.start
        if (r1, c0) < (val_end_ln, val_end_col):
            continue
        if (r1, tok.end[1]) > (node_end_ln, node_end_col):
            break
        if tok.type == tokenize.OP and tok.string == ".":
            saw_dot = True
            continue
        if saw_dot and tok.type == tokenize.NAME and tok.string == old_ident:
            return (r1 - 1, c0, tok.end[1])
    return None


def _annotation_mentions_class(ann: Optional[ast.AST], target_classes: Set[str]) -> Optional[str]:
    if ann is None:
        return None
    names = [n.id for n in ast.walk(ann) if isinstance(n, ast.Name)]
    if any(nm in target_classes for nm in names):
        return "target"
    non_wrappers = [
        nm for nm in names
        if nm[:1].isupper() and nm not in ("Optional", "Union", "Any", "Final", "ClassVar", "Type", "Sequence", "List", "Set", "Tuple", "Dict")
    ]
    if non_wrappers:
        return "other"
    return None


def _call_created_class_tag(expr: Optional[ast.AST], target_classes: Set[str]) -> Optional[str]:
    if not isinstance(expr, ast.Call):
        return None
    fn = expr.func
    cname = ""
    if isinstance(fn, ast.Name):
        cname = fn.id
    elif isinstance(fn, ast.Attribute):
        cname = fn.attr
    if not cname:
        return None
    if cname in target_classes:
        return "target"
    if cname[:1].isupper():
        return "other"
    return None


def _rename_class_method_in_python(
    source_lf: str,
    target_container: str,
    old_ident: str,
    new_ident: str,
) -> Tuple[str, int]:
    clean = source_lf[1:] if source_lf.startswith("\ufeff") else source_lf
    bom_offset = 1 if (source_lf.startswith("\ufeff")) else 0
    try:
        tree = ast.parse(clean)
        all_tokens = list(tokenize.generate_tokens(io.StringIO(clean).readline))
    except (SyntaxError, tokenize.TokenError):
        return source_lf, 0

    ident_tokens = [t for t in all_tokens if t.type == tokenize.NAME and t.string == old_ident and t.start[0] == t.end[0]]
    if not ident_tokens:
        return source_lf, 0

    target_norm = target_container.replace("/", ".").replace("::", ".")
    target_leaf = target_norm.split(".")[-1]
    target_classes: Set[str] = {target_leaf}
    target_class_nodes: Set[int] = set()

    # Pass 1: discover target classes and direct/transitive subclasses within file
    all_class_defs: List[Tuple[str, ast.ClassDef]] = []

    def _collect_classes(nodes: Sequence[ast.AST], prefix: str = "") -> None:
        for nd in nodes:
            if isinstance(nd, ast.ClassDef):
                qual = f"{prefix}.{nd.name}" if prefix else nd.name
                all_class_defs.append((qual, nd))
                if qual == target_norm or nd.name == target_leaf:
                    target_classes.add(nd.name)
                    target_class_nodes.add(id(nd))
                _collect_classes(nd.body, qual)

    _collect_classes(tree.body)

    changed = True
    while changed:
        changed = False
        for _, cnode in all_class_defs:
            if id(cnode) in target_class_nodes:
                continue
            for base_expr in cnode.bases:
                bname = base_expr.id if isinstance(base_expr, ast.Name) else (base_expr.attr if isinstance(base_expr, ast.Attribute) else "")
                if bname in target_classes:
                    target_classes.add(cnode.name)
                    target_class_nodes.add(id(cnode))
                    changed = True

    spans: Set[Tuple[int, int, int]] = set()

    def _receiver_is_target(recv: ast.AST, bound_vars: Dict[str, str], in_target_cls: bool) -> bool:
        if isinstance(recv, ast.Name):
            if recv.id in target_classes:
                return True
            return bound_vars.get(recv.id) == "target"
        if isinstance(recv, ast.Attribute):
            return recv.attr in target_classes
        if isinstance(recv, ast.Call):
            ctag = _call_created_class_tag(recv, target_classes)
            if ctag == "target":
                return True
            if isinstance(recv.func, ast.Name) and recv.func.id == "super" and in_target_cls:
                return True
        return False

    def _scan_expr(expr: Optional[ast.AST], bound_vars: Dict[str, str], in_target_cls: bool, in_cls_body: bool = False) -> None:
        if expr is None:
            return
        if isinstance(expr, ast.Attribute):
            _scan_expr(expr.value, bound_vars, in_target_cls, False)
            if expr.attr == old_ident and _receiver_is_target(expr.value, bound_vars, in_target_cls):
                sp = _find_attr_name_span(all_tokens, expr, old_ident)
                if sp is not None:
                    spans.add(sp)
            return
        if in_cls_body and in_target_cls and isinstance(expr, ast.Name) and expr.id == old_ident:
            ln0 = int(expr.lineno) - 1
            col0 = int(expr.col_offset)
            spans.add((ln0, col0, col0 + len(old_ident)))
            return
        for child in ast.iter_child_nodes(expr):
            _scan_expr(child, bound_vars, in_target_cls, in_cls_body)

    def _walk_block(
        stmts: Sequence[ast.stmt],
        outer_vars: Dict[str, str],
        *,
        enclosing_cls: Optional[ast.ClassDef] = None,
        is_class_body: bool = False,
    ) -> None:
        bound_vars = dict(outer_vars)
        in_target_cls = enclosing_cls is not None and id(enclosing_cls) in target_class_nodes

        for st in stmts:
            if isinstance(st, ast.ClassDef):
                for b_ex in st.bases:
                    _scan_expr(b_ex, bound_vars, in_target_cls)
                for d_ex in st.decorator_list:
                    _scan_expr(d_ex, bound_vars, in_target_cls)
                _walk_block(st.body, bound_vars, enclosing_cls=st, is_class_body=True)
                continue

            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for d_ex in st.decorator_list:
                    _scan_expr(d_ex, bound_vars, in_target_cls, is_class_body)
                for def_val in list(st.args.defaults) + [d for d in st.args.kw_defaults if d is not None]:
                    _scan_expr(def_val, bound_vars, in_target_cls, False)

                if is_class_body and in_target_cls and st.name == old_ident:
                    sp_def = _find_def_name_span(ident_tokens, int(st.lineno), old_ident)
                    if sp_def is not None:
                        spans.add(sp_def)

                fn_vars = {k: v for k, v in bound_vars.items() if k not in ("self", "cls")}
                all_args = list(getattr(st.args, "posonlyargs", ())) + list(st.args.args)
                if is_class_body and enclosing_cls is not None and all_args:
                    has_staticmethod = any(
                        (isinstance(d, ast.Name) and d.id == "staticmethod")
                        or (isinstance(d, ast.Attribute) and d.attr == "staticmethod")
                        for d in st.decorator_list
                    )
                    if not has_staticmethod:
                        fn_vars[all_args[0].arg] = "target" if in_target_cls else "other"

                for arg_item in all_args + list(st.args.kwonlyargs):
                    atag = _annotation_mentions_class(arg_item.annotation, target_classes)
                    if atag is not None:
                        fn_vars[arg_item.arg] = atag

                _walk_block(st.body, fn_vars, enclosing_cls=enclosing_cls, is_class_body=False)
                continue

            if isinstance(st, ast.Assign):
                _scan_expr(st.value, bound_vars, in_target_cls, is_class_body)
                ctag = _call_created_class_tag(st.value, target_classes)
                for tgt in st.targets:
                    _scan_expr(tgt, bound_vars, in_target_cls, False)
                    if isinstance(tgt, ast.Name):
                        if ctag is not None:
                            bound_vars[tgt.id] = ctag
                        elif isinstance(st.value, ast.Name) and st.value.id in bound_vars:
                            bound_vars[tgt.id] = bound_vars[st.value.id]
                        else:
                            bound_vars.pop(tgt.id, None)
                continue

            if isinstance(st, ast.AnnAssign):
                _scan_expr(st.value, bound_vars, in_target_cls, is_class_body)
                atag = _annotation_mentions_class(st.annotation, target_classes) or _call_created_class_tag(st.value, target_classes)
                if isinstance(st.target, ast.Name) and atag is not None:
                    bound_vars[st.target.id] = atag
                continue

            for child_node in ast.iter_child_nodes(st):
                if isinstance(child_node, ast.stmt):
                    _walk_block([child_node], bound_vars, enclosing_cls=enclosing_cls, is_class_body=False)
                elif isinstance(child_node, ast.expr):
                    _scan_expr(child_node, bound_vars, in_target_cls, is_class_body)

    _walk_block(tree.body, {})

    if bom_offset and spans:
        spans = {(r0, (sc + bom_offset if r0 == 0 else sc), (ec + bom_offset if r0 == 0 else ec)) for r0, sc, ec in spans}
    return _apply_token_spans(source_lf, spans, new_ident)


def _rename_top_level_in_python(source_lf: str, old_ident: str, new_ident: str) -> Tuple[str, int]:
    """Rename a top-level symbol in Python while preserving unrelated class methods and stdlib attributes."""
    clean = source_lf[1:] if source_lf.startswith("\ufeff") else source_lf
    bom_offset = 1 if source_lf.startswith("\ufeff") else 0
    try:
        tree = ast.parse(clean)
        all_tokens = list(tokenize.generate_tokens(io.StringIO(clean).readline))
    except (SyntaxError, tokenize.TokenError):
        return _rename_identifier_in_code(source_lf, old_ident, new_ident)

    ident_tokens = [t for t in all_tokens if t.type == tokenize.NAME and t.string == old_ident and t.start[0] == t.end[0]]
    if not ident_tokens:
        return source_lf, 0

    imported_modules: Set[str] = set()
    local_import_aliases: Set[str] = set()
    protected_spans: Set[Tuple[int, int, int]] = set()

    for nd in ast.walk(tree):
        if isinstance(nd, ast.Import):
            for al in nd.names:
                mod_root = al.name.split(".")[0]
                bound = al.asname or mod_root
                imported_modules.add(bound)
                if mod_root not in _COMMON_STDLIB_MODULES:
                    local_import_aliases.add(bound)
        elif isinstance(nd, ast.ClassDef):
            for body_item in nd.body:
                if isinstance(body_item, (ast.FunctionDef, ast.AsyncFunctionDef)) and body_item.name == old_ident:
                    sp = _find_def_name_span(ident_tokens, int(body_item.lineno), old_ident)
                    if sp is not None:
                        protected_spans.add(sp)

    for nd in ast.walk(tree):
        if isinstance(nd, ast.Attribute) and nd.attr == old_ident:
            sp_attr = _find_attr_name_span(all_tokens, nd, old_ident)
            if sp_attr is None:
                continue
            if isinstance(nd.value, ast.Name) and nd.value.id in local_import_aliases:
                continue
            protected_spans.add(sp_attr)

    spans: Set[Tuple[int, int, int]] = set()
    for tok in ident_tokens:
        cand = (tok.start[0] - 1, tok.start[1], tok.end[1])
        if cand not in protected_spans:
            spans.add(cand)

    if bom_offset and spans:
        spans = {(r0, (sc + bom_offset if r0 == 0 else sc), (ec + bom_offset if r0 == 0 else ec)) for r0, sc, ec in spans}
    return _apply_token_spans(source_lf, spans, new_ident)


def _rename_identifier_in_code(source_lf: str, old_ident: str, new_ident: str) -> Tuple[str, int]:
    pattern = re.compile(
        r"""(?:"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|`(?:\\.|[^`\\])*`|/\*[\s\S]*?\*/|//[^\r\n]*|#[^\r\n]*)"""
        rf"""|\b({re.escape(old_ident)})\b"""
    )
    count = 0

    def _sub(m: re.Match[str]) -> str:
        nonlocal count
        if m.group(1) is not None:
            count += 1
            return new_ident
        return m.group(0)

    return pattern.sub(_sub, source_lf), count


def _rename_class_method_in_brace_code(
    source_lf: str,
    ext: str,
    target_container: str,
    old_ident: str,
    new_ident: str,
) -> Tuple[str, int]:
    """Rename `target_container.old_ident` in JS/TS/Rust/Go/Java/C# without touching unrelated classes."""
    target_leaf = target_container.replace("/", ".").replace("::", ".").split(".")[-1]
    lines = source_lf.splitlines(keepends=True)
    raw_lines_no_nl = [ln.rstrip("\r\n") for ln in lines]
    syms = _extract_level3_brace_and_headings(raw_lines_no_nl, ext)

    target_spans_lines: List[Tuple[int, int]] = []
    other_spans_lines: List[Tuple[int, int]] = []
    for s in syms:
        if s.get("kind") in ("class", "impl", "trait", "struct", "interface"):
            if s.get("name") == target_leaf:
                target_spans_lines.append((int(s["line"]), int(s["end_line"])))
            else:
                other_spans_lines.append((int(s["line"]), int(s["end_line"])))
        elif ext == ".go" and s.get("kind") == "method":
            if s.get("parent") == target_leaf:
                target_spans_lines.append((int(s["line"]), int(s["end_line"])))
            else:
                other_spans_lines.append((int(s["line"]), int(s["end_line"])))

    # Discover local typed / constructed instance names (`x = new Target(...)`, `x: Target`, `x := Target{}`)
    bound_inst_re = re.compile(
        rf"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::\s*{re.escape(target_leaf)}\b|(?::=|=)\s*(?:&?{re.escape(target_leaf)}\s*\{{|new\s+{re.escape(target_leaf)}\s*\(|{re.escape(target_leaf)}::))"
    )
    bound_instances: Set[str] = {m.group(1) for m in bound_inst_re.finditer(source_lf)}

    total_count = 0
    out_lines: List[str] = []

    def _in_ranges(ln_1: int, rngs: Sequence[Tuple[int, int]]) -> bool:
        return any(s <= ln_1 <= e for s, e in rngs)

    for idx0, full_ln in enumerate(lines):
        ln_1 = idx0 + 1
        in_target = _in_ranges(ln_1, target_spans_lines)
        in_other = _in_ranges(ln_1, other_spans_lines) and not in_target
        updated_ln = full_ln

        if in_target:
            # Rename method definition header and `this.old_ident` / `self.old_ident` / `Target.old_ident`
            def_rx = re.compile(
                rf"(^\s*(?:(?:pub(?:\([^)]*\))?|public|private|protected|static|readonly|override|async|fn|func\s*\([^)]*\))\s+)*)({re.escape(old_ident)})(\s*(?:<[^>]*>)?\s*\()"
            )
            updated_ln, c_def = def_rx.subn(rf"\1{new_ident}\3", updated_ln, count=1)
            total_count += c_def

            recv_alts = "|".join(re.escape(x) for x in sorted({"this", "self", target_leaf} | bound_instances))
            call_rx = re.compile(rf"\b({recv_alts})(\s*(?:\.|::)\s*)({re.escape(old_ident)})\b")
            updated_ln, c_call = call_rx.subn(rf"\1\2{new_ident}", updated_ln)
            total_count += c_call
        elif not in_other:
            receivers = sorted({target_leaf} | bound_instances)
            if receivers:
                recv_alts = "|".join(re.escape(x) for x in receivers)
                ext_rx = re.compile(rf"\b({recv_alts})(\s*(?:\.|::)\s*)({re.escape(old_ident)})\b")
                updated_ln, c_ext = ext_rx.subn(rf"\1\2{new_ident}", updated_ln)
                total_count += c_ext
            new_call_rx = re.compile(rf"(\bnew\s+{re.escape(target_leaf)}\s*\([^)]*\)\s*\.\s*)({re.escape(old_ident)})\b")
            updated_ln, c_new = new_call_rx.subn(rf"\1{new_ident}", updated_ln)
            total_count += c_new
        else:
            # Inside an unrelated class: ONLY rename explicit `TargetClass.old_ident` or typed `bound_inst.old_ident`
            receivers = sorted({target_leaf} | (bound_instances - {"this", "self"}))
            if receivers:
                recv_alts = "|".join(re.escape(x) for x in receivers)
                ext_rx = re.compile(rf"\b({recv_alts})(\s*(?:\.|::)\s*)({re.escape(old_ident)})\b")
                updated_ln, c_ext = ext_rx.subn(rf"\1\2{new_ident}", updated_ln)
                total_count += c_ext

        out_lines.append(updated_ln)

    return "".join(out_lines), total_count


def rename_symbol(
    symbol: str,
    new_name: str,
    path: Union[Path, str] = ".",
    *,
    dry_run: bool = False,
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    """
    Rename a symbol across code files with AST class-method scoping:
    - Qualified `ClassA.method` renames only `ClassA` (and its subclasses / typed instances), never `ClassB.method`.
    - Unqualified `method` refuses ambiguous renames when defined on multiple classes or colliding with top-level functions.
    """
    g = _default_guard(guard)
    norm_sym = (symbol or "").strip().replace("/", ".").replace("::", ".")
    if "." in norm_sym:
        target_container, old_leaf = norm_sym.rsplit(".", 1)
        target_container = target_container.strip()
        old_leaf = old_leaf.strip()
    else:
        target_container = ""
        old_leaf = norm_sym

    clean_new = (new_name or "").strip()
    if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", old_leaf):
        return {"ok": False, "error": f"Invalid source symbol identifier `{symbol}`."}
    if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", clean_new):
        return {"ok": False, "error": f"Invalid `new_name` `{new_name}`: must be a valid identifier."}
    if old_leaf == clean_new:
        return {"ok": False, "error": "`new_name` is identical to current symbol name."}

    req_mode = "read" if dry_run else "write"
    r_info = heal_and_resolve_path(str(path or "."), g, mode=req_mode, must_exist=True, tool_name="rename_symbol")
    if not r_info["ok"]:
        return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}

    root_p: Path = r_info["path"]
    cand_files = _iter_workspace_code_files(root_p, g, exts=RENAMEABLE_CODE_EXTS, max_files=600)
    if not dry_run:
        cand_files = [fp for fp in cand_files if g.check_path_access(str(fp), mode="write") is None]
    ws_roots = [Path(r) for r in getattr(g, "workspace_roots", ()) or []]
    word_re = re.compile(rf"\b{re.escape(old_leaf)}\b")

    lock_ctx = contextlib.nullcontext() if dry_run else MultiFileLock(cand_files)
    with lock_ctx:
        file_records: List[Tuple[Path, bytes, str, str]] = []
        method_defs: List[Tuple[Path, Dict[str, Any]]] = []
        top_defs: List[Tuple[Path, Dict[str, Any]]] = []

        for fp in cand_files:
            if not fp.is_file() or is_link_or_junction(fp):
                continue
            try:
                if fp.stat().st_size > MAX_DEFAULT_READ_BYTES:
                    continue
                raw_b = fp.read_bytes()
                raw_txt, enc_tag = detect_and_decode_bytes(raw_b, strict_for_edit=True)
            except Exception:
                continue
            if not word_re.search(raw_txt):
                continue
            file_records.append((fp, raw_b, raw_txt, enc_tag))
            for s in extract_symbols_from_text(raw_txt, str(fp)):
                if s.get("name") != old_leaf:
                    continue
                if s.get("kind") == "method" and s.get("parent"):
                    method_defs.append((fp, s))
                else:
                    top_defs.append((fp, s))

        distinct_parents = sorted({str(s["parent"]) for _, s in method_defs})
        effective_container = target_container

        if not effective_container:
            if len(distinct_parents) >= 2 or (len(distinct_parents) == 1 and len(top_defs) >= 1):
                conflicts = [f"{p}.{old_leaf}" for p in distinct_parents] + [
                    str(s.get("qualname") or s["name"]) for _, s in top_defs
                ]
                return {
                    "ok": False,
                    "ambiguous_symbol": True,
                    "symbol": norm_sym,
                    "conflicting_definitions": conflicts,
                    "error": (
                        f"Ambiguous symbol `{old_leaf}` is defined across multiple classes/scopes "
                        f"({', '.join(conflicts[:6])}); pass qualified `ClassName.{old_leaf}` to avoid modifying unrelated classes."
                    ),
                }
            if len(distinct_parents) == 1 and not top_defs:
                effective_container = distinct_parents[0]
        else:
            tgt_leaf = effective_container.split(".")[-1]
            has_matching_container = any(
                str(s.get("parent") or "") == effective_container
                or str(s.get("parent") or "").split(".")[-1] == tgt_leaf
                for _, s in method_defs
            )
            if not has_matching_container:
                return {
                    "ok": False,
                    "symbol": norm_sym,
                    "symbol_candidates": [f"{p}.{old_leaf}" for p in distinct_parents],
                    "error": f"Qualified method `{norm_sym}` not found in `{root_p.name}`.",
                }

        planned: List[Tuple[Path, bytes, bytes, int, str]] = []
        for fp, raw_b, raw_txt, enc_tag in file_records:
            lf_txt = raw_txt.replace("\r\n", "\n")
            ext = fp.suffix.lower()
            if effective_container:
                if ext in (".py", ".pyi"):
                    upd_lf, cnt = _rename_class_method_in_python(lf_txt, effective_container, old_leaf, clean_new)
                else:
                    upd_lf, cnt = _rename_class_method_in_brace_code(lf_txt, ext, effective_container, old_leaf, clean_new)
            else:
                if ext in (".py", ".pyi"):
                    upd_lf, cnt = _rename_top_level_in_python(lf_txt, old_leaf, clean_new)
                else:
                    upd_lf, cnt = _rename_identifier_in_code(lf_txt, old_leaf, clean_new)

            if cnt > 0 and upd_lf != lf_txt:
                final_b = encode_with_detected_encoding(preserve_line_endings_for_edit(raw_txt, upd_lf), enc_tag)
                planned.append((fp, raw_b, final_b, cnt, make_compact_diff(lf_txt, upd_lf, filename=fp.name, max_lines=16)))

        sym_label = f"{effective_container}.{old_leaf}" if effective_container else old_leaf
        if dry_run or not planned:
            return {
                "ok": True, "dry_run": bool(dry_run), "symbol": sym_label, "new_name": clean_new,
                "files_affected": len(planned), "files_modified": 0,
                "total_replacements": sum(c for _, _, _, c, _ in planned),
                "changes": [{"path": str(fp), "replacements": cnt, "diff_preview": dp} for fp, _, _, cnt, dp in planned],
            }

        for fp, _, final_b, _, _ in planned:
            chk_txt, _ = detect_and_decode_bytes(final_b, strict_for_edit=False)
            sc = auto_check_syntax(fp, content=chk_txt, raw_bytes=final_b)
            if not sc.get("valid", True):
                return {
                    "ok": False, "dry_run": False, "failed_path": str(fp),
                    "auto_rolled_back": True, "rolled_back_all": True, "syntax_check": sc,
                    "error": f"Rename `{sym_label}` -> `{clean_new}` introduced a syntax error in `{fp.name}` ({sc.get('error')}); aborted before modifying any file.",
                }

        committed_originals: List[Tuple[Path, bytes]] = []
        committed_changes: List[Dict[str, Any]] = []
        sr = g.effective_state_root()
        for fp, orig_b, final_b, cnt, dp in planned:
            ws_root = _matching_ws_root(fp, g)
            try:
                cm = atomic_validate_and_replace(
                    fp,
                    final_b,
                    enforce_syntax=True,
                    save_snapshot=True,
                    workspace_root=ws_root,
                    workspace_roots=ws_roots,
                    state_root=sr,
                    guard=g,
                )
            except BaseException as exc:
                for rp, rb in reversed(committed_originals):
                    rp_ws = _matching_ws_root(rp, g)
                    with contextlib.suppress(Exception):
                        atomic_validate_and_replace(rp, rb, enforce_syntax=False, save_snapshot=False, workspace_root=rp_ws, workspace_roots=ws_roots, state_root=sr, guard=g)
                        pop_latest_undo_entry_quiet(rp, workspace_root=rp_ws, workspace_roots=ws_roots, state_root=sr, guard=g)
                return {
                    "ok": False, "dry_run": False, "failed_path": str(fp),
                    "auto_rolled_back": True, "rolled_back_all": True,
                    "error": f"Write failed on `{fp.name}` ({type(exc).__name__}: {exc}); rolled back all files.",
                }
            if not cm.get("ok"):
                for rp, rb in reversed(committed_originals):
                    rp_ws = _matching_ws_root(rp, g)
                    with contextlib.suppress(Exception):
                        atomic_validate_and_replace(rp, rb, enforce_syntax=False, save_snapshot=False, workspace_root=rp_ws, workspace_roots=ws_roots, state_root=sr, guard=g)
                        pop_latest_undo_entry_quiet(rp, workspace_root=rp_ws, workspace_roots=ws_roots, state_root=sr, guard=g)
                out_err = dict(cm) if cm.get("file_locked_by_external_app") else {}
                out_err.update({
                    "ok": False, "dry_run": False, "failed_path": str(fp),
                    "auto_rolled_back": True, "rolled_back_all": True,
                    "syntax_check": cm.get("syntax_check"),
                    "error": str(cm.get("error") or f"Commit failed on `{fp.name}`; rolled back all files."),
                })
                return out_err
            committed_originals.append((fp, orig_b))
            committed_changes.append({"path": str(fp), "replacements": cnt, "sha256": cm["sha256"], "diff_preview": dp})

    return {
        "ok": True, "dry_run": False, "symbol": sym_label, "new_name": clean_new,
        "files_affected": len(committed_changes), "files_modified": len(committed_changes),
        "total_replacements": sum(int(item["replacements"]) for item in committed_changes),
        "changes": committed_changes,
    }


def run_code_intel(
    path: Union[Path, str] = ".",
    action: str = "outline",
    symbols: Any = None,
    symbol: str = "",
    new_name: str = "",
    include_line_numbers: bool = True,
    max_results: int = 50,
    *,
    guard: Optional[WorkspaceGuard] = None,
    check_node: bool = True,
) -> Dict[str, Any]:
    g = _default_guard(guard)
    act = (action or "outline").strip().lower()
    if act == "find_symbol":
        act = "symbol"
    elif act in ("find_references", "find_referencing_symbols", "references"):
        act = "refs"
    if act == "outline":
        r_info = heal_and_resolve_path(str(path or "."), g, mode="read", must_exist=True, tool_name="code_intel")
        if not r_info["ok"]:
            return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}
        fp: Path = r_info["path"]
        if fp.is_dir():
            ov = get_symbols_overview(fp, max_files=max_results, guard=g)
            ov["action"] = "outline"
            return ov
        ol = extract_outline(fp, guard=g)
        ol["action"] = "outline"
        if ol.get("ok") and fp.suffix.lower() in WIRE_CONTRACT_EXTS:
            wc = parse_file_wire_contracts(fp)
            if wc:
                ol["wire_contracts"] = wc
        return ol

    if act in ("overview", "repo_map"):
        rm = repo_map(project_path=path, max_files=max_results, guard=g)
        if rm.get("ok"):
            rm["action"] = act
        return rm

    if act == "symbol":
        sym_list: List[str] = []
        if symbol and str(symbol).strip():
            sym_list.append(str(symbol).strip())
        if isinstance(symbols, str) and symbols.strip():
            for part in symbols.split(","):
                if part.strip() and part.strip() not in sym_list:
                    sym_list.append(part.strip())
        elif isinstance(symbols, (list, tuple)):
            for part in symbols:
                if str(part).strip() and str(part).strip() not in sym_list:
                    sym_list.append(str(part).strip())
        if not sym_list:
            return {"ok": False, "action": "symbol", "error": "Provide `symbol` or `symbols` when action='symbol'."}
        if len(sym_list) == 1:
            res = find_symbol(sym_list[0], path=path, include_body=True, include_line_numbers=include_line_numbers, max_results=max_results, guard=g)
            res["action"] = "symbol"
            return res
        merged_matches: List[Dict[str, Any]] = []
        merged_cands: Dict[str, List[Dict[str, Any]]] = {}
        for sq in sym_list[:8]:
            sub = find_symbol(sq, path=path, include_body=True, include_line_numbers=include_line_numbers, max_results=max_results, guard=g)
            merged_matches.extend(sub.get("matches") or [])
            if sub.get("symbol_candidates"):
                merged_cands[sq] = sub["symbol_candidates"]
        out_m: Dict[str, Any] = {"ok": True, "action": "symbol", "symbols": sym_list[:8], "count": len(merged_matches), "matches": merged_matches}
        if merged_cands:
            out_m["symbol_candidates"] = merged_cands
        return out_m

    if act == "refs":
        eff_sym = (symbol or "").strip()
        if not eff_sym and isinstance(symbols, (list, tuple)) and symbols:
            eff_sym = str(symbols[0]).strip()
        elif not eff_sym and isinstance(symbols, str):
            eff_sym = symbols.strip()
        res_r = find_referencing_symbols(eff_sym, path=path, max_results=max_results, guard=g)
        res_r["action"] = "refs"
        return res_r

    if act == "diagnostics":
        r_info = heal_and_resolve_path(str(path or "."), g, mode="read", must_exist=True, tool_name="code_intel")
        if not r_info["ok"]:
            return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}
        base: Path = r_info["path"]
        targets = _iter_workspace_code_files(base, g, max_files=min(80, max(1, int(max_results or 50))))
        diagnostics: List[Dict[str, Any]] = []
        for fp in targets:
            try:
                raw_b = fp.read_bytes()
                txt, _ = detect_and_decode_bytes(raw_b, strict_for_edit=False)
            except Exception as exc:
                diagnostics.append({"file": str(fp), "severity": "error", "kind": "decode_error", "error": str(exc)})
                continue
            sc = auto_check_syntax(fp, content=txt, raw_bytes=raw_b, check_node=check_node)
            if not sc.get("valid", True):
                diagnostics.append({
                    "file": str(fp), "severity": "error", "kind": "syntax_error",
                    "checker": sc.get("checker", ""), "line": sc.get("line", 1),
                    "column": sc.get("column", 1), "error": sc.get("error", "Syntax error"),
                })
            for nm_d in check_struct_field_naming_consistency(str(fp), txt):
                diagnostics.append({"file": str(fp), "severity": "warning", **nm_d})
            for mp_d in check_object_literal_mapping_consistency(str(fp), txt):
                diagnostics.append({"file": str(fp), "severity": "warning", **mp_d})
            if len(diagnostics) >= max_results:
                break
        return {
            "ok": True, "action": "diagnostics", "path": str(base),
            "files_checked": len(targets), "issue_count": len(diagnostics),
            "diagnostics": diagnostics[:max_results],
        }

    if act in ("rename_symbol", "rename"):
        eff_sym = (symbol or "").strip()
        eff_new = (new_name or "").strip()
        if not eff_sym or not eff_new:
            return {
                "ok": False,
                "action": "rename_symbol",
                "error_code": "INVALID_PARAMETER",
                "error": "Provide both `symbol` (or `ClassName.method`) and `new_name` when action='rename_symbol'.",
            }
        res_rn = rename_symbol(eff_sym, eff_new, path=path, guard=g)
        res_rn["action"] = "rename_symbol"
        return res_rn

    return {
        "ok": False, "error_code": "INVALID_PARAMETER", "action": action,
        "allowed_actions": ["outline", "overview", "repo_map", "symbol", "refs", "diagnostics", "rename_symbol"],
        "error": f"Invalid code_intel action `{action}`; expected 'outline', 'overview', 'repo_map', 'symbol', 'refs', 'diagnostics', or 'rename_symbol'.",
    }
