"""Fault-tolerant SKILL.md frontmatter parser, symlink/junction-safe local scanner, and mtime-cached BM25F index.

Zero third-party runtime dependencies; compatible with Python >= 3.9.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import re
import threading
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from cosmos_mcp.capabilities.skills.models import (
    SkillRecord,
    SkillsConfig,
    disabled_skills_fingerprint,
    is_link_or_junction,
    is_skill_disabled,
    is_subpath,
    read_disabled_skills_state,
)
from cosmos_mcp.capabilities.skills.vetter import decode_text_with_bom_and_cookie

__all__ = [
    "LocalSkillIndex",
    "find_skill_markdown",
    "parse_skill_frontmatter",
    "scan_local_skills",
    "tokenize_mixed_text",
]

_SKIP_SCAN_DIRS: Set[str] = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    ".undo_history",
    ".pytest_cache",
    ".mypy_cache",
}

_PLAIN_SCALAR_ONLY_KEYS: Set[str] = {
    "name",
    "description",
    "short-description",
    "short_description",
    "license",
    "argument-hint",
}

_STOP_WORDS_EN: Set[str] = {
    "a", "an", "and", "are", "as", "at", "be", "before", "by", "for", "from",
    "how", "in", "into", "is", "it", "of", "on", "or", "that", "the", "this",
    "to", "use", "using", "when", "with", "your", "you", "want", "wants", "need",
}

_STOP_BIGRAMS_ZH: Set[str] = {
    "的时", "时候", "去了", "下去", "是被", "到了", "怎么", "什么", "一个", "我们",
    "这个", "那个", "然后", "可以", "没有", "已经", "如果", "因为", "所以", "进行",
    "出现", "导致", "问题", "情况", "当前", "需要", "使用", "通过", "以及", "或者",
    "帮我", "一下", "里面", "某件", "某个", "大家", "别人", "发给", "给我",
}

_GENERIC_META_EN: Set[str] = {"skill", "skills", "tool", "tools"}
_GENERIC_META_ZH: Tuple[str, ...] = ("技能", "工具")
_GENERIC_META_ALL: Set[str] = set(_GENERIC_META_EN) | set(_GENERIC_META_ZH)

# Lightweight bidirectional ZH <-> EN core technical concept bridge
_BILINGUAL_CONCEPT_GROUPS: Tuple[Tuple[Tuple[str, ...], Tuple[str, ...]], ...] = (
    (("前端", "界面"), ("frontend", "ui")),
    (("后端", "服务端"), ("backend", "server")),
    (("官网", "落地页", "网站", "网页"), ("landing", "website", "web", "page")),
    (("设计", "排版", "样式"), ("design", "layout", "style")),
    (("审查", "审计", "红队", "检视"), ("audit", "review", "redteam")),
    (("数据泄漏", "数据泄露", "泄漏", "泄露"), ("leakage", "leak")),
    (("过拟合",), ("overfitting", "overfit")),
    (("静默退化", "退化", "兜底", "降级"), ("fallback", "degradation", "degrade")),
    (("表格", "电子表格", "工作簿"), ("xlsx", "excel", "csv", "spreadsheet", "table")),
    (("文档", "报告", "论文"), ("doc", "docx", "pdf", "document", "markdown")),
    (("幻灯片", "演示", "汇报"), ("slide", "slides", "pptx", "presentation", "deck")),
    (("测试", "单测", "验收"), ("test", "testing", "unittest", "pytest")),
    (("安全", "漏洞", "体检"), ("security", "vetter", "vulnerability")),
    (("数据库", "查询"), ("database", "sql", "postgres", "sqlite")),
)

_FRONTMATTER_RE = re.compile(
    r"^---[ \t]*\r?\n(.*?)(?:\r?\n---[ \t]*(?:\r?\n|$))",
    re.DOTALL,
)
_EMPTY_FRONTMATTER_RE = re.compile(r"^---[ \t]*\r?\n---[ \t]*(?:\r?\n|$)")
_BLOCK_SCALAR_HEADER_RE = re.compile(r"^([|>])([+-]?\d*|\d*[+-]?)$")


def _strip_yaml_inline_comment(raw: str) -> str:
    """Remove trailing YAML `# comment` outside single/double quotes."""
    in_single = False
    in_double = False
    i = 0
    n = len(raw)
    while i < n:
        ch = raw[i]
        if in_single:
            if ch == "'":
                if i + 1 < n and raw[i + 1] == "'":
                    i += 2
                    continue
                in_single = False
        elif in_double:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_double = False
        else:
            if ch == "'":
                in_single = True
            elif ch == '"':
                in_double = True
            elif ch == "#" and (i == 0 or raw[i - 1].isspace()):
                return raw[:i].rstrip()
        i += 1
    return raw.strip()


def _is_wrapped_single_quoted(s: str) -> bool:
    if len(s) < 2 or s[0] != "'" or s[-1] != "'":
        return False
    i = 1
    n = len(s)
    while i < n:
        if s[i] == "'":
            if i + 1 < n and s[i + 1] == "'":
                i += 2
                continue
            return i == n - 1
        i += 1
    return False


def _is_wrapped_double_quoted(s: str) -> bool:
    if len(s) < 2 or s[0] != '"' or s[-1] != '"':
        return False
    i = 1
    n = len(s)
    while i < n:
        if s[i] == "\\" and i + 1 < n:
            i += 2
            continue
        if s[i] == '"':
            return i == n - 1
        i += 1
    return False


def _unquote_yaml_scalar(s: str) -> str:
    if _is_wrapped_single_quoted(s):
        return s[1:-1].replace("''", "'")
    if _is_wrapped_double_quoted(s):
        inner = s[1:-1]
        try:
            return json.loads(f'"{inner}"')
        except Exception:
            return (
                inner.replace('\\"', '"')
                .replace("\\n", "\n")
                .replace("\\t", "\t")
                .replace("\\\\", "\\")
            )
    return s


def _split_top_level_flow(inner: str, sep: str = ",") -> List[str]:
    parts: List[str] = []
    buf: List[str] = []
    in_single = False
    in_double = False
    depth_brack = 0
    depth_brace = 0
    depth_paren = 0
    i = 0
    n = len(inner)
    while i < n:
        ch = inner[i]
        if in_single:
            buf.append(ch)
            if ch == "'":
                if i + 1 < n and inner[i + 1] == "'":
                    buf.append(inner[i + 1])
                    i += 2
                    continue
                in_single = False
        elif in_double:
            buf.append(ch)
            if ch == "\\" and i + 1 < n:
                buf.append(inner[i + 1])
                i += 2
                continue
            if ch == '"':
                in_double = False
        else:
            if ch == "'":
                in_single = True
                buf.append(ch)
            elif ch == '"':
                in_double = True
                buf.append(ch)
            elif ch == "[":
                depth_brack += 1
                buf.append(ch)
            elif ch == "]":
                depth_brack = max(0, depth_brack - 1)
                buf.append(ch)
            elif ch == "{":
                depth_brace += 1
                buf.append(ch)
            elif ch == "}":
                depth_brace = max(0, depth_brace - 1)
                buf.append(ch)
            elif ch == "(":
                depth_paren += 1
                buf.append(ch)
            elif ch == ")":
                depth_paren = max(0, depth_paren - 1)
                buf.append(ch)
            elif ch == sep and depth_brack == 0 and depth_brace == 0 and depth_paren == 0:
                parts.append("".join(buf).strip())
                buf = []
            else:
                buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail or parts:
        if tail:
            parts.append(tail)
    return parts


def _try_parse_flow_value(scalar: str) -> Tuple[bool, Any]:
    """Attempt to parse YAML flow sequence `[...]` or flow mapping `{...}`."""
    s = scalar.strip()
    if not s:
        return False, None
    if (s.startswith("[") and s.endswith("]")) or (s.startswith("{") and s.endswith("}")):
        try:
            return True, json.loads(s)
        except Exception:
            pass
        if s.startswith("[") and s.endswith("]"):
            inner = s[1:-1].strip()
            if not inner:
                return True, []
            items = _split_top_level_flow(inner, ",")
            out_list: List[Any] = []
            for item in items:
                ok_sub, val_sub = _try_parse_flow_value(item)
                out_list.append(val_sub if ok_sub else _parse_scalar_value(item))
            return True, out_list
        if s.startswith("{") and s.endswith("}"):
            inner = s[1:-1].strip()
            if not inner:
                return True, {}
            entries = _split_top_level_flow(inner, ",")
            out_dict: Dict[str, Any] = {}
            for entry in entries:
                if ":" not in entry:
                    return False, None
                k_raw, v_raw = entry.split(":", 1)
                k = _unquote_yaml_scalar(k_raw.strip())
                if not k:
                    return False, None
                v_clean = v_raw.strip()
                ok_sub, val_sub = _try_parse_flow_value(v_clean)
                out_dict[k] = val_sub if ok_sub else _parse_scalar_value(v_clean)
            return True, out_dict
    return False, None


def _parse_scalar_value(raw: str, *, force_string: bool = False) -> Any:
    cleaned = _strip_yaml_inline_comment(raw)
    if not cleaned:
        return ""
    if _is_wrapped_single_quoted(cleaned) or _is_wrapped_double_quoted(cleaned):
        return _unquote_yaml_scalar(cleaned)
    if not force_string:
        ok_flow, flow_val = _try_parse_flow_value(cleaned)
        if ok_flow:
            return flow_val
        low = cleaned.lower()
        if low in ("true", "yes"):
            return True
        if low in ("false", "no"):
            return False
        if low in ("null", "~"):
            return None
    return cleaned


def _repair_frontmatter_scalar_fields(frontmatter: str) -> Tuple[str, bool]:
    """Line-level scalar repair inspired by `openai/codex` `repair_frontmatter_scalar_fields`."""
    changed = False
    block_scalar_indent: Optional[int] = None
    repaired_lines: List[str] = []

    for line in frontmatter.splitlines():
        expanded = line.expandtabs(2)
        indent = len(expanded) - len(expanded.lstrip(" "))
        stripped = expanded.strip()

        if block_scalar_indent is not None:
            if not stripped or indent > block_scalar_indent:
                repaired_lines.append(line)
                continue
            block_scalar_indent = None

        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            repaired_lines.append(line)
            continue

        if ":" not in line:
            repaired_lines.append(line)
            continue

        key_part, value_part = line.split(":", 1)
        if not key_part.strip() or (value_part and not value_part[0].isspace()):
            repaired_lines.append(line)
            continue

        trimmed_start = value_part.lstrip()
        leading_ws = value_part[: len(value_part) - len(trimmed_start)]
        if not trimmed_start or trimmed_start.startswith("#"):
            repaired_lines.append(line)
            continue

        scalar = _strip_yaml_inline_comment(trimmed_start)
        comment_suffix = trimmed_start[len(scalar) :].rstrip("\r\n")
        if not scalar:
            repaired_lines.append(line)
            continue

        first_ch = scalar[0]
        if first_ch in ("|", ">") and _BLOCK_SCALAR_HEADER_RE.match(scalar):
            block_scalar_indent = indent
            repaired_lines.append(line)
            continue

        if _is_wrapped_single_quoted(scalar) or _is_wrapped_double_quoted(scalar):
            repaired_lines.append(line)
            continue

        has_colon_sep = bool(re.search(r":\s", scalar))
        invalid_flow = False
        if first_ch in ("[", "{"):
            ok_flow, _ = _try_parse_flow_value(scalar)
            if not ok_flow:
                invalid_flow = True
        elif first_ch in ("@", "`"):
            invalid_flow = True

        if not has_colon_sep and not invalid_flow:
            repaired_lines.append(line)
            continue

        quoted = "'" + scalar.replace("'", "''") + "'"
        repaired_lines.append(f"{key_part}:{leading_ws}{quoted}{comment_suffix}")
        changed = True

    return ("\n".join(repaired_lines), changed)


def _line_indent(line: str) -> int:
    exp = line.expandtabs(2)
    return len(exp) - len(exp.lstrip(" "))


def _collect_block_scalar(lines: Sequence[str], start_idx: int, parent_indent: int, style: str) -> Tuple[str, int]:
    collected: List[str] = []
    i = start_idx
    n = len(lines)
    while i < n:
        ln = lines[i]
        stripped = ln.strip()
        ind = _line_indent(ln)
        if stripped and ind <= parent_indent:
            break
        collected.append(ln.expandtabs(2))
        i += 1

    while collected and not collected[-1].strip():
        collected.pop()

    if not collected:
        return "", i

    non_empty_indents = [len(c) - len(c.lstrip(" ")) for c in collected if c.strip()]
    base_indent = min(non_empty_indents) if non_empty_indents else 0
    dedented = [c[base_indent:] if len(c) >= base_indent else "" for c in collected]

    if style.startswith("|"):
        text = "\n".join(dedented)
        if style.endswith("+"):
            text += "\n"
        return text, i

    # Folded `>` / `>-` / `>+`
    paragraphs: List[str] = []
    cur_para: List[str] = []
    for dl in dedented:
        if not dl.strip():
            if cur_para:
                paragraphs.append(" ".join(cur_para))
                cur_para = []
            else:
                paragraphs.append("")
        else:
            cur_para.append(dl.strip())
    if cur_para:
        paragraphs.append(" ".join(cur_para))
    folded = "\n\n".join(p for p in paragraphs if p != "" or len(paragraphs) == 1)
    if style.endswith("+"):
        folded += "\n"
    return folded.strip() if not style.endswith("+") else folded, i


def _split_mapping_line(stripped: str) -> Optional[Tuple[str, str]]:
    """Split `key: val` at top level if valid mapping entry."""
    in_single = False
    in_double = False
    for idx, ch in enumerate(stripped):
        if in_single:
            if ch == "'":
                in_single = False
        elif in_double:
            if ch == '"':
                in_double = False
        else:
            if ch == "'":
                in_single = True
            elif ch == '"':
                in_double = True
            elif ch == ":":
                rest = stripped[idx + 1 :]
                if not rest or rest[0].isspace():
                    key = _unquote_yaml_scalar(stripped[:idx].strip())
                    if key:
                        return key, rest.strip()
                return None
    return None


def _parse_yaml_node(lines: Sequence[str], start_idx: int, min_indent: int) -> Tuple[Any, int]:
    """Parse an indented YAML mapping or block sequence without third-party packages."""
    n = len(lines)
    i = start_idx
    while i < n:
        s = lines[i].strip()
        if not s or s.startswith("#"):
            i += 1
            continue
        break
    if i >= n:
        return None, i

    first_indent = _line_indent(lines[i])
    if first_indent < min_indent:
        return None, i

    first_stripped = lines[i].strip()
    if first_stripped == "-" or first_stripped.startswith("- "):
        return _parse_yaml_sequence(lines, i, first_indent)
    return _parse_yaml_mapping(lines, i, first_indent)


def _parse_yaml_sequence(lines: Sequence[str], start_idx: int, seq_indent: int) -> Tuple[List[Any], int]:
    items: List[Any] = []
    i = start_idx
    n = len(lines)
    while i < n:
        raw_ln = lines[i]
        stripped = raw_ln.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        ind = _line_indent(raw_ln)
        if ind < seq_indent:
            break
        if ind > seq_indent and not (stripped == "-" or stripped.startswith("- ")):
            # Continuation of previous scalar item
            if items and isinstance(items[-1], str):
                items[-1] = f"{items[-1]} {_strip_yaml_inline_comment(stripped)}".strip()
            i += 1
            continue
        if not (stripped == "-" or stripped.startswith("- ")):
            break

        item_rest = stripped[1:].strip()
        i += 1
        if not item_rest or item_rest.startswith("#"):
            nested_val, i = _parse_yaml_node(lines, i, seq_indent + 1)
            if nested_val is not None:
                items.append(nested_val)
            continue

        # Check if `- key: val` inline dict item
        kv = _split_mapping_line(item_rest)
        if kv is not None and not _is_wrapped_single_quoted(item_rest) and not _is_wrapped_double_quoted(item_rest):
            k0, v0 = kv
            item_dict: Dict[str, Any] = {}
            if v0:
                item_dict[k0] = _parse_scalar_value(v0)
            else:
                sub_val, i = _parse_yaml_node(lines, i, seq_indent + 1)
                item_dict[k0] = sub_val
            while i < n:
                nxt_s = lines[i].strip()
                if not nxt_s or nxt_s.startswith("#"):
                    i += 1
                    continue
                nxt_ind = _line_indent(lines[i])
                if nxt_ind <= seq_indent:
                    break
                sub_map, i = _parse_yaml_mapping(lines, i, nxt_ind)
                if isinstance(sub_map, dict):
                    item_dict.update(sub_map)
                else:
                    break
            items.append(item_dict)
            continue

        items.append(_parse_scalar_value(item_rest))
    return items, i


def _parse_yaml_mapping(lines: Sequence[str], start_idx: int, map_indent: int) -> Tuple[Dict[str, Any], int]:
    result: Dict[str, Any] = {}
    i = start_idx
    n = len(lines)
    while i < n:
        raw_ln = lines[i]
        stripped = raw_ln.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        ind = _line_indent(raw_ln)
        if ind < map_indent:
            break
        if ind > map_indent:
            # Unexpected stray continuation line
            i += 1
            continue

        kv = _split_mapping_line(stripped)
        if kv is None:
            i += 1
            continue
        key, val_rest = kv
        key_low = key.lower()
        force_str = key_low in _PLAIN_SCALAR_ONLY_KEYS
        val_clean = _strip_yaml_inline_comment(val_rest) if val_rest else ""
        i += 1

        if val_clean and _BLOCK_SCALAR_HEADER_RE.match(val_clean):
            block_str, i = _collect_block_scalar(lines, i, ind, val_clean)
            result[key] = block_str
            continue

        if not val_clean:
            # Peek next non-empty, non-comment line
            j = i
            while j < n and (not lines[j].strip() or lines[j].strip().startswith("#")):
                j += 1
            if j >= n:
                result[key] = "" if force_str else None
                i = j
                continue
            nxt_ind = _line_indent(lines[j])
            nxt_s = lines[j].strip()
            if force_str and nxt_ind > ind:
                cont_parts: List[str] = []
                while j < n:
                    cs = lines[j].strip()
                    if not cs or cs.startswith("#"):
                        j += 1
                        continue
                    if _line_indent(lines[j]) <= ind:
                        break
                    cont_parts.append(_unquote_yaml_scalar(_strip_yaml_inline_comment(cs)))
                    j += 1
                result[key] = " ".join(p for p in cont_parts if p)
                i = j
                continue
            # Note: YAML allows block sequences `- item` at `nxt_ind == ind` under a mapping key
            if nxt_ind > ind or (nxt_ind == ind and (nxt_s == "-" or nxt_s.startswith("- "))):
                sub_node, i = _parse_yaml_node(lines, j, nxt_ind)
                result[key] = sub_node
            else:
                result[key] = "" if force_str else None
                i = j
            continue

        parsed_val = _parse_scalar_value(val_rest, force_string=force_str)
        # Support multi-line plain scalar continuation on deeper indented lines
        if isinstance(parsed_val, str) and not (
            _is_wrapped_single_quoted(val_clean) or _is_wrapped_double_quoted(val_clean)
        ):
            cont_lines: List[str] = [parsed_val]
            while i < n:
                nxt_raw = lines[i]
                nxt_s = nxt_raw.strip()
                if not nxt_s or nxt_s.startswith("#"):
                    i += 1
                    continue
                nxt_ind = _line_indent(nxt_raw)
                if nxt_ind <= ind:
                    break
                if not force_str and (
                    nxt_s == "-"
                    or nxt_s.startswith("- ")
                    or _split_mapping_line(nxt_s) is not None
                ):
                    break
                cont_lines.append(_unquote_yaml_scalar(_strip_yaml_inline_comment(nxt_s)))
                i += 1
            parsed_val = " ".join(p for p in cont_lines if p)

        result[key] = parsed_val
    return result, i


def _coerce_str_list(val: Any, *, split_whitespace: bool = False) -> List[str]:
    if val is None or isinstance(val, bool):
        return []
    if isinstance(val, (list, tuple)):
        out: List[str] = []
        for item in val:
            if item is None or isinstance(item, (dict, list, bool)):
                continue
            s = str(item).strip()
            if s:
                out.append(s)
        return out
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return []
        ok_flow, flow_val = _try_parse_flow_value(s)
        if ok_flow and isinstance(flow_val, list):
            return _coerce_str_list(flow_val)
        if "," in s:
            parts = _split_top_level_flow(s, ",")
            if len(parts) > 1:
                return [p.strip() for p in parts if p.strip()]
        if split_whitespace:
            # Split whitespace at parenthesis depth 0 so `Bash(git: *) Read` stays intact
            tokens: List[str] = []
            buf: List[str] = []
            p_depth = 0
            for ch in s:
                if ch == "(":
                    p_depth += 1
                    buf.append(ch)
                elif ch == ")":
                    p_depth = max(0, p_depth - 1)
                    buf.append(ch)
                elif ch.isspace() and p_depth == 0:
                    if buf:
                        tokens.append("".join(buf))
                        buf = []
                else:
                    buf.append(ch)
            if buf:
                tokens.append("".join(buf))
            return [t for t in tokens if t]
        return [s]
    return [str(val).strip()] if str(val).strip() else []


def _dedup_preserve_order(seq: Sequence[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for item in seq:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def parse_skill_frontmatter(raw_text: str, fallback_name: str = "") -> Dict[str, Any]:
    """Parse YAML frontmatter from `SKILL.md` / `skill.md` / `skills.md` with zero external dependencies."""
    cleaned = (raw_text or "").lstrip("\ufeff")
    if _EMPTY_FRONTMATTER_RE.match(cleaned):
        m_empty = _EMPTY_FRONTMATTER_RE.match(cleaned)
        body_empty = cleaned[m_empty.end() :] if m_empty else ""
        return {
            "name": fallback_name,
            "description": "",
            "short_description": "",
            "license": "",
            "compatibility": "",
            "allowed_tools": [],
            "allowed-tools": [],
            "requires_bins": [],
            "requires_env": [],
            "requires": {"bins": [], "env": []},
            "metadata": {},
            "body": body_empty,
            "has_frontmatter": True,
            "repaired": False,
        }

    m = _FRONTMATTER_RE.match(cleaned)
    if not m:
        return {
            "name": fallback_name,
            "description": "",
            "short_description": "",
            "license": "",
            "compatibility": "",
            "allowed_tools": [],
            "allowed-tools": [],
            "requires_bins": [],
            "requires_env": [],
            "requires": {"bins": [], "env": []},
            "metadata": {},
            "body": cleaned,
            "has_frontmatter": False,
            "repaired": False,
        }

    raw_fm = m.group(1)
    body = cleaned[m.end() :]
    repaired_fm, was_repaired = _repair_frontmatter_scalar_fields(raw_fm)

    parsed_map: Dict[str, Any] = {}
    try:
        node, _ = _parse_yaml_mapping(repaired_fm.splitlines(), 0, 0)
        if isinstance(node, dict):
            parsed_map = node
    except Exception:
        parsed_map = {}

    # Normalize metadata (supports nested dict OR JSON string)
    raw_meta = parsed_map.get("metadata")
    metadata: Dict[str, Any] = {}
    if isinstance(raw_meta, dict):
        metadata = dict(raw_meta)
    elif isinstance(raw_meta, str) and raw_meta.strip().startswith("{"):
        try:
            loaded_meta = json.loads(raw_meta.strip())
            if isinstance(loaded_meta, dict):
                metadata = loaded_meta
        except Exception:
            pass

    for sub_ns in ("openclaw", "clawdbot"):
        sub_val = metadata.get(sub_ns)
        if isinstance(sub_val, str) and sub_val.strip().startswith("{"):
            try:
                loaded_sub = json.loads(sub_val.strip())
                if isinstance(loaded_sub, dict):
                    metadata[sub_ns] = loaded_sub
            except Exception:
                pass

    raw_name = parsed_map.get("name")
    name_str = " ".join(str(raw_name).split()).strip() if isinstance(raw_name, (str, int, float)) else ""
    final_name = name_str or fallback_name

    short_desc_raw = metadata.get("short-description") or metadata.get("short_description") or ""
    short_desc = " ".join(str(short_desc_raw).split()).strip() if short_desc_raw else ""

    raw_desc = parsed_map.get("description")
    desc_str = str(raw_desc).strip() if isinstance(raw_desc, (str, int, float)) else ""
    if not desc_str and short_desc:
        desc_str = short_desc

    raw_license = parsed_map.get("license") or metadata.get("license") or ""
    license_str = " ".join(str(raw_license).split()).strip() if isinstance(raw_license, (str, int, float)) else ""

    raw_compat = parsed_map.get("compatibility")
    if raw_compat is None:
        raw_compat = metadata.get("compatibility")
    if isinstance(raw_compat, (list, tuple)):
        compat_str = ", ".join(str(x).strip() for x in raw_compat if str(x).strip())
    elif isinstance(raw_compat, (str, int, float)):
        compat_str = " ".join(str(raw_compat).split()).strip()
    else:
        compat_str = ""

    raw_allowed = (
        parsed_map.get("allowed-tools")
        if "allowed-tools" in parsed_map
        else parsed_map.get("allowed_tools")
    )
    if raw_allowed is None:
        raw_allowed = metadata.get("allowed-tools") or metadata.get("allowed_tools")
    allowed_tools = _dedup_preserve_order(_coerce_str_list(raw_allowed, split_whitespace=True))

    bins_acc: List[str] = []
    env_acc: List[str] = []
    req_containers: List[Any] = [
        parsed_map.get("requires"),
        metadata.get("requires"),
    ]
    for ns in ("openclaw", "clawdbot"):
        ns_obj = metadata.get(ns)
        if isinstance(ns_obj, dict):
            req_containers.append(ns_obj.get("requires"))

    for req in req_containers:
        if isinstance(req, dict):
            bins_acc.extend(_coerce_str_list(req.get("bins"), split_whitespace=True))
            env_acc.extend(_coerce_str_list(req.get("env"), split_whitespace=True))

    requires_bins = _dedup_preserve_order(bins_acc)
    requires_env = _dedup_preserve_order(env_acc)

    out: Dict[str, Any] = {}
    for k, v in parsed_map.items():
        if isinstance(k, str):
            out[k] = v

    out.update(
        {
            "name": final_name,
            "description": desc_str,
            "short_description": short_desc,
            "license": license_str,
            "compatibility": compat_str,
            "allowed_tools": allowed_tools,
            "allowed-tools": list(allowed_tools),
            "requires_bins": requires_bins,
            "requires_env": requires_env,
            "requires": {"bins": list(requires_bins), "env": list(requires_env)},
            "metadata": metadata,
            "body": body,
            "has_frontmatter": True,
            "repaired": was_repaired,
        }
    )
    return out


def find_skill_markdown(skill_dir: Union[str, Path]) -> Optional[Path]:
    """Locate `SKILL.md` / `skill.md` / `skills.md` inside `skill_dir` while blocking escaped symlinks."""
    base = Path(skill_dir)
    if os.name == "nt":
        for nt_name in ("SKILL.md", "skills.md"):
            cand = base / nt_name
            try:
                if cand.is_file():
                    if is_link_or_junction(cand) and not is_subpath(cand, base):
                        continue
                    return cand
            except OSError:
                continue
        return None

    for candidate_name in ("SKILL.md", "skill.md", "SKILLS.md", "skills.md"):
        cand = base / candidate_name
        try:
            if cand.is_file():
                if is_link_or_junction(cand) and not is_subpath(cand, base):
                    continue
                return cand
        except OSError:
            continue

    plural_fallback: Optional[Path] = None
    try:
        for entry in os.scandir(str(base)):
            low_name = entry.name.lower()
            if low_name in ("skill.md", "skills.md"):
                p = Path(entry.path)
                if p.is_file() and (not is_link_or_junction(p) or is_subpath(p, base)):
                    if low_name == "skill.md":
                        return p
                    if plural_fallback is None:
                        plural_fallback = p
    except OSError:
        pass
    return plural_fallback


def _entry_is_reparse(entry: os.DirEntry[str]) -> bool:
    try:
        if entry.is_symlink():
            return True
        if os.name == "nt":
            st = entry.stat(follow_symlinks=False)
            if getattr(st, "st_file_attributes", 0) & 0x400:
                return True
    except OSError:
        return is_link_or_junction(entry.path)
    return False


def _is_dir_or_junction(entry: os.DirEntry[str]) -> bool:
    try:
        if entry.is_dir(follow_symlinks=True):
            return True
    except OSError:
        pass
    if _entry_is_reparse(entry):
        return os.path.isdir(entry.path)
    return False


def _iter_skill_dirs_under_root(root_path: Path, max_depth: int = 3) -> List[Tuple[Path, Path]]:
    """Yield `(skill_dir, skill_md_path)` under `root_path` with depth <= `max_depth`."""
    found: List[Tuple[Path, Path]] = []
    visited_real: Set[str] = set()

    def _walk(cur_dir: Path, cur_real_norm: str, depth: int) -> None:
        if depth > max_depth or cur_real_norm in visited_real:
            return
        visited_real.add(cur_real_norm)

        try:
            entries = sorted(os.scandir(str(cur_dir)), key=lambda e: e.name.lower())
        except OSError:
            visited_real.discard(cur_real_norm)
            return

        for entry in entries:
            ename = entry.name
            if ename.startswith(".") or ename in _SKIP_SCAN_DIRS or ename.lower() in _SKIP_SCAN_DIRS:
                continue
            if not _is_dir_or_junction(entry):
                continue
            child_dir = Path(entry.path)
            md_path = find_skill_markdown(child_dir)
            if md_path is not None:
                found.append((child_dir, md_path))
            elif depth < max_depth:
                if _entry_is_reparse(entry):
                    try:
                        c_real = os.path.realpath(entry.path)
                    except OSError:
                        continue
                else:
                    c_real = os.path.join(cur_real_norm, ename)
                c_norm = os.path.normcase(c_real) if os.name == "nt" else c_real
                _walk(child_dir, c_norm, depth + 1)

        visited_real.discard(cur_real_norm)

    try:
        root_real = os.path.realpath(str(root_path))
        root_norm = os.path.normcase(root_real) if os.name == "nt" else root_real
    except OSError:
        return found

    _walk(root_path, root_norm, 1)
    return found


def _compute_trust_tier(source_scope: str, has_scripts: bool) -> str:
    if source_scope == "antigravity_builtin":
        return "builtin"
    if source_scope == "managed":
        return "managed_with_scripts" if has_scripts else "managed_prompt_only"
    if source_scope.startswith("plugin:"):
        return "plugin_with_scripts" if has_scripts else "plugin_prompt_only"
    if source_scope in ("workspace", "workspace_claude"):
        return "workspace_with_scripts" if has_scripts else "workspace_prompt_only"
    return "local_with_scripts" if has_scripts else "local_prompt_only"


def scan_local_skills(
    config: SkillsConfig,
    cwd: Optional[Union[str, Path]] = None,
    *,
    include_disabled: bool = True,
) -> List[SkillRecord]:
    """Scan `config.ordered_scan_roots(cwd=cwd)` in priority order and deduplicate skills."""
    from cosmos_mcp.capabilities.skills.loader import list_skill_resources, sanitize_skill_text

    roots = config.ordered_scan_roots(cwd=cwd)
    disabled_state = read_disabled_skills_state(config)
    seen_keys: Set[str] = set()
    records: List[SkillRecord] = []

    for source_scope, root_path in roots:
        for skill_dir, md_path in _iter_skill_dirs_under_root(root_path, max_depth=3):
            dir_key = skill_dir.name.lower()
            if dir_key in seen_keys:
                continue

            try:
                st = md_path.stat()
                raw_bytes = md_path.read_bytes()
                raw_text = decode_text_with_bom_and_cookie(raw_bytes, md_path.suffix)
            except OSError:
                continue

            fm = parse_skill_frontmatter(raw_text, fallback_name=skill_dir.name)
            clean_name = sanitize_skill_text(str(fm.get("name") or skill_dir.name)).strip() or skill_dir.name
            name_key = clean_name.lower()
            if name_key in seen_keys:
                continue

            seen_keys.add(dir_key)
            seen_keys.add(name_key)

            full_desc = sanitize_skill_text(str(fm.get("description") or "")).strip()
            single_line_desc = " ".join(full_desc.split())
            summary_desc = (
                single_line_desc[:280] + "..."
                if len(single_line_desc) > 280
                else single_line_desc
            )

            res = list_skill_resources(skill_dir, max_depth=3)
            scripts_count = len(res["scripts"])
            references_count = len(res["references"])
            assets_count = len(res["assets"])
            has_scripts = scripts_count > 0
            trust_tier = _compute_trust_tier(source_scope, has_scripts)

            records.append(
                SkillRecord(
                    name=clean_name,
                    dir_name=skill_dir.name,
                    description=summary_desc,
                    full_description=full_desc,
                    skill_dir=str(skill_dir),
                    source_root=str(root_path),
                    source_scope=source_scope,
                    scripts_count=scripts_count,
                    references_count=references_count,
                    assets_count=assets_count,
                    has_scripts=has_scripts,
                    trust_tier=trust_tier,
                    license=sanitize_skill_text(str(fm.get("license") or "")).strip(),
                    compatibility=sanitize_skill_text(str(fm.get("compatibility") or "")).strip(),
                    allowed_tools=tuple(fm.get("allowed_tools") or ()),
                    requires_bins=tuple(fm.get("requires_bins") or ()),
                    requires_env=tuple(fm.get("requires_env") or ()),
                    metadata=dict(fm.get("metadata") or {}),
                    mtime_ns=int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))),
                    enabled=not is_skill_disabled(
                        config,
                        name=clean_name,
                        dir_name=skill_dir.name,
                        skill_dir=skill_dir,
                        source_scope=source_scope,
                        source_root=root_path,
                        disabled_state=disabled_state,
                    ),
                )
            )

    if not include_disabled:
        return [r for r in records if r.enabled]
    return records


def _light_en_stem(tok: str) -> str:
    """Deterministic lightweight standard-library stemmer for technical English."""
    if len(tok) <= 3 or tok.isdigit():
        return tok
    if tok.endswith("ies") and len(tok) > 4:
        return tok[:-3] + "y"
    for suf in ("ation", "ition", "ment", "ness", "ingly", "edly"):
        if tok.endswith(suf) and len(tok) - len(suf) >= 4:
            base = tok[: -len(suf)]
            if len(base) >= 4 and base[-1] == base[-2]:
                base = base[:-1]
            return base
    for suf in ("ing", "ous", "ive", "able", "ible"):
        if tok.endswith(suf) and len(tok) - len(suf) >= 4:
            base = tok[: -len(suf)]
            if len(base) >= 4 and base[-1] == base[-2]:
                base = base[:-1]
            return base
    if tok.endswith("es") and len(tok) > 4 and not tok.endswith(("ses", "xes", "zes")):
        base = tok[:-2]
        if base.endswith("u") and tok.endswith("gues"):
            return tok[:-4]
        return base
    if tok.endswith("s") and len(tok) > 3 and not tok.endswith(("ss", "us", "is")):
        return tok[:-1]
    if tok.endswith("ed") and len(tok) > 4:
        base = tok[:-2]
        if len(base) >= 4 and base[-1] == base[-2]:
            base = base[:-1]
        return base
    return tok


def tokenize_mixed_text(text: str, *, is_query: bool = False) -> List[str]:
    """Tokenize mixed EN/CJK text with camelCase/hyphen splitting, light stemming, CJK 2-grams, and ZH<->EN concept bridging."""
    if not text:
        return []
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", text)
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", spaced)
    low = spaced.lower()
    out: List[str] = []
    zh_chunks: List[str] = []
    en_seen: Set[str] = set()

    for m in re.finditer(r"[a-z0-9][a-z0-9_.-]*|[\u4e00-\u9fff]+", low):
        chunk = m.group(0)
        if "\u4e00" <= chunk[0] <= "\u9fff":
            zh_chunks.append(chunk)
            if 2 <= len(chunk) <= 4 and chunk not in _STOP_BIGRAMS_ZH:
                out.append(chunk)
            if len(chunk) >= 2:
                for i in range(len(chunk) - 1):
                    bg = chunk[i : i + 2]
                    if bg not in _STOP_BIGRAMS_ZH:
                        out.append(bg)
        else:
            sub_parts = [p for p in re.split(r"[-_./]+", chunk) if p]
            if len(sub_parts) > 1 and not is_query:
                out.append(chunk.replace("_", "-"))
            for sp in sub_parts:
                if sp in _STOP_WORDS_EN:
                    continue
                if len(sp) >= 2 or sp.isdigit():
                    out.append(sp)
                    en_seen.add(sp)
                    st = _light_en_stem(sp)
                    if st != sp and len(st) >= 3:
                        out.append(st)
                        en_seen.add(st)

    # Bidirectional ZH <-> EN core technical concept bridging
    if zh_chunks or en_seen:
        existing_set: Set[str] = set(out)
        zh_joined = " ".join(zh_chunks)
        for zh_group, en_group in _BILINGUAL_CONCEPT_GROUPS:
            zh_hit = bool(zh_chunks and any(zt in zh_joined for zt in zh_group))
            en_hit = bool(
                en_seen
                and any(et in en_seen or _light_en_stem(et) in en_seen for et in en_group)
            )
            if zh_hit:
                for zt in zh_group:
                    if zt in zh_joined and zt not in existing_set:
                        out.append(zt)
                        existing_set.add(zt)
                for et in en_group:
                    if et not in existing_set:
                        out.append(et)
                        existing_set.add(et)
                    est = _light_en_stem(et)
                    if est != et and len(est) >= 3 and est not in existing_set:
                        out.append(est)
                        existing_set.add(est)
            if en_hit:
                for zt in zh_group:
                    if zt not in existing_set:
                        out.append(zt)
                        existing_set.add(zt)
                    if len(zt) >= 3:
                        for idx in range(len(zt) - 1):
                            bg = zt[idx : idx + 2]
                            if bg not in _STOP_BIGRAMS_ZH and bg not in existing_set:
                                out.append(bg)
                                existing_set.add(bg)

    return out


def _extract_literal_query_tokens(q_clean: str) -> Set[str]:
    """Extract literal non-meta tokens typed directly in `q_clean` prior to bilingual concept expansion."""
    if not q_clean:
        return set()
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", q_clean)
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", spaced)
    low = spaced.lower()
    lits: Set[str] = set()
    for m in re.finditer(r"[a-z0-9][a-z0-9_.-]*|[\u4e00-\u9fff]+", low):
        chunk = m.group(0).strip("._-/")
        if not chunk:
            continue
        if "\u4e00" <= chunk[0] <= "\u9fff":
            if chunk not in _GENERIC_META_ALL and chunk not in _STOP_BIGRAMS_ZH:
                lits.add(chunk)
        else:
            norm_chunk = chunk.replace("_", "-")
            if norm_chunk not in _STOP_WORDS_EN and norm_chunk not in _GENERIC_META_ALL:
                lits.add(norm_chunk)
            for sp in re.split(r"[-_./]+", chunk):
                if sp and sp not in _STOP_WORDS_EN and sp not in _GENERIC_META_ALL:
                    lits.add(sp)
    return lits


def _extract_substantive_query_info(q_clean: str) -> Tuple[List[str], List[str]]:
    """Return `(substantive_tokens, single_char_zh_residuals)` after stripping generic container meta-words."""
    if not q_clean:
        return [], []
    stripped = q_clean
    for meta_zh in _GENERIC_META_ZH:
        stripped = stripped.replace(meta_zh, " ")
    stripped = re.sub(r"(^|[^\u4e00-\u9fff])的+|的+(?=[^\u4e00-\u9fff]|$)", r"\1", stripped)
    stripped = re.sub(r"\b(?:skills?|tools?)\b", " ", stripped, flags=re.IGNORECASE)
    sub_toks = [
        t
        for t in _dedup_preserve_order(tokenize_mixed_text(stripped, is_query=True))
        if t not in _GENERIC_META_ALL
    ]
    single_zh: List[str] = []
    if not sub_toks:
        for m in re.finditer(r"[\u4e00-\u9fff]+", stripped):
            seg = m.group(0)
            if len(seg) == 1 and seg not in ("的", "了", "吗", "呢", "吧", "啊"):
                single_zh.append(seg)
    return sub_toks, single_zh


class LocalSkillIndex:
    """Thread-safe field-weighted BM25F local skill search engine cached by ordered roots + SKILL.md `mtime_ns` fingerprint."""

    def __init__(
        self,
        config: Optional[SkillsConfig] = None,
        k1: float = 1.2,
        b: float = 0.72,
        name_boost: float = 3.2,
    ) -> None:
        self.config: SkillsConfig = config if config is not None else SkillsConfig()
        self.k1 = float(k1)
        self.b = float(b)
        self.name_boost = float(name_boost)
        self._lock = threading.RLock()

        self._fingerprint: Optional[Tuple[Any, ...]] = None
        self._records: List[SkillRecord] = []
        self._by_key: Dict[str, SkillRecord] = {}
        self._doc_tf: List[Dict[str, float]] = []
        self._doc_len: List[float] = []
        self._df: Dict[str, int] = {}
        self._avgdl: float = 1.0

    def _compute_fingerprint(
        self, cwd: Optional[Union[str, Path]] = None
    ) -> Tuple[Any, ...]:
        roots = self.config.ordered_scan_roots(cwd=cwd)
        root_sig: List[Tuple[str, str]] = []
        file_sig: List[Tuple[str, str, int, int]] = []
        seen_dir_keys: Set[str] = set()

        for scope, rp in roots:
            rp_str = os.path.normcase(str(rp)) if os.name == "nt" else str(rp)
            root_sig.append((scope, rp_str))
            for skill_dir, md_path in _iter_skill_dirs_under_root(rp, max_depth=3):
                dk = skill_dir.name.lower()
                if dk in seen_dir_keys:
                    continue
                try:
                    st = md_path.stat()
                except OSError:
                    continue
                seen_dir_keys.add(dk)
                mtime_ns = int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))
                file_sig.append((rp_str, dk, mtime_ns, int(st.st_size)))

        state_sig = str(self.config.resolved_state_root())
        dis_sig = disabled_skills_fingerprint(self.config)
        return (state_sig, dis_sig, tuple(root_sig), tuple(file_sig))

    def _ensure_index(
        self,
        cwd: Optional[Union[str, Path]] = None,
        force_refresh: bool = False,
    ) -> bool:
        """Ensure in-memory BM25F structures are up to date; returns `cache_hit`."""
        with self._lock:
            fp = self._compute_fingerprint(cwd=cwd)
            if not force_refresh and self._fingerprint is not None and fp == self._fingerprint:
                return True

            records = scan_local_skills(self.config, cwd=cwd, include_disabled=True)
            self._records = records
            self._fingerprint = fp

            by_key: Dict[str, SkillRecord] = {}
            for r in records:
                dk = r.dir_name.lower()
                nk = r.name.lower()
                if dk not in by_key:
                    by_key[dk] = r
                if nk not in by_key:
                    by_key[nk] = r
            self._by_key = by_key

            doc_tf: List[Dict[str, float]] = []
            doc_len: List[float] = []
            df: Dict[str, int] = {}

            for r in records:
                name_toks = tokenize_mixed_text(f"{r.name} {r.dir_name}", is_query=False)
                desc_source = r.full_description or r.description
                if r.compatibility:
                    desc_source = f"{desc_source} {r.compatibility}"
                if r.requires_bins:
                    desc_source = f"{desc_source} {' '.join(r.requires_bins)}"
                desc_toks = tokenize_mixed_text(desc_source, is_query=False)

                tf: Dict[str, float] = {}
                for t in name_toks:
                    tf[t] = tf.get(t, 0.0) + self.name_boost
                for t in desc_toks:
                    tf[t] = tf.get(t, 0.0) + 1.0

                dl = sum(tf.values()) or 1.0
                doc_tf.append(tf)
                doc_len.append(dl)
                for t in tf:
                    df[t] = df.get(t, 0) + 1

            self._doc_tf = doc_tf
            self._doc_len = doc_len
            self._df = df
            self._avgdl = (sum(doc_len) / len(records)) if records else 1.0
            return False

    def list_skills(
        self,
        cwd: Optional[Union[str, Path]] = None,
        force_refresh: bool = False,
        *,
        include_disabled: bool = False,
    ) -> List[SkillRecord]:
        """Return deduplicated `SkillRecord` list in priority order using the `mtime_ns` cache."""
        with self._lock:
            self._ensure_index(cwd=cwd, force_refresh=force_refresh)
            if include_disabled:
                return list(self._records)
            return [r for r in self._records if r.enabled]

    def get_skill(
        self,
        name: str,
        cwd: Optional[Union[str, Path]] = None,
        *,
        include_disabled: bool = False,
    ) -> Optional[SkillRecord]:
        """Retrieve a `SkillRecord` by skill name or directory name (case-insensitive)."""
        clean = (name or "").strip().lstrip("/").strip().lower()
        if not clean:
            return None
        with self._lock:
            self._ensure_index(cwd=cwd, force_refresh=False)
            rec = self._by_key.get(clean)
            if rec is None:
                return None
            if not include_disabled and not rec.enabled:
                return None
            return rec

    def search(
        self,
        query: str = "",
        cwd: Optional[Union[str, Path]] = None,
        limit: int = 10,
        force_refresh: bool = False,
        *,
        include_disabled: bool = False,
    ) -> Dict[str, Any]:
        """Search indexed skills via BM25F (`name_boost=3.2`), excluding disabled skills unless `include_disabled=True`."""
        with self._lock:
            cache_hit = self._ensure_index(cwd=cwd, force_refresh=force_refresh)
            active_records = list(self._records) if include_disabled else [r for r in self._records if r.enabled]
            n_docs = len(active_records)
            total_corpus = max(1, len(self._records))
            eff_limit = max(0, int(limit))

            q_clean = (query or "").strip().lstrip("/").strip().lower()
            if not q_clean:
                sorted_records = sorted(
                    active_records,
                    key=lambda r: (r.name.lower(), r.dir_name.lower()),
                )
                items = [
                    r.to_summary_dict(score=0.0, matched_terms=0)
                    for r in sorted_records[:eff_limit]
                ]
                return {
                    "ok": True,
                    "query": query,
                    "total_unique_skills": n_docs,
                    "count": len(items),
                    "cache_hit": cache_hit,
                    "items": items,
                }

            raw_q_toks = tokenize_mixed_text(q_clean, is_query=True)
            q_toks = _dedup_preserve_order(raw_q_toks)
            literal_q_toks = _extract_literal_query_tokens(q_clean)
            substantive_q_toks, residual_substantive_zh = _extract_substantive_query_info(q_clean)
            substantive_q_set = set(substantive_q_toks)
            has_substantive_intent = bool(substantive_q_set or residual_substantive_zh)
            only_meta_query = not has_substantive_intent

            scored: List[Tuple[float, str, Dict[str, Any]]] = []
            for idx, r in enumerate(self._records):
                if not include_disabled and not r.enabled:
                    continue
                tf = self._doc_tf[idx]
                dl = self._doc_len[idx]
                score = 0.0
                matched_terms = 0
                substantive_matched = 0

                for qt in q_toks:
                    f = tf.get(qt, 0.0)
                    if f <= 0.0:
                        continue
                    is_meta_tok = qt in _GENERIC_META_ALL
                    if has_substantive_intent and qt in substantive_q_set:
                        substantive_matched += 1
                    matched_terms += 1
                    df_t = self._df.get(qt, 0)
                    idf = math.log(1.0 + (total_corpus - df_t + 0.5) / (df_t + 0.5))
                    denom = f + self.k1 * (1.0 - self.b + self.b * (dl / self._avgdl))
                    term_score = idf * ((f * (self.k1 + 1.0)) / denom)
                    if has_substantive_intent and is_meta_tok:
                        term_score *= 0.2
                    score += term_score

                nm = r.name.lower()
                dn = r.dir_name.lower()
                nm_norm = nm.replace("_", "-")
                dn_norm = dn.replace("_", "-")
                name_variants = {nm, dn, nm_norm, dn_norm}
                name_segments = {
                    seg
                    for seg in re.split(r"[-_./\s]+", f"{nm} {dn}")
                    if len(seg) >= 3 and seg not in _GENERIC_META_ALL
                }

                if q_clean in name_variants or q_clean.replace("_", "-") in name_variants:
                    score += 25.0
                    matched_terms = max(matched_terms, 1)
                    substantive_matched = max(substantive_matched, 1)
                elif literal_q_toks & name_variants:
                    score += 22.0
                    matched_terms = max(matched_terms, 1)
                    substantive_matched = max(substantive_matched, 1)
                elif not only_meta_query and len(q_clean) >= 3 and (nm.startswith(q_clean) or dn.startswith(q_clean)):
                    score += 10.0
                    matched_terms = max(matched_terms, 1)
                    substantive_matched = max(substantive_matched, 1)
                elif not only_meta_query and len(q_clean) >= 3 and (q_clean in nm or q_clean in dn):
                    score += 6.0
                    matched_terms = max(matched_terms, 1)
                    substantive_matched = max(substantive_matched, 1)
                elif literal_q_toks & name_segments:
                    score += 6.0
                    matched_terms = max(matched_terms, 1)
                    substantive_matched = max(substantive_matched, 1)

                if has_substantive_intent and substantive_matched == 0 and residual_substantive_zh:
                    hay_low = f"{nm} {dn} {(r.full_description or r.description).lower()}"
                    if any(ch in hay_low for ch in residual_substantive_zh):
                        substantive_matched += 1
                        score = max(score, 1.0)

                if has_substantive_intent and substantive_matched == 0:
                    continue

                if score > 0.0:
                    coord = 1.0 + 0.08 * min(matched_terms, 6)
                    final_score = round(score * coord, 4)
                    scored.append(
                        (
                            final_score,
                            nm,
                            r.to_summary_dict(score=final_score, matched_terms=matched_terms),
                        )
                    )

            scored.sort(key=lambda x: (-x[0], x[1]))
            top_items = [x[2] for x in scored[:eff_limit]]
            return {
                "ok": True,
                "query": query,
                "total_unique_skills": n_docs,
                "count": len(top_items),
                "cache_hit": cache_hit,
                "items": top_items,
            }
