#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unified Patching Engine (`cosmos_mcp.core.patch`).

Consolidates patching primitives into a single pure-stdlib module (Python >=3.9, zero third-party deps):
1. 9-Strategy Fuzzy Matcher (`exact`, `line_trimmed`, `whitespace_normalized`, `indentation_flexible`,
   `escape_normalized`, `trimmed_boundary`, `unicode_normalized`, `block_anchor`, `context_aware`)
   with base-indentation delta rebasing and low-entropy short-block protection.
2. Closest-Match Diagnostics returning a single numbered snippet and exact 1-based `[start_line, end_line]`
   on match failure without duplicate payload bloat.
3. Multi-segment 1-based `[start_line, end_line]` bottom-up descending replacement preventing line-number drift.
4. `v4a` multi-file patch parser & atomic transaction executor (`multi_patch` / `apply_v4a_patch`)
   with pre-commit simulation, syntax validation, recoverable trash deletion, and full rollback on failure.
5. Fence-aware Markdown section patching (`heading:` / `section:` / `append_section:`).
"""
from __future__ import annotations

import bisect
import contextlib
from dataclasses import dataclass, field
import difflib
from enum import Enum
import hashlib
import os
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from .fs_io import (
    atomic_validate_and_replace,
    auto_check_syntax,
    check_office_or_os_file_lock,
    detect_and_decode_bytes,
    detect_dominant_crlf,
    encode_with_detected_encoding,
    preserve_line_endings_for_edit,
    split_lines_exact_nl,
    verify_expected_sha256,
)
from .fs_tx import (
    MultiFileLock,
    get_file_lock,
    pop_latest_undo_entry_quiet,
    restore_from_trash,
    safe_trash_file,
)

MIN_FUZZY_WHITESPACE_CHARS: int = 3
MIN_APPROX_STRATEGY_CHARS: int = 10
WINDOW_DRIFT_LINES: int = 15

_LOW_ENTROPY_STRIP_RE = re.compile(r"[\s{}\(\)\[\];,]+")
_FENCE_OPEN_RE = re.compile(r"^\s*(`{3,}|~{3,})")

UNICODE_MAP: Dict[str, str] = {
    "\u201c": '"',
    "\u201d": '"',
    "\u2018": "'",
    "\u2019": "'",
    "\u2014": "--",
    "\u2013": "-",
    "\u2026": "...",
    "\u00a0": " ",
}

_INDENT_REBASE_STRATEGIES: frozenset[str] = frozenset(
    {
        "line_trimmed",
        "whitespace_normalized",
        "indentation_flexible",
        "trimmed_boundary",
        "unicode_normalized",
        "block_anchor",
        "context_aware",
    }
)


# ---------------------------------------------------------------------------
# 1. Unified Diff & Closest-Match Diagnostics
# ---------------------------------------------------------------------------


def make_compact_diff(
    old_content: str,
    new_content: str,
    filename: str = "file",
    max_lines: int = 60,
    context_lines: int = 2,
) -> str:
    """Build a compact unified diff capped at `max_lines`."""
    diff_lines = list(
        difflib.unified_diff(
            old_content.splitlines(),
            new_content.splitlines(),
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            lineterm="",
            n=context_lines,
        )
    )
    preview = "\n".join(diff_lines[:max_lines])
    if len(diff_lines) > max_lines:
        preview += f"\n... ({len(diff_lines) - max_lines} more diff lines)"
    return preview


def find_sliding_window_closest_match(
    content_lf: str,
    old_lf: str,
    *,
    line_offset: int = 0,
    filename: str = "file",
) -> Dict[str, Any]:
    """
    Locate the closest matching block in `content_lf` with exact 1-based `[start_line, end_line]`,
    numbered snippet, and a compact unified diff against `old_lf`.
    """
    d_lines = content_lf.splitlines()
    o_lines = old_lf.splitlines()
    while o_lines and not o_lines[0].strip():
        o_lines.pop(0)
    while o_lines and not o_lines[-1].strip():
        o_lines.pop()

    if not d_lines or not o_lines:
        s1 = 1 + line_offset
        return {
            "start_line": s1,
            "end_line": s1,
            "similarity": 0.0,
            "snippet": "",
            "suggestion": f"Use edit_file(path, start_line={s1}, end_line={s1}, new_text=...) or align old_text with L{s1}.",
        }

    n, m = len(d_lines), len(o_lines)
    ndisk = [x.strip() for x in d_lines]
    nold = [x.strip() for x in o_lines]
    nold_s = "\n".join(nold)
    rold_s = "\n".join(o_lines)

    if n <= 220:
        cands: Set[int] = set(range(max(1, n - m + 1)))
    else:
        cands = set()
        ne = [i for i, s in enumerate(nold) if s] or [0]
        anchors = list(dict.fromkeys([ne[0], max(ne, key=lambda i: len(nold[i])), ne[len(ne) // 2], ne[-1]]))
        tri_idx: Dict[str, List[int]] = {}
        for idx, dl in enumerate(ndisk):
            if len(dl) >= 3:
                for k in range(min(len(dl) - 2, 72)):
                    lst = tri_idx.setdefault(dl[k : k + 3], [])
                    if len(lst) < 80 and (not lst or lst[-1] != idx):
                        lst.append(idx)
        votes: Dict[int, int] = {}
        for a_off in anchors:
            astr = nold[a_off]
            if len(astr) >= 3:
                for k in range(min(len(astr) - 2, 72)):
                    for d_i in tri_idx.get(astr[k : k + 3], ()):
                        ws = max(0, min(max(0, n - m), d_i - a_off))
                        votes[ws] = votes.get(ws, 0) + 1
        for ws, _ in sorted(votes.items(), key=lambda kv: -kv[1])[:28]:
            for d in (-1, 0, 1):
                cands.add(max(0, min(max(0, n - 1), ws + d)))
        if not cands:
            a0 = anchors[0]
            top_q = sorted(
                ((difflib.SequenceMatcher(None, nold[a0], dl).quick_ratio(), i) for i, dl in enumerate(ndisk)),
                reverse=True,
            )[:16]
            for _, i in top_q:
                cands.add(max(0, min(max(0, n - 1), i - a0)))

    best_sim, best_s, best_e = -1.0, 0, min(n, m)
    wlens = sorted({max(1, m - 1), m, min(n, m + 1)})
    for s in sorted(cands):
        for wl in wlens:
            e = min(n, s + wl)
            if e <= s:
                continue
            sm = difflib.SequenceMatcher(None, nold_s, "\n".join(ndisk[s:e]))
            if sm.quick_ratio() + 0.05 < best_sim:
                continue
            sc = 0.72 * sm.ratio() + 0.28 * difflib.SequenceMatcher(None, rold_s, "\n".join(d_lines[s:e])).ratio()
            if sc > best_sim:
                best_sim, best_s, best_e = sc, s, e

    abs_s = best_s + 1 + line_offset
    abs_e = best_e + line_offset
    ctx_s = max(0, best_s - 2)
    ctx_e = min(n, best_e + 2)
    numbered_ctx = "\n".join(f"{ctx_s + 1 + line_offset + k}| {d_lines[ctx_s + k]}" for k in range(ctx_e - ctx_s))
    return {
        "start_line": abs_s,
        "end_line": abs_e,
        "similarity": round(max(0.0, best_sim), 3),
        "snippet": numbered_ctx,
        "suggestion": f"Use edit_file(path, start_line={abs_s}, end_line={abs_e}, new_text=...) or align old_text with L{abs_s}-L{abs_e}.",
    }


def find_closest_match_diagnostic(
    content: str,
    old_text: str,
    *,
    filename: str = "file",
    line_offset: int = 0,
) -> Dict[str, Any]:
    """Return closest-snippet diagnostic with exact 1-based line numbers and compact unified diff."""
    return find_sliding_window_closest_match(
        content.replace("\r\n", "\n"),
        (old_text or "").replace("\r\n", "\n"),
        line_offset=line_offset,
        filename=filename,
    )


# ---------------------------------------------------------------------------
# 2. 9-Strategy Fuzzy Matcher + Indentation Delta Rebasing
# ---------------------------------------------------------------------------


def effective_fuzzy_char_count(text: str) -> int:
    """Count meaningful characters after removing whitespace and pure bracket/delimiter tokens."""
    if not text:
        return 0
    return len(_LOW_ENTROPY_STRIP_RE.sub("", text))


def _unicode_normalize(text: str) -> str:
    for char, repl in UNICODE_MAP.items():
        text = text.replace(char, repl)
    return text


def _leading_ws_width(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _rebase_replacement_indent(
    content: str,
    start: int,
    end: int,
    old_string: str,
    new_string: str,
    strategy_name: str,
) -> str:
    """Shift `new_string` by `(min_orig_indent - min_old_indent)` when matched via indent-flexible strategy."""
    if strategy_name not in _INDENT_REBASE_STRATEGIES or not new_string:
        return new_string
    if start > 0 and content[start - 1] != "\n":
        return new_string

    orig_block = content[start:end]
    orig_non_empty = [ln for ln in orig_block.split("\n") if ln.strip()]
    old_non_empty = [ln for ln in old_string.split("\n") if ln.strip()]
    new_lines = new_string.split("\n")
    new_non_empty = [ln for ln in new_lines if ln.strip()]
    if not orig_non_empty or not old_non_empty or not new_non_empty:
        return new_string

    min_orig = min(_leading_ws_width(ln) for ln in orig_non_empty)
    min_old = min(_leading_ws_width(ln) for ln in old_non_empty)
    min_new = min(_leading_ws_width(ln) for ln in new_non_empty)

    delta = min_orig - min_old
    if delta == 0:
        return new_string
    if min_new == min_orig and min_old != min_new:
        return new_string

    first_indented = next((ln for ln in orig_non_empty if _leading_ws_width(ln) > 0), "")
    indent_char = "\t" if first_indented.startswith("\t") else " "

    rebased: List[str] = []
    for ln in new_lines:
        if not ln.strip():
            rebased.append(ln)
        elif delta > 0:
            rebased.append((indent_char * delta) + ln)
        else:
            strip_n = min(-delta, _leading_ws_width(ln))
            rebased.append(ln[strip_n:])
    return "\n".join(rebased)


def _calculate_line_positions(
    content_lines: List[str],
    start_line: int,
    end_line: int,
    content_length: int,
) -> Tuple[int, int]:
    start_pos = sum(len(line) + 1 for line in content_lines[:start_line])
    end_pos = sum(len(line) + 1 for line in content_lines[:end_line]) - 1
    if end_pos >= content_length:
        end_pos = content_length
    return start_pos, end_pos


def _find_normalized_matches(
    content: str,
    content_lines: List[str],
    content_normalized_lines: List[str],
    pattern_normalized: str,
) -> List[Tuple[int, int]]:
    pattern_norm_lines = pattern_normalized.split("\n")
    num_pattern_lines = len(pattern_norm_lines)
    matches: List[Tuple[int, int]] = []
    for i in range(len(content_normalized_lines) - num_pattern_lines + 1):
        block = "\n".join(content_normalized_lines[i : i + num_pattern_lines])
        if block == pattern_normalized:
            start_pos, end_pos = _calculate_line_positions(content_lines, i, i + num_pattern_lines, len(content))
            matches.append((start_pos, end_pos))
    return matches


def _map_normalized_positions(
    original: str,
    normalized: str,
    normalized_matches: List[Tuple[int, int]],
) -> List[Tuple[int, int]]:
    if not normalized_matches:
        return []
    orig_to_norm: List[int] = []
    orig_idx = 0
    norm_idx = 0
    while orig_idx < len(original) and norm_idx < len(normalized):
        if original[orig_idx] == normalized[norm_idx]:
            orig_to_norm.append(norm_idx)
            orig_idx += 1
            norm_idx += 1
        elif original[orig_idx] in " \t" and normalized[norm_idx] == " ":
            orig_to_norm.append(norm_idx)
            orig_idx += 1
            if orig_idx < len(original) and original[orig_idx] not in " \t":
                norm_idx += 1
        elif original[orig_idx] in " \t":
            orig_to_norm.append(norm_idx)
            orig_idx += 1
        else:
            orig_to_norm.append(norm_idx)
            orig_idx += 1
    while orig_idx < len(original):
        orig_to_norm.append(len(normalized))
        orig_idx += 1

    norm_to_orig_start: Dict[int, int] = {}
    norm_to_orig_end: Dict[int, int] = {}
    for orig_pos, norm_pos in enumerate(orig_to_norm):
        if norm_pos not in norm_to_orig_start:
            norm_to_orig_start[norm_pos] = orig_pos
        norm_to_orig_end[norm_pos] = orig_pos

    original_matches: List[Tuple[int, int]] = []
    for norm_start, norm_end in normalized_matches:
        if norm_start in norm_to_orig_start:
            orig_start = norm_to_orig_start[norm_start]
        else:
            orig_start = min(i for i, n in enumerate(orig_to_norm) if n >= norm_start)
        if norm_end - 1 in norm_to_orig_end:
            orig_end = norm_to_orig_end[norm_end - 1] + 1
        else:
            orig_end = orig_start + (norm_end - norm_start)
        while orig_end < len(original) and original[orig_end] in " \t":
            orig_end += 1
        original_matches.append((orig_start, min(orig_end, len(original))))
    return original_matches


def _strategy_exact(content: str, pattern: str) -> List[Tuple[int, int]]:
    """Strategy 1: Exact string match."""
    matches: List[Tuple[int, int]] = []
    start = 0
    while True:
        pos = content.find(pattern, start)
        if pos == -1:
            break
        matches.append((pos, pos + len(pattern)))
        start = pos + 1
    return matches


def _strategy_line_trimmed(content: str, pattern: str) -> List[Tuple[int, int]]:
    """Strategy 2: Strip leading and trailing whitespace on each line."""
    pattern_lines = [line.strip() for line in pattern.split("\n")]
    if not any(pattern_lines):
        return []
    content_lines = content.split("\n")
    content_normalized_lines = [line.strip() for line in content_lines]
    return _find_normalized_matches(content, content_lines, content_normalized_lines, "\n".join(pattern_lines))


def _strategy_whitespace_normalized(content: str, pattern: str) -> List[Tuple[int, int]]:
    """Strategy 3: Collapse runs of spaces/tabs into a single space."""
    def _norm(s: str) -> str:
        return re.sub(r"[ \t]+", " ", s)

    pattern_normalized = _norm(pattern)
    if not pattern_normalized.strip():
        return []
    content_normalized = _norm(content)
    matches_in_normalized = _strategy_exact(content_normalized, pattern_normalized)
    if not matches_in_normalized:
        return []
    mapped = _map_normalized_positions(content, content_normalized, matches_in_normalized)
    if "\n" in pattern and not pattern.startswith((" ", "\t")):
        widened: List[Tuple[int, int]] = []
        for orig_s, orig_e in mapped:
            line_s = content.rfind("\n", 0, orig_s) + 1
            if orig_s > line_s and content[line_s:orig_s].strip(" \t") == "":
                orig_s = line_s
            widened.append((orig_s, orig_e))
        return widened
    return mapped


def _strategy_indentation_flexible(content: str, pattern: str) -> List[Tuple[int, int]]:
    """Strategy 4: Strip leading whitespace per line (preserving trailing text)."""
    pattern_lines = [line.lstrip(" \t") for line in pattern.split("\n")]
    if not any(ln.strip() for ln in pattern_lines):
        return []
    content_lines = content.split("\n")
    content_stripped_lines = [line.lstrip(" \t") for line in content_lines]
    return _find_normalized_matches(content, content_lines, content_stripped_lines, "\n".join(pattern_lines))


def _strategy_escape_normalized(content: str, pattern: str) -> List[Tuple[int, int]]:
    """Strategy 5: Unescape literal `\\n`, `\\t`, `\\r` sequences."""
    pattern_unescaped = pattern.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r")
    if pattern_unescaped == pattern:
        return []
    return _strategy_exact(content, pattern_unescaped)


def _strategy_trimmed_boundary(content: str, pattern: str) -> List[Tuple[int, int]]:
    """Strategy 6: Trim whitespace on first and last lines only (preserving interior lines)."""
    pattern_lines = pattern.split("\n")
    if not pattern_lines or not any(ln.strip() for ln in pattern_lines):
        return []
    pattern_lines[0] = pattern_lines[0].strip()
    if len(pattern_lines) > 1:
        pattern_lines[-1] = pattern_lines[-1].strip()
    modified_pattern = "\n".join(pattern_lines)
    content_lines = content.split("\n")
    matches: List[Tuple[int, int]] = []
    pattern_line_count = len(pattern_lines)
    for i in range(len(content_lines) - pattern_line_count + 1):
        check_lines = content_lines[i : i + pattern_line_count].copy()
        check_lines[0] = check_lines[0].strip()
        if len(check_lines) > 1:
            check_lines[-1] = check_lines[-1].strip()
        if "\n".join(check_lines) == modified_pattern:
            start_pos, end_pos = _calculate_line_positions(content_lines, i, i + pattern_line_count, len(content))
            matches.append((start_pos, end_pos))
    return matches


def _build_orig_to_norm_map(original: str) -> List[int]:
    result: List[int] = []
    norm_pos = 0
    for char in original:
        result.append(norm_pos)
        repl = UNICODE_MAP.get(char)
        norm_pos += len(repl) if repl is not None else 1
    result.append(norm_pos)
    return result


def _map_positions_norm_to_orig(
    orig_to_norm: List[int],
    norm_matches: List[Tuple[int, int]],
) -> List[Tuple[int, int]]:
    norm_to_orig_start: Dict[int, int] = {}
    for orig_pos, norm_pos in enumerate(orig_to_norm[:-1]):
        if norm_pos not in norm_to_orig_start:
            norm_to_orig_start[norm_pos] = orig_pos

    results: List[Tuple[int, int]] = []
    orig_len = len(orig_to_norm) - 1
    for norm_start, norm_end in norm_matches:
        if norm_start not in norm_to_orig_start:
            continue
        orig_start = norm_to_orig_start[norm_start]
        orig_end = orig_start
        while orig_end < orig_len and orig_to_norm[orig_end] < norm_end:
            orig_end += 1
        results.append((orig_start, orig_end))
    return results


def _strategy_unicode_normalized(content: str, pattern: str) -> List[Tuple[int, int]]:
    """Strategy 7: Smart quotes, dashes, ellipsis, and NBSP normalization."""
    norm_pattern = _unicode_normalize(pattern)
    norm_content = _unicode_normalize(content)
    if norm_content == content and norm_pattern == pattern:
        return []
    norm_matches = _strategy_exact(norm_content, norm_pattern)
    if not norm_matches:
        norm_matches = _strategy_line_trimmed(norm_content, norm_pattern)
    if not norm_matches:
        return []
    orig_to_norm = _build_orig_to_norm_map(content)
    return _map_positions_norm_to_orig(orig_to_norm, norm_matches)


def _strategy_block_anchor(content: str, pattern: str) -> List[Tuple[int, int]]:
    """Strategy 8: First + last line anchor with middle SequenceMatcher similarity."""
    if effective_fuzzy_char_count(pattern) < MIN_APPROX_STRATEGY_CHARS:
        return []
    norm_pattern = _unicode_normalize(pattern)
    norm_content = _unicode_normalize(content)
    pattern_lines = norm_pattern.split("\n")
    if len(pattern_lines) < 3:
        return []
    first_line = pattern_lines[0].strip()
    last_line = pattern_lines[-1].strip()
    if not first_line or not last_line:
        return []

    norm_content_lines = norm_content.split("\n")
    orig_content_lines = content.split("\n")
    pattern_line_count = len(pattern_lines)

    potential_matches: List[int] = []
    for i in range(len(norm_content_lines) - pattern_line_count + 1):
        if (
            norm_content_lines[i].strip() == first_line
            and norm_content_lines[i + pattern_line_count - 1].strip() == last_line
        ):
            potential_matches.append(i)

    if not potential_matches:
        return []
    threshold = 0.50 if len(potential_matches) == 1 else 0.70
    matches: List[Tuple[int, int]] = []
    pattern_middle = "\n".join(pattern_lines[1:-1])
    for i in potential_matches:
        content_middle = "\n".join(norm_content_lines[i + 1 : i + pattern_line_count - 1])
        similarity = difflib.SequenceMatcher(None, content_middle, pattern_middle).ratio()
        if similarity >= threshold:
            start_pos, end_pos = _calculate_line_positions(orig_content_lines, i, i + pattern_line_count, len(content))
            matches.append((start_pos, end_pos))
    return matches


def _strategy_context_aware(content: str, pattern: str) -> List[Tuple[int, int]]:
    """Strategy 9: Line-by-line similarity (>=50% lines >=0.80 ratio & >=0.65 block ratio)."""
    if effective_fuzzy_char_count(pattern) < MIN_APPROX_STRATEGY_CHARS:
        return []
    pattern_lines = pattern.split("\n")
    if len(pattern_lines) < 3:
        return []
    content_lines = content.split("\n")
    pattern_line_count = len(pattern_lines)
    norm_pat_block = "\n".join(ln.strip() for ln in pattern_lines)
    matches: List[Tuple[int, int]] = []

    for i in range(len(content_lines) - pattern_line_count + 1):
        block_lines = content_lines[i : i + pattern_line_count]
        high_sim_count = 0
        for p_line, c_line in zip(pattern_lines, block_lines):
            if difflib.SequenceMatcher(None, p_line.strip(), c_line.strip()).ratio() >= 0.80:
                high_sim_count += 1
        if high_sim_count >= pattern_line_count * 0.5:
            norm_blk = "\n".join(ln.strip() for ln in block_lines)
            if difflib.SequenceMatcher(None, norm_pat_block, norm_blk).ratio() >= 0.65:
                start_pos, end_pos = _calculate_line_positions(content_lines, i, i + pattern_line_count, len(content))
                matches.append((start_pos, end_pos))
    return matches


FUZZY_STRATEGIES_9: Tuple[Tuple[str, Callable[[str, str], List[Tuple[int, int]]]], ...] = (
    ("exact", _strategy_exact),
    ("line_trimmed", _strategy_line_trimmed),
    ("whitespace_normalized", _strategy_whitespace_normalized),
    ("indentation_flexible", _strategy_indentation_flexible),
    ("escape_normalized", _strategy_escape_normalized),
    ("trimmed_boundary", _strategy_trimmed_boundary),
    ("unicode_normalized", _strategy_unicode_normalized),
    ("block_anchor", _strategy_block_anchor),
    ("context_aware", _strategy_context_aware),
)


def _format_multi_match_error(content: str, matches: List[Tuple[int, int]]) -> str:
    line_nums = [content.count("\n", 0, s) + 1 for s, _ in matches[:12]]
    lines_str = ", ".join(f"L{ln}" for ln in line_nums)
    return (
        f"Found {len(matches)} matches for old_text at [{lines_str}]. "
        f"Provide surrounding context, scope by start_line/end_line, or set replace_all=True."
    )


def _apply_replacements(
    content: str,
    matches: List[Tuple[int, int]],
    old_string: str,
    new_string: str,
    strategy_name: str = "exact",
) -> str:
    sorted_matches = sorted(matches, key=lambda x: x[0], reverse=True)
    result = content
    for start, end in sorted_matches:
        adj_new = _rebase_replacement_indent(content, start, end, old_string, new_string, strategy_name)
        result = result[:start] + adj_new + result[end:]
    return result


def fuzzy_find_and_replace(
    content: str,
    old_string: str,
    new_string: str,
    replace_all: bool = False,
) -> Tuple[str, int, Optional[str], Optional[str]]:
    """
    Find and replace `old_string` with `new_string` using the 9-strategy chain and base-indentation rebasing.
    Returns `(new_content, match_count, strategy_name, error_message)`.
    """
    if not old_string:
        return content, 0, None, "old_text cannot be empty"
    if old_string == new_string:
        return content, 0, None, "old_text and new_text are identical"

    exact_matches = _strategy_exact(content, old_string)
    if exact_matches:
        if len(exact_matches) > 1 and not replace_all:
            return content, 0, None, _format_multi_match_error(content, exact_matches)
        return _apply_replacements(content, exact_matches, old_string, new_string, "exact"), len(exact_matches), "exact", None

    eff_chars = effective_fuzzy_char_count(old_string)
    if eff_chars < MIN_FUZZY_WHITESPACE_CHARS:
        trimmed_hits = _strategy_line_trimmed(content, old_string)
        if len(trimmed_hits) > 1 and not replace_all:
            return content, 0, None, _format_multi_match_error(content, trimmed_hits)
        return (
            content,
            0,
            None,
            (
                f"Could not find an exact match for delimiter-only old_text ({eff_chars} effective chars < "
                f"{MIN_FUZZY_WHITESPACE_CHARS}); add surrounding context lines."
            ),
        )

    for strategy_name, strategy_fn in FUZZY_STRATEGIES_9[1:]:
        matches = strategy_fn(content, old_string)
        if matches:
            if len(matches) > 1 and not replace_all:
                return content, 0, None, _format_multi_match_error(content, matches)
            new_content = _apply_replacements(content, matches, old_string, new_string, strategy_name)
            return new_content, len(matches), strategy_name, None

    return content, 0, None, "Could not find a match for old_text in the file"


def find_fuzzy_match_locations(
    content_lf: str,
    old_lf: str,
    *,
    line_offset: int = 0,
    max_locations: int = 8,
) -> Tuple[int, List[Dict[str, Any]]]:
    """Return `(total_matches, locations)` with 1-based `[line, end_line]` for multi-match disambiguation."""
    if not content_lf or not old_lf:
        return 0, []
    spans: List[Tuple[int, int]] = []
    for _, sfn in FUZZY_STRATEGIES_9:
        cs = sfn(content_lf, old_lf)
        if cs:
            spans = list(cs)
            break
    if not spans:
        return 0, []

    lines = content_lf.splitlines()
    lstarts = [0] + [idx + 1 for idx, ch in enumerate(content_lf) if ch == "\n"]
    locs: List[Dict[str, Any]] = []
    for cs_pos, ce_pos in spans[:max_locations]:
        sr = max(1, bisect.bisect_right(lstarts, max(0, cs_pos)))
        er = max(sr, bisect.bisect_right(lstarts, max(cs_pos, ce_pos - 1)))
        c0, c1 = max(0, sr - 2), min(len(lines), er + 1)
        locs.append(
            {
                "line": sr + line_offset,
                "end_line": er + line_offset,
                "context": "\n".join(f"{k + 1 + line_offset}| {lines[k]}" for k in range(c0, c1)),
            }
        )
    return len(spans), locs


# ---------------------------------------------------------------------------
# 3. Fence-Aware Markdown Section Patching
# ---------------------------------------------------------------------------


def markdown_section_patch(
    content: str,
    selector_spec: str,
    new_text: str,
) -> Tuple[str, int, str, str]:
    """
    Replace or append a Markdown section via `heading: ...`, `section: ...`, or `append_section: ...`
    while ignoring `#` comments inside fenced code blocks (` ``` ` / `~~~`).
    """
    m_pref = re.match(r"^(heading|section|append_section):\s*(.+)$", selector_spec.strip(), re.DOTALL)
    if not m_pref:
        return content, 0, "", "not_a_section_selector"
    mode = m_pref.group(1).lower()
    raw_query = m_pref.group(2).strip().splitlines()[0].strip()
    if not raw_query:
        return content, 0, "", "empty_section_heading_query"

    m_hashes = re.match(r"^(#{1,6})\s*(.+)$", raw_query)
    req_level = len(m_hashes.group(1)) if m_hashes else None
    title_needle = (m_hashes.group(2) if m_hashes else raw_query).strip()

    lines = content.splitlines(keepends=True)
    heading_re = re.compile(r"^\s*(#{1,6})\s+(.+?)\s*$")
    in_fence = False
    fence_marker = ""
    headings: List[Tuple[int, int, str]] = []

    for idx, ln in enumerate(lines):
        stripped_r = ln.rstrip("\r\n")
        mf = _FENCE_OPEN_RE.match(stripped_r)
        if mf:
            tok = mf.group(1)
            if not in_fence:
                in_fence = True
                fence_marker = tok[0] * len(tok)
                continue
            if stripped_r.lstrip().startswith(fence_marker) and stripped_r.strip() == stripped_r.strip()[0] * len(stripped_r.strip()):
                in_fence = False
                fence_marker = ""
                continue
        if in_fence:
            continue
        mh = heading_re.match(stripped_r)
        if mh:
            headings.append((idx, len(mh.group(1)), mh.group(2).strip()))

    start_idx = -1
    start_level = 0
    for exact_only in (True, False):
        for idx, lvl, htitle in headings:
            if req_level is not None and lvl != req_level:
                continue
            matched = (title_needle == htitle) if exact_only else (title_needle in htitle)
            if matched:
                start_idx = idx
                start_level = lvl
                break
        if start_idx >= 0:
            break

    if start_idx < 0:
        return content, 0, "", f"markdown_section_not_found:{raw_query}"

    if mode == "heading":
        orig_line = lines[start_idx]
        line_nl = "\r\n" if orig_line.endswith("\r\n") else ("\n" if orig_line.endswith("\n") else "")
        clean_h_new = new_text.rstrip("\r\n")
        if not re.match(r"^\s*#{1,6}\s+", clean_h_new):
            clean_h_new = ("#" * start_level) + " " + clean_h_new.lstrip()
        lines_out = list(lines)
        lines_out[start_idx] = clean_h_new + line_nl
        return "".join(lines_out), 1, f"markdown_replace_heading(L{start_idx + 1})", ""

    end_idx = len(lines)
    for idx, lvl, _ in headings:
        if idx > start_idx and lvl <= start_level:
            end_idx = idx
            break

    nl = "\r\n" if "\r\n" in content else "\n"
    clean_new = new_text.rstrip("\r\n")
    trailing_sep = (nl + nl) if end_idx < len(lines) else nl
    if mode == "append_section":
        existing_sec = "".join(lines[start_idx:end_idx]).rstrip("\r\n")
        replacement_block = existing_sec + nl + clean_new + trailing_sep
        strat = f"markdown_append_section(L{start_idx + 1}..L{end_idx})"
    else:
        if not re.match(r"^\s*#{1,6}\s+", clean_new):
            clean_new = lines[start_idx].rstrip("\r\n") + nl + clean_new
        replacement_block = clean_new + trailing_sep
        strat = f"markdown_replace_section(L{start_idx + 1}..L{end_idx})"

    updated = "".join(lines[:start_idx]) + replacement_block + "".join(lines[end_idx:])
    return updated, 1, strat, ""


# ---------------------------------------------------------------------------
# 4. Single & Multi-Segment `[start_line, end_line]` Bottom-Up Line Replacement
# ---------------------------------------------------------------------------


def _apply_single_line_range_raw(
    raw_text: str,
    start_line: int,
    end_line: int,
    new_text: str,
) -> Tuple[Optional[str], Optional[str]]:
    req_s = int(start_line)
    req_e = int(end_line)
    if req_s < 1:
        return None, f"Invalid line range {start_line}..{end_line}: start_line must be >= 1 (1-based indexing)."
    if req_e < req_s:
        return None, f"Invalid line range {start_line}..{end_line}: end_line must be >= start_line."

    dominant_crlf = detect_dominant_crlf(raw_text)
    orig_raw_lines = split_lines_exact_nl(raw_text)
    total = len(orig_raw_lines)
    if req_s > total + 1:
        return None, f"Invalid line range {start_line}..{end_line}: start_line exceeds file length + 1 (file has {total} lines)."

    s = req_s
    e = min(total, req_e)
    new_lf = new_text.replace("\r\n", "\n")
    prefix_lines = list(orig_raw_lines[: s - 1])
    replaced_slice = orig_raw_lines[s - 1 : e]
    suffix_lines = list(orig_raw_lines[e:])

    slice_crlf = sum(1 for x in replaced_slice if x.endswith("\r\n"))
    slice_lf = sum(1 for x in replaced_slice if x.endswith("\n") and not x.endswith("\r\n"))
    use_crlf = (slice_crlf >= slice_lf) if (slice_crlf + slice_lf) > 0 else dominant_crlf
    nl_sep = "\r\n" if use_crlf else "\n"

    orig_had_trailing_nl = bool(not orig_raw_lines or orig_raw_lines[-1].endswith(("\n", "\r")))
    want_trailing_nl = orig_had_trailing_nl or new_lf.endswith(("\n", "\r"))

    if s == total + 1 and prefix_lines and not prefix_lines[-1].endswith(("\n", "\r")) and new_lf != "":
        prev_nl = "\r\n" if dominant_crlf else "\n"
        prefix_lines[-1] = prefix_lines[-1] + prev_nl

    if new_lf == "":
        replacement_lines: List[str] = []
    else:
        raw_rep_lines = new_lf.splitlines()
        if raw_rep_lines:
            replacement_lines = [ln + nl_sep for ln in raw_rep_lines]
            if req_e >= total and not want_trailing_nl:
                replacement_lines[-1] = raw_rep_lines[-1]
        else:
            replacement_lines = [nl_sep]

    return "".join(prefix_lines + replacement_lines + suffix_lines), None


def apply_line_range_edits_in_memory(
    raw_text: str,
    edits: Sequence[Union[Dict[str, Any], Tuple[int, int, str]]],
) -> Dict[str, Any]:
    """
    Apply multiple non-overlapping 1-based inclusive `[start_line, end_line]` edits in descending
    bottom-up order so earlier line expansions/contractions never shift downstream line numbers.
    """
    if not edits:
        return {"ok": False, "error": "edits list cannot be empty"}

    orig_total = len(split_lines_exact_nl(raw_text))
    parsed_ranges: List[Tuple[int, int, int, str]] = []
    for idx, item in enumerate(edits):
        if isinstance(item, tuple) and len(item) == 3:
            sl, el, ntxt = int(item[0]), int(item[1]), str(item[2])
        elif isinstance(item, dict):
            sl = int(item.get("start_line") or item.get("StartLine") or 0)
            el = int(item.get("end_line") or item.get("EndLine") or sl)
            ntxt = str(
                item.get("new_text")
                if "new_text" in item
                else (item.get("ReplacementContent") or item.get("replacement") or "")
            )
        else:
            return {"ok": False, "failed_index": idx, "error": f"Invalid line-range edit at index {idx}"}

        if sl < 1 or el < sl:
            return {
                "ok": False,
                "failed_index": idx,
                "error": f"Invalid 1-based inclusive line range {sl}..{el} at index {idx}.",
            }
        if sl > orig_total + 1:
            return {
                "ok": False,
                "failed_index": idx,
                "error": f"start_line={sl} exceeds file length + 1 ({orig_total} lines) at index {idx}.",
            }
        parsed_ranges.append((sl, el, idx, ntxt))

    for i_a in range(len(parsed_ranges)):
        sa, ea, idx_a, _ = parsed_ranges[i_a]
        for i_b in range(i_a + 1, len(parsed_ranges)):
            sb, eb, idx_b, _ = parsed_ranges[i_b]
            if max(sa, sb) <= min(ea, eb):
                return {
                    "ok": False,
                    "overlapping_ranges": True,
                    "error": f"Overlapping line ranges [{sa}..{ea}] (index {idx_a}) and [{sb}..{eb}] (index {idx_b}).",
                }

    sorted_desc = sorted(parsed_ranges, key=lambda x: (-x[0], -x[1], -x[2]))
    reordered = [x[2] for x in sorted_desc] != list(range(len(parsed_ranges)))
    cur_text = raw_text
    applied_spans: List[str] = []
    for sl, el, _, ntxt in sorted_desc:
        next_text, err = _apply_single_line_range_raw(cur_text, sl, el, ntxt)
        if err is not None or next_text is None:
            return {"ok": False, "error": err or "Failed applying line range"}
        cur_text = next_text
        applied_spans.append(f"{sl}..{el}")

    return {
        "ok": True,
        "patched_text": cur_text,
        "applied_count": len(sorted_desc),
        "applied_bottom_up": True,
        "reordered_from_input": reordered,
        "applied_ranges_order": applied_spans,
    }


# ---------------------------------------------------------------------------
# 5. Core Single-File Patch Computation & `patch_file` / `smart_patch_file`
# ---------------------------------------------------------------------------


def _compute_edit_span_and_preview(old_lf: str, new_lf: str, filename: str = "file") -> Tuple[int, int, int, str]:
    old_lines = old_lf.splitlines()
    new_lines = new_lf.splitlines()
    sm = difflib.SequenceMatcher(None, old_lines, new_lines)
    changed_count = 0
    first_new_ln = 1
    last_new_ln = max(1, len(new_lines))
    saw_change = False
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        if not saw_change:
            saw_change = True
            first_new_ln = j1 + 1
        last_new_ln = max(first_new_ln, j2 if j2 > j1 else j1 + 1)
        changed_count += max(i2 - i1, j2 - j1)
    return changed_count, first_new_ln, last_new_ln, make_compact_diff(old_lf, new_lf, filename=filename, max_lines=60)


def compute_patched_bytes(
    p: Path,
    raw_bytes: bytes,
    old_text: str,
    new_text: str,
    *,
    start_line: int = 0,
    end_line: int = 0,
    replace_all: bool = False,
) -> Dict[str, Any]:
    """Compute patched file bytes in memory preserving original encoding and mixed `CRLF/LF`."""
    try:
        raw_text, enc_tag = detect_and_decode_bytes(raw_bytes, strict_for_edit=True)
    except ValueError as exc:
        return {"ok": False, "path": str(p), "error": str(exc)}

    has_bom = enc_tag.endswith("-bom") or enc_tag == "utf-8-sig"
    content_lf = raw_text.replace("\r\n", "\n")
    old_lf = (old_text or "").replace("\r\n", "\n")
    new_lf = (new_text or "").replace("\r\n", "\n")

    s_req, e_req = int(start_line or 0), int(end_line or 0)
    if s_req < 0 or e_req < 0 or (s_req > 0 and e_req > 0 and e_req < s_req):
        return {"ok": False, "path": str(p), "error": f"Invalid line window: start_line={s_req}, end_line={e_req}."}

    if (s_req > 0 or e_req > 0) and old_lf == "":
        eff_s = s_req if s_req > 0 else 1
        eff_e = e_req if e_req > 0 else eff_s
        patched_raw, l_err = _apply_single_line_range_raw(raw_text, eff_s, eff_e, new_text)
        if l_err is not None or patched_raw is None:
            return {"ok": False, "path": str(p), "error": l_err or "Invalid line range"}
        new_content_lf = patched_raw.replace("\r\n", "\n")
        final_bytes = encode_with_detected_encoding(patched_raw, enc_tag)
        lines_changed, s_ln, e_ln, udiff = _compute_edit_span_and_preview(content_lf, new_content_lf, filename=p.name)
        return {
            "ok": True,
            "replaced_count": 1,
            "strategy_used": f"line_range(L{eff_s}..L{eff_e})",
            "encoding": enc_tag,
            "bom_preserved": has_bom,
            "final_bytes": final_bytes,
            "lines_changed": lines_changed,
            "start_line": s_ln,
            "end_line": e_ln,
            "diff_preview": udiff,
        }

    if s_req > 0 or e_req > 0:
        lkeep = content_lf.splitlines(keepends=True)
        win_s = max(1, (s_req if s_req > 0 else 1) - WINDOW_DRIFT_LINES)
        win_e = min(len(lkeep), (e_req if e_req > 0 else (s_req + max(len(old_lf.splitlines()), 1))) + WINDOW_DRIFT_LINES)
        s_i, e_i = max(0, win_s - 1), max(0, win_e)
        win_doc = "".join(lkeep[s_i:e_i])
        patched_w, count, strategy_used, err = fuzzy_find_and_replace(win_doc, old_lf, new_lf, replace_all=replace_all)
        if count == 0:
            if err and "Found " in err and " matches" in err:
                tm, locs = find_fuzzy_match_locations(win_doc, old_lf, line_offset=s_i)
                return {
                    "ok": False,
                    "path": str(p),
                    "multiple_matches": True,
                    "match_count": tm,
                    "match_locations": locs,
                    "error": f"Found {tm} matches inside window [L{win_s}-L{win_e}]. Narrow start_line/end_line or add context.",
                }
            diag = find_closest_match_diagnostic(
                win_doc if win_doc else content_lf,
                old_lf,
                filename=p.name,
                line_offset=s_i if win_doc else 0,
            )
            return {
                "ok": False,
                "path": str(p),
                "window_searched": [win_s, max(win_s, win_e)],
                "closest_match": diag,
                "error": f"old_text not found inside window [L{win_s}-L{max(win_s, win_e)}] ({err}).",
            }
        new_content_lf = "".join(lkeep[:s_i]) + patched_w + "".join(lkeep[e_i:])
        strategy_or_err = f"window(L{win_s}..L{win_e}):{strategy_used}"
    elif old_lf.lstrip().startswith(("heading:", "section:", "append_section:")):
        new_content_lf, count, strategy_used, err = markdown_section_patch(content_lf, old_lf, new_lf)
        strategy_or_err = strategy_used or err
        if count == 0:
            diag = find_closest_match_diagnostic(content_lf, old_lf, filename=p.name)
            return {
                "ok": False,
                "path": str(p),
                "closest_match": diag,
                "error": f"Markdown section selector failed ({err})",
            }
    else:
        new_content_lf, count, strategy_used, err = fuzzy_find_and_replace(
            content_lf, old_lf, new_lf, replace_all=replace_all
        )
        strategy_or_err = str(strategy_used or err or "")
        if count == 0:
            if err and "Found " in err and " matches" in err:
                tm, locs = find_fuzzy_match_locations(content_lf, old_lf)
                return {
                    "ok": False,
                    "path": str(p),
                    "multiple_matches": True,
                    "match_count": tm,
                    "match_locations": locs,
                    "error": str(err),
                }
            diag = find_closest_match_diagnostic(content_lf, old_lf, filename=p.name)
            return {
                "ok": False,
                "path": str(p),
                "closest_match": diag,
                "error": f"old_text not found (tried 9 fuzzy strategies: {strategy_or_err})",
            }

    patched_text = preserve_line_endings_for_edit(raw_text, new_content_lf)
    final_bytes = encode_with_detected_encoding(patched_text, enc_tag)
    lines_changed, s_ln, e_ln, udiff = _compute_edit_span_and_preview(content_lf, new_content_lf, filename=p.name)
    return {
        "ok": True,
        "replaced_count": count,
        "strategy_used": strategy_or_err,
        "encoding": enc_tag,
        "bom_preserved": has_bom,
        "final_bytes": final_bytes,
        "lines_changed": lines_changed,
        "start_line": s_ln,
        "end_line": e_ln,
        "diff_preview": udiff,
    }


_compute_patched_bytes = compute_patched_bytes


def patch_file(
    path_str: str | Path,
    old_text: str = "",
    new_text: str = "",
    *,
    start_line: int = 0,
    end_line: int = 0,
    replace_all: bool = False,
    edits: Optional[Sequence[Dict[str, Any]]] = None,
    auto_rollback_on_invalid: bool = True,
    check_node: bool = True,
    save_snapshot: bool = True,
    expected_sha256: str = "",
    workspace_root: Optional[str | Path] = None,
    undo_dir: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """
    Surgical 9-strategy fuzzy / windowed / Markdown-section / multi-segment patch primitive
    with encoding & CRLF preservation, staged syntax check, and `.undo_history` snapshot.
    """
    if edits is not None:
        if (old_text or "").strip() or (new_text or "").strip():
            return {
                "ok": False,
                "path": str(path_str),
                "error": "Pass either `edits=[...]` OR `old_text`/`new_text`, not both.",
            }
        enriched_edits = [{**ed, "path": ed.get("path") or str(path_str)} for ed in edits]
        return multi_patch(
            enriched_edits,
            verify_after=auto_rollback_on_invalid,
            check_node=check_node,
            save_snapshot=save_snapshot,
            workspace_root=workspace_root,
            undo_dir=undo_dir,
        )

    p = Path(path_str).expanduser().resolve()
    with get_file_lock(p):
        if not p.exists() or not p.is_file():
            return {"ok": False, "path": str(p), "error": f"File not found: {p}"}
        pre_lock = check_office_or_os_file_lock(p, exc=None, for_write=True)
        if pre_lock is not None:
            return pre_lock
        try:
            raw_bytes = p.read_bytes()
        except OSError as rd_exc:
            lk_d = check_office_or_os_file_lock(p, exc=rd_exc, for_write=True)
            if lk_d is not None:
                return lk_d
            return {"ok": False, "path": str(p), "error": f"{type(rd_exc).__name__}: {rd_exc}"}

        lock_err = verify_expected_sha256(raw_bytes, expected_sha256)
        if lock_err:
            return {"ok": False, "optimistic_lock_conflict": True, "path": str(p), "error": lock_err}

        calc = compute_patched_bytes(
            p,
            raw_bytes,
            old_text,
            new_text,
            start_line=start_line,
            end_line=end_line,
            replace_all=replace_all,
        )
        if not calc["ok"]:
            return calc

        commit = atomic_validate_and_replace(
            p,
            calc["final_bytes"],
            enforce_syntax=auto_rollback_on_invalid,
            check_node=check_node,
            save_snapshot=save_snapshot,
            workspace_root=workspace_root,
            undo_dir=undo_dir,
        )
        if not commit["ok"]:
            if commit.get("file_locked_by_external_app") or commit.get("backup_failed"):
                return {**commit, "path": str(p)}
            return {
                "ok": False,
                "auto_rolled_back": True,
                "path": str(p),
                "strategy_used": calc["strategy_used"],
                "error": "Edit introduced a syntax error; rejected during staging before modifying the original file.",
                "syntax_check": commit.get("syntax_check"),
            }

        return {
            "ok": True,
            "path": str(p),
            "encoding": calc["encoding"],
            "bom_preserved": calc["bom_preserved"],
            "lines_changed": calc["lines_changed"],
            "start_line": calc["start_line"],
            "end_line": calc["end_line"],
            "replaced_count": calc["replaced_count"],
            "strategy_used": calc["strategy_used"],
            "final_bytes": commit["final_bytes"],
            "undo_snapshot": commit["undo_snapshot"],
            "sha256": commit["sha256"],
            "sha256_prefix": commit["sha256_prefix"],
            "syntax_check": commit["syntax_check"],
            "diff_preview": calc["diff_preview"],
        }


smart_patch_file = patch_file


# ---------------------------------------------------------------------------
# 6. `v4a` Multi-File Patch Parser & All-or-Nothing Atomic Executor
# ---------------------------------------------------------------------------


class OperationType(Enum):
    ADD = "add"
    UPDATE = "update"
    DELETE = "delete"
    MOVE = "move"


@dataclass
class HunkLine:
    prefix: str  # ' ', '-', or '+'
    content: str


@dataclass
class Hunk:
    context_hint: Optional[str] = None
    lines: List[HunkLine] = field(default_factory=list)


@dataclass
class PatchOperation:
    operation: OperationType
    file_path: str
    new_path: Optional[str] = None
    hunks: List[Hunk] = field(default_factory=list)


def parse_v4a_patch(patch_content: str) -> Tuple[List[PatchOperation], Optional[str]]:
    """
    Parse a V4A format multi-file patch (`*** Begin Patch` ... `*** End Patch`), supporting:
    - `*** Update File: <path>` (with optional `*** Move to: <new_path>` and `@@ ... @@` hunks)
    - `*** Add File: <path>` (`+` lines)
    - `*** Delete File: <path>`
    - `*** Move File: <old_path> -> <new_path>`
    """
    norm_patch = (patch_content or "").replace("\r\n", "\n")
    lines = norm_patch.split("\n")
    operations: List[PatchOperation] = []

    start_idx: Optional[int] = None
    end_idx: Optional[int] = None
    for i, line in enumerate(lines):
        if "*** Begin Patch" in line or "***Begin Patch" in line:
            start_idx = i
        elif "*** End Patch" in line or "***End Patch" in line:
            end_idx = i
            break

    if start_idx is None:
        start_idx = -1
    if end_idx is None:
        end_idx = len(lines)

    i = start_idx + 1
    current_op: Optional[PatchOperation] = None
    current_hunk: Optional[Hunk] = None

    def _flush_op() -> None:
        nonlocal current_op, current_hunk
        if current_op is not None:
            if current_hunk is not None and current_hunk.lines:
                current_op.hunks.append(current_hunk)
            operations.append(current_op)
        current_op = None
        current_hunk = None

    while i < end_idx:
        line = lines[i]
        update_match = re.match(r"^\*\*\*\s*Update\s+File:\s*(.+)$", line)
        add_match = re.match(r"^\*\*\*\s*Add\s+File:\s*(.+)$", line)
        delete_match = re.match(r"^\*\*\*\s*Delete\s+File:\s*(.+)$", line)
        move_match = re.match(r"^\*\*\*\s*Move\s+File:\s*(.+?)\s*->\s*(.+)$", line)
        move_to_match = re.match(r"^\*\*\*\s*Move\s+to:\s*(.+)$", line)

        if update_match:
            _flush_op()
            current_op = PatchOperation(operation=OperationType.UPDATE, file_path=update_match.group(1).strip())
        elif add_match:
            _flush_op()
            current_op = PatchOperation(operation=OperationType.ADD, file_path=add_match.group(1).strip())
            current_hunk = Hunk()
        elif delete_match:
            _flush_op()
            operations.append(PatchOperation(operation=OperationType.DELETE, file_path=delete_match.group(1).strip()))
        elif move_match:
            _flush_op()
            operations.append(
                PatchOperation(
                    operation=OperationType.MOVE,
                    file_path=move_match.group(1).strip(),
                    new_path=move_match.group(2).strip(),
                )
            )
        elif move_to_match and current_op is not None and current_op.operation == OperationType.UPDATE:
            current_op.new_path = move_to_match.group(1).strip()
        elif line.startswith("@@"):
            if current_op is not None:
                if current_hunk is not None and current_hunk.lines:
                    current_op.hunks.append(current_hunk)
                hint_match = re.match(r"^@@\s*(.+?)\s*@@\s*$", line)
                hint = hint_match.group(1) if hint_match else line[2:].strip() or None
                current_hunk = Hunk(context_hint=hint)
        elif line.startswith("***"):
            return [], f"Parse error at line {i + 1}: unrecognized V4A directive {line!r}"
        elif current_op is not None:
            if current_op.operation == OperationType.ADD:
                if line.startswith("+"):
                    if current_hunk is None:
                        current_hunk = Hunk()
                    current_hunk.lines.append(HunkLine("+", line[1:]))
                elif line == "":
                    pass
                else:
                    return [], f"Parse error in Add File {current_op.file_path!r} at line {i + 1}: expected '+' prefix, got {line!r}"
            else:
                if line.startswith("+"):
                    if current_hunk is None:
                        current_hunk = Hunk()
                    current_hunk.lines.append(HunkLine("+", line[1:]))
                elif line.startswith("-"):
                    if current_hunk is None:
                        current_hunk = Hunk()
                    current_hunk.lines.append(HunkLine("-", line[1:]))
                elif line.startswith(" "):
                    if current_hunk is None:
                        current_hunk = Hunk()
                    current_hunk.lines.append(HunkLine(" ", line[1:]))
                elif line.startswith("\\"):
                    pass
                elif line == "":
                    # Blank line inside an active hunk before more hunk lines acts as an empty context line
                    has_more_in_hunk = False
                    for nxt in lines[i + 1 : end_idx]:
                        if nxt.startswith(("***", "@@")):
                            break
                        if nxt != "":
                            has_more_in_hunk = True
                            break
                    if current_hunk is not None and current_hunk.lines and has_more_in_hunk:
                        current_hunk.lines.append(HunkLine(" ", ""))
                else:
                    if current_hunk is None:
                        current_hunk = Hunk()
                    current_hunk.lines.append(HunkLine(" ", line))
        elif line.strip():
            if start_idx >= 0:
                return [], f"Parse error at line {i + 1}: unexpected line outside file operation {line!r}"
        i += 1

    _flush_op()
    if not operations:
        return [], "Parse error: no V4A patch operations found"

    parse_errors: List[str] = []
    for op in operations:
        if not op.file_path:
            parse_errors.append("Operation with empty file path")
        if op.operation == OperationType.UPDATE and not op.hunks and not op.new_path:
            parse_errors.append(f"UPDATE {op.file_path!r}: no hunks found")
        if op.operation == OperationType.ADD and not any(
            hl.prefix == "+" for hk in op.hunks for hl in hk.lines
        ):
            # Allow empty file creation if Add File header is explicitly present with 0 lines
            pass
        if op.operation == OperationType.MOVE and not op.new_path:
            parse_errors.append(f"MOVE {op.file_path!r}: missing destination path")
    if parse_errors:
        return [], "Parse error: " + "; ".join(parse_errors)
    return operations, None


def _resolve_op_path(raw_rel: str, base_dir: Path) -> Path:
    p = Path(raw_rel).expanduser()
    return p.resolve() if p.is_absolute() else (base_dir / p).resolve()


def _apply_hunks_to_text_lf(
    content_lf: str,
    hunks: Sequence[Hunk],
    filename: str = "file",
) -> Tuple[Optional[str], Optional[str], Optional[Dict[str, Any]]]:
    cur = content_lf
    for h_idx, hunk in enumerate(hunks):
        search_lines = [hl.content for hl in hunk.lines if hl.prefix in (" ", "-")]
        replace_lines = [hl.content for hl in hunk.lines if hl.prefix in (" ", "+")]
        if search_lines:
            search_pattern = "\n".join(search_lines)
            replacement = "\n".join(replace_lines)
            next_c, cnt, _strat, err = fuzzy_find_and_replace(cur, search_pattern, replacement, replace_all=False)
            if cnt == 0 and hunk.context_hint:
                hint_pos = cur.find(hunk.context_hint)
                if hint_pos != -1:
                    win_s = max(0, cur.rfind("\n", 0, max(0, hint_pos - 600)) + 1)
                    win_e = min(len(cur), hint_pos + 2400)
                    win = cur[win_s:win_e]
                    win_new, cnt_w, _strat_w, err_w = fuzzy_find_and_replace(
                        win, search_pattern, replacement, replace_all=False
                    )
                    if cnt_w > 0:
                        next_c = cur[:win_s] + win_new + cur[win_e:]
                        cnt = cnt_w
                        err = None
                    else:
                        err = err_w
            if cnt == 0:
                diag = find_closest_match_diagnostic(cur, search_pattern, filename=filename)
                label = f"'{hunk.context_hint}'" if hunk.context_hint else f"#{h_idx + 1}"
                return None, f"Hunk {label} failed to match: {err}", diag
            cur = next_c
        else:
            insert_text = "\n".join(replace_lines)
            if hunk.context_hint:
                occurrences = cur.count(hunk.context_hint)
                if occurrences == 0:
                    diag = find_closest_match_diagnostic(cur, hunk.context_hint, filename=filename)
                    return None, f"Addition-only hunk context hint '{hunk.context_hint}' not found", diag
                if occurrences > 1:
                    return None, f"Addition-only hunk context hint '{hunk.context_hint}' is ambiguous ({occurrences} hits)", None
                hint_pos = cur.find(hunk.context_hint)
                eol = cur.find("\n", hint_pos)
                if eol != -1:
                    cur = cur[: eol + 1] + insert_text + "\n" + cur[eol + 1 :]
                else:
                    cur = cur + "\n" + insert_text
            else:
                cur = (cur.rstrip("\n") + "\n" + insert_text + "\n") if cur else (insert_text + "\n")
    return cur, None, None


def apply_v4a_patch(
    patch_content: str,
    *,
    base_dir: Optional[str | Path] = None,
    check_syntax: bool = True,
    check_node: bool = True,
    save_snapshot: bool = True,
    workspace_root: Optional[str | Path] = None,
    undo_dir: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """
    Parse and atomically execute a V4A multi-file patch:
    - Acquires `MultiFileLock` in canonical path order across all referenced source & destination paths.
    - Simulates all operations in memory and validates syntax across EVERY resulting file BEFORE touching disk.
    - Moves deleted files into `.undo_history/trash` (never permanently deleting).
    - Performs compensating rollback across all touched files if any OS error occurs mid-commit.
    """
    operations, parse_err = parse_v4a_patch(patch_content)
    if parse_err:
        return {"ok": False, "error": parse_err, "rolled_back_all": True}

    eff_base = (
        Path(base_dir).expanduser().resolve()
        if base_dir is not None
        else (
            Path(workspace_root).expanduser().resolve()
            if workspace_root is not None and str(workspace_root).strip()
            else Path.cwd().resolve()
        )
    )
    eff_ws = workspace_root if workspace_root is not None else eff_base

    all_lock_paths: List[Path] = []
    resolved_ops: List[Tuple[PatchOperation, Path, Optional[Path]]] = []
    for op in operations:
        src_p = _resolve_op_path(op.file_path, eff_base)
        dst_p = _resolve_op_path(op.new_path, eff_base) if op.new_path else None
        all_lock_paths.append(src_p)
        if dst_p is not None:
            all_lock_paths.append(dst_p)
        resolved_ops.append((op, src_p, dst_p))

    with MultiFileLock(all_lock_paths):
        orig_disk: Dict[Path, Optional[bytes]] = {}
        virtual_fs: Dict[Path, Optional[bytes]] = {}

        for p in dict.fromkeys(all_lock_paths):
            if p.exists():
                if p.is_dir():
                    return {
                        "ok": False,
                        "failed_path": str(p),
                        "error": f"Target path is a directory, not a file: {p}",
                        "rolled_back_all": True,
                    }
                pre_lk = check_office_or_os_file_lock(p, exc=None, for_write=True)
                if pre_lk is not None:
                    return {**pre_lk, "failed_path": str(p), "rolled_back_all": True}
                try:
                    b = p.read_bytes()
                except OSError as rd_exc:
                    lk_d = check_office_or_os_file_lock(p, exc=rd_exc, for_write=True)
                    if lk_d is not None:
                        return {**lk_d, "failed_path": str(p), "rolled_back_all": True}
                    return {
                        "ok": False,
                        "failed_path": str(p),
                        "error": f"{type(rd_exc).__name__}: {rd_exc}",
                        "rolled_back_all": True,
                    }
                orig_disk[p] = b
                virtual_fs[p] = b
            else:
                orig_disk[p] = None
                virtual_fs[p] = None

        files_created: List[str] = []
        files_modified: List[str] = []
        files_deleted: List[str] = []
        files_moved: List[str] = []

        # Phase 1: Full in-memory simulation across all V4A operations
        for idx, (op, src_p, dst_p) in enumerate(resolved_ops):
            cur_b = virtual_fs.get(src_p)

            if op.operation == OperationType.ADD:
                add_lines = [hl.content for hk in op.hunks for hl in hk.lines if hl.prefix == "+"]
                add_txt = ("\n".join(add_lines) + "\n") if add_lines else ""
                virtual_fs[src_p] = add_txt.encode("utf-8")
                if str(src_p) not in files_created:
                    files_created.append(str(src_p))

            elif op.operation == OperationType.DELETE:
                if cur_b is None:
                    return {
                        "ok": False,
                        "failed_index": idx,
                        "failed_path": str(src_p),
                        "error": f"File not found for deletion: {src_p}",
                        "rolled_back_all": True,
                    }
                virtual_fs[src_p] = None
                if str(src_p) not in files_deleted:
                    files_deleted.append(str(src_p))

            elif op.operation == OperationType.MOVE:
                if cur_b is None or dst_p is None:
                    return {
                        "ok": False,
                        "failed_index": idx,
                        "failed_path": str(src_p),
                        "error": f"Source file not found for move: {src_p}",
                        "rolled_back_all": True,
                    }
                if dst_p != src_p and virtual_fs.get(dst_p) is not None:
                    return {
                        "ok": False,
                        "failed_index": idx,
                        "failed_path": str(dst_p),
                        "error": f"Destination already exists for move: {dst_p}",
                        "rolled_back_all": True,
                    }
                virtual_fs[src_p] = None
                virtual_fs[dst_p] = cur_b
                files_moved.append(f"{src_p} -> {dst_p}")

            elif op.operation == OperationType.UPDATE:
                if cur_b is None:
                    return {
                        "ok": False,
                        "failed_index": idx,
                        "failed_path": str(src_p),
                        "error": f"File not found for update: {src_p}",
                        "rolled_back_all": True,
                    }
                try:
                    raw_txt, enc_tag = detect_and_decode_bytes(cur_b, strict_for_edit=True)
                except ValueError as exc:
                    return {
                        "ok": False,
                        "failed_index": idx,
                        "failed_path": str(src_p),
                        "error": str(exc),
                        "rolled_back_all": True,
                    }
                content_lf = raw_txt.replace("\r\n", "\n")
                if op.hunks:
                    updated_lf, h_err, diag = _apply_hunks_to_text_lf(content_lf, op.hunks, filename=src_p.name)
                    if h_err is not None or updated_lf is None:
                        return {
                            "ok": False,
                            "failed_index": idx,
                            "failed_path": str(src_p),
                            "error": f"{src_p.name}: {h_err}",
                            "closest_match": diag,
                            "rolled_back_all": True,
                        }
                    restored_txt = preserve_line_endings_for_edit(raw_txt, updated_lf)
                    next_bytes = encode_with_detected_encoding(restored_txt, enc_tag)
                else:
                    next_bytes = cur_b

                if dst_p is not None and dst_p != src_p:
                    if virtual_fs.get(dst_p) is not None:
                        return {
                            "ok": False,
                            "failed_index": idx,
                            "failed_path": str(dst_p),
                            "error": f"Move destination already exists: {dst_p}",
                            "rolled_back_all": True,
                        }
                    virtual_fs[src_p] = None
                    virtual_fs[dst_p] = next_bytes
                    files_moved.append(f"{src_p} -> {dst_p}")
                else:
                    virtual_fs[src_p] = next_bytes
                    if str(src_p) not in files_modified and str(src_p) not in files_created:
                        files_modified.append(str(src_p))

        # Phase 2: Pre-commit syntax validation across ALL resulting files BEFORE modifying disk
        if check_syntax:
            for p, final_b in virtual_fs.items():
                if final_b is None or final_b == orig_disk.get(p):
                    continue
                txt_chk, _ = detect_and_decode_bytes(final_b, strict_for_edit=False)
                sc = auto_check_syntax(p, content=txt_chk, raw_bytes=final_b, check_node=check_node)
                if not sc.get("valid", True):
                    return {
                        "ok": False,
                        "failed_path": str(p),
                        "auto_rolled_back": True,
                        "rolled_back_all": True,
                        "syntax_check": sc,
                        "error": f"Syntax verification failed on {p.name} ({sc.get('error')}); aborted V4A patch with zero disk changes.",
                    }

        # Phase 3: Physical commit with compensating rollback journal
        written_existing: List[Path] = []
        written_new: List[Path] = []
        trashed_ids: List[Tuple[Path, str]] = []
        diff_chunks: List[str] = []

        def _rollback_committed() -> None:
            for nw in reversed(written_new):
                with contextlib.suppress(Exception):
                    if nw.exists():
                        nw.unlink(missing_ok=True)
                    pop_latest_undo_entry_quiet(nw, workspace_root=eff_ws, undo_dir=undo_dir)
            for ow in reversed(written_existing):
                orig_b = orig_disk.get(ow)
                if orig_b is not None:
                    with contextlib.suppress(Exception):
                        atomic_validate_and_replace(
                            ow,
                            orig_b,
                            enforce_syntax=False,
                            check_node=False,
                            save_snapshot=False,
                            workspace_root=eff_ws,
                            undo_dir=undo_dir,
                        )
                        pop_latest_undo_entry_quiet(ow, workspace_root=eff_ws, undo_dir=undo_dir)
            for _tp, tid in reversed(trashed_ids):
                if tid:
                    with contextlib.suppress(Exception):
                        restore_from_trash(tid, workspace_root=eff_ws, undo_dir=undo_dir)

        # 3a) Write all added/updated/moved-destination files first
        sha_by_path: Dict[str, str] = {}
        for p, final_b in virtual_fs.items():
            if final_b is None:
                continue
            orig_b = orig_disk.get(p)
            if orig_b == final_b and p.exists():
                sha_by_path[str(p)] = hashlib.sha256(final_b).hexdigest().lower()
                continue
            try:
                cm = atomic_validate_and_replace(
                    p,
                    final_b,
                    enforce_syntax=check_syntax,
                    check_node=check_node,
                    save_snapshot=save_snapshot,
                    workspace_root=eff_ws,
                    undo_dir=undo_dir,
                )
            except Exception as exc:
                _rollback_committed()
                return {
                    "ok": False,
                    "failed_path": str(p),
                    "rolled_back_all": True,
                    "error": f"Commit failed on {p.name} ({type(exc).__name__}: {exc}); rolled back all files.",
                }
            if not cm.get("ok"):
                _rollback_committed()
                return {
                    "ok": False,
                    "failed_path": str(p),
                    "auto_rolled_back": True,
                    "rolled_back_all": True,
                    "syntax_check": cm.get("syntax_check"),
                    "error": cm.get("error") or f"Commit failed on {p.name}; rolled back all files.",
                }
            if orig_b is None:
                written_new.append(p)
            else:
                written_existing.append(p)
            sha_by_path[str(p)] = cm["sha256"]

            old_txt_d = detect_and_decode_bytes(orig_b, strict_for_edit=False)[0] if orig_b is not None else ""
            new_txt_d = detect_and_decode_bytes(final_b, strict_for_edit=False)[0]
            d_prev = make_compact_diff(old_txt_d.replace("\r\n", "\n"), new_txt_d.replace("\r\n", "\n"), filename=p.name, max_lines=30)
            if d_prev:
                diff_chunks.append(d_prev)

        # 3b) Move deleted / moved-from files into `.undo_history/trash`
        for p, final_b in virtual_fs.items():
            if final_b is None and orig_disk.get(p) is not None and p.exists():
                tr_res = safe_trash_file(p, reason="v4a_patch_delete_or_move", workspace_root=eff_ws, undo_dir=undo_dir)
                if not tr_res.get("ok"):
                    _rollback_committed()
                    return {
                        "ok": False,
                        "failed_path": str(p),
                        "rolled_back_all": True,
                        "error": f"Failed to trash {p.name}: {tr_res.get('error')}; rolled back all files.",
                    }
                trashed_ids.append((p, str(tr_res.get("trash_id") or "")))

        return {
            "ok": True,
            "format": "v4a",
            "applied_count": len(resolved_ops),
            "files_created": files_created,
            "files_modified": files_modified,
            "files_deleted": files_deleted,
            "files_moved": files_moved,
            "trashed_items": [{"path": str(tp), "trash_id": tid} for tp, tid in trashed_ids],
            "sha256_by_path": sha_by_path,
            "diff_preview": "\n".join(diff_chunks[:60]),
        }


def multi_patch(
    edits_or_patch: Union[str, Sequence[Dict[str, Any]]],
    *,
    verify_after: bool = True,
    check_node: bool = True,
    save_snapshot: bool = True,
    base_dir: Optional[str | Path] = None,
    workspace_root: Optional[str | Path] = None,
    undo_dir: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """
    Unified atomic multi-file patch transaction accepting EITHER:
    1. A `v4a` patch string (`*** Begin Patch ... *** End Patch`), OR
    2. A list of edit dicts (`[{"path": ..., "old_text": ..., "new_text": ...}]` or line-range dicts
       `[{"path": ..., "start_line": ..., "end_line": ..., "new_text": ...}]` with automatic bottom-up ordering).
    Guarantees 100% rollback across all touched files if any edit or syntax check fails.
    """
    if isinstance(edits_or_patch, str):
        return apply_v4a_patch(
            edits_or_patch,
            base_dir=base_dir,
            check_syntax=verify_after,
            check_node=check_node,
            save_snapshot=save_snapshot,
            workspace_root=workspace_root,
            undo_dir=undo_dir,
        )

    if not isinstance(edits_or_patch, (list, tuple)) or not edits_or_patch:
        return {"ok": False, "error": "edits must be a non-empty list of patch dicts or a V4A patch string", "rolled_back_all": True}

    eff_base = (
        Path(base_dir).expanduser().resolve()
        if base_dir is not None
        else (
            Path(workspace_root).expanduser().resolve()
            if workspace_root is not None and str(workspace_root).strip()
            else None
        )
    )

    resolved_targets: List[Path] = []
    for idx, item in enumerate(edits_or_patch):
        if not isinstance(item, dict):
            return {"ok": False, "failed_index": idx, "error": "Each edit entry must be a dict", "rolled_back_all": True}
        raw_path = str(item.get("path") or item.get("TargetFile") or "").strip()
        if not raw_path:
            return {"ok": False, "failed_index": idx, "error": f"edits[{idx}] missing `path`", "rolled_back_all": True}
        cand_p = Path(raw_path).expanduser()
        p_norm = (eff_base / cand_p).resolve() if (eff_base is not None and not cand_p.is_absolute()) else cand_p.resolve()
        resolved_targets.append(p_norm)

    unique_paths = list(dict.fromkeys(resolved_targets))

    with MultiFileLock(unique_paths):
        orig_buffers: Dict[Path, bytes] = {}
        staged_buffers: Dict[Path, bytes] = {}

        for idx, p in enumerate(resolved_targets):
            if p in orig_buffers:
                continue
            if not p.exists() or not p.is_file():
                return {"ok": False, "failed_index": idx, "failed_path": str(p), "error": f"File not found: {p}", "rolled_back_all": True}
            pre_lk = check_office_or_os_file_lock(p, exc=None, for_write=True)
            if pre_lk is not None:
                return {**pre_lk, "failed_index": idx, "failed_path": str(p), "rolled_back_all": True}
            try:
                disk_b = p.read_bytes()
            except OSError as rd_exc:
                lk_d = check_office_or_os_file_lock(p, exc=rd_exc, for_write=True)
                if lk_d is not None:
                    return {**lk_d, "failed_index": idx, "failed_path": str(p), "rolled_back_all": True}
                return {"ok": False, "failed_index": idx, "failed_path": str(p), "error": f"{type(rd_exc).__name__}: {rd_exc}", "rolled_back_all": True}
            orig_buffers[p] = disk_b
            staged_buffers[p] = disk_b

        checked_sha_paths: Set[Path] = set()
        for idx, item in enumerate(edits_or_patch):
            p = resolved_targets[idx]
            exp_sha = str(item.get("expected_sha256") or "").strip()
            if exp_sha and p not in checked_sha_paths:
                lk_err = verify_expected_sha256(orig_buffers[p], exp_sha)
                if lk_err:
                    return {
                        "ok": False,
                        "failed_index": idx,
                        "failed_path": str(p),
                        "optimistic_lock_conflict": True,
                        "error": lk_err,
                        "rolled_back_all": True,
                    }
                checked_sha_paths.add(p)

        # Group by file to order pure `[start_line, end_line]` edits bottom-up descending
        by_file: Dict[Path, List[Tuple[int, Dict[str, Any]]]] = {}
        for idx, item in enumerate(edits_or_patch):
            by_file.setdefault(resolved_targets[idx], []).append((idx, item))

        execution_plan: List[Tuple[int, Path, Dict[str, Any]]] = []
        reordered_bottom_up = False
        for tp in unique_paths:
            f_items = by_file[tp]
            if len(f_items) >= 2:
                pure_ranges: List[Tuple[int, int, int, Dict[str, Any]]] = []
                text_items: List[Tuple[int, Dict[str, Any]]] = []
                valid_pure = True
                for orig_idx, ch in f_items:
                    c_old = str(ch.get("old_text") or "")
                    c_sl = int(ch.get("start_line") or ch.get("StartLine") or 0)
                    c_el = int(ch.get("end_line") or ch.get("EndLine") or 0)
                    if (c_sl > 0 or c_el > 0) and c_old == "":
                        s_r = c_sl if c_sl > 0 else 1
                        e_r = c_el if c_el > 0 else s_r
                        if s_r < 1 or e_r < s_r:
                            valid_pure = False
                            break
                        pure_ranges.append((s_r, e_r, orig_idx, ch))
                    elif c_old != "" and c_sl == 0 and c_el == 0:
                        text_items.append((orig_idx, ch))
                    else:
                        valid_pure = False
                        break

                if valid_pure and len(pure_ranges) >= 2:
                    for i_a in range(len(pure_ranges)):
                        sa, ea, idx_a, _ = pure_ranges[i_a]
                        for i_b in range(i_a + 1, len(pure_ranges)):
                            sb, eb, idx_b, _ = pure_ranges[i_b]
                            if max(sa, sb) <= min(ea, eb):
                                return {
                                    "ok": False,
                                    "failed_index": idx_b,
                                    "failed_path": str(tp),
                                    "overlapping_ranges": True,
                                    "error": f"Overlapping line ranges [{sa}..{ea}] and [{sb}..{eb}] in {tp.name}.",
                                    "rolled_back_all": True,
                                }
                    sorted_pure = [(x[2], x[3]) for x in sorted(pure_ranges, key=lambda x: (-x[0], -x[1], -x[2]))]
                    combined = sorted_pure + text_items
                    if [x[0] for x in combined] != [x[0] for x in f_items]:
                        reordered_bottom_up = True
                    f_items = combined

            for orig_idx, ch in f_items:
                execution_plan.append((orig_idx, tp, ch))

        pending_calcs: List[Tuple[int, Path, Dict[str, Any]]] = []
        for orig_idx, p, item in execution_plan:
            old_text = str(item.get("old_text") or "")
            new_text = str(item.get("new_text") if "new_text" in item else (item.get("ReplacementContent") or ""))
            sl = int(item.get("start_line") or item.get("StartLine") or 0)
            el = int(item.get("end_line") or item.get("EndLine") or 0)
            replace_all = bool(item.get("replace_all", False))

            calc = compute_patched_bytes(
                p,
                staged_buffers[p],
                old_text,
                new_text,
                start_line=sl,
                end_line=el,
                replace_all=replace_all,
            )
            if not calc["ok"]:
                err_resp = dict(calc)
                err_resp.update({"failed_index": orig_idx, "failed_path": str(p), "rolled_back_all": True})
                return err_resp
            staged_buffers[p] = calc["final_bytes"]
            pending_calcs.append((orig_idx, p, calc))

        if verify_after:
            for p, final_b in staged_buffers.items():
                txt_chk, _ = detect_and_decode_bytes(final_b, strict_for_edit=False)
                sc = auto_check_syntax(p, content=txt_chk, raw_bytes=final_b, check_node=check_node)
                if not sc.get("valid", True):
                    return {
                        "ok": False,
                        "failed_path": str(p),
                        "error": f"Syntax verification failed on {p.name}; aborted transaction before modifying any file.",
                        "syntax_check": sc,
                        "auto_rolled_back": True,
                        "rolled_back_all": True,
                    }

        committed_meta: Dict[Path, Dict[str, Any]] = {}
        committed_paths: List[Path] = []
        for p, final_b in staged_buffers.items():
            try:
                cm = atomic_validate_and_replace(
                    p,
                    final_b,
                    enforce_syntax=verify_after,
                    check_node=check_node,
                    save_snapshot=save_snapshot,
                    workspace_root=workspace_root,
                    undo_dir=undo_dir,
                )
            except Exception as exc:
                for rp in reversed(committed_paths):
                    with contextlib.suppress(Exception):
                        atomic_validate_and_replace(
                            rp,
                            orig_buffers[rp],
                            enforce_syntax=False,
                            check_node=False,
                            save_snapshot=False,
                            workspace_root=workspace_root,
                            undo_dir=undo_dir,
                        )
                        pop_latest_undo_entry_quiet(rp, workspace_root=workspace_root, undo_dir=undo_dir)
                return {
                    "ok": False,
                    "failed_path": str(p),
                    "error": f"Write failed on {p.name} ({type(exc).__name__}: {exc}); rolled back all {len(committed_paths)} previously written files.",
                    "rolled_back_all": True,
                }
            if not cm.get("ok"):
                for rp in reversed(committed_paths):
                    with contextlib.suppress(Exception):
                        atomic_validate_and_replace(
                            rp,
                            orig_buffers[rp],
                            enforce_syntax=False,
                            check_node=False,
                            save_snapshot=False,
                            workspace_root=workspace_root,
                            undo_dir=undo_dir,
                        )
                        pop_latest_undo_entry_quiet(rp, workspace_root=workspace_root, undo_dir=undo_dir)
                if cm.get("file_locked_by_external_app"):
                    return {**cm, "failed_path": str(p), "rolled_back_all": True}
                return {
                    "ok": False,
                    "failed_path": str(p),
                    "error": cm.get("error") or f"Verification failed on {p.name}; rolled back all {len(committed_paths)} files atomically.",
                    "syntax_check": cm.get("syntax_check"),
                    "auto_rolled_back": True,
                    "rolled_back_all": True,
                }
            committed_meta[p] = cm
            committed_paths.append(p)

        applied: List[Dict[str, Any]] = []
        for orig_idx, p, calc in sorted(pending_calcs, key=lambda x: x[0]):
            cm = committed_meta[p]
            applied.append(
                {
                    "ok": True,
                    "index": orig_idx,
                    "path": str(p),
                    "lines_changed": calc["lines_changed"],
                    "start_line": calc["start_line"],
                    "end_line": calc["end_line"],
                    "replaced_count": calc["replaced_count"],
                    "strategy_used": calc["strategy_used"],
                    "sha256": cm["sha256"],
                }
            )
        out_res: Dict[str, Any] = {
            "ok": True,
            "applied_count": len(applied),
            "files_modified": len(unique_paths),
            "results": applied,
        }
        if reordered_bottom_up:
            out_res["line_edits_applied_bottom_up"] = True
        return out_res


multi_patch_files = multi_patch
