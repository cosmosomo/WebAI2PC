from __future__ import annotations

"""
Workspace path auto-healing, typo candidate suggestion (`did_you_mean`), and
JS/TS object-literal property mapping consistency checks (`cosmos_mcp.core.path_heal`).

Strictly depends only on Python >=3.9 stdlib and `cosmos_mcp.core`.
"""

import difflib
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from cosmos_mcp.core.guard import WorkspaceGuard, canonical_realpath, expand_env_and_tilde, has_ntfs_ads_stream, strip_file_uri

IGNORED_HEAL_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".next",
    ".nuxt",
    ".undo_history",
    ".local_snapshots",
    ".mcp_state",
    ".localpc_memory",
    ".runtime",
    "dist",
    "build",
    "target",
    "out",
    "coverage",
}

_JS_TS_EXTS: Set[str] = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
_PROP_MAPPING_LINE_RE = re.compile(
    r"(?:^|[{,\s])([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*(?:[A-Za-z_$][A-Za-z0-9_$]*\??\.)+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:[,}\r\n]|//|$)"
)


def is_link_or_junction(p: Union[Path, str]) -> bool:
    """Return True if `p` is a symbolic link or Windows NTFS junction/mount-point (allowing OneDrive 0x9000* cloud files)."""
    p_str = str(p)
    try:
        st = os.lstat(p_str)
    except FileNotFoundError:
        return False
    except OSError:
        return os.path.islink(p_str)
    reparse_tag = int(getattr(st, "st_reparse_tag", 0) or 0)
    if reparse_tag != 0:
        return reparse_tag in (0xA000000C, 0xA0000003)
    if stat.S_ISLNK(getattr(st, "st_mode", 0)) or os.path.islink(p_str):
        return True
    p_obj = p if isinstance(p, Path) else Path(p_str)
    is_junc = getattr(p_obj, "is_junction", None)
    if callable(is_junc) and is_junc():
        return True
    if os.name == "nt" and bool(getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)):
        return True
    return False


def has_link_or_junction_in_rel(target: Path, base: Path) -> bool:
    """Return True if `target` or any component between `base` and `target` is a link/junction."""
    try:
        rel_parts = target.relative_to(base).parts
    except Exception:
        return is_link_or_junction(target)
    cur = base
    for part in rel_parts:
        cur = cur / part
        if is_link_or_junction(cur):
            return True
    return False


def is_noise_dir_name(name: str, *, allow_hidden: bool = False) -> bool:
    low = name.lower()
    if not allow_hidden and name.startswith("."):
        return True
    return (
        low in IGNORED_HEAL_DIRS
        or low.startswith("backups")
        or low.endswith("_bundle")
    )


def _norm_key(p: Path) -> str:
    return os.path.normcase(os.path.abspath(str(p)))


def _collapse_adjacent_duplicates(parts: Sequence[str]) -> Tuple[str, ...]:
    out: List[str] = []
    for pt in parts:
        if out and os.path.normcase(out[-1]) == os.path.normcase(pt):
            continue
        out.append(pt)
    return tuple(out)


def heal_duplicated_path_candidates(
    raw_path_str: str,
    workspace_roots: Sequence[Union[Path, str]] = (),
) -> List[Tuple[Path, str]]:
    """
    Generate candidate paths repairing common duplicated workspace prefixes such as:
    - `ws/sub/a.py` or `ws/ws/sub/a.py` when `workspace_root` is `.../ws`
    - `<abs_ws>/ws/sub/a.py` or `<abs_ws>/ws/ws/sub/a.py`
    - multi-root relative paths across secondary `workspace_roots`
    """
    clean_s = strip_file_uri(expand_env_and_tilde((raw_path_str or "").strip()))
    if not clean_s:
        return []

    roots: List[Path] = []
    for r in workspace_roots:
        if r is not None and str(r).strip():
            rp = Path(r).expanduser().resolve()
            if rp not in roots:
                roots.append(rp)

    raw_p = Path(clean_s)
    cands: List[Tuple[Path, str]] = []
    seen: Set[str] = set()

    def _add(cp: Path, reason: str) -> None:
        key = _norm_key(cp)
        if key not in seen:
            seen.add(key)
            cands.append((cp, reason))

    norm_slashes = clean_s.replace("\\", "/").strip("/")
    rel_tokens = [tok for tok in norm_slashes.split("/") if tok and tok != "."]

    for ws_p in roots:
        ws_name_nc = os.path.normcase(ws_p.name)

        # 1) Relative input: try direct join on each workspace root + stripped repeated `ws.name` prefixes
        if not raw_p.is_absolute() and rel_tokens:
            _add((ws_p / Path(*rel_tokens)).resolve(), f"resolved under workspace root `{ws_p}`")
            idx = 0
            while idx < len(rel_tokens) - 1 and os.path.normcase(rel_tokens[idx]) == ws_name_nc:
                idx += 1
            if idx > 0:
                _add(
                    (ws_p / Path(*rel_tokens[idx:])).resolve(),
                    f"stripped duplicated workspace prefix `{ '/'.join(rel_tokens[:idx]) }/`",
                )
            collapsed = _collapse_adjacent_duplicates(rel_tokens)
            if collapsed != tuple(rel_tokens):
                _add(
                    (ws_p / Path(*collapsed)).resolve(),
                    "collapsed adjacent duplicated path segments",
                )
                if len(collapsed) > 1 and os.path.normcase(collapsed[0]) == ws_name_nc:
                    _add(
                        (ws_p / Path(*collapsed[1:])).resolve(),
                        f"stripped duplicated workspace prefix `{collapsed[0]}/`",
                    )

        # 2) Absolute input inside `ws_p` (or `ws_p.parent`) containing repeated `ws_p.name`
        if raw_p.is_absolute():
            abs_p = raw_p.resolve()
            try:
                rel_under_ws = abs_p.relative_to(ws_p).parts
            except ValueError:
                rel_under_ws = ()
            if rel_under_ws:
                idx = 0
                while idx < len(rel_under_ws) - 1 and os.path.normcase(rel_under_ws[idx]) == ws_name_nc:
                    idx += 1
                if idx > 0:
                    _add(
                        ws_p.joinpath(*rel_under_ws[idx:]).resolve(),
                        f"stripped duplicated workspace segment `{ws_p.name}/`",
                    )
                collapsed_abs = _collapse_adjacent_duplicates(rel_under_ws)
                if collapsed_abs != tuple(rel_under_ws):
                    _add(
                        ws_p.joinpath(*collapsed_abs).resolve(),
                        "collapsed adjacent duplicated path segments",
                    )
                    if len(collapsed_abs) > 1 and os.path.normcase(collapsed_abs[0]) == ws_name_nc:
                        _add(
                            ws_p.joinpath(*collapsed_abs[1:]).resolve(),
                            f"stripped duplicated workspace segment `{collapsed_abs[0]}/`",
                        )

    return cands


def _format_display_candidate(cand: Path, roots: Sequence[Path]) -> str:
    for ws_p in roots:
        try:
            return cand.resolve().relative_to(ws_p.resolve()).as_posix()
        except Exception:
            continue
    return str(cand)


def suggest_did_you_mean(
    missing_p: Path,
    *,
    guard: Optional[WorkspaceGuard] = None,
    workspace_roots: Sequence[Union[Path, str]] = (),
    max_candidates: int = 5,
) -> List[str]:
    """
    Suggest close existing sibling or nearby workspace files (`did_you_mean`) when a target path is missing.
    """
    want_name = missing_p.name
    if not want_name:
        return []
    want_low = want_name.lower()
    want_stem = missing_p.stem.lower()

    roots: List[Path] = []
    if guard is not None:
        roots.extend(guard.workspace_roots)
    for r in workspace_roots:
        if r is not None and str(r).strip():
            rp = Path(r).expanduser().resolve()
            if rp not in roots:
                roots.append(rp)

    def _allowed(cp: Path) -> bool:
        target_p = canonical_realpath(cp) if is_link_or_junction(cp) else cp
        if is_link_or_junction(cp) and not target_p.exists():
            return False
        if guard is not None:
            return guard.check_path_access(str(target_p), mode="read") is None
        return not is_link_or_junction(cp)

    scored: List[Tuple[float, str]] = []
    seen_disp: Set[str] = set()

    def _consider(cp: Path, bonus: float = 0.0) -> None:
        if not _allowed(cp):
            return
        c_low = cp.name.lower()
        ratio = difflib.SequenceMatcher(None, want_low, c_low).ratio()
        if want_stem and len(want_stem) >= 3 and (want_stem in c_low or cp.stem.lower() in want_stem):
            ratio = max(ratio, 0.68)
        score = min(1.0, ratio + bonus)
        if score >= 0.44:
            disp = _format_display_candidate(cp, roots)
            if disp not in seen_disp:
                seen_disp.add(disp)
                scored.append((score, disp))

    parent = missing_p.parent
    if parent.is_dir() and not is_link_or_junction(parent) and _allowed(parent):
        try:
            with os.scandir(parent) as it:
                for idx, entry in enumerate(it):
                    if idx >= 300:
                        break
                    if entry.name.startswith("."):
                        continue
                    _consider(Path(entry.path), bonus=0.08)
        except OSError:
            pass

    scan_roots: List[Path] = []
    cur = parent
    for _ in range(4):
        if cur.is_dir() and not is_link_or_junction(cur) and _allowed(cur):
            if not roots or any(
                cur == r or str(cur).lower().startswith(str(r).lower().rstrip("\\/") + os.sep)
                for r in roots
            ):
                scan_roots.append(cur)
                break
        if cur.parent == cur:
            break
        cur = cur.parent
    for ws_r in roots:
        if ws_r.is_dir() and ws_r not in scan_roots:
            scan_roots.append(ws_r)

    scanned_files = 0
    for sr in scan_roots:
        if len(scored) >= max_candidates * 3 or scanned_files >= 400:
            break
        for root_dir, dirs, files in os.walk(sr, followlinks=False):
            root_p = Path(root_dir)
            dirs[:] = [
                d
                for d in sorted(dirs)
                if not is_noise_dir_name(d)
                and not is_link_or_junction(root_p / d)
                and _allowed(root_p / d)
            ]
            for fn in sorted(files):
                scanned_files += 1
                if scanned_files > 400:
                    break
                if fn.startswith("."):
                    continue
                _consider(root_p / fn, bonus=0.0)
            if scanned_files > 400:
                break

    scored.sort(key=lambda item: (-item[0], len(item[1]), item[1]))
    return [disp for _, disp in scored[: max(1, int(max_candidates))]]


def heal_and_resolve_path(
    raw_path: str,
    guard: WorkspaceGuard,
    *,
    mode: str = "read",
    must_exist: bool = False,
    expect_dir: bool = False,
    tool_name: str = "",
) -> Dict[str, Any]:
    """
    Validate path access via `WorkspaceGuard`, resolve against `workspace_roots`,
    auto-heal duplicated workspace prefixes (`ws/ws/sub/a.py`), and attach `did_you_mean` on miss.
    """
    raw_in = str(raw_path or "").strip()
    if not raw_in:
        if mode == "read" and guard.workspace_roots:
            default_ws = guard.workspace_roots[0]
            g_err = guard.check_path_access(str(default_ws), mode=mode, tool_name=tool_name)
            if g_err:
                return {"ok": False, "blocked_by_guardrail": True, "path": default_ws, "error": g_err}
            return {"ok": True, "path": default_ws, "healed": False, "healed_note": ""}
        return {"ok": False, "path": None, "error": "Target `path` is required and cannot be empty."}

    raw_guard_err = guard.check_path_access(raw_in, mode=mode, tool_name=tool_name)
    primary = guard.normalize_target_path(raw_in)
    norm_guard_err = guard.check_path_access(str(primary), mode=mode, tool_name=tool_name)

    # Check if primary directly satisfies request
    if raw_guard_err is None and norm_guard_err is None and primary.exists():
        if expect_dir and not primary.is_dir():
            return {"ok": False, "path": primary, "error": f"Path is not a directory: {primary}"}
        return {"ok": True, "path": primary, "healed": False, "healed_note": ""}

    # Attempt multi-root & duplicated-prefix healing (e.g. `ws/ws/sub/a.py` or secondary workspace root)
    # Only allow healing if raw_in does NOT contain ADS or traversal/credential block on raw tokens
    has_hard_security_block = bool(
        raw_guard_err
        and any(
            tag in raw_guard_err
            for tag in (
                "CREDENTIAL ISOLATION",
                "ANTI-TAMPER",
                "PERSISTENCE ISOLATION",
                "OS ISOLATION",
                "Alternate Data Stream",
                "TIER POLICY",
            )
        )
    )
    if not has_hard_security_block:
        for cand_p, reason in heal_duplicated_path_candidates(raw_in, guard.workspace_roots):
            if _norm_key(cand_p) == _norm_key(primary) and raw_guard_err is None and norm_guard_err is None:
                continue
            if guard.check_path_access(str(cand_p), mode=mode, tool_name=tool_name) is not None:
                continue
            if cand_p.exists():
                if expect_dir and not cand_p.is_dir():
                    continue
                return {
                    "ok": True,
                    "path": cand_p,
                    "healed": True,
                    "healed_from": raw_in,
                    "healed_note": f"Auto-healed path `{raw_in}` -> `{cand_p}` ({reason}).",
                }

    # If blocked by guardrail and no valid healed workspace target matched, surface guardrail error
    eff_guard_err = raw_guard_err or norm_guard_err
    if eff_guard_err:
        return {
            "ok": False,
            "blocked_by_guardrail": True,
            "path": primary,
            "error": eff_guard_err,
        }

    # For write operations (`must_exist=False`), check if duplicated workspace prefix exists on parent dir
    if not must_exist:
        if not primary.parent.exists():
            for cand_p, reason in heal_duplicated_path_candidates(raw_in, guard.workspace_roots):
                if (
                    cand_p.parent.exists()
                    and guard.check_path_access(str(cand_p), mode=mode, tool_name=tool_name) is None
                ):
                    return {
                        "ok": True,
                        "path": cand_p,
                        "healed": True,
                        "healed_from": raw_in,
                        "healed_note": f"Auto-healed parent path `{raw_in}` -> `{cand_p}` ({reason}).",
                    }
        return {"ok": True, "path": primary, "healed": False, "healed_note": ""}

    # `must_exist=True` and target does not exist: compute `did_you_mean`
    cands = suggest_did_you_mean(primary, guard=guard, workspace_roots=guard.workspace_roots)
    kind_word = "Directory" if expect_dir else "File"
    err_msg = f"{kind_word} not found: {primary}"
    if cands:
        err_msg += f" (did you mean: {', '.join(cands[:3])}?)"
    out: Dict[str, Any] = {
        "ok": False,
        "path": primary,
        "error": err_msg,
    }
    if cands:
        out["did_you_mean"] = cands
    return out


def _split_ident_tokens(ident: str) -> List[str]:
    clean = ident.strip("_$")
    if not clean:
        return []
    snake_parts = re.split(r"[_$]+", clean)
    tokens: List[str] = []
    for part in snake_parts:
        if not part:
            continue
        sub = re.findall(r"[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+", part)
        if sub:
            tokens.extend(t.lower() for t in sub)
        else:
            tokens.append(part.lower())
    return tokens


def check_object_literal_mapping_consistency(
    old_or_path: str,
    new_or_content: str,
    path_str: str = "",
) -> List[Dict[str, Any]]:
    """
    Detect suspicious property-name transpositions or near-miss typos in newly written JS/TS
    object-literal property mappings (`targetProp: obj.sourceProp`).

    Supports both:
    - `check_object_literal_mapping_consistency(old_content, new_content, path_str)`
    - `check_object_literal_mapping_consistency(path_str, content)`
    """
    if not path_str and ("\n" not in old_or_path) and Path(old_or_path).suffix.lower() in _JS_TS_EXTS:
        eff_path = old_or_path
        old_text = ""
        new_text = new_or_content
    else:
        eff_path = path_str
        old_text = old_or_path or ""
        new_text = new_or_content or ""

    if eff_path and Path(eff_path).suffix.lower() not in _JS_TS_EXTS:
        return []
    if not new_text:
        return []

    old_lines_set = {ln.strip() for ln in old_text.splitlines() if ln.strip()} if old_text else set()
    notices: List[Dict[str, Any]] = []

    for line_no, raw_ln in enumerate(new_text.splitlines(), start=1):
        stripped = raw_ln.strip()
        if not stripped or stripped.startswith("//") or stripped in old_lines_set:
            continue
        for m in _PROP_MAPPING_LINE_RE.finditer(raw_ln):
            lhs = m.group(1)
            rhs = m.group(2)
            if lhs == rhs or lhs.lower() == rhs.lower():
                continue
            lhs_toks = _split_ident_tokens(lhs)
            rhs_toks = _split_ident_tokens(rhs)
            if len(lhs_toks) < 2 or len(rhs_toks) < 2:
                continue
            lhs_norm = "_".join(lhs_toks)
            rhs_norm = "_".join(rhs_toks)
            if lhs_norm == rhs_norm or len(lhs_norm) < 6 or len(rhs_norm) < 6:
                continue
            # Check either exact token-bag permutation (`user_id_hash` vs `hash_user_id`) or high char similarity
            sim = difflib.SequenceMatcher(None, lhs_norm, rhs_norm).ratio()
            same_bag = sorted(lhs_toks) == sorted(rhs_toks)
            shared_prefix_or_suffix = (lhs_toks[0] == rhs_toks[0]) or (lhs_toks[-1] == rhs_toks[-1])
            if same_bag or (sim >= 0.76 and shared_prefix_or_suffix):
                notices.append(
                    {
                        "line": line_no,
                        "kind": "possible_property_mapping_mismatch",
                        "target_property": lhs,
                        "source_property": rhs,
                        "similarity": round(sim, 3),
                        "detail": f"Line {line_no} maps `{lhs}` from `.{rhs}`; verify property naming alignment.",
                    }
                )
                if len(notices) >= 8:
                    return notices
    return notices
