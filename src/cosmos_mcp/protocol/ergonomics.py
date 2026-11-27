from __future__ import annotations

"""
Session sideband ergonomics hook implementing `ExecutionHook`:
1. Unread-overwrite guard, legacy `overwrite=False` compatibility, and 300s peer MVCC check.
2. Consecutive error loop detector (`_loop_guard_warning`).
3. Post-edit unverified state reminder (`verification_state`).
4. Unified recognition of `[GUARD ...]` and `[LOCALPC ...]` error prefixes + Office exclusive locks
   (preserving `ok=True` on read-only operations when Office `~$` temp lock files exist).
5. Zero ghost-tool leakage (`sanitize_ghost_tool_mentions` rewrites/strips inactive tool names).

Strictly depends only on Python >=3.9 stdlib and `cosmos_mcp.core`.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import threading
import time
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from cosmos_mcp.core.contracts import ExecutionHook, SafetyBand, ToolCallContext
from cosmos_mcp.core.fs_io import check_office_or_os_file_lock
from cosmos_mcp.core.fs_tx import find_office_temp_lock_file
from cosmos_mcp.core.guard import WorkspaceGuard

MVCC_WINDOW_SEC = 300.0

ALL_CORE_BASE_TOOLS: FrozenSet[str] = frozenset(
    {
        "get_status",
        "find_files",
        "list_dir",
        "repo_map",
        "search_code",
        "code_intel",
        "code_outline",
        "get_symbols_overview",
        "find_symbol",
        "find_referencing_symbols",
        "replace_symbol_body",
        "insert_after_symbol",
        "rename_symbol",
        "read_file",
        "write_file",
        "edit_file",
        "patch_file",
        "replace_lines",
        "multi_patch",
        "manage_files",
        "undo_or_trash",
        "undo_edit",
        "trash_file",
        "restore_trash",
        "run_command",
        "run_python",
        "bg_command",
        "batch_probe",
        "web_research",
        "workspace_memory",
        "skill_hub",
        "skill_manage",
        "skill_search",
        "skill_load",
        "skill_register",
        "browser_use",
        "cua_window",
        "desktop_window",
    }
)

WRITE_MUTATION_TOOLS: FrozenSet[str] = frozenset(
    {
        "write_file",
        "edit_file",
        "patch_file",
        "replace_lines",
        "multi_patch",
        "replace_symbol_body",
        "insert_after_symbol",
        "rename_symbol",
        "manage_files",
        "undo_or_trash",
        "undo_edit",
        "trash_file",
        "restore_trash",
    }
)

NON_CODE_DOC_CONFIG_EXTS: FrozenSet[str] = frozenset(
    {
        ".md",
        ".markdown",
        ".rst",
        ".txt",
        ".json",
        ".jsonl",
        ".csv",
        ".tsv",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".yaml",
        ".yml",
        ".env",
        ".gitignore",
        ".lock",
    }
)


def _is_code_file_requiring_verification(path_str: str) -> bool:
    if not path_str or not str(path_str).strip():
        return False
    try:
        p = Path(str(path_str).strip())
        if p.exists() and p.is_dir():
            return False
        ext = p.suffix.lower()
    except Exception:
        ext = os.path.splitext(str(path_str))[1].lower()
    if not ext or ext in NON_CODE_DOC_CONFIG_EXTS:
        return False
    return True


READ_TRACKING_TOOLS: FrozenSet[str] = frozenset(
    {
        "read_file",
        "code_intel",
        "code_outline",
        "get_symbols_overview",
        "find_symbol",
    }
)

_EQUIVALENT_TOOL_FALLBACKS: Dict[str, Tuple[str, ...]] = {
    "patch_file": ("edit_file", "write_file"),
    "replace_lines": ("edit_file", "write_file"),
    "multi_patch": ("edit_file",),
    "replace_symbol_body": ("edit_file",),
    "insert_after_symbol": ("edit_file",),
    "rename_symbol": ("code_intel",),
    "edit_file": ("write_file",),
    "write_file": ("edit_file", "run_command"),
    "code_outline": ("code_intel", "read_file"),
    "get_symbols_overview": ("code_intel", "read_file"),
    "find_symbol": ("code_intel", "search_code", "read_file"),
    "find_referencing_symbols": ("code_intel", "search_code"),
    "code_intel": ("read_file",),
    "list_dir": ("find_files",),
    "repo_map": ("code_intel", "find_files"),
    "find_files": ("search_code",),
    "undo_edit": ("manage_files",),
    "trash_file": ("manage_files",),
    "restore_trash": ("manage_files",),
    "undo_or_trash": ("manage_files",),
    "manage_files": ("edit_file", "write_file"),
    "run_python": ("run_command",),
    "skill_search": ("skill_hub",),
    "skill_load": ("skill_hub",),
    "skill_register": ("skill_manage",),
    "desktop_window": ("cua_window",),
}

_GUARD_PREFIX_RE = re.compile(
    r"\[(?:GUARD|LOCALPC)(?:\s+[A-Z0-9_-]+)*\]",
    re.IGNORECASE,
)

_TIER_BLOCK_RE = re.compile(
    r"\[(?:GUARD\s+TIER\s+POLICY|LOCALPC\s+PERMISSION\s+TIER\s+BLOCKED)\]",
    re.IGNORECASE,
)

_TEST_COMMAND_RE = re.compile(
    r"(?:^|[\s;&|])(?:pytest|py\.test|python(?:3|\.\d+)?\s+-m\s+(?:pytest|unittest)|cargo\s+test|go\s+test|npm\s+test|pnpm\s+test|yarn\s+test|npx\s+(?:vitest|jest)|vitest|jest)\b",
    re.IGNORECASE,
)

VERIFICATION_DIRTY_MESSAGE = (
    "Workspace files were modified since the last passing verification/test run; "
    "run tests or syntax/runtime verification before concluding."
)


def is_verification_command(cmd: str) -> bool:
    s = (cmd or "").strip()
    if not s or re.search(r"\s(?:--version|--help|-h)\s*$", s):
        return False
    return bool(_TEST_COMMAND_RE.search(s))


def strip_tool_prefix(tool_name: str, prefix: str = "pc") -> str:
    clean = (tool_name or "").strip()
    if clean in ALL_CORE_BASE_TOOLS:
        return clean
    for pref in (prefix, "pc", "pc2", "pc3", "server", "vps", "pad"):
        if pref and clean.startswith(f"{pref}_"):
            cand = clean[len(pref) + 1 :]
            if cand in ALL_CORE_BASE_TOOLS:
                return cand
    return clean


def sanitize_ghost_tool_mentions(
    text: str,
    exposed_base_tools: Optional[Iterable[str]],
    *,
    prefix: str = "pc",
) -> str:
    """Ensure sideband hints, guard messages, and loop warnings never mention unexposed tools."""
    if not text or exposed_base_tools is None:
        return text
    active_bases: Set[str] = {strip_tool_prefix(str(t), prefix=prefix) for t in exposed_base_tools if t}
    if not active_bases:
        return text

    eff_pref = (prefix or "").strip().rstrip("_")

    def _fmt_tool(base: str) -> str:
        return f"{eff_pref}_{base}" if eff_pref else base

    def _pick_replacement(base: str) -> str:
        if base in active_bases:
            return _fmt_tool(base)
        for cand in _EQUIVALENT_TOOL_FALLBACKS.get(base, ()):
            if cand in active_bases:
                return _fmt_tool(cand)
        if "read_file" in active_bases:
            return _fmt_tool("read_file")
        return "an active workspace tool"

    sorted_bases = sorted(ALL_CORE_BASE_TOOLS, key=len, reverse=True)
    joined = "|".join(re.escape(b) for b in sorted_bases)
    known_prefixes: Set[str] = {
        p
        for p in (eff_pref.lower(), "pc", "pc1", "pc2", "pc3", "desk", "laptop", "server", "vps", "pad", "cosmos", "localpc")
        if p
    }
    tok_re = re.compile(rf"\b(?:([A-Za-z][A-Za-z0-9]*)_)?({joined})\b")

    def _replace_match(m: re.Match[str]) -> str:
        s_idx, e_idx = m.start(), m.end()
        if s_idx > 0 and e_idx < len(text):
            q_before, q_after = text[s_idx - 1], text[e_idx]
            if (q_before == "'" and q_after == "'") or (q_before == '"' and q_after == '"'):
                return m.group(0)
        had_pref = m.group(1)
        base = m.group(2)
        followed_by_call = bool(re.match(r"^\s*\(", text[e_idx:]))
        if had_pref:
            if had_pref.lower() not in known_prefixes:
                return m.group(0)
            if base in active_bases:
                return _fmt_tool(base)
            return _pick_replacement(base)
        if not followed_by_call:
            return m.group(0)
        if base in active_bases:
            return _fmt_tool(base)
        return _pick_replacement(base)

    rewritten = tok_re.sub(_replace_match, text)
    dedup_slash_re = re.compile(r"\b([A-Za-z0-9_]+)\s*/\s*\1\b")
    while dedup_slash_re.search(rewritten):
        rewritten = dedup_slash_re.sub(r"\1", rewritten)
    return rewritten


def recognize_error_diagnostics(
    payload: Dict[str, Any],
    *,
    target_path: str = "",
    exc: Optional[BaseException] = None,
    prefix: str = "pc",
    exposed_base_tools: Optional[Iterable[str]] = None,
    for_write: bool = False,
) -> Dict[str, Any]:
    """Unify `[GUARD ...]` and `[LOCALPC ...]` guardrail error classification and Office lock diagnostics.

    Read-only operations (`for_write=False` or already-succeeded `ok=True` with `exc is None`) NEVER
    overwrite `ok` to `False` when an Office `~$` temp lock file exists; they keep `ok=True` and only
    attach a lightweight `readonly_lock_notice`.
    """
    out = dict(payload)
    err_str = str(out.get("error") or out.get("stderr") or (str(exc) if exc is not None else "")).strip()
    already_succeeded = (out.get("ok") is True) and (exc is None) and not err_str

    # 1) Office / external process file lock check
    if target_path and not out.get("file_locked_by_external_app"):
        try:
            tp = Path(target_path)
            if not for_write or already_succeeded:
                if exc is None and out.get("ok", True) is not False:
                    lock_temp = find_office_temp_lock_file(tp)
                    if lock_temp is not None and "readonly_lock_notice" not in out:
                        out["readonly_lock_notice"] = (
                            f"提示：`{tp.name}` 当前已在 Excel / WPS / Office 中打开（检测到 `{lock_temp.name}`），"
                            "本次只读读取正常完成；后续如需写入修改请先保存并关闭该文件。"
                        )
                elif exc is not None:
                    lk_ro = check_office_or_os_file_lock(tp, exc=exc, for_write=False)
                    if lk_ro is not None:
                        out.update(lk_ro)
                        err_str = str(out.get("error") or err_str)
            else:
                lk_info = check_office_or_os_file_lock(tp, exc=exc, for_write=True)
                if lk_info is None and (
                    "正被 Excel" in err_str
                    or "WPS" in err_str
                    or ("Office" in err_str and "占用" in err_str)
                    or "being used by another process" in err_str.lower()
                    or "sharing violation" in err_str.lower()
                    or "另一个程序正在使用" in err_str
                ):
                    alt_p = tp.with_name(f"{tp.stem}_更新版{tp.suffix}")
                    lk_info = {
                        "ok": False,
                        "file_locked_by_external_app": True,
                        "path": str(tp),
                        "suggested_save_as": str(alt_p),
                        "error": (
                            f"文件 `{tp.name}` 当前正被 Excel / WPS / Office 等外部程序打开占用，已中止写入以保护未保存内容。"
                            f"请先保存并关闭 `{tp.name}` 后重试，或另存为 `{alt_p.name}`。"
                        ),
                        "hint": f"File `{tp.name}` is locked by an external Office/WPS process; close it or write to `{alt_p}`.",
                    }
                if lk_info is not None:
                    out.update(lk_info)
                    out.setdefault("error_code", "ERR_OFFICE_FILE_LOCKED")
                    err_str = str(out.get("error") or err_str)
        except Exception:
            pass
    elif out.get("file_locked_by_external_app"):
        out.setdefault("error_code", "ERR_OFFICE_FILE_LOCKED")

    # 2) Unified `[GUARD ...]` and `[LOCALPC ...]` prefix recognition
    if err_str and _GUARD_PREFIX_RE.search(err_str):
        out["blocked_by_guardrail"] = True
        if _TIER_BLOCK_RE.search(err_str):
            out["blocked_by_permission_tier"] = True
        if "hint" not in out:
            if out.get("blocked_by_permission_tier"):
                out["hint"] = "Operation requires a higher permission tier; stick to read-only inspection tools in L1."
            elif "SANDBOX" in err_str.upper():
                raw_h = f"Target is outside allowed workspace roots; inspect allowed paths via {prefix}_get_status or {prefix}_find_files."
                out["hint"] = sanitize_ghost_tool_mentions(raw_h, exposed_base_tools, prefix=prefix)
            else:
                out["hint"] = "Blocked by host security guardrail; do not retry the same restricted path or command."

    # 3) Scrub any ghost tool references across `error` and `hint`
    if exposed_base_tools is not None:
        for field_k in ("error", "hint"):
            if isinstance(out.get(field_k), str) and out[field_k]:
                out[field_k] = sanitize_ghost_tool_mentions(out[field_k], exposed_base_tools, prefix=prefix)

    return out


def _summarize_skills_for_status(
    *,
    workspace_roots: Sequence[Union[str, Path]],
    state_root: Optional[Union[str, Path]] = None,
    policy: Optional[Any] = None,
    scan_host_global_skills: Optional[bool] = None,
) -> Dict[str, Any]:
    """Scan workspace `.agents/skills`, built-in `host_skills`, `skills_store`, and optional host roots for `get_status`."""
    try:
        from cosmos_mcp.capabilities.skills.models import SkillsConfig
        from cosmos_mcp.capabilities.skills.parser_and_index import scan_local_skills

        explicit_auto: Optional[bool]
        if scan_host_global_skills is not None:
            explicit_auto = bool(scan_host_global_skills)
        elif policy is not None:
            explicit_auto = None
        else:
            explicit_auto = False

        cfg = SkillsConfig(
            workspace_roots=list(workspace_roots),
            state_root=state_root,
            auto_discover_host_roots=explicit_auto,
            policy=policy,
        )
        records = scan_local_skills(cfg, include_disabled=False)
        ws_skills = [
            {"name": r.name, "description": r.description}
            for r in records
            if r.source_scope in ("workspace", "workspace_claude", "project")
        ]
        host_cnt = sum(
            1
            for r in records
            if r.source_scope not in ("managed", "workspace", "workspace_claude", "project", "antigravity_builtin")
        )
        managed_cnt = len(records)
        return {
            "workspace_skills": ws_skills,
            "workspace_skill_count": len(ws_skills),
            "managed_skill_count": managed_cnt,
            "host_skill_count": host_cnt,
            "scan_host_global_skills": bool(cfg.auto_discover_host_roots),
        }
    except Exception:
        return {
            "workspace_skills": [],
            "workspace_skill_count": 0,
            "managed_skill_count": 0,
            "host_skill_count": 0,
            "scan_host_global_skills": bool(
                scan_host_global_skills
                if scan_host_global_skills is not None
                else getattr(policy, "scan_host_global_skills", False)
            ),
        }


class SessionSidebandTracker(ExecutionHook):
    """Stateful `ExecutionHook` tracking per-session file reads, 300s peer MVCC writes, and loop guards."""

    def __init__(
        self,
        guard: Optional[WorkspaceGuard] = None,
        *,
        policy_getter: Optional[Callable[[], Dict[str, Any]]] = None,
        policy: Optional[Any] = None,
        enforce_unread_overwrite: bool = True,
    ) -> None:
        self._guard = guard
        self._policy_getter = policy_getter
        self._policy = policy
        self._enforce_unread_overwrite = bool(enforce_unread_overwrite)
        self._lock = threading.Lock()
        self._session_known_files: Dict[str, Set[str]] = {}
        self._read_timestamps: Dict[Tuple[str, str], float] = {}
        self._file_last_write: Dict[str, Dict[str, Any]] = {}
        self._mutation_log: List[Dict[str, Any]] = []
        self._peer_cursor: Dict[str, int] = {}
        self._error_streaks: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._dirty_since_last_test: Dict[str, bool] = {}

    @staticmethod
    def resolve_session_key(caller: str = "", session_hint: str = "") -> str:
        c = (caller or "").strip()
        if c:
            return f"caller:{c}"
        s = (session_hint or "").strip()
        if s:
            return f"sess:{s}"
        return "sess:default"

    @staticmethod
    def _norm_path(path_str: str) -> str:
        if not path_str:
            return ""
        try:
            return os.path.normcase(str(Path(path_str).expanduser().resolve()))
        except Exception:
            return os.path.normcase(str(path_str))

    def _active_policy_snapshot(self, ctx: Optional[ToolCallContext] = None) -> Tuple[str, Optional[Set[str]], str]:
        prefix = ctx.prefix if (ctx is not None and ctx.prefix) else (self._guard.tool_prefix if self._guard else "pc")
        exposed: Optional[Set[str]] = None
        profile = "standard"
        if self._policy_getter is not None:
            try:
                pol = self._policy_getter() or {}
                if isinstance(pol, dict):
                    if pol.get("prefix"):
                        prefix = str(pol["prefix"])
                    if pol.get("toolset_profile"):
                        profile = str(pol["toolset_profile"])
                    raw_exp = pol.get("exposed_tools")
                    if raw_exp is not None:
                        exposed = {strip_tool_prefix(str(x), prefix=prefix) for x in raw_exp if x}
            except Exception:
                pass
        return prefix, exposed, profile

    def record_read(self, session_key: str, caller: str, path_str: str) -> None:
        np = self._norm_path(path_str)
        if not np:
            return
        now = time.time()
        eff_c = (caller or "").strip()
        with self._lock:
            self._session_known_files.setdefault(session_key, set()).add(np)
            self._read_timestamps[(session_key, np)] = now
            if eff_c:
                self._session_known_files.setdefault(f"caller:{eff_c}", set()).add(np)
                self._read_timestamps[(f"caller:{eff_c}", np)] = now

    def record_write(
        self,
        session_key: str,
        caller: str,
        path_str: str,
        tool_name: str,
        sha256_prefix: str = "",
        *,
        mark_verification_dirty: Optional[bool] = None,
    ) -> None:
        np = self._norm_path(path_str)
        if not np:
            return
        now = time.time()
        eff_c = (caller or "").strip()
        should_mark_dirty = (
            _is_code_file_requiring_verification(path_str)
            if mark_verification_dirty is None
            else bool(mark_verification_dirty)
        )
        with self._lock:
            self._session_known_files.setdefault(session_key, set()).add(np)
            self._read_timestamps[(session_key, np)] = now
            if should_mark_dirty:
                self._dirty_since_last_test[session_key] = True
            if eff_c:
                ck = f"caller:{eff_c}"
                self._session_known_files.setdefault(ck, set()).add(np)
                self._read_timestamps[(ck, np)] = now
                if should_mark_dirty:
                    self._dirty_since_last_test[ck] = True
            rec = {
                "path": path_str,
                "norm_path": np,
                "caller": eff_c,
                "session_key": session_key,
                "tool": tool_name,
                "sha256_prefix": (sha256_prefix or "")[:12],
                "ts": now,
            }
            self._file_last_write[np] = rec
            self._mutation_log.append(rec)
            if len(self._mutation_log) > 400:
                trim = len(self._mutation_log) - 300
                del self._mutation_log[:trim]
                for k in list(self._peer_cursor.keys()):
                    self._peer_cursor[k] = max(0, self._peer_cursor[k] - trim)

    def record_test_pass(self, session_key: str, caller: str = "") -> None:
        eff_c = (caller or "").strip()
        with self._lock:
            self._dirty_since_last_test[session_key] = False
            if eff_c:
                self._dirty_since_last_test[f"caller:{eff_c}"] = False

    def check_write_guards(
        self,
        *,
        session_key: str,
        caller: str,
        path_str: str,
        existed_before: bool,
        mode: str = "overwrite",
        overwrite: bool = True,
        allow_shrink: bool = False,
        overwrite_unread: bool = False,
        strict_unread_guard: bool = False,
        expected_sha256: str = "",
        prefix: str = "pc",
        exposed_tools: Optional[Iterable[str]] = None,
        toolset_profile: str = "standard",
    ) -> Optional[Dict[str, Any]]:
        if not existed_before:
            return None
        np = self._norm_path(path_str)
        eff_c = (caller or "").strip()

        if mode == "overwrite" and not overwrite:
            raw_msg = (
                f"[OVERWRITE BLOCKED]: `{Path(path_str).name}` already exists and overwrite=False. "
                f"Use {prefix}_edit_file for surgical changes or pass mode='overwrite'."
            )
            return {
                "ok": False,
                "overwrite_blocked": True,
                "path": path_str,
                "error": sanitize_ghost_tool_mentions(raw_msg, exposed_tools, prefix=prefix),
            }

        now = time.time()
        with self._lock:
            last_w = self._file_last_write.get(np)
            if last_w and not (expected_sha256 or "").strip():
                prev_c = str(last_w.get("caller") or "").strip()
                age = now - float(last_w.get("ts") or 0.0)
                if prev_c and eff_c and prev_c != eff_c and 0.0 <= age <= MVCC_WINDOW_SEC:
                    last_r = max(
                        self._read_timestamps.get((session_key, np), 0.0),
                        self._read_timestamps.get((f"caller:{eff_c}", np), 0.0),
                    )
                    if last_r < float(last_w["ts"]):
                        raw_mvcc = (
                            f"[MVCC PEER CONFLICT]: `{Path(path_str).name}` was modified {age:.1f}s ago by peer "
                            f"`{prev_c}` (sha256={last_w.get('sha256_prefix', '')}). Read latest lines via "
                            f"{prefix}_read_file or pass expected_sha256."
                        )
                        return {
                            "ok": False,
                            "mvcc_peer_conflict": True,
                            "peer_caller": prev_c,
                            "peer_sha256_prefix": last_w.get("sha256_prefix", ""),
                            "path": path_str,
                            "error": sanitize_ghost_tool_mentions(raw_mvcc, exposed_tools, prefix=prefix),
                        }

            prof_low = (toolset_profile or "").strip().lower()
            is_unrestricted_profile = prof_low == "all"
            if (
                strict_unread_guard
                and self._enforce_unread_overwrite
                and not is_unrestricted_profile
                and mode == "overwrite"
                and not (allow_shrink or overwrite_unread)
                and not (expected_sha256 or "").strip()
            ):
                known = np in self._session_known_files.get(session_key, set())
                if not known and eff_c:
                    known = (f"caller:{eff_c}", np) in self._read_timestamps
                if not known:
                    raw_unread = (
                        f"[UNREAD OVERWRITE GUARD]: `{Path(path_str).name}` already exists on disk and has not been "
                        f"read in this session. Read it first with {prefix}_read_file, use {prefix}_edit_file for "
                        f"targeted edits, or pass overwrite_unread=True / expected_sha256."
                    )
                    return {
                        "ok": False,
                        "unread_overwrite_blocked": True,
                        "path": path_str,
                        "error": sanitize_ghost_tool_mentions(raw_unread, exposed_tools, prefix=prefix),
                    }
        return None

    def before_call(self, ctx: ToolCallContext) -> Optional[Dict[str, Any]]:
        if ctx.base_name != "write_file":
            return None
        raw_path = str(ctx.arguments.get("path") or "").strip()
        if not raw_path:
            return None
        prefix, exposed, profile = self._active_policy_snapshot(ctx)
        session_key = self.resolve_session_key(ctx.caller, ctx.session_hint)

        target_p: Optional[Path] = None
        if self._guard is not None:
            try:
                target_p = self._guard.normalize_target_path(raw_path)
            except Exception:
                target_p = None
        if target_p is None:
            target_p = Path(raw_path).expanduser().resolve()

        existed_before = target_p.exists() and target_p.is_file()
        if not existed_before:
            return None

        mode = str(ctx.arguments.get("mode") or "overwrite").strip().lower()
        disallow_ov = bool(ctx.arguments.get("_legacy_disallow_overwrite", False)) or (ctx.arguments.get("overwrite") is False)
        allow_shrink = bool(ctx.arguments.get("allow_shrink", False))
        overwrite_unread = bool(ctx.arguments.get("overwrite_unread", False))
        strict_unread_guard = bool(ctx.arguments.get("strict_unread_guard", False))
        expected_sha = str(ctx.arguments.get("expected_sha256") or "")

        return self.check_write_guards(
            session_key=session_key,
            caller=ctx.caller,
            path_str=str(target_p),
            existed_before=existed_before,
            mode=mode,
            overwrite=(not disallow_ov),
            allow_shrink=allow_shrink,
            overwrite_unread=overwrite_unread,
            strict_unread_guard=strict_unread_guard,
            expected_sha256=expected_sha,
            prefix=prefix,
            exposed_tools=exposed,
            toolset_profile=profile,
        )

    def after_call(
        self,
        ctx: ToolCallContext,
        result: Any,
        error: Optional[BaseException],
        duration_ms: float,
    ) -> Any:
        _ = duration_ms
        prefix, exposed, _ = self._active_policy_snapshot(ctx)
        session_key = self.resolve_session_key(ctx.caller, ctx.session_hint)
        base = strip_tool_prefix(ctx.base_name, prefix=prefix)
        raw_target = str(
            ctx.arguments.get("path")
            or ctx.arguments.get("project_path")
            or ctx.arguments.get("cwd")
            or ""
        ).strip()

        act_arg = str(ctx.arguments.get("action") or "").strip().lower()
        is_write_op = (
            base in WRITE_MUTATION_TOOLS
            and act_arg != "list"
            and ctx.safety_band != SafetyBand.READONLY
            and not ctx.readonly_endpoint
        )

        # Handle multimodal list `[TextContent-dict, ImageContent-dict]` from `read_file` on images
        if isinstance(result, list) and base == "read_file" and error is None:
            if raw_target:
                self.record_read(session_key, ctx.caller, raw_target)
            with self._lock:
                self._error_streaks.pop((session_key, self._norm_path(raw_target) or base), None)
            return result

        if not isinstance(result, dict):
            if error is not None:
                err_dict = recognize_error_diagnostics(
                    {"ok": False, "error": f"{type(error).__name__}: {error}"},
                    target_path=raw_target,
                    exc=error,
                    prefix=prefix,
                    exposed_base_tools=exposed,
                    for_write=is_write_op,
                )
                return self._track_streak_and_sidebands(
                    ctx, session_key, base, raw_target, err_dict, prefix, exposed
                )
            return result

        enriched = recognize_error_diagnostics(
            result,
            target_path=str(result.get("path") or result.get("failed_path") or raw_target),
            exc=error,
            prefix=prefix,
            exposed_base_tools=exposed,
            for_write=is_write_op,
        )
        is_ok = bool(enriched.get("ok", error is None)) and error is None

        resolved_path = str(enriched.get("path") or raw_target)
        touched_code_file = False
        if is_ok:
            if base == "get_status" and not str(ctx.arguments.get("job_id") or "").strip():
                pol_snap: Dict[str, Any] = {}
                if self._policy_getter is not None:
                    try:
                        pol_snap = dict(self._policy_getter() or {})
                    except Exception:
                        pol_snap = {}
                ws_roots_snap = (
                    pol_snap.get("workspace_roots")
                    or enriched.get("workspace_roots")
                    or ([str(p) for p in self._guard.workspace_roots] if self._guard is not None else [])
                )
                st_root_snap = pol_snap.get("state_root") or (
                    str(self._guard.effective_state_root()) if self._guard is not None else None
                )
                eff_pol_obj = self._policy or getattr(self._guard, "policy", None)
                scan_flag_snap: Optional[bool] = (
                    bool(pol_snap["scan_host_global_skills"])
                    if "scan_host_global_skills" in pol_snap
                    else (bool(getattr(eff_pol_obj, "scan_host_global_skills", False)) if eff_pol_obj is not None else None)
                )
                enriched.update(
                    _summarize_skills_for_status(
                        workspace_roots=ws_roots_snap,
                        state_root=st_root_snap,
                        policy=eff_pol_obj,
                        scan_host_global_skills=scan_flag_snap,
                    )
                )

            if base == "write_file" and resolved_path:
                eff_mode = str(enriched.get("mode") or ctx.arguments.get("mode") or "overwrite").strip().lower()
                eff_c = (ctx.caller or "").strip()
                np_w = self._norm_path(resolved_path)
                with self._lock:
                    was_known = np_w in self._session_known_files.get(session_key, set())
                    if not was_known and eff_c:
                        was_known = (f"caller:{eff_c}", np_w) in self._read_timestamps
                undo_cmd = sanitize_ghost_tool_mentions(
                    f"{prefix}_manage_files(action='undo', path='{resolved_path}')",
                    exposed,
                    prefix=prefix,
                )
                if enriched.get("shrink_warning"):
                    enriched["undo_hint"] = undo_cmd
                    if isinstance(enriched.get("warning"), str):
                        enriched["warning"] = sanitize_ghost_tool_mentions(enriched["warning"], exposed, prefix=prefix)
                if (
                    self._enforce_unread_overwrite
                    and bool(enriched.get("existed_before"))
                    and eff_mode == "overwrite"
                    and not was_known
                    and not bool(ctx.arguments.get("overwrite_unread", False))
                    and not str(ctx.arguments.get("expected_sha256") or "").strip()
                ):
                    unread_msg = sanitize_ghost_tool_mentions(
                        f"Overwrote existing file `{Path(resolved_path).name}` without reading it first in this session; "
                        f"pre-edit backup snapshot was saved and can be restored anytime via {undo_cmd}.",
                        exposed,
                        prefix=prefix,
                    )
                    enriched["unread_overwrite_warning"] = True
                    enriched["undo_hint"] = undo_cmd
                    prev_warn = str(enriched.get("warning") or "").strip()
                    enriched["warning"] = f"{prev_warn} {unread_msg}".strip() if prev_warn else unread_msg

            if base in READ_TRACKING_TOOLS and resolved_path:
                self.record_read(session_key, ctx.caller, resolved_path)
            elif base in WRITE_MUTATION_TOOLS and not enriched.get("dry_run") and enriched.get("action") not in ("list", "mkdir") and act_arg != "mkdir":
                if isinstance(enriched.get("changes"), list):
                    for ch in enriched["changes"]:
                        if isinstance(ch, dict) and ch.get("path"):
                            p_ch = str(ch["path"])
                            is_code_ch = _is_code_file_requiring_verification(p_ch)
                            touched_code_file = touched_code_file or is_code_ch
                            self.record_write(
                                session_key,
                                ctx.caller,
                                p_ch,
                                ctx.resolved_name,
                                str(ch.get("sha256") or ""),
                                mark_verification_dirty=is_code_ch,
                            )
                elif isinstance(enriched.get("results"), list):
                    for r_it in enriched["results"]:
                        if isinstance(r_it, dict) and r_it.get("path"):
                            p_it = str(r_it["path"])
                            is_code_it = _is_code_file_requiring_verification(p_it)
                            touched_code_file = touched_code_file or is_code_it
                            self.record_write(
                                session_key,
                                ctx.caller,
                                p_it,
                                ctx.resolved_name,
                                str(r_it.get("sha256") or ""),
                                mark_verification_dirty=is_code_it,
                            )
                elif resolved_path:
                    target_for_code_chk = str(enriched.get("destination") or resolved_path)
                    is_code_p = _is_code_file_requiring_verification(target_for_code_chk)
                    touched_code_file = is_code_p
                    self.record_write(
                        session_key,
                        ctx.caller,
                        target_for_code_chk,
                        ctx.resolved_name,
                        str(enriched.get("sha256") or ""),
                        mark_verification_dirty=is_code_p,
                    )
            elif base == "run_command" and int(enriched.get("exit_code", 0) or 0) == 0:
                if is_verification_command(str(ctx.arguments.get("command") or "")):
                    self.record_test_pass(session_key, ctx.caller)
            elif base == "run_python" and int(enriched.get("exit_code", 0) or 0) == 0:
                code_s = str(ctx.arguments.get("code") or "")
                if "pytest" in code_s or "unittest" in code_s or "assert " in code_s:
                    self.record_test_pass(session_key, ctx.caller)

        return self._track_streak_and_sidebands(
            ctx,
            session_key,
            base,
            resolved_path,
            enriched,
            prefix,
            exposed,
            touched_code_file=touched_code_file,
        )

    def _track_streak_and_sidebands(
        self,
        ctx: ToolCallContext,
        session_key: str,
        base: str,
        resolved_path: str,
        payload: Dict[str, Any],
        prefix: str,
        exposed: Optional[Set[str]],
        *,
        touched_code_file: bool = False,
    ) -> Dict[str, Any]:
        out = dict(payload)
        is_ok = bool(out.get("ok", True))
        act_now = str(out.get("action") or ctx.arguments.get("action") or "").strip().lower()
        is_bg_kill_or_query = (
            (base == "bg_command" and act_now in ("kill", "status", "list"))
            or bool(out.get("killed"))
            or str(out.get("status") or "").strip().lower() == "killed"
        )
        if (
            "exit_code" in out
            and out.get("exit_code") not in (0, None)
            and not out.get("promoted_to_background")
            and not (is_bg_kill_or_query and out.get("ok", True) is not False)
        ):
            is_ok = False

        target_key = self._norm_path(resolved_path) or base
        target_label = Path(resolved_path).name if (resolved_path and Path(resolved_path).name) else base
        args_fp = hashlib.sha256(
            json.dumps({k: v for k, v in sorted(ctx.arguments.items()) if k != "caller"}, default=str, ensure_ascii=False).encode("utf-8")
        ).hexdigest()[:16]

        loop_warn = ""
        peer_items: List[Dict[str, Any]] = []
        attach_dirty = False
        eff_c = (ctx.caller or "").strip()

        with self._lock:
            streak_k = (session_key, target_key)
            if not is_ok:
                prev = self._error_streaks.get(streak_k, {"count": 0, "identical_count": 0, "last_fp": ""})
                new_cnt = int(prev.get("count", 0)) + 1
                same_args = bool(prev.get("last_fp") == args_fp)
                ident_cnt = (int(prev.get("identical_count", 1)) + 1) if same_args else 1
                self._error_streaks[streak_k] = {
                    "count": new_cnt,
                    "identical_count": ident_cnt,
                    "last_fp": args_fp,
                }
                if same_args and ident_cnt >= 2:
                    raw_w = (
                        f"[LOOP GUARD ({ident_cnt} identical failed calls on {target_label})]: "
                        f"Stop retrying identical arguments. Inspect actual disk state with "
                        f"{prefix}_read_file / {prefix}_code_intel or check path via {prefix}_find_files."
                    )
                    loop_warn = sanitize_ghost_tool_mentions(raw_w, exposed, prefix=prefix)
                elif new_cnt >= 2:
                    raw_w = (
                        f"[RETRY HINT ({new_cnt} consecutive errors on {target_label})]: "
                        f"Follow `hint` above or inspect current file lines with {prefix}_read_file / {prefix}_code_intel."
                    )
                    loop_warn = sanitize_ghost_tool_mentions(raw_w, exposed, prefix=prefix)
            else:
                self._error_streaks.pop(streak_k, None)

            if (
                is_ok
                and touched_code_file
                and base in WRITE_MUTATION_TOOLS
                and not out.get("dry_run")
                and act_now not in ("list", "mkdir")
            ):
                attach_dirty = bool(
                    self._dirty_since_last_test.get(session_key, False)
                    or (eff_c and self._dirty_since_last_test.get(f"caller:{eff_c}", False))
                )

            cur_idx = self._peer_cursor.get(session_key, len(self._mutation_log))
            if cur_idx < len(self._mutation_log):
                seen_p: Set[str] = set()
                for item in reversed(self._mutation_log[cur_idx:]):
                    it_c = str(item.get("caller") or "")
                    it_s = str(item.get("session_key") or "")
                    if (eff_c and it_c and it_c != eff_c) or (not eff_c and it_s != session_key):
                        np_i = str(item.get("norm_path") or "")
                        if np_i and np_i not in seen_p:
                            seen_p.add(np_i)
                            peer_items.append(
                                {
                                    "path": item["path"],
                                    "caller": it_c or it_s,
                                    "tool": item["tool"],
                                    "sha256_prefix": item["sha256_prefix"],
                                }
                            )
                peer_items.reverse()
                self._peer_cursor[session_key] = len(self._mutation_log)

        if attach_dirty:
            out["verification_state"] = VERIFICATION_DIRTY_MESSAGE
        if peer_items:
            out["_peer_updates"] = peer_items[:10]
        if loop_warn:
            out["_loop_guard_warning"] = loop_warn
        return out
