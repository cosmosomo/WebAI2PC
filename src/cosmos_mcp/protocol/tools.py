from __future__ import annotations

"""Declarative `ToolSpec` & `ExecutionHook` builder for the 16 default core tools and registered capabilities.

Locks the default core toolset to the canonical 16-item surface:
`("get_status", "find_files", "search_code", "code_intel", "read_file", "edit_file",
  "write_file", "manage_files", "run_command", "run_python", "bg_command", "batch_probe",
  "web_research", "workspace_memory", "skill_hub", "skill_manage")`
and appends any static tools provided by `cosmos_mcp.capabilities.load_registered_providers()`.
"""

import asyncio
import contextvars
import importlib
import inspect
from pathlib import Path
import re
import shutil
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from cosmos_mcp.capabilities import load_registered_providers
from cosmos_mcp.core import (
    code as ast_intel,
    exec as exec_ops,
    fs as file_ops,
    memory as workspace_memory,
    patch as patch_ops,
    search_nav,
    web as web_research,
)
from cosmos_mcp.core.config import DEFAULT_CORE_TOOLS, normalize_tier as normalize_tier_full
from cosmos_mcp.core.contracts import ExecutionHook, SafetyBand, ToolSpec
from cosmos_mcp.core.fs_io import encode_with_detected_encoding
from cosmos_mcp.core.guard import WorkspaceGuard, normalize_tier
from cosmos_mcp.core.path_heal import is_link_or_junction
from cosmos_mcp.core.proc import ProcessManager
from cosmos_mcp.protocol.ergonomics import SessionSidebandTracker

CORE_TOOLSET_PROFILES: Dict[str, Tuple[str, ...]] = {
    "standard": DEFAULT_CORE_TOOLS,
    "full": DEFAULT_CORE_TOOLS,
    "minimal": (
        "get_status",
        "find_files",
        "search_code",
        "read_file",
        "edit_file",
        "run_command",
        "bg_command",
    ),
    "symbol": DEFAULT_CORE_TOOLS,
    "hybrid": (
        "get_status",
        "find_files",
        "search_code",
        "code_intel",
        "read_file",
        "edit_file",
        "write_file",
        "manage_files",
        "run_command",
        "bg_command",
        "web_research",
    ),
}

_PROFILE_ALIASES: Dict[str, str] = {
    "standard": "standard",
    "default": "standard",
    "recommended": "standard",
    "core": "standard",
    "core_12": "standard",
    "core_16": "standard",
    "full": "full",
    "all": "all",
    "minimal": "minimal",
    "lean": "minimal",
    "compact": "minimal",
    "symbol": "symbol",
    "hybrid": "hybrid",
}

MANAGE_FILES_ACTIONS: Tuple[str, ...] = (
    "mkdir",
    "move",
    "rename",
    "copy",
    "trash",
    "restore",
    "undo",
    "redo",
    "list",
)

SKILL_HUB_FALLBACK_ACTIONS: Tuple[str, ...] = (
    "search",
    "load",
    "read_file",
    "market_search",
    "vet",
)

SKILL_MANAGE_FALLBACK_ACTIONS: Tuple[str, ...] = (
    "list",
    "create",
    "install",
    "sync",
    "enable",
    "disable",
    "trash",
    "trash_list",
    "restore",
)


def normalize_core_toolset_profile(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return ""
    mapped = _PROFILE_ALIASES.get(s.lower(), s)
    if mapped in CORE_TOOLSET_PROFILES or mapped == "all":
        return mapped
    raise ValueError(
        f"Unknown core toolset profile `{raw}` (expected standard, full, minimal, symbol, hybrid, or all)."
    )


def filter_core_tools_by_profile(specs: Sequence[ToolSpec], profile: str) -> List[ToolSpec]:
    norm = normalize_core_toolset_profile(profile)
    if not norm or norm == "all":
        return list(specs)
    by_name = {sp.base_name: sp for sp in specs}
    ordered_names = CORE_TOOLSET_PROFILES[norm]
    selected = [by_name[nm] for nm in ordered_names if nm in by_name]
    core_known = set(DEFAULT_CORE_TOOLS)
    for sp in specs:
        if sp.base_name not in core_known and sp not in selected:
            selected.append(sp)
    return selected


def _prop(ptype: str, desc: str = "", **extra: Any) -> Dict[str, Any]:
    d: Dict[str, Any] = {"type": ptype}
    if desc:
        d["description"] = desc
    d.update(extra)
    return d


def _obj_schema(props: Dict[str, Any], required: Sequence[str] = ()) -> Dict[str, Any]:
    merged_props: Dict[str, Any] = dict(props)
    if "target" not in merged_props:
        merged_props["target"] = _prop(
            "string",
            "Target node ('auto' routes by path, or 'local'/'server'/PC alias)",
            default="auto",
        )
    merged_props["caller"] = _prop("string", "Session caller tag", default="")
    s: Dict[str, Any] = {
        "type": "object",
        "properties": merged_props,
    }
    if required:
        s["required"] = list(required)
    return s


def _accepts_kwarg(fn: Callable[..., Any], kw_name: str) -> bool:
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return False
    for p in sig.parameters.values():
        if p.kind == inspect.Parameter.VAR_KEYWORD:
            return True
    return kw_name in sig.parameters


def _filter_accepted_kwargs(fn: Callable[..., Any], kwargs: Dict[str, Any]) -> Dict[str, Any]:
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return kwargs
    for p in sig.parameters.values():
        if p.kind == inspect.Parameter.VAR_KEYWORD:
            return kwargs
    allowed = {
        k
        for k, p in sig.parameters.items()
        if p.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
    }
    return {k: v for k, v in kwargs.items() if k in allowed}


def _ensure_first_sentence_no_internal_dots(desc: str) -> str:
    """Guarantee zero premature `.` inside the opening summary sentence so Gemini `expand_tools` never truncates."""
    s = (desc or "").strip()
    if not s:
        return s
    # Split at real sentence end (`.` followed by whitespace or EOS), sanitize internal dots in sentence 1
    m_end = re.search(r"\.(?:\s|$)", s)
    if m_end is None:
        return s.replace("SKILL.md", "SKILL markdown").replace("skills.sh", "skills-sh").replace("..", " to ") + "."
    # Find the actual end of the first sentence (skipping common inline file/domain tokens like SKILL.md, skills.sh, .docx)
    cleaned = (
        s.replace("SKILL.md", "SKILL markdown")
        .replace("skills.sh", "skills-sh")
        .replace(".undo_history", "undo/trash vault")
        .replace(".mcp_bak", "undo/trash vault")
        .replace("edits=[...]", "edits list")
        .replace("[...]", "list")
        .replace("0..25s", "0 to 25s")
    )
    cleaned = re.sub(r"(?<!\w)\.(docx|xlsx|pptx|pdf|ipynb)\b", r"\1", cleaned, flags=re.IGNORECASE)
    return cleaned


_EDIT_CHUNK_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "path": _prop("string"),
        "old_text": _prop("string"),
        "new_text": _prop("string", default=""),
        "start_line": _prop("integer"),
        "end_line": _prop("integer"),
        "symbol": _prop("string"),
        "replace_all": _prop("boolean"),
        "expected_sha256": _prop("string"),
    },
}


class _SkillPolicyProxy:
    """Live policy adapter satisfying both `LiveRuntimePolicy` attributes and dict-style `.get()` for `build_skill_tool_specs(pol)`."""

    def __init__(self, guard: WorkspaceGuard, policy_getter: Callable[[], Dict[str, Any]]) -> None:
        self.guard = guard
        self._policy_getter = policy_getter

    def _snap(self) -> Dict[str, Any]:
        return self._policy_getter()

    def refresh(self, force: bool = False) -> Tuple[str, Dict[str, Any], str]:
        _ = force
        return self.tier_key, {}, self.workspace

    def get(self, key: str, default: Any = None) -> Any:
        return self._snap().get(key, default)

    @property
    def state_root(self) -> Path:
        sr = self._snap().get("state_root")
        return Path(str(sr)).expanduser().resolve() if sr else self.guard.effective_state_root()

    @property
    def workspace_roots(self) -> Tuple[Path, ...]:
        raw_r = self._snap().get("workspace_roots")
        if isinstance(raw_r, (list, tuple)) and raw_r:
            return tuple(Path(str(x)).expanduser().resolve() for x in raw_r)
        if self.guard.workspace_roots:
            return tuple(self.guard.workspace_roots)
        return (Path.cwd().resolve(),)

    @property
    def primary_workspace(self) -> Path:
        return self.workspace_roots[0]

    @property
    def workspace(self) -> str:
        return str(self.primary_workspace)

    @property
    def eff_prefix(self) -> str:
        return str(self._snap().get("prefix") or self.guard.tool_prefix or "pc")

    @property
    def tier_key(self) -> str:
        return normalize_tier_full(str(self._snap().get("tier") or self.guard.tier))

    @property
    def short_tier_code(self) -> str:
        return normalize_tier(self.tier_key)

    @property
    def restrict_to_workspace(self) -> bool:
        return self.short_tier_code != "L4"

    @property
    def allow_edit(self) -> bool:
        return self.short_tier_code in ("L2", "L3", "L4")

    @property
    def allow_exec(self) -> bool:
        return self.short_tier_code in ("L3", "L4")

    @property
    def allow_host_admin(self) -> bool:
        return self.short_tier_code == "L4"

    @property
    def scan_host_global_skills(self) -> bool:
        return bool(self._snap().get("scan_host_global_skills", False))


def _ensure_target_in_schema(raw_schema: Dict[str, Any]) -> Dict[str, Any]:
    schema = dict(raw_schema or {"type": "object", "properties": {}})
    props = dict(schema.get("properties") or {})
    if "target" not in props:
        props["target"] = _prop(
            "string",
            "Target node ('auto' routes by path, or 'local'/'server'/PC alias)",
            default="auto",
        )
        schema["properties"] = props
    return schema


def _try_load_real_skill_tool_specs(pol_obj: Any, guard: WorkspaceGuard) -> Optional[List[ToolSpec]]:
    """Lazily import `build_skill_tool_specs` from `cosmos_mcp.capabilities.skills` once available on disk."""
    mod_name = "cosmos_mcp.capabilities.skills"
    try:
        if mod_name in sys.modules and not hasattr(sys.modules[mod_name], "build_skill_tool_specs"):
            importlib.reload(sys.modules[mod_name])
        from cosmos_mcp.capabilities.skills import build_skill_tool_specs  # type: ignore[attr-defined]
    except (ImportError, AttributeError):
        return None

    try:
        sig = inspect.signature(build_skill_tool_specs)
        params = list(sig.parameters.values())
        if not params:
            raw_specs = build_skill_tool_specs()
        elif _accepts_kwarg(build_skill_tool_specs, "guard"):
            raw_specs = build_skill_tool_specs(pol_obj, guard=guard)
        else:
            raw_specs = build_skill_tool_specs(pol_obj)
    except TypeError:
        raw_specs = build_skill_tool_specs(pol_obj)

    if not raw_specs:
        return None

    normalized: List[ToolSpec] = []
    for sp in raw_specs:
        clean_desc = _ensure_first_sentence_no_internal_dots(getattr(sp, "description", ""))
        if isinstance(sp, ToolSpec):
            patched_schema = _ensure_target_in_schema(sp.input_schema)
            if clean_desc != sp.description or patched_schema != sp.input_schema:
                sp = ToolSpec(
                    base_name=sp.base_name,
                    handler=sp.handler,
                    safety_band=sp.safety_band,
                    input_schema=patched_schema,
                    title=sp.title,
                    description=clean_desc,
                    nudge_prefer=sp.nudge_prefer,
                    pack=sp.pack,
                    aliases=sp.aliases,
                    param_aliases=sp.param_aliases,
                    action_param=sp.action_param,
                    action_enum=sp.action_enum,
                    idempotent=sp.idempotent,
                    open_world=sp.open_world,
                    oauth_scope=sp.oauth_scope,
                )
            normalized.append(sp)
        else:
            band_raw = getattr(getattr(sp, "safety_band", None), "value", str(getattr(sp, "safety_band", "READONLY")))
            band = SafetyBand(band_raw) if band_raw in SafetyBand.__members__ else SafetyBand.READONLY
            normalized.append(
                ToolSpec(
                    base_name=str(sp.base_name),
                    handler=sp.handler,
                    safety_band=band,
                    input_schema=_ensure_target_in_schema(dict(getattr(sp, "input_schema", None) or {})),
                    title=str(getattr(sp, "title", "") or ""),
                    description=clean_desc,
                    aliases=tuple(getattr(sp, "aliases", ()) or ()),
                    param_aliases=dict(getattr(sp, "param_aliases", None) or {}),
                    action_param=str(getattr(sp, "action_param", "action") or "action"),
                    action_enum=tuple(getattr(sp, "action_enum", ()) or ()),
                    idempotent=bool(getattr(sp, "idempotent", False)),
                    open_world=bool(getattr(sp, "open_world", False)),
                    oauth_scope=str(getattr(sp, "oauth_scope", "") or ""),
                )
            )
    return normalized


def _fallback_manage_files_sync(
    *,
    action: str,
    path: str,
    destination: str,
    overwrite: bool,
    trash_id: str,
    reason: str,
    limit: int,
    guard: WorkspaceGuard,
) -> Dict[str, Any]:
    """Compatibility fallback when `file_ops.manage_files` is not yet merged, delegating `undo/redo/trash/restore/list` to `file_ops.undo_or_trash`."""
    act = (action or "list").strip().lower()
    if act in ("undo", "redo", "trash", "restore", "list"):
        eff_tid = trash_id or (destination if act == "restore" and not trash_id else "")
        return file_ops.undo_or_trash(
            action=act,
            path=path,
            trash_id=eff_tid,
            reason=reason,
            limit=limit,
            guard=guard,
        )

    if act == "mkdir":
        if not (path or "").strip():
            return {"ok": False, "action": "mkdir", "error": "`path` is required when action='mkdir'."}
        r_info = file_ops.heal_and_resolve_path(str(path), guard, mode="write", must_exist=False, tool_name="manage_files")
        if not r_info["ok"]:
            return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}
        fp: Path = r_info["path"]
        if is_link_or_junction(fp):
            return {"ok": False, "blocked_by_guardrail": True, "path": str(fp), "error": f"Refusing symlink or junction path: {fp}"}
        fp.mkdir(parents=True, exist_ok=True)
        return {"ok": True, "action": "mkdir", "path": str(fp)}

    if act in ("move", "rename", "copy"):
        if not (path or "").strip() or not (destination or "").strip():
            return {"ok": False, "action": act, "error": f"`path` and `destination` are required when action='{act}'."}
        src_mode = "read" if act == "copy" else "write"
        src_info = file_ops.heal_and_resolve_path(str(path), guard, mode=src_mode, must_exist=True, tool_name="manage_files")
        if not src_info["ok"]:
            return {k: (str(v) if isinstance(v, Path) else v) for k, v in src_info.items() if v is not None}
        src_p: Path = src_info["path"]
        if is_link_or_junction(src_p):
            return {"ok": False, "blocked_by_guardrail": True, "path": str(src_p), "error": f"Refusing symlink or junction source: {src_p}"}

        raw_dst = str(destination).strip()
        if act == "rename" and ("/" not in raw_dst and "\\" not in raw_dst):
            raw_dst = str(src_p.parent / raw_dst)
        dst_info = file_ops.heal_and_resolve_path(raw_dst, guard, mode="write", must_exist=False, tool_name="manage_files")
        if not dst_info["ok"]:
            return {k: (str(v) if isinstance(v, Path) else v) for k, v in dst_info.items() if v is not None}
        dst_p: Path = dst_info["path"]
        if is_link_or_junction(dst_p):
            return {"ok": False, "blocked_by_guardrail": True, "path": str(dst_p), "error": f"Refusing symlink or junction destination: {dst_p}"}

        if dst_p.exists():
            if not overwrite:
                return {
                    "ok": False,
                    "action": act,
                    "already_exists": True,
                    "path": str(src_p),
                    "destination": str(dst_p),
                    "error": f"Destination `{dst_p.name}` already exists (pass overwrite=True to replace safely via trash).",
                }
            tr_res = file_ops.trash_file(dst_p, reason=reason or f"manage_files:{act}:overwrite", guard=guard)
            if not tr_res.get("ok"):
                return tr_res

        dst_p.parent.mkdir(parents=True, exist_ok=True)
        if act == "copy":
            if src_p.is_dir():
                shutil.copytree(str(src_p), str(dst_p))
            else:
                shutil.copy2(str(src_p), str(dst_p))
        else:
            shutil.move(str(src_p), str(dst_p))
        return {
            "ok": True,
            "action": act,
            "path": str(src_p),
            "destination": str(dst_p),
        }

    return {
        "ok": False,
        "action": act,
        "allowed_actions": list(MANAGE_FILES_ACTIONS),
        "error": f"Unknown manage_files action `{action}`; expected one of {list(MANAGE_FILES_ACTIONS)}.",
    }


def build_core_tools(
    guard: Optional[WorkspaceGuard] = None,
    proc_mgr: Optional[ProcessManager] = None,
    policy_getter: Optional[Callable[[], Dict[str, Any]]] = None,
    *,
    policy: Optional[Any] = None,
    toolset_profile: str = "",
    enforce_unread_overwrite: bool = True,
    include_registered_capabilities: bool = True,
) -> Tuple[List[ToolSpec], List[ExecutionHook]]:
    """Build protocol-agnostic `ToolSpec` declarations (16 core tools + registered `CapabilityProvider`s) and `ExecutionHook`s."""
    g = guard if guard is not None else WorkspaceGuard(restrict_to_workspace=False, tier="L3")
    pm = proc_mgr if proc_mgr is not None else ProcessManager(guard=g)
    norm_prof = normalize_core_toolset_profile(toolset_profile) if toolset_profile else ""

    def _effective_policy() -> Dict[str, Any]:
        base_pol: Dict[str, Any] = {
            "prefix": g.tool_prefix,
            "tier": normalize_tier(g.tier),
            "workspace": str(g.workspace_roots[0]) if g.workspace_roots else str(Path.cwd().resolve()),
            "workspace_roots": [str(p) for p in g.workspace_roots] if g.workspace_roots else [str(Path.cwd().resolve())],
            "state_root": str(g.effective_state_root()),
            "toolset_profile": norm_prof if norm_prof in CORE_TOOLSET_PROFILES else "standard",
            "exposed_tools": CORE_TOOLSET_PROFILES.get(norm_prof, DEFAULT_CORE_TOOLS),
        }
        if policy is not None:
            try:
                base_pol["prefix"] = str(getattr(policy, "eff_prefix", "") or base_pol["prefix"])
                base_pol["tier"] = str(getattr(policy, "tier_key", "") or base_pol["tier"])
                base_pol["workspace"] = str(getattr(policy, "workspace", "") or base_pol["workspace"])
                ws_r_obj = getattr(policy, "workspace_roots", None)
                if ws_r_obj:
                    base_pol["workspace_roots"] = [str(p) for p in ws_r_obj]
                sr_obj = getattr(policy, "state_root", None)
                if sr_obj:
                    base_pol["state_root"] = str(sr_obj)
                py_p = getattr(policy, "python_path", None)
                if py_p:
                    base_pol["python_path"] = str(py_p)
                if hasattr(policy, "scan_host_global_skills"):
                    base_pol["scan_host_global_skills"] = bool(getattr(policy, "scan_host_global_skills", False))
            except Exception:
                pass
        if policy_getter is not None:
            try:
                dyn = policy_getter() or {}
                if isinstance(dyn, dict):
                    base_pol.update(dyn)
            except Exception:
                pass
        return base_pol

    pol_for_skills: Any = (
        policy
        if policy is not None
        else (getattr(g, "policy", None) or getattr(pm, "policy", None) or _SkillPolicyProxy(g, _effective_policy))
    )

    tracker = SessionSidebandTracker(
        guard=g,
        policy_getter=_effective_policy,
        policy=pol_for_skills,
        enforce_unread_overwrite=enforce_unread_overwrite,
    )
    status_ro_var: contextvars.ContextVar[bool] = contextvars.ContextVar("cosmos_status_call_readonly", default=False)

    class _GetStatusReadonlyContextHook(ExecutionHook):
        def before_call(self, ctx: Any) -> Optional[Dict[str, Any]]:
            is_ro = bool(getattr(ctx, "readonly_endpoint", False))
            raw_scopes = getattr(ctx, "scopes", None)
            if not is_ro and raw_scopes is not None:
                sc_set = {str(s).strip() for s in raw_scopes if str(s).strip()}
                if not (sc_set & {"mcp:tools", "workspace", "server:admin"}):
                    is_ro = True
            status_ro_var.set(is_ro)
            return None

        def after_call(self, ctx: Any, result: Any, error: Optional[BaseException], duration_ms: float) -> Any:
            _ = (ctx, error, duration_ms)
            status_ro_var.set(False)
            return result

    status_ro_hook = _GetStatusReadonlyContextHook()

    def _log_edit_activity(tool_base: str, target_p: str, summary: str, caller: str) -> None:
        ws_r = g.workspace_roots[0] if g.workspace_roots else None
        workspace_memory.record_auto_activity(
            tool_base,
            target_p,
            summary,
            author=caller,
            workspace_root=ws_r,
            guard=g,
        )

    def _readonly_tier_block(tool_name: str, eff_act: str, cur_tier: str, allowed_ro: Sequence[str]) -> Dict[str, Any]:
        return {
            "ok": False,
            "error_code": "ERR_READONLY_ACTION_BLOCKED",
            "tier_error_code": "ERR_TIER_DENIED",
            "blocked_by_guardrail": True,
            "blocked_by_permission_tier": True,
            "blocked_by_readonly_action": True,
            "tool": tool_name,
            "action": eff_act,
            "permission_tier": cur_tier,
            "allowed_readonly_actions": list(allowed_ro),
            "error": (
                f"[LOCALPC PERMISSION TIER BLOCKED] (ERR_TIER_DENIED / ERR_READONLY_ACTION_BLOCKED): "
                f"`{tool_name}` action='{eff_act}' is forbidden in tier `{cur_tier}` "
                f"(allowed read-only actions: {list(allowed_ro)})."
            ),
        }

    # --- Bound Handlers ---

    async def _h_get_status(
        job_id: str = "",
        wait_seconds: float = 0.0,
        tail_lines: int = 80,
        guide: str = "",
        open_page: str = "",
        caller: str = "",
    ) -> Dict[str, Any]:
        _ = caller
        is_ro_ctx = bool(status_ro_var.get())
        if not is_ro_ctx:
            try:
                from cosmos_mcp.protocol.transport import _REQUEST_TRANSPORT_CTX

                req_ctx = _REQUEST_TRANSPORT_CTX.get()
                if req_ctx.scopes is not None:
                    sc_set = {str(s).strip() for s in req_ctx.scopes if str(s).strip()}
                    if not (sc_set & {"mcp:tools", "workspace", "server:admin"}):
                        is_ro_ctx = True
            except Exception:
                pass
        return await asyncio.to_thread(
            exec_ops.get_status,
            job_id=job_id,
            wait_seconds=wait_seconds,
            tail_lines=tail_lines,
            guide=guide,
            open_page=open_page,
            allow_open_page=(not is_ro_ctx),
            open_blocked_reason="readonly_endpoint" if is_ro_ctx else "",
            proc_mgr=pm,
            guard=g,
            policy_getter=_effective_policy,
        )

    async def _h_find_files(
        path: str = ".",
        pattern: str = "",
        extensions: Any = None,
        excludes: Any = None,
        entry_type: str = "any",
        max_depth: int = 8,
        limit: int = 60,
        sort_by: str = "",
        caller: str = "",
    ) -> Dict[str, Any]:
        _ = caller
        call_kw: Dict[str, Any] = {
            "path": path,
            "pattern": pattern,
            "extensions": extensions,
            "excludes": excludes,
            "entry_type": entry_type,
            "max_depth": max_depth,
            "limit": limit,
            "guard": g,
        }
        if sort_by and _accepts_kwarg(search_nav.find_files, "sort_by"):
            call_kw["sort_by"] = sort_by
        res = await asyncio.to_thread(search_nav.find_files, **call_kw)
        if sort_by and isinstance(res, dict) and res.get("ok") and not _accepts_kwarg(search_nav.find_files, "sort_by"):
            sb = sort_by.strip().lower()
            entries = res.get("entries")
            if isinstance(entries, list) and entries and isinstance(entries[0], dict):
                if sb in ("size", "size_desc"):
                    entries.sort(key=lambda it: int(it.get("size") or 0), reverse=True)
                elif sb in ("mtime", "modified", "mtime_desc"):
                    entries.sort(key=lambda it: float(it.get("mtime") or 0.0), reverse=True)
                elif sb == "name":
                    entries.sort(key=lambda it: str(it.get("name") or it.get("path") or "").lower())
        return res

    async def _h_search_code(
        pattern: str = "",
        path: str = ".",
        glob_filter: str = "",
        files_only: bool = False,
        case_insensitive: bool = False,
        fixed_strings: bool = False,
        include_docs: Optional[bool] = None,
        max_results: int = 40,
        query: str = "",
        keyword: str = "",
        glob: str = "",
        caller: str = "",
    ) -> Dict[str, Any]:
        _ = caller
        call_kw: Dict[str, Any] = {
            "pattern": pattern,
            "path": path,
            "glob_filter": glob_filter,
            "files_only": files_only,
            "case_insensitive": case_insensitive,
            "fixed_strings": fixed_strings,
            "max_results": max_results,
            "query": query,
            "keyword": keyword,
            "glob": glob,
            "guard": g,
        }
        if include_docs is not None and _accepts_kwarg(search_nav.search_code, "include_docs"):
            call_kw["include_docs"] = bool(include_docs)
        res = await asyncio.to_thread(search_nav.search_code, **call_kw)
        if (
            include_docs is False
            and isinstance(res, dict)
            and res.get("ok")
            and not _accepts_kwarg(search_nav.search_code, "include_docs")
        ):
            doc_exts = (".md", ".markdown", ".rst", ".txt")
            if isinstance(res.get("matches"), list):
                kept = [m for m in res["matches"] if not str(m.get("path") or m.get("file") or "").lower().endswith(doc_exts)]
                res = {**res, "matches": kept, "count": len(kept)}
            elif isinstance(res.get("files"), list):
                kept_f = [f for f in res["files"] if not str(f).lower().endswith(doc_exts)]
                res = {**res, "files": kept_f, "count": len(kept_f)}
        return res

    async def _h_code_intel(
        path: str = ".",
        action: str = "outline",
        symbols: Any = None,
        symbol: str = "",
        new_name: str = "",
        include_line_numbers: bool = True,
        max_results: int = 50,
        caller: str = "",
    ) -> Dict[str, Any]:
        pol = _effective_policy()
        tier_norm = normalize_tier(str(pol.get("tier") or g.tier))
        eff_act = (action or "outline").strip().lower()
        ro_allowed = ("outline", "overview", "repo_map", "symbol", "refs", "diagnostics")
        if tier_norm == "L1" and eff_act not in ro_allowed:
            return _readonly_tier_block("code_intel", eff_act, tier_norm, ro_allowed)
        allow_node = tier_norm in ("L3", "L4")
        call_kw: Dict[str, Any] = {
            "path": path,
            "action": eff_act,
            "symbols": symbols,
            "symbol": symbol,
            "include_line_numbers": include_line_numbers,
            "max_results": max_results,
            "guard": g,
            "check_node": allow_node,
        }
        if _accepts_kwarg(ast_intel.run_code_intel, "new_name"):
            call_kw["new_name"] = new_name
        res = await asyncio.to_thread(ast_intel.run_code_intel, **call_kw)
        if isinstance(res, dict) and res.get("ok") and eff_act in ("rename_symbol", "rename"):
            _log_edit_activity("code_intel", str(path), f"rename_symbol:{symbol}->{new_name}", caller)
        return res

    async def _h_read_file(
        path: str,
        start_line: int = 1,
        end_line: int = 0,
        max_lines: int = 800,
        include_line_numbers: bool = True,
        symbol: str = "",
        caller: str = "",
    ) -> Any:
        _ = caller
        return await asyncio.to_thread(
            file_ops.read_file,
            path=path,
            start_line=start_line,
            end_line=end_line,
            max_lines=max_lines,
            include_line_numbers=include_line_numbers,
            symbol=symbol,
            guard=g,
        )

    async def _h_write_file(
        path: str,
        content: str,
        mode: str = "overwrite",
        encoding: str = "",
        allow_shrink: bool = False,
        overwrite_unread: bool = False,
        expected_sha256: str = "",
        check_syntax: bool = True,
        overwrite: bool = True,
        _legacy_disallow_overwrite: bool = False,
        caller: str = "",
    ) -> Dict[str, Any]:
        call_kw: Dict[str, Any] = {
            "path": path,
            "content": content,
            "mode": mode,
            "allow_shrink": bool(allow_shrink),
            "overwrite_unread": bool(overwrite_unread),
            "expected_sha256": expected_sha256,
            "check_syntax": bool(check_syntax),
            "overwrite": bool(overwrite),
            "_legacy_disallow_overwrite": bool(_legacy_disallow_overwrite),
            "guard": g,
        }
        eff_enc = (encoding or "").strip()
        if eff_enc and _accepts_kwarg(file_ops.write_file, "encoding"):
            call_kw["encoding"] = eff_enc
        res = await asyncio.to_thread(file_ops.write_file, **call_kw)
        if (
            res.get("ok")
            and eff_enc
            and not _accepts_kwarg(file_ops.write_file, "encoding")
            and res.get("path")
        ):
            try:
                enc_bytes = encode_with_detected_encoding(content, eff_enc)
                Path(str(res["path"])).write_bytes(enc_bytes)
                res["encoding"] = eff_enc
            except Exception:
                pass
        if res.get("ok"):
            _log_edit_activity("write_file", str(res.get("path") or path), f"write_file:{mode}", caller)
        return res

    async def _h_edit_file(
        path: str = "",
        old_text: str = "",
        new_text: str = "",
        start_line: int = 0,
        end_line: int = 0,
        symbol: str = "",
        insert_after_symbol: str = "",
        patch_text: str = "",
        replace_all: bool = False,
        edits: Any = None,
        expected_sha256: str = "",
        check_syntax: bool = True,
        caller: str = "",
    ) -> Dict[str, Any]:
        clean_patch = str(patch_text or "").strip()
        clean_ins_sym = str(insert_after_symbol or "").strip()

        if clean_patch and not _accepts_kwarg(file_ops.edit_file, "patch_text"):
            eff_patch = clean_patch
            if path and not re.search(r"^\*\*\*\s*(?:Update|Add|Delete|Move)\s+File:", eff_patch, flags=re.MULTILINE):
                eff_patch = f"*** Begin Patch\n*** Update File: {path}\n{eff_patch}\n*** End Patch"
            ops, p_err = patch_ops.parse_v4a_patch(eff_patch)
            if p_err:
                return {"ok": False, "rolled_back_all": True, "error": p_err}
            base_ws = g.workspace_roots[0] if g.workspace_roots else Path.cwd().resolve()
            for op in ops:
                for rel_cand in (op.file_path, op.new_path):
                    if not rel_cand:
                        continue
                    cand_p = Path(rel_cand).expanduser()
                    resolved_cand = (base_ws / cand_p).resolve() if not cand_p.is_absolute() else cand_p.resolve()
                    r_chk = file_ops.heal_and_resolve_path(
                        str(resolved_cand),
                        g,
                        mode="write",
                        must_exist=False,
                        tool_name="edit_file",
                    )
                    if not r_chk["ok"]:
                        return {
                            "ok": False,
                            "rolled_back_all": True,
                            **{k: (str(v) if isinstance(v, Path) else v) for k, v in r_chk.items() if v is not None},
                        }
            res = await asyncio.to_thread(
                file_ops.multi_patch,
                eff_patch,
                check_syntax=bool(check_syntax),
                guard=g,
            )
            if isinstance(res, dict) and res.get("ok"):
                _log_edit_activity("edit_file", str(path or base_ws), "edit_file:patch_text", caller)
            return res

        if clean_ins_sym and not _accepts_kwarg(file_ops.edit_file, "insert_after_symbol"):
            res = await asyncio.to_thread(
                ast_intel.insert_after_symbol,
                path=path,
                symbol=clean_ins_sym,
                code=new_text,
                expected_sha256=expected_sha256,
                check_syntax=bool(check_syntax),
                guard=g,
            )
            if isinstance(res, dict) and res.get("ok"):
                _log_edit_activity("edit_file", str(res.get("path") or path), f"insert_after_symbol:{clean_ins_sym}", caller)
            return res

        edit_kw: Dict[str, Any] = {
            "path": path,
            "old_text": old_text,
            "new_text": new_text,
            "start_line": start_line,
            "end_line": end_line,
            "symbol": symbol,
            "replace_all": bool(replace_all),
            "edits": edits,
            "expected_sha256": expected_sha256,
            "check_syntax": bool(check_syntax),
            "guard": g,
        }
        if clean_patch and _accepts_kwarg(file_ops.edit_file, "patch_text"):
            edit_kw["patch_text"] = clean_patch
        if clean_ins_sym and _accepts_kwarg(file_ops.edit_file, "insert_after_symbol"):
            edit_kw["insert_after_symbol"] = clean_ins_sym
        res = await asyncio.to_thread(file_ops.edit_file, **edit_kw)
        if res.get("ok"):
            _log_edit_activity("edit_file", str(res.get("path") or path), "edit_file", caller)
        return res

    async def _h_manage_files(
        action: str = "list",
        path: str = "",
        destination: str = "",
        overwrite: bool = False,
        trash_id: str = "",
        reason: str = "",
        limit: int = 20,
        caller: str = "",
    ) -> Dict[str, Any]:
        pol = _effective_policy()
        cur_tier = normalize_tier(str(pol.get("tier") or g.tier))
        eff_act = (action or "list").strip().lower()
        if cur_tier == "L1" and eff_act != "list":
            return _readonly_tier_block("manage_files", eff_act, cur_tier, ("list",))

        native_fn = getattr(file_ops, "manage_files", None)
        if callable(native_fn):
            raw_kw = {
                "action": eff_act,
                "path": path,
                "destination": destination,
                "overwrite": bool(overwrite),
                "trash_id": trash_id,
                "reason": reason,
                "limit": limit,
                "guard": g,
            }
            res = await asyncio.to_thread(native_fn, **_filter_accepted_kwargs(native_fn, raw_kw))
        else:
            res = await asyncio.to_thread(
                _fallback_manage_files_sync,
                action=eff_act,
                path=path,
                destination=destination,
                overwrite=bool(overwrite),
                trash_id=trash_id,
                reason=reason,
                limit=limit,
                guard=g,
            )

        if isinstance(res, dict) and res.get("ok") and eff_act != "list":
            target_logged = str(res.get("destination") or res.get("path") or res.get("original_path") or path)
            _log_edit_activity("manage_files", target_logged, f"manage_files:{eff_act}", caller)
        return res

    async def _h_run_command(
        command: str,
        cwd: str = "",
        timeout_seconds: float = 90.0,
        sync_wait_cap_sec: Optional[float] = None,
        caller: str = "",
    ) -> Dict[str, Any]:
        _ = caller
        return await exec_ops.run_command(
            command=command,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            sync_wait_cap_sec=sync_wait_cap_sec,
            proc_mgr=pm,
            guard=g,
        )

    async def _h_run_python(
        code: str,
        cwd: str = "",
        timeout_seconds: float = 90.0,
        python_path: str = "",
        venv: str = "",
        conda_env: str = "",
        sync_wait_cap_sec: Optional[float] = None,
        caller: str = "",
    ) -> Dict[str, Any]:
        _ = caller
        pol = _effective_policy()
        eff_py = (python_path or "").strip() or str(pol.get("python_path") or "").strip()
        call_kw: Dict[str, Any] = {
            "code": code,
            "cwd": cwd,
            "timeout_seconds": timeout_seconds,
            "sync_wait_cap_sec": sync_wait_cap_sec,
            "python_path": eff_py,
            "venv": venv,
            "conda_env": conda_env,
            "policy": pol,
            "proc_mgr": pm,
            "guard": g,
        }
        return await exec_ops.run_python(**_filter_accepted_kwargs(exec_ops.run_python, call_kw))

    async def _h_bg_command(
        action: str = "list",
        command: str = "",
        job_id: str = "",
        cwd: str = "",
        wait_seconds: float = 0.0,
        tail_lines: int = 80,
        max_ttl_seconds: Optional[int] = None,
        python_path: str = "",
        venv: str = "",
        conda_env: str = "",
        caller: str = "",
    ) -> Dict[str, Any]:
        _ = caller
        pol = _effective_policy()
        cur_tier = normalize_tier(str(pol.get("tier") or g.tier))
        raw_act = (action or "").strip().lower()
        eff_act = "start" if ((not raw_act or raw_act == "list") and (command or "").strip() and not (job_id or "").strip()) else (raw_act or "list")
        if cur_tier in ("L1", "L2") and eff_act not in ("status", "list"):
            return _readonly_tier_block("bg_command", eff_act, cur_tier, ("status", "list"))

        eff_py = (python_path or "").strip() or str(pol.get("python_path") or "").strip()
        bg_kw: Dict[str, Any] = {
            "action": action,
            "command": command,
            "job_id": job_id,
            "cwd": cwd,
            "wait_seconds": wait_seconds,
            "tail_lines": tail_lines,
            "python_path": eff_py,
            "venv": venv,
            "conda_env": conda_env,
            "policy": pol,
            "proc_mgr": pm,
            "guard": g,
        }
        if max_ttl_seconds is not None:
            bg_kw["max_ttl_seconds"] = int(max_ttl_seconds)
        return await asyncio.to_thread(exec_ops.bg_command, **_filter_accepted_kwargs(exec_ops.bg_command, bg_kw))

    async def _h_batch_probe(
        code: str = "",
        cwd: str = ".",
        timeout_seconds: int = 20,
        python_code: str = "",
        project_path: str = "",
        caller: str = "",
    ) -> Dict[str, Any]:
        _ = caller
        eff_code = code if (code or "").strip() else python_code
        eff_proj = cwd if (cwd and cwd != ".") else (project_path or cwd or ".")
        return await asyncio.to_thread(
            exec_ops.batch_probe,
            project_path=eff_proj,
            python_code=eff_code,
            timeout_seconds=int(timeout_seconds or 20),
            proc_mgr=pm,
            guard=g,
        )

    async def _h_web_research(
        action: str = "search",
        query: str = "",
        url: str = "",
        max_results: int = 6,
        max_chars: int = 12000,
        offset: int = 0,
        caller: str = "",
    ) -> Dict[str, Any]:
        _ = caller
        eff_off = max(0, int(offset or 0))
        if eff_off > 0 and _accepts_kwarg(web_research.run_web_research, "offset"):
            return await asyncio.to_thread(
                web_research.run_web_research,
                action=action,
                query=query,
                url=url,
                max_results=max_results,
                max_chars=max_chars,
                offset=eff_off,
                guard=g,
            )
        fetch_cap = max_chars + eff_off if (eff_off > 0 and (action or "search").strip().lower() == "fetch") else max_chars
        res = await asyncio.to_thread(
            web_research.run_web_research,
            action=action,
            query=query,
            url=url,
            max_results=max_results + eff_off if (eff_off > 0 and (action or "search").strip().lower() != "fetch") else max_results,
            max_chars=fetch_cap,
            guard=g,
        )
        if eff_off > 0 and isinstance(res, dict) and res.get("ok"):
            if isinstance(res.get("content"), str):
                sliced = res["content"][eff_off : eff_off + int(max_chars or 12000)]
                res = {**res, "content": sliced, "offset": eff_off}
            elif isinstance(res.get("results"), list):
                sliced_r = res["results"][eff_off : eff_off + int(max_results or 6)]
                res = {**res, "results": sliced_r, "offset": eff_off}
        return res

    async def _h_workspace_memory(
        action: str = "read",
        topic: str = "",
        content: str = "",
        query: str = "",
        author: str = "",
        limit: int = 10,
        kind: str = "",
        caller: str = "",
    ) -> Dict[str, Any]:
        pol = _effective_policy()
        cur_tier = normalize_tier(str(pol.get("tier") or g.tier))
        eff_act = (action or "read").strip().lower()
        if cur_tier == "L1" and eff_act not in ("read", "search"):
            return _readonly_tier_block("workspace_memory", eff_act, cur_tier, ("read", "search"))
        eff_author = (author or caller or "agent").strip()
        ws_r = pol.get("workspace") or (str(g.workspace_roots[0]) if g.workspace_roots else None)
        return await asyncio.to_thread(
            workspace_memory.run_workspace_memory,
            action=eff_act,
            topic=topic,
            content=content,
            author=eff_author,
            limit=int(limit or 10),
            query=query,
            workspace_root=ws_r,
            allow_write=(cur_tier != "L1"),
            tier=cur_tier,
            kind=kind,
            guard=g,
        )

    _lazy_skill_cache: Dict[str, ToolSpec] = {}

    def _resolve_live_skill_spec(base_nm: str) -> Optional[ToolSpec]:
        if base_nm in _lazy_skill_cache:
            return _lazy_skill_cache[base_nm]
        loaded = _try_load_real_skill_tool_specs(pol_for_skills, g)
        if loaded:
            for sp_item in loaded:
                _lazy_skill_cache[sp_item.base_name] = sp_item
        return _lazy_skill_cache.get(base_nm)

    async def _h_skill_hub_fallback(**kwargs: Any) -> Any:
        live_sp = _resolve_live_skill_spec("skill_hub")
        if live_sp is not None:
            fn = live_sp.handler
            call_kw = _filter_accepted_kwargs(fn, kwargs)
            out = await fn(**call_kw) if inspect.iscoroutinefunction(fn) else await asyncio.to_thread(fn, **call_kw)
            return (await out) if inspect.isawaitable(out) else out
        act = str(kwargs.get("action") or "search").strip().lower()
        return {
            "ok": True,
            "action": act,
            "skills": [],
            "count": 0,
            "fallback_stub": True,
            "note": "cosmos_mcp.capabilities.skills module is not yet initialized; returning empty skill list.",
        }

    async def _h_skill_manage_fallback(**kwargs: Any) -> Any:
        pol = _effective_policy()
        cur_tier = normalize_tier(str(pol.get("tier") or g.tier))
        act = str(kwargs.get("action") or "list").strip().lower()
        if cur_tier == "L1" and act not in ("list", "trash_list"):
            return _readonly_tier_block("skill_manage", act, cur_tier, ("list", "trash_list"))
        live_sp = _resolve_live_skill_spec("skill_manage")
        if live_sp is not None:
            fn = live_sp.handler
            call_kw = _filter_accepted_kwargs(fn, kwargs)
            out = await fn(**call_kw) if inspect.iscoroutinefunction(fn) else await asyncio.to_thread(fn, **call_kw)
            return (await out) if inspect.isawaitable(out) else out
        if act in ("list", "trash_list"):
            return {"ok": True, "action": act, "items": [], "count": 0, "fallback_stub": True}
        return {
            "ok": False,
            "action": act,
            "fallback_stub": True,
            "error": "cosmos_mcp.capabilities.skills module is not yet initialized on disk.",
        }

    # --- Build `skill_hub` & `skill_manage` via `cosmos_mcp.capabilities.skills.build_skill_tool_specs` ---

    skill_specs = _try_load_real_skill_tool_specs(pol_for_skills, g)
    if skill_specs is None:
        skill_specs = [
            ToolSpec(
                base_name="skill_hub",
                handler=_h_skill_hub_fallback,
                safety_band=SafetyBand.READONLY,
                title="Agent Skill Hub",
                description="Search, load, and inspect local Agent Skills, discover remote registries, or security-audit skill packages in memory.",
                input_schema=_obj_schema({
                    "action": _prop(
                        "string",
                        "search|load|read_file|market_search|vet",
                        enum=list(SKILL_HUB_FALLBACK_ACTIONS),
                        default="search",
                    ),
                    "query": _prop("string", "Keywords to search local or public market skills", default=""),
                    "skill": _prop("string", "Skill name or ID to load or inspect", default=""),
                    "rel_path": _prop("string", "Relative resource file inside a skill directory", default=""),
                    "source": _prop("string", "Local path or HTTPS GitHub repository URL when action='vet'", default=""),
                }),
                aliases=("skill_search", "skill_load"),
                action_param="action",
                action_enum=SKILL_HUB_FALLBACK_ACTIONS,
                idempotent=True,
                open_world=True,
                oauth_scope="server:read",
            ),
            ToolSpec(
                base_name="skill_manage",
                handler=_h_skill_manage_fallback,
                safety_band=SafetyBand.WORKSPACE_WRITE,
                title="Manage Agent Skills",
                description="List, create, two-phase install, sync, enable, disable, or safely trash and restore Agent Skills across scopes.",
                input_schema=_obj_schema({
                    "action": _prop(
                        "string",
                        "list|create|install|sync|enable|disable|trash|trash_list|restore",
                        enum=list(SKILL_MANAGE_FALLBACK_ACTIONS),
                        default="list",
                    ),
                    "skill": _prop("string", "Target skill name or ID", default=""),
                    "source": _prop("string", "Local path or HTTPS GitHub URL when action='install'", default=""),
                    "content": _prop("string", "Complete skill markdown content when action='create'", default=""),
                    "scope": _prop("string", "Target scope (managed|project)", default="project"),
                    "confirm_warn": _prop("boolean", "Explicit confirmation when installing a WARN-level skill", default=False),
                    "trash_id": _prop("string", "Trash entry ID when action='restore'", default=""),
                }),
                aliases=("skill_register",),
                action_param="action",
                action_enum=SKILL_MANAGE_FALLBACK_ACTIONS,
                idempotent=False,
                open_world=True,
                oauth_scope="workspace",
            ),
        ]

    # --- Declarative 16 Canonical Core ToolSpecs ---

    all_specs: List[ToolSpec] = [
        ToolSpec(
            base_name="get_status",
            handler=_h_get_status,
            safety_band=SafetyBand.READONLY,
            title="Get Host & Workspace Status",
            description="Read local OS, workspace roots, disk space, active tier, step-by-step setup guides (`guide`), open local Studio settings (`open_page`), or long-poll background `job_id` for 0 to 25s.",
            input_schema=_obj_schema({
                "job_id": _prop("string", "Background job ID or 'list'", default=""),
                "wait_seconds": _prop("number", "Long-poll seconds (0 to 25)", default=0.0),
                "tail_lines": _prop("integer", "Tail log lines", default=80),
                "guide": _prop(
                    "string",
                    "Optional tutorial topic ('overview'|'cloudflare'|'gateways'|'permissions'|'gemini_chatgpt'|'packs_and_skills'|'troubleshooting'|'all') to read step-by-step user setup & Studio configuration instructions.",
                    default="",
                ),
                "open_page": _prop(
                    "string",
                    "Optional local Studio page to open in the user's PC browser ('studio'|'gateways'|'cloudflare'|'permissions'|'runtime'|'tools'|'skills'|'appearance'|'tutorials') when the user asks to open or configure local settings.",
                    default="",
                ),
            }),
            idempotent=True,
        ),
        ToolSpec(
            base_name="find_files",
            handler=_h_find_files,
            safety_band=SafetyBand.READONLY,
            title="Find Files & Directory Tree",
            description="Find files and directories by glob/substring, extension filter, entry_type, max_depth, and sort_by.",
            input_schema=_obj_schema({
                "path": _prop("string", "Base directory", default="."),
                "pattern": _prop("string", "Filename glob or substring", default=""),
                "extensions": _prop("array", "Extension filter list", items={"type": "string"}),
                "excludes": _prop("array", "Exclude globs", items={"type": "string"}),
                "entry_type": _prop("string", "any|file|dir", enum=["any", "file", "dir"], default="any"),
                "max_depth": _prop("integer", "Traversal depth", default=8),
                "limit": _prop("integer", "Max results", default=60),
                "sort_by": _prop("string", "Sort order (path|mtime|size|name)", default=""),
            }),
            aliases=("find_by_name", "glob"),
            param_aliases={"directory": "path", "dir": "path", "query": "pattern", "max_results": "limit"},
            idempotent=True,
        ),
        ToolSpec(
            base_name="search_code",
            handler=_h_search_code,
            safety_band=SafetyBand.READONLY,
            title="Search Code Across Files",
            description="Fast regex or literal code search with enclosing symbol signatures and snake_case/camelCase fallback.",
            input_schema=_obj_schema({
                "pattern": _prop("string", "Regex or literal search pattern", default=""),
                "path": _prop("string", "Directory or file path", default="."),
                "glob_filter": _prop("string", "Filename glob filter (e.g. '*.py')", default=""),
                "files_only": _prop("boolean", "Return matching file paths only", default=False),
                "case_insensitive": _prop("boolean", "Case-insensitive search", default=False),
                "fixed_strings": _prop("boolean", "Treat pattern as literal text", default=False),
                "include_docs": _prop("boolean", "Include documentation files in search", default=True),
                "max_results": _prop("integer", "Max matches", default=40),
            }),
            aliases=("grep_search", "search_code_ripgrep"),
            param_aliases={
                "query": "pattern",
                "keyword": "pattern",
                "regex": "pattern",
                "glob": "glob_filter",
                "file_pattern": "glob_filter",
            },
            idempotent=True,
        ),
        ToolSpec(
            base_name="code_intel",
            handler=_h_code_intel,
            safety_band=SafetyBand.WORKSPACE_EDIT,
            title="Code Intelligence Facade",
            description="Project overview/repo_map, symbol outline, definitions, cross-file references, diagnostics, and AST-scoped rename_symbol.",
            input_schema=_obj_schema({
                "path": _prop("string", "Target file or directory", default="."),
                "action": _prop(
                    "string",
                    "outline|overview|repo_map|symbol|refs|diagnostics|rename_symbol",
                    enum=["outline", "overview", "repo_map", "symbol", "refs", "diagnostics", "rename_symbol"],
                    default="outline",
                ),
                "symbol": _prop("string", "Target symbol or Class.method", default=""),
                "new_name": _prop("string", "New identifier name when action='rename_symbol'", default=""),
                "symbols": _prop("array", "Multiple symbol names", items={"type": "string"}),
                "include_line_numbers": _prop("boolean", "Prefix line numbers", default=True),
                "max_results": _prop("integer", "Max items", default=50),
            }),
            aliases=("view_file_outline",),
            param_aliases={"name": "symbol", "name_path": "symbol", "query": "symbol", "old_name": "symbol"},
            action_param="action",
            action_enum=("outline", "overview", "repo_map", "symbol", "refs", "diagnostics", "rename_symbol"),
            idempotent=False,
        ),
        ToolSpec(
            base_name="read_file",
            handler=_h_read_file,
            safety_band=SafetyBand.READONLY,
            title="Read Local File",
            description="Read code and UTF-8 text slices (`>2MiB` streaming, negative tail `start_line`, `symbol` slice), local images with native vision, or `docx/xlsx/pptx/pdf/ipynb` document text.",
            input_schema=_obj_schema(
                {
                    "path": _prop("string", "Target file or image path"),
                    "start_line": _prop("integer", "1-based start line or negative tail count", default=1),
                    "end_line": _prop("integer", "1-based inclusive end line (0 = auto)", default=0),
                    "max_lines": _prop("integer", "Max lines per call", default=800),
                    "include_line_numbers": _prop("boolean", "Prefix 1-based line numbers", default=True),
                    "symbol": _prop("string", "Optional symbol name to slice", default=""),
                },
                required=("path",),
            ),
            aliases=("view_file",),
            param_aliases={"file_path": "path", "file": "path"},
            idempotent=True,
        ),
        ToolSpec(
            base_name="edit_file",
            handler=_h_edit_file,
            safety_band=SafetyBand.WORKSPACE_EDIT,
            title="Surgical File Editor",
            description=_ensure_first_sentence_no_internal_dots(
                "Surgical code, text, docx, and xlsx editor (`Sheet1!B4` or value match, `~$` lock guard, undo rollback) "
                "supporting `±15`-line window drift, `symbol` or `insert_after_symbol` scope, `patch_text`, and atomic `edits` list."
            ),
            input_schema=_obj_schema({
                "path": _prop("string", "Target file path (code, text, .docx, or .xlsx)", default=""),
                "old_text": _prop("string", "Snippet to match, or .xlsx cell ref like 'Sheet1!B4'", default=""),
                "new_text": _prop("string", "Replacement text or .xlsx cell value/formula", default=""),
                "start_line": _prop("integer", "Optional 1-based window start", default=0),
                "end_line": _prop("integer", "Optional 1-based window end", default=0),
                "symbol": _prop("string", "Optional symbol scope", default=""),
                "insert_after_symbol": _prop("string", "Insert `new_text` immediately after the named symbol", default=""),
                "patch_text": _prop("string", "Optional V4A multi-file patch text (`*** Begin Patch ... *** End Patch`)", default=""),
                "replace_all": _prop("boolean", "Replace all occurrences", default=False),
                "edits": _prop("array", "Multi-chunk atomic edits", items=_EDIT_CHUNK_SCHEMA),
                "expected_sha256": _prop("string", "Optional optimistic lock SHA256", default=""),
                "check_syntax": _prop("boolean", "Run staged syntax precheck", default=True),
            }),
            param_aliases={
                "file_path": "path",
                "old_string": "old_text",
                "new_string": "new_text",
                "patch": "patch_text",
                "diff": "patch_text",
            },
        ),
        ToolSpec(
            base_name="write_file",
            handler=_h_write_file,
            safety_band=SafetyBand.WORKSPACE_EDIT,
            title="Write or Create File",
            description="Write or append text preserving encoding with shrink guard (`allow_shrink`), unread guard, snapshot, and staged syntax check.",
            input_schema=_obj_schema(
                {
                    "path": _prop("string", "Target file path"),
                    "content": _prop("string", "File text content"),
                    "mode": _prop("string", "overwrite|append", enum=["overwrite", "append"], default="overwrite"),
                    "encoding": _prop("string", "Optional target text encoding", default=""),
                    "allow_shrink": _prop("boolean", "Allow >50% size reduction on existing files", default=False),
                    "overwrite_unread": _prop("boolean", "Allow overwriting an existing unread file", default=False),
                    "expected_sha256": _prop("string", "Optional optimistic lock SHA256", default=""),
                    "check_syntax": _prop("boolean", "Run staged syntax precheck", default=True),
                },
                required=("path", "content"),
            ),
            param_aliases={"file_path": "path", "text": "content"},
        ),
        ToolSpec(
            base_name="manage_files",
            handler=_h_manage_files,
            safety_band=SafetyBand.WORKSPACE_EDIT,
            title="Manage Files, Undo & Recoverable Trash",
            description="Safe workspace file lifecycle manager with recoverable undo/trash vault.",
            input_schema=_obj_schema({
                "action": _prop(
                    "string",
                    "mkdir|move|rename|copy|trash|restore|undo|redo|list",
                    enum=list(MANAGE_FILES_ACTIONS),
                    default="list",
                ),
                "path": _prop("string", "Target file or directory path", default=""),
                "destination": _prop("string", "Destination path for move/rename/copy", default=""),
                "overwrite": _prop("boolean", "Replace existing destination safely via trash", default=False),
                "trash_id": _prop("string", "Trash item ID or 'latest' when action='restore'", default=""),
                "reason": _prop("string", "Optional note for trash operation", default=""),
                "limit": _prop("integer", "Max items returned when action='list'", default=20),
            }),
            param_aliases={
                "file_path": "path",
                "src": "path",
                "source": "path",
                "dest": "destination",
                "dst": "destination",
                "new_path": "destination",
            },
            action_param="action",
            action_enum=MANAGE_FILES_ACTIONS,
        ),
        ToolSpec(
            base_name="run_command",
            handler=_h_run_command,
            safety_band=SafetyBand.WORKSPACE_EXEC,
            title="Run Terminal Command",
            description="Execute a headless terminal command (`CREATE_NO_WINDOW`) with automatic promotion to `bg_command` on long tasks.",
            input_schema=_obj_schema(
                {
                    "command": _prop("string", "Shell command to execute"),
                    "cwd": _prop("string", "Working directory", default=""),
                    "timeout_seconds": _prop("number", "Max timeout seconds", default=90.0),
                    "sync_wait_cap_sec": _prop("number", "Foreground wait cap before background promotion"),
                },
                required=("command",),
            ),
            param_aliases={"cmd": "command", "workdir": "cwd"},
        ),
        ToolSpec(
            base_name="run_python",
            handler=_h_run_python,
            safety_band=SafetyBand.WORKSPACE_EXEC,
            title="Run Python Code via Stdin",
            description="Execute multiline Python code via stdin (`CREATE_NO_WINDOW`) with `python_path`/`venv`/`conda_env` selection and zero quote escaping.",
            input_schema=_obj_schema(
                {
                    "code": _prop("string", "Python source code"),
                    "cwd": _prop("string", "Working directory", default=""),
                    "timeout_seconds": _prop("number", "Max timeout seconds", default=90.0),
                    "python_path": _prop("string", "Optional Python or Conda interpreter executable path", default=""),
                    "venv": _prop("string", "Optional virtualenv directory path", default=""),
                    "conda_env": _prop("string", "Optional Conda environment name or prefix", default=""),
                    "sync_wait_cap_sec": _prop("number", "Foreground wait cap before background promotion"),
                },
                required=("code",),
            ),
            param_aliases={"python_code": "code", "script": "code", "workdir": "cwd", "python_exe": "python_path"},
        ),
        ToolSpec(
            base_name="bg_command",
            handler=_h_bg_command,
            safety_band=SafetyBand.WORKSPACE_EXEC,
            title="Manage Background Command",
            description="Detached background job controller returning `log_path`/`log_file` and `tail`/`log_tail`.",
            input_schema=_obj_schema({
                "action": _prop("string", "start|status|wait|list|kill", enum=["start", "status", "wait", "list", "kill"], default="list"),
                "command": _prop("string", "Command to start", default=""),
                "job_id": _prop("string", "Background job ID", default=""),
                "cwd": _prop("string", "Working directory", default=""),
                "wait_seconds": _prop("number", "Long-poll wait seconds", default=0.0),
                "tail_lines": _prop("integer", "Tail log lines", default=80),
                "max_ttl_seconds": _prop("integer", "Maximum background job lifetime in seconds"),
                "python_path": _prop("string", "Optional Python interpreter executable path", default=""),
                "venv": _prop("string", "Optional virtualenv directory path", default=""),
                "conda_env": _prop("string", "Optional Conda environment name or prefix", default=""),
            }),
            param_aliases={"cmd": "command", "workdir": "cwd", "python_exe": "python_path"},
            action_param="action",
            action_enum=("start", "status", "wait", "list", "kill"),
        ),
        ToolSpec(
            base_name="batch_probe",
            handler=_h_batch_probe,
            safety_band=SafetyBand.READONLY,
            title="Read-Only Python Batch Probe",
            description="Execute an isolated read-only Python batch probe (`CREATE_NO_WINDOW`) with pre-injected `PROJ`, `rg`, `outline`, `list_dir`, and `RESULT`.",
            input_schema=_obj_schema(
                {
                    "code": _prop("string", "Read-only deterministic Python probe assigning summary data to RESULT"),
                    "cwd": _prop("string", "Target workspace directory", default="."),
                    "timeout_seconds": _prop("integer", "Probe timeout seconds (5 to 60)", default=20),
                },
                required=("code",),
            ),
            param_aliases={
                "python_code": "code",
                "script": "code",
                "project_path": "cwd",
                "path": "cwd",
                "workdir": "cwd",
            },
            idempotent=True,
        ),
        ToolSpec(
            base_name="web_research",
            handler=_h_web_research,
            safety_band=SafetyBand.READONLY,
            title="Local SSRF-Safe Web & GitHub Research",
            description="Query public web or GitHub repositories or fetch technical pages via SSRF-safe transport.",
            input_schema=_obj_schema({
                "action": _prop("string", "search|github_search|fetch", enum=["search", "github_search", "fetch"], default="search"),
                "query": _prop("string", "Search keywords", default=""),
                "url": _prop("string", "Public HTTP/HTTPS URL for fetch", default=""),
                "max_results": _prop("integer", "Max search results", default=6),
                "max_chars": _prop("integer", "Max fetched characters", default=12000),
                "offset": _prop("integer", "Character or result pagination offset", default=0),
            }),
            action_param="action",
            action_enum=("search", "github_search", "fetch"),
            idempotent=True,
        ),
        ToolSpec(
            base_name="workspace_memory",
            handler=_h_workspace_memory,
            safety_band=SafetyBand.WORKSPACE_WRITE,
            title="Shared Workspace Memory & Activity Ledger",
            description="Read, post, or search cross-session workspace notes and edit activity breadcrumbs in externalized SQLite WAL storage.",
            input_schema=_obj_schema({
                "action": _prop("string", "read|post|search", enum=["read", "post", "search"], default="read"),
                "topic": _prop("string", "Short note topic", default=""),
                "content": _prop("string", "Note body when action='post'", default=""),
                "query": _prop("string", "Search query when action='search'", default=""),
                "author": _prop("string", "Optional author tag", default=""),
                "limit": _prop("integer", "Max entries returned (1 to 100)", default=10),
                "kind": _prop("string", "Optional entry kind filter (note|auto_activity|all)", default=""),
            }),
            param_aliases={"note": "content", "text": "content", "message": "content"},
            action_param="action",
            action_enum=("read", "post", "search"),
        ),
        *skill_specs,
    ]

    if include_registered_capabilities:
        existing_names = {sp.base_name for sp in all_specs}
        for provider in load_registered_providers():
            try:
                ext_specs = provider.build_static_tools() or ()
            except Exception:
                ext_specs = ()
            for ext_sp in ext_specs:
                if ext_sp.base_name not in existing_names:
                    all_specs.append(ext_sp)
                    existing_names.add(ext_sp.base_name)

    selected_specs = filter_core_tools_by_profile(all_specs, norm_prof) if norm_prof else all_specs
    return selected_specs, [status_ro_hook, tracker]
