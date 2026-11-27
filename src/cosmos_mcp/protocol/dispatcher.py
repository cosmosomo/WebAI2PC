"""Table-driven tool registry, SafetyBand policy/scope gate, silent legacy alias routing, and bounded audit slots."""
from __future__ import annotations

import asyncio
from collections import deque
import inspect
import json
import os
from pathlib import Path
import re
import secrets
import threading
import time
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from cosmos_mcp.capabilities import CapabilityProvider, load_registered_providers
from cosmos_mcp.core.config import (
    DEFAULT_CORE_TOOLS,
    LiveRuntimePolicy,
    MIXED_TOOL_READONLY_ACTIONS,
    TOOLSET_PROFILES,
    is_mixed_tool_readonly_action,
    normalize_prefix,
    normalize_tier,
    normalize_toolset_profile,
)
from cosmos_mcp.core.contracts import (
    AuditCallback,
    AuditEvent,
    DEFAULT_PROPERTY_DESCRIPTIONS,
    ExecutionHook,
    PackPlugin,
    RuntimePaths,
    SafetyBand,
    ToolCallContext,
    ToolSpec,
    normalize_input_schema,
)
from cosmos_mcp.core.fs_tx import check_office_or_os_file_lock
from cosmos_mcp.core.guard import expand_env_and_tilde, redact_sensitive_output, strip_file_uri


_TIER_ALLOWED_BANDS: Dict[str, frozenset[SafetyBand]] = {
    "tier1_readonly": frozenset({SafetyBand.READONLY}),
    "tier2_workspace_edit": frozenset({SafetyBand.READONLY, SafetyBand.WORKSPACE_WRITE}),
    "tier3_workspace_dev": frozenset({SafetyBand.READONLY, SafetyBand.WORKSPACE_WRITE, SafetyBand.WORKSPACE_EXEC}),
    "tier4_full_power": frozenset(
        {SafetyBand.READONLY, SafetyBand.WORKSPACE_WRITE, SafetyBand.WORKSPACE_EXEC, SafetyBand.HOST_ADMIN}
    ),
}

# Silent internal routing aliases: never listed in `tools/list`, automatically mapped when invoked by name
DEFAULT_UNREGISTERED_TOOL_ALIASES: Dict[str, str] = {
    # Legacy file lifecycle & rollback names -> `manage_files`
    "undo_or_trash": "manage_files",
    "trash_file": "manage_files",
    "restore_trash": "manage_files",
    "undo_edit": "manage_files",
    # Legacy edit/patch names -> `edit_file`
    "patch_file": "edit_file",
    "multi_patch": "edit_file",
    "replace_lines": "edit_file",
    "insert_after_symbol": "edit_file",
    "replace_symbol_body": "edit_file",
    # Legacy navigation & AST names -> `find_files` / `code_intel`
    "list_dir": "find_files",
    "code_outline": "code_intel",
    "get_code_outline": "code_intel",
    "extract_code_outline": "code_intel",
    "view_file_outline": "code_intel",
    "repo_map": "code_intel",
    "get_repo_map": "code_intel",
    "get_symbols_overview": "code_intel",
    "find_symbol": "code_intel",
    "find_referencing_symbols": "code_intel",
    "rename_symbol": "code_intel",
    # Cross-host IDE & skill/pack convenience aliases
    "find_by_name": "find_files",
    "glob": "find_files",
    "grep_search": "search_code",
    "search_code_ripgrep": "search_code",
    "view_file": "read_file",
    "memory": "workspace_memory",
    "shared_memory": "workspace_memory",
    "blackboard": "workspace_memory",
    "handoff_memory": "workspace_memory",
    "skill_search": "skill_hub",
    "skill_load": "skill_hub",
    "skill_register": "skill_manage",
    "desktop_window": "cua_window",
}

DEFAULT_PARAM_ALIASES: Dict[str, Dict[str, str]] = {
    "search_code": {
        "glob": "glob_filter",
        "file_glob": "glob_filter",
        "query": "pattern",
        "Query": "pattern",
        "keyword": "pattern",
        "SearchPath": "path",
        "file_path": "path",
        "CaseInsensitive": "case_insensitive",
    },
    "find_files": {
        "SearchDirectory": "path",
        "directory": "path",
        "dir": "path",
        "file_path": "path",
        "Pattern": "pattern",
        "glob": "pattern",
        "max_entries": "limit",
    },
    "read_file": {
        "AbsolutePath": "path",
        "file_path": "path",
        "StartLine": "start_line",
        "EndLine": "end_line",
    },
    "code_intel": {
        "AbsolutePath": "path",
        "file_path": "path",
        "relative_path": "path",
        "project_path": "path",
        "max_files": "max_results",
        "name_path": "symbol",
        "old_name": "symbol",
    },
    "edit_file": {
        "file_path": "path",
        "old_string": "old_text",
        "new_string": "new_text",
        "patch": "patch_text",
        "diff": "patch_text",
    },
    "write_file": {"file_path": "path", "text": "content"},
    "manage_files": {
        "file_path": "path",
        "src": "path",
        "source": "path",
        "dest": "destination",
        "dst": "destination",
        "target": "destination",
        "new_path": "destination",
    },
    "undo_or_trash": {"file_path": "path"},
    "run_python": {"python_code": "code", "script": "code", "workdir": "cwd", "python_exe": "python_path"},
    "bg_command": {"cmd": "command", "workdir": "cwd", "python_exe": "python_path"},
    "batch_probe": {"python_code": "code", "script": "code", "project_path": "cwd", "path": "cwd", "workdir": "cwd"},
    "workspace_memory": {"note": "content"},
}

_ZW_CHAR = "\u200c"


def _unsanitize_ipi_obj(val: Any) -> Any:
    """Recursively strip any echoed `\u200c` zero-width non-joiner characters from inbound tool arguments."""
    if isinstance(val, str):
        return val.replace(_ZW_CHAR, "") if _ZW_CHAR in val else val
    if isinstance(val, list):
        return [_unsanitize_ipi_obj(x) for x in val]
    if isinstance(val, tuple):
        return tuple(_unsanitize_ipi_obj(x) for x in val)
    if isinstance(val, dict):
        return {
            (k.replace(_ZW_CHAR, "") if isinstance(k, str) and _ZW_CHAR in k else k): _unsanitize_ipi_obj(v)
            for k, v in val.items()
        }
    return val


def _project_readonly_mixed_spec(sp: ToolSpec) -> ToolSpec:
    """Project a mixed read/write `ToolSpec` down to its strictly read-only query actions."""
    ro_actions = MIXED_TOOL_READONLY_ACTIONS.get(sp.base_name)
    if not ro_actions:
        return sp
    ro_schema = json.loads(json.dumps(sp.input_schema))
    props = ro_schema.get("properties")
    if isinstance(props, dict) and isinstance(props.get(sp.action_param), dict):
        act_prop = props[sp.action_param]
        act_prop["enum"] = list(ro_actions)
        act_prop["description"] = "|".join(ro_actions) + " (read-only mode)"
        if act_prop.get("default") not in ro_actions:
            act_prop["default"] = ro_actions[0]
    return ToolSpec(
        base_name=sp.base_name,
        handler=sp.handler,
        safety_band=SafetyBand.READONLY,
        input_schema=ro_schema,
        title=sp.title,
        description=sp.description,
        nudge_prefer=sp.nudge_prefer,
        pack=sp.pack,
        aliases=sp.aliases,
        param_aliases=sp.param_aliases,
        action_param=sp.action_param,
        action_enum=ro_actions,
        idempotent=True,
        open_world=sp.open_world,
        oauth_scope="server:read",
    )


def is_band_permitted_by_scopes(spec: ToolSpec, scopes: Optional[Iterable[str]]) -> bool:
    """Check whether OAuth `scopes` permit invoking or listing `spec`."""
    if scopes is None:
        return True
    scope_set = {str(s).strip() for s in scopes if str(s).strip()}
    if spec.safety_band in (SafetyBand.WORKSPACE_EXEC, SafetyBand.HOST_ADMIN):
        if "server:admin" not in scope_set:
            return False
    if spec.oauth_scope:
        if spec.oauth_scope == "server:read":
            return bool(scope_set & {"server:read", "workspace", "server:admin"})
        if spec.oauth_scope == "workspace":
            return bool(scope_set & {"workspace", "server:admin"})
        return spec.oauth_scope in scope_set

    if spec.safety_band == SafetyBand.READONLY:
        return bool(scope_set & {"server:read", "workspace", "server:admin"})
    if spec.safety_band == SafetyBand.WORKSPACE_WRITE:
        return bool(scope_set & {"workspace", "server:admin"})
    if spec.safety_band == SafetyBand.WORKSPACE_EXEC:
        return "server:admin" in scope_set
    if spec.safety_band == SafetyBand.HOST_ADMIN:
        return "server:admin" in scope_set
    return False


VPS_HUB_WORKSPACE_TOOL_BASES: frozenset[str] = frozenset(
    {
        "find_files",
        "read_file",
        "search_code",
        "code_intel",
        "edit_file",
        "write_file",
        "manage_files",
        "run_command",
        "run_python",
        "bg_command",
        "batch_probe",
        "workspace_memory",
    }
)


class KernelDispatcher:
    """Central protocol-agnostic tool registry and execution engine shared by LowLevelServer and jsonrpc_lite."""

    MAX_AUDIT_CALLBACK_SLOTS = 16
    MAX_RECENT_AUDIT_EVENTS = 200

    def __init__(
        self,
        policy: LiveRuntimePolicy,
        *,
        max_audit_slots: int = MAX_AUDIT_CALLBACK_SLOTS,
        max_recent_events: int = MAX_RECENT_AUDIT_EVENTS,
    ) -> None:
        self.policy = policy
        self._lock = threading.RLock()
        self._specs: Dict[str, ToolSpec] = {}
        self._registration_order: List[str] = []
        self._capability_tool_bases: Set[str] = set()
        self._tool_aliases: Dict[str, str] = dict(DEFAULT_UNREGISTERED_TOOL_ALIASES)
        self._packs: Dict[str, PackPlugin] = {}
        self._hooks: List[ExecutionHook] = []
        self._max_audit_slots = max(1, min(64, int(max_audit_slots)))
        self._audit_slots: Dict[str, AuditCallback] = {}
        self._recent_audit: Deque[AuditEvent] = deque(maxlen=max(10, int(max_recent_events)))
        self._seen_epochs: Dict[str, Tuple[int, int]] = {}
        self._inflight_count = 0
        self._remote_nodes: Dict[str, Dict[str, Any]] = {}
        self._remote_forwarder: Optional[Callable[..., Any]] = None
        self.vps_hub_mode: bool = False
        self.bound_node_id: str = ""

    def is_vps_hub_active(self) -> bool:
        if self.vps_hub_mode:
            return True
        pol_tm = str(getattr(self.policy, "tunnel_mode", "") or "").strip().lower()
        if pol_tm == "vps_hub":
            return True
        env_tm = (os.environ.get("COSMOS_TUNNEL_MODE") or os.environ.get("LOCALPC_TUNNEL_MODE") or "").strip().lower()
        return env_tm == "vps_hub"

    def is_stock_or_empty_vps_hub_workspace(self) -> bool:
        """Return True when `vps_hub` local workspace is the stock `/var/lib/cosmos-mcp-hub` / `/opt/cosmos-mcp-hub` dir or empty."""
        if not self.is_vps_hub_active():
            return False
        roots = list(getattr(self.policy, "workspace_roots", ()) or ())
        if not roots:
            return True
        ignored_names = {".cosmos_mcp", ".undo_history", "state", "secrets", "logs", "config"}
        for raw_root in roots:
            ws_p = Path(raw_root)
            norm_s = str(ws_p).replace("\\", "/").rstrip("/").lower()
            if norm_s.endswith(("/cosmos-mcp-hub", "/cosmos-mcp-hub/workspace", "/var/lib/cosmos-mcp/workspace")):
                continue
            if not ws_p.exists() or not ws_p.is_dir():
                continue
            try:
                has_user_entry = any(child.name not in ignored_names for child in ws_p.iterdir())
            except OSError:
                has_user_entry = False
            if has_user_entry:
                return False
        return True

    @property
    def inflight_count(self) -> int:
        return self._inflight_count

    @property
    def prefix(self) -> str:
        raw_tp = getattr(self.policy, "tool_prefix", None) or self.policy.eff_prefix
        return normalize_prefix(raw_tp)

    def set_remote_forwarder(self, fn: Optional[Callable[..., Any]]) -> None:
        """Register or clear the global WSS child-node tool forwarder callback."""
        with self._lock:
            self._remote_forwarder = fn

    def register_remote_node(
        self,
        node_id: str,
        *,
        workspace_roots: Sequence[Any] = (),
        drives: Sequence[str] = (),
        online: bool = True,
        platform_name: str = "",
        device_label: str = "",
        forwarder: Optional[Callable[..., Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Thread-safely register or update a child PC node for `target='auto'` / explicit `target` routing."""
        nid = str(node_id or "").strip()
        if not nid:
            raise ValueError("Remote node_id must not be empty.")
        with self._lock:
            prev = self._remote_nodes.get(nid, {})
            ws_strs = [str(r).strip() for r in (workspace_roots or ()) if str(r).strip()]
            if not ws_strs and prev.get("workspace_roots"):
                ws_strs = list(prev["workspace_roots"])
            drv_list: List[str] = []
            for d in (drives or ()):
                ds = str(d or "").strip().rstrip("\\/").lower()
                if ds and not ds.endswith(":"):
                    ds = ds + ":"
                if re.fullmatch(r"[a-z]:", ds) and ds not in drv_list:
                    drv_list.append(ds)
            for ws_s in ws_strs:
                m_drv = re.match(r"^([A-Za-z]:)(?:[\\/]|$)", ws_s)
                if m_drv:
                    dl = m_drv.group(1).lower()
                    if dl not in drv_list:
                        drv_list.append(dl)
            if not drv_list and prev.get("drives"):
                drv_list = list(prev["drives"])
            entry: Dict[str, Any] = {
                "node_id": nid,
                "online": bool(online),
                "workspace_roots": ws_strs,
                "drives": drv_list,
                "platform": str(platform_name or prev.get("platform") or ""),
                "device_label": str(device_label or prev.get("device_label") or nid),
                "forwarder": forwarder if forwarder is not None else prev.get("forwarder"),
                "metadata": dict(metadata) if metadata is not None else dict(prev.get("metadata") or {}),
                "updated_at": time.time(),
            }
            self._remote_nodes[nid] = entry
            return {k: v for k, v in entry.items() if k != "forwarder"}

    def unregister_remote_node(self, node_id: str, *, keep_offline_record: bool = False) -> bool:
        """Remove a child PC node (or mark it offline when `keep_offline_record=True`)."""
        nid = str(node_id or "").strip()
        if not nid:
            return False
        with self._lock:
            if nid not in self._remote_nodes:
                return False
            if keep_offline_record:
                self._remote_nodes[nid]["online"] = False
                self._remote_nodes[nid]["forwarder"] = None
                self._remote_nodes[nid]["updated_at"] = time.time()
                return True
            self._remote_nodes.pop(nid, None)
            return True

    def list_remote_nodes(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {k: v for k, v in info.items() if k != "forwarder"}
                for info in self._remote_nodes.values()
            ]

    def prefixed_name(self, base_name: str) -> str:
        p = self.prefix
        return f"{p}_{base_name}" if p else base_name

    def register_tool(self, spec: ToolSpec) -> None:
        with self._lock:
            self._specs[spec.base_name] = spec
            if spec.base_name not in self._registration_order:
                self._registration_order.append(spec.base_name)
            for al in spec.aliases:
                clean_al = al.strip()
                if clean_al:
                    self._tool_aliases[clean_al] = spec.base_name

    def register_tools(self, specs: Iterable[ToolSpec]) -> None:
        for sp in specs:
            self.register_tool(sp)

    def register_capability_provider(self, provider: CapabilityProvider) -> None:
        """Mount static tools from an extension `CapabilityProvider`."""
        try:
            ext_specs = provider.build_static_tools() or ()
        except Exception:
            ext_specs = ()
        with self._lock:
            for sp in ext_specs:
                self._capability_tool_bases.add(sp.base_name)
                self.register_tool(sp)

    def load_registered_capabilities(self) -> List[ToolSpec]:
        """Synchronize registered extension providers from `cosmos_mcp.capabilities.load_registered_providers()`."""
        added: List[ToolSpec] = []
        for provider in load_registered_providers():
            try:
                ext_specs = provider.build_static_tools() or ()
            except Exception:
                ext_specs = ()
            with self._lock:
                for sp in ext_specs:
                    self._capability_tool_bases.add(sp.base_name)
                    if sp.base_name not in self._specs:
                        self.register_tool(sp)
                        added.append(sp)
        return added

    def register_pack(self, plugin: PackPlugin) -> None:
        with self._lock:
            self._packs[plugin.pack_id] = plugin
            for sp in plugin.get_tools():
                if sp.pack is None:
                    sp = ToolSpec(
                        base_name=sp.base_name,
                        handler=sp.handler,
                        safety_band=sp.safety_band,
                        input_schema=sp.input_schema,
                        title=sp.title,
                        description=sp.description,
                        nudge_prefer=sp.nudge_prefer,
                        pack=plugin.pack_id,
                        aliases=sp.aliases,
                        param_aliases=sp.param_aliases,
                        action_param=sp.action_param,
                        action_enum=sp.action_enum,
                        idempotent=sp.idempotent,
                        open_world=sp.open_world,
                        oauth_scope=sp.oauth_scope,
                    )
                self.register_tool(sp)

    def shutdown_packs(self, prefix_filter: str = "") -> None:
        with self._lock:
            packs = list(self._packs.values())
        for pk in packs:
            try:
                pk.shutdown(prefix_filter=prefix_filter)
            except Exception:
                pass

    def add_execution_hook(self, hook: ExecutionHook) -> None:
        with self._lock:
            if hook not in self._hooks:
                self._hooks.append(hook)

    def register_audit_callback(self, slot_id: str, callback: AuditCallback) -> str:
        """Register an audit callback in a bounded slot map (evicts oldest slot if full)."""
        clean_id = (slot_id or "").strip() or f"slot_{secrets.token_hex(4)}"
        with self._lock:
            if clean_id in self._audit_slots:
                self._audit_slots.pop(clean_id)
            elif len(self._audit_slots) >= self._max_audit_slots:
                oldest_key = next(iter(self._audit_slots))
                self._audit_slots.pop(oldest_key, None)
            self._audit_slots[clean_id] = callback
        return clean_id

    def unregister_audit_callback(self, slot_id: str) -> bool:
        with self._lock:
            return self._audit_slots.pop(slot_id, None) is not None

    def recent_audit_events(self, limit: int = 20) -> List[Dict[str, Any]]:
        cap = max(1, min(self.MAX_RECENT_AUDIT_EVENTS, int(limit)))
        with self._lock:
            items = list(self._recent_audit)[-cap:]
        items.reverse()
        return [
            {
                "call_id": ev.call_id,
                "ts": ev.ts,
                "caller": ev.caller,
                "tool": ev.tool,
                "resolved_tool": ev.resolved_tool,
                "safety_band": ev.safety_band,
                "tier": ev.tier,
                "ok": ev.ok,
                "duration_ms": ev.duration_ms,
                "error": ev.error,
                "blocked_reason": ev.blocked_reason,
            }
            for ev in items
        ]

    def get_spec(self, base_name: str) -> Optional[ToolSpec]:
        with self._lock:
            return self._specs.get(base_name)

    def all_registered_specs(self) -> List[ToolSpec]:
        with self._lock:
            return [self._specs[k] for k in self._registration_order if k in self._specs]

    def strip_prefix_and_resolve_base(self, raw_name: str) -> Tuple[str, str]:
        """Return `(resolved_base_name, matched_alias_or_empty)`."""
        clean = (raw_name or "").strip()
        if not clean:
            return "", ""
        eff_p = self.prefix
        inst_p = normalize_prefix(getattr(self.policy, "eff_prefix", "pc"))
        with self._lock:
            known = set(self._specs.keys())
            aliases = dict(self._tool_aliases)

        if clean in known:
            return clean, ""
        if clean in aliases and aliases[clean] in known:
            return aliases[clean], clean

        cand_prefixes: List[str] = []
        for pfx_c in (eff_p, inst_p, "pc"):
            if pfx_c and pfx_c not in cand_prefixes:
                cand_prefixes.append(pfx_c)

        for pfx in cand_prefixes:
            if pfx and clean.startswith(f"{pfx}_"):
                sub = clean[len(pfx) + 1 :]
                if sub in known:
                    return sub, ""
                if sub in aliases and aliases[sub] in known:
                    return aliases[sub], sub

        if "_" in clean:
            _, rest = clean.split("_", 1)
            if rest in known:
                return rest, ""
            if rest in aliases and aliases[rest] in known:
                return aliases[rest], rest

        if clean in aliases:
            return aliases[clean], clean
        return clean, ""

    def normalize_call_arguments(
        self,
        base_name: str,
        raw_args: Optional[Dict[str, Any]],
        matched_tool_alias: str = "",
    ) -> Dict[str, Any]:
        """Normalize silent legacy tool aliases & cross-host parameter aliases without mutating caller's dict."""
        cleaned_raw = _unsanitize_ipi_obj(dict(raw_args or {}))
        args: Dict[str, Any] = dict(cleaned_raw) if isinstance(cleaned_raw, dict) else {}
        spec = self.get_spec(base_name)

        if matched_tool_alias == "grep_search" and "IsRegex" in args and "fixed_strings" not in args:
            args["fixed_strings"] = not bool(args.pop("IsRegex"))
        elif matched_tool_alias in ("code_outline", "get_code_outline", "extract_code_outline", "view_file_outline", "get_symbols_overview"):
            args["action"] = "outline"
        elif matched_tool_alias in ("repo_map", "get_repo_map"):
            args.setdefault("action", "overview")
        elif matched_tool_alias == "find_symbol":
            args["action"] = "symbol"
        elif matched_tool_alias == "find_referencing_symbols":
            args["action"] = "refs"
        elif matched_tool_alias == "rename_symbol":
            args["action"] = "rename_symbol"
        elif matched_tool_alias == "insert_after_symbol":
            if "symbol" in args and "insert_after_symbol" not in args:
                args["insert_after_symbol"] = args.pop("symbol")
            if "code" in args and "new_text" not in args:
                args["new_text"] = args.pop("code")
        elif matched_tool_alias == "replace_symbol_body":
            if "body" in args and "new_text" not in args:
                args["new_text"] = args.pop("body")
            elif "code" in args and "new_text" not in args:
                args["new_text"] = args.pop("code")
        elif matched_tool_alias == "list_dir":
            args.setdefault("max_depth", 1)
        elif matched_tool_alias == "trash_file":
            args["action"] = "trash"
        elif matched_tool_alias == "undo_edit":
            args.setdefault("action", "undo")
        elif matched_tool_alias == "undo_or_trash":
            args.setdefault("action", "undo")
        elif matched_tool_alias == "restore_trash":
            args.setdefault("action", "restore" if args.get("trash_id") else "list")
        elif matched_tool_alias == "skill_search":
            args.setdefault("action", "search")
        elif matched_tool_alias == "skill_load":
            args.setdefault("action", "load")
        elif matched_tool_alias == "skill_register":
            args.setdefault("action", "create")

        merged_map: Dict[str, str] = {}
        if base_name in DEFAULT_PARAM_ALIASES:
            merged_map.update(DEFAULT_PARAM_ALIASES[base_name])
        if spec is not None and spec.param_aliases:
            merged_map.update(spec.param_aliases)

        for alias_key, canonical_key in merged_map.items():
            if alias_key in args:
                val = args.pop(alias_key)
                if canonical_key not in args or args[canonical_key] in ("", None):
                    args[canonical_key] = val

        if base_name == "write_file" and "overwrite" in args:
            ov = bool(args.pop("overwrite"))
            if not ov and args.get("mode", "overwrite") == "overwrite":
                args["_legacy_disallow_overwrite"] = True
                args.setdefault("disallow_overwrite", True)
        return args

    def rewrite_prefix_in_payload(self, payload: Any) -> Any:
        eff_p = self.prefix
        if eff_p == "pc" or not eff_p:
            return payload
        with self._lock:
            known = sorted(self._specs.keys(), key=len, reverse=True)
        if not known:
            return payload
        pat = re.compile(r"\bpc_(" + "|".join(re.escape(k) for k in known) + r")\b")

        def _walk(node: Any) -> Any:
            if isinstance(node, str):
                return pat.sub(rf"{eff_p}_\1", node)
            if isinstance(node, dict):
                out: Dict[str, Any] = {}
                for k, v in node.items():
                    if k in ("error", "stderr", "hint", "suggestion", "diagnostic", "stdout", "_loop_guard_warning"):
                        out[k] = _walk(v)
                    else:
                        out[k] = v
                return out
            if isinstance(node, list):
                return [_walk(x) for x in node]
            return node

        return _walk(payload)

    def _ordered_profile_bases(self, profile_name: str, enabled_tools: Sequence[str], enabled_packs: Sequence[str]) -> List[str]:
        prof = normalize_toolset_profile(profile_name)
        with self._lock:
            reg_order = list(self._registration_order)
            specs_map = dict(self._specs)
            cap_bases = set(self._capability_tool_bases)

        profile_template = TOOLSET_PROFILES.get(prof, DEFAULT_CORE_TOOLS)
        ordered: List[str] = []
        matched_any_known = any(b in specs_map for b in profile_template)
        if matched_any_known:
            for b in profile_template:
                if b in specs_map and specs_map[b].pack is None and b not in ordered:
                    ordered.append(b)
            for b in reg_order:
                if b in cap_bases and b in specs_map and specs_map[b].pack is None and b not in ordered:
                    ordered.append(b)
        else:
            for b in reg_order:
                if b in specs_map and specs_map[b].pack is None and b not in ordered:
                    ordered.append(b)

        for extra in enabled_tools:
            if extra in specs_map and extra not in ordered:
                ordered.append(extra)

        active_pack_set = set(enabled_packs)
        for b in reg_order:
            sp = specs_map.get(b)
            if sp is not None and sp.pack and sp.pack in active_pack_set and b not in ordered:
                ordered.append(b)
        return ordered

    def active_tool_specs(
        self,
        *,
        scopes: Optional[Iterable[str]] = None,
        readonly_only: bool = False,
        preserve_epoch_snapshot: bool = False,
    ) -> List[ToolSpec]:
        """Compute currently exposed `ToolSpec` list filtered by live `policy`, `scopes`, and `readonly_only`."""
        self.load_registered_capabilities()
        cur_tier, _, _ = self.policy.refresh()
        t_norm = normalize_tier(cur_tier)
        allowed_bands = _TIER_ALLOWED_BANDS.get(t_norm, _TIER_ALLOWED_BANDS["tier3_workspace_dev"])
        is_pure_readonly_mode = bool(readonly_only or t_norm == "tier1_readonly")
        if readonly_only:
            allowed_bands = frozenset({SafetyBand.READONLY})
        elif preserve_epoch_snapshot and (self.policy.tier_epoch > 0 or self.policy.workspace_epoch > 0) and not self.policy.enabled_packs:
            allowed_bands = allowed_bands & frozenset(
                {SafetyBand.READONLY, SafetyBand.WORKSPACE_WRITE, SafetyBand.WORKSPACE_EXEC}
            )

        dis_set = set(self.policy.disabled_tools)
        ordered = self._ordered_profile_bases(
            self.policy.toolset_profile,
            self.policy.enabled_tools,
            () if readonly_only else self.policy.enabled_packs,
        )
        with self._lock:
            specs_map = dict(self._specs)

        out: List[ToolSpec] = []
        for base in ordered:
            if base in dis_set:
                continue
            sp = specs_map.get(base)
            if sp is None:
                continue
            if sp.pack and sp.pack not in self.policy.enabled_packs and base not in self.policy.enabled_tools:
                continue
            if sp.safety_band in allowed_bands and is_band_permitted_by_scopes(sp, scopes):
                if sp.base_name in MIXED_TOOL_READONLY_ACTIONS and (
                    readonly_only
                    or (sp.safety_band == SafetyBand.WORKSPACE_WRITE and not self.policy.allow_edit)
                    or (sp.safety_band == SafetyBand.WORKSPACE_EXEC and not self.policy.allow_exec)
                    or (
                        sp.base_name == "workspace_memory"
                        and scopes is not None
                        and not ({str(s).strip() for s in scopes} & {"workspace", "server:admin"})
                    )
                ):
                    out.append(_project_readonly_mixed_spec(sp))
                else:
                    out.append(sp)
            elif sp.base_name in MIXED_TOOL_READONLY_ACTIONS and SafetyBand.READONLY in allowed_bands:
                ro_sp = _project_readonly_mixed_spec(sp)
                if is_band_permitted_by_scopes(ro_sp, scopes):
                    out.append(ro_sp)
        return out

    def record_seen_epoch(self, session_hint: str) -> None:
        key = (session_hint or "http").strip() or "http"
        with self._lock:
            self._seen_epochs.setdefault(key, (int(self.policy.tier_epoch), int(self.policy.workspace_epoch)))

    def consume_policy_change_notice(self, session_hint: str, caller: str = "") -> Optional[Dict[str, Any]]:
        cur_ep = (int(self.policy.tier_epoch), int(self.policy.workspace_epoch))
        conn_k = (session_hint or "http").strip() or "http"
        eff_c = (caller or "").strip()
        track_k = f"{conn_k}:{eff_c}" if eff_c else conn_k
        with self._lock:
            baseline = self._seen_epochs.get(conn_k, (0, 0))
            prev_ep = self._seen_epochs.get(track_k, baseline)
            self._seen_epochs[track_k] = cur_ep
            if not eff_c:
                self._seen_epochs[conn_k] = cur_ep
            if prev_ep == cur_ep:
                return None
            changed: List[str] = []
            if cur_ep[0] != prev_ep[0]:
                changed.append("tier")
            if cur_ep[1] != prev_ep[1]:
                changed.append("workspace_roots")
            return {
                "tier": self.policy.tier_key,
                "tier_label": self.policy.dynamic_tier_label(),
                "restrict_to_workspace": bool(self.policy.restrict_to_workspace),
                "workspace": self.policy.workspace,
                "workspace_roots": [str(p) for p in self.policy.workspace_roots],
                "changed": changed,
                "tier_epoch": cur_ep[0],
                "workspace_epoch": cur_ep[1],
            }

    def list_tool_dicts(
        self,
        *,
        scopes: Optional[Iterable[str]] = None,
        readonly_only: bool = False,
        session_hint: str = "http",
        zero_popup_annotations: Optional[bool] = None,
        preserve_epoch_snapshot: bool = False,
        description_builder: Optional[Callable[[ToolSpec, List[ToolSpec]], str]] = None,
    ) -> List[Dict[str, Any]]:
        """Serialize exposed tools to standard MCP JSON-RPC `Tool` dictionaries."""
        self.record_seen_epoch(session_hint)
        specs = self.active_tool_specs(
            scopes=scopes,
            readonly_only=readonly_only,
            preserve_epoch_snapshot=preserve_epoch_snapshot,
        )
        is_ro_tier = not self.policy.allow_edit or readonly_only
        ann_mode_low = str(getattr(self.policy, "annotation_mode", "") or "").strip().lower()
        if zero_popup_annotations is not None:
            eff_seamless = bool(zero_popup_annotations) and not readonly_only
        elif bool(getattr(self.policy, "approval_popups", False)) or ann_mode_low in (
            "honest",
            "strict",
            "confirm",
            "prompt",
            "popups",
        ):
            eff_seamless = False
        elif ann_mode_low in ("compat", "seamless", "auto", "zero_popup", "silent"):
            eff_seamless = not readonly_only
        else:
            eff_seamless = not readonly_only
        tools_out: List[Dict[str, Any]] = []
        for sp in specs:
            schema = json.loads(json.dumps(sp.input_schema))
            if is_ro_tier:
                act_p = (schema.get("properties") or {}).get(sp.action_param)
                if isinstance(act_p, dict):
                    if sp.base_name == "workspace_memory":
                        act_p["enum"] = ["read", "search"]
                    elif sp.base_name == "skill_manage":
                        act_p["enum"] = ["list", "trash_list"]
                    elif sp.base_name == "code_intel":
                        cur_enum = act_p.get("enum") or list(sp.action_enum)
                        act_p["enum"] = [str(v) for v in cur_enum if str(v) != "rename_symbol"]
            desc = (
                description_builder(sp, specs)
                if description_builder is not None
                else (f"{sp.description} {sp.nudge_prefer}".strip() if sp.nudge_prefer else (sp.description or f"Execute {self.prefixed_name(sp.base_name)}."))
            )
            desc = self.rewrite_prefix_in_payload(desc)
            if eff_seamless or sp.safety_band == SafetyBand.READONLY:
                ann = {
                    "title": sp.title,
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": bool(sp.open_world) if not eff_seamless else False,
                }
            elif sp.safety_band == SafetyBand.WORKSPACE_WRITE:
                ann = {
                    "title": sp.title,
                    "readOnlyHint": False,
                    "destructiveHint": True,
                    "idempotentHint": bool(sp.idempotent),
                    "openWorldHint": False,
                }
            else:
                ann = {
                    "title": sp.title,
                    "readOnlyHint": False,
                    "destructiveHint": True,
                    "idempotentHint": False,
                    "openWorldHint": bool(sp.open_world),
                }
            tools_out.append(
                {
                    "name": self.prefixed_name(sp.base_name),
                    "title": sp.title,
                    "description": desc,
                    "inputSchema": schema,
                    "annotations": ann,
                }
            )
        return tools_out

    def _emit_audit(self, event: AuditEvent) -> None:
        with self._lock:
            self._recent_audit.append(event)
            callbacks = list(self._audit_slots.values())
        for cb in callbacks:
            try:
                cb(event)
            except Exception:
                pass

    def check_call_gate(
        self,
        spec: Optional[ToolSpec],
        requested_name: str,
        resolved_name: str,
        *,
        scopes: Optional[Iterable[str]] = None,
        readonly_only: bool = False,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        cur_tier, _, _ = self.policy.refresh()
        t_norm = normalize_tier(cur_tier)

        if spec is None:
            return {
                "ok": False,
                "unknown_tool": True,
                "tool": requested_name,
                "error": f"Unknown tool `{requested_name}`.",
            }

        if spec.base_name in self.policy.disabled_tools:
            return {
                "ok": False,
                "blocked_by_tool_filter": True,
                "tool": resolved_name,
                "disabled_tools": list(self.policy.disabled_tools),
                "error": f"[LOCALPC TOOLFILTER BLOCKED]: Tool `{resolved_name}` is disabled in `disabled_tools`.",
            }

        if spec.pack and spec.pack not in self.policy.enabled_packs and spec.base_name not in self.policy.enabled_tools:
            return {
                "ok": False,
                "blocked_by_tool_filter": True,
                "tool": resolved_name,
                "pack": spec.pack,
                "enabled_packs": list(self.policy.enabled_packs),
                "error": f"[LOCALPC PACK BLOCKED]: Peripheral pack `{spec.pack}` for `{resolved_name}` is not enabled.",
            }

        is_mixed = spec.base_name in MIXED_TOOL_READONLY_ACTIONS
        is_ro_act, eff_act = (
            is_mixed_tool_readonly_action(spec.base_name, arguments, action_param=spec.action_param)
            if is_mixed
            else (False, "")
        )
        if spec.base_name == "bg_command" and eff_act == "check_update":
            is_ro_act = True
        eff_spec_for_scope = spec

        if readonly_only:
            if is_mixed:
                if not is_ro_act:
                    ro_allowed = list(MIXED_TOOL_READONLY_ACTIONS[spec.base_name])
                    return {
                        "ok": False,
                        "error_code": "ERR_READONLY_ACTION_BLOCKED",
                        "tier_error_code": "ERR_TIER_DENIED",
                        "blocked_by_readonly_endpoint": True,
                        "blocked_by_readonly_action": True,
                        "tool": resolved_name,
                        "action": eff_act,
                        "allowed_readonly_actions": ro_allowed,
                        "safety_band": spec.safety_band.value,
                        "error": (
                            f"[READONLY ENDPOINT BLOCKED] (ERR_READONLY_ACTION_BLOCKED): "
                            f"`{resolved_name}` action='{eff_act}' is forbidden on `/mcp/readonly` "
                            f"(allowed read-only actions: {ro_allowed})."
                        ),
                    }
                eff_spec_for_scope = _project_readonly_mixed_spec(spec)
            elif spec.safety_band != SafetyBand.READONLY:
                return {
                    "ok": False,
                    "error_code": "ERR_READONLY_ACTION_BLOCKED",
                    "blocked_by_readonly_endpoint": True,
                    "tool": resolved_name,
                    "safety_band": spec.safety_band.value,
                    "error": f"[READONLY ENDPOINT BLOCKED] (ERR_READONLY_ACTION_BLOCKED): Tool `{resolved_name}` ({spec.safety_band.value}) is forbidden on `/mcp/readonly`.",
                }

        allowed_bands = _TIER_ALLOWED_BANDS.get(t_norm, _TIER_ALLOWED_BANDS["tier3_workspace_dev"])
        if spec.safety_band not in allowed_bands:
            if is_mixed and is_ro_act and SafetyBand.READONLY in allowed_bands:
                eff_spec_for_scope = _project_readonly_mixed_spec(spec)
            else:
                ro_allowed_hint = list(MIXED_TOOL_READONLY_ACTIONS.get(spec.base_name, ()))
                err_payload: Dict[str, Any] = {
                    "ok": False,
                    "error_code": "ERR_READONLY_ACTION_BLOCKED" if is_mixed else "ERR_TIER_DENIED",
                    "tier_error_code": "ERR_TIER_DENIED",
                    "blocked_by_permission_tier": True,
                    "tool": resolved_name,
                    "permission_tier": t_norm,
                    "permission_label": self.policy.dynamic_tier_label(t_norm),
                    "error": (
                        f"[LOCALPC PERMISSION TIER BLOCKED] (ERR_TIER_DENIED / ERR_READONLY_ACTION_BLOCKED): "
                        f"`{resolved_name}`"
                        + (f" action='{eff_act}'" if is_mixed else f" ({spec.safety_band.value})")
                        + f" is disabled in tier `{t_norm}`."
                    ),
                }
                if is_mixed:
                    err_payload["action"] = eff_act
                    err_payload["blocked_by_readonly_action"] = True
                    err_payload["allowed_readonly_actions"] = ro_allowed_hint
                return err_payload

        if spec.base_name == "workspace_memory" and not self.policy.allow_edit:
            if not is_ro_act:
                return {
                    "ok": False,
                    "error_code": "ERR_READONLY_ACTION_BLOCKED",
                    "tier_error_code": "ERR_TIER_DENIED",
                    "blocked_by_permission_tier": True,
                    "blocked_by_readonly_action": True,
                    "tool": resolved_name,
                    "action": eff_act,
                    "permission_tier": t_norm,
                    "allowed_readonly_actions": list(MIXED_TOOL_READONLY_ACTIONS["workspace_memory"]),
                    "error": (
                        f"[LOCALPC PERMISSION TIER BLOCKED] (ERR_TIER_DENIED / ERR_READONLY_ACTION_BLOCKED): "
                        f"`{resolved_name}` action='{eff_act}' is disabled in read-only tier `{t_norm}`."
                    ),
                }
            eff_spec_for_scope = _project_readonly_mixed_spec(spec)

        if not is_band_permitted_by_scopes(eff_spec_for_scope, scopes):
            if is_mixed and is_ro_act and is_band_permitted_by_scopes(_project_readonly_mixed_spec(spec), scopes):
                return None
            return {
                "ok": False,
                "blocked_by_oauth_scope": True,
                "tool": resolved_name,
                "safety_band": eff_spec_for_scope.safety_band.value,
                "error": f"[OAUTH SCOPE BLOCKED]: Token scopes do not permit `{resolved_name}` ({eff_spec_for_scope.safety_band.value}).",
            }
        return None

    @staticmethod
    def _filter_kwargs_for_handler(handler: Callable[..., Any], args: Dict[str, Any]) -> Dict[str, Any]:
        clean_args = {k: v for k, v in args.items() if not k.startswith("_legacy_")}
        try:
            sig = inspect.signature(handler)
        except (TypeError, ValueError):
            return clean_args
        for param in sig.parameters.values():
            if param.kind == inspect.Parameter.VAR_KEYWORD:
                return clean_args
        accepted = {
            name
            for name, param in sig.parameters.items()
            if param.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
        }
        return {k: v for k, v in clean_args.items() if k in accepted}

    def _extract_and_strip_target(
        self,
        base_name: str,
        raw_args: Optional[Dict[str, Any]],
    ) -> Tuple[str, Dict[str, Any]]:
        """Extract and strip routing `target` before local argument normalization & path pre-checks."""
        cleaned_raw = _unsanitize_ipi_obj(dict(raw_args or {}))
        args_copy: Dict[str, Any] = dict(cleaned_raw) if isinstance(cleaned_raw, dict) else {}
        if "target" not in args_copy:
            return "auto", args_copy
        raw_target_val = args_copy.pop("target")
        target_str = str(raw_target_val or "").strip()
        if not target_str:
            return "auto", args_copy

        # Preserve legacy `manage_files(action='move'|'rename'|'copy', path=..., target='<dest_path>')` only when
        # `destination` is absent and `target` is clearly a filesystem path rather than `"auto"`/`"local"`/node_id.
        if (
            base_name == "manage_files"
            and str(args_copy.get("action") or "").strip().lower() in ("move", "rename", "copy")
            and not any(k in args_copy for k in ("destination", "dest", "dst", "new_path"))
        ):
            t_low = target_str.lower()
            with self._lock:
                known_nodes_low = {k.lower() for k in self._remote_nodes}
            local_names_low = {
                "auto",
                "local",
                "server",
                self.prefix.lower(),
                self.policy.eff_prefix.lower(),
                str(getattr(self.policy, "instance_id", "") or "").lower(),
                str(getattr(self.policy, "device_label", "") or "").lower(),
            }
            if t_low not in local_names_low and t_low not in known_nodes_low and (
                "/" in target_str or "\\" in target_str or "." in target_str
            ):
                args_copy["destination"] = target_str
                return "auto", args_copy

        return target_str, args_copy

    def _resolve_remote_route(
        self,
        req_target: str,
        norm_args: Dict[str, Any],
        *,
        session_hint: str = "",
        base_name: str = "",
        bound_node_id: str = "",
    ) -> Tuple[str, Optional[Dict[str, Any]], Optional[Callable[..., Any]]]:
        """
        Return `(route_mode, node_entry, forwarder_fn)`:
        - `route_mode == "local"`: execute on this host
        - `route_mode == "remote"`: forward via `forwarder_fn` to `node_entry`
        - `route_mode == "offline"`: return structured `ERR_NODE_OFFLINE` without raising HTTP 502
        """
        import sys as _sys

        t_clean = (req_target or "").strip()
        t_low = t_clean.lower()
        is_vps_hub = self.is_vps_hub_active()
        explicit_local_targets = {"local", "server", "vps", "vps_hub", "hub"}
        local_aliases = set(explicit_local_targets)
        for cand_local in (
            self.prefix.lower(),
            self.policy.eff_prefix.lower(),
            str(getattr(self.policy, "instance_id", "") or "").lower(),
            str(getattr(self.policy, "device_label", "") or "").strip().lower(),
        ):
            if not cand_local:
                continue
            if is_vps_hub and cand_local in ("pc", "pc1", "cosmos-pc"):
                continue
            local_aliases.add(cand_local)

        with self._lock:
            nodes_snapshot = dict(self._remote_nodes)
            global_fwd = self._remote_forwarder

        def _find_node_by_key(key_raw: str) -> Optional[Dict[str, Any]]:
            k_clean = (key_raw or "").strip()
            k_low = k_clean.lower()
            if not k_low:
                return None
            direct = nodes_snapshot.get(k_clean)
            if direct is not None:
                return direct
            for n_info in nodes_snapshot.values():
                if (
                    str(n_info.get("node_id") or "").lower() == k_low
                    or str(n_info.get("device_label") or "").lower() == k_low
                ):
                    return n_info
            return None

        if not t_clean or t_low == "auto":
            if session_hint == "vps_hub_node":
                return "local", None, None

            eff_bound = (bound_node_id or self.bound_node_id or "").strip()
            if eff_bound and eff_bound.lower() not in explicit_local_targets:
                b_node = _find_node_by_key(eff_bound)
                if b_node is not None and b_node.get("online", False):
                    b_fwd = b_node.get("forwarder") or global_fwd
                    if b_fwd is not None:
                        return "remote", b_node, b_fwd
                return "offline", (b_node or {"node_id": eff_bound}), None

            if not nodes_snapshot:
                return "local", None, None

            eff_host_plat = str(getattr(self, "_host_platform", "") or _sys.platform).lower()
            is_local_win = eff_host_plat.startswith("win")
            online_nodes: List[Dict[str, Any]] = [
                n_info
                for n_info in nodes_snapshot.values()
                if n_info.get("online", False) and (n_info.get("forwarder") or global_fwd) is not None
            ]
            offline_nodes: List[Dict[str, Any]] = [
                n_info for n_info in nodes_snapshot.values() if not n_info.get("online", False)
            ]
            has_any_win_remote = any(
                str(n.get("platform") or "").lower().startswith("win") or bool(n.get("drives"))
                for n in nodes_snapshot.values()
            )

            def _pick_preferred_pc_node(cands: Sequence[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
                if not cands:
                    return None
                win_cands = [
                    n
                    for n in cands
                    if str(n.get("platform") or "").lower().startswith("win") or bool(n.get("drives"))
                ]
                pool = win_cands if win_cands else list(cands)
                for n in pool:
                    if str(n.get("node_id") or "").lower() in ("pc", "pc1"):
                        return n
                return pool[0]

            cand_paths: List[str] = []
            for pk in ("path", "cwd", "destination"):
                pv = norm_args.get(pk)
                if isinstance(pv, str) and pv.strip():
                    cand_paths.append(strip_file_uri(pv.strip()))
            edits_v = norm_args.get("edits")
            if isinstance(edits_v, list):
                for ed in edits_v[:8]:
                    if isinstance(ed, dict):
                        ep = ed.get("path") or ed.get("file_path")
                        if isinstance(ep, str) and ep.strip():
                            cand_paths.append(strip_file_uri(ep.strip()))
            for opt_pk in ("venv", "python_path", "source"):
                opv = norm_args.get(opt_pk)
                if isinstance(opv, str):
                    op_s = opv.strip()
                    if op_s and not re.match(r"^(?:https?|git)://|^git@", op_s, re.IGNORECASE):
                        if "/" in op_s or "\\" in op_s or re.match(r"^[A-Za-z]:", op_s):
                            cand_paths.append(strip_file_uri(op_s))

            if not cand_paths:
                default_online = _pick_preferred_pc_node(online_nodes)
                if default_online is not None:
                    return "remote", default_online, (default_online.get("forwarder") or global_fwd)
                if (
                    offline_nodes
                    and base_name in VPS_HUB_WORKSPACE_TOOL_BASES
                    and self.is_stock_or_empty_vps_hub_workspace()
                ):
                    return "offline", _pick_preferred_pc_node(offline_nodes), None
                return "local", None, None

            local_ws_norms: List[str] = []
            for loc_ws in (*self.policy.workspace_roots, *getattr(self.policy, "readonly_workspace_roots", ())):
                try:
                    lw_norm = str(Path(loc_ws).resolve()).replace("\\", "/").rstrip("/").lower()
                    if lw_norm:
                        local_ws_norms.append(lw_norm)
                except Exception:
                    pass

            def _is_under_local_ws(norm_p: str) -> bool:
                for lw in local_ws_norms:
                    if norm_p == lw or norm_p.startswith(lw + "/"):
                        return True
                return False

            def _classify_win_path(raw_p: str) -> Tuple[bool, str]:
                m_drv = re.match(r"^([A-Za-z]:)(?:[\\/]|$)", raw_p)
                if m_drv:
                    return True, m_drv.group(1).lower()
                if re.match(r"^\\\\[^\\/]+", raw_p):
                    return True, ""
                if re.match(
                    r"^(?:%[A-Za-z_][A-Za-z0-9_]*%|\$env:[A-Za-z_][A-Za-z0-9_]*)(?:[\\/]|$)",
                    raw_p,
                    re.IGNORECASE,
                ):
                    return True, ""
                m_gb = re.match(r"^/([A-Za-z])(?:/|$)", raw_p)
                if m_gb and has_any_win_remote:
                    gb_letter = m_gb.group(1)
                    if is_local_win or not Path(f"/{gb_letter}").exists():
                        return True, f"{gb_letter.lower()}:"
                return False, ""

            def _match_ws_prefix(norm_p: str, cands: Sequence[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
                best_node: Optional[Dict[str, Any]] = None
                best_len = -1
                for n_info in cands:
                    for r_ws in n_info.get("workspace_roots") or ():
                        rw_norm = str(r_ws).replace("\\", "/").rstrip("/").lower()
                        if rw_norm and (norm_p == rw_norm or norm_p.startswith(rw_norm + "/")):
                            if len(rw_norm) > best_len:
                                best_len = len(rw_norm)
                                best_node = n_info
                return best_node

            has_local_abs_path = False
            has_relative_path = False

            for cp in cand_paths:
                cp_norm = cp.replace("\\", "/").rstrip("/").lower()
                if is_local_win and ("%" in cp or "$" in cp):
                    cp_norm = expand_env_and_tilde(cp).replace("\\", "/").rstrip("/").lower()
                is_under_loc = _is_under_local_ws(cp_norm) if cp_norm else False

                # 1) Explicit remote workspace root prefix match (online first, then offline)
                if cp_norm and not is_under_loc:
                    ws_online = _match_ws_prefix(cp_norm, online_nodes)
                    if ws_online is not None:
                        return "remote", ws_online, (ws_online.get("forwarder") or global_fwd)
                    ws_offline = _match_ws_prefix(cp_norm, offline_nodes)
                    if ws_offline is not None:
                        return "offline", ws_offline, None

                # 2) Explicit Windows drive / UNC / Windows env / Git-Bash drive path
                is_win_p, drv_low = _classify_win_path(cp)
                if is_win_p:
                    if is_local_win and is_under_loc:
                        has_local_abs_path = True
                        continue
                    if drv_low:
                        for n_info in online_nodes:
                            if drv_low in (n_info.get("drives") or ()):
                                return "remote", n_info, (n_info.get("forwarder") or global_fwd)
                    win_online = _pick_preferred_pc_node(
                        [
                            n
                            for n in online_nodes
                            if str(n.get("platform") or "").lower().startswith("win")
                            or bool(n.get("drives"))
                            or not is_local_win
                        ]
                    )
                    if win_online is not None:
                        return "remote", win_online, (win_online.get("forwarder") or global_fwd)

                    if drv_low:
                        for n_info in offline_nodes:
                            if drv_low in (n_info.get("drives") or ()):
                                return "offline", n_info, None
                    if not is_local_win and offline_nodes:
                        off_pc = _pick_preferred_pc_node(offline_nodes)
                        return "offline", off_pc, None
                    if is_local_win:
                        has_local_abs_path = True
                    continue

                # 3) Explicit POSIX / Linux absolute path (starts with `/`, e.g. `/etc/hosts`, `/opt/...`, `/var/...`)
                if cp.startswith("/"):
                    has_local_abs_path = True
                    continue

                # 4) Relative path (`.`, `./...`, `docs/a.docx`, `月度预算.xlsx`, `~/...`)
                has_relative_path = True

            if has_local_abs_path:
                return "local", None, None

            if has_relative_path:
                default_online = _pick_preferred_pc_node(online_nodes)
                if default_online is not None:
                    return "remote", default_online, (default_online.get("forwarder") or global_fwd)
                if (
                    offline_nodes
                    and base_name in VPS_HUB_WORKSPACE_TOOL_BASES
                    and self.is_stock_or_empty_vps_hub_workspace()
                ):
                    return "offline", _pick_preferred_pc_node(offline_nodes), None

            return "local", None, None

        if t_low in explicit_local_targets:
            return "local", None, None

        matched_node = _find_node_by_key(t_clean)
        if matched_node is not None:
            if matched_node.get("online", False):
                eff_fwd = matched_node.get("forwarder") or global_fwd
                if eff_fwd is not None:
                    return "remote", matched_node, eff_fwd
            return "offline", matched_node, None

        if t_low in local_aliases:
            return "local", None, None

        return "offline", None, None

    @staticmethod
    async def _invoke_remote_forwarder(
        fwd_fn: Callable[..., Any],
        target_node_id: str,
        base_name: str,
        resolved_name: str,
        forward_args: Dict[str, Any],
        ctx: ToolCallContext,
    ) -> Any:
        call_kw: Dict[str, Any] = {}
        pos_args: Tuple[Any, ...] = (target_node_id, base_name, forward_args)
        try:
            sig = inspect.signature(fwd_fn)
            params = list(sig.parameters.values())
            has_var_pos = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)
            has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)
            pos_params = [
                p for p in params if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
            ]
            if len(pos_params) == 1 and not has_var_pos:
                pos_args = (
                    {
                        "target": target_node_id,
                        "tool": resolved_name,
                        "base_name": base_name,
                        "arguments": forward_args,
                        "readonly_only": ctx.readonly_endpoint,
                        "caller": ctx.caller,
                    },
                )
            elif len(pos_params) == 2 and not has_var_pos:
                pos_args = (target_node_id, forward_args)
            else:
                extra_candidates = {
                    "tool_name": resolved_name,
                    "readonly_only": ctx.readonly_endpoint,
                    "scopes": ctx.scopes,
                    "caller": ctx.caller,
                    "context": ctx,
                }
                for ek, ev in extra_candidates.items():
                    if has_var_kw or ek in sig.parameters:
                        if ek not in [p.name for p in pos_params[:3]]:
                            call_kw[ek] = ev
        except (TypeError, ValueError):
            pass

        if inspect.iscoroutinefunction(fwd_fn):
            return await fwd_fn(*pos_args, **call_kw)
        maybe_coro = await asyncio.to_thread(fwd_fn, *pos_args, **call_kw)
        if inspect.isawaitable(maybe_coro):
            return await maybe_coro
        return maybe_coro

    async def call_tool_raw(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
        *,
        scopes: Optional[Iterable[str]] = None,
        readonly_only: bool = False,
        session_hint: str = "http",
        client_platform: str = "",
        bound_node_id: str = "",
    ) -> Tuple[Any, bool]:
        """Dispatch a tool call and return `(payload_or_blocks, is_error)`."""
        t0 = time.monotonic()
        self.load_registered_capabilities()
        call_id = f"call_{int(time.time() * 1000)}_{secrets.token_hex(4)}"
        base_name, matched_alias = self.strip_prefix_and_resolve_base(name)
        spec = self.get_spec(base_name)
        resolved_name = self.prefixed_name(base_name) if spec is not None else (name or "")
        req_target, stripped_raw_args = self._extract_and_strip_target(base_name, arguments)
        norm_args = self.normalize_call_arguments(base_name, stripped_raw_args, matched_tool_alias=matched_alias)
        norm_args.pop("target", None)
        caller = str(norm_args.get("caller") or "").strip()
        scope_fset = frozenset(str(s) for s in scopes) if scopes is not None else None

        notice = self.consume_policy_change_notice(session_hint=session_hint, caller=caller)
        gate_err = self.check_call_gate(
            spec,
            name,
            resolved_name,
            scopes=scope_fset,
            readonly_only=readonly_only,
            arguments=norm_args,
        )
        if gate_err is not None:
            gate_err = self.rewrite_prefix_in_payload(gate_err)
            if notice is not None:
                gate_err = {"_policy_change_notice": notice, **gate_err}
            dur_ms = round((time.monotonic() - t0) * 1000, 2)
            blocked_tag = next(
                (k for k in ("blocked_by_readonly_endpoint", "blocked_by_permission_tier", "blocked_by_oauth_scope", "blocked_by_tool_filter", "unknown_tool") if gate_err.get(k)),
                "blocked",
            )
            self._emit_audit(
                AuditEvent(
                    call_id=call_id,
                    ts=time.time(),
                    caller=caller,
                    tool=name,
                    resolved_tool=resolved_name,
                    base_name=base_name,
                    safety_band=spec.safety_band.value if spec else "UNKNOWN",
                    tier=self.policy.tier_key,
                    ok=False,
                    duration_ms=dur_ms,
                    error=str(gate_err.get("error") or ""),
                    blocked_reason=blocked_tag,
                )
            )
            return gate_err, True

        assert spec is not None
        ctx = ToolCallContext(
            call_id=call_id,
            requested_name=name,
            resolved_name=resolved_name,
            base_name=base_name,
            prefix=self.prefix,
            arguments=norm_args,
            caller=caller,
            session_hint=session_hint,
            safety_band=spec.safety_band,
            tier_key=self.policy.tier_key,
            scopes=scope_fset,
            readonly_endpoint=readonly_only,
            client_platform=client_platform,
        )

        eff_bound_nid = (bound_node_id or "").strip()
        if not eff_bound_nid and "_" in (name or ""):
            cand_nid = (name or "").strip().split("_", 1)[0].lower()
            if cand_nid and cand_nid != self.prefix.lower():
                with self._lock:
                    if any(str(k).lower() == cand_nid for k in self._remote_nodes):
                        eff_bound_nid = cand_nid

        # Short-circuit multi-PC `target` routing BEFORE local WorkspaceGuard / hooks path pre-checks
        route_mode, remote_node, fwd_fn = self._resolve_remote_route(
            req_target,
            norm_args,
            session_hint=session_hint,
            base_name=base_name,
            bound_node_id=eff_bound_nid,
        )
        if route_mode == "offline":
            clean_req_t = req_target if req_target.strip().lower() not in ("", "auto") else ""
            offline_target = str((remote_node or {}).get("node_id") or eff_bound_nid or clean_req_t or "pc")
            offline_payload: Dict[str, Any] = {
                "ok": False,
                "error_code": "ERR_NODE_OFFLINE",
                "target": offline_target,
                "message": f"目标节点 '{offline_target}' 当前离线或关机，主站服务仍在线运行。",
            }
            if notice is not None:
                offline_payload = {"_policy_change_notice": notice, **offline_payload}
            dur_ms = round((time.monotonic() - t0) * 1000, 2)
            self._emit_audit(
                AuditEvent(
                    call_id=call_id,
                    ts=time.time(),
                    caller=caller,
                    tool=name,
                    resolved_tool=resolved_name,
                    base_name=base_name,
                    safety_band=spec.safety_band.value,
                    tier=self.policy.tier_key,
                    ok=False,
                    duration_ms=dur_ms,
                    error=offline_payload["message"],
                    blocked_reason="node_offline",
                )
            )
            return offline_payload, True

        if route_mode == "remote" and remote_node is not None and fwd_fn is not None:
            target_nid = str(remote_node.get("node_id") or req_target)
            self._inflight_count += 1
            try:
                rem_res = await self._invoke_remote_forwarder(
                    fwd_fn, target_nid, base_name, resolved_name, dict(norm_args), ctx
                )
            except (ConnectionError, TimeoutError, OSError):
                rem_offline: Dict[str, Any] = {
                    "ok": False,
                    "error_code": "ERR_NODE_OFFLINE",
                    "target": target_nid,
                    "message": f"目标节点 '{target_nid}' 当前离线或关机，主站服务仍在线运行。",
                }
                if notice is not None:
                    rem_offline = {"_policy_change_notice": notice, **rem_offline}
                dur_ms = round((time.monotonic() - t0) * 1000, 2)
                self._emit_audit(
                    AuditEvent(
                        call_id=call_id,
                        ts=time.time(),
                        caller=caller,
                        tool=name,
                        resolved_tool=resolved_name,
                        base_name=base_name,
                        safety_band=spec.safety_band.value,
                        tier=self.policy.tier_key,
                        ok=False,
                        duration_ms=dur_ms,
                        error=rem_offline["message"],
                        blocked_reason="node_offline",
                    )
                )
                return rem_offline, True
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit, asyncio.CancelledError)):
                    raise
                rem_res = {
                    "ok": False,
                    "tool": resolved_name,
                    "target": target_nid,
                    "error": redact_sensitive_output(f"{type(exc).__name__}: {exc}"),
                }
            finally:
                self._inflight_count = max(0, self._inflight_count - 1)

            rem_res = self.rewrite_prefix_in_payload(rem_res)
            if notice is not None and isinstance(rem_res, dict):
                rem_res = {"_policy_change_notice": notice, **rem_res}
            rem_is_err = bool(isinstance(rem_res, dict) and rem_res.get("ok") is False)
            dur_ms = round((time.monotonic() - t0) * 1000, 2)
            self._emit_audit(
                AuditEvent(
                    call_id=call_id,
                    ts=time.time(),
                    caller=caller,
                    tool=name,
                    resolved_tool=resolved_name,
                    base_name=base_name,
                    safety_band=spec.safety_band.value,
                    tier=self.policy.tier_key,
                    ok=not rem_is_err,
                    duration_ms=dur_ms,
                    error=redact_sensitive_output(str((rem_res or {}).get("error") or (rem_res or {}).get("message") or ""))[:400]
                    if rem_is_err and isinstance(rem_res, dict)
                    else "",
                )
            )
            return rem_res, rem_is_err

        with self._lock:
            hooks = list(self._hooks)

        for hk in hooks:
            short_circuit = hk.before_call(ctx)
            if short_circuit is not None:
                out_sc = self.rewrite_prefix_in_payload(short_circuit)
                if notice is not None and isinstance(out_sc, dict):
                    out_sc = {"_policy_change_notice": notice, **out_sc}
                dur_ms = round((time.monotonic() - t0) * 1000, 2)
                is_err_sc = bool(isinstance(out_sc, dict) and out_sc.get("ok") is False)
                self._emit_audit(
                    AuditEvent(
                        call_id=call_id,
                        ts=time.time(),
                        caller=caller,
                        tool=name,
                        resolved_tool=resolved_name,
                        base_name=base_name,
                        safety_band=spec.safety_band.value,
                        tier=self.policy.tier_key,
                        ok=not is_err_sc,
                        duration_ms=dur_ms,
                        error=str(out_sc.get("error") or "") if isinstance(out_sc, dict) and is_err_sc else "",
                        blocked_reason="hook_short_circuit" if is_err_sc else "",
                    )
                )
                return out_sc, is_err_sc

        if base_name == "write_file" and (
            norm_args.get("_legacy_disallow_overwrite") or norm_args.get("disallow_overwrite")
        ) and str(norm_args.get("mode") or "overwrite") == "overwrite":
            raw_target = str(norm_args.get("path") or "").strip()
            if raw_target:
                cand_p = Path(expand_env_and_tilde(raw_target)).expanduser()
                if not cand_p.is_absolute():
                    cand_p = (self.policy.primary_workspace / cand_p).resolve()
                else:
                    cand_p = cand_p.resolve()
                if self.policy.is_path_allowed(cand_p) and cand_p.exists():
                    ov_err: Dict[str, Any] = {
                        "ok": False,
                        "blocked_by_disallow_overwrite": True,
                        "tool": resolved_name,
                        "path": str(cand_p),
                        "error": f"File already exists and overwrite=False: `{cand_p}`.",
                    }
                    ov_err = self.rewrite_prefix_in_payload(ov_err)
                    if notice is not None:
                        ov_err = {"_policy_change_notice": notice, **ov_err}
                    dur_ms = round((time.monotonic() - t0) * 1000, 2)
                    self._emit_audit(
                        AuditEvent(
                            call_id=call_id,
                            ts=time.time(),
                            caller=caller,
                            tool=name,
                            resolved_tool=resolved_name,
                            base_name=base_name,
                            safety_band=spec.safety_band.value,
                            tier=self.policy.tier_key,
                            ok=False,
                            duration_ms=dur_ms,
                            error=str(ov_err.get("error") or ""),
                            blocked_reason="disallow_overwrite",
                        )
                    )
                    return ov_err, True

        self._inflight_count += 1
        caught_exc: Optional[BaseException] = None
        result: Any = None
        try:
            call_kwargs = self._filter_kwargs_for_handler(spec.handler, norm_args)
            if inspect.iscoroutinefunction(spec.handler):
                result = await spec.handler(**call_kwargs)
            else:
                maybe_coro = await asyncio.to_thread(spec.handler, **call_kwargs)
                if inspect.isawaitable(maybe_coro):
                    result = await maybe_coro
                else:
                    result = maybe_coro
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit, asyncio.CancelledError)):
                raise
            caught_exc = exc
            raw_err = f"{type(exc).__name__}: {exc}"
            if isinstance(exc, OSError) and (
                isinstance(exc, PermissionError)
                or getattr(exc, "winerror", None) in (32, 33)
                or getattr(exc, "errno", None) in (13, 16)
            ):
                target_p = norm_args.get("path") or getattr(exc, "filename", None)
                if target_p:
                    try:
                        cand_lock_p = Path(expand_env_and_tilde(str(target_p))).expanduser()
                        if not cand_lock_p.is_absolute():
                            cand_lock_p = (self.policy.primary_workspace / cand_lock_p).resolve()
                        lock_diag = check_office_or_os_file_lock(
                            cand_lock_p,
                            exc=exc,
                            for_write=(spec.safety_band != SafetyBand.READONLY),
                        )
                        if isinstance(lock_diag, dict) and lock_diag.get("error"):
                            raw_err = f"{lock_diag['error']} ({raw_err})"
                        elif isinstance(lock_diag, str) and lock_diag:
                            raw_err = f"{lock_diag} ({raw_err})"
                    except Exception:
                        pass
            result = {
                "ok": False,
                "tool": resolved_name,
                "error": redact_sensitive_output(raw_err),
            }
        finally:
            self._inflight_count = max(0, self._inflight_count - 1)

        dur_ms = round((time.monotonic() - t0) * 1000, 2)
        for hk in hooks:
            try:
                result = hk.after_call(ctx, result, caught_exc, dur_ms)
            except Exception:
                pass

        result = self.rewrite_prefix_in_payload(result)
        if notice is not None and isinstance(result, dict):
            result = {"_policy_change_notice": notice, **result}

        is_error = caught_exc is not None or (isinstance(result, dict) and result.get("ok") is False)
        err_str = ""
        if is_error and isinstance(result, dict):
            err_str = redact_sensitive_output(str(result.get("error") or result.get("stderr") or ""))[:400]

        self._emit_audit(
            AuditEvent(
                call_id=call_id,
                ts=time.time(),
                caller=caller,
                tool=name,
                resolved_tool=resolved_name,
                base_name=base_name,
                safety_band=spec.safety_band.value,
                tier=self.policy.tier_key,
                ok=not is_error,
                duration_ms=dur_ms,
                error=err_str,
            )
        )
        return result, is_error
