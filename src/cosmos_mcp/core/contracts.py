"""Pure-stdlib shared contracts for tool specifications, safety bands, peripheral packs, hooks, and runtime paths.

Zero third-party dependencies (Python >=3.9 standard library only) so core tools, optional packs,
and capability providers can declare `ToolSpec`, `PackPlugin`, and `ExecutionHook` directly.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path
import re
from typing import Any, Callable, Dict, Optional, Pattern, Protocol, Sequence, Tuple

UNAMBIGUOUS_PW_ALPHABET: str = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
UNAMBIGUOUS_PW_PREFIX_RE: Pattern[str] = re.compile(r"^[a-z][a-z0-9_]{0,15}$")

TIER_ORDER: Tuple[str, ...] = (
    "tier1_readonly",
    "tier2_workspace_edit",
    "tier3_workspace_dev",
    "tier4_full_power",
)

TIER_NUMERIC_LEVEL: Dict[str, int] = {
    "tier1_readonly": 1,
    "tier2_workspace_edit": 2,
    "tier3_workspace_dev": 3,
    "tier4_full_power": 4,
    "L1": 1,
    "L2": 2,
    "L3": 3,
    "L4": 4,
}

CANONICAL_TIER_MAP: Dict[str, str] = {
    "1": "tier1_readonly",
    "l1": "tier1_readonly",
    "readonly": "tier1_readonly",
    "tier1": "tier1_readonly",
    "tier1_readonly": "tier1_readonly",
    "2": "tier2_workspace_edit",
    "l2": "tier2_workspace_edit",
    "edit": "tier2_workspace_edit",
    "tier2": "tier2_workspace_edit",
    "tier2_workspace_edit": "tier2_workspace_edit",
    "3": "tier3_workspace_dev",
    "l3": "tier3_workspace_dev",
    "dev": "tier3_workspace_dev",
    "standard": "tier3_workspace_dev",
    "tier3": "tier3_workspace_dev",
    "tier3_workspace_dev": "tier3_workspace_dev",
    "4": "tier4_full_power",
    "l4": "tier4_full_power",
    "full": "tier4_full_power",
    "max": "tier4_full_power",
    "agent": "tier4_full_power",
    "tier4": "tier4_full_power",
    "tier4_full_agent": "tier4_full_power",
    "tier4_full_access": "tier4_full_power",
    "tier4_full_power": "tier4_full_power",
}


class SafetyBand(str, Enum):
    """Execution risk bands governing L1..L4 tier gating, OAuth scopes, and `/mcp/readonly` isolation."""

    READONLY = "READONLY"
    WORKSPACE_WRITE = "WORKSPACE_WRITE"
    WORKSPACE_EDIT = "WORKSPACE_WRITE"
    WORKSPACE_EXEC = "WORKSPACE_EXEC"
    HOST_ADMIN = "HOST_ADMIN"


DEFAULT_PROPERTY_DESCRIPTIONS: Dict[str, Dict[str, str]] = {
    "get_status": {
        "job_id": "Background job ID or 'list'",
        "wait_seconds": "Long-poll wait 0..25s",
        "tail_lines": "Trailing output lines",
    },
    "find_files": {
        "path": "Directory root (no glob)",
        "pattern": "Filename glob pattern",
        "extensions": "Extension filter list, e.g. ['py']",
        "excludes": "Excluded directory/file globs",
        "entry_type": "any|file|dir",
        "max_depth": "Maximum directory traversal depth",
        "limit": "Maximum entries returned",
        "sort_by": "Sort order (e.g. path, mtime, size, name)",
    },
    "search_code": {
        "pattern": "Regex or literal search pattern",
        "path": "Target directory or file path",
        "glob_filter": "File glob filter (e.g. '*.py')",
        "fixed_strings": "Match literal text instead of regex",
        "case_insensitive": "Case-insensitive match",
        "files_only": "Return matching file paths only",
        "include_docs": "Include documentation files (.md/.rst/.txt)",
        "max_results": "Maximum match count",
    },
    "code_intel": {
        "path": "Target file or directory",
        "action": "outline|symbol|refs|diagnostics",
        "symbols": "Batch 1-5 symbol names",
        "symbol": "Single symbol name or Class.method",
    },
    "read_file": {
        "path": "Target file or image path",
        "start_line": "1-based start line (or negative tail e.g. -80)",
        "end_line": "1-based inclusive end line",
        "symbol": "Optional symbol scope to slice",
    },
    "edit_file": {
        "path": "Target file path",
        "old_text": "Exact or window-scoped text to replace",
        "new_text": "Replacement text",
        "start_line": "Optional 1-based window start",
        "end_line": "Optional 1-based window end",
        "symbol": "Optional symbol scope",
        "edits": "Batch edit chunks",
        "expected_sha256": "Optimistic lock SHA-256",
    },
    "write_file": {
        "path": "Target file path",
        "content": "Text content to write",
        "mode": "overwrite|append",
        "encoding": "Optional text encoding (e.g. utf-8, utf-8-sig, utf-16, gb18030)",
        "allow_shrink": "Allow >50% file shrink on overwrite",
        "overwrite_unread": "Allow overwriting unread existing file",
        "expected_sha256": "Optimistic lock SHA-256",
    },
    "manage_files": {
        "action": "mkdir|move|rename|copy|trash|restore|undo|redo|list",
        "path": "Target file or directory path",
        "destination": "Destination path for move/rename/copy",
        "overwrite": "Allow replacing existing destination (via recoverable trash)",
        "trash_id": "Trash item ID or 'latest' when action='restore'",
        "reason": "Optional note for trash operation",
        "limit": "Max entries returned when action='list'",
    },
    "undo_or_trash": {
        "action": "undo|redo|trash|list|restore",
        "path": "Target file or directory path",
        "trash_id": "Trash item ID when action='restore'",
    },
    "run_command": {
        "command": "Shell command to execute",
        "cwd": "Working directory",
        "timeout_seconds": "Timeout seconds (1..120)",
    },
    "run_python": {
        "code": "Multiline UTF-8 Python source code",
        "cwd": "Working directory",
        "timeout_seconds": "Timeout seconds (1..120)",
        "python_path": "Optional Python / Conda interpreter executable path",
        "venv": "Optional virtualenv directory path",
        "conda_env": "Optional Conda environment name or prefix",
    },
    "bg_command": {
        "action": "start|status|wait|list|kill",
        "command": "Command string when starting",
        "cwd": "Working directory",
        "job_id": "Background job ID",
        "wait_seconds": "Wait 0..25s for completion",
        "tail_lines": "Trailing log lines",
        "max_ttl_seconds": "Maximum background job lifetime in seconds",
        "python_path": "Optional Python interpreter executable path",
        "venv": "Optional virtualenv directory path",
        "conda_env": "Optional Conda environment name or prefix",
    },
    "batch_probe": {
        "code": "Read-only deterministic Python probe assigning summary data to RESULT",
        "cwd": "Target workspace directory",
        "timeout_seconds": "Probe timeout seconds (1..60)",
    },
    "web_research": {
        "action": "search|github_search|fetch",
        "query": "Search keywords",
        "url": "Public HTTPS URL when action='fetch'",
        "offset": "Character or result offset for pagination",
    },
    "workspace_memory": {
        "action": "read|post|search",
        "topic": "Short note topic",
        "content": "Note body when action='post'",
        "query": "Search query when action='search'",
    },
    "skill_hub": {
        "action": "search|load|read_file|market_search|vet",
        "query": "Keywords to search local or public market skills",
        "skill": "Skill name or ID to load or inspect",
        "rel_path": "Relative resource file inside a skill directory",
        "source": "Local path or HTTPS GitHub repository URL when action='vet'",
    },
    "skill_manage": {
        "action": "list|create|install|sync|enable|disable|trash|trash_list|restore",
        "skill": "Target skill name or ID",
        "source": "Local path or HTTPS GitHub URL when action='install'",
        "content": "Complete SKILL.md content when action='create'",
        "scope": "Target scope (managed|project)",
        "confirm_warn": "Explicit confirmation when installing a WARN-level skill",
        "trash_id": "Trash entry ID when action='restore'",
    },
}


def normalize_input_schema(base_name: str, raw_schema: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Produce clean MCP JSON Schema without `$defs` or `title` clutter and apply aligned property descriptions."""
    if not raw_schema:
        schema: Dict[str, Any] = {"type": "object", "properties": {}, "required": []}
    else:
        schema = json.loads(json.dumps(raw_schema))
    schema.pop("$defs", None)
    schema.pop("title", None)
    schema.setdefault("type", "object")
    props = schema.setdefault("properties", {})
    if isinstance(props, dict):
        if base_name == "search_code" and "glob" in props and "glob_filter" not in props:
            props["glob_filter"] = props.pop("glob")
        for pv in props.values():
            if isinstance(pv, dict):
                pv.pop("title", None)
        desc_map = DEFAULT_PROPERTY_DESCRIPTIONS.get(base_name) or {}
        for pk, pdesc in desc_map.items():
            if isinstance(props.get(pk), dict) and not props[pk].get("description"):
                props[pk]["description"] = pdesc
    return schema


@dataclass(frozen=True)
class ToolSpec:
    """Declarative specification for a single MCP tool registered in `KernelDispatcher`."""

    base_name: str
    handler: Callable[..., Any]
    safety_band: SafetyBand = SafetyBand.READONLY
    input_schema: Dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})
    title: str = ""
    description: str = ""
    nudge_prefer: str = ""
    pack: Optional[str] = None
    aliases: Tuple[str, ...] = ()
    param_aliases: Dict[str, str] = field(default_factory=dict)
    action_param: str = "action"
    action_enum: Tuple[str, ...] = ()
    idempotent: bool = False
    open_world: bool = False
    oauth_scope: str = ""

    def __post_init__(self) -> None:
        clean_schema = normalize_input_schema(self.base_name, self.input_schema)
        object.__setattr__(self, "input_schema", clean_schema)
        if not self.title:
            object.__setattr__(self, "title", self.base_name.replace("_", " ").title())
        if not self.action_enum:
            props = clean_schema.get("properties") or {}
            act_prop = props.get(self.action_param)
            if isinstance(act_prop, dict) and isinstance(act_prop.get("enum"), list):
                object.__setattr__(self, "action_enum", tuple(str(x) for x in act_prop["enum"]))

    def effective_action_values(self, *, tier_allow_edit: bool = True) -> Tuple[str, ...]:
        vals = self.action_enum
        if not tier_allow_edit:
            if self.base_name in ("manage_files", "undo_or_trash", "restore_trash"):
                return tuple(v for v in vals if v == "list")
            if self.base_name == "bg_command":
                return tuple(v for v in vals if v in ("status", "list"))
            if self.base_name == "workspace_memory":
                return tuple(v for v in vals if v in ("read", "search"))
            if self.base_name == "code_intel":
                return tuple(v for v in vals if v != "rename_symbol")
            if self.base_name == "skill_manage":
                return tuple(v for v in vals if v in ("list", "trash_list"))
        return vals

    def parameter_names(self) -> Tuple[str, ...]:
        props = self.input_schema.get("properties") or {}
        return tuple(str(k) for k in props.keys())


class PackPlugin(Protocol):
    """Pluggable optional peripheral pack interface (`browser`, `cua`, `pad`, etc.)."""

    pack_id: str

    def get_tools(self) -> Sequence[ToolSpec]: ...

    def shutdown(self, prefix_filter: str = "") -> None: ...


@dataclass
class ToolCallContext:
    """Per-invocation context passed through `ExecutionHook` and audit slots."""

    call_id: str
    requested_name: str
    resolved_name: str
    base_name: str
    prefix: str
    arguments: Dict[str, Any]
    caller: str
    session_hint: str
    safety_band: SafetyBand
    tier_key: str
    scopes: Optional[frozenset[str]] = None
    readonly_endpoint: bool = False
    client_platform: str = ""


class ExecutionHook(Protocol):
    """Middleware hook executed around tool handlers inside `KernelDispatcher`."""

    def before_call(self, ctx: ToolCallContext) -> Optional[Dict[str, Any]]: ...

    def after_call(
        self,
        ctx: ToolCallContext,
        result: Any,
        error: Optional[BaseException],
        duration_ms: float,
    ) -> Any: ...


@dataclass(frozen=True)
class AuditEvent:
    """Structured immutable record emitted to bounded audit callback slots."""

    call_id: str
    ts: float
    caller: str
    tool: str
    resolved_tool: str
    base_name: str
    safety_band: str
    tier: str
    ok: bool
    duration_ms: float
    error: str = ""
    blocked_reason: str = ""


AuditCallback = Callable[[AuditEvent], None]


@dataclass(frozen=True)
class RuntimePaths:
    """Explicit runtime state-root pinning so shims never depend on `__file__.parent` depth."""

    mcp_live_dir: Path
    shared_logs_dir: Optional[Path] = None
    scripts_dir: Optional[Path] = None
    state_dir: Optional[Path] = None
    audit_file: Optional[Path] = None
    undo_dir: Optional[Path] = None

    def resolved_logs_dir(self) -> Path:
        if self.shared_logs_dir is not None:
            return self.shared_logs_dir
        return self.mcp_live_dir / "logs"

    def resolved_state_dir(self) -> Path:
        if self.state_dir is not None:
            return self.state_dir
        return self.mcp_live_dir / ".mcp_state"

    def resolved_undo_dir(self) -> Path:
        if self.undo_dir is not None:
            return self.undo_dir
        return self.mcp_live_dir / ".undo_history"


__all__ = [
    "AuditCallback",
    "AuditEvent",
    "CANONICAL_TIER_MAP",
    "DEFAULT_PROPERTY_DESCRIPTIONS",
    "ExecutionHook",
    "PackPlugin",
    "RuntimePaths",
    "SafetyBand",
    "TIER_NUMERIC_LEVEL",
    "TIER_ORDER",
    "ToolCallContext",
    "ToolSpec",
    "UNAMBIGUOUS_PW_ALPHABET",
    "UNAMBIGUOUS_PW_PREFIX_RE",
    "normalize_input_schema",
]
