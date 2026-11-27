"""Native Cosmos MCP `skill_hub` + `skill_manage` adapter and `SkillsCapabilityProvider`."""
from __future__ import annotations

import inspect
from pathlib import Path
import shutil
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from cosmos_mcp.capabilities.base import CapabilityProvider
from cosmos_mcp.capabilities.skills.loader import load_skill_content
from cosmos_mcp.capabilities.skills.lock_and_sync import (
    WRITABLE_HOST_IDS,
    SkillPackageManager,
    compute_clawhub_fingerprint,
    compute_skill_folder_hash,
    is_link_or_junction as _ls_is_link,
    is_managed_sync_dir,
    read_skills_lock,
    sanitize_skill_dir_name,
    write_skills_lock,
)
from cosmos_mcp.capabilities.skills.models import (
    FetchedSkillPackage,
    MarketCandidate,
    SkillRecord,
    SkillsConfig,
    VirtualFileEntry,
    is_subpath,
    normalize_canonical_tier_key,
    normalize_tier_level,
    set_skill_disabled_state,
)
from cosmos_mcp.capabilities.skills.parser_and_index import LocalSkillIndex, scan_local_skills
from cosmos_mcp.capabilities.skills.vetter import audit_skill_directory
from cosmos_mcp.core.contracts import (
    CANONICAL_TIER_MAP,
    SafetyBand,
    TIER_NUMERIC_LEVEL,
    TIER_ORDER,
    ToolSpec,
)

if TYPE_CHECKING:
    from cosmos_mcp.core.config import LiveRuntimePolicy

SKILL_HUB_CANONICAL_ACTIONS: Tuple[str, ...] = (
    "search",
    "load",
    "read_file",
    "market_search",
    "vet",
)
SKILL_HUB_ACTIONS: Tuple[str, ...] = (
    "search",
    "list",
    "load",
    "read_file",
    "market_search",
    "discover",
    "vet",
    "preview",
)

SKILL_MANAGE_CANONICAL_ACTIONS: Tuple[str, ...] = (
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
SKILL_MANAGE_ACTIONS: Tuple[str, ...] = (
    "list",
    "create",
    "register",
    "install",
    "sync",
    "sync_hosts",
    "enable",
    "disable",
    "set_host_enabled",
    "trash",
    "remove",
    "trash_list",
    "restore",
    "check",
    "relock",
    "update",
    "scan_unmanaged",
    "adopt",
)

_READONLY_MANAGE_ACTIONS: Tuple[str, ...] = (
    "list",
    "trash_list",
    "check",
    "scan_unmanaged",
)

_MUTATING_MANAGE_ACTIONS: Tuple[str, ...] = tuple(
    act for act in SKILL_MANAGE_ACTIONS if act not in _READONLY_MANAGE_ACTIONS
)

SKILL_HUB_DESCRIPTION = (
    "Proactively call `search` or `load` to check workspace and local Agent Skills whenever handling project handovers, "
    "policy or compliance checks, specialized domain workflows, or questions about available skills and capabilities; "
    "use `market_search` and `vet` to discover and security-audit online skills in memory."
)
SKILL_MANAGE_DESCRIPTION = (
    "Create, install, enable, disable, synchronize, verify lockfiles, "
    "or move and restore Agent Skills via recoverable trash."
)

SKILL_HUB_INPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": list(SKILL_HUB_CANONICAL_ACTIONS),
            "default": "search",
            "description": "search|load|read_file|market_search|vet",
        },
        "query": {
            "type": "string",
            "description": "Keywords to search local or public market skills",
        },
        "skill": {
            "type": "string",
            "description": "Skill name or ID to load or inspect",
        },
        "rel_path": {
            "type": "string",
            "description": "Relative resource file inside a skill directory",
        },
        "source": {
            "type": "string",
            "description": "Local path or HTTPS GitHub repository URL when action='vet'",
        },
        "scope": {
            "type": "string",
            "enum": ["all", "managed", "project", "workspace", "host"],
            "description": "Scope filter (all|managed|project|host)",
        },
        "sources": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Optional market source filter list (skills_sh, clawhub, mcp_registry, github)",
        },
        "cwd": {
            "type": "string",
            "description": "Optional project workspace directory path",
        },
        "include_disabled": {
            "type": "boolean",
            "default": False,
            "description": "Include disabled skills in local search or list results",
        },
        "offset": {
            "type": "integer",
            "minimum": 0,
            "default": 0,
            "description": "0-based character offset when reading skill files",
        },
        "max_chars": {
            "type": "integer",
            "minimum": 1,
            "default": 24000,
            "description": "Maximum characters returned per slice",
        },
        "wrap_untrusted": {
            "type": "boolean",
            "default": True,
            "description": "Wrap loaded external skill content in untrusted boundary tags",
        },
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": 200,
            "default": 20,
            "description": "Maximum skill records or market candidates to return",
        },
        "caller": {
            "type": "string",
            "description": "Optional session or subagent identifier",
        },
    },
    "required": [],
}

SKILL_MANAGE_INPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": list(SKILL_MANAGE_CANONICAL_ACTIONS),
            "default": "list",
            "description": "list|create|install|sync|enable|disable|trash|trash_list|restore",
        },
        "skill": {
            "type": "string",
            "description": "Target skill name or ID",
        },
        "source": {
            "type": "string",
            "description": "Local path or HTTPS GitHub URL when action='install'",
        },
        "content": {
            "type": "string",
            "description": "Complete SKILL.md content when action='create'",
        },
        "scope": {
            "type": "string",
            "enum": ["managed", "project", "workspace"],
            "description": "Target scope (managed|project)",
        },
        "confirm_warn": {
            "type": "boolean",
            "default": False,
            "description": "Explicit confirmation when installing or creating a WARN-level skill",
        },
        "trash_id": {
            "type": "string",
            "description": "Trash entry ID when action='restore'",
        },
        "preview_token": {
            "type": "string",
            "description": "Verified in-memory preview token from skill_hub(action='vet') or dry-run install",
        },
        "cwd": {
            "type": "string",
            "description": "Optional target project workspace directory when scope='project'",
        },
        "hosts": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Optional target host IDs when action='sync'",
        },
        "host_id": {
            "type": "string",
            "description": "Optional single host ID when toggling per-host sync",
        },
        "dry_run": {
            "type": "boolean",
            "description": "Preview without writing files",
        },
        "force": {
            "type": "boolean",
            "default": False,
            "description": "Allow replacing or removing modified skill via recoverable trash",
        },
        "sync_hosts": {
            "type": "boolean",
            "description": "Synchronize managed skill copies to enabled writable local host directories",
        },
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": 200,
            "default": 25,
            "description": "Maximum records returned for list or trash_list",
        },
        "caller": {
            "type": "string",
            "description": "Optional session or subagent identifier",
        },
    },
    "required": [],
}


def _is_runtime_policy_like(obj: Any) -> bool:
    return (
        obj is not None
        and not isinstance(obj, SkillsConfig)
        and hasattr(obj, "tier_key")
        and hasattr(obj, "workspace_roots")
        and hasattr(obj, "state_root")
    )


def coerce_skills_config(
    config_or_policy: Optional[Union[SkillsConfig, "LiveRuntimePolicy"]] = None,
    *,
    policy: Optional["LiveRuntimePolicy"] = None,
) -> SkillsConfig:
    """Build or attach a `SkillsConfig` directly bound to `LiveRuntimePolicy`."""
    if isinstance(config_or_policy, SkillsConfig):
        if policy is not None and config_or_policy.policy is None:
            config_or_policy.policy = policy
        return config_or_policy
    if _is_runtime_policy_like(config_or_policy):
        return SkillsConfig(policy=config_or_policy)  # type: ignore[arg-type]
    if policy is not None:
        return SkillsConfig(policy=policy)
    return SkillsConfig()


def _call_compatible(fn: Callable[..., Any], *pos_args: Any, **cand_kwargs: Any) -> Any:
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return fn(*pos_args, **cand_kwargs)
    has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
    if has_var_kw:
        return fn(*pos_args, **cand_kwargs)
    filtered = {k: v for k, v in cand_kwargs.items() if k in sig.parameters and v is not None}
    return fn(*pos_args, **filtered)


def _matches_scope_filter(source_scope: str, norm_scope: str) -> bool:
    if not norm_scope or norm_scope == "all":
        return True
    if norm_scope in ("project", "workspace"):
        return source_scope in ("workspace", "workspace_claude", "project")
    if norm_scope == "host":
        return source_scope not in ("managed", "workspace", "workspace_claude", "project")
    return source_scope == norm_scope


class SkillsMcpService:
    """Native facade backing `skill_hub`, `skill_manage`, and Cosmos Studio `/api/studio/skills/*`."""

    def __init__(
        self,
        config: Optional[Union[SkillsConfig, "LiveRuntimePolicy"]] = None,
        *,
        policy: Optional["LiveRuntimePolicy"] = None,
        package_manager: Optional[SkillPackageManager] = None,
        local_index: Any = None,
        market_client: Any = None,
    ) -> None:
        self.config: SkillsConfig = coerce_skills_config(config, policy=policy)
        self.package_manager: SkillPackageManager = package_manager or SkillPackageManager(
            self.config,
            market_client=market_client,
        )
        self._local_index = local_index
        self._market_client = market_client

    @property
    def policy(self) -> Optional["LiveRuntimePolicy"]:
        return self.config.policy

    def _get_index(self) -> LocalSkillIndex:
        if self._local_index is not None:
            return self._local_index
        self._local_index = LocalSkillIndex(self.config)
        return self._local_index

    def _get_market_client(self) -> Any:
        if self._market_client is not None:
            return self._market_client
        from cosmos_mcp.capabilities.skills.market import MarketClient

        self._market_client = MarketClient(self.config)
        return self._market_client

    def _default_sync_hosts(self) -> bool:
        """Suppress automatic host-directory sync when `state_root` is isolated without `home_dir`."""
        if self.config.home_dir is not None:
            return True
        if self.config.policy is not None:
            # Live runtime state_root is managed by Cosmos MCP; only auto-sync into user home hosts
            # when explicitly requested via `sync` or `sync_hosts=True`.
            return False
        if self.config.state_root is not None:
            try:
                default_sr = (Path.home().expanduser().resolve() / ".cosmos-skills").resolve()
                if self.config.resolved_state_root() != default_sr:
                    return False
            except OSError:
                return False
        return True

    def _effective_security_gate(
        self,
        *,
        req_tier: Any = None,
        req_tier_level: Any = None,
        req_policy: Any = None,
        readonly_only: bool = False,
        matched_alias: str = "",
    ) -> Tuple[int, str, bool, Tuple[Path, ...], bool, str]:
        """Return `(tier_level, tier_key, restrict_to_workspaces, workspace_roots, readonly_only, matched_alias)`.

        Dynamically reads `self.config.policy` (`tier_key`, `workspace_roots`, `state_root`) on every call,
        while allowing per-request overrides to ONLY tighten permissions (`min`).
        """
        tier_level = self.config.live_tier_level()
        restrict_ws = self.config.live_restrict_to_workspaces()
        ws_roots: List[Path] = [Path(w).expanduser().resolve() for w in self.config.live_workspace_roots()]

        if req_policy is not None:
            pol_t = getattr(req_policy, "tier_level", None)
            if pol_t is None:
                pol_t = getattr(req_policy, "tier_key", None)
            if pol_t is not None:
                tier_level = min(tier_level, normalize_tier_level(pol_t))
            pol_guard = getattr(req_policy, "guard", None)
            if (
                bool(getattr(req_policy, "restrict_to_workspace", False))
                or bool(getattr(req_policy, "restrict_to_workspaces", False))
                or bool(getattr(pol_guard, "restrict_to_workspace", False))
            ):
                restrict_ws = True
            req_ws = getattr(req_policy, "workspace_roots", None)
            if req_ws:
                ws_roots = [Path(w).expanduser().resolve() for w in req_ws]

        if req_tier is not None:
            tier_level = min(tier_level, normalize_tier_level(req_tier))
        if req_tier_level is not None:
            tier_level = min(tier_level, normalize_tier_level(req_tier_level))

        if tier_level == 2 and ws_roots:
            restrict_ws = True
        elif tier_level == 4 and self.config._explicit_restrict_to_workspaces is None and req_policy is None:
            restrict_ws = bool(self.config.live_restrict_to_workspaces())

        tier_key = TIER_ORDER[max(1, min(4, tier_level)) - 1]
        return tier_level, tier_key, restrict_ws, tuple(ws_roots), bool(readonly_only), matched_alias

    @staticmethod
    def _is_within_workspaces(candidate_path: Path, ws_roots: Sequence[Path]) -> bool:
        return any(is_subpath(candidate_path, wr) for wr in ws_roots)

    def _check_cwd_or_workspace_boundary(
        self,
        raw_dir: Optional[str],
        *,
        param_name: str,
        restrict_ws: bool,
        ws_roots: Sequence[Path],
    ) -> Tuple[Optional[Path], Optional[Dict[str, Any]]]:
        if not raw_dir or not str(raw_dir).strip():
            return None, None
        resolved = Path(str(raw_dir).strip()).expanduser().resolve()
        if restrict_ws and ws_roots and not self._is_within_workspaces(resolved, ws_roots):
            return None, {
                "ok": False,
                "installed": False,
                "blocked_by_security_gate": True,
                "error": (
                    f"Security gate blocked out-of-workspace `{param_name}`: '{resolved}' is not inside "
                    f"authorized workspace_roots {[str(w) for w in ws_roots]}."
                ),
            }
        return resolved, None

    def _list_records(
        self,
        cwd: Optional[str] = None,
        scope: str = "all",
        *,
        include_disabled: bool = False,
    ) -> List[SkillRecord]:
        idx = self._get_index()
        if idx is not None and hasattr(idx, "list_skills"):
            res = _call_compatible(idx.list_skills, cwd=cwd, include_disabled=include_disabled)
            records = list(res) if isinstance(res, (list, tuple)) else []
        else:
            res = _call_compatible(scan_local_skills, self.config, cwd=cwd, include_disabled=include_disabled)
            records = list(res) if isinstance(res, (list, tuple)) else []

        norm_scope = (scope or "all").strip().lower()
        if norm_scope and norm_scope != "all":
            records = [r for r in records if _matches_scope_filter(r.source_scope, norm_scope)]
        return records

    def _search_local(
        self,
        query: str,
        cwd: Optional[str] = None,
        scope: str = "all",
        limit: int = 20,
        *,
        include_disabled: bool = False,
    ) -> List[Dict[str, Any]]:
        cap = max(1, min(200, int(limit)))
        q_clean = (query or "").strip()
        if not q_clean:
            return [
                r.to_summary_dict()
                for r in self._list_records(cwd=cwd, scope=scope, include_disabled=include_disabled)[:cap]
            ]

        idx = self._get_index()
        raw_res = _call_compatible(
            idx.search,
            q_clean,
            cwd=cwd,
            limit=max(cap * 2, 20),
            top_k=max(cap * 2, 20),
            include_disabled=include_disabled,
        )
        if isinstance(raw_res, dict):
            raw_hits = raw_res.get("items") or raw_res.get("results") or []
        else:
            raw_hits = raw_res or []

        out: List[Dict[str, Any]] = []
        norm_scope = (scope or "all").strip().lower()
        for item in raw_hits:
            if isinstance(item, SkillRecord):
                if not include_disabled and not item.enabled:
                    continue
                d = item.to_summary_dict()
            elif isinstance(item, tuple) and len(item) >= 2 and isinstance(item[0], SkillRecord):
                if not include_disabled and not item[0].enabled:
                    continue
                score_val = float(item[1]) if isinstance(item[1], (int, float)) else None
                matched_val = int(item[2]) if len(item) >= 3 and isinstance(item[2], int) else None
                d = item[0].to_summary_dict(score=score_val, matched_terms=matched_val)
            elif isinstance(item, dict):
                if not include_disabled and item.get("enabled") is False:
                    continue
                d = dict(item)
            else:
                continue
            sc = str(d.get("source_scope") or "")
            if not _matches_scope_filter(sc, norm_scope):
                continue
            out.append(d)
            if len(out) >= cap:
                break
        return out

    def _load_local(
        self,
        name: str,
        *,
        resource_path: str = "",
        cwd: Optional[str] = None,
        offset: int = 0,
        max_chars: int = 24000,
        wrap_untrusted: bool = True,
        include_disabled: bool = False,
    ) -> Dict[str, Any]:
        target_name = (name or "").strip()
        if not target_name:
            return {"ok": False, "action": "load", "error": "Parameter `skill` is required for loading."}
        if isinstance(max_chars, bool) or int(max_chars) <= 0:
            return {"ok": False, "action": "load", "error": f"Parameter `max_chars` must be >= 1 (got {max_chars!r})."}
        if isinstance(offset, bool) or int(offset) < 0:
            return {"ok": False, "action": "load", "error": f"Parameter `offset` must be >= 0 (got {offset!r})."}

        target_file = (resource_path or "").strip() or "SKILL.md"
        loaded = load_skill_content(
            self.config,
            target_name,
            file=target_file,
            cwd=cwd,
            offset=int(offset),
            max_chars=int(max_chars),
            wrap_untrusted=bool(wrap_untrusted),
            index=self._get_index(),
            include_disabled=include_disabled,
        )
        res_dict = dict(loaded)
        res_dict.setdefault("ok", "error" not in res_dict)
        return res_dict

    def handle_skill_search(self, **kwargs: Any) -> Dict[str, Any]:
        call_kw = dict(kwargs)
        call_kw["action"] = "search"
        eff_name = str(call_kw.get("skill") or call_kw.get("name") or call_kw.get("skill_name") or "").strip()
        if eff_name and not str(call_kw.get("query") or "").strip():
            call_kw["query"] = eff_name
        return self.handle_skill_hub(**call_kw)

    def handle_skill_load(self, **kwargs: Any) -> Dict[str, Any]:
        call_kw = dict(kwargs)
        call_kw["action"] = "load"
        return self.handle_skill_hub(**call_kw)

    def handle_skill_register(self, **kwargs: Any) -> Dict[str, Any]:
        call_kw = dict(kwargs)
        call_kw["action"] = "register"
        if str(call_kw.get("content") or "").strip() and call_kw.get("dry_run") is None:
            call_kw["dry_run"] = False
        return self.handle_skill_manage(**call_kw)

    def handle_skill_hub(
        self,
        action: str = "",
        query: str = "",
        skill: str = "",
        name: str = "",
        rel_path: str = "",
        resource_path: str = "",
        source: str = "",
        path: str = "",
        source_ref: str = "",
        install_ref: str = "",
        scope: Optional[str] = None,
        sources: Optional[Sequence[str]] = None,
        cwd: Optional[str] = None,
        workspace: Optional[str] = None,
        include_disabled: bool = False,
        offset: Optional[int] = None,
        max_chars: Optional[int] = None,
        wrap_untrusted: Optional[bool] = None,
        limit: int = 20,
        _tier: Any = None,
        tier_level: Any = None,
        **extra: Any,
    ) -> Dict[str, Any]:
        """Execute read-only `skill_hub` actions (`search|list|load|read_file|market_search|vet`)."""
        try:
            eff_tier, eff_tier_key, restrict_ws, ws_roots, readonly_only, matched_alias = self._effective_security_gate(
                req_tier=_tier,
                req_tier_level=tier_level,
                req_policy=extra.get("_policy"),
                readonly_only=bool(extra.get("_readonly_only", False)),
                matched_alias=str(extra.get("_matched_alias") or ""),
            )
        except ValueError as exc:
            return {"ok": False, "blocked_by_security_gate": True, "error": str(exc)}

        eff_name = (skill or name or str(extra.get("skill_name") or "")).strip()
        eff_query = (query or "").strip()
        eff_path_alias = (path or str(extra.get("path") or "")).strip()
        eff_rel_path = (rel_path or resource_path or str(extra.get("file") or "")).strip()
        eff_action = (action or "").strip().lower()
        if eff_action == "read_file" and not eff_rel_path and eff_path_alias and not source:
            eff_rel_path = eff_path_alias
            eff_path_alias = ""
        eff_source_ref = (
            source
            or eff_path_alias
            or source_ref
            or install_ref
            or str(extra.get("install_ref") or "")
        ).strip()

        if matched_alias == "skill_search":
            eff_action = "search"
            if eff_name and not eff_query:
                eff_query = eff_name
        elif matched_alias == "skill_load":
            eff_action = "load"
        elif not eff_action:
            if eff_source_ref:
                eff_action = "vet"
            elif eff_name and eff_rel_path:
                eff_action = "read_file"
            elif eff_name and not eff_query:
                eff_action = "load"
            elif eff_query:
                eff_action = "search"
            else:
                eff_action = "search"

        if eff_action not in SKILL_HUB_ACTIONS:
            return {
                "ok": False,
                "error": f"Unsupported skill_hub action {eff_action!r}; expected one of {list(SKILL_HUB_CANONICAL_ACTIONS)}.",
            }

        has_cwd = cwd is not None and bool(str(cwd).strip())
        has_ws = workspace is not None and bool(str(workspace).strip())
        raw_cwd = str(cwd).strip() if has_cwd else (str(workspace).strip() if has_ws else None)
        cwd_param_label = "workspace" if (not has_cwd and has_ws) else "cwd"

        cwd_resolved, cwd_err = self._check_cwd_or_workspace_boundary(
            raw_cwd,
            param_name=cwd_param_label,
            restrict_ws=restrict_ws,
            ws_roots=ws_roots,
        )
        if cwd_err is not None:
            return cwd_err
        eff_cwd = str(cwd_resolved) if cwd_resolved is not None else None
        list_scope = str(scope).strip() if (scope is not None and str(scope).strip()) else "all"
        inc_disabled = bool(include_disabled)

        try:
            if eff_action == "list":
                recs = self._list_records(cwd=eff_cwd, scope=list_scope, include_disabled=inc_disabled)
                cap = max(1, min(200, int(limit)))
                items = [r.to_summary_dict() for r in recs[:cap]]
                return {
                    "ok": True,
                    "action": "list",
                    "scope": list_scope,
                    "permission_tier": eff_tier_key,
                    "total": len(recs),
                    "skills": items,
                    "results": items,
                }

            if eff_action == "search":
                hits = self._search_local(
                    query=eff_query,
                    cwd=eff_cwd,
                    scope=list_scope,
                    limit=limit,
                    include_disabled=inc_disabled,
                )
                return {
                    "ok": True,
                    "action": "search",
                    "query": eff_query,
                    "permission_tier": eff_tier_key,
                    "count": len(hits),
                    "results": hits,
                    "items": hits,
                }

            if eff_action in ("load", "read_file"):
                if eff_action == "read_file" and not eff_rel_path:
                    return {
                        "ok": False,
                        "action": "read_file",
                        "error": "Parameter `rel_path` is required for `action='read_file'`.",
                    }
                raw_offset = offset if offset is not None else extra.get("offset")
                raw_max_chars = max_chars if max_chars is not None else extra.get("max_chars")
                raw_wrap = wrap_untrusted if wrap_untrusted is not None else extra.get("wrap_untrusted", True)

                if raw_offset is not None:
                    if isinstance(raw_offset, bool):
                        return {"ok": False, "action": eff_action, "error": f"Parameter `offset` must be >= 0 (got {raw_offset!r})."}
                    try:
                        eff_offset = int(raw_offset)
                    except (TypeError, ValueError):
                        return {"ok": False, "action": eff_action, "error": f"Parameter `offset` must be >= 0 (got {raw_offset!r})."}
                    if eff_offset < 0:
                        return {"ok": False, "action": eff_action, "error": f"Parameter `offset` must be >= 0 (got {raw_offset!r})."}
                else:
                    eff_offset = 0

                if raw_max_chars is not None:
                    if isinstance(raw_max_chars, bool):
                        return {
                            "ok": False,
                            "action": eff_action,
                            "error": f"Parameter `max_chars` must be >= 1 (got {raw_max_chars!r}).",
                        }
                    try:
                        eff_max_chars = int(raw_max_chars)
                    except (TypeError, ValueError):
                        return {
                            "ok": False,
                            "action": eff_action,
                            "error": f"Parameter `max_chars` must be >= 1 (got {raw_max_chars!r}).",
                        }
                    if eff_max_chars <= 0:
                        return {
                            "ok": False,
                            "action": eff_action,
                            "error": f"Parameter `max_chars` must be >= 1 (got {raw_max_chars!r}).",
                        }
                else:
                    eff_max_chars = 24000

                res_load = self._load_local(
                    eff_name,
                    resource_path=eff_rel_path,
                    cwd=eff_cwd,
                    offset=eff_offset,
                    max_chars=eff_max_chars,
                    wrap_untrusted=bool(raw_wrap),
                    include_disabled=inc_disabled,
                )
                res_load["action"] = eff_action
                return res_load

            if eff_action in ("market_search", "discover"):
                if not eff_query:
                    return {
                        "ok": False,
                        "action": eff_action,
                        "error": f"Parameter `query` is required for `{eff_action}`.",
                    }
                cap = max(1, min(200, int(limit)))
                client = self._get_market_client()
                search_fn = getattr(client, "discover", None) or getattr(client, "search", None)
                if search_fn is None:
                    return {"ok": False, "action": eff_action, "error": "MarketClient has no discover/search method."}
                call_kw: Dict[str, Any] = {"limit": cap}
                if sources:
                    call_kw["sources"] = list(sources)
                raw_cands = _call_compatible(search_fn, eff_query, **call_kw)
                cands_out: List[Dict[str, Any]] = []
                by_source: Dict[str, Any] = {}
                errors_map: Dict[str, Any] = {}
                if isinstance(raw_cands, dict):
                    for c in raw_cands.get("candidates") or raw_cands.get("items") or []:
                        c_dict = c.to_dict() if isinstance(c, MarketCandidate) else dict(c)
                        ref_val = str(
                            c_dict.get("install_ref")
                            or c_dict.get("source_ref")
                            or c_dict.get("source_url")
                            or c_dict.get("id")
                            or ""
                        )
                        c_dict["install_ref"] = str(c_dict.get("install_ref") or ref_val)
                        c_dict["source_ref"] = str(c_dict.get("source_ref") or c_dict["install_ref"])
                        cands_out.append(c_dict)
                    if isinstance(raw_cands.get("by_source"), dict):
                        by_source = dict(raw_cands["by_source"])
                    if isinstance(raw_cands.get("errors"), dict):
                        errors_map = dict(raw_cands["errors"])
                elif isinstance(raw_cands, (list, tuple)):
                    for c in raw_cands:
                        c_dict = c.to_dict() if isinstance(c, MarketCandidate) else dict(c)
                        ref_val = str(
                            c_dict.get("install_ref")
                            or c_dict.get("source_ref")
                            or c_dict.get("source_url")
                            or c_dict.get("id")
                            or ""
                        )
                        c_dict["install_ref"] = str(c_dict.get("install_ref") or ref_val)
                        c_dict["source_ref"] = str(c_dict.get("source_ref") or c_dict["install_ref"])
                        cands_out.append(c_dict)
                cands_out = cands_out[:cap]
                return {
                    "ok": True,
                    "action": eff_action,
                    "query": eff_query,
                    "count": len(cands_out),
                    "candidates": cands_out,
                    "results": cands_out,
                    "by_source": by_source,
                    "errors": errors_map,
                }

            # eff_action in ("vet", "preview")
            if not eff_source_ref and eff_name:
                rec = self._get_index().get_skill(eff_name, cwd=eff_cwd, include_disabled=True)
                if rec is not None and Path(rec.skill_dir).is_dir():
                    rep = audit_skill_directory(Path(rec.skill_dir), skill_name=rec.name, config=self.config)
                    return {
                        "ok": True,
                        "action": eff_action,
                        "skill_name": rec.name,
                        "skill_dir": rec.skill_dir,
                        "source_scope": rec.source_scope,
                        "enabled": rec.enabled,
                        "verdict": rep.verdict,
                        "blocked": rep.verdict == "BLOCK",
                        "requires_confirmation": rep.verdict == "WARN",
                        "audit": rep.to_dict(),
                    }
                return {
                    "ok": False,
                    "action": eff_action,
                    "error": f"Skill not found for vetting: {eff_name!r}; pass `source` for remote or local paths.",
                }

            if not eff_source_ref:
                return {
                    "ok": False,
                    "action": eff_action,
                    "status": "invalid_source",
                    "error": "source is required",
                }

            src_strip = eff_source_ref
            if (eff_tier <= 1 or readonly_only) and restrict_ws and ws_roots and src_strip:
                cand_local = Path(src_strip).expanduser()
                try:
                    local_exists = cand_local.exists()
                except OSError:
                    local_exists = False
                if local_exists:
                    res_local = cand_local.resolve()
                    allowed_ro = list(ws_roots) + list(self.config.readonly_skill_roots_for_sandbox())
                    if not any(is_subpath(res_local, rt) for rt in allowed_ro):
                        return {
                            "ok": False,
                            "blocked_by_security_gate": True,
                            "error": (
                                f"Security gate blocked preview of local directory outside authorized workspaces: '{res_local}'."
                            ),
                        }

            if scope is not None and str(scope).strip():
                norm_prev_scope = str(scope).strip().lower()
                target_scope = "project" if norm_prev_scope in ("project", "workspace") else "managed"
            else:
                target_scope = "project" if cwd_resolved is not None else "managed"

            prep = self.package_manager.prepare_install(
                source_ref=eff_source_ref,
                scope=target_scope,
                target_workspace=cwd_resolved,
                force_name=eff_name,
            )
            if isinstance(prep, dict):
                prep = dict(prep)
                prep.setdefault("action", eff_action)
                if prep.get("error") == "source_ref is required":
                    prep["error"] = "source is required"
            return prep
        except Exception as exc:
            err_s = str(exc)
            is_gate = "outside authorized workspace" in err_s or "escapes" in err_s
            out_err: Dict[str, Any] = {"ok": False, "action": eff_action, "error": f"{type(exc).__name__}: {exc}"}
            if is_gate:
                out_err["blocked_by_security_gate"] = True
            return out_err

    @staticmethod
    def _with_warn_confirmation_message(res: Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(res, dict) and res.get("status") == "warn_confirmation_required" and not res.get("installed"):
            out = dict(res)
            tok_hint = str(out.get("preview_token") or "<preview_token>")
            out.setdefault(
                "message",
                (
                    "Security audit returned WARN (installed=False). Review audit.findings and re-call "
                    f"skill_manage(action='install', preview_token='{tok_hint}', confirm_warn=True) to commit installation."
                ),
            )
            return out
        return res

    def _create_or_register_inline_skill(
        self,
        name: str,
        content: str,
        *,
        action_name: str = "create",
        scope: str = "managed",
        target_workspace: Optional[Path] = None,
        dry_run: bool = False,
        confirm_warn: bool = False,
        overwrite: bool = False,
        sync_hosts: bool = False,
        tier_level: int = 3,
    ) -> Dict[str, Any]:
        """Create or register inline `SKILL.md` content after 3-tier `vetter` verification."""
        clean_name = sanitize_skill_dir_name(name)
        _, resolved_ws, skills_root, _ = self.package_manager._resolve_scope_paths(scope, target_workspace)
        target_dir = skills_root / clean_name

        if action_name == "create" and target_dir.exists() and not overwrite and not dry_run:
            return {
                "ok": False,
                "action": "create",
                "created": False,
                "installed": False,
                "status": "already_exists",
                "skill_name": clean_name,
                "target_dir": str(target_dir),
                "error": (
                    f"Skill '{clean_name}' already exists at {target_dir}. "
                    "Pass force=True to replace via recoverable trash."
                ),
            }

        pkg = FetchedSkillPackage(
            source_type="local",
            source_id=f"inline:{clean_name}",
            source_url="",
            skill_name=clean_name,
            entries=[VirtualFileEntry(rel_path="SKILL.md", raw_bytes=content.encode("utf-8"))],
        )
        prep = self.package_manager.prepare_install(
            source_ref=f"inline:{clean_name}",
            scope=scope,
            target_workspace=target_workspace,
            force_name=clean_name,
            overwrite=overwrite,
            pre_fetched_package=pkg,
        )
        if not prep.get("ok") or dry_run:
            out_prep = dict(prep)
            out_prep["action"] = action_name
            out_prep.setdefault("created", False)
            return out_prep

        if tier_level == 2 and (prep.get("verdict") == "WARN" or bool((prep.get("audit") or {}).get("scripts_detected"))):
            return {
                "ok": False,
                "action": action_name,
                "created": False,
                "installed": False,
                "blocked_by_security_gate": True,
                "tier_level": 2,
                "verdict": prep.get("verdict"),
                "audit": prep.get("audit"),
                "error": "Tier L2 (no-exec tier) prohibits creating or installing skills with WARN findings or executable scripts.",
            }

        if prep.get("verdict") == "WARN" or prep.get("requires_confirmation"):
            if action_name == "register" and confirm_warn:
                out = dict(prep)
                out.update(
                    {
                        "ok": False,
                        "action": action_name,
                        "created": False,
                        "installed": False,
                        "dry_run": False,
                        "blocked_by_security_gate": True,
                        "status": "warn_preview_required",
                        "requires_confirmation": True,
                        "error": (
                            f"Inline skill '{clean_name}' triggered WARN security findings and cannot be installed "
                            "with unpreviewed confirm_warn=True. Review audit.findings and re-call with preview_token + confirm_warn=True."
                        ),
                    }
                )
                return out
            if not confirm_warn:
                res_warn = self._with_warn_confirmation_message(
                    self.package_manager.install(
                        preview_token=str(prep.get("preview_token") or ""),
                        scope=scope,
                        target_workspace=target_workspace,
                        confirm_warn=False,
                        overwrite=overwrite,
                        sync_hosts=sync_hosts,
                        dry_run=False,
                    )
                )
                out_w = dict(res_warn)
                out_w["action"] = action_name
                out_w["created"] = False
                return out_w

        res_inst = self.package_manager.install(
            preview_token=str(prep.get("preview_token") or ""),
            scope=scope,
            target_workspace=target_workspace,
            confirm_warn=bool(confirm_warn),
            overwrite=overwrite,
            sync_hosts=sync_hosts,
            dry_run=False,
        )
        out_inst = dict(res_inst)
        out_inst["action"] = action_name
        is_installed = bool(out_inst.get("installed"))
        out_inst["created"] = is_installed
        if is_installed:
            set_skill_disabled_state(
                self.config,
                skill_key=clean_name,
                enabled=True,
                scope=scope,
                workspace=resolved_ws,
                skill_dir=target_dir,
            )
            self._get_index()._ensure_index(cwd=resolved_ws, force_refresh=True)
        return out_inst

    def _toggle_skill_enabled(
        self,
        skill_name: str,
        *,
        enabled: bool,
        explicit_scope: Optional[str],
        ws_path: Optional[Path],
        eff_cwd: Optional[str],
        eff_sync_hosts: bool,
        eff_tier: int,
        restrict_ws: bool,
        ws_roots: Sequence[Path],
    ) -> Dict[str, Any]:
        """Enable or disable a project, managed, or host skill and refresh index cache."""
        clean_req = (skill_name or "").strip().lstrip("/").strip()
        if not clean_req:
            return {
                "ok": False,
                "action": "enable" if enabled else "disable",
                "error": "Parameter `skill` is required.",
            }

        recs_all = scan_local_skills(self.config, cwd=eff_cwd, include_disabled=True)
        key_low = clean_req.lower()
        slug_low = sanitize_skill_dir_name(clean_req).lower()
        matched: Optional[SkillRecord] = None
        for r in recs_all:
            if r.name.lower() in (key_low, slug_low) or r.dir_name.lower() in (key_low, slug_low):
                if explicit_scope:
                    norm_sc = explicit_scope.strip().lower()
                    if norm_sc in ("project", "workspace") and r.source_scope not in ("workspace", "workspace_claude", "project"):
                        continue
                    if norm_sc == "managed" and r.source_scope != "managed":
                        continue
                matched = r
                break
        if matched is None:
            for r in recs_all:
                if r.name.lower() in (key_low, slug_low) or r.dir_name.lower() in (key_low, slug_low):
                    matched = r
                    break

        if explicit_scope and explicit_scope.strip():
            toggle_scope = "project" if explicit_scope.strip().lower() in ("project", "workspace") else "managed"
        elif ws_path is not None:
            toggle_scope = "project"
        elif matched is not None and matched.source_scope in ("workspace", "workspace_claude", "project"):
            toggle_scope = "project"
        else:
            toggle_scope = "managed"

        if eff_tier == 2 and toggle_scope != "project":
            return {
                "ok": False,
                "action": "enable" if enabled else "disable",
                "blocked_by_security_gate": True,
                "blocked_by_permission_tier": True,
                "tier_level": 2,
                "scope": toggle_scope,
                "error": "Security gate: Tier L2 only permits enabling/disabling project-scoped skills inside workspace_roots.",
            }

        skill_dir_path: Optional[Path] = Path(matched.skill_dir) if matched is not None else None
        eff_ws_target: Optional[Path] = ws_path
        if eff_ws_target is None and matched is not None and matched.source_scope in ("workspace", "workspace_claude", "project"):
            sr_p = Path(matched.source_root)
            if sr_p.name.lower() == "skills" and sr_p.parent.name.lower() in (".agents", ".claude"):
                eff_ws_target = sr_p.parent.parent.resolve()
        if eff_ws_target is None and toggle_scope == "project" and ws_roots:
            eff_ws_target = ws_roots[0]

        if toggle_scope == "project" and restrict_ws and ws_roots and eff_ws_target is not None:
            if not self._is_within_workspaces(eff_ws_target, ws_roots):
                return {
                    "ok": False,
                    "action": "enable" if enabled else "disable",
                    "blocked_by_security_gate": True,
                    "error": f"Security gate: workspace '{eff_ws_target}' is outside authorized workspace_roots.",
                }

        if matched is None and toggle_scope == "project" and eff_ws_target is not None:
            cand_proj_dir = eff_ws_target / ".agents" / "skills" / sanitize_skill_dir_name(clean_req)
            if cand_proj_dir.is_dir():
                skill_dir_path = cand_proj_dir
        elif matched is None and toggle_scope == "managed":
            cand_mgd_dir = self.config.managed_skills_store() / sanitize_skill_dir_name(clean_req)
            if cand_mgd_dir.is_dir():
                skill_dir_path = cand_mgd_dir

        if matched is None and (skill_dir_path is None or not skill_dir_path.is_dir()):
            return {
                "ok": False,
                "action": "enable" if enabled else "disable",
                "status": "not_found",
                "skill_name": clean_req,
                "error": f"Skill not found: {clean_req!r}",
            }

        canon_name = matched.name if matched is not None else sanitize_skill_dir_name(clean_req)
        extra_keys: List[str] = [clean_req, sanitize_skill_dir_name(clean_req)]
        if matched is not None:
            extra_keys.extend([matched.name, matched.dir_name])

        set_skill_disabled_state(
            self.config,
            skill_key=canon_name,
            enabled=enabled,
            scope=toggle_scope,
            workspace=eff_ws_target,
            skill_dir=skill_dir_path,
            extra_keys=extra_keys,
        )

        # Synchronize managed host copies if requested in L3+
        removed_host_copies: List[str] = []
        synced_targets: List[Dict[str, Any]] = []
        if toggle_scope == "managed" and eff_tier >= 3 and eff_sync_hosts:
            dir_slug = matched.dir_name if matched is not None else sanitize_skill_dir_name(clean_req)
            mgd_dir = self.config.managed_skills_store() / dir_slug
            if not enabled:
                for hid, hroot in self.config.host_skill_roots():
                    if hid not in WRITABLE_HOST_IDS:
                        continue
                    dest_dir = hroot / dir_slug
                    if is_managed_sync_dir(dest_dir):
                        try:
                            shutil.rmtree(dest_dir)
                            removed_host_copies.append(hid)
                        except OSError:
                            pass
            elif mgd_dir.is_dir():
                sync_res = self.package_manager.sync_skill_to_hosts(
                    dir_slug,
                    source_dir=mgd_dir,
                    overwrite=False,
                )
                synced_targets = list(sync_res.get("synced_targets") or [])

        self._get_index()._ensure_index(cwd=eff_cwd, force_refresh=True)
        return {
            "ok": True,
            "action": "enable" if enabled else "disable",
            "skill_name": canon_name,
            "enabled": bool(enabled),
            "scope": toggle_scope,
            "workspace": str(eff_ws_target) if eff_ws_target is not None else "",
            "skill_dir": str(skill_dir_path) if skill_dir_path is not None else "",
            "removed_host_copies": removed_host_copies,
            "synced_targets": synced_targets,
        }

    def _relock_skills(
        self,
        *,
        skill_name: str = "",
        scope: str = "managed",
        target_workspace: Optional[Path] = None,
        sync_hosts: bool = False,
        tier_level: int = 3,
    ) -> Dict[str, Any]:
        norm_scope, resolved_ws, skills_root, lock_path = self.package_manager._resolve_scope_paths(
            scope,
            target_workspace,
        )
        filter_name = sanitize_skill_dir_name(skill_name) if skill_name.strip() else ""

        if tier_level == 2:
            cand_dirs: List[Tuple[str, Path]] = []
            if filter_name:
                cand_dirs.append((filter_name, skills_root / filter_name))
            elif skills_root.is_dir():
                for ch in sorted(skills_root.iterdir(), key=lambda p: p.name.lower()):
                    if not ch.name.startswith(".") and ch.is_dir():
                        cand_dirs.append((ch.name, ch))
            for cname, cdir in cand_dirs:
                if cdir.is_dir():
                    rep = audit_skill_directory(cdir, skill_name=cname, config=self.config)
                    if rep.verdict in ("WARN", "BLOCK") or bool(rep.scripts_detected):
                        return {
                            "ok": False,
                            "relocked": False,
                            "blocked_by_security_gate": True,
                            "tier_level": 2,
                            "verdict": rep.verdict,
                            "audit": rep.to_dict(),
                            "error": "Tier L2 prohibits relocking skills with WARN/BLOCK findings or executable scripts.",
                        }

        relock_fn = getattr(self.package_manager, "relock_skill", None)
        if callable(relock_fn):
            res = _call_compatible(
                relock_fn,
                skill_name=filter_name,
                name=filter_name,
                scope=norm_scope,
                target_workspace=resolved_ws,
                sync_hosts=sync_hosts,
            )
            out = dict(res) if isinstance(res, dict) else {"ok": bool(res)}
            out.setdefault("action", "relock")
            out.setdefault("relocked", bool(out.get("ok")))
            return out

        with self.package_manager._op_lock:
            lock_data = read_skills_lock(lock_path)
            skills_map = lock_data["skills"]
            targets = [filter_name] if filter_name else sorted(skills_map.keys())
            updated: List[Dict[str, Any]] = []
            for tname in targets:
                sdir = skills_root / tname
                if not _ls_is_link(sdir) and sdir.is_dir():
                    actual_hash = compute_skill_folder_hash(sdir)
                    prev_entry = dict(skills_map.get(tname) or {"source": f"local:{tname}", "sourceType": "local", "commit": ""})
                    prev_entry["computedHash"] = actual_hash
                    if prev_entry.get("sourceType") == "clawhub" or "clawhubFingerprint" in prev_entry:
                        prev_entry["clawhubFingerprint"] = compute_clawhub_fingerprint(sdir)
                    skills_map[tname] = prev_entry
                    updated.append({"skill_name": tname, "computed_hash": actual_hash})
            write_skills_lock(lock_path, lock_data)
        return {"ok": True, "action": "relock", "relocked": True, "skills": updated}

    def handle_skill_manage(
        self,
        action: str = "",
        skill: str = "",
        name: str = "",
        source: str = "",
        source_ref: str = "",
        install_ref: str = "",
        preview_token: str = "",
        content: str = "",
        scope: Optional[str] = None,
        workspace: str = "",
        cwd: str = "",
        hosts: Optional[Sequence[str]] = None,
        dry_run: Optional[bool] = None,
        confirm_warn: bool = False,
        overwrite: bool = False,
        force: bool = False,
        sync_hosts: Optional[bool] = None,
        host_id: str = "",
        enabled: Optional[bool] = None,
        check_remote: bool = False,
        trash_id: str = "",
        limit: int = 25,
        _tier: Any = None,
        tier_level: Any = None,
        **extra: Any,
    ) -> Dict[str, Any]:
        """Execute `skill_manage` actions (`list|create|install|sync|enable|disable|trash|trash_list|restore`) with L1..L4 tier gates."""
        try:
            eff_tier, eff_tier_key, restrict_ws, ws_roots, readonly_only, matched_alias = self._effective_security_gate(
                req_tier=_tier,
                req_tier_level=tier_level,
                req_policy=extra.get("_policy"),
                readonly_only=bool(extra.get("_readonly_only", False)),
                matched_alias=str(extra.get("_matched_alias") or ""),
            )
        except ValueError as exc:
            return {"ok": False, "installed": False, "blocked_by_security_gate": True, "error": str(exc)}

        eff_name = (skill or name or str(extra.get("skill_name") or "")).strip()
        eff_source_ref = (source or source_ref or install_ref or str(extra.get("install_ref") or "")).strip()
        eff_content = content if content else str(extra.get("markdown") or "")
        tok_clean = (preview_token or "").strip()
        eff_action = (action or "").strip().lower()

        if matched_alias == "skill_register":
            eff_action = "register"
        elif not eff_action:
            if eff_content and eff_name:
                eff_action = "create"
            elif eff_source_ref or tok_clean:
                eff_action = "install"
            else:
                eff_action = "list"

        if eff_action not in SKILL_MANAGE_ACTIONS:
            return {
                "ok": False,
                "error": f"Unsupported skill_manage action {eff_action!r}; expected one of {list(SKILL_MANAGE_CANONICAL_ACTIONS)}.",
            }

        if (eff_tier <= 1 or readonly_only) and eff_action in _MUTATING_MANAGE_ACTIONS:
            return {
                "ok": False,
                "installed": False,
                "error_code": "ERR_READONLY_ACTION_BLOCKED",
                "tier_error_code": "ERR_TIER_DENIED",
                "blocked_by_security_gate": True,
                "blocked_by_permission_tier": True,
                "permission_tier": eff_tier_key,
                "tier_level": eff_tier,
                "action": eff_action,
                "allowed_readonly_actions": ["list", "trash_list"],
                "error": (
                    f"[LOCALPC PERMISSION TIER BLOCKED] (ERR_TIER_DENIED / ERR_READONLY_ACTION_BLOCKED): "
                    f"`skill_manage` action='{eff_action}' is disabled in read-only tier `{eff_tier_key}`."
                ),
            }

        has_ws = bool(workspace and str(workspace).strip())
        has_cwd = bool(cwd and str(cwd).strip())
        raw_ws = str(workspace).strip() if has_ws else (str(cwd).strip() if has_cwd else str(extra.get("cwd") or "").strip())
        ws_param_label = "cwd" if (not has_ws and (has_cwd or bool(extra.get("cwd")))) else "workspace"

        ws_path, ws_err = self._check_cwd_or_workspace_boundary(
            raw_ws,
            param_name=ws_param_label,
            restrict_ws=restrict_ws,
            ws_roots=ws_roots,
        )
        if ws_err is not None:
            return ws_err
        eff_cwd = str(ws_path) if ws_path is not None else None

        if scope is None or not str(scope).strip():
            eff_scope = "project" if bool(raw_ws) else "managed"
        else:
            norm_sc = str(scope).strip().lower()
            if norm_sc == "all" and eff_action == "list":
                eff_scope = "all"
            elif norm_sc == "host" and eff_action == "list":
                eff_scope = "host"
            else:
                eff_scope = "project" if norm_sc in ("project", "workspace") else "managed"

        eff_sync_hosts = self._default_sync_hosts() if sync_hosts is None else bool(sync_hosts)
        eff_overwrite = bool(overwrite or force)

        if eff_tier == 2:
            if eff_action in ("sync", "sync_hosts", "set_host_enabled", "adopt"):
                return {
                    "ok": False,
                    "error_code": "ERR_TIER_DENIED",
                    "tier_error_code": "ERR_TIER_DENIED",
                    "blocked_by_security_gate": True,
                    "blocked_by_permission_tier": True,
                    "permission_tier": eff_tier_key,
                    "tier_level": 2,
                    "action": eff_action,
                    "error": f"Security gate: Tier L2 (`{eff_tier_key}`) prohibits host/home directory mutation action '{eff_action}'.",
                }
            if eff_action in ("create", "register", "install", "relock", "update", "trash", "remove") and eff_scope != "project":
                return {
                    "ok": False,
                    "installed": False,
                    "error_code": "ERR_TIER_DENIED",
                    "tier_error_code": "ERR_TIER_DENIED",
                    "blocked_by_security_gate": True,
                    "blocked_by_permission_tier": True,
                    "permission_tier": eff_tier_key,
                    "tier_level": 2,
                    "scope": eff_scope,
                    "error": "Security gate: Tier L2 only permits scope='project' inside authorized workspace_roots.",
                }
            eff_sync_hosts = False

        if dry_run is None:
            if tok_clean:
                eff_dry_run = False
            elif eff_action in ("create", "register") and bool(eff_content and eff_content.strip()):
                eff_dry_run = False
            elif eff_action == "install" and bool(confirm_warn):
                # Keep two-phase WARN guard in install path below (still rejects unpreviewed WARN!)
                eff_dry_run = False
            else:
                eff_dry_run = True
        else:
            eff_dry_run = bool(dry_run)

        try:
            if eff_action == "list":
                list_filter_scope = "all" if (scope is None or not str(scope).strip()) else eff_scope
                recs = self._list_records(cwd=eff_cwd, scope=list_filter_scope, include_disabled=True)
                cap = max(1, min(200, int(limit)))
                items = [r.to_summary_dict() for r in recs[:cap]]
                enabled_count = sum(1 for r in recs if r.enabled)
                disabled_count = len(recs) - enabled_count
                return {
                    "ok": True,
                    "action": "list",
                    "scope": list_filter_scope,
                    "permission_tier": eff_tier_key,
                    "state_root": str(self.config.resolved_state_root()),
                    "managed_skills_store": str(self.config.managed_skills_store()),
                    "total": len(recs),
                    "enabled_count": enabled_count,
                    "disabled_count": disabled_count,
                    "skills": items,
                    "items": items,
                }

            if eff_action == "trash_list":
                t_res = dict(self.package_manager.list_trashed_skills(limit=int(limit)))
                t_res["action"] = "trash_list"
                return t_res

            if eff_action in ("create", "register"):
                if not eff_name:
                    return {
                        "ok": False,
                        "created": False,
                        "installed": False,
                        "action": eff_action,
                        "error": f"Parameter `skill` is required for `action='{eff_action}'`.",
                    }
                if not (eff_content and eff_content.strip()):
                    return {
                        "ok": False,
                        "created": False,
                        "installed": False,
                        "action": eff_action,
                        "error": f"Parameter `content` is required for `action='{eff_action}'`.",
                    }
                return self._create_or_register_inline_skill(
                    eff_name,
                    eff_content,
                    action_name=eff_action,
                    scope=eff_scope,
                    target_workspace=ws_path,
                    dry_run=eff_dry_run,
                    confirm_warn=bool(confirm_warn),
                    overwrite=eff_overwrite,
                    sync_hosts=eff_sync_hosts,
                    tier_level=eff_tier,
                )

            if eff_action == "install":
                if eff_content and eff_name and not eff_source_ref and not tok_clean:
                    return self._create_or_register_inline_skill(
                        eff_name,
                        eff_content,
                        action_name="install",
                        scope=eff_scope,
                        target_workspace=ws_path,
                        dry_run=eff_dry_run,
                        confirm_warn=bool(confirm_warn),
                        overwrite=eff_overwrite,
                        sync_hosts=eff_sync_hosts,
                        tier_level=eff_tier,
                    )

                if tok_clean:
                    staged = self.package_manager._get_staged_preview(tok_clean)
                    if staged is None:
                        return {
                            "ok": False,
                            "installed": False,
                            "status": "invalid_or_expired_preview_token",
                            "error": "preview_token is invalid or expired; run preview/vet again.",
                        }
                    if restrict_ws and ws_roots and staged.target_workspace is not None:
                        if not self._is_within_workspaces(staged.target_workspace, ws_roots):
                            return {
                                "ok": False,
                                "installed": False,
                                "blocked_by_security_gate": True,
                                "error": "Security gate: preview_token target workspace is outside authorized workspace_roots.",
                            }
                    if eff_tier == 2:
                        if staged.scope != "project":
                            return {
                                "ok": False,
                                "installed": False,
                                "blocked_by_security_gate": True,
                                "tier_level": 2,
                                "error": "Security gate: Tier L2 only permits scope='project' installations.",
                            }
                        if staged.audit_report.verdict == "WARN" or bool(staged.audit_report.scripts_detected):
                            return {
                                "ok": False,
                                "installed": False,
                                "blocked_by_security_gate": True,
                                "tier_level": 2,
                                "verdict": staged.audit_report.verdict,
                                "scripts_detected": list(staged.audit_report.scripts_detected),
                                "error": "Security gate: Tier L2 prohibits installing skills with executable scripts or WARN findings.",
                            }
                    res_tok = self._with_warn_confirmation_message(
                        self.package_manager.install(
                            preview_token=tok_clean,
                            scope=staged.scope,
                            target_workspace=staged.target_workspace,
                            confirm_warn=bool(confirm_warn),
                            overwrite=eff_overwrite,
                            sync_hosts=eff_sync_hosts,
                            dry_run=eff_dry_run,
                            force_name=eff_name,
                        )
                    )
                    if res_tok.get("installed"):
                        self._get_index()._ensure_index(cwd=eff_cwd, force_refresh=True)
                    return res_tok

                prep = self.package_manager.prepare_install(
                    source_ref=eff_source_ref,
                    scope=eff_scope,
                    target_workspace=ws_path,
                    force_name=eff_name,
                    overwrite=eff_overwrite,
                )
                if not prep.get("ok") or eff_dry_run:
                    return prep

                audit_dict = prep.get("audit") or {}
                scripts_det = list(audit_dict.get("scripts_detected") or [])
                if eff_tier == 2 and (prep.get("verdict") == "WARN" or bool(scripts_det)):
                    return {
                        "ok": False,
                        "installed": False,
                        "blocked_by_security_gate": True,
                        "tier_level": 2,
                        "verdict": prep.get("verdict"),
                        "scripts_detected": scripts_det,
                        "audit": audit_dict,
                        "error": "Security gate: Tier L2 prohibits installing skills with executable scripts or WARN findings.",
                    }

                if prep.get("verdict") == "WARN" or prep.get("requires_confirmation"):
                    if confirm_warn:
                        out = dict(prep)
                        out.update(
                            {
                                "ok": False,
                                "installed": False,
                                "dry_run": False,
                                "blocked_by_security_gate": True,
                                "status": "warn_preview_required",
                                "requires_confirmation": True,
                                "error": (
                                    f"Skill '{prep.get('skill_name')}' triggered WARN security findings and cannot be "
                                    "installed in a single step with unpreviewed confirm_warn=True. Review audit.findings "
                                    "and re-call skill_manage(action='install', preview_token=..., confirm_warn=True)."
                                ),
                            }
                        )
                        return out
                    return self._with_warn_confirmation_message(
                        self.package_manager.install(
                            preview_token=str(prep.get("preview_token") or ""),
                            scope=eff_scope,
                            target_workspace=ws_path,
                            confirm_warn=False,
                            overwrite=eff_overwrite,
                            sync_hosts=eff_sync_hosts,
                            dry_run=False,
                            force_name=eff_name,
                        )
                    )

                res_direct = self.package_manager.install(
                    preview_token=str(prep.get("preview_token") or ""),
                    scope=eff_scope,
                    target_workspace=ws_path,
                    confirm_warn=False,
                    overwrite=eff_overwrite,
                    sync_hosts=eff_sync_hosts,
                    dry_run=False,
                    force_name=eff_name,
                )
                if res_direct.get("installed"):
                    self._get_index()._ensure_index(cwd=eff_cwd, force_refresh=True)
                return res_direct

            if eff_action in ("enable", "disable"):
                is_en = eff_action == "enable"
                if host_id and str(host_id).strip():
                    if eff_tier == 2:
                        return {
                            "ok": False,
                            "blocked_by_security_gate": True,
                            "blocked_by_permission_tier": True,
                            "tier_level": 2,
                            "error": "Security gate: Tier L2 prohibits per-host skill mutation.",
                        }
                    res_h = dict(self.package_manager.set_skill_host_enabled(eff_name, str(host_id).strip(), is_en))
                    res_h["action"] = eff_action
                    return res_h
                return self._toggle_skill_enabled(
                    eff_name,
                    enabled=is_en,
                    explicit_scope=scope,
                    ws_path=ws_path,
                    eff_cwd=eff_cwd,
                    eff_sync_hosts=eff_sync_hosts,
                    eff_tier=eff_tier,
                    restrict_ws=restrict_ws,
                    ws_roots=ws_roots,
                )

            if eff_action == "set_host_enabled":
                if not eff_name or not host_id or enabled is None:
                    return {
                        "ok": False,
                        "action": "set_host_enabled",
                        "error": "Parameters `skill`, `host_id`, and `enabled` are required for `set_host_enabled`.",
                    }
                return self.package_manager.set_skill_host_enabled(eff_name, host_id, bool(enabled))

            if eff_action in ("sync", "sync_hosts"):
                target_hosts_arg = [str(h).strip() for h in (hosts or ()) if str(h).strip()] or None
                if not target_hosts_arg and host_id and str(host_id).strip():
                    target_hosts_arg = [str(host_id).strip()]
                if eff_name:
                    res_s = dict(
                        self.package_manager.sync_skill_to_hosts(
                            eff_name,
                            target_hosts=target_hosts_arg,
                            overwrite=eff_overwrite,
                        )
                    )
                    res_s["action"] = eff_action
                    return res_s
                store = self.config.managed_skills_store()
                synced_skills: List[Dict[str, Any]] = []
                if store.is_dir():
                    for r in self._list_records(cwd=eff_cwd, scope="managed", include_disabled=False):
                        sr = self.package_manager.sync_skill_to_hosts(
                            r.dir_name,
                            source_dir=Path(r.skill_dir),
                            target_hosts=target_hosts_arg,
                            overwrite=eff_overwrite,
                        )
                        synced_skills.append(sr)
                return {
                    "ok": True,
                    "action": eff_action,
                    "synced_skill_count": len(synced_skills),
                    "skills": synced_skills,
                }

            if eff_action in ("trash", "remove"):
                if not eff_name:
                    return {"ok": False, "action": eff_action, "error": f"Parameter `skill` is required for `action='{eff_action}'`."}
                rm_res = dict(
                    self.package_manager.remove_skill(
                        eff_name,
                        scope=eff_scope,
                        target_workspace=ws_path,
                        force=bool(force or overwrite),
                    )
                )
                rm_res["action"] = eff_action
                if rm_res.get("ok"):
                    self._get_index()._ensure_index(cwd=eff_cwd, force_refresh=True)
                return rm_res

            if eff_action == "restore":
                eff_tid = (trash_id or "latest").strip() or "latest"
                rest_res = dict(self.package_manager.restore_trashed_skill(eff_tid, overwrite=eff_overwrite))
                rest_res["action"] = "restore"
                if rest_res.get("ok"):
                    self._get_index()._ensure_index(cwd=eff_cwd, force_refresh=True)
                return rest_res

            if eff_action == "check":
                return self.package_manager.check_skills(
                    scope=eff_scope,
                    target_workspace=ws_path,
                    skill_name=eff_name,
                    check_remote=bool(check_remote),
                )

            if eff_action == "relock":
                return self._relock_skills(
                    skill_name=eff_name,
                    scope=eff_scope,
                    target_workspace=ws_path,
                    sync_hosts=eff_sync_hosts,
                    tier_level=eff_tier,
                )

            if eff_action == "update":
                if eff_tier == 2:
                    return {
                        "ok": False,
                        "blocked_by_security_gate": True,
                        "tier_level": 2,
                        "error": "Security gate: Use two-phase vet + install in Tier L2 to verify prompt-only packages.",
                    }
                upd_res = self.package_manager.update_skill(
                    skill_name=eff_name,
                    scope=eff_scope,
                    target_workspace=ws_path,
                    confirm_warn=bool(confirm_warn),
                    force=eff_overwrite,
                    sync_hosts=eff_sync_hosts,
                )
                if upd_res.get("ok"):
                    self._get_index()._ensure_index(cwd=eff_cwd, force_refresh=True)
                return upd_res

            if eff_action == "scan_unmanaged":
                return self.package_manager.scan_unmanaged_skills()

            # eff_action == "adopt"
            if not eff_name and not eff_source_ref:
                return {"ok": False, "action": "adopt", "error": "Parameter `skill` (or `source`) is required for `adopt`."}
            adopt_res = self.package_manager.adopt_unmanaged_skill(
                skill_name=eff_name or Path(eff_source_ref).name,
                source_host=host_id,
                source_path=eff_source_ref or None,
                confirm_warn=bool(confirm_warn),
                sync_hosts=eff_sync_hosts,
            )
            if adopt_res.get("ok"):
                self._get_index()._ensure_index(cwd=eff_cwd, force_refresh=True)
            return adopt_res
        except Exception as exc:
            err_s = str(exc)
            is_gate = "outside authorized workspace" in err_s or "escapes" in err_s
            out_err: Dict[str, Any] = {
                "ok": False,
                "installed": False,
                "action": eff_action,
                "error": f"{type(exc).__name__}: {exc}",
            }
            if is_gate:
                out_err["blocked_by_security_gate"] = True
            return out_err


def build_skill_tool_specs(
    policy: Optional[Union["LiveRuntimePolicy", SkillsConfig]] = None,
    *,
    service: Optional[SkillsMcpService] = None,
) -> Tuple[ToolSpec, ToolSpec]:
    """Build native `(skill_hub, skill_manage)` `ToolSpec` pair directly coupled to `LiveRuntimePolicy`."""
    svc = service or SkillsMcpService(policy)

    # Guard against Gemini expand_tools truncation before the first period character.
    first_dot_hub = SKILL_HUB_DESCRIPTION.find(".")
    assert first_dot_hub == len(SKILL_HUB_DESCRIPTION) - 1
    first_dot_manage = SKILL_MANAGE_DESCRIPTION.find(".")
    assert first_dot_manage == len(SKILL_MANAGE_DESCRIPTION) - 1

    hub_spec = ToolSpec(
        base_name="skill_hub",
        handler=svc.handle_skill_hub,
        safety_band=SafetyBand.READONLY,
        input_schema=SKILL_HUB_INPUT_SCHEMA,
        title="Skill Hub",
        description=SKILL_HUB_DESCRIPTION,
        aliases=("skill_search", "skill_load"),
        param_aliases={
            "name": "skill",
            "skill_name": "skill",
            "file": "rel_path",
            "resource_path": "rel_path",
            "path": "source",
            "source_ref": "source",
            "install_ref": "source",
            "workspace": "cwd",
        },
        action_param="action",
        action_enum=SKILL_HUB_CANONICAL_ACTIONS,
        idempotent=True,
        open_world=True,
        oauth_scope="server:read",
    )

    manage_spec = ToolSpec(
        base_name="skill_manage",
        handler=svc.handle_skill_manage,
        safety_band=SafetyBand.WORKSPACE_WRITE,
        input_schema=SKILL_MANAGE_INPUT_SCHEMA,
        title="Skill Manage",
        description=SKILL_MANAGE_DESCRIPTION,
        aliases=("skill_register",),
        param_aliases={
            "name": "skill",
            "skill_name": "skill",
            "source_ref": "source",
            "install_ref": "source",
            "markdown": "content",
            "workspace": "cwd",
            "confirm_security_warnings": "confirm_warn",
            "overwrite": "force",
        },
        action_param="action",
        action_enum=SKILL_MANAGE_CANONICAL_ACTIONS,
        idempotent=False,
        open_world=True,
        oauth_scope="workspace",
    )
    return (hub_spec, manage_spec)


class SkillsCapabilityProvider(CapabilityProvider):
    """Native `CapabilityProvider` mounting `skill_hub` and `skill_manage` into `KernelDispatcher`."""

    name: str = "skills"

    def __init__(
        self,
        policy: Optional[Union["LiveRuntimePolicy", SkillsConfig]] = None,
        *,
        service: Optional[SkillsMcpService] = None,
    ) -> None:
        self.service: SkillsMcpService = service or SkillsMcpService(policy)

    def build_static_tools(self) -> Sequence[ToolSpec]:
        return build_skill_tool_specs(self.service.config, service=self.service)


__all__ = [
    "CANONICAL_TIER_MAP",
    "SKILL_HUB_ACTIONS",
    "SKILL_HUB_CANONICAL_ACTIONS",
    "SKILL_HUB_DESCRIPTION",
    "SKILL_HUB_INPUT_SCHEMA",
    "SKILL_MANAGE_ACTIONS",
    "SKILL_MANAGE_CANONICAL_ACTIONS",
    "SKILL_MANAGE_DESCRIPTION",
    "SKILL_MANAGE_INPUT_SCHEMA",
    "SkillsCapabilityProvider",
    "SkillsMcpService",
    "TIER_NUMERIC_LEVEL",
    "TIER_ORDER",
    "build_skill_tool_specs",
    "coerce_skills_config",
]
