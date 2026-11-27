from __future__ import annotations

"""
Command & Python execution, detached background job control, isolated read-only
`batch_probe`, and host/workspace status with `0..25s` job long-polling (`exec_ops.py`).

All subprocess spawning (`CREATE_NO_WINDOW`), Win32 JobObjects, L3 sandbox hooks,
and background job persistence delegate directly to `cosmos_mcp.core.proc`.
Strictly depends only on Python >=3.9 stdlib, `cosmos_mcp.core`,
and sibling `core_tools.{path_heal,workspace_memory}`.
"""

import getpass
from pathlib import Path
import platform
import shutil
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from cosmos_mcp.core.guard import WorkspaceGuard, normalize_tier
from cosmos_mcp.core.proc import (
    DEFAULT_BG_MAX_TTL_SECONDS,
    ProcessManager,
    resolve_rich_python,
)
from cosmos_mcp.core.path_heal import heal_and_resolve_path
from cosmos_mcp.core.memory import read_recent_activity


def _default_guard(guard: Optional[WorkspaceGuard], proc_mgr: Optional[ProcessManager] = None) -> WorkspaceGuard:
    if guard is not None:
        return guard
    if proc_mgr is not None and getattr(proc_mgr, "guard", None) is not None:
        return proc_mgr.guard  # type: ignore[return-value]
    return WorkspaceGuard(restrict_to_workspace=False, tier="L3")


def _default_proc_mgr(proc_mgr: Optional[ProcessManager], guard: WorkspaceGuard) -> ProcessManager:
    if proc_mgr is not None:
        return proc_mgr
    return ProcessManager(guard=guard)


def _resolve_effective_policy(
    policy: Optional[Any],
    policy_getter: Optional[Callable[[], Dict[str, Any]]],
    proc_mgr: Optional[ProcessManager],
    guard: Optional[WorkspaceGuard],
) -> Optional[Any]:
    if policy is not None:
        return policy
    if policy_getter is not None:
        try:
            return policy_getter()
        except Exception:
            pass
    if proc_mgr is not None and getattr(proc_mgr, "policy", None) is not None:
        return getattr(proc_mgr, "policy", None)
    if guard is not None and getattr(guard, "policy", None) is not None:
        return getattr(guard, "policy", None)
    return None


def get_workspace_disk_info(path_str: Union[Path, str]) -> Optional[Dict[str, Any]]:
    """Return workspace disk usage summary (`path`, `total_gb`, `free_gb`, `used_percent`)."""
    try:
        target = str(path_str)
        du = shutil.disk_usage(target)
        denom = du.used + du.free
        return {
            "path": target,
            "total_gb": round(du.total / (1024 ** 3), 2),
            "free_gb": round(du.free / (1024 ** 3), 2),
            "used_percent": round(100.0 * du.used / denom, 1) if denom > 0 else 0.0,
        }
    except Exception:
        return None


def enrich_bg_dual_keys(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Guarantee backward- and forward-compatible dual keys on background job payloads:
    - both `log_path` and `log_file`
    - both `tail` and `log_tail`
    """
    out = dict(payload)
    lp = out.get("log_path") if out.get("log_path") is not None else out.get("log_file")
    if lp is not None:
        out["log_path"] = str(lp)
        out["log_file"] = str(lp)
    elif out.get("job_id") or out.get("action") in ("start", "status", "wait", "kill"):
        out.setdefault("log_path", "")
        out.setdefault("log_file", "")

    tl = out.get("log_tail") if out.get("log_tail") is not None else out.get("tail")
    if tl is not None:
        out["log_tail"] = str(tl)
        out["tail"] = str(tl)
    elif out.get("job_id") or out.get("action") in ("start", "status", "wait", "kill"):
        out.setdefault("log_tail", "")
        out.setdefault("tail", "")

    for list_key in ("jobs", "active_jobs", "recent_jobs"):
        if isinstance(out.get(list_key), list):
            norm_jobs: List[Dict[str, Any]] = []
            for jb in out[list_key]:
                if isinstance(jb, dict):
                    jb_copy = dict(jb)
                    j_lp = jb_copy.get("log_path") if jb_copy.get("log_path") is not None else jb_copy.get("log_file")
                    if j_lp is not None:
                        jb_copy["log_path"] = str(j_lp)
                        jb_copy["log_file"] = str(j_lp)
                    j_tl = jb_copy.get("log_tail") if jb_copy.get("log_tail") is not None else jb_copy.get("tail")
                    if j_tl is not None:
                        jb_copy["log_tail"] = str(j_tl)
                        jb_copy["tail"] = str(j_tl)
                    norm_jobs.append(jb_copy)
                else:
                    norm_jobs.append(jb)
            out[list_key] = norm_jobs
    return out


def _resolve_exec_cwd(
    raw_cwd: Union[Path, str],
    guard: WorkspaceGuard,
    proc_mgr: ProcessManager,
    tool_name: str,
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    cwd_s = str(raw_cwd or "").strip()
    if not cwd_s:
        eff = proc_mgr.resolve_effective_cwd("")
        g_err = guard.check_path_access(eff, mode="read", tool_name=tool_name)
        if g_err:
            return None, {
                "ok": False,
                "blocked_by_guardrail": True,
                "exit_code": -403,
                "duration_ms": 0,
                "stdout": "",
                "stderr": g_err,
                "error": g_err,
                "truncated": False,
            }
        return eff, None

    r_info = heal_and_resolve_path(
        cwd_s,
        guard,
        mode="read",
        must_exist=True,
        expect_dir=True,
        tool_name=tool_name,
    )
    if not r_info["ok"]:
        err_msg = str(r_info.get("error") or f"Invalid cwd: {cwd_s}")
        is_guard = bool(r_info.get("blocked_by_guardrail"))
        err_out: Dict[str, Any] = {
            "ok": False,
            "blocked_by_guardrail": is_guard,
            "exit_code": -403 if is_guard else -1,
            "duration_ms": 0,
            "stdout": "",
            "stderr": err_msg,
            "error": err_msg,
            "truncated": False,
        }
        if r_info.get("did_you_mean"):
            err_out["did_you_mean"] = r_info["did_you_mean"]
        return None, err_out

    return str(r_info["path"]), None


async def run_command(
    command: str,
    cwd: Union[Path, str] = "",
    timeout_seconds: float = 90.0,
    sync_wait_cap_sec: Optional[float] = None,
    *,
    max_mem_mb: Optional[int] = None,
    proc_mgr: Optional[ProcessManager] = None,
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    """Execute a terminal command with `CREATE_NO_WINDOW` and automatic background promotion."""
    g = _default_guard(guard, proc_mgr)
    pm = _default_proc_mgr(proc_mgr, g)

    cmd_s = (command or "").strip()
    if not cmd_s:
        return {"ok": False, "exit_code": -1, "duration_ms": 0, "stdout": "", "stderr": "", "error": "`command` cannot be empty."}

    work_dir, cwd_err = _resolve_exec_cwd(cwd, g, pm, "run_command")
    if cwd_err is not None or work_dir is None:
        return cwd_err or {"ok": False, "error": "Failed to resolve working directory."}

    res = await pm.execute(
        command,
        cwd=work_dir,
        timeout=float(timeout_seconds or 90.0),
        raise_on_error=False,
        sync_wait_cap_sec=sync_wait_cap_sec,
        max_mem_mb=max_mem_mb,
    )
    if res.get("promoted_to_background") or res.get("job_id"):
        return enrich_bg_dual_keys(res)
    return res


async def run_python(
    code: str,
    cwd: Union[Path, str] = "",
    timeout_seconds: float = 90.0,
    sync_wait_cap_sec: Optional[float] = None,
    python_path: str = "",
    *,
    venv: str = "",
    conda_env: str = "",
    max_mem_mb: Optional[int] = None,
    policy: Optional[Any] = None,
    policy_getter: Optional[Callable[[], Dict[str, Any]]] = None,
    proc_mgr: Optional[ProcessManager] = None,
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    """Execute multiline Python via stdin pipe with `CREATE_NO_WINDOW` and virtual/Conda environment selection."""
    g = _default_guard(guard, proc_mgr)
    pm = _default_proc_mgr(proc_mgr, g)
    eff_pol = _resolve_effective_policy(policy, policy_getter, pm, g)

    if not (code or "").strip():
        return {"ok": False, "exit_code": -1, "duration_ms": 0, "stdout": "", "stderr": "", "error": "`code` cannot be empty."}

    work_dir, cwd_err = _resolve_exec_cwd(cwd, g, pm, "run_python")
    if cwd_err is not None or work_dir is None:
        return cwd_err or {"ok": False, "error": "Failed to resolve working directory."}

    res = await pm.execute_python_stdin(
        code,
        cwd=work_dir,
        timeout=float(timeout_seconds or 90.0),
        python_path=python_path,
        venv=venv,
        conda_env=conda_env,
        policy=eff_pol,
        max_mem_mb=max_mem_mb,
        sync_wait_cap_sec=sync_wait_cap_sec,
    )
    if res.get("promoted_to_background") or res.get("job_id"):
        return enrich_bg_dual_keys(res)
    return res


def bg_command(
    action: str = "list",
    command: str = "",
    job_id: str = "",
    cwd: Union[Path, str] = "",
    wait_seconds: float = 0.0,
    tail_lines: int = 80,
    max_ttl_seconds: Union[int, str] = DEFAULT_BG_MAX_TTL_SECONDS,
    python_path: str = "",
    *,
    venv: str = "",
    conda_env: str = "",
    policy: Optional[Any] = None,
    policy_getter: Optional[Callable[[], Dict[str, Any]]] = None,
    proc_mgr: Optional[ProcessManager] = None,
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    """
    Manage detached background jobs (`start|status|wait|list|kill`).
    Supports `job_id='latest'`, `max_ttl_seconds=14400`, `python_path` (`venv`/`conda_env`),
    and returns both `log_path`/`log_file` and `tail`/`log_tail` dual keys.
    """
    g = _default_guard(guard, proc_mgr)
    pm = _default_proc_mgr(proc_mgr, g)
    eff_pol = _resolve_effective_policy(policy, policy_getter, pm, g)

    raw_act = (action or "").strip().lower()
    if (not raw_act or raw_act == "list") and (command or "").strip() and not (job_id or "").strip():
        eff_act = "start"
    else:
        eff_act = raw_act or "list"

    if isinstance(max_ttl_seconds, str):
        s_ttl = max_ttl_seconds.strip()
        eff_ttl = int(s_ttl) if s_ttl.isdigit() else DEFAULT_BG_MAX_TTL_SECONDS
    else:
        eff_ttl = int(max_ttl_seconds or DEFAULT_BG_MAX_TTL_SECONDS)

    work_dir = ""
    if eff_act == "start" or str(cwd or "").strip():
        resolved_cwd, cwd_err = _resolve_exec_cwd(cwd, g, pm, "bg_command")
        if cwd_err is not None:
            return enrich_bg_dual_keys({**cwd_err, "action": eff_act})
        work_dir = resolved_cwd or ""
    else:
        work_dir = pm.resolve_effective_cwd("")

    raw_res = pm.manage_bg_command(
        action=eff_act,
        command=command,
        cwd=work_dir,
        job_id=job_id,
        tail_lines=int(tail_lines or 80),
        wait_seconds=max(0.0, float(wait_seconds or 0.0)),
        max_ttl_seconds=eff_ttl,
        python_path=python_path,
        venv=venv,
        conda_env=conda_env,
        policy=eff_pol,
    )
    return enrich_bg_dual_keys(raw_res)


def batch_probe(
    project_path: Union[Path, str] = ".",
    python_code: str = "",
    timeout_seconds: int = 20,
    *,
    proc_mgr: Optional[ProcessManager] = None,
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    """
    Execute an isolated read-only Python batch probe (`sys.addaudithook` locked)
    with pre-injected `PROJ`, `rg`, `outline`, `list_dir`, and `RESULT`.
    """
    g = _default_guard(guard, proc_mgr)
    pm = _default_proc_mgr(proc_mgr, g)

    r_info = heal_and_resolve_path(
        str(project_path or "."),
        g,
        mode="read",
        must_exist=True,
        expect_dir=True,
        tool_name="batch_probe",
    )
    if not r_info["ok"]:
        return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}

    proj_p: Path = r_info["path"]
    if not (python_code or "").strip():
        return {
            "ok": False,
            "path": str(proj_p),
            "error": "`python_code` is required for batch_probe (assign output to `RESULT`).",
        }

    eff_timeout = max(5, min(60, int(timeout_seconds or 20)))
    return pm.run_batch_probe(proj_p, python_code, timeout_seconds=eff_timeout)


def get_status(
    job_id: str = "",
    wait_seconds: float = 0.0,
    tail_lines: int = 80,
    guide: str = "",
    open_page: str = "",
    *,
    allow_open_page: bool = True,
    open_blocked_reason: str = "",
    proc_mgr: Optional[ProcessManager] = None,
    guard: Optional[WorkspaceGuard] = None,
    policy_getter: Optional[Callable[[], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Return local host, workspace, disk space, active policy telemetry,
    optional inline setup tutorial (`guide`), optional safe local Studio launch (`open_page`),
    or long-poll background `job_id` for `0..25s` (`wait_seconds`).
    """
    from cosmos_mcp.core.tutorials_catalog import (
        ALLOWED_STUDIO_PAGE_KEYS,
        CANONICAL_GUIDE_TOPICS,
        build_studio_deep_links,
        get_tutorial_guide,
        open_local_studio_page_safely,
        resolve_local_studio_page,
    )

    g = _default_guard(guard, proc_mgr)
    pm = _default_proc_mgr(proc_mgr, g)

    pol_extra: Dict[str, Any] = {}
    if policy_getter is not None:
        try:
            pol_extra = dict(policy_getter() or {})
        except Exception:
            pol_extra = {}

    ws_roots = [str(r) for r in g.workspace_roots]
    default_ws = str(pol_extra.get("workspace") or (ws_roots[0] if ws_roots else Path.cwd().resolve()))
    cur_tier = str(pol_extra.get("tier") or normalize_tier(g.tier))
    disk = get_workspace_disk_info(default_ws)
    eff_pol_obj = pol_extra if pol_extra else (getattr(pm, "policy", None) or getattr(g, "policy", None))
    raw_port = pol_extra.get("port") or (
        getattr(eff_pol_obj, "port", 0) if eff_pol_obj is not None and not isinstance(eff_pol_obj, dict) else 0
    )
    try:
        eff_port = int(raw_port or 0)
    except (TypeError, ValueError):
        eff_port = 0
    if eff_port <= 0 or eff_port > 65535:
        eff_port = 8096
    deep_links = build_studio_deep_links(eff_port)
    studio_nav_fields: Dict[str, Any] = {
        "studio_url": deep_links["studio"],
        "tutorials_url": deep_links["tutorials"],
        "studio_deep_links": deep_links,
        "available_guides": list(CANONICAL_GUIDE_TOPICS),
    }
    rich_py = resolve_rich_python(default_ws, guard=g, policy=eff_pol_obj)
    cfg_py = str(
        pol_extra.get("python_path")
        or (getattr(eff_pol_obj, "python_path", "") if eff_pol_obj is not None and not isinstance(eff_pol_obj, dict) else "")
        or getattr(g, "python_path", "")
        or ""
    ).strip()
    eff_python_path = cfg_py or rich_py
    raw_packs = (
        pol_extra.get("enabled_packs")
        if pol_extra.get("enabled_packs") is not None
        else (getattr(eff_pol_obj, "enabled_packs", None) if eff_pol_obj is not None and not isinstance(eff_pol_obj, dict) else None)
    )
    eff_enabled_packs = [str(x) for x in raw_packs] if raw_packs is not None else []
    available_packs = ["browser", "desktop"]

    clean_jid = (job_id or "").strip()
    if clean_jid:
        eff_wait = max(0.0, min(25.0, float(wait_seconds or 0.0)))
        bg_act = "list" if clean_jid.lower() == "list" else "status"
        target_jid = "" if bg_act == "list" else clean_jid
        bg_res = bg_command(
            action=bg_act,
            job_id=target_jid,
            cwd=default_ws,
            wait_seconds=eff_wait,
            tail_lines=int(tail_lines or 80),
            proc_mgr=pm,
            guard=g,
        )
        if not bg_res.get("ok"):
            return bg_res
        merged = {
            **bg_res,
            "permission_tier": cur_tier,
            "workspace": default_ws,
            "default_workspace": default_ws,
            "workspace_roots": ws_roots,
            "python_path": eff_python_path,
            "available_packs": available_packs,
            "enabled_packs": eff_enabled_packs,
        }
        if disk is not None:
            merged["disk"] = disk
        for k in ("device_label", "prefix", "tool_prefix", "toolset_profile"):
            if pol_extra.get(k) is not None:
                merged["tool_prefix" if k == "prefix" else k] = pol_extra[k]
        return merged

    try:
        cur_user = getpass.getuser()
    except Exception:
        cur_user = ""

    active_jobs, recent_jobs = pm.summarize_jobs_for_status(tail_lines=15)

    out: Dict[str, Any] = {
        "ok": True,
        "hostname": platform.node(),
        "user": cur_user,
        "system": platform.system(),
        "release": platform.release(),
        "python_version": platform.python_version(),
        "python_path": eff_python_path,
        "rich_python_exe": rich_py,
        "permission_tier": cur_tier,
        "restrict_to_workspace": bool(g.restrict_to_workspace),
        "workspace": default_ws,
        "default_workspace": default_ws,
        "workspace_roots": ws_roots,
        "tool_prefix": str(pol_extra.get("prefix") or pol_extra.get("tool_prefix") or g.tool_prefix),
        "available_packs": available_packs,
        "enabled_packs": eff_enabled_packs,
        "active_jobs": active_jobs,
        "recent_jobs": recent_jobs,
        "recent_workspace_activity": read_recent_activity(default_ws, limit=5, guard=g),
        **studio_nav_fields,
    }
    if disk is not None:
        out["disk"] = disk
    for opt_k in ("device_label", "toolset_profile", "prompt_profile", "enabled_packs", "keep_awake", "active_tool_count", "version"):
        if pol_extra.get(opt_k) is not None:
            out[opt_k] = pol_extra[opt_k]

    clean_open = str(open_page or "").strip()
    clean_guide = str(guide or "").strip()
    if clean_open:
        resolved_page = resolve_local_studio_page(clean_open, port=eff_port)
        target_url = resolved_page.get("url", "")
        if not target_url:
            out["opened_in_browser"] = False
            out["open_blocked_reason"] = "invalid_page_key"
            out["target_url"] = ""
            out["allowed_open_pages"] = list(ALLOWED_STUDIO_PAGE_KEYS)
        elif not allow_open_page:
            out["opened_in_browser"] = False
            out["open_blocked_reason"] = open_blocked_reason or "readonly_endpoint"
            out["target_url"] = target_url
        else:
            open_res = open_local_studio_page_safely(clean_open, port=eff_port)
            was_opened = bool(open_res.get("opened", False))
            out["opened_in_browser"] = was_opened
            out["target_url"] = str(open_res.get("url") or target_url)
            if not was_opened and open_res.get("reason"):
                out["open_blocked_reason"] = str(open_res["reason"])
        if not clean_guide and resolved_page.get("guide_topic"):
            clean_guide = resolved_page["guide_topic"]

    if clean_guide:
        guide_doc = get_tutorial_guide(clean_guide, port=eff_port)
        out["guide_topic"] = guide_doc["topic"]
        out["tutorial_markdown"] = guide_doc["markdown"]
        if guide_doc.get("unknown_guide_fallback"):
            out["requested_guide"] = guide_doc.get("requested_guide", clean_guide)
            out["unknown_guide_fallback"] = True

    return out
