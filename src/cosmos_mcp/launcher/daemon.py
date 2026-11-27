"""Detached terminal-independent daemon supervisor, anti-sleep lock, persistent slow-backoff self-healing,
`--stdio` parent-lifecycle binder, system tray controller, and non-destructive live instance hot-switch menu.

Enforces:
- 100% pure Python stdlib + `cosmos_mcp.core` + sibling cold-start modules (`bootstrap`, `tunnels`, `tray`).
- Windows detached background execution (`pythonw.exe` + `CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`),
  with non-obfuscated WMI `Win32_Process.Create` (`ShowWindow=0`, `-m cosmos_mcp.launcher.daemon`) fallback to escape
  non-breakaway parent JobObjects cleanly via module entry arguments.
- Holds `SleepInhibitor` anti-sleep lock defaulting to `keep_awake=True` so idle PCs do not sleep after 15 minutes.
- Supervises 3 independent gateway slots (`instant`, `workers_dev`, `self_hosted`) in parallel without cross-killing
  other slots, aggregating ready gateway URLs and green tray status whenever `>= 1` enabled gateway is ready.
"""
from __future__ import annotations

import contextlib
import ctypes
from dataclasses import dataclass
import hashlib
import inspect
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
import urllib.request

from cosmos_mcp.core.config import GATEWAY_IDS, normalize_gateways_config
from cosmos_mcp.core.fs_tx import atomic_write_json, safe_trash_file
from cosmos_mcp.core.net_power import SleepInhibitor
from cosmos_mcp.core.proc import (
    CREATE_NO_WINDOW,
    OwnedJobHandle,
    assign_win32_job_kill_on_close,
    get_process_create_token,
    is_raw_pid_alive,
    terminate_verified_pid_tree,
    verify_pid_alive,
)
from cosmos_mcp.launcher.bootstrap import (
    atomic_write_text,
    resolve_persisted_src_dir,
    resolve_windowless_python,
)
from cosmos_mcp.launcher.tray import WindowsSystemTrayController
import cosmos_mcp.launcher.tunnels as _tunnels_mod
from cosmos_mcp.launcher.tunnels import (
    CloudflaredTunnelSupervisor,
    VpsWssNodeSupervisor,
    build_vps_ssh_reverse_tunnel_cmd,
    ensure_cloudflared_binary,
    hot_refresh_public_url,
    load_tunnel_token,
    normalize_tunnel_token,
    save_tunnel_token,
    srvus_ssh_key_paths,
    vps_node_secret_path,
    wait_tunnel_dns_and_https_ready,
)

DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_BREAKAWAY_FROM_JOB = 0x01000000

_ORIG_CLOUDFLARED_CLS = CloudflaredTunnelSupervisor
_WMI_STDIO_HANDLE: Optional[Any] = None

# Optional lazy-loaded or monkeypatched Cloudflare Workers / Public Gateway / srv.us relay symbols
WorkersDevRelaySupervisor: Optional[Any] = None
SrvUsSshTunnelSupervisor: Optional[Any] = None
load_or_create_workers_tunnel_secret: Optional[Callable[..., str]] = None
probe_public_gateway_online: Optional[Callable[..., Dict[str, Any]]] = None


@dataclass
class GatewaySlotRuntime:
    """Live runtime state for one independent gateway slot (`instant` | `workers_dev` | `self_hosted`)."""

    slot_id: str
    enabled: bool = False
    submode: str = ""
    effective_mode: str = ""
    state: str = "disabled"  # "disabled" | "connecting" | "ready" | "error"
    ready: bool = False
    public_url: str = ""
    ready_url: str = ""
    probing_url: str = ""
    probe_note: str = ""
    next_reprobe_mono: float = 0.0
    last_error: str = ""
    last_disconnect_reason_zh: str = ""
    consecutive_failures: int = 0
    retry_not_before: float = 0.0
    active_sig: str = ""
    pid: Optional[int] = None

    def reset_disabled(self, submode: str = "") -> None:
        self.enabled = False
        if submode:
            self.submode = submode
        self.effective_mode = self.submode
        self.state = "disabled"
        self.ready = False
        self.public_url = ""
        self.ready_url = ""
        self.probing_url = ""
        self.probe_note = ""
        self.next_reprobe_mono = 0.0
        self.last_error = ""
        self.last_disconnect_reason_zh = ""
        self.consecutive_failures = 0
        self.retry_not_before = 0.0
        self.active_sig = ""
        self.pid = None

    def to_status_dict(self) -> Dict[str, Any]:
        eff_pub = self.public_url if self.enabled else ""
        is_ready = bool(self.enabled and self.ready)
        if not self.enabled:
            phase = "disabled"
        elif is_ready:
            phase = "ready"
        elif self.consecutive_failures >= 2:
            phase = "reconnecting"
        elif self.state == "error" or self.last_error:
            phase = "error"
        else:
            phase = "probing"
        out: Dict[str, Any] = {
            "slot_id": self.slot_id,
            "enabled": bool(self.enabled),
            "submode": self.submode,
            "effective_mode": (self.effective_mode or self.submode) if self.enabled else self.submode,
            "state": self.state if self.enabled else "disabled",
            "phase": phase,
            "ready": is_ready,
            "tunnel_ready": is_ready,
            "public_url": eff_pub,
            "mcp_url": f"{eff_pub}/mcp" if eff_pub else "",
            "readonly_mcp_url": f"{eff_pub}/mcp/readonly" if eff_pub else "",
            "pid": self.pid if self.enabled else None,
            "consecutive_failures": int(self.consecutive_failures) if self.enabled else 0,
            "last_error": self.last_error[:500] if (self.enabled and self.last_error) else "",
            "last_disconnect_reason_zh": (
                self.last_disconnect_reason_zh[:240] if (self.enabled and self.last_disconnect_reason_zh) else ""
            ),
        }
        if self.enabled and self.probe_note and not self.ready:
            out["probe_note"] = self.probe_note[:240]
        return out


def _resolve_srvus_supervisor_cls() -> Optional[Any]:
    return SrvUsSshTunnelSupervisor or getattr(_tunnels_mod, "SrvUsSshTunnelSupervisor", None)


_PERMANENT_TRAY_SKIP_REASONS = frozenset(
    {
        "non_windows",
        "env_cosmos_no_tray",
        "session_0_service",
        "missing_window_station",
        "non_interactive_window_station",
    }
)


_WORKERS_GATEWAY_MODES = frozenset({"workers_dev", "cloudflare_workers", "public_gateway"})


def _call_probe_public_gateway_online(base_url: str = "", timeout_sec: float = 1.5) -> Dict[str, Any]:
    probe_fn = probe_public_gateway_online
    if probe_fn is None:
        try:
            from cosmos_mcp.launcher import cf_workers_gateway as _cf_gw

            probe_fn = getattr(_cf_gw, "probe_public_gateway_online", None)
        except ImportError:
            probe_fn = None
    if callable(probe_fn):
        return probe_fn(base_url, timeout_sec=timeout_sec)
    clean = str(base_url or "").strip().rstrip("/")
    return {
        "configured": bool(clean),
        "online": False,
        "base_url": clean,
        "status_code": 0,
        "reason": "unconfigured" if not clean else "probe_unavailable",
    }


def _resolve_workers_gateway_components() -> Tuple[Optional[Any], Optional[Callable[..., str]], Optional[Callable[..., Dict[str, Any]]]]:
    """Lazily resolve `(WorkersDevRelaySupervisor, load_or_create_workers_tunnel_secret, ensure_master_seed_identity)`."""
    sup_cls = WorkersDevRelaySupervisor
    secret_fn = load_or_create_workers_tunnel_secret
    seed_fn: Optional[Callable[..., Dict[str, Any]]] = None
    try:
        from cosmos_mcp.launcher import cf_workers_gateway as _cf_gw

        if sup_cls is None:
            sup_cls = getattr(_cf_gw, "WorkersDevRelaySupervisor", None)
        if secret_fn is None:
            secret_fn = getattr(_cf_gw, "load_or_create_workers_tunnel_secret", None)
        seed_fn = getattr(_cf_gw, "ensure_master_seed_identity", None)
    except ImportError:
        pass
    return sup_cls, secret_fn, seed_fn


def _load_gateway_tunnel_secret(
    state_root: Path,
    prefix: str,
    mode: str,
    cfg_doc: Dict[str, Any],
    secret_fn: Optional[Callable[..., str]],
    seed_info: Optional[Dict[str, Any]] = None,
) -> str:
    eff_p = _norm_prefix(prefix)
    if mode == "public_gateway":
        cfg_sec = str(cfg_doc.get("public_gateway_secret") or "").strip()
        if cfg_sec:
            return cfg_sec
        sec_file = state_root / "secrets" / (
            f"public_gateway_secret_{eff_p}.txt" if eff_p != "pc" else "public_gateway_secret.txt"
        )
        if sec_file.is_file():
            try:
                s_val = sec_file.read_text(encoding="utf-8", errors="replace").strip()
                if s_val:
                    return s_val
            except OSError:
                pass
        if isinstance(seed_info, dict) and seed_info.get("node_tunnel_secret"):
            return str(seed_info["node_tunnel_secret"]).strip()
    elif cfg_doc.get("workers_tunnel_secret"):
        s_cfg = str(cfg_doc["workers_tunnel_secret"]).strip()
        if s_cfg:
            return s_cfg

    if callable(secret_fn):
        try:
            params = inspect.signature(secret_fn).parameters
            if "prefix" in params:
                return str(secret_fn(state_root, prefix=eff_p) or "").strip()
            return str(secret_fn(state_root) or "").strip()
        except Exception:
            pass

    fallback_p = state_root / "secrets" / (
        f"workers_tunnel_secret_{eff_p}.txt" if eff_p != "pc" else "workers_tunnel_secret.txt"
    )
    if fallback_p.is_file():
        try:
            return fallback_p.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return ""
    return ""


def _instantiate_workers_supervisor(
    sup_cls: Any,
    *,
    public_url: str,
    local_port: int,
    tunnel_secret: str,
    state_root: Path,
    prefix: str,
    mode: str,
    on_state_change: Callable[..., None],
) -> Any:
    """Instantiate `WorkersDevRelaySupervisor` matching its signature cleanly across `workers_dev` and `public_gateway`."""
    clean_pub = public_url.rstrip("/")
    ws_scheme = "wss://" if clean_pub.startswith("https://") else "ws://"
    ws_rest = clean_pub.split("://", 1)[-1]
    tunnel_ws_url = f"{ws_scheme}{ws_rest}/_cosmos_tunnel"

    try:
        sig = inspect.signature(sup_cls)
        params = sig.parameters
        accepts_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
    except (TypeError, ValueError):
        params = {}
        accepts_var_kw = True

    candidate_kwargs: Dict[str, Any] = {}
    url_param_matched = False
    for u_key in ("public_url", "gateway_url", "worker_url", "base_url", "url"):
        if u_key in params:
            candidate_kwargs[u_key] = clean_pub
            url_param_matched = True
            break
    if not url_param_matched and accepts_var_kw:
        candidate_kwargs["public_url"] = clean_pub

    for ws_key in ("tunnel_ws_url", "ws_url", "relay_ws_url", "tunnel_url"):
        if ws_key in params:
            candidate_kwargs[ws_key] = tunnel_ws_url
            break

    if "local_port" in params or accepts_var_kw:
        candidate_kwargs["local_port"] = int(local_port)
    elif "port" in params:
        candidate_kwargs["port"] = int(local_port)

    for sec_key in ("tunnel_secret", "secret", "auth_secret"):
        if sec_key in params:
            candidate_kwargs[sec_key] = tunnel_secret
            break
    else:
        if accepts_var_kw:
            candidate_kwargs["tunnel_secret"] = tunnel_secret

    if "state_root" in params or accepts_var_kw:
        candidate_kwargs["state_root"] = state_root
    if "prefix" in params or accepts_var_kw:
        candidate_kwargs["prefix"] = prefix
    if "mode" in params:
        candidate_kwargs["mode"] = mode

    for cb_key in ("on_ready_change", "on_state_change", "on_status_change", "on_url_change"):
        if cb_key in params:
            candidate_kwargs[cb_key] = on_state_change

    return sup_cls(**candidate_kwargs)


def _instantiate_cloudflared_supervisor(cf_cls: Any, **kwargs: Any) -> Any:
    try:
        params = inspect.signature(cf_cls).parameters
        has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
    except (TypeError, ValueError):
        params = {}
        has_var_kw = True
    filtered = {k: v for k, v in kwargs.items() if has_var_kw or k in params}
    return cf_cls(**filtered)


def _popen_flags(*, detached: bool = False, breakaway: bool = False) -> int:
    if sys.platform != "win32":
        return 0
    flags = CREATE_NO_WINDOW
    if detached:
        flags |= DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    if breakaway:
        flags |= CREATE_BREAKAWAY_FROM_JOB
    return flags


def build_wmi_daemon_cmdline(argv: List[str], *, log_path: Path, pythonpath: str = "") -> str:
    """Build a plain `-B -m cosmos_mcp.launcher.daemon` command line without obfuscation or inline `-c` code."""
    clean_argv = list(argv)
    if "--log-file" not in clean_argv:
        clean_argv.extend(["--log-file", str(log_path)])
    if pythonpath and "--pythonpath" not in clean_argv:
        clean_argv.extend(["--pythonpath", str(pythonpath)])
    return subprocess.list2cmdline(clean_argv)


def _spawn_via_wmi_win32_process(
    argv: List[str],
    *,
    cwd: Path,
    env: Dict[str, str],
    log_path: Path,
) -> Optional[int]:
    """Escape a non-breakaway Win32 JobObject by launching windowless `pythonw.exe -B -m cosmos_mcp.launcher.daemon`."""
    if sys.platform != "win32" or len(argv) < 4:
        return None
    pwsh = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not pwsh:
        return None

    pypath_val = str(env.get("PYTHONPATH") or "").strip()
    cmd_line = build_wmi_daemon_cmdline(argv, log_path=log_path, pythonpath=pypath_val)
    child_env = dict(env)
    child_env["PYTHONDONTWRITEBYTECODE"] = "1"
    child_env["PYTHONUTF8"] = "1"
    child_env["COSMOS_WMI_CMD"] = cmd_line
    child_env["COSMOS_WMI_CWD"] = str(cwd)

    ps_cmd = (
        "$ErrorActionPreference = 'Stop'; "
        "$si = ([wmiclass]'Win32_ProcessStartup').CreateInstance(); "
        "$si.ShowWindow = 0; "
        "$ev = [System.Collections.Generic.List[string]]::new(); "
        "foreach ($de in [System.Environment]::GetEnvironmentVariables().GetEnumerator()) { "
        "$k = [string]$de.Key; "
        "if ($k -and -not $k.StartsWith('COSMOS_WMI_')) { $ev.Add(\"$k=$($de.Value)\") } "
        "}; "
        "$si.EnvironmentVariables = [string[]]$ev.ToArray(); "
        "$r = ([wmiclass]'Win32_Process').Create($env:COSMOS_WMI_CMD, $env:COSMOS_WMI_CWD, $si); "
        "if ($r.ReturnValue -eq 0 -and $r.ProcessId) { Write-Output \"WMI_PID=$($r.ProcessId)\" } else { exit 1 }"
    )
    try:
        res = subprocess.run(
            [pwsh, "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=25.0,
            env=child_env,
            creationflags=CREATE_NO_WINDOW,
        )
        if res.returncode == 0:
            for ln in (res.stdout or "").splitlines():
                ln_s = ln.strip()
                if ln_s.startswith("WMI_PID="):
                    pid_val = int(ln_s.split("=", 1)[1].strip())
                    if pid_val > 0:
                        return pid_val
    except Exception:
        return None
    return None


def _norm_prefix(prefix: str) -> str:
    val = (prefix or "pc").strip().lower()
    return val if val else "pc"


def daemon_status_path(state_root: Path, prefix: str = "pc") -> Path:
    eff = _norm_prefix(prefix)
    return Path(state_root) / "state" / (f"daemon_status_{eff}.json" if eff != "pc" else "daemon_status.json")


def daemon_stop_flag_path(state_root: Path, prefix: str = "pc") -> Path:
    eff = _norm_prefix(prefix)
    return Path(state_root) / "state" / (f"daemon_stop_{eff}.flag" if eff != "pc" else "daemon_stop.flag")


def service_cfg_path(state_root: Path, prefix: str = "pc") -> Path:
    eff = _norm_prefix(prefix)
    return Path(state_root) / "config" / (f"service_{eff}.json" if eff != "pc" else "service.json")


def _retire_runtime_file(target: Path, state_root: Path, reason: str) -> None:
    if target.exists():
        safe_trash_file(target, reason=reason, undo_dir=Path(state_root) / ".undo_history")


def _is_stop_active(state_root: Path, prefix: str = "pc") -> bool:
    flag = daemon_stop_flag_path(state_root, prefix)
    if not flag.is_file():
        return False
    try:
        return flag.read_text(encoding="utf-8", errors="replace").strip().startswith("STOP:")
    except OSError:
        return False


def compute_crash_backoff_sec(consecutive_failures: int) -> float:
    """Compute slow persistent crash-recovery backoff (`1.5s -> ... -> 30s~60s`, never quitting permanently)."""
    n = max(0, int(consecutive_failures))
    if n == 0:
        return 1.5
    raw = 1.5 * (2 ** min(n, 6))
    if n >= 5:
        return min(60.0, max(30.0, raw))
    return min(60.0, raw)


def probe_local_healthz(port: int, timeout_sec: float = 4.0) -> Optional[Dict[str, Any]]:
    """Direct loopback `/healthz` check bypassing system HTTP proxy."""
    if not port or int(port) <= 0:
        return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for attempt in range(2):
        req = urllib.request.Request(
            f"http://127.0.0.1:{int(port)}/healthz",
            headers={"Accept": "application/json", "Host": f"127.0.0.1:{int(port)}"},
        )
        try:
            with opener.open(req, timeout=timeout_sec) as resp:
                if int(getattr(resp, "status", 200)) == 200:
                    doc = json.loads(resp.read().decode("utf-8", errors="replace"))
                    if isinstance(doc, dict) and doc.get("status") == "ok":
                        return doc
        except Exception:
            if attempt == 0:
                time.sleep(0.15)
                continue
            return None
    return None


def _state_fp(state_root: Path) -> str:
    norm = os.path.normcase(str(Path(state_root).expanduser().resolve()))
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:12]


_INPROC_SUPERVISOR_LOCKS: set[str] = set()
_INPROC_SUPERVISOR_LOCK_GUARD = threading.Lock()


class SupervisorSingletonLock:
    """Cross-process single-instance mutex (`Local\\CosmosMcpSupervisor_<fp>_<prefix>` on Windows, `fcntl` on POSIX)."""

    def __init__(self, state_root: Path, prefix: str = "pc") -> None:
        self.state_root = Path(state_root).expanduser().resolve()
        self.prefix = _norm_prefix(prefix)
        self.state_fp = _state_fp(self.state_root)
        self.mutex_name = f"Local\\CosmosMcpSupervisor_{self.state_fp}_{self.prefix}"
        self.lock_path = self.state_root / "state" / f"supervisor_{self.prefix}.lock"
        self._win_handle: Optional[int] = None
        self._posix_fh: Optional[Any] = None
        self._acquired: bool = False

    def acquire(self) -> bool:
        if self._acquired:
            return True
        with _INPROC_SUPERVISOR_LOCK_GUARD:
            if self.mutex_name in _INPROC_SUPERVISOR_LOCKS:
                return False
            _INPROC_SUPERVISOR_LOCKS.add(self.mutex_name)

        ok = False
        try:
            if sys.platform == "win32":
                from ctypes import wintypes

                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
                kernel32.CreateMutexW.restype = wintypes.HANDLE
                kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
                kernel32.WaitForSingleObject.restype = wintypes.DWORD
                kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
                kernel32.CloseHandle.restype = wintypes.BOOL

                h_mtx = kernel32.CreateMutexW(None, False, self.mutex_name)
                if not h_mtx:
                    return False
                wait_rc = int(kernel32.WaitForSingleObject(h_mtx, 0))
                # WAIT_OBJECT_0 (0x0) or WAIT_ABANDONED (0x80) grants ownership cleanly
                if wait_rc in (0x00000000, 0x00000080):
                    self._win_handle = int(h_mtx)
                    self._acquired = True
                    ok = True
                    return True
                kernel32.CloseHandle(h_mtx)
                return False

            import fcntl

            self.lock_path.parent.mkdir(parents=True, exist_ok=True)
            fh = self.lock_path.open("a+", encoding="utf-8")
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                fh.close()
                return False
            self._posix_fh = fh
            self._acquired = True
            ok = True
            return True
        finally:
            if not ok:
                with _INPROC_SUPERVISOR_LOCK_GUARD:
                    _INPROC_SUPERVISOR_LOCKS.discard(self.mutex_name)

    def release(self) -> None:
        if not self._acquired:
            return
        self._acquired = False
        try:
            if sys.platform == "win32" and self._win_handle:
                from ctypes import wintypes

                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel32.ReleaseMutex.argtypes = [wintypes.HANDLE]
                kernel32.ReleaseMutex.restype = wintypes.BOOL
                kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
                kernel32.CloseHandle.restype = wintypes.BOOL
                h_val, self._win_handle = self._win_handle, None
                kernel32.ReleaseMutex(wintypes.HANDLE(h_val))
                kernel32.CloseHandle(wintypes.HANDLE(h_val))
            elif self._posix_fh is not None:
                import fcntl

                fh, self._posix_fh = self._posix_fh, None
                with contextlib.suppress(OSError):
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                with contextlib.suppress(OSError):
                    fh.close()
        finally:
            with _INPROC_SUPERVISOR_LOCK_GUARD:
                _INPROC_SUPERVISOR_LOCKS.discard(self.mutex_name)


def _is_local_tcp_port_occupied(port: int) -> bool:
    if port <= 0:
        return False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_conn:
        s_conn.settimeout(0.15)
        if s_conn.connect_ex(("127.0.0.1", int(port))) == 0:
            return True
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_bind:
            s_bind.bind(("127.0.0.1", int(port)))
            return False
    except OSError:
        return True


def _is_python_executable_pid(pid: int) -> bool:
    if pid <= 0 or pid == os.getpid():
        return False
    if sys.platform == "win32":
        try:
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.QueryFullProcessImageNameW.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.LPWSTR,
                ctypes.POINTER(wintypes.DWORD),
            ]
            kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            h_proc = kernel32.OpenProcess(0x1000, False, int(pid))
            if not h_proc:
                return False
            try:
                buf_len = wintypes.DWORD(1024)
                buf = ctypes.create_unicode_buffer(1024)
                if not kernel32.QueryFullProcessImageNameW(h_proc, 0, buf, ctypes.byref(buf_len)):
                    return False
                exe_name = Path(buf.value).name.lower()
                return exe_name.startswith("python")
            finally:
                kernel32.CloseHandle(h_proc)
        except Exception:
            return False
    comm_p = Path(f"/proc/{int(pid)}/comm")
    if comm_p.is_file():
        with contextlib.suppress(OSError):
            return comm_p.read_text(encoding="utf-8", errors="replace").strip().lower().startswith("python")
    try:
        r = subprocess.run(
            ["ps", "-p", str(int(pid)), "-o", "comm="],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        return Path(r.stdout.strip()).name.lower().startswith("python")
    except Exception:
        return False


def _find_listening_pids_on_local_port(port: int) -> List[int]:
    if port <= 0:
        return []
    pids: List[int] = []
    if sys.platform == "win32":
        try:
            from ctypes import wintypes

            class _MIB_TCPROW_OWNER_PID(ctypes.Structure):
                _fields_ = [
                    ("dwState", wintypes.DWORD),
                    ("dwLocalAddr", wintypes.DWORD),
                    ("dwLocalPort", wintypes.DWORD),
                    ("dwRemoteAddr", wintypes.DWORD),
                    ("dwRemotePort", wintypes.DWORD),
                    ("dwOwningPid", wintypes.DWORD),
                ]

            iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
            size = wintypes.DWORD(0)
            iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, 2, 3, 0)
            if size.value > 0:
                buf = ctypes.create_string_buffer(size.value)
                if iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, 2, 3, 0) == 0:
                    num = int(ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD))[0])
                    rows = (_MIB_TCPROW_OWNER_PID * num).from_buffer_copy(buf, ctypes.sizeof(wintypes.DWORD))
                    for row in rows:
                        lport = socket.ntohs(int(row.dwLocalPort) & 0xFFFF)
                        opid = int(row.dwOwningPid)
                        if lport == int(port) and opid > 0 and opid not in pids:
                            pids.append(opid)
        except Exception:
            pass
    else:
        for cmd in (["lsof", "-ti", f"TCP:{int(port)}", "-sTCP:LISTEN"],):
            if shutil.which(cmd[0]):
                with contextlib.suppress(Exception):
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=2.0)
                    for tok in r.stdout.split():
                        if tok.isdigit() and int(tok) > 0 and int(tok) not in pids:
                            pids.append(int(tok))
    return pids


def detect_running_instance(state_root: Path, prefix: str = "pc") -> Dict[str, Any]:
    """Detect whether a healthy Cosmos MCP instance is currently online for `(state_root, prefix)`."""
    st_root = Path(state_root).expanduser().resolve()
    eff_p = _norm_prefix(prefix)
    d_path = daemon_status_path(st_root, eff_p)
    cfg_p = service_cfg_path(st_root, eff_p)

    cfg_doc: Dict[str, Any] = {}
    if cfg_p.is_file():
        try:
            loaded = json.loads(cfg_p.read_text(encoding="utf-8-sig"))
            if isinstance(loaded, dict):
                cfg_doc = loaded
        except Exception:
            cfg_doc = {}

    d_doc: Dict[str, Any] = {}
    if d_path.is_file():
        try:
            loaded_d = json.loads(d_path.read_text(encoding="utf-8-sig"))
            if isinstance(loaded_d, dict):
                d_doc = loaded_d
                if str(d_doc.get("status") or "") == "stopped":
                    d_doc = {}
        except Exception:
            d_doc = {}

    port = int(d_doc.get("port") or cfg_doc.get("port") or 8096)
    sup_pid = int(d_doc.get("supervisor_pid") or 0)
    sup_tok = d_doc.get("supervisor_create_token")
    srv_pid = int(d_doc.get("server_pid") or 0)
    srv_tok = d_doc.get("server_create_token")

    sup_alive = verify_pid_alive(sup_pid, sup_tok)[0] if sup_pid > 0 else False
    srv_alive = verify_pid_alive(srv_pid, srv_tok)[0] if srv_pid > 0 else False
    hz = probe_local_healthz(port) if (sup_alive or srv_alive or d_path.is_file() or cfg_p.is_file()) else None
    if hz is not None and not (sup_alive or srv_alive):
        if str(hz.get("state_fp") or "") != _state_fp(st_root):
            hz = None
    online = bool(hz is not None or sup_alive or srv_alive)

    eff_mode = str(d_doc.get("mode") or cfg_doc.get("tunnel_mode") or "local").strip().lower() or "local"
    if eff_mode == "local" and not bool(d_doc.get("any_gateway_ready")):
        pub_url = f"http://127.0.0.1:{port}"
    elif d_doc.get("tunnel_ready") and str(d_doc.get("public_url") or "").startswith("https://"):
        pub_url = str(d_doc["public_url"]).strip().rstrip("/")
    elif eff_mode == "public_gateway":
        raw_pg_pub = str(
            d_doc.get("public_url")
            or cfg_doc.get("public_base")
            or cfg_doc.get("public_base_url")
            or cfg_doc.get("public_gateway_url")
            or ""
        ).strip().rstrip("/")
        pg_h = raw_pg_pub.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower() if raw_pg_pub else ""
        if pg_h in ("127.0.0.1", "localhost", "::1") or (
            pg_h.startswith("gw.cosmos-mcp.") and pg_h.endswith((".org", ".workers.dev"))
        ):
            raw_pg_pub = ""
        pub_url = raw_pg_pub
    else:
        pub_url = str(
            d_doc.get("public_url")
            or cfg_doc.get("public_base")
            or cfg_doc.get("public_base_url")
            or cfg_doc.get("vps_hub_url")
            or cfg_doc.get("public_gateway_url")
            or cfg_doc.get("workers_dev_url")
            or f"http://127.0.0.1:{port}"
        ).rstrip("/")

    out_info: Dict[str, Any] = {
        "online": online,
        "healthz_ok": hz is not None,
        "supervisor_alive": sup_alive,
        "server_alive": srv_alive,
        "supervisor_pid": sup_pid if sup_alive else None,
        "server_pid": srv_pid if srv_alive else None,
        "port": port,
        "mode": eff_mode,
        "tunnel_mode": eff_mode,
        "effective_tunnel_mode": str(d_doc.get("effective_tunnel_mode") or eff_mode),
        "tool_prefix": str((hz or {}).get("tool_prefix") or cfg_doc.get("tool_prefix") or eff_p),
        "public_url": pub_url,
        "mcp_url": f"{pub_url}/mcp" if pub_url else "",
        "readonly_mcp_url": f"{pub_url}/mcp/readonly" if pub_url else "",
        "skill_url": f"{pub_url}/skill" if pub_url else "",
        "studio_url": f"http://127.0.0.1:{port}/",
        "local_admin_url": f"http://127.0.0.1:{port}/",
        "permission_tier": str((hz or {}).get("permission_tier") or cfg_doc.get("permission_tier") or "tier3_workspace_dev"),
        "toolset_profile": str((hz or {}).get("toolset_profile") or cfg_doc.get("toolset_profile") or "standard"),
        "workspace_roots": list(cfg_doc.get("workspace_roots") or ([cfg_doc["workspace"]] if cfg_doc.get("workspace") else [])),
        "readonly_workspace_roots": list(cfg_doc.get("readonly_workspace_roots") or []),
        "scan_host_global_skills": bool(cfg_doc.get("scan_host_global_skills", False)),
        "tray_enabled": bool(cfg_doc.get("tray_enabled", True)),
        "enabled_packs": list(cfg_doc.get("enabled_packs") or []),
        "keep_awake": bool(cfg_doc.get("keep_awake", True)),
        "tunnel_ready": bool(d_doc.get("tunnel_ready", eff_mode == "local")),
        "tunnel_token_configured": bool(load_tunnel_token(st_root, prefix=eff_p)),
        "tunnel_pid": int(d_doc.get("tunnel_pid") or 0) or None,
        "tunnel_pids": list(d_doc.get("tunnel_pids") or []),
        "last_error": str(d_doc.get("last_error") or ""),
        "healthz": hz,
    }
    for extra_k in (
        "public_gateway_online",
        "instant_fallback_active",
        "srvus_fixed_active",
        "consecutive_failures",
        "last_disconnect_reason_zh",
        "gateways",
        "selected_gateway",
        "any_gateway_ready",
        "enabled_gateway_ids",
        "ready_gateway_ids",
    ):
        if extra_k in d_doc:
            out_info[extra_k] = d_doc[extra_k]
    return out_info


def spawn_detached_daemon(
    *,
    python_exe: str | Path,
    state_root: Path,
    port: int = 8096,
    mode: str = "",
    prefix: str = "pc",
    tool_prefix: str = "",
    no_tray: bool = False,
    public_url: str = "",
    tunnel_token: str = "",
    vps_ssh: str = "",
    vps_remote_port: int = 18096,
    vps_ssh_port: int = 22,
    vps_identity_file: str = "",
    wait_ready_sec: float = 20.0,
) -> Dict[str, Any]:
    """Spawn a terminal-independent background supervisor process (`pythonw.exe` on Windows)."""
    st_root = Path(state_root).expanduser().resolve()
    eff_p = _norm_prefix(prefix)
    logs_dir = st_root / "logs"
    state_dir = st_root / "state"
    logs_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)

    if tunnel_token and normalize_tunnel_token(tunnel_token):
        save_tunnel_token(st_root, tunnel_token, prefix=eff_p)

    cfg_p = service_cfg_path(st_root, eff_p)
    saved_mode = ""
    saved_vps_ssh = ""
    saved_vps_wss_mode = False
    if cfg_p.is_file():
        try:
            doc = json.loads(cfg_p.read_text(encoding="utf-8-sig"))
            if isinstance(doc, dict):
                saved_mode = str(doc.get("tunnel_mode") or "").strip().lower()
                saved_vps_ssh = str(doc.get("vps_ssh") or "").strip()
                saved_vps_wss_mode = bool(
                    doc.get("vps_hub_mode")
                    or str(doc.get("vps_hub_url") or "").strip()
                    or str(doc.get("vps_node_secret") or "").strip()
                )
        except Exception:
            saved_mode = ""
    if vps_node_secret_path(st_root, prefix=eff_p).is_file():
        saved_vps_wss_mode = True
    eff_mode = (mode or saved_mode or "local").strip().lower()
    eff_vps_ssh = (vps_ssh or saved_vps_ssh).strip()

    sup_log = logs_dir / (f"supervisor_{eff_p}.log" if eff_p != "pc" else "supervisor.log")
    if eff_mode == "vps" and not saved_vps_wss_mode and eff_vps_ssh and shutil.which("ssh") is None:
        with sup_log.open("a", encoding="utf-8", errors="replace") as lf:
            lf.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [ERROR] supervisor precheck failed: `ssh` binary not found on PATH for --mode vps\n")
        return {
            "ok": False,
            "error": "ssh_binary_not_found",
            "detail": "未检测到系统 ssh 客户端，请先安装 OpenSSH Client 后再使用 --mode vps。",
        }

    stop_flag = daemon_stop_flag_path(st_root, eff_p)
    atomic_write_text(stop_flag, f"CLEAR:{time.time()}\n")

    exe_detached = resolve_windowless_python(python_exe)
    argv = [
        exe_detached,
        "-B",
        "-m",
        "cosmos_mcp.launcher.daemon",
        "--state-dir",
        str(st_root),
        "--runtime-python",
        str(python_exe),
        "--port",
        str(int(port)),
        "--mode",
        eff_mode,
        "--prefix",
        eff_p,
    ]
    if tool_prefix:
        argv.extend(["--tool-prefix", _norm_prefix(tool_prefix)])
    if no_tray:
        argv.append("--no-tray")
    if public_url:
        argv.extend(["--public-url", public_url])
    if eff_vps_ssh:
        argv.extend(["--vps-ssh", eff_vps_ssh, "--vps-remote-port", str(int(vps_remote_port)), "--vps-ssh-port", str(int(vps_ssh_port))])
    if vps_identity_file:
        argv.extend(["--vps-identity-file", vps_identity_file])

    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONUTF8"] = "1"
    env["COSMOS_MCP_STATE_DIR"] = str(st_root)
    env["LOCALPC_MCP_STATE_DIR"] = str(st_root)
    if no_tray:
        env["COSMOS_NO_TRAY"] = "1"
    persisted_src = resolve_persisted_src_dir(st_root)
    if persisted_src is not None:
        existing_pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{persisted_src}{os.pathsep}{existing_pp}" if existing_pp else str(persisted_src)

    spawned_pid = 0
    with sup_log.open("a", encoding="utf-8", errors="replace") as log_fh:
        log_fh.write(
            f"{time.strftime('%Y-%m-%d %H:%M:%S')} [INFO] spawning detached Cosmos MCP supervisor "
            f"(port={int(port)}, mode={eff_mode}, prefix={eff_p})\n"
        )
        log_fh.flush()
        popen_kwargs: Dict[str, Any] = {
            "stdin": subprocess.DEVNULL,
            "stdout": log_fh,
            "stderr": subprocess.STDOUT,
            "cwd": str(st_root),
            "env": env,
            "close_fds": True,
        }
        if sys.platform == "win32":
            wmi_pid = (
                _spawn_via_wmi_win32_process(argv, cwd=st_root, env=env, log_path=sup_log)
                if not os.environ.get("PYTEST_CURRENT_TEST")
                else None
            )
            if wmi_pid is not None and wmi_pid > 0:
                spawned_pid = int(wmi_pid)
            else:
                try:
                    proc = subprocess.Popen(
                        argv,
                        **popen_kwargs,
                        creationflags=_popen_flags(detached=True, breakaway=True),
                    )
                    spawned_pid = int(proc.pid)
                except OSError:
                    proc = subprocess.Popen(
                        argv,
                        **popen_kwargs,
                        creationflags=_popen_flags(detached=True, breakaway=False),
                    )
                    spawned_pid = int(proc.pid)
        else:
            popen_kwargs["start_new_session"] = True
            proc = subprocess.Popen(argv, **popen_kwargs)
            spawned_pid = int(proc.pid)

    deadline = time.monotonic() + max(1.0, float(wait_ready_sec))
    while time.monotonic() < deadline:
        live = detect_running_instance(st_root, eff_p)
        if live.get("healthz_ok"):
            if eff_mode in ("cloudflare", "cloudflare_token", "public_gateway"):
                pub_u = str(live.get("public_url") or "")
                last_err = str(live.get("last_error") or "")
                if pub_u.startswith("https://") or "tunnel error" in last_err.lower():
                    return {"ok": True, "spawned_pid": spawned_pid, **live}
            else:
                return {"ok": True, "spawned_pid": spawned_pid, **live}
        if spawned_pid > 0 and not is_raw_pid_alive(spawned_pid):
            break
        time.sleep(0.25)

    live_final = detect_running_instance(st_root, eff_p)
    return {
        "ok": bool(live_final.get("healthz_ok")),
        "spawned_pid": spawned_pid,
        **live_final,
    }


def stop_daemon(state_root: Path, prefix: str = "pc", timeout_sec: float = 8.0) -> Dict[str, Any]:
    """Gracefully stop background supervisor, all coexisting tunnel subprocesses, and MCP server processes."""
    st_root = Path(state_root).expanduser().resolve()
    eff_p = _norm_prefix(prefix)
    state_dir = st_root / "state"
    state_dir.mkdir(parents=True, exist_ok=True)

    stop_flag = daemon_stop_flag_path(st_root, eff_p)
    atomic_write_text(stop_flag, f"STOP:{time.time()}\n")

    atomic_write_json(
        state_dir / "kill_signal.json",
        {
            "ts": time.time(),
            "ts_ns": time.time_ns(),
            "reason": "daemon_stop",
            "prefix_filter": eff_p,
            "emitter_pid": os.getpid(),
        },
    )

    d_path = daemon_status_path(st_root, eff_p)
    d_doc: Dict[str, Any] = {}
    if d_path.is_file():
        try:
            loaded = json.loads(d_path.read_text(encoding="utf-8-sig"))
            if isinstance(loaded, dict):
                d_doc = loaded
        except Exception:
            d_doc = {}

    sup_pid = int(d_doc.get("supervisor_pid") or 0)
    sup_tok = d_doc.get("supervisor_create_token")
    srv_pid = int(d_doc.get("server_pid") or 0)
    srv_tok = d_doc.get("server_create_token")

    raw_tun_pids: List[int] = []
    if d_doc.get("tunnel_pid"):
        with contextlib.suppress(TypeError, ValueError):
            raw_tun_pids.append(int(d_doc["tunnel_pid"]))
    if isinstance(d_doc.get("tunnel_pids"), list):
        for tp in d_doc["tunnel_pids"]:
            with contextlib.suppress(TypeError, ValueError):
                raw_tun_pids.append(int(tp))
    if isinstance(d_doc.get("gateways"), dict):
        for gw_item in d_doc["gateways"].values():
            if isinstance(gw_item, dict) and gw_item.get("pid"):
                with contextlib.suppress(TypeError, ValueError):
                    raw_tun_pids.append(int(gw_item["pid"]))

    tun_pids_unique: List[int] = []
    seen_tp: set[int] = set()
    for tp_val in raw_tun_pids:
        if tp_val > 0 and tp_val != os.getpid() and tp_val not in (sup_pid, srv_pid) and tp_val not in seen_tp:
            seen_tp.add(tp_val)
            tun_pids_unique.append(tp_val)

    deadline = time.monotonic() + max(1.0, float(timeout_sec))
    while time.monotonic() < deadline:
        sup_alive = verify_pid_alive(sup_pid, sup_tok)[0] if sup_pid > 0 else False
        srv_alive = verify_pid_alive(srv_pid, srv_tok)[0] if srv_pid > 0 else False
        if not sup_alive and not srv_alive:
            break
        time.sleep(0.2)

    terminated: List[int] = []
    for pid, tok in ((sup_pid, sup_tok), (srv_pid, srv_tok)):
        if pid > 0 and pid != os.getpid() and verify_pid_alive(pid, tok)[0]:
            terminate_verified_pid_tree(pid, expected_create_token=tok)
            terminated.append(pid)
    for tpid in tun_pids_unique:
        if is_raw_pid_alive(tpid):
            terminate_verified_pid_tree(tpid, expected_create_token=None)
            terminated.append(tpid)

    active_dir = state_dir / "active_pids"
    if active_dir.is_dir():
        for pf in list(active_dir.glob("*.json")):
            try:
                p_doc = json.loads(pf.read_text(encoding="utf-8-sig"))
                if str(p_doc.get("tool_prefix") or "pc") != eff_p:
                    continue
                apid = int(p_doc.get("pid") or 0)
                if apid > 0 and apid != os.getpid() and is_raw_pid_alive(apid):
                    terminate_verified_pid_tree(apid, expected_create_token=None)
                    if apid not in terminated:
                        terminated.append(apid)
                _retire_runtime_file(pf, st_root, "daemon_stop_pid")
            except Exception:
                continue

    if d_path.is_file():
        atomic_write_json(d_path, {"status": "stopped", "stopped_at": round(time.time(), 3), "port": d_doc.get("port") or 8096})
    return {"ok": True, "terminated_pids": terminated}


class StandaloneSupervisorLoop:
    """Long-lived resident supervisor holding `SleepInhibitor`, managing 3 gateway slots, tray & server self-healing."""

    def __init__(
        self,
        *,
        state_root: Path,
        runtime_python: str | Path,
        port: int = 8096,
        mode: str = "",
        prefix: str = "pc",
        tool_prefix: str = "",
        no_tray: bool = False,
        public_url: str = "",
        tunnel_token: str = "",
        vps_ssh: str = "",
        vps_remote_port: Optional[int] = None,
        vps_ssh_port: Optional[int] = None,
        vps_identity_file: str = "",
        enforce_singleton: Optional[bool] = None,
    ) -> None:
        self.state_root = Path(state_root).expanduser().resolve()
        self.runtime_python = str(runtime_python)
        self.port = int(port)
        self.prefix = _norm_prefix(prefix)
        self.no_tray = bool(no_tray or str(os.environ.get("COSMOS_NO_TRAY") or "").strip().lower() in ("1", "true", "yes", "on"))

        cfg_doc = self._read_cfg_doc()
        self.tool_prefix = _norm_prefix(tool_prefix or str(cfg_doc.get("tool_prefix") or self.prefix))
        saved_mode = str(cfg_doc.get("tunnel_mode") or "").strip().lower()
        self._explicit_init_mode = (mode or "").strip().lower()
        self.mode = (mode or saved_mode or "local").strip().lower()
        saved_pub = str(
            cfg_doc.get("public_base")
            or cfg_doc.get("public_base_url")
            or cfg_doc.get("public_gateway_url")
            or cfg_doc.get("workers_dev_url")
            or ""
        ).strip().rstrip("/")
        self.public_url = (public_url or (saved_pub if self.mode != "local" else "")).strip().rstrip("/")
        if tunnel_token and normalize_tunnel_token(tunnel_token):
            save_tunnel_token(self.state_root, tunnel_token, prefix=self.prefix)
        self.tunnel_token = normalize_tunnel_token(tunnel_token) or load_tunnel_token(self.state_root, prefix=self.prefix)

        self.vps_ssh = (vps_ssh or str(cfg_doc.get("vps_ssh") or "")).strip()
        self.vps_remote_port = int(
            vps_remote_port
            if (vps_remote_port is not None and int(vps_remote_port) > 0)
            else (cfg_doc.get("vps_remote_port") or 18096)
        )
        self.vps_ssh_port = int(
            vps_ssh_port
            if (vps_ssh_port is not None and int(vps_ssh_port) > 0)
            else (cfg_doc.get("vps_ssh_port") or 22)
        )
        self.vps_identity_file = (vps_identity_file or str(cfg_doc.get("vps_identity_file") or "")).strip()

        self.inhibitor = SleepInhibitor(keep_display_on=False)
        self._status_io_lock = threading.RLock()

        # Independent per-slot tunnel supervisors (`instant`, `workers_dev`, `self_hosted`)
        self._cf_quick_supervisor: Optional[CloudflaredTunnelSupervisor] = None
        self._active_cf_quick_sig: str = ""
        self._cf_quick_retry_not_before: float = 0.0

        self._cf_named_supervisor: Optional[CloudflaredTunnelSupervisor] = None
        self._active_cf_named_sig: str = ""
        self._cf_named_retry_not_before: float = 0.0

        self._srvus_supervisor: Optional[Any] = None
        self._srvus_retry_not_before: float = 0.0
        self._srvus_fixed_active: bool = False
        self._last_srvus_retry_req_ts: float = float(cfg_doc.get("srvus_retry_requested_at") or 0.0)
        self._active_srvus_key_sig: Optional[Tuple[bool, int, int, str]] = None
        self._last_seen_srvus_key_sig: Tuple[bool, int, int, str] = self._compute_srvus_key_sig()

        self._pg_workers_supervisor: Optional[Any] = None
        self._active_pg_workers_sig: str = ""
        self._pg_workers_retry_not_before: float = 0.0

        self._workers_supervisor: Optional[Any] = None
        self._active_workers_sig: str = ""
        self._workers_retry_not_before: float = 0.0

        self._vps_wss_supervisor: Optional[Any] = None
        self._active_vps_wss_sig: str = ""
        self._vps_wss_retry_not_before: float = 0.0

        self._gateway_slots: Dict[str, GatewaySlotRuntime] = {
            gid: GatewaySlotRuntime(slot_id=gid) for gid in GATEWAY_IDS
        }
        self._selected_gateway: str = str(cfg_doc.get("selected_gateway") or "instant").strip().lower()
        if self._selected_gateway not in GATEWAY_IDS:
            self._selected_gateway = "instant"

        self._public_gateway_online: Optional[bool] = None
        self._instant_fallback_active: bool = False
        self._effective_tunnel_mode: str = self.mode
        self._pg_last_base: str = "__unprobed__"
        self._pg_next_probe_mono: float = 0.0
        self._pg_probe_interval_sec: float = 15.0
        self._consecutive_relay_failures: int = 0
        self._last_disconnect_reason_zh: str = ""
        self._last_balloon_alert_mono: Optional[float] = None
        if self.mode != "local" and self.public_url:
            pg_init_h = self.public_url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
            if (
                not self.public_url.startswith("https://")
                or pg_init_h in ("127.0.0.1", "localhost", "::1")
                or (pg_init_h.startswith("gw.cosmos-mcp.") and pg_init_h.endswith((".org", ".workers.dev")))
            ):
                self.public_url = ""
        self._ssh_proc: Optional[subprocess.Popen[Any]] = None
        self._ssh_job: Optional[OwnedJobHandle] = None
        self._active_ssh_sig: Optional[tuple[str, int, int, str]] = None
        self._ssh_retry_not_before: float = 0.0
        self._ssh_log_offset: int = 0
        self._last_tunnel_error: str = ""
        self._tunnel_ready_url: str = ""
        self._tunnel_probing_url: str = ""
        self._tunnel_probe_note: str = ""
        self._tunnel_reprobe_interval_sec: float = 9.0
        self._tunnel_next_reprobe_mono: float = 0.0
        self._server_proc: Optional[subprocess.Popen[Any]] = None
        self._server_job: Optional[OwnedJobHandle] = None
        self._tray: Optional[WindowsSystemTrayController] = None
        self._tray_permanently_unavailable: bool = False
        self.consecutive_crashes: int = 0
        self.total_restarts: int = 0
        self._enforce_singleton: Optional[bool] = enforce_singleton
        self._singleton_lock = SupervisorSingletonLock(self.state_root, self.prefix)
        self.singleton_conflict: bool = False
        self._status_flush_interval_sec: float = 15.0
        self._last_status_sig: Optional[str] = None
        self._last_status_write_mono: float = 0.0
        self._local_healthz_grace_sec: float = 30.0
        self._local_healthz_interval_sec: float = 10.0
        self._local_healthz_timeout_sec: float = 3.5
        self._local_healthz_max_failures: int = 6
        self._sup_logger, self._sup_log_handler = self._init_supervisor_logger()

    def _should_enforce_singleton(self) -> bool:
        if self._enforce_singleton is not None:
            return bool(self._enforce_singleton)
        raw_env = str(os.environ.get("COSMOS_DISABLE_SUPERVISOR_MUTEX") or "").strip().lower()
        return raw_env not in ("1", "true", "yes", "on")

    @property
    def _cf_supervisor(self) -> Optional[CloudflaredTunnelSupervisor]:
        if self.mode == "cloudflare_token" and self._cf_named_supervisor is not None:
            return self._cf_named_supervisor
        return self._cf_quick_supervisor or self._cf_named_supervisor

    @_cf_supervisor.setter
    def _cf_supervisor(self, value: Optional[CloudflaredTunnelSupervisor]) -> None:
        if value is None:
            self._cf_quick_supervisor = None
            self._cf_named_supervisor = None
            return
        if bool(getattr(value, "is_named_tunnel", False)) or self.mode == "cloudflare_token":
            self._cf_named_supervisor = value
        else:
            self._cf_quick_supervisor = value

    def _init_supervisor_logger(self) -> tuple[logging.Logger, RotatingFileHandler]:
        class _WinSafeSupHandler(RotatingFileHandler):
            def doRollover(self) -> None:
                try:
                    super().doRollover()
                except OSError:
                    pass

            def emit(self, record: logging.LogRecord) -> None:
                try:
                    super().emit(record)
                except OSError:
                    pass
                finally:
                    if self.stream is not None:
                        try:
                            self.stream.flush()
                            self.stream.close()
                        except Exception:
                            pass
                        self.stream = None

        logs_dir = self.state_root / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        sup_log = logs_dir / (f"supervisor_{self.prefix}.log" if self.prefix != "pc" else "supervisor.log")
        lgr = logging.getLogger(f"cosmos_mcp.supervisor.{self.prefix}.{os.getpid()}.{id(self)}")
        lgr.setLevel(logging.INFO)
        lgr.propagate = False
        fh = _WinSafeSupHandler(
            str(sup_log),
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
            delay=True,
        )
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] supervisor: %(message)s"))
        lgr.addHandler(fh)
        return lgr, fh

    def _log(self, msg: str, *args: Any, error: bool = False) -> None:
        try:
            if error:
                self._sup_logger.error(msg, *args)
            else:
                self._sup_logger.info(msg, *args)
            self._sup_log_handler.flush()
        except Exception:
            pass

    def _read_cfg_doc(self) -> Dict[str, Any]:
        svc_name = f"service_{self.prefix}.json" if self.prefix != "pc" else "service.json"
        candidates: List[tuple[float, Dict[str, Any]]] = []
        for cand_p in (service_cfg_path(self.state_root, self.prefix), self.state_root / "state" / svc_name):
            if not cand_p.is_file():
                continue
            try:
                doc = json.loads(cand_p.read_text(encoding="utf-8-sig"))
                if isinstance(doc, dict):
                    stamp = float(doc.get("policy_updated_at") or cand_p.stat().st_mtime)
                    candidates.append((stamp, doc))
            except Exception:
                continue
        if not candidates:
            return {}
        candidates.sort(key=lambda item: item[0])
        merged: Dict[str, Any] = {}
        for _, d in candidates:
            merged.update(d)
        return merged

    def _should_stop(self) -> bool:
        return _is_stop_active(self.state_root, self.prefix)

    def _sync_keep_awake_from_cfg(self, cfg_doc: Optional[Dict[str, Any]] = None) -> bool:
        doc = cfg_doc if cfg_doc is not None else self._read_cfg_doc()
        want_awake = bool(doc.get("keep_awake", True))
        cur_enabled = bool(self.inhibitor.status().get("enabled"))
        if want_awake and not cur_enabled:
            self.inhibitor.enable()
        elif not want_awake and cur_enabled:
            self.inhibitor.disable()
        return want_awake

    def _active_wss_relay(self) -> Optional[Any]:
        if self._workers_supervisor is not None:
            return self._workers_supervisor
        if self._pg_workers_supervisor is not None:
            return self._pg_workers_supervisor
        if self._vps_wss_supervisor is not None:
            return self._vps_wss_supervisor
        return None

    @staticmethod
    def _is_relay_obj_alive(sup_obj: Optional[Any]) -> bool:
        if sup_obj is None:
            return False
        for attr in ("is_process_alive", "is_alive", "is_running"):
            fn = getattr(sup_obj, attr, None)
            if callable(fn):
                return bool(fn())
        if hasattr(sup_obj, "running"):
            return bool(sup_obj.running)
        return True

    def _resolve_relay_pid(self, sup_obj: Optional[Any]) -> Optional[int]:
        if sup_obj is None:
            return None
        if hasattr(sup_obj, "pid"):
            raw_p = sup_obj.pid
            val = raw_p() if callable(raw_p) else raw_p
            if isinstance(val, int) and val > 0:
                return int(val)
            return None
        return os.getpid() if self._is_relay_obj_alive(sup_obj) else None

    def _resolve_workers_pid(self) -> Optional[int]:
        return self._resolve_relay_pid(self._workers_supervisor or self._pg_workers_supervisor)

    def _sanitize_public_gateway_url(self, url: str) -> str:
        raw_u = (url or "").strip().rstrip("/")
        if not raw_u.startswith("https://"):
            return ""
        u_host = raw_u.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
        if u_host in ("127.0.0.1", "localhost", "::1"):
            return ""
        if not self._public_gateway_online and u_host.startswith("gw.cosmos-mcp.") and u_host.endswith((".org", ".workers.dev")):
            return ""
        return raw_u

    def _compute_slot_pid(self, slot_id: str) -> Optional[int]:
        if slot_id == "instant":
            if self._srvus_supervisor is not None:
                p = self._resolve_relay_pid(self._srvus_supervisor)
                if p:
                    return p
            if self._cf_quick_supervisor is not None and self._cf_quick_supervisor.pid:
                return int(self._cf_quick_supervisor.pid)
            if self._pg_workers_supervisor is not None:
                return self._resolve_relay_pid(self._pg_workers_supervisor)
            return None
        if slot_id == "workers_dev":
            if self._workers_supervisor is not None:
                return self._resolve_relay_pid(self._workers_supervisor)
            return None
        if slot_id == "self_hosted":
            if self._cf_named_supervisor is not None and self._cf_named_supervisor.pid:
                return int(self._cf_named_supervisor.pid)
            if self._vps_wss_supervisor is not None:
                p = self._resolve_relay_pid(self._vps_wss_supervisor)
                if p:
                    return p
            if self._ssh_proc is not None and self._ssh_proc.poll() is None:
                return int(self._ssh_proc.pid)
            return None
        return None

    def _collect_tunnel_pids(self) -> Tuple[Optional[int], List[int]]:
        subproc_pids: List[int] = []
        any_inproc_pid: Optional[int] = None
        for gid in GATEWAY_IDS:
            slot = self._gateway_slots[gid]
            if not slot.enabled:
                continue
            spid = self._compute_slot_pid(gid)
            slot.pid = spid
            if spid and spid > 0:
                if spid != os.getpid():
                    if spid not in subproc_pids:
                        subproc_pids.append(spid)
                elif any_inproc_pid is None:
                    any_inproc_pid = spid

        sel_slot = self._gateway_slots.get(self._selected_gateway)
        primary_pid: Optional[int] = None
        if sel_slot is not None and sel_slot.enabled and sel_slot.pid:
            primary_pid = sel_slot.pid
        elif subproc_pids:
            primary_pid = subproc_pids[0]
        elif any_inproc_pid is not None:
            primary_pid = any_inproc_pid
        return primary_pid, subproc_pids

    def _recompute_aggregated_gateway_state(self) -> None:
        for gid in GATEWAY_IDS:
            slot = self._gateway_slots[gid]
            if slot.enabled:
                slot.pid = self._compute_slot_pid(gid)
            else:
                slot.pid = None

        enabled_slots = [self._gateway_slots[gid] for gid in GATEWAY_IDS if self._gateway_slots[gid].enabled]
        if not enabled_slots:
            self.mode = "local"
            self._effective_tunnel_mode = "local"
            self.public_url = f"http://127.0.0.1:{self.port}"
            self._tunnel_ready_url = ""
            self._tunnel_probe_note = ""
            self._last_tunnel_error = ""
            self._consecutive_relay_failures = 0
            self._last_disconnect_reason_zh = ""
            return

        ready_slots = [
            s
            for s in enabled_slots
            if s.ready and self._sanitize_public_gateway_url(s.public_url).startswith("https://")
        ]
        enabled_id_set = {s.slot_id for s in enabled_slots}
        sel_id = self._selected_gateway if self._selected_gateway in enabled_id_set else enabled_slots[0].slot_id
        sel_slot = self._gateway_slots[sel_id]

        if ready_slots:
            chosen = sel_slot if sel_slot in ready_slots else ready_slots[0]
            clean_ready_u = self._sanitize_public_gateway_url(chosen.public_url)
            self.mode = chosen.submode or self.mode
            self._effective_tunnel_mode = chosen.effective_mode or chosen.submode or self.mode
            self.public_url = clean_ready_u
            self._tunnel_ready_url = clean_ready_u
            self._tunnel_probe_note = ""
            # At least 1 enabled gateway is ready -> top-level & tray stay healthy green
            self._last_tunnel_error = ""
            self._consecutive_relay_failures = 0
            self._last_disconnect_reason_zh = ""
            return

        # Zero gateways ready yet: prefer selected slot (or first enabled slot with URL)
        if self._sanitize_public_gateway_url(sel_slot.public_url):
            chosen = sel_slot
        else:
            chosen = next(
                (s for s in enabled_slots if self._sanitize_public_gateway_url(s.public_url)),
                sel_slot,
            )
        self.mode = sel_slot.submode or chosen.submode or self.mode
        self._effective_tunnel_mode = chosen.effective_mode or chosen.submode or self.mode
        self.public_url = self._sanitize_public_gateway_url(chosen.public_url)
        self._tunnel_ready_url = ""

        max_consec = max((s.consecutive_failures for s in enabled_slots), default=0)
        ordered_candidates = [sel_slot] + [s for s in enabled_slots if s.slot_id != sel_slot.slot_id]
        err_slot = (
            next(
                (
                    s
                    for s in ordered_candidates
                    if s.consecutive_failures == max_consec and (s.last_disconnect_reason_zh or s.last_error)
                ),
                None,
            )
            or next((s for s in ordered_candidates if s.last_error), None)
            or chosen
        )
        self._consecutive_relay_failures = max_consec
        self._last_disconnect_reason_zh = err_slot.last_disconnect_reason_zh
        self._last_tunnel_error = err_slot.last_error
        self._tunnel_probe_note = err_slot.probe_note or chosen.probe_note

    def _push_tray_failure_if_all_gateways_down(self) -> None:
        if self._tray is None:
            return
        enabled_slots = [self._gateway_slots[gid] for gid in GATEWAY_IDS if self._gateway_slots[gid].enabled]
        any_ready = any(s.ready for s in enabled_slots)
        if any_ready:
            try:
                self._tray.update_snapshot(
                    {
                        "public_url": self.public_url,
                        "tunnel_ready": True,
                        "any_gateway_ready": True,
                        "consecutive_failures": 0,
                        "last_disconnect_reason_zh": "",
                        "last_error": "",
                        "gateways": {gid: self._gateway_slots[gid].to_status_dict() for gid in GATEWAY_IDS},
                    }
                )
            except Exception:
                pass
            return
        if self._consecutive_relay_failures >= 3:
            eff_reason = (
                self._last_disconnect_reason_zh
                or self._last_tunnel_error
                or "远程加密通道连续重连失败，正在后台持续重试。"
            )
            self._last_disconnect_reason_zh = eff_reason
            try:
                self._tray.update_snapshot(
                    {
                        "consecutive_failures": self._consecutive_relay_failures,
                        "last_disconnect_reason_zh": eff_reason,
                        "last_error": eff_reason,
                        "tunnel_ready": False,
                        "any_gateway_ready": False,
                        "gateways": {gid: self._gateway_slots[gid].to_status_dict() for gid in GATEWAY_IDS},
                    }
                )
            except Exception:
                pass

    def _write_daemon_status(self, *, state_label: str, last_error: str = "", force: bool = False) -> None:
        with self._status_io_lock:
            self._write_daemon_status_locked(state_label=state_label, last_error=last_error, force=force)

    def _write_daemon_status_locked(
        self,
        *,
        state_label: str,
        last_error: str = "",
        force: bool = False,
    ) -> None:
        if state_label != "stopped" and self._should_stop():
            return
        srv_pid = int(self._server_proc.pid) if self._server_proc and self._server_proc.poll() is None else None
        tun_pid, tun_pids = self._collect_tunnel_pids()
        gateways_payload = {gid: self._gateway_slots[gid].to_status_dict() for gid in GATEWAY_IDS}
        if "instant" in gateways_payload:
            gateways_payload["instant"]["srvus_fixed_active"] = bool(
                self._gateway_slots["instant"].enabled and self._srvus_fixed_active
            )
            gateways_payload["instant"]["instant_fallback_active"] = bool(
                self._gateway_slots["instant"].enabled and self._instant_fallback_active
            )
        enabled_ids = [gid for gid in GATEWAY_IDS if self._gateway_slots[gid].enabled]
        ready_ids = [gid for gid in enabled_ids if self._gateway_slots[gid].ready]
        any_gw_ready = len(ready_ids) > 0

        if self.mode == "local" and not enabled_ids:
            eff_pub = f"http://127.0.0.1:{self.port}"
            is_tun_ready = True
        else:
            eff_pub = self._sanitize_public_gateway_url(self.public_url)
            is_tun_ready = bool(
                any_gw_ready or (eff_pub.startswith("https://") and self._tunnel_ready_url == eff_pub)
            )

        payload: Dict[str, Any] = {
            "status": state_label,
            "supervisor_pid": os.getpid(),
            "supervisor_create_token": get_process_create_token(os.getpid()),
            "server_pid": srv_pid,
            "server_create_token": get_process_create_token(srv_pid) if srv_pid else None,
            "tunnel_pid": tun_pid,
            "tunnel_pids": tun_pids,
            "port": self.port,
            "mode": self.mode,
            "selected_gateway": self._selected_gateway if enabled_ids else "",
            "effective_tunnel_mode": self._effective_tunnel_mode or self.mode,
            "prefix": self.prefix,
            "tool_prefix": self.tool_prefix,
            "public_url": eff_pub,
            "mcp_url": f"{eff_pub}/mcp" if eff_pub else "",
            "readonly_mcp_url": f"{eff_pub}/mcp/readonly" if eff_pub else "",
            "tunnel_ready": is_tun_ready,
            "any_gateway_ready": any_gw_ready,
            "enabled_gateway_ids": enabled_ids,
            "ready_gateway_ids": ready_ids,
            "gateways": gateways_payload,
            "srvus_fixed_active": bool(self._srvus_fixed_active),
            "consecutive_crashes": self.consecutive_crashes,
            "total_restarts": self.total_restarts,
            "keep_awake": bool(self.inhibitor.status().get("enabled")),
            "updated_at": round(time.time(), 3),
        }
        if (self.mode != "local" or enabled_ids) and not eff_pub:
            payload["connecting_status_zh"] = "正在建立加密连接…"
        if self._gateway_slots["instant"].enabled and self._gateway_slots["instant"].submode == "public_gateway":
            payload["public_gateway_online"] = bool(self._public_gateway_online)
            payload["instant_fallback_active"] = bool(self._instant_fallback_active)
        elif self._instant_fallback_active:
            payload["instant_fallback_active"] = True
        if not any_gw_ready:
            if self._consecutive_relay_failures > 0:
                payload["consecutive_failures"] = self._consecutive_relay_failures
            if self._last_disconnect_reason_zh:
                payload["last_disconnect_reason_zh"] = self._last_disconnect_reason_zh[:240]
            if self._tunnel_probe_note and not is_tun_ready:
                payload["tunnel_probe_note"] = self._tunnel_probe_note[:240]
        eff_err = (last_error or ("" if any_gw_ready else self._last_tunnel_error)).strip()
        if eff_err:
            payload["last_error"] = eff_err[:500]
        target_status_p = daemon_status_path(self.state_root, self.prefix)
        sig_doc = {k: v for k, v in payload.items() if k != "updated_at"}
        status_sig = json.dumps(sig_doc, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        now_mono = time.monotonic()
        if (
            not force
            and state_label != "stopped"
            and self._last_status_sig == status_sig
            and (now_mono - self._last_status_write_mono) < max(0.0, float(self._status_flush_interval_sec))
            and target_status_p.is_file()
        ):
            return
        atomic_write_json(target_status_p, payload)
        self._last_status_sig = status_sig
        self._last_status_write_mono = now_mono

    def _sync_tray_from_cfg(self, *, state_label: str = "running", cfg_doc: Optional[Dict[str, Any]] = None) -> None:
        doc = cfg_doc if cfg_doc is not None else self._read_cfg_doc()
        want_tray = (not self.no_tray) and bool(doc.get("tray_enabled", True))
        if not want_tray:
            if self._tray is not None:
                try:
                    self._tray.stop()
                except Exception:
                    pass
                self._tray = None
            return

        if self._tray_permanently_unavailable:
            return

        enabled_ids = [gid for gid in GATEWAY_IDS if self._gateway_slots[gid].enabled]
        any_gw_ready = any(self._gateway_slots[gid].ready for gid in enabled_ids)
        gateways_payload = {gid: self._gateway_slots[gid].to_status_dict() for gid in GATEWAY_IDS}
        if "instant" in gateways_payload:
            gateways_payload["instant"]["srvus_fixed_active"] = bool(
                self._gateway_slots["instant"].enabled and self._srvus_fixed_active
            )
            gateways_payload["instant"]["instant_fallback_active"] = bool(
                self._gateway_slots["instant"].enabled and self._instant_fallback_active
            )

        if self.mode == "local" and not enabled_ids:
            eff_pub = f"http://127.0.0.1:{self.port}"
        else:
            eff_pub = self._sanitize_public_gateway_url(self.public_url)
        srv_alive = bool(self._server_proc is not None and self._server_proc.poll() is None)
        if any_gw_ready:
            eff_last_err = ""
            eff_consec = 0
            eff_reason_zh = ""
        else:
            eff_last_err = (
                self._last_disconnect_reason_zh
                if self._consecutive_relay_failures >= 3 and self._last_disconnect_reason_zh
                else self._last_tunnel_error
            )
            eff_consec = self._consecutive_relay_failures
            eff_reason_zh = self._last_disconnect_reason_zh

        snap: Dict[str, Any] = {
            "port": self.port,
            "mode": self.mode,
            "effective_tunnel_mode": self._effective_tunnel_mode or self.mode,
            "public_url": eff_pub,
            "mcp_url": f"{eff_pub}/mcp" if eff_pub else "",
            "readonly_mcp_url": f"{eff_pub}/mcp/readonly" if eff_pub else "",
            "studio_url": f"http://127.0.0.1:{self.port}/",
            "tunnel_ready": self._tunnel_ready,
            "any_gateway_ready": any_gw_ready,
            "gateways": gateways_payload,
            "permission_tier": str(doc.get("permission_tier") or "tier3_workspace_dev"),
            "previous_non_readonly_tier": str(doc.get("previous_non_readonly_tier") or "tier3_workspace_dev"),
            "server_alive": srv_alive,
            "status": state_label,
            "connecting_status_zh": "正在建立加密连接…" if ((self.mode != "local" or enabled_ids) and not eff_pub) else "",
            "last_error": eff_last_err,
            "consecutive_failures": eff_consec,
            "last_disconnect_reason_zh": eff_reason_zh,
            "instant_fallback_active": self._instant_fallback_active,
            "srvus_fixed_active": self._srvus_fixed_active,
            "connector_name": "Cosmos",
        }
        if self._gateway_slots["instant"].enabled and self._gateway_slots["instant"].submode == "public_gateway":
            snap["public_gateway_online"] = bool(self._public_gateway_online)

        if self._tray is None:
            ctrl = WindowsSystemTrayController(self.state_root, port=self.port, prefix=self.prefix)
            ctrl.update_snapshot(snap)
            if ctrl.start():
                self._tray = ctrl
            else:
                if ctrl.skip_reason in _PERMANENT_TRAY_SKIP_REASONS:
                    self._tray_permanently_unavailable = True
                ctrl.stop()
        else:
            self._tray.update_snapshot(snap)

    @property
    def _tunnel_ready(self) -> bool:
        enabled_slots = [self._gateway_slots[gid] for gid in GATEWAY_IDS if self._gateway_slots[gid].enabled]
        if not enabled_slots and self.mode == "local":
            return True
        if any(s.ready for s in enabled_slots):
            return True
        clean_u = (self.public_url or "").strip().rstrip("/")
        return bool(clean_u.startswith("https://") and self._tunnel_ready_url == clean_u)

    def _is_workers_supervisor_alive(self) -> bool:
        return self._is_relay_obj_alive(self._workers_supervisor or self._pg_workers_supervisor)

    @staticmethod
    def _read_relay_explicit_ready(w: Optional[Any]) -> Tuple[Optional[bool], str]:
        if w is None:
            return False, ""
        last_err = str(getattr(w, "last_error", "") or "").strip()
        for attr in ("is_connected", "is_ready", "tunnel_ready", "connected", "ready"):
            if hasattr(w, attr):
                raw = getattr(w, attr)
                val = raw() if callable(raw) else raw
                return bool(val), last_err
        st_fn = getattr(w, "status", None)
        if callable(st_fn):
            try:
                st_doc = st_fn()
                if isinstance(st_doc, dict):
                    if not last_err and st_doc.get("last_error"):
                        last_err = str(st_doc["last_error"]).strip()
                    for k in ("tunnel_ready", "connected", "ready"):
                        if k in st_doc:
                            return bool(st_doc[k]), last_err
            except Exception:
                pass
        return None, last_err

    def _read_workers_explicit_ready(self) -> Tuple[Optional[bool], str]:
        """Inspect explicit connectivity state on `WorkersDevRelaySupervisor` if exposed."""
        return self._read_relay_explicit_ready(self._workers_supervisor or self._pg_workers_supervisor)

    def _is_slot_proc_alive(self, slot_id: str) -> bool:
        slot = self._gateway_slots[slot_id]
        if not slot.enabled:
            return False
        if slot_id == "instant":
            if slot.submode == "public_gateway":
                if self._srvus_fixed_active and self._srvus_supervisor is not None:
                    return self._is_relay_obj_alive(self._srvus_supervisor)
                if self._instant_fallback_active and self._cf_quick_supervisor is not None:
                    alive_fn = getattr(self._cf_quick_supervisor, "is_process_alive", None)
                    return bool(alive_fn()) if callable(alive_fn) else (self._cf_quick_supervisor.pid is not None)
                if self._pg_workers_supervisor is not None:
                    return self._is_relay_obj_alive(self._pg_workers_supervisor)
                return False
            if self._cf_quick_supervisor is None:
                return False
            alive_fn = getattr(self._cf_quick_supervisor, "is_process_alive", None)
            return bool(alive_fn()) if callable(alive_fn) else (self._cf_quick_supervisor.pid is not None)
        if slot_id == "workers_dev":
            return self._is_relay_obj_alive(self._workers_supervisor)
        if slot_id == "self_hosted":
            if slot.submode == "cloudflare_token":
                if self._cf_named_supervisor is None:
                    return False
                alive_fn = getattr(self._cf_named_supervisor, "is_process_alive", None)
                return bool(alive_fn()) if callable(alive_fn) else (self._cf_named_supervisor.pid is not None)
            if slot.submode in ("vps_hub", "vps") and self._vps_wss_supervisor is not None:
                return self._is_relay_obj_alive(self._vps_wss_supervisor)
            if slot.submode == "vps":
                return self._ssh_proc is not None and self._ssh_proc.poll() is None
            return bool(slot.public_url.startswith("https://"))
        return False

    def _is_tunnel_proc_alive(self) -> bool:
        return any(self._is_slot_proc_alive(gid) for gid in GATEWAY_IDS if self._gateway_slots[gid].enabled)

    def _verify_slot_public_ready_async(
        self,
        slot: GatewaySlotRuntime,
        target_url: str,
        *,
        tunnel_mode: str = "",
        timeout_sec: float = 15.0,
        recheck_existing: bool = False,
    ) -> None:
        clean_u = (target_url or "").strip().rstrip("/")
        if not clean_u.startswith("https://") or not slot.enabled:
            return
        if ((slot.ready and slot.ready_url == clean_u) and not recheck_existing) or slot.probing_url == clean_u:
            return
        slot.probing_url = clean_u
        slot_id = slot.slot_id
        eff_tm = tunnel_mode or slot.submode or self.mode

        def _probe_worker() -> None:
            try:
                res = wait_tunnel_dns_and_https_ready(clean_u, timeout_sec=timeout_sec)
            except Exception as exc:
                res = {"ok": False, "error": str(exc)}
            finally:
                if slot.probing_url == clean_u:
                    slot.probing_url = ""
            if self._should_stop() or not slot.enabled or (slot.public_url or "").strip().rstrip("/") != clean_u:
                return
            if res.get("ok"):
                was_already_ready = bool(slot.ready and slot.ready_url == clean_u)
                if not was_already_ready:
                    hot_refresh_public_url(
                        self.state_root,
                        clean_u,
                        port=self.port,
                        prefix=self.prefix,
                        tunnel_mode=eff_tm,
                        gateway_id=slot_id,
                    )
                with self._status_io_lock:
                    slot.ready = True
                    slot.ready_url = clean_u
                    slot.state = "ready"
                    slot.probe_note = ""
                    slot.last_error = ""
                    slot.last_disconnect_reason_zh = ""
                    slot.consecutive_failures = 0
                    slot.next_reprobe_mono = time.monotonic() + 45.0
                    if not was_already_ready:
                        self._recompute_aggregated_gateway_state()
                        self._push_tray_failure_if_all_gateways_down()
                        self._write_daemon_status_locked(state_label="running", last_error=self._last_tunnel_error)
                if not was_already_ready:
                    self._log(
                        "public tunnel DNS+HTTPS verified ready [%s]: %s (dns=%s)",
                        slot_id,
                        clean_u,
                        res.get("dns_provider") or "https_direct",
                    )
            else:
                with self._status_io_lock:
                    slot.consecutive_failures = int(getattr(slot, "consecutive_failures", 0) or 0) + 1
                    if recheck_existing and slot.ready and slot.consecutive_failures < 2:
                        slot.next_reprobe_mono = time.monotonic() + 12.0
                        return
                    slot.ready = False
                    slot.ready_url = ""
                    if slot.state != "error":
                        slot.state = "connecting"
                    slot.probe_note = str(res.get("error") or "waiting_for_public_https")[:240]
                    slot.next_reprobe_mono = time.monotonic() + max(0.05, float(self._tunnel_reprobe_interval_sec))
                    self._recompute_aggregated_gateway_state()
                    self._write_daemon_status_locked(state_label="running", last_error=self._last_tunnel_error)
                self._log("public tunnel readiness probe pending [%s] for %s: %s", slot_id, clean_u, slot.probe_note)

        threading.Thread(
            target=_probe_worker,
            name=f"cosmos-tunnel-probe-{self.prefix}-{slot_id}",
            daemon=True,
        ).start()

    def _sync_slot_wss_readiness(
        self,
        slot: GatewaySlotRuntime,
        relay_obj: Optional[Any],
        *,
        tunnel_mode: str,
        stopped_note: str = "workers_relay_stopped",
    ) -> bool:
        if relay_obj is None or not slot.enabled:
            return False
        consec = max(0, int(getattr(relay_obj, "consecutive_failures", 0) or 0))
        reason_zh = str(
            getattr(relay_obj, "last_disconnect_reason_zh", "") or getattr(relay_obj, "last_error", "") or ""
        ).strip()
        slot.consecutive_failures = consec

        clean_u = (slot.public_url or "").strip().rstrip("/")
        if not clean_u.startswith("https://") or not self._is_relay_obj_alive(relay_obj):
            was_ready = slot.ready
            slot.ready = False
            slot.ready_url = ""
            slot.probe_note = stopped_note
            if consec >= 3 or reason_zh:
                slot.last_disconnect_reason_zh = reason_zh or "远程加密通道连续重连失败，正在后台持续重试。"
                slot.last_error = slot.last_disconnect_reason_zh
                slot.state = "error"
            else:
                slot.state = "connecting"
            return was_ready

        exp_ready, w_err = self._read_relay_explicit_ready(relay_obj)
        if exp_ready is True:
            changed = (not slot.ready) or (slot.ready_url != clean_u) or bool(slot.last_error)
            slot.ready = True
            slot.ready_url = clean_u
            slot.state = "ready"
            slot.probe_note = ""
            slot.last_error = ""
            slot.last_disconnect_reason_zh = ""
            slot.consecutive_failures = 0
            if changed:
                hot_refresh_public_url(
                    self.state_root,
                    clean_u,
                    port=self.port,
                    prefix=self.prefix,
                    tunnel_mode=tunnel_mode,
                    gateway_id=slot.slot_id,
                )
            return changed
        if exp_ready is False:
            eff_err_txt = reason_zh or w_err
            if consec >= 3 and not eff_err_txt:
                eff_err_txt = "远程加密通道连续重连失败，正在后台持续重试。"
            changed = slot.ready or (eff_err_txt != slot.last_error) or (consec >= 3)
            slot.ready = False
            slot.ready_url = ""
            slot.last_disconnect_reason_zh = eff_err_txt
            slot.last_error = eff_err_txt
            slot.probe_note = eff_err_txt[:240] if eff_err_txt else "waiting_for_workers_ws"
            slot.state = "error" if (consec >= 3 or bool(eff_err_txt)) else "connecting"
            return changed
        return False

    def _poll_tunnel_readiness(self) -> None:
        """Periodically re-probe public HTTPS readiness across all enabled gateway slots."""
        if self._should_stop():
            return
        enabled_slots = [self._gateway_slots[gid] for gid in GATEWAY_IDS if self._gateway_slots[gid].enabled]
        if not enabled_slots:
            return

        any_changed = False
        now_mono = time.monotonic()

        for slot in enabled_slots:
            gid = slot.slot_id
            # 1) WSS relay slots (`workers_dev`, `instant:public_gateway` online, `self_hosted:vps_hub`)
            if gid == "workers_dev" and self._workers_supervisor is not None:
                if self._sync_slot_wss_readiness(
                    slot,
                    self._workers_supervisor,
                    tunnel_mode="workers_dev",
                    stopped_note="workers_relay_stopped",
                ):
                    any_changed = True
                exp_r, _ = self._read_relay_explicit_ready(self._workers_supervisor)
                if exp_r is not None:
                    continue

            if gid == "instant" and slot.submode == "public_gateway" and self._pg_workers_supervisor is not None:
                if self._sync_slot_wss_readiness(
                    slot,
                    self._pg_workers_supervisor,
                    tunnel_mode="public_gateway",
                    stopped_note="workers_relay_stopped",
                ):
                    any_changed = True
                exp_pg, _ = self._read_relay_explicit_ready(self._pg_workers_supervisor)
                if exp_pg is not None:
                    continue

            if gid == "self_hosted" and slot.submode in ("vps_hub", "vps") and self._vps_wss_supervisor is not None:
                if self._sync_slot_wss_readiness(
                    slot,
                    self._vps_wss_supervisor,
                    tunnel_mode=slot.submode,
                    stopped_note="vps_wss_stopped",
                ):
                    any_changed = True
                exp_v, _ = self._read_relay_explicit_ready(self._vps_wss_supervisor)
                if exp_v is not None:
                    continue

            # 2) Subprocess / HTTP-probed slots (`srv_us`, `cloudflare`, `cloudflare_token`, `vps` SSH, `custom`)
            clean_u = (slot.public_url or "").strip().rstrip("/")
            alive = self._is_slot_proc_alive(gid)
            if not clean_u.startswith("https://") or not alive:
                if slot.ready or slot.ready_url:
                    slot.ready = False
                    slot.ready_url = ""
                    slot.probing_url = ""
                    slot.probe_note = "tunnel_process_exited" if not alive else ""
                    slot.next_reprobe_mono = 0.0
                    slot.state = "error" if slot.last_error else "connecting"
                    any_changed = True
                continue
            if slot.probing_url == clean_u:
                continue
            if slot.ready:
                if slot.next_reprobe_mono <= 0.0:
                    slot.next_reprobe_mono = now_mono + 45.0
                elif now_mono >= slot.next_reprobe_mono:
                    slot.next_reprobe_mono = now_mono + 45.0
                    self._verify_slot_public_ready_async(
                        slot,
                        clean_u,
                        tunnel_mode=slot.submode,
                        timeout_sec=5.0,
                        recheck_existing=True,
                    )
                continue
            if now_mono >= slot.next_reprobe_mono:
                slot.next_reprobe_mono = now_mono + max(0.05, float(self._tunnel_reprobe_interval_sec))
                self._verify_slot_public_ready_async(
                    slot,
                    clean_u,
                    tunnel_mode=slot.submode,
                    timeout_sec=5.0,
                )

        self._recompute_aggregated_gateway_state()
        self._push_tray_failure_if_all_gateways_down()
        if any_changed or self._consecutive_relay_failures >= 3:
            self._write_daemon_status(state_label="running", last_error=self._last_tunnel_error)

    def _compute_srvus_key_sig(self) -> Tuple[bool, int, int, str]:
        priv_p, _ = srvus_ssh_key_paths(self.state_root, self.prefix)
        try:
            if not priv_p.is_file():
                return (False, 0, 0, "")
            st = priv_p.stat()
            digest = hashlib.sha256(priv_p.read_bytes()).hexdigest()[:16]
            return (True, int(st.st_mtime_ns), int(st.st_size), digest)
        except OSError:
            return (False, 0, 0, "")

    def _stop_srvus_supervisor(self) -> None:
        if self._srvus_supervisor is None:
            self._srvus_fixed_active = False
            self._active_srvus_key_sig = None
            return
        s_sup = self._srvus_supervisor
        self._srvus_supervisor = None
        self._srvus_fixed_active = False
        self._active_srvus_key_sig = None
        try:
            stop_fn = getattr(s_sup, "stop", None) or getattr(s_sup, "close", None)
            if callable(stop_fn):
                stop_fn()
        except Exception:
            pass

    def _stop_cf_quick_supervisor(self) -> None:
        if self._cf_quick_supervisor is None:
            self._active_cf_quick_sig = ""
            return
        q_sup = self._cf_quick_supervisor
        self._cf_quick_supervisor = None
        self._active_cf_quick_sig = ""
        try:
            q_sup.stop()
        except Exception:
            pass

    def _stop_cf_named_supervisor(self) -> None:
        if self._cf_named_supervisor is None:
            self._active_cf_named_sig = ""
            return
        n_sup = self._cf_named_supervisor
        self._cf_named_supervisor = None
        self._active_cf_named_sig = ""
        try:
            n_sup.stop()
        except Exception:
            pass

    def _stop_cf_supervisor(self) -> None:
        self._stop_cf_quick_supervisor()
        self._stop_cf_named_supervisor()

    def _stop_pg_workers_supervisor(self) -> None:
        if self._pg_workers_supervisor is None:
            self._active_pg_workers_sig = ""
            return
        pw_sup = self._pg_workers_supervisor
        self._pg_workers_supervisor = None
        self._active_pg_workers_sig = ""
        try:
            stop_fn = getattr(pw_sup, "stop", None) or getattr(pw_sup, "close", None)
            if callable(stop_fn):
                stop_fn()
        except Exception:
            pass

    def _stop_workers_supervisor(self) -> None:
        if self._workers_supervisor is None:
            self._active_workers_sig = ""
            return
        w_sup = self._workers_supervisor
        self._workers_supervisor = None
        self._active_workers_sig = ""
        try:
            stop_fn = getattr(w_sup, "stop", None) or getattr(w_sup, "close", None)
            if callable(stop_fn):
                stop_fn()
        except Exception:
            pass

    def _stop_vps_wss_supervisor(self) -> None:
        if self._vps_wss_supervisor is None:
            self._active_vps_wss_sig = ""
            return
        v_sup = self._vps_wss_supervisor
        self._vps_wss_supervisor = None
        self._active_vps_wss_sig = ""
        try:
            stop_fn = getattr(v_sup, "stop", None) or getattr(v_sup, "close", None)
            if callable(stop_fn):
                stop_fn()
        except Exception:
            pass

    def _stop_ssh_tunnel(self) -> None:
        if self._ssh_proc is None and self._ssh_job is None and self._active_ssh_sig is None:
            return
        proc = self._ssh_proc
        self._ssh_proc = None
        self._active_ssh_sig = None
        if proc is not None:
            pid = getattr(proc, "pid", None)
            if proc.poll() is None:
                if isinstance(pid, int) and pid > 0:
                    terminate_verified_pid_tree(pid, expected_create_token=None)
                if proc.poll() is None:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                try:
                    proc.wait(timeout=2.0)
                except Exception:
                    pass
            else:
                try:
                    proc.wait(timeout=0.2)
                except Exception:
                    pass
        if self._ssh_job is not None:
            try:
                self._ssh_job.close()
            except Exception:
                pass
            self._ssh_job = None

    @staticmethod
    def _extract_ssh_log_error(ssh_log: Path, start_offset: int, exit_code: Optional[int]) -> str:
        if ssh_log.is_file():
            try:
                with ssh_log.open("rb") as fh:
                    size = ssh_log.stat().st_size
                    seek_pos = max(0, min(int(start_offset), size))
                    if size - seek_pos > 8192:
                        seek_pos = size - 8192
                    fh.seek(seek_pos)
                    chunk = fh.read().decode("utf-8", errors="replace")
                lines = [ln.strip() for ln in chunk.splitlines() if ln.strip()]
                if lines:
                    return " | ".join(lines[-2:])[:280]
            except Exception:
                pass
        return f"ssh exited with code {exit_code}"

    def _start_or_maintain_srvus_tunnel(self, slot: GatewaySlotRuntime, *, initial: bool) -> bool:
        srvus_cls = _resolve_srvus_supervisor_cls()
        if srvus_cls is None:
            return False
        if (
            os.environ.get("PYTEST_CURRENT_TEST")
            and not os.environ.get("COSMOS_TEST_ALLOW_SRVUS")
            and SrvUsSshTunnelSupervisor is None
            and CloudflaredTunnelSupervisor is not _ORIG_CLOUDFLARED_CLS
            and str(getattr(srvus_cls, "__module__", "")).startswith("cosmos_mcp.")
        ):
            return False

        cur_key_sig = self._compute_srvus_key_sig()
        if cur_key_sig != self._last_seen_srvus_key_sig:
            self._last_seen_srvus_key_sig = cur_key_sig
            self._srvus_retry_not_before = 0.0

        if self._srvus_supervisor is not None:
            if self._active_srvus_key_sig is not None and cur_key_sig != self._active_srvus_key_sig:
                self._log("srv.us Ed25519 key changed; restarting persistent SSH tunnel with updated identity")
                self._stop_srvus_supervisor()
                self._srvus_retry_not_before = 0.0
                if slot.public_url.endswith(".srv.us"):
                    slot.public_url = ""
                    slot.ready = False
                    slot.ready_url = ""
            elif self._is_relay_obj_alive(self._srvus_supervisor) and slot.public_url.startswith("https://"):
                slot.effective_mode = "srv_us"
                self._srvus_fixed_active = True
                self._instant_fallback_active = False
                return True
            else:
                self._stop_srvus_supervisor()

        if not initial and time.monotonic() < self._srvus_retry_not_before:
            return False

        def _on_srvus_url(new_u: str) -> None:
            clean_new = (new_u or "").strip().rstrip("/")
            if not clean_new.startswith("https://") or not slot.enabled:
                return
            if clean_new != slot.public_url:
                slot.ready = False
                slot.ready_url = ""
                slot.probing_url = ""
                slot.next_reprobe_mono = 0.0
            slot.public_url = clean_new
            slot.effective_mode = "srv_us"
            slot.last_error = ""
            slot.state = "ready" if slot.ready else "connecting"
            self._srvus_fixed_active = True
            self._instant_fallback_active = False
            hot_refresh_public_url(
                self.state_root,
                clean_new,
                port=self.port,
                prefix=self.prefix,
                tunnel_mode="public_gateway",
                gateway_id="instant",
            )
            self._recompute_aggregated_gateway_state()
            self._write_daemon_status(state_label="running", last_error=self._last_tunnel_error)
            self._verify_slot_public_ready_async(slot, clean_new, tunnel_mode="public_gateway")

        srvus_inst: Optional[Any] = None
        try:
            srvus_kwargs: Dict[str, Any] = {
                "local_port": self.port,
                "state_root": self.state_root,
                "prefix": self.prefix,
                "on_url_change": _on_srvus_url,
            }
            try:
                sig_s = inspect.signature(srvus_cls).parameters
                has_vk_s = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig_s.values())
                if "persist_tunnel_mode" in sig_s or has_vk_s:
                    srvus_kwargs["persist_tunnel_mode"] = "public_gateway"
                if "gateway_id" in sig_s or has_vk_s:
                    srvus_kwargs["gateway_id"] = "instant"
            except (TypeError, ValueError):
                pass
            srvus_inst = srvus_cls(**srvus_kwargs)
            start_fn = getattr(srvus_inst, "start", None)
            found_url = str(start_fn(wait_url_timeout_sec=4.0) if callable(start_fn) else "").strip().rstrip("/")
            if found_url.startswith("https://"):
                self._stop_cf_quick_supervisor()
                self._cf_quick_retry_not_before = 0.0
                self._srvus_supervisor = srvus_inst
                self._active_srvus_key_sig = self._compute_srvus_key_sig()
                self._last_seen_srvus_key_sig = self._active_srvus_key_sig
                self._srvus_retry_not_before = 0.0
                self._srvus_fixed_active = True
                self._instant_fallback_active = False
                slot.effective_mode = "srv_us"
                slot.public_url = found_url
                slot.last_error = ""
                slot.state = "ready" if slot.ready else "connecting"
                hot_refresh_public_url(
                    self.state_root,
                    found_url,
                    port=self.port,
                    prefix=self.prefix,
                    tunnel_mode="public_gateway",
                    gateway_id="instant",
                )
                self._recompute_aggregated_gateway_state()
                self._write_daemon_status(state_label="running", last_error=self._last_tunnel_error)
                self._verify_slot_public_ready_async(slot, found_url, tunnel_mode="public_gateway")
                return True
        except Exception as exc:
            self._log("srv.us persistent SSH tunnel unavailable, falling back to Quick Tunnel: %s", exc)

        if srvus_inst is not None:
            try:
                stop_fn = getattr(srvus_inst, "stop", None)
                if callable(stop_fn):
                    stop_fn()
            except Exception:
                pass
        self._srvus_retry_not_before = time.monotonic() + 60.0
        self._srvus_fixed_active = False
        return False

    def _start_or_maintain_quick_cloudflared(
        self,
        slot: GatewaySlotRuntime,
        *,
        initial: bool,
        fallback_from_public_gateway: bool = False,
    ) -> None:
        want_sig = "quick_fb" if fallback_from_public_gateway else "quick_direct"
        eff_tm = "public_gateway" if fallback_from_public_gateway else "cloudflare"
        if self._cf_quick_supervisor is None or self._active_cf_quick_sig != want_sig:
            if not initial and time.monotonic() < self._cf_quick_retry_not_before:
                return
            self._stop_cf_quick_supervisor()
            try:
                cf_bin = ensure_cloudflared_binary(self.state_root / "bin")

                def _on_cf_url(new_u: str) -> None:
                    if not slot.enabled:
                        return
                    if new_u != slot.public_url:
                        slot.ready = False
                        slot.ready_url = ""
                        slot.probing_url = ""
                        slot.next_reprobe_mono = 0.0
                    slot.public_url = new_u
                    slot.last_error = ""
                    slot.state = "ready" if slot.ready else "connecting"
                    hot_refresh_public_url(
                        self.state_root,
                        new_u,
                        port=self.port,
                        prefix=self.prefix,
                        tunnel_mode=eff_tm,
                        gateway_id="instant",
                    )
                    self._recompute_aggregated_gateway_state()
                    self._write_daemon_status(state_label="running", last_error=self._last_tunnel_error)
                    self._verify_slot_public_ready_async(slot, new_u, tunnel_mode=eff_tm)

                self._cf_quick_supervisor = _instantiate_cloudflared_supervisor(
                    CloudflaredTunnelSupervisor,
                    cloudflared_bin=cf_bin,
                    local_port=self.port,
                    state_root=self.state_root,
                    prefix=self.prefix,
                    protocol="http2",
                    persist_tunnel_mode=eff_tm,
                    gateway_id="instant",
                    on_url_change=_on_cf_url,
                )
                self._active_cf_quick_sig = want_sig
                self._cf_quick_retry_not_before = 0.0
                found_url = str(self._cf_quick_supervisor.start(wait_url_timeout_sec=12.0 if initial else 6.0) or "").strip()
                if found_url:
                    slot.public_url = found_url
                    slot.last_error = ""
                    slot.state = "ready" if slot.ready else "connecting"
                    hot_refresh_public_url(
                        self.state_root,
                        found_url,
                        port=self.port,
                        prefix=self.prefix,
                        tunnel_mode=eff_tm,
                        gateway_id="instant",
                    )
                    self._recompute_aggregated_gateway_state()
                    self._write_daemon_status(state_label="running", last_error=self._last_tunnel_error)
                    self._verify_slot_public_ready_async(slot, found_url, tunnel_mode=eff_tm)
                else:
                    slot.state = "error"
                    slot.last_error = (
                        "cloudflare tunnel error: 暂未连上 Cloudflare 边缘节点分配公网 HTTPS 地址"
                        "（正在后台持续重试，请检查网络连接或切换其他通道）"
                    )
            except Exception as exc:
                self._cf_quick_retry_not_before = time.monotonic() + 15.0
                slot.state = "error"
                slot.last_error = (
                    f"cloudflare tunnel error: 无法启动 Cloudflare 加密通道"
                    f"（联网后自动重试）：{exc}"
                )

    def _sync_instant_slot(self, slot_cfg: Dict[str, Any], doc: Dict[str, Any], *, initial: bool) -> None:
        slot = self._gateway_slots["instant"]
        raw_sub = str(slot_cfg.get("submode") or "public_gateway").strip().lower()
        submode = raw_sub if raw_sub in ("public_gateway", "cloudflare") else "public_gateway"
        if not bool(slot_cfg.get("enabled")):
            self._stop_srvus_supervisor()
            self._stop_cf_quick_supervisor()
            self._stop_pg_workers_supervisor()
            self._srvus_retry_not_before = 0.0
            self._cf_quick_retry_not_before = 0.0
            self._pg_workers_retry_not_before = 0.0
            self._public_gateway_online = None
            self._instant_fallback_active = False
            self._srvus_fixed_active = False
            slot.reset_disabled(submode=submode)
            return

        prev_sub = slot.submode
        was_enabled = slot.enabled
        slot.enabled = True
        slot.submode = submode

        if submode == "cloudflare":
            self._stop_srvus_supervisor()
            self._stop_pg_workers_supervisor()
            self._srvus_retry_not_before = 0.0
            self._pg_workers_retry_not_before = 0.0
            self._public_gateway_online = None
            self._instant_fallback_active = False
            self._srvus_fixed_active = False
            slot.effective_mode = "cloudflare"
            if (not was_enabled or prev_sub != "cloudflare") and not initial and "trycloudflare.com" not in slot.public_url.lower():
                slot.public_url = ""
                slot.ready = False
                slot.ready_url = ""
            self._start_or_maintain_quick_cloudflared(slot, initial=initial, fallback_from_public_gateway=False)
            return

        # `submode == "public_gateway"`
        sup_cls, sec_fn, seed_fn = _resolve_workers_gateway_components()
        retry_req_ts = float(doc.get("srvus_retry_requested_at") or 0.0)
        if retry_req_ts > self._last_srvus_retry_req_ts:
            self._last_srvus_retry_req_ts = retry_req_ts
            self._srvus_retry_not_before = 0.0
            self._pg_next_probe_mono = 0.0

        pg_base = str(
            os.environ.get("COSMOS_PUBLIC_GATEWAY_BASE")
            or doc.get("public_gateway_base")
            or ""
        ).strip().rstrip("/")
        if not pg_base:
            cand_pg_u = str(doc.get("public_gateway_url") or "").strip().rstrip("/")
            if cand_pg_u and "trycloudflare.com" not in cand_pg_u.lower() and ".srv.us" not in cand_pg_u.lower():
                pg_base = cand_pg_u.split("/u/", 1)[0] if "/u/" in cand_pg_u else cand_pg_u

        now_mono_pg = time.monotonic()
        need_pg_probe = (
            initial
            or not was_enabled
            or prev_sub != "public_gateway"
            or pg_base != self._pg_last_base
            or self._public_gateway_online is None
            or probe_public_gateway_online is not None
            or not pg_base
            or now_mono_pg >= self._pg_next_probe_mono
        )
        if need_pg_probe:
            pg_probe = _call_probe_public_gateway_online(pg_base, timeout_sec=1.5)
            pg_online = bool(pg_probe.get("online"))
            self._public_gateway_online = pg_online
            self._pg_last_base = pg_base
            self._pg_next_probe_mono = now_mono_pg + max(1.0, float(self._pg_probe_interval_sec))
            probed_base_url = str(pg_probe.get("base_url") or pg_base).strip().rstrip("/")
        else:
            pg_online = bool(self._public_gateway_online)
            probed_base_url = pg_base

        if not pg_online:
            self._stop_pg_workers_supervisor()
            self._pg_workers_retry_not_before = 0.0
            prefer_quick = bool(doc.get("prefer_quick_tunnel"))
            if prefer_quick:
                self._stop_srvus_supervisor()
                self._srvus_retry_not_before = 0.0
            elif self._start_or_maintain_srvus_tunnel(slot, initial=initial):
                return

            self._srvus_fixed_active = False
            self._instant_fallback_active = True
            slot.effective_mode = "cloudflare"
            if slot.public_url and "trycloudflare.com" not in slot.public_url.lower():
                slot.public_url = ""
                slot.ready = False
                slot.ready_url = ""
                slot.probing_url = ""
            self._start_or_maintain_quick_cloudflared(slot, initial=initial, fallback_from_public_gateway=True)
            return

        # `public_gateway` online
        self._instant_fallback_active = False
        self._srvus_fixed_active = False
        slot.effective_mode = "public_gateway"
        self._stop_srvus_supervisor()
        self._srvus_retry_not_before = 0.0
        self._stop_cf_quick_supervisor()
        self._cf_quick_retry_not_before = 0.0

        raw_pg_url = str(doc.get("public_gateway_url") or slot_cfg.get("public_url") or "").strip().rstrip("/")
        if raw_pg_url and ("trycloudflare.com" in raw_pg_url.lower() or ".srv.us" in raw_pg_url.lower()):
            raw_pg_url = ""
        gw_url = raw_pg_url
        seed_info: Optional[Dict[str, Any]] = None
        if callable(seed_fn):
            try:
                gw_base_hint = probed_base_url or str(doc.get("public_gateway_base") or "").strip()
                if gw_url and "/u/" in gw_url:
                    gw_base_hint = gw_url.split("/u/", 1)[0]
                elif gw_url:
                    gw_base_hint = gw_url
                seed_info = seed_fn(self.state_root, prefix=self.prefix, gateway_base=gw_base_hint)
                if isinstance(seed_info, dict) and seed_info.get("public_url"):
                    seed_pub = str(seed_info["public_url"]).strip().rstrip("/")
                    if not gw_url or "/u/" not in gw_url or self._sanitize_public_gateway_url(gw_url) == "":
                        gw_url = seed_pub
            except Exception:
                seed_info = None

        if not gw_url or not gw_url.startswith("https://"):
            self._stop_pg_workers_supervisor()
            slot.ready = False
            slot.state = "error"
            slot.last_error = "public_gateway tunnel error: 未配置固定网关 HTTPS 地址。"
            return
        if sup_cls is None:
            self._stop_pg_workers_supervisor()
            self._pg_workers_retry_not_before = time.monotonic() + 10.0
            slot.ready = False
            slot.state = "error"
            slot.last_error = "public_gateway tunnel error: cf_workers_gateway 模块未就绪。"
            return

        tun_secret = _load_gateway_tunnel_secret(
            self.state_root,
            self.prefix,
            "public_gateway",
            doc,
            sec_fn,
            seed_info=seed_info,
        )
        want_pg_sig = f"public_gateway:{gw_url}:{hash(tun_secret)}"
        if self._pg_workers_supervisor is None or self._active_pg_workers_sig != want_pg_sig:
            if not initial and time.monotonic() < self._pg_workers_retry_not_before:
                return
            self._stop_pg_workers_supervisor()
            if gw_url != slot.public_url:
                slot.ready = False
                slot.ready_url = ""
                slot.probing_url = ""
                slot.next_reprobe_mono = 0.0
            slot.public_url = gw_url
            slot.state = "connecting"
            hot_refresh_public_url(
                self.state_root,
                gw_url,
                port=self.port,
                prefix=self.prefix,
                tunnel_mode="public_gateway",
                gateway_id="instant",
            )
            try:
                def _on_pg_state(*cb_args: Any, **cb_kwargs: Any) -> None:
                    _ = (cb_args, cb_kwargs)
                    if slot.enabled and slot.submode == "public_gateway" and self._pg_workers_supervisor is not None:
                        self._sync_slot_wss_readiness(
                            slot,
                            self._pg_workers_supervisor,
                            tunnel_mode="public_gateway",
                            stopped_note="workers_relay_stopped",
                        )
                        self._recompute_aggregated_gateway_state()
                        self._push_tray_failure_if_all_gateways_down()
                        self._write_daemon_status(state_label="running", last_error=self._last_tunnel_error)

                pg_inst = _instantiate_workers_supervisor(
                    sup_cls,
                    public_url=gw_url,
                    local_port=self.port,
                    tunnel_secret=tun_secret,
                    state_root=self.state_root,
                    prefix=self.prefix,
                    mode="public_gateway",
                    on_state_change=_on_pg_state,
                )
                self._pg_workers_supervisor = pg_inst
                self._active_pg_workers_sig = want_pg_sig
                self._pg_workers_retry_not_before = 0.0
                self._start_relay_instance(pg_inst, initial=initial)
                self._sync_slot_wss_readiness(
                    slot,
                    pg_inst,
                    tunnel_mode="public_gateway",
                    stopped_note="workers_relay_stopped",
                )
                exp_pg, _ = self._read_relay_explicit_ready(pg_inst)
                if exp_pg is None:
                    self._verify_slot_public_ready_async(slot, gw_url, tunnel_mode="public_gateway")
            except Exception as exc:
                self._stop_pg_workers_supervisor()
                self._pg_workers_retry_not_before = time.monotonic() + 10.0
                slot.ready = False
                slot.state = "error"
                slot.last_error = f"public_gateway tunnel error: {exc}"
        else:
            self._sync_slot_wss_readiness(
                slot,
                self._pg_workers_supervisor,
                tunnel_mode="public_gateway",
                stopped_note="workers_relay_stopped",
            )

    @staticmethod
    def _start_relay_instance(inst: Any, *, initial: bool) -> None:
        start_fn = getattr(inst, "start", None)
        if not callable(start_fn):
            return
        try:
            st_params = inspect.signature(start_fn).parameters
        except (TypeError, ValueError):
            st_params = {}
        wait_val = 8.0 if initial else 3.0
        if "wait_connected_timeout_sec" in st_params:
            start_fn(wait_connected_timeout_sec=wait_val)
        elif "wait_ready_timeout_sec" in st_params:
            start_fn(wait_ready_timeout_sec=wait_val)
        elif "wait_url_timeout_sec" in st_params:
            start_fn(wait_url_timeout_sec=wait_val)
        elif "timeout_sec" in st_params:
            start_fn(timeout_sec=wait_val)
        else:
            start_fn()

    def _sync_workers_slot(self, slot_cfg: Dict[str, Any], doc: Dict[str, Any], *, initial: bool) -> None:
        slot = self._gateway_slots["workers_dev"]
        if not bool(slot_cfg.get("enabled")):
            self._stop_workers_supervisor()
            self._workers_retry_not_before = 0.0
            slot.reset_disabled(submode="workers_dev")
            return

        slot.enabled = True
        slot.submode = "workers_dev"
        slot.effective_mode = "workers_dev"

        sup_cls, sec_fn, _ = _resolve_workers_gateway_components()
        cand_slot_u = str(slot_cfg.get("public_url") or "").strip().rstrip("/")
        cand_doc_u = str(doc.get("workers_dev_url") or "").strip().rstrip("/")
        cand_custom_dom = str(doc.get("workers_custom_domain") or doc.get("workers_dev_custom_domain") or "").strip()
        if cand_custom_dom and "://" not in cand_custom_dom:
            cand_custom_dom = f"https://{cand_custom_dom}"
        cand_top_u = ""
        if self._selected_gateway == "workers_dev":
            raw_top = str(doc.get("public_base") or doc.get("public_base_url") or "").strip().rstrip("/")
            if raw_top and "trycloudflare.com" not in raw_top.lower() and ".srv.us" not in raw_top.lower():
                cand_top_u = raw_top

        gw_url = ""
        for cand_w in (cand_slot_u, cand_custom_dom, cand_doc_u, cand_top_u):
            c_clean = str(cand_w or "").strip().rstrip("/")
            if c_clean.startswith("https://") and "trycloudflare.com" not in c_clean.lower() and ".srv.us" not in c_clean.lower():
                gw_url = c_clean
                break

        if not gw_url:
            self._stop_workers_supervisor()
            slot.ready = False
            slot.ready_url = ""
            slot.state = "error"
            slot.last_error = "workers_dev tunnel error: 未配置固定网关 HTTPS 地址。"
            return

        if sup_cls is None:
            self._stop_workers_supervisor()
            self._workers_retry_not_before = time.monotonic() + 10.0
            slot.ready = False
            slot.state = "error"
            slot.last_error = "workers_dev tunnel error: cf_workers_gateway 模块未就绪。"
            return

        tun_secret = _load_gateway_tunnel_secret(
            self.state_root,
            self.prefix,
            "workers_dev",
            doc,
            sec_fn,
            seed_info=None,
        )
        want_w_sig = f"workers_dev:{gw_url}:{hash(tun_secret)}"
        if self._workers_supervisor is None or self._active_workers_sig != want_w_sig:
            if not initial and time.monotonic() < self._workers_retry_not_before:
                return
            self._stop_workers_supervisor()
            if gw_url != slot.public_url:
                slot.ready = False
                slot.ready_url = ""
                slot.probing_url = ""
                slot.next_reprobe_mono = 0.0
            slot.public_url = gw_url
            slot.state = "connecting"
            hot_refresh_public_url(
                self.state_root,
                gw_url,
                port=self.port,
                prefix=self.prefix,
                tunnel_mode="workers_dev",
                gateway_id="workers_dev",
            )
            try:
                def _on_workers_state(*cb_args: Any, **cb_kwargs: Any) -> None:
                    _ = (cb_args, cb_kwargs)
                    if slot.enabled and self._workers_supervisor is not None:
                        self._sync_slot_wss_readiness(
                            slot,
                            self._workers_supervisor,
                            tunnel_mode="workers_dev",
                            stopped_note="workers_relay_stopped",
                        )
                        self._recompute_aggregated_gateway_state()
                        self._push_tray_failure_if_all_gateways_down()
                        self._write_daemon_status(state_label="running", last_error=self._last_tunnel_error)

                w_inst = _instantiate_workers_supervisor(
                    sup_cls,
                    public_url=gw_url,
                    local_port=self.port,
                    tunnel_secret=tun_secret,
                    state_root=self.state_root,
                    prefix=self.prefix,
                    mode="workers_dev",
                    on_state_change=_on_workers_state,
                )
                self._workers_supervisor = w_inst
                self._active_workers_sig = want_w_sig
                self._workers_retry_not_before = 0.0
                self._start_relay_instance(w_inst, initial=initial)
                self._sync_slot_wss_readiness(
                    slot,
                    w_inst,
                    tunnel_mode="workers_dev",
                    stopped_note="workers_relay_stopped",
                )
                exp_w, _ = self._read_relay_explicit_ready(w_inst)
                if exp_w is None:
                    self._verify_slot_public_ready_async(slot, gw_url, tunnel_mode="workers_dev")
            except Exception as exc:
                self._stop_workers_supervisor()
                self._workers_retry_not_before = time.monotonic() + 10.0
                slot.ready = False
                slot.state = "error"
                slot.last_error = f"workers_dev tunnel error: {exc}"
        else:
            self._sync_slot_wss_readiness(
                slot,
                self._workers_supervisor,
                tunnel_mode="workers_dev",
                stopped_note="workers_relay_stopped",
            )

    def _sync_self_hosted_slot(self, slot_cfg: Dict[str, Any], doc: Dict[str, Any], *, initial: bool) -> None:
        slot = self._gateway_slots["self_hosted"]
        raw_sub = str(slot_cfg.get("submode") or "vps_hub").strip().lower()
        if raw_sub == "reverse_proxy":
            raw_sub = "custom"
        submode = raw_sub if raw_sub in ("vps_hub", "vps", "cloudflare_token", "custom") else "vps_hub"

        if not bool(slot_cfg.get("enabled")):
            self._stop_cf_named_supervisor()
            self._stop_vps_wss_supervisor()
            self._stop_ssh_tunnel()
            self._cf_named_retry_not_before = 0.0
            self._vps_wss_retry_not_before = 0.0
            self._ssh_retry_not_before = 0.0
            slot.reset_disabled(submode=submode)
            return

        slot.enabled = True
        slot.submode = submode
        slot.effective_mode = submode

        if submode != "cloudflare_token":
            self._stop_cf_named_supervisor()
            self._cf_named_retry_not_before = 0.0
        if submode not in ("vps_hub", "vps"):
            self._stop_vps_wss_supervisor()
            self._vps_wss_retry_not_before = 0.0
        if submode != "vps":
            self._stop_ssh_tunnel()
            self._ssh_retry_not_before = 0.0

        cfg_pub_raw = str(doc.get("public_base") or doc.get("public_base_url") or "").strip().rstrip("/")
        cfg_pub_non_temp = (
            cfg_pub_raw
            if (cfg_pub_raw and "trycloudflare.com" not in cfg_pub_raw.lower() and ".srv.us" not in cfg_pub_raw.lower())
            else ""
        )
        slot_pub_cfg = str(slot_cfg.get("public_url") or "").strip().rstrip("/")
        if slot_pub_cfg and ("trycloudflare.com" in slot_pub_cfg.lower() or ".srv.us" in slot_pub_cfg.lower()):
            slot_pub_cfg = ""

        if submode == "cloudflare_token":
            tok = load_tunnel_token(self.state_root, prefix=self.prefix) or self.tunnel_token
            fixed_u = slot_pub_cfg or cfg_pub_non_temp or slot.public_url
            want_sig = f"token:{hash(tok)}:{fixed_u}"
            if not tok:
                self._stop_cf_named_supervisor()
                slot.ready = False
                slot.state = "error"
                slot.last_error = "cloudflare named tunnel error: 未配置固定域名 Tunnel Token。"
                return
            if self._cf_named_supervisor is None or self._active_cf_named_sig != want_sig:
                if not initial and time.monotonic() < self._cf_named_retry_not_before:
                    return
                self._stop_cf_named_supervisor()
                try:
                    cf_bin = ensure_cloudflared_binary(self.state_root / "bin")

                    def _on_named_url(new_u: str) -> None:
                        if not slot.enabled or slot.submode != "cloudflare_token":
                            return
                        if new_u != slot.public_url:
                            slot.ready = False
                            slot.ready_url = ""
                            slot.probing_url = ""
                            slot.next_reprobe_mono = 0.0
                        slot.public_url = new_u
                        slot.last_error = ""
                        slot.state = "ready" if slot.ready else "connecting"
                        hot_refresh_public_url(
                            self.state_root,
                            new_u,
                            port=self.port,
                            prefix=self.prefix,
                            tunnel_mode="cloudflare_token",
                            gateway_id="self_hosted",
                        )
                        self._recompute_aggregated_gateway_state()
                        self._write_daemon_status(state_label="running", last_error=self._last_tunnel_error)
                        self._verify_slot_public_ready_async(slot, new_u, tunnel_mode="cloudflare_token")

                    self._cf_named_supervisor = _instantiate_cloudflared_supervisor(
                        CloudflaredTunnelSupervisor,
                        cloudflared_bin=cf_bin,
                        local_port=self.port,
                        state_root=self.state_root,
                        prefix=self.prefix,
                        protocol="http2",
                        tunnel_token=tok,
                        fixed_public_url=fixed_u,
                        persist_tunnel_mode="cloudflare_token",
                        gateway_id="self_hosted",
                        on_url_change=_on_named_url,
                    )
                    self._active_cf_named_sig = want_sig
                    self._cf_named_retry_not_before = 0.0
                    found_url = str(self._cf_named_supervisor.start(wait_url_timeout_sec=12.0 if initial else 3.0) or "").strip()
                    if found_url:
                        slot.public_url = found_url
                        slot.last_error = ""
                        slot.state = "ready" if slot.ready else "connecting"
                        hot_refresh_public_url(
                            self.state_root,
                            found_url,
                            port=self.port,
                            prefix=self.prefix,
                            tunnel_mode="cloudflare_token",
                            gateway_id="self_hosted",
                        )
                        self._verify_slot_public_ready_async(slot, found_url, tunnel_mode="cloudflare_token")
                except Exception as exc:
                    self._cf_named_retry_not_before = time.monotonic() + 15.0
                    slot.ready = False
                    slot.state = "error"
                    slot.last_error = f"cloudflare named tunnel error: {exc}"
            return

        if submode in ("vps_hub", "vps"):
            raw_vps_hub_url = str(doc.get("vps_hub_url") or "").strip().rstrip("/")
            if raw_vps_hub_url and "://" not in raw_vps_hub_url:
                raw_vps_hub_url = f"https://{raw_vps_hub_url}"
            raw_vps_node_sec = str(doc.get("vps_node_secret") or "").strip()
            sec_p = vps_node_secret_path(self.state_root, prefix=self.prefix)
            if not raw_vps_node_sec and sec_p.is_file():
                try:
                    raw_vps_node_sec = sec_p.read_text(encoding="utf-8", errors="replace").strip()
                except OSError:
                    raw_vps_node_sec = ""

            has_wss_cfg = bool(
                submode == "vps_hub"
                or doc.get("vps_hub_mode")
                or raw_vps_hub_url
                or raw_vps_node_sec
            )
            eff_vps_hub_u = (
                raw_vps_hub_url
                or slot_pub_cfg
                or (cfg_pub_non_temp if self._selected_gateway == "self_hosted" else "")
                or (slot.public_url if not slot.public_url.startswith("http://127.0.0.1") else "")
            )

            if has_wss_cfg and (submode == "vps_hub" or (eff_vps_hub_u and raw_vps_node_sec)):
                self._stop_ssh_tunnel()
                self._ssh_retry_not_before = 0.0
                slot.effective_mode = "vps_hub" if submode == "vps_hub" else "vps"

                if not eff_vps_hub_u or not eff_vps_hub_u.startswith(("https://", "http://")) or not raw_vps_node_sec:
                    self._stop_vps_wss_supervisor()
                    slot.ready = False
                    slot.state = "error"
                    slot.last_error = f"{submode} tunnel error: 未配置自有服务器 HTTPS 地址或节点密钥。"
                    return

                ws_roots = list(doc.get("workspace_roots") or ([doc["workspace"]] if doc.get("workspace") else []))
                dev_label = str(doc.get("device_label") or "").strip()
                want_vps_sig = f"vps_wss:{eff_vps_hub_u}:{hash(raw_vps_node_sec)}:{tuple(str(x) for x in ws_roots)}:{dev_label}"

                if self._vps_wss_supervisor is None or self._active_vps_wss_sig != want_vps_sig:
                    if not initial and time.monotonic() < self._vps_wss_retry_not_before:
                        return
                    self._stop_vps_wss_supervisor()
                    if eff_vps_hub_u != slot.public_url:
                        slot.ready = False
                        slot.ready_url = ""
                        slot.probing_url = ""
                        slot.next_reprobe_mono = 0.0
                    slot.public_url = eff_vps_hub_u
                    slot.state = "connecting"
                    hot_refresh_public_url(
                        self.state_root,
                        eff_vps_hub_u,
                        port=self.port,
                        prefix=self.prefix,
                        tunnel_mode=submode,
                        gateway_id="self_hosted",
                    )
                    try:
                        def _on_vps_wss_state(*cb_args: Any, **cb_kwargs: Any) -> None:
                            _ = (cb_args, cb_kwargs)
                            if slot.enabled and slot.submode in ("vps_hub", "vps") and self._vps_wss_supervisor is not None:
                                self._sync_slot_wss_readiness(
                                    slot,
                                    self._vps_wss_supervisor,
                                    tunnel_mode=submode,
                                    stopped_note="vps_wss_stopped",
                                )
                                self._recompute_aggregated_gateway_state()
                                self._push_tray_failure_if_all_gateways_down()
                                self._write_daemon_status(state_label="running", last_error=self._last_tunnel_error)

                        vps_cls = VpsWssNodeSupervisor
                        try:
                            v_params = inspect.signature(vps_cls).parameters
                            v_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in v_params.values())
                        except (TypeError, ValueError, AttributeError):
                            v_params = {}
                            v_var_kw = True

                        v_kwargs: Dict[str, Any] = {}
                        for uk in ("vps_url", "public_url", "url"):
                            if uk in v_params:
                                v_kwargs[uk] = eff_vps_hub_u
                                break
                        else:
                            if v_var_kw:
                                v_kwargs["vps_url"] = eff_vps_hub_u
                        for sk in ("node_secret", "tunnel_secret", "secret"):
                            if sk in v_params:
                                v_kwargs[sk] = raw_vps_node_sec
                                break
                        else:
                            if v_var_kw:
                                v_kwargs["node_secret"] = raw_vps_node_sec
                        if "local_port" in v_params or v_var_kw:
                            v_kwargs["local_port"] = self.port
                        if "state_root" in v_params or v_var_kw:
                            v_kwargs["state_root"] = self.state_root
                        if "prefix" in v_params or v_var_kw:
                            v_kwargs["prefix"] = self.prefix
                        if "workspace_roots" in v_params:
                            v_kwargs["workspace_roots"] = ws_roots
                        if "device_label" in v_params and dev_label:
                            v_kwargs["device_label"] = dev_label
                        for cbk in ("on_state_change", "on_ready_change", "on_status_change"):
                            if cbk in v_params:
                                v_kwargs[cbk] = _on_vps_wss_state
                                break

                        v_inst = vps_cls(**v_kwargs)
                        self._vps_wss_supervisor = v_inst
                        self._active_vps_wss_sig = want_vps_sig
                        self._vps_wss_retry_not_before = 0.0
                        self._start_relay_instance(v_inst, initial=initial)
                        self._sync_slot_wss_readiness(
                            slot,
                            v_inst,
                            tunnel_mode=submode,
                            stopped_note="vps_wss_stopped",
                        )
                        exp_v_ready, _ = self._read_relay_explicit_ready(v_inst)
                        if exp_v_ready is None:
                            self._verify_slot_public_ready_async(slot, eff_vps_hub_u, tunnel_mode=submode)
                    except Exception as exc:
                        self._stop_vps_wss_supervisor()
                        self._vps_wss_retry_not_before = time.monotonic() + 10.0
                        slot.ready = False
                        slot.state = "error"
                        slot.last_error = f"{submode} tunnel error: {exc}"
                else:
                    self._sync_slot_wss_readiness(
                        slot,
                        self._vps_wss_supervisor,
                        tunnel_mode=submode,
                        stopped_note="vps_wss_stopped",
                    )
                return

            # Plain `vps` SSH `-R` reverse tunnel
            self._stop_vps_wss_supervisor()
            self._vps_wss_retry_not_before = 0.0
            eff_ssh_pub = slot_pub_cfg or cfg_pub_non_temp
            pub_changed = False
            if eff_ssh_pub:
                pub_changed = eff_ssh_pub != slot.public_url
                if pub_changed:
                    slot.ready = False
                    slot.ready_url = ""
                    slot.probing_url = ""
                    slot.next_reprobe_mono = 0.0
                slot.public_url = eff_ssh_pub
                if initial or pub_changed:
                    hot_refresh_public_url(
                        self.state_root,
                        slot.public_url,
                        port=self.port,
                        prefix=self.prefix,
                        tunnel_mode="vps",
                        gateway_id="self_hosted",
                    )

            if not self.vps_ssh:
                self._stop_ssh_tunnel()
                slot.ready = False
                slot.state = "error"
                slot.last_error = "vps tunnel error: 未填写自有云服务器 SSH 地址。"
                return

            want_ssh_sig = (self.vps_ssh, int(self.vps_remote_port), int(self.vps_ssh_port), self.vps_identity_file)
            if self._ssh_proc is not None and self._active_ssh_sig != want_ssh_sig:
                self._log("VPS SSH config changed (%s -> %s); restarting reverse tunnel", self._active_ssh_sig, want_ssh_sig)
                self._stop_ssh_tunnel()
                self._ssh_retry_not_before = 0.0
            had_live_ssh = self._ssh_proc is not None and self._ssh_proc.poll() is None
            self._ensure_vps_ssh_alive(slot, write_status=False)
            if (
                (initial or pub_changed or not had_live_ssh)
                and self._ssh_proc is not None
                and self._ssh_proc.poll() is None
                and slot.public_url.startswith("https://")
            ):
                self._verify_slot_public_ready_async(slot, slot.public_url, tunnel_mode="vps")
            return

        # `submode == "custom"`
        slot.last_error = ""
        eff_custom_pub = slot_pub_cfg or cfg_pub_non_temp
        if eff_custom_pub:
            pub_changed = eff_custom_pub != slot.public_url
            if pub_changed:
                slot.ready = False
                slot.ready_url = ""
                slot.probing_url = ""
                slot.next_reprobe_mono = 0.0
            slot.public_url = eff_custom_pub
            slot.state = "ready" if slot.ready else "connecting"
            if initial or pub_changed:
                hot_refresh_public_url(
                    self.state_root,
                    slot.public_url,
                    port=self.port,
                    prefix=self.prefix,
                    tunnel_mode="custom",
                    gateway_id="self_hosted",
                )
                if slot.public_url.startswith("https://"):
                    self._verify_slot_public_ready_async(slot, slot.public_url, tunnel_mode="custom")

    def _resolve_effective_gateways(self, doc: Dict[str, Any], *, initial: bool) -> Tuple[Dict[str, Dict[str, Any]], str]:
        work_doc = dict(doc)
        if initial and self._explicit_init_mode and not work_doc.get("gateways") and not work_doc.get("tunnel_mode"):
            work_doc["tunnel_mode"] = self._explicit_init_mode
            if self.public_url and self._explicit_init_mode != "local":
                work_doc["public_base"] = self.public_url
        elif initial and self._explicit_init_mode and not work_doc.get("gateways") and work_doc.get("tunnel_mode") != self._explicit_init_mode:
            work_doc["tunnel_mode"] = self._explicit_init_mode
        return normalize_gateways_config(work_doc)

    def _sync_all_gateways_from_cfg(self, *, initial: bool = False) -> None:
        doc = self._read_cfg_doc()
        if doc.get("tool_prefix"):
            self.tool_prefix = _norm_prefix(str(doc["tool_prefix"]))
        if "vps_ssh" in doc:
            self.vps_ssh = str(doc.get("vps_ssh") or "").strip()
        if "vps_remote_port" in doc and doc.get("vps_remote_port"):
            try:
                rp_val = int(doc["vps_remote_port"])
                if 1 <= rp_val <= 65535:
                    self.vps_remote_port = rp_val
            except (TypeError, ValueError):
                pass
        if "vps_ssh_port" in doc and doc.get("vps_ssh_port"):
            try:
                sp_val = int(doc["vps_ssh_port"])
                if 1 <= sp_val <= 65535:
                    self.vps_ssh_port = sp_val
            except (TypeError, ValueError):
                pass
        if "vps_identity_file" in doc:
            self.vps_identity_file = str(doc.get("vps_identity_file") or "").strip()

        gws_cfg, sel_gw = self._resolve_effective_gateways(doc, initial=initial)
        self._selected_gateway = sel_gw

        self._sync_instant_slot(gws_cfg["instant"], doc, initial=initial)
        self._sync_workers_slot(gws_cfg["workers_dev"], doc, initial=initial)
        self._sync_self_hosted_slot(gws_cfg["self_hosted"], doc, initial=initial)

        with self._status_io_lock:
            self._recompute_aggregated_gateway_state()
            self._push_tray_failure_if_all_gateways_down()
            self._write_daemon_status_locked(state_label="running", last_error=self._last_tunnel_error)

    def _sync_tunnel_from_cfg(self, *, initial: bool = False) -> None:
        self._sync_all_gateways_from_cfg(initial=initial)

    def _ensure_vps_ssh_alive(
        self,
        slot: Optional[GatewaySlotRuntime] = None,
        *,
        write_status: bool = True,
    ) -> None:
        sh_slot = slot if slot is not None else self._gateway_slots["self_hosted"]
        if (
            not sh_slot.enabled
            or sh_slot.submode != "vps"
            or not self.vps_ssh
            or self._vps_wss_supervisor is not None
        ):
            return
        logs_dir = self.state_root / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        ssh_log = logs_dir / (f"vps_ssh_{self.prefix}.log" if self.prefix != "pc" else "vps_ssh.log")

        if self._ssh_proc is not None:
            rc_existing = self._ssh_proc.poll()
            if rc_existing is None:
                sh_slot.pid = int(self._ssh_proc.pid)
                return
            err_tail = self._extract_ssh_log_error(ssh_log, self._ssh_log_offset, rc_existing)
            self._stop_ssh_tunnel()
            self._ssh_retry_not_before = time.monotonic() + 5.0
            sh_slot.ready = False
            sh_slot.ready_url = ""
            sh_slot.state = "error"
            sh_slot.last_error = f"vps tunnel error: SSH 反向隧道连接断开或握手失败 ({err_tail})"
            self._log("VPS SSH reverse tunnel exited (rc=%s): %s", rc_existing, err_tail, error=True)
            if write_status:
                self._recompute_aggregated_gateway_state()
                self._write_daemon_status(state_label="running", last_error=self._last_tunnel_error)
            return

        if time.monotonic() < self._ssh_retry_not_before:
            return

        ssh_bin = shutil.which("ssh")
        if not ssh_bin:
            self._ssh_retry_not_before = time.monotonic() + 10.0
            sh_slot.ready = False
            sh_slot.state = "error"
            sh_slot.last_error = "vps tunnel error: 未检测到系统 ssh 客户端，请先安装 OpenSSH Client。"
            self._log("ssh binary not found on PATH; cannot start --mode vps reverse tunnel", error=True)
            if write_status:
                self._recompute_aggregated_gateway_state()
                self._write_daemon_status(state_label="running", last_error=self._last_tunnel_error)
            return
        if self._ssh_job is not None:
            self._ssh_job.close()
            self._ssh_job = None
        cmd = build_vps_ssh_reverse_tunnel_cmd(
            self.vps_ssh,
            self.vps_remote_port,
            self.port,
            ssh_port=self.vps_ssh_port,
            identity_file=self.vps_identity_file,
            ssh_bin=ssh_bin,
        )
        self._ssh_log_offset = ssh_log.stat().st_size if ssh_log.is_file() else 0
        try:
            with ssh_log.open("a", encoding="utf-8", errors="replace") as lf:
                self._ssh_proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=lf,
                    stderr=subprocess.STDOUT,
                    close_fds=True,
                    creationflags=_popen_flags(),
                )
        except Exception as exc:
            self._ssh_proc = None
            self._ssh_retry_not_before = time.monotonic() + 5.0
            sh_slot.ready = False
            sh_slot.state = "error"
            sh_slot.last_error = f"vps tunnel error: 无法拉起 ssh 进程 ({exc})"
            if write_status:
                self._recompute_aggregated_gateway_state()
                self._write_daemon_status(state_label="running", last_error=self._last_tunnel_error)
            return

        self._ssh_job = OwnedJobHandle(assign_win32_job_kill_on_close(int(self._ssh_proc.pid), max_mem_mb=0))
        self._active_ssh_sig = (self.vps_ssh, int(self.vps_remote_port), int(self.vps_ssh_port), self.vps_identity_file)
        sh_slot.pid = int(self._ssh_proc.pid)
        self._log("spawned VPS SSH reverse tunnel pid=%s target=%s remote_port=%s", self._ssh_proc.pid, self.vps_ssh, self.vps_remote_port)

        handshake_deadline = time.monotonic() + 0.35
        while time.monotonic() < handshake_deadline:
            rc_early = self._ssh_proc.poll()
            if rc_early is not None:
                err_tail = self._extract_ssh_log_error(ssh_log, self._ssh_log_offset, rc_early)
                self._stop_ssh_tunnel()
                self._ssh_retry_not_before = time.monotonic() + 5.0
                sh_slot.ready = False
                sh_slot.state = "error"
                sh_slot.last_error = f"vps tunnel error: SSH 反向隧道握手失败 ({err_tail})"
                self._log("VPS SSH handshake failed immediately (rc=%s): %s", rc_early, err_tail, error=True)
                if write_status:
                    self._recompute_aggregated_gateway_state()
                    self._write_daemon_status(state_label="running", last_error=self._last_tunnel_error)
                return
            time.sleep(0.05)

        sh_slot.last_error = ""
        sh_slot.state = "ready" if sh_slot.ready else "connecting"
        if write_status:
            self._recompute_aggregated_gateway_state()
            self._write_daemon_status(state_label="running")

    def _reclaim_stale_python_port_holder(self) -> List[int]:
        if not _is_local_tcp_port_occupied(self.port):
            return []
        cand_pids = _find_listening_pids_on_local_port(self.port)
        active_dir = self.state_root / "state" / "active_pids"
        if active_dir.is_dir():
            for pf in list(active_dir.glob("*.json")):
                with contextlib.suppress(Exception):
                    doc = json.loads(pf.read_text(encoding="utf-8-sig"))
                    if int(doc.get("port") or 0) == int(self.port):
                        apid = int(doc.get("pid") or 0)
                        if apid > 0 and apid not in cand_pids:
                            cand_pids.append(apid)
        reclaimed: List[int] = []
        for pid in cand_pids:
            if pid <= 0 or pid == os.getpid():
                continue
            if not is_raw_pid_alive(pid) or not _is_python_executable_pid(pid):
                continue
            self._log("reclaiming occupied port %s from stale python pid=%s", self.port, pid, error=True)
            terminate_verified_pid_tree(pid, expected_create_token=None)
            reclaimed.append(pid)
        if reclaimed:
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline and _is_local_tcp_port_occupied(self.port):
                time.sleep(0.1)
        return reclaimed

    def _terminate_current_server_child(self) -> None:
        if self._server_proc is not None and self._server_proc.poll() is None:
            try:
                self._server_proc.terminate()
                self._server_proc.wait(timeout=3.0)
            except Exception:
                terminate_verified_pid_tree(self._server_proc.pid, expected_create_token=None)
        if self._server_job is not None:
            self._server_job.close()
            self._server_job = None

    def _spawn_server_child(self) -> subprocess.Popen[Any]:
        if self._server_job is not None:
            self._server_job.close()
            self._server_job = None
        self._reclaim_stale_python_port_holder()
        logs_dir = self.state_root / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        srv_log = logs_dir / (f"server_{self.prefix}.log" if self.prefix != "pc" else "server.log")
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONUTF8"] = "1"
        env["COSMOS_MCP_STATE_DIR"] = str(self.state_root)
        env["LOCALPC_MCP_STATE_DIR"] = str(self.state_root)
        persisted_src = resolve_persisted_src_dir(self.state_root)
        if persisted_src is not None:
            existing_pp = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = f"{persisted_src}{os.pathsep}{existing_pp}" if existing_pp else str(persisted_src)

        loaded_cfg = self._read_cfg_doc()
        cfg_tunnel_mode = str(loaded_cfg.get("tunnel_mode") or "").strip().lower()
        eff_tunnel_mode = cfg_tunnel_mode or self.mode or "local"
        eff_tp = _norm_prefix(str(loaded_cfg.get("tool_prefix") or self.tool_prefix or self.prefix))
        self.tool_prefix = eff_tp

        argv = [
            self.runtime_python,
            "-B",
            "-m",
            "cosmos_mcp.launcher.app",
            "--state-dir",
            str(self.state_root),
            "--host",
            "127.0.0.1",
            "--port",
            str(self.port),
            "--prefix",
            self.prefix,
            "--tool-prefix",
            eff_tp,
            "--tunnel-mode",
            eff_tunnel_mode,
        ]
        if self.public_url and eff_tunnel_mode != "local":
            argv.extend(["--public-url", self.public_url])

        with srv_log.open("a", encoding="utf-8", errors="replace") as lf:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=lf,
                stderr=subprocess.STDOUT,
                cwd=str(self.state_root),
                env=env,
                creationflags=_popen_flags(),
            )
        self._server_job = OwnedJobHandle(
            assign_win32_job_kill_on_close(int(proc.pid), max_mem_mb=0, allow_breakaway=True)
        )
        self._log(
            "spawned uvicorn server child pid=%s port=%s mode=%s job_bound=%s",
            proc.pid,
            self.port,
            eff_tunnel_mode,
            bool(self._server_job.handle),
        )
        return proc

    def run_forever(self) -> int:
        if self._should_enforce_singleton() and not self._singleton_lock.acquire():
            self.singleton_conflict = True
            self._log(
                "another supervisor instance already holds singleton lock (%s); exiting cleanly",
                self._singleton_lock.mutex_name,
                error=True,
            )
            with contextlib.suppress(Exception):
                self._sup_logger.removeHandler(self._sup_log_handler)
                self._sup_log_handler.close()
            return 0

        self._log("supervisor starting pid=%s port=%s mode=%s prefix=%s", os.getpid(), self.port, self.mode, self.prefix)
        cfg_init = self._read_cfg_doc()
        self._sync_keep_awake_from_cfg(cfg_init)
        self._write_daemon_status(state_label="starting")
        self._sync_tray_from_cfg(state_label="starting", cfg_doc=cfg_init)
        try:
            initial_tunnel_synced = False
            while not self._should_stop():
                try:
                    cfg_cur = self._read_cfg_doc()
                    self._sync_keep_awake_from_cfg(cfg_cur)
                    started_mono = time.monotonic()
                    self._server_proc = self._spawn_server_child()
                    local_hz_failures = 0
                    next_local_hz_mono = started_mono + max(0.0, float(self._local_healthz_grace_sec))
                    deadlock_restarted = False
                    self._write_daemon_status(state_label="running")
                    if not initial_tunnel_synced:
                        self._sync_all_gateways_from_cfg(initial=True)
                        self._ensure_vps_ssh_alive()
                        self._write_daemon_status(state_label="running", last_error=self._last_tunnel_error)
                        initial_tunnel_synced = True
                    else:
                        self._sync_all_gateways_from_cfg(initial=False)
                        self._ensure_vps_ssh_alive()
                    self._sync_tray_from_cfg(state_label="running")
                except Exception as spawn_exc:
                    self._log("error preparing server child in supervisor loop (retrying): %r", spawn_exc, error=True)
                    time.sleep(1.0)
                    continue

                while not self._should_stop():
                    try:
                        ret = self._server_proc.poll()
                        if ret is not None:
                            break
                        now_mono = time.monotonic()
                        if (now_mono - started_mono) >= 45.0 and self.consecutive_crashes > 0:
                            self.consecutive_crashes = 0
                            self._write_daemon_status(state_label="running", last_error=self._last_tunnel_error)
                        if (
                            (now_mono - started_mono) >= max(0.0, float(self._local_healthz_grace_sec))
                            and now_mono >= next_local_hz_mono
                        ):
                            next_local_hz_mono = now_mono + max(0.01, float(self._local_healthz_interval_sec))
                            hz_doc = probe_local_healthz(
                                self.port,
                                timeout_sec=float(self._local_healthz_timeout_sec),
                            )
                            if hz_doc is not None:
                                local_hz_failures = 0
                            else:
                                local_hz_failures += 1
                                self._log(
                                    "local /healthz probe failed on port %s (%s/%s)",
                                    self.port,
                                    local_hz_failures,
                                    self._local_healthz_max_failures,
                                    error=True,
                                )
                                if local_hz_failures >= max(1, int(self._local_healthz_max_failures)):
                                    deadlock_pid = self._server_proc.pid if self._server_proc else None
                                    self._log(
                                        "local /healthz failed %s consecutive times on port %s; restarting deadlocked server pid=%s",
                                        local_hz_failures,
                                        self.port,
                                        deadlock_pid,
                                        error=True,
                                    )
                                    self._terminate_current_server_child()
                                    deadlock_restarted = True
                                    break
                        loop_cfg = self._read_cfg_doc()
                        self._sync_keep_awake_from_cfg(loop_cfg)
                        self._sync_all_gateways_from_cfg(initial=False)
                        self._ensure_vps_ssh_alive()
                        self._poll_tunnel_readiness()
                        self._sync_tray_from_cfg(state_label="running", cfg_doc=loop_cfg)
                    except Exception as loop_exc:
                        self._log("transient exception in supervisor inner loop (continuing): %r", loop_exc, error=True)
                        time.sleep(1.0)
                        continue
                    time.sleep(0.8)

                if self._should_stop():
                    break

                try:
                    self.consecutive_crashes += 1
                    self.total_restarts += 1
                    wait_s = 1.0 if deadlock_restarted else compute_crash_backoff_sec(self.consecutive_crashes)
                    reason_tag = "local /healthz deadlock" if deadlock_restarted else f"rc={self._server_proc.returncode if self._server_proc else None}"
                    self._log(
                        "server child restarting (%s); retry #%s in %.1fs",
                        reason_tag,
                        self.consecutive_crashes,
                        wait_s,
                        error=True,
                    )
                    err_msg = f"server restarting ({reason_tag}); persistent self-heal retry #{self.consecutive_crashes} in {wait_s:.1f}s"
                    self._write_daemon_status(
                        state_label="restarting_backoff",
                        last_error=err_msg,
                    )
                    self._sync_tray_from_cfg(state_label="restarting_backoff")
                    end_sleep = time.monotonic() + wait_s
                    while time.monotonic() < end_sleep and not self._should_stop():
                        time.sleep(0.5)
                except Exception as backoff_exc:
                    self._log("transient exception during restart backoff: %r", backoff_exc, error=True)
                    time.sleep(1.0)
        finally:
            self._log("supervisor shutting down port=%s", self.port)
            if self._tray is not None:
                try:
                    self._tray.stop()
                except Exception:
                    pass
                self._tray = None
            self._stop_cf_supervisor()
            self._stop_srvus_supervisor()
            self._stop_pg_workers_supervisor()
            self._stop_workers_supervisor()
            self._stop_vps_wss_supervisor()
            self._stop_ssh_tunnel()
            self._terminate_current_server_child()
            self.inhibitor.disable()
            with contextlib.suppress(Exception):
                atomic_write_json(
                    daemon_status_path(self.state_root, self.prefix),
                    {"status": "stopped", "stopped_at": round(time.time(), 3), "port": self.port},
                )
            self._singleton_lock.release()
            try:
                self._sup_logger.removeHandler(self._sup_log_handler)
                self._sup_log_handler.close()
            except Exception:
                pass
        return 0


def bind_stdio_to_parent_lifecycle(on_parent_dead: Optional[Callable[[], None]] = None) -> Optional[threading.Thread]:
    """Bind `--stdio` server to its parent IDE process via creation-token-verified PPID liveness monitor."""
    ppid = os.getppid()
    if ppid <= 1:
        return None
    parent_tok = get_process_create_token(ppid)

    def _watch_parent() -> None:
        while True:
            time.sleep(1.5)
            cur_ppid = os.getppid()
            alive, _ = verify_pid_alive(ppid, parent_tok)
            if cur_ppid != ppid or not alive:
                if on_parent_dead is not None:
                    try:
                        on_parent_dead()
                    except Exception:
                        pass
                os._exit(0)

    th = threading.Thread(target=_watch_parent, name="stdio-parent-watchdog", daemon=True)
    th.start()
    return th


def interactive_hot_switch_menu(
    *,
    live_info: Dict[str, Any],
    on_set_tier: Callable[[str], Dict[str, Any]],
    on_add_workspace: Callable[[str], Dict[str, Any]],
    on_toggle_pack: Callable[[str], Dict[str, Any]],
    on_show_credentials: Callable[[], Dict[str, Any]],
    on_stop: Callable[[], Dict[str, Any]],
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> Dict[str, Any]:
    """Non-destructive interactive hot-switch menu when an online instance is already running."""
    output_fn(
        "\n============================================================\n"
        f" 检测到 Cosmos MCP 正在运行（端口: {live_info.get('port')} · 在途连接不断流保护已生效）\n"
        f" 当前地址 : {live_info.get('mcp_url')}\n"
        f" 本地控制台: {live_info.get('local_admin_url')}\n"
        f" 开放目录 : {', '.join(str(x) for x in (live_info.get('workspace_roots') or []))}\n"
        "============================================================\n"
        " 请选择热切换操作（不会中断在途连接与公网通道）：\n"
        "  [1] 切换安全模式（工作区内顺畅开发 / 仅修改文件（禁运行命令） / 只读浏览模式 / 全盘顺畅开发（不限目录））\n"
        "  [2] 追加开放工作目录（多目录热挂载）\n"
        "  [3] 开关扩展能力包（browser 受管浏览器 / desktop 桌面操控）\n"
        "  [4] 查看连接口令、4 位核对码与连接地址\n"
        "  [5] 停止后台常驻服务\n"
        "  [0] 退出菜单（保持当前服务继续运行）\n"
    )
    choice = (input_fn("请输入编号 [0-5] (默认 0): ") or "0").strip()
    if choice == "1":
        tier_in = (
            input_fn("请输入模式 [L3 工作区内顺畅开发 / L2 仅修改文件（禁运行命令） / L1 只读浏览模式 / L4 全盘顺畅开发（不限目录）]: ")
            or ""
        ).strip()
        if tier_in:
            res = on_set_tier(tier_in)
            output_fn(f"已实时切换安全模式: {res.get('permission_tier')}")
            return {"ok": True, "menu_action": "set_tier", "result": res}
    elif choice == "2":
        ws_in = (input_fn("请输入要新增开放的目录路径: ") or "").strip()
        if ws_in:
            res = on_add_workspace(ws_in)
            output_fn(f"已实时更新开放目录: {res.get('workspace_roots')}")
            return {"ok": True, "menu_action": "add_workspace", "result": res}
    elif choice == "3":
        pk_in = (input_fn("请输入要开启的扩展包（browser / desktop / browser,desktop / none 清空）: ") or "").strip()
        res = on_toggle_pack(pk_in or "none")
        output_fn(f"已实时更新扩展包: {res.get('enabled_packs')}")
        return {"ok": True, "menu_action": "toggle_pack", "result": res}
    elif choice == "4":
        creds = on_show_credentials()
        output_fn(
            f"\n  连接器地址   : {creds.get('mcp_url')}\n"
            f"  只读连接地址 : {creds.get('readonly_mcp_url')}\n"
            f"  授权连接口令 : {creds.get('connection_password')}\n"
            f"  4 位核对码   : {creds.get('pair_code')}\n"
            f"  Cosmos Studio: {creds.get('local_admin_url')}\n"
        )
        return {"ok": True, "menu_action": "show_credentials", "result": creds}
    elif choice == "5":
        res = on_stop()
        output_fn("后台常驻服务已停止。")
        return {"ok": True, "menu_action": "stop", "result": res}
    return {"ok": True, "menu_action": "noop_keep_running"}


def _cli_entry() -> int:
    global _WMI_STDIO_HANDLE
    import argparse

    parser = argparse.ArgumentParser(description="Cosmos MCP Resident Daemon Supervisor")
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--runtime-python", required=True)
    parser.add_argument("--port", type=int, default=8096)
    parser.add_argument("--mode", default="")
    parser.add_argument("--prefix", default="pc")
    parser.add_argument("--tool-prefix", default="")
    parser.add_argument("--no-tray", action="store_true")
    parser.add_argument("--public-url", default="")
    parser.add_argument("--tunnel-token", default="")
    parser.add_argument("--vps-ssh", default="")
    parser.add_argument("--vps-remote-port", type=int, default=0)
    parser.add_argument("--vps-ssh-port", type=int, default=0)
    parser.add_argument("--vps-identity-file", default="")
    parser.add_argument("--log-file", default="")
    parser.add_argument("--pythonpath", default="")
    args = parser.parse_args()

    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["PYTHONUTF8"] = "1"
    if args.pythonpath:
        os.environ["PYTHONPATH"] = args.pythonpath
        extra_paths = [p for p in str(args.pythonpath).split(os.pathsep) if p and p not in sys.path]
        if extra_paths:
            sys.path[0:0] = extra_paths
    if args.log_file:
        try:
            lf_path = Path(args.log_file).expanduser().resolve()
            lf_path.parent.mkdir(parents=True, exist_ok=True)
            _WMI_STDIO_HANDLE = lf_path.open("a", encoding="utf-8", errors="replace", buffering=1)
            sys.stdout = _WMI_STDIO_HANDLE
            sys.stderr = _WMI_STDIO_HANDLE
        except Exception:
            pass

    sup = StandaloneSupervisorLoop(
        state_root=Path(args.state_dir),
        runtime_python=args.runtime_python,
        port=args.port,
        mode=args.mode,
        prefix=args.prefix,
        tool_prefix=args.tool_prefix,
        no_tray=bool(args.no_tray),
        public_url=args.public_url,
        tunnel_token=args.tunnel_token,
        vps_ssh=args.vps_ssh,
        vps_remote_port=args.vps_remote_port or None,
        vps_ssh_port=args.vps_ssh_port or None,
        vps_identity_file=args.vps_identity_file,
    )
    return sup.run_forever()


if __name__ == "__main__":
    raise SystemExit(_cli_entry())
