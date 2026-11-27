"""
Layer 0 Windowless Process Tree, Background Job Persistence & Batch Probe Primitive (`cosmos_mcp.core.proc`).

Pure Python >=3.9 standard-library implementation providing:
1. Strict L0 zero-popup execution (`CREATE_NO_WINDOW = 0x08000000`) + Win32 JobObject
   (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, default `16 GiB` or `0` unlimited) with `.detach()`
   clearing `KILL_ON_JOB_CLOSE` on smooth synchronous-to-background promotion.
2. Stripping MCP's own internal `.venv` while prioritizing target project `.venv`/`.conda`,
   explicit `python_path` / `venv` / `conda_env`, or `policy.python_path`, with optional
   explicit L3 audit hook opt-in and automatic writable `MPLCONFIGDIR` fallback.
3. Persistent background job ledger (`<state_root>/state/bg_jobs.json`) without indiscriminate
   `atexit` job slaughter: jobs survive daemon restarts (`DEFAULT_BG_MAX_TTL_SECONDS = 14400`),
   verify `(pid, proc_create_token)` before termination, and tail logs with `\\r` progress folding.
4. Read-only `run_batch_probe` sandbox using `sandbox_hook.BATCH_PROBE_RUNNER_SCRIPT`.
"""
from __future__ import annotations

import ast
import asyncio
import base64
import contextlib
import ctypes
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple, Union

from cosmos_mcp.core.guard import (
    CREATE_NO_WINDOW,
    DEFAULT_GUARD,
    WorkspaceGuard,
    canonical_realpath,
    expand_env_and_tilde,
    get_discovered_toolchain_dirs,
    get_stripped_host_path,
)
from cosmos_mcp.core.net_power import SleepInhibitor
from cosmos_mcp.core.sandbox_hook import (
    BATCH_PROBE_RUNNER_SCRIPT,
    prepare_l3_sandbox_env,
)

LOGGER = logging.getLogger("cosmos_mcp.l0.proc")

CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_BREAKAWAY_FROM_JOB = 0x01000000
SEM_NO_CRASH_POPUP_MASK = 0x8003
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
TH32CS_SNAPPROCESS = 0x00000002
STILL_ACTIVE_WIN32 = 259

MAX_OUTPUT_CHARS = 24000
MAX_RAW_CAPTURE_BYTES = 2 * 1024 * 1024
HEAD_KEEP_RATIO = 0.35
PRUNE_KEEP_BUDGET = 20000
PRUNE_HEAD_CHARS = int(PRUNE_KEEP_BUDGET * HEAD_KEEP_RATIO)
DEFAULT_MAX_PROC_MEM_MB = 16384
MAX_SPILL_FILES = 50
MAX_SLOTS = 8
MAX_BG_JOBS = 16
DEFAULT_BG_MAX_TTL_SECONDS = 14400
MAX_BG_LOG_BYTES = 8 * 1024 * 1024
MAX_TAIL_READ_BYTES = 256 * 1024
TAIL_CHUNK_BYTES = 65536
MAX_BG_HISTORY_ENTRIES = 64
DEFAULT_SYNC_WAIT_CAP_SEC = 20.0
MAX_SYNC_WAIT_CAP_SEC = 60.0
MIN_SYNC_WAIT_CAP_SEC = 0.2
MAX_AUDIT_LOG_BYTES = 5 * 1024 * 1024

_AUDIT_LOCK = threading.Lock()
_SPILL_LOCK = threading.Lock()

if sys.platform == "win32":
    from ctypes import wintypes

    class _FILETIME(ctypes.Structure):
        _fields_ = [
            ("dwLowDateTime", wintypes.DWORD),
            ("dwHighDateTime", wintypes.DWORD),
        ]

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount", ctypes.c_uint64),
            ("WriteTransferCount", ctypes.c_uint64),
            ("OtherTransferCount", ctypes.c_uint64),
        ]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class _PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]


def suppress_win32_crash_dialogs() -> int:
    """Set `SetErrorMode(0x8003)` on Windows so child crashes never pop WER/GPF modal dialogs (`GAP-08`)."""
    if sys.platform != "win32":
        return 0
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.SetErrorMode.argtypes = [ctypes.c_uint]
        kernel32.SetErrorMode.restype = ctypes.c_uint
        prev = int(kernel32.SetErrorMode(SEM_NO_CRASH_POPUP_MASK))
        kernel32.SetErrorMode(prev | SEM_NO_CRASH_POPUP_MASK)
        return prev | SEM_NO_CRASH_POPUP_MASK
    except Exception:
        return 0


def cancel_win32_handle_io(stream_or_fd: Any) -> bool:
    """Issue Win32 `CancelIoEx(handle, NULL)` on a stream or file descriptor before timeout cleanup (`GAP-08`)."""
    if sys.platform != "win32" or stream_or_fd is None:
        return False
    try:
        import msvcrt

        fd = stream_or_fd if isinstance(stream_or_fd, int) else int(stream_or_fd.fileno())
        if fd < 0:
            return False
        h_os = msvcrt.get_osfhandle(fd)
        if not h_os or h_os == -1:
            return False
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        kernel32.CancelIoEx.restype = wintypes.BOOL
        return bool(kernel32.CancelIoEx(wintypes.HANDLE(h_os), None))
    except Exception:
        return False


suppress_win32_crash_dialogs()


def win32_no_window_flags(*, new_process_group: bool = False, breakaway: bool = False) -> int:
    if sys.platform != "win32":
        return 0
    flags = CREATE_NO_WINDOW
    if new_process_group:
        flags |= CREATE_NEW_PROCESS_GROUP
    if breakaway:
        flags |= CREATE_BREAKAWAY_FROM_JOB
    return flags


def _popen_with_optional_breakaway(
    argv: Sequence[str],
    *,
    breakaway: Optional[bool] = None,
    **kwargs: Any,
) -> subprocess.Popen[Any]:
    """Spawn a Win32 subprocess attempting `CREATE_BREAKAWAY_FROM_JOB` ONLY when explicitly enabled."""
    if sys.platform != "win32":
        return subprocess.Popen(argv, **kwargs)
    orig_flags = int(kwargs.get("creationflags") or 0)
    if breakaway is False:
        if orig_flags & CREATE_BREAKAWAY_FROM_JOB:
            clean_kw = dict(kwargs)
            clean_kw["creationflags"] = orig_flags & ~CREATE_BREAKAWAY_FROM_JOB
            return subprocess.Popen(argv, **clean_kw)
        return subprocess.Popen(argv, **kwargs)
    if breakaway is True and not (orig_flags & CREATE_BREAKAWAY_FROM_JOB):
        orig_flags |= CREATE_BREAKAWAY_FROM_JOB
        kwargs = {**kwargs, "creationflags": orig_flags}
    if not (orig_flags & CREATE_BREAKAWAY_FROM_JOB):
        return subprocess.Popen(argv, **kwargs)
    try:
        return subprocess.Popen(argv, **kwargs)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 5 or isinstance(exc, PermissionError):
            fallback_kw = dict(kwargs)
            fallback_kw["creationflags"] = orig_flags & ~CREATE_BREAKAWAY_FROM_JOB
            return subprocess.Popen(argv, **fallback_kw)
        raise


def assign_win32_job_kill_on_close(
    pid: int,
    max_mem_mb: int = DEFAULT_MAX_PROC_MEM_MB,
    *,
    allow_breakaway: bool = False,
) -> Optional[int]:
    """Bind `pid` to a Win32 Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (and optional `BREAKAWAY_OK`)."""
    if sys.platform != "win32" or pid <= 0:
        return None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        h_job = kernel32.CreateJobObjectW(None, None)
        if not h_job:
            return None
        base_limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | (
            JOB_OBJECT_LIMIT_BREAKAWAY_OK if allow_breakaway else 0
        )
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        ok_set = False
        if max_mem_mb > 0 and sys.maxsize > 2**32:
            info.BasicLimitInformation.LimitFlags = base_limit_flags | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            info.ProcessMemoryLimit = int(max_mem_mb) * 1024 * 1024
            ok_set = bool(kernel32.SetInformationJobObject(h_job, 9, ctypes.byref(info), ctypes.sizeof(info)))
        if not ok_set:
            info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = base_limit_flags
            ok_set = bool(kernel32.SetInformationJobObject(h_job, 9, ctypes.byref(info), ctypes.sizeof(info)))
        if not ok_set:
            kernel32.CloseHandle(h_job)
            return None

        h_proc = kernel32.OpenProcess(0x0101, False, int(pid))
        if not h_proc:
            kernel32.CloseHandle(h_job)
            return None
        try:
            if not kernel32.AssignProcessToJobObject(h_job, h_proc):
                kernel32.CloseHandle(h_job)
                return None
            return int(h_job)
        finally:
            kernel32.CloseHandle(h_proc)
    except Exception:
        return None


def _clear_win32_job_kill_on_close(h_job: Optional[int]) -> None:
    """Clear `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` so promoted background jobs survive daemon restart."""
    if sys.platform != "win32" or not h_job:
        return
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = 0
        kernel32.SetInformationJobObject(wintypes.HANDLE(h_job), 9, ctypes.byref(info), ctypes.sizeof(info))
    except Exception:
        pass


def _close_win32_job(h_job: Optional[int]) -> None:
    if sys.platform == "win32" and h_job:
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            kernel32.CloseHandle(wintypes.HANDLE(h_job))
        except Exception:
            pass


def assign_win32_bg_job_object(pid: int) -> Optional[int]:
    """Bind background `pid` to a Win32 Job Object without `KILL_ON_JOB_CLOSE` so restarts survive yet `revoke_all` reaps all descendants."""
    if sys.platform != "win32" or pid <= 0:
        return None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        h_job = kernel32.CreateJobObjectW(None, None)
        if not h_job:
            return None
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_BREAKAWAY_OK
        if not kernel32.SetInformationJobObject(h_job, 9, ctypes.byref(info), ctypes.sizeof(info)):
            kernel32.CloseHandle(h_job)
            return None
        h_proc = kernel32.OpenProcess(0x0101, False, int(pid))
        if not h_proc:
            kernel32.CloseHandle(h_job)
            return None
        try:
            if not kernel32.AssignProcessToJobObject(h_job, h_proc):
                kernel32.CloseHandle(h_job)
                return None
            return int(h_job)
        finally:
            kernel32.CloseHandle(h_proc)
    except Exception:
        return None


def _terminate_win32_job(h_job: Optional[int], exit_code: int = 1) -> bool:
    if sys.platform != "win32" or not h_job:
        return False
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        return bool(kernel32.TerminateJobObject(wintypes.HANDLE(h_job), wintypes.UINT(int(exit_code) & 0xFFFFFFFF)))
    except Exception:
        return False


class OwnedJobHandle:
    """RAII wrapper for Win32 JobObject handle supporting `.detach()` on background promotion."""

    def __init__(self, handle: Optional[int]) -> None:
        self._handle = handle

    @property
    def handle(self) -> Optional[int]:
        return self._handle

    def detach(self, *, survive_daemon_exit: bool = True) -> "OwnedJobHandle":
        handle, self._handle = self._handle, None
        if handle is not None and survive_daemon_exit:
            _clear_win32_job_kill_on_close(handle)
        return OwnedJobHandle(handle)

    def close(self) -> None:
        handle, self._handle = self._handle, None
        if handle is not None:
            _close_win32_job(handle)


def get_process_create_token(pid: int) -> Optional[str]:
    """
    Return an OS-level process creation timestamp token for `pid` to prevent PID-reuse kills.
    - Windows: 64-bit FILETIME ticks from `GetProcessTimes` (`100ns` units since 1601-01-01).
    - Linux: `/proc/<pid>/stat` field 22 (`starttime` clock ticks since boot).
    - macOS/BSD: `ps -p <pid> -o lstart=` string.
    """
    if pid <= 0:
        return None
    if sys.platform == "win32":
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.GetProcessTimes.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(_FILETIME),
                ctypes.POINTER(_FILETIME),
                ctypes.POINTER(_FILETIME),
                ctypes.POINTER(_FILETIME),
            ]
            kernel32.GetProcessTimes.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL

            h = kernel32.OpenProcess(0x1000, False, int(pid))
            if not h:
                return None
            try:
                c_ft, e_ft, k_ft, u_ft = _FILETIME(), _FILETIME(), _FILETIME(), _FILETIME()
                if kernel32.GetProcessTimes(h, ctypes.byref(c_ft), ctypes.byref(e_ft), ctypes.byref(k_ft), ctypes.byref(u_ft)):
                    ticks = (int(c_ft.dwHighDateTime) << 32) | int(c_ft.dwLowDateTime)
                    if ticks > 0:
                        return str(ticks)
            finally:
                kernel32.CloseHandle(h)
        except Exception:
            return None
        return None

    proc_stat = Path(f"/proc/{pid}/stat")
    if proc_stat.is_file():
        try:
            raw = proc_stat.read_text(encoding="utf-8", errors="replace")
            rparen = raw.rfind(")")
            if rparen > 0:
                fields = raw[rparen + 2 :].split()
                if len(fields) > 19:
                    return fields[19]
        except Exception:
            pass

    try:
        r = subprocess.run(
            ["ps", "-p", str(pid), "-o", "lstart="],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=2.0,
            creationflags=win32_no_window_flags(),
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass
    return None


def is_raw_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
            kernel32.GetExitCodeProcess.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL

            h = kernel32.OpenProcess(0x1000, False, int(pid))
            if not h:
                return int(ctypes.get_last_error()) == 5
            try:
                ec = wintypes.DWORD(0)
                if kernel32.GetExitCodeProcess(h, ctypes.byref(ec)):
                    return int(ec.value) == STILL_ACTIVE_WIN32
                return False
            finally:
                kernel32.CloseHandle(h)
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def verify_pid_alive(pid: int, expected_create_token: Optional[str] = None) -> Tuple[bool, bool]:
    """
    Verify both that `pid` is currently alive AND that its creation token matches `expected_create_token`.
    Returns `(is_same_process_alive, pid_was_reused)`.
    """
    if not is_raw_pid_alive(pid):
        return False, False
    if expected_create_token:
        actual = get_process_create_token(pid)
        if actual is not None and str(actual) != str(expected_create_token):
            return False, True
    return True, False


def _collect_descendant_pids_win32(root_pid: int, root_create_token: Optional[str] = None) -> List[int]:
    """Snapshot Win32 process table and return verified child/grandchild PIDs of `root_pid`."""
    if sys.platform != "win32" or root_pid <= 0:
        return []
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
        kernel32.Process32FirstW.restype = wintypes.BOOL
        kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
        kernel32.Process32NextW.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        invalid_handle = ctypes.c_void_p(-1).value
        if not snap or int(snap) == invalid_handle:
            return []
        children_map: Dict[int, List[int]] = {}
        try:
            pe = _PROCESSENTRY32W()
            pe.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
            ok = bool(kernel32.Process32FirstW(snap, ctypes.byref(pe)))
            while ok:
                cpid = int(pe.th32ProcessID)
                ppid = int(pe.th32ParentProcessID)
                if cpid > 4 and cpid != ppid:
                    children_map.setdefault(ppid, []).append(cpid)
                ok = bool(kernel32.Process32NextW(snap, ctypes.byref(pe)))
        finally:
            kernel32.CloseHandle(snap)

        root_ticks = int(root_create_token) if (root_create_token and str(root_create_token).isdigit()) else 0
        self_pid = os.getpid()
        descendants: List[int] = []
        seen: Set[int] = {int(root_pid), 0, 4, self_pid}
        queue: List[int] = [int(root_pid)]
        while queue:
            cur = queue.pop(0)
            for child in children_map.get(cur, ()):
                if child in seen:
                    continue
                seen.add(child)
                if root_ticks > 0:
                    ctok = get_process_create_token(child)
                    if ctok and ctok.isdigit() and (int(ctok) + 500_000) < root_ticks:
                        continue
                descendants.append(child)
                queue.append(child)
        return descendants
    except Exception:
        return []


def _terminate_single_pid_win32(pid: int) -> bool:
    if sys.platform != "win32" or pid <= 0 or pid == os.getpid():
        return False
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        h = kernel32.OpenProcess(0x0001, False, int(pid))
        if not h:
            return False
        try:
            return bool(kernel32.TerminateProcess(h, 1))
        finally:
            kernel32.CloseHandle(h)
    except Exception:
        return False


_LAST_KILL_DIAGNOSTICS = threading.local()


def get_last_kill_diagnostics() -> Dict[str, Any]:
    """Return structured diagnostics from the most recent process-tree termination call on this thread."""
    raw = getattr(_LAST_KILL_DIAGNOSTICS, "value", None)
    if not isinstance(raw, dict):
        return {"terminated": False, "pid_reused": False, "still_running": [], "errors": []}
    return {
        "terminated": bool(raw.get("terminated")),
        "pid_reused": bool(raw.get("pid_reused")),
        "still_running": list(raw.get("still_running") or []),
        "errors": list(raw.get("errors") or []),
    }


def _record_kill_diagnostics(
    *,
    terminated: bool,
    pid_reused: bool,
    still_running: Sequence[int],
    errors: Sequence[str],
    diagnostics: Optional[Dict[str, Any]] = None,
) -> None:
    payload: Dict[str, Any] = {
        "terminated": bool(terminated),
        "pid_reused": bool(pid_reused),
        "still_running": [int(p) for p in still_running],
        "errors": [str(e) for e in errors],
    }
    _LAST_KILL_DIAGNOSTICS.value = payload
    if diagnostics is not None:
        diagnostics.clear()
        diagnostics.update(payload)


def _safe_is_pid_alive(pid: int, errors: List[str]) -> bool:
    """Fail-closed liveness check: if exit cannot be confirmed, treat the PID as still running."""
    try:
        return bool(is_raw_pid_alive(pid))
    except Exception as exc:
        errors.append(f"liveness_check({pid}) error={exc}")
        return True


def _kill_process_tree_win32(
    pid: int,
    expected_create_token: Optional[str] = None,
    job_handle: Optional[OwnedJobHandle] = None,
    wait_timeout_sec: float = 1.0,
    diagnostics: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, bool]:
    """Verify `(pid, expected_create_token)`, kill child/grandchild tree windowlessly, and confirm exit within `<=1.0s`."""
    errors: List[str] = []
    alive, reused = verify_pid_alive(pid, expected_create_token)
    if reused:
        if job_handle is not None:
            job_handle.detach(survive_daemon_exit=True).close()
        _record_kill_diagnostics(
            terminated=False,
            pid_reused=True,
            still_running=[],
            errors=errors,
            diagnostics=diagnostics,
        )
        return False, True

    eff_tok = expected_create_token or (get_process_create_token(pid) if alive else None)
    desc_before = _collect_descendant_pids_win32(pid, eff_tok) if pid > 0 else []

    any_terminate_ok = False
    killed_via_job = False
    if job_handle is not None:
        raw_jh = job_handle.handle
        if raw_jh:
            killed_via_job = bool(_terminate_win32_job(raw_jh, 1))
            if killed_via_job:
                any_terminate_ok = True
            else:
                errors.append(f"TerminateJobObject({pid}) failed")
        job_handle.close()

    if not alive and not desc_before and not killed_via_job:
        _record_kill_diagnostics(
            terminated=False,
            pid_reused=False,
            still_running=[],
            errors=errors,
            diagnostics=diagnostics,
        )
        return False, False

    if alive and pid > 0:
        try:
            tk_res = subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=3.0,
                creationflags=CREATE_NO_WINDOW,
            )
            if getattr(tk_res, "returncode", 1) == 0:
                any_terminate_ok = True
            else:
                errors.append(f"taskkill({pid}) rc={getattr(tk_res, 'returncode', -1)}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"taskkill({pid}) error={exc}")

    desc_after = _collect_descendant_pids_win32(pid, eff_tok) if pid > 0 else []
    target_pids = [
        p for p in dict.fromkeys(([pid] if alive else []) + list(reversed(desc_before)) + list(reversed(desc_after)))
        if p > 0 and p != os.getpid()
    ]
    for t_pid in target_pids:
        if _safe_is_pid_alive(t_pid, errors):
            if _terminate_single_pid_win32(t_pid):
                any_terminate_ok = True
            else:
                errors.append(f"TerminateProcess({t_pid}) failed")
            if t_pid != pid:
                try:
                    tk_child = subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(t_pid)],
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        timeout=2.0,
                        creationflags=CREATE_NO_WINDOW,
                    )
                    if getattr(tk_child, "returncode", 1) == 0:
                        any_terminate_ok = True
                    else:
                        errors.append(f"taskkill({t_pid}) rc={getattr(tk_child, 'returncode', -1)}")
                except (OSError, subprocess.TimeoutExpired) as exc:
                    errors.append(f"taskkill({t_pid}) error={exc}")

    if target_pids and wait_timeout_sec > 0:
        deadline = time.monotonic() + max(0.05, min(2.0, float(wait_timeout_sec)))
        while time.monotonic() < deadline:
            survivors = [p for p in target_pids if _safe_is_pid_alive(p, errors)]
            if not survivors:
                break
            for spid in survivors:
                if _terminate_single_pid_win32(spid):
                    any_terminate_ok = True
            time.sleep(0.03)

    remaining = [p for p in target_pids if _safe_is_pid_alive(p, errors)]
    terminated = bool(any_terminate_ok and not remaining)
    _record_kill_diagnostics(
        terminated=terminated,
        pid_reused=False,
        still_running=remaining,
        errors=errors,
        diagnostics=diagnostics,
    )
    return terminated, False


def terminate_verified_pid_tree(
    pid: int,
    expected_create_token: Optional[str] = None,
    job_handle: Optional[OwnedJobHandle] = None,
    pgid: Optional[int] = None,
    wait_timeout_sec: float = 1.0,
    diagnostics: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, bool]:
    """
    Safely terminate a process tree ONLY after verifying `(pid, expected_create_token)`.
    Returns `(terminated, pid_reused_skipped)`.
    """
    if sys.platform == "win32":
        return _kill_process_tree_win32(
            pid,
            expected_create_token=expected_create_token,
            job_handle=job_handle,
            wait_timeout_sec=wait_timeout_sec,
            diagnostics=diagnostics,
        )
    errors: List[str] = []
    alive, reused = verify_pid_alive(pid, expected_create_token)
    if reused:
        if job_handle is not None:
            job_handle.detach(survive_daemon_exit=True).close()
        _record_kill_diagnostics(
            terminated=False,
            pid_reused=True,
            still_running=[],
            errors=errors,
            diagnostics=diagnostics,
        )
        return False, True
    if job_handle is not None:
        job_handle.close()
    if not alive:
        _record_kill_diagnostics(
            terminated=False,
            pid_reused=False,
            still_running=[],
            errors=errors,
            diagnostics=diagnostics,
        )
        return False, False
    any_signal_ok = False
    eff_pgid = pgid
    if eff_pgid is None:
        with contextlib.suppress(Exception):
            eff_pgid = os.getpgid(pid)
    sig_val = getattr(signal, "SIGKILL", signal.SIGTERM)
    if eff_pgid and eff_pgid > 1 and eff_pgid != os.getpgid(0):
        try:
            os.killpg(eff_pgid, sig_val)
            any_signal_ok = True
        except OSError as exc:
            errors.append(f"os.killpg({eff_pgid}) error={exc}")
    try:
        os.kill(pid, sig_val)
        any_signal_ok = True
    except OSError as exc:
        errors.append(f"os.kill({pid}) error={exc}")
    if wait_timeout_sec > 0:
        deadline = time.monotonic() + max(0.05, min(2.0, float(wait_timeout_sec)))
        while time.monotonic() < deadline:
            if not _safe_is_pid_alive(pid, errors):
                break
            time.sleep(0.03)
    still_alive = _safe_is_pid_alive(pid, errors)
    remaining = [pid] if still_alive else []
    terminated = bool(any_signal_ok and not remaining)
    _record_kill_diagnostics(
        terminated=terminated,
        pid_reused=False,
        still_running=remaining,
        errors=errors,
        diagnostics=diagnostics,
    )
    return terminated, False


# --- Healthy Target Project `.venv` & Rich Host Python Discovery ---

def _norm_dir_key(raw_p: str) -> str:
    return os.path.normcase(os.path.normpath(raw_p.strip().strip('"'))).rstrip("\\/")


def _is_bootstrap_venv_entry(name: str) -> bool:
    low = name.lower()
    if low in ("__pycache__", "_distutils_hack", "pkg_resources", "distutils-precedence.pth", "easy_install.py", "readme.txt", "readme.md"):
        return True
    if low in ("pip", "setuptools", "wheel"):
        return True
    return low.startswith(("_virtualenv", "pip-", "pip_", "setuptools-", "setuptools_", "wheel-", "wheel_"))


def is_healthy_project_venv(vdir: Path) -> bool:
    """Fast check that `<vdir>` has a Python binary and non-hollow `site-packages` (or valid `pyvenv.cfg` with packages)."""
    py_cands = (
        (vdir / "Scripts" / "python.exe", vdir / "python.exe")
        if sys.platform == "win32"
        else (vdir / "bin" / "python3", vdir / "bin" / "python")
    )
    if not any(p.is_file() for p in py_cands):
        return False
    sp_dirs: List[Path] = []
    for cand_sp in (vdir / "Lib" / "site-packages", vdir / "lib" / "site-packages"):
        if cand_sp.is_dir():
            sp_dirs.append(cand_sp)
    for lib_name in ("lib", "lib64"):
        lib_root = vdir / lib_name
        if lib_root.is_dir():
            with contextlib.suppress(OSError):
                with os.scandir(lib_root) as lit:
                    for lde in lit:
                        if lde.name.lower().startswith("python") and lde.is_dir(follow_symlinks=False):
                            sp_p = Path(lde.path) / "site-packages"
                            if sp_p.is_dir() and sp_p not in sp_dirs:
                                sp_dirs.append(sp_p)
    if not sp_dirs:
        return False
    for sp in sp_dirs:
        with contextlib.suppress(OSError):
            with os.scandir(sp) as it:
                for de in it:
                    if _is_bootstrap_venv_entry(de.name):
                        continue
                    low = de.name.lower()
                    if de.is_dir(follow_symlinks=False):
                        return True
                    if de.is_file(follow_symlinks=False) and low.endswith((".pth", ".egg-link", ".egg-info", ".egg", ".py", ".pyd", ".so", ".dll")):
                        if de.stat().st_size > 0:
                            return True
    return False


def _python_from_env_dir(env_dir: Path) -> Optional[Path]:
    """Return console Python executable inside a virtualenv or Conda prefix directory if present."""
    py_cands = (
        (env_dir / "Scripts" / "python.exe", env_dir / "python.exe")
        if sys.platform == "win32"
        else (env_dir / "bin" / "python3", env_dir / "bin" / "python")
    )
    for py_c in py_cands:
        if py_c.is_file():
            return Path(resolve_console_python(str(py_c)))
    return None


def is_healthy_project_conda(cdir: Path) -> bool:
    """Check that `<cdir>` is a valid local Conda prefix (`.conda`) with a Python binary."""
    if _python_from_env_dir(cdir) is None:
        return False
    return (cdir / "conda-meta").is_dir() or is_healthy_project_venv(cdir)


def find_target_project_venv(
    cwd: Optional[Union[str, Path]] = None,
    *,
    workspace_roots: Sequence[Path] = (),
    state_root: Optional[Path] = None,
    product_root: Optional[Path] = None,
) -> Optional[Tuple[Path, Path]]:
    """Locate healthy `<cwd>/.venv` or `<cwd>/.conda` (or workspace root), skipping MCP's own internal `.venv`."""
    own_keys: Set[str] = set()
    for own_base in (state_root, product_root):
        if own_base is not None:
            v_own = own_base / ".venv"
            own_keys.add(_norm_dir_key(str(v_own)))
            own_keys.add(_norm_dir_key(str(canonical_realpath(v_own))))
    if sys.prefix != sys.base_prefix:
        own_keys.add(_norm_dir_key(sys.prefix))

    search_dirs: List[Path] = []
    if cwd and str(cwd).strip():
        cwd_p = canonical_realpath(cwd)
        if cwd_p.is_dir():
            search_dirs.append(cwd_p)
            cur = cwd_p
            for _ in range(6):
                if cur.parent == cur:
                    break
                if workspace_roots and any(_norm_dir_key(str(cur)) == _norm_dir_key(str(w)) for w in workspace_roots):
                    break
                cur = cur.parent
                if cur not in search_dirs:
                    search_dirs.append(cur)
    for ws in workspace_roots:
        if ws.is_dir() and ws not in search_dirs:
            search_dirs.append(ws)

    for base_d in search_dirs:
        for env_sub, checker in ((".venv", is_healthy_project_venv), (".conda", is_healthy_project_conda)):
            vdir = base_d / env_sub
            if not vdir.is_dir():
                continue
            vk = _norm_dir_key(str(canonical_realpath(vdir)))
            if vk in own_keys:
                continue
            if not checker(vdir):
                continue
            py_found = _python_from_env_dir(vdir)
            if py_found is not None:
                return canonical_realpath(vdir), py_found
    return None


_CACHED_HOST_PYTHON: Optional[str] = None
_CACHED_CONDA_INFO_ENVS: Optional[Tuple[float, List[Path]]] = None


def _env_get_ci(env: Mapping[str, str], key: str, default: str = "") -> str:
    if key in env:
        return env[key]
    ku = key.upper()
    for k, v in env.items():
        if k.upper() == ku:
            return v
    return default


def _env_pop_ci(env: Dict[str, str], key: str) -> None:
    ku = key.upper()
    for k in [ek for ek in env.keys() if ek.upper() == ku]:
        env.pop(k, None)


def _env_set_ci(env: Dict[str, str], key: str, value: str) -> None:
    _env_pop_ci(env, key)
    env[key] = value


_SAFE_CONDA_ENV_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


def resolve_console_python(exe_path: Optional[str] = None) -> str:
    """Ensure Windows `pythonw.exe` (GUI subsystem) is mapped to sibling `python.exe` for console/pipe execution."""
    raw = (exe_path or sys.executable or "").strip()
    if sys.platform == "win32" and raw.lower().endswith("pythonw.exe"):
        cand = Path(raw).with_name("python.exe")
        if cand.is_file():
            return str(cand)
        return raw[:-5] + ".exe"
    return raw


_ensure_console_python_exe = resolve_console_python

_BG_PYTHONW_HEAD_RE = re.compile(
    r'^(?P<pre>\s*(?:cmd(?:\.exe)?\s+/[cC]\s+)?(?:&\s*)?)'
    r'(?:"(?P<dq>[^"\r\n]*?pythonw(?:\.exe)?)"|\'(?P<sq>[^\'\r\n]*?pythonw(?:\.exe)?)\'|(?P<bare>[^\s"\'&|;]*?pythonw(?:\.exe)?))'
    r'(?=\s|$)',
    re.IGNORECASE,
)


def _normalize_bg_pythonw_command(command: str) -> str:
    """Rewrite leading `pythonw.exe` / `pythonw` in `bg_command` to console `python.exe` so shells wait for completion."""
    m = _BG_PYTHONW_HEAD_RE.match(command)
    if not m:
        return command
    pre = m.group("pre") or ""
    rest = command[m.end() :]
    dq, sq, bare = m.group("dq"), m.group("sq"), m.group("bare")
    raw_tok = dq or sq or bare or ""
    quote_ch = '"' if dq is not None else ("'" if sq is not None else "")
    has_sep = ("\\" in raw_tok) or ("/" in raw_tok)
    if has_sep:
        p = Path(raw_tok)
        sib_name = "python.exe" if (sys.platform == "win32" or raw_tok.lower().endswith(".exe")) else "python"
        sib = p.with_name(sib_name)
        mapped = str(sib) if sib.is_file() else str(p.with_name(sib_name))
    else:
        mapped = "python.exe" if sys.platform == "win32" else "python"
    return f"{pre}{quote_ch}{mapped}{quote_ch}{rest}"


def _read_conda_environments_txt() -> List[Path]:
    out: List[Path] = []
    env_txt = Path.home() / ".conda" / "environments.txt"
    if not env_txt.is_file():
        return out
    with contextlib.suppress(OSError):
        for ln in env_txt.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = ln.strip()
            if s and not s.startswith("#"):
                p = Path(s)
                if p.is_dir() and p not in out:
                    out.append(p)
    return out


def _find_conda_executable() -> Optional[str]:
    env_conda = (os.environ.get("CONDA_EXE") or "").strip()
    if env_conda and Path(env_conda).is_file():
        return env_conda
    home = Path.home()
    if sys.platform == "win32":
        for root_d in (
            home / "miniconda3",
            home / "anaconda3",
            home / "miniforge3",
            home / "mambaforge",
            Path(os.environ.get("LOCALAPPDATA") or "") / "miniconda3",
            Path(os.environ.get("LOCALAPPDATA") or "") / "anaconda3",
        ):
            cexe = root_d / "Scripts" / "conda.exe"
            if cexe.is_file():
                return str(cexe)
    w = shutil.which("conda.exe") if sys.platform == "win32" else shutil.which("conda")
    if w:
        return w
    w_any = shutil.which("conda")
    if w_any and sys.platform == "win32":
        wp = Path(w_any)
        # Map `.../Library/bin/conda.BAT` or `.../condabin/conda.bat` to `.../Scripts/conda.exe` when present
        for anc in (wp.parent.parent, wp.parent.parent.parent):
            cand_exe = anc / "Scripts" / "conda.exe"
            if cand_exe.is_file():
                return str(cand_exe)
    return w_any


def _query_conda_info_envs() -> List[Path]:
    global _CACHED_CONDA_INFO_ENVS
    now = time.monotonic()
    if _CACHED_CONDA_INFO_ENVS is not None and (now - _CACHED_CONDA_INFO_ENVS[0]) < 60.0:
        return list(_CACHED_CONDA_INFO_ENVS[1])
    conda_bin = _find_conda_executable()
    if not conda_bin:
        return []
    envs: List[Path] = []
    try:
        argv = [conda_bin, "info", "--envs", "--json"]
        if sys.platform == "win32" and conda_bin.lower().endswith((".bat", ".cmd")):
            argv = [os.environ.get("ComSpec") or "cmd.exe", "/d", "/s", "/c", f'"{conda_bin}" info --envs --json']
        r = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8.0,
            creationflags=win32_no_window_flags(),
        )
        if r.returncode == 0 and r.stdout.strip():
            doc = json.loads(r.stdout)
            for ep in doc.get("envs") or []:
                if ep:
                    p = Path(str(ep))
                    if p.is_dir() and p not in envs:
                        envs.append(p)
    except Exception:
        pass
    _CACHED_CONDA_INFO_ENVS = (now, envs)
    return list(envs)


def _extract_policy_python_path(policy: Optional[Any], guard: Optional[WorkspaceGuard]) -> str:
    if policy is not None:
        if isinstance(policy, Mapping):
            val = str(policy.get("python_path") or "").strip()
            if val:
                return val
        else:
            val = str(getattr(policy, "python_path", "") or "").strip()
            if val:
                return val
    if guard is not None:
        g_val = str(getattr(guard, "python_path", "") or "").strip()
        if g_val:
            return g_val
    return (os.environ.get("COSMOS_PYTHON_PATH") or "").strip()


def resolve_python_interpreter(
    python_path: str = "",
    cwd: Optional[Union[str, Path]] = None,
    *,
    venv: str = "",
    conda_env: str = "",
    policy: Optional[Any] = None,
    guard: Optional[WorkspaceGuard] = None,
) -> str:
    """
    Resolve Python interpreter from explicit `python_path` / `venv` / `conda_env`,
    `policy.python_path`, or automatic `.venv`/`.conda`/`CONDA_PREFIX`/host discovery.
    Raises `FileNotFoundError` when an explicit caller-supplied spec does not exist.
    """
    eff_guard = guard or DEFAULT_GUARD
    explicit_spec = (python_path or venv or conda_env or "").strip()
    spec = explicit_spec or _extract_policy_python_path(policy, eff_guard)
    if not spec:
        return resolve_rich_python(cwd=cwd, guard=eff_guard)

    expanded = expand_env_and_tilde(spec).strip().strip("\"'")
    cand_paths: List[Path] = []
    exp_p = Path(expanded)
    if exp_p.is_absolute():
        cand_paths.append(exp_p)
    else:
        if cwd and str(cwd).strip():
            cand_paths.append(canonical_realpath(cwd) / exp_p)
        for ws in eff_guard.workspace_roots:
            cand_paths.append(ws / exp_p)
        cand_paths.append(exp_p)

    for cp in cand_paths:
        if cp.is_file():
            return resolve_console_python(str(canonical_realpath(cp)))
        if cp.is_dir():
            for d_cand in (cp, cp / ".venv", cp / ".conda"):
                if d_cand.is_dir():
                    py_hit = _python_from_env_dir(d_cand)
                    if py_hit is not None:
                        return str(py_hit)

    # Named Conda environment lookup (`base` or `<name>`)
    has_sep = ("/" in expanded) or ("\\" in expanded)
    if not has_sep:
        low_name = expanded.lower()
        home = Path.home()
        conda_bases = [
            home / "miniconda3",
            home / "anaconda3",
            home / "miniforge3",
            home / "mambaforge",
            home / ".conda",
        ]
        if sys.platform == "win32":
            local_app = os.environ.get("LOCALAPPDATA") or ""
            if local_app:
                conda_bases.extend([
                    Path(local_app) / "miniconda3",
                    Path(local_app) / "anaconda3",
                    Path(local_app) / "Continuum" / "anaconda3",
                ])
            prog_data = os.environ.get("ProgramData") or ""
            if prog_data:
                conda_bases.extend([
                    Path(prog_data) / "miniconda3",
                    Path(prog_data) / "anaconda3",
                    Path(prog_data) / "miniforge3",
                ])
        conda_bin_disc = _find_conda_executable()
        if conda_bin_disc:
            cb_p = Path(conda_bin_disc).resolve()
            if cb_p.parent.name.lower() in ("scripts", "condabin", "bin"):
                cb_root = cb_p.parent.parent
                if cb_root.is_dir() and cb_root not in conda_bases:
                    conda_bases.insert(0, cb_root)

        conda_prefix_raw = (os.environ.get("CONDA_PREFIX") or "").strip()
        env_dir_cands: List[Path] = []
        if low_name == "base":
            if conda_prefix_raw:
                cp_obj = Path(conda_prefix_raw)
                if cp_obj.parent.name.lower() == "envs":
                    env_dir_cands.append(cp_obj.parent.parent)
                else:
                    env_dir_cands.append(cp_obj)
            env_dir_cands.extend(conda_bases)
            for et_p in _read_conda_environments_txt():
                if et_p.parent.name.lower() != "envs":
                    env_dir_cands.append(et_p)
        else:
            if conda_prefix_raw:
                cp_obj = Path(conda_prefix_raw)
                if cp_obj.name.lower() == low_name:
                    env_dir_cands.append(cp_obj)
                if cp_obj.parent.name.lower() == "envs":
                    env_dir_cands.append(cp_obj.parent / expanded)
                else:
                    env_dir_cands.append(cp_obj / "envs" / expanded)
            for cb in conda_bases:
                env_dir_cands.append(cb / "envs" / expanded)
            for et_p in _read_conda_environments_txt():
                if et_p.name.lower() == low_name:
                    env_dir_cands.append(et_p)

        for ed in env_dir_cands:
            if ed.is_dir():
                py_hit = _python_from_env_dir(ed)
                if py_hit is not None:
                    return str(py_hit)

        info_envs = _query_conda_info_envs()
        for ie in info_envs:
            if (low_name == "base" and ie.parent.name.lower() != "envs") or ie.name.lower() == low_name:
                py_hit = _python_from_env_dir(ie)
                if py_hit is not None:
                    return str(py_hit)

        which_py = shutil.which(expanded)
        if which_py and "microsoft\\windowsapps" not in which_py.lower() and Path(which_py).is_file():
            return resolve_console_python(str(canonical_realpath(which_py)))

    if explicit_spec:
        raise FileNotFoundError(f"Python interpreter or virtual/Conda environment not found: `{explicit_spec}`")
    return resolve_rich_python(cwd=cwd, guard=eff_guard)


def resolve_rich_python(
    cwd: Optional[Union[str, Path]] = None,
    *,
    guard: Optional[WorkspaceGuard] = None,
    policy: Optional[Any] = None,
) -> str:
    """Resolve target project `.venv`/`.conda` or `policy.python_path` first, else host Python >=3.9."""
    global _CACHED_HOST_PYTHON
    eff_guard = guard or DEFAULT_GUARD
    pol_py = _extract_policy_python_path(policy, eff_guard)
    if pol_py:
        with contextlib.suppress(FileNotFoundError):
            return resolve_python_interpreter(python_path=pol_py, cwd=cwd, guard=eff_guard)

    st_root = eff_guard.effective_state_root()
    proj_venv = find_target_project_venv(
        cwd,
        workspace_roots=eff_guard.workspace_roots,
        state_root=st_root,
        product_root=eff_guard.product_root,
    )
    if proj_venv is not None:
        return str(proj_venv[1])

    own_keys: Set[str] = {_norm_dir_key(str(st_root / ".venv"))}
    if eff_guard.product_root is not None:
        own_keys.add(_norm_dir_key(str(eff_guard.product_root / ".venv")))

    conda_prefix = (os.environ.get("CONDA_PREFIX") or "").strip()
    if conda_prefix and _norm_dir_key(conda_prefix) not in own_keys and Path(conda_prefix).is_dir():
        cp_py = _python_from_env_dir(Path(conda_prefix))
        if cp_py is not None:
            return str(cp_py)

    if _CACHED_HOST_PYTHON and Path(_CACHED_HOST_PYTHON).is_file():
        return _CACHED_HOST_PYTHON

    stripped_path = get_stripped_host_path(
        state_root=st_root,
        product_root=eff_guard.product_root,
    )
    home = Path.home()
    cands: List[str] = []
    if sys.platform == "win32":
        for nm in ("python.exe", "python", "python3.exe", "python3"):
            w = shutil.which(nm, path=stripped_path)
            if w and "microsoft\\windowsapps" not in w.lower():
                cands.append(w)
        cands.extend([
            str(Path(sys.base_prefix) / "python.exe"),
            str(home / "miniconda3" / "python.exe"),
            str(home / "anaconda3" / "python.exe"),
            str(home / "miniforge3" / "python.exe"),
        ])
        for et_dir in _read_conda_environments_txt():
            cands.append(str(et_dir / "python.exe"))
    else:
        for nm in ("python3", "python"):
            w = shutil.which(nm, path=stripped_path)
            if w:
                cands.append(w)
        cands.extend([
            str(Path(sys.base_prefix) / "bin" / "python3"),
            str(home / "miniconda3" / "bin" / "python3"),
            str(home / "anaconda3" / "bin" / "python3"),
            "/opt/homebrew/bin/python3",
            "/usr/bin/python3",
        ])
        for et_dir in _read_conda_environments_txt():
            cands.append(str(et_dir / "bin" / "python3"))

    for c in cands:
        if c and not c.lower().endswith("pythonw.exe") and Path(c).is_file():
            _CACHED_HOST_PYTHON = str(Path(c))
            return _CACHED_HOST_PYTHON
    return resolve_console_python(sys.executable)


def _is_truthy_env(val: Optional[str]) -> bool:
    return bool(val and val.strip().lower() in ("1", "true", "yes", "on"))


def _path_under_roots(cand: Path, roots: Sequence[Path]) -> bool:
    try:
        ck = _norm_dir_key(str(canonical_realpath(cand)))
    except Exception:
        ck = _norm_dir_key(str(cand))
    sep = "\\" if sys.platform == "win32" else "/"
    for r in roots:
        rk = _norm_dir_key(str(canonical_realpath(r)))
        if rk and (ck == rk or ck.startswith(rk + sep)):
            return True
    return False


def _is_dir_writable_or_creatable(target_dir: Path) -> bool:
    try:
        probe = target_dir
        while not probe.exists() and probe != probe.parent:
            probe = probe.parent
        return probe.exists() and os.access(str(probe), os.W_OK)
    except Exception:
        return False


def _env_runtime_dirs_for_python(py_exe: Path) -> Tuple[Optional[Path], List[Path], bool, bool]:
    """Return `(env_root, path_head_dirs, is_venv, is_conda)` for a resolved Python binary."""
    parent = py_exe.parent
    if parent.name.lower() in ("scripts", "bin"):
        env_root = parent.parent
        dirs: List[Path] = [parent, env_root]
    else:
        env_root = parent
        sub_bin = env_root / ("Scripts" if sys.platform == "win32" else "bin")
        dirs = [env_root, sub_bin]
    is_conda = (env_root / "conda-meta").is_dir()
    is_venv = (env_root / "pyvenv.cfg").is_file()
    if is_conda and sys.platform == "win32":
        dirs.extend([
            env_root / "Library" / "bin",
            env_root / "Library" / "usr" / "bin",
            env_root / "Library" / "mingw-w64" / "bin",
        ])
    return env_root, [d for d in dirs if d.is_dir()], is_venv, is_conda


def build_subprocess_env(
    cwd: Optional[Union[str, Path]] = None,
    *,
    guard: Optional[WorkspaceGuard] = None,
    python_exe: Optional[str] = None,
    enable_sandbox_hook: Optional[bool] = None,
) -> Dict[str, str]:
    """
    Build UTF-8 child process environment:
    - Strips MCP internal `.venv` and prioritizes explicit `python_exe` or target project `.venv`/`.conda`.
    - Injects `<root>/src` layout onto `PYTHONPATH` when present.
    - Does NOT inject `sys.addaudithook` `sitecustomize.py` in normal dev execution unless
      explicitly enabled (`enable_sandbox_hook=True` / `guard.strict_sandbox_hook` / `COSMOS_ENABLE_SANDBOX_HOOK=1`).
    - Automatically provides a writable `MPLCONFIGDIR` when unset and default `~/.matplotlib` is restricted.
    """
    eff_guard = guard or DEFAULT_GUARD
    env = os.environ.copy()
    _env_set_ci(env, "PYTHONIOENCODING", "utf-8")
    _env_set_ci(env, "PYTHONUTF8", "1")
    _env_pop_ci(env, "PYTHONHOME")
    sep = os.pathsep

    st_root = eff_guard.effective_state_root()
    chosen_py: Optional[Path] = None
    exclude_v: Optional[Path] = None
    if python_exe and Path(python_exe).is_file():
        chosen_py = Path(resolve_console_python(python_exe))
        env_r_tmp, _, _, _ = _env_runtime_dirs_for_python(chosen_py)
        exclude_v = env_r_tmp
    else:
        proj_venv = find_target_project_venv(
            cwd,
            workspace_roots=eff_guard.workspace_roots,
            state_root=st_root,
            product_root=eff_guard.product_root,
        )
        if proj_venv is not None:
            exclude_v, chosen_py = proj_venv
        else:
            chosen_py = Path(resolve_rich_python(cwd=cwd, guard=eff_guard))

    raw_host_path = _env_get_ci(env, "PATH", "")
    _env_pop_ci(env, "VIRTUAL_ENV")
    cleaned_path = get_stripped_host_path(
        raw_host_path,
        exclude_venv=exclude_v,
        state_root=st_root,
        product_root=eff_guard.product_root,
    )

    tc_dirs = [d for d in get_discovered_toolchain_dirs() if Path(d).is_dir()]
    env_root, head_dirs, is_venv, is_conda = _env_runtime_dirs_for_python(chosen_py)
    if env_root is not None:
        if is_venv:
            _env_set_ci(env, "VIRTUAL_ENV", str(env_root))
            _env_pop_ci(env, "CONDA_PREFIX")
            _env_pop_ci(env, "CONDA_DEFAULT_ENV")
        elif is_conda:
            _env_set_ci(env, "CONDA_PREFIX", str(env_root))
            _env_set_ci(env, "CONDA_DEFAULT_ENV", env_root.name)
    head_parts = [str(p) for p in head_dirs]
    merged_parts = head_parts + ([cleaned_path] if cleaned_path else []) + tc_dirs
    _env_set_ci(env, "PATH", sep.join(dict.fromkeys(p for p in sep.join(merged_parts).split(sep) if p)))

    # Inject `src` layout onto PYTHONPATH if target project uses `src/<pkg>/__init__.py`
    cand_roots: List[Path] = []
    if cwd and str(cwd).strip():
        cp = canonical_realpath(cwd)
        if cp.is_dir():
            cand_roots.append(cp)
    for ws in eff_guard.workspace_roots:
        if ws.is_dir() and ws not in cand_roots:
            cand_roots.append(ws)
    for root_p in cand_roots:
        src_d = root_p / "src"
        if src_d.is_dir():
            with contextlib.suppress(OSError):
                if any(sub.is_dir() and not sub.name.startswith(".") and (sub / "__init__.py").is_file() for sub in src_d.iterdir()):
                    cur_pp = [p for p in _env_get_ci(env, "PYTHONPATH", "").split(sep) if p]
                    cur_norm = {_norm_dir_key(p) for p in cur_pp}
                    for extra_d in (str(src_d), str(root_p)):
                        if _norm_dir_key(extra_d) not in cur_norm:
                            cur_pp.append(extra_d)
                    _env_set_ci(env, "PYTHONPATH", sep.join(cur_pp))
                    break

    if enable_sandbox_hook is not None:
        use_hook = bool(enable_sandbox_hook)
    else:
        use_hook = bool(
            getattr(eff_guard, "enable_sandbox_hook", False)
            or getattr(eff_guard, "strict_sandbox_hook", False)
            or _is_truthy_env(os.environ.get("COSMOS_ENABLE_SANDBOX_HOOK"))
            or _is_truthy_env(os.environ.get("LOCALPC_ENABLE_SANDBOX_HOOK"))
            or _is_truthy_env(os.environ.get("COSMOS_STRICT_SANDBOX_HOOK"))
        )
    restrict_l3 = bool(use_hook and eff_guard.restrict_to_workspace and eff_guard.workspace_roots)
    out_env = prepare_l3_sandbox_env(
        env,
        eff_guard.workspace_roots,
        st_root,
        restrict_to_workspace=restrict_l3,
        enable_audit_hook=restrict_l3,
    )

    if not (out_env.get("MPLCONFIGDIR") or "").strip():
        default_mpl = Path.home() / ".matplotlib"
        mpl_restricted = bool(
            (eff_guard.restrict_to_workspace and eff_guard.workspace_roots and not _path_under_roots(default_mpl, eff_guard.workspace_roots))
            or not _is_dir_writable_or_creatable(default_mpl)
        )
        if mpl_restricted:
            with contextlib.suppress(OSError):
                mpl_dir = st_root / "state" / "tmp_l3_sandbox" / "mplconfig"
                mpl_dir.mkdir(parents=True, exist_ok=True)
                out_env["MPLCONFIGDIR"] = str(mpl_dir)

    return out_env


# --- Bounded Stream & Tail Log Utilities ---

def collapse_carriage_returns(text: str) -> str:
    """Collapse in-line `\\r` progress refreshes (such as `tqdm`) to the latest frame per `\\n` line."""
    if not text:
        return ""
    norm = text.replace("\r\n", "\n")
    if "\r" not in norm:
        return norm
    collapsed: List[str] = []
    for raw_ln in norm.split("\n"):
        if "\r" not in raw_ln:
            collapsed.append(raw_ln)
        else:
            frames = [seg for seg in raw_ln.split("\r") if seg]
            collapsed.append(frames[-1] if frames else "")
    return "\n".join(collapsed)

def decode_process_bytes(raw_b: bytes) -> str:
    if not raw_b:
        return ""
    try:
        return raw_b.decode("utf-8")
    except UnicodeDecodeError:
        if sys.platform == "win32":
            parts: List[str] = []
            for ln in raw_b.splitlines(keepends=True):
                try:
                    parts.append(ln.decode("utf-8"))
                except UnicodeDecodeError:
                    try:
                        parts.append(ln.decode("gb18030"))
                    except UnicodeDecodeError:
                        parts.append(ln.decode("utf-8", errors="replace"))
            return "".join(parts)
        return raw_b.decode("utf-8", errors="replace")


def read_log_tail_bounded(
    log_path: Union[str, Path],
    tail_lines: int = 80,
    *,
    max_bytes: int = MAX_TAIL_READ_BYTES,
    guard: Optional[WorkspaceGuard] = None,
) -> Tuple[str, int]:
    """
    Stream the last `tail_lines` from `log_path` using bounded reverse binary seeks.
    Never calls `.read_text()` on multi-GB logs; reads at most `max_bytes` from EOF.
    Returns `(redacted_tail_text, bytes_inspected)`.
    """
    eff_guard = guard or DEFAULT_GUARD
    lp = Path(log_path)
    if not lp.is_file():
        return "", 0
    want_lines = max(1, min(500, int(tail_lines or 80)))
    cap_bytes = max(4096, int(max_bytes))
    try:
        with lp.open("rb") as fh:
            file_size = fh.seek(0, os.SEEK_END)
            if file_size <= 0:
                return "", 0
            min_pos = max(0, file_size - cap_bytes)
            pos = file_size
            chunks: List[bytes] = []
            nl_count = 0
            inspected = 0
            while pos > min_pos and nl_count <= want_lines:
                step = min(TAIL_CHUNK_BYTES, pos - min_pos)
                pos -= step
                fh.seek(pos, os.SEEK_SET)
                buf = fh.read(step)
                if not buf:
                    break
                chunks.append(buf)
                inspected += len(buf)
                nl_count += buf.count(b"\n")
            raw_tail = b"".join(reversed(chunks))
        decoded = collapse_carriage_returns(decode_process_bytes(raw_tail))
        lines = decoded.splitlines()
        selected = "\n".join(lines[-want_lines:])
        return eff_guard.redact_sensitive_output(selected[-20000:]), inspected
    except OSError:
        return "", 0


def _read_file_bounded_text(
    file_path: Optional[Union[str, Path]],
    cap: int = MAX_RAW_CAPTURE_BYTES,
    guard: Optional[WorkspaceGuard] = None,
) -> Tuple[str, bool]:
    """Read `file_path` up to `cap` bytes (head + tail bounded seek if >2 MiB) and redact sensitive secrets."""
    eff_guard = guard or DEFAULT_GUARD
    if not file_path:
        return "", False
    p = Path(file_path)
    if not p.is_file():
        return "", False
    try:
        with p.open("rb") as fh:
            size = fh.seek(0, os.SEEK_END)
            if size <= 0:
                return "", False
            fh.seek(0, os.SEEK_SET)
            if size <= cap:
                raw_b = fh.read(size)
                return eff_guard.redact_sensitive_output(decode_process_bytes(raw_b)), False
            usable = max(128, cap - 128)
            head_cap = max(64, int(usable * HEAD_KEEP_RATIO))
            tail_cap = max(64, usable - head_cap)
            head_part = fh.read(head_cap)
            fh.seek(max(head_cap, size - tail_cap), os.SEEK_SET)
            tail_part = fh.read(tail_cap)
            est_lines = max(1, (size - head_cap - tail_cap) // 64)
            msg = f"\n...[raw stream exceeded 2 MiB cap, omitted ~{est_lines} lines]...\n".encode("ascii")
            return eff_guard.redact_sensitive_output(decode_process_bytes(head_part + msg + tail_part)), True
    except OSError:
        return "", False


def _merge_stderr_into_bg_log(log_path: Optional[Union[str, Path]], err_path: Optional[Union[str, Path]]) -> None:
    if not log_path or not err_path:
        return
    lp = Path(log_path)
    ep = Path(err_path)
    if not ep.is_file():
        return
    try:
        err_sz = ep.stat().st_size
        if err_sz > 0:
            with ep.open("rb") as ef, lp.open("ab") as lf:
                lf.write(b"\n--- [STDERR] ---\n")
                rem = MAX_BG_LOG_BYTES
                while rem > 0:
                    ch = ef.read(min(65536, rem))
                    if not ch:
                        break
                    lf.write(ch)
                    rem -= len(ch)
        ep.unlink(missing_ok=True)
    except OSError:
        pass


_BG_SENTINEL_SCRIPT = r"""import base64, ctypes, json, os, signal, subprocess, sys, time
from pathlib import Path

def _win_tok(pid):
    from ctypes import wintypes
    class _FT(ctypes.Structure):
        _fields_ = [("lo", wintypes.DWORD), ("hi", wintypes.DWORD)]
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    h = k32.OpenProcess(0x1000, False, int(pid))
    if not h:
        return None
    try:
        c, e, k, u = _FT(), _FT(), _FT(), _FT()
        if k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)):
            t = (int(c.hi) << 32) | int(c.lo)
            return str(t) if t > 0 else None
    finally:
        k32.CloseHandle(h)
    return None

def _write_rc_once(rc_p, val):
    p = Path(rc_p)
    if p.is_file():
        return
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.parent / f".{p.name}.{os.getpid()}.tmp"
        tmp.write_text(str(int(val)), encoding="ascii")
        os.replace(str(tmp), str(p))
    except OSError:
        pass

def _merge_cleanup(cfg):
    ep_s = cfg.get("err_path") or ""
    lp_s = cfg.get("log_path") or ""
    ip_s = cfg.get("in_path") or ""
    if ep_s:
        ep = Path(ep_s)
        if ep.is_file():
            try:
                if ep.stat().st_size > 0 and lp_s:
                    with ep.open("rb") as ef, Path(lp_s).open("ab") as lf:
                        lf.write(b"\n--- [STDERR] ---\n")
                        while True:
                            ch = ef.read(65536)
                            if not ch:
                                break
                            lf.write(ch)
                ep.unlink(missing_ok=True)
            except OSError:
                pass
    if ip_s:
        try:
            Path(ip_s).unlink(missing_ok=True)
        except OSError:
            pass

def main():
    cfg = json.loads(base64.b64decode(sys.argv[1]).decode("utf-8"))
    pid = int(cfg["pid"])
    exp_tok = cfg.get("tok")
    ttl = max(1.0, float(cfg.get("ttl") or 14400.0))
    rc_path = cfg["rc_path"]
    if sys.platform == "win32":
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.SetErrorMode(0x8003)
        if exp_tok:
            cur_t = _win_tok(pid)
            if cur_t is not None and cur_t != str(exp_tok):
                _merge_cleanup(cfg)
                return
        h_proc = k32.OpenProcess(0x00101000, False, pid)
        if not h_proc:
            _merge_cleanup(cfg)
            _write_rc_once(rc_path, 0)
            return
        try:
            wait_ms = min(0x7FFFFFFF, int(ttl * 1000))
            res = k32.WaitForSingleObject(wintypes.HANDLE(h_proc), wintypes.DWORD(wait_ms))
            if res == 0x00000102:
                cur_t2 = _win_tok(pid) if exp_tok else None
                if not exp_tok or cur_t2 == str(exp_tok):
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], stdin=subprocess.DEVNULL, capture_output=True, creationflags=0x08000000)
                _merge_cleanup(cfg)
                _write_rc_once(rc_path, -9)
                return
            ec = wintypes.DWORD(0)
            if k32.GetExitCodeProcess(wintypes.HANDLE(h_proc), ctypes.byref(ec)):
                val = int(ec.value)
                if val >= 0x80000000:
                    val = val - 0x100000000
                _merge_cleanup(cfg)
                _write_rc_once(rc_path, val)
        finally:
            k32.CloseHandle(wintypes.HANDLE(h_proc))
    else:
        deadline = time.monotonic() + ttl
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except OSError:
                _merge_cleanup(cfg)
                _write_rc_once(rc_path, 0)
                return
            time.sleep(0.1)
        pgid = cfg.get("pgid")
        try:
            if pgid and int(pgid) > 1:
                os.killpg(int(pgid), signal.SIGKILL)
        except OSError:
            pass
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        _merge_cleanup(cfg)
        _write_rc_once(rc_path, -9)

if __name__ == "__main__":
    main()
"""


def _spawn_detached_bg_sentinel(
    *,
    pid: int,
    proc_create_token: Optional[str],
    ttl_seconds: float,
    rc_path: Path,
    log_path: Path,
    err_path: Optional[Path] = None,
    in_path: Optional[Path] = None,
    pgid: Optional[int] = None,
) -> None:
    """Spawn a windowless detached stdlib sentinel so `.rc` and TTL cleanup survive MCP parent death (`GAP-04`)."""
    if pid <= 0:
        return
    try:
        py_con = resolve_console_python(sys.executable)
        cfg_b64 = base64.b64encode(
            json.dumps(
                {
                    "pid": int(pid),
                    "tok": proc_create_token,
                    "ttl": float(ttl_seconds),
                    "rc_path": str(rc_path),
                    "log_path": str(log_path),
                    "err_path": str(err_path) if err_path else "",
                    "in_path": str(in_path) if in_path else "",
                    "pgid": pgid,
                },
                ensure_ascii=False,
            ).encode("utf-8")
        ).decode("ascii")
        clean_env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("PYTHONPATH", "COSMOS_L3_WORKSPACES", "LOCALPC_L3_WORKSPACE", "PYTHONSTARTUP")
        }
        clean_env["PYTHONDONTWRITEBYTECODE"] = "1"
        clean_env["PYTHONUTF8"] = "1"
        popen_kw: Dict[str, Any] = {}
        if sys.platform == "win32":
            popen_kw["creationflags"] = win32_no_window_flags(new_process_group=True, breakaway=True)
        else:
            popen_kw["start_new_session"] = True
        _popen_with_optional_breakaway(
            [py_con, "-B", "-c", _BG_SENTINEL_SCRIPT, cfg_b64],
            breakaway=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=clean_env,
            close_fds=True,
            **popen_kw,
        )
    except Exception as exc:
        LOGGER.warning("failed spawning bg sentinel for pid=%s: %s", pid, exc)


def truncate_stream_head_tail(text: str, budget_chars: int = PRUNE_KEEP_BUDGET, spill_path: Optional[Path] = None) -> str:
    eff_budget = max(200, int(budget_chars))
    if len(text) <= eff_budget:
        return text
    head_n = max(1, int(round(eff_budget * HEAD_KEEP_RATIO)))
    tail_n = max(1, eff_budget - head_n)
    if head_n + tail_n >= len(text):
        return text
    mid = text[head_n : len(text) - tail_n]
    omitted_lines = max(1, mid.count("\n"))
    if spill_path is not None:
        marker = f"\n...[omitted {omitted_lines} lines; full output at {spill_path}]...\n"
    else:
        marker = f"\n...[omitted {omitted_lines} lines]...\n"
    return text[:head_n] + marker + text[-tail_n:]


def _resolve_shell() -> Tuple[str, str]:
    if sys.platform == "win32":
        exe = shutil.which("pwsh.exe") or shutil.which("powershell.exe") or "powershell.exe"
        return exe, "pwsh"
    exe = shutil.which("bash") or shutil.which("sh") or "/bin/sh"
    return exe, "posix"


def _encode_pwsh_script(script_body: str) -> str:
    wrapped = (
        "$ProgressPreference = 'SilentlyContinue'\n"
        "[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)\n"
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n"
        "$OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n"
        f"{script_body}"
    )
    return base64.b64encode(wrapped.encode("utf-16le")).decode("ascii")


def _normalize_pwsh_command(command: str) -> str:
    stripped = command.lstrip()
    if stripped.startswith('"'):
        m = re.match(r'^"([^"\r\n]+)"(?=\s|$)(.*)$', stripped, flags=re.DOTALL)
        if m:
            inner = m.group(1).strip()
            rest = m.group(2).lstrip()
            if ("\\" in inner or "/" in inner or inner.lower().endswith((".exe", ".cmd", ".bat", ".ps1"))) and not rest.startswith("|"):
                return "& " + stripped
    return command


_PY_DASH_C_RE = re.compile(
    r'^\s*(?:&\s*)?(?:"([^"]*python[^"]*)"|\'([^\']*python[^\']*)\'|(python(?:\d*(?:\.\d+)*)?(?:\.exe)?))'
    r'(?:\s+-X\s+utf8|\s+-u)*\s+-c\s+"([\s\S]+)"\s*$',
    re.IGNORECASE,
)


def _read_rc_file_int(rc_path: Optional[Union[str, Path]]) -> Optional[int]:
    if not rc_path:
        return None
    p = Path(rc_path)
    if not p.is_file():
        return None
    try:
        txt = p.read_text(encoding="utf-8-sig", errors="replace").strip()
        return int(txt) if txt else None
    except Exception:
        return None


def append_audit_log(audit_path: Union[str, Path], entry: Dict[str, Any]) -> None:
    try:
        p = Path(audit_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {"ts": datetime.now(timezone.utc).isoformat(), **entry}
        line = json.dumps(payload, ensure_ascii=False) + "\n"
        with _AUDIT_LOCK:
            if p.exists():
                with contextlib.suppress(OSError):
                    if p.stat().st_size > MAX_AUDIT_LOG_BYTES:
                        bak = p.with_suffix(p.suffix + ".1")
                        p.replace(bak)
            with p.open("a", encoding="utf-8") as fh:
                fh.write(line)
    except Exception as exc:
        LOGGER.warning("audit log write failed: %s", exc)


class ProcessManager:
    """
    Stateful L0 process and background job manager backed by `<state_root>/state/bg_jobs.json`.
    Does NOT register indiscriminate `atexit` job killers so detached `bg_command` jobs
    survive daemon restarts and recover cleanly in subsequent `ProcessManager` instances.
    """

    def __init__(
        self,
        guard: Optional[WorkspaceGuard] = None,
        *,
        state_root: Optional[Union[str, Path]] = None,
        sync_wait_cap_sec: float = DEFAULT_SYNC_WAIT_CAP_SEC,
        max_slots: int = MAX_SLOTS,
        max_proc_mem_mb: int = DEFAULT_MAX_PROC_MEM_MB,
        enable_sandbox_hook: Optional[bool] = None,
        sleep_inhibitor: Optional[SleepInhibitor] = None,
    ) -> None:
        suppress_win32_crash_dialogs()
        self.guard: WorkspaceGuard = guard or DEFAULT_GUARD
        self._explicit_state_root: Optional[Path] = canonical_realpath(state_root) if state_root else None
        self.default_sync_wait_cap_sec: float = max(MIN_SYNC_WAIT_CAP_SEC, min(MAX_SYNC_WAIT_CAP_SEC, float(sync_wait_cap_sec)))
        self.default_max_proc_mem_mb: int = max(0, int(max_proc_mem_mb))
        self.enable_sandbox_hook: Optional[bool] = enable_sandbox_hook
        self._slots = asyncio.Semaphore(max(1, int(max_slots)))
        self._bg_lock = threading.RLock()
        self._fg_lock = threading.Lock()
        self._live_bg_handles: Dict[str, Dict[str, Any]] = {}
        self._active_fg_procs: Dict[int, Tuple[subprocess.Popen[bytes], OwnedJobHandle, Optional[str], str]] = {}
        self._persisted_jobs: Dict[str, Dict[str, Any]] = {}
        self._bg_sleep_inhibitor: SleepInhibitor = sleep_inhibitor or SleepInhibitor()
        self._load_persisted_ledger()

    @property
    def state_root(self) -> Path:
        if self._explicit_state_root is not None:
            return self._explicit_state_root
        return self.guard.effective_state_root()

    @property
    def bg_jobs_index_path(self) -> Path:
        return self.state_root / "state" / "bg_jobs.json"

    @property
    def legacy_bg_jobs_index_path(self) -> Path:
        return self.state_root / "bg_jobs.json"

    @property
    def bg_logs_dir(self) -> Path:
        return self.state_root / "logs" / "bg_jobs"

    @property
    def bg_sleep_inhibitor_active(self) -> bool:
        return bool(self._bg_sleep_inhibitor.status().get("enabled"))

    def _sync_bg_sleep_inhibitor(self) -> None:
        with self._bg_lock:
            has_running = any(
                isinstance(r, dict) and r.get("exit_code") is None
                for r in self._persisted_jobs.values()
            )
        cur_enabled = bool(self._bg_sleep_inhibitor.status().get("enabled"))
        if has_running and not cur_enabled:
            self._bg_sleep_inhibitor.enable()
        elif not has_running and cur_enabled:
            self._bg_sleep_inhibitor.disable()

    def _load_persisted_ledger(self) -> None:
        for cand_p in (self.legacy_bg_jobs_index_path, self.bg_jobs_index_path):
            if not cand_p.is_file():
                continue
            try:
                doc = json.loads(cand_p.read_text(encoding="utf-8"))
                jobs = doc.get("jobs") if isinstance(doc, dict) else None
                if isinstance(jobs, dict):
                    with self._bg_lock:
                        for jid, rec in jobs.items():
                            if isinstance(rec, dict) and jid:
                                self._persisted_jobs[str(jid)] = dict(rec)
            except Exception as exc:
                LOGGER.warning("failed reading bg_jobs ledger (%s): %s", cand_p, exc)

    def _save_persisted_ledger(self) -> None:
        with self._bg_lock:
            idx_p = self.bg_jobs_index_path
            idx_p.parent.mkdir(parents=True, exist_ok=True)
            if len(self._persisted_jobs) > MAX_BG_HISTORY_ENTRIES:
                finished = [
                    jid
                    for jid, r in self._persisted_jobs.items()
                    if r.get("exit_code") is not None or r.get("ended_at") is not None
                ]
                finished.sort(key=lambda k: float(self._persisted_jobs[k].get("ended_at") or self._persisted_jobs[k].get("started_at") or 0.0))
                excess = len(self._persisted_jobs) - MAX_BG_HISTORY_ENTRIES
                for old_k in finished[: max(0, excess)]:
                    self._persisted_jobs.pop(old_k, None)
            payload = {"version": 1, "updated_at": time.time(), "jobs": self._persisted_jobs}
            tmp_p = idx_p.parent / f".bg_jobs.{os.getpid()}.{secrets.token_hex(3)}.tmp"
            tmp_p.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            os.replace(str(tmp_p), str(idx_p))
        self._sync_bg_sleep_inhibitor()

    def _read_combined_job_tail(self, rec: Dict[str, Any], tail_lines: int) -> Tuple[str, int]:
        tail_txt, tail_bytes = read_log_tail_bounded(rec.get("log_path", ""), tail_lines=tail_lines, guard=self.guard)
        err_lp = str(rec.get("err_log_path") or "").strip()
        if err_lp and Path(err_lp).is_file():
            err_txt, err_b = read_log_tail_bounded(err_lp, tail_lines=max(10, tail_lines // 2), guard=self.guard)
            if err_txt:
                tail_txt = f"{tail_txt}\n--- [STDERR] ---\n{err_txt}".strip() if tail_txt else err_txt
                tail_bytes += err_b
        return tail_txt, tail_bytes

    def _resolve_job_id(self, raw_job_id: str) -> Optional[str]:
        clean = (raw_job_id or "").strip()
        if not clean:
            return None
        if clean.lower() != "latest":
            return clean
        with self._bg_lock:
            self._load_persisted_ledger()
            if not self._persisted_jobs:
                return None
            best_jid: Optional[str] = None
            best_key = (-1.0, -1)
            for idx, (jid_k, rec_v) in enumerate(self._persisted_jobs.items()):
                st_val = float(rec_v.get("started_at") or 0.0) if isinstance(rec_v, dict) else 0.0
                cand_key = (st_val, idx)
                if cand_key >= best_key:
                    best_key = cand_key
                    best_jid = str(jid_k)
            return best_jid

    def summarize_jobs_for_status(
        self,
        tail_lines: int = 15,
        max_recent: int = 5,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Return `(active_jobs, recent_jobs)` with status, elapsed time, `log_path`, and folded tail lines."""
        self._reap_and_count_running()
        with self._bg_lock:
            records = [dict(r) for r in self._persisted_jobs.values() if isinstance(r, dict) and r.get("job_id")]

        active_raw = [r for r in records if r.get("exit_code") is None]
        finished_raw = [r for r in records if r.get("exit_code") is not None]
        active_raw.sort(key=lambda r: float(r.get("started_at") or 0.0), reverse=True)
        finished_raw.sort(key=lambda r: float(r.get("ended_at") or r.get("started_at") or 0.0), reverse=True)

        eff_tail = max(1, min(100, int(tail_lines or 15)))

        def _fmt_job(rec: Dict[str, Any]) -> Dict[str, Any]:
            running = rec.get("exit_code") is None
            end_ref = float(rec.get("ended_at") or time.time())
            started_ref = float(rec.get("started_at") or end_ref)
            elapsed = round(max(0.0, end_ref - started_ref), 2)
            tail_txt, _ = self._read_combined_job_tail(rec, tail_lines=eff_tail)
            lp_s = str(rec.get("log_path") or "")
            if running:
                st_label = "running"
            elif rec.get("timed_out"):
                st_label = "timed_out"
            elif rec.get("exit_code") == 0:
                st_label = "completed"
            else:
                st_label = "finished"
            return {
                "job_id": str(rec.get("job_id") or ""),
                "pid": rec.get("pid"),
                "running": running,
                "status": st_label,
                "exit_code": rec.get("exit_code"),
                "timed_out": bool(rec.get("timed_out")),
                "elapsed_sec": elapsed,
                "duration_ms": round(elapsed * 1000),
                "cwd": str(rec.get("cwd") or ""),
                "command": str(rec.get("command") or ""),
                "log_path": lp_s,
                "log_file": lp_s,
                "log_tail": tail_txt,
                "tail": tail_txt,
                "max_ttl_seconds": rec.get("max_ttl_seconds"),
            }

        active_out = [_fmt_job(r) for r in active_raw]
        recent_out = [_fmt_job(r) for r in finished_raw[: max(1, int(max_recent or 5))]]
        return active_out, recent_out

    def _refresh_job_record(self, jid: str) -> Optional[Dict[str, Any]]:
        with self._bg_lock:
            if jid not in self._persisted_jobs:
                self._load_persisted_ledger()
            rec = self._persisted_jobs.get(jid)
            if rec is None:
                return None

            dirty = False
            live = self._live_bg_handles.get(jid)
            now = time.time()

            # Check `.rc` file first
            rc_val = _read_rc_file_int(rec.get("rc_path"))
            if rc_val is not None and rec.get("exit_code") is None:
                rec["exit_code"] = rc_val
                rec["ended_at"] = rec.get("ended_at") or now
                dirty = True

            if live is not None and live.get("proc") is not None:
                poll_rc = live["proc"].poll()
                if poll_rc is not None and rec.get("exit_code") is None:
                    rec["exit_code"] = int(poll_rc)
                    rec["ended_at"] = rec.get("ended_at") or now
                    dirty = True

            pid = int(rec.get("pid") or 0)
            tok = rec.get("proc_create_token")
            if rec.get("exit_code") is None:
                alive, reused = verify_pid_alive(pid, tok)
                if reused:
                    rec["pid_reused"] = True
                    rec["exit_code"] = rc_val if rc_val is not None else -1
                    rec["ended_at"] = rec.get("ended_at") or now
                    dirty = True
                elif not alive:
                    rc_after = _read_rc_file_int(rec.get("rc_path"))
                    if rc_after is None:
                        for _ in range(4):
                            time.sleep(0.05)
                            rc_after = _read_rc_file_int(rec.get("rc_path"))
                            if rc_after is not None:
                                break
                            if live is not None and live.get("proc") is not None:
                                p_rc = live["proc"].poll()
                                if p_rc is not None:
                                    rc_after = int(p_rc)
                                    break
                    rec["exit_code"] = rc_after if rc_after is not None else -1
                    rec["ended_at"] = rec.get("ended_at") or now
                    dirty = True
                else:
                    ttl = float(rec.get("max_ttl_seconds") or DEFAULT_BG_MAX_TTL_SECONDS)
                    started_at = float(rec.get("started_at") or now)
                    if now - started_at > ttl:
                        jh = live.get("job_handle") if live else None
                        _LAST_KILL_DIAGNOSTICS.value = None
                        killed_ttl, reused_ttl = terminate_verified_pid_tree(pid, tok, job_handle=jh, pgid=rec.get("pgid"))
                        diag_ttl = get_last_kill_diagnostics()
                        rec["timed_out"] = True
                        if killed_ttl or reused_ttl or not diag_ttl.get("still_running"):
                            if reused_ttl:
                                rec["pid_reused"] = True
                            rec["exit_code"] = -9 if killed_ttl else (_read_rc_file_int(rec.get("rc_path")) or -1)
                            rec["ended_at"] = now
                        dirty = True

            if rec.get("exit_code") is not None:
                _merge_stderr_into_bg_log(rec.get("log_path"), rec.get("err_log_path"))
                in_p_s = str(rec.get("in_path") or "").strip()
                if in_p_s:
                    with contextlib.suppress(OSError):
                        Path(in_p_s).unlink(missing_ok=True)

            if dirty:
                self._save_persisted_ledger()
            return dict(rec)

    def _reap_and_count_running(self) -> int:
        with self._bg_lock:
            self._load_persisted_ledger()
            running = 0
            for jid in list(self._persisted_jobs.keys()):
                rec = self._refresh_job_record(jid)
                if rec and rec.get("exit_code") is None:
                    running += 1
        self._sync_bg_sleep_inhibitor()
        return running

    def active_session_pids(self, prefix_filter: str = "") -> Set[int]:
        """Return verified-alive foreground and background session PIDs for L3 window/focus fencing (`S-02`)."""
        pf = (prefix_filter or "").strip()
        pids: Set[int] = set()
        with self._fg_lock:
            fg_snap = list(self._active_fg_procs.items())
        for pid, (proc, _jh, tok, pfx) in fg_snap:
            if pf and pfx and pfx != pf:
                continue
            if proc.poll() is None:
                alive, reused = verify_pid_alive(pid, tok)
                if alive and not reused:
                    pids.add(int(pid))

        self._reap_and_count_running()
        with self._bg_lock:
            bg_snap = list(self._persisted_jobs.values())
        for rec in bg_snap:
            if not isinstance(rec, dict) or rec.get("exit_code") is not None:
                continue
            rec_pfx = str(rec.get("tool_prefix") or rec.get("prefix") or "").strip()
            if pf and rec_pfx and rec_pfx != pf:
                continue
            pid_b = int(rec.get("pid") or 0)
            if pid_b > 0:
                alive, reused = verify_pid_alive(pid_b, rec.get("proc_create_token"))
                if alive and not reused:
                    pids.add(pid_b)
        return pids

    def resolve_effective_cwd(self, cwd: Optional[Union[str, Path]]) -> str:
        raw_c = str(cwd or "").strip()
        if raw_c:
            return str(canonical_realpath(raw_c))
        if self.guard.workspace_roots:
            return str(self.guard.workspace_roots[0])
        return str(canonical_realpath(Path.home()))

    def _finalize_output(self, stdout_txt: str, stderr_txt: str, cwd: str, raw_clipped: bool) -> Dict[str, Any]:
        if len(stdout_txt) + len(stderr_txt) <= MAX_OUTPUT_CHARS and not raw_clipped:
            return {"stdout": stdout_txt, "stderr": stderr_txt, "truncated": False}
        spill_dir = self.state_root / "logs" / "spill"
        spill_path: Optional[Path] = None
        combined = f"{stdout_txt}\n--- [STDERR] ---\n{stderr_txt}" if (stdout_txt and stderr_txt) else (stdout_txt or stderr_txt)
        total_lines = max(1, len(combined.splitlines()))
        with contextlib.suppress(OSError):
            spill_dir.mkdir(parents=True, exist_ok=True)
            spill_path = spill_dir / f"cmd_{int(time.time() * 1000)}_{secrets.token_hex(3)}.log"
            with _SPILL_LOCK:
                existing = sorted(spill_dir.glob("cmd_*.log"), key=lambda p: p.stat().st_mtime if p.exists() else 0.0)
                for old_p in existing[: max(0, len(existing) - MAX_SPILL_FILES + 1)]:
                    with contextlib.suppress(OSError):
                        old_p.unlink()
                spill_path.write_bytes(combined.encode("utf-8", errors="replace")[:MAX_RAW_CAPTURE_BYTES])
        out_p = truncate_stream_head_tail(stdout_txt, PRUNE_KEEP_BUDGET // 2 if stderr_txt else PRUNE_KEEP_BUDGET, spill_path=spill_path)
        err_p = truncate_stream_head_tail(stderr_txt, PRUNE_KEEP_BUDGET // 2 if stdout_txt else PRUNE_KEEP_BUDGET, spill_path=spill_path)
        res: Dict[str, Any] = {"stdout": out_p, "stderr": err_p, "truncated": True, "total_lines": total_lines}
        if spill_path is not None:
            res["spill_path"] = str(spill_path)
        return res

    async def _run_foreground(
        self,
        argv: List[str],
        cwd: str,
        timeout: float,
        *,
        source: Optional[bytes] = None,
        sync_wait_cap_sec: Optional[float] = None,
        promote_to_bg: bool = True,
        breakaway: bool = False,
        display_cmd: str = "",
        python_exe: Optional[str] = None,
        max_mem_mb: Optional[int] = None,
        enable_sandbox_hook: Optional[bool] = None,
    ) -> Dict[str, Any]:
        started = time.monotonic()
        started_wall = time.time()
        eff_cap = (
            self.default_sync_wait_cap_sec
            if sync_wait_cap_sec is None
            else max(MIN_SYNC_WAIT_CAP_SEC, min(MAX_SYNC_WAIT_CAP_SEC, float(sync_wait_cap_sec)))
        )
        wait_window = min(eff_cap, float(timeout)) if (promote_to_bg and timeout > 0) else float(timeout)
        eff_hook = self.enable_sandbox_hook if enable_sandbox_hook is None else enable_sandbox_hook
        eff_mem_mb = self.default_max_proc_mem_mb if max_mem_mb is None else max(0, int(max_mem_mb))

        # Build env BEFORE spawning — Fail-Closed if explicit L3 sandbox hook init fails
        child_env = build_subprocess_env(
            cwd=cwd,
            guard=self.guard,
            python_exe=python_exe,
            enable_sandbox_hook=eff_hook,
        )

        popen_kwargs: Dict[str, Any] = {}
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = win32_no_window_flags(
                new_process_group=True,
                breakaway=bool(breakaway),
            )
        else:
            popen_kwargs["start_new_session"] = True

        acquired = False
        proc: Optional[subprocess.Popen[bytes]] = None
        proc_create_tok: Optional[str] = None
        job = OwnedJobHandle(None)
        promoted = False
        bg_dir = self.bg_logs_dir
        bg_dir.mkdir(parents=True, exist_ok=True)
        jid = f"bg_{int(time.time())}_{secrets.token_hex(3)}"
        out_path = bg_dir / f"{jid}.log"
        err_path = bg_dir / f"{jid}.err.log"
        rc_path = bg_dir / f"{jid}.rc"
        in_path: Optional[Path] = (bg_dir / f".{jid}.in") if source is not None else None

        def _cleanup_fg_temp_files() -> None:
            for tp in (in_path, out_path, err_path, rc_path):
                if tp is not None:
                    with contextlib.suppress(OSError):
                        tp.unlink(missing_ok=True)

        async def _stop_and_collect() -> None:
            if proc is not None:
                for stream_cand in (proc.stdin, proc.stdout, proc.stderr):
                    cancel_win32_handle_io(stream_cand)
                await asyncio.to_thread(
                    terminate_verified_pid_tree,
                    proc.pid,
                    proc_create_tok,
                    job,
                    None,
                )

        try:
            try:
                await asyncio.wait_for(self._slots.acquire(), timeout=max(1.0, float(timeout)))
                acquired = True
            except asyncio.TimeoutError:
                return {
                    "ok": False,
                    "timed_out": True,
                    "timeout_seconds": timeout,
                    "timeout_phase": "queue",
                    "exit_code": -9,
                    "duration_ms": round((time.monotonic() - started) * 1000),
                    "stdout": "",
                    "stderr": f"[TIMEOUT] Command waited >{timeout}s for an execution slot.",
                    "truncated": False,
                }

            # GAP-04: Redirect stdin/stdout/stderr directly to OS disk file handles and close
            # parent descriptors immediately after Popen so child has ZERO pipe to MCP parent.
            if in_path is not None and source is not None:
                in_path.write_bytes(source)

            def _spawn_with_disk_files() -> subprocess.Popen[bytes]:
                in_fh = in_path.open("rb") if in_path is not None else None
                out_fh = out_path.open("wb")
                err_fh = err_path.open("wb")
                try:
                    return _popen_with_optional_breakaway(
                        argv,
                        breakaway=bool(breakaway),
                        bufsize=0,
                        cwd=cwd,
                        stdin=in_fh if in_fh is not None else subprocess.DEVNULL,
                        stdout=out_fh,
                        stderr=err_fh,
                        env=child_env,
                        **popen_kwargs,
                    )
                finally:
                    for fh_c in (in_fh, out_fh, err_fh):
                        if fh_c is not None:
                            with contextlib.suppress(OSError):
                                fh_c.close()

            proc = await asyncio.to_thread(_spawn_with_disk_files)
            proc_create_tok = get_process_create_token(proc.pid)
            job = OwnedJobHandle(assign_win32_job_kill_on_close(proc.pid, max_mem_mb=eff_mem_mb))
            with self._fg_lock:
                self._active_fg_procs[proc.pid] = (proc, job, proc_create_tok, self.guard.tool_prefix)

            loop = asyncio.get_running_loop()
            exit_future: asyncio.Future[int] = loop.create_future()

            def _wait_proc() -> None:
                assert proc is not None
                rc_v = proc.wait()
                with self._fg_lock:
                    self._active_fg_procs.pop(proc.pid, None)
                with contextlib.suppress(RuntimeError):
                    loop.call_soon_threadsafe(lambda: (not exit_future.done()) and exit_future.set_result(rc_v))

            t_wait = threading.Thread(target=_wait_proc, daemon=True)
            t_wait.start()

            try:
                await asyncio.wait_for(asyncio.shield(exit_future), timeout=wait_window)
            except asyncio.TimeoutError:
                if proc.poll() is not None:
                    with contextlib.suppress(asyncio.TimeoutError):
                        await asyncio.wait_for(asyncio.shield(exit_future), timeout=0.6)
                elif promote_to_bg and float(timeout) > wait_window:
                    running_n = self._reap_and_count_running()
                    if running_n >= MAX_BG_JOBS:
                        await _stop_and_collect()
                        out_s, out_c = _read_file_bounded_text(out_path, guard=self.guard)
                        err_s, err_c = _read_file_bounded_text(err_path, guard=self.guard)
                        msg = f"[TIMEOUT] Command exceeded {wait_window}s and MAX_BG_JOBS ({MAX_BG_JOBS}) is full."
                        out_meta = self._finalize_output(out_s, (err_s + "\n" + msg).strip(), cwd, bool(out_c or err_c))
                        return {
                            "ok": False,
                            "timed_out": True,
                            "bg_slots_full": True,
                            "exit_code": -9,
                            "duration_ms": round((time.monotonic() - started) * 1000),
                            **out_meta,
                        }

                    promoted = True
                    partial_out, out_clip = _read_file_bounded_text(out_path, guard=self.guard)
                    partial_err, err_clip = _read_file_bounded_text(err_path, guard=self.guard)
                    detached_job = job.detach(survive_daemon_exit=True)
                    with self._fg_lock:
                        self._active_fg_procs.pop(proc.pid, None)
                    pgid_val = None
                    if sys.platform != "win32":
                        with contextlib.suppress(Exception):
                            pgid_val = int(os.getpgid(proc.pid))

                    max_ttl = max(DEFAULT_BG_MAX_TTL_SECONDS, int(timeout))
                    rem_ttl = max(5.0, float(max_ttl) - (time.time() - started_wall))
                    polled_rc = proc.poll()
                    if polled_rc is not None:
                        detached_job.close()
                        with contextlib.suppress(OSError):
                            rc_path.write_text(str(int(polled_rc)), encoding="ascii")
                        _merge_stderr_into_bg_log(out_path, err_path)
                    else:
                        _spawn_detached_bg_sentinel(
                            pid=proc.pid,
                            proc_create_token=proc_create_tok,
                            ttl_seconds=rem_ttl,
                            rc_path=rc_path,
                            log_path=out_path,
                            err_path=err_path,
                            in_path=in_path,
                            pgid=pgid_val,
                        )

                    with self._bg_lock:
                        rec_entry: Dict[str, Any] = {
                            "job_id": jid,
                            "pid": proc.pid,
                            "pgid": pgid_val,
                            "proc_create_token": proc_create_tok,
                            "tool_prefix": self.guard.tool_prefix,
                            "prefix": self.guard.tool_prefix,
                            "command": (display_cmd or " ".join(str(x) for x in argv[:4]))[:400],
                            "cwd": cwd,
                            "log_path": str(out_path),
                            "err_log_path": str(err_path),
                            "in_path": str(in_path) if in_path is not None else "",
                            "rc_path": str(rc_path),
                            "started_at": started_wall,
                            "ended_at": time.time() if polled_rc is not None else None,
                            "exit_code": polled_rc,
                            "max_ttl_seconds": max_ttl,
                            "promoted_from_sync": True,
                            "timed_out": False,
                        }
                        self._persisted_jobs[jid] = rec_entry
                        self._live_bg_handles[jid] = {
                            "proc": proc,
                            "job_handle": detached_job if polled_rc is None else None,
                            "waiter_thread": t_wait,
                        }
                        self._save_persisted_ledger()

                    if polled_rc is None:
                        def _finalize_local_promoted(p_ref: subprocess.Popen[bytes], j_id: str, rc_p: Path, lp: Path, ep: Path, ip: Optional[Path]) -> None:
                            rc_done = p_ref.wait()
                            _merge_stderr_into_bg_log(lp, ep)
                            if ip is not None:
                                with contextlib.suppress(OSError):
                                    ip.unlink(missing_ok=True)
                            if not rc_p.is_file():
                                with contextlib.suppress(OSError):
                                    tmp_rc = rc_p.parent / f".{rc_p.name}.{os.getpid()}.tmp"
                                    tmp_rc.write_text(str(int(rc_done)), encoding="ascii")
                                    os.replace(str(tmp_rc), str(rc_p))
                            with self._bg_lock:
                                rec_p = self._persisted_jobs.get(j_id)
                                if rec_p is not None and rec_p.get("exit_code") is None:
                                    rec_p["exit_code"] = int(rc_done)
                                    rec_p["ended_at"] = time.time()
                                    self._save_persisted_ledger()

                        threading.Thread(
                            target=_finalize_local_promoted,
                            args=(proc, jid, rc_path, out_path, err_path, in_path),
                            daemon=True,
                        ).start()

                    out_meta = self._finalize_output(partial_out, partial_err, cwd, bool(out_clip or err_clip))
                    elapsed_s = round(time.monotonic() - started, 2)
                    return {
                        "ok": True,
                        "promoted_to_background": True,
                        "status": "running_in_background",
                        "job_id": jid,
                        "pid": proc.pid,
                        "elapsed_sec": elapsed_s,
                        "duration_ms": round(elapsed_s * 1000),
                        "max_ttl_seconds": max_ttl,
                        "log_path": str(out_path),
                        **out_meta,
                    }
                else:
                    await _stop_and_collect()
                    out_t, out_tc = _read_file_bounded_text(out_path, guard=self.guard)
                    err_t, err_tc = _read_file_bounded_text(err_path, guard=self.guard)
                    hint = f"[TIMEOUT] Execution exceeded {timeout}s limit."
                    out_meta = self._finalize_output(out_t, (err_t + "\n" + hint).strip(), cwd, bool(out_tc or err_tc))
                    return {
                        "ok": False,
                        "timed_out": True,
                        "timeout_seconds": timeout,
                        "timeout_phase": "execution",
                        "exit_code": -9,
                        "duration_ms": round((time.monotonic() - started) * 1000),
                        **out_meta,
                    }

            out_f, out_fc = _read_file_bounded_text(out_path, guard=self.guard)
            err_f, err_fc = _read_file_bounded_text(err_path, guard=self.guard)
            out_meta = self._finalize_output(out_f, err_f, cwd, bool(out_fc or err_fc))
            return {
                "ok": proc.returncode == 0,
                "exit_code": proc.returncode,
                "duration_ms": round((time.monotonic() - started) * 1000),
                **out_meta,
            }
        except asyncio.CancelledError:
            await _stop_and_collect()
            raise
        except Exception:
            await _stop_and_collect()
            raise
        finally:
            if proc is not None and not promoted:
                with self._fg_lock:
                    self._active_fg_procs.pop(proc.pid, None)
            if not promoted:
                _cleanup_fg_temp_files()
            try:
                job.close()
            finally:
                if acquired:
                    self._slots.release()

    async def execute_python_stdin(
        self,
        code: str,
        cwd: str = "",
        timeout: float = 90.0,
        *,
        python_exe: Optional[str] = None,
        python_path: str = "",
        venv: str = "",
        conda_env: str = "",
        policy: Optional[Any] = None,
        max_mem_mb: Optional[int] = None,
        enable_sandbox_hook: Optional[bool] = None,
        sync_wait_cap_sec: Optional[float] = None,
        promote_to_bg: bool = True,
    ) -> Dict[str, Any]:
        if self.guard.tier in ("L1", "L2"):
            msg = f"[GUARD TIER POLICY]: Tier {self.guard.tier} prohibits subprocess execution (`execute_python_stdin`)."
            return {"ok": False, "blocked_by_guardrail": True, "exit_code": -403, "duration_ms": 0, "stdout": "", "stderr": msg, "error": msg, "truncated": False}
        eff_cwd = self.resolve_effective_cwd(cwd)
        cwd_err = self.guard.check_path_access(eff_cwd, mode="read", tool_name="run_python")
        if cwd_err:
            return {"ok": False, "blocked_by_guardrail": True, "exit_code": -403, "duration_ms": 0, "stdout": "", "stderr": cwd_err, "error": cwd_err, "truncated": False}
        blocked = self.guard.check_python_code_safety(code, cwd=eff_cwd)
        if blocked:
            return {"ok": False, "blocked_by_guardrail": True, "exit_code": -403, "duration_ms": 0, "stdout": "", "stderr": blocked, "error": blocked, "truncated": False}
        if not Path(eff_cwd).is_dir():
            err_nf = f"cwd is not an existing directory: {eff_cwd}"
            return {"ok": False, "exit_code": -1, "duration_ms": 0, "stdout": "", "stderr": err_nf, "error": err_nf, "truncated": False}

        py_bin: Optional[str] = None
        run_argv: Optional[List[str]] = None
        try:
            if python_exe and python_exe.strip():
                if Path(python_exe).is_file():
                    py_bin = resolve_console_python(python_exe)
                else:
                    py_bin = resolve_python_interpreter(
                        python_path=python_exe,
                        cwd=eff_cwd,
                        policy=policy or getattr(self, "policy", None),
                        guard=self.guard,
                    )
            else:
                py_bin = resolve_python_interpreter(
                    python_path=python_path,
                    cwd=eff_cwd,
                    venv=venv,
                    conda_env=conda_env,
                    policy=policy or getattr(self, "policy", None),
                    guard=self.guard,
                )
        except FileNotFoundError as exc:
            clean_cenv = (conda_env or "").strip()
            conda_cli = _find_conda_executable() if (clean_cenv and not (python_path or venv or "").strip()) else None
            if conda_cli and _SAFE_CONDA_ENV_NAME_RE.fullmatch(clean_cenv):
                run_argv = [conda_cli, "run", "--no-capture-output", "-n", clean_cenv, "python", "-B", "-X", "utf8", "-u", "-"]
            else:
                err_s = str(exc)
                return {"ok": False, "exit_code": -1, "duration_ms": 0, "stdout": "", "stderr": err_s, "error": err_s, "truncated": False}

        if run_argv is None:
            assert py_bin is not None
            run_argv = [py_bin, "-B", "-X", "utf8", "-u", "-"]

        preview = "python -u - <<EOF: " + " ".join(ln.strip() for ln in code.splitlines()[:2] if ln.strip())
        res = await self._run_foreground(
            run_argv,
            eff_cwd,
            timeout,
            source=code.encode("utf-8"),
            sync_wait_cap_sec=sync_wait_cap_sec,
            promote_to_bg=promote_to_bg,
            display_cmd=preview,
            python_exe=py_bin,
            max_mem_mb=max_mem_mb,
            enable_sandbox_hook=enable_sandbox_hook,
        )
        res["python_exe"] = py_bin or f"conda:{(conda_env or '').strip()}"
        return res

    async def execute(
        self,
        command: str,
        cwd: str = "",
        timeout: float = 90.0,
        *,
        raise_on_error: bool = False,
        sync_wait_cap_sec: Optional[float] = None,
        promote_to_bg: Optional[bool] = None,
        max_mem_mb: Optional[int] = None,
        enable_sandbox_hook: Optional[bool] = None,
    ) -> Dict[str, Any]:
        if self.guard.tier in ("L1", "L2"):
            msg = f"[GUARD TIER POLICY]: Tier {self.guard.tier} prohibits shell command execution (`execute`)."
            return {"ok": False, "blocked_by_guardrail": True, "exit_code": -403, "duration_ms": 0, "stdout": "", "stderr": msg, "error": msg, "truncated": False}
        eff_cwd = self.resolve_effective_cwd(cwd)
        cwd_err = self.guard.check_path_access(eff_cwd, mode="read", tool_name="run_command")
        if cwd_err:
            return {"ok": False, "blocked_by_guardrail": True, "exit_code": -403, "duration_ms": 0, "stdout": "", "stderr": cwd_err, "error": cwd_err, "truncated": False}
        blocked = self.guard.check_destructive_command(command, cwd=eff_cwd)
        if blocked:
            return {"ok": False, "blocked_by_guardrail": True, "exit_code": -403, "duration_ms": 0, "stdout": "", "stderr": blocked, "error": blocked, "truncated": False}
        if not Path(eff_cwd).is_dir():
            err_nf = f"cwd is not an existing directory: {eff_cwd}"
            return {"ok": False, "exit_code": -1, "duration_ms": 0, "stdout": "", "stderr": err_nf, "error": err_nf, "truncated": False}

        shell_exe, shell_kind = _resolve_shell()
        if shell_kind == "pwsh":
            argv = [shell_exe, "-NoProfile", "-NonInteractive", "-EncodedCommand", _encode_pwsh_script(_normalize_pwsh_command(command))]
        else:
            argv = [shell_exe, "-c", command]

        eff_promote = (not raise_on_error) if promote_to_bg is None else bool(promote_to_bg)
        result = await self._run_foreground(
            argv,
            eff_cwd,
            timeout,
            sync_wait_cap_sec=sync_wait_cap_sec,
            promote_to_bg=eff_promote,
            display_cmd=command,
            max_mem_mb=max_mem_mb,
            enable_sandbox_hook=enable_sandbox_hook,
        )
        if result.get("promoted_to_background"):
            return result
        if result.get("timed_out"):
            if raise_on_error:
                raise TimeoutError(f"Command timed out after {timeout}s")
            return result

        rc = int(result.get("exit_code") or 0)
        duration_ms = int(result.get("duration_ms") or 0)
        err_out = str(result.get("stderr") or "")

        if shell_kind == "pwsh" and rc != 0 and duration_ms < 4000 and '\\"' in command:
            m = _PY_DASH_C_RE.match(command)
            if m and any(k in f"{result.get('stdout', '')}\n{err_out}" for k in ("SyntaxError", "ParserError", "Unexpected token")):
                unescaped = m.group(4).replace('\\"', '"').replace("\\\\", "\\")
                rescued = await self.execute_python_stdin(
                    unescaped,
                    eff_cwd,
                    timeout,
                    sync_wait_cap_sec=sync_wait_cap_sec,
                    max_mem_mb=max_mem_mb,
                    enable_sandbox_hook=enable_sandbox_hook,
                )
                if rescued.get("ok"):
                    rescued["auto_rescued_pwsh_quotes"] = True
                    return rescued

        if raise_on_error and rc != 0:
            raise ValueError(f"Command failed with exit {rc}; stdout={result.get('stdout')}; stderr={err_out}")
        return result

    def manage_bg_command(
        self,
        action: str = "list",
        command: str = "",
        cwd: str = "",
        job_id: str = "",
        tail_lines: int = 80,
        wait_seconds: float = 0.0,
        max_ttl_seconds: int = DEFAULT_BG_MAX_TTL_SECONDS,
        python_path: str = "",
        *,
        venv: str = "",
        conda_env: str = "",
        policy: Optional[Any] = None,
        enable_sandbox_hook: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Manage persistent background jobs (`start` | `status` | `wait` | `list` | `kill`).
        Persists metadata in `<state_root>/state/bg_jobs.json`, survives daemon restarts, verifies
        `(pid, proc_create_token)` before termination, and tails logs with `\\r` folding.
        """
        act = (action or "list").strip().lower()
        if act == "list" and command.strip() and not job_id.strip():
            act = "start"

        if act == "start":
            if self.guard.tier in ("L1", "L2"):
                msg = f"[GUARD TIER POLICY]: Tier {self.guard.tier} prohibits starting background commands."
                return {"ok": False, "blocked_by_guardrail": True, "error": msg}
            cmd_clean = (command or "").strip()
            if not cmd_clean:
                return {"ok": False, "error": "command is required when action='start'"}
            eff_cwd = self.resolve_effective_cwd(cwd)
            cwd_err = self.guard.check_path_access(eff_cwd, mode="read", tool_name="bg_command")
            if cwd_err:
                return {"ok": False, "blocked_by_guardrail": True, "error": cwd_err}
            blocked = self.guard.check_destructive_command(cmd_clean, cwd=eff_cwd)
            if blocked:
                return {"ok": False, "blocked_by_guardrail": True, "error": blocked}
            if not Path(eff_cwd).is_dir():
                return {"ok": False, "error": f"cwd is not an existing directory: {eff_cwd}"}

            eff_pol = policy or getattr(self, "policy", None)
            py_override: Optional[str] = None
            conda_run_fallback_env: str = ""
            if (python_path or venv or conda_env or "").strip() or _extract_policy_python_path(eff_pol, self.guard):
                try:
                    py_override = resolve_python_interpreter(
                        python_path=python_path,
                        cwd=eff_cwd,
                        venv=venv,
                        conda_env=conda_env,
                        policy=eff_pol,
                        guard=self.guard,
                    )
                except FileNotFoundError as exc:
                    clean_cenv = (conda_env or "").strip()
                    conda_cli = _find_conda_executable() if (clean_cenv and not (python_path or venv or "").strip()) else None
                    if conda_cli and _SAFE_CONDA_ENV_NAME_RE.fullmatch(clean_cenv):
                        conda_run_fallback_env = clean_cenv
                    else:
                        return {"ok": False, "action": "start", "error": str(exc)}

            eff_hook = self.enable_sandbox_hook if enable_sandbox_hook is None else enable_sandbox_hook
            child_env = build_subprocess_env(
                cwd=eff_cwd,
                guard=self.guard,
                python_exe=py_override,
                enable_sandbox_hook=eff_hook,
            )
            running_n = self._reap_and_count_running()
            if running_n >= MAX_BG_JOBS:
                return {"ok": False, "error": f"Maximum concurrent background jobs ({MAX_BG_JOBS}) reached."}

            bg_dir = self.bg_logs_dir
            bg_dir.mkdir(parents=True, exist_ok=True)
            jid = f"bg_{int(time.time())}_{secrets.token_hex(3)}"
            log_path = bg_dir / f"{jid}.log"
            rc_path = bg_dir / f"{jid}.rc"

            cmd_exec = _normalize_bg_pythonw_command(cmd_clean)
            shell_exe, shell_kind = _resolve_shell()
            if shell_kind == "pwsh":
                eff_cmd = _normalize_pwsh_command(cmd_exec)
                env_boot_ps = ""
                if py_override and Path(py_override).is_file():
                    py_ov_p = Path(py_override)
                    _, ov_dirs, ov_is_venv, ov_is_conda = _env_runtime_dirs_for_python(py_ov_p)
                    ov_prefix_str = os.pathsep.join(str(d) for d in ov_dirs)
                    py_ov_esc = str(py_ov_p).replace("'", "''")
                    env_boot_lines: List[str] = []
                    if ov_prefix_str:
                        ov_p_esc = ov_prefix_str.replace("'", "''")
                        env_boot_lines.append(f"$env:PATH = '{ov_p_esc}' + [System.IO.Path]::PathSeparator + $env:PATH")
                    if ov_is_venv:
                        v_esc = str(py_ov_p.parent.parent).replace("'", "''")
                        env_boot_lines.append(f"$env:VIRTUAL_ENV = '{v_esc}'")
                    elif ov_is_conda:
                        c_root = py_ov_p.parent if py_ov_p.parent.name.lower() != "scripts" else py_ov_p.parent.parent
                        c_esc = str(c_root).replace("'", "''")
                        env_boot_lines.append(f"$env:CONDA_PREFIX = '{c_esc}'")
                    env_boot_lines.append(f"function global:python {{ & '{py_ov_esc}' @args }}")
                    env_boot_lines.append(f"function global:python3 {{ & '{py_ov_esc}' @args }}")
                    env_boot_ps = "\n".join(env_boot_lines) + "\n"
                elif conda_run_fallback_env:
                    c_cli = (_find_conda_executable() or "conda").replace("'", "''")
                    eff_cmd = re.sub(
                        r"^\s*(?:&\s*)?python(?:3|\.exe)?\b",
                        f"& '{c_cli}' run --no-capture-output -n {conda_run_fallback_env} python",
                        eff_cmd,
                        count=1,
                        flags=re.IGNORECASE,
                    )
                wrapper_ps = (
                    f"{env_boot_ps}"
                    f"try {{\n{eff_cmd}\n$ec = if ($null -ne $LASTEXITCODE) {{ [int]$LASTEXITCODE }} else {{ 0 }}\n}} "
                    f"catch {{\nWrite-Error $_\n$ec = 1\n}}\n"
                    f"[System.IO.File]::WriteAllText({json.dumps(str(rc_path))}, \"$ec\", [System.Text.Encoding]::ASCII)"
                )
                argv = [shell_exe, "-NoProfile", "-NonInteractive", "-EncodedCommand", _encode_pwsh_script(wrapper_ps)]
            else:
                eff_sh_cmd = cmd_exec
                if conda_run_fallback_env:
                    c_cli_sh = _find_conda_executable() or "conda"
                    eff_sh_cmd = re.sub(
                        r"^\s*python(?:3)?\b",
                        f"{json.dumps(c_cli_sh)} run --no-capture-output -n {conda_run_fallback_env} python",
                        eff_sh_cmd,
                        count=1,
                    )
                quoted_rc = json.dumps(str(rc_path))
                wrapper_sh = f"( {eff_sh_cmd} ); _ec=$?; printf '%s' \"$_ec\" > {quoted_rc}; exit $_ec"
                argv = [shell_exe, "-c", wrapper_sh]

            popen_kwargs: Dict[str, Any] = {}
            if sys.platform == "win32":
                popen_kwargs["creationflags"] = win32_no_window_flags(new_process_group=True, breakaway=True)
            else:
                popen_kwargs["start_new_session"] = True

            log_fh = log_path.open("w", encoding="utf-8", buffering=1)
            try:
                proc = _popen_with_optional_breakaway(
                    argv,
                    breakaway=True,
                    cwd=eff_cwd,
                    stdin=subprocess.DEVNULL,
                    stdout=log_fh,
                    stderr=subprocess.STDOUT,
                    env=child_env,
                    **popen_kwargs,
                )
            finally:
                log_fh.close()

            proc_tok = get_process_create_token(proc.pid)
            bg_job = OwnedJobHandle(assign_win32_bg_job_object(proc.pid))
            pgid_val = None
            if sys.platform != "win32":
                with contextlib.suppress(Exception):
                    pgid_val = int(os.getpgid(proc.pid))

            ttl_clamped = max(10, min(int(max_ttl_seconds or DEFAULT_BG_MAX_TTL_SECONDS), 604800))
            _spawn_detached_bg_sentinel(
                pid=proc.pid,
                proc_create_token=proc_tok,
                ttl_seconds=float(ttl_clamped),
                rc_path=rc_path,
                log_path=log_path,
                pgid=pgid_val,
            )
            rec_new: Dict[str, Any] = {
                "job_id": jid,
                "pid": proc.pid,
                "pgid": pgid_val,
                "proc_create_token": proc_tok,
                "tool_prefix": self.guard.tool_prefix,
                "prefix": self.guard.tool_prefix,
                "command": cmd_clean[:400],
                "cwd": eff_cwd,
                "log_path": str(log_path),
                "in_path": "",
                "rc_path": str(rc_path),
                "started_at": time.time(),
                "ended_at": None,
                "exit_code": None,
                "max_ttl_seconds": ttl_clamped,
                "promoted_from_sync": False,
                "timed_out": False,
            }
            if py_override:
                rec_new["python_exe"] = py_override
            with self._bg_lock:
                self._persisted_jobs[jid] = rec_new
                self._live_bg_handles[jid] = {"proc": proc, "job_handle": bg_job}
                self._save_persisted_ledger()

            if float(wait_seconds or 0.0) > 0.0:
                wait_res = self.manage_bg_command(action="wait", job_id=jid, tail_lines=tail_lines, wait_seconds=wait_seconds)
                merged_start: Dict[str, Any] = {
                    **wait_res,
                    "action": "start",
                    "job_id": jid,
                    "pid": proc.pid,
                    "proc_create_token": proc_tok,
                    "cwd": eff_cwd,
                    "log_path": str(log_path),
                    "max_ttl_seconds": ttl_clamped,
                }
                if py_override:
                    merged_start["python_exe"] = py_override
                return merged_start

            start_out: Dict[str, Any] = {
                "ok": True,
                "action": "start",
                "job_id": jid,
                "pid": proc.pid,
                "proc_create_token": proc_tok,
                "cwd": eff_cwd,
                "log_path": str(log_path),
                "max_ttl_seconds": ttl_clamped,
                "running": True,
            }
            if py_override:
                start_out["python_exe"] = py_override
            return start_out

        if act == "list":
            self._reap_and_count_running()
            with self._bg_lock:
                ordered = sorted(
                    self._persisted_jobs.values(),
                    key=lambda r: float(r.get("started_at") or 0.0),
                    reverse=True,
                )
            items = []
            for r in ordered[:32]:
                running = r.get("exit_code") is None
                end_ref = float(r.get("ended_at") or time.time())
                elapsed = round(max(0.0, end_ref - float(r.get("started_at") or end_ref)), 2)
                items.append({
                    "job_id": r.get("job_id"),
                    "pid": r.get("pid"),
                    "running": running,
                    "exit_code": r.get("exit_code"),
                    "timed_out": bool(r.get("timed_out")),
                    "elapsed_sec": elapsed,
                    "cwd": r.get("cwd"),
                    "command": r.get("command"),
                    "log_path": str(r.get("log_path") or ""),
                    "max_ttl_seconds": r.get("max_ttl_seconds"),
                })
            return {"ok": True, "action": "list", "count": len(items), "jobs": items}

        if act in ("status", "wait", "kill"):
            raw_jid = (job_id or "").strip()
            if not raw_jid:
                return {"ok": False, "action": act, "error": f"job_id is required when action='{act}'"}
            jid_resolved = self._resolve_job_id(raw_jid)
            if not jid_resolved:
                return {"ok": False, "action": act, "job_id": raw_jid, "error": "No background jobs found for job_id='latest'."}
            jid = jid_resolved
            rec = self._refresh_job_record(jid)
            if rec is None:
                return {"ok": False, "action": act, "error": f"Unknown job_id: '{jid}'"}

            if act == "kill":
                pid = int(rec.get("pid") or 0)
                tok = rec.get("proc_create_token")
                was_exited = rec.get("exit_code") is not None
                killed = False
                pid_reused = bool(rec.get("pid_reused", False))
                still_running = False
                still_running_pids: List[int] = []
                kill_errors: List[str] = []
                if not was_exited and pid > 0:
                    live_h = self._live_bg_handles.get(jid)
                    jh = live_h.get("job_handle") if live_h else None
                    _LAST_KILL_DIAGNOSTICS.value = None
                    killed, pid_reused = terminate_verified_pid_tree(pid, tok, job_handle=jh, pgid=rec.get("pgid"))
                    diag = get_last_kill_diagnostics()
                    kill_errors = list(diag.get("errors") or [])
                    if not killed and not pid_reused:
                        still_running_pids = list(diag.get("still_running") or [])
                        if still_running_pids:
                            still_running = True
                        else:
                            alive_after, reused_after = verify_pid_alive(pid, tok)
                            if reused_after:
                                pid_reused = True
                            elif alive_after:
                                still_running = True
                                still_running_pids = [pid]
                    if not still_running:
                        with self._bg_lock:
                            stored = self._persisted_jobs.get(jid)
                            if stored is not None:
                                stored["ended_at"] = stored.get("ended_at") or time.time()
                                if pid_reused:
                                    stored["pid_reused"] = True
                                    stored["exit_code"] = _read_rc_file_int(stored.get("rc_path"))
                                    if stored["exit_code"] is None:
                                        stored["exit_code"] = -1
                                else:
                                    stored["exit_code"] = -9 if killed else (_read_rc_file_int(stored.get("rc_path")) or -1)
                                self._save_persisted_ledger()
                refreshed = self._refresh_job_record(jid) or rec
                tail_txt, tail_bytes = self._read_combined_job_tail(refreshed, tail_lines=tail_lines)
                kill_resp: Dict[str, Any] = {
                    "ok": not still_running,
                    "action": "kill",
                    "job_id": jid,
                    "pid": pid,
                    "killed": killed,
                    "already_exited": (was_exited or (not killed)) and (not still_running),
                    "pid_reused": pid_reused,
                    "running": still_running,
                    "still_running": still_running,
                    "still_running_pids": still_running_pids,
                    "errors": kill_errors,
                    "exit_code": None if still_running else refreshed.get("exit_code"),
                    "log_path": str(refreshed.get("log_path") or rec.get("log_path") or ""),
                    "log_tail": tail_txt,
                    "tail_bytes_read": tail_bytes,
                }
                if still_running:
                    kill_resp["error"] = "; ".join(kill_errors) if kill_errors else f"Failed to terminate process {pid}; still running."
                return kill_resp

            waited_s = 0.0
            eff_wait = float(wait_seconds if wait_seconds else (15.0 if act == "wait" else 0.0))
            if act == "wait" or eff_wait > 0.0:
                cap_w = max(0.05, min(eff_wait, MAX_SYNC_WAIT_CAP_SEC))
                t0 = time.monotonic()
                deadline = t0 + cap_w
                while time.monotonic() < deadline:
                    rec = self._refresh_job_record(jid) or rec
                    if rec.get("exit_code") is not None:
                        break
                    time.sleep(min(0.08, max(0.01, deadline - time.monotonic())))
                waited_s = round(time.monotonic() - t0, 3)

            rec = self._refresh_job_record(jid) or rec
            running = rec.get("exit_code") is None
            end_ref = float(rec.get("ended_at") or time.time())
            elapsed = round(max(0.0, end_ref - float(rec.get("started_at") or end_ref)), 2)
            tail_txt, tail_bytes = self._read_combined_job_tail(rec, tail_lines=tail_lines)
            out_resp: Dict[str, Any] = {
                "ok": True,
                "action": act,
                "job_id": jid,
                "pid": rec.get("pid"),
                "running": running,
                "status": "running" if running else ("completed" if rec.get("exit_code") == 0 else "finished"),
                "exit_code": rec.get("exit_code"),
                "timed_out": bool(rec.get("timed_out")),
                "pid_reused": bool(rec.get("pid_reused")),
                "elapsed_sec": elapsed,
                "cwd": rec.get("cwd"),
                "command": rec.get("command"),
                "log_path": str(rec.get("log_path") or ""),
                "max_ttl_seconds": rec.get("max_ttl_seconds"),
                "log_tail": tail_txt,
                "tail_bytes_read": tail_bytes,
            }
            if act == "wait" or eff_wait > 0.0:
                out_resp["waited_seconds"] = waited_s
                out_resp["timed_out_waiting"] = running
            return out_resp

        return {"ok": False, "action": act, "error": f"Unsupported action '{act}'. Choose from: start, status, wait, list, kill"}

    def kill_all_active_commands(
        self,
        reason: str = "revoke",
        include_persisted_bg: bool = True,
        prefix_filter: str = "",
    ) -> Dict[str, Any]:
        """Explicit session cleanup; preserves detached `_persisted_jobs` across graceful shutdown/restart."""
        if isinstance(include_persisted_bg, str) and not prefix_filter:
            prefix_filter = include_persisted_bg
            include_persisted_bg = True
        clean_pfx = (prefix_filter or "").strip()
        fg_killed: List[int] = []
        fg_still_running: List[int] = []
        kill_errors: List[str] = []
        with self._fg_lock:
            fg_items = list(self._active_fg_procs.items())
        for pid, (proc, jh, tok, _pfx) in fg_items:
            if clean_pfx and _pfx and _pfx != clean_pfx:
                continue
            was_running = proc.poll() is None
            for stream_c in (proc.stdin, proc.stdout, proc.stderr):
                cancel_win32_handle_io(stream_c)
            _LAST_KILL_DIAGNOSTICS.value = None
            terminated, reused = terminate_verified_pid_tree(pid, tok, job_handle=jh)
            diag = get_last_kill_diagnostics()
            is_still_running = bool(
                was_running
                and not terminated
                and not reused
                and (diag.get("still_running") or proc.poll() is None)
            )
            if is_still_running:
                fg_still_running.append(pid)
                kill_errors.extend(list(diag.get("errors") or []))
            else:
                if was_running and terminated:
                    fg_killed.append(pid)
                with self._fg_lock:
                    self._active_fg_procs.pop(pid, None)

        norm_reason = (reason or "").strip().lower()
        graceful_reasons = {
            "shutdown",
            "lifespan_shutdown",
            "session_shutdown",
            "graceful_shutdown",
            "graceful_restart",
            "atexit",
        }
        should_kill_bg = bool(include_persisted_bg) and norm_reason not in graceful_reasons

        bg_killed: List[int] = []
        bg_still_running: List[int] = []
        if should_kill_bg:
            with self._bg_lock:
                self._load_persisted_ledger()
                jids = list(self._persisted_jobs.keys())
            for jid in jids:
                with self._bg_lock:
                    raw_rec = dict(self._persisted_jobs.get(jid) or {})
                    live_h = self._live_bg_handles.get(jid)
                if not raw_rec:
                    continue
                rec_pfx = str(raw_rec.get("tool_prefix") or raw_rec.get("prefix") or "").strip()
                if clean_pfx and rec_pfx and rec_pfx != clean_pfx:
                    continue
                pid_cand = int(raw_rec.get("pid") or 0)
                tok_cand = raw_rec.get("proc_create_token")
                jh_cand = live_h.get("job_handle") if live_h else None
                rec = self._refresh_job_record(jid)
                if rec and rec.get("exit_code") is None:
                    res_k = self.manage_bg_command(action="kill", job_id=jid)
                    if res_k.get("killed") and pid_cand > 0:
                        bg_killed.append(pid_cand)
                    elif res_k.get("still_running") and pid_cand > 0:
                        if pid_cand not in bg_still_running:
                            bg_still_running.append(pid_cand)
                        errs_k = res_k.get("errors") or ([res_k.get("error")] if res_k.get("error") else [])
                        kill_errors.extend(str(e) for e in errs_k if e)
                elif sys.platform == "win32" and (pid_cand > 0 or (jh_cand is not None and jh_cand.handle)):
                    _LAST_KILL_DIAGNOSTICS.value = None
                    killed_extra, reused_extra = _kill_process_tree_win32(
                        pid_cand,
                        expected_create_token=tok_cand,
                        job_handle=jh_cand,
                        wait_timeout_sec=1.0,
                    )
                    diag_extra = get_last_kill_diagnostics()
                    if killed_extra and pid_cand > 0 and pid_cand not in bg_killed:
                        bg_killed.append(pid_cand)
                    elif not reused_extra and diag_extra.get("still_running"):
                        for sp in diag_extra.get("still_running") or []:
                            if int(sp) > 0 and int(sp) not in bg_still_running:
                                bg_still_running.append(int(sp))
                        kill_errors.extend(list(diag_extra.get("errors") or []))
        still_running = list(dict.fromkeys(fg_still_running + bg_still_running))
        self._sync_bg_sleep_inhibitor()
        self.guard.record_security_event(
            "active_commands_killed",
            f"fg={fg_killed},bg={bg_killed},still_running={still_running},include_persisted_bg={should_kill_bg}",
            reason,
        )
        return {
            "ok": not still_running,
            "reason": reason,
            "persisted_bg_killed": should_kill_bg,
            "fg_killed": fg_killed,
            "bg_killed": bg_killed,
            "still_running": still_running,
            "errors": kill_errors,
        }

    def run_batch_probe(
        self,
        project_path: Union[str, Path],
        python_code: str,
        timeout_seconds: int = 20,
    ) -> Dict[str, Any]:
        """Execute a deterministic read-only Python batch probe inside an audit-hooked child process."""
        path_err = self.guard.check_path_access(project_path, mode="read", tool_name="batch_probe")
        if path_err:
            return {"ok": False, "blocked_by_guardrail": True, "error": path_err}

        proj = canonical_realpath(project_path)
        if not proj.exists():
            return {"ok": False, "error": f"Project path not found: {proj}"}

        pipelock_err = self.guard.check_command_pipelock(python_code, cwd=str(proj), is_python_code=True, tool_name="batch_probe")
        if pipelock_err:
            return {"ok": False, "blocked_by_guardrail": True, "error": pipelock_err}

        mut_hit = _detect_ast_mutation_in_probe(python_code)
        if mut_hit:
            self.guard.record_security_event("batch_probe_mutation_blocked", python_code[:200], mut_hit)
            return {
                "ok": False,
                "blocked_by_guardrail": True,
                "error": f"[GUARD BATCH PROBE]: batch_probe is strictly read-only ({mut_hit} prohibited).",
            }

        sensitive_env_re = re.compile(r"(?i)(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL|COOKIE|SESSION)")
        env = {k: v for k, v in os.environ.items() if not sensitive_env_re.search(k)}
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        py_bin = resolve_rich_python(cwd=proj, guard=self.guard)
        t0 = time.monotonic()
        popen_kwargs: Dict[str, Any] = {}
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = win32_no_window_flags(new_process_group=True)
        else:
            popen_kwargs["start_new_session"] = True

        proc = subprocess.Popen(
            [py_bin, "-B", "-X", "utf8", "-c", BATCH_PROBE_RUNNER_SCRIPT],
            cwd=str(proj),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            **popen_kwargs,
        )
        job = OwnedJobHandle(assign_win32_job_kill_on_close(proc.pid))
        try:
            probe_input = json.dumps({
                "proj": str(proj),
                "code": python_code,
                "ws_roots": [str(w) for w in self.guard.workspace_roots],
                "restrict_ws": self.guard.restrict_to_workspace,
                "read_blocked": list(self.guard._read_blocked_prefixes()),
                "state_root": str(self.state_root),
            })
            out, err = proc.communicate(input=probe_input, timeout=max(3, min(60, int(timeout_seconds))))
            dur = round((time.monotonic() - t0) * 1000)
            lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
            if lines:
                parsed = json.loads(lines[-1])
                parsed["project_path"] = str(proj)
                parsed["duration_ms"] = dur
                if isinstance(parsed.get("stdout"), str):
                    parsed["stdout"] = self.guard.redact_sensitive_output(parsed["stdout"])
                if "result" in parsed:
                    redacted_res = self.guard.redact_sensitive_output(json.dumps(parsed["result"], ensure_ascii=False))
                    with contextlib.suppress(Exception):
                        parsed["result"] = json.loads(redacted_res)
                return parsed
            return {
                "ok": False,
                "project_path": str(proj),
                "duration_ms": dur,
                "error": self.guard.redact_sensitive_output((err or "Empty output from batch_probe")[:1000]),
            }
        except subprocess.TimeoutExpired:
            terminate_verified_pid_tree(proc.pid, None, job_handle=job)
            return {
                "ok": False,
                "project_path": str(proj),
                "timed_out": True,
                "duration_ms": round((time.monotonic() - t0) * 1000),
                "error": f"batch_probe timed out after {timeout_seconds}s.",
            }
        finally:
            job.close()


def _detect_ast_mutation_in_probe(code: str) -> Optional[str]:
    from cosmos_mcp.core.guard import strip_python_comments_tokenize

    cleaned = strip_python_comments_tokenize(code)
    try:
        tree = ast.parse(cleaned)
    except SyntaxError:
        return None
    blocked_mods = {
        "subprocess", "_posixsubprocess", "shutil", "socket",
        "ctypes", "_ctypes", "_winapi", "msvcrt", "winreg",
        "importlib", "builtins",
    }
    blocked_names = {"__import__", "__builtins__", "builtins"}
    blocked_attrs = {
        "write_text", "write_bytes", "unlink", "rmdir", "removedirs",
        "rmtree", "remove", "rename", "replace", "mkdir", "makedirs",
        "system", "popen", "Popen", "startfile",
        "import_module", "dlopen", "dlsym", "WinDLL", "CDLL", "OleDLL", "PyDLL", "LoadLibrary",
        "__builtins__", "__subclasses__", "f_builtins", "f_globals",
    }
    for nd in ast.walk(tree):
        if isinstance(nd, ast.Import):
            for al in nd.names:
                if al.name.split(".", 1)[0] in blocked_mods:
                    return f"import {al.name}"
        elif isinstance(nd, ast.ImportFrom):
            mod_root = (nd.module or "").split(".", 1)[0]
            if mod_root in blocked_mods:
                return f"from {nd.module} import ..."
            for al in nd.names:
                if al.name in blocked_mods or al.name in blocked_names or al.name == "import_module":
                    return f"from {nd.module or '.'} import {al.name}"
        elif isinstance(nd, ast.Name) and nd.id in blocked_names:
            return f"{nd.id}"
        elif isinstance(nd, ast.Attribute) and nd.attr in ("__builtins__", "__subclasses__", "f_builtins", "f_globals"):
            return f".{nd.attr}"
        elif isinstance(nd, ast.Call):
            fn = nd.func
            if isinstance(fn, ast.Name) and fn.id in ("__import__", "builtins"):
                return f"{fn.id}()"
            if isinstance(fn, ast.Attribute) and fn.attr in blocked_attrs:
                if isinstance(fn.value, ast.Name) and fn.value.id in ("list", "set", "dict"):
                    continue
                return f".{fn.attr}()"
            if isinstance(fn, ast.Name) and fn.id == "open" and len(nd.args) >= 2:
                m_arg = nd.args[1]
                if isinstance(m_arg, ast.Constant) and isinstance(m_arg.value, str) and any(c in m_arg.value for c in ("w", "a", "x", "+")):
                    return f"open(..., {m_arg.value!r})"
    return None


# --- Default Module-Level Convenience Instance & Functions ---

DEFAULT_PROCESS_MANAGER = ProcessManager(guard=DEFAULT_GUARD)


async def execute(
    command: str,
    cwd: str = "",
    timeout: float = 90.0,
    raise_on_error: bool = False,
    sync_wait_cap_sec: Optional[float] = None,
    *,
    max_mem_mb: Optional[int] = None,
    enable_sandbox_hook: Optional[bool] = None,
) -> Dict[str, Any]:
    return await DEFAULT_PROCESS_MANAGER.execute(
        command,
        cwd=cwd,
        timeout=timeout,
        raise_on_error=raise_on_error,
        sync_wait_cap_sec=sync_wait_cap_sec,
        max_mem_mb=max_mem_mb,
        enable_sandbox_hook=enable_sandbox_hook,
    )


async def execute_python_stdin(
    code: str,
    cwd: str = "",
    timeout: float = 90.0,
    python_exe: Optional[str] = None,
    sync_wait_cap_sec: Optional[float] = None,
    *,
    python_path: str = "",
    venv: str = "",
    conda_env: str = "",
    policy: Optional[Any] = None,
    max_mem_mb: Optional[int] = None,
    enable_sandbox_hook: Optional[bool] = None,
) -> Dict[str, Any]:
    return await DEFAULT_PROCESS_MANAGER.execute_python_stdin(
        code,
        cwd=cwd,
        timeout=timeout,
        python_exe=python_exe,
        python_path=python_path,
        venv=venv,
        conda_env=conda_env,
        policy=policy,
        max_mem_mb=max_mem_mb,
        enable_sandbox_hook=enable_sandbox_hook,
        sync_wait_cap_sec=sync_wait_cap_sec,
    )


def manage_bg_command(
    action: str = "list",
    command: str = "",
    cwd: str = "",
    job_id: str = "",
    tail_lines: int = 80,
    wait_seconds: float = 0.0,
    max_ttl_seconds: int = DEFAULT_BG_MAX_TTL_SECONDS,
    python_path: str = "",
    *,
    venv: str = "",
    conda_env: str = "",
    policy: Optional[Any] = None,
    enable_sandbox_hook: Optional[bool] = None,
) -> Dict[str, Any]:
    return DEFAULT_PROCESS_MANAGER.manage_bg_command(
        action=action,
        command=command,
        cwd=cwd,
        job_id=job_id,
        tail_lines=tail_lines,
        wait_seconds=wait_seconds,
        max_ttl_seconds=max_ttl_seconds,
        python_path=python_path,
        venv=venv,
        conda_env=conda_env,
        policy=policy,
        enable_sandbox_hook=enable_sandbox_hook,
    )


def run_batch_probe(project_path: Union[str, Path], python_code: str, timeout_seconds: int = 20) -> Dict[str, Any]:
    return DEFAULT_PROCESS_MANAGER.run_batch_probe(project_path, python_code, timeout_seconds=timeout_seconds)


def active_session_pids(prefix_filter: str = "") -> Set[int]:
    return DEFAULT_PROCESS_MANAGER.active_session_pids(prefix_filter=prefix_filter)


def kill_all_active_commands(
    reason: str = "revoke",
    include_persisted_bg: bool = True,
    prefix_filter: str = "",
) -> Dict[str, Any]:
    return DEFAULT_PROCESS_MANAGER.kill_all_active_commands(
        reason=reason,
        include_persisted_bg=include_persisted_bg,
        prefix_filter=prefix_filter,
    )
