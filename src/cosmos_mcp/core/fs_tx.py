#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Filesystem transaction, cross-process locking, externalized undo history, and trash primitives.

Pure Python >=3.9 standard-library implementation:
1. Cross-process & thread-reentrant file locks (`msvcrt.locking` on Windows, `fcntl.flock` on POSIX)
   and deadlock-free lexicographical `MultiFileLock`.
2. Externalized snapshots & operation ledgers under `<state_root>/history/<workspace_hash>` so user
   Git repositories remain completely clean (`git status --porcelain` has zero `.undo_history/`).
3. Dual-quota LRU snapshot pruning (per-file count + directory total count & byte cap) that never
   evicts recoverable trash items.
4. Recoverable trash vault (`<state_root>/trash` when same-volume, or a target-volume system temp /
   hidden state folder outside any Git repository when cross-volume) plus `undo_last_edit` supporting
   edits, file/dir creations, moves, renames, trashes, and `path=""` latest-operation rollback.
"""
from __future__ import annotations

import contextlib
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from cosmos_mcp.core.path_heal import is_link_or_junction

SNAPSHOT_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".venv",
        "venv",
        "node_modules",
        "build",
        "dist",
        "target",
        "__pycache__",
        ".git",
        ".undo_history",
        ".cosmos_mcp_state",
        ".cosmos_mcp_trash",
    }
)

MAX_UNDO_PER_FILE: int = 30
MAX_UNDO_SNAPSHOT_COUNT: int = 200
MAX_UNDO_SNAPSHOT_TOTAL_BYTES: int = 100 * 1024 * 1024  # 100 MiB (snapshots only; never touches trash)

OFFICE_DOC_EXTS: frozenset[str] = frozenset(
    {
        ".xlsx",
        ".xls",
        ".xlsm",
        ".xlsb",
        ".docx",
        ".doc",
        ".docm",
        ".pptx",
        ".ppt",
        ".csv",
        ".odt",
        ".ods",
        ".odp",
        ".rtf",
    }
)

_UNDO_LOCK = threading.RLock()
_FILE_LOCKS_GUARD = threading.Lock()
_FILE_LOCKS: Dict[str, "CrossProcessFileLock"] = {}
_UNDO_SNAP_SEQ = 0
_OP_LEDGER_SEQ = 0
_TRASH_SEQ = 0
_RECENT_UNDO_BASES: List[Path] = []
_KNOWN_MANAGED_TRASH_DIRS: set[str] = set()


def _next_op_seq(existing_index: Optional[Dict[str, Any]] = None) -> int:
    global _OP_LEDGER_SEQ
    max_seen = _OP_LEDGER_SEQ
    if isinstance(existing_index, dict):
        for hist in existing_index.values():
            if isinstance(hist, list):
                for rec in hist[:4]:
                    if isinstance(rec, dict):
                        s_val = int(rec.get("op_seq") or 0)
                        if s_val > max_seen:
                            max_seen = s_val
    _OP_LEDGER_SEQ = max_seen + 1
    return _OP_LEDGER_SEQ


def _hide_windows_dir(dir_p: Path) -> None:
    if sys.platform == "win32":
        with contextlib.suppress(Exception):
            ctypes.windll.kernel32.SetFileAttributesW(str(dir_p), 0x02)


_ACL_CACHE_LOCK = threading.Lock()
_ACL_APPLIED_CACHE: set[Tuple[str, bool, int]] = set()
_CURRENT_WIN_USER_SID: Optional[str] = None
_WIN_SID_RE = re.compile(r"^S-1-\d+(?:-\d+)+$")


def _get_current_windows_user_sid() -> str:
    """Resolve current Windows process token user SID (`S-1-5-21-...`) in 0ms via 64-bit safe `ctypes`."""
    global _CURRENT_WIN_USER_SID
    if _CURRENT_WIN_USER_SID is not None:
        return _CURRENT_WIN_USER_SID
    if sys.platform != "win32":
        return ""
    try:
        from ctypes import wintypes

        class _SID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("Sid", ctypes.c_void_p),
                ("Attributes", wintypes.DWORD),
            ]

        class _TOKEN_USER(ctypes.Structure):
            _fields_ = [
                ("User", _SID_AND_ATTRIBUTES),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

        kernel32.GetCurrentProcess.argtypes = []
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE

        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
        kernel32.LocalFree.restype = wintypes.HLOCAL

        advapi32.OpenProcessToken.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        advapi32.OpenProcessToken.restype = wintypes.BOOL

        advapi32.GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.GetTokenInformation.restype = wintypes.BOOL

        advapi32.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL

        TOKEN_QUERY = 0x0008
        TOKEN_USER_CLASS = 1

        tok_handle = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(tok_handle)):
            return ""
        try:
            needed = wintypes.DWORD(0)
            advapi32.GetTokenInformation(tok_handle, TOKEN_USER_CLASS, None, 0, ctypes.byref(needed))
            if needed.value == 0:
                return ""
            buf = ctypes.create_string_buffer(needed.value)
            if not advapi32.GetTokenInformation(
                tok_handle,
                TOKEN_USER_CLASS,
                buf,
                needed.value,
                ctypes.byref(needed),
            ):
                return ""
            tok_user = ctypes.cast(buf, ctypes.POINTER(_TOKEN_USER)).contents
            sid_ptr = tok_user.User.Sid
            if not sid_ptr:
                return ""
            str_sid_ptr = ctypes.c_void_p()
            if not advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(str_sid_ptr)):
                return ""
            try:
                sid_str = ctypes.wstring_at(str_sid_ptr.value) if str_sid_ptr.value else ""
            finally:
                if str_sid_ptr.value:
                    kernel32.LocalFree(ctypes.c_void_p(str_sid_ptr.value))
            if sid_str and _WIN_SID_RE.match(sid_str):
                _CURRENT_WIN_USER_SID = sid_str
                return sid_str
            return ""
        finally:
            if tok_handle.value:
                kernel32.CloseHandle(tok_handle)
    except Exception:
        return ""


def apply_current_user_only_acl(path: Union[str, Path], *, force_win_acl: bool = False) -> bool:
    """Restrict `path` to current OS user (+ SYSTEM & Administrators on Windows) with zero console popup."""
    try:
        p = Path(path)
        if not p.exists() or p.is_symlink():
            return False
        st = p.stat()
        is_dir = stat.S_ISDIR(st.st_mode)
    except OSError:
        return False

    if sys.platform != "win32":
        try:
            os.chmod(p, 0o700 if is_dir else 0o600)
            return True
        except OSError:
            return False

    if os.environ.get("PYTEST_CURRENT_TEST") and not force_win_acl:
        if is_dir:
            with contextlib.suppress(OSError):
                os.chmod(p, 0o700)
        return True

    norm_k = canonical_lock_key(p)
    ctime_ns = int(getattr(st, "st_ctime_ns", 0))
    cache_entry = (norm_k, is_dir, ctime_ns)
    with _ACL_CACHE_LOCK:
        if cache_entry in _ACL_APPLIED_CACHE:
            return True

    sid = _get_current_windows_user_sid()
    if not sid or not _WIN_SID_RE.match(sid):
        return False

    sys_root = (os.environ.get("SystemRoot") or r"C:\Windows").strip()
    icacls_cand = Path(sys_root) / "System32" / "icacls.exe"
    icacls_exe = str(icacls_cand) if icacls_cand.is_file() else "icacls"
    perm = "(OI)(CI)F" if is_dir else "F"
    cmd = [
        icacls_exe,
        str(p),
        "/inheritance:r",
        "/grant:r",
        f"*S-1-5-18:{perm}",
        f"*S-1-5-32-544:{perm}",
        f"*{sid}:{perm}",
    ]
    try:
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=8.0,
            check=False,
            creationflags=0x08000000,
        )
        if proc.returncode == 0:
            with _ACL_CACHE_LOCK:
                if len(_ACL_APPLIED_CACHE) > 4096:
                    _ACL_APPLIED_CACHE.clear()
                _ACL_APPLIED_CACHE.add(cache_entry)
            return True
    except Exception:
        pass
    return False


def find_office_temp_lock_file(target_p: Path) -> Optional[Path]:
    """Detect sibling Office/WPS/LibreOffice lock file (`~$foo.xlsx`, `~$oo.docx`, `.~lock.foo#`)."""
    name = target_p.name
    if not name or name.startswith("~$"):
        return None
    parent = target_p.parent
    cands: List[Path] = [parent / f"~${name}", parent / f".~lock.{name}#"]
    if target_p.suffix.lower() in OFFICE_DOC_EXTS and len(name) > 2:
        cands.append(parent / f"~${name[2:]}")
    for c in cands:
        with contextlib.suppress(OSError):
            if c.exists():
                return c
    return None


_find_office_temp_lock_file = find_office_temp_lock_file


def check_office_or_os_file_lock(
    target_p: str | Path,
    exc: Optional[BaseException] = None,
    for_write: bool = True,
) -> Optional[Dict[str, Any]]:
    """Return structured Chinese diagnostic dict when `target_p` is locked by Office (`~$*`) or OS `PermissionError`."""
    tp = Path(target_p)
    lock_temp = find_office_temp_lock_file(tp) if for_write else None
    is_os_lock = False
    if exc is not None:
        win_err = getattr(exc, "winerror", None)
        err_no = getattr(exc, "errno", None)
        low_m = str(exc).lower()
        office_perm = False
        if isinstance(exc, PermissionError) and tp.suffix.lower() in OFFICE_DOC_EXTS and tp.exists():
            try:
                office_perm = bool(stat.S_IMODE(tp.stat().st_mode) & stat.S_IWUSR)
            except OSError:
                office_perm = True
        if (
            win_err in (32, 33)
            or err_no == 16
            or office_perm
            or "being used by another process" in low_m
            or "另一个程序正在使用" in low_m
            or "sharing violation" in low_m
        ):
            is_os_lock = True
        elif isinstance(exc, PermissionError) and tp.exists() and for_write:
            try:
                if bool(stat.S_IMODE(tp.stat().st_mode) & stat.S_IWUSR):
                    is_os_lock = True
            except OSError:
                is_os_lock = True

    if not is_os_lock and lock_temp is not None:
        pass
    elif not is_os_lock and lock_temp is None:
        return None

    alt_path = tp.with_name(f"{tp.stem}_更新版{tp.suffix}")
    action_word = "修改或移动" if for_write else "读取"
    return {
        "ok": False,
        "file_locked_by_external_app": True,
        "locked_by_office_temp": lock_temp is not None,
        "lock_file": str(lock_temp) if lock_temp is not None else None,
        "path": str(tp),
        "suggested_save_as": str(alt_path),
        "error": (
            f"文件 `{tp.name}` 当前正被 Excel / WPS / Office 等外部程序打开占用，为保护未保存修改已中止{action_word}。"
            f"请先保存并关闭 `{tp.name}` 后重试，或另存为新文件 `{alt_path.name}`。"
        ),
        "hint": (
            f"File `{tp.name}` is currently locked by an open application (e.g. Excel/Office). "
            f"Ask the user to save and close `{tp.name}`, or write output to `{alt_path}` instead."
        ),
    }


def canonical_lock_key(path_str: str | Path) -> str:
    """Return normalized realpath key suitable for cross-process lock deduplication and ordering."""
    try:
        return os.path.normcase(os.path.realpath(os.path.abspath(os.path.expanduser(str(path_str)))))
    except Exception:
        return os.path.normcase(os.path.abspath(str(path_str)))


_canonical_lock_key = canonical_lock_key


def get_user_private_lock_dir(lock_dir: Optional[str | Path] = None) -> Path:
    """Return per-user private lock directory (`0o700` on POSIX), respecting optional env/arg override."""
    override = str(
        lock_dir
        or os.environ.get("COSMOS_MCP_LOCK_DIR")
        or os.environ.get("LOCALPC_LOCK_DIR")
        or ""
    ).strip()
    if override:
        custom_p = Path(override).expanduser().resolve()
        custom_p.mkdir(parents=True, exist_ok=True)
        return custom_p

    if sys.platform == "win32":
        local_app = (os.environ.get("LOCALAPPDATA") or "").strip()
        base_d = Path(local_app) if local_app else (Path.home() / "AppData" / "Local")
        win_dir = base_d / "CosmosMCP" / "locks"
        win_dir.mkdir(parents=True, exist_ok=True)
        return win_dir

    uid = os.getuid() if hasattr(os, "getuid") else 0
    posix_dir = Path(f"/tmp/cosmos-mcp-locks-{uid}")
    posix_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    st = posix_dir.lstat()
    if stat.S_ISLNK(st.st_mode):
        raise PermissionError(f"Refusing symlinked lock directory: {posix_dir}")
    if hasattr(os, "getuid") and st.st_uid != uid:
        raise PermissionError(f"Lock directory {posix_dir} is owned by uid {st.st_uid}, expected {uid}")
    if stat.S_IMODE(st.st_mode) != 0o700:
        os.chmod(posix_dir, 0o700)
    return posix_dir


class CrossProcessFileLock:
    """Thread-reentrant + cross-process exclusive file lock (`msvcrt.locking` / `fcntl.flock`)."""

    def __init__(self, norm_key: str, lock_dir: Optional[str | Path] = None) -> None:
        self._norm_key = norm_key
        self._lock_dir_override = lock_dir
        self._sha = hashlib.sha256(norm_key.encode("utf-8")).hexdigest()[:40]
        self._rlock = threading.RLock()
        self._depth = 0
        self._fh: Optional[Any] = None
        self._lock_path: Optional[Path] = None

    @property
    def key(self) -> str:
        return self._norm_key

    def _open_lock_handle(self, lock_path: Path) -> Any:
        fh = lock_path.open("a+b")
        try:
            fh.seek(0, os.SEEK_END)
            if fh.tell() == 0:
                fh.write(b"0")
                fh.flush()
        except OSError:
            pass
        return fh

    def acquire(self, timeout: float = 30.0) -> bool:
        self._rlock.acquire()
        try:
            if self._depth == 0:
                ldir = get_user_private_lock_dir(self._lock_dir_override)
                lock_path = ldir / f"{self._sha}.lock"
                fh = self._open_lock_handle(lock_path)
                deadline = time.monotonic() + max(0.05, float(timeout))
                delay = 0.005
                while True:
                    try:
                        if sys.platform == "win32":
                            import msvcrt

                            fh.seek(0)
                            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                        else:
                            import fcntl

                            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                            try:
                                st_fd = os.fstat(fh.fileno())
                                st_p = lock_path.stat()
                                inode_ok = st_fd.st_ino == st_p.st_ino and st_fd.st_dev == st_p.st_dev
                            except OSError:
                                inode_ok = False
                            if not inode_ok:
                                with contextlib.suppress(OSError):
                                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                                    fh.close()
                                fh = self._open_lock_handle(lock_path)
                                continue
                        break
                    except OSError as exc:
                        if time.monotonic() >= deadline:
                            with contextlib.suppress(OSError):
                                fh.close()
                            raise TimeoutError(
                                f"Timed out acquiring cross-process file lock for {self._norm_key}: {exc}"
                            ) from exc
                        time.sleep(delay)
                        delay = min(delay * 1.6, 0.05)
                self._fh = fh
                self._lock_path = lock_path
            self._depth += 1
            return True
        except BaseException:
            self._rlock.release()
            raise

    def release(self) -> None:
        try:
            if self._depth > 0:
                self._depth -= 1
            if self._depth == 0 and self._fh is not None:
                fh = self._fh
                lock_path = self._lock_path
                self._fh = None
                self._lock_path = None
                try:
                    if sys.platform == "win32":
                        import msvcrt

                        fh.seek(0)
                        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        if lock_path is not None:
                            try:
                                lock_path.unlink()
                            except OSError:
                                pass
                        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
                finally:
                    with contextlib.suppress(OSError):
                        fh.close()
                    if sys.platform == "win32" and lock_path is not None:
                        try:
                            lock_path.unlink()
                        except OSError:
                            pass
        finally:
            self._rlock.release()

    def __enter__(self) -> "CrossProcessFileLock":
        self.acquire()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()


_CrossProcessFileLock = CrossProcessFileLock


def get_file_lock(path_str: str | Path) -> CrossProcessFileLock:
    """Return cached thread-reentrant & cross-process lock for `path_str`."""
    norm = canonical_lock_key(path_str)
    with _FILE_LOCKS_GUARD:
        lk = _FILE_LOCKS.get(norm)
        if lk is None:
            if len(_FILE_LOCKS) > 4096:
                stale_keys = [
                    k for k, v in list(_FILE_LOCKS.items())[:1024] if v._depth == 0 and v._fh is None
                ]
                for sk in stale_keys:
                    _FILE_LOCKS.pop(sk, None)
            lk = CrossProcessFileLock(norm)
            _FILE_LOCKS[norm] = lk
        return lk


cross_process_file_lock = get_file_lock


class MultiFileLock:
    """Acquire multiple cross-process file locks in canonical lexicographical order to prevent deadlocks."""

    def __init__(self, paths: Sequence[str | Path], timeout: float = 30.0) -> None:
        by_key: Dict[str, CrossProcessFileLock] = {}
        for p in paths:
            k = canonical_lock_key(p)
            if k not in by_key:
                by_key[k] = get_file_lock(p)
        self._ordered_keys: Tuple[str, ...] = tuple(sorted(by_key.keys()))
        self._locks: List[CrossProcessFileLock] = [by_key[k] for k in self._ordered_keys]
        self._timeout = float(timeout)

    @property
    def ordered_keys(self) -> Tuple[str, ...]:
        return self._ordered_keys

    def __enter__(self) -> "MultiFileLock":
        acquired: List[CrossProcessFileLock] = []
        try:
            for lk in self._locks:
                lk.acquire(timeout=self._timeout)
                acquired.append(lk)
            return self
        except BaseException:
            for lk in reversed(acquired):
                lk.release()
            raise

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        for lk in reversed(self._locks):
            lk.release()


_MultiFileLock = MultiFileLock


def _is_under_dir(target: Path, base_dir: Path) -> bool:
    try:
        t_res = target.resolve()
        b_res = base_dir.resolve()
        if t_res == b_res:
            return False
        sep = "\\" if sys.platform == "win32" else "/"
        t_low = os.path.normcase(str(t_res))
        b_low = os.path.normcase(str(b_res)).rstrip("\\/")
        return t_low.startswith(b_low + sep)
    except Exception:
        return False


def _has_git_ancestor(dir_p: Path) -> bool:
    try:
        cur = dir_p.resolve()
    except Exception:
        cur = dir_p
    while True:
        with contextlib.suppress(OSError):
            if (cur / ".git").exists():
                return True
        if cur.parent == cur:
            break
        cur = cur.parent
    return False


def _ensure_undo_dir(undo_dir: Path) -> None:
    undo_dir.mkdir(parents=True, exist_ok=True)
    gi = undo_dir / ".gitignore"
    if not gi.exists():
        with contextlib.suppress(OSError):
            gi.write_text("*\n", encoding="utf-8")
    with _UNDO_LOCK:
        resolved = undo_dir.resolve()
        if resolved in _RECENT_UNDO_BASES:
            _RECENT_UNDO_BASES.remove(resolved)
        _RECENT_UNDO_BASES.insert(0, resolved)
        del _RECENT_UNDO_BASES[24:]


def _deepest_existing_ancestor(path_p: Path) -> Path:
    cur = path_p
    while not cur.exists() and cur.parent != cur:
        cur = cur.parent
    return cur


def _same_volume_st_dev(path_a: Path, path_b: Path) -> bool:
    """Return True iff `path_a` and `path_b` reside on the exact same OS volume via `os.stat().st_dev`."""
    try:
        anc_a = _deepest_existing_ancestor(path_a.resolve())
        anc_b = _deepest_existing_ancestor(path_b.resolve())
        dev_a = os.stat(anc_a).st_dev
        dev_b = os.stat(anc_b).st_dev
        if dev_a and dev_b:
            return dev_a == dev_b
        if sys.platform == "win32":
            return bool(anc_a.drive) and anc_a.drive.lower() == anc_b.drive.lower()
        return dev_a == dev_b
    except OSError:
        return False


def _configured_explicit_undo_dir() -> Optional[Path]:
    for env_k in ("COSMOS_MCP_UNDO_DIR", "LOCALPC_UNDO_DIR"):
        raw = (os.environ.get(env_k) or "").strip()
        if raw:
            return Path(raw).expanduser().resolve()
    return None


def _has_explicit_undo_env() -> bool:
    return _configured_explicit_undo_dir() is not None


def _effective_state_root(
    state_root: Optional[Union[str, Path]] = None,
    guard: Optional[Any] = None,
) -> Path:
    if state_root is not None and str(state_root).strip():
        return Path(state_root).expanduser().resolve()
    if guard is not None and hasattr(guard, "effective_state_root"):
        with contextlib.suppress(Exception):
            return Path(guard.effective_state_root()).expanduser().resolve()
    from .guard import resolve_state_root

    return resolve_state_root()


def compute_workspace_hash(ws_path: Union[str, Path]) -> str:
    """Compute stable 16-hex SHA-256 identifier for a workspace directory."""
    try:
        norm = os.path.normcase(str(Path(ws_path).expanduser().resolve()))
    except Exception:
        norm = os.path.normcase(os.path.abspath(str(ws_path)))
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]


def _resolve_allowed_roots(
    workspace_root: Optional[Union[str, Path]] = None,
    workspace_roots: Optional[Sequence[Union[str, Path]]] = None,
) -> List[Path]:
    """Normalize explicit `workspace_root` + `workspace_roots` into a deduplicated list of resolved `Path` objects."""
    raw_items: List[Union[str, Path]] = []
    if workspace_root is not None and str(workspace_root).strip():
        raw_items.append(workspace_root)
    if workspace_roots is not None:
        if isinstance(workspace_roots, (str, Path)):
            for pt in str(workspace_roots).split(os.pathsep):
                if pt.strip():
                    raw_items.append(pt.strip())
        else:
            for item in workspace_roots:
                if item is not None and str(item).strip():
                    raw_items.append(item)

    out: List[Path] = []
    seen_norm: set[str] = set()
    for raw in raw_items:
        with contextlib.suppress(Exception):
            rp = Path(raw).expanduser().resolve()
            nk = os.path.normcase(str(rp))
            if nk not in seen_norm:
                seen_norm.add(nk)
                out.append(rp)
    return out


def _resolve_workspace_roots_list(
    workspace_root: Optional[Union[str, Path]] = None,
    workspace_roots: Optional[Sequence[Union[str, Path]]] = None,
) -> List[Path]:
    explicit = _resolve_allowed_roots(workspace_root=workspace_root, workspace_roots=workspace_roots)
    if explicit:
        return explicit

    env_items: List[str] = []
    for env_k in ("COSMOS_WORKSPACE_ROOTS", "COSMOS_MCP_WORKSPACE_ROOT", "LOCALPC_WORKSPACE_ROOT"):
        ev = (os.environ.get(env_k) or "").strip()
        if ev:
            for pt in ev.split(os.pathsep):
                if pt.strip():
                    env_items.append(pt.strip())
            break
    return _resolve_allowed_roots(workspace_roots=env_items)


def _resolve_workspace_root(workspace_root: Optional[str | Path] = None) -> Optional[Path]:
    roots = _resolve_workspace_roots_list(workspace_root=workspace_root)
    return roots[0] if roots else None


def _infer_workspace_anchor(tp: Optional[Path], ws_roots: Sequence[Path]) -> Path:
    """Infer workspace root path solely for computing `<workspace_hash>` under `state_root/history/`."""
    if ws_roots:
        if tp is None:
            return ws_roots[0]
        matching = [ws for ws in ws_roots if tp == ws or _is_under_dir(tp, ws)]
        if matching:
            matching.sort(key=lambda p: len(p.parts), reverse=True)
            return matching[0]

    if tp is not None:
        stop_dirs: set[str] = set()
        with contextlib.suppress(Exception):
            stop_dirs.add(os.path.normcase(str(Path(tempfile.gettempdir()).resolve())))
        with contextlib.suppress(Exception):
            stop_dirs.add(os.path.normcase(str(Path.home().resolve())))

        anchor = tp if tp.is_dir() else tp.parent
        cur = anchor
        while True:
            norm_cur = os.path.normcase(str(cur))
            if norm_cur in stop_dirs or len(cur.parts) <= 1:
                break
            with contextlib.suppress(OSError):
                if (cur / ".git").exists():
                    return cur.resolve()
            if cur.parent == cur:
                break
            cur = cur.parent
        return anchor.resolve()

    return Path.cwd().resolve()


def _resolve_cross_volume_hidden_subdir(tp: Path, subdir_name: str) -> Optional[Path]:
    """Locate a same-volume hidden directory outside any user Git repository for staging or trash."""
    with contextlib.suppress(Exception):
        tmp_root = Path(tempfile.gettempdir()).resolve()
        if _same_volume_st_dev(tmp_root, tp) and not _has_git_ancestor(tmp_root):
            state_tmp = tmp_root / ".cosmos_mcp_state"
            cand = state_tmp / subdir_name
            cand.mkdir(parents=True, exist_ok=True)
            _hide_windows_dir(state_tmp)
            return cand.resolve()

    resolved_tp = tp.resolve()
    vol_anchor = Path(resolved_tp.anchor) if resolved_tp.anchor else None
    if vol_anchor is not None and vol_anchor.exists() and not _has_git_ancestor(vol_anchor):
        with contextlib.suppress(OSError):
            state_vol = vol_anchor / ".cosmos_mcp_state"
            cand_v = state_vol / subdir_name
            cand_v.mkdir(parents=True, exist_ok=True)
            _hide_windows_dir(state_vol)
            return cand_v.resolve()

    for anc in reversed(resolved_tp.parents):
        if len(anc.parts) <= 1:
            continue
        if not _same_volume_st_dev(anc, resolved_tp) or _has_git_ancestor(anc):
            continue
        with contextlib.suppress(OSError):
            state_anc = anc / ".cosmos_mcp_state"
            cand_a = state_anc / subdir_name
            cand_a.mkdir(parents=True, exist_ok=True)
            _hide_windows_dir(state_anc)
            return cand_a.resolve()

    return None


def resolve_same_volume_staging_dir(
    target_p: Union[str, Path],
    *,
    state_root: Optional[Union[str, Path]] = None,
    guard: Optional[Any] = None,
    undo_dir: Optional[Union[str, Path]] = None,
) -> Optional[Path]:
    """Return a same-volume staging directory outside any Git repository, or None to use a transient file."""
    tp = Path(target_p).expanduser().resolve()
    if undo_dir is not None and str(undo_dir).strip():
        exp_u = Path(undo_dir).expanduser().resolve()
        if _same_volume_st_dev(exp_u, tp) and not _has_git_ancestor(exp_u):
            d = exp_u / "staging"
            with contextlib.suppress(OSError):
                d.mkdir(parents=True, exist_ok=True)
                return d
    sr = _effective_state_root(state_root=state_root, guard=guard)
    if _same_volume_st_dev(sr, tp):
        d = sr / "staging"
        with contextlib.suppress(OSError):
            d.mkdir(parents=True, exist_ok=True)
            return d.resolve()
    return _resolve_cross_volume_hidden_subdir(tp, "staging")


def resolve_trash_storage_dir(
    target_p: Union[str, Path],
    *,
    state_root: Optional[Union[str, Path]] = None,
    guard: Optional[Any] = None,
    undo_dir: Optional[Union[str, Path]] = None,
) -> Path:
    """
    Resolve trash payload directory:
    - Explicit `undo_dir` / `COSMOS_MCP_UNDO_DIR` when passed (e.g. `doctor` uninstall).
    - `<state_root>/trash` when on the same volume as `state_root`.
    - Target-volume system temp or hidden `.cosmos_mcp_state/trash` outside any Git repository when cross-volume.
    """
    tp = Path(target_p).expanduser().resolve()
    if undo_dir is not None and str(undo_dir).strip():
        d = (Path(undo_dir).expanduser().resolve() / "trash").resolve()
        d.mkdir(parents=True, exist_ok=True)
        with _UNDO_LOCK:
            _KNOWN_MANAGED_TRASH_DIRS.add(os.path.normcase(str(d)))
        return d

    exp_env = _configured_explicit_undo_dir()
    if exp_env is not None:
        d = (exp_env / "trash").resolve()
        d.mkdir(parents=True, exist_ok=True)
        with _UNDO_LOCK:
            _KNOWN_MANAGED_TRASH_DIRS.add(os.path.normcase(str(d)))
        return d

    sr = _effective_state_root(state_root=state_root, guard=guard)
    if _same_volume_st_dev(sr, tp):
        d = (sr / "trash").resolve()
        d.mkdir(parents=True, exist_ok=True)
        with _UNDO_LOCK:
            _KNOWN_MANAGED_TRASH_DIRS.add(os.path.normcase(str(d)))
        return d

    cross_d = _resolve_cross_volume_hidden_subdir(tp, "trash")
    if cross_d is not None:
        with _UNDO_LOCK:
            _KNOWN_MANAGED_TRASH_DIRS.add(os.path.normcase(str(cross_d)))
        return cross_d

    fallback_d = (sr / "trash").resolve()
    fallback_d.mkdir(parents=True, exist_ok=True)
    with _UNDO_LOCK:
        _KNOWN_MANAGED_TRASH_DIRS.add(os.path.normcase(str(fallback_d)))
    return fallback_d


def resolve_undo_dir(
    target_p: Optional[str | Path] = None,
    *,
    workspace_root: Optional[str | Path] = None,
    workspace_roots: Optional[Sequence[str | Path]] = None,
    undo_dir: Optional[str | Path] = None,
    state_root: Optional[str | Path] = None,
    guard: Optional[Any] = None,
    require_same_volume: bool = False,
) -> Path:
    """Resolve externalized history directory (`<state_root>/history/<workspace_hash>`) without touching user Git repos."""
    tp = Path(target_p).expanduser().resolve() if (target_p is not None and str(target_p).strip()) else None
    ws_roots = _resolve_workspace_roots_list(workspace_root=workspace_root, workspace_roots=workspace_roots)

    if undo_dir is not None and str(undo_dir).strip():
        explicit_u = Path(undo_dir).expanduser().resolve()
        if not require_same_volume or tp is None or _same_volume_st_dev(explicit_u, tp):
            return explicit_u
        same_v = _resolve_cross_volume_hidden_subdir(tp, "history")
        if same_v is not None:
            return same_v
        return explicit_u

    exp_env = _configured_explicit_undo_dir()
    if exp_env is not None:
        if not require_same_volume or tp is None or _same_volume_st_dev(exp_env, tp):
            return exp_env
        same_v = _resolve_cross_volume_hidden_subdir(tp, "history")
        if same_v is not None:
            return same_v
        return exp_env

    sr = _effective_state_root(state_root=state_root, guard=guard)
    if tp is None and not ws_roots:
        with _UNDO_LOCK:
            if _RECENT_UNDO_BASES:
                return _RECENT_UNDO_BASES[0]

    anchor = _infer_workspace_anchor(tp, ws_roots)
    hist_base = (sr / "history" / compute_workspace_hash(anchor)).resolve()

    if require_same_volume and tp is not None and not _same_volume_st_dev(hist_base, tp):
        same_v = _resolve_cross_volume_hidden_subdir(tp, "history")
        if same_v is not None:
            return same_v
    return hist_base


def _candidate_undo_bases(
    target_p: Optional[Path] = None,
    *,
    workspace_root: Optional[str | Path] = None,
    workspace_roots: Optional[Sequence[str | Path]] = None,
    undo_dir: Optional[str | Path] = None,
    state_root: Optional[str | Path] = None,
    guard: Optional[Any] = None,
) -> List[Path]:
    cands: List[Path] = []

    def _add(p: Optional[Path]) -> None:
        if p is None:
            return
        rp = p.resolve()
        if rp not in cands:
            cands.append(rp)

    ws_roots = _resolve_workspace_roots_list(workspace_root=workspace_root, workspace_roots=workspace_roots)
    if undo_dir is not None and str(undo_dir).strip():
        _add(Path(undo_dir).expanduser())
        with _UNDO_LOCK:
            for rb in _RECENT_UNDO_BASES:
                _add(rb)
        return cands

    sr = _effective_state_root(state_root=state_root, guard=guard)
    for ws_p in ws_roots:
        _add(sr / "history" / compute_workspace_hash(ws_p))
    if target_p is not None:
        _add(
            resolve_undo_dir(
                target_p,
                workspace_root=workspace_root,
                workspace_roots=workspace_roots,
                state_root=sr,
                guard=guard,
            )
        )
    _add(_configured_explicit_undo_dir())
    hist_parent = sr / "history"
    if hist_parent.is_dir():
        with contextlib.suppress(OSError):
            for sub in sorted(hist_parent.iterdir()):
                if sub.is_dir():
                    _add(sub)
    with _UNDO_LOCK:
        for rb in _RECENT_UNDO_BASES:
            _add(rb)
    return cands


def should_skip_undo_snapshot(
    path_str: str | Path,
    workspace_root: Optional[str | Path] = None,
    workspace_roots: Optional[Sequence[str | Path]] = None,
) -> bool:
    """Return True if `path_str` resides inside transient build/dependency directories (`.venv`, `node_modules`, `build`, `dist`, `target`)."""
    try:
        p = Path(path_str).expanduser().resolve()
    except Exception:
        p = Path(str(path_str))

    ws_roots = _resolve_workspace_roots_list(workspace_root=workspace_root, workspace_roots=workspace_roots)
    matched_ws = [ws for ws in ws_roots if _is_under_dir(p, ws)]
    dir_parts: Tuple[str, ...]
    if matched_ws:
        matched_ws.sort(key=lambda w: len(w.parts), reverse=True)
        dir_parts = p.relative_to(matched_ws[0]).parts[:-1]
    else:
        tmp_root: Optional[Path] = None
        with contextlib.suppress(Exception):
            tmp_root = Path(tempfile.gettempdir()).resolve()
        if tmp_root is not None and _is_under_dir(p, tmp_root):
            dir_parts = p.relative_to(tmp_root).parts[:-1]
        else:
            dir_parts = p.parts[1:-1] if len(p.parts) > 1 else ()

    return any(seg.lower() in SNAPSHOT_SKIP_DIRS for seg in dir_parts)


def _lookup_history_key(mapping: Dict[str, Any], target_p: Path) -> str:
    exact = str(target_p)
    if exact in mapping:
        return exact
    norm_t = os.path.normcase(exact)
    for k in mapping.keys():
        if os.path.normcase(str(k)) == norm_t:
            return str(k)
    return exact


def _format_trashed_at(rec: Dict[str, Any]) -> str:
    val = str(rec.get("trashed_at") or "").strip()
    if val:
        return val
    ts_ms = rec.get("ts")
    if isinstance(ts_ms, (int, float)) and ts_ms > 0:
        return datetime.fromtimestamp(float(ts_ms) / 1000.0, tz=timezone.utc).isoformat()
    return ""


def atomic_write_text(target: Path, text: str, mode_override: Optional[int] = None) -> None:
    """Write `text` as UTF-8 via same-directory temp file + `fsync` + `os.replace`, preserving permissions & monotonic `mtime_ns`."""
    target.parent.mkdir(parents=True, exist_ok=True)
    orig_mode: Optional[int] = None
    prev_mtime_ns = 0
    if target.exists() and not target.is_symlink():
        with contextlib.suppress(OSError):
            st_prev = target.stat()
            orig_mode = stat.S_IMODE(st_prev.st_mode)
            prev_mtime_ns = int(st_prev.st_mtime_ns)
    raw = text.encode("utf-8")
    tmp_p: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=str(target.parent),
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as tf:
            tf.write(raw)
            tf.flush()
            os.fsync(tf.fileno())
            tmp_p = Path(tf.name)
        if sys.platform != "win32":
            with contextlib.suppress(OSError):
                if mode_override is not None:
                    os.chmod(tmp_p, mode_override)
                elif orig_mode is not None:
                    os.chmod(tmp_p, orig_mode)
                else:
                    cur_umask = os.umask(0o022)
                    os.umask(cur_umask)
                    os.chmod(tmp_p, 0o666 & ~cur_umask)
        for _att in range(8):
            try:
                os.replace(str(tmp_p), str(target))
                break
            except PermissionError:
                if sys.platform != "win32" or _att >= 7:
                    raise
                time.sleep(0.015 * (_att + 1))
        if prev_mtime_ns:
            with contextlib.suppress(OSError):
                cur_ns = int(target.stat().st_mtime_ns)
                if cur_ns <= prev_mtime_ns:
                    bumped = prev_mtime_ns + 1_000_000
                    os.utime(target, ns=(bumped, bumped))
    finally:
        if tmp_p is not None and tmp_p.exists():
            with contextlib.suppress(OSError):
                tmp_p.unlink()


_atomic_write_text = atomic_write_text


def atomic_write_json(target: Path, payload: Any, mode_override: Optional[int] = None) -> None:
    """Write `payload` as UTF-8 JSON via same-directory temp file + `fsync` + `os.replace`."""
    atomic_write_text(
        target,
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        mode_override=mode_override,
    )


_atomic_write_json = atomic_write_json


def _is_protected_trash_path(cand: Path) -> bool:
    low_parts = {pt.lower() for pt in cand.parts}
    return bool(low_parts & {"trash", ".trash", ".cosmos_mcp_trash"})


def prune_undo_snapshots(
    snap_dir: str | Path,
    undo_idx: Optional[Path] = None,
    redo_idx: Optional[Path] = None,
    *,
    max_count: Optional[int] = None,
    max_total_bytes: Optional[int] = None,
    max_per_file: Optional[int] = None,
) -> Dict[str, int]:
    """
    Prune history `snapshots/` by per-file snapshot cap AND directory LRU count/byte caps.
    Strictly protects `trash/` and `.trash/` so user deleted items are never evicted.
    """
    eff_max_cnt = MAX_UNDO_SNAPSHOT_COUNT if max_count is None else max(1, int(max_count))
    eff_max_bytes = MAX_UNDO_SNAPSHOT_TOTAL_BYTES if max_total_bytes is None else max(1, int(max_total_bytes))
    eff_per_file = MAX_UNDO_PER_FILE if max_per_file is None else max(1, int(max_per_file))

    base_p = Path(snap_dir).resolve()
    if _is_protected_trash_path(base_p):
        return {"evicted_count": 0, "evicted_bytes": 0}
    if base_p.name != "snapshots" and ((base_p / "snapshots").is_dir() or (base_p / "index.json").is_file()):
        if undo_idx is None:
            undo_idx = base_p / "index.json"
        if redo_idx is None:
            redo_idx = base_p / "redo_index.json"
        actual_snap_dir = base_p / "snapshots"
    else:
        actual_snap_dir = base_p
        if undo_idx is None and (actual_snap_dir.parent / "index.json").is_file():
            undo_idx = actual_snap_dir.parent / "index.json"
        if redo_idx is None and (actual_snap_dir.parent / "redo_index.json").is_file():
            redo_idx = actual_snap_dir.parent / "redo_index.json"

    if not actual_snap_dir.is_dir() or _is_protected_trash_path(actual_snap_dir):
        return {"evicted_count": 0, "evicted_bytes": 0}

    evicted_norms: set[str] = set()
    evicted_cnt = 0
    evicted_bytes = 0

    # 1. Per-file snapshot count pruning via index.json
    if undo_idx is not None and undo_idx.is_file():
        with contextlib.suppress(Exception), get_file_lock(undo_idx):
            raw_idx = json.loads(undo_idx.read_text(encoding="utf-8"))
            if isinstance(raw_idx, dict):
                idx_changed = False
                trimmed_idx: Dict[str, Any] = {}
                for k_path, hist_list in raw_idx.items():
                    if not isinstance(hist_list, list):
                        trimmed_idx[k_path] = hist_list
                        continue
                    if len(hist_list) <= eff_per_file:
                        trimmed_idx[k_path] = hist_list
                        continue
                    idx_changed = True
                    kept_h = hist_list[:eff_per_file]
                    overflow_h = hist_list[eff_per_file:]
                    trimmed_idx[k_path] = kept_h
                    for rec in overflow_h:
                        if not isinstance(rec, dict):
                            continue
                        sp_raw = str(rec.get("snap_path") or "").strip()
                        if not sp_raw:
                            continue
                        sp = Path(sp_raw)
                        if _is_protected_trash_path(sp) or not _is_under_dir(sp, actual_snap_dir):
                            continue
                        try:
                            if sp.is_file():
                                sz_f = sp.stat().st_size
                                sp.unlink(missing_ok=True)
                                evicted_cnt += 1
                                evicted_bytes += int(sz_f)
                            evicted_norms.add(os.path.normcase(str(sp)))
                            evicted_norms.add(os.path.normcase(str(sp.resolve())))
                        except OSError:
                            continue
                if idx_changed:
                    atomic_write_json(undo_idx, trimmed_idx)

    # 2. Directory-wide count & total-bytes LRU pruning (oldest first)
    entries: List[Tuple[int, str, int, Path]] = []
    total_bytes = 0
    try:
        with os.scandir(actual_snap_dir) as it:
            for de in it:
                try:
                    if not de.is_file(follow_symlinks=False):
                        continue
                    cand_fp = Path(de.path)
                    if _is_protected_trash_path(cand_fp):
                        continue
                    st = de.stat(follow_symlinks=False)
                    sz = int(st.st_size)
                    total_bytes += sz
                    entries.append((int(st.st_mtime_ns), de.name, sz, cand_fp))
                except OSError:
                    continue
    except OSError:
        return {"evicted_count": evicted_cnt, "evicted_bytes": evicted_bytes}

    rem_cnt = len(entries)
    if rem_cnt > eff_max_cnt or total_bytes > eff_max_bytes:
        entries.sort(key=lambda item: (item[0], item[1]))
        dir_evicted_norms: set[str] = set()
        for _, _, sz, fp in entries:
            if rem_cnt <= eff_max_cnt and total_bytes <= eff_max_bytes:
                break
            if _is_protected_trash_path(fp):
                continue
            try:
                fp.unlink(missing_ok=True)
                rem_cnt -= 1
                total_bytes = max(0, total_bytes - sz)
                evicted_cnt += 1
                evicted_bytes += sz
                dir_evicted_norms.add(os.path.normcase(str(fp)))
                with contextlib.suppress(Exception):
                    dir_evicted_norms.add(os.path.normcase(str(fp.resolve())))
            except OSError:
                continue
        evicted_norms |= dir_evicted_norms

    if evicted_norms:
        for idx_p in (undo_idx, redo_idx):
            if idx_p is not None and idx_p.is_file():
                with contextlib.suppress(Exception), get_file_lock(idx_p):
                    raw_d = json.loads(idx_p.read_text(encoding="utf-8"))
                    if isinstance(raw_d, dict):
                        changed = False
                        cleaned: Dict[str, Any] = {}
                        for k_path, hist_list in raw_d.items():
                            if not isinstance(hist_list, list):
                                cleaned[k_path] = hist_list
                                continue
                            kept = [
                                rec
                                for rec in hist_list
                                if not (
                                    isinstance(rec, dict)
                                    and (rec.get("snap_path") or rec.get("redo_path"))
                                    and os.path.normcase(str(rec.get("snap_path") or rec.get("redo_path")))
                                    in evicted_norms
                                )
                            ]
                            if len(kept) != len(hist_list):
                                changed = True
                            if kept:
                                cleaned[k_path] = kept
                        if changed:
                            atomic_write_json(idx_p, cleaned)

    return {"evicted_count": evicted_cnt, "evicted_bytes": evicted_bytes}


_prune_undo_snapshots = prune_undo_snapshots


def _clear_redo_for_path(redo_idx: Path, target_p: Path) -> None:
    if not redo_idx.is_file():
        return
    with contextlib.suppress(Exception), get_file_lock(redo_idx):
        redo_data = json.loads(redo_idx.read_text(encoding="utf-8"))
        if isinstance(redo_data, dict):
            k = _lookup_history_key(redo_data, target_p)
            if k in redo_data:
                redo_data.pop(k, None)
                atomic_write_json(redo_idx, redo_data)


def save_undo_snapshot(
    path_str: Union[str, Path],
    pre_read_bytes: Optional[bytes] = None,
    *,
    workspace_root: Optional[Union[str, Path]] = None,
    workspace_roots: Optional[Sequence[Union[str, Path]]] = None,
    undo_dir: Optional[Union[str, Path]] = None,
    state_root: Optional[Union[str, Path]] = None,
    guard: Optional[Any] = None,
    clear_redo: bool = True,
    record_index: bool = True,
    max_per_file: Optional[int] = None,
    max_count: Optional[int] = None,
    max_total_bytes: Optional[int] = None,
) -> Optional[str]:
    """
    Save pre-edit snapshot of `path_str` into `<state_root>/history/<workspace_hash>/snapshots` and run LRU quota pruning.
    Automatically skips `.venv`, `node_modules`, `build`, `dist`, and `target`.
    """
    global _UNDO_SNAP_SEQ
    p = Path(path_str).expanduser().resolve()
    if should_skip_undo_snapshot(p, workspace_root=workspace_root, workspace_roots=workspace_roots):
        return None
    if pre_read_bytes is None and (not p.exists() or not p.is_file()):
        return None

    with _UNDO_LOCK:
        try:
            undo_base = resolve_undo_dir(
                p,
                workspace_root=workspace_root,
                workspace_roots=workspace_roots,
                undo_dir=undo_dir,
                state_root=state_root,
                guard=guard,
            )
            _ensure_undo_dir(undo_base)
            snap_dir = undo_base / "snapshots"
            undo_idx = undo_base / "index.json"
            redo_idx = undo_base / "redo_index.json"
            snap_dir.mkdir(parents=True, exist_ok=True)

            content = pre_read_bytes if pre_read_bytes is not None else p.read_bytes()
            orig_mode: Optional[int] = None
            if p.exists() and not p.is_symlink():
                with contextlib.suppress(OSError):
                    orig_mode = stat.S_IMODE(p.stat().st_mode)

            full_sha = hashlib.sha256(content).hexdigest().lower()
            ts = int(time.time() * 1000)
            _UNDO_SNAP_SEQ += 1
            safe_name = p.name.replace("/", "_").replace("\\", "_")
            snap_name = f"{ts}_{_UNDO_SNAP_SEQ:06d}_{threading.get_ident()}_{full_sha[:10]}_{safe_name}"
            snap_path = snap_dir / snap_name
            snap_path.write_bytes(content)

            if record_index:
                with get_file_lock(undo_idx):
                    idx_data: Dict[str, List[Dict[str, Any]]] = {}
                    if undo_idx.is_file():
                        with contextlib.suppress(Exception):
                            loaded = json.loads(undo_idx.read_text(encoding="utf-8"))
                            if isinstance(loaded, dict):
                                idx_data = loaded
                    seq = _next_op_seq(idx_data)
                    key = _lookup_history_key(idx_data, p)
                    history = list(idx_data.get(key) or [])
                    rec: Dict[str, Any] = {
                        "op": "edit",
                        "existed_before": True,
                        "snap_path": str(snap_path),
                        "ts": ts,
                        "op_seq": seq,
                        "sha256": full_sha,
                        "sha256_prefix": full_sha[:12],
                        "bytes": len(content),
                    }
                    if orig_mode is not None:
                        rec["mode"] = orig_mode
                    history.insert(0, rec)
                    idx_data[key] = history
                    atomic_write_json(undo_idx, idx_data)

                if clear_redo:
                    _clear_redo_for_path(redo_idx, p)
                prune_undo_snapshots(
                    snap_dir,
                    undo_idx=undo_idx,
                    redo_idx=redo_idx,
                    max_count=max_count,
                    max_total_bytes=max_total_bytes,
                    max_per_file=max_per_file,
                )
            return str(snap_path)
        except Exception:
            return None


def record_file_creation_undo(
    path_str: str | Path,
    created_sha256: str = "",
    *,
    workspace_root: Optional[str | Path] = None,
    workspace_roots: Optional[Sequence[str | Path]] = None,
    undo_dir: Optional[str | Path] = None,
    state_root: Optional[str | Path] = None,
    guard: Optional[Any] = None,
    op_kind: str = "create",
) -> bool:
    """Record a newly created file or directory in history `index.json` so `undo_last_edit` moves it to trash."""
    p = Path(path_str).expanduser().resolve()
    if should_skip_undo_snapshot(p, workspace_root=workspace_root, workspace_roots=workspace_roots):
        return False
    with _UNDO_LOCK:
        try:
            undo_base = resolve_undo_dir(
                p,
                workspace_root=workspace_root,
                workspace_roots=workspace_roots,
                undo_dir=undo_dir,
                state_root=state_root,
                guard=guard,
            )
            _ensure_undo_dir(undo_base)
            snap_dir = undo_base / "snapshots"
            undo_idx = undo_base / "index.json"
            redo_idx = undo_base / "redo_index.json"
            snap_dir.mkdir(parents=True, exist_ok=True)
            ts = int(time.time() * 1000)
            with get_file_lock(undo_idx):
                idx_data: Dict[str, List[Dict[str, Any]]] = {}
                if undo_idx.is_file():
                    with contextlib.suppress(Exception):
                        loaded = json.loads(undo_idx.read_text(encoding="utf-8"))
                        if isinstance(loaded, dict):
                            idx_data = loaded
                seq = _next_op_seq(idx_data)
                key = _lookup_history_key(idx_data, p)
                history = list(idx_data.get(key) or [])
                history.insert(
                    0,
                    {
                        "op": op_kind or "create",
                        "existed_before": False,
                        "snap_path": "",
                        "ts": ts,
                        "op_seq": seq,
                        "created_sha256": created_sha256,
                        "sha256": "",
                        "sha256_prefix": "",
                        "bytes": 0,
                    },
                )
                idx_data[key] = history[:MAX_UNDO_PER_FILE]
                atomic_write_json(undo_idx, idx_data)
            _clear_redo_for_path(redo_idx, p)
            return True
        except Exception:
            return False


def record_move_undo(
    src_path: Union[str, Path],
    dst_path: Union[str, Path],
    *,
    action_kind: str = "move",
    dst_existed_before: bool = False,
    overwritten_snap_path: str = "",
    overwritten_trash_id: str = "",
    workspace_root: Optional[Union[str, Path]] = None,
    workspace_roots: Optional[Sequence[Union[str, Path]]] = None,
    undo_dir: Optional[Union[str, Path]] = None,
    state_root: Optional[Union[str, Path]] = None,
    guard: Optional[Any] = None,
) -> bool:
    """Record a `move` or `rename` operation in history `index.json` so `undo_last_edit` reverses it cleanly."""
    src_p = Path(src_path).expanduser().resolve()
    dst_p = Path(dst_path).expanduser().resolve()
    if should_skip_undo_snapshot(dst_p, workspace_root=workspace_root, workspace_roots=workspace_roots):
        return False
    with _UNDO_LOCK:
        try:
            undo_base = resolve_undo_dir(
                dst_p,
                workspace_root=workspace_root,
                workspace_roots=workspace_roots,
                undo_dir=undo_dir,
                state_root=state_root,
                guard=guard,
            )
            _ensure_undo_dir(undo_base)
            undo_idx = undo_base / "index.json"
            redo_idx = undo_base / "redo_index.json"
            ts = int(time.time() * 1000)
            sz_b = 0
            with contextlib.suppress(OSError):
                if dst_p.is_file():
                    sz_b = int(dst_p.stat().st_size)
            with get_file_lock(undo_idx):
                idx_data: Dict[str, List[Dict[str, Any]]] = {}
                if undo_idx.is_file():
                    with contextlib.suppress(Exception):
                        loaded = json.loads(undo_idx.read_text(encoding="utf-8"))
                        if isinstance(loaded, dict):
                            idx_data = loaded
                seq = _next_op_seq(idx_data)
                key = _lookup_history_key(idx_data, dst_p)
                history = list(idx_data.get(key) or [])
                history.insert(
                    0,
                    {
                        "op": "rename" if action_kind == "rename" else "move",
                        "src_path": str(src_p),
                        "dst_path": str(dst_p),
                        "existed_before": bool(dst_existed_before),
                        "dst_existed_before": bool(dst_existed_before),
                        "overwritten_snap_path": str(overwritten_snap_path or ""),
                        "overwritten_trash_id": str(overwritten_trash_id or ""),
                        "snap_path": "",
                        "ts": ts,
                        "op_seq": seq,
                        "bytes": sz_b,
                    },
                )
                idx_data[key] = history[:MAX_UNDO_PER_FILE]
                atomic_write_json(undo_idx, idx_data)
            _clear_redo_for_path(redo_idx, dst_p)
            return True
        except Exception:
            return False


def pop_latest_undo_entry_quiet(
    target_p: str | Path,
    *,
    workspace_root: Optional[str | Path] = None,
    workspace_roots: Optional[Sequence[str | Path]] = None,
    undo_dir: Optional[str | Path] = None,
    state_root: Optional[str | Path] = None,
    guard: Optional[Any] = None,
) -> None:
    """Pop top undo index frame quietly when an `os.replace` commit fails after writing a snapshot."""
    p = Path(target_p).expanduser().resolve()
    with _UNDO_LOCK, contextlib.suppress(Exception):
        undo_base = resolve_undo_dir(
            p,
            workspace_root=workspace_root,
            workspace_roots=workspace_roots,
            undo_dir=undo_dir,
            state_root=state_root,
            guard=guard,
        )
        undo_idx = undo_base / "index.json"
        if undo_idx.is_file():
            with get_file_lock(undo_idx):
                idx_data = json.loads(undo_idx.read_text(encoding="utf-8"))
                if isinstance(idx_data, dict):
                    key = _lookup_history_key(idx_data, p)
                    hist = idx_data.get(key)
                    if isinstance(hist, list) and hist:
                        hist.pop(0)
                        if hist:
                            idx_data[key] = hist
                        else:
                            idx_data.pop(key, None)
                        atomic_write_json(undo_idx, idx_data)


def _remove_link_or_junction_only(link_p: Path, st_raw: Optional[os.stat_result]) -> None:
    """Detach a symlink or Windows NTFS junction itself without ever traversing into its target."""
    is_win_dir_reparse = bool(
        sys.platform == "win32"
        and st_raw is not None
        and (getattr(st_raw, "st_file_attributes", 0) & 0x10)
    )
    if is_win_dir_reparse:
        try:
            os.rmdir(str(link_p))
            return
        except OSError:
            os.unlink(str(link_p))
            return
    try:
        os.unlink(str(link_p))
    except OSError:
        os.rmdir(str(link_p))


def safe_trash_file(
    path_str: Union[str, Path],
    reason: str = "",
    *,
    workspace_root: Optional[Union[str, Path]] = None,
    workspace_roots: Optional[Sequence[Union[str, Path]]] = None,
    undo_dir: Optional[Union[str, Path]] = None,
    state_root: Optional[Union[str, Path]] = None,
    guard: Optional[Any] = None,
    record_undo: bool = True,
) -> Dict[str, Any]:
    """Move a file or directory into recoverable externalized trash storage instead of permanently deleting it."""
    global _TRASH_SEQ
    raw_s = str(path_str or "").strip()
    if not raw_s:
        return {"ok": False, "error": "Empty path cannot be trashed"}

    raw_expanded = os.path.abspath(os.path.expanduser(os.path.expandvars(raw_s)))
    raw_p = Path(raw_expanded)
    st_raw: Optional[os.stat_result] = None
    try:
        st_raw = os.lstat(raw_p)
    except OSError:
        st_raw = None

    if (st_raw is not None and is_link_or_junction(raw_p)) or raw_p.is_symlink():
        parent_resolved = raw_p.parent.resolve() if raw_p.parent != raw_p else raw_p.parent
        link_p = parent_resolved / raw_p.name
        link_lock = CrossProcessFileLock(f"link::{os.path.normcase(str(link_p))}")
        with link_lock, _UNDO_LOCK:
            try:
                st_cur = os.lstat(link_p)
            except FileNotFoundError:
                return {"ok": False, "path": str(link_p), "error": f"Path not found: {link_p}"}
            except OSError as exc:
                return {"ok": False, "path": str(link_p), "error": f"{type(exc).__name__}: {exc}"}

            link_target = ""
            with contextlib.suppress(OSError):
                link_target = str(os.readlink(link_p))

            reparse_tag_cur = int(getattr(st_cur, "st_reparse_tag", 0) or 0)
            is_junc_fn = getattr(link_p, "is_junction", None)
            if reparse_tag_cur == 0xA0000003 or (callable(is_junc_fn) and is_junc_fn()) or (
                reparse_tag_cur == 0
                and not stat.S_ISLNK(st_cur.st_mode)
                and bool(getattr(st_cur, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400))
            ):
                link_kind = "junction"
            elif bool(getattr(st_cur, "st_file_attributes", 0) & 0x10):
                link_kind = "dir_symlink"
            else:
                link_kind = "symlink"

            try:
                undo_base = resolve_undo_dir(
                    parent_resolved,
                    workspace_root=workspace_root,
                    workspace_roots=workspace_roots,
                    undo_dir=undo_dir,
                    state_root=state_root,
                    guard=guard,
                )
                _ensure_undo_dir(undo_base)
                trash_dir = resolve_trash_storage_dir(parent_resolved, state_root=state_root, guard=guard, undo_dir=undo_dir)
                trash_idx = undo_base / "trash_index.json"
                trash_dir.mkdir(parents=True, exist_ok=True)

                ts = int(time.time() * 1000)
                _TRASH_SEQ += 1
                trashed_at = datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc).isoformat()
                safe_name = link_p.name.replace("/", "_").replace("\\", "_")
                trash_id = f"trash_{ts}_{_TRASH_SEQ:04d}_{safe_name}"
                dest_meta = trash_dir / f"{trash_id}.link_meta.json"

                _remove_link_or_junction_only(link_p, st_cur)
                meta_payload = {
                    "trash_id": trash_id,
                    "original_path": str(link_p),
                    "is_link_or_junction": True,
                    "link_kind": link_kind,
                    "link_target": link_target,
                    "ts": ts,
                    "seq": _TRASH_SEQ,
                    "trashed_at": trashed_at,
                    "reason": reason,
                }
                atomic_write_json(dest_meta, meta_payload)

                with get_file_lock(trash_idx):
                    records_l: List[Dict[str, Any]] = []
                    if trash_idx.is_file():
                        with contextlib.suppress(Exception):
                            loaded_l = json.loads(trash_idx.read_text(encoding="utf-8"))
                            if isinstance(loaded_l, list):
                                records_l = loaded_l
                    records_l.insert(
                        0,
                        {
                            "trash_id": trash_id,
                            "original_path": str(link_p),
                            "trash_path": str(dest_meta),
                            "is_link_or_junction": True,
                            "link_kind": link_kind,
                            "link_target": link_target,
                            "ts": ts,
                            "seq": _TRASH_SEQ,
                            "trashed_at": trashed_at,
                            "reason": reason,
                        },
                    )
                    atomic_write_json(trash_idx, records_l[:500])

                return {
                    "ok": True,
                    "trash_id": trash_id,
                    "original_path": str(link_p),
                    "moved_to": str(dest_meta),
                    "trashed_at": trashed_at,
                    "is_link_or_junction": True,
                    "link_kind": link_kind,
                    "link_target": link_target,
                    "removed_link_only": True,
                    "same_volume": True,
                    "same_volume_replace": False,
                }
            except Exception as exc:
                return {"ok": False, "path": str(link_p), "error": f"{type(exc).__name__}: {exc}"}

    p = raw_p.resolve()

    with get_file_lock(p), _UNDO_LOCK:
        if not p.exists() and not p.is_symlink():
            return {"ok": False, "path": str(p), "error": f"Path not found: {p}"}
        if p.is_file():
            ext_lock = check_office_or_os_file_lock(p, for_write=True)
            if ext_lock is not None:
                return ext_lock
        try:
            undo_base = resolve_undo_dir(
                p,
                workspace_root=workspace_root,
                workspace_roots=workspace_roots,
                undo_dir=undo_dir,
                state_root=state_root,
                guard=guard,
            )
            _ensure_undo_dir(undo_base)
            trash_dir = resolve_trash_storage_dir(p, state_root=state_root, guard=guard, undo_dir=undo_dir)
            trash_idx = undo_base / "trash_index.json"
            trash_dir.mkdir(parents=True, exist_ok=True)

            item_bytes = 0
            with contextlib.suppress(OSError):
                if p.is_file():
                    item_bytes = int(p.stat().st_size)

            ts = int(time.time() * 1000)
            _TRASH_SEQ += 1
            trashed_at = datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc).isoformat()
            safe_name = p.name.replace("/", "_").replace("\\", "_")
            trash_id = f"trash_{ts}_{_TRASH_SEQ:04d}_{safe_name}"
            dest = trash_dir / trash_id
            same_vol = _same_volume_st_dev(trash_dir, p)
            used_replace = False
            if same_vol:
                try:
                    os.replace(str(p), str(dest))
                    used_replace = True
                except OSError:
                    shutil.move(str(p), str(dest))
            else:
                shutil.move(str(p), str(dest))

            with get_file_lock(trash_idx):
                records: List[Dict[str, Any]] = []
                if trash_idx.is_file():
                    with contextlib.suppress(Exception):
                        loaded = json.loads(trash_idx.read_text(encoding="utf-8"))
                        if isinstance(loaded, list):
                            records = loaded
                records.insert(
                    0,
                    {
                        "trash_id": trash_id,
                        "original_path": str(p),
                        "trash_path": str(dest),
                        "ts": ts,
                        "seq": _TRASH_SEQ,
                        "trashed_at": trashed_at,
                        "reason": reason,
                    },
                )
                atomic_write_json(trash_idx, records[:500])

            if record_undo and not should_skip_undo_snapshot(
                p, workspace_root=workspace_root, workspace_roots=workspace_roots
            ):
                undo_idx = undo_base / "index.json"
                with get_file_lock(undo_idx):
                    idx_data: Dict[str, List[Dict[str, Any]]] = {}
                    if undo_idx.is_file():
                        with contextlib.suppress(Exception):
                            loaded_u = json.loads(undo_idx.read_text(encoding="utf-8"))
                            if isinstance(loaded_u, dict):
                                idx_data = loaded_u
                    seq = _next_op_seq(idx_data)
                    key = _lookup_history_key(idx_data, p)
                    hist = list(idx_data.get(key) or [])
                    hist.insert(
                        0,
                        {
                            "op": "trash",
                            "trash_id": trash_id,
                            "original_path": str(p),
                            "trash_path": str(dest),
                            "existed_before": True,
                            "snap_path": "",
                            "ts": ts,
                            "op_seq": seq,
                            "bytes": item_bytes,
                        },
                    )
                    idx_data[key] = hist[:MAX_UNDO_PER_FILE]
                    atomic_write_json(undo_idx, idx_data)

            return {
                "ok": True,
                "trash_id": trash_id,
                "original_path": str(p),
                "moved_to": str(dest),
                "trashed_at": trashed_at,
                "same_volume": same_vol,
                "same_volume_replace": used_replace,
            }
        except OSError as exc:
            lk_err = check_office_or_os_file_lock(p, exc=exc, for_write=True)
            if lk_err is not None:
                return lk_err
            return {"ok": False, "path": str(p), "error": f"{type(exc).__name__}: {exc}"}
        except Exception as exc:
            return {"ok": False, "path": str(p), "error": f"{type(exc).__name__}: {exc}"}


trash_file = safe_trash_file


def _is_managed_trash_payload(
    trash_p: Path,
    candidate_indexes: Sequence[Path],
    state_root: Optional[Union[str, Path]] = None,
    guard: Optional[Any] = None,
) -> bool:
    sr = _effective_state_root(state_root=state_root, guard=guard)
    allowed_dirs: List[Path] = [sr / "trash", sr / ".trash"]
    with contextlib.suppress(Exception):
        tmp_r = Path(tempfile.gettempdir()).resolve()
        allowed_dirs.append(tmp_r / ".cosmos_mcp_state" / "trash")
        allowed_dirs.append(tmp_r / ".cosmos_mcp_trash")
    for idx_p in candidate_indexes:
        allowed_dirs.append(idx_p.parent / "trash")
        allowed_dirs.append(idx_p.parent / ".trash")
    with _UNDO_LOCK:
        for kd in _KNOWN_MANAGED_TRASH_DIRS:
            allowed_dirs.append(Path(kd))
    if any(_is_under_dir(trash_p, td) for td in allowed_dirs):
        return True
    parent_p = trash_p.parent
    if parent_p.name.lower() == "trash" and parent_p.parent.name.lower() == ".cosmos_mcp_state":
        return True
    return False


def _check_tx_write_paths(
    paths: Sequence[Path],
    *,
    allowed_roots: Sequence[Path],
    guard: Optional[Any],
    action_label: str,
    tool_name: str,
) -> Optional[Dict[str, Any]]:
    for raw_p in paths:
        cand_p = Path(raw_p).resolve()
        enforce_ws = bool(getattr(guard, "restrict_to_workspace", True)) if guard is not None else True
        if enforce_ws and allowed_roots and not any(_is_under_dir(cand_p, ws_r) for ws_r in allowed_roots):
            roots_s = ", ".join(str(r) for r in allowed_roots)
            return {
                "ok": False,
                "action": action_label,
                "blocked_by_guardrail": True,
                "path": str(cand_p),
                "original_path": str(cand_p),
                "error": f"Cannot {action_label} `{cand_p}` outside workspace [{roots_s}].",
            }
        if guard is not None and callable(getattr(guard, "check_path_access", None)):
            try:
                g_err = guard.check_path_access(cand_p, mode="write", tool_name=tool_name)
            except TypeError:
                g_err = guard.check_path_access(cand_p, "write")
            except Exception as exc:
                g_err = f"[GUARD WORKSPACE SANDBOX]: {exc}"
            if g_err:
                return {
                    "ok": False,
                    "action": action_label,
                    "blocked_by_guardrail": True,
                    "path": str(cand_p),
                    "original_path": str(cand_p),
                    "error": str(g_err),
                }
    return None


def restore_trash_item(
    action: str = "list",
    trash_id: str = "",
    limit: int = 20,
    workspace_root: Optional[Union[str, Path]] = None,
    undo_dir: Optional[Union[str, Path]] = None,
    workspace_roots: Optional[Sequence[Union[str, Path]]] = None,
    state_root: Optional[Union[str, Path]] = None,
    guard: Optional[Any] = None,
) -> Dict[str, Any]:
    """List trashed items (`action='list'`) or atomically restore a trashed item (`action='restore'`)."""
    raw_act = (action or "list").strip().lower()
    act = {"list_trash": "list", "trash_list": "list", "restore_trash": "restore"}.get(raw_act, raw_act)
    if act not in ("list", "restore"):
        return {"ok": False, "error": "action must be 'list' or 'restore'"}

    allowed_roots = _resolve_allowed_roots(workspace_root=workspace_root, workspace_roots=workspace_roots)

    cand_bases = _candidate_undo_bases(
        None,
        workspace_root=workspace_root,
        workspace_roots=workspace_roots,
        undo_dir=undo_dir,
        state_root=state_root,
        guard=guard,
    )
    candidate_indexes = [b / "trash_index.json" for b in cand_bases]

    loaded_sources: List[Tuple[Path, List[Dict[str, Any]]]] = []
    for idx_p in candidate_indexes:
        if idx_p.is_file():
            with contextlib.suppress(Exception):
                raw_list = json.loads(idx_p.read_text(encoding="utf-8"))
                if isinstance(raw_list, list):
                    loaded_sources.append((idx_p, [r for r in raw_list if isinstance(r, dict)]))

    def _collect_valid_items() -> List[Dict[str, Any]]:
        seen_ids: set[str] = set()
        merged: List[Dict[str, Any]] = []
        for _, records in loaded_sources:
            for rec in records:
                tid_c = str(rec.get("trash_id") or "").strip()
                orig_str = str(rec.get("original_path") or "").strip()
                trash_str = str(rec.get("trash_path") or "").strip()
                if not tid_c or not orig_str or not trash_str or tid_c in seen_ids:
                    continue
                orig_p_c = Path(orig_str).resolve()
                if allowed_roots and not any(_is_under_dir(orig_p_c, ws_r) for ws_r in allowed_roots):
                    continue
                trash_p_c = Path(trash_str).resolve()
                if not trash_p_c.exists() and not trash_p_c.is_symlink():
                    continue
                seen_ids.add(tid_c)
                entry: Dict[str, Any] = {
                    "trash_id": tid_c,
                    "original_path": str(orig_p_c),
                    "trashed_at": _format_trashed_at(rec),
                    "_sort_key": (int(rec.get("ts") or 0), int(rec.get("seq") or 0)),
                    "reason": str(rec.get("reason") or ""),
                }
                with contextlib.suppress(OSError):
                    if trash_p_c.is_file():
                        entry["bytes"] = trash_p_c.stat().st_size
                merged.append(entry)
        merged.sort(key=lambda x: x.get("_sort_key", (0, 0)), reverse=True)
        for item in merged:
            item.pop("_sort_key", None)
        return merged

    if act == "list":
        merged_all = _collect_valid_items()
        cap = max(1, min(200, int(limit)))
        return {
            "ok": True,
            "action": "list",
            "count": len(merged_all),
            "items": merged_all[:cap],
        }

    tid = (trash_id or "").strip()
    if not tid:
        return {"ok": False, "error": "Please provide trash_id (or 'latest') when action='restore'"}
    if tid.lower() == "latest":
        items_latest = _collect_valid_items()
        if not items_latest:
            return {"ok": False, "error": "当前回收站没有可恢复的文件"}
        tid = str(items_latest[0]["trash_id"])

    found_rec: Optional[Dict[str, Any]] = None
    for _, records in loaded_sources:
        for rec in records:
            if str(rec.get("trash_id") or "").strip() == tid:
                found_rec = rec
                break
        if found_rec is not None:
            break

    if found_rec is None:
        return {"ok": False, "error": f"Trash item not found: {tid}"}

    orig_p = Path(str(found_rec.get("original_path") or "")).resolve()
    trash_p = Path(str(found_rec.get("trash_path") or "")).resolve()

    tx_gate_err = _check_tx_write_paths(
        [orig_p],
        allowed_roots=allowed_roots,
        guard=guard,
        action_label="restore",
        tool_name="restore_trash",
    )
    if tx_gate_err is not None:
        return tx_gate_err

    if not _is_managed_trash_payload(trash_p, candidate_indexes, state_root=state_root, guard=guard):
        return {
            "ok": False,
            "blocked_by_guardrail": True,
            "error": f"Trashed payload `{trash_p}` is outside managed trash storage.",
        }
    if not trash_p.exists() and not trash_p.is_symlink():
        return {"ok": False, "error": f"Trashed payload missing on disk: {trash_p}"}

    with get_file_lock(orig_p), _UNDO_LOCK:
        if orig_p.is_symlink():
            return {
                "ok": False,
                "conflict": True,
                "original_path": str(orig_p),
                "error": f"Refused to overwrite existing symlink at original path: {orig_p}",
            }
        if orig_p.exists():
            if orig_p.is_file() and orig_p.stat().st_size > 0:
                return {
                    "ok": False,
                    "conflict": True,
                    "original_path": str(orig_p),
                    "error": f"Refused to overwrite existing non-empty file ({orig_p.stat().st_size} bytes) at `{orig_p}`.",
                }
            if orig_p.is_dir() and any(orig_p.iterdir()):
                return {
                    "ok": False,
                    "conflict": True,
                    "original_path": str(orig_p),
                    "error": f"Refused to overwrite existing non-empty directory at `{orig_p}`.",
                }

        try:
            orig_p.parent.mkdir(parents=True, exist_ok=True)
            if found_rec.get("is_link_or_junction"):
                return {
                    "ok": False,
                    "is_link_or_junction": True,
                    "original_path": str(orig_p),
                    "link_target": str(found_rec.get("link_target") or ""),
                    "error": f"Trashed item `{tid}` is a detached symlink/junction metadata record (target `{found_rec.get('link_target')}`); recreate the link explicitly if needed.",
                }
            try:
                os.replace(str(trash_p), str(orig_p))
            except OSError:
                shutil.move(str(trash_p), str(orig_p))

            for idx_p, _ in loaded_sources:
                with get_file_lock(idx_p):
                    fresh_list = json.loads(idx_p.read_text(encoding="utf-8")) if idx_p.is_file() else []
                    if isinstance(fresh_list, list):
                        new_records = [
                            r
                            for r in fresh_list
                            if isinstance(r, dict) and str(r.get("trash_id") or "").strip() != tid
                        ]
                        if len(new_records) != len(fresh_list):
                            atomic_write_json(idx_p, new_records)

            for base_d in cand_bases:
                u_idx = base_d / "index.json"
                if u_idx.is_file():
                    with contextlib.suppress(Exception), get_file_lock(u_idx):
                        u_map = json.loads(u_idx.read_text(encoding="utf-8"))
                        if isinstance(u_map, dict):
                            uk = _lookup_history_key(u_map, orig_p)
                            u_hist = u_map.get(uk)
                            if isinstance(u_hist, list) and u_hist:
                                filtered_h = [
                                    r
                                    for r in u_hist
                                    if not (
                                        isinstance(r, dict)
                                        and r.get("op") == "trash"
                                        and str(r.get("trash_id") or "").strip() == tid
                                    )
                                ]
                                if len(filtered_h) != len(u_hist):
                                    if filtered_h:
                                        u_map[uk] = filtered_h
                                    else:
                                        u_map.pop(uk, None)
                                    atomic_write_json(u_idx, u_map)

            return {
                "ok": True,
                "action": "restore",
                "trash_id": tid,
                "original_path": str(orig_p),
                "restored_path": str(orig_p),
                "restored_to": str(orig_p),
            }
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def restore_from_trash(
    trash_id: str = "latest",
    *,
    action: str = "restore",
    limit: int = 20,
    workspace_root: Optional[Union[str, Path]] = None,
    workspace_roots: Optional[Sequence[Union[str, Path]]] = None,
    undo_dir: Optional[Union[str, Path]] = None,
    state_root: Optional[Union[str, Path]] = None,
    guard: Optional[Any] = None,
) -> Dict[str, Any]:
    """Restore a trashed item by `trash_id` (defaults to `'latest'` most recently deleted item), or list items."""
    eff_act = (action or "restore").strip().lower()
    eff_tid = (trash_id or "").strip() or ("latest" if eff_act == "restore" else "")
    return restore_trash_item(
        action=eff_act,
        trash_id=eff_tid,
        limit=limit,
        workspace_root=workspace_root,
        workspace_roots=workspace_roots,
        undo_dir=undo_dir,
        state_root=state_root,
        guard=guard,
    )


def _push_redo_entry(undo_base: Path, target_p: Path, entry: Dict[str, Any]) -> None:
    _ensure_undo_dir(undo_base)
    redo_idx = undo_base / "redo_index.json"
    with get_file_lock(redo_idx):
        redo_data: Dict[str, List[Dict[str, Any]]] = {}
        if redo_idx.is_file():
            with contextlib.suppress(Exception):
                raw = json.loads(redo_idx.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    redo_data = raw
        entry_copy = dict(entry)
        entry_copy.setdefault("op_seq", _next_op_seq(redo_data))
        key = _lookup_history_key(redo_data, target_p)
        hist = list(redo_data.get(key) or [])
        hist.insert(0, entry_copy)
        redo_data[key] = hist[:MAX_UNDO_PER_FILE]
        atomic_write_json(redo_idx, redo_data)


def _pop_redo_entry(undo_base: Path, target_p: Path) -> None:
    redo_idx = undo_base / "redo_index.json"
    if not redo_idx.is_file():
        return
    with get_file_lock(redo_idx):
        try:
            redo_data = json.loads(redo_idx.read_text(encoding="utf-8"))
        except Exception:
            return
        if not isinstance(redo_data, dict):
            return
        key = _lookup_history_key(redo_data, target_p)
        hist = redo_data.get(key)
        if isinstance(hist, list) and hist:
            hist.pop(0)
            if hist:
                redo_data[key] = hist
            else:
                redo_data.pop(key, None)
            atomic_write_json(redo_idx, redo_data)


def undo_last_edit(
    path_str: Union[str, Path] = "",
    action: str = "undo",
    *,
    workspace_root: Optional[Union[str, Path]] = None,
    workspace_roots: Optional[Sequence[Union[str, Path]]] = None,
    undo_dir: Optional[Union[str, Path]] = None,
    state_root: Optional[Union[str, Path]] = None,
    guard: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Roll back `path_str` (or the latest workspace operation when `path_str=""`)
    across edits, creations, moves, renames, and trashes (`action='undo'`), or re-apply (`action='redo'`).
    """
    raw_in = str(path_str or "").strip()
    act = (action or "undo").strip().lower()
    if act not in ("undo", "redo"):
        return {"ok": False, "path": raw_in, "error": f"Invalid action `{action}`: must be 'undo' or 'redo'."}

    allowed_roots = _resolve_allowed_roots(workspace_root=workspace_root, workspace_roots=workspace_roots)
    explicit_p: Optional[Path] = Path(raw_in).expanduser().resolve() if raw_in else None
    if explicit_p is not None and allowed_roots and not any(_is_under_dir(explicit_p, ws_r) for ws_r in allowed_roots):
        roots_s = ", ".join(str(r) for r in allowed_roots)
        return {
            "ok": False,
            "action": act,
            "blocked_by_guardrail": True,
            "path": str(explicit_p),
            "error": f"Cannot {act} `{explicit_p}` outside workspace [{roots_s}].",
        }

    cand_bases = _candidate_undo_bases(
        explicit_p,
        workspace_root=workspace_root,
        workspace_roots=workspace_roots,
        undo_dir=undo_dir,
        state_root=state_root,
        guard=guard,
    )
    allowed_undo_dirs = set(cand_bases)

    with _UNDO_LOCK:
        if act == "redo":
            chosen_base: Optional[Path] = None
            chosen_redo_idx: Optional[Path] = None
            redo_data: Dict[str, List[Dict[str, Any]]] = {}
            redo_key = str(explicit_p) if explicit_p is not None else ""
            redo_hist: List[Dict[str, Any]] = []
            best_redo_sort: Tuple[int, int] = (-1, -1)

            for base_d in cand_bases:
                r_idx = base_d / "redo_index.json"
                if not r_idx.is_file():
                    continue
                try:
                    with get_file_lock(r_idx):
                        d_tmp = json.loads(r_idx.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if not isinstance(d_tmp, dict):
                    continue
                if explicit_p is not None:
                    rk = _lookup_history_key(d_tmp, explicit_p)
                    rh = d_tmp.get(rk, [])
                    if isinstance(rh, list) and rh:
                        chosen_base = base_d
                        chosen_redo_idx = r_idx
                        redo_data = d_tmp
                        redo_key = rk
                        redo_hist = rh
                        break
                else:
                    for cand_k, cand_h in d_tmp.items():
                        if not isinstance(cand_h, list) or not cand_h or not isinstance(cand_h[0], dict):
                            continue
                        cp = Path(str(cand_k)).resolve()
                        if allowed_roots and not any(_is_under_dir(cp, ws_r) for ws_r in allowed_roots):
                            continue
                        sk = (int(cand_h[0].get("ts") or 0), int(cand_h[0].get("op_seq") or 0))
                        if sk > best_redo_sort:
                            best_redo_sort = sk
                            chosen_base = base_d
                            chosen_redo_idx = r_idx
                            redo_data = d_tmp
                            redo_key = str(cand_k)
                            redo_hist = cand_h

            if chosen_base is None or chosen_redo_idx is None or not redo_hist:
                return {"ok": False, "action": "redo", "path": redo_key, "error": f"No redo history found for {redo_key or 'workspace'}"}

            p = Path(redo_key).resolve()
            key = str(p)
            with get_file_lock(p):
                latest_redo = redo_hist[0]
                redo_op = str(latest_redo.get("op") or ("edit" if latest_redo.get("existed_before", True) else "create"))
                if redo_op in ("move", "rename"):
                    src_r = Path(str(latest_redo.get("src_path") or "")).resolve()
                    dst_r = Path(str(latest_redo.get("dst_path") or key)).resolve()
                    mv_redo_err = _check_tx_write_paths(
                        [src_r, dst_r],
                        allowed_roots=allowed_roots,
                        guard=guard,
                        action_label="redo",
                        tool_name="undo_edit",
                    )
                    if mv_redo_err is not None:
                        return mv_redo_err
                    if not src_r.exists():
                        return {"ok": False, "action": "redo", "path": str(src_r), "error": f"Source missing for redo {redo_op}: {src_r}"}
                    dst_r.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        os.replace(str(src_r), str(dst_r))
                    except OSError:
                        shutil.move(str(src_r), str(dst_r))
                    record_move_undo(
                        src_r,
                        dst_r,
                        action_kind=redo_op,
                        workspace_root=workspace_root,
                        workspace_roots=workspace_roots,
                        undo_dir=chosen_base,
                        state_root=state_root,
                        guard=guard,
                    )
                    with get_file_lock(chosen_redo_idx):
                        redo_hist.pop(0)
                        if redo_hist:
                            redo_data[redo_key] = redo_hist
                        else:
                            redo_data.pop(redo_key, None)
                        atomic_write_json(chosen_redo_idx, redo_data)
                    return {
                        "ok": True,
                        "action": "redo",
                        "redone_op": redo_op,
                        "path": str(dst_r),
                        "destination": str(dst_r),
                        "remaining_redos": len(redo_hist),
                    }

                redo_target_err = _check_tx_write_paths(
                    [p],
                    allowed_roots=allowed_roots,
                    guard=guard,
                    action_label="redo",
                    tool_name="undo_edit",
                )
                if redo_target_err is not None:
                    return redo_target_err

                existed_before = bool(latest_redo.get("existed_before", True))
                raw_redo_path = str(latest_redo.get("redo_path") or "").strip()
                redo_snap_p = Path(raw_redo_path).resolve() if raw_redo_path else None
                if redo_snap_p is not None and not any(_is_under_dir(redo_snap_p, ud) for ud in allowed_undo_dirs):
                    return {
                        "ok": False,
                        "action": "redo",
                        "blocked_by_guardrail": True,
                        "path": key,
                        "error": f"Redo snapshot `{redo_snap_p}` is outside managed history storage.",
                    }

                if not existed_before:
                    restored_ok = False
                    tid = str(latest_redo.get("trash_id") or "").strip()
                    if not p.exists() and tid:
                        tr_res = restore_from_trash(
                            tid,
                            workspace_root=workspace_root,
                            workspace_roots=workspace_roots,
                            undo_dir=chosen_base,
                            state_root=state_root,
                            guard=guard,
                        )
                        restored_ok = bool(tr_res.get("ok"))
                    if not restored_ok:
                        if redo_snap_p is None or not redo_snap_p.is_file():
                            return {"ok": False, "action": "redo", "path": key, "error": "Redo snapshot missing on disk."}
                        p.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(str(redo_snap_p), str(p))

                    final_b = p.read_bytes() if p.is_file() else b""
                    final_sha = hashlib.sha256(final_b).hexdigest().lower()
                    undo_idx_r = chosen_base / "index.json"
                    with get_file_lock(undo_idx_r):
                        u_data = json.loads(undo_idx_r.read_text(encoding="utf-8")) if undo_idx_r.is_file() else {}
                        seq = _next_op_seq(u_data)
                        uk = _lookup_history_key(u_data, p)
                        uh = list(u_data.get(uk) or [])
                        uh.insert(
                            0,
                            {
                                "op": "create",
                                "existed_before": False,
                                "snap_path": "",
                                "ts": int(time.time() * 1000),
                                "op_seq": seq,
                                "created_sha256": final_sha,
                                "sha256": "",
                                "sha256_prefix": "",
                                "bytes": 0,
                            },
                        )
                        u_data[uk] = uh[:MAX_UNDO_PER_FILE]
                        atomic_write_json(undo_idx_r, u_data)

                    with get_file_lock(chosen_redo_idx):
                        redo_hist.pop(0)
                        if redo_hist:
                            redo_data[redo_key] = redo_hist
                        else:
                            redo_data.pop(redo_key, None)
                        atomic_write_json(chosen_redo_idx, redo_data)
                    return {
                        "ok": True,
                        "action": "redo",
                        "path": key,
                        "existed_before": False,
                        "sha256": final_sha,
                        "restored_bytes": len(final_b),
                        "remaining_redos": len(redo_hist),
                    }

                if redo_snap_p is None or not redo_snap_p.is_file():
                    return {"ok": False, "action": "redo", "path": key, "error": f"Redo snapshot missing: {redo_snap_p}"}

                if p.is_file():
                    save_undo_snapshot(
                        p,
                        workspace_root=workspace_root,
                        workspace_roots=workspace_roots,
                        undo_dir=chosen_base,
                        state_root=state_root,
                        guard=guard,
                        clear_redo=False,
                    )
                p.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(redo_snap_p), str(p))
                final_b = p.read_bytes()
                final_sha = hashlib.sha256(final_b).hexdigest().lower()
                with get_file_lock(chosen_redo_idx):
                    redo_hist.pop(0)
                    if redo_hist:
                        redo_data[redo_key] = redo_hist
                    else:
                        redo_data.pop(redo_key, None)
                    atomic_write_json(chosen_redo_idx, redo_data)
                return {
                    "ok": True,
                    "action": "redo",
                    "path": key,
                    "existed_before": True,
                    "sha256": final_sha,
                    "restored_bytes": len(final_b),
                    "remaining_redos": len(redo_hist),
                }

        # act == "undo"
        chosen_u_base: Optional[Path] = None
        chosen_u_idx: Optional[Path] = None
        idx_data: Dict[str, List[Dict[str, Any]]] = {}
        hist_key = str(explicit_p) if explicit_p is not None else ""
        history: List[Dict[str, Any]] = []
        saw_any_idx = False
        best_sort: Tuple[int, int] = (-1, -1)

        for base_d in cand_bases:
            u_idx = base_d / "index.json"
            if not u_idx.is_file():
                continue
            saw_any_idx = True
            try:
                with get_file_lock(u_idx):
                    d_tmp = json.loads(u_idx.read_text(encoding="utf-8"))
            except Exception as exc:
                return {"ok": False, "action": "undo", "path": hist_key, "error": f"Failed to read undo index: {exc}"}
            if not isinstance(d_tmp, dict):
                continue

            if explicit_p is not None:
                hk = _lookup_history_key(d_tmp, explicit_p)
                h_list = d_tmp.get(hk, [])
                if isinstance(h_list, list) and h_list:
                    chosen_u_base = base_d
                    chosen_u_idx = u_idx
                    idx_data = d_tmp
                    hist_key = hk
                    history = h_list
                    break
                # Also match move/rename entries when caller passes the original `src_path`
                norm_exp = os.path.normcase(str(explicit_p))
                for cand_k, cand_h in d_tmp.items():
                    if not isinstance(cand_h, list) or not cand_h or not isinstance(cand_h[0], dict):
                        continue
                    top_r = cand_h[0]
                    if top_r.get("op") in ("move", "rename") and os.path.normcase(str(top_r.get("src_path") or "")) == norm_exp:
                        sk = (int(top_r.get("ts") or 0), int(top_r.get("op_seq") or 0))
                        if sk > best_sort:
                            best_sort = sk
                            chosen_u_base = base_d
                            chosen_u_idx = u_idx
                            idx_data = d_tmp
                            hist_key = str(cand_k)
                            history = cand_h
            else:
                for cand_k, cand_h in d_tmp.items():
                    if not isinstance(cand_h, list) or not cand_h or not isinstance(cand_h[0], dict):
                        continue
                    cp = Path(str(cand_k)).resolve()
                    if allowed_roots and not any(_is_under_dir(cp, ws_r) for ws_r in allowed_roots):
                        continue
                    top_r = cand_h[0]
                    sk = (int(top_r.get("ts") or 0), int(top_r.get("op_seq") or 0))
                    if sk > best_sort:
                        best_sort = sk
                        chosen_u_base = base_d
                        chosen_u_idx = u_idx
                        idx_data = d_tmp
                        hist_key = str(cand_k)
                        history = cand_h

        if chosen_u_base is None or chosen_u_idx is None or not history:
            msg = (
                f"No undo snapshots found for {hist_key}"
                if (saw_any_idx and hist_key)
                else ("No undoable operations found in workspace." if saw_any_idx else "No undo history index found yet.")
            )
            return {"ok": False, "action": "undo", "path": hist_key, "error": msg}

        p = Path(hist_key).resolve()
        key = str(p)
        latest = history[0]
        op_type = str(latest.get("op") or ("edit" if latest.get("existed_before", True) else "create"))

        # 1) Undo `trash`: restore item from trash vault
        if op_type == "trash":
            tr_gate_err = _check_tx_write_paths(
                [p],
                allowed_roots=allowed_roots,
                guard=guard,
                action_label="undo",
                tool_name="undo_edit",
            )
            if tr_gate_err is not None:
                tr_gate_err["undone_op"] = "trash"
                return tr_gate_err
            tid = str(latest.get("trash_id") or "").strip()
            tr_restore = restore_from_trash(
                tid or "latest",
                workspace_root=workspace_root,
                workspace_roots=workspace_roots,
                undo_dir=chosen_u_base,
                state_root=state_root,
                guard=guard,
            )
            if not tr_restore.get("ok"):
                out_tr_err: Dict[str, Any] = {
                    "ok": False,
                    "action": "undo",
                    "undone_op": "trash",
                    "path": key,
                    "error": str(tr_restore.get("error") or "Failed to restore trashed item."),
                }
                if tr_restore.get("blocked_by_guardrail"):
                    out_tr_err["blocked_by_guardrail"] = True
                return out_tr_err
            with get_file_lock(chosen_u_idx):
                fresh_map = json.loads(chosen_u_idx.read_text(encoding="utf-8")) if chosen_u_idx.is_file() else {}
                if isinstance(fresh_map, dict):
                    fk = _lookup_history_key(fresh_map, p)
                    fh = fresh_map.get(fk)
                    if isinstance(fh, list) and fh and fh[0].get("op") == "trash" and fh[0].get("trash_id") == tid:
                        fh.pop(0)
                        if fh:
                            fresh_map[fk] = fh
                        else:
                            fresh_map.pop(fk, None)
                        atomic_write_json(chosen_u_idx, fresh_map)
            return {
                "ok": True,
                "action": "undo",
                "undone_op": "trash",
                "path": key,
                "restored_path": key,
                "trash_id": tid,
            }

        # 2) Undo `move` / `rename`: move `dst_path` back to `src_path` and restore overwritten target if any
        if op_type in ("move", "rename"):
            src_p = Path(str(latest.get("src_path") or "")).resolve()
            dst_p = Path(str(latest.get("dst_path") or key)).resolve()
            mv_undo_err = _check_tx_write_paths(
                [src_p, dst_p],
                allowed_roots=allowed_roots,
                guard=guard,
                action_label="undo",
                tool_name="undo_edit",
            )
            if mv_undo_err is not None:
                mv_undo_err["undone_op"] = op_type
                return mv_undo_err
            with MultiFileLock([src_p, dst_p]):
                if not dst_p.exists() and not dst_p.is_symlink():
                    return {
                        "ok": False,
                        "action": "undo",
                        "undone_op": op_type,
                        "path": str(dst_p),
                        "error": f"Moved file no longer exists at `{dst_p}`.",
                    }
                if src_p.exists() or src_p.is_symlink():
                    return {
                        "ok": False,
                        "action": "undo",
                        "conflict": True,
                        "undone_op": op_type,
                        "path": str(src_p),
                        "error": f"Cannot move `{dst_p.name}` back to `{src_p}` because `{src_p.name}` already exists.",
                    }
                try:
                    src_p.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        os.replace(str(dst_p), str(src_p))
                    except OSError:
                        shutil.move(str(dst_p), str(src_p))

                    ov_snap = str(latest.get("overwritten_snap_path") or "").strip()
                    ov_tid = str(latest.get("overwritten_trash_id") or "").strip()
                    if ov_tid and not dst_p.exists():
                        restore_from_trash(
                            ov_tid,
                            workspace_root=workspace_root,
                            workspace_roots=workspace_roots,
                            undo_dir=chosen_u_base,
                            state_root=state_root,
                            guard=guard,
                        )
                    elif ov_snap and not dst_p.exists():
                        ov_snap_p = Path(ov_snap).resolve()
                        if ov_snap_p.is_file() and any(_is_under_dir(ov_snap_p, ud) for ud in allowed_undo_dirs):
                            shutil.copy2(str(ov_snap_p), str(dst_p))
                except Exception as exc:
                    return {"ok": False, "action": "undo", "undone_op": op_type, "path": str(dst_p), "error": f"{type(exc).__name__}: {exc}"}

                with get_file_lock(chosen_u_idx):
                    history.pop(0)
                    if history:
                        idx_data[hist_key] = history
                    else:
                        idx_data.pop(hist_key, None)
                    atomic_write_json(chosen_u_idx, idx_data)

                _push_redo_entry(
                    chosen_u_base,
                    dst_p,
                    {
                        "op": op_type,
                        "src_path": str(src_p),
                        "dst_path": str(dst_p),
                        "existed_before": False,
                        "ts": int(time.time() * 1000),
                    },
                )
                return {
                    "ok": True,
                    "action": "undo",
                    "undone_op": op_type,
                    "path": str(src_p),
                    "restored_path": str(src_p),
                    "moved_from": str(dst_p),
                    "moved_to": str(src_p),
                    "remaining_snapshots": len(history),
                    "can_redo": True,
                }

        # 3) Undo `create` / `edit`
        edit_undo_err = _check_tx_write_paths(
            [p],
            allowed_roots=allowed_roots,
            guard=guard,
            action_label="undo",
            tool_name="undo_edit",
        )
        if edit_undo_err is not None:
            edit_undo_err["undone_op"] = op_type
            return edit_undo_err
        with get_file_lock(p):
            existed_before = bool(latest.get("existed_before", True))

            if not existed_before:
                redo_dir = chosen_u_base / ".redo"
                _ensure_undo_dir(chosen_u_base)
                redo_dir.mkdir(parents=True, exist_ok=True)
                cur_bytes = p.read_bytes() if p.is_file() else b""
                cur_sha = hashlib.sha256(cur_bytes).hexdigest().lower() if cur_bytes else ""
                ts_r = int(time.time() * 1000)
                safe_nm = p.name.replace("/", "_").replace("\\", "_")
                redo_file = redo_dir / f"{ts_r}_{threading.get_ident()}_{cur_sha[:10] or 'empty'}_{safe_nm}"
                if p.is_file():
                    redo_file.write_bytes(cur_bytes)
                trash_res = (
                    safe_trash_file(
                        p,
                        reason="undo_created_file",
                        workspace_root=workspace_root,
                        workspace_roots=workspace_roots,
                        undo_dir=undo_dir,
                        state_root=state_root,
                        guard=guard,
                        record_undo=False,
                    )
                    if p.exists()
                    else {"ok": True, "trash_id": "", "moved_to": ""}
                )
                if not trash_res.get("ok"):
                    return {
                        "ok": False,
                        "action": "undo",
                        "path": key,
                        "error": f"Failed to move newly created item to trash during undo: {trash_res.get('error')}",
                    }
                with get_file_lock(chosen_u_idx):
                    history.pop(0)
                    if history:
                        idx_data[hist_key] = history
                    else:
                        idx_data.pop(hist_key, None)
                    atomic_write_json(chosen_u_idx, idx_data)
                _push_redo_entry(
                    chosen_u_base,
                    p,
                    {
                        "op": op_type,
                        "existed_before": False,
                        "redo_path": str(redo_file) if redo_file.is_file() else "",
                        "trash_id": str(trash_res.get("trash_id") or ""),
                        "sha256": cur_sha,
                        "sha256_prefix": cur_sha[:12],
                        "bytes": len(cur_bytes),
                        "ts": ts_r,
                    },
                )
                return {
                    "ok": True,
                    "action": "undo",
                    "undone_op": op_type,
                    "path": key,
                    "existed_before": False,
                    "undid_file_creation": True,
                    "moved_to_trash": True,
                    "trash_id": trash_res.get("trash_id", ""),
                    "remaining_snapshots": len(history),
                    "can_redo": True,
                }

            snap_p = Path(str(latest.get("snap_path") or "")).resolve()
            if not any(_is_under_dir(snap_p, ud) for ud in allowed_undo_dirs):
                return {
                    "ok": False,
                    "action": "undo",
                    "blocked_by_guardrail": True,
                    "path": key,
                    "error": f"Undo snapshot `{snap_p}` is outside managed history storage.",
                }
            if not snap_p.is_file():
                return {"ok": False, "action": "undo", "path": key, "error": f"Snapshot file missing: {snap_p}"}

            if p.exists():
                pre_lk = check_office_or_os_file_lock(p, exc=None, for_write=True)
                if pre_lk is not None:
                    lk_res = dict(pre_lk)
                    lk_res["action"] = "undo"
                    return lk_res

            redo_file_opt: Optional[Path] = None
            pushed_redo = False
            orig_imode: Optional[int] = latest.get("mode") if isinstance(latest.get("mode"), int) else None
            if orig_imode is None and p.exists() and not p.is_symlink():
                with contextlib.suppress(OSError):
                    orig_imode = stat.S_IMODE(p.stat().st_mode)
            try:
                if p.is_file():
                    redo_dir = chosen_u_base / ".redo"
                    _ensure_undo_dir(chosen_u_base)
                    redo_dir.mkdir(parents=True, exist_ok=True)
                    cur_bytes = p.read_bytes()
                    cur_sha = hashlib.sha256(cur_bytes).hexdigest().lower()
                    ts_r = int(time.time() * 1000)
                    safe_nm = p.name.replace("/", "_").replace("\\", "_")
                    redo_file_opt = redo_dir / f"{ts_r}_{threading.get_ident()}_{cur_sha[:10]}_{safe_nm}"
                    redo_file_opt.write_bytes(cur_bytes)
                    _push_redo_entry(
                        chosen_u_base,
                        p,
                        {
                            "op": "edit",
                            "existed_before": True,
                            "redo_path": str(redo_file_opt),
                            "sha256": cur_sha,
                            "sha256_prefix": cur_sha[:12],
                            "bytes": len(cur_bytes),
                            "ts": ts_r,
                        },
                    )
                    pushed_redo = True

                p.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(snap_p), str(p))
                if orig_imode is not None and sys.platform != "win32":
                    with contextlib.suppress(OSError):
                        os.chmod(str(p), orig_imode)
                restored_b = p.read_bytes()
            except OSError as io_exc:
                if redo_file_opt is not None:
                    with contextlib.suppress(OSError):
                        redo_file_opt.unlink(missing_ok=True)
                if pushed_redo:
                    with contextlib.suppress(Exception):
                        _pop_redo_entry(chosen_u_base, p)
                lk_err = check_office_or_os_file_lock(p, exc=io_exc, for_write=True)
                if lk_err is not None:
                    out_lk = dict(lk_err)
                    out_lk["action"] = "undo"
                    return out_lk
                return {
                    "ok": False,
                    "action": "undo",
                    "path": key,
                    "file_locked_by_external_app": True,
                    "error": f"{type(io_exc).__name__}: {io_exc}",
                }

            restored_sha = hashlib.sha256(restored_b).hexdigest().lower()
            with get_file_lock(chosen_u_idx):
                history.pop(0)
                if history:
                    idx_data[hist_key] = history
                else:
                    idx_data.pop(hist_key, None)
                atomic_write_json(chosen_u_idx, idx_data)
            return {
                "ok": True,
                "action": "undo",
                "undone_op": "edit",
                "path": key,
                "existed_before": True,
                "restored_from": str(snap_p),
                "sha256": restored_sha,
                "restored_bytes": len(restored_b),
                "remaining_snapshots": len(history),
                "can_redo": True,
            }


def list_undo_snapshots(
    limit: int = 20,
    *,
    workspace_root: Optional[Union[str, Path]] = None,
    workspace_roots: Optional[Sequence[Union[str, Path]]] = None,
    undo_dir: Optional[Union[str, Path]] = None,
    state_root: Optional[Union[str, Path]] = None,
    guard: Optional[Any] = None,
    redo: bool = False,
) -> List[Dict[str, Any]]:
    """List files with available undo (or redo) operations/snapshots."""
    allowed_roots = _resolve_allowed_roots(workspace_root=workspace_root, workspace_roots=workspace_roots)
    explicit_ws = allowed_roots[0] if len(allowed_roots) == 1 else None
    idx_filename = "redo_index.json" if redo else "index.json"
    cand_bases = _candidate_undo_bases(
        None,
        workspace_root=workspace_root,
        workspace_roots=workspace_roots,
        undo_dir=undo_dir,
        state_root=state_root,
        guard=guard,
    )
    cand_indexes = [b / idx_filename for b in cand_bases]

    seen_norm: set[str] = set()
    entries: List[Dict[str, Any]] = []
    for idx_p in cand_indexes:
        if not idx_p.is_file():
            continue
        try:
            with get_file_lock(idx_p):
                raw_map = json.loads(idx_p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(raw_map, dict):
            continue
        for raw_k, h_list in raw_map.items():
            if not isinstance(h_list, list) or not h_list:
                continue
            orig_str = str(raw_k or "").strip()
            if not orig_str:
                continue
            orig_p = Path(orig_str).resolve()
            if allowed_roots and not any(_is_under_dir(orig_p, ws_r) for ws_r in allowed_roots):
                continue
            norm_k = os.path.normcase(str(orig_p))
            if norm_k in seen_norm:
                continue
            latest = h_list[0] if isinstance(h_list[0], dict) else {}
            op_kind = str(latest.get("op") or ("edit" if latest.get("existed_before", True) else "create"))
            existed_b = bool(latest.get("existed_before", True))
            snap_field = "redo_path" if redo else "snap_path"
            raw_snap = str(latest.get(snap_field) or "").strip()
            if op_kind == "edit" and raw_snap and not Path(raw_snap).is_file():
                continue
            if op_kind in ("create", "move", "rename") and not redo and not orig_p.exists():
                continue
            if op_kind == "trash" and not redo:
                tp_s = str(latest.get("trash_path") or "").strip()
                if tp_s and not Path(tp_s).exists():
                    continue
            seen_norm.add(norm_k)
            rel_s = (
                orig_p.relative_to(explicit_ws).as_posix()
                if (explicit_ws is not None and _is_under_dir(orig_p, explicit_ws))
                else str(orig_p)
            )
            entry_d: Dict[str, Any] = {
                "path": str(orig_p),
                "rel_path": rel_s,
                "op": op_kind,
                "snapshot_count": len(h_list),
                "latest_at": _format_trashed_at(latest),
                "existed_before": existed_b,
                "bytes": int(latest.get("bytes") or 0),
                "_sort_key": (int(latest.get("ts") or 0), int(latest.get("op_seq") or 0)),
            }
            if op_kind in ("move", "rename") and latest.get("src_path"):
                entry_d["src_path"] = str(latest["src_path"])
            if op_kind == "trash" and latest.get("trash_id"):
                entry_d["trash_id"] = str(latest["trash_id"])
            entries.append(entry_d)
    entries.sort(key=lambda x: x.get("_sort_key", (0, 0)), reverse=True)
    for it in entries:
        it.pop("_sort_key", None)
    cap = max(1, min(200, int(limit or 20)))
    return entries[:cap]
