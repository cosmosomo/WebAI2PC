"""Cross-platform zero-dependency native folder picker (`pick_directory_native`).

Enforces:
- 100% Python standard library across Windows, macOS, and Linux.
- Process-wide non-blocking `threading.Lock(blocking=False)` preventing concurrent multi-popup storms
  when the user double-clicks the "浏览选择文件夹…" button in Cosmos Studio.
- Windows: spawns a short-lived isolated `pythonw.exe -B -c <script>` subprocess (`stdin=subprocess.DEVNULL`,
  `CREATE_NO_WINDOW`) ONLY when triggered by explicit user click on the local Studio route.
  Inside the helper, prefers 64-bit Win32 COM `IFileOpenDialog` (`FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_NOCHANGEDIR`,
  zero `_tkinter` requirement), falling back to `SHBrowseForFolderW` and `tkinter.filedialog.askdirectory`.
- macOS: verifies interactive Aqua GUI session before invoking `/usr/bin/osascript` (`choose folder`).
- Linux: checks `DISPLAY` or `WAYLAND_DISPLAY` and tries `zenity` then `kdialog`.
- Headless / non-interactive environments return `{"ok": False, "fallback": "in_page_tree", "reason": "headless_environment"}`.
"""
from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
from typing import Any, Dict, Mapping, Optional

from cosmos_mcp.core.proc import CREATE_NO_WINDOW
from cosmos_mcp.launcher.bootstrap import resolve_windowless_python

_PICKER_LOCK = threading.Lock()

UOI_FLAGS = 1
WSF_VISIBLE = 0x0001


class _USEROBJECTFLAGS(ctypes.Structure):
    _fields_ = [
        ("fInherit", wintypes.BOOL),
        ("fReserved", wintypes.BOOL),
        ("dwFlags", wintypes.DWORD),
    ]


def _normalize_selected_dir(raw_path: str) -> str:
    clean = str(raw_path or "").strip()
    if not clean:
        return ""
    return str(Path(clean).expanduser().resolve())


def _is_windows_interactive_desktop(env: Optional[Mapping[str, str]] = None) -> bool:
    if sys.platform != "win32":
        return False
    eff_env = env if env is not None else os.environ
    if str(eff_env.get("COSMOS_HEADLESS_PICKER") or "").strip().lower() in ("1", "true", "yes", "on"):
        return False
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        u32 = ctypes.WinDLL("user32", use_last_error=True)
        k32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        k32.ProcessIdToSessionId.restype = wintypes.BOOL
        u32.GetProcessWindowStation.argtypes = []
        u32.GetProcessWindowStation.restype = wintypes.HANDLE
        u32.GetUserObjectInformationW.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        u32.GetUserObjectInformationW.restype = wintypes.BOOL

        sess_id = wintypes.DWORD(0)
        if k32.ProcessIdToSessionId(wintypes.DWORD(os.getpid()), ctypes.byref(sess_id)):
            if int(sess_id.value) == 0:
                return False
        hwinsta = u32.GetProcessWindowStation()
        if not hwinsta:
            return False
        uof = _USEROBJECTFLAGS()
        needed = wintypes.DWORD(0)
        if u32.GetUserObjectInformationW(hwinsta, UOI_FLAGS, ctypes.byref(uof), ctypes.sizeof(uof), ctypes.byref(needed)):
            if (int(uof.dwFlags) & WSF_VISIBLE) == 0:
                return False
        return True
    except Exception:
        return False


_WIN32_PICKER_HELPER_SCRIPT = r"""
import base64
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import sys

payload = json.loads(base64.b64decode(sys.argv[1]).decode("utf-8"))
title = str(payload.get("title") or "选择授权编程目录")
initial_dir = str(payload.get("initial_dir") or "")
out_file = Path(str(payload["out_file"]))

def _write_out(doc):
    out_file.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")

try:
    u32 = ctypes.WinDLL("user32", use_last_error=True)
    if hasattr(u32, "SetProcessDpiAwarenessContext"):
        u32.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
        u32.SetProcessDpiAwarenessContext.restype = wintypes.BOOL
        u32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
except Exception:
    pass

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_uint8 * 8),
    ]

def _guid(d1, d2, d3, hex8):
    return GUID(d1, d2, d3, (ctypes.c_uint8 * 8)(*bytes.fromhex(hex8)))

def _pick_via_ifileopendialog():
    ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    ole32.CoInitializeEx.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    ole32.CoInitializeEx.restype = ctypes.c_long
    ole32.CoUninitialize.argtypes = []
    ole32.CoUninitialize.restype = None
    ole32.CoCreateInstance.argtypes = [
        ctypes.POINTER(GUID), ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p),
    ]
    ole32.CoCreateInstance.restype = ctypes.c_long
    ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    ole32.CoTaskMemFree.restype = None
    shell32.SHCreateItemFromParsingName.argtypes = [
        wintypes.LPCWSTR, ctypes.c_void_p, ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p),
    ]
    shell32.SHCreateItemFromParsingName.restype = ctypes.c_long

    clsid_fod = _guid(0xDC1C5A9C, 0xE88A, 0x4DDE, "A5A160F82A20AEF7")
    iid_fod = _guid(0xD57C7288, 0xD4AD, 0x4768, "BE029D969532D960")
    iid_si = _guid(0x43826D1E, 0xE718, 0x42EE, "BC55A1E261C37BFE")

    hr_init = int(ole32.CoInitializeEx(None, 0x2))
    need_uninit = hr_init >= 0
    if hr_init < 0 and hr_init != -2147417850:
        raise RuntimeError(f"CoInitializeEx: 0x{hr_init & 0xFFFFFFFF:08X}")
    dlg = ctypes.c_void_p()
    try:
        hr_c = int(ole32.CoCreateInstance(ctypes.byref(clsid_fod), None, 0x1, ctypes.byref(iid_fod), ctypes.byref(dlg)))
        if hr_c < 0 or not dlg.value:
            raise RuntimeError(f"CoCreateInstance: 0x{hr_c & 0xFFFFFFFF:08X}")
        vt = ctypes.cast(ctypes.cast(dlg, ctypes.POINTER(ctypes.c_void_p)).contents.value, ctypes.POINTER(ctypes.c_void_p * 29)).contents
        fn_release = ctypes.WINFUNCTYPE(wintypes.ULONG, ctypes.c_void_p)(vt[2])
        fn_show = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, wintypes.HWND)(vt[3])
        fn_set_opts = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, wintypes.DWORD)(vt[9])
        fn_get_opts = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD))(vt[10])
        fn_set_folder = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p)(vt[12])
        fn_set_title = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, wintypes.LPCWSTR)(vt[17])
        fn_get_result = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))(vt[20])
        try:
            opts = wintypes.DWORD(0)
            fn_get_opts(dlg, ctypes.byref(opts))
            fn_set_opts(dlg, wintypes.DWORD(int(opts.value) | 0x00000020 | 0x00000040 | 0x00000008))
            fn_set_title(dlg, title)
            if initial_dir and Path(initial_dir).is_dir():
                psi_init = ctypes.c_void_p()
                if int(shell32.SHCreateItemFromParsingName(str(Path(initial_dir).resolve()), None, ctypes.byref(iid_si), ctypes.byref(psi_init))) >= 0 and psi_init.value:
                    ivt = ctypes.cast(ctypes.cast(psi_init, ctypes.POINTER(ctypes.c_void_p)).contents.value, ctypes.POINTER(ctypes.c_void_p * 8)).contents
                    i_rel = ctypes.WINFUNCTYPE(wintypes.ULONG, ctypes.c_void_p)(ivt[2])
                    try:
                        fn_set_folder(dlg, psi_init)
                    finally:
                        i_rel(psi_init)
            hr_show = int(fn_show(dlg, None))
            if (hr_show & 0xFFFFFFFF) == 0x800704C7:
                return {"ok": False, "cancelled": True}
            if hr_show < 0:
                raise RuntimeError(f"Show failed: 0x{hr_show & 0xFFFFFFFF:08X}")
            psi_res = ctypes.c_void_p()
            hr_res = int(fn_get_result(dlg, ctypes.byref(psi_res)))
            if hr_res < 0 or not psi_res.value:
                return {"ok": False, "cancelled": True}
            rvt = ctypes.cast(ctypes.cast(psi_res, ctypes.POINTER(ctypes.c_void_p)).contents.value, ctypes.POINTER(ctypes.c_void_p * 8)).contents
            r_rel = ctypes.WINFUNCTYPE(wintypes.ULONG, ctypes.c_void_p)(rvt[2])
            r_name = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p))(rvt[5])
            psz = ctypes.c_void_p()
            try:
                if int(r_name(psi_res, wintypes.DWORD(0x80058000), ctypes.byref(psz))) >= 0 and psz.value:
                    picked = ctypes.wstring_at(psz.value)
                    return {"ok": True, "path": str(Path(picked).resolve())}
                return {"ok": False, "cancelled": True}
            finally:
                if psz.value:
                    ole32.CoTaskMemFree(psz)
                r_rel(psi_res)
        finally:
            fn_release(dlg)
    finally:
        if need_uninit:
            ole32.CoUninitialize()

def _pick_via_shbrowse():
    ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    ole32.CoInitializeEx.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    ole32.CoInitializeEx.restype = ctypes.c_long
    ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    ole32.CoTaskMemFree.restype = None

    class BROWSEINFOW(ctypes.Structure):
        _fields_ = [
            ("hwndOwner", wintypes.HWND),
            ("pidlRoot", ctypes.c_void_p),
            ("pszDisplayName", wintypes.LPWSTR),
            ("lpszTitle", wintypes.LPCWSTR),
            ("ulFlags", wintypes.UINT),
            ("lpfn", ctypes.c_void_p),
            ("lParam", wintypes.LPARAM),
            ("iImage", ctypes.c_int),
        ]

    shell32.SHBrowseForFolderW.argtypes = [ctypes.POINTER(BROWSEINFOW)]
    shell32.SHBrowseForFolderW.restype = ctypes.c_void_p
    shell32.SHGetPathFromIDListW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR]
    shell32.SHGetPathFromIDListW.restype = wintypes.BOOL

    ole32.CoInitializeEx(None, 0x2)
    disp_buf = ctypes.create_unicode_buffer(260)
    bi = BROWSEINFOW()
    bi.hwndOwner = None
    bi.pidlRoot = None
    bi.pszDisplayName = disp_buf
    bi.lpszTitle = title
    bi.ulFlags = 0x0001 | 0x0040
    pidl = shell32.SHBrowseForFolderW(ctypes.byref(bi))
    if not pidl:
        return {"ok": False, "cancelled": True}
    try:
        path_buf = ctypes.create_unicode_buffer(32768)
        if shell32.SHGetPathFromIDListW(pidl, path_buf) and path_buf.value:
            return {"ok": True, "path": str(Path(path_buf.value).resolve())}
        return {"ok": False, "cancelled": True}
    finally:
        ole32.CoTaskMemFree(pidl)

def _pick_via_tkinter():
    import tkinter as tk
    from tkinter import filedialog
    root = tk.Tk()
    root.withdraw()
    try:
        sel = filedialog.askdirectory(title=title, initialdir=initial_dir or None, mustexist=True)
    finally:
        root.destroy()
    if not sel:
        return {"ok": False, "cancelled": True}
    return {"ok": True, "path": str(Path(sel).resolve())}

try:
    res = _pick_via_ifileopendialog()
except Exception:
    try:
        res = _pick_via_shbrowse()
    except Exception:
        try:
            res = _pick_via_tkinter()
        except Exception as exc:
            res = {"ok": False, "fallback": "in_page_tree", "reason": f"win32_picker_unavailable:{exc}"}

_write_out(res)
"""


def _pick_directory_windows(title: str, initial_dir: str, timeout_sec: float) -> Dict[str, Any]:
    if not _is_windows_interactive_desktop():
        return {"ok": False, "fallback": "in_page_tree", "reason": "headless_environment"}

    pyw = resolve_windowless_python(sys.executable)
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONUTF8"] = "1"

    with tempfile.TemporaryDirectory(prefix="cosmos_picker_") as tmp_dir:
        out_path = Path(tmp_dir) / "picked.json"
        payload_b64 = base64.b64encode(
            json.dumps(
                {
                    "title": title,
                    "initial_dir": initial_dir,
                    "out_file": str(out_path),
                },
                ensure_ascii=False,
            ).encode("utf-8")
        ).decode("ascii")
        try:
            proc = subprocess.run(
                [pyw, "-B", "-c", _WIN32_PICKER_HELPER_SCRIPT, payload_b64],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(2.0, float(timeout_sec)),
                env=env,
                creationflags=CREATE_NO_WINDOW,
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "cancelled": True, "reason": "picker_timeout"}
        except Exception as exc:
            return {"ok": False, "fallback": "in_page_tree", "reason": f"picker_spawn_failed:{exc}"}

        if out_path.is_file():
            try:
                doc = json.loads(out_path.read_text(encoding="utf-8"))
                if isinstance(doc, dict):
                    if doc.get("ok") and doc.get("path"):
                        return {"ok": True, "path": _normalize_selected_dir(str(doc["path"]))}
                    return doc
            except Exception:
                pass

        if proc.returncode != 0:
            return {"ok": False, "fallback": "in_page_tree", "reason": "picker_subprocess_failed"}
        return {"ok": False, "cancelled": True}


def _is_macos_gui_session(env: Optional[Mapping[str, str]] = None) -> bool:
    eff_env = env if env is not None else os.environ
    if str(eff_env.get("COSMOS_HEADLESS_PICKER") or "").strip().lower() in ("1", "true", "yes", "on"):
        return False
    if eff_env.get("SSH_CONNECTION") or eff_env.get("SSH_TTY"):
        return False
    if not os.path.isfile("/usr/bin/osascript"):
        return False
    launchctl = shutil.which("launchctl")
    if launchctl:
        try:
            res = subprocess.run(
                [launchctl, "managername"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=3.0,
            )
            if res.returncode == 0 and res.stdout.strip() and res.stdout.strip() != "Aqua":
                return False
        except Exception:
            pass
    return True


def _pick_directory_macos(title: str, initial_dir: str, timeout_sec: float) -> Dict[str, Any]:
    if not _is_macos_gui_session():
        return {"ok": False, "fallback": "in_page_tree", "reason": "headless_environment"}

    start_dir = str(Path(initial_dir).expanduser().resolve()) if (initial_dir and Path(initial_dir).expanduser().is_dir()) else ""
    if start_dir:
        applescript = (
            "on run argv\n"
            "  set pTitle to item 1 of argv\n"
            "  set pInit to POSIX file (item 2 of argv)\n"
            "  return POSIX path of (choose folder with prompt pTitle default location pInit)\n"
            "end run"
        )
        cmd = ["/usr/bin/osascript", "-e", applescript, title, start_dir]
    else:
        applescript = (
            "on run argv\n"
            "  set pTitle to item 1 of argv\n"
            "  return POSIX path of (choose folder with prompt pTitle)\n"
            "end run"
        )
        cmd = ["/usr/bin/osascript", "-e", applescript, title]

    try:
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(2.0, float(timeout_sec)),
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "cancelled": True, "reason": "picker_timeout"}
    except Exception:
        return {"ok": False, "fallback": "in_page_tree", "reason": "headless_environment"}

    if proc.returncode == 0 and (proc.stdout or "").strip():
        return {"ok": True, "path": _normalize_selected_dir(proc.stdout.strip())}
    err_low = (proc.stderr or "").lower()
    if "(-128)" in err_low or "canceled" in err_low or "cancelled" in err_low:
        return {"ok": False, "cancelled": True}
    return {"ok": False, "fallback": "in_page_tree", "reason": "headless_environment"}


def _pick_directory_linux(title: str, initial_dir: str, timeout_sec: float, env: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    eff_env = env if env is not None else os.environ
    if str(eff_env.get("COSMOS_HEADLESS_PICKER") or "").strip().lower() in ("1", "true", "yes", "on"):
        return {"ok": False, "fallback": "in_page_tree", "reason": "headless_environment"}
    if not (eff_env.get("DISPLAY") or eff_env.get("WAYLAND_DISPLAY")):
        return {"ok": False, "fallback": "in_page_tree", "reason": "headless_environment"}

    start_dir = str(Path(initial_dir).expanduser().resolve()) if (initial_dir and Path(initial_dir).expanduser().is_dir()) else str(Path.home())
    candidates = []
    zenity_bin = shutil.which("zenity")
    if zenity_bin:
        z_cmd = [zenity_bin, "--file-selection", "--directory", f"--title={title}", f"--filename={start_dir.rstrip('/')}/"]
        candidates.append(z_cmd)
    kdialog_bin = shutil.which("kdialog")
    if kdialog_bin:
        candidates.append([kdialog_bin, "--getexistingdirectory", start_dir, "--title", title])

    if not candidates:
        return {"ok": False, "fallback": "in_page_tree", "reason": "headless_environment"}

    for cmd in candidates:
        try:
            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(2.0, float(timeout_sec)),
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "cancelled": True, "reason": "picker_timeout"}
        except Exception:
            continue

        if proc.returncode == 0 and (proc.stdout or "").strip():
            selected = proc.stdout.strip().splitlines()[-1].strip()
            return {"ok": True, "path": _normalize_selected_dir(selected)}
        if proc.returncode == 1:
            return {"ok": False, "cancelled": True}

    return {"ok": False, "fallback": "in_page_tree", "reason": "headless_environment"}


def pick_directory_native(
    *,
    title: str = "选择授权编程目录",
    initial_dir: str = "",
    timeout_sec: float = 120.0,
) -> Dict[str, Any]:
    """Open native OS folder selection dialog with non-blocking concurrency lock and headless fallback."""
    if not _PICKER_LOCK.acquire(blocking=False):
        return {"ok": False, "busy": True, "reason": "picker_already_open"}
    try:
        eff_title = (title or "选择授权编程目录").strip() or "选择授权编程目录"
        eff_init = (initial_dir or "").strip()
        if sys.platform == "win32":
            return _pick_directory_windows(eff_title, eff_init, timeout_sec)
        if sys.platform == "darwin":
            return _pick_directory_macos(eff_title, eff_init, timeout_sec)
        return _pick_directory_linux(eff_title, eff_init, timeout_sec)
    finally:
        _PICKER_LOCK.release()
