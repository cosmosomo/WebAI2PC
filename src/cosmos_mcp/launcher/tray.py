"""64-bit pure-stdlib Windows system tray controller (`WindowsSystemTrayController`).

Enforces:
- Zero third-party dependencies: pure `ctypes` (`user32`, `shell32`, `gdi32`, `kernel32`).
- Dynamic High-DPI GDI `CreateIconIndirect` circle status icon (`16x16` / `32x32`):
  - Ready & public tunnel online : `#34C759` (emerald green)
  - Local / tunnel connecting    : `#0071E3` (apple blue)
  - Read-only protection mode    : `#FF9F0A` (amber orange)
  - Error / crash recovery       : `#FF3B30` (red)
- Full 64-bit pointer/handle `argtypes` & `restype` declarations (`WNDPROCTYPE`, `DefWindowProcW`,
  `CreatePopupMenu`, `AppendMenuW`, `TrackPopupMenu`, `PostMessageW`, `Shell_NotifyIconW`).
- Explorer restart self-healing via `RegisterWindowMessageW("TaskbarCreated")`.
- Zero disk/network/process I/O inside `WM_RBUTTONUP`: reads atomic in-memory snapshot pushed by
  `StandaloneSupervisorLoop.update_snapshot(...)` in 0ms and dispatches menu actions on `daemon=True` worker threads.
- Zero background clipboard writes: Win32 `OpenClipboard` is invoked ONLY when the user clicks "复制 MCP 连接地址" or "复制首句唤醒词".
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple
import webbrowser

from cosmos_mcp.core.fs_tx import atomic_write_json, atomic_write_text, get_file_lock
from cosmos_mcp.core.proc import CREATE_NO_WINDOW

# Visual palette (R, G, B)
COLOR_READY_GREEN: Tuple[int, int, int] = (0x34, 0xC7, 0x59)   # #34C759
COLOR_LOCAL_BLUE: Tuple[int, int, int] = (0x00, 0x71, 0xE3)    # #0071E3
COLOR_READONLY_AMBER: Tuple[int, int, int] = (0xFF, 0x9F, 0x0A)  # #FF9F0A
COLOR_ERROR_RED: Tuple[int, int, int] = (0xFF, 0x3B, 0x30)     # #FF3B30

TRAY_STATE_COLORS: Dict[str, Tuple[int, int, int]] = {
    "ready": COLOR_READY_GREEN,
    "connecting": COLOR_LOCAL_BLUE,
    "readonly": COLOR_READONLY_AMBER,
    "error": COLOR_ERROR_RED,
}

# Context menu command IDs
MENU_ID_HEADER = 1000
MENU_ID_OPEN_STUDIO = 1001
MENU_ID_COPY_MCP_URL = 1002
MENU_ID_TOGGLE_READONLY = 1003
MENU_ID_REVOKE_ALL = 1004
MENU_ID_STOP_EXIT = 1005
MENU_ID_COPY_WAKE_PROMPT = 1006
MENU_ID_START_RESUME = 1007

DEFAULT_WAKE_CONNECTOR_NAME = "Cosmos"
DEFAULT_WAKE_PROMPT_SUFFIX = "帮我看看当前工作目录里有哪些文件"

# Win32 window & tray constants
WM_NULL = 0x0000
WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_USER = 0x0400
WM_TRAYICON = WM_USER + 20
WM_TRAY_SYNC_STATE = WM_USER + 21
WM_TRAY_SHUTDOWN = WM_USER + 22
WM_TRAY_BALLOON = WM_USER + 23

WM_LBUTTONUP = 0x0202
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205
WM_CONTEXTMENU = 0x007B

NIM_ADD = 0x00000000
NIM_MODIFY = 0x00000001
NIM_DELETE = 0x00000002

NIF_MESSAGE = 0x00000001
NIF_ICON = 0x00000002
NIF_TIP = 0x00000004
NIF_INFO = 0x00000010

NIIF_WARNING = 0x00000002
NIIF_NOSOUND = 0x00000020

MF_STRING = 0x00000000
MF_GRAYED = 0x00000001
MF_DISABLED = 0x00000002
MF_SEPARATOR = 0x00000800

TPM_LEFTALIGN = 0x0000
TPM_BOTTOMALIGN = 0x0020
TPM_NONOTIFY = 0x0080
TPM_RETURNCMD = 0x0100
TPM_RIGHTBUTTON = 0x0002

WS_EX_TOOLWINDOW = 0x00000080
WS_EX_NOACTIVATE = 0x08000000

SM_CXSMICON = 49
UOI_FLAGS = 1
WSF_VISIBLE = 0x0001
ERROR_ACCESS_DENIED = 5
ERROR_ALREADY_EXISTS = 183

CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002

LRESULT = ctypes.c_ssize_t
ULONG_PTR = ctypes.c_size_t

if sys.platform == "win32":
    WNDPROCTYPE = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
else:
    WNDPROCTYPE = None  # type: ignore[assignment]


class USEROBJECTFLAGS(ctypes.Structure):
    _fields_ = [
        ("fInherit", wintypes.BOOL),
        ("fReserved", wintypes.BOOL),
        ("dwFlags", wintypes.DWORD),
    ]


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class ICONINFO(ctypes.Structure):
    _fields_ = [
        ("fIcon", wintypes.BOOL),
        ("xHotspot", wintypes.DWORD),
        ("yHotspot", wintypes.DWORD),
        ("hbmMask", wintypes.HBITMAP),
        ("hbmColor", wintypes.HBITMAP),
    ]


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HICON),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uTimeoutOrVersion", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
    ]


class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROCTYPE if WNDPROCTYPE is not None else ctypes.c_void_p),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


_WIN32_APIS_CACHE: Optional[Tuple[Any, Any, Any, Any]] = None
_WIN32_APIS_LOCK = threading.Lock()


def _bind_win32_apis() -> Tuple[Any, Any, Any, Any]:
    """Load `user32`, `shell32`, `gdi32`, `kernel32` with complete 64-bit `argtypes` and `restype`."""
    global _WIN32_APIS_CACHE
    if sys.platform != "win32":
        raise RuntimeError("Win32 tray APIs are only available on Windows.")
    with _WIN32_APIS_LOCK:
        if _WIN32_APIS_CACHE is not None:
            return _WIN32_APIS_CACHE

        u32 = ctypes.WinDLL("user32", use_last_error=True)
        sh32 = ctypes.WinDLL("shell32", use_last_error=True)
        gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)

        # kernel32 64-bit signatures
        k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        k32.GetModuleHandleW.restype = wintypes.HMODULE
        k32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        k32.ProcessIdToSessionId.restype = wintypes.BOOL
        k32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        k32.CreateMutexW.restype = wintypes.HANDLE
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL
        k32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        k32.GlobalAlloc.restype = wintypes.HANDLE
        k32.GlobalLock.argtypes = [wintypes.HANDLE]
        k32.GlobalLock.restype = ctypes.c_void_p
        k32.GlobalUnlock.argtypes = [wintypes.HANDLE]
        k32.GlobalUnlock.restype = wintypes.BOOL
        k32.GlobalFree.argtypes = [wintypes.HANDLE]
        k32.GlobalFree.restype = wintypes.HANDLE

        # user32 64-bit signatures
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
        u32.GetSystemMetrics.argtypes = [ctypes.c_int]
        u32.GetSystemMetrics.restype = ctypes.c_int
        u32.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
        u32.RegisterWindowMessageW.restype = wintypes.UINT
        u32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
        u32.RegisterClassW.restype = wintypes.ATOM
        u32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
        u32.UnregisterClassW.restype = wintypes.BOOL
        u32.CreateWindowExW.argtypes = [
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.HWND,
            wintypes.HMENU,
            wintypes.HINSTANCE,
            wintypes.LPVOID,
        ]
        u32.CreateWindowExW.restype = wintypes.HWND
        u32.DestroyWindow.argtypes = [wintypes.HWND]
        u32.DestroyWindow.restype = wintypes.BOOL
        u32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        u32.DefWindowProcW.restype = LRESULT
        u32.CreatePopupMenu.argtypes = []
        u32.CreatePopupMenu.restype = wintypes.HMENU
        u32.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, ULONG_PTR, wintypes.LPCWSTR]
        u32.AppendMenuW.restype = wintypes.BOOL
        u32.TrackPopupMenu.argtypes = [
            wintypes.HMENU,
            wintypes.UINT,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.HWND,
            ctypes.c_void_p,
        ]
        u32.TrackPopupMenu.restype = wintypes.INT
        u32.DestroyMenu.argtypes = [wintypes.HMENU]
        u32.DestroyMenu.restype = wintypes.BOOL
        u32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
        u32.GetCursorPos.restype = wintypes.BOOL
        u32.SetForegroundWindow.argtypes = [wintypes.HWND]
        u32.SetForegroundWindow.restype = wintypes.BOOL
        u32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        u32.PostMessageW.restype = wintypes.BOOL
        u32.PostQuitMessage.argtypes = [ctypes.c_int]
        u32.PostQuitMessage.restype = None
        u32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
        u32.GetMessageW.restype = ctypes.c_int
        u32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        u32.TranslateMessage.restype = wintypes.BOOL
        u32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
        u32.DispatchMessageW.restype = LRESULT
        u32.CreateIconIndirect.argtypes = [ctypes.POINTER(ICONINFO)]
        u32.CreateIconIndirect.restype = wintypes.HICON
        u32.DestroyIcon.argtypes = [wintypes.HICON]
        u32.DestroyIcon.restype = wintypes.BOOL
        u32.OpenClipboard.argtypes = [wintypes.HWND]
        u32.OpenClipboard.restype = wintypes.BOOL
        u32.EmptyClipboard.argtypes = []
        u32.EmptyClipboard.restype = wintypes.BOOL
        u32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
        u32.SetClipboardData.restype = wintypes.HANDLE
        u32.CloseClipboard.argtypes = []
        u32.CloseClipboard.restype = wintypes.BOOL

        # gdi32 64-bit signatures
        gdi32.CreateDIBSection.argtypes = [
            wintypes.HDC,
            ctypes.POINTER(BITMAPINFOHEADER),
            wintypes.UINT,
            ctypes.POINTER(ctypes.c_void_p),
            wintypes.HANDLE,
            wintypes.DWORD,
        ]
        gdi32.CreateDIBSection.restype = wintypes.HBITMAP
        gdi32.CreateBitmap.argtypes = [ctypes.c_int, ctypes.c_int, wintypes.UINT, wintypes.UINT, ctypes.c_void_p]
        gdi32.CreateBitmap.restype = wintypes.HBITMAP
        gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
        gdi32.DeleteObject.restype = wintypes.BOOL

        # shell32 64-bit signatures
        sh32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
        sh32.Shell_NotifyIconW.restype = wintypes.BOOL

        _WIN32_APIS_CACHE = (u32, sh32, gdi32, k32)
        return _WIN32_APIS_CACHE


def _norm_prefix(prefix: str) -> str:
    val = (prefix or "pc").strip().lower()
    return val if val else "pc"


def _compute_state_fp(state_root: Path) -> str:
    norm = os.path.normcase(str(Path(state_root).expanduser().resolve()))
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:12]


def build_tray_mutex_name(state_root: Path, prefix: str = "pc") -> str:
    fp = _compute_state_fp(state_root)
    eff = _norm_prefix(prefix)
    return f"Local\\CosmosMcpTray_{fp}_{eff}"


def probe_windows_tray_eligibility(
    state_root: Optional[Path] = None,
    prefix: str = "pc",
    *,
    env: Optional[Mapping[str, str]] = None,
    check_mutex: bool = True,
) -> Tuple[bool, str]:
    """Inspect whether the current process can safely attach a Windows system tray icon."""
    if sys.platform != "win32":
        return False, "non_windows"

    eff_env = env if env is not None else os.environ
    no_tray_val = str(eff_env.get("COSMOS_NO_TRAY") or "").strip().lower()
    if no_tray_val in ("1", "true", "yes", "on"):
        return False, "env_cosmos_no_tray"

    try:
        u32, _, _, k32 = _bind_win32_apis()
    except Exception as exc:
        return False, f"win32_bind_failed:{exc}"

    session_id = wintypes.DWORD(0)
    if k32.ProcessIdToSessionId(wintypes.DWORD(os.getpid()), ctypes.byref(session_id)):
        if int(session_id.value) == 0:
            return False, "session_0_service"

    hwinsta = u32.GetProcessWindowStation()
    if not hwinsta:
        return False, "missing_window_station"
    uof = USEROBJECTFLAGS()
    needed = wintypes.DWORD(0)
    if u32.GetUserObjectInformationW(
        hwinsta,
        UOI_FLAGS,
        ctypes.byref(uof),
        ctypes.sizeof(uof),
        ctypes.byref(needed),
    ):
        if (int(uof.dwFlags) & WSF_VISIBLE) == 0:
            return False, "non_interactive_window_station"

    if check_mutex and state_root is not None:
        mutex_name = build_tray_mutex_name(state_root, prefix)
        ctypes.set_last_error(0)
        h_probe = k32.CreateMutexW(None, False, mutex_name)
        err = ctypes.get_last_error()
        if not h_probe:
            if err == ERROR_ACCESS_DENIED:
                return False, "mutex_access_denied"
            return False, f"mutex_create_failed:{err}"
        try:
            if err == ERROR_ALREADY_EXISTS:
                return False, "mutex_already_held"
        finally:
            k32.CloseHandle(h_probe)

    return True, "ok"


def render_status_dot_bgra(rgb: Tuple[int, int, int], size: int = 32) -> Tuple[bytes, bytes]:
    """Render an anti-aliased status circle dot as `(bgra_bytes, mask_1bpp_bytes)` for `CreateIconIndirect`."""
    dim = 16 if int(size) <= 20 else 32
    r_in, g_in, b_in = int(rgb[0]) & 0xFF, int(rgb[1]) & 0xFF, int(rgb[2]) & 0xFF

    cx = (dim - 1) / 2.0
    cy = (dim - 1) / 2.0
    outer_r = dim * 0.41
    ring_inner_r = outer_r - max(1.15, dim * 0.055)

    bgra = bytearray(dim * dim * 4)
    stride_mask = ((dim + 31) // 32) * 4
    mask = bytearray(stride_mask * dim)

    for y in range(dim):
        for x in range(dim):
            dist = math.hypot(x - cx, y - cy)
            # Smooth 1px anti-aliased edge
            coverage = max(0.0, min(1.0, (outer_r + 0.55) - dist))
            idx = (y * dim + x) * 4
            if coverage <= 0.0:
                bgra[idx : idx + 4] = b"\x00\x00\x00\x00"
                byte_pos = y * stride_mask + (x >> 3)
                mask[byte_pos] |= 0x80 >> (x & 7)
                continue

            # Subtle white contrast rim around the status dot for visibility on both dark & light taskbars
            ring_t = max(0.0, min(1.0, dist - ring_inner_r))
            pr = int(round(r_in * (1.0 - 0.22 * ring_t) + 255.0 * (0.22 * ring_t)))
            pg = int(round(g_in * (1.0 - 0.22 * ring_t) + 255.0 * (0.22 * ring_t)))
            pb = int(round(b_in * (1.0 - 0.22 * ring_t) + 255.0 * (0.22 * ring_t)))
            pa = int(round(255.0 * coverage))

            # Premultiplied BGRA for crisp compositing in Windows Shell notification area
            bgra[idx] = (pb * pa) // 255
            bgra[idx + 1] = (pg * pa) // 255
            bgra[idx + 2] = (pr * pa) // 255
            bgra[idx + 3] = pa

    return bytes(bgra), bytes(mask)


def create_status_dot_hicon(rgb: Tuple[int, int, int], size: Optional[int] = None) -> int:
    """Create a native Win32 `HICON` via GDI `CreateDIBSection` + `CreateIconIndirect` without leaking bitmaps."""
    u32, _, gdi32, _ = _bind_win32_apis()
    if size is None:
        sm_w = int(u32.GetSystemMetrics(SM_CXSMICON) or 16)
        dim = 16 if sm_w <= 20 else 32
    else:
        dim = 16 if int(size) <= 20 else 32

    bgra_bytes, mask_bytes = render_status_dot_bgra(rgb, size=dim)

    bmi = BITMAPINFOHEADER()
    bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bmi.biWidth = dim
    bmi.biHeight = -dim  # top-down DIB
    bmi.biPlanes = 1
    bmi.biBitCount = 32
    bmi.biCompression = 0
    bmi.biSizeImage = len(bgra_bytes)

    bits_ptr = ctypes.c_void_p()
    hbm_color = gdi32.CreateDIBSection(None, ctypes.byref(bmi), 0, ctypes.byref(bits_ptr), None, 0)
    if not hbm_color or not bits_ptr.value:
        if hbm_color:
            gdi32.DeleteObject(hbm_color)
        return 0

    hbm_mask = None
    try:
        ctypes.memmove(bits_ptr.value, bgra_bytes, len(bgra_bytes))
        mask_buf = ctypes.create_string_buffer(mask_bytes, len(mask_bytes))
        hbm_mask = gdi32.CreateBitmap(dim, dim, 1, 1, ctypes.cast(mask_buf, ctypes.c_void_p))
        if not hbm_mask:
            return 0
        ii = ICONINFO()
        ii.fIcon = True
        ii.xHotspot = 0
        ii.yHotspot = 0
        ii.hbmMask = hbm_mask
        ii.hbmColor = hbm_color
        hicon = u32.CreateIconIndirect(ctypes.byref(ii))
        return int(hicon) if hicon else 0
    finally:
        if hbm_mask:
            gdi32.DeleteObject(hbm_mask)
        if hbm_color:
            gdi32.DeleteObject(hbm_color)


def resolve_tray_visual_state(snapshot: Mapping[str, Any]) -> Tuple[str, str, Tuple[int, int, int]]:
    """Map an in-memory daemon snapshot to `(state_key, status_zh, rgb_color)` in 0ms."""
    status_str = str(snapshot.get("status") or "running").strip().lower()
    last_err = str(snapshot.get("last_error") or "").strip()
    consec_fail = int(snapshot.get("consecutive_failures") or snapshot.get("tunnel_consecutive_failures") or 0)
    srv_alive = snapshot.get("server_alive")
    tier = str(snapshot.get("permission_tier") or "tier3_workspace_dev").strip().lower()
    mode = str(snapshot.get("mode") or snapshot.get("tunnel_mode") or "local").strip().lower() or "local"
    tun_ready = bool(snapshot.get("tunnel_ready"))

    if status_str in ("error", "restarting_backoff", "stopped") or (srv_alive is False and status_str != "starting"):
        if status_str == "restarting_backoff":
            return "error", "异常重连中", COLOR_ERROR_RED
        return "error", "服务异常", COLOR_ERROR_RED

    gws_snap = snapshot.get("gateways")
    any_gw_ready = bool(snapshot.get("any_gateway_ready"))
    if not any_gw_ready and isinstance(gws_snap, Mapping):
        any_gw_ready = any(
            isinstance(gv, Mapping)
            and bool(gv.get("enabled"))
            and (bool(gv.get("ready")) or str(gv.get("state") or "").lower() == "ready")
            for gv in gws_snap.values()
        )
    eff_tun_ready = any_gw_ready or (mode != "local" and tun_ready)

    if not eff_tun_ready and (consec_fail >= 3 or bool(last_err)):
        if consec_fail >= 3:
            return "error", "异常重连中", COLOR_ERROR_RED
        return "error", "服务异常", COLOR_ERROR_RED

    if tier == "tier1_readonly":
        return "readonly", "只读保护模式", COLOR_READONLY_AMBER

    if eff_tun_ready:
        return "ready", "公网就绪", COLOR_READY_GREEN

    if mode == "local":
        return "connecting", "本机直连", COLOR_LOCAL_BLUE
    return "connecting", "连接中", COLOR_LOCAL_BLUE


def format_tray_tooltip(snapshot: Mapping[str, Any]) -> str:
    """Format <=127-char Win32 notification tooltip from in-memory snapshot."""
    port = int(snapshot.get("port") or 8096)
    state_key, label_zh, _ = resolve_tray_visual_state(snapshot)
    reason_zh = str(snapshot.get("last_disconnect_reason_zh") or "").strip()
    if state_key == "error" and reason_zh:
        return f"Cosmos MCP (:{port} · {label_zh} · {reason_zh})"[:127]
    return f"Cosmos MCP (:{port} · {label_zh})"[:127]


def format_wake_test_prompt(snapshot: Mapping[str, Any]) -> str:
    """Format first-turn `@Cosmos ...` wake prompt from in-memory snapshot with ZERO I/O."""
    raw_prompt = str(snapshot.get("wake_prompt") or "").strip()
    if raw_prompt:
        return raw_prompt
    raw_name = str(snapshot.get("connector_name") or DEFAULT_WAKE_CONNECTOR_NAME).strip() or DEFAULT_WAKE_CONNECTOR_NAME
    if raw_name.startswith("\x40"):
        raw_name = raw_name[1:].strip() or DEFAULT_WAKE_CONNECTOR_NAME
    return f"\x40{raw_name} {DEFAULT_WAKE_PROMPT_SUFFIX}"


def build_tray_menu_items(snapshot: Mapping[str, Any]) -> List[Tuple[int, int, str]]:
    """Construct right-click popup menu tuples `(uFlags, uIDNewItem, lpNewItem)` with ZERO I/O."""
    port = int(snapshot.get("port") or 8096)
    _, label_zh, _ = resolve_tray_visual_state(snapshot)
    status_str = str(snapshot.get("status") or "running").strip().lower()
    tier = str(snapshot.get("permission_tier") or "tier3_workspace_dev").strip().lower()
    prev_tier = str(snapshot.get("previous_non_readonly_tier") or "tier3_workspace_dev").strip().lower()
    restore_labels = {
        "tier2_workspace_edit": "恢复仅修改文件模式",
        "tier3_workspace_dev": "恢复工作区内顺畅开发模式",
        "tier4_full_power": "恢复全盘顺畅开发模式",
    }
    toggle_label = (
        restore_labels.get(prev_tier, "恢复工作区内顺畅开发模式")
        if tier == "tier1_readonly"
        else "切换为只读安全模式"
    )
    mode = str(snapshot.get("mode") or snapshot.get("tunnel_mode") or "public_gateway").strip().lower() or "public_gateway"
    raw_mcp = str(snapshot.get("mcp_url") or "").strip()
    copy_ready = True if mode == "local" else raw_mcp.startswith("https://")
    copy_flags = MF_STRING if copy_ready else (MF_STRING | MF_GRAYED)
    copy_label = "复制 MCP 连接地址" if copy_ready else "正在建立加密连接…"

    items: List[Tuple[int, int, str]] = [
        (MF_STRING | MF_GRAYED, MENU_ID_HEADER, f"Cosmos MCP (:{port} · {label_zh})"),
        (MF_SEPARATOR, 0, ""),
        (MF_STRING, MENU_ID_OPEN_STUDIO, "打开控制台面板"),
        (copy_flags, MENU_ID_COPY_MCP_URL, copy_label),
        (MF_STRING, MENU_ID_COPY_WAKE_PROMPT, "复制首句唤醒词"),
        (MF_SEPARATOR, 0, ""),
        (MF_STRING, MENU_ID_TOGGLE_READONLY, toggle_label),
        (MF_STRING, MENU_ID_REVOKE_ALL, "断开全部已授权连接"),
        (MF_SEPARATOR, 0, ""),
    ]
    if status_str == "stopped":
        items.append((MF_STRING, MENU_ID_START_RESUME, "启动后台服务"))
    items.append((MF_STRING, MENU_ID_STOP_EXIT, "停止服务并退出"))
    return items


def copy_text_to_win32_clipboard(text: str) -> bool:
    """Write UTF-16LE Unicode text to Windows clipboard ONLY on explicit user menu click."""
    clean = str(text or "")
    if not clean or sys.platform != "win32":
        return False
    u32, _, _, k32 = _bind_win32_apis()
    encoded = clean.encode("utf-16le") + b"\x00\x00"

    opened = False
    for _ in range(4):
        if u32.OpenClipboard(None):
            opened = True
            break
        time.sleep(0.02)
    if not opened:
        return False

    hmem = None
    transferred = False
    try:
        u32.EmptyClipboard()
        hmem = k32.GlobalAlloc(GMEM_MOVEABLE, len(encoded))
        if not hmem:
            return False
        locked_ptr = k32.GlobalLock(hmem)
        if not locked_ptr:
            return False
        try:
            ctypes.memmove(locked_ptr, encoded, len(encoded))
        finally:
            k32.GlobalUnlock(hmem)
        if u32.SetClipboardData(CF_UNICODETEXT, hmem):
            transferred = True
            return True
        return False
    finally:
        if hmem and not transferred:
            k32.GlobalFree(hmem)
        u32.CloseClipboard()


def _open_local_studio_url(url: str) -> None:
    target = str(url or "").strip()
    if not target:
        return
    if sys.platform == "win32":
        try:
            os.startfile(target)  # type: ignore[attr-defined]
            return
        except Exception:
            try:
                subprocess.Popen(
                    ["rundll32.exe", "url.dll,FileProtocolHandler", target],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=CREATE_NO_WINDOW,
                )
                return
            except Exception:
                pass
    webbrowser.open(target)


def apply_tray_permission_toggle(state_root: Path, prefix: str = "pc", current_tier: str = "") -> Dict[str, Any]:
    """Atomically toggle `permission_tier` between `tier1_readonly` and remembered `previous_non_readonly_tier`."""
    st_root = Path(state_root).expanduser().resolve()
    eff_p = _norm_prefix(prefix)
    svc_name = f"service_{eff_p}.json" if eff_p != "pc" else "service.json"
    cfg_path = st_root / "config" / svc_name
    state_svc_path = st_root / "state" / svc_name
    state_dir = st_root / "state"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)

    non_ro_tiers = ("tier2_workspace_edit", "tier3_workspace_dev", "tier4_full_power")
    with get_file_lock(cfg_path):
        doc: Dict[str, Any] = {}
        if cfg_path.is_file():
            raw_txt = cfg_path.read_text(encoding="utf-8-sig")
            if raw_txt.strip():
                loaded = json.loads(raw_txt)
                if isinstance(loaded, dict):
                    doc = dict(loaded)

        cur_tier = (current_tier or str(doc.get("permission_tier") or "tier3_workspace_dev")).strip().lower()
        saved_prev = str(doc.get("previous_non_readonly_tier") or "").strip().lower()
        if cur_tier == "tier1_readonly":
            target_tier = saved_prev if saved_prev in non_ro_tiers else "tier3_workspace_dev"
            eff_prev_non_ro = target_tier
        else:
            eff_prev_non_ro = cur_tier if cur_tier in non_ro_tiers else "tier3_workspace_dev"
            target_tier = "tier1_readonly"

        now_ts = round(time.time(), 6)
        next_rev = int(doc.get("policy_revision") or 0) + 1
        doc["permission_tier"] = target_tier
        doc["previous_non_readonly_tier"] = eff_prev_non_ro
        doc["policy_updated_at"] = now_ts
        doc["policy_revision"] = next_rev

        atomic_write_json(cfg_path, doc)
        if state_svc_path.is_file():
            atomic_write_json(state_svc_path, doc)
        root_cfg_path = st_root / "config.json"
        if eff_p == "pc" and root_cfg_path.is_file():
            root_doc: Dict[str, Any] = {}
            try:
                loaded_root = json.loads(root_cfg_path.read_text(encoding="utf-8-sig"))
                if isinstance(loaded_root, dict):
                    root_doc = dict(loaded_root)
            except Exception:
                root_doc = {}
            root_doc["permission_tier"] = target_tier
            root_doc["previous_non_readonly_tier"] = eff_prev_non_ro
            root_doc["policy_updated_at"] = now_ts
            root_doc["policy_revision"] = next_rev
            atomic_write_json(root_cfg_path, root_doc)

    atomic_write_json(
        state_dir / "kill_signal.json",
        {
            "ts": time.time(),
            "ts_ns": time.time_ns(),
            "reason": f"tray_tier_switch:{target_tier}",
            "prefix_filter": eff_p,
            "emitter_pid": os.getpid(),
        },
    )
    return {
        "ok": True,
        "permission_tier": target_tier,
        "previous_non_readonly_tier": eff_prev_non_ro,
        "policy_revision": next_rev,
    }


def apply_tray_start_or_resume_daemon(
    state_root: Path,
    *,
    prefix: str = "pc",
    port: int = 8096,
    python_exe: Optional[str] = None,
) -> Dict[str, Any]:
    """Explicitly clear user `STOP` lock and spawn/resume detached daemon from tray click (`clear_user_stop=True`)."""
    from cosmos_mcp.launcher.daemon import spawn_detached_daemon

    st_root = Path(state_root).expanduser().resolve()
    eff_p = _norm_prefix(prefix)
    eff_py = str(python_exe or sys.executable)
    return spawn_detached_daemon(
        python_exe=eff_py,
        state_root=st_root,
        port=int(port),
        prefix=eff_p,
        clear_user_stop=True,
    )


def apply_tray_revoke_all_tokens(state_root: Path, prefix: str = "pc") -> Dict[str, Any]:
    """Delete `access`/`refresh`/`authz_done` OAuth records in `oauth[_<prefix>].sqlite3` and emit `kill_signal.json`."""
    st_root = Path(state_root).expanduser().resolve()
    eff_p = _norm_prefix(prefix)
    state_dir = st_root / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    db_path = state_dir / (f"oauth_{eff_p}.sqlite3" if eff_p != "pc" else "oauth.sqlite3")
    deleted = 0
    if db_path.is_file():
        conn = sqlite3.connect(str(db_path), timeout=10.0)
        try:
            with conn:
                cur = conn.execute(
                    "DELETE FROM records WHERE kind IN ("
                    "'access','refresh','refresh_replay','authz_done','code','consent','consent_result','ticket'"
                    ")"
                )
                deleted = max(0, int(cur.rowcount or 0))
        except sqlite3.OperationalError:
            deleted = 0
        finally:
            conn.close()

    atomic_write_json(
        state_dir / "kill_signal.json",
        {
            "ts": time.time(),
            "ts_ns": time.time_ns(),
            "reason": "tray_revoke_all",
            "prefix_filter": eff_p,
            "emitter_pid": os.getpid(),
        },
    )
    return {"ok": True, "deleted_tokens": deleted}


def apply_tray_stop_daemon_flag(state_root: Path, prefix: str = "pc") -> Dict[str, Any]:
    """Write `daemon_stop[_<prefix>].flag` and `kill_signal.json` to trigger clean daemon shutdown."""
    st_root = Path(state_root).expanduser().resolve()
    eff_p = _norm_prefix(prefix)
    state_dir = st_root / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    flag_name = f"daemon_stop_{eff_p}.flag" if eff_p != "pc" else "daemon_stop.flag"
    atomic_write_text(state_dir / flag_name, f"STOP:{time.time()}\n")
    atomic_write_json(
        state_dir / "kill_signal.json",
        {
            "ts": time.time(),
            "ts_ns": time.time_ns(),
            "reason": "tray_stop_daemon",
            "prefix_filter": eff_p,
            "emitter_pid": os.getpid(),
        },
    )
    return {"ok": True, "stop_flag": str(state_dir / flag_name)}


class WindowsSystemTrayController:
    """Non-blocking 64-bit Win32 notification-area controller driven by atomic memory snapshots."""

    def __init__(
        self,
        state_root: Path,
        *,
        port: int = 8096,
        prefix: str = "pc",
        shell_notify_fn: Optional[Callable[[int, Any], bool]] = None,
        clipboard_fn: Optional[Callable[[str], bool]] = None,
        browser_open_fn: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.state_root = Path(state_root).expanduser().resolve()
        self.port = int(port)
        self.prefix = _norm_prefix(prefix)
        self._shell_notify_override = shell_notify_fn
        self._clipboard_fn = clipboard_fn or copy_text_to_win32_clipboard
        self._browser_open_fn = browser_open_fn or _open_local_studio_url

        # Atomic reference replaced as a whole dict so `WM_RBUTTONUP` reads in 0ms without locking or I/O
        self._snapshot_ref: Dict[str, Any] = {
            "port": self.port,
            "mode": "public_gateway",
            "public_url": "",
            "mcp_url": "",
            "readonly_mcp_url": "",
            "studio_url": f"http://127.0.0.1:{self.port}/",
            "connector_name": DEFAULT_WAKE_CONNECTOR_NAME,
            "wake_prompt": f"\x40{DEFAULT_WAKE_CONNECTOR_NAME} {DEFAULT_WAKE_PROMPT_SUFFIX}",
            "tunnel_ready": False,
            "permission_tier": "tier3_workspace_dev",
            "server_alive": True,
            "status": "starting",
            "connecting_status_zh": "正在建立加密连接…",
            "last_error": "",
        }
        self._lifecycle_lock = threading.Lock()
        self._ready_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._hwnd: int = 0
        self._mutex_handle: int = 0
        self._wndproc_ref: Any = None
        self._class_name: str = ""
        self._wm_taskbar_created: int = 0
        self._icon_cache: Dict[str, int] = {}
        self._nid: Optional[NOTIFYICONDATAW] = None
        self._applied_visual_sig: Tuple[str, str] = ("", "")
        self._balloon_lock = threading.Lock()
        self._last_balloon_mono: Optional[float] = None
        self._pending_balloon: Optional[Tuple[str, str]] = None
        self._running: bool = False
        self.skip_reason: str = ""

    @property
    def is_running(self) -> bool:
        return bool(self._running and self._thread is not None and self._thread.is_alive())

    def get_snapshot(self) -> Dict[str, Any]:
        return dict(self._snapshot_ref)

    def update_snapshot(self, snapshot: Mapping[str, Any]) -> None:
        """Atomically replace the in-memory tray snapshot (called every ~0.8s by `StandaloneSupervisorLoop`)."""
        merged = dict(self._snapshot_ref)
        merged.update(dict(snapshot))
        port_val = int(merged.get("port") or self.port)
        merged["port"] = port_val
        mode_val = str(merged.get("mode") or merged.get("tunnel_mode") or "local").strip().lower()
        raw_pub = str(merged.get("public_url") or "").strip().rstrip("/")
        if mode_val == "public_gateway" and not raw_pub:
            merged["public_url"] = ""
            merged["mcp_url"] = ""
            merged["readonly_mcp_url"] = ""
        else:
            pub_u = raw_pub or f"http://127.0.0.1:{port_val}"
            merged["public_url"] = pub_u
            merged["mcp_url"] = f"{pub_u}/mcp"
            merged["readonly_mcp_url"] = f"{pub_u}/mcp/readonly"
        merged["studio_url"] = f"http://127.0.0.1:{port_val}/"
        conn_name = str(merged.get("connector_name") or DEFAULT_WAKE_CONNECTOR_NAME).strip() or DEFAULT_WAKE_CONNECTOR_NAME
        merged["connector_name"] = conn_name
        if "wake_prompt" not in snapshot:
            merged["wake_prompt"] = format_wake_test_prompt({"connector_name": conn_name})
        self._snapshot_ref = merged

        state_key, _, _ = resolve_tray_visual_state(merged)
        tip = format_tray_tooltip(merged)
        if (state_key, tip) != self._applied_visual_sig and self._hwnd:
            try:
                u32, _, _, _ = _bind_win32_apis()
                u32.PostMessageW(wintypes.HWND(self._hwnd), WM_TRAY_SYNC_STATE, 0, 0)
            except Exception:
                pass

    def notify_balloon(self, title: str, message: str, *, cooldown_sec: float = 600.0) -> bool:
        """Silent no-op: background auto-reconnect must NEVER pop Win32 `NIF_INFO` desktop toast banners."""
        _ = (title, message, cooldown_sec)
        return False

    def handle_menu_command(self, cmd_id: int, snapshot: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Execute a selected popup menu command (invoked on a detached `daemon=True` worker thread)."""
        snap = dict(snapshot if snapshot is not None else self._snapshot_ref)
        port_val = int(snap.get("port") or self.port)
        studio_url = str(snap.get("studio_url") or f"http://127.0.0.1:{port_val}/")
        tier_cur = str(snap.get("permission_tier") or "tier3_workspace_dev")
        raw_mcp = str(snap.get("mcp_url") or "").strip()
        explicit_mode = str(snap.get("mode") or snap.get("tunnel_mode") or "").strip().lower()
        if not explicit_mode:
            explicit_mode = "local" if raw_mcp.startswith("http://127.0.0.1") else "public_gateway"
        if explicit_mode == "local":
            mcp_url = raw_mcp or f"http://127.0.0.1:{port_val}/mcp"
        else:
            mcp_url = raw_mcp if raw_mcp.startswith("https://") else ""

        if cmd_id == MENU_ID_OPEN_STUDIO:
            self._browser_open_fn(studio_url)
            return {"ok": True, "action": "open_studio", "url": studio_url}

        if cmd_id == MENU_ID_COPY_MCP_URL:
            if not mcp_url:
                return {
                    "ok": False,
                    "action": "copy_mcp_url",
                    "mcp_url": "",
                    "status_zh": "正在建立加密连接…",
                }
            copied = bool(self._clipboard_fn(mcp_url))
            return {"ok": copied, "action": "copy_mcp_url", "mcp_url": mcp_url}

        if cmd_id == MENU_ID_COPY_WAKE_PROMPT:
            wake_text = format_wake_test_prompt(snap)
            copied = bool(self._clipboard_fn(wake_text))
            return {"ok": copied, "action": "copy_wake_prompt", "wake_prompt": wake_text}

        if cmd_id == MENU_ID_TOGGLE_READONLY:
            res = apply_tray_permission_toggle(self.state_root, prefix=self.prefix, current_tier=tier_cur)
            self.update_snapshot(
                {
                    "permission_tier": res["permission_tier"],
                    "previous_non_readonly_tier": res["previous_non_readonly_tier"],
                }
            )
            return {"ok": True, "action": "toggle_readonly", **res}

        if cmd_id == MENU_ID_REVOKE_ALL:
            res = apply_tray_revoke_all_tokens(self.state_root, prefix=self.prefix)
            return {"ok": True, "action": "revoke_all", **res}

        if cmd_id is not None and cmd_id == MENU_ID_START_RESUME:
            res = apply_tray_start_or_resume_daemon(self.state_root, prefix=self.prefix, port=port_val)
            if res.get("ok"):
                self.update_snapshot({"status": "starting", "server_alive": True, "last_error": ""})
            return {"ok": bool(res.get("ok")), "action": "start_resume", **res}

        if cmd_id == MENU_ID_STOP_EXIT:
            res = apply_tray_stop_daemon_flag(self.state_root, prefix=self.prefix)
            self.stop()
            return {"ok": True, "action": "stop_exit", **res}

        return {"ok": False, "action": "noop", "cmd_id": cmd_id}

    def _notify_shell(self, msg_code: int, nid: NOTIFYICONDATAW) -> bool:
        if self._shell_notify_override is not None:
            return bool(self._shell_notify_override(msg_code, nid))
        _, sh32, _, _ = _bind_win32_apis()
        return bool(sh32.Shell_NotifyIconW(msg_code, ctypes.byref(nid)))

    def _get_or_create_state_icon(self, state_key: str, rgb: Tuple[int, int, int]) -> int:
        cached = self._icon_cache.get(state_key, 0)
        if cached:
            return cached
        hicon = create_status_dot_hicon(rgb)
        if hicon:
            self._icon_cache[state_key] = hicon
        return hicon

    def _apply_current_nid_state(self, *, re_add: bool = False) -> None:
        if self._nid is None or not self._hwnd:
            return
        snap = self._snapshot_ref
        state_key, _, rgb = resolve_tray_visual_state(snap)
        tip = format_tray_tooltip(snap)
        hicon = self._get_or_create_state_icon(state_key, rgb)
        self._nid.hIcon = wintypes.HICON(hicon)
        self._nid.szTip = tip
        self._nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        op = NIM_ADD if re_add else NIM_MODIFY
        self._notify_shell(op, self._nid)
        self._applied_visual_sig = (state_key, tip)

    def start(self, wait_ready_sec: float = 3.0) -> bool:
        """Start the background Win32 message-pump thread if `probe_windows_tray_eligibility` permits."""
        with self._lifecycle_lock:
            if self.is_running:
                return True
            allowed, reason = probe_windows_tray_eligibility(
                self.state_root,
                self.prefix,
                check_mutex=False,
            )
            if not allowed:
                self.skip_reason = reason
                return False

            _, _, _, k32 = _bind_win32_apis()
            mutex_name = build_tray_mutex_name(self.state_root, self.prefix)
            ctypes.set_last_error(0)
            h_mtx = k32.CreateMutexW(None, False, mutex_name)
            err = ctypes.get_last_error()
            if not h_mtx or err == ERROR_ALREADY_EXISTS:
                if h_mtx:
                    k32.CloseHandle(h_mtx)
                self.skip_reason = "mutex_already_held" if err == ERROR_ALREADY_EXISTS else f"mutex_error:{err}"
                return False

            self._mutex_handle = int(h_mtx)
            self._ready_event.clear()
            self._running = True
            self.skip_reason = ""
            th = threading.Thread(
                target=self._win32_message_loop,
                name=f"cosmos-tray-{self.prefix}",
                daemon=True,
            )
            self._thread = th
            th.start()

        self._ready_event.wait(timeout=max(0.2, float(wait_ready_sec)))
        return self.is_running

    def _win32_message_loop(self) -> None:
        u32, _, _, k32 = _bind_win32_apis()
        hinst = k32.GetModuleHandleW(None)
        fp = _compute_state_fp(self.state_root)
        cls_name = f"CosmosMcpTrayWnd_{fp}_{self.prefix}_{os.getpid()}_{id(self) & 0xFFFF:04x}"
        self._class_name = cls_name
        self._wm_taskbar_created = int(u32.RegisterWindowMessageW("TaskbarCreated") or 0)

        def _wnd_proc(hwnd: int, msg: int, wparam: int, lparam: int) -> int:
            try:
                if msg == WM_TRAYICON:
                    ev = int(lparam) & 0xFFFF
                    if ev == WM_LBUTTONDBLCLK:
                        snap_now = self._snapshot_ref
                        threading.Thread(
                            target=self.handle_menu_command,
                            args=(MENU_ID_OPEN_STUDIO, snap_now),
                            daemon=True,
                        ).start()
                        return 0
                    if ev in (WM_RBUTTONUP, WM_CONTEXTMENU):
                        # Strict 0ms non-blocking popup: read cursor & atomic memory dict ref immediately
                        pt = wintypes.POINT()
                        u32.GetCursorPos(ctypes.byref(pt))
                        snap_now = self._snapshot_ref
                        items = build_tray_menu_items(snap_now)
                        hmenu = u32.CreatePopupMenu()
                        if hmenu:
                            try:
                                for m_flags, m_id, m_text in items:
                                    u32.AppendMenuW(
                                        hmenu,
                                        int(m_flags),
                                        ULONG_PTR(int(m_id)),
                                        m_text if m_text else None,
                                    )
                                u32.SetForegroundWindow(wintypes.HWND(hwnd))
                                chosen = int(
                                    u32.TrackPopupMenu(
                                        hmenu,
                                        TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
                                        int(pt.x),
                                        int(pt.y),
                                        0,
                                        wintypes.HWND(hwnd),
                                        None,
                                    )
                                    or 0
                                )
                                u32.PostMessageW(wintypes.HWND(hwnd), WM_NULL, 0, 0)
                            finally:
                                u32.DestroyMenu(hmenu)
                            if chosen > 0:
                                threading.Thread(
                                    target=self.handle_menu_command,
                                    args=(chosen, snap_now),
                                    daemon=True,
                                ).start()
                        return 0
                elif self._wm_taskbar_created and msg == self._wm_taskbar_created:
                    self._apply_current_nid_state(re_add=True)
                    return 0
                elif msg == WM_TRAY_SYNC_STATE:
                    self._apply_current_nid_state(re_add=False)
                    return 0
                elif msg == WM_TRAY_BALLOON:
                    with self._balloon_lock:
                        self._pending_balloon = None
                    self._apply_current_nid_state(re_add=False)
                    return 0
                elif msg in (WM_TRAY_SHUTDOWN, WM_CLOSE):
                    if self._nid is not None:
                        try:
                            self._notify_shell(NIM_DELETE, self._nid)
                        except Exception:
                            pass
                        self._nid = None
                    if hwnd:
                        u32.DestroyWindow(wintypes.HWND(hwnd))
                    return 0
                elif msg == WM_DESTROY:
                    u32.PostQuitMessage(0)
                    return 0
            except Exception:
                pass
            return int(u32.DefWindowProcW(wintypes.HWND(hwnd), int(msg), wparam, lparam))

        assert WNDPROCTYPE is not None
        self._wndproc_ref = WNDPROCTYPE(_wnd_proc)
        wc = WNDCLASSW()
        wc.style = 0
        wc.lpfnWndProc = self._wndproc_ref
        wc.cbClsExtra = 0
        wc.cbWndExtra = 0
        wc.hInstance = hinst
        wc.hIcon = None
        wc.hCursor = None
        wc.hbrBackground = None
        wc.lpszMenuName = None
        wc.lpszClassName = cls_name

        atom = u32.RegisterClassW(ctypes.byref(wc))
        if not atom:
            self._running = False
            self._release_resources_on_thread_exit(u32, k32, hinst, registered=False)
            self._ready_event.set()
            return

        # Hidden top-level tool window (never shown, zero focus impact, receives `TaskbarCreated` broadcast)
        hwnd = u32.CreateWindowExW(
            WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
            cls_name,
            cls_name,
            0,
            0,
            0,
            0,
            0,
            None,
            None,
            hinst,
            None,
        )
        if not hwnd:
            self._running = False
            self._release_resources_on_thread_exit(u32, k32, hinst, registered=True)
            self._ready_event.set()
            return

        self._hwnd = int(hwnd)
        state_key, _, rgb = resolve_tray_visual_state(self._snapshot_ref)
        tip = format_tray_tooltip(self._snapshot_ref)
        hicon = self._get_or_create_state_icon(state_key, rgb)

        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = wintypes.HWND(self._hwnd)
        nid.uID = 1
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        nid.uCallbackMessage = WM_TRAYICON
        nid.hIcon = wintypes.HICON(hicon)
        nid.szTip = tip
        self._nid = nid
        self._applied_visual_sig = (state_key, tip)
        self._notify_shell(NIM_ADD, nid)
        self._ready_event.set()

        msg = wintypes.MSG()
        try:
            while True:
                ret = int(u32.GetMessageW(ctypes.byref(msg), None, 0, 0))
                if ret <= 0:
                    break
                u32.TranslateMessage(ctypes.byref(msg))
                u32.DispatchMessageW(ctypes.byref(msg))
        finally:
            if self._nid is not None:
                try:
                    self._notify_shell(NIM_DELETE, self._nid)
                except Exception:
                    pass
                self._nid = None
            self._hwnd = 0
            self._running = False
            self._release_resources_on_thread_exit(u32, k32, hinst, registered=True)

    def _release_resources_on_thread_exit(self, u32: Any, k32: Any, hinst: Any, *, registered: bool) -> None:
        for _, hicon in list(self._icon_cache.items()):
            if hicon:
                try:
                    u32.DestroyIcon(wintypes.HICON(hicon))
                except Exception:
                    pass
        self._icon_cache.clear()
        if registered and self._class_name:
            try:
                u32.UnregisterClassW(self._class_name, hinst)
            except Exception:
                pass
        if self._mutex_handle:
            try:
                k32.CloseHandle(wintypes.HANDLE(self._mutex_handle))
            except Exception:
                pass
            self._mutex_handle = 0

    def stop(self, timeout_sec: float = 3.0) -> None:
        """Remove tray icon via `NIM_DELETE`, destroy hidden window, and release mutex cleanly."""
        with self._lifecycle_lock:
            hwnd = self._hwnd
            th = self._thread
            if hwnd and sys.platform == "win32":
                try:
                    u32, _, _, _ = _bind_win32_apis()
                    u32.PostMessageW(wintypes.HWND(hwnd), WM_TRAY_SHUTDOWN, 0, 0)
                except Exception:
                    pass
            self._running = False

        if th is not None and th.is_alive() and th is not threading.current_thread():
            th.join(timeout=max(0.2, float(timeout_sec)))

        with self._lifecycle_lock:
            if self._mutex_handle and sys.platform == "win32" and (self._thread is None or not self._thread.is_alive()):
                try:
                    _, _, _, k32 = _bind_win32_apis()
                    k32.CloseHandle(wintypes.HANDLE(self._mutex_handle))
                except Exception:
                    pass
                self._mutex_handle = 0
            self._thread = None
