from __future__ import annotations

"""Layer 1 Pluggable Windows Offscreen CUA Pack (`cosmos_mcp.packs.desktop`).

Provides `CuaWindowPackPlugin` (`pack_id="cua"`, tool `cua_window`):
1. Preserves 150% high-DPI physical coordinate scaling, offscreen `PrintWindow(PW_RENDERFULLCONTENT=2)`
   capture, `#32770` popup/sub-dialog enumeration & capture, `grid_step=50` coordinate grid rendering,
   and non-activating background `PostMessageW`/`SendMessageW`/UIA control (`focus_unchanged=True`,
   zero `SetForegroundWindow`, zero clipboard touch `delta_clip == 0`).
2. `L3` (`tier3_workspace_dev`) full-action window fence: restricts ALL `cua_window` actions
   (`list_windows`, `capture`/`screenshot`, `uia_tree`, `click`, `invoke`, `set_value`, `type_text`,
   `send_keys`, `post_message`, `restore`, `close`, `close_window`) strictly to windows belonging to
   authorized `workspace_roots` or the current MCP session seed PID subtree (linked with
   `ProcessManager.active_session_pids` / active foreground & background jobs). Never captures the
   full desktop or enumerates/operates private external windows in `L3`.
3. `L4` (`tier4_full_power`) human-present yield & dirty-scene guardrails:
   - Checks Win32 `GetLastInputInfo` before mutating actions in `L4`; yields immediately with
     `ERR_HUMAN_ACTIVE_YIELD` when physical keyboard/mouse idle time `< 2500ms`.
   - Protects unsaved windows (`*`, `未保存`, `Modified`, `Unsaved`, `EM_GETMODIFY`, or owned save
     confirmation dialogs) from accidental data loss on `close` / `close_window`.
   - Detects `Winlogon` lock screen or all-zero pure black frames BEFORE grid overlay and returns
     `ERR_SCREEN_LOCKED_OR_BLACK_FRAME` (`ok=False`) instead of falsely reporting `ok=True`.
"""

import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple, Union

from cosmos_mcp.core.contracts import PackPlugin, SafetyBand, ToolSpec
from cosmos_mcp.core.fs_io import (
    detect_image_magic,
    encode_rgb_png_stdlib,
    parse_image_dimensions_stdlib,
)
from cosmos_mcp.core.guard import (
    DEFAULT_GUARD,
    WorkspaceGuard,
    canonical_realpath,
    normalize_tier,
    strip_file_uri,
)
from cosmos_mcp.core.proc import (
    DEFAULT_PROCESS_MANAGER,
    ProcessManager,
    get_process_create_token,
    verify_pid_alive,
    win32_no_window_flags,
)

MAX_CAPTURE_LONG_EDGE: int = 1440
MAX_CAPTURE_BYTES: int = 340 * 1024
PW_RENDERFULLCONTENT: int = 0x00000002
DEFAULT_HUMAN_IDLE_THRESHOLD_MS: int = 2500

ERR_SCREEN_LOCKED_OR_BLACK_FRAME = "ERR_SCREEN_LOCKED_OR_BLACK_FRAME"
ERR_HUMAN_ACTIVE_YIELD = "ERR_HUMAN_ACTIVE_YIELD"
ERR_UNSAVED_DOCUMENT_PROTECTED = "ERR_UNSAVED_DOCUMENT_PROTECTED"
ERR_L3_WINDOW_SCOPE_BLOCKED = "ERR_L3_WINDOW_SCOPE_BLOCKED"

CUA_WINDOW_ACTIONS: Tuple[str, ...] = (
    "list_windows",
    "capture",
    "screenshot",
    "uia_tree",
    "click",
    "double_click",
    "right_click",
    "scroll",
    "invoke",
    "set_value",
    "type_text",
    "send_keys",
    "post_message",
    "restore",
    "close",
    "close_window",
)

CUA_MUTATING_ACTIONS: frozenset[str] = frozenset(
    {
        "click",
        "double_click",
        "right_click",
        "scroll",
        "invoke",
        "set_value",
        "type_text",
        "send_keys",
        "post_message",
        "restore",
        "close",
        "close_window",
    }
)

_UNSAVED_TITLE_STAR_RE = re.compile(
    r"(?:^\s*[*●]\s*\S|\S\s*\*\s*$|^\s*[^*]+\*(?=\s*[-—–|])|(?<=[\s(\[])\*[^\s*]+)"
)
_UNSAVED_TITLE_KEYWORDS: Tuple[str, ...] = (
    "未保存",
    "修改未保存",
    "unsaved",
    "modified",
)
_SAVE_CONFIRM_DIALOG_TOKENS: Tuple[str, ...] = (
    "是否保存",
    "你想将更改保存到",
    "将更改保存到",
    "不保存",
    "保存更改",
    "do you want to save",
    "save changes",
    "don't save",
)

_DIGIT_BITMAPS_3X5: Dict[str, Tuple[int, int, int, int, int]] = {
    "0": (0b111, 0b101, 0b101, 0b101, 0b111),
    "1": (0b010, 0b110, 0b010, 0b010, 0b111),
    "2": (0b111, 0b001, 0b111, 0b100, 0b111),
    "3": (0b111, 0b001, 0b111, 0b001, 0b111),
    "4": (0b101, 0b101, 0b111, 0b001, 0b001),
    "5": (0b111, 0b100, 0b111, 0b001, 0b111),
    "6": (0b111, 0b100, 0b111, 0b101, 0b111),
    "7": (0b111, 0b001, 0b010, 0b010, 0b010),
    "8": (0b111, 0b101, 0b111, 0b101, 0b111),
    "9": (0b111, 0b101, 0b111, 0b001, 0b111),
}

_NAMED_VK_MAP: Dict[str, int] = {
    "enter": 0x0D,
    "return": 0x0D,
    "tab": 0x09,
    "esc": 0x1B,
    "escape": 0x1B,
    "space": 0x20,
    "spacebar": 0x20,
    "backspace": 0x08,
    "bksp": 0x08,
    "bs": 0x08,
    "delete": 0x2E,
    "del": 0x2E,
    "insert": 0x2D,
    "ins": 0x2D,
    "up": 0x26,
    "arrowup": 0x26,
    "down": 0x28,
    "arrowdown": 0x28,
    "left": 0x25,
    "arrowleft": 0x25,
    "right": 0x27,
    "arrowright": 0x27,
    "home": 0x24,
    "end": 0x23,
    "pageup": 0x21,
    "pgup": 0x21,
    "prior": 0x21,
    "pagedown": 0x22,
    "pgdn": 0x22,
    "next": 0x22,
    **{f"f{idx}": 0x70 + (idx - 1) for idx in range(1, 25)},
}

_MODIFIER_VK_MAP: Dict[str, Tuple[str, int]] = {
    "ctrl": ("ctrl", 0x11),
    "control": ("ctrl", 0x11),
    "ctl": ("ctrl", 0x11),
    "alt": ("alt", 0x12),
    "menu": ("alt", 0x12),
    "option": ("alt", 0x12),
    "shift": ("shift", 0x10),
    "win": ("win", 0x5B),
    "lwin": ("win", 0x5B),
    "meta": ("win", 0x5B),
    "super": ("win", 0x5B),
    "cmd": ("win", 0x5B),
}

_OEM_KEY_VK_MAP: Dict[str, int] = {
    "+": 0xBB,
    "plus": 0xBB,
    "=": 0xBB,
    "equals": 0xBB,
    "-": 0xBD,
    "minus": 0xBD,
    ",": 0xBC,
    "comma": 0xBC,
    ".": 0xBE,
    "period": 0xBE,
    "/": 0xBF,
    "slash": 0xBF,
    ";": 0xBA,
    "[": 0xDB,
    "\\": 0xDC,
    "]": 0xDD,
    "'": 0xDE,
    "`": 0xC0,
}

_EXTENDED_VK_SET: frozenset[int] = frozenset({0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2D, 0x2E, 0x5B, 0x5C})

_CAPTURE_SCALE_LOCK = threading.Lock()
_WINDOW_CAPTURE_SCALE_CACHE: Dict[int, Dict[str, Any]] = {}


def record_window_capture_scale(
    hwnd: int,
    *,
    image_width: int,
    image_height: int,
    captured_width: int,
    captured_height: int,
    client_offset: Sequence[int] = (0, 0),
    client_size: Sequence[int] = (0, 0),
) -> Dict[str, Any]:
    """Cache latest screenshot `(image_size / captured_size)` scale factor for `hwnd`."""
    hw = int(hwnd or 0)
    cap_w = max(1, int(captured_width or 1))
    cap_h = max(1, int(captured_height or 1))
    img_w = max(1, int(image_width or cap_w))
    img_h = max(1, int(image_height or cap_h))
    sx = float(img_w) / float(cap_w)
    sy = float(img_h) / float(cap_h)
    sf = round(sx, 6)
    entry = {
        "hwnd": hw,
        "scale_factor": sf,
        "scale_x": round(sx, 6),
        "scale_y": round(sy, 6),
        "image_size": [img_w, img_h],
        "captured_size": [cap_w, cap_h],
        "client_offset": [int(client_offset[0]), int(client_offset[1])] if len(client_offset) >= 2 else [0, 0],
        "client_size": [int(client_size[0]), int(client_size[1])] if len(client_size) >= 2 else [0, 0],
        "updated_at": time.monotonic(),
    }
    if hw > 0:
        with _CAPTURE_SCALE_LOCK:
            _WINDOW_CAPTURE_SCALE_CACHE[hw] = entry
    return entry


def get_cached_window_capture_scale(hwnd: int) -> Optional[Dict[str, Any]]:
    hw = int(hwnd or 0)
    if hw <= 0:
        return None
    with _CAPTURE_SCALE_LOCK:
        rec = _WINDOW_CAPTURE_SCALE_CACHE.get(hw)
        return dict(rec) if rec is not None else None


def parse_key_chord_spec(raw_spec: str) -> Optional[Dict[str, Any]]:
    """Parse `ctrl+s`, `alt+f4`, `ctrl+shift+z`, `win+r`, or special keys (`enter`, `f1..f12`, arrows, `delete`, etc.).

    Returns:
      - `None` if `raw_spec` is plain literal text rather than a chord/special key.
      - `{'ok': True, 'modifiers': [(name, vk), ...], 'vk': int, 'key_name': str, 'chord': str}` on valid key spec.
      - `{'ok': False, 'error': str}` if modifier prefix (`ctrl+...`) has an invalid trailing key token.
    """
    s = (raw_spec or "").strip()
    if not s:
        return None
    low = s.lower()
    if low in _NAMED_VK_MAP:
        return {
            "ok": True,
            "modifiers": [],
            "vk": _NAMED_VK_MAP[low],
            "key_name": low,
            "chord": low,
        }
    if "+" not in s:
        return None

    # Split modifier chord while preserving trailing '+' key (`ctrl++`)
    work = low
    trailing_plus = False
    if work.endswith("++"):
        work = work[:-2]
        trailing_plus = True
    parts = [p.strip() for p in work.split("+") if p.strip()]
    if trailing_plus:
        parts.append("+")
    if len(parts) < 2:
        return None

    mod_parts = parts[:-1]
    key_part = parts[-1]
    if not all(mp in _MODIFIER_VK_MAP for mp in mod_parts):
        return None

    mods: List[Tuple[str, int]] = []
    seen_mods: Set[str] = set()
    for mp in mod_parts:
        m_name, m_vk = _MODIFIER_VK_MAP[mp]
        if m_name not in seen_mods:
            seen_mods.add(m_name)
            mods.append((m_name, m_vk))

    main_vk = 0
    if key_part in _NAMED_VK_MAP:
        main_vk = _NAMED_VK_MAP[key_part]
    elif key_part in _OEM_KEY_VK_MAP:
        main_vk = _OEM_KEY_VK_MAP[key_part]
    elif len(key_part) == 1 and "a" <= key_part <= "z":
        main_vk = ord(key_part.upper())
    elif len(key_part) == 1 and "0" <= key_part <= "9":
        main_vk = ord(key_part)

    if main_vk <= 0:
        return {
            "ok": False,
            "error": f"Unrecognized key `{key_part}` in key combination `{raw_spec}`.",
        }

    chord_norm = "+".join([m[0] for m in mods] + [key_part])
    return {
        "ok": True,
        "modifiers": mods,
        "vk": main_vk,
        "key_name": key_part,
        "chord": chord_norm,
    }

_CMDLINE_CACHE_LOCK = threading.Lock()
_CMDLINE_CACHE: Dict[Tuple[int, str], Tuple[float, str]] = {}
_PROC_CWD_CACHE: Dict[int, Tuple[float, Optional[str], str]] = {}


# ---------------------------------------------------------------------------
# Shared Image Compression & Workspace-Guarded Save Utilities
# ---------------------------------------------------------------------------


def compress_capture_bytes(raw_bytes: bytes, source_label: str = "capture") -> Dict[str, Any]:
    """Compress PNG/BMP/JPEG capture bytes into <=1440px, <=340KiB JPEG (or pure-stdlib PNG fallback)."""
    sha = hashlib.sha256(raw_bytes).hexdigest().lower()
    try:
        from PIL import Image  # type: ignore

        with Image.open(io.BytesIO(raw_bytes)) as src_im:
            orig_w, orig_h = int(src_im.width), int(src_im.height)
            im = src_im.copy()
            if im.mode in ("RGBA", "LA") or (im.mode == "P" and "transparency" in im.info):
                rgba = im.convert("RGBA")
                bg = Image.new("RGB", rgba.size, (255, 255, 255))
                bg.paste(rgba, mask=rgba.split()[3])
                im = bg
            elif im.mode != "RGB":
                im = im.convert("RGB")

            resample_fn = getattr(getattr(Image, "Resampling", Image), "LANCZOS")
            if max(im.size) > MAX_CAPTURE_LONG_EDGE:
                scale = float(MAX_CAPTURE_LONG_EDGE) / float(max(im.size))
                im = im.resize(
                    (max(1, int(round(im.width * scale))), max(1, int(round(im.height * scale)))),
                    resample=resample_fn,
                )

            out_bytes = b""
            for q in (84, 76, 68, 58, 48, 38):
                buf = io.BytesIO()
                im.save(buf, format="JPEG", quality=q, optimize=True)
                out_bytes = buf.getvalue()
                if len(out_bytes) <= MAX_CAPTURE_BYTES:
                    break
            while len(out_bytes) > MAX_CAPTURE_BYTES and max(im.size) > 320:
                im = im.resize(
                    (max(1, int(round(im.width * 0.82))), max(1, int(round(im.height * 0.82)))),
                    resample=resample_fn,
                )
                buf = io.BytesIO()
                im.save(buf, format="JPEG", quality=45, optimize=True)
                out_bytes = buf.getvalue()
            w, h = int(im.width), int(im.height)
            mime = "image/jpeg"
    except ImportError:
        out_bytes = raw_bytes
        det_mime = detect_image_magic(raw_bytes[:32]) or "image/png"
        orig_w, orig_h = parse_image_dimensions_stdlib(raw_bytes, det_mime)
        w, h = int(orig_w), int(orig_h)
        mime = det_mime

    b64_str = base64.b64encode(out_bytes).decode("ascii")
    return {
        "b64_data": b64_str,
        "mime": mime,
        "out_bytes": out_bytes,
        "meta": {
            "ok": True,
            "is_image": True,
            "source": source_label,
            "mime_type": mime,
            "width": w,
            "height": h,
            "original_width": orig_w or w,
            "original_height": orig_h or h,
            "byte_size": len(out_bytes),
            "sha256": sha,
            "sha256_prefix": sha[:12],
        },
    }


def save_optional_capture(
    out_bytes: bytes,
    save_path: str,
    guard: WorkspaceGuard,
    *,
    workspace_root: str = "",
    tool_name: str = "cua_window",
) -> Tuple[Optional[str], Optional[str]]:
    """Validate `save_path` against `WorkspaceGuard` and persist `out_bytes` if requested."""
    clean_save = (save_path or "").strip()
    if not clean_save:
        return None, None
    resolved = guard.normalize_target_path(clean_save, base_dir=workspace_root or None)
    err = guard.check_path_access(resolved, mode="write", tool_name=tool_name)
    if err:
        return None, err
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_bytes(out_bytes)
    return str(resolved), None


def build_mcp_image_blocks(meta: Dict[str, Any], b64_data: str, mime: str) -> List[Dict[str, Any]]:
    """Build protocol-neutral MCP content block dicts without importing optional `mcp.types`."""
    return [
        {"type": "text", "text": json.dumps(meta, ensure_ascii=False)},
        {"type": "image", "data": b64_data, "mimeType": mime},
    ]


# ---------------------------------------------------------------------------
# RGB Conversion, Pure-Black / Lock-Screen Check & Coordinate Grid Rendering
# ---------------------------------------------------------------------------


def bgra_to_rgb_packed(raw_bgra: bytes, width: int, height: int) -> bytearray:
    """Convert top-down 32-bit BGRA buffer into packed 24-bit RGB (`width * height * 3`)."""
    w = int(width)
    h = int(height)
    stride_bgra = w * 4
    stride_rgb = w * 3
    rgb = bytearray(w * h * 3)
    for row_idx in range(h):
        src = raw_bgra[row_idx * stride_bgra : (row_idx + 1) * stride_bgra]
        dst_off = row_idx * stride_rgb
        rgb[dst_off : dst_off + stride_rgb : 3] = src[2::4]
        rgb[dst_off + 1 : dst_off + stride_rgb : 3] = src[1::4]
        rgb[dst_off + 2 : dst_off + stride_rgb : 3] = src[0::4]
    return rgb


def draw_coordinate_grid_rgb(rgb: bytearray, width: int, height: int, grid_step: int = 0) -> bytearray:
    """Overlay semi-transparent coordinate grid lines and 2x-scaled pixel coordinate labels onto `rgb`."""
    w = int(width)
    h = int(height)
    step = int(grid_step or 0)
    if step < 20 or w < 24 or h < 24:
        return rgb
    stride_rgb = w * 3

    def _blend_px(px: int, py: int, cr: int, cg: int, cb: int, alpha_num: int) -> None:
        if 0 <= px < w and 0 <= py < h:
            idx = py * stride_rgb + px * 3
            inv = 256 - alpha_num
            rgb[idx] = (rgb[idx] * inv + cr * alpha_num) >> 8
            rgb[idx + 1] = (rgb[idx + 1] * inv + cg * alpha_num) >> 8
            rgb[idx + 2] = (rgb[idx + 2] * inv + cb * alpha_num) >> 8

    def _draw_label(lx: int, ly: int, text_s: str) -> None:
        scale = 2
        char_w = 3 * scale + scale
        box_w = len(text_s) * char_w + 4
        box_h = 5 * scale + 4
        for by in range(ly, min(h, ly + box_h)):
            row_base = by * stride_rgb
            for bx in range(lx, min(w, lx + box_w)):
                if bx >= 0 and by >= 0:
                    idx = row_base + bx * 3
                    rgb[idx] = (rgb[idx] * 64 + 12 * 192) >> 8
                    rgb[idx + 1] = (rgb[idx + 1] * 64 + 20 * 192) >> 8
                    rgb[idx + 2] = (rgb[idx + 2] * 64 + 38 * 192) >> 8
        cx_cursor = lx + 2
        cy_top = ly + 2
        for ch in text_s:
            rows_bits = _DIGIT_BITMAPS_3X5.get(ch)
            if rows_bits:
                for ry, bits in enumerate(rows_bits):
                    for rx in range(3):
                        if (bits >> (2 - rx)) & 1:
                            for sy in range(scale):
                                for sx in range(scale):
                                    px = cx_cursor + rx * scale + sx
                                    py = cy_top + ry * scale + sy
                                    if 0 <= px < w and 0 <= py < h:
                                        idx = py * stride_rgb + px * 3
                                        rgb[idx] = 255
                                        rgb[idx + 1] = 235
                                        rgb[idx + 2] = 59
            cx_cursor += char_w

    for gx in range(step, w, step):
        is_major = (gx % (step * 2)) == 0
        cr, cg, cb, al = (255, 56, 56, 176) if is_major else (0, 200, 255, 136)
        for gy in range(h):
            _blend_px(gx, gy, cr, cg, cb, al)
        _draw_label(min(gx + 2, max(0, w - 36)), 2, str(gx))

    for gy in range(step, h, step):
        is_major = (gy % (step * 2)) == 0
        cr, cg, cb, al = (255, 56, 56, 176) if is_major else (0, 200, 255, 136)
        for gx in range(w):
            _blend_px(gx, gy, cr, cg, cb, al)
        _draw_label(2, min(gy + 2, max(0, h - 16)), str(gy))

    for gx in range(step, w, step):
        for gy in range(step, h, step):
            for dx in (-1, 0, 1):
                for dy in (-1, 0, 1):
                    _blend_px(gx + dx, gy + dy, 255, 235, 59, 220)
    return rgb


def detect_input_desktop_name_win32() -> str:
    """Return active Win32 input desktop name (e.g. `'Default'` or `'Winlogon'`), or `''` if unavailable."""
    if sys.platform != "win32":
        return ""
    try:
        import ctypes
        from ctypes import wintypes

        u32 = ctypes.WinDLL("user32", use_last_error=True)
        u32.OpenInputDesktop.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        u32.OpenInputDesktop.restype = wintypes.HANDLE
        u32.GetUserObjectInformationW.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        u32.GetUserObjectInformationW.restype = wintypes.BOOL
        u32.CloseDesktop.argtypes = [wintypes.HANDLE]
        u32.CloseDesktop.restype = wintypes.BOOL

        hdesk = u32.OpenInputDesktop(0, False, 0x0001)  # DESKTOP_READOBJECTS
        if not hdesk:
            return ""
        try:
            buf = ctypes.create_unicode_buffer(128)
            needed = wintypes.DWORD(0)
            if u32.GetUserObjectInformationW(hdesk, 2, buf, ctypes.sizeof(buf), ctypes.byref(needed)):  # UOI_NAME = 2
                return str(buf.value or "").strip()
        finally:
            u32.CloseDesktop(hdesk)
    except Exception:
        return ""
    return ""


def check_locked_or_black_rgb_frame(
    rgb_buf: Union[bytes, bytearray],
    *,
    desktop_name: Optional[str] = None,
) -> Tuple[bool, bool, bool]:
    """Return `(is_bad, is_screen_locked, is_all_black)` before drawing any coordinate grid."""
    d_name = (detect_input_desktop_name_win32() if desktop_name is None else desktop_name).strip().lower()
    is_locked = d_name == "winlogon"
    is_black = (len(rgb_buf) == 0) or (not any(rgb_buf))
    return (is_locked or is_black), is_locked, is_black


# ---------------------------------------------------------------------------
# Physical Human Idle Probe (`GetLastInputInfo` + `GetTickCount64`) & L0 Invariants
# ---------------------------------------------------------------------------


def get_physical_idle_ms(*, default_ms: int = 999999) -> int:
    """Query physical keyboard/mouse idle milliseconds via Win32 `GetLastInputInfo` + `GetTickCount64`."""
    if sys.platform != "win32":
        return int(default_ms)
    try:
        import ctypes
        from ctypes import wintypes

        class _LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]

        u32 = ctypes.WinDLL("user32", use_last_error=True)
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        u32.GetLastInputInfo.argtypes = [ctypes.POINTER(_LASTINPUTINFO)]
        u32.GetLastInputInfo.restype = wintypes.BOOL
        k32.GetTickCount64.argtypes = []
        k32.GetTickCount64.restype = ctypes.c_uint64

        tick64 = int(k32.GetTickCount64())
        lii = _LASTINPUTINFO(ctypes.sizeof(_LASTINPUTINFO), 0)
        if u32.GetLastInputInfo(ctypes.byref(lii)):
            dw32 = int(lii.dwTime) & 0xFFFFFFFF
            raw_diff = ((tick64 & 0xFFFFFFFF) - dw32) & 0xFFFFFFFF
            return 0 if raw_diff >= 0x80000000 else int(raw_diff)
    except Exception:
        pass
    return int(default_ms)


def snapshot_l0_desktop_state() -> Tuple[int, Tuple[int, int], int]:
    """Read `(foreground_hwnd, cursor_xy, clipboard_seq)` via zero-intrusion read-only Win32 counters."""
    if sys.platform != "win32":
        return 0, (0, 0), 0
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    u32.GetForegroundWindow.argtypes = []
    u32.GetForegroundWindow.restype = wintypes.HWND
    u32.GetClipboardSequenceNumber.argtypes = []
    u32.GetClipboardSequenceNumber.restype = wintypes.DWORD

    fg = int(u32.GetForegroundWindow() or 0)
    pt = wintypes.POINT(0, 0)
    u32.GetCursorPos(ctypes.byref(pt))
    clip_seq = int(u32.GetClipboardSequenceNumber() or 0)
    return fg, (int(pt.x), int(pt.y)), clip_seq


def is_hwnd_responsive_win32(hwnd: int, timeout_ms: int = 600) -> bool:
    """Win32 `SendMessageTimeoutW(WM_NULL, SMTO_ABORTIFHUNG)` hung-HWND circuit breaker."""
    if sys.platform != "win32" or int(hwnd or 0) <= 0:
        return False
    try:
        import ctypes
        from ctypes import wintypes

        u32 = ctypes.WinDLL("user32", use_last_error=True)
        u32.IsWindow.argtypes = [wintypes.HWND]
        u32.IsWindow.restype = wintypes.BOOL
        h_arg = wintypes.HWND(int(hwnd))
        if not u32.IsWindow(h_arg):
            return False
        if hasattr(u32, "IsHungAppWindow"):
            u32.IsHungAppWindow.argtypes = [wintypes.HWND]
            u32.IsHungAppWindow.restype = wintypes.BOOL
            if u32.IsHungAppWindow(h_arg):
                return False
        smto = u32.SendMessageTimeoutW
        smto.argtypes = [
            wintypes.HWND,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
            wintypes.UINT,
            wintypes.UINT,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        smto.restype = wintypes.LPARAM
        ctypes.set_last_error(0)
        res_out = ctypes.c_size_t(0)
        ok = smto(h_arg, 0x0000, 0, 0, 0x0002, int(timeout_ms), ctypes.byref(res_out))
        return bool(ok or ctypes.get_last_error() != 1460)
    except Exception:
        return True


# ---------------------------------------------------------------------------
# Process / Workspace Lineage Helpers for L3 Window Scope Fence
# ---------------------------------------------------------------------------


_EMBEDDED_WIN_DRIVE_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z]:[\\/][^\s\"'<>|;*?]+)")
_SCRIPT_LIKE_EXTS: frozenset[str] = frozenset(
    {
        ".py",
        ".pyw",
        ".pyc",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".jsx",
        ".ps1",
        ".bat",
        ".cmd",
        ".sh",
        ".exe",
        ".com",
        ".rb",
        ".lua",
        ".pl",
        ".jar",
        ".html",
        ".htm",
        ".ui",
    }
)
_SYSTEM_ANCESTOR_STOP_EXES: frozenset[str] = frozenset(
    {
        "explorer.exe",
        "services.exe",
        "svchost.exe",
        "wininit.exe",
        "sihost.exe",
        "taskhostw.exe",
        "userinit.exe",
        "lsass.exe",
        "csrss.exe",
    }
)


def _expand_win32_long_path(p: str) -> str:
    """Expand Windows 8.3 short paths (`GetLongPathNameW`), resolve symlinks/junctions, and normalize case."""
    raw = strip_file_uri(str(p or "").strip().strip("\"'"))
    if not raw:
        return ""
    expanded = os.path.expanduser(os.path.expandvars(raw))
    if sys.platform != "win32":
        try:
            return os.path.normcase(os.path.normpath(os.path.realpath(expanded))).rstrip("/")
        except Exception:
            return os.path.normcase(os.path.normpath(expanded)).rstrip("/")

    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_long = k32.GetLongPathNameW
    get_long.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    get_long.restype = wintypes.DWORD

    def _to_long(s_in: str) -> str:
        if not s_in:
            return s_in
        with contextlib.suppress(Exception):
            needed = int(get_long(s_in, None, 0) or 0)
            if needed > 0:
                buf = ctypes.create_unicode_buffer(needed + 2)
                written = int(get_long(s_in, buf, needed + 2) or 0)
                if 0 < written <= needed + 2 and buf.value:
                    return str(buf.value)
        return s_in

    norm_s = os.path.normpath(expanded.replace("/", "\\"))
    drv, tail = os.path.splitdrive(norm_s)
    if tail:
        cleaned_parts = [
            (pt.rstrip(". ") if pt not in ("", ".", "..") and ":" not in pt else pt)
            for pt in tail.split("\\")
        ]
        norm_s = drv + "\\".join(cleaned_parts)

    try:
        cand = _to_long(norm_s)
        p_obj = Path(cand)
        if p_obj.exists():
            real_s = _to_long(os.path.realpath(str(p_obj)))
            return os.path.normcase(os.path.normpath(real_s)).rstrip("\\/")
        missing_tail: List[str] = []
        probe = p_obj
        while probe != probe.parent and not probe.exists():
            missing_tail.append(probe.name)
            probe = probe.parent
        if probe.exists():
            base_long = Path(_to_long(os.path.realpath(str(probe))))
            for seg in reversed(missing_tail):
                base_long = base_long / seg
            return os.path.normcase(os.path.normpath(str(base_long))).rstrip("\\/")
        return os.path.normcase(os.path.normpath(cand)).rstrip("\\/")
    except Exception:
        return os.path.normcase(norm_s).rstrip("\\/")


def _query_process_full_path_win32(pid: int) -> str:
    if sys.platform != "win32" or int(pid or 0) <= 0:
        return ""
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    hproc = k32.OpenProcess(0x1000, False, int(pid))
    if not hproc:
        return ""
    try:
        pbuf = ctypes.create_unicode_buffer(2048)
        sz = wintypes.DWORD(2048)
        if k32.QueryFullProcessImageNameW(hproc, 0, pbuf, ctypes.byref(sz)):
            return str(pbuf.value or "")
        return ""
    finally:
        k32.CloseHandle(hproc)


def _query_process_name_win32(pid: int) -> str:
    full_p = _query_process_full_path_win32(pid)
    return os.path.basename(full_p) if full_p else ""


def _query_process_peb_cwd_and_cmdline_win32(pid: int) -> Tuple[str, str]:
    """Read target 64-bit process PEB `ProcessParameters.CurrentDirectory` & `CommandLine` via `ntdll`."""
    if sys.platform != "win32" or int(pid or 0) <= 4:
        return "", ""
    try:
        import ctypes
        from ctypes import wintypes

        if ctypes.sizeof(ctypes.c_void_p) != 8:
            return "", ""

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL
        k32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
        k32.IsWow64Process.restype = wintypes.BOOL
        k32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        k32.ReadProcessMemory.restype = wintypes.BOOL
        ntdll.NtQueryInformationProcess.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.ULONG,
            ctypes.POINTER(wintypes.ULONG),
        ]
        ntdll.NtQueryInformationProcess.restype = ctypes.c_long

        class _PROCESS_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("Reserved1", ctypes.c_void_p),
                ("PebBaseAddress", ctypes.c_void_p),
                ("Reserved2", ctypes.c_void_p * 2),
                ("UniqueProcessId", ctypes.c_void_p),
                ("Reserved3", ctypes.c_void_p),
            ]

        class _UNICODE_STRING(ctypes.Structure):
            _fields_ = [
                ("Length", wintypes.USHORT),
                ("MaximumLength", wintypes.USHORT),
                ("Buffer", ctypes.c_void_p),
            ]

        hproc = k32.OpenProcess(0x0410, False, int(pid))  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        if not hproc:
            return "", ""
        try:
            wow64 = wintypes.BOOL(0)
            if k32.IsWow64Process(hproc, ctypes.byref(wow64)) and wow64.value:
                return "", ""
            pbi = _PROCESS_BASIC_INFORMATION()
            rlen = wintypes.ULONG(0)
            if (
                ntdll.NtQueryInformationProcess(
                    hproc, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(rlen)
                )
                != 0
                or not pbi.PebBaseAddress
            ):
                return "", ""
            params_ptr = ctypes.c_void_p(0)
            nread = ctypes.c_size_t(0)
            if not k32.ReadProcessMemory(
                hproc,
                ctypes.c_void_p(int(pbi.PebBaseAddress) + 0x20),
                ctypes.byref(params_ptr),
                ctypes.sizeof(params_ptr),
                ctypes.byref(nread),
            ) or not params_ptr.value:
                return "", ""

            flags = wintypes.ULONG(0)
            k32.ReadProcessMemory(
                hproc,
                ctypes.c_void_p(int(params_ptr.value) + 0x08),
                ctypes.byref(flags),
                ctypes.sizeof(flags),
                ctypes.byref(nread),
            )

            def _read_ustr(offset: int) -> str:
                us = _UNICODE_STRING()
                if not k32.ReadProcessMemory(
                    hproc,
                    ctypes.c_void_p(int(params_ptr.value) + offset),
                    ctypes.byref(us),
                    ctypes.sizeof(us),
                    ctypes.byref(nread),
                ):
                    return ""
                if not us.Length or not us.Buffer or us.Length > 65534:
                    return ""
                buf_addr = int(us.Buffer) if (int(flags.value) & 0x01) else (int(params_ptr.value) + int(us.Buffer))
                raw_buf = ctypes.create_string_buffer(int(us.Length))
                if not k32.ReadProcessMemory(
                    hproc,
                    ctypes.c_void_p(buf_addr),
                    raw_buf,
                    int(us.Length),
                    ctypes.byref(nread),
                ):
                    return ""
                return raw_buf.raw.decode("utf-16-le", errors="replace").strip("\x00").strip()

            return _read_ustr(0x38), _read_ustr(0x70)
        finally:
            k32.CloseHandle(hproc)
    except Exception:
        return "", ""


def _snapshot_win32_parent_pids() -> Dict[int, int]:
    """Return `{pid: parent_pid}` across Win32 processes via `CreateToolhelp32Snapshot` (zero subprocess)."""
    if sys.platform != "win32":
        return {}
    import ctypes
    from ctypes import wintypes

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

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    snap = k32.CreateToolhelp32Snapshot(0x00000002, 0)
    invalid_h = wintypes.HANDLE(-1).value
    if not snap or snap == invalid_h:
        return {}
    out: Dict[int, int] = {}
    try:
        pe = _PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        if k32.Process32FirstW(snap, ctypes.byref(pe)):
            while True:
                out[int(pe.th32ProcessID)] = int(pe.th32ParentProcessID)
                if not k32.Process32NextW(snap, ctypes.byref(pe)):
                    break
    finally:
        k32.CloseHandle(snap)
    return out


def _prefetch_process_cmdlines_win32(pids: Iterable[int]) -> None:
    """Populate PEB `(cwd, cmdline)` fast-path cache first, falling back to batched WMI only when needed."""
    if sys.platform != "win32":
        return
    now = time.monotonic()
    missing_peb: List[int] = []
    with _CMDLINE_CACHE_LOCK:
        for raw_p in pids:
            p = int(raw_p or 0)
            if p <= 4:
                continue
            cached = _CMDLINE_CACHE.get((p, ""))
            cwd_cached = _PROC_CWD_CACHE.get(p)
            if not cached or (now - cached[0]) >= 15.0 or not cwd_cached or (now - cwd_cached[0]) >= 15.0:
                if p not in missing_peb:
                    missing_peb.append(p)
    if not missing_peb:
        return

    still_missing_wmi: List[int] = []
    for p in missing_peb:
        ctok = get_process_create_token(p)
        peb_cwd, peb_cmd = _query_process_peb_cwd_and_cmdline_win32(p)
        ts_peb = time.monotonic()
        with _CMDLINE_CACHE_LOCK:
            if peb_cwd:
                _PROC_CWD_CACHE[p] = (ts_peb, ctok, peb_cwd)
            if peb_cmd:
                _CMDLINE_CACHE[(p, "")] = (ts_peb, peb_cmd)
        if not peb_cmd:
            exe_p = _query_process_full_path_win32(p)
            exe_low = os.path.normcase(exe_p)
            if not exe_low.startswith(r"c:\windows\system32\\"):
                still_missing_wmi.append(p)
            else:
                with _CMDLINE_CACHE_LOCK:
                    _CMDLINE_CACHE[(p, "")] = (ts_peb, "")

    if not still_missing_wmi:
        return
    pwsh = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not pwsh:
        return
    for idx in range(0, len(still_missing_wmi), 40):
        chunk = still_missing_wmi[idx : idx + 40]
        or_clause = " OR ".join(f"ProcessId={p}" for p in chunk)
        ps_script = (
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
            f"$ items = @(Get-CimInstance Win32_Process -Filter '{or_clause}' -ErrorAction SilentlyContinue | "
            "ForEach-Object { @{ p = [int]$_.ProcessId; c = [string]$_.CommandLine } }); "
            "[Console]::Out.Write(($items | ConvertTo-Json -Compress))".replace("$ items", "$items")
        )
        enc = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
        fetched: Dict[int, str] = {}
        with contextlib.suppress(Exception):
            r = subprocess.run(
                [pwsh, "-NoProfile", "-NonInteractive", "-EncodedCommand", enc],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=4.5,
                creationflags=win32_no_window_flags(),
            )
            raw_out = (r.stdout or "").strip()
            if raw_out:
                parsed = json.loads(raw_out)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                if isinstance(parsed, list):
                    for row in parsed:
                        if isinstance(row, dict) and row.get("p"):
                            fetched[int(row["p"])] = str(row.get("c") or "").strip()
        ts_done = time.monotonic()
        with _CMDLINE_CACHE_LOCK:
            for p in chunk:
                _CMDLINE_CACHE[(p, "")] = (ts_done, fetched.get(p, ""))


def _query_process_cwd_win32(pid: int) -> str:
    if sys.platform != "win32" or int(pid or 0) <= 4:
        return ""
    p = int(pid)
    ctok = get_process_create_token(p)
    now = time.monotonic()
    with _CMDLINE_CACHE_LOCK:
        cached = _PROC_CWD_CACHE.get(p)
        if cached and (now - cached[0]) < 15.0 and cached[1] == ctok:
            return cached[2]
    peb_cwd, peb_cmd = _query_process_peb_cwd_and_cmdline_win32(p)
    ts_done = time.monotonic()
    with _CMDLINE_CACHE_LOCK:
        _PROC_CWD_CACHE[p] = (ts_done, ctok, peb_cwd)
        if peb_cmd:
            _CMDLINE_CACHE[(p, "")] = (ts_done, peb_cmd)
    return peb_cwd


def _query_process_cmdline_win32(pid: int, exe_hint: str = "") -> str:
    _ = exe_hint
    if sys.platform != "win32" or int(pid or 0) <= 0:
        return ""
    key = (int(pid), "")
    now = time.monotonic()
    with _CMDLINE_CACHE_LOCK:
        cached = _CMDLINE_CACHE.get(key)
        if cached and (now - cached[0]) < 15.0:
            return cached[1]
    _prefetch_process_cmdlines_win32([int(pid)])
    with _CMDLINE_CACHE_LOCK:
        cached2 = _CMDLINE_CACHE.get(key)
        return cached2[1] if cached2 else ""


def _split_win32_cmdline_tokens(cmdline: str) -> List[str]:
    s = (cmdline or "").strip()
    if not s:
        return []
    if sys.platform == "win32":
        with contextlib.suppress(Exception):
            import ctypes
            from ctypes import wintypes

            shell32 = ctypes.WinDLL("shell32", use_last_error=True)
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            shell32.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
            shell32.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
            k32.LocalFree.argtypes = [wintypes.HLOCAL]
            k32.LocalFree.restype = wintypes.HLOCAL
            argc = ctypes.c_int(0)
            argv_ptr = shell32.CommandLineToArgvW(s, ctypes.byref(argc))
            if argv_ptr:
                try:
                    return [str(argv_ptr[i] or "") for i in range(max(0, int(argc.value)))]
                finally:
                    k32.LocalFree(argv_ptr)
    tokens: List[str] = []
    for m in re.finditer(r'"([^"]*)"|\'([^\']*)\'|([^\s"\']+)', s):
        tok = m.group(1) if m.group(1) is not None else (m.group(2) if m.group(2) is not None else m.group(3))
        if tok:
            tokens.append(tok)
    return tokens


def _is_path_inside_any_root(cand_path_str: str, roots: Sequence[Path]) -> bool:
    if not cand_path_str or not roots:
        return False
    cp = _expand_win32_long_path(cand_path_str)
    if not cp:
        return False
    for r in roots:
        rp = _expand_win32_long_path(str(canonical_realpath(r)))
        if rp and (cp == rp or cp.startswith(rp + os.sep)):
            return True
    return False


def _extract_cmdline_path_candidates(cmdline: str) -> Tuple[List[str], List[str]]:
    """Extract `(abs_or_short_candidates, relative_arg_candidates)` from a Win32 command line."""
    abs_cands: List[str] = []
    rel_cands: List[str] = []
    for m in _EMBEDDED_WIN_DRIVE_PATH_RE.finditer(cmdline or ""):
        frag = m.group(1).rstrip(".,;:)")
        if frag and frag not in abs_cands:
            abs_cands.append(frag)

    tokens = _split_win32_cmdline_tokens(cmdline)
    for idx, raw_tok in enumerate(tokens):
        tok = (raw_tok or "").strip().strip("\"'").rstrip(";")
        if not tok or "://" in tok:
            continue
        if idx == 0:
            if "~" in tok or re.match(r"^[A-Za-z]:[\\/]", tok) or tok.startswith("\\\\"):
                if tok not in abs_cands:
                    abs_cands.append(tok)
            elif ("\\" in tok or "/" in tok) and not tok.startswith("-"):
                if tok not in rel_cands:
                    rel_cands.append(tok)
            continue

        if tok.startswith("-"):
            if "=" not in tok:
                continue
            _, tok = tok.split("=", 1)
            tok = tok.strip().strip("\"'")
        elif tok.startswith("/") and len(tok) <= 3 and "." not in tok and "\\" not in tok:
            continue
        elif tok.startswith("/") and ":" in tok and sys.platform == "win32":
            _, rhs = tok.split(":", 1)
            if re.match(r"^[A-Za-z]:[\\/]", rhs) or rhs.startswith((".", "\\")):
                tok = rhs.strip().strip("\"'")

        if not tok or "://" in tok:
            continue
        if re.match(r"^[A-Za-z]:[\\/]", tok) or tok.startswith("\\\\") or "~" in tok or os.path.isabs(tok):
            if tok not in abs_cands:
                abs_cands.append(tok)
        else:
            if tok not in rel_cands:
                rel_cands.append(tok)
    return abs_cands, rel_cands


def _cmdline_references_any_workspace(
    cmdline: str,
    roots: Sequence[Path],
    *,
    proc_cwd: str = "",
) -> bool:
    if not cmdline or not roots:
        return False
    ws_norms = [
        _expand_win32_long_path(str(canonical_realpath(r)))
        for r in roots
        if str(r or "").strip()
    ]
    ws_norms = [w for w in ws_norms if len(w) >= 3]
    if not ws_norms:
        return False

    cmd_norm = os.path.normcase(cmdline).replace("/", "\\")
    for ws_norm in ws_norms:
        idx = cmd_norm.find(ws_norm)
        while idx >= 0:
            end_i = idx + len(ws_norm)
            after_ok = (end_i >= len(cmd_norm)) or (cmd_norm[end_i] in ("\\", '"', "'", " ", "\t", ";"))
            before_ok = (idx == 0) or (cmd_norm[idx - 1] in ('"', "'", " ", "\t", "="))
            if before_ok and after_ok:
                return True
            idx = cmd_norm.find(ws_norm, idx + 1)

    abs_cands, rel_cands = _extract_cmdline_path_candidates(cmdline)
    for cand in abs_cands:
        exp_p = _expand_win32_long_path(cand)
        if exp_p and any(exp_p == ws or exp_p.startswith(ws + os.sep) for ws in ws_norms):
            return True

    clean_cwd = (proc_cwd or "").strip()
    if clean_cwd:
        cwd_long = _expand_win32_long_path(clean_cwd)
        if cwd_long:
            for rel_tok in rel_cands:
                with contextlib.suppress(Exception):
                    joined = Path(cwd_long) / rel_tok
                    if joined.exists() and _is_path_inside_any_root(str(joined), roots):
                        return True
        return False

    # Fallback when process CWD is unavailable (e.g. WOW64 process or standalone cmdline unit test):
    # match relative script/path tokens that resolve inside a workspace root without `..` escape.
    for rel_tok in rel_cands:
        if rel_tok in (".", ".."):
            continue
        ext_low = os.path.splitext(rel_tok)[1].lower()
        if ext_low not in _SCRIPT_LIKE_EXTS and "\\" not in rel_tok and "/" not in rel_tok:
            continue
        for r in roots:
            with contextlib.suppress(Exception):
                ws_real = canonical_realpath(r)
                cand_file = ws_real / rel_tok
                if cand_file.is_file() and _is_path_inside_any_root(str(cand_file), (ws_real,)):
                    return True
    return False


def _cmdline_targets_only_external_path(cmdline: str, roots: Sequence[Path]) -> bool:
    """Return True if argument tokens (`argv[1:]`) explicitly reference an existing external path and zero workspace paths."""
    if not cmdline:
        return False
    tokens = _split_win32_cmdline_tokens(cmdline)
    saw_external = False
    for raw_tok in tokens[1:]:
        tok = (raw_tok or "").strip().strip("\"'")
        if not tok or tok.startswith("-") or "://" in tok:
            continue
        if re.match(r"^[A-Za-z]:[\\/]", tok) or tok.startswith("\\\\"):
            if _is_path_inside_any_root(tok, roots):
                return False
            with contextlib.suppress(Exception):
                if Path(tok).exists():
                    saw_external = True
    return saw_external


def collect_mcp_session_seed_pids(
    *,
    proc_manager: Optional[ProcessManager] = None,
    state_root: Optional[Path] = None,
    prefix: str = "",
    extra_seed_pids: Iterable[int] = (),
    include_self_pid: bool = True,
) -> Set[int]:
    """Collect active MCP session seed PIDs from `ProcessManager` (`active_session_pids`, fg, bg) and `state_root`."""
    seeds: Set[int] = set()
    if include_self_pid:
        seeds.add(os.getpid())
    for ep in extra_seed_pids:
        if int(ep or 0) > 0:
            seeds.add(int(ep))

    if proc_manager is not None:
        # 1. Direct linkage with `ProcessManager.active_session_pids` if present (callable or collection)
        asp = getattr(proc_manager, "active_session_pids", None)
        if callable(asp):
            try:
                vals = asp(prefix)
            except TypeError:
                vals = asp()
            for v in vals or ():
                if int(v or 0) > 0:
                    seeds.add(int(v))
        elif isinstance(asp, (set, frozenset, list, tuple)):
            for v in asp:
                if int(v or 0) > 0:
                    seeds.add(int(v))

        # 2. Live foreground processes in `ProcessManager`
        fg_lock = getattr(proc_manager, "_fg_lock", None)
        fg_map = getattr(proc_manager, "_active_fg_procs", None)
        if isinstance(fg_map, dict):
            if fg_lock is not None:
                with fg_lock:
                    fg_pids = list(fg_map.keys())
            else:
                fg_pids = list(fg_map.keys())
            for fp in fg_pids:
                if int(fp or 0) > 0 and verify_pid_alive(int(fp))[0]:
                    seeds.add(int(fp))

        # 3. Live background jobs in `ProcessManager`
        with contextlib.suppress(Exception):
            bg_list = proc_manager.manage_bg_command(action="list")
            for job in bg_list.get("jobs") or ():
                if isinstance(job, dict) and job.get("running"):
                    jp = int(job.get("pid") or 0)
                    if jp > 0 and verify_pid_alive(jp)[0]:
                        seeds.add(jp)

    if state_root is not None:
        sr = Path(state_root)
        for idx_cand in (sr / "bg_jobs.json", sr / "state" / "bg_jobs.json"):
            if idx_cand.is_file():
                with contextlib.suppress(Exception):
                    doc = json.loads(idx_cand.read_text(encoding="utf-8-sig"))
                    jobs_map = doc.get("jobs") if isinstance(doc, dict) else None
                    if isinstance(jobs_map, dict):
                        for rec in jobs_map.values():
                            if isinstance(rec, dict) and rec.get("exit_code") is None:
                                jp = int(rec.get("pid") or 0)
                                tok = rec.get("proc_create_token")
                                if jp > 0 and verify_pid_alive(jp, tok)[0]:
                                    seeds.add(jp)
        bg_dir = sr / "state" / "bg_jobs"
        if bg_dir.is_dir():
            for jf in bg_dir.glob("*.json"):
                with contextlib.suppress(Exception):
                    doc = json.loads(jf.read_text(encoding="utf-8-sig"))
                    if isinstance(doc, dict) and doc.get("exit_code") is None:
                        j_pref = str(doc.get("tool_prefix") or prefix or "pc").strip()
                        if not prefix or j_pref == prefix:
                            jp = int(doc.get("pid") or 0)
                            tok = doc.get("proc_create_token")
                            if jp > 0 and verify_pid_alive(jp, tok)[0]:
                                seeds.add(jp)
    return seeds


def _is_pid_in_l3_scope(
    owner_pid: int,
    *,
    workspace_roots: Sequence[Path],
    seed_pids: Set[int],
    ppid_map: Optional[Dict[int, int]] = None,
    stop_ancestor_pid: int = 0,
) -> bool:
    if owner_pid <= 0:
        return False
    if owner_pid in seed_pids:
        return True
    pmap = _snapshot_win32_parent_pids() if ppid_map is None else ppid_map
    cur_p = owner_pid
    visited: Set[int] = set()
    for _ in range(12):
        if cur_p in seed_pids:
            return True
        if cur_p <= 4 or cur_p in visited:
            break
        visited.add(cur_p)
        cur_p = int(pmap.get(cur_p) or 0)

    if not workspace_roots:
        return False

    def _win32_ctime_ticks(p_val: int) -> Optional[int]:
        if sys.platform != "win32" or p_val <= 4:
            return None
        tok = get_process_create_token(p_val)
        return int(tok) if (isinstance(tok, str) and tok.isdigit()) else None

    # Inspect target process + up to 3 parent hops: (1) executable realpath, (2) cmdline args (8.3 + realpath), (3) process CWD
    walk_p = owner_pid
    walk_visited: Set[int] = set()
    prev_ctime: Optional[int] = _win32_ctime_ticks(owner_pid)
    for hop in range(4):
        if walk_p <= 4 or walk_p in walk_visited:
            break
        if hop > 0 and stop_ancestor_pid > 0 and walk_p == stop_ancestor_pid:
            break
        walk_visited.add(walk_p)
        if hop > 0 and sys.platform == "win32":
            alive_ok, _ = verify_pid_alive(walk_p)
            if not alive_ok:
                break
            cur_ctime = _win32_ctime_ticks(walk_p)
            if prev_ctime is not None and cur_ctime is not None and cur_ctime > prev_ctime:
                break
            if cur_ctime is not None:
                prev_ctime = cur_ctime

        exe_full = _query_process_full_path_win32(walk_p)
        exe_base = os.path.basename(exe_full).lower() if exe_full else ""
        if hop > 0 and exe_base in _SYSTEM_ANCESTOR_STOP_EXES:
            break
        if exe_full and _is_path_inside_any_root(exe_full, workspace_roots):
            return True

        proc_cwd = _query_process_cwd_win32(walk_p)
        cmdline = _query_process_cmdline_win32(walk_p, exe_hint=exe_full)
        if cmdline and _cmdline_references_any_workspace(cmdline, workspace_roots, proc_cwd=proc_cwd):
            return True
        if proc_cwd and _is_path_inside_any_root(proc_cwd, workspace_roots):
            if not _cmdline_targets_only_external_path(cmdline, workspace_roots):
                return True

        walk_p = int(pmap.get(walk_p) or 0)
    return False


def _is_window_in_l3_workspace_scope(
    hwnd: int,
    *,
    workspace_roots: Sequence[Path],
    seed_pids: Optional[Set[int]] = None,
    ppid_map: Optional[Dict[int, int]] = None,
    owner_pid: int = 0,
    stop_ancestor_pid: int = 0,
) -> bool:
    """Validate whether Win32 `hwnd` belongs to an authorized L3 workspace process or session seed subtree."""
    hw_int = int(hwnd or 0)
    eff_pid = int(owner_pid or 0)
    if hw_int <= 0 and eff_pid <= 0:
        return False
    if sys.platform == "win32" and hw_int > 0:
        import ctypes
        from ctypes import wintypes

        u32 = ctypes.WinDLL("user32", use_last_error=True)
        u32.GetDesktopWindow.argtypes = []
        u32.GetDesktopWindow.restype = wintypes.HWND
        u32.GetShellWindow.argtypes = []
        u32.GetShellWindow.restype = wintypes.HWND
        u32.IsWindow.argtypes = [wintypes.HWND]
        u32.IsWindow.restype = wintypes.BOOL

        desk_h = int(u32.GetDesktopWindow() or 0)
        shell_h = int(u32.GetShellWindow() or 0)
        if hw_int == desk_h or (shell_h > 0 and hw_int == shell_h):
            return False
        if not bool(u32.IsWindow(wintypes.HWND(hw_int))):
            return False
        cls_name, wnd_pid = _read_hwnd_class_and_pid(hw_int)
        if cls_name.lower() in {"progman", "workerw", "shell_traywnd", "shell_secondarytraywnd"}:
            return False
        if eff_pid <= 0:
            eff_pid = wnd_pid

    return _is_pid_in_l3_scope(
        eff_pid,
        workspace_roots=workspace_roots,
        seed_pids=seed_pids if seed_pids is not None else set(),
        ppid_map=ppid_map,
        stop_ancestor_pid=stop_ancestor_pid,
    )


# ---------------------------------------------------------------------------
# 64-Bit Safe Win32 Message, Geometry, Menu, Dialog & UIA Primitives
# ---------------------------------------------------------------------------


def _post_message_64safe(hwnd: int, msg_id: int, wparam: int = 0, lparam: int = 0) -> bool:
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    u32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    u32.PostMessageW.restype = wintypes.BOOL
    wmask = (1 << (ctypes.sizeof(wintypes.WPARAM) * 8)) - 1
    lbits = ctypes.sizeof(wintypes.LPARAM) * 8
    lmask = (1 << lbits) - 1
    lu = int(lparam) & lmask
    if lu >= (1 << (lbits - 1)):
        lu -= 1 << lbits
    return bool(
        u32.PostMessageW(
            wintypes.HWND(int(hwnd)),
            wintypes.UINT(int(msg_id)),
            wintypes.WPARAM(int(wparam) & wmask),
            wintypes.LPARAM(lu),
        )
    )


def _send_text_win32_64safe(target_hwnd: int, msg_id: int, wparam: int, text_val: str) -> int:
    """Explicit 64-bit ctypes pointer declaration for `SendMessageW(..., LPCWSTR)`."""
    import ctypes
    from ctypes import wintypes

    if not is_hwnd_responsive_win32(target_hwnd, timeout_ms=600):
        raise TimeoutError(f"Target HWND {target_hwnd} did not respond within 600ms before SendMessageW.")
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPCWSTR]
    user32.SendMessageW.restype = ctypes.c_ssize_t
    mask = (1 << (ctypes.sizeof(wintypes.WPARAM) * 8)) - 1
    res = user32.SendMessageW(
        wintypes.HWND(int(target_hwnd)),
        wintypes.UINT(int(msg_id)),
        wintypes.WPARAM(int(wparam) & mask),
        str(text_val),
    )
    return int(res)


def _send_int_msg_timeout_win32(
    target_hwnd: int,
    msg_id: int,
    wparam: int = 0,
    lparam: int = 0,
    timeout_ms: int = 120,
) -> Tuple[bool, int]:
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    smto = u32.SendMessageTimeoutW
    smto.argtypes = [
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
        wintypes.UINT,
        wintypes.UINT,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    smto.restype = wintypes.LPARAM
    wmask = (1 << (ctypes.sizeof(wintypes.WPARAM) * 8)) - 1
    lbits = ctypes.sizeof(wintypes.LPARAM) * 8
    lmask = (1 << lbits) - 1
    lu = int(lparam) & lmask
    if lu >= (1 << (lbits - 1)):
        lu -= 1 << lbits
    out_val = ctypes.c_size_t(0)
    ok = bool(
        smto(
            wintypes.HWND(int(target_hwnd)),
            wintypes.UINT(int(msg_id)),
            wintypes.WPARAM(int(wparam) & wmask),
            wintypes.LPARAM(lu),
            0x0002,
            int(timeout_ms),
            ctypes.byref(out_val),
        )
    )
    return ok, int(out_val.value)


def _read_hwnd_text_64safe(target_hwnd: int, max_chars: int = 256) -> str:
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    buf = ctypes.create_unicode_buffer(max_chars)
    ok, _ = _send_int_msg_timeout_win32(
        target_hwnd,
        0x000D,  # WM_GETTEXT
        max_chars - 1,
        ctypes.addressof(buf),
        timeout_ms=80,
    )
    txt = buf.value.strip() if ok else ""
    if not txt:
        u32.GetWindowTextW(wintypes.HWND(int(target_hwnd)), buf, max_chars - 1)
        txt = buf.value.strip()
    return txt


def _read_hwnd_class_and_pid(hwnd: int) -> Tuple[str, int]:
    if sys.platform != "win32" or int(hwnd or 0) <= 0:
        return "", 0
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    cbuf = ctypes.create_unicode_buffer(128)
    u32.GetClassNameW(wintypes.HWND(int(hwnd)), cbuf, 127)
    wpid = wintypes.DWORD(0)
    u32.GetWindowThreadProcessId(wintypes.HWND(int(hwnd)), ctypes.byref(wpid))
    return cbuf.value.strip(), int(wpid.value or 0)


@contextlib.contextmanager
def _align_thread_dpi_to_window(hwnd: int) -> Iterator[None]:
    """Temporarily switch the calling thread's `DPI_AWARENESS_CONTEXT` to match `hwnd` (or PMv2 `-4` when `hwnd<=0`)."""
    if sys.platform != "win32":
        yield
        return
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    set_ctx = getattr(u32, "SetThreadDpiAwarenessContext", None)
    if set_ctx is None:
        yield
        return
    set_ctx.argtypes = [ctypes.c_void_p]
    set_ctx.restype = ctypes.c_void_p
    u32.IsWindow.argtypes = [wintypes.HWND]
    u32.IsWindow.restype = wintypes.BOOL

    target_ctx = ctypes.c_void_p(-4)  # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
    hw_int = int(hwnd or 0)
    get_win_ctx = getattr(u32, "GetWindowDpiAwarenessContext", None)
    if hw_int > 0 and get_win_ctx is not None and bool(u32.IsWindow(wintypes.HWND(hw_int))):
        get_win_ctx.argtypes = [wintypes.HWND]
        get_win_ctx.restype = ctypes.c_void_p
        win_ctx = get_win_ctx(wintypes.HWND(hw_int))
        if win_ctx:
            target_ctx = ctypes.c_void_p(win_ctx)

    prev_ctx = set_ctx(target_ctx)
    try:
        yield
    finally:
        if prev_ctx is not None:
            set_ctx(ctypes.c_void_p(prev_ctx))


def get_window_dpi_info(hwnd: int = 0) -> Dict[str, Any]:
    """Return `{'dpi': int, 'dpi_scale': float, 'window_dpi_aware': bool}` for `hwnd` (or primary display if `hwnd<=0`)."""
    if sys.platform != "win32":
        return {"dpi": 96, "dpi_scale": 1.0, "window_dpi_aware": True}
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    u32.IsWindow.argtypes = [wintypes.HWND]
    u32.IsWindow.restype = wintypes.BOOL

    hw_int = int(hwnd or 0)
    h_arg = wintypes.HWND(hw_int)
    hwnd_valid = hw_int > 0 and bool(u32.IsWindow(h_arg))

    window_dpi_aware = True
    if (
        hwnd_valid
        and hasattr(u32, "GetWindowDpiAwarenessContext")
        and hasattr(u32, "AreDpiAwarenessContextsEqual")
    ):
        with contextlib.suppress(Exception):
            u32.GetWindowDpiAwarenessContext.argtypes = [wintypes.HWND]
            u32.GetWindowDpiAwarenessContext.restype = ctypes.c_void_p
            u32.AreDpiAwarenessContextsEqual.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            u32.AreDpiAwarenessContextsEqual.restype = wintypes.BOOL
            win_ctx = u32.GetWindowDpiAwarenessContext(h_arg)
            if win_ctx:
                is_unaware = bool(
                    u32.AreDpiAwarenessContextsEqual(ctypes.c_void_p(win_ctx), ctypes.c_void_p(-1))
                    or u32.AreDpiAwarenessContextsEqual(ctypes.c_void_p(win_ctx), ctypes.c_void_p(-5))
                )
                window_dpi_aware = not is_unaware

    dpi = 0
    with _align_thread_dpi_to_window(0):
        u32.MonitorFromWindow.argtypes = [wintypes.HWND, wintypes.DWORD]
        u32.MonitorFromWindow.restype = wintypes.HMONITOR
        u32.MonitorFromPoint.argtypes = [wintypes.POINT, wintypes.DWORD]
        u32.MonitorFromPoint.restype = wintypes.HMONITOR

        if hwnd_valid and window_dpi_aware and hasattr(u32, "GetDpiForWindow"):
            with contextlib.suppress(Exception):
                u32.GetDpiForWindow.argtypes = [wintypes.HWND]
                u32.GetDpiForWindow.restype = wintypes.UINT
                cand_dpi = int(u32.GetDpiForWindow(h_arg) or 0)
                if cand_dpi > 0:
                    # If window is placed offscreen (`MonitorFromWindow(DEFAULTTONULL) == 0`) and reported 96,
                    # check primary monitor DPI so offscreen high-DPI windows report host monitor scale accurately.
                    if cand_dpi == 96 and not u32.MonitorFromWindow(h_arg, 0):
                        cand_dpi = 0
                    dpi = cand_dpi

        shcore = None
        with contextlib.suppress(Exception):
            shcore = ctypes.WinDLL("shcore", use_last_error=True)

        if dpi <= 0 and shcore is not None and hasattr(shcore, "GetDpiForMonitor"):
            with contextlib.suppress(Exception):
                hmon = (
                    u32.MonitorFromWindow(h_arg, 1)
                    if hwnd_valid
                    else u32.MonitorFromPoint(wintypes.POINT(0, 0), 1)
                )
                if hmon:
                    shcore.GetDpiForMonitor.argtypes = [
                        wintypes.HMONITOR,
                        ctypes.c_int,
                        ctypes.POINTER(ctypes.c_uint),
                        ctypes.POINTER(ctypes.c_uint),
                    ]
                    shcore.GetDpiForMonitor.restype = ctypes.c_long
                    dx, dy = ctypes.c_uint(0), ctypes.c_uint(0)
                    if shcore.GetDpiForMonitor(hmon, 0, ctypes.byref(dx), ctypes.byref(dy)) == 0 and dx.value > 0:
                        dpi = int(dx.value)

        if dpi <= 0 and hasattr(u32, "GetDpiForSystem"):
            with contextlib.suppress(Exception):
                u32.GetDpiForSystem.argtypes = []
                u32.GetDpiForSystem.restype = wintypes.UINT
                dpi = int(u32.GetDpiForSystem() or 0)

        if dpi <= 0 and shcore is not None and hasattr(shcore, "GetScaleFactorForMonitor"):
            with contextlib.suppress(Exception):
                hmon = (
                    u32.MonitorFromWindow(h_arg, 1)
                    if hwnd_valid
                    else u32.MonitorFromPoint(wintypes.POINT(0, 0), 1)
                )
                if hmon:
                    shcore.GetScaleFactorForMonitor.argtypes = [wintypes.HMONITOR, ctypes.POINTER(ctypes.c_int)]
                    shcore.GetScaleFactorForMonitor.restype = ctypes.c_long
                    sf = ctypes.c_int(0)
                    if shcore.GetScaleFactorForMonitor(hmon, ctypes.byref(sf)) == 0 and sf.value > 0:
                        dpi = int(round(96.0 * float(sf.value) / 100.0))

    if dpi <= 0:
        dpi = 96
    return {
        "dpi": dpi,
        "dpi_scale": round(float(dpi) / 96.0, 4),
        "window_dpi_aware": window_dpi_aware,
    }


def get_window_dpi_scale(hwnd: int = 0) -> float:
    """Return effective display DPI scale (e.g. `1.25` at 120 DPI, `1.5` at 144 DPI) for `hwnd`."""
    return float(get_window_dpi_info(hwnd)["dpi_scale"])


def get_window_rect(hwnd: int) -> Tuple[int, int, int, int]:
    """Return `(left, top, right, bottom)` in `hwnd`'s own thread-aligned DPI coordinate space."""
    if sys.platform != "win32" or int(hwnd or 0) <= 0:
        return 0, 0, 0, 0
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    u32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    u32.GetWindowRect.restype = wintypes.BOOL
    rc = wintypes.RECT()
    with _align_thread_dpi_to_window(int(hwnd)):
        u32.GetWindowRect(wintypes.HWND(int(hwnd)), ctypes.byref(rc))
    return int(rc.left), int(rc.top), int(rc.right), int(rc.bottom)


def _get_window_geometry_win32(hwnd: int) -> Dict[str, Any]:
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    u32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    u32.GetWindowRect.restype = wintypes.BOOL
    u32.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    u32.GetClientRect.restype = wintypes.BOOL
    u32.ClientToScreen.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.POINT)]
    u32.ClientToScreen.restype = wintypes.BOOL
    u32.IsIconic.argtypes = [wintypes.HWND]
    u32.IsIconic.restype = wintypes.BOOL

    h_arg = wintypes.HWND(int(hwnd))
    wrc = wintypes.RECT()
    crc = wintypes.RECT()
    pt_cli = wintypes.POINT(0, 0)
    with _align_thread_dpi_to_window(int(hwnd)):
        u32.GetWindowRect(h_arg, ctypes.byref(wrc))
        u32.GetClientRect(h_arg, ctypes.byref(crc))
        u32.ClientToScreen(h_arg, ctypes.byref(pt_cli))
        is_min = bool(u32.IsIconic(h_arg))

    win_w = max(0, int(wrc.right - wrc.left))
    win_h = max(0, int(wrc.bottom - wrc.top))
    cli_w = max(0, int(crc.right - crc.left))
    cli_h = max(0, int(crc.bottom - crc.top))
    dpi_info = get_window_dpi_info(int(hwnd))

    return {
        "window_rect": [int(wrc.left), int(wrc.top), int(wrc.right), int(wrc.bottom)],
        "window_size": [win_w, win_h],
        "client_size": [cli_w, cli_h],
        "client_offset": [int(pt_cli.x - wrc.left), int(pt_cli.y - wrc.top)],
        "minimized": is_min,
        "dpi": dpi_info["dpi"],
        "dpi_scale": dpi_info["dpi_scale"],
        "system_dpi_scale": dpi_info["dpi_scale"],
        "window_dpi": dpi_info["dpi"],
        "window_dpi_aware": dpi_info["window_dpi_aware"],
    }


def _clean_menu_label(raw: str) -> str:
    s = (raw or "").split("\t", 1)[0].strip()
    s = re.sub(r"\(&[A-Za-z0-9]\)", "", s)
    return s.replace("&", "").replace("...", "").replace("…", "").strip()


def _enum_win32_menu_bar(hwnd: int) -> List[Dict[str, Any]]:
    if sys.platform != "win32":
        return []
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    u32.GetMenu.argtypes = [wintypes.HWND]
    u32.GetMenu.restype = wintypes.HMENU
    u32.GetSubMenu.argtypes = [wintypes.HMENU, ctypes.c_int]
    u32.GetSubMenu.restype = wintypes.HMENU
    u32.GetMenuItemCount.argtypes = [wintypes.HMENU]
    u32.GetMenuItemCount.restype = ctypes.c_int
    u32.GetMenuItemID.argtypes = [wintypes.HMENU, ctypes.c_int]
    u32.GetMenuItemID.restype = wintypes.UINT
    u32.GetMenuStringW.argtypes = [wintypes.HMENU, wintypes.UINT, wintypes.LPWSTR, ctypes.c_int, wintypes.UINT]
    u32.GetMenuStringW.restype = ctypes.c_int
    u32.GetMenuItemRect.argtypes = [wintypes.HWND, wintypes.HMENU, wintypes.UINT, ctypes.POINTER(wintypes.RECT)]
    u32.GetMenuItemRect.restype = wintypes.BOOL
    u32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    u32.GetWindowRect.restype = wintypes.BOOL

    h_arg = wintypes.HWND(int(hwnd))
    hmenu = u32.GetMenu(h_arg)
    if not hmenu:
        return []
    items: List[Dict[str, Any]] = []
    with _align_thread_dpi_to_window(int(hwnd)):
        wrc = wintypes.RECT()
        u32.GetWindowRect(h_arg, ctypes.byref(wrc))
        wl, wt = int(wrc.left), int(wrc.top)

        def _walk(cur_menu: Any, parent_path: str, depth: int) -> None:
            if not cur_menu or depth > 3 or len(items) >= 80:
                return
            cnt = int(u32.GetMenuItemCount(cur_menu))
            for idx in range(max(0, cnt)):
                buf = ctypes.create_unicode_buffer(256)
                u32.GetMenuStringW(cur_menu, idx, buf, 255, 0x0400)  # MF_BYPOSITION
                raw_lbl = buf.value.strip()
                sub = u32.GetSubMenu(cur_menu, idx)
                raw_id = int(u32.GetMenuItemID(cur_menu, idx))
                cmd_id = raw_id if (not sub and 0 < raw_id < 0xFFFFFFFF) else 0
                if not raw_lbl and cmd_id == 0 and not sub:
                    continue
                clean_lbl = _clean_menu_label(raw_lbl) or raw_lbl
                full_path = f"{parent_path} > {clean_lbl}" if parent_path else clean_lbl
                bbox = {"x": 0, "y": 0, "width": 0, "height": 0}
                center = [0, 0]
                if depth == 0:
                    mrc = wintypes.RECT()
                    if u32.GetMenuItemRect(h_arg, cur_menu, idx, ctypes.byref(mrc)):
                        bx, by = int(mrc.left) - wl, int(mrc.top) - wt
                        bw, bh = max(0, int(mrc.right - mrc.left)), max(0, int(mrc.bottom - mrc.top))
                        bbox = {"x": bx, "y": by, "width": bw, "height": bh}
                        center = [bx + bw // 2, by + bh // 2]
                aid = f"menu_{cmd_id}" if cmd_id > 0 else f"menubar_{idx}"
                items.append(
                    {
                        "name": raw_lbl,
                        "clean_name": clean_lbl,
                        "menu_path": full_path,
                        "automation_id": aid,
                        "menu_command_id": cmd_id,
                        "has_submenu": bool(sub),
                        "depth": depth,
                        "control_type": "MenuItem",
                        "class_name": "Win32Menu",
                        "native_hwnd": int(hwnd),
                        "enabled": True,
                        "bbox": bbox,
                        "window_rel_bounds": dict(bbox),
                        "center": center,
                    }
                )
                if sub:
                    _walk(sub, full_path, depth + 1)

        _walk(hmenu, "", 0)
    return items


def _enum_owned_dialogs_win32(parent_hwnd: int, owner_pid: int = 0) -> List[Dict[str, Any]]:
    """Enumerate visible owned popup / `#32770` modal sub-dialogs associated with `parent_hwnd`."""
    if sys.platform != "win32" or int(parent_hwnd or 0) <= 0:
        return []
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    u32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
    u32.GetWindow.restype = wintypes.HWND
    u32.IsWindowVisible.argtypes = [wintypes.HWND]
    u32.IsWindowVisible.restype = wintypes.BOOL
    if owner_pid <= 0:
        _, owner_pid = _read_hwnd_class_and_pid(parent_hwnd)

    dialogs: List[Dict[str, Any]] = []
    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

    def _cb(hw: int, _lp: int) -> bool:
        hwi = int(hw or 0)
        if hwi <= 0 or hwi == int(parent_hwnd):
            return True
        if not u32.IsWindowVisible(wintypes.HWND(hwi)):
            return True
        gw_owner = int(u32.GetWindow(wintypes.HWND(hwi), 4) or 0)  # GW_OWNER = 4
        cls_name, wpid = _read_hwnd_class_and_pid(hwi)
        is_owned = gw_owner == int(parent_hwnd)
        is_same_pid_dlg = owner_pid > 0 and wpid == owner_pid and cls_name == "#32770"
        if not (is_owned or is_same_pid_dlg):
            return True
        title = _read_hwnd_text_64safe(hwi, max_chars=256)
        dl, dt, dr, db = get_window_rect(hwi)
        dialogs.append(
            {
                "hwnd": hwi,
                "owner_hwnd": gw_owner,
                "pid": wpid,
                "class_name": cls_name,
                "title": title,
                "is_common_dialog": cls_name == "#32770",
                "bounds": {
                    "x": dl,
                    "y": dt,
                    "width": max(0, dr - dl),
                    "height": max(0, db - dt),
                },
            }
        )
        return True

    u32.EnumWindows(WNDENUMPROC(_cb), 0)
    return dialogs


def _enum_windows_zero_focus(
    on_screen_only: bool = True,
    include_minimized: bool = False,
    pid_filter: int = 0,
    title_query: str = "",
) -> List[Dict[str, Any]]:
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    u32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
    u32.GetWindow.restype = wintypes.HWND
    u32.GetForegroundWindow.argtypes = []
    u32.GetForegroundWindow.restype = wintypes.HWND
    u32.IsWindowVisible.argtypes = [wintypes.HWND]
    u32.IsWindowVisible.restype = wintypes.BOOL
    u32.IsIconic.argtypes = [wintypes.HWND]
    u32.IsIconic.restype = wintypes.BOOL
    dwm = getattr(ctypes.windll, "dwmapi", None)
    fg_hwnd = int(u32.GetForegroundWindow() or 0)
    skip_classes = {"progman", "workerw", "shell_traywnd", "shell_secondarytraywnd", "msctfime ui", "ime"}
    skip_titles = {"Program Manager", "MSCTFIME UI", "Default IME", "Windows Input Experience", "Windows 输入体验"}
    q_low = (title_query or "").strip().lower()
    results: List[Dict[str, Any]] = []

    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

    def _cb(hwnd: int, _lp: int) -> bool:
        hw = int(hwnd or 0)
        if hw <= 0:
            return True
        visible = bool(u32.IsWindowVisible(wintypes.HWND(hw)))
        if on_screen_only and not visible and pid_filter <= 0 and not q_low:
            return True
        minimized = bool(u32.IsIconic(wintypes.HWND(hw)))
        if on_screen_only and minimized and not include_minimized and pid_filter <= 0 and not q_low:
            return True
        if on_screen_only and dwm is not None and pid_filter <= 0 and not q_low:
            cloaked = ctypes.c_int(0)
            if dwm.DwmGetWindowAttribute(wintypes.HWND(hw), 14, ctypes.byref(cloaked), ctypes.sizeof(cloaked)) == 0 and cloaked.value != 0:
                return True

        cls_name, p_val = _read_hwnd_class_and_pid(hw)
        if pid_filter > 0 and p_val != pid_filter:
            return True

        tbuf = ctypes.create_unicode_buffer(512)
        u32.GetWindowTextW(wintypes.HWND(hw), tbuf, 511)
        title = tbuf.value.strip()
        if cls_name.lower() in skip_classes or title in skip_titles:
            return True
        if not title and cls_name != "#32770" and pid_filter <= 0 and not q_low:
            return True

        proc_name = _query_process_name_win32(p_val)
        if q_low and (q_low not in title.lower() and q_low not in proc_name.lower() and q_low not in cls_name.lower()):
            return True

        rl, rt, rr, rb = get_window_rect(hw)
        w, h = int(rr - rl), int(rb - rt)
        if on_screen_only and (w <= 1 or h <= 1) and pid_filter <= 0 and not q_low:
            return True

        owner_hw = int(u32.GetWindow(wintypes.HWND(hw), 4) or 0)
        results.append(
            {
                "hwnd": hw,
                "window_id": hw,
                "owner_hwnd": owner_hw,
                "pid": p_val,
                "process_name": proc_name,
                "class_name": cls_name,
                "is_dialog": cls_name == "#32770",
                "title": title,
                "bounds": {"x": rl, "y": rt, "width": w, "height": h},
                "visible": visible,
                "minimized": minimized,
                "is_foreground": hw == fg_hwnd,
                "responsive": is_hwnd_responsive_win32(hw, timeout_ms=80),
            }
        )
        return True

    u32.EnumWindows(WNDENUMPROC(_cb), 0)
    return results


def _resolve_target_hwnd(
    hwnd: int,
    pid: int,
    title_query: str,
    *,
    prefer_authorized_fn: Optional[Callable[[int], bool]] = None,
) -> Tuple[int, Optional[str]]:
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    u32.IsWindow.argtypes = [wintypes.HWND]
    u32.IsWindow.restype = wintypes.BOOL
    u32.GetDesktopWindow.argtypes = []
    u32.GetDesktopWindow.restype = wintypes.HWND

    if int(hwnd or 0) > 0:
        hw = int(hwnd)
        if hw == int(u32.GetDesktopWindow() or 0):
            return hw, None
        if not u32.IsWindow(wintypes.HWND(hw)):
            return 0, f"Window HWND {hw} does not exist."
        if not is_hwnd_responsive_win32(hw, timeout_ms=600):
            return 0, f"Window HWND {hw} did not respond within 600ms (hung window guard)."
        return hw, None

    if int(pid or 0) > 0 or (title_query or "").strip():
        cands = _enum_windows_zero_focus(
            on_screen_only=False,
            include_minimized=True,
            pid_filter=int(pid or 0),
            title_query=title_query,
        )
        cands.sort(
            key=lambda w: (
                0 if (prefer_authorized_fn is not None and prefer_authorized_fn(int(w["pid"]))) else 1,
                0 if (w["visible"] and not w["minimized"] and w["bounds"]["width"] > 10 and w["bounds"]["height"] > 10) else 1,
                0 if w["title"] else 1,
                -(w["bounds"]["width"] * w["bounds"]["height"]),
            )
        )
        for c in cands:
            if is_hwnd_responsive_win32(c["hwnd"], timeout_ms=150):
                return int(c["hwnd"]), None
        return 0, f"No responsive window matched pid={pid}, title_query={title_query!r}."

    return 0, "Provide `hwnd` (or `pid` / `title_query`) to target a specific window; full-desktop capture is prohibited."


def _capture_hwnd_printwindow_offscreen(
    hwnd: int,
    *,
    grid_step: int = 0,
    prefix: str = "pc",
    desktop_name_override: Optional[str] = None,
) -> Dict[str, Any]:
    """Capture a Win32 HWND offscreen via `PrintWindow(hwnd, hdc, PW_RENDERFULLCONTENT=2)` with black-frame & lock-screen detection."""
    import ctypes
    from ctypes import wintypes

    try:
        from PIL import Image as _PilImage  # type: ignore
    except ImportError:
        _PilImage = None

    class _BITMAPINFOHEADER(ctypes.Structure):
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

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
    u32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    u32.GetWindowRect.restype = wintypes.BOOL
    u32.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    u32.GetClientRect.restype = wintypes.BOOL
    u32.IsIconic.argtypes = [wintypes.HWND]
    u32.IsIconic.restype = wintypes.BOOL
    u32.GetWindowDC.argtypes = [wintypes.HWND]
    u32.GetWindowDC.restype = wintypes.HDC
    u32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
    u32.ReleaseDC.restype = ctypes.c_int
    u32.PrintWindow.argtypes = [wintypes.HWND, wintypes.HDC, wintypes.UINT]
    u32.PrintWindow.restype = wintypes.BOOL
    gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]
    gdi32.CreateCompatibleDC.restype = wintypes.HDC
    gdi32.CreateCompatibleBitmap.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int]
    gdi32.CreateCompatibleBitmap.restype = wintypes.HBITMAP
    gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
    gdi32.SelectObject.restype = wintypes.HGDIOBJ
    gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
    gdi32.DeleteObject.restype = wintypes.BOOL
    gdi32.DeleteDC.argtypes = [wintypes.HDC]
    gdi32.DeleteDC.restype = wintypes.BOOL
    gdi32.GetDIBits.argtypes = [
        wintypes.HDC,
        wintypes.HBITMAP,
        wintypes.UINT,
        wintypes.UINT,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.UINT,
    ]
    gdi32.GetDIBits.restype = ctypes.c_int

    h_arg = wintypes.HWND(int(hwnd))
    win_title = _read_hwnd_text_64safe(int(hwnd), max_chars=512)
    cls_name, owner_pid = _read_hwnd_class_and_pid(int(hwnd))

    with _align_thread_dpi_to_window(int(hwnd)):
        rc = wintypes.RECT()
        u32.GetWindowRect(h_arg, ctypes.byref(rc))
        w, h = int(rc.right - rc.left), int(rc.bottom - rc.top)

        if bool(u32.IsIconic(h_arg)):
            return {
                "ok": False,
                "hwnd": int(hwnd),
                "title": win_title,
                "window_minimized": True,
                "minimized_stub_size": [w, h],
                "error": (
                    f"Window HWND {hwnd} (`{win_title}`) is currently minimized (`IsIconic=True`, {w}x{h} titlebar stub). "
                    "Offscreen PrintWindow cannot render client controls while minimized."
                ),
                "hint": f"Restore the window without stealing focus via {prefix}_cua_window(action='restore', hwnd={hwnd}) before calling action='capture' or 'click'.",
            }

        if w <= 0 or h <= 0:
            crc = wintypes.RECT()
            u32.GetClientRect(h_arg, ctypes.byref(crc))
            w, h = int(crc.right - crc.left), int(crc.bottom - crc.top)
        if w <= 0 or h <= 0:
            return {"ok": False, "hwnd": int(hwnd), "error": f"Window HWND {hwnd} has zero dimensions ({w}x{h}); restore or resize before PrintWindow capture."}

        w = min(w, 4096)
        h = min(h, 4096)
        hwnd_dc = u32.GetWindowDC(h_arg)
        if not hwnd_dc:
            return {"ok": False, "hwnd": int(hwnd), "error": f"GetWindowDC failed for HWND {hwnd}."}

        mem_dc = gdi32.CreateCompatibleDC(hwnd_dc)
        bmp = gdi32.CreateCompatibleBitmap(hwnd_dc, w, h)
        old_bmp = gdi32.SelectObject(mem_dc, bmp)
        try:
            pw_ok = bool(u32.PrintWindow(h_arg, mem_dc, PW_RENDERFULLCONTENT))
            if not pw_ok:
                pw_ok = bool(u32.PrintWindow(h_arg, mem_dc, 0))
            if not pw_ok:
                _send_int_msg_timeout_win32(int(hwnd), 0x0317, int(mem_dc), 0x1E, timeout_ms=200)
                pw_ok = True

            bmi = _BITMAPINFOHEADER()
            bmi.biSize = ctypes.sizeof(_BITMAPINFOHEADER)
            bmi.biWidth = w
            bmi.biHeight = -h  # top-down DIB
            bmi.biPlanes = 1
            bmi.biBitCount = 32
            bmi.biCompression = 0

            buf = ctypes.create_string_buffer(w * h * 4)
            gdi32.GetDIBits(mem_dc, bmp, 0, h, buf, ctypes.byref(bmi), 0)
            rgb_buf = bgra_to_rgb_packed(buf.raw, w, h)
            if not any(rgb_buf):
                if bool(u32.PrintWindow(h_arg, mem_dc, 0)):
                    pw_ok = True
                    gdi32.GetDIBits(mem_dc, bmp, 0, h, buf, ctypes.byref(bmi), 0)
                    rgb_buf = bgra_to_rgb_packed(buf.raw, w, h)
            if not any(rgb_buf):
                _send_int_msg_timeout_win32(int(hwnd), 0x0317, int(mem_dc), 0x1E, timeout_ms=250)
                pw_ok = True
                gdi32.GetDIBits(mem_dc, bmp, 0, h, buf, ctypes.byref(bmi), 0)
                rgb_buf = bgra_to_rgb_packed(buf.raw, w, h)
        finally:
            gdi32.SelectObject(mem_dc, old_bmp)
            gdi32.DeleteObject(bmp)
            gdi32.DeleteDC(mem_dc)
            u32.ReleaseDC(h_arg, hwnd_dc)

    # Check lock-screen (`Winlogon`) and all-zero pure black pixels BEFORE drawing grid overlay!
    is_bad, is_locked, is_black = check_locked_or_black_rgb_frame(rgb_buf, desktop_name=desktop_name_override)
    if is_bad:
        reason_detail = "locked Winlogon desktop" if is_locked else "all-zero pure black frame"
        return {
            "ok": False,
            "hwnd": int(hwnd),
            "title": win_title,
            "class_name": cls_name,
            "error_code": ERR_SCREEN_LOCKED_OR_BLACK_FRAME,
            "screen_locked": is_locked,
            "black_frame": is_black,
            "captured_size": [w, h],
            "error": (
                f"{ERR_SCREEN_LOCKED_OR_BLACK_FRAME}: Offscreen PrintWindow(2) capture for HWND {hwnd} "
                f"(`{win_title}`) detected {reason_detail} ({w}x{h}); refusing to report a blank frame as ok=True."
            ),
        }

    eff_grid = int(grid_step or 0) if int(grid_step or 0) >= 20 else 0
    if eff_grid >= 20:
        draw_coordinate_grid_rgb(rgb_buf, w, h, grid_step=eff_grid)

    if _PilImage is not None:
        img = _PilImage.frombytes("RGB", (w, h), bytes(rgb_buf))
        png_io = io.BytesIO()
        img.save(png_io, format="PNG")
        raw_png_out = png_io.getvalue()
    else:
        raw_png_out = encode_rgb_png_stdlib(rgb_buf, w, h)

    geom = _get_window_geometry_win32(hwnd)
    owned_dialogs = _enum_owned_dialogs_win32(int(hwnd), owner_pid=owner_pid)
    return {
        "ok": bool(pw_ok),
        "hwnd": int(hwnd),
        "title": win_title,
        "class_name": cls_name,
        "is_dialog": cls_name == "#32770",
        "owned_dialogs": owned_dialogs,
        "window_minimized": False,
        "window_rect": [int(rc.left), int(rc.top), int(rc.right), int(rc.bottom)],
        "captured_size": [w, h],
        "client_offset": geom["client_offset"],
        "dpi": geom["dpi"],
        "dpi_scale": geom["dpi_scale"],
        "window_dpi_aware": geom["window_dpi_aware"],
        "grid_step": eff_grid,
        "grid_drawn": eff_grid >= 20,
        "coordinate_space": "window_capture_px",
        "raw_png": raw_png_out,
    }


capture_window_offscreen = _capture_hwnd_printwindow_offscreen


def _infer_win32_control_type(class_name: str, style: int) -> str:
    cl = (class_name or "").strip().lower()
    if cl == "button":
        bs = style & 0x0F
        if bs in (2, 3, 5, 6):
            return "CheckBox"
        if bs in (4, 9):
            return "RadioButton"
        if bs == 7:
            return "Group"
        return "Button"
    if "edit" in cl or "richedit" in cl:
        return "Edit"
    if "combobox" in cl:
        return "ComboBox"
    if "listbox" in cl:
        return "List"
    if "syslistview" in cl:
        return "DataGrid"
    if "systreeview" in cl:
        return "Tree"
    if "static" in cl:
        return "Text"
    return class_name or "Custom"


def _enum_win32_child_controls(parent_hwnd: int, max_items: int = 100) -> List[Dict[str, Any]]:
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    u32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    u32.GetWindowRect.restype = wintypes.BOOL
    u32.IsWindowVisible.argtypes = [wintypes.HWND]
    u32.IsWindowVisible.restype = wintypes.BOOL
    u32.IsWindowEnabled.argtypes = [wintypes.HWND]
    u32.IsWindowEnabled.restype = wintypes.BOOL
    u32.GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
    u32.GetWindowLongW.restype = wintypes.LONG
    u32.GetDlgCtrlID.argtypes = [wintypes.HWND]
    u32.GetDlgCtrlID.restype = ctypes.c_int

    items: List[Dict[str, Any]] = []
    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

    with _align_thread_dpi_to_window(int(parent_hwnd)):
        p_rc = wintypes.RECT()
        u32.GetWindowRect(wintypes.HWND(int(parent_hwnd)), ctypes.byref(p_rc))
        pl, pt = int(p_rc.left), int(p_rc.top)

        def _cb(ch_hwnd: int, _lp: int) -> bool:
            if len(items) >= max_items:
                return False
            chw = int(ch_hwnd or 0)
            if chw <= 0:
                return True
            cbuf = ctypes.create_unicode_buffer(128)
            u32.GetClassNameW(wintypes.HWND(chw), cbuf, 127)
            cls_s = cbuf.value.strip()
            style = int(u32.GetWindowLongW(wintypes.HWND(chw), -16) or 0)
            txt = _read_hwnd_text_64safe(chw, max_chars=256)
            rc = wintypes.RECT()
            u32.GetWindowRect(wintypes.HWND(chw), ctypes.byref(rc))
            ctrl_id = int(u32.GetDlgCtrlID(wintypes.HWND(chw)) or 0)
            bx = int(rc.left) - pl
            by = int(rc.top) - pt
            bw = max(0, int(rc.right - rc.left))
            bh = max(0, int(rc.bottom - rc.top))
            bbox = {"x": bx, "y": by, "width": bw, "height": bh}
            items.append(
                {
                    "child_hwnd": chw,
                    "control_id": ctrl_id,
                    "automation_id": str(ctrl_id) if ctrl_id != 0 else "",
                    "class_name": cls_s,
                    "control_type": _infer_win32_control_type(cls_s, style),
                    "style": style,
                    "text": txt[:160],
                    "visible": bool(u32.IsWindowVisible(wintypes.HWND(chw))),
                    "enabled": bool(u32.IsWindowEnabled(wintypes.HWND(chw))),
                    "bbox": bbox,
                    "window_rel_bounds": dict(bbox),
                    "center": [bx + bw // 2, by + bh // 2],
                }
            )
            return True

        u32.EnumChildWindows(wintypes.HWND(int(parent_hwnd)), WNDENUMPROC(_cb), 0)
    return items


def _run_uia_powershell_op(
    hwnd: int,
    op: str,
    control_name: str = "",
    automation_id: str = "",
    control_type: str = "",
    value: str = "",
    max_elements: int = 60,
) -> Dict[str, Any]:
    """Execute UTF-8 safe .NET `UIAutomationClient` query/action via UTF-16LE `-EncodedCommand` (`CREATE_NO_WINDOW`)."""
    pwsh = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not pwsh:
        return {"ok": False, "error": "powershell.exe not found for UIAutomationClient bridge."}

    payload_json = json.dumps(
        {
            "hwnd": int(hwnd),
            "op": op,
            "control_name": control_name or "",
            "automation_id": automation_id or "",
            "control_type": control_type or "",
            "value": value or "",
            "max_elements": max(5, min(200, int(max_elements or 60))),
        },
        ensure_ascii=False,
    )
    payload_b64 = base64.b64encode(payload_json.encode("utf-8")).decode("ascii")

    ps_script = f"""
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$reqJson = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{payload_b64}'))
$req = $reqJson | ConvertFrom-Json
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$root = [System.Windows.Automation.AutomationElement]::FromHandle([IntPtr][int64]$req.hwnd)
if ($null -eq $root) {{
    @{{ ok = $false; error = "AutomationElement.FromHandle returned null" }} | ConvertTo-Json -Compress
    exit 0
}}
$rootRect = $root.Current.BoundingRectangle
$rx0 = if ([double]::IsInfinity($rootRect.Left)) {{ 0.0 }} else {{ [double]$rootRect.Left }}
$ry0 = if ([double]::IsInfinity($rootRect.Top)) {{ 0.0 }} else {{ [double]$rootRect.Top }}
$rw0 = if ([double]::IsInfinity($rootRect.Width)) {{ 0.0 }} else {{ [double]$rootRect.Width }}
$rh0 = if ([double]::IsInfinity($rootRect.Height)) {{ 0.0 }} else {{ [double]$rootRect.Height }}

if ($req.op -eq 'tree') {{
    $all = $root.FindAll([System.Windows.Automation.TreeScope]::Subtree, [System.Windows.Automation.Condition]::TrueCondition)
    $cap = [Math]::Min([int]$req.max_elements, $all.Count)
    $items = @()
    for ($i = 0; $i -lt $cap; $i++) {{
        $el = $all[$i]
        try {{
            $c = $el.Current
            $r = $c.BoundingRectangle
            $pats = @()
            foreach ($p in $el.GetSupportedPatterns()) {{
                $pats += ($p.ProgrammaticName -replace 'PatternIdentifiers\\.Pattern$','')
            }}
            $valStr = ''
            $vpObj = $null
            if ($el.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$vpObj)) {{
                try {{ $valStr = [string]$vpObj.Current.Value }} catch {{}}
            }}
            $items += @{{
                index = $i
                name = [string]$c.Name
                automation_id = [string]$c.AutomationId
                control_type = ([string]$c.ControlType.ProgrammaticName -replace '^ControlType\\.','')
                class_name = [string]$c.ClassName
                native_hwnd = [int64]$c.NativeWindowHandle
                enabled = [bool]$c.IsEnabled
                value = if ($valStr.Length -gt 120) {{ $valStr.Substring(0, 120) }} else {{ $valStr }}
                patterns = $pats
                uia_raw_rel_bounds = @{{
                    x = if ([double]::IsInfinity($r.Left)) {{ 0.0 }} else {{ [double]$r.Left - $rx0 }}
                    y = if ([double]::IsInfinity($r.Top)) {{ 0.0 }} else {{ [double]$r.Top - $ry0 }}
                    width = if ([double]::IsInfinity($r.Width)) {{ 0.0 }} else {{ [double]$r.Width }}
                    height = if ([double]::IsInfinity($r.Height)) {{ 0.0 }} else {{ [double]$r.Height }}
                }}
            }}
        }} catch {{}}
    }}
    @{{
        ok = $true
        total_found = $all.Count
        returned = $items.Count
        uia_root_rect = @{{ left = $rx0; top = $ry0; width = $rw0; height = $rh0 }}
        elements = $items
    }} | ConvertTo-Json -Depth 6 -Compress
    exit 0
}}

$all = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
$wantAid = ([string]$req.automation_id).Trim()
$wantName = ([string]$req.control_name).Trim()
$wantType = ([string]$req.control_type).Trim().ToLowerInvariant()
$bestEl = $null
$bestScore = 999999

for ($i = 0; $i -lt $all.Count; $i++) {{
    $el = $all[$i]
    try {{
        $c = $el.Current
        $ct = ([string]$c.ControlType.ProgrammaticName -replace '^ControlType\\.','')
        $ctLow = $ct.ToLowerInvariant()
        if ($wantType -ne '' -and $ctLow -ne $wantType) {{ continue }}

        $matched = $false
        $exactBonus = 10
        if ($wantAid -ne '' -and $c.AutomationId -eq $wantAid) {{
            $matched = $true
            $exactBonus = 0
        }}
        if (-not $matched -and $wantName -ne '') {{
            $nm = [string]$c.Name
            $nmClean = ($nm -replace '\\(&[A-Za-z0-9]\\)','' -replace '&','' -replace '\\.\\.\\.','').Trim()
            if ($nm -eq $wantName -or $nmClean -eq $wantName) {{
                $matched = $true
                $exactBonus = 0
            }} elseif ($nm -like "*$wantName*") {{
                $matched = $true
                $exactBonus = 5
            }}
        }}
        if (-not $matched -and $wantAid -eq '' -and $wantName -eq '' -and $req.op -eq 'set_value') {{
            $vpTmp = $null
            if ($el.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$vpTmp)) {{
                $matched = $true
                $exactBonus = 8
            }}
        }}
        if (-not $matched) {{ continue }}

        $typeRank = 20
        if ($req.op -eq 'invoke') {{
            if (@('button','splitbutton','menuitem','checkbox','radiobutton','hyperlink') -contains $ctLow) {{ $typeRank = 0 }}
            elseif (@('combobox','tabitem','custom') -contains $ctLow) {{ $typeRank = 10 }}
            elseif (@('listitem','dataitem','treeitem','text') -contains $ctLow) {{ $typeRank = 30 }}
        }} elseif ($req.op -eq 'set_value') {{
            if (@('edit','document','combobox') -contains $ctLow) {{ $typeRank = 0 }}
        }}
        $score = $typeRank * 100 + $exactBonus * 10 + [Math]::Min(9, $i)
        if ($score -lt $bestScore) {{
            $bestScore = $score
            $bestEl = $el
        }}
    }} catch {{}}
}}

if ($null -eq $bestEl) {{
    @{{ ok = $false; error = "No matching UIA descendant found for automation_id='$wantAid' control_name='$wantName' control_type='$wantType'" }} | ConvertTo-Json -Compress
    exit 0
}}

$bc = $bestEl.Current
$bct = ([string]$bc.ControlType.ProgrammaticName -replace '^ControlType\\.','')
if ($req.op -eq 'invoke') {{
    $ip = $null
    if ($bestEl.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$ip)) {{
        $ip.Invoke()
        @{{ ok = $true; pattern = 'InvokePattern'; matched_name = [string]$bc.Name; matched_aid = [string]$bc.AutomationId; matched_control_type = $bct; native_hwnd = [int64]$bc.NativeWindowHandle }} | ConvertTo-Json -Compress
        exit 0
    }}
    $tp = $null
    if ($bestEl.TryGetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern, [ref]$tp)) {{
        $tp.Toggle()
        @{{ ok = $true; pattern = 'TogglePattern'; matched_name = [string]$bc.Name; matched_aid = [string]$bc.AutomationId; matched_control_type = $bct; native_hwnd = [int64]$bc.NativeWindowHandle }} | ConvertTo-Json -Compress
        exit 0
    }}
    $eip = $null
    if ($bestEl.TryGetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern, [ref]$eip)) {{
        $eip.Expand()
        @{{ ok = $true; pattern = 'ExpandCollapsePattern'; matched_name = [string]$bc.Name; matched_aid = [string]$bc.AutomationId; matched_control_type = $bct; native_hwnd = [int64]$bc.NativeWindowHandle }} | ConvertTo-Json -Compress
        exit 0
    }}
    $sip = $null
    if ($bestEl.TryGetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern, [ref]$sip)) {{
        $sip.Select()
        @{{ ok = $true; pattern = 'SelectionItemPattern'; matched_name = [string]$bc.Name; matched_aid = [string]$bc.AutomationId; matched_control_type = $bct; native_hwnd = [int64]$bc.NativeWindowHandle }} | ConvertTo-Json -Compress
        exit 0
    }}
    @{{ ok = $false; matched_name = [string]$bc.Name; matched_control_type = $bct; native_hwnd = [int64]$bc.NativeWindowHandle; error = "Matched UIA element ($bct) does not expose Invoke/Toggle/SelectionItem pattern" }} | ConvertTo-Json -Compress
    exit 0
}}
if ($req.op -eq 'set_value') {{
    $vp = $null
    if ($bestEl.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$vp)) {{
        $vp.SetValue([string]$req.value)
        @{{ ok = $true; pattern = 'ValuePattern'; matched_name = [string]$bc.Name; matched_aid = [string]$bc.AutomationId; matched_control_type = $bct; native_hwnd = [int64]$bc.NativeWindowHandle }} | ConvertTo-Json -Compress
        exit 0
    }}
    @{{ ok = $false; matched_name = [string]$bc.Name; matched_control_type = $bct; native_hwnd = [int64]$bc.NativeWindowHandle; error = "Matched UIA element ($bct) does not expose ValuePattern" }} | ConvertTo-Json -Compress
    exit 0
}}
"""
    encoded_cmd = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
    try:
        r = subprocess.run(
            [pwsh, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_cmd],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10.0,
            creationflags=win32_no_window_flags(),
        )
        out_s = (r.stdout or "").strip()
        if out_s:
            for ln in reversed(out_s.splitlines()):
                if ln.strip().startswith("{"):
                    return json.loads(ln.strip())
        return {"ok": False, "error": (r.stderr or out_s or f"UIA PowerShell exited with {r.returncode}")[:300]}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def extract_uia_tree(hwnd: int, max_elements: int = 60) -> Dict[str, Any]:
    """Extract DPI-calibrated UIA + Win32 child + menu + owned dialog tree in `hwnd`'s capture coordinate space."""
    with _align_thread_dpi_to_window(int(hwnd)):
        geom = _get_window_geometry_win32(int(hwnd))
        cap_w, cap_h = geom["window_size"]
        win32_children = _enum_win32_child_controls(int(hwnd), max_items=max(10, min(150, int(max_elements or 60))))
        menu_items = _enum_win32_menu_bar(int(hwnd))
        owned_dialogs = _enum_owned_dialogs_win32(int(hwnd))
    uia_res = _run_uia_powershell_op(int(hwnd), op="tree", max_elements=int(max_elements or 60))

    uia_root = uia_res.get("uia_root_rect") or {}
    uia_w = float(uia_root.get("width") or 0.0)
    uia_h = float(uia_root.get("height") or 0.0)
    if cap_w > 0 and uia_w > 0 and not geom["minimized"]:
        scale_x = float(cap_w) / uia_w
        scale_y = (float(cap_h) / uia_h) if (cap_h > 0 and uia_h > 0) else scale_x
    else:
        scale_x = 1.0
        scale_y = 1.0

    w32_by_hwnd = {int(c["child_hwnd"]): c for c in win32_children}
    calibrated_elements: List[Dict[str, Any]] = []
    for el in uia_res.get("elements", []):
        raw_b = el.get("uia_raw_rel_bounds") or el.get("window_rel_bounds") or {}
        bx = int(round(float(raw_b.get("x") or 0.0) * scale_x))
        by = int(round(float(raw_b.get("y") or 0.0) * scale_y))
        bw = max(0, int(round(float(raw_b.get("width") or 0.0) * scale_x)))
        bh = max(0, int(round(float(raw_b.get("height") or 0.0) * scale_y)))
        bbox = {"x": bx, "y": by, "width": bw, "height": bh}
        el_out = {k: v for k, v in el.items() if k != "uia_raw_rel_bounds"}
        nat_h = int(el_out.get("native_hwnd") or 0)
        if nat_h in w32_by_hwnd:
            w32_info = w32_by_hwnd[nat_h]
            if str(el_out.get("control_type") or "") in ("Pane", "Custom", "") and w32_info.get("control_type"):
                el_out["control_type"] = w32_info["control_type"]
            if not el_out.get("automation_id") and w32_info.get("automation_id"):
                el_out["automation_id"] = w32_info["automation_id"]
        el_out["bbox"] = bbox
        el_out["window_rel_bounds"] = dict(bbox)
        el_out["center"] = [bx + bw // 2, by + bh // 2]
        calibrated_elements.append(el_out)

    existing_menu_names = {
        _clean_menu_label(str(e.get("name") or ""))
        for e in calibrated_elements
        if str(e.get("control_type") or "").lower() in ("menuitem", "menubar")
    }
    for mi in menu_items:
        if mi["clean_name"] not in existing_menu_names or mi.get("depth", 0) > 0:
            calibrated_elements.append(mi)

    out_tree: Dict[str, Any] = {
        "ok": True,
        "hwnd": int(hwnd),
        "window_minimized": geom["minimized"],
        "coordinate_space": "window_capture_px",
        "capture_size": {"width": cap_w, "height": cap_h},
        "client_offset": {"x": geom["client_offset"][0], "y": geom["client_offset"][1]},
        "dpi": geom["dpi"],
        "dpi_scale": geom["dpi_scale"],
        "window_dpi_aware": geom["window_dpi_aware"],
        "uia_ok": bool(uia_res.get("ok")),
        "uia_elements": calibrated_elements,
        "menu_items": menu_items,
        "win32_children": win32_children,
        "owned_dialogs": owned_dialogs,
    }
    if geom["minimized"]:
        out_tree["warning"] = f"Window HWND {hwnd} is minimized (`IsIconic=True`); restore before coordinate clicking or capture."
    if not uia_res.get("ok") and uia_res.get("error"):
        out_tree["uia_note"] = uia_res["error"]
    return out_tree


def _trigger_win32_control_non_activating(top_hwnd: int, child_hwnd: int) -> Dict[str, Any]:
    """Trigger Win32 Button / CheckBox / RadioButton via `WM_COMMAND(BN_CLICKED)` without stealing foreground focus."""
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    u32.GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
    u32.GetWindowLongW.restype = wintypes.LONG
    u32.GetDlgCtrlID.argtypes = [wintypes.HWND]
    u32.GetDlgCtrlID.restype = ctypes.c_int
    u32.GetParent.argtypes = [wintypes.HWND]
    u32.GetParent.restype = wintypes.HWND
    u32.IsWindow.argtypes = [wintypes.HWND]
    u32.IsWindow.restype = wintypes.BOOL
    u32.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    u32.GetClientRect.restype = wintypes.BOOL

    chw = wintypes.HWND(int(child_hwnd))
    cls_name, _ = _read_hwnd_class_and_pid(int(child_hwnd))
    cls_low = cls_name.lower()
    style = int(u32.GetWindowLongW(chw, -16) or 0)
    ctrl_id = int(u32.GetDlgCtrlID(chw) or 0)
    parent_h = int(u32.GetParent(chw) or top_hwnd)

    if cls_low == "button" and int(child_hwnd) != int(top_hwnd):
        bs = style & 0x0F
        extra_state: Dict[str, Any] = {}
        if bs in (2, 3, 5, 6):  # CheckBox / AutoCheckBox / 3State
            _, cur_chk = _send_int_msg_timeout_win32(child_hwnd, 0x00F0, 0, 0, timeout_ms=80)
            next_chk = 0 if cur_chk == 1 else 1
            _send_int_msg_timeout_win32(child_hwnd, 0x00F1, next_chk, 0, timeout_ms=80)
            extra_state["checked"] = bool(next_chk == 1)
        elif bs in (4, 9):  # RadioButton
            _send_int_msg_timeout_win32(child_hwnd, 0x00F1, 1, 0, timeout_ms=80)
            extra_state["checked"] = True

        top_cls, _ = _read_hwnd_class_and_pid(int(top_hwnd))
        if top_cls == "#32770" and bs in (0, 1, 12, 13):
            _post_message_64safe(int(top_hwnd), 0x0111, (0 << 16) | (ctrl_id & 0xFFFF), int(child_hwnd))
            delivery_m = "PostMessageW(WM_COMMAND:#32770)"
            time.sleep(0.06)
            if ctrl_id in (1, 2) and u32.IsWindow(wintypes.HWND(int(top_hwnd))):
                _post_message_64safe(int(child_hwnd), 0x00F5, 0, 0)  # BM_CLICK
                delivery_m = "PostMessageW(BM_CLICK:#32770)"
                time.sleep(0.08)
            if ctrl_id in (1, 2) and u32.IsWindow(wintypes.HWND(int(top_hwnd))):
                uia_d = _run_uia_powershell_op(int(top_hwnd), op="invoke", automation_id=str(ctrl_id))
                if uia_d.get("ok"):
                    delivery_m = f"UIA({uia_d.get('pattern', 'InvokePattern')}:#32770)"
            return {
                "ok": True,
                "target_hwnd": int(child_hwnd),
                "target_class": cls_name,
                "control_id": ctrl_id,
                "delivery": delivery_m,
                **extra_state,
            }

        wparam = (0 << 16) | (ctrl_id & 0xFFFF)
        _post_message_64safe(parent_h, 0x0111, wparam, int(child_hwnd))
        return {
            "ok": True,
            "target_hwnd": int(child_hwnd),
            "target_class": cls_name,
            "control_id": ctrl_id,
            "delivery": "PostMessageW(WM_COMMAND:BN_CLICKED)",
            **extra_state,
        }

    rc = wintypes.RECT()
    with _align_thread_dpi_to_window(int(top_hwnd)):
        u32.GetClientRect(chw, ctypes.byref(rc))
    cx = max(1, int(rc.right - rc.left) // 2)
    cy = max(1, int(rc.bottom - rc.top) // 2)
    lparam = ((cy & 0xFFFF) << 16) | (cx & 0xFFFF)
    _post_message_64safe(int(child_hwnd), 0x0200, 0, lparam)
    time.sleep(0.01)
    _post_message_64safe(int(child_hwnd), 0x0201, 0x0001, lparam)
    time.sleep(0.025)
    _post_message_64safe(int(child_hwnd), 0x0202, 0, lparam)
    return {
        "ok": True,
        "target_hwnd": int(child_hwnd),
        "target_class": cls_name,
        "control_id": ctrl_id,
        "delivery": "PostMessageW(WM_LBUTTONDOWN/UP)",
    }


def _resolve_cua_coordinates(
    parent_hwnd: int,
    raw_x: int,
    raw_y: int,
    *,
    coord_space: str = "auto",
    geom: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Translate `(raw_x, raw_y)` from `image` / `client` / `window` / `auto` space into real window & client coords."""
    eff_geom = geom if geom is not None else _get_window_geometry_win32(int(parent_hwnd))
    win_w, win_h = eff_geom["window_size"]
    cli_off_x, cli_off_y = eff_geom["client_offset"]
    mode = (coord_space or "auto").strip().lower() or "auto"

    if mode == "client":
        parent_cx = int(raw_x)
        parent_cy = int(raw_y)
        wx = parent_cx + int(cli_off_x)
        wy = parent_cy + int(cli_off_y)
        return {
            "wx": wx,
            "wy": wy,
            "parent_client_xy": [parent_cx, parent_cy],
            "input_xy": [int(raw_x), int(raw_y)],
            "coord_space_used": "client",
            "scale_factor": 1.0,
            "scale_x": 1.0,
            "scale_y": 1.0,
        }

    if mode == "window":
        wx = int(raw_x)
        wy = int(raw_y)
        return {
            "wx": wx,
            "wy": wy,
            "parent_client_xy": [wx - int(cli_off_x), wy - int(cli_off_y)],
            "input_xy": [int(raw_x), int(raw_y)],
            "coord_space_used": "window",
            "scale_factor": 1.0,
            "scale_x": 1.0,
            "scale_y": 1.0,
        }

    cached = get_cached_window_capture_scale(int(parent_hwnd))
    sx = 1.0
    sy = 1.0
    sf = 1.0
    img_w, img_h = win_w, win_h
    has_valid_scale = False
    if cached is not None:
        cap_w, cap_h = cached["captured_size"]
        if abs(cap_w - win_w) <= 4 and abs(cap_h - win_h) <= 4:
            sx = float(cached["scale_x"] or 1.0)
            sy = float(cached["scale_y"] or 1.0)
            sf = float(cached["scale_factor"] or 1.0)
            img_w, img_h = cached["image_size"]
            has_valid_scale = sf < 0.9999

    if not has_valid_scale and mode == "image" and max(win_w, win_h) > MAX_CAPTURE_LONG_EDGE:
        sf = float(MAX_CAPTURE_LONG_EDGE) / float(max(win_w, win_h))
        img_w = max(1, int(round(win_w * sf)))
        img_h = max(1, int(round(win_h * sf)))
        sx = float(img_w) / float(max(1, win_w))
        sy = float(img_h) / float(max(1, win_h))
        sf = round(sx, 6)
        has_valid_scale = True

    if mode == "image" or (has_valid_scale and 0 <= int(raw_x) <= img_w and 0 <= int(raw_y) <= img_h):
        wx = int(round(float(raw_x) / sx)) if sx > 0 else int(raw_x)
        wy = int(round(float(raw_y) / sy)) if sy > 0 else int(raw_y)
        if win_w > 0 and wx == win_w + 1:
            wx = win_w
        if win_h > 0 and wy == win_h + 1:
            wy = win_h
        return {
            "wx": wx,
            "wy": wy,
            "parent_client_xy": [wx - int(cli_off_x), wy - int(cli_off_y)],
            "input_xy": [int(raw_x), int(raw_y)],
            "coord_space_used": "image",
            "scale_factor": round(sf, 6),
            "scale_x": round(sx, 6),
            "scale_y": round(sy, 6),
        }

    wx = int(raw_x)
    wy = int(raw_y)
    return {
        "wx": wx,
        "wy": wy,
        "parent_client_xy": [wx - int(cli_off_x), wy - int(cli_off_y)],
        "input_xy": [int(raw_x), int(raw_y)],
        "coord_space_used": "window",
        "scale_factor": 1.0,
        "scale_x": 1.0,
        "scale_y": 1.0,
    }


def _hit_test_child_hwnd_win32(
    parent_hwnd: int,
    wx: int,
    wy: int,
    *,
    prefer_input: bool = False,
) -> Dict[str, Any]:
    """Hit-test deepest visible enabled child HWND at window-relative `(wx, wy)` via `ChildWindowFromPointEx` + bbox."""
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    u32.IsWindowVisible.argtypes = [wintypes.HWND]
    u32.IsWindowVisible.restype = wintypes.BOOL
    u32.IsWindowEnabled.argtypes = [wintypes.HWND]
    u32.IsWindowEnabled.restype = wintypes.BOOL
    u32.GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
    u32.GetWindowLongW.restype = wintypes.LONG
    u32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    u32.GetWindowRect.restype = wintypes.BOOL
    u32.ScreenToClient.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.POINT)]
    u32.ScreenToClient.restype = wintypes.BOOL
    u32.ChildWindowFromPointEx.argtypes = [wintypes.HWND, wintypes.POINT, wintypes.UINT]
    u32.ChildWindowFromPointEx.restype = wintypes.HWND

    h_parent = wintypes.HWND(int(parent_hwnd))
    with _align_thread_dpi_to_window(int(parent_hwnd)):
        geom = _get_window_geometry_win32(parent_hwnd)
        wl, wt, _wr, _wb = geom["window_rect"]
        p_cli_x, p_cli_y = geom["client_offset"]
        screen_x = wl + int(wx)
        screen_y = wt + int(wy)

        def _window_to_local_client_xy(h_wnd: int) -> Tuple[int, int]:
            if int(h_wnd) == int(parent_hwnd):
                return int(wx) - int(p_cli_x), int(wy) - int(p_cli_y)
            rc_w = wintypes.RECT()
            rc_c = wintypes.RECT()
            if u32.GetWindowRect(wintypes.HWND(h_wnd), ctypes.byref(rc_w)):
                off_x, off_y = 0, 0
                if u32.GetClientRect(wintypes.HWND(h_wnd), ctypes.byref(rc_c)):
                    ww = max(0, int(rc_w.right - rc_w.left))
                    wh = max(0, int(rc_w.bottom - rc_w.top))
                    cw = max(0, int(rc_c.right - rc_c.left))
                    ch = max(0, int(rc_c.bottom - rc_c.top))
                    off_x = max(0, (ww - cw) // 2)
                    off_y = max(0, wh - ch - off_x)
                return screen_x - int(rc_w.left) - off_x, screen_y - int(rc_w.top) - off_y
            pt_fb = wintypes.POINT(screen_x, screen_y)
            u32.ScreenToClient(wintypes.HWND(h_wnd), ctypes.byref(pt_fb))
            return int(pt_fb.x), int(pt_fb.y)

        u32.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
        u32.GetClientRect.restype = wintypes.BOOL

        # 1. Recursive ChildWindowFromPointEx (CWP_SKIPINVISIBLE | CWP_SKIPDISABLED | CWP_SKIPTRANSPARENT = 0x0007)
        cwp_hit = int(parent_hwnd)
        cwp_area = 10**12
        cur_h = int(parent_hwnd)
        for _ in range(8):
            lx_cur, ly_cur = _window_to_local_client_xy(cur_h)
            pt_cur = wintypes.POINT(lx_cur, ly_cur)
            nxt = int(u32.ChildWindowFromPointEx(wintypes.HWND(cur_h), pt_cur, 0x0007) or 0)
            if nxt <= 0 or nxt == cur_h:
                break
            cls_n, _ = _read_hwnd_class_and_pid(nxt)
            sty_n = int(u32.GetWindowLongW(wintypes.HWND(nxt), -16) or 0)
            if cls_n.lower() == "button" and (sty_n & 0x0F) == 7:
                break
            rc_n = wintypes.RECT()
            if u32.GetWindowRect(wintypes.HWND(nxt), ctypes.byref(rc_n)):
                cwp_area = max(1, int(rc_n.right - rc_n.left) * int(rc_n.bottom - rc_n.top))
            cwp_hit = nxt
            cur_h = nxt

        # 2. EnumChildWindows bounding-box refinement
        bbox_hit = int(parent_hwnd)
        best_area = 10**12
        input_hit = 0
        best_input_area = 10**12
        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

        def _cb(ch_hwnd: int, _lp: int) -> bool:
            nonlocal bbox_hit, best_area, input_hit, best_input_area
            chw = int(ch_hwnd or 0)
            if chw <= 0 or not u32.IsWindowVisible(wintypes.HWND(chw)) or not u32.IsWindowEnabled(wintypes.HWND(chw)):
                return True
            cls_i, _ = _read_hwnd_class_and_pid(chw)
            cls_low = cls_i.lower()
            style_i = int(u32.GetWindowLongW(wintypes.HWND(chw), -16) or 0)
            if cls_low == "button" and (style_i & 0x0F) == 7:
                return True
            rc = wintypes.RECT()
            if u32.GetWindowRect(wintypes.HWND(chw), ctypes.byref(rc)):
                if rc.left <= screen_x <= rc.right and rc.top <= screen_y <= rc.bottom:
                    area = max(1, int(rc.right - rc.left) * int(rc.bottom - rc.top))
                    if area <= best_area:
                        best_area = area
                        bbox_hit = chw
                    if ("edit" in cls_low or "richedit" in cls_low or "combobox" in cls_low) and area <= best_input_area:
                        best_input_area = area
                        input_hit = chw
            return True

        u32.EnumChildWindows(h_parent, WNDENUMPROC(_cb), 0)

        if prefer_input and input_hit > 0:
            target_hwnd = input_hit
        elif cwp_hit != int(parent_hwnd):
            target_hwnd = bbox_hit if (bbox_hit != int(parent_hwnd) and best_area < cwp_area) else cwp_hit
        else:
            target_hwnd = bbox_hit

        cx, cy = _window_to_local_client_xy(target_hwnd)
        cls_name, _ = _read_hwnd_class_and_pid(target_hwnd)

    return {
        "target_hwnd": int(target_hwnd),
        "target_class": cls_name,
        "screen_xy": [screen_x, screen_y],
        "client_xy": [cx, cy],
        "geom": geom,
    }


def _postmessage_click_offscreen(
    parent_hwnd: int,
    raw_x: int,
    raw_y: int,
    prefix: str = "pc",
    *,
    button: str = "left",
    coord_space: str = "auto",
) -> Dict[str, Any]:
    """Deliver zero-focus background `click` / `double_click` / `right_click` with capture scale unscaling."""
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    u32.IsIconic.argtypes = [wintypes.HWND]
    u32.IsIconic.restype = wintypes.BOOL

    h_parent = wintypes.HWND(int(parent_hwnd))
    with _align_thread_dpi_to_window(int(parent_hwnd)):
        if bool(u32.IsIconic(h_parent)):
            return {
                "ok": False,
                "hwnd": int(parent_hwnd),
                "window_minimized": True,
                "error": f"Window HWND {parent_hwnd} is minimized (`IsIconic=True`); restore before coordinate clicking.",
                "hint": f"Call {prefix}_cua_window(action='restore', hwnd={parent_hwnd}) first.",
            }

        geom = _get_window_geometry_win32(parent_hwnd)
        win_w, win_h = geom["window_size"]
        cli_off_x, cli_off_y = geom["client_offset"]
        coord_info = _resolve_cua_coordinates(parent_hwnd, raw_x, raw_y, coord_space=coord_space, geom=geom)
        wx = int(coord_info["wx"])
        wy = int(coord_info["wy"])

        if wx < 0 or wy < 0 or (win_w > 0 and wx > win_w) or (win_h > 0 and wy > win_h):
            return {
                "ok": False,
                "hwnd": int(parent_hwnd),
                "input_xy": coord_info["input_xy"],
                "window_xy": [wx, wy],
                "coord_space_used": coord_info["coord_space_used"],
                "scale_factor": coord_info["scale_factor"],
                "capture_size": [win_w, win_h],
                "error": f"Coordinates ({wx}, {wy}) are outside window capture bounds [0..{win_w}, 0..{win_h}].",
                "hint": f"Inspect control `center` via {prefix}_cua_window(action='uia_tree', hwnd={parent_hwnd}) or capture with grid_step=50.",
            }

        if button == "left":
            menu_items = _enum_win32_menu_bar(parent_hwnd)
            for mi in menu_items:
                if mi.get("depth") == 0:
                    mb = mi["bbox"]
                    if mb["width"] > 0 and mb["height"] > 0:
                        if mb["x"] <= wx <= (mb["x"] + mb["width"]) and mb["y"] <= wy <= (mb["y"] + mb["height"]):
                            cmd_id = int(mi.get("menu_command_id") or 0)
                            if cmd_id > 0:
                                _post_message_64safe(int(parent_hwnd), 0x0111, cmd_id, 0)
                                return {
                                    "ok": True,
                                    "parent_hwnd": int(parent_hwnd),
                                    "target_hwnd": int(parent_hwnd),
                                    "target_class": "Win32Menu",
                                    "menu_item": mi["name"],
                                    "menu_command_id": cmd_id,
                                    "input_xy": coord_info["input_xy"],
                                    "window_xy": [wx, wy],
                                    "parent_client_xy": coord_info["parent_client_xy"],
                                    "coord_space_used": coord_info["coord_space_used"],
                                    "scale_factor": coord_info["scale_factor"],
                                    "dpi": geom["dpi"],
                                    "dpi_scale": geom["dpi_scale"],
                                    "window_dpi_aware": geom["window_dpi_aware"],
                                    "delivery": "PostMessageW(WM_COMMAND:MenuItem)",
                                }
                            sub_children = [
                                {
                                    "name": sm["name"],
                                    "clean_name": sm["clean_name"],
                                    "automation_id": sm["automation_id"],
                                    "menu_command_id": sm["menu_command_id"],
                                }
                                for sm in menu_items
                                if sm.get("depth", 0) > 0 and sm["menu_path"].startswith(mi["clean_name"] + " > ")
                            ]
                            return {
                                "ok": True,
                                "parent_hwnd": int(parent_hwnd),
                                "target_hwnd": int(parent_hwnd),
                                "target_class": "Win32MenuBar",
                                "hit_menu_bar": True,
                                "menu_header": mi["name"],
                                "submenu_items": sub_children,
                                "input_xy": coord_info["input_xy"],
                                "window_xy": [wx, wy],
                                "parent_client_xy": coord_info["parent_client_xy"],
                                "coord_space_used": coord_info["coord_space_used"],
                                "scale_factor": coord_info["scale_factor"],
                                "dpi": geom["dpi"],
                                "dpi_scale": geom["dpi_scale"],
                                "window_dpi_aware": geom["window_dpi_aware"],
                                "delivery": "Win32MenuInspect(non_blocking)",
                            }

        hit = _hit_test_child_hwnd_win32(parent_hwnd, wx, wy, prefer_input=False)
        target_hwnd = int(hit["target_hwnd"])
        cls_name = str(hit["target_class"])
        cx, cy = hit["client_xy"]

        if target_hwnd == int(parent_hwnd) and wy < cli_off_y:
            return {
                "ok": False,
                "hwnd": int(parent_hwnd),
                "non_client_area": True,
                "input_xy": coord_info["input_xy"],
                "window_xy": [wx, wy],
                "client_offset": [cli_off_x, cli_off_y],
                "error": f"Coordinates ({wx}, {wy}) fall in the non-client title/caption bar (client area starts at y={cli_off_y}).",
                "hint": f"Use y >= {cli_off_y} for client controls, or action='close_window' / action='restore' for window frame commands.",
            }

    common_meta = {
        "parent_hwnd": int(parent_hwnd),
        "input_xy": coord_info["input_xy"],
        "window_xy": [wx, wy],
        "parent_client_xy": coord_info["parent_client_xy"],
        "coord_space_used": coord_info["coord_space_used"],
        "scale_factor": coord_info["scale_factor"],
        "dpi": geom["dpi"],
        "dpi_scale": geom["dpi_scale"],
        "window_dpi_aware": geom["window_dpi_aware"],
    }

    if button == "left" and cls_name.lower() == "button" and target_hwnd != int(parent_hwnd):
        trig = _trigger_win32_control_non_activating(parent_hwnd, target_hwnd)
        return {
            **trig,
            **common_meta,
            "client_xy": [cx, cy],
        }

    cx_clamped = max(0, cx)
    cy_clamped = max(0, cy)
    lparam = ((cy_clamped & 0xFFFF) << 16) | (cx_clamped & 0xFFFF)
    with _align_thread_dpi_to_window(int(target_hwnd)):
        _post_message_64safe(target_hwnd, 0x0200, 0, lparam)  # WM_MOUSEMOVE
        time.sleep(0.01)

        if button == "right":
            _post_message_64safe(target_hwnd, 0x0204, 0x0002, lparam)  # WM_RBUTTONDOWN (MK_RBUTTON=2)
            time.sleep(0.025)
            _post_message_64safe(target_hwnd, 0x0205, 0, lparam)  # WM_RBUTTONUP
            delivery_str = "PostMessageW(WM_RBUTTONDOWN/UP)"
        elif button == "double":
            _post_message_64safe(target_hwnd, 0x0201, 0x0001, lparam)  # WM_LBUTTONDOWN
            time.sleep(0.015)
            _post_message_64safe(target_hwnd, 0x0202, 0, lparam)  # WM_LBUTTONUP
            time.sleep(0.015)
            _post_message_64safe(target_hwnd, 0x0203, 0x0001, lparam)  # WM_LBUTTONDBLCLK
            time.sleep(0.02)
            _post_message_64safe(target_hwnd, 0x0202, 0, lparam)  # WM_LBUTTONUP
            delivery_str = "PostMessageW(WM_LBUTTONDBLCLK)"
        else:
            _post_message_64safe(target_hwnd, 0x0201, 0x0001, lparam)  # WM_LBUTTONDOWN
            time.sleep(0.03)
            _post_message_64safe(target_hwnd, 0x0202, 0, lparam)  # WM_LBUTTONUP
            delivery_str = "PostMessageW(WM_LBUTTONDOWN/UP)"

    return {
        "ok": True,
        "target_hwnd": int(target_hwnd),
        "target_class": cls_name,
        **common_meta,
        "client_xy": [cx_clamped, cy_clamped],
        "delivery": delivery_str,
    }


def _scroll_window_offscreen(
    parent_hwnd: int,
    *,
    raw_x: Optional[int] = None,
    raw_y: Optional[int] = None,
    coord_space: str = "auto",
    direction: str = "down",
    wheel_delta: int = 0,
    clicks: int = 3,
    prefix: str = "pc",
) -> Dict[str, Any]:
    """Deliver background `WM_MOUSEWHEEL` / `WM_MOUSEHWHEEL` message without stealing focus."""
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    u32.IsIconic.argtypes = [wintypes.HWND]
    u32.IsIconic.restype = wintypes.BOOL
    if bool(u32.IsIconic(wintypes.HWND(int(parent_hwnd)))):
        return {
            "ok": False,
            "hwnd": int(parent_hwnd),
            "window_minimized": True,
            "error": f"Window HWND {parent_hwnd} is minimized (`IsIconic=True`); restore before scrolling.",
            "hint": f"Call {prefix}_cua_window(action='restore', hwnd={parent_hwnd}) first.",
        }

    eff_dir = (direction or "down").strip().lower()
    if eff_dir not in ("down", "up", "left", "right"):
        return {
            "ok": False,
            "hwnd": int(parent_hwnd),
            "error": f"Unsupported scroll direction `{direction}` (expected down, up, left, or right).",
        }

    geom = _get_window_geometry_win32(parent_hwnd)
    cli_w, cli_h = geom["client_size"]
    cli_off_x, cli_off_y = geom["client_offset"]

    if raw_x is not None and raw_y is not None:
        coord_info = _resolve_cua_coordinates(parent_hwnd, raw_x, raw_y, coord_space=coord_space, geom=geom)
        wx, wy = int(coord_info["wx"]), int(coord_info["wy"])
    else:
        wx = int(cli_off_x) + max(1, int(cli_w) // 2)
        wy = int(cli_off_y) + max(1, int(cli_h) // 2)
        coord_info = {
            "wx": wx,
            "wy": wy,
            "parent_client_xy": [wx - int(cli_off_x), wy - int(cli_off_y)],
            "input_xy": [wx, wy],
            "coord_space_used": "window",
            "scale_factor": 1.0,
        }

    hit = _hit_test_child_hwnd_win32(parent_hwnd, wx, wy, prefer_input=False)
    target_hwnd = int(hit["target_hwnd"])
    cls_name = str(hit["target_class"])
    screen_x, screen_y = hit["screen_xy"]

    eff_clicks = max(1, min(50, abs(int(clicks or 3))))
    if int(wheel_delta or 0) != 0:
        z_delta = int(wheel_delta)
    else:
        mag = 120 * eff_clicks
        z_delta = -mag if eff_dir in ("down", "left") else mag

    z_clamped = max(-32760, min(32760, z_delta))
    sx16 = max(-32768, min(32767, int(screen_x))) & 0xFFFF
    sy16 = max(-32768, min(32767, int(screen_y))) & 0xFFFF
    lparam_screen = (sy16 << 16) | sx16
    wparam = ((z_clamped & 0xFFFF) << 16) | 0
    msg_id = 0x020E if eff_dir in ("left", "right") else 0x020A  # WM_MOUSEHWHEEL or WM_MOUSEWHEEL

    with _align_thread_dpi_to_window(int(target_hwnd)):
        ok_sm, _ = _send_int_msg_timeout_win32(target_hwnd, msg_id, wparam, lparam_screen, timeout_ms=180)
        if not ok_sm:
            _post_message_64safe(target_hwnd, msg_id, wparam, lparam_screen)

    return {
        "ok": True,
        "parent_hwnd": int(parent_hwnd),
        "target_hwnd": target_hwnd,
        "target_class": cls_name,
        "direction": eff_dir,
        "wheel_delta": z_clamped,
        "window_xy": [wx, wy],
        "parent_client_xy": coord_info["parent_client_xy"],
        "coord_space_used": coord_info["coord_space_used"],
        "scale_factor": coord_info["scale_factor"],
        "delivery": "SendMessageTimeoutW(WM_MOUSEWHEEL)" if msg_id == 0x020A else "SendMessageTimeoutW(WM_MOUSEHWHEEL)",
    }


def _synthesize_key_chord_non_activating(target_hwnd: int, chord_info: Dict[str, Any]) -> Dict[str, Any]:
    """Synthesize background modifier + virtual-key chord (`ctrl+s`, `alt+f4`, `f5`, arrows) without `WM_CHAR` literal typing."""
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    u32.MapVirtualKeyW.argtypes = [wintypes.UINT, wintypes.UINT]
    u32.MapVirtualKeyW.restype = wintypes.UINT
    u32.GetForegroundWindow.argtypes = []
    u32.GetForegroundWindow.restype = wintypes.HWND
    u32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    u32.GetWindowThreadProcessId.restype = wintypes.DWORD
    u32.AttachThreadInput.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.BOOL]
    u32.AttachThreadInput.restype = wintypes.BOOL
    u32.GetKeyboardState.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
    u32.GetKeyboardState.restype = wintypes.BOOL
    u32.SetKeyboardState.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
    u32.SetKeyboardState.restype = wintypes.BOOL
    k32.GetCurrentThreadId.argtypes = []
    k32.GetCurrentThreadId.restype = wintypes.DWORD

    mods: List[Tuple[str, int]] = list(chord_info.get("modifiers") or [])
    main_vk = int(chord_info["vk"]) & 0xFF
    alt_only = any(m_nm == "alt" for m_nm, _ in mods) and not any(m_nm == "ctrl" for m_nm, _ in mods)

    def _mk_lparam(vk_code: int, *, is_up: bool, alt_ctx: bool) -> int:
        scan = int(u32.MapVirtualKeyW(vk_code & 0xFF, 0) or 0) & 0xFF
        lp = 1 | (scan << 16)
        if vk_code in _EXTENDED_VK_SET:
            lp |= 1 << 24
        if alt_ctx:
            lp |= 1 << 29
        if is_up:
            lp |= (1 << 30) | (1 << 31)
        return lp

    cur_tid = int(k32.GetCurrentThreadId() or 0)
    target_tid = int(u32.GetWindowThreadProcessId(wintypes.HWND(int(target_hwnd)), None) or 0)
    fg_h = int(u32.GetForegroundWindow() or 0)
    fg_tid = int(u32.GetWindowThreadProcessId(wintypes.HWND(fg_h), None) or 0) if fg_h > 0 else 0

    attached = False
    state_modified = False
    orig_state = (ctypes.c_ubyte * 256)()
    try:
        if mods and target_tid > 0 and (target_tid == cur_tid or target_tid != fg_tid):
            if target_tid != cur_tid:
                attached = bool(u32.AttachThreadInput(cur_tid, target_tid, True))
            if target_tid == cur_tid or attached:
                if u32.GetKeyboardState(orig_state):
                    mod_state = (ctypes.c_ubyte * 256)(*orig_state)
                    for _m_name, m_vk in mods:
                        mod_state[m_vk & 0xFF] |= 0x80
                        if m_vk == 0x11:
                            mod_state[0xA2] |= 0x80  # VK_LCONTROL
                        elif m_vk == 0x10:
                            mod_state[0xA0] |= 0x80  # VK_LSHIFT
                        elif m_vk == 0x12:
                            mod_state[0xA4] |= 0x80  # VK_LMENU
                    state_modified = bool(u32.SetKeyboardState(mod_state))

        for m_name, m_vk in mods:
            msg_m_dn = 0x0104 if (alt_only and m_name == "alt") else 0x0100
            _post_message_64safe(target_hwnd, msg_m_dn, m_vk, _mk_lparam(m_vk, is_up=False, alt_ctx=(alt_only and m_name == "alt")))

        msg_main_dn = 0x0104 if alt_only else 0x0100
        _post_message_64safe(target_hwnd, msg_main_dn, main_vk, _mk_lparam(main_vk, is_up=False, alt_ctx=alt_only))

        # Ensure target thread processes WM_KEYDOWN while modifier keyboard state is active
        _send_int_msg_timeout_win32(target_hwnd, 0x0000, 0, 0, timeout_ms=60)
        time.sleep(0.015)

        msg_main_up = 0x0105 if alt_only else 0x0101
        _post_message_64safe(target_hwnd, msg_main_up, main_vk, _mk_lparam(main_vk, is_up=True, alt_ctx=alt_only))

        for m_name, m_vk in reversed(mods):
            msg_m_up = 0x0105 if (alt_only and m_name != "alt") else 0x0101
            _post_message_64safe(target_hwnd, msg_m_up, m_vk, _mk_lparam(m_vk, is_up=True, alt_ctx=False))

        _send_int_msg_timeout_win32(target_hwnd, 0x0000, 0, 0, timeout_ms=50)
    finally:
        if state_modified:
            with contextlib.suppress(Exception):
                u32.SetKeyboardState(orig_state)
        if attached:
            with contextlib.suppress(Exception):
                u32.AttachThreadInput(cur_tid, target_tid, False)

    return {
        "ok": True,
        "target_hwnd": int(target_hwnd),
        "vk": main_vk,
        "modifiers": [m[0] for m in mods],
        "chord": chord_info.get("chord", ""),
        "delivery": "PostMessageW(VK_CHORD:WM_KEYDOWN/UP)",
    }


def _set_win32_control_value_64safe(top_hwnd: int, target_hwnd: int, value_str: str) -> Dict[str, Any]:
    """Set value on Win32 Edit / ComboBox with 64-bit pointer safety and zero clipboard touch."""
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    cls_name, _ = _read_hwnd_class_and_pid(target_hwnd)
    cls_low = cls_name.lower()
    ctrl_id = int(u32.GetDlgCtrlID(wintypes.HWND(int(target_hwnd))) or 0)
    parent_h = int(u32.GetParent(wintypes.HWND(int(target_hwnd))) or top_hwnd)

    if "combobox" in cls_low:
        inner_children = _enum_win32_child_controls(target_hwnd, max_items=16)
        inner_edit = next((int(c["child_hwnd"]) for c in inner_children if "edit" in c["class_name"].lower()), 0)
        if inner_edit > 0:
            res_ed = _send_text_win32_64safe(inner_edit, 0x000C, 0, value_str)
            ed_id = int(u32.GetDlgCtrlID(wintypes.HWND(inner_edit)) or ctrl_id)
            ed_parent = int(u32.GetParent(wintypes.HWND(inner_edit)) or target_hwnd)
            _post_message_64safe(ed_parent, 0x0111, (0x0100 << 16) | (ed_id & 0xFFFF), inner_edit)
            _post_message_64safe(ed_parent, 0x0111, (0x0400 << 16) | (ed_id & 0xFFFF), inner_edit)
            _post_message_64safe(ed_parent, 0x0111, (0x0300 << 16) | (ed_id & 0xFFFF), inner_edit)
            _post_message_64safe(parent_h, 0x0111, (5 << 16) | (ctrl_id & 0xFFFF), int(target_hwnd))
            return {
                "ok": bool(res_ed != 0 or value_str == ""),
                "target_hwnd": inner_edit,
                "combo_hwnd": int(target_hwnd),
                "target_class": "Edit(in ComboBox)",
                "delivery": "SendMessageW(WM_SETTEXT, LPCWSTR)",
                "value_length": len(value_str),
            }
        _, cnt = _send_int_msg_timeout_win32(target_hwnd, 0x0146, 0, 0, timeout_ms=80)
        matched_idx = -1
        for idx in range(max(0, min(200, cnt))):
            _, tlen = _send_int_msg_timeout_win32(target_hwnd, 0x0149, idx, 0, timeout_ms=60)
            if 0 <= tlen < 512:
                ibuf = ctypes.create_unicode_buffer(tlen + 4)
                ok_lb, _ = _send_int_msg_timeout_win32(target_hwnd, 0x0148, idx, ctypes.addressof(ibuf), timeout_ms=60)
                if ok_lb:
                    item_s = ibuf.value
                    if item_s == value_str or item_s.strip().lower() == value_str.strip().lower():
                        matched_idx = idx
                        break
        if matched_idx >= 0:
            _send_int_msg_timeout_win32(target_hwnd, 0x014E, matched_idx, 0, timeout_ms=80)
        else:
            sel_rc = _send_text_win32_64safe(target_hwnd, 0x014D, -1, value_str)
            if sel_rc < 0:
                return {
                    "ok": False,
                    "target_hwnd": int(target_hwnd),
                    "target_class": cls_name,
                    "error": f"Value {value_str!r} not found in dropdown-list ComboBox (count={cnt}).",
                }
            matched_idx = sel_rc
        _post_message_64safe(parent_h, 0x0111, (1 << 16) | (ctrl_id & 0xFFFF), int(target_hwnd))
        return {
            "ok": True,
            "target_hwnd": int(target_hwnd),
            "target_class": cls_name,
            "selected_index": matched_idx,
            "delivery": "SendMessageW(CB_SETCURSEL+CBN_SELCHANGE)",
            "value_length": len(value_str),
        }

    rc_set = _send_text_win32_64safe(target_hwnd, 0x000C, 0, value_str)
    if "edit" in cls_low:
        _post_message_64safe(parent_h, 0x0111, (0x0300 << 16) | (ctrl_id & 0xFFFF), int(target_hwnd))
    return {
        "ok": bool(rc_set != 0 or value_str == ""),
        "target_hwnd": int(target_hwnd),
        "target_class": cls_name,
        "delivery": "SendMessageW(WM_SETTEXT, LPCWSTR)",
        "value_length": len(value_str),
    }


# ---------------------------------------------------------------------------
# Unsaved Document & Save-Confirmation Dialog Guard
# ---------------------------------------------------------------------------


def has_unsaved_title_marker(title: str) -> bool:
    """Detect asterisk `*`, bullet `●`, `未保存`, `Unsaved`, or `Modified` markers in a window title."""
    t = (title or "").strip()
    if not t:
        return False
    low = t.lower()
    if any(kw in low for kw in _UNSAVED_TITLE_KEYWORDS):
        return True
    return bool(_UNSAVED_TITLE_STAR_RE.search(t))


def _detect_unsaved_window_state(hwnd: int) -> Optional[Dict[str, Any]]:
    """Inspect window title, owned `#32770`/save confirmation popups, and child `EM_GETMODIFY` flags."""
    title = _read_hwnd_text_64safe(hwnd, max_chars=512)
    if has_unsaved_title_marker(title):
        return {"reason": "unsaved_title_marker", "title": title}

    _, owner_pid = _read_hwnd_class_and_pid(hwnd)
    for dlg in _enum_owned_dialogs_win32(hwnd, owner_pid=owner_pid):
        dlg_hw = int(dlg["hwnd"])
        dlg_title = str(dlg.get("title") or "")
        child_texts = " ".join(c["text"] for c in _enum_win32_child_controls(dlg_hw, max_items=32) if c.get("text"))
        combined = f"{dlg_title} {child_texts}".lower()
        if any(tok in combined for tok in _SAVE_CONFIRM_DIALOG_TOKENS):
            return {
                "reason": "save_confirmation_dialog_active",
                "title": title,
                "save_dialog_hwnd": dlg_hw,
                "save_dialog_title": dlg_title,
            }

    for ch in _enum_win32_child_controls(hwnd, max_items=32):
        cls_l = ch["class_name"].lower()
        if "edit" in cls_l or "richedit" in cls_l:
            ok_m, mod_flag = _send_int_msg_timeout_win32(int(ch["child_hwnd"]), 0x00B8, 0, 0, timeout_ms=50)  # EM_GETMODIFY
            if ok_m and mod_flag != 0:
                return {"reason": "edit_control_modified_flag", "title": title, "modified_child_hwnd": int(ch["child_hwnd"])}

    return None


CUA_WINDOW_INPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": list(CUA_WINDOW_ACTIONS),
            "default": "list_windows",
            "description": "list_windows|capture|screenshot|uia_tree|click|double_click|right_click|scroll|invoke|set_value|type_text|send_keys|post_message|restore|close|close_window",
        },
        "hwnd": {"type": "integer", "default": 0, "description": "Window HWND"},
        "pid": {"type": "integer", "default": 0, "description": "Process ID"},
        "title_query": {"type": "string", "default": "", "description": "Title/exe filter"},
        "control_name": {"type": "string", "default": "", "description": "UIA/menu/child name"},
        "automation_id": {"type": "string", "default": "", "description": "UIA AutomationId or Win32 control ID"},
        "control_type": {"type": "string", "default": "", "description": "Button|MenuItem|Edit|ComboBox|ListItem"},
        "value": {"type": "string", "default": "", "description": "Text, key chord (e.g. ctrl+s), or option value"},
        "text": {"type": "string", "default": "", "description": "Alias for value when action='type_text', 'set_value', or 'send_keys'"},
        "x": {"type": "integer", "default": -1, "description": "Target X coordinate (image or client space)"},
        "y": {"type": "integer", "default": -1, "description": "Target Y coordinate (image or client space)"},
        "coord_space": {
            "type": "string",
            "enum": ["auto", "image", "client", "window"],
            "default": "auto",
            "description": "Coordinate space for (x, y): auto|image|client|window",
        },
        "direction": {
            "type": "string",
            "default": "down",
            "description": "Scroll direction for action='scroll': down|up|left|right",
        },
        "wheel_delta": {
            "type": "integer",
            "default": 0,
            "description": "Explicit WM_MOUSEWHEEL delta (multiples of 120; negative scrolls down)",
        },
        "clicks": {
            "type": "integer",
            "default": 3,
            "description": "Number of 120-unit wheel notches when wheel_delta=0",
        },
        "vk": {"type": "integer", "default": 0, "description": "Virtual-key code for send_keys/post_message"},
        "grid_step": {"type": "integer", "default": 0, "description": "Coordinate grid step px (e.g. 50)"},
        "on_screen_only": {"type": "boolean", "default": True, "description": "Skip hidden/zero-size windows"},
        "include_minimized": {"type": "boolean", "default": False, "description": "Include minimized windows in list_windows"},
        "max_elements": {"type": "integer", "default": 60, "description": "Max UIA elements returned (5..200)"},
        "save_path": {"type": "string", "default": "", "description": "Optional workspace path to save screenshot"},
        "force_discard_unsaved": {"type": "boolean", "default": False, "description": "Explicitly confirm closing unsaved window"},
        "delivery_mode": {
            "type": "string",
            "enum": ["background_zero_focus", "foreground_physical"],
            "default": "background_zero_focus",
            "description": "Input delivery mode: background_zero_focus (PostMessageW/UIA, zero focus steal) or foreground_physical",
        },
        "caller": {"type": "string", "default": "", "description": "Optional caller identifier"},
    },
    "required": [],
}


class CuaWindowPackPlugin:
    """Layer 1 `PackPlugin` exposing `cua_window` (`pack_id='cua'`)."""

    pack_id: str = "cua"

    def __init__(
        self,
        *,
        guard: Optional[WorkspaceGuard] = None,
        proc_manager: Optional[ProcessManager] = None,
        policy: Optional[Any] = None,
        state_root: Optional[Union[str, Path]] = None,
        prefix: str = "",
        human_idle_threshold_ms: int = DEFAULT_HUMAN_IDLE_THRESHOLD_MS,
        delivery_mode: str = "background_zero_focus",
        idle_ms_provider: Optional[Callable[[], int]] = None,
        desktop_name_provider: Optional[Callable[[], str]] = None,
        extra_seed_pids: Iterable[int] = (),
        include_self_pid: bool = True,
    ) -> None:
        self.guard: WorkspaceGuard = guard or DEFAULT_GUARD
        self.proc_manager: Optional[ProcessManager] = DEFAULT_PROCESS_MANAGER if proc_manager is None else proc_manager
        self.policy = policy
        self._explicit_state_root: Optional[Path] = canonical_realpath(state_root) if state_root else None
        self._explicit_prefix = (prefix or "").strip()
        self.human_idle_threshold_ms = max(0, int(human_idle_threshold_ms))
        self.delivery_mode = (delivery_mode or "background_zero_focus").strip() or "background_zero_focus"
        self._idle_ms_provider = idle_ms_provider
        self._desktop_name_provider = desktop_name_provider
        self._extra_seed_pids: Set[int] = {int(p) for p in extra_seed_pids if int(p or 0) > 0}
        self.include_self_pid = bool(include_self_pid)

    def _effective_human_idle_threshold_ms(self) -> int:
        if self.policy is not None:
            for attr_name in ("human_idle_threshold_ms", "cua_human_idle_threshold_ms"):
                raw_thr = getattr(self.policy, attr_name, None)
                if raw_thr is not None:
                    try:
                        return max(0, int(raw_thr))
                    except (TypeError, ValueError):
                        pass
        return max(0, int(self.human_idle_threshold_ms))

    def register_session_pid(self, pid: int) -> None:
        if int(pid or 0) > 0:
            self._extra_seed_pids.add(int(pid))

    def _effective_prefix(self) -> str:
        if self._explicit_prefix:
            return self._explicit_prefix
        if self.policy is not None:
            pol_p = str(getattr(self.policy, "eff_prefix", "") or "").strip()
            if pol_p:
                return pol_p
        return self.guard.tool_prefix or "pc"

    def _effective_state_root(self) -> Path:
        if self._explicit_state_root is not None:
            return self._explicit_state_root
        if self.policy is not None and getattr(self.policy, "state_root", None):
            return canonical_realpath(self.policy.state_root)
        return self.guard.effective_state_root()

    def _resolve_runtime_scope(self) -> Tuple[str, bool, Tuple[Path, ...]]:
        """Return `(short_tier, restrict_to_workspace, workspace_roots)`."""
        if self.policy is not None and hasattr(self.policy, "refresh"):
            cur_tier, cur_tcfg, cur_ws = self.policy.refresh()
            restrict = bool(cur_tcfg.get("restrict_to_workspace", True))
            short_t = normalize_tier(cur_tier, restrict_to_workspace=restrict)
            pol_roots = getattr(self.policy, "workspace_roots", ())
            if pol_roots:
                roots = tuple(canonical_realpath(p) for p in pol_roots)
            elif cur_ws:
                roots = (canonical_realpath(cur_ws),)
            else:
                roots = self.guard.workspace_roots
            return short_t, restrict, roots

        short_t = normalize_tier(self.guard.tier, restrict_to_workspace=self.guard.restrict_to_workspace)
        restrict = bool(self.guard.restrict_to_workspace or short_t == "L3")
        return short_t, restrict, self.guard.workspace_roots

    def _query_idle_ms(self) -> int:
        if self._idle_ms_provider is not None:
            return int(self._idle_ms_provider())
        return get_physical_idle_ms()

    def _build_l3_scope_block_dict(
        self,
        *,
        action: str,
        target_hwnd: int,
        owner_pid: int,
        short_tier: str,
        workspace_roots: Sequence[Path],
        prefix: str,
    ) -> Dict[str, Any]:
        exe_full = _query_process_full_path_win32(owner_pid) if owner_pid > 0 else ""
        proc_base = os.path.basename(exe_full) if exe_full else f"pid:{owner_pid}"
        ws_disp = ", ".join(str(r) for r in workspace_roots) if workspace_roots else "(none)"
        return {
            "ok": False,
            "pack": "cua",
            "action": action,
            "hwnd": int(target_hwnd),
            "owner_pid": int(owner_pid),
            "owner_process": proc_base,
            "owner_exe": exe_full,
            "permission_tier": short_tier,
            "workspace_root": str(workspace_roots[0]) if workspace_roots else "",
            "blocked_by_guardrail": True,
            "blocked_by_l3_window_scope": True,
            "error_code": ERR_L3_WINDOW_SCOPE_BLOCKED,
            "error": (
                f"[LOCALPC L3 WINDOW SCOPE BLOCKED]: Refused `{action}` on external host window HWND {target_hwnd} "
                f"(`{proc_base}`, pid={owner_pid}) outside workspace [{ws_disp}]. "
                f"In L3 (`tier3_workspace_dev`), `{prefix}_cua_window` strictly restricts all window inspection, capture, "
                "and control actions to workspace processes or current MCP session seed PID descendants."
            ),
            "hint": "Switch to L4 (`tier4_full_power`) on the host PC if you intend to operate external desktop applications.",
        }

    def cua_window(
        self,
        action: str = "list_windows",
        hwnd: int = 0,
        pid: int = 0,
        title_query: str = "",
        control_name: str = "",
        automation_id: str = "",
        control_type: str = "",
        value: str = "",
        text: str = "",
        x: int = -1,
        y: int = -1,
        coord_space: str = "auto",
        direction: str = "down",
        wheel_delta: int = 0,
        clicks: int = 3,
        vk: int = 0,
        grid_step: int = 0,
        on_screen_only: bool = True,
        include_minimized: bool = False,
        max_elements: int = 60,
        save_path: str = "",
        force_discard_unsaved: bool = False,
        delivery_mode: str = "",
        caller: str = "",
    ) -> Any:
        _ = caller
        eff_delivery_mode = (delivery_mode or self.delivery_mode or "background_zero_focus").strip().lower()
        eff_prefix = self._effective_prefix()
        short_tier, restrict_l3, ws_roots = self._resolve_runtime_scope()
        ws_primary = str(ws_roots[0]) if ws_roots else str(Path.cwd())
        act = (action or "list_windows").strip().lower()

        if act not in CUA_WINDOW_ACTIONS:
            return {
                "ok": False,
                "pack": "cua",
                "error": f"Unsupported action `{action}` for {eff_prefix}_cua_window (expected {', '.join(CUA_WINDOW_ACTIONS)}).",
            }

        if short_tier in ("L1", "L2"):
            return {
                "ok": False,
                "pack": "cua",
                "action": act,
                "blocked_by_permission_tier": True,
                "permission_tier": short_tier,
                "error": f"[LOCALPC PERMISSION TIER BLOCKED]: `{eff_prefix}_cua_window` is disabled in tier `{short_tier}`.",
            }

        if sys.platform != "win32":
            return {
                "ok": False,
                "pack": "cua",
                "action": act,
                "unsupported_platform": True,
                "platform": sys.platform,
                "error": (
                    f"{eff_prefix}_cua_window requires Windows (win32) for offscreen Win32 EnumWindows / PrintWindow(2) / UIA control "
                    f"(current OS platform: `{sys.platform}`)."
                ),
            }

        import ctypes
        from ctypes import wintypes

        fg_before, cur_before, clip_before = snapshot_l0_desktop_state()

        def _attach_zero_focus_proof(doc: Dict[str, Any], target_h: int = 0, settle_ms: int = 0) -> Dict[str, Any]:
            if settle_ms > 0:
                time.sleep(min(0.15, settle_ms / 1000.0))
                if target_h > 0:
                    is_hwnd_responsive_win32(target_h, timeout_ms=50)
            fg_after, cur_after, clip_after = snapshot_l0_desktop_state()
            doc["focus_unchanged"] = bool(fg_before == fg_after)
            doc["foreground_hwnd_before"] = fg_before
            doc["foreground_hwnd_after"] = fg_after
            doc["cursor_unchanged"] = bool(cur_before == cur_after)
            doc["clipboard_unchanged"] = bool(clip_before == clip_after)
            doc["delta_clip"] = int(clip_after - clip_before)
            doc["delivery_mode"] = eff_delivery_mode
            return doc

        enforce_l3_fence = bool(short_tier == "L3" or restrict_l3)
        seed_pids: Set[int] = set()
        ppid_map: Dict[int, int] = {}
        stop_anc_pid = 0 if self.include_self_pid else os.getpid()
        if enforce_l3_fence:
            seed_pids = collect_mcp_session_seed_pids(
                proc_manager=self.proc_manager,
                state_root=self._effective_state_root(),
                prefix=eff_prefix,
                extra_seed_pids=self._extra_seed_pids,
                include_self_pid=self.include_self_pid,
            )
            ppid_map = _snapshot_win32_parent_pids()

        def _pid_ok_l3(cand_pid: int) -> bool:
            if not enforce_l3_fence:
                return True
            return _is_pid_in_l3_scope(
                cand_pid,
                workspace_roots=ws_roots,
                seed_pids=seed_pids,
                ppid_map=ppid_map,
                stop_ancestor_pid=stop_anc_pid,
            )

        def _win_ok_l3(cand_hwnd: int, cand_pid: int = 0) -> bool:
            if not enforce_l3_fence:
                return True
            return _is_window_in_l3_workspace_scope(
                cand_hwnd,
                workspace_roots=ws_roots,
                seed_pids=seed_pids,
                ppid_map=ppid_map,
                owner_pid=cand_pid,
                stop_ancestor_pid=stop_anc_pid,
            )

        eff_val = value if value != "" else text
        eff_x: Optional[int] = int(x) if x is not None and int(x) >= 0 else None
        eff_y: Optional[int] = int(y) if y is not None and int(y) >= 0 else None

        # 1. `list_windows` (with full L3 window fence!)
        if act == "list_windows":
            if enforce_l3_fence and int(hwnd or 0) > 0:
                _, h_pid = _read_hwnd_class_and_pid(int(hwnd))
                if not _win_ok_l3(int(hwnd), h_pid):
                    return _attach_zero_focus_proof(
                        self._build_l3_scope_block_dict(
                            action="list_windows",
                            target_hwnd=int(hwnd),
                            owner_pid=h_pid,
                            short_tier=short_tier,
                            workspace_roots=ws_roots,
                            prefix=eff_prefix,
                        )
                    )
            if enforce_l3_fence and int(pid or 0) > 0 and not _pid_ok_l3(int(pid)):
                return _attach_zero_focus_proof(
                    self._build_l3_scope_block_dict(
                        action="list_windows",
                        target_hwnd=int(hwnd or 0),
                        owner_pid=int(pid),
                        short_tier=short_tier,
                        workspace_roots=ws_roots,
                        prefix=eff_prefix,
                    )
                )

            raw_wins = _enum_windows_zero_focus(
                on_screen_only=bool(on_screen_only),
                include_minimized=bool(include_minimized),
                pid_filter=int(pid or 0),
                title_query=title_query or "",
            )
            if int(hwnd or 0) > 0:
                raw_wins = [w for w in raw_wins if int(w["hwnd"]) == int(hwnd)]

            if enforce_l3_fence:
                if ws_roots:
                    cand_pids = [int(w["pid"]) for w in raw_wins if int(w["pid"]) not in seed_pids]
                    if cand_pids:
                        _prefetch_process_cmdlines_win32(cand_pids)
                kept_wins: List[Dict[str, Any]] = []
                blocked_first: Optional[Dict[str, Any]] = None
                filtered_ext = 0
                for w in raw_wins:
                    if _win_ok_l3(int(w["hwnd"]), int(w["pid"])):
                        kept_wins.append(w)
                    else:
                        filtered_ext += 1
                        if blocked_first is None:
                            blocked_first = w
                has_explicit_target = bool((title_query or "").strip() or int(hwnd or 0) > 0 or int(pid or 0) > 0)
                if not kept_wins and blocked_first is not None and has_explicit_target:
                    return _attach_zero_focus_proof(
                        self._build_l3_scope_block_dict(
                            action="list_windows",
                            target_hwnd=int(blocked_first["hwnd"]),
                            owner_pid=int(blocked_first["pid"]),
                            short_tier=short_tier,
                            workspace_roots=ws_roots,
                            prefix=eff_prefix,
                        )
                    )
                return _attach_zero_focus_proof(
                    {
                        "ok": True,
                        "pack": "cua",
                        "action": "list_windows",
                        "permission_tier": short_tier,
                        "l3_window_fence": True,
                        "external_windows_filtered": filtered_ext,
                        "window_count": len(kept_wins),
                        "windows": kept_wins[:120],
                    }
                )

            return _attach_zero_focus_proof(
                {
                    "ok": True,
                    "pack": "cua",
                    "action": "list_windows",
                    "permission_tier": short_tier,
                    "window_count": len(raw_wins),
                    "windows": raw_wins[:120],
                }
            )

        # 2. Resolve target HWND (forbidding full-desktop HWND 0 capture)
        u32 = ctypes.WinDLL("user32", use_last_error=True)
        u32.GetDesktopWindow.argtypes = []
        u32.GetDesktopWindow.restype = wintypes.HWND
        desktop_hwnd = int(u32.GetDesktopWindow() or 0)

        eff_hwnd, err_h = _resolve_target_hwnd(
            hwnd,
            pid,
            title_query,
            prefer_authorized_fn=_pid_ok_l3 if enforce_l3_fence else None,
        )
        if err_h or eff_hwnd <= 0:
            if enforce_l3_fence and int(hwnd or 0) == 0 and int(pid or 0) == 0 and not (title_query or "").strip():
                return _attach_zero_focus_proof(
                    {
                        "ok": False,
                        "pack": "cua",
                        "action": act,
                        "blocked_by_guardrail": True,
                        "blocked_by_l3_window_scope": True,
                        "error_code": ERR_L3_WINDOW_SCOPE_BLOCKED,
                        "error": f"[LOCALPC L3 WINDOW SCOPE BLOCKED]: Full-desktop `{act}` without a workspace window `hwnd` is prohibited in L3.",
                    }
                )
            return _attach_zero_focus_proof({"ok": False, "pack": "cua", "action": act, "error": err_h or "Target window not found."})

        if desktop_hwnd > 0 and eff_hwnd == desktop_hwnd:
            return _attach_zero_focus_proof(
                self._build_l3_scope_block_dict(
                    action=act,
                    target_hwnd=eff_hwnd,
                    owner_pid=0,
                    short_tier=short_tier,
                    workspace_roots=ws_roots,
                    prefix=eff_prefix,
                )
            )

        # 3. Enforce L3 window fence across ALL remaining actions (`capture`, `screenshot`, `uia_tree`, `click`, `type_text`, `close_window`, etc.)
        if enforce_l3_fence:
            _, owner_pid = _read_hwnd_class_and_pid(eff_hwnd)
            if not _win_ok_l3(eff_hwnd, owner_pid):
                return _attach_zero_focus_proof(
                    self._build_l3_scope_block_dict(
                        action=act,
                        target_hwnd=eff_hwnd,
                        owner_pid=owner_pid,
                        short_tier=short_tier,
                        workspace_roots=ws_roots,
                        prefix=eff_prefix,
                    )
                )

        # 4. Enforce human-present yield ONLY on foreground physical input modes (never on `background_zero_focus` PostMessageW)
        eff_idle_threshold_ms = self._effective_human_idle_threshold_ms()
        if (
            eff_delivery_mode != "background_zero_focus"
            and act in CUA_MUTATING_ACTIONS
            and eff_idle_threshold_ms > 0
        ):
            idle_ms = self._query_idle_ms()
            if idle_ms < eff_idle_threshold_ms:
                return _attach_zero_focus_proof(
                    {
                        "ok": False,
                        "pack": "cua",
                        "action": act,
                        "hwnd": eff_hwnd,
                        "blocked": True,
                        "blocked_by_guardrail": True,
                        "human_active_yield": True,
                        "error_code": ERR_HUMAN_ACTIVE_YIELD,
                        "idle_ms": idle_ms,
                        "threshold_ms": eff_idle_threshold_ms,
                        "error": (
                            f"[CUA HUMAN ACTIVE YIELD] ({ERR_HUMAN_ACTIVE_YIELD}): Physical keyboard/mouse input was active "
                            f"{idle_ms}ms ago (< {eff_idle_threshold_ms}ms threshold); yielding to human during foreground input."
                        ),
                    }
                )

        # 5. `restore` (non-activating `SW_SHOWNOACTIVATE = 4`)
        if act == "restore":
            h_arg = wintypes.HWND(eff_hwnd)
            was_min = bool(u32.IsIconic(h_arg))
            if was_min:
                u32.ShowWindow(h_arg, 4)  # SW_SHOWNOACTIVATE
                time.sleep(0.06)
                if bool(u32.IsIconic(h_arg)):
                    _send_int_msg_timeout_win32(eff_hwnd, 0x0112, 0xF120, 0, timeout_ms=200)
                    time.sleep(0.06)
            now_min = bool(u32.IsIconic(h_arg))
            return _attach_zero_focus_proof(
                {
                    "ok": not now_min,
                    "pack": "cua",
                    "action": "restore",
                    "hwnd": eff_hwnd,
                    "was_minimized": was_min,
                    "window_minimized": now_min,
                },
                target_h=eff_hwnd,
                settle_ms=30,
            )

        # 6. `capture` / `screenshot` (with `Winlogon` / pure-black frame detection & `#32770` owned dialog metadata)
        if act in ("capture", "screenshot"):
            d_override = self._desktop_name_provider() if self._desktop_name_provider is not None else None
            cap_res = _capture_hwnd_printwindow_offscreen(
                eff_hwnd,
                grid_step=int(grid_step or 0),
                prefix=eff_prefix,
                desktop_name_override=d_override,
            )
            if not cap_res.get("ok"):
                return _attach_zero_focus_proof({"pack": "cua", "action": act, **cap_res})

            comp = compress_capture_bytes(cap_res["raw_png"], source_label=f"cua_window:PrintWindow(hwnd={eff_hwnd})")
            saved_p, save_err = save_optional_capture(
                comp["out_bytes"],
                save_path,
                self.guard,
                workspace_root=ws_primary,
                tool_name="cua_window",
            )
            if save_err:
                return _attach_zero_focus_proof({"ok": False, "pack": "cua", "blocked_by_guardrail": True, "error": save_err})

            cap_sz = cap_res.get("captured_size") or [comp["meta"]["width"], comp["meta"]["height"]]
            geom_now = _get_window_geometry_win32(eff_hwnd)
            scale_rec = record_window_capture_scale(
                eff_hwnd,
                image_width=int(comp["meta"]["width"]),
                image_height=int(comp["meta"]["height"]),
                captured_width=int(cap_sz[0]),
                captured_height=int(cap_sz[1]),
                client_offset=cap_res.get("client_offset") or geom_now["client_offset"],
                client_size=geom_now["client_size"],
            )

            meta = _attach_zero_focus_proof(
                {
                    **comp["meta"],
                    "pack": "cua",
                    "action": act,
                    "hwnd": eff_hwnd,
                    "title": cap_res.get("title", ""),
                    "class_name": cap_res.get("class_name", ""),
                    "is_dialog": cap_res.get("is_dialog", False),
                    "owned_dialogs": cap_res.get("owned_dialogs", []),
                    "window_minimized": False,
                    "window_rect": cap_res.get("window_rect"),
                    "captured_size": cap_res.get("captured_size"),
                    "client_offset": cap_res.get("client_offset"),
                    "scale_factor": scale_rec["scale_factor"],
                    "dpi": cap_res.get("dpi"),
                    "dpi_scale": cap_res.get("dpi_scale"),
                    "window_dpi_aware": cap_res.get("window_dpi_aware"),
                    "grid_step": cap_res.get("grid_step", 0),
                    "grid_drawn": cap_res.get("grid_drawn", False),
                    "coordinate_space": "image" if scale_rec["scale_factor"] < 0.9999 else "window_capture_px",
                    "capture_api": "PrintWindow(PW_RENDERFULLCONTENT=2)",
                }
            )
            if saved_p:
                meta["saved_path"] = saved_p
            return build_mcp_image_blocks(meta, comp["b64_data"], comp["mime"])

        # 7. `uia_tree` (150% DPI calibrated to `window_capture_px` + owned `#32770` dialogs)
        if act == "uia_tree":
            tree_doc = extract_uia_tree(eff_hwnd, max_elements=int(max_elements or 60))
            return _attach_zero_focus_proof({"pack": "cua", "action": "uia_tree", **tree_doc})

        # 7b. `scroll` (background zero-focus `WM_MOUSEWHEEL`)
        if act == "scroll":
            sc_res = _scroll_window_offscreen(
                eff_hwnd,
                raw_x=eff_x,
                raw_y=eff_y,
                coord_space=coord_space,
                direction=direction,
                wheel_delta=int(wheel_delta or 0),
                clicks=int(clicks or 3),
                prefix=eff_prefix,
            )
            return _attach_zero_focus_proof({"pack": "cua", "action": "scroll", "hwnd": eff_hwnd, **sc_res}, target_h=eff_hwnd, settle_ms=35)

        # 7c. `double_click` / `right_click`
        if act in ("double_click", "right_click"):
            btn_kind = "double" if act == "double_click" else "right"
            tx, ty = eff_x, eff_y
            eff_cs = coord_space
            if (tx is None or ty is None) and ((control_name or "").strip() or (automation_id or "").strip()):
                want_cn_m = (control_name or "").strip().lower()
                want_aid_m = (automation_id or "").strip()
                for ch in _enum_win32_child_controls(eff_hwnd, max_items=120):
                    if (want_aid_m and ch["automation_id"] == want_aid_m) or (
                        want_cn_m and want_cn_m in ch["text"].lower()
                    ):
                        tx, ty = int(ch["center"][0]), int(ch["center"][1])
                        eff_cs = "window"
                        break
            if tx is None or ty is None:
                return _attach_zero_focus_proof(
                    {
                        "ok": False,
                        "pack": "cua",
                        "action": act,
                        "hwnd": eff_hwnd,
                        "error": f"Provide `(x, y)` coordinates (or `control_name`/`automation_id`) for action='{act}'.",
                    }
                )
            clk_m = _postmessage_click_offscreen(eff_hwnd, tx, ty, prefix=eff_prefix, button=btn_kind, coord_space=eff_cs)
            return _attach_zero_focus_proof({"pack": "cua", "action": act, "hwnd": eff_hwnd, **clk_m}, target_h=eff_hwnd, settle_ms=45)

        # 8. `invoke` / `click`
        if act in ("invoke", "click"):
            want_cn = (control_name or "").strip()
            want_aid = (automation_id or "").strip()
            want_ct = (control_type or "").strip().lower()

            if eff_x is not None and eff_y is not None and not want_cn and not want_aid and not want_ct:
                clk = _postmessage_click_offscreen(
                    eff_hwnd,
                    eff_x,
                    eff_y,
                    prefix=eff_prefix,
                    button="left",
                    coord_space=coord_space,
                )
                return _attach_zero_focus_proof({"pack": "cua", "action": act, **clk}, target_h=eff_hwnd, settle_ms=45)

            if want_ct in ("", "menuitem", "menubar") and (want_cn or want_aid):
                menu_items = _enum_win32_menu_bar(eff_hwnd)
                clean_want = _clean_menu_label(want_cn).lower()
                for mi in menu_items:
                    aid_match = bool(
                        want_aid and (mi["automation_id"] == want_aid or (mi["menu_command_id"] > 0 and str(mi["menu_command_id"]) == want_aid))
                    )
                    nm_match = bool(
                        want_cn
                        and (
                            mi["name"].lower() == want_cn.lower()
                            or mi["clean_name"].lower() == clean_want
                            or mi["menu_path"].lower().endswith(" > " + clean_want)
                        )
                    )
                    if aid_match or nm_match:
                        cmd_id = int(mi.get("menu_command_id") or 0)
                        if cmd_id > 0:
                            _post_message_64safe(eff_hwnd, 0x0111, cmd_id, 0)
                            return _attach_zero_focus_proof(
                                {
                                    "ok": True,
                                    "pack": "cua",
                                    "action": act,
                                    "hwnd": eff_hwnd,
                                    "matched_name": mi["name"],
                                    "matched_control_type": "MenuItem",
                                    "menu_command_id": cmd_id,
                                    "delivery": "PostMessageW(WM_COMMAND:MenuItem)",
                                },
                                target_h=eff_hwnd,
                                settle_ms=45,
                            )

            if want_ct in ("", "button", "checkbox", "radiobutton", "splitbutton"):
                children = _enum_win32_child_controls(eff_hwnd, max_items=120)
                best_btn: Optional[Dict[str, Any]] = None
                clean_want_btn = _clean_menu_label(want_cn).lower()
                for ch in children:
                    if not ch["enabled"]:
                        continue
                    ch_ct = ch["control_type"].lower()
                    if ch_ct not in ("button", "checkbox", "radiobutton"):
                        continue
                    if want_ct and ch_ct != want_ct:
                        continue
                    aid_ok = bool(want_aid and ch["automation_id"] == want_aid)
                    ch_txt = ch["text"]
                    ch_clean = _clean_menu_label(ch_txt).lower()
                    nm_exact = bool(want_cn and (ch_txt.lower() == want_cn.lower() or ch_clean == clean_want_btn))
                    nm_sub = bool(want_cn and not nm_exact and clean_want_btn and clean_want_btn in ch_clean)
                    if aid_ok or nm_exact or nm_sub:
                        best_btn = ch
                        if aid_ok or nm_exact:
                            break
                if best_btn is not None:
                    trig = _trigger_win32_control_non_activating(eff_hwnd, int(best_btn["child_hwnd"]))
                    return _attach_zero_focus_proof(
                        {
                            "pack": "cua",
                            "action": act,
                            "hwnd": eff_hwnd,
                            "matched_name": best_btn["text"],
                            "matched_aid": best_btn["automation_id"],
                            "matched_control_type": best_btn["control_type"],
                            **trig,
                        },
                        target_h=eff_hwnd,
                        settle_ms=45,
                    )

            uia_inv = _run_uia_powershell_op(
                eff_hwnd,
                op="invoke",
                control_name=want_cn,
                automation_id=want_aid,
                control_type=control_type,
            )
            if uia_inv.get("ok"):
                return _attach_zero_focus_proof({"pack": "cua", "action": act, "hwnd": eff_hwnd, **uia_inv}, target_h=eff_hwnd, settle_ms=45)

            cand_hw = int(uia_inv.get("native_hwnd") or 0)
            if cand_hw > 0 and u32.IsWindow(wintypes.HWND(cand_hw)):
                trig = _trigger_win32_control_non_activating(eff_hwnd, cand_hw)
                return _attach_zero_focus_proof({"pack": "cua", "action": act, "hwnd": eff_hwnd, **trig}, target_h=eff_hwnd, settle_ms=45)

            if eff_x is not None and eff_y is not None:
                clk = _postmessage_click_offscreen(
                    eff_hwnd,
                    eff_x,
                    eff_y,
                    prefix=eff_prefix,
                    button="left",
                    coord_space=coord_space,
                )
                return _attach_zero_focus_proof({"pack": "cua", "action": act, **clk}, target_h=eff_hwnd, settle_ms=45)

            return _attach_zero_focus_proof(
                {
                    "ok": False,
                    "pack": "cua",
                    "action": act,
                    "hwnd": eff_hwnd,
                    "error": uia_inv.get("error") or "Provide `control_name` / `automation_id` (optional `control_type`) or window-relative `(x, y)` coordinates.",
                }
            )

        # 9. `set_value` / `type_text` (zero clipboard, zero focus steal, exact `(x, y)` ChildWindowFromPointEx targeting)
        if act in ("set_value", "type_text"):
            want_cn = (control_name or "").strip()
            want_aid = (automation_id or "").strip()
            want_ct = (control_type or "").strip().lower()
            val_str = str(eff_val or "")

            if eff_x is not None and eff_y is not None and not want_aid and not want_cn:
                geom_t = _get_window_geometry_win32(eff_hwnd)
                win_w_t, win_h_t = geom_t["window_size"]
                coord_t = _resolve_cua_coordinates(eff_hwnd, eff_x, eff_y, coord_space=coord_space, geom=geom_t)
                wx_t, wy_t = int(coord_t["wx"]), int(coord_t["wy"])
                if wx_t < 0 or wy_t < 0 or (win_w_t > 0 and wx_t > win_w_t) or (win_h_t > 0 and wy_t > win_h_t):
                    return _attach_zero_focus_proof(
                        {
                            "ok": False,
                            "pack": "cua",
                            "action": act,
                            "hwnd": eff_hwnd,
                            "input_xy": coord_t["input_xy"],
                            "window_xy": [wx_t, wy_t],
                            "coord_space_used": coord_t["coord_space_used"],
                            "scale_factor": coord_t["scale_factor"],
                            "capture_size": [win_w_t, win_h_t],
                            "error": f"Coordinates ({wx_t}, {wy_t}) are outside window bounds [0..{win_w_t}, 0..{win_h_t}].",
                        }
                    )
                hit_t = _hit_test_child_hwnd_win32(eff_hwnd, wx_t, wy_t, prefer_input=True)
                hit_hwnd = int(hit_t["target_hwnd"])
                hit_cls = str(hit_t["target_class"])
                hit_cls_l = hit_cls.lower()
                xy_meta = {
                    "input_xy": coord_t["input_xy"],
                    "window_xy": [wx_t, wy_t],
                    "parent_client_xy": coord_t["parent_client_xy"],
                    "client_xy": hit_t["client_xy"],
                    "coord_space_used": coord_t["coord_space_used"],
                    "scale_factor": coord_t["scale_factor"],
                }
                if hit_hwnd != eff_hwnd and ("edit" in hit_cls_l or "richedit" in hit_cls_l or "combobox" in hit_cls_l or act == "set_value"):
                    sv_xy = _set_win32_control_value_64safe(eff_hwnd, hit_hwnd, val_str)
                    return _attach_zero_focus_proof(
                        {"pack": "cua", "action": act, "hwnd": eff_hwnd, **xy_meta, **sv_xy},
                        target_h=eff_hwnd,
                        settle_ms=35,
                    )
                # Custom / canvas / non-Edit control at `(wx_t, wy_t)`: focus point locally and stream WM_CHAR to `hit_hwnd`
                cx_h = max(0, int(hit_t["client_xy"][0]))
                cy_h = max(0, int(hit_t["client_xy"][1]))
                lp_h = ((cy_h & 0xFFFF) << 16) | (cx_h & 0xFFFF)
                _post_message_64safe(hit_hwnd, 0x0201, 0x0001, lp_h)
                _post_message_64safe(hit_hwnd, 0x0202, 0, lp_h)
                for ch_c in val_str[:500]:
                    _post_message_64safe(hit_hwnd, 0x0102, ord(ch_c), 1)
                return _attach_zero_focus_proof(
                    {
                        "ok": True,
                        "pack": "cua",
                        "action": act,
                        "hwnd": eff_hwnd,
                        "target_hwnd": hit_hwnd,
                        "target_class": hit_cls,
                        "chars_posted": min(500, len(val_str)),
                        "delivery": "PostMessageW(WM_CHAR:hit_hwnd)",
                        **xy_meta,
                    },
                    target_h=eff_hwnd,
                    settle_ms=35,
                )

            children = _enum_win32_child_controls(eff_hwnd, max_items=120)
            cand_win32 = 0
            for ch in children:
                ch_cls_l = ch["class_name"].lower()
                ch_ct_l = ch["control_type"].lower()
                if want_ct and ch_ct_l != want_ct and want_ct not in ch_cls_l:
                    continue
                if want_aid and ch["automation_id"] == want_aid and ("edit" in ch_cls_l or "combobox" in ch_cls_l):
                    cand_win32 = int(ch["child_hwnd"])
                    break
                if want_cn and (want_cn.lower() == ch["text"].lower() or want_cn.lower() in ch_cls_l):
                    cand_win32 = int(ch["child_hwnd"])
                    break
            if cand_win32 <= 0 and not want_aid and not want_cn:
                self_cls, _ = _read_hwnd_class_and_pid(eff_hwnd)
                if "edit" in self_cls.lower() or "combobox" in self_cls.lower():
                    cand_win32 = eff_hwnd
                else:
                    for ch in children:
                        if ch["visible"] and ("edit" in ch["class_name"].lower() or (want_ct == "combobox" and "combobox" in ch["class_name"].lower())):
                            cand_win32 = int(ch["child_hwnd"])
                            break

            if act == "type_text" and cand_win32 <= 0 and not want_aid and not want_cn:
                for ch_c in val_str[:500]:
                    _post_message_64safe(eff_hwnd, 0x0102, ord(ch_c), 1)
                return _attach_zero_focus_proof(
                    {
                        "ok": True,
                        "pack": "cua",
                        "action": "type_text",
                        "hwnd": eff_hwnd,
                        "target_hwnd": eff_hwnd,
                        "chars_posted": min(500, len(val_str)),
                        "delivery": "PostMessageW(WM_CHAR)",
                    },
                    target_h=eff_hwnd,
                    settle_ms=35,
                )

            if cand_win32 > 0:
                sv_res = _set_win32_control_value_64safe(eff_hwnd, cand_win32, val_str)
                if sv_res.get("ok"):
                    return _attach_zero_focus_proof({"pack": "cua", "action": act, "hwnd": eff_hwnd, **sv_res}, target_h=eff_hwnd, settle_ms=35)

            uia_sv = _run_uia_powershell_op(
                eff_hwnd,
                op="set_value",
                control_name=want_cn,
                automation_id=want_aid,
                control_type=control_type,
                value=val_str,
            )
            if uia_sv.get("ok"):
                return _attach_zero_focus_proof(
                    {"pack": "cua", "action": act, "hwnd": eff_hwnd, "value_length": len(val_str), **uia_sv},
                    target_h=eff_hwnd,
                    settle_ms=35,
                )

            nat_hw = int(uia_sv.get("native_hwnd") or 0)
            target_h = nat_hw if nat_hw > 0 else eff_hwnd
            sv_fb = _set_win32_control_value_64safe(eff_hwnd, target_h, val_str)
            return _attach_zero_focus_proof({"pack": "cua", "action": act, "hwnd": eff_hwnd, **sv_fb}, target_h=eff_hwnd, settle_ms=35)

        # 10. `post_message` / `send_keys`
        if act in ("post_message", "send_keys"):
            if act == "post_message" and eff_x is not None and eff_y is not None:
                clk = _postmessage_click_offscreen(
                    eff_hwnd,
                    eff_x,
                    eff_y,
                    prefix=eff_prefix,
                    button="left",
                    coord_space=coord_space,
                )
                return _attach_zero_focus_proof({"pack": "cua", "action": act, **clk}, target_h=eff_hwnd, settle_ms=40)

            target_key_h = eff_hwnd
            if (automation_id or "").strip() or (control_name or "").strip():
                for ch in _enum_win32_child_controls(eff_hwnd, max_items=100):
                    if (automation_id and ch["automation_id"] == automation_id.strip()) or (
                        control_name and control_name.strip().lower() in ch["text"].lower()
                    ):
                        target_key_h = int(ch["child_hwnd"])
                        break
            elif eff_x is not None and eff_y is not None:
                coord_k = _resolve_cua_coordinates(eff_hwnd, eff_x, eff_y, coord_space=coord_space)
                hit_k = _hit_test_child_hwnd_win32(eff_hwnd, int(coord_k["wx"]), int(coord_k["wy"]), prefer_input=True)
                target_key_h = int(hit_k["target_hwnd"])

            eff_vk = int(vk or 0)
            if eff_vk <= 0 and act == "send_keys" and str(eff_val or "").strip():
                chord_parsed = parse_key_chord_spec(str(eff_val))
                if chord_parsed is not None:
                    if not chord_parsed.get("ok"):
                        return _attach_zero_focus_proof(
                            {
                                "ok": False,
                                "pack": "cua",
                                "action": "send_keys",
                                "hwnd": eff_hwnd,
                                "error": str(chord_parsed.get("error") or "Invalid key combination."),
                            }
                        )
                    chord_res = _synthesize_key_chord_non_activating(target_key_h, chord_parsed)
                    return _attach_zero_focus_proof(
                        {
                            "pack": "cua",
                            "action": "send_keys",
                            "hwnd": eff_hwnd,
                            **chord_res,
                        },
                        target_h=eff_hwnd,
                        settle_ms=35,
                    )

            if eff_vk > 0:
                vk_code = eff_vk & 0xFF
                chord_vk = _synthesize_key_chord_non_activating(
                    target_key_h,
                    {"ok": True, "modifiers": [], "vk": vk_code, "chord": f"vk:{vk_code}"},
                )
                return _attach_zero_focus_proof(
                    {
                        "ok": True,
                        "pack": "cua",
                        "action": act,
                        "hwnd": eff_hwnd,
                        "target_hwnd": target_key_h,
                        "vk": vk_code,
                        "delivery": chord_vk["delivery"],
                    },
                    target_h=eff_hwnd,
                    settle_ms=35,
                )
            if eff_val:
                for ch_c in str(eff_val)[:500]:
                    _post_message_64safe(target_key_h, 0x0102, ord(ch_c), 1)  # WM_CHAR
                return _attach_zero_focus_proof(
                    {
                        "ok": True,
                        "pack": "cua",
                        "action": act,
                        "hwnd": eff_hwnd,
                        "target_hwnd": target_key_h,
                        "chars_posted": min(500, len(str(eff_val))),
                        "delivery": "PostMessageW(WM_CHAR)",
                    },
                    target_h=eff_hwnd,
                    settle_ms=35,
                )
            return _attach_zero_focus_proof(
                {
                    "ok": False,
                    "pack": "cua",
                    "action": act,
                    "hwnd": eff_hwnd,
                    "error": f"Provide `vk` keycode or `value` text (or `(x, y)` for post_message) when calling action='{act}'.",
                }
            )

        # 11. `close` / `close_window` (with unsaved title `*`/`未保存`/`Modified` & save-confirmation dialog guard!)
        if not force_discard_unsaved:
            unsaved_pre = _detect_unsaved_window_state(eff_hwnd)
            if unsaved_pre is not None:
                return _attach_zero_focus_proof(
                    {
                        "ok": False,
                        "pack": "cua",
                        "action": act,
                        "hwnd": eff_hwnd,
                        "blocked_by_guardrail": True,
                        "unsaved_changes_protected": True,
                        "error_code": ERR_UNSAVED_DOCUMENT_PROTECTED,
                        **unsaved_pre,
                        "error": (
                            f"[CUA UNSAVED GUARD] ({ERR_UNSAVED_DOCUMENT_PROTECTED}): Refused to close window HWND {eff_hwnd} "
                            f"(`{unsaved_pre.get('title', '')}`) because unsaved changes were detected ({unsaved_pre['reason']}). "
                            "Save the document first before closing."
                        ),
                    }
                )

        u32.IsWindow.argtypes = [wintypes.HWND]
        u32.IsWindow.restype = wintypes.BOOL
        pre_dialogs = {int(d["hwnd"]) for d in _enum_owned_dialogs_win32(eff_hwnd)}
        _post_message_64safe(eff_hwnd, 0x0010, 0, 0)  # WM_CLOSE
        time.sleep(0.08)

        if not force_discard_unsaved and u32.IsWindow(wintypes.HWND(eff_hwnd)):
            post_dialogs = [d for d in _enum_owned_dialogs_win32(eff_hwnd) if int(d["hwnd"]) not in pre_dialogs]
            if post_dialogs:
                dlg0 = post_dialogs[0]
                return _attach_zero_focus_proof(
                    {
                        "ok": False,
                        "pack": "cua",
                        "action": act,
                        "hwnd": eff_hwnd,
                        "blocked_by_guardrail": True,
                        "unsaved_changes_protected": True,
                        "error_code": ERR_UNSAVED_DOCUMENT_PROTECTED,
                        "reason": "save_confirmation_dialog_popped",
                        "save_dialog_hwnd": int(dlg0["hwnd"]),
                        "save_dialog_title": dlg0.get("title", ""),
                        "error": (
                            f"[CUA UNSAVED GUARD] ({ERR_UNSAVED_DOCUMENT_PROTECTED}): Window HWND {eff_hwnd} opened a "
                            f"confirmation dialog (HWND {dlg0['hwnd']}) upon close; aborted without discarding unsaved data."
                        ),
                    },
                    target_h=eff_hwnd,
                )

        is_gone = not bool(u32.IsWindow(wintypes.HWND(eff_hwnd)))
        return _attach_zero_focus_proof(
            {
                "ok": True,
                "pack": "cua",
                "action": act,
                "hwnd": eff_hwnd,
                "closed": is_gone,
                "delivery": "PostMessageW(WM_CLOSE)",
            },
            target_h=eff_hwnd,
            settle_ms=35,
        )

    def get_tools(self) -> Sequence[ToolSpec]:
        return (
            ToolSpec(
                base_name="cua_window",
                handler=self.cua_window,
                safety_band=SafetyBand.WORKSPACE_EXEC,
                input_schema=CUA_WINDOW_INPUT_SCHEMA,
                title="Zero-Focus Offscreen Windows CUA Pack",
                description=(
                    "Windows offscreen zero-focus GUI control (alias `desktop_window`): "
                    "`action='list_windows|uia_tree|double_click|right_click|scroll|restore'` plus synonymous pairs "
                    "`capture`/`screenshot`, `click`/`invoke`, `set_value`/`type_text`, `send_keys`/`post_message`, `close`/`close_window`."
                ),
                pack=self.pack_id,
                aliases=("desktop_window",),
                param_aliases={"text": "value"},
                action_param="action",
                action_enum=CUA_WINDOW_ACTIONS,
                open_world=False,
            ),
        )

    def shutdown(self, prefix_filter: str = "") -> None:
        _ = prefix_filter


__all__ = [
    "CUA_MUTATING_ACTIONS",
    "CUA_WINDOW_ACTIONS",
    "CUA_WINDOW_INPUT_SCHEMA",
    "CuaWindowPackPlugin",
    "DEFAULT_HUMAN_IDLE_THRESHOLD_MS",
    "ERR_HUMAN_ACTIVE_YIELD",
    "ERR_L3_WINDOW_SCOPE_BLOCKED",
    "ERR_SCREEN_LOCKED_OR_BLACK_FRAME",
    "ERR_UNSAVED_DOCUMENT_PROTECTED",
    "PackPlugin",
    "_align_thread_dpi_to_window",
    "_cmdline_references_any_workspace",
    "_expand_win32_long_path",
    "_is_window_in_l3_workspace_scope",
    "_postmessage_click_offscreen",
    "bgra_to_rgb_packed",
    "build_mcp_image_blocks",
    "capture_window_offscreen",
    "check_locked_or_black_rgb_frame",
    "collect_mcp_session_seed_pids",
    "compress_capture_bytes",
    "detect_input_desktop_name_win32",
    "draw_coordinate_grid_rgb",
    "encode_rgb_png_stdlib",
    "extract_uia_tree",
    "get_physical_idle_ms",
    "get_window_dpi_info",
    "get_window_dpi_scale",
    "get_window_rect",
    "has_unsaved_title_marker",
    "is_hwnd_responsive_win32",
    "save_optional_capture",
    "snapshot_l0_desktop_state",
]
