"""End-to-end verification for S5 (`packs/browser.py`, `packs/desktop.py`, public docs, and `scripts/build_release.py`)."""
from __future__ import annotations

import ctypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import threading
import time
from typing import Any, Dict, Tuple
import zipfile

import pytest

from cosmos_mcp.core.config import DEFAULT_CORE_TOOLS
from cosmos_mcp.core.guard import WorkspaceGuard
from cosmos_mcp.core.proc import ProcessManager
from cosmos_mcp.packs.browser import BrowserPackPlugin, find_system_chromium_binary
from cosmos_mcp.packs.desktop import CuaWindowPackPlugin, snapshot_l0_desktop_state

REPO_ROOT = Path(__file__).resolve().parents[1]
CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0

if sys.platform == "win32":
    ctypes.windll.kernel32.SetErrorMode(0x8003)


DIRTY_DUAL_LOGIN_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>Dirty Dual Login Test Page</title>
  <style>
    html, body { margin: 0; padding: 0; font-family: sans-serif; }
    .tall-spacer { height: 2600px; background: linear-gradient(#f8fafc, #e2e8f0); padding: 24px; }
    #mobile-drawer { display: none; }
    .vis-hidden { visibility: hidden; width: 180px; height: 32px; }
    .zero-opacity { opacity: 0; width: 180px; height: 32px; }
    .zero-rect { width: 0; height: 0; padding: 0; border: 0; overflow: hidden; }
    .desktop-box { padding: 16px; border: 1px solid #cbd5e1; background: #ffffff; max-width: 520px; }
    .field-row { margin: 10px 0; }
  </style>
</head>
<body>
  <!-- 1. Hidden mobile login form appearing FIRST in DOM with duplicate ID & class -->
  <div id="mobile-drawer">
    <form id="login-form" class="login-form">
      <input id="mob-user" class="user-input" name="username" type="text" value="" placeholder="Mobile Username" />
      <button id="mob-btn" class="login-btn" type="button" onclick="window.__mobClicked = (window.__mobClicked || 0) + 1">Mobile Login</button>
    </form>
  </div>

  <!-- 2. Additional hidden decoys (visibility:hidden, opacity:0, 0x0 rect) -->
  <input id="vis-hidden-user" class="user-input" name="username" type="text" value="" />
  <script>document.getElementById('vis-hidden-user').className = 'user-input vis-hidden';</script>
  <input id="zero-op-user" class="user-input zero-opacity" name="username" type="text" value="" />
  <input id="zero-rect-user" class="user-input zero-rect" name="username" type="text" value="" />
  <input id="ghost-only-input" style="display:none" type="text" value="" />

  <!-- 3. Visible desktop login form -->
  <div class="tall-spacer">
    <div class="desktop-box">
      <form id="login-form" class="login-form">
        <div class="field-row">
          <label for="desk-user">Username</label>
          <input id="desk-user" class="user-input" name="username" type="text" value="" placeholder="Desktop Username" style="width:220px;height:30px;" />
        </div>
        <div class="field-row">
          <select class="env-select" id="hidden-env-select" style="display:none;">
            <option value="wrong">Wrong Hidden</option>
          </select>
          <select class="env-select" id="desk-env-select" style="width:200px;height:30px;">
            <option value="dev">Development</option>
            <option value="prod">Production</option>
            <option value="staging">Staging</option>
          </select>
        </div>
        <div class="field-row">
          <div id="region-combo" role="combobox" aria-expanded="false" tabindex="0"
               style="width:200px;height:30px;border:1px solid #94a3b8;line-height:30px;padding:0 8px;cursor:pointer;"
               onclick="this.setAttribute('aria-expanded','true'); document.getElementById('region-listbox').style.display='block';">
            Select Region
          </div>
          <div id="region-listbox" role="listbox" style="display:none;border:1px solid #94a3b8;width:200px;">
            <div role="option" data-value="ap-east" style="height:28px;line-height:28px;padding:0 8px;cursor:pointer;"
                 onclick="window.__comboPicked='ap-east'; document.getElementById('region-combo').textContent='Asia East';">Asia East</div>
            <div role="option" data-value="eu-central" style="height:28px;line-height:28px;padding:0 8px;cursor:pointer;"
                 onclick="window.__comboPicked='eu-central'; document.getElementById('region-combo').textContent='EU Central';">EU Central</div>
          </div>
        </div>
        <div class="field-row">
          <div id="overview-tab" role="tab" tabindex="0" style="display:inline-block;width:120px;height:28px;border:1px solid #64748b;">Overview Tab</div>
          <div id="rich-note" contenteditable="true" style="width:240px;height:40px;border:1px solid #64748b;margin-top:8px;">Editable Note</div>
        </div>
        <div class="field-row">
          <button id="desk-btn" class="login-btn" type="button" style="width:120px;height:32px;"
                  onclick="window.__deskClicked = (window.__deskClicked || 0) + 1">Desktop Sign In</button>
          <a id="open-tab2" href="/tab2" target="_blank" style="display:inline-block;margin-left:12px;height:28px;">Open Second Tab</a>
          <a id="dl-report" href="/download/cosmos-check.txt" download="cosmos-check.txt" style="display:inline-block;margin-left:12px;height:28px;">Download File</a>
        </div>
      </form>
    </div>
    <div id="bottom-marker" style="margin-top:2100px;height:40px;">Bottom Marker Reached</div>
  </div>
</body>
</html>
"""

SECOND_TAB_HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8" /><title>Second Managed Tab</title></head>
<body><h1 id="tab2-heading">Second Tab Content Active</h1></body>
</html>
"""


class _DirtyPageHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/tab2"):
            body = SECOND_TAB_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path.startswith("/download/"):
            payload = b"cosmos-managed-download-verified\n"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", 'attachment; filename="cosmos-check.txt"')
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
            return

        body = DIRTY_DUAL_LOGIN_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def dirty_http_server() -> Tuple[str, ThreadingHTTPServer]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _DirtyPageHandler)
    port = int(srv.server_address[1])
    th = threading.Thread(target=srv.serve_forever, name="dirty-http-s5", daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{port}", srv
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=3.0)


@pytest.mark.skipif(find_system_chromium_binary() is None, reason="Requires local Edge/Chrome/Chromium binary")
def test_browser_pack_hidden_dom_filtering_scroll_select_tabs_download_and_login_window(
    tmp_path: Path,
    dirty_http_server: Tuple[str, ThreadingHTTPServer],
) -> None:
    base_url, _ = dirty_http_server
    ws_dir = tmp_path / "workspace"
    state_dir = tmp_path / "state"
    ws_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)

    guard = WorkspaceGuard(
        workspace_roots=ws_dir,
        state_root=state_dir,
        tier="tier3_workspace_dev",
        restrict_to_workspace=True,
    )
    pm = ProcessManager(state_root=state_dir)
    plugin = BrowserPackPlugin(
        guard=guard,
        proc_manager=pm,
        state_root=state_dir,
        prefix="pc",
        allow_loopback_dev=True,
    )

    fg_before, _, _ = snapshot_l0_desktop_state()
    try:
        opened = plugin.browser_use(action="open", url=f"{base_url}/", wait_ms=150)
        assert opened["ok"] is True, opened
        assert opened.get("scroll_height", 0) >= 2000
        assert opened.get("total_height", 0) >= 2000
        assert opened.get("scroll_y", -1) == 0

        # Snapshot must exclude all hidden inputs and include ARIA combobox/tab + contenteditable
        elems = opened.get("elements", [])
        elem_ids = {str(item.get("id") or "") for item in elems}
        elem_roles = {str(item.get("role") or "") for item in elems}
        assert "desk-user" in elem_ids
        assert "mob-user" not in elem_ids
        assert "vis-hidden-user" not in elem_ids
        assert "zero-op-user" not in elem_ids
        assert "zero-rect-user" not in elem_ids
        assert "ghost-only-input" not in elem_ids
        assert "combobox" in elem_roles
        assert "tab" in elem_roles
        assert "rich-note" in elem_ids

        # Duplicate `#login-form input` and `.user-input` must skip hidden mobile/decoy inputs and fill `#desk-user`
        fill_res = plugin.browser_use(action="fill", selector="#login-form input", text="alice_visible")
        assert fill_res["ok"] is True, fill_res
        assert fill_res["matched_count"] == 2
        assert fill_res["visible_count"] == 1
        assert fill_res["picked_id"] == "desk-user"

        fill_cls = plugin.browser_use(action="fill", selector=".user-input", text="bob_desktop_only")
        assert fill_cls["ok"] is True, fill_cls
        assert fill_cls["matched_count"] == 5
        assert fill_cls["visible_count"] == 1
        assert fill_cls["picked_id"] == "desk-user"

        # Selector matching ONLY hidden node(s) must return ok=False honestly
        fill_hidden = plugin.browser_use(action="fill", selector="#ghost-only-input", text="never")
        assert fill_hidden["ok"] is False
        assert fill_hidden.get("error_code") == "ERR_ELEMENT_HIDDEN"

        # Clicking `.login-btn` must skip hidden `#mob-btn` and click visible `#desk-btn`
        clk_btn = plugin.browser_use(action="click", selector=".login-btn")
        assert clk_btn["ok"] is True, clk_btn
        assert clk_btn["matched_count"] == 2
        assert clk_btn["visible_count"] == 1

        dom_check = plugin.browser_use(
            action="evaluate",
            script="""() => ({
                mobVal: document.getElementById('mob-user').value,
                visHiddenVal: document.getElementById('vis-hidden-user').value,
                zeroOpVal: document.getElementById('zero-op-user').value,
                zeroRectVal: document.getElementById('zero-rect-user').value,
                deskVal: document.getElementById('desk-user').value,
                mobClicked: window.__mobClicked || 0,
                deskClicked: window.__deskClicked || 0
            })""",
        )
        assert dom_check["ok"] is True
        vals = dom_check["result"]
        assert vals["mobVal"] == ""
        assert vals["visHiddenVal"] == ""
        assert vals["zeroOpVal"] == ""
        assert vals["zeroRectVal"] == ""
        assert vals["deskVal"] == "bob_desktop_only"
        assert vals["mobClicked"] == 0
        assert vals["deskClicked"] == 1

        # Select on `<select>` (skipping hidden duplicate `.env-select`) & ARIA `[role="combobox"]`
        sel_res = plugin.browser_use(action="select", selector=".env-select", value="prod")
        assert sel_res["ok"] is True, sel_res
        assert sel_res["selected_value"] == "prod"
        assert sel_res["selected_label"] == "Production"

        combo_res = plugin.browser_use(action="select", selector="#region-combo", label="EU Central")
        assert combo_res["ok"] is True, combo_res
        assert combo_res["selected_value"] == "eu-central"

        # Scroll down, verify snapshot scroll metrics, then scroll back to top
        sc_down = plugin.browser_use(action="scroll", direction="down", amount=800)
        assert sc_down["ok"] is True, sc_down
        assert sc_down["scroll_y"] >= 500
        snap_scrolled = plugin.browser_use(action="snapshot")
        assert snap_scrolled["ok"] is True
        assert snap_scrolled["scroll_y"] >= 500
        assert snap_scrolled["scroll"]["total_height"] >= 2000

        sc_top = plugin.browser_use(action="scroll", direction="top")
        assert sc_top["ok"] is True, sc_top
        assert sc_top["scroll_y"] == 0

        # Download into workspace via CDP `Browser.setDownloadBehavior` / Playwright download handler
        dl_clk = plugin.browser_use(action="click", selector="#dl-report", wait_ms=350)
        assert dl_clk["ok"] is True, dl_clk
        expected_dl = ws_dir / "cosmos-check.txt"
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not expected_dl.is_file():
            time.sleep(0.1)
            plugin.browser_use(action="snapshot")
        assert expected_dl.is_file(), f"Expected downloaded file at {expected_dl}"
        assert expected_dl.read_text(encoding="utf-8").strip() == "cosmos-managed-download-verified"

        # Multi-tab `list_tabs` & `switch_tab`
        tab_clk = plugin.browser_use(action="click", selector="#open-tab2", wait_ms=400)
        assert tab_clk["ok"] is True, tab_clk
        tabs_info = plugin.browser_use(action="list_tabs")
        tab_deadline = time.monotonic() + 3.0
        while time.monotonic() < tab_deadline and int(tabs_info.get("tab_count") or 0) < 2:
            time.sleep(0.1)
            tabs_info = plugin.browser_use(action="list_tabs")
        assert tabs_info["ok"] is True, tabs_info
        assert tabs_info["tab_count"] >= 2

        sw_res = plugin.browser_use(action="switch_tab", text="Second Managed Tab")
        if not sw_res.get("ok"):
            sw_res = plugin.browser_use(action="switch_tab", url="/tab2")
        assert sw_res["ok"] is True, sw_res
        snap_t2 = plugin.browser_use(action="snapshot", wait_ms=150)
        assert snap_t2["ok"] is True
        assert "tab2" in snap_t2["url"] or "Second Managed Tab" in snap_t2["title"]

        sw_back = plugin.browser_use(action="switch_tab", index=0)
        assert sw_back["ok"] is True, sw_back

        # Non-activating offscreen `open_login_window` using isolated managed profile
        login_win = plugin.browser_use(
            action="open_login_window",
            url=f"{base_url}/",
            offscreen=True,
            wait_ms=250,
        )
        assert login_win["ok"] is True, login_win
        assert login_win["show_mode"] == "SW_SHOWNOACTIVATE"
        assert login_win["isolated_managed_profile"] is True
        assert int(login_win["browser_pid"]) > 0

        if sys.platform == "win32":
            fg_after, _, _ = snapshot_l0_desktop_state()
            assert fg_after == fg_before, "Browser automation or open_login_window must never steal foreground focus"

        closed = plugin.browser_use(action="close")
        assert closed["ok"] is True
    finally:
        plugin.shutdown()


OFFSCREEN_WIN32_APP_CODE = textwrap.dedent(
    """\
    import ctypes
    from ctypes import wintypes
    import json
    from pathlib import Path
    import sys

    ctypes.windll.kernel32.SetErrorMode(0x8003)
    u32 = ctypes.WinDLL("user32", use_last_error=True)
    gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    if hasattr(u32, "SetProcessDpiAwarenessContext"):
        u32.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
        u32.SetProcessDpiAwarenessContext.restype = wintypes.BOOL
        u32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))

    state_file = Path(sys.argv[1])
    ready_file = Path(sys.argv[2])

    WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

    k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    k32.GetModuleHandleW.restype = wintypes.HMODULE
    gdi32.CreateSolidBrush.argtypes = [wintypes.COLORREF]
    gdi32.CreateSolidBrush.restype = wintypes.HBRUSH
    u32.FillRect.argtypes = [wintypes.HDC, ctypes.POINTER(wintypes.RECT), wintypes.HBRUSH]
    u32.FillRect.restype = ctypes.c_int
    u32.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    u32.GetClientRect.restype = wintypes.BOOL
    u32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    u32.DefWindowProcW.restype = ctypes.c_ssize_t
    u32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    u32.GetWindowTextLengthW.restype = ctypes.c_int
    u32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    u32.GetWindowTextW.restype = ctypes.c_int
    u32.GetKeyState.argtypes = [ctypes.c_int]
    u32.GetKeyState.restype = ctypes.c_short
    u32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    u32.ShowWindow.restype = wintypes.BOOL
    u32.UpdateWindow.argtypes = [wintypes.HWND]
    u32.UpdateWindow.restype = wintypes.BOOL
    u32.DestroyWindow.argtypes = [wintypes.HWND]
    u32.DestroyWindow.restype = wintypes.BOOL
    u32.PostQuitMessage.argtypes = [ctypes.c_int]
    u32.PostQuitMessage.restype = None
    u32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
    u32.GetMessageW.restype = wintypes.BOOL
    u32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
    u32.TranslateMessage.restype = wintypes.BOOL
    u32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
    u32.DispatchMessageW.restype = ctypes.c_ssize_t

    bg_brush = gdi32.CreateSolidBrush(0x00F4F1EC)

    state = {
        "hwnd": 0,
        "edit1_hwnd": 0,
        "edit2_hwnd": 0,
        "btn_hwnd": 0,
        "edit1_text": "box1_initial",
        "edit2_text": "",
        "btn_clicks": 0,
        "double_clicks": 0,
        "last_dblclk_xy": [0, 0],
        "right_clicks": 0,
        "last_rclick_xy": [0, 0],
        "wheel_events": 0,
        "wheel_delta_sum": 0,
        "ctrl_s_triggered": 0,
        "ctrl_down_seen": False,
        "wm_chars_main": [],
    }

    def read_text(hw: int) -> str:
        if not hw:
            return ""
        n = u32.GetWindowTextLengthW(wintypes.HWND(hw))
        buf = ctypes.create_unicode_buffer(n + 2)
        u32.GetWindowTextW(wintypes.HWND(hw), buf, n + 2)
        return str(buf.value or "")

    def flush_state() -> None:
        state["edit1_text"] = read_text(state["edit1_hwnd"])
        state["edit2_text"] = read_text(state["edit2_hwnd"])
        tmp = state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
        tmp.replace(state_file)

    def _xy_from_lp(lp: int):
        x = ctypes.c_short(lp & 0xFFFF).value
        y = ctypes.c_short((lp >> 16) & 0xFFFF).value
        return [int(x), int(y)]

    def py_wndproc(hwnd, msg, wp, lp):
        if msg in (0x0014, 0x0318):  # WM_ERASEBKGND / WM_PRINTCLIENT
            rc = wintypes.RECT()
            u32.GetClientRect(hwnd, ctypes.byref(rc))
            u32.FillRect(wintypes.HDC(wp), ctypes.byref(rc), bg_brush)
            return 1
        if msg == 0x0111:  # WM_COMMAND
            ctrl_id = int(wp) & 0xFFFF
            notif = (int(wp) >> 16) & 0xFFFF
            if ctrl_id == 103 and notif == 0:  # BN_CLICKED
                state["btn_clicks"] += 1
                flush_state()
                return 0
            if ctrl_id in (101, 102):
                flush_state()
        elif msg == 0x0203:  # WM_LBUTTONDBLCLK
            state["double_clicks"] += 1
            state["last_dblclk_xy"] = _xy_from_lp(int(lp))
            flush_state()
            return 0
        elif msg == 0x0205:  # WM_RBUTTONUP
            state["right_clicks"] += 1
            state["last_rclick_xy"] = _xy_from_lp(int(lp))
            flush_state()
            return 0
        elif msg == 0x020A:  # WM_MOUSEWHEEL
            delta = ctypes.c_short((int(wp) >> 16) & 0xFFFF).value
            state["wheel_events"] += 1
            state["wheel_delta_sum"] += int(delta)
            flush_state()
            return 0
        elif msg == 0x0100:  # WM_KEYDOWN
            vk = int(wp) & 0xFF
            if vk in (0x11, 0xA2, 0xA3):  # VK_CONTROL
                state["ctrl_down_seen"] = True
            elif vk == 0x53:  # 'S'
                ctrl_state_down = bool(u32.GetKeyState(0x11) & 0x8000)
                if ctrl_state_down or state["ctrl_down_seen"]:
                    state["ctrl_s_triggered"] += 1
                    flush_state()
                    return 0
        elif msg == 0x0101:  # WM_KEYUP
            vk = int(wp) & 0xFF
            if vk in (0x11, 0xA2, 0xA3):
                state["ctrl_down_seen"] = False
        elif msg == 0x0102:  # WM_CHAR
            state["wm_chars_main"].append(chr(int(wp) & 0xFFFF))
            flush_state()
        elif msg == 0x0010:  # WM_CLOSE
            u32.DestroyWindow(hwnd)
            return 0
        elif msg == 0x0002:  # WM_DESTROY
            u32.PostQuitMessage(0)
            return 0
        return u32.DefWindowProcW(hwnd, msg, wp, lp)

    wndproc_cb = WNDPROC(py_wndproc)

    class WNDCLASSEXW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.UINT),
            ("style", wintypes.UINT),
            ("lpfnWndProc", WNDPROC),
            ("cbClsExtra", ctypes.c_int),
            ("cbWndExtra", ctypes.c_int),
            ("hInstance", wintypes.HINSTANCE),
            ("hIcon", wintypes.HICON),
            ("hCursor", wintypes.HANDLE),
            ("hbrBackground", wintypes.HBRUSH),
            ("lpszMenuName", wintypes.LPCWSTR),
            ("lpszClassName", wintypes.LPCWSTR),
            ("hIconSm", wintypes.HICON),
        ]

    hinst = k32.GetModuleHandleW(None)
    cls_name = "CosmosS5OffscreenTestCls"
    wc = WNDCLASSEXW()
    wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
    wc.style = 0x0008  # CS_DBLCLKS so WM_LBUTTONDBLCLK is synthesized/accepted cleanly
    wc.lpfnWndProc = wndproc_cb
    wc.hInstance = hinst
    wc.hbrBackground = bg_brush
    wc.lpszClassName = cls_name
    u32.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
    u32.RegisterClassExW.restype = wintypes.ATOM
    u32.RegisterClassExW(ctypes.byref(wc))

    WS_POPUP = 0x80000000
    WS_CLIPCHILDREN = 0x02000000
    WS_VISIBLE = 0x10000000
    WS_CHILD = 0x40000000
    WS_BORDER = 0x00800000
    ES_AUTOHSCROLL = 0x0080
    WS_EX_NOACTIVATE = 0x08000000
    WS_EX_APPWINDOW = 0x00040000

    u32.CreateWindowExW.argtypes = [
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
    ]
    u32.CreateWindowExW.restype = wintypes.HWND

    hwnd = u32.CreateWindowExW(
        WS_EX_NOACTIVATE | WS_EX_APPWINDOW,
        cls_name,
        "Cosmos S5 Offscreen 1800x1000 Harness",
        WS_POPUP | WS_CLIPCHILDREN,
        -32000, -32000, 1800, 1000,
        None, None, hinst, None,
    )
    edit1 = u32.CreateWindowExW(
        0, "Edit", "box1_initial",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        40, 40, 360, 44,
        hwnd, wintypes.HMENU(101), hinst, None,
    )
    edit2 = u32.CreateWindowExW(
        0, "Edit", "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        1260, 400, 400, 48,
        hwnd, wintypes.HMENU(102), hinst, None,
    )
    btn = u32.CreateWindowExW(
        0, "Button", "Far Scale Button",
        WS_CHILD | WS_VISIBLE,
        1500, 720, 220, 60,
        hwnd, wintypes.HMENU(103), hinst, None,
    )

    state["hwnd"] = int(hwnd)
    state["edit1_hwnd"] = int(edit1)
    state["edit2_hwnd"] = int(edit2)
    state["btn_hwnd"] = int(btn)

    u32.ShowWindow(hwnd, 4)  # SW_SHOWNOACTIVATE
    u32.UpdateWindow(hwnd)
    flush_state()
    ready_file.write_text(str(int(hwnd)), encoding="utf-8")

    msg = wintypes.MSG()
    while u32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        u32.TranslateMessage(ctypes.byref(msg))
        u32.DispatchMessageW(ctypes.byref(msg))
    """
)


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 offscreen CUA test requires Windows")
def test_desktop_pack_1800x1000_scale_unscaling_second_edit_type_text_ctrl_s_and_mouse_actions(
    tmp_path: Path,
) -> None:
    ws_dir = tmp_path / "ws_cua"
    state_dir = tmp_path / "state_cua"
    ws_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)

    app_script = ws_dir / "offscreen_dual_edit_1800x1000.py"
    state_json = ws_dir / "win_state.json"
    ready_flag = ws_dir / "win_ready.txt"
    app_script.write_text(OFFSCREEN_WIN32_APP_CODE, encoding="utf-8")

    fg_initial, _, clip_initial = snapshot_l0_desktop_state()

    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    proc = subprocess.Popen(
        [sys.executable, "-B", str(app_script), str(state_json), str(ready_flag)],
        cwd=str(ws_dir),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        creationflags=CREATE_NO_WINDOW,
    )

    try:
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and not ready_flag.is_file():
            assert proc.poll() is None, f"Win32 helper exited early: {proc.stderr.read() if proc.stderr else b''!r}"
            time.sleep(0.05)
        assert ready_flag.is_file(), "Timed out waiting for offscreen 1800x1000 Win32 window"
        target_hwnd = int(ready_flag.read_text(encoding="utf-8").strip())
        assert target_hwnd > 0

        def read_win_state() -> Dict[str, Any]:
            return json.loads(state_json.read_text(encoding="utf-8"))

        guard = WorkspaceGuard(
            workspace_roots=ws_dir,
            state_root=state_dir,
            tier="tier3_workspace_dev",
            restrict_to_workspace=True,
        )
        pm = ProcessManager(state_root=state_dir)
        cua = CuaWindowPackPlugin(
            guard=guard,
            proc_manager=pm,
            state_root=state_dir,
            prefix="pc",
        )

        # 1. Capture 1800x1000 window -> compressed to 1440x800 (`scale_factor == 0.8`)
        cap_blocks = cua.cua_window(action="capture", hwnd=target_hwnd)
        assert isinstance(cap_blocks, list) and len(cap_blocks) >= 2
        cap_meta = json.loads(cap_blocks[0]["text"])
        assert cap_meta["ok"] is True, cap_meta
        assert cap_meta["captured_size"] == [1800, 1000]
        assert cap_meta["width"] == 1440
        assert cap_meta["height"] == 800
        assert abs(float(cap_meta["scale_factor"]) - 0.8) < 1e-3
        assert cap_meta["focus_unchanged"] is True

        # 2. Click button at real window [1500..1720, 720..780] using downscaled image coords (1288, 600) -> (1610, 750)
        # Note: (1288, 600) without unscaling would miss [1500..1720, 720..780] completely!
        clk_res = cua.cua_window(action="click", hwnd=target_hwnd, x=1288, y=600)
        assert clk_res["ok"] is True, clk_res
        assert clk_res["coord_space_used"] == "image"
        assert clk_res["window_xy"] == [1610, 750]
        assert clk_res["focus_unchanged"] is True

        time.sleep(0.08)
        st_after_clk = read_win_state()
        assert st_after_clk["btn_clicks"] == 1

        # Explicit `coord_space="client"` also works directly at (1610, 750)
        clk_client = cua.cua_window(action="click", hwnd=target_hwnd, x=1610, y=750, coord_space="client")
        assert clk_client["ok"] is True, clk_client
        assert clk_client["coord_space_used"] == "client"
        time.sleep(0.08)
        assert read_win_state()["btn_clicks"] == 2

        # 3. `type_text` at 2nd Edit box image coords (1168, 339) -> real (1460, 424) inside Edit2 [1260..1660, 400..448]
        # Must write ONLY into Edit2 and leave Edit1 == "box1_initial"!
        type_res = cua.cua_window(
            action="type_text",
            hwnd=target_hwnd,
            x=1168,
            y=339,
            value="precise_second_input_text",
        )
        assert type_res["ok"] is True, type_res
        assert type_res["focus_unchanged"] is True
        assert type_res["delta_clip"] == 0

        time.sleep(0.08)
        st_after_type = read_win_state()
        assert st_after_type["edit1_text"] == "box1_initial", "First Edit box must never be overwritten"
        assert st_after_type["edit2_text"] == "precise_second_input_text"

        # 4. `send_keys("ctrl+s")` must trigger Ctrl+S key chord and NEVER type literal "ctrl+s" into Edit boxes or WM_CHAR
        sk_res = cua.cua_window(action="send_keys", hwnd=target_hwnd, value="ctrl+s")
        assert sk_res["ok"] is True, sk_res
        assert sk_res["vk"] == 0x53
        assert "ctrl" in sk_res["modifiers"]
        assert sk_res["focus_unchanged"] is True

        time.sleep(0.08)
        st_after_sk = read_win_state()
        assert st_after_sk["ctrl_s_triggered"] >= 1
        # Win32 `TranslateMessage` translates genuine `VK_CONTROL + 'S'` WM_KEYDOWN into ASCII DC3 ('\x13'), never literal 'c','t','r','l','+','s'
        assert st_after_sk["wm_chars_main"] in ([], ["\x13"])
        assert "ctrl+s" not in "".join(st_after_sk["wm_chars_main"]).lower()
        assert st_after_sk["edit1_text"] == "box1_initial"
        assert st_after_sk["edit2_text"] == "precise_second_input_text"

        # 5. `double_click`, `right_click`, and `scroll` (`WM_MOUSEWHEEL`)
        dbl_res = cua.cua_window(action="double_click", hwnd=target_hwnd, x=400, y=240)
        assert dbl_res["ok"] is True, dbl_res
        assert dbl_res["window_xy"] == [500, 300]
        assert dbl_res["focus_unchanged"] is True

        rclk_res = cua.cua_window(action="right_click", hwnd=target_hwnd, x=480, y=280)
        assert rclk_res["ok"] is True, rclk_res
        assert rclk_res["window_xy"] == [600, 350]
        assert rclk_res["focus_unchanged"] is True

        scr_res = cua.cua_window(action="scroll", hwnd=target_hwnd, x=400, y=240, direction="down", clicks=3)
        assert scr_res["ok"] is True, scr_res
        assert scr_res["wheel_delta"] == -360
        assert scr_res["focus_unchanged"] is True

        time.sleep(0.1)
        st_final = read_win_state()
        assert st_final["double_clicks"] == 1
        assert st_final["last_dblclk_xy"] == [500, 300]
        assert st_final["right_clicks"] == 1
        assert st_final["last_rclick_xy"] == [600, 350]
        assert st_final["wheel_events"] == 1
        assert st_final["wheel_delta_sum"] == -360

        fg_end, _, clip_end = snapshot_l0_desktop_state()
        assert fg_end == fg_initial
        assert clip_end == clip_initial

        close_res = cua.cua_window(action="close_window", hwnd=target_hwnd)
        assert close_res["ok"] is True
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                proc.kill()
        if proc.stderr is not None:
            proc.stderr.close()


def test_public_docs_and_build_release_check_gate(tmp_path: Path) -> None:
    readme_txt = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    security_txt = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")
    doc01_txt = (REPO_ROOT / "docs" / "01_网页版Gemini与手机远程连接教程.md").read_text(encoding="utf-8")
    doc03_txt = (REPO_ROOT / "docs" / "03_Cosmos_Studio面板与扩展包指南.md").read_text(encoding="utf-8")
    skill_txt = (REPO_ROOT / "host_skills" / "SKILL.md").read_text(encoding="utf-8")

    assert "WebAI2PC" in readme_txt
    assert "Gemini" in readme_txt and "ChatGPT" in readme_txt
    assert "docs/README.md" in readme_txt and "docs/AI_SETUP_GUIDE.md" in readme_txt
    assert not (REPO_ROOT / "docs" / "02_桌面客户端一键接入教程.md").exists()
    for core_tool in DEFAULT_CORE_TOOLS:
        assert core_tool in skill_txt, f"host_skills/SKILL.md missing core tool `{core_tool}`"

    assert "https://datatracker.ietf.org/doc/html/rfc8707" in security_txt
    assert "/mcp/readonly" in security_txt
    assert "--tunnel-token" in doc01_txt
    assert "trycloudflare.com" in doc01_txt and "trycloudflare.com" in readme_txt
    assert "browser_use" in doc03_txt and "cua_window" in doc03_txt

    out_zip = tmp_path / "Cosmos-MCP-v1.2.1.zip"
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    proc = subprocess.run(
        [sys.executable, "-B", str(REPO_ROOT / "scripts" / "build_release.py"), "--output", str(out_zip), "--check"],
        cwd=str(REPO_ROOT),
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        creationflags=CREATE_NO_WINDOW,
    )
    assert proc.returncode == 0, f"build_release.py --check failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert "[CHECK PASSED]" in proc.stdout
    assert out_zip.is_file()

    with zipfile.ZipFile(out_zip, "r") as zf:
        names = set(zf.namelist())
        assert "pyproject.toml" in names
        assert "README.md" in names
        assert "SECURITY.md" in names
        assert "CHANGELOG.md" in names
        assert "host_skills/SKILL.md" in names
        assert "一键启动_Cosmos_MCP.bat" in names
        assert "start_cosmos_mcp.sh" in names
        assert not any("__pycache__" in n or n.startswith(("build/", "dist/", ".git/")) for n in names)
