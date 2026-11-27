"""Opt-in peripheral capability packs (`browser`, `desktop` / `cua`)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, Optional, Union

from cosmos_mcp.core.contracts import PackPlugin, SafetyBand, ToolSpec
from cosmos_mcp.core.guard import WorkspaceGuard
from cosmos_mcp.core.proc import ProcessManager

from .browser import (
    BROWSER_USE_ACTIONS,
    BROWSER_USE_INPUT_SCHEMA,
    BrowserPackPlugin,
    close_all_browser_sessions,
    find_system_chromium_binary,
    resolve_browser_proxy_settings,
    validate_outbound_http_url,
)
from .desktop import (
    CUA_MUTATING_ACTIONS,
    CUA_WINDOW_ACTIONS,
    CUA_WINDOW_INPUT_SCHEMA,
    DEFAULT_HUMAN_IDLE_THRESHOLD_MS,
    ERR_HUMAN_ACTIVE_YIELD,
    ERR_L3_WINDOW_SCOPE_BLOCKED,
    ERR_SCREEN_LOCKED_OR_BLACK_FRAME,
    ERR_UNSAVED_DOCUMENT_PROTECTED,
    CuaWindowPackPlugin,
    build_mcp_image_blocks,
    check_locked_or_black_rgb_frame,
    collect_mcp_session_seed_pids,
    compress_capture_bytes,
    detect_input_desktop_name_win32,
    draw_coordinate_grid_rgb,
    encode_rgb_png_stdlib,
    get_physical_idle_ms,
    has_unsaved_title_marker,
    is_hwnd_responsive_win32,
    save_optional_capture,
    snapshot_l0_desktop_state,
)


def build_default_device_packs(
    *,
    guard: Optional[WorkspaceGuard] = None,
    proc_manager: Optional[ProcessManager] = None,
    policy: Optional[Any] = None,
    state_root: Optional[Union[str, Path]] = None,
    prefix: str = "",
    mcp_port: Union[int, Callable[[], int]] = 0,
    mcp_public_url: Union[str, Callable[[], str]] = "",
) -> Dict[str, PackPlugin]:
    browser_plugin = BrowserPackPlugin(
        guard=guard,
        proc_manager=proc_manager,
        policy=policy,
        state_root=state_root,
        prefix=prefix,
        mcp_port=mcp_port,
        mcp_public_url=mcp_public_url,
    )
    desktop_plugin = CuaWindowPackPlugin(
        guard=guard,
        proc_manager=proc_manager,
        policy=policy,
        state_root=state_root,
        prefix=prefix,
    )
    return {
        "browser": browser_plugin,
        "desktop": desktop_plugin,
        "cua": desktop_plugin,
    }


__all__ = [
    "BROWSER_USE_ACTIONS",
    "BROWSER_USE_INPUT_SCHEMA",
    "BrowserPackPlugin",
    "CUA_MUTATING_ACTIONS",
    "CUA_WINDOW_ACTIONS",
    "CUA_WINDOW_INPUT_SCHEMA",
    "CuaWindowPackPlugin",
    "build_default_device_packs",
    "close_all_browser_sessions",
]
