"""Thin, layout-decoupled Studio test server & UI capability driver (`flexible-testing`).

Consolidates duplicated ephemeral server lifecycle (`LiveStudioServer`) and cross-test
headless Chromium/Edge navigation/actions (`StudioPageDriver`) with state-based polling
instead of fixed sleeps, while keeping one-off local assertions inside individual tests.
"""
from __future__ import annotations

import ctypes
import json
from pathlib import Path
import socket
import sys
import threading
import time
from typing import Any, Dict, Optional

import httpx
import uvicorn

if sys.platform == "win32":
    ctypes.windll.kernel32.SetErrorMode(0x8003)

from cosmos_mcp.launcher.app import create_standalone_app
from cosmos_mcp.packs.browser import _HeadlessCdpPage, find_system_chromium_binary


def find_free_port() -> int:
    """Return an available ephemeral TCP port on `127.0.0.1`."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class LiveStudioServer:
    """Run `create_standalone_app` on an ephemeral `127.0.0.1` port in a background thread."""

    def __init__(
        self,
        state_dir: Path,
        workspace_dir: Path,
        *,
        tunnel_mode: Optional[str] = None,
        thread_prefix: str = "studio-test",
    ) -> None:
        self.state_dir = state_dir
        self.workspace_dir = workspace_dir
        self.port = find_free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        app_kwargs: Dict[str, Any] = {
            "state_dir": str(state_dir),
            "host": "127.0.0.1",
            "port": self.port,
            "workspace": str(workspace_dir),
        }
        if tunnel_mode is not None:
            app_kwargs["tunnel_mode"] = tunnel_mode
        self.app = create_standalone_app(**app_kwargs)
        cfg = uvicorn.Config(
            self.app,
            host="127.0.0.1",
            port=self.port,
            log_level="error",
            access_log=False,
        )
        self.server = uvicorn.Server(cfg)
        self.server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
        self._thread = threading.Thread(
            target=self.server.run,
            name=f"{thread_prefix}-{self.port}",
            daemon=True,
        )

    def __enter__(self) -> "LiveStudioServer":
        self._thread.start()
        deadline = time.monotonic() + 12.0
        with httpx.Client(trust_env=False, timeout=2.5) as client:
            while time.monotonic() < deadline:
                try:
                    resp = client.get(f"{self.base_url}/healthz")
                    if resp.status_code == 200:
                        return self
                except Exception:
                    pass
                time.sleep(0.06)
        raise RuntimeError(f"Timed out waiting for temporary Studio server at {self.base_url}.")

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.server.should_exit = True
        self._thread.join(timeout=5.0)
        if hasattr(self.app.state, "watchdog"):
            self.app.state.watchdog.stop()
        if hasattr(self.app.state, "kill_watchdog"):
            self.app.state.kill_watchdog.stop()
        if hasattr(self.app.state, "dispatcher"):
            self.app.state.dispatcher.shutdown_packs(prefix_filter="pc")


class StudioPageDriver:
    """Thin headless CDP capability driver for Cosmos Studio UI tests.

    All waits use condition polling (`wait_until`) rather than fixed `wait_for_timeout`
    sleeps, and clipboard calls are intercepted in-page so the host OS clipboard is
    never modified.
    """

    def __init__(self, profile_dir: Path, browser_exe: Optional[str] = None) -> None:
        exe = browser_exe or find_system_chromium_binary()
        if not exe:
            raise RuntimeError("No local Chromium/Edge/Chrome binary found for headless Studio UI tests.")
        profile_dir.mkdir(parents=True, exist_ok=True)
        self.profile_dir = profile_dir
        self.browser_exe = exe
        self.cdp = _HeadlessCdpPage(
            profile_dir,
            exe,
            proxy_settings={"server": "", "bypass_semicolon": ""},
            url_validator=None,
        )

    def __enter__(self) -> "StudioPageDriver":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def close(self) -> None:
        self.cdp.close()

    def set_viewport(
        self,
        width: int,
        height: int,
        *,
        mobile: bool = False,
        device_scale_factor: int = 1,
    ) -> None:
        self.cdp._cdp_call(
            "Emulation.setDeviceMetricsOverride",
            {
                "width": width,
                "height": height,
                "deviceScaleFactor": device_scale_factor,
                "mobile": mobile,
            },
        )
        # On `about:blank` without a viewport meta tag, mobile emulation defaults innerWidth to 980px
        # until a responsive document is loaded; only wait for innerWidth match when applicable.
        self.wait_until(
            """(args) => {
                if (args.mobile && (location.href === 'about:blank' || !document.querySelector('meta[name="viewport"]'))) {
                    return true;
                }
                return Math.abs(window.innerWidth - args.w) <= 2;
            }""",
            arg={"w": width, "mobile": mobile},
            timeout_sec=3.0,
            description=f"viewport width == {width}",
        )

    def evaluate(self, js_expr: str, *args: Any) -> Any:
        return self.cdp.evaluate(js_expr, *args)

    def screenshot(self, *, full_page: bool = False) -> bytes:
        return self.cdp.screenshot(full_page=full_page)

    def wait_until(
        self,
        js_predicate: str,
        *,
        arg: Any = None,
        timeout_sec: float = 6.0,
        interval_sec: float = 0.05,
        description: str = "condition",
    ) -> Any:
        """Poll `js_predicate` until it returns a truthy value or raise TimeoutError."""
        deadline = time.monotonic() + timeout_sec
        last_val: Any = None
        while time.monotonic() < deadline:
            if arg is None:
                last_val = self.cdp.evaluate(js_predicate)
            else:
                last_val = self.cdp.evaluate(js_predicate, arg)
            if last_val:
                return last_val
            time.sleep(interval_sec)
        raise TimeoutError(f"StudioPageDriver.wait_until timed out ({timeout_sec}s) waiting for: {description} (last={last_val!r})")

    def install_runtime_probes(self) -> None:
        """Attach in-page JS error, console.error, and non-destructive clipboard probes."""
        self.cdp.evaluate(
            """() => {
                if (window.__studioProbesInstalled) return true;
                window.__studioProbesInstalled = true;
                window.__jsErrors = window.__jsErrors || [];
                window.__consoleErrors = window.__consoleErrors || [];
                window.__copiedHistory = window.__copiedHistory || [];
                window.addEventListener('error', (e) => {
                    window.__jsErrors.push(String((e && (e.message || e.error)) || e));
                });
                window.addEventListener('unhandledrejection', (e) => {
                    window.__jsErrors.push(String((e && e.reason) || e));
                });
                const origConsoleErr = console.error.bind(console);
                console.error = (...args) => {
                    window.__consoleErrors.push(args.map(a => String(a)).join(' '));
                    return origConsoleErr(...args);
                };
                try {
                    Object.defineProperty(navigator, 'clipboard', {
                        configurable: true,
                        value: {
                            writeText: async (txt) => {
                                window.__copiedHistory.push(String(txt));
                            },
                            readText: async () => '',
                        },
                    });
                } catch (_) {}
                return true;
            }"""
        )

    def goto(self, url: str, *, wait_studio_ready: bool = True) -> None:
        self.cdp.goto(url)
        self.wait_until(
            "() => document.readyState === 'complete'",
            timeout_sec=8.0,
            description="document.readyState === 'complete'",
        )
        self.install_runtime_probes()
        if wait_studio_ready:
            self.wait_until(
                """() => {
                    const badge = document.getElementById('service-status-badge');
                    const boot = document.getElementById('studio-boot-data');
                    return Boolean(badge && boot && document.body && document.body.innerText.trim().length > 0);
                }""",
                timeout_sec=8.0,
                description="Studio initial DOM hydration",
            )

    def trigger_poll(self) -> None:
        self.cdp.evaluate("() => { window.dispatchEvent(new Event('focus')); }")

    def get_runtime_diagnostics(self) -> Dict[str, Any]:
        return self.cdp.evaluate(
            """() => ({
                jsErrors: (window.__jsErrors || []).slice(),
                consoleErrors: (window.__consoleErrors || []).slice(),
                copiedHistory: (window.__copiedHistory || []).slice(),
            })"""
        )

    # ------------------------------------------------------------------
    # Cross-test Reusable Business Actions
    # ------------------------------------------------------------------

    def open_settings(self, category: str = "gateways") -> None:
        self.cdp.evaluate(
            """(cat) => {
                const sv = document.getElementById('settings-view');
                if (!sv || !sv.classList.contains('active')) {
                    const openBtn = document.getElementById('open-settings-btn');
                    if (openBtn) openBtn.click();
                    else if (window.__cosmosStudioNav) window.__cosmosStudioNav.openSettings(cat);
                }
                const navBtn = document.querySelector(`.settings-nav-btn[data-settings-cat="${cat}"]`);
                if (navBtn) navBtn.click();
            }""",
            category,
        )
        self.wait_until(
            """(cat) => {
                const sv = document.getElementById('settings-view');
                const pane = document.getElementById('settings-pane-' + cat);
                return Boolean(sv && sv.classList.contains('active') && pane && pane.classList.contains('active'));
            }""",
            arg=category,
            timeout_sec=5.0,
            description=f"settings pane '{category}' active",
        )

    def close_settings(self) -> None:
        self.cdp.evaluate(
            """() => {
                const sv = document.getElementById('settings-view');
                if (sv && sv.classList.contains('active')) {
                    const closeBtn = document.getElementById('close-settings-btn');
                    if (closeBtn) closeBtn.click();
                    else if (window.__cosmosStudioNav) window.__cosmosStudioNav.closeSettings();
                }
            }"""
        )
        self.wait_until(
            """() => {
                const wb = document.getElementById('workbench-view');
                return Boolean(wb && wb.classList.contains('active'));
            }""",
            timeout_sec=5.0,
            description="workbench view active",
        )

    def unlock_session(self, password: str) -> None:
        self.cdp.evaluate(
            """(pw) => {
                const inp = document.getElementById('session-pw-input');
                const form = document.getElementById('session-unlock-form');
                if (inp) inp.value = pw;
                if (form) form.dispatchEvent(new Event('submit', { cancelable: true }));
            }""",
            password,
        )
        self.wait_until(
            "() => Boolean(document.getElementById('session-unlock-bar')?.classList.contains('unlocked'))",
            timeout_sec=6.0,
            description="session unlocked",
        )

    def toggle_gateway(self, gw_id: str, *, enabled: Optional[bool] = None) -> Dict[str, Any]:
        self.open_settings("gateways")
        current = self.cdp.evaluate(
            """(gid) => {
                const sw = document.querySelector(`[data-gw-switch="${gid}"]`);
                return sw ? { checked: Boolean(sw.checked), disabled: Boolean(sw.disabled) } : null;
            }""",
            gw_id,
        )
        if current is None:
            raise RuntimeError(f"Gateway switch not found for gateway_id={gw_id!r}")
        target = (not current["checked"]) if enabled is None else bool(enabled)
        if current["checked"] != target:
            self.cdp.evaluate(
                """(gid) => {
                    const sw = document.querySelector(`[data-gw-switch="${gid}"]`);
                    if (sw) sw.click();
                }""",
                gw_id,
            )
            self.wait_until(
                """(args) => {
                    const sw = document.querySelector(`[data-gw-switch="${args.gid}"]`);
                    const pill = document.getElementById('gw-pill-' + args.gid);
                    if (!sw || sw.disabled) return false;
                    if (Boolean(sw.checked) !== args.target) return false;
                    if (!args.target) return pill && pill.textContent.trim() === '未开启';
                    return Boolean(pill && pill.textContent.trim() !== '未开启');
                }""",
                arg={"gid": gw_id, "target": target},
                timeout_sec=6.0,
                description=f"gateway '{gw_id}' toggled to {target}",
            )
        return self.cdp.evaluate(
            """(gid) => {
                const sw = document.querySelector(`[data-gw-switch="${gid}"]`);
                const pill = document.getElementById('gw-pill-' + gid);
                return {
                    checked: Boolean(sw && sw.checked),
                    pillText: pill ? pill.textContent.trim() : '',
                };
            }""",
            gw_id,
        )

    def add_workspace(self, path: str | Path, *, readonly: bool = False) -> Dict[str, Any]:
        self.close_settings()
        path_str = str(path)
        name_token = Path(path_str).name
        self.cdp.evaluate(
            """(args) => {
                const chk = document.getElementById('chk-add-ws-readonly');
                if (chk) chk.checked = Boolean(args.readonly);
                const inp = document.getElementById('manual-ws-input');
                if (inp) inp.value = args.path;
                const btn = document.getElementById('add-manual-ws-btn');
                if (btn) btn.click();
            }""",
            {"path": path_str, "readonly": readonly},
        )
        return self.wait_until(
            """(nameTok) => {
                const listEl = document.getElementById('workspace-roots-list');
                if (!listEl) return false;
                const rows = Array.from(listEl.querySelectorAll('.ws-row'));
                const matched = rows.find(r => (r.textContent || '').includes(nameTok));
                if (!matched) return false;
                const tag = matched.querySelector('.ws-path .tag');
                const chk = document.getElementById('chk-add-ws-readonly');
                return {
                    ok: true,
                    badgeText: tag ? tag.textContent.trim() : '',
                    readonlyChkReset: chk ? !chk.checked : true,
                    permSelectCount: document.querySelectorAll('.ws-perm-select').length,
                };
            }""",
            arg=name_token,
            timeout_sec=6.0,
            description=f"workspace '{name_token}' added to list",
        )

    def set_safety_mode(self, mode: str) -> Dict[str, Any]:
        self.close_settings()
        self.cdp.evaluate(
            """(m) => {
                const btn = document.querySelector(`[data-target-safety="${m}"]`);
                if (btn) btn.click();
            }""",
            mode,
        )
        return self.wait_until(
            """(m) => {
                const card = document.querySelector(`#safety-mode-cards .safety-card[data-safety="${m}"]`);
                if (!card || !card.classList.contains('active')) return false;
                const badge = document.getElementById('service-status-badge');
                const dot = document.getElementById('service-status-dot');
                const txt = document.getElementById('service-status-text');
                const banner = document.getElementById('workspace-fullpower-banner');
                return {
                    mode: m,
                    badgeClass: badge ? badge.className : '',
                    dotClass: dot ? dot.className : '',
                    statusText: txt ? txt.textContent.trim() : '',
                    fullpowerBannerVisible: banner ? getComputedStyle(banner).display !== 'none' : false,
                };
            }""",
            arg=mode,
            timeout_sec=6.0,
            description=f"safety mode '{mode}' active",
        )

    def select_host_scene(self, scene: str) -> None:
        self.close_settings()
        self.cdp.evaluate(
            """(sc) => {
                const btn = document.querySelector(`.host-seg-btn[data-host-scene="${sc}"]`);
                if (btn) btn.click();
            }""",
            scene,
        )
        self.wait_until(
            """(sc) => {
                const panel = document.getElementById('host-panel-' + sc);
                return Boolean(panel && panel.classList.contains('active'));
            }""",
            arg=scene,
            timeout_sec=4.0,
            description=f"host scene '{scene}' active",
        )

    def set_appearance(self, *, style_pack: Optional[str] = None, theme: Optional[str] = None) -> Dict[str, str]:
        self.cdp.evaluate(
            """(args) => {
                if (args.style_pack) {
                    const btn = document.querySelector(`[data-w2p-style="${args.style_pack}"]`);
                    if (btn) btn.click();
                    else if (window.WebAI2PCBrand && typeof window.WebAI2PCBrand.setStylePack === 'function') {
                        window.WebAI2PCBrand.setStylePack(args.style_pack);
                    } else {
                        document.documentElement.setAttribute('data-style-pack', args.style_pack);
                    }
                }
                if (args.theme) {
                    const btn = document.querySelector(`[data-w2p-theme="${args.theme}"]`);
                    if (btn) btn.click();
                    else if (window.WebAI2PCBrand && typeof window.WebAI2PCBrand.setTheme === 'function') {
                        window.WebAI2PCBrand.setTheme(args.theme);
                    } else {
                        document.documentElement.setAttribute('data-theme', args.theme);
                    }
                }
            }""",
            {"style_pack": style_pack, "theme": theme},
        )
        return self.wait_until(
            """(args) => {
                const curPack = document.documentElement.getAttribute('data-style-pack') || '';
                const curTheme = document.documentElement.getAttribute('data-theme') || '';
                if (args.style_pack && curPack !== args.style_pack) return false;
                if (args.theme && curTheme !== args.theme) return false;
                return { style_pack: curPack, theme: curTheme };
            }""",
            arg={"style_pack": style_pack, "theme": theme},
            timeout_sec=3.0,
            description=f"appearance pack={style_pack} theme={theme}",
        )
