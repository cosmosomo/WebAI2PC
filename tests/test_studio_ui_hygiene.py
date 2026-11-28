"""Layout-decoupled universal Studio Web UI hygiene patrol (`flexible-testing`).

Verifies invariant quality baselines independent of tab counts, card counts, exact
Chinese copy, or pixel coordinates:
1. Zero horizontal overflow across target viewports (`1440x900`, `1280x720`, `390x844`),
   explicitly excluding containers that declare horizontal scrolling (`.table-scroll`,
   `pre`, `code`, `.log-viewer`, `.mono-value`, or `overflow-x: auto|scroll`).
2. Zero uncaught JavaScript runtime errors and zero `console.error` emissions across
   Workbench, Settings categories, and `/consent`.
3. Readable WCAG contrast (`>= 4.5:1`) across all supported style packs
   (`warm-paper`, `obsidian-emerald`, `cupertino-frost`, `graphite-mono`) in both
   `light` and `dark` themes on Studio and `/consent`.
4. Visible text free of internal debug jargon, unreplaced template placeholders, and
   sensitive local paths.
5. Zero unintended OS clipboard writes during page load, navigation, and theme switches.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple

import httpx

from cosmos_mcp.core.fs_tx import atomic_write_json
from _studio_driver import LiveStudioServer, StudioPageDriver

STYLE_PACKS: Tuple[str, ...] = (
    "warm-paper",
    "obsidian-emerald",
    "cupertino-frost",
    "graphite-mono",
)
THEMES: Tuple[str, ...] = ("light", "dark")

TARGET_VIEWPORTS: Tuple[Tuple[int, int, bool, int], ...] = (
    (1440, 900, False, 1),
    (1280, 720, False, 1),
    (390, 844, True, 2),
)

FORBIDDEN_VISIBLE_TOKENS: Tuple[str, ...] = (
    "tier1_readonly",
    "tier2_workspace_edit",
    "tier3_workspace_dev",
    "tier4_full_power",
    "T5_champion_12",
    "toolset_profile",
    "cua_window",
    "annotation_mode",
    "workspace_roots",
    "tailscale",
    "web" + "-taint",
    "web" + "_taint",
    "data-ip-pack",
    "[at]Cosmos",
    "__STUDIO_BOOT_JSON__",
    "__DEVICE_LABEL__",
    "__STATUS_TEXT__",
    "secrets/auth.json",
    "oauth.sqlite3",
)

_CONTRAST_HELPER_JS = """
function parseRgb(str) {
    const m = String(str || '').match(/rgba?\\(\\s*(\\d+)\\s*,\\s*(\\d+)\\s*,\\s*(\\d+)(?:\\s*,\\s*([0-9.]+))?\\s*\\)/i);
    if (!m) return null;
    const a = m[4] === undefined ? 1 : Number(m[4]);
    return { r: Number(m[1]), g: Number(m[2]), b: Number(m[3]), a };
}
function effectiveBg(el) {
    let cur = el;
    while (cur && cur.nodeType === 1) {
        const bg = parseRgb(getComputedStyle(cur).backgroundColor);
        if (bg && bg.a > 0.05) return bg;
        cur = cur.parentElement;
    }
    return { r: 255, g: 255, b: 255, a: 1 };
}
function relLum(rgb) {
    const c = [rgb.r, rgb.g, rgb.b].map(v => {
        v /= 255;
        return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    });
    return c[0] * 0.2126 + c[1] * 0.7152 + c[2] * 0.0722;
}
function contrastRatio(fg, bg) {
    const l1 = relLum(fg);
    const l2 = relLum(bg);
    return Number(((Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05)).toFixed(2));
}
"""


def _check_overflow_and_jargon(driver: StudioPageDriver, *, context_label: str) -> None:
    snap = driver.evaluate(
        """() => {
            const iw = window.innerWidth;
            const sw = document.documentElement.scrollWidth;
            const offenders = [];
            const isAllowedScrollable = (el) => {
                let cur = el;
                while (cur && cur.nodeType === 1 && cur !== document.body && cur !== document.documentElement) {
                    const cs = getComputedStyle(cur);
                    const ox = (cs.overflowX || '').toLowerCase();
                    if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
                    if (cur.matches('.table-scroll, pre, code, .log-viewer, .mono-value')) return true;
                    cur = cur.parentElement;
                }
                return false;
            };
            for (const el of document.querySelectorAll('section, button, input, a, .card')) {
                const cs = getComputedStyle(el);
                if (cs.display === 'none' || cs.visibility === 'hidden') continue;
                const rect = el.getBoundingClientRect();
                if (rect.width <= 0 || rect.height <= 0) continue;
                if (rect.right > iw + 3 && !isAllowedScrollable(el)) {
                    offenders.push({
                        tag: el.tagName,
                        id: el.id || '',
                        cls: String(el.className || '').slice(0, 60),
                        right: Math.round(rect.right),
                        iw,
                    });
                    if (offenders.length >= 5) break;
                }
            }
            return {
                innerWidth: iw,
                scrollWidth: sw,
                offenders,
                visibleText: document.body ? document.body.innerText : '',
            };
        }"""
    )
    assert snap["scrollWidth"] <= snap["innerWidth"] + 2, (
        f"Horizontal overflow in {context_label}: scrollWidth={snap['scrollWidth']} > innerWidth={snap['innerWidth']}"
    )
    assert snap["offenders"] == [], f"Overflowing elements in {context_label}: {snap['offenders']}"

    vis_low = str(snap["visibleText"]).lower()
    for bad_tok in FORBIDDEN_VISIBLE_TOKENS:
        assert bad_tok.lower() not in vis_low, f"Forbidden internal/sensitive token `{bad_tok}` visible in {context_label}"


def test_studio_ui_hygiene_viewports_errors_jargon_and_clipboard(tmp_path: Path) -> None:
    """Patrol Workbench and Settings across desktop/laptop/mobile viewports for overflow, JS errors, jargon, and clipboard silence."""
    st_dir = tmp_path / "hygiene_state"
    ws_dir = tmp_path / "hygiene_ws"
    ws_dir.mkdir(parents=True)

    with LiveStudioServer(st_dir, ws_dir, tunnel_mode="public_gateway", thread_prefix="hygiene-studio") as srv:
        atomic_write_json(
            st_dir / "state" / "daemon_status.json",
            {
                "status": "running",
                "supervisor_pid": 90001,
                "port": srv.port,
                "mode": "public_gateway",
                "effective_tunnel_mode": "srv_us",
                "public_url": "https://hygiene-demo.srv.us",
                "tunnel_ready": True,
                "srvus_fixed_active": True,
                "gateways": {
                    "instant": {
                        "enabled": True,
                        "submode": "public_gateway",
                        "effective_mode": "srv_us",
                        "phase": "ready",
                        "tunnel_ready": True,
                        "public_url": "https://hygiene-demo.srv.us",
                        "srvus_fixed_active": True,
                        "last_error": "",
                    }
                },
            },
        )

        with StudioPageDriver(tmp_path / "cdp_hygiene_vp") as driver:
            driver.set_viewport(1440, 900, mobile=False, device_scale_factor=1)
            driver.goto(f"{srv.base_url}/")

            # Discover available settings categories dynamically rather than hardcoding count
            settings_cats: List[str] = driver.evaluate(
                """() => Array.from(document.querySelectorAll('.settings-nav-btn[data-settings-cat]'))
                    .map(el => el.getAttribute('data-settings-cat'))
                    .filter(Boolean)"""
            )
            assert len(settings_cats) >= 1

            for vw, vh, is_mob, dpr in TARGET_VIEWPORTS:
                driver.set_viewport(vw, vh, mobile=is_mob, device_scale_factor=dpr)
                driver.close_settings()
                _check_overflow_and_jargon(driver, context_label=f"workbench@{vw}x{vh}")

                for cat in settings_cats:
                    driver.open_settings(cat)
                    _check_overflow_and_jargon(driver, context_label=f"settings:{cat}@{vw}x{vh}")

                # Ensure appearance panel does not expose internal promo copy button in normal mode
                has_promo_btn = driver.evaluate("() => Boolean(document.querySelector('[data-w2p-copy-promo=\"1\"]'))")
                assert has_promo_btn is False

            diag = driver.get_runtime_diagnostics()
            assert diag["jsErrors"] == [], f"Uncaught JS errors during UI hygiene patrol: {diag['jsErrors']}"
            assert diag["consoleErrors"] == [], f"Console errors during UI hygiene patrol: {diag['consoleErrors']}"
            assert diag["copiedHistory"] == [], f"Unexpected clipboard writes during passive UI patrol: {diag['copiedHistory']}"


def test_studio_and_consent_contrast_across_all_style_packs_and_themes(tmp_path: Path) -> None:
    """Verify WCAG AA (>=4.5:1) contrast for primary actions and body text across all 4 style packs x light/dark on Studio and /consent."""
    st_dir = tmp_path / "contrast_state"
    ws_dir = tmp_path / "contrast_ws"
    ws_dir.mkdir(parents=True)

    with LiveStudioServer(st_dir, ws_dir, tunnel_mode="public_gateway", thread_prefix="hygiene-contrast") as srv:
        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=8.0) as http:
            reg = http.post(
                "/register",
                json={
                    "client_name": "HygieneContrastClient",
                    "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                },
            )
            assert reg.status_code in (200, 201)
            cid = reg.json()["client_id"]
            auth_r = http.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": cid,
                    "redirect_uri": "https://chatgpt.com/connector_platform_oauth_redirect",
                    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    "code_challenge_method": "S256",
                    "state": "hygiene_contrast_state",
                },
                follow_redirects=True,
            )
            assert auth_r.status_code == 200
            consent_url = str(auth_r.url)

        with StudioPageDriver(tmp_path / "cdp_hygiene_contrast") as driver:
            driver.set_viewport(1280, 720, mobile=False, device_scale_factor=1)
            driver.goto(f"{srv.base_url}/")

            # Disable CSS transitions during theme sweep so computed colors reflect final state immediately
            driver.evaluate(
                """() => {
                    const st = document.createElement('style');
                    st.id = '__hygiene-no-trans';
                    st.textContent = 'html body *, html .btn, button, a, input, *::before, *::after { transition: none !important; transition-duration: 0s !important; animation: none !important; } #first-wake-banner { display: block !important; } #wb-conn-drawer { display: block !important; }';
                    document.head.appendChild(st);
                    void document.body.offsetHeight;
                }"""
            )

            studio_ratios: Dict[str, Dict[str, float]] = {}
            for pack in STYLE_PACKS:
                for theme in THEMES:
                    driver.set_appearance(style_pack=pack, theme=theme)
                    ratios = driver.evaluate(
                        f"""() => {{
                            {_CONTRAST_HELPER_JS}
                            const wb = document.getElementById('first-wake-banner');
                            if (wb) wb.style.display = 'block';
                            void document.body.offsetHeight;
                            const out = {{}};
                            for (const [k, sel] of [
                                ['wake_btn', '#copy-wake-prompt-btn'],
                                ['copy_mcp_btn', '#copy-mcp-url-btn'],
                                ['body_text', 'body'],
                                ['card_title', '#wb-workspace-card .card-title'],
                            ]) {{
                                const el = document.querySelector(sel);
                                if (!el) continue;
                                el.style.transition = 'none';
                                void el.offsetHeight;
                                const fg = parseRgb(getComputedStyle(el).color);
                                const bg = effectiveBg(el);
                                if (fg && bg) out[k] = contrastRatio(fg, bg);
                            }}
                            return out;
                        }}"""
                    )
                    studio_ratios[f"{pack}:{theme}"] = ratios
                    for elem_key, cr in ratios.items():
                        assert cr >= 4.5, f"Studio contrast failure on {pack}:{theme} [{elem_key}] = {cr} < 4.5"

            diag_studio = driver.get_runtime_diagnostics()
            assert diag_studio["jsErrors"] == []
            assert diag_studio["consoleErrors"] == []
            assert diag_studio["copiedHistory"] == []

            # Measure /consent page across all 8 style pack x theme combinations + mobile viewport hygiene
            driver.goto(consent_url, wait_studio_ready=False)
            driver.evaluate(
                """() => {
                    const hero = document.getElementById('local-bridge-hero');
                    if (hero) hero.style.display = 'block';
                    const btn = document.getElementById('local-bridge-approve-btn');
                    if (btn) btn.style.transition = 'none';
                }"""
            )
            for pack in STYLE_PACKS:
                for theme in THEMES:
                    driver.set_appearance(style_pack=pack, theme=theme)
                    cr_val = driver.evaluate(
                        f"""() => {{
                            {_CONTRAST_HELPER_JS}
                            const btn = document.getElementById('local-bridge-approve-btn');
                            const fg = parseRgb(getComputedStyle(btn).color);
                            const bg = effectiveBg(btn);
                            return contrastRatio(fg, bg);
                        }}"""
                    )
                    assert cr_val >= 4.5, f"/consent #local-bridge-approve-btn contrast {cr_val} < 4.5 on {pack}:{theme}"

            driver.set_viewport(390, 844, mobile=True, device_scale_factor=2)
            _check_overflow_and_jargon(driver, context_label="consent@390x844")
            diag_consent = driver.get_runtime_diagnostics()
            assert diag_consent["jsErrors"] == []
            assert diag_consent["consoleErrors"] == []
            assert diag_consent["copiedHistory"] == []
