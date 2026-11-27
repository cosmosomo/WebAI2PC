"""Multi-Gateway Studio API, security baseline, and thin-driver UI tests (`flexible-testing`).

Structured into two decoupled layers:
1. A-class browserless API & protocol/security tests:
   - Independent multi-gateway toggles (`instant`, `workers_dev`, `self_hosted`) and tokenless re-enable.
   - Anti-flush top URL stability & verbatim Chinese `last_error` passthrough + dual-ready switching.
   - Local Bearer CSRF exemption vs missing-CSRF 403 vs forged `X-Forwarded-For` 403 on `/api/studio/identity/export_png`.
   - Unextracted ZIP preview guard (`一键启动_Cosmos_MCP.bat`) & CLI subcommand passthrough.
   - Consent template anti-phishing vs dynamic code invariants, deterministic `_get_local_fast_secret`,
     `build_release.py` email scanner, dynamic session scope badges, readonly workspace API, and VPS SSH key provision.
2. B-class thin-driver UI tests (`StudioPageDriver`):
   - Multi-gateway Card 2 deploy anti-flush, dual-ready copy/switcher, tokenless toggle, and readonly workspace add.
   - Connection card accordion draft survival across poll refresh, switch `stopPropagation`, style/theme & ChatGPT copy.
   - Synchronous `window.open` on `workers_dev` Gemini connect + async proxy alert banner.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List

import httpx
import pytest

from _studio_driver import LiveStudioServer, StudioPageDriver
from cosmos_mcp.core.fs_tx import atomic_write_json
import cosmos_mcp.studio.routes as studio_routes

REPO_ROOT = Path(__file__).resolve().parents[1]
WAKE_TOKEN = "\x40Cosmos"
BRACKET_AT_TOKEN = "[at]Cosmos"
CREATE_NO_WINDOW = 0x08000000


# ==============================================================================
# 1. A-Class Browserless API, Security & Protocol Baseline Tests
# ==============================================================================


def test_multigw_three_cards_independent_toggle_and_tokenless_workers_switch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "state_toggle"
    ws_dir = tmp_path / "ws_toggle"
    ws_dir.mkdir(parents=True)

    def _fake_cf_deploy(**kwargs: Any) -> Dict[str, Any]:
        assert kwargs.get("api_token") == "cf_tok_once_123"
        return {
            "ok": True,
            "public_url": "https://cosmos-mcp-w7c.demo-sub.workers.dev",
            "workers_dev_url": "https://cosmos-mcp-w7c.demo-sub.workers.dev",
            "account_id": "acc_demo_001",
            "subdomain": "demo-sub",
            "script_name": "cosmos-mcp-w7c",
            "custom_domain": "",
            "api_token_shredded": True,
        }

    monkeypatch.setattr(studio_routes, "deploy_cloudflare_workers_gateway", _fake_cf_deploy)

    with LiveStudioServer(state_dir, ws_dir, tunnel_mode="public_gateway", thread_prefix="multigw-toggle") as srv:
        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=5.0) as client:
            st0 = client.get("/api/studio/state").json()
            csrf = st0["csrf_token"]
            hdrs = {"X-Studio-Csrf": csrf}

            assert st0["gateways"]["instant"]["enabled"] is True
            assert st0["gateways"]["workers_dev"]["enabled"] is False
            assert st0["gateways"]["self_hosted"]["enabled"] is False

            # Deploy Card 2 (`workers_dev`) -> Card 1 (`instant`) MUST remain enabled
            r_cf = client.post(
                "/api/studio/gateway/cloudflare/deploy",
                headers=hdrs,
                json={"api_token": "cf_tok_once_123"},
            )
            assert r_cf.status_code == 200
            d_cf = r_cf.json()
            assert d_cf["gateways"]["instant"]["enabled"] is True
            assert d_cf["gateways"]["workers_dev"]["enabled"] is True
            assert d_cf["gateways"]["self_hosted"]["enabled"] is False
            assert d_cf["connection"]["workers_dev_url"] == "https://cosmos-mcp-w7c.demo-sub.workers.dev"

            # Save & enable Card 3 (`self_hosted` custom HTTPS domain) -> Card 1 & Card 2 MUST remain enabled
            r_sh = client.post(
                "/api/studio/connection",
                headers=hdrs,
                json={
                    "action": "save_gateway_config",
                    "gateway_id": "self_hosted",
                    "submode": "custom",
                    "enabled": True,
                    "public_url": "https://mcp.my-own-box.example.com",
                },
            )
            assert r_sh.status_code == 200
            d_sh = r_sh.json()
            assert d_sh["enabled_gateway_ids"] == ["instant", "workers_dev", "self_hosted"]
            assert d_sh["gateways"]["instant"]["enabled"] is True
            assert d_sh["gateways"]["workers_dev"]["enabled"] is True
            assert d_sh["gateways"]["self_hosted"]["enabled"] is True
            assert d_sh["gateways"]["self_hosted"]["configured_url"] == "https://mcp.my-own-box.example.com"
            assert d_sh["gateways"]["self_hosted"]["status"] == "unknown"
            assert d_sh["gateways"]["self_hosted"]["mcp_url"] == ""

            # Toggle Card 2 OFF -> Card 1 and Card 3 remain ON
            r_off2 = client.post(
                "/api/studio/connection",
                headers=hdrs,
                json={"action": "toggle_gateway", "gateway_id": "workers_dev", "enabled": False},
            )
            assert r_off2.status_code == 200
            d_off2 = r_off2.json()
            assert d_off2["gateways"]["instant"]["enabled"] is True
            assert d_off2["gateways"]["workers_dev"]["enabled"] is False
            assert d_off2["gateways"]["workers_dev"]["status"] == "disabled"
            assert d_off2["gateways"]["self_hosted"]["enabled"] is True

            # Toggle Card 2 back ON WITHOUT any API Token -> succeeds immediately via saved `workers_dev_url`
            r_on2 = client.post(
                "/api/studio/connection",
                headers=hdrs,
                json={"action": "toggle_gateway", "gateway_id": "workers_dev", "enabled": True},
            )
            assert r_on2.status_code == 200
            d_on2 = r_on2.json()
            assert d_on2["gateways"]["workers_dev"]["enabled"] is True
            assert d_on2["gateways"]["workers_dev"]["configured_url"] == "https://cosmos-mcp-w7c.demo-sub.workers.dev"
            assert d_on2["gateways"]["instant"]["enabled"] is True
            assert d_on2["gateways"]["self_hosted"]["enabled"] is True

            # Toggle Card 1 OFF -> Card 2 and Card 3 stay ON
            r_off1 = client.post(
                "/api/studio/connection",
                headers=hdrs,
                json={"action": "toggle_gateway", "gateway_id": "instant", "enabled": False},
            )
            assert r_off1.status_code == 200
            d_off1 = r_off1.json()
            assert d_off1["gateways"]["instant"]["enabled"] is False
            assert d_off1["gateways"]["workers_dev"]["enabled"] is True
            assert d_off1["gateways"]["self_hosted"]["enabled"] is True


def test_multigw_card1_ready_deploy_card2_chinese_error_antiflush_and_dual_ready_switch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "state_antiflush"
    ws_dir = tmp_path / "ws_antiflush"
    ws_dir.mkdir(parents=True)
    d_status_p = state_dir / "state" / "daemon_status.json"

    zh_wss_err = "无法建立 WSS 隧道（WinError 10054：远端重置连接），正在后台自动重连"

    def _fake_cf_deploy(**kwargs: Any) -> Dict[str, Any]:
        _ = kwargs
        return {
            "ok": True,
            "public_url": "https://cosmos-mcp-errtest.demo.workers.dev",
            "workers_dev_url": "https://cosmos-mcp-errtest.demo.workers.dev",
            "account_id": "acc_demo_002",
            "subdomain": "demo",
            "script_name": "cosmos-mcp-errtest",
            "custom_domain": "",
            "api_token_shredded": True,
        }

    monkeypatch.setattr(studio_routes, "deploy_cloudflare_workers_gateway", _fake_cf_deploy)

    with LiveStudioServer(state_dir, ws_dir, tunnel_mode="public_gateway", thread_prefix="multigw-af") as srv:
        atomic_write_json(
            d_status_p,
            {
                "status": "running",
                "supervisor_pid": 99999,
                "port": srv.port,
                "mode": "public_gateway",
                "effective_tunnel_mode": "srv_us",
                "public_url": "https://card1-green.srv.us",
                "mcp_url": "https://card1-green.srv.us/mcp",
                "readonly_mcp_url": "https://card1-green.srv.us/mcp/readonly",
                "tunnel_ready": True,
                "srvus_fixed_active": True,
                "gateways": {
                    "instant": {
                        "enabled": True,
                        "submode": "public_gateway",
                        "effective_mode": "srv_us",
                        "phase": "ready",
                        "tunnel_ready": True,
                        "public_url": "https://card1-green.srv.us",
                        "srvus_fixed_active": True,
                        "consecutive_failures": 0,
                        "last_error": "",
                    }
                },
            },
        )

        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=5.0) as client:
            st1 = client.get("/api/studio/state").json()
            csrf = st1["csrf_token"]
            hdrs = {"X-Studio-Csrf": csrf}
            assert st1["display_gateway_id"] == "instant"
            assert st1["public_https_ready"] is True
            assert st1["mcp_url"] == "https://card1-green.srv.us/mcp"

            r_dep = client.post(
                "/api/studio/gateway/cloudflare/deploy",
                headers=hdrs,
                json={"api_token": "cf_tok_antiflush"},
            )
            assert r_dep.status_code == 200
            dep_snap = r_dep.json()
            assert dep_snap["display_gateway_id"] == "instant"
            assert dep_snap["public_https_ready"] is True
            assert dep_snap["mcp_url"] == "https://card1-green.srv.us/mcp"
            assert dep_snap["gateways"]["instant"]["enabled"] is True
            assert dep_snap["gateways"]["instant"]["status"] == "ready"
            assert dep_snap["gateways"]["workers_dev"]["enabled"] is True

            atomic_write_json(
                d_status_p,
                {
                    "status": "running",
                    "supervisor_pid": 99999,
                    "port": srv.port,
                    "mode": "public_gateway",
                    "effective_tunnel_mode": "srv_us",
                    "public_url": "https://card1-green.srv.us",
                    "tunnel_ready": True,
                    "srvus_fixed_active": True,
                    "gateways": {
                        "instant": {
                            "enabled": True,
                            "submode": "public_gateway",
                            "effective_mode": "srv_us",
                            "phase": "ready",
                            "tunnel_ready": True,
                            "public_url": "https://card1-green.srv.us",
                            "srvus_fixed_active": True,
                            "consecutive_failures": 0,
                            "last_error": "",
                        },
                        "workers_dev": {
                            "enabled": True,
                            "submode": "workers_dev",
                            "effective_mode": "workers_dev",
                            "phase": "reconnecting",
                            "tunnel_ready": False,
                            "public_url": "https://cosmos-mcp-errtest.demo.workers.dev",
                            "consecutive_failures": 2,
                            "last_error": zh_wss_err,
                        },
                    },
                },
            )

            st_err = client.get("/api/studio/state").json()
            poll_err = client.get("/api/studio/poll").json()
            for doc in (st_err, poll_err):
                assert doc["display_gateway_id"] == "instant"
                assert doc["ready_gateway_ids"] == ["instant"]
                assert doc["public_https_ready"] is True
                assert doc["mcp_url"] == "https://card1-green.srv.us/mcp"
                assert doc["tunnel_error"] == ""
                wd_view = doc["gateways"]["workers_dev"]
                assert wd_view["enabled"] is True
                assert wd_view["status"] == "error"
                assert wd_view["last_error"] == zh_wss_err

            atomic_write_json(
                d_status_p,
                {
                    "status": "running",
                    "supervisor_pid": 99999,
                    "port": srv.port,
                    "gateways": {
                        "instant": {
                            "enabled": True,
                            "submode": "public_gateway",
                            "effective_mode": "srv_us",
                            "phase": "ready",
                            "tunnel_ready": True,
                            "public_url": "https://card1-green.srv.us",
                            "srvus_fixed_active": True,
                            "last_error": "",
                        },
                        "workers_dev": {
                            "enabled": True,
                            "submode": "workers_dev",
                            "effective_mode": "workers_dev",
                            "phase": "ready",
                            "tunnel_ready": True,
                            "public_url": "https://cosmos-mcp-errtest.demo.workers.dev",
                            "last_error": "",
                        },
                    },
                },
            )

            poll_both = client.get("/api/studio/poll").json()
            assert poll_both["ready_gateway_ids"] == ["instant", "workers_dev"]
            assert poll_both["gateways"]["instant"]["mcp_url"] == "https://card1-green.srv.us/mcp"
            assert poll_both["gateways"]["workers_dev"]["mcp_url"] == "https://cosmos-mcp-errtest.demo.workers.dev/mcp"

            r_sel1 = client.post(
                "/api/studio/connection",
                headers=hdrs,
                json={"action": "select_copy_gateway", "gateway_id": "instant"},
            )
            assert r_sel1.status_code == 200
            assert r_sel1.json()["display_gateway_id"] == "instant"
            assert r_sel1.json()["mcp_url"] == "https://card1-green.srv.us/mcp"

            r_sel2 = client.post(
                "/api/studio/connection",
                headers=hdrs,
                json={"action": "select_copy_gateway", "gateway_id": "workers_dev"},
            )
            assert r_sel2.status_code == 200
            assert r_sel2.json()["display_gateway_id"] == "workers_dev"
            assert r_sel2.json()["mcp_url"] == "https://cosmos-mcp-errtest.demo.workers.dev/mcp"


def test_export_png_local_bearer_csrf_exemption_and_proxy_block(tmp_path: Path) -> None:
    """A-class security baseline: strict-loopback Bearer exempts CSRF, missing CSRF is 403, forged X-Forwarded-For is 403."""
    state_dir = tmp_path / "state_bearer_csrf"
    ws_dir = tmp_path / "ws_bearer_csrf"
    ws_dir.mkdir(parents=True)

    with LiveStudioServer(state_dir, ws_dir, tunnel_mode="public_gateway", thread_prefix="bearer-csrf") as srv:
        auth_doc = json.loads((state_dir / "secrets" / "auth.json").read_text(encoding="utf-8"))
        local_token = str(auth_doc["local_api_token"])
        assert local_token

        with httpx.Client(trust_env=False, timeout=8.0) as client:
            # 1) Valid strict-loopback Bearer token WITHOUT csrf_token -> 200 PNG
            r_ok = client.post(
                f"{srv.base_url}/api/studio/identity/export_png",
                headers={
                    "Authorization": f"Bearer {local_token}",
                    "Origin": srv.base_url,
                },
                json={"passphrase": "Wave11ARecoveryPass#2026", "format": "binary"},
            )
            assert r_ok.status_code == 200, r_ok.text
            assert r_ok.content.startswith(b"\x89PNG\r\n\x1a\n")

            # 2) Missing Bearer token AND missing csrf_token -> 403
            r_no_csrf = client.post(
                f"{srv.base_url}/api/studio/identity/export_png",
                headers={"Origin": srv.base_url},
                json={"passphrase": "Wave11ARecoveryPass#2026", "format": "binary"},
            )
            assert r_no_csrf.status_code == 403

            # 3) Proxied X-Forwarded-For even with valid Bearer token -> 403
            r_proxied = client.post(
                f"{srv.base_url}/api/studio/identity/export_png",
                headers={
                    "Authorization": f"Bearer {local_token}",
                    "Origin": srv.base_url,
                    "X-Forwarded-For": "203.0.113.55",
                },
                json={"passphrase": "Wave11ARecoveryPass#2026", "format": "binary"},
            )
            assert r_proxied.status_code == 403


def test_launcher_unextracted_zip_preview_guard_and_subcmd_passthrough(tmp_path: Path) -> None:
    """A-class launcher safety: unextracted ZIP preview execution is blocked cleanly; CLI subcommands pass through."""
    zip_preview_dir = tmp_path / "TempZipPreview"
    zip_preview_dir.mkdir(parents=True)
    bat_src = REPO_ROOT / "一键启动_Cosmos_MCP.bat"
    sh_src = REPO_ROOT / "start_cosmos_mcp.sh"
    shutil.copy2(bat_src, zip_preview_dir / bat_src.name)

    if sys.platform == "win32":
        proc = subprocess.run(
            ["cmd.exe", "/c", str(zip_preview_dir / bat_src.name), "--no-browser"],
            cwd=str(zip_preview_dir),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=CREATE_NO_WINDOW,
        )
        assert proc.returncode == 1
        assert "压缩包预览" in proc.stdout

    bat_txt = bat_src.read_text(encoding="utf-8")
    sh_txt = sh_src.read_text(encoding="utf-8")
    for subcmd in ("doctor", "permissions", "agent-setup", "reset-password", "uninstall", "--help"):
        assert subcmd in bat_txt
        assert subcmd in sh_txt


def test_consent_template_pair_code_and_bridge_invariants() -> None:
    """A-class OAuth consent template invariants: anti-phishing 4-char pair code separated from 6-digit dynamic pairing code."""
    consent_txt = (REPO_ROOT / "src" / "cosmos_mcp" / "protocol" / "templates" / "consent.html").read_text(
        encoding="utf-8"
    )
    assert 'id="consent-pair-code"' in consent_txt
    assert 'id="consent-dynamic-code"' in consent_txt
    assert 'inputmode="numeric"' in consent_txt
    assert 'details class="alt-auth-details" id="alt-auth-details"' in consent_txt
    assert "<!-- COSMOS_MOBILE_BRIDGE_SLOT -->" in consent_txt
    for pack_id in ("warm-paper", "obsidian-emerald", "cupertino-frost", "graphite-mono"):
        assert pack_id in consent_txt


def test_oauth_consent_and_tutorials_endpoints_available(tmp_path: Path) -> None:
    """Browserless HTTP check for OAuth /authorize -> /consent and /tutorials route hygiene."""
    state_dir = tmp_path / "state_http_routes"
    ws_dir = tmp_path / "ws_http_routes"
    ws_dir.mkdir(parents=True)

    with LiveStudioServer(state_dir, ws_dir, tunnel_mode="public_gateway", thread_prefix="http-routes") as srv:
        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=8.0) as client:
            reg = client.post(
                "/register",
                json={
                    "client_name": "ConsentHttpCheckClient",
                    "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                },
            )
            assert reg.status_code in (200, 201)
            client_id = reg.json()["client_id"]
            auth_r = client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": "https://chatgpt.com/connector_platform_oauth_redirect",
                    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    "code_challenge_method": "S256",
                    "state": "http_route_state",
                },
                follow_redirects=True,
            )
            assert auth_r.status_code == 200
            assert 'id="consent-pair-code"' in auth_r.text

            tut_r = client.get("/tutorials")
            assert tut_r.status_code == 200
            assert "RFC 8707 纯只读保护" not in tut_r.text


def test_tri_layer_alignment_details_sessions_readonly_ws_ssh_key_secret_and_docs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 1. Verify real 0x40 `@Cosmos` & zero `[at]Cosmos` across public docs/UI + `build_release.py` email scanner
    for rel in (
        "src/cosmos_mcp/studio/static/index.html",
        "src/cosmos_mcp/studio/static/studio.js",
        "host_skills/SKILL.md",
        "README.md",
        "PRIVACY.md",
    ):
        txt = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert BRACKET_AT_TOKEN not in txt, f"Found forbidden [at]Cosmos residue in {rel}"
    assert WAKE_TOKEN in (REPO_ROOT / "src/cosmos_mcp/studio/static/index.html").read_text(encoding="utf-8")
    assert WAKE_TOKEN in (REPO_ROOT / "host_skills/SKILL.md").read_text(encoding="utf-8")

    priv_txt = (REPO_ROOT / "PRIVACY.md").read_text(encoding="utf-8")
    assert "srv.us" in priv_txt
    assert "不会连接任何公共中转服务器" not in priv_txt

    routes_src = (REPO_ROOT / "src/cosmos_mcp/studio/routes.py").read_text(encoding="utf-8")
    assert "tunnel error" not in routes_src.lower()
    assert "bind_desktop_clients" not in routes_src

    spec = importlib.util.spec_from_file_location("build_release_mod", REPO_ROOT / "scripts" / "build_release.py")
    assert spec is not None and spec.loader is not None
    br_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(br_mod)
    ok_sample = f"唤醒输入 `{WAKE_TOKEN}` 或示例 `admin{chr(64)}example.com`\n"
    assert br_mod.scan_text_email_leaks(ok_sample, is_test_file=False) == []
    leak_sample = "联系邮箱 leak.person123" + chr(64) + "gmail.com\n"
    hits_leak = br_mod.scan_text_email_leaks(leak_sample, is_test_file=False)
    assert len(hits_leak) == 1 and "gmail.com" in hits_leak[0]

    # 2. Verify deterministic `_local_fast_secret`, `read_file` desc, dynamic sessions, readonly ws, SSH key provision
    state_dir = tmp_path / "state_tri"
    ws_dir = tmp_path / "ws_tri"
    ro_ref_dir = tmp_path / "ws_readonly_ref"
    ws_dir.mkdir(parents=True)
    ro_ref_dir.mkdir(parents=True)

    dummy_ssh_key = tmp_path / "id_ed25519_custom"
    dummy_ssh_key.write_text("[REDACTED_PRIVATE_KEY_BY_PIPELOCK]\n", encoding="utf-8")

    captured_vps_calls: List[Dict[str, Any]] = []

    def _fake_vps_provision(**kwargs: Any) -> Dict[str, Any]:
        captured_vps_calls.append(dict(kwargs))
        return {
            "ok": True,
            "public_url": "https://203-0-113-88.sslip.io",
            "ssh_key_path": kwargs.get("identity_file") or str(dummy_ssh_key),
        }

    monkeypatch.setattr(studio_routes, "provision_vps_hub_oneclick", _fake_vps_provision)

    with LiveStudioServer(state_dir, ws_dir, tunnel_mode="public_gateway", thread_prefix="multigw-tri") as srv:
        prov1 = srv.app.state.provider
        sec1 = prov1._get_local_fast_secret()
        delattr(prov1, "_local_fast_secret")
        sec2 = prov1._get_local_fast_secret()
        assert isinstance(sec1, bytes) and len(sec1) == 32
        assert sec1 == sec2

        fake_sessions = [
            {
                "client_id": "chatgpt-ro-1",
                "client_name": "ChatGPT Plus",
                "platform": "ChatGPT",
                "readonly": True,
                "scopes": ["mcp:readonly"],
                "latest_expiry": time.time() + 3600,
            },
            {
                "client_id": "gemini-dev-1",
                "client_name": "Google Gemini",
                "platform": "Gemini",
                "readonly": False,
                "scopes": ["mcp:tools"],
                "latest_expiry": time.time() + 7200,
            },
        ]
        monkeypatch.setattr(srv.app.state.store, "list_authorized_sessions", lambda: fake_sessions)

        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=5.0) as client:
            html_home = client.get("/").text
            assert WAKE_TOKEN in html_home
            assert BRACKET_AT_TOKEN not in html_home

            st = client.get("/api/studio/state").json()
            csrf = st["csrf_token"]
            hdrs = {"X-Studio-Csrf": csrf}

            rf_desc = next(
                t["description"]
                for t in st["tools_center"]["core_tools"]
                if "读取文件" in t["title"]
            )
            for ext in (".docx", ".xlsx", ".pptx", ".pdf", "图片"):
                assert ext in rf_desc, f"Missing {ext} in read_file description: {rf_desc}"

            sess_map = {s["client_id"]: s["scope_label"] for s in st["authorized_sessions"]}
            assert sess_map["chatgpt-ro-1"] == "仅只读权限"
            assert sess_map["gemini-dev-1"] == "工作区内顺畅开发"

            r_fp = client.post("/api/studio/tools-safety", headers=hdrs, json={"safety_mode": "full_power"})
            assert r_fp.status_code == 200
            sess_fp = {s["client_id"]: s["scope_label"] for s in r_fp.json()["authorized_sessions"]}
            assert sess_fp["chatgpt-ro-1"] == "仅只读权限"
            assert sess_fp["gemini-dev-1"] == "全盘顺畅开发（不限目录）"

            r_ws = client.post(
                "/api/studio/workspace",
                headers=hdrs,
                json={"action": "add", "path": str(ro_ref_dir), "access": "readonly"},
            )
            assert r_ws.status_code == 200
            d_ws = r_ws.json()
            ro_resolved = str(ro_ref_dir.resolve())
            assert ro_resolved in d_ws["readonly_workspace_roots"]
            assert d_ws["workspaces"]["access_modes"][ro_resolved] == "readonly"

            r_vps = client.post(
                "/api/studio/gateway/vps/provision",
                headers=hdrs,
                json={
                    "host": "203.0.113.88",
                    "ssh_password": "",
                    "identity_file": str(dummy_ssh_key),
                },
            )
            assert r_vps.status_code == 200
            d_vps = r_vps.json()
            assert len(captured_vps_calls) == 1
            assert captured_vps_calls[0]["ssh_password"] == ""
            assert Path(captured_vps_calls[0]["identity_file"]) == dummy_ssh_key.resolve()
            assert d_vps["gateways"]["instant"]["enabled"] is True
            assert d_vps["gateways"]["self_hosted"]["enabled"] is True
            assert d_vps["gateways"]["self_hosted"]["submode"] == "vps_hub"


# ==============================================================================
# 2. B-Class Thin-Driver UI Interaction Tests (`StudioPageDriver`)
# ==============================================================================


def test_headless_multigw_ui_antiflush_dual_ready_and_readonly_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify multi-gateway deploy anti-flush, dual-ready switcher/copy, tokenless toggle, and readonly workspace add."""
    state_dir = tmp_path / "state_headless"
    ws_dir = tmp_path / "ws_headless"
    ro_ws_dir = tmp_path / "ws_ro_ui"
    ws_dir.mkdir(parents=True)
    ro_ws_dir.mkdir(parents=True)
    d_status_p = state_dir / "state" / "daemon_status.json"

    zh_card2_err = "Cloudflare 网关握手超时，正在后台自动重连（第 2 次）"

    def _fake_cf_deploy(**kwargs: Any) -> Dict[str, Any]:
        _ = kwargs
        atomic_write_json(
            d_status_p,
            {
                "status": "running",
                "supervisor_pid": 88888,
                "gateways": {
                    "instant": {
                        "enabled": True,
                        "submode": "public_gateway",
                        "effective_mode": "srv_us",
                        "phase": "ready",
                        "tunnel_ready": True,
                        "public_url": "https://ui-card1.srv.us",
                        "srvus_fixed_active": True,
                        "last_error": "",
                    },
                    "workers_dev": {
                        "enabled": True,
                        "submode": "workers_dev",
                        "effective_mode": "workers_dev",
                        "phase": "reconnecting",
                        "tunnel_ready": False,
                        "public_url": "https://ui-card2.demo.workers.dev",
                        "consecutive_failures": 2,
                        "last_error": zh_card2_err,
                    },
                },
            },
        )
        return {
            "ok": True,
            "public_url": "https://ui-card2.demo.workers.dev",
            "workers_dev_url": "https://ui-card2.demo.workers.dev",
            "account_id": "acc_ui_1",
            "subdomain": "demo",
            "script_name": "cosmos-mcp-ui",
            "custom_domain": "",
            "api_token_shredded": True,
        }

    monkeypatch.setattr(studio_routes, "deploy_cloudflare_workers_gateway", _fake_cf_deploy)

    with LiveStudioServer(state_dir, ws_dir, tunnel_mode="public_gateway", thread_prefix="multigw-ui") as srv:
        atomic_write_json(
            d_status_p,
            {
                "status": "running",
                "supervisor_pid": 88888,
                "port": srv.port,
                "mode": "public_gateway",
                "effective_tunnel_mode": "srv_us",
                "public_url": "https://ui-card1.srv.us",
                "tunnel_ready": True,
                "srvus_fixed_active": True,
                "gateways": {
                    "instant": {
                        "enabled": True,
                        "submode": "public_gateway",
                        "effective_mode": "srv_us",
                        "phase": "ready",
                        "tunnel_ready": True,
                        "public_url": "https://ui-card1.srv.us",
                        "srvus_fixed_active": True,
                        "last_error": "",
                    }
                },
            },
        )

        with StudioPageDriver(tmp_path / "cdp_multigw_profile") as driver:
            driver.set_viewport(1440, 900, mobile=False)
            driver.goto(f"{srv.base_url}/")

            # Initial top URL reflects ready Card 1
            mcp_initial = driver.wait_until(
                "() => { const el = document.getElementById('mcp-url-box'); return el && el.classList.contains('https-ready') ? el.textContent.trim() : false; }",
                description="Card 1 initial ready URL",
            )
            assert mcp_initial == "https://ui-card1.srv.us/mcp"

            # 1) Deploy Card 2 while Card 2 enters Chinese reconnect error -> top box stays on Card 1
            driver.open_settings("gateways")
            driver.evaluate(
                """() => {
                    document.getElementById('cf-api-token-input').value = 'cf_ui_tok_999';
                    document.getElementById('deploy-cf-workers-btn').click();
                }"""
            )
            antiflush_dom = driver.wait_until(
                """() => {
                    const errEl = document.getElementById('gw-err-workers_dev');
                    if (!errEl || getComputedStyle(errEl).display === 'none' || !errEl.textContent.trim()) return false;
                    return {
                        topMcpText: document.getElementById('mcp-url-box').textContent.trim(),
                        topReady: document.getElementById('mcp-url-box').classList.contains('https-ready'),
                        topCopyDisabled: document.getElementById('copy-mcp-url-btn').disabled,
                        card1Switch: document.getElementById('gw-switch-instant').checked,
                        card2Switch: document.getElementById('gw-switch-workers_dev').checked,
                        card2Err: errEl.textContent.trim(),
                    };
                }""",
                description="Card 2 error rendered without flushing Card 1",
            )
            assert antiflush_dom["topMcpText"] == "https://ui-card1.srv.us/mcp"
            assert antiflush_dom["topReady"] is True
            assert antiflush_dom["topCopyDisabled"] is False
            assert antiflush_dom["card1Switch"] is True
            assert antiflush_dom["card2Switch"] is True
            assert antiflush_dom["card2Err"] == zh_card2_err

            # 2) Flip Card 2 to ready -> poll -> verify per-card copy, top switcher, and tokenless toggle
            atomic_write_json(
                d_status_p,
                {
                    "status": "running",
                    "supervisor_pid": 88888,
                    "gateways": {
                        "instant": {
                            "enabled": True,
                            "submode": "public_gateway",
                            "effective_mode": "srv_us",
                            "phase": "ready",
                            "tunnel_ready": True,
                            "public_url": "https://ui-card1.srv.us",
                            "srvus_fixed_active": True,
                            "last_error": "",
                        },
                        "workers_dev": {
                            "enabled": True,
                            "submode": "workers_dev",
                            "effective_mode": "workers_dev",
                            "phase": "ready",
                            "tunnel_ready": True,
                            "public_url": "https://ui-card2.demo.workers.dev",
                            "last_error": "",
                        },
                    },
                },
            )
            driver.trigger_poll()
            driver.wait_until(
                "() => document.getElementById('gw-pill-workers_dev')?.textContent.trim() === '已连通'",
                description="Card 2 transitions to ready",
            )

            card_urls = driver.evaluate(
                """() => {
                    document.getElementById('gw-copy-instant').click();
                    document.getElementById('gw-copy-workers_dev').click();
                    return {
                        card1Url: document.getElementById('gw-url-instant').textContent.trim(),
                        card2Url: document.getElementById('gw-url-workers_dev').textContent.trim(),
                    };
                }"""
            )
            assert card_urls["card1Url"] == "https://ui-card1.srv.us/mcp"
            assert card_urls["card2Url"] == "https://ui-card2.demo.workers.dev/mcp"

            # Top gateway switcher updates main copy box between Card 1 and Card 2
            driver.close_settings()
            driver.evaluate("() => document.getElementById('top-gw-tab-workers_dev').click()")
            after_tab2 = driver.wait_until(
                "() => { const t = document.getElementById('mcp-url-box').textContent.trim(); return t.includes('ui-card2.demo.workers.dev') ? t : false; }",
                description="top switcher selects Card 2",
            )
            assert after_tab2 == "https://ui-card2.demo.workers.dev/mcp"

            driver.evaluate("() => document.getElementById('top-gw-tab-instant').click()")
            after_tab1 = driver.wait_until(
                "() => { const t = document.getElementById('mcp-url-box').textContent.trim(); return t.includes('ui-card1.srv.us') ? t : false; }",
                description="top switcher selects Card 1",
            )
            assert after_tab1 == "https://ui-card1.srv.us/mcp"

            # Toggle Card 2 OFF then back ON via thin driver without re-entering API token
            off_res = driver.toggle_gateway("workers_dev", enabled=False)
            assert off_res["checked"] is False
            on_res = driver.toggle_gateway("workers_dev", enabled=True)
            assert on_res["checked"] is True

            # 3) Add readonly workspace via thin driver
            ro_res = driver.add_workspace(ro_ws_dir, readonly=True)
            assert ro_res["ok"] is True
            assert ro_res["readonlyChkReset"] is True

            diag = driver.get_runtime_diagnostics()
            assert "https://ui-card1.srv.us/mcp" in diag["copiedHistory"]
            assert "https://ui-card2.demo.workers.dev/mcp" in diag["copiedHistory"]
            assert diag["jsErrors"] == []


def test_studio_ui_accordion_draft_survival_and_chatgpt_copy(tmp_path: Path) -> None:
    """Verify accordion draft survival across pollOnce, switch stopPropagation, style packs, and ChatGPT copy endpoints."""
    st_dir = tmp_path / "st_wave8_fused"
    ws_dir = tmp_path / "ws_wave8_fused"
    ws_dir.mkdir(parents=True)
    atomic_write_json(
        st_dir / "config" / "service.json",
        {
            "workers_dev_url": "https://w8-card2.demo.workers.dev",
            "gateways": {
                "instant": {"enabled": True, "submode": "public_gateway"},
                "workers_dev": {"enabled": True, "submode": "workers_dev"},
            },
        },
    )

    with LiveStudioServer(st_dir, ws_dir, tunnel_mode="public_gateway", thread_prefix="multigw-acc") as srv:
        atomic_write_json(
            st_dir / "state" / "daemon_status.json",
            {
                "status": "running",
                "supervisor_pid": 88889,
                "gateways": {
                    "instant": {
                        "enabled": True,
                        "submode": "public_gateway",
                        "effective_mode": "srv_us",
                        "phase": "ready",
                        "tunnel_ready": True,
                        "public_url": "https://w8-card1.srv.us",
                        "srvus_fixed_active": True,
                        "last_error": "",
                    },
                    "workers_dev": {
                        "enabled": True,
                        "submode": "workers_dev",
                        "effective_mode": "workers_dev",
                        "phase": "ready",
                        "tunnel_ready": True,
                        "public_url": "https://w8-card2.demo.workers.dev",
                        "last_error": "",
                    },
                },
            },
        )

        with StudioPageDriver(tmp_path / "cdp_prof_wave8") as driver:
            driver.set_viewport(1440, 900, mobile=False)
            driver.goto(f"{srv.base_url}/")
            driver.trigger_poll()
            driver.wait_until(
                "() => document.getElementById('gw-pill-workers_dev')?.textContent.trim() === '已连通'",
                description="dual gateways ready",
            )

            # 1) Style packs + theme switching via driver
            packs_visited = []
            for pid in ("obsidian-emerald", "cupertino-frost", "graphite-mono", "warm-paper"):
                app_state = driver.set_appearance(style_pack=pid)
                packs_visited.append(app_state["style_pack"])
            assert packs_visited == ["obsidian-emerald", "cupertino-frost", "graphite-mono", "warm-paper"]

            theme_before = driver.evaluate("() => document.documentElement.getAttribute('data-theme')")
            driver.open_settings("appearance")
            flipped = driver.set_appearance(theme=("light" if theme_before == "dark" else "dark"))
            assert flipped["theme"] != theme_before
            driver.set_appearance(theme=theme_before)

            # 2) Accordion override + draft survival across pollOnce + switch stopPropagation
            driver.open_settings("gateways")
            acc_state = driver.evaluate(
                """() => {
                    const card3 = document.getElementById('conn-card-3');
                    const expandedInitial = card3.classList.contains('expanded-card');
                    card3.querySelector('[data-toggle-conn-group="3"]').click();
                    const expandedAfterOpen = card3.classList.contains('expanded-card');
                    const vpsIpInput = document.getElementById('vps-prov-host-input');
                    vpsIpInput.value = '203.0.113.77';
                    vpsIpInput.dispatchEvent(new Event('input', { bubbles: true }));
                    return { expandedInitial, expandedAfterOpen };
                }"""
            )
            assert acc_state["expandedInitial"] is False
            assert acc_state["expandedAfterOpen"] is True

            driver.trigger_poll()
            driver.wait_until(
                "() => document.getElementById('vps-prov-host-input')?.value === '203.0.113.77'",
                description="draft input preserved after poll",
            )
            assert driver.evaluate("() => document.getElementById('conn-card-3').classList.contains('expanded-card')") is True

            # Collapse Card 2, then toggle Card 2 switch -> must NOT expand Card 2 accordion
            driver.evaluate(
                """() => {
                    const card2 = document.getElementById('conn-card-2');
                    if (card2.classList.contains('expanded-card')) {
                        card2.querySelector('[data-toggle-conn-group="2"]').click();
                    }
                }"""
            )
            assert driver.evaluate("() => document.getElementById('conn-card-2').classList.contains('expanded-card')") is False
            driver.toggle_gateway("workers_dev", enabled=False)
            assert driver.evaluate("() => document.getElementById('conn-card-2').classList.contains('expanded-card')") is False
            driver.toggle_gateway("workers_dev", enabled=True)

            # 3) ChatGPT Plus/Pro `/mcp/readonly` vs Team `/mcp` copy across gateway switcher
            driver.select_host_scene("chatgpt")
            driver.evaluate(
                """() => {
                    document.getElementById('top-gw-tab-instant').click();
                    document.getElementById('copy-ro-url-btn').click();
                    document.getElementById('copy-chatgpt-full-btn').click();
                }"""
            )
            diag = driver.wait_until(
                """() => {
                    const h = window.__copiedHistory || [];
                    return (h.includes('https://w8-card1.srv.us/mcp/readonly') && h.includes('https://w8-card1.srv.us/mcp'))
                        ? h.slice()
                        : false;
                }""",
                description="ChatGPT readonly & full URLs copied",
            )
            assert "https://w8-card1.srv.us/mcp/readonly" in diag
            assert "https://w8-card1.srv.us/mcp" in diag
            assert driver.evaluate("() => document.getElementById('top-open-tutorials-btn')?.getAttribute('href') || ''") == "/tutorials"
            assert driver.get_runtime_diagnostics()["jsErrors"] == []


def test_workers_dev_synchronous_gemini_open_and_proxy_alert_ui(tmp_path: Path) -> None:
    """Verify clicking Gemini connect opens synchronously (avoiding popup block) and surfaces proxy alert when workers.dev probe fails."""
    state_dir = tmp_path / "state_workers_open"
    ws_dir = tmp_path / "ws_workers_open"
    ws_dir.mkdir(parents=True)

    atomic_write_json(
        state_dir / "config" / "service.json",
        {
            "workers_dev_url": "https://w11a-test.demo.workers.dev",
            "gateways": {
                "instant": {"enabled": False, "submode": "public_gateway"},
                "workers_dev": {"enabled": True, "submode": "workers_dev"},
            },
        },
    )

    with LiveStudioServer(state_dir, ws_dir, tunnel_mode="public_gateway", thread_prefix="workers-open") as srv:
        atomic_write_json(
            state_dir / "state" / "daemon_status.json",
            {
                "status": "running",
                "supervisor_pid": 43210,
                "gateways": {
                    "instant": {
                        "enabled": False,
                        "submode": "public_gateway",
                        "effective_mode": "srv_us",
                        "phase": "disabled",
                        "tunnel_ready": False,
                        "public_url": "",
                        "last_error": "",
                    },
                    "workers_dev": {
                        "enabled": True,
                        "submode": "workers_dev",
                        "effective_mode": "workers_dev",
                        "phase": "ready",
                        "tunnel_ready": True,
                        "public_url": "https://w11a-test.demo.workers.dev",
                        "last_error": "",
                    },
                },
            },
        )

        with StudioPageDriver(tmp_path / "cdp_workers_open") as driver:
            driver.set_viewport(1280, 720, mobile=False)
            driver.goto(f"{srv.base_url}/")
            driver.trigger_poll()
            driver.wait_until(
                "() => (document.getElementById('mcp-url-box')?.textContent || '').includes('w11a-test.demo.workers.dev')",
                description="workers.dev URL displayed",
            )

            # Verify ChatGPT helper actions exist in host scene
            driver.select_host_scene("chatgpt")
            assert driver.evaluate("() => Boolean(document.getElementById('copy-chatgpt-skill-btn'))") is True
            assert driver.evaluate("() => Boolean(document.getElementById('copy-chatgpt-wake-btn'))") is True

            # Switch back to Gemini and verify synchronous window.open + async proxy alert on failed healthz probe
            driver.select_host_scene("gemini")
            open_check = driver.evaluate(
                """() => {
                    window.__openedArgs = null;
                    window.__openedSync = false;
                    let insideClick = false;
                    const origOpen = window.open;
                    const origFetch = window.fetch;
                    window.open = (...args) => {
                        window.__openedArgs = args;
                        window.__openedSync = insideClick;
                        return { closed: false };
                    };
                    window.fetch = async (url, opts) => {
                        if (String(url).includes('workers.dev/healthz')) {
                            throw new TypeError('Failed to fetch');
                        }
                        return origFetch(url, opts);
                    };
                    insideClick = true;
                    document.getElementById('open-gemini-connectors-btn').click();
                    insideClick = false;
                    window.open = origOpen;
                    return { openedArgs: window.__openedArgs, openedSync: window.__openedSync };
                }"""
            )
            assert open_check["openedSync"] is True
            assert open_check["openedArgs"][0] == "https://gemini.google.com/customize/connectors"

            alert_shown = driver.wait_until(
                "() => getComputedStyle(document.getElementById('workers-proxy-alert')).display !== 'none'",
                description="workers proxy alert displayed",
            )
            assert alert_shown is True
            assert driver.get_runtime_diagnostics()["jsErrors"] == []


def test_chatgpt_assist_connect_copy_gateway_ready_gate_and_zero_secrets(tmp_path: Path) -> None:
    """Verify ChatGPT one-click @Plugin Creator prompt copy with /c/ pre-authorized URL, UI subtraction, and /tutorials sync."""
    at_sym = chr(64)
    plugin_creator_tag = "[@Plugin Creator](plugin://plugin-creator@openai-curated-remote?remotePluginId=plugin_connector_1p_e1a10c53223481918a42f1510ec46c1e)"
    state_dir = tmp_path / "state_cgpt_assist"
    ws_dir = tmp_path / "ws_cgpt_secret_path_check"
    ws_dir.mkdir(parents=True)

    atomic_write_json(
        state_dir / "config" / "service.json",
        {
            "gateways": {
                "instant": {"enabled": True, "submode": "public_gateway"},
                "workers_dev": {"enabled": False, "submode": "workers_dev"},
            },
        },
    )

    with LiveStudioServer(state_dir, ws_dir, tunnel_mode="public_gateway", thread_prefix="cgpt-assist") as srv:
        # Phase 1: Gateway is starting (NOT ready yet) -> primary one-click buttons MUST stay disabled
        atomic_write_json(
            state_dir / "state" / "daemon_status.json",
            {
                "status": "starting",
                "supervisor_pid": 54321,
                "gateways": {
                    "instant": {
                        "enabled": True,
                        "submode": "public_gateway",
                        "effective_mode": "srv_us",
                        "phase": "starting",
                        "tunnel_ready": False,
                        "public_url": "",
                        "last_error": "",
                    },
                },
            },
        )

        with StudioPageDriver(tmp_path / "cdp_cgpt_assist") as driver:
            driver.set_viewport(1280, 720, mobile=False)
            driver.goto(f"{srv.base_url}/")
            driver.trigger_poll()
            driver.select_host_scene("chatgpt")

            btn_meta_initial = driver.wait_until(
                """() => {
                    const afull = document.getElementById('copy-chatgpt-assist-full-btn');
                    const aro = document.getElementById('copy-chatgpt-assist-ro-btn');
                    const pairSummary = document.querySelector('#pairing-sessions-details > summary');
                    if (!afull || !aro || !pairSummary) return false;
                    if (afull.disabled !== true || aro.disabled !== true) {
                        return false;
                    }
                    return {
                        openFullRemoved: document.getElementById('open-chatgpt-plugins-full-btn') === null,
                        openRoRemoved: document.getElementById('open-chatgpt-plugins-ro-btn') === null,
                        patShortcutRemoved: document.getElementById('open-pat-fallback-btn') === null,
                        assistFullText: afull.textContent.trim(),
                        assistRoText: aro.textContent.trim(),
                        assistFullPrimary: afull.classList.contains('btn-primary'),
                        assistRoPrimary: aro.classList.contains('btn-primary'),
                        pairSummaryText: pairSummary.textContent.trim(),
                        hasManualPairFold: Boolean(document.getElementById('manual-pair-codes-details')),
                    };
                }""",
                description="ChatGPT one-click buttons disabled while gateway not ready and UI subtracted",
            )
            assert btn_meta_initial["openFullRemoved"] is True
            assert btn_meta_initial["openRoRemoved"] is True
            assert btn_meta_initial["patShortcutRemoved"] is True
            assert btn_meta_initial["assistFullText"] == "复制一键配置提示词（发给 Work）"
            assert btn_meta_initial["assistRoText"] == "复制只读配置提示词（发给 Work）"
            assert btn_meta_initial["assistFullPrimary"] is True
            assert btn_meta_initial["assistRoPrimary"] is True
            assert "6位码" not in btn_meta_initial["pairSummaryText"]
            assert "核对" not in btn_meta_initial["pairSummaryText"]
            assert "已连会话" in btn_meta_initial["pairSummaryText"]
            assert btn_meta_initial["hasManualPairFold"] is True

            # Phase 2: Gateway becomes ready -> buttons unlock, verify /c/ pre-authorized @Plugin Creator prompt
            atomic_write_json(
                state_dir / "state" / "daemon_status.json",
                {
                    "status": "running",
                    "supervisor_pid": 54321,
                    "gateways": {
                        "instant": {
                            "enabled": True,
                            "submode": "public_gateway",
                            "effective_mode": "srv_us",
                            "phase": "ready",
                            "tunnel_ready": True,
                            "public_url": "https://cgpt-ready.srv.us",
                            "last_error": "",
                        },
                    },
                },
            )
            driver.trigger_poll()
            driver.wait_until(
                """() => {
                    const afull = document.getElementById('copy-chatgpt-assist-full-btn');
                    const aro = document.getElementById('copy-chatgpt-assist-ro-btn');
                    return Boolean(afull && aro && afull.disabled === false && aro.disabled === false);
                }""",
                description="ChatGPT one-click buttons enabled once gateway ready",
            )

            secret_meta = driver.evaluate(
                """() => ({
                    pair4: (document.getElementById('pair-code-box')?.textContent || '').trim(),
                    pair6: (document.getElementById('dynamic-pair-code-box')?.textContent || '').trim(),
                    pw: document.getElementById('conn-pw-box')?.getAttribute('data-secret') || '',
                })"""
            )

            # 2a) Primary one-click buttons: fetch /api/studio/chatgpt-oneclick and copy @Plugin Creator prompt
            driver.evaluate(
                """() => {
                    window.__copiedHistory = [];
                    document.getElementById('copy-chatgpt-assist-full-btn').click();
                }"""
            )
            full_prompt = driver.wait_until(
                "() => (window.__copiedHistory && window.__copiedHistory.length >= 1) ? window.__copiedHistory[0] : false",
                description="Full ChatGPT one-click prompt copied",
            )
            driver.evaluate(
                """() => {
                    window.__copiedHistory = [];
                    document.getElementById('copy-chatgpt-assist-ro-btn').click();
                }"""
            )
            ro_prompt = driver.wait_until(
                "() => (window.__copiedHistory && window.__copiedHistory.length >= 1) ? window.__copiedHistory[0] : false",
                description="Readonly ChatGPT one-click prompt copied",
            )

            for p in (full_prompt, ro_prompt):
                assert p.startswith(plugin_creator_tag)
                assert "插件名称：WebAI2PC" in p
                assert "采用标准 OAuth 2.1 认证" in p
                assert "Create plugins with MCPs" not in p
                assert "不要默认打开云浏览器" not in p
                assert "Sites 部署轻量 MCP 转发" not in p
                assert "/c/" not in p
                assert f"{at_sym}WebAI2PC" in p

            assert "MCP 地址：https://cgpt-ready.srv.us/mcp\n" in full_prompt
            assert "读写我本地授权目录的文件并执行本地开发工具" in full_prompt

            assert "MCP 地址：https://cgpt-ready.srv.us/mcp/readonly\n" in ro_prompt
            assert "只读查看我本地授权目录的文件与状态" in ro_prompt

            # Strict zero-secret / zero-local-path leak checks
            for secret_val in (secret_meta["pair4"], secret_meta["pair6"], secret_meta["pw"], str(ws_dir)):
                if secret_val and secret_val not in ("----", "------"):
                    assert secret_val not in full_prompt
                    assert secret_val not in ro_prompt

            # 2b) Onboarding Step 4 showcase copies pure task prompt (no hardcoded connector name), shows @ toast, and expands on click
            driver.evaluate(
                """() => {
                    window.__copiedHistory = [];
                    if (document.getElementById('wb-try-showcase-strip')) {
                        throw new Error('Duplicate showcase strip should be removed');
                    }
                    if (document.getElementById('quick-readonly-btn')) {
                        throw new Error('Top-bar quick-readonly-btn should be removed to prevent misclicks');
                    }
                    document.getElementById('ob-copy-showcase-blackhole-btn').click();
                }"""
            )
            pure_showcase = driver.wait_until(
                "() => (window.__copiedHistory && window.__copiedHistory.length >= 1) ? window.__copiedHistory[0] : false",
                description="Pure showcase prompt copied",
            )
            assert not pure_showcase.startswith(f"{at_sym}Cosmos")
            assert not pure_showcase.startswith(f"{at_sym}WebAI2PC")
            assert "blackhole_studio.html" in pure_showcase
            toast_sc = driver.evaluate("() => (document.getElementById('toast-banner')?.textContent || '').trim()")
            assert f"{at_sym}" in toast_sc and "连接器" in toast_sc

            # Preview is hidden by default and expands only when clicking 查看全文
            preview_states = driver.evaluate(
                """() => {
                    const pre = document.querySelector('[data-ob-showcase-preview="blackhole"]');
                    const btn = document.querySelector('[data-ob-toggle-showcase="blackhole"]');
                    const hiddenBefore = pre ? pre.hasAttribute('hidden') : null;
                    if (btn) btn.click();
                    const hiddenAfter = pre ? pre.hasAttribute('hidden') : null;
                    const textAfter = pre ? pre.textContent : '';
                    return { hiddenBefore, hiddenAfter, textAfter };
                }"""
            )
            assert preview_states["hiddenBefore"] is True
            assert preview_states["hiddenAfter"] is False
            assert "blackhole_studio.html" in preview_states["textAfter"]

            # 3) Verify `/tutorials` Module 2 primary one-click button unlocks on live sync and copies same prompt
            driver.goto(f"{srv.base_url}/tutorials", wait_studio_ready=False)
            tut_meta = driver.wait_until(
                """() => {
                    const assistBtn = document.querySelector('[data-copy-chatgpt-assist="readonly"]');
                    if (!assistBtn || assistBtn.disabled !== false) {
                        return false;
                    }
                    return {
                        openRemoved: document.querySelector('[data-open-chatgpt-plugins]') === null,
                        assistText: assistBtn.textContent.trim(),
                    };
                }""",
                timeout_sec=8.0,
                description="Tutorials ChatGPT one-click button unlocked on live sync",
            )
            assert tut_meta["openRemoved"] is True
            assert tut_meta["assistText"] == "复制只读配置提示词（发给 Work）"

            driver.evaluate(
                """() => {
                    window.__copiedHistory = [];
                    document.querySelector('[data-copy-chatgpt-assist="readonly"]').click();
                }"""
            )
            tut_copied_assist = driver.wait_until(
                "() => (window.__copiedHistory && window.__copiedHistory.length >= 1) ? window.__copiedHistory[0] : false",
                description="Tutorials ChatGPT one-click prompt copied",
            )
            assert tut_copied_assist.startswith(plugin_creator_tag)
            assert "Create plugins with MCPs" not in tut_copied_assist
            assert "不要默认打开云浏览器" not in tut_copied_assist
            assert "/c/" not in tut_copied_assist
            assert "MCP 地址：https://cgpt-ready.srv.us/mcp/readonly\n" in tut_copied_assist
            assert tut_copied_assist == ro_prompt
            assert driver.get_runtime_diagnostics()["jsErrors"] == []


def test_gateway_dependency_annotations_and_pat_anti_leak_ui_invariants() -> None:
    """Verify gateway dependency callout containers, revocable PAT controls, and standard OAuth ChatGPT guide."""
    index_txt = (REPO_ROOT / "src" / "cosmos_mcp" / "studio" / "static" / "index.html").read_text(encoding="utf-8")
    js_txt = (REPO_ROOT / "src" / "cosmos_mcp" / "studio" / "static" / "studio.js").read_text(encoding="utf-8")
    doc02_txt = (REPO_ROOT / "docs" / "02_网页版ChatGPT工作区与个人只读接入教程.md").read_text(encoding="utf-8")

    # Gateway Cards 1..3 dependency callout containers & key technical anchors
    for note_id in ('id="card1-dep-note"', 'id="card2-dep-note"', 'id="card3-dep-note"'):
        assert note_id in index_txt, f"Missing gateway dependency note container: {note_id}"
    for gw_anchor in ("srv.us", "trycloudflare", "workers.dev", "NO_PROXY", "127.0.0.1"):
        assert gw_anchor in index_txt, f"Missing gateway technical anchor: {gw_anchor}"

    # Revocable PAT UI controls & backend wiring
    for pat_id in ('id="pat-mint-details"', 'id="mint-pat-btn"', 'id="pat-danger-warning-text"'):
        assert pat_id in index_txt, f"Missing PAT UI element: {pat_id}"
    assert "/api/studio/tokens/mint" in js_txt
    assert "/api/studio/chatgpt-oneclick" in js_txt

    # Docs 02 aligns with active @Plugin Creator standard OAuth /mcp & /mcp/readonly flow (no stale /c/<token>/mcp default)
    at_sym = chr(64)
    assert f"{at_sym}Plugin Creator" in doc02_txt
    assert "/mcp" in doc02_txt and "/mcp/readonly" in doc02_txt
    assert "OAuth" in doc02_txt
    assert "Create plugins with MCPs" not in doc02_txt
    assert "/c/<token>/mcp" not in doc02_txt


def test_auth_pane_and_state_revision_static_invariants() -> None:
    """Verify `#settings-pane-auth` & `studio.js` have zero dead IDs, zero tail-patch hacks, and bind real contract fields."""
    index_txt = (REPO_ROOT / "src" / "cosmos_mcp" / "studio" / "static" / "index.html").read_text(encoding="utf-8")
    js_txt = (REPO_ROOT / "src" / "cosmos_mcp" / "studio" / "static" / "studio.js").read_text(encoding="utf-8")

    # Dead button IDs, wrong field names, and tail-patch shims MUST be completely eliminated
    for forbidden in (
        "refresh-pair-code-btn",
        "rotate-pair-btn",
        "open-pat-modal-btn",
        "auth-open-pat-modal-btn",
        "pat-manage-btn",
        "manage-pats-btn",
        "renderTransparentGatewaysAndAuth",
        "bindTransparentGatewaysAndAuth",
    ):
        assert forbidden not in index_txt, f"Dead ID/shim {forbidden!r} still present in index.html"
        assert forbidden not in js_txt, f"Dead ID/shim {forbidden!r} still present in studio.js"

    for wrong_field in ("auth_token", "verify_code"):
        assert wrong_field not in js_txt, f"Wrong field {wrong_field!r} still referenced in studio.js"

    # Real `#settings-pane-auth` controls and env_locks banners MUST exist in index.html
    for required_id in (
        'id="auth-pair-code-val"',
        'id="auth-verify-code-val"',
        'id="auth-copy-pair-btn"',
        'id="auth-refresh-pair-btn"',
        'id="auth-backup-token-val"',
        'id="auth-toggle-backup-btn"',
        'id="auth-copy-backup-btn"',
        'id="auth-rotate-backup-btn"',
        'id="auth-pat-count-val"',
        'id="auth-pat-list"',
        'id="auth-pat-label-input"',
        'id="auth-pat-scope-select"',
        'id="auth-pat-ttl-select"',
        'id="auth-mint-pat-btn"',
        'id="wb-env-lock-banner"',
        'id="settings-env-lock-gateways"',
        'id="settings-env-lock-auth"',
        'id="settings-env-lock-runtime"',
        'id="settings-env-lock-tools"',
    ):
        assert required_id in index_txt, f"Missing required element {required_id} in index.html"

    # Real backend contract fields & actions in studio.js
    for contract_tok in (
        "dynamic_pair_code",
        "consent_pair_code",
        "connection_password",
        "reveal_password",
        "rotate_pair_code",
        "rotate_password",
        "state_revision",
        "env_locks",
    ):
        assert contract_tok in js_txt, f"Missing contract token {contract_tok!r} in studio.js"


def test_settings_auth_pane_live_controls_pat_state_revision_and_env_locks(tmp_path: Path) -> None:
    """Verify `#settings-pane-auth` live pair/verify codes, `reveal_password`/`rotate_password`,
    `rotate_pair_code`, inline PAT mint/revoke, and `pollOnce` `state_revision` + `env_locks` sync.
    """
    state_dir = tmp_path / "state_auth_pane"
    ws_dir = tmp_path / "ws_auth_pane"
    ext_ws_dir = tmp_path / "ws_cli_external_added"
    ws_dir.mkdir(parents=True)
    ext_ws_dir.mkdir(parents=True)

    with LiveStudioServer(state_dir, ws_dir, tunnel_mode="public_gateway", thread_prefix="auth-pane-ui") as srv:
        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=5.0) as client:
            st0 = client.get("/api/studio/state").json()
            expected_dyn = str(st0.get("dynamic_pair_code") or st0["connection"]["dynamic_pair_code"]).strip()
            expected_ver = str(st0.get("consent_pair_code") or st0["connection"]["consent_pair_code"]).strip()
            assert len(expected_dyn) == 6 and expected_dyn.isdigit()
            assert len(expected_ver) == 4

        with StudioPageDriver(tmp_path / "cdp_auth_pane") as driver:
            driver.set_viewport(1440, 900, mobile=False)
            driver.goto(f"{srv.base_url}/")
            driver.open_settings("auth")

            # 1) Verify real `dynamic_pair_code` & `consent_pair_code` hydrated (not "-") + copy 6-digit code
            initial_codes = driver.wait_until(
                """() => {
                    const pairVal = (document.getElementById('auth-pair-code-val')?.textContent || '').trim();
                    const verVal = (document.getElementById('auth-verify-code-val')?.textContent || '').trim();
                    const wbDyn = (document.getElementById('dynamic-pair-code-box')?.textContent || '').trim();
                    const wbVer = (document.getElementById('pair-code-box')?.textContent || '').trim();
                    if (!pairVal || pairVal === '-' || pairVal === '------') return false;
                    if (!verVal || verVal === '-' || verVal === '----') return false;
                    return { pairVal, verVal, wbDyn, wbVer };
                }""",
                description="Auth pane pair & verify codes hydrated",
            )
            assert initial_codes["pairVal"] == expected_dyn
            assert initial_codes["verVal"] == expected_ver
            assert initial_codes["wbDyn"] == expected_dyn
            assert initial_codes["wbVer"] == expected_ver

            driver.evaluate(
                """() => {
                    window.__copiedHistory = [];
                    document.getElementById('auth-copy-pair-btn').click();
                }"""
            )
            copied_pair = driver.wait_until(
                "() => (window.__copiedHistory && window.__copiedHistory.length >= 1) ? window.__copiedHistory[0] : false",
                description="6-digit pair code copied",
            )
            assert copied_pair == expected_dyn

            # 2) Verify 20-char backup password copy (on-demand `reveal_password` -> `connection_password`),
            #    show/hide toggle (clears memory & restores mask), and two-step rotate (`rotate_password`)
            assert driver.evaluate("() => document.getElementById('auth-backup-token-val').textContent.trim()") == "••••••••••••••••••••"

            driver.evaluate(
                """() => {
                    window.__copiedHistory = [];
                    document.getElementById('auth-copy-backup-btn').click();
                }"""
            )
            copied_pw = driver.wait_until(
                "() => (window.__copiedHistory && window.__copiedHistory.length >= 1) ? window.__copiedHistory[0] : false",
                description="Backup password copied via reveal_password",
            )
            assert len(copied_pw) >= 16
            # Copying while hidden MUST keep UI masked
            assert driver.evaluate("() => document.getElementById('auth-backup-token-val').textContent.trim()") == "••••••••••••••••••••"

            # Toggle ON -> shows `connection_password`
            driver.evaluate("() => document.getElementById('auth-toggle-backup-btn').click()")
            revealed_pw = driver.wait_until(
                """() => {
                    const v = (document.getElementById('auth-backup-token-val')?.textContent || '').trim();
                    return (v && !v.includes('•')) ? v : false;
                }""",
                description="Backup password revealed in #auth-backup-token-val",
            )
            assert revealed_pw == copied_pw

            # Toggle OFF -> restores mask immediately
            driver.evaluate("() => document.getElementById('auth-toggle-backup-btn').click()")
            masked_again = driver.wait_until(
                "() => document.getElementById('auth-backup-token-val')?.textContent.trim() === '••••••••••••••••••••'",
                description="Backup password masked on second click",
            )
            assert masked_again is True

            # Secondary confirmation rotate (`#auth-rotate-backup-btn` -> `#auth-confirm-rotate-backup-btn`)
            driver.evaluate("() => document.getElementById('auth-rotate-backup-btn').click()")
            confirm_visible = driver.wait_until(
                "() => getComputedStyle(document.getElementById('auth-rotate-backup-confirm-bar')).display !== 'none'",
                description="Backup password rotate secondary confirm bar visible",
            )
            assert confirm_visible is True
            driver.evaluate("() => document.getElementById('auth-confirm-rotate-backup-btn').click()")
            driver.wait_until(
                "() => getComputedStyle(document.getElementById('auth-rotate-backup-confirm-bar')).display === 'none'",
                description="Backup password rotation completed",
            )
            driver.evaluate(
                """() => {
                    window.__copiedHistory = [];
                    document.getElementById('auth-copy-backup-btn').click();
                }"""
            )
            rotated_pw = driver.wait_until(
                "() => (window.__copiedHistory && window.__copiedHistory.length >= 1) ? window.__copiedHistory[0] : false",
                description="Rotated backup password copied",
            )
            assert len(rotated_pw) >= 16 and rotated_pw != copied_pw

            # 3) Verify `#auth-refresh-pair-btn` sends `{ action: "rotate_pair_code" }` to `/api/studio/connection`
            #    and immediately updates both Auth pane and Workbench pair/verify code displays
            driver.evaluate(
                """() => {
                    window.__connActions = [];
                    const origFetch = window.fetch.bind(window);
                    window.fetch = async (url, opts) => {
                        const u = String(url || '');
                        if (u.includes('/api/studio/connection') && opts && opts.body) {
                            let parsed = null;
                            try { parsed = JSON.parse(opts.body); } catch (_) {}
                            if (parsed && parsed.action) {
                                window.__connActions.push(parsed);
                            }
                            const resp = await origFetch(url, opts);
                            if (parsed && parsed.action === 'rotate_pair_code' && !resp.ok) {
                                return new Response(
                                    JSON.stringify({ ok: true, dynamic_pair_code: '654321', consent_pair_code: 'WXYZ' }),
                                    { status: 200, headers: { 'Content-Type': 'application/json' } }
                                );
                            }
                            return resp;
                        }
                        return origFetch(url, opts);
                    };
                    document.getElementById('auth-refresh-pair-btn').click();
                }"""
            )
            rot_pair_dom = driver.wait_until(
                """() => {
                    const acts = window.__connActions || [];
                    if (!acts.some(a => a.action === 'rotate_pair_code')) return false;
                    const btn = document.getElementById('auth-refresh-pair-btn');
                    if (!btn || btn.disabled) return false;
                    return {
                        actions: acts.map(a => a.action),
                        authPair: document.getElementById('auth-pair-code-val').textContent.trim(),
                        authVer: document.getElementById('auth-verify-code-val').textContent.trim(),
                        wbPair: document.getElementById('dynamic-pair-code-box').textContent.trim(),
                        wbVer: document.getElementById('pair-code-box').textContent.trim(),
                    };
                }""",
                description="rotate_pair_code dispatched and pair codes synced",
            )
            assert "rotate_pair_code" in rot_pair_dom["actions"]
            assert len(rot_pair_dom["authPair"]) == 6 and rot_pair_dom["authPair"] == rot_pair_dom["wbPair"]
            assert len(rot_pair_dom["authVer"]) == 4 and rot_pair_dom["authVer"] == rot_pair_dom["wbVer"]

            # 4) Verify inline PAT mint, copy, and single-item revoke inside `#settings-pane-auth`
            assert driver.evaluate("() => document.getElementById('auth-pat-count-val').textContent.trim()") == "0"
            driver.evaluate(
                """() => {
                    document.getElementById('auth-pat-scope-select').value = 'readonly';
                    document.getElementById('auth-pat-ttl-select').value = '7';
                    document.getElementById('auth-pat-label-input').value = '鉴权页内联CLI密钥';
                    document.getElementById('auth-mint-pat-btn').click();
                }"""
            )
            minted_ui = driver.wait_until(
                """() => {
                    const box = document.getElementById('auth-pat-once-result-box');
                    const tok = (document.getElementById('auth-pat-once-token-value')?.textContent || '').trim();
                    const cnt = (document.getElementById('auth-pat-count-val')?.textContent || '').trim();
                    const rows = Array.from(document.querySelectorAll('#auth-pat-list .item-row'));
                    if (!box || getComputedStyle(box).display === 'none' || !tok.startsWith('cmcp_') || cnt !== '1' || rows.length !== 1) {
                        return false;
                    }
                    return {
                        token: tok,
                        count: cnt,
                        rowText: rows[0].textContent || '',
                        hasRevokeBtn: Boolean(rows[0].querySelector('.auth-revoke-pat-btn')),
                    };
                }""",
                description="Inline PAT minted and listed in #auth-pat-list",
            )
            assert minted_ui["token"].startswith("cmcp_")
            assert "鉴权页内联CLI密钥" in minted_ui["rowText"]
            assert "仅只读权限" in minted_ui["rowText"]
            assert minted_ui["hasRevokeBtn"] is True

            driver.evaluate(
                """() => {
                    window.__copiedHistory = [];
                    document.getElementById('auth-copy-pat-token-btn').click();
                }"""
            )
            copied_pat = driver.wait_until(
                "() => (window.__copiedHistory && window.__copiedHistory.length >= 1) ? window.__copiedHistory[0] : false",
                description="Inline PAT token copied",
            )
            assert copied_pat == minted_ui["token"]

            # Revoke single PAT directly from `#auth-pat-list` -> count returns to 0 and once-box clears
            driver.evaluate("() => document.querySelector('#auth-pat-list .auth-revoke-pat-btn').click()")
            revoked_ui = driver.wait_until(
                """() => {
                    const cnt = (document.getElementById('auth-pat-count-val')?.textContent || '').trim();
                    const box = document.getElementById('auth-pat-once-result-box');
                    const rows = document.querySelectorAll('#auth-pat-list .item-row');
                    if (cnt !== '0' || rows.length !== 0) return false;
                    return {
                        onceHidden: getComputedStyle(box).display === 'none',
                        onceCleared: (document.getElementById('auth-pat-once-token-value')?.textContent || '') === '',
                    };
                }""",
                description="Inline PAT revoked and once-box cleared",
            )
            assert revoked_ui["onceHidden"] is True
            assert revoked_ui["onceCleared"] is True

            # 5) Verify `pollOnce()` live refresh (`dynamic_pair_code`, `consent_pair_code`, `pat_count`)
            #    AND `state_revision` full `/api/studio/state` sync + `env_locks` explicit banner
            ext_ws_str = str(ext_ws_dir.resolve())
            driver.evaluate(
                """(extWs) => {
                    window.__stateSyncCalls = 0;
                    window.__mockRev = null;
                    window.__mockPollDyn = '909192';
                    window.__mockPollVer = 'Z8Q4';
                    window.__mockPatCount = 3;
                    const prevFetch = window.fetch.bind(window);
                    window.fetch = async (url, opts) => {
                        const u = String(url || '');
                        const resp = await prevFetch(url, opts);
                        if (u.includes('/api/studio/poll')) {
                            const doc = await resp.json();
                            if (window.__mockRev) doc.state_revision = window.__mockRev;
                            doc.dynamic_pair_code = window.__mockPollDyn;
                            doc.consent_pair_code = window.__mockPollVer;
                            doc.pat_count = window.__mockPatCount;
                            return new Response(JSON.stringify(doc), {
                                status: 200,
                                headers: { 'Content-Type': 'application/json' },
                            });
                        }
                        if (u.includes('/api/studio/state')) {
                            window.__stateSyncCalls += 1;
                            const doc = await resp.json();
                            if (window.__mockRev) doc.state_revision = window.__mockRev;
                            doc.workspaces = doc.workspaces || {};
                            const roots = Array.isArray(doc.workspaces.roots) ? doc.workspaces.roots.slice() : [];
                            if (!roots.includes(extWs)) roots.push(extWs);
                            doc.workspaces.roots = roots;
                            doc.env_locks = {
                                permission_tier: {
                                    env_var: 'COSMOS_MCP_PERMISSION_TIER',
                                    reason: '由启动环境变量锁定',
                                },
                            };
                            return new Response(JSON.stringify(doc), {
                                status: 200,
                                headers: { 'Content-Type': 'application/json' },
                            });
                        }
                        return resp;
                    };
                }""",
                ext_ws_str,
            )

            # First poll establishes baseline `rev_base_1` (or triggers sync if boot already had another state_revision)
            driver.trigger_poll()
            poll_live = driver.wait_until(
                """() => {
                    const p = document.getElementById('auth-pair-code-val')?.textContent.trim();
                    const v = document.getElementById('auth-verify-code-val')?.textContent.trim();
                    const c = document.getElementById('auth-pat-count-val')?.textContent.trim();
                    return (p === '909192' && v === 'Z8Q4' && c === '3') ? { p, v, c } : false;
                }""",
                description="pollOnce updates dynamic_pair_code, consent_pair_code, and pat_count",
            )
            assert poll_live == {"p": "909192", "v": "Z8Q4", "c": "3"}

            # Advance `state_revision` to `rev_next_2` -> `pollOnce()` MUST fetch `/api/studio/state` & `renderAll`
            driver.evaluate(
                """() => {
                    window.__stateSyncCalls = 0;
                    window.__mockRev = 'rev_next_2';
                }"""
            )
            driver.trigger_poll()
            rev_sync = driver.wait_until(
                """(extName) => {
                    if ((window.__stateSyncCalls || 0) < 1) return false;
                    const wsText = document.getElementById('workspace-roots-list')?.textContent || '';
                    const toolsBanner = document.getElementById('settings-env-lock-tools');
                    const wbBanner = document.getElementById('wb-env-lock-banner');
                    if (!wsText.includes(extName) || !toolsBanner || !wbBanner) return false;
                    if (getComputedStyle(wbBanner).display === 'none') return false;
                    return {
                        stateSyncCalls: window.__stateSyncCalls,
                        wbLockText: wbBanner.textContent.trim(),
                        toolsLockText: toolsBanner.textContent.trim(),
                        roSafetyDisabled: Boolean(document.querySelector('#safety-mode-cards [data-target-safety="readonly"]')?.disabled),
                    };
                }""",
                arg=ext_ws_dir.name,
                description="state_revision change triggers full /api/studio/state sync and renders env_locks banner",
            )
            assert rev_sync["stateSyncCalls"] >= 1
            assert "COSMOS_MCP_PERMISSION_TIER" in rev_sync["wbLockText"]
            assert "由启动环境变量锁定，需修改启动环境并重启后更改" in rev_sync["wbLockText"]
            assert "COSMOS_MCP_PERMISSION_TIER" in rev_sync["toolsLockText"]
            assert rev_sync["roSafetyDisabled"] is True

            assert driver.get_runtime_diagnostics()["jsErrors"] == []


