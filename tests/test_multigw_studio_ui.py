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
            assert d_sh["gateways"]["self_hosted"]["mcp_url"] == "https://mcp.my-own-box.example.com/mcp"

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
    """Verify ChatGPT primary open-plugins & secondary diagnostic copy buttons, showcase host-prefix copy, and /tutorials sync."""
    at_sym = chr(64)
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
        # Phase 1: Gateway is starting (NOT ready yet) -> both primary & secondary buttons MUST stay disabled
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
                    const ofull = document.getElementById('open-chatgpt-plugins-full-btn');
                    const oro = document.getElementById('open-chatgpt-plugins-ro-btn');
                    const afull = document.getElementById('copy-chatgpt-assist-full-btn');
                    const aro = document.getElementById('copy-chatgpt-assist-ro-btn');
                    if (!ofull || !oro || !afull || !aro) return false;
                    if (ofull.disabled !== true || oro.disabled !== true || afull.disabled !== true || aro.disabled !== true) {
                        return false;
                    }
                    return {
                        openFullText: ofull.textContent.trim(),
                        openRoText: oro.textContent.trim(),
                        assistFullText: afull.textContent.trim(),
                        assistRoText: aro.textContent.trim(),
                    };
                }""",
                description="ChatGPT primary & assist buttons disabled while gateway not ready",
            )
            assert btn_meta_initial["openFullText"] == "复制地址并打开 ChatGPT 插件页"
            assert btn_meta_initial["openRoText"] == "复制地址并打开 ChatGPT 插件页"
            assert btn_meta_initial["assistFullText"] == "复制给 ChatGPT 接入 / 排障"
            assert btn_meta_initial["assistRoText"] == "复制给 ChatGPT 接入 / 排障"

            # Phase 2: Gateway becomes ready -> buttons unlock, stub window.open, verify pure URL copy & diagnostic copy
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
                    const ofull = document.getElementById('open-chatgpt-plugins-full-btn');
                    const oro = document.getElementById('open-chatgpt-plugins-ro-btn');
                    const afull = document.getElementById('copy-chatgpt-assist-full-btn');
                    const aro = document.getElementById('copy-chatgpt-assist-ro-btn');
                    return Boolean(
                        ofull && oro && afull && aro &&
                        ofull.disabled === false && oro.disabled === false &&
                        afull.disabled === false && aro.disabled === false
                    );
                }""",
                description="ChatGPT primary & assist buttons enabled once gateway ready",
            )

            secret_meta = driver.evaluate(
                """() => ({
                    pair4: (document.getElementById('pair-code-box')?.textContent || '').trim(),
                    pair6: (document.getElementById('dynamic-pair-code-box')?.textContent || '').trim(),
                    pw: document.getElementById('conn-pw-box')?.getAttribute('data-secret') || '',
                })"""
            )

            # 2a) Primary buttons: stub window.open synchronously & verify pure URL copy without launching external browser
            open_calls = driver.evaluate(
                """() => {
                    window.__copiedHistory = [];
                    const calls = [];
                    const origOpen = window.open;
                    window.open = (...args) => { calls.push(args); return null; };
                    try {
                        document.getElementById('open-chatgpt-plugins-full-btn').click();
                        document.getElementById('open-chatgpt-plugins-ro-btn').click();
                    } finally {
                        window.open = origOpen;
                    }
                    return calls;
                }"""
            )
            assert len(open_calls) == 2
            assert open_calls[0][:3] == ["https://chatgpt.com/plugins", "_blank", "noopener"]
            assert open_calls[1][:3] == ["https://chatgpt.com/plugins", "_blank", "noopener"]

            copied_urls = driver.wait_until(
                "() => (window.__copiedHistory && window.__copiedHistory.length >= 2) ? window.__copiedHistory.slice() : false",
                description="Both pure ChatGPT URLs copied by primary buttons",
            )
            assert copied_urls[0] == "https://cgpt-ready.srv.us/mcp"
            assert copied_urls[1] == "https://cgpt-ready.srv.us/mcp/readonly"

            # 2b) Secondary diagnostic buttons: zero-secret diagnostic prompt
            driver.evaluate(
                """() => {
                    window.__copiedHistory = [];
                    document.getElementById('copy-chatgpt-assist-full-btn').click();
                    document.getElementById('copy-chatgpt-assist-ro-btn').click();
                }"""
            )
            copied_list = driver.wait_until(
                "() => (window.__copiedHistory && window.__copiedHistory.length >= 2) ? window.__copiedHistory.slice() : false",
                description="Both ChatGPT diagnostic prompts copied",
            )
            full_prompt, ro_prompt = copied_list[0], copied_list[1]

            for p in (full_prompt, ro_prompt):
                assert p.splitlines()[0] == "请帮我把 WebAI2PC 接入我当前选中的 ChatGPT 工作区/账号，并完成首次真实调用。"
                assert "认证方式：OAuth" in p
                assert "不要默认打开云浏览器，也不要新建中转服务" in p
                assert "https://chatgpt.com/plugins" in p
                assert "Create plugins with MCPs" in p
                assert "找到 pc_get_status 或 get_status，用实际参数调用一次" in p
                assert "能分别在 Chat 和 Work 验证就分别验证" in p
                assert f"{at_sym}WebAI2PC" in p

            assert "MCP 地址：https://cgpt-ready.srv.us/mcp\n" in full_prompt
            assert "ChatGPT Team / Business / Enterprise / Edu 工作区，授权后可在 Chat 和 Work 中通过" in full_prompt

            assert "MCP 地址：https://cgpt-ready.srv.us/mcp/readonly\n" in ro_prompt
            assert f"ChatGPT Plus / Pro，授权后可在 Chat 和 Work 中通过 {at_sym}WebAI2PC 使用该服务提供的只读工具。" in ro_prompt

            for p in (full_prompt, ro_prompt):
                assert p.splitlines()[-1] == "【安全提醒：上方包含本机专属连接地址，仅限粘贴给本人登录的账号使用，请勿发往微信群、论坛、公开 Issue 或转给他人。】"

            toast_text = driver.evaluate("() => (document.getElementById('toast-banner')?.textContent || '').trim()")
            assert "仅限填入本人账号，请勿外发给他人或群聊" in toast_text
            assert toast_text == "已复制 ChatGPT 接入与排障指令（仅限填入本人账号，请勿外发给他人或群聊；不含配对码与本机路径）"

            # Strict zero-secret / zero-local-path leak checks
            for secret_val in (secret_meta["pair4"], secret_meta["pair6"], secret_meta["pw"], str(ws_dir)):
                if secret_val and secret_val not in ("----", "------"):
                    assert secret_val not in full_prompt
                    assert secret_val not in ro_prompt

            # 2c) Showcase 1-click prompt button adapts prefix between Gemini (`@Cosmos `) and ChatGPT (`@WebAI2PC `)
            driver.select_host_scene("gemini")
            driver.evaluate(
                """() => {
                    const det = document.getElementById('showcase-prompts-details');
                    if (det) det.open = true;
                    window.__copiedHistory = [];
                    document.getElementById('copy-showcase-blackhole-btn').click();
                }"""
            )
            gem_showcase = driver.wait_until(
                "() => (window.__copiedHistory && window.__copiedHistory.length >= 1) ? window.__copiedHistory[0] : false",
                description="Gemini showcase prompt copied",
            )
            assert gem_showcase.startswith(f"{at_sym}Cosmos ")
            assert "blackhole_studio.html" in gem_showcase

            driver.select_host_scene("chatgpt")
            driver.evaluate(
                """() => {
                    window.__copiedHistory = [];
                    document.getElementById('copy-showcase-blackhole-btn').click();
                }"""
            )
            cgpt_showcase = driver.wait_until(
                "() => (window.__copiedHistory && window.__copiedHistory.length >= 1) ? window.__copiedHistory[0] : false",
                description="ChatGPT showcase prompt copied",
            )
            assert cgpt_showcase.startswith(f"{at_sym}WebAI2PC ")
            assert "blackhole_studio.html" in cgpt_showcase

            # 3) Verify `/tutorials` Module 2 primary & secondary buttons unlock on live sync and stub window.open cleanly
            driver.goto(f"{srv.base_url}/tutorials", wait_studio_ready=False)
            tut_meta = driver.wait_until(
                """() => {
                    const openBtn = document.querySelector('[data-open-chatgpt-plugins="readonly"]');
                    const assistBtn = document.querySelector('[data-copy-chatgpt-assist="readonly"]');
                    if (!openBtn || !assistBtn || openBtn.disabled !== false || assistBtn.disabled !== false) {
                        return false;
                    }
                    return {
                        openText: openBtn.textContent.trim(),
                        assistText: assistBtn.textContent.trim(),
                    };
                }""",
                timeout_sec=8.0,
                description="Tutorials ChatGPT primary & assist buttons unlocked on live sync",
            )
            assert tut_meta["openText"] == "复制地址并打开 ChatGPT 插件页"
            assert tut_meta["assistText"] == "复制给 ChatGPT 接入 / 排障"

            tut_open_calls = driver.evaluate(
                """() => {
                    window.__copiedHistory = [];
                    const calls = [];
                    const origOpen = window.open;
                    window.open = (...args) => { calls.push(args); return null; };
                    try {
                        document.querySelector('[data-open-chatgpt-plugins="readonly"]').click();
                    } finally {
                        window.open = origOpen;
                    }
                    return calls;
                }"""
            )
            assert len(tut_open_calls) == 1
            assert tut_open_calls[0][:3] == ["https://chatgpt.com/plugins", "_blank", "noopener"]
            tut_copied_url = driver.wait_until(
                "() => (window.__copiedHistory && window.__copiedHistory.length >= 1) ? window.__copiedHistory[0] : false",
                description="Tutorials primary button copied readonly URL",
            )
            assert tut_copied_url == "https://cgpt-ready.srv.us/mcp/readonly"

            driver.evaluate(
                """() => {
                    window.__copiedHistory = [];
                    document.querySelector('[data-copy-chatgpt-assist="readonly"]').click();
                }"""
            )
            tut_copied_assist = driver.wait_until(
                "() => (window.__copiedHistory && window.__copiedHistory.length >= 1) ? window.__copiedHistory[0] : false",
                description="Tutorials ChatGPT diagnostic prompt copied",
            )
            assert tut_copied_assist.splitlines()[0] == "请帮我把 WebAI2PC 接入我当前选中的 ChatGPT 工作区/账号，并完成首次真实调用。"
            assert "不要默认打开云浏览器，也不要新建中转服务" in tut_copied_assist
            assert "https://chatgpt.com/plugins" in tut_copied_assist
            assert "Create plugins with MCPs" in tut_copied_assist
            assert "找到 pc_get_status 或 get_status，用实际参数调用一次" in tut_copied_assist
            assert "MCP 地址：https://cgpt-ready.srv.us/mcp/readonly\n" in tut_copied_assist
            assert tut_copied_assist == ro_prompt
            assert driver.get_runtime_diagnostics()["jsErrors"] == []
