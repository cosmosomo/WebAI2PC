"""Comprehensive regression tests for the 8 Studio & connection architecture fixes (`fix/dogma-pkg2-studio`)."""
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, Dict

import httpx
import pytest
from starlette.testclient import TestClient

from _studio_driver import LiveStudioServer, StudioPageDriver
from cosmos_mcp.core.config import (
    LiveRuntimePolicy,
    ensure_initialized,
    load_endpoint_secret,
)
from cosmos_mcp.core.fs_tx import atomic_write_json, atomic_write_text
from cosmos_mcp.launcher import bootstrap, cf_workers_gateway as cfgw, daemon, doctor, updater
from cosmos_mcp.protocol.dispatcher import KernelDispatcher
from cosmos_mcp.protocol.oauth import OAuthProvider, OAuthSQLiteStore
from cosmos_mcp.protocol.transport import create_protocol_app
from cosmos_mcp.studio.routes import _persist_extra_studio_config


REPO_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# 1. Config Fields, 4-File Projection Sync & Annotation Mode Persistence
# ---------------------------------------------------------------------------


def test_fix1_policy_fields_four_config_consolidation_and_annotation_modes(tmp_path: Path) -> None:
    st_root = tmp_path / "st_fix1"
    ws_dir = tmp_path / "ws_fix1"
    ws_dir.mkdir(parents=True)

    init_res = ensure_initialized(
        product_root=st_root,
        cli_state_dir=str(st_root),
        port=18961,
        workspace_roots=[str(ws_dir)],
    )
    assert init_res["redact_project_secrets"] is False
    assert init_res["enable_oneclick_token_route"] is False

    # Seed legacy secondary files with stale `public_url` & `workers_custom_domain`
    legacy_svc_cfg = st_root / "config" / "service_config.json"
    state_svc = st_root / "state" / "service.json"
    root_cfg = st_root / "config.json"
    stale_doc = {
        "public_url": "https://stale-ghost.trycloudflare.com",
        "public_base": "https://stale-ghost.trycloudflare.com",
        "workers_custom_domain": "stale.example.com",
        "workers_dev_custom_domain": "stale.example.com",
    }
    for p in (legacy_svc_cfg, state_svc, root_cfg):
        atomic_write_json(p, dict(stale_doc))

    policy = LiveRuntimePolicy(
        state_root=st_root,
        workspace_roots=[ws_dir],
        cfg_path=st_root / "config" / "service.json",
    )
    assert policy.redact_project_secrets is False
    assert policy.enable_oneclick_token_route is False

    # Toggle new boolean policy fields and clear custom domain / public_url
    policy.persist_changes(
        redact_project_secrets=True,
        enable_oneclick_token_route=True,
        workers_dev_custom_domain="",
        extra_patch={"public_base": ""},
    )
    assert policy.redact_project_secrets is True
    assert policy.enable_oneclick_token_route is True
    if policy.guard is not None:
        assert getattr(policy.guard, "redact_project_secrets", None) is True

    # Verify all secondary config projections were overwritten and cleared
    for sec_p in (legacy_svc_cfg, state_svc, root_cfg):
        sec_doc = json.loads(sec_p.read_text(encoding="utf-8"))
        assert sec_doc["public_base"] == ""
        assert sec_doc["public_url"] == ""
        assert sec_doc["workers_custom_domain"] == ""
        assert sec_doc["redact_project_secrets"] is True
        assert sec_doc["enable_oneclick_token_route"] is True

    # Even if someone manually pollutes `service_config.json`, `_read_merged_service_config` prioritizes `config/service.json`
    atomic_write_json(
        legacy_svc_cfg,
        {
            "public_url": "https://resurrected-bad.example.com",
            "public_base": "https://resurrected-bad.example.com",
            "workers_custom_domain": "bad.example.com",
        },
    )
    merged_cf = cfgw._read_merged_service_config(st_root, "pc")
    assert merged_cf.get("public_base") == ""
    assert merged_cf.get("workers_dev_custom_domain") == ""

    # Verify `_persist_extra_studio_config` preserves all 4 annotation_mode strings verbatim on disk
    for mode_val, expected_popups in (
        ("seamless", False),
        ("compat", False),
        ("strict", True),
        ("honest", True),
    ):
        _persist_extra_studio_config(policy, annotation_mode=mode_val)
        on_disk = json.loads((st_root / "config" / "service.json").read_text(encoding="utf-8"))
        assert on_disk["annotation_mode"] == mode_val
        assert policy.approval_popups is expected_popups


# ---------------------------------------------------------------------------
# 2. Startup Scripts `COSMOS_REPO_SRC` & Studio Restart `app_src` Sync
# ---------------------------------------------------------------------------


def test_fix2_startup_scripts_and_restart_service_sync_repo_src(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bat_txt = (REPO_ROOT / "一键启动_Cosmos_MCP.bat").read_text(encoding="utf-8")
    sh_txt = (REPO_ROOT / "start_cosmos_mcp.sh").read_text(encoding="utf-8")

    # Every Python launch branch in `.bat` (including `.venv`) and `.sh` injects `COSMOS_REPO_SRC` at `sys.path[0]`
    assert 'if exist "%COSMOS_STATE_ROOT%\\.venv\\Scripts\\python.exe"' in bat_txt
    assert bat_txt.count("sys.path.insert(0,p)") >= 8
    assert "-m cosmos_mcp.launcher.cli" not in bat_txt
    assert b"\r\n" in (REPO_ROOT / "一键启动_Cosmos_MCP.bat").read_bytes()
    assert 'export COSMOS_REPO_SRC="${SCRIPT_DIR}/src"' in sh_txt
    assert sh_txt.count("sys.path.insert(0,p)") >= 2
    assert b"\r\n" not in (REPO_ROOT / "start_cosmos_mcp.sh").read_bytes()

    # Simulate a fake git repo checkout + state_root where `app_src` initially has an older file
    fake_repo = tmp_path / "fake_git_repo"
    (fake_repo / ".git").mkdir(parents=True)
    fake_src_pkg = fake_repo / "src" / "cosmos_mcp"
    fake_src_pkg.mkdir(parents=True)
    init_ver = bootstrap.read_package_init_version(REPO_ROOT / "src" / "cosmos_mcp" / "__init__.py")
    atomic_write_text(fake_src_pkg / "__init__.py", f'__version__ = "{init_ver}"\nMARKER = "v_old"\n')

    st_dir = tmp_path / "st_restart_sync"
    ws_dir = tmp_path / "ws_restart_sync"
    ws_dir.mkdir(parents=True)
    bootstrap.sync_portable_app_src(st_dir, source_src_dir=fake_repo / "src")
    assert 'MARKER = "v_old"' in (st_dir / "app_src" / "cosmos_mcp" / "__init__.py").read_text(encoding="utf-8")

    # Developer edits the repo file, then triggers Studio `service-control` `restart` (`signal_only=True`)
    atomic_write_text(fake_src_pkg / "__init__.py", f'__version__ = "{init_ver}"\nMARKER = "v_new_from_repo"\n')
    monkeypatch.setenv("COSMOS_REPO_SRC", str(fake_repo / "src"))

    with LiveStudioServer(st_dir, ws_dir, thread_prefix="fix2-restart") as srv:
        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=10.0) as client:
            csrf = client.get("/api/studio/state").json()["csrf_token"]
            r_res = client.post(
                "/api/studio/service-control",
                headers={"X-Studio-Csrf": csrf, "Origin": srv.base_url},
                json={"action": "restart", "signal_only": True},
            )
            assert r_res.status_code == 200, r_res.text
            res_doc = r_res.json()
            assert res_doc["ok"] is True
            assert Path(res_doc["synced_app_src"]).resolve() == (st_dir / "app_src").resolve()

    synced_txt = (st_dir / "app_src" / "cosmos_mcp" / "__init__.py").read_text(encoding="utf-8")
    assert 'MARKER = "v_new_from_repo"' in synced_txt
    assert (st_dir / "state" / "repo_source.json").is_file()


# ---------------------------------------------------------------------------
# 3 & 4. Instant Policy + 4s Poll Revision Keys + Tokenless CF Custom Domain
# ---------------------------------------------------------------------------


def test_fix3_fix4_poll_revision_keys_instant_policy_and_tokenless_cf_domain(tmp_path: Path) -> None:
    st_dir = tmp_path / "st_fix34"
    ws_dir = tmp_path / "ws_fix34"
    ws_dir.mkdir(parents=True)

    with LiveStudioServer(st_dir, ws_dir, tunnel_mode="public_gateway", thread_prefix="fix34-studio") as srv:
        d_status_p = st_dir / "state" / "daemon_status.json"
        d_doc: Dict[str, Any] = {
            "status": "running",
            "supervisor_pid": 91000,
            "port": srv.port,
            "mode": "public_gateway",
            "effective_tunnel_mode": "srv_us",
            "public_url": "",
            "tunnel_ready": False,
            "gateways": {
                "instant": {
                    "enabled": True,
                    "submode": "public_gateway",
                    "effective_mode": "srv_us",
                    "instant_policy": "auto",
                    "trycloudflare_backup": False,
                    "phase": "probing",
                    "tunnel_ready": False,
                    "public_url": "",
                    "last_error": "",
                    "subchannels": {
                        "srv_us": {"role": "primary", "enabled": True, "status": "connecting", "public_url": "", "last_error": ""},
                        "trycloudflare": {"role": "backup", "enabled": False, "status": "disabled", "public_url": "", "last_error": ""},
                    },
                }
            },
        }
        atomic_write_json(d_status_p, d_doc)

        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=10.0) as client:
            st0 = client.get("/api/studio/state").json()
            csrf = st0["csrf_token"]
            rev0 = st0["state_revision"]

            # Subchannel error / status change MUST bump `state_revision` on `/api/studio/poll`
            d_doc["gateways"]["instant"]["last_error"] = "ssh handshake timeout"
            d_doc["gateways"]["instant"]["subchannels"]["srv_us"]["status"] = "error"
            d_doc["gateways"]["instant"]["subchannels"]["srv_us"]["last_error"] = "ssh handshake timeout"
            atomic_write_json(d_status_p, d_doc)
            rev1 = client.get("/api/studio/poll").json()["state_revision"]
            assert rev1 != rev0

            # Backup subchannel connecting / becoming ready MUST bump `state_revision`
            d_doc["gateways"]["instant"]["trycloudflare_backup"] = True
            d_doc["gateways"]["instant"]["subchannels"]["trycloudflare"] = {
                "role": "backup",
                "enabled": True,
                "status": "ready",
                "public_url": "https://sub-ready.trycloudflare.com",
                "last_error": "",
            }
            atomic_write_json(d_status_p, d_doc)
            rev2 = client.get("/api/studio/poll").json()["state_revision"]
            assert rev2 != rev1

            # Set `instant_policy` -> `srv_us_only` via Studio connection API
            r_pol = client.post(
                "/api/studio/connection",
                headers={"X-Studio-Csrf": csrf, "Origin": srv.base_url},
                json={"action": "set_instant_policy", "instant_policy": "srv_us_only"},
            )
            assert r_pol.status_code == 200
            pol_doc = r_pol.json()
            assert pol_doc["gateways"]["instant"]["instant_policy"] == "srv_us_only"
            assert pol_doc["state_revision"] != rev2

            # Seed an already-deployed Cloudflare Worker (tunnel secret present, API token shredded)
            wt_sec_p = cfgw.workers_tunnel_secret_path(st_dir, prefix="pc")
            atomic_write_text(wt_sec_p, "a" * 64 + "\n", mode_override=0o600)
            _persist_extra_studio_config(
                srv.app.state.policy,
                workers_dev_url="https://cosmos-node123.demo.workers.dev",
                workers_dev_subdomain="demo",
                workers_dev_script_name="cosmos-node123",
            )

            # Save custom domain WITHOUT API token
            r_dom_save = client.post(
                "/api/studio/connection",
                headers={"X-Studio-Csrf": csrf, "Origin": srv.base_url},
                json={"action": "save_workers_custom_domain", "custom_domain": "mcp.custom-zone.example.com"},
            )
            assert r_dom_save.status_code == 200, r_dom_save.text
            d_saved = r_dom_save.json()
            assert d_saved["connection"]["workers_deployed"] is True
            assert d_saved["connection"]["workers_dev_custom_domain"] == "mcp.custom-zone.example.com"
            assert d_saved["connection"]["workers_dev_url"] == "https://cosmos-node123.demo.workers.dev"
            assert d_saved["gateways"]["workers_dev"]["configured_url"] == "https://mcp.custom-zone.example.com"

            # Clear custom domain WITHOUT API token -> restores raw `*.workers.dev` and does NOT resurrect from secondary files
            r_dom_clr = client.post(
                "/api/studio/connection",
                headers={"X-Studio-Csrf": csrf, "Origin": srv.base_url},
                json={"action": "clear_workers_custom_domain"},
            )
            assert r_dom_clr.status_code == 200, r_dom_clr.text
            d_cleared = r_dom_clr.json()
            assert d_cleared["connection"]["workers_dev_custom_domain"] == ""
            assert d_cleared["gateways"]["workers_dev"]["configured_url"] == "https://cosmos-node123.demo.workers.dev"


# ---------------------------------------------------------------------------
# 5. ChatGPT One-Click Selected Gateway + PNG Import `self_hosted` + Secret Rotate
# ---------------------------------------------------------------------------


def test_fix5_chatgpt_oneclick_selected_gateway_png_import_and_secret_rotation(tmp_path: Path) -> None:
    st_src = tmp_path / "st_png_src"
    ws_dir = tmp_path / "ws_fix5"
    ws_dir.mkdir(parents=True)

    with LiveStudioServer(st_src, ws_dir, tunnel_mode="public_gateway", thread_prefix="fix5-studio") as srv:
        # Both `instant` (`srv.us`) AND `workers_dev` are online and ready
        wt_sec_p = cfgw.workers_tunnel_secret_path(st_src, prefix="pc")
        atomic_write_text(wt_sec_p, "b" * 64 + "\n", mode_override=0o600)
        _persist_extra_studio_config(
            srv.app.state.policy,
            workers_dev_url="https://cosmos-raw.sub.workers.dev",
            workers_dev_custom_domain="mcp.my-custom.dev",
            vps_hub_url="https://hub.selfhosted.example.com",
        )
        srv.app.state.policy.update_gateway_slot(
            "workers_dev",
            enabled=True,
            submode="workers_dev",
            public_url="https://mcp.my-custom.dev",
            extra_fields={"workers_dev_url": "https://cosmos-raw.sub.workers.dev", "custom_domain": "https://mcp.my-custom.dev"},
        )
        srv.app.state.policy.update_gateway_slot(
            "self_hosted",
            enabled=True,
            submode="vps_hub",
            public_url="https://hub.selfhosted.example.com",
        )
        atomic_write_json(
            st_src / "state" / "daemon_status.json",
            {
                "status": "running",
                "supervisor_pid": 92000,
                "port": srv.port,
                "mode": "public_gateway",
                "effective_tunnel_mode": "srv_us",
                "public_url": "https://user-picked.srv.us",
                "tunnel_ready": True,
                "srvus_fixed_active": True,
                "gateways": {
                    "instant": {
                        "enabled": True,
                        "submode": "public_gateway",
                        "effective_mode": "srv_us",
                        "phase": "ready",
                        "tunnel_ready": True,
                        "public_url": "https://user-picked.srv.us",
                        "srvus_fixed_active": True,
                    },
                    "workers_dev": {
                        "enabled": True,
                        "submode": "workers_dev",
                        "effective_mode": "workers_dev",
                        "phase": "ready",
                        "tunnel_ready": True,
                        "public_url": "https://mcp.my-custom.dev",
                    },
                    "self_hosted": {
                        "enabled": True,
                        "submode": "vps_hub",
                        "effective_mode": "vps_hub",
                        "phase": "ready",
                        "tunnel_ready": True,
                        "public_url": "https://hub.selfhosted.example.com",
                    },
                },
            },
        )

        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=10.0) as client:
            csrf = client.get("/api/studio/state").json()["csrf_token"]

            # User explicitly selects `instant` (`srv.us`) -> `chatgpt-oneclick` MUST use `instant`, NOT `workers_dev`!
            r_sel = client.post(
                "/api/studio/connection",
                headers={"X-Studio-Csrf": csrf, "Origin": srv.base_url},
                json={"action": "select_copy_gateway", "gateway_id": "instant"},
            )
            assert r_sel.status_code == 200

            r_oc = client.post(
                "/api/studio/chatgpt-oneclick",
                headers={"X-Studio-Csrf": csrf, "Origin": srv.base_url},
                json={"kind": "mcp", "rotate": False},
            )
            assert r_oc.status_code == 200
            oc_doc = r_oc.json()
            assert oc_doc["gateway_id"] == "instant"
            assert oc_doc["mcp_url"] == "https://user-picked.srv.us/mcp"
            assert "https://user-picked.srv.us/mcp" in oc_doc["prompt"]

            # Rotating endpoint secret MUST NOT overwrite `workers_dev_url` with `mcp.my-custom.dev` AND must update `self_hosted`
            r_rot = client.post(
                "/api/studio/connection",
                headers={"X-Studio-Csrf": csrf, "Origin": srv.base_url},
                json={"action": "rotate_endpoint_secret", "revoke_sessions": False},
            )
            assert r_rot.status_code == 200
            ep_sec = load_endpoint_secret(st_src, prefix="pc")
            assert len(ep_sec) >= 16
            cfg_rot = json.loads((st_src / "config" / "service.json").read_text(encoding="utf-8"))
            assert cfg_rot["workers_dev_url"] == f"https://cosmos-raw.sub.workers.dev/u/{ep_sec}"
            assert cfg_rot["gateways"]["workers_dev"]["public_url"] == f"https://mcp.my-custom.dev/u/{ep_sec}"
            assert cfg_rot["gateways"]["self_hosted"]["public_url"] == f"https://hub.selfhosted.example.com/u/{ep_sec}"
            assert cfg_rot["vps_hub_url"] == f"https://hub.selfhosted.example.com/u/{ep_sec}"

            # Disabling endpoint secret cleanly strips `/u/<ep_sec>` from both while keeping raw `workers_dev_url`
            r_dis = client.post(
                "/api/studio/connection",
                headers={"X-Studio-Csrf": csrf, "Origin": srv.base_url},
                json={"action": "disable_endpoint_secret"},
            )
            assert r_dis.status_code == 200
            cfg_dis = json.loads((st_src / "config" / "service.json").read_text(encoding="utf-8"))
            assert cfg_dis["workers_dev_url"] == "https://cosmos-raw.sub.workers.dev"
            assert cfg_dis["gateways"]["workers_dev"]["public_url"] == "https://mcp.my-custom.dev"
            assert cfg_dis["gateways"]["self_hosted"]["public_url"] == "https://hub.selfhosted.example.com"

            # Export recovery card when `self_hosted` (`vps_hub`) is selected, then import into a fresh state root
            srv.app.state.policy.persist_changes(tunnel_mode="vps_hub", selected_gateway="self_hosted")
            r_exp = client.post(
                "/api/studio/identity/export_png",
                headers={"X-Studio-Csrf": csrf, "Origin": srv.base_url},
                json={"passphrase": "Recover-Pass-2026!"},
            )
            assert r_exp.status_code == 200
            png_b64 = r_exp.json()["png_base64"]
            assert len(base64.b64decode(png_b64)) > 64

    st_dst = tmp_path / "st_png_dst"
    ws_dst = tmp_path / "ws_png_dst"
    ws_dst.mkdir(parents=True)
    with LiveStudioServer(st_dst, ws_dst, tunnel_mode="public_gateway", thread_prefix="fix5-import") as srv_dst:
        sync_called = {"count": 0}
        srv_dst.app.state.gateway_sync_hook_box = [lambda *_a: sync_called.__setitem__("count", sync_called["count"] + 1)]
        with httpx.Client(base_url=srv_dst.base_url, trust_env=False, timeout=10.0) as client_dst:
            csrf_dst = client_dst.get("/api/studio/state").json()["csrf_token"]
            r_imp = client_dst.post(
                "/api/studio/identity/import_png",
                headers={"X-Studio-Csrf": csrf_dst, "Origin": srv_dst.base_url},
                json={"passphrase": "Recover-Pass-2026!", "png_base64": png_b64},
            )
            assert r_imp.status_code == 200, r_imp.text
            imp_doc = r_imp.json()
            assert imp_doc["gateways"]["self_hosted"]["enabled"] is True
            assert imp_doc["gateways"]["self_hosted"]["configured_url"] == "https://hub.selfhosted.example.com"
            assert sync_called["count"] >= 1


# ---------------------------------------------------------------------------
# 6, 7 & 8. Headless UI & API Verification: Unlock Meta CSRF, Wipe Password,
#           Oneclick Route Switch, Skills Sync, Updater API & Uninstall Cleanup
# ---------------------------------------------------------------------------


def test_fix6_fix7_fix8_ui_csrf_sync_password_redaction_update_and_uninstall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Check `[at]Cosmos` is completely absent from `index.html`
    html_src = (REPO_ROOT / "src" / "cosmos_mcp" / "studio" / "static" / "index.html").read_text(encoding="utf-8")
    assert "[at]Cosmos" not in html_src
    assert "@连接器名称" in html_src

    st_dir = tmp_path / "st_fix678"
    ws_dir = tmp_path / "ws_fix678"
    ws_dir.mkdir(parents=True)

    # Stub updater functions to verify `/api/studio/update` check & apply without network
    monkeypatch.setattr(
        updater,
        "check_for_updates",
        lambda state_root, **kw: {
            "ok": True,
            "current_version": "1.2.1",
            "latest_version": "1.2.9",
            "update_available": True,
            "tunnel_impact": {"url_changes_on_full_restart": False},
        },
    )
    monkeypatch.setattr(
        updater,
        "stage_and_apply_update",
        lambda state_root, **kw: {
            "ok": True,
            "status": "handoff_scheduled",
            "from_version": "1.2.1",
            "to_version": "1.2.9",
            "restart_mode": "worker_hot_reload",
            "message": "已调度平滑升级至 v1.2.9",
        },
    )

    with LiveStudioServer(st_dir, ws_dir, tunnel_mode="public_gateway", thread_prefix="fix678-studio") as srv:
        # Extract real owner password via loopback `reveal_password`, while `GET /api/studio/state` returns `""`
        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=10.0) as client:
            st_init = client.get("/api/studio/state").json()
            csrf = st_init["csrf_token"]
            assert st_init["connection"]["connection_password"] == ""
            assert st_init["connection"]["has_saved_password"] is True
            rev_resp = client.post(
                "/api/studio/connection",
                headers={"X-Studio-Csrf": csrf, "Origin": srv.base_url},
                json={"action": "reveal_password"},
            ).json()
            owner_pw = rev_resp["connection_password"]
            assert len(owner_pw) >= 16

            # Test `/api/studio/update` check & apply
            r_uchk = client.post(
                "/api/studio/update",
                headers={"X-Studio-Csrf": csrf, "Origin": srv.base_url},
                json={"action": "check"},
            )
            assert r_uchk.status_code == 200
            assert r_uchk.json()["update_available"] is True
            assert r_uchk.json()["latest_version"] == "1.2.9"

            r_uapp = client.post(
                "/api/studio/update",
                headers={"X-Studio-Csrf": csrf, "Origin": srv.base_url},
                json={"action": "apply"},
            )
            assert r_uapp.status_code == 200
            assert r_uapp.json()["to_version"] == "1.2.9"

        # Verify refreshless remote unlock updates `<meta name="studio-csrf">` and removes duplicate drawer strip in Chromium
        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=10.0) as rem_http:
            r_rem_html = rem_http.get(
                "/studio",
                headers={"Accept": "text/html", "X-Forwarded-For": "203.0.113.9"},
            )
            assert r_rem_html.status_code == 200
            assert '<meta name="studio-csrf" content="' in r_rem_html.text
            assert "__STUDIO_CSRF__" not in r_rem_html.text

        with StudioPageDriver(tmp_path / "cdp_fix678") as driver:
            driver.set_viewport(1440, 900, mobile=False, device_scale_factor=1)
            driver.goto(f"{srv.base_url}/")

            dom_check = driver.evaluate(
                """() => ({
                    metaCsrf: (document.querySelector('meta[name="studio-csrf"]') || {}).content || '',
                    hasDupStrip: Boolean(document.getElementById('cosmos-anti-share-strip')),
                    hasInstantPolicy: Boolean(document.getElementById('instant-policy-select')),
                    hasAuthWipeBtn: Boolean(document.getElementById('auth-wipe-plaintext-pw-btn')),
                    hasOneclickChk: Boolean(document.getElementById('chk-enable-oneclick-route')),
                    hasCheckUpdateBtn: Boolean(document.getElementById('check-update-btn')),
                    hasWebCompatChk: Boolean(document.getElementById('chk-web-compat-mode')),
                    hasRedactChk: Boolean(document.getElementById('chk-redact-project-secrets')),
                    hasSkillsScanChk: Boolean(document.getElementById('chk-skills-scan-host')),
                })"""
            )
            assert dom_check["metaCsrf"] == csrf
            assert dom_check["hasDupStrip"] is False
            assert dom_check["hasInstantPolicy"] is True
            assert dom_check["hasAuthWipeBtn"] is True
            assert dom_check["hasOneclickChk"] is True
            assert dom_check["hasCheckUpdateBtn"] is True
            assert dom_check["hasWebCompatChk"] is True
            assert dom_check["hasRedactChk"] is True
            assert dom_check["hasSkillsScanChk"] is True

            # Simulate locked boot CSRF in `<meta name="studio-csrf">`, then call `renderAll` on `/api/studio/unlock`
            # and verify `<meta name="studio-csrf">` dynamically updates to `local_admin_csrf`!
            synced_meta = driver.evaluate(
                f"""async () => {{
                    const meta = document.querySelector('meta[name="studio-csrf"]');
                    meta.setAttribute('content', 'stale_locked_csrf');
                    const r = await fetch('/api/studio/unlock', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json', 'X-Studio-Csrf': {json.dumps(csrf)} }},
                        body: JSON.stringify({{ owner_password: {json.dumps(owner_pw)}, csrf: {json.dumps(csrf)} }})
                    }});
                    const d = await r.json();
                    document.getElementById('session-pw-input').value = {json.dumps(owner_pw)};
                    document.getElementById('session-unlock-form').dispatchEvent(new Event('submit', {{ cancelable: true }}));
                    return {{ unlockOk: d.ok }};
                }}"""
            )
            assert synced_meta["unlockOk"] is True
            updated_meta = driver.wait_until(
                """() => {
                    const c = document.querySelector('meta[name="studio-csrf"]')?.getAttribute('content') || '';
                    return (c && c !== 'stale_locked_csrf') ? c : false;
                }""",
                description="meta[name='studio-csrf'] refreshed after unlock",
            )
            assert updated_meta == csrf

            # Toggle `#chk-skills-scan-host` in `#settings-pane-skills` and verify `#chk-scan-host-skills` syncs
            driver.open_settings("skills")
            driver.evaluate(
                """() => {
                    const skChk = document.getElementById('chk-skills-scan-host');
                    skChk.checked = true;
                    skChk.dispatchEvent(new Event('change', { bubbles: true }));
                }"""
            )
            scan_synced = driver.wait_until(
                """() => {
                    const s = document.getElementById('chk-skills-scan-host');
                    const t = document.getElementById('chk-scan-host-skills');
                    if (s && t && s.checked && t.checked) {
                        return { skillsChecked: s.checked, toolsChecked: t.checked };
                    }
                    return false;
                }""",
                timeout_sec=5.0,
                description="skills/tools scan_host_global_skills sync",
            )
            assert scan_synced["skillsChecked"] is True
            assert scan_synced["toolsChecked"] is True

    # Verify `doctor.run_uninstall` cleans `app_src_prev` and shreds `chatgpt_oneclick_vault.json`
    un_st = tmp_path / "st_uninstall_cleanup"
    (un_st / "app_src_prev" / "cosmos_mcp").mkdir(parents=True)
    atomic_write_text(un_st / "app_src_prev" / "cosmos_mcp" / "__init__.py", "# prev rollback snapshot\n")
    (un_st / "state").mkdir(parents=True, exist_ok=True)
    vault_f = un_st / "state" / "chatgpt_oneclick_vault.json"
    atomic_write_text(vault_f, '{"secret_token": "oc_super_sensitive_1234567890"}\n')

    un_res = doctor.run_uninstall(
        un_st,
        purge=True,
        home_dir=tmp_path / "fake_home",
        appdata_dir=tmp_path / "fake_appdata",
        winreg_store={},
    )
    assert un_res["ok"] is True
    assert not (un_st / "app_src_prev").exists()
    assert not vault_f.exists()
