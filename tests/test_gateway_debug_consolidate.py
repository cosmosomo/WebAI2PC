"""Targeted regression tests for dual-subchannel instant gateway coexistence, gateway-debug, and /c/ security hardening."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, List

import pytest
from starlette.testclient import TestClient

from cosmos_mcp.core.config import LiveRuntimePolicy, ensure_initialized, save_endpoint_secret
from cosmos_mcp.launcher import app as launcher_app
from cosmos_mcp.launcher import daemon, tunnels
from cosmos_mcp.protocol.dispatcher import KernelDispatcher
from cosmos_mcp.protocol.oauth import OAuthProvider, OAuthSQLiteStore
from cosmos_mcp.protocol.transport import create_protocol_app


def _make_sup(tmp_path: Path, name: str = "st", port: int = 18940) -> daemon.StandaloneSupervisorLoop:
    st_dir = tmp_path / name
    st_dir.mkdir(parents=True, exist_ok=True)
    return daemon.StandaloneSupervisorLoop(
        state_root=st_dir,
        runtime_python=sys.executable,
        port=port,
        mode="public_gateway",
        no_tray=True,
        enforce_singleton=False,
    )


def _close_sup(sup: daemon.StandaloneSupervisorLoop) -> None:
    sup._sup_logger.removeHandler(sup._sup_log_handler)
    sup._sup_log_handler.close()


def _make_studio_app(tmp_path: Path, port: int = 18945) -> tuple[Any, Path, str]:
    st_dir = tmp_path / "studio_st"
    ws_dir = tmp_path / "ws"
    ws_dir.mkdir(parents=True, exist_ok=True)
    creds = ensure_initialized(
        product_root=st_dir,
        cli_state_dir=str(st_dir),
        port=port,
        workspace_roots=[str(ws_dir)],
        tunnel_mode="public_gateway",
    )
    app = launcher_app.create_standalone_app(
        product_root=st_dir,
        state_dir=str(st_dir),
        port=port,
        public_url=f"http://127.0.0.1:{port}",
        prefix="pc",
    )
    return app, st_dir, str(creds.get("password") or "")


def test_srvus_start_timeout_is_10s_and_reboot_notice_cleaned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert daemon.SRVUS_START_WAIT_TIMEOUT_SEC == 10.0
    assert "Tunnel Token 模式" not in tunnels.QUICK_TUNNEL_REBOOT_NOTICE_ZH

    seen_timeouts: List[float] = []

    class _FakeSrvUs:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs
            self.last_error = ""
            self.pid = 41234

        def start(self, wait_url_timeout_sec: float = 0.0) -> str:
            seen_timeouts.append(float(wait_url_timeout_sec))
            return "https://fixed1234567890.srv.us"

        def is_process_alive(self) -> bool:
            return True

        def stop(self) -> None:
            pass

    monkeypatch.setattr(daemon, "SrvUsSshTunnelSupervisor", _FakeSrvUs)
    monkeypatch.setattr(daemon, "probe_public_gateway_online", lambda *_a, **_kw: {"online": False})
    monkeypatch.setattr(daemon, "hot_refresh_public_url", lambda *_a, **_kw: None)

    sup = _make_sup(tmp_path, "st_10s")
    monkeypatch.setattr(sup, "_verify_slot_public_ready_async", lambda *_a, **_kw: None)
    try:
        doc = {
            "instant_trycloudflare_backup": False,
            "gateways": {"instant": {"enabled": True, "submode": "public_gateway"}},
        }
        sup._sync_instant_slot(doc["gateways"]["instant"], doc, initial=True)
        assert seen_timeouts == [10.0]
        assert sup._gateway_slots["instant"].effective_mode == "srv_us"
        assert sup._gateway_slots["instant"].public_url == "https://fixed1234567890.srv.us"
        st_dict = sup._gateway_slots["instant"].to_status_dict()
        assert st_dict["subchannels"]["srv_us"]["public_url"] == "https://fixed1234567890.srv.us"
        assert st_dict["subchannels"]["trycloudflare"]["enabled"] is False
        assert st_dict["subchannels"]["trycloudflare"]["status"] == "disabled"
    finally:
        _close_sup(sup)


def test_instant_dual_subchannels_coexist_and_auto_fallback_switchback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    srvus_state = {"count": 0, "succeed": True, "stopped": 0}
    cf_state = {"count": 0, "stopped": 0}
    fake_now = [1000.0]
    inflight_state = {"inflight": 1}

    class _FakeSrvUs:
        def __init__(self, **kwargs: Any) -> None:
            self.last_error = "ssh handshake refused by remote"
            self.pid = 42001
            self._alive = True

        def start(self, wait_url_timeout_sec: float = 0.0) -> str:
            srvus_state["count"] += 1
            if srvus_state["succeed"]:
                self.last_error = ""
                return "https://primary987654.srv.us"
            self._alive = False
            return ""

        def is_process_alive(self) -> bool:
            return self._alive

        def stop(self) -> None:
            self._alive = False
            srvus_state["stopped"] += 1

    class _FakeQuickCf:
        def __init__(self, **kwargs: Any) -> None:
            self.pid = 42002
            self.current_url = "https://backup-abc.trycloudflare.com"
            self.last_error = ""
            self.stopped = False

        def start(self, wait_url_timeout_sec: float = 0.0) -> str:
            cf_state["count"] += 1
            return self.current_url

        def is_process_alive(self) -> bool:
            return not self.stopped

        def stop(self) -> None:
            self.stopped = True
            cf_state["stopped"] += 1

    monkeypatch.setattr(daemon, "SrvUsSshTunnelSupervisor", _FakeSrvUs)
    monkeypatch.setattr(daemon, "CloudflaredTunnelSupervisor", _FakeQuickCf)
    monkeypatch.setattr(daemon, "ensure_cloudflared_binary", lambda _d: Path("cloudflared.exe"))
    monkeypatch.setattr(daemon, "probe_public_gateway_online", lambda *_a, **_kw: {"online": False})
    monkeypatch.setattr(daemon, "hot_refresh_public_url", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        daemon, "probe_local_healthz", lambda *_a, **_kw: {"ok": True, "inflight": inflight_state["inflight"]}
    )
    monkeypatch.setattr(daemon.time, "monotonic", lambda: fake_now[0])

    # 1) Coexistence: instant_trycloudflare_backup=True -> BOTH srv.us & trycloudflare run concurrently without killing each other,
    #    and instant's primary public_url ALWAYS stays srv.us!
    sup_coex = _make_sup(tmp_path, "st_coex", port=18941)
    monkeypatch.setattr(sup_coex, "_verify_slot_public_ready_async", lambda *_a, **_kw: None)
    try:
        doc_coex = {
            "instant_trycloudflare_backup": True,
            "gateways": {
                "instant": {
                    "enabled": True,
                    "submode": "public_gateway",
                    "trycloudflare_backup": True,
                }
            },
        }
        sup_coex._sync_instant_slot(doc_coex["gateways"]["instant"], doc_coex, initial=True)
        assert srvus_state["count"] == 1
        assert cf_state["count"] == 1
        assert srvus_state["stopped"] == 0
        assert cf_state["stopped"] == 0

        slot = sup_coex._gateway_slots["instant"]
        assert slot.public_url == "https://primary987654.srv.us"
        assert slot.effective_mode == "srv_us"
        assert slot.srvus_url == "https://primary987654.srv.us"
        assert slot.trycloudflare_url == "https://backup-abc.trycloudflare.com"
        st_dict = slot.to_status_dict()
        assert st_dict["subchannels"]["srv_us"]["public_url"] == "https://primary987654.srv.us"
        assert st_dict["subchannels"]["srv_us"]["mcp_url"] == "https://primary987654.srv.us/mcp"
        assert st_dict["subchannels"]["trycloudflare"]["enabled"] is True
        assert st_dict["subchannels"]["trycloudflare"]["public_url"] == "https://backup-abc.trycloudflare.com"
        assert st_dict["subchannels"]["trycloudflare"]["mcp_url"] == "https://backup-abc.trycloudflare.com/mcp"

        # Independent subchannel reconnect: reconnecting trycloudflare NEVER kills srv.us
        sup_coex._consume_gateway_reconnect_requests({"subchannel_reconnect_requested_at": {"trycloudflare": 200.0}})
        assert srvus_state["stopped"] == 0
        assert cf_state["stopped"] == 1
        assert sup_coex._srvus_supervisor is not None
        assert sup_coex._cf_quick_supervisor is None

        # Turning backup OFF stops trycloudflare while keeping srv.us alive
        doc_off = {
            "instant_trycloudflare_backup": False,
            "gateways": {
                "instant": {
                    "enabled": True,
                    "submode": "public_gateway",
                    "trycloudflare_backup": False,
                }
            },
        }
        sup_coex._sync_instant_slot(doc_off["gateways"]["instant"], doc_off, initial=False)
        assert srvus_state["stopped"] == 0
        assert slot.public_url == "https://primary987654.srv.us"
        assert slot.to_status_dict()["subchannels"]["trycloudflare"]["enabled"] is False
    finally:
        _close_sup(sup_coex)

    # 2) Default instant_trycloudflare_backup=False: when srv.us fails, auto-fallback to trycloudflare,
    #    defer switchback while inflight > 0, and smoothly recover srv.us when inflight == 0
    srvus_state["count"] = 0
    srvus_state["succeed"] = False
    cf_state["count"] = 0
    sup_fb = _make_sup(tmp_path, "st_fb", port=18943)
    monkeypatch.setattr(sup_fb, "_verify_slot_public_ready_async", lambda *_a, **_kw: None)
    try:
        doc_fb = {
            "instant_trycloudflare_backup": False,
            "gateways": {"instant": {"enabled": True, "submode": "public_gateway", "trycloudflare_backup": False}},
        }
        sup_fb._sync_instant_slot(doc_fb["gateways"]["instant"], doc_fb, initial=True)
        assert srvus_state["count"] == 1
        assert cf_state["count"] == 1
        assert sup_fb._instant_fallback_active is True
        assert sup_fb._gateway_slots["instant"].srvus_status == "error"
        assert "ssh handshake refused by remote" in sup_fb._gateway_slots["instant"].srvus_error
        assert ".trycloudflare.com" in sup_fb._gateway_slots["instant"].public_url

        # srv.us healthy again, but inflight == 1 -> defer switchback
        srvus_state["succeed"] = True
        fake_now[0] += 130.0
        inflight_state["inflight"] = 1
        sup_fb._sync_instant_slot(doc_fb["gateways"]["instant"], doc_fb, initial=False)
        assert srvus_state["count"] == 1
        assert sup_fb._instant_fallback_active is True

        # inflight == 0 -> smoothly recovers srv.us and stops auto-fallback trycloudflare
        fake_now[0] += 20.0
        inflight_state["inflight"] = 0
        sup_fb._sync_instant_slot(doc_fb["gateways"]["instant"], doc_fb, initial=False)
        assert srvus_state["count"] == 2
        assert sup_fb._instant_fallback_active is False
        assert sup_fb._srvus_fixed_active is True
        assert sup_fb._gateway_slots["instant"].public_url == "https://primary987654.srv.us"
        assert sup_fb._gateway_slots["instant"].to_status_dict()["subchannels"]["trycloudflare"]["enabled"] is False
    finally:
        _close_sup(sup_fb)


def test_studio_dual_subchannels_endpoint_secret_debug_and_actions(tmp_path: Path) -> None:
    app, st_dir, _pw = _make_studio_app(tmp_path, port=18946)

    # Enable endpoint_secret to verify BOTH subchannels' mcp_url / readonly_mcp_url respect /u/<secret>
    ep_sec = save_endpoint_secret(st_dir, "0123456789abcdef01234567", prefix="pc")

    cfg_p = st_dir / "config" / "service.json"
    cfg_doc = json.loads(cfg_p.read_text(encoding="utf-8-sig"))
    cfg_doc["selected_gateway"] = "instant"
    cfg_doc["instant_trycloudflare_backup"] = True
    cfg_doc["gateways"] = {
        "instant": {
            "enabled": True,
            "submode": "public_gateway",
            "trycloudflare_backup": True,
            "public_url": "https://primary-fixed.srv.us",
            "updated_at": 100.0,
        },
        "workers_dev": {
            "enabled": True,
            "submode": "workers_dev",
            "public_url": "https://my-perm-node.workers.dev",
            "updated_at": 100.0,
        },
        "self_hosted": {
            "enabled": False,
            "submode": "vps_hub",
            "public_url": "",
            "updated_at": 0.0,
        },
    }
    cfg_p.write_text(json.dumps(cfg_doc, ensure_ascii=False, indent=2), encoding="utf-8")

    d_status_p = st_dir / "state" / "daemon_status.json"
    d_status_p.parent.mkdir(parents=True, exist_ok=True)
    d_status_p.write_text(
        json.dumps(
            {
                "status": "running",
                "mode": "public_gateway",
                "public_url": "https://primary-fixed.srv.us",
                "tunnel_ready": True,
                "gateways": {
                    "instant": {
                        "enabled": True,
                        "submode": "public_gateway",
                        "effective_mode": "srv_us",
                        "trycloudflare_backup": True,
                        "phase": "ready",
                        "tunnel_ready": True,
                        "public_url": "https://primary-fixed.srv.us",
                        "srvus_fixed_active": True,
                        "instant_fallback_active": False,
                        "subchannels": {
                            "srv_us": {
                                "label": "srv.us 免登录固定地址",
                                "role": "primary",
                                "enabled": True,
                                "status": "ready",
                                "public_url": "https://primary-fixed.srv.us",
                                "mcp_url": "https://primary-fixed.srv.us/mcp",
                                "readonly_mcp_url": "https://primary-fixed.srv.us/mcp/readonly",
                                "last_error": "",
                            },
                            "trycloudflare": {
                                "label": "trycloudflare 备用临时通道（重启会变）",
                                "role": "backup",
                                "enabled": True,
                                "status": "ready",
                                "public_url": "https://backup-coexist.trycloudflare.com",
                                "mcp_url": "https://backup-coexist.trycloudflare.com/mcp",
                                "readonly_mcp_url": "https://backup-coexist.trycloudflare.com/mcp/readonly",
                                "last_error": "",
                            },
                        },
                    },
                    "workers_dev": {
                        "enabled": True,
                        "submode": "workers_dev",
                        "effective_mode": "workers_dev",
                        "phase": "ready",
                        "tunnel_ready": True,
                        "public_url": "https://my-perm-node.workers.dev",
                    },
                    "self_hosted": {
                        "enabled": False,
                        "submode": "vps_hub",
                        "phase": "disabled",
                        "tunnel_ready": False,
                        "public_url": "",
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    # Seed logs with sensitive tokens to verify redaction + 25-line cap
    logs_dir = st_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    srvus_lines = [f"2026-11-27 line-{i} ok" for i in range(30)]
    srvus_lines.append("Authorization: Bearer super_secret_bearer_token_123456")
    srvus_lines.append("url=https://demo.srv.us/c/oc_abcd1234567890xyz/mcp token=cmcp_secret_pat_99887766")
    srvus_lines.append(f"secret=myVerySecretPass12345 /u/{ep_sec}/mcp")
    (logs_dir / "srvus.log").write_text("\n".join(srvus_lines) + "\n", encoding="utf-8")
    (logs_dir / "supervisor.log").write_text(
        "unrelated boot line\n"
        "workers_dev relay connected ok with Bearer tok_should_be_masked_999\n"
        "self_hosted vps ssh ready\n",
        encoding="utf-8",
    )

    client = TestClient(app, base_url="http://127.0.0.1:18946", client=("127.0.0.1", 52100))

    # 1) /api/studio/state returns BOTH subchannels simultaneously with endpoint_secret applied,
    #    and instant's primary URL is srv.us (never overwritten by trycloudflare)
    st_resp = client.get("/api/studio/state")
    assert st_resp.status_code == 200
    st_json = st_resp.json()
    inst_st = st_json["gateways"]["instant"]
    assert inst_st["public_url"] == f"https://primary-fixed.srv.us/u/{ep_sec}"
    assert inst_st["mcp_url"] == f"https://primary-fixed.srv.us/u/{ep_sec}/mcp"
    subch = inst_st["subchannels"]
    assert subch["srv_us"]["role"] == "primary"
    assert subch["srv_us"]["status"] == "ready"
    assert subch["srv_us"]["mcp_url"] == f"https://primary-fixed.srv.us/u/{ep_sec}/mcp"
    assert subch["srv_us"]["readonly_mcp_url"] == f"https://primary-fixed.srv.us/u/{ep_sec}/mcp/readonly"
    assert subch["trycloudflare"]["role"] == "backup"
    assert subch["trycloudflare"]["enabled"] is True
    assert subch["trycloudflare"]["status"] == "ready"
    assert subch["trycloudflare"]["mcp_url"] == f"https://backup-coexist.trycloudflare.com/u/{ep_sec}/mcp"
    assert subch["trycloudflare"]["readonly_mcp_url"] == f"https://backup-coexist.trycloudflare.com/u/{ep_sec}/mcp/readonly"
    csrf_tok = st_json["csrf_token"]

    # 2) GET /api/studio/gateway-debug: non-loopback rejected (404 stealth without /u/<sec>, 403 with /u/<sec> or non-loopback peer)
    r_stealth = client.get(
        "/api/studio/gateway-debug",
        headers={"x-cosmos-via-tunnel": "1", "x-forwarded-host": "my-perm-node.workers.dev"},
    )
    assert r_stealth.status_code in (403, 404)
    rem_client = TestClient(app, base_url="http://127.0.0.1:18946", client=("10.0.0.99", 52101))
    r_forbid = rem_client.get(f"/u/{ep_sec}/api/studio/gateway-debug")
    assert r_forbid.status_code == 403

    r_dbg = client.get("/api/studio/gateway-debug")
    assert r_dbg.status_code == 200
    dbg = r_dbg.json()
    assert dbg["ok"] is True
    assert dbg["endpoint_secret_enabled"] is True
    assert dbg["endpoint_secret_masked"] != ""
    inst_dbg = dbg["gateways"]["instant"]
    assert inst_dbg["subchannels"]["srv_us"]["mcp_url"] == f"https://primary-fixed.srv.us/u/{ep_sec}/mcp"
    assert inst_dbg["subchannels"]["trycloudflare"]["mcp_url"] == f"https://backup-coexist.trycloudflare.com/u/{ep_sec}/mcp"
    assert len(inst_dbg["log_tail"]) <= 25
    joined_inst = "\n".join(inst_dbg["log_tail"])
    assert "super_secret_bearer_token_123456" not in joined_inst
    assert "oc_abcd1234567890xyz" not in joined_inst
    assert "cmcp_secret_pat_99887766" not in joined_inst
    assert ep_sec not in joined_inst
    assert "[REDACTED]" in joined_inst

    # 3) POST /api/studio/connection: set_trycloudflare_backup + reconnect_subchannel
    r_tb_off = client.post(
        "/api/studio/connection",
        json={"action": "set_trycloudflare_backup", "enabled": False, "csrf_token": csrf_tok},
        headers={"X-CSRF-Token": csrf_tok, "Origin": "http://127.0.0.1:18946"},
    )
    assert r_tb_off.status_code == 200
    saved_off = json.loads(cfg_p.read_text(encoding="utf-8-sig"))
    assert saved_off["instant_trycloudflare_backup"] is False
    assert saved_off["gateways"]["instant"]["enabled"] is True
    assert saved_off["gateways"]["instant"]["trycloudflare_backup"] is False

    r_tb_on = client.post(
        "/api/studio/connection",
        json={"action": "set_trycloudflare_backup", "enabled": True, "csrf_token": csrf_tok},
        headers={"X-CSRF-Token": csrf_tok, "Origin": "http://127.0.0.1:18946"},
    )
    assert r_tb_on.status_code == 200
    saved_on = json.loads(cfg_p.read_text(encoding="utf-8-sig"))
    assert saved_on["instant_trycloudflare_backup"] is True
    assert saved_on["gateways"]["instant"]["enabled"] is True
    assert float(saved_on["subchannel_reconnect_requested_at"]["trycloudflare"]) > 0.0

    r_rec_sc = client.post(
        "/api/studio/connection",
        json={"action": "reconnect_subchannel", "subchannel": "srv_us", "csrf_token": csrf_tok},
        headers={"X-CSRF-Token": csrf_tok, "Origin": "http://127.0.0.1:18946"},
    )
    assert r_rec_sc.status_code == 200
    saved_sc = json.loads(cfg_p.read_text(encoding="utf-8-sig"))
    assert float(saved_sc["subchannel_reconnect_requested_at"]["srv_us"]) > 0.0

    # 4) POST /api/studio/chatgpt-oneclick: no /c/oc_, prefers permanent OAuth URL, clean prompt
    r_oc = client.post(
        "/api/studio/chatgpt-oneclick",
        json={"scope": "full", "csrf_token": csrf_tok},
        headers={"X-CSRF-Token": csrf_tok, "Origin": "http://127.0.0.1:18946"},
    )
    assert r_oc.status_code == 200
    oc_body = r_oc.json()
    assert oc_body["ok"] is True
    assert oc_body["gateway_id"] == "workers_dev"
    assert "/c/" not in oc_body["oneclick_url"]
    assert "oc_" not in oc_body["oneclick_url"]
    assert "ChatGPT Sites" not in oc_body["prompt"]
    assert "[@Plugin Creator](plugin://plugin-creator@openai-curated-remote?remotePluginId=plugin_connector_1p_e1a10c53223481918a42f1510ec46c1e)" in oc_body["prompt"]


def test_c_token_mcp_path_disabled_by_default_stealth_404(tmp_path: Path) -> None:
    st_dir = tmp_path / "st_c404"
    ws_dir = tmp_path / "ws_c404"
    ws_dir.mkdir(parents=True, exist_ok=True)
    ensure_initialized(
        product_root=st_dir,
        cli_state_dir=str(st_dir),
        port=18947,
        workspace_roots=[str(ws_dir)],
    )
    public_base = "https://perm-test.srv.us"
    store = OAuthSQLiteStore(st_dir / "state" / "oauth.sqlite3")
    provider = OAuthProvider(
        store=store,
        base_url=public_base,
        password_hash="h",
        salt="00" * 16,
        allowed_resources={public_base, f"{public_base}/mcp", f"{public_base}/mcp/readonly"},
        issuer=public_base,
        state_root=st_dir,
    )
    policy = LiveRuntimePolicy(
        state_root=st_dir, workspace_roots=[ws_dir], cfg_path=st_dir / "config" / "service.json"
    )
    dispatcher = KernelDispatcher(policy=policy)
    proto_app = create_protocol_app(
        dispatcher,
        provider=provider,
        store=store,
        policy=policy,
        public_url=public_base,
        port=18947,
    )
    with TestClient(proto_app, base_url=public_base) as client:
        for path in ("/c", "/c/oc_removed_capability_token_123456/mcp", "/c/oc_removed_capability_token_123456/mcp/readonly"):
            resp = client.post(
                path,
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                headers={"Host": "perm-test.srv.us", "Accept": "application/json, text/event-stream"},
            )
            assert resp.status_code == 404, path
