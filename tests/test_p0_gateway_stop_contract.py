"""Targeted P0 contract tests for gateway unknown-state truth and persistent user STOP lock guard."""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest
from starlette.testclient import TestClient

from cosmos_mcp.core.config import LiveRuntimePolicy, ensure_initialized
from cosmos_mcp.launcher import app as launcher_app
from cosmos_mcp.launcher import daemon
from cosmos_mcp.studio.routes import _resolve_studio_gateways_view


def _make_policy_and_cfg(tmp_path: Path, name: str = "gw_st", port: int = 18960) -> tuple[LiveRuntimePolicy, Dict[str, Any], Path]:
    st_dir = tmp_path / name
    ws_dir = tmp_path / f"{name}_ws"
    ws_dir.mkdir(parents=True, exist_ok=True)
    ensure_initialized(
        product_root=st_dir,
        cli_state_dir=str(st_dir),
        port=port,
        workspace_roots=[str(ws_dir)],
        tunnel_mode="public_gateway",
    )
    policy = LiveRuntimePolicy(
        state_root=st_dir,
        cfg_path=st_dir / "config" / "service.json",
        workspace_roots=[str(ws_dir)],
        eff_prefix="pc",
    )
    extra_cfg: Dict[str, Any] = {
        "selected_gateway": "instant",
        "tunnel_mode": "public_gateway",
        "public_base": "https://stale-fixed.srv.us",
        "workers_dev_url": "https://stale-node.workers.dev",
        "gateways": {
            "instant": {
                "enabled": True,
                "submode": "public_gateway",
                "public_url": "https://stale-fixed.srv.us",
                "updated_at": 100.0,
            },
            "workers_dev": {
                "enabled": True,
                "submode": "workers_dev",
                "public_url": "https://stale-node.workers.dev",
                "updated_at": 100.0,
            },
            "self_hosted": {
                "enabled": True,
                "submode": "custom",
                "public_url": "https://custom-host.example.com",
                "updated_at": 100.0,
            },
        },
    }
    return policy, extra_cfg, st_dir


@pytest.mark.parametrize("d_doc", [None, {}, {"status": "stopped"}])
def test_gateway_view_returns_unknown_without_daemon_observation(
    tmp_path: Path, d_doc: Dict[str, Any] | None
) -> None:
    policy, extra_cfg, _ = _make_policy_and_cfg(tmp_path, name="no_daemon")
    view = _resolve_studio_gateways_view(
        policy=policy,
        extra_cfg=extra_cfg,
        d_doc=d_doc,
        raw_live_pub="https://stale-fixed.srv.us",
    )

    assert view["public_https_ready"] is False
    assert view["ready_gateway_ids"] == []
    assert view["tunnel_connecting"] is False
    assert view["mcp_url"] == ""

    expected_urls = {
        "instant": "https://stale-fixed.srv.us",
        "workers_dev": "https://stale-node.workers.dev",
        "self_hosted": "https://custom-host.example.com",
    }
    for gid, cfg_url in expected_urls.items():
        slot = view["gateways"][gid]
        assert slot["status"] == "unknown", f"{gid} must be unknown without daemon observation"
        assert slot["status_label_zh"] == "未确认"
        assert slot["observed_state"] == "unknown"
        assert slot["public_https_ready"] is False
        assert slot["configured_url"] == cfg_url
        assert slot["mcp_url"] == ""

    assert view["gateways"]["instant"]["subchannels"]["srv_us"]["status"] == "unknown"


def test_gateway_view_partial_daemon_observation_marks_missing_slots_unknown(tmp_path: Path) -> None:
    policy, extra_cfg, _ = _make_policy_and_cfg(tmp_path, name="partial_daemon")
    d_doc = {
        "status": "running",
        "mode": "public_gateway",
        "public_url": "https://live-fixed.srv.us",
        "tunnel_ready": True,
        "gateways": {
            "instant": {
                "enabled": True,
                "submode": "public_gateway",
                "effective_mode": "srv_us",
                "phase": "ready",
                "tunnel_ready": True,
                "public_url": "https://live-fixed.srv.us",
                "srvus_fixed_active": True,
            },
            # workers_dev is present as an empty placeholder dict (no live observation fields)
            "workers_dev": {},
            # self_hosted is completely absent from runtime gateways
        },
    }
    view = _resolve_studio_gateways_view(
        policy=policy,
        extra_cfg=extra_cfg,
        d_doc=d_doc,
        raw_live_pub="https://live-fixed.srv.us",
    )

    assert view["gateways"]["instant"]["status"] == "ready"
    assert view["gateways"]["instant"]["public_https_ready"] is True
    assert view["gateways"]["instant"]["observed_state"] == "ready"
    assert view["ready_gateway_ids"] == ["instant"]

    for gid, cfg_url in (
        ("workers_dev", "https://stale-node.workers.dev"),
        ("self_hosted", "https://custom-host.example.com"),
    ):
        slot = view["gateways"][gid]
        assert slot["status"] == "unknown"
        assert slot["status_label_zh"] == "未确认"
        assert slot["observed_state"] == "unknown"
        assert slot["public_https_ready"] is False
        assert slot["configured_url"] == cfg_url


def test_studio_state_endpoint_never_fabricates_ready_without_daemon_status(tmp_path: Path) -> None:
    st_dir = tmp_path / "studio_no_daemon"
    ws_dir = tmp_path / "ws"
    ws_dir.mkdir(parents=True, exist_ok=True)
    port = 18962
    ensure_initialized(
        product_root=st_dir,
        cli_state_dir=str(st_dir),
        port=port,
        workspace_roots=[str(ws_dir)],
        tunnel_mode="public_gateway",
    )
    cfg_p = st_dir / "config" / "service.json"
    cfg_doc = json.loads(cfg_p.read_text(encoding="utf-8-sig"))
    cfg_doc["selected_gateway"] = "workers_dev"
    cfg_doc["gateways"] = {
        "instant": {
            "enabled": False,
            "submode": "public_gateway",
            "public_url": "",
            "updated_at": 0.0,
        },
        "workers_dev": {
            "enabled": True,
            "submode": "workers_dev",
            "public_url": "https://historical-only.workers.dev",
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

    app = launcher_app.create_standalone_app(
        product_root=st_dir,
        state_dir=str(st_dir),
        port=port,
        public_url=f"http://127.0.0.1:{port}",
        prefix="pc",
    )
    client = TestClient(app, base_url=f"http://127.0.0.1:{port}", client=("127.0.0.1", 52111))
    resp = client.get("/api/studio/state")
    assert resp.status_code == 200
    data = resp.json()
    wd = data["gateways"]["workers_dev"]
    assert wd["status"] == "unknown"
    assert wd["status_label_zh"] == "未确认"
    assert wd["observed_state"] == "unknown"
    assert wd["public_https_ready"] is False
    assert wd["configured_url"] == "https://historical-only.workers.dev"
    assert data["public_https_ready"] is False


def test_spawn_detached_daemon_blocked_by_user_stop_unless_explicitly_cleared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    st_dir = tmp_path / "stop_lock_st"
    (st_dir / "state").mkdir(parents=True, exist_ok=True)
    stop_flag = daemon.daemon_stop_flag_path(st_dir, "pc")
    stop_flag.write_text("STOP:1700000000.0\n", encoding="utf-8")

    spawn_calls: List[List[str]] = []

    class _FakeProc:
        def __init__(self, pid: int = 54321) -> None:
            self.pid = pid

    def _fake_popen(argv: List[str], **_kwargs: Any) -> _FakeProc:
        spawn_calls.append(list(argv))
        return _FakeProc()

    monkeypatch.setattr(daemon.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(daemon, "_spawn_via_wmi_win32_process", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        daemon,
        "detect_running_instance",
        lambda *_a, **_kw: {
            "online": True,
            "healthz_ok": True,
            "public_url": "http://127.0.0.1:18965",
        },
    )

    # 1) Default call (clear_user_stop=False): MUST refuse to spawn and MUST preserve STOP lock
    blocked = daemon.spawn_detached_daemon(
        python_exe=sys.executable,
        state_root=st_dir,
        port=18965,
        mode="local",
        prefix="pc",
        no_tray=True,
        wait_ready_sec=1.0,
    )
    assert blocked["ok"] is False
    assert blocked["blocked_by_user_stop"] is True
    assert spawn_calls == []
    assert stop_flag.read_text(encoding="utf-8").strip() == "STOP:1700000000.0"

    # 2) Explicit user start (clear_user_stop=True): clears STOP lock and spawns daemon
    allowed = daemon.spawn_detached_daemon(
        python_exe=sys.executable,
        state_root=st_dir,
        port=18965,
        mode="local",
        prefix="pc",
        no_tray=True,
        wait_ready_sec=1.0,
        clear_user_stop=True,
    )
    assert allowed["ok"] is True
    assert allowed.get("blocked_by_user_stop") is not True
    assert len(spawn_calls) == 1
    assert stop_flag.read_text(encoding="utf-8").strip().startswith("CLEAR:")


def test_cli_explicit_start_passes_clear_user_stop_true() -> None:
    cli_path = Path(__file__).resolve().parents[1] / "src" / "cosmos_mcp" / "launcher" / "cli.py"
    tree = ast.parse(cli_path.read_text(encoding="utf-8-sig"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "spawn_detached_daemon"
    ]
    assert len(calls) == 1
    kw_map = {kw.arg: kw.value for kw in calls[0].keywords if kw.arg}
    assert "clear_user_stop" in kw_map
    assert isinstance(kw_map["clear_user_stop"], ast.Constant)
    assert kw_map["clear_user_stop"].value is True
