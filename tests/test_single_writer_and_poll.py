"""Targeted backend contract tests for single-writer config authority, pair-code rotation,
poll/state revision + PAT count + env_locks exposure, and explicit STOP lock recovery.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List

import pytest
from starlette.testclient import TestClient

import cosmos_mcp.core.config as cfg_mod
from cosmos_mcp.core.config import LiveRuntimePolicy, ensure_initialized
from cosmos_mcp.launcher import app as launcher_app
from cosmos_mcp.launcher import daemon
from cosmos_mcp.launcher import tray
import cosmos_mcp.studio.routes as routes_mod


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _init_studio_client(
    tmp_path: Path,
    *,
    name: str,
    port: int,
    tier_key: str = "tier3_workspace_dev",
    toolset_profile: str = "standard",
    enabled_packs: List[str] | None = None,
) -> tuple[TestClient, Any, Path, Path]:
    st_dir = (tmp_path / name).resolve()
    ws_dir = (tmp_path / f"{name}_ws").resolve()
    ws_dir.mkdir(parents=True, exist_ok=True)
    ensure_initialized(
        product_root=st_dir,
        cli_state_dir=str(st_dir),
        port=port,
        tier_key=tier_key,
        toolset_profile=toolset_profile,
        enabled_packs=enabled_packs or [],
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
    client = TestClient(app, base_url=f"http://127.0.0.1:{port}", client=("127.0.0.1", 53110))
    return client, app, st_dir, ws_dir


# ---------------------------------------------------------------------------
# 1) Single-lock writer, zero exception swallowing, & preserving toolset_profile
# ---------------------------------------------------------------------------


def test_single_writer_lock_no_swallow_and_preserve_toolset_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, app, st_dir, _ws_dir = _init_studio_client(
        tmp_path,
        name="single_writer",
        port=18971,
        tier_key="tier3_workspace_dev",
        toolset_profile="minimal",
    )
    policy = app.state.policy
    cfg_path = st_dir / "config" / "service.json"
    assert policy.cfg_path.resolve() == cfg_path.resolve()
    assert policy.toolset_profile == "minimal"

    lock_paths: List[Path] = []
    real_get_file_lock = cfg_mod.get_file_lock

    class _LockSpy:
        def __init__(self, target: Path) -> None:
            self._target = Path(target).resolve()
            self._inner = real_get_file_lock(target)

        def __enter__(self) -> Any:
            lock_paths.append(self._target)
            return self._inner.__enter__()

        def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Any:
            return self._inner.__exit__(exc_type, exc_val, exc_tb)

    monkeypatch.setattr(cfg_mod, "get_file_lock", lambda p: _LockSpy(p))
    monkeypatch.setattr(tray, "get_file_lock", lambda p: _LockSpy(p))

    rev_before = policy.policy_revision
    routes_mod._persist_extra_studio_config(
        policy,
        tunnel_mode="workers_dev",
        workers_dev_url="https://demo-node.workers.dev",
        subchannel_reconnect_requested_at={"srv_us": 1234.5},
    )
    assert cfg_path.resolve() in lock_paths
    assert policy.policy_revision == rev_before + 1
    saved_doc = _read_json(cfg_path)
    assert saved_doc["tunnel_mode"] == "workers_dev"
    assert saved_doc["workers_dev_url"] == "https://demo-node.workers.dev"
    assert saved_doc["subchannel_reconnect_requested_at"]["srv_us"] == 1234.5

    routes_mod._update_studio_gateway_slot(
        policy,
        "workers_dev",
        enabled=True,
        submode="workers_dev",
        public_url="https://demo-node.workers.dev",
        select=True,
        port=18971,
    )
    assert policy.policy_revision == rev_before + 2
    assert _read_json(cfg_path)["gateways"]["workers_dev"]["public_url"] == "https://demo-node.workers.dev"

    # Disk write failure MUST propagate (never silently swallowed) and leave memory/disk intact
    real_atomic_write = cfg_mod.atomic_write_json

    def _boom_write(*_a: Any, **_kw: Any) -> None:
        raise OSError("simulated disk write failure")

    monkeypatch.setattr(cfg_mod, "atomic_write_json", _boom_write)
    rev_stable = policy.policy_revision
    with pytest.raises(OSError, match="simulated disk write failure"):
        routes_mod._persist_extra_studio_config(policy, tunnel_mode="vps_hub")
    with pytest.raises(OSError, match="simulated disk write failure"):
        routes_mod._update_studio_gateway_slot(policy, "self_hosted", enabled=True, submode="vps_hub")
    assert policy.policy_revision == rev_stable
    assert _read_json(cfg_path)["tunnel_mode"] == "workers_dev"
    monkeypatch.setattr(cfg_mod, "atomic_write_json", real_atomic_write)

    # Switching safety_mode & capability packs via Studio API MUST NOT reset toolset_profile="minimal"
    csrf = client.get("/api/studio/state").json()["csrf_token"]
    r_safety = client.post(
        "/api/studio/tools-safety",
        headers={"X-Studio-Csrf": csrf},
        json={"safety_mode": "full_power", "pack_browser": True},
    )
    assert r_safety.status_code == 200
    assert policy.tier_key == "tier4_full_power"
    assert "browser" in policy.enabled_packs
    assert policy.toolset_profile == "minimal"
    assert _read_json(cfg_path)["toolset_profile"] == "minimal"

    # Tray toggle holds lock on config/service.json and ignores stale state/service.json
    stale_state_cfg = st_dir / "state" / "service.json"
    stale_state_cfg.parent.mkdir(parents=True, exist_ok=True)
    stale_state_cfg.write_text(
        json.dumps({"permission_tier": "tier2_workspace_edit", "toolset_profile": "standard"}),
        encoding="utf-8",
    )
    future_ts = time.time() + 3600.0
    os.utime(stale_state_cfg, (future_ts, future_ts))

    lock_paths.clear()
    toggle_res = tray.apply_tray_permission_toggle(st_dir, prefix="pc")
    assert cfg_path.resolve() in lock_paths
    assert toggle_res["permission_tier"] == "tier1_readonly"
    assert toggle_res["previous_non_readonly_tier"] == "tier4_full_power"
    after_tray_doc = _read_json(cfg_path)
    assert after_tray_doc["permission_tier"] == "tier1_readonly"
    assert after_tray_doc["toolset_profile"] == "minimal"
    assert after_tray_doc["workers_dev_url"] == "https://demo-node.workers.dev"


# ---------------------------------------------------------------------------
# 2) Stale config.json tier3_workspace_dev never overwrites service.json tier4_full_power
# ---------------------------------------------------------------------------


def test_stale_legacy_config_json_never_overwrites_service_json_tier4(tmp_path: Path) -> None:
    st_dir = (tmp_path / "tier4_guard").resolve()
    ws_dir = (tmp_path / "tier4_ws").resolve()
    ws_dir.mkdir(parents=True, exist_ok=True)
    port = 18972
    ensure_initialized(
        product_root=st_dir,
        cli_state_dir=str(st_dir),
        port=port,
        tier_key="tier4_full_power",
        enabled_packs=["browser", "cua"],
        workspace_roots=[str(ws_dir)],
        tunnel_mode="public_gateway",
    )
    auth_cfg = st_dir / "config" / "service.json"
    assert _read_json(auth_cfg)["permission_tier"] == "tier4_full_power"

    # Plant stale config.json and state/service.json with tier3_workspace_dev and newer mtime
    legacy_root_cfg = st_dir / "config.json"
    legacy_state_cfg = st_dir / "state" / "service.json"
    legacy_state_cfg.parent.mkdir(parents=True, exist_ok=True)
    stale_payload = {
        "permission_tier": "tier3_workspace_dev",
        "enabled_packs": [],
        "tunnel_mode": "local",
    }
    for lp in (legacy_root_cfg, legacy_state_cfg):
        lp.write_text(json.dumps(stale_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        fut = time.time() + 7200.0
        os.utime(lp, (fut, fut))

    app = launcher_app.create_standalone_app(
        product_root=st_dir,
        state_dir=str(st_dir),
        port=port,
        public_url=f"http://127.0.0.1:{port}",
        prefix="pc",
    )
    client = TestClient(app, base_url=f"http://127.0.0.1:{port}", client=("127.0.0.1", 53112))

    st_resp = client.get("/api/studio/state")
    assert st_resp.status_code == 200
    st_json = st_resp.json()
    assert app.state.policy.tier_key == "tier4_full_power"
    assert st_json["safety_mode"] == "full_power"
    # L4 full power with browser + cua packs exposes >15 tools (16+ core+pack tools, never dropping to 15)
    assert st_json["tools_center"]["active_total_count"] >= 16

    # Saving extra Studio config must NOT read stale tier3 from config.json back into service.json;
    # instead it one-way repairs existing secondary files to tier4_full_power!
    csrf = st_json["csrf_token"]
    r_conn = client.post(
        "/api/studio/connection",
        headers={"X-Studio-Csrf": csrf},
        json={"action": "set_runtime_prefs", "keep_awake": False},
    )
    assert r_conn.status_code == 200
    assert _read_json(auth_cfg)["permission_tier"] == "tier4_full_power"
    assert _read_json(legacy_root_cfg)["permission_tier"] == "tier4_full_power"
    assert _read_json(legacy_state_cfg)["permission_tier"] == "tier4_full_power"
    assert app.state.policy.tier_key == "tier4_full_power"

    # Supervisor _read_cfg_doc also reads config/service.json authoritatively over newer state/service.json
    legacy_state_cfg.write_text(json.dumps({"permission_tier": "tier1_readonly", "tunnel_mode": "local"}), encoding="utf-8")
    os.utime(legacy_state_cfg, (time.time() + 9000.0, time.time() + 9000.0))
    sup = daemon.StandaloneSupervisorLoop(
        state_root=st_dir,
        runtime_python=sys.executable,
        port=port,
        prefix="pc",
        no_tray=True,
        enforce_singleton=False,
    )
    assert sup._read_cfg_doc()["permission_tier"] == "tier4_full_power"


# ---------------------------------------------------------------------------
# 3) Consistent state_revision, pat_count, and env_locks across /state and /poll
# ---------------------------------------------------------------------------


def test_poll_and_state_revision_pat_count_and_env_locks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, app, st_dir, _ws_dir = _init_studio_client(
        tmp_path,
        name="poll_contract",
        port=18973,
    )
    store = app.state.store

    s0 = client.get("/api/studio/state").json()
    p0 = client.get("/api/studio/poll").json()
    assert s0["state_revision"]
    assert s0["state_revision"] == s0["connection"]["state_revision"] == p0["state_revision"]
    assert s0["pat_count"] == s0["connection"]["pat_count"] == p0["pat_count"] == 0
    assert s0["env_locks"] == s0["connection"]["env_locks"] == p0["env_locks"] == {}

    # Mint 2 PAT tokens and 1 non-PAT OAuth session -> pat_count == 2, state_revision updates immediately
    pat1 = store.mint_personal_access_token(label="CLI Key 1", readonly=True, ttl_days=7)
    pat2 = store.mint_personal_access_token(label="Sites Key 2", readonly=False, ttl_days=30)
    assert pat1["token"].startswith("cmcp_") and pat2["token"].startswith("cmcp_")

    # Also insert a regular OAuth client + access token to ensure pat_count only counts PATs
    now_ts = int(time.time())
    exp_ts = now_ts + 3600
    store.put(
        "client",
        "oauth_web_client_1",
        {
            "client_id": "oauth_web_client_1",
            "client_name": "Gemini Web",
            "redirect_uris": ["https://gemini.google.com/callback"],
            "created_at": now_ts,
        },
        float(exp_ts + 86400),
    )
    store.put(
        "access",
        "tok_regular_oauth_123456",
        {
            "token": "tok_regular_oauth_123456",
            "client_id": "oauth_web_client_1",
            "scopes": ["mcp:tools"],
            "expires_at": exp_ts,
            "resource": "http://127.0.0.1:18973/mcp",
            "subject": "owner",
        },
        float(exp_ts),
    )

    s1_resp = client.get("/api/studio/state")
    p1_resp = client.get("/api/studio/poll")
    assert "cmcp_" not in s1_resp.text
    assert "cmcp_" not in p1_resp.text
    s1 = s1_resp.json()
    p1 = p1_resp.json()
    assert s1["pat_count"] == s1["connection"]["pat_count"] == p1["pat_count"] == 2
    assert s1["authorized_sessions_count"] == p1["authorized_sessions_count"] == 3
    assert s1["state_revision"] != s0["state_revision"]
    assert s1["state_revision"] == s1["connection"]["state_revision"] == p1["state_revision"]

    # External config modification (e.g. tray toggle) immediately changes /api/studio/poll state_revision
    tray.apply_tray_permission_toggle(st_dir, prefix="pc")
    p2 = client.get("/api/studio/poll").json()
    s2 = client.get("/api/studio/state").json()
    assert p2["state_revision"] != p1["state_revision"]
    assert p2["state_revision"] == s2["state_revision"] == s2["connection"]["state_revision"]
    assert p2["safety_mode"] == "readonly"

    # Startup environment lock exposure in both /api/studio/state and /api/studio/poll
    monkeypatch.setenv("COSMOS_MCP_PERMISSION_TIER", "tier1_readonly")
    locked_client, _locked_app, _locked_st, _ = _init_studio_client(
        tmp_path,
        name="env_locked_state",
        port=18974,
        tier_key="tier3_workspace_dev",
    )
    ls = locked_client.get("/api/studio/state").json()
    lp = locked_client.get("/api/studio/poll").json()
    expected_lock = {
        "env_var": "COSMOS_MCP_PERMISSION_TIER",
        "reason": "由启动环境变量锁定",
    }
    assert ls["env_locks"]["permission_tier"] == expected_lock
    assert ls["connection"]["env_locks"]["permission_tier"] == expected_lock
    assert lp["env_locks"]["permission_tier"] == expected_lock


# ---------------------------------------------------------------------------
# 4) rotate_pair_code immediate update & loopback + CSRF enforcement
# ---------------------------------------------------------------------------


def test_rotate_pair_code_updates_immediately_and_enforces_loopback_csrf(tmp_path: Path) -> None:
    client, app, _st_dir, _ws_dir = _init_studio_client(
        tmp_path,
        name="pair_rotate",
        port=18975,
    )
    provider = app.state.provider
    s0 = client.get("/api/studio/state").json()
    csrf = s0["csrf_token"]
    old_dyn = s0["dynamic_pair_code"]
    assert len(old_dyn) == 6 and old_dyn.isdigit()
    assert provider.verify_dynamic_code(old_dyn) is True

    # Missing CSRF -> 403
    r_no_csrf = client.post("/api/studio/connection", json={"action": "rotate_pair_code"})
    assert r_no_csrf.status_code == 403

    # Non-loopback client -> 403 even with CSRF
    remote_client = TestClient(app, base_url="http://127.0.0.1:18975", client=("203.0.113.42", 53115))
    r_remote = remote_client.post(
        "/api/studio/connection",
        headers={"X-Studio-Csrf": csrf},
        json={"action": "rotate_pair_code"},
    )
    assert r_remote.status_code == 403

    # Valid loopback + CSRF -> immediately rotates 6-digit dynamic_pair_code & state_revision
    r_rot = client.post(
        "/api/studio/connection",
        headers={"X-Studio-Csrf": csrf},
        json={"action": "rotate_pair_code"},
    )
    assert r_rot.status_code == 200
    rot_doc = r_rot.json()
    assert rot_doc["ok"] is True
    new_dyn = rot_doc["dynamic_pair_code"]
    assert len(new_dyn) == 6 and new_dyn.isdigit()
    assert new_dyn != old_dyn
    assert rot_doc["consent_pair_code"]
    assert rot_doc["state_revision"] != s0["state_revision"]

    # Provider verifies the new code and rejects the rotated-out old code
    assert provider.verify_dynamic_code(new_dyn) is True
    assert provider.verify_dynamic_code(old_dyn) is False

    # Subsequent /api/studio/poll reflects the rotated dynamic_pair_code and new state_revision
    p_after = client.get("/api/studio/poll").json()
    assert p_after["dynamic_pair_code"] != old_dyn
    assert provider.verify_dynamic_code(p_after["dynamic_pair_code"]) is True
    assert p_after["state_revision"] == rot_doc["state_revision"]


# ---------------------------------------------------------------------------
# 5) Explicit Studio / Tray resume clears STOP lock while auto-spawn stays blocked
# ---------------------------------------------------------------------------


def test_explicit_restart_clears_stop_lock_while_auto_heal_stays_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _app, st_dir, _ws_dir = _init_studio_client(
        tmp_path,
        name="stop_recovery",
        port=18976,
    )
    csrf = client.get("/api/studio/state").json()["csrf_token"]
    stop_flag = daemon.daemon_stop_flag_path(st_dir, "pc")
    stop_flag.parent.mkdir(parents=True, exist_ok=True)
    stop_flag.write_text("STOP:1700000123.0\n", encoding="utf-8")

    status_file = st_dir / "state" / "daemon_status.json"
    status_file.write_text(json.dumps({"status": "stopped", "supervisor_pid": 0}), encoding="utf-8")

    # (a) Non-manual background spawn_detached_daemon (clear_user_stop=False) MUST remain blocked
    blocked = daemon.spawn_detached_daemon(
        python_exe=sys.executable,
        state_root=st_dir,
        port=18976,
        mode="local",
        prefix="pc",
        no_tray=True,
        wait_ready_sec=0.5,
    )
    assert blocked["ok"] is False
    assert blocked["blocked_by_user_stop"] is True
    assert stop_flag.read_text(encoding="utf-8").startswith("STOP:")

    # (b) StandaloneSupervisorLoop.run_forever() also exits 0 immediately when STOP lock is active
    sup = daemon.StandaloneSupervisorLoop(
        state_root=st_dir,
        runtime_python=sys.executable,
        port=18976,
        prefix="pc",
        no_tray=True,
        enforce_singleton=False,
    )
    assert sup.run_forever() == 0
    assert stop_flag.read_text(encoding="utf-8").startswith("STOP:")

    # (c) Explicit Studio panel restart clears STOP lock (CLEAR:...) and calls spawn_detached_daemon(clear_user_stop=True)
    spawn_records: List[Dict[str, Any]] = []

    def _spy_spawn(**kwargs: Any) -> Dict[str, Any]:
        spawn_records.append(dict(kwargs))
        return {"ok": True, "pid": 43210, "cleared": bool(kwargs.get("clear_user_stop"))}

    monkeypatch.setattr(routes_mod, "spawn_detached_daemon", _spy_spawn)
    monkeypatch.setattr(daemon, "spawn_detached_daemon", _spy_spawn)

    r_restart = client.post(
        "/api/studio/service-control",
        headers={"X-Studio-Csrf": csrf},
        json={"action": "restart"},
    )
    assert r_restart.status_code == 200
    res_doc = r_restart.json()
    assert res_doc["ok"] is True
    assert stop_flag.read_text(encoding="utf-8").startswith("CLEAR:")
    assert len(spawn_records) == 1
    assert spawn_records[0]["clear_user_stop"] is True

    # Re-lock STOP and verify Studio connection `service_restart` + Tray `MENU_ID_START_RESUME` also clear STOP
    stop_flag.write_text("STOP:1700000456.0\n", encoding="utf-8")
    r_conn_restart = client.post(
        "/api/studio/connection",
        headers={"X-Studio-Csrf": csrf},
        json={"action": "service_restart"},
    )
    assert r_conn_restart.status_code == 200
    assert stop_flag.read_text(encoding="utf-8").startswith("CLEAR:")
    assert len(spawn_records) == 2
    assert spawn_records[1]["clear_user_stop"] is True

    tray_res = tray.apply_tray_start_or_resume_daemon(st_dir, prefix="pc", port=18976)
    assert tray_res["ok"] is True
    assert len(spawn_records) == 3
    assert spawn_records[2]["clear_user_stop"] is True
