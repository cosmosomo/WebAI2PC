"""Wave 7-A verification suite for multi-gateway coexistence, Win32 registry proxy detection,
non-obfuscated WMI daemon launch, single read-only workspace root retention, and L4 tray toggle restore.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, List

import pytest

from cosmos_mcp.core.config import (
    GATEWAY_IDS,
    TIER_DISPLAY_ZH,
    LiveRuntimePolicy,
    normalize_gateways_config,
    normalize_readonly_workspace_roots,
    parse_strict_annotation_mode,
)
from cosmos_mcp.core.fs_tx import atomic_write_json
from cosmos_mcp.core.guard import WorkspaceGuard
from cosmos_mcp.core.net_power import detect_configured_proxy
from cosmos_mcp.core.proc import CREATE_NO_WINDOW
from cosmos_mcp.launcher import bootstrap, cli, daemon, tunnels
from cosmos_mcp.launcher.cf_workers_gateway import (
    WorkersDevRelaySupervisor,
    _detect_system_proxy,
)
from cosmos_mcp.launcher.tray import (
    COLOR_READY_GREEN,
    COLOR_READONLY_AMBER,
    MENU_ID_TOGGLE_READONLY,
    WindowsSystemTrayController,
    apply_tray_permission_toggle,
    build_tray_menu_items,
    resolve_tray_visual_state,
)


def test_legacy_service_json_lossless_migration_and_slot_isolation(tmp_path: Path) -> None:
    # 1) Legacy `public_gateway` + `.srv.us` migrates cleanly to `instant` slot
    doc_inst: Dict[str, Any] = {
        "tunnel_mode": "public_gateway",
        "public_base": "https://node01.srv.us",
    }
    gws_1, sel_1 = normalize_gateways_config(doc_inst)
    assert set(gws_1.keys()) == set(GATEWAY_IDS)
    assert sel_1 == "instant"
    assert gws_1["instant"]["enabled"] is True
    assert gws_1["instant"]["submode"] == "public_gateway"
    assert gws_1["instant"]["public_url"] == "https://node01.srv.us"
    assert gws_1["workers_dev"]["enabled"] is False
    assert gws_1["self_hosted"]["enabled"] is False
    assert doc_inst["pinned_gateway_urls"] == ["https://node01.srv.us"]

    # 2) Legacy `workers_dev` migrates to `workers_dev` slot
    doc_wd: Dict[str, Any] = {
        "tunnel_mode": "workers_dev",
        "workers_dev_url": "https://cosmos-mcp-node01.team.workers.dev",
    }
    gws_2, sel_2 = normalize_gateways_config(doc_wd)
    assert sel_2 == "workers_dev"
    assert gws_2["workers_dev"]["enabled"] is True
    assert gws_2["workers_dev"]["public_url"] == "https://cosmos-mcp-node01.team.workers.dev"
    assert gws_2["instant"]["enabled"] is False
    assert gws_2["self_hosted"]["enabled"] is False

    # 3) Legacy `vps_hub` migrates to `self_hosted` slot
    doc_vps: Dict[str, Any] = {
        "tunnel_mode": "vps_hub",
        "vps_hub_url": "https://hub.example.org",
    }
    gws_3, sel_3 = normalize_gateways_config(doc_vps)
    assert sel_3 == "self_hosted"
    assert gws_3["self_hosted"]["enabled"] is True
    assert gws_3["self_hosted"]["submode"] == "vps_hub"
    assert gws_3["self_hosted"]["public_url"] == "https://hub.example.org"

    # 4) `LiveRuntimePolicy.update_gateway_slot` enables a 2nd slot without turning off the 1st slot
    ws = tmp_path / "ws_mgw"
    st = tmp_path / "state_mgw"
    ws.mkdir()
    cfg_p = st / "config" / "service.json"
    cfg_p.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(
        cfg_p,
        {
            "workspace_roots": [str(ws)],
            "tunnel_mode": "public_gateway",
            "public_base": "https://keep01.srv.us",
        },
    )

    policy = LiveRuntimePolicy.from_disk(state_root=st, eff_prefix="pc")
    assert list(policy.get_enabled_gateways().keys()) == ["instant"]
    assert policy.selected_gateway == "instant"

    policy.update_gateway_slot(
        "workers_dev",
        enabled=True,
        submode="workers_dev",
        public_url="https://cosmos-mcp-keep01.team.workers.dev",
        select=True,
    )
    assert list(policy.get_enabled_gateways().keys()) == ["instant", "workers_dev"]
    assert policy.gateways["instant"]["enabled"] is True
    assert policy.gateways["instant"]["public_url"] == "https://keep01.srv.us"
    assert policy.gateways["workers_dev"]["enabled"] is True
    assert policy.selected_gateway == "workers_dev"
    assert set(policy.pinned_gateway_urls) == {
        "https://keep01.srv.us",
        "https://cosmos-mcp-keep01.team.workers.dev",
    }

    # 5) `hot_refresh_public_url(..., gateway_id="instant")` updates ONLY `instant` when `selected_gateway == "workers_dev"`
    hr_res = tunnels.hot_refresh_public_url(
        st,
        "https://ephemeral-99.trycloudflare.com",
        port=18400,
        prefix="pc",
        tunnel_mode="cloudflare",
        gateway_id="instant",
    )
    assert hr_res["synced_top_public_base"] is False
    saved_after = json.loads(cfg_p.read_text(encoding="utf-8"))
    assert saved_after["public_base"] == "https://cosmos-mcp-keep01.team.workers.dev"
    assert saved_after["gateways"]["instant"]["public_url"] == "https://ephemeral-99.trycloudflare.com"
    assert saved_after["gateways"]["workers_dev"]["public_url"] == "https://cosmos-mcp-keep01.team.workers.dev"
    assert "https://cosmos-mcp-keep01.team.workers.dev" in saved_after["pinned_gateway_urls"]

    # Legacy `update_config(tunnel_mode="local")` still performs single-switch compat
    policy.refresh()
    policy.update_config({"tunnel_mode": "local"})
    assert policy.get_enabled_gateways() == {}
    assert policy.tunnel_mode == "local"


def test_instant_srvus_ready_survives_failing_workers_dev_and_keeps_tray_green(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    wait_tunnel_probes: Any,
) -> None:
    st = tmp_path / "state_coexist"
    ws = tmp_path / "ws_coexist"
    ws.mkdir()
    cli.ensure_standalone_state(st, port=18410, workspace_roots=[str(ws)], tunnel_mode="public_gateway")

    srvus_events: List[str] = []
    workers_instances: List[Any] = []

    class _FakeSrvUs:
        def __init__(self, **kw: Any) -> None:
            self.kw = kw
            self._alive = True
            self.pid = 71001

        def is_process_alive(self) -> bool:
            return self._alive

        def start(self, wait_url_timeout_sec: float = 4.0) -> str:
            _ = wait_url_timeout_sec
            srvus_events.append("start")
            return "https://steady777.srv.us"

        def stop(self) -> None:
            self._alive = False
            srvus_events.append("stop")

    class _FailingWorkersRelay:
        def __init__(self, **kw: Any) -> None:
            self.kw = kw
            self._alive = True
            self.consecutive_failures = 4
            self.last_disconnect_reason_zh = "Workers 边缘握手超时（连续失败 4 次）"
            self.last_error = "handshake_timeout"
            workers_instances.append(self)

        def is_alive(self) -> bool:
            return self._alive

        def is_connected(self) -> bool:
            return False

        def start(self, **_kw: Any) -> str:
            return str(self.kw.get("public_url") or "")

        def stop(self) -> None:
            self._alive = False

    monkeypatch.setattr(daemon, "probe_public_gateway_online", lambda *_a, **_k: {"configured": False, "online": False})
    monkeypatch.setattr(daemon, "SrvUsSshTunnelSupervisor", _FakeSrvUs)
    monkeypatch.setattr(daemon, "WorkersDevRelaySupervisor", _FailingWorkersRelay)
    monkeypatch.setattr(daemon, "load_or_create_workers_tunnel_secret", lambda *_a, **_k: "sec-" + ("a" * 56))
    monkeypatch.setattr(daemon, "wait_tunnel_dns_and_https_ready", lambda u, **_k: {"ok": True, "public_url": u})

    balloon_calls: List[Any] = []
    tray_snaps: List[Dict[str, Any]] = []

    class _MockTray:
        def update_snapshot(self, snap: Dict[str, Any]) -> None:
            tray_snaps.append(dict(snap))

        def notify_balloon(self, *args: Any, **kwargs: Any) -> bool:
            balloon_calls.append((args, kwargs))
            return True

        def stop(self) -> None:
            pass

    sup = daemon.StandaloneSupervisorLoop(state_root=st, runtime_python=sys.executable, port=18410, mode="public_gateway")
    sup._tray = _MockTray()  # type: ignore[assignment]
    try:
        sup._sync_tunnel_from_cfg(initial=True)
        wait_tunnel_probes()

        d_init = json.loads(daemon.daemon_status_path(st).read_text(encoding="utf-8"))
        assert d_init["tunnel_ready"] is True
        assert d_init["public_url"] == "https://steady777.srv.us"
        assert d_init["gateways"]["instant"]["state"] == "ready"

        # Enable a failing/reconnecting `workers_dev` slot alongside online `instant` (`srv.us`)
        policy = LiveRuntimePolicy.from_disk(state_root=st, eff_prefix="pc")
        policy.update_gateway_slot(
            "workers_dev",
            enabled=True,
            public_url="https://broken-worker.team.workers.dev",
            make_selected=True,
        )

        sup._sync_tunnel_from_cfg(initial=False)
        sup._poll_tunnel_readiness()
        sup._sync_tray_from_cfg(state_label="running")

        # `srv.us` MUST NOT be killed, top-level `tunnel_ready` MUST stay True on the ready URL, and tray MUST stay green
        assert "stop" not in srvus_events
        assert sup._srvus_supervisor is not None and sup._srvus_supervisor.is_process_alive() is True
        assert len(workers_instances) == 1

        d_co = json.loads(daemon.daemon_status_path(st).read_text(encoding="utf-8"))
        assert d_co["tunnel_ready"] is True
        assert d_co["any_gateway_ready"] is True
        assert d_co["public_url"] == "https://steady777.srv.us"
        assert d_co["gateways"]["instant"]["enabled"] is True
        assert d_co["gateways"]["instant"]["ready"] is True
        assert d_co["gateways"]["instant"]["state"] == "ready"
        assert d_co["gateways"]["workers_dev"]["enabled"] is True
        assert d_co["gateways"]["workers_dev"]["ready"] is False
        assert d_co["gateways"]["workers_dev"]["state"] == "error"
        assert d_co["gateways"]["workers_dev"]["consecutive_failures"] == 4
        assert balloon_calls == []
        assert tray_snaps
        live_snap = {**tray_snaps[-1], "server_alive": True}
        assert resolve_tray_visual_state(live_snap) == ("ready", "公网就绪", COLOR_READY_GREEN)
    finally:
        sup._stop_srvus_supervisor()
        sup._stop_workers_supervisor()
        sup._stop_cf_supervisor()
        sup._sup_logger.removeHandler(sup._sup_log_handler)
        sup._sup_log_handler.close()


def test_dual_cloudflared_quick_and_named_coexist_and_stop_daemon_cleans_all_tunnel_pids(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    wait_tunnel_probes: Any,
) -> None:
    st = tmp_path / "state_dual_cf"
    ws = tmp_path / "ws_dual_cf"
    ws.mkdir()
    cli.ensure_standalone_state(st, port=18412, workspace_roots=[str(ws)], tunnel_mode="cloudflare")
    tunnels.save_tunnel_token(st, "eyJhIjoiY2YtbmFtZWQtdGVzdC10b2tlbiJ9", prefix="pc")

    policy = LiveRuntimePolicy.from_disk(state_root=st, eff_prefix="pc")
    policy.update_gateway_slot("instant", enabled=True, submode="cloudflare")
    policy.update_gateway_slot(
        "self_hosted",
        enabled=True,
        submode="cloudflare_token",
        public_url="https://named.example.org",
        make_selected=True,
    )

    created_cf: List[Any] = []

    class _FakeDualCf:
        def __init__(self, **kw: Any) -> None:
            self.kw = kw
            self.is_named_tunnel = bool(kw.get("tunnel_token"))
            self.pid = 72002 if self.is_named_tunnel else 72001
            self._alive = True
            created_cf.append(self)

        def is_process_alive(self) -> bool:
            return self._alive

        def start(self, wait_url_timeout_sec: float = 6.0) -> str:
            _ = wait_url_timeout_sec
            return "https://named.example.org" if self.is_named_tunnel else "https://quick-dual.trycloudflare.com"

        def stop(self) -> None:
            self._alive = False

    monkeypatch.setattr(daemon, "ensure_cloudflared_binary", lambda _b: tmp_path / "cloudflared")
    monkeypatch.setattr(daemon, "CloudflaredTunnelSupervisor", _FakeDualCf)
    monkeypatch.setattr(daemon, "wait_tunnel_dns_and_https_ready", lambda u, **_k: {"ok": True, "public_url": u})

    sup = daemon.StandaloneSupervisorLoop(state_root=st, runtime_python=sys.executable, port=18412)
    try:
        sup._sync_tunnel_from_cfg(initial=True)
        wait_tunnel_probes()

        assert sup._cf_quick_supervisor is not None and sup._cf_quick_supervisor.is_process_alive()
        assert sup._cf_named_supervisor is not None and sup._cf_named_supervisor.is_process_alive()
        d_doc = json.loads(daemon.daemon_status_path(st).read_text(encoding="utf-8"))
        assert set(d_doc["tunnel_pids"]) == {72001, 72002}

        killed_pids: List[int] = []
        monkeypatch.setattr(daemon, "is_raw_pid_alive", lambda pid: pid in (72001, 72002))
        monkeypatch.setattr(daemon, "terminate_verified_pid_tree", lambda pid, expected_create_token=None: killed_pids.append(pid))
        stop_res = daemon.stop_daemon(st, prefix="pc", timeout_sec=1.0)
        assert set(killed_pids) == {72001, 72002}
        assert {72001, 72002}.issubset(set(stop_res["terminated_pids"]))
    finally:
        sup._stop_cf_supervisor()
        sup._sup_logger.removeHandler(sup._sup_log_handler)
        sup._sup_log_handler.close()


def test_win32_no_proxy_reads_registry_proxy_respects_bypass_and_injects_edge_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "WSS_PROXY", "wss_proxy"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1,.internal.example.org")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(
        "urllib.request.getproxies",
        lambda: {"no": "localhost,127.0.0.1,.internal.example.org"},
    )
    monkeypatch.setattr(
        "urllib.request.getproxies_registry",
        lambda: {
            "http": "http://127.0.0.1:7897",
            "https": "http://127.0.0.1:7897",
            "override": "localhost;127.*;*.corp.example.com;<local>",
        },
        raising=False,
    )
    monkeypatch.setattr("urllib.request.proxy_bypass_registry", lambda _h: False, raising=False)

    assert detect_configured_proxy("https", target_host="api.cloudflare.com") == "http://127.0.0.1:7897"
    assert _detect_system_proxy("https", target_host="cosmos-mcp-node.sub.workers.dev") == "http://127.0.0.1:7897"
    assert detect_configured_proxy("https", target_host="svc.internal.example.org") == ""
    assert detect_configured_proxy("https", target_host="git.corp.example.com") == ""
    assert detect_configured_proxy("https", target_host="127.0.0.1") == ""
    assert detect_configured_proxy("https", target_host="devbox-local") == ""

    # Edge forwarded headers fallback in `WorkersDevRelaySupervisor._normalize_req_headers`
    sup = object.__new__(WorkersDevRelaySupervisor)
    sup.public_url = "https://cosmos-mcp-node.sub.workers.dev"
    sup.public_prefix = ""
    norm_hdrs = sup._normalize_req_headers([("Accept", "application/json"), ("Host", "internal")])
    hdr_map = {k.lower(): v for k, v in norm_hdrs}
    assert hdr_map.get("x-forwarded-host") == "cosmos-mcp-node.sub.workers.dev"
    assert hdr_map.get("x-cosmos-via-tunnel") == "1"

    # Existing `X-Forwarded-Host` is preserved without duplication
    norm_keep = sup._normalize_req_headers({"X-Forwarded-Host": "custom.example.org"})
    fh_vals = [v for k, v in norm_keep if k.lower() == "x-forwarded-host"]
    assert fh_vals == ["custom.example.org"]


def test_wmi_daemon_spawn_has_zero_base64_or_exec_obfuscation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_src = Path(daemon.__file__).read_text(encoding="utf-8")
    assert "base64" not in daemon_src
    assert "b64decode" not in daemon_src
    assert "FromBase64String" not in daemon_src
    assert "EncodedCommand" not in daemon_src
    assert "exec(" not in daemon_src

    captured: Dict[str, Any] = {}

    class _FakeCompleted:
        returncode = 0
        stdout = "WMI_PID=88421\n"
        stderr = ""

    def _fake_run(cmd: List[str], **kwargs: Any) -> _FakeCompleted:
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return _FakeCompleted()

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr("shutil.which", lambda _name: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    monkeypatch.setattr(subprocess, "run", _fake_run)

    argv = [
        r"C:\Python312\pythonw.exe",
        "-B",
        "-m",
        "cosmos_mcp.launcher.daemon",
        "--state-dir",
        str(tmp_path),
        "--runtime-python",
        r"C:\Python312\python.exe",
        "--port",
        "8096",
    ]
    pid = daemon._spawn_via_wmi_win32_process(
        argv,
        cwd=tmp_path,
        env={"PYTHONPATH": str(tmp_path / "src"), "LOCALPC_MCP_STATE_DIR": str(tmp_path)},
        log_path=tmp_path / "logs" / "supervisor.log",
    )
    assert pid == 88421
    run_cmd = captured["cmd"]
    run_kw = captured["kwargs"]
    assert "-EncodedCommand" not in run_cmd
    assert "-Command" in run_cmd
    assert run_kw["stdin"] == subprocess.DEVNULL
    assert (int(run_kw["creationflags"]) & CREATE_NO_WINDOW) != 0

    wmi_cmd = run_kw["env"]["COSMOS_WMI_CMD"]
    assert "-B -m cosmos_mcp.launcher.daemon" in wmi_cmd
    assert "--log-file" in wmi_cmd
    assert "base64" not in wmi_cmd.lower()
    assert "b64decode" not in wmi_cmd.lower()
    assert "exec(" not in wmi_cmd.lower()


def test_single_readonly_workspace_root_not_washed_out(tmp_path: Path) -> None:
    only_ws = tmp_path / "only_readonly_ws"
    only_ws.mkdir()
    (only_ws / "data.txt").write_text("important", encoding="utf-8")

    ro_norm = normalize_readonly_workspace_roots([only_ws], [only_ws])
    assert ro_norm == (only_ws.resolve(),)

    st = tmp_path / "state_single_ro"
    cli.ensure_standalone_state(
        st,
        port=18420,
        workspace_roots=[str(only_ws)],
        readonly_workspace_roots=[str(only_ws)],
        tunnel_mode="local",
    )
    policy = LiveRuntimePolicy.from_disk(state_root=st, eff_prefix="pc")
    assert [p.resolve() for p in policy.readonly_workspace_roots] == [only_ws.resolve()]

    guard = WorkspaceGuard(
        workspace_roots=policy.workspace_roots,
        readonly_workspace_roots=policy.readonly_workspace_roots,
        state_root=st,
        tier="L3",
    )
    assert guard.check_path_access(only_ws / "data.txt", mode="read") is None
    err_w = guard.check_path_access(only_ws / "data.txt", mode="write")
    assert err_w is not None and "ERR_READONLY_WORKSPACE" in err_w


def test_tray_readonly_toggle_preserves_l4_and_tri_layer_alignment(tmp_path: Path) -> None:
    st = tmp_path / "state_tray_l4"
    ws = tmp_path / "ws_tray_l4"
    ws.mkdir()

    # 1) Preserve `.srv.us` fixed URL + `seamless` annotation_mode on `cli.ensure_standalone_state`
    cli.ensure_standalone_state(
        st,
        port=18430,
        tier_key="L4",
        workspace_roots=[str(ws)],
        tunnel_mode="public_gateway",
        public_url="https://keepfixed88.srv.us",
    )
    # Re-run without `--public-url` to verify `.srv.us` in `service.json` is preserved instead of wiped
    res_cli = cli.ensure_standalone_state(st, port=18430)
    cfg_doc = json.loads((st / "config" / "service.json").read_text(encoding="utf-8"))
    assert cfg_doc["public_base"] == "https://keepfixed88.srv.us"
    assert cfg_doc["annotation_mode"] == "seamless"
    assert parse_strict_annotation_mode("seamless") == "seamless"
    assert parse_strict_annotation_mode("compat") == "seamless"
    assert parse_strict_annotation_mode("strict") == "strict"
    assert parse_strict_annotation_mode("honest") == "strict"
    assert res_cli["effective_tunnel_mode"] == "srv_us"

    # 2) Tray toggle from L4 (`tier4_full_power`) -> `tier1_readonly` -> restores `tier4_full_power` (NOT downgraded to L3)
    ctrl = WindowsSystemTrayController(st, port=18430, prefix="pc")
    ctrl.update_snapshot({"permission_tier": "tier4_full_power", "server_alive": True, "mode": "local"})

    t1 = ctrl.handle_menu_command(MENU_ID_TOGGLE_READONLY)
    assert t1["permission_tier"] == "tier1_readonly"
    assert t1["previous_non_readonly_tier"] == "tier4_full_power"
    assert resolve_tray_visual_state(ctrl.get_snapshot()) == ("readonly", "只读保护模式", COLOR_READONLY_AMBER)

    ro_menu = build_tray_menu_items(ctrl.get_snapshot())
    ro_toggle_label = [it[2] for it in ro_menu if it[1] == MENU_ID_TOGGLE_READONLY][0]
    assert "全盘" in ro_toggle_label

    t2 = ctrl.handle_menu_command(MENU_ID_TOGGLE_READONLY)
    assert t2["permission_tier"] == "tier4_full_power"
    saved_l4 = json.loads((st / "config" / "service.json").read_text(encoding="utf-8"))
    assert saved_l4["permission_tier"] == "tier4_full_power"

    # Also verify L2 -> L1 -> L2 roundtrip
    r_l2_to_ro = apply_tray_permission_toggle(st, prefix="pc", current_tier="tier2_workspace_edit")
    assert r_l2_to_ro["permission_tier"] == "tier1_readonly"
    r_ro_to_l2 = apply_tray_permission_toggle(st, prefix="pc")
    assert r_ro_to_l2["permission_tier"] == "tier2_workspace_edit"

    # 3) Verify 4-tier Chinese labels aligned, `_rewrite_conn_info_urls` placeholder replacement, and `.pyd` not skipped
    assert TIER_DISPLAY_ZH["tier3_workspace_dev"] == "工作区内顺畅开发"
    assert TIER_DISPLAY_ZH["tier4_full_power"] == "全盘顺畅开发（不限目录）"
    assert cli.TIER_DISPLAY_ZH == TIER_DISPLAY_ZH
    assert ".pyd" not in bootstrap._SYNC_SKIP_SUFFIXES

    conn_f = tmp_path / "conn_info_sample.txt"
    conn_f.write_text(
        "  主连接器地址   : (正在建立加密连接… 启动后自动生成公网 HTTPS 地址)\n"
        "  纯只读端点地址 : (正在建立加密连接… 启动后自动生成公网 HTTPS 地址)\n"
        "  动态守则地址   : (正在建立加密连接… 启动后自动生成公网 HTTPS 地址)\n"
        "  [临时地址提示] : 临时地址会在重启后变化\n",
        encoding="utf-8",
    )
    tunnels._rewrite_conn_info_urls(conn_f, "https://keepfixed88.srv.us")
    rewritten = conn_f.read_text(encoding="utf-8")
    assert "https://keepfixed88.srv.us/mcp\n" in rewritten
    assert "https://keepfixed88.srv.us/mcp/readonly\n" in rewritten
    assert "https://keepfixed88.srv.us/skill\n" in rewritten
    assert "[临时地址提示]" not in rewritten
