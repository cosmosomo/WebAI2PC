"""v1.1 core incremental feature verification suite (`test_s8_v11_features.py`)."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

import openpyxl
from starlette.testclient import TestClient

from cosmos_mcp.capabilities.skills import scan_local_skills
from cosmos_mcp.capabilities.skills.models import SkillsConfig
from cosmos_mcp.core.config import DEFAULT_PUBLIC_GATEWAY_BASE, LiveRuntimePolicy
from cosmos_mcp.core.fs import edit_file, extract_docx_text_stdlib, extract_xlsx_text_stdlib, manage_files
from cosmos_mcp.core.fs_tx import atomic_write_json
from cosmos_mcp.core.guard import WorkspaceGuard
from cosmos_mcp.core.net_power import ES_CONTINUOUS, ES_SYSTEM_REQUIRED, SleepInhibitor
from cosmos_mcp.core.proc import CREATE_NO_WINDOW
from cosmos_mcp.core.sandbox_hook import L3_SITECUSTOMIZE_SOURCE
from cosmos_mcp.launcher import bootstrap, cli, daemon
from cosmos_mcp.launcher.app import create_standalone_app
from cosmos_mcp.launcher.cf_workers_gateway import (
    FRAME_REQ_END,
    FRAME_REQ_HEAD,
    FRAME_RES_BODY,
    FRAME_RES_END,
    FRAME_RES_HEAD,
    pack_tunnel_frame,
    unpack_tunnel_frame,
)


def _make_split_run_docx(path: Path) -> bytes:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            "</Types>",
        )
        zf.writestr(
            "word/document.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body><w:p>"
            "<w:r><w:t>Hel</w:t></w:r><w:r><w:t>lo </w:t></w:r><w:r><w:t>Legacy</w:t></w:r>"
            "</w:p></w:body></w:document>",
        )
    return path.read_bytes()


def _make_workbook_xlsx(path: Path) -> bytes:
    wb = openpyxl.Workbook()
    ws = wb.active
    assert ws is not None
    ws.title = "Budget"
    ws["A1"] = "Item"
    ws["B1"] = 100
    wb.save(path)
    wb.close()
    return path.read_bytes()


def test_office_docx_xlsx_edit_lock_and_byte_exact_undo(tmp_path: Path) -> None:
    ws = tmp_path / "ws_office"
    st = tmp_path / "state_office"
    ws.mkdir()
    guard = WorkspaceGuard(workspace_roots=[ws], state_root=st, tier="L3")

    docx_p = ws / "spec.docx"
    orig_docx_sha = hashlib.sha256(_make_split_run_docx(docx_p)).hexdigest()
    res_d = edit_file(path=docx_p, old_text="Hello Legacy", new_text="Hello Cosmos V11", guard=guard)
    assert res_d["ok"] is True
    assert "Hello Cosmos V11" in extract_docx_text_stdlib(docx_p)
    undo_d = manage_files(guard, action="undo", path=docx_p)
    assert undo_d["ok"] is True
    assert hashlib.sha256(docx_p.read_bytes()).hexdigest() == orig_docx_sha

    xlsx_p = ws / "budget.xlsx"
    orig_xlsx_sha = hashlib.sha256(_make_workbook_xlsx(xlsx_p)).hexdigest()
    res_x = edit_file(path=xlsx_p, old_text="Budget!B1", new_text="256", guard=guard)
    assert res_x["ok"] is True
    assert "256" in "\n".join(extract_xlsx_text_stdlib(xlsx_p))

    lock_p = ws / "~$budget.xlsx"
    lock_p.write_bytes(b"office-lock")
    locked_res = edit_file(path=xlsx_p, old_text="Budget!B1", new_text="512", guard=guard)
    assert locked_res["ok"] is False
    assert locked_res.get("error_code") == "ERR_OFFICE_FILE_LOCKED"
    lock_p.unlink()

    undo_x = manage_files(guard, action="undo", path=xlsx_p)
    assert undo_x["ok"] is True
    assert hashlib.sha256(xlsx_p.read_bytes()).hexdigest() == orig_xlsx_sha


def test_longest_prefix_readonly_parent_rw_child_and_l3_hook(tmp_path: Path) -> None:
    outer_ro = tmp_path / "outer_ro"
    inner_rw = outer_ro / "inner_rw"
    inner_rw.mkdir(parents=True)
    (outer_ro / "readme.txt").write_text("parent-ro", encoding="utf-8")

    guard = WorkspaceGuard(
        workspace_roots=[inner_rw],
        readonly_workspace_roots=[outer_ro],
        state_root=tmp_path / "st_guard",
        tier="L3",
    )
    assert guard.check_path_access(outer_ro / "readme.txt", mode="read") is None
    err_ro = guard.check_path_access(outer_ro / "readme.txt", mode="write")
    assert err_ro is not None and "ERR_READONLY_WORKSPACE" in err_ro
    assert guard.check_path_access(inner_rw / "allowed.txt", mode="write") is None

    hook_dir = tmp_path / "hook_pkg"
    hook_dir.mkdir()
    (hook_dir / "sitecustomize.py").write_text(L3_SITECUSTOMIZE_SOURCE, encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(hook_dir)
    env["COSMOS_L3_WORKSPACES"] = str(inner_rw)
    env["COSMOS_L3_READONLY_WORKSPACES"] = str(outer_ro)
    env["COSMOS_L3_ALLOW_TMP"] = str(tmp_path / "l3_tmp")
    (tmp_path / "l3_tmp").mkdir()

    probe_code = (
        f"from pathlib import Path\n"
        f"assert Path({str(outer_ro / 'readme.txt')!r}).read_text('utf-8') == 'parent-ro'\n"
        f"Path({str(inner_rw / 'ok.txt')!r}).write_text('rw-ok', encoding='utf-8')\n"
        f"try:\n"
        f"    Path({str(outer_ro / 'deny.txt')!r}).write_text('nope', encoding='utf-8')\n"
        f"    raise SystemExit('WRITE_NOT_BLOCKED')\n"
        f"except PermissionError:\n"
        f"    print('L3_HOOK_OK')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-B", "-c", probe_code],
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        creationflags=CREATE_NO_WINDOW,
    )
    assert proc.returncode == 0, proc.stderr
    assert "L3_HOOK_OK" in proc.stdout


def test_host_skills_default_isolation_and_builtin_scan(tmp_path: Path) -> None:
    fake_home = tmp_path / "fake_home"
    global_sk = fake_home / ".claude" / "skills" / "global-leak-skill"
    global_sk.mkdir(parents=True)
    (global_sk / "SKILL.md").write_text("---\nname: global-leak-skill\ndescription: host global\n---\nbody\n", encoding="utf-8")

    st_root = tmp_path / "state_sk"
    ws = tmp_path / "ws_sk"
    ws.mkdir()

    policy = LiveRuntimePolicy(workspace_roots=[ws], cfg_path=st_root / "config" / "service.json", state_root=st_root)
    assert policy.scan_host_global_skills is False
    sk_cfg = SkillsConfig(workspace_roots=[ws], state_root=st_root, home_dir=fake_home, policy=policy)
    records = scan_local_skills(sk_cfg)
    names = {rec.name for rec in records}
    assert "global-leak-skill" not in names
    assert "cosmos-mcp-guide" in names


def test_instance_id_tool_prefix_hotswap_and_cosmos_node_ws(tmp_path: Path) -> None:
    ws = tmp_path / "ws_node"
    st = tmp_path / "state_node"
    ws.mkdir()
    policy = LiveRuntimePolicy(workspace_roots=[ws], cfg_path=st / "config" / "service.json", state_root=st, eff_prefix="pc")
    assert policy.instance_id == "pc"
    policy.persist_changes(tool_prefix="workpc")
    assert policy.tool_prefix == "workpc"
    assert policy.instance_id == "pc"
    assert (st / "config" / "service.json").is_file()

    sec_dir = st / "secrets"
    sec_dir.mkdir(parents=True, exist_ok=True)
    (sec_dir / "vps_node_secret.txt").write_text("node-sec-v11-test", encoding="utf-8")
    app = create_standalone_app(state_dir=str(st), workspace_roots=[str(ws)], port=18291, public_url="https://hub.example.org")
    disp = app.state.dispatcher

    meta_b64 = base64.urlsafe_b64encode(
        json.dumps(
            {"node_id": "laptop", "workspace_roots": ["/remote_ws"], "drives": [], "platform": "linux", "device_label": "Laptop"}
        ).encode("utf-8")
    ).decode("ascii")

    with TestClient(app) as client:
        with client.websocket_connect(
            "/_cosmos_node",
            headers={
                "Authorization": "Bearer node-sec-v11-test",
                "X-Cosmos-Node-Alias": "laptop",
                "X-Cosmos-Node-Meta": meta_b64,
            },
        ) as ws_conn:
            f_type, req_id, _ = unpack_tunnel_frame(ws_conn.receive_bytes())
            assert f_type == FRAME_REQ_HEAD
            while True:
                ft_i, _, _ = unpack_tunnel_frame(ws_conn.receive_bytes())
                if ft_i == FRAME_REQ_END:
                    break
            ws_conn.send_bytes(
                pack_tunnel_frame(FRAME_RES_HEAD, req_id, json.dumps({"status": 200, "headers": {"content-type": "application/json"}}).encode("utf-8"))
            )
            ws_conn.send_bytes(
                pack_tunnel_frame(
                    FRAME_RES_BODY,
                    req_id,
                    json.dumps({"ok": True, "workspace_roots": ["/remote_ws"], "drives": [], "platform": "linux", "device_label": "Laptop"}).encode("utf-8"),
                )
            )
            ws_conn.send_bytes(pack_tunnel_frame(FRAME_RES_END, req_id, b""))

            fut = ws_conn.portal.start_task_soon(
                disp.call_tool_raw,
                "workpc_read_file",
                {"path": "/remote_ws/hello.txt", "target": "laptop"},
            )
            f_exec, exec_rid, _ = unpack_tunnel_frame(ws_conn.receive_bytes())
            assert f_exec == FRAME_REQ_HEAD
            while True:
                ft_b, _, _ = unpack_tunnel_frame(ws_conn.receive_bytes())
                if ft_b == FRAME_REQ_END:
                    break
            ws_conn.send_bytes(
                pack_tunnel_frame(FRAME_RES_HEAD, exec_rid, json.dumps({"status": 200, "headers": {"content-type": "application/json"}}).encode("utf-8"))
            )
            ws_conn.send_bytes(
                pack_tunnel_frame(FRAME_RES_BODY, exec_rid, json.dumps({"ok": True, "result": {"ok": True, "text": "remote-ok"}, "is_error": False}).encode("utf-8"))
            )
            ws_conn.send_bytes(pack_tunnel_frame(FRAME_RES_END, exec_rid, b""))
            fwd_res, _ = fut.result(timeout=5.0)
            assert "remote-ok" in json.dumps(fwd_res, ensure_ascii=False)

        res_off, err_flag = asyncio.run(disp.call_tool_raw("workpc_read_file", {"path": "/remote_ws/a.txt"}))
        assert err_flag is True or (isinstance(res_off, dict) and res_off.get("ok") is False)
        assert "ERR_NODE_OFFLINE" in json.dumps(res_off, ensure_ascii=False)


def test_public_consent_local_bridge_spoof_cf_403_and_6digit_pair_code(tmp_path: Path) -> None:
    ws = tmp_path / "ws_oa"
    st = tmp_path / "state_oa"
    ws.mkdir()
    port = 18296
    pub_u = "https://gw-demo.workers.dev"
    app = create_standalone_app(state_dir=str(st), workspace_roots=[str(ws)], port=port, public_url=pub_u)
    oauth_prov = app.state.provider

    with TestClient(app, base_url=pub_u, client=("127.0.0.1", 50000)) as pub_client:
        reg = pub_client.post(
            "/register",
            json={
                "client_name": "Gemini Connector",
                "redirect_uris": ["https://oauth-redirect.googleusercontent.com/r/v11test"],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
        )
        assert reg.status_code in (200, 201)
        cid = reg.json()["client_id"]
        verifier = "v11_pkce_verifier_abcdefghijklmnopqrstuvwxyz_0123456789"
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")

        def _start_consent(state_val: str) -> tuple[str, str]:
            r_auth = pub_client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": cid,
                    "redirect_uri": "https://oauth-redirect.googleusercontent.com/r/v11test",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": state_val,
                    "resource": f"{pub_u}/mcp",
                },
                headers={"X-Forwarded-Proto": "https"},
                follow_redirects=False,
            )
            assert r_auth.status_code in (302, 303)
            r_get = pub_client.get(r_auth.headers["location"], headers={"X-Forwarded-Proto": "https"})
            assert r_get.status_code == 200
            m_t = re.search(r'name="ticket"\s+value="([^"]+)"', r_get.text)
            m_c = re.search(r'name="csrf"\s+value="([^"]+)"', r_get.text)
            assert m_t and m_c
            return m_t.group(1), m_c.group(1)

        t1, c1 = _start_consent("st_bridge")
        r_post = pub_client.post(
            f"/consent?ticket={t1}",
            data={"ticket": t1, "csrf": c1, "auth_mode": "local_bridge"},
            headers={"Origin": pub_u, "X-Forwarded-Proto": "https"},
            follow_redirects=False,
        )
        assert r_post.status_code in (302, 303)
        bridge_url = r_post.headers["location"]
        assert bridge_url.startswith(f"http://127.0.0.1:{port}/oauth/local-bridge?")

        r_spoof = pub_client.get(bridge_url, headers={"CF-Connecting-IP": "198.51.100.7"}, follow_redirects=False)
        assert r_spoof.status_code in (403, 421)

        r_loop = pub_client.get(bridge_url, follow_redirects=False)
        assert r_loop.status_code in (302, 303)
        comp_url = r_loop.headers["location"]
        assert comp_url.startswith(f"{pub_u}/consent/complete?")

        r_comp = pub_client.get(comp_url, headers={"X-Forwarded-Proto": "https"}, follow_redirects=False)
        assert r_comp.status_code in (302, 303)
        assert "code=" in r_comp.headers["location"]

        t2, c2 = _start_consent("st_pair6")
        code6 = oauth_prov.get_dynamic_pair_code()
        assert len(code6) == 6 and code6.isdigit()
        r_pair = pub_client.post(
            f"/consent?ticket={t2}",
            data={"ticket": t2, "csrf": c2, "decision": "approve", "pair_code": code6},
            headers={"Origin": pub_u, "X-Forwarded-Proto": "https"},
            follow_redirects=False,
        )
        assert r_pair.status_code in (302, 303)
        assert "code=" in r_pair.headers["location"]


def test_gateway_defaults_battery_stub_daemon_wirings_and_studio_zero_loopback(tmp_path: Path, monkeypatch) -> None:
    assert DEFAULT_PUBLIC_GATEWAY_BASE == ""
    assert bootstrap.is_windows_store_stub(r"C:\Users\alice\AppData\Local\Microsoft\WindowsApps\python.exe") is True
    assert bootstrap.is_windows_store_stub(r"C:\Python312\python.exe") is False

    flags_seen: list[int] = []
    on_bat = {"val": False}
    inhib = SleepInhibitor(
        refresh_interval_sec=60.0,
        _platform_override="win32",
        _win32_setter=lambda f: (flags_seen.append(f), 1)[1],
        _battery_probe=lambda: on_bat["val"],
    )
    st_ac = inhib.enable()
    assert st_ac["inhibiting_sleep"] is True
    assert flags_seen[-1] & ES_SYSTEM_REQUIRED
    on_bat["val"] = True
    inhib.disable()
    st_bat = inhib.enable()
    assert st_bat["on_battery"] is True and st_bat["inhibiting_sleep"] is False
    assert flags_seen[-1] == ES_CONTINUOUS
    inhib.disable()

    st_d = tmp_path / "state_daemon_v11"
    ws_d = tmp_path / "ws_daemon_v11"
    ws_d.mkdir()
    cli.ensure_standalone_state(st_d, port=18298, workspace_roots=[str(ws_d)], tunnel_mode="public_gateway")

    class _FakeCf:
        def __init__(self, **_kw):
            self.pid = 51234

        def is_process_alive(self) -> bool:
            return True

        def start(self, wait_url_timeout_sec: float = 12.0) -> str:
            _ = wait_url_timeout_sec
            return "https://instant-v11-node.trycloudflare.com"

        def stop(self) -> None:
            self.pid = None

    vps_events: list[str] = []

    class _FakeVpsWss:
        def __init__(self, **kw):
            self.consecutive_failures = 0
            self.last_disconnect_reason_zh = ""
            self.last_error = ""
            self._alive = True
            self._conn = True
            vps_events.append(f"init:{kw.get('vps_url')}")

        def is_alive(self) -> bool:
            return self._alive

        def is_connected(self) -> bool:
            return self._conn

        def start(self, **_kw) -> str:
            vps_events.append("start")
            return "https://vps-hub.example.org"

        def stop(self) -> None:
            self._alive = False
            vps_events.append("stop")

    monkeypatch.setattr(daemon, "probe_public_gateway_online", lambda *_a, **_k: {"configured": False, "online": False})
    monkeypatch.setattr(daemon, "ensure_cloudflared_binary", lambda _b: tmp_path / "cloudflared")
    monkeypatch.setattr(daemon, "CloudflaredTunnelSupervisor", _FakeCf)
    monkeypatch.setattr(daemon, "VpsWssNodeSupervisor", _FakeVpsWss)
    monkeypatch.setattr(daemon, "wait_tunnel_dns_and_https_ready", lambda u, **_k: {"ok": True, "public_url": u})

    sup = daemon.StandaloneSupervisorLoop(state_root=st_d, runtime_python=sys.executable, port=18298, mode="public_gateway")
    balloon_calls: list[tuple[str, str]] = []
    tray_snaps: list[dict] = []

    class _MockTray:
        def update_snapshot(self, snap):
            tray_snaps.append(dict(snap))

        def notify_balloon(self, title: str, msg: str, **_kw) -> bool:
            balloon_calls.append((title, msg))
            return True

        def stop(self) -> None:
            pass

    sup._tray = _MockTray()  # type: ignore[assignment]
    try:
        sup._sync_tunnel_from_cfg(initial=True)
        d_doc = json.loads(daemon.daemon_status_path(st_d).read_text(encoding="utf-8"))
        assert d_doc["public_url"] == "https://instant-v11-node.trycloudflare.com"
        assert "127.0.0.1" not in d_doc["mcp_url"]
        assert d_doc["public_gateway_online"] is False
        assert d_doc["instant_fallback_active"] is True
        assert d_doc["effective_tunnel_mode"] == "cloudflare"

        cfg_p = daemon.service_cfg_path(st_d, "pc")
        cfg_doc = json.loads(cfg_p.read_text(encoding="utf-8"))
        cfg_doc.update(
            {
                "tunnel_mode": "vps_hub",
                "vps_hub_url": "https://vps-hub.example.org",
                "vps_node_secret": "vps-sec-123",
                "policy_updated_at": 9999999999.0,
            }
        )
        atomic_write_json(cfg_p, cfg_doc)
        sup._sync_tunnel_from_cfg(initial=False)
        assert "init:https://vps-hub.example.org" in vps_events and "start" in vps_events

        sup._vps_wss_supervisor._conn = False  # type: ignore[union-attr]
        sup._vps_wss_supervisor.consecutive_failures = 3  # type: ignore[union-attr]
        sup._vps_wss_supervisor.last_disconnect_reason_zh = "云端 WSS 握手超时（连续失败 3 次）"  # type: ignore[union-attr]
        sup._poll_tunnel_readiness()
        sup._poll_tunnel_readiness()
        assert balloon_calls == []
        assert tray_snaps[-1]["last_disconnect_reason_zh"] == "云端 WSS 握手超时（连续失败 3 次）"
        from cosmos_mcp.launcher.tray import COLOR_ERROR_RED, format_tray_tooltip, resolve_tray_visual_state

        assert resolve_tray_visual_state(tray_snaps[-1]) == ("error", "异常重连中", COLOR_ERROR_RED)
        assert "云端 WSS 握手超时（连续失败 3 次）" in format_tray_tooltip(tray_snaps[-1])

        cfg_doc["tunnel_mode"] = "local"
        cfg_doc["policy_updated_at"] += 10.0
        atomic_write_json(cfg_p, cfg_doc)
        sup._sync_tunnel_from_cfg(initial=False)
        assert "stop" in vps_events and sup._vps_wss_supervisor is None
    finally:
        sup._stop_cf_supervisor()
        sup._stop_vps_wss_supervisor()
        sup._sup_logger.removeHandler(sup._sup_log_handler)
        sup._sup_log_handler.close()

    st_st = tmp_path / "state_studio_noloop"
    app_st = create_standalone_app(state_dir=str(st_st), workspace_roots=[str(ws_d)], port=18299, tunnel_mode="public_gateway")
    with TestClient(app_st, base_url="http://127.0.0.1:18299") as st_client:
        r_st = st_client.get("/api/studio/state")
        assert r_st.status_code == 200
        st_body = r_st.json()
        for url_k in ("mcp_url", "readonly_mcp_url", "public_url"):
            assert "127.0.0.1" not in str(st_body.get(url_k) or "")


def test_v12_srvus_priority_tray_noloopback_real_at_wake_and_wheels_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    wait_tunnel_probes,
) -> None:
    from cosmos_mcp.launcher.tray import (
        MENU_ID_COPY_MCP_URL,
        MF_GRAYED,
        WindowsSystemTrayController,
        build_tray_menu_items,
    )

    # 1) Studio JS must construct real `@` (`0x40`) via `String.fromCharCode(64)` with zero `[at]` literal
    repo_root = Path(__file__).resolve().parents[1]
    studio_js = (repo_root / "src" / "cosmos_mcp" / "studio" / "static" / "studio.js").read_text(encoding="utf-8")
    assert ("[" + "at" + "]") not in studio_js
    assert "String.fromCharCode(64)" in studio_js
    assert "probeWorkersDevReachabilitySilent" in studio_js

    # 2) Tray menu & clipboard copy strictly block `http://127.0.0.1` in remote modes before HTTPS is ready
    snap_connecting = {"port": 18310, "mode": "public_gateway", "mcp_url": "", "tunnel_ready": False}
    items_conn = build_tray_menu_items(snap_connecting)
    copy_item = [it for it in items_conn if it[1] == MENU_ID_COPY_MCP_URL][0]
    assert (copy_item[0] & MF_GRAYED) != 0
    assert copy_item[2] == "正在建立加密连接…"

    copied_vals: list[str] = []
    tray_ctrl = WindowsSystemTrayController(tmp_path / "tray_st", port=18310, clipboard_fn=lambda s: (copied_vals.append(s) or True))
    res_block = tray_ctrl.handle_menu_command(MENU_ID_COPY_MCP_URL, snapshot=snap_connecting)
    assert res_block["ok"] is False and copied_vals == []
    res_ok = tray_ctrl.handle_menu_command(
        MENU_ID_COPY_MCP_URL,
        snapshot={"port": 18310, "mode": "public_gateway", "mcp_url": "https://fixed123.srv.us/mcp", "tunnel_ready": True},
    )
    assert res_ok["ok"] is True and copied_vals == ["https://fixed123.srv.us/mcp"]

    # 3) `daemon.py` Route 1 tries `SrvUsSshTunnelSupervisor` first, then seamlessly falls back on empty URL / `prefer_quick_tunnel`
    st_s = tmp_path / "state_srvus_v12"
    ws_s = tmp_path / "ws_srvus_v12"
    ws_s.mkdir()
    cli.ensure_standalone_state(st_s, port=18311, workspace_roots=[str(ws_s)], tunnel_mode="public_gateway")

    srvus_return = {"url": "https://abc999.srv.us"}

    class _FakeSrvUs:
        def __init__(self, **kw):
            self.kw = kw
            self._alive = True
            self.pid = 61234

        def is_process_alive(self) -> bool:
            return self._alive

        def start(self, wait_url_timeout_sec: float = 4.0) -> str:
            _ = wait_url_timeout_sec
            return srvus_return["url"]

        def stop(self) -> None:
            self._alive = False

    class _FakeQuickCf:
        def __init__(self, **_kw):
            self.pid = 62345

        def is_process_alive(self) -> bool:
            return True

        def start(self, wait_url_timeout_sec: float = 12.0) -> str:
            _ = wait_url_timeout_sec
            return "https://quick-fallback-v12.trycloudflare.com"

        def stop(self) -> None:
            self.pid = None

    monkeypatch.setattr(daemon, "probe_public_gateway_online", lambda *_a, **_k: {"configured": False, "online": False})
    monkeypatch.setattr(daemon, "SrvUsSshTunnelSupervisor", _FakeSrvUs)
    monkeypatch.setattr(daemon, "ensure_cloudflared_binary", lambda _b: tmp_path / "cloudflared")
    monkeypatch.setattr(daemon, "CloudflaredTunnelSupervisor", _FakeQuickCf)
    monkeypatch.setattr(daemon, "wait_tunnel_dns_and_https_ready", lambda u, **_k: {"ok": True, "public_url": u})

    sup_v12 = daemon.StandaloneSupervisorLoop(state_root=st_s, runtime_python=sys.executable, port=18311, mode="public_gateway")
    try:
        sup_v12._sync_tunnel_from_cfg(initial=True)
        wait_tunnel_probes()
        d_s1 = json.loads(daemon.daemon_status_path(st_s).read_text(encoding="utf-8"))
        assert d_s1["public_url"] == "https://abc999.srv.us"
        assert d_s1["srvus_fixed_active"] is True
        assert d_s1["instant_fallback_active"] is False
        assert d_s1["effective_tunnel_mode"] == "srv_us"

        # Verify Studio `/api/studio/state` reports `srvus_fixed_active=True` and `instant_fallback_active=False`
        app_v12 = create_standalone_app(state_dir=str(st_s), workspace_roots=[str(ws_s)], port=18311, tunnel_mode="public_gateway")
        with TestClient(app_v12, base_url="http://127.0.0.1:18311", client=("127.0.0.1", 51004)) as c_v12:
            st_response = c_v12.get("/api/studio/state")
            assert st_response.status_code == 200
            st_json = st_response.json()
            assert st_json["locked"] is False
            assert st_json["is_loopback"] is True
            assert st_json["srvus_fixed_active"] is True
            assert st_json["instant_fallback_active"] is False
            assert st_json["mcp_url"] == "https://abc999.srv.us/mcp"

        # Simulate `prefer_quick_tunnel=True` -> seamless switch to Quick Tunnel
        cfg_p = daemon.service_cfg_path(st_s, "pc")
        cfg_doc = json.loads(cfg_p.read_text(encoding="utf-8"))
        cfg_doc["prefer_quick_tunnel"] = True
        cfg_doc["policy_updated_at"] = 9999999999.0
        atomic_write_json(cfg_p, cfg_doc)
        sup_v12._sync_tunnel_from_cfg(initial=False)
        wait_tunnel_probes()
        d_s2 = json.loads(daemon.daemon_status_path(st_s).read_text(encoding="utf-8"))
        assert d_s2["public_url"] == "https://quick-fallback-v12.trycloudflare.com"
        assert d_s2["srvus_fixed_active"] is False
        assert d_s2["instant_fallback_active"] is True
    finally:
        sup_v12._stop_srvus_supervisor()
        sup_v12._stop_cf_supervisor()
        sup_v12._sup_logger.removeHandler(sup_v12._sup_log_handler)
        sup_v12._sup_log_handler.close()

    # 4) `build_release.py` supports `--embed-python-dir` + `--wheels-dir` and passes `run_release_checks`
    import importlib.util

    spec_br = importlib.util.spec_from_file_location("build_release_mod", repo_root / "scripts" / "build_release.py")
    assert spec_br and spec_br.loader
    br_mod = importlib.util.module_from_spec(spec_br)
    spec_br.loader.exec_module(br_mod)

    fake_embed = tmp_path / "fake_py_embed"
    fake_embed.mkdir()
    (fake_embed / "python.exe").write_bytes(b"MZ_FAKE_PY")
    (fake_embed / "python312._pth").write_text("python312.zip\n.\n#import site\n", encoding="utf-8")
    fake_wheels = tmp_path / "fake_wheels"
    fake_wheels.mkdir()
    (fake_wheels / "cosmos_dummy-0.1.0-py3-none-any.whl").write_bytes(b"PK_FAKE_WHL")

    portable_zip = tmp_path / "Cosmos-MCP-v1.2.1-portable.zip"
    b_res = br_mod.build_release_zip(repo_root, out_zip=portable_zip, embed_python_dir=fake_embed, wheels_dir=fake_wheels)
    assert b_res["ok"] is True and b_res["bundled_wheels"] == 1
    chk_ok, chk_errs, _ = br_mod.run_release_checks(repo_root, zip_path=portable_zip)
    assert chk_ok is True, chk_errs


def test_vps_hub_online_pc_default_relative_routing_and_offline_contract(
    tmp_path: Path,
    monkeypatch,
) -> None:
    vps_ws = tmp_path / "vps_hub_ws"
    vps_st = tmp_path / "vps_hub_state"
    vps_ws.mkdir()
    (vps_ws / "vps_only.txt").write_text("vps-local-file", encoding="utf-8")

    app = create_standalone_app(
        state_dir=str(vps_st),
        workspace_roots=[str(vps_ws)],
        port=18319,
        public_url="https://vps-hub.example.org",
        tunnel_mode="vps_hub",
    )
    disp = app.state.dispatcher

    # 1) Standalone / zero-remote-node mode: 100% local execution for `.`, relative paths, and pathless tools
    res_local_find, err_lf = asyncio.run(disp.call_tool_raw("pc_find_files", {"path": "."}))
    assert err_lf is False
    assert "vps_only.txt" in json.dumps(res_local_find, ensure_ascii=False)
    res_local_st, err_ls = asyncio.run(disp.call_tool_raw("pc_get_status", {}))
    assert err_ls is False and res_local_st["ok"] is True

    # Simulate Linux 24h `vps_hub` host with an online Windows PC child node mounted
    monkeypatch.setattr(sys, "platform", "linux")
    forwarded_calls: list[tuple[str, str, dict]] = []

    async def _fake_pc_forwarder(target_nid: str, base_name: str, forward_args: dict, **_kw):
        forwarded_calls.append((target_nid, base_name, dict(forward_args)))
        return {
            "ok": True,
            "routed_to": target_nid,
            "base_name": base_name,
            "echo_args": dict(forward_args),
        }

    disp.set_remote_forwarder(_fake_pc_forwarder)
    disp.register_remote_node(
        "pc",
        workspace_roots=[r"E:\Users\Alice\Workspace"],
        drives=["e:", "c:"],
        online=True,
        platform_name="win32",
        device_label="Alice-Desktop",
        forwarder=_fake_pc_forwarder,
    )

    # 2) Online PC child node + `target="auto"` (or omitted): `.`, `docs/a.docx`, `月度预算.xlsx`, empty cwd, and pathless tools route to PC
    for tool_name, call_args, expected_base in (
        ("pc_find_files", {"path": ".", "target": "auto"}, "find_files"),
        ("pc_read_file", {"path": "docs/a.docx", "target": "auto"}, "read_file"),
        ("pc_edit_file", {"path": "月度预算.xlsx", "old_text": "Budget!B2", "new_text": "200"}, "edit_file"),
        ("pc_get_status", {"target": "auto"}, "get_status"),
        ("pc_run_command", {"command": "dir"}, "run_command"),
        ("pc_read_file", {"path": r"C:\Users\Alice\Desktop\memo.txt"}, "read_file"),
        ("pc_read_file", {"path": r"\\NAS\share\report.xlsx"}, "read_file"),
        ("pc_read_file", {"path": "/c/Users/Alice/Desktop/gitbash.txt"}, "read_file"),
    ):
        before_cnt = len(forwarded_calls)
        out_r, is_err_r = asyncio.run(disp.call_tool_raw(tool_name, call_args))
        assert is_err_r is False
        assert len(forwarded_calls) == before_cnt + 1
        assert forwarded_calls[-1][0] == "pc"
        assert forwarded_calls[-1][1] == expected_base
        assert out_r["routed_to"] == "pc"

    # 3) Same Linux `vps_hub` with online PC child node: Linux `/` absolute paths & explicit `target="local"` / `"server"` stay on VPS
    fwd_snapshot = len(forwarded_calls)
    mode_etc, node_etc, _ = disp._resolve_remote_route("auto", {"path": "/etc/hostname"})
    assert mode_etc == "local" and node_etc is None

    out_etc, _ = asyncio.run(disp.call_tool_raw("pc_read_file", {"path": "/etc/hostname", "target": "auto"}))
    assert len(forwarded_calls) == fwd_snapshot
    assert not (isinstance(out_etc, dict) and out_etc.get("routed_to") == "pc")

    for linux_p in ("/opt/cosmos-mcp-hub/hub_gateway.py", "/var/log/syslog", "/srv/app", "/tmp/probe.txt", "/home/ubuntu/a.py", "/root/.bashrc"):
        m_lx, _, _ = disp._resolve_remote_route("auto", {"path": linux_p})
        assert m_lx == "local", linux_p

    out_loc_find, err_loc_find = asyncio.run(disp.call_tool_raw("pc_find_files", {"path": ".", "target": "local"}))
    assert err_loc_find is False
    assert len(forwarded_calls) == fwd_snapshot
    assert Path(out_loc_find["path"]).resolve() == vps_ws.resolve()

    out_srv_st, err_srv_st = asyncio.run(disp.call_tool_raw("pc_get_status", {"target": "server"}))
    assert err_srv_st is False and out_srv_st["ok"] is True
    assert len(forwarded_calls) == fwd_snapshot

    # 4) PC child node goes offline: Windows paths & explicit `target="pc"` return `ERR_NODE_OFFLINE` (no 502), while pathless/Linux requests work locally
    disp.unregister_remote_node("pc", keep_offline_record=True)

    for win_off_args in (
        {"path": r"E:\Users\Alice\Workspace\spec.docx"},
        {"path": r"C:\Users\Alice\Desktop\memo.txt"},
        {"path": r"\\NAS\share\report.xlsx"},
        {"path": ".", "target": "pc"},
    ):
        off_res, off_err = asyncio.run(
            disp.call_tool_raw(
                "pc_read_file" if win_off_args.get("path") != "." else "pc_find_files",
                win_off_args,
            )
        )
        assert off_err is True
        assert isinstance(off_res, dict) and off_res.get("ok") is False
        assert off_res.get("error_code") == "ERR_NODE_OFFLINE"
        assert off_res.get("target") == "pc"

    vps_st_off, vps_st_err = asyncio.run(disp.call_tool_raw("pc_get_status", {}))
    assert vps_st_err is False and vps_st_off["ok"] is True
    vps_find_off, vps_find_err = asyncio.run(disp.call_tool_raw("pc_find_files", {"path": "."}))
    assert vps_find_err is False
    assert Path(vps_find_off["path"]).resolve() == vps_ws.resolve()

