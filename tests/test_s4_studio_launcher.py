"""End-to-end & headless visual verification suite for S4 (`Cosmos Studio 1.0` & `launcher/`).

Verifies:
1. CLI cold-start binds current project `Path.cwd()` (fallback `~/CosmosWorkspace` on system dirs),
   `keep_awake=True` default, no-arg `start` preserves saved `cloudflare`/`cloudflare_token`/`custom` modes,
   `Pillow>=10.0.0` & `pypdf>=4.0.0` in `CORE_RUNTIME_PIP_SPECS`, `一键启动_Cosmos_MCP.bat` creation & uninstall cleanup,
   and 100% zero `tailscale` residue across `launcher/` and `studio/`.
2. Live temporary local instance rendered in `--headless=new` Chromium/Edge at `1440x900` (desktop) and `390x844` (mobile):
   layout integrity, zero horizontal overflow, synchronized status light + label, and zero bare internal codes.
3. Session-once password unlock -> directory tree browse & add workspace -> Python path config ->
   enable/disable single pack (verifying `browser` shutdown fix when `desktop` stays on) ->
   safety mode downgrade (`edit_only` -> `readonly`) and restore (`full_dev`) + `annotation_mode` sync ->
   live task kill, undo snapshot & trash restore, and honest `.agents/skills/` scan, all `HTTP 200`.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict

import httpx
import pytest

from _studio_driver import LiveStudioServer, StudioPageDriver
from cosmos_mcp.core.fs_tx import atomic_write_json, atomic_write_text, save_undo_snapshot, safe_trash_file
from cosmos_mcp.core.proc import is_raw_pid_alive, resolve_console_python
from cosmos_mcp.launcher import bootstrap, cli, daemon, doctor, tunnels
from cosmos_mcp.launcher.app import create_standalone_app


# ---------------------------------------------------------------------------
# 1. Launcher Cold-Start, No-Tailscale, & 4 Hard Bug Fixes
# ---------------------------------------------------------------------------


def test_zero_tailscale_residue_across_launcher_and_studio() -> None:
    src_root = Path(__file__).resolve().parents[1] / "src" / "cosmos_mcp"
    offenders = []
    for sub in ("launcher", "studio"):
        for p in sorted((src_root / sub).rglob("*")):
            if not p.is_file() or "__pycache__" in p.parts:
                continue
            txt = p.read_text(encoding="utf-8", errors="replace")
            if "tailscale" in txt.lower() or "ts.net" in txt.lower():
                offenders.append(str(p.relative_to(src_root)))
    assert offenders == [], f"Unexpected tailscale residue in: {offenders}"


def test_bootstrap_specs_include_pillow_and_pypdf() -> None:
    specs_joined = " | ".join(bootstrap.CORE_RUNTIME_PIP_SPECS)
    assert "Pillow>=10.0.0" in specs_joined
    assert "pypdf>=4.0.0" in specs_joined
    assert "PIL" in bootstrap.CORE_RUNTIME_IMPORTS
    assert "pypdf" in bootstrap.CORE_RUNTIME_IMPORTS


def test_cold_start_defaults_cwd_keep_awake_and_system_dir_fallback(tmp_path: Path) -> None:
    proj_dir = tmp_path / "my_active_project"
    proj_dir.mkdir(parents=True)
    state_dir = tmp_path / "state_a"
    fake_home = tmp_path / "home_a"
    fake_home.mkdir(parents=True)

    res = cli.ensure_standalone_state(state_dir, port=18120, cwd=proj_dir)
    assert Path(res["default_workspace"]).resolve() == proj_dir.resolve()
    assert res["keep_awake"] is True
    assert not (fake_home / "LocalPCWorkspace").exists()
    assert (state_dir / "一键启动_Cosmos_MCP.bat").is_file()

    # Protected drive root / System32 must fall back to ~/CosmosWorkspace (never ~/LocalPCWorkspace)
    sys_cand = Path(r"C:\Windows\System32") if sys.platform == "win32" else Path("/usr")
    fb_ws = cli.resolve_default_workspace(cwd=sys_cand, home=fake_home, state_root=state_dir)
    assert fb_ws == (fake_home / "CosmosWorkspace").resolve()
    assert not (fake_home / "LocalPCWorkspace").exists()


def test_no_arg_start_preserves_saved_remote_modes_and_named_tunnel_token(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    st_dir = tmp_path / "state_modes"
    ws_dir = tmp_path / "ws_modes"
    ws_dir.mkdir(parents=True)

    # 1. Configure `cloudflare` mode
    rc1 = cli.main(
        [
            "start",
            "--state-dir",
            str(st_dir),
            "--workspace",
            str(ws_dir),
            "--mode",
            "cloudflare",
            "--prepare-only",
            "--json",
        ]
    )
    assert rc1 == 0
    out1 = json.loads(capsys.readouterr().out)
    assert out1["mode"] == "cloudflare"
    assert out1["keep_awake"] is True
    assert "重启后" in out1["reboot_notice"] and "更换" in out1["reboot_notice"]

    # 2. Run `cosmos-mcp start` WITHOUT `--mode`: must NOT overwrite back to `local`!
    rc2 = cli.main(["start", "--state-dir", str(st_dir), "--prepare-only", "--json"])
    assert rc2 == 0
    out2 = json.loads(capsys.readouterr().out)
    assert out2["mode"] == "cloudflare"
    assert out2["tunnel_mode"] == "cloudflare"

    # 3. Configure `cloudflare_token` with `--tunnel-token` and fixed domain
    fake_tok = "eyJhIjoiMTIzNDU2Nzg5MCIsInQiOiJhYmNkZWZnaCIsInMiOiJzxYzAxMjM0NTY3ODkwIn0="
    rc3 = cli.main(
        [
            "start",
            "--state-dir",
            str(st_dir),
            "--tunnel-token",
            f"cloudflared.exe service install {fake_tok}",
            "--public-url",
            "https://mcp.fixed-example.com",
            "--prepare-only",
            "--json",
        ]
    )
    assert rc3 == 0
    out3 = json.loads(capsys.readouterr().out)
    assert out3["mode"] == "cloudflare_token"
    assert out3["mcp_url"] == "https://mcp.fixed-example.com/mcp"
    assert tunnels.load_tunnel_token(st_dir) == fake_tok

    # Verify `--protocol http2` on both Quick Tunnel and Named Tunnel commands
    quick_cmd = tunnels.build_cloudflared_quick_tunnel_cmd("cloudflared", 8096)
    assert "--protocol" in quick_cmd and "http2" in quick_cmd
    named_cmd = tunnels.build_cloudflared_named_tunnel_cmd("cloudflared", fake_tok)
    assert named_cmd[:6] == ["cloudflared", "tunnel", "--no-autoupdate", "--protocol", "http2", "run"]
    assert named_cmd[-2:] == ["--token", fake_tok]

    # No-arg `start` still preserves `cloudflare_token` and fixed URL
    rc4 = cli.main(["start", "--state-dir", str(st_dir), "--prepare-only", "--json"])
    assert rc4 == 0
    out4 = json.loads(capsys.readouterr().out)
    assert out4["mode"] == "cloudflare_token"
    assert out4["mcp_url"] == "https://mcp.fixed-example.com/mcp"

    # Doctor redacts `tunnel_token`
    rep = doctor.run_doctor(st_dir)
    assert "tailscale_available" not in rep["network"]
    assert rep["network"]["tunnel_token_configured"] is True
    assert fake_tok not in json.dumps(rep, ensure_ascii=False)


def test_oneclick_bat_and_uninstall_cleans_desktop_shortcuts_safely(tmp_path: Path) -> None:
    st_dir = tmp_path / "state_uninst"
    fake_home = tmp_path / "home_uninst"
    desk = fake_home / "Desktop"
    ws_dir = tmp_path / "ws_uninst"
    desk.mkdir(parents=True)
    ws_dir.mkdir(parents=True)

    cli.ensure_standalone_state(st_dir, port=18125, workspace_roots=[str(ws_dir)])
    bat_desk = cli.create_desktop_shortcut(st_dir, port=18125, desktop_dir=desk)
    assert bat_desk is not None and bat_desk.is_file()
    if sys.platform == "win32":
        assert bat_desk.name == "一键启动_Cosmos_MCP.bat"
        bat_txt = bat_desk.read_text(encoding="utf-8")
        assert "-B -m cosmos_mcp.launcher.cli start" in bat_txt
        assert "--port 18125" in bat_txt
        assert "--open-browser" in bat_txt
        assert 'start "" "http://127.0.0.1:' not in bat_txt

    # Simulate residual `.lnk` shortcut for Cosmos Studio AND an unrelated user `.lnk`
    cosmos_lnk = desk / "Cosmos Studio 控制台.lnk"
    unrelated_lnk = desk / "Cosmos应急网络与环境自救.lnk"
    cosmos_lnk.write_bytes(b"FAKE_LNK_COSMOS_STUDIO")
    unrelated_lnk.write_bytes(b"DO_NOT_TOUCH_USER_LNK")

    # Create undo snapshot in state_root/history so recovery preservation AND clean workspace are verified
    sample_f = ws_dir / "note.txt"
    sample_f.write_text("v1", encoding="utf-8")
    save_undo_snapshot(sample_f, workspace_roots=[ws_dir], state_root=st_dir)

    winreg_mock: Dict[str, str] = {"Cosmos-MCP": "cmd"}
    un_res = doctor.run_uninstall(
        st_dir,
        home_dir=fake_home,
        desktop_dir=desk,
        platform_name="win32",
        winreg_store=winreg_mock,
    )
    assert un_res["ok"] is True
    assert not bat_desk.exists()
    assert not cosmos_lnk.exists()
    assert unrelated_lnk.is_file(), "Unrelated user shortcut on Desktop must never be removed!"
    assert (st_dir / "history").is_dir()
    assert not (ws_dir / ".undo_history").exists()


# ---------------------------------------------------------------------------
# 2. Studio Targeted Pack Shutdown Bug Fix & Full HTTP 200 E2E Flow
# ---------------------------------------------------------------------------


def test_studio_e2e_single_password_session_pack_cleanup_and_recovery(tmp_path: Path) -> None:
    st_dir = tmp_path / "studio_state"
    ws1 = tmp_path / "ws_main"
    ws2 = tmp_path / "ws_added_from_tree"
    ws1.mkdir(parents=True)
    ws2.mkdir(parents=True)

    with LiveStudioServer(st_dir, ws1) as srv:
        app = srv.app
        dispatcher = app.state.dispatcher
        policy = app.state.policy

        # Track pack shutdown calls to prove the single-pack `browser` cleanup bug fix
        has_cua_pack = "cua" in dispatcher._packs
        shutdown_calls = {"browser": 0, "cua": 0}
        orig_b_shutdown = dispatcher._packs["browser"].shutdown
        orig_c_shutdown = dispatcher._packs["cua"].shutdown if has_cua_pack else None

        def _spy_b_shutdown(prefix_filter: str = "") -> None:
            shutdown_calls["browser"] += 1
            orig_b_shutdown(prefix_filter=prefix_filter)

        def _spy_c_shutdown(prefix_filter: str = "") -> None:
            shutdown_calls["cua"] += 1
            if orig_c_shutdown is not None:
                orig_c_shutdown(prefix_filter=prefix_filter)

        dispatcher._packs["browser"].shutdown = _spy_b_shutdown  # type: ignore[method-assign]
        if has_cua_pack:
            dispatcher._packs["cua"].shutdown = _spy_c_shutdown  # type: ignore[method-assign]

        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=10.0) as client:
            # Verify HTML & separated CSS/JS static assets
            r_html = client.get("/", headers={"Accept": "text/html"})
            assert r_html.status_code == 200
            assert "/static/studio.css" in r_html.text
            assert "/static/studio.js" in r_html.text
            assert client.get("/static/studio.css").status_code == 200
            assert client.get("/static/studio.js").status_code == 200

            st0 = client.get("/api/studio/state").json()
            assert st0["ok"] is True
            assert st0["unlocked"] is True
            assert st0["tools_center"]["core_count"] == 16
            base_skill_count = st0["skills"]["count"]
            assert isinstance(base_skill_count, int) and base_skill_count >= 0
            csrf = st0["csrf_token"]
            assert st0["connection"]["connection_password"] == ""
            r_rev = client.post(
                "/api/studio/connection",
                headers={"X-Studio-Csrf": csrf},
                json={"action": "reveal_password"},
            )
            assert r_rev.status_code == 200
            owner_pw = r_rev.json()["connection_password"]
            assert owner_pw

            # Proxied/non-loopback unauthenticated state is locked and mutation must fail with 403
            st_proxied = client.get("/api/studio/state", headers={"X-Forwarded-For": "203.0.113.9"}).json()
            assert st_proxied["unlocked"] is False
            r_denied = client.post(
                "/api/studio/workspace",
                headers={"X-Studio-Csrf": st_proxied["csrf_token"], "X-Forwarded-For": "203.0.113.9"},
                json={"action": "add", "path": str(ws2)},
            )
            assert r_denied.status_code == 403

            # Step 1: Enter password ONCE -> receive session cookie (`cosmos_studio_sid`)
            r_unlock = client.post(
                "/api/studio/unlock",
                headers={"X-Studio-Csrf": csrf},
                json={"owner_password": owner_pw},
            )
            assert r_unlock.status_code == 200
            assert "cosmos_studio_sid" in client.cookies
            assert r_unlock.json()["unlocked"] is True

            # Step 2: Browse directory tree & add new workspace WITHOUT re-sending password!
            r_tree_root = client.get("/api/studio/fs-tree", headers={"X-Studio-Csrf": csrf})
            assert r_tree_root.status_code == 200
            r_tree_tmp = client.get(
                "/api/studio/fs-tree",
                params={"path": str(tmp_path)},
                headers={"X-Studio-Csrf": csrf},
            )
            assert r_tree_tmp.status_code == 200
            entry_names = [e["name"] for e in r_tree_tmp.json()["entries"]]
            assert "ws_added_from_tree" in entry_names

            r_add_ws = client.post(
                "/api/studio/workspace",
                headers={"X-Studio-Csrf": csrf},
                json={"action": "add", "path": str(ws2)},
            )
            assert r_add_ws.status_code == 200
            assert str(ws2.resolve()) in r_add_ws.json()["workspaces"]["roots"]

            # Save default Python interpreter path -> verify policy.python_path & service.json
            r_py = client.post(
                "/api/studio/workspace",
                headers={"X-Studio-Csrf": csrf},
                json={"action": "set_python", "python_path": sys.executable},
            )
            assert r_py.status_code == 200
            assert Path(policy.python_path).resolve() == Path(sys.executable).resolve()

            # Step 3: Enable BOTH `browser` and `desktop` packs -> then disable ONLY `browser`!
            r_pk_both = client.post(
                "/api/studio/tools-safety",
                headers={"X-Studio-Csrf": csrf},
                json={"pack_browser": True, "pack_desktop": True},
            )
            assert r_pk_both.status_code == 200
            assert set(policy.enabled_packs) == {"browser", "cua"}

            before_b = shutdown_calls["browser"]
            before_c = shutdown_calls["cua"]
            r_pk_only_desk = client.post(
                "/api/studio/tools-safety",
                headers={"X-Studio-Csrf": csrf},
                json={"pack_browser": False, "pack_desktop": True},
            )
            assert r_pk_only_desk.status_code == 200
            assert list(policy.enabled_packs) == ["cua"]
            assert shutdown_calls["browser"] > before_b, "Disabling `browser` alone MUST invoke BrowserPackPlugin.shutdown()!"
            assert shutdown_calls["cua"] == before_c, "Keeping `desktop` enabled must NOT kill desktop pack!"

            # Step 4: Switch safety downgrade (`edit_only` -> `readonly`) and back to `full_dev` + `confirm_popups`
            r_edit = client.post(
                "/api/studio/tools-safety",
                headers={"X-Studio-Csrf": csrf},
                json={"safety_mode": "edit_only", "confirm_popups": True},
            )
            assert r_edit.status_code == 200
            d_edit = r_edit.json()
            assert d_edit["safety_mode"] == "edit_only"
            assert d_edit["status_kind"] == "editonly"
            assert policy.approval_popups is True
            assert getattr(policy, "annotation_mode", "") == "honest"

            r_ro = client.post(
                "/api/studio/tools-safety",
                headers={"X-Studio-Csrf": csrf},
                json={"safety_mode": "readonly"},
            )
            assert r_ro.status_code == 200
            assert r_ro.json()["safety_mode"] == "readonly"
            assert r_ro.json()["status_kind"] == "readonly"

            # Switch to `full_power` (`tier4_full_power` unrestricted cross-directory mode) and verify cross-dir recovery
            r_fp = client.post(
                "/api/studio/tools-safety",
                headers={"X-Studio-Csrf": csrf},
                json={"safety_mode": "full_power"},
            )
            assert r_fp.status_code == 200
            d_fp = r_fp.json()
            assert d_fp["safety_mode"] == "full_power"
            assert d_fp["safety_mode_label"] == "全盘顺畅开发（不限目录）"
            assert d_fp["status_kind"] == "online"
            assert "全盘顺畅开发（不限目录）" in d_fp["status_text"]
            assert policy.tier_key == "tier4_full_power"
            assert policy.restrict_to_workspace is False
            assert policy.guard is not None and policy.guard.restrict_to_workspace is False

            poll_fp = client.get("/api/studio/poll").json()
            assert poll_fp["safety_mode"] == "full_power"
            assert "全盘顺畅开发（不限目录）" in poll_fp["status_text"]

            # Verify external tray toggle (`service.json` -> `tier1_readonly`) syncs immediately on `/api/studio/poll`
            from cosmos_mcp.launcher.tray import apply_tray_permission_toggle

            tray_ro = apply_tray_permission_toggle(st_dir, prefix="pc", current_tier="tier4_full_power")
            assert tray_ro["permission_tier"] == "tier1_readonly"
            poll_after_tray = client.get("/api/studio/poll").json()
            assert poll_after_tray["safety_mode"] == "readonly"
            assert poll_after_tray["status_kind"] == "readonly"

            r_fp2 = client.post(
                "/api/studio/tools-safety",
                headers={"X-Studio-Csrf": csrf},
                json={"safety_mode": "full_power"},
            )
            assert r_fp2.status_code == 200 and r_fp2.json()["safety_mode"] == "full_power"

            ext_outside_dir = tmp_path / "ext_outside_workspace_dir"
            ext_outside_dir.mkdir(parents=True, exist_ok=True)
            ext_edit_f = ext_outside_dir / "cross_dir_mod.py"
            ext_edit_f.write_text("v = 10\n", encoding="utf-8")
            save_undo_snapshot(ext_edit_f, state_root=st_dir)
            atomic_write_text(ext_edit_f, "v = 20\n")

            ext_trash_f = ext_outside_dir / "cross_dir_note.txt"
            ext_trash_f.write_text("cross-dir-trash-ok", encoding="utf-8")
            ext_tr = safe_trash_file(ext_trash_f, reason="test_cross_dir_trash", state_root=st_dir)
            assert not ext_trash_f.exists()

            rec_fp = client.get("/api/studio/recovery").json()
            assert any(Path(it["path"]).resolve() == ext_edit_f.resolve() for it in rec_fp["snapshots"])
            assert any(it["trash_id"] == ext_tr["trash_id"] for it in rec_fp["trash_items"])

            r_ext_undo = client.post(
                "/api/studio/recovery",
                headers={"X-Studio-Csrf": csrf},
                json={"action": "undo", "path": str(ext_edit_f)},
            )
            assert r_ext_undo.status_code == 200
            assert ext_edit_f.read_text(encoding="utf-8") == "v = 10\n"

            r_ext_rest = client.post(
                "/api/studio/recovery",
                headers={"X-Studio-Csrf": csrf},
                json={"action": "restore_trash", "trash_id": ext_tr["trash_id"]},
            )
            assert r_ext_rest.status_code == 200
            assert ext_trash_f.read_text(encoding="utf-8") == "cross-dir-trash-ok"

            r_full = client.post(
                "/api/studio/tools-safety",
                headers={"X-Studio-Csrf": csrf},
                json={"safety_mode": "full_dev", "confirm_popups": False},
            )
            assert r_full.status_code == 200
            assert r_full.json()["safety_mode"] == "full_dev"
            assert r_full.json()["safety_mode_label"] == "工作区内顺畅开发"
            assert r_full.json()["status_kind"] == "online"
            assert policy.restrict_to_workspace is True
            assert policy.guard is not None and policy.guard.restrict_to_workspace is True
            assert policy.approval_popups is False
            assert getattr(policy, "_annotation_mode", "") in ("seamless", "compat")
            policy.persist_changes(approval_popups=True)
            assert policy.approval_popups is True
            assert getattr(policy, "_annotation_mode", "") in ("strict", "honest")
            policy.persist_changes(approval_popups=False)
            assert policy.approval_popups is False
            assert getattr(policy, "_annotation_mode", "") in ("seamless", "compat")

            # Step 5: Recovery (one-click undo & one-click trash restore) + honest `.agents/skills` scan
            target_f = ws1 / "demo.py"
            target_f.write_text("x = 1\n", encoding="utf-8")
            save_undo_snapshot(target_f, workspace_roots=policy.workspace_roots)
            atomic_write_text(target_f, "x = 999\n")

            trashed_f = ws1 / "to_recover.txt"
            trashed_f.write_text("precious content", encoding="utf-8")
            tr_info = safe_trash_file(trashed_f, reason="test_trash", workspace_roots=policy.workspace_roots)
            assert not trashed_f.exists()

            rec_list = client.get("/api/studio/recovery").json()
            assert len(rec_list["snapshots"]) >= 1
            assert len(rec_list["trash_items"]) >= 1

            r_undo = client.post(
                "/api/studio/recovery",
                headers={"X-Studio-Csrf": csrf},
                json={"action": "undo", "path": str(target_f)},
            )
            assert r_undo.status_code == 200
            assert target_f.read_text(encoding="utf-8") == "x = 1\n"

            r_rest = client.post(
                "/api/studio/recovery",
                headers={"X-Studio-Csrf": csrf},
                json={"action": "restore_trash", "trash_id": tr_info["trash_id"]},
            )
            assert r_rest.status_code == 200
            assert trashed_f.read_text(encoding="utf-8") == "precious content"

            # Background task start -> live tail log -> one-click kill
            pm = app.state.proc_mgr
            bg_start = pm.manage_bg_command(action="start", command="echo STUDIO_BG_HELLO", cwd=str(ws1))
            assert bg_start["ok"] is True
            jid = bg_start["job_id"]
            r_tk_log = client.get("/api/studio/tasks", params={"job_id": jid})
            assert r_tk_log.status_code == 200
            assert r_tk_log.json()["selected"]["job_id"] == jid
            r_tk_kill = client.post(
                "/api/studio/tasks",
                headers={"X-Studio-Csrf": csrf},
                json={"action": "kill", "job_id": jid},
            )
            assert r_tk_kill.status_code == 200

            # Honest `.agents/skills` scan: create 1 real skill in workspace and verify count increments by +1
            sk_md = ws1 / ".agents" / "skills" / "s4-unique-demo-skill" / "SKILL.md"
            sk_md.parent.mkdir(parents=True)
            sk_md.write_text("---\nname: s4-unique-demo-skill\ndescription: 示例本地技能\n---\n# Demo\n", encoding="utf-8")
            st_after_sk = client.get("/api/studio/state").json()
            assert st_after_sk["skills"]["count"] == base_skill_count + 1
            assert any(it["name"] == "s4-unique-demo-skill" for it in st_after_sk["skills"]["items"])


# ---------------------------------------------------------------------------
# 3. Headless Browser (`--headless=new`) 1440x900 & 390x844 Visual + Click E2E
# ---------------------------------------------------------------------------


def test_headless_browser_dual_viewport_visual_and_dom_click_flow(tmp_path: Path) -> None:
    st_dir = tmp_path / "headless_state"
    ws1 = tmp_path / "project_alpha"
    ws2 = tmp_path / "project_beta"
    ws1.mkdir(parents=True)
    ws2.mkdir(parents=True)
    prof_dir = tmp_path / "cdp_profile"
    prof_dir.mkdir(parents=True)

    with LiveStudioServer(st_dir, ws1, thread_prefix="s4-ui") as srv:
        pw_plain = cli._extract_saved_password(st_dir, "pc")
        assert pw_plain

        with StudioPageDriver(prof_dir) as driver:
            driver.set_viewport(1440, 900, mobile=False, device_scale_factor=1)
            driver.goto(f"{srv.base_url}/")

            desk_metrics = driver.evaluate(
                """() => {
                    const badge = document.getElementById('service-status-badge');
                    const dot = document.getElementById('service-status-dot');
                    const txt = document.getElementById('service-status-text');
                    return {
                        badgeClass: badge ? badge.className : '',
                        dotClass: dot ? dot.className : '',
                        statusText: txt ? txt.textContent.trim() : '',
                    };
                }"""
            )
            assert "online" in desk_metrics["badgeClass"] and "online" in desk_metrics["dotClass"]
            assert "在线运行" in desk_metrics["statusText"]

            desk_png = driver.screenshot(full_page=False)
            assert len(desk_png) > 10_000 and desk_png[:8] == b"\x89PNG\r\n\x1a\n"

            # 1) Unlock session once via thin driver
            driver.unlock_session(pw_plain)

            # 2) Open directory tree picker to verify drawer opens, then add ws2 via driver and toggle readonly
            driver.evaluate("() => document.getElementById('open-tree-picker-btn').click()")
            driver.wait_until(
                "() => document.getElementById('fs-tree-drawer')?.classList.contains('open')",
                description="directory tree drawer opened",
            )
            ws_added = driver.add_workspace(ws2, readonly=False)
            assert ws_added["ok"] is True
            assert ws_added["permSelectCount"] == 1

            # Toggle secondary workspace permission `<select>` to readonly and confirm in live runtime state
            driver.evaluate(
                """() => {
                    const sel = document.querySelector('.ws-perm-select');
                    sel.value = 'readonly';
                    sel.dispatchEvent(new Event('change'));
                }"""
            )
            ws_ro_ok = driver.wait_until(
                """async () => {
                    const st = await (await fetch('/api/studio/state')).json();
                    return (st.workspaces.readonly_roots || []).some(p => p.toLowerCase().includes('project_beta'));
                }""",
                description="secondary workspace switched to readonly",
            )
            assert ws_ro_ok is True

            # 3) Settings -> Tools packs toggle (enable desktop -> enable browser -> disable browser)
            driver.open_settings("tools")
            driver.evaluate(
                """() => {
                    const dChk = document.getElementById('chk-pack-desktop');
                    dChk.checked = true;
                    dChk.dispatchEvent(new Event('change'));
                }"""
            )
            deadline = time.monotonic() + 6.0
            while time.monotonic() < deadline and "cua" not in srv.app.state.policy.enabled_packs:
                time.sleep(0.05)
            assert "cua" in srv.app.state.policy.enabled_packs

            driver.evaluate(
                """() => {
                    const bChk = document.getElementById('chk-pack-browser');
                    bChk.checked = true;
                    bChk.dispatchEvent(new Event('change'));
                }"""
            )
            deadline = time.monotonic() + 6.0
            while time.monotonic() < deadline and "browser" not in srv.app.state.policy.enabled_packs:
                time.sleep(0.05)
            assert {"cua", "browser"}.issubset(set(srv.app.state.policy.enabled_packs))

            driver.evaluate(
                """() => {
                    const bChk = document.getElementById('chk-pack-browser');
                    bChk.checked = false;
                    bChk.dispatchEvent(new Event('change'));
                }"""
            )
            deadline = time.monotonic() + 6.0
            while time.monotonic() < deadline and "browser" in srv.app.state.policy.enabled_packs:
                time.sleep(0.05)
            assert "cua" in srv.app.state.policy.enabled_packs and "browser" not in srv.app.state.policy.enabled_packs

            # 4) Safety tier transitions (`readonly` -> `full_power` -> `full_dev`) via thin driver
            ro_state = driver.set_safety_mode("readonly")
            assert "readonly" in ro_state["badgeClass"] and "readonly" in ro_state["dotClass"]

            fp_state = driver.set_safety_mode("full_power")
            assert "online" in fp_state["badgeClass"]
            assert fp_state["fullpowerBannerVisible"] is True

            dev_state = driver.set_safety_mode("full_dev")
            assert "online" in dev_state["badgeClass"] and "online" in dev_state["dotClass"]
            assert dev_state["fullpowerBannerVisible"] is False

            # Mobile screenshot sanity check
            driver.set_viewport(390, 844, mobile=True, device_scale_factor=2)
            mob_png = driver.screenshot(full_page=False)
            assert len(mob_png) > 10_000 and mob_png[:8] == b"\x89PNG\r\n\x1a\n"
            assert driver.get_runtime_diagnostics()["jsErrors"] == []


# ---------------------------------------------------------------------------
# 4. W2-A Regressions: First-Run Cloudflare Default, VPS Hot-Switch & Reap,
#    and `uninstall --purge` Cryptographic Wipe (Zero `%TEMP%` Secret Residue)
# ---------------------------------------------------------------------------


def test_first_run_default_cloudflare_explicit_local_and_16_core_help(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ws_dir = tmp_path / "ws_first_run"
    ws_dir.mkdir(parents=True)

    # 1) Unconfigured first-run `start` and `agent-setup` (without `--mode`) default to `public_gateway` (`srv.us` first, 4s auto-fallback)
    st_fresh = tmp_path / "state_fresh_default"
    rc_fresh = cli.main(
        [
            "start",
            "--state-dir",
            str(st_fresh),
            "--workspace",
            str(ws_dir),
            "--prepare-only",
            "--json",
        ]
    )
    assert rc_fresh == 0
    out_fresh = json.loads(capsys.readouterr().out)
    assert out_fresh["mode"] == "public_gateway"
    assert out_fresh["tunnel_mode"] == "public_gateway"

    st_agent = tmp_path / "state_agent_setup_default"
    rc_agent = cli.main(
        [
            "agent-setup",
            "--state-dir",
            str(st_agent),
            "--workspace",
            str(ws_dir),
            "--prepare-only",
            "--json",
        ]
    )
    assert rc_agent == 0
    out_agent = json.loads(capsys.readouterr().out)
    assert out_agent["mode"] == "public_gateway"
    assert out_agent["tunnel_mode"] == "public_gateway"

    # 1b) Explicit `--mode openssh` works as a first-class self-documenting alias for Card 1
    st_openssh = tmp_path / "state_explicit_openssh"
    rc_openssh = cli.main(
        [
            "agent-setup",
            "--state-dir",
            str(st_openssh),
            "--workspace",
            str(ws_dir),
            "--mode",
            "openssh",
            "--prepare-only",
            "--json",
        ]
    )
    assert rc_openssh == 0
    out_openssh = json.loads(capsys.readouterr().out)
    assert out_openssh["ok"] is True
    saved_openssh_cfg = json.loads((st_openssh / "config" / "service.json").read_text(encoding="utf-8-sig"))
    assert saved_openssh_cfg["gateways"]["instant"]["enabled"] is True
    assert saved_openssh_cfg["gateways"]["instant"]["submode"] == "public_gateway"

    # 2) Explicit `--mode local` strictly respects `"local"` and persists `"local"` across subsequent no-arg `start`
    st_local = tmp_path / "state_explicit_local"
    rc_loc1 = cli.main(
        [
            "start",
            "--state-dir",
            str(st_local),
            "--workspace",
            str(ws_dir),
            "--mode",
            "local",
            "--prepare-only",
            "--json",
        ]
    )
    assert rc_loc1 == 0
    out_loc1 = json.loads(capsys.readouterr().out)
    assert out_loc1["mode"] == "local"
    assert out_loc1["tunnel_mode"] == "local"
    assert out_loc1["mcp_url"].startswith("http://127.0.0.1:")

    rc_loc2 = cli.main(["start", "--state-dir", str(st_local), "--prepare-only", "--json"])
    assert rc_loc2 == 0
    out_loc2 = json.loads(capsys.readouterr().out)
    assert out_loc2["mode"] == "local"
    assert out_loc2["tunnel_mode"] == "local"

    # 3) CLI `--toolset` help text reflects 16 core tools (`16 项`), zero stale `12 项`
    parser = cli.build_cli_parser()
    for sub_cmd in ("start", "setup", "agent-setup"):
        sub_parser = parser._subparsers._group_actions[0].choices[sub_cmd]  # type: ignore[union-attr]
        help_txt = sub_parser.format_help()
        assert "16 项" in help_txt
        assert "12 项" not in help_txt

    # 4) Offline fallback: if `cloudflared` cannot start when offline, supervisor preserves `cloudflare tunnel error`
    st_offline = tmp_path / "state_offline_cf"
    cli.ensure_standalone_state(st_offline, port=18190, workspace_roots=[str(ws_dir)], tunnel_mode="cloudflare")
    monkeypatch.setattr(
        daemon,
        "ensure_cloudflared_binary",
        lambda _bin_dir: (_ for _ in ()).throw(RuntimeError("network unreachable while offline")),
    )
    sup_off = daemon.StandaloneSupervisorLoop(
        state_root=st_offline,
        runtime_python=sys.executable,
        port=18190,
        mode="cloudflare",
    )
    try:
        sup_off._sync_tunnel_from_cfg(initial=True)
        sup_off._write_daemon_status(state_label="running")
        d_doc = json.loads(daemon.daemon_status_path(st_offline).read_text(encoding="utf-8"))
        assert d_doc["public_url"] == ""
        assert d_doc["mcp_url"] == ""
        assert d_doc.get("connecting_status_zh") == "正在建立加密连接…"
        assert "cloudflare tunnel error" in d_doc.get("last_error", "").lower()
    finally:
        sup_off._stop_cf_supervisor()
        sup_off._stop_ssh_tunnel()
        sup_off._sup_logger.removeHandler(sup_off._sup_log_handler)
        sup_off._sup_log_handler.close()


def test_daemon_vps_ssh_hot_switch_restart_error_and_zero_orphan_reap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    st_dir = tmp_path / "state_vps_hot"
    ws_dir = tmp_path / "ws_vps_hot"
    fake_bin = tmp_path / "fake_ssh_bin"
    ws_dir.mkdir(parents=True)
    fake_bin.mkdir(parents=True)

    mock_ssh_py = tmp_path / "mock_ssh_worker.py"
    pid_ledger = tmp_path / "spawned_ssh_children.jsonl"
    mock_ssh_py.write_text(
        "import json, os, sys, time\n"
        f"ledger = {str(pid_ledger)!r}\n"
        "args = sys.argv[1:]\n"
        "with open(ledger, 'a', encoding='utf-8') as fh:\n"
        "    fh.write(json.dumps({'pid': os.getpid(), 'args': args}) + '\\n')\n"
        "if any('bad-auth@' in a for a in args):\n"
        "    sys.stderr.write('Permission denied (publickey).\\n')\n"
        "    sys.stderr.flush()\n"
        "    raise SystemExit(255)\n"
        "time.sleep(15)\n",
        encoding="utf-8",
    )

    py_con = resolve_console_python(sys.executable)
    if sys.platform == "win32":
        ssh_shim = fake_bin / "ssh.bat"
        ssh_shim.write_text(
            f'@echo off\r\n"{py_con}" -B "{mock_ssh_py}" %*\r\n',
            encoding="utf-8",
        )
    else:
        ssh_shim = fake_bin / "ssh"
        ssh_shim.write_text(
            f'#!/usr/bin/env bash\nexec "{py_con}" -B "{mock_ssh_py}" "$@"\n',
            encoding="utf-8",
        )
        os.chmod(ssh_shim, 0o755)

    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}")

    cli.ensure_standalone_state(st_dir, port=18192, workspace_roots=[str(ws_dir)], tunnel_mode="local")
    sup = daemon.StandaloneSupervisorLoop(
        state_root=st_dir,
        runtime_python=sys.executable,
        port=18192,
        mode="local",
    )
    try:
        sup._sync_tunnel_from_cfg(initial=True)
        assert sup.mode == "local"
        assert sup._ssh_proc is None

        # 1) Hot-switch `local` -> `vps` via `service.json` (simulating Studio save): spawns real SSH reverse tunnel
        cfg_p = daemon.service_cfg_path(st_dir, "pc")
        cfg_doc = json.loads(cfg_p.read_text(encoding="utf-8"))
        cfg_doc.update(
            {
                "tunnel_mode": "vps",
                "vps_ssh": "deploy@vps-node1.example.org",
                "vps_remote_port": 18096,
                "vps_ssh_port": 2222,
                "public_base": "https://mcp-vps1.example.org",
                "public_base_url": "https://mcp-vps1.example.org",
                "policy_updated_at": time.time(),
            }
        )
        atomic_write_json(cfg_p, cfg_doc)

        sup._sync_tunnel_from_cfg(initial=False)
        assert sup.mode == "vps"
        assert sup.vps_ssh == "deploy@vps-node1.example.org"
        assert sup.vps_remote_port == 18096
        assert sup.vps_ssh_port == 2222
        assert sup._ssh_proc is not None and sup._ssh_proc.poll() is None
        ssh_pid_1 = int(sup._ssh_proc.pid)
        assert is_raw_pid_alive(ssh_pid_1)

        d_st1 = json.loads(daemon.daemon_status_path(st_dir).read_text(encoding="utf-8"))
        assert d_st1["mode"] == "vps"
        assert d_st1["tunnel_pid"] == ssh_pid_1
        assert d_st1["public_url"] == "https://mcp-vps1.example.org"
        assert "last_error" not in d_st1

        # 2) Change `vps_remote_port` in `service.json` -> restarts SSH tunnel & terminates old `ssh_pid_1`
        cfg_doc["vps_remote_port"] = 18099
        cfg_doc["policy_updated_at"] = time.time() + 1.0
        atomic_write_json(cfg_p, cfg_doc)

        sup._sync_tunnel_from_cfg(initial=False)
        assert sup.vps_remote_port == 18099
        assert sup._ssh_proc is not None and sup._ssh_proc.poll() is None
        ssh_pid_2 = int(sup._ssh_proc.pid)
        assert ssh_pid_2 != ssh_pid_1
        assert is_raw_pid_alive(ssh_pid_2)
        assert not is_raw_pid_alive(ssh_pid_1), "Previous SSH tunnel process leaked after remote_port update!"

        # 3) Switch `vps` -> `local` -> terminates and reaps `ssh_pid_2` (zero orphan SSH processes)
        cfg_doc["tunnel_mode"] = "local"
        cfg_doc["public_base"] = ""
        cfg_doc["public_base_url"] = ""
        cfg_doc["policy_updated_at"] = time.time() + 2.0
        atomic_write_json(cfg_p, cfg_doc)

        sup._sync_tunnel_from_cfg(initial=False)
        assert sup.mode == "local"
        assert sup._ssh_proc is None
        assert not is_raw_pid_alive(ssh_pid_2), "Orphan SSH process survived after switching from `vps` to `local`!"

        # Verify inner Python worker processes spawned by `ssh` shim are also 100% reaped
        records = [
            json.loads(ln)
            for ln in pid_ledger.read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]
        assert len(records) == 2
        for rec in records:
            assert not is_raw_pid_alive(int(rec["pid"])), f"Orphan inner SSH worker pid={rec['pid']} leaked!"

        # 4) Handshake failure (`Permission denied (publickey)`) surfaces `"vps tunnel error"` into `daemon_status.json`
        cfg_doc.update(
            {
                "tunnel_mode": "vps",
                "vps_ssh": "bad-auth@vps-node2.example.org",
                "vps_remote_port": 18100,
                "policy_updated_at": time.time() + 3.0,
            }
        )
        atomic_write_json(cfg_p, cfg_doc)

        sup._sync_tunnel_from_cfg(initial=False)
        if sup._ssh_proc is not None:
            time.sleep(0.5)
            sup._ensure_vps_ssh_alive()
        assert sup._ssh_proc is None
        d_err = json.loads(daemon.daemon_status_path(st_dir).read_text(encoding="utf-8"))
        assert "vps tunnel error" in d_err.get("last_error", "").lower()
        assert "permission denied" in d_err.get("last_error", "").lower()
    finally:
        sup._stop_cf_supervisor()
        sup._stop_ssh_tunnel()
        sup._sup_logger.removeHandler(sup._sup_log_handler)
        sup._sup_log_handler.close()


def test_uninstall_purge_shreds_secrets_and_leaves_zero_temp_vault_residue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    isolated_temp = tmp_path / "isolated_sys_temp"
    isolated_temp.mkdir(parents=True)
    for env_k in ("TMP", "TEMP", "TMPDIR"):
        monkeypatch.setenv(env_k, str(isolated_temp))

    st_dir = tmp_path / "state_purge_target"
    fake_home = tmp_path / "home_purge"
    desk = fake_home / "Desktop"
    ws_dir = tmp_path / "ws_purge_safe"
    desk.mkdir(parents=True)
    ws_dir.mkdir(parents=True)

    user_keep_file = ws_dir / "keep_me.py"
    user_keep_file.write_text("VALUE = 42\n", encoding="utf-8")

    fake_cf_tok = "eyJhIjoiPURGE99887766554433221100IiwidCI6InB1cmdlLXRlc3QtdG9rZW4ifQ=="
    init_res = cli.ensure_standalone_state(
        st_dir,
        port=18195,
        workspace_roots=[str(ws_dir)],
        tunnel_mode="cloudflare_token",
        tunnel_token=fake_cf_tok,
        public_url="https://purge-test.example.org",
    )
    bat_desk = cli.create_desktop_shortcut(st_dir, port=18195, desktop_dir=desk)
    assert bat_desk is not None and bat_desk.exists()

    auth_doc = json.loads((st_dir / "secrets" / "auth.json").read_text(encoding="utf-8"))
    pw_hash_marker = str(auth_doc["password_hash"])
    api_tok_marker = str(auth_doc["local_api_token"])
    conn_pw_marker = str(init_res["connection_password"])
    oauth_secret_marker = "OAUTH_REFRESH_SECRET_MARKER_W2A_PURGE_778899"

    # Populate `state/oauth.sqlite3` in WAL mode + explicit `-wal` / `-shm` files
    import sqlite3

    oauth_db = st_dir / "state" / "oauth.sqlite3"
    conn = sqlite3.connect(str(oauth_db))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE IF NOT EXISTS records (k TEXT PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO records (k, value) VALUES (?, ?)", ("rt_1", oauth_secret_marker))
        conn.commit()
    finally:
        conn.close()
    (st_dir / "state" / "oauth.sqlite3-wal").write_text(oauth_secret_marker, encoding="utf-8")
    (st_dir / "state" / "oauth.sqlite3-shm").write_text(oauth_secret_marker, encoding="utf-8")

    # Verify byte-level zero overwrite via hardlink probe on a secret file before `run_uninstall(..., purge=True)`
    probe_secret = st_dir / "secrets" / "extra_probe_secret.txt"
    probe_hardlink = tmp_path / "hardlink_inode_probe.bin"
    probe_secret.write_text("TOP_SECRET_INODE_PAYLOAD_1234567890", encoding="utf-8")
    os.link(probe_secret, probe_hardlink)

    purge_res = doctor.run_uninstall(
        st_dir,
        purge=True,
        home_dir=fake_home,
        desktop_dir=desk,
        platform_name="win32",
        winreg_store={"Cosmos-MCP": "cmd"},
    )
    assert purge_res["ok"] is True
    assert purge_res["purge"] is True

    # Hardlink sharing the exact same inode proves `secrets/*` bytes were overwritten & truncated to 0 before unlink!
    assert probe_hardlink.stat().st_size == 0
    assert probe_hardlink.read_bytes() == b""

    # Entire state directory, `secrets/`, `oauth.sqlite3*`, and desktop shortcut are completely gone
    assert not st_dir.exists()
    assert not bat_desk.exists()
    assert user_keep_file.read_text(encoding="utf-8") == "VALUE = 42\n"

    # Zero `cosmos_purged_vault` or leaked credentials anywhere in `%TEMP%` or parent temp tree
    assert not (isolated_temp / "cosmos_purged_vault").exists()
    sensitive_markers = (
        pw_hash_marker,
        api_tok_marker,
        conn_pw_marker,
        fake_cf_tok,
        oauth_secret_marker,
        "TOP_SECRET_INODE_PAYLOAD_1234567890",
    )
    for scan_file in tmp_path.rglob("*"):
        if not scan_file.is_file():
            continue
        raw_txt = scan_file.read_text(encoding="utf-8", errors="ignore")
        for marker in sensitive_markers:
            assert marker and marker not in raw_txt, f"Sensitive credential `{marker[:12]}...` leaked in {scan_file}!"


def test_daemon_tunnel_ready_background_reprobe_and_reset_on_exit_or_url_switch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    wait_tunnel_probes,
) -> None:
    st_dir = tmp_path / "state_reprobe"
    ws_dir = tmp_path / "ws_reprobe"
    ws_dir.mkdir(parents=True)
    cli.ensure_standalone_state(st_dir, port=18197, workspace_roots=[str(ws_dir)], tunnel_mode="cloudflare")

    probe_calls: list[tuple[str, float]] = []
    probe_plan = {"ok": False}

    def _fake_wait_tunnel(url: str, *, timeout_sec: float = 30.0, **_: Any) -> Dict[str, Any]:
        probe_calls.append((url, float(timeout_sec)))
        if probe_plan["ok"]:
            return {"ok": True, "public_url": url, "dns_resolved": True, "dns_provider": "cloudflare_doh", "status_code": 200}
        return {"ok": False, "public_url": url, "dns_resolved": False, "dns_provider": "", "error": "timeout_waiting_for_tunnel_ready"}

    class _FakeCfSupervisor:
        def __init__(self, **kwargs: Any) -> None:
            self.on_url_change = kwargs.get("on_url_change")
            self.current_url = "https://delayed-edge-node1.trycloudflare.com"
            self._alive = True

        @property
        def pid(self) -> int | None:
            return 43210 if self._alive else None

        def is_process_alive(self) -> bool:
            return self._alive

        def start(self, wait_url_timeout_sec: float = 12.0) -> str:
            _ = wait_url_timeout_sec
            return self.current_url

        def stop(self) -> None:
            self._alive = False

    fake_holder: Dict[str, _FakeCfSupervisor] = {}

    def _make_cf(**kwargs: Any) -> _FakeCfSupervisor:
        inst = _FakeCfSupervisor(**kwargs)
        fake_holder["cf"] = inst
        return inst

    monkeypatch.setattr(daemon, "ensure_cloudflared_binary", lambda _d: tmp_path / "cloudflared")
    monkeypatch.setattr(daemon, "CloudflaredTunnelSupervisor", _make_cf)
    monkeypatch.setattr(daemon, "wait_tunnel_dns_and_https_ready", _fake_wait_tunnel)

    sup = daemon.StandaloneSupervisorLoop(
        state_root=st_dir,
        runtime_python=sys.executable,
        port=18197,
        mode="cloudflare",
    )
    sup._tunnel_reprobe_interval_sec = 0.12
    try:
        # 1) Initial 15s probe times out -> `tunnel_ready` starts as False in `daemon_status.json`
        sup._sync_tunnel_from_cfg(initial=True)
        wait_tunnel_probes()
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and not probe_calls:
            time.sleep(0.02)
        time.sleep(0.05)

        assert len(probe_calls) == 1
        assert probe_calls[0] == ("https://delayed-edge-node1.trycloudflare.com", 15.0)
        assert sup._tunnel_ready is False
        d_st0 = json.loads(daemon.daemon_status_path(st_dir).read_text(encoding="utf-8"))
        assert d_st0["tunnel_ready"] is False
        assert d_st0.get("tunnel_probe_note") == "timeout_waiting_for_tunnel_ready"

        # 2) Edge DNS finishes propagating -> `_poll_tunnel_readiness()` re-probes (`timeout_sec=5.0`) and flips `tunnel_ready` to True
        probe_plan["ok"] = True
        time.sleep(0.16)
        sup._poll_tunnel_readiness()

        wait_tunnel_probes()
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and not sup._tunnel_ready:
            time.sleep(0.02)
        time.sleep(0.05)

        assert sup._tunnel_ready is True
        assert probe_calls[-1] == ("https://delayed-edge-node1.trycloudflare.com", 5.0)
        d_st1 = json.loads(daemon.daemon_status_path(st_dir).read_text(encoding="utf-8"))
        assert d_st1["tunnel_ready"] is True
        assert d_st1["public_url"] == "https://delayed-edge-node1.trycloudflare.com"
        assert "tunnel_probe_note" not in d_st1

        # 3) Switching URL resets `tunnel_ready` to False until the new URL passes readiness probe
        probe_plan["ok"] = False
        cb = fake_holder["cf"].on_url_change
        assert callable(cb)
        cb("https://rotated-edge-node2.trycloudflare.com")
        wait_tunnel_probes()
        time.sleep(0.06)
        d_st2 = json.loads(daemon.daemon_status_path(st_dir).read_text(encoding="utf-8"))
        assert sup._tunnel_ready is False
        assert d_st2["tunnel_ready"] is False
        assert d_st2["public_url"] == "https://rotated-edge-node2.trycloudflare.com"

        probe_plan["ok"] = True
        time.sleep(0.16)
        sup._poll_tunnel_readiness()
        wait_tunnel_probes()
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and not sup._tunnel_ready:
            time.sleep(0.02)
        time.sleep(0.05)
        d_st3 = json.loads(daemon.daemon_status_path(st_dir).read_text(encoding="utf-8"))
        assert d_st3["tunnel_ready"] is True

        # 4) Tunnel process exit immediately resets `tunnel_ready` back to False
        fake_holder["cf"]._alive = False
        sup._poll_tunnel_readiness()
        d_st4 = json.loads(daemon.daemon_status_path(st_dir).read_text(encoding="utf-8"))
        assert sup._tunnel_ready is False
        assert d_st4["tunnel_ready"] is False
    finally:
        sup._stop_cf_supervisor()
        sup._stop_ssh_tunnel()
        sup._sup_logger.removeHandler(sup._sup_log_handler)
        sup._sup_log_handler.close()


# ---------------------------------------------------------------------------
# 5. v1.2.1 Dir 2 Closures: Card 1 Non-Locking Switch, `/poll` `srvus_fixed_active`,
#    PNG Recovery `workers_dev` Preservation + `srvus_ed25519` Hot Reload, & `@Cosmos` Tray Wake
# ---------------------------------------------------------------------------


def test_v121_dir2_card1_bidirectional_switch_and_poll_srvus_sync(tmp_path: Path) -> None:
    st_dir = tmp_path / "state_v121_card1_poll"
    ws_dir = tmp_path / "ws_v121_card1"
    ws_dir.mkdir(parents=True)
    cli.ensure_standalone_state(st_dir, workspace_roots=[str(ws_dir)])

    with LiveStudioServer(st_dir, ws_dir) as srv:
        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=10.0) as client:
            st0 = client.get("/api/studio/state").json()
            assert st0["ok"] is True
            csrf = st0["csrf_token"]
            assert st0["connection"]["connector_name"] == "Cosmos"
            assert st0["connection"]["tunnel_mode"] == "public_gateway"
            assert st0["srvus_fixed_active"] is False
            assert "skill_markdown" in st0["tools_center"]
            assert "WebAI2PC" in st0["tools_center"]["skill_markdown"]
            assert chr(64) in st0["tools_center"]["skill_markdown"]

            poll0 = client.get("/api/studio/poll").json()
            assert poll0["ok"] is True
            assert "srvus_fixed_active" in poll0
            assert poll0["srvus_fixed_active"] is False
            assert poll0["instant_fallback_active"] is True

            # Simulate background `srv.us` persistent SSH tunnel becoming ready -> `/api/studio/poll` reflects it immediately
            d_status_p = daemon.daemon_status_path(st_dir)
            atomic_write_json(
                d_status_p,
                {
                    "status": "running",
                    "port": srv.port,
                    "mode": "public_gateway",
                    "effective_tunnel_mode": "srv_us",
                    "public_url": "https://fixed-v121-node.srv.us",
                    "mcp_url": "https://fixed-v121-node.srv.us/mcp",
                    "readonly_mcp_url": "https://fixed-v121-node.srv.us/mcp/readonly",
                    "tunnel_ready": True,
                    "srvus_fixed_active": True,
                    "instant_fallback_active": False,
                    "public_gateway_online": False,
                    "updated_at": time.time(),
                },
            )

            poll1 = client.get("/api/studio/poll").json()
            assert poll1["srvus_fixed_active"] is True
            assert poll1["instant_fallback_active"] is False
            assert poll1["effective_tunnel_mode"] == "srv_us"
            assert poll1["public_https_ready"] is True
            assert poll1["mcp_url"] == "https://fixed-v121-node.srv.us/mcp"
            assert poll1["reboot_notice"] == ""

            # Switch to temporary quick tunnel (`cloudflare`) and verify `srvus_fixed_active` AND stale `.srv.us` URL clear cleanly
            r_quick = client.post(
                "/api/studio/connection",
                headers={"X-Studio-Csrf": csrf},
                json={"action": "save_tunnel", "tunnel_mode": "cloudflare"},
            )
            assert r_quick.status_code == 200
            d_quick = r_quick.json()
            assert d_quick["connection"]["tunnel_mode"] == "cloudflare"
            assert d_quick["srvus_fixed_active"] is False
            assert d_quick["gateways"]["instant"]["submode"] == "cloudflare"
            assert d_quick["public_https_ready"] is False
            assert d_quick["mcp_url"] == ""

            # Switch back from `cloudflare` to `public_gateway` (`srv.us` fixed priority)
            r_back = client.post(
                "/api/studio/connection",
                headers={"X-Studio-Csrf": csrf},
                json={"action": "save_tunnel", "tunnel_mode": "public_gateway"},
            )
            assert r_back.status_code == 200
            d_back = r_back.json()
            assert d_back["connection"]["tunnel_mode"] == "public_gateway"
            assert d_back["srvus_fixed_active"] is True

        prof_dir = tmp_path / "cdp_card1_profile"
        prof_dir.mkdir(parents=True)
        # Start in connecting state, load page, then flip `daemon_status.json` to `srvus_fixed_active=True`
        atomic_write_json(
            d_status_p,
            {
                "status": "running",
                "port": srv.port,
                "mode": "public_gateway",
                "effective_tunnel_mode": "public_gateway",
                "public_url": "",
                "tunnel_ready": False,
                "srvus_fixed_active": False,
                "instant_fallback_active": True,
                "updated_at": time.time(),
            },
        )
        with StudioPageDriver(prof_dir) as driver:
            driver.set_viewport(1440, 900, mobile=False)
            driver.goto(f"{srv.base_url}/")
            driver.open_settings("gateways")

            fallback_ui = driver.evaluate(
                """() => {
                    const btn1 = document.getElementById('activate-card1-btn');
                    const qBtn = document.getElementById('switch-card1-quick-btn');
                    const skBtn = document.getElementById('copy-host-skill-btn');
                    return {
                        btn1Disabled: btn1 ? btn1.disabled : true,
                        quickHidden: qBtn ? getComputedStyle(qBtn).display === 'none' : false,
                        hasSkillCopyBtn: Boolean(skBtn),
                    };
                }"""
            )
            assert fallback_ui["btn1Disabled"] is False
            assert fallback_ui["quickHidden"] is True
            assert fallback_ui["hasSkillCopyBtn"] is True

            atomic_write_json(
                d_status_p,
                {
                    "status": "running",
                    "port": srv.port,
                    "mode": "public_gateway",
                    "effective_tunnel_mode": "srv_us",
                    "public_url": "https://live-poll-v121.srv.us",
                    "mcp_url": "https://live-poll-v121.srv.us/mcp",
                    "readonly_mcp_url": "https://live-poll-v121.srv.us/mcp/readonly",
                    "tunnel_ready": True,
                    "srvus_fixed_active": True,
                    "instant_fallback_active": False,
                    "updated_at": time.time(),
                },
            )
            driver.trigger_poll()
            polled_ui = driver.wait_until(
                """() => {
                    const box = document.getElementById('card1-srvus-fixed-box');
                    if (!box || getComputedStyle(box).display === 'none') return false;
                    return {
                        srvusVisible: true,
                        mcpText: document.getElementById('mcp-url-box').textContent.trim(),
                        exportVisible: getComputedStyle(document.getElementById('open-export-id-modal-btn')).display !== 'none',
                        quickSwitchVisible: getComputedStyle(document.getElementById('switch-card1-quick-btn')).display !== 'none',
                    };
                }""",
                description="Card 1 srv.us fixed status synced via poll",
            )
            assert polled_ui["srvusVisible"] is True
            assert polled_ui["mcpText"] == "https://live-poll-v121.srv.us/mcp"
            assert polled_ui["exportVisible"] is True
            assert polled_ui["quickSwitchVisible"] is True

            # Click secondary quick-tunnel switch -> verify `#activate-card1-btn` stays enabled and switches back
            driver.evaluate("() => document.getElementById('switch-card1-quick-btn').click()")
            driver.wait_until(
                """async () => {
                    const st = await (await fetch('/api/studio/state')).json();
                    const btn1 = document.getElementById('activate-card1-btn');
                    return st.connection && st.connection.tunnel_mode === 'cloudflare' && btn1 && !btn1.disabled;
                }""",
                description="switched to cloudflare quick tunnel",
            )
            driver.evaluate("() => document.getElementById('activate-card1-btn').click()")
            back_ok = driver.wait_until(
                """async () => {
                    const st = await (await fetch('/api/studio/state')).json();
                    return st.connection && st.connection.tunnel_mode === 'public_gateway';
                }""",
                description="switched back to public_gateway",
            )
            assert back_ok is True


def test_v121_dir2_recovery_png_import_preserves_workers_dev_and_daemon_srvus_key_hot_reload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    wait_tunnel_probes,
) -> None:
    from cosmos_mcp.launcher.cf_workers_gateway import (
        ensure_master_seed_identity,
        export_identity_recovery_png,
        workers_tunnel_secret_path,
    )

    # 1) Export v2 PNG recovery card from `st_src` configured with `tunnel_mode == "workers_dev"`
    st_src = tmp_path / "state_png_src"
    ws_dir = tmp_path / "ws_png"
    ws_dir.mkdir(parents=True)
    cli.ensure_standalone_state(st_src, port=18340, workspace_roots=[str(ws_dir)], tunnel_mode="workers_dev")
    src_seed = ensure_master_seed_identity(st_src, prefix="pc")
    atomic_write_text(workers_tunnel_secret_path(st_src, "pc"), "wt_secret_v121_test\n", mode_override=0o600)
    priv_src, pub_src = tunnels.srvus_ssh_key_paths(st_src, "pc")
    atomic_write_text(priv_src, "-----BEGIN OPENSSH PRIVATE KEY-----\nSRC_KEY_V121\n-----END OPENSSH PRIVATE KEY-----\n", mode_override=0o600)
    atomic_write_text(pub_src, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISrcKeyV121 cosmos-mcp\n", mode_override=0o600)

    src_cfg_p = daemon.service_cfg_path(st_src, "pc")
    src_cfg = json.loads(src_cfg_p.read_text(encoding="utf-8"))
    src_cfg.update(
        {
            "tunnel_mode": "workers_dev",
            "workers_dev_url": "https://cosmos-mcp-v121.demo-sub.workers.dev",
            "workers_dev_subdomain": "demo-sub",
            "workers_dev_script_name": "cosmos-mcp-v121",
            "workers_dev_account_id": "acc_v121_demo",
            "public_base": "https://cosmos-mcp-v121.demo-sub.workers.dev",
            "public_base_url": "https://cosmos-mcp-v121.demo-sub.workers.dev",
        }
    )
    atomic_write_json(src_cfg_p, src_cfg)

    import base64

    png_bytes = export_identity_recovery_png(st_src, "recover-pass-v121", prefix="pc")

    # Import onto fresh `st_dst` (cold-start `ensure_standalone_state` -> in-memory `policy.tunnel_mode == "public_gateway"`)
    st_dst = tmp_path / "state_png_dst"
    cli.ensure_standalone_state(st_dst, workspace_roots=[str(ws_dir)])
    with LiveStudioServer(st_dst, ws_dir) as srv:
        assert srv.app.state.policy.tunnel_mode == "public_gateway"
        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=10.0) as client:
            csrf = client.get("/api/studio/state").json()["csrf_token"]
            r_imp = client.post(
                "/api/studio/identity/import_png",
                headers={"X-Studio-Csrf": csrf},
                json={
                    "png_base64": "data:image/png;base64," + base64.b64encode(png_bytes).decode("ascii"),
                    "passphrase": "recover-pass-v121",
                },
            )
            assert r_imp.status_code == 200, r_imp.text
            d_imp = r_imp.json()
            assert d_imp["restored_identity"]["node_id"] == src_seed["node_id"]
            assert d_imp["connection"]["tunnel_mode"] == "workers_dev"
            assert (
                d_imp["connection"].get("public_url") == "https://cosmos-mcp-v121.demo-sub.workers.dev"
                or d_imp["gateways"]["workers_dev"]["configured_url"] == "https://cosmos-mcp-v121.demo-sub.workers.dev"
            )
            assert srv.app.state.policy.tunnel_mode == "workers_dev"
            assert srv.app.state.policy.workers_dev_subdomain == "demo-sub"

            dst_cfg_on_disk = json.loads(daemon.service_cfg_path(st_dst, "pc").read_text(encoding="utf-8"))
            assert dst_cfg_on_disk["tunnel_mode"] == "workers_dev"
            assert dst_cfg_on_disk["workers_dev_url"] == "https://cosmos-mcp-v121.demo-sub.workers.dev"

    # 2) Verify `daemon.py` detects `secrets/srvus_ed25519` key rotation and hot-restarts `SrvUsSshTunnelSupervisor`
    st_srv = tmp_path / "state_daemon_srvus_hot"
    cli.ensure_standalone_state(st_srv, port=18345, workspace_roots=[str(ws_dir)], tunnel_mode="public_gateway")
    priv_d, pub_d = tunnels.srvus_ssh_key_paths(st_srv, "pc")
    atomic_write_text(priv_d, "SSH_PRIV_KEY_GENERATION_1\n", mode_override=0o600)
    atomic_write_text(pub_d, "ssh-ed25519 AAAA_GEN_1\n", mode_override=0o600)

    events = {"starts": 0, "stops": 0}

    class _KeyAwareFakeSrvUs:
        def __init__(self, **kw: Any) -> None:
            self.state_root = Path(kw["state_root"])
            self.prefix = str(kw.get("prefix") or "pc")
            self._alive = True
            self.pid = 71000 + events["starts"]

        def is_process_alive(self) -> bool:
            return self._alive

        def start(self, wait_url_timeout_sec: float = 4.0) -> str:
            _ = wait_url_timeout_sec
            events["starts"] += 1
            kp, _ = tunnels.srvus_ssh_key_paths(self.state_root, self.prefix)
            raw_k = kp.read_text(encoding="utf-8")
            if "GENERATION_2" in raw_k:
                return "https://restored-key2.srv.us"
            return "https://initial-key1.srv.us"

        def stop(self) -> None:
            events["stops"] += 1
            self._alive = False

    monkeypatch.setattr(daemon, "probe_public_gateway_online", lambda *_a, **_k: {"configured": False, "online": False})
    monkeypatch.setattr(daemon, "SrvUsSshTunnelSupervisor", _KeyAwareFakeSrvUs)
    monkeypatch.setattr(daemon, "wait_tunnel_dns_and_https_ready", lambda u, **_k: {"ok": True, "public_url": u})

    sup_hot = daemon.StandaloneSupervisorLoop(
        state_root=st_srv,
        runtime_python=sys.executable,
        port=18345,
        mode="public_gateway",
    )
    try:
        sup_hot._sync_tunnel_from_cfg(initial=True)
        wait_tunnel_probes()
        assert events == {"starts": 1, "stops": 0}
        assert sup_hot.public_url == "https://initial-key1.srv.us"

        # Polling without key change must NOT restart tunnel
        sup_hot._sync_tunnel_from_cfg(initial=False)
        assert events == {"starts": 1, "stops": 0}

        # Replace `secrets/srvus_ed25519` (simulating PNG identity recovery card import) -> must hot-restart & update URL
        atomic_write_text(priv_d, "SSH_PRIV_KEY_GENERATION_2_RESTORED\n", mode_override=0o600)
        sup_hot._sync_tunnel_from_cfg(initial=False)
        wait_tunnel_probes()
        assert events == {"starts": 2, "stops": 1}
        assert sup_hot.public_url == "https://restored-key2.srv.us"
        d_hot = json.loads(daemon.daemon_status_path(st_srv).read_text(encoding="utf-8"))
        assert d_hot["public_url"] == "https://restored-key2.srv.us"
        assert d_hot["srvus_fixed_active"] is True
    finally:
        sup_hot._stop_srvus_supervisor()
        sup_hot._sup_logger.removeHandler(sup_hot._sup_log_handler)
        sup_hot._sup_log_handler.close()


def test_v121_dir2_cosmos_connector_wake_alignment_and_tray_menu_copy(tmp_path: Path) -> None:
    from cosmos_mcp.launcher.tray import (
        MENU_ID_COPY_WAKE_PROMPT,
        MF_GRAYED,
        WindowsSystemTrayController,
        build_tray_menu_items,
    )

    at_sym = chr(64)

    # 1) Tray popup menu includes enabled "复制首句唤醒词" (0ms pure memory snapshot) and copies wake prompt
    snap = {"port": 18350, "mode": "public_gateway", "mcp_url": "", "tunnel_ready": False}
    menu_items = build_tray_menu_items(snap)
    wake_entries = [it for it in menu_items if it[1] == MENU_ID_COPY_WAKE_PROMPT]
    assert len(wake_entries) == 1
    assert (wake_entries[0][0] & MF_GRAYED) == 0
    assert wake_entries[0][2] == "复制首句唤醒词"

    copied: list[str] = []
    ctrl = WindowsSystemTrayController(
        tmp_path / "tray_wake_state",
        port=18350,
        clipboard_fn=lambda txt: (copied.append(txt) or True),
    )
    res = ctrl.handle_menu_command(MENU_ID_COPY_WAKE_PROMPT, snapshot=snap)
    assert res["ok"] is True
    assert str(res["wake_prompt"]).startswith(at_sym)
    assert copied == [res["wake_prompt"]]

    # 2) Verify `README.md`, `docs/*`, and `index.html` include natural `@` connector wake guidance without escaped `[at]` typos
    repo_root = Path(__file__).resolve().parents[1]
    for rel in (
        "README.md",
        "docs/01_网页版Gemini与手机远程连接教程.md",
        "docs/03_Cosmos_Studio面板与扩展包指南.md",
        "src/cosmos_mcp/studio/static/index.html",
    ):
        txt = (repo_root / rel).read_text(encoding="utf-8")
        assert at_sym in txt, f"{rel} missing @ connector mention hint"
        assert "[at]" not in txt.lower(), f"{rel} contains escaped [at] typo"


def test_v121_silent_auto_reconnect_forbids_nif_info_toast_and_updates_tooltip_and_studio(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from starlette.testclient import TestClient

    from cosmos_mcp.core.fs_tx import atomic_write_json
    from cosmos_mcp.launcher import daemon
    from cosmos_mcp.launcher.app import create_standalone_app
    from cosmos_mcp.launcher.cf_workers_gateway import MSG_DISCONNECT_REMOTE_UNREACHABLE_ZH
    from cosmos_mcp.launcher.tray import (
        COLOR_ERROR_RED,
        NIF_INFO,
        WindowsSystemTrayController,
        format_tray_tooltip,
        resolve_tray_visual_state,
    )

    monkeypatch.delenv("COSMOS_NO_TRAY", raising=False)

    # 1) WindowsSystemTrayController.notify_balloon must NEVER emit Win32 `NIF_INFO` toast notifications
    shell_calls: list[tuple[int, int]] = []
    ctrl = WindowsSystemTrayController(
        tmp_path / "tray_no_toast_state",
        port=18360,
        shell_notify_fn=lambda msg_code, nid: (shell_calls.append((int(msg_code), int(nid.uFlags))) or True),
    )
    assert ctrl.notify_balloon("Cosmos MCP 连接中断", MSG_DISCONNECT_REMOTE_UNREACHABLE_ZH, cooldown_sec=0.0) is False
    assert shell_calls == []
    assert all((flags & NIF_INFO) == 0 for _, flags in shell_calls)

    # 2) Disconnect snapshot updates tray icon color (`COLOR_ERROR_RED`) and hover tooltip (<=127 chars)
    ctrl.update_snapshot(
        {
            "port": 18360,
            "mode": "workers_dev",
            "tunnel_ready": False,
            "consecutive_failures": 5,
            "last_disconnect_reason_zh": MSG_DISCONNECT_REMOTE_UNREACHABLE_ZH,
            "last_error": MSG_DISCONNECT_REMOTE_UNREACHABLE_ZH,
        }
    )
    snap_err = ctrl.get_snapshot()
    assert resolve_tray_visual_state(snap_err) == ("error", "异常重连中", COLOR_ERROR_RED)
    tip_err = format_tray_tooltip(snap_err)
    assert len(tip_err) <= 127
    assert "异常重连中" in tip_err
    assert MSG_DISCONNECT_REMOTE_UNREACHABLE_ZH in tip_err

    # 3) Daemon supervisor never calls `notify_balloon` on repeated relay failures, while Studio surfaces banner
    st_dir = tmp_path / "daemon_silent_reconnect"
    ws_dir = tmp_path / "ws_silent_reconnect"
    ws_dir.mkdir()
    sup = daemon.StandaloneSupervisorLoop(
        state_root=st_dir,
        runtime_python=sys.executable,
        port=18361,
        mode="workers_dev",
        public_url="https://silent-test.workers.dev",
    )
    balloon_invocations: list[tuple[str, str]] = []
    pushed_snaps: list[dict] = []

    class _SpyTray:
        def update_snapshot(self, s):
            pushed_snaps.append(dict(s))

        def notify_balloon(self, title: str, msg: str, **_kw) -> bool:
            balloon_invocations.append((title, msg))
            return True

        def stop(self) -> None:
            pass

    class _FakeFailingRelay:
        consecutive_failures = 4
        last_disconnect_reason_zh = MSG_DISCONNECT_REMOTE_UNREACHABLE_ZH
        last_error = MSG_DISCONNECT_REMOTE_UNREACHABLE_ZH

        def is_alive(self) -> bool:
            return True

        def is_connected(self) -> bool:
            return False

        def stop(self) -> None:
            pass

    sup._tray = _SpyTray()  # type: ignore[assignment]
    sup._workers_supervisor = _FakeFailingRelay()
    if hasattr(sup, "_gateway_slots") and "workers_dev" in sup._gateway_slots:
        sup._gateway_slots["workers_dev"].enabled = True
        sup._gateway_slots["workers_dev"].submode = "workers_dev"
        sup._gateway_slots["workers_dev"].public_url = "https://silent-test.workers.dev"
    try:
        sup._poll_tunnel_readiness()
        sup._sync_tray_from_cfg(state_label="running", cfg_doc={"tray_enabled": True})
        assert balloon_invocations == []
        assert pushed_snaps[-1]["last_disconnect_reason_zh"] == MSG_DISCONNECT_REMOTE_UNREACHABLE_ZH
        d_doc = json.loads(daemon.daemon_status_path(st_dir).read_text(encoding="utf-8"))
        assert d_doc["consecutive_failures"] == 4
        assert d_doc["last_disconnect_reason_zh"] == MSG_DISCONNECT_REMOTE_UNREACHABLE_ZH
    finally:
        sup._stop_workers_supervisor()
        sup._sup_logger.removeHandler(sup._sup_log_handler)
        sup._sup_log_handler.close()

    # Ensure `supervisor_pid` is non-zero in `daemon_status.json` and check Studio state/poll banner `tunnel_error`
    d_doc["supervisor_pid"] = os.getpid()
    atomic_write_json(daemon.daemon_status_path(st_dir), d_doc)
    app = create_standalone_app(state_dir=str(st_dir), workspace_roots=[str(ws_dir)], port=18361, tunnel_mode="workers_dev")
    with TestClient(app, base_url="http://127.0.0.1:18361", client=("127.0.0.1", 51061)) as client:
        st_json = client.get("/api/studio/state").json()
        assert st_json["connection"]["tunnel_error"] == MSG_DISCONNECT_REMOTE_UNREACHABLE_ZH
        poll_json = client.get("/api/studio/poll").json()
        assert poll_json["tunnel_error"] == MSG_DISCONNECT_REMOTE_UNREACHABLE_ZH


def test_s4_tutorials_page_and_swappable_brand_style_assets(tmp_path: Path) -> None:
    from starlette.testclient import TestClient

    st_dir = tmp_path / "studio_tutorials_brand"
    ws_dir = tmp_path / "ws_tutorials_brand"
    ws_dir.mkdir()
    app = create_standalone_app(
        state_dir=str(st_dir),
        workspace_roots=[str(ws_dir)],
        port=18362,
        tunnel_mode="local",
    )
    with TestClient(app, base_url="http://127.0.0.1:18362", client=("127.0.0.1", 51062)) as client:
        root_res = client.get("/")
        assert root_res.status_code == 200
        assert "/static/themes.css" in root_res.text
        assert "/static/brand-packs.js" in root_res.text
        assert 'href="/tutorials"' in root_res.text
        assert "data-appearance-switcher" in root_res.text
        assert 'data-brand-slot="header-mark"' in root_res.text

        tut_res = client.get("/tutorials")
        assert tut_res.status_code == 200
        assert "WebAI2PC · 交互式使用教程" in tut_res.text
        for mod_id in ("mod-gemini", "mod-chatgpt", "mod-channels", "mod-templates", "mod-safety", "mod-troubleshoot"):
            assert mod_id in tut_res.text

        for asset, expected_ct in (
            ("themes.css", "text/css"),
            ("brand-packs.js", "application/javascript"),
            ("tutorials.js", "application/javascript"),
            ("favicon.svg", "image/svg+xml"),
        ):
            r_asset = client.get(f"/static/{asset}")
            assert r_asset.status_code == 200
            assert expected_ct in r_asset.headers.get("content-type", "")

        fav_res = client.get("/favicon.ico")
        assert fav_res.status_code == 200
        assert "image/svg+xml" in fav_res.headers.get("content-type", "")




