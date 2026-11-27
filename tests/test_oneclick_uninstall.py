"""Comprehensive verification suite for S10: One-click clean uninstall, CF Worker teardown & CLI recovery secret hardening."""
from __future__ import annotations

import ast
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, List
from urllib.error import HTTPError
import urllib.request

import pytest

from cosmos_mcp.core.proc import CREATE_NO_WINDOW
from cosmos_mcp.launcher import autostart, cf_workers_gateway, cli, doctor


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_launcher_python310_fstring_compat_and_script_line_endings() -> None:
    """Verify zero backslashes inside f-string expressions across touched launcher modules & exact CRLF/LF on scripts."""
    for mod_name in ("autostart.py", "doctor.py", "cli.py", "cf_workers_gateway.py"):
        mod_path = REPO_ROOT / "src" / "cosmos_mcp" / "launcher" / mod_name
        src = mod_path.read_text(encoding="utf-8")
        # On Python < 3.12, `ast.parse` itself raises SyntaxError on any backslash inside `{...}`;
        # on Python >= 3.12 (PEP 701), `ast.get_source_segment` isolates each `{...}` expression.
        tree = ast.parse(src, filename=str(mod_path))
        if sys.version_info >= (3, 12):
            for node in ast.walk(tree):
                if isinstance(node, ast.JoinedStr):
                    for val in node.values:
                        if isinstance(val, ast.FormattedValue):
                            seg = ast.get_source_segment(src, val) or ""
                            assert "\\" not in seg, f"Python <3.12 f-string backslash in {mod_name}:{val.lineno}: {seg}"

    bat_path = REPO_ROOT / "一键卸载_Cosmos_MCP.bat"
    sh_path = REPO_ROOT / "uninstall_cosmos_mcp.sh"
    assert bat_path.is_file()
    assert sh_path.is_file()

    bat_raw = bat_path.read_bytes()
    assert not bat_raw.startswith(b"\xef\xbb\xbf"), "BAT script must be UTF-8 without BOM"
    assert b"\r\n" in bat_raw
    assert b"\r\r\n" not in bat_raw
    assert b"\n" not in bat_raw.replace(b"\r\n", b""), "BAT script must use strict CRLF line endings"

    sh_raw = sh_path.read_bytes()
    assert not sh_raw.startswith(b"\xef\xbb\xbf")
    assert b"\r" not in sh_raw, "Shell script must use strict LF line endings"


def test_windows_hkcu_uninstall_registry_lifecycle_and_cross_root_isolation(tmp_path: Path) -> None:
    """1) Verify HKCU Uninstall registration, Start Menu shortcut cleanup, idempotency & cross-state_root isolation."""
    st_a = tmp_path / "state_1"
    st_b = tmp_path / "state_10"
    fake_home = tmp_path / "fake_home"
    desk = fake_home / "Desktop"
    programs_dir = fake_home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs"
    ws_a = tmp_path / "ws_a"
    for d in (st_a, st_b, desk, programs_dir, ws_a):
        d.mkdir(parents=True, exist_ok=True)

    assert autostart.WIN_UNINSTALL_KEY_ROOT == r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
    assert autostart.uninstall_entry_id("pc") == "Cosmos-MCP"
    assert autostart.uninstall_entry_id("work") == "Cosmos-MCP-work"

    # Under PYTEST_CURRENT_TEST without `uninstall_reg_store`, real host winreg must NEVER be touched
    res_pytest_guard = autostart.register_windows_uninstall_entry(st_a, prefix="pc", platform_name="win32")
    assert res_pytest_guard["ok"] is True
    assert res_pytest_guard["registered"] is False
    assert res_pytest_guard.get("skipped_pytest") is True
    assert (st_a / "bin" / "uninstall_cosmos_mcp.cmd").is_file()

    reg_store: Dict[str, Dict[str, Any]] = {}
    reg_res = autostart.register_windows_uninstall_entry(
        st_a,
        prefix="pc",
        display_version="1.2.1",
        platform_name="win32",
        uninstall_reg_store=reg_store,
    )
    assert reg_res["ok"] is True
    assert reg_res["registered"] is True
    assert "Cosmos-MCP" in reg_store
    entry = reg_store["Cosmos-MCP"]
    assert entry["DisplayName"] == "WebAI2PC (Cosmos MCP)"
    assert entry["DisplayVersion"] == "1.2.1"
    assert entry["Publisher"] == "WebAI2PC"
    assert entry["InstallLocation"] == str(st_a.resolve())
    assert str(st_a.resolve()) in entry["UninstallString"]
    assert "--quiet" in entry["QuietUninstallString"]
    assert entry["NoModify"] == 1
    assert entry["NoRepair"] == 1

    cmd_txt = (st_a / "bin" / "uninstall_cosmos_mcp.cmd").read_bytes()
    assert b"chcp 65001" in cmd_txt
    assert b"\r\n" in cmd_txt and b"\r\r\n" not in cmd_txt

    # Create Start Menu shortcuts: one belonging to `st_a`, one belonging to `st_b`, and one unrelated user shortcut
    sm_a = programs_dir / "WebAI2PC.lnk"
    sm_b = programs_dir / "Cosmos_MCP_Other.lnk"
    sm_user = programs_dir / "MyEditor.lnk"
    sm_a.write_text(f"TARGET={st_a.resolve()}\\bin\\uninstall_cosmos_mcp.cmd", encoding="utf-8")
    sm_b.write_text(f"TARGET={st_b.resolve()}\\bin\\uninstall_cosmos_mcp.cmd", encoding="utf-8")
    sm_user.write_text("USER_KEEP", encoding="utf-8")

    # Uninstalling `st_b` (`state_10`) must NOT delete `st_a` (`state_1`) registry entry or `st_a`'s Start Menu shortcut!
    cli.ensure_standalone_state(st_a, workspace_roots=[str(ws_a)], tunnel_mode="local")
    cli.ensure_standalone_state(st_b, workspace_roots=[str(ws_a)], tunnel_mode="local")
    un_b = doctor.run_uninstall(
        st_b,
        home_dir=fake_home,
        desktop_dir=desk,
        platform_name="win32",
        winreg_store={},
        uninstall_reg_store=reg_store,
    )
    assert un_b["ok"] is True
    assert all(item["removed"] is False for item in un_b["windows_uninstall_removed"])
    assert "Cosmos-MCP" in reg_store
    assert sm_a.is_file()
    assert not sm_b.exists()
    assert sm_user.is_file()

    # Now uninstall `st_a`: removes `Cosmos-MCP` from `reg_store` and cleans `sm_a`, keeping `sm_user`
    un_a = doctor.run_uninstall(
        st_a,
        purge=True,
        home_dir=fake_home,
        desktop_dir=desk,
        platform_name="win32",
        winreg_store={},
        uninstall_reg_store=reg_store,
    )
    assert un_a["ok"] is True
    assert any(item["removed"] is True for item in un_a["windows_uninstall_removed"])
    assert "Cosmos-MCP" not in reg_store
    assert not sm_a.exists()
    assert sm_user.is_file()

    # Second run is 100% idempotent
    un_a_again = doctor.run_uninstall(
        st_a,
        purge=True,
        home_dir=fake_home,
        desktop_dir=desk,
        platform_name="win32",
        winreg_store={},
        uninstall_reg_store=reg_store,
    )
    assert un_a_again["ok"] is True
    assert all(item["removed"] is False for item in un_a_again["windows_uninstall_removed"])


def test_uninstall_purge_byte_level_zero_shred_new_secret_types_and_deferred_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """2) Verify byte-level 0x00 overwrite before truncate(0) on connection.dpapi, connection.enc, endpoint_secret.txt & local_vault.key."""
    st_dir = tmp_path / "state_shred"
    fake_home = tmp_path / "home_shred"
    desk = fake_home / "Desktop"
    ws_dir = tmp_path / "ws_shred"
    desk.mkdir(parents=True)
    ws_dir.mkdir(parents=True)
    user_code = ws_dir / "important.py"
    user_code.write_text("ANSWER = 100\n", encoding="utf-8")

    cli.ensure_standalone_state(st_dir, workspace_roots=[str(ws_dir)], tunnel_mode="local")
    sec_dir = st_dir / "secrets"
    targets = {
        "connection.dpapi": sec_dir / "connection.dpapi",
        "connection.enc": sec_dir / "connection.enc",
        "endpoint_secret.txt": sec_dir / "endpoint_secret.txt",
        "local_vault.key": sec_dir / "local_vault.key",
    }
    markers: Dict[str, bytes] = {}
    hardlinks: Dict[str, Path] = {}
    for idx, (label, path_obj) in enumerate(targets.items()):
        payload = (f"SENSITIVE_S10_SECRET_{idx}_{label}_".encode("ascii") * 6)[:180]
        path_obj.write_bytes(payload)
        markers[label] = payload
        hl = tmp_path / f"hl_{idx}_{label}.probe"
        os.link(path_obj, hl)
        hardlinks[label] = hl

    # Spy on `os.fsync` inside `doctor` to capture raw bytes on disk right after 0x00 overwrite (before truncate(0))
    pre_truncate_snapshots: Dict[str, List[bytes]] = {k: [] for k in targets}
    real_fsync = os.fsync

    def _spy_fsync(fd: int) -> None:
        for label, hl_p in hardlinks.items():
            if hl_p.is_file():
                raw_now = hl_p.read_bytes()
                if len(raw_now) > 0:
                    pre_truncate_snapshots[label].append(raw_now)
        real_fsync(fd)

    monkeypatch.setattr(doctor.os, "fsync", _spy_fsync)

    res = doctor.run_uninstall(
        st_dir,
        purge=True,
        home_dir=fake_home,
        desktop_dir=desk,
        platform_name="win32",
        winreg_store={},
        uninstall_reg_store={},
    )
    assert res["ok"] is True
    assert not st_dir.exists()
    assert user_code.read_text(encoding="utf-8") == "ANSWER = 100\n"

    for label, hl_p in hardlinks.items():
        # 1) Before truncate(0), the exact inode was overwritten with 100% `0x00` bytes >= original secret length!
        snaps = pre_truncate_snapshots[label]
        assert any(
            len(b) >= len(markers[label]) and set(b) == {0}
            for b in snaps
        ), f"{label} was not overwritten with 0x00 bytes prior to truncate/unlink!"
        # 2) After truncate(0) & unlink, the inode size is 0
        assert hl_p.stat().st_size == 0
        assert hl_p.read_bytes() == b""

    # Verify Windows `.venv\Scripts\python.exe` self-lock deferred cleanup scheduling & safety guard
    st_locked = tmp_path / "state_venv_locked"
    fake_venv_py = st_locked / ".venv" / "Scripts" / "python.exe"
    fake_venv_py.parent.mkdir(parents=True)
    fake_venv_py.write_bytes(b"MZ_LOCKED")

    popen_calls: List[Dict[str, Any]] = []

    class _DummyProc:
        pid = 99999

    def _fake_popen(cmd: Any, **kwargs: Any) -> _DummyProc:
        popen_calls.append({"cmd": cmd, "kwargs": kwargs})
        return _DummyProc()

    monkeypatch.setattr(doctor.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(doctor.sys, "platform", "win32")
    monkeypatch.setattr(doctor.sys, "executable", str(fake_venv_py))
    monkeypatch.setattr(doctor, "_purge_path_permanently", lambda p, **_kw: False if p == st_locked else True)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    res_locked = doctor.run_uninstall(
        st_locked,
        purge=True,
        home_dir=fake_home,
        desktop_dir=desk,
        platform_name=None,
        winreg_store={},
        uninstall_reg_store={},
    )
    assert res_locked["ok"] is True
    assert res_locked["deferred_self_cleanup_scheduled"] is True
    assert len(popen_calls) == 1
    called_cmd = str(popen_calls[0]["cmd"])
    called_flags = int(popen_calls[0]["kwargs"].get("creationflags") or 0)
    assert "ping -n 3 127.0.0.1 >nul" in called_cmd
    assert "rmdir /s /q" in called_cmd
    assert str(st_locked.resolve()) in called_cmd
    assert (called_flags & CREATE_NO_WINDOW) == CREATE_NO_WINDOW
    assert (called_flags & doctor.DETACHED_PROCESS) == doctor.DETACHED_PROCESS


def test_delete_cloudflare_workers_gateway_and_endpoint_secret_recovery_card(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """3) Verify CF Worker DELETE (200 & 404/10007 idempotency + token shred), CLI --cf-api-token, and endpoint_secret in v2 PNG."""
    st_dir = tmp_path / "state_cf_del"
    ws_dir = tmp_path / "ws_cf_del"
    ws_dir.mkdir(parents=True)
    cli.ensure_standalone_state(st_dir, workspace_roots=[str(ws_dir)], tunnel_mode="workers_dev")

    cfg_p = st_dir / "config" / "service.json"
    cfg_doc = json.loads(cfg_p.read_text(encoding="utf-8"))
    cfg_doc["workers_dev_script_name"] = "cosmos-mcp-s10node123"
    cfg_p.write_text(json.dumps(cfg_doc, indent=2), encoding="utf-8")

    tok_file = cf_workers_gateway.cloudflare_api_token_secret_path(st_dir, "pc")
    tok_file.write_text("cfut_s10_persisted_secret_token_1234567890\n", encoding="utf-8")
    tok_hl = tmp_path / "cf_tok_hl.probe"
    os.link(tok_file, tok_hl)

    seen_requests: List[tuple[str, str]] = []
    delete_mode = {"status": 200}

    class _FakeResp:
        def __init__(self, status: int, body: Dict[str, Any]) -> None:
            self.status = status
            self._raw = json.dumps(body).encode("utf-8")

        def read(self) -> bytes:
            return self._raw

        def __enter__(self) -> "_FakeResp":
            return self

        def __exit__(self, *_: Any) -> None:
            return None

    def _fake_opener(req: urllib.request.Request, timeout: float = 35.0) -> _FakeResp:
        _ = timeout
        method = req.get_method()
        url = req.full_url
        seen_requests.append((method, url))
        if method == "GET" and url.endswith("/accounts"):
            return _FakeResp(200, {"success": True, "result": [{"id": "acc_auto_s10", "name": "Demo"}]})
        if method == "DELETE" and "/workers/scripts/cosmos-mcp-s10node123" in url:
            if delete_mode["status"] == 200:
                return _FakeResp(200, {"success": True, "result": {"id": "cosmos-mcp-s10node123"}})
            err_body = json.dumps(
                {"success": False, "errors": [{"code": 10007, "message": "workers.api.error.script_not_found"}]}
            ).encode("utf-8")
            raise HTTPError(url, 404, "Not Found", hdrs=None, fp=io.BytesIO(err_body))  # type: ignore[arg-type]
        raise AssertionError(f"Unexpected CF request: {method} {url}")

    # A) 200 OK deletion + account auto-discovery + automatic token shred
    res_200 = cf_workers_gateway.delete_cloudflare_workers_gateway(
        api_token="",
        state_root=st_dir,
        prefix="pc",
        opener_override=_fake_opener,
    )
    assert res_200["ok"] is True
    assert res_200["deleted"] is True
    assert res_200["already_absent"] is False
    assert res_200["account_id"] == "acc_auto_s10"
    assert res_200["script_name"] == "cosmos-mcp-s10node123"
    assert res_200["api_token_purged"] is True
    assert not tok_file.exists()
    assert tok_hl.stat().st_size == 0

    # B) 404 / code 10007 idempotent success
    delete_mode["status"] = 404
    tok_file.write_text("cfut_second_token_to_wipe_99887766\n", encoding="utf-8")
    res_404 = cf_workers_gateway.delete_cloudflare_workers_gateway(
        api_token="cfut_explicit_tok_1234567890",
        state_root=st_dir,
        prefix="pc",
        opener_override=_fake_opener,
    )
    assert res_404["ok"] is True
    assert res_404["deleted"] is False
    assert res_404["already_absent"] is True
    assert not tok_file.exists()

    # C) CLI `uninstall --cf-api-token` wires `cloudflare_worker_cleanup` before state removal
    monkeypatch.setattr(
        cli,
        "delete_cloudflare_workers_gateway",
        lambda **kw: cf_workers_gateway.delete_cloudflare_workers_gateway(**kw, opener_override=_fake_opener),
    )
    rc_un = cli.main(
        [
            "uninstall",
            "--state-dir",
            str(st_dir),
            "--cf-api-token",
            "cfut_cli_tok_1234567890",
            "-y",
            "--json",
        ]
    )
    assert rc_un == 0
    un_doc = json.loads(capsys.readouterr().out)
    assert un_doc["ok"] is True
    assert un_doc["cloudflare_worker_cleanup"]["ok"] is True
    assert un_doc["cloudflare_worker_cleanup"]["script_name"] == "cosmos-mcp-s10node123"

    # D) Recovery card v2 packs and restores `secrets/endpoint_secret.txt` (with v1 backward compatibility)
    st_ep_src = tmp_path / "state_ep_src"
    st_ep_dst = tmp_path / "state_ep_dst"
    cli.ensure_standalone_state(st_ep_src, workspace_roots=[str(ws_dir)], tunnel_mode="local")
    ep_secret_val = "ep_sec_v12_exact_secret_value_998877\n"
    ep_src_p = cf_workers_gateway.endpoint_secret_path(st_ep_src, "pc")
    ep_src_p.write_text(ep_secret_val, encoding="utf-8")

    png_v2 = cf_workers_gateway.export_identity_recovery_png(st_ep_src, "StrongPass-S10!", prefix="pc")
    assert b"ep_sec_v12_exact_secret_value_998877" not in png_v2

    imp_v2 = cf_workers_gateway.import_identity_recovery_png(png_v2, "StrongPass-S10!", st_ep_dst, prefix="pc")
    assert imp_v2["restored"] is True
    assert imp_v2["has_endpoint_secret"] is True
    ep_dst_p = cf_workers_gateway.endpoint_secret_path(st_ep_dst, "pc")
    assert ep_dst_p.read_text(encoding="utf-8") == ep_secret_val


def test_cli_passwordless_identity_uses_random_local_key_and_rejects_legacy_public_constant(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """4) Verify passwordless `identity --export/--import` uses random local secret and old public constant CANNOT decrypt new cards."""
    assert not hasattr(cli, "DEFAULT_CLI_RECOVERY_PASSPHRASE")

    real_home_key = Path.home().expanduser().resolve() / ".cosmos-mcp-cli-recovery.key"
    had_real_home_key_before = real_home_key.exists()

    st_src = tmp_path / "st_id_src"
    st_dst = tmp_path / "st_id_dst"
    st_probe = tmp_path / "st_id_probe"
    ws_dir = tmp_path / "ws_id"
    ws_dir.mkdir(parents=True)

    cli.ensure_standalone_state(st_src, workspace_roots=[str(ws_dir)], tool_prefix="devbox", tunnel_mode="local")
    card_png = tmp_path / "no_arg_card.png"

    rc_exp = cli.main(["identity", "--state-dir", str(st_src), "--export", str(card_png), "--json"])
    assert rc_exp == 0
    exp_out = json.loads(capsys.readouterr().out)
    assert exp_out["ok"] is True
    assert exp_out["passphrase_mode"] == "local_machine_key"

    # Key must be stored in `tmp_path / ".cosmos-mcp-cli-recovery.key"` under pytest without polluting real `$HOME`
    test_key_file = tmp_path / ".cosmos-mcp-cli-recovery.key"
    assert test_key_file.is_file()
    if not had_real_home_key_before:
        assert not real_home_key.exists()
    secret_val = test_key_file.read_text(encoding="utf-8").strip()
    assert len(secret_val) >= 40
    assert secret_val != "cosmos-mcp-cli-default-recovery-v2"

    # Hard security check: the old public hardcoded constant MUST FAIL to decrypt the newly exported card!
    with pytest.raises(ValueError, match="Invalid recovery passphrase"):
        cf_workers_gateway.import_identity_recovery_png(
            card_png.read_bytes(),
            "cosmos-mcp-cli-default-recovery-v2",
            st_probe,
        )

    # Same local environment round-trips cleanly without `--passphrase`
    rc_imp = cli.main(["identity", "--state-dir", str(st_dst), "--import", str(card_png), "--json"])
    assert rc_imp == 0
    imp_out = json.loads(capsys.readouterr().out)
    assert imp_out["ok"] is True
    assert imp_out["node_id"] == exp_out["node_id"]
    assert imp_out["tool_prefix"] == "devbox"

    # One-way legacy read compatibility: an old historical card encrypted with the old v2 constant can still be read once
    legacy_png = tmp_path / "historical_v2_card.png"
    cli._run_export_identity(
        st_src,
        prefix="pc",
        out_path=legacy_png,
        passphrase="cosmos-mcp-cli-default-recovery-v2",
        passphrase_mode="explicit",
    )
    st_legacy_dst = tmp_path / "st_id_legacy_dst"
    rc_leg = cli.main(["identity", "--state-dir", str(st_legacy_dst), "--import", str(legacy_png), "--json"])
    assert rc_leg == 0
    leg_out = json.loads(capsys.readouterr().out)
    assert leg_out["ok"] is True
    assert leg_out["node_id"] == exp_out["node_id"]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows `.bat` subprocess test")
def test_oneclick_uninstall_bat_real_subprocess_dry_run_and_purge_e2e(tmp_path: Path) -> None:
    """5) Execute `一键卸载_Cosmos_MCP.bat --dry-run --json` and `--purge -y --json` end-to-end in real subprocess."""
    bat_path = REPO_ROOT / "一键卸载_Cosmos_MCP.bat"
    st_dir = tmp_path / "state_bat_e2e"
    ws_dir = tmp_path / "ws_bat_e2e"
    ws_dir.mkdir(parents=True)
    keep_file = ws_dir / "project_main.py"
    keep_file.write_text("KEEP = True\n", encoding="utf-8")

    cli.ensure_standalone_state(st_dir, workspace_roots=[str(ws_dir)], tunnel_mode="local")
    dpapi_f = st_dir / "secrets" / "connection.dpapi"
    ep_f = st_dir / "secrets" / "endpoint_secret.txt"
    dpapi_f.write_bytes(b"DPAPI_BAT_E2E_BLOB_" * 8)
    ep_f.write_text("EP_SECRET_BAT_E2E_998877\n", encoding="utf-8")
    hl_dpapi = tmp_path / "bat_dpapi.probe"
    os.link(dpapi_f, hl_dpapi)

    env = dict(os.environ)
    env["COSMOS_NO_PAUSE"] = "1"
    env["PYTEST_CURRENT_TEST"] = "test_oneclick_uninstall_bat"

    # Step 1: `--dry-run --json`
    proc_dry = subprocess.run(
        ["cmd.exe", "/d", "/c", str(bat_path), "--state-dir", str(st_dir), "--dry-run", "--json"],
        cwd=str(REPO_ROOT),
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30.0,
        creationflags=CREATE_NO_WINDOW,
    )
    assert proc_dry.returncode == 0, proc_dry.stderr
    dry_doc = json.loads(proc_dry.stdout)
    assert dry_doc["ok"] is True
    assert dry_doc["dry_run"] is True
    assert st_dir.is_dir()

    # Step 2: `--purge -y --json`
    proc_purge = subprocess.run(
        ["cmd.exe", "/d", "/c", str(bat_path), "--state-dir", str(st_dir), "--purge", "-y", "--json"],
        cwd=str(REPO_ROOT),
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30.0,
        creationflags=CREATE_NO_WINDOW,
    )
    assert proc_purge.returncode == 0, proc_purge.stderr
    purge_doc = json.loads(proc_purge.stdout)
    assert purge_doc["ok"] is True
    assert purge_doc["purge"] is True
    assert not st_dir.exists()
    assert hl_dpapi.stat().st_size == 0
    assert keep_file.read_text(encoding="utf-8") == "KEEP = True\n"
