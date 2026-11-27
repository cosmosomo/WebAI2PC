"""Regression tests for Wave 11-C: CLI full lifecycle, doctor redaction/uninstall, autostart & release packaging."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import tomllib
import zipfile

import pytest

from cosmos_mcp.capabilities.skills import models as skill_models
from cosmos_mcp.launcher import autostart, cli, doctor
from cosmos_mcp.protocol.oauth import derive_dynamic_pair_code


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_cli_new_flags_public_url_normalization_and_vps_hub_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    st_dir = tmp_path / "state_cli"
    ws_main = tmp_path / "ws_main"
    ro_one = tmp_path / "ro_one"
    ro_two = tmp_path / "ro_two"
    ws_main.mkdir(parents=True)
    ro_one.mkdir(parents=True)
    ro_two.mkdir(parents=True)

    # 1. Invalid plaintext http:// non-loopback `--public-url` must fail cleanly with exit code 2
    rc_bad = cli.main(
        [
            "agent-setup",
            "--state-dir",
            str(st_dir),
            "--mode",
            "custom",
            "--public-url",
            "http://example.com/mcp",
            "--prepare-only",
            "--json",
        ]
    )
    assert rc_bad == 2
    err_doc = json.loads(capsys.readouterr().out)
    assert err_doc["ok"] is False
    assert "https://" in err_doc["error"]

    # 2. `--prepare-only` with `--readonly-workspace`, `--scan-host-global-skills`, `--python-path`,
    #    `--enable-pack desktop`, `--no-tray`, and duplicate `/mcp/mcp` suffix stripping
    rc_ok = cli.main(
        [
            "agent-setup",
            "--state-dir",
            str(st_dir),
            "--workspace",
            str(ws_main),
            "--readonly-workspace",
            f"{ro_one},{ro_two}",
            "--scan-host-global-skills",
            "true",
            "--python-path",
            sys.executable,
            "--enable-pack",
            "desktop",
            "--no-tray",
            "--mode",
            "vps_hub",
            "--public-url",
            "https://hub.example.com/mcp/mcp",
            "--prepare-only",
            "--json",
        ]
    )
    assert rc_ok == 0
    prep = json.loads(capsys.readouterr().out)
    assert prep["ok"] is True
    assert prep["runtime_ready"] is True
    assert prep["tray_enabled"] is False
    assert prep["scan_host_global_skills"] is True
    assert prep["python_path"] == sys.executable
    assert prep["enabled_packs"] == ["desktop"]
    assert prep["public_url"] == "https://hub.example.com"
    assert prep["mcp_url"] == "https://hub.example.com/mcp"
    assert prep["readonly_mcp_url"] == "https://hub.example.com/mcp/readonly"
    assert prep["gateway_warning"] == "vps_node_secret_missing"
    assert len(prep["dynamic_pair_code"]) == 6 and prep["dynamic_pair_code"].isdigit()

    ro_norm = {os.path.normcase(p) for p in prep["readonly_workspace_roots"]}
    assert os.path.normcase(str(ro_one.resolve())) in ro_norm
    assert os.path.normcase(str(ro_two.resolve())) in ro_norm
    # Readonly roots are also mounted in active `workspace_roots`
    ws_norm = {os.path.normcase(p) for p in prep["workspace_roots"]}
    assert ro_norm.issubset(ws_norm)

    # Underlying `service.json` preserves internal `["cua"]` pack key while persisting `tray_enabled: False`
    svc_doc = json.loads((st_dir / "config" / "service.json").read_text(encoding="utf-8"))
    assert svc_doc["enabled_packs"] == ["cua"]
    assert svc_doc["tray_enabled"] is False

    # 3. `status --json` computes matching 6-digit `dynamic_pair_code` and reports `gateway_warning`
    rc_st = cli.main(["status", "--state-dir", str(st_dir), "--json"])
    assert rc_st == 0
    st_out = json.loads(capsys.readouterr().out)
    auth_doc = json.loads((st_dir / "secrets" / "auth.json").read_text(encoding="utf-8"))
    expected_dyn = derive_dynamic_pair_code(auth_doc["password_hash"], auth_doc["salt"])
    assert len(st_out["dynamic_pair_code"]) == 6 and st_out["dynamic_pair_code"].isdigit()
    assert st_out["dynamic_pair_code"] in {expected_dyn, prep["dynamic_pair_code"]}
    assert st_out["enabled_packs"] == ["desktop"]
    assert st_out["gateway_warning"] == "vps_node_secret_missing"

    # 4. `agent-setup --guide --json` reflects `public_gateway --no-browser` and `L1..L4` tiers
    rc_guide = cli.main(["agent-setup", "--state-dir", str(st_dir), "--guide", "--json"])
    assert rc_guide == 0
    guide_doc = json.loads(capsys.readouterr().out)
    assert "--mode public_gateway --no-browser --json" in guide_doc["recommended_commands"]["agent_setup_public_gateway"]
    assert set(guide_doc["permission_tiers"].keys()) == {"L1", "L2", "L3", "L4"}


def test_cli_export_and_import_identity_syncs_workspace_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    st_src = tmp_path / "state_src"
    st_dst = tmp_path / "state_dst"
    st_dst2 = tmp_path / "state_dst2"
    ws_a = tmp_path / "proj_alpha"
    ro_b = tmp_path / "docs_readonly"
    ws_a.mkdir(parents=True)
    ro_b.mkdir(parents=True)

    rc_init = cli.main(
        [
            "permissions",
            "--state-dir",
            str(st_src),
            "--tool-prefix",
            "workbox",
            "--tier",
            "L2",
            "--workspace",
            str(ws_a),
            "--readonly-workspace",
            str(ro_b),
            "--enable-pack",
            "desktop",
            "--scan-host-global-skills",
            "true",
            "--json",
        ]
    )
    assert rc_init == 0
    _ = capsys.readouterr()

    card_png = tmp_path / "recovery_card.png"
    rc_exp = cli.main(
        [
            "export-identity",
            "--state-dir",
            str(st_src),
            "--out",
            str(card_png),
            "--passphrase",
            "Wave11C-StrongPass!",
            "--json",
        ]
    )
    assert rc_exp == 0
    exp_doc = json.loads(capsys.readouterr().out)
    assert exp_doc["ok"] is True
    assert card_png.is_file()
    raw_png = card_png.read_bytes()
    assert raw_png[:8] == b"\x89PNG\r\n\x1a\n"
    assert b"cMcp" in raw_png and b"cPol" in raw_png

    rc_imp = cli.main(
        [
            "import-identity",
            "--state-dir",
            str(st_dst),
            "--in",
            str(card_png),
            "--passphrase",
            "Wave11C-StrongPass!",
            "--json",
        ]
    )
    assert rc_imp == 0
    imp_doc = json.loads(capsys.readouterr().out)
    assert imp_doc["ok"] is True
    assert imp_doc["policy_restored"] is True
    assert imp_doc["node_id"] == exp_doc["node_id"]
    assert imp_doc["tool_prefix"] == "workbox"
    assert imp_doc["permission_tier"] == "tier2_workspace_edit"
    assert imp_doc["enabled_packs"] == ["desktop"]
    assert imp_doc["scan_host_global_skills"] is True
    assert os.path.normcase(str(ro_b.resolve())) in {os.path.normcase(x) for x in imp_doc["readonly_workspace_roots"]}
    assert os.path.normcase(str(ws_a.resolve())) in {os.path.normcase(x) for x in imp_doc["workspace_roots"]}

    # Unified `identity --export / --import` without explicit `--passphrase` also round-trips cleanly
    card_default = tmp_path / "recovery_default.png"
    assert cli.main(["identity", "--state-dir", str(st_src), "--export", str(card_default), "--json"]) == 0
    _ = capsys.readouterr()
    assert cli.main(["identity", "--state-dir", str(st_dst2), "--import", str(card_default), "--json"]) == 0
    imp2 = json.loads(capsys.readouterr().out)
    assert imp2["node_id"] == exp_doc["node_id"]
    assert imp2["tool_prefix"] == "workbox"


def test_cli_agent_setup_live_daemon_populates_supervisor_alive(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    st_dir = tmp_path / "state_live_daemon"
    ws_dir = tmp_path / "ws_live"
    ws_dir.mkdir(parents=True)
    port = _pick_free_port()

    try:
        rc = cli.main(
            [
                "agent-setup",
                "--state-dir",
                str(st_dir),
                "--workspace",
                str(ws_dir),
                "--mode",
                "local",
                "--port",
                str(port),
                "--no-browser",
                "--no-tray",
                "--json",
            ]
        )
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["ok"] is True
        assert out["online"] is True
        assert out["supervisor_alive"] is True
        assert int(out["supervisor_pid"] or 0) > 0
        assert int(out["server_pid"] or 0) > 0
        assert out["tray_enabled"] is False
        assert len(out["dynamic_pair_code"]) == 6 and out["dynamic_pair_code"].isdigit()
    finally:
        cli.main(["stop", "--state-dir", str(st_dir), "--json"])
        _ = capsys.readouterr()


def test_doctor_redacts_proxy_credentials_hostname_seed_and_non_users_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    st_dir = tmp_path / "state_doc"
    ws_dir = tmp_path / "ws_doc"
    ws_dir.mkdir(parents=True)

    cli.ensure_standalone_state(
        st_dir,
        workspace_roots=[str(ws_dir)],
        tunnel_mode="vps_hub",
        public_url="https://hub.example.com",
    )
    fake_seed_hex = "ab" * 32
    (st_dir / "secrets" / "master_seed.hex").write_text(fake_seed_hex, encoding="utf-8")
    cfg_p = st_dir / "config" / "service.json"
    cfg_doc = json.loads(cfg_p.read_text(encoding="utf-8"))
    cfg_doc["vps_host"] = "198.51.100.77"
    cfg_doc["workspace_roots"] = [r"D:\TopSecretCorp\ProjectX", str(ws_dir)]
    cfg_p.write_text(json.dumps(cfg_doc, indent=2), encoding="utf-8")
    (st_dir / "logs").mkdir(parents=True, exist_ok=True)
    proxy_u = "http://corpuser:UltraSecretPw99" + chr(64) + "proxy.example.com:8080"
    (st_dir / "logs" / "supervisor.log").write_text(
        f"proxy={proxy_u} seed={fake_seed_hex} ws=E:\\PrivateRepo\\alpha host={socket.gethostname()}\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("HTTPS_PROXY", proxy_u)
    bundle_zip = tmp_path / "diag_bundle.zip"
    rep = doctor.run_doctor(st_dir, bundle=True, bundle_output=bundle_zip)

    assert rep["service_online"] is False
    assert rep["gateway_healthy"] is False
    assert "vps_node_secret_missing" in rep["gateway_issues"]

    serialized = json.dumps(rep, ensure_ascii=False)
    assert "UltraSecretPw99" not in serialized
    assert "corpuser:UltraSecretPw99" not in serialized
    assert fake_seed_hex not in serialized
    assert "198.51.100.77" not in serialized
    assert "TopSecretCorp" not in serialized
    assert "PrivateRepo" not in serialized

    host_raw = socket.gethostname().strip()
    if len(host_raw) >= 3 and host_raw.lower() not in {"localhost", "runner", "ubuntu", "root", "user"}:
        assert host_raw not in serialized

    assert bundle_zip.is_file()
    with zipfile.ZipFile(bundle_zip, "r") as zf:
        for name in zf.namelist():
            txt = zf.read(name).decode("utf-8", errors="replace")
            assert "UltraSecretPw99" not in txt
            assert fake_seed_hex not in txt
            assert "TopSecretCorp" not in txt
            assert "PrivateRepo" not in txt


def test_uninstall_scoped_prefix_preserves_shared_venv_and_default_instance(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    st_dir = tmp_path / "state_multi"
    ws_pc = tmp_path / "ws_pc"
    ws_work = tmp_path / "ws_work"
    ws_pc.mkdir(parents=True)
    ws_work.mkdir(parents=True)

    cli.ensure_standalone_state(st_dir, prefix="pc", workspace_roots=[str(ws_pc)], tunnel_mode="local")
    cli.ensure_standalone_state(st_dir, prefix="work", workspace_roots=[str(ws_work)], tunnel_mode="local")
    fake_venv_py = st_dir / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python3")
    fake_venv_py.parent.mkdir(parents=True, exist_ok=True)
    fake_venv_py.write_bytes(b"MZ_FAKE_SHARED_VENV")
    (st_dir / "app_src" / "cosmos_mcp").mkdir(parents=True, exist_ok=True)
    (st_dir / "app_src" / "cosmos_mcp" / "__init__.py").write_text("", encoding="utf-8")

    rc = cli.main(["uninstall", "--state-dir", str(st_dir), "--prefix", "work", "-y", "--json"])
    assert rc == 0
    res = json.loads(capsys.readouterr().out)
    assert res["ok"] is True
    assert res["prefix"] == "work"
    assert res["scoped_instance_only"] is True
    assert "--purge" in res["purge_hint"]

    # `work` instance config is removed, while `pc` config + shared `.venv` + `app_src` remain intact
    assert not (st_dir / "config" / "service_work.json").exists()
    assert (st_dir / "config" / "service.json").is_file()
    assert fake_venv_py.is_file()
    assert (st_dir / "app_src" / "cosmos_mcp" / "__init__.py").is_file()


def test_autostart_prefers_python_embed_and_packaging_gates(tmp_path: Path) -> None:
    st_dir = tmp_path / "state_embed"
    embed_pyw = st_dir / "python-embed" / "pythonw.exe"
    venv_pyw = st_dir / ".venv" / "Scripts" / "pythonw.exe"
    embed_pyw.parent.mkdir(parents=True, exist_ok=True)
    venv_pyw.parent.mkdir(parents=True, exist_ok=True)
    embed_pyw.write_bytes(b"MZ_EMBED")
    venv_pyw.write_bytes(b"MZ_VENV")

    chosen = autostart._resolve_autostart_python(
        sys.executable,
        st_dir,
        platform_name="win32",
    )
    assert os.path.normcase(str(chosen)) == os.path.normcase(str(embed_pyw))
    fake_reg: dict[str, str] = {}
    auto_res = autostart.enable_autostart(
        python_exe=sys.executable,
        state_root=st_dir,
        prefix="pc",
        platform_name="win32",
        winreg_store=fake_reg,
        run_ctl=False,
    )
    assert auto_res["ok"] is True
    assert os.path.normcase(str(embed_pyw)) in os.path.normcase(fake_reg[auto_res["entry_name"]])

    repo_root = Path(__file__).resolve().parents[1]
    pyproj = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    deps = pyproj["project"]["dependencies"]
    assert any(d.startswith("cryptography>=") for d in deps)
    pkg_data = pyproj["tool"]["setuptools"]["package-data"]
    assert "SKILL.md" in pkg_data.get("cosmos_mcp.host_skills", [])
    assert skill_models.PACKAGE_VERSION == pyproj["project"]["version"] == "1.2.1"

    # Verify `build_release.py` binary byte-level scanner catches embedded sensitive path in `.exe`
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_release_mod", repo_root / "scripts" / "build_release.py")
    assert spec and spec.loader
    br = importlib.util.module_from_spec(spec)
    sys.modules["build_release_mod"] = br
    spec.loader.exec_module(br)

    dirty_zip = tmp_path / "dirty.zip"
    forbidden_user = "SYNTHETIC_DEV_USER_99"
    dirty_bytes = b"MZ\x90\x00#!C:\\Users\\" + forbidden_user.encode("ascii") + b"\\python.exe\x00"
    with zipfile.ZipFile(dirty_zip, "w") as zf:
        zf.writestr(
            "python-embed/Lib/site-packages/bin/uvicorn.exe",
            dirty_bytes,
        )
    toks = br._build_forbidden_archive_tokens("TESTHOST", forbidden_user, {"localhost", "runner", "root", "user"})
    hits = br.scan_archive_entry_sensitive_bytes(dirty_bytes, toks)
    assert len(hits) >= 1
    prev_extra = os.environ.get("COSMOS_EXTRA_FORBIDDEN_TOKENS")
    os.environ["COSMOS_EXTRA_FORBIDDEN_TOKENS"] = forbidden_user
    try:
        ok_chk, errs_chk, _ = br.run_release_checks(repo_root, dirty_zip)
    finally:
        if prev_extra is None:
            os.environ.pop("COSMOS_EXTRA_FORBIDDEN_TOKENS", None)
        else:
            os.environ["COSMOS_EXTRA_FORBIDDEN_TOKENS"] = prev_extra
    assert ok_chk is False
    assert any("Byte-level sensitive token leaked" in e for e in errs_chk)
    assert any("Forbidden pip/uv `.exe` script wrapper" in e for e in errs_chk)
