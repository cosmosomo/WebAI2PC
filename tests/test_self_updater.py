"""Deterministic local regression suite for zero-drop self-updater, staging security gates,
portable `app_src` anti-downgrade lock, `RELOAD_WORKER` tunnel preservation, and 15s watchdog auto-rollback.
"""
from __future__ import annotations

import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import re
import socket
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
import urllib.request
import zipfile

import pytest

from cosmos_mcp.core import net_power
from cosmos_mcp.core.fs_tx import atomic_write_json, atomic_write_text
from cosmos_mcp.launcher import bootstrap, cli, daemon, updater

REPO_ROOT = Path(__file__).resolve().parents[1]


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


_CACHED_REPO_ENTRIES: Optional[List[Tuple[str, bytes]]] = None


def _get_cached_repo_entries() -> List[Tuple[str, bytes]]:
    global _CACHED_REPO_ENTRIES
    if _CACHED_REPO_ENTRIES is not None:
        return _CACHED_REPO_ENTRIES
    entries: List[Tuple[str, bytes]] = []
    src_root = REPO_ROOT / "src" / "cosmos_mcp"
    for cur_root, dirs, files in os.walk(src_root):
        dirs[:] = [d for d in sorted(dirs) if d not in ("__pycache__", ".pytest_cache")]
        rel_d = Path(cur_root).relative_to(REPO_ROOT)
        for fname in sorted(files):
            if fname.endswith((".pyc", ".pyo", ".bak")):
                continue
            fp = Path(cur_root) / fname
            entries.append(((rel_d / fname).as_posix(), fp.read_bytes()))
    hs_root = REPO_ROOT / "host_skills"
    if hs_root.is_dir():
        for cur_root, dirs, files in os.walk(hs_root):
            dirs[:] = [d for d in sorted(dirs) if d != "__pycache__"]
            rel_h = Path(cur_root).relative_to(REPO_ROOT)
            for fname in sorted(files):
                fp_h = Path(cur_root) / fname
                entries.append(((rel_h / fname).as_posix(), fp_h.read_bytes()))
    _CACHED_REPO_ENTRIES = entries
    return entries


def _build_synthetic_release_zip(
    out_zip: Path,
    *,
    version: str = "1.2.2",
    wrapper_dir: str = "",
    extra_pyproject_dep: str = "",
    extra_files: Optional[Dict[str, bytes]] = None,
    mutate_file_fn: Optional[Callable[[str, bytes], bytes]] = None,
    full_repo: bool = False,
) -> Tuple[Path, str]:
    """Create a Cosmos MCP source archive (compact unit layout or `full_repo=True` live server layout)."""
    prefix = f"{wrapper_dir.strip('/')}/" if wrapper_dir.strip("/") else ""
    buf = io.BytesIO()

    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        pyproj_txt = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        pyproj_txt = re.sub(
            r'(?m)^version\s*=\s*"[^"]+"',
            f'version = "{version}"',
            pyproj_txt,
            count=1,
        )
        if extra_pyproject_dep:
            pyproj_txt = pyproj_txt.replace(
                "dependencies = [\n",
                f'dependencies = [\n    "{extra_pyproject_dep}",\n',
                1,
            )
        zf.writestr(f"{prefix}pyproject.toml", pyproj_txt.encode("utf-8"))

        if full_repo:
            source_entries = _get_cached_repo_entries()
        else:
            source_entries = [
                ("src/cosmos_mcp/__init__.py", f'"""Cosmos MCP."""\n\n__version__ = "{version}"\n'.encode("utf-8")),
                ("src/cosmos_mcp/core/__init__.py", b""),
                ("src/cosmos_mcp/core/config.py", f'PRODUCT_VERSION = "{version}"\n'.encode("utf-8")),
                ("src/cosmos_mcp/launcher/__init__.py", b""),
                ("src/cosmos_mcp/launcher/daemon.py", b'"""Daemon stub."""\n'),
                ("src/cosmos_mcp/launcher/tunnels.py", b'"""Tunnels stub."""\n'),
                ("src/cosmos_mcp/launcher/cf_workers_gateway.py", b'"""Workers gateway stub."""\n'),
                ("host_skills/SKILL.md", b"# Cosmos MCP Host Skill\n"),
            ]

        for rel_posix, orig_bytes in source_entries:
            data = orig_bytes
            if rel_posix == "src/cosmos_mcp/__init__.py":
                txt = data.decode("utf-8")
                txt = re.sub(
                    r'__version__\s*=\s*["\'][^"\']+["\']',
                    f'__version__ = "{version}"',
                    txt,
                )
                data = txt.encode("utf-8")
            elif rel_posix == "src/cosmos_mcp/core/config.py":
                txt_c = data.decode("utf-8")
                txt_c = re.sub(
                    r'PRODUCT_VERSION\s*=\s*["\'][^"\']+["\']',
                    f'PRODUCT_VERSION = "{version}"',
                    txt_c,
                    count=1,
                )
                data = txt_c.encode("utf-8")
            if mutate_file_fn is not None:
                data = mutate_file_fn(rel_posix, data)
            zf.writestr(f"{prefix}{rel_posix}", data)

        if extra_files:
            for raw_arc, raw_bytes in extra_files.items():
                zf.writestr(raw_arc, raw_bytes)

    raw_zip = buf.getvalue()
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    out_zip.write_bytes(raw_zip)
    return out_zip, hashlib.sha256(raw_zip).hexdigest()


class _LocalUpdateApiServer:
    """Thread-backed local HTTPServer stubbing GitHub Releases, `commits/main`, and ZIP downloads."""

    def __init__(self) -> None:
        self.release_status: int = 200
        self.release_payload: Dict[str, Any] = {}
        self.main_status: int = 200
        self.main_payload: Dict[str, Any] = {}
        self.archives: Dict[str, bytes] = {}
        self.requests_seen: List[str] = []

        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

            def do_GET(self) -> None:  # noqa: N802
                outer.requests_seen.append(self.path)
                if self.path.endswith("/releases/latest"):
                    body = json.dumps(outer.release_payload).encode("utf-8")
                    self.send_response(outer.release_status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if self.path.endswith("/commits/main"):
                    body = json.dumps(outer.main_payload).encode("utf-8")
                    self.send_response(outer.main_status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                for key, payload in outer.archives.items():
                    if self.path.endswith(key):
                        self.send_response(200)
                        self.send_header("Content-Type", "application/zip")
                        self.send_header("Content-Length", str(len(payload)))
                        self.end_headers()
                        self.wfile.write(payload)
                        return
                self.send_response(404)
                self.end_headers()

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = int(self._srv.server_address[1])
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._srv.serve_forever, name="local-upd-api", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()
        self._thread.join(timeout=3.0)


class _Broken502ProxyServer:
    """Local HTTP proxy returning `502 Bad Gateway` so proxy->direct fallback is deterministically verified."""

    def __init__(self) -> None:
        self.proxy_hits: int = 0
        outer = self

        class _ProxyHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

            def do_GET(self) -> None:  # noqa: N802
                outer.proxy_hits += 1
                msg = b"upstream proxy bad gateway"
                self.send_response(502)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)

            def do_CONNECT(self) -> None:  # noqa: N802
                outer.proxy_hits += 1
                self.send_response(502)
                self.end_headers()

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), _ProxyHandler)
        self.port = int(self._srv.server_address[1])
        self.proxy_url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._srv.serve_forever, name="broken-502-proxy", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()
        self._thread.join(timeout=3.0)


# ---------------------------------------------------------------------------
# Test 1: `check_for_updates` (`release`, `404` -> `main` fallback, proxy `502` -> direct fallback)
# ---------------------------------------------------------------------------


def test_check_for_updates_release_404_fallback_and_proxy_502_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    st_root = tmp_path / "state_chk"
    bootstrap.sync_portable_app_src(st_root, source_src_dir=REPO_ROOT / "src")
    (st_root / "state").mkdir(parents=True, exist_ok=True)

    # Verify `tunnel_impact` detects ephemeral `trycloudflare.com` vs fixed `srv.us`
    atomic_write_json(
        daemon.daemon_status_path(st_root),
        {
            "status": "running",
            "mode": "cloudflare",
            "effective_tunnel_mode": "cloudflare",
            "public_url": "https://ephemeral-demo-box.trycloudflare.com",
            "gateways": {
                "instant": {
                    "enabled": True,
                    "ready": True,
                    "public_url": "https://ephemeral-demo-box.trycloudflare.com",
                }
            },
        },
    )

    api_srv = _LocalUpdateApiServer()
    proxy_srv = _Broken502ProxyServer()
    try:
        fake_sha = "a" * 64
        api_srv.release_status = 200
        api_srv.release_payload = {
            "tag_name": "v1.2.2",
            "target_commitish": "9f8e7d6c5b4a3210",
            "body": "Zero-drop worker hot-reload release.",
            "assets": [
                {
                    "name": "Cosmos-MCP-v1.2.2.zip",
                    "browser_download_url": f"{api_srv.base_url}/downloads/Cosmos-MCP-v1.2.2.zip",
                    "digest": f"sha256:{fake_sha}",
                }
            ],
        }
        monkeypatch.setenv("COSMOS_UPDATE_API_BASE", api_srv.base_url)
        monkeypatch.delenv("COSMOS_UPDATE_ARCHIVE_URL", raising=False)

        # 1a. Standard `release` channel check
        res_rel = updater.check_for_updates(st_root, channel="release")
        assert res_rel["ok"] is True, res_rel
        assert res_rel["channel"] == "release"
        assert res_rel["fallback_to_main"] is False
        assert res_rel["current_version"] == "1.2.1"
        assert res_rel["latest_version"] == "1.2.2"
        assert res_rel["update_available"] is True
        assert res_rel["expected_sha256"] == fake_sha
        assert res_rel["download_url"].endswith("/downloads/Cosmos-MCP-v1.2.2.zip")
        assert res_rel["tunnel_impact"]["only_ephemeral_trycloudflare"] is True
        assert res_rel["tunnel_impact"]["url_changes_on_full_restart"] is True

        # Switch `daemon_status.json` to fixed `srv.us` URL -> `only_ephemeral_trycloudflare` becomes False
        atomic_write_json(
            daemon.daemon_status_path(st_root),
            {
                "status": "running",
                "mode": "srv_us",
                "srvus_fixed_active": True,
                "public_url": "https://steady-node.srv.us",
            },
        )
        res_fixed = updater.check_for_updates(st_root, channel="release")
        assert res_fixed["tunnel_impact"]["has_fixed_public_url"] is True
        assert res_fixed["tunnel_impact"]["only_ephemeral_trycloudflare"] is False

        # 1b. `404` on `/releases/latest` smoothly falls back to `commits/main` (`fallback_to_main=True`)
        api_srv.release_status = 404
        api_srv.release_payload = {"message": "Not Found"}
        main_commit_sha = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
        api_srv.main_status = 200
        api_srv.main_payload = {
            "sha": main_commit_sha,
            "commit": {
                "message": "feat(updater): add hot-reload engine\n\nDetailed notes.",
                "committer": {"date": "2026-11-27T12:00:00Z"},
            },
        }
        res_fb = updater.check_for_updates(st_root, channel="release")
        assert res_fb["ok"] is True, res_fb
        assert res_fb["channel"] == "main"
        assert res_fb["fallback_to_main"] is True
        assert res_fb["latest_commit"] == main_commit_sha
        assert res_fb["update_available"] is True
        assert "feat(updater): add hot-reload engine" in res_fb["release_notes"]

        # Once `.cosmos_update_meta.json` records the same commit SHA & version, `update_available` turns False
        bootstrap.write_app_src_update_meta(
            st_root / "app_src",
            {
                "version": "1.2.1",
                "commit_sha": main_commit_sha,
                "source_tree_hash": bootstrap.compute_source_tree_hash(st_root / "app_src" / "cosmos_mcp"),
                "self_updated_at": time.time(),
            },
        )
        res_up_to_date = updater.check_for_updates(st_root, channel="main")
        assert res_up_to_date["ok"] is True
        assert res_up_to_date["update_available"] is False

        # 1c. Configured HTTP proxy returning `502` automatically retries direct (`ProxyHandler({})`)
        monkeypatch.setattr(urllib.request, "proxy_bypass", lambda _h: False)
        monkeypatch.setattr(net_power, "is_host_proxy_bypassed", lambda *_a, **_k: False)
        monkeypatch.setattr(updater, "detect_configured_proxy", lambda **_k: proxy_srv.proxy_url)
        api_srv.release_status = 200
        api_srv.release_payload = {
            "tag_name": "v1.2.3",
            "body": "Proxy fallback check.",
            "assets": [
                {
                    "name": "Cosmos-MCP-v1.2.3.zip",
                    "browser_download_url": f"{api_srv.base_url}/downloads/Cosmos-MCP-v1.2.3.zip",
                }
            ],
        }
        res_px = updater.check_for_updates(st_root, channel="release")
        assert proxy_srv.proxy_hits >= 1
        assert res_px["ok"] is True, res_px
        assert res_px["latest_version"] == "1.2.3"
        assert res_px["update_available"] is True
        assert res_px["proxy_used"] == ""
    finally:
        api_srv.close()
        proxy_srv.close()


# ---------------------------------------------------------------------------
# Test 2: Tamper / Zip-Slip / AST syntax & in-flight task gates
# ---------------------------------------------------------------------------


def test_tamper_zip_slip_and_ast_syntax_gates_preserve_active_app_src(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    st_root = tmp_path / "state_sec"
    app_src = bootstrap.sync_portable_app_src(st_root, source_src_dir=REPO_ROOT / "src")
    assert app_src is not None
    baseline_hash = bootstrap.compute_source_tree_hash(app_src / "cosmos_mcp")
    assert len(baseline_hash) == 64

    good_zip, good_sha = _build_synthetic_release_zip(tmp_path / "good_122.zip", version="1.2.2")

    # 2a. SHA-256 mismatch is rejected before extraction
    wrong_sha = "f" * 64
    assert wrong_sha != good_sha
    monkeypatch.setenv("COSMOS_UPDATE_EXPECTED_SHA256", wrong_sha)
    res_sha = updater.stage_and_apply_update(st_root, archive_path=good_zip, defer_restart_sec=0.0)
    assert res_sha["ok"] is False
    assert res_sha["error_code"] == "ERR_SHA256_MISMATCH"
    assert bootstrap.compute_source_tree_hash(app_src / "cosmos_mcp") == baseline_hash
    monkeypatch.delenv("COSMOS_UPDATE_EXPECTED_SHA256", raising=False)

    # 2b. Zip-Slip `../../escaped_payload.py` traversal is rejected with zero outside writes
    escape_target = tmp_path / "escaped_payload.py"
    slip_zip, _ = _build_synthetic_release_zip(
        tmp_path / "zip_slip.zip",
        version="1.2.2",
        extra_files={"../../escaped_payload.py": b"raise SystemExit('escaped')\n"},
    )
    res_slip = updater.stage_and_apply_update(st_root, archive_path=slip_zip, defer_restart_sec=0.0)
    assert res_slip["ok"] is False
    assert res_slip["error_code"] == "ERR_ZIP_SLIP_DETECTED"
    assert not escape_target.exists()
    assert bootstrap.compute_source_tree_hash(app_src / "cosmos_mcp") == baseline_hash

    # 2c. Archive containing Python `SyntaxError` is caught at `ast.parse` gate and `app_src` stays untouched
    bad_ast_zip, _ = _build_synthetic_release_zip(
        tmp_path / "bad_syntax.zip",
        version="1.2.2",
        extra_files={"src/cosmos_mcp/corrupted_mod.py": b"def broken_syntax(:\n    pass\n"},
    )
    res_ast = updater.stage_and_apply_update(st_root, archive_path=bad_ast_zip, defer_restart_sec=0.0)
    assert res_ast["ok"] is False
    assert res_ast["error_code"] == "ERR_SYNTAX_CHECK_FAILED"
    assert "corrupted_mod.py" in str(res_ast.get("bad_file") or "")
    assert not (app_src / "cosmos_mcp" / "corrupted_mod.py").exists()
    assert bootstrap.compute_source_tree_hash(app_src / "cosmos_mcp") == baseline_hash

    # 2d. Active foreground task guard (`ERR_ACTIVE_TASKS_BUSY` when `force_active_tasks=False`)
    atomic_write_json(
        st_root / "state" / "active_tasks.json",
        [{"task_id": "fg-demo-1", "status": "running", "running": True, "started_at": time.time()}],
    )
    monkeypatch.setattr(updater.time, "sleep", lambda _s: None)
    orig_mono = time.monotonic
    ticks = iter([0.0, 1.2, 2.5, 3.4])
    monkeypatch.setattr(updater.time, "monotonic", lambda: next(ticks, orig_mono() + 10.0))
    res_busy = updater.stage_and_apply_update(
        st_root,
        archive_path=good_zip,
        force_active_tasks=False,
        defer_restart_sec=0.0,
    )
    assert res_busy["ok"] is False
    assert res_busy["error_code"] == "ERR_ACTIVE_TASKS_BUSY"
    assert bootstrap.compute_source_tree_hash(app_src / "cosmos_mcp") == baseline_hash


# ---------------------------------------------------------------------------
# Test 3: Dependency pre-check gate (zero `pip` offline pass vs missing dep abort)
# ---------------------------------------------------------------------------


def test_dependency_precheck_zero_pip_offline_and_unsatisfied_abort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    st_root = tmp_path / "state_deps"
    app_src = bootstrap.sync_portable_app_src(st_root, source_src_dir=REPO_ROOT / "src")
    assert app_src is not None
    baseline_hash = bootstrap.compute_source_tree_hash(app_src / "cosmos_mcp")

    # Verify both `tomllib` and Python 3.10 regex fallback produce identical dependency lists
    pyproj_raw = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    specs_tomllib = updater.parse_pyproject_dependency_specs(pyproj_raw, enabled_packs=("browser",))
    monkeypatch.setattr(updater, "tomllib", None)
    specs_regex = updater.parse_pyproject_dependency_specs(pyproj_raw, enabled_packs=("browser",))
    assert specs_regex == specs_tomllib
    assert any(s.startswith("mcp>=") for s in specs_regex)
    assert any(s.startswith("playwright>=") for s in specs_regex)

    # 3a. Satisfied dependencies pass with ZERO `pip` calls
    def _forbid_pip(*_args: Any, **_kwargs: Any) -> Dict[str, object]:
        raise AssertionError("pip_install_with_mirror_fallback must NOT be invoked when deps are satisfied")

    monkeypatch.setattr(updater, "pip_install_with_mirror_fallback", _forbid_pip)
    clean_122_zip, clean_122_sha = _build_synthetic_release_zip(
        tmp_path / "clean_122.zip",
        version="1.2.2",
        wrapper_dir="WebAI2PC-main",
    )
    monkeypatch.setenv("COSMOS_UPDATE_EXPECTED_SHA256", clean_122_sha)
    res_ok = updater.stage_and_apply_update(st_root, archive_path=clean_122_zip, defer_restart_sec=0.0)
    monkeypatch.delenv("COSMOS_UPDATE_EXPECTED_SHA256", raising=False)
    assert res_ok["ok"] is True, res_ok
    assert res_ok["pip_invoked"] is False
    assert res_ok["to_version"] == "1.2.2"
    assert bootstrap.read_package_init_version(app_src / "cosmos_mcp" / "__init__.py") == "1.2.2"
    updated_hash = bootstrap.compute_source_tree_hash(app_src / "cosmos_mcp")
    assert updated_hash != baseline_hash

    # 3b. Unsatisfiable dependency (`nonexistent-cosmos-pkg>=99.0`) aborts cleanly without touching `app_src`
    pip_attempts: List[Sequence[str]] = []

    def _failing_offline_pip(_py: Any, specs: Sequence[str], **_kw: Any) -> Dict[str, object]:
        pip_attempts.append(list(specs))
        return {"ok": False, "source": "failed", "attempts": [{"source": "offline_test", "returncode": 1}]}

    monkeypatch.setattr(updater, "pip_install_with_mirror_fallback", _failing_offline_pip)
    impossible_zip, _ = _build_synthetic_release_zip(
        tmp_path / "impossible_123.zip",
        version="1.2.3",
        extra_pyproject_dep="nonexistent-cosmos-pkg>=99.0",
    )
    res_bad_dep = updater.stage_and_apply_update(st_root, archive_path=impossible_zip, defer_restart_sec=0.0)
    assert res_bad_dep["ok"] is False
    assert res_bad_dep["error_code"] == "ERR_DEPS_UNSATISFIED"
    assert "nonexistent-cosmos-pkg>=99.0" in res_bad_dep["missing_or_outdated"]
    assert len(pip_attempts) == 1
    # Active `app_src` remains completely intact at `1.2.2`
    assert bootstrap.read_package_init_version(app_src / "cosmos_mcp" / "__init__.py") == "1.2.2"
    assert bootstrap.compute_source_tree_hash(app_src / "cosmos_mcp") == updated_hash


# ---------------------------------------------------------------------------
# Test 4: `bootstrap.py:sync_portable_app_src` anti-downgrade lock
# ---------------------------------------------------------------------------


def test_sync_portable_app_src_anti_downgrade_lock(tmp_path: Path) -> None:
    st_root = tmp_path / "state_lock"
    old_portable = tmp_path / "Cosmos-MCP-v1.2.1-extracted"
    old_121_zip, _ = _build_synthetic_release_zip(tmp_path / "v121.zip", version="1.2.1")
    with zipfile.ZipFile(old_121_zip, "r") as zf:
        zf.extractall(old_portable)

    # Initial cold start syncs `1.2.1` into `<state_root>/app_src`
    app_src = bootstrap.sync_portable_app_src(st_root, source_src_dir=old_portable / "src")
    assert app_src is not None
    assert bootstrap.read_package_init_version(app_src / "cosmos_mcp" / "__init__.py") == "1.2.1"

    # One-click self-update upgrades `<state_root>/app_src` to `9.9.9`
    up_999_zip, _ = _build_synthetic_release_zip(tmp_path / "v999.zip", version="9.9.9")
    res_up = updater.stage_and_apply_update(st_root, archive_path=up_999_zip, defer_restart_sec=0.0)
    assert res_up["ok"] is True, res_up
    assert bootstrap.read_package_init_version(app_src / "cosmos_mcp" / "__init__.py") == "9.9.9"
    meta_999 = bootstrap.read_app_src_update_meta(app_src)
    assert meta_999["version"] == "9.9.9"
    hash_999 = bootstrap.compute_source_tree_hash(app_src / "cosmos_mcp")
    assert meta_999["source_tree_hash"] == hash_999

    # Relaunching from old `1.2.1` extracted folder MUST NOT downgrade `app_src` back to `1.2.1`
    synced_after = bootstrap.sync_portable_app_src(st_root, source_src_dir=old_portable / "src")
    assert synced_after == app_src
    assert bootstrap.read_package_init_version(app_src / "cosmos_mcp" / "__init__.py") == "9.9.9"
    assert bootstrap.compute_source_tree_hash(app_src / "cosmos_mcp") == hash_999

    # Manual download of a strictly newer `10.0.0` archive DOES sync forward cleanly
    newer_portable = tmp_path / "Cosmos-MCP-v10.0.0-extracted"
    v10_zip, _ = _build_synthetic_release_zip(tmp_path / "v1000.zip", version="10.0.0")
    with zipfile.ZipFile(v10_zip, "r") as zf:
        zf.extractall(newer_portable)
    bootstrap.sync_portable_app_src(st_root, source_src_dir=newer_portable / "src")
    assert bootstrap.read_package_init_version(app_src / "cosmos_mcp" / "__init__.py") == "10.0.0"


# ---------------------------------------------------------------------------
# Test 5: Real process E2E `worker_hot_reload` (zero tunnel drop) + 15s watchdog rollback
# ---------------------------------------------------------------------------


def test_live_supervisor_worker_hot_reload_zero_tunnel_drop_and_watchdog_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    st_root = tmp_path / "state_e2e"
    ws_dir = tmp_path / "workspace_e2e"
    ws_dir.mkdir(parents=True, exist_ok=True)
    port = _pick_free_port()

    cli.ensure_standalone_state(
        st_root,
        workspace_roots=[str(ws_dir)],
        tunnel_mode="cloudflare",
    )
    cfg_p = daemon.service_cfg_path(st_root)
    cfg_doc = json.loads(cfg_p.read_text(encoding="utf-8"))
    cfg_doc["port"] = port
    cfg_doc["tray_enabled"] = False
    cfg_doc["prefer_quick_tunnel"] = True
    atomic_write_json(cfg_p, cfg_doc)

    app_src = bootstrap.sync_portable_app_src(st_root, source_src_dir=REPO_ROOT / "src")
    assert app_src is not None

    # Stub tunnel supervisors recording every `stop()` call — must remain `0` across hot-reload & rollback
    class _StubQuickTunnelSupervisor:
        is_named_tunnel = False

        def __init__(self, **kwargs: Any) -> None:
            self.pid = os.getpid()
            self.public_url = "https://keep-same-random-url.trycloudflare.com"
            self.last_error = ""
            self.start_calls = 0
            self.stop_calls = 0
            self._on_url = kwargs.get("on_url_change")

        def start(self, **_kwargs: Any) -> str:
            self.start_calls += 1
            return self.public_url

        def ensure_alive(self) -> Optional[str]:
            return self.public_url

        def is_process_alive(self) -> bool:
            return True

        def stop(self) -> None:
            self.stop_calls += 1

    class _PassiveRelayStub:
        def __init__(self, name: str) -> None:
            self.name = name
            self.stop_calls = 0
            self.running = True

        def is_alive(self) -> bool:
            return self.running

        def is_process_alive(self) -> bool:
            return self.running

        def stop(self) -> None:
            self.stop_calls += 1
            self.running = False

    cf_instances: List[_StubQuickTunnelSupervisor] = []

    def _make_cf_stub(**kw: Any) -> _StubQuickTunnelSupervisor:
        inst = _StubQuickTunnelSupervisor(**kw)
        cf_instances.append(inst)
        return inst

    monkeypatch.setattr(daemon, "CloudflaredTunnelSupervisor", _make_cf_stub)
    monkeypatch.setattr(daemon, "ensure_cloudflared_binary", lambda *_a, **_k: Path(sys.executable))
    monkeypatch.setattr(daemon, "wait_tunnel_dns_and_https_ready", lambda u, **_k: {"ok": True, "public_url": u})

    sup = daemon.StandaloneSupervisorLoop(
        state_root=st_root,
        runtime_python=sys.executable,
        port=port,
        mode="cloudflare",
        no_tray=True,
        enforce_singleton=False,
    )
    vps_stub = _PassiveRelayStub("vps")
    sup._vps_supervisor = vps_stub

    sup_thread = threading.Thread(target=sup.run_forever, name="e2e-supervisor-loop", daemon=True)
    sup_thread.start()

    api_srv = _LocalUpdateApiServer()
    try:
        # Wait for initial `1.2.1` `app.py` child + Quick Tunnel URL to become ready
        boot_deadline = time.monotonic() + 18.0
        hz_init: Optional[Dict[str, Any]] = None
        d_before: Dict[str, Any] = {}
        while time.monotonic() < boot_deadline:
            hz_init = daemon.probe_local_healthz(port, timeout_sec=1.5)
            if daemon.daemon_status_path(st_root).is_file():
                with contextlib.suppress(Exception):
                    d_before = json.loads(daemon.daemon_status_path(st_root).read_text(encoding="utf-8"))
            if (
                hz_init is not None
                and hz_init.get("status") == "ok"
                and d_before.get("public_url") == "https://keep-same-random-url.trycloudflare.com"
                and int(d_before.get("server_pid") or 0) > 0
            ):
                break
            time.sleep(0.2)
        assert hz_init is not None, "Initial server child failed to start on local port"
        assert hz_init["version"] == "1.2.1"

        pid_initial = int(d_before["server_pid"])
        rev_initial = str(d_before["server_build_rev"])
        assert pid_initial > 0
        assert len(rev_initial) == 12
        assert len(cf_instances) == 1
        assert d_before["public_url"] == "https://keep-same-random-url.trycloudflare.com"

        # Part A: Stage & apply good `1.2.2` update via local HTTPServer + detached `--handoff-worker`
        good_122_zip, good_122_sha = _build_synthetic_release_zip(
            tmp_path / "rel_122.zip",
            version="1.2.2",
            full_repo=True,
        )
        api_srv.archives["/Cosmos-MCP-v1.2.2.zip"] = good_122_zip.read_bytes()
        api_srv.release_status = 200
        api_srv.release_payload = {
            "tag_name": "v1.2.2",
            "body": "Hot-reload upgrade to 1.2.2",
            "assets": [
                {
                    "name": "Cosmos-MCP-v1.2.2.zip",
                    "browser_download_url": f"{api_srv.base_url}/Cosmos-MCP-v1.2.2.zip",
                    "digest": f"sha256:{good_122_sha}",
                }
            ],
        }
        monkeypatch.setenv("COSMOS_UPDATE_API_BASE", api_srv.base_url)

        upd_sched = updater.stage_and_apply_update(
            st_root,
            channel="release",
            defer_restart_sec=0.25,
            health_timeout_sec=15.0,
        )
        assert upd_sched["ok"] is True, upd_sched
        assert upd_sched["status"] == "handoff_scheduled"
        assert upd_sched["restart_mode"] == "worker_hot_reload"
        assert upd_sched["launcher_changed"] is False
        expected_122_rev = upd_sched["to_revision"]
        assert expected_122_rev != rev_initial

        status_fp = updater.last_update_status_path(st_root)
        wait_succ = time.monotonic() + 18.0
        final_succ: Dict[str, Any] = {}
        while time.monotonic() < wait_succ:
            if status_fp.is_file():
                try:
                    final_succ = json.loads(status_fp.read_text(encoding="utf-8"))
                except Exception:
                    final_succ = {}
                if final_succ.get("status") in ("succeeded", "rolled_back"):
                    break
            time.sleep(0.2)

        assert final_succ.get("status") == "succeeded", final_succ
        hz_after = daemon.probe_local_healthz(port, timeout_sec=2.0)
        assert hz_after is not None
        assert hz_after["version"] == "1.2.2"

        d_after = json.loads(daemon.daemon_status_path(st_root).read_text(encoding="utf-8"))
        pid_122 = int(d_after["server_pid"])
        assert pid_122 > 0 and pid_122 != pid_initial
        assert d_after["consecutive_crashes"] == 0
        assert d_after["server_build_rev"] == expected_122_rev
        assert float(d_after["last_worker_reload_ts"] or 0) > 0
        assert d_after["public_url"] == "https://keep-same-random-url.trycloudflare.com"

        # Zero tunnel disconnects across active tunnel supervisors!
        assert len(cf_instances) == 1
        assert cf_instances[0].stop_calls == 0
        assert vps_stub.stop_calls == 0

        sup_log_txt = (st_root / "logs" / "supervisor.log").read_text(encoding="utf-8", errors="replace")
        assert "graceful worker hot-reload requested; preserving active public tunnels" in sup_log_txt

        # Part B: Verify `trycloudflare.com` ephemeral URL protection when `launcher/daemon.py` changes
        def _touch_daemon_comment(rel_p: str, raw_b: bytes) -> bytes:
            if rel_p == "src/cosmos_mcp/launcher/daemon.py":
                return raw_b + b"\n# benign comment change in launcher layer\n"
            return raw_b

        gw_change_zip, _ = _build_synthetic_release_zip(
            tmp_path / "rel_122_gw.zip",
            version="1.2.2",
            mutate_file_fn=_touch_daemon_comment,
            full_repo=True,
        )
        res_ephem_guard = updater.stage_and_apply_update(
            st_root,
            archive_path=gw_change_zip,
            allow_tunnel_restart=False,
            defer_restart_sec=0.0,
            health_timeout_sec=15.0,
        )
        assert res_ephem_guard["ok"] is True, res_ephem_guard
        assert res_ephem_guard["launcher_changed"] is True
        assert res_ephem_guard["restart_mode"] == "worker_hot_reload"
        assert res_ephem_guard["deferred_daemon_restart_note"] is True
        assert cf_instances[0].stop_calls == 0

        # Part C: Feed a startup-crashing `1.2.3` archive (valid Python AST, raises at `app.py` runtime)
        def _inject_runtime_crash(rel_p: str, raw_b: bytes) -> bytes:
            if rel_p == "src/cosmos_mcp/launcher/app.py":
                return b'raise RuntimeError("simulated startup crash in broken update")\n'
            if rel_p == "src/cosmos_mcp/launcher/daemon.py":
                return raw_b + b"\n# benign comment change in launcher layer\n"
            return raw_b

        broken_123_zip, broken_123_sha = _build_synthetic_release_zip(
            tmp_path / "rel_123_broken.zip",
            version="1.2.3",
            mutate_file_fn=_inject_runtime_crash,
            full_repo=True,
        )
        api_srv.archives["/Cosmos-MCP-v1.2.3.zip"] = broken_123_zip.read_bytes()
        api_srv.release_payload = {
            "tag_name": "v1.2.3",
            "body": "Broken runtime build",
            "assets": [
                {
                    "name": "Cosmos-MCP-v1.2.3.zip",
                    "browser_download_url": f"{api_srv.base_url}/Cosmos-MCP-v1.2.3.zip",
                    "digest": f"sha256:{broken_123_sha}",
                }
            ],
        }

        sched_bad = updater.stage_and_apply_update(
            st_root,
            channel="release",
            defer_restart_sec=0.2,
            health_timeout_sec=15.0,
        )
        assert sched_bad["ok"] is True
        assert sched_bad["status"] == "handoff_scheduled"

        wait_rb = time.monotonic() + 24.0
        final_rb: Dict[str, Any] = {}
        while time.monotonic() < wait_rb:
            if status_fp.is_file():
                try:
                    final_rb = json.loads(status_fp.read_text(encoding="utf-8"))
                except Exception:
                    final_rb = {}
                if final_rb.get("status") == "rolled_back":
                    break
            time.sleep(0.25)

        assert final_rb.get("status") == "rolled_back", final_rb
        assert final_rb.get("rollback_healthz_ok") is True
        assert final_rb.get("restored_version") == "1.2.2"

        # Verify `app_src` rolled back to `1.2.2` and `/healthz` is healthy again with ZERO tunnel drops
        assert bootstrap.read_package_init_version(app_src / "cosmos_mcp" / "__init__.py") == "1.2.2"
        hz_recovered = daemon.probe_local_healthz(port, timeout_sec=2.0)
        assert hz_recovered is not None
        assert hz_recovered["version"] == "1.2.2"
        assert len(cf_instances) == 1
        assert cf_instances[0].stop_calls == 0
        assert vps_stub.stop_calls == 0
    finally:
        api_srv.close()
        atomic_write_text(daemon.daemon_stop_flag_path(st_root), f"STOP:{time.time()}\n")
        sup_thread.join(timeout=8.0)


def _mount_test_dispatcher(ws_dir: Path, st_dir: Path, *, tier: str = "tier3_workspace_dev"):
    from cosmos_mcp.capabilities import clear_registered_providers
    from cosmos_mcp.core.config import LiveRuntimePolicy
    from cosmos_mcp.core.guard import WorkspaceGuard
    from cosmos_mcp.core.proc import ProcessManager
    from cosmos_mcp.protocol.dispatcher import KernelDispatcher
    from cosmos_mcp.protocol.tools import build_core_tools

    clear_registered_providers()
    guard = WorkspaceGuard(
        workspace_roots=[ws_dir],
        restrict_to_workspace=(tier != "tier4_full_power"),
        state_root=st_dir,
        tool_prefix="pc",
    )
    proc_mgr = ProcessManager(guard=guard, state_root=st_dir)
    cfg_p = st_dir / "config" / "service.json"
    policy = LiveRuntimePolicy(
        tier_key=tier,
        workspace_roots=[ws_dir],
        cfg_path=cfg_p,
        state_root=st_dir,
        guard=guard,
    )
    dispatcher = KernelDispatcher(policy)
    specs, hooks = build_core_tools(
        guard=guard,
        proc_mgr=proc_mgr,
        policy=policy,
        policy_getter=lambda: {
            "prefix": policy.eff_prefix,
            "tier": policy.short_tier_code,
            "workspace": policy.workspace,
            "state_root": str(st_dir),
            "toolset_profile": policy.toolset_profile,
            "python_path": policy.python_path,
            "exposed_tools": [sp.base_name for sp in dispatcher.active_tool_specs()],
        },
    )
    dispatcher.register_tools(specs)
    for hk in hooks:
        dispatcher.add_execution_hook(hk)
    return policy, dispatcher


def test_mcp_tool_count_16_and_readonly_update_checks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio

    ws_dir = tmp_path / "ws"
    ws_dir.mkdir(parents=True)
    st_dir = tmp_path / "state"
    bootstrap.sync_portable_app_src(st_dir, source_src_dir=REPO_ROOT / "src")

    status_fp = updater.last_update_status_path(st_dir, prefix="pc")
    status_fp.parent.mkdir(parents=True, exist_ok=True)
    status_fp.write_text(
        json.dumps(
            {
                "ok": True,
                "status": "succeeded",
                "from_version": "1.2.0",
                "to_version": "1.2.1",
                "restart_mode": "worker_hot_reload",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    api_srv = _LocalUpdateApiServer()
    api_srv.release_payload = {
        "tag_name": "v1.2.2",
        "target_commitish": "1234567890abcdef1234567890abcdef12345678",
        "body": "Stub release v1.2.2 for MCP readonly check",
        "assets": [
            {
                "name": "Cosmos-MCP-v1.2.2.zip",
                "browser_download_url": f"{api_srv.base_url}/Cosmos-MCP-v1.2.2.zip",
            }
        ],
    }
    monkeypatch.setenv("COSMOS_UPDATE_API_BASE", api_srv.base_url)
    monkeypatch.delenv("COSMOS_UPDATE_ARCHIVE_URL", raising=False)
    monkeypatch.delenv("COSMOS_UPDATE_MIRROR", raising=False)
    monkeypatch.delenv("COSMOS_UPDATE_EXPECTED_SHA256", raising=False)

    try:
        policy, dispatcher = _mount_test_dispatcher(ws_dir, st_dir, tier="tier3_workspace_dev")
        l3_tools = dispatcher.list_tool_dicts()
        assert len(l3_tools) == 16
        by_name = {t["name"]: t for t in l3_tools}
        assert "check_update" in by_name["pc_get_status"]["inputSchema"]["properties"]
        bg_enum = by_name["pc_bg_command"]["inputSchema"]["properties"]["action"]["enum"]
        assert "check_update" in bg_enum and "self_update" in bg_enum

        # Switch to L1 (`tier1_readonly`) and verify both `get_status(check_update=True)` and `bg_command(action="check_update")`
        policy.update_config({"permission_tier": "tier1_readonly"})

        res_no_net, _ = asyncio.run(dispatcher.call_tool_raw("pc_get_status", {}, readonly_only=True))
        assert res_no_net.get("ok") is True
        assert "update_check" not in res_no_net
        assert res_no_net.get("last_update_status", {}).get("to_version") == "1.2.1"

        res_status_chk, _ = asyncio.run(
            dispatcher.call_tool_raw("pc_get_status", {"check_update": True}, readonly_only=True)
        )
        assert res_status_chk.get("ok") is True
        uc = res_status_chk.get("update_check") or {}
        assert uc.get("ok") is True
        assert uc.get("latest_version") == "1.2.2"
        assert uc.get("update_available") is True

        res_bg_ro, _ = asyncio.run(
            dispatcher.call_tool_raw(
                "pc_bg_command",
                {"action": "check_update", "channel": "release"},
                readonly_only=True,
            )
        )
        assert res_bg_ro.get("ok") is True, res_bg_ro
        assert res_bg_ro.get("latest_version") == "1.2.2"
        assert res_bg_ro.get("update_available") is True

        res_bg_l1, _ = asyncio.run(
            dispatcher.call_tool_raw(
                "pc_bg_command",
                {"action": "check_update", "channel": "release"},
                readonly_only=False,
            )
        )
        assert res_bg_l1.get("ok") is True, res_bg_l1
        assert res_bg_l1.get("latest_version") == "1.2.2"
    finally:
        api_srv.close()


def test_mcp_bg_command_self_update_permission_gates_and_l3_l4_exec(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio

    ws_dir = tmp_path / "ws"
    ws_dir.mkdir(parents=True)
    st_dir = tmp_path / "state"
    policy, dispatcher = _mount_test_dispatcher(ws_dir, st_dir, tier="tier1_readonly")

    calls: List[Dict[str, Any]] = []

    def _fake_stage_and_apply(state_root: Path, **kwargs: Any) -> Dict[str, Any]:
        calls.append({"state_root": str(state_root), **kwargs})
        return {
            "ok": True,
            "status": "handoff_scheduled",
            "defer_restart_sec": kwargs.get("defer_restart_sec"),
            "channel": kwargs.get("channel"),
        }

    monkeypatch.setattr(updater, "stage_and_apply_update", _fake_stage_and_apply)

    # 1) L1 blocked
    r_l1, _ = asyncio.run(dispatcher.call_tool_raw("pc_bg_command", {"action": "self_update"}))
    assert r_l1.get("ok") is False
    assert r_l1.get("blocked_by_permission_tier") is True
    assert len(calls) == 0

    # 2) L2 blocked
    policy.update_config({"permission_tier": "tier2_workspace_edit"})
    r_l2, _ = asyncio.run(dispatcher.call_tool_raw("pc_bg_command", {"action": "self_update"}))
    assert r_l2.get("ok") is False
    assert r_l2.get("blocked_by_permission_tier") is True
    assert len(calls) == 0

    # 3) L3 on `/mcp/readonly` (`readonly_only=True`) blocked
    policy.update_config({"permission_tier": "tier3_workspace_dev"})
    r_ro, _ = asyncio.run(
        dispatcher.call_tool_raw("pc_bg_command", {"action": "self_update"}, readonly_only=True)
    )
    assert r_ro.get("ok") is False
    assert r_ro.get("blocked_by_readonly_endpoint") is True
    assert len(calls) == 0

    # 4) L3 allowed -> calls `stage_and_apply_update(..., defer_restart_sec=1.5)`
    r_l3, _ = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_bg_command",
            {
                "action": "self_update",
                "channel": "main",
                "allow_tunnel_restart": True,
                "force_active_tasks": True,
            },
        )
    )
    assert r_l3.get("ok") is True, r_l3
    assert len(calls) == 1
    assert calls[0]["channel"] == "main"
    assert calls[0]["allow_tunnel_restart"] is True
    assert calls[0]["force_active_tasks"] is True
    assert calls[0]["defer_restart_sec"] == 1.5

    # 5) L4 allowed
    policy.update_config({"permission_tier": "tier4_full_power"})
    r_l4, _ = asyncio.run(dispatcher.call_tool_raw("pc_bg_command", {"action": "self_update"}))
    assert r_l4.get("ok") is True, r_l4
    assert len(calls) == 2
    assert calls[1]["channel"] == "release"
    assert calls[1]["defer_restart_sec"] == 1.5


def test_cli_update_check_and_local_archive_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from cosmos_mcp.launcher import cli

    st_dir = tmp_path / "cli_state"
    bootstrap.sync_portable_app_src(st_dir, source_src_dir=REPO_ROOT / "src")

    api_srv = _LocalUpdateApiServer()
    api_srv.release_payload = {
        "tag_name": "v1.2.2",
        "target_commitish": "abcdef0123456789abcdef0123456789abcdef01",
        "body": "CLI update check stub v1.2.2",
        "assets": [
            {
                "name": "Cosmos-MCP-v1.2.2.zip",
                "browser_download_url": f"{api_srv.base_url}/Cosmos-MCP-v1.2.2.zip",
            }
        ],
    }
    monkeypatch.setenv("COSMOS_UPDATE_API_BASE", api_srv.base_url)
    monkeypatch.delenv("COSMOS_UPDATE_ARCHIVE_URL", raising=False)
    monkeypatch.delenv("COSMOS_UPDATE_MIRROR", raising=False)
    monkeypatch.delenv("COSMOS_UPDATE_EXPECTED_SHA256", raising=False)

    try:
        rc_chk = cli.main(["update", "--check", "--json", "--state-dir", str(st_dir), "--prefix", "pc"])
        assert rc_chk == 0
        chk_doc = json.loads(capsys.readouterr().out)
        assert chk_doc["ok"] is True
        assert chk_doc["latest_version"] == "1.2.2"
        assert chk_doc["update_available"] is True

        local_zip, _ = _build_synthetic_release_zip(tmp_path / "cli_upd_122.zip", version="1.2.2")
        rc_apply = cli.main(
            [
                "update",
                "--archive",
                str(local_zip),
                "--json",
                "--state-dir",
                str(st_dir),
                "--prefix",
                "pc",
            ]
        )
        assert rc_apply == 0
        apply_doc = json.loads(capsys.readouterr().out)
        assert apply_doc["ok"] is True
        assert apply_doc["to_version"] == "1.2.2"
        assert apply_doc["restart_mode"] == "offline_updated"
        assert bootstrap.read_package_init_version(st_dir / "app_src" / "cosmos_mcp" / "__init__.py") == "1.2.2"

        bat_txt = (REPO_ROOT / "一键启动_Cosmos_MCP.bat").read_text(encoding="utf-8")
        sh_txt = (REPO_ROOT / "start_cosmos_mcp.sh").read_text(encoding="utf-8")
        assert "vps-caddy-snippet update " in bat_txt
        assert "vps-caddy-snippet|update|" in sh_txt
    finally:
        api_srv.close()

