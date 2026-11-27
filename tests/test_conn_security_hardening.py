"""Connection, Guard, FS Transaction & Sandbox Hook Security Hardening Regression Suite.

Covers:
1. `BrowserPackPlugin` real-time `is_remote` binding (`launcher/app.py` & `packs/browser.py`),
   remote loopback/RFC1918 (`127.0.0.1:<port>`, `10.*`, `172.16..31.*`, `192.168.*`) SSRF blocking,
   per-call `worker.active_ssrf_ctx["is_remote_session"]` refresh, and local dev compatibility (`False`);
2. Read-only `pc_get_status(open_page=...)` popup suppression in remote `L1` (`not policy.allow_edit`)
   and `/mcp/readonly` (`readonly_only`), while preserving `/mcp` (`L3`/`L4`) setup UX;
3. `WorkspaceGuard` write-blocked prefixes (`<state_root>/app_src`, `.undo_history`, `browser_profile`),
   `L4` enforcement of explicit `readonly_workspace_roots`, and `cmcp_*` token redaction;
4. `core/fs_tx.py` write-access & `allowed_roots` gates across `restore_trash_item`, `undo_last_edit`,
   and `redo` (`move`/`rename`/`edit`/`create`), preserving `guard=None` legacy compatibility;
5. `core/sandbox_hook.py` isolation of `.huggingface/token` & `huggingface/stored_tokens` (preserving
   normal model weight cache read-only access) and blocking out-of-workspace `os.chdir` in `batch_probe`;
6. Pure Python stdlib AST gate on `core/` and Python 3.10 f-string `{...}` backslash-free discipline.
"""
from __future__ import annotations

import ast
import asyncio
import ctypes
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace
from typing import Any, Dict, List, Tuple
import webbrowser

import pytest

if sys.platform == "win32":
    ctypes.windll.kernel32.SetErrorMode(0x8003)

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from cosmos_mcp.capabilities import clear_registered_providers  # noqa: E402
from cosmos_mcp.core import fs as file_ops  # noqa: E402
from cosmos_mcp.core import fs_tx  # noqa: E402
from cosmos_mcp.core.config import ensure_initialized  # noqa: E402
from cosmos_mcp.core.guard import CREATE_NO_WINDOW, DEFAULT_GUARD, WorkspaceGuard  # noqa: E402
from cosmos_mcp.core.proc import ProcessManager  # noqa: E402
from cosmos_mcp.core.sandbox_hook import L3_SITECUSTOMIZE_SOURCE  # noqa: E402
from cosmos_mcp.launcher.app import create_standalone_app  # noqa: E402
from cosmos_mcp.packs import browser as browser_mod  # noqa: E402
from cosmos_mcp.packs.browser import (  # noqa: E402
    BrowserPackPlugin,
    _private_lan_cdp_block_patterns,
    validate_outbound_http_url,
)
from cosmos_mcp.protocol.transport import RequestTransportContext, _REQUEST_TRANSPORT_CTX  # noqa: E402

_INITIAL_GUARD_SNAPSHOT: Dict[str, Any] = dict(DEFAULT_GUARD.__dict__)

TOUCHED_REPO_FILES: Tuple[str, ...] = (
    "src/cosmos_mcp/launcher/app.py",
    "src/cosmos_mcp/packs/browser.py",
    "src/cosmos_mcp/protocol/tools.py",
    "src/cosmos_mcp/core/guard.py",
    "src/cosmos_mcp/core/fs_tx.py",
    "src/cosmos_mcp/core/sandbox_hook.py",
    "tests/test_conn_security_hardening.py",
)

CORE_HARDENED_FILES: Tuple[str, ...] = (
    "src/cosmos_mcp/core/guard.py",
    "src/cosmos_mcp/core/fs_tx.py",
    "src/cosmos_mcp/core/sandbox_hook.py",
)


@pytest.fixture(autouse=True)
def _isolate_global_state() -> Any:
    saved = dict(_INITIAL_GUARD_SNAPSHOT)
    try:
        yield
    finally:
        clear_registered_providers()
        DEFAULT_GUARD.__dict__.clear()
        DEFAULT_GUARD.__dict__.update(saved)


def _assert_no_py310_fstring_backslash(src_text: str, rel_path: str) -> None:
    # On Python < 3.12, `ast.parse` itself raises SyntaxError if any f-string `{...}` expression
    # contains a backslash (whereas `FormattedValue.lineno`/`col_offset` points to the outer JoinedStr).
    tree = ast.parse(src_text, filename=rel_path)
    if sys.version_info < (3, 12):
        return
    bs = chr(92)
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    seg = ast.get_source_segment(src_text, part) or ""
                    assert bs not in seg, f"Backslash in f-string expression at {rel_path}:{part.lineno}: {seg}"


def test_core_stdlib_purity_and_fstring_compat_gate() -> None:
    stdlib_names = set(getattr(sys, "stdlib_module_names", ())) | {
        "__future__",
        "tomllib",
        "msvcrt",
        "fcntl",
        "winreg",
    }
    for rel in TOUCHED_REPO_FILES:
        src = (REPO_ROOT / rel).read_text(encoding="utf-8")
        _assert_no_py310_fstring_backslash(src, rel)

    for rel in CORE_HARDENED_FILES:
        src = (REPO_ROOT / rel).read_text(encoding="utf-8")
        tree = ast.parse(src, filename=rel)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top_pkg = alias.name.split(".")[0]
                    if top_pkg == "cosmos_mcp":
                        assert alias.name.startswith("cosmos_mcp.core"), f"Forbidden import {alias.name} in {rel}"
                    else:
                        assert top_pkg in stdlib_names, f"Non-stdlib import {alias.name} in {rel}"
            elif isinstance(node, ast.ImportFrom) and (node.level or 0) == 0:
                mod_name = node.module or ""
                top_pkg = mod_name.split(".")[0]
                if top_pkg == "cosmos_mcp":
                    assert mod_name.startswith("cosmos_mcp.core"), f"Forbidden from-import {mod_name} in {rel}"
                else:
                    assert top_pkg in stdlib_names, f"Non-stdlib from-import {mod_name} in {rel}"


def test_browser_pack_remote_ssrf_isolation_and_worker_ctx_refresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_dir = tmp_path / "ws_browser"
    st_dir = tmp_path / "st_browser"
    ws_dir.mkdir(parents=True)
    port = 18741
    pub_url = "https://secfix3-gw.workers.dev"

    ensure_initialized(
        product_root=st_dir,
        public_url=pub_url,
        port=port,
        cli_state_dir=str(st_dir),
        tier_key="tier3_workspace_dev",
        prefix="pc",
        workspace_roots=[ws_dir],
    )
    app = create_standalone_app(
        workspace=str(ws_dir),
        state_dir=str(st_dir),
        port=port,
        public_url=pub_url,
        tunnel_mode="workers_dev",
    )
    dispatcher = app.state.dispatcher
    policy = app.state.policy
    policy.apply_direct(enabled_packs=["browser"])

    browser_pk = dispatcher._packs["browser"]
    assert isinstance(browser_pk, BrowserPackPlugin)
    assert callable(browser_pk.is_remote_session_fn)

    # 1) Outside remote transport context (local dev / direct unit test): `_is_remote_session()` stays False
    assert browser_pk._is_remote_session() is False
    standalone_pk = BrowserPackPlugin(guard=app.state.policy.guard, state_root=st_dir, mcp_port=port)
    assert standalone_pk._is_remote_session() is False
    assert (
        validate_outbound_http_url(
            "http://127.0.0.1:3000/dev",
            mcp_port=port,
            is_remote_session=browser_pk._is_remote_session(),
            allow_loopback_dev=True,
        )
        == "http://127.0.0.1:3000/dev"
    )

    # CDP/Playwright blocked pattern list must cover 127.*, 10.*, 192.168.*, and 172.16..31.*
    cdp_pats = set(_private_lan_cdp_block_patterns())
    for expected_pat in (
        "http://127.*",
        "http://10.*",
        "http://192.168.*",
        "http://172.16.*",
        "http://172.31.*",
        "https://172.24.*",
    ):
        assert expected_pat in cdp_pats

    # 2) Inside remote MCP transport context (`is_remote_session=True`):
    #    - With `allow_loopback_dev=True` (default in L2..L4), user dev servers (`127.0.0.1:3000`, `localhost:5173`),
    #      LAN (`192.168.*`, `10.*`), and authorized workspace `file://` HTML previews are ALLOWED!
    #    - Control plane (`127.0.0.1:{port}`, `mcp_public_url`), `0.0.0.0`, cloud metadata (`169.254.169.254`),
    #      and `<state_root>/secrets` `file://` remain unbypassably BLOCKED!
    #    - Toggling `allow_loopback_dev=False` (or switching to `tier1_readonly`) cleanly blocks loopback/LAN/`file://`.
    preview_html = ws_dir / "preview.html"
    preview_html.write_text("<h1>Dev Preview</h1>", encoding="utf-8")
    state_secret_file = st_dir / "secrets" / "auth.json"
    bad_exe_file = ws_dir / "payload.exe"
    bad_exe_file.write_bytes(b"MZ")

    monkeypatch.setattr(browser_mod, "find_system_chromium_binary", lambda: "fake_chromium.exe")
    tok_rem = _REQUEST_TRANSPORT_CTX.set(RequestTransportContext(is_remote=True, public_url=pub_url))
    try:
        assert browser_pk._is_remote_session() is True
        assert browser_pk._effective_allow_loopback_dev() is True
        for allowed_dev_url in (
            "http://127.0.0.1:3000/admin",
            "http://localhost:5173/",
            "http://192.168.1.1/",
            "http://10.0.0.8:8080/",
            preview_html.as_uri(),
        ):
            checked_u = validate_outbound_http_url(
                allowed_dev_url,
                mcp_port=port,
                mcp_public_url=pub_url,
                is_remote_session=True,
                allow_loopback_dev=browser_pk._effective_allow_loopback_dev(),
                guard=policy.guard,
            )
            assert checked_u == allowed_dev_url, allowed_dev_url

        # Control plane, cloud metadata, 0.0.0.0, state secrets & executable `file://` are ALWAYS blocked
        for hard_blocked_url in (
            f"http://127.0.0.1:{port}/api/studio/state",
            f"http://localhost:{port}/",
            f"{pub_url}/api/studio/state",
            "http://0.0.0.0:3000/",
            "http://169.254.169.254/latest/meta-data/",
            state_secret_file.as_uri(),
            bad_exe_file.as_uri(),
        ):
            res_hb, _ = asyncio.run(
                dispatcher.call_tool_raw("pc_browser_use", {"action": "open", "url": hard_blocked_url})
            )
            assert res_hb["ok"] is False, (hard_blocked_url, res_hb)
            assert res_hb.get("blocked_by_ssrf_guard") is True

        # User toggles `allow_loopback_dev=False` -> loopback, LAN, and `file://` are blocked immediately
        policy.apply_direct(allow_loopback_dev=False)
        assert browser_pk._effective_allow_loopback_dev() is False
        for blocked_lan_url in (
            "http://127.0.0.1:3000/admin",
            "http://localhost:5173/",
            "http://192.168.1.1/",
            "http://10.0.0.8:8080/",
            "http://172.16.0.1/",
            preview_html.as_uri(),
        ):
            res_b, _ = asyncio.run(
                dispatcher.call_tool_raw("pc_browser_use", {"action": "open", "url": blocked_lan_url})
            )
            assert res_b["ok"] is False, (blocked_lan_url, res_b)
            assert res_b.get("blocked_by_ssrf_guard") is True

        # Re-enable `allow_loopback_dev=True`, verify L1 read-only mode still auto-disables local preview
        policy.apply_direct(allow_loopback_dev=True, tier_key="tier1_readonly")
        assert browser_pk._effective_allow_loopback_dev() is False
        policy.apply_direct(tier_key="tier3_workspace_dev", enabled_packs=["browser"])
        assert browser_pk._effective_allow_loopback_dev() is True
    finally:
        _REQUEST_TRANSPORT_CTX.reset(tok_rem)

    # 3) Verify worker `_task` refreshes `worker.active_ssrf_ctx["is_remote_session"]` right before navigation/page access
    seen_worker_remote_flags: List[bool] = []

    class _FakePage:
        url = "about:blank"

        def title(self) -> str:
            return "Blank"

        def evaluate(self, _script: str, _arg: Any = None) -> Dict[str, Any]:
            return {"url": "about:blank", "title": "Blank", "elements": []}

        def wait_for_timeout(self, _ms: int) -> None:
            return None

    class _FakeWorker:
        active_backend = "fake"

        def __init__(self) -> None:
            self.active_ssrf_ctx: Dict[str, Any] = {"is_remote_session": False}
            self.pw_downloads: List[Dict[str, Any]] = []

        def submit(self, task_fn: Any, timeout_sec: float = 10.0) -> Any:
            _ = timeout_sec
            # Simulate a concurrent call having mutated `active_ssrf_ctx` right before `_task` runs on worker thread
            self.active_ssrf_ctx = {"is_remote_session": not bool(self.active_ssrf_ctx.get("is_remote_session"))}

            def _ensure_page() -> Tuple[Any, Any]:
                seen_worker_remote_flags.append(bool(self.active_ssrf_ctx.get("is_remote_session")))
                return SimpleNamespace(pages=[]), _FakePage()

            return task_fn((_ensure_page, lambda: False, lambda _p: None))

    fake_worker = _FakeWorker()
    monkeypatch.setattr(browser_pk, "_get_or_create_worker", lambda _prof: fake_worker)

    tok_r2 = _REQUEST_TRANSPORT_CTX.set(RequestTransportContext(is_remote=True))
    try:
        snap_rem = browser_pk.browser_use(action="snapshot")
        assert snap_rem["ok"] is True
    finally:
        _REQUEST_TRANSPORT_CTX.reset(tok_r2)

    tok_l2 = _REQUEST_TRANSPORT_CTX.set(RequestTransportContext(is_remote=False))
    try:
        snap_loc = browser_pk.browser_use(action="snapshot")
        assert snap_loc["ok"] is True
    finally:
        _REQUEST_TRANSPORT_CTX.reset(tok_l2)

    assert seen_worker_remote_flags == [True, False]

    # 4) Verify macOS `.local` mDNS immunity: `_local_machine_ips(ttl_sec=0)` never calls slow `socket.getaddrinfo`
    #    on Darwin while still blocking `http://<host_lan_ip>:<mcp_port>/` via `ifconfig` interface enumeration.
    def _forbidden_getaddrinfo(*_a: Any, **_kw: Any) -> Any:
        raise AssertionError("socket.getaddrinfo must not be called for local host IPs on Darwin")

    monkeypatch.setattr(browser_mod.sys, "platform", "darwin")
    monkeypatch.setattr(browser_mod.socket, "getaddrinfo", _forbidden_getaddrinfo)
    monkeypatch.setattr(browser_mod.shutil, "which", lambda name: "/sbin/ifconfig" if name == "ifconfig" else None)
    monkeypatch.setattr(
        browser_mod.subprocess,
        "run",
        lambda *_a, **_kw: SimpleNamespace(
            returncode=0,
            stdout="lo0: flags=8049<UP,LOOPBACK>\n\tinet 127.0.0.1 netmask 0xff000000\nen0: flags=8863<UP>\n\tinet 192.168.77.88 netmask 0xffffff00\n",
        ),
    )
    browser_mod._LOCAL_MACHINE_IPS_CACHE = (0.0, set())
    darwin_ips = browser_mod._local_machine_ips(ttl_sec=0.0)
    assert "192.168.77.88" in darwin_ips
    with pytest.raises(PermissionError, match="protected local MCP/control port"):
        validate_outbound_http_url("http://192.168.77.88:18741/api/studio/state", mcp_port=18741, allow_loopback_dev=True)
    assert (
        validate_outbound_http_url("http://192.168.77.88:3000/", mcp_port=18741, allow_loopback_dev=True)
        == "http://192.168.77.88:3000/"
    )
    browser_mod._LOCAL_MACHINE_IPS_CACHE = (0.0, set())


def test_get_status_open_page_readonly_mode_blocks_popup_preserves_l3_l4(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("COSMOS_DISABLE_BROWSER_OPEN", raising=False)
    if sys.platform.startswith("linux"):
        monkeypatch.setenv("DISPLAY", ":99")

    opened_urls: List[str] = []
    monkeypatch.setattr(webbrowser, "open", lambda u, new=2, autoraise=True: (opened_urls.append(u), True)[1])

    port = 18742
    pub_url = "https://secfix3-status.workers.dev"
    ws_dir = tmp_path / "ws_status"
    st_dir = tmp_path / "st_status"
    ws_dir.mkdir(parents=True)

    ensure_initialized(
        product_root=st_dir,
        public_url=pub_url,
        port=port,
        cli_state_dir=str(st_dir),
        tier_key="tier3_workspace_dev",
        prefix="pc",
        workspace_roots=[ws_dir],
    )
    app = create_standalone_app(
        workspace=str(ws_dir),
        state_dir=str(st_dir),
        port=port,
        public_url=pub_url,
        tunnel_mode="workers_dev",
    )
    dispatcher = app.state.dispatcher
    policy = app.state.policy
    expected_gw_url = f"http://127.0.0.1:{port}/#settings/gateways"

    # 1) Normal `/mcp` in L3 and L4 opens `#settings/gateways` smoothly
    tok_rem = _REQUEST_TRANSPORT_CTX.set(RequestTransportContext(is_remote=True, public_url=pub_url))
    try:
        for active_tier in ("tier3_workspace_dev", "tier4_full_power"):
            opened_urls.clear()
            policy.apply_direct(tier_key=active_tier)
            res_ok, is_err = asyncio.run(
                dispatcher.call_tool_raw("pc_get_status", {"open_page": "gateways"})
            )
            assert not is_err and res_ok["ok"] is True
            assert res_ok["opened_in_browser"] is True
            assert res_ok["target_url"] == expected_gw_url
            assert opened_urls == [expected_gw_url]

        # 2) Remote session in L1 read-only tier (`not policy.allow_edit`): NO host popup, returns `target_url` + hint
        opened_urls.clear()
        policy.apply_direct(tier_key="tier1_readonly")
        assert policy.allow_edit is False
        res_l1, err_l1 = asyncio.run(
            dispatcher.call_tool_raw("pc_get_status", {"open_page": "gateways"})
        )
        assert not err_l1 and res_l1["ok"] is True
        assert res_l1["opened_in_browser"] is False
        assert res_l1["target_url"] == expected_gw_url
        assert expected_gw_url in str(res_l1.get("open_page_hint") or "")
        assert opened_urls == []
    finally:
        _REQUEST_TRANSPORT_CTX.reset(tok_rem)

    # 3) Read-only endpoint (`readonly_only=True` or ctx.readonly_only=True) in L3/L4 also suppresses popup
    policy.apply_direct(tier_key="tier3_workspace_dev")
    opened_urls.clear()
    res_ro_ep, err_ro_ep = asyncio.run(
        dispatcher.call_tool_raw("pc_get_status", {"open_page": "gateways"}, readonly_only=True)
    )
    assert not err_ro_ep and res_ro_ep["opened_in_browser"] is False
    assert res_ro_ep["open_blocked_reason"] == "readonly_endpoint"
    assert res_ro_ep["target_url"] == expected_gw_url
    assert expected_gw_url in str(res_ro_ep.get("open_page_hint") or "")
    assert opened_urls == []

    tok_ro_ctx = _REQUEST_TRANSPORT_CTX.set(
        SimpleNamespace(is_remote=True, readonly_only=True, scopes=None)  # type: ignore[arg-type]
    )
    try:
        res_ctx_ro, _ = asyncio.run(
            dispatcher.call_tool_raw("pc_get_status", {"open_page": "gateways"})
        )
        assert res_ctx_ro["opened_in_browser"] is False
        assert res_ctx_ro["open_blocked_reason"] == "readonly_endpoint"
        assert res_ctx_ro["target_url"] == expected_gw_url
        assert opened_urls == []
    finally:
        _REQUEST_TRANSPORT_CTX.reset(tok_ro_ctx)


def test_guard_write_blocked_prefixes_l4_readonly_roots_and_cmcp_redact(tmp_path: Path) -> None:
    ws_dir = tmp_path / "workspace_with_nested_state"
    nested_state = ws_dir / ".local_state_root"
    ro_dir = tmp_path / "explicit_readonly_ref"
    rw_sub = ro_dir / "writable_subproject"
    ws_dir.mkdir(parents=True)
    nested_state.mkdir(parents=True)
    rw_sub.mkdir(parents=True)

    # 1) `<state_root>/app_src`, `<state_root>/.undo_history`, `<state_root>/browser_profile` write-protected in L3 & L4
    for tier_code in ("L3", "L4"):
        g = WorkspaceGuard(
            workspace_roots=[ws_dir, rw_sub],
            readonly_workspace_roots=[ro_dir],
            restrict_to_workspace=(tier_code != "L4"),
            tier=tier_code,
            state_root=nested_state,
        )
        for protected_rel in (
            nested_state / "app_src" / "cosmos_mcp" / "injected.py",
            nested_state / ".undo_history" / "index.json",
            nested_state / "browser_profile" / "Default" / "Preferences",
        ):
            err_w = g.check_path_access(protected_rel, mode="write")
            assert err_w is not None and "ANTI-TAMPER" in err_w, (tier_code, protected_rel, err_w)

        # Normal workspace file remains writable
        assert g.check_path_access(ws_dir / "main.py", mode="write") is None

        # 2) Explicit `readonly_workspace_roots` blocks writes across both L3 and L4 (honoring user's explicit read-only mount)
        assert g.check_path_access(ro_dir / "reference.md", mode="read") is None
        ro_err = g.check_path_access(ro_dir / "reference.md", mode="write")
        assert ro_err is not None and "ERR_READONLY_WORKSPACE" in ro_err
        # Longest-prefix writable child under `ro_dir` remains writable
        assert g.check_path_access(rw_sub / "editable.py", mode="write") is None

    # 3) `SECRET_REDACT_PATTERNS` redacts `cmcp_[A-Za-z0-9_\-]{16,}` connector tokens
    g_redact = WorkspaceGuard(
        readonly_workspace_roots=[ro_dir],
        restrict_to_workspace=True,
        tier="L3",
        state_root=nested_state,
    )
    raw_secret = "cmcp_9f8e7d6c5b4a3210_Token-XYZ987"
    redacted = g_redact.redact_sensitive_output(f"Authorization: Bearer {raw_secret} active")
    assert raw_secret not in redacted
    assert "[REDACTED_MCP_TOKEN]" in redacted


def test_fs_tx_restore_undo_redo_write_gates_and_guardless_compat(tmp_path: Path) -> None:
    ws_a = tmp_path / "ws_a"
    ws_b = tmp_path / "ws_b"
    st_dir = tmp_path / "state_tx"
    ws_a.mkdir(parents=True)
    ws_b.mkdir(parents=True)
    st_dir.mkdir(parents=True)

    # 1) Legacy `guard=None` compatibility on `undo_last_edit` and `restore_trash_item`
    legacy_f = ws_a / "legacy.txt"
    legacy_f.write_text("v1", encoding="utf-8")
    fs_tx.save_undo_snapshot(legacy_f, workspace_root=ws_a, state_root=st_dir)
    legacy_f.write_text("v2", encoding="utf-8")
    u_leg = fs_tx.undo_last_edit(legacy_f, action="undo", workspace_root=ws_a, state_root=st_dir)
    assert u_leg["ok"] is True and legacy_f.read_text(encoding="utf-8") == "v1"
    r_leg = fs_tx.undo_last_edit(legacy_f, action="redo", workspace_root=ws_a, state_root=st_dir)
    assert r_leg["ok"] is True and legacy_f.read_text(encoding="utf-8") == "v2"
    tr_leg = fs_tx.safe_trash_file(legacy_f, workspace_root=ws_a, state_root=st_dir)
    assert tr_leg["ok"] is True and not legacy_f.exists()
    rs_leg = fs_tx.restore_trash_item(
        action="restore",
        trash_id=tr_leg["trash_id"],
        workspace_root=ws_a,
        state_root=st_dir,
    )
    assert rs_leg["ok"] is True and legacy_f.read_text(encoding="utf-8") == "v2"

    # 2) `redo` (`move`/`rename` branch) blocks moving from `src_r` after `ws_b` is removed from `workspace_roots`
    g_both = WorkspaceGuard(workspace_roots=[ws_a, ws_b], state_root=st_dir, tier="L3")
    src_b = ws_b / "from_b.txt"
    dst_a = ws_a / "into_a.txt"
    src_b.write_text("confidential-b", encoding="utf-8")

    mv_res = file_ops.manage_files(g_both, action="move", path=src_b, destination=dst_a)
    assert mv_res["ok"] is True and dst_a.is_file() and not src_b.exists()
    un_mv = file_ops.manage_files(g_both, action="undo", path=dst_a)
    assert un_mv["ok"] is True and src_b.is_file() and not dst_a.exists()

    # Narrow allowed roots to `[ws_a]` only -> `redo` must NOT pull `src_b` out of unpermitted `ws_b`!
    g_only_a = WorkspaceGuard(workspace_roots=[ws_a], state_root=st_dir, tier="L3")
    redo_blocked = file_ops.manage_files(g_only_a, action="redo", path=dst_a)
    assert redo_blocked["ok"] is False
    assert redo_blocked.get("blocked_by_guardrail") is True
    assert src_b.is_file() and src_b.read_text(encoding="utf-8") == "confidential-b"
    assert not dst_a.exists()

    # 3) Downgrading `ws_b` to `readonly_workspace_roots` blocks `undo(path="")`, `redo(path="")`, and `restore("latest")`
    edit_b = ws_b / "ro_target.txt"
    edit_b.write_text("before", encoding="utf-8")
    assert file_ops.edit_file(edit_b, old_text="before", new_text="after_1", guard=g_both)["ok"] is True
    assert file_ops.edit_file(edit_b, old_text="after_1", new_text="after_2", guard=g_both)["ok"] is True
    # Undo once while still writable so both an undo entry AND a redo entry exist for `edit_b`
    assert file_ops.manage_files(g_both, action="undo", path=edit_b)["ok"] is True
    assert edit_b.read_text(encoding="utf-8") == "after_1"

    trash_b = ws_b / "ro_trashed.txt"
    trash_b.write_text("trashed-body", encoding="utf-8")
    tr_b = file_ops.manage_files(g_both, action="trash", path=trash_b)
    assert tr_b["ok"] is True and not trash_b.exists()

    # Now mount `ws_b` as read-only in workspace-restricted tiers (`L2` and `L3`)
    for tier_ro_test in ("L2", "L3"):
        g_ro_b = WorkspaceGuard(
            workspace_roots=[ws_a],
            readonly_workspace_roots=[ws_b],
            restrict_to_workspace=True,
            state_root=st_dir,
            tier=tier_ro_test,
        )
        u_ro = file_ops.manage_files(g_ro_b, action="undo", path="")
        assert u_ro["ok"] is False and u_ro.get("blocked_by_guardrail") is True
        assert not trash_b.exists()

        u_ro_explicit = file_ops.manage_files(g_ro_b, action="undo", path=edit_b)
        assert u_ro_explicit["ok"] is False and u_ro_explicit.get("blocked_by_guardrail") is True
        assert edit_b.read_text(encoding="utf-8") == "after_1"

        redo_ro = file_ops.manage_files(g_ro_b, action="redo", path="")
        assert redo_ro["ok"] is False and redo_ro.get("blocked_by_guardrail") is True
        assert edit_b.read_text(encoding="utf-8") == "after_1"

        rest_ro = file_ops.manage_files(g_ro_b, action="restore", trash_id="latest")
        assert rest_ro["ok"] is False and rest_ro.get("blocked_by_guardrail") is True
        assert not trash_b.exists()


def test_sandbox_hook_blocks_hf_tokens_and_outside_chdir_preserves_model_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_home = tmp_path / "fake_home"
    ws_dir = tmp_path / "ws_probe"
    ws_sub = ws_dir / "sub_pkg"
    outside_dir = tmp_path / "outside_secret_dir"
    st_dir = tmp_path / "state_probe"
    ws_sub.mkdir(parents=True)
    outside_dir.mkdir(parents=True)
    st_dir.mkdir(parents=True)

    hf_tok = fake_home / ".huggingface" / "token"
    hf_stored = fake_home / ".cache" / "huggingface" / "stored_tokens"
    hf_model_cfg = fake_home / ".cache" / "huggingface" / "hub" / "models--demo" / "snapshots" / "v1" / "config.json"
    hf_tokenizer = fake_home / ".cache" / "huggingface" / "hub" / "models--demo" / "snapshots" / "v1" / "tokenizer.json"
    hf_tok.parent.mkdir(parents=True)
    hf_stored.parent.mkdir(parents=True)
    hf_model_cfg.parent.mkdir(parents=True)

    hf_tok.write_text("hf_SUPER_SECRET_TOKEN_01", encoding="utf-8")
    hf_stored.write_text("hf_STORED_SECRET_TOKEN_02", encoding="utf-8")
    hf_model_cfg.write_text('{"model_type": "bert"}', encoding="utf-8")
    hf_tokenizer.write_text('{"version": "1.0"}', encoding="utf-8")

    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))

    guard = WorkspaceGuard(workspace_roots=[ws_dir], state_root=st_dir, tier="L3", restrict_to_workspace=True)
    # Host-side guard also isolates HF token files while allowing HF model cache reads
    assert guard.check_path_access(hf_tok, mode="read") is not None
    assert guard.check_path_access(hf_stored, mode="read") is not None
    assert guard.check_path_access(hf_model_cfg, mode="read") is None
    assert guard.check_path_access(hf_tokenizer, mode="read") is None

    pm = ProcessManager(guard=guard, state_root=st_dir)
    probe_script = f"""
import os
outcomes = {{}}

for label, p_str in [
    ("hf_token", {str(hf_tok)!r}),
    ("hf_stored", {str(hf_stored)!r}),
    ("hf_model_cfg", {str(hf_model_cfg)!r}),
    ("hf_tokenizer", {str(hf_tokenizer)!r}),
]:
    try:
        outcomes[label] = "ALLOW:" + Path(p_str).read_text(encoding="utf-8")
    except PermissionError:
        outcomes[label] = "BLOCKED"

for ch_label, d_str in [
    ("chdir_outside", {str(outside_dir)!r}),
    ("chdir_cache", {str(fake_home / ".cache")!r}),
    ("chdir_ws_sub", {str(ws_sub)!r}),
]:
    try:
        os.chdir(d_str)
        outcomes[ch_label] = "ALLOW"
    except PermissionError:
        outcomes[ch_label] = "BLOCKED"

RESULT["outcomes"] = outcomes
"""
    t0 = time.monotonic()
    probe_res = pm.run_batch_probe(ws_dir, probe_script, timeout_seconds=15)
    assert time.monotonic() - t0 < 10.0
    assert probe_res["ok"] is True, probe_res
    outcomes = probe_res["result"]["outcomes"]
    assert outcomes["hf_token"] == "BLOCKED"
    assert outcomes["hf_stored"] == "BLOCKED"
    assert outcomes["hf_model_cfg"].startswith("ALLOW:")
    assert outcomes["hf_tokenizer"].startswith("ALLOW:")
    assert outcomes["chdir_outside"] == "BLOCKED"
    assert outcomes["chdir_cache"] == "BLOCKED"
    assert outcomes["chdir_ws_sub"] == "ALLOW"
    assert "hf_SUPER_SECRET_TOKEN_01" not in str(probe_res)
    assert "hf_STORED_SECRET_TOKEN_02" not in str(probe_res)

    # Also verify L3 `sitecustomize.py` hook blocks `.huggingface/token` & `stored_tokens` while allowing model cache
    hook_dir = tmp_path / "l3_hook_pkg"
    l3_tmp = tmp_path / "l3_tmp"
    hook_dir.mkdir()
    l3_tmp.mkdir()
    (hook_dir / "sitecustomize.py").write_text(L3_SITECUSTOMIZE_SOURCE, encoding="utf-8")
    child_env = dict(os.environ)
    child_env["PYTHONDONTWRITEBYTECODE"] = "1"
    child_env["PYTHONPATH"] = str(hook_dir)
    child_env["COSMOS_L3_WORKSPACES"] = str(ws_dir)
    child_env["COSMOS_L3_ALLOW_TMP"] = str(l3_tmp)
    child_env["HOME"] = str(fake_home)
    child_env["USERPROFILE"] = str(fake_home)

    l3_code = (
        f"from pathlib import Path\n"
        f"assert 'bert' in Path({str(hf_model_cfg)!r}).read_text('utf-8')\n"
        f"for bad in ({str(hf_tok)!r}, {str(hf_stored)!r}):\n"
        f"    try:\n"
        f"        Path(bad).read_text('utf-8')\n"
        f"        raise SystemExit('NOT_BLOCKED:' + bad)\n"
        f"    except PermissionError:\n"
        f"        pass\n"
        f"print('L3_HF_OK')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-B", "-c", l3_code],
        env=child_env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    assert proc.returncode == 0, proc.stderr
    assert "L3_HF_OK" in proc.stdout


def test_user_configurable_guard_switches_l4_tx_and_studio_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from starlette.testclient import TestClient

    fake_home = tmp_path / "home_cfg"
    ws_dir = tmp_path / "ws_cfg"
    ext_dir = tmp_path / "ext_outside_ws"
    st_dir = tmp_path / "st_cfg"
    ws_dir.mkdir(parents=True)
    ext_dir.mkdir(parents=True)
    st_dir.mkdir(parents=True)
    ssh_key = fake_home / ".ssh" / "id_ed25519"
    ssh_key.parent.mkdir(parents=True)
    ssh_key.write_text("PRIVATE_KEY_DEMO", encoding="utf-8")
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))

    port = 18749
    pub_url = "https://cfg-gold.workers.dev"
    ensure_initialized(
        product_root=st_dir,
        public_url=pub_url,
        port=port,
        cli_state_dir=str(st_dir),
        tier_key="tier3_workspace_dev",
        prefix="pc",
        workspace_roots=[ws_dir],
    )
    app = create_standalone_app(
        workspace=str(ws_dir),
        state_dir=str(st_dir),
        port=port,
        public_url=pub_url,
        tunnel_mode="workers_dev",
    )
    dispatcher = app.state.dispatcher
    policy = app.state.policy

    # 1) Redline #1: default `approval_popups=False` keeps `readOnlyHint=True` for Web Gemini `Always allow`
    tool_defs = dispatcher.list_tool_dicts()
    by_name = {t["name"]: t for t in tool_defs}
    assert by_name["pc_write_file"]["annotations"]["readOnlyHint"] is True
    assert by_name["pc_run_python"]["annotations"]["readOnlyHint"] is True

    # 2) Project `.env` works out of the box in L2..L4 (`protect_dotenv_files=False`),
    #    blocks when `protect_dotenv_files=True`, and ALWAYS blocks on `/mcp/readonly`, L1, & `<state_root>/.env`.
    proj_env = ws_dir / ".env"
    proj_env.write_text("PORT=5173\n", encoding="utf-8")
    state_env = st_dir / ".env"
    state_env.write_text("CONTROL_SECRET=1\n", encoding="utf-8")

    res_env_ok, err_env_ok = asyncio.run(
        dispatcher.call_tool_raw("pc_read_file", {"path": str(proj_env)})
    )
    assert not err_env_ok and res_env_ok["ok"] is True
    assert "5173" in res_env_ok["content"]

    # `/mcp/readonly` (`readonly_only=True`) isolates `.env` automatically even when `protect_dotenv_files=False`
    res_env_ro, _ = asyncio.run(
        dispatcher.call_tool_raw("pc_read_file", {"path": str(proj_env)}, readonly_only=True)
    )
    assert res_env_ro["ok"] is False

    # `<state_root>/.env` is ALWAYS isolated across L3 & L4
    policy.apply_direct(tier_key="tier4_full_power")
    assert policy.guard.check_path_access(state_env, mode="read") is not None

    # User enables `protect_dotenv_files=True` -> blocks project `.env` even in L4
    policy.apply_direct(protect_dotenv_files=True)
    assert policy.guard.check_path_access(proj_env, mode="read") is not None
    policy.apply_direct(protect_dotenv_files=False)
    assert policy.guard.check_path_access(proj_env, mode="read") is None

    # 3) `protect_host_credentials` (default True -> toggleable False in L4, while `<state_root>/secrets` stays blocked)
    state_sec = st_dir / "secrets" / "auth.json"
    assert policy.guard.check_path_access(ssh_key, mode="read") is not None
    policy.apply_direct(protect_host_credentials=False)
    assert policy.guard.check_path_access(ssh_key, mode="read") is None
    assert policy.guard.check_path_access(state_sec, mode="read") is not None
    policy.apply_direct(protect_host_credentials=True)

    # 4) Dogmatic `.Parent` shell regex is gone; `block_destructive_commands=False` lifts `rm`/`os.remove`
    #    while keeping WebAI2PC daemon self-protection active
    assert policy.guard.check_command_pipelock("(Get-Item .).Parent.FullName", cwd=str(ws_dir)) is None
    assert policy.guard.check_destructive_command("git reset --hard HEAD~1", cwd=str(ws_dir)) is not None
    assert policy.guard.check_python_code_safety("import os\nos.remove('src/main.py')", cwd=str(ws_dir)) is not None

    policy.apply_direct(block_destructive_commands=False)
    assert policy.guard.check_destructive_command("git reset --hard HEAD~1", cwd=str(ws_dir)) is None
    assert policy.guard.check_python_code_safety("import os\nos.remove('src/main.py')", cwd=str(ws_dir)) is None
    # WebAI2PC own daemon self-protection remains active even when `block_destructive_commands=False`
    assert policy.guard.check_destructive_command("taskkill /F /IM cloudflared.exe", cwd=str(ws_dir)) is not None
    policy.apply_direct(block_destructive_commands=True)

    # 5) L4 (`tier4_full_power`, `restrict_to_workspace=False`) allows edit + undo + redo + trash + restore outside `ws_dir`
    ext_file = ext_dir / "outside_note.txt"
    ext_file.write_text("alpha", encoding="utf-8")
    assert file_ops.edit_file(ext_file, old_text="alpha", new_text="beta", guard=policy.guard)["ok"] is True
    assert file_ops.manage_files(policy.guard, action="undo", path=ext_file)["ok"] is True
    assert ext_file.read_text(encoding="utf-8") == "alpha"
    assert file_ops.manage_files(policy.guard, action="redo", path=ext_file)["ok"] is True
    assert ext_file.read_text(encoding="utf-8") == "beta"
    tr_ext = file_ops.manage_files(policy.guard, action="trash", path=ext_file)
    assert tr_ext["ok"] is True and not ext_file.exists()
    rs_ext = file_ops.manage_files(policy.guard, action="restore", trash_id=tr_ext["trash_id"])
    assert rs_ext["ok"] is True and ext_file.read_text(encoding="utf-8") == "beta"

    # 6) Studio `/api/studio/tools-safety` <-> `/api/studio/state` bidirectional sync & persistence
    #    (and Redline #3: `127.0.0.1` loopback direct access requires zero password)
    origin_hdr = {"Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
    with TestClient(app, base_url=f"http://127.0.0.1:{port}", client=("127.0.0.1", 52111)) as client:
        r_init = client.get("/api/studio/state", headers=origin_hdr)
        assert r_init.status_code == 200
        init_doc = r_init.json()
        tc_init = init_doc["tools_center"]
        assert tc_init["allow_loopback_dev"] is True
        assert tc_init["protect_dotenv_files"] is False
        assert tc_init["protect_host_credentials"] is True
        assert tc_init["block_destructive_commands"] is True

        post_hdr = {**origin_hdr, "X-Studio-Csrf": init_doc["csrf_token"]}
        r_upd = client.post(
            "/api/studio/tools-safety",
            json={
                "allow_loopback_dev": False,
                "protect_dotenv_files": True,
                "protect_host_credentials": False,
                "block_destructive_commands": False,
            },
            headers=post_hdr,
        )
        assert r_upd.status_code == 200
        tc_upd = r_upd.json()["tools_center"]
        assert tc_upd["allow_loopback_dev"] is False
        assert tc_upd["protect_dotenv_files"] is True
        assert tc_upd["protect_host_credentials"] is False
        assert tc_upd["block_destructive_commands"] is False
        assert policy.allow_loopback_dev is False
        assert policy.guard.protect_dotenv_files is True
        assert policy.guard.protect_host_credentials is False
        assert policy.guard.block_destructive_commands is False

