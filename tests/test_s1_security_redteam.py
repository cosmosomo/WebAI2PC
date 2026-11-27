"""Wave 11-B Security Red-Team Regression Suite (`C-SEC-01`, `C-SEC-02`, `C-PRIV-03`, `C-SEC-03`, `C-SEC-05`).

Verifies all 5 security & privacy hardening defenses without touching live ports `:8096` / `:8093`
and without spawning any visible Windows console window (`CREATE_NO_WINDOW=0x08000000`):
1. `C-SEC-01`: `/mcp/readonly` `batch_probe` & `L3` `run_python` block static & dynamic `ctypes` / `_winapi`
   / `msvcrt` / `winreg` / `__import__` escapes, and synchronous foreground execution never enables
   `CREATE_BREAKAWAY_FROM_JOB` unless `breakaway=True` is explicitly requested (`bg_command`).
2. `C-SEC-02`: `/consent` invalidates `ticket` on the 3rd consecutive failure, triggers a global HTTP `429`
   cooldown after 8 failures within 30s even when `X-Forwarded-For` / `X-Cosmos-Client-IP` is rotated on
   every request, extracts rightmost `X-Forwarded-For` hop, injects `X-Cosmos-Client-IP {remote_host}` in
   Caddy templates, and includes `<a href="/">返回本地 Studio 控制台</a>` on `/consent` error pages.
3. `C-PRIV-03`: `L1` and `/mcp/readonly` deny reading `.env` / `.env.*` while allowing `.env.example` and
   `.env.template`; `L4` (`tier4_full_power`) still protects `<state_root>/{secrets,state,config,.env}`;
   `guard.py` contains zero author-private `COSMOS_MODE_HOME` / `.cosmos-mode` literals; `vps_hub` saves
   `vps_node_secret` exclusively in `<state_root>/secrets/vps_node_secret.txt` and never in `service.json`.
4. `C-SEC-03`: `LiveRuntimePolicy.apply_direct` & `persist_changes` enforce `_startup_env_locks` against
   runtime escalation; `/remote-admin/policy` validates `python_path` as a real local Python interpreter
   and defaults to `403` disabled on public gateway requests.
5. `C-SEC-05`: `/.well-known/*/{subpath}` returns `404` for unknown random subpaths without polluting
   `allowed_resources`, unauthenticated public `GET /skill` returns `401`, and `VPS_RESIDENT_HUB_PY`
   enforces request header (`431`) and request body (`413`) size caps.
"""
from __future__ import annotations

import asyncio
import base64
import ctypes
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlsplit

import pytest
from starlette.testclient import TestClient

if sys.platform == "win32":
    ctypes.windll.kernel32.SetErrorMode(0x8003)

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from cosmos_mcp.core.config import LiveRuntimePolicy, ensure_initialized  # noqa: E402
from cosmos_mcp.core.guard import WorkspaceGuard  # noqa: E402
from cosmos_mcp.core.proc import (  # noqa: E402
    CREATE_BREAKAWAY_FROM_JOB,
    ProcessManager,
    _detect_ast_mutation_in_probe,
    _popen_with_optional_breakaway,
    run_batch_probe,
)
from cosmos_mcp.launcher.tunnels import (  # noqa: E402
    VPS_RESIDENT_HUB_PY,
    build_vps_hub_caddy_site_snippet,
    generate_vps_caddy_snippet,
    provision_vps_hub_oneclick,
)
from cosmos_mcp.protocol.dispatcher import KernelDispatcher  # noqa: E402
from cosmos_mcp.protocol.oauth import (  # noqa: E402
    OAuthProvider,
    OAuthSQLiteStore,
    resolve_client_ip_from_headers,
    validate_and_apply_remote_policy_update,
)
from cosmos_mcp.protocol.tools import build_core_tools  # noqa: E402
from cosmos_mcp.protocol.transport import create_protocol_app  # noqa: E402


def _pkce_pair(seed: str) -> Tuple[str, str]:
    verifier = f"wave11b_pkce_verifier_{seed}_0123456789abcdef0123456789"
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .decode("ascii")
        .rstrip("=")
    )
    return verifier, challenge


def _build_test_harness(
    tmp_path: Path,
    *,
    tier_key: str = "tier3_workspace_dev",
    public_base: str = "https://sec-w11b.example.com",
    port: int = 18496,
    tunnel_mode: str = "",
) -> Tuple[Any, LiveRuntimePolicy, KernelDispatcher, OAuthSQLiteStore, OAuthProvider, str, Path, Path]:
    ws_dir = tmp_path / "workspace"
    ws_dir.mkdir(parents=True, exist_ok=True)
    st_dir = tmp_path / "state_root"
    creds = ensure_initialized(
        product_root=st_dir,
        public_url=public_base,
        port=port,
        cli_state_dir=str(st_dir),
        tier_key=tier_key,
        prefix="pc",
        workspace_roots=[ws_dir],
    )
    conn_txt = (st_dir / "连接信息_CONNECTION_INFO.txt").read_text(encoding="utf-8")
    m_pw = re.search(r"授权页连接口令\s*:\s*([^\r\n]+)", conn_txt)
    assert m_pw is not None
    owner_pw = m_pw.group(1).strip()

    guard = WorkspaceGuard(
        [ws_dir],
        tier=tier_key,
        restrict_to_workspace=(tier_key != "tier4_full_power"),
        state_root=st_dir,
        tool_prefix="pc",
    )
    proc_mgr = ProcessManager(guard=guard, state_root=st_dir)
    policy = LiveRuntimePolicy(
        tier_key=tier_key,
        workspace_roots=[ws_dir],
        cfg_path=st_dir / "config" / "service.json",
        state_root=st_dir,
        guard=guard,
    )
    dispatcher = KernelDispatcher(policy)
    specs, hooks = build_core_tools(
        guard=guard,
        proc_mgr=proc_mgr,
        policy_getter=lambda: {
            "prefix": policy.eff_prefix,
            "tier": policy.short_tier_code,
            "workspace": policy.workspace,
            "toolset_profile": policy.toolset_profile,
            "python_path": policy.python_path,
            "exposed_tools": [sp.base_name for sp in dispatcher.active_tool_specs()],
        },
    )
    dispatcher.register_tools(specs)
    for hk in hooks:
        dispatcher.add_execution_hook(hk)

    store = OAuthSQLiteStore(st_dir / "state" / "oauth.sqlite3")
    provider = OAuthProvider(
        store=store,
        base_url=public_base,
        password_hash=str(creds["password_hash"]),
        salt=str(creds["salt"]),
        tier_label=policy.dynamic_tier_label(),
        tier_key=policy.tier_key,
        toolset_profile=policy.toolset_profile,
        tool_prefix="pc",
        tunnel_mode=tunnel_mode,
        local_port=port,
    )
    app = create_protocol_app(
        dispatcher,
        policy=policy,
        store=store,
        provider=provider,
        proc_mgr=proc_mgr,
        public_url=public_base,
        port=port,
        local_api_token=str(creds["local_api_token"]),
        tunnel_mode=tunnel_mode,
    )
    return app, policy, dispatcher, store, provider, owner_pw, ws_dir, st_dir


def test_c_sec_01_batch_probe_and_l3_block_ctypes_winapi_and_breakaway_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_dir = tmp_path / "ws_probe"
    ws_dir.mkdir(parents=True)
    (ws_dir / "sample.py").write_text("def greet():\n    return 'ok'\n", encoding="utf-8")
    st_dir = tmp_path / "st_probe"
    st_dir.mkdir(parents=True)

    # 1) Static AST scanner blocks ctypes / _ctypes / _winapi / msvcrt / winreg / importlib / __import__ / builtins
    for bad_snippet in (
        "import ctypes\nRESULT['x'] = 1",
        "import _winapi\nRESULT['x'] = 1",
        "from importlib import import_module\nRESULT['x'] = 1",
        "c = __import__('ctypes')\nRESULT['x'] = 1",
        "import builtins\nRESULT['x'] = 1",
    ):
        reason = _detect_ast_mutation_in_probe(bad_snippet)
        assert reason is not None, f"Expected AST block for: {bad_snippet}"

    # 2) Dynamic runtime string-concatenation bypasses inside `run_batch_probe` are blocked by __import__ + audit hook
    dyn_escape_code = (
        "import json\n"
        "raw_b = getattr(json.loads, '__glo' + 'bals__')['__buil' + 'tins__']\n"
        "fn = raw_b['__imp' + 'ort__'] if isinstance(raw_b, dict) else getattr(raw_b, '__imp' + 'ort__')\n"
        "blocked = []\n"
        "for mod_parts in (('cty', 'pes'), ('_win', 'api'), ('msv', 'crt'), ('win', 'reg')):\n"
        "    mod_name = mod_parts[0] + mod_parts[1]\n"
        "    try:\n"
        "        fn(mod_name)\n"
        "        blocked.append(f'ESCAPED:{mod_name}')\n"
        "    except Exception as exc:\n"
        "        blocked.append(f'BLOCKED:{mod_name}:{type(exc).__name__}')\n"
        "RESULT['checks'] = blocked\n"
        "RESULT['outline_ok'] = len(outline('sample.py')) >= 0\n"
    )
    probe_res = run_batch_probe(ws_dir, dyn_escape_code, timeout_seconds=15)
    assert probe_res["ok"] is True, probe_res
    checks = probe_res["result"]["checks"]
    assert len(checks) == 4
    assert all(item.startswith("BLOCKED:") for item in checks), checks

    # 3) L3 `run_python` sandbox hook also blocks dynamic `ctypes` / `_winapi` imports in user scripts
    guard_l3 = WorkspaceGuard([ws_dir], tier="tier3_workspace_dev", state_root=st_dir)
    pm = ProcessManager(guard=guard_l3, state_root=st_dir, enable_sandbox_hook=True)
    l3_res = asyncio.run(
        pm.execute_python_stdin(
            "import ctypes\nprint('L3_CTYPES_ESCAPED')\n",
            cwd=str(ws_dir),
            timeout=15.0,
        )
    )
    assert l3_res["ok"] is False
    assert "L3_CTYPES_ESCAPED" not in l3_res.get("stdout", "")
    assert "COSMOS L3 SANDBOX" in (l3_res.get("stderr", "") + l3_res.get("stdout", ""))

    # 4) Foreground execution strips CREATE_BREAKAWAY_FROM_JOB (`breakaway=False`), while explicit `breakaway=True` preserves it
    observed_flags: List[int] = []

    class _DummyProc:
        pid = 99999

    def _fake_popen(*args: Any, **kwargs: Any) -> _DummyProc:
        observed_flags.append(int(kwargs.get("creationflags", 0) or 0))
        return _DummyProc()

    monkeypatch.setattr(subprocess, "Popen", _fake_popen)
    _popen_with_optional_breakaway(
        ["python", "-B", "-c", "pass"],
        creationflags=0x08000000 | CREATE_BREAKAWAY_FROM_JOB,
        breakaway=False,
    )
    assert (observed_flags[-1] & CREATE_BREAKAWAY_FROM_JOB) == 0

    _popen_with_optional_breakaway(
        ["python", "-B", "-c", "pass"],
        creationflags=0x08000000,
        breakaway=True,
    )
    if sys.platform == "win32":
        assert (observed_flags[-1] & CREATE_BREAKAWAY_FROM_JOB) == CREATE_BREAKAWAY_FROM_JOB


def test_c_sec_02_consent_3_attempt_invalidation_global_ip_rotation_shield_and_console_link(
    tmp_path: Path,
) -> None:
    public_base = "https://sec02-gw.example.com"
    app, _, _, store, _, owner_pw, _, _ = _build_test_harness(
        tmp_path,
        public_base=public_base,
        port=18497,
        tunnel_mode="reverse_proxy",
    )
    redirect_uri = "https://chatgpt.com/connector_platform_oauth_redirect"

    # Verify rightmost X-Forwarded-For hop extraction & Caddy X-Cosmos-Client-IP overwrite
    ip_res, trusted = resolve_client_ip_from_headers(
        {"x-forwarded-for": "10.9.8.7, 198.51.100.88"},
        peer_host="127.0.0.1",
        tunnel_mode="reverse_proxy",
    )
    assert trusted is True and ip_res == "198.51.100.88"
    assert "header_up X-Cosmos-Client-IP {remote_host}" in generate_vps_caddy_snippet("mcp.example.com", 18096)
    hub_snip = build_vps_hub_caddy_site_snippet("203.0.113.10", custom_domain="hub.example.com", hub_port=18096)
    assert "header_up X-Cosmos-Client-IP {remote_host}" in hub_snip
    assert "/remote-admin" in hub_snip

    with TestClient(app, base_url=public_base, client=("127.0.0.1", 51200)) as client:
        # 1) Direct `/consent` without ticket renders `返回本地 Studio 控制台` link
        r_no_ticket = client.get("/consent", headers={"Accept": "text/html"})
        assert r_no_ticket.status_code == 400
        assert '<a href="/">返回本地 Studio 控制台</a>' in r_no_ticket.text

        reg = client.post(
            "/register",
            json={
                "client_name": "RedTeam Client",
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
        )
        assert reg.status_code in (200, 201)
        client_id = reg.json()["client_id"]

        def _mint_consent_ticket(seed: str, spoof_ip: str) -> Tuple[str, str]:
            _, challenge = _pkce_pair(seed)
            r_auth = client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": f"st_{seed}",
                },
                headers={"X-Cosmos-Client-IP": spoof_ip},
                follow_redirects=False,
            )
            assert r_auth.status_code in (302, 307)
            loc = r_auth.headers["location"]
            path_qs = urlsplit(loc).path + "?" + urlsplit(loc).query
            r_get = client.get(path_qs, headers={"Accept": "text/html", "X-Cosmos-Client-IP": spoof_ip})
            assert r_get.status_code == 200
            m_t = re.search(r'name="ticket"\s+value="([^"]+)"', r_get.text)
            m_c = re.search(r'name="csrf"\s+value="([^"]+)"', r_get.text)
            assert m_t and m_c
            return m_t.group(1), m_c.group(1)

        # 2) Single ticket invalidates on 3rd consecutive wrong attempt
        t1, c1 = _mint_consent_ticket("t1", "198.51.100.1")
        for idx in range(1, 4):
            r_fail = client.post(
                f"/consent?ticket={t1}",
                data={"ticket": t1, "csrf": c1, "auth_mode": "pair_code", "pair_code": "000000"},
                headers={"Origin": public_base, "X-Cosmos-Client-IP": f"198.51.100.{idx}", "Accept": "application/json"},
                follow_redirects=False,
            )
            assert r_fail.status_code == 403
            body = r_fail.json()
            assert body["ticket_invalidated"] is (idx == 3)

        # Submitting valid owner password on invalidated `t1` must now fail (403 expired_or_legacy_transaction)
        r_after_inv = client.post(
            f"/consent?ticket={t1}",
            data={"ticket": t1, "csrf": c1, "auth_mode": "password", "password": owner_pw},
            headers={"Origin": public_base, "X-Cosmos-Client-IP": "198.51.100.50", "Accept": "application/json"},
            follow_redirects=False,
        )
        assert r_after_inv.status_code == 403

        # 3) Rotating forged client IPs across fresh tickets hits global 8-failure shield -> HTTP 429
        # Already recorded 3 global failures above; failures 4..7 return 403, failure 8 triggers 429!
        statuses: List[int] = []
        for idx in range(4, 10):
            tk, cs = _mint_consent_ticket(f"rot_{idx}", f"203.0.113.{idx}")
            r_rot = client.post(
                f"/consent?ticket={tk}",
                data={"ticket": tk, "csrf": cs, "auth_mode": "pair_code", "pair_code": "999999"},
                headers={"Origin": public_base, "X-Cosmos-Client-IP": f"203.0.113.{idx}", "Accept": "application/json"},
                follow_redirects=False,
            )
            statuses.append(r_rot.status_code)
            if r_rot.status_code == 429:
                assert r_rot.json().get("reason") == "global_auth_cooldown"
                break
        assert 429 in statuses, f"Expected global 429 lockout despite IP rotation, got {statuses}"
        assert store.check_global_auth_lockout()[0] is True


def test_c_priv_03_dotenv_isolation_state_root_protection_in_l4_and_secret_file_only(
    tmp_path: Path,
) -> None:
    public_base = "https://priv03-gw.example.com"
    app, policy, dispatcher, _, _, owner_pw, ws_dir, st_dir = _build_test_harness(
        tmp_path,
        tier_key="tier1_readonly",
        public_base=public_base,
        port=18498,
    )
    (ws_dir / ".env").write_text("OPENAI_API_KEY=sk-live-secret-123\n", encoding="utf-8")
    (ws_dir / ".env.production").write_text("DB_PASS=prod-secret\n", encoding="utf-8")
    (ws_dir / ".env.example").write_text("OPENAI_API_KEY=your-key-here\n", encoding="utf-8")
    (ws_dir / ".env.template").write_text("DB_PASS=placeholder\n", encoding="utf-8")

    # 1) L1 (`tier1_readonly`) denies `.env` & `.env.production` but allows `.env.example` & `.env.template`
    for blocked_name in (".env", ".env.production"):
        res_blk, is_err = asyncio.run(
            dispatcher.call_tool_raw("pc_read_file", {"path": str(ws_dir / blocked_name)})
        )
        assert is_err is True or res_blk.get("ok") is False, f"Expected L1 block on {blocked_name}: {res_blk}"

    for allowed_name in (".env.example", ".env.template"):
        res_ok, is_err_ok = asyncio.run(
            dispatcher.call_tool_raw("pc_read_file", {"path": str(ws_dir / allowed_name)})
        )
        assert not is_err_ok and res_ok.get("ok") is True, f"Expected L1 allow on {allowed_name}: {res_ok}"

    # 2) Even in L4 (`tier4_full_power`), `/mcp/readonly` denies `.env` AND `<state_root>/{secrets,state,config,.env}` stay protected
    policy.apply_direct(tier_key="tier4_full_power")
    ro_res, ro_err = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_read_file",
            {"path": str(ws_dir / ".env")},
            readonly_only=True,
        )
    )
    assert ro_err is True or ro_res.get("ok") is False

    (st_dir / ".env").write_text("MASTER_SECRET=never-expose\n", encoding="utf-8")
    guard_l4 = WorkspaceGuard([ws_dir, st_dir], tier="tier4_full_power", state_root=st_dir)
    for protected_target in (
        st_dir / "secrets" / "auth.json",
        st_dir / "state" / "oauth.sqlite3",
        st_dir / "config" / "service.json",
        st_dir / ".env",
    ):
        assert guard_l4.check_path_access(protected_target, mode="read", tool_name="read_file") is not None
        assert guard_l4.check_path_access(protected_target, mode="write", tool_name="write_file") is not None

    # 3) Zero author-private `COSMOS_MODE_HOME` or `.cosmos-mode` literals in `guard.py`
    guard_src = (REPO_ROOT / "src" / "cosmos_mcp" / "core" / "guard.py").read_text(encoding="utf-8")
    assert "COSMOS_MODE_HOME" not in guard_src
    assert ".cosmos-mode" not in guard_src

    # 4) `provision_vps_hub_oneclick` stores `vps_node_secret` ONLY in `secrets/vps_node_secret.txt`, NOT `config/service.json`
    st_vps = tmp_path / "st_vps_secret_test"
    ensure_initialized(product_root=st_vps, public_url="http://127.0.0.1:18499", port=18499, cli_state_dir=str(st_vps))

    def _fake_ssh_runner(
        cmd: List[str],
        env: Dict[str, str],
        timeout: float,
        stage: str,
        stdin_script: str | None = None,
    ) -> Tuple[int, str, str]:
        if stage == "probe_remote":
            return (
                0,
                json.dumps(
                    {
                        "public_ip": "198.51.100.99",
                        "port_80_ok": True,
                        "port_443_ok": True,
                        "mem_total_mb": 2048,
                        "swap_created": False,
                    }
                )
                + "\n",
                "",
            )
        if stage == "deploy_hub_and_caddy":
            assert stdin_script is not None
            assert "svc_doc.pop('vps_node_secret', None)" in stdin_script
            return 0, "DEPLOY_OK\n", ""
        return 0, "OK\n", ""

    vps_out = provision_vps_hub_oneclick(
        host="198.51.100.99",
        ssh_user="root",
        local_port=18499,
        state_root=st_vps,
        prefix="pc",
        runner_override=_fake_ssh_runner,
    )
    assert vps_out["ok"] is True
    sec_file = st_vps / "secrets" / "vps_node_secret.txt"
    assert sec_file.is_file() and len(sec_file.read_text(encoding="utf-8").strip()) >= 32
    svc_json_txt = (st_vps / "config" / "service.json").read_text(encoding="utf-8")
    svc_json_doc = json.loads(svc_json_txt)
    assert "vps_node_secret" not in svc_json_doc
    assert sec_file.read_text(encoding="utf-8").strip() not in svc_json_txt
    _ = (app, owner_pw)


def test_c_sec_03_startup_env_locks_enforced_and_remote_admin_policy_hardened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_dir = tmp_path / "ws_lock"
    ws_dir.mkdir(parents=True)
    st_dir = tmp_path / "st_lock"
    st_dir.mkdir(parents=True)

    # 1) Startup env lock on `COSMOS_PERMISSION_TIER=L1` blocks `apply_direct` and `persist_changes` escalation
    monkeypatch.setenv("COSMOS_PERMISSION_TIER", "L1")
    locked_pol = LiveRuntimePolicy(
        workspace_roots=[ws_dir],
        state_root=st_dir,
        cfg_path=st_dir / "config" / "service.json",
    )
    assert "tier_key" in locked_pol._startup_env_locks
    assert locked_pol.tier_key == "tier1_readonly"
    with pytest.raises(ValueError, match="ERR_STARTUP_ENV_LOCKED"):
        locked_pol.apply_direct(tier_key="tier4_full_power")
    assert locked_pol.tier_key == "tier1_readonly"

    with pytest.raises(ValueError, match="ERR_STARTUP_ENV_LOCKED"):
        locked_pol.persist_changes(tier_key="tier3_workspace_dev")
    assert locked_pol.tier_key == "tier1_readonly"
    monkeypatch.delenv("COSMOS_PERMISSION_TIER", raising=False)

    # 2) `validate_and_apply_remote_policy_update` rejects non-Python / nonexistent / UNC `python_path`
    public_base = "https://sec03-gw.example.com"
    app, policy, _, store, provider, owner_pw, _, _ = _build_test_harness(
        tmp_path / "h2",
        public_base=public_base,
        port=18501,
        tunnel_mode="cloudflare",
    )
    fake_exe = tmp_path / "not_python.exe"
    fake_exe.write_bytes(b"MZ")
    for bad_py in (
        str(fake_exe),
        str(tmp_path / "missing_dir" / "python.exe"),
        r"\\evil-server\share\python.exe",
    ):
        bad_res = validate_and_apply_remote_policy_update(
            policy,
            store,
            provider,
            {"owner_password": owner_pw, "python_path": bad_py},
        )
        assert bad_res["ok"] is False and bad_res["status_code"] == 400
        assert "ERR_INVALID_PYTHON_PATH" in bad_res["error"]

    ok_res = validate_and_apply_remote_policy_update(
        policy,
        store,
        provider,
        {"owner_password": owner_pw, "python_path": sys.executable},
    )
    assert ok_res["ok"] is True

    # 3) `/remote-admin/policy` defaults to 403 disabled on public gateway requests
    with TestClient(app, base_url=public_base, client=("127.0.0.1", 51300)) as client:
        r_pub_adm = client.post(
            "/remote-admin/policy",
            json={"owner_password": owner_pw, "annotation_mode": "strict"},
            headers={"CF-Connecting-IP": "198.51.100.42", "X-Forwarded-Proto": "https"},
        )
        assert r_pub_adm.status_code == 403
        assert r_pub_adm.json()["error"] == "remote_admin_policy_disabled_on_public_gateway"


def test_c_sec_05_well_known_subpath_never_pollutes_allowed_resources_and_hub_limits(
    tmp_path: Path,
) -> None:
    public_base = "https://sec05-gw.example.com"
    app, _, _, _, provider, _, _, _ = _build_test_harness(
        tmp_path,
        public_base=public_base,
        port=18502,
    )
    baseline_resources = set(provider.allowed_resources)

    with TestClient(app, base_url=public_base, client=("127.0.0.1", 51400)) as client:
        # 1) Known `/mcp` and `/mcp/readonly` discovery endpoints succeed
        assert client.get("/.well-known/oauth-protected-resource/mcp").status_code == 200
        assert client.get("/.well-known/oauth-protected-resource/mcp/readonly").status_code == 200

        # 2) Unauthenticated arbitrary random subpaths return 404 and NEVER grow `allowed_resources`
        for i in range(25):
            r1 = client.get(f"/.well-known/oauth-protected-resource/random-probe-{i}/mcp")
            r2 = client.get(f"/.well-known/oauth-authorization-server/random-probe-{i}")
            r3 = client.get(f"/.well-known/oauth-protected-resource/untrusted-junk-{i}")
            assert r1.status_code == 404
            assert r2.status_code == 404
            assert r3.status_code == 404
        assert set(provider.allowed_resources) == baseline_resources

        # 3) Unauthenticated public `GET /skill` returns 401, while strict direct loopback returns 200
        r_pub_skill = client.get("/skill", headers={"X-Forwarded-Proto": "https", "X-Real-IP": "203.0.113.55"})
        assert r_pub_skill.status_code == 401

        r_loc_skill = client.get("http://127.0.0.1:18502/skill")
        assert r_loc_skill.status_code == 200
        assert "pc_read_file" in r_loc_skill.text

    # 4) `VPS_RESIDENT_HUB_PY` enforces header (`431`) and body (`413`) size caps
    hub_ns: Dict[str, Any] = {}
    exec(compile(VPS_RESIDENT_HUB_PY, "<VPS_RESIDENT_HUB_PY>", "exec"), hub_ns)
    assert hub_ns["MAX_HTTP_HEADER_BYTES"] == 65536
    assert hub_ns["MAX_HTTP_BODY_BYTES"] == 16 * 1024 * 1024

    async def _exercise_hub_limits() -> Tuple[bytes, bytes]:
        hub_state = hub_ns["HubState"]("unit-test-secret")
        handle_conn = hub_ns["handle_conn"]

        class _FakeWriter:
            def __init__(self) -> None:
                self.buf = bytearray()
                self.closed = False

            def write(self, data: bytes) -> None:
                self.buf.extend(data)

            async def drain(self) -> None:
                return None

            def close(self) -> None:
                self.closed = True

        # Oversized header (> 64 KiB) -> 431
        r_big_hdr = asyncio.StreamReader(limit=256 * 1024)
        r_big_hdr.feed_data(b"GET /mcp HTTP/1.1\r\nX-Junk: " + (b"A" * 70000) + b"\r\n\r\n")
        r_big_hdr.feed_eof()
        w_big_hdr = _FakeWriter()
        await handle_conn(hub_state, r_big_hdr, w_big_hdr)

        # Oversized Content-Length (> 16 MiB) -> 413 without allocating body
        r_big_body = asyncio.StreamReader()
        r_big_body.feed_data(b"POST /mcp HTTP/1.1\r\nHost: example.com\r\nContent-Length: 999999999\r\n\r\n")
        r_big_body.feed_eof()
        w_big_body = _FakeWriter()
        await handle_conn(hub_state, r_big_body, w_big_body)
        return bytes(w_big_hdr.buf), bytes(w_big_body.buf)

    resp_hdr_bytes, resp_body_bytes = asyncio.run(_exercise_hub_limits())
    assert resp_hdr_bytes.startswith(b"HTTP/1.1 431 ")
    assert resp_body_bytes.startswith(b"HTTP/1.1 413 ")
