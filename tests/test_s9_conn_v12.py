"""v1.2 connection & OAuth local-bridge proxy-hijack fallback verification suite (`test_s9_conn_v12.py`)."""
from __future__ import annotations

import base64
import ctypes
import hashlib
from pathlib import Path
import re
import sys
from urllib.parse import parse_qs, urlsplit

from starlette.testclient import TestClient

if sys.platform == "win32":
    ctypes.windll.kernel32.SetErrorMode(0x8003)

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from cosmos_mcp.core.config import LiveRuntimePolicy, ensure_initialized  # noqa: E402
from cosmos_mcp.core.guard import WorkspaceGuard  # noqa: E402
from cosmos_mcp.core.proc import ProcessManager  # noqa: E402
from cosmos_mcp.protocol.dispatcher import KernelDispatcher  # noqa: E402
from cosmos_mcp.protocol.oauth import OAuthProvider, OAuthSQLiteStore  # noqa: E402
from cosmos_mcp.protocol.tools import build_core_tools  # noqa: E402
from cosmos_mcp.protocol.transport import create_protocol_app  # noqa: E402

BROWSER_HTML_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"


def _pkce_pair(seed: str = "v12") -> tuple[str, str]:
    verifier = f"cosmos_{seed}_pkce_verifier_0123456789abcdefghijklmnopqrstuvwxyz"
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
    return verifier, challenge


def _build_oauth_protocol_harness(
    tmp_path: Path,
    *,
    public_base: str = "https://gw-v12.workers.dev",
    port: int = 18396,
    tunnel_mode: str = "",
) -> tuple[object, OAuthSQLiteStore, OAuthProvider]:
    ws_dir = tmp_path / "ws"
    st_dir = tmp_path / "state"
    ws_dir.mkdir(parents=True, exist_ok=True)
    creds = ensure_initialized(
        product_root=st_dir,
        public_url=public_base,
        port=port,
        cli_state_dir=str(st_dir),
        workspace_roots=[ws_dir],
        tunnel_mode=tunnel_mode or None,
    )
    guard = WorkspaceGuard(workspace_roots=[ws_dir], state_root=st_dir, tool_prefix="pc")
    proc_mgr = ProcessManager(guard=guard, state_root=st_dir)
    cfg_path = st_dir / "config" / "service.json"
    policy = LiveRuntimePolicy(workspace_roots=[ws_dir], cfg_path=cfg_path, state_root=st_dir, guard=guard)
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
        public_url=public_base,
        port=port,
        local_api_token=str(creds["local_api_token"]),
        tunnel_mode=tunnel_mode,
    )
    return app, store, provider


def _count_records_of_kind(store: OAuthSQLiteStore, kind: str) -> int:
    conn = store.connect(readonly=True)
    try:
        row = conn.execute("SELECT COUNT(*) FROM records WHERE kind = ?", (kind,)).fetchone()
        return int(row[0]) if row else 0
    finally:
        conn.close()


def _register_and_open_consent(
    client: TestClient,
    *,
    public_base: str,
    redirect_uri: str,
    challenge: str,
    state_val: str,
    extra_headers: dict[str, str] | None = None,
) -> tuple[str, str, str]:
    reg = client.post(
        "/register",
        json={
            "client_name": "Gemini Web Connector",
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
    )
    assert reg.status_code in (200, 201)
    client_id = reg.json()["client_id"]

    hdrs = {"X-Forwarded-Proto": "https", **(extra_headers or {})}
    r_auth = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state_val,
            "resource": f"{public_base}/mcp",
        },
        headers=hdrs,
        follow_redirects=False,
    )
    assert r_auth.status_code in (302, 303)

    r_get = client.get(
        r_auth.headers["location"],
        headers={**hdrs, "Accept": BROWSER_HTML_ACCEPT},
    )
    assert r_get.status_code == 200
    assert '<details class="alt-auth-details" id="alt-auth-details">' in r_get.text
    assert '<details class="alt-auth-details" id="alt-auth-details" open>' not in r_get.text

    m_ticket = re.search(r'name="ticket"\s+value="([^"]+)"', r_get.text)
    m_csrf = re.search(r'name="csrf"\s+value="([^"]+)"', r_get.text)
    assert m_ticket and m_csrf
    return client_id, m_ticket.group(1), m_csrf.group(1)


def test_local_bridge_api_and_forged_proxy_requests_strictly_403(tmp_path: Path) -> None:
    public_base = "https://gw-v12-sec.workers.dev"
    port = 18396
    app, store, _ = _build_oauth_protocol_harness(tmp_path, public_base=public_base, port=port)
    redirect_uri = "https://oauth-redirect.googleusercontent.com/r/v12sec"
    _, challenge = _pkce_pair("sec")

    with TestClient(app, base_url=public_base, client=("127.0.0.1", 51001)) as client:
        _, ticket, csrf = _register_and_open_consent(
            client,
            public_base=public_base,
            redirect_uri=redirect_uri,
            challenge=challenge,
            state_val="st_sec_403",
        )
        r_post = client.post(
            f"/consent?ticket={ticket}",
            data={"ticket": ticket, "csrf": csrf, "auth_mode": "local_bridge"},
            headers={"Origin": public_base, "X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        assert r_post.status_code == 302
        bridge_url = r_post.headers["location"]
        assert bridge_url.startswith(f"http://127.0.0.1:{port}/oauth/local-bridge?")
        bridge_qs = parse_qs(urlsplit(bridge_url).query)
        nonce = bridge_qs["nonce"][0]

        # 1) Pure API / non-HTML requests with forged X-Forwarded-For MUST return 403 and NEVER mint proof or consume nonce
        for api_accept in ("*/*", "application/json"):
            r_api = client.get(
                bridge_url,
                headers={"Accept": api_accept, "X-Forwarded-For": "198.51.100.9"},
                follow_redirects=False,
            )
            assert r_api.status_code == 403
            assert r_api.json() == {
                "error": "forbidden_non_loopback",
                "reason": "pure_local_loopback_required",
            }
            assert _count_records_of_kind(store, "local_bridge_proof") == 0
            assert store.get("local_bridge_nonce", nonce) is not None

        # 2) Browser Accept: text/html WITHOUT valid signed nonce MUST still return 403 forbidden_non_loopback
        for bad_url in (
            f"http://127.0.0.1:{port}/oauth/local-bridge",
            f"http://127.0.0.1:{port}/oauth/local-bridge?ticket={ticket}&nonce=forged.invalid_sig",
        ):
            r_bad_html = client.get(
                bad_url,
                headers={"Accept": BROWSER_HTML_ACCEPT, "X-Forwarded-For": "198.51.100.9"},
                follow_redirects=False,
            )
            assert r_bad_html.status_code == 403
            assert r_bad_html.json() == {
                "error": "forbidden_non_loopback",
                "reason": "pure_local_loopback_required",
            }
            assert _count_records_of_kind(store, "local_bridge_proof") == 0


def test_browser_proxy_hijacked_local_bridge_falls_back_to_consent_6digit_code(tmp_path: Path) -> None:
    public_base = "https://gw-v12-ux.workers.dev"
    port = 18397
    app, store, provider = _build_oauth_protocol_harness(tmp_path, public_base=public_base, port=port)
    redirect_uri = "https://oauth-redirect.googleusercontent.com/r/v12ux"
    verifier, challenge = _pkce_pair("ux")

    with TestClient(app, base_url=public_base, client=("127.0.0.1", 51002)) as client:
        client_id, ticket, csrf = _register_and_open_consent(
            client,
            public_base=public_base,
            redirect_uri=redirect_uri,
            challenge=challenge,
            state_val="st_proxy_fb",
        )
        r_post = client.post(
            f"/consent?ticket={ticket}",
            data={"ticket": ticket, "csrf": csrf, "auth_mode": "local_bridge"},
            headers={"Origin": public_base, "X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        assert r_post.status_code == 302
        bridge_url = r_post.headers["location"]
        nonce = parse_qs(urlsplit(bridge_url).query)["nonce"][0]
        assert store.get("local_bridge_nonce", nonce) is not None

        # Step 1: Browser top-level 302 navigation hijacked by SwitchyOmega / global proxy (`X-Forwarded-For: 198.51.100.9`)
        r_hijacked = client.get(
            bridge_url,
            headers={
                "Accept": BROWSER_HTML_ACCEPT,
                "X-Forwarded-For": "198.51.100.9",
            },
            follow_redirects=False,
        )
        assert r_hijacked.status_code == 302
        fallback_loc = r_hijacked.headers["location"]
        parsed_fb = urlsplit(fallback_loc)
        assert f"{parsed_fb.scheme}://{parsed_fb.netloc}{parsed_fb.path}" == f"{public_base}/consent"
        fb_qs = parse_qs(parsed_fb.query)
        assert fb_qs.get("ticket") == [ticket]
        assert fb_qs.get("bridge_fallback") == ["1"]

        # Security check: nonce consumed once, zero `local_bridge_proof` ever minted, replay gets 403
        assert store.get("local_bridge_nonce", nonce) is None
        assert _count_records_of_kind(store, "local_bridge_proof") == 0
        r_replay = client.get(
            bridge_url,
            headers={"Accept": BROWSER_HTML_ACCEPT, "X-Forwarded-For": "198.51.100.9"},
            follow_redirects=False,
        )
        assert r_replay.status_code == 403
        assert r_replay.json()["error"] == "forbidden_non_loopback"

        # Step 2: Follow 302 back to `/consent?ticket=...&bridge_fallback=1` -> 200 HTML with Chinese proxy banner & `<details ... open>`
        r_fb_consent = client.get(
            fallback_loc,
            headers={"Accept": BROWSER_HTML_ACCEPT, "X-Forwarded-Proto": "https"},
        )
        assert r_fb_consent.status_code == 200
        fb_html = r_fb_consent.text
        assert "检测到浏览器代理接管了 127.0.0.1 回环请求，已为您展开下方 6 位动态配对码输入框（在任务栏托盘或本地面板即可查看）" in fb_html
        assert '<details class="alt-auth-details" id="alt-auth-details" open>' in fb_html

        m_csrf2 = re.search(r'name="csrf"\s+value="([^"]+)"', fb_html)
        assert m_csrf2 is not None

        # Step 3: Submit valid 6-digit `pair_code` -> 302 OAuth `code` -> `/token` PKCE exchange succeeds
        dyn_code = provider.get_dynamic_pair_code()
        assert len(dyn_code) == 6 and dyn_code.isdigit()
        r_approve = client.post(
            f"/consent?ticket={ticket}",
            data={
                "ticket": ticket,
                "csrf": m_csrf2.group(1),
                "auth_mode": "pair_code",
                "pair_code": dyn_code,
            },
            headers={"Origin": public_base, "X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        assert r_approve.status_code == 302
        cb_loc = r_approve.headers["location"]
        assert cb_loc.startswith(redirect_uri + "?")
        cb_qs = parse_qs(urlsplit(cb_loc).query)
        assert cb_qs.get("state") == ["st_proxy_fb"]
        auth_code = cb_qs["code"][0]

        r_tok = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
            },
        )
        assert r_tok.status_code == 200
        tok_json = r_tok.json()
        assert tok_json.get("access_token")
        assert tok_json.get("refresh_token")


def test_browser_proxy_fallback_preserves_gateway_subpath_prefix(tmp_path: Path) -> None:
    public_base = "https://gw-v12-sub.workers.dev"
    port = 18398
    app, store, _ = _build_oauth_protocol_harness(tmp_path, public_base=public_base, port=port)
    redirect_uri = "https://chatgpt.com/connector_platform_oauth_redirect"
    _, challenge = _pkce_pair("sub")

    with TestClient(app, base_url=public_base, client=("127.0.0.1", 51003)) as client:
        _, ticket, csrf = _register_and_open_consent(
            client,
            public_base=public_base,
            redirect_uri=redirect_uri,
            challenge=challenge,
            state_val="st_subpath",
            extra_headers={"X-Cosmos-Public-Prefix": "/u/node42"},
        )
        r_post = client.post(
            f"/consent?ticket={ticket}",
            data={"ticket": ticket, "csrf": csrf, "auth_mode": "local_bridge"},
            headers={
                "Origin": public_base,
                "X-Forwarded-Proto": "https",
                "X-Cosmos-Public-Prefix": "/u/node42",
                "Accept": BROWSER_HTML_ACCEPT,
            },
            follow_redirects=False,
        )
        assert r_post.status_code == 302
        bridge_url = r_post.headers["location"]

        r_hijacked = client.get(
            bridge_url,
            headers={"Accept": BROWSER_HTML_ACCEPT, "X-Forwarded-For": "198.51.100.9"},
            follow_redirects=False,
        )
        assert r_hijacked.status_code == 302
        assert _count_records_of_kind(store, "local_bridge_proof") == 0
        parsed_fb = urlsplit(r_hijacked.headers["location"])
        assert f"{parsed_fb.scheme}://{parsed_fb.netloc}{parsed_fb.path}" == f"{public_base}/u/node42/consent"
        fb_qs = parse_qs(parsed_fb.query)
        assert fb_qs.get("ticket") == [ticket]
        assert fb_qs.get("bridge_fallback") == ["1"]


def test_vps_hub_consent_expands_6digit_code_and_hides_dead_loopback_bridge(tmp_path: Path) -> None:
    public_base = "https://203.0.113.88"
    port = 18096
    app, store, provider = _build_oauth_protocol_harness(
        tmp_path,
        public_base=public_base,
        port=port,
        tunnel_mode="vps_hub",
    )
    redirect_uri = "https://oauth-redirect.googleusercontent.com/r/v121vps"
    verifier, challenge = _pkce_pair("v121_vps")

    with TestClient(app, base_url=public_base, client=("127.0.0.1", 51101)) as client:
        reg = client.post(
            "/register",
            json={
                "client_name": "Gemini Web Connector",
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
        )
        assert reg.status_code in (200, 201)
        client_id = reg.json()["client_id"]

        r_auth = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "st_vps_hub_18096",
                "resource": f"{public_base}/mcp",
            },
            headers={"X-Forwarded-Proto": "https", "X-Real-IP": "198.51.100.22"},
            follow_redirects=False,
        )
        assert r_auth.status_code in (302, 303)

        r_get = client.get(
            r_auth.headers["location"],
            headers={"X-Forwarded-Proto": "https", "X-Real-IP": "198.51.100.22", "Accept": BROWSER_HTML_ACCEPT},
        )
        assert r_get.status_code == 200
        assert r_get.headers.get("referrer-policy") == "same-origin"
        # VPS :18096 mode MUST hide the guaranteed-to-fail 127.0.0.1:18096 primary button and expand 6-digit code box
        assert 'id="local-bridge-approve-btn"' not in r_get.text
        assert '<details class="alt-auth-details" id="alt-auth-details" open>' in r_get.text
        assert "云服务器主站连接验证：输入 6 位动态配对码或 20 位连接口令" in r_get.text
        assert 'id="consent-dynamic-code"' in r_get.text

        m_ticket = re.search(r'name="ticket"\s+value="([^"]+)"', r_get.text)
        m_csrf = re.search(r'name="csrf"\s+value="([^"]+)"', r_get.text)
        assert m_ticket and m_csrf
        ticket, csrf = m_ticket.group(1), m_csrf.group(1)

        # Even if a crafted/stale request submits auth_mode="local_bridge" on vps_hub, it never jumps to 127.0.0.1:18096
        r_lb_html = client.post(
            f"/consent?ticket={ticket}",
            data={"ticket": ticket, "csrf": csrf, "auth_mode": "local_bridge"},
            headers={"Origin": public_base, "X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        assert r_lb_html.status_code == 200
        assert _count_records_of_kind(store, "local_bridge_nonce") == 0
        assert '<details class="alt-auth-details" id="alt-auth-details" open>' in r_lb_html.text

        r_lb_api = client.post(
            f"/consent?ticket={ticket}",
            data={"ticket": ticket, "csrf": csrf, "auth_mode": "local_bridge"},
            headers={"Origin": public_base, "X-Forwarded-Proto": "https", "Accept": "application/json"},
            follow_redirects=False,
        )
        assert r_lb_api.status_code == 403
        assert r_lb_api.json()["reason"] == "remote_hub_requires_pair_code"

        # Approve directly using the 6-digit Studio dynamic pairing code
        dyn_code = provider.get_dynamic_pair_code()
        r_ok = client.post(
            f"/consent?ticket={ticket}",
            data={"ticket": ticket, "csrf": csrf, "auth_mode": "pair_code", "pair_code": dyn_code},
            headers={"Origin": public_base, "X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        assert r_ok.status_code == 302
        assert r_ok.headers.get("referrer-policy") == "no-referrer"
        auth_code = parse_qs(urlsplit(r_ok.headers["location"]).query)["code"][0]

        r_tok = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
            },
        )
        assert r_tok.status_code == 200
        assert r_tok.json().get("access_token")


def test_vps_oneclick_syncs_local_auth_json_via_stdin_tar_0600_and_totp_matches(tmp_path: Path, monkeypatch) -> None:
    import io
    import json
    import tarfile

    from cosmos_mcp.launcher import tunnels
    from cosmos_mcp.protocol.oauth import derive_dynamic_pair_code

    st_local = tmp_path / "local_state"
    assert not (st_local / "secrets" / "auth.json").exists()

    # Build a tiny deterministic source tar.gz so test runs in milliseconds while exercising full bundle logic
    mini_tar_buf = io.BytesIO()
    with tarfile.open(fileobj=mini_tar_buf, mode="w:gz") as tf:
        payload = b"# stub\n"
        ti = tarfile.TarInfo(name="cosmos_mcp/__init__.py")
        ti.size = len(payload)
        ti.mode = 0o644
        tf.addfile(ti, io.BytesIO(payload))
    monkeypatch.setattr(
        tunnels,
        "build_cosmos_mcp_source_tar_gz_b64",
        lambda *_a, **_kw: base64.b64encode(mini_tar_buf.getvalue()).decode("ascii"),
    )

    recorded_calls: list[tuple[str, list[str], str | None]] = []

    def _fake_ssh_runner(cmd: list[str], *, env: dict[str, str], timeout: float, stage: str, stdin_script: str | None = None):
        _ = (env, timeout)
        recorded_calls.append((stage, list(cmd), stdin_script))
        if stage == "preflight":
            return (
                0,
                json.dumps(
                    {
                        "mem_kb": 2097152,
                        "swap_created": False,
                        "cloud_provider": "aws",
                        "region": "ap-northeast-1",
                        "public_ip": "198.51.100.77",
                        "port_80_ok": True,
                        "port_443_ok": True,
                    }
                )
                + "\n",
                "",
            )
        if stage == "deploy_hub_and_caddy":
            return (0, "DEPLOY_OK\n", "")
        return (0, "", "")

    res = tunnels.provision_vps_hub_oneclick(
        host="198.51.100.77",
        ssh_user="root",
        local_port=18499,
        state_root=st_local,
        prefix="pc",
        runner_override=_fake_ssh_runner,
    )
    assert res["ok"] is True

    # 1) Local `secrets/auth.json` must have been auto-initialized
    local_auth_path = st_local / "secrets" / "auth.json"
    assert local_auth_path.is_file()
    local_auth = json.loads(local_auth_path.read_text(encoding="utf-8"))
    assert local_auth.get("password_hash") and local_auth.get("salt") and local_auth.get("local_api_token")
    node_secret = (st_local / "secrets" / "vps_node_secret.txt").read_text(encoding="utf-8").strip()

    # 2) Zero secret leakage in ANY command-line argument or return dictionary
    res_serialized = json.dumps(res, ensure_ascii=False)
    for sensitive in (
        local_auth["password_hash"],
        local_auth["salt"],
        local_auth["local_api_token"],
        node_secret,
    ):
        assert sensitive not in res_serialized
        for _st, cmd_argv, _stdin in recorded_calls:
            joined_argv = " ".join(cmd_argv)
            assert sensitive not in joined_argv

    deploy_calls = [c for c in recorded_calls if c[0] == "deploy_hub_and_caddy"]
    assert len(deploy_calls) == 1
    _, deploy_cmd, deploy_stdin = deploy_calls[0]
    assert deploy_cmd[-1] == "python3 -B -"
    assert deploy_stdin is not None
    assert "os.chmod('/var/lib/cosmos-mcp/state/secrets', 0o700)" in deploy_stdin

    m_bundle = re.search(r"base64\.b64decode\('([A-Za-z0-9+/=]+)'\)", deploy_stdin)
    assert m_bundle is not None
    bundle_doc = json.loads(base64.b64decode(m_bundle.group(1)).decode("utf-8"))
    sec_tar_bytes = base64.b64decode(bundle_doc["secrets_tar_gz_b64"])

    with tarfile.open(fileobj=io.BytesIO(sec_tar_bytes), mode="r:gz") as sec_tf:
        members = {m.name: m for m in sec_tf.getmembers()}
        assert "secrets/auth.json" in members
        assert "secrets/vps_node_secret.txt" in members
        assert members["secrets/auth.json"].mode == 0o600
        assert members["secrets/vps_node_secret.txt"].mode == 0o600
        f_auth = sec_tf.extractfile("secrets/auth.json")
        assert f_auth is not None
        synced_auth = json.loads(f_auth.read().decode("utf-8"))

    assert synced_auth == local_auth

    # 3) Verify 6-digit TOTP dynamic pairing code from local Studio matches remote VPS `/consent` 100%
    remote_store = OAuthSQLiteStore(tmp_path / "remote_vps_oauth.sqlite3")
    vps_provider = OAuthProvider(
        store=remote_store,
        base_url="https://198.51.100.77",
        password_hash=str(synced_auth["password_hash"]),
        salt=str(synced_auth["salt"]),
        tunnel_mode="vps_hub",
        local_port=18096,
    )
    fixed_ts = 1795680000.0
    local_studio_6digit = derive_dynamic_pair_code(
        str(local_auth["password_hash"]),
        str(local_auth["salt"]),
        timestamp=fixed_ts,
    )
    assert vps_provider.verify_dynamic_code(local_studio_6digit, now=fixed_ts) is True


def test_cloudflare_token_template_url_includes_zone_read_and_workers_routes_edit(tmp_path: Path, monkeypatch) -> None:
    import json

    from cosmos_mcp.launcher import cf_workers_gateway as cfgw

    parsed_tpl = urlsplit(cfgw.CLOUDFLARE_TOKEN_TEMPLATE_URL)
    assert parsed_tpl.scheme == "https" and parsed_tpl.netloc == "dash.cloudflare.com"
    qs_tpl = parse_qs(parsed_tpl.query)
    assert qs_tpl.get("accountId") == ["*"]
    assert qs_tpl.get("zoneId") == ["all"]
    perm_Raw = qs_tpl["permissionGroupKeys"][0]
    perm_list = json.loads(perm_Raw)
    perm_set = {(item["key"], item["type"]) for item in perm_list}
    assert ("workers_scripts", "edit") in perm_set
    assert ("account_settings", "read") in perm_set
    assert ("zone", "read") in perm_set
    assert ("workers_routes", "edit") in perm_set

    # Verify custom domain deployment surfaces clear 403 error if token lacks Zone:Read, and succeeds when granted
    zone_status = {"code": 403}

    def _mock_cf_api(openers, method: str, url: str, *, api_token: str, body=None, content_type: str = "application/json", timeout_sec: float = 35.0):
        _ = (openers, api_token, body, content_type, timeout_sec)
        if method == "GET" and url.endswith("/accounts"):
            return 200, {"success": True, "result": [{"id": "acc_demo_1", "name": "Demo"}]}
        if method == "GET" and url.endswith("/workers/subdomain"):
            return 200, {"success": True, "result": {"subdomain": "demo-sub"}}
        if method == "GET" and url.endswith("/workers/scripts"):
            return 200, {"success": True, "result": []}
        if method == "PUT" and "/workers/scripts/" in url:
            return 200, {"success": True, "result": {"id": "cosmos-mcp-test"}}
        if url.endswith("/subdomain") and "/workers/scripts/" in url:
            return 200, {"success": True, "result": {"enabled": True}}
        if method == "GET" and "/zones?" in url:
            if zone_status["code"] == 403:
                return 403, {"success": False, "errors": [{"code": 9109, "message": "Unauthorized to access requested resource"}]}
            return 200, {"success": True, "result": [{"id": "zone_dpdns_1", "name": "example.dpdns.org"}]}
        if method == "PUT" and url.endswith("/workers/domains"):
            return 200, {"success": True, "result": {"hostname": "mcp.example.dpdns.org"}}
        return 404, {"success": False, "errors": [{"code": 404, "message": f"Unhandled {method} {url}"}]}

    monkeypatch.setattr(cfgw, "_cf_api_call", _mock_cf_api)
    st_cf = tmp_path / "cf_state"
    res_403 = cfgw.deploy_cloudflare_workers_gateway(
        api_token="cf_tok_missing_zone_read",
        state_root=st_cf,
        custom_domain="mcp.example.dpdns.org",
    )
    assert res_403["ok"] is False
    assert res_403["status_code"] == 403
    assert res_403["error"] == "custom_domain_zones_query_failed"
    assert "Zone: Read" in res_403["message"]

    zone_status["code"] = 200
    res_ok = cfgw.deploy_cloudflare_workers_gateway(
        api_token="cf_tok_with_zone_read_and_routes_edit",
        state_root=st_cf,
        custom_domain="mcp.example.dpdns.org",
    )
    assert res_ok["ok"] is True
    assert res_ok["public_url"] == "https://mcp.example.dpdns.org"
    assert res_ok["api_token_shredded"] is True
    assert not cfgw.cloudflare_api_token_secret_path(st_cf).exists()


def test_consent_post_missing_or_null_origin_graceful_fallback_and_cross_site_403(tmp_path: Path) -> None:
    public_base = "https://gw-v121-priv.workers.dev"
    port = 18399
    app, store, provider = _build_oauth_protocol_harness(tmp_path, public_base=public_base, port=port)
    redirect_uri = "https://oauth-redirect.googleusercontent.com/r/v121priv"
    verifier, challenge = _pkce_pair("v121_priv")

    with TestClient(app, base_url=public_base, client=("127.0.0.1", 51104)) as client:
        client_id, ticket, csrf = _register_and_open_consent(
            client,
            public_base=public_base,
            redirect_uri=redirect_uri,
            challenge=challenge,
            state_val="st_priv_origin",
        )

        # 1) Cross-site foreign Origin MUST strictly return 403 across local_bridge, pair_code, password, and deny
        dyn_code = provider.get_dynamic_pair_code()
        for mode_payload in (
            {"ticket": ticket, "csrf": csrf, "auth_mode": "local_bridge"},
            {"ticket": ticket, "csrf": csrf, "auth_mode": "pair_code", "pair_code": dyn_code},
            {"ticket": ticket, "csrf": csrf, "decision": "deny"},
        ):
            r_evil_orig = client.post(
                f"/consent?ticket={ticket}",
                data=mode_payload,
                headers={
                    "Origin": "https://evil.example",
                    "X-Forwarded-Proto": "https",
                    "Accept": BROWSER_HTML_ACCEPT,
                },
                follow_redirects=False,
            )
            assert r_evil_orig.status_code == 403
            assert r_evil_orig.headers.get("x-consent-result") == "origin_mismatch"
            assert _count_records_of_kind(store, "local_bridge_nonce") == 0
            assert _count_records_of_kind(store, "code") == 0

        # 2) Sandboxed cross-site iframe (`Origin: null` + `Sec-Fetch-Site: cross-site`) or foreign `Referer` MUST strictly 403
        r_cross_site = client.post(
            f"/consent?ticket={ticket}",
            data={"ticket": ticket, "csrf": csrf, "auth_mode": "pair_code", "pair_code": dyn_code},
            headers={
                "Origin": "null",
                "Sec-Fetch-Site": "cross-site",
                "X-Forwarded-Proto": "https",
                "Accept": BROWSER_HTML_ACCEPT,
            },
            follow_redirects=False,
        )
        assert r_cross_site.status_code == 403
        assert r_cross_site.headers.get("x-consent-result") == "origin_mismatch"

        r_foreign_ref = client.post(
            f"/consent?ticket={ticket}",
            data={"ticket": ticket, "csrf": csrf, "auth_mode": "pair_code", "pair_code": dyn_code},
            headers={
                "Referer": "https://evil.example/lure",
                "X-Forwarded-Proto": "https",
                "Accept": BROWSER_HTML_ACCEPT,
            },
            follow_redirects=False,
        )
        assert r_foreign_ref.status_code == 403
        assert r_foreign_ref.headers.get("x-consent-result") == "origin_mismatch"

        # 3) Non-HTML API request to local_bridge without Origin still returns 403 JSON
        r_api_no_orig = client.post(
            f"/consent?ticket={ticket}",
            data={"ticket": ticket, "csrf": csrf, "auth_mode": "local_bridge"},
            headers={"X-Forwarded-Proto": "https", "Accept": "application/json"},
            follow_redirects=False,
        )
        assert r_api_no_orig.status_code == 403
        assert r_api_no_orig.json()["reason"] == "origin_mismatch"

        # 4) Same-site browser POST on `local_bridge` with stripped Origin (`""` or `"null"`) gracefully re-renders 200 HTML
        #    with `<details ... open>` and preserves selected_scope / selected_ttl without burning attempts!
        for stripped_hdrs in (
            {"X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT, "Sec-Fetch-Site": "same-origin"},
            {"Origin": "null", "X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
        ):
            r_fb = client.post(
                f"/consent?ticket={ticket}",
                data={
                    "ticket": ticket,
                    "csrf": csrf,
                    "auth_mode": "local_bridge",
                    "grant_scope": "readonly",
                    "session_ttl": "2h",
                },
                headers=stripped_hdrs,
                follow_redirects=False,
            )
            assert r_fb.status_code == 200
            assert r_fb.headers.get("referrer-policy") == "same-origin"
            assert '<details class="alt-auth-details" id="alt-auth-details" open>' in r_fb.text
            assert "6 位动态配对码" in r_fb.text
            assert _count_records_of_kind(store, "local_bridge_nonce") == 0
            pending_doc = store.get("consent", ticket)
            assert pending_doc is not None
            assert int(pending_doc.get("attempts") or 0) == 0
            assert pending_doc.get("selected_scope") == "readonly"
            assert pending_doc.get("selected_ttl") == "2h"

        # 5) Submitting valid CSRF + valid 6-digit pairing code with stripped Origin & same-origin Referer succeeds (302 -> /token)
        r_approve = client.post(
            f"/consent?ticket={ticket}",
            data={
                "ticket": ticket,
                "csrf": csrf,
                "auth_mode": "pair_code",
                "pair_code": provider.get_dynamic_pair_code(),
                "grant_scope": "readonly",
                "session_ttl": "2h",
            },
            headers={
                "Referer": f"{public_base}/consent?ticket={ticket}",
                "Sec-Fetch-Site": "same-origin",
                "X-Forwarded-Proto": "https",
                "Accept": BROWSER_HTML_ACCEPT,
            },
            follow_redirects=False,
        )
        assert r_approve.status_code == 302
        assert r_approve.headers.get("referrer-policy") == "no-referrer"
        cb_qs = parse_qs(urlsplit(r_approve.headers["location"]).query)
        assert cb_qs.get("state") == ["st_priv_origin"]
        auth_code = cb_qs["code"][0]

        r_tok = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
            },
        )
        assert r_tok.status_code == 200
        assert r_tok.json().get("access_token")


def test_public_consent_local_bridge_double_click_idempotent_302_and_cross_browser_403(tmp_path: Path) -> None:
    public_base = "https://demo01fixedexample7x9k2m4p.srv.us"
    port = 18401
    app, store, _ = _build_oauth_protocol_harness(
        tmp_path,
        public_base=public_base,
        port=port,
        tunnel_mode="public_gateway",
    )
    redirect_uri = "https://oauth-redirect.googleusercontent.com/r/v121_double_click"
    verifier_a, challenge_a = _pkce_pair("v121_dc_seq")
    verifier_b, challenge_b = _pkce_pair("v121_dc_conc")

    with TestClient(app, base_url=public_base, client=("127.0.0.1", 51201)) as browser_a:
        foreign_browser = TestClient(app, base_url=public_base, client=("127.0.0.1", 51202))
        other_sess_browser = TestClient(app, base_url=public_base, client=("127.0.0.1", 51203))
        # ------------------------------------------------------------------
        # Part A: Sequential double-click (Click 1 completes `/consent/complete`, then Click 2 `POST /consent` arrives)
        # ------------------------------------------------------------------
        client_id, ticket, csrf = _register_and_open_consent(
            browser_a,
            public_base=public_base,
            redirect_uri=redirect_uri,
            challenge=challenge_a,
            state_val="st_dc_seq_1",
        )
        # Other browser opens a separate `/authorize` session so it has a valid-format but DIFFERENT `__Host-cosmos_consent_s`
        _register_and_open_consent(
            other_sess_browser,
            public_base=public_base,
            redirect_uri=redirect_uri,
            challenge=challenge_a,
            state_val="st_other_browser",
        )

        r_click1 = browser_a.post(
            f"/consent?ticket={ticket}",
            data={"ticket": ticket, "csrf": csrf, "auth_mode": "local_bridge"},
            headers={"Origin": public_base, "X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        assert r_click1.status_code == 302
        r_hop2 = browser_a.get(r_click1.headers["location"], follow_redirects=False)
        assert r_hop2.status_code == 302
        r_hop3 = browser_a.get(
            r_hop2.headers["location"],
            headers={"X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        assert r_hop3.status_code == 302
        first_cb_loc = r_hop3.headers["location"]
        first_code = parse_qs(urlsplit(first_cb_loc).query)["code"][0]
        assert store.get("consent", ticket) is None
        assert store.get("consent_result", ticket) is not None

        # Same browser clicks `#local-bridge-approve-btn` again while Google callback navigation is still in flight:
        # MUST return 302 to the exact same callback URL with `first_code` (NEVER 403!)
        r_click2 = browser_a.post(
            f"/consent?ticket={ticket}",
            data={"ticket": ticket, "csrf": csrf, "auth_mode": "local_bridge"},
            headers={"Origin": public_base, "X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        assert r_click2.status_code == 302
        assert parse_qs(urlsplit(r_click2.headers["location"]).query)["code"] == [first_code]

        # Security gates:
        # 1) Foreign browser WITHOUT `__Host-cosmos_consent_s` cookie MUST get 403
        r_no_cookie = foreign_browser.post(
            f"/consent?ticket={ticket}",
            data={"ticket": ticket, "csrf": csrf, "auth_mode": "local_bridge"},
            headers={"Origin": public_base, "X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        assert r_no_cookie.status_code == 403
        assert r_no_cookie.headers.get("x-consent-result") == "completed_submission_not_authenticated"

        # 2) Different browser with a DIFFERENT `__Host-cosmos_consent_s` cookie MUST get 403
        r_wrong_cookie = other_sess_browser.post(
            f"/consent?ticket={ticket}",
            data={"ticket": ticket, "csrf": csrf, "auth_mode": "local_bridge"},
            headers={"Origin": public_base, "X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        assert r_wrong_cookie.status_code == 403
        assert r_wrong_cookie.headers.get("x-consent-result") == "completed_submission_not_authenticated"

        # 3) Cross-site POST (`Origin: https://evil.example`) even WITH `browser_a` cookies MUST get 403 `origin_mismatch`
        r_cross_site = browser_a.post(
            f"/consent?ticket={ticket}",
            data={"ticket": ticket, "csrf": csrf, "auth_mode": "local_bridge"},
            headers={"Origin": "https://evil.example", "X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        assert r_cross_site.status_code == 403
        assert r_cross_site.headers.get("x-consent-result") == "origin_mismatch"

        # First issued `code` remains valid and exchanges cleanly for tokens!
        r_tok = browser_a.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": first_code,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_verifier": verifier_a,
            },
        )
        assert r_tok.status_code == 200
        assert r_tok.json().get("access_token")

        # Once `code` has been exchanged, same-browser duplicate `POST /consent` returns friendly 200 HTML
        r_after_exchange = browser_a.post(
            f"/consent?ticket={ticket}",
            data={"ticket": ticket, "csrf": csrf, "auth_mode": "local_bridge"},
            headers={"Origin": public_base, "X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        assert r_after_exchange.status_code == 200
        assert "授权已经提交" in r_after_exchange.text

        # ------------------------------------------------------------------
        # Part B: Concurrent in-flight double-click (two `POST /consent` mint two nonces before `/consent/complete`)
        # ------------------------------------------------------------------
        cid_b, ticket_b, csrf_b = _register_and_open_consent(
            browser_a,
            public_base=public_base,
            redirect_uri=redirect_uri,
            challenge=challenge_b,
            state_val="st_dc_conc_2",
        )
        p1 = browser_a.post(
            f"/consent?ticket={ticket_b}",
            data={"ticket": ticket_b, "csrf": csrf_b, "auth_mode": "local_bridge"},
            headers={"Origin": public_base, "X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        p2 = browser_a.post(
            f"/consent?ticket={ticket_b}",
            data={"ticket": ticket_b, "csrf": csrf_b, "auth_mode": "local_bridge"},
            headers={"Origin": public_base, "X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        assert p1.status_code == 302 and p2.status_code == 302
        assert p1.headers["location"] != p2.headers["location"]

        # Request 1 finishes full 3-hop flow while browser actually follows Request 2's redirect chain
        lb1 = browser_a.get(p1.headers["location"], follow_redirects=False)
        cc1 = browser_a.get(lb1.headers["location"], headers={"X-Forwarded-Proto": "https"}, follow_redirects=False)
        assert cc1.status_code == 302
        code_conc = parse_qs(urlsplit(cc1.headers["location"]).query)["code"][0]

        lb2 = browser_a.get(p2.headers["location"], follow_redirects=False)
        assert lb2.status_code == 302
        cc2 = browser_a.get(
            lb2.headers["location"],
            headers={"X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        assert cc2.status_code == 302
        assert parse_qs(urlsplit(cc2.headers["location"]).query)["code"] == [code_conc]

        r_tok_b = browser_a.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code_conc,
                "client_id": cid_b,
                "redirect_uri": redirect_uri,
                "code_verifier": verifier_b,
            },
        )
        assert r_tok_b.status_code == 200
        assert r_tok_b.json().get("access_token")


def test_consent_complete_tunnel_retry_idempotent_and_session_enforced(tmp_path: Path) -> None:
    public_base = "https://retry-v121.srv.us"
    port = 18402
    app, _, _ = _build_oauth_protocol_harness(tmp_path, public_base=public_base, port=port, tunnel_mode="public_gateway")
    redirect_uri = "https://oauth-redirect.googleusercontent.com/r/v121_complete_retry"
    verifier, challenge = _pkce_pair("v121_cc_retry")

    with TestClient(app, base_url=public_base, client=("127.0.0.1", 51211)) as browser_a:
        attacker_browser = TestClient(app, base_url=public_base, client=("127.0.0.1", 51212))
        client_id, ticket, csrf = _register_and_open_consent(
            browser_a,
            public_base=public_base,
            redirect_uri=redirect_uri,
            challenge=challenge,
            state_val="st_cc_retry",
        )
        r_post = browser_a.post(
            f"/consent?ticket={ticket}",
            data={"ticket": ticket, "csrf": csrf, "auth_mode": "local_bridge"},
            headers={"Origin": public_base, "X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        r_lb = browser_a.get(r_post.headers["location"], follow_redirects=False)
        assert r_lb.status_code == 302
        complete_url = r_lb.headers["location"]

        # First `GET /consent/complete` consumes `local_bridge_proof` & `consent` and issues `code`
        r_cc_1 = browser_a.get(
            complete_url,
            headers={"X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        assert r_cc_1.status_code == 302
        issued_code = parse_qs(urlsplit(r_cc_1.headers["location"]).query)["code"][0]

        # Simulate tunnel drop causing browser auto-retry of exact same `GET /consent/complete?ticket=...&proof=...`
        r_cc_retry = browser_a.get(
            complete_url,
            headers={"X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        assert r_cc_retry.status_code == 302
        assert parse_qs(urlsplit(r_cc_retry.headers["location"]).query)["code"] == [issued_code]

        # Foreign browser without matching `__Host-cosmos_consent_s` cookie MUST get 403
        r_cc_foreign = attacker_browser.get(
            complete_url,
            headers={"X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        assert r_cc_foreign.status_code == 403
        assert r_cc_foreign.headers.get("x-consent-result") == "consent_session_cookie_mismatch"

        # Tampered proof signature MUST still get 403 even with valid browser session cookie
        r_cc_forged = browser_a.get(
            f"/consent/complete?ticket={ticket}&proof=forged.bad_sig",
            headers={"X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        assert r_cc_forged.status_code == 403
        assert r_cc_forged.headers.get("x-consent-result") == "proof_invalid_or_replayed"

        # Exchange `issued_code` -> subsequent retry returns 200 HTML ("授权已经提交")
        r_tok = browser_a.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": issued_code,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
            },
        )
        assert r_tok.status_code == 200
        r_cc_after_tok = browser_a.get(
            complete_url,
            headers={"X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
            follow_redirects=False,
        )
        assert r_cc_after_tok.status_code == 200
        assert "授权已经提交" in r_cc_after_tok.text


def test_consent_html_anti_double_click_preserves_local_bridge_auth_mode(tmp_path: Path) -> None:
    from cosmos_mcp.packs.browser import _HeadlessCdpPage, find_system_chromium_binary

    public_base = "https://ux-lock-v121.srv.us"
    port = 18403
    app, _, _ = _build_oauth_protocol_harness(tmp_path, public_base=public_base, port=port, tunnel_mode="public_gateway")
    redirect_uri = "https://oauth-redirect.googleusercontent.com/r/v121_btn_lock"
    _, challenge = _pkce_pair("v121_btn_lock")

    with TestClient(app, base_url=public_base, client=("127.0.0.1", 51221)) as client:
        _, ticket, csrf = _register_and_open_consent(
            client,
            public_base=public_base,
            redirect_uri=redirect_uri,
            challenge=challenge,
            state_val="st_btn_lock",
        )
        r_get = client.get(
            f"/consent?ticket={ticket}",
            headers={"X-Forwarded-Proto": "https", "Accept": BROWSER_HTML_ACCEPT},
        )
        assert r_get.status_code == 200
        rendered_html = r_get.text

    assert "正在通过本机确认连接，请稍候…" in rendered_html
    assert 'setAttribute("data-submitting", "1")' in rendered_html
    assert "pageshow" in rendered_html
    assert "12000" in rendered_html

    browser_exe = find_system_chromium_binary()
    if browser_exe:
        html_file = tmp_path / "consent_preview.html"
        html_file.write_text(rendered_html, encoding="utf-8")
        prof_dir = tmp_path / "headless_consent_prof"
        prof_dir.mkdir(parents=True, exist_ok=True)
        cdp = _HeadlessCdpPage(
            prof_dir,
            browser_exe,
            proxy_settings={"server": "", "bypass_semicolon": ""},
            url_validator=None,
        )
        try:
            cdp.goto(html_file.as_uri())
            cdp.wait_for_timeout(80)
            probe = cdp.evaluate(
                """() => {
                    const form = document.querySelector('form');
                    const btn = document.getElementById('local-bridge-approve-btn');
                    const submissions = [];
                    form.addEventListener('submit', (ev) => {
                        const fd = new FormData(form, ev.submitter || undefined);
                        const obj = {};
                        for (const [k, v] of fd.entries()) {
                            obj[k] = v;
                        }
                        submissions.push({
                            entries: obj,
                            btnDisabledDuringSerialize: btn.disabled,
                            btnTextAfterHandler: btn.textContent.trim(),
                            dataSubmitting: form.getAttribute('data-submitting'),
                        });
                        ev.preventDefault();
                    });

                    btn.click();
                    const afterFirstClick = {
                        count: submissions.length,
                        first: submissions[0] || null,
                        hasSubmittingClass: btn.classList.contains('is-submitting'),
                        ariaDisabled: btn.getAttribute('aria-disabled'),
                    };

                    // Rapid 2nd & 3rd click + programmatic requestSubmit MUST all be blocked
                    btn.click();
                    btn.click();
                    if (typeof form.requestSubmit === 'function') {
                        form.requestSubmit(btn);
                    }
                    const countAfterSpam = submissions.length;

                    // Simulate bfcache `pageshow` restore -> button unlocks and restores original label
                    window.dispatchEvent(new Event('pageshow'));
                    const afterPageShow = {
                        dataSubmitting: form.getAttribute('data-submitting'),
                        hasSubmittingClass: btn.classList.contains('is-submitting'),
                        restoredText: btn.textContent.trim(),
                    };

                    btn.click();
                    return {
                        afterFirstClick,
                        countAfterSpam,
                        afterPageShow,
                        countAfterRestoreClick: submissions.length,
                        restoredEntries: submissions[1] ? submissions[1].entries : null,
                    };
                }"""
            )
            assert probe["afterFirstClick"]["count"] == 1
            first_sub = probe["afterFirstClick"]["first"]
            assert first_sub is not None
            assert first_sub["btnDisabledDuringSerialize"] is False
            assert first_sub["entries"].get("auth_mode") == "local_bridge"
            assert first_sub["entries"].get("ticket") == ticket
            assert first_sub["entries"].get("csrf") == csrf
            assert first_sub["btnTextAfterHandler"] == "正在通过本机确认连接，请稍候…"
            assert first_sub["dataSubmitting"] == "1"
            assert probe["afterFirstClick"]["hasSubmittingClass"] is True
            assert probe["afterFirstClick"]["ariaDisabled"] == "true"
            assert probe["countAfterSpam"] == 1
            assert probe["afterPageShow"]["dataSubmitting"] is None
            assert probe["afterPageShow"]["hasSubmittingClass"] is False
            assert probe["afterPageShow"]["restoredText"] == "本机一键允许连接（免输口令）"
            assert probe["countAfterRestoreClick"] == 2
            assert probe["restoredEntries"]["auth_mode"] == "local_bridge"
        finally:
            cdp.close()


def test_srvus_tunnel_supervisor_remembers_working_route_and_preserves_popen_contract(tmp_path: Path, monkeypatch) -> None:
    import io

    from cosmos_mcp.launcher import tunnels

    def _fast_keypair(state_root: Path, prefix: str = "pc") -> tuple[Path, str]:
        priv_p, pub_p = tunnels.srvus_ssh_key_paths(state_root, prefix=prefix)
        priv_p.parent.mkdir(parents=True, exist_ok=True)
        priv_p.write_text("FAKE_ED25519_PRIV\n", encoding="utf-8")
        pub_line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeTestKey cosmos-mcp-srvus-pc"
        pub_p.write_text(pub_line + "\n", encoding="utf-8")
        return priv_p, pub_line

    monkeypatch.setattr(tunnels, "ensure_srvus_ssh_keypair", _fast_keypair)

    # 1) Legacy `popen_factory`-only contract: zero real proxy/TCP probes, fast-fails cleanly when no URL is emitted
    st_contract = tmp_path / "srvus_contract_state"
    contract_cmds: list[list[str]] = []

    class _ContractDeadProc:
        pid = 70001

        def __init__(self) -> None:
            self.stdout = io.StringIO("Usage: ssh srv.us -R 1:localhost:3000 …\n")

        def poll(self) -> int:
            return 255

        def wait(self, timeout: float | None = None) -> int:
            _ = timeout
            return 255

        def terminate(self) -> None:
            pass

    def _dead_popen(cmd: list[str], **_kw):
        contract_cmds.append(list(cmd))
        return _ContractDeadProc()

    sup_dead = tunnels.SrvUsSshTunnelSupervisor(
        local_port=18404,
        state_root=st_contract,
        popen_factory=_dead_popen,
    )
    assert sup_dead.start(wait_url_timeout_sec=1.5) == ""
    assert len(contract_cmds) == 2
    for argv in contract_cmds:
        assert not any(a.startswith("ProxyCommand=") for a in argv)
        assert "ServerAliveInterval=15" in argv
        assert "ServerAliveCountMax=3" in argv
        assert "TCPKeepAlive=yes" in argv
    sup_dead.stop()

    # 2) Sticky route selection: once `"direct"` gets `1: https://...srv.us/`, reconnects reuse `"direct"` (even on odd `attempt_idx`!)
    #    and only switch to `"proxy"` after >= 2 consecutive failures without a URL.
    st_sticky = tmp_path / "srvus_sticky_state"
    sup_sticky = tunnels.SrvUsSshTunnelSupervisor(
        local_port=18405,
        state_root=st_sticky,
        popen_factory=_dead_popen,
        proxy_detector=lambda _scheme: "http://127.0.0.1:7896",
        tcp_prober=lambda _h, _p, _t: True,
    )

    def _has_proxy_cmd(argv: list[str]) -> bool:
        return any(a.startswith("ProxyCommand=") for a in argv)

    # Cold start (`attempt_idx=0`) with reachable direct `:22` chooses direct first
    cmd0 = sup_sticky._select_runtime_command(0)
    assert _has_proxy_cmd(cmd0) is False

    # Simulate `1: https://demo01fixedexample7x9k2m4p.srv.us/` discovered on direct route
    sup_sticky._handle_discovered_url("https://demo01fixedexample7x9k2m4p.srv.us/")
    assert sup_sticky.preferred_route == "direct"
    assert tunnels._load_srvus_route_hint(st_sticky, "pc") == "direct"

    # Subsequent idle disconnects (`attempt_idx=1, 2, 3` — including odd indices!) MUST stick to `"direct"`
    for idx in (1, 2, 3):
        cmd_reconn = sup_sticky._select_runtime_command(idx)
        assert _has_proxy_cmd(cmd_reconn) is False, f"attempt_idx={idx} unexpectedly switched to proxy!"

    # Simulate 1 transient failure on `"direct"` -> still retries `"direct"` once more before switching
    sup_sticky._route_consecutive_failures = 1
    assert _has_proxy_cmd(sup_sticky._select_runtime_command(4)) is False

    # Simulate 2 consecutive failures on `"direct"` (e.g. moved to a network blocking `:22`) -> switches to `"proxy"`!
    sup_sticky._route_consecutive_failures = 2
    cmd_failover = sup_sticky._select_runtime_command(5)
    assert _has_proxy_cmd(cmd_failover) is True

    # Once `"proxy"` succeeds with `1: https://...srv.us/`, `"proxy"` becomes the new sticky route across new instances
    sup_sticky._handle_discovered_url("https://demo01fixedexample7x9k2m4p.srv.us/")
    assert sup_sticky.preferred_route == "proxy"
    assert tunnels._load_srvus_route_hint(st_sticky, "pc") == "proxy"
    assert _has_proxy_cmd(sup_sticky._select_runtime_command(6)) is True
    assert _has_proxy_cmd(sup_sticky._select_runtime_command(7)) is True

    sup_reloaded = tunnels.SrvUsSshTunnelSupervisor(
        local_port=18405,
        state_root=st_sticky,
        popen_factory=_dead_popen,
        proxy_detector=lambda _scheme: "http://127.0.0.1:7896",
        tcp_prober=lambda _h, _p, _t: True,
    )
    assert sup_reloaded.preferred_route == "proxy"
    assert _has_proxy_cmd(sup_reloaded._select_runtime_command(0)) is True


