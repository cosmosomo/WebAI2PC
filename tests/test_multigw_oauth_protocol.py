"""Wave 7-B: Dynamic multi-gateway whitelist auth, RFC 8707 resource guards, deterministic bridge secret, and vps_hub offline PC protection."""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import secrets
from typing import Any, Dict, Tuple
from urllib.parse import parse_qs, urlsplit

import pytest
from starlette.testclient import TestClient

from cosmos_mcp.core.config import ensure_initialized, resolve_service_cfg_path
from cosmos_mcp.core.fs_tx import atomic_write_json
from cosmos_mcp.launcher.app import create_standalone_app
from cosmos_mcp.protocol.oauth import OAuthProvider, OAuthSQLiteStore

_ONE_BY_ONE_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC"
)


def _pkce_pair() -> Tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def _extract_csrf_from_html(html: str) -> str:
    marker = 'name="csrf" value="'
    idx = html.find(marker)
    assert idx != -1, f"csrf hidden input not found in HTML: {html[:400]}"
    start = idx + len(marker)
    end = html.find('"', start)
    assert end != -1
    return html[start:end]


def _write_multigw_service_cfg(
    state_root: Path,
    *,
    port: int,
    workspace: Path,
    gateways: Dict[str, Dict[str, Any]],
    selected_gateway: str = "instant",
    tunnel_mode: str = "public_gateway",
    public_base: str = "https://a.srv.us",
    extra_fields: Dict[str, Any] | None = None,
) -> Path:
    ensure_initialized(
        product_root=state_root,
        cli_state_dir=str(state_root),
        port=port,
        workspace=str(workspace),
        tunnel_mode=tunnel_mode,
        public_url=public_base,
    )
    cfg_path = resolve_service_cfg_path(state_root, "pc")
    doc = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
    doc["gateways"] = gateways
    doc["selected_gateway"] = selected_gateway
    doc["tunnel_mode"] = tunnel_mode
    doc["public_base"] = public_base
    if extra_fields:
        doc.update(extra_fields)
    atomic_write_json(cfg_path, doc)
    return cfg_path


def _tunnel_relay_headers(port: int, forwarded_host: str, proto: str = "https") -> Dict[str, str]:
    return {
        "Host": f"127.0.0.1:{port}",
        "x-cosmos-via-tunnel": "1",
        "x-forwarded-host": forwarded_host,
        "x-forwarded-proto": proto,
    }


def _direct_public_headers(public_host: str, proto: str = "https") -> Dict[str, str]:
    return {
        "Host": public_host,
        "x-forwarded-proto": proto,
    }


def test_concurrent_dual_gateway_well_known_and_401_isolation(tmp_path: Path) -> None:
    """a.srv.us (direct Host) and b.workers.dev (loopback + x-cosmos-via-tunnel + x-forwarded-host) serve isolated metadata concurrently."""
    state_root = tmp_path / "state_dual_meta"
    ws = tmp_path / "ws_dual_meta"
    ws.mkdir(parents=True, exist_ok=True)
    port = 18791
    _write_multigw_service_cfg(
        state_root,
        port=port,
        workspace=ws,
        gateways={
            "instant": {"enabled": True, "submode": "public_gateway", "public_url": "https://a.srv.us"},
            "workers_dev": {"enabled": True, "submode": "workers_dev", "public_url": "https://b.workers.dev"},
            "self_hosted": {"enabled": False, "submode": "vps_hub", "public_url": ""},
        },
        selected_gateway="instant",
        tunnel_mode="public_gateway",
        public_base="https://a.srv.us",
    )

    app = create_standalone_app(state_dir=str(state_root), port=port, workspace=str(ws))
    with TestClient(app, raise_server_exceptions=True) as client:
        def _probe_gateway(kind: str, idx: int) -> Tuple[str, int]:
            if kind == "srvus":
                hdrs = _direct_public_headers("a.srv.us")
                exp_base = "https://a.srv.us"
            else:
                hdrs = _tunnel_relay_headers(port, "b.workers.dev")
                exp_base = "https://b.workers.dev"

            r_pr = client.get("/.well-known/oauth-protected-resource", headers=hdrs)
            assert r_pr.status_code == 200, r_pr.text
            pr_doc = r_pr.json()
            assert pr_doc["resource"] == f"{exp_base}/mcp"
            assert pr_doc["authorization_servers"] == [exp_base]

            r_pr_ro = client.get("/.well-known/oauth-protected-resource/mcp/readonly", headers=hdrs)
            assert r_pr_ro.status_code == 200, r_pr_ro.text
            assert r_pr_ro.json()["resource"] == f"{exp_base}/mcp/readonly"

            r_as = client.get("/.well-known/oauth-authorization-server", headers=hdrs)
            assert r_as.status_code == 200, r_as.text
            as_doc = r_as.json()
            assert as_doc["issuer"] == exp_base
            assert as_doc["authorization_endpoint"] == f"{exp_base}/authorize"
            assert as_doc["token_endpoint"] == f"{exp_base}/token"
            assert as_doc["registration_endpoint"] == f"{exp_base}/register"

            r_mcp = client.post(
                "/mcp",
                headers={**hdrs, "Accept": "application/json, text/event-stream"},
                json={"jsonrpc": "2.0", "id": idx, "method": "initialize", "params": {}},
            )
            assert r_mcp.status_code == 401
            www_auth = r_mcp.headers.get("www-authenticate", "")
            assert f'resource_metadata="{exp_base}/.well-known/oauth-protected-resource/mcp"' in www_auth
            other_host = "b.workers.dev" if kind == "srvus" else "a.srv.us"
            assert other_host not in www_auth
            assert other_host not in r_pr.text
            assert other_host not in r_as.text
            return kind, idx

        tasks = [("srvus" if i % 2 == 0 else "workers", i) for i in range(16)]
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda item: _probe_gateway(item[0], item[1]), tasks))
        assert len(results) == 16


def test_concurrent_dual_gateway_full_oauth_local_bridge_and_mcp(tmp_path: Path) -> None:
    """Full /register -> /authorize -> /consent -> /oauth/local-bridge -> /consent/complete -> /token -> /mcp (+ /preview/{token}) across both gateways concurrently without cross-jumping."""
    state_root = tmp_path / "state_dual_flow"
    ws = tmp_path / "ws_dual_flow"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "hello_multigw.txt").write_text("multi-gateway-verified\n", encoding="utf-8")
    (ws / "dot.png").write_bytes(_ONE_BY_ONE_PNG)
    port = 18792
    _write_multigw_service_cfg(
        state_root,
        port=port,
        workspace=ws,
        gateways={
            "instant": {"enabled": True, "submode": "public_gateway", "public_url": "https://a.srv.us"},
            "workers_dev": {"enabled": True, "submode": "workers_dev", "public_url": "https://b.workers.dev"},
            "self_hosted": {"enabled": False, "submode": "vps_hub", "public_url": ""},
        },
        selected_gateway="instant",
        tunnel_mode="public_gateway",
        public_base="https://a.srv.us",
    )

    app = create_standalone_app(state_dir=str(state_root), port=port, workspace=str(ws))
    with TestClient(app, raise_server_exceptions=True) as shared_lifespan_client:
        _ = shared_lifespan_client

        def _run_full_gateway_flow(kind: str) -> Dict[str, Any]:
            if kind == "srvus":
                base_url = "https://a.srv.us"
                other_host = "b.workers.dev"
                gw_hdrs = _direct_public_headers("a.srv.us")
            else:
                base_url = "https://b.workers.dev"
                other_host = "a.srv.us"
                gw_hdrs = _tunnel_relay_headers(port, "b.workers.dev")

            redirect_uri = "https://chatgpt.com/connector_platform_oauth_redirect"
            state_val = f"st-{kind}-{secrets.token_hex(6)}"
            verifier, challenge = _pkce_pair()

            browser = TestClient(app, base_url=base_url, raise_server_exceptions=True)
            loopback_client = TestClient(
                app,
                base_url=f"http://127.0.0.1:{port}",
                client=("127.0.0.1", 51234),
                raise_server_exceptions=True,
            )

            # 1. Dynamic Client Registration
            r_reg = browser.post(
                "/register",
                headers=gw_hdrs,
                json={
                    "client_name": f"openai-mcp-{kind}",
                    "redirect_uris": [redirect_uri],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                },
            )
            assert r_reg.status_code in (200, 201), r_reg.text
            client_id = r_reg.json()["client_id"]

            # 2. GET /authorize -> 302 to /consent?ticket=...
            r_auth = browser.get(
                "/authorize",
                headers=gw_hdrs,
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": state_val,
                    "resource": f"{base_url}/mcp",
                },
                follow_redirects=False,
            )
            assert r_auth.status_code == 302, r_auth.text
            consent_loc = r_auth.headers["location"]
            assert other_host not in consent_loc
            ticket = parse_qs(urlsplit(consent_loc).query)["ticket"][0]

            # 3. GET /consent -> verify 1-click local_bridge button is rendered
            r_consent_get = browser.get(
                f"/consent?ticket={ticket}",
                headers={**gw_hdrs, "Accept": "text/html"},
                follow_redirects=False,
            )
            assert r_consent_get.status_code == 200
            assert "local-bridge-approve-btn" in r_consent_get.text
            csrf = _extract_csrf_from_html(r_consent_get.text)

            # 4. POST /consent (auth_mode=local_bridge) -> 302 to http://127.0.0.1:<port>/oauth/local-bridge
            r_consent_post = browser.post(
                "/consent",
                headers={
                    **gw_hdrs,
                    "Accept": "text/html",
                    "Origin": base_url,
                    "Referer": f"{base_url}/consent?ticket={ticket}",
                },
                data={
                    "ticket": ticket,
                    "csrf": csrf,
                    "auth_mode": "local_bridge",
                    "grant_scope": "default",
                    "session_ttl": "30d",
                },
                follow_redirects=False,
            )
            assert r_consent_post.status_code == 302, r_consent_post.text
            bridge_loc = r_consent_post.headers["location"]
            assert bridge_loc.startswith(f"http://127.0.0.1:{port}/oauth/local-bridge?")
            bridge_qs = parse_qs(urlsplit(bridge_loc).query)
            nonce = bridge_qs["nonce"][0]

            # 5. GET /oauth/local-bridge on pure loopback -> MUST 302 back to https://<same-gateway>/consent/complete!
            r_bridge = loopback_client.get(
                "/oauth/local-bridge",
                params={"ticket": ticket, "nonce": nonce},
                headers={"Host": f"127.0.0.1:{port}", "Accept": "text/html"},
                follow_redirects=False,
            )
            assert r_bridge.status_code == 302, r_bridge.text
            complete_loc = r_bridge.headers["location"]
            assert complete_loc.startswith(f"{base_url}/consent/complete?"), (
                f"Expected redirect to {base_url}/consent/complete, got {complete_loc}"
            )
            assert other_host not in complete_loc
            complete_qs = parse_qs(urlsplit(complete_loc).query)
            proof = complete_qs["proof"][0]

            # 6. GET /consent/complete on the originating gateway (carrying same-browser __Host-cosmos_consent_s cookie)
            r_complete = browser.get(
                "/consent/complete",
                params={"ticket": ticket, "proof": proof},
                headers={**gw_hdrs, "Accept": "text/html"},
                follow_redirects=False,
            )
            assert r_complete.status_code == 302, r_complete.text
            cb_loc = r_complete.headers["location"]
            cb_qs = parse_qs(urlsplit(cb_loc).query)
            assert cb_qs["state"] == [state_val]
            assert cb_qs["iss"] == [base_url]
            code = cb_qs["code"][0]

            # Verify W5-B same-browser double-click idempotency on /consent/complete vs foreign browser 403
            r_complete_dup = browser.get(
                "/consent/complete",
                params={"ticket": ticket, "proof": proof},
                headers={**gw_hdrs, "Accept": "text/html"},
                follow_redirects=False,
            )
            assert r_complete_dup.status_code == 302
            assert r_complete_dup.headers["location"] == cb_loc

            foreign_browser = TestClient(app, base_url=base_url, raise_server_exceptions=True)
            r_complete_csrf = foreign_browser.get(
                "/consent/complete",
                params={"ticket": ticket, "proof": proof},
                headers={**gw_hdrs, "Accept": "text/html"},
                follow_redirects=False,
            )
            assert r_complete_csrf.status_code == 403

            # 7. POST /token (authorization_code + explicit matching resource)
            r_tok = browser.post(
                "/token",
                headers=gw_hdrs,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "code_verifier": verifier,
                    "resource": f"{base_url}/mcp",
                },
            )
            assert r_tok.status_code == 200, r_tok.text
            tok_doc = r_tok.json()
            access_token = tok_doc["access_token"]
            refresh_token = tok_doc["refresh_token"]

            # 8. POST /mcp initialize + tools/call read_file (text + PNG preview_url domain isolation)
            mcp_hdrs = {
                **gw_hdrs,
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json, text/event-stream",
                "User-Agent": "openai-mcp/1.0.0",
            }
            r_init = browser.post(
                "/mcp",
                headers=mcp_hdrs,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "openai-mcp", "version": "1.0.0"},
                    },
                },
            )
            assert r_init.status_code == 200, r_init.text
            sess_id = r_init.headers.get("mcp-session-id", "")
            call_hdrs = {**mcp_hdrs, **({"mcp-session-id": sess_id} if sess_id else {})}
            r_call = browser.post(
                "/mcp",
                headers=call_hdrs,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "pc_read_file",
                        "arguments": {"path": "hello_multigw.txt"},
                    },
                },
            )
            assert r_call.status_code == 200, r_call.text
            assert "multi-gateway-verified" in r_call.text

            r_img = browser.post(
                "/mcp",
                headers=call_hdrs,
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "pc_read_file",
                        "arguments": {"path": "dot.png"},
                    },
                },
            )
            assert r_img.status_code == 200, r_img.text
            m_prev = re.search(r"https://[^\"\\\s]+/preview/[A-Za-z0-9._~-]+", r_img.text)
            if m_prev:
                prev_u = m_prev.group(0)
                assert prev_u.startswith(f"{base_url}/preview/"), prev_u
                assert other_host not in prev_u
                prev_path = urlsplit(prev_u).path
                r_prev_get = browser.get(prev_path, headers=gw_hdrs)
                assert r_prev_get.status_code == 200
                assert r_prev_get.headers.get("content-type", "").startswith("image/png")

            # 9. Refresh token stays bound to the same gateway resource
            r_ref = browser.post(
                "/token",
                headers=gw_hdrs,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": client_id,
                    "resource": f"{base_url}/mcp",
                },
            )
            assert r_ref.status_code == 200, r_ref.text
            return {"kind": kind, "access_token": access_token}

        with ThreadPoolExecutor(max_workers=2) as pool:
            f_a = pool.submit(_run_full_gateway_flow, "srvus")
            f_b = pool.submit(_run_full_gateway_flow, "workers")
            out_a = f_a.result()
            out_b = f_b.result()
        assert out_a["kind"] == "srvus"
        assert out_b["kind"] == "workers"
        assert out_a["access_token"] != out_b["access_token"]


def test_per_gateway_consent_mode_vps_hub_vs_workers_dev(tmp_path: Path) -> None:
    """is_remote_hub_consent_mode uses per-gateway gw.tunnel_mode so workers_dev keeps 1-click bridge while vps_hub hides it."""
    state_root = tmp_path / "state_per_gw_tm"
    ws = tmp_path / "ws_per_gw_tm"
    ws.mkdir(parents=True, exist_ok=True)
    port = 18793
    _write_multigw_service_cfg(
        state_root,
        port=port,
        workspace=ws,
        gateways={
            "instant": {"enabled": False, "submode": "public_gateway", "public_url": ""},
            "workers_dev": {"enabled": True, "submode": "workers_dev", "public_url": "https://w.workers.dev"},
            "self_hosted": {"enabled": True, "submode": "vps_hub", "public_url": "https://hub.example.com"},
        },
        selected_gateway="self_hosted",
        tunnel_mode="vps_hub",
        public_base="https://hub.example.com",
    )

    app = create_standalone_app(state_dir=str(state_root), port=port, workspace=str(ws))
    redirect_uri = "https://chatgpt.com/connector_platform_oauth_redirect"
    _, challenge = _pkce_pair()

    with TestClient(app, raise_server_exceptions=True) as client:
        for base_u, hdrs, expect_local_bridge_btn in (
            ("https://w.workers.dev", _tunnel_relay_headers(port, "w.workers.dev"), True),
            ("https://hub.example.com", _direct_public_headers("hub.example.com"), False),
        ):
            r_reg = client.post(
                "/register",
                headers=hdrs,
                json={"client_name": "Test", "redirect_uris": [redirect_uri], "token_endpoint_auth_method": "none"},
            )
            cid = r_reg.json()["client_id"]
            r_auth = client.get(
                "/authorize",
                headers=hdrs,
                params={
                    "response_type": "code",
                    "client_id": cid,
                    "redirect_uri": redirect_uri,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": "st",
                    "resource": f"{base_u}/mcp",
                },
                follow_redirects=False,
            )
            tkt = parse_qs(urlsplit(r_auth.headers["location"]).query)["ticket"][0]
            r_con = client.get(f"/consent?ticket={tkt}", headers={**hdrs, "Accept": "text/html"})
            assert r_con.status_code == 200
            if expect_local_bridge_btn:
                assert 'id="local-bridge-approve-btn"' in r_con.text
            else:
                assert 'id="local-bridge-approve-btn"' not in r_con.text


def test_host_spoofing_421_and_rfc8707_token_resource_guards(tmp_path: Path) -> None:
    """Unknown Host / untrusted tunnel X-Forwarded-Host -> 421; forged X-Forwarded-Host on public Host ignored; illegal /token resource -> 400."""
    state_root = tmp_path / "state_sec_421"
    ws = tmp_path / "ws_sec_421"
    ws.mkdir(parents=True, exist_ok=True)
    port = 18794
    _write_multigw_service_cfg(
        state_root,
        port=port,
        workspace=ws,
        gateways={
            "instant": {"enabled": True, "submode": "public_gateway", "public_url": "https://a.srv.us"},
            "workers_dev": {"enabled": True, "submode": "workers_dev", "public_url": "https://b.workers.dev"},
            "self_hosted": {"enabled": False, "submode": "vps_hub", "public_url": "https://disabled.example.com"},
        },
        selected_gateway="instant",
        tunnel_mode="public_gateway",
        public_base="https://a.srv.us",
    )

    app = create_standalone_app(state_dir=str(state_root), port=port, workspace=str(ws))
    with TestClient(app, raise_server_exceptions=True) as client:
        # 1. Branch 1: Unknown non-loopback Host -> 421 Misdirected Request
        for path in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server", "/authorize", "/mcp"):
            r_evil = client.get(path, headers={"Host": "evil.attacker.com", "X-Forwarded-Proto": "https"})
            assert r_evil.status_code == 421, (path, r_evil.status_code, r_evil.text)
            assert r_evil.json()["error"] == "invalid_host"

        # Disabled gateway Host -> 421
        r_dis = client.get("/.well-known/oauth-protected-resource", headers={"Host": "disabled.example.com"})
        assert r_dis.status_code == 421

        # 2. Branch 2: Loopback Host + tunnel marker with unknown or missing X-Forwarded-Host -> 421
        r_tun_evil = client.get(
            "/.well-known/oauth-protected-resource",
            headers=_tunnel_relay_headers(port, "evil.attacker.com"),
        )
        assert r_tun_evil.status_code == 421
        assert r_tun_evil.json()["error"] == "invalid_host"

        r_cf_missing = client.get(
            "/.well-known/oauth-protected-resource",
            headers={"Host": f"127.0.0.1:{port}", "cf-connecting-ip": "203.0.113.55"},
        )
        assert r_cf_missing.status_code == 421

        # 3. Client-forged X-Forwarded-Host on direct public Host: a.srv.us MUST be ignored (zero reflection / cross-gateway hijack)
        r_forged_xfh = client.get(
            "/.well-known/oauth-authorization-server",
            headers={"Host": "a.srv.us", "X-Forwarded-Host": "evil.attacker.com", "X-Forwarded-Proto": "https"},
        )
        assert r_forged_xfh.status_code == 200
        assert r_forged_xfh.json()["issuer"] == "https://a.srv.us"
        assert "evil.attacker.com" not in r_forged_xfh.text

        r_cross_xfh = client.get(
            "/.well-known/oauth-authorization-server",
            headers={"Host": "a.srv.us", "X-Forwarded-Host": "b.workers.dev", "X-Forwarded-Proto": "https"},
        )
        assert r_cross_xfh.status_code == 200
        assert r_cross_xfh.json()["issuer"] == "https://a.srv.us"

        # 4. RFC 8707 strict resource checks on /authorize and POST /token
        redirect_uri = "https://chatgpt.com/connector_platform_oauth_redirect"
        hdrs_a = _direct_public_headers("a.srv.us")
        browser_a = TestClient(app, base_url="https://a.srv.us", raise_server_exceptions=True)
        loopback_c = TestClient(
            app,
            base_url=f"http://127.0.0.1:{port}",
            client=("127.0.0.1", 51235),
            raise_server_exceptions=True,
        )

        r_reg = browser_a.post(
            "/register",
            headers=hdrs_a,
            json={
                "client_name": "SecClient",
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
        )
        cid = r_reg.json()["client_id"]
        _, challenge = _pkce_pair()

        # Cross-gateway resource on /authorize when arriving on Host: a.srv.us -> 400 or error redirect
        r_bad_auth_res = browser_a.get(
            "/authorize",
            headers=hdrs_a,
            params={
                "response_type": "code",
                "client_id": cid,
                "redirect_uri": redirect_uri,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "st1",
                "resource": "https://b.workers.dev/mcp",
            },
            follow_redirects=False,
        )
        assert r_bad_auth_res.status_code in (302, 400)
        if r_bad_auth_res.status_code == 302:
            assert "error=" in r_bad_auth_res.headers["location"]

        def _mint_code_on_a(resource_url: str, grant_scope: str = "default") -> Tuple[str, str]:
            ver, chal = _pkce_pair()
            r1 = browser_a.get(
                "/authorize",
                headers=hdrs_a,
                params={
                    "response_type": "code",
                    "client_id": cid,
                    "redirect_uri": redirect_uri,
                    "code_challenge": chal,
                    "code_challenge_method": "S256",
                    "state": "st-ok",
                    "resource": resource_url,
                },
                follow_redirects=False,
            )
            tkt = parse_qs(urlsplit(r1.headers["location"]).query)["ticket"][0]
            r2 = browser_a.get(f"/consent?ticket={tkt}", headers={**hdrs_a, "Accept": "text/html"})
            csrf = _extract_csrf_from_html(r2.text)
            r3 = browser_a.post(
                "/consent",
                headers={**hdrs_a, "Accept": "text/html", "Origin": "https://a.srv.us"},
                data={"ticket": tkt, "csrf": csrf, "auth_mode": "local_bridge", "grant_scope": grant_scope},
                follow_redirects=False,
            )
            nonce = parse_qs(urlsplit(r3.headers["location"]).query)["nonce"][0]
            r4 = loopback_c.get(
                "/oauth/local-bridge",
                params={"ticket": tkt, "nonce": nonce},
                headers={"Host": f"127.0.0.1:{port}", "Accept": "text/html"},
                follow_redirects=False,
            )
            proof = parse_qs(urlsplit(r4.headers["location"]).query)["proof"][0]
            r5 = browser_a.get(
                "/consent/complete",
                params={"ticket": tkt, "proof": proof},
                headers={**hdrs_a, "Accept": "text/html"},
                follow_redirects=False,
            )
            return parse_qs(urlsplit(r5.headers["location"]).query)["code"][0], ver

        # 4a. Untrusted external resource and cross-gateway resource on POST /token -> 400
        code_full, ver_full = _mint_code_on_a("https://a.srv.us/mcp")
        for bad_res in ("https://evil.attacker.com/mcp", "https://b.workers.dev/mcp", "https://disabled.example.com/mcp"):
            r_bad_tok = browser_a.post(
                "/token",
                headers=hdrs_a,
                data={
                    "grant_type": "authorization_code",
                    "code": code_full,
                    "client_id": cid,
                    "redirect_uri": redirect_uri,
                    "code_verifier": ver_full,
                    "resource": bad_res,
                },
            )
            assert r_bad_tok.status_code == 400, (bad_res, r_bad_tok.status_code, r_bad_tok.text)

        # Narrowing from /mcp -> same-gateway /mcp/readonly IS allowed and narrows scopes to server:read
        r_narrow_ok = browser_a.post(
            "/token",
            headers=hdrs_a,
            data={
                "grant_type": "authorization_code",
                "code": code_full,
                "client_id": cid,
                "redirect_uri": redirect_uri,
                "code_verifier": ver_full,
                "resource": "https://a.srv.us/mcp/readonly",
            },
        )
        assert r_narrow_ok.status_code == 200, r_narrow_ok.text
        assert r_narrow_ok.json()["scope"] == "server:read"

        # 4b. Escalating /mcp/readonly -> /mcp on POST /token (code & refresh_token) -> 400
        code_ro, ver_ro = _mint_code_on_a("https://a.srv.us/mcp/readonly", grant_scope="readonly")
        r_esc_code = browser_a.post(
            "/token",
            headers=hdrs_a,
            data={
                "grant_type": "authorization_code",
                "code": code_ro,
                "client_id": cid,
                "redirect_uri": redirect_uri,
                "code_verifier": ver_ro,
                "resource": "https://a.srv.us/mcp",
            },
        )
        assert r_esc_code.status_code == 400, r_esc_code.text

        r_ok_ro = browser_a.post(
            "/token",
            headers=hdrs_a,
            data={
                "grant_type": "authorization_code",
                "code": code_ro,
                "client_id": cid,
                "redirect_uri": redirect_uri,
                "code_verifier": ver_ro,
                "resource": "https://a.srv.us/mcp/readonly",
            },
        )
        assert r_ok_ro.status_code == 200, r_ok_ro.text
        ro_refresh = r_ok_ro.json()["refresh_token"]

        r_esc_ref = browser_a.post(
            "/token",
            headers=hdrs_a,
            data={
                "grant_type": "refresh_token",
                "refresh_token": ro_refresh,
                "client_id": cid,
                "resource": "https://a.srv.us/mcp",
            },
        )
        assert r_esc_ref.status_code == 400, r_esc_ref.text


def test_dynamic_gateway_hot_sync_add_and_disable_zero_restart(tmp_path: Path) -> None:
    """Adding/updating gateways in service.json & daemon_status.json hot-syncs trusted_gateways, allowed_hosts, and allowed_origins without restart."""
    state_root = tmp_path / "state_hotsync"
    ws = tmp_path / "ws_hotsync"
    ws.mkdir(parents=True, exist_ok=True)
    port = 18795
    cfg_path = _write_multigw_service_cfg(
        state_root,
        port=port,
        workspace=ws,
        gateways={
            "instant": {"enabled": True, "submode": "public_gateway", "public_url": "https://a.srv.us"},
            "workers_dev": {"enabled": False, "submode": "workers_dev", "public_url": ""},
            "self_hosted": {"enabled": False, "submode": "custom", "public_url": ""},
        },
        selected_gateway="instant",
        tunnel_mode="public_gateway",
        public_base="https://a.srv.us",
    )

    app = create_standalone_app(state_dir=str(state_root), port=port, workspace=str(ws))
    with TestClient(app, raise_server_exceptions=True) as client:
        assert client.get("/.well-known/oauth-protected-resource", headers=_direct_public_headers("a.srv.us")).status_code == 200
        assert client.get("/.well-known/oauth-protected-resource", headers=_tunnel_relay_headers(port, "b.workers.dev")).status_code == 421
        assert client.get("/.well-known/oauth-protected-resource", headers=_direct_public_headers("c.custom.example.com")).status_code == 421

        # Hot-enable workers_dev (with live URL in daemon_status.json) + self_hosted (in service.json) with zero restart!
        doc = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
        doc["gateways"]["workers_dev"] = {"enabled": True, "submode": "workers_dev", "public_url": ""}
        doc["gateways"]["self_hosted"] = {"enabled": True, "submode": "custom", "public_url": "https://c.custom.example.com"}
        atomic_write_json(cfg_path, doc)
        atomic_write_json(
            state_root / "state" / "daemon_status.json",
            {
                "status": "running",
                "gateways": {
                    "instant": {"enabled": True, "effective_mode": "public_gateway", "public_url": "https://a.srv.us", "tunnel_ready": True},
                    "workers_dev": {"enabled": True, "effective_mode": "workers_dev", "public_url": "https://b.workers.dev", "tunnel_ready": True},
                    "self_hosted": {"enabled": True, "effective_mode": "custom", "public_url": "https://c.custom.example.com", "tunnel_ready": True},
                },
            },
        )

        r_a = client.get("/.well-known/oauth-protected-resource", headers=_direct_public_headers("a.srv.us"))
        r_b = client.get("/.well-known/oauth-protected-resource", headers=_tunnel_relay_headers(port, "b.workers.dev"))
        r_c = client.get("/.well-known/oauth-protected-resource", headers=_direct_public_headers("c.custom.example.com"))
        assert r_a.status_code == 200 and r_a.json()["resource"] == "https://a.srv.us/mcp"
        assert r_b.status_code == 200 and r_b.json()["resource"] == "https://b.workers.dev/mcp"
        assert r_c.status_code == 200 and r_c.json()["resource"] == "https://c.custom.example.com/mcp"

        bundle = app.state.transport_bundle
        sec = getattr(bundle.main_session_manager, "security_settings", None) or getattr(
            bundle.main_session_manager, "_security_settings", None
        )
        assert "a.srv.us" in sec.allowed_hosts
        assert "b.workers.dev" in sec.allowed_hosts
        assert "c.custom.example.com" in sec.allowed_hosts
        assert "https://b.workers.dev" in sec.allowed_origins
        assert "https://c.custom.example.com" in sec.allowed_origins

        # Hot-disable self_hosted -> immediately rejected with 421 while a.srv.us and b.workers.dev stay live
        doc2 = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
        doc2["gateways"]["self_hosted"]["enabled"] = False
        atomic_write_json(cfg_path, doc2)

        assert client.get("/.well-known/oauth-protected-resource", headers=_direct_public_headers("c.custom.example.com")).status_code == 421
        assert client.get("/.well-known/oauth-protected-resource", headers=_direct_public_headers("a.srv.us")).status_code == 200
        assert client.get("/.well-known/oauth-protected-resource", headers=_tunnel_relay_headers(port, "b.workers.dev")).status_code == 200


def test_deterministic_bridge_boot_secret_survives_provider_restart(tmp_path: Path) -> None:
    """When master_seed exists, _bridge_boot_secret is deterministic across provider hot-restarts so in-flight /oauth/local-bridge succeeds."""
    state_root = tmp_path / "state_det_bridge"
    ws = tmp_path / "ws_det_bridge"
    ws.mkdir(parents=True, exist_ok=True)
    port = 18796
    _write_multigw_service_cfg(
        state_root,
        port=port,
        workspace=ws,
        gateways={
            "instant": {"enabled": False, "submode": "public_gateway", "public_url": ""},
            "workers_dev": {"enabled": True, "submode": "workers_dev", "public_url": "https://b.workers.dev"},
            "self_hosted": {"enabled": False, "submode": "vps_hub", "public_url": ""},
        },
        selected_gateway="workers_dev",
        tunnel_mode="workers_dev",
        public_base="https://b.workers.dev",
    )

    app1 = create_standalone_app(state_dir=str(state_root), port=port, workspace=str(ws))
    hdrs_b = _tunnel_relay_headers(port, "b.workers.dev")
    redirect_uri = "https://chatgpt.com/connector_platform_oauth_redirect"
    _, challenge = _pkce_pair()

    browser1 = TestClient(app1, base_url="https://b.workers.dev", raise_server_exceptions=True)
    r_reg = browser1.post(
        "/register",
        headers=hdrs_b,
        json={"client_name": "RestartTest", "redirect_uris": [redirect_uri], "token_endpoint_auth_method": "none"},
    )
    cid = r_reg.json()["client_id"]
    r_auth = browser1.get(
        "/authorize",
        headers=hdrs_b,
        params={
            "response_type": "code",
            "client_id": cid,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "st-restart",
            "resource": "https://b.workers.dev/mcp",
        },
        follow_redirects=False,
    )
    ticket = parse_qs(urlsplit(r_auth.headers["location"]).query)["ticket"][0]

    r_get = browser1.get(f"/consent?ticket={ticket}", headers={**hdrs_b, "Accept": "text/html"})
    consent_cookie = r_get.cookies.get("__Host-cosmos_consent_s") or browser1.cookies.get("__Host-cosmos_consent_s")
    assert consent_cookie
    csrf = _extract_csrf_from_html(r_get.text)
    r_post = browser1.post(
        "/consent",
        headers={**hdrs_b, "Accept": "text/html", "Origin": "https://b.workers.dev"},
        data={"ticket": ticket, "csrf": csrf, "auth_mode": "local_bridge"},
        follow_redirects=False,
    )
    assert r_post.status_code == 302
    nonce = parse_qs(urlsplit(r_post.headers["location"]).query)["nonce"][0]

    # Simulate hot restart: construct brand-new app2 on the same state_root BEFORE /oauth/local-bridge is visited!
    app2 = create_standalone_app(state_dir=str(state_root), port=port, workspace=str(ws))
    loopback2 = TestClient(
        app2,
        base_url=f"http://127.0.0.1:{port}",
        client=("127.0.0.1", 51236),
        raise_server_exceptions=True,
    )
    r_bridge = loopback2.get(
        "/oauth/local-bridge",
        params={"ticket": ticket, "nonce": nonce},
        headers={"Host": f"127.0.0.1:{port}", "Accept": "text/html"},
        follow_redirects=False,
    )
    assert r_bridge.status_code == 302, r_bridge.text
    assert r_bridge.headers["location"].startswith("https://b.workers.dev/consent/complete?")
    proof = parse_qs(urlsplit(r_bridge.headers["location"]).query)["proof"][0]

    browser2 = TestClient(app2, base_url="https://b.workers.dev", raise_server_exceptions=True)
    browser2.cookies.set("__Host-cosmos_consent_s", consent_cookie, domain="b.workers.dev", path="/")
    r_done = browser2.get(
        "/consent/complete",
        params={"ticket": ticket, "proof": proof},
        headers={**hdrs_b, "Accept": "text/html"},
        follow_redirects=False,
    )
    assert r_done.status_code == 302, r_done.text
    assert "code=" in r_done.headers["location"]

    # Seedless fallback: two standalone OAuthProviders without master_seed or auth.json fall back to distinct random secrets
    bare_dir = tmp_path / "bare_seedless"
    bare_dir.mkdir(parents=True, exist_ok=True)
    bare_store = OAuthSQLiteStore(bare_dir / "oauth_bare.sqlite3")
    p_rand_1 = OAuthProvider(store=bare_store, base_url="http://127.0.0.1:8096", password_hash="h", salt="s")
    p_rand_2 = OAuthProvider(store=bare_store, base_url="http://127.0.0.1:8096", password_hash="h", salt="s")
    assert p_rand_1._bridge_boot_secret != p_rand_2._bridge_boot_secret


def test_vps_hub_offline_pc_node_list_dir_dot_returns_err_node_offline(tmp_path: Path) -> None:
    """In vps_hub mode, calling list_dir('.') / list_dir() when child PC node is offline returns ERR_NODE_OFFLINE instead of silent empty Linux dir."""
    import asyncio

    async def _run() -> None:
        state_root = tmp_path / "state_vps_offline"
        empty_hub_ws = tmp_path / "var" / "lib" / "cosmos-mcp-hub"
        empty_hub_ws.mkdir(parents=True, exist_ok=True)
        port = 18797
        _write_multigw_service_cfg(
            state_root,
            port=port,
            workspace=empty_hub_ws,
            gateways={
                "instant": {"enabled": False, "submode": "public_gateway", "public_url": ""},
                "workers_dev": {"enabled": False, "submode": "workers_dev", "public_url": ""},
                "self_hosted": {"enabled": True, "submode": "vps_hub", "public_url": "https://hub.example.com"},
            },
            selected_gateway="self_hosted",
            tunnel_mode="vps_hub",
            public_base="https://hub.example.com",
            extra_fields={"vps_node_secret": "sec-" + secrets.token_hex(16)},
        )

        app = create_standalone_app(
            state_dir=str(state_root),
            port=port,
            workspace=str(empty_hub_ws),
            tunnel_mode="vps_hub",
        )
        disp = app.state.dispatcher
        try:
            # 1. Cold-boot vps_hub with paired secret and stock /var/lib/cosmos-mcp-hub workspace:
            #    list_dir(path="."), list_dir() (no path), pc_list_dir(path="."), and target="pc" MUST all return ERR_NODE_OFFLINE!
            for tool_nm, call_args in (
                ("list_dir", {"path": "."}),
                ("list_dir", {}),
                ("pc_list_dir", {"path": "."}),
                ("find_files", {"path": ".", "target": "pc"}),
            ):
                out_raw, is_err = await disp.call_tool_raw(tool_nm, dict(call_args))
                assert is_err is True, (tool_nm, call_args, out_raw)
                assert isinstance(out_raw, dict)
                assert out_raw.get("ok") is False
                assert out_raw.get("error_code") == "ERR_NODE_OFFLINE"
                assert out_raw.get("target") == "pc"

            # 2. Bound PC request (bound_node_id="pc") while PC is offline returns ERR_NODE_OFFLINE
            (empty_hub_ws / "hub_readme.txt").write_text("hub local file\n", encoding="utf-8")
            out_bound, is_err_bound = await disp.call_tool_raw("list_dir", {"path": "."}, bound_node_id="pc")
            assert is_err_bound is True
            assert out_bound["error_code"] == "ERR_NODE_OFFLINE"
            assert out_bound["target"] == "pc"

            # 3. Explicit target="hub" accesses the VPS hub local directory cleanly when needed
            out_hub, is_err_hub = await disp.call_tool_raw("list_dir", {"path": ".", "target": "hub"})
            assert is_err_hub is False
            assert out_hub.get("ok") is True
        finally:
            app.state.watchdog.stop()

    asyncio.run(_run())
