"""S10 Secrecy & Link Hardening Regression Suite:
1. Windows DPAPI (`CryptProtectData` / `CryptUnprotectData`) + pure-stdlib AEAD credential vault roundtrip & plaintext wipe;
2. Windows current-user-only ACL (`apply_current_user_only_acl` via 64-bit `ctypes` SID + `icacls /inheritance:r`);
3. High-entropy `/u/<24-char secret>/mcp` private endpoint path: full OAuth 2.1 + PKCE + MCP tool calls, Stealth 404 Gate on bare paths, zero-drop grace for pre-issued Bearer/refresh tokens, and instant invalidation upon rotation with `revoke_sessions=True`;
4. Studio zero-plaintext-in-HTML, zero-plaintext-on-remote-session, password/secret rotation, and loopback-only `POST /api/studio/uninstall`.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
from typing import Any, Dict, Tuple
from urllib.parse import parse_qs, urlsplit

import pytest
from starlette.testclient import TestClient

from cosmos_mcp.core.config import (
    ENDPOINT_SECRET_RE,
    WIPED_PASSWORD_PLACEHOLDER_ZH,
    apply_endpoint_secret_to_url,
    clear_endpoint_secret,
    dpapi_connection_vault_path,
    enc_connection_vault_path,
    ensure_initialized,
    generate_endpoint_secret,
    generate_readable_password,
    is_plaintext_connection_password_wiped,
    load_encrypted_connection_password,
    load_endpoint_secret,
    resolve_service_cfg_path,
    save_encrypted_connection_password,
    save_endpoint_secret,
    strip_endpoint_secret_from_url,
    wipe_plaintext_connection_password,
)
from cosmos_mcp.core.fs_tx import _get_current_windows_user_sid, apply_current_user_only_acl, atomic_write_json
from cosmos_mcp.launcher import cf_workers_gateway as cfgw
from cosmos_mcp.launcher.app import create_standalone_app
from cosmos_mcp.protocol.oauth import verify_owner_password
from cosmos_mcp.studio.routes import _extract_saved_connection_password


def _pkce_pair() -> Tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def _extract_csrf_from_html(html_text: str) -> str:
    marker = 'name="csrf" value="'
    idx = html_text.find(marker)
    assert idx != -1, f"csrf input missing in consent HTML: {html_text[:300]}"
    start = idx + len(marker)
    end = html_text.find('"', start)
    assert end != -1
    return html_text[start:end]


def _extract_boot_json_from_studio_html(html_text: str) -> Dict[str, Any]:
    m = re.search(r'<script[^>]*id="studio-boot-data"[^>]*>([\s\S]*?)</script>', html_text)
    if m:
        return json.loads(m.group(1))
    m_var = re.search(r"window\.__STUDIO_BOOT__\s*=\s*(\{[\s\S]*?\});\s*</script>", html_text)
    assert m_var is not None, "Could not locate Studio boot JSON in HTML"
    return json.loads(m_var.group(1))


def _setup_public_gateway_state(
    state_root: Path,
    workspace: Path,
    *,
    port: int,
    public_base: str = "https://sec-test.srv.us",
) -> Tuple[str, Dict[str, Any]]:
    init_res = ensure_initialized(
        product_root=state_root,
        cli_state_dir=str(state_root),
        port=port,
        workspace=str(workspace),
        tunnel_mode="public_gateway",
        public_url=public_base,
    )
    cfg_path = resolve_service_cfg_path(state_root, "pc")
    doc = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
    doc["gateways"] = {
        "instant": {"enabled": True, "submode": "public_gateway", "public_url": public_base},
        "workers_dev": {"enabled": False, "submode": "workers_dev", "public_url": "https://my-gw.demo.workers.dev"},
        "self_hosted": {"enabled": False, "submode": "vps_hub", "public_url": ""},
    }
    doc["selected_gateway"] = "instant"
    doc["tunnel_mode"] = "public_gateway"
    doc["public_base"] = public_base
    atomic_write_json(cfg_path, doc)

    d_status = state_root / "state" / "daemon_status.json"
    atomic_write_json(
        d_status,
        {
            "status": "running",
            "port": port,
            "mode": "public_gateway",
            "effective_tunnel_mode": "srv_us",
            "public_url": public_base,
            "mcp_url": f"{public_base}/mcp",
            "readonly_mcp_url": f"{public_base}/mcp/readonly",
            "tunnel_ready": True,
            "srvus_fixed_active": True,
            "gateways": {
                "instant": {
                    "enabled": True,
                    "submode": "public_gateway",
                    "effective_mode": "srv_us",
                    "phase": "ready",
                    "tunnel_ready": True,
                    "srvus_fixed_active": True,
                    "public_url": public_base,
                }
            },
        },
    )
    owner_pw = _extract_saved_connection_password(state_root, "pc")
    assert owner_pw
    return owner_pw, init_res


def _complete_oauth_password_flow(
    client: TestClient,
    *,
    issuer_base: str,
    owner_pw: str,
    prefix_path: str = "",
) -> Tuple[str, str, str]:
    """Run full OAuth 2.1 DCR + PKCE S256 + `/consent` password flow and return `(access_token, refresh_token, client_id)`."""
    redirect_uri = "https://chatgpt.com/connector_platform_oauth_redirect"
    verifier, challenge = _pkce_pair()
    state_val = "st_" + secrets.token_hex(6)

    r_reg = client.post(
        f"{prefix_path}/register",
        json={
            "client_name": "ChatGPT Web Connector",
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
    )
    assert r_reg.status_code in (200, 201), r_reg.text
    client_id = r_reg.json()["client_id"]

    r_auth = client.get(
        f"{prefix_path}/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state_val,
            "resource": f"{issuer_base}/mcp",
        },
        headers={"X-Forwarded-Proto": "https"},
        follow_redirects=False,
    )
    assert r_auth.status_code == 302, r_auth.text
    consent_loc = r_auth.headers["location"]
    if prefix_path:
        assert f"{prefix_path}/consent?" in consent_loc

    parsed_c = urlsplit(consent_loc)
    consent_req_target = f"{parsed_c.path}?{parsed_c.query}"
    r_cget = client.get(
        consent_req_target,
        headers={"Accept": "text/html", "X-Forwarded-Proto": "https"},
    )
    assert r_cget.status_code == 200, r_cget.text
    csrf_tok = _extract_csrf_from_html(r_cget.text)
    ticket = parse_qs(parsed_c.query)["ticket"][0]

    origin_only = f"{urlsplit(issuer_base).scheme}://{urlsplit(issuer_base).netloc}"
    r_cpost = client.post(
        consent_req_target,
        data={
            "ticket": ticket,
            "csrf": csrf_tok,
            "auth_mode": "password",
            "password": owner_pw,
            "grant_scope": "default",
            "session_ttl": "30d",
        },
        headers={
            "Origin": origin_only,
            "X-Forwarded-Proto": "https",
            "Accept": "text/html",
        },
        follow_redirects=False,
    )
    assert r_cpost.status_code == 302, r_cpost.text
    cb_loc = r_cpost.headers["location"]
    cb_qs = parse_qs(urlsplit(cb_loc).query)
    assert cb_qs["iss"] == [issuer_base]
    auth_code = cb_qs["code"][0]

    r_tok = client.post(
        f"{prefix_path}/token",
        data={
            "grant_type": "authorization_code",
            "code": auth_code,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
            "resource": f"{issuer_base}/mcp",
        },
        headers={"X-Forwarded-Proto": "https"},
    )
    assert r_tok.status_code == 200, r_tok.text
    tok_doc = r_tok.json()
    return str(tok_doc["access_token"]), str(tok_doc["refresh_token"]), client_id


def test_dpapi_and_stdlib_vault_roundtrip_and_wipe_plaintext(tmp_path: Path) -> None:
    st_dir = tmp_path / "state_vault"
    ws_dir = tmp_path / "ws_vault"
    ws_dir.mkdir(parents=True, exist_ok=True)

    init_doc = ensure_initialized(
        product_root=st_dir,
        cli_state_dir=str(st_dir),
        port=18901,
        workspace=str(ws_dir),
    )
    conn_file = st_dir / "连接信息_CONNECTION_INFO.txt"
    sec_conn_file = st_dir / "secrets" / "connection.txt"
    assert conn_file.is_file() and sec_conn_file.is_file()

    m_pw = re.search(r"授权页连接口令\s*:\s*([^\r\n]+)", conn_file.read_text(encoding="utf-8"))
    assert m_pw is not None
    raw_pw = m_pw.group(1).strip()
    assert verify_owner_password(raw_pw, init_doc["password_hash"], init_doc["salt"])
    # Hyphenless lowercase entry also passes
    assert verify_owner_password(raw_pw.replace("-", "").lower(), init_doc["password_hash"], init_doc["salt"])

    # Also verify 24-char password support in generator + verifier
    pw24 = generate_readable_password(24)
    assert len(pw24.replace("-", "")) == 24
    salt24 = secrets.token_bytes(16)
    hash24 = hashlib.scrypt(pw24.encode("utf-8"), salt=salt24, n=16384, r=8, p=1).hex()
    assert verify_owner_password(pw24, hash24, salt24.hex())
    assert verify_owner_password(pw24.replace("-", "").lower(), hash24, salt24.hex())

    # Verify native encrypted vault was automatically populated during `ensure_initialized`
    if sys.platform == "win32":
        dpapi_p = dpapi_connection_vault_path(st_dir, "pc")
        assert dpapi_p.is_file()
        assert raw_pw.encode("utf-8") not in dpapi_p.read_bytes()
    assert load_encrypted_connection_password(st_dir, "pc") == raw_pw

    # Verify cross-platform stdlib AEAD fallback vault + tamper detection
    st_enc = tmp_path / "state_stdlib_enc"
    enc_p = save_encrypted_connection_password(st_enc, "ABCD2-EFGH3-JKLM4-NPQR5", prefix="pc", force_stdlib_enc=True)
    assert enc_p == enc_connection_vault_path(st_enc, "pc")
    assert b"ABCD2" not in enc_p.read_bytes()
    assert load_encrypted_connection_password(st_enc, "pc") == "ABCD2-EFGH3-JKLM4-NPQR5"

    tampered_doc = json.loads(enc_p.read_text(encoding="utf-8"))
    tampered_doc["tag"] = "0" * 64
    enc_p.write_text(json.dumps(tampered_doc), encoding="utf-8")
    assert load_encrypted_connection_password(st_enc, "pc") == ""

    # Wipe plaintext password lines from CONNECTION_INFO & secrets/connection.txt
    assert is_plaintext_connection_password_wiped(st_dir, "pc") is False
    wipe_res = wipe_plaintext_connection_password(st_dir, "pc")
    assert wipe_res["ok"] is True
    assert is_plaintext_connection_password_wiped(st_dir, "pc") is True

    for tf in (conn_file, sec_conn_file):
        content_after = tf.read_text(encoding="utf-8")
        assert raw_pw not in content_after
        assert WIPED_PASSWORD_PLACEHOLDER_ZH in content_after

    # Studio helper & vault decryptor still recover exact password with zero disk plaintext!
    assert load_encrypted_connection_password(st_dir, "pc") == raw_pw
    assert _extract_saved_connection_password(st_dir, "pc") == raw_pw

    # Subsequent `ensure_initialized` preserves wiped mode (does not re-leak plaintext to text files)
    ensure_initialized(product_root=st_dir, cli_state_dir=str(st_dir), port=18901, workspace=str(ws_dir))
    assert raw_pw not in conn_file.read_text(encoding="utf-8")
    assert _extract_saved_connection_password(st_dir, "pc") == raw_pw


def test_windows_current_user_only_acl_real_icacls(tmp_path: Path) -> None:
    sec_dir = tmp_path / "acl_secrets_dir"
    sec_dir.mkdir(parents=True, exist_ok=True)
    sec_file = sec_dir / "auth.json"
    sec_file.write_text('{"secret": 1}\n', encoding="utf-8")

    assert apply_current_user_only_acl(sec_dir, force_win_acl=True) is True
    assert apply_current_user_only_acl(sec_file, force_win_acl=True) is True

    if sys.platform == "win32":
        cur_sid = _get_current_windows_user_sid()
        assert cur_sid.startswith("S-1-")
        sys_root = os.environ.get("SystemRoot") or r"C:\Windows"
        icacls_exe = str(Path(sys_root) / "System32" / "icacls.exe")
        proc = subprocess.run(
            [icacls_exe, str(sec_file)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10.0,
            check=True,
            creationflags=0x08000000,
        )
        out_txt = proc.stdout.decode("mbcs", errors="replace")
        out_low = out_txt.lower()
        assert "(i)" not in out_low, f"Expected inheritance removed, got: {out_txt}"
        assert "everyone" not in out_low
        assert "builtin\\users" not in out_low
        assert "(f)" in out_low
    else:
        assert stat.S_IMODE(sec_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE(sec_file.stat().st_mode) == 0o600


def test_endpoint_secret_url_helper_and_stealth_404_full_oauth_grace_and_revocation(tmp_path: Path) -> None:
    ep_sec = generate_endpoint_secret()
    assert ENDPOINT_SECRET_RE.fullmatch(ep_sec) is not None

    assert apply_endpoint_secret_to_url("https://node1.srv.us", ep_sec) == f"https://node1.srv.us/u/{ep_sec}"
    assert apply_endpoint_secret_to_url("https://my-gw.sub.workers.dev", ep_sec) == f"https://my-gw.sub.workers.dev/u/{ep_sec}"
    assert apply_endpoint_secret_to_url("https://quick.trycloudflare.com", ep_sec) == f"https://quick.trycloudflare.com/u/{ep_sec}"
    assert apply_endpoint_secret_to_url("https://203.0.113.88", ep_sec) == f"https://203.0.113.88/u/{ep_sec}"
    assert apply_endpoint_secret_to_url("https://mcp.my-domain.com", ep_sec) == f"https://mcp.my-domain.com/u/{ep_sec}"

    ep_sec2 = generate_endpoint_secret()
    assert (
        apply_endpoint_secret_to_url(f"https://mcp.my-domain.com/u/{ep_sec}", ep_sec2, previous_secret=ep_sec)
        == f"https://mcp.my-domain.com/u/{ep_sec2}"
    )
    # Multi-tenant fixed public gateway with 16-hex `node_id` preserves its `/u/<node_id>` routing
    assert (
        apply_endpoint_secret_to_url("https://shared-hub.cosmos.example.org/u/0123456789abcdef", ep_sec)
        == "https://shared-hub.cosmos.example.org/u/0123456789abcdef"
    )
    assert strip_endpoint_secret_from_url(f"https://my-gw.sub.workers.dev/u/{ep_sec2}", ep_sec2) == "https://my-gw.sub.workers.dev"

    # Full end-to-end protocol verification
    st_root = tmp_path / "state_stealth"
    ws_dir = tmp_path / "ws_stealth"
    ws_dir.mkdir(parents=True, exist_ok=True)
    port = 18902
    public_base = "https://sec-test.srv.us"
    owner_pw, _ = _setup_public_gateway_state(st_root, ws_dir, port=port, public_base=public_base)

    app = create_standalone_app(state_dir=str(st_root), port=port, workspace=str(ws_dir))
    with TestClient(app, raise_server_exceptions=True) as _lifespan_holder:
        _ = _lifespan_holder
        pub_client = TestClient(app, base_url=public_base, raise_server_exceptions=True)
        lb_client = TestClient(app, base_url=f"http://127.0.0.1:{port}", client=("127.0.0.1", 52100), raise_server_exceptions=True)

        # 1) Pre-secret OAuth session on bare `/mcp`
        legacy_at, legacy_rt, legacy_cid = _complete_oauth_password_flow(
            pub_client,
            issuer_base=public_base,
            owner_pw=owner_pw,
            prefix_path="",
        )
        r_leg_ok = pub_client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {legacy_at}", "Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
        assert r_leg_ok.status_code == 200, r_leg_ok.text

        # 2) Enable 24-char endpoint secret via Studio API (without revoking active sessions)
        st_init = lb_client.get("/api/studio/state").json()
        csrf = st_init["csrf_token"]
        assert st_init["connection"]["mcp_url"] == f"{public_base}/mcp"
        assert st_init["connection"]["endpoint_secret_enabled"] is False

        r_rot = lb_client.post(
            "/api/studio/connection",
            json={"action": "rotate_endpoint_secret", "revoke_sessions": False, "csrf": csrf},
            headers={"Origin": f"http://127.0.0.1:{port}"},
        )
        assert r_rot.status_code == 200, r_rot.text
        rot_doc = r_rot.json()
        assert rot_doc["connection"]["endpoint_secret_enabled"] is True
        assert "••••" in rot_doc["connection"]["endpoint_secret_masked"]

        active_sec = load_endpoint_secret(st_root, "pc")
        assert ENDPOINT_SECRET_RE.fullmatch(active_sec) is not None
        assert rot_doc["connection"]["mcp_url"] == f"{public_base}/u/{active_sec}/mcp"
        assert rot_doc["connection"]["readonly_mcp_url"] == f"{public_base}/u/{active_sec}/mcp/readonly"
        # `workers_dev` configured URL was also updated with `/u/<active_sec>`
        assert rot_doc["connection"]["workers_dev_url"] == f"https://my-gw.demo.workers.dev/u/{active_sec}"

        # 3) Stealth 404 Gate: ALL unauthenticated bare paths & wrong-secret paths return plain-text 404 with zero MCP headers!
        for method, bare_path in (
            ("POST", "/mcp"),
            ("GET", "/mcp"),
            ("POST", "/mcp/readonly"),
            ("GET", "/.well-known/oauth-protected-resource"),
            ("GET", "/.well-known/oauth-protected-resource/mcp"),
            ("GET", "/.well-known/oauth-authorization-server"),
            ("POST", "/register"),
            ("GET", "/authorize"),
            ("GET", "/consent"),
            ("GET", "/healthz"),
            ("GET", "/skill"),
            ("GET", "/"),
            ("POST", "/u/wrongsecret0000000000000/mcp"),
            ("GET", "/.well-known/oauth-authorization-server/u/wrongsecret0000000000000"),
        ):
            r_probe = pub_client.request(method, bare_path, headers={"Accept": "text/html, application/json"})
            assert r_probe.status_code == 404, f"Expected stealth 404 on {method} {bare_path}, got {r_probe.status_code}"
            assert "www-authenticate" not in {k.lower() for k in r_probe.headers.keys()}
            assert "mcp-session-id" not in {k.lower() for k in r_probe.headers.keys()}
            assert r_probe.headers.get("content-type", "").startswith("text/plain")

        # 4) Smooth Zero-Drop Grace: previously issued Bearer token & refresh token keep working without interruption!
        r_grace_mcp = pub_client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {legacy_at}", "Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert r_grace_mcp.status_code == 200, r_grace_mcp.text

        r_grace_ref = pub_client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": legacy_rt, "client_id": legacy_cid},
            headers={"X-Forwarded-Proto": "https"},
        )
        assert r_grace_ref.status_code == 200, r_grace_ref.text
        refreshed_legacy_at = r_grace_ref.json()["access_token"]
        assert refreshed_legacy_at

        # 5) Full OAuth 2.1 + PKCE + MCP tool execution on `/u/<active_sec>/mcp`
        sec_pfx = f"/u/{active_sec}"
        sec_issuer = f"{public_base}{sec_pfx}"

        r_401 = pub_client.post(
            f"{sec_pfx}/mcp",
            headers={"Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": {}},
        )
        assert r_401.status_code == 401
        assert f'resource_metadata="{public_base}/.well-known/oauth-protected-resource{sec_pfx}/mcp"' in r_401.headers.get(
            "www-authenticate", ""
        )

        r_pr = pub_client.get(f"/.well-known/oauth-protected-resource{sec_pfx}/mcp")
        assert r_pr.status_code == 200, r_pr.text
        assert r_pr.json()["resource"] == f"{sec_issuer}/mcp"
        assert r_pr.json()["authorization_servers"] == [sec_issuer]

        r_as = pub_client.get(f"/.well-known/oauth-authorization-server{sec_pfx}")
        assert r_as.status_code == 200, r_as.text
        as_doc = r_as.json()
        assert as_doc["issuer"] == sec_issuer
        assert as_doc["registration_endpoint"] == f"{sec_issuer}/register"
        assert as_doc["authorization_endpoint"] == f"{sec_issuer}/authorize"
        assert as_doc["token_endpoint"] == f"{sec_issuer}/token"

        sec_at, _, _ = _complete_oauth_password_flow(
            pub_client,
            issuer_base=sec_issuer,
            owner_pw=owner_pw,
            prefix_path=sec_pfx,
        )
        r_call = pub_client.post(
            f"{sec_pfx}/mcp",
            headers={"Authorization": f"Bearer {sec_at}", "Accept": "application/json, text/event-stream"},
            json={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "pc_get_status", "arguments": {}},
            },
        )
        assert r_call.status_code == 200, r_call.text
        rpc_res = r_call.json()["result"]
        assert rpc_res["isError"] is False
        inner_status = json.loads(rpc_res["content"][0]["text"])
        assert inner_status["ok"] is True

        # 6) Rotate endpoint secret WITH `revoke_sessions=True` -> both legacy & previous secret tokens fail immediately!
        r_rot2 = lb_client.post(
            "/api/studio/connection",
            json={"action": "rotate_endpoint_secret", "revoke_sessions": True, "csrf": csrf},
            headers={"Origin": f"http://127.0.0.1:{port}"},
        )
        assert r_rot2.status_code == 200
        next_sec = load_endpoint_secret(st_root, "pc")
        assert next_sec != active_sec

        r_old_leg = pub_client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {refreshed_legacy_at}", "Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}},
        )
        assert r_old_leg.status_code == 404

        r_old_sec = pub_client.post(
            f"{sec_pfx}/mcp",
            headers={"Authorization": f"Bearer {sec_at}", "Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 6, "method": "tools/list", "params": {}},
        )
        assert r_old_sec.status_code == 404

        r_old_on_new = pub_client.post(
            f"/u/{next_sec}/mcp",
            headers={"Authorization": f"Bearer {sec_at}", "Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}},
        )
        assert r_old_on_new.status_code == 401

        # 7) Disable endpoint secret -> restores short `/mcp` URL
        r_dis = lb_client.post(
            "/api/studio/connection",
            json={"action": "disable_endpoint_secret", "csrf": csrf},
            headers={"Origin": f"http://127.0.0.1:{port}"},
        )
        assert r_dis.status_code == 200
        assert load_endpoint_secret(st_root, "pc") == ""
        assert r_dis.json()["connection"]["mcp_url"] == f"{public_base}/mcp"
        clear_endpoint_secret(st_root, "pc")


def test_studio_zero_html_password_remote_redaction_actions_and_uninstall_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    st_root = tmp_path / "state_studio_sec"
    ws_dir = tmp_path / "ws_studio_sec"
    ws_dir.mkdir(parents=True, exist_ok=True)
    user_code_file = ws_dir / "keep_me.py"
    user_code_file.write_text("x = 42\n", encoding="utf-8")

    port = 18903
    public_base = "https://studio-sec.srv.us"
    owner_pw, _ = _setup_public_gateway_state(st_root, ws_dir, port=port, public_base=public_base)

    app = create_standalone_app(state_dir=str(st_root), port=port, workspace=str(ws_dir))
    with TestClient(app, raise_server_exceptions=True) as _lifespan_holder:
        _ = _lifespan_holder
        lb_client = TestClient(
            app,
            base_url=f"http://127.0.0.1:{port}",
            client=("127.0.0.1", 52200),
            raise_server_exceptions=True,
        )
        rem_client = TestClient(app, base_url=public_base, raise_server_exceptions=True)

        # 1) First-screen HTML (`GET /studio` & `GET /`) contains ZERO plaintext password!
        for html_path in ("/studio", "/"):
            r_html = lb_client.get(html_path, headers={"Accept": "text/html"})
            assert r_html.status_code == 200
            assert owner_pw not in r_html.text
            boot_doc = _extract_boot_json_from_studio_html(r_html.text)
            assert boot_doc["connection"]["connection_password"] == ""
            assert boot_doc["connection"]["has_saved_password"] is True

        # 2) Loopback `GET /api/studio/state` never leaks plaintext password; `reveal_password` returns it on demand
        st_lb = lb_client.get("/api/studio/state").json()
        csrf = st_lb["csrf_token"]
        assert st_lb["connection"]["connection_password"] == ""
        assert st_lb["connection"]["has_saved_password"] is True
        assert owner_pw not in json.dumps(st_lb)

        r_rev_lb = lb_client.post(
            "/api/studio/connection",
            json={"action": "reveal_password", "csrf": csrf},
            headers={"Origin": f"http://127.0.0.1:{port}"},
        )
        assert r_rev_lb.status_code == 200
        assert r_rev_lb.json()["connection_password"] == owner_pw

        # 3) Remote Studio session: even AFTER unlocking with valid owner password, `connection_password` is strictly `""`!
        st_rem_locked = rem_client.get("/api/studio/state").json()
        assert st_rem_locked["locked"] is True
        unlock_csrf = st_rem_locked["csrf_token"]

        r_unlock = rem_client.post(
            "/api/studio/unlock",
            json={"password": owner_pw, "csrf": unlock_csrf},
            headers={"Origin": public_base},
        )
        assert r_unlock.status_code == 200, r_unlock.text
        unlock_doc = r_unlock.json()
        assert unlock_doc["unlocked"] is True
        assert unlock_doc["connection"]["connection_password"] == ""
        assert unlock_doc["connection"]["has_saved_password"] is True
        assert owner_pw not in r_unlock.text

        rem_csrf = unlock_doc["csrf_token"]
        st_rem_after = rem_client.get("/api/studio/state").json()
        assert st_rem_after["unlocked"] is True
        assert st_rem_after["connection"]["connection_password"] == ""
        assert owner_pw not in json.dumps(st_rem_after)

        # Remote `reveal_password` -> 403 Forbidden
        r_rev_rem = rem_client.post(
            "/api/studio/connection",
            json={"action": "reveal_password", "csrf": rem_csrf},
            headers={"Origin": public_base},
        )
        assert r_rev_rem.status_code == 403

        # Remote `POST /api/studio/uninstall` -> 403 Forbidden even when unlocked!
        r_uninst_rem = rem_client.post(
            "/api/studio/uninstall",
            json={"purge": True, "csrf": rem_csrf},
            headers={"Origin": public_base},
        )
        assert r_uninst_rem.status_code == 403
        assert "仅允许在本机浏览器执行一键卸载" in r_uninst_rem.json()["error"]

        # 4) Loopback `wipe_plaintext_password` + `rotate_password` (preserving zero-plaintext on disk!)
        r_wipe = lb_client.post(
            "/api/studio/connection",
            json={"action": "wipe_plaintext_password", "csrf": csrf},
            headers={"Origin": f"http://127.0.0.1:{port}"},
        )
        assert r_wipe.status_code == 200
        assert r_wipe.json()["connection"]["plaintext_password_wiped"] is True
        conn_txt_wiped = (st_root / "连接信息_CONNECTION_INFO.txt").read_text(encoding="utf-8")
        assert owner_pw not in conn_txt_wiped

        r_rot_pw = lb_client.post(
            "/api/studio/connection",
            json={"action": "rotate_password", "revoke_sessions": True, "csrf": csrf},
            headers={"Origin": f"http://127.0.0.1:{port}"},
        )
        assert r_rot_pw.status_code == 200
        rot_pw_doc = r_rot_pw.json()
        assert rot_pw_doc["connection"]["connection_password"] == ""
        new_pw = rot_pw_doc["connection_password"]
        assert new_pw and new_pw != owner_pw
        assert app.state.provider.authenticate_owner(owner_pw) is False
        assert app.state.provider.authenticate_owner(new_pw) is True
        # Old remote session cookie bound to old password hash is automatically invalidated!
        assert rem_client.get("/api/studio/state").json()["locked"] is True
        # Disk text files remain wiped (0 plaintext of `new_pw` on disk!) while vault decrypts `new_pw`
        assert new_pw not in (st_root / "连接信息_CONNECTION_INFO.txt").read_text(encoding="utf-8")
        assert load_encrypted_connection_password(st_root, "pc") == new_pw

        # 5) Loopback `POST /api/studio/uninstall`: `dry_run=True` then full `purge=True` with `cf_api_token`
        r_dry = lb_client.post(
            "/api/studio/uninstall",
            json={"dry_run": True, "purge": True, "csrf": csrf},
            headers={"Origin": f"http://127.0.0.1:{port}"},
        )
        assert r_dry.status_code == 200, r_dry.text
        dry_doc = r_dry.json()
        assert dry_doc["ok"] is True and dry_doc["dry_run"] is True
        assert st_root.exists()

        cf_deleted_calls = []

        def _fake_del_cf(**kwargs: Any) -> Dict[str, Any]:
            cf_deleted_calls.append(kwargs)
            return {"ok": True, "deleted": True}

        monkeypatch.setattr(cfgw, "delete_cloudflare_workers_gateway", _fake_del_cf, raising=False)

        r_uninst = lb_client.post(
            "/api/studio/uninstall",
            json={"dry_run": False, "purge": True, "cf_api_token": "cfut_test_token_123", "csrf": csrf},
            headers={"Origin": f"http://127.0.0.1:{port}"},
        )
        assert r_uninst.status_code == 200, r_uninst.text
        u_doc = r_uninst.json()
        assert u_doc["ok"] is True
        assert u_doc["dry_run"] is False
        assert u_doc["cf_worker_cleanup"] == {"ok": True, "deleted": True}
        assert len(cf_deleted_calls) == 1
        assert not st_root.exists()
        # User workspace files must remain 100% untouched!
        assert user_code_file.is_file() and user_code_file.read_text(encoding="utf-8") == "x = 42\n"


def test_stealth_404_allows_issued_pat_bearer_on_bare_mcp_and_enforces_readonly_scope(tmp_path: Path) -> None:
    """When `/u/<endpoint_secret>` stealth 404 is enabled, valid PAT Bearer tokens pass smoothly on `/mcp` & `/mcp/readonly`."""
    st_root = tmp_path / "state_pat"
    ws_dir = tmp_path / "ws_pat"
    ws_dir.mkdir(parents=True, exist_ok=True)
    port = 18824
    public_base = "https://sec-pat.srv.us"
    workers_base = "https://my-gw.demo.workers.dev"
    _setup_public_gateway_state(st_root, ws_dir, port=port, public_base=public_base)
    cfg_p = resolve_service_cfg_path(st_root, "pc")
    cfg_d = json.loads(cfg_p.read_text(encoding="utf-8-sig"))
    cfg_d["gateways"]["workers_dev"]["enabled"] = True
    atomic_write_json(cfg_p, cfg_d)

    app = create_standalone_app(state_dir=str(st_root), port=port, workspace=str(ws_dir))
    mcp_list_req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    mcp_hdrs_base = {"Accept": "application/json, text/event-stream"}

    with TestClient(app, raise_server_exceptions=False) as _lifespan_holder:
        _ = _lifespan_holder
        lb_client = TestClient(
            app,
            base_url=f"http://127.0.0.1:{port}",
            client=("127.0.0.1", 52100),
            raise_server_exceptions=False,
        )
        rem_client = TestClient(
            app,
            base_url=public_base,
            client=("198.51.100.88", 52100),
            raise_server_exceptions=False,
        )
        wd_client = TestClient(
            app,
            base_url=workers_base,
            client=("198.51.100.89", 52101),
            raise_server_exceptions=False,
        )

        st_doc = lb_client.get("/api/studio/state").json()
        csrf = st_doc["csrf_token"]

        # Enable `/u/<endpoint_secret>` stealth 404
        r_rot = lb_client.post(
            "/api/studio/connection",
            json={"action": "rotate_endpoint_secret", "revoke_sessions": False, "csrf": csrf},
            headers={"Origin": f"http://127.0.0.1:{port}"},
        )
        assert r_rot.status_code == 200, r_rot.text
        ep_sec = load_endpoint_secret(st_root, "pc")
        assert len(ep_sec) >= 24

        # Unauthenticated or forged PAT on bare `/mcp` and `/mcp/readonly` still hits Stealth 404
        assert rem_client.post("/mcp", json=mcp_list_req, headers=mcp_hdrs_base).status_code == 404
        assert (
            rem_client.post(
                "/mcp/readonly",
                json=mcp_list_req,
                headers={**mcp_hdrs_base, "Authorization": "Bearer cmcp_forged_nonexistent_pat_token"},
            ).status_code
            == 404
        )
        assert wd_client.post("/mcp", json=mcp_list_req, headers=mcp_hdrs_base).status_code == 404

        # Mint a readonly PAT and a full-access PAT via loopback Studio endpoint
        r_ro_pat = lb_client.post(
            "/api/studio/tokens/mint",
            json={"label": "Sites RO", "readonly": True, "ttl_days": 7, "csrf": csrf},
            headers={"Origin": f"http://127.0.0.1:{port}"},
        )
        assert r_ro_pat.status_code == 200, r_ro_pat.text
        ro_tok = r_ro_pat.json()["minted_token"]["token"]

        r_rw_pat = lb_client.post(
            "/api/studio/tokens/mint",
            json={"label": "CLI RW", "readonly": False, "ttl_days": 7, "csrf": csrf},
            headers={"Origin": f"http://127.0.0.1:{port}"},
        )
        assert r_rw_pat.status_code == 200, r_rw_pat.text
        rw_mint = r_rw_pat.json()["minted_token"]
        rw_tok = rw_mint["token"]
        rw_cid = rw_mint["client_id"]

        # Readonly PAT smoothly passes Stealth 404 on bare `/mcp/readonly` AND `/u/<secret>/mcp/readonly` (including workers_dev),
        # while upward escalation to `/mcp` is blocked with 403 `forbidden_cross_resource`.
        assert (
            rem_client.post(
                "/mcp/readonly",
                json=mcp_list_req,
                headers={**mcp_hdrs_base, "Authorization": f"Bearer {ro_tok}"},
            ).status_code
            == 200
        )
        assert (
            wd_client.post(
                "/mcp/readonly",
                json=mcp_list_req,
                headers={**mcp_hdrs_base, "Authorization": f"Bearer {ro_tok}"},
            ).status_code
            == 200
        )
        assert (
            rem_client.post(
                f"/u/{ep_sec}/mcp/readonly",
                json=mcp_list_req,
                headers={**mcp_hdrs_base, "Authorization": f"Bearer {ro_tok}"},
            ).status_code
            == 200
        )
        assert (
            rem_client.post(
                "/mcp",
                json=mcp_list_req,
                headers={**mcp_hdrs_base, "Authorization": f"Bearer {ro_tok}"},
            ).status_code
            == 403
        )

        # Full PAT smoothly passes Stealth 404 on bare `/mcp` AND `/mcp/readonly` across both gateways
        assert (
            rem_client.post(
                "/mcp",
                json=mcp_list_req,
                headers={**mcp_hdrs_base, "Authorization": f"Bearer {rw_tok}"},
            ).status_code
            == 200
        )
        assert (
            wd_client.post(
                "/mcp",
                json=mcp_list_req,
                headers={**mcp_hdrs_base, "Authorization": f"Bearer {rw_tok}"},
            ).status_code
            == 200
        )
        assert (
            rem_client.post(
                "/mcp/readonly",
                json=mcp_list_req,
                headers={**mcp_hdrs_base, "Authorization": f"Bearer {rw_tok}"},
            ).status_code
            == 200
        )

        # Revoking the PAT immediately restores Stealth 404 on bare `/mcp`
        app.state.provider.store.revoke_client(rw_cid, delete_client=True)
        assert (
            rem_client.post(
                "/mcp",
                json=mcp_list_req,
                headers={**mcp_hdrs_base, "Authorization": f"Bearer {rw_tok}"},
            ).status_code
            == 404
        )


def test_chatgpt_oneclick_capability_path_e2e_accept_origin_stealth_and_revocation(tmp_path: Path) -> None:
    """Verify `/api/studio/chatgpt-oneclick` standard OAuth URL output, default-off `/c/<token>/mcp` Stealth 404, and `/u/<secret>` alignment."""
    st_root = tmp_path / "state_oc"
    ws_dir = tmp_path / "ws_oc"
    ws_dir.mkdir(parents=True, exist_ok=True)
    port = 18829
    public_base = "https://oc-demo.srv.us"
    _setup_public_gateway_state(st_root, ws_dir, port=port, public_base=public_base)

    app = create_standalone_app(state_dir=str(st_root), port=port, workspace=str(ws_dir))
    list_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    mcp_hdrs = {"Accept": "application/json, text/event-stream"}

    with TestClient(app, raise_server_exceptions=False) as _lifespan_holder:
        _ = _lifespan_holder
        lb_client = TestClient(
            app,
            base_url=f"http://127.0.0.1:{port}",
            client=("127.0.0.1", 52200),
            raise_server_exceptions=False,
        )
        rem_client = TestClient(
            app,
            base_url=public_base,
            client=("198.51.100.91", 52201),
            raise_server_exceptions=False,
        )

        st_doc = lb_client.get("/api/studio/state").json()
        csrf = st_doc["csrf_token"]

        # 1) Non-loopback caller MUST be rejected with 403 on `/api/studio/chatgpt-oneclick`
        r_rem_oc = rem_client.post(
            "/api/studio/chatgpt-oneclick",
            json={"kind": "mcp", "rotate": False, "csrf": csrf},
            headers={"Origin": public_base},
        )
        assert r_rem_oc.status_code == 403

        # 2) Loopback `/api/studio/chatgpt-oneclick` outputs standard OAuth 2.1 URLs without `/c/oc_` passwordless tokens
        r_full1 = lb_client.post(
            "/api/studio/chatgpt-oneclick",
            json={"kind": "mcp", "rotate": False, "csrf": csrf},
            headers={"Origin": f"http://127.0.0.1:{port}"},
        )
        assert r_full1.status_code == 200, r_full1.text
        d_full1 = r_full1.json()
        assert d_full1["ok"] is True
        assert d_full1["readonly"] is False
        assert d_full1["oneclick_url"] == f"{public_base}/mcp"
        assert d_full1["mcp_url"] == f"{public_base}/mcp"
        assert "/c/" not in d_full1["oneclick_url"] and "oc_" not in d_full1["oneclick_url"]
        assert "/c/" not in d_full1["prompt"] and "oc_" not in d_full1["prompt"]

        r_ro = lb_client.post(
            "/api/studio/chatgpt-oneclick",
            json={"kind": "readonly", "rotate": False, "csrf": csrf},
            headers={"Origin": f"http://127.0.0.1:{port}"},
        )
        assert r_ro.status_code == 200, r_ro.text
        d_ro = r_ro.json()
        assert d_ro["readonly"] is True
        assert d_ro["oneclick_url"] == f"{public_base}/mcp/readonly"
        assert "/c/" not in d_ro["oneclick_url"] and "oc_" not in d_ro["oneclick_url"]

        # 3) Legacy `/c/<tok>/...` capability paths are permanently removed and MUST return 404
        fake_tok = "oc_forged_invalid_token_123456789012345"
        for blocked_c_path in (
            "/c",
            f"/c/{fake_tok}/mcp",
            f"/c/{fake_tok}/mcp/readonly",
        ):
            r_c404 = rem_client.post(blocked_c_path, json=list_req, headers=mcp_hdrs)
            assert r_c404.status_code == 404, blocked_c_path
        assert rem_client.get(f"/c/{fake_tok}/studio").status_code == 404
        assert rem_client.get(f"/c/{fake_tok}/api/studio/state").status_code == 404
        assert rem_client.get(f"/c/{fake_tok}/oauth/authorize").status_code == 404

        # 4) Rotating endpoint secret enables `/u/<ep_sec>` Stealth 404 on bare `/mcp` and updates oneclick OAuth URL
        r_rot = lb_client.post(
            "/api/studio/connection",
            json={"action": "rotate_endpoint_secret", "revoke_sessions": False, "csrf": csrf},
            headers={"Origin": f"http://127.0.0.1:{port}"},
        )
        assert r_rot.status_code == 200, r_rot.text
        ep_sec = load_endpoint_secret(st_root)
        assert len(ep_sec) >= 16
        assert rem_client.post("/mcp", json=list_req, headers=mcp_hdrs).status_code == 404

        # Sync daemon observation URL with the active `/u/<ep_sec>` secret and verify updated oneclick URL
        d_status_p = st_root / "state" / "daemon_status.json"
        d_doc = json.loads(d_status_p.read_text(encoding="utf-8"))
        d_doc["public_url"] = f"{public_base}/u/{ep_sec}"
        if isinstance(d_doc.get("gateways"), dict) and isinstance(d_doc["gateways"].get("instant"), dict):
            d_doc["gateways"]["instant"]["public_url"] = f"{public_base}/u/{ep_sec}"
        d_status_p.write_text(json.dumps(d_doc), encoding="utf-8")

        r_new = lb_client.post(
            "/api/studio/chatgpt-oneclick",
            json={"kind": "mcp", "rotate": False, "csrf": csrf},
            headers={"Origin": f"http://127.0.0.1:{port}"},
        )
        assert r_new.status_code == 200, r_new.text
        d_new = r_new.json()
        assert d_new["oneclick_url"] == f"{public_base}/u/{ep_sec}/mcp"
        assert rem_client.post(f"/u/{ep_sec}/mcp", json=list_req, headers=mcp_hdrs).status_code == 401

