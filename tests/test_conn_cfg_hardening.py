"""Regression suite for Connection, Configuration & Multi-Gateway Protocol Hardening."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import struct
import threading
from typing import Any, Dict

from starlette.testclient import TestClient

from cosmos_mcp.core.config import (
    LiveRuntimePolicy,
    _load_or_create_master_seed,
    ensure_initialized,
    load_safe_state_dotenv,
)
from cosmos_mcp.core.fs_tx import atomic_write_json, atomic_write_text
from cosmos_mcp.core.net_power import StdlibWebSocketClient, build_ssrf_safe_openers
from cosmos_mcp.launcher.app import create_standalone_app
from cosmos_mcp.launcher.autostart import _extract_state_dir_from_cmd
from cosmos_mcp.launcher.bootstrap import STRICT_CORE_IMPORTS
from cosmos_mcp.launcher.cf_workers_gateway import (
    export_identity_recovery_png,
    import_identity_recovery_png,
    pack_tunnel_frame,
    save_workers_custom_domain_local,
    unpack_tunnel_frame,
    workers_tunnel_secret_path,
)
from cosmos_mcp.launcher.cli import SUPPORTED_TUNNEL_MODES
from cosmos_mcp.launcher.doctor import redact_text
from cosmos_mcp.launcher.tunnels import (
    TRYCLOUDFLARE_URL_RE,
    VpsWssNodeSupervisor,
    build_vps_hub_caddy_site_snippet,
    hot_refresh_public_url,
)
from cosmos_mcp.protocol.oauth_web import CONSENT_SESSION_COOKIE_HTTPS


def test_dotenv_loading_env_tier_lock_and_master_seed_unification(tmp_path: Path, monkeypatch: Any) -> None:
    state_root = tmp_path / "state_cfg"
    ws_root = tmp_path / "ws_cfg"
    ws_root.mkdir(parents=True, exist_ok=True)
    ensure_initialized(product_root=state_root, port=18811, cli_state_dir=str(state_root))

    dotenv_file = state_root / ".env"
    atomic_write_text(
        dotenv_file,
        "COSMOS_CLOUDFLARED_MIRROR=https://mirror.example.com/cloudflared\n"
        "EVIL_UNSAFE_KEY=should_be_ignored\n",
    )
    monkeypatch.delenv("COSMOS_CLOUDFLARED_MIRROR", raising=False)
    monkeypatch.delenv("EVIL_UNSAFE_KEY", raising=False)
    applied = load_safe_state_dotenv(state_root)
    assert applied.get("COSMOS_CLOUDFLARED_MIRROR") == "https://mirror.example.com/cloudflared"
    assert "EVIL_UNSAFE_KEY" not in os.environ

    # Startup env lock (`LOCALPC_PERMISSION_TIER=L1`) must never escalate via runtime os.environ mutation
    monkeypatch.delenv("COSMOS_PERMISSION_TIER", raising=False)
    monkeypatch.setenv("LOCALPC_PERMISSION_TIER", "tier1_readonly")
    pol = LiveRuntimePolicy(workspace=str(ws_root), state_root=state_root, product_root=state_root)
    assert pol.tier_key == "tier1_readonly"
    monkeypatch.setenv("COSMOS_PERMISSION_TIER", "tier4_full_disk")
    monkeypatch.setenv("LOCALPC_PERMISSION_TIER", "tier4_full_disk")
    pol.refresh(force=True)
    assert pol.tier_key == "tier1_readonly"

    # Unified 32-byte master_seed.bin <-> master_seed sync
    seed_bytes = _load_or_create_master_seed(state_root / "secrets")
    assert len(seed_bytes) == 32
    assert (state_root / "secrets" / "master_seed.bin").read_bytes() == seed_bytes
    assert bytes.fromhex((state_root / "secrets" / "master_seed").read_text(encoding="ascii").strip()) == seed_bytes


def test_bootstrap_cli_doctor_and_autostart_guards(tmp_path: Path) -> None:
    assert "websockets" in STRICT_CORE_IMPORTS
    assert "cryptography" in STRICT_CORE_IMPORTS
    assert "openssh" in SUPPORTED_TUNNEL_MODES
    assert "srv_us" in SUPPORTED_TUNNEL_MODES
    assert "trycloudflare" in SUPPORTED_TUNNEL_MODES
    assert "cf_workers" in SUPPORTED_TUNNEL_MODES
    assert "cloudflare_workers" in SUPPORTED_TUNNEL_MODES
    assert "reverse_proxy" in SUPPORTED_TUNNEL_MODES

    from cosmos_mcp.core.config import mode_to_gateway_slot, normalize_gateways_config
    from cosmos_mcp.launcher.cli import ensure_standalone_state
    from cosmos_mcp.launcher.daemon import StandaloneSupervisorLoop, normalize_instant_policy
    from cosmos_mcp.launcher.doctor import _discover_gateway_slots_for_probe
    from cosmos_mcp.studio.routes import (
        ALL_SUPPORTED_TUNNEL_MODES,
        TUNNEL_MODE_LABELS_ZH,
        _normalize_instant_policy,
        _normalize_studio_gateways_cfg,
        _slot_and_submode_for_tunnel_mode,
    )

    assert mode_to_gateway_slot("openssh") == ("instant", "public_gateway")
    assert mode_to_gateway_slot("trycloudflare") == ("instant", "cloudflare")
    assert mode_to_gateway_slot("cf_workers") == ("workers_dev", "workers_dev")
    assert mode_to_gateway_slot("cloudflare_workers") == ("workers_dev", "workers_dev")
    assert mode_to_gateway_slot("reverse_proxy") == ("self_hosted", "custom")

    gws_openssh, sel_openssh = normalize_gateways_config(
        {
            "tunnel_mode": "openssh",
            "gateways": {"instant": {"enabled": True, "submode": "openssh", "public_url": "https://demo99.srv.us"}},
        }
    )
    assert sel_openssh == "instant"
    assert gws_openssh["instant"]["enabled"] is True
    assert gws_openssh["instant"]["submode"] == "public_gateway"
    assert gws_openssh["instant"]["public_url"] == "https://demo99.srv.us"
    assert normalize_instant_policy("openssh_only") == "srv_us_only"
    assert normalize_instant_policy("openssh_fixed") == "srv_us_only"

    # Symmetric normalization for `trycloudflare`, `trycloudflare_only`, `cf_workers`, `cloudflare_workers`, `reverse_proxy`
    gws_trycf, sel_trycf = normalize_gateways_config(
        {
            "tunnel_mode": "trycloudflare",
            "instant_policy": "trycloudflare_only",
            "gateways": {"instant": {"enabled": True, "submode": "trycloudflare"}},
        }
    )
    assert sel_trycf == "instant"
    assert gws_trycf["instant"]["enabled"] is True
    assert gws_trycf["instant"]["submode"] == "cloudflare"
    assert gws_trycf["instant"]["instant_policy"] == "quick_only"
    assert normalize_instant_policy("trycloudflare_only") == "quick_only"
    assert normalize_instant_policy("", submode="trycloudflare") == "quick_only"
    assert _normalize_instant_policy("trycloudflare_only") == "quick_only"
    assert _normalize_instant_policy("", submode="trycloudflare") == "quick_only"

    alias_state = tmp_path / "state_trycf"
    alias_ws = tmp_path / "ws_trycf"
    alias_ws.mkdir(parents=True, exist_ok=True)
    ensure_initialized(product_root=alias_state, port=18821, cli_state_dir=str(alias_state))
    pol_probe = LiveRuntimePolicy(workspace=str(alias_ws), state_root=alias_state, product_root=alias_state)
    pol_probe.gateways = {}

    for alias_mode, expected_slot_sub in (
        ("trycloudflare", ("instant", "cloudflare")),
        ("cf_workers", ("workers_dev", "workers_dev")),
        ("cloudflare_workers", ("workers_dev", "workers_dev")),
        ("reverse_proxy", ("self_hosted", "custom")),
    ):
        assert alias_mode in ALL_SUPPORTED_TUNNEL_MODES
        assert alias_mode in TUNNEL_MODE_LABELS_ZH
        assert _slot_and_submode_for_tunnel_mode(alias_mode) == expected_slot_sub
        doc_slots = {
            s["gateway_id"]: s
            for s in _discover_gateway_slots_for_probe(tmp_path, "pc", {"tunnel_mode": alias_mode}, {})
        }
        assert doc_slots[expected_slot_sub[0]]["enabled"] is True
        assert doc_slots[expected_slot_sub[0]]["submode"] == expected_slot_sub[1]
        gws_alias, sel_alias = normalize_gateways_config({"tunnel_mode": alias_mode})
        assert sel_alias == expected_slot_sub[0]
        assert gws_alias[expected_slot_sub[0]]["submode"] == expected_slot_sub[1]
        st_gws, st_sel, _ = _normalize_studio_gateways_cfg(pol_probe, {"tunnel_mode": alias_mode})
        assert st_sel == expected_slot_sub[0]
        assert st_gws[expected_slot_sub[0]]["submode"] == expected_slot_sub[1]

    # Verify CLI `ensure_standalone_state`, `update_gateway_slot`, and `StandaloneSupervisorLoop` normalize aliases cleanly
    import sys

    ensure_standalone_state(
        alias_state,
        port=18821,
        workspace_roots=[str(alias_ws)],
        tunnel_mode="trycloudflare",
        prefix="pc",
    )
    svc_doc = json.loads((alias_state / "config" / "service.json").read_text(encoding="utf-8"))
    assert svc_doc["tunnel_mode"] == "cloudflare"
    assert svc_doc["gateways"]["instant"]["submode"] == "cloudflare"

    for cli_alias, canon_tm in (("cf_workers", "workers_dev"), ("cloudflare_workers", "workers_dev")):
        ensure_standalone_state(
            alias_state,
            port=18821,
            workspace_roots=[str(alias_ws)],
            tunnel_mode=cli_alias,
            public_url="https://demo-fixed.sub.workers.dev",
            prefix="pc",
        )
        svc_cf = json.loads((alias_state / "config" / "service.json").read_text(encoding="utf-8"))
        assert svc_cf["tunnel_mode"] == canon_tm
        assert svc_cf["gateways"]["workers_dev"]["submode"] == "workers_dev"

    pol_alias = LiveRuntimePolicy(workspace=str(alias_ws), state_root=alias_state, product_root=alias_state)
    pol_alias.update_gateway_slot("instant", enabled=True, submode="trycloudflare", select=True)
    assert pol_alias.gateways["instant"]["submode"] == "cloudflare"
    assert pol_alias.tunnel_mode == "cloudflare"

    sup_trycf = StandaloneSupervisorLoop(
        state_root=alias_state,
        runtime_python=sys.executable,
        port=18821,
        mode="trycloudflare",
        no_tray=True,
        enforce_singleton=False,
    )
    assert sup_trycf.mode == "cloudflare"
    sup_cfw = StandaloneSupervisorLoop(
        state_root=alias_state,
        runtime_python=sys.executable,
        port=18821,
        mode="cf_workers",
        no_tray=True,
        enforce_singleton=False,
    )
    assert sup_cfw.mode == "workers_dev"

    sample = (
        "tok1=cmcp_AbCdEfGhIjKlMnOpQrStUvWxYz123456 "
        "tok2=cfut_0123456789abcdef0123456789abcdef01234567 "
        "u1=https://demo123456.srv.us/mcp "
        "u2=https://cosmos-mcp-abcdef1234.sub123.workers.dev/mcp "
        '{"account_id": "0123456789abcdef0123456789abcdef"}'
    )
    redacted = redact_text(sample)
    assert "cmcp_AbCd" not in redacted
    assert "cfut_0123" not in redacted
    assert "demo123456.srv.us" not in redacted
    assert "cosmos-mcp-abcdef1234" not in redacted
    assert "0123456789abcdef0123456789abcdef" not in redacted

    cmd_str = f'"pythonw.exe" -B -m cosmos_mcp.launcher.daemon --state-dir "{tmp_path}" --port 8096'
    assert _extract_state_dir_from_cmd(cmd_str) == tmp_path.resolve()


def test_ws_fragmented_binary_survives_interleaved_ping_pong_and_socks_opener(monkeypatch: Any) -> None:
    # 1) SOCKS5 system proxy does not crash urllib ProxyHandler
    monkeypatch.setenv("ALL_PROXY", "socks5h://127.0.0.1:1080")
    openers = build_ssrf_safe_openers(target_url="https://api.example.com/v1")
    assert len(openers) >= 1

    # 2) Fragmented binary WebSocket frame with interleaved Ping(0x9) and Pong(0xA)
    s_srv, s_cli = socket.socketpair()
    try:
        ws = StdlibWebSocketClient("ws://127.0.0.1:8096/_cosmos_tunnel")
        ws.sock = s_cli
        ws.closed = False

        req_id = b"\x11" * 16
        full_tunnel_msg = pack_tunnel_frame(0x10, req_id, b'{"method":"POST","path_qs":"/mcp"}')
        frag1, frag2 = full_tunnel_msg[:10], full_tunnel_msg[10:]

        def _pack_unmasked(opcode: int, payload: bytes, *, fin: bool) -> bytes:
            b0 = (0x80 if fin else 0x00) | (opcode & 0x0F)
            n = len(payload)
            if n < 126:
                return bytes([b0, n]) + payload
            return bytes([b0, 126]) + struct.pack("!H", n) + payload

        wire = (
            _pack_unmasked(0x2, frag1, fin=False)
            + _pack_unmasked(0x9, b"hb1", fin=True)
            + _pack_unmasked(0xA, b"hb2", fin=True)
            + _pack_unmasked(0x0, frag2, fin=True)
        )

        def _feed() -> None:
            s_srv.sendall(wire)

        t = threading.Thread(target=_feed, daemon=True)
        t.start()
        reassembled = ws.recv_message_bytes()
        t.join(timeout=2.0)
        assert reassembled == full_tunnel_msg
        ft, rid_out, pl_out = unpack_tunnel_frame(reassembled or b"")
        assert ft == 0x10 and rid_out == req_id and b'"/mcp"' in pl_out
    finally:
        s_srv.close()
        s_cli.close()


def test_tunnel_regex_ipv6_caddy_and_vps_loopback_header_strip(tmp_path: Path) -> None:
    assert TRYCLOUDFLARE_URL_RE.search("failed to request https://api.trycloudflare.com/tunnel") is None
    m_valid = TRYCLOUDFLARE_URL_RE.search("url=https://amber-forest-demo.trycloudflare.com")
    assert m_valid is not None and m_valid.group(0) == "https://amber-forest-demo.trycloudflare.com"

    try:
        hot_refresh_public_url(tmp_path, "https://api.trycloudflare.com", port=18812)
        raised = False
    except ValueError:
        raised = True
    assert raised is True

    snippet_v6 = build_vps_hub_caddy_site_snippet("2001:db8::42", hub_port=18096)
    assert "https://[2001:db8::42] {" in snippet_v6

    ensure_initialized(product_root=tmp_path, port=18812, cli_state_dir=str(tmp_path))
    sup = VpsWssNodeSupervisor(
        vps_url="https://hub.example.com",
        node_secret="s" * 64,
        local_port=18812,
        state_root=tmp_path,
    )

    class _DummyUnauthReq:
        req_id = b"0" * 16
        path_qs = "/_cosmos_node/info"
        headers = [
            ("X-Cosmos-Via-Tunnel", "1"),
            ("Accept", "application/json"),
        ]

    forbidden_msgs: list[str] = []
    orig_forb = sup._send_local_forbidden
    sup._send_local_forbidden = lambda _rs, msg: forbidden_msgs.append(msg)  # type: ignore[method-assign]
    try:
        sup._execute_local_http(_DummyUnauthReq(), b"")
    finally:
        sup._send_local_forbidden = orig_forb  # type: ignore[method-assign]
    assert len(forbidden_msgs) == 1 and "Bearer" in forbidden_msgs[0]

    class _DummyReq:
        path_qs = "/_cosmos_node/info"
        headers = [
            ("Authorization", "Bearer " + ("s" * 64)),
            ("X-Cosmos-Via-Tunnel", "1"),
            ("X-Forwarded-Host", "hub.example.com"),
            ("X-Forwarded-Proto", "https"),
            ("Forwarded", "proto=https;host=hub.example.com"),
            ("Accept", "application/json"),
        ]

    captured: Dict[str, Any] = {}
    orig_exec = VpsWssNodeSupervisor.__bases__[0]._execute_local_http
    VpsWssNodeSupervisor.__bases__[0]._execute_local_http = lambda self_obj, rs, bb: captured.setdefault("hdrs", list(rs.headers))  # type: ignore[method-assign]
    try:
        req_obj = _DummyReq()
        sup._execute_local_http(req_obj, b"")
    finally:
        VpsWssNodeSupervisor.__bases__[0]._execute_local_http = orig_exec  # type: ignore[method-assign]
    hdr_keys_low = {k.lower() for k, _ in captured["hdrs"]}
    assert "x-forwarded-host" not in hdr_keys_low
    assert "x-forwarded-proto" not in hdr_keys_low
    assert "forwarded" not in hdr_keys_low
    assert "x-cosmos-local-token" in hdr_keys_low


def test_recovery_png_v2_gateways_and_tokenless_workers_custom_domain(tmp_path: Path) -> None:
    src_state = tmp_path / "src_state"
    dst_state = tmp_path / "dst_state"
    ensure_initialized(product_root=src_state, port=18813, cli_state_dir=str(src_state))

    sec_p = workers_tunnel_secret_path(src_state, prefix="pc")
    atomic_write_text(sec_p, ("a" * 64) + "\n", mode_override=0o600)
    atomic_write_text(src_state / "secrets" / "vps_node_secret.txt", ("b" * 64) + "\n", mode_override=0o600)
    atomic_write_json(
        src_state / "config" / "service.json",
        {
            "port": 18813,
            "workers_dev_url": "https://cosmos-mcp-0011223344.demo.workers.dev",
            "workers_subdomain": "demo",
            "workers_script_name": "cosmos-mcp-0011223344",
            "extra_trusted_urls": ["https://proxy.example.org"],
            "gateways": {
                "instant": {"enabled": True, "submode": "srv_us", "public_url": "https://demo99.srv.us"},
                "workers_dev": {
                    "enabled": True,
                    "submode": "workers_dev",
                    "public_url": "https://cosmos-mcp-0011223344.demo.workers.dev",
                },
                "self_hosted": {"enabled": False, "submode": "vps_hub", "public_url": ""},
            },
            "selected_gateway": "workers_dev",
        },
    )

    res_dom = save_workers_custom_domain_local(src_state, "mcp.example.com")
    assert res_dom["ok"] is True
    assert res_dom["public_url"] == "https://mcp.example.com"
    assert res_dom["workers_dev_url"] == "https://cosmos-mcp-0011223344.demo.workers.dev"

    png_bytes = export_identity_recovery_png(src_state, "StrongPass!2026")
    restored = import_identity_recovery_png(png_bytes, "StrongPass!2026", dst_state)
    assert restored["restored"] is True
    assert (dst_state / "secrets" / "vps_node_secret.txt").read_text(encoding="utf-8").strip() == ("b" * 64)
    dst_cfg = json.loads((dst_state / "config" / "service.json").read_text(encoding="utf-8-sig"))
    assert dst_cfg["gateways"]["workers_dev"]["public_url"] == "https://mcp.example.com"
    assert dst_cfg["extra_trusted_urls"] == ["https://proxy.example.org"]


def test_multidomain_dual_workers_nginx_forwarded_refresh_replay_and_google_revoke(tmp_path: Path) -> None:
    import base64
    import hashlib
    from urllib.parse import parse_qs, urlsplit

    state_root = tmp_path / "state_asgi"
    ws_root = tmp_path / "ws_asgi"
    ws_root.mkdir(parents=True, exist_ok=True)
    port = 18819
    pw_txt = "ABCDE-FGHIJ-KLMNP-QRSTU"
    ensure_initialized(product_root=state_root, port=port, cli_state_dir=str(state_root))
    salt_b = b"0123456789abcdef"
    atomic_write_json(
        state_root / "secrets" / "auth.json",
        {
            "salt": salt_b.hex(),
            "password_hash": hashlib.scrypt(pw_txt.encode("utf-8"), salt=salt_b, n=16384, r=8, p=1).hex(),
            "local_api_token": "cmcp_testlocaltoken0123456789",
        },
        mode_override=0o600,
    )

    atomic_write_json(
        state_root / "config" / "service.json",
        {
            "host": "127.0.0.1",
            "port": port,
            "workspace_roots": [str(ws_root)],
            "permission_tier": "tier3_workspace_dev",
            "workers_dev_url": "https://cosmos-mcp-0011223344.demo.workers.dev",
            "workers_custom_domain": "mcp.example.com",
            "extra_trusted_urls": ["https://proxy.example.org"],
            "gateways": {
                "instant": {"enabled": True, "submode": "srv_us", "public_url": "https://demo99.srv.us"},
                "workers_dev": {
                    "enabled": True,
                    "submode": "workers_dev",
                    "public_url": "https://mcp.example.com",
                    "workers_dev_url": "https://cosmos-mcp-0011223344.demo.workers.dev",
                    "custom_domain": "https://mcp.example.com",
                },
                "self_hosted": {"enabled": False, "submode": "custom", "public_url": ""},
            },
            "selected_gateway": "workers_dev",
            "tunnel_mode": "workers_dev",
            "public_base": "https://mcp.example.com",
        },
    )

    app = create_standalone_app(state_dir=str(state_root), port=port, workspace=str(ws_root))

    with TestClient(app, raise_server_exceptions=True) as client:
        # F-01: Both workers.dev and custom_domain are live on the same workers_dev slot
        h_wd = {
            "Host": f"127.0.0.1:{port}",
            "X-Cosmos-Via-Tunnel": "1",
            "X-Forwarded-Host": "cosmos-mcp-0011223344.demo.workers.dev",
            "X-Forwarded-Proto": "https",
        }
        h_cd = {
            "Host": f"127.0.0.1:{port}",
            "X-Cosmos-Via-Tunnel": "1",
            "X-Forwarded-Host": "mcp.example.com",
            "X-Forwarded-Proto": "https",
        }
        assert client.get("/.well-known/oauth-protected-resource", headers=h_wd).status_code == 200
        assert client.get("/.well-known/oauth-protected-resource", headers=h_cd).status_code == 200

        # F-02: Standard Nginx reverse proxy WITHOUT X-Cosmos-Via-Tunnel + RFC 7239 Forwarded: proto=https
        h_nginx = {
            "Host": f"127.0.0.1:{port}",
            "X-Forwarded-Host": "proxy.example.org",
            "Forwarded": "for=203.0.113.10;proto=https;host=proxy.example.org",
        }
        r_ng = client.get("/.well-known/oauth-protected-resource", headers=h_nginx)
        assert r_ng.status_code == 200
        assert r_ng.json()["resource"] == "https://proxy.example.org/mcp"

        # Untrusted X-Forwarded-Host on loopback must return 421, never leak into loopback!
        h_evil = {"Host": f"127.0.0.1:{port}", "X-Forwarded-Host": "evil.example.net"}
        assert client.get("/.well-known/oauth-protected-resource", headers=h_evil).status_code == 421

        # Helper to complete PKCE authorization on a target gateway
        def _authorize_and_mint(gw_headers: Dict[str, str], base_u: str, redirect_uri: str, client_name: str) -> Dict[str, Any]:
            reg = client.post(
                "/register",
                headers=gw_headers,
                json={
                    "client_name": client_name,
                    "redirect_uris": [redirect_uri],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                },
            )
            assert reg.status_code in (200, 201)
            cid = reg.json()["client_id"]
            verifier = "v" * 48
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
            r_az = client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": cid,
                    "redirect_uri": redirect_uri,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": "st123",
                    "resource": f"{base_u}/mcp",
                },
                headers=gw_headers,
                follow_redirects=False,
            )
            assert r_az.status_code in (302, 303)
            consent_loc = r_az.headers["location"]
            ticket = parse_qs(urlsplit(consent_loc).query)["ticket"][0]
            r_cs = client.get(f"/consent?ticket={ticket}", headers=gw_headers)
            assert r_cs.status_code == 200
            if "Forwarded" in gw_headers:
                assert CONSENT_SESSION_COOKIE_HTTPS in r_cs.cookies
            import re as _re
            m_csrf = _re.search(r'name="csrf"[^>]*value="([^"]+)"|value="([^"]+)"[^>]*name="csrf"|name="csrf_token"[^>]*value="([^"]+)"|value="([^"]+)"[^>]*name="csrf_token"', r_cs.text)
            assert m_csrf is not None, r_cs.text[:500]
            csrf_val = next(g for g in m_csrf.groups() if g)
            csrf_field = "csrf" if 'name="csrf"' in r_cs.text else "csrf_token"
            cookie_hdr = "; ".join(f"{ck}={cv}" for ck, cv in r_cs.cookies.items())
            r_post = client.post(
                "/consent",
                data={"ticket": ticket, csrf_field: csrf_val, "password": pw_txt, "decision": "approve", "grant_mode": "standard"},
                headers={**gw_headers, "Cookie": cookie_hdr, "Origin": base_u, "Referer": f"{base_u}/consent?ticket={ticket}"},
                follow_redirects=False,
            )
            assert r_post.status_code in (302, 303)
            code = parse_qs(urlsplit(r_post.headers["location"]).query)["code"][0]
            r_tok = client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": cid,
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "code_verifier": verifier,
                    "resource": f"{base_u}/mcp",
                },
                headers=gw_headers,
            )
            assert r_tok.status_code == 200
            return {"client_id": cid, **r_tok.json()}

        # Verify RFC 7239 Forwarded: proto=https sets __Host- cookie + F-03 concurrent refresh_replay scope isolation
        gpt_tok = _authorize_and_mint(
            h_nginx,
            "https://proxy.example.org",
            "https://chatgpt.com/connector_platform_oauth_redirect",
            "ChatGPT",
        )
        old_rt = gpt_tok["refresh_token"]
        # Path B first: narrow to /mcp/readonly, then concurrently refresh /mcp with same old_rt!
        r_ro = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": gpt_tok["client_id"],
                "refresh_token": old_rt,
                "resource": "https://proxy.example.org/mcp/readonly",
            },
            headers=h_nginx,
        )
        assert r_ro.status_code == 200
        assert r_ro.json()["scope"] == "server:read"

        r_full = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": gpt_tok["client_id"],
                "refresh_token": old_rt,
                "resource": "https://proxy.example.org/mcp",
            },
            headers=h_nginx,
        )
        assert r_full.status_code == 200
        assert "workspace" in r_full.json()["scope"].split()
        assert r_full.json()["access_token"] != r_ro.json()["access_token"]
        assert r_full.json()["refresh_token"] == r_ro.json()["refresh_token"]

        # F-06: Token minted on proxy.example.org (`extra_trusted`) cannot be used on instant (`demo99.srv.us`),
        # while token minted on workers_dev (`mcp.example.com`) works on its dual alias (`cosmos-mcp-0011223344.demo.workers.dev`)!
        h_srv = {"Host": "demo99.srv.us"}
        mcp_init_body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
        }
        r_cross = client.post(
            "/mcp",
            json=mcp_init_body,
            headers={
                **h_srv,
                "Authorization": f"Bearer {r_full.json()['access_token']}",
                "Accept": "application/json, text/event-stream",
            },
        )
        assert r_cross.status_code in (401, 403)

        gem_tok = _authorize_and_mint(
            h_cd,
            "https://mcp.example.com",
            "https://oauth-redirect.googleusercontent.com/r/custom-mcp-gemtest01",
            "Google Gemini",
        )
        r_dual_ok = client.post(
            "/mcp",
            json=mcp_init_body,
            headers={
                **h_wd,
                "Authorization": f"Bearer {gem_tok['access_token']}",
                "Accept": "application/json, text/event-stream",
            },
        )
        assert r_dual_ok.status_code == 200

        # F-05: Google Gemini DCR re-registers client_2 and revokes old refresh_token -> old access_token immediately invalidated!
        reg2 = client.post(
            "/register",
            headers=h_cd,
            json={
                "client_name": "Google Gemini",
                "redirect_uris": ["https://oauth-redirect.googleusercontent.com/r/custom-mcp-gemtest01"],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
        )
        cid2 = reg2.json()["client_id"]
        r_rev = client.post(
            "/revoke",
            data={"client_id": cid2, "token": gem_tok["refresh_token"]},
            headers=h_cd,
        )
        assert r_rev.status_code == 200
        r_after_rev = client.post(
            "/mcp",
            json=mcp_init_body,
            headers={
                **h_cd,
                "Authorization": f"Bearer {gem_tok['access_token']}",
                "Accept": "application/json, text/event-stream",
            },
        )
        assert r_after_rev.status_code == 401
