"""Deterministic 5-layer end-to-end connectivity check tests (`flexible-testing`).

Covers:
1. Loopback `/healthz` Origin CORS reflection (`127.0.0.1` / `localhost` allowed, external Origins blocked,
   zero `Access-Control-Allow-Credentials`).
2. Full all-green 4-layer backend probe (`local_service` + `proxy_and_deps` + `gateways` + `mcp_protocol`)
   and `*.workers.dev` proxy-OK / direct-fail classification using a local TLS upstream mock server and
   local TCP `CONNECT` proxy (zero external internet access).
3. Fault classification:
   - Dead configured proxy port (`proxy_and_deps.status == "error"`, credential userinfo scrubbed);
   - `NO_PROXY` missing `127.0.0.1` / `localhost` (`local_service.status == "warn"`);
   - Cloudflare `403` `cf-mitigated: challenge` WAF / Bot Fight Mode detection;
   - Cloudflare `1027` daily quota exhausted & `530` / `1033` tunnel edge error & `/mcp` `404` prefix mismatch;
   - 100% hostname & `/u/<secret>` stealth path masking in `masked_url` and `redacted_share_text`.
4. `POST /api/studio/connectivity-check` authentication & CSRF/Origin guards + `cosmos-mcp doctor --probe --json` CLI.
5. Headless Chromium Studio UI interaction (`#run-conn-check-btn`, `#conn-check-panel` 5-step rendering,
   redacted copy toast, `[data-gw-probe]` per-card speed probe, `ZH/EN` live toggle, and WCAG contrast >= 4.5:1).
"""
from __future__ import annotations

import contextlib
import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import httpx
import pytest

from _studio_driver import LiveStudioServer, StudioPageDriver, find_free_port
from cosmos_mcp.core.fs_tx import atomic_write_json
from cosmos_mcp.launcher.doctor import mask_public_url_for_display, run_connectivity_check
from cosmos_mcp.packs.browser import find_system_chromium_binary

REPO_ROOT = Path(__file__).resolve().parents[1]
CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


def _generate_test_tls_bundle(tmp_dir: Path) -> Tuple[Path, ssl.SSLContext, ssl.SSLContext]:
    """Create an ephemeral self-signed CA + server certificate covering loopback and synthetic gateway hosts."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Cosmos Test Root CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    x509.DNSName("demo-node-01.srv.us"),
                    x509.DNSName("cosmos-mcp-demo.sub.workers.dev"),
                    x509.DNSName("mcp.mybox.example.com"),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = tmp_dir / "mock_gw_cert.pem"
    key_pem = tmp_dir / "mock_gw_key.pem"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.load_cert_chain(certfile=str(cert_pem), keyfile=str(key_pem))

    cli_ctx = ssl.create_default_context(cafile=str(cert_pem))
    return cert_pem, srv_ctx, cli_ctx


class _MockTlsGatewayServer:
    """Local TLS HTTP server simulating public gateway `/healthz`, OAuth discovery, and `/mcp` endpoints."""

    def __init__(
        self,
        srv_ssl_ctx: ssl.SSLContext,
        handler_fn: Callable[[str, str, Dict[str, str], bytes], Tuple[int, Dict[str, str], bytes]],
    ) -> None:
        self.handler_fn = handler_fn
        parent = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _dispatch(self, method: str) -> None:
                clen = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(clen) if clen > 0 else b""
                hdr_map = {k.lower(): v for k, v in self.headers.items()}
                code, resp_hdrs, resp_body = parent.handler_fn(method, self.path, hdr_map, body)
                self.send_response(code)
                sent_cl = False
                for hk, hv in resp_hdrs.items():
                    if hk.lower() == "content-length":
                        sent_cl = True
                    self.send_header(hk, hv)
                if not sent_cl:
                    self.send_header("Content-Length", str(len(resp_body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if method != "HEAD" and resp_body:
                    self.wfile.write(resp_body)

            def do_GET(self) -> None:
                self._dispatch("GET")

            def do_POST(self) -> None:
                self._dispatch("POST")

            def do_OPTIONS(self) -> None:
                self._dispatch("OPTIONS")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = int(self.httpd.server_address[1])
        self.httpd.socket = srv_ssl_ctx.wrap_socket(self.httpd.socket, server_side=True)
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self) -> "_MockTlsGatewayServer":
        self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(timeout=3.0)


class _LocalConnectProxy:
    """Minimal HTTP `CONNECT` tunnel forwarding all target hostnames to `127.0.0.1:<target_tls_port>`."""

    def __init__(self, target_tls_port: int) -> None:
        self.target_tls_port = target_tls_port
        self.connect_hosts: list[str] = []
        parent = self

        class _ThreadingTcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
            allow_reuse_address = True
            daemon_threads = True

        class _ProxyHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.settimeout(3.0)
                buf = b""
                while b"\r\n\r\n" not in buf and len(buf) < 8192:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                head_line = buf.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
                parts = head_line.split()
                if len(parts) < 2 or parts[0].upper() != "CONNECT":
                    self.request.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
                    return
                parent.connect_hosts.append(parts[1])
                try:
                    upstream = socket.create_connection(("127.0.0.1", parent.target_tls_port), timeout=2.0)
                except OSError:
                    self.request.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    return
                with upstream:
                    self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    sockets = [self.request, upstream]
                    while True:
                        rlist, _, _ = select.select(sockets, [], [], 3.0)
                        if not rlist:
                            break
                        done = False
                        for s in rlist:
                            try:
                                data = s.recv(16384)
                            except OSError:
                                data = b""
                            if not data:
                                done = True
                                break
                            other = upstream if s is self.request else self.request
                            other.sendall(data)
                        if done:
                            break

        self.server = _ThreadingTcpServer(("127.0.0.1", 0), _ProxyHandler)
        self.port = int(self.server.server_address[1])
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "_LocalConnectProxy":
        self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=3.0)


def _write_gateway_state(
    state_dir: Path,
    local_port: int,
    *,
    gateway_id: str = "instant",
    submode: str = "public_gateway",
    public_url: str = "",
    endpoint_secret: str = "",
) -> None:
    cfg_dir = state_dir / "config"
    st_sub = state_dir / "state"
    sec_dir = state_dir / "secrets"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    st_sub.mkdir(parents=True, exist_ok=True)
    sec_dir.mkdir(parents=True, exist_ok=True)

    gateways_cfg: Dict[str, Any] = {
        "instant": {"enabled": False, "submode": "public_gateway", "public_url": ""},
        "workers_dev": {"enabled": False, "submode": "workers_dev", "public_url": ""},
        "self_hosted": {"enabled": False, "submode": "custom", "public_url": ""},
    }
    gateways_cfg[gateway_id] = {
        "enabled": True,
        "submode": submode,
        "public_url": public_url,
    }
    svc_doc: Dict[str, Any] = {
        "host": "127.0.0.1",
        "port": local_port,
        "tunnel_mode": submode,
        "public_base": public_url,
        "selected_gateway": gateway_id,
        "gateways": gateways_cfg,
    }
    if endpoint_secret:
        (sec_dir / "endpoint_secret.txt").write_text(endpoint_secret, encoding="utf-8")
        svc_doc["endpoint_secret"] = endpoint_secret

    atomic_write_json(cfg_dir / "service.json", svc_doc)
    atomic_write_json(
        st_sub / "daemon_status.json",
        {
            "status": "running",
            "port": local_port,
            "mode": submode,
            "public_url": public_url,
            "tunnel_ready": bool(public_url),
            "gateways": {
                gateway_id: {
                    "enabled": True,
                    "submode": submode,
                    "phase": "ready" if public_url else "starting",
                    "tunnel_ready": bool(public_url),
                    "public_url": public_url,
                    "last_error": "",
                }
            },
        },
    )


def test_healthz_loopback_origin_cors_headers(tmp_path: Path) -> None:
    state_dir = tmp_path / "cors_state"
    ws_dir = tmp_path / "cors_ws"
    ws_dir.mkdir(parents=True)

    with LiveStudioServer(state_dir, ws_dir, tunnel_mode="local", thread_prefix="conn-cors") as srv:
        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=5.0) as client:
            r_lb = client.get("/healthz", headers={"Origin": "http://127.0.0.1:8096"})
            assert r_lb.status_code == 200
            assert r_lb.headers.get("access-control-allow-origin") == "http://127.0.0.1:8096"
            assert "Origin" in (r_lb.headers.get("vary") or "")
            assert "access-control-allow-credentials" not in {k.lower() for k in r_lb.headers.keys()}

            r_lh = client.get("/healthz", headers={"Origin": "http://localhost:5173"})
            assert r_lh.status_code == 200
            assert r_lh.headers.get("access-control-allow-origin") == "http://localhost:5173"

            r_opt = client.options("/healthz", headers={"Origin": "http://127.0.0.1:8096"})
            assert r_opt.status_code == 204
            assert r_opt.headers.get("access-control-allow-origin") == "http://127.0.0.1:8096"

            r_evil = client.get("/healthz", headers={"Origin": "https://evil.example.com"})
            assert r_evil.status_code == 200
            assert r_evil.headers.get("access-control-allow-origin") is None

            r_spoof = client.get("/healthz", headers={"Origin": "http://127.0.0.1.evil.com:8096"})
            assert r_spoof.status_code == 200
            assert r_spoof.headers.get("access-control-allow-origin") is None


def test_all_green_e2e_workers_proxy_vs_direct_and_stealth_redaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cert_pem, srv_ssl_ctx, cli_ssl_ctx = _generate_test_tls_bundle(tmp_path)
    state_dir = tmp_path / "green_state"
    ws_dir = tmp_path / "green_ws"
    ws_dir.mkdir(parents=True)
    stealth_sec = "SecStealthToken987654321"

    def _healthy_upstream(method: str, path: str, hdrs: Dict[str, str], body: bytes) -> Tuple[int, Dict[str, str], bytes]:
        if method == "GET" and path in ("/healthz", f"/u/{stealth_sec}/healthz"):
            return 200, {"Content-Type": "application/json"}, b'{"status":"ok"}'
        if method == "GET" and path in (
            "/.well-known/oauth-authorization-server",
            f"/u/{stealth_sec}/.well-known/oauth-authorization-server",
            f"/.well-known/oauth-authorization-server/u/{stealth_sec}",
        ):
            meta = {
                "issuer": "https://demo-node-01.srv.us",
                "authorization_endpoint": "https://demo-node-01.srv.us/authorize",
                "token_endpoint": "https://demo-node-01.srv.us/token",
                "registration_endpoint": "https://demo-node-01.srv.us/register",
            }
            return 200, {"Content-Type": "application/json"}, json.dumps(meta).encode("utf-8")
        if method == "POST" and path in ("/mcp", f"/u/{stealth_sec}/mcp"):
            return (
                401,
                {
                    "Content-Type": "application/json",
                    "WWW-Authenticate": 'Bearer realm="mcp", resource_metadata="https://example/.well-known/oauth-protected-resource"',
                },
                b'{"error":"unauthorized"}',
            )
        return 404, {"Content-Type": "text/plain"}, b"not found"

    with (
        LiveStudioServer(state_dir, ws_dir, tunnel_mode="local", thread_prefix="conn-green") as studio_srv,
        _MockTlsGatewayServer(srv_ssl_ctx, _healthy_upstream) as mock_gw,
        _LocalConnectProxy(mock_gw.port) as mock_px,
    ):
        monkeypatch.setenv("SSL_CERT_FILE", str(cert_pem))
        monkeypatch.setenv("HTTPS_PROXY", f"http://pxuser:TopSecretPxPw99@127.0.0.1:{mock_px.port}")
        monkeypatch.setenv("HTTP_PROXY", f"http://pxuser:TopSecretPxPw99@127.0.0.1:{mock_px.port}")
        monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost,::1")

        # 1. Stealth `/u/<secret>/mcp` on `*.srv.us` -> 100% all-green + zero secret/subdomain leak
        _write_gateway_state(
            state_dir,
            studio_srv.port,
            gateway_id="instant",
            submode="public_gateway",
            public_url="https://demo-node-01.srv.us",
            endpoint_secret=stealth_sec,
        )
        res = run_connectivity_check(
            state_dir,
            local_port=studio_srv.port,
            ssl_context=cli_ssl_ctx,
        )
        assert res["overall_status"] == "ok"
        assert res["ok"] is True
        assert res["duration_ms"] < 4000
        assert res["local_service"]["status"] == "ok"
        assert res["local_service"]["tool_count"] >= 12
        assert res["proxy_and_deps"]["status"] == "ok"
        assert res["proxy_and_deps"]["proxy_reachable"] is True
        assert res["proxy_and_deps"]["proxy_endpoint"] == f"http://127.0.0.1:{mock_px.port}"

        inst_gw = next(g for g in res["gateways"] if g["gateway_id"] == "instant")
        assert inst_gw["status"] == "ok"
        assert inst_gw["masked_url"] == "https://demo***.srv.us/u/***/mcp"
        assert res["mcp_protocol"]["status"] == "ok"
        proto_item = next(p for p in res["mcp_protocol"]["items"] if p["gateway_id"] == "instant")
        assert proto_item["oauth_metadata_ok"] is True
        assert proto_item["mcp_auth_gate_ok"] is True

        serialized = json.dumps(res, ensure_ascii=False)
        share_txt = res["redacted_share_text"]
        assert "https://***.srv.us/u/***/mcp" in share_txt
        for forbidden in ("demo-node-01", stealth_sec, "TopSecretPxPw99", str(state_dir)):
            assert forbidden not in serialized
            assert forbidden not in share_txt

        # 2. `*.workers.dev` where `via_proxy` succeeds (`200`) and `direct` fails (unresolvable synthetic domain)
        _write_gateway_state(
            state_dir,
            studio_srv.port,
            gateway_id="workers_dev",
            submode="workers_dev",
            public_url="https://cosmos-mcp-demo.sub.workers.dev",
        )
        res_wd = run_connectivity_check(
            state_dir,
            local_port=studio_srv.port,
            gateway_id="workers_dev",
            ssl_context=cli_ssl_ctx,
        )
        assert res_wd["overall_status"] == "ok"
        wd_gw = res_wd["gateways"][0]
        assert wd_gw["status"] == "ok"
        assert wd_gw["via_proxy"]["ok"] is True
        assert wd_gw["direct"]["ok"] is False
        assert "经代理连通正常" in wd_gw["message_zh"]
        assert "workers.dev" in wd_gw["message_zh"]


def test_fault_classifications_dead_proxy_no_proxy_waf_403_1027_530_and_404(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, srv_ssl_ctx, cli_ssl_ctx = _generate_test_tls_bundle(tmp_path)
    state_dir = tmp_path / "fault_state"
    ws_dir = tmp_path / "fault_ws"
    ws_dir.mkdir(parents=True)

    mode_box = {"scenario": "waf_403"}

    def _faulty_upstream(method: str, path: str, hdrs: Dict[str, str], body: bytes) -> Tuple[int, Dict[str, str], bytes]:
        sc = mode_box["scenario"]
        if sc == "cf_1027":
            return 429, {"Content-Type": "text/plain"}, b"Error 1027: Worker exceeded daily request limit"
        if sc == "cf_530":
            return 530, {"Content-Type": "text/html"}, b"Cloudflare Tunnel error 1033"
        if path == "/healthz":
            return 200, {"Content-Type": "application/json"}, b'{"status":"ok"}'
        if sc == "waf_403" and "/.well-known/oauth-authorization-server" in path:
            return (
                403,
                {"Content-Type": "text/html", "cf-mitigated": "challenge"},
                b"<!DOCTYPE html><title>Just a moment...</title>",
            )
        if "/.well-known/oauth-authorization-server" in path:
            meta = {
                "authorization_endpoint": "https://127.0.0.1/authorize",
                "token_endpoint": "https://127.0.0.1/token",
                "registration_endpoint": "https://127.0.0.1/register",
            }
            return 200, {"Content-Type": "application/json"}, json.dumps(meta).encode("utf-8")
        if sc == "mcp_404" and method == "POST":
            return 404, {"Content-Type": "text/plain"}, b"Not Found"
        return 401, {"WWW-Authenticate": "Bearer"}, b""

    with (
        LiveStudioServer(state_dir, ws_dir, tunnel_mode="local", thread_prefix="conn-fault") as studio_srv,
        _MockTlsGatewayServer(srv_ssl_ctx, _faulty_upstream) as mock_gw,
    ):
        gw_url = f"https://127.0.0.1:{mock_gw.port}"
        _write_gateway_state(
            state_dir,
            studio_srv.port,
            gateway_id="self_hosted",
            submode="custom",
            public_url=gw_url,
        )

        # (A) Dead proxy port + missing NO_PROXY loopback
        dead_port = find_free_port()
        monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{dead_port}")
        monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{dead_port}")
        monkeypatch.setenv("NO_PROXY", "internal.corp")

        res_px = run_connectivity_check(
            state_dir,
            local_port=studio_srv.port,
            gateway_id="self_hosted",
            ssl_context=cli_ssl_ctx,
        )
        assert res_px["local_service"]["status"] == "warn"
        assert res_px["local_service"]["no_proxy_ok"] is False
        assert "NO_PROXY" in res_px["local_service"]["message_zh"]
        assert res_px["proxy_and_deps"]["status"] == "error"
        assert res_px["proxy_and_deps"]["proxy_reachable"] is False
        assert f"127.0.0.1:{dead_port}" in res_px["proxy_and_deps"]["message_zh"]

        # Clear proxy env for upstream protocol error assertions
        for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setattr("cosmos_mcp.launcher.doctor.detect_configured_proxy", lambda *a, **kw: "")

        # (B) Cloudflare 403 Bot Fight Mode / WAF Managed Challenge
        mode_box["scenario"] = "waf_403"
        res_waf = run_connectivity_check(
            state_dir,
            local_port=studio_srv.port,
            gateway_id="self_hosted",
            ssl_context=cli_ssl_ctx,
        )
        assert res_waf["overall_status"] == "error"
        assert res_waf["mcp_protocol"]["status"] == "error"
        assert res_waf["mcp_protocol"]["items"][0]["error_code"] == "cf_waf_challenge_403"
        assert "Bot Fight Mode" in res_waf["mcp_protocol"]["message_zh"]

        # (C) Cloudflare 1027 quota exhausted
        mode_box["scenario"] = "cf_1027"
        res_1027 = run_connectivity_check(
            state_dir,
            local_port=studio_srv.port,
            gateway_id="self_hosted",
            ssl_context=cli_ssl_ctx,
        )
        assert res_1027["overall_status"] == "error"
        assert res_1027["gateways"][0]["error_code"] == "cf_1027"
        assert "1027" in res_1027["gateways"][0]["message_zh"]

        # (D) Cloudflare 530 / 1033 tunnel disconnected
        mode_box["scenario"] = "cf_530"
        res_530 = run_connectivity_check(
            state_dir,
            local_port=studio_srv.port,
            gateway_id="self_hosted",
            ssl_context=cli_ssl_ctx,
        )
        assert res_530["overall_status"] == "error"
        assert res_530["gateways"][0]["error_code"] == "cf_530_1033"
        assert "530" in res_530["gateways"][0]["message_zh"]

        # (E) `/mcp` 404 route/stealth prefix mismatch
        mode_box["scenario"] = "mcp_404"
        res_404 = run_connectivity_check(
            state_dir,
            local_port=studio_srv.port,
            gateway_id="self_hosted",
            ssl_context=cli_ssl_ctx,
        )
        assert res_404["overall_status"] == "error"
        assert res_404["mcp_protocol"]["items"][0]["error_code"] == "mcp_route_404"
        assert "404" in res_404["mcp_protocol"]["message_zh"]


def test_studio_connectivity_api_auth_and_cli_doctor_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cert_pem, srv_ssl_ctx, _ = _generate_test_tls_bundle(tmp_path)
    state_dir = tmp_path / "api_state"
    ws_dir = tmp_path / "api_ws"
    ws_dir.mkdir(parents=True)

    def _ok_upstream(method: str, path: str, hdrs: Dict[str, str], body: bytes) -> Tuple[int, Dict[str, str], bytes]:
        if path == "/healthz":
            return 200, {"Content-Type": "application/json"}, b'{"status":"ok"}'
        if "/.well-known/oauth-authorization-server" in path:
            meta = {
                "authorization_endpoint": "https://127.0.0.1/authorize",
                "token_endpoint": "https://127.0.0.1/token",
                "registration_endpoint": "https://127.0.0.1/register",
            }
            return 200, {"Content-Type": "application/json"}, json.dumps(meta).encode("utf-8")
        return 401, {"WWW-Authenticate": "Bearer"}, b""

    with (
        LiveStudioServer(state_dir, ws_dir, tunnel_mode="public_gateway", thread_prefix="conn-api") as srv,
        _MockTlsGatewayServer(srv_ssl_ctx, _ok_upstream) as mock_gw,
    ):
        monkeypatch.setenv("SSL_CERT_FILE", str(cert_pem))
        monkeypatch.setattr("cosmos_mcp.launcher.doctor.detect_configured_proxy", lambda *a, **kw: "")

        _write_gateway_state(
            state_dir,
            srv.port,
            gateway_id="instant",
            submode="public_gateway",
            public_url=f"https://127.0.0.1:{mock_gw.port}",
        )
        auth_doc = json.loads((state_dir / "secrets" / "auth.json").read_text(encoding="utf-8"))
        local_tok = auth_doc["local_api_token"]

        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=8.0) as client:
            # Unauthenticated / missing CSRF -> 403
            r_no_csrf = client.post("/api/studio/connectivity-check", json={})
            assert r_no_csrf.status_code == 403

            # Forged cross-site Origin -> 403
            st0 = client.get("/api/studio/state").json()
            csrf = st0["csrf_token"]
            r_bad_orig = client.post(
                "/api/studio/connectivity-check",
                headers={"X-Studio-Csrf": csrf, "Origin": "https://evil.example.org"},
                json={},
            )
            assert r_bad_orig.status_code == 403

            # Valid CSRF -> 200 OK
            r_ok = client.post(
                "/api/studio/connectivity-check",
                headers={"X-Studio-Csrf": csrf},
                json={"gateway_id": "instant"},
            )
            assert r_ok.status_code == 200
            doc_ok = r_ok.json()
            assert doc_ok["overall_status"] == "ok"
            assert doc_ok["local_service"]["status"] == "ok"
            assert doc_ok["mcp_protocol"]["status"] == "ok"

            # Valid local Bearer token with empty body -> 200 OK
            r_bearer = client.post(
                "/api/studio/connectivity-check",
                headers={"Authorization": f"Bearer {local_tok}"},
            )
            assert r_bearer.status_code == 200
            assert r_bearer.json()["overall_status"] == "ok"

            # Unknown gateway_id -> 400
            r_bad_gw = client.post(
                "/api/studio/connectivity-check",
                headers={"X-Studio-Csrf": csrf},
                json={"gateway_id": "nonexistent_slot"},
            )
            assert r_bad_gw.status_code == 400

        # CLI `cosmos-mcp doctor --probe --json` subprocess test (zero window, stdin=DEVNULL)
        cli_env = dict(os.environ)
        cli_env["PYTHONDONTWRITEBYTECODE"] = "1"
        cli_env["PYTHONUTF8"] = "1"
        cli_env["SSL_CERT_FILE"] = str(cert_pem)
        existing_pp = cli_env.get("PYTHONPATH", "")
        src_str = str(REPO_ROOT / "src")
        cli_env["PYTHONPATH"] = f"{src_str}{os.pathsep}{existing_pp}" if existing_pp else src_str
        run_kw: Dict[str, Any] = {"creationflags": CREATE_NO_WINDOW} if sys.platform == "win32" else {}

        proc = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "cosmos_mcp.launcher.cli",
                "doctor",
                "--probe",
                "--json",
                "--state-dir",
                str(state_dir),
            ],
            cwd=str(REPO_ROOT),
            env=cli_env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=25,
            **run_kw,
        )
        assert proc.returncode == 0, f"doctor --probe failed: stderr={proc.stderr} stdout={proc.stdout}"
        cli_doc = json.loads(proc.stdout)
        assert "connectivity_check" in cli_doc
        assert cli_doc["connectivity_check"]["overall_status"] == "ok"


@pytest.mark.skipif(not find_system_chromium_binary(), reason="Headless Chromium/Edge not available on this host")
def test_studio_headless_ui_conn_check_panel_bilingual_and_contrast(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cert_pem, srv_ssl_ctx, _ = _generate_test_tls_bundle(tmp_path)
    state_dir = tmp_path / "ui_state"
    ws_dir = tmp_path / "ui_ws"
    ws_dir.mkdir(parents=True)

    def _ui_upstream(method: str, path: str, hdrs: Dict[str, str], body: bytes) -> Tuple[int, Dict[str, str], bytes]:
        orig = hdrs.get("origin", "")
        cors = {"Access-Control-Allow-Origin": orig, "Vary": "Origin"} if orig.startswith("http://127.0.0.1") else {}
        if path == "/healthz":
            return 200, {"Content-Type": "application/json", **cors}, b'{"status":"ok"}'
        if "/.well-known/oauth-authorization-server" in path:
            meta = {
                "authorization_endpoint": "https://demo-node-01.srv.us/authorize",
                "token_endpoint": "https://demo-node-01.srv.us/token",
                "registration_endpoint": "https://demo-node-01.srv.us/register",
            }
            return 200, {"Content-Type": "application/json"}, json.dumps(meta).encode("utf-8")
        return 401, {"WWW-Authenticate": "Bearer"}, b""

    with (
        LiveStudioServer(state_dir, ws_dir, tunnel_mode="public_gateway", thread_prefix="conn-ui") as srv,
        _MockTlsGatewayServer(srv_ssl_ctx, _ui_upstream) as mock_gw,
        _LocalConnectProxy(mock_gw.port) as mock_px,
    ):
        monkeypatch.setenv("SSL_CERT_FILE", str(cert_pem))
        monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{mock_px.port}")
        monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{mock_px.port}")
        monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost,::1")

        _write_gateway_state(
            state_dir,
            srv.port,
            gateway_id="instant",
            submode="public_gateway",
            public_url="https://demo-node-01.srv.us",
        )

        with StudioPageDriver(tmp_path / "cdp_conn_ui") as driver:
            driver.set_viewport(1440, 900, mobile=False, device_scale_factor=1)
            driver.goto(f"{srv.base_url}/")
            driver.evaluate(
                """() => {
                    if (window.WebAI2PCI18n && typeof window.WebAI2PCI18n.setLang === 'function') {
                        window.WebAI2PCI18n.setLang('zh');
                    }
                }"""
            )
            driver.wait_until(
                "() => (document.documentElement.getAttribute('data-lang') || 'zh') === 'zh'",
                timeout_sec=3.0,
                description="initial zh locale normalized for US CI runners",
            )

            # Verify connectivity check & locale controls required by this panel flow are mounted
            shell_ok = driver.evaluate(
                """() => ({
                    hasLangBtn: Boolean(document.getElementById('lang-toggle-btn')),
                    hasConnBtn: Boolean(document.getElementById('run-conn-check-btn')),
                })"""
            )
            assert shell_ok == {
                "hasLangBtn": True,
                "hasConnBtn": True,
            }

            # Collapse `#wb-conn-drawer`, then click `#run-conn-check-btn` -> must auto-expand & render 5 steps
            driver.evaluate(
                """() => {
                    const drw = document.getElementById('wb-conn-drawer');
                    if (drw && drw.classList.contains('open')) {
                        document.getElementById('toggle-conn-details-btn').click();
                    }
                    document.getElementById('run-conn-check-btn').click();
                }"""
            )

            driver.wait_until(
                """() => {
                    const panel = document.getElementById('conn-check-panel');
                    const rows = document.querySelectorAll('#conn-check-steps .conn-step-row');
                    const copyBtn = document.getElementById('copy-conn-diag-btn');
                    return Boolean(panel && getComputedStyle(panel).display !== 'none' && rows.length === 5 && copyBtn && !copyBtn.disabled);
                }""",
                timeout_sec=10.0,
                description="5-step connectivity check panel rendered",
            )

            zh_snap = driver.evaluate(
                """() => ({
                    drawerOpen: document.getElementById('wb-conn-drawer').classList.contains('open'),
                    panelText: document.getElementById('conn-check-panel').innerText,
                })"""
            )
            assert zh_snap["drawerOpen"] is True
            assert "1. 本机回环服务与代理排除" in zh_snap["panelText"]
            assert "5. 当前浏览器授权页直达" in zh_snap["panelText"]
            assert "demo-node-01" not in zh_snap["panelText"]

            # Click `#copy-conn-diag-btn` -> verify redacted share text copied & toast shown
            driver.evaluate("() => document.getElementById('copy-conn-diag-btn').click()")
            driver.wait_until(
                "() => (window.__copiedHistory || []).length >= 1",
                timeout_sec=3.0,
                description="redacted share text copied",
            )
            copied_txt = driver.evaluate("() => window.__copiedHistory[window.__copiedHistory.length - 1]")
            assert "https://***.srv.us/mcp" in copied_txt
            assert "demo-node-01" not in copied_txt

            # Toggle language ZH -> EN -> verify button & panel translate cleanly
            driver.evaluate("() => document.getElementById('lang-toggle-btn').click()")
            driver.wait_until(
                """() => document.documentElement.getAttribute('data-lang') === 'en'
                    && document.getElementById('conn-check-panel').innerText.includes('1. Local Loopback & NO_PROXY')""",
                timeout_sec=4.0,
                description="English connectivity panel translation",
            )
            en_btn_txt = driver.evaluate("() => document.getElementById('run-conn-check-btn').innerText.trim()")
            assert en_btn_txt == "Check Connectivity"

            # Toggle back EN -> ZH
            driver.evaluate("() => document.getElementById('lang-toggle-btn').click()")
            driver.wait_until(
                """() => document.documentElement.getAttribute('data-lang') === 'zh'
                    && document.getElementById('conn-check-panel').innerText.includes('1. 本机回环服务与代理排除')""",
                timeout_sec=4.0,
                description="Chinese connectivity panel restoration",
            )

            # Open Settings -> Gateways -> click `[data-gw-probe="instant"]`
            driver.open_settings("gateways")
            driver.evaluate("() => document.querySelector('[data-gw-probe=\"instant\"]').click()")
            driver.wait_until(
                """() => {
                    const box = document.getElementById('gw-probe-box-instant');
                    return Boolean(box && getComputedStyle(box).display !== 'none' && box.innerText.length > 5);
                }""",
                timeout_sec=10.0,
                description="per-card instant probe result rendered",
            )

            # Check WCAG contrast >= 4.5:1 across light & dark themes on `#run-conn-check-btn` and `#conn-check-badge`
            for theme_name in ("light", "dark"):
                driver.set_appearance(style_pack="warm-paper", theme=theme_name)
                cr_snap = driver.evaluate(
                    """() => {
                        function parseRgb(str) {
                            const m = String(str || '').match(/rgba?\\(\\s*(\\d+)\\s*,\\s*(\\d+)\\s*,\\s*(\\d+)(?:\\s*,\\s*([0-9.]+))?\\s*\\)/i);
                            if (!m) return null;
                            return { r: Number(m[1]), g: Number(m[2]), b: Number(m[3]), a: m[4] === undefined ? 1 : Number(m[4]) };
                        }
                        function effectiveBg(el) {
                            let cur = el;
                            while (cur && cur.nodeType === 1) {
                                const bg = parseRgb(getComputedStyle(cur).backgroundColor);
                                if (bg && bg.a > 0.05) return bg;
                                cur = cur.parentElement;
                            }
                            return { r: 255, g: 255, b: 255, a: 1 };
                        }
                        function relLum(rgb) {
                            const c = [rgb.r, rgb.g, rgb.b].map(v => {
                                v /= 255;
                                return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
                            });
                            return c[0] * 0.2126 + c[1] * 0.7152 + c[2] * 0.0722;
                        }
                        function ratio(sel) {
                            const el = document.querySelector(sel);
                            const fg = parseRgb(getComputedStyle(el).color);
                            const bg = effectiveBg(el);
                            const l1 = relLum(fg), l2 = relLum(bg);
                            return Number(((Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05)).toFixed(2));
                        }
                        const st = document.createElement('style');
                        st.textContent = '*,*::before,*::after{transition:none!important;}';
                        document.head.appendChild(st);
                        const out = {
                            btn: ratio('#run-conn-check-btn'),
                            badge: ratio('#conn-check-badge'),
                            stepTitle: ratio('#conn-check-steps .conn-step-title'),
                        };
                        st.remove();
                        return out;
                    }"""
                )
                for k_cr, v_cr in cr_snap.items():
                    assert v_cr >= 4.5, f"Contrast {k_cr}={v_cr} < 4.5 on {theme_name}"

            # Check mobile 390x844 zero horizontal overflow while panel is open
            driver.close_settings()
            driver.set_viewport(390, 844, mobile=True, device_scale_factor=2)
            overflow = driver.evaluate(
                "() => ({ iw: window.innerWidth, sw: document.documentElement.scrollWidth })"
            )
            assert overflow["sw"] <= overflow["iw"] + 2

            diag = driver.get_runtime_diagnostics()
            assert diag["jsErrors"] == []
            assert diag["consoleErrors"] == []


def test_mask_public_url_helper_variants() -> None:
    assert (
        mask_public_url_for_display("https://demo-node-01.srv.us/mcp", full_subdomain_mask=False)
        == "https://demo***.srv.us/mcp"
    )
    assert (
        mask_public_url_for_display("https://demo-node-01.srv.us/u/secret123456/mcp", full_subdomain_mask=True)
        == "https://***.srv.us/u/***/mcp"
    )
    assert (
        mask_public_url_for_display("https://cosmos-mcp-abcd.mysub.workers.dev/mcp", full_subdomain_mask=True)
        == "https://***.workers.dev/mcp"
    )
