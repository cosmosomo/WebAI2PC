"""Production ASGI end-to-end verification suite for S6 Auth & Trust Hardening.

Verifies through full `create_standalone_app` live HTTP entrypoints:
1. RFC 8707 `/mcp/readonly` audience & scope isolation:
   - DCR + `/authorize` + `GET /consent?ticket=...` (200 HTML, 4-char pair code, `16px` input, show/hide password toggle, zero `FileNotFoundError`)
   - `POST /consent` + `/token` minting `resource="http://127.0.0.1:<port>/mcp/readonly"` narrows scopes to `["server:read"]`
   - `POST /mcp/readonly` (`tools/list`) -> `200` (read-only tools only)
   - `POST /mcp` with the same readonly token -> `403` (`forbidden_cross_resource`)
2. Full `/mcp` token & `/consent` interactive options:
   - Full `/mcp` token -> `200` on `/mcp` (12 core tools) and `200` downward on `/mcp/readonly` (read-only tools)
   - Selecting "仅授予只读权限" (`grant_scope="readonly"`) on `/consent` narrows `/mcp` authorization to `["server:read"]`, blocking `/mcp` with `403` while allowing `/mcp/readonly` (`200`)
   - Selecting "本次 2 小时临时授权" (`session_ttl="2h"`) issues `expires_in == 7200` and caps refresh/session expiry at 2 hours
3. Strict client verification, `oauth.sqlite3` hashed token storage, 300s concurrent refresh, Studio per-client `revoke_client`, and `audit.jsonl` + recovery alignment:
   - Spoofed DCR `client_name="My Gemini Bot"` with non-Google callback returns `is_google_gemini_client(...) == False` and rotates refresh tokens
   - Raw `oauth.sqlite3` / `-wal` bytes on disk contain ZERO plaintext `access_token` or `refresh_token` strings; all token keys use `sha256:` digests
   - Concurrent refresh within 300s+ grace window returns identical valid tokens
   - Studio renders `list_authorized_sessions()`, `logs/audit.jsonl` recent operations, snapshot undo & trash restore, and single-client `revoke_client` immediately invalidates that client's token (`401`) while preserving sibling clients (`200`).
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from _studio_driver import LiveStudioServer, StudioPageDriver  # noqa: E402
from cosmos_mcp.core.fs_tx import safe_trash_file  # noqa: E402
from cosmos_mcp.launcher import cli  # noqa: E402
from cosmos_mcp.protocol.oauth import (  # noqa: E402
    CONSENT_TEMPLATE_PATH,
    derive_consent_pair_code,
    is_google_gemini_client,
)
from cosmos_mcp.studio.routes import read_asset_text  # noqa: E402


def _make_pkce(seed: str) -> Tuple[str, str]:
    verifier = f"cosmos_s6_pkce_verifier_{seed}_0123456789abcdef"
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .decode("ascii")
        .rstrip("=")
    )
    return verifier, challenge


def _oauth_dcr_and_consent(
    base_url: str,
    owner_password: str,
    *,
    client_name: str,
    redirect_uri: str,
    resource: Optional[str],
    grant_scope: Optional[str] = None,
    session_ttl: Optional[str] = None,
    requested_scope: str = "workspace server:read server:admin",
) -> Tuple[str, Dict[str, Any], str]:
    """Run full DCR `/register` -> `/authorize` -> `GET /consent` -> `POST /consent` -> `/token` flow."""
    with httpx.Client(base_url=base_url, trust_env=False, timeout=10.0) as oauth_http:
        reg = oauth_http.post(
            "/register",
            json={
                "client_name": client_name,
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
        )
        assert reg.status_code in (200, 201), reg.text
        client_id = reg.json()["client_id"]

        verifier, challenge = _make_pkce(client_id[:12])
        auth_params: Dict[str, str] = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": f"st_{client_id[:8]}",
            "scope": requested_scope,
        }
        if resource is not None:
            auth_params["resource"] = resource

        auth_resp = oauth_http.get("/authorize", params=auth_params, follow_redirects=False)
        assert auth_resp.status_code in (302, 307), auth_resp.text
        loc = auth_resp.headers["location"]
        consent_path_qs = urlsplit(loc).path + "?" + urlsplit(loc).query
        qs_ticket = parse_qs(urlsplit(loc).query)["ticket"][0]

        get_consent = oauth_http.get(consent_path_qs, headers={"Accept": "text/html"})
        assert get_consent.status_code == 200
        assert get_consent.headers.get("content-type", "").startswith("text/html")
        consent_html = get_consent.text

        # Verify unified single-source consent UX invariants
        expected_pair = derive_consent_pair_code(qs_ticket)
        assert f'id="consent-pair-code">{expected_pair}</strong>' in consent_html or expected_pair in consent_html
        assert "font-size: 16px" in consent_html
        assert 'id="toggle-password-btn"' in consent_html
        assert 'name="grant_scope"' in consent_html
        assert 'name="session_ttl"' in consent_html
        csp_hdr = get_consent.headers.get("content-security-policy", "")
        assert "script-src 'nonce-" in csp_hdr

        m_csrf = re.search(r'name="csrf"\s+value="([^"]+)"', consent_html)
        assert m_csrf is not None

        form_data: Dict[str, str] = {
            "ticket": qs_ticket,
            "csrf": m_csrf.group(1),
            "password": owner_password,
            "decision": "approve",
        }
        if grant_scope is not None:
            form_data["grant_scope"] = grant_scope
        if session_ttl is not None:
            form_data["session_ttl"] = session_ttl

        post_consent = oauth_http.post(
            consent_path_qs,
            data=form_data,
            headers={"Accept": "text/html"},
            follow_redirects=False,
        )
        assert post_consent.status_code == 302, post_consent.text
        cb_qs = parse_qs(urlsplit(post_consent.headers["location"]).query)
        auth_code = cb_qs["code"][0]

        tok_resp = oauth_http.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
            },
        )
        assert tok_resp.status_code == 200, tok_resp.text
        return client_id, tok_resp.json(), consent_html


def test_single_consent_template_source_of_truth_and_strict_gemini_client_check() -> None:
    # Single template source of truth: `studio.routes.read_asset_text("consent.html")` never raises FileNotFoundError
    canonical_tpl = CONSENT_TEMPLATE_PATH.read_text(encoding="utf-8")
    via_studio_helper = read_asset_text("consent.html")
    assert via_studio_helper == canonical_tpl
    assert "font-size: 16px" in canonical_tpl
    assert 'id="toggle-password-btn"' in canonical_tpl

    # Unauthenticated DCR client spoofing `client_name` with `"Gemini"` MUST NOT match `is_google_gemini_client`
    assert is_google_gemini_client("My Gemini Bot", ["http://127.0.0.1:54321/callback"]) is False
    assert is_google_gemini_client("Google Gemini Official", ["https://claude.ai/api/mcp/auth_callback"]) is False
    assert is_google_gemini_client("Gemini Spoof", ["https://evil-attacker.googleusercontent.com/cb"]) is False

    # Official validated Google redirect hosts DO match `is_google_gemini_client`
    assert (
        is_google_gemini_client(
            "Connected App",
            ["https://oauth-redirect.googleusercontent.com/r/prod/user_bound_custom-mcp-12345"],
        )
        is True
    )
    assert is_google_gemini_client("Vertex Connector", ["https://vertexaisearch.cloud.google.com/oauth/cb"]) is True


def test_s6_full_production_asgi_auth_hardening_and_studio_revocation(tmp_path: Path) -> None:
    st_dir = tmp_path / "s6_state"
    ws_dir = tmp_path / "s6_workspace"
    ws_dir.mkdir(parents=True)

    with LiveStudioServer(st_dir, ws_dir, thread_prefix="s6-uvicorn") as srv:
        owner_pw = cli._extract_saved_password(st_dir, "pc")
        assert owner_pw

        mcp_accept_hdr = {"Accept": "application/json, text/event-stream"}

        # ------------------------------------------------------------------
        # ① Readonly endpoint `/mcp/readonly` token -> 200 on `/mcp/readonly`, 403 on `/mcp`
        # ------------------------------------------------------------------
        ro_resource = f"{srv.base_url}/mcp/readonly"
        ro_client_id, ro_tok, ro_consent_html = _oauth_dcr_and_consent(
            srv.base_url,
            owner_pw,
            client_name="ChatGPT Readonly Connector",
            redirect_uri="https://chatgpt.com/connector_platform_oauth_redirect",
            resource=ro_resource,
        )
        assert "只读连接端点" in ro_consent_html
        assert ro_tok["scope"] == "server:read"
        ro_bearer = ro_tok["access_token"]
        ro_refresh = ro_tok["refresh_token"]

        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=10.0) as http:
            # Protected resource metadata for `/mcp/readonly` advertises strictly `["server:read"]`
            prm_ro = http.get("/.well-known/oauth-protected-resource/mcp/readonly")
            assert prm_ro.status_code == 200
            assert prm_ro.json()["scopes_supported"] == ["server:read"]

            # `POST /mcp/readonly` (`tools/list`) -> 200 (only read-only tools)
            r_ro_ok = http.post(
                "/mcp/readonly",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                headers={**mcp_accept_hdr, "Authorization": f"Bearer {ro_bearer}"},
            )
            assert r_ro_ok.status_code == 200, r_ro_ok.text
            ro_tool_names = [t["name"] for t in r_ro_ok.json()["result"]["tools"]]
            assert "pc_read_file" in ro_tool_names
            assert "pc_search_code" in ro_tool_names
            assert "pc_write_file" not in ro_tool_names
            assert "pc_edit_file" not in ro_tool_names
            assert "pc_run_command" not in ro_tool_names
            assert "pc_run_python" not in ro_tool_names

            # Cross-endpoint upward escalation attempt: `POST /mcp` MUST return HTTP 403 `forbidden_cross_resource`!
            r_ro_escalate = http.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                headers={**mcp_accept_hdr, "Authorization": f"Bearer {ro_bearer}"},
            )
            assert r_ro_escalate.status_code == 403, r_ro_escalate.text
            esc_err = r_ro_escalate.json()
            assert esc_err["error"] == "forbidden_cross_resource"
            assert "Readonly endpoint token cannot access full /mcp endpoint" in esc_err["error_description"]

            # Refreshing `/mcp/readonly` token keeps narrowed `["server:read"]` scope and still 403s on `/mcp`
            r_ro_ref = http.post(
                "/token",
                data={"grant_type": "refresh_token", "refresh_token": ro_refresh, "client_id": ro_client_id},
            )
            assert r_ro_ref.status_code == 200, r_ro_ref.text
            ro_ref_data = r_ro_ref.json()
            assert ro_ref_data["scope"] == "server:read"
            ro_bearer_2 = ro_ref_data["access_token"]
            assert (
                http.post(
                    "/mcp",
                    json={"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
                    headers={**mcp_accept_hdr, "Authorization": f"Bearer {ro_bearer_2}"},
                ).status_code
                == 403
            )

        # ------------------------------------------------------------------
        # ② Full `/mcp` token + `/consent` "仅授予只读权限" & "2 小时临时会话" options
        # ------------------------------------------------------------------
        full_resource = f"{srv.base_url}/mcp"
        full_client_id, full_tok, _ = _oauth_dcr_and_consent(
            srv.base_url,
            owner_pw,
            client_name="ChatGPT Team Workspace",
            redirect_uri="https://chatgpt.com/connector_platform_oauth_redirect",
            resource=full_resource,
            grant_scope="default",
            session_ttl="30d",
        )
        assert "workspace" in full_tok["scope"].split()
        full_bearer = full_tok["access_token"]

        # Consent checkbox/radio 1: `resource=/mcp` + `grant_scope="readonly"` -> narrowed to `server:read`
        opt_ro_cid, opt_ro_tok, _ = _oauth_dcr_and_consent(
            srv.base_url,
            owner_pw,
            client_name="Readonly Consent Choice Client",
            redirect_uri="https://chatgpt.com/connector_platform_oauth_redirect",
            resource=full_resource,
            grant_scope="readonly",
            session_ttl="30d",
        )
        assert opt_ro_tok["scope"] == "server:read"

        # Consent checkbox/radio 2: `session_ttl="2h"` -> 2-hour temporary session (`expires_in == 7200`)
        t_before_2h = time.time()
        temp_cid, temp_tok, _ = _oauth_dcr_and_consent(
            srv.base_url,
            owner_pw,
            client_name="Temp 2H Guest Device",
            redirect_uri="http://127.0.0.1:43123/cb",
            resource=full_resource,
            grant_scope="default",
            session_ttl="2h",
        )
        assert temp_tok["expires_in"] == 7200

        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=10.0) as http:
            # Full `/mcp` token -> 200 on `/mcp` with all 16 core tools
            r_full_main = http.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}},
                headers={**mcp_accept_hdr, "Authorization": f"Bearer {full_bearer}"},
            )
            assert r_full_main.status_code == 200
            full_tools = [t["name"] for t in r_full_main.json()["result"]["tools"]]
            assert len(full_tools) == 16
            assert "pc_write_file" in full_tools and "pc_run_python" in full_tools
            assert "pc_skill_hub" in full_tools and "pc_skill_manage" in full_tools

            # Full `/mcp` token downward to `/mcp/readonly` -> 200 (constrained by `readonly_only=True`)
            r_full_down = http.post(
                "/mcp/readonly",
                json={"jsonrpc": "2.0", "id": 11, "method": "tools/list", "params": {}},
                headers={**mcp_accept_hdr, "Authorization": f"Bearer {full_bearer}"},
            )
            assert r_full_down.status_code == 200
            down_tools = [t["name"] for t in r_full_down.json()["result"]["tools"]]
            assert "pc_read_file" in down_tools
            assert "pc_write_file" not in down_tools

            # User-selected `grant_scope="readonly"` token -> 403 on `/mcp`, 200 on `/mcp/readonly`
            r_opt_ro_main = http.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 12, "method": "tools/list", "params": {}},
                headers={**mcp_accept_hdr, "Authorization": f"Bearer {opt_ro_tok['access_token']}"},
            )
            assert r_opt_ro_main.status_code == 403
            assert r_opt_ro_main.json()["error"] == "forbidden_cross_resource"

            r_opt_ro_sub = http.post(
                "/mcp/readonly",
                json={"jsonrpc": "2.0", "id": 13, "method": "tools/list", "params": {}},
                headers={**mcp_accept_hdr, "Authorization": f"Bearer {opt_ro_tok['access_token']}"},
            )
            assert r_opt_ro_sub.status_code == 200

            # Execute real write & edit tools via `/mcp` so `audit.jsonl` and `.undo_history` populate
            target_file = ws_dir / "s6_notes.txt"
            r_write_v1 = http.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 14,
                    "method": "tools/call",
                    "params": {
                        "name": "pc_write_file",
                        "arguments": {"path": str(target_file), "content": "version_one\n", "caller": "s6-e2e"},
                    },
                },
                headers={**mcp_accept_hdr, "Authorization": f"Bearer {full_bearer}"},
            )
            assert r_write_v1.status_code == 200
            assert r_write_v1.json()["result"]["isError"] is False

            r_edit_v2 = http.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 15,
                    "method": "tools/call",
                    "params": {
                        "name": "pc_edit_file",
                        "arguments": {
                            "path": str(target_file),
                            "old_text": "version_one",
                            "new_text": "version_two",
                            "caller": "s6-e2e",
                        },
                    },
                },
                headers={**mcp_accept_hdr, "Authorization": f"Bearer {full_bearer}"},
            )
            assert r_edit_v2.status_code == 200
            assert target_file.read_text(encoding="utf-8") == "version_two\n"

        # ------------------------------------------------------------------
        # ③ Spoofed `"My Gemini Bot"` + `oauth.sqlite3` raw-byte check + 300s concurrent refresh + Studio `revoke_client`
        # ------------------------------------------------------------------
        spoof_cid, spoof_tok, _ = _oauth_dcr_and_consent(
            srv.base_url,
            owner_pw,
            client_name="My Gemini Bot",
            redirect_uri="http://127.0.0.1:54999/callback",
            resource=full_resource,
        )
        spoof_at_0 = spoof_tok["access_token"]
        spoof_rt_0 = spoof_tok["refresh_token"]

        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=10.0) as http:
            # Concurrent refresh using `spoof_rt_0`: must rotate (`!= spoof_rt_0`, proving no Gemini non-rotating bypass)
            # AND replay within 300s+ grace window must return identical token pair!
            ref_a = http.post(
                "/token",
                data={"grant_type": "refresh_token", "refresh_token": spoof_rt_0, "client_id": spoof_cid},
            )
            ref_b = http.post(
                "/token",
                data={"grant_type": "refresh_token", "refresh_token": spoof_rt_0, "client_id": spoof_cid},
            )
            assert ref_a.status_code == 200 and ref_b.status_code == 200
            tok_a = ref_a.json()
            tok_b = ref_b.json()
            assert tok_a["refresh_token"] != spoof_rt_0, "Spoofed Gemini client_name must NOT bypass refresh rotation!"
            assert tok_a["access_token"] == tok_b["access_token"]
            assert tok_a["refresh_token"] == tok_b["refresh_token"]
            spoof_active_at = tok_a["access_token"]
            spoof_active_rt = tok_a["refresh_token"]

            # Inspect raw SQLite + WAL bytes on disk: ZERO plaintext access/refresh tokens!
            db_file = st_dir / "state" / "oauth.sqlite3"
            assert db_file.is_file()
            raw_disk_blobs = [db_file.read_bytes()]
            for sfx in ("-wal", "-shm"):
                side_p = Path(str(db_file) + sfx)
                if side_p.is_file():
                    raw_disk_blobs.append(side_p.read_bytes())
            combined_bytes = b"\n".join(raw_disk_blobs)

            all_sensitive_tokens = (
                ro_bearer,
                ro_refresh,
                ro_bearer_2,
                full_bearer,
                full_tok["refresh_token"],
                opt_ro_tok["access_token"],
                temp_tok["access_token"],
                spoof_at_0,
                spoof_rt_0,
                spoof_active_at,
                spoof_active_rt,
            )
            for raw_secret in all_sensitive_tokens:
                assert raw_secret.encode("utf-8") not in combined_bytes, (
                    "Plaintext bearer/refresh token leaked into oauth.sqlite3 raw disk bytes!"
                )

            with sqlite3.connect(str(db_file)) as conn:
                tok_rows = conn.execute(
                    "SELECT kind, key, value FROM records WHERE kind IN ('access', 'refresh', 'refresh_replay')"
                ).fetchall()
            assert len(tok_rows) >= 6
            for r_kind, r_key, r_val in tok_rows:
                assert str(r_key).startswith("sha256:"), f"Un-hashed {r_kind} key in SQLite: {r_key}"
                parsed_v = json.loads(r_val)
                assert "token" not in parsed_v
                assert "access_token" not in parsed_v
                assert "refresh_token" not in parsed_v

            # Studio state, `audit.jsonl` stream, snapshot/trash one-click recovery, and single-client `revoke_client`
            audit_jsonl = st_dir / "logs" / "audit.jsonl"
            assert audit_jsonl.is_file()
            audit_lines = [json.loads(ln) for ln in audit_jsonl.read_text(encoding="utf-8").splitlines() if ln.strip()]
            assert any(ev.get("resolved_tool") == "pc_write_file" and ev.get("caller") == "s6-e2e" for ev in audit_lines)

            trash_sample = ws_dir / "s6_trashed.txt"
            trash_sample.write_text("recover_me_s6", encoding="utf-8")
            tr_rec = safe_trash_file(trash_sample, reason="s6_test", workspace_roots=[ws_dir])
            assert not trash_sample.exists()

            st_init = http.get("/api/studio/state").json()
            csrf = st_init["csrf_token"]
            r_unlock = http.post(
                "/api/studio/unlock",
                headers={"X-Studio-Csrf": csrf},
                json={"owner_password": owner_pw},
            )
            assert r_unlock.status_code == 200
            unlocked_state = r_unlock.json()

            # Verify Studio authorized_sessions list has all 5 clients with platform, readonly/2h metadata & expiry
            sess_by_id = {s["client_id"]: s for s in unlocked_state["connection"]["authorized_sessions"]}
            assert {ro_client_id, full_client_id, opt_ro_cid, temp_cid, spoof_cid}.issubset(sess_by_id.keys())
            assert sess_by_id[ro_client_id]["readonly"] is True
            assert sess_by_id[opt_ro_cid]["readonly"] is True
            assert sess_by_id[full_client_id]["readonly"] is False
            assert sess_by_id[temp_cid]["temporary_session"] is True
            assert "2小时临时授权" in sess_by_id[temp_cid]["scope_label"]
            assert sess_by_id[temp_cid]["latest_expiry"] <= t_before_2h + 7215

            # Verify Studio `recovery.audit_events` + snapshot undo + trash restore
            audit_ui = unlocked_state["recovery"]["audit_events"]
            assert any(ev["tool"] == "pc_edit_file" for ev in audit_ui)

            r_undo = http.post(
                "/api/studio/recovery",
                headers={"X-Studio-Csrf": csrf},
                json={"action": "undo", "path": str(target_file)},
            )
            assert r_undo.status_code == 200
            assert target_file.read_text(encoding="utf-8") == "version_one\n"

            r_restore = http.post(
                "/api/studio/recovery",
                headers={"X-Studio-Csrf": csrf},
                json={"action": "restore_trash", "trash_id": tr_rec["trash_id"]},
            )
            assert r_restore.status_code == 200
            assert trash_sample.read_text(encoding="utf-8") == "recover_me_s6"

            # Verify `spoof_active_at` works (200) right BEFORE `revoke_client`, then immediately 401s AFTER `revoke_client`!
            pre_kick = http.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 20, "method": "tools/list", "params": {}},
                headers={**mcp_accept_hdr, "Authorization": f"Bearer {spoof_active_at}"},
            )
            assert pre_kick.status_code == 200

            r_kick = http.post(
                "/api/studio/connection",
                headers={"X-Studio-Csrf": csrf},
                json={"action": "revoke_client", "client_id": spoof_cid},
            )
            assert r_kick.status_code == 200
            after_ids = {s["client_id"] for s in r_kick.json()["connection"]["authorized_sessions"]}
            assert spoof_cid not in after_ids
            assert full_client_id in after_ids

            # Kicked client's access token MUST immediately fail with 401 on `/mcp` and `/mcp/readonly`
            post_kick_mcp = http.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 21, "method": "tools/list", "params": {}},
                headers={**mcp_accept_hdr, "Authorization": f"Bearer {spoof_active_at}"},
            )
            assert post_kick_mcp.status_code == 401

            post_kick_ro = http.post(
                "/mcp/readonly",
                json={"jsonrpc": "2.0", "id": 22, "method": "tools/list", "params": {}},
                headers={**mcp_accept_hdr, "Authorization": f"Bearer {spoof_active_at}"},
            )
            assert post_kick_ro.status_code == 401

            # Kicked client's refresh token (and replay cache) MUST also be invalidated
            post_kick_ref = http.post(
                "/token",
                data={"grant_type": "refresh_token", "refresh_token": spoof_active_rt, "client_id": spoof_cid},
            )
            assert post_kick_ref.status_code == 400
            assert post_kick_ref.json()["error"] == "invalid_grant"

            # Sibling full client token MUST remain 200 active!
            sibling_ok = http.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 23, "method": "tools/list", "params": {}},
                headers={**mcp_accept_hdr, "Authorization": f"Bearer {full_bearer}"},
            )
            assert sibling_ok.status_code == 200


def test_s6_headless_consent_csp_toggle_and_studio_per_client_kick_dom(tmp_path: Path) -> None:
    st_dir = tmp_path / "s6_dom_state"
    ws_dir = tmp_path / "s6_dom_ws"
    prof_dir = tmp_path / "s6_cdp_prof"
    ws_dir.mkdir(parents=True)
    prof_dir.mkdir(parents=True)

    with LiveStudioServer(st_dir, ws_dir, thread_prefix="s6-uvicorn") as srv:
        owner_pw = cli._extract_saved_password(st_dir, "pc")
        assert owner_pw

        # Mint two real OAuth clients (`keep_cid` and `kick_cid`) + run one write tool for `audit.jsonl`
        keep_cid, keep_tok, _ = _oauth_dcr_and_consent(
            srv.base_url,
            owner_pw,
            client_name="Keep Alive Client",
            redirect_uri="https://chatgpt.com/connector_platform_oauth_redirect",
            resource=f"{srv.base_url}/mcp",
        )
        kick_cid, kick_tok, _ = _oauth_dcr_and_consent(
            srv.base_url,
            owner_pw,
            client_name="Kick Target Readonly",
            redirect_uri="https://chatgpt.com/connector_platform_oauth_redirect",
            resource=f"{srv.base_url}/mcp/readonly",
        )

        mcp_accept_hdr = {"Accept": "application/json, text/event-stream"}
        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=10.0) as http:
            w_resp = http.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "pc_write_file",
                        "arguments": {"path": str(ws_dir / "dom_audit.txt"), "content": "audit_ok\n", "caller": "dom-e2e"},
                    },
                },
                headers={**mcp_accept_hdr, "Authorization": f"Bearer {keep_tok['access_token']}"},
            )
            assert w_resp.status_code == 200

            # Also create a fresh `/consent?ticket=...` URL to verify CSP Nonce eye toggle & 16px mobile input in real Chromium
            reg = http.post(
                "/register",
                json={
                    "client_name": "Mobile Consent Check",
                    "redirect_uris": ["http://127.0.0.1:45678/cb"],
                    "grant_types": ["authorization_code"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                },
            )
            mob_cid = reg.json()["client_id"]
            _, mob_chal = _make_pkce("mob_dom_check")
            a_resp = http.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": mob_cid,
                    "redirect_uri": "http://127.0.0.1:45678/cb",
                    "code_challenge": mob_chal,
                    "code_challenge_method": "S256",
                    "state": "mob_st",
                    "resource": f"{srv.base_url}/mcp/readonly",
                },
                follow_redirects=False,
            )
            consent_url = a_resp.headers["location"]
            ticket_id = parse_qs(urlsplit(consent_url).query)["ticket"][0]

        with StudioPageDriver(prof_dir) as driver:
            # 1) Mobile 390x844 `/consent?ticket=...`: verify 16px computed font-size, 4-char pair code, and CSP Nonce eye toggle
            driver.set_viewport(390, 844, mobile=True, device_scale_factor=2)
            driver.goto(consent_url, wait_studio_ready=False)
            consent_dom = driver.evaluate(
                """() => {
                    const pw = document.getElementById('consent-password');
                    const btn = document.getElementById('toggle-password-btn');
                    const pair = document.getElementById('consent-pair-code');
                    const beforeType = pw ? pw.type : '';
                    const fontSize = pw ? window.getComputedStyle(pw).fontSize : '';
                    if (btn) btn.click();
                    const toggledType = pw ? pw.type : '';
                    if (btn) btn.click();
                    const restoredType = pw ? pw.type : '';
                    return {
                        fontSize,
                        beforeType,
                        toggledType,
                        restoredType,
                        pairCode: pair ? pair.textContent.trim() : '',
                    };
                }"""
            )
            assert consent_dom["fontSize"] == "16px"
            assert consent_dom["beforeType"] == "password"
            assert consent_dom["toggledType"] == "text"
            assert consent_dom["restoredType"] == "password"
            assert consent_dom["pairCode"] == derive_consent_pair_code(ticket_id)

            # 2) Studio 1440x900: unlock -> inspect `#authorized-sessions-list` -> click `.revoke-client-btn` for `kick_cid` -> check `#audit-events-list`
            driver.set_viewport(1440, 900, mobile=False, device_scale_factor=1)
            driver.goto(f"{srv.base_url}/")
            driver.unlock_session(owner_pw)

            before_text = driver.evaluate(
                """(targetCid) => {
                    const pd = document.getElementById('pairing-sessions-details');
                    if (pd) pd.open = true;
                    const listEl = document.getElementById('authorized-sessions-list');
                    const txt = listEl ? listEl.innerText : '';
                    const btn = document.querySelector(`.revoke-client-btn[data-client-id="${targetCid}"]`);
                    if (!btn) return { foundBtn: false, beforeText: txt };
                    btn.click();
                    return { foundBtn: true, beforeText: txt };
                }""",
                kick_cid,
            )
            assert before_text["foundBtn"] is True, before_text
            assert "仅只读权限" in before_text["beforeText"]

            driver.wait_until(
                """(targetCid) => !document.querySelector(`.revoke-client-btn[data-client-id="${targetCid}"]`)""",
                arg=kick_cid,
                description="revoked client removed from DOM",
            )
            assert driver.evaluate(
                """(keepCid) => Boolean(document.querySelector(`.revoke-client-btn[data-client-id="${keepCid}"]`))""",
                keep_cid,
            ) is True

            driver.evaluate("""() => document.querySelector(".activity-seg-btn[data-activity-pane='audit']").click()""")
            audit_text = driver.wait_until(
                """() => {
                    const txt = (document.getElementById('audit-events-list') || {}).innerText || '';
                    return (txt.includes('写入文件') || txt.includes('pc_write_file')) ? txt : false;
                }""",
                description="audit event rendered",
            )
            assert "写入文件" in audit_text or "pc_write_file" in audit_text

        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=10.0) as http:
            assert (
                http.post(
                    "/mcp/readonly",
                    json={"jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {}},
                    headers={**mcp_accept_hdr, "Authorization": f"Bearer {kick_tok['access_token']}"},
                ).status_code
                == 401
            )
            assert (
                http.post(
                    "/mcp",
                    json={"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}},
                    headers={**mcp_accept_hdr, "Authorization": f"Bearer {keep_tok['access_token']}"},
                ).status_code
                == 200
            )


def test_revocable_pat_loopback_mint_scope_isolation_multigw_and_zero_plaintext(tmp_path: Path) -> None:
    """Verify revocable Sites/CLI PAT security boundaries end-to-end:
    1) `DEFAULT_REDIRECT_HOSTS` / `OPENAI_REDIRECT_HOSTS` exclude `chatgpt.site` (DCR rejects `*.chatgpt.site`);
    2) Non-loopback / proxied / missing-CSRF / cross-origin `POST /api/studio/tokens/mint` -> 403;
    3) Readonly PAT -> 200 on `/mcp/readonly` (loopback & active multi-gateways), 403 on `/mcp`;
    4) Readwrite PAT -> 200 on `/mcp` & `/mcp/readonly`, `revoke_client` immediately invalidates it (`401`);
    5) Zero `cmcp_` plaintext leakage in `/`, `/studio`, `/api/studio/state`, `/api/studio/poll`, and `oauth.sqlite3`.
    """
    from cosmos_mcp.core.config import DEFAULT_REDIRECT_HOSTS
    from cosmos_mcp.core.fs_tx import atomic_write_json
    from cosmos_mcp.protocol.oauth import OPENAI_REDIRECT_HOSTS

    # ⑤ Redirect host allowlist strictly excludes wildcard/any `chatgpt.site`
    all_redir_hosts = {h.lower() for h in (*DEFAULT_REDIRECT_HOSTS, *OPENAI_REDIRECT_HOSTS)}
    assert all("chatgpt.site" not in h for h in all_redir_hosts), all_redir_hosts

    st_dir = tmp_path / "pat_state"
    ws_dir = tmp_path / "pat_workspace"
    ws_dir.mkdir(parents=True)

    with LiveStudioServer(st_dir, ws_dir, tunnel_mode="public_gateway", thread_prefix="pat-s6") as srv:
        owner_pw = cli._extract_saved_password(st_dir, "pc")
        assert owner_pw
        auth_doc = json.loads((st_dir / "secrets" / "auth.json").read_text(encoding="utf-8"))
        local_api_tok = str(auth_doc["local_api_token"])
        mcp_accept_hdr = {"Accept": "application/json, text/event-stream"}

        # Simulate two active public gateways (`instant` srv.us + `workers_dev`) for multi-gateway PAT compatibility check
        d_status_p = st_dir / "state" / "daemon_status.json"
        atomic_write_json(
            d_status_p,
            {
                "status": "running",
                "supervisor_pid": 99999,
                "port": srv.port,
                "mode": "public_gateway",
                "effective_tunnel_mode": "srv_us",
                "public_url": "https://pat-gw1.srv.us",
                "tunnel_ready": True,
                "srvus_fixed_active": True,
                "gateways": {
                    "instant": {
                        "enabled": True,
                        "submode": "public_gateway",
                        "effective_mode": "srv_us",
                        "phase": "ready",
                        "tunnel_ready": True,
                        "public_url": "https://pat-gw1.srv.us",
                        "srvus_fixed_active": True,
                        "last_error": "",
                    },
                    "workers_dev": {
                        "enabled": True,
                        "submode": "workers_dev",
                        "effective_mode": "workers_dev",
                        "phase": "ready",
                        "tunnel_ready": True,
                        "public_url": "https://pat-gw2.demo.workers.dev",
                        "last_error": "",
                    },
                },
            },
        )

        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=10.0) as http:
            # DCR must reject `*.chatgpt.site` callback URI
            r_bad_dcr = http.post(
                "/register",
                json={
                    "client_name": "Untrusted ChatGPT Site",
                    "redirect_uris": ["https://my-team-app.chatgpt.site/oauth/callback"],
                    "grant_types": ["authorization_code"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                },
            )
            assert r_bad_dcr.status_code == 400, r_bad_dcr.text

            st0 = http.get("/api/studio/state").json()
            csrf = st0["csrf_token"]
            csrf_hdrs = {"X-Studio-Csrf": csrf, "Origin": srv.base_url}

            # Register both active gateways into provider's trusted gateway map via Studio config save/state sync
            http.post(
                "/api/studio/connection",
                headers=csrf_hdrs,
                json={
                    "action": "save_gateway_config",
                    "gateway_id": "self_hosted",
                    "submode": "custom",
                    "enabled": True,
                    "public_url": "https://pat-gw3.example.com",
                },
            )

            # ① Non-loopback / proxied / missing-CSRF / cross-origin requests to `/api/studio/tokens/mint` MUST return 403
            for tunnel_hdr in (
                {"X-Forwarded-For": "203.0.113.42"},
                {"X-Cosmos-Via-Tunnel": "1", "X-Forwarded-Host": "pat-gw1.srv.us"},
                {"CF-Connecting-IP": "198.51.100.88"},
            ):
                r_non_lb = http.post(
                    "/api/studio/tokens/mint",
                    headers={
                        **csrf_hdrs,
                        "Authorization": f"Bearer {local_api_tok}",
                        **tunnel_hdr,
                    },
                    json={"label": "Blocked Remote Mint", "readonly": True, "ttl_days": 7},
                )
                assert r_non_lb.status_code == 403, (tunnel_hdr, r_non_lb.text)

            # Even an unlocked remote Studio session cookie MUST still get 403 when non-loopback headers are present
            r_unlock = http.post(
                "/api/studio/unlock",
                headers=csrf_hdrs,
                json={"owner_password": owner_pw},
            )
            assert r_unlock.status_code == 200
            r_cookie_remote = http.post(
                "/api/studio/tokens/mint",
                headers={**csrf_hdrs, "X-Forwarded-For": "203.0.113.99"},
                json={"label": "Blocked Cookie Remote Mint", "readonly": True, "ttl_days": 7},
            )
            assert r_cookie_remote.status_code == 403

            # Loopback without CSRF (and without local Bearer) -> 403; cross-site Origin -> 403
            with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=10.0) as fresh_http:
                assert (
                    fresh_http.post(
                        "/api/studio/tokens/mint",
                        headers={"Origin": srv.base_url},
                        json={"label": "No CSRF", "readonly": True, "ttl_days": 7},
                    ).status_code
                    == 403
                )
                assert (
                    fresh_http.post(
                        "/api/studio/tokens/mint",
                        headers={"X-Studio-Csrf": csrf, "Origin": "https://evil.chatgpt.site"},
                        json={"label": "Bad Origin", "readonly": True, "ttl_days": 7},
                    ).status_code
                    == 403
                )

            # ② Mint Readonly PAT (`readonly=True`) on strict loopback -> 200 on `/mcp/readonly`, 403 on `/mcp`
            r_mint_ro = http.post(
                "/api/studio/tokens/mint",
                headers=csrf_hdrs,
                json={"label": "ChatGPT Sites Readonly", "readonly": True, "ttl_days": 7},
            )
            assert r_mint_ro.status_code == 200, r_mint_ro.text
            ro_doc = r_mint_ro.json()
            ro_minted = ro_doc["minted_token"]
            ro_pat = ro_minted["token"]
            ro_cid = ro_minted["client_id"]
            assert ro_pat.startswith("cmcp_") and len(ro_pat) >= 40
            assert ro_cid.startswith("pat_")
            assert ro_minted["readonly"] is True
            assert ro_minted["platform"] == "专用密钥 (Sites / CLI)"
            assert ro_minted["scopes"] == ["server:read"]

            # Readonly PAT succeeds on loopback `/mcp/readonly` AND active public gateway `/mcp/readonly`
            r_ro_lb = http.post(
                "/mcp/readonly",
                json={"jsonrpc": "2.0", "id": 101, "method": "tools/list", "params": {}},
                headers={**mcp_accept_hdr, "Authorization": f"Bearer {ro_pat}"},
            )
            assert r_ro_lb.status_code == 200, r_ro_lb.text
            ro_tools = [t["name"] for t in r_ro_lb.json()["result"]["tools"]]
            assert "pc_read_file" in ro_tools
            assert "pc_write_file" not in ro_tools

            r_ro_gw = http.post(
                "/mcp/readonly",
                json={"jsonrpc": "2.0", "id": 102, "method": "tools/list", "params": {}},
                headers={
                    **mcp_accept_hdr,
                    "Authorization": f"Bearer {ro_pat}",
                    "Host": "pat-gw3.example.com",
                    "X-Forwarded-Proto": "https",
                },
            )
            assert r_ro_gw.status_code == 200, r_ro_gw.text

            # Readonly PAT calling `/mcp` MUST be blocked with HTTP 403 `forbidden_cross_resource`
            for extra_h in ({}, {"Host": "pat-gw3.example.com", "X-Forwarded-Proto": "https"}):
                r_ro_esc = http.post(
                    "/mcp",
                    json={"jsonrpc": "2.0", "id": 103, "method": "tools/list", "params": {}},
                    headers={**mcp_accept_hdr, "Authorization": f"Bearer {ro_pat}", **extra_h},
                )
                assert r_ro_esc.status_code == 403, r_ro_esc.text
                assert r_ro_esc.json()["error"] == "forbidden_cross_resource"

            # ③ Mint Readwrite PAT (`readonly=False`) -> 200 on `/mcp` & `/mcp/readonly`, then `revoke_client` -> immediate 401
            r_mint_rw = http.post(
                "/api/studio/tokens/mint",
                headers=csrf_hdrs,
                json={"label": "Headless CLI Full", "readonly": False, "ttl_days": 30},
            )
            assert r_mint_rw.status_code == 200, r_mint_rw.text
            rw_minted = r_mint_rw.json()["minted_token"]
            rw_pat = rw_minted["token"]
            rw_cid = rw_minted["client_id"]
            assert rw_pat.startswith("cmcp_") and rw_pat != ro_pat
            assert rw_cid.startswith("pat_") and rw_cid != ro_cid
            assert rw_minted["readonly"] is False
            assert "workspace" in rw_minted["scopes"]

            for extra_h in ({}, {"Host": "pat-gw3.example.com", "X-Forwarded-Proto": "https"}):
                r_rw_main = http.post(
                    "/mcp",
                    json={"jsonrpc": "2.0", "id": 104, "method": "tools/list", "params": {}},
                    headers={**mcp_accept_hdr, "Authorization": f"Bearer {rw_pat}", **extra_h},
                )
                assert r_rw_main.status_code == 200, r_rw_main.text
                rw_tools = [t["name"] for t in r_rw_main.json()["result"]["tools"]]
                assert "pc_write_file" in rw_tools and "pc_run_python" in rw_tools

            # ④ Zero `cmcp_` plaintext leakage in `/`, `/studio`, `/api/studio/state`, `/api/studio/poll`, and `oauth.sqlite3`
            for check_path, check_hdrs in (
                ("/", {"Accept": "text/html"}),
                ("/studio", {"Accept": "text/html"}),
                ("/api/studio/state", {"Accept": "application/json"}),
                ("/api/studio/poll", {"Accept": "application/json"}),
            ):
                resp_chk = http.get(check_path, headers=check_hdrs)
                assert resp_chk.status_code == 200
                body_txt = resp_chk.text
                assert ro_pat not in body_txt, f"Readonly PAT leaked in {check_path}"
                assert rw_pat not in body_txt, f"Readwrite PAT leaked in {check_path}"
                assert "cmcp_" not in body_txt, f"Unexpected `cmcp_` token prefix found in {check_path}"

            st_after = http.get("/api/studio/state").json()
            sess_by_cid = {s["client_id"]: s for s in st_after["authorized_sessions"]}
            assert ro_cid in sess_by_cid and rw_cid in sess_by_cid
            assert sess_by_cid[ro_cid]["platform"] == "专用密钥 (Sites / CLI)"
            assert sess_by_cid[ro_cid]["readonly"] is True
            assert sess_by_cid[rw_cid]["platform"] == "专用密钥 (Sites / CLI)"
            assert sess_by_cid[rw_cid]["readonly"] is False

            oauth_db_files = list((st_dir / "state").glob("oauth.sqlite3*"))
            assert oauth_db_files
            for db_f in oauth_db_files:
                raw_bytes = db_f.read_bytes()
                assert ro_pat.encode("utf-8") not in raw_bytes
                assert rw_pat.encode("utf-8") not in raw_bytes
                assert b"cmcp_" not in raw_bytes

            # One-click disconnect (`revoke_client`) immediately invalidates `rw_pat` (`401`) while preserving `ro_pat` (`200`)
            r_rev = http.post(
                "/api/studio/connection",
                headers=csrf_hdrs,
                json={"action": "revoke_client", "client_id": rw_cid},
            )
            assert r_rev.status_code == 200, r_rev.text
            assert rw_cid not in {s["client_id"] for s in r_rev.json()["authorized_sessions"]}

            assert (
                http.post(
                    "/mcp",
                    json={"jsonrpc": "2.0", "id": 105, "method": "tools/list", "params": {}},
                    headers={**mcp_accept_hdr, "Authorization": f"Bearer {rw_pat}"},
                ).status_code
                == 401
            )
            assert (
                http.post(
                    "/mcp/readonly",
                    json={"jsonrpc": "2.0", "id": 106, "method": "tools/list", "params": {}},
                    headers={**mcp_accept_hdr, "Authorization": f"Bearer {rw_pat}"},
                ).status_code
                == 401
            )
            assert (
                http.post(
                    "/mcp/readonly",
                    json={"jsonrpc": "2.0", "id": 107, "method": "tools/list", "params": {}},
                    headers={**mcp_accept_hdr, "Authorization": f"Bearer {ro_pat}"},
                ).status_code
                == 200
            )

