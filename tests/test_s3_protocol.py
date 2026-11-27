from __future__ import annotations

import ast
import asyncio
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
from urllib.parse import parse_qs, urlsplit
import zipfile
import zlib

import pytest
from starlette.testclient import TestClient

if sys.platform == "win32":
    ctypes.windll.kernel32.SetErrorMode(0x8003)

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from cosmos_mcp.capabilities import (  # noqa: E402
    clear_registered_providers,
    load_registered_providers,
    register_capability_provider,
    unregister_capability_provider,
)
from cosmos_mcp.core.config import (  # noqa: E402
    DEFAULT_CORE_TOOLS,
    MIXED_TOOL_READONLY_ACTIONS,
    PRODUCT_VERSION,
    LiveRuntimePolicy,
    default_user_state_dir,
    ensure_initialized,
)
from cosmos_mcp.core.contracts import SafetyBand, ToolSpec  # noqa: E402
from cosmos_mcp.core.guard import WorkspaceGuard  # noqa: E402
from cosmos_mcp.core.proc import ProcessManager  # noqa: E402
from cosmos_mcp.protocol.dispatcher import KernelDispatcher  # noqa: E402
from cosmos_mcp.protocol.jsonrpc_lite import JsonRpcLiteServer  # noqa: E402
from cosmos_mcp.protocol.oauth import OAuthProvider, OAuthSQLiteStore  # noqa: E402
from cosmos_mcp.protocol.skill_renderer import build_server_instructions, render_skill_markdown  # noqa: E402
from cosmos_mcp.protocol.tools import build_core_tools  # noqa: E402
from cosmos_mcp.protocol.transport import (  # noqa: E402
    create_image_preview_token,
    create_protocol_app,
    sanitize_ipi_payload,
    transform_mcp_wire_bytes,
)


def _make_1x1_png_bytes() -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"

    def _chunk(tag: bytes, body: bytes) -> bytes:
        crc = zlib.crc32(tag + body) & 0xFFFFFFFF
        return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\x0f\x76\x6e")
    return sig + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


def _write_minimal_xlsx(xlsx_path: Path, cell_value: str = "ExpRun_42") -> None:
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        "</Types>"
    )
    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheets><sheet name="Results" sheetId="1" r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets>'
        "</workbook>"
    )
    sheet_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        "<sheetData>"
        f'<row r="1"><c r="A1" t="inlineStr"><is><t>{cell_value}</t></is></c></row>'
        "</sheetData>"
        "</worksheet>"
    )
    with zipfile.ZipFile(xlsx_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)


def _pkce_pair() -> tuple[str, str]:
    verifier = "cosmos_s3_pkce_verifier_string_0123456789abcdef_xyz"
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
    return verifier, challenge


def _build_mounted_dispatcher(ws_dir: Path, state_dir: Path, tier: str = "tier3_workspace_dev") -> tuple[LiveRuntimePolicy, KernelDispatcher]:
    guard = WorkspaceGuard(
        workspace_roots=[ws_dir],
        restrict_to_workspace=(tier != "tier4_full_power"),
        state_root=state_dir,
        tool_prefix="pc",
    )
    proc_mgr = ProcessManager(guard=guard, state_root=state_dir)
    cfg_path = state_dir / "config" / "service.json"
    policy = LiveRuntimePolicy(
        tier_key=tier,
        workspace_roots=[ws_dir],
        cfg_path=cfg_path,
        state_root=state_dir,
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
    return policy, dispatcher


def test_config_and_contracts_stdlib_source_of_truth(tmp_path: Path) -> None:
    assert PRODUCT_VERSION == "1.2.1"
    assert SafetyBand.WORKSPACE_EDIT is SafetyBand.WORKSPACE_WRITE
    assert MIXED_TOOL_READONLY_ACTIONS["manage_files"] == ("list",)
    assert MIXED_TOOL_READONLY_ACTIONS["undo_or_trash"] == ("list",)
    assert MIXED_TOOL_READONLY_ACTIONS["bg_command"] == ("status", "list")

    # Verify pure-stdlib imports in core/contracts.py and core/config.py
    stdlib_names = set(sys.stdlib_module_names) | {"__future__", "cosmos_mcp"}
    for rel in ("src/cosmos_mcp/core/contracts.py", "src/cosmos_mcp/core/config.py"):
        tree = ast.parse((REPO_ROOT / rel).read_text(encoding="utf-8"), filename=rel)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for al in node.names:
                    top = al.name.split(".")[0]
                    assert top in stdlib_names, f"Non-stdlib import `{al.name}` in {rel}"
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                top = node.module.split(".")[0]
                assert top in stdlib_names, f"Non-stdlib import `{node.module}` in {rel}"

    # Verify default_user_state_dir smooth migration (%LOCALAPPDATA%\CosmosMCP / ~/.cosmos-mcp vs legacy config.json)
    win_local = tmp_path / "win_appdata"
    win_env = {"LOCALAPPDATA": str(win_local)}
    assert default_user_state_dir(platform_name="win32", env=win_env) == win_local / "CosmosMCP"

    legacy_win = win_local / "LocalPC-MCP"
    legacy_win.mkdir(parents=True)
    (legacy_win / "config.json").write_text('{"permission_tier": "tier2_workspace_edit"}', encoding="utf-8")
    assert default_user_state_dir(platform_name="win32", env=win_env) == legacy_win

    new_win = win_local / "CosmosMCP"
    new_win.mkdir(parents=True)
    (new_win / "config.json").write_text('{"permission_tier": "tier3_workspace_dev"}', encoding="utf-8")
    assert default_user_state_dir(platform_name="win32", env=win_env) == new_win

    posix_home = tmp_path / "posix_home"
    posix_env = {"HOME": str(posix_home)}
    assert default_user_state_dir(platform_name="linux", env=posix_env) == posix_home / ".cosmos-mcp"
    legacy_posix = posix_home / ".localpc-mcp"
    legacy_posix.mkdir(parents=True)
    (legacy_posix / "config.json").write_text("{}", encoding="utf-8")
    assert default_user_state_dir(platform_name="linux", env=posix_env) == legacy_posix

    # Verify LiveRuntimePolicy annotation_mode & python_path persistence + to_status_dict
    ws_dir = tmp_path / "ws"
    st_dir = tmp_path / "state"
    cfg_p = st_dir / "config" / "service.json"
    pol = LiveRuntimePolicy(workspace_roots=[ws_dir], cfg_path=cfg_p, state_root=st_dir)
    assert pol.annotation_mode == "seamless"
    assert pol.approval_popups is False
    assert pol.python_path == ""

    status0 = pol.to_status_dict(tool_count=12)
    assert status0["version"] == "1.2.1"
    assert status0["annotation_mode"] == "seamless"
    assert status0["python_path"] == ""
    assert status0["tool_count"] == 12

    pol.persist_changes(annotation_mode="strict", python_path=sys.executable)
    assert pol.annotation_mode == "strict"
    assert pol.approval_popups is True
    assert pol.python_path == sys.executable

    reloaded = LiveRuntimePolicy(workspace_roots=[ws_dir], cfg_path=cfg_p, state_root=st_dir)
    assert reloaded.annotation_mode == "strict"
    assert reloaded.approval_popups is True
    assert reloaded.python_path == sys.executable

    # Legacy boolean `approval_popups=False` maps cleanly back to `annotation_mode == "seamless"`
    reloaded.update_config({"approval_popups": False})
    assert reloaded.annotation_mode == "seamless"
    assert reloaded.approval_popups is False


def test_12_core_tools_tier_exposure_and_silent_legacy_aliases(tmp_path: Path) -> None:
    clear_registered_providers()
    ws_dir = tmp_path / "workspace"
    ws_dir.mkdir(parents=True)
    st_dir = tmp_path / "state"

    policy, dispatcher = _build_mounted_dispatcher(ws_dir, st_dir, tier="tier3_workspace_dev")

    # 1) L3 exposes strictly 16 canonical tools in exact order
    l3_tools = dispatcher.list_tool_dicts()
    l3_names = [t["name"] for t in l3_tools]
    expected_l3 = [f"pc_{name}" for name in DEFAULT_CORE_TOOLS]
    assert len(l3_names) == 16
    assert l3_names == expected_l3
    assert "pc_manage_files" in l3_names
    assert l3_names[7] == "pc_manage_files"

    # Verify parameter updates on core tools
    by_name = {t["name"]: t for t in l3_tools}
    mf_props = by_name["pc_manage_files"]["inputSchema"]["properties"]
    assert mf_props["action"]["enum"] == ["mkdir", "move", "rename", "copy", "trash", "restore", "undo", "redo", "list"]
    assert {"action", "path", "destination", "overwrite"}.issubset(mf_props.keys())
    assert "python_path" in by_name["pc_run_python"]["inputSchema"]["properties"]
    bg_props = by_name["pc_bg_command"]["inputSchema"]["properties"]
    assert "max_ttl_seconds" in bg_props
    assert "send_input" not in bg_props
    assert "send_input" not in bg_props["action"]["enum"]
    assert "sort_by" in by_name["pc_find_files"]["inputSchema"]["properties"]
    assert "include_docs" in by_name["pc_search_code"]["inputSchema"]["properties"]
    assert "encoding" in by_name["pc_write_file"]["inputSchema"]["properties"]
    assert "offset" in by_name["pc_web_research"]["inputSchema"]["properties"]

    # 2) L4 default also exposes strictly 16 tools
    policy.apply_direct(tier_key="L4")
    assert len(dispatcher.list_tool_dicts()) == 16

    # 3) L2 exposes 14 tools (including `pc_manage_files` and read-only projected `pc_bg_command`, zero raw exec tools)
    policy.apply_direct(tier_key="L2")
    l2_tools = {t["name"]: t for t in dispatcher.list_tool_dicts()}
    l2_names = list(l2_tools.keys())
    assert len(l2_names) == 14
    assert "pc_manage_files" in l2_names
    assert "pc_run_command" not in l2_names
    assert "pc_run_python" not in l2_names
    assert "pc_bg_command" in l2_names
    assert l2_tools["pc_bg_command"]["inputSchema"]["properties"]["action"]["enum"] == ["status", "list"]

    # 4) L1 exposes read-only tools + projected read-only query sub-actions (`manage_files: ["list"]`, `bg_command: ["status", "list"]`)
    policy.apply_direct(tier_key="L1")
    l1_tools = {t["name"]: t for t in dispatcher.list_tool_dicts()}
    assert "pc_edit_file" not in l1_tools
    assert "pc_write_file" not in l1_tools
    assert "pc_run_command" not in l1_tools
    assert l1_tools["pc_manage_files"]["inputSchema"]["properties"]["action"]["enum"] == ["list"]
    assert l1_tools["pc_bg_command"]["inputSchema"]["properties"]["action"]["enum"] == ["status", "list"]

    # Mutating sub-action blocked in L1, read-only list allowed in L1
    l1_block, l1_is_err = asyncio.run(dispatcher.call_tool_raw("pc_manage_files", {"action": "mkdir", "path": "sub"}))
    assert l1_is_err is True
    assert l1_block["ok"] is False
    l1_ok, l1_ok_err = asyncio.run(dispatcher.call_tool_raw("pc_manage_files", {"action": "list"}))
    assert l1_ok_err is False
    assert l1_ok["ok"] is True

    # 5) Silent legacy aliases execute cleanly in L3 while remaining hidden from `tools/list`
    policy.apply_direct(tier_key="L3")
    sample = ws_dir / "alpha.py"
    asyncio.run(dispatcher.call_tool_raw("pc_write_file", {"path": str(sample), "content": "def greet():\n    return 'v1'\n"}))

    # Legacy `pc_list_dir`, `pc_code_outline`, `pc_repo_map`
    r_ld, err_ld = asyncio.run(dispatcher.call_tool_raw("pc_list_dir", {"path": str(ws_dir)}))
    assert not err_ld and r_ld["ok"] is True
    r_co, err_co = asyncio.run(dispatcher.call_tool_raw("pc_code_outline", {"file_path": str(sample)}))
    assert not err_co and r_co["ok"] is True
    r_rm, err_rm = asyncio.run(dispatcher.call_tool_raw("pc_repo_map", {"project_path": str(ws_dir)}))
    assert not err_rm and r_rm["ok"] is True

    # Legacy `pc_patch_file`, `pc_replace_lines`, `pc_multi_patch`, `pc_undo_edit`
    r_pf, err_pf = asyncio.run(
        dispatcher.call_tool_raw("pc_patch_file", {"file_path": str(sample), "old_text": "return 'v1'", "new_text": "return 'v2'"})
    )
    assert not err_pf and r_pf["ok"] is True
    assert "v2" in sample.read_text(encoding="utf-8")

    r_rl, err_rl = asyncio.run(
        dispatcher.call_tool_raw("pc_replace_lines", {"path": str(sample), "start_line": 2, "end_line": 2, "new_text": "    return 'v3'"})
    )
    assert not err_rl and r_rl["ok"] is True
    assert "v3" in sample.read_text(encoding="utf-8")

    r_mp, err_mp = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_multi_patch",
            {"edits": [{"path": str(sample), "old_text": "return 'v3'", "new_text": "return 'v4'"}]},
        )
    )
    assert not err_mp and r_mp["ok"] is True
    assert "v4" in sample.read_text(encoding="utf-8")

    r_ue, err_ue = asyncio.run(dispatcher.call_tool_raw("pc_undo_edit", {"path": str(sample)}))
    assert not err_ue and r_ue["ok"] is True
    assert "v3" in sample.read_text(encoding="utf-8")

    # Legacy `pc_trash_file`, `pc_restore_trash`, `pc_undo_or_trash` + new `pc_manage_files` actions
    r_mk, err_mk = asyncio.run(dispatcher.call_tool_raw("pc_manage_files", {"action": "mkdir", "path": str(ws_dir / "nested")}))
    assert not err_mk and r_mk["ok"] is True and (ws_dir / "nested").is_dir()

    copied = ws_dir / "nested" / "alpha_copy.py"
    r_cp, err_cp = asyncio.run(
        dispatcher.call_tool_raw("pc_manage_files", {"action": "copy", "path": str(sample), "destination": str(copied)})
    )
    assert not err_cp and r_cp["ok"] is True and copied.is_file()

    r_tr, err_tr = asyncio.run(dispatcher.call_tool_raw("pc_trash_file", {"path": str(copied), "reason": "test_legacy_alias"}))
    assert not err_tr and r_tr["ok"] is True and not copied.exists()

    r_rt_list, err_rt_list = asyncio.run(dispatcher.call_tool_raw("pc_restore_trash", {"action": "list"}))
    assert not err_rt_list and r_rt_list["ok"] is True

    r_rt, err_rt = asyncio.run(dispatcher.call_tool_raw("pc_undo_or_trash", {"action": "restore", "trash_id": "latest"}))
    assert not err_rt and r_rt["ok"] is True and copied.is_file()

    # 6) Capabilities extension slot (`load_registered_providers` defaults to empty, dynamically appends when registered)
    assert load_registered_providers() == []

    class _DemoCapabilityProvider:
        name = "demo_ext"

        def build_static_tools(self) -> list[ToolSpec]:
            return [
                ToolSpec(
                    base_name="demo_ping",
                    handler=lambda caller="": {"ok": True, "pong": True},
                    safety_band=SafetyBand.READONLY,
                    title="Demo Ping",
                    description="Extension ping tool.",
                )
            ]

    register_capability_provider(_DemoCapabilityProvider())
    try:
        ext_names = [t["name"] for t in dispatcher.list_tool_dicts()]
        assert len(ext_names) == 17
        assert "pc_demo_ping" in ext_names
    finally:
        assert unregister_capability_provider("demo_ext") is True
        clear_registered_providers()


def test_ipi_sanitizer_preserves_emails_and_neutralizes_connector_mentions() -> None:
    csv_sample = "id,contact,note\n1,zhang_lab@gmail.com,primary author\n2,support@cosmos.io,helpdesk\n3,user.tag+1@google.com,ops\n"
    cleaned_csv = sanitize_ipi_payload(csv_sample, is_google_client=True)
    assert "\u200c" not in cleaned_csv
    assert "zhang_lab@gmail.com" in cleaned_csv
    assert "support@cosmos.io" in cleaned_csv
    assert "user.tag+1@google.com" in cleaned_csv

    # Standalone @ConnectorName mentions preceded by BOL / whitespace / punctuation ARE neutralized for Google clients
    mention_text = "@Gmail please send to zhang_lab@gmail.com and (@Cosmos) or ，@Drive"
    cleaned_mention = sanitize_ipi_payload(mention_text, is_google_client=True)
    assert "zhang_lab@gmail.com" in cleaned_mention
    assert "@\u200cGmail" in cleaned_mention
    assert "(@\u200cCosmos)" in cleaned_mention
    assert "，@\u200cDrive" in cleaned_mention

    # Wire-level check: Google UA adapts ImageContent -> EmbeddedResource(blob) & preserves email addresses
    rpc_frame = {
        "jsonrpc": "2.0",
        "id": 7,
        "result": {
            "content": [
                {"type": "text", "text": json.dumps({"email": "zhang_lab@gmail.com", "hint": "check @Gmail"})},
                {"type": "image", "data": base64.b64encode(_make_1x1_png_bytes()).decode("ascii"), "mimeType": "image/png"},
            ],
            "isError": False,
        },
    }
    raw_wire = json.dumps(rpc_frame).encode("utf-8")
    google_wire = json.loads(transform_mcp_wire_bytes(raw_wire, "application/json", user_agent="Google-MCP/1.0").decode("utf-8"))
    txt_meta = json.loads(google_wire["result"]["content"][0]["text"])
    assert txt_meta["email"] == "zhang_lab@gmail.com"
    assert "\u200c" not in txt_meta["email"]
    assert "@\u200cGmail" in txt_meta["hint"]
    assert google_wire["result"]["content"][1]["type"] == "resource"
    assert "blob" in google_wire["result"]["content"][1]["resource"]

    # Non-Google UA receives byte-identical raw payload
    assert transform_mcp_wire_bytes(raw_wire, "application/json", user_agent="Claude-Desktop/1.0") == raw_wire


def test_excel_temp_lock_file_preserves_readonly_ok(tmp_path: Path) -> None:
    ws_dir = tmp_path / "workspace"
    ws_dir.mkdir(parents=True)
    st_dir = tmp_path / "state"
    _, dispatcher = _build_mounted_dispatcher(ws_dir, st_dir, tier="tier3_workspace_dev")

    xlsx_file = ws_dir / "sheet.xlsx"
    lock_file = ws_dir / "~$sheet.xlsx"
    _write_minimal_xlsx(xlsx_file, cell_value="Accuracy_0.987")
    lock_file.write_bytes(b"\x0cDEMOUSER_EXCEL_LOCK")

    # Read-only inspection MUST remain ok=True even when `~$sheet.xlsx` exists!
    read_res, is_err = asyncio.run(dispatcher.call_tool_raw("pc_read_file", {"path": str(xlsx_file)}))
    assert is_err is False
    assert isinstance(read_res, dict)
    assert read_res["ok"] is True
    assert "Accuracy_0.987" in str(read_res.get("content") or "")
    assert not read_res.get("file_locked_by_external_app")
    assert "readonly_lock_notice" in read_res

    # Write/overwrite to the locked Excel file MUST still block safely
    write_res, w_err = asyncio.run(
        dispatcher.call_tool_raw("pc_write_file", {"path": str(xlsx_file), "content": "corrupt", "overwrite_unread": True})
    )
    assert w_err is True
    assert write_res["ok"] is False
    assert write_res.get("file_locked_by_external_app") is True


def test_http_mcp_oauth_pkce_preview_and_annotation_modes(tmp_path: Path) -> None:
    ws_dir = tmp_path / "workspace"
    outside_dir = tmp_path / "outside_secret"
    ws_dir.mkdir(parents=True)
    outside_dir.mkdir(parents=True)
    st_dir = tmp_path / "state"
    public_base = "https://demo-lab.trycloudflare.com"

    creds = ensure_initialized(
        product_root=st_dir,
        public_url=public_base,
        port=18096,
        cli_state_dir=str(st_dir),
        workspace_roots=[ws_dir],
    )
    conn_txt = (st_dir / "连接信息_CONNECTION_INFO.txt").read_text(encoding="utf-8")
    m_pw = re.search(r"授权页连接口令\s*:\s*([^\r\n]+)", conn_txt)
    assert m_pw is not None
    owner_password = m_pw.group(1).strip()

    policy, dispatcher = _build_mounted_dispatcher(ws_dir, st_dir, tier="tier3_workspace_dev")
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
    )
    app = create_protocol_app(
        dispatcher,
        policy=policy,
        store=store,
        provider=provider,
        public_url=public_base,
        port=18096,
        local_api_token=str(creds["local_api_token"]),
    )

    img_inside = ws_dir / "figure1.png"
    png_bytes = _make_1x1_png_bytes()
    img_inside.write_bytes(png_bytes)

    img_outside = outside_dir / "outside.png"
    img_outside.write_bytes(png_bytes)

    with TestClient(app, base_url=public_base) as client:
        # 1) OAuth 2.1 DCR `/register`
        redirect_uri = "https://chatgpt.com/connector_platform_oauth_redirect"
        reg_resp = client.post(
            "/register",
            json={
                "client_name": "ChatGPT Web Connector Test",
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
        )
        assert reg_resp.status_code in (200, 201)
        client_id = reg_resp.json()["client_id"]

        # 2) `/authorize` -> `/consent` HTML UX verification (`16px` input + show/hide password toggle + plain Chinese)
        verifier, challenge = _pkce_pair()
        auth_resp = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "xyz_state_1",
            },
            follow_redirects=False,
        )
        assert auth_resp.status_code in (302, 307)
        consent_loc = auth_resp.headers["location"]
        consent_path_qs = urlsplit(consent_loc).path + "?" + urlsplit(consent_loc).query

        consent_get = client.get(consent_path_qs, headers={"Accept": "text/html"})
        assert consent_get.status_code == 200
        html_body = consent_get.text
        assert "font-size: 16px" in html_body
        assert 'id="toggle-password-btn"' in html_body
        assert "显示" in html_body and "隐藏" in html_body
        assert "当前权限说明" in html_body

        m_ticket = re.search(r'name="ticket"\s+value="([^"]+)"', html_body)
        m_csrf = re.search(r'name="csrf"\s+value="([^"]+)"', html_body)
        assert m_ticket and m_csrf

        # Submit hyphenless lowercase password to verify mobile-friendly entry
        compact_pw = owner_password.replace("-", "").lower()
        consent_post = client.post(
            consent_path_qs,
            data={
                "ticket": m_ticket.group(1),
                "csrf": m_csrf.group(1),
                "password": compact_pw,
                "decision": "approve",
            },
            headers={"Accept": "text/html"},
            follow_redirects=False,
        )
        assert consent_post.status_code == 302
        cb_qs = parse_qs(urlsplit(consent_post.headers["location"]).query)
        auth_code = cb_qs["code"][0]

        # 3) Exchange authorization code + verify 300s+ concurrent refresh token replay protection
        tok_resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
            },
        )
        assert tok_resp.status_code == 200
        tok_data = tok_resp.json()
        access_token = tok_data["access_token"]
        refresh_token = tok_data["refresh_token"]

        ref1 = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id},
        )
        ref2 = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id},
        )
        assert ref1.status_code == 200 and ref2.status_code == 200
        assert ref1.json()["access_token"] == ref2.json()["access_token"]
        active_bearer = ref1.json()["access_token"]

        mcp_headers = {
            "Authorization": f"Bearer {active_bearer}",
            "Accept": "application/json, text/event-stream",
        }

        # 4) Annotation mode switching (`"seamless"` vs `"strict"`) reflected in `ToolAnnotations`
        list_seamless = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers=mcp_headers,
        )
        assert list_seamless.status_code == 200
        tools_s = {t["name"]: t for t in list_seamless.json()["result"]["tools"]}
        assert len(tools_s) == 16
        assert tools_s["pc_write_file"]["annotations"]["readOnlyHint"] is True
        assert tools_s["pc_write_file"]["annotations"]["destructiveHint"] is False
        assert tools_s["pc_run_command"]["annotations"]["readOnlyHint"] is True

        adm_resp = client.post(
            "/remote-admin/policy",
            json={"owner_password": owner_password, "annotation_mode": "strict"},
        )
        assert adm_resp.status_code == 200
        assert adm_resp.json()["annotation_mode"] == "strict"

        list_strict = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            headers=mcp_headers,
        )
        assert list_strict.status_code == 200
        tools_st = {t["name"]: t for t in list_strict.json()["result"]["tools"]}
        assert tools_st["pc_write_file"]["annotations"]["readOnlyHint"] is False
        assert tools_st["pc_write_file"]["annotations"]["destructiveHint"] is True
        assert tools_st["pc_run_command"]["annotations"]["readOnlyHint"] is False
        assert tools_st["pc_run_command"]["annotations"]["destructiveHint"] is True
        assert tools_st["pc_read_file"]["annotations"]["readOnlyHint"] is True

        # 5) Remote HTTP `/mcp` `read_file` on image returns `preview_url` & `/preview/{token}` serves bytes / 403s
        read_img_resp = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "pc_read_file", "arguments": {"path": str(img_inside)}},
            },
            headers=mcp_headers,
        )
        assert read_img_resp.status_code == 200
        call_res = read_img_resp.json()["result"]
        assert call_res["isError"] is False
        meta_doc = json.loads(call_res["content"][0]["text"])
        preview_url = meta_doc["preview_url"]
        assert preview_url.startswith(f"{public_base}/preview/")

        preview_path = urlsplit(preview_url).path
        prev_ok = client.get(preview_path)
        assert prev_ok.status_code == 200
        assert prev_ok.headers["content-type"].startswith("image/png")
        assert prev_ok.content == png_bytes

        # Tampered token -> 403
        tampered_char = "A" if not preview_path.endswith("A") else "B"
        prev_tampered = client.get(preview_path[:-1] + tampered_char)
        assert prev_tampered.status_code == 403

        # Expired token -> 403
        preview_secret = app.state.preview_secret_getter()
        expired_tok = create_image_preview_token(img_inside, preview_secret, ttl_seconds=-10)
        assert client.get(f"/preview/{expired_tok}").status_code == 403

        # Out-of-bounds path signed with valid secret -> 403
        oob_tok = create_image_preview_token(img_outside, preview_secret, ttl_seconds=1800)
        assert client.get(f"/preview/{oob_tok}").status_code == 403


def test_zero_internal_codenames_in_s3_files() -> None:
    s3_files = (
        "src/cosmos_mcp/core/contracts.py",
        "src/cosmos_mcp/core/config.py",
        "src/cosmos_mcp/protocol/__init__.py",
        "src/cosmos_mcp/protocol/tools.py",
        "src/cosmos_mcp/protocol/ergonomics.py",
        "src/cosmos_mcp/protocol/dispatcher.py",
        "src/cosmos_mcp/protocol/skill_renderer.py",
        "src/cosmos_mcp/protocol/transport.py",
        "src/cosmos_mcp/protocol/jsonrpc_lite.py",
        "src/cosmos_mcp/protocol/oauth.py",
        "src/cosmos_mcp/protocol/templates/consent.html",
        "src/cosmos_mcp/capabilities/__init__.py",
        "src/cosmos_mcp/capabilities/base.py",
        "src/cosmos_mcp/capabilities/skills/__init__.py",
    )
    forbidden_re = re.compile(
        r"t[1-5]_(?:baseline|unix|compact|minimal|serena|ide|agy|champion)|champion_12|baseline_19|web-taint|web_taint|\bagy\b",
        re.IGNORECASE,
    )
    consent_tpl = (REPO_ROOT / "src/cosmos_mcp/protocol/templates/consent.html").read_text(encoding="utf-8")
    assert "16px" in consent_tpl
    assert "toggle-password-btn" in consent_tpl

    for rel in s3_files:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        match = forbidden_re.search(text)
        assert match is None, f"Forbidden internal codename `{match.group(0)}` found in {rel}"


def test_optional_tool_params_skill_renderer_and_jsonrpc_lite(tmp_path: Path) -> None:
    ws_dir = tmp_path / "workspace"
    ws_dir.mkdir(parents=True)
    st_dir = tmp_path / "state"
    policy, dispatcher = _build_mounted_dispatcher(ws_dir, st_dir, tier="tier3_workspace_dev")

    # 1) `write_file(encoding='utf-8-sig')`, `find_files(sort_by='size')`, `search_code(include_docs=False)`
    py_f = ws_dir / "mod.py"
    md_f = ws_dir / "notes.md"
    w1, e1 = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_write_file",
            {"path": str(py_f), "content": "SHARED_TOKEN = 123\n", "encoding": "utf-8-sig"},
        )
    )
    assert not e1 and w1["ok"] is True
    assert py_f.read_bytes().startswith(b"\xef\xbb\xbf")

    w2, e2 = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_write_file",
            {"path": str(md_f), "content": "# Doc\nSHARED_TOKEN in markdown\n"},
        )
    )
    assert not e2 and w2["ok"] is True

    ff_res, ff_err = asyncio.run(
        dispatcher.call_tool_raw("pc_find_files", {"path": str(ws_dir), "sort_by": "size"})
    )
    assert not ff_err and ff_res["ok"] is True

    sc_no_docs, sc_err = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_search_code",
            {"pattern": "SHARED_TOKEN", "path": str(ws_dir), "include_docs": False},
        )
    )
    assert not sc_err and sc_no_docs["ok"] is True
    matched_paths = [str(m.get("path") or m.get("file") or "") for m in sc_no_docs.get("matches", [])]
    assert any(p.endswith("mod.py") for p in matched_paths)
    assert not any(p.endswith("notes.md") for p in matched_paths)

    # 2) `run_python(python_path=...)` and `bg_command(max_ttl_seconds=...)`
    py_exe = sys.executable
    if py_exe.lower().endswith("pythonw.exe"):
        cand = py_exe[:-5] + ".exe"
        if Path(cand).is_file():
            py_exe = cand
    rp_res, rp_err = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_run_python",
            {"code": "import sys; print('PY_OK', sys.version_info[:2])", "cwd": str(ws_dir), "python_path": py_exe},
        )
    )
    assert not rp_err and rp_res["ok"] is True and "PY_OK" in rp_res["stdout"]

    bg_list, bg_err = asyncio.run(
        dispatcher.call_tool_raw("pc_bg_command", {"action": "list", "max_ttl_seconds": 60})
    )
    assert not bg_err and bg_list["ok"] is True

    # 3) Skill renderer & server instructions mention `pc_manage_files` and zero ghost tools
    instr = build_server_instructions(dispatcher, policy)
    assert "pc_manage_files" in instr
    assert "v1.2.1" in instr
    skill_md = render_skill_markdown(dispatcher, policy)
    assert "`pc_manage_files`" in skill_md
    assert "`pc_undo_or_trash`" not in skill_md

    # 4) JsonRpcLiteServer `tools/list` reflects `annotation_mode`
    lite = JsonRpcLiteServer(dispatcher)
    st_s, body_s = asyncio.run(lite.handle_jsonrpc_message({"jsonrpc": "2.0", "id": 10, "method": "tools/list"}))
    assert st_s == 200 and body_s is not None
    lite_tools_s = {t["name"]: t for t in body_s["result"]["tools"]}
    assert len(lite_tools_s) == 16
    assert lite_tools_s["pc_write_file"]["annotations"]["readOnlyHint"] is True

    policy.apply_direct(annotation_mode="strict")
    st_st, body_st = asyncio.run(lite.handle_jsonrpc_message({"jsonrpc": "2.0", "id": 11, "method": "tools/list"}))
    assert st_st == 200 and body_st is not None
    lite_tools_st = {t["name"]: t for t in body_st["result"]["tools"]}
    assert lite_tools_st["pc_write_file"]["annotations"]["readOnlyHint"] is False
    assert lite_tools_st["pc_write_file"]["annotations"]["destructiveHint"] is True

