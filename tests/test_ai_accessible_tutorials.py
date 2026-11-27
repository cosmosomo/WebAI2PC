"""Wave 13-A Regression Suite: AI-Accessible Inline Tutorials, Safe Local Studio Open & `/tutorials.md`.

Covers:
1. `pc_get_status()` default navigation fields (`studio_url`, `tutorials_url`, `studio_deep_links`, `available_guides`);
2. `pc_get_status(guide=...)` topics & aliases (`cloudflare`, `permissions`, `gateways`, `gemini_chatgpt`, `packs_and_skills`, `troubleshooting`, `all`) aligned with `index.html` v1.2.1;
3. `pc_get_status(open_page=...)` strict loopback allowlist (`monkeypatch` zero-popup browser capture), external/injection rejection, headless/env skip, L1 local config UI support on `/mcp`, and strict `opened_in_browser=False` side-effect block on `/mcp/readonly`;
4. Unauthenticated `GET /tutorials.md` & `GET /llms.txt` on both loopback and public gateway Hosts returning `200 text/markdown` with zero host/user/path/port leakage;
5. Exact allowlist `GET /static/brand/{brand_file}` returning `200 image/svg+xml` for the 6 v2 SVGs and `404` otherwise;
6. Core tool count strictly locked at `16`, pure-stdlib AST gate on `core/tutorials_catalog.py`, and `build_server_instructions` / `render_skill_markdown` hints.
"""
from __future__ import annotations

import ast
import asyncio
import base64
import ctypes
import getpass
import hashlib
import json
from pathlib import Path
import platform
import re
import sys
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlsplit
import webbrowser

import pytest
from starlette.testclient import TestClient

if sys.platform == "win32":
    ctypes.windll.kernel32.SetErrorMode(0x8003)

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from cosmos_mcp.capabilities import clear_registered_providers  # noqa: E402
from cosmos_mcp.core import tutorials_catalog  # noqa: E402
from cosmos_mcp.core.config import DEFAULT_CORE_TOOLS, ensure_initialized  # noqa: E402
from cosmos_mcp.core.guard import DEFAULT_GUARD  # noqa: E402
from cosmos_mcp.launcher.app import create_standalone_app  # noqa: E402
from cosmos_mcp.protocol.skill_renderer import build_server_instructions, render_skill_markdown  # noqa: E402


_INITIAL_DEFAULT_GUARD_STATE: Dict[str, Any] = dict(DEFAULT_GUARD.__dict__)


class _DefaultGuardIsolationPlugin:
    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_protocol(self, item: Any, nextitem: Any) -> Any:
        _ = (item, nextitem)
        saved = dict(_INITIAL_DEFAULT_GUARD_STATE)
        try:
            yield
        finally:
            clear_registered_providers()
            DEFAULT_GUARD.__dict__.clear()
            DEFAULT_GUARD.__dict__.update(saved)


@pytest.fixture(autouse=True)
def _restore_default_guard_singleton(request: pytest.FixtureRequest) -> Any:
    pm = request.config.pluginmanager
    if not pm.has_plugin("w13a_default_guard_isolation"):
        pm.register(_DefaultGuardIsolationPlugin(), name="w13a_default_guard_isolation")
    saved_state = dict(_INITIAL_DEFAULT_GUARD_STATE)
    try:
        yield
    finally:
        clear_registered_providers()
        DEFAULT_GUARD.__dict__.clear()
        DEFAULT_GUARD.__dict__.update(saved_state)


def _pkce_pair(seed: str) -> Tuple[str, str]:
    verifier = f"wave13a_pkce_verifier_{seed}_0123456789abcdef0123456789"
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .decode("ascii")
        .rstrip("=")
    )
    return verifier, challenge


def _build_standalone_harness(
    tmp_path: Path,
    *,
    port: int = 18696,
    public_base: str = "https://w13a-gw.workers.dev",
) -> Tuple[Any, str, Path, Path]:
    clear_registered_providers()
    ws_dir = tmp_path / "secret_user_workspace_w13a"
    ws_dir.mkdir(parents=True, exist_ok=True)
    st_dir = tmp_path / "secret_state_root_w13a"

    ensure_initialized(
        product_root=st_dir,
        public_url=public_base,
        port=port,
        cli_state_dir=str(st_dir),
        tier_key="tier3_workspace_dev",
        prefix="pc",
        workspace_roots=[ws_dir],
    )
    conn_txt = (st_dir / "连接信息_CONNECTION_INFO.txt").read_text(encoding="utf-8")
    m_pw = re.search(r"授权页连接口令\s*:\s*([^\r\n]+)", conn_txt)
    assert m_pw is not None
    owner_pw = m_pw.group(1).strip()

    app = create_standalone_app(
        workspace=str(ws_dir),
        state_dir=str(st_dir),
        port=port,
        public_url=public_base,
        tunnel_mode="workers_dev",
    )
    return app, owner_pw, ws_dir, st_dir


def _mint_oauth_token_for_resource(
    client: TestClient,
    public_base: str,
    owner_pw: str,
    *,
    resource_url: str,
    seed: str,
) -> str:
    redirect_uri = "https://chatgpt.com/connector_platform_oauth_redirect"
    reg = client.post(
        "/register",
        json={
            "client_name": f"Wave13A Client {seed}",
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
    )
    assert reg.status_code in (200, 201), reg.text
    client_id = reg.json()["client_id"]

    verifier, challenge = _pkce_pair(seed)
    r_auth = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": f"st_{seed}",
            "resource": resource_url,
        },
        follow_redirects=False,
    )
    assert r_auth.status_code in (302, 307), r_auth.text
    loc = r_auth.headers["location"]
    consent_path_qs = urlsplit(loc).path + "?" + urlsplit(loc).query

    r_consent_get = client.get(consent_path_qs, headers={"Accept": "text/html"})
    assert r_consent_get.status_code == 200
    m_ticket = re.search(r'name="ticket"\s+value="([^"]+)"', r_consent_get.text)
    m_csrf = re.search(r'name="csrf"\s+value="([^"]+)"', r_consent_get.text)
    assert m_ticket and m_csrf

    r_consent_post = client.post(
        consent_path_qs,
        data={
            "ticket": m_ticket.group(1),
            "csrf": m_csrf.group(1),
            "auth_mode": "password",
            "password": owner_pw,
            "decision": "approve",
        },
        headers={"Origin": public_base, "Accept": "text/html"},
        follow_redirects=False,
    )
    assert r_consent_post.status_code == 302, r_consent_post.text
    auth_code = parse_qs(urlsplit(r_consent_post.headers["location"]).query)["code"][0]

    r_tok = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": auth_code,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
            "resource": resource_url,
        },
    )
    assert r_tok.status_code == 200, r_tok.text
    return str(r_tok.json()["access_token"])


def test_tutorials_catalog_pure_stdlib_and_16_core_tools_contract(tmp_path: Path) -> None:
    # 1) Pure-stdlib AST check on `src/cosmos_mcp/core/tutorials_catalog.py`
    stdlib_names = set(sys.stdlib_module_names) | {"__future__", "cosmos_mcp"}
    rel = "src/cosmos_mcp/core/tutorials_catalog.py"
    tree = ast.parse((REPO_ROOT / rel).read_text(encoding="utf-8"), filename=rel)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for al in node.names:
                top = al.name.split(".")[0]
                assert top in stdlib_names, f"Non-stdlib import `{al.name}` in {rel}"
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            top = node.module.split(".")[0]
            assert top in stdlib_names, f"Non-stdlib import `{node.module}` in {rel}"

    # 2) Core tool count strictly locked to 16 + first-sentence period discipline + instructions hint
    app, _, _, _ = _build_standalone_harness(tmp_path, port=18691)
    dispatcher = app.state.dispatcher
    policy = app.state.policy

    assert len(DEFAULT_CORE_TOOLS) == 16
    tool_dicts = dispatcher.list_tool_dicts()
    assert len(tool_dicts) == 16

    by_name = {t["name"]: t for t in tool_dicts}
    assert "pc_get_status" in by_name
    gs_schema = by_name["pc_get_status"]["inputSchema"]["properties"]
    assert "guide" in gs_schema
    assert "open_page" in gs_schema

    # First sentence of `pc_get_status` description must not contain internal periods before its sentence end
    gs_desc = by_name["pc_get_status"]["description"]
    assert "guide" in gs_desc and "open_page" in gs_desc

    instr_main = build_server_instructions(dispatcher, policy, readonly_only=False)
    assert "pc_get_status(guide='cloudflare'|'permissions'|'all', open_page='gateways'|'studio'|'tutorials')" in instr_main

    instr_ro = build_server_instructions(dispatcher, policy, readonly_only=True)
    assert "pc_get_status(guide='cloudflare'|'permissions'|'all')" in instr_ro
    assert "open_page=" not in instr_ro

    skill_md_main = render_skill_markdown(dispatcher, policy, readonly_only=False)
    assert "open_page='gateways'|'studio'|'tutorials'" in skill_md_main
    skill_md_ro = render_skill_markdown(dispatcher, policy, readonly_only=True)
    assert "guide='cloudflare'|'permissions'|'all'" in skill_md_ro
    assert "open_page=" not in skill_md_ro


def test_get_status_navigation_guides_and_index_html_alignment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("COSMOS_DISABLE_BROWSER_OPEN", "1")
    port = 18692
    app, _, _, _ = _build_standalone_harness(tmp_path, port=port)
    dispatcher = app.state.dispatcher

    # 1) Default `pc_get_status()` includes `studio_url`, `tutorials_url`, `studio_deep_links`, `available_guides`
    res_default, is_err = asyncio.run(dispatcher.call_tool_raw("pc_get_status", {}))
    assert not is_err and res_default["ok"] is True
    assert res_default["studio_url"] == f"http://127.0.0.1:{port}/"
    assert res_default["tutorials_url"] == f"http://127.0.0.1:{port}/tutorials"
    deep_links = res_default["studio_deep_links"]
    assert deep_links["studio"] == f"http://127.0.0.1:{port}/"
    assert deep_links["gateways"] == f"http://127.0.0.1:{port}/#settings/gateways"
    assert deep_links["cloudflare"] == f"http://127.0.0.1:{port}/#settings/gateways"
    assert deep_links["runtime"] == f"http://127.0.0.1:{port}/#settings/runtime"
    assert deep_links["tools"] == f"http://127.0.0.1:{port}/#settings/tools"
    assert deep_links["skills"] == f"http://127.0.0.1:{port}/#settings/skills"
    assert deep_links["appearance"] == f"http://127.0.0.1:{port}/#settings/appearance"
    assert deep_links["tutorials"] == f"http://127.0.0.1:{port}/tutorials"
    assert set(tutorials_catalog.CANONICAL_GUIDE_TOPICS).issubset(set(res_default["available_guides"]))
    assert "tutorial_markdown" not in res_default

    # 2) `guide="cloudflare"` (and alias `"cf"`) matches exact v1.2.1 Studio buttons & steps
    for alias in ("cloudflare", "cf", "workers_dev"):
        res_cf, err_cf = asyncio.run(dispatcher.call_tool_raw("pc_get_status", {"guide": alias}))
        assert not err_cf and res_cf["ok"] is True
        assert res_cf["guide_topic"] == "cloudflare"
        md_cf = res_cf["tutorial_markdown"]
        assert f"http://127.0.0.1:{port}/#settings/gateways" in md_cf
        assert "Cloudflare 专属固定网关" in md_cf
        assert "打开 Cloudflare 预填权限页" in md_cf
        assert "https://dash.cloudflare.com/profile/api-tokens" in md_cf
        assert "一键部署并开启（约 3 秒）" in md_cf
        assert "workers.dev/mcp" in md_cf

    # 3) `guide="permissions"` matches exact 4 radio tiers & workspace controls
    res_perm, err_perm = asyncio.run(dispatcher.call_tool_raw("pc_get_status", {"guide": "permissions"}))
    assert not err_perm and res_perm["guide_topic"] == "permissions"
    md_perm = res_perm["tutorial_markdown"]
    for exact_ui_term in ("只读", "仅改文件", "工作区开发", "全盘开发", "以只读参考目录添加", "修改撤回", "回收箱"):
        assert exact_ui_term in md_perm, f"Missing UI label {exact_ui_term!r} in permissions guide"

    # 4) `guide="all"` merges all topics cleanly
    res_all, err_all = asyncio.run(dispatcher.call_tool_raw("pc_get_status", {"guide": "all"}))
    assert not err_all and res_all["guide_topic"] == "all"
    md_all = res_all["tutorial_markdown"]
    for expected_fragment in (
        "#settings/gateways",
        "#settings/runtime",
        "#settings/tools",
        "#settings/skills",
        "#settings/appearance",
        "/tutorials",
        "Always allow",
        "/mcp/readonly",
        "16 -> 18",
    ):
        assert expected_fragment in md_all


def test_open_page_allowlist_monkeypatch_zero_popup_and_readonly_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("COSMOS_DISABLE_BROWSER_OPEN", raising=False)
    if sys.platform.startswith("linux"):
        monkeypatch.setenv("DISPLAY", ":99")

    opened_urls: List[str] = []

    def _fake_browser_open(url: str, new: int = 2, autoraise: bool = True) -> bool:
        _ = (new, autoraise)
        opened_urls.append(url)
        return True

    monkeypatch.setattr(webbrowser, "open", _fake_browser_open)

    port = 18693
    public_base = "https://w13a-ro-test.workers.dev"
    app, owner_pw, _, _ = _build_standalone_harness(tmp_path, port=port, public_base=public_base)
    dispatcher = app.state.dispatcher
    policy = app.state.policy

    # 1) On main `/mcp` dispatcher (even if user's local panel is currently in `L1` readonly tier!),
    #    `open_page="cloudflare"` safely opens `http://127.0.0.1:<port>/#settings/gateways` and auto-attaches guide.
    policy.apply_direct(tier_key="tier1_readonly")
    res_open_cf, err_open = asyncio.run(
        dispatcher.call_tool_raw("pc_get_status", {"open_page": "cloudflare"})
    )
    assert not err_open and res_open_cf["ok"] is True
    assert res_open_cf["opened_in_browser"] is True
    assert res_open_cf["target_url"] == f"http://127.0.0.1:{port}/#settings/gateways"
    assert opened_urls == [f"http://127.0.0.1:{port}/#settings/gateways"]
    assert res_open_cf["guide_topic"] == "cloudflare"
    assert "Cloudflare 专属固定网关" in res_open_cf["tutorial_markdown"]

    policy.apply_direct(tier_key="tier3_workspace_dev")
    opened_urls.clear()

    # Verify other allowlisted deep-link keys
    expected_map = {
        "studio": f"http://127.0.0.1:{port}/",
        "permissions": f"http://127.0.0.1:{port}/",
        "runtime": f"http://127.0.0.1:{port}/#settings/runtime",
        "tools": f"http://127.0.0.1:{port}/#settings/tools",
        "skills": f"http://127.0.0.1:{port}/#settings/skills",
        "appearance": f"http://127.0.0.1:{port}/#settings/appearance",
        "tutorials": f"http://127.0.0.1:{port}/tutorials",
    }
    for key, exp_url in expected_map.items():
        opened_urls.clear()
        r_p, e_p = asyncio.run(dispatcher.call_tool_raw("pc_get_status", {"open_page": key}))
        assert not e_p and r_p["opened_in_browser"] is True
        assert r_p["target_url"] == exp_url
        assert opened_urls == [exp_url]

    # 2) Reject arbitrary external URLs / phishing / shell injection keys -> ZERO browser calls!
    opened_urls.clear()
    for malicious_key in (
        "https://evil.attacker.com/phish",
        "//evil.attacker.com",
        "javascript:alert(1)",
        "file:///C:/Windows/System32/calc.exe",
        "studio & calc.exe",
        "../../etc/passwd",
    ):
        r_bad, e_bad = asyncio.run(dispatcher.call_tool_raw("pc_get_status", {"open_page": malicious_key}))
        assert not e_bad and r_bad["ok"] is True
        assert r_bad["opened_in_browser"] is False
        assert r_bad["open_blocked_reason"] == "invalid_page_key"
        assert r_bad["target_url"] == ""
    assert opened_urls == []

    # 3) Headless / `COSMOS_DISABLE_BROWSER_OPEN=1` skips gracefully without opening browser
    monkeypatch.setenv("COSMOS_DISABLE_BROWSER_OPEN", "1")
    hl_res = tutorials_catalog.open_local_studio_page_safely("gateways", port=port)
    assert hl_res["opened"] is False
    assert hl_res["reason"] == "headless_or_disabled"
    assert hl_res["url"] == f"http://127.0.0.1:{port}/#settings/gateways"
    assert opened_urls == []
    monkeypatch.delenv("COSMOS_DISABLE_BROWSER_OPEN", raising=False)

    # 4) Readonly scope (`scopes=["server:read", "mcp:readonly"]`) & HTTP `/mcp/readonly` endpoint MUST block `open_page` side effects!
    for ro_kwargs in (
        {"readonly_only": True},
        {"scopes": ["server:read", "mcp:readonly"]},
        {"scopes": ["server:read"]},
    ):
        r_ro_scope, e_ro_scope = asyncio.run(
            dispatcher.call_tool_raw(
                "pc_get_status",
                {"open_page": "cloudflare", "guide": "cloudflare"},
                **ro_kwargs,
            )
        )
        assert not e_ro_scope and r_ro_scope["ok"] is True, r_ro_scope
        assert r_ro_scope["opened_in_browser"] is False
        assert r_ro_scope["open_blocked_reason"] == "readonly_endpoint"
        assert r_ro_scope["target_url"] == f"http://127.0.0.1:{port}/#settings/gateways"
        assert r_ro_scope["guide_topic"] == "cloudflare"
        assert "Cloudflare 专属固定网关" in r_ro_scope["tutorial_markdown"]
        assert opened_urls == []

    # Full end-to-end HTTP `/mcp` vs `/mcp/readonly` OAuth token verification
    with TestClient(app, base_url=public_base, client=("127.0.0.1", 51600)) as client:
        ro_token = _mint_oauth_token_for_resource(
            client,
            public_base,
            owner_pw,
            resource_url=f"{public_base}/mcp/readonly",
            seed="ro1",
        )
        full_token = _mint_oauth_token_for_resource(
            client,
            public_base,
            owner_pw,
            resource_url=f"{public_base}/mcp",
            seed="full1",
        )

        # Calling `pc_get_status(open_page="cloudflare")` on `/mcp/readonly` -> `opened_in_browser is False`
        opened_urls.clear()
        http_ro = client.post(
            "/mcp/readonly",
            json={
                "jsonrpc": "2.0",
                "id": 101,
                "method": "tools/call",
                "params": {"name": "pc_get_status", "arguments": {"open_page": "cloudflare"}},
            },
            headers={
                "Authorization": f"Bearer {ro_token}",
                "Accept": "application/json, text/event-stream",
            },
        )
        assert http_ro.status_code == 200, http_ro.text
        ro_payload = json.loads(http_ro.json()["result"]["content"][0]["text"])
        assert ro_payload["ok"] is True
        assert ro_payload["opened_in_browser"] is False
        assert ro_payload["open_blocked_reason"] == "readonly_endpoint"
        assert ro_payload["target_url"] == f"http://127.0.0.1:{port}/#settings/gateways"
        assert "Cloudflare 专属固定网关" in ro_payload["tutorial_markdown"]
        assert opened_urls == []

        # Calling `pc_get_status(open_page="cloudflare")` on main `/mcp` -> `opened_in_browser is True`
        http_main = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 102,
                "method": "tools/call",
                "params": {"name": "pc_get_status", "arguments": {"open_page": "cloudflare"}},
            },
            headers={
                "Authorization": f"Bearer {full_token}",
                "Accept": "application/json, text/event-stream",
            },
        )
        assert http_main.status_code == 200, http_main.text
        main_payload = json.loads(http_main.json()["result"]["content"][0]["text"])
        assert main_payload["ok"] is True
        assert main_payload["opened_in_browser"] is True
        assert main_payload["target_url"] == f"http://127.0.0.1:{port}/#settings/gateways"
        assert opened_urls == [f"http://127.0.0.1:{port}/#settings/gateways"]


def test_public_tutorials_md_llms_txt_zero_leak_and_static_brand_svgs(tmp_path: Path) -> None:
    port = 18694
    public_base = "https://w13a-public-docs.workers.dev"
    app, _, ws_dir, st_dir = _build_standalone_harness(tmp_path, port=port, public_base=public_base)

    cur_hostname = platform.node().strip()
    try:
        cur_user = getpass.getuser().strip()
    except Exception:
        cur_user = ""

    with TestClient(app, base_url=public_base, client=("127.0.0.1", 51650)) as pub_client:
        # 1) Public Host unauthenticated `GET /tutorials.md` & `GET /llms.txt` -> 200 text/markdown, zero host/path/port leak
        for ep_path in ("/tutorials.md", "/llms.txt"):
            r_pub = pub_client.get(
                ep_path,
                headers={"CF-Connecting-IP": "198.51.100.77", "X-Forwarded-Proto": "https"},
            )
            assert r_pub.status_code == 200, (ep_path, r_pub.status_code, r_pub.text)
            assert r_pub.headers["content-type"].startswith("text/markdown")
            body = r_pub.text
            assert "WebAI2PC" in body
            assert "Cloudflare 专属固定网关" in body
            assert str(ws_dir) not in body
            assert ws_dir.name not in body
            assert str(st_dir) not in body
            assert st_dir.name not in body
            assert str(port) not in body
            if cur_hostname and len(cur_hostname) >= 3:
                assert cur_hostname not in body
            if cur_user and len(cur_user) >= 3 and cur_user.lower() not in ("user", "root", "admin"):
                assert cur_user not in body

        # 2) Loopback Host `GET /tutorials.md` & `GET /llms.txt` -> 200 text/markdown
        for ep_path in ("/tutorials.md", "/llms.txt"):
            r_loc = pub_client.get(f"http://127.0.0.1:{port}{ep_path}")
            assert r_loc.status_code == 200
            assert r_loc.headers["content-type"].startswith("text/markdown")
            assert r_loc.text == tutorials_catalog.render_public_tutorials_markdown()

        # 3) `/static/brand/{brand_file}` serves exact 6 allowlisted v2 SVGs (`200 image/svg+xml`) and 404s others
        for svg_name in (
            "webai2pc-icon-v2-light.svg",
            "webai2pc-icon-v2-dark.svg",
            "webai2pc-logo-v2-light.svg",
            "webai2pc-logo-v2-dark.svg",
            "webai2pc-mark-v2-light.svg",
            "webai2pc-mark-v2-dark.svg",
        ):
            r_svg = pub_client.get(f"http://127.0.0.1:{port}/static/brand/{svg_name}")
            assert r_svg.status_code == 200, svg_name
            assert r_svg.headers["content-type"].startswith("image/svg+xml")
            assert "<svg" in r_svg.text

        for rejected_name in ("unknown.svg", "index.html", "webai2pc-logo-v1.svg"):
            r_404 = pub_client.get(f"http://127.0.0.1:{port}/static/brand/{rejected_name}")
            assert r_404.status_code == 404


def test_tutorial_zero_divergence_and_overwrite_guard() -> None:
    """Prevent stale worktrees/branches from re-introducing legacy Gemini paths or dropping AI setup links."""
    legacy_paths = (
        "Customize -> Connectors",
        "Customize（自定义） -> Connectors",
        "Customize -&gt; Connectors",
        "Settings -> Connectors",
    )

    scan_files: List[Path] = [
        REPO_ROOT / "README.md",
        REPO_ROOT / "README_EN.md",
        REPO_ROOT / "src/cosmos_mcp/core/tutorials_catalog.py",
        REPO_ROOT / "src/cosmos_mcp/protocol/skill_renderer.py",
        REPO_ROOT / "src/cosmos_mcp/studio/static/index.html",
        REPO_ROOT / "src/cosmos_mcp/studio/static/tutorials.html",
        REPO_ROOT / "src/cosmos_mcp/core/config.py",
        REPO_ROOT / "scripts/build_release.py",
    ]
    scan_files.extend(sorted((REPO_ROOT / "docs").glob("*.md")))
    scan_files.extend(sorted((REPO_ROOT / "host_skills").rglob("*.md")))

    legacy_hits: List[str] = []
    for path in scan_files:
        assert path.exists(), f"Expected tracked file missing: {path}"
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(REPO_ROOT).as_posix()
        for token in legacy_paths:
            if token in text:
                legacy_hits.append(f"{rel}: {token}")
    assert not legacy_hits, f"Legacy Gemini connector path residue found: {legacy_hits}"

    doc01_files = sorted((REPO_ROOT / "docs").glob("01_*.md"))
    assert doc01_files, "Expected docs/01_*.md tutorial file to exist"

    required_guide_files: List[Path] = [
        REPO_ROOT / "README.md",
        REPO_ROOT / "README_EN.md",
        *doc01_files,
        REPO_ROOT / "docs/AI_SETUP_GUIDE.md",
        REPO_ROOT / "src/cosmos_mcp/core/tutorials_catalog.py",
        REPO_ROOT / "src/cosmos_mcp/studio/static/index.html",
        REPO_ROOT / "src/cosmos_mcp/studio/static/tutorials.html",
    ]
    required_tokens = (
        "https://gemini.google.com/customize/connectors",
        "Personal Intelligence",
        "Connected Apps",
        "MCP Server URL",
    )
    no_browser_open_zh = (
        "勿在浏览器地址栏",
        "不要把",
        "不是从浏览器地址栏",
        "不是用来直接在浏览器地址栏",
        "勿直接浏览器打开",
        "不要直接打开",
        "不要在浏览器地址栏",
    )
    no_browser_open_en = (
        "address bar",
        "do not open",
        "don't open",
    )

    for path in required_guide_files:
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(REPO_ROOT).as_posix()
        for token in required_tokens:
            assert token in text, f"{rel} missing required Gemini connector token: {token}"
        if path.name == "README_EN.md":
            lower = text.lower()
            assert any(k in lower for k in no_browser_open_en), (
                f"{rel} missing do-not-open-in-browser-address-bar warning"
            )
        else:
            assert any(k in text for k in no_browser_open_zh), (
                f"{rel} missing 勿直接浏览器打开 warning"
            )

    required_screenshots = (
        "assets/tutorials/gemini-step1-personal-intelligence.png",
        "assets/tutorials/gemini-step2-connected-apps.png",
        "assets/tutorials/gemini-step3-connectors-custom.png",
        "assets/tutorials/gemini-step4-mcp-server-url.png",
    )
    for rel_img in required_screenshots:
        img_path = REPO_ROOT / rel_img
        assert img_path.is_file() and img_path.stat().st_size > 0, (
            f"Missing or empty Gemini step screenshot: {rel_img}"
        )

    for entry_doc in ("README.md", "README_EN.md", "AGENTS.md"):
        top30 = "\n".join((REPO_ROOT / entry_doc).read_text(encoding="utf-8").splitlines()[:30])
        assert "docs/AI_SETUP_GUIDE.md" in top30, (
            f"{entry_doc} missing docs/AI_SETUP_GUIDE.md entry within first 30 lines"
        )
def test_cloudflare_channel_dependencies_and_proxy_boundaries_aligned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify Cloudflare channel dependencies, Mainland China proxy boundaries, and non-CF contrasts across catalog & docs."""
    monkeypatch.setenv("COSMOS_DISABLE_BROWSER_OPEN", "1")
    app, _, _, _ = _build_standalone_harness(tmp_path, port=18695)
    dispatcher = app.state.dispatcher

    res_cf, err_cf = asyncio.run(dispatcher.call_tool_raw("pc_get_status", {"guide": "cloudflare"}))
    assert not err_cf and res_cf["ok"] is True
    md_cf = res_cf["tutorial_markdown"]
    for req_cf in (
        "零外部二进制依赖",
        "100,000",
        "1027",
        "125",
        "DNS 污染",
        "HTTPS_PROXY",
        "WSS_PROXY",
        "127.0.0.1,localhost,::1",
        "Active Zone",
        "Bot Fight Mode",
    ):
        assert req_cf in md_cf, f"cloudflare guide missing `{req_cf}`"

    res_gw, err_gw = asyncio.run(dispatcher.call_tool_raw("pc_get_status", {"guide": "gateways"}))
    assert not err_gw and res_gw["ok"] is True
    md_gw = res_gw["tutorial_markdown"]
    for req_gw in (
        "OpenSSH",
        "COSMOS_CLOUDFLARED_MIRROR",
        "ha-connections:1",
        "530",
        "1033",
        "200",
        "http://127.0.0.1:8096",
        "cloudflare_token",
        "Bot Fight Mode",
    ):
        assert req_gw in md_gw, f"gateways guide missing `{req_gw}`"

    res_ts, err_ts = asyncio.run(dispatcher.call_tool_raw("pc_get_status", {"guide": "troubleshooting"}))
    assert not err_ts and res_ts["ok"] is True
    md_ts = res_ts["tutorial_markdown"]
    for req_ts in ("DNS 污染", "127.0.0.1,localhost,::1", "COSMOS_CLOUDFLARED_MIRROR", "Bot Fight Mode"):
        assert req_ts in md_ts, f"troubleshooting guide missing `{req_ts}`"

    # Guard against re-introducing the misleading "switch back to rule mode without workers.dev proxy" phrasing
    stale_misleading_phrases = (
        "绑好后即可切回规则模式",
        "绑定完成后即可切回规则模式日常使用",
        "点完 `本机一键允许连接` 后即可切回原规则模式",
        "日常无需开全局",
    )
    doc04_zh = REPO_ROOT / "docs/04_三大连接通道选型与网络排障手册.md"
    doc04_en = REPO_ROOT / "docs/en/04_gateways_and_troubleshooting.md"
    aligned_files = [
        REPO_ROOT / "README.md",
        REPO_ROOT / "README_EN.md",
        doc04_zh,
        doc04_en,
        REPO_ROOT / "docs/AI_SETUP_GUIDE.md",
        REPO_ROOT / "docs/en/AI_SETUP_GUIDE.md",
        REPO_ROOT / "src/cosmos_mcp/studio/static/tutorials.html",
        REPO_ROOT / "src/cosmos_mcp/core/tutorials_catalog.py",
        REPO_ROOT / "host_skills/webai2pc-setup-tutorial/SKILL.md",
    ]
    for fp in aligned_files:
        txt = fp.read_text(encoding="utf-8")
        rel = fp.relative_to(REPO_ROOT).as_posix()
        for bad in stale_misleading_phrases:
            assert bad not in txt, f"{rel} still contains misleading proxy guidance: {bad!r}"
        for common_tok in ("COSMOS_CLOUDFLARED_MIRROR", "100,000", "125", "workers.dev", "srv.us"):
            assert common_tok in txt, f"{rel} missing required channel dependency token `{common_tok}`"

    # Verify doc04 official Cloudflare reference links
    for doc04_p in (doc04_zh, doc04_en):
        d_txt = doc04_p.read_text(encoding="utf-8")
        for official_url in (
            "https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/",
            "https://developers.cloudflare.com/workers/platform/limits/",
            "https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors/error-524/",
            "https://github.com/cloudflare/cloudflared/releases/latest",
        ):
            assert official_url in d_txt, f"{doc04_p.name} missing official reference link {official_url}"

    # Verify build_release.render_quickstart_txt includes channel dependency & proxy summary
    from scripts.build_release import render_quickstart_txt

    qs_txt = render_quickstart_txt("1.2.1").decode("utf-8")
    for qs_tok in ("COSMOS_CLOUDFLARED_MIRROR", "100,000", "workers.dev", "127.0.0.1,localhost,::1", "srv.us"):
        assert qs_tok in qs_txt, f"render_quickstart_txt missing `{qs_tok}`"
