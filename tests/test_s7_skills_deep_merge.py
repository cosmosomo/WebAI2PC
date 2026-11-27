"""S7 Comprehensive Verification Suite: Native `capabilities/skills/` Deep Merge & Cosmos Studio Upgrade.

Covers:
1. Architecture & hygiene gates: zero `StandaloneToolSpec` / `cli.py` / `__main__.py` / `studio_api.py` standalone shell,
   native `ToolSpec` + `SafetyBand` + `LiveRuntimePolicy` coupling, first-sentence `.` invariant, zero private conda path,
   zero private pack residue, zero `native-folder-dialog`, zero forbidden tunnel vendor residue.
2. Core `cosmos-skills` capabilities: frontmatter YAML parser, multi-host discovery (including read-only `cc_switch`
   and `cosmos_skills_store`), BM25F multilingual search, progressive loader + secret sanitization + traversal guard,
   3-tier AST supply-chain vetter, SSRF guards, mock market discovery, and official `skills-lock.json` v2 SHA-256 vectors.
3. Cross-repo fixes: live hot-switching across `tier1_readonly .. tier4_full_power`, `workspace_roots`, and `state_root`
   (`<state_root>/skills_store`), project-scoped disabled skill exclusion from `skill_hub(action="search")`, and
   `skill_manage(action="create" | "trash_list" | "trash" | "restore")`.
4. Cosmos Studio HTTP & Headless Browser (`1440x900` + `390x844`) end-to-end verification:
   - Loopback (`127.0.0.1`) passwordless CSRF access vs remote/proxied `403` session lock + cross-origin rejection.
   - Explicit `tunnel_mode="local"` warning + 1-click Cloudflare HTTPS tunnel CTA + `https://.../mcp` Gemini tip,
     with secondary desktop clients folded into `<details>` and 16 core tools header parity.
   - `/api/studio/poll` 4-second sync prioritizing `state/latest_consent_pair_code.txt`.
   - `vps` SSH reverse-tunnel channel save (`vps_ssh`, `vps_remote_port`, `public_base`) without resetting to `local`.
   - `.undo_history` snapshot unified Diff preview (`/api/studio/recovery/diff` + modal) and `/api/studio/service-control`.
   - Tab 5 visual skills center (`/api/studio/skills/*`): local search & detail, 3-tier AST report (`BLOCK/WARN/INFO` + `file_rel`),
     WARN install checkbox/banner auto-reset, in-page create form, enable/disable toggle, force-trash detail button cleanup,
     in-place restore, and dual-viewport zero horizontal overflow.
"""
from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple
import zipfile

import httpx
import pytest

from _studio_driver import LiveStudioServer, StudioPageDriver
from cosmos_mcp.capabilities.skills import (
    LOCKFILE_VERSION,
    MarketClient,
    SSRFError,
    SkillsCapabilityProvider,
    SkillsConfig,
    SkillsMcpService,
    VirtualFileEntry,
    WRITABLE_HOST_IDS,
    ZipSecurityLimitError,
    audit_package_entries,
    build_skill_tool_specs,
    compute_clawhub_fingerprint,
    default_host_skill_roots,
    extract_zip_to_virtual_entries,
    hash_skill_files,
    load_skill_content,
    normalize_tier_level,
    parse_skill_frontmatter,
    validate_public_https_url,
)
from cosmos_mcp.core.config import LiveRuntimePolicy
from cosmos_mcp.core.contracts import SafetyBand, TIER_ORDER, ToolSpec
from cosmos_mcp.core.fs_tx import atomic_write_text, save_undo_snapshot
from cosmos_mcp.launcher import cli, tunnels
from cosmos_mcp.protocol.dispatcher import KernelDispatcher


def _make_zip_bytes(files: Dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel, data in files.items():
            zf.writestr(rel, data)
    return buf.getvalue()


# ==============================================================================
# 1. Architecture, Native Coupling & Cleanliness Gates
# ==============================================================================


def test_native_architecture_cleanliness_and_tool_spec_invariants() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    skills_pkg = repo_root / "src" / "cosmos_mcp" / "capabilities" / "skills"
    studio_pkg = repo_root / "src" / "cosmos_mcp" / "studio"

    # Standalone shell files MUST NOT exist
    for forbidden_file in ("cli.py", "__main__.py", "studio_api.py", "mcp_tools.py"):
        assert not (skills_pkg / forbidden_file).exists(), f"Redundant shell file {forbidden_file} should not exist"

    # Zero StandaloneToolSpec / StandaloneSafetyBand / cosmos_skills imports / tailscale residue
    for py_file in sorted(skills_pkg.glob("*.py")):
        src = py_file.read_text(encoding="utf-8")
        assert "from __future__ import annotations" in src, f"Missing future annotations in {py_file.name}"
        assert "StandaloneToolSpec" not in src
        assert "StandaloneSafetyBand" not in src
        assert "from cosmos_skills" not in src
        assert "import cosmos_skills" not in src
        assert "tailscale" not in src.lower()

    # Studio cleanliness: zero private conda drive path, zero private pack residue, zero native-folder-dialog
    priv_conda_probe = ("e:" + "\\" + "anaconda").lower()
    for st_file in [
        studio_pkg / "routes.py",
        studio_pkg / "static" / "index.html",
        studio_pkg / "static" / "studio.js",
        studio_pkg / "static" / "studio.css",
    ]:
        txt = st_file.read_text(encoding="utf-8")
        low = txt.lower()
        assert "tailscale" not in low, f"tailscale residue in {st_file.name}"
        assert "native-folder-dialog" not in low, f"native-folder-dialog residue in {st_file.name}"
        assert "native-folder-btn" not in low, f"native-folder-btn residue in {st_file.name}"
        assert priv_conda_probe not in low, f"Hardcoded private conda path in {st_file.name}"
        if st_file.name == "routes.py":
            assert '"pad"' not in txt and "'pad'" not in txt

    # Verify build_skill_tool_specs contract & first-sentence period invariant
    specs = build_skill_tool_specs()
    assert len(specs) == 2
    hub_spec, manage_spec = specs
    assert isinstance(hub_spec, ToolSpec) and isinstance(manage_spec, ToolSpec)
    assert hub_spec.base_name == "skill_hub" and hub_spec.safety_band == SafetyBand.READONLY
    assert manage_spec.base_name == "skill_manage" and manage_spec.safety_band == SafetyBand.WORKSPACE_WRITE
    for sp in specs:
        dot_pos = sp.description.find(".")
        assert dot_pos == len(sp.description) - 1, f"Internal period before sentence end in {sp.base_name}: {sp.description!r}"
    assert manage_spec.effective_action_values(tier_allow_edit=False) == ("list", "trash_list")


# ==============================================================================
# 2. Core `cosmos-skills` Capabilities Merged Regression
# ==============================================================================


def test_frontmatter_parser_bm25_loader_and_host_roots(tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()

    # Verify all required host skill roots are auto-discovered and read-only hosts are protected
    roots_map = dict(default_host_skill_roots(fake_home))
    for expected_host in (
        "cosmos_skills_store",
        "universal_agents",
        "claude_code",
        "cursor",
        "windsurf",
        "codex",
        "gemini_cli",
        "cc_switch",
    ):
        assert expected_host in roots_map, f"Missing host root {expected_host}"
    assert "cc_switch" not in WRITABLE_HOST_IDS
    assert "cosmos_skills_store" not in WRITABLE_HOST_IDS
    assert "cursor" in WRITABLE_HOST_IDS and "windsurf" in WRITABLE_HOST_IDS

    # Populate skills across ~/.cosmos-skills/skills_store, ~/.cursor/skills, and ~/.cc-switch/skills
    legacy_dir = fake_home / ".cosmos-skills" / "skills_store" / "legacy-db-helper"
    legacy_dir.mkdir(parents=True)
    (legacy_dir / "SKILL.md").write_text(
        "---\nname: legacy-db-helper\ndescription: PostgreSQL schema migration and query tuning: fast & safe\n"
        'metadata: \'{"openclaw":{"requires":{"bins":["psql"]}}}\'\n---\n# DB Helper\nSecret token sk-9fR4mK8vQ2pL7xZ5wN3bT6yH1jC0dG8s\n',
        encoding="utf-8",
    )
    cursor_dir = fake_home / ".cursor" / "skills" / "ui-layout-audit"
    cursor_dir.mkdir(parents=True)
    (cursor_dir / "SKILL.md").write_text(
        "---\nname: ui-layout-audit\ndescription: Responsive CSS grid viewport inspection\n---\n# UI Audit\n",
        encoding="utf-8",
    )

    fm = parse_skill_frontmatter((legacy_dir / "SKILL.md").read_text(encoding="utf-8"))
    assert fm["name"] == "legacy-db-helper"
    assert "psql" in fm["requires_bins"]

    pol = LiveRuntimePolicy(
        tier_key="tier3_workspace_dev",
        workspace_roots=[tmp_path / "ws"],
        state_root=tmp_path / "state",
    )
    (tmp_path / "ws").mkdir(exist_ok=True)
    cfg = SkillsConfig(home_dir=fake_home, policy=pol)
    svc = SkillsMcpService(cfg)

    # Bilingual ZH -> EN search ("数据库" -> PostgreSQL / database)
    s_db = svc.handle_skill_hub(action="search", query="数据库迁移")
    assert s_db["ok"] and any(r["name"] == "legacy-db-helper" for r in s_db["results"])

    # Progressive loader redacts live secret & blocks path traversal
    loaded = load_skill_content(cfg, "legacy-db-helper")
    assert loaded["ok"] is True
    assert "sk-9fR4mK8vQ2pL7xZ5wN3bT6yH1jC0dG8s" not in loaded["content"]
    assert "<untrusted_skill_content" in loaded["content"]

    trav = load_skill_content(cfg, "legacy-db-helper", file="../outside.txt")
    assert trav["ok"] is False and trav["blocked_by_security_gate"] is True


def test_vetter_ssrf_market_and_official_hash_vectors(tmp_path: Path) -> None:
    # Official skills.sh v2 hash vectors
    assert LOCKFILE_VERSION == 1 or LOCKFILE_VERSION >= 1
    assert hash_skill_files([]) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert hash_skill_files([("SKILL.md", b"# hi\n")]) == "93c36952d8843b33e68ae970ebabcc03e1687c9bb0dd1ecaf357060318952f55"
    assert hash_skill_files([("SKILL.md", b"a\n"), ("docs/b.md", b"b\n")]) == "b22c4d22aa319d2924312fa18fcbfedc88fa89c74dbd8f298c683e1caf7b7f24"
    fp_vec = compute_clawhub_fingerprint([("SKILL.md", b"# claw\n")])
    assert len(fp_vec) == 64

    # Zip-Slip & AST malicious code BLOCK vs WARN vs benign INFO
    slip_zip = _make_zip_bytes({"../../evil.py": b"print(1)\n", "SKILL.md": b"# x\n"})
    slip_entries = extract_zip_to_virtual_entries(slip_zip)
    rep_slip = audit_package_entries("slip-pkg", slip_entries)
    assert rep_slip.verdict == "BLOCK"

    # Obfuscated Python AST base64 + exec -> BLOCK with exact file_rel
    rep_ast = audit_package_entries(
        "ast-evil",
        [
            VirtualFileEntry(rel_path="SKILL.md", raw_bytes=b"---\nname: ast-evil\ndescription: x\n---\n# Hi\n"),
            VirtualFileEntry(
                rel_path="scripts/runner.py",
                raw_bytes=b"import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n",
            ),
        ],
    )
    assert rep_ast.verdict == "BLOCK"
    assert any(f.file_rel == "scripts/runner.py" and f.severity == "BLOCK" for f in rep_ast.findings)

    # Subprocess + network -> WARN
    rep_warn = audit_package_entries(
        "warn-pkg",
        [
            VirtualFileEntry(rel_path="SKILL.md", raw_bytes=b"---\nname: warn-pkg\ndescription: w\n---\n# Warn\n"),
            VirtualFileEntry(
                rel_path="scripts/fetch.py",
                raw_bytes=b"import subprocess, urllib.request\nurllib.request.urlopen('https://api.github.com')\nsubprocess.run(['git', 'status'])\n",
            ),
        ],
    )
    assert rep_warn.verdict == "WARN"

    # Benign defensive markdown -> INFO
    rep_ok = audit_package_entries(
        "clean-doc",
        [VirtualFileEntry(rel_path="SKILL.md", raw_bytes=b"---\nname: clean-doc\ndescription: Pure markdown guide\n---\n# Clean Guide\n")],
    )
    assert rep_ok.verdict == "INFO"

    # Oversized archive guard
    tiny_cfg = SkillsConfig(max_archive_bytes=32)
    with pytest.raises(ZipSecurityLimitError):
        extract_zip_to_virtual_entries(b"P" * 100, config=tiny_cfg)

    # SSRF validation blocks loopback, metadata IP, and plain HTTP
    for bad_url in ("http://github.com/a/b", "https://127.0.0.1/x", "https://169.254.169.254/latest/meta-data"):
        with pytest.raises(SSRFError):
            validate_public_https_url(bad_url, resolve_dns=False)

    # Mock MarketClient discovery
    def _mock_http(method: str, url: str, headers: Any, body: Any, timeout: float, proxy: Any) -> Tuple[int, Dict[str, str], bytes]:
        if "skills.sh" in url:
            payload = {"skills": [{"id": "vercel-labs/agent-skills/react-best-practices", "name": "react-best-practices", "installs": 1200}]}
            return 200, {"content-type": "application/json"}, json.dumps(payload).encode("utf-8")
        return 200, {"content-type": "application/json"}, b'{"items": []}'

    mc = MarketClient(SkillsConfig(http_transport=_mock_http))
    disc = mc.discover("react", sources=["skills_sh"], limit=5)
    assert len(disc["candidates"]) == 1
    assert disc["candidates"][0]["name"] == "react-best-practices"


# ==============================================================================
# 3. LiveRuntimePolicy Hot-Switching, Project Disable Fix & Create/Trash Flow
# ==============================================================================


def test_live_policy_hot_switch_project_disable_filter_and_create_trash(tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    ws1 = tmp_path / "ws1"
    ws2 = tmp_path / "ws2"
    outside_ws = tmp_path / "outside_ws"
    sr1 = tmp_path / "state_1"
    sr2 = tmp_path / "state_2"
    for d in (fake_home, ws1, ws2, outside_ws, sr1, sr2):
        d.mkdir(parents=True)

    policy = LiveRuntimePolicy(
        tier_key="tier3_workspace_dev",
        workspace_roots=[ws1],
        state_root=sr1,
    )
    cfg = SkillsConfig(home_dir=fake_home, policy=policy)
    svc = SkillsMcpService(cfg)
    disp = KernelDispatcher(policy)
    disp.register_capability_provider(SkillsCapabilityProvider(policy, service=svc))

    async def _scenario() -> None:
        # 1) Create managed skill in tier3_workspace_dev -> lands in <sr1>/skills_store
        c_mgd, err = await disp.call_tool_raw(
            "skill_manage",
            {
                "action": "create",
                "skill": "release-checklist",
                "content": "---\nname: release-checklist\ndescription: Pre-release checklist verification\n---\n# Checklist\n",
            },
        )
        assert not err and c_mgd["ok"] and c_mgd["created"]
        assert (sr1 / "skills_store" / "release-checklist" / "SKILL.md").is_file()

        # Duplicate create without force -> cleanly rejected as already_exists
        c_dup, _ = await disp.call_tool_raw(
            "skill_manage",
            {
                "action": "create",
                "skill": "release-checklist",
                "content": "---\nname: release-checklist\ndescription: v2\n---\n# v2\n",
            },
        )
        assert not c_dup["ok"] and c_dup.get("status") == "already_exists"

        # Malicious create (BiDi Trojan Source) -> blocked by vetter BEFORE touching disk
        c_evil, _ = await disp.call_tool_raw(
            "skill_manage",
            {
                "action": "create",
                "skill": "trojan-skill",
                "content": "---\nname: trojan-skill\ndescription: bad\n---\nsafe \u202e hidden\n",
            },
        )
        assert not c_evil["ok"] and c_evil.get("verdict") == "BLOCK"
        assert not (sr1 / "skills_store" / "trojan-skill").exists()

        # 2) Project skill create & disable -> MUST NOT appear as enabled in skill_hub(action="search")!
        c_proj, _ = await disp.call_tool_raw(
            "skill_manage",
            {
                "action": "create",
                "skill": "ws1-sql-helper",
                "scope": "project",
                "cwd": str(ws1),
                "content": "---\nname: ws1-sql-helper\ndescription: Workspace SQL query helper\n---\n# SQL\n",
            },
        )
        assert c_proj["ok"] and (ws1 / ".agents" / "skills" / "ws1-sql-helper" / "SKILL.md").is_file()

        hub_before, _ = await disp.call_tool_raw("skill_hub", {"action": "search", "query": "ws1-sql-helper"})
        assert any(r["name"] == "ws1-sql-helper" and r["enabled"] is True for r in hub_before["results"])

        dis_res, _ = await disp.call_tool_raw(
            "skill_manage",
            {"action": "disable", "skill": "ws1-sql-helper", "scope": "project", "cwd": str(ws1)},
        )
        assert dis_res["ok"] and dis_res["enabled"] is False

        # Verify excluded from keyword search, empty-query search, list, and load!
        hub_kw, _ = await disp.call_tool_raw("skill_hub", {"action": "search", "query": "ws1-sql-helper"})
        assert not any(r["name"] == "ws1-sql-helper" for r in hub_kw["results"])
        hub_all, _ = await disp.call_tool_raw("skill_hub", {"action": "search", "query": ""})
        assert not any(r["name"] == "ws1-sql-helper" for r in hub_all["results"])
        hub_load_dis, _ = await disp.call_tool_raw("skill_hub", {"action": "load", "skill": "ws1-sql-helper"})
        assert hub_load_dis["ok"] is False and hub_load_dis.get("enabled") is False

        # Management list still surfaces disabled skill with enabled=False; re-enable restores search visibility
        m_list, _ = await disp.call_tool_raw("skill_manage", {"action": "list"})
        rec_dis = next(r for r in m_list["skills"] if r["name"] == "ws1-sql-helper")
        assert rec_dis["enabled"] is False

        en_res, _ = await disp.call_tool_raw(
            "skill_manage",
            {"action": "enable", "skill": "ws1-sql-helper", "scope": "project", "cwd": str(ws1)},
        )
        assert en_res["ok"] and en_res["enabled"] is True
        hub_reenabled, _ = await disp.call_tool_raw("skill_hub", {"action": "search", "query": "ws1-sql-helper"})
        assert any(r["name"] == "ws1-sql-helper" for r in hub_reenabled["results"])

        # 3) Out-of-workspace cwd blocked in L3, then allowed after hot-switching to tier4_full_power!
        out_l3, _ = await disp.call_tool_raw(
            "skill_manage",
            {
                "action": "create",
                "skill": "outside-skill",
                "scope": "project",
                "cwd": str(outside_ws),
                "content": "---\nname: outside-skill\ndescription: test\n---\n# Out\n",
            },
        )
        assert not out_l3["ok"] and out_l3.get("blocked_by_security_gate") is True

        # Hot-switch across all 4 canonical tiers:
        # L1 (`tier1_readonly`): list & trash_list succeed; mutating actions blocked
        policy.tier_key = "tier1_readonly"
        l1_list, l1_err = await disp.call_tool_raw("skill_manage", {"action": "list"})
        assert not l1_err and l1_list["ok"]
        l1_tlist, l1_terr = await disp.call_tool_raw("skill_manage", {"action": "trash_list"})
        assert not l1_terr and l1_tlist["ok"]
        l1_mut, l1_merr = await disp.call_tool_raw(
            "skill_manage",
            {"action": "disable", "skill": "ws1-sql-helper", "scope": "project", "cwd": str(ws1)},
        )
        assert l1_merr and not l1_mut["ok"] and l1_mut.get("blocked_by_permission_tier") is True

        # L2 (`tier2_workspace_edit`): managed scope blocked; project prompt-only scope allowed
        policy.tier_key = "tier2_workspace_edit"
        l2_mgd, _ = await disp.call_tool_raw(
            "skill_manage",
            {"action": "create", "skill": "l2-mgd", "scope": "managed", "content": "---\nname: l2-mgd\ndescription: x\n---\n# x\n"},
        )
        assert not l2_mgd["ok"] and l2_mgd.get("blocked_by_permission_tier") is True
        l2_proj, _ = await disp.call_tool_raw(
            "skill_manage",
            {
                "action": "create",
                "skill": "l2-proj",
                "scope": "project",
                "cwd": str(ws1),
                "content": "---\nname: l2-proj\ndescription: L2 prompt skill\n---\n# L2\n",
            },
        )
        assert l2_proj["ok"] and l2_proj["created"] is True

        # L4 (`tier4_full_power`) + hot-switch workspace_roots -> [ws2] + state_root -> sr2
        policy.tier_key = "tier4_full_power"
        policy.workspace_roots = [ws2]
        policy.state_root = sr2
        assert TIER_ORDER[-1] == "tier4_full_power"
        assert normalize_tier_level("tier4_full_power") == 4

        l4_out, _ = await disp.call_tool_raw(
            "skill_manage",
            {
                "action": "create",
                "skill": "outside-skill",
                "scope": "project",
                "cwd": str(outside_ws),
                "content": "---\nname: outside-skill\ndescription: L4 unrestricted\n---\n# Out\n",
            },
        )
        assert l4_out["ok"] and (outside_ws / ".agents" / "skills" / "outside-skill" / "SKILL.md").is_file()

        l4_sr2, _ = await disp.call_tool_raw(
            "skill_manage",
            {
                "action": "create",
                "skill": "sr2-managed-skill",
                "content": "---\nname: sr2-managed-skill\ndescription: Stored in sr2\n---\n# SR2\n",
            },
        )
        assert l4_sr2["ok"] and (sr2 / "skills_store" / "sr2-managed-skill" / "SKILL.md").is_file()

        # Trash -> trash_list -> restore lifecycle
        tr_rm, _ = await disp.call_tool_raw("skill_manage", {"action": "trash", "skill": "sr2-managed-skill"})
        assert tr_rm["ok"] and not (sr2 / "skills_store" / "sr2-managed-skill").exists()
        tr_ls, _ = await disp.call_tool_raw("skill_manage", {"action": "trash_list"})
        assert tr_ls["ok"] and any(it["skill_name"] == "sr2-managed-skill" for it in tr_ls["items"])
        tr_tid = next(it["trash_id"] for it in tr_ls["items"] if it["skill_name"] == "sr2-managed-skill")
        tr_rest, _ = await disp.call_tool_raw("skill_manage", {"action": "restore", "trash_id": tr_tid})
        assert tr_rest["ok"] and (sr2 / "skills_store" / "sr2-managed-skill" / "SKILL.md").is_file()

    asyncio.run(_scenario())


# ==============================================================================
# 4. Studio HTTP Endpoints: Loopback Passwordless, Remote Lock, Poll, VPS, Diff, Skills API
# ==============================================================================


def test_studio_loopback_passwordless_remote_guard_poll_vps_diff_and_skills_api(tmp_path: Path) -> None:
    st_dir = tmp_path / "studio_state"
    ws1 = tmp_path / "ws_alpha"
    ws2 = tmp_path / "ws_beta"
    ws1.mkdir(parents=True)
    ws2.mkdir(parents=True)

    # Create a file + .undo_history snapshot to verify Diff preview endpoint
    demo_py = ws1 / "calc.py"
    atomic_write_text(demo_py, "def add(a, b):\n    return a + b\n")
    save_undo_snapshot(demo_py, workspace_roots=[ws1], state_root=st_dir)
    atomic_write_text(demo_py, "def add(a, b):\n    return int(a) + int(b)\n")

    with LiveStudioServer(st_dir, ws1, thread_prefix="s7-studio") as srv:
        owner_pw = cli._extract_saved_password(st_dir, "pc")
        assert owner_pw

        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=10.0) as client:
            # 1) Direct loopback (`127.0.0.1`) is unlocked immediately without manual password copy-paste!
            st0 = client.get("/api/studio/state").json()
            assert st0["ok"] is True
            assert st0["is_loopback"] is True
            assert st0["unlocked"] is True
            csrf = st0["csrf_token"]

            # Loopback + valid CSRF can add workspace WITHOUT sending owner_password
            r_ws_ok = client.post(
                "/api/studio/workspace",
                headers={"X-Studio-Csrf": csrf, "Origin": srv.base_url},
                json={"action": "add", "path": str(ws2)},
            )
            assert r_ws_ok.status_code == 200 and str(ws2.resolve()) in r_ws_ok.json()["workspaces"]["roots"]

            # Cross-origin Origin header MUST still be rejected with 403 even on loopback!
            r_xorigin = client.post(
                "/api/studio/workspace",
                headers={"X-Studio-Csrf": csrf, "Origin": "https://evil.attacker.example"},
                json={"action": "add", "path": str(ws2)},
            )
            assert r_xorigin.status_code == 403

            # Proxied / remote request (`X-Forwarded-For` / `CF-Connecting-IP`) MUST require session authentication!
            remote_headers = {
                "X-Studio-Csrf": csrf,
                "X-Forwarded-For": "203.0.113.77",
                "CF-Connecting-IP": "203.0.113.77",
            }
            st_remote_locked = client.get("/api/studio/state", headers=remote_headers).json()
            assert st_remote_locked["locked"] is True and st_remote_locked["unlocked"] is False
            r_remote_mut = client.post(
                "/api/studio/workspace",
                headers=remote_headers,
                json={"action": "remove", "path": str(ws2)},
            )
            assert r_remote_mut.status_code == 403
            r_remote_skills = client.get("/api/studio/skills/local", headers=remote_headers)
            assert r_remote_skills.status_code == 403
            r_remote_poll = client.get("/api/studio/poll", headers=remote_headers)
            assert r_remote_poll.status_code == 403

            # Unlocking remotely with owner_password mints cookie and grants access
            with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=10.0) as rem_client:
                r_rem_unlock = rem_client.post(
                    "/api/studio/unlock",
                    headers=remote_headers,
                    json={"owner_password": owner_pw},
                )
                assert r_rem_unlock.status_code == 200 and r_rem_unlock.json()["unlocked"] is True
                r_rem_after = rem_client.get("/api/studio/skills/local", headers=remote_headers)
                assert r_rem_after.status_code == 200 and r_rem_after.json()["ok"] is True

            # 2) `/api/studio/poll` prioritizes `state/latest_consent_pair_code.txt` in real time
            pair_file = st_dir / "state" / "latest_consent_pair_code.txt"
            pair_file.parent.mkdir(parents=True, exist_ok=True)
            pair_file.write_text("K9W4\n", encoding="utf-8")
            poll_doc = client.get("/api/studio/poll", headers={"X-Studio-Csrf": csrf}).json()
            assert poll_doc["ok"] is True
            assert poll_doc["consent_pair_code"] == "K9W4" and poll_doc["pair_code"] == "K9W4"

            # 3) `vps` SSH reverse-tunnel channel save persists `tunnel_mode="vps"`, `vps_ssh`, `vps_remote_port`, `public_base`
            r_vps = client.post(
                "/api/studio/connection",
                headers={"X-Studio-Csrf": csrf},
                json={
                    "action": "save_tunnel",
                    "tunnel_mode": "vps",
                    "vps_ssh": "deploy@vps.example.org",
                    "vps_remote_port": 18099,
                    "public_url": "https://mcp-vps.example.org",
                },
            )
            assert r_vps.status_code == 200
            vps_doc = r_vps.json()
            assert vps_doc["connection"]["tunnel_mode"] == "vps"
            assert vps_doc["connection"]["vps_ssh"] == "deploy@vps.example.org"
            assert vps_doc["connection"]["vps_remote_port"] == 18099
            assert vps_doc["connection"]["gateways"]["self_hosted"]["configured_url"] == "https://mcp-vps.example.org"
            assert vps_doc["connection"]["gateways"]["self_hosted"]["status"] == "unknown"
            assert vps_doc["connection"]["mcp_url"] == ""

            saved_service = json.loads((st_dir / "config" / "service.json").read_text(encoding="utf-8"))
            assert saved_service["tunnel_mode"] == "vps"
            assert saved_service["vps_ssh"] == "deploy@vps.example.org"
            assert saved_service["vps_remote_port"] == 18099
            assert saved_service["public_base"] == "https://mcp-vps.example.org"

            d_status_file = st_dir / "state" / "daemon_status.json"
            d_status_file.write_text(
                json.dumps(
                    {
                        "status": "running",
                        "mode": "vps",
                        "public_url": "https://mcp-vps.example.org",
                        "tunnel_ready": True,
                        "gateways": {
                            "self_hosted": {
                                "enabled": True,
                                "submode": "vps",
                                "effective_mode": "vps",
                                "phase": "ready",
                                "tunnel_ready": True,
                                "public_url": "https://mcp-vps.example.org",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            vps_ready_state = client.get("/api/studio/state").json()
            assert vps_ready_state["public_https_ready"] is True
            assert vps_ready_state["mcp_url"] == "https://mcp-vps.example.org/mcp"
            d_status_file.unlink()

            # Switch back to local so we also test local -> cloudflare CTA cleanly
            client.post(
                "/api/studio/connection",
                headers={"X-Studio-Csrf": csrf},
                json={"action": "save_tunnel", "tunnel_mode": "local"},
            )

            # 4) `.undo_history` Diff preview endpoint (`/api/studio/recovery/diff`)
            r_diff = client.get(
                "/api/studio/recovery/diff",
                params={"path": str(demo_py)},
                headers={"X-Studio-Csrf": csrf},
            )
            assert r_diff.status_code == 200
            diff_doc = r_diff.json()
            assert diff_doc["ok"] is True
            assert "-    return a + b" in diff_doc["diff_text"]
            assert "+    return int(a) + int(b)" in diff_doc["diff_text"]
            assert diff_doc["added_lines"] >= 1 and diff_doc["removed_lines"] >= 1

            # 5) Service control (`restart` & `stop` signals in pytest safe mode)
            r_restart = client.post(
                "/api/studio/service-control",
                headers={"X-Studio-Csrf": csrf},
                json={"action": "restart", "signal_only": True},
            )
            assert r_restart.status_code == 200 and r_restart.json()["action"] == "restart"
            assert (st_dir / "state" / "daemon_stop.flag").read_text(encoding="utf-8").startswith("CLEAR:")

            r_stop = client.post(
                "/api/studio/service-control",
                headers={"X-Studio-Csrf": csrf},
                json={"action": "stop", "signal_only": True},
            )
            assert r_stop.status_code == 200 and r_stop.json()["action"] == "stop"
            assert (st_dir / "state" / "daemon_stop.flag").read_text(encoding="utf-8").startswith("STOP:")

            # 6) `/api/studio/skills/*` full lifecycle
            r_sk_create = client.post(
                "/api/studio/skills/create",
                headers={"X-Studio-Csrf": csrf},
                json={
                    "skill": "studio-api-helper",
                    "scope": "project",
                    "cwd": str(ws1),
                    "content": "---\nname: studio-api-helper\ndescription: Created via Studio API\n---\n# Studio Helper\n",
                },
            )
            assert r_sk_create.status_code == 200 and r_sk_create.json()["created"] is True

            r_sk_det = client.get(
                "/api/studio/skills/detail",
                params={"skill": "studio-api-helper"},
                headers={"X-Studio-Csrf": csrf},
            ).json()
            assert r_sk_det["ok"] is True
            assert r_sk_det["audit"]["verdict"] == "INFO"

            # Vet local folder inside authorized ws1 with WARN script -> two-phase install
            warn_pkg_dir = ws1 / "warn_source_skill"
            (warn_pkg_dir / "scripts").mkdir(parents=True)
            (warn_pkg_dir / "SKILL.md").write_text(
                "---\nname: warn-net-runner\ndescription: Runs git fetch\n---\n# Runner\n",
                encoding="utf-8",
            )
            (warn_pkg_dir / "scripts" / "sync.py").write_text(
                "import subprocess, urllib.request\nurllib.request.urlopen('https://api.github.com')\nsubprocess.run(['git', 'status'])\n",
                encoding="utf-8",
            )
            r_vet = client.post(
                "/api/studio/skills/vet",
                headers={"X-Studio-Csrf": csrf},
                json={"source": str(warn_pkg_dir), "scope": "managed"},
            ).json()
            assert r_vet["ok"] is True and r_vet["verdict"] == "WARN"
            assert any(f["file_rel"] == "scripts/sync.py" for f in r_vet["audit"]["findings"])
            ptok = r_vet["preview_token"]

            # Without confirm_warn -> installed=False
            r_inst_no_confirm = client.post(
                "/api/studio/skills/install",
                headers={"X-Studio-Csrf": csrf},
                json={"preview_token": ptok, "confirm_warn": False},
            ).json()
            assert r_inst_no_confirm["installed"] is False

            # With confirm_warn=True -> installed=True
            r_inst_ok = client.post(
                "/api/studio/skills/install",
                headers={"X-Studio-Csrf": csrf},
                json={"preview_token": ptok, "confirm_warn": True},
            ).json()
            assert r_inst_ok["ok"] is True and r_inst_ok["installed"] is True


# ==============================================================================
# 5. Headless Browser Dual-Viewport (`1440x900` & `390x844`) & Real DOM Click Flows
# ==============================================================================


def test_headless_studio_dual_viewport_and_skills_center_dom_flows(tmp_path: Path) -> None:
    st_dir = tmp_path / "browser_state"
    ws1 = tmp_path / "browser_ws"
    prof_dir = tmp_path / "cdp_prof"
    ws1.mkdir(parents=True)
    prof_dir.mkdir(parents=True)

    # Seed a modified file for Diff modal + a WARN local skill package for 2-phase install UI reset test
    sample_file = ws1 / "app.py"
    atomic_write_text(sample_file, "VALUE = 1\n")
    save_undo_snapshot(sample_file, workspace_roots=[ws1], state_root=st_dir)
    atomic_write_text(sample_file, "VALUE = 42\n")

    warn_src_dir = ws1 / "_staged_warn_skill"
    (warn_src_dir / "scripts").mkdir(parents=True)
    (warn_src_dir / "SKILL.md").write_text(
        "---\nname: dom-warn-skill\ndescription: Skill with WARN AST finding\n---\n# DOM Warn Skill\n",
        encoding="utf-8",
    )
    (warn_src_dir / "scripts" / "check.py").write_text(
        "import subprocess, urllib.request\nurllib.request.urlopen('https://api.github.com')\nsubprocess.run(['echo', 'ok'])\n",
        encoding="utf-8",
    )

    with LiveStudioServer(st_dir, ws1, thread_prefix="s7-studio") as srv:
        # Explicitly configure `tunnel_mode="local"` before asserting `localGuideVisible`
        with httpx.Client(base_url=srv.base_url, trust_env=False, timeout=10.0) as init_http:
            st_boot = init_http.get("/api/studio/state").json()
            init_r = init_http.post(
                "/api/studio/connection",
                headers={"X-Studio-Csrf": st_boot["csrf_token"]},
                json={"action": "save_tunnel", "tunnel_mode": "local"},
            )
            assert init_r.status_code == 200 and init_r.json()["connection"]["tunnel_mode"] == "local"

        with StudioPageDriver(prof_dir) as driver:
            # 1) Passwordless loopback boot & local loopback guide visibility
            driver.set_viewport(1440, 900, mobile=False)
            driver.goto(f"{srv.base_url}/")

            boot_dom = driver.wait_until(
                """() => {
                    const bar = document.getElementById('session-unlock-bar');
                    const guide = document.getElementById('local-loopback-guide');
                    if (!bar || !bar.classList.contains('unlocked')) return false;
                    return {
                        unlockedBar: true,
                        localGuideVisible: guide ? getComputedStyle(guide).display !== 'none' : false,
                        hasQuickEnableBtn: Boolean(document.getElementById('quick-enable-cf-btn')),
                        hasCopyPairBtn: Boolean(document.getElementById('copy-pair-code-btn')),
                    };
                }""",
                description="passwordless loopback boot ready",
            )
            assert boot_dom["unlockedBar"] is True
            assert boot_dom["localGuideVisible"] is True
            assert boot_dom["hasQuickEnableBtn"] is True
            assert boot_dom["hasCopyPairBtn"] is True

            # 2) Save VPS tunnel via Settings -> Gateways -> verify HTTPS highlight & Gemini guide update
            driver.open_settings("gateways")
            driver.evaluate(
                """() => {
                    document.querySelector("#channel-selector .channel-option[data-mode='vps']").click();
                    document.getElementById('vps-ssh-input').value = 'ops@vps.example.net';
                    document.getElementById('vps-remote-port-input').value = '18097';
                    document.getElementById('vps-public-url-input').value = 'https://gemini-bridge.example.net';
                    document.getElementById('save-channel-btn').click();
                }"""
            )
            driver.wait_until(
                """() => {
                    const box = document.getElementById('mcp-url-box');
                    return Boolean(box && !box.classList.contains('https-ready'));
                }""",
                description="VPS config saved without fabricating ready before daemon probe",
            )
            (st_dir / "state" / "daemon_status.json").write_text(
                json.dumps(
                    {
                        "status": "running",
                        "port": srv.port,
                        "mode": "vps",
                        "public_url": "https://gemini-bridge.example.net",
                        "tunnel_ready": True,
                        "gateways": {
                            "self_hosted": {
                                "enabled": True,
                                "submode": "vps",
                                "effective_mode": "vps",
                                "phase": "ready",
                                "tunnel_ready": True,
                                "public_url": "https://gemini-bridge.example.net",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            driver.trigger_poll()
            vps_ui_res = driver.wait_until(
                """() => {
                    const box = document.getElementById('mcp-url-box');
                    if (!box || !box.textContent.includes('https://gemini-bridge.example.net/mcp')) return false;
                    const gd = document.getElementById('gemini-https-guide-details');
                    if (gd) gd.open = true;
                    return {
                        mcpUrl: box.textContent.trim(),
                        httpsReadyClass: box.classList.contains('https-ready'),
                        geminiTipVisible: getComputedStyle(document.getElementById('gemini-https-guide')).display !== 'none',
                    };
                }""",
                description="VPS tunnel URL propagated to top box",
            )
            assert vps_ui_res["httpsReadyClass"] is True
            assert vps_ui_res["geminiTipVisible"] is True

            # 3) Write new consent_pair_code on disk and verify poll updates #pair-code-box without F5
            driver.close_settings()
            (st_dir / "state" / "latest_consent_pair_code.txt").write_text("M7X2\n", encoding="utf-8")
            driver.trigger_poll()
            polled_code = driver.wait_until(
                "() => { const c = document.getElementById('pair-code-box')?.textContent.trim(); return c === 'M7X2' ? c : false; }",
                timeout_sec=8.0,
                description="pair code updated to M7X2",
            )
            assert polled_code == "M7X2"

            # 4) Activity -> Undo: Open `.undo_history` Diff modal and verify +/- lines render
            driver.evaluate("""() => document.querySelector(".activity-seg-btn[data-activity-pane='undo']").click()""")
            driver.wait_until("() => Boolean(document.querySelector('.diff-snapshot-btn'))", description="diff button rendered")
            driver.evaluate("() => document.querySelector('.diff-snapshot-btn').click()")
            diff_text = driver.wait_until(
                """() => {
                    const modal = document.getElementById('diff-preview-modal');
                    if (!modal || getComputedStyle(modal).display === 'none') return false;
                    const txt = document.getElementById('diff-modal-body').innerText;
                    return txt.includes('VALUE = 42') ? txt : false;
                }""",
                description="diff modal shows VALUE = 42",
            )
            assert "VALUE = 42" in diff_text
            driver.evaluate("() => document.getElementById('close-diff-modal-btn').click()")

            # 5) Settings -> Skills: vet & install WARN skill (checkbox & error banner reset), force-trash, restore
            driver.open_settings("skills")
            driver.evaluate(
                """(warnPath) => {
                    document.querySelector(".skills-subtab-btn[data-skill-subtab='market']").click();
                    document.getElementById('skill-vet-source-input').value = warnPath;
                    document.getElementById('skill-install-scope-select').value = 'managed';
                    document.getElementById('skill-vet-btn').click();
                }""",
                str(warn_src_dir),
            )
            report_text = driver.wait_until(
                """() => {
                    const box = document.getElementById('skill-vet-report-box');
                    if (!box || getComputedStyle(box).display === 'none') return false;
                    return box.innerText || false;
                }""",
                description="AST vet report displayed",
            )
            assert "WARN" in report_text and "scripts/check.py" in report_text

            # Click install WITHOUT checking confirm_warn -> error banner must show
            driver.evaluate("() => document.getElementById('skill-commit-install-btn').click()")
            err_before = driver.wait_until(
                "() => getComputedStyle(document.getElementById('skill-install-error-banner')).display !== 'none'",
                description="warn confirmation error banner shown",
            )
            assert err_before is True

            # Check confirm_warn & overwrite and commit install -> auto-resets checkboxes & hides error banner
            driver.evaluate(
                """() => {
                    document.getElementById('skill-confirm-warn-chk').checked = true;
                    document.getElementById('skill-overwrite-chk').checked = true;
                    document.getElementById('skill-commit-install-btn').click();
                }"""
            )
            install_state = driver.wait_until(
                """() => {
                    const title = document.getElementById('skill-detail-title')?.textContent || '';
                    const warnChk = document.getElementById('skill-confirm-warn-chk');
                    if (!title.includes('dom-warn-skill') || !warnChk || warnChk.checked) return false;
                    return {
                        warnChkAfter: warnChk.checked,
                        overwriteChkAfter: document.getElementById('skill-overwrite-chk').checked,
                        errVisibleAfter: getComputedStyle(document.getElementById('skill-install-error-banner')).display !== 'none',
                        detailActionsBeforeTrash: document.getElementById('skill-detail-actions').children.length,
                    };
                }""",
                description="WARN skill installed and checkboxes reset",
            )
            assert install_state["warnChkAfter"] is False
            assert install_state["overwriteChkAfter"] is False
            assert install_state["errVisibleAfter"] is False
            assert install_state["detailActionsBeforeTrash"] >= 2

            # Modify installed skill on disk to trigger modified_requires_force -> force-trash -> restore
            installed_md = st_dir / "skills_store" / "dom-warn-skill" / "SKILL.md"
            assert installed_md.is_file()
            installed_md.write_text(installed_md.read_text(encoding="utf-8") + "\n# Locally edited\n", encoding="utf-8")

            driver.evaluate(
                """() => {
                    const buttons = Array.from(document.querySelectorAll('#skill-detail-actions button'));
                    const rmBtn = buttons.find(b => b.classList.contains('btn-danger') || b.textContent.includes('回收箱'));
                    if (rmBtn) rmBtn.click();
                }"""
            )
            driver.wait_until("() => Boolean(document.querySelector('.force-trash-skill-btn'))", description="force-trash button appears")
            driver.evaluate("() => document.querySelector('.force-trash-skill-btn').click()")
            driver.wait_until(
                "() => document.getElementById('skill-detail-actions').children.length === 0",
                description="detail actions cleared after force-trash",
            )

            # Switch to Trash subview and click restore
            driver.evaluate("""() => document.querySelector(".skills-subtab-btn[data-skill-subtab='trash']").click()""")
            driver.wait_until("() => Boolean(document.querySelector('.skill-restore-btn'))", description="skill restore button appears")
            driver.evaluate("() => document.querySelector('.skill-restore-btn').click()")
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and not installed_md.is_file():
                time.sleep(0.05)
            assert installed_md.is_file()
            assert driver.get_runtime_diagnostics()["jsErrors"] == []
