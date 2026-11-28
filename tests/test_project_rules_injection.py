from __future__ import annotations

import asyncio
import ctypes
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict

import pytest
from starlette.testclient import TestClient

if sys.platform == "win32":
    ctypes.windll.kernel32.SetErrorMode(0x8003)

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from cosmos_mcp.core.config import LiveRuntimePolicy
from cosmos_mcp.core.guard import WorkspaceGuard
from cosmos_mcp.core.proc import ProcessManager
from cosmos_mcp.launcher.app import create_standalone_app
from cosmos_mcp.protocol.dispatcher import KernelDispatcher
from cosmos_mcp.protocol.ergonomics import (
    ErgonomicsMiddleware,
    PROJECT_RULE_INLINE_MAX_CHARS,
    SessionSidebandTracker,
    _is_unsafe_climb_boundary,
)
from cosmos_mcp.protocol.skill_renderer import build_server_instructions
from cosmos_mcp.protocol.tools import build_core_tools


def _make_dispatcher(ws_root: Path, state_root: Path, *, tier: str = "tier3_workspace_dev") -> tuple[KernelDispatcher, LiveRuntimePolicy]:
    guard = WorkspaceGuard(
        workspace_roots=[ws_root],
        restrict_to_workspace=(tier != "tier4_full_power"),
        tier=tier,
        state_root=state_root,
    )
    policy = LiveRuntimePolicy(
        tier_key=tier,
        workspace_roots=[ws_root],
        state_root=state_root,
        cfg_path=state_root / "config" / "service.json",
        guard=guard,
    )
    proc_mgr = ProcessManager(guard=guard, state_root=state_root)
    dispatcher = KernelDispatcher(policy)
    specs, hooks = build_core_tools(guard=guard, proc_mgr=proc_mgr, policy=policy)
    dispatcher.register_tools(specs)
    for hk in hooks:
        dispatcher.add_execution_hook(hk)
    return dispatcher, policy


def test_first_touch_dedup_sha_change_and_tools_coverage(tmp_path: Path) -> None:
    """Verify first-touch injection on search_code / find_files / run_command, session dedup, and SHA-change re-inject."""
    assert ErgonomicsMiddleware is SessionSidebandTracker

    ws = tmp_path / "ws"
    st = tmp_path / "state"
    ws.mkdir(parents=True)
    st.mkdir(parents=True)

    (ws / ".git").mkdir()
    agents_md = ws / "AGENTS.md"
    agents_md.write_text("# Project Alpha Rules\n- Always run targeted tests.\n", encoding="utf-8")
    src_dir = ws / "src"
    src_dir.mkdir()
    (src_dir / "hello.py").write_text("def greet() -> str:\n    return 'hi'\n", encoding="utf-8")

    dispatcher, policy = _make_dispatcher(ws, st)

    # Server handshake instructions include a concise note without dumping long rule contents
    srv_instr = build_server_instructions(dispatcher, policy)
    assert "AGENTS.md" in srv_instr
    assert "Always run targeted tests." not in srv_instr

    # 1) `search_code` first touch -> injects `_project_instructions`
    res1, err1 = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_search_code",
            {"pattern": "greet", "path": str(src_dir), "caller": "sess-search"},
        )
    )
    assert not err1 and res1["ok"] is True
    assert "_project_instructions" in res1
    pi_1 = res1["_project_instructions"]
    assert len(pi_1) == 1
    assert pi_1[0]["name"] == "AGENTS.md"
    assert Path(pi_1[0]["path"]).resolve() == agents_md.resolve()
    assert Path(pi_1[0]["project_root"]).resolve() == ws.resolve()
    assert len(pi_1[0]["sha256"]) == 16
    assert pi_1[0]["truncated"] is False
    assert "Always run targeted tests." in pi_1[0]["content"]
    sha_v1 = pi_1[0]["sha256"]

    # 2) Second call in the same session -> zero duplicate injection
    res2, err2 = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_find_files",
            {"path": str(src_dir), "caller": "sess-search"},
        )
    )
    assert not err2 and res2["ok"] is True
    assert "_project_instructions" not in res2

    # 3) Independent session (`find_files` & `run_command`) gets its own first-touch injection
    res_ff, err_ff = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_find_files",
            {"path": str(ws), "caller": "sess-find"},
        )
    )
    assert not err_ff and "_project_instructions" in res_ff
    assert res_ff["_project_instructions"][0]["sha256"] == sha_v1

    res_cmd, err_cmd = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_run_command",
            {"command": "echo rules_probe_ok", "cwd": str(src_dir), "caller": "sess-cmd"},
        )
    )
    assert not err_cmd and res_cmd["ok"] is True
    assert "_project_instructions" in res_cmd
    assert res_cmd["_project_instructions"][0]["sha256"] == sha_v1

    res_cmd_2, err_cmd_2 = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_run_command",
            {"command": "echo rules_probe_again", "cwd": str(src_dir), "caller": "sess-cmd"},
        )
    )
    assert not err_cmd_2 and "_project_instructions" not in res_cmd_2

    # 4) Modifying `AGENTS.md` updates `sha256` -> re-injects once on next touch, then deduplicates again
    agents_md.write_text("# Project Alpha Rules v2\n- Updated rule after refactor.\n", encoding="utf-8")
    res3, err3 = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_search_code",
            {"pattern": "greet", "path": str(src_dir), "caller": "sess-search"},
        )
    )
    assert not err3 and "_project_instructions" in res3
    sha_v2 = res3["_project_instructions"][0]["sha256"]
    assert sha_v2 != sha_v1
    assert "Updated rule after refactor." in res3["_project_instructions"][0]["content"]

    res4, err4 = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_search_code",
            {"pattern": "greet", "path": str(src_dir), "caller": "sess-search"},
        )
    )
    assert not err4 and "_project_instructions" not in res4


def test_cross_project_switching_priority_subdir_stacking_and_truncation(tmp_path: Path) -> None:
    """Verify proj_a/AGENTS.md -> proj_b/AGENT.md -> proj_c/CLAUDE.md, subdir stacking, priority, and >12288 outline."""
    ws = tmp_path / "multi_ws"
    st = tmp_path / "state"
    ws.mkdir(parents=True)
    st.mkdir(parents=True)

    # proj_a: AGENTS.md + CLAUDE.md (AGENTS.md wins priority) + nested packages/ui/AGENTS.md
    proj_a = ws / "proj_a"
    (proj_a / ".git").mkdir(parents=True)
    (proj_a / "AGENTS.md").write_text("# Proj A Root AGENTS\nroot-rule-a\n", encoding="utf-8")
    (proj_a / "CLAUDE.md").write_text("# Proj A Ignored Lower Priority\n", encoding="utf-8")
    sub_ui = proj_a / "packages" / "ui"
    sub_ui.mkdir(parents=True)
    (sub_ui / "AGENTS.md").write_text("# Proj A Subdir UI Rules\nsubdir-ui-rule\n", encoding="utf-8")
    (sub_ui / "button.ts").write_text("export const btn = 1;\n", encoding="utf-8")

    # proj_b: AGENT.md
    proj_b = ws / "proj_b"
    (proj_b / ".git").mkdir(parents=True)
    (proj_b / "AGENT.md").write_text("# Proj B AGENT Rules\nrule-from-agent-md\n", encoding="utf-8")
    (proj_b / "app.py").write_text("x = 2\n", encoding="utf-8")

    # proj_c: CLAUDE.md (> 12288 chars with Markdown headings)
    proj_c = ws / "proj_c"
    (proj_c / ".git").mkdir(parents=True)
    long_sections = [
        "# Proj C Architecture Guide",
        "Introductory paragraph for project C.",
        "## Section 1: Database Layer",
        "detail-line-db " * 350,
        "### Section 1.1: Migrations",
        "detail-line-mig " * 350,
        "#### Section 1.1.1: Rollback Safety",
        "detail-line-rb " * 450,
    ]
    long_md = "\n".join(long_sections) + "\n"
    assert len(long_md) > PROJECT_RULE_INLINE_MAX_CHARS
    (proj_c / "CLAUDE.md").write_text(long_md, encoding="utf-8")
    (proj_c / "service.py").write_text("y = 3\n", encoding="utf-8")

    dispatcher, _ = _make_dispatcher(ws, st)
    caller = "sess-multi-proj"

    # Touch proj_a root -> injects only proj_a/AGENTS.md (winning over CLAUDE.md)
    ra_root, _ = asyncio.run(
        dispatcher.call_tool_raw("pc_find_files", {"path": str(proj_a), "caller": caller})
    )
    pi_a_root = ra_root["_project_instructions"]
    assert [it["name"] for it in pi_a_root] == ["AGENTS.md"]
    assert "root-rule-a" in pi_a_root[0]["content"]

    # Touch proj_a/packages/ui -> root already injected, so ONLY subdir AGENTS.md is newly injected!
    ra_sub, _ = asyncio.run(
        dispatcher.call_tool_raw("pc_read_file", {"path": str(sub_ui / "button.ts"), "caller": caller})
    )
    pi_a_sub = ra_sub["_project_instructions"]
    assert len(pi_a_sub) == 1
    assert Path(pi_a_sub[0]["path"]).resolve() == (sub_ui / "AGENTS.md").resolve()
    assert Path(pi_a_sub[0]["project_root"]).resolve() == proj_a.resolve()
    assert "subdir-ui-rule" in pi_a_sub[0]["content"]

    # Fresh session touching proj_a/packages/ui directly -> gets BOTH root + subdir stacked in order
    ra_fresh, _ = asyncio.run(
        dispatcher.call_tool_raw("pc_read_file", {"path": str(sub_ui / "button.ts"), "caller": "sess-fresh-stack"})
    )
    pi_fresh = ra_fresh["_project_instructions"]
    assert [Path(it["path"]).resolve() for it in pi_fresh] == [
        (proj_a / "AGENTS.md").resolve(),
        (sub_ui / "AGENTS.md").resolve(),
    ]

    # Switch to proj_b -> injects proj_b/AGENT.md
    rb, _ = asyncio.run(
        dispatcher.call_tool_raw("pc_read_file", {"path": str(proj_b / "app.py"), "caller": caller})
    )
    assert [it["name"] for it in rb["_project_instructions"]] == ["AGENT.md"]
    assert "rule-from-agent-md" in rb["_project_instructions"][0]["content"]

    # Switch to proj_c -> injects truncated proj_c/CLAUDE.md with Markdown heading outline
    rc, _ = asyncio.run(
        dispatcher.call_tool_raw("pc_read_file", {"path": str(proj_c / "service.py"), "caller": caller})
    )
    pi_c = rc["_project_instructions"]
    assert len(pi_c) == 1
    assert pi_c[0]["name"] == "CLAUDE.md"
    assert pi_c[0]["truncated"] is True
    assert "outline" in pi_c[0]
    titles = [h["title"] for h in pi_c[0]["outline"]]
    assert "Proj C Architecture Guide" in titles
    assert "Section 1: Database Layer" in titles
    assert "Section 1.1.1: Rollback Safety" in titles
    assert "pc_read_file" in pi_c[0]["content"]


def test_direct_read_file_anti_duplication(tmp_path: Path) -> None:
    """Directly calling full `read_file('AGENTS.md')` must NOT duplicate `_project_instructions` on that or later calls."""
    ws = tmp_path / "ws_direct"
    st = tmp_path / "state"
    ws.mkdir(parents=True)
    st.mkdir(parents=True)
    (ws / ".git").mkdir()
    (ws / "AGENTS.md").write_text("# Direct Read Rules\nno-dup-please\n", encoding="utf-8")
    (ws / "main.py").write_text("val = 42\n", encoding="utf-8")

    dispatcher, _ = _make_dispatcher(ws, st)

    # Full `read_file("AGENTS.md")` -> returns file content cleanly WITHOUT `_project_instructions`
    r_read, err = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_read_file",
            {"path": str(ws / "AGENTS.md"), "caller": "sess-direct-read"},
        )
    )
    assert not err and r_read["ok"] is True
    assert "no-dup-please" in r_read["content"]
    assert "_project_instructions" not in r_read

    # Subsequent tool call in the same project -> already registered as read, still zero duplicate injection!
    r_next, err_next = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_search_code",
            {"pattern": "val", "path": str(ws), "caller": "sess-direct-read"},
        )
    )
    assert not err_next and r_next["ok"] is True
    assert "_project_instructions" not in r_next


def test_studio_tools_safety_toggle_and_env_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Studio `/api/studio/tools-safety` toggling `auto_inject_project_rules=False` immediately stops injection."""
    monkeypatch.delenv("COSMOS_AUTO_INJECT_PROJECT_RULES", raising=False)
    monkeypatch.delenv("COSMOS_MCP_AUTO_INJECT_PROJECT_RULES", raising=False)

    ws = tmp_path / "studio_ws"
    st = tmp_path / "studio_state"
    ws.mkdir(parents=True)
    st.mkdir(parents=True)
    (ws / ".git").mkdir()
    (ws / "AGENTS.md").write_text("# Studio Controlled Rules\ntoggle-check\n", encoding="utf-8")
    (ws / "a.py").write_text("a = 1\n", encoding="utf-8")

    port = 18964
    app = create_standalone_app(
        state_dir=str(st),
        port=port,
        workspace=str(ws),
        tunnel_mode="local",
    )
    dispatcher: KernelDispatcher = app.state.dispatcher
    origin_hdr = {"Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}

    with TestClient(app, base_url=f"http://127.0.0.1:{port}", client=("127.0.0.1", 53120)) as client:
        st_init = client.get("/api/studio/state", headers=origin_hdr).json()
        assert st_init["auto_inject_project_rules"] is True
        assert st_init["tools_center"]["auto_inject_project_rules"] is True
        rev_before = st_init["state_revision"]

        # Initially enabled -> injects `_project_instructions`
        r_on, _ = asyncio.run(
            dispatcher.call_tool_raw("pc_find_files", {"path": str(ws), "caller": "sess-before-off"})
        )
        assert "_project_instructions" in r_on

        # Turn OFF via `/api/studio/tools-safety`
        post_hdr = {**origin_hdr, "X-Studio-Csrf": st_init["csrf_token"]}
        r_off_api = client.post(
            "/api/studio/tools-safety",
            headers=post_hdr,
            json={"auto_inject_project_rules": False},
        )
        assert r_off_api.status_code == 200
        off_doc = r_off_api.json()
        assert off_doc["auto_inject_project_rules"] is False
        assert off_doc["tools_center"]["auto_inject_project_rules"] is False
        assert off_doc["state_revision"] != rev_before

        cfg_disk = json.loads((st / "config" / "service.json").read_text(encoding="utf-8"))
        assert cfg_disk["auto_inject_project_rules"] is False

        # Brand-new session immediately receives ZERO `_project_instructions`
        r_off_call, _ = asyncio.run(
            dispatcher.call_tool_raw("pc_find_files", {"path": str(ws), "caller": "sess-after-off"})
        )
        assert "_project_instructions" not in r_off_call
        assert "AGENTS.md" not in build_server_instructions(dispatcher, app.state.policy)

        # Turn back ON -> brand-new session receives `_project_instructions` again
        r_on_api = client.post(
            "/api/studio/tools-safety",
            headers=post_hdr,
            json={"auto_inject_project_rules": True},
        )
        assert r_on_api.status_code == 200
        assert r_on_api.json()["tools_center"]["auto_inject_project_rules"] is True

        r_re_on, _ = asyncio.run(
            dispatcher.call_tool_raw("pc_find_files", {"path": str(ws), "caller": "sess-after-re-on"})
        )
        assert "_project_instructions" in r_re_on

        # Environment variable override `COSMOS_AUTO_INJECT_PROJECT_RULES=0`
        monkeypatch.setenv("COSMOS_AUTO_INJECT_PROJECT_RULES", "0")
        r_env_off, _ = asyncio.run(
            dispatcher.call_tool_raw("pc_find_files", {"path": str(ws), "caller": "sess-env-override"})
        )
        assert "_project_instructions" not in r_env_off


def test_guardrail_boundary_and_secret_isolation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify parent outside workspace, unmounted HOME/.dsh, bare root, and escaped symlinks are never injected."""
    monkeypatch.delenv("COSMOS_AUTO_INJECT_PROJECT_RULES", raising=False)

    # Parent directory above `ws` has an `AGENTS.md` that MUST NOT leak into `ws`
    outer = tmp_path / "outer"
    outer.mkdir(parents=True)
    (outer / "AGENTS.md").write_text("OUTER_FORBIDDEN_RULE_LEAK\n", encoding="utf-8")

    ws = outer / "authorized_ws"
    ws.mkdir(parents=True)
    (ws / "code.py").write_text("z = 9\n", encoding="utf-8")

    st = tmp_path / "guard_state"
    st.mkdir(parents=True)
    dispatcher, policy = _make_dispatcher(ws, st, tier="tier3_workspace_dev")

    r_clean, err = asyncio.run(
        dispatcher.call_tool_raw("pc_read_file", {"path": str(ws / "code.py"), "caller": "sess-boundary"})
    )
    assert not err and r_clean["ok"] is True
    assert "_project_instructions" not in r_clean

    # Symlink inside `ws` pointing to `outer/AGENTS.md` MUST be rejected by `guard.check_path_access`
    sym_agents = ws / "AGENTS.md"
    symlink_created = False
    try:
        os.symlink(str(outer / "AGENTS.md"), str(sym_agents))
        symlink_created = True
    except OSError:
        symlink_created = False

    if symlink_created:
        r_sym, _ = asyncio.run(
            dispatcher.call_tool_raw("pc_find_files", {"path": str(ws), "caller": "sess-symlink"})
        )
        assert "_project_instructions" not in r_sym
        sym_agents.unlink()

    # Unmounted `Path.home()`, `~/.dsh`, and bare drive roots MUST return True on `_is_unsafe_climb_boundary`
    fake_home = tmp_path / "fake_home"
    (fake_home / ".dsh").mkdir(parents=True)
    (fake_home / "AGENTS.md").write_text("HOME_LEAK\n", encoding="utf-8")
    (fake_home / ".dsh" / "AGENTS.md").write_text("DSH_LEAK\n", encoding="utf-8")
    sub_under_home = fake_home / "work_sub"
    sub_under_home.mkdir(parents=True)
    (sub_under_home / "note.txt").write_text("hello\n", encoding="utf-8")

    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))

    ws_norm = {os.path.normcase(str(ws.resolve())).rstrip("\\/")}
    assert _is_unsafe_climb_boundary(Path(ws.anchor), ws_norm) is True
    assert _is_unsafe_climb_boundary(fake_home, ws_norm) is True
    assert _is_unsafe_climb_boundary(fake_home / ".dsh", ws_norm) is True

    # Even in L4 (`tier4_full_power`), touching `fake_home/work_sub/note.txt` must NOT climb into unmounted `fake_home`
    disp_l4, pol_l4 = _make_dispatcher(ws, st, tier="tier4_full_power")
    r_l4_home, err_l4 = asyncio.run(
        disp_l4.call_tool_raw("pc_read_file", {"path": str(sub_under_home / "note.txt"), "caller": "sess-l4-home"})
    )
    assert not err_l4 and r_l4_home["ok"] is True
    assert "_project_instructions" not in r_l4_home

    # When `redact_project_secrets=True`, generic secret literals inside `AGENTS.md` are redacted before injection
    pol_l4.apply_direct(redact_project_secrets=True)
    fake_tok = "sk-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    (ws / "AGENTS.md").write_text(f"# Rules\nExample key: {fake_tok}\n", encoding="utf-8")
    r_redacted, _ = asyncio.run(
        disp_l4.call_tool_raw("pc_find_files", {"path": str(ws), "caller": "sess-redact"})
    )
    assert "_project_instructions" in r_redacted
    injected_txt = r_redacted["_project_instructions"][0]["content"]
    assert fake_tok not in injected_txt
    assert re.search(r"REDACTED", injected_txt)
