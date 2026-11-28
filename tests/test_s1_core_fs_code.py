from __future__ import annotations

import ast
import asyncio
import base64
import ctypes
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import zipfile

import pytest

from cosmos_mcp.core import code as code_ops
from cosmos_mcp.core import fs as file_ops
from cosmos_mcp.core import fs_io, fs_tx, memory, patch, path_heal, search_nav
from cosmos_mcp.core.config import LiveRuntimePolicy
from cosmos_mcp.core.guard import CREATE_NO_WINDOW, WorkspaceGuard
from cosmos_mcp.core.proc import ProcessManager
from cosmos_mcp.protocol.dispatcher import KernelDispatcher
from cosmos_mcp.protocol.tools import build_core_tools

REPO_ROOT = Path(__file__).resolve().parents[1]

WHITELIST_CORE_FILES = (
    "src/cosmos_mcp/core/guard.py",
    "src/cosmos_mcp/core/path_heal.py",
    "src/cosmos_mcp/core/fs_io.py",
    "src/cosmos_mcp/core/fs_tx.py",
    "src/cosmos_mcp/core/fs.py",
    "src/cosmos_mcp/core/patch.py",
    "src/cosmos_mcp/core/search_nav.py",
    "src/cosmos_mcp/core/code.py",
    "src/cosmos_mcp/core/memory.py",
)


def _run_git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    flags = 0
    if sys.platform == "win32":
        ctypes.windll.kernel32.SetErrorMode(0x8003)
        flags = CREATE_NO_WINDOW
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        creationflags=flags,
        check=True,
    )


def _make_guard(ws_dir: Path, st_dir: Path, tier: str = "L3") -> WorkspaceGuard:
    ws_dir.mkdir(parents=True, exist_ok=True)
    st_dir.mkdir(parents=True, exist_ok=True)
    return WorkspaceGuard(
        workspace_roots=[ws_dir],
        restrict_to_workspace=True,
        tier=tier,
        tool_prefix="pc_",
        state_root=st_dir,
    )


def _make_dispatcher(ws_dir: Path, st_dir: Path, tier: str = "tier3_workspace_dev") -> KernelDispatcher:
    ws_dir.mkdir(parents=True, exist_ok=True)
    st_dir.mkdir(parents=True, exist_ok=True)
    guard = WorkspaceGuard(
        workspace_roots=[ws_dir],
        restrict_to_workspace=(tier != "tier4_full_power"),
        state_root=st_dir,
        tool_prefix="pc",
    )
    proc_mgr = ProcessManager(guard=guard, state_root=st_dir)
    cfg_path = st_dir / "config" / "service.json"
    policy = LiveRuntimePolicy(
        tier_key=tier,
        workspace_roots=[ws_dir],
        cfg_path=cfg_path,
        state_root=st_dir,
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
    return dispatcher


def test_whitelist_stdlib_only_and_zero_internal_codenames() -> None:
    stdlib_names = set(getattr(sys, "stdlib_module_names", ())) | {
        "__future__",
        "tomllib",
        "msvcrt",
        "fcntl",
        "winreg",
    }
    lazy_optional_allowed = {"PIL", "pypdf"}

    legacy_tokens = [
        "".join(("l0", "_", "primitives")),
        "".join(("l1", "_", "capabilities")),
        "".join(("T5", "_", "cham", "pion", "_12")),
        "".join(("cham", "pion", "_12")),
        "".join(("base", "line", "_19")),
        "".join(("web", "-", "taint")),
        "".join(("web", "_", "taint")),
    ]
    forbidden_re = re.compile(
        "|".join(re.escape(tok) for tok in legacy_tokens) + r"|\b" + "ag" + r"y\b",
        re.IGNORECASE,
    )

    for rel in (*WHITELIST_CORE_FILES, "tests/test_s1_core_fs_code.py"):
        full_p = REPO_ROOT / rel
        src = full_p.read_text(encoding="utf-8")
        hit = forbidden_re.search(src)
        assert hit is None, f"Forbidden internal token `{hit.group(0)}` found in {rel}"

    for rel in WHITELIST_CORE_FILES:
        full_p = REPO_ROOT / rel
        tree = ast.parse(full_p.read_text(encoding="utf-8"), filename=str(full_p))

        def _walk_imports(node: ast.AST, inside_fn: bool = False) -> None:
            now_in_fn = inside_fn or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top_pkg = alias.name.split(".")[0]
                    if top_pkg == "cosmos_mcp":
                        assert alias.name.startswith("cosmos_mcp.core"), f"Non-core import {alias.name} in {rel}"
                    elif now_in_fn and top_pkg in lazy_optional_allowed:
                        continue
                    else:
                        assert top_pkg in stdlib_names, f"Third-party import `{alias.name}` forbidden in {rel}"
            elif isinstance(node, ast.ImportFrom):
                if (node.level or 0) > 0:
                    pass
                else:
                    mod_name = node.module or ""
                    top_pkg = mod_name.split(".")[0]
                    if top_pkg == "cosmos_mcp":
                        assert mod_name.startswith("cosmos_mcp.core"), f"Non-core from-import {mod_name} in {rel}"
                    elif now_in_fn and top_pkg in lazy_optional_allowed:
                        pass
                    else:
                        assert top_pkg in stdlib_names, f"Third-party from-import `{mod_name}` forbidden in {rel}"
            for ch in ast.iter_child_nodes(node):
                _walk_imports(ch, now_in_fn)

        _walk_imports(tree)


def test_guard_list_set_remove_allowed_and_os_deletion_blocked(tmp_path: Path) -> None:
    ws_dir = tmp_path / "ws"
    st_dir = tmp_path / "state"
    g_l3 = _make_guard(ws_dir, st_dir, tier="L3")
    g_l1 = _make_guard(ws_dir, st_dir, tier="L1")

    safe_code = (
        'feature_cols = ["id", "bad_col", "score"]\n'
        'feature_cols.remove("bad_col")\n'
        "seen = {1, 2, 3}\n"
        "seen.remove(2)\n"
        "class Cleaner:\n"
        "    def prune(self):\n"
        "        self.cols.remove('x')\n"
    )
    assert g_l3.check_python_code_safety(safe_code) is None
    assert g_l1.check_python_code_safety(safe_code) is None

    # Physical file deletion calls via os / pathlib / shutil remain blocked
    assert g_l3.check_python_code_safety("import os\nos.remove('a.txt')\n") is not None
    assert g_l3.check_python_code_safety("import os as _os\n_os.remove('a.txt')\n") is not None
    assert g_l3.check_python_code_safety("from os import remove\nremove('a.txt')\n") is not None
    assert g_l3.check_python_code_safety("from pathlib import Path\nPath('a.txt').unlink()\n") is not None
    assert g_l3.check_python_code_safety("import shutil\nshutil.rmtree('sub')\n") is not None


def test_guard_auth_json_scoped_strictly_to_state_root(tmp_path: Path) -> None:
    ws_dir = tmp_path / "project"
    st_dir = tmp_path / "cosmos_state"
    g = _make_guard(ws_dir, st_dir, tier="L3")

    # User project's own auth.json (including project secrets/auth.json) is allowed
    proj_auth = ws_dir / "auth.json"
    proj_nested_auth = ws_dir / "secrets" / "auth.json"
    assert g.check_path_access(str(proj_auth), mode="write") is None
    assert g.check_path_access(str(proj_auth), mode="read") is None
    assert g.check_path_access(str(proj_nested_auth), mode="write") is None
    assert g.check_path_access(str(proj_nested_auth), mode="read") is None

    w_res = file_ops.write_file(proj_auth, '{"service": "demo", "role": "user"}\n', guard=g)
    assert w_res["ok"] is True
    r_res = file_ops.read_file(proj_auth, include_line_numbers=False, guard=g)
    assert r_res["ok"] is True and '"demo"' in r_res["content"]

    assert g.check_python_code_safety(f"from pathlib import Path\nprint(Path({str(proj_auth)!r}).read_text())\n") is None

    # Service state_root secrets & connection files are strictly blocked even at L4 unrestricted
    g_l4 = WorkspaceGuard(restrict_to_workspace=False, tier="L4", state_root=st_dir)
    svc_secret = st_dir / "secrets" / "auth.json"
    svc_pwd = st_dir / "secrets" / "owner_password.txt"
    svc_conn = st_dir / "CONNECTION_INFO.txt"
    svc_oauth = st_dir / "state" / "oauth_tokens.sqlite3"
    svc_secret.parent.mkdir(parents=True, exist_ok=True)
    svc_oauth.parent.mkdir(parents=True, exist_ok=True)
    svc_secret.write_text("{}", encoding="utf-8")
    svc_pwd.write_text("pw", encoding="utf-8")
    svc_conn.write_text("url", encoding="utf-8")
    svc_oauth.write_text("db", encoding="utf-8")

    for protected in (svc_secret, svc_pwd, svc_conn, svc_oauth):
        assert g_l4.check_path_access(str(protected), mode="read") is not None
        assert g_l4.check_path_access(str(protected), mode="write") is not None


def test_git_repo_zero_pollution_and_externalized_history_and_memory(tmp_path: Path) -> None:
    repo_dir = tmp_path / "user_git_repo"
    st_dir = tmp_path / "service_state"
    repo_dir.mkdir(parents=True)
    g = _make_guard(repo_dir, st_dir, tier="L3")

    _run_git(["init"], cwd=repo_dir)
    _run_git(["config", "user.email", "dev@example.com"], cwd=repo_dir)
    _run_git(["config", "user.name", "Dev"], cwd=repo_dir)

    tracked = repo_dir / "module.py"
    tracked.write_text(
        "def compute_total(items):\n"
        "    total = 0\n"
        "    for x in items:\n"
        "        total += x\n"
        "    return total\n",
        encoding="utf-8",
    )
    _run_git(["add", "module.py"], cwd=repo_dir)
    _run_git(["commit", "-m", "init"], cwd=repo_dir)
    assert _run_git(["status", "--porcelain"], cwd=repo_dir).stdout.strip() == ""

    # 1) Edit tracked file, create UTF-16LE file, check shrink guard & syntax precheck, write memory
    ed = file_ops.edit_file(tracked, old_text="total = 0", new_text="total = 10", guard=g)
    assert ed["ok"] is True

    # Syntax error rejected in external staging before touching target
    bad_ed = file_ops.write_file(tracked, "def broken(:\n    pass\n", allow_shrink=True, guard=g)
    assert bad_ed["ok"] is False and bad_ed.get("auto_rolled_back") is True

    # UTF-16LE roundtrip + >50% shrink warning with snapshot rollback
    u16_file = repo_dir / "config_u16.txt"
    u16_payload = ("line_alpha = 100\r\n" * 20)
    u16_file.write_bytes(b"\xff\xfe" + u16_payload.encode("utf-16-le"))
    r_u16 = file_ops.read_file(u16_file, start_line=1, end_line=3, include_line_numbers=False, guard=g)
    assert r_u16["ok"] is True and r_u16["encoding"] == "utf-16-le-bom"
    shrink_res = file_ops.write_file(u16_file, "short\r\n", allow_shrink=False, guard=g)
    assert shrink_res["ok"] is True and shrink_res.get("shrink_warning") is True
    assert shrink_res.get("undo_snapshot") and "undo" in str(shrink_res.get("warning", "")).lower()
    un_u16 = file_ops.manage_files(g, action="undo", path=u16_file)
    assert un_u16["ok"] is True and u16_file.read_bytes() == b"\xff\xfe" + u16_payload.encode("utf-16-le")

    # Memory notes & auto activity go to <state_root>/history/<ws_hash>/shared_memory.sqlite3
    mem_res = memory.run_workspace_memory(
        action="post",
        content="verified clean git tree",
        author="tester",
        workspace_root=repo_dir,
        guard=g,
    )
    assert mem_res["ok"] is True
    memory.record_auto_activity("edit_file", str(tracked), "edit_file", author="tester", workspace_root=repo_dir, guard=g)
    recent_mem = memory.read_recent_activity(workspace_root=repo_dir, guard=g)
    assert len(recent_mem) >= 2

    # Even while `module.py` is modified, zero `.undo_history` or `.localpc_memory` in git status!
    porcelain_mid = _run_git(["status", "--porcelain"], cwd=repo_dir).stdout
    assert ".undo_history" not in porcelain_mid
    assert ".localpc_memory" not in porcelain_mid
    assert not (repo_dir / ".undo_history").exists()
    assert not (repo_dir / ".localpc_memory").exists()

    ws_hash = fs_tx.compute_workspace_hash(repo_dir)
    expected_hist = st_dir / "history" / ws_hash
    assert (expected_hist / "index.json").is_file()
    assert (expected_hist / "shared_memory.sqlite3").is_file()

    # Trash `config_u16.txt` -> goes to `st_dir / "trash"` (same volume)
    tr = file_ops.manage_files(g, action="trash", path=u16_file)
    assert tr["ok"] is True and not u16_file.exists()
    assert Path(tr["moved_to"]).parent == (st_dir / "trash").resolve()

    # Undo edit on `module.py` -> repo returns to 100% clean `git status --porcelain`!
    un = file_ops.manage_files(g, action="undo", path=tracked)
    assert un["ok"] is True
    assert _run_git(["status", "--porcelain"], cwd=repo_dir).stdout.strip() == ""


def test_manage_files_literal_brackets_pathless_undo_and_dispatcher(tmp_path: Path) -> None:
    ws_dir = tmp_path / "ws"
    st_dir = tmp_path / "state"
    g = _make_guard(ws_dir, st_dir, tier="L3")
    dispatcher = _make_dispatcher(ws_dir, st_dir, tier="L3")

    # Small PNG (`<= 340KiB`, `<= 1440px`) with literal brackets `IMG_9842[1].png`
    png_bytes = fs_io.encode_rgb_png_stdlib(4, 4, b"\x10\x80\xf0" * 16)
    orig_img = ws_dir / "IMG_9842[1].png"
    decoy_img = ws_dir / "IMG_98421.png"
    orig_img.write_bytes(png_bytes)
    decoy_bytes = fs_io.encode_rgb_png_stdlib(2, 2, b"\xff\x00\x00" * 4)
    decoy_img.write_bytes(decoy_bytes)

    # Verify small PNG lossless raw passthrough in `read_file`
    blocks = file_ops.read_file(orig_img, guard=g)
    assert isinstance(blocks, list) and len(blocks) == 2
    meta = json.loads(blocks[0]["text"])
    assert meta["encoder"] == "png_lossless_passthrough"
    assert base64.b64decode(blocks[1]["data"]) == png_bytes

    # 1) mkdir -> rename bracketed file -> move bracketed file via dispatcher `pc_manage_files`
    mk, mk_err = asyncio.run(
        dispatcher.call_tool_raw("pc_manage_files", {"action": "mkdir", "path": str(ws_dir / "album[2026]")})
    )
    assert not mk_err and mk["ok"] is True and (ws_dir / "album[2026]").is_dir()

    rn, rn_err = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_manage_files",
            {"action": "rename", "path": str(orig_img), "destination": "IMG_9842_renamed[1].png"},
        )
    )
    renamed_p = ws_dir / "IMG_9842_renamed[1].png"
    assert not rn_err and rn["ok"] is True
    assert not orig_img.exists() and renamed_p.is_file()
    assert decoy_img.read_bytes() == decoy_bytes  # decoy `IMG_98421.png` untouched!

    moved_p = ws_dir / "album[2026]" / "IMG_9842_final[1].png"
    mv, mv_err = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_manage_files",
            {"action": "move", "path": str(renamed_p), "destination": str(moved_p)},
        )
    )
    assert not mv_err and mv["ok"] is True
    assert not renamed_p.exists() and moved_p.read_bytes() == png_bytes

    # 2) Pathless `undo` (`path=""`) rolls back `move`, then rolls back `rename`!
    u1, u1_err = asyncio.run(dispatcher.call_tool_raw("pc_manage_files", {"action": "undo"}))
    assert not u1_err and u1["ok"] is True and u1["undone_op"] == "move"
    assert renamed_p.is_file() and not moved_p.exists()

    u2, u2_err = asyncio.run(dispatcher.call_tool_raw("pc_manage_files", {"action": "undo"}))
    assert not u2_err and u2["ok"] is True and u2["undone_op"] == "rename"
    assert orig_img.is_file() and orig_img.read_bytes() == png_bytes and not renamed_p.exists()

    # 3) Trash bracketed file -> pathless `undo` restores it from trash!
    tr, tr_err = asyncio.run(dispatcher.call_tool_raw("pc_manage_files", {"action": "trash", "path": str(orig_img)}))
    assert not tr_err and tr["ok"] is True and not orig_img.exists()

    ls_res = file_ops.manage_files(g, action="list")
    assert ls_res["ok"] is True and ls_res["trash_count"] >= 1

    u3 = file_ops.undo_or_trash(action="undo", guard=g)
    assert u3["ok"] is True and u3["undone_op"] == "trash"
    assert orig_img.is_file() and orig_img.read_bytes() == png_bytes


def _build_sample_xlsx(xlsx_path: Path) -> None:
    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Metrics" sheetId="1" r:id="rId1"/></sheets>'
        "</workbook>"
    )
    rels_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        "</Relationships>"
    )
    # xf[0]: General (0), xf[1]: builtin date (14), xf[2]: custom date (165 -> yyyy-mm-dd)
    styles_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<numFmts count="1"><numFmt numFmtId="165" formatCode="yyyy-mm-dd"/></numFmts>'
        '<cellStyleXfs count="1"><xf numFmtId="0"/></cellStyleXfs>'
        '<cellXfs count="3">'
        '<xf numFmtId="0"/>'
        '<xf numFmtId="14" applyNumberFormat="1"/>'
        '<xf numFmtId="165" applyNumberFormat="1"/>'
        "</cellXfs>"
        "</styleSheet>"
    )
    sheet_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        "<sheetData>"
        '<row r="1">'
        '<c r="A1" t="inlineStr"><is><t>ExperimentDate</t></is></c>'
        '<c r="B1" t="inlineStr"><is><t>CustomDate</t></is></c>'
        '<c r="C1" t="inlineStr"><is><t>UncachedTotal</t></is></c>'
        "</row>"
        '<row r="2">'
        '<c r="A2" s="1"><v>46350</v></c>'
        '<c r="B2" s="2"><v>46351</v></c>'
        '<c r="C2"><f>SUM(D2:D10)</f></c>'
        "</row>"
        "</sheetData>"
        "</worksheet>"
    )
    with zipfile.ZipFile(xlsx_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/_rels/workbook.xml.rels", rels_xml)
        zf.writestr("xl/styles.xml", styles_xml)
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)


def _build_sample_pptx(pptx_path: Path) -> None:
    pres_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<p:sldIdLst><p:sldId id="256" r:id="rId2"/><p:sldId id="257" r:id="rId1"/></p:sldIdLst>'
        "</p:presentation>"
    )
    rels_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId2" Type="slide" Target="slides/slide1.xml"/>'
        '<Relationship Id="rId1" Type="slide" Target="slides/slide2.xml"/>'
        "</Relationships>"
    )
    slide1_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
        'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
        "<p:cSld><p:spTree><p:sp><p:txBody>"
        "<a:p><a:r><a:t>Quarterly Architecture Review</a:t></a:r></a:p>"
        "<a:p><a:r><a:t>Latency dropped 42%</a:t></a:r></a:p>"
        "</p:txBody></p:sp></p:spTree></p:cSld></p:sld>"
    )
    slide2_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
        'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
        "<p:cSld><p:spTree><p:graphicFrame><a:graphic><a:graphicData><a:tbl>"
        "<a:tr><a:tc><a:txBody><a:p><a:r><a:t>Metric</a:t></a:r></a:p></a:txBody></a:tc>"
        "<a:tc><a:txBody><a:p><a:r><a:t>P99_MS</a:t></a:r></a:p></a:txBody></a:tc></a:tr>"
        "</a:tbl></a:graphicData></a:graphic></p:graphicFrame></p:spTree></p:cSld></p:sld>"
    )
    with zipfile.ZipFile(pptx_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("ppt/presentation.xml", pres_xml)
        zf.writestr("ppt/_rels/presentation.xml.rels", rels_xml)
        zf.writestr("ppt/slides/slide1.xml", slide1_xml)
        zf.writestr("ppt/slides/slide2.xml", slide2_xml)


def _build_sample_ipynb(ipynb_path: Path) -> str:
    giant_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ" + ("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=" * 300)
    nb_doc = {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {},
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [
                    "# Ablation Study\n",
                    f"![plot](data:image/png;base64,{giant_b64})\n",
                ],
                "attachments": {"fig.png": {"image/png": giant_b64}},
            },
            {
                "cell_type": "code",
                "execution_count": 7,
                "metadata": {},
                "source": ["def compute_f1_macro():\n", "    return 0.9412\n"],
                "outputs": [
                    {"output_type": "stream", "name": "stdout", "text": ["EPOCH_CONVERGED=True\n"]},
                    {
                        "output_type": "display_data",
                        "data": {
                            "image/png": giant_b64,
                            "text/plain": ["<Figure size 800x600>"],
                        },
                        "metadata": {},
                    },
                ],
            },
        ],
    }
    ipynb_path.write_text(json.dumps(nb_doc), encoding="utf-8")
    return giant_b64[:80]


def test_read_file_xlsx_ipynb_pptx_and_write_file_base64(tmp_path: Path) -> None:
    ws_dir = tmp_path / "ws"
    st_dir = tmp_path / "state"
    g = _make_guard(ws_dir, st_dir, tier="L3")
    dispatcher = _make_dispatcher(ws_dir, st_dir, tier="L3")

    # 1) .xlsx date serial `46350` -> `2026-11-24` and uncached `<f>` -> `=SUM(D2:D10)`
    xlsx_p = ws_dir / "results.xlsx"
    _build_sample_xlsx(xlsx_p)
    rx = file_ops.read_file(xlsx_p, include_line_numbers=False, guard=g)
    assert rx["ok"] is True and rx["document_format"] == "xlsx"
    assert "2026-11-24" in rx["content"]
    assert "2026-11-25" in rx["content"]
    assert "46350" not in rx["content"]
    assert "=SUM(D2:D10)" in rx["content"]

    # 2) .pptx per-slide extraction
    pptx_p = ws_dir / "deck.pptx"
    _build_sample_pptx(pptx_p)
    rp = file_ops.read_file(pptx_p, include_line_numbers=False, guard=g)
    assert rp["ok"] is True and rp["document_format"] == "pptx"
    assert "[Slide 1]" in rp["content"]
    assert "Quarterly Architecture Review" in rp["content"]
    assert "[Slide 2]" in rp["content"]
    assert "Metric | P99_MS" in rp["content"]

    # 3) .ipynb per-cell source + text outputs with giant Base64 stripped
    ipynb_p = ws_dir / "experiment.ipynb"
    b64_prefix = _build_sample_ipynb(ipynb_p)
    rn = file_ops.read_file(ipynb_p, include_line_numbers=False, guard=g)
    assert rn["ok"] is True and rn["document_format"] == "ipynb"
    assert "Ablation Study" in rn["content"]
    assert "def compute_f1_macro():" in rn["content"]
    assert "EPOCH_CONVERGED=True" in rn["content"]
    assert "<Figure size 800x600>" in rn["content"]
    assert b64_prefix not in rn["content"]

    # 4) `write_file(encoding="base64")` binary decode via direct API & protocol `pc_write_file`
    raw_binary = b"\x00\x89PNG\r\n\x1a\n\xde\xad\xbe\xef\x00\xff"
    b64_str = base64.b64encode(raw_binary).decode("ascii")
    bin_p = ws_dir / "payload.bin"
    wb, wb_err = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_write_file",
            {"path": str(bin_p), "content": b64_str, "encoding": "base64"},
        )
    )
    assert not wb_err and wb["ok"] is True
    assert wb["encoding"] == "base64"
    assert bin_p.read_bytes() == raw_binary


def test_patch_failure_receipt_deduplicated_and_edit_file_hint(tmp_path: Path) -> None:
    ws_dir = tmp_path / "ws"
    st_dir = tmp_path / "state"
    g = _make_guard(ws_dir, st_dir, tier="L3")

    target = ws_dir / "calc.py"
    target.write_text(
        "def alpha():\n"
        "    UNIQUE_DIAG_SENTINEL = 424242\n"
        "    return UNIQUE_DIAG_SENTINEL + 1\n",
        encoding="utf-8",
    )

    fail = file_ops.edit_file(
        target,
        old_text="    COMPLETELY_UNRELATED_CALL(x, y, z)\n    UNIQUE_DIAG_SENTINEL = -1\n",
        new_text="    return 0\n",
        guard=g,
    )
    assert fail["ok"] is False
    assert "closest_match" in fail
    assert "diagnostic" not in fail

    cm = fail["closest_match"]
    assert set(cm.keys()) <= {"start_line", "end_line", "similarity", "snippet", "suggestion"}
    assert "edit_file(" in cm["suggestion"]
    assert "replace_line_range" not in json.dumps(fail, ensure_ascii=False)

    # Previously `UNIQUE_DIAG_SENTINEL` was repeated 12x across 6 duplicate fields x 2 keys; now only in `snippet`!
    dumped = json.dumps(fail, ensure_ascii=False)
    assert dumped.count("UNIQUE_DIAG_SENTINEL = 424242") == 1


def test_find_files_search_code_include_docs_and_code_intel(tmp_path: Path) -> None:
    ws_dir = tmp_path / "repo"
    st_dir = tmp_path / "state"
    g = _make_guard(ws_dir, st_dir, tier="L3")

    # 1) `find_files`: default `max_depth=8`, `size_bytes`, `mtime`, `sort_by="mtime"`
    deep_dir = ws_dir / "l1" / "l2" / "l3" / "l4" / "l5" / "l6"
    deep_dir.mkdir(parents=True)
    older_f = ws_dir / "src" / "pkg" / "older.py"
    older_f.parent.mkdir(parents=True)
    older_f.write_text("class Dog:\n    def speak(self):\n        return self._bark_impl()\n    def _bark_impl(self):\n        return 'woof'\n", encoding="utf-8")

    newer_deep_f = deep_dir / "newer_deep.py"
    newer_deep_f.write_text(
        "from src.pkg.older import Dog\n"
        "class Robot:\n"
        "    def speak(self):\n"
        "        return 'beep'\n"
        "    def ping(self):\n"
        "        return self.speak()\n\n"
        "def run_demo():\n"
        "    pet = Dog()\n"
        "    bot = Robot()\n"
        "    return pet.speak(), bot.speak()\n",
        encoding="utf-8",
    )
    now_ts = time.time()
    os.utime(older_f, (now_ts - 120.0, now_ts - 120.0))
    os.utime(newer_deep_f, (now_ts, now_ts))

    ff = search_nav.find_files(ws_dir, entry_type="file", sort_by="mtime", guard=g)
    assert ff["ok"] is True
    assert ff["max_depth"] == 8
    rels = [e["rel_path"] for e in ff["entries"]]
    assert "l1/l2/l3/l4/l5/l6/newer_deep.py" in rels
    assert rels[0] == "l1/l2/l3/l4/l5/l6/newer_deep.py"
    for ent in ff["entries"]:
        assert "size_bytes" in ent and ent["size_bytes"] > 0
        assert "mtime" in ent and ent["mtime"] > 0

    # 2) `search_code`: no `formatted_matches`; `include_docs=True` searches `.xlsx`/`.pptx`/`.ipynb`/`.md`
    xlsx_p = ws_dir / "sheet.xlsx"
    _build_sample_xlsx(xlsx_p)
    pptx_p = ws_dir / "slides.pptx"
    _build_sample_pptx(pptx_p)
    ipynb_p = ws_dir / "nb.ipynb"
    _build_sample_ipynb(ipynb_p)
    md_p = ws_dir / "NOTES.md"
    md_p.write_text("# Notes\nQuarterly Architecture Review\n", encoding="utf-8")

    sc_code_only = search_nav.search_code("Quarterly Architecture Review", path=ws_dir, include_docs=False, guard=g)
    assert sc_code_only["ok"] is True
    assert "formatted_matches" not in sc_code_only
    assert sc_code_only["count"] == 0

    sc_with_docs = search_nav.search_code("Quarterly Architecture Review", path=ws_dir, include_docs=True, guard=g)
    assert sc_with_docs["ok"] is True
    assert "formatted_matches" not in sc_with_docs
    doc_hit_rels = {m["rel_path"] for m in sc_with_docs["matches"]}
    assert "slides.pptx" in doc_hit_rels
    assert "NOTES.md" in doc_hit_rels

    sc_xlsx = search_nav.search_code("2026-11-24", path=ws_dir, include_docs=True, guard=g)
    assert any(m["rel_path"] == "sheet.xlsx" for m in sc_xlsx["matches"])
    sc_ipynb = search_nav.search_code("compute_f1_macro", path=ws_dir, include_docs=True, guard=g)
    assert any(m["rel_path"] == "nb.ipynb" for m in sc_ipynb["matches"])

    # 3) `code_intel`: directory `outline` recurses into `src/` (`file_count > 0`) & merges `overview`/`repo_map`
    ci_outline = code_ops.run_code_intel(path=ws_dir, action="outline", guard=g)
    assert ci_outline["ok"] is True
    assert ci_outline["file_count"] >= 2
    outlined_rels = {f["file"] for f in ci_outline["files"]}
    assert "src/pkg/older.py" in outlined_rels

    ci_overview = code_ops.run_code_intel(path=ws_dir, action="overview", guard=g)
    assert ci_overview["ok"] is True and ci_overview["action"] == "overview"
    assert ci_overview["file_count"] >= 2 and "repo_map" in ci_overview

    ci_rm = code_ops.run_code_intel(path=ws_dir, action="repo_map", guard=g)
    assert ci_rm["ok"] is True and ci_rm["action"] == "repo_map"
    assert ci_rm["file_count"] >= 2

    # 4) `rename_symbol`: blocks ambiguous unqualified `speak`, and scopes `Dog.speak` without touching `Robot.speak`
    ambig = code_ops.rename_symbol("speak", "vocalize", path=ws_dir, guard=g)
    assert ambig["ok"] is False and ambig.get("ambiguous_symbol") is True

    scoped = code_ops.rename_symbol("Dog.speak", "bark", path=ws_dir, guard=g)
    assert scoped["ok"] is True
    assert scoped["files_modified"] == 2

    older_after = older_f.read_text(encoding="utf-8")
    newer_after = newer_deep_f.read_text(encoding="utf-8")
    assert "def bark(self):" in older_after and "def speak" not in older_after
    assert "pet.bark()" in newer_after
    # Unrelated `Robot.speak` and `bot.speak()` and `self.speak()` inside `Robot` MUST stay untouched!
    assert "class Robot:\n    def speak(self):" in newer_after
    assert "return self.speak()" in newer_after
    assert "bot.speak()" in newer_after


def test_pdf_no_pypdf_cidfont_guard_unread_overwrite_warning_and_skills_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zlib

    ws_dir = tmp_path / "ws_drift"
    st_dir = tmp_path / "state_drift"
    sk_dir = ws_dir / ".agents" / "skills" / "ledger-ops-brief"
    sk_dir.mkdir(parents=True)
    (sk_dir / "SKILL.md").write_text(
        "---\nname: ledger-ops-brief\ndescription: Monthly reimbursement reconciliation checklist\n---\n# Ledger Brief\n",
        encoding="utf-8",
    )

    g = _make_guard(ws_dir, st_dir, tier="L3")
    dispatcher = _make_dispatcher(ws_dir, st_dir, tier="L3")

    # 1) Without `pypdf`, CIDFont / non-UTF8 binary glyph stream MUST return `ok: False` (never Mojibake `ok: True`)
    cid_pdf = ws_dir / "cid_chinese.pdf"
    cid_stream = zlib.compress(b"BT /F1 12 Tf <1bbd052c354c0a2d> Tj ET")
    cid_pdf.write_bytes(
        b"%PDF-1.4\n1 0 obj << /Type /Font /Subtype /CIDFontType2 /Encoding /Identity-H >> endobj\n"
        b"2 0 obj << /Filter /FlateDecode /Length "
        + str(len(cid_stream)).encode("ascii")
        + b" >>\nstream\n"
        + cid_stream
        + b"\nendstream\nendobj\n%%EOF\n"
    )
    ascii_pdf = ws_dir / "plain_ascii.pdf"
    ascii_pdf.write_bytes(
        b"%PDF-1.4\n1 0 obj << /Length 30 >>\nstream\nBT (Clean Invoice 2026) Tj ET\nendstream\nendobj\n%%EOF\n"
    )

    monkeypatch.setitem(sys.modules, "pypdf", None)
    cid_res = file_ops.read_file(cid_pdf, guard=g)
    assert cid_res["ok"] is False
    assert "pypdf" in str(cid_res.get("error", "")).lower()

    ascii_res = file_ops.read_file(ascii_pdf, include_line_numbers=False, guard=g)
    assert ascii_res["ok"] is True
    assert "Clean Invoice 2026" in ascii_res["content"]

    multilang_text = "Café München αβγδ ∑≤∞ 𠀀𠮷"
    utf16_hex = (b"\xfe\xff" + multilang_text.encode("utf-16-be")).hex()
    multilang_pdf = ws_dir / "multilang_utf16.pdf"
    multilang_stream = f"BT <{utf16_hex}> Tj ET".encode("ascii")
    multilang_pdf.write_bytes(
        b"%PDF-1.4\n1 0 obj << /Length "
        + str(len(multilang_stream)).encode("ascii")
        + b" >>\nstream\n"
        + multilang_stream
        + b"\nendstream\nendobj\n%%EOF\n"
    )
    ml_res = file_ops.read_file(multilang_pdf, include_line_numbers=False, guard=g)
    assert ml_res["ok"] is True
    assert "Café München" in ml_res["content"] and "αβγδ" in ml_res["content"] and "𠀀" in ml_res["content"]

    # 2) Unread `pc_write_file` overwrite succeeds with snapshot + `unread_overwrite_warning` + one-step `undo`
    tmpl = ws_dir / "template.md"
    orig_tmpl = "# Handover Template\n\n" + ("- Pending item placeholder line\n" * 12)
    tmpl.write_text(orig_tmpl, encoding="utf-8")

    ov_res, ov_err = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_write_file",
            {"path": str(tmpl), "content": "# Completed Brief\nAll items reconciled.\n"},
        )
    )
    assert not ov_err and ov_res["ok"] is True
    assert ov_res.get("unread_overwrite_warning") is True
    assert ov_res.get("shrink_warning") is True
    assert ov_res.get("undo_snapshot")
    assert "undo" in str(ov_res.get("warning", "")).lower()

    undo_res, undo_err = asyncio.run(
        dispatcher.call_tool_raw("pc_manage_files", {"action": "undo", "path": str(tmpl)})
    )
    assert not undo_err and undo_res["ok"] is True
    assert tmpl.read_text(encoding="utf-8") == orig_tmpl

    # 3) `pc_get_status` exposes workspace `.agents/skills` summary list + `managed_skill_count`
    st_res, st_err = asyncio.run(dispatcher.call_tool_raw("pc_get_status", {}))
    assert not st_err and st_res["ok"] is True
    assert st_res.get("managed_skill_count", 0) >= 1
    ws_skills = st_res.get("workspace_skills") or []
    assert any(
        s.get("name") == "ledger-ops-brief" and "reimbursement" in str(s.get("description", "")).lower()
        for s in ws_skills
    )


def test_tier4_full_power_cross_directory_fs_search_patch_undo_and_policy_notice(tmp_path: Path) -> None:
    ws_dir = tmp_path / "ws_primary"
    ro_parent = tmp_path / "ro_parent_hub"
    ext_dir_d = tmp_path / "ext_drive_d_repo"
    ext_dir_e = tmp_path / "ext_drive_e_notes"
    st_dir = tmp_path / "state_fullpower"
    for d in (ws_dir, ro_parent, ext_dir_d, ext_dir_e, st_dir):
        d.mkdir(parents=True, exist_ok=True)

    (st_dir / "secrets").mkdir(parents=True, exist_ok=True)
    secret_file = st_dir / "secrets" / "auth.json"
    secret_file.write_text('{"password_hash": "topsecret"}', encoding="utf-8")

    ext_seed = ext_dir_d / "existing.py"
    ext_seed.write_text("def calc_value(x: int) -> int:\n    return x + 1\n", encoding="utf-8")
    ro_seed = ro_parent / "hub_note.py"
    ro_seed.write_text("HUB_VERSION = 1\n", encoding="utf-8")

    dispatcher = _make_dispatcher(ws_dir, st_dir, tier="tier3_workspace_dev")
    dispatcher.policy.persist_changes(
        workspace_roots=[ws_dir, ro_parent],
        readonly_workspace_roots=[ro_parent],
    )
    # Prime baseline epoch snapshot for session "http"
    dispatcher.list_tool_dicts(session_hint="http")

    # 1) In `tier3_workspace_dev` (`restrict_to_workspace=True`), external dirs and read-only parent writes are blocked
    for tool_nm, call_args in (
        ("pc_find_files", {"path": str(ext_dir_d)}),
        ("pc_search_code", {"pattern": "calc_value", "path": str(ext_dir_d)}),
        ("pc_read_file", {"path": str(ext_seed)}),
        ("pc_write_file", {"path": str(ext_dir_e / "blocked.txt"), "content": "nope\n"}),
        ("pc_patch_file", {"path": str(ext_seed), "old_text": "x + 1", "new_text": "x + 2"}),
    ):
        res_l3, _ = asyncio.run(dispatcher.call_tool_raw(tool_nm, call_args, session_hint="http"))
        assert res_l3["ok"] is False, f"{tool_nm} unexpectedly succeeded outside workspace in L3: {res_l3}"
        assert res_l3.get("blocked_by_guardrail") is True

    ro_w_l3, _ = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_write_file",
            {"path": str(ro_parent / "new_in_ro.py"), "content": "VAL = 2\n"},
            session_hint="http",
        )
    )
    assert ro_w_l3["ok"] is False and "ERR_READONLY_WORKSPACE" in str(ro_w_l3.get("error", ""))

    # 2) Hot-switch to `tier4_full_power` -> next tool call carries `_policy_change_notice` with `restrict_to_workspace=False`
    dispatcher.policy.persist_changes(tier_key="tier4_full_power")
    assert dispatcher.policy.restrict_to_workspace is False
    assert dispatcher.policy.guard is not None and dispatcher.policy.guard.restrict_to_workspace is False

    st_l4, st_err = asyncio.run(dispatcher.call_tool_raw("pc_get_status", {}, session_hint="http"))
    assert not st_err and st_l4["ok"] is True
    assert st_l4["restrict_to_workspace"] is False
    notice = st_l4.get("_policy_change_notice")
    assert isinstance(notice, dict)
    assert notice["tier"] == "tier4_full_power"
    assert notice["restrict_to_workspace"] is False

    # 3) All cross-directory file/search/patch/undo/trash operations outside `workspace_roots` succeed cleanly
    ff_res, ff_err = asyncio.run(dispatcher.call_tool_raw("pc_find_files", {"path": str(ext_dir_d)}, session_hint="http"))
    assert not ff_err and ff_res["ok"] is True
    assert any(it["name"] == "existing.py" for it in ff_res["entries"])

    sc_res, sc_err = asyncio.run(
        dispatcher.call_tool_raw("pc_search_code", {"pattern": "calc_value", "path": str(ext_dir_d)}, session_hint="http")
    )
    assert not sc_err and sc_res["ok"] is True and sc_res["count"] == 1

    rd_res, rd_err = asyncio.run(
        dispatcher.call_tool_raw("pc_read_file", {"path": str(ext_seed), "include_line_numbers": False}, session_hint="http")
    )
    assert not rd_err and rd_res["ok"] is True
    assert "return x + 1" in rd_res["content"]

    pt_res, pt_err = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_patch_file",
            {"path": str(ext_seed), "old_text": "return x + 1", "new_text": "return x + 42"},
            session_hint="http",
        )
    )
    assert not pt_err and pt_res["ok"] is True
    assert "return x + 42" in ext_seed.read_text(encoding="utf-8")

    ext_written = ext_dir_e / "sub" / "notes.py"
    wr_res, wr_err = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_write_file",
            {"path": str(ext_written), "content": " ANSWER = 99\n".lstrip()},
            session_hint="http",
        )
    )
    assert not wr_err and wr_res["ok"] is True
    assert ext_written.read_text(encoding="utf-8") == "ANSWER = 99\n"

    # Secondary directory explicitly marked read-only by the user remains write-protected even in `tier4_full_power`
    ro_w_l4, ro_err_l4 = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_write_file",
            {"path": str(ro_parent / "unblocked_in_l4.py"), "content": "OK = True\n"},
            session_hint="http",
        )
    )
    assert ro_err_l4 is True
    assert ro_w_l4["ok"] is False and "ERR_READONLY_WORKSPACE" in str(ro_w_l4.get("error", ""))

    # Undo & trash/restore work on external directories in `tier4_full_power`
    undo_res, u_err = asyncio.run(
        dispatcher.call_tool_raw("pc_manage_files", {"action": "undo", "path": str(ext_seed)}, session_hint="http")
    )
    assert not u_err and undo_res["ok"] is True
    assert "return x + 1" in ext_seed.read_text(encoding="utf-8")

    tr_res, tr_err = asyncio.run(
        dispatcher.call_tool_raw("pc_manage_files", {"action": "trash", "path": str(ext_written)}, session_hint="http")
    )
    assert not tr_err and tr_res["ok"] is True and not ext_written.exists()

    ls_res, ls_err = asyncio.run(
        dispatcher.call_tool_raw("pc_manage_files", {"action": "list"}, session_hint="http")
    )
    assert not ls_err and ls_res["ok"] is True
    assert any(Path(it["original_path"]).resolve() == ext_written.resolve() for it in ls_res["trash_items"])

    rest_res, rest_err = asyncio.run(
        dispatcher.call_tool_raw(
            "pc_manage_files",
            {"action": "restore", "trash_id": tr_res["trash_id"]},
            session_hint="http",
        )
    )
    assert not rest_err and rest_res["ok"] is True
    assert ext_written.read_text(encoding="utf-8") == "ANSWER = 99\n"

    # 4) Credential isolation (`secrets/auth.json`) still holds strictly in `tier4_full_power`
    sec_rd, _ = asyncio.run(dispatcher.call_tool_raw("pc_read_file", {"path": str(secret_file)}, session_hint="http"))
    assert sec_rd["ok"] is False and sec_rd.get("blocked_by_guardrail") is True


