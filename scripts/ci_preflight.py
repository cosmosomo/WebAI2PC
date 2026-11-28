"""Fast cross-platform compatibility, diff-scoped pytest preflight, and remote CI watcher."""
from __future__ import annotations

import argparse
import ast
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import tokenize
from typing import Iterable, List, Optional, Sequence, Set

REPO_ROOT = Path(__file__).resolve().parents[1]
SCAN_DIRS: Sequence[str] = ("src", "tests", "scripts")
DEFAULT_GITHUB_REPO = "cosmosomo/WebAI2PC"


def _is_win_guard_expr(node: ast.AST) -> bool:
    seg = ast.unparse(node).lower()
    return any(tok in seg for tok in ("win32", "'nt'", '"nt"', "windows"))


def _check_unguarded_creationflags(tree: ast.Module, rel_path: str) -> List[str]:
    """Catch nonzero `creationflags=` passed to `subprocess` outside a Windows platform guard."""
    issues: List[str] = []
    unsafe_consts: Set[str] = set()
    for stmt in tree.body:
        if (
            isinstance(stmt, ast.Assign)
            and isinstance(stmt.value, ast.Constant)
            and isinstance(stmt.value.value, int)
            and stmt.value.value != 0
        ):
            for target in stmt.targets:
                if isinstance(target, ast.Name) and any(k in target.id for k in ("WINDOW", "FLAG", "DETACH")):
                    unsafe_consts.add(target.id)

    def _always_exits(stmts: Sequence[ast.stmt]) -> bool:
        return any(
            isinstance(n, (ast.Return, ast.Raise)) or (isinstance(n, ast.Call) and "skip" in ast.unparse(n.func))
            for s in stmts
            for n in ast.walk(s)
        )

    def _visit(node: ast.AST, guarded: bool) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(k in node.name.lower() for k in ("win32", "windows")):
                guarded = True
            for dec in node.decorator_list:
                if _is_win_guard_expr(dec):
                    guarded = True
        if isinstance(node, ast.If):
            win_cond = _is_win_guard_expr(node.test)
            early_exit = _always_exits(node.body)
            for s in node.body:
                _visit(s, guarded or win_cond)
            for s in node.orelse:
                _visit(s, guarded or (win_cond and early_exit))
            return

        if isinstance(node, ast.Call):
            fn_str = ast.unparse(node.func)
            if any(fn_str.endswith(k) for k in ("Popen", "subprocess.run", "check_output", "check_call", "subprocess.call")):
                for kw in node.keywords:
                    if kw.arg == "creationflags" and not guarded:
                        val = kw.value
                        if isinstance(val, ast.IfExp) and _is_win_guard_expr(val.test):
                            continue
                        if isinstance(val, ast.Constant) and isinstance(val.value, int) and val.value != 0:
                            issues.append(
                                f"[POSIX-CREATIONFLAGS] `{rel_path}:{node.lineno}` passes nonzero `creationflags={val.value}` "
                                "without a `win32`/`os.name == 'nt'` guard (raises ValueError on Linux/macOS)"
                            )
                        elif isinstance(val, ast.Name) and val.id in unsafe_consts:
                            issues.append(
                                f"[POSIX-CREATIONFLAGS] `{rel_path}:{node.lineno}` passes unguarded Windows constant `{val.id}` "
                                "to `creationflags=` (use `0x08000000 if sys.platform == 'win32' else 0`)"
                            )
                        elif isinstance(val, ast.BinOp) and any(
                            isinstance(n, ast.Name) and n.id in unsafe_consts for n in ast.walk(val)
                        ):
                            issues.append(
                                f"[POSIX-CREATIONFLAGS] `{rel_path}:{node.lineno}` passes unguarded Windows flags `{ast.unparse(val)}` "
                                "to `creationflags=` (raises ValueError on Linux/macOS)"
                            )

        for child in ast.iter_child_nodes(node):
            _visit(child, guarded)
            if isinstance(child, ast.If) and _is_win_guard_expr(child.test) and _always_exits(child.body):
                guarded = True

    _visit(tree, False)
    return issues


def check_python_source_compat(source: str, rel_path: str) -> List[str]:
    """Check objective Python 3.11 syntax & cross-platform POSIX compatibility."""
    issues: List[str] = []
    try:
        tree = ast.parse(source, filename=rel_path)
    except SyntaxError as exc:
        tag = "[PY311-FSTRING]" if ("f-string" in str(exc.msg).lower() and "backslash" in str(exc.msg).lower()) else "[SYNTAX]"
        issues.append(f"{tag} `{rel_path}:{exc.lineno}` failed AST parse: {exc.msg}")
        return issues

    # 1) Top-level unguarded `import winreg` / `import msvcrt` crashes pytest collection on Linux/macOS.
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in ("winreg", "msvcrt") or alias.name.startswith(("winreg.", "msvcrt.")):
                    issues.append(
                        f"[POSIX-IMPORT] `{rel_path}:{node.lineno}` has top-level `import {alias.name}` outside a platform guard"
                    )
        elif isinstance(node, ast.ImportFrom) and (
            (node.module or "") in ("winreg", "msvcrt") or (node.module or "").startswith(("winreg.", "msvcrt."))
        ):
            issues.append(
                f"[POSIX-IMPORT] `{rel_path}:{node.lineno}` has top-level `from {node.module} import ...` outside a platform guard"
            )

    # 2) Unguarded nonzero `creationflags=` crashes Linux/macOS subprocess calls with `ValueError`.
    issues.extend(_check_unguarded_creationflags(tree, rel_path))

    # 3) Backslash inside `{...}` f-string expression raises compile-time SyntaxError on Python <3.12.
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
        brace_depths: List[int] = []
        for tok_type, tok_str, (start_row, _), _, _ in tokens:
            if hasattr(tokenize, "FSTRING_START") and tok_type == tokenize.FSTRING_START:
                brace_depths.append(0)
            elif hasattr(tokenize, "FSTRING_END") and tok_type == tokenize.FSTRING_END:
                if brace_depths:
                    brace_depths.pop()
            elif brace_depths:
                if tok_type == tokenize.OP and tok_str == "{":
                    brace_depths[-1] += 1
                elif tok_type == tokenize.OP and tok_str == "}":
                    brace_depths[-1] = max(0, brace_depths[-1] - 1)
                elif brace_depths[-1] > 0 and "\\" in tok_str:
                    issues.append(
                        f"[PY311-FSTRING] `{rel_path}:{start_row}` uses a backslash inside an f-string expression (SyntaxError on Python <3.12)"
                    )
                    break
    except tokenize.TokenError:
        pass

    return issues


def check_workflow_yaml_compat(yaml_text: str, rel_path: str) -> List[str]:
    """Catch bash `\\` line continuations inside cross-platform / Windows PowerShell workflow steps."""
    issues: List[str] = []
    if "windows" not in yaml_text.lower() and "matrix.os" not in yaml_text:
        return issues

    lines = yaml_text.splitlines()
    for idx, line in enumerate(lines, start=1):
        if re.search(r"\b(?:pytest|python)\b.*\\\s*$", line):
            window_slice = "\n".join(lines[max(0, idx - 8) : min(len(lines), idx + 4)])
            if "shell: bash" not in window_slice and "runner.os != 'Windows'" not in window_slice:
                issues.append(
                    f"[WORKFLOW-PWSH] `{rel_path}:{idx}` uses trailing `\\` line continuation without `shell: bash` (breaks windows-latest PowerShell)"
                )
    return issues


def select_impacted_test_files(changed_paths: Iterable[str], root: Path = REPO_ROOT) -> List[str]:
    """Map changed repo-relative file paths to fast, high-signal regression suites for pre-push gating."""
    selected: List[str] = []

    def _add(*rels: str) -> None:
        for r in rels:
            if (root / r).is_file() and r not in selected:
                selected.append(r)

    for raw in changed_paths:
        rel = raw.strip().replace("\\", "/").lstrip("./")
        if not rel:
            continue
        if rel.startswith("tests/test_") and rel.endswith(".py"):
            _add(rel)
            continue
        if rel.startswith("src/cosmos_mcp/studio/static/"):
            _add("tests/test_studio_ui_hygiene.py", "tests/test_conn_cfg_hardening.py")
        elif rel.startswith("src/cosmos_mcp/studio/"):
            _add("tests/test_conn_cfg_hardening.py", "tests/test_p0_gateway_stop_contract.py", "tests/test_studio_ui_hygiene.py")
        elif rel.startswith("src/cosmos_mcp/packs/browser"):
            _add("tests/test_conn_security_hardening.py")
        elif rel.startswith("src/cosmos_mcp/packs/"):
            _add("tests/test_p0_lifecycle_contract.py")
        elif rel.startswith("src/cosmos_mcp/core/"):
            _add("tests/test_p0_config_contract.py", "tests/test_dogma_core_fixes.py")
        elif rel.startswith("src/cosmos_mcp/launcher/"):
            _add("tests/test_p0_gateway_stop_contract.py", "tests/test_conn_cfg_hardening.py")
        elif rel.startswith("src/cosmos_mcp/protocol/"):
            _add("tests/test_s3_protocol.py", "tests/test_multigw_oauth_protocol.py", "tests/test_project_rules_injection.py")
        elif rel.startswith("src/cosmos_mcp/capabilities/"):
            _add("tests/test_s7_skills_deep_merge.py", "tests/test_dogma_core_fixes.py")
        elif (
            rel.startswith(("docs/", "host_skills/", "assets/", "scripts/"))
            or rel in ("README.md", "README_EN.md", "PRIVACY.md", "PRIVACY_EN.md", "AGENTS.md")
        ):
            _add("tests/test_ai_accessible_tutorials.py", "tests/test_release_security_gates.py")

    # Keep pre-push fast (<35s): cap at 6 highest-priority suites when sweeping dozens of files
    return selected[:6]


def _git_changed_files(root: Path, from_sha: str, to_sha: str) -> List[str]:
    null_sha = "0" * 40
    eff_from = from_sha if (from_sha and from_sha != null_sha) else f"{to_sha}~1"
    proc = subprocess.run(
        ["git", "diff", "--name-only", f"{eff_from}..{to_sha}"],
        cwd=str(root),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=0x08000000 if os.name == "nt" else 0,
    )
    if proc.returncode != 0:
        return []
    return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]


def _iter_repo_python_files(root: Path) -> Iterable[Path]:
    skip_dirs = {"__pycache__", ".git", "build", "dist", ".venv", "venv", ".pytest_cache", ".ruff_cache"}
    for sub in SCAN_DIRS:
        base = root / sub
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            if any(part in skip_dirs or part.startswith(".") for part in path.relative_to(root).parts):
                continue
            yield path


def run_preflight(
    root: Path = REPO_ROOT,
    *,
    run_release_gate: bool = True,
    changed_files: Optional[Sequence[str]] = None,
    pytest_timeout_sec: int = 42,
) -> List[str]:
    issues: List[str] = []
    for py_file in _iter_repo_python_files(root):
        rel = py_file.relative_to(root).as_posix()
        src = py_file.read_text(encoding="utf-8-sig")
        issues.extend(check_python_source_compat(src, rel))

    wf_dir = root / ".github" / "workflows"
    if wf_dir.is_dir():
        for wf_file in sorted(wf_dir.glob("*.yml")):
            rel_wf = wf_file.relative_to(root).as_posix()
            issues.extend(check_workflow_yaml_compat(wf_file.read_text(encoding="utf-8"), rel_wf))

    if issues:
        return issues

    if run_release_gate:
        build_script = root / "scripts" / "build_release.py"
        if build_script.is_file():
            proc = subprocess.run(
                [sys.executable, "-B", str(build_script), "--check"],
                cwd=str(root),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=0x08000000 if os.name == "nt" else 0,
            )
            if proc.returncode != 0:
                combined = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
                issues.append(f"[RELEASE-GATE] `scripts/build_release.py --check` failed:\n{combined}")
                return issues

    if changed_files:
        suites = select_impacted_test_files(changed_files, root=root)
        if suites:
            env = dict(os.environ)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            env["PYTHONUTF8"] = "1"
            env["LOCALPC_NO_BROWSER"] = "1"
            env["COSMOS_NO_TRAY"] = "1"
            try:
                proc_pt = subprocess.run(
                    [sys.executable, "-B", "-m", "pytest", "-p", "no:cacheprovider", "-q", "--maxfail=2", *suites],
                    cwd=str(root),
                    env=env,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=max(10, int(pytest_timeout_sec)),
                    creationflags=0x08000000 if os.name == "nt" else 0,
                )
                if proc_pt.returncode != 0:
                    tail = "\n".join(((proc_pt.stdout or "") + "\n" + (proc_pt.stderr or "")).strip().splitlines()[-35:])
                    issues.append(
                        f"[IMPACTED-PYTEST] Regression failed in `{' '.join(suites)}`:\n{tail}\n"
                        f"[AI ACTION REQUIRED]: Fix the root cause above (do not weaken security/WCAG assertions), "
                        f"verify `python -B -m pytest {' '.join(suites)}`, then push again."
                    )
            except subprocess.TimeoutExpired:
                sys.stderr.write(
                    f"[PREFLIGHT-NOTE] Impacted pytest exceeded {pytest_timeout_sec}s local budget; deferring full run to GitHub CI Gate.\n"
                )
    return issues


def watch_remote_ci(sha_prefix: str = "", repo: str = DEFAULT_GITHUB_REPO, wait_sec: int = 35) -> int:
    """Inspect or poll the latest GitHub Actions CI run and print actionable failure excerpts for AI/humans."""
    gh_bin = shutil.which("gh")
    if not gh_bin:
        sys.stderr.write("[WATCH-CI] GitHub CLI (`gh`) not found on PATH.\n")
        return 2
    flags = 0x08000000 if os.name == "nt" else 0
    deadline = time.monotonic() + max(0, int(wait_sec))
    target = (sha_prefix or "").strip().lower()

    while True:
        res = subprocess.run(
            [gh_bin, "api", f"repos/{repo}/actions/runs?per_page=8"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=flags,
        )
        if res.returncode != 0:
            sys.stderr.write(f"[WATCH-CI] `gh api` error: {res.stderr}\n")
            return 2
        runs = json.loads(res.stdout).get("workflow_runs") or []
        matched = next((r for r in runs if not target or str(r.get("head_sha") or "").lower().startswith(target)), None)
        if matched is None:
            if time.monotonic() >= deadline:
                sys.stderr.write(f"[WATCH-CI] No GitHub Actions run found for sha `{target}` yet.\n")
                return 1
            time.sleep(4.0)
            continue

        run_id = matched["id"]
        status = matched.get("status")
        conc = matched.get("conclusion")
        head_sha = str(matched.get("head_sha") or "")[:7]
        branch = matched.get("head_branch")
        url = matched.get("html_url")
        jobs_res = subprocess.run(
            [gh_bin, "api", f"repos/{repo}/actions/runs/{run_id}/jobs"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=flags,
        )
        jobs = (json.loads(jobs_res.stdout).get("jobs") or []) if jobs_res.returncode == 0 else []
        if status == "completed":
            print(f"[CI {str(conc).upper()}] Run #{matched.get('run_number')} ({head_sha} on {branch}): {url}")
            for j in jobs:
                print(f"  - {j['name']}: {j['conclusion']}")
            if conc == "success":
                return 0
            for fj in [j for j in jobs if j.get("conclusion") == "failure"][:2]:
                log_r = subprocess.run(
                    [gh_bin, "api", f"repos/{repo}/actions/jobs/{fj['id']}/logs"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    creationflags=flags,
                )
                err_lines = [
                    ln for ln in (log_r.stdout or "").splitlines()
                    if any(k in ln for k in ("FAILED ", "AssertionError", "E   ", "ValueError:", "SyntaxError:"))
                ]
                print(f"\n--- Failure excerpt ({fj['name']}) ---")
                for el in err_lines[-20:]:
                    print(" ", el[-160:])
            return 1

        if time.monotonic() >= deadline:
            done_n = sum(1 for j in jobs if j.get("status") == "completed")
            print(
                f"[CI IN_PROGRESS] Run #{matched.get('run_number')} ({head_sha} on {branch}, {done_n}/{len(jobs)} jobs done): {url}\n"
                f"Re-run `python -B scripts/ci_preflight.py --watch-ci {head_sha}` in ~35s until status == completed/success."
            )
            return 3
        time.sleep(6.0)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run cross-platform preflight, diff-scoped pytest, or watch remote CI.")
    parser.add_argument("--skip-release-check", action="store_true", help="Skip `build_release.py --check`.")
    parser.add_argument("--changed-from", default="", help="Base commit SHA for impacted pytest selection.")
    parser.add_argument("--changed-to", default="", help="Target commit SHA for impacted pytest selection.")
    parser.add_argument("--watch-ci", nargs="?", const="LATEST", default=None, help="Poll latest GitHub Actions CI run (optional SHA prefix).")
    parser.add_argument("--wait-sec", type=int, default=35, help="Max seconds to poll in `--watch-ci` mode (default 35s).")
    args = parser.parse_args(argv)

    if args.watch_ci is not None:
        sha_arg = "" if args.watch_ci == "LATEST" else str(args.watch_ci)
        return watch_remote_ci(sha_arg, wait_sec=args.wait_sec)

    changed: List[str] = []
    if args.changed_to:
        changed = _git_changed_files(REPO_ROOT, args.changed_from, args.changed_to)

    issues = run_preflight(
        REPO_ROOT,
        run_release_gate=not args.skip_release_check,
        changed_files=changed,
    )
    if issues:
        sys.stderr.write("\n=== [AI-PREPUSH-BLOCKED] CI PREFLIGHT FAILED ===\n")
        for item in issues:
            sys.stderr.write(f"  - {item}\n")
        sys.stderr.write("================================================\n")
        return 1
    suite_msg = ""
    if changed:
        ran = select_impacted_test_files(changed, root=REPO_ROOT)
        if ran:
            suite_msg = f" + {len(ran)} impacted pytest suite(s) ({', '.join(ran)})"
    print(f"[PREFLIGHT PASSED] Python 3.11/POSIX compatibility, workflow syntax, release hygiene{suite_msg} verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
