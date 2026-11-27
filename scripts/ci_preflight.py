"""Fast cross-platform & Python 3.11 compatibility + release hygiene preflight gate."""
from __future__ import annotations

import argparse
import ast
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tokenize
from typing import Iterable, List, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
SCAN_DIRS: Sequence[str] = ("src", "tests", "scripts")


def check_python_source_compat(source: str, rel_path: str) -> List[str]:
    """Check objective Python 3.11 syntax & cross-platform import compatibility."""
    issues: List[str] = []
    try:
        tree = ast.parse(source, filename=rel_path)
    except SyntaxError as exc:
        tag = "[PY311-FSTRING]" if ("f-string" in str(exc.msg).lower() and "backslash" in str(exc.msg).lower()) else "[SYNTAX]"
        issues.append(f"{tag} `{rel_path}:{exc.lineno}` failed AST parse: {exc.msg}")
        return issues

    # 1) Top-level unguarded `import winreg` / `from winreg import ...` crashes pytest collection on Linux/macOS.
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "winreg" or alias.name.startswith("winreg."):
                    issues.append(
                        f"[POSIX-IMPORT] `{rel_path}:{node.lineno}` has top-level `import winreg` outside a platform guard"
                    )
        elif isinstance(node, ast.ImportFrom) and (node.module == "winreg" or (node.module or "").startswith("winreg.")):
            issues.append(
                f"[POSIX-IMPORT] `{rel_path}:{node.lineno}` has top-level `from winreg import ...` outside a platform guard"
            )

    # 2) Backslash inside `{...}` f-string expression is valid on Python 3.12+ (PEP 701)
    #    but raises compile-time SyntaxError on Python 3.11 regardless of runtime platform branches.
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
        # Single-line or multi-line pytest/python invocation using bash trailing `\` breaks Windows PowerShell
        if re.search(r"\b(?:pytest|python)\b.*\\\s*$", line):
            window_slice = "\n".join(lines[max(0, idx - 8) : min(len(lines), idx + 4)])
            if "shell: bash" not in window_slice and "runner.os != 'Windows'" not in window_slice:
                issues.append(
                    f"[WORKFLOW-PWSH] `{rel_path}:{idx}` uses trailing `\\` line continuation without `shell: bash` (breaks windows-latest PowerShell)"
                )
    return issues


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


def run_preflight(root: Path = REPO_ROOT, *, run_release_gate: bool = True) -> List[str]:
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run fast cross-platform & release hygiene preflight checks.")
    parser.add_argument("--skip-release-check", action="store_true", help="Skip `build_release.py --check`.")
    args = parser.parse_args(argv)

    issues = run_preflight(REPO_ROOT, run_release_gate=not args.skip_release_check)
    if issues:
        sys.stderr.write("\n=== CI PREFLIGHT FAILED ===\n")
        for item in issues:
            sys.stderr.write(f"  - {item}\n")
        sys.stderr.write("===========================\n")
        return 1
    print("[PREFLIGHT PASSED] Python 3.11/POSIX compatibility, workflow shell syntax, and release hygiene verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
