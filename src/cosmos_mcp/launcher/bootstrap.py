"""Pure-stdlib cold-start runtime bootstrapper for Cosmos MCP (`Python 3.10~3.14`).

Enforces:
- Zero third-party imports (100% bare-machine Python >=3.9 compatible).
- Python 3.10~3.14 interpreter discovery (filtering WindowsApps 0-byte stubs).
- Minimum version validation (`mcp>=1.30.0`, `pydantic>=2.11.0`) in `check_runtime_deps_ready`.
- Self-contained portable source sync (`src/cosmos_mcp` + `host_skills` -> `<state_root>/app_src`)
  and mandatory `<state_root>/.venv` creation (`--system-site-packages` fast-path + `cosmos_mcp_src.pth`)
  so autostart, shortcuts, and desktop `stdio` bindings survive moving/deleting the extracted ZIP directory.
- Local offline wheelhouse (`<repo>/wheels` or `COSMOS_WHEELHOUSE`) support and graceful degradation
  from optional `docs` (`Pillow`, `pypdf`, `openpyxl`) to core runtime dependencies if optional wheels fail.
"""
from __future__ import annotations

import importlib.resources
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import Dict, List, Optional, Sequence, Tuple
import urllib.request

from cosmos_mcp.core.fs_tx import safe_trash_file
from cosmos_mcp.core.net_power import detect_configured_proxy
from cosmos_mcp.core.proc import CREATE_NO_WINDOW, resolve_console_python

SUPPORTED_RUNTIME_MIN: Tuple[int, int] = (3, 10)
SUPPORTED_RUNTIME_MAX: Tuple[int, int] = (3, 14)

PRIMARY_PYPI_INDEX = "https://pypi.org/simple"
PRIMARY_PYPI_TIMEOUT_SEC = 18

FALLBACK_TSINGHUA_INDEX = "https://pypi.tuna.tsinghua.edu.cn/simple"
FALLBACK_TSINGHUA_HOST = "pypi.tuna.tsinghua.edu.cn"
FALLBACK_MIRROR_TIMEOUT_SEC = 120

GET_PIP_URLS: Tuple[str, ...] = (
    "https://bootstrap.pypa.io/get-pip.py",
    "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/packages/get-pip.py",
)

MIN_RUNTIME_PACKAGE_VERSIONS: Dict[str, Tuple[int, int, int]] = {
    "mcp": (1, 30, 0),
    "pydantic": (2, 11, 0),
}

STRICT_CORE_IMPORTS: Tuple[str, ...] = (
    "mcp",
    "starlette",
    "uvicorn",
    "websockets",
    "pydantic",
    "multipart",
    "cryptography",
)

OPTIONAL_DOCS_IMPORTS: Tuple[str, ...] = (
    "PIL",
    "pypdf",
    "openpyxl",
)

# Full default bootstrap target imports (`check_runtime_deps_ready` checks `STRICT_CORE_IMPORTS` so core starts even if docs degrade)
CORE_RUNTIME_IMPORTS: Tuple[str, ...] = STRICT_CORE_IMPORTS + OPTIONAL_DOCS_IMPORTS

STRICT_CORE_PIP_SPECS: Tuple[str, ...] = (
    "mcp>=1.30.0,<2.0.0",
    "starlette>=0.47.2; python_version < '3.14'",
    "starlette>=1.3.1; python_version >= '3.14'",
    "uvicorn>=0.35.0",
    "h11>=0.16.0",
    "websockets>=15.0.1",
    "pydantic>=2.11.0,<3.0.0; python_version < '3.14'",
    "pydantic>=2.12.0,<3.0.0; python_version >= '3.14'",
    "python-multipart>=0.0.20",
    "cryptography>=46.0.7",
)

# Keep literal `Pillow>=10.0.0` and `pypdf>=4.0.0` tokens compatible with `tests/test_s4_studio_launcher.py`
OPTIONAL_DOCS_PIP_SPECS: Tuple[str, ...] = (
    "Pillow>=10.0.0",
    "pypdf>=4.0.0",
    "openpyxl>=3.1.5",
)

CORE_RUNTIME_PIP_SPECS: Tuple[str, ...] = STRICT_CORE_PIP_SPECS + OPTIONAL_DOCS_PIP_SPECS

_SYNC_SKIP_DIRS: frozenset[str] = frozenset(
    {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".undo_history", ".git"}
)
_SYNC_SKIP_SUFFIXES: Tuple[str, ...] = (".pyc", ".pyo", ".bak")


def _popen_flags() -> int:
    return CREATE_NO_WINDOW if sys.platform == "win32" else 0


def resolve_windows_system_exe(exe_name: str) -> str:
    """Resolve `cmd.exe` / `powershell.exe` deterministically via `SystemRoot` even when `.venv` strips global PATH."""
    clean = str(exe_name or "").strip()
    if not clean:
        return ""
    try:
        found = shutil.which(clean) if (os.name == "nt" or sys.platform != "win32") else None
    except Exception:
        found = None
    if found and Path(found).is_file():
        return str(Path(found).resolve())
    if sys.platform != "win32":
        return clean
    low = clean.lower()
    if not low.endswith(".exe"):
        low_exe = f"{low}.exe"
    else:
        low_exe = low
    sys_root = Path(os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows")
    if low_exe == "cmd.exe":
        comspec = (os.environ.get("ComSpec") or os.environ.get("COMSPEC") or "").strip()
        if comspec and Path(comspec).is_file():
            return str(Path(comspec).resolve())
        cand = sys_root / "System32" / "cmd.exe"
        if cand.is_file():
            return str(cand)
    elif low_exe == "powershell.exe":
        cand = sys_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        if cand.is_file():
            return str(cand)
    else:
        for sub in (sys_root / "System32" / low_exe, sys_root / "System32" / "OpenSSH" / low_exe):
            if sub.is_file():
                return str(sub)
    return clean


def _clean_subproc_env(base_env: Optional[Dict[str, str]] = None, *, strip_proxy: bool = False) -> Dict[str, str]:
    env = dict(base_env if base_env is not None else os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONUTF8"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    if sys.platform == "win32":
        sys_root = Path(env.get("SystemRoot") or env.get("WINDIR") or r"C:\Windows")
        env.setdefault("SystemRoot", str(sys_root))
        cmd_abs = sys_root / "System32" / "cmd.exe"
        if cmd_abs.is_file():
            env.setdefault("ComSpec", str(cmd_abs))
        cur_path = env.get("PATH") or env.get("Path") or ""
        cur_low = {p.strip().lower().rstrip("\\/") for p in cur_path.split(os.pathsep) if p.strip()}
        extra_win_dirs = [
            sys_root / "System32",
            sys_root,
            sys_root / "System32" / "WindowsPowerShell" / "v1.0",
            sys_root / "System32" / "OpenSSH",
        ]
        appended = [str(d) for d in extra_win_dirs if d.is_dir() and str(d).lower().rstrip("\\/") not in cur_low]
        if appended:
            env["PATH"] = os.pathsep.join(([cur_path] if cur_path else []) + appended)
    if strip_proxy:
        for k in list(env.keys()):
            if k.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
                env.pop(k, None)
    else:
        proxy = detect_configured_proxy()
        if proxy and not env.get("HTTPS_PROXY") and not env.get("https_proxy"):
            env["HTTPS_PROXY"] = proxy
            env["HTTP_PROXY"] = proxy
    return env


def is_windows_store_stub(exe_path: str | Path) -> bool:
    """Return True if `exe_path` points to a WindowsApps Store alias or reparse stub."""
    p_str = str(exe_path or "").strip()
    if not p_str:
        return True
    for cand in (p_str, os.path.normpath(p_str)):
        norm = cand.replace("/", "\\").lower()
        if "\\microsoft\\windowsapps\\" in norm or norm.endswith("\\microsoft\\windowsapps"):
            return True
    return False


def ensure_embed_pth_site_enabled(
    embed_dir: Path,
    *,
    extra_entries: Sequence[str] = ("Lib/site-packages", "../src", "../app_src"),
) -> List[Path]:
    """Enable `import site` and ensure package search paths in `python*._pth` inside `embed_dir`."""
    updated: List[Path] = []
    if not embed_dir.is_dir():
        return updated
    try:
        (embed_dir / "Lib" / "site-packages").mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    for pth_fp in sorted(embed_dir.glob("python*._pth")):
        if not pth_fp.is_file():
            continue
        try:
            raw_txt = pth_fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        path_lines: List[str] = []
        seen_norm: set[str] = set()
        for raw_ln in raw_txt.splitlines():
            s_ln = raw_ln.strip()
            if not s_ln:
                continue
            low = s_ln.lower()
            if re.fullmatch(r"#\s*import\s+site", low) or low == "import site":
                continue
            if s_ln.startswith("#"):
                path_lines.append(raw_ln)
                continue
            nk = s_ln.replace("\\", "/").rstrip("/").lower()
            if nk not in seen_norm:
                seen_norm.add(nk)
                path_lines.append(s_ln)
        for extra in extra_entries:
            ex_s = str(extra or "").strip()
            if not ex_s:
                continue
            nk = ex_s.replace("\\", "/").rstrip("/").lower()
            if nk not in seen_norm:
                seen_norm.add(nk)
                path_lines.append(ex_s)
        path_lines.append("import site")
        eol = "\r\n" if ("\r\n" in raw_txt or sys.platform == "win32") else "\n"
        new_txt = eol.join(path_lines) + eol
        if new_txt != raw_txt:
            try:
                atomic_write_text(pth_fp, new_txt)
                updated.append(pth_fp)
            except OSError:
                continue
    return updated


def find_embedded_python_exe(
    repo_root: Optional[Path] = None,
    state_root: Optional[Path] = None,
) -> Optional[Path]:
    """Locate bundled `python-embed/python.exe` (or `python-embed/bin/python3`) if present."""
    search_bases: List[Path] = []
    if repo_root is not None:
        search_bases.append(Path(repo_root))
    detected_repo = find_repo_root()
    if detected_repo is not None:
        search_bases.append(detected_repo)
    src_dir = find_repo_src_dir()
    if src_dir is not None:
        search_bases.append(src_dir.parent)
    if state_root is not None:
        search_bases.append(Path(state_root))

    rel_candidates = (
        (("python-embed", "python.exe"), ("python-embed", "bin", "python3"), ("python-embed", "bin", "python"))
        if sys.platform == "win32"
        else (("python-embed", "bin", "python3"), ("python-embed", "bin", "python"), ("python-embed", "python.exe"))
    )
    seen: set[str] = set()
    for base in search_bases:
        for rel_parts in rel_candidates:
            cand = base.joinpath(*rel_parts)
            key = os.path.normcase(str(cand))
            if key in seen:
                continue
            seen.add(key)
            try:
                if cand.is_file() and not is_windows_store_stub(cand):
                    return cand.resolve()
            except OSError:
                continue
    return None


def _iter_all_path_executables(names: Sequence[str], *, env_path: Optional[str] = None) -> List[str]:
    """Scan all `PATH` directories for `names`, skipping `WindowsApps` stubs so later valid entries are found."""
    raw_path = env_path if env_path is not None else os.environ.get("PATH", "")
    if not raw_path:
        return []
    out: List[str] = []
    seen: set[str] = set()
    is_win = sys.platform == "win32"
    for raw_dir in raw_path.split(os.pathsep):
        d_str = raw_dir.strip().strip('"')
        if not d_str:
            continue
        d_path = Path(d_str)
        if is_windows_store_stub(d_path / "python.exe"):
            continue
        for nm in names:
            file_cands = [d_path / f"{nm}.exe", d_path / nm] if (is_win and not nm.lower().endswith(".exe")) else [d_path / nm]
            for fc in file_cands:
                try:
                    if not fc.is_file() or is_windows_store_stub(fc):
                        continue
                    if not is_win and not os.access(fc, os.X_OK):
                        continue
                    fc_s = str(fc)
                    key = fc_s.lower() if is_win else fc_s
                    if key not in seen:
                        seen.add(key)
                        out.append(fc_s)
                except OSError:
                    continue
    return out


def probe_python_version(cmd: Sequence[str], timeout_sec: float = 6.0) -> Optional[Tuple[str, Tuple[int, int, int]]]:
    """Probe `cmd` and return `(resolved_executable, (major, minor, micro))` if healthy."""
    if not cmd:
        return None
    first = str(cmd[0])
    if os.path.isabs(first) and is_windows_store_stub(first):
        return None
    code = (
        "import json, sys; "
        "print(json.dumps({'exe': sys.executable, 'ver': list(sys.version_info[:3])}))"
    )
    try:
        proc = subprocess.run(
            [*cmd, "-B", "-c", code],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
            env=_clean_subproc_env(),
            creationflags=_popen_flags(),
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    for line in reversed((proc.stdout or "").splitlines()):
        line_s = line.strip()
        if line_s.startswith("{") and line_s.endswith("}"):
            try:
                doc = json.loads(line_s)
                exe = str(doc.get("exe") or "").strip()
                ver = doc.get("ver") or []
                if exe and len(ver) >= 3 and not is_windows_store_stub(exe):
                    return (exe, (int(ver[0]), int(ver[1]), int(ver[2])))
            except Exception:
                continue
    return None


def _candidate_python_commands() -> List[List[str]]:
    candidates: List[List[str]] = []
    seen: set[str] = set()

    def _add(cmd: List[str]) -> None:
        if not cmd or not cmd[0]:
            return
        if os.path.isabs(cmd[0]) and is_windows_store_stub(cmd[0]):
            return
        key = " ".join(cmd).lower() if sys.platform == "win32" else " ".join(cmd)
        if key not in seen:
            seen.add(key)
            candidates.append(cmd)

    embed_exe = find_embedded_python_exe()
    if embed_exe is not None:
        ensure_embed_pth_site_enabled(embed_exe.parent)
        _add([str(embed_exe)])

    cur_exe = resolve_console_python()
    if cur_exe and not is_windows_store_stub(cur_exe):
        _add([cur_exe])

    if sys.platform == "win32":
        for py_launcher in _iter_all_path_executables(("py",)):
            for minor in (13, 12, 11, 10, 14):
                _add([py_launcher, f"-3.{minor}"])
            _add([py_launcher, "-3"])

        for w in _iter_all_path_executables(("python3", "python")):
            _add([w])

        local_app = os.environ.get("LOCALAPPDATA", "").strip()
        app_data = os.environ.get("APPDATA", "").strip()
        user_prof = os.environ.get("USERPROFILE", "").strip()
        prog_files = os.environ.get("ProgramFiles", r"C:\Program Files").strip()
        prog_files_x86 = os.environ.get("ProgramFiles(x86)", "").strip()
        prog_data = os.environ.get("ProgramData", r"C:\ProgramData").strip()

        for minor in (13, 12, 11, 10, 14):
            if local_app:
                p1 = Path(local_app) / "Programs" / "Python" / f"Python3{minor}" / "python.exe"
                if p1.is_file():
                    _add([str(p1)])
            if prog_files:
                p2 = Path(prog_files) / f"Python3{minor}" / "python.exe"
                if p2.is_file():
                    _add([str(p2)])
            if prog_files_x86:
                p2x = Path(prog_files_x86) / f"Python3{minor}" / "python.exe"
                if p2x.is_file():
                    _add([str(p2x)])
            p3 = Path(f"C:\\Python3{minor}\\python.exe")
            if p3.is_file():
                _add([str(p3)])

        for py_base in (
            Path(local_app) / "Programs" / "Python" if local_app else None,
            Path(prog_files) if prog_files else None,
            Path(prog_files_x86) if prog_files_x86 else None,
        ):
            if py_base is not None and py_base.is_dir():
                for py_cand in sorted(py_base.glob("Python3*/python.exe"), reverse=True):
                    if py_cand.is_file():
                        _add([str(py_cand)])

        conda_roots: List[Path] = []
        for base_env in (user_prof, local_app, prog_data):
            if base_env:
                for dist_name in ("anaconda3", "miniconda3", "miniforge3"):
                    conda_roots.append(Path(base_env) / dist_name / "python.exe")
        for cp in conda_roots:
            if cp.is_file():
                _add([str(cp)])

        for uv_base in (
            Path(app_data) / "uv" / "python" if app_data else None,
            Path(local_app) / "uv" / "python" if local_app else None,
        ):
            if uv_base is not None and uv_base.is_dir():
                for uv_py in sorted(uv_base.glob("*/python.exe"), reverse=True):
                    if uv_py.is_file():
                        _add([str(uv_py)])
    else:
        for minor in (13, 12, 11, 10, 14):
            for prefix_dir in ("", "/opt/homebrew/bin/", "/usr/local/bin/", "/usr/bin/"):
                name = f"{prefix_dir}python3.{minor}"
                w = name if (prefix_dir and os.path.isfile(name) and os.access(name, os.X_OK)) else shutil.which(name)
                if w:
                    _add([w])
        for fixed_posix in ("/opt/homebrew/bin/python3", "/usr/local/bin/python3"):
            if os.path.isfile(fixed_posix) and os.access(fixed_posix, os.X_OK):
                _add([fixed_posix])

        home_dir = Path(os.environ.get("HOME") or str(Path.home())).expanduser()
        for conda_posix in (
            home_dir / "anaconda3" / "bin" / "python3",
            home_dir / "miniconda3" / "bin" / "python3",
            home_dir / "miniforge3" / "bin" / "python3",
            Path("/opt/anaconda3/bin/python3"),
            Path("/opt/miniconda3/bin/python3"),
        ):
            if conda_posix.is_file() and os.access(conda_posix, os.X_OK):
                _add([str(conda_posix)])

        uv_posix_base = home_dir / ".local" / "share" / "uv" / "python"
        if uv_posix_base.is_dir():
            for uv_py in sorted(uv_posix_base.glob("*/bin/python3"), reverse=True):
                if uv_py.is_file() and os.access(uv_py, os.X_OK):
                    _add([str(uv_py)])

        for w in _iter_all_path_executables(("python3", "python")):
            _add([w])
    return candidates


def find_suitable_python(
    preferred_exe: Optional[str | Path] = None,
    *,
    min_version: Tuple[int, int] = SUPPORTED_RUNTIME_MIN,
    max_version: Tuple[int, int] = SUPPORTED_RUNTIME_MAX,
) -> Optional[Tuple[str, Tuple[int, int, int]]]:
    """Locate a healthy Python 3.10~3.14 interpreter on the host."""
    if preferred_exe:
        probed = probe_python_version([str(preferred_exe)])
        if probed is not None:
            _, ver = probed
            if min_version <= (ver[0], ver[1]) <= max_version:
                return probed
    else:
        embed_exe = find_embedded_python_exe()
        if embed_exe is not None:
            ensure_embed_pth_site_enabled(embed_exe.parent)
            probed_emb = probe_python_version([str(embed_exe)])
            if probed_emb is not None:
                _, emb_ver = probed_emb
                if min_version <= (emb_ver[0], emb_ver[1]) <= max_version:
                    return probed_emb
        cur_v = (int(sys.version_info[0]), int(sys.version_info[1]), int(sys.version_info[2]))
        if min_version <= (cur_v[0], cur_v[1]) <= max_version:
            cur_console = resolve_console_python(sys.executable)
            cand_self = cur_console if (cur_console and Path(cur_console).is_file()) else sys.executable
            if cand_self and Path(cand_self).is_file() and not is_windows_store_stub(cand_self):
                return (str(cand_self), cur_v)

    for cmd in _candidate_python_commands():
        probed = probe_python_version(cmd)
        if probed is None:
            continue
        exe, ver = probed
        if min_version <= (ver[0], ver[1]) <= max_version:
            return (exe, ver)
    return None


def venv_python_path(venv_dir: Path, *, windowless: bool = False) -> Path:
    if sys.platform == "win32":
        name = "pythonw.exe" if windowless else "python.exe"
        cand = venv_dir / "Scripts" / name
        if windowless and not cand.is_file():
            return venv_dir / "Scripts" / "python.exe"
        return cand
    return venv_dir / "bin" / "python"


def resolve_windowless_python(python_exe: str | Path) -> str:
    """Resolve `pythonw.exe` sibling on Windows to avoid console window flashes; no-op on POSIX."""
    p = Path(str(python_exe))
    if sys.platform != "win32":
        return str(p)
    if p.name.lower() == "pythonw.exe" and p.is_file():
        return str(p)
    cand = p.with_name("pythonw.exe")
    if cand.is_file():
        return str(cand)
    return str(p)


def find_repo_src_dir() -> Optional[Path]:
    """If running from an uninstalled source tree (`src/cosmos_mcp/...` or `app_src/cosmos_mcp/...`), return parent of `cosmos_mcp`."""
    here = Path(__file__).resolve()
    for idx in (2, 3):
        if len(here.parents) > idx:
            src_cand = here.parents[idx]
            if src_cand.name.lower() in ("site-packages", "dist-packages"):
                return None
            if (src_cand / "cosmos_mcp" / "__init__.py").is_file():
                return src_cand
    return None


def find_repo_root() -> Optional[Path]:
    src_dir = find_repo_src_dir()
    if src_dir is not None:
        if (src_dir.parent / "pyproject.toml").is_file() or (src_dir.parent / "host_skills").is_dir():
            return src_dir.parent
    return None


def find_wheelhouse_dir(repo_root: Optional[Path] = None) -> Optional[Path]:
    """Locate local offline wheelhouse from `COSMOS_WHEELHOUSE` or `<repo>/wheels`."""
    env_wh = (os.environ.get("COSMOS_WHEELHOUSE") or "").strip()
    candidates: List[Path] = []
    if env_wh:
        candidates.append(Path(os.path.expandvars(env_wh)).expanduser())
    eff_repo = repo_root or find_repo_root()
    if eff_repo is not None:
        candidates.append(eff_repo / "wheels")
    src_dir = find_repo_src_dir()
    if src_dir is not None:
        candidates.append(src_dir.parent / "wheels")
    for cand in candidates:
        try:
            if cand.is_dir() and any(cand.glob("*.whl")):
                return cand.resolve()
        except OSError:
            continue
    return None


def _sync_clean_dir_tree(src_tree: Path, dst_tree: Path, *, undo_dir: Path) -> None:
    """Incrementally sync `src_tree` -> `dst_tree` excluding caches and retiring stale files via `safe_trash_file`."""
    src_resolved = src_tree.resolve()
    dst_resolved = dst_tree.resolve()
    if os.path.normcase(str(src_resolved)) == os.path.normcase(str(dst_resolved)):
        return

    expected_rel_files: set[str] = set()
    for root, dirs, files in os.walk(src_resolved):
        dirs[:] = [d for d in sorted(dirs) if d not in _SYNC_SKIP_DIRS and not d.lower().endswith(".egg-info")]
        rel_dir = Path(root).relative_to(src_resolved)
        target_dir = dst_resolved / rel_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        for fname in sorted(files):
            if any(fname.lower().endswith(sfx) for sfx in _SYNC_SKIP_SUFFIXES):
                continue
            s_fp = Path(root) / fname
            d_fp = target_dir / fname
            rel_key = os.path.normcase((rel_dir / fname).as_posix())
            expected_rel_files.add(rel_key)
            need_copy = True
            if d_fp.is_file():
                try:
                    s_st = s_fp.stat()
                    d_st = d_fp.stat()
                    if s_st.st_size == d_st.st_size and abs(s_st.st_mtime - d_st.st_mtime) < 1.0:
                        need_copy = False
                except OSError:
                    need_copy = True
            if need_copy:
                shutil.copy2(s_fp, d_fp)

    if dst_resolved.is_dir():
        for root, dirs, files in os.walk(dst_resolved):
            dirs[:] = [d for d in sorted(dirs) if d not in _SYNC_SKIP_DIRS]
            rel_dir = Path(root).relative_to(dst_resolved)
            for fname in files:
                if any(fname.lower().endswith(sfx) for sfx in _SYNC_SKIP_SUFFIXES):
                    continue
                rel_key = os.path.normcase((rel_dir / fname).as_posix())
                if rel_key not in expected_rel_files:
                    safe_trash_file(Path(root) / fname, reason="sync_app_src_stale", undo_dir=undo_dir)


def sync_portable_app_src(state_root: Path, *, source_src_dir: Optional[Path] = None) -> Optional[Path]:
    """Sync uninstalled `src/cosmos_mcp` (and `host_skills`) into `<state_root>/app_src` so deleting Downloads stays safe."""
    st_root = Path(state_root).expanduser().resolve()
    app_src = (st_root / "app_src").resolve()
    src_dir = (Path(source_src_dir).expanduser().resolve() if source_src_dir is not None else find_repo_src_dir())

    if src_dir is None:
        if (app_src / "cosmos_mcp" / "__init__.py").is_file():
            return app_src
        return None

    if os.path.normcase(str(src_dir.resolve())) == os.path.normcase(str(app_src)):
        return app_src

    pkg_src = src_dir / "cosmos_mcp"
    if not (pkg_src / "__init__.py").is_file():
        return app_src if (app_src / "cosmos_mcp" / "__init__.py").is_file() else None

    undo_dir = st_root / ".undo_history"
    app_src.mkdir(parents=True, exist_ok=True)
    _sync_clean_dir_tree(pkg_src, app_src / "cosmos_mcp", undo_dir=undo_dir)

    for hs_cand in (src_dir.parent / "host_skills", src_dir / "host_skills"):
        if hs_cand.is_dir():
            _sync_clean_dir_tree(hs_cand, app_src / "host_skills", undo_dir=undo_dir)
            break

    emb_src = src_dir.parent / "python-embed"
    if (
        emb_src.is_dir()
        and ((emb_src / "python.exe").is_file() or (emb_src / "bin" / "python3").is_file())
        and (not os.environ.get("PYTEST_CURRENT_TEST") or os.environ.get("COSMOS_TEST_SYNC_EMBED") == "1")
    ):
        emb_dst = st_root / "python-embed"
        _sync_clean_dir_tree(emb_src, emb_dst, undo_dir=undo_dir)
        ensure_embed_pth_site_enabled(emb_dst, extra_entries=("Lib/site-packages", "../app_src"))
        sp_emb = emb_dst / "Lib" / "site-packages"
        sp_emb.mkdir(parents=True, exist_ok=True)
        atomic_write_text(sp_emb / "cosmos_mcp_src.pth", str(app_src) + "\n")

    return app_src


def resolve_persisted_src_dir(state_root: Optional[Path] = None) -> Optional[Path]:
    """Return `<state_root>/app_src` (syncing if running from uninstalled checkout), falling back to `find_repo_src_dir()`."""
    if state_root is not None:
        synced = sync_portable_app_src(state_root)
        if synced is not None and (synced / "cosmos_mcp" / "__init__.py").is_file():
            return synced
    return find_repo_src_dir()


def check_runtime_deps_ready(
    python_exe: str | Path,
    extra_imports: Sequence[str] = (),
    timeout_sec: float = 10.0,
    *,
    require_cosmos_mcp: bool = False,
    inject_repo_src: bool = True,
) -> bool:
    """Fast offline import + minimum version (`mcp>=1.30.0`, `pydantic>=2.11.0`) check."""
    exe = str(python_exe or "").strip()
    if not exe or not Path(exe).is_file():
        return False
    mods = list(STRICT_CORE_IMPORTS) + [m for m in extra_imports if m and m not in STRICT_CORE_IMPORTS]
    if require_cosmos_mcp and "cosmos_mcp" not in mods:
        mods.append("cosmos_mcp")

    probe_code = (
        "import importlib, importlib.metadata as md, json, re, sys\n"
        f"mods = {json.dumps(mods)}\n"
        "for m in mods:\n"
        "    importlib.import_module(m)\n"
        "def _v(pkg):\n"
        "    raw = md.version(pkg).split('+')[0]\n"
        "    nums = [int(x) for x in re.findall(r'\\d+', raw)[:3]]\n"
        "    while len(nums) < 3:\n"
        "        nums.append(0)\n"
        "    return tuple(nums[:3])\n"
        "if _v('mcp') < (1, 30, 0):\n"
        "    raise SystemExit(2)\n"
        "min_pyd = (2, 12, 0) if sys.version_info >= (3, 14) else (2, 11, 0)\n"
        "if _v('pydantic') < min_pyd:\n"
        "    raise SystemExit(3)\n"
        "print('COSMOS_DEPS_OK')\n"
    )
    env = _clean_subproc_env()
    if inject_repo_src:
        repo_src = find_repo_src_dir()
        if repo_src is not None:
            existing_pp = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = f"{repo_src}{os.pathsep}{existing_pp}" if existing_pp else str(repo_src)
    else:
        env.pop("PYTHONPATH", None)

    try:
        proc = subprocess.run(
            [exe, "-B", "-c", probe_code],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
            env=env,
            creationflags=_popen_flags(),
        )
        return proc.returncode == 0 and "COSMOS_DEPS_OK" in (proc.stdout or "")
    except Exception:
        return False


def _has_pip(python_exe: str | Path) -> bool:
    try:
        proc = subprocess.run(
            [str(python_exe), "-B", "-m", "pip", "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=8.0,
            env=_clean_subproc_env(),
            creationflags=_popen_flags(),
        )
        return proc.returncode == 0
    except Exception:
        return False


def heal_missing_pip(venv_py: Path, base_python: str, *, undo_dir: Optional[Path] = None) -> bool:
    """Self-heal a virtualenv created on hosts where `ensurepip` is missing."""
    if _has_pip(venv_py):
        return True

    wh_dir = find_wheelhouse_dir()
    try:
        p1 = subprocess.run(
            [str(venv_py), "-B", "-m", "ensurepip", "--upgrade"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30.0,
            env=_clean_subproc_env(),
            creationflags=_popen_flags(),
        )
        if p1.returncode == 0 and _has_pip(venv_py):
            return True
    except Exception:
        pass

    uv_bin = shutil.which("uv")
    if uv_bin:
        if wh_dir is not None:
            try:
                p_uv_wh = subprocess.run(
                    [uv_bin, "pip", "install", "--python", str(venv_py), "--no-index", "--find-links", str(wh_dir), "pip"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=30.0,
                    env=_clean_subproc_env(strip_proxy=True),
                    creationflags=_popen_flags(),
                )
                if p_uv_wh.returncode == 0 and _has_pip(venv_py):
                    return True
            except Exception:
                pass
        for idx_url, t_sec in ((PRIMARY_PYPI_INDEX, PRIMARY_PYPI_TIMEOUT_SEC), (FALLBACK_TSINGHUA_INDEX, 60)):
            try:
                p_uv = subprocess.run(
                    [uv_bin, "pip", "install", "--python", str(venv_py), "--index-url", idx_url, "pip"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=float(t_sec + 10),
                    env=_clean_subproc_env(strip_proxy=(idx_url == FALLBACK_TSINGHUA_INDEX)),
                    creationflags=_popen_flags(),
                )
                if p_uv.returncode == 0 and _has_pip(venv_py):
                    return True
            except Exception:
                continue

    host_pip_Args: List[Tuple[List[str], bool]] = []
    if wh_dir is not None:
        host_pip_Args.append((["--no-index", "--find-links", str(wh_dir)], True))
    host_pip_Args.extend(([], False) if i == 0 else x for i, x in enumerate([([], False), (["-i", FALLBACK_TSINGHUA_INDEX], True), (["-i", PRIMARY_PYPI_INDEX], False)]))

    for host_cmd in ([base_python, "-B", "-m", "pip"], [shutil.which("pip3") or ""], [shutil.which("pip") or ""]):
        if not host_cmd[0]:
            continue
        for idx_args, strip_px in host_pip_Args:
            try:
                p_hp = subprocess.run(
                    [*host_cmd, "--python", str(venv_py), "install", "--no-input", *idx_args, "pip"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=60.0,
                    env=_clean_subproc_env(strip_proxy=strip_px),
                    creationflags=_popen_flags(),
                )
                if p_hp.returncode == 0 and _has_pip(venv_py):
                    return True
            except Exception:
                continue

    eff_undo = undo_dir or (Path(tempfile.gettempdir()) / "cosmos_bootstrap_trash")
    for url in GET_PIP_URLS:
        tmp_script: Optional[Path] = None
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Cosmos-MCP-Bootstrap/1.0"})
            with urllib.request.urlopen(req, timeout=20.0) as resp:
                body = resp.read()
            if len(body) < 1024:
                continue
            with tempfile.NamedTemporaryFile(prefix="cosmos_get_pip_", suffix=".py", delete=False) as tf:
                tf.write(body)
                tmp_script = Path(tf.name)
            for idx_url in (PRIMARY_PYPI_INDEX, FALLBACK_TSINGHUA_INDEX):
                p_gp = subprocess.run(
                    [str(venv_py), "-B", str(tmp_script), "--no-warn-script-location", "-i", idx_url],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=float(FALLBACK_MIRROR_TIMEOUT_SEC),
                    env=_clean_subproc_env(strip_proxy=(idx_url == FALLBACK_TSINGHUA_INDEX)),
                    creationflags=_popen_flags(),
                )
                if p_gp.returncode == 0 and _has_pip(venv_py):
                    return True
        except Exception:
            continue
        finally:
            if tmp_script is not None and tmp_script.exists():
                safe_trash_file(tmp_script, reason="bootstrap_get_pip_cleanup", undo_dir=eff_undo)
    return _has_pip(venv_py)


def _locate_venv_site_packages(venv_py: Path) -> Optional[Path]:
    site_dirs: List[Path] = []
    try:
        proc = subprocess.run(
            [str(venv_py), "-B", "-c", "import json, site; print(json.dumps(site.getsitepackages()))"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8.0,
            env=_clean_subproc_env(),
            creationflags=_popen_flags(),
        )
        if proc.returncode == 0:
            for raw_d in json.loads((proc.stdout or "[]").strip().splitlines()[-1]):
                p_cand = Path(str(raw_d))
                if p_cand.is_dir() and "site-packages" in p_cand.name.lower():
                    site_dirs.append(p_cand)
    except Exception:
        pass
    if not site_dirs:
        win_sp = venv_py.parent.parent / "Lib" / "site-packages"
        if win_sp.is_dir():
            site_dirs.append(win_sp)
        else:
            site_dirs.extend(sorted((venv_py.parent.parent / "lib").glob("python*/site-packages")))
    return site_dirs[0] if site_dirs else None


def _probe_python_site_paths(python_exe: str | Path) -> List[Path]:
    """Return site-packages / user-site directories of `python_exe` (handling nested venvs cleanly)."""
    code = (
        "import json, site, sysconfig\n"
        "paths = []\n"
        "for p in [sysconfig.get_path('purelib'), sysconfig.get_path('platlib')]:\n"
        "    if p and p not in paths:\n"
        "        paths.append(p)\n"
        "try:\n"
        "    up = site.getusersitepackages()\n"
        "    if up and up not in paths:\n"
        "        paths.append(up)\n"
        "except Exception:\n"
        "    pass\n"
        "print(json.dumps(paths))\n"
    )
    try:
        proc = subprocess.run(
            [str(python_exe), "-B", "-c", code],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=6.0,
            env=_clean_subproc_env(),
            creationflags=_popen_flags(),
        )
        if proc.returncode == 0:
            raw = json.loads((proc.stdout or "[]").strip().splitlines()[-1])
            return [Path(str(x)).resolve() for x in raw if x and Path(str(x)).is_dir()]
    except Exception:
        pass
    return []


def _write_venv_src_pth(
    venv_py: Path,
    src_dir: Optional[Path],
    *,
    extra_paths: Sequence[Path] = (),
) -> bool:
    """Write `cosmos_mcp_src.pth` into `.venv/site-packages` pointing to `<state_root>/app_src`."""
    sp_dir = _locate_venv_site_packages(venv_py)
    if sp_dir is None:
        return False
    lines: List[str] = []
    seen: set[str] = set()
    if src_dir is not None:
        resolved_src = src_dir.resolve()
        if (resolved_src / "cosmos_mcp" / "__init__.py").is_file():
            nk = os.path.normcase(str(resolved_src))
            seen.add(nk)
            lines.append(str(resolved_src))
    for ep in extra_paths:
        ep_res = Path(ep).resolve()
        nk = os.path.normcase(str(ep_res))
        if ep_res.is_dir() and nk not in seen and nk != os.path.normcase(str(sp_dir.resolve())):
            seen.add(nk)
            lines.append(str(ep_res))
    if not lines:
        return False
    atomic_write_text(sp_dir / "cosmos_mcp_src.pth", "\n".join(lines) + "\n")
    return True


def _write_venv_repo_pth(venv_py: Path, repo_root: Path) -> bool:
    """Backward-compatible helper linking `<repo_root>/src` into `.venv` via `.pth`."""
    src_dir = (repo_root / "src").resolve()
    if not (src_dir / "cosmos_mcp" / "__init__.py").is_file():
        return False
    return _write_venv_src_pth(venv_py, src_dir)


def _can_emit_bootstrap_progress() -> bool:
    if os.environ.get("COSMOS_QUIET_BOOTSTRAP") or os.environ.get("PYTEST_CURRENT_TEST"):
        return False
    if "--json" in sys.argv:
        return False
    return bool(sys.stderr is not None and hasattr(sys.stderr, "write"))


def _emit_bootstrap_progress(msg_zh: str) -> None:
    if not _can_emit_bootstrap_progress():
        return
    try:
        sys.stderr.write(f"[环境准备] {msg_zh}\n")
        sys.stderr.flush()
    except Exception:
        pass


def _run_pip_streaming(
    cmd: Sequence[str],
    *,
    timeout_sec: float,
    env: Dict[str, str],
    progress_label_zh: str,
) -> Tuple[int, str]:
    """Run pip subprocess with `stdin=DEVNULL` while streaming concise Chinese progress lines when interactive."""
    show_live = _can_emit_bootstrap_progress()
    if show_live and progress_label_zh:
        _emit_bootstrap_progress(progress_label_zh)

    proc = subprocess.Popen(
        list(cmd),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        creationflags=_popen_flags(),
    )
    captured_lines: List[str] = []

    def _reader() -> None:
        stream = proc.stdout
        if stream is None:
            return
        try:
            for raw_ln in stream:
                ln = raw_ln.rstrip("\r\n")
                if not ln.strip():
                    continue
                captured_lines.append(ln)
                if len(captured_lines) > 160:
                    del captured_lines[:40]
                if show_live and any(
                    ln.lstrip().startswith(pfx)
                    for pfx in ("Collecting ", "Downloading ", "Using cached ", "Installing collected packages", "Successfully installed")
                ):
                    try:
                        sys.stderr.write(f"  -> {ln.strip()[:120]}\n")
                        sys.stderr.flush()
                    except Exception:
                        pass
        except Exception:
            pass

    reader_th = threading.Thread(target=_reader, name="cosmos-pip-progress", daemon=True)
    reader_th.start()
    try:
        rc = proc.wait(timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.wait(timeout=2.0)
        except Exception:
            pass
        reader_th.join(timeout=1.0)
        raise
    reader_th.join(timeout=2.0)
    return int(rc), "\n".join(captured_lines)[-900:]


def pip_install_with_mirror_fallback(
    python_exe: str | Path,
    specs: Sequence[str],
    *,
    wheelhouse_dir: Optional[Path] = None,
    primary_timeout_sec: int = PRIMARY_PYPI_TIMEOUT_SEC,
    mirror_timeout_sec: int = FALLBACK_MIRROR_TIMEOUT_SEC,
) -> Dict[str, object]:
    """Install `specs` trying local wheelhouse (`--no-index --find-links`) -> default/pip.conf -> Tsinghua mirror."""
    if not specs:
        return {"ok": True, "source": "noop", "elapsed_sec": 0.0}

    t0 = time.monotonic()
    py_s = str(python_exe)
    attempts: List[Dict[str, object]] = []
    eff_wh = Path(wheelhouse_dir).expanduser().resolve() if wheelhouse_dir is not None else find_wheelhouse_dir()
    find_links_args = ["--find-links", str(eff_wh)] if (eff_wh is not None and eff_wh.is_dir()) else []
    pkg_preview = ", ".join(str(s).split(">=")[0].split("<")[0].split(";")[0].strip() for s in specs[:5])

    if find_links_args:
        cmd_wh = [
            py_s,
            "-B",
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--progress-bar",
            "off",
            "--no-index",
            *find_links_args,
            *specs,
        ]
        try:
            rc_wh, tail_wh = _run_pip_streaming(
                cmd_wh,
                timeout_sec=90.0,
                env=_clean_subproc_env(strip_proxy=True),
                progress_label_zh=f"正在从随包离线目录安装运行组件（{pkg_preview}）...",
            )
            if rc_wh == 0:
                _emit_bootstrap_progress("离线组件安装完成。")
                return {
                    "ok": True,
                    "source": "local_wheelhouse",
                    "wheelhouse": str(eff_wh),
                    "elapsed_sec": round(time.monotonic() - t0, 3),
                }
            attempts.append(
                {
                    "source": "local_wheelhouse",
                    "wheelhouse": str(eff_wh),
                    "returncode": rc_wh,
                    "stderr_tail": tail_wh[-600:],
                }
            )
        except Exception as exc:
            attempts.append({"source": "local_wheelhouse", "error": str(exc)})

    cmd_default = [
        py_s,
        "-B",
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-input",
        "--progress-bar",
        "off",
        "--timeout",
        str(int(primary_timeout_sec)),
        "--retries",
        "1",
        *find_links_args,
        *specs,
    ]
    try:
        rc1, tail1 = _run_pip_streaming(
            cmd_default,
            timeout_sec=float(max(primary_timeout_sec * 3, 45)),
            env=_clean_subproc_env(strip_proxy=False),
            progress_label_zh=f"首次运行正在准备独立 Python 依赖（{pkg_preview}），约需 10~30 秒...",
        )
        if rc1 == 0:
            _emit_bootstrap_progress("Python 运行依赖安装完成。")
            return {
                "ok": True,
                "source": "default_or_pip_conf",
                "index_url": os.environ.get("PIP_INDEX_URL") or PRIMARY_PYPI_INDEX,
                "elapsed_sec": round(time.monotonic() - t0, 3),
            }
        attempts.append(
            {
                "source": "default_or_pip_conf",
                "returncode": rc1,
                "stderr_tail": tail1[-600:],
            }
        )
    except subprocess.TimeoutExpired:
        attempts.append({"source": "default_or_pip_conf", "error": f"timeout>{primary_timeout_sec}s"})
    except Exception as exc:
        attempts.append({"source": "default_or_pip_conf", "error": str(exc)})

    cmd_mirror = [
        py_s,
        "-B",
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-input",
        "--progress-bar",
        "off",
        "--timeout",
        str(int(mirror_timeout_sec)),
        "--retries",
        "2",
        "-i",
        FALLBACK_TSINGHUA_INDEX,
        *find_links_args,
        *specs,
    ]
    try:
        rc2, tail2 = _run_pip_streaming(
            cmd_mirror,
            timeout_sec=float(max(mirror_timeout_sec + 30, 150)),
            env=_clean_subproc_env(strip_proxy=True),
            progress_label_zh=f"默认源响应较慢，已自动切换国内镜像源继续下载（{pkg_preview}）...",
        )
        if rc2 == 0:
            _emit_bootstrap_progress("国内镜像源依赖安装完成。")
            return {
                "ok": True,
                "source": "tsinghua_mirror",
                "index_url": FALLBACK_TSINGHUA_INDEX,
                "elapsed_sec": round(time.monotonic() - t0, 3),
                "fallback_from": attempts,
            }
        attempts.append(
            {
                "source": "tsinghua_mirror",
                "returncode": rc2,
                "stderr_tail": tail2[-800:],
            }
        )
    except subprocess.TimeoutExpired:
        attempts.append({"source": "tsinghua_mirror", "error": f"timeout>{mirror_timeout_sec}s"})
    except Exception as exc:
        attempts.append({"source": "tsinghua_mirror", "error": str(exc)})

    return {
        "ok": False,
        "source": "failed",
        "elapsed_sec": round(time.monotonic() - t0, 3),
        "attempts": attempts,
    }


def ensure_runtime_environment(
    state_root: Path,
    *,
    preferred_python: Optional[str | Path] = None,
    extra_pip_specs: Sequence[str] = (),
    extra_imports: Sequence[str] = (),
    allow_ambient_passthrough: bool = True,
) -> Dict[str, object]:
    """Ensure `<state_root>/.venv` (Python 3.10~3.14) and `<state_root>/app_src` are self-contained and ready."""
    state_root = Path(state_root).expanduser().resolve()
    app_src = sync_portable_app_src(state_root)
    venv_dir = state_root / ".venv"
    venv_py = venv_python_path(venv_dir, windowless=False)

    if venv_py.is_file() and not extra_pip_specs:
        probed_venv = probe_python_version([str(venv_py)])
        if probed_venv is not None:
            _, v_ver = probed_venv
            if SUPPORTED_RUNTIME_MIN <= (v_ver[0], v_ver[1]) <= SUPPORTED_RUNTIME_MAX:
                if app_src is not None:
                    existing_pth = (_locate_venv_site_packages(venv_py) or Path("")) / "cosmos_mcp_src.pth"
                    existing_extra: List[Path] = []
                    if existing_pth.is_file():
                        for ln in existing_pth.read_text(encoding="utf-8", errors="replace").splitlines():
                            p_ln = Path(ln.strip())
                            if p_ln.is_dir() and os.path.normcase(str(p_ln)) != os.path.normcase(str(app_src)):
                                if not (p_ln / "cosmos_mcp" / "__init__.py").is_file():
                                    existing_extra.append(p_ln)
                    _write_venv_src_pth(venv_py, app_src, extra_paths=existing_extra)
                if check_runtime_deps_ready(
                    venv_py,
                    extra_imports=extra_imports,
                    require_cosmos_mcp=True,
                    inject_repo_src=False,
                ):
                    return {
                        "ok": True,
                        "mode": "venv_cached_offline",
                        "python_exe": str(venv_py),
                        "pythonw_exe": resolve_windowless_python(venv_py),
                        "python_version": ".".join(str(x) for x in v_ver),
                        "app_src": str(app_src) if app_src else "",
                    }

    state_embed_exe = find_embedded_python_exe(state_root=state_root)
    if state_embed_exe is not None and not extra_pip_specs:
        is_inside_state_root = os.path.normcase(str(state_embed_exe)).startswith(
            os.path.normcase(str(state_root)).rstrip("\\/") + os.sep
        )
        if is_inside_state_root:
            ensure_embed_pth_site_enabled(state_embed_exe.parent)
        probed_emb = probe_python_version([str(state_embed_exe)])
        if probed_emb is not None:
            _, e_ver = probed_emb
            if SUPPORTED_RUNTIME_MIN <= (e_ver[0], e_ver[1]) <= SUPPORTED_RUNTIME_MAX:
                if app_src is not None and is_inside_state_root:
                    sp_emb = state_embed_exe.parent / "Lib" / "site-packages"
                    sp_emb.mkdir(parents=True, exist_ok=True)
                    atomic_write_text(sp_emb / "cosmos_mcp_src.pth", str(app_src) + "\n")
                if check_runtime_deps_ready(
                    state_embed_exe,
                    extra_imports=extra_imports,
                    require_cosmos_mcp=True,
                    inject_repo_src=not is_inside_state_root,
                ):
                    return {
                        "ok": True,
                        "mode": "python_embed_cached",
                        "python_exe": str(state_embed_exe),
                        "pythonw_exe": resolve_windowless_python(state_embed_exe),
                        "python_version": ".".join(str(x) for x in e_ver),
                        "app_src": str(app_src) if app_src else "",
                    }

    found = find_suitable_python(preferred_python)
    if found is None:
        return {
            "ok": False,
            "error": "python_310_314_not_found",
            "detail": "未检测到可用的 Python 3.10~3.14 解释器，请先安装 Python 3.11 或 3.12（勾选 Add to PATH）。",
        }
    base_exe, base_ver = found

    # Fast self-contained `.venv` creation (`--system-site-packages` + `cosmos_mcp_src.pth`) when host already satisfies deps
    if allow_ambient_passthrough and not extra_pip_specs and check_runtime_deps_ready(base_exe, extra_imports=extra_imports):
        venv_dir.parent.mkdir(parents=True, exist_ok=True)
        if not venv_py.is_file():
            p_fast = subprocess.run(
                [base_exe, "-B", "-m", "venv", "--system-site-packages", "--without-pip", str(venv_dir)],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=45.0,
                env=_clean_subproc_env(),
                creationflags=_popen_flags(),
            )
            if p_fast.returncode != 0 and venv_dir.exists():
                safe_trash_file(venv_dir, reason="venv_sys_site_retry", undo_dir=state_root / ".undo_history")
        if venv_py.is_file():
            host_sites = _probe_python_site_paths(base_exe)
            _write_venv_src_pth(venv_py, app_src, extra_paths=host_sites)
            if check_runtime_deps_ready(
                venv_py,
                extra_imports=extra_imports,
                require_cosmos_mcp=True,
                inject_repo_src=False,
            ):
                return {
                    "ok": True,
                    "mode": "venv_system_site_packages",
                    "python_exe": str(venv_py),
                    "pythonw_exe": resolve_windowless_python(venv_py),
                    "python_version": ".".join(str(x) for x in base_ver),
                    "app_src": str(app_src) if app_src else "",
                }

    venv_dir.parent.mkdir(parents=True, exist_ok=True)
    if not venv_py.is_file():
        p_venv = subprocess.run(
            [base_exe, "-B", "-m", "venv", str(venv_dir)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60.0,
            env=_clean_subproc_env(),
            creationflags=_popen_flags(),
        )
        if p_venv.returncode != 0 or not venv_py.is_file():
            if venv_dir.exists():
                safe_trash_file(venv_dir, reason="venv_broken_retry_nopip", undo_dir=state_root / ".undo_history")
            p_nopip = subprocess.run(
                [base_exe, "-B", "-m", "venv", "--without-pip", str(venv_dir)],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=45.0,
                env=_clean_subproc_env(),
                creationflags=_popen_flags(),
            )
            if p_nopip.returncode != 0 or not venv_py.is_file():
                base_dir = Path(base_exe).resolve().parent
                if any(base_dir.glob("python*._pth")):
                    emb_dst = state_root / "python-embed"
                    if os.path.normcase(str(base_dir)) != os.path.normcase(str(emb_dst.resolve())):
                        _sync_clean_dir_tree(base_dir, emb_dst, undo_dir=state_root / ".undo_history")
                    ensure_embed_pth_site_enabled(emb_dst, extra_entries=("Lib/site-packages", "../app_src"))
                    venv_py = emb_dst / Path(base_exe).name
                else:
                    return {
                        "ok": False,
                        "error": "venv_create_failed",
                        "detail": (p_nopip.stderr or p_venv.stderr or "创建虚拟环境失败")[-600:],
                    }

    if not heal_missing_pip(venv_py, base_exe, undo_dir=state_root / ".undo_history"):
        return {
            "ok": False,
            "error": "ensurepip_heal_failed",
            "detail": "当前系统 Python 缺失 pip/ensurepip 且自动修复失败（Linux 请运行 apt install python3-venv python3-pip）。",
        }

    wh_dir = find_wheelhouse_dir()
    core_specs = list(STRICT_CORE_PIP_SPECS)
    for sp in extra_pip_specs:
        if sp and sp not in core_specs:
            core_specs.append(sp)

    full_specs = list(core_specs)
    for doc_sp in OPTIONAL_DOCS_PIP_SPECS:
        if doc_sp not in full_specs:
            full_specs.append(doc_sp)

    docs_degraded = False
    pip_res = pip_install_with_mirror_fallback(venv_py, full_specs, wheelhouse_dir=wh_dir)
    if not pip_res.get("ok"):
        pip_core_res = pip_install_with_mirror_fallback(venv_py, core_specs, wheelhouse_dir=wh_dir)
        if not pip_core_res.get("ok"):
            return {
                "ok": False,
                "error": "dependency_install_failed",
                "pip_result": pip_core_res,
                "full_attempt": pip_res,
            }
        pip_res = pip_core_res
        docs_degraded = True

    if app_src is not None:
        _write_venv_src_pth(venv_py, app_src)
    else:
        repo_root = find_repo_root()
        if repo_root is not None:
            _write_venv_repo_pth(venv_py, repo_root)

    return {
        "ok": True,
        "mode": "venv_bootstrapped_core_only" if docs_degraded else "venv_bootstrapped",
        "docs_degraded": docs_degraded,
        "python_exe": str(venv_py),
        "pythonw_exe": resolve_windowless_python(venv_py),
        "python_version": ".".join(str(x) for x in base_ver),
        "pip_source": pip_res.get("source"),
        "app_src": str(app_src) if app_src else "",
    }


def resolve_asset_path(filename: str) -> Path:
    """Locate a bundled static asset (`index.html`, `studio.css`, `studio.js`) across `.whl` and editable layouts."""
    clean_name = str(filename or "").strip().lstrip("/\\")
    if not clean_name or ".." in clean_name:
        raise ValueError(f"Invalid asset filename: {filename!r}")
    mapped = "index.html" if clean_name == "status.html" else clean_name
    for pkg in ("cosmos_mcp.studio.static", "cosmos_mcp.launcher.assets"):
        try:
            pkg_files = importlib.resources.files(pkg)
            candidate = pkg_files.joinpath(mapped)
            cand_path = Path(str(candidate))
            if cand_path.is_file():
                return cand_path
        except Exception:
            continue
    studio_fallback = Path(__file__).resolve().parent.parent / "studio" / "static" / mapped
    if studio_fallback.is_file():
        return studio_fallback
    return Path(__file__).resolve().parent / "assets" / clean_name


def read_asset_text(filename: str, encoding: str = "utf-8") -> str:
    """Read bundled static asset text via `importlib.resources` with filesystem fallback."""
    p = resolve_asset_path(filename)
    return p.read_text(encoding=encoding)


def atomic_write_text(target: Path, text: str, mode_override: Optional[int] = None) -> None:
    """Atomically write UTF-8 `text` to `target` (single-source-of-truth in `core.fs_tx`)."""
    from cosmos_mcp.core.fs_tx import atomic_write_text as _core_atomic_write_text

    _core_atomic_write_text(target, text, mode_override=mode_override)
