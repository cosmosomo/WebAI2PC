"""
Layer 0 Python Subprocess Audit Sandbox Hook (`cosmos_mcp.core.sandbox_hook`).

Pure Python >=3.9 standard-library implementation providing:
1. Standalone generation of `sitecustomize.py` installing a CPython `sys.addaudithook`
   in `L3` Python child processes and prepending the hook directory to `PYTHONPATH`[0].
2. Multi-workspace root enforcement inside child processes (`COSMOS_L3_WORKSPACES`),
   intercepting out-of-bounds file read/write, `sqlite3.connect`, out-of-bounds `subprocess.Popen`,
   unverified `dir_fd` handle escapes, NTFS ADS streams, and `-I`/`-E`/`-S` unhook flags.
3. Fail-Closed initialization: any directory creation or `sitecustomize.py` write/verify failure
   unconditionally raises `PermissionError("ERR_L3_SANDBOX_INIT_FAILED")` (eliminating the legacy
   silent `except OSError: pass` bypass).
4. Locked read-only `batch_probe` subprocess runner generator with frozen builtins.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple, Union

from cosmos_mcp.core.guard import canonical_realpath

ERR_L3_SANDBOX_INIT_FAILED = "ERR_L3_SANDBOX_INIT_FAILED"
ERR_READONLY_WORKSPACE = "ERR_READONLY_WORKSPACE"

L3_SITECUSTOMIZE_SOURCE = r"""import builtins, importlib, os, re, sys, urllib.parse
from pathlib import Path

def _install_cosmos_l3_hook():
    _any = any
    _isinstance = isinstance
    _str = str
    _int = int
    _len = len
    _tuple = tuple
    _bool = bool
    _dict = dict
    _PermErr = PermissionError
    _BaseExc = BaseException
    _getframe = sys._getframe
    _fsd = os.fsdecode
    _realpath = os.path.realpath
    _readlink = getattr(os, "readlink", None)
    _abspath = os.path.abspath
    _pjoin = os.path.join
    _splitdrive = os.path.splitdrive
    _pathsep = os.pathsep
    _urlsplit = urllib.parse.urlsplit
    _unquote = urllib.parse.unquote
    _is_win = sys.platform == "win32"
    _Path = Path

    _raw_multi = os.environ.get("COSMOS_L3_WORKSPACES", "").strip()
    _raw_single = os.environ.get("LOCALPC_L3_WORKSPACE", "").strip()
    _raw_ro_multi = os.environ.get("COSMOS_L3_READONLY_WORKSPACES", "").strip()
    _restrict_ws = os.environ.get("COSMOS_L3_RESTRICT_WS", "1").strip() != "0"
    _raw_parts = [p.strip() for p in _raw_multi.split(_pathsep) if p.strip()] if _raw_multi else []
    if _raw_single and _raw_single not in _raw_parts:
        _raw_parts.append(_raw_single)
    if not _raw_parts and not _raw_ro_multi:
        return

    _sep = chr(92) if _is_win else "/"
    _strip_chars = _sep + "/"
    _ws_list = []
    for _wp in _raw_parts:
        try:
            _wl = _realpath(_abspath(_wp)).lower().rstrip(_strip_chars)
        except _BaseExc:
            _wl = _wp.lower().rstrip(_strip_chars)
        if _wl and _wl not in _ws_list:
            _ws_list.append(_wl)

    _ro_ws_list = []
    if _raw_ro_multi:
        for _rwp in _raw_ro_multi.split(_pathsep):
            _rwp_s = _rwp.strip()
            if not _rwp_s:
                continue
            try:
                _rwl = _realpath(_abspath(_rwp_s)).lower().rstrip(_strip_chars)
            except _BaseExc:
                _rwl = _rwp_s.lower().rstrip(_strip_chars)
            if _rwl and _rwl not in _ro_ws_list:
                _ro_ws_list.append(_rwl)
                if _rwl not in _ws_list:
                    _ws_list.append(_rwl)
    if not _ws_list:
        return
    _ws_roots = _tuple(_ws_list)
    _ro_ws_roots = _tuple(_ro_ws_list)
    _ro_ws_set = frozenset(_ro_ws_roots)
    _scan_host_skills = os.environ.get("COSMOS_L3_SCAN_HOST_SKILLS", "0").strip() == "1"

    _tmp_raw = (os.environ.get("COSMOS_L3_ALLOW_TMP") or os.environ.get("LOCALPC_L3_ALLOW_TMP") or "").strip()
    _sr_raw = (os.environ.get("COSMOS_L3_STATE_ROOT") or os.environ.get("LOCALPC_L3_STATE_ROOT") or "").strip()
    try:
        _tmp_low = _realpath(_abspath(_tmp_raw)).lower().rstrip(_strip_chars) if _tmp_raw else ""
    except _BaseExc:
        _tmp_low = _tmp_raw.lower().rstrip(_strip_chars)
    try:
        _sr_low = _realpath(_abspath(_sr_raw)).lower().rstrip(_strip_chars) if _sr_raw else ""
    except _BaseExc:
        _sr_low = _sr_raw.lower().rstrip(_strip_chars)

    _guard_dir_s = _realpath(_abspath(_str(_Path(__file__).parent)))
    _guard_low = _guard_dir_s.lower().rstrip(_strip_chars)
    _eff_sr_low = _sr_low
    if not _eff_sr_low:
        try:
            _p_up = _Path(__file__).parent
            if _p_up.parent.name.lower() == "state":
                _eff_sr_low = _realpath(_abspath(_str(_p_up.parent.parent))).lower().rstrip(_strip_chars)
        except _BaseExc:
            _eff_sr_low = ""
    _secrets_low = (_eff_sr_low + _sep + "secrets") if _eff_sr_low else ""
    _venv_low = (_eff_sr_low + _sep + ".venv") if _eff_sr_low else ""
    _spill_low = (_eff_sr_low + _sep + "logs" + _sep + "spill") if _eff_sr_low else ""
    _bglogs_low = (_eff_sr_low + _sep + "logs" + _sep + "bg_jobs") if _eff_sr_low else ""
    _skills_store_low = (_eff_sr_low + _sep + "skills_store") if _eff_sr_low else ""
    _sr_hs_low = (_eff_sr_low + _sep + "host_skills") if _eff_sr_low else ""
    _app_hs_low = (_eff_sr_low + _sep + "app_src" + _sep + "host_skills") if _eff_sr_low else ""
    _home = _Path.home()
    _ro_cands = [
        _Path(sys.prefix),
        _Path(sys.base_prefix),
        _home / ".cargo" / "bin",
        _home / ".cargo" / "registry",
        _home / ".rustup",
        _home / ".pyenv",
        _home / ".cache",
        _home / ".huggingface",
        _home / ".matplotlib",
        _home / ".config" / "matplotlib",
    ]
    if _scan_host_skills:
        _ro_cands.extend([
            _home / ".agents" / "skills",
            _home / ".claude" / "skills",
            _home / ".cursor" / "skills",
            _home / ".codeium" / "windsurf" / "skills",
            _home / ".codex" / "skills",
            _home / ".gemini" / "skills",
            _home / ".cc-switch" / "skills",
            _home / ".cosmos-skills" / "skills_store",
        ])
    if _is_win:
        _win_root = _Path(os.environ.get("SystemRoot") or ("C:" + _sep + "Windows"))
        _ro_cands.extend([
            _Path("C:" + _sep + "Program Files" + _sep + "Go"),
            _Path("C:" + _sep + "Program Files (x86)" + _sep + "Go"),
            _Path("C:" + _sep + "Go"),
            _win_root / "Fonts",
            _win_root / "System32",
        ])
    else:
        _ro_cands.extend([
            _Path("/usr/local/go"),
            _Path("/usr/lib/go"),
            _Path("/usr/lib/rustlib"),
            _Path("/usr/share/fonts"),
            _Path("/usr/local/share/fonts"),
            _Path("/usr/share/zoneinfo"),
            _Path("/etc/localtime"),
        ])
    for _sp in sys.path:
        if _sp:
            if "site-packages" in _sp.lower() or "dist-packages" in _sp.lower():
                _ro_cands.append(_Path(_sp))
            _sp_p = _Path(_sp)
            for _hs_cand in (_sp_p / "host_skills", _sp_p.parent / "host_skills"):
                try:
                    if _hs_cand.is_dir():
                        _ro_cands.append(_hs_cand)
                except _BaseExc:
                    pass
    for _ek in ("GOROOT", "RUSTUP_HOME", "PYENV_ROOT", "VIRTUAL_ENV", "CONDA_PREFIX", "XDG_CACHE_HOME", "HF_HOME", "TORCH_HOME"):
        _ev = (os.environ.get(_ek) or "").strip()
        if _ev:
            _ro_cands.append(_Path(_ev))
    _cargo_ev = (os.environ.get("CARGO_HOME") or "").strip()
    if _cargo_ev:
        _ro_cands.append(_Path(_cargo_ev) / "bin")
        _ro_cands.append(_Path(_cargo_ev) / "registry")

    _ro_list = [_guard_low]
    for _extra_ro in (_venv_low, _spill_low, _bglogs_low, _skills_store_low, _sr_hs_low, _app_hs_low):
        if _extra_ro and _extra_ro not in _ro_list:
            _ro_list.append(_extra_ro)
    for _rc in _ro_cands:
        try:
            _rl = _realpath(_abspath(_str(_rc))).lower().rstrip(_strip_chars)
        except _BaseExc:
            _rl = _str(_rc).lower().rstrip(_strip_chars)
        if _rl and _rl not in _ro_list:
            _ro_list.append(_rl)
    _ro_roots = _tuple(_ro_list)

    _prot_cred = os.environ.get("COSMOS_L3_PROTECT_CREDENTIALS", "1") != "0"
    _prot_dotenv = os.environ.get("COSMOS_L3_PROTECT_DOTENV", "0") == "1"
    try:
        _home_npmrc_low = _realpath(_abspath(_str(_home / ".npmrc"))).lower().rstrip(_strip_chars)
    except _BaseExc:
        _home_npmrc_low = _str(_home / ".npmrc").lower().rstrip(_strip_chars)
    _sens_pats = [
        r"(?:^|[\\/])(?:owner_password\.txt|连接信息_CONNECTION_INFO[^\\/]*\.txt|latest_consent_pair_code[^\\/]*\.txt|oauth(?:_[a-z0-9_.-]+)?\.sqlite3(?:-wal|-shm)?|\.(?:human_ui_secret|peer_hmac_secret))$",
    ]
    if _prot_cred:
        _sens_pats.extend([
            r"(?:^|[\\/])\.(?:ssh|aws|gnupg|kube|azure)(?:$|[\\/])",
            r"(?:^|[\\/])\.cargo[\\/]credentials(?:\.toml)?$",
            r"(?:^|[\\/])\.?huggingface[\\/](?:token|stored_tokens)(?:$|[\\/])",
            r"(?:^|[\\/])\.(?:git-credentials|pypirc|netrc)$",
            r"(?:^|[\\/])appdata[\\/]local[\\/](?:google[\\/]chrome|microsoft[\\/]edge|bravesoftware[\\/]brave-browser|chromium)[\\/]user data(?:$|[\\/])",
        ])
    if _prot_dotenv:
        _sens_pats.append(
            r"(?:^|[\\/])\.env(?:\.(?!(?:example|template|sample|dist|defaults)$)[a-z0-9_.-]+)?$"
        )
    _sens_rx = _tuple(re.compile(p, re.IGNORECASE) for p in _sens_pats)
    _ads_rx = re.compile(r"::\$[A-Za-z0-9_]+")
    _py_iso_rx = re.compile(r"^-(?=[A-Za-z]*[IES])[A-Za-z]+$")
    _pop_tok_rx = re.compile(r'"([^"]*)"|(\S+)')
    _wflags = _int(os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
    _wchars = frozenset({"w", "a", "x", "+"})
    _ptypes = (_str, bytes, os.PathLike)
    _mut_1 = frozenset({
        "os." + "remove",
        "os." + "unlink",
        "os." + "rmdir",
        "os." + "removedirs",
        "os.mkdir",
        "os.makedirs",
        "os.chmod",
        "os.chown",
        "os.truncate",
        "os.ftruncate",
    })
    _mut_2 = frozenset({"os.rename", "os.replace", "os.link", "os.symlink"})
    _dir_ev = frozenset({"os.listdir", "os.scandir", "glob.glob", "os.chdir"})
    _proc_block_prefixes = ("os.startfile", "os.system", "os.popen", "os.spawn", "os.posix_spawn", "os.exec")
    _prot_attrs = frozenset({"__closure__", "cell_contents"})
    _prot_env_keys = frozenset({
        "COSMOS_L3_WORKSPACES",
        "LOCALPC_L3_WORKSPACE",
        "COSMOS_L3_READONLY_WORKSPACES",
        "COSMOS_L3_RESTRICT_WS",
        "COSMOS_L3_SCAN_HOST_SKILLS",
        "COSMOS_L3_PROTECT_CREDENTIALS",
        "COSMOS_L3_PROTECT_DOTENV",
        "COSMOS_L3_STATE_ROOT",
        "LOCALPC_L3_STATE_ROOT",
        "COSMOS_L3_ALLOW_TMP",
        "LOCALPC_L3_ALLOW_TMP",
    })
    _sys_bin_exts = (".dll", ".pyd", ".so", ".dylib", ".nls", ".cat")
    _null_devs = frozenset({"nul", "//./nul", "/dev/null", "con", "conin$", "conout$", "//./con", "//./conin$", "//./conout$"})
    _ext_p1 = (_sep * 2) + "?" + _sep
    _ext_p2 = (_sep * 2) + "." + _sep
    _fd_map = {}

    def _under(c_l, b_l):
        return _bool(b_l) and (c_l == b_l or c_l.startswith(b_l + _sep))

    def _under_any_ws(c_l):
        return _any(_under(c_l, w) for w in _ws_roots)

    def _resolve_dfd(dfd):
        if dfd in _fd_map:
            return _fd_map[dfd]
        if not _is_win:
            try:
                return _realpath(f"/proc/self/fd/{dfd}")
            except _BaseExc:
                pass
        raise _PermErr("[COSMOS L3 SANDBOX]: Unverified dir_fd handle access is prohibited in Tier L3.")

    def _chk_p(raw_t, is_write, base_dir=None):
        ts = _fsd(raw_t)
        ts_strip = ts.strip()
        ts_l = ts_strip.lower().replace(_sep, "/")
        if ts_l in _null_devs:
            return ""
        if _ads_rx.search(ts_strip):
            raise _PermErr("[COSMOS L3 SANDBOX]: NTFS Alternate Data Streams are prohibited.")
        if _is_win:
            _drv, _rest = _splitdrive(ts_strip.removeprefix(_ext_p1).removeprefix(_ext_p2))
            if ":" in _rest:
                raise _PermErr("[COSMOS L3 SANDBOX]: NTFS Alternate Data Streams are prohibited.")
        eff_t = _pjoin(base_dir, ts) if (base_dir and not _Path(ts).is_absolute()) else ts
        try:
            res_s = _realpath(_abspath(eff_t))
        except _BaseExc:
            res_s = eff_t
        tl = res_s.lower().rstrip(_strip_chars)
        if tl.replace(_sep, "/") in _null_devs:
            return res_s
        if _any(rx.search(res_s) or rx.search(ts) for rx in _sens_rx):
            raise _PermErr("[COSMOS L3 SANDBOX]: Sensitive host credential path is isolated.")
        if _prot_cred and tl.endswith(_sep + ".npmrc") and (
            tl == _home_npmrc_low or (_restrict_ws and not _under_any_ws(tl))
        ):
            raise _PermErr("[COSMOS L3 SANDBOX]: Sensitive host credential path is isolated.")
        if _secrets_low and _under(tl, _secrets_low):
            raise _PermErr("[COSMOS L3 SANDBOX]: MCP state and secrets are isolated.")
        if _eff_sr_low and _under(tl, _eff_sr_low) and not _under(tl, _tmp_low) and not (
            not is_write
            and (
                _under(tl, _guard_low)
                or _under(tl, _venv_low)
                or _under(tl, _spill_low)
                or _under(tl, _bglogs_low)
                or _under(tl, _skills_store_low)
                or _under(tl, _sr_hs_low)
                or _under(tl, _app_hs_low)
            )
        ):
            raise _PermErr("[COSMOS L3 SANDBOX]: MCP state and secrets are isolated.")
        if _tmp_low and _under(tl, _tmp_low):
            return res_s
        if _under_any_ws(tl):
            if is_write and _ro_ws_set:
                _best_w = ""
                _best_len = -1
                for _w in _ws_roots:
                    if _under(tl, _w) and _len(_w) > _best_len:
                        _best_w = _w
                        _best_len = _len(_w)
                if _best_w and _best_w in _ro_ws_set:
                    raise _PermErr(
                        f"ERR_READONLY_WORKSPACE: [COSMOS L3 SANDBOX]: Workspace {_best_w} is mounted as read-only; write access to {res_s} is prohibited."
                    )
            return res_s
        if not _restrict_ws:
            return res_s
        if not is_write:
            if _any(_under(tl, r) for r in _ro_roots):
                return res_s
            if tl.endswith(_sys_bin_exts):
                return res_s
        raise _PermErr(f"[COSMOS L3 SANDBOX]: Tier L3 restricts Python file access to workspaces {_ws_roots} (got {res_s}).")

    _stdlib_dir = _realpath(_abspath(os.path.dirname(os.__file__))).lower().rstrip(_strip_chars)
    _trusted_site_list = []
    for _sp_cand in sys.path:
        if _sp_cand and ("site-packages" in _sp_cand.lower() or "dist-packages" in _sp_cand.lower()):
            try:
                _sp_real = _realpath(_abspath(_str(_sp_cand))).lower().rstrip(_strip_chars)
            except _BaseExc:
                _sp_real = ""
            if _sp_real and _sp_real not in _trusted_site_list:
                if (not _under_any_ws(_sp_real)) or ((_sep + ".venv" + _sep) in _sp_real) or ((_sep + "venv" + _sep) in _sp_real):
                    _trusted_site_list.append(_sp_real)
    for _wr_v in _ws_roots:
        for _vn in (".venv", "venv"):
            _vp_base = _Path(_wr_v) / _vn
            for _sp_sub in (_vp_base / "Lib" / "site-packages", _vp_base / "lib" / "site-packages"):
                try:
                    if _sp_sub.is_dir():
                        _vs_r = _realpath(_abspath(_str(_sp_sub))).lower().rstrip(_strip_chars)
                        if _vs_r and _vs_r not in _trusted_site_list:
                            _trusted_site_list.append(_vs_r)
                except _BaseExc:
                    pass
            try:
                _lib_d = _vp_base / "lib"
                if _lib_d.is_dir():
                    for _py_ch in _lib_d.iterdir():
                        _sp_py = _py_ch / "site-packages"
                        if _py_ch.name.lower().startswith("python") and _sp_py.is_dir():
                            _vs_r2 = _realpath(_abspath(_str(_sp_py))).lower().rstrip(_strip_chars)
                            if _vs_r2 and _vs_r2 not in _trusted_site_list:
                                _trusted_site_list.append(_vs_r2)
            except _BaseExc:
                pass
    _trusted_site_dirs = _tuple(_trusted_site_list)
    _raw_mod_block = frozenset({"ctypes", "_ctypes", "_winapi", "msvcrt", "winreg"})
    _ctypes_ev_block = frozenset({"ctypes.dlopen", "ctypes.dlsym", "ctypes.cdata"})

    def _is_trusted_internal_caller(skip_ctypes=False):
        if not _restrict_ws:
            return True
        f = _getframe(1)
        while f is not None:
            co = f.f_code
            fn = co.co_filename or ""
            if fn.startswith("<frozen ") or co.co_name in (
                "_hook", "_guarded_import", "_guarded_import_module", "_is_trusted_internal_caller"
            ):
                f = f.f_back
                continue
            fn_l = fn.lower()
            if skip_ctypes and ("\\ctypes\\" in fn_l or "/ctypes/" in fn_l):
                f = f.f_back
                continue
            if fn.startswith("<"):
                return False
            try:
                fn_real = _realpath(_abspath(fn)).lower()
            except _BaseExc:
                return False
            if (fn_real.endswith("\\importlib\\__init__.py") or fn_real.endswith("/importlib/__init__.py")) and co.co_name == "import_module":
                f = f.f_back
                continue
            if fn_real.endswith("\\runpy.py") or fn_real.endswith("/runpy.py"):
                return False
            if _under(fn_real, _stdlib_dir) or _any(_under(fn_real, sd) for sd in _trusted_site_dirs):
                return True
            if _under_any_ws(fn_real):
                return False
            return False
        return False

    _orig_import = builtins.__import__
    def _guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and _isinstance(name, _str) and name.split(".", 1)[0] in _raw_mod_block:
            if not _is_trusted_internal_caller(skip_ctypes=False):
                raise _PermErr(f"[COSMOS L3 SANDBOX]: import {name} is prohibited in Tier L3.")
        return _orig_import(name, globals, locals, fromlist, level)

    _orig_imp_mod = importlib.import_module
    def _guarded_import_module(name, package=None):
        eff_n = name.lstrip(".") if _isinstance(name, _str) else ""
        if eff_n and eff_n.split(".", 1)[0] in _raw_mod_block:
            if not _is_trusted_internal_caller(skip_ctypes=False):
                raise _PermErr(f"[COSMOS L3 SANDBOX]: import {name} is prohibited in Tier L3.")
        return _orig_imp_mod(name, package)

    builtins.__import__ = _guarded_import
    importlib.import_module = _guarded_import_module

    _orig_os_open = os.open
    def _guarded_os_open(path, flags, mode=0o777, *, dir_fd=None):
        iw = _bool(flags & _wflags)
        b_dir = _resolve_dfd(dir_fd) if (dir_fd is not None and _isinstance(dir_fd, _int) and dir_fd >= 0) else None
        if _isinstance(path, _ptypes):
            res_p = _chk_p(path, iw, base_dir=b_dir)
        else:
            raise _PermErr("[COSMOS L3 SANDBOX]: Non-path os.open target is prohibited in Tier L3.")
        fd_out = _orig_os_open(path, flags, mode, dir_fd=dir_fd) if dir_fd is not None else _orig_os_open(path, flags, mode)
        if res_p:
            _fd_map[fd_out] = res_p
        return fd_out

    os.open = _guarded_os_open
    if not _is_win and "posix" in sys.modules:
        try:
            sys.modules["posix"].open = _guarded_os_open
        except _BaseExc:
            pass

    def _chk_dfd_arg(args, idx):
        if _len(args) > idx:
            dv = args[idx]
            if _isinstance(dv, _int) and dv >= 0:
                return _resolve_dfd(dv)
        return None

    def _hook(ev, args):
        if ev in _ctypes_ev_block or ev.startswith("ctypes."):
            if not _is_trusted_internal_caller(skip_ctypes=True):
                raise _PermErr(f"[COSMOS L3 SANDBOX]: {ev} is prohibited in Tier L3.")
            return
        if ev == "import":
            mn = args[0] if _len(args) > 0 else ""
            if _isinstance(mn, _str) and mn.split(".", 1)[0] in _raw_mod_block:
                if not _is_trusted_internal_caller(skip_ctypes=False):
                    raise _PermErr(f"[COSMOS L3 SANDBOX]: import {mn} is prohibited in Tier L3.")
            return
        if _any(ev.startswith(p) for p in _proc_block_prefixes):
            if _restrict_ws:
                raise _PermErr(f"[COSMOS L3 SANDBOX]: {ev} is prohibited in Tier L3; use workspace-scoped subprocesses.")
            return
        if ev in ("os.putenv", "os.unsetenv"):
            ek_p = _fsd(args[0]).strip().upper() if (_len(args) > 0 and _isinstance(args[0], _ptypes)) else ""
            if ek_p in _prot_env_keys:
                raise _PermErr(f"[COSMOS L3 SANDBOX]: mutating {ek_p} is prohibited in Tier L3.")
            return
        if ev in ("object.__setattr__", "object.__delattr__"):
            tgt_obj = args[0] if _len(args) > 0 else None
            an = args[1] if _len(args) > 1 else ""
            if tgt_obj in (_guarded_os_open, _guarded_import, _guarded_import_module, _is_trusted_internal_caller, _hook, _chk_p, _resolve_dfd, _under, _under_any_ws) or an in _prot_attrs:
                raise _PermErr(f"[COSMOS L3 SANDBOX]: mutating {an} is prohibited in Tier L3.")
            return
        if ev == "sqlite3.connect":
            db_t = args[0] if _len(args) > 0 else ""
            if _isinstance(db_t, _ptypes):
                dbs = _fsd(db_t).strip()
                if dbs == ":memory:" or dbs.startswith("file::memory:") or "mode=memory" in dbs.lower():
                    return
                is_ro = False
                if dbs.lower().startswith("file:"):
                    parsed_u = _urlsplit(dbs)
                    is_ro = "mode=ro" in (parsed_u.query or "").lower()
                    u_path = _unquote(parsed_u.path or "")
                    if _is_win and u_path.startswith("/") and _len(u_path) > 2 and u_path[2] == ":":
                        u_path = u_path[1:]
                    dbs = u_path or dbs[5:]
                if dbs and dbs != ":memory:":
                    _chk_p(dbs, not is_ro)
            return
        if ev == "subprocess.Popen":
            argv_a = args[1] if _len(args) > 1 else None
            cwd_a = args[2] if _len(args) > 2 else None
            env_a = args[3] if _len(args) > 3 else None
            if cwd_a is not None and _isinstance(cwd_a, _ptypes):
                _chk_p(cwd_a, False)
            if _isinstance(env_a, _dict):
                req_ws = (
                    env_a.get("COSMOS_L3_WORKSPACES")
                    or env_a.get(b"COSMOS_L3_WORKSPACES")
                    or env_a.get("LOCALPC_L3_WORKSPACE")
                    or env_a.get(b"LOCALPC_L3_WORKSPACE")
                )
                pp_v = env_a.get("PYTHONPATH") or env_a.get(b"PYTHONPATH") or ""
                if _isinstance(pp_v, bytes):
                    pp_v = _fsd(pp_v)
                if not req_ws or _guard_low not in _str(pp_v).lower():
                    raise _PermErr("[COSMOS L3 SANDBOX]: Stripping L3 sandbox environment variables in subprocess.Popen is prohibited.")
            if _isinstance(argv_a, _ptypes):
                _argv_list = [(m[0] if m[0] != "" else m[1]) for m in _pop_tok_rx.findall(_fsd(argv_a))]
            elif _isinstance(argv_a, (list, tuple)):
                _argv_list = [_fsd(x) for x in argv_a if _isinstance(x, _ptypes)]
            else:
                _argv_list = []
            if _len(_argv_list) > 0:
                a0 = _argv_list[0].lower()
                a0_base = _Path(a0).stem if a0 else ""
                is_py_bin = a0_base.startswith("python") or a0_base == "py"
                _allow_iso_pip = (
                    is_py_bin
                    and _len(_argv_list) >= 5
                    and _argv_list[1].strip() == "-I"
                    and _argv_list[2].strip() == "-m"
                    and _argv_list[3].strip().lower() == "pip"
                    and _argv_list[4].strip().lower() == "install"
                )
                for _i_tok, tok_i in enumerate(_argv_list[1:], 1):
                    ts_i = tok_i.strip()
                    if is_py_bin and _py_iso_rx.match(ts_i) and not (_allow_iso_pip and _i_tok == 1):
                        raise _PermErr("[COSMOS L3 SANDBOX]: Python -I/-E/-S isolation flags are prohibited in Tier L3.")
                    if not ts_i or ts_i.startswith("-"):
                        continue
                    p_i = _Path(ts_i)
                    if p_i.is_absolute() or ".." in p_i.parts:
                        _chk_p(ts_i, False, base_dir=_fsd(cwd_a) if (cwd_a and _isinstance(cwd_a, _ptypes)) else None)
            return
        if ev in _mut_1:
            t0 = args[0] if _len(args) > 0 else None
            dfd_idx = 2 if ev == "os.mkdir" else 1
            b_d = _chk_dfd_arg(args, dfd_idx)
            if _isinstance(t0, _int):
                _chk_p(_resolve_dfd(t0), True)
            elif _isinstance(t0, _ptypes):
                _chk_p(t0, True, base_dir=b_d)
            return
        if ev in _mut_2:
            if ev == "os.symlink":
                b_dst = _chk_dfd_arg(args, 2)
                t_dst = args[1] if _len(args) > 1 else None
                if _isinstance(t_dst, _ptypes):
                    _chk_p(t_dst, True, base_dir=b_dst)
                t_src = args[0] if _len(args) > 0 else None
                if _isinstance(t_src, _ptypes):
                    _chk_p(t_src, False, base_dir=b_dst)
            else:
                b0 = _chk_dfd_arg(args, 2)
                b1 = _chk_dfd_arg(args, 3)
                t0 = args[0] if _len(args) > 0 else None
                t1 = args[1] if _len(args) > 1 else None
                if _isinstance(t0, _ptypes):
                    _chk_p(t0, True, base_dir=b0)
                if _isinstance(t1, _ptypes):
                    _chk_p(t1, True, base_dir=b1)
            return
        if ev in _dir_ev:
            td = args[0] if _len(args) > 0 else None
            if _isinstance(td, _int):
                _chk_p(_resolve_dfd(td), False)
            elif _isinstance(td, _ptypes):
                _chk_p(td, False)
            return
        if ev == "open":
            to = args[0] if _len(args) > 0 else None
            mo = args[1] if _len(args) > 1 else "r"
            fl = args[2] if _len(args) > 2 else 0
            iw = (_isinstance(mo, _str) and _any(c in _wchars for c in mo)) or (_isinstance(fl, _int) and (fl & _wflags) != 0)
            if _isinstance(to, _int):
                if to in _fd_map:
                    _chk_p(_fd_map[to], iw)
                elif not _is_win and to not in (0, 1, 2):
                    try:
                        _fd_t = _readlink(f"/proc/self/fd/{to}") if _readlink is not None else ""
                    except _BaseExc:
                        _fd_t = ""
                    if _fd_t.startswith("/"):
                        _chk_p(_fd_t, iw)
                return
            if _isinstance(to, _ptypes):
                _chk_p(to, iw)

    sys.addaudithook(_hook)

_install_cosmos_l3_hook()
del _install_cosmos_l3_hook, builtins, importlib, os, re, sys, urllib, Path
"""


def _norm_dir_key(raw_p: str) -> str:
    return os.path.normcase(os.path.normpath(raw_p.strip().strip('"'))).rstrip("\\/")


def ensure_l3_sandbox_files(state_root: Union[Path, str]) -> Tuple[Path, Path, Path]:
    """
    Create L3 sandbox hook & temp directories and write `sitecustomize.py`.
    Fail-Closed: ANY filesystem failure raises `PermissionError("ERR_L3_SANDBOX_INIT_FAILED: ...")`.
    """
    try:
        sr = Path(state_root).expanduser()
        if sr.exists() and not sr.is_dir():
            raise OSError(f"state_root is not a directory: {sr}")
        guard_dir = (sr / "state" / "l3_py_guard")
        tmp_dir = (sr / "state" / "tmp_l3_sandbox")
        mpl_dir = tmp_dir / "mplconfig"
        guard_dir.mkdir(parents=True, exist_ok=True)
        tmp_dir.mkdir(parents=True, exist_ok=True)
        mpl_dir.mkdir(parents=True, exist_ok=True)
        sc_file = guard_dir / "sitecustomize.py"
        need_write = True
        if sc_file.is_file():
            existing = sc_file.read_text(encoding="utf-8")
            if existing == L3_SITECUSTOMIZE_SOURCE:
                need_write = False
        if need_write:
            tmp_sc = guard_dir / f".sitecustomize.{os.getpid()}.tmp"
            tmp_sc.write_text(L3_SITECUSTOMIZE_SOURCE, encoding="utf-8")
            os.replace(str(tmp_sc), str(sc_file))
        if not sc_file.is_file() or sc_file.read_text(encoding="utf-8") != L3_SITECUSTOMIZE_SOURCE:
            raise OSError(f"Verification of {sc_file} failed after write")
        return canonical_realpath(guard_dir), canonical_realpath(tmp_dir), canonical_realpath(sc_file)
    except PermissionError as exc:
        if ERR_L3_SANDBOX_INIT_FAILED in str(exc):
            raise
        raise PermissionError(f"{ERR_L3_SANDBOX_INIT_FAILED}: {exc}") from exc
    except Exception as exc:
        raise PermissionError(f"{ERR_L3_SANDBOX_INIT_FAILED}: {exc}") from exc


def prepare_l3_sandbox_env(
    env: Mapping[str, str],
    workspace_roots: Sequence[Union[Path, str]],
    state_root: Union[Path, str],
    *,
    readonly_workspace_roots: Optional[Sequence[Union[Path, str]]] = None,
    scan_host_global_skills: Optional[bool] = None,
    allow_host_global_skills: Optional[bool] = None,
    protect_host_credentials: Optional[bool] = None,
    protect_dotenv_files: Optional[bool] = None,
    restrict_to_workspace: bool = True,
    enable_audit_hook: bool = True,
) -> Dict[str, str]:
    """
    Inject L3 `sitecustomize.py` directory at `PYTHONPATH`[0] and configure sandbox env vars.
    Fail-Closed: raises `PermissionError("ERR_L3_SANDBOX_INIT_FAILED: ...")` if hook setup fails.
    """
    out_env = dict(env)
    sep = os.pathsep

    resolved_ro_roots: List[str] = []
    if readonly_workspace_roots is not None:
        for ro_r in readonly_workspace_roots:
            if ro_r is not None and str(ro_r).strip():
                ro_p = str(canonical_realpath(ro_r))
                if ro_p and ro_p not in resolved_ro_roots:
                    resolved_ro_roots.append(ro_p)
    elif (out_env.get("COSMOS_L3_READONLY_WORKSPACES") or "").strip():
        for ro_part in out_env["COSMOS_L3_READONLY_WORKSPACES"].split(sep):
            if ro_part.strip():
                ro_p = str(canonical_realpath(ro_part.strip()))
                if ro_p and ro_p not in resolved_ro_roots:
                    resolved_ro_roots.append(ro_p)

    if not enable_audit_hook or (not restrict_to_workspace and not resolved_ro_roots):
        try:
            sr_cand = canonical_realpath(state_root)
            guard_cand_key = _norm_dir_key(str(sr_cand / "state" / "l3_py_guard"))
        except Exception:
            guard_cand_key = ""
        existing_pp = [
            p
            for p in (out_env.get("PYTHONPATH") or "").split(sep)
            if p and (not guard_cand_key or _norm_dir_key(p) != guard_cand_key)
        ]
        if existing_pp:
            out_env["PYTHONPATH"] = sep.join(existing_pp)
        else:
            out_env.pop("PYTHONPATH", None)
        for k in (
            "COSMOS_L3_WORKSPACES",
            "LOCALPC_L3_WORKSPACE",
            "COSMOS_L3_READONLY_WORKSPACES",
            "COSMOS_L3_RESTRICT_WS",
            "COSMOS_L3_SCAN_HOST_SKILLS",
            "COSMOS_L3_PROTECT_CREDENTIALS",
            "COSMOS_L3_PROTECT_DOTENV",
            "COSMOS_L3_ALLOW_TMP",
            "LOCALPC_L3_ALLOW_TMP",
            "COSMOS_L3_STATE_ROOT",
            "LOCALPC_L3_STATE_ROOT",
        ):
            out_env.pop(k, None)
        return out_env

    resolved_roots: List[str] = []
    for r in workspace_roots:
        if r is not None and str(r).strip():
            rp = str(canonical_realpath(r))
            if rp and rp not in resolved_roots:
                resolved_roots.append(rp)
    if restrict_to_workspace and not resolved_roots:
        raise PermissionError(f"{ERR_L3_SANDBOX_INIT_FAILED}: workspace_roots must not be empty when restrict_to_workspace=True")
    for ro_item in resolved_ro_roots:
        if ro_item not in resolved_roots:
            resolved_roots.append(ro_item)

    if scan_host_global_skills is not None:
        eff_scan_skills = bool(scan_host_global_skills)
    elif allow_host_global_skills is not None:
        eff_scan_skills = bool(allow_host_global_skills)
    elif "COSMOS_L3_SCAN_HOST_SKILLS" in out_env:
        eff_scan_skills = str(out_env.get("COSMOS_L3_SCAN_HOST_SKILLS") or "").strip().lower() in ("1", "true", "yes", "on")
    else:
        eff_scan_skills = False

    guard_dir, tmp_dir, _ = ensure_l3_sandbox_files(state_root)
    sr_resolved = str(canonical_realpath(state_root))
    guard_key = _norm_dir_key(str(guard_dir))
    existing_pp = [p for p in (out_env.get("PYTHONPATH") or "").split(sep) if p and _norm_dir_key(p) != guard_key]

    eff_prot_cred = bool(protect_host_credentials) if protect_host_credentials is not None else True
    eff_prot_dotenv = bool(protect_dotenv_files) if protect_dotenv_files is not None else False

    joined_ws = sep.join(resolved_roots)
    out_env["COSMOS_L3_WORKSPACES"] = joined_ws
    out_env["LOCALPC_L3_WORKSPACE"] = resolved_roots[0] if resolved_roots else ""
    out_env["COSMOS_L3_READONLY_WORKSPACES"] = sep.join(resolved_ro_roots)
    out_env["COSMOS_L3_RESTRICT_WS"] = "1" if restrict_to_workspace else "0"
    out_env["COSMOS_L3_SCAN_HOST_SKILLS"] = "1" if eff_scan_skills else "0"
    out_env["COSMOS_L3_PROTECT_CREDENTIALS"] = "1" if eff_prot_cred else "0"
    out_env["COSMOS_L3_PROTECT_DOTENV"] = "1" if eff_prot_dotenv else "0"
    out_env["COSMOS_L3_ALLOW_TMP"] = str(tmp_dir)
    out_env["LOCALPC_L3_ALLOW_TMP"] = str(tmp_dir)
    out_env["COSMOS_L3_STATE_ROOT"] = sr_resolved
    out_env["LOCALPC_L3_STATE_ROOT"] = sr_resolved
    out_env["TMP"] = str(tmp_dir)
    out_env["TEMP"] = str(tmp_dir)
    out_env["TMPDIR"] = str(tmp_dir)
    out_env["MPLCONFIGDIR"] = str(tmp_dir / "mplconfig")
    out_env["PYTHONPATH"] = sep.join([str(guard_dir)] + existing_pp)
    return out_env


BATCH_PROBE_RUNNER_SCRIPT = r"""import ast, builtins, contextlib, fnmatch, importlib, io, json, os, re, sys, traceback, urllib.parse
from pathlib import Path

def _bootstrap_probe():
    payload = json.loads(sys.stdin.read())
    proj = Path(payload["proj"]).resolve()
    ws_roots_raw = payload.get("ws_roots") or []
    restrict_ws = bool(payload.get("restrict_ws", True))
    read_blocked_raw = payload.get("read_blocked") or []
    sr_raw = str(payload.get("state_root") or "").strip()
    _env_shs = os.environ.get("COSMOS_L3_SCAN_HOST_SKILLS")
    if _env_shs is not None and _env_shs.strip() != "":
        _scan_host_skills = _env_shs.strip() == "1"
    else:
        _scan_host_skills = bool(payload.get("scan_host_global_skills") or payload.get("allow_host_global_skills"))

    _sep = "\\" if sys.platform == "win32" else "/"
    _strip = _sep + "/"
    _ws_roots = tuple(os.path.realpath(str(w)).lower().rstrip(_strip) for w in ws_roots_raw if w)
    _read_b_list = [os.path.realpath(str(b)).lower().rstrip(_strip) for b in read_blocked_raw if b]
    if sr_raw:
        _sr_base = os.path.realpath(sr_raw).lower().rstrip(_strip)
        for _sr_sub in ("secrets", "state", "config", ".env"):
            _sr_item = _sr_base + _sep + _sr_sub
            if _sr_item not in _read_b_list:
                _read_b_list.append(_sr_item)
    _read_blocked = tuple(_read_b_list)
    _home = Path.home()
    _ro_cands = [
        Path(sys.prefix),
        Path(sys.base_prefix),
        _home / ".cache",
        _home / ".huggingface",
        _home / ".matplotlib",
        _home / ".config" / "matplotlib",
    ]
    if _scan_host_skills:
        _ro_cands.extend([
            _home / ".agents" / "skills",
            _home / ".claude" / "skills",
            _home / ".cursor" / "skills",
            _home / ".codeium" / "windsurf" / "skills",
            _home / ".codex" / "skills",
            _home / ".gemini" / "skills",
            _home / ".cc-switch" / "skills",
            _home / ".cosmos-skills" / "skills_store",
        ])
    if sr_raw:
        _ro_cands.append(Path(sr_raw) / "skills_store")
        _ro_cands.append(Path(sr_raw) / "host_skills")
        _ro_cands.append(Path(sr_raw) / "app_src" / "host_skills")
    _venv_site_cands = []
    _venv_base_roots = [proj] + [Path(w) for w in ws_roots_raw if w]
    for _vb in _venv_base_roots:
        for _vn in (".venv", "venv"):
            _vp = _vb / _vn
            for _sp_cand in (_vp / "Lib" / "site-packages", _vp / "lib" / "site-packages"):
                try:
                    if _sp_cand.is_dir() and _sp_cand not in _venv_site_cands:
                        _venv_site_cands.append(_sp_cand)
                except BaseException:
                    pass
            try:
                _vlib = _vp / "lib"
                if _vlib.is_dir():
                    for _pch in _vlib.iterdir():
                        _sp_py = _pch / "site-packages"
                        if _pch.name.lower().startswith("python") and _sp_py.is_dir() and _sp_py not in _venv_site_cands:
                            _venv_site_cands.append(_sp_py)
            except BaseException:
                pass
    for _vsp in _venv_site_cands:
        _ro_cands.append(_vsp)
        _vsp_s = str(_vsp)
        if not any(os.path.normcase(os.path.abspath(p)) == os.path.normcase(os.path.abspath(_vsp_s)) for p in sys.path if p):
            sys.path.append(_vsp_s)
    for _sp in sys.path:
        if _sp:
            if "site-packages" in _sp.lower() or "dist-packages" in _sp.lower():
                _ro_cands.append(Path(_sp))
            _sp_p = Path(_sp)
            for _hs_c in (_sp_p / "host_skills", _sp_p.parent / "host_skills"):
                if _hs_c.is_dir():
                    _ro_cands.append(_hs_c)
    _allowed_imp = tuple(dict.fromkeys(
        os.path.realpath(str(c)).lower().rstrip(_strip) for c in _ro_cands
    ))
    _prot_cred = bool(payload.get("protect_host_credentials", True))
    _prot_dotenv = bool(payload.get("protect_dotenv_files", False))
    _home_npmrc_low = os.path.realpath(os.path.abspath(str(_home / ".npmrc"))).lower().rstrip(_strip)
    _sens_pats = [
        r"(?:^|[\\/])(?:owner_password\.txt|连接信息_CONNECTION_INFO[^\\/]*\.txt|latest_consent_pair_code[^\\/]*\.txt|oauth(?:_[a-z0-9_.-]+)?\.sqlite3(?:-wal|-shm)?|\.(?:human_ui_secret|peer_hmac_secret))$",
    ]
    if _prot_cred:
        _sens_pats.extend([
            r"(?:^|[\\/])\.(?:ssh|aws|gnupg|kube|azure)(?:$|[\\/])",
            r"(?:^|[\\/])\.cargo[\\/]credentials(?:\.toml)?$",
            r"(?:^|[\\/])\.?huggingface[\\/](?:token|stored_tokens)(?:$|[\\/])",
            r"(?:^|[\\/])\.(?:git-credentials|pypirc|netrc)$",
        ])
    if _prot_dotenv:
        _sens_pats.append(
            r"(?:^|[\\/])\.env(?:\.(?!(?:example|template|sample|dist|defaults)$)[a-z0-9_.-]+)?$"
        )
    _sens_rxs = tuple(re.compile(p, re.IGNORECASE) for p in _sens_pats)
    _ads_rx = re.compile(r"::\$[A-Za-z0-9_]+")
    _ignored_dirs = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build", ".undo_history", "target"}

    def _under(c_l, b_l):
        return bool(b_l) and (c_l == b_l or c_l.startswith(b_l + _sep))

    def _check_read(raw_t, for_chdir=False):
        ts = os.fsdecode(raw_t)
        if _ads_rx.search(ts):
            raise PermissionError("[COSMOS BATCH PROBE]: NTFS Alternate Data Streams are prohibited.")
        res_s = os.path.realpath(os.path.abspath(ts))
        tl = res_s.lower().rstrip(_strip)
        if any(_under(tl, rb) for rb in _read_blocked):
            raise PermissionError("[COSMOS BATCH PROBE]: MCP secrets and state files are isolated.")
        if any(rx.search(res_s) or rx.search(ts) for rx in _sens_rxs):
            raise PermissionError("[COSMOS BATCH PROBE]: Sensitive host credential path is isolated.")
        if _prot_cred and tl.endswith(_sep + ".npmrc") and (
            tl == _home_npmrc_low or (restrict_ws and _ws_roots and not any(_under(tl, w) for w in _ws_roots))
        ):
            raise PermissionError("[COSMOS BATCH PROBE]: Sensitive host credential path is isolated.")
        if not for_chdir and any(_under(tl, ap) for ap in _allowed_imp):
            return res_s
        if restrict_ws and _ws_roots and not any(_under(tl, w) for w in _ws_roots):
            raise PermissionError(f"[COSMOS BATCH PROBE]: Read outside workspace roots {_ws_roots} is blocked.")
        return res_s

    def _rg(pat, glob="", max_results=50):
        rx = re.compile(pat)
        hits = []
        cap = max(1, min(200, int(max_results)))
        for root_d, dirs, files in os.walk(proj):
            dirs[:] = [d for d in sorted(dirs) if not d.startswith(".") and d.lower() not in _ignored_dirs]
            for fn in sorted(files):
                if glob and not fnmatch.fnmatch(fn, glob):
                    continue
                fp = Path(root_d) / fn
                try:
                    _check_read(str(fp))
                    if fp.stat().st_size > 2 * 1024 * 1024:
                        continue
                    for idx, ln in enumerate(fp.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                        if rx.search(ln):
                            hits.append(f"{fp}:{idx}:{ln[:200]}")
                            if len(hits) >= cap:
                                return hits
                except PermissionError:
                    raise
                except Exception:
                    continue
        return hits

    def _outline(rel_or_abs):
        p = Path(rel_or_abs)
        fp = p.resolve() if p.is_absolute() else (proj / p).resolve()
        _check_read(str(fp))
        txt = fp.read_text(encoding="utf-8", errors="replace")
        lines = txt.splitlines()
        syms = []
        if fp.suffix.lower() == ".py":
            tree = ast.parse(txt)
            for nd in ast.walk(tree):
                if isinstance(nd, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    sl = int(getattr(nd, "lineno", 1))
                    el = int(getattr(nd, "end_lineno", sl) or sl)
                    syms.append({"line": sl, "end_line": el, "name": nd.name, "kind": type(nd).__name__})
            syms.sort(key=lambda x: x["line"])
        return {"ok": True, "path": str(fp), "total_lines": len(lines), "symbols": syms}

    def _list_dir(rel_or_abs=".", max_entries=200):
        p = Path(rel_or_abs)
        base = p.resolve() if p.is_absolute() else (proj / p).resolve()
        _check_read(str(base))
        if not base.is_dir():
            return []
        return [x.name + ("/" if x.is_dir() else "") for x in sorted(base.iterdir())[:max_entries]]

    for _bm in ("_tkinter", "tkinter", "urllib.request", "http.client"):
        sys.modules.pop(_bm, None)

    _any = any
    _isinstance = isinstance
    _str = str
    _int = int
    _len = len
    _PermErr = PermissionError
    _getframe = sys._getframe
    _urlsplit = urllib.parse.urlsplit
    _unquote = urllib.parse.unquote
    _is_win = sys.platform == "win32"
    _stdlib_dir = os.path.realpath(os.path.dirname(os.__file__)).lower().rstrip(_strip)
    _trusted_site_list = []
    for _p_sp in sys.path:
        if _p_sp and ("site-packages" in _p_sp.lower() or "dist-packages" in _p_sp.lower()):
            _sp_r = os.path.realpath(str(_p_sp)).lower().rstrip(_strip)
            if _sp_r and _sp_r not in _trusted_site_list:
                if (
                    not any(_under(_sp_r, w) for w in _ws_roots)
                    or ((_sep + ".venv" + _sep) in _sp_r)
                    or ((_sep + "venv" + _sep) in _sp_r)
                ):
                    _trusted_site_list.append(_sp_r)
    for _vsp_t in _venv_site_cands:
        _vr_t = os.path.realpath(str(_vsp_t)).lower().rstrip(_strip)
        if _vr_t and _vr_t not in _trusted_site_list:
            _trusted_site_list.append(_vr_t)
    _trusted_site_dirs = tuple(_trusted_site_list)
    _raw_mod_block = frozenset({
        "ctypes", "_ctypes", "_winapi", "msvcrt", "winreg",
        "subprocess", "_posixsubprocess", "shutil", "socket",
    })
    _ctypes_ev_block = frozenset({"ctypes.dlopen", "ctypes.dlsym", "ctypes.cdata"})

    def _is_trusted_internal_caller(skip_ctypes=False):
        f = _getframe(1)
        while f is not None:
            co = f.f_code
            fn = co.co_filename or ""
            if fn.startswith("<frozen ") or co.co_name in (
                "_ro_hook", "_guarded_import", "_guarded_import_module", "_is_trusted_internal_caller"
            ):
                f = f.f_back
                continue
            fn_l = fn.lower()
            if skip_ctypes and ("\\ctypes\\" in fn_l or "/ctypes/" in fn_l):
                f = f.f_back
                continue
            if fn.startswith("<"):
                return False
            try:
                fn_real = os.path.realpath(fn).lower()
            except BaseException:
                return False
            if (fn_real.endswith("\\importlib\\__init__.py") or fn_real.endswith("/importlib/__init__.py")) and co.co_name == "import_module":
                f = f.f_back
                continue
            if fn_real.endswith("\\runpy.py") or fn_real.endswith("/runpy.py"):
                return False
            if _under(fn_real, _stdlib_dir) or any(_under(fn_real, sd) for sd in _trusted_site_dirs):
                return True
            if any(_under(fn_real, w) for w in _ws_roots):
                return False
            return False
        return False

    _orig_import = builtins.__import__
    def _guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and _isinstance(name, _str):
            top_m = name.split(".", 1)[0]
            if top_m in _raw_mod_block or top_m == "importlib":
                if not _is_trusted_internal_caller(skip_ctypes=False):
                    raise _PermErr(f"[COSMOS BATCH PROBE]: import {name} is prohibited in read-only batch_probe.")
        return _orig_import(name, globals, locals, fromlist, level)

    _orig_imp_mod = importlib.import_module
    def _guarded_import_module(name, package=None):
        eff_n = name.lstrip(".") if _isinstance(name, _str) else ""
        if eff_n and (eff_n.split(".", 1)[0] in _raw_mod_block or eff_n.split(".", 1)[0] == "importlib"):
            if not _is_trusted_internal_caller(skip_ctypes=False):
                raise _PermErr(f"[COSMOS BATCH PROBE]: import {name} is prohibited in read-only batch_probe.")
        return _orig_imp_mod(name, package)

    builtins.__import__ = _guarded_import
    importlib.import_module = _guarded_import_module

    _wflags = int(os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
    _wchars = frozenset({"w", "a", "x", "+"})
    _ptypes = (str, bytes, os.PathLike)
    _os_mut = tuple("os." + x for x in (
        "system", "popen", "exec", "spawn", "posix_spawn", "fork", "startfile",
        "remove", "unlink", "rmdir", "removedirs", "rename", "replace",
        "truncate", "ftruncate", "mkdir", "makedirs", "chmod", "chown", "link", "symlink",
    ))
    _blocked_ev = frozenset({
        "sys._current_frames", "_tkinter.", "tkinter.",
        "subprocess.", "_posixsubprocess.", "shutil.",
        "socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg",
        "winreg.CreateKey", "winreg.SetValue", "winreg.DeleteKey", "winreg.DeleteValue",
        "urllib.request", "http.client", "ftplib.", "smtplib.", "telnetlib.",
        "webbrowser.", "pty.",
    } | set(_os_mut))
    _blocked_imp = frozenset({
        "_tkinter", "tkinter",
        "ftplib", "smtplib", "telnetlib", "xmlrpc", "webbrowser", "pty", "tty", "termios",
        "bdb", "pdb",
    })
    _prot_fns = (_check_read, _rg, _outline, _list_dir, _guarded_import, _guarded_import_module, _is_trusted_internal_caller)
    _dir_ev = frozenset({"os.listdir", "os.scandir", "glob.glob", "os.chdir"})

    def _ro_hook(ev, args):
        if ev in _ctypes_ev_block or ev.startswith("ctypes."):
            if not _is_trusted_internal_caller(skip_ctypes=True):
                raise _PermErr(f"[COSMOS BATCH PROBE]: {ev} is prohibited in read-only batch_probe.")
            return
        if ev == "sqlite3.connect":
            db_t = args[0] if _len(args) > 0 else ""
            if not _isinstance(db_t, _ptypes):
                raise _PermErr("[COSMOS BATCH PROBE]: non-string sqlite3.connect target is prohibited.")
            dbs = os.fsdecode(db_t).strip()
            dbs_low = dbs.lower()
            if dbs == ":memory:" or dbs_low.startswith("file::memory:") or "mode=memory" in dbs_low:
                return
            if dbs_low.startswith("file:"):
                parsed_u = _urlsplit(dbs)
                q_params = [p.strip().lower() for p in (parsed_u.query or "").split("&") if p.strip()]
                if "mode=ro" in q_params:
                    u_path = _unquote(parsed_u.path or "")
                    if _is_win and _len(u_path) > 2 and u_path[0] == "/" and u_path[2] == ":":
                        u_path = u_path[1:]
                    if not u_path and parsed_u.netloc and parsed_u.netloc.lower() != "localhost":
                        raise _PermErr("[COSMOS BATCH PROBE]: remote UNC sqlite3 URI is prohibited.")
                    if u_path and u_path != ":memory:":
                        _check_read(u_path)
                    return
            raise _PermErr(
                "[COSMOS BATCH PROBE]: sqlite3.connect in read-only batch_probe requires ':memory:' or URI 'file:...?mode=ro' (with uri=True)."
            )
        if _any(ev.startswith(bp) for bp in _blocked_ev):
            raise _PermErr(f"[COSMOS BATCH PROBE]: {ev} is prohibited in read-only batch_probe.")
        if ev in ("object.__setattr__", "object.__delattr__"):
            tgt_o = args[0] if _len(args) > 0 else None
            an = args[1] if _len(args) > 1 else ""
            if tgt_o is _ro_hook or tgt_o in _prot_fns or an in ("__closure__", "__globals__", "cell_contents"):
                raise _PermErr(f"[COSMOS BATCH PROBE]: mutating {an} is prohibited.")
        if ev == "import":
            mn = args[0] if _len(args) > 0 else ""
            if _isinstance(mn, _str):
                top_mn = mn.split(".", 1)[0]
                if top_mn in _blocked_imp:
                    raise _PermErr(f"[COSMOS BATCH PROBE]: import {mn} is prohibited in read-only batch_probe.")
                if top_mn in _raw_mod_block or top_mn == "importlib":
                    if not _is_trusted_internal_caller(skip_ctypes=False):
                        raise _PermErr(f"[COSMOS BATCH PROBE]: import {mn} is prohibited in read-only batch_probe.")
        if ev in _dir_ev:
            tgt = args[0] if _len(args) > 0 else None
            if _isinstance(tgt, _int):
                raise _PermErr("[COSMOS BATCH PROBE]: integer fd directory listing is prohibited.")
            if _isinstance(tgt, _ptypes):
                _check_read(tgt, for_chdir=(ev == "os.chdir"))
        if ev == "open":
            tgt = args[0] if _len(args) > 0 else None
            mo = args[1] if _len(args) > 1 else "r"
            fl = args[2] if _len(args) > 2 else 0
            if mo is None:
                raise _PermErr("[COSMOS BATCH PROBE]: low-level os.open is prohibited in read-only batch_probe.")
            if _isinstance(mo, _str) and _any(c in _wchars for c in mo):
                raise _PermErr("[COSMOS BATCH PROBE]: file write open is prohibited in read-only batch_probe.")
            if _isinstance(fl, _int) and (fl & _wflags):
                raise _PermErr("[COSMOS BATCH PROBE]: write flags are prohibited in read-only batch_probe.")
            if _isinstance(tgt, _int):
                raise _PermErr("[COSMOS BATCH PROBE]: integer fd open is prohibited in read-only batch_probe.")
            if _isinstance(tgt, _ptypes):
                _check_read(tgt)

    code_str = payload["code"]
    buf = io.StringIO()
    env_g = {
        "__builtins__": __builtins__,
        "Path": Path,
        "json": json,
        "re": re,
        "PROJ": proj,
        "rg": _rg,
        "outline": _outline,
        "list_dir": _list_dir,
        "RESULT": {},
    }
    sys.addaudithook(_ro_hook)
    try:
        with contextlib.redirect_stdout(buf):
            exec(compile(code_str, "<batch_probe>", "exec"), env_g, env_g)
        res_val = env_g.get("RESULT")
        try:
            json.dumps(res_val)
        except BaseException:
            res_val = str(res_val)[:8000]
        print(json.dumps({"ok": True, "stdout": buf.getvalue()[:16000], "result": res_val}, ensure_ascii=False))
    except BaseException as exc:
        print(json.dumps({
            "ok": False,
            "stdout": buf.getvalue()[:8000],
            "error": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc()[-6000:],
        }, ensure_ascii=False))

_bootstrap_probe()
"""
