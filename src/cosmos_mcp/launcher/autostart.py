"""Cross-platform idempotent login-session autostart manager (`HKCU Run` / `LaunchAgents` / `systemd --user`).

Enforces:
- Pure Python standard library + `cosmos_mcp.core` + `cosmos_mcp.launcher.bootstrap`.
- Windows uses `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run` with `pythonw.exe` (NEVER `.vbs`).
- macOS uses `~/Library/LaunchAgents/com.cosmos.mcp*.plist` (`plistlib`).
- Linux uses `~/.config/systemd/user/cosmos-mcp*.service` and reports `loginctl` linger state.
- Preserves saved `cloudflare_token` / `cloudflare` / `vps` / `custom` tunnel configuration across reboots.
"""
from __future__ import annotations

import os
from pathlib import Path
import plistlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Sequence

from cosmos_mcp.core.fs_tx import safe_trash_file
from cosmos_mcp.core.proc import CREATE_NO_WINDOW, resolve_console_python
from cosmos_mcp.launcher.bootstrap import (
    atomic_write_text,
    find_embedded_python_exe,
    find_repo_src_dir,
    resolve_persisted_src_dir,
    resolve_windows_system_exe,
    resolve_windowless_python,
    venv_python_path,
)

WIN_RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
WIN_UNINSTALL_KEY_ROOT = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"


def _popen_flags() -> int:
    return CREATE_NO_WINDOW if sys.platform == "win32" else 0


def _norm_prefix(prefix: str) -> str:
    val = (prefix or "pc").strip().lower()
    return val if val else "pc"


def autostart_entry_id(prefix: str = "pc") -> str:
    eff = _norm_prefix(prefix)
    return "Cosmos-MCP" if eff == "pc" else f"Cosmos-MCP-{eff}"


def uninstall_entry_id(prefix: str = "pc") -> str:
    eff = _norm_prefix(prefix)
    return "Cosmos-MCP" if eff == "pc" else f"Cosmos-MCP-{eff}"


def _legacy_autostart_entry_id(prefix: str = "pc") -> str:
    eff = _norm_prefix(prefix)
    return "LocalPC-MCP" if eff == "pc" else f"LocalPC-MCP-{eff}"


def macos_plist_label(prefix: str = "pc") -> str:
    eff = _norm_prefix(prefix)
    return "com.cosmos.mcp" if eff == "pc" else f"com.cosmos.mcp.{eff}"


def linux_unit_name(prefix: str = "pc") -> str:
    eff = _norm_prefix(prefix)
    return "cosmos-mcp.service" if eff == "pc" else f"cosmos-mcp-{eff}.service"


def session_boundary_notice(platform_name: Optional[str] = None, *, linger_enabled: Optional[bool] = None) -> str:
    """Return honest user-login session boundary explanation."""
    plat = platform_name or sys.platform
    if plat == "win32":
        return (
            "系统边界说明：Windows 当前用户开机自启（HKCU\\...\\Run，使用 pythonw.exe 无黑框静默运行）"
            "在登录 Windows 桌面后自动拉起；配合 Cloudflare 固定 Tunnel Token 可保持永久固定域名不断联。"
        )
    if plat == "darwin":
        return (
            "系统边界说明：macOS LaunchAgents 随当前用户图形界面登录后自动拉起；"
            "若重启后停留在系统登录窗口尚未进入桌面，服务将在登录后启动。"
        )
    if linger_enabled is True:
        return "系统边界说明：Linux systemd --user 已开启 loginctl linger，支持系统重启后免登录后台常驻自启。"
    return (
        "系统边界说明：Linux systemd --user 默认在当前用户登录会话期间运行；"
        "如需无人值守重启免登录常驻，可执行 `sudo loginctl enable-linger $USER`。"
    )


def build_autostart_argv(
    python_exe: str | Path,
    state_root: Path,
    *,
    prefix: str = "pc",
    mode: str = "",
    port: int = 0,
    platform_name: Optional[str] = None,
) -> List[str]:
    plat = platform_name or sys.platform
    exe = resolve_windowless_python(python_exe) if plat == "win32" else str(python_exe)
    argv = [
        exe,
        "-B",
        "-m",
        "cosmos_mcp.launcher.cli",
        "start",
        "--daemon",
        "--no-browser",
        "--state-dir",
        str(Path(state_root).expanduser().resolve()),
    ]
    eff_p = _norm_prefix(prefix)
    if eff_p != "pc":
        argv.extend(["--prefix", eff_p])
    if mode and str(mode).strip().lower() != "local":
        argv.extend(["--mode", str(mode).strip()])
    if port and int(port) > 0:
        argv.extend(["--port", str(int(port))])
    return argv


def format_windows_run_command(argv: Sequence[str]) -> str:
    return subprocess.list2cmdline([str(a) for a in argv])


def _check_linux_linger() -> Optional[bool]:
    loginctl = shutil.which("loginctl")
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    if not loginctl or not user:
        return None
    try:
        proc = subprocess.run(
            [loginctl, "show-user", user, "-p", "Linger"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=4.0,
            creationflags=_popen_flags(),
        )
        if proc.returncode == 0:
            out = (proc.stdout or "").strip().lower()
            if "linger=yes" in out:
                return True
            if "linger=no" in out:
                return False
    except Exception:
        pass
    return None


def _trash_file_quiet(target: Path, state_root: Optional[Path], reason: str) -> bool:
    if not target.is_file():
        return False
    undo_base = (state_root / ".undo_history") if state_root else (Path(tempfile.gettempdir()) / "cosmos_autostart_trash")
    res = safe_trash_file(target, reason=reason, undo_dir=undo_base)
    return bool(res.get("ok") or not target.exists())


def _cleanup_legacy_vbs_if_any(state_root: Path, home_dir: Path) -> List[str]:
    """Move legacy `.vbs` wrappers into recoverable trash if left over by older versions."""
    _ = home_dir
    removed: List[str] = []
    candidates = [
        state_root / "start_silent.vbs",
        state_root / "state" / "autostart.vbs",
    ]
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        startup_dir = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        candidates.append(startup_dir / "LocalPC-MCP.vbs")
        candidates.append(startup_dir / "Cosmos-MCP.vbs")
    for p in candidates:
        if _trash_file_quiet(p, state_root, "cleanup_legacy_vbs"):
            removed.append(str(p))
    return removed


def _resolve_autostart_python(
    python_exe: str | Path,
    state_root: Path,
    *,
    platform_name: Optional[str] = None,
) -> str | Path:
    """Prefer `<state_root>/python-embed/pythonw.exe` -> `<state_root>/.venv` -> app `python-embed` -> `python_exe`."""
    plat = platform_name or sys.platform
    st_root = Path(state_root).expanduser().resolve()

    if plat == "win32":
        for emb_cand in (
            st_root / "python-embed" / "pythonw.exe",
            st_root / "python-embed" / "python.exe",
        ):
            if emb_cand.is_file():
                return resolve_windowless_python(emb_cand)
        venv_win_w = st_root / ".venv" / "Scripts" / "pythonw.exe"
        venv_win_c = st_root / ".venv" / "Scripts" / "python.exe"
        if venv_win_w.is_file():
            return venv_win_w
        if venv_win_c.is_file():
            return resolve_windowless_python(venv_win_c)
        if platform_name is None:
            app_embed = find_embedded_python_exe(state_root=st_root)
            if app_embed is not None and app_embed.is_file():
                return resolve_windowless_python(app_embed)
        return resolve_windowless_python(python_exe)

    for posix_emb in (
        st_root / "python-embed" / "bin" / "python3",
        st_root / "python-embed" / "bin" / "python",
    ):
        if posix_emb.is_file():
            return posix_emb
    for posix_venv in (
        st_root / ".venv" / "bin" / "python3",
        st_root / ".venv" / "bin" / "python",
        venv_python_path(st_root / ".venv", windowless=False),
    ):
        if posix_venv.is_file():
            return posix_venv
    if platform_name is None:
        app_embed_px = find_embedded_python_exe(state_root=st_root)
        if app_embed_px is not None and app_embed_px.is_file():
            return app_embed_px
    return python_exe


def enable_autostart(
    *,
    python_exe: str | Path,
    state_root: Path,
    prefix: str = "pc",
    mode: str = "",
    port: int = 0,
    platform_name: Optional[str] = None,
    home_dir: Optional[Path] = None,
    winreg_store: Optional[Dict[str, str]] = None,
    run_ctl: bool = True,
) -> Dict[str, Any]:
    """Idempotently register user-session autostart for Windows / macOS / Linux."""
    plat = platform_name or sys.platform
    eff_home = Path(home_dir).expanduser() if home_dir is not None else Path.home()
    st_root = Path(state_root).expanduser().resolve()
    persisted_src = resolve_persisted_src_dir(st_root)
    eff_py = _resolve_autostart_python(python_exe, st_root, platform_name=plat)
    _ = resolve_windows_system_exe("cmd.exe") if plat == "win32" else ""
    argv = build_autostart_argv(
        eff_py,
        st_root,
        prefix=prefix,
        mode=mode,
        port=port,
        platform_name=plat,
    )
    entry_name = autostart_entry_id(prefix)
    legacy_name = _legacy_autostart_entry_id(prefix)

    if plat == "win32":
        cmd_str = format_windows_run_command(argv)
        legacy_removed = _cleanup_legacy_vbs_if_any(st_root, eff_home)
        if winreg_store is not None:
            winreg_store.pop(legacy_name, None)
            winreg_store[entry_name] = cmd_str
        else:
            import winreg  # type: ignore[import-not-found]

            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, WIN_RUN_KEY_PATH) as key:
                try:
                    winreg.DeleteValue(key, legacy_name)
                except FileNotFoundError:
                    pass
                winreg.SetValueEx(key, entry_name, 0, winreg.REG_SZ, cmd_str)
        return {
            "ok": True,
            "platform": "win32",
            "mechanism": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "entry_name": entry_name,
            "command": cmd_str,
            "uses_pythonw": argv[0].lower().endswith("pythonw.exe"),
            "legacy_vbs_removed": legacy_removed,
            "boundary_notice": session_boundary_notice("win32"),
        }

    if plat == "darwin":
        label = macos_plist_label(prefix)
        agents_dir = eff_home / "Library" / "LaunchAgents"
        agents_dir.mkdir(parents=True, exist_ok=True)
        plist_path = agents_dir / f"{label}.plist"
        env_vars: Dict[str, str] = {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
            "COSMOS_MCP_STATE_DIR": str(st_root),
            "LOCALPC_MCP_STATE_DIR": str(st_root),
        }
        if persisted_src is not None:
            env_vars["PYTHONPATH"] = str(persisted_src)
        logs_dir = st_root / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        plist_doc: Dict[str, Any] = {
            "Label": label,
            "ProgramArguments": argv,
            "RunAtLoad": True,
            "KeepAlive": False,
            "WorkingDirectory": str(st_root),
            "EnvironmentVariables": env_vars,
            "StandardOutPath": str(logs_dir / f"launchd_{_norm_prefix(prefix)}.out.log"),
            "StandardErrorPath": str(logs_dir / f"launchd_{_norm_prefix(prefix)}.err.log"),
        }
        plist_path.write_bytes(plistlib.dumps(plist_doc))
        if run_ctl and shutil.which("launchctl"):
            uid = os.getuid() if hasattr(os, "getuid") else 501
            subprocess.run(
                ["launchctl", "bootout", f"gui/{uid}", str(plist_path)],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=6.0,
            )
            subprocess.run(
                ["launchctl", "bootstrap", f"gui/{uid}", str(plist_path)],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=8.0,
            )
        return {
            "ok": True,
            "platform": "darwin",
            "mechanism": "LaunchAgents",
            "label": label,
            "plist_path": str(plist_path),
            "command": argv,
            "boundary_notice": session_boundary_notice("darwin"),
        }

    unit = linux_unit_name(prefix)
    unit_dir = eff_home / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    unit_path = unit_dir / unit
    exec_line = " ".join(shlex.quote(a) for a in argv)
    pp_line = f'Environment="PYTHONPATH={persisted_src}"\n' if persisted_src is not None else ""
    unit_text = (
        "[Unit]\n"
        f"Description=Cosmos MCP Service ({_norm_prefix(prefix)})\n"
        "After=network-online.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        f"WorkingDirectory={st_root}\n"
        'Environment="PYTHONDONTWRITEBYTECODE=1"\n'
        'Environment="PYTHONUTF8=1"\n'
        f'Environment="COSMOS_MCP_STATE_DIR={st_root}"\n'
        f'Environment="LOCALPC_MCP_STATE_DIR={st_root}"\n'
        f"{pp_line}"
        f"ExecStart={exec_line}\n\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )
    unit_path.write_text(unit_text, encoding="utf-8")
    systemctl_ok = False
    if run_ctl and shutil.which("systemctl"):
        try:
            subprocess.run(["systemctl", "--user", "daemon-reload"], stdin=subprocess.DEVNULL, capture_output=True, timeout=8.0)
            p_en = subprocess.run(["systemctl", "--user", "enable", unit], stdin=subprocess.DEVNULL, capture_output=True, timeout=8.0)
            systemctl_ok = p_en.returncode == 0
        except Exception:
            systemctl_ok = False
    linger = _check_linux_linger() if run_ctl else None
    return {
        "ok": True,
        "platform": "linux",
        "mechanism": "systemd --user",
        "unit_name": unit,
        "unit_path": str(unit_path),
        "systemctl_enabled": systemctl_ok,
        "linger_enabled": linger,
        "command": argv,
        "boundary_notice": session_boundary_notice("linux", linger_enabled=linger),
    }


def _extract_state_dir_from_cmd(cmd_text: str) -> Optional[Path]:
    if not cmd_text:
        return None
    m = re.search(r'--state-dir(?:\s+|=)(?:"([^"]+)"|\'([^\']+)\'|([^\s"\']+))', cmd_text, re.IGNORECASE)
    raw = (m.group(1) or m.group(2) or m.group(3) or "").strip() if m else ""
    if not raw:
        return None
    try:
        return Path(raw).expanduser().resolve()
    except OSError:
        return None


def _autostart_cmd_belongs_to_state_root(
    cmd_text: str,
    state_root: Optional[Path],
    *,
    is_default_state_root: bool = True,
    primary_state_exists: bool = False,
) -> bool:
    if state_root is None:
        return True
    st_resolved = Path(state_root).expanduser().resolve()
    st_norm = os.path.normcase(str(st_resolved)).replace("/", "\\")
    txt_norm = os.path.normcase(cmd_text or "").replace("/", "\\")
    if st_norm and st_norm in txt_norm:
        return True
    parsed_sd = _extract_state_dir_from_cmd(cmd_text or "")
    if parsed_sd is not None:
        return os.path.normcase(str(parsed_sd)).replace("/", "\\") == st_norm
    low = txt_norm.lower()
    if is_default_state_root:
        if "--state-dir" in low or "cosmos_mcp_state_dir=" in low:
            return False
        return True
    has_other_target = (
        "--state-dir" in low
        or "cosmos_mcp_state_dir=" in low
        or "localpc_mcp_state_dir=" in low
        or ":\\" in low
        or "\\users\\" in low
        or "\\home\\" in low
    )
    if has_other_target or primary_state_exists:
        return False
    return True


def disable_autostart(
    *,
    state_root: Optional[Path] = None,
    prefix: str = "pc",
    platform_name: Optional[str] = None,
    home_dir: Optional[Path] = None,
    winreg_store: Optional[Dict[str, str]] = None,
    run_ctl: bool = True,
    is_default_state_root: bool = True,
    primary_state_exists: bool = False,
) -> Dict[str, Any]:
    """Idempotently remove user-session autostart registration without error if already absent."""
    plat = platform_name or sys.platform
    eff_home = Path(home_dir).expanduser() if home_dir is not None else Path.home()
    entry_name = autostart_entry_id(prefix)
    legacy_name = _legacy_autostart_entry_id(prefix)

    if plat == "win32":
        existed = False
        if winreg_store is not None:
            for nm in (entry_name, legacy_name):
                if nm in winreg_store:
                    val_s = str(winreg_store.get(nm) or "")
                    if not _autostart_cmd_belongs_to_state_root(
                        val_s,
                        state_root,
                        is_default_state_root=is_default_state_root,
                        primary_state_exists=primary_state_exists,
                    ):
                        continue
                    existed = True
                    winreg_store.pop(nm, None)
        else:
            import winreg  # type: ignore[import-not-found]

            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, WIN_RUN_KEY_PATH, 0, winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE) as key:
                    for nm in (entry_name, legacy_name):
                        try:
                            val_raw, _ = winreg.QueryValueEx(key, nm)
                            if not _autostart_cmd_belongs_to_state_root(
                                str(val_raw or ""),
                                state_root,
                                is_default_state_root=is_default_state_root,
                                primary_state_exists=primary_state_exists,
                            ):
                                continue
                            winreg.DeleteValue(key, nm)
                            existed = True
                        except FileNotFoundError:
                            continue
            except FileNotFoundError:
                existed = False
        legacy_removed = (
            _cleanup_legacy_vbs_if_any(state_root or eff_home, eff_home)
            if (state_root and (is_default_state_root or not primary_state_exists))
            else []
        )
        return {
            "ok": True,
            "platform": "win32",
            "entry_name": entry_name,
            "removed": existed,
            "legacy_vbs_removed": legacy_removed,
        }

    if plat == "darwin":
        label = macos_plist_label(prefix)
        plist_path = eff_home / "Library" / "LaunchAgents" / f"{label}.plist"
        existed = plist_path.is_file()
        if existed and state_root is not None:
            try:
                plist_txt = plist_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                plist_txt = ""
            if not _autostart_cmd_belongs_to_state_root(
                plist_txt,
                state_root,
                is_default_state_root=is_default_state_root,
                primary_state_exists=primary_state_exists,
            ):
                return {"ok": True, "platform": "darwin", "label": label, "plist_path": str(plist_path), "removed": False}
        if existed and run_ctl and shutil.which("launchctl"):
            uid = os.getuid() if hasattr(os, "getuid") else 501
            subprocess.run(["launchctl", "bootout", f"gui/{uid}", str(plist_path)], stdin=subprocess.DEVNULL, capture_output=True, timeout=6.0)
        if existed:
            _trash_file_quiet(plist_path, state_root, "disable_autostart_plist")
        return {
            "ok": True,
            "platform": "darwin",
            "label": label,
            "plist_path": str(plist_path),
            "removed": existed,
        }

    unit = linux_unit_name(prefix)
    unit_path = eff_home / ".config" / "systemd" / "user" / unit
    existed = unit_path.is_file()
    if existed and state_root is not None:
        try:
            unit_txt = unit_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            unit_txt = ""
        if not _autostart_cmd_belongs_to_state_root(
            unit_txt,
            state_root,
            is_default_state_root=is_default_state_root,
            primary_state_exists=primary_state_exists,
        ):
            return {"ok": True, "platform": "linux", "unit_name": unit, "unit_path": str(unit_path), "removed": False}
    if run_ctl and shutil.which("systemctl"):
        try:
            subprocess.run(["systemctl", "--user", "disable", unit], stdin=subprocess.DEVNULL, capture_output=True, timeout=8.0)
        except Exception:
            pass
    if existed:
        _trash_file_quiet(unit_path, state_root, "disable_autostart_unit")
    if run_ctl and shutil.which("systemctl"):
        try:
            subprocess.run(["systemctl", "--user", "daemon-reload"], stdin=subprocess.DEVNULL, capture_output=True, timeout=8.0)
        except Exception:
            pass
    return {
        "ok": True,
        "platform": "linux",
        "unit_name": unit,
        "unit_path": str(unit_path),
        "removed": existed,
    }


def get_autostart_status(
    *,
    prefix: str = "pc",
    state_root: Optional[Path] = None,
    is_default_state_root: bool = True,
    primary_state_exists: bool = False,
    platform_name: Optional[str] = None,
    home_dir: Optional[Path] = None,
    winreg_store: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    plat = platform_name or sys.platform
    eff_home = Path(home_dir).expanduser() if home_dir is not None else Path.home()
    entry_name = autostart_entry_id(prefix)
    legacy_name = _legacy_autostart_entry_id(prefix)

    if plat == "win32":
        val: Optional[str] = None
        if winreg_store is not None:
            val = winreg_store.get(entry_name) or winreg_store.get(legacy_name)
        else:
            import winreg  # type: ignore[import-not-found]

            for nm in (entry_name, legacy_name):
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, WIN_RUN_KEY_PATH, 0, winreg.KEY_QUERY_VALUE) as key:
                        raw_val, _ = winreg.QueryValueEx(key, nm)
                        val = str(raw_val)
                        break
                except (FileNotFoundError, OSError):
                    continue
        belongs = bool(val) and _autostart_cmd_belongs_to_state_root(
            val or "",
            state_root,
            is_default_state_root=is_default_state_root,
            primary_state_exists=primary_state_exists,
        )
        return {
            "enabled": belongs,
            "platform": "win32",
            "mechanism": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "entry_name": entry_name,
            "command": (val or "") if belongs else "",
            "boundary_notice": session_boundary_notice("win32"),
        }

    if plat == "darwin":
        label = macos_plist_label(prefix)
        plist_path = eff_home / "Library" / "LaunchAgents" / f"{label}.plist"
        is_en = plist_path.is_file()
        if is_en and state_root is not None:
            try:
                is_en = _autostart_cmd_belongs_to_state_root(
                    plist_path.read_text(encoding="utf-8", errors="replace"),
                    state_root,
                    is_default_state_root=is_default_state_root,
                    primary_state_exists=primary_state_exists,
                )
            except OSError:
                pass
        return {
            "enabled": is_en,
            "platform": "darwin",
            "mechanism": "LaunchAgents",
            "label": label,
            "plist_path": str(plist_path),
            "boundary_notice": session_boundary_notice("darwin"),
        }

    unit = linux_unit_name(prefix)
    unit_path = eff_home / ".config" / "systemd" / "user" / unit
    linger = _check_linux_linger()
    is_en_lx = unit_path.is_file()
    if is_en_lx and state_root is not None:
        try:
            is_en_lx = _autostart_cmd_belongs_to_state_root(
                unit_path.read_text(encoding="utf-8", errors="replace"),
                state_root,
                is_default_state_root=is_default_state_root,
                primary_state_exists=primary_state_exists,
            )
        except OSError:
            pass
    return {
        "enabled": is_en_lx,
        "platform": "linux",
        "mechanism": "systemd --user",
        "unit_name": unit,
        "unit_path": str(unit_path),
        "linger_enabled": linger,
        "boundary_notice": session_boundary_notice("linux", linger_enabled=linger),
    }


def _windows_uninstall_script_path(state_root: Path, prefix: str = "pc") -> Path:
    st_root = Path(state_root).expanduser().resolve()
    eff = _norm_prefix(prefix)
    fname = "uninstall_cosmos_mcp.cmd" if eff == "pc" else f"uninstall_cosmos_mcp_{eff}.cmd"
    return st_root / "bin" / fname


def _build_windows_uninstall_cmd_script(
    state_root: Path,
    *,
    prefix: str = "pc",
    python_exe: Optional[str | Path] = None,
) -> str:
    st_root = Path(state_root).expanduser().resolve()
    eff = _norm_prefix(prefix)
    persisted_src = resolve_persisted_src_dir(st_root) or find_repo_src_dir()
    src_str = str(persisted_src) if persisted_src is not None else ""
    st_str = str(st_root)
    venv_dir_str = str(st_root / ".venv")
    embed_exe_str = str(st_root / "python-embed" / "python.exe")
    venv_exe_str = str(st_root / ".venv" / "Scripts" / "python.exe")
    prefix_arg = f" --prefix {eff}" if eff != "pc" else ""

    ext_py_hint = ""
    if python_exe is not None and str(python_exe).strip():
        cand_con = resolve_console_python(str(python_exe).strip())
        try:
            cand_norm = os.path.normcase(str(Path(cand_con).resolve()))
            venv_norm = os.path.normcase(str((st_root / ".venv").resolve()))
            if not cand_norm.startswith(venv_norm + os.sep):
                ext_py_hint = cand_con
        except OSError:
            ext_py_hint = ""

    lines: List[str] = [
        "@echo off",
        "chcp 65001 >nul",
        "setlocal EnableExtensions",
        'set "PYTHONDONTWRITEBYTECODE=1"',
        'set "PYTHONUTF8=1"',
        f'set "COSMOS_MCP_STATE_DIR={st_str}"',
        f'set "LOCALPC_MCP_STATE_DIR={st_str}"',
    ]
    if src_str:
        lines.append(f'set "COSMOS_REPO_SRC={src_str}"')
        lines.append(f'set "PYTHONPATH={src_str};%PYTHONPATH%"')

    lines.extend(
        [
            'set "_COSMOS_UN_PY="',
            'set "_COSMOS_UN_PYL="',
        ]
    )
    if ext_py_hint:
        lines.append(f'call :probe_ext_py "{ext_py_hint}"')

    lines.extend(
        [
            "if not defined _COSMOS_UN_PY (",
            "    for /f \"delims=\" %%L in ('where py 2^>nul') do (",
            '        if not defined _COSMOS_UN_PYL call :probe_py_launcher "%%~fL"',
            "    )",
            ")",
            "if not defined _COSMOS_UN_PY if not defined _COSMOS_UN_PYL (",
            "    for /f \"delims=\" %%P in ('where python 2^>nul') do (",
            '        if not defined _COSMOS_UN_PY call :probe_ext_py "%%~fP"',
            "    )",
            ")",
            "if not defined _COSMOS_UN_PY if not defined _COSMOS_UN_PYL (",
            "    for %%V in (313 312 311 310 314) do (",
            '        if not defined _COSMOS_UN_PY if defined LOCALAPPDATA call :probe_ext_py "%LOCALAPPDATA%\\Programs\\Python\\Python%%V\\python.exe"',
            '        if not defined _COSMOS_UN_PY if defined ProgramFiles call :probe_ext_py "%ProgramFiles%\\Python%%V\\python.exe"',
            '        if not defined _COSMOS_UN_PY call :probe_ext_py "C:\\Python%%V\\python.exe"',
            "    )",
            ")",
            'if not defined _COSMOS_UN_PY if not defined _COSMOS_UN_PYL if defined USERPROFILE call :probe_ext_py "%USERPROFILE%\\anaconda3\\python.exe"',
            'if not defined _COSMOS_UN_PY if not defined _COSMOS_UN_PYL if defined USERPROFILE call :probe_ext_py "%USERPROFILE%\\miniconda3\\python.exe"',
            'if not defined _COSMOS_UN_PY if not defined _COSMOS_UN_PYL call :probe_ext_py "C:\\ProgramData\\anaconda3\\python.exe"',
            'if not defined _COSMOS_UN_PY if not defined _COSMOS_UN_PYL call :probe_ext_py "C:\\ProgramData\\miniconda3\\python.exe"',
            f'if not defined _COSMOS_UN_PY if not defined _COSMOS_UN_PYL if exist "{embed_exe_str}" set "_COSMOS_UN_PY={embed_exe_str}"',
            f'if not defined _COSMOS_UN_PY if not defined _COSMOS_UN_PYL if exist "{venv_exe_str}" set "_COSMOS_UN_PY={venv_exe_str}"',
            "if not defined _COSMOS_UN_PY if not defined _COSMOS_UN_PYL (",
            "    echo 未检测到可用的 Python 3.10~3.14 环境，无法执行卸载程序。",
            "    if not defined COSMOS_NO_PAUSE if not defined PYTEST_CURRENT_TEST pause",
            "    exit /b 1",
            ")",
            'if /i "%~1"=="--quiet" goto :run_quiet',
            'if /i "%~1"=="/quiet" goto :run_quiet',
            'if /i "%~1"=="-q" goto :run_quiet',
            'if not "%~1"=="" goto :run_passthrough',
            "if defined COSMOS_NO_PAUSE goto :run_quiet",
            "if defined PYTEST_CURRENT_TEST goto :run_quiet",
            "echo ============================================================",
            "echo  WebAI2PC (Cosmos MCP) 卸载向导",
            "echo ============================================================",
            "echo  本操作仅移除软件运行环境与连接配置，不会改动您的个人项目代码目录。",
            "echo.",
            "echo  [1] 彻底卸载并粉碎凭据（默认：停止服务与隧道、取消自启、0x00 覆写销毁全部本地密钥与令牌）",
            "echo  [2] 标准卸载保留修改快照（停止服务与自启，保留 .undo_history 与回收箱修改快照）",
            "echo  [Q] 取消",
            "echo.",
            'set "_UN_CHOICE=1"',
            'set /p "_UN_CHOICE=请输入选项 [1/2/Q] (直接回车默认 1): "',
            'if /i "%_UN_CHOICE%"=="Q" (',
            "    echo 已取消卸载。",
            "    exit /b 0",
            ")",
            'if "%_UN_CHOICE%"=="2" (',
            f'    call :invoke_cli uninstall --state-dir "{st_str}"{prefix_arg} -y',
            "    set \"_UN_RC=%ERRORLEVEL%\"",
            "    echo 标准卸载已完成。",
            "    pause",
            "    exit /b %_UN_RC%",
            ")",
            f'call :invoke_cli uninstall --state-dir "{st_str}"{prefix_arg} --purge -y',
            'set "_UN_RC=%ERRORLEVEL%"',
            "echo 彻底卸载与凭据销毁已完成。",
            "pause",
            "exit /b %_UN_RC%",
            "",
            ":run_quiet",
            f'call :invoke_cli uninstall --state-dir "{st_str}"{prefix_arg} --purge -y',
            "exit /b %ERRORLEVEL%",
            "",
            ":run_passthrough",
            f'call :invoke_cli uninstall --state-dir "{st_str}"{prefix_arg} %*',
            "exit /b %ERRORLEVEL%",
            "",
            ":invoke_cli",
            "if defined _COSMOS_UN_PYL (",
            '    "%_COSMOS_UN_PYL%" -3 -B -c "import os,sys; p=os.environ.get(\'COSMOS_REPO_SRC\',\'\'); p and p not in sys.path and sys.path.insert(0,p); from cosmos_mcp.launcher.cli import main; raise SystemExit(main(sys.argv[1:]))" %*',
            "    exit /b %ERRORLEVEL%",
            ")",
            '"%_COSMOS_UN_PY%" -B -c "import os,sys; p=os.environ.get(\'COSMOS_REPO_SRC\',\'\'); p and p not in sys.path and sys.path.insert(0,p); from cosmos_mcp.launcher.cli import main; raise SystemExit(main(sys.argv[1:]))" %*',
            "exit /b %ERRORLEVEL%",
            "",
            ":probe_py_launcher",
            'set "_PYL=%~1"',
            'if not defined _PYL exit /b 1',
            'if not exist "%_PYL%" exit /b 1',
            'echo "%_PYL%" | findstr /i /c:"\\WindowsApps\\" >nul',
            "if not errorlevel 1 exit /b 1",
            '"%_PYL%" -3 -B -c "import sys; raise SystemExit(0 if \'windowsapps\' not in sys.executable.lower() and (3,10)<=sys.version_info[:2]<=(3,14) else 1)" >nul 2>nul',
            "if errorlevel 1 exit /b 1",
            'set "_COSMOS_UN_PYL=%_PYL%"',
            "exit /b 0",
            "",
            ":probe_ext_py",
            'set "_CAND=%~1"',
            'if not defined _CAND exit /b 1',
            'if not exist "%_CAND%" exit /b 1',
            'echo "%_CAND%" | findstr /i /c:"\\WindowsApps\\" >nul',
            "if not errorlevel 1 exit /b 1",
            f'echo "%_CAND%" | findstr /i /c:"{venv_dir_str}" >nul',
            "if not errorlevel 1 exit /b 1",
            '"%_CAND%" -B -c "import sys; raise SystemExit(0 if \'windowsapps\' not in sys.executable.lower() and (3,10)<=sys.version_info[:2]<=(3,14) else 1)" >nul 2>nul',
            "if errorlevel 1 exit /b 1",
            'set "_COSMOS_UN_PY=%_CAND%"',
            "exit /b 0",
            "",
        ]
    )
    return "\r\n".join(lines)


def _uninstall_entry_belongs_to_state_root(
    entry_values: Dict[str, Any],
    state_root: Optional[Path],
    *,
    is_default_state_root: bool = True,
    primary_state_exists: bool = False,
) -> bool:
    if state_root is None:
        return True
    st_resolved = Path(state_root).expanduser().resolve()
    st_norm = os.path.normcase(str(st_resolved)).replace("/", "\\").rstrip("\\")

    raw_loc = str(entry_values.get("InstallLocation") or "").strip()
    if raw_loc:
        try:
            loc_resolved = Path(raw_loc).expanduser().resolve()
            loc_norm = os.path.normcase(str(loc_resolved)).replace("/", "\\").rstrip("\\")
        except OSError:
            loc_norm = os.path.normcase(raw_loc).replace("/", "\\").rstrip("\\")
        return loc_norm == st_norm

    cmd_txt = str(entry_values.get("UninstallString") or entry_values.get("QuietUninstallString") or "").strip()
    if not cmd_txt:
        return False
    txt_norm = os.path.normcase(cmd_txt).replace("/", "\\")
    if st_norm and re.search(re.escape(st_norm) + r'(?:\\|"|\'|\s|$)', txt_norm):
        return True
    parsed_sd = _extract_state_dir_from_cmd(cmd_txt)
    if parsed_sd is not None:
        return os.path.normcase(str(parsed_sd)).replace("/", "\\").rstrip("\\") == st_norm
    if re.search(r"[a-z]:\\", txt_norm, re.IGNORECASE):
        return False
    return _autostart_cmd_belongs_to_state_root(
        cmd_txt,
        state_root,
        is_default_state_root=is_default_state_root,
        primary_state_exists=primary_state_exists,
    )


def register_windows_uninstall_entry(
    state_root: Path,
    *,
    python_exe: Optional[str | Path] = None,
    prefix: str = "pc",
    display_version: str = "1.2.1",
    platform_name: Optional[str] = None,
    uninstall_reg_store: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Idempotently register per-user (`HKCU`, zero UAC/admin) Windows 'Installed Apps' uninstall entry."""
    plat = platform_name or sys.platform
    eff = _norm_prefix(prefix)
    entry_id = uninstall_entry_id(eff)
    if plat != "win32":
        return {
            "ok": True,
            "registered": False,
            "platform": plat,
            "entry_id": entry_id,
            "reason": "non_windows",
        }

    st_root = Path(state_root).expanduser().resolve()
    script_path = _windows_uninstall_script_path(st_root, eff)
    script_content = _build_windows_uninstall_cmd_script(st_root, prefix=eff, python_exe=python_exe)
    script_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(script_path, script_content)

    cmd_exe = resolve_windows_system_exe("cmd.exe") or "cmd.exe"
    display_name = "WebAI2PC (Cosmos MCP)" if eff == "pc" else f"WebAI2PC (Cosmos MCP - {eff})"
    uninstall_str = f'"{cmd_exe}" /s /d /c ""{script_path}""'
    quiet_uninstall_str = f'"{cmd_exe}" /s /d /c ""{script_path}" --quiet"'

    entry_values: Dict[str, Any] = {
        "DisplayName": display_name,
        "DisplayVersion": str(display_version or "1.2.1"),
        "Publisher": "WebAI2PC",
        "InstallLocation": str(st_root),
        "UninstallString": uninstall_str,
        "QuietUninstallString": quiet_uninstall_str,
        "NoModify": 1,
        "NoRepair": 1,
    }

    if uninstall_reg_store is not None:
        uninstall_reg_store[entry_id] = dict(entry_values)
        return {
            "ok": True,
            "registered": True,
            "platform": "win32",
            "entry_id": entry_id,
            "key_path": f"HKCU\\{WIN_UNINSTALL_KEY_ROOT}\\{entry_id}",
            "script_path": str(script_path),
            "values": dict(entry_values),
        }

    if os.environ.get("PYTEST_CURRENT_TEST"):
        return {
            "ok": True,
            "registered": False,
            "skipped_pytest": True,
            "platform": "win32",
            "entry_id": entry_id,
            "key_path": f"HKCU\\{WIN_UNINSTALL_KEY_ROOT}\\{entry_id}",
            "script_path": str(script_path),
            "values": dict(entry_values),
        }

    import winreg  # type: ignore[import-not-found]

    subkey_path = f"{WIN_UNINSTALL_KEY_ROOT}\\{entry_id}"
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, subkey_path) as key:
        for val_name, val_data in entry_values.items():
            if isinstance(val_data, int):
                winreg.SetValueEx(key, val_name, 0, winreg.REG_DWORD, int(val_data))
            else:
                winreg.SetValueEx(key, val_name, 0, winreg.REG_SZ, str(val_data))

    return {
        "ok": True,
        "registered": True,
        "platform": "win32",
        "entry_id": entry_id,
        "key_path": f"HKCU\\{subkey_path}",
        "script_path": str(script_path),
        "values": dict(entry_values),
    }


def unregister_windows_uninstall_entry(
    state_root: Optional[Path] = None,
    *,
    prefix: str = "pc",
    platform_name: Optional[str] = None,
    uninstall_reg_store: Optional[Dict[str, Dict[str, Any]]] = None,
    is_default_state_root: bool = True,
    primary_state_exists: bool = False,
) -> Dict[str, Any]:
    """Idempotently remove per-user Windows 'Installed Apps' uninstall entry if owned by `state_root`."""
    plat = platform_name or sys.platform
    eff = _norm_prefix(prefix)
    entry_id = uninstall_entry_id(eff)
    legacy_id = _legacy_autostart_entry_id(eff)

    if plat != "win32":
        return {
            "ok": True,
            "platform": plat,
            "entry_id": entry_id,
            "removed": False,
        }

    if uninstall_reg_store is not None:
        removed = False
        for cid in (entry_id, legacy_id):
            cur = uninstall_reg_store.get(cid)
            if not isinstance(cur, dict):
                continue
            if not _uninstall_entry_belongs_to_state_root(
                cur,
                state_root,
                is_default_state_root=is_default_state_root,
                primary_state_exists=primary_state_exists,
            ):
                continue
            uninstall_reg_store.pop(cid, None)
            removed = True
        return {
            "ok": True,
            "platform": "win32",
            "entry_id": entry_id,
            "removed": removed,
        }

    if os.environ.get("PYTEST_CURRENT_TEST"):
        return {
            "ok": True,
            "platform": "win32",
            "entry_id": entry_id,
            "removed": False,
            "skipped_pytest": True,
        }

    import winreg  # type: ignore[import-not-found]

    removed = False
    for cid in (entry_id, legacy_id):
        subkey_path = f"{WIN_UNINSTALL_KEY_ROOT}\\{cid}"
        loaded_vals: Dict[str, Any] = {}
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey_path, 0, winreg.KEY_QUERY_VALUE) as skey:
                for qname in ("InstallLocation", "UninstallString", "QuietUninstallString", "Publisher", "DisplayName"):
                    try:
                        v_raw, _ = winreg.QueryValueEx(skey, qname)
                        loaded_vals[qname] = v_raw
                    except FileNotFoundError:
                        continue
        except FileNotFoundError:
            continue
        except OSError:
            continue

        if not _uninstall_entry_belongs_to_state_root(
            loaded_vals,
            state_root,
            is_default_state_root=is_default_state_root,
            primary_state_exists=primary_state_exists,
        ):
            continue

        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                WIN_UNINSTALL_KEY_ROOT,
                0,
                winreg.KEY_WRITE | winreg.KEY_QUERY_VALUE,
            ) as parent_key:
                winreg.DeleteKey(parent_key, cid)
                removed = True
        except FileNotFoundError:
            continue
        except OSError:
            continue

    return {
        "ok": True,
        "platform": "win32",
        "entry_id": entry_id,
        "removed": removed,
    }

