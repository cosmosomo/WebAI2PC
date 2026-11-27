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
from cosmos_mcp.core.proc import CREATE_NO_WINDOW
from cosmos_mcp.launcher.bootstrap import (
    find_embedded_python_exe,
    resolve_persisted_src_dir,
    resolve_windows_system_exe,
    resolve_windowless_python,
    venv_python_path,
)

WIN_RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"


def _popen_flags() -> int:
    return CREATE_NO_WINDOW if sys.platform == "win32" else 0


def _norm_prefix(prefix: str) -> str:
    val = (prefix or "pc").strip().lower()
    return val if val else "pc"


def autostart_entry_id(prefix: str = "pc") -> str:
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
