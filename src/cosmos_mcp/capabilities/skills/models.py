"""Shared contracts, models, live-policy configuration, and enablement state for `cosmos_mcp.capabilities.skills`."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from cosmos_mcp.core.contracts import (
    CANONICAL_TIER_MAP,
    TIER_NUMERIC_LEVEL,
    TIER_ORDER,
)

from cosmos_mcp import __version__ as _COSMOS_PACKAGE_VERSION

if TYPE_CHECKING:
    from cosmos_mcp.core.config import LiveRuntimePolicy

PACKAGE_VERSION = str(_COSMOS_PACKAGE_VERSION or "1.2.1")

# Tuple of (status_code, response_headers_lower, body_bytes)
HttpTransportFn = Callable[
    [str, str, Optional[Dict[str, str]], Optional[bytes], float, Optional[str]],
    Tuple[int, Dict[str, str], bytes],
]
TrashFn = Callable[[Union[str, Path], str, Path], Dict[str, Any]]

_DISABLED_STATE_LOCK = threading.RLock()
DISABLED_SKILLS_FILE_NAME = "disabled_skills.json"

_EXTRA_TIER_ALIASES: Dict[str, str] = {
    "tier_1": "tier1_readonly",
    "tier-1": "tier1_readonly",
    "tier_2": "tier2_workspace_edit",
    "tier-2": "tier2_workspace_edit",
    "tier_3": "tier3_workspace_dev",
    "tier-3": "tier3_workspace_dev",
    "l-env": "tier3_workspace_dev",
    "tier_4": "tier4_full_power",
    "tier-4": "tier4_full_power",
    "tier4_host_admin": "tier4_full_power",
    "host_admin": "tier4_full_power",
    "l-open": "tier4_full_power",
}


def normalize_canonical_tier_key(raw_tier: Any) -> str:
    """Resolve integer `1..4` or tier alias into `cosmos_mcp.core.contracts.TIER_ORDER` canonical key."""
    if isinstance(raw_tier, bool):
        raise ValueError(f"Invalid tier value: {raw_tier!r}; expected 1..4 or one of {TIER_ORDER}.")
    if isinstance(raw_tier, int):
        idx = max(1, min(4, raw_tier)) - 1
        return TIER_ORDER[idx]
    if isinstance(raw_tier, str):
        s = raw_tier.strip()
        if not s:
            raise ValueError("Invalid empty tier string.")
        low = s.lower()
        if low in CANONICAL_TIER_MAP:
            return CANONICAL_TIER_MAP[low]
        if low in _EXTRA_TIER_ALIASES:
            return _EXTRA_TIER_ALIASES[low]
        if s in TIER_NUMERIC_LEVEL:
            lvl = TIER_NUMERIC_LEVEL[s]
            return TIER_ORDER[max(1, min(4, lvl)) - 1]
        if low.lstrip("+-").isdigit():
            idx = max(1, min(4, int(low))) - 1
            return TIER_ORDER[idx]
        raise ValueError(f"Invalid tier_level: {raw_tier!r}; expected 1..4 or one of {TIER_ORDER}.")
    idx = max(1, min(4, int(raw_tier))) - 1
    return TIER_ORDER[idx]


def normalize_tier_level(raw_tier: Any) -> int:
    """Normalize integer `1..4` or tier key (`tier1_readonly..tier4_full_power`, `L1..L4`) into `1..4`."""
    canon = normalize_canonical_tier_key(raw_tier)
    return int(TIER_NUMERIC_LEVEL.get(canon, 3))


def _coerce_optional_path(val: Optional[Union[str, Path]]) -> Optional[Path]:
    if val is None:
        return None
    if isinstance(val, Path):
        s = str(val).strip()
        return val if s else None
    s_raw = str(val).strip()
    return Path(s_raw) if s_raw else None


def _coerce_path_tuple(val: Any) -> Tuple[Path, ...]:
    if val is None:
        return ()
    if isinstance(val, (str, os.PathLike)):
        p = _coerce_optional_path(val)  # type: ignore[arg-type]
        return (p,) if p is not None else ()
    out: List[Path] = []
    for item in val:
        p_item = _coerce_optional_path(item)
        if p_item is not None:
            out.append(p_item)
    return tuple(out)


def _norm_abs_key(path: Union[str, Path]) -> str:
    try:
        rp = os.path.realpath(str(Path(path).expanduser()))
    except OSError:
        rp = os.path.abspath(str(path))
    cleaned = rp.rstrip("\\/") or rp
    return os.path.normcase(cleaned) if os.name == "nt" else cleaned


def is_subpath(child: Union[str, Path], parent: Union[str, Path]) -> bool:
    """Safe containment check after resolving both paths."""
    try:
        c_res = os.path.realpath(str(child))
        p_res = os.path.realpath(str(parent))
        if os.name == "nt":
            c_cmp = os.path.normcase(c_res)
            p_cmp = os.path.normcase(p_res)
        else:
            c_cmp = c_res
            p_cmp = p_res
        return c_cmp == p_cmp or c_cmp.startswith(p_cmp.rstrip("\\/") + os.sep)
    except (OSError, ValueError):
        return False


def is_link_or_junction(path: Union[str, Path]) -> bool:
    """Detect symlinks and Windows NTFS directory junctions without resolving the target."""
    p_str = str(path)
    try:
        if os.path.islink(p_str):
            return True
        if hasattr(os.path, "isjunction") and os.path.isjunction(p_str):  # type: ignore[attr-defined]
            return True
        if os.name == "nt":
            st = os.lstat(p_str)
            reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            return bool(getattr(st, "st_file_attributes", 0) & reparse_flag)
    except OSError:
        return False
    return False


def unlink_link_or_junction(path: Union[str, Path]) -> bool:
    """Safely detach a symlink or Windows directory junction without modifying its target."""
    if not is_link_or_junction(path):
        return False
    p_str = str(path)
    try:
        if os.name == "nt":
            try:
                os.rmdir(p_str)
                return True
            except OSError:
                os.unlink(p_str)
                return True
        if os.path.isdir(p_str) and not os.path.islink(p_str):
            os.rmdir(p_str)
        else:
            os.unlink(p_str)
        return True
    except OSError:
        return False


def atomic_write_bytes(target: Path, data: bytes) -> None:
    """Atomically write bytes to target file via same-directory temp file + os.replace."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
        os.replace(tmp_name, str(target))
    except BaseException:
        try:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        except OSError:
            pass
        raise


def atomic_write_json(target: Path, payload: Any) -> None:
    """Atomically write UTF-8 formatted JSON to target file."""
    raw = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    atomic_write_bytes(target, raw)


def _resolve_windows_hermes_roots(home: Path, explicit_home: bool) -> List[Tuple[str, Path]]:
    """Resolve `%LOCALAPPDATA%\\hermes\\skills` dynamically, strictly isolating explicit `home_dir`."""
    appdata_hermes = home / "AppData" / "Local" / "hermes" / "skills"
    if explicit_home:
        out_explicit: List[Tuple[str, Path]] = [("hermes", appdata_hermes)]
        posix_explicit = home / ".hermes" / "skills"
        if posix_explicit.is_dir():
            out_explicit.append(("hermes_posix", posix_explicit))
        return out_explicit

    env_local_appdata = os.environ.get("LOCALAPPDATA", "").strip()
    out: List[Tuple[str, Path]] = []
    if env_local_appdata:
        env_hermes = Path(env_local_appdata).expanduser() / "hermes" / "skills"
        if env_hermes.exists() or not appdata_hermes.exists():
            out.append(("hermes", env_hermes))
            if appdata_hermes.is_dir() and appdata_hermes != env_hermes:
                out.append(("hermes_appdata", appdata_hermes))
        else:
            out.append(("hermes", appdata_hermes))
    else:
        out.append(("hermes", appdata_hermes))

    posix_hermes = home / ".hermes" / "skills"
    if posix_hermes.is_dir():
        out.append(("hermes_posix", posix_hermes))
    return out


def default_host_skill_roots(home_dir: Optional[Union[str, Path]] = None) -> List[Tuple[str, Path]]:
    """Return ordered `(host_id, skill_root_path)` candidates under user home (isolated when `home_dir` is given)."""
    coerced_home = _coerce_optional_path(home_dir)
    explicit_home = coerced_home is not None
    if coerced_home is not None:
        raw_str = str(coerced_home)
        home = coerced_home.expanduser() if raw_str.startswith("~") else coerced_home
    else:
        home = Path.home().expanduser()
    candidates: List[Tuple[str, Path]] = [
        ("cosmos_skills_store", home / ".cosmos-skills" / "skills_store"),
        ("universal_agents", home / ".agents" / "skills"),
        ("cc_switch", home / ".cc-switch" / "skills"),
        ("claude_code", home / ".claude" / "skills"),
        ("cursor", home / ".cursor" / "skills"),
        ("windsurf", home / ".codeium" / "windsurf" / "skills"),
        ("codex", home / ".codex" / "skills"),
        ("gemini_cli", home / ".gemini" / "skills"),
        ("antigravity_global", home / ".gemini" / "config" / "skills"),
    ]
    candidates.extend(_resolve_windows_hermes_roots(home, explicit_home=explicit_home))
    candidates.extend(
        [
            ("opencode", home / ".config" / "opencode" / "skills"),
            ("grok", home / ".grok" / "skills"),
            ("kimi_code", home / ".kimi-code" / "skills"),
            ("copilot", home / ".copilot" / "skills"),
        ]
    )
    plugins_root = home / ".gemini" / "config" / "plugins"
    if plugins_root.is_dir():
        try:
            for entry in sorted(plugins_root.iterdir(), key=lambda p: p.name.lower()):
                sp = entry / "skills"
                if entry.is_dir() and sp.is_dir():
                    candidates.append((f"plugin:{entry.name}", sp))
        except OSError:
            pass
    agy_builtin = home / ".gemini" / "antigravity" / "builtin" / "skills"
    if agy_builtin.is_dir():
        candidates.append(("antigravity_builtin", agy_builtin))
    return candidates


class SkillsConfig:
    """Live-policy-coupled configuration for local skill discovery, market access, vetting, and state paths.

    When `policy` (`cosmos_mcp.core.config.LiveRuntimePolicy`) is attached, `tier_level`, `tier_key`,
    `workspace_roots`, `restrict_to_workspaces`, and `resolved_state_root()` dynamically read the latest
    `policy` attributes on every call so Studio/CLI hot-switching takes effect immediately without restart.
    """

    def __init__(
        self,
        workspace_roots: Union[str, Path, Sequence[Union[str, Path]]] = (),
        state_root: Optional[Union[str, Path]] = None,
        extra_readonly_roots: Union[str, Path, Sequence[Union[str, Path]]] = (),
        auto_discover_host_roots: Optional[bool] = None,
        home_dir: Optional[Union[str, Path]] = None,
        restrict_to_workspaces: Optional[bool] = None,
        tier_level: Optional[Union[int, str]] = None,
        enabled_hosts: Optional[Union[str, Sequence[str]]] = None,
        proxy_url: Optional[str] = None,
        http_timeout_sec: float = 12.0,
        max_archive_bytes: int = 10 * 1024 * 1024,
        max_extracted_bytes: int = 25 * 1024 * 1024,
        max_single_file_bytes: int = 1 * 1024 * 1024,
        max_file_count: int = 500,
        http_transport: Optional[HttpTransportFn] = None,
        trash_fn: Optional[TrashFn] = None,
        *,
        policy: Optional["LiveRuntimePolicy"] = None,
    ) -> None:
        self.policy: Optional["LiveRuntimePolicy"] = policy
        self._explicit_workspace_roots: Tuple[Path, ...] = _coerce_path_tuple(workspace_roots)
        self._explicit_state_root: Optional[Path] = _coerce_optional_path(state_root)
        self.extra_readonly_roots: Tuple[Path, ...] = _coerce_path_tuple(extra_readonly_roots)
        self.home_dir: Optional[Path] = _coerce_optional_path(home_dir)
        self._explicit_restrict_to_workspaces: Optional[bool] = (
            None if restrict_to_workspaces is None else bool(restrict_to_workspaces)
        )
        self._explicit_auto_discover_host_roots: Optional[bool] = (
            None if auto_discover_host_roots is None else bool(auto_discover_host_roots)
        )
        self._explicit_tier_level: Optional[int] = (
            None if tier_level is None else normalize_tier_level(tier_level)
        )
        if enabled_hosts is not None:
            if isinstance(enabled_hosts, str):
                s_h = enabled_hosts.strip()
                self.enabled_hosts: Optional[Tuple[str, ...]] = (s_h,) if s_h else ()
            else:
                self.enabled_hosts = tuple(str(h).strip() for h in enabled_hosts if str(h).strip())
        else:
            self.enabled_hosts = None
        self.proxy_url: Optional[str] = proxy_url
        self.http_timeout_sec: float = float(http_timeout_sec)
        self.max_archive_bytes: int = int(max_archive_bytes)
        self.max_extracted_bytes: int = int(max_extracted_bytes)
        self.max_single_file_bytes: int = int(max_single_file_bytes)
        self.max_file_count: int = int(max_file_count)
        self.http_transport: Optional[HttpTransportFn] = http_transport
        self.trash_fn: Optional[TrashFn] = trash_fn

    def _refresh_policy(self) -> Optional["LiveRuntimePolicy"]:
        pol = self.policy
        if pol is not None:
            refresh_fn = getattr(pol, "refresh", None)
            if callable(refresh_fn):
                try:
                    refresh_fn()
                except Exception:
                    pass
        return pol

    @property
    def tier_key(self) -> str:
        if self._explicit_tier_level is not None:
            return TIER_ORDER[max(1, min(4, self._explicit_tier_level)) - 1]
        pol = self._refresh_policy()
        if pol is not None:
            raw_tk = getattr(pol, "tier_key", None)
            if raw_tk is not None:
                try:
                    return normalize_canonical_tier_key(raw_tk)
                except ValueError:
                    pass
        return "tier3_workspace_dev"

    @property
    def tier_level(self) -> int:
        if self._explicit_tier_level is not None:
            return self._explicit_tier_level
        pol = self._refresh_policy()
        if pol is not None:
            raw_tk = getattr(pol, "tier_key", None)
            if raw_tk is not None:
                try:
                    return normalize_tier_level(raw_tk)
                except ValueError:
                    pass
        return 3

    @tier_level.setter
    def tier_level(self, value: Optional[Union[int, str]]) -> None:
        self._explicit_tier_level = None if value is None else normalize_tier_level(value)

    @property
    def workspace_roots(self) -> Tuple[Path, ...]:
        pol = self._refresh_policy()
        if pol is not None:
            pol_roots = _coerce_path_tuple(getattr(pol, "workspace_roots", ()))
            if not self._explicit_workspace_roots:
                return pol_roots
            merged: List[Path] = []
            seen: Set[str] = set()
            for p in (*pol_roots, *self._explicit_workspace_roots):
                k = _norm_abs_key(p)
                if k not in seen:
                    seen.add(k)
                    merged.append(p)
            return tuple(merged)
        return self._explicit_workspace_roots

    @workspace_roots.setter
    def workspace_roots(self, value: Any) -> None:
        self._explicit_workspace_roots = _coerce_path_tuple(value)

    @property
    def state_root(self) -> Optional[Path]:
        if self._explicit_state_root is not None:
            return self._explicit_state_root
        pol = self._refresh_policy()
        if pol is not None:
            pol_sr = _coerce_optional_path(getattr(pol, "state_root", None))
            if pol_sr is not None:
                return pol_sr
        return None

    @state_root.setter
    def state_root(self, value: Optional[Union[str, Path]]) -> None:
        self._explicit_state_root = _coerce_optional_path(value)

    @property
    def restrict_to_workspaces(self) -> bool:
        if self._explicit_restrict_to_workspaces is not None:
            return self._explicit_restrict_to_workspaces
        pol = self._refresh_policy()
        if pol is not None:
            if self.tier_level >= 4:
                return False
            if hasattr(pol, "restrict_to_workspace"):
                return bool(getattr(pol, "restrict_to_workspace"))
            if hasattr(pol, "restrict_to_workspaces"):
                return bool(getattr(pol, "restrict_to_workspaces"))
            return True
        return False

    @restrict_to_workspaces.setter
    def restrict_to_workspaces(self, value: Optional[bool]) -> None:
        self._explicit_restrict_to_workspaces = None if value is None else bool(value)

    @property
    def auto_discover_host_roots(self) -> bool:
        if self._explicit_auto_discover_host_roots is not None:
            return self._explicit_auto_discover_host_roots
        pol = self._refresh_policy()
        if pol is not None:
            return bool(getattr(pol, "scan_host_global_skills", False))
        return not self.restrict_to_workspaces

    @auto_discover_host_roots.setter
    def auto_discover_host_roots(self, value: Optional[bool]) -> None:
        self._explicit_auto_discover_host_roots = None if value is None else bool(value)

    def live_tier_level(self) -> int:
        return self.tier_level

    def live_workspace_roots(self) -> Tuple[Path, ...]:
        return self.workspace_roots

    def live_restrict_to_workspaces(self) -> bool:
        return self.restrict_to_workspaces

    def effective_auto_discover_host_roots(self) -> bool:
        return self.auto_discover_host_roots

    def resolved_home(self) -> Path:
        if self.home_dir is not None:
            h_raw = Path(self.home_dir)
            return (h_raw.expanduser() if str(h_raw).startswith("~") else h_raw).resolve()
        return Path.home().expanduser().resolve()

    def host_skill_roots(self) -> List[Tuple[str, Path]]:
        """Resolve host skill root candidates respecting explicit `home_dir` isolation."""
        explicit_arg: Optional[Path] = self.resolved_home() if self.home_dir is not None else None
        return default_host_skill_roots(explicit_arg)

    def resolved_state_root(self) -> Path:
        sr = self.state_root
        if sr is not None:
            s_raw = Path(sr)
            return (s_raw.expanduser() if str(s_raw).startswith("~") else s_raw).resolve()
        if self.home_dir is None:
            env_root = os.environ.get("COSMOS_SKILLS_STATE_DIR", "").strip()
            if env_root:
                return Path(env_root).expanduser().resolve()
        return (self.resolved_home() / ".cosmos-skills").resolve()

    def managed_skills_store(self) -> Path:
        """Canonical store `<state_root>/skills_store` for managed user-level installations."""
        return self.resolved_state_root() / "skills_store"

    def state_meta_dir(self) -> Path:
        return self.resolved_state_root() / "state"

    def undo_dir(self) -> Path:
        return self.resolved_state_root() / ".undo_history"

    def is_within_workspaces(self, target: Union[str, Path]) -> bool:
        """Return True if `target` resolves inside at least one configured `workspace_roots`."""
        ws_tuple = self.workspace_roots
        if not ws_tuple:
            return False
        try:
            t_res = Path(target).expanduser().resolve()
        except OSError:
            return False
        for ws in ws_tuple:
            try:
                ws_res = Path(ws).expanduser().resolve()
            except OSError:
                continue
            if is_subpath(t_res, ws_res):
                return True
        return False

    def ordered_scan_roots(self, cwd: Optional[Union[str, Path]] = None) -> List[Tuple[str, Path]]:
        """Return ordered `(source_scope_label, root_path)` list for deduplicated skill scanning."""
        roots: List[Tuple[str, Path]] = []
        seen: Set[str] = set()

        def _add(label: str, p: Path) -> None:
            try:
                rp = p.expanduser().resolve()
            except OSError:
                return
            key = os.path.normcase(str(rp)) if os.name == "nt" else str(rp)
            if key not in seen:
                seen.add(key)
                roots.append((label, rp))

        restrict_ws = self.restrict_to_workspaces
        ws_list: List[Path] = []
        if cwd:
            try:
                c_path = Path(cwd).expanduser().resolve()
            except OSError:
                c_path = None
            if c_path is not None and (not restrict_ws or self.is_within_workspaces(c_path)):
                ws_list.append(c_path)
                cur = c_path
                for _ in range(6):
                    if restrict_ws and not self.is_within_workspaces(cur):
                        break
                    if (cur / ".git").exists():
                        if cur not in ws_list:
                            ws_list.append(cur)
                        break
                    if cur.parent == cur:
                        break
                    cur = cur.parent
        for ws in self.workspace_roots:
            try:
                ws_res = Path(ws).expanduser().resolve()
                if ws_res not in ws_list:
                    ws_list.append(ws_res)
            except OSError:
                continue

        for ws in ws_list:
            if (ws / ".agents" / "skills").is_dir():
                _add("workspace", ws / ".agents" / "skills")
            if (ws / ".claude" / "skills").is_dir():
                _add("workspace_claude", ws / ".claude" / "skills")

        store = self.managed_skills_store()
        if store.is_dir():
            _add("managed", store)

        for builtin_root in self._resolve_builtin_host_skills_roots():
            if builtin_root.is_dir():
                _add("antigravity_builtin", builtin_root)

        for extra in self.extra_readonly_roots:
            ep = Path(extra)
            if ep.is_dir():
                _add("extra", ep)

        if self.auto_discover_host_roots:
            for host_label, hp in self.host_skill_roots():
                if hp.is_dir():
                    _add(host_label, hp)
        elif self.home_dir is not None:
            legacy_store = self.resolved_home() / ".cosmos-skills" / "skills_store"
            if legacy_store.is_dir():
                _add("cosmos_skills_store", legacy_store)

        return roots

    def _resolve_builtin_host_skills_roots(self) -> List[Path]:
        """Locate built-in `host_skills` from `<repo>/host_skills` or `<resolved_state_root>/app_src/host_skills`."""
        cand_dirs: List[Path] = []
        try:
            mod_file = Path(__file__).resolve()
            for anc in mod_file.parents[:6]:
                cand_dirs.append(anc / "host_skills")
        except OSError:
            pass
        try:
            cand_dirs.append(self.resolved_state_root() / "app_src" / "host_skills")
        except OSError:
            pass

        chosen: Optional[Path] = None
        seen_c: Set[str] = set()
        for hs in cand_dirs:
            k = _norm_abs_key(hs)
            if k in seen_c:
                continue
            seen_c.add(k)
            try:
                if not hs.is_dir():
                    continue
                has_root_md = (hs / "SKILL.md").is_file() or (hs / "skill.md").is_file()
                has_sub_md = any(
                    ch.is_dir() and not ch.name.startswith(".") and ((ch / "SKILL.md").is_file() or (ch / "skill.md").is_file())
                    for ch in hs.iterdir()
                )
                if has_root_md or has_sub_md:
                    chosen = hs.resolve()
                    break
            except OSError:
                continue

        if chosen is None:
            fallback_bytes = b""
            try:
                from cosmos_mcp.protocol.skill_renderer import render_skill_markdown

                rendered = render_skill_markdown()
                if rendered:
                    fallback_bytes = rendered.encode("utf-8")
            except Exception:
                fallback_bytes = b""
            if not fallback_bytes:
                return []
            bundle_bases_fb = []
            try:
                bundle_bases_fb.append(self.state_meta_dir() / "builtin_host_skills")
            except OSError:
                pass
            bundle_bases_fb.append(Path(tempfile.gettempdir()) / ".cosmos_mcp_builtin_host_skills")
            for b_root in bundle_bases_fb:
                try:
                    dest_md = b_root / "cosmos-mcp-guide" / "SKILL.md"
                    if not dest_md.is_file() or dest_md.read_bytes() != fallback_bytes:
                        atomic_write_bytes(dest_md, fallback_bytes)
                    return [b_root.resolve()]
                except OSError:
                    continue
            return []

        scan_roots: List[Path] = []
        try:
            has_sub = any(
                ch.is_dir() and not ch.name.startswith(".") and ((ch / "SKILL.md").is_file() or (ch / "skill.md").is_file())
                for ch in chosen.iterdir()
            )
            if has_sub:
                scan_roots.append(chosen)
        except OSError:
            pass

        root_md = chosen / "SKILL.md" if (chosen / "SKILL.md").is_file() else (chosen / "skill.md" if (chosen / "skill.md").is_file() else None)
        if root_md is not None:
            slug = "cosmos-mcp-guide"
            try:
                raw_bytes = root_md.read_bytes()
                head_txt = raw_bytes[:4096].decode("utf-8-sig", errors="replace")
                for ln in head_txt.splitlines()[:25]:
                    s_ln = ln.strip()
                    if s_ln.lower().startswith("name:"):
                        cand_nm = s_ln.split(":", 1)[1].strip().strip("\"'")
                        safe_nm = "".join(ch if (ch.isalnum() or ch in "._-") else "-" for ch in cand_nm).strip("-.")
                        if safe_nm:
                            slug = safe_nm
                        break
            except OSError:
                raw_bytes = b""

            if raw_bytes:
                bundle_bases = []
                try:
                    bundle_bases.append(self.state_meta_dir() / "builtin_host_skills")
                except OSError:
                    pass
                bundle_bases.append(Path(tempfile.gettempdir()) / ".cosmos_mcp_builtin_host_skills")

                for b_root in bundle_bases:
                    try:
                        dest_md = b_root / slug / "SKILL.md"
                        if not dest_md.is_file() or dest_md.read_bytes() != raw_bytes:
                            atomic_write_bytes(dest_md, raw_bytes)
                        scan_roots.append(b_root.resolve())
                        break
                    except OSError:
                        continue

        return scan_roots

    def readonly_skill_roots_for_sandbox(self, cwd: Optional[Union[str, Path]] = None) -> Tuple[Path, ...]:
        """Return existing skill roots to register as read+exec-only in L3 Guard & Sandbox."""
        out: List[Path] = []
        store = self.managed_skills_store()
        out.append(store)
        for _, rp in self.ordered_scan_roots(cwd=cwd):
            if rp not in out:
                out.append(rp)
        return tuple(out)


def disabled_skills_state_path(config: SkillsConfig) -> Path:
    """Return `<state_root>/state/disabled_skills.json`."""
    return config.state_meta_dir() / DISABLED_SKILLS_FILE_NAME


def disabled_skills_fingerprint(config: SkillsConfig) -> Tuple[str, int, int]:
    """Return `(norm_state_path, mtime_ns, size)` so BM25F cache invalidates immediately on toggle."""
    fp = disabled_skills_state_path(config)
    p_norm = _norm_abs_key(fp)
    try:
        st = fp.stat()
        mtime_ns = int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))
        return (p_norm, mtime_ns, int(st.st_size))
    except OSError:
        return (p_norm, 0, 0)


def _normalize_skill_id_variants(raw_key: str) -> Set[str]:
    clean = (raw_key or "").strip().lstrip("/").strip().lower()
    if not clean:
        return set()
    return {clean, clean.replace("_", "-"), clean.replace("-", "_")}


def read_disabled_skills_state(config: SkillsConfig) -> Dict[str, Any]:
    """Read `<state_root>/state/disabled_skills.json` safely."""
    fp = disabled_skills_state_path(config)
    default_doc: Dict[str, Any] = {"version": 1, "global": [], "projects": {}, "by_dir": []}
    if not fp.is_file():
        return default_doc
    try:
        raw = json.loads(fp.read_text(encoding="utf-8"))
    except Exception:
        return default_doc
    if not isinstance(raw, dict):
        return default_doc
    glob_list = [str(x).strip().lower() for x in (raw.get("global") or []) if str(x).strip()]
    by_dir_list = [str(x).strip() for x in (raw.get("by_dir") or []) if str(x).strip()]
    proj_map: Dict[str, List[str]] = {}
    raw_proj = raw.get("projects")
    if isinstance(raw_proj, dict):
        for ws_k, arr in raw_proj.items():
            if isinstance(arr, list):
                norm_ws = _norm_abs_key(ws_k)
                vals = sorted({str(x).strip().lower() for x in arr if str(x).strip()})
                if vals:
                    proj_map[norm_ws] = vals
    return {
        "version": 1,
        "global": sorted(set(glob_list)),
        "projects": proj_map,
        "by_dir": sorted(set(by_dir_list)),
    }


def is_skill_disabled(
    config: SkillsConfig,
    *,
    name: str,
    dir_name: str = "",
    skill_dir: Optional[Union[str, Path]] = None,
    source_scope: str = "",
    source_root: Optional[Union[str, Path]] = None,
    disabled_state: Optional[Dict[str, Any]] = None,
) -> bool:
    """Return True if a project, managed, or host skill has been disabled."""
    state = disabled_state if disabled_state is not None else read_disabled_skills_state(config)
    glob_set = set(state.get("global") or ())
    by_dir_set = set(state.get("by_dir") or ())
    proj_map: Dict[str, List[str]] = state.get("projects") or {}

    if not glob_set and not by_dir_set and not proj_map:
        return False

    variants = _normalize_skill_id_variants(name) | _normalize_skill_id_variants(dir_name)
    if skill_dir is not None and str(skill_dir).strip():
        if _norm_abs_key(skill_dir) in by_dir_set:
            return True

    if variants & glob_set:
        return True

    if source_scope in ("workspace", "workspace_claude", "project"):
        cand_ws_keys: Set[str] = set()
        if source_root is not None and str(source_root).strip():
            sr_path = Path(source_root)
            if sr_path.name.lower() == "skills" and sr_path.parent.name.lower() in (".agents", ".claude"):
                cand_ws_keys.add(_norm_abs_key(sr_path.parent.parent))
        if skill_dir is not None and str(skill_dir).strip():
            sd_path = Path(skill_dir)
            if sd_path.parent.name.lower() == "skills" and sd_path.parent.parent.name.lower() in (".agents", ".claude"):
                cand_ws_keys.add(_norm_abs_key(sd_path.parent.parent.parent))
        for wk in cand_ws_keys:
            proj_disabled = set(proj_map.get(wk) or ())
            if variants & proj_disabled:
                return True
        # Also honor workspace containment if a parent workspace root disabled this skill
        if skill_dir is not None and proj_map:
            for wk, p_list in proj_map.items():
                if (variants & set(p_list)) and is_subpath(skill_dir, wk):
                    return True

    return False


def set_skill_disabled_state(
    config: SkillsConfig,
    *,
    skill_key: str,
    enabled: bool,
    scope: str = "managed",
    workspace: Optional[Union[str, Path]] = None,
    skill_dir: Optional[Union[str, Path]] = None,
    extra_keys: Sequence[str] = (),
) -> Dict[str, Any]:
    """Persist enable/disable state for a global/managed/host or project-scoped skill."""
    norm_scope = (scope or "managed").strip().lower()
    is_project_scope = norm_scope in ("project", "workspace")
    key_set: Set[str] = set()
    for raw_k in (skill_key, *extra_keys):
        clean_k = (raw_k or "").strip().lstrip("/").strip().lower()
        if clean_k:
            key_set.add(clean_k)

    with _DISABLED_STATE_LOCK:
        state = read_disabled_skills_state(config)
        glob_set: Set[str] = set(state.get("global") or ())
        by_dir_set: Set[str] = set(state.get("by_dir") or ())
        proj_map: Dict[str, Set[str]] = {
            k: set(v) for k, v in (state.get("projects") or {}).items()
        }

        dir_norm = _norm_abs_key(skill_dir) if (skill_dir is not None and str(skill_dir).strip()) else ""
        ws_norm = ""
        if workspace is not None and str(workspace).strip():
            ws_norm = _norm_abs_key(workspace)
        elif is_project_scope and skill_dir is not None and str(skill_dir).strip():
            sd_p = Path(skill_dir)
            if sd_p.parent.name.lower() == "skills" and sd_p.parent.parent.name.lower() in (".agents", ".claude"):
                ws_norm = _norm_abs_key(sd_p.parent.parent.parent)
        elif is_project_scope and config.workspace_roots:
            ws_norm = _norm_abs_key(config.workspace_roots[0])

        if enabled:
            all_variants: Set[str] = set()
            for k in key_set:
                all_variants |= _normalize_skill_id_variants(k)
            if dir_norm:
                by_dir_set.discard(dir_norm)
            if is_project_scope and ws_norm:
                if ws_norm in proj_map:
                    proj_map[ws_norm] -= all_variants
                    if not proj_map[ws_norm]:
                        proj_map.pop(ws_norm, None)
            else:
                glob_set -= all_variants
                for wk in list(proj_map.keys()):
                    proj_map[wk] -= all_variants
                    if not proj_map[wk]:
                        proj_map.pop(wk, None)
                if dir_norm:
                    by_dir_set.discard(dir_norm)
        else:
            if dir_norm:
                by_dir_set.add(dir_norm)
            if is_project_scope and ws_norm:
                proj_map.setdefault(ws_norm, set()).update(key_set)
            else:
                glob_set.update(key_set)

        new_doc = {
            "version": 1,
            "global": sorted(glob_set),
            "projects": {k: sorted(v) for k, v in sorted(proj_map.items()) if v},
            "by_dir": sorted(by_dir_set),
        }
        atomic_write_json(disabled_skills_state_path(config), new_doc)
        return new_doc


@dataclass
class SkillRecord:
    """Normalized metadata for a discovered local skill."""

    name: str
    dir_name: str
    description: str
    full_description: str
    skill_dir: str
    source_root: str
    source_scope: str
    scripts_count: int = 0
    references_count: int = 0
    assets_count: int = 0
    has_scripts: bool = False
    trust_tier: str = "local_prompt_only"
    license: str = ""
    compatibility: str = ""
    allowed_tools: Tuple[str, ...] = ()
    requires_bins: Tuple[str, ...] = ()
    requires_env: Tuple[str, ...] = ()
    metadata: Dict[str, Any] = field(default_factory=dict)
    mtime_ns: int = 0
    enabled: bool = True

    def to_summary_dict(self, score: Optional[float] = None, matched_terms: Optional[int] = None) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "dir_name": self.dir_name,
            "description": self.description,
            "source_scope": self.source_scope,
            "source_root": self.source_root,
            "skill_dir": self.skill_dir,
            "enabled": bool(self.enabled),
            "has_scripts": self.has_scripts,
            "scripts_count": self.scripts_count,
            "references_count": self.references_count,
            "assets_count": self.assets_count,
            "trust_tier": self.trust_tier,
        }
        if self.requires_bins:
            d["requires_bins"] = list(self.requires_bins)
        if self.requires_env:
            d["requires_env"] = list(self.requires_env)
        if score is not None:
            d["score"] = score
        if matched_terms is not None:
            d["matched_terms"] = matched_terms
        return d


@dataclass
class VirtualFileEntry:
    """In-memory file entry extracted from an archive or local folder prior to vetting/install."""

    rel_path: str
    raw_bytes: Optional[bytes] = None
    is_symlink: bool = False
    symlink_escapes: bool = False
    path_traversal: bool = False
    oversized: bool = False
    actual_size: int = 0


@dataclass
class SecurityFinding:
    """Single finding produced by the 3-tier supply-chain vetter."""

    severity: str  # "BLOCK" | "WARN" | "INFO"
    rule_id: str
    file_rel: str
    detail: str
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityAuditReport:
    """Aggregated 3-tier security audit report for a skill package."""

    skill_name: str
    verdict: str = "INFO"  # "BLOCK" | "WARN" | "INFO"
    findings: List[SecurityFinding] = field(default_factory=list)
    stripped_files: List[str] = field(default_factory=list)
    scripts_detected: List[str] = field(default_factory=list)

    def add(self, severity: str, rule_id: str, file_rel: str, detail: str, remediation: str = "") -> None:
        self.findings.append(SecurityFinding(severity, rule_id, file_rel, detail, remediation))
        rank = {"INFO": 0, "WARN": 1, "BLOCK": 2}
        if rank.get(severity, 0) > rank.get(self.verdict, 0):
            self.verdict = severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "skill_name": self.skill_name,
            "verdict": self.verdict,
            "blocked": self.verdict == "BLOCK",
            "requires_confirmation": self.verdict == "WARN",
            "scripts_detected": list(self.scripts_detected),
            "stripped_files": list(self.stripped_files),
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class MarketCandidate:
    """Normalized search candidate from skills.sh, ClawHub, Official MCP Registry, or GitHub."""

    source: str
    id: str
    name: str
    owner: str = ""
    summary: str = ""
    source_url: str = ""
    install_ref: str = ""
    version: str = ""
    popularity: int = 0
    kind: str = "skill"
    audit_info: Dict[str, Any] = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FetchedSkillPackage:
    """Single-pass in-memory fetched skill package ready for vetting and atomic installation."""

    source_type: str
    source_id: str
    source_url: str
    skill_name: str
    entries: List[VirtualFileEntry]
    commit_sha: str = ""
    version: str = ""
    ref: str = ""
    subpath: str = ""
    upstream_audit: Dict[str, Any] = field(default_factory=dict)
