"""Single-source-of-truth one-click self-updater, staging verifier, and 15-second rollback watchdog.

Enforces:
- 100% pure Python standard-library top-level imports (Python 3.10~3.14 compatible, zero f-string backslashes).
- Zero permanent file deletion (`_sync_clean_dir_tree` + `safe_trash_file` only; never `shutil.rmtree` or `unlink`).
- Tamper-resistant staging: 80 MiB download cap, SHA-256 verification, Zip-Slip / symlink rejection, and full-tree
  Python `ast.parse` syntax verification before touching `<state_root>/app_src`.
- Pre-flight dependency satisfaction check (`importlib.metadata` + PEP 440/508 markers) so updates with unchanged
  dependencies finish offline with zero `pip` invocations, while unsatisfiable dependencies abort cleanly.
- Zero-drop tunnel continuity (`worker_hot_reload` when tunnel supervisor code is unchanged or when an active
  ephemeral `trycloudflare.com` URL must be preserved) + detached 15-second `/healthz` watchdog auto-rollback.
"""
from __future__ import annotations

import argparse
import ast
import contextlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
import urllib.error
from urllib.parse import urlsplit
import urllib.request
import zipfile

try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    tomllib = None  # type: ignore[assignment]

from cosmos_mcp.core.fs_tx import atomic_write_json, safe_trash_file
from cosmos_mcp.core.net_power import detect_configured_proxy
from cosmos_mcp.core.proc import (
    CREATE_NO_WINDOW,
    is_raw_pid_alive,
    resolve_console_python,
    verify_pid_alive,
)
from cosmos_mcp.launcher.bootstrap import (
    _clean_subproc_env,
    _locate_venv_site_packages,
    _sync_clean_dir_tree,
    _write_venv_src_pth,
    atomic_write_text,
    compute_source_tree_hash,
    ensure_embed_pth_site_enabled,
    find_embedded_python_exe,
    find_repo_root,
    find_repo_src_dir,
    parse_semver_tuple,
    pip_install_with_mirror_fallback,
    read_app_src_update_meta,
    read_package_init_version,
    sync_portable_app_src,
    venv_python_path,
    write_app_src_update_meta,
)
from cosmos_mcp.launcher.daemon import (
    CREATE_BREAKAWAY_FROM_JOB,
    CREATE_NEW_PROCESS_GROUP,
    DETACHED_PROCESS,
    _is_stop_active,
    daemon_status_path,
    detect_running_instance,
    probe_local_healthz,
    request_worker_hot_reload,
    sanitize_daemon_inherited_env,
    service_cfg_path,
    spawn_detached_daemon,
    stop_daemon,
)

GITHUB_REPO_SLUG = "cosmosomo/WebAI2PC"
DEFAULT_GITHUB_API_BASE = "https://api.github.com"
DEFAULT_CODELOAD_BASE = "https://codeload.github.com"
MAX_UPDATE_ARCHIVE_BYTES = 80 * 1024 * 1024  # 80 MiB
MAX_EXTRACTED_TOTAL_BYTES = 260 * 1024 * 1024  # 260 MiB zip-bomb guard
PROXY_FALLBACK_HTTP_CODES: frozenset[int] = frozenset({407, 502, 503, 504})
LAUNCHER_TUNNEL_REL_FILES: Tuple[str, ...] = (
    "launcher/daemon.py",
    "launcher/tunnels.py",
    "launcher/cf_workers_gateway.py",
)

_PACK_TO_OPTIONAL_GROUP: Dict[str, str] = {
    "browser": "browser",
    "docs": "docs",
    "code": "code",
    "full": "full",
}
_SHA256_HEX_RE = re.compile(r"\b([0-9a-fA-F]{64})\b")
_REQ_SPLIT_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(.*)$")
_SPEC_OP_RE = re.compile(r"^(~=|==|!=|<=|>=|<|>)\s*([^\s,]+)$")
_MARKER_CMP_RE = re.compile(
    r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(==|!=|<=|>=|<|>|in|not\s+in)\s*['\"]([^'\"]*)['\"]\s*$"
)


def _norm_prefix(prefix: str) -> str:
    val = (prefix or "pc").strip().lower()
    return val if val else "pc"


def last_update_status_path(state_root: Path, prefix: str = "pc") -> Path:
    eff = _norm_prefix(prefix)
    name = f"last_update_status_{eff}.json" if eff != "pc" else "last_update_status.json"
    return Path(state_root).expanduser().resolve() / "state" / name


def compute_app_src_revision(src_cosmos_dir: Path) -> str:
    """Compute deterministic 12-char hex SHA-256 revision over `cosmos_mcp` source tree."""
    digest = compute_source_tree_hash(src_cosmos_dir)
    return digest[:12] if digest else ""


def _normalize_dist_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").strip()).lower()


def _resolve_active_cosmos_dir(state_root: Path) -> Tuple[Optional[Path], Dict[str, Any]]:
    st_root = Path(state_root).expanduser().resolve()
    app_src = st_root / "app_src"
    if (app_src / "cosmos_mcp" / "__init__.py").is_file():
        return app_src / "cosmos_mcp", read_app_src_update_meta(app_src)
    repo_src = find_repo_src_dir()
    if repo_src is not None and (repo_src / "cosmos_mcp" / "__init__.py").is_file():
        return repo_src / "cosmos_mcp", {}
    return None, {}


def _inspect_tunnel_impact(state_root: Path, prefix: str = "pc") -> Dict[str, Any]:
    st_root = Path(state_root).expanduser().resolve()
    eff_p = _norm_prefix(prefix)
    d_path = daemon_status_path(st_root, eff_p)
    cfg_path = service_cfg_path(st_root, eff_p)

    d_doc: Dict[str, Any] = {}
    if d_path.is_file():
        with contextlib.suppress(Exception):
            loaded = json.loads(d_path.read_text(encoding="utf-8-sig"))
            if isinstance(loaded, dict) and str(loaded.get("status") or "") != "stopped":
                d_doc = loaded

    cfg_doc: Dict[str, Any] = {}
    if cfg_path.is_file():
        with contextlib.suppress(Exception):
            loaded_c = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
            if isinstance(loaded_c, dict):
                cfg_doc = loaded_c

    eff_mode = str(
        d_doc.get("effective_tunnel_mode")
        or d_doc.get("mode")
        or cfg_doc.get("tunnel_mode")
        or "local"
    ).strip().lower() or "local"

    https_urls: List[str] = []
    gws = d_doc.get("gateways")
    if isinstance(gws, dict):
        for gw_item in gws.values():
            if not isinstance(gw_item, dict) or not gw_item.get("enabled"):
                continue
            gu = str(gw_item.get("public_url") or "").strip().rstrip("/")
            if gu.startswith("https://") and gu not in https_urls:
                https_urls.append(gu)

    top_pub = str(d_doc.get("public_url") or cfg_doc.get("public_base") or "").strip().rstrip("/")
    if top_pub.startswith("https://") and top_pub not in https_urls:
        https_urls.append(top_pub)

    def _is_trycf(u: str) -> bool:
        host = (urlsplit(u).hostname or "").strip().lower()
        return host.endswith(".trycloudflare.com") and host != "api.trycloudflare.com"

    ephemeral_urls = [u for u in https_urls if _is_trycf(u)]
    fixed_urls = [u for u in https_urls if not _is_trycf(u)]
    if not https_urls and eff_mode == "cloudflare" and not bool(d_doc.get("srvus_fixed_active")):
        only_trycf = True
    else:
        only_trycf = bool(ephemeral_urls) and not bool(fixed_urls)
    has_fixed = bool(fixed_urls) or bool(d_doc.get("srvus_fixed_active"))

    return {
        "mode": eff_mode,
        "public_url": top_pub or (https_urls[0] if https_urls else ""),
        "active_https_urls": https_urls,
        "has_fixed_public_url": has_fixed,
        "only_ephemeral_trycloudflare": only_trycf,
        "url_changes_on_full_restart": only_trycf,
        "worker_hot_reload_supported": True,
    }


def _apply_mirror_to_url(raw_url: str, mirror_base: str) -> str:
    clean_u = (raw_url or "").strip()
    clean_m = (mirror_base or "").strip().rstrip("/")
    if not clean_u or not clean_m:
        return clean_u
    parsed = urlsplit(clean_u)
    host = (parsed.hostname or "").strip().lower()
    if host in ("127.0.0.1", "localhost", "::1") or clean_u.startswith(clean_m):
        return clean_u
    if host in ("github.com", "codeload.github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"):
        return f"{clean_m}/{clean_u}"
    return clean_u


def _is_allowed_download_url(raw_url: str) -> bool:
    parsed = urlsplit((raw_url or "").strip())
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return False
    if scheme == "https":
        return True
    if scheme == "http" and (host in ("127.0.0.1", "localhost", "::1") or host.startswith("127.")):
        return True
    return False


def _build_urllib_openers_with_proxy_fallback(target_url: str) -> List[Tuple[str, urllib.request.OpenerDirector]]:
    parsed = urlsplit(target_url)
    host = (parsed.hostname or "").strip().lower()
    scheme = (parsed.scheme or "https").lower()
    openers: List[Tuple[str, urllib.request.OpenerDirector]] = []

    raw_proxy = detect_configured_proxy(scheme=scheme, target_host=host)
    if raw_proxy:
        p_scheme = (urlsplit(raw_proxy).scheme or "").lower()
        if p_scheme in ("http", "https"):
            px_handler = urllib.request.ProxyHandler({"http": raw_proxy, "https": raw_proxy})
            openers.append((raw_proxy, urllib.request.build_opener(px_handler)))

    openers.append(("", urllib.request.build_opener(urllib.request.ProxyHandler({}))))
    return openers


def _http_get_bytes_with_proxy_fallback(
    url: str,
    *,
    timeout_sec: float = 8.0,
    accept: str = "application/vnd.github+json",
    max_bytes: int = MAX_UPDATE_ARCHIVE_BYTES,
) -> Tuple[int, bytes, str]:
    """Fetch `url` trying configured proxy first, falling back to direct `ProxyHandler({})` on 407/502/503/504 or proxy failure."""
    openers = _build_urllib_openers_with_proxy_fallback(url)
    headers = {
        "User-Agent": "Cosmos-MCP-Updater/1.2",
        "Accept": accept,
    }
    last_exc: Optional[BaseException] = None
    for idx, (proxy_label, opener) in enumerate(openers):
        has_next = idx + 1 < len(openers)
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with opener.open(req, timeout=max(1.0, float(timeout_sec))) as resp:
                status = int(getattr(resp, "status", 200) or 200)
                if proxy_label and has_next and status in PROXY_FALLBACK_HTTP_CODES:
                    continue
                chunks: List[bytes] = []
                total = 0
                while True:
                    buf = resp.read(65536)
                    if not buf:
                        break
                    total += len(buf)
                    if total > max_bytes:
                        raise ValueError(f"ERR_ARCHIVE_TOO_LARGE:{total}>{max_bytes}")
                    chunks.append(buf)
                return status, b"".join(chunks), proxy_label
        except urllib.error.HTTPError as http_err:
            code = int(getattr(http_err, "code", 0) or 0)
            if proxy_label and has_next and code in PROXY_FALLBACK_HTTP_CODES:
                last_exc = http_err
                continue
            err_body = b""
            with contextlib.suppress(Exception):
                err_body = http_err.read(65536)
            return code, err_body, proxy_label
        except urllib.error.URLError as url_err:
            last_exc = url_err
            if proxy_label and has_next:
                continue
            raise
        except Exception as exc:
            last_exc = exc
            if isinstance(exc, ValueError) and str(exc).startswith("ERR_ARCHIVE_TOO_LARGE:"):
                raise
            if proxy_label and has_next:
                continue
            raise
    if last_exc is not None:
        raise last_exc
    raise RuntimeError(f"Failed fetching URL: {url}")


def _extract_sha256_from_release(doc: Dict[str, Any], chosen_asset: Optional[Dict[str, Any]]) -> str:
    if isinstance(chosen_asset, dict):
        raw_digest = str(chosen_asset.get("digest") or chosen_asset.get("sha256") or "").strip()
        if raw_digest.lower().startswith("sha256:"):
            cand = raw_digest.split(":", 1)[1].strip()
            if len(cand) == 64 and all(c in "0123456789abcdefABCDEF" for c in cand):
                return cand.lower()
        elif len(raw_digest) == 64 and all(c in "0123456789abcdefABCDEF" for c in raw_digest):
            return raw_digest.lower()

        asset_name = str(chosen_asset.get("name") or "").strip()
        body_txt = str(doc.get("body") or "")
        if asset_name and body_txt:
            for ln in body_txt.splitlines():
                if asset_name in ln:
                    m_ln = _SHA256_HEX_RE.search(ln)
                    if m_ln:
                        return m_ln.group(1).lower()

    direct_sha = str(doc.get("expected_sha256") or doc.get("sha256") or "").strip()
    if len(direct_sha) == 64 and all(c in "0123456789abcdefABCDEF" for c in direct_sha):
        return direct_sha.lower()
    return ""


def _pick_release_zip_asset(assets: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(assets, list):
        return None
    zip_assets = [
        a
        for a in assets
        if isinstance(a, dict)
        and str(a.get("name") or "").lower().endswith(".zip")
        and str(a.get("browser_download_url") or "").strip()
    ]
    if not zip_assets:
        return None
    # Prefer lightweight cross-platform source/portable ZIP (`Cosmos-MCP-vX.Y.Z.zip`) over huge full-embed bundle
    for item in zip_assets:
        nm = str(item.get("name") or "").lower()
        if "win64-full" not in nm and "embed" not in nm:
            return item
    return zip_assets[0]


def check_for_updates(
    state_root: Path,
    *,
    prefix: str = "pc",
    channel: str = "release",
    timeout_sec: float = 8.0,
) -> Dict[str, Any]:
    """Query GitHub Releases (`channel='release'`, auto-fallback to `'main'` on 404) or `commits/main`."""
    st_root = Path(state_root).expanduser().resolve()
    eff_p = _norm_prefix(prefix)
    req_channel = (channel or "release").strip().lower()
    if req_channel not in ("release", "main"):
        req_channel = "release"

    cosmos_dir, meta = _resolve_active_cosmos_dir(st_root)
    current_version = (
        read_package_init_version(cosmos_dir / "__init__.py")
        if cosmos_dir is not None
        else ""
    ) or str(meta.get("version") or "0.0.0")
    current_revision = compute_app_src_revision(cosmos_dir) if cosmos_dir is not None else ""
    current_commit = str(meta.get("commit_sha") or "").strip()
    tunnel_impact = _inspect_tunnel_impact(st_root, prefix=eff_p)

    api_base = (os.environ.get("COSMOS_UPDATE_API_BASE") or DEFAULT_GITHUB_API_BASE).strip().rstrip("/")
    override_archive_url = (os.environ.get("COSMOS_UPDATE_ARCHIVE_URL") or "").strip()
    mirror_base = (os.environ.get("COSMOS_UPDATE_MIRROR") or "").strip()

    fallback_to_main = False
    eff_channel = req_channel
    proxy_used = ""
    latest_version = current_version
    latest_commit = ""
    download_url = ""
    expected_sha256 = (os.environ.get("COSMOS_UPDATE_EXPECTED_SHA256") or "").strip().lower()
    release_notes = ""

    try:
        if req_channel == "release":
            rel_api_url = f"{api_base}/repos/{GITHUB_REPO_SLUG}/releases/latest"
            status_code, raw_bytes, px = _http_get_bytes_with_proxy_fallback(
                rel_api_url,
                timeout_sec=timeout_sec,
                accept="application/vnd.github+json",
                max_bytes=4 * 1024 * 1024,
            )
            proxy_used = px
            if status_code == 404:
                fallback_to_main = True
                eff_channel = "main"
            elif status_code != 200:
                return {
                    "ok": False,
                    "error_code": f"ERR_HTTP_{status_code}",
                    "error": f"查询更新接口返回 HTTP {status_code}",
                    "channel": req_channel,
                    "fallback_to_main": False,
                    "current_version": current_version,
                    "current_revision": current_revision,
                    "current_commit": current_commit,
                    "latest_version": "",
                    "latest_commit": "",
                    "update_available": False,
                    "download_url": "",
                    "expected_sha256": "",
                    "release_notes": "",
                    "proxy_used": proxy_used,
                    "tunnel_impact": tunnel_impact,
                }
            else:
                rel_doc = json.loads(raw_bytes.decode("utf-8", errors="replace"))
                raw_tag = str(rel_doc.get("tag_name") or rel_doc.get("name") or "").strip()
                if not raw_tag:
                    fallback_to_main = True
                    eff_channel = "main"
                else:
                    latest_version = raw_tag.lstrip("vV") or current_version
                    raw_commitish = str(rel_doc.get("target_commitish") or "").strip()
                    if len(raw_commitish) >= 7 and all(c in "0123456789abcdefABCDEF" for c in raw_commitish):
                        latest_commit = raw_commitish.lower()
                    chosen_asset = _pick_release_zip_asset(rel_doc.get("assets"))
                    if chosen_asset is not None:
                        download_url = str(chosen_asset.get("browser_download_url") or "").strip()
                    else:
                        download_url = (
                            str(rel_doc.get("zipball_url") or "").strip()
                            or f"{DEFAULT_CODELOAD_BASE}/{GITHUB_REPO_SLUG}/zip/refs/tags/{raw_tag}"
                        )
                    if not expected_sha256:
                        expected_sha256 = _extract_sha256_from_release(rel_doc, chosen_asset)
                    release_notes = str(rel_doc.get("body") or "").strip()

        if eff_channel == "main":
            main_api_url = f"{api_base}/repos/{GITHUB_REPO_SLUG}/commits/main"
            status_m, raw_m, px_m = _http_get_bytes_with_proxy_fallback(
                main_api_url,
                timeout_sec=timeout_sec,
                accept="application/vnd.github+json",
                max_bytes=4 * 1024 * 1024,
            )
            proxy_used = px_m
            if status_m != 200:
                return {
                    "ok": False,
                    "error_code": f"ERR_HTTP_{status_m}",
                    "error": f"查询主干提交接口返回 HTTP {status_m}",
                    "channel": req_channel,
                    "fallback_to_main": fallback_to_main,
                    "current_version": current_version,
                    "current_revision": current_revision,
                    "current_commit": current_commit,
                    "latest_version": "",
                    "latest_commit": "",
                    "update_available": False,
                    "download_url": "",
                    "expected_sha256": "",
                    "release_notes": "",
                    "proxy_used": proxy_used,
                    "tunnel_impact": tunnel_impact,
                }
            commit_doc = json.loads(raw_m.decode("utf-8", errors="replace"))
            latest_commit = str(commit_doc.get("sha") or "").strip().lower()
            if commit_doc.get("version"):
                latest_version = str(commit_doc["version"]).strip().lstrip("vV")
            commit_inner = commit_doc.get("commit") if isinstance(commit_doc.get("commit"), dict) else {}
            msg = str(commit_inner.get("message") or commit_doc.get("message") or "").strip()
            committer_info = commit_inner.get("committer") if isinstance(commit_inner.get("committer"), dict) else {}
            author_info = commit_inner.get("author") if isinstance(commit_inner.get("author"), dict) else {}
            c_date = str(committer_info.get("date") or author_info.get("date") or "").strip()
            summary_line = msg.splitlines()[0].strip() if msg else ""
            release_notes = f"{summary_line} ({c_date})" if (summary_line and c_date) else (summary_line or c_date)
            download_url = (
                str(commit_doc.get("download_url") or "").strip()
                or f"{DEFAULT_CODELOAD_BASE}/{GITHUB_REPO_SLUG}/zip/refs/heads/main"
            )
            if not expected_sha256 and commit_doc.get("expected_sha256"):
                expected_sha256 = str(commit_doc["expected_sha256"]).strip().lower()
    except Exception as exc:
        return {
            "ok": False,
            "error_code": "ERR_NETWORK_UNREACHABLE",
            "error": f"检查更新失败：{exc}",
            "channel": req_channel,
            "fallback_to_main": fallback_to_main,
            "current_version": current_version,
            "current_revision": current_revision,
            "current_commit": current_commit,
            "latest_version": "",
            "latest_commit": "",
            "update_available": False,
            "download_url": "",
            "expected_sha256": "",
            "release_notes": "",
            "proxy_used": proxy_used,
            "tunnel_impact": tunnel_impact,
        }

    if override_archive_url:
        download_url = override_archive_url
    elif mirror_base:
        download_url = _apply_mirror_to_url(download_url, mirror_base)

    cur_v_tup = parse_semver_tuple(current_version)
    lat_v_tup = parse_semver_tuple(latest_version)
    if eff_channel == "release":
        if lat_v_tup > cur_v_tup:
            update_available = True
        elif lat_v_tup == cur_v_tup and latest_commit and current_commit:
            c_low = current_commit.lower()
            l_low = latest_commit.lower()
            update_available = not (l_low.startswith(c_low) or c_low.startswith(l_low))
        else:
            update_available = False
    else:
        if lat_v_tup > cur_v_tup:
            update_available = True
        elif latest_commit:
            if not current_commit:
                update_available = True
            else:
                c_low = current_commit.lower()
                l_low = latest_commit.lower()
                update_available = not (l_low.startswith(c_low) or c_low.startswith(l_low))
        else:
            update_available = False

    return {
        "ok": True,
        "channel": eff_channel,
        "requested_channel": req_channel,
        "fallback_to_main": fallback_to_main,
        "current_version": current_version,
        "current_revision": current_revision,
        "current_commit": current_commit,
        "latest_version": latest_version,
        "latest_commit": latest_commit,
        "update_available": update_available,
        "download_url": download_url,
        "expected_sha256": expected_sha256,
        "release_notes": release_notes,
        "proxy_used": proxy_used,
        "tunnel_impact": tunnel_impact,
    }


def _extract_toml_string_array_regex(section_body: str, key_name: str) -> List[str]:
    pat = re.compile(r"(?m)^\s*" + re.escape(key_name) + r"\s*=\s*\[(.*?)\]", re.DOTALL)
    m = pat.search(section_body)
    if not m:
        return []
    arr_txt = m.group(1)
    cleaned_lines: List[str] = []
    for raw_ln in arr_txt.splitlines():
        in_sq = False
        in_dq = False
        cut_idx = len(raw_ln)
        for i, ch in enumerate(raw_ln):
            if ch == "'" and not in_dq:
                in_sq = not in_sq
            elif ch == '"' and not in_sq:
                in_dq = not in_dq
            elif ch == "#" and not in_sq and not in_dq:
                cut_idx = i
                break
        cleaned_lines.append(raw_ln[:cut_idx])
    joined = "\n".join(cleaned_lines)
    items: List[str] = []
    for m_str in re.finditer(r'''"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)' ''', joined, re.VERBOSE):
        raw_val = m_str.group(1) if m_str.group(1) is not None else (m_str.group(2) or "")
        val = raw_val.strip()
        if val:
            items.append(val)
    return items


def parse_pyproject_dependency_specs(
    pyproject_text: str,
    *,
    enabled_packs: Sequence[str] = (),
) -> List[str]:
    """Parse `[project].dependencies` and selected `optional-dependencies` via `tomllib` or stdlib regex fallback."""
    specs: List[str] = []
    opt_groups = [
        _PACK_TO_OPTIONAL_GROUP[pk_norm]
        for pk_norm in (str(p or "").strip().lower() for p in enabled_packs)
        if pk_norm in _PACK_TO_OPTIONAL_GROUP
    ]

    if tomllib is not None:
        doc = tomllib.loads(pyproject_text)
        proj = doc.get("project") if isinstance(doc, dict) else None
        if isinstance(proj, dict):
            raw_deps = proj.get("dependencies")
            if isinstance(raw_deps, list):
                specs.extend(str(x).strip() for x in raw_deps if str(x).strip())
            raw_opt = proj.get("optional-dependencies")
            if isinstance(raw_opt, dict):
                for grp in opt_groups:
                    grp_list = raw_opt.get(grp)
                    if isinstance(grp_list, list):
                        for item in grp_list:
                            s_item = str(item).strip()
                            if s_item and s_item not in specs:
                                specs.append(s_item)
        return specs

    # Python 3.10 regex fallback
    sections: Dict[str, str] = {}
    cur_sec = ""
    buf: List[str] = []
    for ln in pyproject_text.splitlines():
        s_ln = ln.strip()
        if s_ln.startswith("[") and s_ln.endswith("]") and not s_ln.startswith("[["):
            if cur_sec:
                sections[cur_sec] = "\n".join(buf)
            cur_sec = s_ln[1:-1].strip()
            buf = []
        else:
            buf.append(ln)
    if cur_sec:
        sections[cur_sec] = "\n".join(buf)

    proj_body = sections.get("project", "")
    specs.extend(_extract_toml_string_array_regex(proj_body, "dependencies"))
    opt_body = sections.get("project.optional-dependencies", "")
    for grp in opt_groups:
        for item in _extract_toml_string_array_regex(opt_body, grp):
            if item not in specs:
                specs.append(item)
    return specs


def _pep440_key(ver_str: str) -> Tuple[Tuple[int, ...], int, int]:
    """Convert PEP 440 version string into comparable `(release_tuple, stage_rank, stage_num)`."""
    clean = (ver_str or "").strip().lstrip("vV").split("+", 1)[0].strip()
    m = re.match(r"^(\d+(?:\.\d+)*)(?:[-._]?(a|alpha|b|beta|rc|c|pre|preview|post|dev)(\d*))?", clean, re.IGNORECASE)
    if not m:
        nums_fallback = [int(x) for x in re.findall(r"\d+", clean)]
        while len(nums_fallback) < 3:
            nums_fallback.append(0)
        return (tuple(nums_fallback), 0, 0)
    rel_nums = [int(x) for x in m.group(1).split(".")]
    while len(rel_nums) > 1 and rel_nums[-1] == 0:
        rel_nums.pop()
    tag = (m.group(2) or "").lower()
    tag_num = int(m.group(3) or "0")
    if not tag:
        stage_rank = 0
    elif tag == "post":
        stage_rank = 1
    elif tag == "dev":
        stage_rank = -4
    elif tag in ("a", "alpha"):
        stage_rank = -3
    elif tag in ("b", "beta"):
        stage_rank = -2
    else:
        stage_rank = -1
    return (tuple(rel_nums), stage_rank, tag_num)


def _compare_pep440(installed_ver: str, op: str, target_ver: str) -> bool:
    if op in ("==", "!=") and target_ver.endswith(".*"):
        prefix_parts = [int(x) for x in target_ver[:-2].split(".") if x.isdigit()]
        inst_parts = [int(x) for x in re.findall(r"\d+", installed_ver.split("+", 1)[0])]
        while len(inst_parts) < len(prefix_parts):
            inst_parts.append(0)
        matched = inst_parts[: len(prefix_parts)] == prefix_parts
        return matched if op == "==" else (not matched)

    k_inst = _pep440_key(installed_ver)
    k_tgt = _pep440_key(target_ver)
    if op == ">=":
        return k_inst >= k_tgt
    if op == "<=":
        return k_inst <= k_tgt
    if op == ">":
        return k_inst > k_tgt
    if op == "<":
        return k_inst < k_tgt
    if op == "==":
        return k_inst == k_tgt
    if op == "!=":
        return k_inst != k_tgt
    if op == "~=":
        raw_parts = [int(x) for x in re.findall(r"\d+", target_ver.split("+", 1)[0])]
        if len(raw_parts) < 2:
            return k_inst >= k_tgt
        upper_parts = list(raw_parts[:-1])
        upper_parts[-1] += 1
        upper_str = ".".join(str(x) for x in upper_parts)
        return k_inst >= k_tgt and k_inst < _pep440_key(upper_str)
    return True


def _eval_single_marker_atom(atom: str, env_info: Dict[str, str]) -> bool:
    s = atom.strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        wrapped = True
        for idx, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and idx < len(s) - 1:
                    wrapped = False
                    break
        if wrapped:
            s = s[1:-1].strip()
        else:
            break

    m = _MARKER_CMP_RE.match(s)
    if not m:
        return True
    var_name, op_raw, rhs = m.group(1), re.sub(r"\s+", " ", m.group(2).strip()), m.group(3)
    lhs = env_info.get(var_name, "")
    if var_name in ("python_version", "python_full_version"):
        return _compare_pep440(lhs, op_raw, rhs)
    if op_raw == "==":
        return lhs == rhs
    if op_raw == "!=":
        return lhs != rhs
    if op_raw == "in":
        return lhs in rhs
    if op_raw == "not in":
        return lhs not in rhs
    return True


def _evaluate_pep508_marker(marker_expr: str, env_info: Dict[str, str]) -> bool:
    clean = (marker_expr or "").strip()
    if not clean:
        return True
    or_clauses = re.split(r"\bor\b", clean)
    for or_part in or_clauses:
        and_atoms = re.split(r"\band\b", or_part)
        if all(_eval_single_marker_atom(atom, env_info) for atom in and_atoms if atom.strip()):
            return True
    return False


def _probe_python_installed_distributions(
    python_exe: str | Path,
    package_names: Sequence[str] = (),
    timeout_sec: float = 12.0,
) -> Optional[Dict[str, Any]]:
    raw_exe = str(python_exe or "").strip()
    if not raw_exe:
        return None
    console_py = resolve_console_python(raw_exe) or raw_exe
    if not Path(console_py).is_file():
        if Path(raw_exe).is_file():
            console_py = raw_exe
        else:
            return None

    dedup_names: List[str] = []
    for nm in package_names:
        c_nm = str(nm or "").strip()
        if c_nm and c_nm not in dedup_names:
            dedup_names.append(c_nm)

    probe_code = (
        "import importlib.metadata as md, importlib.util, json, os, platform, re, sys\n"
        f"targets = {json.dumps(dedup_names)}\n"
        "dists = {}\n"
        "for raw_nm in targets:\n"
        "    key = re.sub(r'[-_.]+', '-', str(raw_nm).strip()).lower()\n"
        "    for cand in (raw_nm, key, key.replace('-', '_')):\n"
        "        try:\n"
        "            dists[key] = str(md.version(cand))\n"
        "            break\n"
        "        except Exception:\n"
        "            continue\n"
        "has_pip = importlib.util.find_spec('pip') is not None\n"
        "print(json.dumps({\n"
        "    'python_version': f'{sys.version_info[0]}.{sys.version_info[1]}',\n"
        "    'python_full_version': f'{sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}',\n"
        "    'sys_platform': sys.platform,\n"
        "    'os_name': os.name,\n"
        "    'platform_system': platform.system(),\n"
        "    'platform_machine': platform.machine(),\n"
        "    'implementation_name': sys.implementation.name,\n"
        "    'has_pip': has_pip,\n"
        "    'dists': dists,\n"
        "}))\n"
    )
    flags = CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        proc = subprocess.run(
            [console_py, "-B", "-c", probe_code],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
            env=_clean_subproc_env(),
            creationflags=flags,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    for ln in reversed((proc.stdout or "").splitlines()):
        s_ln = ln.strip()
        if s_ln.startswith("{") and s_ln.endswith("}"):
            with contextlib.suppress(Exception):
                doc = json.loads(s_ln)
                if isinstance(doc, dict) and isinstance(doc.get("dists"), dict):
                    return doc
    return None


def check_pyproject_deps_satisfied(
    pyproject_text: str,
    *,
    python_exe: str | Path,
    enabled_packs: Sequence[str] = (),
) -> Dict[str, Any]:
    """Verify whether `python_exe` already satisfies `pyproject.toml` dependencies without invoking `pip`."""
    specs = parse_pyproject_dependency_specs(pyproject_text, enabled_packs=enabled_packs)
    req_pkg_names: List[str] = []
    for raw_s in specs:
        m_nm = _REQ_SPLIT_RE.match(raw_s.partition(";")[0].strip())
        if m_nm:
            req_pkg_names.append(m_nm.group(1))
    probed = _probe_python_installed_distributions(python_exe, package_names=req_pkg_names)
    if probed is None:
        return {
            "satisfied": False,
            "missing_or_outdated": list(specs) if specs else ["python_runtime_unavailable"],
            "can_pip_install": False,
        }

    env_info: Dict[str, str] = {
        "python_version": str(probed.get("python_version") or ""),
        "python_full_version": str(probed.get("python_full_version") or ""),
        "sys_platform": str(probed.get("sys_platform") or ""),
        "os_name": str(probed.get("os_name") or ""),
        "platform_system": str(probed.get("platform_system") or ""),
        "platform_machine": str(probed.get("platform_machine") or ""),
        "implementation_name": str(probed.get("implementation_name") or "cpython"),
    }
    dists: Dict[str, str] = {str(k): str(v) for k, v in (probed.get("dists") or {}).items()}
    missing_or_outdated: List[str] = []

    for raw_spec in specs:
        req_part, sep, marker_part = raw_spec.partition(";")
        if sep and not _evaluate_pep508_marker(marker_part, env_info):
            continue
        req_clean = req_part.strip()
        if not req_clean:
            continue
        m_req = _REQ_SPLIT_RE.match(req_clean)
        if not m_req:
            continue
        pkg_name = _normalize_dist_name(m_req.group(1))
        ver_constraints = m_req.group(2).strip()
        installed_ver = dists.get(pkg_name)
        if not installed_ver:
            missing_or_outdated.append(raw_spec)
            continue
        if ver_constraints:
            ok_all = True
            for clause in ver_constraints.split(","):
                c_s = clause.strip()
                if not c_s:
                    continue
                m_op = _SPEC_OP_RE.match(c_s)
                if not m_op:
                    continue
                if not _compare_pep440(installed_ver, m_op.group(1), m_op.group(2)):
                    ok_all = False
                    break
            if not ok_all:
                missing_or_outdated.append(raw_spec)

    exe_path = Path(str(python_exe)).expanduser()
    parent_dir = exe_path.resolve().parent if exe_path.exists() else exe_path.parent
    is_pth_locked_embed = any(parent_dir.glob("python*._pth"))
    can_pip = bool(probed.get("has_pip")) and (not is_pth_locked_embed or bool(probed.get("has_pip")))
    return {
        "satisfied": len(missing_or_outdated) == 0,
        "missing_or_outdated": missing_or_outdated,
        "can_pip_install": can_pip,
    }


def _caller_inside_mcp_dispatcher() -> bool:
    frame = sys._getframe(0)
    depth = 0
    while frame is not None and depth < 40:
        fname = (frame.f_code.co_filename or "").replace("\\", "/").lower()
        if fname.endswith("/protocol/dispatcher.py"):
            return True
        frame = frame.f_back
        depth += 1
    return False


def _detect_active_foreground_tasks(state_root: Path, prefix: str = "pc") -> List[Dict[str, Any]]:
    st_root = Path(state_root).expanduser().resolve()
    eff_p = _norm_prefix(prefix)
    state_dir = st_root / "state"
    busy: List[Dict[str, Any]] = []
    now_ts = time.time()

    # 1. Explicit active foreground task files in `<state_root>/state`
    task_files: List[Path] = [
        state_dir / "active_tasks.json",
        state_dir / f"active_tasks_{eff_p}.json",
    ]
    active_tasks_dir = state_dir / "active_tasks"
    if active_tasks_dir.is_dir():
        task_files.extend(sorted(active_tasks_dir.glob("*.json")))

    for tf in task_files:
        if not tf.is_file():
            continue
        with contextlib.suppress(Exception):
            doc = json.loads(tf.read_text(encoding="utf-8-sig"))
            items: List[Any] = []
            if isinstance(doc, list):
                items = doc
            elif isinstance(doc, dict):
                if isinstance(doc.get("tasks"), list):
                    items = doc["tasks"]
                elif isinstance(doc.get("tasks"), dict):
                    items = list(doc["tasks"].values())
                elif doc.get("task_id") or doc.get("running") or doc.get("status") == "running":
                    items = [doc]
            for it in items:
                if not isinstance(it, dict):
                    continue
                t_pfx = _norm_prefix(str(it.get("prefix") or it.get("tool_prefix") or eff_p))
                if t_pfx != eff_p:
                    continue
                if it.get("ended_at") is not None or it.get("exit_code") is not None:
                    continue
                st_lbl = str(it.get("status") or "").strip().lower()
                is_run = bool(it.get("running", st_lbl in ("running", "active", "in_progress")))
                if not is_run:
                    continue
                pid_val = int(it.get("pid") or 0)
                if pid_val > 0 and not verify_pid_alive(pid_val, it.get("proc_create_token"))[0]:
                    continue
                started_at = float(it.get("started_at") or now_ts)
                if pid_val == 0 and (now_ts - started_at) > 600.0:
                    continue
                busy.append(
                    {
                        "source": tf.name,
                        "task_id": str(it.get("task_id") or it.get("id") or "foreground_task"),
                        "tool": str(it.get("tool") or it.get("command") or ""),
                    }
                )

    # 2. Live loopback `/healthz` in-flight MCP tool call count
    d_path = daemon_status_path(st_root, eff_p)
    if d_path.is_file():
        with contextlib.suppress(Exception):
            d_doc = json.loads(d_path.read_text(encoding="utf-8-sig"))
            if isinstance(d_doc, dict) and str(d_doc.get("status") or "") != "stopped":
                srv_pid = int(d_doc.get("server_pid") or 0)
                srv_tok = d_doc.get("server_create_token")
                port = int(d_doc.get("port") or 0)
                if srv_pid > 0 and port > 0 and verify_pid_alive(srv_pid, srv_tok)[0]:
                    hz = probe_local_healthz(port, timeout_sec=1.0)
                    if isinstance(hz, dict):
                        inflight = int(hz.get("inflight") or 0)
                        allowance = 1 if (os.getpid() == srv_pid and _caller_inside_mcp_dispatcher()) else 0
                        if inflight > allowance:
                            busy.append(
                                {
                                    "source": "healthz_inflight",
                                    "inflight": inflight,
                                    "server_pid": srv_pid,
                                }
                            )
    return busy


def _safe_extract_zip_archive(zip_path: Path, extract_root: Path) -> Tuple[bool, str, str]:
    """Validate and extract `zip_path` into `extract_root`, rejecting Zip-Slip (`..`), drive paths, and symlinks."""
    extract_resolved = extract_root.resolve()
    extract_resolved.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            infos = zf.infolist()
            total_uncompressed = 0
            validated_members: List[Tuple[zipfile.ZipInfo, Path, bool]] = []
            for info in infos:
                raw_name = info.filename or ""
                norm_posix = raw_name.replace("\\", "/")
                if norm_posix.startswith("/") or "\x00" in norm_posix:
                    return False, "ERR_ZIP_SLIP_DETECTED", f"压缩包含非法绝对路径条目：{raw_name!r}"
                p_posix = PurePosixPath(norm_posix)
                parts = [pt for pt in p_posix.parts if pt not in ("", ".")]
                if not parts:
                    continue
                if any(pt == ".." or ":" in pt for pt in parts):
                    return False, "ERR_ZIP_SLIP_DETECTED", f"压缩包含路径穿越条目：{raw_name!r}"
                unix_mode = (info.external_attr >> 16) & 0o170000
                if unix_mode == 0o120000:
                    return False, "ERR_ZIP_SLIP_DETECTED", f"压缩包含非法符号链接条目：{raw_name!r}"
                total_uncompressed += max(0, int(info.file_size or 0))
                if total_uncompressed > MAX_EXTRACTED_TOTAL_BYTES:
                    return False, "ERR_ARCHIVE_TOO_LARGE", "压缩包解压体积超出安全上限。"
                dest_path = extract_resolved.joinpath(*parts).resolve()
                try:
                    common = os.path.commonpath([str(extract_resolved), str(dest_path)])
                except ValueError:
                    return False, "ERR_ZIP_SLIP_DETECTED", f"压缩包跨盘符路径越界：{raw_name!r}"
                if os.path.normcase(common) != os.path.normcase(str(extract_resolved)):
                    return False, "ERR_ZIP_SLIP_DETECTED", f"压缩包目标路径越界：{raw_name!r}"
                validated_members.append((info, dest_path, info.is_dir() or norm_posix.endswith("/")))

            for info, dest_path, is_dir_entry in validated_members:
                if is_dir_entry:
                    dest_path.mkdir(parents=True, exist_ok=True)
                    continue
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as src_fh, dest_path.open("wb") as dst_fh:
                    while True:
                        chunk = src_fh.read(65536)
                        if not chunk:
                            break
                        dst_fh.write(chunk)
    except zipfile.BadZipFile as exc:
        return False, "ERR_CORRUPT_ARCHIVE", f"更新压缩包损坏无法读取：{exc}"
    except Exception as exc:
        return False, "ERR_EXTRACT_FAILED", f"解压更新包失败：{exc}"
    return True, "", ""


def _locate_staged_package_root(extract_root: Path) -> Optional[Path]:
    candidates: List[Path] = [extract_root]
    with contextlib.suppress(OSError):
        for child in sorted(extract_root.iterdir()):
            if child.is_dir():
                candidates.append(child)
    for cand in candidates:
        if (cand / "src" / "cosmos_mcp" / "__init__.py").is_file() and (cand / "pyproject.toml").is_file():
            return cand
    return None


def _verify_python_syntax_tree(root_dir: Path) -> Tuple[bool, str, str]:
    """Run `ast.parse` on every `.py` file under `root_dir` to block broken packages before staging promotion."""
    for cur_root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in sorted(dirs) if d not in ("__pycache__", ".git", ".venv")]
        for fname in sorted(files):
            if not fname.lower().endswith(".py"):
                continue
            fp = Path(cur_root) / fname
            rel_s = fp.relative_to(root_dir).as_posix()
            try:
                raw = fp.read_bytes()
                if b"\x00" in raw:
                    return False, rel_s, f"NUL byte in Python source `{rel_s}`"
                src_txt = raw.decode("utf-8")
                ast.parse(src_txt, filename=rel_s)
            except (SyntaxError, UnicodeDecodeError, ValueError) as exc:
                return False, rel_s, f"{type(exc).__name__} in `{rel_s}`: {exc}"
    return True, "", ""


def _sha256_file_norm(fp: Path) -> str:
    if not fp.is_file():
        return ""
    try:
        data = fp.read_bytes().replace(b"\r\n", b"\n")
        return hashlib.sha256(data).hexdigest()
    except OSError:
        return ""


def _resolve_target_runtime_python(state_root: Path, prefix: str = "pc") -> Tuple[str, str, List[str]]:
    st_root = Path(state_root).expanduser().resolve()
    eff_p = _norm_prefix(prefix)
    cfg_p = service_cfg_path(st_root, eff_p)
    cfg_doc: Dict[str, Any] = {}
    if cfg_p.is_file():
        with contextlib.suppress(Exception):
            loaded = json.loads(cfg_p.read_text(encoding="utf-8-sig"))
            if isinstance(loaded, dict):
                cfg_doc = loaded

    enabled_packs = [str(x) for x in (cfg_doc.get("enabled_packs") or []) if x]

    venv_py = venv_python_path(st_root / ".venv", windowless=False)
    if venv_py.is_file():
        return str(venv_py), "venv", enabled_packs

    emb_py = find_embedded_python_exe(state_root=st_root)
    if emb_py is not None and emb_py.is_file():
        st_norm = os.path.normcase(str(st_root)).rstrip("\\/") + os.sep
        if os.path.normcase(str(emb_py)).startswith(st_norm):
            return str(emb_py), "python_embed", enabled_packs

    cfg_py = str(cfg_doc.get("python_path") or "").strip()
    if cfg_py and Path(cfg_py).is_file():
        parent_d = Path(cfg_py).resolve().parent
        kind = "python_embed" if any(parent_d.glob("python*._pth")) else "ambient"
        return str(Path(cfg_py).resolve()), kind, enabled_packs

    con_self = resolve_console_python(sys.executable) or sys.executable
    return str(con_self), "ambient", enabled_packs


def _refresh_runtime_pth_links(state_root: Path, app_src: Path) -> None:
    st_root = Path(state_root).expanduser().resolve()
    venv_py = venv_python_path(st_root / ".venv", windowless=False)
    if venv_py.is_file():
        sp_dir = _locate_venv_site_packages(venv_py)
        extra_paths: List[Path] = []
        if sp_dir is not None:
            pth_file = sp_dir / "cosmos_mcp_src.pth"
            if pth_file.is_file():
                with contextlib.suppress(OSError):
                    for ln in pth_file.read_text(encoding="utf-8", errors="replace").splitlines():
                        cand = Path(ln.strip())
                        if cand.is_dir() and os.path.normcase(str(cand)) != os.path.normcase(str(app_src)):
                            if not (cand / "cosmos_mcp" / "__init__.py").is_file():
                                extra_paths.append(cand)
        _write_venv_src_pth(venv_py, app_src, extra_paths=extra_paths)

    emb_py = find_embedded_python_exe(state_root=st_root)
    if emb_py is not None and emb_py.is_file():
        st_norm = os.path.normcase(str(st_root)).rstrip("\\/") + os.sep
        if os.path.normcase(str(emb_py)).startswith(st_norm):
            ensure_embed_pth_site_enabled(emb_py.parent, extra_entries=("Lib/site-packages", "../app_src"))
            sp_emb = emb_py.parent / "Lib" / "site-packages"
            with contextlib.suppress(OSError):
                sp_emb.mkdir(parents=True, exist_ok=True)
                atomic_write_text(sp_emb / "cosmos_mcp_src.pth", str(app_src) + "\n")


def _maybe_sync_clean_portable_dir(state_root: Path, pkg_root: Path) -> bool:
    """Optionally sync non-`.git` writable portable extracted folder if running from one."""
    cand = find_repo_root()
    if cand is None or not cand.is_dir():
        return False
    # Strictly never touch any Git repository or worktree
    if any((anc / ".git").exists() for anc in (cand, *cand.parents)):
        return False
    if not ((cand / "一键启动_Cosmos_MCP.bat").is_file() or (cand / "start_cosmos_mcp.sh").is_file()):
        return False
    if not os.access(cand, os.W_OK):
        return False
    undo_dir = Path(state_root).expanduser().resolve() / ".undo_history"
    try:
        if (pkg_root / "src" / "cosmos_mcp" / "__init__.py").is_file():
            _sync_clean_dir_tree(pkg_root / "src" / "cosmos_mcp", cand / "src" / "cosmos_mcp", undo_dir=undo_dir)
        if (pkg_root / "host_skills").is_dir():
            _sync_clean_dir_tree(pkg_root / "host_skills", cand / "host_skills", undo_dir=undo_dir)
        return True
    except OSError:
        return False


def _read_daemon_doc(state_root: Path, prefix: str = "pc") -> Dict[str, Any]:
    d_path = daemon_status_path(state_root, prefix)
    if not d_path.is_file():
        return {}
    try:
        doc = json.loads(d_path.read_text(encoding="utf-8-sig"))
        return doc if isinstance(doc, dict) else {}
    except Exception:
        return {}


def _execute_handoff_and_watchdog(
    *,
    state_root: Path,
    prefix: str,
    port: int,
    restart_mode: str,
    defer_sec: float,
    health_timeout_sec: float,
    prev_server_pid: int,
    runtime_python: str,
    from_version: str,
    to_version: str,
    to_revision: str,
    deferred_daemon_restart_note: bool = False,
) -> Dict[str, Any]:
    """Perform worker hot-reload or full daemon handoff, then enforce 15s `/healthz` watchdog + auto-rollback."""
    st_root = Path(state_root).expanduser().resolve()
    eff_p = _norm_prefix(prefix)
    undo_dir = st_root / ".undo_history"
    app_src = st_root / "app_src"
    app_src_prev = st_root / "app_src_prev"
    status_out_path = last_update_status_path(st_root, eff_p)

    if defer_sec > 0:
        time.sleep(min(15.0, float(defer_sec)))

    pre_doc = _read_daemon_doc(st_root, eff_p)
    eff_prev_srv_pid = int(pre_doc.get("server_pid") or prev_server_pid or 0)
    eff_prev_srv_tok = pre_doc.get("server_create_token")
    prev_reload_ts = float(pre_doc.get("last_worker_reload_ts") or 0.0)
    sup_pid = int(pre_doc.get("supervisor_pid") or 0)
    sup_tok = pre_doc.get("supervisor_create_token")
    sup_alive = verify_pid_alive(sup_pid, sup_tok)[0] if sup_pid > 0 else False

    cfg_doc: Dict[str, Any] = {}
    cfg_p = service_cfg_path(st_root, eff_p)
    if cfg_p.is_file():
        with contextlib.suppress(Exception):
            loaded_c = json.loads(cfg_p.read_text(encoding="utf-8-sig"))
            if isinstance(loaded_c, dict):
                cfg_doc = loaded_c
    no_tray = not bool(cfg_doc.get("tray_enabled", True))

    was_user_stopped = _is_stop_active(st_root, eff_p)
    if restart_mode == "worker_hot_reload" and sup_alive:
        request_worker_hot_reload(st_root, prefix=eff_p)
    elif not was_user_stopped:
        stop_daemon(st_root, prefix=eff_p, timeout_sec=6.0)
        spawn_detached_daemon(
            python_exe=runtime_python,
            state_root=st_root,
            port=port,
            prefix=eff_p,
            no_tray=no_tray,
            wait_ready_sec=min(8.0, max(2.0, float(health_timeout_sec))),
            clear_user_stop=True,
        )

    failure_reason = ""
    deadline = time.monotonic() + max(1.5, float(health_timeout_sec))
    while time.monotonic() < deadline:
        cur_doc = _read_daemon_doc(st_root, eff_p)
        cur_srv_pid = int(cur_doc.get("server_pid") or 0)
        cur_reload_ts = float(cur_doc.get("last_worker_reload_ts") or 0.0)
        cur_crashes = int(cur_doc.get("consecutive_crashes") or 0)
        cur_state = str(cur_doc.get("status") or "")

        if restart_mode == "worker_hot_reload" and sup_alive and eff_prev_srv_pid > 0:
            prev_still_alive = verify_pid_alive(eff_prev_srv_pid, eff_prev_srv_tok)[0]
            worker_switched = (
                (not prev_still_alive)
                or (cur_srv_pid > 0 and cur_srv_pid != eff_prev_srv_pid)
                or (cur_reload_ts > prev_reload_ts)
            )
        else:
            worker_switched = True

        if worker_switched and cur_crashes >= 2 and cur_state == "restarting_backoff":
            failure_reason = f"新版服务连续启动崩溃 ({cur_crashes} 次): {cur_doc.get('last_error') or ''}".strip()
            break

        if worker_switched:
            srv_ok = True
            if cur_srv_pid > 0 and not is_raw_pid_alive(cur_srv_pid):
                srv_ok = False
            elif cur_state in ("reloading_worker", "restarting_backoff"):
                srv_ok = False
            if srv_ok:
                hz = probe_local_healthz(port, timeout_sec=1.5)
                if hz is not None and hz.get("status") == "ok":
                    if sup_alive and to_revision:
                        rev_wait = time.monotonic() + 1.2
                        while time.monotonic() < rev_wait:
                            d_chk = _read_daemon_doc(st_root, eff_p)
                            if str(d_chk.get("server_build_rev") or "") == to_revision and d_chk.get("last_worker_reload_ts"):
                                cur_doc = d_chk
                                cur_srv_pid = int(d_chk.get("server_pid") or cur_srv_pid or 0)
                                break
                            time.sleep(0.1)
                    ok_payload: Dict[str, Any] = {
                        "ok": True,
                        "status": "succeeded",
                        "from_version": from_version,
                        "to_version": to_version,
                        "to_revision": to_revision,
                        "restart_mode": restart_mode,
                        "deferred_daemon_restart_note": deferred_daemon_restart_note,
                        "server_pid": cur_srv_pid or None,
                        "healthz": hz,
                        "completed_at": round(time.time(), 3),
                    }
                    atomic_write_json(status_out_path, ok_payload)
                    return ok_payload
        time.sleep(0.2)

    # Health check failed within 15s window -> automatic rollback to `app_src_prev`
    if not failure_reason:
        failure_reason = f"新版本在 {health_timeout_sec:.1f}s 内未通过本地 /healthz 健康检查，已自动回滚。"

    if (app_src_prev / "cosmos_mcp" / "__init__.py").is_file():
        _sync_clean_dir_tree(app_src_prev, app_src, undo_dir=undo_dir)
        _refresh_runtime_pth_links(st_root, app_src)

    post_doc = _read_daemon_doc(st_root, eff_p)
    sup_pid_now = int(post_doc.get("supervisor_pid") or sup_pid or 0)
    sup_tok_now = post_doc.get("supervisor_create_token") or sup_tok
    if sup_pid_now > 0 and verify_pid_alive(sup_pid_now, sup_tok_now)[0]:
        request_worker_hot_reload(st_root, prefix=eff_p)
    elif not was_user_stopped:
        stop_daemon(st_root, prefix=eff_p, timeout_sec=4.0)
        spawn_detached_daemon(
            python_exe=runtime_python,
            state_root=st_root,
            port=port,
            prefix=eff_p,
            no_tray=no_tray,
            wait_ready_sec=10.0,
            clear_user_stop=True,
        )

    rollback_hz: Optional[Dict[str, Any]] = None
    rb_deadline = time.monotonic() + 15.0
    while time.monotonic() < rb_deadline:
        rb_doc = _read_daemon_doc(st_root, eff_p)
        rb_state = str(rb_doc.get("status") or "")
        rb_srv_pid = int(rb_doc.get("server_pid") or 0)
        if rb_state not in ("reloading_worker", "restarting_backoff") and (rb_srv_pid <= 0 or is_raw_pid_alive(rb_srv_pid)):
            cand_hz = probe_local_healthz(port, timeout_sec=1.5)
            if cand_hz is not None and cand_hz.get("status") == "ok":
                rollback_hz = cand_hz
                expected_rb_rev = compute_app_src_revision(app_src / "cosmos_mcp")
                if expected_rb_rev:
                    rb_rev_wait = time.monotonic() + 1.2
                    while time.monotonic() < rb_rev_wait:
                        d_rb = _read_daemon_doc(st_root, eff_p)
                        if str(d_rb.get("server_build_rev") or "") == expected_rb_rev and str(d_rb.get("status") or "") == "running":
                            break
                        time.sleep(0.1)
                break
        time.sleep(0.25)

    restored_ver = read_package_init_version(app_src / "cosmos_mcp" / "__init__.py")
    restored_rev = compute_app_src_revision(app_src / "cosmos_mcp")
    rb_payload: Dict[str, Any] = {
        "ok": False,
        "status": "rolled_back",
        "error_code": "ERR_NEW_VERSION_UNHEALTHY_ROLLED_BACK",
        "error": failure_reason,
        "from_version": from_version,
        "failed_version": to_version,
        "failed_revision": to_revision,
        "restored_version": restored_ver,
        "restored_revision": restored_rev,
        "rollback_healthz_ok": rollback_hz is not None,
        "healthz": rollback_hz,
        "completed_at": round(time.time(), 3),
    }
    atomic_write_json(status_out_path, rb_payload)
    return rb_payload


def _spawn_detached_handoff_watchdog(
    *,
    state_root: Path,
    prefix: str,
    port: int,
    restart_mode: str,
    defer_sec: float,
    health_timeout_sec: float,
    prev_server_pid: int,
    runtime_python: str,
    from_version: str,
    to_version: str,
    to_revision: str,
    deferred_daemon_restart_note: bool,
) -> int:
    st_root = Path(state_root).expanduser().resolve()
    eff_p = _norm_prefix(prefix)
    logs_dir = st_root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    upd_log = logs_dir / (f"updater_{eff_p}.log" if eff_p != "pc" else "updater.log")

    # Prefer a Python runner whose `cosmos_mcp.launcher.updater` cannot be broken by staged `app_src`
    # while injecting `app_src_prev` (if it contains `updater.py`) or repo src after `app_src`.
    con_py = resolve_console_python(runtime_python) or runtime_python
    argv = [
        str(con_py),
        "-B",
        "-m",
        "cosmos_mcp.launcher.updater",
        "--handoff-worker",
        "--state-dir",
        str(st_root),
        "--prefix",
        eff_p,
        "--port",
        str(int(port)),
        "--restart-mode",
        restart_mode,
        "--defer-sec",
        str(float(defer_sec)),
        "--health-timeout-sec",
        str(float(health_timeout_sec)),
        "--prev-server-pid",
        str(int(prev_server_pid)),
        "--runtime-python",
        str(runtime_python),
        "--from-version",
        from_version,
        "--to-version",
        to_version,
        "--to-revision",
        to_revision,
    ]
    if deferred_daemon_restart_note:
        argv.append("--deferred-daemon-note")

    env = sanitize_daemon_inherited_env(dict(os.environ))
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONUTF8"] = "1"
    env["COSMOS_MCP_STATE_DIR"] = str(st_root)
    py_paths: List[str] = []
    app_src_prev = st_root / "app_src_prev"
    app_src = st_root / "app_src"
    repo_src = find_repo_src_dir()
    # Put a known-good `updater.py` provider first so the watchdog boots even if staged `__init__.py` raises at import!
    for cand_p in (app_src_prev, repo_src, app_src):
        if cand_p is not None and (cand_p / "cosmos_mcp" / "launcher" / "updater.py").is_file():
            s_cand = str(cand_p.resolve())
            if s_cand not in py_paths:
                py_paths.append(s_cand)
    if (app_src / "cosmos_mcp" / "__init__.py").is_file():
        s_app = str(app_src.resolve())
        if s_app not in py_paths:
            py_paths.append(s_app)
    existing_pp = env.get("PYTHONPATH", "")
    if existing_pp:
        py_paths.append(existing_pp)
    if py_paths:
        env["PYTHONPATH"] = os.pathsep.join(py_paths)

    with upd_log.open("a", encoding="utf-8", errors="replace") as lf:
        popen_kwargs: Dict[str, Any] = {
            "stdin": subprocess.DEVNULL,
            "stdout": lf,
            "stderr": subprocess.STDOUT,
            "cwd": str(st_root),
            "env": env,
            "close_fds": True,
        }
        if sys.platform == "win32":
            base_flags = CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
            try:
                proc = subprocess.Popen(
                    argv,
                    **popen_kwargs,
                    creationflags=base_flags | CREATE_BREAKAWAY_FROM_JOB,
                )
            except OSError:
                proc = subprocess.Popen(
                    argv,
                    **popen_kwargs,
                    creationflags=base_flags,
                )
        else:
            popen_kwargs["start_new_session"] = True
            proc = subprocess.Popen(argv, **popen_kwargs)
        return int(proc.pid)


def stage_and_apply_update(
    state_root: Path,
    *,
    prefix: str = "pc",
    channel: str = "release",
    archive_path: Optional[Path] = None,
    allow_tunnel_restart: bool = False,
    force_active_tasks: bool = False,
    defer_restart_sec: float = 1.2,
    health_timeout_sec: float = 15.0,
) -> Dict[str, Any]:
    """Download/stage update archive, verify SHA-256 + AST + deps, atomically swap `app_src`, and hot-reload with rollback."""
    st_root = Path(state_root).expanduser().resolve()
    eff_p = _norm_prefix(prefix)
    undo_dir = st_root / ".undo_history"
    (st_root / "state").mkdir(parents=True, exist_ok=True)

    # Step A: Active foreground task protection (wait up to 3.0s unless `force_active_tasks=True`)
    if not force_active_tasks:
        busy_tasks = _detect_active_foreground_tasks(st_root, prefix=eff_p)
        if busy_tasks:
            wait_deadline = time.monotonic() + 3.0
            while time.monotonic() < wait_deadline and busy_tasks:
                time.sleep(0.2)
                busy_tasks = _detect_active_foreground_tasks(st_root, prefix=eff_p)
            if busy_tasks:
                return {
                    "ok": False,
                    "error_code": "ERR_ACTIVE_TASKS_BUSY",
                    "error": "当前仍有正在执行的前台任务，为避免中断在途操作已暂缓更新。",
                    "active_tasks": busy_tasks,
                }

    cur_cosmos_dir, cur_meta = _resolve_active_cosmos_dir(st_root)
    from_version = (
        read_package_init_version(cur_cosmos_dir / "__init__.py")
        if cur_cosmos_dir is not None
        else ""
    ) or str(cur_meta.get("version") or "0.0.0")
    from_revision = compute_app_src_revision(cur_cosmos_dir) if cur_cosmos_dir is not None else ""

    target_commit = ""
    expected_sha256 = (os.environ.get("COSMOS_UPDATE_EXPECTED_SHA256") or "").strip().lower()
    download_url = ""
    proxy_used = ""

    if archive_path is None:
        chk = check_for_updates(st_root, prefix=eff_p, channel=channel)
        if not chk.get("ok"):
            return {
                "ok": False,
                "error_code": str(chk.get("error_code") or "ERR_UPDATE_CHECK_FAILED"),
                "error": str(chk.get("error") or "无法获取远端版本信息。"),
                "check_result": chk,
            }
        download_url = str(chk.get("download_url") or "").strip()
        target_commit = str(chk.get("latest_commit") or "").strip()
        proxy_used = str(chk.get("proxy_used") or "")
        if not expected_sha256:
            expected_sha256 = str(chk.get("expected_sha256") or "").strip().lower()
        if not download_url or not _is_allowed_download_url(download_url):
            return {
                "ok": False,
                "error_code": "ERR_INSECURE_DOWNLOAD_URL",
                "error": f"不安全的更新包下载地址：{download_url!r}",
            }

    staging_dir = st_root / "staging" / f"upd_{int(time.time() * 1000)}_{os.getpid()}"
    staging_dir.mkdir(parents=True, exist_ok=True)
    try:
        # Step B: Safe download / archive verification + Zip-Slip guard + full `.py` AST syntax gate
        if archive_path is not None:
            local_zip = Path(archive_path).expanduser().resolve()
            if not local_zip.is_file():
                return {
                    "ok": False,
                    "error_code": "ERR_ARCHIVE_NOT_FOUND",
                    "error": f"未找到指定的本地更新包：{local_zip}",
                }
            fsize = local_zip.stat().st_size
            if fsize <= 0 or fsize > MAX_UPDATE_ARCHIVE_BYTES:
                return {
                    "ok": False,
                    "error_code": "ERR_ARCHIVE_TOO_LARGE",
                    "error": f"更新包大小异常（{fsize} 字节，上限 80 MiB）。",
                }
            actual_sha = hashlib.sha256(local_zip.read_bytes()).hexdigest().lower()
            if expected_sha256 and actual_sha != expected_sha256:
                return {
                    "ok": False,
                    "error_code": "ERR_SHA256_MISMATCH",
                    "error": "更新包 SHA-256 校验值不匹配，已拒绝应用。",
                    "expected_sha256": expected_sha256,
                    "actual_sha256": actual_sha,
                }
            work_zip = local_zip
        else:
            work_zip = staging_dir / "package.zip"
            try:
                dl_status, dl_bytes, dl_px = _http_get_bytes_with_proxy_fallback(
                    download_url,
                    timeout_sec=30.0,
                    accept="application/octet-stream, application/zip, */*",
                    max_bytes=MAX_UPDATE_ARCHIVE_BYTES,
                )
                if dl_px:
                    proxy_used = dl_px
            except ValueError as ve:
                if str(ve).startswith("ERR_ARCHIVE_TOO_LARGE:"):
                    return {
                        "ok": False,
                        "error_code": "ERR_ARCHIVE_TOO_LARGE",
                        "error": "远端更新包体积超过 80 MiB 安全上限，已中止下载。",
                    }
                raise
            except Exception as dl_exc:
                return {
                    "ok": False,
                    "error_code": "ERR_DOWNLOAD_FAILED",
                    "error": f"下载更新包失败：{dl_exc}",
                }
            if dl_status != 200 or not dl_bytes:
                return {
                    "ok": False,
                    "error_code": f"ERR_DOWNLOAD_HTTP_{dl_status}",
                    "error": f"下载更新包返回 HTTP {dl_status}。",
                }
            actual_sha = hashlib.sha256(dl_bytes).hexdigest().lower()
            if expected_sha256 and actual_sha != expected_sha256:
                return {
                    "ok": False,
                    "error_code": "ERR_SHA256_MISMATCH",
                    "error": "下载包 SHA-256 哈希与预期不一致，已拦截防篡改门禁。",
                    "expected_sha256": expected_sha256,
                    "actual_sha256": actual_sha,
                }
            work_zip.write_bytes(dl_bytes)

        extract_root = staging_dir / "extracted"
        ext_ok, ext_code, ext_err = _safe_extract_zip_archive(work_zip, extract_root)
        if not ext_ok:
            return {"ok": False, "error_code": ext_code, "error": ext_err}

        pkg_root = _locate_staged_package_root(extract_root)
        if pkg_root is None:
            return {
                "ok": False,
                "error_code": "ERR_INVALID_PACKAGE_LAYOUT",
                "error": "更新包缺少有效的 `src/cosmos_mcp/__init__.py` 或 `pyproject.toml` 结构。",
            }

        ast_ok, bad_py, ast_err = _verify_python_syntax_tree(pkg_root)
        if not ast_ok:
            return {
                "ok": False,
                "error_code": "ERR_SYNTAX_CHECK_FAILED",
                "bad_file": bad_py,
                "error": f"更新包内 Python 源码语法校验未通过，已拦截上线：{ast_err}",
            }

        # Step C: Daemon/tunnel diff + Dependency pre-install gate
        staged_cosmos = pkg_root / "src" / "cosmos_mcp"
        if cur_cosmos_dir is not None and cur_cosmos_dir.is_dir():
            launcher_changed = any(
                _sha256_file_norm(staged_cosmos / rel_f) != _sha256_file_norm(cur_cosmos_dir / rel_f)
                for rel_f in LAUNCHER_TUNNEL_REL_FILES
            )
        else:
            launcher_changed = False

        target_py_exe, runtime_kind, enabled_packs = _resolve_target_runtime_python(st_root, prefix=eff_p)
        pyproject_txt = (pkg_root / "pyproject.toml").read_text(encoding="utf-8", errors="replace")
        dep_check = check_pyproject_deps_satisfied(
            pyproject_txt,
            python_exe=target_py_exe,
            enabled_packs=enabled_packs,
        )
        pip_invoked = False
        pip_result: Optional[Dict[str, Any]] = None
        if not dep_check["satisfied"]:
            if runtime_kind != "python_embed" and dep_check.get("can_pip_install"):
                pip_invoked = True
                staged_wheels = pkg_root / "wheels" if (pkg_root / "wheels").is_dir() else None
                con_py = resolve_console_python(target_py_exe) or target_py_exe
                pip_timeout = int(os.environ.get("COSMOS_UPDATE_PIP_TIMEOUT_SEC") or "12")
                pip_result = pip_install_with_mirror_fallback(
                    con_py,
                    dep_check["missing_or_outdated"],
                    wheelhouse_dir=staged_wheels,
                    primary_timeout_sec=pip_timeout,
                    mirror_timeout_sec=max(pip_timeout, 18),
                )
                dep_recheck = check_pyproject_deps_satisfied(
                    pyproject_txt,
                    python_exe=target_py_exe,
                    enabled_packs=enabled_packs,
                )
                if not pip_result.get("ok") or not dep_recheck["satisfied"]:
                    return {
                        "ok": False,
                        "error_code": "ERR_DEPS_UNSATISFIED",
                        "missing_or_outdated": dep_recheck["missing_or_outdated"],
                        "can_pip_install": dep_check["can_pip_install"],
                        "pip_invoked": True,
                        "pip_result": pip_result,
                        "error": "新版所需 Python 依赖未满足且自动安装未成功，已安全中止更新并保留现役版本完好无损。",
                    }
            else:
                return {
                    "ok": False,
                    "error_code": "ERR_DEPS_UNSATISFIED",
                    "missing_or_outdated": dep_check["missing_or_outdated"],
                    "can_pip_install": dep_check["can_pip_install"],
                    "pip_invoked": False,
                    "error": "当前便携运行环境缺少 pip 或无法离线满足新增依赖，已安全中止更新并保留现役版本。",
                }

        # Step D: Backup `app_src_prev` + atomic sync `app_src` + write `.cosmos_update_meta.json`
        app_src = (st_root / "app_src").resolve()
        if not (app_src / "cosmos_mcp" / "__init__.py").is_file() and cur_cosmos_dir is not None:
            sync_portable_app_src(st_root, source_src_dir=cur_cosmos_dir.parent)

        prev_tree_hash = (
            compute_source_tree_hash(app_src / "cosmos_mcp")
            if (app_src / "cosmos_mcp" / "__init__.py").is_file()
            else (compute_source_tree_hash(cur_cosmos_dir) if cur_cosmos_dir is not None else "")
        )
        old_meta = read_app_src_update_meta(app_src) if app_src.is_dir() else {}

        app_src_prev = (st_root / "app_src_prev").resolve()
        if (app_src / "cosmos_mcp" / "__init__.py").is_file():
            app_src_prev.mkdir(parents=True, exist_ok=True)
            _sync_clean_dir_tree(app_src, app_src_prev, undo_dir=undo_dir)

        app_src.mkdir(parents=True, exist_ok=True)
        _sync_clean_dir_tree(staged_cosmos, app_src / "cosmos_mcp", undo_dir=undo_dir)
        if (pkg_root / "host_skills").is_dir():
            _sync_clean_dir_tree(pkg_root / "host_skills", app_src / "host_skills", undo_dir=undo_dir)

        to_version = read_package_init_version(app_src / "cosmos_mcp" / "__init__.py") or from_version
        new_tree_hash = compute_source_tree_hash(app_src / "cosmos_mcp")
        to_revision = new_tree_hash[:12]

        replaced_hashes: List[str] = []
        if isinstance(old_meta.get("replaced_tree_hashes"), list):
            replaced_hashes.extend(str(x) for x in old_meta["replaced_tree_hashes"] if x)
        if prev_tree_hash and prev_tree_hash != new_tree_hash and prev_tree_hash not in replaced_hashes:
            replaced_hashes.append(prev_tree_hash)

        write_app_src_update_meta(
            app_src,
            {
                "version": to_version,
                "commit_sha": target_commit,
                "source_tree_hash": new_tree_hash,
                "previous_source_tree_hash": prev_tree_hash,
                "replaced_tree_hashes": replaced_hashes[-10:],
                "self_updated_at": round(time.time(), 3),
                "channel": channel,
            },
        )
        _refresh_runtime_pth_links(st_root, app_src)
        portable_dir_synced = _maybe_sync_clean_portable_dir(st_root, pkg_root)
    finally:
        if staging_dir.exists():
            safe_trash_file(staging_dir, reason="update_staging_cleanup", undo_dir=undo_dir)

    # Step E: Tiered zero-drop restart + 15s watchdog automatic rollback
    tunnel_impact = _inspect_tunnel_impact(st_root, prefix=eff_p)
    deferred_daemon_restart_note = False
    if not launcher_changed:
        restart_mode = "worker_hot_reload"
    elif tunnel_impact["only_ephemeral_trycloudflare"] and not allow_tunnel_restart:
        restart_mode = "worker_hot_reload"
        deferred_daemon_restart_note = True
    else:
        restart_mode = "full_daemon_handoff"

    live = detect_running_instance(st_root, eff_p)
    port = int(live.get("port") or 8096)
    prev_srv_pid = int(live.get("server_pid") or 0)
    status_out_path = last_update_status_path(st_root, eff_p)

    if not live.get("online") and not live.get("supervisor_alive") and not live.get("server_alive"):
        offline_res: Dict[str, Any] = {
            "ok": True,
            "status": "succeeded",
            "restart_mode": "offline_updated",
            "launcher_changed": launcher_changed,
            "deferred_daemon_restart_note": deferred_daemon_restart_note,
            "pip_invoked": pip_invoked,
            "portable_dir_synced": portable_dir_synced,
            "from_version": from_version,
            "from_revision": from_revision,
            "to_version": to_version,
            "to_revision": to_revision,
            "proxy_used": proxy_used,
            "completed_at": round(time.time(), 3),
        }
        atomic_write_json(status_out_path, offline_res)
        return offline_res

    atomic_write_json(
        status_out_path,
        {
            "ok": True,
            "status": "applying",
            "restart_mode": restart_mode,
            "launcher_changed": launcher_changed,
            "deferred_daemon_restart_note": deferred_daemon_restart_note,
            "from_version": from_version,
            "to_version": to_version,
            "to_revision": to_revision,
            "started_at": round(time.time(), 3),
        },
    )

    if float(defer_restart_sec) > 0:
        wd_pid = _spawn_detached_handoff_watchdog(
            state_root=st_root,
            prefix=eff_p,
            port=port,
            restart_mode=restart_mode,
            defer_sec=float(defer_restart_sec),
            health_timeout_sec=float(health_timeout_sec),
            prev_server_pid=prev_srv_pid,
            runtime_python=target_py_exe,
            from_version=from_version,
            to_version=to_version,
            to_revision=to_revision,
            deferred_daemon_restart_note=deferred_daemon_restart_note,
        )
        return {
            "ok": True,
            "status": "handoff_scheduled",
            "watchdog_pid": wd_pid,
            "defer_restart_sec": float(defer_restart_sec),
            "restart_mode": restart_mode,
            "launcher_changed": launcher_changed,
            "deferred_daemon_restart_note": deferred_daemon_restart_note,
            "pip_invoked": pip_invoked,
            "portable_dir_synced": portable_dir_synced,
            "from_version": from_version,
            "from_revision": from_revision,
            "to_version": to_version,
            "to_revision": to_revision,
            "proxy_used": proxy_used,
            "status_file": str(status_out_path),
        }

    wd_res = _execute_handoff_and_watchdog(
        state_root=st_root,
        prefix=eff_p,
        port=port,
        restart_mode=restart_mode,
        defer_sec=0.0,
        health_timeout_sec=float(health_timeout_sec),
        prev_server_pid=prev_srv_pid,
        runtime_python=target_py_exe,
        from_version=from_version,
        to_version=to_version,
        to_revision=to_revision,
        deferred_daemon_restart_note=deferred_daemon_restart_note,
    )
    return {
        **wd_res,
        "launcher_changed": launcher_changed,
        "pip_invoked": pip_invoked,
        "portable_dir_synced": portable_dir_synced,
        "from_revision": from_revision,
        "proxy_used": proxy_used,
    }


def _cli_entry(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Cosmos MCP Self-Updater & Rollback Watchdog")
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--prefix", default="pc")
    parser.add_argument("--channel", default="release", choices=("release", "main"))
    parser.add_argument("--check", action="store_true", help="Check for available updates")
    parser.add_argument("--apply", action="store_true", help="Download, verify, and apply update")
    parser.add_argument("--archive", default="", help="Optional local ZIP archive path")
    parser.add_argument("--allow-tunnel-restart", action="store_true")
    parser.add_argument("--force-active-tasks", action="store_true")
    parser.add_argument("--defer-sec", type=float, default=1.2)
    parser.add_argument("--health-timeout-sec", type=float, default=15.0)

    # Internal detached watchdog handoff flags
    parser.add_argument("--handoff-worker", action="store_true")
    parser.add_argument("--port", type=int, default=8096)
    parser.add_argument("--restart-mode", default="worker_hot_reload")
    parser.add_argument("--prev-server-pid", type=int, default=0)
    parser.add_argument("--runtime-python", default="")
    parser.add_argument("--from-version", default="")
    parser.add_argument("--to-version", default="")
    parser.add_argument("--to-revision", default="")
    parser.add_argument("--deferred-daemon-note", action="store_true")

    args = parser.parse_args(list(argv) if argv is not None else None)
    st_root = Path(args.state_dir).expanduser().resolve()

    if args.handoff_worker:
        rt_py = args.runtime_python or resolve_console_python(sys.executable) or sys.executable
        res = _execute_handoff_and_watchdog(
            state_root=st_root,
            prefix=args.prefix,
            port=int(args.port),
            restart_mode=args.restart_mode,
            defer_sec=float(args.defer_sec),
            health_timeout_sec=float(args.health_timeout_sec),
            prev_server_pid=int(args.prev_server_pid),
            runtime_python=rt_py,
            from_version=args.from_version,
            to_version=args.to_version,
            to_revision=args.to_revision,
            deferred_daemon_restart_note=bool(args.deferred_daemon_note),
        )
        print(json.dumps(res, ensure_ascii=False))
        return 0 if res.get("ok") else 1

    if args.apply:
        arc_p = Path(args.archive).expanduser().resolve() if args.archive else None
        res_apply = stage_and_apply_update(
            st_root,
            prefix=args.prefix,
            channel=args.channel,
            archive_path=arc_p,
            allow_tunnel_restart=bool(args.allow_tunnel_restart),
            force_active_tasks=bool(args.force_active_tasks),
            defer_restart_sec=float(args.defer_sec),
            health_timeout_sec=float(args.health_timeout_sec),
        )
        print(json.dumps(res_apply, ensure_ascii=False, indent=2))
        return 0 if res_apply.get("ok") else 1

    res_chk = check_for_updates(st_root, prefix=args.prefix, channel=args.channel)
    print(json.dumps(res_chk, ensure_ascii=False, indent=2))
    return 0 if res_chk.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(_cli_entry())
