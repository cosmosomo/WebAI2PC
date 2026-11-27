"""Pure-stdlib tunnel managers (`Cloudflare Quick Tunnel`, `Cloudflare Named Tunnel Token`, `VPS SSH -R`).

Enforces:
- 100% Python stdlib + `cosmos_mcp.core` + `cosmos_mcp.launcher.bootstrap`.
- `cloudflared` SHA-256 verified download & mandatory `--protocol http2` default for proxy/campus compatibility.
- Quick Tunnel (`cloudflare`): temporary `*.trycloudflare.com` URL with hot-swap on reconnect (zero server downtime)
  and explicit notice that temporary domain changes after PC reboot.
- Named Tunnel (`cloudflare_token`): `--tunnel-token` permanent fixed domain via `cloudflared tunnel run --token`,
  surviving reboots and autostart with zero address drift.
- `--mode vps` / `custom`: SSH `-R` reverse tunnel and custom reverse-proxy HTTPS domain support.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import inspect
import io
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
import urllib.request

from cosmos_mcp.core.config import (
    GATEWAY_IDS,
    collect_pinned_gateway_urls,
    is_pinned_gateway_url,
    mode_to_gateway_slot,
    normalize_gateways_config,
)
from cosmos_mcp.core.fs_tx import atomic_write_json, safe_trash_file
from cosmos_mcp.core.net_power import detect_configured_proxy
from cosmos_mcp.core.proc import (
    CREATE_NO_WINDOW,
    OwnedJobHandle,
    assign_win32_job_kill_on_close,
    is_raw_pid_alive,
    resolve_console_python,
    terminate_verified_pid_tree,
)
from cosmos_mcp.launcher.bootstrap import atomic_write_text
from cosmos_mcp.launcher.cf_workers_gateway import (
    CLOUDFLARE_TOKEN_TEMPLATE_URL,
    DEFAULT_PUBLIC_GATEWAY_BASE,
    FRAME_HEADER_LEN,
    FRAME_REQ_BODY,
    FRAME_REQ_CANCEL,
    FRAME_REQ_END,
    FRAME_REQ_HEAD,
    FRAME_RES_BODY,
    FRAME_RES_END,
    FRAME_RES_HEAD,
    RECOVERY_PNG_CHUNK_TYPE,
    REQ_BODY_CHUNK_BYTES,
    RES_BODY_CHUNK_BYTES,
    WORKER_RELAY_MJS,
    WorkersDevRelaySupervisor,
    cloudflare_api_token_secret_path,
    deploy_cloudflare_workers_gateway,
    ensure_master_seed_identity,
    export_identity_recovery_png,
    import_identity_recovery_png,
    load_cloudflare_api_token,
    load_or_create_workers_tunnel_secret,
    master_seed_secret_path,
    pack_tunnel_frame,
    shred_cloudflare_api_token,
    unpack_tunnel_frame,
    workers_tunnel_secret_path,
)

TRYCLOUDFLARE_URL_RE = re.compile(r"https://(?!api\.trycloudflare\.com\b)[a-z0-9-]+\.trycloudflare\.com", re.IGNORECASE)
SRVUS_URL_RE = re.compile(r"https://(?!www\.srv\.us\b)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.srv\.us\b", re.IGNORECASE)
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
SHA256_HEX_RE = re.compile(r"\b([a-fA-F0-9]{64})\b")
CF_TOKEN_EXTRACT_RE = re.compile(r"(?<![A-Za-z0-9_+/=-])(eyJ[A-Za-z0-9_+/=-]{20,})(?![A-Za-z0-9_+/=-])")

MAX_TUNNEL_LOG_BYTES = 8 * 1024 * 1024
FRAME_ERR_ABORT = 0xFF


def _rotate_tunnel_log_if_needed(log_file: Path, max_bytes: int = MAX_TUNNEL_LOG_BYTES) -> bool:
    """Rotate `<name>.log` -> `<name>.log.1` when size exceeds `max_bytes` (default 8 MiB)."""
    try:
        if not log_file.is_file() or log_file.stat().st_size <= max_bytes:
            return False
        backup_path = log_file.with_name(log_file.name + ".1")
        os.replace(log_file, backup_path)
        return True
    except OSError:
        return False

QUICK_TUNNEL_REBOOT_NOTICE_ZH = "提示：电脑关机重启后临时地址会更换；如需开机自启保持永久固定域名不断联，请切换为 Cloudflare 固定 Tunnel Token 模式。"

DOH_ENDPOINTS: Tuple[str, ...] = (
    "https://doh.pub/dns-query",
    "https://dns.alidns.com/resolve",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
)

CLOUDFLARED_RELEASES_API = "https://api.github.com/repos/cloudflare/cloudflared/releases/latest"
CLOUDFLARED_DOWNLOAD_BASE = "https://github.com/cloudflare/cloudflared/releases/latest/download"

VPS_SSH_MANDATORY_OPTIONS: Tuple[str, ...] = (
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "ServerAliveInterval=15",
    "-o",
    "ServerAliveCountMax=3",
    "-o",
    "ExitOnForwardFailure=yes",
    "-o",
    "StrictHostKeyChecking=accept-new",
)


def _popen_flags() -> int:
    return CREATE_NO_WINDOW if sys.platform == "win32" else 0


def _norm_prefix(prefix: str) -> str:
    val = (prefix or "pc").strip().lower()
    return val if val else "pc"


def _service_cfg_path(state_root: Path, prefix: str = "pc") -> Path:
    eff = _norm_prefix(prefix)
    return state_root / "config" / (f"service_{eff}.json" if eff != "pc" else "service.json")


def _daemon_status_path(state_root: Path, prefix: str = "pc") -> Path:
    eff = _norm_prefix(prefix)
    return state_root / "state" / (f"daemon_status_{eff}.json" if eff != "pc" else "daemon_status.json")


def _conn_info_paths(state_root: Path, prefix: str = "pc") -> Tuple[Path, Path]:
    eff = _norm_prefix(prefix)
    root_name = f"连接信息_CONNECTION_INFO_{eff}.txt" if eff != "pc" else "连接信息_CONNECTION_INFO.txt"
    sec_name = f"connection_{eff}.txt" if eff != "pc" else "connection.txt"
    return (state_root / root_name, state_root / "secrets" / sec_name)


def tunnel_token_secret_path(state_root: Path, prefix: str = "pc") -> Path:
    eff = _norm_prefix(prefix)
    fn = f"tunnel_token_{eff}.txt" if eff != "pc" else "tunnel_token.txt"
    return Path(state_root).expanduser().resolve() / "secrets" / fn


def normalize_tunnel_token(raw: str) -> str:
    """Normalize raw `--tunnel-token` input, including full `cloudflared service install <TOKEN>` paste."""
    s = (raw or "").strip().strip("\"'")
    if not s:
        return ""
    m = CF_TOKEN_EXTRACT_RE.search(s)
    if m:
        return m.group(1).strip()
    parts = [p.strip() for p in s.split() if p.strip()]
    if len(parts) >= 2 and "--token" in parts:
        idx = parts.index("--token")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    if len(parts) >= 2 and parts[-2].lower() == "install":
        return parts[-1]
    return parts[-1] if parts else ""


def save_tunnel_token(state_root: Path, raw_token: str, *, prefix: str = "pc") -> str:
    """Persist normalized Cloudflare Named Tunnel token into `secrets/tunnel_token*.txt` (mode 0600)."""
    clean = normalize_tunnel_token(raw_token)
    p = tunnel_token_secret_path(state_root, prefix=prefix)
    if not clean:
        if p.exists():
            safe_trash_file(p, reason="clear_tunnel_token", undo_dir=Path(state_root) / ".undo_history")
        return ""
    atomic_write_text(p, clean + "\n", mode_override=0o600)
    return clean


def load_tunnel_token(state_root: Path, *, prefix: str = "pc") -> str:
    """Load saved Cloudflare Named Tunnel token from `secrets/tunnel_token*.txt`."""
    p = tunnel_token_secret_path(state_root, prefix=prefix)
    if p.is_file():
        try:
            return normalize_tunnel_token(p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            return ""
    return ""


def cloudflared_asset_name(
    system_name: Optional[str] = None,
    machine_name: Optional[str] = None,
) -> str:
    """Return official `cloudflared` release asset filename for the target OS/arch."""
    sys_low = (system_name or platform.system()).lower()
    mach_low = (machine_name or platform.machine()).lower()
    is_arm = any(k in mach_low for k in ("arm64", "aarch64"))
    if "windows" in sys_low or sys_low == "win32":
        return "cloudflared-windows-arm64.exe" if is_arm else "cloudflared-windows-amd64.exe"
    if "darwin" in sys_low or "mac" in sys_low:
        return "cloudflared-darwin-arm64.tgz" if is_arm else "cloudflared-darwin-amd64.tgz"
    return "cloudflared-linux-arm64" if is_arm else "cloudflared-linux-amd64"


def compute_sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().lower()


def compute_sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().lower()


def extract_sha256_from_release_metadata(release_doc: Dict[str, Any], asset_name: str) -> str:
    """Extract expected SHA-256 hex digest for `asset_name` from GitHub Release JSON or body text."""
    assets = release_doc.get("assets")
    if isinstance(assets, list):
        for item in assets:
            if not isinstance(item, dict):
                continue
            if str(item.get("name") or "") == asset_name:
                digest = str(item.get("digest") or "").strip().lower()
                if digest.startswith("sha256:") and len(digest) == 71:
                    return digest[7:]
    body = str(release_doc.get("body") or "")
    if body and asset_name in body:
        for line in body.splitlines():
            if asset_name in line:
                m = SHA256_HEX_RE.search(line)
                if m:
                    return m.group(1).lower()
    return ""


MAX_CLOUDFLARED_META_BYTES = 4 * 1024 * 1024
MAX_CLOUDFLARED_DOWNLOAD_BYTES = 160 * 1024 * 1024


class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject protocol-downgrade or malformed redirects during binary/metadata downloads."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        parsed = urlsplit((newurl or "").strip())
        if parsed.scheme.lower() != "https" or not (parsed.hostname or "").strip():
            raise URLError(f"Blocked non-HTTPS redirect target during download: {newurl!r}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _validate_https_download_url(raw_url: str, *, label: str = "cloudflared download URL") -> str:
    clean_u = (raw_url or "").strip()
    parsed = urlsplit(clean_u)
    if parsed.scheme.lower() != "https" or not (parsed.hostname or "").strip():
        raise ValueError(f"{label} must use https:// with a valid hostname: {raw_url!r}")
    if parsed.username or parsed.password:
        raise ValueError(f"{label} must not embed credentials in URL: {raw_url!r}")
    return clean_u


def _read_bounded_stream(resp_obj: Any, max_bytes: int, *, label: str = "download") -> bytes:
    """Read up to `max_bytes` from an HTTP response or unit-test mock opener stream."""
    cap = max(1, int(max_bytes))
    if isinstance(resp_obj, (bytes, bytearray, memoryview)):
        raw_b = bytes(resp_obj)
        if len(raw_b) > cap:
            raise ValueError(f"{label} exceeded max allowed size ({len(raw_b)} > {cap} bytes).")
        return raw_b

    hdrs = getattr(resp_obj, "headers", None)
    if hdrs is not None and hasattr(hdrs, "get"):
        cl_raw = hdrs.get("Content-Length") or hdrs.get("content-length")
        if cl_raw is not None:
            cl_int = -1
            with contextlib.suppress(ValueError, TypeError):
                cl_int = int(str(cl_raw).strip())
            if cl_int > cap:
                raise ValueError(f"{label} Content-Length exceeded max allowed size ({cl_int} > {cap} bytes).")

    read_fn = getattr(resp_obj, "read", None)
    if not callable(read_fn):
        raise TypeError(f"Unsupported response object for {label}: {type(resp_obj).__name__}")

    chunk_sz = min(65536, cap + 1)
    try:
        chunk = read_fn(chunk_sz)
    except TypeError:
        raw_all = read_fn()
        data_all = raw_all.encode("utf-8") if isinstance(raw_all, str) else bytes(raw_all)
        if len(data_all) > cap:
            raise ValueError(f"{label} exceeded max allowed size ({len(data_all)} > {cap} bytes).")
        return data_all

    buf = bytearray()
    while chunk:
        c_bytes = chunk.encode("utf-8") if isinstance(chunk, str) else bytes(chunk)
        buf.extend(c_bytes)
        if len(buf) > cap:
            raise ValueError(f"{label} stream exceeded max allowed size ({cap} bytes).")
        chunk = read_fn(chunk_sz)
    return bytes(buf)


def _build_url_opener(
    use_proxy: bool = True,
    target_host: str = "",
    *,
    https_only: bool = False,
) -> urllib.request.OpenerDirector:
    handlers: List[Any] = []
    if use_proxy:
        proxy = detect_configured_proxy("https", target_host=target_host)
        if proxy:
            p_norm = proxy if "://" in proxy else f"http://{proxy}"
            if p_norm.lower().startswith(("http://", "https://")):
                handlers.append(urllib.request.ProxyHandler({"http": p_norm, "https": p_norm}))
            else:
                handlers.append(urllib.request.ProxyHandler({}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    if https_only:
        handlers.append(_HttpsOnlyRedirectHandler())
    return urllib.request.build_opener(*handlers)


def ensure_cloudflared_binary(
    bin_dir: Path,
    *,
    expected_sha256: str = "",
    download_url: str = "",
    opener: Optional[Callable[[urllib.request.Request, float], Any]] = None,
    timeout_sec: float = 60.0,
) -> Path:
    """Locate or download `cloudflared` supporting `COSMOS_CLOUDFLARED_BIN` / `COSMOS_CLOUDFLARED_MIRROR` and SHA-256 check."""
    env_bin_raw = (os.environ.get("COSMOS_CLOUDFLARED_BIN") or "").strip()
    if env_bin_raw and not download_url:
        env_bin_path = Path(os.path.expandvars(env_bin_raw)).expanduser()
        if not env_bin_path.is_file() or env_bin_path.stat().st_size <= 0:
            raise FileNotFoundError(f"COSMOS_CLOUDFLARED_BIN points to missing or empty binary: {env_bin_raw}")
        if expected_sha256 and compute_sha256_file(env_bin_path) != expected_sha256.lower():
            raise ValueError(f"COSMOS_CLOUDFLARED_BIN SHA-256 mismatch for `{env_bin_path}`.")
        return env_bin_path.resolve()

    bin_dir = Path(bin_dir).expanduser().resolve()
    bin_dir.mkdir(parents=True, exist_ok=True)
    exe_name = "cloudflared.exe" if sys.platform == "win32" else "cloudflared"
    local_bin = bin_dir / exe_name
    if local_bin.is_file() and local_bin.stat().st_size > 1024:
        if not expected_sha256 or compute_sha256_file(local_bin) == expected_sha256.lower():
            return local_bin

    env_mirror = (os.environ.get("COSMOS_CLOUDFLARED_MIRROR") or "").strip()
    if not expected_sha256 and not download_url and not env_mirror:
        sys_which = shutil.which("cloudflared")
        if sys_which and Path(sys_which).is_file():
            return Path(sys_which)

    asset = cloudflared_asset_name()
    if download_url:
        eff_url = _validate_https_download_url(download_url, label="cloudflared download_url")
    elif env_mirror:
        clean_m = _validate_https_download_url(env_mirror, label="COSMOS_CLOUDFLARED_MIRROR").rstrip("/")
        eff_url = clean_m if clean_m.endswith(asset) else f"{clean_m}/{asset}"
    else:
        eff_url = f"{CLOUDFLARED_DOWNLOAD_BASE}/{asset}"

    def _fetch(req: urllib.request.Request, t_sec: float, max_bytes: int = MAX_CLOUDFLARED_META_BYTES) -> bytes:
        _validate_https_download_url(req.full_url, label="cloudflared request URL")
        if opener is not None:
            opened = opener(req, t_sec)
            if hasattr(opened, "__enter__"):
                with opened as r:
                    return _read_bounded_stream(r, max_bytes, label=req.full_url)
            return _read_bounded_stream(opened, max_bytes, label=req.full_url)
        req_host = (urlsplit(req.full_url).hostname or "").strip().lower()
        url_opener = _build_url_opener(use_proxy=True, target_host=req_host, https_only=True)
        with url_opener.open(req, timeout=t_sec) as r:
            return _read_bounded_stream(r, max_bytes, label=req.full_url)

    exp_hex = expected_sha256.strip().lower()
    if not exp_hex and (env_mirror or download_url):
        # For custom mirrors, check `<mirror_asset>.sha256` sidecar first so intranet mirrors work offline
        sha_req_first = urllib.request.Request(
            f"{eff_url}.sha256",
            headers={"User-Agent": "Cosmos-MCP/1.0"},
        )
        try:
            sha_txt_first = _fetch(sha_req_first, 12.0, MAX_CLOUDFLARED_META_BYTES).decode("utf-8", errors="replace")
            m_first = SHA256_HEX_RE.search(sha_txt_first)
            if m_first:
                exp_hex = m_first.group(1).lower()
        except Exception:
            pass
    if not exp_hex:
        # 1) Try GitHub Releases HTML page (zero 60/hr unauthenticated API rate limit behind shared proxies)
        html_req = urllib.request.Request(
            "https://github.com/cloudflare/cloudflared/releases/latest",
            headers={"User-Agent": "Cosmos-MCP/1.0"},
        )
        try:
            html_txt = _fetch(html_req, 15.0, MAX_CLOUDFLARED_META_BYTES).decode("utf-8", errors="replace")
            m_html = re.search(rf"{re.escape(asset)}[^a-fA-F0-9\r\n]{{0,48}}([a-fA-F0-9]{{64}})", html_txt)
            if m_html:
                exp_hex = m_html.group(1).lower()
        except Exception:
            pass
    if not exp_hex:
        # 2) Fallback to GitHub Releases JSON API (wrapped so HTTP 403 rate-limit never aborts)
        meta_req = urllib.request.Request(
            CLOUDFLARED_RELEASES_API,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "Cosmos-MCP/1.0"},
        )
        try:
            raw_meta = _fetch(meta_req, 15.0, MAX_CLOUDFLARED_META_BYTES)
            rel_doc = json.loads(raw_meta.decode("utf-8", errors="replace"))
            if isinstance(rel_doc, dict):
                exp_hex = extract_sha256_from_release_metadata(rel_doc, asset)
        except Exception:
            pass
    if not exp_hex:
        # 3) Final fallback to `.sha256` sidecar
        sha_req = urllib.request.Request(
            f"{eff_url}.sha256",
            headers={"User-Agent": "Cosmos-MCP/1.0"},
        )
        try:
            sha_txt = _fetch(sha_req, 12.0, MAX_CLOUDFLARED_META_BYTES).decode("utf-8", errors="replace")
            m = SHA256_HEX_RE.search(sha_txt)
            if m:
                exp_hex = m.group(1).lower()
        except Exception:
            pass
    if not exp_hex or len(exp_hex) != 64:
        raise RuntimeError(f"Unable to obtain official SHA-256 digest for `{asset}`; refusing unverified binary download.")

    bin_req = urllib.request.Request(eff_url, headers={"User-Agent": "Cosmos-MCP/1.0"})
    payload = _fetch(bin_req, timeout_sec, MAX_CLOUDFLARED_DOWNLOAD_BYTES)
    if not payload:
        raise ValueError(f"Downloaded empty payload for `{asset}`.")
    actual_hex = compute_sha256_bytes(payload)
    if actual_hex != exp_hex:
        raise ValueError(
            f"cloudflared SHA-256 verification failed for `{asset}`: expected {exp_hex}, got {actual_hex}"
        )

    with tempfile.NamedTemporaryFile(dir=str(bin_dir), prefix=".cf_dl_", delete=False) as tf:
        tf.write(payload)
        tmp_path = Path(tf.name)

    try:
        if asset.endswith(".tgz") or asset.endswith(".tar.gz"):
            with tarfile.open(tmp_path, "r:gz") as tar:
                member = next((m for m in tar.getmembers() if m.isfile() and Path(m.name).name == exe_name), None)
                if member is None:
                    raise RuntimeError(f"`{exe_name}` not found inside `{asset}` archive.")
                if member.size > MAX_CLOUDFLARED_DOWNLOAD_BYTES:
                    raise ValueError(
                        f"Extracted `{exe_name}` size exceeded max allowed size ({member.size} > {MAX_CLOUDFLARED_DOWNLOAD_BYTES} bytes)."
                    )
                extracted = tar.extractfile(member)
                if extracted is None:
                    raise RuntimeError(f"Failed extracting `{exe_name}` from `{asset}`.")
                data_bin = _read_bounded_stream(extracted, MAX_CLOUDFLARED_DOWNLOAD_BYTES, label=exe_name)
            with tempfile.NamedTemporaryFile(dir=str(bin_dir), prefix=".cf_bin_", delete=False) as bf:
                bf.write(data_bin)
                bin_tmp = Path(bf.name)
            if sys.platform != "win32":
                os.chmod(bin_tmp, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
            os.replace(bin_tmp, local_bin)
        else:
            if sys.platform != "win32":
                os.chmod(tmp_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
            os.replace(tmp_path, local_bin)
            tmp_path = Path("")
    finally:
        if str(tmp_path) and tmp_path.exists():
            safe_trash_file(tmp_path, reason="cf_dl_temp_cleanup", undo_dir=bin_dir.parent / ".undo_history")
    return local_bin


def build_cloudflared_quick_tunnel_cmd(
    cloudflared_bin: str | Path,
    local_port: int,
    *,
    protocol: str = "http2",
    extra_args: Sequence[str] = (),
) -> List[str]:
    """Build `cloudflared` Quick Tunnel command enforcing `--protocol http2` for proxy & campus networks."""
    eff_proto = (protocol or "http2").strip() or "http2"
    cmd = [
        str(cloudflared_bin),
        "tunnel",
        "--url",
        f"http://127.0.0.1:{int(local_port)}",
        "--no-autoupdate",
        "--protocol",
        eff_proto,
        "--edge-ip-version",
        "4",
    ]
    for arg in extra_args:
        if arg:
            cmd.append(str(arg))
    return cmd


def build_cloudflared_named_tunnel_cmd(
    cloudflared_bin: str | Path,
    tunnel_token: str,
    *,
    protocol: str = "http2",
    extra_args: Sequence[str] = (),
) -> List[str]:
    """Build `cloudflared` Named Tunnel fixed-domain command enforcing `--protocol http2`."""
    clean_tok = normalize_tunnel_token(tunnel_token)
    if not clean_tok:
        raise ValueError("Cloudflare Tunnel Token 不能为空。")
    eff_proto = (protocol or "http2").strip() or "http2"
    cmd = [
        str(cloudflared_bin),
        "tunnel",
        "--no-autoupdate",
        "--protocol",
        eff_proto,
        "run",
        "--token",
        clean_tok,
    ]
    for arg in extra_args:
        if arg:
            cmd.append(str(arg))
    return cmd


def probe_doh_hostname_resolved(
    hostname: str,
    *,
    doh_endpoints: Sequence[str] = DOH_ENDPOINTS,
    timeout_sec: float = 3.5,
    opener: Optional[Callable[[urllib.request.Request, float], bytes]] = None,
) -> Tuple[bool, str]:
    """Check DNS resolution of `hostname` across domestic (`doh.pub`, `alidns`) and global DoH endpoints."""
    clean_host = (hostname or "").strip().lower().rstrip(".")
    if not clean_host:
        return False, ""

    try:
        import socket

        infos = socket.getaddrinfo(clean_host, 443, type=socket.SOCK_STREAM)
        if infos:
            return True, "system_dns"
    except Exception:
        pass

    direct_opener = _build_url_opener(use_proxy=False)
    for ep in doh_endpoints:
        q = urlencode({"name": clean_host, "type": "A"})
        sep = "&" if "?" in ep else "?"
        req = urllib.request.Request(
            f"{ep}{sep}{q}",
            headers={"Accept": "application/dns-json", "User-Agent": "Cosmos-MCP/1.0"},
        )
        try:
            if opener is not None:
                raw = opener(req, timeout_sec)
            else:
                with direct_opener.open(req, timeout=timeout_sec) as resp:
                    raw = resp.read()
            doc = json.loads(raw.decode("utf-8", errors="replace"))
            if isinstance(doc, dict) and int(doc.get("Status", -1)) == 0 and doc.get("Answer"):
                return True, ep
        except Exception:
            continue
    return False, ""


def wait_tunnel_dns_and_https_ready(
    public_url: str,
    *,
    timeout_sec: float = 30.0,
    doh_endpoints: Sequence[str] = DOH_ENDPOINTS,
) -> Dict[str, Any]:
    """Wait until `public_url` resolves via DoH and `/healthz` responds over HTTPS."""
    clean = (public_url or "").strip().rstrip("/")
    host = (urlsplit(clean).hostname or "").strip().lower()
    deadline = time.monotonic() + max(1.0, float(timeout_sec))
    dns_ok = False
    dns_provider = ""
    last_err = ""
    while time.monotonic() < deadline:
        if not dns_ok and host:
            dns_ok, dns_provider = probe_doh_hostname_resolved(host, doh_endpoints=doh_endpoints, timeout_sec=3.0)
        if dns_ok or not host:
            probe = probe_public_healthz_end_to_end(clean, timeout_sec=4.0)
            if probe.get("ok"):
                return {
                    "ok": True,
                    "public_url": clean,
                    "dns_resolved": True,
                    "dns_provider": dns_provider or "https_direct",
                    "status_code": probe.get("status_code", 200),
                }
            last_err = str(probe.get("error") or "")
        time.sleep(1.0)
    return {
        "ok": False,
        "public_url": clean,
        "dns_resolved": dns_ok,
        "dns_provider": dns_provider,
        "error": last_err or "timeout_waiting_for_tunnel_ready",
    }


def _rewrite_conn_info_urls(info_path: Path, new_public_url: str) -> None:
    if not info_path.is_file():
        return
    try:
        old_text = info_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    clean = new_public_url.rstrip("/")
    val_pat = r"(?:https?://[^\s\r\n]+|\([^)\r\n]*\))"
    updated = re.sub(
        rf"(主连接器地址\s*:\s*){val_pat}",
        rf"\g<1>{clean}/mcp",
        old_text,
    )
    updated = re.sub(
        rf"(纯只读端点地址\s*:\s*){val_pat}",
        rf"\g<1>{clean}/mcp/readonly",
        updated,
    )
    updated = re.sub(
        rf"(动态守则地址\s*:\s*){val_pat}",
        rf"\g<1>{clean}/skill",
        updated,
    )
    if clean.startswith("https://") and "trycloudflare.com" not in clean.lower():
        updated = re.sub(r"^[ \t]*\[临时地址提示\][^\r\n]*\r?\n", "", updated, flags=re.MULTILINE)
    if updated != old_text:
        atomic_write_text(info_path, updated, mode_override=0o600)


def hot_refresh_public_url(
    state_root: Path,
    new_public_url: str,
    *,
    port: int = 8096,
    prefix: str = "pc",
    tunnel_mode: str = "",
    gateway_id: str = "",
) -> Dict[str, Any]:
    """Atomically hot-refresh slot `public_url`, `pinned_gateway_urls`, and (when selected/empty) `public_base`."""
    st_root = Path(state_root).expanduser().resolve()
    clean_url = (new_public_url or "").strip().rstrip("/")
    if not clean_url.startswith(("https://", "http://")) or clean_url.lower() == "https://api.trycloudflare.com":
        raise ValueError(f"Invalid public tunnel URL: {new_public_url!r}")

    cfg_path = _service_cfg_path(st_root, prefix)
    cfg_doc: Dict[str, Any] = {}
    if cfg_path.is_file():
        try:
            loaded = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
            if isinstance(loaded, dict):
                cfg_doc = loaded
        except Exception:
            cfg_doc = {}

    explicit_gw = (gateway_id or "").strip().lower()
    gws, sel_gw = normalize_gateways_config(cfg_doc)
    eff_gw = (
        explicit_gw
        if explicit_gw in GATEWAY_IDS
        else (mode_to_gateway_slot(tunnel_mode)[0] if tunnel_mode else "")
    )
    if eff_gw in GATEWAY_IDS:
        slot_obj = dict(gws.get(eff_gw) or {"enabled": True, "submode": eff_gw, "public_url": ""})
        slot_obj["public_url"] = clean_url
        if tunnel_mode:
            mapped_slot, mapped_sub = mode_to_gateway_slot(tunnel_mode)
            if mapped_slot == eff_gw and mapped_sub:
                slot_obj["submode"] = mapped_sub
        gws[eff_gw] = slot_obj
        cfg_doc["gateways"] = gws
        pinned_urls = collect_pinned_gateway_urls(gws, cfg_doc)
        if is_pinned_gateway_url(clean_url) and clean_url not in pinned_urls:
            pinned_urls.append(clean_url)
        cfg_doc["pinned_gateway_urls"] = pinned_urls

    old_url = str(cfg_doc.get("public_base") or cfg_doc.get("public_base_url") or "").strip().rstrip("/")
    top_empty = (not old_url) or old_url.startswith(("http://127.", "http://localhost", "http://[::1]"))
    if explicit_gw in GATEWAY_IDS:
        should_sync_top = (explicit_gw == sel_gw) or top_empty
    else:
        should_sync_top = True

    cfg_doc.setdefault("host", "127.0.0.1")
    cfg_doc.setdefault("port", int(port))
    if should_sync_top:
        prev_list: List[str] = [
            str(u).strip().rstrip("/")
            for u in (cfg_doc.get("previous_public_bases") or [])
            if str(u).strip()
        ]
        if old_url and old_url != clean_url and old_url not in prev_list:
            prev_list.append(old_url)
        prev_list = [u for u in prev_list if u != clean_url][-8:]
        cfg_doc["public_base"] = clean_url
        cfg_doc["public_base_url"] = clean_url
        if tunnel_mode:
            eff_tm_norm = tunnel_mode.strip().lower()
            cfg_doc["tunnel_mode"] = eff_tm_norm
            cfg_doc["_gateways_mirrored_mode"] = eff_tm_norm
        cfg_doc["previous_public_bases"] = prev_list
    cfg_doc["policy_updated_at"] = round(time.time(), 6)
    atomic_write_json(cfg_path, cfg_doc)
    state_svc_path = st_root / "state" / cfg_path.name
    if state_svc_path.is_file():
        with contextlib.suppress(Exception):
            atomic_write_json(state_svc_path, cfg_doc)

    daemon_path = _daemon_status_path(st_root, prefix)
    if daemon_path.is_file():
        try:
            d_doc = json.loads(daemon_path.read_text(encoding="utf-8-sig"))
            if isinstance(d_doc, dict):
                if eff_gw in GATEWAY_IDS and isinstance(d_doc.get("gateways"), dict):
                    gw_d = d_doc["gateways"].get(eff_gw)
                    if isinstance(gw_d, dict):
                        gw_d["public_url"] = clean_url
                if should_sync_top:
                    d_doc["public_url"] = clean_url
                    d_doc["public_base_url"] = clean_url
                    d_doc["mcp_url"] = f"{clean_url}/mcp"
                    d_doc["readonly_mcp_url"] = f"{clean_url}/mcp/readonly"
                    if tunnel_mode:
                        d_doc["mode"] = tunnel_mode.strip().lower()
                d_doc["tunnel_updated_at"] = round(time.time(), 3)
                atomic_write_json(daemon_path, d_doc)
        except Exception:
            pass

    if should_sync_top:
        for info_p in _conn_info_paths(st_root, prefix):
            _rewrite_conn_info_urls(info_p, clean_url)

    return {
        "ok": True,
        "previous_url": old_url,
        "public_url": clean_url,
        "gateway_id": eff_gw,
        "synced_top_public_base": should_sync_top,
        "mcp_url": f"{clean_url}/mcp",
        "cfg_path": str(cfg_path),
        "server_restarted": False,
    }


class CloudflaredTunnelSupervisor:
    """Supervises `cloudflared` Quick Tunnel or Named Tunnel (`--token`) with `--protocol http2` and zero server downtime."""

    def __init__(
        self,
        *,
        cloudflared_bin: str | Path,
        local_port: int,
        state_root: Path,
        prefix: str = "pc",
        protocol: str = "http2",
        tunnel_token: str = "",
        fixed_public_url: str = "",
        persist_tunnel_mode: str = "",
        gateway_id: str = "",
        on_url_change: Optional[Callable[[str], None]] = None,
        popen_factory: Optional[Callable[..., Any]] = None,
    ) -> None:
        self.cloudflared_bin = Path(str(cloudflared_bin))
        self.local_port = int(local_port)
        self.state_root = Path(state_root).expanduser().resolve()
        self.prefix = _norm_prefix(prefix)
        self.protocol = protocol or "http2"
        self.tunnel_token = normalize_tunnel_token(tunnel_token)
        self.fixed_public_url = (fixed_public_url or "").strip().rstrip("/")
        self.persist_tunnel_mode = (persist_tunnel_mode or "").strip().lower()
        self.gateway_id = (gateway_id or ("self_hosted" if self.tunnel_token else "instant")).strip().lower()
        self.on_url_change = on_url_change
        self._popen_factory = popen_factory or subprocess.Popen
        self._stop_event = threading.Event()
        self._url_ready_event = threading.Event()
        self._lock = threading.Lock()
        self._proc: Optional[Any] = None
        self._job_handle: Optional[OwnedJobHandle] = None
        self._thread: Optional[threading.Thread] = None
        self.current_url: str = self.fixed_public_url
        self.reconnect_count: int = 0

    @property
    def is_named_tunnel(self) -> bool:
        return bool(self.tunnel_token)

    def build_command(self) -> List[str]:
        if self.tunnel_token:
            return build_cloudflared_named_tunnel_cmd(
                self.cloudflared_bin,
                self.tunnel_token,
                protocol=self.protocol,
            )
        return build_cloudflared_quick_tunnel_cmd(
            self.cloudflared_bin,
            self.local_port,
            protocol=self.protocol,
        )

    def _handle_discovered_url(self, url: str, *, mark_ready: bool = True) -> None:
        clean = url.strip().rstrip("/")
        if not clean:
            return
        with self._lock:
            changed = clean != self.current_url
            if self.current_url and changed:
                self.reconnect_count += 1
            self.current_url = clean
        if changed:
            eff_tm = self.persist_tunnel_mode or ("cloudflare_token" if self.is_named_tunnel else "cloudflare")
            hot_refresh_public_url(
                self.state_root,
                clean,
                port=self.local_port,
                prefix=self.prefix,
                tunnel_mode=eff_tm,
                gateway_id=self.gateway_id,
            )
            if self.on_url_change is not None:
                try:
                    self.on_url_change(clean)
                except Exception:
                    pass
        if mark_ready:
            self._url_ready_event.set()

    def _scrub_log_line(self, line: str) -> str:
        if self.tunnel_token and self.tunnel_token in line:
            return line.replace(self.tunnel_token, "[REDACTED_TUNNEL_TOKEN]")
        return line

    def _run_loop(self) -> None:
        backoff = 2.0
        logs_dir = self.state_root / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_file = logs_dir / (f"cloudflared_{self.prefix}.log" if self.prefix != "pc" else "cloudflared.log")

        if self.is_named_tunnel and self.fixed_public_url:
            hot_refresh_public_url(
                self.state_root,
                self.fixed_public_url,
                port=self.local_port,
                prefix=self.prefix,
                tunnel_mode="cloudflare_token",
                gateway_id=self.gateway_id or "self_hosted",
            )

        while not self._stop_event.is_set():
            cmd = self.build_command()
            started_at = time.monotonic()
            try:
                proc = self._popen_factory(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    creationflags=_popen_flags(),
                )
                cf_pid = getattr(proc, "pid", None)
                job_h = (
                    OwnedJobHandle(assign_win32_job_kill_on_close(int(cf_pid), max_mem_mb=0))
                    if (self._popen_factory is subprocess.Popen and isinstance(cf_pid, int) and cf_pid > 0)
                    else None
                )
                with self._lock:
                    if self._job_handle is not None:
                        self._job_handle.close()
                    self._proc = proc
                    self._job_handle = job_h
                if proc.stdout is not None:
                    _rotate_tunnel_log_if_needed(log_file)
                    with log_file.open("a", encoding="utf-8", errors="replace") as lf:
                        for line in proc.stdout:
                            lf.write(self._scrub_log_line(line))
                            lf.flush()
                            low_ln = line.lower()
                            is_edge_reg = "registered tunnel connection" in low_ln or ("connection " in low_ln and " registered" in low_ln)
                            if self.is_named_tunnel:
                                if is_edge_reg:
                                    if self.fixed_public_url:
                                        self._handle_discovered_url(self.fixed_public_url, mark_ready=True)
                                    else:
                                        self._url_ready_event.set()
                            else:
                                m = TRYCLOUDFLARE_URL_RE.search(line)
                                if m:
                                    # Persist URL immediately; wait for edge registration (or custom popen mock EOF) before marking ready
                                    self._handle_discovered_url(m.group(0), mark_ready=(self._popen_factory is not subprocess.Popen))
                                elif is_edge_reg and self.current_url:
                                    self._url_ready_event.set()
                            if self._stop_event.is_set():
                                break
                    if self.current_url and self._popen_factory is not subprocess.Popen:
                        self._url_ready_event.set()
                proc.wait(timeout=5.0)
            except Exception:
                pass

            if self._stop_event.is_set():
                break
            if (time.monotonic() - started_at) >= 45.0:
                backoff = 2.0
            self._stop_event.wait(backoff)
            backoff = min(45.0, backoff * 1.8)

    def start(self, wait_url_timeout_sec: float = 25.0) -> str:
        if self._thread is not None and self._thread.is_alive():
            return self.current_url
        self._stop_event.clear()
        self._url_ready_event.clear()
        th = threading.Thread(target=self._run_loop, name=f"cf-tunnel-{self.prefix}", daemon=True)
        th.start()
        self._thread = th
        if wait_url_timeout_sec > 0:
            self._url_ready_event.wait(timeout=wait_url_timeout_sec)
        return self.current_url

    @property
    def pid(self) -> Optional[int]:
        with self._lock:
            if self._proc is None:
                return None
            poll_fn = getattr(self._proc, "poll", None)
            if callable(poll_fn) and poll_fn() is not None:
                return None
            return int(self._proc.pid) if getattr(self._proc, "pid", None) else None

    def is_process_alive(self) -> bool:
        with self._lock:
            if self._proc is None:
                return False
            poll_fn = getattr(self._proc, "poll", None)
            if callable(poll_fn) and poll_fn() is not None:
                return False
            return True

    def stop(self, timeout_sec: float = 5.0) -> None:
        self._stop_event.set()
        with self._lock:
            proc = self._proc
            self._proc = None
            job_h = self._job_handle
            self._job_handle = None
        if proc is not None:
            pid = getattr(proc, "pid", None)
            try:
                proc.terminate()
                proc.wait(timeout=2.0)
            except Exception:
                if isinstance(pid, int) and pid > 0 and is_raw_pid_alive(pid):
                    terminate_verified_pid_tree(pid, expected_create_token=None)
        if job_h is not None:
            job_h.close()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout_sec)


# ---------------------------------------------------------------------------
# Zero-Login Fixed-Domain `srv.us` SSH Reverse Tunnel Supervisor
# ---------------------------------------------------------------------------


class _DualPidInt(int):
    """Int subclass compatible with both property access (`sup.pid`) and method call (`sup.pid()`)."""

    def __call__(self) -> int:
        return int(self)


def _resolve_system_ssh_bin() -> str:
    found = shutil.which("ssh")
    if found:
        return found
    if sys.platform == "win32":
        sys_root = os.environ.get("SystemRoot") or r"C:\Windows"
        win_ssh = Path(sys_root) / "System32" / "OpenSSH" / "ssh.exe"
        if win_ssh.is_file():
            return str(win_ssh)
    return "ssh"


def _resolve_system_ssh_keygen_bin() -> str:
    found = shutil.which("ssh-keygen")
    if found:
        return found
    if sys.platform == "win32":
        sys_root = os.environ.get("SystemRoot") or r"C:\Windows"
        win_kg = Path(sys_root) / "System32" / "OpenSSH" / "ssh-keygen.exe"
        if win_kg.is_file():
            return str(win_kg)
    return "ssh-keygen"


def _resolve_connect_proxy_bin() -> str:
    found = shutil.which("connect")
    if found and Path(found).is_file():
        return str(Path(found))
    if sys.platform == "win32":
        for env_k in ("ProgramFiles", "ProgramFiles(x86)"):
            base = os.environ.get(env_k)
            if not base:
                continue
            for rel in ("Git/mingw64/bin/connect.exe", "Git/usr/bin/connect.exe"):
                cand = Path(base) / rel
                if cand.is_file():
                    return str(cand)
    return ""


def _restrict_ssh_private_key_acl(priv_p: Path) -> None:
    if not priv_p.is_file():
        return
    if sys.platform != "win32":
        with contextlib.suppress(OSError):
            os.chmod(priv_p, 0o600)
        return
    icacls_bin = shutil.which("icacls")
    user_name = (os.environ.get("USERNAME") or "").strip()
    if icacls_bin and user_name:
        user_dom = (os.environ.get("USERDOMAIN") or "").strip()
        trustee = f"{user_dom}\\{user_name}" if user_dom else user_name
        with contextlib.suppress(Exception):
            subprocess.run(
                [
                    icacls_bin,
                    str(priv_p),
                    "/inheritance:r",
                    "/grant:r",
                    "*S-1-5-18:(F)",
                    "*S-1-5-32-544:(F)",
                    f"{trustee}:(F)",
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=8,
                creationflags=_popen_flags(),
                check=False,
            )


def srvus_ssh_key_paths(state_root: Path, prefix: str = "pc") -> Tuple[Path, Path]:
    """Return `(<state_root>/secrets/srvus_ed25519[_<prefix>], <...>.pub)` paths."""
    eff = _norm_prefix(prefix)
    stem = f"srvus_ed25519_{eff}" if eff != "pc" else "srvus_ed25519"
    sec_dir = Path(state_root).expanduser().resolve() / "secrets"
    return sec_dir / stem, sec_dir / f"{stem}.pub"


def ensure_srvus_ssh_keypair(state_root: Path, prefix: str = "pc") -> Tuple[Path, str]:
    """Generate or load persistent `<state_root>/secrets/srvus_ed25519[_<prefix>]` OpenSSH keypair via `ssh-keygen`."""
    priv_p, pub_p = srvus_ssh_key_paths(state_root, prefix=prefix)
    priv_p.parent.mkdir(parents=True, exist_ok=True)
    eff = _norm_prefix(prefix)
    comment = f"cosmos-mcp-srvus-{eff}"

    if priv_p.is_file() and priv_p.stat().st_size > 0:
        if pub_p.is_file():
            with contextlib.suppress(OSError):
                pub_txt = pub_p.read_text(encoding="utf-8", errors="replace").strip()
                if pub_txt.startswith("ssh-"):
                    if sys.platform != "win32":
                        with contextlib.suppress(OSError):
                            os.chmod(priv_p, 0o600)
                    return priv_p, pub_txt
        # Private key exists without `.pub` (e.g. imported from encrypted PNG recovery card): derive `.pub` non-destructively
        _restrict_ssh_private_key_acl(priv_p)
        keygen = _resolve_system_ssh_keygen_bin()
        with contextlib.suppress(Exception):
            drv_proc = subprocess.run(
                [keygen, "-y", "-f", str(priv_p)],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                creationflags=_popen_flags(),
                check=False,
            )
            if drv_proc.returncode == 0 and drv_proc.stdout.strip().startswith("ssh-"):
                pub_line = f"{drv_proc.stdout.strip()} {comment}"
                atomic_write_text(pub_p, pub_line + "\n", mode_override=0o600)
                return priv_p, pub_line

    keygen_bin = _resolve_system_ssh_keygen_bin()
    for stale in (priv_p, pub_p):
        if stale.exists():
            _shred_temp_file(stale)
    try:
        proc = subprocess.run(
            [keygen_bin, "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(priv_p)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            creationflags=_popen_flags(),
            check=False,
        )
        if proc.returncode == 0 and priv_p.is_file() and pub_p.is_file():
            if sys.platform != "win32":
                with contextlib.suppress(OSError):
                    os.chmod(priv_p, 0o600)
                    os.chmod(pub_p, 0o600)
            pub_out = pub_p.read_text(encoding="utf-8", errors="replace").strip()
            if pub_out.startswith("ssh-"):
                return priv_p, pub_out
    except Exception:
        pass

    # Pure-Python cryptography fallback if `ssh-keygen` binary is unavailable
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        key_obj = ed25519.Ed25519PrivateKey.generate()
        priv_bytes = key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = key_obj.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        pub_line = f"{pub_bytes.decode('ascii').strip()} {comment}"
        atomic_write_text(priv_p, priv_bytes.decode("ascii"), mode_override=0o600)
        atomic_write_text(pub_p, pub_line + "\n", mode_override=0o600)
        _restrict_ssh_private_key_acl(priv_p)
        return priv_p, pub_line
    except Exception as exc:
        raise RuntimeError(f"Failed generating srv.us Ed25519 SSH keypair: {exc}") from exc


_SSH_PROXY_BRIDGE_PY = r'''"""Stdlib HTTP CONNECT & SOCKS5 `ProxyCommand` stdio bridge for OpenSSH."""
import base64, os, socket, struct, sys, threading
from urllib.parse import unquote, urlsplit

def _pump(rd, wr, sock_ref=None):
    try:
        while True:
            buf = rd()
            if not buf:
                break
            wr(buf)
    except Exception:
        pass
    finally:
        if sock_ref is not None:
            try:
                sock_ref.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                sock_ref.close()
            except Exception:
                pass

def main():
    if sys.platform == "win32":
        import msvcrt
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    proxy_raw, dst_host, dst_port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    if "://" not in proxy_raw:
        proxy_raw = "http://" + proxy_raw
    u = urlsplit(proxy_raw)
    scheme = (u.scheme or "http").lower()
    p_host = u.hostname or "127.0.0.1"
    p_port = int(u.port or (1080 if "socks" in scheme else 8080))
    user = unquote(u.username) if u.username else ""
    pw = unquote(u.password) if u.password else ""

    sock = socket.create_connection((p_host, p_port), timeout=3.5)
    if "socks" in scheme:
        if user:
            sock.sendall(b"\x05\x02\x00\x02")
        else:
            sock.sendall(b"\x05\x01\x00")
        ver, method = sock.recv(2)
        if ver != 5 or method == 0xFF:
            raise RuntimeError("SOCKS5 greeting rejected")
        if method == 0x02:
            ub, pb = user.encode("utf-8"), pw.encode("utf-8")
            sock.sendall(b"\x01" + bytes([len(ub)]) + ub + bytes([len(pb)]) + pb)
            av, st = sock.recv(2)
            if st != 0:
                raise RuntimeError("SOCKS5 auth failed")
        hb = dst_host.encode("idna")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack("!H", dst_port))
        rep = sock.recv(4)
        if len(rep) < 4 or rep[1] != 0:
            raise RuntimeError("SOCKS5 CONNECT failed")
        atyp = rep[3]
        if atyp == 1:
            sock.recv(6)
        elif atyp == 3:
            ln = sock.recv(1)[0]
            sock.recv(ln + 2)
        elif atyp == 4:
            sock.recv(18)
    else:
        hdrs = [f"CONNECT {dst_host}:{dst_port} HTTP/1.1", f"Host: {dst_host}:{dst_port}"]
        if user:
            tok = base64.b64encode(f"{user}:{pw}".encode("utf-8")).decode("ascii")
            hdrs.append(f"Proxy-Authorization: Basic {tok}")
        hdrs.extend(["", ""])
        sock.sendall("\r\n".join(hdrs).encode("latin-1"))
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 16384:
            ch = sock.recv(1024)
            if not ch:
                break
            buf += ch
        status_ln = buf.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        if " 200" not in status_ln:
            raise RuntimeError(f"HTTP CONNECT rejected: {status_ln}")

    sock.settimeout(None)
    in_fd, out_fd = sys.stdin.fileno(), sys.stdout.fileno()
    t_up = threading.Thread(target=_pump, args=(lambda: os.read(in_fd, 32768), sock.sendall, sock), daemon=True)
    t_up.start()
    try:
        sock.settimeout(4.0)
        first_dn = sock.recv(32768)
        if not first_dn:
            return
        os.write(out_fd, first_dn)
        sock.settimeout(None)
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        os._exit(1)
    t_dn = threading.Thread(target=_pump, args=(lambda: sock.recv(32768), lambda b: os.write(out_fd, b), sock), daemon=True)
    t_dn.start()
    t_dn.join()
    try:
        sock.close()
    except Exception:
        pass
    os._exit(0)

if __name__ == "__main__":
    main()
'''


def _srvus_route_hint_path(state_root: Path, prefix: str = "pc") -> Path:
    eff = _norm_prefix(prefix)
    fn = f"srvus_route_hint_{eff}.json" if eff != "pc" else "srvus_route_hint.json"
    return Path(state_root).expanduser().resolve() / "state" / fn


def _load_srvus_route_hint(state_root: Path, prefix: str = "pc") -> Optional[str]:
    p = _srvus_route_hint_path(state_root, prefix)
    if not p.is_file():
        return None
    with contextlib.suppress(Exception):
        doc = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        if isinstance(doc, dict):
            route = str(doc.get("preferred_route") or "").strip().lower()
            if route in ("direct", "proxy"):
                return route
    return None


def _save_srvus_route_hint(state_root: Path, prefix: str, route: str) -> None:
    if route not in ("direct", "proxy"):
        return
    p = _srvus_route_hint_path(state_root, prefix)
    with contextlib.suppress(Exception):
        p.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(p, {"preferred_route": route, "updated_at": time.time()})


def _build_srvus_proxy_command(proxy_url: str, state_root: Path) -> str:
    clean_p = (proxy_url or "").strip()
    if not clean_p:
        return ""
    parsed = urlsplit(clean_p if "://" in clean_p else f"http://{clean_p}")
    scheme = (parsed.scheme or "http").lower()
    p_host = (parsed.hostname or "").strip()
    p_port = parsed.port or (1080 if "socks" in scheme else 8080)
    if not p_host:
        return ""

    connect_bin = _resolve_connect_proxy_bin()
    if connect_bin and not parsed.username and " " not in connect_bin:
        flag = "-S" if "socks" in scheme else "-H"
        return f"{connect_bin} {flag} {p_host}:{int(p_port)} %h %p"

    bin_dir = Path(state_root).expanduser().resolve() / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    bridge_script = bin_dir / "cosmos_ssh_proxy_bridge.py"
    if not bridge_script.is_file() or bridge_script.read_text(encoding="utf-8", errors="replace") != _SSH_PROXY_BRIDGE_PY:
        atomic_write_text(bridge_script, _SSH_PROXY_BRIDGE_PY, mode_override=0o700)
    py_con = resolve_console_python(sys.executable)
    return f'"{py_con}" -u -B "{bridge_script}" "{clean_p}" %h %p'


class SrvUsSshTunnelSupervisor:
    """Supervises zero-login fixed-domain `srv.us` SSH `-R` tunnel with sticky route memory & fast recovery."""

    def __init__(
        self,
        *,
        local_port: int,
        state_root: Path,
        prefix: str = "pc",
        ssh_host: str = "srv.us",
        ssh_port: int = 22,
        on_url_change: Optional[Callable[[str], None]] = None,
        popen_factory: Optional[Callable[..., Any]] = None,
        persist_tunnel_mode: str = "srv_us",
        gateway_id: str = "instant",
        proxy_detector: Optional[Callable[[str], str]] = None,
        tcp_prober: Optional[Callable[[str, int, float], bool]] = None,
    ) -> None:
        self.local_port = int(local_port)
        self.state_root = Path(state_root).expanduser().resolve()
        self.prefix = _norm_prefix(prefix)
        self.ssh_host = (ssh_host or "srv.us").strip() or "srv.us"
        self.ssh_port = int(ssh_port or 22)
        self.persist_tunnel_mode = (persist_tunnel_mode or "srv_us").strip().lower() or "srv_us"
        self.gateway_id = (gateway_id or "instant").strip().lower() or "instant"
        self.on_url_change = on_url_change
        self._popen_factory = popen_factory or subprocess.Popen
        self._proxy_detector = proxy_detector
        self._tcp_prober = tcp_prober
        self._stop_event = threading.Event()
        self._url_ready_event = threading.Event()
        self._fast_fail_event = threading.Event()
        self._lock = threading.Lock()
        self._proc: Optional[Any] = None
        self._job_handle: Optional[OwnedJobHandle] = None
        self._thread: Optional[threading.Thread] = None
        self.public_url: str = ""
        self.last_error: str = ""
        self.reconnect_count: int = 0
        self._startup_budget_sec: float = 4.0
        self._preferred_route: Optional[str] = (
            _load_srvus_route_hint(self.state_root, self.prefix)
            if (self._popen_factory is subprocess.Popen or proxy_detector is not None or tcp_prober is not None)
            else None
        )
        self._last_launch_route: str = "direct"
        self._route_consecutive_failures: int = 0
        self._attempt_got_url: bool = False

    @property
    def preferred_route(self) -> Optional[str]:
        with self._lock:
            return self._preferred_route

    @property
    def current_url(self) -> str:
        return self.public_url

    @current_url.setter
    def current_url(self, value: str) -> None:
        self.public_url = (value or "").strip().rstrip("/")

    def build_command(self, *, proxy_command: str = "", connect_timeout_sec: int = 4) -> List[str]:
        priv_key, _ = ensure_srvus_ssh_keypair(self.state_root, prefix=self.prefix)
        ssh_bin = _resolve_system_ssh_bin()
        eff_ct = max(1, int(connect_timeout_sec or 4))
        cmd: List[str] = [
            ssh_bin,
            "-i",
            str(priv_key),
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "BatchMode=yes",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "TCPKeepAlive=yes",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            f"ConnectTimeout={eff_ct}",
        ]
        if int(self.ssh_port) != 22:
            cmd.extend(["-p", str(int(self.ssh_port))])
        if proxy_command:
            cmd.extend(["-o", f"ProxyCommand={proxy_command}"])
        cmd.extend(
            [
                "-T",
                "-R",
                f"1:127.0.0.1:{int(self.local_port)}",
                self.ssh_host,
            ]
        )
        return cmd

    def _handle_discovered_url(self, raw_url: str) -> None:
        parsed = urlsplit(raw_url.strip().rstrip("/"))
        if not parsed.scheme or not parsed.netloc:
            return
        clean = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
        winning_route = ""
        with self._lock:
            changed = clean != self.public_url
            if self.public_url and changed:
                self.reconnect_count += 1
            self.public_url = clean
            self.last_error = ""
            self._attempt_got_url = True
            self._route_consecutive_failures = 0
            if self._last_launch_route in ("direct", "proxy"):
                self._preferred_route = self._last_launch_route
                winning_route = self._last_launch_route
        if winning_route:
            _save_srvus_route_hint(self.state_root, self.prefix, winning_route)
        if changed:
            hot_refresh_public_url(
                self.state_root,
                clean,
                port=self.local_port,
                prefix=self.prefix,
                tunnel_mode=self.persist_tunnel_mode or "srv_us",
                gateway_id=self.gateway_id,
            )
            if self.on_url_change is not None:
                with contextlib.suppress(Exception):
                    self.on_url_change(clean)
        self._url_ready_event.set()

    def _select_runtime_command(self, attempt_idx: int) -> List[str]:
        if (
            self._popen_factory is not subprocess.Popen
            and self._proxy_detector is None
            and self._tcp_prober is None
        ):
            with self._lock:
                self._last_launch_route = "direct"
            return self.build_command()

        probe_fn = self._tcp_prober or (lambda h, p, t: _probe_tcp_port_reachable(h, p, timeout_sec=t))
        if self._proxy_detector is not None:
            proxy_raw = self._proxy_detector("https") or self._proxy_detector("http")
        else:
            proxy_raw = (
                detect_configured_proxy("https", target_host=self.ssh_host)
                or detect_configured_proxy("http", target_host=self.ssh_host)
            )
        if not proxy_raw:
            with self._lock:
                self._last_launch_route = "direct"
            ct = max(2, min(4, int(self._startup_budget_sec))) if not self.public_url else 4
            return self.build_command(connect_timeout_sec=ct)

        with self._lock:
            pref = self._preferred_route
            consec_fails = self._route_consecutive_failures

        use_proxy = False
        if pref in ("direct", "proxy"):
            # Reuse proven route; only probe/switch to the alternate route after >=2 consecutive failures
            if consec_fails < 2:
                use_proxy = pref == "proxy"
            else:
                alt_use_proxy = pref != "proxy"
                use_proxy = alt_use_proxy if (consec_fails % 2 == 0) else (pref == "proxy")
        else:
            probe_sec = min(0.9, max(0.3, self._startup_budget_sec * 0.25))
            direct_reachable = bool(probe_fn(self.ssh_host, self.ssh_port, probe_sec))
            if direct_reachable:
                use_proxy = attempt_idx >= 1 and (attempt_idx % 2 == 1)
            else:
                use_proxy = attempt_idx % 2 == 0

        if use_proxy:
            proxy_cmd = _build_srvus_proxy_command(proxy_raw, self.state_root)
            if proxy_cmd:
                with self._lock:
                    self._last_launch_route = "proxy"
                return self.build_command(proxy_command=proxy_cmd, connect_timeout_sec=3)

        with self._lock:
            self._last_launch_route = "direct"
        direct_ct = 3 if not self.public_url else 4
        return self.build_command(connect_timeout_sec=direct_ct)

    def _run_loop(self) -> None:
        backoff = 0.8
        attempt_idx = 0
        logs_dir = self.state_root / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_file = logs_dir / (f"srvus_{self.prefix}.log" if self.prefix != "pc" else "srvus.log")

        while not self._stop_event.is_set():
            started_at = time.monotonic()
            tail_lines: List[str] = []
            with self._lock:
                self._attempt_got_url = False
            try:
                cmd = self._select_runtime_command(attempt_idx)
                attempt_idx += 1
                proc = self._popen_factory(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    creationflags=_popen_flags(),
                )
                ssh_pid = getattr(proc, "pid", None)
                job_h = (
                    OwnedJobHandle(assign_win32_job_kill_on_close(int(ssh_pid), max_mem_mb=0))
                    if (self._popen_factory is subprocess.Popen and isinstance(ssh_pid, int) and ssh_pid > 0)
                    else None
                )
                with self._lock:
                    if self._job_handle is not None:
                        self._job_handle.close()
                    self._proc = proc
                    self._job_handle = job_h

                if proc.stdout is not None:
                    _rotate_tunnel_log_if_needed(log_file)
                    with log_file.open("a", encoding="utf-8", errors="replace") as lf:
                        for raw_line in proc.stdout:
                            lf.write(raw_line)
                            lf.flush()
                            clean_ln = _ANSI_ESCAPE_RE.sub("", raw_line).strip()
                            if clean_ln:
                                tail_lines.append(clean_ln)
                                if len(tail_lines) > 4:
                                    tail_lines.pop(0)
                            m = SRVUS_URL_RE.search(clean_ln)
                            if m:
                                self._handle_discovered_url(m.group(0))
                            if self._stop_event.is_set():
                                break
                wait_fn = getattr(proc, "wait", None)
                rc = wait_fn(timeout=1.0) if callable(wait_fn) else 0
                if not self.public_url and not self._stop_event.is_set():
                    err_detail = " | ".join(tail_lines[-2:]) if tail_lines else f"ssh exited with code {rc}"
                    with self._lock:
                        self.last_error = f"srv.us tunnel error: {err_detail}"[:300]
            except Exception as exc:
                if not self._stop_event.is_set():
                    with self._lock:
                        self.last_error = f"srv.us tunnel error: {exc}"[:300]

            if self._stop_event.is_set():
                break
            with self._lock:
                got_url = self._attempt_got_url
                if got_url:
                    self._route_consecutive_failures = 0
                else:
                    self._route_consecutive_failures += 1

            if not self.public_url:
                if (
                    self._popen_factory is not subprocess.Popen
                    and self._proxy_detector is None
                    and self._tcp_prober is None
                    and attempt_idx >= 2
                ):
                    self._fast_fail_event.set()
                    break
                self._stop_event.wait(0.15 if attempt_idx == 1 else 0.4)
                continue
            if got_url and (time.monotonic() - started_at) >= 25.0:
                backoff = 0.5
            self._stop_event.wait(backoff)
            backoff = min(20.0, max(0.8, backoff * 1.7))

    def start(self, wait_url_timeout_sec: float = 4.0) -> str:
        if self._thread is not None and self._thread.is_alive() and self.public_url:
            return self.public_url
        if self._thread is not None and self._thread.is_alive():
            self.stop(timeout_sec=0.5)

        eff_wait = max(0.05, float(wait_url_timeout_sec)) if wait_url_timeout_sec > 0 else 0.0
        self._startup_budget_sec = eff_wait if eff_wait > 0 else 4.0
        self.public_url = ""
        self.last_error = ""
        self._stop_event.clear()
        self._url_ready_event.clear()
        self._fast_fail_event.clear()

        th = threading.Thread(target=self._run_loop, name=f"srvus-tunnel-{self.prefix}", daemon=True)
        th.start()
        self._thread = th

        if eff_wait > 0:
            deadline = time.monotonic() + eff_wait
            while not self._url_ready_event.is_set() and not self._fast_fail_event.is_set():
                rem = deadline - time.monotonic()
                if rem <= 0:
                    break
                self._url_ready_event.wait(timeout=min(0.05, rem))

        if not self.public_url:
            with self._lock:
                if not self.last_error:
                    self.last_error = f"srv.us SSH tunnel timed out after {eff_wait:.1f}s"
            self.stop(timeout_sec=0.4)
            return ""
        return self.public_url

    @property
    def pid(self) -> Optional[int]:
        with self._lock:
            if self._proc is None:
                return None
            poll_fn = getattr(self._proc, "poll", None)
            if callable(poll_fn) and poll_fn() is not None:
                return None
            raw_pid = getattr(self._proc, "pid", None)
            if isinstance(raw_pid, int) and raw_pid > 0:
                return _DualPidInt(raw_pid)
            return None

    def is_process_alive(self) -> bool:
        with self._lock:
            if self._stop_event.is_set():
                return False
            if self._proc is not None:
                poll_fn = getattr(self._proc, "poll", None)
                if not callable(poll_fn) or poll_fn() is None:
                    return True
            if (
                self.public_url
                and self._thread is not None
                and self._thread.is_alive()
                and self._route_consecutive_failures < 2
            ):
                return True
            return False

    def stop(self, timeout_sec: float = 5.0) -> None:
        self._stop_event.set()
        with self._lock:
            proc = self._proc
            self._proc = None
            job_h = self._job_handle
            self._job_handle = None
        if proc is not None:
            pid = getattr(proc, "pid", None)
            try:
                term_fn = getattr(proc, "terminate", None)
                if callable(term_fn):
                    term_fn()
                wait_fn = getattr(proc, "wait", None)
                if callable(wait_fn):
                    wait_fn(timeout=min(0.4, max(0.1, float(timeout_sec) * 0.5)))
            except Exception:
                kill_fn = getattr(proc, "kill", None)
                if callable(kill_fn):
                    with contextlib.suppress(Exception):
                        kill_fn()
                if (
                    self._popen_factory is subprocess.Popen
                    and isinstance(pid, int)
                    and pid > 0
                    and is_raw_pid_alive(pid)
                ):
                    terminate_verified_pid_tree(pid, expected_create_token=None)
            stdout_obj = getattr(proc, "stdout", None)
            if stdout_obj is not None and hasattr(stdout_obj, "close"):
                with contextlib.suppress(Exception):
                    stdout_obj.close()
        if job_h is not None:
            job_h.close()
        if self._thread is not None and self._thread.is_alive() and threading.current_thread() is not self._thread:
            self._thread.join(timeout=timeout_sec)


# ---------------------------------------------------------------------------
# VPS SSH `-R` Reverse Tunnel & Caddy Snippet
# ---------------------------------------------------------------------------

def build_vps_ssh_reverse_tunnel_cmd(
    ssh_target: str,
    remote_bind_port: int,
    local_port: int,
    *,
    ssh_port: int = 22,
    identity_file: str = "",
    ssh_bin: str = "ssh",
) -> List[str]:
    """Build non-interactive SSH `-R` reverse tunnel command preventing HostKey / dead-TCP hangs."""
    target = (ssh_target or "").strip()
    if not target:
        raise ValueError("`ssh_target` (e.g. user@vps.example.com) is required for `--mode vps`.")
    cmd: List[str] = [
        ssh_bin,
        "-N",
        "-T",
        *VPS_SSH_MANDATORY_OPTIONS,
        "-p",
        str(int(ssh_port)),
    ]
    if identity_file and str(identity_file).strip():
        cmd.extend(["-i", str(Path(identity_file).expanduser())])
    cmd.extend(
        [
            "-R",
            f"127.0.0.1:{int(remote_bind_port)}:127.0.0.1:{int(local_port)}",
            target,
        ]
    )
    return cmd


def generate_vps_caddy_snippet(domain: str, remote_port: int = 18096) -> str:
    """Generate Caddyfile reverse-proxy snippet with SSE `flush_interval -1` for Streamable HTTP MCP."""
    clean_host = (domain or "").strip()
    if "://" in clean_host:
        clean_host = urlsplit(clean_host).netloc or clean_host
    clean_host = clean_host.strip("/") or "mcp.example.com"
    r_port = int(remote_port)
    return (
        f"{clean_host} {{\n"
        "    encode gzip\n"
        f"    reverse_proxy 127.0.0.1:{r_port} {{\n"
        "        flush_interval -1\n"
        "        header_up Host {host}\n"
        "        header_up X-Forwarded-Proto {scheme}\n"
        "        header_up X-Real-IP {remote_host}\n"
        "        header_up X-Cosmos-Client-IP {remote_host}\n"
        "    }\n"
        "}\n"
    )


def probe_public_healthz_end_to_end(
    public_base: str,
    *,
    timeout_sec: float = 12.0,
    opener: Optional[Callable[[urllib.request.Request, float], Tuple[int, bytes]]] = None,
) -> Dict[str, Any]:
    """Probe `public_base/healthz` end-to-end and return structured diagnostics + troubleshooting hints."""
    clean = (public_base or "").strip().rstrip("/")
    if not clean.startswith(("https://", "http://")):
        return {
            "ok": False,
            "url": clean,
            "error": "invalid_public_base",
            "hints": ["请提供以 https:// 开头的公网域名地址（例如 https://mcp.example.com）。"],
        }
    target_url = f"{clean}/healthz"
    req = urllib.request.Request(
        target_url,
        headers={"Accept": "application/json", "User-Agent": "Cosmos-MCP-Probe/1.0"},
    )
    try:
        if opener is not None:
            code, raw = opener(req, timeout_sec)
        else:
            ctx = ssl.create_default_context()
            https_handler = urllib.request.HTTPSHandler(context=ctx)
            parsed_pb = urlsplit(clean)
            host_low = (parsed_pb.hostname or "").strip().lower()
            openers_to_try: List[urllib.request.OpenerDirector] = []
            if host_low not in ("127.0.0.1", "::1", "localhost"):
                sys_proxy = detect_configured_proxy(parsed_pb.scheme or "https", target_host=host_low)
                if sys_proxy and sys_proxy.lower().startswith(("http://", "https://")):
                    openers_to_try.append(
                        urllib.request.build_opener(
                            urllib.request.ProxyHandler({"http": sys_proxy, "https": sys_proxy}),
                            https_handler,
                        )
                    )
            openers_to_try.append(urllib.request.build_opener(urllib.request.ProxyHandler({}), https_handler))
            last_ue: Optional[Exception] = None
            code = 0
            raw = b""
            per_try_timeout = (
                max(1.5, min(float(timeout_sec), 3.0))
                if len(openers_to_try) > 1
                else max(1.0, float(timeout_sec))
            )
            for idx_o, op_cand in enumerate(openers_to_try):
                fresh_req = urllib.request.Request(
                    target_url,
                    headers={"Accept": "application/json", "User-Agent": "Cosmos-MCP-Probe/1.0"},
                )
                try:
                    with op_cand.open(fresh_req, timeout=per_try_timeout) as resp:
                        code = int(getattr(resp, "status", 200))
                        raw = resp.read()
                    last_ue = None
                    break
                except HTTPError:
                    raise
                except Exception as ue_cand:
                    last_ue = ue_cand
                    if idx_o + 1 >= len(openers_to_try):
                        raise
            if last_ue is not None:
                raise last_ue
        body_txt = raw.decode("utf-8", errors="replace")
        if 200 <= code < 300:
            return {"ok": True, "url": target_url, "status_code": code, "body": body_txt[:400]}
        return {
            "ok": False,
            "url": target_url,
            "status_code": code,
            "error": f"http_status_{code}",
            "hints": [
                f"公网地址返回 HTTP {code}，请确认 Cloudflare Tunnel 或自有服务器 Caddy/Nginx 已转发至本机监听端口。",
                "若使用自有服务器，可运行 `cosmos-mcp vps-caddy-snippet --domain <域名> --remote-port <远端端口>` 获取标准配置。",
            ],
        }
    except HTTPError as he:
        return {
            "ok": False,
            "url": target_url,
            "status_code": int(he.code),
            "error": f"http_error_{he.code}",
            "hints": [
                f"公网网关返回 HTTP {he.code}（若为 502/530，请检查本机服务是否在线及隧道目标端口是否一致）。",
            ],
        }
    except Exception as exc:
        return {
            "ok": False,
            "url": target_url,
            "error": str(exc),
            "hints": [
                "无法访问公网 /healthz：请检查 ① 域名解析是否已生效；② 固定域名 Tunnel Token 或 SSH 反向隧道是否已连通；③ 443 端口是否放行。",
            ],
        }


# ---------------------------------------------------------------------------
# Card 3: 1-Minute Windowless VPS 24h MCP Hub Provisioner & `:443 WSS` Node
# ---------------------------------------------------------------------------

CLOUD_FIREWALL_GUIDES_ZH: Dict[str, str] = {
    "aliyun": (
        "阿里云安全组放行路径：登录 ECS 控制台 -> 实例与镜像 -> 实例 -> 点击目标服务器 -> "
        "「安全组」页签 -> 管理规则 -> 入方向手动添加两条规则：允许 TCP `80/80` 与 `443/443`，授权对象 `0.0.0.0/0`。"
    ),
    "tencent": (
        "腾讯云防火墙/安全组放行路径：轻量应用服务器进入「防火墙 -> 添加规则」放行 TCP `80` 与 `443`；"
        "云服务器 CVM 进入「安全组 -> 修改规则 -> 入站规则」添加 `TCP:80` 与 `TCP:443` 来源 `0.0.0.0/0`。"
    ),
    "aws": (
        "AWS 安全组放行路径：EC2 Console -> Instances -> 选中实例 -> Security 页签 -> 点击 Security Group -> "
        "Edit inbound rules -> 添加 `HTTP (TCP 80)` 与 `HTTPS (TCP 443)` Source `0.0.0.0/0`。"
    ),
    "oracle": (
        "Oracle Cloud 双层放行路径：① VCN -> Subnets -> Security Lists -> Add Ingress Rules 放行 TCP `80` 与 `443` (`0.0.0.0/0`)；"
        "② Oracle Ubuntu 镜像默认自带主机 iptables 拦截，已由脚本尝试放行，请确认子网安全列表已生效。"
    ),
    "vultr": (
        "Vultr 防火墙放行路径：Products -> Network -> Firewall -> 选择绑定的 Firewall Group -> "
        "Inbound IPv4 Rules 添加 `TCP 80` 与 `TCP 443` (`Anywhere 0.0.0.0/0`)。"
    ),
    "generic": (
        "云厂商控制台安全组/防火墙放行指引：请登录您的云服务器管理面板，在「防火墙 / 安全组 (Security Group) -> 入站规则」中"
        "放行 `TCP 80`（证书签发校验）与 `TCP 443`（HTTPS 与 WSS 隧道），来源设为 `0.0.0.0/0`。"
    ),
}

_MAINLAND_CN_REGION_RE = re.compile(
    r"^(?:cn-[a-z0-9-]+|ap-(?:beijing|shanghai|guangzhou|chengdu|chongqing|nanjing|shenzhen)[a-z0-9-]*)$",
    re.IGNORECASE,
)


def get_cloud_firewall_guide(cloud_provider: str, blocked_ports: Sequence[int] = (80, 443)) -> str:
    prov = (cloud_provider or "generic").strip().lower()
    base = CLOUD_FIREWALL_GUIDES_ZH.get(prov) or CLOUD_FIREWALL_GUIDES_ZH["generic"]
    ports_txt = ", ".join(str(int(p)) for p in blocked_ports) if blocked_ports else "80, 443"
    return f"检测到远端端口 [{ports_txt}] 外部不可达。{base}"


def vps_ssh_key_paths(state_root: Path, prefix: str = "pc") -> Tuple[Path, Path]:
    eff = _norm_prefix(prefix)
    stem = f"vps_id_ed25519_{eff}" if eff != "pc" else "vps_id_ed25519"
    sec_dir = Path(state_root).expanduser().resolve() / "secrets"
    return sec_dir / stem, sec_dir / f"{stem}.pub"


def vps_node_secret_path(state_root: Path, prefix: str = "pc") -> Path:
    eff = _norm_prefix(prefix)
    fn = f"vps_node_secret_{eff}.txt" if eff != "pc" else "vps_node_secret.txt"
    return Path(state_root).expanduser().resolve() / "secrets" / fn


def load_or_create_vps_node_secret(state_root: Path, prefix: str = "pc") -> str:
    p = vps_node_secret_path(state_root, prefix=prefix)
    if p.is_file():
        with contextlib.suppress(OSError):
            val = p.read_text(encoding="utf-8", errors="replace").strip()
            if len(val) >= 32:
                return val
    sec = secrets.token_hex(32)
    atomic_write_text(p, sec + "\n", mode_override=0o600)
    return sec


def _shred_temp_file(file_path: Path) -> None:
    if not file_path.exists() and not file_path.is_symlink():
        return
    try:
        if file_path.is_file() and not file_path.is_symlink():
            sz = max(int(file_path.stat().st_size), 128)
            with file_path.open("r+b") as fh:
                fh.seek(0)
                fh.write(b"\x00" * sz)
                fh.flush()
                with contextlib.suppress(OSError):
                    os.fsync(fh.fileno())
                fh.seek(0)
                fh.truncate(0)
                fh.flush()
                with contextlib.suppress(OSError):
                    os.fsync(fh.fileno())
    except OSError:
        pass
    with contextlib.suppress(OSError):
        file_path.unlink(missing_ok=True)


def ensure_vps_ssh_keypair(state_root: Path, prefix: str = "pc") -> Tuple[Path, str]:
    """Generate or load dedicated `<state_root>/secrets/vps_id_ed25519[_<prefix>]` OpenSSH keypair."""
    priv_p, pub_p = vps_ssh_key_paths(state_root, prefix=prefix)
    priv_p.parent.mkdir(parents=True, exist_ok=True)
    if priv_p.is_file() and pub_p.is_file():
        with contextlib.suppress(OSError):
            pub_txt = pub_p.read_text(encoding="utf-8", errors="replace").strip()
            if pub_txt.startswith("ssh-"):
                if sys.platform != "win32":
                    with contextlib.suppress(OSError):
                        os.chmod(priv_p, 0o600)
                return priv_p, pub_txt

    eff = _norm_prefix(prefix)
    comment = f"cosmos-mcp-{eff}"
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        key_obj = ed25519.Ed25519PrivateKey.generate()
        priv_bytes = key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = key_obj.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        pub_line = f"{pub_bytes.decode('ascii').strip()} {comment}"
        atomic_write_text(priv_p, priv_bytes.decode("ascii"), mode_override=0o600)
        atomic_write_text(pub_p, pub_line + "\n", mode_override=0o600)
        return priv_p, pub_line
    except Exception:
        keygen = shutil.which("ssh-keygen") or "ssh-keygen"
        for stale in (priv_p, pub_p):
            if stale.exists():
                _shred_temp_file(stale)
        proc = subprocess.run(
            [keygen, "-t", "ed25519", "-N", "", "-C", comment, "-f", str(priv_p)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            creationflags=_popen_flags(),
            check=False,
        )
        if proc.returncode != 0 or not pub_p.is_file():
            raise RuntimeError(f"Failed generating SSH Ed25519 keypair: {proc.stderr.strip()}")
        if sys.platform != "win32":
            with contextlib.suppress(OSError):
                os.chmod(priv_p, 0o600)
        return priv_p, pub_p.read_text(encoding="utf-8", errors="replace").strip()


def ip_to_sslip_domain(public_ip: str) -> str:
    clean_ip = (public_ip or "").strip().strip("[]")
    if ":" in clean_ip:
        return f"{clean_ip.replace(':', '-')}.sslip.io"
    return f"{clean_ip.replace('.', '-')}.sslip.io"


COSMOS_CADDY_MANAGED_MARKER = "# Managed by Cosmos MCP Hub"


def build_vps_hub_caddy_site_snippet(
    public_ip: str,
    *,
    custom_domain: str = "",
    hub_port: int = 18096,
) -> str:
    """Build standalone Caddy site block(s) safe for `/etc/caddy/cosmos-mcp.caddy` `import`."""
    clean_ip = (public_ip or "").strip()
    if not clean_ip:
        raise ValueError("`public_ip` is required to configure Caddy site block.")

    clean_domain = (custom_domain or "").strip().lower()
    if "://" in clean_domain:
        clean_domain = (urlsplit(clean_domain).hostname or clean_domain).strip().lower()
    clean_domain = clean_domain.strip("/")

    r_port = int(hub_port)
    proxy_body = (
        "    encode gzip\n"
        "    @blocked_admin path /studio /studio/* /api/studio /api/studio/* /oauth/local-bridge /oauth/local-bridge/* /local-admin /local-admin/* /remote-admin /remote-admin/*\n"
        '    respond @blocked_admin "Forbidden" 403\n'
        f"    reverse_proxy 127.0.0.1:{r_port} {{\n"
        "        flush_interval -1\n"
        "        header_up X-Cosmos-Via-Tunnel 1\n"
        "        header_up X-Forwarded-Proto https\n"
        "        header_up X-Forwarded-Host {host}\n"
        "        header_up X-Real-IP {remote_host}\n"
        "        header_up X-Cosmos-Client-IP {remote_host}\n"
        "    }\n"
    )

    if clean_domain:
        return f"{clean_domain} {{\n{proxy_body}}}\n"

    sslip_host = ip_to_sslip_domain(clean_ip)
    ip_host_lit = f"[{clean_ip}]" if (":" in clean_ip and not clean_ip.startswith("[")) else clean_ip
    ip_block = (
        f"https://{ip_host_lit} {{\n"
        "    tls {\n"
        "        issuer acme {\n"
        "            profile shortlived\n"
        "        }\n"
        "    }\n"
        f"{proxy_body}"
        "}\n\n"
    )
    sslip_block = f"{sslip_host} {{\n{proxy_body}}}\n"
    return ip_block + sslip_block


def build_vps_hub_caddyfile(
    public_ip: str,
    *,
    custom_domain: str = "",
    hub_port: int = 18096,
    cert_storage_dir: str = "/var/lib/cosmos-mcp/caddy",
) -> str:
    """Build Caddy v2.11+ `Caddyfile` with `default_sni`, persistent cert dir, and shortlived IP + sslip.io fallback."""
    clean_ip = (public_ip or "").strip()
    if not clean_ip:
        raise ValueError("`public_ip` is required to configure Caddy `default_sni`.")

    site_body = build_vps_hub_caddy_site_snippet(
        clean_ip,
        custom_domain=custom_domain,
        hub_port=hub_port,
    )
    global_block = (
        f"{COSMOS_CADDY_MANAGED_MARKER}\n"
        "{\n"
        f"    storage file_system {cert_storage_dir}\n"
        f"    default_sni {clean_ip}\n"
        "}\n\n"
    )
    return global_block + site_body


def is_default_or_cosmos_caddyfile(content: str) -> bool:
    """Return True if `content` is empty, Cosmos-managed, or the stock Caddy welcome `:80` sample."""
    raw = str(content or "")
    if COSMOS_CADDY_MANAGED_MARKER in raw:
        return True
    active_lines = [
        ln.strip()
        for ln in raw.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    if not active_lines:
        return True
    joined = "\n".join(active_lines)
    if (
        ":80" in joined
        and "/usr/share/caddy" in joined
        and "reverse_proxy" not in joined
        and "php_fastcgi" not in joined
        and "import " not in joined
    ):
        return True
    return False


def _strip_caddy_comment(line: str) -> str:
    in_quotes = False
    escaped = False
    out: List[str] = []
    for idx, ch in enumerate(line):
        if escaped:
            out.append(ch)
            escaped = False
            continue
        if ch == "\\":
            out.append(ch)
            escaped = True
            continue
        if ch == '"':
            in_quotes = not in_quotes
            out.append(ch)
            continue
        if ch == "#" and not in_quotes and (idx == 0 or line[idx - 1].isspace()):
            break
        out.append(ch)
    return "".join(out)


def ensure_caddyfile_global_default_sni(caddyfile_content: str, public_ip: str) -> str:
    """Ensure top-level Caddyfile global options block declares `default_sni <public_ip>` for bare-IP ACME certs."""
    clean_ip = (public_ip or "").strip()
    if not clean_ip:
        return caddyfile_content

    raw = str(caddyfile_content or "")
    lines = raw.splitlines(keepends=True)
    first_idx: Optional[int] = None
    for idx, ln in enumerate(lines):
        stripped = _strip_caddy_comment(ln).strip()
        if stripped:
            first_idx = idx
            break

    if first_idx is None:
        sep = "" if (not raw or raw.endswith("\n")) else "\n"
        return f"{{\n    default_sni {clean_ip}\n}}\n{sep}{raw}"

    first_active = _strip_caddy_comment(lines[first_idx]).strip()
    # Single-line global block: `{ ... }` at the very top of Caddyfile (not `{$ENV}`)
    if first_active.startswith("{") and not first_active.startswith("{$") and first_active.endswith("}"):
        if re.search(r"\bdefault_sni\b", first_active):
            return raw
        inner = first_active[1:-1].strip()
        replacement = (
            f"{{\n    default_sni {clean_ip}\n    {inner}\n}}\n"
            if inner
            else f"{{\n    default_sni {clean_ip}\n}}\n"
        )
        lines[first_idx] = replacement
        return "".join(lines)

    # Multi-line global block: `{` alone on the first active line
    if first_active == "{":
        depth = 0
        end_idx = len(lines) - 1
        for i in range(first_idx, len(lines)):
            code_part = _strip_caddy_comment(lines[i])
            depth += code_part.count("{") - code_part.count("}")
            if depth <= 0:
                end_idx = i
                break
        for i in range(first_idx, end_idx + 1):
            if re.match(r"^\s*default_sni\b", _strip_caddy_comment(lines[i])):
                return raw
        lines.insert(first_idx + 1, f"    default_sni {clean_ip}\n")
        return "".join(lines)

    # No top-level `{` global block: safely prepend global block at the very top
    return f"{{\n    default_sni {clean_ip}\n}}\n\n{raw}"


_CACHED_SRC_TAR_KEY: Optional[Tuple[str, int, int, int]] = None
_CACHED_SRC_TAR_B64: str = ""


def build_cosmos_mcp_source_tar_gz_b64(src_pkg_dir: Optional[Path] = None) -> str:
    """Pack local `cosmos_mcp` package directory (`Path(__file__).resolve().parents[1]`) into gzipped tar Base64."""
    global _CACHED_SRC_TAR_KEY, _CACHED_SRC_TAR_B64
    pkg_dir = Path(src_pkg_dir).resolve() if src_pkg_dir is not None else Path(__file__).resolve().parents[1]
    if not pkg_dir.is_dir():
        raise FileNotFoundError(f"cosmos_mcp package source directory not found: {pkg_dir}")

    excluded_dirs = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".undo_history", ".git"}
    excluded_suffixes = (".pyc", ".pyo", ".pyd", ".bak")

    collected: List[Tuple[str, Path, os.stat_result]] = []
    max_mtime_ns = 0
    total_bytes = 0
    for root, dirs, files in os.walk(pkg_dir):
        dirs[:] = sorted(d for d in dirs if d not in excluded_dirs and d.lower() not in excluded_dirs)
        for fname in sorted(files):
            low_f = fname.lower()
            if any(low_f.endswith(sfx) for sfx in excluded_suffixes):
                continue
            fp = Path(root) / fname
            try:
                st = fp.stat()
            except OSError:
                continue
            rel_posix = fp.relative_to(pkg_dir).as_posix()
            collected.append((rel_posix, fp, st))
            if st.st_mtime_ns > max_mtime_ns:
                max_mtime_ns = st.st_mtime_ns
            total_bytes += int(st.st_size)

    cache_key = (str(pkg_dir), len(collected), total_bytes, max_mtime_ns)
    if _CACHED_SRC_TAR_KEY == cache_key and _CACHED_SRC_TAR_B64:
        return _CACHED_SRC_TAR_B64

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=9) as tf:
        for rel_posix, fp, _st in collected:
            data = fp.read_bytes()
            ti = tarfile.TarInfo(name=f"cosmos_mcp/{rel_posix}")
            ti.size = len(data)
            ti.mtime = 1764115200
            ti.mode = 0o755 if rel_posix.endswith(".sh") else 0o644
            tf.addfile(ti, io.BytesIO(data))

    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    _CACHED_SRC_TAR_KEY = cache_key
    _CACHED_SRC_TAR_B64 = encoded
    return encoded


def build_vps_hub_systemd_unit(
    *,
    hub_dir: str = "/opt/cosmos-mcp-hub",
    env_file: str = "/etc/cosmos-mcp/hub.env",
    hub_port: int = 18096,
    state_root: str = "/var/lib/cosmos-mcp/state",
) -> str:
    p_num = int(hub_port)
    exec_cmd = (
        f"/bin/sh -c 'if [ -x {hub_dir}/venv/bin/python ] && "
        f'{hub_dir}/venv/bin/python -c "import uvicorn, websockets, starlette, mcp, pydantic, cryptography, multipart, cosmos_mcp.launcher.app" >/dev/null 2>&1; '
        f"then exec {hub_dir}/venv/bin/python -m cosmos_mcp.launcher.app "
        f"--host 127.0.0.1 --port {p_num} --state-root {state_root}; fi; "
        f"exec /usr/bin/env python3 -B {hub_dir}/hub_gateway.py --host 127.0.0.1 --port {p_num} --state-root {state_root}'"
    )
    return (
        "[Unit]\n"
        "Description=Cosmos MCP 24h Resident Hub & WSS Node Multiplexer\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"WorkingDirectory={hub_dir}\n"
        f"EnvironmentFile={env_file}\n"
        "Environment=PYTHONDONTWRITEBYTECODE=1\n"
        "Environment=PYTHONUTF8=1\n"
        f"Environment=PYTHONPATH={hub_dir}/src\n"
        f"Environment=COSMOS_MCP_STATE_DIR={state_root}\n"
        f"ExecStart={exec_cmd}\n"
        "Restart=always\n"
        "RestartSec=2\n"
        "LimitNOFILE=65535\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


# Compact pure-stdlib 24h resident VPS Hub fallback: stays online 24/7 returning ERR_NODE_OFFLINE (never 502) when PC is off
VPS_RESIDENT_HUB_PY = r'''"""24h Resident Cosmos MCP VPS Hub (`/_cosmos_node` WSS binary multiplexer + offline `ERR_NODE_OFFLINE` guard)."""
import argparse, asyncio, base64, hashlib, hmac, importlib.util, json, os, struct, time, uuid

FRAME_REQ_HEAD, FRAME_REQ_BODY, FRAME_REQ_END, FRAME_REQ_CANCEL = 0x10, 0x11, 0x12, 0x13
FRAME_RES_HEAD, FRAME_RES_BODY, FRAME_RES_END = 0x20, 0x21, 0x22
FRAME_ERR_ABORT = 0xFF
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

class HubState:
    def __init__(self, secret: str) -> None:
        self.secret = secret
        self.node_writer = None
        self.pending = {}
        self.last_drop = 0.0

    def pack_ws(self, payload: bytes, opcode: int = 0x2) -> bytes:
        n = len(payload)
        hdr = bytearray([0x80 | opcode])
        if n < 126:
            hdr.append(n)
        elif n < 65536:
            hdr.append(126)
            hdr.extend(struct.pack("!H", n))
        else:
            hdr.append(127)
            hdr.extend(struct.pack("!Q", n))
        return bytes(hdr) + payload

MAX_HTTP_HEADER_BYTES = 65536
MAX_HTTP_BODY_BYTES = 16 * 1024 * 1024
MAX_WS_FRAME_BYTES = 32 * 1024 * 1024

async def read_ws_frame(reader: asyncio.StreamReader):
    b0, b1 = await reader.readexactly(2)
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    if length == 126:
        length = struct.unpack("!H", await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", await reader.readexactly(8))[0]
    if length > MAX_WS_FRAME_BYTES:
        raise ValueError("ws_frame_too_large")
    mkey = await reader.readexactly(4) if masked else b""
    data = await reader.readexactly(length)
    if masked:
        data = bytes(b ^ mkey[i & 3] for i, b in enumerate(data))
    return opcode, data

async def handle_conn(hub: HubState, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        raw_head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=15.0)
    except asyncio.LimitOverrunError:
        writer.write(b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        return
    except Exception:
        writer.close()
        return
    if len(raw_head) > MAX_HTTP_HEADER_BYTES:
        writer.write(b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        return
    lines = raw_head.decode("latin-1", errors="replace").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 2:
        writer.close()
        return
    method, path_qs = parts[0].upper(), parts[1]
    if len(path_qs) > 8192:
        writer.write(b"HTTP/1.1 414 URI Too Long\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        return
    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()

    path_only = path_qs.split("?", 1)[0]
    if path_only == "/_cosmos_node" and hdrs.get("upgrade", "").lower() == "websocket":
        auth = hdrs.get("authorization", "")
        tok = auth[7:].strip() if auth.startswith("Bearer ") else ""
        if not hub.secret or not hmac.compare_digest(tok.encode(), hub.secret.encode()):
            writer.write(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 12\r\n\r\nUnauthorized")
            await writer.drain()
            writer.close()
            return
        ws_key = hdrs.get("sec-websocket-key", "")
        acc = base64.b64encode(hashlib.sha1((ws_key + WS_GUID).encode()).digest()).decode()
        writer.write(f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {acc}\r\n\r\n".encode())
        await writer.drain()
        if hub.node_writer is not None:
            try:
                hub.node_writer.close()
            except Exception:
                pass
            for pq in list(hub.pending.values()):
                try:
                    pq.put_nowait((FRAME_ERR_ABORT, b"node_reconnected"))
                except Exception:
                    pass
        hub.node_writer = writer
        try:
            while True:
                op, data = await read_ws_frame(reader)
                if op == 0x8:
                    break
                if op == 0x9:
                    writer.write(hub.pack_ws(data[:125], opcode=0xA))
                    await writer.drain()
                    continue
                if op == 0x2 and len(data) >= 17:
                    ft, rid, pl = data[0], data[1:17], data[17:]
                    q = hub.pending.get(rid)
                    if q is not None:
                        await q.put((ft, pl))
        except Exception:
            pass
        finally:
            if hub.node_writer is writer:
                hub.node_writer = None
                hub.last_drop = time.monotonic()
                for pq in list(hub.pending.values()):
                    try:
                        pq.put_nowait((FRAME_ERR_ABORT, b"node_disconnected"))
                    except Exception:
                        pass
            writer.close()
        return

    try:
        clen = int(hdrs.get("content-length") or 0)
    except ValueError:
        writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        return
    if clen < 0 or clen > MAX_HTTP_BODY_BYTES:
        writer.write(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        return
    body = await asyncio.wait_for(reader.readexactly(clen), timeout=30.0) if clen > 0 else b""

    if hub.node_writer is None:
        if path_only == "/healthz":
            resp_b = json.dumps({"ok": True, "status": "hub_online", "node_online": False}).encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(resp_b)).encode() + b"\r\n\r\n" + resp_b)
        else:
            rpc_id = None
            try:
                rpc_id = json.loads(body.decode("utf-8")).get("id")
            except Exception:
                pass
            offline_doc = {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {"code": -32001, "message": "ERR_NODE_OFFLINE: Local PC node is currently powered off or disconnected; VPS 24h MCP Hub is online."},
                "ok": False,
                "code": "ERR_NODE_OFFLINE",
            }
            resp_b = json.dumps(offline_doc).encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(resp_b)).encode() + b"\r\n\r\n" + resp_b)
        await writer.drain()
        writer.close()
        return

    rid = uuid.uuid4().bytes
    q = asyncio.Queue()
    hub.pending[rid] = q
    try:
        nw = hub.node_writer
        head_p = json.dumps({"method": method, "path_qs": path_qs, "headers": hdrs}).encode()
        nw.write(hub.pack_ws(bytes([FRAME_REQ_HEAD]) + rid + head_p))
        for off in range(0, len(body), 131072):
            nw.write(hub.pack_ws(bytes([FRAME_REQ_BODY]) + rid + body[off:off + 131072]))
        nw.write(hub.pack_ws(bytes([FRAME_REQ_END]) + rid))
        await nw.drain()

        while True:
            ft, pl = await asyncio.wait_for(q.get(), timeout=92.0)
            if ft == FRAME_ERR_ABORT:
                break
            if ft == FRAME_RES_HEAD:
                meta = json.loads(pl.decode("utf-8"))
                st = int(meta.get("status") or 200)
                out_h = [f"HTTP/1.1 {st} OK", "Transfer-Encoding: chunked"]
                for hk, hv in (meta.get("headers") or []):
                    if hk.lower() not in ("transfer-encoding", "content-length", "connection"):
                        out_h.append(f"{hk}: {hv}")
                out_h.extend(["Connection: close", "", ""])
                writer.write("\r\n".join(out_h).encode("latin-1", errors="replace"))
                await writer.drain()
            elif ft == FRAME_RES_BODY and pl:
                writer.write(f"{len(pl):x}\r\n".encode("ascii") + pl + b"\r\n")
                await writer.drain()
            elif ft == FRAME_RES_END:
                writer.write(b"0\r\n\r\n")
                await writer.drain()
                break
    except Exception:
        pass
    finally:
        hub.pending.pop(rid, None)
        writer.close()

async def _serve_stdlib_hub(host: str, port: int) -> None:
    hub = HubState(os.environ.get("COSMOS_NODE_SECRET", ""))
    srv = await asyncio.start_server(lambda r, w: handle_conn(hub, r, w), host, port)
    async with srv:
        await srv.serve_forever()

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18096)
    ap.add_argument("--state-root", "--state-dir", dest="state_root", default=os.environ.get("COSMOS_MCP_STATE_DIR", "/var/lib/cosmos-mcp/state"))
    args = ap.parse_args()
    if args.state_root:
        os.environ.setdefault("COSMOS_MCP_STATE_DIR", args.state_root)
        os.environ.setdefault("LOCALPC_MCP_STATE_DIR", args.state_root)
    if (
        os.environ.get("COSMOS_FORCE_STDLIB_HUB") != "1"
        and importlib.util.find_spec("cosmos_mcp.launcher.app") is not None
        and importlib.util.find_spec("uvicorn") is not None
    ):
        from cosmos_mcp.launcher.app import main as app_main
        argv_app = ["--host", args.host, "--port", str(args.port), "--state-dir", args.state_root, "--tunnel-mode", "vps_hub"]
        pub_env = (os.environ.get("COSMOS_PUBLIC_URL") or "").strip()
        if pub_env:
            argv_app.extend(["--public-url", pub_env])
        app_main(argv_app)
        return
    asyncio.run(_serve_stdlib_hub(args.host, args.port))

if __name__ == "__main__":
    main()
'''


class VpsWssNodeSupervisor(WorkersDevRelaySupervisor):
    """Registers the local PC as an outbound `:443 WSS` child node (`wss://<vps_host>/_cosmos_node`) on a 24h VPS Hub."""

    def __init__(
        self,
        vps_url: str,
        node_secret: str,
        local_port: int,
        state_root: Path,
        prefix: str = "pc",
        *,
        node_alias: str = "",
        workspace_roots: Sequence[Any] = (),
        device_label: str = "",
        ssl_context: Optional[ssl.SSLContext] = None,
        ping_interval_sec: float = 25.0,
        idle_timeout_sec: float = 45.0,
        backoff_schedule: Sequence[float] = (1.0, 2.0, 5.0, 15.0),
        max_workers: int = 16,
        local_timeout_sec: float = 95.0,
        route_watch_interval_sec: float = 1.0,
        egress_ip_probe: Optional[Callable[[], str]] = None,
        on_state_change: Optional[Callable[..., Any]] = None,
    ) -> None:
        st_root = Path(state_root).expanduser().resolve()
        eff_pref = _norm_prefix(prefix)
        eff_alias = (node_alias or eff_pref or "pc").strip().lower()

        cfg_roots: List[str] = [str(r).strip() for r in (workspace_roots or ()) if str(r).strip()]
        cfg_label = (device_label or "").strip()
        if not cfg_roots or not cfg_label:
            cfg_p = _service_cfg_path(st_root, eff_pref)
            if cfg_p.is_file():
                with contextlib.suppress(Exception):
                    doc = json.loads(cfg_p.read_text(encoding="utf-8-sig"))
                    if isinstance(doc, dict):
                        if not cfg_roots:
                            raw_r = doc.get("workspace_roots") or ([doc["workspace"]] if doc.get("workspace") else [])
                            cfg_roots = [str(x).strip() for x in raw_r if str(x).strip()]
                        if not cfg_label:
                            cfg_label = str(doc.get("device_label") or "").strip()

        drives: List[str] = []
        for ws_s in cfg_roots:
            m_drv = re.match(r"^([A-Za-z]:)(?:[\\/]|$)", ws_s)
            if m_drv:
                dl = m_drv.group(1).lower()
                if dl not in drives:
                    drives.append(dl)

        meta_b64 = base64.urlsafe_b64encode(
            json.dumps(
                {
                    "node_id": eff_alias,
                    "workspace_roots": cfg_roots,
                    "drives": drives,
                    "platform": sys.platform,
                    "device_label": cfg_label or eff_alias,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        ).decode("ascii")

        super().__init__(
            public_url=vps_url,
            tunnel_secret=node_secret,
            local_port=local_port,
            state_root=st_root,
            prefix=eff_pref,
            tunnel_endpoint_path="/_cosmos_node",
            extra_ws_headers={
                "X-Cosmos-Node-Alias": eff_alias,
                "X-Cosmos-Node-Meta": meta_b64,
            },
            ping_interval_sec=ping_interval_sec,
            idle_timeout_sec=idle_timeout_sec,
            backoff_schedule=backoff_schedule,
            max_workers=max_workers,
            local_timeout_sec=local_timeout_sec,
            route_watch_interval_sec=route_watch_interval_sec,
            ssl_context=ssl_context,
            egress_ip_probe=egress_ip_probe,
            on_state_change=on_state_change,
        )
        self.node_alias = eff_alias

    def _read_local_api_token(self) -> str:
        auth_p = self.state_root / "secrets" / "auth.json"
        if auth_p.is_file():
            with contextlib.suppress(Exception):
                doc = json.loads(auth_p.read_text(encoding="utf-8-sig"))
                if isinstance(doc, dict):
                    return str(doc.get("local_api_token") or "").strip()
        return ""

    def _execute_local_http(self, req_state: Any, body_bytes: bytes) -> None:
        if str(getattr(req_state, "path_qs", "") or "").startswith("/_cosmos_node/"):
            tok = self._read_local_api_token()
            cleaned = [
                (k, v)
                for (k, v) in req_state.headers
                if k.lower()
                not in (
                    "x-cosmos-via-tunnel",
                    "x-cosmos-public-prefix",
                    "x-cosmos-local-token",
                    "x-forwarded-host",
                    "x-forwarded-proto",
                    "forwarded",
                )
            ]
            if tok:
                cleaned.append(("X-Cosmos-Local-Token", tok))
            req_state.headers = cleaned
        super()._execute_local_http(req_state, body_bytes)


def _invoke_ssh_runner(
    runner_override: Optional[Callable[..., Any]],
    cmd: List[str],
    *,
    env: Dict[str, str],
    timeout: float,
    stage: str,
    stdin_script: Optional[str] = None,
) -> Tuple[int, str, str]:
    if runner_override is not None:
        sig = inspect.signature(runner_override)
        accepts_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
        kwargs: Dict[str, Any] = {}
        if accepts_var_kw or "env" in sig.parameters:
            kwargs["env"] = env
        if accepts_var_kw or "timeout" in sig.parameters:
            kwargs["timeout"] = timeout
        if accepts_var_kw or "stage" in sig.parameters:
            kwargs["stage"] = stage
        if stdin_script is not None and (accepts_var_kw or "stdin_script" in sig.parameters):
            kwargs["stdin_script"] = stdin_script
        raw_res = runner_override(cmd, **kwargs)
        if isinstance(raw_res, dict):
            return (
                int(raw_res.get("returncode", 0)),
                str(raw_res.get("stdout") or ""),
                str(raw_res.get("stderr") or ""),
            )
        if isinstance(raw_res, tuple) and len(raw_res) >= 2:
            rc = int(raw_res[0])
            out = str(raw_res[1] or "")
            err = str(raw_res[2] or "") if len(raw_res) >= 3 else ""
            return rc, out, err
        return (
            int(getattr(raw_res, "returncode", 0)),
            str(getattr(raw_res, "stdout", "") or ""),
            str(getattr(raw_res, "stderr", "") or ""),
        )

    eff_cmd = list(cmd)
    run_kwargs: Dict[str, Any] = {
        "env": env,
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": timeout,
        "creationflags": _popen_flags(),
        "check": False,
    }
    if stdin_script is not None:
        # Always pipe script/secret payload via SSH stdin so secrets never appear in OS command-line arguments
        eff_cmd[-1] = "python3 -B -"
        run_kwargs["input"] = stdin_script
    else:
        run_kwargs["stdin"] = subprocess.DEVNULL

    proc = subprocess.run(eff_cmd, **run_kwargs)
    return int(proc.returncode), str(proc.stdout or ""), str(proc.stderr or "")


def _probe_tcp_port_reachable(host: str, port: int, timeout_sec: float = 2.5) -> bool:
    with contextlib.suppress(OSError):
        with socket.create_connection((host, int(port)), timeout=timeout_sec):
            return True
    return False


def provision_vps_hub_oneclick(
    *,
    host: str,
    ssh_password: str = "",
    ssh_user: str = "root",
    ssh_port: int = 22,
    identity_file: str = "",
    custom_domain: str = "",
    local_port: int = 8096,
    state_root: Path,
    prefix: str = "pc",
    runner_override: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    """
    1-minute windowless VPS provisioner:
    1) Zero-popup `SSH_ASKPASS` key planting (2-line env-ref script, zero plaintext password on disk, shredded on exit).
    2) 3-second preflight: `MemTotal < 256MB` -> auto 512MB `/swapfile`, Mainland China ICP `:443` warning, `:80/:443` probe.
    3) Caddy v2.11+ deployment (`default_sni <IP>`, `/var/lib/cosmos-mcp/caddy`, `shortlived` IP cert + `sslip.io` fallback).
    4) 24h systemd Cosmos MCP Hub (`ERR_NODE_OFFLINE` when PC is off, zero `502`) + `:443 WSS` child-node credentials.
    """
    clean_host = (host or "").strip()
    if "://" in clean_host:
        clean_host = (urlsplit(clean_host).hostname or clean_host).strip()
    if "@" in clean_host and ssh_user == "root":
        u_part, h_part = clean_host.rsplit("@", 1)
        if u_part.strip() and h_part.strip():
            ssh_user = u_part.strip()
            clean_host = h_part.strip()
    clean_user = (ssh_user or "root").strip() or "root"
    if not clean_host:
        return {"ok": False, "error": "missing_vps_host", "message": "请填写云服务器公网 IP 或主机名。"}

    st_root = Path(state_root).expanduser().resolve()
    eff_prefix = _norm_prefix(prefix)
    ssh_bin = shutil.which("ssh") or "ssh"

    if identity_file and Path(identity_file).expanduser().is_file():
        priv_key_path = Path(identity_file).expanduser().resolve()
        pub_candidate = Path(str(priv_key_path) + ".pub")
        pub_key_line = (
            pub_candidate.read_text(encoding="utf-8", errors="replace").strip()
            if pub_candidate.is_file()
            else ""
        )
    else:
        priv_key_path, pub_key_line = ensure_vps_ssh_keypair(st_root, prefix=eff_prefix)

    base_env = dict(os.environ)
    base_env["PYTHONDONTWRITEBYTECODE"] = "1"
    base_env["PYTHONUTF8"] = "1"

    # Step 1: Windowless non-interactive `SSH_ASKPASS` key installation when `ssh_password` is provided
    if ssh_password:
        if not pub_key_line:
            priv_key_path, pub_key_line = ensure_vps_ssh_keypair(st_root, prefix=eff_prefix)
        sec_dir = st_root / "secrets"
        sec_dir.mkdir(parents=True, exist_ok=True)
        ext = ".cmd" if sys.platform == "win32" else ".sh"
        askpass_path = sec_dir / f".cosmos_askpass_{secrets.token_hex(6)}{ext}"
        try:
            if sys.platform == "win32":
                # Safe Python-stdio env reader (handles `&|^%"!` in passwords with zero disk plaintext!)
                py_con = resolve_console_python(sys.executable)
                askpass_body = (
                    '@echo off\r\n"'
                    + str(py_con)
                    + '" -B -c "import os,sys;sys.stdout.write(os.environ.get(\'COSMOS_SSH_PASS\',\'\')+\'\\n\')"\r\n'
                )
            else:
                askpass_body = "#!/bin/sh\nprintf '%s\\n' \"$COSMOS_SSH_PASS\"\n"
            atomic_write_text(askpass_path, askpass_body, mode_override=0o700)
            if sys.platform != "win32":
                with contextlib.suppress(OSError):
                    os.chmod(askpass_path, 0o700)

            ask_env = dict(base_env)
            ask_env["COSMOS_SSH_PASS"] = ssh_password
            ask_env["SSH_ASKPASS"] = str(askpass_path)
            ask_env["SSH_ASKPASS_REQUIRE"] = "force"
            ask_env["DISPLAY"] = "127.0.0.1:0"

            pub_b64 = base64.b64encode(pub_key_line.encode("utf-8")).decode("ascii")
            install_key_remote = (
                f"umask 077 && mkdir -p ~/.ssh && "
                f"PUB=$(printf '%s' '{pub_b64}' | base64 -d) && "
                f"(grep -qxF \"$PUB\" ~/.ssh/authorized_keys 2>/dev/null || printf '%s\\n' \"$PUB\" >> ~/.ssh/authorized_keys)"
            )
            ask_cmd = [
                ssh_bin,
                "-T",
                "-p",
                str(int(ssh_port)),
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                "ConnectTimeout=12",
                "-o",
                "PubkeyAuthentication=no",
                "-o",
                "PreferredAuthentications=password,keyboard-interactive",
                "-o",
                "NumberOfPasswordPrompts=1",
                f"{clean_user}@{clean_host}",
                install_key_remote,
            ]
            rc_key, _, err_key = _invoke_ssh_runner(
                runner_override,
                ask_cmd,
                env=ask_env,
                timeout=25.0,
                stage="install_ssh_key",
            )
            if rc_key != 0:
                return {
                    "ok": False,
                    "step": "install_ssh_key",
                    "error": "ssh_auth_failed",
                    "message": f"SSH 免密公钥植入失败 (rc={rc_key}): {err_key.strip()[:240]}",
                }
        finally:
            _shred_temp_file(askpass_path)

    ssh_key_base_cmd = [
        ssh_bin,
        "-T",
        *VPS_SSH_MANDATORY_OPTIONS,
        "-p",
        str(int(ssh_port)),
        "-i",
        str(priv_key_path),
        f"{clean_user}@{clean_host}",
    ]

    # Step 2: First-3-second server preflight (auto 512MB swap if MemTotal < 256MB, cloud/ICP detect, :80/:443 probe)
    preflight_py = (
        "import json, os, socket, subprocess, urllib.request\n"
        "mem_kb = 0\n"
        "try:\n"
        "    for ln in open('/proc/meminfo'):\n"
        "        if ln.startswith('MemTotal:'):\n"
        "            mem_kb = int(ln.split()[1])\n"
        "except Exception:\n"
        "    mem_kb = 1048576\n"
        "swap_created = False\n"
        "if 0 < mem_kb < 262144 and not os.path.exists('/swapfile'):\n"
        "    rc = os.system('(fallocate -l 512M /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=512 status=none) && chmod 600 /swapfile && mkswap /swapfile >/dev/null 2>&1 && swapon /swapfile')\n"
        "    swap_created = (rc == 0)\n"
        "def _mget(url, hdrs=None):\n"
        "    try:\n"
        "        req = urllib.request.Request(url, headers=hdrs or {})\n"
        "        with urllib.request.urlopen(req, timeout=0.8) as r:\n"
        "            return r.read().decode('utf-8', 'replace').strip()\n"
        "    except Exception:\n"
        "        return ''\n"
        "prov, reg, pub_ip = 'generic', '', ''\n"
        "ali_reg = _mget('http://100.100.100.200/latest/meta-data/region-id')\n"
        "if ali_reg:\n"
        "    prov, reg = 'aliyun', ali_reg\n"
        "    pub_ip = _mget('http://100.100.100.200/latest/meta-data/eipv4') or _mget('http://100.100.100.200/latest/meta-data/public-ipv4')\n"
        "if not reg:\n"
        "    tc_reg = _mget('http://metadata.tencentyun.com/latest/meta-data/placement/region')\n"
        "    if tc_reg:\n"
        "        prov, reg = 'tencent', tc_reg\n"
        "        pub_ip = _mget('http://metadata.tencentyun.com/latest/meta-data/public-ipv4')\n"
        "if not reg:\n"
        "    opc = _mget('http://169.254.169.254/opc/v2/instance/regionCanonicalName', {'Authorization': 'Bearer Oracle'})\n"
        "    if opc:\n"
        "        prov, reg = 'oracle', opc\n"
        "if not reg:\n"
        "    aws_az = _mget('http://169.254.169.254/latest/meta-data/placement/availability-zone')\n"
        "    if aws_az:\n"
        "        prov, reg = 'aws', aws_az[:-1]\n"
        "        pub_ip = _mget('http://169.254.169.254/latest/meta-data/public-ipv4')\n"
        "print(json.dumps({'mem_kb': mem_kb, 'swap_created': swap_created, 'cloud_provider': prov, 'region': reg, 'public_ip': pub_ip}))\n"
    )
    preflight_b64 = base64.b64encode(preflight_py.encode("utf-8")).decode("ascii")
    rc_pre, out_pre, err_pre = _invoke_ssh_runner(
        runner_override,
        [*ssh_key_base_cmd, f"python3 -B -c \"import base64;exec(base64.b64decode('{preflight_b64}'))\""],
        env=base_env,
        timeout=25.0,
        stage="preflight",
    )
    if rc_pre != 0:
        return {
            "ok": False,
            "step": "preflight",
            "error": "vps_preflight_failed",
            "message": f"服务器环境体检连接失败 (rc={rc_pre}): {err_pre.strip()[:240]}",
        }

    pre_doc: Dict[str, Any] = {}
    for line in reversed(out_pre.strip().splitlines()):
        with contextlib.suppress(Exception):
            parsed_ln = json.loads(line.strip())
            if isinstance(parsed_ln, dict):
                pre_doc = parsed_ln
                break

    cloud_provider = str(pre_doc.get("cloud_provider") or "generic").strip().lower()
    region = str(pre_doc.get("region") or "").strip().lower()
    swap_created = bool(pre_doc.get("swap_created", False))
    mem_kb = int(pre_doc.get("mem_kb") or 0)

    detected_ip = str(pre_doc.get("public_ip") or "").strip()
    if not detected_ip:
        with contextlib.suppress(ValueError):
            ipaddress.ip_address(clean_host)
            detected_ip = clean_host
    if not detected_ip and runner_override is None:
        with contextlib.suppress(OSError):
            detected_ip = str(socket.getaddrinfo(clean_host, 443, type=socket.SOCK_STREAM)[0][4][0])
    public_ip = detected_ip or clean_host

    is_mainland_china = bool(
        pre_doc.get("is_mainland_china")
        or (region and _MAINLAND_CN_REGION_RE.match(region))
    )
    warnings: List[str] = []
    if is_mainland_china:
        warnings.append(
            f"检测到中国内地机房 ({cloud_provider}:{region or 'cn'})：未完成 ICP 备案的裸 IP 或域名在 :80/:443 端口可能被运营商或云安全中心阻断；"
            "建议使用中国香港/新加坡/东京等免备案地域，或绑定已完成备案的自有域名。"
        )

    # Bidirectional :80/:443 check
    blocked_ports: List[int] = []
    if "port_80_ok" in pre_doc or "port_443_ok" in pre_doc:
        if not bool(pre_doc.get("port_80_ok", True)):
            blocked_ports.append(80)
        if not bool(pre_doc.get("port_443_ok", True)):
            blocked_ports.append(443)
    elif runner_override is None:
        # Spin transient 3s remote socket binder on unbound 80/443 and probe from local machine
        probe_srv_py = (
            "import socket, time, threading\n"
            "socks = []\n"
            "for p in (80, 443):\n"
            "    try:\n"
            "        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "        s.bind(('0.0.0.0', p)); s.listen(4); socks.append(s)\n"
            "    except OSError:\n"
            "        pass\n"
            "print('READY', flush=True)\n"
            "time.sleep(2.8)\n"
            "for s in socks: s.close()\n"
        )
        pb64 = base64.b64encode(probe_srv_py.encode("utf-8")).decode("ascii")
        proc_bind = subprocess.Popen(
            [*ssh_key_base_cmd, f"python3 -B -c \"import base64;exec(base64.b64decode('{pb64}'))\""],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            creationflags=_popen_flags(),
        )
        try:
            if proc_bind.stdout is not None:
                proc_bind.stdout.readline()
            for p_num in (80, 443):
                if not _probe_tcp_port_reachable(clean_host, p_num, timeout_sec=2.2):
                    blocked_ports.append(p_num)
        finally:
            with contextlib.suppress(Exception):
                proc_bind.wait(timeout=4.0)

    if blocked_ports:
        return {
            "ok": False,
            "step": "preflight_ports",
            "error": "ports_blocked_by_security_group",
            "blocked_ports": blocked_ports,
            "cloud_provider": cloud_provider,
            "region": region,
            "is_mainland_china": is_mainland_china,
            "firewall_guide": get_cloud_firewall_guide(cloud_provider, blocked_ports),
            "warnings": warnings,
        }

    # Step 3 & 4: Deploy Caddy v2.11+ (`default_sni` + `/var/lib/cosmos-mcp/caddy` + dual cert) & 24h 16-tool Resident Hub
    clean_dom = (custom_domain or "").strip().lower()
    if "://" in clean_dom:
        clean_dom = (urlsplit(clean_dom).hostname or clean_dom).strip().lower()
    clean_dom = clean_dom.strip("/")

    ip_url_host = f"[{public_ip}]" if (":" in public_ip and not public_ip.startswith("[")) else public_ip
    primary_url = f"https://{clean_dom}" if clean_dom else f"https://{ip_url_host}"
    fallback_sslip_url = "" if clean_dom else f"https://{ip_to_sslip_domain(public_ip)}"
    sslip_only_snippet = (
        ""
        if clean_dom
        else build_vps_hub_caddy_site_snippet(
            public_ip,
            custom_domain=ip_to_sslip_domain(public_ip),
            hub_port=18096,
        )
    )

    node_secret = load_or_create_vps_node_secret(st_root, prefix=eff_prefix)
    auth_json_path = st_root / "secrets" / "auth.json"
    auth_doc_local: Optional[Dict[str, Any]] = None
    if auth_json_path.is_file():
        with contextlib.suppress(Exception):
            loaded_auth = json.loads(auth_json_path.read_text(encoding="utf-8-sig"))
            if (
                isinstance(loaded_auth, dict)
                and str(loaded_auth.get("password_hash") or "").strip()
                and str(loaded_auth.get("salt") or "").strip()
            ):
                auth_doc_local = loaded_auth
    if auth_doc_local is None:
        from cosmos_mcp.core.config import ensure_initialized

        ensure_initialized(
            product_root=st_root,
            port=int(local_port),
            cli_state_dir=str(st_root),
            prefix=eff_prefix,
        )
        loaded_after = json.loads(auth_json_path.read_text(encoding="utf-8-sig"))
        auth_doc_local = loaded_after if isinstance(loaded_after, dict) else {}

    auth_json_bytes = (json.dumps(auth_doc_local, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    node_secret_bytes = (node_secret + "\n").encode("utf-8")
    sec_tar_buf = io.BytesIO()
    with tarfile.open(fileobj=sec_tar_buf, mode="w:gz", compresslevel=9) as sec_tf:
        for arc_name, payload_bytes in (
            ("secrets/auth.json", auth_json_bytes),
            ("secrets/vps_node_secret.txt", node_secret_bytes),
        ):
            ti_sec = tarfile.TarInfo(name=arc_name)
            ti_sec.size = len(payload_bytes)
            ti_sec.mtime = 1764115200
            ti_sec.mode = 0o600
            sec_tf.addfile(ti_sec, io.BytesIO(payload_bytes))
    secrets_tar_gz_b64 = base64.b64encode(sec_tar_buf.getvalue()).decode("ascii")

    src_tar_gz_b64 = build_cosmos_mcp_source_tar_gz_b64()
    caddyfile_txt = build_vps_hub_caddyfile(
        public_ip,
        custom_domain=clean_dom,
        hub_port=18096,
        cert_storage_dir="/var/lib/cosmos-mcp/caddy",
    )
    caddy_snippet_txt = build_vps_hub_caddy_site_snippet(
        public_ip,
        custom_domain=clean_dom,
        hub_port=18096,
    )
    systemd_txt = build_vps_hub_systemd_unit(
        hub_dir="/opt/cosmos-mcp-hub",
        env_file="/etc/cosmos-mcp/hub.env",
        hub_port=18096,
        state_root="/var/lib/cosmos-mcp/state",
    )
    env_file_txt = (
        f"COSMOS_NODE_SECRET={node_secret}\n"
        f"COSMOS_PUBLIC_URL={primary_url}\n"
        f"LOCALPC_PUBLIC_URL={primary_url}\n"
        "COSMOS_MCP_STATE_DIR=/var/lib/cosmos-mcp/state\n"
        "LOCALPC_MCP_STATE_DIR=/var/lib/cosmos-mcp/state\n"
        "COSMOS_TUNNEL_MODE=vps_hub\n"
        "PYTHONPATH=/opt/cosmos-mcp-hub/src\n"
    )

    bundle_b64 = base64.b64encode(
        json.dumps(
            {
                "caddyfile": caddyfile_txt,
                "caddy_snippet": caddy_snippet_txt,
                "sslip_only_snippet": sslip_only_snippet,
                "public_ip": public_ip,
                "clean_domain": clean_dom,
                "primary_url": primary_url,
                "node_secret": node_secret,
                "secrets_tar_gz_b64": secrets_tar_gz_b64,
                "systemd_unit": systemd_txt,
                "hub_py": VPS_RESIDENT_HUB_PY,
                "env_file": env_file_txt,
                "src_tar_gz_b64": src_tar_gz_b64,
            }
        ).encode("utf-8")
    ).decode("ascii")

    deploy_remote_py = (
        "import base64, inspect, io, json, os, pathlib, platform, re, shutil, subprocess, sys, tarfile, urllib.request\n"
        f"b = json.loads(base64.b64decode('{bundle_b64}').decode('utf-8'))\n"
        "for d in ('/opt/cosmos-mcp-hub/src', '/opt/cosmos-mcp-hub/workspace', '/etc/cosmos-mcp', '/var/lib/cosmos-mcp/caddy', '/var/lib/cosmos-mcp/state/config', '/var/lib/cosmos-mcp/state/secrets', '/etc/caddy', '/etc/systemd/system'):\n"
        "    pathlib.Path(d).mkdir(parents=True, exist_ok=True)\n"
        "os.chmod('/var/lib/cosmos-mcp/state/secrets', 0o700)\n"
        "pkg_dst = pathlib.Path('/opt/cosmos-mcp-hub/src/cosmos_mcp')\n"
        "if pkg_dst.exists():\n"
        "    shutil.rmtree(pkg_dst, ignore_errors=True)\n"
        "with tarfile.open(fileobj=io.BytesIO(base64.b64decode(b['src_tar_gz_b64'])), mode='r:gz') as tf:\n"
        "    if 'filter' in inspect.signature(tf.extractall).parameters:\n"
        "        tf.extractall('/opt/cosmos-mcp-hub/src', filter='data')\n"
        "    else:\n"
        "        tf.extractall('/opt/cosmos-mcp-hub/src')\n"
        "app_py_p = pkg_dst / 'launcher' / 'app.py'\n"
        "if app_py_p.is_file():\n"
        "    app_txt = app_py_p.read_text(encoding='utf-8', errors='replace')\n"
        "    orig_app_txt = app_txt\n"
        "    if '\"--state-root\"' not in app_txt and \"'--state-root'\" not in app_txt:\n"
        "        app_txt = app_txt.replace('\"--state-dir\",', '\"--state-dir\", \"--state-root\",', 1)\n"
        "        app_txt = app_txt.replace('state_dir=args.state_dir', 'state_dir=(args.state_dir or getattr(args, \"state_root\", \"\"))')\n"
        "    if 'COSMOS_PUBLIC_URL' not in app_txt:\n"
        "        app_txt = app_txt.replace('public_url=args.public_url', 'public_url=(args.public_url or os.environ.get(\"COSMOS_PUBLIC_URL\", \"\"))')\n"
        "    if app_txt != orig_app_txt:\n"
        "        app_py_p.write_text(app_txt, encoding='utf-8')\n"
        "pathlib.Path('/opt/cosmos-mcp-hub/hub_gateway.py').write_text(b['hub_py'], encoding='utf-8')\n"
        "old_umask = os.umask(0o077)\n"
        "try:\n"
        "    env_p = pathlib.Path('/etc/cosmos-mcp/hub.env')\n"
        "    env_p.write_text(b['env_file'], encoding='utf-8')\n"
        "    os.chmod(env_p, 0o600)\n"
        "    with tarfile.open(fileobj=io.BytesIO(base64.b64decode(b['secrets_tar_gz_b64'])), mode='r:gz') as stf:\n"
        "        if 'filter' in inspect.signature(stf.extractall).parameters:\n"
        "            stf.extractall('/var/lib/cosmos-mcp/state', filter='data')\n"
        "        else:\n"
        "            stf.extractall('/var/lib/cosmos-mcp/state')\n"
        "    for s_rel in ('auth.json', 'vps_node_secret.txt'):\n"
        "        sp = pathlib.Path('/var/lib/cosmos-mcp/state/secrets') / s_rel\n"
        "        if sp.is_file():\n"
        "            os.chmod(sp, 0o600)\n"
        "finally:\n"
        "    os.umask(old_umask)\n"
        "svc_cfg_p = pathlib.Path('/var/lib/cosmos-mcp/state/config/service.json')\n"
        "svc_doc = {}\n"
        "if svc_cfg_p.is_file():\n"
        "    try: svc_doc = json.loads(svc_cfg_p.read_text(encoding='utf-8'))\n"
        "    except Exception: svc_doc = {}\n"
        "svc_doc.setdefault('host', '127.0.0.1')\n"
        "svc_doc.setdefault('port', 18096)\n"
        "svc_doc.setdefault('workspace', '/opt/cosmos-mcp-hub/workspace')\n"
        "svc_doc.setdefault('workspace_roots', ['/opt/cosmos-mcp-hub/workspace'])\n"
        "svc_doc['public_base'] = b['primary_url']\n"
        "svc_doc['public_base_url'] = b['primary_url']\n"
        "svc_doc['tunnel_mode'] = 'vps_hub'\n"
        "svc_doc['vps_hub_mode'] = True\n"
        "svc_doc['vps_hub_url'] = b['primary_url']\n"
        "svc_doc.pop('vps_node_secret', None)\n"
        "svc_cfg_p.write_text(json.dumps(svc_doc, ensure_ascii=False, indent=2) + '\\n', encoding='utf-8')\n"
        "venv_py = pathlib.Path('/opt/cosmos-mcp-hub/venv/bin/python')\n"
        "if not venv_py.is_file():\n"
        "    subprocess.run([sys.executable, '-m', 'venv', '--system-site-packages', '/opt/cosmos-mcp-hub/venv'], stdin=subprocess.DEVNULL, capture_output=True, check=False)\n"
        "if not venv_py.is_file() and shutil.which('apt-get'):\n"
        "    os.system('apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv python3-pip >/dev/null 2>&1')\n"
        "    subprocess.run([sys.executable, '-m', 'venv', '--system-site-packages', '/opt/cosmos-mcp-hub/venv'], stdin=subprocess.DEVNULL, capture_output=True, check=False)\n"
        "if venv_py.is_file():\n"
        "    chk_code = (\n"
        "        'import importlib.metadata as m, uvicorn, websockets, starlette, mcp, pydantic, anyio, httpx, cryptography, multipart, PIL, pypdf, openpyxl, docx, pptx; '\n"
        "        'v_mcp = tuple(int(x) for x in m.version(\"mcp\").split(\".\")[:2] if x.isdigit()); '\n"
        "        'v_pyd = tuple(int(x) for x in m.version(\"pydantic\").split(\".\")[:2] if x.isdigit()); '\n"
        "        'raise SystemExit(0 if (v_mcp >= (1, 30) and v_pyd >= (2, 11)) else 1)'\n"
        "    )\n"
        "    chk_imp = subprocess.run([str(venv_py), '-c', chk_code], stdin=subprocess.DEVNULL, capture_output=True, check=False)\n"
        "    if chk_imp.returncode != 0:\n"
        "        if subprocess.run([str(venv_py), '-m', 'pip', '--version'], stdin=subprocess.DEVNULL, capture_output=True, check=False).returncode != 0:\n"
        "            subprocess.run([str(venv_py), '-m', 'ensurepip', '--upgrade'], stdin=subprocess.DEVNULL, capture_output=True, check=False)\n"
        "        core_pip_pkgs = [\n"
        "            'mcp>=1.30.0,<2.0.0',\n"
        "            \"starlette>=0.47.2; python_version < '3.14'\",\n"
        "            \"starlette>=1.3.1; python_version >= '3.14'\",\n"
        "            'uvicorn>=0.35.0',\n"
        "            'h11>=0.16.0',\n"
        "            'websockets>=15.0.1',\n"
        "            'cryptography>=46.0.7',\n"
        "            \"pydantic>=2.11.0,<3.0.0; python_version < '3.14'\",\n"
        "            \"pydantic>=2.12.0,<3.0.0; python_version >= '3.14'\",\n"
        "            'python-multipart>=0.0.20',\n"
        "            'anyio',\n"
        "            'httpx>=0.28.1',\n"
        "        ]\n"
        "        doc_pip_pkgs = [\n"
        "            'Pillow>=10.0.0',\n"
        "            'pypdf>=6.0.0',\n"
        "            'openpyxl>=3.1.5',\n"
        "            'python-docx>=1.2.0',\n"
        "            'python-pptx>=1.0.2',\n"
        "        ]\n"
        "        pip_pkgs = [*core_pip_pkgs, *doc_pip_pkgs]\n"
        "        r_pip = subprocess.run([str(venv_py), '-m', 'pip', 'install', '--quiet', '--disable-pip-version-check', *pip_pkgs], stdin=subprocess.DEVNULL, capture_output=True, timeout=110, check=False)\n"
        "        if r_pip.returncode != 0:\n"
        "            subprocess.run([str(venv_py), '-m', 'pip', 'install', '--quiet', '--disable-pip-version-check', *core_pip_pkgs], stdin=subprocess.DEVNULL, capture_output=True, timeout=85, check=False)\n"
        "pathlib.Path('/etc/systemd/system/cosmos-mcp-hub.service').write_text(b['systemd_unit'], encoding='utf-8')\n"
        "def _caddy_ver_ok():\n"
        "    cb = shutil.which('caddy')\n"
        "    if not cb: return False\n"
        "    try:\n"
        "        r = subprocess.run([cb, 'version'], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5)\n"
        "        m = re.search(r'v?(\\d+)\\.(\\d+)', r.stdout or '')\n"
        "        return bool(m and (int(m.group(1)), int(m.group(2))) >= (2, 11))\n"
        "    except Exception:\n"
        "        return False\n"
        "if not _caddy_ver_ok() and shutil.which('apt-get'):\n"
        "    os.system('apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl >/dev/null 2>&1 && '\n"
        "              'curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg && '\n"
        "              'curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list && '\n"
        "              'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq caddy >/dev/null 2>&1')\n"
        "if not _caddy_ver_ok() and shutil.which('dnf'):\n"
        "    os.system(\"dnf install -y -q 'dnf-command(copr)' >/dev/null 2>&1; dnf copr enable -y -q @caddy/caddy >/dev/null 2>&1; dnf install -y -q caddy >/dev/null 2>&1\")\n"
        "if not _caddy_ver_ok() and shutil.which('yum'):\n"
        "    os.system('yum install -y -q yum-plugin-copr >/dev/null 2>&1; yum copr enable -y -q @caddy/caddy >/dev/null 2>&1; yum install -y -q caddy >/dev/null 2>&1')\n"
        "if not _caddy_ver_ok():\n"
        "    mach = platform.machine().lower()\n"
        "    arch = 'arm64' if mach in ('aarch64', 'arm64') else ('amd64' if mach in ('x86_64', 'amd64') else '')\n"
        "    if arch:\n"
        "        dl_u = 'https://' + 'caddyserver.com/api/download?os=linux&arch=' + arch\n"
        "        dest_c = pathlib.Path('/usr/local/bin/caddy')\n"
        "        tmp_c = pathlib.Path('/usr/local/bin/.caddy.cosmos.tmp')\n"
        "        dest_c.parent.mkdir(parents=True, exist_ok=True)\n"
        "        max_c_bytes = 160 * 1024 * 1024\n"
        "        c_buf = bytearray()\n"
        "        with urllib.request.urlopen(dl_u, timeout=45) as r_dl:\n"
        "            while True:\n"
        "                ch_c = r_dl.read(65536)\n"
        "                if not ch_c:\n"
        "                    break\n"
        "                c_buf.extend(ch_c)\n"
        "                if len(c_buf) > max_c_bytes:\n"
        "                    raise RuntimeError('caddy download exceeded 160 MiB limit')\n"
        "        if len(c_buf) < 4 or bytes(c_buf[:4]) != b'\\x7fELF':\n"
        "            raise RuntimeError('caddy download did not return a valid Linux ELF binary')\n"
        "        tmp_c.write_bytes(bytes(c_buf))\n"
        "        os.chmod(tmp_c, 0o755)\n"
        "        os.replace(tmp_c, dest_c)\n"
        "        if not pathlib.Path('/usr/bin/caddy').exists():\n"
        "            try: os.symlink(str(dest_c), '/usr/bin/caddy')\n"
        "            except OSError: shutil.copy2(dest_c, '/usr/bin/caddy')\n"
        "        if not pathlib.Path('/etc/systemd/system/caddy.service').exists() and not pathlib.Path('/lib/systemd/system/caddy.service').exists():\n"
        "            pathlib.Path('/etc/systemd/system/caddy.service').write_text(\n"
        "                '[Unit]\\nDescription=Caddy\\nAfter=network.target network-online.target\\nRequires=network-online.target\\n\\n'\n"
        "                '[Service]\\nType=notify\\nExecStart=/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile\\n'\n"
        "                'ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --force\\n'\n"
        "                'TimeoutStopSec=5s\\nLimitNOFILE=1048576\\nPrivateTmp=true\\n\\n[Install]\\nWantedBy=multi-user.target\\n',\n"
        "                encoding='utf-8',\n"
        "            )\n"
        "os.system('chown -R caddy:caddy /var/lib/cosmos-mcp/caddy 2>/dev/null || true')\n"
        "def _strip_cf_cmt(ln):\n"
        "    iq, esc, out = False, False, []\n"
        "    for i, ch in enumerate(ln):\n"
        "        if esc: out.append(ch); esc = False; continue\n"
        "        if ch == '\\\\': out.append(ch); esc = True; continue\n"
        "        if ch == '\"': iq = not iq; out.append(ch); continue\n"
        "        if ch == '#' and not iq and (i == 0 or ln[i - 1].isspace()): break\n"
        "        out.append(ch)\n"
        "    return ''.join(out)\n"
        "def _ensure_global_default_sni(raw, ip_s):\n"
        "    if not ip_s: return raw\n"
        "    lns = raw.splitlines(keepends=True)\n"
        "    f_idx = next((idx for idx, ln in enumerate(lns) if _strip_cf_cmt(ln).strip()), None)\n"
        "    if f_idx is None:\n"
        "        return '{\\n    default_sni ' + ip_s + '\\n}\\n' + raw\n"
        "    fa = _strip_cf_cmt(lns[f_idx]).strip()\n"
        "    if fa.startswith('{') and not fa.startswith('{$') and fa.endswith('}'):\n"
        "        if re.search(r'\\bdefault_sni\\b', fa): return raw\n"
        "        inner = fa[1:-1].strip()\n"
        "        lns[f_idx] = ('{\\n    default_sni ' + ip_s + '\\n    ' + inner + '\\n}\\n') if inner else ('{\\n    default_sni ' + ip_s + '\\n}\\n')\n"
        "        return ''.join(lns)\n"
        "    if fa == '{':\n"
        "        dp, e_idx = 0, len(lns) - 1\n"
        "        for i in range(f_idx, len(lns)):\n"
        "            cp = _strip_cf_cmt(lns[i])\n"
        "            dp += cp.count('{') - cp.count('}')\n"
        "            if dp <= 0: e_idx = i; break\n"
        "        if any(re.match(r'^\\s*default_sni\\b', _strip_cf_cmt(lns[i])) for i in range(f_idx, e_idx + 1)): return raw\n"
        "        lns.insert(f_idx + 1, '    default_sni ' + ip_s + '\\n')\n"
        "        return ''.join(lns)\n"
        "    return '{\\n    default_sni ' + ip_s + '\\n}\\n\\n' + raw\n"
        "cf_main = pathlib.Path('/etc/caddy/Caddyfile')\n"
        "cf_bak = pathlib.Path('/etc/caddy/Caddyfile.cosmos.bak')\n"
        "cf_snip = pathlib.Path('/etc/caddy/cosmos-mcp.caddy')\n"
        "marker = '# Managed by Cosmos MCP Hub'\n"
        "imp_ln = 'import /etc/caddy/cosmos-mcp.caddy'\n"
        "use_primary = not cf_main.is_file()\n"
        "orig_ex_txt = cf_main.read_text(encoding='utf-8', errors='replace') if not use_primary else ''\n"
        "if not use_primary:\n"
        "    act = [x.strip() for x in orig_ex_txt.splitlines() if x.strip() and not x.strip().startswith('#')]\n"
        "    joined = '\\n'.join(act)\n"
        "    if not act or marker in orig_ex_txt or (':80' in joined and '/usr/share/caddy' in joined and 'reverse_proxy' not in joined and 'php_fastcgi' not in joined and 'import ' not in joined):\n"
        "        use_primary = True\n"
        "if use_primary:\n"
        "    cf_main.write_text(b['caddyfile'], encoding='utf-8')\n"
        "else:\n"
        "    if not cf_bak.is_file():\n"
        "        cf_bak.write_text(orig_ex_txt, encoding='utf-8')\n"
        "    cf_snip.write_text(marker + '\\n' + b['caddy_snippet'], encoding='utf-8')\n"
        "    upd_txt = _ensure_global_default_sni(orig_ex_txt, b['public_ip']) if not b.get('clean_domain') else orig_ex_txt\n"
        "    if not any(_strip_cf_cmt(x).strip() == imp_ln for x in upd_txt.splitlines()):\n"
        "        sep = '' if upd_txt.endswith('\\n') else '\\n'\n"
        "        upd_txt = upd_txt + sep + '\\n' + imp_ln + '\\n'\n"
        "    if upd_txt != orig_ex_txt:\n"
        "        cf_main.write_text(upd_txt, encoding='utf-8')\n"
        "    caddy_bin = shutil.which('caddy')\n"
        "    if caddy_bin and not b.get('clean_domain') and b.get('sslip_only_snippet'):\n"
        "        v_res = subprocess.run([caddy_bin, 'validate', '--config', '/etc/caddy/Caddyfile'], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15, check=False)\n"
        "        if v_res.returncode != 0:\n"
        "            cf_snip.write_text(marker + '\\n' + b['sslip_only_snippet'], encoding='utf-8')\n"
        "subprocess.run(['systemctl', 'daemon-reload'], stdin=subprocess.DEVNULL, check=False)\n"
        "subprocess.run(['systemctl', 'enable', '--now', 'cosmos-mcp-hub.service'], stdin=subprocess.DEVNULL, check=True)\n"
        "subprocess.run(['systemctl', 'restart', 'cosmos-mcp-hub.service'], stdin=subprocess.DEVNULL, check=True)\n"
        "subprocess.run(['systemctl', 'enable', '--now', 'caddy'], stdin=subprocess.DEVNULL, check=True)\n"
        "subprocess.run(['systemctl', 'reload-or-restart', 'caddy'], stdin=subprocess.DEVNULL, check=True)\n"
        "print('DEPLOY_OK')\n"
    )
    rc_dep, out_dep, err_dep = _invoke_ssh_runner(
        runner_override,
        [*ssh_key_base_cmd, "python3 -B -"],
        env=base_env,
        timeout=180.0,
        stage="deploy_hub_and_caddy",
        stdin_script=deploy_remote_py,
    )
    if rc_dep != 0 or "DEPLOY_OK" not in out_dep:
        return {
            "ok": False,
            "step": "deploy_hub_and_caddy",
            "error": "vps_hub_deploy_failed",
            "message": f"部署 24h MCP 主站与 Caddy 失败 (rc={rc_dep}): {(err_dep or out_dep).strip()[:300]}",
            "warnings": warnings,
        }

    hot_refresh_public_url(
        st_root,
        primary_url,
        port=int(local_port),
        prefix=eff_prefix,
        tunnel_mode="vps_hub",
        gateway_id="self_hosted",
    )
    with contextlib.suppress(Exception):
        cfg_p = _service_cfg_path(st_root, eff_prefix)
        if cfg_p.is_file():
            cfg_doc = json.loads(cfg_p.read_text(encoding="utf-8-sig"))
            if isinstance(cfg_doc, dict):
                gws_v, sel_v = normalize_gateways_config(cfg_doc)
                other_active_v = any(
                    gid != "self_hosted"
                    and bool(gws_v.get(gid, {}).get("enabled"))
                    and bool(str(gws_v.get(gid, {}).get("public_url") or "").strip())
                    for gid in gws_v
                )
                gws_v["self_hosted"] = {
                    **dict(gws_v.get("self_hosted") or {}),
                    "enabled": True,
                    "submode": "vps_hub",
                    "public_url": primary_url,
                }
                if not other_active_v or not sel_v or sel_v == "self_hosted":
                    sel_v = "self_hosted"
                    cfg_doc["tunnel_mode"] = "vps_hub"
                    cfg_doc["_gateways_mirrored_mode"] = "vps_hub"
                    cfg_doc["public_base"] = primary_url
                    cfg_doc["public_base_url"] = primary_url
                cfg_doc["gateways"] = gws_v
                cfg_doc["selected_gateway"] = sel_v
                atomic_write_text(
                    vps_node_secret_path(st_root, prefix=eff_prefix),
                    f"{node_secret}\n",
                    mode_override=0o600,
                )
                cfg_doc["vps_ssh"] = f"{clean_user}@{clean_host}"
                cfg_doc["vps_ssh_port"] = int(ssh_port)
                cfg_doc["vps_identity_file"] = str(priv_key_path)
                cfg_doc.pop("vps_node_secret", None)
                cfg_doc["vps_hub_mode"] = True
                cfg_doc["vps_hub_url"] = primary_url
                cfg_doc["pinned_gateway_urls"] = collect_pinned_gateway_urls(gws_v, cfg_doc)
                atomic_write_json(cfg_p, cfg_doc)

    return {
        "ok": True,
        "public_url": primary_url,
        "mcp_url": f"{primary_url}/mcp",
        "readonly_mcp_url": f"{primary_url}/mcp/readonly",
        "fallback_sslip_url": fallback_sslip_url,
        "public_ip": public_ip,
        "ssh_key_path": str(priv_key_path),
        "node_secret_path": str(vps_node_secret_path(st_root, prefix=eff_prefix)),
        "caddy_cert_dir": "/var/lib/cosmos-mcp/caddy",
        "caddyfile": caddyfile_txt,
        "systemd_unit": systemd_txt,
        "swap_created": swap_created,
        "mem_total_kb": mem_kb,
        "cloud_provider": cloud_provider,
        "region": region,
        "is_mainland_china": is_mainland_china,
        "warnings": warnings,
    }
