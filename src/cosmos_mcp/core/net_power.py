"""
Layer 0 Proxy/Fake-IP Safe Network & Anti-Sleep Keepalive Primitive (`cosmos_mcp.core.net_power`).

Pure Python >=3.9 standard-library implementation providing:
1. SSRF-safe HTTP/HTTPS requester & URL validator compatible with Clash / Mihomo / Sing-box
   `TUN + Fake-IP` (`198.18.0.0/15`) and explicit external proxies:
   - Strictly blocks literal loopback/internal hostnames and private/link-local/metadata IPs
     (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`,
     `100.64.0.0/10`, `::1`, `fc00::/7`, `fe80::/10`, plus IPv4-mapped IPv6).
   - Permits valid public domain names when an explicit external proxy is configured or when
     system DNS returns `198.18.0.0/15` (RFC 2544 / Fake-IP virtual range), while validating
     every HTTP redirect hop via `SSRFSafeRedirectHandler`.
2. Pure-stdlib RFC 6455 WebSocket / WSS client (`StdlibWebSocketClient`):
   - Zero `Origin` header by default for direct local headless Chromium CDP connections.
   - Remote TLS `wss://` (`ALPN http/1.1`) and HTTP `CONNECT` proxy tunneling.
   - `16 MiB` (`16 * 1024 * 1024` bytes) single-frame and fragmented-message memory cap.
3. Cross-platform anti-sleep keepalive (`SleepInhibitor`):
   - Windows: dedicated daemon thread calling `SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)`.
   - macOS: windowless `caffeinate -i -w <pid>`.
   - Linux: optional `systemd-inhibit --what=idle:sleep` keepalive.
   - Runtime `enable() / disable() / status()` lifecycle control.
"""
from __future__ import annotations

import base64
import contextlib
import ctypes
import fnmatch
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union
import urllib.error
import urllib.parse
import urllib.request

from cosmos_mcp.core.guard import CREATE_NO_WINDOW, record_security_event

DEFAULT_MAX_WS_FRAME_BYTES = 16 * 1024 * 1024  # 16 MiB
DEFAULT_MAX_HTTP_BYTES = 4 * 1024 * 1024  # 4 MiB
ERR_WS_FRAME_TOO_LARGE = "ERR_WS_FRAME_TOO_LARGE"
ERR_SSRF_BLOCKED = "ERR_SSRF_BLOCKED"

ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001
ES_DISPLAY_REQUIRED = 0x00000002

FAKE_IP_NETWORK = ipaddress.ip_network("198.18.0.0/15")
_STRICT_IPV4_BLOCKED_NETS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
)
_STRICT_IPV6_BLOCKED_NETS = (
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
)

BLOCKED_INTERNAL_HOSTNAMES = frozenset({
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata",
    "metadata.google.internal",
    "instance-data",
    "broadcasthost",
})
BLOCKED_INTERNAL_SUFFIXES = (
    ".localhost",
    ".internal",
    ".local",
    ".home.arpa",
    ".lan",
    ".localdomain",
)

_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$", re.IGNORECASE)

IpObj = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
DnsResolverFn = Callable[[str, int], Sequence[str]]


def is_valid_public_domain(hostname: str) -> bool:
    """Return True iff `hostname` is a syntactically valid public FQDN (not a literal IP or internal suffix)."""
    h = (hostname or "").strip().strip("[]").lower().rstrip(".")
    if not h or len(h) > 253 or "." not in h:
        return False
    if h in BLOCKED_INTERNAL_HOSTNAMES or any(h.endswith(sfx) for sfx in BLOCKED_INTERNAL_SUFFIXES):
        return False
    try:
        ipaddress.ip_address(h.split("%", 1)[0])
        return False
    except ValueError:
        pass
    labels = h.split(".")
    if len(labels) < 2:
        return False
    if not all(_DOMAIN_LABEL_RE.match(lbl) for lbl in labels):
        return False
    return bool(_TLD_RE.match(labels[-1]))


def _extract_embedded_ipv4(ip_obj: IpObj) -> List[ipaddress.IPv4Address]:
    out: List[ipaddress.IPv4Address] = []
    if isinstance(ip_obj, ipaddress.IPv6Address):
        if ip_obj.ipv4_mapped is not None:
            out.append(ip_obj.ipv4_mapped)
        if ip_obj.sixtofour is not None:
            out.append(ip_obj.sixtofour)
        if ip_obj.teredo is not None:
            out.extend([ip_obj.teredo[0], ip_obj.teredo[1]])
    return out


def is_strict_blocked_ip(ip_obj: IpObj) -> bool:
    """
    Return True for loopback, RFC 1918 private, link-local / cloud metadata (`169.254.0.0/16`),
    CGNAT (`100.64.0.0/10`), ULA (`fc00::/7`), unspecified, multicast, or reserved Class E.
    Note: `198.18.0.0/15` (RFC 2544 / Fake-IP) is evaluated separately by `is_fake_ip_address`.
    """
    if isinstance(ip_obj, ipaddress.IPv4Address):
        return any(ip_obj in net for net in _STRICT_IPV4_BLOCKED_NETS)
    if any(ip_obj in net for net in _STRICT_IPV6_BLOCKED_NETS):
        return True
    for v4 in _extract_embedded_ipv4(ip_obj):
        if any(v4 in net for net in _STRICT_IPV4_BLOCKED_NETS):
            return True
    return False


def is_fake_ip_address(ip_obj: IpObj) -> bool:
    """Return True iff `ip_obj` belongs to `198.18.0.0/15` (RFC 2544 / Clash & Sing-box Fake-IP pool)."""
    if isinstance(ip_obj, ipaddress.IPv4Address):
        return ip_obj in FAKE_IP_NETWORK
    return any(v4 in FAKE_IP_NETWORK for v4 in _extract_embedded_ipv4(ip_obj))


_PROXY_SCHEME_KEYS: Tuple[str, ...] = ("https", "http", "all", "socks5h", "socks5", "socks")


def _extract_clean_target_host(raw_target: str) -> str:
    val = (raw_target or "").strip()
    if not val:
        return ""
    if "://" in val:
        return (urllib.parse.urlsplit(val).hostname or "").strip().strip("[]").lower().rstrip(".")
    # Handle bare host[:port] without breaking IPv6 literals
    if val.startswith("["):
        return (urllib.parse.urlsplit(f"https://{val}").hostname or "").strip().strip("[]").lower().rstrip(".")
    if val.count(":") == 1:
        host_part, port_part = val.rsplit(":", 1)
        if port_part.isdigit():
            val = host_part
    return val.strip().strip("[]").lower().rstrip(".")


def get_effective_system_proxies() -> Dict[str, str]:
    """Return OS proxy dict, merging `getproxies_registry()` on Win32 when `NO_PROXY` short-circuits `getproxies()`."""
    merged: Dict[str, str] = {}
    with contextlib.suppress(Exception):
        sys_p = urllib.request.getproxies()
        if isinstance(sys_p, dict):
            merged.update({str(k).lower(): str(v) for k, v in sys_p.items() if v is not None})

    has_actual_proxy = any(bool(str(merged.get(k) or "").strip()) for k in _PROXY_SCHEME_KEYS)
    if not has_actual_proxy and sys.platform == "win32":
        reg_fn = getattr(urllib.request, "getproxies_registry", None)
        if callable(reg_fn):
            with contextlib.suppress(Exception):
                reg_p = reg_fn()
                if isinstance(reg_p, dict) and reg_p:
                    combined = {str(k).lower(): str(v) for k, v in reg_p.items() if v is not None}
                    for k, v in merged.items():
                        if k not in combined or not str(combined.get(k) or "").strip():
                            combined[k] = v
                    merged = combined
    return merged


def is_host_proxy_bypassed(target_host: str, proxies: Optional[Dict[str, str]] = None) -> bool:
    """Return True if `target_host` matches loopback, `NO_PROXY`, or Windows `ProxyOverride` rules."""
    host = _extract_clean_target_host(target_host)
    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "::1") or host.startswith("127."):
        return True

    host_ip: Optional[IpObj] = None
    with contextlib.suppress(ValueError):
        host_ip = ipaddress.ip_address(host.split("%", 1)[0])

    raw_tokens: List[str] = []
    for raw_np in (
        os.environ.get("NO_PROXY"),
        os.environ.get("no_proxy"),
        (proxies or {}).get("no"),
    ):
        if raw_np:
            raw_tokens.extend(re.split(r"[,\s]+", str(raw_np)))
    raw_override = (proxies or {}).get("override") or (proxies or {}).get("proxyoverride")
    if raw_override:
        raw_tokens.extend(re.split(r"[;,\s]+", str(raw_override)))

    for tok in raw_tokens:
        pat = tok.strip().lower()
        if not pat:
            continue
        if pat == "*":
            return True
        if pat == "<local>":
            if "." not in host and host_ip is None:
                return True
            continue
        if pat.startswith("[") and "]" in pat:
            pat = pat[1 : pat.index("]")]
        elif pat.count(":") == 1 and not ("/" in pat):
            hp, pp = pat.rsplit(":", 1)
            if pp.isdigit():
                pat = hp
        pat = pat.rstrip(".")
        if not pat:
            continue
        if "/" in pat and host_ip is not None:
            with contextlib.suppress(ValueError):
                net = ipaddress.ip_network(pat, strict=False)
                if host_ip.version == net.version and host_ip in net:
                    return True
            continue
        if "*" in pat or "?" in pat:
            if fnmatch.fnmatchcase(host, pat):
                return True
            if pat.startswith("*.") and host == pat[2:]:
                return True
            continue
        sfx = pat[1:] if pat.startswith(".") else pat
        if sfx and (host == sfx or host.endswith("." + sfx)):
            return True

    if sys.platform == "win32":
        bypass_reg_fn = getattr(urllib.request, "proxy_bypass_registry", None)
        if callable(bypass_reg_fn):
            with contextlib.suppress(Exception):
                if bypass_reg_fn(host):
                    return True
    return False


def detect_configured_proxy(
    scheme: str = "https",
    explicit_proxy: Optional[str] = None,
    target_host: str = "",
) -> str:
    """Detect active external proxy from `explicit_proxy`, environment variables, or OS/Win32 registry proxy settings."""
    if explicit_proxy and explicit_proxy.strip():
        return explicit_proxy.strip()
    eff_host = _extract_clean_target_host(target_host)
    if eff_host and is_host_proxy_bypassed(eff_host):
        return ""
    sc_low = "https" if scheme.lower() in ("https", "wss") else "http"
    env_order = (
        ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SOCKS_PROXY", "socks_proxy", "HTTP_PROXY", "http_proxy")
        if sc_low == "https"
        else ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "SOCKS_PROXY", "socks_proxy")
    )
    for k in env_order:
        v = (os.environ.get(k) or "").strip()
        if v:
            return v
    with contextlib.suppress(Exception):
        sys_p = get_effective_system_proxies()
        if sys_p:
            if eff_host and is_host_proxy_bypassed(eff_host, sys_p):
                return ""
            if sc_low == "https":
                cand = (
                    sys_p.get("https")
                    or sys_p.get("all")
                    or sys_p.get("socks5h")
                    or sys_p.get("socks5")
                    or sys_p.get("socks")
                    or sys_p.get("http")
                    or ""
                )
            else:
                cand = (
                    sys_p.get("http")
                    or sys_p.get("all")
                    or sys_p.get("socks5h")
                    or sys_p.get("socks5")
                    or sys_p.get("socks")
                    or ""
                )
            if cand and str(cand).strip():
                cs = str(cand).strip()
                if "://" not in cs:
                    if cand in (sys_p.get("socks"), sys_p.get("socks5"), sys_p.get("socks5h")):
                        return f"socks5h://{cs}"
                    return f"http://{cs}"
                return cs
    return ""


def _default_dns_resolve(host: str, port: int) -> List[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addrs: List[str] = []
    for info in infos:
        raw_ip = str(info[4][0]).split("%", 1)[0]
        if raw_ip and raw_ip not in addrs:
            addrs.append(raw_ip)
    return addrs


def validate_public_url(
    raw_url: str,
    *,
    proxy_url: Optional[str] = None,
    allowed_schemes: Tuple[str, ...] = ("http", "https"),
    resolver: Optional[DnsResolverFn] = None,
) -> Dict[str, Any]:
    """
    Validate a target URL against SSRF while preserving compatibility with external proxies
    and Clash / Sing-box `TUN + Fake-IP` (`198.18.0.0/15`).

    Raises `ValueError` on malformed URLs / unsupported schemes, and `PermissionError` on SSRF hits.
    Returns metadata dict `{"url": url, "host": host, "resolved_ips": [...], "fake_ip": bool, "via_proxy": bool}`.
    """
    url = (raw_url or "").strip()
    if not url:
        raise ValueError("URL must not be empty.")
    parsed = urllib.parse.urlsplit(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in allowed_schemes:
        raise ValueError(f"Unsupported URL scheme `{scheme}:` (allowed: {allowed_schemes}).")
    if parsed.username or parsed.password:
        raise PermissionError(f"{ERR_SSRF_BLOCKED}: Embedded credentials in URL are prohibited.")

    host_raw = (parsed.hostname or "").strip().strip("[]")
    host = host_raw.lower().rstrip(".")
    if not host:
        raise ValueError("URL is missing a valid hostname.")

    if host in BLOCKED_INTERNAL_HOSTNAMES or any(host.endswith(sfx) for sfx in BLOCKED_INTERNAL_SUFFIXES):
        record_security_event("ssrf_internal_host_blocked", url, f"Blocked internal host `{host}`")
        raise PermissionError(f"{ERR_SSRF_BLOCKED}: Access to loopback or internal hostname `{host}` is prohibited.")

    # 1. Literal IP address check (never treated as a public domain name, so literal 198.18.x.x is also blocked)
    literal_ip: Optional[IpObj] = None
    with contextlib.suppress(ValueError):
        literal_ip = ipaddress.ip_address(host.split("%", 1)[0])

    if literal_ip is not None:
        if is_strict_blocked_ip(literal_ip) or is_fake_ip_address(literal_ip) or not literal_ip.is_global:
            record_security_event("ssrf_literal_ip_blocked", url, f"Blocked non-public literal IP `{literal_ip}`")
            raise PermissionError(
                f"{ERR_SSRF_BLOCKED}: Direct access to loopback, private, link-local, or virtual IP `{literal_ip}` is prohibited."
            )
        return {
            "url": url,
            "host": host,
            "resolved_ips": [str(literal_ip)],
            "fake_ip": False,
            "via_proxy": bool(detect_configured_proxy(scheme, proxy_url, target_host=host)),
        }

    # 2. Must be a valid public domain name
    if not is_valid_public_domain(host):
        record_security_event("ssrf_invalid_domain_blocked", url, f"Non-public hostname `{host}`")
        raise PermissionError(f"{ERR_SSRF_BLOCKED}: Hostname `{host}` is not a valid public domain name.")

    eff_port = parsed.port or (443 if scheme in ("https", "wss") else 80)
    active_proxy = detect_configured_proxy(scheme, proxy_url, target_host=host)
    has_explicit_proxy = bool(proxy_url and proxy_url.strip()) or bool(active_proxy)
    dns_fn = resolver or _default_dns_resolve

    try:
        resolved_strs = list(dns_fn(host, eff_port))
    except OSError as exc:
        if has_explicit_proxy:
            return {
                "url": url,
                "host": host,
                "resolved_ips": [],
                "fake_ip": False,
                "via_proxy": True,
            }
        raise RuntimeError(f"DNS resolution failed for `{host}`: {exc}") from exc

    if not resolved_strs:
        if has_explicit_proxy:
            return {"url": url, "host": host, "resolved_ips": [], "fake_ip": False, "via_proxy": True}
        raise RuntimeError(f"DNS resolution returned no addresses for `{host}`.")

    saw_fake_ip = False
    verified_ips: List[str] = []
    for ip_s in resolved_strs:
        clean_ip_s = str(ip_s).split("%", 1)[0]
        ip_obj = ipaddress.ip_address(clean_ip_s)
        if is_strict_blocked_ip(ip_obj):
            record_security_event("ssrf_dns_rebind_blocked", url, f"Host `{host}` resolved to `{ip_obj}`")
            raise PermissionError(
                f"{ERR_SSRF_BLOCKED}: Host `{host}` resolves to forbidden loopback/private/link-local IP `{ip_obj}`."
            )
        if is_fake_ip_address(ip_obj):
            saw_fake_ip = True
            verified_ips.append(str(ip_obj))
            continue
        if not ip_obj.is_global and not has_explicit_proxy:
            record_security_event("ssrf_reserved_ip_blocked", url, f"Host `{host}` resolved to reserved `{ip_obj}`")
            raise PermissionError(f"{ERR_SSRF_BLOCKED}: Host `{host}` resolves to non-global address `{ip_obj}`.")
        verified_ips.append(str(ip_obj))

    return {
        "url": url,
        "host": host,
        "resolved_ips": verified_ips,
        "fake_ip": saw_fake_ip,
        "via_proxy": has_explicit_proxy,
    }


def validate_public_http_url(
    raw_url: str,
    *,
    proxy_url: Optional[str] = None,
    resolver: Optional[DnsResolverFn] = None,
) -> str:
    validate_public_url(raw_url, proxy_url=proxy_url, allowed_schemes=("http", "https"), resolver=resolver)
    return raw_url.strip()


class SSRFSafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Validates every HTTP 30x redirect target against `validate_public_url` before following."""

    def __init__(
        self,
        *,
        proxy_url: Optional[str] = None,
        resolver: Optional[DnsResolverFn] = None,
        max_redirects: int = 8,
    ) -> None:
        super().__init__()
        self.proxy_url = proxy_url
        self.resolver = resolver
        self.max_redirects = max_redirects
        self._hops = 0

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        self._hops += 1
        if self._hops > self.max_redirects:
            raise urllib.error.HTTPError(req.full_url, code, "Too many redirects", headers, fp)
        abs_target = urllib.parse.urljoin(req.full_url, newurl)
        validate_public_url(
            abs_target,
            proxy_url=self.proxy_url,
            allowed_schemes=("http", "https"),
            resolver=self.resolver,
        )
        return super().redirect_request(req, fp, code, msg, headers, abs_target)


def build_ssrf_safe_openers(
    *,
    proxy_url: Optional[str] = None,
    enforce_ssrf: bool = True,
    resolver: Optional[DnsResolverFn] = None,
    ssl_context: Optional[ssl.SSLContext] = None,
    target_url: str = "",
) -> List[urllib.request.OpenerDirector]:
    ctx = ssl_context or ssl.create_default_context()
    https_handler = urllib.request.HTTPSHandler(context=ctx)

    def _mk_handlers(proxy_map: Optional[Dict[str, str]]) -> List[Any]:
        handlers: List[Any] = []
        if proxy_map is not None:
            handlers.append(urllib.request.ProxyHandler(proxy_map))
        if enforce_ssrf:
            handlers.append(SSRFSafeRedirectHandler(proxy_url=proxy_url, resolver=resolver))
        handlers.append(https_handler)
        return handlers

    def _filter_http_proxy_map(raw_map: Dict[str, str]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for k in ("http", "https"):
            v = str(raw_map.get(k) or "").strip()
            if not v:
                continue
            if "://" not in v:
                v = f"http://{v}"
            if v.lower().startswith(("http://", "https://")):
                out[k] = v
        return out

    if proxy_url and proxy_url.strip():
        p_clean = proxy_url.strip()
        if "://" not in p_clean:
            p_clean = f"http://{p_clean}"
        if p_clean.lower().startswith(("http://", "https://")):
            return [urllib.request.build_opener(*_mk_handlers({"http": p_clean, "https": p_clean}))]
        return [urllib.request.build_opener(*_mk_handlers({}))]

    openers: List[urllib.request.OpenerDirector] = []
    sys_proxies = get_effective_system_proxies()
    http_sys_proxies = _filter_http_proxy_map(sys_proxies)
    if http_sys_proxies and not (target_url and is_host_proxy_bypassed(target_url, sys_proxies)):
        openers.append(urllib.request.build_opener(*_mk_handlers(http_sys_proxies)))
    openers.append(urllib.request.build_opener(*_mk_handlers({})))
    return openers


def http_request(
    url: str,
    *,
    method: str = "GET",
    data: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 15.0,
    proxy_url: Optional[str] = None,
    enforce_public_ssrf: bool = True,
    max_bytes: int = DEFAULT_MAX_HTTP_BYTES,
    resolver: Optional[DnsResolverFn] = None,
    ssl_context: Optional[ssl.SSLContext] = None,
) -> Dict[str, Any]:
    """Execute an HTTP/HTTPS request with Fake-IP-compatible SSRF & redirect protection."""
    if enforce_public_ssrf:
        validate_public_url(url, proxy_url=proxy_url, allowed_schemes=("http", "https"), resolver=resolver)

    req_headers = {"User-Agent": "CosmosMCP/3.0"}
    if headers:
        req_headers.update(headers)

    cap = max(1024, int(max_bytes))
    last_err: Optional[Exception] = None
    for opener in build_ssrf_safe_openers(
        proxy_url=proxy_url,
        enforce_ssrf=enforce_public_ssrf,
        resolver=resolver,
        ssl_context=ssl_context,
        target_url=url,
    ):
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method.upper())
        try:
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read(cap + 1)
                truncated = len(raw) > cap
                if truncated:
                    raw = raw[:cap]
                charset = resp.headers.get_content_charset() or "utf-8"
                try:
                    text = raw.decode(charset, errors="replace")
                except LookupError:
                    text = raw.decode("utf-8", errors="replace")
                return {
                    "ok": 200 <= int(resp.status) < 400,
                    "status": int(resp.status),
                    "url": str(resp.geturl()),
                    "headers": dict(resp.headers.items()),
                    "body_bytes": raw,
                    "text": text,
                    "truncated": truncated,
                }
        except PermissionError:
            raise
        except urllib.error.HTTPError as he:
            err_raw = b""
            with contextlib.suppress(Exception):
                err_raw = he.read(min(cap, 65536))
            return {
                "ok": False,
                "status": int(he.code),
                "url": url,
                "error": f"HTTP {he.code}: {he.reason}",
                "body_bytes": err_raw,
                "text": err_raw.decode("utf-8", errors="replace"),
                "truncated": False,
            }
        except Exception as exc:
            last_err = exc
            continue
    raise ConnectionError(f"HTTP request failed for {url}: {last_err}")


# --- Pure-Stdlib RFC 6455 WebSocket / WSS Client & Network Change Probe ---

MAX_PROXY_CONNECT_HEADER_BYTES = 64 * 1024  # 64 KiB


def _xor_mask_bytes(payload: bytes, mask_key: bytes) -> bytes:
    """Block-level CPython big-int XOR masking (<1ms for multi-MB frames)."""
    n = len(payload)
    if n == 0:
        return b""
    rep = (mask_key * ((n + 3) // 4))[:n]
    return (int.from_bytes(payload, "big") ^ int.from_bytes(rep, "big")).to_bytes(n, "big")


def enable_tcp_keepalive(
    sock: socket.socket,
    *,
    idle_sec: int = 15,
    interval_sec: int = 5,
    count: int = 3,
) -> bool:
    """Enable OS-level TCP keepalive (`TCP_KEEPIDLE=15` / Windows `SIO_KEEPALIVE_VALS=(1, 15000, 5000)`)."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except (OSError, AttributeError, ValueError):
        return False
    if hasattr(socket, "SIO_KEEPALIVE_VALS") and hasattr(sock, "ioctl"):
        with contextlib.suppress(OSError, AttributeError, ValueError):
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, int(idle_sec * 1000), int(interval_sec * 1000)))
            return True
    with contextlib.suppress(OSError, AttributeError, ValueError):
        if hasattr(socket, "TCP_KEEPIDLE"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, int(idle_sec))
        elif hasattr(socket, "TCP_KEEPALIVE"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, int(idle_sec))
    with contextlib.suppress(OSError, AttributeError, ValueError):
        if hasattr(socket, "TCP_KEEPINTVL"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, int(interval_sec))
    with contextlib.suppress(OSError, AttributeError, ValueError):
        if hasattr(socket, "TCP_KEEPCNT"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, int(count))
    return True


def _sock_recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        ch = sock.recv(n - len(buf))
        if not ch:
            raise ConnectionError("EOF while reading proxy handshake")
        buf.extend(ch)
    return bytes(buf)


def _connect_socks5_tunnel(
    sock: socket.socket,
    target_host: str,
    target_port: int,
    username: str = "",
    password: str = "",
) -> None:
    """Pure-stdlib RFC 1928 / RFC 1929 SOCKS5 `CONNECT` (`ATYP=0x03` domain pass-through avoiding Fake-IP)."""
    has_auth = bool(username)
    sock.sendall(b"\x05\x02\x00\x02" if has_auth else b"\x05\x01\x00")
    ver, method = _sock_recv_exact(sock, 2)
    if ver != 0x05 or method == 0xFF:
        raise ConnectionError(f"SOCKS5 method negotiation rejected (ver={ver}, method=0x{method:02x})")
    if method == 0x02:
        ub = username.encode("utf-8")[:255]
        pb = password.encode("utf-8")[:255]
        sock.sendall(bytes([0x01, len(ub)]) + ub + bytes([len(pb)]) + pb)
        _aver, astatus = _sock_recv_exact(sock, 2)
        if astatus != 0x00:
            raise ConnectionError("SOCKS5 RFC 1929 username/password authentication failed")
    elif method != 0x00:
        raise ConnectionError(f"Unsupported SOCKS5 auth method: 0x{method:02x}")

    clean_h = target_host.strip("[]")
    try:
        ip_obj = ipaddress.ip_address(clean_h.split("%", 1)[0])
        addr_part = (b"\x01" + ip_obj.packed) if ip_obj.version == 4 else (b"\x04" + ip_obj.packed)
    except ValueError:
        hb = clean_h.encode("idna")
        if len(hb) > 255:
            raise ValueError(f"SOCKS5 domain name exceeds 255 bytes: {clean_h}")
        addr_part = bytes([0x03, len(hb)]) + hb

    sock.sendall(b"\x05\x01\x00" + addr_part + struct.pack("!H", int(target_port)))
    r_ver, rep, _rsv, atyp = _sock_recv_exact(sock, 4)
    if r_ver != 0x05 or rep != 0x00:
        raise ConnectionError(f"SOCKS5 CONNECT rejected (rep=0x{rep:02x})")
    if atyp == 0x01:
        _sock_recv_exact(sock, 6)
    elif atyp == 0x03:
        alen = _sock_recv_exact(sock, 1)[0]
        _sock_recv_exact(sock, alen + 2)
    elif atyp == 0x04:
        _sock_recv_exact(sock, 18)
    else:
        raise ConnectionError(f"Unknown SOCKS5 reply ATYP: 0x{atyp:02x}")


def probe_outbound_local_ip(probe_target: Tuple[str, int] = ("8.8.8.8", 53)) -> str:
    """Zero-packet routing table source-IP probe via UDP `connect()` + `getsockname()[0]`."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(probe_target)
            return str(s.getsockname()[0] or "")
    except OSError:
        return ""


class NetworkChangeDetector:
    """
    Lightweight 1s network/sleep-wake detector triggering active WSS reconnect within <=1.5s:
    1) Detects lid-close / OS suspend-resume via `abs((time.time() - time.monotonic()) - baseline_offset) > 3.0`.
    2) Detects Wi-Fi <-> mobile hotspot or TUN toggle via zero-traffic UDP `getsockname()[0]` change.
    """

    def __init__(
        self,
        *,
        interval_sec: float = 1.0,
        clock_skew_threshold_sec: float = 3.0,
        probe_target: Tuple[str, int] = ("8.8.8.8", 53),
        on_change: Optional[Callable[[Dict[str, Any]], None]] = None,
        _time_fn: Optional[Callable[[], float]] = None,
        _monotonic_fn: Optional[Callable[[], float]] = None,
        _ip_probe_fn: Optional[Callable[[], str]] = None,
    ) -> None:
        self.interval_sec = max(0.05, float(interval_sec))
        self.clock_skew_threshold_sec = max(0.5, float(clock_skew_threshold_sec))
        self._time_fn = _time_fn or time.time
        self._monotonic_fn = _monotonic_fn or time.monotonic
        self._ip_probe_fn = _ip_probe_fn or (lambda: probe_outbound_local_ip(probe_target))
        self._lock = threading.Lock()
        self.baseline_offset: float = self._time_fn() - self._monotonic_fn()
        self.baseline_ip: str = self._ip_probe_fn()
        self._callbacks: List[Callable[[Dict[str, Any]], None]] = [on_change] if on_change is not None else []
        self._change_event = threading.Event()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.last_event: Optional[Dict[str, Any]] = None
        self.change_count: int = 0

    def __enter__(self) -> "NetworkChangeDetector":
        return self.start()

    def __exit__(self, *_exc: Any) -> None:
        self.stop()

    def add_callback(self, fn: Callable[[Dict[str, Any]], None]) -> None:
        with self._lock:
            if fn not in self._callbacks:
                self._callbacks.append(fn)

    def reset_baseline(self) -> None:
        with self._lock:
            self.baseline_offset = self._time_fn() - self._monotonic_fn()
            self.baseline_ip = self._ip_probe_fn()
            self._change_event.clear()

    def check_once(self) -> Optional[Dict[str, Any]]:
        now_wall = self._time_fn()
        now_mono = self._monotonic_fn()
        cur_offset = now_wall - now_mono
        cur_ip = self._ip_probe_fn()
        with self._lock:
            skew = abs(cur_offset - self.baseline_offset)
            wake_hit = skew > self.clock_skew_threshold_sec
            ip_hit = cur_ip != self.baseline_ip
            if not wake_hit and not ip_hit:
                return None
            prev_ip = self.baseline_ip
            self.baseline_offset = cur_offset
            self.baseline_ip = cur_ip
            reasons: List[str] = []
            if wake_hit:
                reasons.append("sleep_wake")
            if ip_hit:
                reasons.append("route_ip_change")
            ev: Dict[str, Any] = {
                "changed": True,
                "reasons": reasons,
                "reason": "+".join(reasons),
                "prev_ip": prev_ip,
                "current_ip": cur_ip,
                "clock_skew_sec": round(skew, 3),
                "ts": now_wall,
            }
            self.last_event = ev
            self.change_count += 1
            self._change_event.set()
            cbs = list(self._callbacks)
        for cb in cbs:
            with contextlib.suppress(Exception):
                cb(ev)
        return ev

    def start(self) -> "NetworkChangeDetector":
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return self
            self._stop_event.clear()

            def _loop() -> None:
                while not self._stop_event.wait(self.interval_sec):
                    with contextlib.suppress(Exception):
                        self.check_once()

            t = threading.Thread(target=_loop, name="cosmos-net-change-detector", daemon=True)
            t.start()
            self._thread = t
        return self

    def wait_for_change(self, timeout: float = 1.5) -> Optional[Dict[str, Any]]:
        if self._change_event.wait(max(0.01, float(timeout))):
            return self.last_event
        return None

    def stop(self, timeout: float = 1.5) -> None:
        self._stop_event.set()
        with self._lock:
            t = self._thread
            self._thread = None
        if t is not None and t.is_alive():
            t.join(timeout=timeout)


class StdlibWebSocketClient:
    """
    Pure Python standard-library RFC 6455 WebSocket / WSS client:
    - Zero `Origin` header by default (direct loopback Chromium CDP compatibility without `--remote-allow-origins=*`).
    - Supports `ws://` and `wss://` (`ssl` with ALPN `http/1.1`), HTTP `CONNECT` (`<=64 KiB`), and `SOCKS5` (`ATYP=0x03`).
    - Full-duplex thread-safe `_send_lock`, block-level big-int XOR masking, OS TCP keepalive (`15s`), and optional `NetworkChangeDetector`.
    - Enforces `max_frame_bytes` (default `16 MiB`) BEFORE payload allocation to prevent OOM.
    """

    def __init__(
        self,
        ws_url: str,
        *,
        timeout: float = 15.0,
        max_frame_bytes: int = DEFAULT_MAX_WS_FRAME_BYTES,
        origin: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        enforce_public_ssrf: bool = False,
        ssl_context: Optional[ssl.SSLContext] = None,
        auto_connect: bool = False,
        proxy_url: str = "",
        watch_network_change: bool = False,
        on_network_change: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        u = urllib.parse.urlsplit((ws_url or "").strip())
        scheme = (u.scheme or "").lower()
        if scheme not in ("ws", "wss", "http", "https"):
            raise ValueError(f"Invalid WebSocket URL scheme `{scheme}` in `{ws_url}`")
        self.ws_url = ws_url.strip()
        self.use_tls = scheme in ("wss", "https")
        self.host = u.hostname or ""
        if not self.host:
            raise ValueError(f"WebSocket URL missing hostname: `{ws_url}`")
        self.port = int(u.port or (443 if self.use_tls else 80))
        self.path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        self.timeout = float(timeout)
        self.max_frame_bytes = max(1024, int(max_frame_bytes))
        self.origin = origin  # None by default -> zero Origin header!
        self.extra_headers = dict(extra_headers or {})
        self.enforce_public_ssrf = bool(enforce_public_ssrf)
        self.ssl_context = ssl_context
        self.sock: Optional[socket.socket] = None
        self.closed: bool = False
        self.network_changed: bool = False
        self._send_lock = threading.Lock()
        self._net_detector: Optional[NetworkChangeDetector] = None
        self._watch_network_change = bool(watch_network_change)
        self._on_network_change = on_network_change
        self._rx_buf = bytearray()
        self._next_rpc_id = 1
        self._last_handshake_request: bytes = b""
        if auto_connect:
            self.connect(proxy_url=proxy_url)

    def __enter__(self) -> "StdlibWebSocketClient":
        if self.sock is None:
            self.connect()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def build_handshake_bytes(self, ws_key: str) -> bytes:
        host_hdr = f"{self.host}:{self.port}" if self.port not in (80, 443) else self.host
        lines = [
            f"GET {self.path} HTTP/1.1",
            f"Host: {host_hdr}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {ws_key}",
            "Sec-WebSocket-Version: 13",
        ]
        if self.origin is not None:
            lines.append(f"Origin: {self.origin}")
        for hk, hv in self.extra_headers.items():
            if hk.lower() not in ("host", "upgrade", "connection", "sec-websocket-key", "sec-websocket-version", "origin"):
                lines.append(f"{hk}: {hv}")
        lines.extend(["", ""])
        return "\r\n".join(lines).encode("ascii")

    def start_network_watch(
        self,
        on_change: Optional[Callable[[Dict[str, Any]], None]] = None,
        *,
        interval_sec: float = 1.0,
    ) -> NetworkChangeDetector:
        """Start 1s sleep-wake & outbound-IP detector; interrupts stale socket within <=1.5s on network shift."""
        self.stop_network_watch()

        def _handle_shift(ev: Dict[str, Any]) -> None:
            self.network_changed = True
            cur_sock = self.sock
            if cur_sock is not None:
                with contextlib.suppress(Exception):
                    cur_sock.shutdown(socket.SHUT_RDWR)
                with contextlib.suppress(Exception):
                    cur_sock.close()
            cb = on_change or self._on_network_change
            if cb is not None:
                with contextlib.suppress(Exception):
                    cb(ev)

        det = NetworkChangeDetector(interval_sec=interval_sec, on_change=_handle_shift)
        det.start()
        self._net_detector = det
        return det

    def stop_network_watch(self) -> None:
        det = self._net_detector
        self._net_detector = None
        if det is not None:
            det.stop()

    def connect(self, proxy_url: str = "") -> None:
        if self.enforce_public_ssrf:
            validate_public_url(
                self.ws_url,
                proxy_url=proxy_url or None,
                allowed_schemes=("ws", "wss", "http", "https"),
            )

        raw_sock: Optional[socket.socket] = None
        proxy_leftover = b""
        try:
            eff_proxy = (proxy_url or "").strip()
            if eff_proxy:
                if "://" not in eff_proxy:
                    eff_proxy = f"http://{eff_proxy}"
                pu = urllib.parse.urlsplit(eff_proxy)
                pscheme = (pu.scheme or "http").lower()
                phost = pu.hostname or "127.0.0.1"
                default_pport = 1080 if pscheme in ("socks5", "socks5h") else 8080
                pport = int(pu.port or default_pport)
                puser = urllib.parse.unquote(pu.username) if pu.username else ""
                ppass = urllib.parse.unquote(pu.password or "") if pu.username else ""
                raw_sock = socket.create_connection((phost, pport), timeout=self.timeout)
                enable_tcp_keepalive(raw_sock)
                raw_sock.settimeout(self.timeout)
                if pscheme in ("socks5", "socks5h"):
                    _connect_socks5_tunnel(raw_sock, self.host, self.port, username=puser, password=ppass)
                elif pscheme in ("http", "https"):
                    connect_lines = [
                        f"CONNECT {self.host}:{self.port} HTTP/1.1",
                        f"Host: {self.host}:{self.port}",
                    ]
                    if puser:
                        cred = f"{puser}:{ppass}"
                        b64_cred = base64.b64encode(cred.encode("utf-8")).decode("ascii")
                        connect_lines.append(f"Proxy-Authorization: Basic {b64_cred}")
                    connect_lines.extend(["", ""])
                    raw_sock.sendall("\r\n".join(connect_lines).encode("ascii"))
                    pbuf = b""
                    while b"\r\n\r\n" not in pbuf:
                        ch = raw_sock.recv(1024)
                        if not ch:
                            raise ConnectionError("EOF from HTTP CONNECT proxy")
                        pbuf += ch
                        if len(pbuf) > MAX_PROXY_CONNECT_HEADER_BYTES:
                            raise ConnectionError("Proxy CONNECT response header exceeded 64 KiB")
                    p_head, proxy_leftover = pbuf.split(b"\r\n\r\n", 1)
                    first_line = p_head.splitlines()[0].decode("latin-1", errors="replace").strip()
                    parts = first_line.split()
                    if len(parts) < 2 or parts[1] != "200":
                        raise ConnectionError(f"HTTP CONNECT rejected by proxy: {first_line}")
                else:
                    raise ValueError(f"Unsupported proxy scheme `{pscheme}` in `{proxy_url}`")
            else:
                raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
                enable_tcp_keepalive(raw_sock)

            if self.use_tls:
                ctx = self.ssl_context
                if ctx is None:
                    ctx = ssl.create_default_context()
                    with contextlib.suppress(Exception):
                        ctx.set_alpn_protocols(["http/1.1"])
                self.sock = ctx.wrap_socket(raw_sock, server_hostname=self.host)
            else:
                self.sock = raw_sock
            self.sock.settimeout(self.timeout)

            ws_key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
            req_bytes = self.build_handshake_bytes(ws_key)
            self._last_handshake_request = req_bytes
            with self._send_lock:
                self.sock.sendall(req_bytes)

            header_buf = proxy_leftover if not self.use_tls else b""
            while b"\r\n\r\n" not in header_buf:
                chunk = self.sock.recv(2048)
                if not chunk:
                    raise ConnectionError("EOF during WebSocket handshake")
                header_buf += chunk
                if len(header_buf) > 32768:
                    raise ConnectionError("WebSocket handshake header exceeded 32 KiB")

            head_part, leftover = header_buf.split(b"\r\n\r\n", 1)
            status_line = head_part.splitlines()[0].decode("latin-1", errors="replace").strip()
            ws_parts = status_line.split()
            if len(ws_parts) < 2 or ws_parts[1] != "101":
                raise ConnectionError(f"WebSocket upgrade rejected: {status_line}")

            expected_accept = base64.b64encode(
                hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
            ).decode("ascii")
            if b"sec-websocket-accept:" in head_part.lower() and expected_accept.encode("ascii") not in head_part:
                raise ConnectionError("Invalid Sec-WebSocket-Accept header")

            self._rx_buf = bytearray(leftover)
            self._frag_opcode = None
            self._frag_chunks = bytearray()
            self.closed = False
            self.network_changed = False
            if self._watch_network_change or self._on_network_change is not None:
                self.start_network_watch(self._on_network_change)
        except Exception:
            if self.sock is not None:
                with contextlib.suppress(Exception):
                    self.sock.close()
                self.sock = None
            elif raw_sock is not None:
                with contextlib.suppress(Exception):
                    raw_sock.close()
            raise

    def _recv_exact(self, n: int) -> bytes:
        if n == 0:
            return b""
        if n > self.max_frame_bytes:
            raise ValueError(f"{ERR_WS_FRAME_TOO_LARGE}: Requested {n} bytes exceeds cap ({self.max_frame_bytes})")
        if self.sock is None:
            raise ConnectionError("WebSocket is not connected")
        while len(self._rx_buf) < n:
            need = n - len(self._rx_buf)
            chunk = self.sock.recv(min(65536, max(4096, need)))
            if not chunk:
                raise ConnectionError("WebSocket connection closed unexpectedly")
            self._rx_buf.extend(chunk)
        out = bytes(self._rx_buf[:n])
        del self._rx_buf[:n]
        return out

    def _encode_masked_frame(self, payload: bytes, opcode: int = 0x1, *, fin: bool = True) -> bytes:
        length = len(payload)
        if length > self.max_frame_bytes:
            raise ValueError(f"{ERR_WS_FRAME_TOO_LARGE}: Outbound frame ({length} bytes) exceeds cap ({self.max_frame_bytes})")
        mask_key = secrets.token_bytes(4)
        b0 = (0x80 if fin else 0x00) | (opcode & 0x0F)
        header = bytearray([b0])
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        header.extend(mask_key)
        return bytes(header) + _xor_mask_bytes(payload, mask_key)

    def send_frame(self, payload: bytes, opcode: int = 0x1, *, fin: bool = True) -> None:
        raw_frame = self._encode_masked_frame(payload, opcode=opcode, fin=fin)
        with self._send_lock:
            if self.sock is None:
                raise ConnectionError("WebSocket is not connected")
            self.sock.sendall(raw_frame)

    def send_binary(self, payload: bytes) -> None:
        raw_frame = self._encode_masked_frame(bytes(payload), opcode=0x2, fin=True)
        with self._send_lock:
            if self.sock is None:
                raise ConnectionError("WebSocket is not connected")
            self.sock.sendall(raw_frame)

    def send_ping(self, payload: bytes = b"") -> None:
        raw_frame = self._encode_masked_frame(bytes(payload)[:125], opcode=0x9, fin=True)
        with self._send_lock:
            if self.sock is None:
                raise ConnectionError("WebSocket is not connected")
            self.sock.sendall(raw_frame)

    def send_text(self, text: str) -> None:
        self.send_frame(text.encode("utf-8"), opcode=0x1)

    def send_json(self, obj: Dict[str, Any]) -> None:
        self.send_frame(json.dumps(obj, ensure_ascii=False).encode("utf-8"), opcode=0x1)

    def recv_frame(self) -> Tuple[int, bytes]:
        """Read next RFC 6455 message/control frame `(opcode, payload)`; auto-replies `Pong(0xA)` under `_send_lock` without dropping fragmented messages."""
        if not hasattr(self, "_frag_chunks"):
            self._frag_opcode = None
            self._frag_chunks = bytearray()
        while True:
            b0, b1 = self._recv_exact(2)
            fin = bool(b0 & 0x80)
            opcode = b0 & 0x0F
            masked = bool(b1 & 0x80)
            length = b1 & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._recv_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._recv_exact(8))[0]

            projected_total = length if opcode >= 0x8 else (len(self._frag_chunks) + length)
            if length > self.max_frame_bytes or projected_total > self.max_frame_bytes:
                self._frag_opcode = None
                self._frag_chunks = bytearray()
                self.close()
                raise ValueError(
                    f"{ERR_WS_FRAME_TOO_LARGE}: Frame/message size ({projected_total} bytes) exceeds {self.max_frame_bytes} bytes cap."
                )

            mask_key = self._recv_exact(4) if masked else b""
            data = self._recv_exact(length)
            if masked and data:
                data = _xor_mask_bytes(data, mask_key)

            if opcode == 0x8:
                self._frag_opcode = None
                self._frag_chunks = bytearray()
                self.closed = True
                return (0x8, data)
            if opcode == 0x9:
                pong_frame = self._encode_masked_frame(data[:125], opcode=0xA, fin=True)
                with contextlib.suppress(Exception):
                    with self._send_lock:
                        if self.sock is not None:
                            self.sock.sendall(pong_frame)
                continue
            if opcode == 0xA:
                return (0xA, data)
            if opcode in (0x1, 0x2):
                if fin:
                    self._frag_opcode = None
                    self._frag_chunks = bytearray()
                    return (opcode, data)
                self._frag_opcode = opcode
                self._frag_chunks = bytearray(data)
                continue
            if opcode == 0x0:
                self._frag_chunks.extend(data)
                if fin:
                    done_op = self._frag_opcode if self._frag_opcode is not None else 0x2
                    done_bytes = bytes(self._frag_chunks)
                    self._frag_opcode = None
                    self._frag_chunks = bytearray()
                    return (done_op, done_bytes)

    def recv_message_bytes(self) -> Optional[bytes]:
        while True:
            opcode, data = self.recv_frame()
            if opcode == 0x8:
                return None
            if opcode == 0xA:
                continue
            return data

    def recv_text(self) -> Optional[str]:
        raw = self.recv_message_bytes()
        if raw is None:
            return None
        return raw.decode("utf-8", errors="replace")

    def recv_json(self) -> Optional[Dict[str, Any]]:
        txt = self.recv_text()
        if txt is None:
            return None
        parsed = json.loads(txt)
        return parsed if isinstance(parsed, dict) else {"data": parsed}

    def cdp_call(self, method: str, params: Optional[Dict[str, Any]] = None, timeout: float = 15.0) -> Dict[str, Any]:
        """JSON-RPC request/response helper for local headless Chromium CDP sessions."""
        if self.sock is None:
            self.connect()
        assert self.sock is not None
        self.sock.settimeout(max(1.0, float(timeout)))
        cid = self._next_rpc_id
        self._next_rpc_id += 1
        self.send_json({"id": cid, "method": method, "params": params or {}})
        deadline = time.monotonic() + max(1.0, float(timeout))
        while time.monotonic() < deadline:
            doc = self.recv_json()
            if doc is None:
                raise ConnectionError("CDP WebSocket closed by browser")
            if doc.get("id") == cid:
                if "error" in doc:
                    raise RuntimeError(f"CDP {method} error: {doc['error']}")
                res = doc.get("result")
                return res if isinstance(res, dict) else {}
        raise TimeoutError(f"CDP {method} timed out after {timeout}s")

    def close(self) -> None:
        self.closed = True
        self.stop_network_watch()
        if self.sock is not None:
            with contextlib.suppress(Exception):
                close_frame = self._encode_masked_frame(b"", opcode=0x8, fin=True)
                with self._send_lock:
                    if self.sock is not None:
                        self.sock.sendall(close_frame)
            with contextlib.suppress(Exception):
                self.sock.close()
            self.sock = None


# Compatibility alias for guest_assist callers
StdlibWSSClient = StdlibWebSocketClient


# --- Cross-Platform Anti-Sleep Keepalive (`SleepInhibitor`) ---

class SYSTEM_POWER_STATUS(ctypes.Structure):
    _fields_ = [
        ("ACLineStatus", ctypes.c_ubyte),
        ("BatteryFlag", ctypes.c_ubyte),
        ("BatteryLifePercent", ctypes.c_ubyte),
        ("SystemStatusFlag", ctypes.c_ubyte),
        ("BatteryLifeTime", ctypes.c_uint32),
        ("BatteryFullLifeTime", ctypes.c_uint32),
    ]


def is_running_on_battery(*, _platform_override: Optional[str] = None) -> bool:
    """Detect whether the host is currently running on DC battery power (`True`) vs AC/desktop (`False`)."""
    plat = (_platform_override or sys.platform).lower()
    if plat == "win32":
        try:
            kernel32 = ctypes.windll.kernel32
            fn = kernel32.GetSystemPowerStatus
            with contextlib.suppress(Exception):
                fn.argtypes = [ctypes.POINTER(SYSTEM_POWER_STATUS)]
                fn.restype = ctypes.c_int
            sps = SYSTEM_POWER_STATUS()
            sps.ACLineStatus = 255
            ok = fn(ctypes.pointer(sps))
            if not ok:
                return False
            return int(sps.ACLineStatus) == 0
        except Exception:
            return False

    if plat == "darwin":
        pmset_bin = shutil.which("pmset") or "/usr/bin/pmset"
        try:
            proc = subprocess.run(
                [pmset_bin, "-g", "ps"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=2.0,
                creationflags=CREATE_NO_WINDOW if sys.platform == "win32" else 0,
                check=False,
            )
            return bool(proc.returncode == 0 and "Battery Power" in (proc.stdout or ""))
        except Exception:
            return False

    return False


def _default_win32_set_execution_state(flags: int) -> int:
    kernel32 = ctypes.windll.kernel32
    fn = kernel32.SetThreadExecutionState
    fn.argtypes = [ctypes.c_uint32]
    fn.restype = ctypes.c_uint32
    return int(fn(ctypes.c_uint32(flags)))


class SleepInhibitor:
    """
    Cross-platform system sleep inhibitor preventing 15-minute idle sleep disconnects while protecting laptop battery:
    - Windows: dedicated daemon thread polling `is_running_on_battery()`; holds
      `SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)` on AC/desktop power, automatically drops to
      `SetThreadExecutionState(ES_CONTINUOUS)` when switched to battery so lid-close sleeps normally, and restores
      anti-sleep automatically when AC power returns.
    - macOS: spawns windowless `caffeinate -i -w <pid>` while on AC power and pauses it while on Battery Power.
    - Linux: spawns optional `systemd-inhibit --what=idle:sleep --mode=block sleep infinity`.
    """

    def __init__(
        self,
        *,
        keep_display_on: bool = False,
        refresh_interval_sec: float = 30.0,
        reason: str = "Cosmos MCP active session keepalive",
        _platform_override: Optional[str] = None,
        _win32_setter: Optional[Callable[[int], int]] = None,
        _battery_probe: Optional[Callable[[], bool]] = None,
    ) -> None:
        self.keep_display_on = bool(keep_display_on)
        self.refresh_interval_sec = max(0.05, float(refresh_interval_sec))
        self.reason = reason
        self._platform = (_platform_override or sys.platform).lower()
        self._win32_setter = _win32_setter or _default_win32_set_execution_state
        self._battery_probe = _battery_probe
        self._lock = threading.RLock()
        self._enabled = False
        self._backend = "none"
        self._stop_evt = threading.Event()
        self._ready_evt = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._proc: Optional[subprocess.Popen[bytes]] = None
        self._last_error: str = ""
        self._started_at: Optional[float] = None
        self._win32_apply_count: int = 0
        self._on_battery: bool = False
        self._last_win32_flags: int = 0

    def _check_on_battery(self) -> bool:
        try:
            if self._battery_probe is not None:
                return bool(self._battery_probe())
            return bool(is_running_on_battery(_platform_override=self._platform))
        except Exception:
            return False

    def __enter__(self) -> "SleepInhibitor":
        self.enable()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.disable()

    def enable(self) -> Dict[str, Any]:
        with self._lock:
            if self._enabled:
                return self.status()

            self._last_error = ""
            if self._platform == "win32":
                self._stop_evt.clear()
                self._ready_evt.clear()
                active_flags = ES_CONTINUOUS | ES_SYSTEM_REQUIRED
                if self.keep_display_on:
                    active_flags |= ES_DISPLAY_REQUIRED
                init_ok = [False]
                err_box = [""]

                def _win_keepalive_worker() -> None:
                    try:
                        on_bat = self._check_on_battery()
                        eff_flags = ES_CONTINUOUS if on_bat else active_flags
                        prev = self._win32_setter(eff_flags)
                        if prev == 0:
                            err_box[0] = "SetThreadExecutionState returned NULL (0)"
                            self._ready_evt.set()
                            return
                        self._on_battery = on_bat
                        self._last_win32_flags = eff_flags
                        self._win32_apply_count += 1
                        init_ok[0] = True
                        self._ready_evt.set()
                        while not self._stop_evt.wait(timeout=self.refresh_interval_sec):
                            on_bat = self._check_on_battery()
                            eff_flags = ES_CONTINUOUS if on_bat else active_flags
                            self._win32_setter(eff_flags)
                            self._on_battery = on_bat
                            self._last_win32_flags = eff_flags
                            self._win32_apply_count += 1
                    except Exception as exc:
                        err_box[0] = str(exc)
                        self._ready_evt.set()
                    finally:
                        if init_ok[0]:
                            with contextlib.suppress(Exception):
                                self._win32_setter(ES_CONTINUOUS)
                            self._last_win32_flags = ES_CONTINUOUS

                t = threading.Thread(target=_win_keepalive_worker, name="cosmos-sleep-inhibitor", daemon=True)
                t.start()
                self._ready_evt.wait(timeout=3.0)
                if init_ok[0]:
                    self._thread = t
                    self._enabled = True
                    self._backend = "win32_thread_execution_state"
                    self._started_at = time.time()
                else:
                    self._stop_evt.set()
                    t.join(timeout=1.0)
                    self._last_error = err_box[0] or "win32 keepalive thread failed to start"
                    self._backend = "noop_error"
                return self.status()

            if self._platform == "darwin":
                caf = shutil.which("caffeinate")
                if not caf:
                    self._backend = "noop_unavailable"
                    self._last_error = "caffeinate binary not found on macOS"
                    return self.status()
                self._stop_evt.clear()
                cmd = [caf, "-i", "-w", str(os.getpid())]
                if self.keep_display_on:
                    cmd.insert(1, "-d")

                def _spawn_caf() -> Optional[subprocess.Popen[bytes]]:
                    return subprocess.Popen(
                        cmd,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                        creationflags=CREATE_NO_WINDOW if sys.platform == "win32" else 0,
                    )

                def _term_caf() -> None:
                    with self._lock:
                        p = self._proc
                        self._proc = None
                    if p is not None and p.poll() is None:
                        with contextlib.suppress(OSError):
                            p.terminate()
                        try:
                            p.wait(timeout=1.0)
                        except subprocess.TimeoutExpired:
                            with contextlib.suppress(OSError):
                                p.kill()
                                p.wait(timeout=0.5)

                try:
                    on_bat = self._check_on_battery()
                    self._on_battery = on_bat
                    if not on_bat:
                        self._proc = _spawn_caf()

                    def _mac_power_watcher() -> None:
                        while not self._stop_evt.wait(timeout=self.refresh_interval_sec):
                            bat_now = self._check_on_battery()
                            self._on_battery = bat_now
                            if bat_now:
                                _term_caf()
                            else:
                                with self._lock:
                                    need_spawn = self._enabled and (self._proc is None or self._proc.poll() is not None)
                                if need_spawn:
                                    with contextlib.suppress(OSError):
                                        p_new = _spawn_caf()
                                        with self._lock:
                                            self._proc = p_new

                    t_mac = threading.Thread(target=_mac_power_watcher, name="cosmos-mac-sleep-inhibitor", daemon=True)
                    t_mac.start()
                    self._thread = t_mac
                    self._enabled = True
                    self._backend = "macos_caffeinate"
                    self._started_at = time.time()
                except OSError as exc:
                    self._backend = "noop_error"
                    self._last_error = str(exc)
                return self.status()

            # Linux / POSIX optional `systemd-inhibit`
            inhibit_bin = shutil.which("systemd-inhibit")
            sleep_bin = shutil.which("sleep") or "/bin/sleep"
            if inhibit_bin and Path(sleep_bin).exists():
                cmd_lin = [
                    inhibit_bin,
                    "--what=idle:sleep",
                    "--who=CosmosMCP",
                    f"--why={self.reason}",
                    "--mode=block",
                    sleep_bin,
                    "infinity",
                ]
                try:
                    proc = subprocess.Popen(
                        cmd_lin,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                        creationflags=CREATE_NO_WINDOW if sys.platform == "win32" else 0,
                    )
                    time.sleep(0.05)
                    if proc.poll() is None:
                        self._proc = proc
                        self._enabled = True
                        self._backend = "linux_systemd_inhibit"
                        self._started_at = time.time()
                        return self.status()
                    self._last_error = f"systemd-inhibit exited immediately (rc={proc.returncode})"
                except OSError as exc:
                    self._last_error = str(exc)
            self._backend = "noop_unavailable"
            return self.status()

    def disable(self) -> Dict[str, Any]:
        with self._lock:
            self._stop_evt.set()
            if self._thread is not None:
                self._thread.join(timeout=2.0)
                self._thread = None
            if self._proc is not None:
                with contextlib.suppress(OSError):
                    self._proc.terminate()
                try:
                    self._proc.wait(timeout=1.5)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(OSError):
                        self._proc.kill()
                        self._proc.wait(timeout=1.0)
                self._proc = None
            self._enabled = False
            self._on_battery = False
            self._started_at = None
            return self.status()

    def status(self) -> Dict[str, Any]:
        with self._lock:
            if self._platform != "darwin" and self._proc is not None and self._proc.poll() is not None:
                self._enabled = False
                self._proc = None
            if self._thread is not None and not self._thread.is_alive():
                self._enabled = False
                self._thread = None
            out: Dict[str, Any] = {
                "enabled": self._enabled,
                "backend": self._backend,
                "platform": self._platform,
                "keep_display_on": self.keep_display_on,
                "on_battery": self._on_battery,
                "inhibiting_sleep": bool(self._enabled and not self._on_battery),
            }
            if self._started_at is not None and self._enabled:
                out["uptime_sec"] = round(max(0.0, time.time() - self._started_at), 2)
            if self._platform == "win32":
                out["apply_count"] = self._win32_apply_count
                out["execution_flags"] = self._last_win32_flags
            if self._proc is not None and self._proc.poll() is None:
                out["helper_pid"] = self._proc.pid
            if self._last_error:
                out["last_error"] = self._last_error
            return out
