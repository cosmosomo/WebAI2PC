"""Zero-Node/Git multi-source open skill & MCP market client with SSRF and TOCTOU guards.

Supports skills.sh, ClawHub, Official MCP Registry, GitHub repositories, and local
directories using only the Python >= 3.9 standard library.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import ssl
import time
from typing import Any, Dict, List, Optional, Pattern, Sequence, Set, Tuple, Union
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from cosmos_mcp.capabilities.skills.models import (
    FetchedSkillPackage,
    MarketCandidate,
    PACKAGE_VERSION,
    SecurityAuditReport,
    SkillsConfig,
    VirtualFileEntry,
    is_subpath,
)
from cosmos_mcp.capabilities.skills.parser_and_index import parse_skill_frontmatter
from cosmos_mcp.capabilities.skills.vetter import (
    ZipSecurityLimitError,
    _RESERVED_SKILL_SUBDIRS,
    _collect_local_dir_entries,
    _is_unsafe_rel_path,
    audit_package_entries,
    decode_text_with_bom_and_cookie,
    extract_zip_to_virtual_entries,
)

__all__ = [
    "MarketClient",
    "MarketError",
    "SSRFError",
    "parse_source_ref",
    "validate_public_https_url",
]


class SSRFError(ValueError):
    """Raised when an outbound URL violates public HTTPS or IP/domain SSRF boundaries."""


class MarketError(RuntimeError):
    """Raised when remote skill discovery, preview, or package retrieval fails."""


_MCP_UNSUPPORTED_PACKAGE_MSG = (
    "MCP server entries (mcp:...) are MCP server configurations rather than SKILL.md packages; "
    "inspect server metadata via discover."
)

_SKILLS_SH_BASE = "https://skills.sh"
_SKILLS_SH_AUDIT_URL = "https://www.skills.sh/tele/audit"
_CLAWHUB_BASE = "https://clawhub.ai"
_MCP_REGISTRY_BASE = "https://registry.modelcontextprotocol.io"
_GITHUB_API_BASE = "https://api.github.com"
_GITHUB_CODELOAD_BASE = "https://codeload.github.com"
_GITHUB_RAW_BASE = "https://raw.githubusercontent.com"

_SOURCE_ALIASES: Dict[str, str] = {
    "coinbase/agentwallet": "coinbase/agentic-wallet-skills",
    "vercel-labs/vercel-skills": "vercel-labs/agent-skills",
}

_FORBIDDEN_EXACT_HOSTS: Set[str] = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata",
    "metadata.google.internal",
    "instance-data",
    "wpad",
    "isatap",
    "localtest.me",
    "lvh.me",
    "vcap.me",
    "lacolhost.com",
    "nip.io",
    "sslip.io",
    "xip.io",
    "traefik.me",
    "1u.ms",
    "rbndr.us",
}

_FORBIDDEN_HOST_SUFFIXES: Tuple[str, ...] = (
    ".localhost",
    ".local",
    ".internal",
    ".lan",
    ".home.arpa",
    ".localdomain",
    ".corp",
    ".intranet",
    ".private",
    ".invalid",
    ".localtest.me",
    ".lvh.me",
    ".vcap.me",
    ".lacolhost.com",
    ".nip.io",
    ".sslip.io",
    ".xip.io",
    ".traefik.me",
    ".1u.ms",
    ".rbndr.us",
)

_CGNAT_IPV4_NET = ipaddress.ip_network("100.64.0.0/10")
_BENCHMARK_IPV4_NET = ipaddress.ip_network("198.18.0.0/15")
_NAT64_WELL_KNOWN_NET = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL_NET = ipaddress.ip_network("64:ff9b:1::/48")

_SHA40_RE: Pattern[str] = re.compile(r"^[0-9a-fA-F]{40}$")
_VERSION_PIN_RE: Pattern[str] = re.compile(r"^v?\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z._-]+)?$")
_WINDOWS_DRIVE_RE: Pattern[str] = re.compile(r"^[a-zA-Z]:[/\\]")
_NUMERIC_HOST_LABEL_RE: Pattern[str] = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)$")
_DASHED_IPV4_LABEL_RE: Pattern[str] = re.compile(r"(?<!\d)(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})(?!\d)")


def _validate_ip_address(ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address], original: str) -> None:
    if isinstance(ip_obj, ipaddress.IPv6Address):
        if ip_obj.ipv4_mapped is not None:
            _validate_ip_address(ip_obj.ipv4_mapped, original)
        if ip_obj.sixtofour is not None:
            _validate_ip_address(ip_obj.sixtofour, original)
        if ip_obj.teredo is not None:
            server_ip, client_ip = ip_obj.teredo
            _validate_ip_address(server_ip, original)
            _validate_ip_address(client_ip, original)
        if ip_obj in _NAT64_WELL_KNOWN_NET or ip_obj in _NAT64_LOCAL_NET:
            embedded_v4 = ipaddress.IPv4Address(int(ip_obj) & 0xFFFFFFFF)
            _validate_ip_address(embedded_v4, original)
            raise SSRFError(f"NAT64 translation IPv6 address blocked: {original}")

    if isinstance(ip_obj, ipaddress.IPv4Address):
        if ip_obj in _CGNAT_IPV4_NET or ip_obj in _BENCHMARK_IPV4_NET:
            raise SSRFError(f"Non-public carrier/benchmark IPv4 address blocked: {original}")

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
        or not ip_obj.is_global
    ):
        raise SSRFError(f"Non-public or reserved IP address blocked: {original}")


def _check_embedded_ip_in_hostname(labels: Sequence[str], raw_host: str) -> None:
    """Detect private/loopback/metadata IPv4 octets embedded inside wildcard DNS rebinding hostnames."""
    if len(labels) >= 5:
        for i in range(len(labels) - 4):
            quad = labels[i : i + 4]
            if all(q.isdigit() and 0 <= int(q) <= 255 for q in quad):
                cand_ip = ipaddress.IPv4Address(".".join(str(int(q)) for q in quad))
                _validate_ip_address(cand_ip, raw_host)

    for lbl in labels:
        for m in _DASHED_IPV4_LABEL_RE.finditer(lbl):
            octets = [int(g) for g in m.groups()]
            if all(0 <= oc <= 255 for oc in octets):
                cand_ip = ipaddress.IPv4Address(".".join(str(oc) for oc in octets))
                _validate_ip_address(cand_ip, raw_host)


def _resolve_and_validate_host_ips(host: str, port: int, raw_host: str, *, strict_dns: bool = False) -> List[str]:
    """Resolve `host` via `socket.getaddrinfo` and verify EVERY resolved IP is globally routable."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        if strict_dns:
            raise MarketError(f"DNS resolution failed for '{raw_host}': {exc}") from exc
        return []

    if not infos:
        if strict_dns:
            raise MarketError(f"DNS resolution returned no addresses for '{raw_host}'")
        return []

    validated_ips: List[str] = []
    for _, _, _, _, sockaddr in infos:
        if not sockaddr:
            continue
        addr_raw = str(sockaddr[0]).split("%", 1)[0]
        try:
            ip_obj = ipaddress.ip_address(addr_raw)
        except ValueError as exc:
            raise SSRFError(f"Unparseable resolved IP {addr_raw!r} for {raw_host}") from exc
        _validate_ip_address(ip_obj, f"{raw_host} ({addr_raw})")
        if addr_raw not in validated_ips:
            validated_ips.append(addr_raw)
    return validated_ips


def validate_public_https_url(
    url: str,
    *,
    resolve_dns: bool = True,
    strict_dns: bool = False,
) -> str:
    """Validate that `url` uses HTTPS and targets a public routable hostname or global IP."""
    if not isinstance(url, str) or not url:
        raise SSRFError("URL must be a non-empty string")
    if any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in url):
        raise SSRFError("URL contains whitespace or control characters")

    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "https":
        raise SSRFError(f"Only 'https://' URLs are permitted (got scheme={parsed.scheme!r})")
    if parsed.username is not None or parsed.password is not None:
        raise SSRFError("Embedded credentials in URLs are forbidden")

    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise SSRFError(f"Invalid URL port: {exc}") from exc

    raw_host = parsed.hostname
    if not raw_host:
        raise SSRFError("URL is missing a target hostname")
    if "%" in raw_host:
        raise SSRFError("IPv6 zone identifiers in URLs are forbidden")

    host = raw_host.rstrip(".").lower()
    if not host:
        raise SSRFError("URL hostname is empty")

    if host in _FORBIDDEN_EXACT_HOSTS or any(host.endswith(suf) for suf in _FORBIDDEN_HOST_SUFFIXES):
        raise SSRFError(f"Internal or wildcard rebinding hostname blocked: {raw_host}")

    # Check standard IPv4 / IPv6 literal first
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        ip_obj = None

    if ip_obj is not None:
        _validate_ip_address(ip_obj, raw_host)
        return url

    # Block obfuscated integer / hex / octal IPv4 literals (e.g. 2130706433, 0x7f.0.0.1, 0177.0.0.1)
    labels = host.split(".")
    if all(_NUMERIC_HOST_LABEL_RE.match(lbl) is not None for lbl in labels):
        raise SSRFError(f"Non-canonical numeric IP literal blocked: {raw_host}")

    if len(labels) < 2 or any(not lbl for lbl in labels):
        raise SSRFError(f"Single-label or malformed hostname blocked: {raw_host}")

    _check_embedded_ip_in_hostname(labels, raw_host)

    if resolve_dns:
        _resolve_and_validate_host_ips(host, port, raw_host, strict_dns=strict_dns)

    return url


class _SSRFSafeHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that validates DNS and peer socket IP to prevent 0-TTL DNS rebinding."""

    def connect(self) -> None:
        _resolve_and_validate_host_ips(self.host, self.port or 443, self.host, strict_dns=True)
        super().connect()
        if self.sock is not None:
            try:
                peer = self.sock.getpeername()
                if peer and peer[0]:
                    peer_ip_str = str(peer[0]).split("%", 1)[0]
                    _validate_ip_address(ipaddress.ip_address(peer_ip_str), f"{self.host} ({peer_ip_str})")
            except SSRFError:
                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None
                raise


class _SSRFSafeHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPSHandler using `_SSRFSafeHTTPSConnection` when connecting directly without proxy."""

    def __init__(self, context: Optional[ssl.SSLContext] = None) -> None:
        super().__init__(context=context)
        self._ssl_context = context

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(_SSRFSafeHTTPSConnection, req, context=self._ssl_context)


class _SafeHTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Enforce SSRF public-HTTPS validation across every HTTP 3xx redirect hop."""

    def __init__(self, *, resolve_dns: bool = True) -> None:
        super().__init__()
        self._resolve_dns = resolve_dns

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Optional[urllib.request.Request]:
        resolved_url = urllib.parse.urljoin(req.full_url, newurl)
        validate_public_https_url(
            resolved_url,
            resolve_dns=self._resolve_dns,
            strict_dns=self._resolve_dns,
        )
        return super().redirect_request(req, fp, code, msg, headers, resolved_url)


def _normalize_http_proxy(raw_proxy: Optional[str]) -> Optional[str]:
    if not raw_proxy:
        return None
    val = raw_proxy.strip()
    if not val:
        return None
    if "://" not in val:
        val = f"http://{val}"
    scheme = urllib.parse.urlsplit(val).scheme.lower()
    if scheme in ("http", "https"):
        return val
    return None


def _resolve_proxy_url(config: SkillsConfig) -> Optional[str]:
    """Resolve outbound HTTP(S) proxy from config, standard environment variables, or OS settings."""
    explicit = _normalize_http_proxy(config.proxy_url)
    if explicit:
        return explicit

    for env_key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        cand = _normalize_http_proxy(os.environ.get(env_key))
        if cand:
            return cand

    try:
        sys_proxies = urllib.request.getproxies()
    except Exception:
        sys_proxies = {}
    for key in ("https", "http"):
        cand = _normalize_http_proxy(sys_proxies.get(key))
        if cand:
            return cand
    return None


def _extract_frontmatter_name(md_text: str) -> str:
    """Extract canonical skill `name` via `parse_skill_frontmatter` (single source of truth)."""
    fm = parse_skill_frontmatter(md_text, fallback_name="")
    if not fm.get("has_frontmatter"):
        return ""
    raw = str(fm.get("name") or "").strip()
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", raw)
    if "/" in cleaned or "\\" in cleaned or ".." in cleaned:
        return ""
    return cleaned


def _normalize_source_name(src: str) -> str:
    low = src.strip().lower().replace("-", "_").replace(".", "_")
    aliases = {
        "skills_sh": "skills_sh",
        "skillssh": "skills_sh",
        "clawhub": "clawhub",
        "clawhub_ai": "clawhub",
        "mcp_registry": "mcp_registry",
        "mcpreg": "mcp_registry",
        "mcp": "mcp_registry",
        "github": "github",
    }
    return aliases.get(low, low)


def _is_version_or_sha_pin(val: str) -> bool:
    return bool(_SHA40_RE.match(val) or _VERSION_PIN_RE.match(val))


def parse_source_ref(
    source_ref: str,
    source_type: str = "auto",
    ref: str = "",
    subpath: str = "",
) -> Dict[str, str]:
    """Parse local path, ClawHub reference, skills.sh shorthand, or GitHub URL into normalized fields."""
    raw = (source_ref or "").strip()
    if not raw:
        raise ValueError("source_ref must not be empty")

    explicit_type = (source_type or "auto").strip().lower()
    if explicit_type in ("skills.sh", "skillssh"):
        explicit_type = "skills_sh"

    # 0. Friendly guard on Official MCP Registry server entries (`mcp:...`)
    if raw.lower().startswith("mcp:") or explicit_type in ("mcp", "mcp_registry", "mcpreg"):
        raise MarketError(_MCP_UNSUPPORTED_PACKAGE_MSG)

    # 1. Local directory detection
    is_local_syntax = (
        raw in (".", "..")
        or raw.startswith(("./", "../", ".\\", "..\\", "/", "\\", "~"))
        or bool(_WINDOWS_DRIVE_RE.match(raw))
    )
    if explicit_type == "local" or (explicit_type == "auto" and (is_local_syntax or os.path.isdir(raw))):
        resolved_local = Path(raw).expanduser().resolve()
        return {
            "source_type": "local",
            "local_path": str(resolved_local),
            "owner": "",
            "repo": "",
            "slug": resolved_local.name,
            "version": "",
            "ref": ref.strip(),
            "subpath": subpath.strip().replace("\\", "/").strip("/"),
            "skill_filter": "",
            "frag_ambiguous": "",
        }

    # 2. ClawHub detection (`clawhub:...`, `@owner/slug`, `https://clawhub.ai/...`, or explicit source_type='clawhub')
    if (
        explicit_type == "clawhub"
        or raw.lower().startswith("clawhub:")
        or raw.lower().startswith("https://clawhub.ai/")
        or (raw.startswith("@") and "/" in raw)
    ):
        body = raw
        if body.lower().startswith("clawhub:"):
            body = body[len("clawhub:") :].strip()
        elif body.lower().startswith("https://clawhub.ai/"):
            u = urllib.parse.urlsplit(body)
            segs = [urllib.parse.unquote(s) for s in u.path.split("/") if s]
            # Patterns: `/<owner>/skills/<slug>` or `/skills/<slug>` or `/<owner>/<slug>`
            if len(segs) >= 3 and segs[1] == "skills":
                body = f"{segs[0].lstrip('@')}/{segs[2]}"
            elif len(segs) >= 2 and segs[0] == "skills":
                body = segs[1]
            elif len(segs) >= 2:
                body = f"{segs[0].lstrip('@')}/{segs[1]}"
            elif len(segs) == 1:
                body = segs[0]

        ver = ref.strip()
        if "@" in body and not body.startswith("@"):
            body, ver_part = body.rsplit("@", 1)
            if not ver:
                ver = ver_part.strip()
        elif body.startswith("@"):
            body_no_lead = body[1:]
            if "@" in body_no_lead:
                body_no_lead, ver_part = body_no_lead.rsplit("@", 1)
                if not ver:
                    ver = ver_part.strip()
            body = body_no_lead

        parts = [p.lstrip("@") for p in body.strip("/").split("/") if p]
        if len(parts) >= 2:
            owner, slug = parts[0], parts[1]
        elif len(parts) == 1:
            owner, slug = "", parts[0]
        else:
            raise ValueError(f"Invalid ClawHub reference: {source_ref!r}")

        return {
            "source_type": "clawhub",
            "local_path": "",
            "owner": owner,
            "repo": "",
            "slug": slug,
            "version": ver,
            "ref": ver,
            "subpath": subpath.strip().replace("\\", "/").strip("/"),
            "skill_filter": "",
            "frag_ambiguous": "",
        }

    # 3. `https://skills.sh/<owner>/<repo>/<skill>` URLs
    if raw.lower().startswith(("https://skills.sh/", "https://www.skills.sh/")):
        u = urllib.parse.urlsplit(raw)
        segs = [urllib.parse.unquote(s) for s in u.path.split("/") if s]
        if len(segs) >= 3:
            return {
                "source_type": "skills_sh",
                "local_path": "",
                "owner": segs[0],
                "repo": segs[1],
                "slug": segs[2],
                "version": "",
                "ref": ref.strip(),
                "subpath": subpath.strip().replace("\\", "/").strip("/"),
                "skill_filter": segs[2],
                "frag_ambiguous": "",
            }

    # 4. GitHub URLs (`https://github.com/owner/repo` or `/tree/<ref>/<subpath>` or `/blob/<ref>/<subpath>/SKILL.md`)
    if raw.lower().startswith("github:"):
        raw = raw[len("github:") :].strip()

    frag_ref = ""
    if "#" in raw and not raw.lower().startswith("https://"):
        raw, frag_ref = raw.split("#", 1)
        frag_ref = urllib.parse.unquote(frag_ref).strip()

    if raw.lower().startswith("https://github.com/"):
        u = urllib.parse.urlsplit(raw)
        if u.fragment and not frag_ref:
            frag_ref = urllib.parse.unquote(u.fragment).strip()
        segs = [urllib.parse.unquote(s) for s in u.path.split("/") if s]
        if len(segs) < 2:
            raise ValueError(f"Invalid GitHub repository URL: {source_ref!r}")
        owner = segs[0]
        repo = segs[1][:-4] if segs[1].endswith(".git") else segs[1]
        parsed_ref = ref.strip() or frag_ref
        parsed_subpath = subpath.strip().replace("\\", "/").strip("/")
        from_tree_url = False

        if len(segs) >= 4 and segs[2] in ("tree", "blob"):
            from_tree_url = True
            if not parsed_ref:
                parsed_ref = segs[3]
            tail_segs = segs[4:]
            if segs[2] == "blob" and tail_segs and tail_segs[-1].lower() in ("skill.md", "skills.md"):
                tail_segs = tail_segs[:-1]
            url_sub = "/".join(tail_segs)
            if url_sub and not parsed_subpath:
                parsed_subpath = url_sub

        if parsed_subpath and _is_unsafe_rel_path(parsed_subpath):
            raise ValueError(f"Unsafe subpath in GitHub URL: {parsed_subpath!r}")

        is_ambig_frag = bool(
            frag_ref
            and not ref.strip()
            and not from_tree_url
            and not parsed_subpath
            and not _is_version_or_sha_pin(frag_ref)
        )
        return {
            "source_type": "skills_sh" if explicit_type == "skills_sh" else "github",
            "local_path": "",
            "owner": owner,
            "repo": repo,
            "slug": PurePosixPath(parsed_subpath).name if parsed_subpath else repo,
            "version": "",
            "ref": parsed_ref,
            "subpath": parsed_subpath,
            "skill_filter": "",
            "frag_ambiguous": "1" if is_ambig_frag else "",
        }

    # Reject any non-HTTPS URLs (e.g. http://...) through SSRF validator if it looks like a URL
    if "://" in raw:
        validate_public_https_url(raw, resolve_dns=False)
        raise ValueError(f"Unsupported remote skill URL host: {source_ref!r}")

    # 5. GitHub / skills.sh shorthand (`owner/repo`, `owner/repo@skill`, `owner/repo@v1.0.0`, `owner/repo/subpath`)
    at_suffix = ""
    if "@" in raw:
        raw, at_suffix = raw.rsplit("@", 1)
        at_suffix = at_suffix.strip()

    clean_repo_path = raw.strip().strip("/")
    segs = [s for s in clean_repo_path.split("/") if s]
    if len(segs) < 2:
        raise ValueError(f"Unrecognized skill source reference: {source_ref!r}")

    owner, repo = segs[0], segs[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    alias_target = _SOURCE_ALIASES.get(f"{owner}/{repo}".lower())
    if alias_target:
        owner, repo = alias_target.split("/", 1)

    parsed_ref = ref.strip() or frag_ref
    parsed_subpath = subpath.strip().replace("\\", "/").strip("/")
    skill_filter = ""
    pinned_via_at = False

    if len(segs) > 2 and not parsed_subpath:
        parsed_subpath = "/".join(segs[2:])

    if at_suffix:
        if _is_version_or_sha_pin(at_suffix) and not ref.strip():
            parsed_ref = at_suffix
            pinned_via_at = True
        else:
            skill_filter = at_suffix

    if parsed_subpath and _is_unsafe_rel_path(parsed_subpath):
        raise ValueError(f"Unsafe skill subpath: {parsed_subpath!r}")
    if skill_filter and _is_unsafe_rel_path(skill_filter):
        raise ValueError(f"Unsafe skill filter: {skill_filter!r}")

    is_ambig_frag = bool(
        frag_ref
        and not ref.strip()
        and not pinned_via_at
        and not skill_filter
        and not parsed_subpath
        and not _is_version_or_sha_pin(frag_ref)
    )
    inferred_type = explicit_type if explicit_type in ("github", "skills_sh") else (
        "skills_sh" if skill_filter else "github"
    )
    slug = skill_filter or (PurePosixPath(parsed_subpath).name if parsed_subpath else repo)
    return {
        "source_type": inferred_type,
        "local_path": "",
        "owner": owner,
        "repo": repo,
        "slug": slug,
        "version": "",
        "ref": parsed_ref,
        "subpath": parsed_subpath,
        "skill_filter": skill_filter,
        "frag_ambiguous": "1" if is_ambig_frag else "",
    }


def _find_skill_subpaths_in_zip(zip_bytes: bytes) -> Tuple[Optional[str], List[Tuple[str, str]]]:
    """Return `(common_top_wrapper, [(repo_rel_skill_dir, zip_member_skill_md_path), ...])` without unpacking all files."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        safe_files: List[str] = []
        for inf in zf.infolist():
            if inf.filename.endswith(("/", "\\")) or inf.is_dir():
                continue
            if not _is_unsafe_rel_path(inf.filename):
                norm_m = inf.filename.replace("\\", "/")
                while norm_m.startswith("./"):
                    norm_m = norm_m[2:]
                safe_files.append(norm_m)

        first_segs: Set[str] = set()
        all_nested = True
        has_root_md = False
        for p in safe_files:
            parts = [s for s in p.split("/") if s and s != "."]
            if not parts:
                continue
            if len(parts) == 1 and parts[0].lower() in ("skill.md", "skills.md"):
                has_root_md = True
            if len(parts) < 2:
                all_nested = False
            first_segs.add(parts[0])

        common_top: Optional[str] = None
        if not has_root_md and all_nested and len(first_segs) == 1:
            cand = next(iter(first_segs))
            if cand.lower() not in _RESERVED_SKILL_SUBDIRS:
                common_top = cand

        prefix = f"{common_top}/" if common_top else ""
        skill_mds: List[Tuple[str, str]] = []
        for p in safe_files:
            rel_repo = p[len(prefix) :] if (prefix and p.startswith(prefix)) else p
            pp = PurePosixPath(rel_repo)
            if pp.name.lower() in ("skill.md", "skills.md"):
                parent_str = "" if str(pp.parent) == "." else str(pp.parent)
                skill_mds.append((parent_str, p))

        return common_top, skill_mds


class MarketClient:
    """Dependency-free open skill and MCP registry client with SSRF & single-pass memory guarantees."""

    def __init__(self, config: Optional[SkillsConfig] = None) -> None:
        self.config: SkillsConfig = config or SkillsConfig()

    def _is_authorized_local_source(self, target_dir: Path) -> bool:
        """Enforce workspace containment for local package fetches when `restrict_to_workspaces=True`."""
        if not self.config.restrict_to_workspaces:
            return True
        if self.config.is_within_workspaces(target_dir):
            return True
        if is_subpath(target_dir, self.config.managed_skills_store()):
            return True
        for extra in self.config.extra_readonly_roots:
            if is_subpath(target_dir, extra):
                return True
        if self.config.auto_discover_host_roots and self.config.tier_level >= 3:
            for _, hp in self.config.host_skill_roots():
                if is_subpath(target_dir, hp):
                    return True
        return False

    def _request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        timeout_sec: Optional[float] = None,
        max_bytes: Optional[int] = None,
    ) -> Tuple[int, Dict[str, str], bytes]:
        proxy_url = _resolve_proxy_url(self.config)
        do_live_dns = (self.config.http_transport is None) and (proxy_url is None)
        validate_public_https_url(url, resolve_dns=do_live_dns, strict_dns=do_live_dns)

        req_headers: Dict[str, str] = {
            "User-Agent": f"cosmos-skills/{PACKAGE_VERSION}",
            "Accept": "application/json, text/plain, */*",
        }
        if headers:
            req_headers.update(headers)

        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        if host == "api.github.com" and "Authorization" not in req_headers:
            gh_tok = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
            if gh_tok:
                req_headers["Authorization"] = f"Bearer {gh_tok}"
            req_headers.setdefault("Accept", "application/vnd.github+json")

        timeout = float(timeout_sec if timeout_sec is not None else self.config.http_timeout_sec)
        byte_cap = int(max_bytes if max_bytes is not None else self.config.max_archive_bytes)

        if self.config.http_transport is not None:
            status, raw_hdrs, resp_bytes = self.config.http_transport(
                method.upper(),
                url,
                req_headers,
                body,
                timeout,
                proxy_url,
            )
            if len(resp_bytes) > byte_cap:
                raise ZipSecurityLimitError(
                    f"Response body ({len(resp_bytes)} bytes) exceeds limit ({byte_cap} bytes)"
                )
            norm_hdrs = {str(k).lower(): str(v) for k, v in (raw_hdrs or {}).items()}
            return int(status), norm_hdrs, resp_bytes

        handlers: List[Any] = [
            urllib.request.ProxyHandler({"https": proxy_url, "http": proxy_url} if proxy_url else {}),
            _SafeHTTPSRedirectHandler(resolve_dns=do_live_dns),
        ]
        if do_live_dns:
            handlers.append(_SSRFSafeHTTPSHandler())

        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, data=body, headers=req_headers, method=method.upper())
        try:
            with opener.open(req, timeout=timeout) as resp:
                validate_public_https_url(resp.geturl(), resolve_dns=do_live_dns, strict_dns=False)
                data = resp.read(byte_cap + 1)
                if len(data) > byte_cap:
                    raise ZipSecurityLimitError(
                        f"Response body from {url} exceeds limit ({byte_cap} bytes)"
                    )
                resp_hdrs = {str(k).lower(): str(v) for k, v in resp.headers.items()}
                return int(resp.getcode() or 200), resp_hdrs, data
        except urllib.error.HTTPError as exc:
            try:
                err_body = exc.read(min(byte_cap, 262_144))
            except Exception:
                err_body = b""
            err_hdrs = {str(k).lower(): str(v) for k, v in (exc.headers.items() if exc.headers else [])}
            return int(exc.code), err_hdrs, err_body
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, SSRFError):
                raise exc.reason from exc
            raise MarketError(f"HTTP {method.upper()} {url} failed: {type(exc).__name__}: {exc}") from exc
        except (SSRFError, ZipSecurityLimitError, MarketError):
            raise
        except Exception as exc:
            raise MarketError(f"HTTP {method.upper()} {url} failed: {type(exc).__name__}: {exc}") from exc

    def _request_json(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout_sec: Optional[float] = None,
    ) -> Tuple[int, Any]:
        status, _, raw = self._request(
            "GET",
            url,
            headers=headers,
            timeout_sec=timeout_sec,
            max_bytes=min(self.config.max_archive_bytes, 4 * 1024 * 1024),
        )
        if not raw:
            return status, {}
        try:
            return status, json.loads(raw.decode("utf-8", "replace"))
        except ValueError as exc:
            if 200 <= status < 300:
                raise MarketError(f"Invalid JSON from {url}: {exc}") from exc
            return status, {"error": raw.decode("utf-8", "replace")[:240]}

    # ------------------------------------------------------------------
    # Multi-source discovery
    # ------------------------------------------------------------------
    def _discover_skills_sh(self, q_clean: str, limit: int) -> Tuple[List[MarketCandidate], Dict[str, Any]]:
        t0 = time.perf_counter()
        if len(q_clean) < 2:
            return [], {
                "source": "skills_sh",
                "ok": True,
                "skipped": True,
                "notice": "skills.sh search requires at least 2 characters; skipped.",
                "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
                "count": 0,
            }

        q_enc = urllib.parse.quote_plus(q_clean)
        url = f"{_SKILLS_SH_BASE}/api/search?q={q_enc}&limit={max(1, min(limit, 50))}"
        status, payload = self._request_json(url)
        if status != 200 or not isinstance(payload, dict):
            err_msg = payload.get("error", f"HTTP {status}") if isinstance(payload, dict) else f"HTTP {status}"
            return [], {
                "source": "skills_sh",
                "ok": False,
                "skipped": False,
                "error": str(err_msg),
                "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
                "count": 0,
            }

        raw_skills = payload.get("skills") or []
        candidates: List[MarketCandidate] = []
        for item in raw_skills[:limit]:
            if not isinstance(item, dict):
                continue
            cid = str(item.get("id") or "")
            repo_src = str(item.get("source") or "")
            skill_id = str(item.get("skillId") or item.get("name") or "")
            name = str(item.get("name") or skill_id or cid)
            owner = repo_src.split("/", 1)[0] if "/" in repo_src else repo_src
            install_ref = f"{repo_src}@{skill_id}" if ("/" in repo_src and skill_id) else (repo_src or cid)
            source_url = f"{_SKILLS_SH_BASE}/{cid}" if cid else (
                f"https://github.com/{repo_src}" if "/" in repo_src else _SKILLS_SH_BASE
            )
            candidates.append(
                MarketCandidate(
                    source="skills_sh",
                    id=cid or install_ref,
                    name=name,
                    owner=owner,
                    summary="",
                    source_url=source_url,
                    install_ref=install_ref,
                    version="",
                    popularity=int(item.get("installs") or 0),
                    kind="skill",
                    audit_info={},
                    extra={"repo": repo_src, "skill_id": skill_id},
                )
            )

        # Best-effort upstream risk summary enrichment via www.skills.sh/tele/audit for top hits
        repo_groups: Dict[str, List[MarketCandidate]] = {}
        for cand in candidates[: min(len(candidates), 5)]:
            repo_src = str(cand.extra.get("repo") or "")
            slug = str(cand.extra.get("skill_id") or cand.name)
            if "/" in repo_src and slug:
                repo_groups.setdefault(repo_src, []).append(cand)

        for repo_src, group in list(repo_groups.items())[:3]:
            slugs_csv = ",".join(str(c.extra.get("skill_id") or c.name) for c in group)
            audit_url = (
                f"{_SKILLS_SH_AUDIT_URL}?source={urllib.parse.quote(repo_src, safe='/')}"
                f"&skills={urllib.parse.quote(slugs_csv, safe=',')}"
            )
            try:
                a_status, a_payload = self._request_json(
                    audit_url,
                    timeout_sec=min(self.config.http_timeout_sec, 3.5),
                )
                if a_status == 200 and isinstance(a_payload, dict):
                    for cand in group:
                        slug = str(cand.extra.get("skill_id") or cand.name)
                        if isinstance(a_payload.get(slug), dict):
                            cand.audit_info = dict(a_payload[slug])
            except Exception:
                pass

        return candidates, {
            "source": "skills_sh",
            "ok": True,
            "skipped": False,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
            "count": len(candidates),
        }

    def _discover_clawhub(self, q_clean: str, limit: int) -> Tuple[List[MarketCandidate], Dict[str, Any]]:
        t0 = time.perf_counter()
        capped = max(1, min(limit, 50))
        if q_clean:
            url = f"{_CLAWHUB_BASE}/api/v1/search?q={urllib.parse.quote_plus(q_clean)}&limit={capped}"
        else:
            url = f"{_CLAWHUB_BASE}/api/v1/skills?limit={min(capped, 25)}&sort=downloads"

        status, payload = self._request_json(url)
        if status != 200 or not isinstance(payload, dict):
            err_msg = payload.get("error", f"HTTP {status}") if isinstance(payload, dict) else f"HTTP {status}"
            return [], {
                "source": "clawhub",
                "ok": False,
                "skipped": False,
                "error": str(err_msg),
                "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
                "count": 0,
            }

        raw_items = payload.get("results") or payload.get("items") or payload.get("skills") or []
        candidates: List[MarketCandidate] = []
        for item in raw_items[:limit]:
            if not isinstance(item, dict):
                continue
            native_skill = ((item.get("native") or {}).get("skill")) if isinstance(item.get("native"), dict) else None
            slug = str(
                item.get("slug")
                or (native_skill.get("slug") if isinstance(native_skill, dict) else "")
                or ""
            )
            owner = str(
                item.get("ownerHandle")
                or ((item.get("owner") or {}).get("handle") if isinstance(item.get("owner"), dict) else "")
                or ((item.get("publisher") or {}).get("handle") if isinstance(item.get("publisher"), dict) else "")
                or ""
            )
            disp_name = str(item.get("displayName") or slug or item.get("id") or "")
            summary = str(
                item.get("summary")
                or (native_skill.get("summary") if isinstance(native_skill, dict) else "")
                or ""
            )
            install_info = item.get("install") if isinstance(item.get("install"), dict) else {}
            ref_str = str(install_info.get("reference") or (f"{owner}/{slug}" if owner and slug else slug))
            install_ref = f"clawhub:{owner}/{slug}" if owner and slug else (f"clawhub:{ref_str}" if ref_str else "")
            canonical = str(
                item.get("canonicalUrl")
                or ((item.get("links") or {}).get("canonical") if isinstance(item.get("links"), dict) else "")
                or ""
            )
            if canonical.startswith("/"):
                source_url = f"{_CLAWHUB_BASE}{canonical}"
            elif canonical.startswith("https://"):
                source_url = canonical
            elif owner and slug:
                source_url = f"{_CLAWHUB_BASE}/{owner}/skills/{slug}"
            else:
                source_url = _CLAWHUB_BASE

            ver = str(item.get("version") or item.get("latestVersion") or "")
            stats = item.get("stats") if isinstance(item.get("stats"), dict) else {}
            metrics = item.get("metrics") if isinstance(item.get("metrics"), dict) else {}
            popularity = int(
                item.get("downloads")
                or stats.get("downloads")
                or metrics.get("rolling60DayInstalls")
                or 0
            )
            trust = dict(item["trust"]) if isinstance(item.get("trust"), dict) else {}
            cid = str(item.get("id") or (f"{owner}/{slug}" if owner and slug else slug))

            candidates.append(
                MarketCandidate(
                    source="clawhub",
                    id=cid,
                    name=disp_name,
                    owner=owner,
                    summary=summary,
                    source_url=source_url,
                    install_ref=install_ref,
                    version=ver,
                    popularity=popularity,
                    kind="skill",
                    audit_info=trust,
                    extra={"slug": slug, "owner_handle": owner},
                )
            )

        return candidates, {
            "source": "clawhub",
            "ok": True,
            "skipped": False,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
            "count": len(candidates),
        }

    def _discover_mcp_registry(self, q_clean: str, limit: int) -> Tuple[List[MarketCandidate], Dict[str, Any]]:
        t0 = time.perf_counter()
        # Official MCP Registry returns HTTP 422 when `search` has < 3 trimmed characters.
        # Automatically fetch the first active page without `search` and filter locally.
        local_filter = len(q_clean) < 3
        if local_filter:
            fetch_limit = min(max(limit * 4, 50), 100)
            url = f"{_MCP_REGISTRY_BASE}/v0.1/servers?version=latest&limit={fetch_limit}"
        else:
            fetch_limit = min(max(limit * 2, 20), 100)
            url = (
                f"{_MCP_REGISTRY_BASE}/v0.1/servers"
                f"?search={urllib.parse.quote_plus(q_clean)}&version=latest&limit={fetch_limit}"
            )

        status, payload = self._request_json(url)
        if status != 200 or not isinstance(payload, dict):
            err_msg = payload.get("detail") or payload.get("error") or f"HTTP {status}" if isinstance(payload, dict) else f"HTTP {status}"
            return [], {
                "source": "mcp_registry",
                "ok": False,
                "skipped": False,
                "error": str(err_msg),
                "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
                "count": 0,
            }

        raw_servers = payload.get("servers") or []
        q_low = q_clean.lower()
        candidates: List[MarketCandidate] = []

        for entry in raw_servers:
            if not isinstance(entry, dict):
                continue
            srv = entry.get("server") if isinstance(entry.get("server"), dict) else entry
            meta_root = entry.get("_meta") if isinstance(entry.get("_meta"), dict) else {}
            official_meta = (
                meta_root.get("io.modelcontextprotocol.registry/official")
                if isinstance(meta_root.get("io.modelcontextprotocol.registry/official"), dict)
                else {}
            )
            srv_status = str(official_meta.get("status") or "active").lower()
            if srv_status != "active":
                continue

            srv_name = str(srv.get("name") or "")
            if not srv_name:
                continue
            title = str(srv.get("title") or (srv_name.split("/", 1)[1] if "/" in srv_name else srv_name))
            desc = str(srv.get("description") or "")
            repo_obj = srv.get("repository") if isinstance(srv.get("repository"), dict) else {}
            repo_url = str(repo_obj.get("url") or "")

            if local_filter and q_low:
                haystack = f"{srv_name} {title} {desc} {repo_url}".lower()
                if q_low not in haystack:
                    continue

            owner = srv_name.split("/", 1)[0] if "/" in srv_name else ""
            ver = str(srv.get("version") or "")
            encoded_name = urllib.parse.quote(srv_name, safe="")
            web_url = str(
                srv.get("websiteUrl")
                or repo_url
                or f"{_MCP_REGISTRY_BASE}/v0.1/servers/{encoded_name}/versions/latest"
            )
            packages = list(srv.get("packages") or [])
            remotes = list(srv.get("remotes") or [])

            candidates.append(
                MarketCandidate(
                    source="mcp_registry",
                    id=srv_name,
                    name=title,
                    owner=owner,
                    summary=desc,
                    source_url=web_url,
                    install_ref=f"mcp:{srv_name}@{ver}" if ver else f"mcp:{srv_name}",
                    version=ver,
                    popularity=0,
                    kind="mcp_server",
                    audit_info={"status": srv_status},
                    extra={
                        "packages": packages,
                        "remotes": remotes,
                        "repository": repo_obj,
                    },
                )
            )
            if len(candidates) >= limit:
                break

        meta_out: Dict[str, Any] = {
            "source": "mcp_registry",
            "ok": True,
            "skipped": False,
            "local_short_query_filter": local_filter,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
            "count": len(candidates),
        }
        return candidates, meta_out

    def _discover_github(self, q_clean: str, limit: int) -> Tuple[List[MarketCandidate], Dict[str, Any]]:
        t0 = time.perf_counter()
        q_term = f"{q_clean} SKILL.md".strip()
        url = (
            f"{_GITHUB_API_BASE}/search/repositories"
            f"?q={urllib.parse.quote_plus(q_term)}&per_page={max(1, min(limit, 30))}"
        )
        status, payload = self._request_json(url)
        if status != 200 or not isinstance(payload, dict):
            err_msg = payload.get("message", f"HTTP {status}") if isinstance(payload, dict) else f"HTTP {status}"
            return [], {
                "source": "github",
                "ok": False,
                "skipped": False,
                "error": str(err_msg),
                "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
                "count": 0,
            }

        candidates: List[MarketCandidate] = []
        for item in (payload.get("items") or [])[:limit]:
            if not isinstance(item, dict):
                continue
            full_name = str(item.get("full_name") or "")
            name = str(item.get("name") or full_name)
            owner = str(((item.get("owner") or {}).get("login")) if isinstance(item.get("owner"), dict) else "")
            if not owner and "/" in full_name:
                owner = full_name.split("/", 1)[0]
            candidates.append(
                MarketCandidate(
                    source="github",
                    id=full_name,
                    name=name,
                    owner=owner,
                    summary=str(item.get("description") or ""),
                    source_url=str(item.get("html_url") or f"https://github.com/{full_name}"),
                    install_ref=full_name,
                    version=str(item.get("default_branch") or ""),
                    popularity=int(item.get("stargazers_count") or 0),
                    kind="skill",
                )
            )

        return candidates, {
            "source": "github",
            "ok": True,
            "skipped": False,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
            "count": len(candidates),
        }

    def discover(
        self,
        query: str,
        sources: Sequence[str] = ("skills_sh", "clawhub", "mcp_registry"),
        limit: int = 10,
    ) -> Dict[str, Any]:
        """Concurrently search configured registries, rank, and cap merged results to `limit`."""
        q_clean = (query or "").strip()
        eff_limit = max(0, int(limit))
        per_source_limit = max(1, eff_limit)
        norm_sources: List[str] = []
        for s in sources:
            ns = _normalize_source_name(s)
            if ns and ns not in norm_sources:
                norm_sources.append(ns)

        dispatch = {
            "skills_sh": self._discover_skills_sh,
            "clawhub": self._discover_clawhub,
            "mcp_registry": self._discover_mcp_registry,
            "github": self._discover_github,
        }

        def _run_one(src_key: str) -> Tuple[str, List[MarketCandidate], Dict[str, Any]]:
            fn = dispatch.get(src_key)
            if fn is None:
                return src_key, [], {
                    "source": src_key,
                    "ok": False,
                    "skipped": True,
                    "error": f"Unsupported market source: {src_key}",
                    "count": 0,
                }
            try:
                cands, meta = fn(q_clean, per_source_limit)
                return src_key, cands, meta
            except SSRFError:
                raise
            except Exception as exc:
                return src_key, [], {
                    "source": src_key,
                    "ok": False,
                    "skipped": False,
                    "error": f"{type(exc).__name__}: {exc}",
                    "count": 0,
                }

        t_start = time.perf_counter()
        ranked_pool: List[Tuple[Tuple[int, int, int, int], MarketCandidate]] = []
        by_source: Dict[str, Dict[str, Any]] = {}
        errors: Dict[str, str] = {}
        q_low = q_clean.lower()

        max_workers = max(1, min(len(norm_sources), 4))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(_run_one, sk) for sk in norm_sources]
            for src_idx, fut in enumerate(futures):
                src_key, cands, meta = fut.result()
                cand_dicts = [c.to_dict() for c in cands]
                meta_with_items = dict(meta)
                meta_with_items["items"] = cand_dicts
                by_source[src_key] = meta_with_items
                if not meta.get("ok", False) and meta.get("error"):
                    errors[src_key] = str(meta["error"])
                for item_rank, cand in enumerate(cands):
                    nm_low = cand.name.lower()
                    slug_low = str(cand.extra.get("slug") or cand.extra.get("skill_id") or "").lower()
                    exact = 0 if (q_low and (nm_low == q_low or slug_low == q_low)) else 1
                    ranked_pool.append(((exact, item_rank, src_idx, -cand.popularity), cand))

        ranked_pool.sort(key=lambda pair: pair[0])
        merged_candidates = [pair[1] for pair in ranked_pool[:eff_limit]]

        return {
            "query": query,
            "total": len(merged_candidates),
            "elapsed_ms": round((time.perf_counter() - t_start) * 1000, 1),
            "candidates": [c.to_dict() for c in merged_candidates],
            "by_source": by_source,
            "errors": errors,
        }

    # ------------------------------------------------------------------
    # ClawHub helpers
    # ------------------------------------------------------------------
    def _fetch_clawhub_verify(self, slug: str, owner: str = "", version: str = "") -> Dict[str, Any]:
        params: List[Tuple[str, str]] = []
        if owner:
            params.append(("ownerHandle", owner))
        if version:
            params.append(("version", version))
        qs = f"?{urllib.parse.urlencode(params)}" if params else ""
        url = f"{_CLAWHUB_BASE}/api/v1/skills/{urllib.parse.quote(slug, safe='')}/verify{qs}"
        try:
            status, payload = self._request_json(url)
            if status == 200 and isinstance(payload, dict):
                return payload
        except Exception:
            pass
        return {}

    def _apply_clawhub_upstream_verdict(
        self,
        report: SecurityAuditReport,
        verify_data: Dict[str, Any],
    ) -> None:
        if not verify_data:
            return
        sec = verify_data.get("security") if isinstance(verify_data.get("security"), dict) else {}
        verdict = str(sec.get("verdict") or "").lower()
        decision = str(verify_data.get("decision") or "").lower()
        if decision in ("block", "reject", "fail") or verdict == "malicious":
            report.add(
                "BLOCK",
                "UPSTREAM_CLAWHUB_MALWARE_BLOCK",
                "SKILL.md",
                f"ClawHub upstream verification flagged skill (decision={decision!r}, verdict={verdict!r})",
            )
        elif verdict == "suspicious":
            report.add(
                "WARN",
                "UPSTREAM_CLAWHUB_SUSPICIOUS",
                "SKILL.md",
                f"ClawHub upstream verification marked skill as suspicious: {sec.get('summary', '')[:160]}",
            )

    def _fallback_clawhub_single_file_preview(self, parsed: Dict[str, str]) -> Dict[str, Any]:
        """Fallback to single-file SKILL.md preview when ClawHub ZIP download is unavailable, marking partial_preview=True."""
        slug = parsed["slug"]
        owner = parsed["owner"]
        version = parsed["version"]

        verify_data = self._fetch_clawhub_verify(slug=slug, owner=owner, version=version)
        resolved_ver = version or str(verify_data.get("version") or "")

        file_params: List[Tuple[str, str]] = [("path", "SKILL.md")]
        if owner:
            file_params.append(("ownerHandle", owner))
        if resolved_ver:
            file_params.append(("version", resolved_ver))
        qs = urllib.parse.urlencode(file_params)

        primary_file_url = f"{_CLAWHUB_BASE}/api/v1/skills/{urllib.parse.quote(slug, safe='')}/file?{qs}"
        status, _, raw_md = self._request("GET", primary_file_url)
        if status == 404:
            alt_params = [("slug", slug)] + file_params
            alt_url = f"{_CLAWHUB_BASE}/api/v1/file?{urllib.parse.urlencode(alt_params)}"
            status, _, raw_md = self._request("GET", alt_url)

        if status != 200 or not raw_md:
            raise MarketError(
                f"ClawHub SKILL.md preview failed for {owner + '/' if owner else ''}{slug} (HTTP {status})"
            )

        skill_md_text = decode_text_with_bom_and_cookie(raw_md, ".md")
        skill_name = _extract_frontmatter_name(skill_md_text) or slug
        report = audit_package_entries(
            skill_name,
            [VirtualFileEntry(rel_path="SKILL.md", raw_bytes=raw_md)],
            config=self.config,
        )
        report.add(
            "WARN",
            "PARTIAL_SINGLE_FILE_PREVIEW",
            "SKILL.md",
            "ClawHub archive download unavailable; preview audited SKILL.md only without full package entries",
            "Fetch full archive during installation to verify bundled files.",
        )
        self._apply_clawhub_upstream_verdict(report, verify_data)

        page_url = str(
            verify_data.get("pageUrl")
            or (f"{_CLAWHUB_BASE}/{owner}/skills/{slug}" if owner else f"{_CLAWHUB_BASE}/skills/{slug}")
        )
        return {
            "ok": True,
            "source_type": "clawhub",
            "source_id": f"{owner}/{slug}" if owner else slug,
            "source_url": page_url,
            "skill_name": skill_name,
            "version": resolved_ver,
            "commit_sha": "",
            "files": ["SKILL.md"],
            "partial_preview": True,
            "preview_notice": "Full ClawHub archive unavailable; audited SKILL.md single file only.",
            "skill_md": skill_md_text,
            "audit": report.to_dict(),
            "upstream_audit": verify_data,
        }

    # ------------------------------------------------------------------
    # Zero-disk remote preview
    # ------------------------------------------------------------------
    def preview_remote_skill(self, source_ref: str, source_type: str = "auto") -> Dict[str, Any]:
        """Preview SKILL.md and full 3-tier security audit report in memory without writing to disk."""
        raw_ref = (source_ref or "").strip()
        if raw_ref.lower().startswith("mcp:") or (source_type or "").strip().lower() in ("mcp", "mcp_registry", "mcpreg"):
            raise MarketError(_MCP_UNSUPPORTED_PACKAGE_MSG)

        parsed = parse_source_ref(source_ref, source_type=source_type)
        kind = parsed["source_type"]

        if kind == "clawhub":
            try:
                pkg_ch = self.fetch_skill_package(source_ref, source_type="clawhub")
            except MarketError:
                return self._fallback_clawhub_single_file_preview(parsed)

            ch_md_text = ""
            for entry in pkg_ch.entries:
                if PurePosixPath(entry.rel_path).name.lower() in ("skill.md", "skills.md") and entry.raw_bytes:
                    ch_md_text = decode_text_with_bom_and_cookie(entry.raw_bytes, ".md")
                    break

            ch_report = audit_package_entries(pkg_ch.skill_name, pkg_ch.entries, config=self.config)
            self._apply_clawhub_upstream_verdict(ch_report, pkg_ch.upstream_audit)
            return {
                "ok": True,
                "source_type": "clawhub",
                "source_id": pkg_ch.source_id,
                "source_url": pkg_ch.source_url,
                "skill_name": pkg_ch.skill_name,
                "version": pkg_ch.version,
                "commit_sha": pkg_ch.commit_sha,
                "files": [e.rel_path for e in pkg_ch.entries],
                "partial_preview": False,
                "skill_md": ch_md_text,
                "audit": ch_report.to_dict(),
                "upstream_audit": dict(pkg_ch.upstream_audit),
            }

        # GitHub / skills.sh / local: single-pass in-memory package fetch first
        pkg: Optional[FetchedSkillPackage] = None
        partial_gh = False
        try:
            pkg = self.fetch_skill_package(source_ref, source_type=source_type)
        except MarketError:
            # Never fall back when an explicit non-ambiguous git ref/tag was requested and 404'd
            if kind in ("github", "skills_sh") and parsed["owner"] and parsed["repo"] and not parsed["ref"]:
                pkg = self._fallback_raw_github_preview_pkg(parsed)
                partial_gh = True
            else:
                raise

        skill_md_text = ""
        for entry in pkg.entries:
            if PurePosixPath(entry.rel_path).name.lower() in ("skill.md", "skills.md") and entry.raw_bytes:
                skill_md_text = decode_text_with_bom_and_cookie(entry.raw_bytes, ".md")
                break

        report = audit_package_entries(pkg.skill_name, pkg.entries, config=self.config)
        if partial_gh:
            report.add(
                "WARN",
                "PARTIAL_SINGLE_FILE_PREVIEW",
                "SKILL.md",
                "GitHub archive unavailable; preview audited SKILL.md only without full repository tree",
            )
        upstream_audit = dict(pkg.upstream_audit)
        if not upstream_audit and pkg.source_type == "skills_sh" and parsed["owner"] and parsed["repo"]:
            repo_src = f"{parsed['owner']}/{parsed['repo']}"
            audit_url = (
                f"{_SKILLS_SH_AUDIT_URL}?source={urllib.parse.quote(repo_src, safe='/')}"
                f"&skills={urllib.parse.quote(pkg.skill_name, safe=',')}"
            )
            try:
                a_status, a_payload = self._request_json(
                    audit_url,
                    timeout_sec=min(self.config.http_timeout_sec, 3.5),
                )
                if a_status == 200 and isinstance(a_payload, dict):
                    upstream_audit = dict(a_payload.get(pkg.skill_name) or a_payload)
            except Exception:
                pass

        return {
            "ok": True,
            "source_type": pkg.source_type,
            "source_id": pkg.source_id,
            "source_url": pkg.source_url,
            "skill_name": pkg.skill_name,
            "version": pkg.version,
            "commit_sha": pkg.commit_sha,
            "ref": pkg.ref,
            "subpath": pkg.subpath,
            "files": [e.rel_path for e in pkg.entries],
            "partial_preview": partial_gh,
            "skill_md": skill_md_text,
            "audit": report.to_dict(),
            "upstream_audit": upstream_audit,
        }

    def _fallback_raw_github_preview_pkg(self, parsed: Dict[str, str]) -> FetchedSkillPackage:
        owner = parsed["owner"]
        repo = parsed["repo"]
        ref_candidates = [parsed["ref"]] if parsed["ref"] else ["HEAD", "main", "master"]
        rel_candidates: List[str] = []
        if parsed["subpath"]:
            rel_candidates.append(f"{parsed['subpath'].strip('/')}/SKILL.md")
        elif parsed["skill_filter"]:
            sf = parsed["skill_filter"]
            rel_candidates.extend([f"skills/{sf}/SKILL.md", f"{sf}/SKILL.md", "SKILL.md"])
        else:
            rel_candidates.append("SKILL.md")

        for r_cand in ref_candidates:
            for p_cand in rel_candidates:
                seg_quoted = "/".join(urllib.parse.quote(seg, safe="") for seg in p_cand.split("/"))
                raw_url = f"{_GITHUB_RAW_BASE}/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repo, safe='')}/{urllib.parse.quote(r_cand, safe='')}/{seg_quoted}"
                status, _, data = self._request("GET", raw_url)
                if status == 200 and data:
                    md_text = decode_text_with_bom_and_cookie(data, ".md")
                    sname = _extract_frontmatter_name(md_text) or parsed["slug"] or repo
                    sub_used = str(PurePosixPath(p_cand).parent)
                    if sub_used == ".":
                        sub_used = ""
                    return FetchedSkillPackage(
                        source_type=parsed["source_type"],
                        source_id=f"{owner}/{repo}" + (f"@{parsed['skill_filter']}" if parsed["skill_filter"] else ""),
                        source_url=f"https://github.com/{owner}/{repo}",
                        skill_name=sname,
                        entries=[VirtualFileEntry(rel_path="SKILL.md", raw_bytes=data)],
                        ref=r_cand,
                        subpath=sub_used,
                    )
        raise MarketError(f"Unable to preview GitHub skill for {owner}/{repo}")

    # ------------------------------------------------------------------
    # Single-pass in-memory package fetch (Zero TOCTOU)
    # ------------------------------------------------------------------
    def _resolve_github_commit_sha(self, owner: str, repo: str, ref: str) -> str:
        if ref and _SHA40_RE.match(ref):
            return ref.lower()

        target_refs = [ref] if ref else ["HEAD", "main", "master"]
        owner_q = urllib.parse.quote(owner, safe="")
        repo_q = urllib.parse.quote(repo, safe="")

        for r_cand in target_refs:
            ref_q = urllib.parse.quote(r_cand, safe="")
            commits_url = f"{_GITHUB_API_BASE}/repos/{owner_q}/{repo_q}/commits/{ref_q}"
            try:
                status, payload = self._request_json(commits_url)
            except MarketError:
                return ""
            if status == 200 and isinstance(payload, dict):
                sha = str(payload.get("sha") or "").strip().lower()
                if _SHA40_RE.match(sha):
                    return sha
            # On HTTP 403 rate-limit or 401, stop querying api.github.com and fall back to codeload immediately
            if status in (401, 403, 429):
                return ""
            if ref:
                break
        return ""

    def _download_github_zip_once(
        self,
        owner: str,
        repo: str,
        ref: str,
        commit_sha: str,
        *,
        allow_default_branch_fallback: bool = False,
    ) -> Tuple[bytes, str, str, bool]:
        owner_q = urllib.parse.quote(owner, safe="")
        repo_q = urllib.parse.quote(repo, safe="")

        ref_try_order: List[str] = []
        if commit_sha:
            ref_try_order.append(commit_sha)
        if ref and ref not in ref_try_order:
            ref_try_order.append(ref)

        # Only try default branches when NO explicit ref/version/tag was requested (or `#skill` shorthand is ambiguous)
        if not ref or allow_default_branch_fallback:
            for default_branch in ("HEAD", "main", "master"):
                if default_branch not in ref_try_order:
                    ref_try_order.append(default_branch)

        last_status = 0
        for r_cand in ref_try_order:
            zip_url = f"{_GITHUB_CODELOAD_BASE}/{owner_q}/{repo_q}/zip/{urllib.parse.quote(r_cand, safe='')}"
            status, _, zip_bytes = self._request(
                "GET",
                zip_url,
                headers={"Accept": "application/zip, application/octet-stream, */*"},
                max_bytes=self.config.max_archive_bytes,
            )
            last_status = status
            if status == 200 and zip_bytes:
                resolved_sha = commit_sha if (not ref or r_cand == commit_sha or r_cand == ref) else ""
                if not resolved_sha:
                    try:
                        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
                            comment = (zf.comment or b"").decode("ascii", "ignore").strip().lower()
                            if _SHA40_RE.match(comment):
                                resolved_sha = comment
                    except Exception:
                        pass
                ref_fell_back = bool(ref and r_cand != ref and r_cand != commit_sha)
                return zip_bytes, resolved_sha, r_cand, ref_fell_back

        if ref and not allow_default_branch_fallback:
            raise MarketError(
                f"GitHub ref or version {ref!r} not found for {owner}/{repo} (HTTP {last_status})"
            )
        raise MarketError(
            f"Failed to download GitHub archive for {owner}/{repo} (tried refs={ref_try_order}, last HTTP {last_status})"
        )

    def _match_skill_subpath_in_zip(
        self,
        zip_bytes: bytes,
        subpath: str,
        skill_filter: str,
    ) -> str:
        _, skill_mds = _find_skill_subpaths_in_zip(zip_bytes)
        if subpath:
            sub_norm = subpath.strip("/")
            for cand_dir, _ in skill_mds:
                if cand_dir == sub_norm or cand_dir.lower() == sub_norm.lower():
                    return cand_dir
            # If user passed `owner/repo/find-skills` where repo actually stores `skills/find-skills`
            if "/" not in sub_norm and not skill_filter:
                skill_filter = sub_norm
            else:
                return sub_norm

        if skill_filter:
            sf_low = skill_filter.strip().lower()
            # 1. Match directory basename (prefer shallowest path)
            dir_matches = [
                cand_dir
                for cand_dir, _ in skill_mds
                if PurePosixPath(cand_dir).name.lower() == sf_low
            ]
            if dir_matches:
                dir_matches.sort(key=lambda s: (s.count("/"), len(s)))
                return dir_matches[0]

            # 2. Match SKILL.md frontmatter `name:`
            with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
                for cand_dir, member_path in skill_mds:
                    try:
                        with zf.open(member_path, "r") as fp:
                            md_head = decode_text_with_bom_and_cookie(fp.read(32_768), ".md")
                        if _extract_frontmatter_name(md_head).lower() == sf_low:
                            return cand_dir
                    except Exception:
                        continue
            raise MarketError(f"Skill '{skill_filter}' was not found inside repository archive")

        # Neither subpath nor skill_filter provided
        if any(cand_dir == "" for cand_dir, _ in skill_mds):
            return ""
        if len(skill_mds) == 1:
            return skill_mds[0][0]
        if len(skill_mds) > 1:
            available = [PurePosixPath(d).name or d for d, _ in skill_mds[:10]]
            raise MarketError(
                f"Repository contains multiple skills ({', '.join(available)}); specify subpath or '@<skill>'"
            )
        return ""

    def fetch_skill_package(
        self,
        source_ref: str,
        source_type: str = "auto",
        ref: str = "",
        subpath: str = "",
    ) -> FetchedSkillPackage:
        """Fetch a skill package in a single in-memory pass (eliminating dual-fetch TOCTOU)."""
        raw_ref = (source_ref or "").strip()
        if raw_ref.lower().startswith("mcp:") or (source_type or "").strip().lower() in ("mcp", "mcp_registry", "mcpreg"):
            raise MarketError(_MCP_UNSUPPORTED_PACKAGE_MSG)

        parsed = parse_source_ref(source_ref, source_type=source_type, ref=ref, subpath=subpath)
        kind = parsed["source_type"]

        # 1. Local skill directory
        if kind == "local":
            base_dir = Path(parsed["local_path"]).expanduser().resolve()
            if parsed["subpath"]:
                if _is_unsafe_rel_path(parsed["subpath"]):
                    raise MarketError("Unsafe local subpath")
                target_dir = (base_dir / parsed["subpath"]).resolve()
                if not is_subpath(target_dir, base_dir):
                    raise MarketError("Local subpath escapes base skill directory")
            else:
                target_dir = base_dir

            if not self._is_authorized_local_source(target_dir):
                raise MarketError(f"Local skill directory is outside authorized workspace roots: {target_dir}")

            entries = _collect_local_dir_entries(target_dir, config=self.config)
            md_entry = next(
                (e for e in entries if PurePosixPath(e.rel_path).name.lower() in ("skill.md", "skills.md")),
                None,
            )
            if md_entry is None:
                raise MarketError(f"Local directory does not contain SKILL.md: {target_dir}")
            md_text = decode_text_with_bom_and_cookie(md_entry.raw_bytes or b"", ".md")
            skill_name = _extract_frontmatter_name(md_text) or target_dir.name
            return FetchedSkillPackage(
                source_type="local",
                source_id=str(target_dir),
                source_url=target_dir.as_uri(),
                skill_name=skill_name,
                entries=entries,
                subpath=parsed["subpath"],
            )

        # 2. ClawHub deterministic ZIP archive
        if kind == "clawhub":
            slug = parsed["slug"]
            owner = parsed["owner"]
            req_ver = parsed["version"]

            verify_data = self._fetch_clawhub_verify(slug=slug, owner=owner, version=req_ver)
            resolved_ver = req_ver or str(verify_data.get("version") or "")

            dl_params: List[Tuple[str, str]] = [("slug", slug)]
            if owner:
                dl_params.append(("ownerHandle", owner))
            if resolved_ver:
                dl_params.append(("version", resolved_ver))
            else:
                dl_params.append(("tag", "latest"))

            dl_url = f"{_CLAWHUB_BASE}/api/v1/download?{urllib.parse.urlencode(dl_params)}"
            status, _, zip_bytes = self._request(
                "GET",
                dl_url,
                headers={"Accept": "application/zip, application/octet-stream, */*"},
                max_bytes=self.config.max_archive_bytes,
            )
            if status != 200 or not zip_bytes:
                raise MarketError(
                    f"ClawHub archive download failed for {owner + '/' if owner else ''}{slug} (HTTP {status})"
                )

            entries = extract_zip_to_virtual_entries(
                zip_bytes,
                subpath=parsed["subpath"],
                config=self.config,
            )
            md_entry = next(
                (e for e in entries if PurePosixPath(e.rel_path).name.lower() in ("skill.md", "skills.md")),
                None,
            )
            if md_entry is None and not any(e.path_traversal or e.symlink_escapes for e in entries):
                raise MarketError(f"Downloaded ClawHub archive for '{slug}' does not contain SKILL.md")

            md_text = decode_text_with_bom_and_cookie(md_entry.raw_bytes or b"", ".md") if md_entry else ""
            skill_name = _extract_frontmatter_name(md_text) or slug
            page_url = str(
                verify_data.get("pageUrl")
                or (f"{_CLAWHUB_BASE}/{owner}/skills/{slug}" if owner else f"{_CLAWHUB_BASE}/skills/{slug}")
            )
            return FetchedSkillPackage(
                source_type="clawhub",
                source_id=f"{owner}/{slug}" if owner else slug,
                source_url=page_url,
                skill_name=skill_name,
                entries=entries,
                version=resolved_ver,
                ref=resolved_ver,
                subpath=parsed["subpath"],
                upstream_audit=verify_data,
            )

        # 3. GitHub / skills.sh single-pass archive download + in-memory extraction
        owner = parsed["owner"]
        repo = parsed["repo"]
        req_ref = parsed["ref"]
        req_subpath = parsed["subpath"]
        skill_filter = parsed["skill_filter"]
        frag_ambiguous = bool(parsed.get("frag_ambiguous"))

        commit_sha = self._resolve_github_commit_sha(owner, repo, req_ref)
        zip_bytes, resolved_sha, used_ref, ref_fell_back = self._download_github_zip_once(
            owner=owner,
            repo=repo,
            ref=req_ref,
            commit_sha=commit_sha,
            allow_default_branch_fallback=frag_ambiguous,
        )
        # Support `owner/repo#<skillName>` shorthand ONLY when `#fragment` was a non-version skill slug
        if ref_fell_back and frag_ambiguous and req_ref and not skill_filter and not req_subpath:
            skill_filter = req_ref
            req_ref = ""

        # Validate archive integrity/limits first and resolve target skill directory in memory
        try:
            matched_subpath = self._match_skill_subpath_in_zip(
                zip_bytes=zip_bytes,
                subpath=req_subpath,
                skill_filter=skill_filter,
            )
        except (zipfile.BadZipFile, OSError) as exc:
            raise ZipSecurityLimitError(f"Invalid GitHub ZIP archive: {exc}") from exc

        entries = extract_zip_to_virtual_entries(
            zip_bytes,
            subpath=matched_subpath,
            config=self.config,
        )
        md_entry = next(
            (e for e in entries if PurePosixPath(e.rel_path).name.lower() in ("skill.md", "skills.md")),
            None,
        )
        if md_entry is None and not any(e.path_traversal or e.symlink_escapes for e in entries):
            raise MarketError(
                f"SKILL.md not found in {owner}/{repo}"
                + (f" under '{matched_subpath}'" if matched_subpath else "")
            )

        md_text = decode_text_with_bom_and_cookie(md_entry.raw_bytes or b"", ".md") if md_entry else ""
        fallback_name = (
            skill_filter
            or (PurePosixPath(matched_subpath).name if matched_subpath else "")
            or repo
        )
        skill_name = _extract_frontmatter_name(md_text) or fallback_name

        source_id = f"{owner}/{repo}@{skill_filter}" if skill_filter else (
            f"{owner}/{repo}/{matched_subpath}" if matched_subpath else f"{owner}/{repo}"
        )
        tree_ref = resolved_sha or req_ref or used_ref
        source_url = (
            f"https://github.com/{owner}/{repo}/tree/{tree_ref}/{matched_subpath}"
            if matched_subpath
            else f"https://github.com/{owner}/{repo}"
        )

        return FetchedSkillPackage(
            source_type=kind,
            source_id=source_id,
            source_url=source_url,
            skill_name=skill_name,
            entries=entries,
            commit_sha=resolved_sha,
            version=req_ref if (req_ref and _VERSION_PIN_RE.match(req_ref) and not ref_fell_back) else "",
            ref=used_ref if ref_fell_back else (req_ref or used_ref),
            subpath=matched_subpath,
        )
