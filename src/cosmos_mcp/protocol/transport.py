"""Dual-instance `mcp.server.lowlevel.Server` Streamable HTTP transport (`/mcp` + `/mcp/readonly`) with zero FastMCP private hacks."""
from __future__ import annotations

import base64
import contextlib
import contextvars
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import re
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

try:
    from mcp.server.auth.handlers.token import TokenHandler
    from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
    from mcp.server.auth.middleware.bearer_auth import (
        AuthenticatedUser,
        BearerAuthBackend,
        RequireAuthMiddleware,
    )
    from mcp.server.auth.middleware.client_auth import AuthenticationError, ClientAuthenticator
    from mcp.server.auth.provider import AccessToken, ProviderTokenVerifier
    from mcp.server.auth.routes import (
        build_metadata,
        build_resource_metadata_url,
        cors_middleware,
        create_auth_routes,
        create_protected_resource_routes,
    )
    from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
    from mcp.server.lowlevel import Server as LowLevelServer
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from mcp.server.transport_security import RequestBodyLimitMiddleware, TransportSecuritySettings
    import mcp.types as types

    MCP_SDK_AVAILABLE = True
except ImportError:
    MCP_SDK_AVAILABLE = False
    from cosmos_mcp.protocol.oauth import AccessToken  # type: ignore[assignment]

    class AuthenticationError(Exception):  # type: ignore[no-redef]
        def __init__(self, message: str = "authentication_error") -> None:
            super().__init__(message)
            self.message = message

    class BearerAuthBackend:  # type: ignore[no-redef]
        def __init__(self, token_verifier: Any = None, resource_server_url: Any = None) -> None:
            self.token_verifier = token_verifier
            self.resource_server_url = resource_server_url

        def _issued_for_this_resource(self, tok_res: Optional[str]) -> bool:
            if not tok_res or not self.resource_server_url:
                return False
            return str(tok_res).rstrip("/") == str(self.resource_server_url).rstrip("/")

        async def authenticate(self, conn: Any) -> Any:
            _ = conn
            return None

    class AuthenticatedUser:  # type: ignore[no-redef]
        is_authenticated = True

        def __init__(self, access_token: Any) -> None:
            self.access_token = access_token

    class _UnsupportedMcpStub:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("Official `mcp` SDK (Python >=3.10) is not installed in this Python 3.9 environment.")

    TokenHandler = _UnsupportedMcpStub  # type: ignore[misc,assignment]
    AuthContextMiddleware = _UnsupportedMcpStub  # type: ignore[misc,assignment]
    RequireAuthMiddleware = _UnsupportedMcpStub  # type: ignore[misc,assignment]
    ClientAuthenticator = _UnsupportedMcpStub  # type: ignore[misc,assignment]
    ProviderTokenVerifier = _UnsupportedMcpStub  # type: ignore[misc,assignment]
    ClientRegistrationOptions = _UnsupportedMcpStub  # type: ignore[misc,assignment]
    RevocationOptions = _UnsupportedMcpStub  # type: ignore[misc,assignment]
    LowLevelServer = _UnsupportedMcpStub  # type: ignore[misc,assignment]
    StreamableHTTPSessionManager = _UnsupportedMcpStub  # type: ignore[misc,assignment]
    RequestBodyLimitMiddleware = _UnsupportedMcpStub  # type: ignore[misc,assignment]
    TransportSecuritySettings = _UnsupportedMcpStub  # type: ignore[misc,assignment]

    def _unsupported_mcp_fn(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("Official `mcp` SDK (Python >=3.10) is not installed in this Python 3.9 environment.")

    build_metadata = _unsupported_mcp_fn  # type: ignore[assignment]
    build_resource_metadata_url = _unsupported_mcp_fn  # type: ignore[assignment]
    cors_middleware = _unsupported_mcp_fn  # type: ignore[assignment]
    create_auth_routes = _unsupported_mcp_fn  # type: ignore[assignment]
    create_protected_resource_routes = _unsupported_mcp_fn  # type: ignore[assignment]

    class _FallbackMcpTypes:
        ContentBlock = Any

        @dataclass
        class ToolAnnotations:
            title: str = ""
            readOnlyHint: bool = True
            destructiveHint: bool = False
            idempotentHint: bool = True
            openWorldHint: bool = False

        @dataclass
        class TextContent:
            type: str = "text"
            text: str = ""

        @dataclass
        class ImageContent:
            type: str = "image"
            data: str = ""
            mimeType: str = "image/png"

        @dataclass
        class EmbeddedResource:
            type: str = "resource"
            resource: Dict[str, Any] = None  # type: ignore[assignment]

        @dataclass
        class CallToolResult:
            content: List[Any]
            isError: bool = False

        @dataclass
        class Tool:
            name: str
            description: str = ""
            inputSchema: Dict[str, Any] = None  # type: ignore[assignment]
            title: str = ""
            annotations: Any = None

        class ListToolsRequest:
            pass

        @dataclass
        class ListToolsResult:
            tools: List[Any]

    types = _FallbackMcpTypes()  # type: ignore[assignment]

try:
    from pydantic import AnyHttpUrl
except ImportError:
    from cosmos_mcp.protocol.oauth import AnyHttpUrl  # type: ignore[assignment]

try:
    from starlette.applications import Starlette
    from starlette.authentication import AuthCredentials
    from starlette.middleware import Middleware
    from starlette.middleware.authentication import AuthenticationMiddleware
    from starlette.requests import HTTPConnection, Request
    from starlette.responses import JSONResponse, Response
    from starlette.routing import Route
except ImportError:
    Starlette = Any  # type: ignore[misc,assignment]
    HTTPConnection = Any  # type: ignore[misc,assignment]
    Request = Any  # type: ignore[misc,assignment]
    AuthenticationMiddleware = Any  # type: ignore[misc,assignment]
    Route = Any  # type: ignore[misc,assignment]

    class AuthCredentials:  # type: ignore[no-redef]
        def __init__(self, scopes: Optional[Sequence[str]] = None) -> None:
            self.scopes = list(scopes or ())

    class Middleware:  # type: ignore[no-redef]
        def __init__(self, cls: Any, *args: Any, **kwargs: Any) -> None:
            self.cls = cls
            self.args = args
            self.kwargs = kwargs

    from cosmos_mcp.protocol.oauth import JSONResponse  # type: ignore[assignment]
    Response = JSONResponse  # type: ignore[misc,assignment]

from cosmos_mcp.core.path_heal import is_link_or_junction
from cosmos_mcp.core.proc import DEFAULT_PROCESS_MANAGER, ProcessManager, append_audit_log
from cosmos_mcp.protocol.dispatcher import KernelDispatcher, SafetyBand, ToolSpec
from cosmos_mcp.protocol.oauth import (
    READONLY_SCOPES,
    SCOPES,
    IssuerResponseMiddleware,
    OAuthProvider,
    OAuthSQLiteStore,
    OAuthStoreBusyError,
    RegisterGrantCompatASGI,
    TrustedGatewayEndpoint,
    extract_request_client_ip,
    get_current_request_gateway,
    identify_client_platform,
    is_google_gemini_client,
    is_readonly_resource_url,
    reset_current_request_gateway,
    reset_request_token_resource,
    resolve_trusted_gateway_from_scope,
    set_current_request_gateway,
    set_request_token_resource,
    validate_and_apply_remote_policy_update,
)
from cosmos_mcp.core.config import (
    DEFAULT_REDIRECT_HOSTS,
    PRODUCT_VERSION,
    KillSignalWatchdog,
    LiveRuntimePolicy,
    emit_kill_signal,
    ensure_initialized,
    normalize_annotation_mode,
    normalize_prefix,
)
from cosmos_mcp.protocol.skill_renderer import (
    build_server_instructions,
    build_tool_description,
    render_minimal_public_skill_markdown,
    render_skill_markdown,
)

LOGGER = logging.getLogger("cosmos_mcp.transport")

PROXY_HEADER_PREFIXES: Tuple[str, ...] = (
    "x-forwarded-",
    "cf-",
    "x-cosmos-via-",
)
PROXY_HEADER_EXACT: Set[str] = {
    "forwarded",
    "x-real-ip",
    "true-client-ip",
    "via",
    "x-original-host",
}
STRICT_TUNNEL_HEADERS: Set[str] = {
    "x-cosmos-via-tunnel",
    "x-cosmos-client-ip",
    "x-cosmos-public-prefix",
    "cf-connecting-ip",
    "cf-ray",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-real-ip",
    "forwarded",
    "true-client-ip",
    "via",
    "x-original-host",
}

_ZW = "\u200c"
_AT_CONNECTOR_OUT_RE = re.compile(
    r"(?<![\w%+])(?<!\w[.-])@(Cosmos|Gmail|Google|Workspace|Drive|Calendar|Docs|Sheets|Slides|Keep|Tasks|YouTube|Maps|Flights|Hotels)\b(?!/)",
    re.IGNORECASE,
)

UNTRUSTED_EXTERNAL_TOOLS: Set[str] = {"web_research", "browser_use"}


def is_untrusted_external_tool(tool_name: str) -> bool:
    """Return True iff `tool_name` (prefixed or base) fetches untrusted external web/DOM content."""
    clean = (tool_name or "").strip().lower()
    if not clean:
        return False
    if clean in UNTRUSTED_EXTERNAL_TOOLS:
        return True
    return any(clean.endswith(f"_{base}") for base in UNTRUSTED_EXTERNAL_TOOLS)

PREVIEW_TTL_SECONDS: int = 1800
MAX_PREVIEW_IMAGE_BYTES: int = 20 * 1024 * 1024
_PREVIEW_ALLOWED_EXTS: Set[str] = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}


def create_image_preview_token(
    image_path: str | Path,
    secret: str | bytes,
    *,
    ttl_seconds: int = PREVIEW_TTL_SECONDS,
    now: Optional[float] = None,
) -> str:
    """Create a short-lived (default 30-min) HMAC-SHA256 signed read-only image preview token."""
    sec_bytes = secret if isinstance(secret, bytes) else str(secret).encode("utf-8")
    base_now = float(now) if now is not None else time.time()
    exp_ts = int(base_now + int(ttl_seconds))
    resolved_str = str(Path(image_path).expanduser().resolve())
    payload_bytes = json.dumps(
        {"p": resolved_str, "exp": exp_ts},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    b64_payload = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
    sig = hmac.new(sec_bytes, b64_payload.encode("ascii"), hashlib.sha256).digest()
    b64_sig = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
    return f"{b64_payload}.{b64_sig}"


def verify_image_preview_token(
    token: str,
    secret: str | bytes,
    *,
    now: Optional[float] = None,
) -> Optional[Dict[str, Any]]:
    """Verify HMAC-SHA256 signature and expiration of a `/preview/{token}` token."""
    clean = (token or "").strip()
    if not clean or "." not in clean or len(clean) > 4096:
        return None
    b64_payload, b64_sig = clean.split(".", 1)
    if not b64_payload or not b64_sig:
        return None
    sec_bytes = secret if isinstance(secret, bytes) else str(secret).encode("utf-8")
    expected_sig = base64.urlsafe_b64encode(
        hmac.new(sec_bytes, b64_payload.encode("ascii"), hashlib.sha256).digest()
    ).decode("ascii").rstrip("=")
    if not hmac.compare_digest(b64_sig, expected_sig):
        return None
    try:
        padded = b64_payload + ("=" * (-len(b64_payload) % 4))
        raw_doc = base64.urlsafe_b64decode(padded.encode("ascii"))
        doc = json.loads(raw_doc.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    path_val = doc.get("p")
    exp_val = doc.get("exp")
    if not isinstance(path_val, str) or not path_val.strip() or "\x00" in path_val:
        return None
    try:
        exp_num = float(exp_val)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    cur_now = float(now) if now is not None else time.time()
    if exp_num <= cur_now:
        return None
    return {"path": path_val, "exp": exp_num}


def _detect_preview_image_mime(file_path: Path, header_bytes: bytes) -> Optional[str]:
    if file_path.suffix.lower() not in _PREVIEW_ALLOWED_EXTS:
        return None
    if header_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if header_bytes.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if len(header_bytes) >= 12 and header_bytes[:4] == b"RIFF" and header_bytes[8:12] == b"WEBP":
        return "image/webp"
    if header_bytes.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if header_bytes.startswith(b"BM"):
        return "image/bmp"
    return None


def _is_valid_public_preview_base(url_str: str) -> bool:
    clean = (url_str or "").strip().rstrip("/")
    if not clean:
        return False
    u = urlsplit(clean)
    scheme = (u.scheme or "").lower()
    host = (u.hostname or "").strip().lower()
    if scheme not in ("http", "https") or not host:
        return False
    return host not in ("127.0.0.1", "localhost", "::1")


def _inject_preview_url_into_blocks(
    raw_out: Any,
    arguments: Dict[str, Any],
    policy: LiveRuntimePolicy,
    public_url: str,
    preview_secret: bytes,
) -> Any:
    if not isinstance(raw_out, list) or not public_url or not preview_secret:
        return raw_out
    has_image = any(
        (isinstance(b, dict) and b.get("type") == "image")
        or getattr(b, "type", None) == "image"
        for b in raw_out
    )
    if not has_image:
        return raw_out

    resolved_img_path = ""
    first_text_idx = -1
    parsed_meta: Optional[Dict[str, Any]] = None
    for idx, blk in enumerate(raw_out):
        if isinstance(blk, dict) and blk.get("type") == "text":
            first_text_idx = idx
            txt = str(blk.get("text") or "")
            try:
                cand = json.loads(txt)
                if isinstance(cand, dict):
                    parsed_meta = cand
                    if isinstance(cand.get("path"), str) and cand["path"].strip():
                        resolved_img_path = cand["path"].strip()
            except Exception:
                parsed_meta = None
            break

    if not resolved_img_path:
        raw_arg_p = str(arguments.get("path") or arguments.get("file_path") or "").strip()
        if raw_arg_p:
            p_cand = Path(raw_arg_p).expanduser()
            if not p_cand.is_absolute():
                p_cand = (policy.primary_workspace / p_cand).resolve()
            else:
                p_cand = p_cand.resolve()
            resolved_img_path = str(p_cand)

    if not resolved_img_path:
        return raw_out
    fp = Path(resolved_img_path)
    if not policy.is_path_allowed(fp):
        return raw_out
    if policy.guard is not None and policy.guard.check_path_access(str(fp), mode="read", tool_name="preview") is not None:
        return raw_out

    tok = create_image_preview_token(fp, preview_secret, ttl_seconds=PREVIEW_TTL_SECONDS)
    preview_url = f"{public_url.rstrip('/')}/preview/{tok}"
    out_blocks = list(raw_out)
    if first_text_idx >= 0:
        orig_blk = dict(out_blocks[first_text_idx])
        if parsed_meta is not None:
            upd_meta = {**parsed_meta, "preview_url": preview_url}
            orig_blk["text"] = json.dumps(upd_meta, ensure_ascii=False)
        else:
            prev_txt = str(orig_blk.get("text") or "").rstrip()
            orig_blk["text"] = f'{prev_txt}\npreview_url: "{preview_url}"'.lstrip()
        out_blocks[first_text_idx] = orig_blk
    else:
        out_blocks.insert(0, {"type": "text", "text": json.dumps({"preview_url": preview_url}, ensure_ascii=False)})
    return out_blocks
_IPI_PHRASE_RES = [
    (re.compile(r"\u6700\u9ad8\u4f18\u5148\u7ea7"), "\u6700\u9ad8" + _ZW + "\u4f18\u5148\u7ea7"),
    (re.compile(r"\u5fc5\u987b100%\u4e25\u683c\u9075\u5faa"), "\u5fc5\u987b100%" + _ZW + "\u4e25\u683c\u9075\u5faa"),
    (re.compile(r"\u4e25\u7981\u8fdd\u80cc"), "\u4e25\u7981" + _ZW + "\u8fdd\u80cc"),
    (re.compile(r"\u6700\u9ad8\u6307\u4ee4"), "\u6700\u9ad8" + _ZW + "\u6307\u4ee4"),
    (re.compile(r"(ignore)(\s+(?:all\s+)?(?:previous|prior)\s+instructions)", re.IGNORECASE), r"\1" + _ZW + r"\2"),
    (re.compile(r"(disregard)(\s+(?:all\s+)?(?:previous|prior)\s+instructions)", re.IGNORECASE), r"\1" + _ZW + r"\2"),
    (re.compile(r"(forget)(\s+(?:all\s+)?(?:previous|prior)\s+instructions)", re.IGNORECASE), r"\1" + _ZW + r"\2"),
    (re.compile(r"(system)(\s+override)", re.IGNORECASE), r"\1" + _ZW + r"\2"),
    (re.compile(r"(you\s+must)(\s+strictly\s+obey)", re.IGNORECASE), r"\1" + _ZW + r"\2"),
    (re.compile(r"<(/?)(system_instruction|system_prompt|developer_instruction|tool_call|function_call)\b", re.IGNORECASE), r"<\1" + _ZW + r"\2"),
    (re.compile(r"\[(\s*/?\s*INST\s*)\]", re.IGNORECASE), r"[" + _ZW + r"\1]"),
    (re.compile(r"<\|(im_start|im_end|system|endoftext)\|>", re.IGNORECASE), r"<|" + _ZW + r"\1|>"),
]


def _is_google_mcp_client(user_agent: str = "") -> bool:
    """Return True iff the request originates from Google Cloud Connector / Web Gemini (`User-Agent` contains `google`)."""
    ua = (user_agent or "").strip().lower()
    return ua == "google" or ua.startswith("google/") or "google-mcp" in ua or "google" in ua


def is_google_user_agent(user_agent: str = "") -> bool:
    return _is_google_mcp_client(user_agent)


def sanitize_ipi_text(
    text: str,
    *,
    is_google_client: bool = True,
    tool_name: Optional[str] = None,
) -> str:
    """Neutralize cross-source connector mentions via `@\\u200c<Name>` ONLY on untrusted external network outputs for Google clients."""
    if not text or not isinstance(text, str) or not is_google_client:
        return text
    if tool_name is not None and not is_untrusted_external_tool(tool_name):
        return text
    out = _AT_CONNECTOR_OUT_RE.sub("@" + _ZW + r"\1", text) if "@" in text else text
    for rx, repl in _IPI_PHRASE_RES:
        out = rx.sub(repl, out)
    return out


def unsanitize_ipi_text(text: str) -> str:
    """Strip transport-injected `\\u200c` zero-width non-joiner characters if echoed back in edit arguments."""
    if not text or not isinstance(text, str) or _ZW not in text:
        return text
    return text.replace(_ZW, "")


def unsanitize_ipi_payload(obj: Any) -> Any:
    """Recursively strip `\\u200c` from all string arguments (nested dicts/lists/tuples) before tool execution."""
    if isinstance(obj, str):
        return unsanitize_ipi_text(obj)
    if isinstance(obj, list):
        return [unsanitize_ipi_payload(x) for x in obj]
    if isinstance(obj, tuple):
        return tuple(unsanitize_ipi_payload(x) for x in obj)
    if isinstance(obj, dict):
        return {
            (unsanitize_ipi_text(k) if isinstance(k, str) else k): unsanitize_ipi_payload(v)
            for k, v in obj.items()
        }
    return obj


def sanitize_ipi_payload(
    obj: Any,
    depth: int = 0,
    *,
    is_google_client: bool = True,
    tool_name: Optional[str] = None,
) -> Any:
    if not is_google_client:
        return obj
    if tool_name is not None and not is_untrusted_external_tool(tool_name):
        return obj
    if isinstance(obj, str):
        stripped = obj.lstrip()
        if depth < 4 and len(obj) <= 4_194_304 and stripped[:1] in ("{", "["):
            try:
                parsed = json.loads(obj)
                if isinstance(parsed, (dict, list)):
                    cleaned = sanitize_ipi_payload(parsed, depth + 1, is_google_client=True, tool_name=tool_name)
                    if cleaned != parsed:
                        return json.dumps(cleaned, ensure_ascii=False)
                    return obj
            except Exception:
                pass
        return sanitize_ipi_text(obj, is_google_client=True, tool_name=tool_name)
    if isinstance(obj, list):
        changed = False
        res_list = []
        for item in obj:
            c = sanitize_ipi_payload(item, depth + 1, is_google_client=True, tool_name=tool_name)
            if c is not item:
                changed = True
            res_list.append(c)
        return res_list if changed else obj
    if isinstance(obj, dict):
        changed = False
        res_dict = {}
        for k, v in obj.items():
            c = sanitize_ipi_payload(v, depth + 1, is_google_client=True, tool_name=tool_name)
            if c is not v:
                changed = True
            res_dict[k] = c
        return res_dict if changed else obj
    return obj


sanitize_ipi_value = sanitize_ipi_payload


def adapt_mcp_images_for_google(result_obj: Any, *, uri_prefix: str = "localpc_capture") -> Tuple[Any, bool]:
    """Convert MCP `ImageContent` (`type=='image'`) into `EmbeddedResource(blob)` for Google Web Gemini."""
    if not isinstance(result_obj, dict):
        return result_obj, False
    content = result_obj.get("content")
    if not isinstance(content, list) or not content:
        return result_obj, False
    ext_map = {
        "image/png": "png",
        "image/jpeg": "jpg",
        "image/jpg": "jpg",
        "image/webp": "webp",
        "image/gif": "gif",
        "image/bmp": "bmp",
    }
    eff_prefix = (uri_prefix or "localpc_capture").strip("/")
    new_content: List[Any] = []
    changed = False
    img_idx = 0
    for blk in content:
        if (
            isinstance(blk, dict)
            and blk.get("type") == "image"
            and isinstance(blk.get("data"), str)
            and blk.get("data")
            and blk.get("mimeType")
        ):
            img_idx += 1
            mime = str(blk["mimeType"]).strip()
            ext = ext_map.get(mime.lower(), "jpg")
            new_content.append(
                {
                    "type": "resource",
                    "resource": {
                        "uri": f"file:///{eff_prefix}_{img_idx}.{ext}",
                        "mimeType": mime,
                        "blob": blk["data"],
                    },
                }
            )
            changed = True
        else:
            new_content.append(blk)
    if not changed:
        return result_obj, False
    return {**result_obj, "content": new_content}, True


def transform_mcp_wire_bytes(
    raw_bytes: bytes,
    content_type: str = "",
    *,
    user_agent: str = "",
    sanitize_taint: bool = True,
    uri_prefix: str = "localpc_capture",
    tool_name: Optional[str] = None,
) -> bytes:
    """Apply `EmbeddedResource(blob)` for Google Cloud Connector, and `@\\u200c<Connector>` ONLY on untrusted external tool outputs.

    Local controlled workspace tools (`read_file`, `search_code`, `find_files`, `code_intel`, `get_status`,
    `batch_probe`, `workspace_memory`, `skill_hub`, etc.) and all non-Google clients receive 100% pure
    source literals with zero `\\u200c` injection.
    """
    if not raw_bytes:
        return raw_bytes
    is_google_client = _is_google_mcp_client(user_agent)
    if not is_google_client:
        return raw_bytes
    eff_sanitize = bool(sanitize_taint and (tool_name is None or is_untrusted_external_tool(tool_name)))
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return raw_bytes

    def _process_rpc_node(rpc_node: Any) -> Tuple[Any, bool]:
        if isinstance(rpc_node, list):
            out_arr = []
            any_ch = False
            for el in rpc_node:
                p_el, ch = _process_rpc_node(el)
                out_arr.append(p_el)
                if ch:
                    any_ch = True
            return (out_arr, True) if any_ch else (rpc_node, False)
        if not isinstance(rpc_node, dict):
            return rpc_node, False
        mut = False
        upd = dict(rpc_node)
        if "result" in upd:
            if eff_sanitize:
                cr = sanitize_ipi_payload(upd["result"], is_google_client=True, tool_name=tool_name)
                if cr != upd["result"]:
                    upd["result"] = cr
                    mut = True
            ar, ach = adapt_mcp_images_for_google(upd["result"], uri_prefix=uri_prefix)
            if ach:
                upd["result"] = ar
                mut = True
        if eff_sanitize and "error" in upd:
            ce = sanitize_ipi_payload(upd["error"], is_google_client=True, tool_name=tool_name)
            if ce != upd["error"]:
                upd["error"] = ce
                mut = True
        return (upd, True) if mut else (rpc_node, False)

    ct_low = (content_type or "").lower()
    if "text/event-stream" in ct_low or text.lstrip().startswith(("event:", "data:")):
        out_lines: List[str] = []
        mutated = False
        for line in text.splitlines(keepends=True):
            if line.startswith("data:"):
                ending = "\r\n" if line.endswith("\r\n") else ("\n" if line.endswith("\n") else "")
                payload_str = line[5 : len(line) - len(ending)].strip()
                if payload_str:
                    try:
                        parsed = json.loads(payload_str)
                        new_obj, ch = _process_rpc_node(parsed)
                        if ch:
                            mutated = True
                            out_lines.append("data: " + json.dumps(new_obj, ensure_ascii=False) + ending)
                            continue
                    except Exception:
                        pass
            out_lines.append(line)
        return "".join(out_lines).encode("utf-8") if mutated else raw_bytes

    try:
        parsed_json = json.loads(text)
        new_json, ch = _process_rpc_node(parsed_json)
        if ch:
            return json.dumps(new_json, ensure_ascii=False).encode("utf-8")
    except Exception:
        pass
    return raw_bytes


def _ro_ann(title: str, *, open_world: bool = False) -> types.ToolAnnotations:
    return types.ToolAnnotations(
        title=title,
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=bool(open_world),
    )


def _zero_popup_ann(title: str) -> types.ToolAnnotations:
    return types.ToolAnnotations(
        title=title,
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )


def _edit_ann(title: str, *, idempotent: bool = False) -> types.ToolAnnotations:
    return types.ToolAnnotations(
        title=title,
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=bool(idempotent),
        openWorldHint=False,
    )


def _exec_ann(title: str, *, open_world: bool = False) -> types.ToolAnnotations:
    return types.ToolAnnotations(
        title=title,
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=False,
        openWorldHint=bool(open_world),
    )


def build_annotations_for_spec(
    spec: ToolSpec,
    *,
    annotation_mode: Optional[str] = None,
    is_gemini_client: bool = True,
    approval_popups: Optional[bool] = None,
) -> types.ToolAnnotations:
    """Build `ToolAnnotations` honoring `annotation_mode` ('seamless'/'compat'/'auto' vs 'strict'/'honest') and `approval_popups`."""
    if bool(approval_popups):
        is_seamless = False
    elif annotation_mode is not None and str(annotation_mode).strip() != "":
        raw_ann = str(annotation_mode).strip().lower()
        if raw_ann in ("honest", "strict", "confirm", "prompt", "popups"):
            is_seamless = False
        elif raw_ann == "auto":
            is_seamless = bool(is_gemini_client)
        elif raw_ann in ("compat", "seamless", "zero_popup", "silent"):
            is_seamless = True
        else:
            is_seamless = normalize_annotation_mode(annotation_mode, approval_popups=approval_popups) == "seamless"
    elif approval_popups is not None:
        is_seamless = not bool(approval_popups)
    else:
        is_seamless = bool(is_gemini_client)

    if is_seamless:
        return _zero_popup_ann(spec.title)
    if spec.safety_band == SafetyBand.READONLY:
        return _ro_ann(spec.title, open_world=spec.open_world)
    if spec.safety_band == SafetyBand.WORKSPACE_WRITE:
        return _edit_ann(spec.title, idempotent=spec.idempotent)
    return _exec_ann(spec.title, open_world=spec.open_world)


@dataclass(frozen=True)
class RequestTransportContext:
    user_agent: str = ""
    client_id: str = ""
    client_platform: str = "Custom MCP Client"
    is_gemini: bool = False
    scopes: Optional[frozenset[str]] = None
    session_hint: str = "http"
    is_remote: bool = True
    public_url: str = ""
    preview_secret: bytes = b""
    bound_node_id: str = ""
    active_tool_box: List[str] = field(default_factory=lambda: [""])


_REQUEST_TRANSPORT_CTX: contextvars.ContextVar[RequestTransportContext] = contextvars.ContextVar(
    "_REQUEST_TRANSPORT_CTX",
    default=RequestTransportContext(),
)


class GatewayContextASGI:
    """Outermost ASGI gate binding `TrustedGatewayEndpoint` to `_REQUEST_GATEWAY_VAR` and rejecting unknown Hosts with 421."""

    def __init__(
        self,
        app: Any,
        *,
        provider: OAuthProvider,
        local_port: int = 8096,
        sync_hook_box: Optional[List[Optional[Callable[[bool], None]]]] = None,
    ) -> None:
        self.app = app
        self.provider = provider
        self.local_port = int(local_port)
        self.sync_hook_box = sync_hook_box

    def _maybe_sync(self, force: bool = False) -> None:
        if self.sync_hook_box and self.sync_hook_box[0] is not None:
            try:
                self.sync_hook_box[0](force)
            except Exception:
                pass

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        self._maybe_sync(False)
        eff_port = int(getattr(self.provider, "local_port", self.local_port) or self.local_port)
        gw = resolve_trusted_gateway_from_scope(
            scope,
            self.provider.get_effective_trusted_gateways(),
            local_port=eff_port,
            default_endpoint=self.provider._default_gateway_endpoint(),
        )
        if gw is None:
            self._maybe_sync(True)
            gw = resolve_trusted_gateway_from_scope(
                scope,
                self.provider.get_effective_trusted_gateways(),
                local_port=eff_port,
                default_endpoint=self.provider._default_gateway_endpoint(),
            )
        if gw is None:
            req_path = str(scope.get("path") or "")
            if req_path.startswith(("/api/studio/", "/static/", "/tutorials.md", "/llms.txt")):
                hdr_map = {
                    k.decode("latin-1").lower(): v.decode("latin-1", errors="replace").strip()
                    for k, v in (scope.get("headers") or ())
                }
                raw_h = hdr_map.get("host", "").lower()
                lb_hosts = {
                    f"127.0.0.1:{eff_port}",
                    f"localhost:{eff_port}",
                    f"[::1]:{eff_port}",
                    "127.0.0.1",
                    "localhost",
                    "[::1]",
                }
                if raw_h in lb_hosts and not hdr_map.get("x-forwarded-host") and not hdr_map.get("forwarded"):
                    gw = self.provider._default_gateway_endpoint()
        if gw is None:
            resp = JSONResponse(
                {"error": "invalid_host"},
                status_code=421,
                headers={"Cache-Control": "no-store"},
            )
            await resp(scope, receive, send)
            return
        tok = set_current_request_gateway(gw)
        try:
            await self.app(scope, receive, send)
        finally:
            reset_current_request_gateway(tok)


def is_strict_direct_loopback(conn: HTTPConnection, port: int) -> bool:
    client_host = conn.client.host if conn.client else ""
    if client_host not in ("127.0.0.1", "::1"):
        return False
    allowed_hosts = {
        f"127.0.0.1:{port}",
        f"localhost:{port}",
        f"[::1]:{port}",
        "127.0.0.1",
        "localhost",
        "[::1]",
    }
    host_hdr = (conn.headers.get("host") or "").strip().lower()
    if host_hdr not in allowed_hosts:
        return False
    for k in conn.headers.keys():
        kl = k.lower()
        if kl in STRICT_TUNNEL_HEADERS or kl in PROXY_HEADER_EXACT or kl.startswith(PROXY_HEADER_PREFIXES):
            return False
    return True


def _iter_public_url_args(eff_publics: Sequence[Any]) -> List[str]:
    out: List[str] = []
    for item in eff_publics:
        if isinstance(item, (list, tuple, set, frozenset)):
            for sub in item:
                s = str(sub or "").strip()
                if s:
                    out.append(s)
        elif isinstance(item, TrustedGatewayEndpoint):
            if item.base_url:
                out.append(item.base_url)
        else:
            s = str(item or "").strip()
            if s:
                out.append(s)
    return out


def build_allowed_hosts(port: int, *eff_publics: Any) -> List[str]:
    hosts = [
        f"127.0.0.1:{port}",
        f"localhost:{port}",
        f"[::1]:{port}",
        "127.0.0.1",
        "localhost",
        "[::1]",
        "testserver",
    ]
    for eff_public in _iter_public_url_args(eff_publics):
        cand = eff_public if "://" in eff_public else f"https://{eff_public}"
        u = urlsplit(cand)
        pub_host = (u.hostname or "").strip().lower()
        try:
            pub_port = u.port
        except ValueError:
            pub_port = None
        if pub_host and pub_host not in ("127.0.0.1", "localhost", "::1", "testserver"):
            host_fmt = f"[{pub_host}]" if ":" in pub_host else pub_host
            cands = [host_fmt, f"{host_fmt}:443", f"{host_fmt}:80", f"{host_fmt}:{port}"]
            if pub_port is not None:
                cands.append(f"{host_fmt}:{pub_port}")
            for item in cands:
                if item not in hosts:
                    hosts.append(item)
    return hosts


def _extract_origin_only(url_or_origin: str) -> str:
    """Extract strictly `scheme://netloc` via `urlsplit` so `/u/<id>` gateway paths never break Origin matching."""
    raw = (url_or_origin or "").strip()
    if not raw:
        return ""
    u = urlsplit(raw)
    if u.scheme and u.netloc:
        return f"{u.scheme.lower()}://{u.netloc.lower()}"
    return raw.rstrip("/").lower()


def _normalize_public_prefix_header(raw_prefix: str) -> str:
    clean = (raw_prefix or "").strip()
    if not clean or not clean.strip("/"):
        return ""
    pref = "/" + clean.strip("/")
    if not re.match(r"^/[a-zA-Z0-9._~/-]+$", pref) or ".." in pref or "//" in pref:
        return ""
    return pref


def build_allowed_origins(port: int, *eff_publics: Any) -> List[str]:
    origins = [
        "https://gemini.google.com",
        "https://chatgpt.com",
        "https://platform.openai.com",
        "https://claude.ai",
        f"http://127.0.0.1:{port}",
        f"http://localhost:{port}",
        "http://127.0.0.1:*",
        "http://localhost:*",
        "http://127.0.0.1",
        "http://localhost",
    ]
    for eff_public in _iter_public_url_args(eff_publics):
        pub_origin = _extract_origin_only(eff_public)
        if pub_origin and pub_origin not in origins:
            origins.append(pub_origin)
    return origins


class OriginGuardASGI:
    """Enforce browser `Origin` allowlist (`403` on untrusted Origin) and handle `OPTIONS` CORS preflight (`204`)."""

    def __init__(self, app: Any, allowed_origins: Sequence[str] | Set[str]) -> None:
        self.app = app
        self.exact_origins: Set[str] = set()
        self.wildcard_prefixes: List[str] = []
        self.allowed_origins = allowed_origins  # type: ignore[assignment]

    @property
    def allowed_origins(self) -> List[str]:
        return sorted(self.exact_origins) + [f"{p}*" for p in self.wildcard_prefixes]

    @allowed_origins.setter
    def allowed_origins(self, values: Iterable[str]) -> None:
        next_exact: Set[str] = set()
        next_wild: List[str] = []
        for raw in values or ():
            if not raw:
                continue
            low = str(raw).strip().rstrip("/").lower()
            if low.endswith(":*"):
                pref = low[:-1]
                if pref not in next_wild:
                    next_wild.append(pref)
            else:
                norm_exact = _extract_origin_only(low)
                if norm_exact:
                    next_exact.add(norm_exact)
        self.exact_origins.clear()
        self.exact_origins.update(next_exact)
        self.wildcard_prefixes[:] = next_wild

    def _is_origin_allowed(self, origin: str) -> bool:
        norm = _extract_origin_only(origin)
        if not norm:
            return False
        if norm in self.exact_origins:
            return True
        if any(_extract_origin_only(item) == norm for item in self.exact_origins):
            return True
        return any(norm.startswith(pref) for pref in self.wildcard_prefixes)

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1", errors="replace").strip() for k, v in scope.get("headers", ())}
        origin = headers.get("origin", "")
        method = str(scope.get("method") or "GET").upper()

        if origin and not self._is_origin_allowed(origin):
            resp = JSONResponse(
                {"error": "forbidden_origin", "detail": f"Untrusted browser Origin `{origin}` rejected."},
                status_code=403,
            )
            await resp(scope, receive, send)
            return

        if method == "OPTIONS":
            req_hdrs = headers.get("access-control-request-headers") or (
                "Authorization, Content-Type, Accept, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID"
            )
            preflight_headers = {
                "Allow": "GET, POST, DELETE, OPTIONS",
                "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
                "Access-Control-Allow-Headers": req_hdrs,
                "Access-Control-Expose-Headers": "Mcp-Session-Id",
                "Access-Control-Max-Age": "86400",
            }
            if origin:
                preflight_headers["Access-Control-Allow-Origin"] = origin
                preflight_headers["Vary"] = "Origin"
            resp = Response(status_code=204, headers=preflight_headers)
            await resp(scope, receive, send)
            return

        if not origin:
            await self.app(scope, receive, send)
            return

        async def send_with_cors(message: Dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                raw_hdrs = list(message.get("headers") or [])
                existing = {k.decode("latin-1").lower() for k, _ in raw_hdrs}
                if "access-control-allow-origin" not in existing:
                    raw_hdrs.append((b"access-control-allow-origin", origin.encode("latin-1")))
                if "access-control-expose-headers" not in existing:
                    raw_hdrs.append((b"access-control-expose-headers", b"Mcp-Session-Id"))
                if "vary" not in existing:
                    raw_hdrs.append((b"vary", b"Origin"))
                message = {**message, "headers": raw_hdrs}
            await send(message)

        await self.app(scope, receive, send_with_cors)


def _normalize_result_to_call_tool_result(raw_payload: Any, is_error: bool) -> types.CallToolResult:
    """Serialize dispatcher output into explicit `types.CallToolResult` (`ensure_ascii=False`, zero double payload)."""
    if isinstance(raw_payload, types.CallToolResult):
        return raw_payload

    if isinstance(raw_payload, (list, tuple)):
        blocks: List[types.ContentBlock] = []
        for item in raw_payload:
            if isinstance(item, (types.TextContent, types.ImageContent, types.EmbeddedResource)):
                blocks.append(item)
            elif isinstance(item, dict):
                btype = item.get("type")
                if btype == "image" and item.get("data") and item.get("mimeType"):
                    blocks.append(types.ImageContent(type="image", data=str(item["data"]), mimeType=str(item["mimeType"])))
                elif btype == "text":
                    blocks.append(types.TextContent(type="text", text=str(item.get("text") or "")))
                else:
                    blocks.append(types.TextContent(type="text", text=json.dumps(item, ensure_ascii=False)))
            else:
                blocks.append(types.TextContent(type="text", text=str(item)))
        if not blocks:
            blocks.append(types.TextContent(type="text", text=""))
        return types.CallToolResult(content=blocks, isError=bool(is_error))

    text_str = raw_payload if isinstance(raw_payload, str) else json.dumps(raw_payload, ensure_ascii=False)
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text_str)],
        isError=bool(is_error),
    )


def create_lowlevel_mcp_server(
    dispatcher: KernelDispatcher,
    *,
    readonly_only: bool = False,
    server_name: str = "",
) -> LowLevelServer:
    """Create a physically isolated `mcp.server.lowlevel.Server` instance (zero `FastMCP._*` private access)."""
    eff_p = dispatcher.prefix
    default_name = (
        (f"local_{eff_p}_mcp_readonly" if eff_p != "pc" else "local_pc_mcp_readonly")
        if readonly_only
        else (f"local_{eff_p}_mcp" if eff_p != "pc" else "local_pc_mcp")
    )
    srv = LowLevelServer(
        name=server_name or default_name,
        version=PRODUCT_VERSION,
        instructions=build_server_instructions(dispatcher, dispatcher.policy, readonly_only=readonly_only),
    )

    def _refresh_srv_instructions(_pol: Optional[LiveRuntimePolicy] = None) -> None:
        srv.instructions = build_server_instructions(dispatcher, dispatcher.policy, readonly_only=readonly_only)

    dispatcher.policy.add_policy_listener(_refresh_srv_instructions)

    @srv.list_tools()
    async def _handle_list_tools(req: types.ListToolsRequest) -> types.ListToolsResult:
        _ = req
        ctx = _REQUEST_TRANSPORT_CTX.get()
        dispatcher.record_seen_epoch(ctx.session_hint)
        specs = dispatcher.active_tool_specs(
            scopes=ctx.scopes,
            readonly_only=readonly_only,
        )
        is_ro_mode = readonly_only or not dispatcher.policy.allow_edit
        tools_list: List[types.Tool] = []
        for sp in specs:
            schema = json.loads(json.dumps(sp.input_schema))
            if is_ro_mode:
                act_p = (schema.get("properties") or {}).get(sp.action_param)
                if isinstance(act_p, dict):
                    if sp.base_name == "workspace_memory":
                        act_p["enum"] = ["read", "search"]
                    elif sp.base_name == "skill_manage":
                        act_p["enum"] = ["list", "trash_list"]
                    elif sp.base_name == "code_intel":
                        cur_enum = act_p.get("enum") or list(sp.action_enum)
                        act_p["enum"] = [str(v) for v in cur_enum if str(v) != "rename_symbol"]
            desc = build_tool_description(sp, specs, dispatcher.policy, host_label=dispatcher.policy.device_label)
            desc = dispatcher.rewrite_prefix_in_payload(desc)
            if readonly_only:
                ann = _ro_ann(sp.title, open_world=sp.open_world)
            else:
                ann = build_annotations_for_spec(
                    sp,
                    annotation_mode=dispatcher.policy.annotation_mode,
                    is_gemini_client=ctx.is_gemini,
                    approval_popups=dispatcher.policy.approval_popups,
                )
            tools_list.append(
                types.Tool(
                    name=dispatcher.prefixed_name(sp.base_name),
                    title=sp.title,
                    description=desc,
                    inputSchema=schema,
                    annotations=ann,
                )
            )
        return types.ListToolsResult(tools=tools_list)

    @srv.call_tool(validate_input=False)
    async def _handle_call_tool(name: str, arguments: Dict[str, Any]) -> types.CallToolResult:
        ctx = _REQUEST_TRANSPORT_CTX.get()
        base_nm, _ = dispatcher.strip_prefix_and_resolve_base(name)
        ctx.active_tool_box[0] = base_nm or (name or "")
        clean_in_args = unsanitize_ipi_payload(arguments or {})
        call_args = clean_in_args if isinstance(clean_in_args, dict) else {}
        raw_out, is_err = await dispatcher.call_tool_raw(
            name,
            call_args,
            scopes=ctx.scopes,
            readonly_only=readonly_only,
            session_hint=ctx.session_hint,
            client_platform=ctx.client_platform,
            bound_node_id=ctx.bound_node_id,
        )
        if not is_err and ctx.is_remote and ctx.public_url and ctx.preview_secret:
            if base_nm == "read_file":
                raw_out = _inject_preview_url_into_blocks(
                    raw_out,
                    call_args,
                    dispatcher.policy,
                    ctx.public_url,
                    ctx.preview_secret,
                )
        return _normalize_result_to_call_tool_result(raw_out, is_err)

    return srv


@dataclass
class DualMcpTransportBundle:
    """Physically isolated `/mcp` and `/mcp/readonly` `LowLevelServer` + `StreamableHTTPSessionManager` pairs."""

    main_server: LowLevelServer
    readonly_server: LowLevelServer
    main_session_manager: StreamableHTTPSessionManager
    readonly_session_manager: StreamableHTTPSessionManager


def create_dual_session_managers(
    dispatcher: KernelDispatcher,
    *,
    port: int = 8096,
    public_url: str = "",
) -> DualMcpTransportBundle:
    eff_public = (public_url or f"http://127.0.0.1:{port}").rstrip("/")
    sec = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=build_allowed_hosts(port, eff_public),
        allowed_origins=build_allowed_origins(port, eff_public),
    )
    main_srv = create_lowlevel_mcp_server(dispatcher, readonly_only=False)
    ro_srv = create_lowlevel_mcp_server(dispatcher, readonly_only=True)
    main_mgr = StreamableHTTPSessionManager(
        app=main_srv,
        stateless=True,
        json_response=True,
        security_settings=sec,
    )
    ro_mgr = StreamableHTTPSessionManager(
        app=ro_srv,
        stateless=True,
        json_response=True,
        security_settings=sec,
    )
    return DualMcpTransportBundle(
        main_server=main_srv,
        readonly_server=ro_srv,
        main_session_manager=main_mgr,
        readonly_session_manager=ro_mgr,
    )


class McpTransportEnvelopeASGI:
    """Bind request identity ContextVar, enforce RFC 8707 audience/scope boundary, and adapt wire payloads."""

    def __init__(
        self,
        session_manager: StreamableHTTPSessionManager,
        *,
        policy: LiveRuntimePolicy,
        readonly_only: bool = False,
        store: Optional[OAuthSQLiteStore] = None,
        local_api_token: str = "",
        sanitize_taint: bool = True,
        public_url_getter: Optional[Callable[[], str]] = None,
        preview_secret_getter: Optional[Callable[[], bytes]] = None,
    ) -> None:
        self.session_manager = session_manager
        self.policy = policy
        self.readonly_only = bool(readonly_only)
        self.store = store
        self.local_api_token = local_api_token
        self.sanitize_taint = sanitize_taint
        self.public_url_getter = public_url_getter
        self.preview_secret_getter = preview_secret_getter

    def _build_context(self, scope: Dict[str, Any]) -> RequestTransportContext:
        req_ua = ""
        mcp_sid = ""
        auth_fp = ""
        raw_auth_val = ""
        raw_pub_pfx = ""
        raw_node_hdr = ""
        has_proxy_hdr = False
        for hk, hv in scope.get("headers", ()):
            kl = hk.lower()
            if kl == b"user-agent":
                req_ua = hv.decode("latin-1", errors="replace").strip()
            elif kl == b"mcp-session-id":
                mcp_sid = hv.decode("latin-1", errors="replace").strip()[:24]
            elif kl == b"authorization":
                raw_auth_val = hv.decode("latin-1", errors="replace").strip()
                if raw_auth_val:
                    auth_fp = hashlib.sha256(raw_auth_val.encode("utf-8")).hexdigest()[:8]
            elif kl == b"x-cosmos-public-prefix":
                raw_pub_pfx = hv.decode("latin-1", errors="replace").strip()
            elif kl in (b"x-cosmos-node-id", b"x-cosmos-target-node"):
                raw_node_hdr = hv.decode("latin-1", errors="replace").strip()
            elif kl in (b"x-forwarded-for", b"cf-connecting-ip", b"x-real-ip", b"forwarded", b"cf-ray", b"x-cosmos-via-tunnel"):
                has_proxy_hdr = True

        client_peer = str((scope.get("client") or ("", 0))[0] or "").strip().lower()
        is_direct_local = bool(
            client_peer in ("127.0.0.1", "::1", "localhost")
            and not has_proxy_hdr
            and self.local_api_token
            and hmac.compare_digest(raw_auth_val, f"Bearer {self.local_api_token}")
        )

        client_id = ""
        scopes_fset: Optional[frozenset[str]] = None
        client_platform = "Custom MCP Client"
        is_gemini = is_google_user_agent(req_ua)

        user_obj = scope.get("user")
        access_tok = getattr(user_obj, "access_token", None) if user_obj is not None else None
        if access_tok is not None:
            client_id = str(getattr(access_tok, "client_id", "") or "")
            raw_sc = getattr(access_tok, "scopes", None)
            scopes_fset = (
                frozenset(str(s) for s in raw_sc if str(s).strip())
                if raw_sc is not None
                else frozenset()
            )
            if client_id == "local_desktop_owner":
                client_platform = "Local Desktop IDE"
            elif client_id and self.store is not None:
                c_doc = self.store.get("client", client_id)
                if isinstance(c_doc, dict):
                    c_name = str(c_doc.get("client_name") or "")
                    c_uris = c_doc.get("redirect_uris") or []
                    client_platform, _ = identify_client_platform(c_name, c_uris)
                    if is_google_gemini_client(c_name, c_uris):
                        is_gemini = True
        elif user_obj is not None and bool(getattr(user_obj, "is_authenticated", False)):
            auth_creds = scope.get("auth")
            raw_auth_sc = getattr(auth_creds, "scopes", None)
            scopes_fset = (
                frozenset(str(s) for s in raw_auth_sc if str(s).strip())
                if raw_auth_sc is not None
                else frozenset()
            )

        bound_node_id = ""
        req_gw = get_current_request_gateway()
        if req_gw is not None and req_gw.public_prefix.startswith("/u/"):
            bound_node_id = req_gw.public_prefix[3:].strip("/")
        if not bound_node_id and raw_pub_pfx:
            norm_p = _normalize_public_prefix_header(raw_pub_pfx)
            if norm_p.startswith("/u/"):
                bound_node_id = norm_p[3:].strip("/")
        if not bound_node_id and access_tok is not None:
            tok_res_s = str(getattr(access_tok, "resource", "") or "").strip()
            if tok_res_s:
                m_u = re.match(r"^/u/([a-zA-Z0-9_-]{2,64})(?:/|$)", urlsplit(tok_res_s).path or "")
                if m_u:
                    bound_node_id = m_u.group(1)
        if not bound_node_id and raw_node_hdr and re.match(r"^[a-zA-Z0-9_-]{1,64}$", raw_node_hdr):
            bound_node_id = raw_node_hdr

        sess_hint = mcp_sid or (f"tok:{auth_fp}" if auth_fp else (req_ua[:24] or "http"))
        is_remote_req = not is_direct_local
        pub_u = ""
        prev_sec = b""
        if is_remote_req and self.public_url_getter is not None and self.preview_secret_getter is not None:
            cand_pub = (self.public_url_getter() or "").strip().rstrip("/")
            if _is_valid_public_preview_base(cand_pub):
                pub_u = cand_pub
                prev_sec = self.preview_secret_getter()
        return RequestTransportContext(
            user_agent=req_ua,
            client_id=client_id,
            client_platform=client_platform,
            is_gemini=is_gemini,
            scopes=scopes_fset,
            session_hint=sess_hint,
            is_remote=is_remote_req,
            public_url=pub_u,
            preview_secret=prev_sec,
            bound_node_id=bound_node_id,
        )

    def _check_cross_resource_escalation(self, scope: Dict[str, Any]) -> Optional[JSONResponse]:
        """Reject `/mcp/readonly` or read-only-scoped tokens attempting upward access to full `/mcp` (RFC 8707)."""
        if self.readonly_only:
            return None
        user_obj = scope.get("user")
        access_tok = getattr(user_obj, "access_token", None) if user_obj is not None else None
        if access_tok is not None:
            tok_res = str(getattr(access_tok, "resource", "") or "").strip()
            raw_sc = getattr(access_tok, "scopes", None)
            tok_scopes = {str(s).strip() for s in (raw_sc or ()) if str(s).strip()}
            if is_readonly_resource_url(tok_res) or "workspace" not in tok_scopes:
                return JSONResponse(
                    {
                        "error": "forbidden_cross_resource",
                        "error_description": "Readonly endpoint token cannot access full /mcp endpoint",
                    },
                    status_code=403,
                    headers={"Cache-Control": "no-store"},
                )
            return None
        if user_obj is not None and bool(getattr(user_obj, "is_authenticated", False)):
            auth_creds = scope.get("auth")
            raw_auth_sc = getattr(auth_creds, "scopes", None)
            if raw_auth_sc is not None:
                cred_scopes = {str(s).strip() for s in raw_auth_sc if str(s).strip()}
                if "workspace" not in cred_scopes:
                    return JSONResponse(
                        {
                            "error": "forbidden_cross_resource",
                            "error_description": "Readonly endpoint token cannot access full /mcp endpoint",
                        },
                        status_code=403,
                        headers={"Cache-Control": "no-store"},
                    )
        return None

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.session_manager.handle_request(scope, receive, send)
            return

        cross_err = self._check_cross_resource_escalation(scope)
        if cross_err is not None:
            await cross_err(scope, receive, send)
            return

        self.policy.refresh()
        ctx = self._build_context(scope)
        tok = _REQUEST_TRANSPORT_CTX.set(ctx)
        try:
            start_msg: Optional[Dict[str, Any]] = None
            resp_ctype = ""
            chunks: List[bytes] = []
            sse_buf = b""
            passthrough_sse = False

            async def send_wrapper(message: Dict[str, Any]) -> None:
                nonlocal start_msg, resp_ctype, sse_buf, passthrough_sse
                if message["type"] == "http.response.start":
                    hdrs = {k.decode("latin-1").lower(): v.decode("latin-1", errors="replace") for k, v in message.get("headers", [])}
                    resp_ctype = hdrs.get("content-type", "")
                    if "text/event-stream" in resp_ctype.lower():
                        passthrough_sse = True
                        await send(message)
                    else:
                        start_msg = message
                elif message["type"] == "http.response.body":
                    if passthrough_sse:
                        sse_buf += message.get("body", b"")
                        more = bool(message.get("more_body", False))
                        if more:
                            nl_idx = sse_buf.rfind(b"\n")
                            if nl_idx >= 0:
                                ready = sse_buf[: nl_idx + 1]
                                sse_buf = sse_buf[nl_idx + 1 :]
                                body = transform_mcp_wire_bytes(
                                    ready,
                                    content_type=resp_ctype,
                                    user_agent=ctx.user_agent,
                                    sanitize_taint=self.sanitize_taint,
                                    tool_name=ctx.active_tool_box[0],
                                )
                                await send({**message, "body": body})
                        else:
                            body = (
                                transform_mcp_wire_bytes(
                                    sse_buf,
                                    content_type=resp_ctype,
                                    user_agent=ctx.user_agent,
                                    sanitize_taint=self.sanitize_taint,
                                    tool_name=ctx.active_tool_box[0],
                                )
                                if sse_buf
                                else b""
                            )
                            sse_buf = b""
                            await send({**message, "body": body, "more_body": False})
                    else:
                        chunks.append(message.get("body", b""))
                        if not message.get("more_body", False):
                            full = transform_mcp_wire_bytes(
                                b"".join(chunks),
                                content_type=resp_ctype,
                                user_agent=ctx.user_agent,
                                sanitize_taint=self.sanitize_taint,
                                tool_name=ctx.active_tool_box[0],
                            )
                            new_headers = [
                                (k, v)
                                for k, v in (start_msg.get("headers", []) if start_msg else [])
                                if k.lower() != b"content-length"
                            ]
                            new_headers.append((b"content-length", str(len(full)).encode("ascii")))
                            if start_msg:
                                await send({**start_msg, "headers": new_headers})
                            await send({"type": "http.response.body", "body": full, "more_body": False})
                else:
                    await send(message)

            await self.session_manager.handle_request(scope, receive, send_wrapper)
        finally:
            _REQUEST_TRANSPORT_CTX.reset(tok)


class OAuthStoreBusyMiddleware:
    """Map transient OAuth SQLite lock errors (`OAuthStoreBusyError`) to `HTTP 503` + `Retry-After: 1` (never `401`)."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        try:
            await self.app(scope, receive, send)
        except OAuthStoreBusyError as exc:
            retry_after_s = str(max(1, int(getattr(exc, "retry_after", 1) or 1)))
            resp = JSONResponse(
                {
                    "error": "temporarily_unavailable",
                    "error_description": "OAuth token store is temporarily busy; please retry shortly.",
                },
                status_code=503,
                headers={
                    "Retry-After": retry_after_s,
                    "Cache-Control": "no-store",
                },
            )
            await resp(scope, receive, send)


class LoopbackOrOAuthBearerBackend(BearerAuthBackend):
    """Verify OAuth 2.1 Bearer tokens for `/mcp` & `/mcp/readonly`, plus `local_api_token` on strict loopback."""

    def __init__(
        self,
        token_verifier: ProviderTokenVerifier,
        resource_server_url: AnyHttpUrl,
        *,
        local_api_token: str,
        allowed_resources: Set[str],
        port: int,
        provider: Optional[OAuthProvider] = None,
    ) -> None:
        super().__init__(token_verifier, resource_server_url=resource_server_url)
        self.local_api_token = local_api_token
        self.allowed_resources = {r.rstrip("/") for r in allowed_resources}
        self.port = port
        self.provider = provider

    def _issued_for_this_resource(self, tok_res: Optional[str]) -> bool:
        if not tok_res:
            return False
        if self.provider is not None and hasattr(self.provider, "is_token_resource_valid_for_current_request"):
            return bool(self.provider.is_token_resource_valid_for_current_request(tok_res))
        if super()._issued_for_this_resource(tok_res):
            return True
        norm_tok = str(tok_res).rstrip("/")
        if norm_tok in self.allowed_resources:
            return True
        return False

    async def authenticate(self, conn: HTTPConnection) -> Optional[Tuple[AuthCredentials, AuthenticatedUser]]:
        req_path = str(conn.scope.get("path") or "")
        if req_path == "/_cosmos_node" or req_path.startswith("/_cosmos_node/"):
            return None
        auth_header = conn.headers.get("Authorization") or conn.headers.get("authorization") or ""
        if auth_header.lower().startswith("bearer ") and self.local_api_token:
            candidate = auth_header[7:].strip()
            if is_strict_direct_loopback(conn, self.port) and hmac.compare_digest(candidate, self.local_api_token):
                tok = AccessToken(
                    token=candidate,
                    client_id="local_desktop_owner",
                    scopes=list(SCOPES),
                    expires_at=int(time.time()) + 86400,
                    resource=str(self.resource_server_url) if self.resource_server_url else None,
                    subject="owner",
                )
                return AuthCredentials(list(SCOPES)), AuthenticatedUser(tok)
        return await super().authenticate(conn)


def create_protocol_app(
    dispatcher: KernelDispatcher,
    *,
    policy: Optional[LiveRuntimePolicy] = None,
    store: Optional[OAuthSQLiteStore] = None,
    provider: Optional[OAuthProvider] = None,
    proc_mgr: Optional[ProcessManager] = None,
    public_url: str = "",
    port: int = 8096,
    local_api_token: str = "",
    sanitize_taint: bool = True,
    tunnel_mode: str = "",
    allow_remote_admin_policy: Optional[bool] = None,
) -> Starlette:
    """Assemble full Starlette ASGI app with OAuth 2.1 DCR/PKCE, dual `/mcp` + `/mcp/readonly`, and remote policy admin."""
    pol = policy or dispatcher.policy
    eff_proc_mgr = proc_mgr if proc_mgr is not None else DEFAULT_PROCESS_MANAGER
    eff_prefix = normalize_prefix(pol.eff_prefix)
    eff_public = (public_url or f"http://127.0.0.1:{port}").rstrip("/")

    if store is None or provider is None or not local_api_token:
        creds = ensure_initialized(
            product_root=pol.state_root,
            public_url=eff_public,
            port=port,
            cli_state_dir=str(pol.state_root),
            tier_key=pol.tier_key,
            prefix=eff_prefix,
            device_label=pol.device_label,
            toolset_profile=pol.toolset_profile,
            workspace_roots=pol.workspace_roots,
            enabled_packs=pol.enabled_packs,
            keep_awake=pol.keep_awake,
            approval_popups=pol.approval_popups,
        )
        eff_admin_token = local_api_token or str(creds["local_api_token"])
        oauth_db_name = f"oauth_{eff_prefix}.sqlite3" if eff_prefix != "pc" else "oauth.sqlite3"
        eff_store = store or OAuthSQLiteStore(pol.state_root / "state" / oauth_db_name)
    else:
        creds = {"password_hash": provider.password_hash, "salt": provider.salt, "local_api_token": local_api_token}
        eff_admin_token = local_api_token
        eff_store = store

    base = AnyHttpUrl(eff_public)
    canonical_issuer = str(base).rstrip("/")
    resource = AnyHttpUrl(eff_public + "/mcp")
    readonly_resource = AnyHttpUrl(eff_public + "/mcp/readonly")
    allowed_res = {
        eff_public,
        eff_public + "/mcp",
        eff_public + "/mcp/readonly",
        f"http://127.0.0.1:{port}",
        f"http://127.0.0.1:{port}/mcp",
        f"http://127.0.0.1:{port}/mcp/readonly",
    }

    eff_tunnel_mode = (
        tunnel_mode
        or str(getattr(pol, "tunnel_mode", "") or "")
        or os.environ.get("COSMOS_TUNNEL_MODE", "")
        or os.environ.get("LOCALPC_TUNNEL_MODE", "")
    ).strip().lower()

    eff_provider = provider or OAuthProvider(
        store=eff_store,
        base_url=eff_public,
        password_hash=str(creds["password_hash"]),
        salt=str(creds["salt"]),
        redirect_hosts=DEFAULT_REDIRECT_HOSTS,
        allowed_resources=allowed_res,
        tier_label=pol.dynamic_tier_label(),
        issuer=canonical_issuer,
        tier_key=pol.tier_key,
        toolset_profile=pol.toolset_profile,
        exposed_tools=[dispatcher.prefixed_name(sp.base_name) for sp in dispatcher.active_tool_specs()],
        tool_prefix=eff_prefix,
        tunnel_mode=eff_tunnel_mode,
        local_port=port,
    )
    eff_provider.local_port = int(port)
    if eff_tunnel_mode and not eff_provider.tunnel_mode:
        eff_provider.tunnel_mode = eff_tunnel_mode

    def _on_kill_signal(sig_doc: Dict[str, Any]) -> None:
        p_filt = str(sig_doc.get("prefix_filter") or eff_prefix).strip()
        reason = str(sig_doc.get("reason") or "kill_signal")
        try:
            eff_proc_mgr.kill_all_active_commands(reason=reason, prefix_filter=p_filt)
        except Exception:
            pass
        try:
            dispatcher.shutdown_packs(prefix_filter=p_filt)
        except Exception:
            pass

    kill_watchdog = KillSignalWatchdog(
        pol.state_root,
        eff_prefix=eff_prefix,
        policy=pol,
        on_kill_callbacks=[_on_kill_signal],
    )

    bearer_backend = LoopbackOrOAuthBearerBackend(
        ProviderTokenVerifier(eff_provider),
        resource_server_url=resource,
        local_api_token=eff_admin_token,
        allowed_resources=allowed_res,
        port=port,
        provider=eff_provider,
    )

    def _persist_audit_event(ev: Any) -> None:
        append_audit_log(
            pol.state_root / "logs" / "audit.jsonl",
            {
                "call_id": ev.call_id,
                "epoch_ts": ev.ts,
                "caller": ev.caller,
                "tool": ev.tool,
                "resolved_tool": ev.resolved_tool,
                "base_name": ev.base_name,
                "safety_band": ev.safety_band,
                "tier": ev.tier,
                "ok": ev.ok,
                "status": "ok" if ev.ok else "error",
                "duration_ms": ev.duration_ms,
                "error": ev.error,
                "blocked_reason": ev.blocked_reason,
            },
        )

    dispatcher.register_audit_callback("persist_audit_jsonl", _persist_audit_event)

    def _on_auth_reload(creds_doc: Dict[str, Any]) -> None:
        if creds_doc.get("password_hash"):
            eff_provider.password_hash = str(creds_doc["password_hash"])
        if creds_doc.get("salt"):
            eff_provider.salt = str(creds_doc["salt"])
        if creds_doc.get("local_api_token"):
            bearer_backend.local_api_token = str(creds_doc["local_api_token"])

    pol.add_auth_listener(_on_auth_reload)

    def _get_active_public_url() -> str:
        gw = get_current_request_gateway()
        if gw is not None and not gw.is_loopback and _is_valid_public_preview_base(gw.base_url):
            return gw.base_url
        prov_base = str(getattr(eff_provider, "base_url", "") or "").strip().rstrip("/")
        if _is_valid_public_preview_base(prov_base):
            return prov_base
        if _is_valid_public_preview_base(eff_public):
            return eff_public
        return ""

    def _get_preview_secret() -> bytes:
        seed = f"cosmos-mcp-preview-v1:{bearer_backend.local_api_token}:{eff_provider.salt}:{eff_provider.password_hash}"
        return hashlib.sha256(seed.encode("utf-8")).digest()

    bundle = create_dual_session_managers(dispatcher, port=port, public_url=eff_public)
    main_envelope = McpTransportEnvelopeASGI(
        bundle.main_session_manager,
        policy=pol,
        readonly_only=False,
        store=eff_store,
        local_api_token=eff_admin_token,
        sanitize_taint=sanitize_taint,
        public_url_getter=_get_active_public_url,
        preview_secret_getter=_get_preview_secret,
    )
    readonly_envelope = McpTransportEnvelopeASGI(
        bundle.readonly_session_manager,
        policy=pol,
        readonly_only=True,
        store=eff_store,
        local_api_token=eff_admin_token,
        sanitize_taint=sanitize_taint,
        public_url_getter=_get_active_public_url,
        preview_secret_getter=_get_preview_secret,
    )

    options = ClientRegistrationOptions(
        enabled=True,
        valid_scopes=eff_provider.valid_scopes,
        default_scopes=eff_provider.default_scopes,
    )

    def _is_trusted_public_prefix(cand_prefix: str, request: Optional[Request] = None) -> bool:
        norm_p = _normalize_public_prefix_header(cand_prefix)
        if not norm_p:
            return cand_prefix.strip("/") == ""
        trusted_pfxs: set[str] = set()
        for ep in eff_provider.get_effective_trusted_gateways().values():
            if ep.public_prefix:
                trusted_pfxs.add(_normalize_public_prefix_header(ep.public_prefix))
            ep_p = (urlsplit(ep.base_url).path or "").rstrip("/")
            if ep_p:
                trusted_pfxs.add(_normalize_public_prefix_header(ep_p))
        for raw_u in (str(getattr(eff_provider, "base_url", "") or ""), eff_public, *eff_provider.allowed_resources):
            if not raw_u:
                continue
            up = (urlsplit(raw_u).path or "").rstrip("/")
            if up.endswith("/mcp/readonly"):
                up = up[: -len("/mcp/readonly")]
            elif up.endswith("/mcp"):
                up = up[: -len("/mcp")]
            if up:
                trusted_pfxs.add(_normalize_public_prefix_header(up))
        node_id_cfg = str(getattr(pol, "public_gateway_node_id", "") or "").strip()
        if node_id_cfg:
            trusted_pfxs.add(_normalize_public_prefix_header(f"/u/{node_id_cfg}"))
        if request is not None:
            hdr_pfx_req = _normalize_public_prefix_header(request.headers.get("x-cosmos-public-prefix", ""))
            peer_h = ((request.client.host if request.client else "") or "").strip().lower()
            if hdr_pfx_req and hdr_pfx_req == norm_p and peer_h in ("127.0.0.1", "::1", "localhost", "testclient"):
                if re.fullmatch(r"/u/[A-Za-z0-9_-]{1,64}", norm_p):
                    trusted_pfxs.add(norm_p)
        trusted_pfxs.discard("")
        return norm_p in trusted_pfxs

    def _current_public_base(request: Optional[Request] = None, embedded_prefix: str = "") -> str:
        gw = get_current_request_gateway()
        raw_hdr_pfx = _normalize_public_prefix_header(request.headers.get("x-cosmos-public-prefix", "")) if request is not None else ""
        hdr_pfx = raw_hdr_pfx if (raw_hdr_pfx and _is_trusted_public_prefix(raw_hdr_pfx, request=request)) else ""
        raw_emb = _normalize_public_prefix_header(embedded_prefix)
        clean_emb = raw_emb if (raw_emb and _is_trusted_public_prefix(raw_emb, request=request)) else ""
        if gw is not None:
            origin = f"{gw.scheme}://{gw.authority}"
            eff_path = clean_emb or hdr_pfx or gw.public_prefix
        else:
            cur = str(getattr(eff_provider, "base_url", "") or eff_public).strip().rstrip("/")
            raw_base = cur if cur.startswith(("http://", "https://")) else eff_public
            u = urlsplit(raw_base)
            origin = f"{u.scheme}://{u.netloc}"
            base_path = (u.path or "").rstrip("/")
            eff_path = clean_emb or hdr_pfx or base_path
        return f"{origin}{eff_path}".rstrip("/")

    def _current_issuer(request: Optional[Request] = None, embedded_prefix: str = "") -> str:
        gw = get_current_request_gateway()
        raw_hdr_pfx = _normalize_public_prefix_header(request.headers.get("x-cosmos-public-prefix", "")) if request is not None else ""
        hdr_pfx = raw_hdr_pfx if (raw_hdr_pfx and _is_trusted_public_prefix(raw_hdr_pfx, request=request)) else ""
        raw_emb = _normalize_public_prefix_header(embedded_prefix)
        clean_emb = raw_emb if (raw_emb and _is_trusted_public_prefix(raw_emb, request=request)) else ""
        if hdr_pfx or clean_emb:
            return _current_public_base(request, embedded_prefix=clean_emb)
        if gw is not None and gw.issuer:
            return gw.issuer
        cur_iss = str(getattr(eff_provider, "issuer", "") or "").strip().rstrip("/")
        return cur_iss if cur_iss.startswith(("http://", "https://")) else str(AnyHttpUrl(_current_public_base())).rstrip("/")

    async def authorization_metadata(request: Request) -> JSONResponse:
        raw_sub = str(request.path_params.get("subpath") or "").strip("/")
        norm_sub = f"/{raw_sub}" if raw_sub else ""
        if norm_sub in ("/mcp", "/mcp/readonly"):
            emb_pfx = ""
        elif norm_sub.endswith("/mcp/readonly"):
            emb_pfx = norm_sub[: -len("/mcp/readonly")]
        elif norm_sub.endswith("/mcp"):
            emb_pfx = norm_sub[: -len("/mcp")]
        else:
            emb_pfx = norm_sub
        if emb_pfx and not _is_trusted_public_prefix(emb_pfx, request=request):
            return JSONResponse(
                {"error": "not_found", "error_description": "Unknown gateway subpath."},
                status_code=404,
                headers={"Cache-Control": "no-store"},
            )
        resolved_pub = _current_public_base(request, embedded_prefix=emb_pfx)
        dyn_base = AnyHttpUrl(resolved_pub)
        dyn_meta = build_metadata(dyn_base, None, options, RevocationOptions(enabled=True))
        dyn_meta.token_endpoint_auth_methods_supported = ["none", "client_secret_post", "client_secret_basic"]
        return JSONResponse(
            {
                **dyn_meta.model_dump(mode="json", exclude_none=True),
                "issuer": _current_issuer(request, embedded_prefix=emb_pfx),
                "authorization_response_iss_parameter_supported": True,
                "code_challenge_methods_supported": ["S256"],
            },
            headers={"Cache-Control": "no-store"},
        )

    async def exchange_token(request: Request) -> Response:
        pol.refresh()
        explicit_res: Optional[str] = None
        try:
            form_preview = await request.form()
            if "resource" in form_preview:
                raw_res_val = form_preview.get("resource")
                if raw_res_val is not None and str(raw_res_val).strip() != "":
                    explicit_res = str(raw_res_val).strip()
        except Exception:
            explicit_res = None
        res_tok = set_request_token_resource(explicit_res)
        try:
            response = await TokenHandler(eff_provider, ClientAuthenticator(eff_provider)).handle(request)
        finally:
            reset_request_token_resource(res_tok)
        if response.status_code == 200:
            try:
                tok = json.loads(response.body).get("access_token", "")
                if tok:
                    eff_provider.store.extend_access_token_ttl_atomic(tok, 1800)
            except Exception:
                pass
        return response

    async def revoke(request: Request) -> JSONResponse:
        pol.refresh()
        try:
            oauth_client = await ClientAuthenticator(eff_provider).authenticate_request(request)
        except AuthenticationError as error:
            return JSONResponse({"error": "invalid_client", "error_description": error.message}, status_code=401)
        form = await request.form()
        token = await eff_provider.load_access_token(str(form.get("token", "")))
        if token is None:
            token = await eff_provider.load_refresh_token(oauth_client, str(form.get("token", "")))
        if token is not None and token.client_id == oauth_client.client_id:
            await eff_provider.revoke_token(token)
        return JSONResponse({}, headers={"Cache-Control": "no-store"})

    async def consent_entry(request: Request) -> Response:
        pol.refresh()
        pol_tm = str(getattr(pol, "tunnel_mode", "") or "").strip().lower()
        if pol_tm and not tunnel_mode and not eff_provider.tunnel_mode:
            eff_provider.tunnel_mode = pol_tm
        return await eff_provider.consent(request)

    async def oauth_local_bridge_entry(request: Request) -> Response:
        from cosmos_mcp.protocol.oauth_web import handle_oauth_local_bridge_request

        pol.refresh()
        return await handle_oauth_local_bridge_request(eff_provider, request, expected_port=port)

    async def consent_complete_entry(request: Request) -> Response:
        from cosmos_mcp.protocol.oauth_web import handle_consent_complete_request

        pol.refresh()
        return await handle_consent_complete_request(eff_provider, request)

    def _is_request_authed(request: Request) -> Tuple[bool, Optional[frozenset[str]]]:
        try:
            u = getattr(request, "user", None)
            if u is not None and bool(getattr(u, "is_authenticated", False)):
                at = getattr(u, "access_token", None)
                if at is not None:
                    raw_at_sc = getattr(at, "scopes", None)
                    sc = frozenset(str(x) for x in raw_at_sc if str(x).strip()) if raw_at_sc is not None else frozenset()
                else:
                    auth_c = getattr(request, "auth", None)
                    raw_c_sc = getattr(auth_c, "scopes", None)
                    sc = frozenset(str(x) for x in raw_c_sc if str(x).strip()) if raw_c_sc is not None else frozenset()
                return True, sc
        except Exception:
            pass
        auth_h = (request.headers.get("authorization") or "").strip()
        if auth_h.lower().startswith("bearer "):
            cand_t = auth_h[7:].strip()
            rec = eff_store.get("access", cand_t) if cand_t else None
            if rec is not None:
                raw_sc_list = rec.get("scopes")
                sc_fset = (
                    frozenset(SCOPES)
                    if raw_sc_list is None
                    else frozenset(str(x) for x in raw_sc_list if str(x).strip())
                )
                return True, sc_fset
        return False, None

    async def root_status(request: Request) -> JSONResponse:
        pol.refresh()
        is_local = is_strict_direct_loopback(request, port)
        is_authed, tok_scopes = _is_request_authed(request)
        if not is_local and not is_authed:
            # Strict zero-path, zero-username public status response
            return JSONResponse(
                {
                    "status": "ok",
                    "service": "LocalPC MCP",
                    "version": PRODUCT_VERSION,
                    "mcp_endpoint": "/mcp",
                    "readonly_mcp_endpoint": "/mcp/readonly",
                    "skill_endpoint": "/skill",
                },
                headers={"Cache-Control": "no-store"},
            )
        specs = dispatcher.active_tool_specs(scopes=tok_scopes)
        return JSONResponse(
            {
                "status": "ok",
                "service": "LocalPC MCP",
                "version": PRODUCT_VERSION,
                "permission_tier": pol.tier_key,
                "permission_label": pol.dynamic_tier_label(tool_count=len(specs)),
                "toolset_profile": pol.toolset_profile,
                "tool_prefix": eff_prefix,
                "device_label": pol.device_label,
                "workspace": pol.workspace,
                "workspace_roots": [str(p) for p in pol.workspace_roots],
                "enabled_packs": list(pol.enabled_packs),
                "keep_awake": pol.keep_awake,
                "annotation_mode": pol.annotation_mode,
                "approval_popups": pol.approval_popups,
                "python_path": pol.python_path,
                "tool_count": len(specs),
                "exposed_tools": [dispatcher.prefixed_name(sp.base_name) for sp in specs],
            },
            headers={"Cache-Control": "no-store"},
        )

    from cosmos_mcp.core.config import parse_bool_flag as _parse_bool_flag

    eff_allow_remote_admin = (
        bool(allow_remote_admin_policy)
        if allow_remote_admin_policy is not None
        else _parse_bool_flag(
            os.environ.get("COSMOS_ALLOW_REMOTE_ADMIN_POLICY")
            or os.environ.get("LOCALPC_ALLOW_REMOTE_ADMIN_POLICY"),
            default=False,
        )
    )

    explicit_tm_arg = (tunnel_mode or "").strip().lower()

    def _is_public_gateway_admin_request(request: Request) -> bool:
        for raw_hk in request.headers.keys():
            hk_l = raw_hk.lower()
            if hk_l in STRICT_TUNNEL_HEADERS or hk_l in PROXY_HEADER_EXACT or hk_l.startswith(PROXY_HEADER_PREFIXES):
                return True
        if is_strict_direct_loopback(request, port):
            return False
        peer_h = ((request.client.host if request.client else "") or "").strip().lower()
        if peer_h not in ("127.0.0.1", "::1", "localhost", "testclient"):
            return True
        if peer_h != "testclient":
            return True
        if explicit_tm_arg not in ("", "local", "direct", "loopback"):
            return True
        return False

    async def skill_endpoint(request: Request) -> Response:
        pol.refresh()
        is_local = is_strict_direct_loopback(request, port)
        is_authed, tok_scopes = _is_request_authed(request)
        if not is_local and not is_authed:
            return JSONResponse(
                {"error": "unauthorized", "error_description": "Bearer authentication required."},
                status_code=401,
                headers={"Cache-Control": "no-store"},
            )
        lang = (request.query_params.get("lang") or "bilingual").strip()
        ro_flag = (request.query_params.get("readonly") or "").strip() in ("1", "true")
        md = render_skill_markdown(
            dispatcher,
            pol,
            scopes=tok_scopes if is_authed else None,
            readonly_only=ro_flag,
            port=port,
            lang=lang,
        )
        return Response(md, status_code=200, media_type="text/markdown; charset=utf-8", headers={"Cache-Control": "no-store"})

    async def admin_policy_endpoint(request: Request) -> JSONResponse:
        req_path = (request.url.path or "").rstrip("/")
        if req_path == "/local-admin/permissions" and not is_strict_direct_loopback(request, port):
            return JSONResponse(
                {"ok": False, "error": "local_loopback_required"},
                status_code=403,
                headers={"Cache-Control": "no-store"},
            )
        if req_path == "/remote-admin/policy" and not eff_allow_remote_admin and _is_public_gateway_admin_request(request):
            return JSONResponse(
                {"ok": False, "error": "remote_admin_policy_disabled_on_public_gateway"},
                status_code=403,
                headers={"Cache-Control": "no-store"},
            )
        ctype = (request.headers.get("content-type") or "").lower()
        if "application/json" in ctype:
            try:
                body_doc = await request.json()
            except Exception:
                return JSONResponse({"ok": False, "error": "invalid_json"}, status_code=400)
        else:
            form_d = await request.form()
            body_doc = {str(k): v for k, v in form_d.items()}

        hdr_admin = (
            request.headers.get("x-localpc-admin-token")
            or (
                request.headers.get("authorization", "")[7:].strip()
                if request.headers.get("authorization", "").lower().startswith("bearer ")
                else ""
            )
            or ""
        ).strip()
        client_ip = extract_request_client_ip(request, tunnel_mode=eff_provider.tunnel_mode)
        action = str(body_doc.get("action") or "").strip().lower()
        if action in ("revoke_client", "revoke_all"):
            from cosmos_mcp.protocol.oauth import verify_remote_management_auth

            auth_chk = verify_remote_management_auth(
                eff_store,
                eff_provider,
                owner_password=str(body_doc.get("owner_password") or body_doc.get("password") or ""),
                admin_token=hdr_admin or str(body_doc.get("admin_token") or ""),
                expected_admin_token=bearer_backend.local_api_token,
                client_ip=client_ip,
            )
            if not auth_chk.get("ok"):
                st = int(auth_chk.pop("status_code", 403))
                return JSONResponse(auth_chk, status_code=st, headers={"Cache-Control": "no-store"})
            if action == "revoke_client":
                cid = str(body_doc.get("client_id") or "").strip()
                if not cid:
                    return JSONResponse({"ok": False, "error": "client_id_required"}, status_code=400)
                rev = eff_store.revoke_client(cid, delete_client=bool(body_doc.get("delete_client")))
            else:
                rev = eff_store.revoke_all_tokens(delete_clients=bool(body_doc.get("delete_clients")))
            sig = emit_kill_signal(pol.state_root, reason=action, prefix_filter=eff_prefix)
            _on_kill_signal(sig)
            return JSONResponse({"ok": True, "action": action, "revocation": rev}, headers={"Cache-Control": "no-store"})

        res = validate_and_apply_remote_policy_update(
            pol,
            eff_store,
            eff_provider,
            body_doc if isinstance(body_doc, dict) else {},
            expected_admin_token=bearer_backend.local_api_token,
            admin_token_header=hdr_admin,
            client_ip=client_ip,
        )
        st_code = int(res.pop("status_code", 200))
        if res.get("ok") and not pol.allow_exec:
            sig = emit_kill_signal(pol.state_root, reason=f"tier_downgrade:{pol.tier_key}", prefix_filter=eff_prefix)
            _on_kill_signal(sig)
        return JSONResponse(res, status_code=st_code, headers={"Cache-Control": "no-store"})

    state_fp = hashlib.sha256(os.path.normcase(str(pol.state_root.resolve())).encode("utf-8")).hexdigest()[:12]

    async def health_endpoint(request: Request) -> JSONResponse:
        pol.refresh()
        if not is_strict_direct_loopback(request, port):
            return JSONResponse({"status": "ok"})
        return JSONResponse(
            {
                "status": "ok",
                "service": "cosmos-mcp",
                "state_fp": state_fp,
                "version": PRODUCT_VERSION,
                "permission_tier": pol.tier_key,
                "toolset_profile": pol.toolset_profile,
                "inflight": dispatcher.inflight_count,
                "tool_count": len(dispatcher.active_tool_specs()),
            },
            headers={"Cache-Control": "no-store"},
        )

    auth_routes = create_auth_routes(
        eff_provider,
        base,
        client_registration_options=options,
        revocation_options=RevocationOptions(enabled=True),
    )
    routes: List[Route] = []
    for route in auth_routes:
        if route.path == "/.well-known/oauth-authorization-server":
            routes.append(
                Route(
                    "/.well-known/oauth-authorization-server",
                    endpoint=cors_middleware(authorization_metadata, ["GET", "OPTIONS"]),
                    methods=["GET", "OPTIONS"],
                )
            )
        elif route.path == "/register":
            routes.append(
                Route(
                    "/register",
                    endpoint=RegisterGrantCompatASGI(route.app, tunnel_mode=eff_provider.tunnel_mode),
                    methods=route.methods,
                )
            )
        elif route.path == "/revoke":
            routes.append(Route("/revoke", endpoint=cors_middleware(revoke, ["POST", "OPTIONS"]), methods=["POST", "OPTIONS"]))
        elif route.path == "/authorize":
            routes.append(
                Route(
                    "/authorize",
                    endpoint=IssuerResponseMiddleware(route.app, eff_provider.issuer, provider=eff_provider),
                    methods=route.methods,
                )
            )
        elif route.path == "/token":
            routes.append(Route("/token", endpoint=cors_middleware(exchange_token, ["POST", "OPTIONS"]), methods=route.methods))
        else:
            routes.append(route)

    routes.append(
        Route(
            "/.well-known/oauth-authorization-server/{subpath:path}",
            endpoint=cors_middleware(authorization_metadata, ["GET", "OPTIONS"]),
            methods=["GET", "OPTIONS"],
        )
    )

    def _build_protected_res_doc(request: Request, *, readonly: bool, embedded_prefix: str = "") -> JSONResponse:
        pub_now = _current_public_base(request, embedded_prefix=embedded_prefix)
        auth_srv = _current_issuer(request, embedded_prefix=embedded_prefix)
        if readonly:
            return JSONResponse(
                {
                    "resource": f"{pub_now}/mcp/readonly",
                    "authorization_servers": [auth_srv],
                    "scopes_supported": list(READONLY_SCOPES),
                    "bearer_methods_supported": ["header"],
                    "resource_name": "LocalPC MCP (Read-Only)",
                },
                headers={"Cache-Control": "no-store"},
            )
        return JSONResponse(
            {
                "resource": f"{pub_now}/mcp",
                "authorization_servers": [auth_srv],
                "scopes_supported": list(SCOPES),
                "bearer_methods_supported": ["header"],
                "resource_name": "LocalPC MCP",
            },
            headers={"Cache-Control": "no-store"},
        )

    async def _protected_res_main(request: Request) -> JSONResponse:
        return _build_protected_res_doc(request, readonly=False)

    async def _protected_res_readonly(request: Request) -> JSONResponse:
        return _build_protected_res_doc(request, readonly=True)

    async def _protected_res_subpath(request: Request) -> JSONResponse:
        raw_sub = str(request.path_params.get("subpath") or "").strip("/")
        norm_sub = f"/{raw_sub}" if raw_sub else ""
        if norm_sub == "/mcp/readonly":
            return _build_protected_res_doc(request, readonly=True, embedded_prefix="")
        if norm_sub == "/mcp":
            return _build_protected_res_doc(request, readonly=False, embedded_prefix="")
        if norm_sub.endswith("/mcp/readonly"):
            emb_pfx = norm_sub[: -len("/mcp/readonly")]
            if emb_pfx and not _is_trusted_public_prefix(emb_pfx, request=request):
                return JSONResponse(
                    {"error": "not_found", "error_description": "Unknown gateway subpath."},
                    status_code=404,
                    headers={"Cache-Control": "no-store"},
                )
            return _build_protected_res_doc(request, readonly=True, embedded_prefix=emb_pfx)
        if norm_sub.endswith("/mcp"):
            emb_pfx = norm_sub[: -len("/mcp")]
            if emb_pfx and not _is_trusted_public_prefix(emb_pfx, request=request):
                return JSONResponse(
                    {"error": "not_found", "error_description": "Unknown gateway subpath."},
                    status_code=404,
                    headers={"Cache-Control": "no-store"},
                )
            return _build_protected_res_doc(request, readonly=False, embedded_prefix=emb_pfx)
        if norm_sub and not _is_trusted_public_prefix(norm_sub, request=request):
            return JSONResponse(
                {"error": "not_found", "error_description": "Unknown gateway subpath."},
                status_code=404,
                headers={"Cache-Control": "no-store"},
            )
        return _build_protected_res_doc(request, readonly=False, embedded_prefix=norm_sub)

    routes.extend(
        [
            Route(
                "/.well-known/oauth-protected-resource",
                endpoint=cors_middleware(_protected_res_main, ["GET", "OPTIONS"]),
                methods=["GET", "OPTIONS"],
            ),
            Route(
                "/.well-known/oauth-protected-resource/mcp",
                endpoint=cors_middleware(_protected_res_main, ["GET", "OPTIONS"]),
                methods=["GET", "OPTIONS"],
            ),
            Route(
                "/.well-known/oauth-protected-resource/mcp/readonly",
                endpoint=cors_middleware(_protected_res_readonly, ["GET", "OPTIONS"]),
                methods=["GET", "OPTIONS"],
            ),
            Route(
                "/.well-known/oauth-protected-resource/{subpath:path}",
                endpoint=cors_middleware(_protected_res_subpath, ["GET", "OPTIONS"]),
                methods=["GET", "OPTIONS"],
            ),
        ]
    )

    def _wrap_dynamic_www_auth(inner_asgi: Any, suffix: str) -> Any:
        async def _app(scope: Dict[str, Any], receive: Any, send: Any) -> None:
            if scope.get("type") != "http":
                await inner_asgi(scope, receive, send)
                return

            hdr_pfx_sc = ""
            for hk_in, hv_in in scope.get("headers") or ():
                if hk_in.lower() == b"x-cosmos-public-prefix":
                    hdr_pfx_sc = _normalize_public_prefix_header(hv_in.decode("latin-1", errors="replace"))
                    break

            async def _send_rewritten(message: Dict[str, Any]) -> None:
                if message.get("type") == "http.response.start" and int(message.get("status", 200)) == 401:
                    eff_pub_sc = _current_public_base(embedded_prefix=hdr_pfx_sc)
                    dyn_meta_u = str(build_resource_metadata_url(AnyHttpUrl(eff_pub_sc + suffix)))
                    patched_hdrs = []
                    for hk, hv in message.get("headers", []):
                        if hk.lower() == b"www-authenticate":
                            raw_v = hv.decode("latin-1", errors="replace")
                            new_v = re.sub(r'resource_metadata="[^"]*"', f'resource_metadata="{dyn_meta_u}"', raw_v)
                            patched_hdrs.append((hk, new_v.encode("latin-1")))
                        else:
                            patched_hdrs.append((hk, hv))
                    message = {**message, "headers": patched_hdrs}
                await send(message)

            await inner_asgi(scope, receive, _send_rewritten)

        return _app

    gw_urls_init = [ep.base_url for ep in eff_provider.get_effective_trusted_gateways().values()]
    allowed_mcp_origins = build_allowed_origins(port, eff_public, *gw_urls_init)
    main_protected = OriginGuardASGI(
        _wrap_dynamic_www_auth(RequireAuthMiddleware(main_envelope, [], build_resource_metadata_url(resource)), "/mcp"),
        allowed_origins=allowed_mcp_origins,
    )
    readonly_protected = OriginGuardASGI(
        _wrap_dynamic_www_auth(RequireAuthMiddleware(readonly_envelope, [], build_resource_metadata_url(readonly_resource)), "/mcp/readonly"),
        allowed_origins=allowed_mcp_origins,
    )

    def _sync_transport_from_provider() -> None:
        bearer_backend.allowed_resources.update(eff_provider.allowed_resources)
        active_gw_urls = [ep.base_url for ep in eff_provider.get_effective_trusted_gateways().values()]
        if eff_provider.base_url and eff_provider.base_url not in active_gw_urls:
            active_gw_urls.insert(0, eff_provider.base_url)
        next_hosts = build_allowed_hosts(port, *active_gw_urls)
        next_origins = build_allowed_origins(port, *active_gw_urls)
        for mgr in (bundle.main_session_manager, bundle.readonly_session_manager):
            sec = getattr(mgr, "security_settings", None) or getattr(mgr, "_security_settings", None)
            if sec is not None:
                sec.allowed_hosts[:] = next_hosts
                sec.allowed_origins[:] = next_origins
        main_protected.allowed_origins = next_origins
        readonly_protected.allowed_origins = next_origins

    eff_provider.register_gateway_sync_listener(_sync_transport_from_provider)
    _sync_transport_from_provider()

    async def preview_image_endpoint(request: Request) -> Response:
        pol.refresh()
        raw_tok = str(request.path_params.get("token") or "").strip()
        no_store_hdrs = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
        verified = verify_image_preview_token(raw_tok, _get_preview_secret())
        if verified is None:
            return JSONResponse(
                {"ok": False, "error": "invalid_or_expired_preview_token"},
                status_code=403,
                headers=no_store_hdrs,
            )
        cand_path = Path(str(verified["path"]))
        if is_link_or_junction(cand_path):
            return JSONResponse(
                {"ok": False, "error": "forbidden_symlink_preview"},
                status_code=403,
                headers=no_store_hdrs,
            )
        if not pol.is_path_allowed(cand_path):
            return JSONResponse(
                {"ok": False, "error": "preview_path_outside_workspace"},
                status_code=403,
                headers=no_store_hdrs,
            )
        if pol.guard is not None:
            g_err = pol.guard.check_path_access(str(cand_path), mode="read", tool_name="preview")
            if g_err is not None:
                return JSONResponse(
                    {"ok": False, "error": "preview_path_denied_by_guard"},
                    status_code=403,
                    headers=no_store_hdrs,
                )
        try:
            resolved_p = cand_path.resolve()
        except OSError:
            return JSONResponse({"ok": False, "error": "preview_path_invalid"}, status_code=403, headers=no_store_hdrs)
        if is_link_or_junction(resolved_p) or not pol.is_path_allowed(resolved_p):
            return JSONResponse(
                {"ok": False, "error": "preview_path_outside_workspace"},
                status_code=403,
                headers=no_store_hdrs,
            )
        if not resolved_p.exists() or not resolved_p.is_file():
            return JSONResponse({"ok": False, "error": "preview_file_not_found"}, status_code=404, headers=no_store_hdrs)
        try:
            fsize = resolved_p.stat().st_size
            if fsize <= 0 or fsize > MAX_PREVIEW_IMAGE_BYTES:
                return JSONResponse({"ok": False, "error": "preview_file_size_rejected"}, status_code=403, headers=no_store_hdrs)
            img_bytes = resolved_p.read_bytes()
        except OSError:
            return JSONResponse({"ok": False, "error": "preview_read_failed"}, status_code=403, headers=no_store_hdrs)
        mime_type = _detect_preview_image_mime(resolved_p, img_bytes[:32])
        if not mime_type:
            return JSONResponse({"ok": False, "error": "unsupported_preview_media_type"}, status_code=403, headers=no_store_hdrs)
        return Response(
            img_bytes,
            status_code=200,
            media_type=mime_type,
            headers={
                "Cache-Control": "private, max-age=300",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; frame-ancestors 'none'",
            },
        )

    async def public_tutorials_md_endpoint(request: Request) -> Response:
        _ = request
        from cosmos_mcp.core.tutorials_catalog import render_public_tutorials_markdown

        return Response(
            render_public_tutorials_markdown(),
            status_code=200,
            media_type="text/markdown; charset=utf-8",
            headers={
                "Cache-Control": "public, max-age=300",
                "X-Content-Type-Options": "nosniff",
                "Access-Control-Allow-Origin": "*",
            },
        )

    routes.extend(
        [
            Route("/", endpoint=root_status, methods=["GET"]),
            Route("/skill", endpoint=skill_endpoint, methods=["GET"]),
            Route("/tutorials.md", endpoint=public_tutorials_md_endpoint, methods=["GET", "HEAD"]),
            Route("/llms.txt", endpoint=public_tutorials_md_endpoint, methods=["GET", "HEAD"]),
            Route("/u/{node_id}/tutorials.md", endpoint=public_tutorials_md_endpoint, methods=["GET", "HEAD"]),
            Route("/u/{node_id}/llms.txt", endpoint=public_tutorials_md_endpoint, methods=["GET", "HEAD"]),
            Route("/preview/{token:path}", endpoint=preview_image_endpoint, methods=["GET"]),
            Route("/local-admin/permissions", endpoint=admin_policy_endpoint, methods=["POST"]),
            Route("/remote-admin/policy", endpoint=admin_policy_endpoint, methods=["POST"]),
            Route("/mcp", endpoint=main_protected, methods=["GET", "POST", "DELETE", "OPTIONS"]),
            Route("/mcp/readonly", endpoint=readonly_protected, methods=["GET", "POST", "DELETE", "OPTIONS"]),
            Route("/oauth/local-bridge", endpoint=oauth_local_bridge_entry, methods=["GET"]),
            Route("/consent", endpoint=consent_entry, methods=["GET", "POST"]),
            Route("/consent/complete", endpoint=consent_complete_entry, methods=["GET"]),
            Route("/u/{node_id}/consent", endpoint=consent_entry, methods=["GET", "POST"]),
            Route("/u/{node_id}/consent/complete", endpoint=consent_complete_entry, methods=["GET"]),
            Route("/healthz", endpoint=health_endpoint, methods=["GET"]),
        ]
    )

    @contextlib.asynccontextmanager
    async def _lifespan(_app: Starlette):
        kill_watchdog.start()
        async with contextlib.AsyncExitStack() as stack:
            await stack.enter_async_context(bundle.main_session_manager.run())
            await stack.enter_async_context(bundle.readonly_session_manager.run())
            try:
                yield
            finally:
                kill_watchdog.stop()
                eff_proc_mgr.kill_all_active_commands(reason="lifespan_shutdown", prefix_filter=eff_prefix)
                dispatcher.shutdown_packs(prefix_filter=eff_prefix)

    gateway_sync_hook_box: List[Optional[Callable[[bool], None]]] = [None]
    app = Starlette(
        routes=routes,
        middleware=[
            Middleware(GatewayContextASGI, provider=eff_provider, local_port=port, sync_hook_box=gateway_sync_hook_box),
            Middleware(RequestBodyLimitMiddleware, max_body_size=4 * 1024 * 1024),
            Middleware(OAuthStoreBusyMiddleware),
            Middleware(AuthenticationMiddleware, backend=bearer_backend),
            Middleware(AuthContextMiddleware),
        ],
        lifespan=_lifespan,
    )
    app.state.policy = pol
    app.state.dispatcher = dispatcher
    app.state.store = eff_store
    app.state.provider = eff_provider
    app.state.bearer_backend = bearer_backend
    app.state.transport_bundle = bundle
    app.state.kill_watchdog = kill_watchdog
    app.state.proc_mgr = eff_proc_mgr
    app.state.preview_secret_getter = _get_preview_secret
    app.state.gateway_sync_hook_box = gateway_sync_hook_box
    return app
