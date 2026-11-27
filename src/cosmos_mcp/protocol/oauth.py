"""SQLite WAL OAuth 2.1 DCR + PKCE S256 store/provider, dual-track refresh, and strong-auth remote policy control."""
from __future__ import annotations

import base64
import contextlib
from contextlib import contextmanager
import contextvars
from dataclasses import asdict, dataclass, fields
import hashlib
import hmac
import html
import json
import logging
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

try:
    from mcp.server.auth.provider import (
        AccessToken,
        AuthorizationCode,
        AuthorizationParams,
        AuthorizeError,
        RefreshToken,
        RegistrationError,
        TokenError,
        construct_redirect_uri,
    )
    from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

    MCP_SDK_AVAILABLE = True
except ImportError:
    MCP_SDK_AVAILABLE = False

    class _OAuthSdkError(Exception):
        def __init__(self, error: str = "oauth_error", error_description: str = "") -> None:
            super().__init__(error_description or error)
            self.error = error
            self.error_description = error_description
            self.message = error_description or error

    class AuthorizeError(_OAuthSdkError):
        pass

    class RegistrationError(_OAuthSdkError):
        pass

    class TokenError(_OAuthSdkError):
        pass

    def construct_redirect_uri(redirect_uri_base: str, **params: Any) -> str:
        parsed = urlsplit(str(redirect_uri_base))
        q_items = list(parse_qsl(parsed.query, keep_blank_values=True))
        for k, v in params.items():
            if v is not None:
                q_items.append((str(k), str(v)))
        return urlunsplit(parsed._replace(query=urlencode(q_items)))

    class _LiteModelMixin:
        def model_dump(self, mode: str = "json", exclude_none: bool = False) -> Dict[str, Any]:
            _ = mode
            raw = asdict(self)  # type: ignore[arg-type]
            if exclude_none:
                return {k: v for k, v in raw.items() if v is not None}
            return raw

        @classmethod
        def model_validate(cls, data: Mapping[str, Any]) -> Any:
            allowed = {f.name for f in fields(cls)}  # type: ignore[arg-type]
            filtered = {k: v for k, v in dict(data).items() if k in allowed}
            return cls(**filtered)

    @dataclass
    class AccessToken(_LiteModelMixin):  # type: ignore[no-redef]
        token: str
        client_id: str
        scopes: List[str]
        expires_at: Optional[int] = None
        resource: Optional[str] = None
        subject: Optional[str] = None

    @dataclass
    class RefreshToken(_LiteModelMixin):  # type: ignore[no-redef]
        token: str
        client_id: str
        scopes: List[str]
        expires_at: Optional[int] = None
        resource: Optional[str] = None
        subject: Optional[str] = None

    @dataclass
    class AuthorizationCode(_LiteModelMixin):  # type: ignore[no-redef]
        code: str
        scopes: List[str]
        expires_at: float
        client_id: str
        code_challenge: str
        redirect_uri: Any
        redirect_uri_provided_explicitly: bool = True
        resource: Optional[str] = None
        subject: Optional[str] = None

    @dataclass
    class AuthorizationParams(_LiteModelMixin):  # type: ignore[no-redef]
        state: Optional[str] = None
        scopes: Optional[List[str]] = None
        code_challenge: str = ""
        redirect_uri: Any = ""
        redirect_uri_provided_explicitly: bool = True
        resource: Optional[str] = None

    @dataclass
    class OAuthClientInformationFull(_LiteModelMixin):  # type: ignore[no-redef]
        client_id: str = ""
        client_secret: Optional[str] = None
        client_name: Optional[str] = None
        redirect_uris: Optional[List[Any]] = None
        scope: Optional[str] = None
        grant_types: Optional[List[str]] = None
        token_endpoint_auth_method: str = "none"

    @dataclass
    class OAuthToken(_LiteModelMixin):  # type: ignore[no-redef]
        access_token: str
        token_type: str = "Bearer"
        expires_in: Optional[int] = None
        scope: Optional[str] = None
        refresh_token: Optional[str] = None

try:
    from pydantic import AnyHttpUrl
except ImportError:
    class AnyHttpUrl(str):  # type: ignore[no-redef]
        def __new__(cls, val: Any) -> "AnyHttpUrl":
            s = str(val or "").strip()
            obj = super().__new__(cls, s)
            obj.host = urlsplit(s).hostname  # type: ignore[attr-defined]
            return obj

try:
    from starlette.requests import Request
    from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
except ImportError:
    Request = Any  # type: ignore[misc,assignment]

    class _FallbackResponse:
        def __init__(self, content: Any = "", status_code: int = 200, headers: Optional[Dict[str, str]] = None) -> None:
            self.status_code = int(status_code)
            self.headers = dict(headers or {})
            if isinstance(content, bytes):
                self.body = content
            elif isinstance(content, str):
                self.body = content.encode("utf-8")
            else:
                self.body = json.dumps(content, ensure_ascii=False).encode("utf-8")

        def set_cookie(self, *args: Any, **kwargs: Any) -> None:
            pass

        def delete_cookie(self, *args: Any, **kwargs: Any) -> None:
            pass

    class HTMLResponse(_FallbackResponse):  # type: ignore[no-redef]
        pass

    class JSONResponse(_FallbackResponse):  # type: ignore[no-redef]
        pass

    class RedirectResponse(_FallbackResponse):  # type: ignore[no-redef]
        def __init__(self, url: str, status_code: int = 302, headers: Optional[Dict[str, str]] = None) -> None:
            hdrs = dict(headers or {})
            hdrs["location"] = str(url)
            super().__init__("", status_code=status_code, headers=hdrs)

from cosmos_mcp.core.config import (
    DEFAULT_REDIRECT_HOSTS,
    UNAMBIGUOUS_PW_ALPHABET,
    LiveRuntimePolicy,
    _split_workspace_string,
    conn_info_filename_for_prefix,
    expand_env_and_tilde,
    load_endpoint_secret,
    normalize_prefix,
    normalize_python_path,
    parse_bool_flag,
    parse_pack_spec,
    parse_strict_annotation_mode,
    parse_strict_tier,
    parse_strict_toolset_profile,
)

LOGGER = logging.getLogger("cosmos_mcp.oauth")
SCOPES: List[str] = ["workspace", "server:read", "server:admin"]
SUB_WORKSTATION_SCOPES: List[str] = ["workspace", "server:read"]
READONLY_SCOPES: List[str] = ["server:read"]
TEMPORARY_SESSION_TTL_SEC: int = 7200
PAT_PLATFORM_LABEL_ZH: str = "专用密钥 (Sites / CLI)"
PAT_RESOURCE_ORIGIN: str = "https://pat.cosmos-mcp.local"
PAT_FULL_RESOURCE: str = f"{PAT_RESOURCE_ORIGIN}/mcp"
PAT_READONLY_RESOURCE: str = f"{PAT_RESOURCE_ORIGIN}/mcp/readonly"
LOOPBACK_PEERS: Set[str] = {"127.0.0.1", "::1", "localhost", "testclient", "unknown", ""}

GOOGLE_REDIRECT_HOSTS: Set[str] = {
    "oauth-redirect.googleusercontent.com",
    "oauth-redirect-sandbox.googleusercontent.com",
    "oauth-redirect-test.googleusercontent.com",
    "vertexaisearch.cloud.google.com",
}
_GOOGLE_OAUTH_REDIRECT_HOST_RE = re.compile(r"^oauth-redirect[a-z0-9-]*\.googleusercontent\.com$")
OPENAI_REDIRECT_HOSTS: Set[str] = {
    "chatgpt.com",
    "platform.openai.com",
}


def is_google_oauth_redirect_host(host: str) -> bool:
    """Return True for official Google Gemini / regional `oauth-redirect*.googleusercontent.com` callback hosts."""
    clean = (host or "").strip().lower()
    if not clean:
        return False
    return clean in GOOGLE_REDIRECT_HOSTS or (_GOOGLE_OAUTH_REDIRECT_HOST_RE.match(clean) is not None)

ALLOWED_NATIVE_REDIRECT_URIS: Set[str] = {
    "cursor://anysphere.cursor-mcp/oauth/callback",
}

_HASHED_TOKEN_KINDS: FrozenSet[str] = frozenset({"access", "refresh", "refresh_replay"})
CONSENT_TEMPLATE_PATH: Path = Path(__file__).resolve().parent / "templates" / "consent.html"

_FALLBACK_CONSENT_TEMPLATE_HTML: str = (
    '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">'
    "<title>授权连接 Cosmos MCP</title>"
    "<style>"
    "body{background:#f8fafc;color:#0f172a;font:16px/1.6 system-ui,-apple-system,sans-serif;max-width:540px;margin:4vh auto;padding:16px;box-sizing:border-box}"
    ".card{background:#fff;border:1px solid #cbd5e1;border-radius:14px;padding:22px 20px}"
    "h1{font-size:20px;margin:0 0 10px}"
    ".badge{display:inline-block;padding:4px 11px;border-radius:999px;font-size:13px;font-weight:600;margin-bottom:10px}"
    ".perm-desc{background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:10px 12px;margin:8px 0 12px;font-size:14px}"
    ".pair{background:#f0fdfa;border:1.5px solid #0f766e;border-radius:10px;padding:10px 12px;margin:10px 0}"
    ".alert{background:#fef2f2;border:1px solid #dc2626;color:#991b1b;padding:10px 12px;border-radius:8px;margin:10px 0;font-size:14px}"
    ".opt-group{border:1px solid #e2e8f0;border-radius:10px;padding:10px 12px;margin:10px 0;background:#f8fafc}"
    ".opt-title{font-size:13.5px;font-weight:600;margin-bottom:6px}"
    ".opt-choice{display:flex;align-items:flex-start;gap:8px;padding:5px 2px;font-size:14px;cursor:pointer}"
    ".opt-choice-sub{display:block;font-size:12.5px;color:#64748b}"
    ".pw-wrap{position:relative;display:flex;align-items:stretch;margin:6px 0 12px}"
    'input[type="password"],input[type="text"],.pw-input{font-family:inherit;font-size: 16px;width:100%;min-height:46px;padding:11px 88px 11px 12px;border:1px solid #94a3b8;border-radius:9px;box-sizing:border-box}'
    ".pw-toggle{position:absolute;right:6px;top:50%;transform:translateY(-50%);height:34px;padding:0 10px;border-radius:6px;border:1px solid #cbd5e1;background:#f8fafc;font-size:13px;cursor:pointer}"
    ".btn-submit,.local-bridge-btn{font-family:inherit;font-size:16px;width:100%;min-height:46px;padding:11px 14px;border-radius:9px;margin:6px 0;cursor:pointer}"
    ".local-bridge-btn,.btn-pw-approve{background:#0071e3;color:#fff;border:1px solid #0071e3;font-weight:600}"
    'button[value="deny"]{background:#fff;color:#334155;border:1px solid #cbd5e1}'
    "</style></head><body><div class=\"card\">"
    "<h1>授权连接本地工作区</h1>"
    '<div class="badge" style="__BADGE_STYLE__">__TIER_LABEL__</div>'
    '<div class="perm-desc"><strong>当前权限说明：</strong>__PERMISSION_DESC_ZH__</div>'
    '<div class="pair">实时 4 位核对码：<strong id="consent-pair-code">__PAIR_CODE__</strong>'
    '<div>请核对与本机 Studio 面板一致（<code>__PAIR_CODE_PATH__</code>）</div></div>'
    "<p><strong>__CLIENT_NAME__</strong> 请求连接工作区服务（口令见 Studio 面板或 <code>__CONN_FILENAME__</code>）。</p>"
    "__ERROR_HTML__"
    '<form method="post" action="__ACTION_URL__">'
    '<input type="hidden" name="ticket" value="__TICKET__">'
    '<input type="hidden" name="csrf" value="__CSRF__">'
    '<div class="opt-group"><div class="opt-title">授权权限范围</div>'
    '<label class="opt-choice"><input type="radio" name="grant_scope" value="default" __SCOPE_DEFAULT_ATTRS__><span><strong>默认当前工作区权限</strong><span class="opt-choice-sub">__SCOPE_DEFAULT_SUB__</span></span></label>'
    '<label class="opt-choice"><input type="radio" name="grant_scope" value="readonly" __SCOPE_READONLY_ATTRS__><span><strong>仅授予只读权限</strong><span class="opt-choice-sub">强制收窄为只读浏览与检索，禁止修改文件或运行命令</span></span></label></div>'
    '<div class="opt-group"><div class="opt-title">授权会话有效期</div>'
    '<label class="opt-choice"><input type="radio" name="session_ttl" value="30d" __TTL_30D_ATTRS__><span><strong>30 天记住设备</strong></span></label>'
    '<label class="opt-choice"><input type="radio" name="session_ttl" value="2h" __TTL_2H_ATTRS__><span><strong>本次 2 小时临时授权</strong></span></label></div>'
    "<!-- COSMOS_LOCAL_QUICK_START -->"
    '<button type="submit" class="local-bridge-btn" id="local-bridge-approve-btn" name="auth_mode" value="local_bridge" formnovalidate>本机一键允许连接（免输口令）</button>'
    "<!-- COSMOS_LOCAL_QUICK_END -->"
    '<details class="alt-auth-details" id="alt-auth-details"><summary>异地电脑或手机操作？输入 20 位连接口令 / 6 位动态配对码</summary>'
    '<div class="pw-wrap"><input id="consent-dynamic-code" class="pw-input" type="text" name="pair_code" maxlength="8" autocomplete="one-time-code" placeholder="输入 6 位动态配对码" style="padding-right:12px"></div>'
    '<button type="submit" class="btn-submit" id="pair-code-approve-btn" name="auth_mode" value="pair_code" formnovalidate>验证 6 位码连接</button>'
    '<div class="pw-wrap"><input id="consent-password" class="pw-input" type="password" name="password" autocomplete="off" placeholder="输入或粘贴 20 位连接口令">'
    '<button type="button" id="toggle-password-btn" class="pw-toggle"><span id="toggle-password-text">显示</span></button></div>'
    '<button type="submit" class="btn-submit btn-pw-approve" id="password-approve-btn" name="auth_mode" value="password">验证口令并允许连接</button>'
    "</details>"
    "<!-- COSMOS_MOBILE_BRIDGE_SLOT -->"
    '<button type="submit" class="btn-submit" name="decision" value="deny" formnovalidate>拒绝连接</button>'
    "</form></div>"
    '<script nonce="__NONCE__">(function(){var p=document.getElementById("consent-password"),b=document.getElementById("toggle-password-btn"),t=document.getElementById("toggle-password-text");if(p&&b){b.addEventListener("click",function(){var s=p.type==="text";p.type=s?"password":"text";if(t)t.textContent=s?"显示":"隐藏";});}})();</script>'
    "</body></html>"
)


def is_readonly_resource_url(resource: Optional[str]) -> bool:
    """Return True iff `resource` stripped of trailing slash ends with `/mcp/readonly`."""
    if not resource:
        return False
    return str(resource).strip().rstrip("/").lower().endswith("/mcp/readonly")


def narrow_scopes_for_resource(
    scopes: Optional[Sequence[str]],
    resource: Optional[str],
    *,
    force_readonly: bool = False,
) -> List[str]:
    """Enforce RFC 8707 scope narrowing: `/mcp/readonly` or explicit readonly consent narrows to `['server:read']`."""
    if force_readonly or is_readonly_resource_url(resource):
        return list(READONLY_SCOPES)
    cleaned = [str(s).strip() for s in (scopes or ()) if str(s).strip()]
    return cleaned or list(READONLY_SCOPES)


def hash_token_storage_key(raw_token: str) -> str:
    """Return `sha256:<hex>` primary key digest so raw bearer/refresh tokens never persist in SQLite."""
    clean = (raw_token or "").strip()
    if not clean:
        return ""
    if clean.startswith("sha256:") and len(clean) == 71 and all(ch in "0123456789abcdef" for ch in clean[7:]):
        return clean
    return "sha256:" + hashlib.sha256(clean.encode("utf-8")).hexdigest()


def _sanitize_token_record_for_disk(kind: str, value: Mapping[str, Any]) -> Dict[str, Any]:
    doc = dict(value)
    if kind in _HASHED_TOKEN_KINDS:
        doc.pop("token", None)
        doc.pop("access_token", None)
        doc.pop("refresh_token", None)
    return doc


def _cipher_keystream(key_bytes: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hmac.new(key_bytes, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest())
        counter += 1
    return bytes(out[:length])


def _wrap_replay_tokens(raw_old_rt: str, access_token: str, refresh_token: Optional[str]) -> Dict[str, str]:
    """Encrypt minted token pair under `raw_old_rt` so `refresh_replay` stores zero plaintext tokens on disk."""
    nonce = secrets.token_bytes(16)
    enc_key = hashlib.sha256(f"cosmos-oauth-replay-enc:v1:{raw_old_rt}".encode("utf-8")).digest()
    mac_key = hashlib.sha256(f"cosmos-oauth-replay-mac:v1:{raw_old_rt}".encode("utf-8")).digest()
    plain = json.dumps(
        {"access_token": access_token, "refresh_token": refresh_token},
        separators=(",", ":"),
    ).encode("utf-8")
    ks = _cipher_keystream(enc_key, nonce, len(plain))
    ct = bytes(a ^ b for a, b in zip(plain, ks))
    tag = hmac.new(mac_key, nonce + ct, hashlib.sha256).hexdigest()
    return {
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("="),
        "ct": base64.urlsafe_b64encode(ct).decode("ascii").rstrip("="),
        "tag": tag,
    }


def _unwrap_replay_tokens(raw_old_rt: str, replay_doc: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    wrapped = replay_doc.get("wrapped_tokens")
    if isinstance(wrapped, Mapping):
        try:
            n_b64 = str(wrapped.get("nonce") or "")
            c_b64 = str(wrapped.get("ct") or "")
            tag = str(wrapped.get("tag") or "")
            nonce = base64.urlsafe_b64decode(n_b64 + ("=" * (-len(n_b64) % 4)))
            ct = base64.urlsafe_b64decode(c_b64 + ("=" * (-len(c_b64) % 4)))
            mac_key = hashlib.sha256(f"cosmos-oauth-replay-mac:v1:{raw_old_rt}".encode("utf-8")).digest()
            exp_tag = hmac.new(mac_key, nonce + ct, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(tag, exp_tag):
                return None
            enc_key = hashlib.sha256(f"cosmos-oauth-replay-enc:v1:{raw_old_rt}".encode("utf-8")).digest()
            ks = _cipher_keystream(enc_key, nonce, len(ct))
            plain = bytes(a ^ b for a, b in zip(ct, ks))
            parsed = json.loads(plain.decode("utf-8"))
            if isinstance(parsed, dict) and parsed.get("access_token"):
                return parsed
        except Exception:
            return None
    if replay_doc.get("access_token"):
        return {
            "access_token": replay_doc.get("access_token"),
            "refresh_token": replay_doc.get("refresh_token"),
        }
    return None


def load_consent_template_html() -> str:
    """Single source-of-truth reader for `protocol/templates/consent.html` with safe inline HTML fallback."""
    try:
        if CONSENT_TEMPLATE_PATH.is_file():
            return CONSENT_TEMPLATE_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        LOGGER.warning("consent template read failed, using inline fallback: %s", exc)
    return _FALLBACK_CONSENT_TEMPLATE_HTML


def render_consent_template_html(
    *,
    tier_key: str,
    tier_label: str,
    permission_desc_zh: str,
    pair_code: str,
    pair_code_path: str,
    client_name: str,
    conn_filename: str,
    consent_path: str,
    ticket: str,
    csrf: str,
    nonce: str,
    error_banner: str = "",
    is_readonly_resource: bool = False,
    selected_scope: str = "default",
    selected_ttl: str = "30d",
    is_remote_hub: Optional[bool] = None,
) -> str:
    tpl = load_consent_template_html()
    is_l4 = str(tier_key or "").startswith("tier4") or str(tier_label or "").upper().startswith("L4")
    badge_style = (
        "background:#fff7ed;color:#9a3412;border:1.5px solid #f97316;"
        if is_l4
        else "background:#ccfbf1;color:#115e59;border:1px solid #5eead4;"
    )
    err_html = f'<div class="alert" role="alert">{html.escape(error_banner)}</div>' if error_banner else ""
    action_url = f"{consent_path}?{urlencode({'ticket': ticket})}" if ticket else consent_path
    eff_ro = bool(is_readonly_resource or str(selected_scope or "").strip().lower() == "readonly")
    if is_readonly_resource:
        scope_default_attrs = "disabled"
        scope_readonly_attrs = "checked"
        scope_default_sub = "当前请求的是 /mcp/readonly 只读连接地址，固定仅授予只读权限"
    else:
        scope_default_attrs = "" if eff_ro else "checked"
        scope_readonly_attrs = "checked" if eff_ro else ""
        scope_default_sub = "随本机当前安全模式同步开放工作目录权限"

    eff_2h = str(selected_ttl or "").strip().lower() in ("2h", "7200", "temp", "temporary")
    ttl_30d_attrs = "" if eff_2h else "checked"
    ttl_2h_attrs = "checked" if eff_2h else ""

    eff_badge_label = "只读连接端点 (/mcp/readonly)" if is_readonly_resource else tier_label
    eff_perm_desc = (
        "当前通过 /mcp/readonly 只读端点连接，强制仅授予只读浏览与检索权限，禁止修改文件或运行命令。"
        if is_readonly_resource
        else permission_desc_zh
    )
    replacements = {
        "__BADGE_STYLE__": badge_style,
        "__TIER_LABEL__": html.escape(eff_badge_label),
        "__PERMISSION_DESC_ZH__": html.escape(eff_perm_desc),
        "__PAIR_CODE__": html.escape(pair_code),
        "__PAIR_CODE_PATH__": html.escape(pair_code_path),
        "__CLIENT_NAME__": html.escape(client_name or "AI 客户端"),
        "__CONN_FILENAME__": html.escape(conn_filename),
        "__ERROR_HTML__": err_html,
        "__ACTION_URL__": html.escape(action_url, quote=True),
        "__TICKET__": html.escape(ticket),
        "__CSRF__": html.escape(csrf),
        "__NONCE__": html.escape(nonce),
        "__SCOPE_DEFAULT_ATTRS__": scope_default_attrs,
        "__SCOPE_READONLY_ATTRS__": scope_readonly_attrs,
        "__SCOPE_DEFAULT_SUB__": html.escape(scope_default_sub),
        "__TTL_30D_ATTRS__": ttl_30d_attrs,
        "__TTL_2H_ATTRS__": ttl_2h_attrs,
    }
    rendered = tpl
    for k, v in replacements.items():
        rendered = rendered.replace(k, v)
    try:
        from cosmos_mcp.protocol.oauth_web import (
            apply_device_consent_layout,
            is_current_request_mobile,
            is_current_request_remote_hub,
        )

        eff_remote_hub = is_current_request_remote_hub() if is_remote_hub is None else bool(is_remote_hub)
        return apply_device_consent_layout(
            rendered,
            is_mobile=is_current_request_mobile(),
            has_error=bool(error_banner),
            local_fast_token="",
            is_remote_hub=eff_remote_hub,
        )
    except Exception:
        return (
            rendered.replace("<!-- COSMOS_LOCAL_QUICK_START -->", "")
            .replace("<!-- COSMOS_LOCAL_QUICK_END -->", "")
            .replace("<!-- COSMOS_MOBILE_BRIDGE_SLOT -->", "")
            .replace("<!-- COSMOS_LOCAL_QUICK_SLOT -->", "")
        )

_REGISTER_CLIENT_IP_VAR: contextvars.ContextVar[str] = contextvars.ContextVar("_REGISTER_CLIENT_IP_VAR", default="")


def set_register_client_ip(ip: str) -> contextvars.Token[str]:
    return _REGISTER_CLIENT_IP_VAR.set((ip or "").strip()[:80])


def reset_register_client_ip(token: contextvars.Token[str]) -> None:
    _REGISTER_CLIENT_IP_VAR.reset(token)


@dataclass(frozen=True)
class TrustedGatewayEndpoint:
    gateway_id: str          # "instant" | "workers_dev" | "self_hosted" | "loopback" | "default"
    tunnel_mode: str         # "srv_us" | "public_gateway" | "cloudflare" | "workers_dev" | "vps_hub" | "vps" | "cloudflare_token" | "custom" | "local"
    scheme: str              # "https" | "http"
    authority: str           # lowercase host[:non_default_port], e.g. "abc.srv.us" or "127.0.0.1:8096"
    public_prefix: str       # "" or "/u/<node_id>"
    base_url: str            # e.g. "https://abc.srv.us" or "https://gw.workers.dev/u/node1"
    issuer: str              # same as base_url (no trailing slash)
    resource: str            # f"{base_url}/mcp"
    readonly_resource: str   # f"{base_url}/mcp/readonly"
    is_loopback: bool = False


_REQUEST_GATEWAY_VAR: contextvars.ContextVar[Optional[TrustedGatewayEndpoint]] = contextvars.ContextVar(
    "cosmos_request_gateway", default=None
)
_REQUEST_TOKEN_RESOURCE_VAR: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "cosmos_request_token_resource", default=None
)

_LOOPBACK_HOSTNAMES: FrozenSet[str] = frozenset({"127.0.0.1", "localhost", "::1"})
_SCRYPT_VERIFY_SEMAPHORE = threading.BoundedSemaphore(4)
_TRUSTED_PUBLIC_PREFIX_RE = re.compile(r"^/u/[a-z0-9_-]{2,64}$", re.IGNORECASE)
_IPV4_HOST_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _is_testserver_host_allowed(scope: Optional[Mapping[str, Any]] = None) -> bool:
    if scope is not None:
        cli_tuple = scope.get("client")
        peer_h = str(cli_tuple[0] or "").strip().lower() if isinstance(cli_tuple, (list, tuple)) and cli_tuple else ""
        if peer_h == "testclient":
            return True
        if os.environ.get("PYTEST_CURRENT_TEST") and peer_h in ("testclient", "127.0.0.1", "::1", "localhost", ""):
            return True
        return False
    return bool(os.environ.get("PYTEST_CURRENT_TEST"))


def get_current_request_gateway() -> Optional[TrustedGatewayEndpoint]:
    return _REQUEST_GATEWAY_VAR.get()


def set_current_request_gateway(gw: Optional[TrustedGatewayEndpoint]) -> contextvars.Token[Optional[TrustedGatewayEndpoint]]:
    return _REQUEST_GATEWAY_VAR.set(gw)


def reset_current_request_gateway(token: contextvars.Token[Optional[TrustedGatewayEndpoint]]) -> None:
    _REQUEST_GATEWAY_VAR.reset(token)


def get_request_token_resource() -> Optional[str]:
    return _REQUEST_TOKEN_RESOURCE_VAR.get()


def set_request_token_resource(resource: Optional[str]) -> contextvars.Token[Optional[str]]:
    return _REQUEST_TOKEN_RESOURCE_VAR.set(resource)


def reset_request_token_resource(token: contextvars.Token[Optional[str]]) -> None:
    _REQUEST_TOKEN_RESOURCE_VAR.reset(token)


def _normalize_trusted_public_prefix(raw_prefix: str) -> str:
    clean = str(raw_prefix or "").strip()
    if not clean or not clean.strip("/"):
        return ""
    norm = "/" + clean.strip("/")
    if not _TRUSTED_PUBLIC_PREFIX_RE.match(norm):
        return ""
    return norm


def _normalize_host_authority(raw_host: str, default_scheme: str = "https") -> Tuple[str, str, Optional[int]]:
    cand = str(raw_host or "").strip()
    if not cand or any(ch in cand for ch in ("/", "?", "#", "@", "\\", "\r", "\n", "\t", " ", "\x00")):
        return "", "", None
    scheme = (default_scheme or "https").strip().lower()
    try:
        u = urlsplit(f"{scheme}://{cand}")
        host = (u.hostname or "").strip().lower()
        port = u.port
    except ValueError:
        return "", "", None
    if not host:
        return "", "", None
    if port is not None and (port < 1 or port > 65535):
        return "", "", None
    host_fmt = f"[{host}]" if ":" in host else host
    if port is None or (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return host_fmt, host, port
    return f"{host_fmt}:{port}", host, port


def _normalize_url_authority(raw_url: str) -> str:
    u = urlsplit(str(raw_url or "").strip())
    scheme = (u.scheme or "https").strip().lower()
    auth, _, _ = _normalize_host_authority(u.netloc, default_scheme=scheme)
    return auth


def build_trusted_gateway_endpoint(
    raw_url: str,
    *,
    gateway_id: str = "default",
    tunnel_mode: str = "",
    local_port: int = 8096,
) -> Optional[TrustedGatewayEndpoint]:
    clean = str(raw_url or "").strip().rstrip("/")
    if not clean or not clean.startswith(("http://", "https://")):
        return None
    u = urlsplit(clean)
    scheme = (u.scheme or "").strip().lower()
    if scheme not in ("http", "https") or not u.netloc:
        return None
    authority, host, _ = _normalize_host_authority(u.netloc, default_scheme=scheme)
    if not authority or not host:
        return None
    raw_path = (u.path or "").rstrip("/")
    if raw_path in ("/mcp", "/mcp/readonly"):
        raw_path = ""
    elif raw_path.endswith("/mcp/readonly"):
        raw_path = raw_path[: -len("/mcp/readonly")]
    elif raw_path.endswith("/mcp"):
        raw_path = raw_path[: -len("/mcp")]
    pub_prefix = raw_path if (raw_path and re.match(r"^/[a-zA-Z0-9._~/-]+$", raw_path) and ".." not in raw_path and "//" not in raw_path) else ""
    is_lb = host in _LOOPBACK_HOSTNAMES or (host == "testserver" and _is_testserver_host_allowed())
    eff_gw_id = str(gateway_id or ("loopback" if is_lb else "default")).strip() or "default"
    eff_tm = str(tunnel_mode or ("local" if is_lb else "")).strip().lower()
    _ = local_port
    base_url = f"{scheme}://{authority}{pub_prefix}"
    return TrustedGatewayEndpoint(
        gateway_id=eff_gw_id,
        tunnel_mode=eff_tm,
        scheme=scheme,
        authority=authority,
        public_prefix=pub_prefix,
        base_url=base_url,
        issuer=base_url,
        resource=f"{base_url}/mcp",
        readonly_resource=f"{base_url}/mcp/readonly",
        is_loopback=is_lb,
    )


def _with_public_prefix(ep: TrustedGatewayEndpoint, prefix: str) -> TrustedGatewayEndpoint:
    clean_p = _normalize_trusted_public_prefix(prefix)
    if not clean_p or ep.public_prefix == clean_p:
        return ep
    base_url = f"{ep.scheme}://{ep.authority}{clean_p}"
    return TrustedGatewayEndpoint(
        gateway_id=ep.gateway_id,
        tunnel_mode=ep.tunnel_mode,
        scheme=ep.scheme,
        authority=ep.authority,
        public_prefix=clean_p,
        base_url=base_url,
        issuer=base_url,
        resource=f"{base_url}/mcp",
        readonly_resource=f"{base_url}/mcp/readonly",
        is_loopback=ep.is_loopback,
    )


def _without_public_prefix(ep: TrustedGatewayEndpoint) -> TrustedGatewayEndpoint:
    if not ep.public_prefix:
        return ep
    base_url = f"{ep.scheme}://{ep.authority}"
    return TrustedGatewayEndpoint(
        gateway_id=ep.gateway_id,
        tunnel_mode=ep.tunnel_mode,
        scheme=ep.scheme,
        authority=ep.authority,
        public_prefix="",
        base_url=base_url,
        issuer=base_url,
        resource=f"{base_url}/mcp",
        readonly_resource=f"{base_url}/mcp/readonly",
        is_loopback=ep.is_loopback,
    )


_SCOPE_PATH_PREFIX_RE = re.compile(r"^(/u/[a-z0-9_-]{2,64})(?:/.*)?$", re.IGNORECASE)
_SCOPE_WK_PREFIX_RE = re.compile(
    r"^/\.well-known/(?:oauth-authorization-server|oauth-protected-resource)(/u/[a-z0-9_-]{2,64})(?:/.*)?$",
    re.IGNORECASE,
)


def resolve_trusted_gateway_from_scope(
    scope: Mapping[str, Any],
    trusted_map: Mapping[Tuple[str, str], TrustedGatewayEndpoint],
    local_port: int = 8096,
    default_endpoint: Optional[TrustedGatewayEndpoint] = None,
) -> Optional[TrustedGatewayEndpoint]:
    """Resolve inbound ASGI `scope` against `trusted_map` (3-tier strict anti-Host-injection gate)."""
    hdr_map: Dict[str, str] = {}
    for hk, hv in scope.get("headers") or ():
        ks = hk.decode("latin-1", errors="replace").strip().lower() if isinstance(hk, (bytes, bytearray)) else str(hk).strip().lower()
        vs = hv.decode("latin-1", errors="replace").strip() if isinstance(hv, (bytes, bytearray)) else str(hv).strip()
        hdr_map[ks] = vs

    prefix = _normalize_trusted_public_prefix(hdr_map.get("x-cosmos-public-prefix", ""))
    if not prefix:
        raw_req_p = str(scope.get("path") or "")
        m_sp = _SCOPE_PATH_PREFIX_RE.match(raw_req_p) or _SCOPE_WK_PREFIX_RE.match(raw_req_p)
        if m_sp:
            prefix = _normalize_trusted_public_prefix(m_sp.group(1).lower())
    via_tunnel = hdr_map.get("x-cosmos-via-tunnel", "").strip() == "1" or bool(hdr_map.get("cf-connecting-ip", "").strip())
    raw_host = hdr_map.get("host", "").strip()

    if not raw_host:
        host_name = "127.0.0.1"
        host_port: Optional[int] = int(local_port)
    else:
        _, host_name, host_port = _normalize_host_authority(raw_host, default_scheme="https")
        if not host_name:
            return None

    is_lb_host = host_name in _LOOPBACK_HOSTNAMES or (host_name == "testserver" and _is_testserver_host_allowed(scope))

    def _lookup_trusted_authority(cand_raw_host: str) -> Optional[TrustedGatewayEndpoint]:
        auth_https, c_host, _ = _normalize_host_authority(cand_raw_host, default_scheme="https")
        auth_http, _, _ = _normalize_host_authority(cand_raw_host, default_scheme="http")
        if not c_host or c_host in _LOOPBACK_HOSTNAMES:
            return None
        for cand_auth in (auth_https, auth_http):
            if not cand_auth:
                continue
            if prefix:
                hit_exact = trusted_map.get((cand_auth, prefix.lower()))
                if hit_exact is not None:
                    return hit_exact
            hit_base = trusted_map.get((cand_auth, ""))
            if hit_base is not None:
                return _with_public_prefix(hit_base, prefix) if prefix else hit_base
            for (map_auth, _), ep_cand in trusted_map.items():
                if map_auth == cand_auth:
                    bare_ep = _without_public_prefix(ep_cand)
                    return _with_public_prefix(bare_ep, prefix) if prefix else bare_ep
        return None

    # Branch 1: Non-loopback `Host` -> match strictly against `trusted_map` (ignore client-forged `X-Forwarded-Host`)
    if not is_lb_host:
        return _lookup_trusted_authority(raw_host)

    # Branch 2: Loopback `Host` + tunnel/reverse-proxy forwarded host (`x-cosmos-via-tunnel`, `cf-connecting-ip`, `x-forwarded-host`, or RFC 7239 `Forwarded: host=`)
    raw_xfh = hdr_map.get("x-forwarded-host", "").strip()
    fwd_host = ""
    raw_fwd = hdr_map.get("forwarded", "").strip()
    if raw_fwd and not raw_xfh:
        m_fh = re.search(r'(?:^|[;,\s])host\s*=\s*"?([^";,\s]+)"?', raw_fwd, re.IGNORECASE)
        if m_fh:
            fwd_host = m_fh.group(1).strip()
    if via_tunnel or raw_xfh or fwd_host:
        cand_fh = raw_xfh.split(",")[-1].strip() if raw_xfh else fwd_host
        if not cand_fh:
            return None
        return _lookup_trusted_authority(cand_fh)

    # Branch 3: Pure loopback request (`127.0.0.1`, `localhost`, `[::1]`, or Starlette `testserver`)
    eff_lp = int(local_port) if int(local_port or 0) > 0 else 8096
    if host_name == "testserver" or not raw_host:
        lb_url = f"http://127.0.0.1:{eff_lp}"
    else:
        fmt_h = f"[{host_name}]" if ":" in host_name else host_name
        lb_url = f"http://{fmt_h}:{host_port}" if (host_port and host_port != 80) else f"http://{fmt_h}"
    lb_ep = build_trusted_gateway_endpoint(lb_url, gateway_id="loopback", tunnel_mode="local", local_port=eff_lp)

    req_path = str(scope.get("path") or "")
    if (
        req_path in ("/oauth/local-bridge", "/studio", "/status", "/healthz")
        or req_path.startswith("/api/studio/")
        or req_path.startswith("/_cosmos_node")
    ):
        return lb_ep

    raw_qs = scope.get("query_string") or b""
    qs_str = raw_qs.decode("latin-1", errors="replace") if isinstance(raw_qs, (bytes, bytearray)) else str(raw_qs)
    if qs_str:
        q_dict = dict(parse_qsl(qs_str, keep_blank_values=True))
        for qk in ("resource", "iss"):
            qv = str(q_dict.get(qk) or "").strip().lower()
            if qv.startswith(("http://127.0.0.1", "http://localhost", "http://[::1]")):
                return lb_ep

    if default_endpoint is not None and not default_endpoint.is_loopback:
        if prefix and not default_endpoint.public_prefix:
            return _with_public_prefix(default_endpoint, prefix)
        return default_endpoint
    return default_endpoint if default_endpoint is not None else lb_ep


def derive_consent_pair_code(ticket: str) -> str:
    """Deterministically derive a 4-char uppercase unambiguous pairing code from `ticket`."""
    clean = (ticket or "").strip()
    if not clean:
        return "----"
    digest = hashlib.sha256(f"localpc-consent-pair:{clean}".encode("utf-8")).digest()
    return "".join(UNAMBIGUOUS_PW_ALPHABET[b & 31] for b in digest[:4])


def derive_dynamic_pair_code(
    password_hash: str,
    salt_hex: str,
    *,
    timestamp: Optional[float] = None,
    step_seconds: int = 30,
) -> str:
    """Derive a 6-digit RFC 6238-style HMAC-SHA256 dynamic pairing code (shown only on local Studio)."""
    if not password_hash or not salt_hex:
        return "000000"
    eff_ts = float(timestamp) if timestamp is not None else time.time()
    slot = int(eff_ts // max(5, int(step_seconds)))
    key = hashlib.sha256(f"cosmos-dynamic-pair-v1:{salt_hex}:{password_hash}".encode("utf-8")).digest()
    mac = hmac.new(key, f"totp:{slot}".encode("ascii"), hashlib.sha256).digest()
    offset = mac[-1] & 0x0F
    code_num = (
        ((mac[offset] & 0x7F) << 24)
        | ((mac[offset + 1] & 0xFF) << 16)
        | ((mac[offset + 2] & 0xFF) << 8)
        | (mac[offset + 3] & 0xFF)
    ) % 1_000_000
    return f"{code_num:06d}"


def verify_dynamic_pair_code(
    candidate: str,
    password_hash: str,
    salt_hex: str,
    *,
    now: Optional[float] = None,
    step_seconds: int = 30,
    drift_steps: int = 1,
) -> bool:
    """Constant-time validator for the 6-digit Studio dynamic pairing code (`±1` 30s window tolerance)."""
    compact = re.sub(r"[\s-]+", "", str(candidate or ""))
    if len(compact) != 6 or not compact.isdigit() or not password_hash or not salt_hex:
        return False
    base_now = float(now) if now is not None else time.time()
    step = max(5, int(step_seconds))
    matched = False
    for delta in range(-abs(int(drift_steps)), abs(int(drift_steps)) + 1):
        exp = derive_dynamic_pair_code(password_hash, salt_hex, timestamp=base_now + (delta * step), step_seconds=step)
        if hmac.compare_digest(compact, exp):
            matched = True
    return matched


def verify_owner_password(password: str, password_hash: str, salt_hex: str) -> bool:
    """Constant-time scrypt owner password check supporting case-insensitive and hyphenless 20-char entry."""
    cleaned = (password or "").strip()
    if not cleaned or not password_hash or not salt_hex:
        return False
    try:
        salt_bytes = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    if not _SCRYPT_VERIFY_SEMAPHORE.acquire(timeout=2.0):
        return False
    try:
        digest = hashlib.scrypt(cleaned.encode("utf-8"), salt=salt_bytes, n=16384, r=8, p=1).hex()
        if hmac.compare_digest(digest, password_hash):
            return True
        compact = re.sub(r"[\s-]+", "", cleaned).upper()
        if len(compact) in (20, 24) and all(ch in UNAMBIGUOUS_PW_ALPHABET for ch in compact):
            grp = 5 if len(compact) == 20 else 6
            formatted = "-".join(compact[i : i + grp] for i in range(0, len(compact), grp))
            if formatted != cleaned:
                alt_digest = hashlib.scrypt(formatted.encode("utf-8"), salt=salt_bytes, n=16384, r=8, p=1).hex()
                return hmac.compare_digest(alt_digest, password_hash)
        return False
    finally:
        _SCRYPT_VERIFY_SEMAPHORE.release()


def identify_client_platform(
    client_name: str,
    redirect_uris: Sequence[Any],
    *,
    client_id: str = "",
) -> Tuple[str, List[str]]:
    hosts: List[str] = []
    schemes: List[str] = []
    for raw in redirect_uris or ():
        s = str(raw or "").strip()
        if not s:
            continue
        u = urlsplit(s)
        scheme = (u.scheme or "").lower()
        host = (u.hostname or "").lower()
        if scheme and scheme not in schemes:
            schemes.append(scheme)
        if host and host not in hosts:
            hosts.append(host)
        elif not host and scheme and f"{scheme}://" not in hosts:
            hosts.append(f"{scheme}://")

    clean_cid = (client_id or "").strip().lower()
    if clean_cid.startswith("pat_"):
        return PAT_PLATFORM_LABEL_ZH, hosts

    if any(is_google_oauth_redirect_host(h) or h == "googleusercontent.com" or h.endswith(".googleusercontent.com") for h in hosts):
        return "Google Gemini", hosts
    if any(h in OPENAI_REDIRECT_HOSTS or h.endswith(".openai.com") for h in hosts):
        return "OpenAI ChatGPT", hosts
    if any(h == "claude.ai" or h.endswith(".claude.ai") for h in hosts):
        return "Anthropic Claude", hosts
    if "cursor" in schemes or any(h in ("cursor.com", "www.cursor.com") for h in hosts):
        return "Cursor", hosts
    if "vscode" in schemes or any(h == "vscode.dev" for h in hosts):
        return "VS Code", hosts

    low_name = (client_name or "").strip().lower()
    if not hosts and not schemes and (
        low_name.startswith("pat_") or "专用密钥" in (client_name or "") or "sites / cli" in low_name
    ):
        return PAT_PLATFORM_LABEL_ZH, hosts
    if "gemini" in low_name:
        return "Google Gemini", hosts
    if "chatgpt" in low_name or "openai" in low_name:
        return "OpenAI ChatGPT", hosts
    if "claude" in low_name or "anthropic" in low_name:
        return "Anthropic Claude", hosts
    if "cursor" in low_name:
        return "Cursor", hosts
    if "vscode" in low_name or "vs code" in low_name:
        return "VS Code", hosts
    return "Custom MCP Client", hosts


def _google_user_bound_ids(uris: Sequence[Any]) -> Set[str]:
    out: Set[str] = set()
    for raw in uris or ():
        u = urlsplit(str(raw or "").strip())
        scheme = (u.scheme or "").lower()
        host = (u.hostname or "").lower()
        is_goog = scheme == "https" and (is_google_oauth_redirect_host(host) or host == "googleusercontent.com")
        if is_goog and ("/user_bound_custom-mcp-" in (u.path or "") or "/custom-mcp-" in (u.path or "")):
            seg = u.path.rsplit("/", 1)[-1]
            if seg.startswith(("user_bound_custom-mcp-", "custom-mcp-")) and len(seg) > len("custom-mcp-"):
                out.add(seg)
    return out


def is_google_gemini_client(client_name: str, redirect_uris: Sequence[Any]) -> bool:
    """Strictly verify official Google Gemini persistent connector via validated `GOOGLE_REDIRECT_HOSTS` (never unauthenticated `client_name`)."""
    _ = client_name
    for raw in redirect_uris or ():
        u = urlsplit(str(raw or "").strip())
        scheme = (u.scheme or "").lower()
        host = (u.hostname or "").lower()
        if scheme == "https" and (
            is_google_oauth_redirect_host(host)
            or (host == "googleusercontent.com" and "/user_bound_custom-mcp-" in (u.path or ""))
        ):
            return True
    return False


def is_persistent_connector_client(redirect_uris: Sequence[Any]) -> bool:
    """Return True for persistent connector callback URIs (`user_bound_custom-mcp-*`, ChatGPT, Claude)."""
    if _google_user_bound_ids(redirect_uris):
        return True
    for raw in redirect_uris or ():
        u = urlsplit(str(raw))
        host = (u.hostname or "").lower()
        if host == "chatgpt.com" or host.endswith(".openai.com") or host == "claude.ai" or host.endswith(".claude.ai"):
            return True
    return False


_SQLITE_READ_RETRY_BACKOFFS: Tuple[float, ...] = (0.05, 0.1, 0.2, 0.4)


class OAuthStoreBusyError(sqlite3.OperationalError):
    """Raised when the OAuth SQLite store remains transiently locked/busy after bounded retries."""

    def __init__(self, message: str = "OAuth token store is temporarily busy", *, retry_after: int = 1) -> None:
        super().__init__(message)
        self.retry_after = max(1, int(retry_after))


def _is_sqlite_locked_or_busy(exc: BaseException) -> bool:
    if not isinstance(exc, sqlite3.OperationalError):
        return False
    code = getattr(exc, "sqlite_errorcode", None)
    if code in (getattr(sqlite3, "SQLITE_BUSY", 5), getattr(sqlite3, "SQLITE_LOCKED", 6)):
        return True
    low = str(exc).lower()
    return "locked" in low or "busy" in low


class OAuthSQLiteStore:
    """SQLite WAL (`busy_timeout=5000`, `mmap_size=0`) store for OAuth 2.1 tokens, DCR clients, and rate guards."""

    def __init__(self, path: Path, create: bool = True) -> None:
        self.path = Path(path)
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._tx() as db:
                db.execute(
                    "CREATE TABLE IF NOT EXISTS records (kind TEXT, key TEXT, value TEXT, expiry REAL, PRIMARY KEY(kind,key))"
                )

    def connect(self, readonly: bool = False) -> sqlite3.Connection:
        if readonly and self.path.is_file():
            uri = self.path.resolve().as_uri() + "?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=5.0, isolation_level=None)
            try:
                conn.execute("PRAGMA busy_timeout = 5000")
                conn.execute("PRAGMA mmap_size = 0")
            except Exception:
                pass
            return conn

        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.path), timeout=10.0, isolation_level=None)
        try:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA busy_timeout = 5000")
            conn.execute("PRAGMA mmap_size = 0")
            conn.execute("PRAGMA journal_size_limit = 67108864")
        except Exception:
            pass
        return conn

    @contextmanager
    def _tx(self):
        try:
            conn = self.connect(readonly=False)
        except sqlite3.OperationalError as exc:
            if _is_sqlite_locked_or_busy(exc):
                raise OAuthStoreBusyError(f"OAuth SQLite store busy on connect: {exc}", retry_after=1) from exc
            raise
        try:
            for attempt in range(5):
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    break
                except sqlite3.OperationalError as exc:
                    if _is_sqlite_locked_or_busy(exc):
                        if attempt < 4:
                            time.sleep(0.05 * (2 ** attempt))
                            continue
                        raise OAuthStoreBusyError(
                            f"OAuth SQLite store busy in transaction: {exc}",
                            retry_after=1,
                        ) from exc
                    raise
            yield conn
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
        finally:
            conn.close()

    @staticmethod
    def _candidate_keys(kind: str, raw_key: str) -> List[str]:
        clean = (raw_key or "").strip()
        if not clean:
            return []
        if kind not in _HASHED_TOKEN_KINDS:
            return [clean]
        h_key = hash_token_storage_key(clean)
        return [h_key] if h_key == clean else [h_key, clean]

    def put(self, kind: str, key: str, value: Dict[str, Any], expiry: float) -> None:
        eff_key = hash_token_storage_key(key) if kind in _HASHED_TOKEN_KINDS else key
        eff_val = _sanitize_token_record_for_disk(kind, value)
        with self._tx() as db:
            db.execute("INSERT OR REPLACE INTO records VALUES (?,?,?,?)", (kind, eff_key, json.dumps(eff_val), float(expiry)))

    def get(self, kind: str, key: str) -> Optional[Dict[str, Any]]:
        if not self.path.is_file():
            return None
        cands = self._candidate_keys(kind, key)
        if not cands:
            return None
        max_retries = len(_SQLITE_READ_RETRY_BACKOFFS)
        for attempt in range(max_retries + 1):
            conn: Optional[sqlite3.Connection] = None
            row = None
            try:
                conn = self.connect(readonly=True)
                for ck in cands:
                    row = conn.execute(
                        "SELECT value,expiry FROM records WHERE kind=? AND key=?",
                        (kind, ck),
                    ).fetchone()
                    if row is not None:
                        break
                return json.loads(row[0]) if row and float(row[1]) > time.time() else None
            except sqlite3.OperationalError as exc:
                if _is_sqlite_locked_or_busy(exc):
                    if attempt < max_retries:
                        time.sleep(_SQLITE_READ_RETRY_BACKOFFS[attempt])
                        continue
                    raise OAuthStoreBusyError(
                        f"OAuth SQLite store temporarily locked during get({kind}): {exc}",
                        retry_after=1,
                    ) from exc
                if "no such table" in str(exc).lower():
                    return None
                raise
            finally:
                if conn is not None:
                    with contextlib.suppress(Exception):
                        conn.close()
        return None

    def consume(
        self,
        kind: str,
        key: str,
        writes: Optional[List[Tuple[str, str, Dict[str, Any], float]]] = None,
    ) -> Optional[Dict[str, Any]]:
        cands = self._candidate_keys(kind, key)
        if not cands:
            return None
        with self._tx() as db:
            now = time.time()
            row = None
            for ck in cands:
                if row is None:
                    cand_row = db.execute("SELECT value,expiry FROM records WHERE kind=? AND key=?", (kind, ck)).fetchone()
                    if cand_row is not None:
                        row = cand_row
                db.execute("DELETE FROM records WHERE kind=? AND key=?", (kind, ck))
            if row and float(row[1]) > now and writes:
                for r_kind, r_key, r_val, r_exp in writes:
                    w_key = hash_token_storage_key(r_key) if r_kind in _HASHED_TOKEN_KINDS else r_key
                    w_val = _sanitize_token_record_for_disk(r_kind, r_val)
                    db.execute(
                        "INSERT OR REPLACE INTO records VALUES (?,?,?,?)",
                        (r_kind, w_key, json.dumps(w_val), float(r_exp)),
                    )
        return json.loads(row[0]) if row and float(row[1]) > now else None

    GLOBAL_AUTH_SHIELD_BUCKET = "__global_credential_shield__"

    @staticmethod
    def _pw_bucket_record_key(bucket_key: str) -> str:
        clean = (bucket_key or "global").strip()[:120] or "global"
        return f"pw_lockout:{clean}"

    def check_auth_lockout(self, bucket_key: str = "global") -> Tuple[bool, int]:
        now = time.time()
        rec = self.get("rate_guard", self._pw_bucket_record_key(bucket_key))
        if not rec:
            return False, 0
        locked_until = float(rec.get("locked_until") or 0.0)
        if locked_until > now:
            return True, max(1, int(locked_until - now))
        return False, 0

    def check_global_auth_lockout(self) -> Tuple[bool, int]:
        return self.check_auth_lockout(self.GLOBAL_AUTH_SHIELD_BUCKET)

    def record_global_auth_result(
        self,
        success: bool,
        *,
        max_failures: int = 8,
        window_sec: int = 30,
        lockout_sec: int = 60,
    ) -> Tuple[bool, int]:
        rec_key = self._pw_bucket_record_key(self.GLOBAL_AUTH_SHIELD_BUCKET)
        with self._tx() as db:
            now = time.time()
            row = db.execute(
                "SELECT value, expiry FROM records WHERE kind='rate_guard' AND key=?",
                (rec_key,),
            ).fetchone()
            state = json.loads(row[0]) if (row and float(row[1]) > now) else {"fails": 0, "locked_until": 0.0}
            if float(state.get("locked_until") or 0.0) > now:
                return True, max(1, int(float(state["locked_until"]) - now))
            if success:
                db.execute("DELETE FROM records WHERE kind='rate_guard' AND key=?", (rec_key,))
                return False, 0
            fails = int(state.get("fails") or 0) + 1
            locked_until = (now + lockout_sec) if fails >= max_failures else 0.0
            expiry = max(now + window_sec, locked_until)
            db.execute(
                "INSERT OR REPLACE INTO records VALUES (?,?,?,?)",
                ("rate_guard", rec_key, json.dumps({"fails": fails, "locked_until": locked_until}), expiry),
            )
            if locked_until > now:
                return True, lockout_sec
            return False, 0

    def record_auth_result(
        self,
        success: bool,
        bucket_key: str = "global",
        max_failures: int = 8,
        window_sec: int = 900,
        lockout_sec: int = 900,
    ) -> Tuple[bool, int]:
        rec_key = self._pw_bucket_record_key(bucket_key)
        with self._tx() as db:
            now = time.time()
            if success:
                db.execute("DELETE FROM records WHERE kind='rate_guard' AND key=?", (rec_key,))
                return False, 0
            row = db.execute(
                "SELECT value, expiry FROM records WHERE kind='rate_guard' AND key=?",
                (rec_key,),
            ).fetchone()
            state = json.loads(row[0]) if (row and float(row[1]) > now) else {"fails": 0, "locked_until": 0.0}
            if float(state.get("locked_until") or 0.0) > now:
                return True, max(1, int(float(state["locked_until"]) - now))
            fails = int(state.get("fails") or 0) + 1
            locked_until = (now + lockout_sec) if fails >= max_failures else 0.0
            expiry = max(now + window_sec, locked_until)
            db.execute(
                "INSERT OR REPLACE INTO records VALUES (?,?,?,?)",
                ("rate_guard", rec_key, json.dumps({"fails": fails, "locked_until": locked_until}), expiry),
            )
            if locked_until > now:
                return True, lockout_sec
            return False, 0

    def extend_client_expiry(self, client_id: str, expiry: float) -> None:
        if not client_id:
            return
        with self._tx() as db:
            db.execute(
                "UPDATE records SET expiry = MAX(expiry, ?) WHERE kind = 'client' AND key = ?",
                (float(expiry), client_id),
            )

    def extend_access_token_ttl_atomic(self, access_token: str, delta_sec: int = 1800) -> bool:
        if not access_token:
            return False
        cands = self._candidate_keys("access", access_token)
        if not cands:
            return False
        h_key = cands[0]
        with self._tx() as db:
            now = time.time()
            matched_key = ""
            row = None
            for ck in cands:
                cand_r = db.execute(
                    "SELECT value, expiry FROM records WHERE kind = 'access' AND key = ? AND expiry > ?",
                    (ck, now),
                ).fetchone()
                if cand_r is not None:
                    matched_key = ck
                    row = cand_r
                    break
            if not row:
                return False
            try:
                rec = json.loads(row[0])
            except Exception:
                return False
            if rec.get("temporary_session"):
                return False
            new_exp = int(rec.get("expires_at") or row[1]) + int(delta_sec)
            max_exp = rec.get("max_expires_at")
            if isinstance(max_exp, (int, float)) and max_exp > 0:
                new_exp = min(new_exp, int(max_exp))
            rec["expires_at"] = new_exp
            clean_rec = _sanitize_token_record_for_disk("access", rec)
            if matched_key != h_key:
                db.execute("DELETE FROM records WHERE kind = 'access' AND key = ?", (matched_key,))
                db.execute(
                    "INSERT OR REPLACE INTO records VALUES (?,?,?,?)",
                    ("access", h_key, json.dumps(clean_rec), float(new_exp)),
                )
                return True
            cur = db.execute(
                "UPDATE records SET value = ?, expiry = ? WHERE kind = 'access' AND key = ? AND expiry > ?",
                (json.dumps(clean_rec), float(new_exp), h_key, now),
            )
            return bool(cur.rowcount and cur.rowcount > 0)

    def check_register_rate_limit(
        self,
        max_per_window: int = 30,
        window_sec: int = 600,
        max_total_clients: int = 500,
        bucket_key: str = "global",
    ) -> bool:
        win_key = f"dcr_window:{(bucket_key or 'global').strip()[:120] or 'global'}"
        with self._tx() as db:
            now = time.time()
            db.execute("DELETE FROM records WHERE expiry <= ?", (now,))
            row = db.execute("SELECT value, expiry FROM records WHERE kind='rate_guard' AND key=?", (win_key,)).fetchone()
            if row and float(row[1]) > now:
                count = int(json.loads(row[0]).get("count") or 0)
                exp = float(row[1])
            else:
                count = 0
                exp = now + window_sec
            if count >= max_per_window:
                return False

            total_clients = db.execute("SELECT COUNT(*) FROM records WHERE kind='client'").fetchone()[0]
            if total_clients >= max_total_clients:
                excess = total_clients - max_total_clients + 1
                evictable = db.execute(
                    "SELECT key FROM records "
                    "WHERE kind = 'client' "
                    "AND key NOT IN ("
                    "  SELECT DISTINCT json_extract(value, '$.client_id') FROM records "
                    "  WHERE kind IN ('access', 'refresh', 'refresh_replay') "
                    "  AND expiry > ? "
                    "  AND json_extract(value, '$.client_id') IS NOT NULL"
                    ") "
                    "ORDER BY expiry ASC LIMIT ?",
                    (now, excess),
                ).fetchall()
                if len(evictable) < excess:
                    return False
                db.executemany("DELETE FROM records WHERE kind = 'client' AND key = ?", [(r[0],) for r in evictable])

            db.execute(
                "INSERT OR REPLACE INTO records VALUES (?,?,?,?)",
                ("rate_guard", win_key, json.dumps({"count": count + 1}), exp),
            )
            return True

    def extend_refresh_non_rotating(
        self,
        rt_token: str,
        updated_rt_payload: Dict[str, Any],
        new_rt_expiry: float,
        access_token: str,
        access_payload: Dict[str, Any],
        access_expiry: float,
    ) -> bool:
        """Extend an active refresh token in-place without rotating it (Google Gemini Connected Apps track)."""
        rt_cands = self._candidate_keys("refresh", rt_token)
        if not rt_cands:
            return False
        h_rt = rt_cands[0]
        h_acc = hash_token_storage_key(access_token)
        clean_rt_val = _sanitize_token_record_for_disk("refresh", updated_rt_payload)
        clean_acc_val = _sanitize_token_record_for_disk("access", access_payload)
        with self._tx() as db:
            now = time.time()
            row = None
            matched_k = ""
            for ck in rt_cands:
                cand_r = db.execute("SELECT value, expiry FROM records WHERE kind='refresh' AND key=?", (ck,)).fetchone()
                if cand_r is not None:
                    row = cand_r
                    matched_k = ck
                    break
            if not row or float(row[1]) <= now:
                return False
            if matched_k and matched_k != h_rt:
                db.execute("DELETE FROM records WHERE kind='refresh' AND key=?", (matched_k,))
            db.execute(
                "INSERT OR REPLACE INTO records VALUES (?,?,?,?)",
                ("refresh", h_rt, json.dumps(clean_rt_val), float(new_rt_expiry)),
            )
            db.execute(
                "INSERT OR REPLACE INTO records VALUES (?,?,?,?)",
                ("access", h_acc, json.dumps(clean_acc_val), float(access_expiry)),
            )
            cid = str(updated_rt_payload.get("client_id") or "")
            if cid:
                db.execute(
                    "UPDATE records SET expiry = MAX(expiry, ?) WHERE kind = 'client' AND key = ?",
                    (now + 365 * 86400, cid),
                )
            return True

    def exchange_refresh_atomic(
        self,
        old_rt: str,
        client_id: str,
        writes: List[Tuple[str, str, Dict[str, Any], float]],
        replay_ttl: int = 3600,
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Single-use refresh rotation with atomic `3600s` `refresh_replay` concurrent grace cache."""
        _ = replay_ttl
        rt_cands = self._candidate_keys("refresh", old_rt)
        if not rt_cands:
            return False, None
        with self._tx() as db:
            now = time.time()
            for ck in rt_cands:
                rep_row = db.execute("SELECT value, expiry FROM records WHERE kind='refresh_replay' AND key=?", (ck,)).fetchone()
                if rep_row and float(rep_row[1]) > now:
                    cached = json.loads(rep_row[0])
                    if client_id and cached.get("client_id") and cached.get("client_id") != client_id:
                        return False, None
                    return True, cached
            row = None
            for ck in rt_cands:
                cand_r = db.execute("SELECT value, expiry FROM records WHERE kind='refresh' AND key=?", (ck,)).fetchone()
                if cand_r is not None:
                    row = cand_r
                    break
            if not row or float(row[1]) <= now:
                return False, None
            for ck in rt_cands:
                db.execute("DELETE FROM records WHERE kind='refresh' AND key=?", (ck,))
            for r_kind, r_key, r_val, r_exp in writes:
                w_key = hash_token_storage_key(r_key) if r_kind in _HASHED_TOKEN_KINDS else r_key
                w_val = _sanitize_token_record_for_disk(r_kind, r_val)
                db.execute(
                    "INSERT OR REPLACE INTO records VALUES (?,?,?,?)",
                    (r_kind, w_key, json.dumps(w_val), float(r_exp)),
                )
            if client_id:
                db.execute(
                    "UPDATE records SET expiry = MAX(expiry, ?) WHERE kind = 'client' AND key = ?",
                    (now + 365 * 86400, client_id),
                )
            return True, None

    def prune_expired(self) -> int:
        now = time.time()
        with self._tx() as db:
            cur = db.execute("DELETE FROM records WHERE expiry <= ?", (now,))
            return max(0, int(cur.rowcount))

    def list_authorized_sessions(self) -> List[Dict[str, Any]]:
        if not self.path.is_file():
            return []
        now = time.time()
        conn = self.connect(readonly=True)
        try:
            rows = conn.execute(
                "SELECT kind, key, value, expiry FROM records "
                "WHERE kind IN ('client', 'access', 'refresh') AND expiry > ?",
                (now,),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        finally:
            conn.close()

        clients_meta: Dict[str, Dict[str, Any]] = {}
        agg: Dict[str, Dict[str, Any]] = {}
        for kind, key, raw_val, exp in rows:
            try:
                doc = json.loads(raw_val) if raw_val else {}
            except Exception:
                doc = {}
            if not isinstance(doc, dict):
                doc = {}
            exp_f = float(exp or 0.0)
            if kind == "client":
                clients_meta[str(key)] = doc
                continue
            cid = str(doc.get("client_id") or "").strip()
            if not cid:
                continue
            slot = agg.setdefault(
                cid,
                {
                    "client_id": cid,
                    "active_access_count": 0,
                    "active_refresh_count": 0,
                    "earliest_expiry": exp_f,
                    "latest_expiry": exp_f,
                    "scopes_set": set(),
                    "resources_set": set(),
                    "any_full_scope": False,
                    "all_temporary": True,
                },
            )
            slot["earliest_expiry"] = min(float(slot["earliest_expiry"]), exp_f)
            slot["latest_expiry"] = max(float(slot["latest_expiry"]), exp_f)
            raw_sc = doc.get("scopes")
            if isinstance(raw_sc, list):
                for s_item in raw_sc:
                    s_clean = str(s_item or "").strip()
                    if s_clean:
                        slot["scopes_set"].add(s_clean)
            res_str = str(doc.get("resource") or "").strip()
            if res_str:
                slot["resources_set"].add(res_str)
            has_ws = isinstance(raw_sc, list) and ("workspace" in raw_sc or "server:admin" in raw_sc)
            if has_ws and not is_readonly_resource_url(res_str):
                slot["any_full_scope"] = True
            if not doc.get("temporary_session"):
                slot["all_temporary"] = False
            if kind == "access":
                slot["active_access_count"] += 1
            elif kind == "refresh":
                slot["active_refresh_count"] += 1

        sessions: List[Dict[str, Any]] = []
        for cid, slot in agg.items():
            if (slot["active_access_count"] + slot["active_refresh_count"]) <= 0:
                continue
            c_doc = clients_meta.get(cid) or {}
            c_name = str(c_doc.get("client_name") or "").strip() or cid
            raw_uris = c_doc.get("redirect_uris") or []
            uris = [str(u) for u in raw_uris if u] if isinstance(raw_uris, list) else []
            platform_label, redirect_hosts = identify_client_platform(c_name, uris, client_id=cid)
            ordered_scopes = [s for s in SCOPES if s in slot["scopes_set"]] + sorted(
                s for s in slot["scopes_set"] if s not in SCOPES
            )
            is_ro = not bool(slot["any_full_scope"])
            is_temp = bool(slot["all_temporary"])
            scope_lbl = "仅只读权限" if is_ro else "工作区标准权限"
            if is_temp:
                scope_lbl += " · 2小时临时授权"
            sessions.append(
                {
                    "client_id": cid,
                    "client_name": c_name,
                    "platform": platform_label,
                    "redirect_hosts": redirect_hosts,
                    "scopes": ordered_scopes,
                    "readonly": is_ro,
                    "temporary_session": is_temp,
                    "scope_label": scope_lbl,
                    "resources": sorted(slot["resources_set"]),
                    "active_access_count": int(slot["active_access_count"]),
                    "active_refresh_count": int(slot["active_refresh_count"]),
                    "earliest_expiry": float(slot["earliest_expiry"]),
                    "latest_expiry": float(slot["latest_expiry"]),
                }
            )
        sessions.sort(key=lambda item: (-item["latest_expiry"], item["client_id"]))
        return sessions

    def mint_personal_access_token(
        self,
        *,
        label: str = "",
        readonly: bool = True,
        ttl_days: int = 30,
    ) -> Dict[str, Any]:
        """Mint a revocable SHA-256 hashed personal access token (`cmcp_*`) in `client` + `access` tables."""
        if isinstance(ttl_days, bool):
            raise ValueError("密钥有效天数需为整数（1 至 365 天）。")
        try:
            eff_ttl_days = int(ttl_days)
        except (TypeError, ValueError) as exc:
            raise ValueError("密钥有效天数需为整数（1 至 365 天）。") from exc
        if eff_ttl_days < 1 or eff_ttl_days > 365:
            raise ValueError("密钥有效天数需在 1 至 365 天之间。")

        cleaned_chars = "".join(ch for ch in str(label or "") if ch.isprintable() and ch not in "\r\n\t")
        clean_label = cleaned_chars.strip()[:80] or "Sites / CLI 专用密钥"
        is_ro = bool(readonly)
        eff_scopes = list(READONLY_SCOPES) if is_ro else list(SCOPES)
        eff_resource = PAT_READONLY_RESOURCE if is_ro else PAT_FULL_RESOURCE

        try:
            self.prune_expired()
        except Exception:
            pass

        now = int(time.time())
        ttl_sec = eff_ttl_days * 86400
        expires_at = now + ttl_sec
        raw_token = "cmcp_" + secrets.token_urlsafe(32)
        client_id = "pat_" + secrets.token_hex(6)

        client_doc: Dict[str, Any] = {
            "client_id": client_id,
            "client_name": clean_label,
            "redirect_uris": [],
            "grant_types": [],
            "token_endpoint_auth_method": "none",
            "scope": " ".join(eff_scopes),
            "token_kind": "personal_access_token",
            "created_at": now,
        }
        access = AccessToken(
            token=raw_token,
            client_id=client_id,
            scopes=eff_scopes,
            expires_at=expires_at,
            resource=eff_resource,
            subject="owner",
        )
        access_doc: Dict[str, Any] = {
            **access.model_dump(mode="json"),
            "temporary_session": False,
            "max_expires_at": expires_at,
        }
        self.put("client", client_id, client_doc, float(expires_at + 7 * 86400))
        self.put("access", raw_token, access_doc, float(expires_at))
        return {
            "ok": True,
            "token": raw_token,
            "client_id": client_id,
            "client_name": clean_label,
            "platform": PAT_PLATFORM_LABEL_ZH,
            "readonly": is_ro,
            "scopes": eff_scopes,
            "resource": eff_resource,
            "ttl_days": eff_ttl_days,
            "expires_at": expires_at,
        }

    def _oneclick_vault_path(self) -> Path:
        return self.path.parent / "chatgpt_oneclick_vault.json"

    def _load_oneclick_vault(self) -> Dict[str, Any]:
        cache = getattr(self, "_oneclick_mem_cache", None)
        if not isinstance(cache, dict):
            cache = {}
            self._oneclick_mem_cache = cache
        vp = self._oneclick_vault_path()
        if not vp.is_file():
            return dict(cache)
        try:
            raw = json.loads(vp.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                return dict(cache)
            from cosmos_mcp.core.config import (
                _dpapi_unprotect_bytes,
                _load_or_create_local_vault_key,
                _stdlib_vault_decrypt,
            )
            alg = str(raw.get("alg") or "")
            if alg == "win32-dpapi" and raw.get("ct"):
                ct_b = base64.b64decode(str(raw["ct"]))
                pt = _dpapi_unprotect_bytes(ct_b, b"cosmos-mcp:chatgpt-oneclick:v1").decode("utf-8")
                doc = json.loads(pt)
                if isinstance(doc, dict):
                    cache.update(doc)
                    return dict(cache)
            elif alg and raw.get("ct"):
                key_b = _load_or_create_local_vault_key(self.path.parent)
                pt = _stdlib_vault_decrypt(raw, key_b, "cosmos-oneclick-vault-v1")
                doc = json.loads(pt)
                if isinstance(doc, dict):
                    cache.update(doc)
                    return dict(cache)
        except Exception:
            pass
        return dict(cache)

    def _save_oneclick_vault(self, doc: Mapping[str, Any]) -> None:
        clean_doc = dict(doc)
        self._oneclick_mem_cache = dict(clean_doc)
        vp = self._oneclick_vault_path()
        try:
            import sys as _sys
            from cosmos_mcp.core.config import (
                _dpapi_protect_bytes,
                _load_or_create_local_vault_key,
                _stdlib_vault_encrypt,
                apply_current_user_only_acl,
                atomic_write_json,
            )
            vp.parent.mkdir(parents=True, exist_ok=True)
            plain_json = json.dumps(clean_doc, ensure_ascii=False)
            if _sys.platform == "win32":
                try:
                    ct_b = _dpapi_protect_bytes(plain_json.encode("utf-8"), b"cosmos-mcp:chatgpt-oneclick:v1")
                    env_doc = {
                        "v": 1,
                        "alg": "win32-dpapi",
                        "ct": base64.b64encode(ct_b).decode("ascii"),
                    }
                    atomic_write_json(vp, env_doc, mode_override=0o600)
                    apply_current_user_only_acl(vp)
                    return
                except Exception:
                    pass
            key_b = _load_or_create_local_vault_key(self.path.parent)
            enc_doc = _stdlib_vault_encrypt(plain_json, key_b, "cosmos-oneclick-vault-v1")
            atomic_write_json(vp, enc_doc, mode_override=0o600)
            apply_current_user_only_acl(vp)
        except Exception:
            pass

    def revoke_oneclick_tokens(self, *, readonly: Optional[bool] = None) -> Dict[str, Any]:
        """Revoke all `token_kind='chatgpt_oneclick'` tokens (optionally filtered by readonly/full)."""
        revoked_ids: List[str] = []
        deleted_total = 0
        if self.path.is_file():
            conn = self.connect(readonly=True)
            try:
                rows = conn.execute(
                    "SELECT key, value FROM records WHERE kind='client' AND json_extract(value,'$.token_kind')='chatgpt_oneclick'"
                ).fetchall()
            except sqlite3.OperationalError:
                rows = []
            finally:
                conn.close()
            for cid, raw_val in rows:
                try:
                    cdoc = json.loads(raw_val) if raw_val else {}
                except Exception:
                    cdoc = {}
                if not isinstance(cdoc, dict):
                    cdoc = {}
                if readonly is not None:
                    c_ro = bool(cdoc.get("readonly", False))
                    if c_ro != bool(readonly):
                        continue
                res = self.revoke_client(str(cid), delete_client=True)
                if res.get("ok"):
                    revoked_ids.append(str(cid))
                    deleted_total += int(res.get("deleted_tokens") or 0)
        vault = self._load_oneclick_vault()
        changed = False
        if readonly is None:
            if vault:
                vault.clear()
                changed = True
        else:
            bkey = "readonly" if bool(readonly) else "full"
            if bkey in vault:
                vault.pop(bkey, None)
                changed = True
        if changed:
            self._save_oneclick_vault(vault)
        return {
            "ok": True,
            "revoked_client_ids": revoked_ids,
            "deleted_tokens": deleted_total,
        }

    def get_or_mint_oneclick_capability_token(
        self,
        *,
        readonly: bool = False,
        rotate: bool = False,
        ttl_days: int = 90,
    ) -> Dict[str, Any]:
        """Return an active reusable or freshly minted high-entropy ChatGPT one-click capability token (`oc_*`)."""
        if isinstance(ttl_days, bool):
            raise ValueError("有效天数需为整数（1 至 365 天）。")
        try:
            eff_ttl_days = int(ttl_days)
        except (TypeError, ValueError) as exc:
            raise ValueError("有效天数需为整数（1 至 365 天）。") from exc
        if eff_ttl_days < 1 or eff_ttl_days > 365:
            raise ValueError("有效天数需在 1 至 365 天之间。")

        is_ro = bool(readonly)
        bucket = "readonly" if is_ro else "full"
        eff_scopes = list(READONLY_SCOPES) if is_ro else list(SCOPES)
        eff_resource = PAT_READONLY_RESOURCE if is_ro else PAT_FULL_RESOURCE
        client_name = "ChatGPT 一键连接（只读）" if is_ro else "ChatGPT 一键连接"

        try:
            self.prune_expired()
        except Exception:
            pass

        vault = self._load_oneclick_vault()
        if not rotate:
            entry = vault.get(bucket)
            if isinstance(entry, dict):
                cached_tok = str(entry.get("token") or "").strip()
                if cached_tok:
                    acc_rec = self.get("access", cached_tok)
                    if isinstance(acc_rec, dict):
                        rec_cid = str(acc_rec.get("client_id") or "").strip()
                        rec_res = str(acc_rec.get("resource") or "").strip().rstrip("/")
                        rec_exp = int(acc_rec.get("expires_at") or 0)
                        c_doc = self.get("client", rec_cid) if rec_cid else None
                        if (
                            isinstance(c_doc, dict)
                            and c_doc.get("token_kind") == "chatgpt_oneclick"
                            and rec_res == eff_resource
                            and rec_exp > int(time.time()) + 300
                        ):
                            return {
                                "ok": True,
                                "token": cached_tok,
                                "client_id": rec_cid,
                                "client_name": str(c_doc.get("client_name") or client_name),
                                "platform": "OpenAI ChatGPT",
                                "readonly": is_ro,
                                "scopes": list(acc_rec.get("scopes") or eff_scopes),
                                "resource": eff_resource,
                                "ttl_days": eff_ttl_days,
                                "expires_at": rec_exp,
                                "reused": True,
                            }
        else:
            self.revoke_oneclick_tokens(readonly=is_ro)
            vault = self._load_oneclick_vault()

        now = int(time.time())
        expires_at = now + eff_ttl_days * 86400
        raw_token = "oc_" + secrets.token_urlsafe(24)
        client_id = "cgpt_oc_" + secrets.token_hex(6)

        client_doc: Dict[str, Any] = {
            "client_id": client_id,
            "client_name": client_name,
            "redirect_uris": [],
            "grant_types": [],
            "token_endpoint_auth_method": "none",
            "scope": " ".join(eff_scopes),
            "token_kind": "chatgpt_oneclick",
            "readonly": is_ro,
            "created_at": now,
        }
        access = AccessToken(
            token=raw_token,
            client_id=client_id,
            scopes=eff_scopes,
            expires_at=expires_at,
            resource=eff_resource,
            subject="owner",
        )
        access_doc: Dict[str, Any] = {
            **access.model_dump(mode="json"),
            "token_kind": "chatgpt_oneclick",
            "temporary_session": False,
            "max_expires_at": expires_at,
        }
        self.put("client", client_id, client_doc, float(expires_at + 7 * 86400))
        self.put("access", raw_token, access_doc, float(expires_at))
        vault[bucket] = {
            "token": raw_token,
            "client_id": client_id,
            "expires_at": expires_at,
            "readonly": is_ro,
        }
        self._save_oneclick_vault(vault)
        return {
            "ok": True,
            "token": raw_token,
            "client_id": client_id,
            "client_name": client_name,
            "platform": "OpenAI ChatGPT",
            "readonly": is_ro,
            "scopes": eff_scopes,
            "resource": eff_resource,
            "ttl_days": eff_ttl_days,
            "expires_at": expires_at,
            "reused": False,
        }

    def revoke_client(self, client_id: str, delete_client: bool = False) -> Dict[str, Any]:
        """Independent per-client revocation preserving sibling clients' replay caches."""
        cid = (client_id or "").strip()
        if not cid:
            return {"ok": False, "client_id": "", "deleted_tokens": 0, "deleted_by_kind": {}}
        if not self.path.is_file():
            return {
                "ok": True,
                "client_id": cid,
                "deleted_tokens": 0,
                "deleted_by_kind": {"access": 0, "refresh": 0, "refresh_replay": 0, "code": 0, "ticket": 0, "client": 0},
                "client_preserved": not delete_client,
            }
        with self._tx() as db:
            c_acc = db.execute("DELETE FROM records WHERE kind='access' AND json_extract(value,'$.client_id')=?", (cid,)).rowcount
            c_ref = db.execute("DELETE FROM records WHERE kind='refresh' AND json_extract(value,'$.client_id')=?", (cid,)).rowcount
            c_rep = db.execute(
                "DELETE FROM records WHERE kind='refresh_replay' AND (json_extract(value,'$.client_id')=? OR json_extract(value,'$.client_id') IS NULL)",
                (cid,),
            ).rowcount
            c_cod = db.execute("DELETE FROM records WHERE kind='code' AND json_extract(value,'$.client_id')=?", (cid,)).rowcount
            c_tkt = db.execute(
                "DELETE FROM records WHERE kind IN ('consent','consent_result','consent_sess','local_bridge_nonce','local_bridge_proof','ticket') AND json_extract(value,'$.client_id')=?",
                (cid,),
            ).rowcount
            c_cli = 0
            if delete_client:
                c_cli = db.execute("DELETE FROM records WHERE kind='client' AND key=?", (cid,)).rowcount
        by_kind = {
            "access": max(0, int(c_acc)),
            "refresh": max(0, int(c_ref)),
            "refresh_replay": max(0, int(c_rep)),
            "code": max(0, int(c_cod)),
            "ticket": max(0, int(c_tkt)),
            "client": max(0, int(c_cli)),
        }
        return {
            "ok": True,
            "client_id": cid,
            "deleted_tokens": sum(by_kind.values()),
            "deleted_by_kind": by_kind,
            "client_preserved": not delete_client,
        }

    def revoke_token_and_related(self, raw_token: str, client_id: str) -> None:
        """Revoke exact token record, its stored `client_id`, `token.client_id`, and Google DCR sibling `client_id`s."""
        target_cids: Set[str] = set()
        if client_id and client_id.strip():
            target_cids.add(client_id.strip())
        if not self.path.is_file():
            return
        with self._tx() as db:
            for knd in ("access", "refresh", "refresh_replay"):
                for ck in self._candidate_keys(knd, raw_token):
                    row = db.execute("SELECT value FROM records WHERE kind=? AND key=?", (knd, ck)).fetchone()
                    if row and row[0]:
                        with contextlib.suppress(Exception):
                            rec = json.loads(row[0])
                            if isinstance(rec, dict) and rec.get("client_id"):
                                target_cids.add(str(rec["client_id"]).strip())
                    db.execute("DELETE FROM records WHERE kind=? AND key=?", (knd, ck))
            bound_google_ids: Set[str] = set()
            for cid in list(target_cids):
                crow = db.execute("SELECT value FROM records WHERE kind='client' AND key=?", (cid,)).fetchone()
                if crow and crow[0]:
                    with contextlib.suppress(Exception):
                        cdoc = json.loads(crow[0])
                        if isinstance(cdoc, dict):
                            bound_google_ids.update(_google_user_bound_ids(cdoc.get("redirect_uris") or []))
            if bound_google_ids:
                all_crows = db.execute("SELECT key, value FROM records WHERE kind='client'").fetchall()
                for ckey, cval in all_crows:
                    with contextlib.suppress(Exception):
                        cdoc2 = json.loads(cval) if cval else {}
                        if isinstance(cdoc2, dict):
                            gids = _google_user_bound_ids(cdoc2.get("redirect_uris") or [])
                            if gids and gids == bound_google_ids:
                                target_cids.add(str(ckey).strip())
        for cid in target_cids:
            if cid:
                self.revoke_client(cid)

    def revoke_all_tokens(self, delete_clients: bool = False) -> Dict[str, Any]:
        if not self.path.is_file():
            return {
                "ok": True,
                "deleted_tokens": 0,
                "deleted_by_kind": {"access": 0, "refresh": 0, "refresh_replay": 0, "code": 0, "ticket": 0, "client": 0},
                "clients_preserved": not delete_clients,
            }
        with self._tx() as db:
            c_acc = db.execute("DELETE FROM records WHERE kind='access'").rowcount
            c_ref = db.execute("DELETE FROM records WHERE kind='refresh'").rowcount
            c_rep = db.execute("DELETE FROM records WHERE kind='refresh_replay'").rowcount
            c_cod = db.execute("DELETE FROM records WHERE kind='code'").rowcount
            c_tkt = db.execute(
                "DELETE FROM records WHERE kind IN ('consent','consent_result','consent_sess','local_bridge_nonce','local_bridge_proof','ticket')"
            ).rowcount
            c_cli = 0
            if delete_clients:
                c_cli = db.execute("DELETE FROM records WHERE kind='client'").rowcount
        by_kind = {
            "access": max(0, int(c_acc)),
            "refresh": max(0, int(c_ref)),
            "refresh_replay": max(0, int(c_rep)),
            "code": max(0, int(c_cod)),
            "ticket": max(0, int(c_tkt)),
            "client": max(0, int(c_cli)),
        }
        return {
            "ok": True,
            "deleted_tokens": sum(by_kind[k] for k in ("access", "refresh", "refresh_replay", "code", "ticket")),
            "deleted_by_kind": by_kind,
            "clients_preserved": not delete_clients,
        }


class IssuerResponseMiddleware:
    """Attach RFC 9207 `iss` query parameter to `302` OAuth authorization redirects and validate inbound `iss`."""

    def __init__(self, app: Any, issuer: str, provider: Optional[Any] = None) -> None:
        self.app = app
        self.issuer = issuer.rstrip("/")
        self.provider = provider

    def _effective_issuer(self, scope: Optional[Dict[str, Any]] = None) -> str:
        gw = _REQUEST_GATEWAY_VAR.get()
        if gw is not None and gw.issuer:
            cur = gw.issuer.rstrip("/")
        else:
            cur = str(getattr(self.provider, "issuer", "") or self.issuer).strip().rstrip("/")
        if scope is not None:
            for hk, hv in scope.get("headers") or ():
                if hk.lower() == b"x-cosmos-public-prefix":
                    raw_p = hv.decode("latin-1", errors="replace").strip()
                    clean_p = "/" + raw_p.strip("/") if raw_p.strip("/") else ""
                    if clean_p and re.match(r"^/[a-zA-Z0-9._~/-]+$", clean_p) and ".." not in clean_p and "//" not in clean_p:
                        if not cur.endswith(clean_p):
                            u = urlsplit(cur)
                            if u.scheme and u.netloc:
                                return f"{u.scheme}://{u.netloc}{clean_p}"
                    break
        return cur

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        eff_iss = self._effective_issuer(scope if scope.get("type") == "http" else None)
        if scope.get("type") == "http":
            raw_qs = (scope.get("query_string") or b"").decode("latin-1", errors="replace")
            if raw_qs:
                q_dict = dict(parse_qsl(raw_qs, keep_blank_values=True))
                if "iss" in q_dict and q_dict["iss"].rstrip("/") != eff_iss:
                    resp = JSONResponse(
                        {"error": "invalid_request", "error_description": "RFC 9207 issuer mismatch"},
                        status_code=400,
                    )
                    await resp(scope, receive, send)
                    return

        async def send_with_issuer(message: Dict[str, Any]) -> None:
            if message["type"] == "http.response.start" and message["status"] == 302:
                headers = []
                for name, value in message["headers"]:
                    if name.lower() == b"location":
                        uri = urlsplit(value.decode("latin-1"))
                        query = parse_qsl(uri.query, keep_blank_values=True)
                        if any(key in ("code", "error") for key, _ in query):
                            query = [(key, item) for key, item in query if key != "iss"]
                            query.append(("iss", eff_iss))
                            value = urlunsplit(uri._replace(query=urlencode(query))).encode("latin-1")
                    headers.append((name, value))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_issuer)


def _first_header_ip(headers_map: Mapping[str, str], keys: Sequence[str]) -> str:
    for key in keys:
        raw = str(headers_map.get(key) or "").split(",", 1)[0].strip()
        if raw:
            return raw[:80]
    return ""


def _rightmost_header_ip(headers_map: Mapping[str, str], keys: Sequence[str]) -> str:
    for key in keys:
        parts = [p.strip() for p in str(headers_map.get(key) or "").split(",") if p.strip()]
        if parts:
            return parts[-1][:80]
    return ""


def resolve_client_ip_from_headers(
    headers_map: Mapping[str, str],
    peer_host: str = "",
    tunnel_mode: str = "",
) -> Tuple[str, bool]:
    """Resolve `(client_ip, has_trusted_ip)` across Cloudflare/DO/VPS/srv.us/public gateway tunnels without global DCR bucket starvation.

    - Non-loopback TCP peers always return `(peer_host, True)` and ignore forwarded headers.
    - Loopback peers (`127.0.0.1`, `::1`, `localhost`, `testclient`):
      * Explicit local-only modes (`local`, `direct`, `loopback`, `ssh`, `ssh_reverse`) without local relay markers
        ignore forwarded headers (`has_trusted_ip=False`) so local processes cannot spoof per-IP lockouts.
      * `srv_us` -> rightmost `x-forwarded-for` hop appended by the `srv.us` edge proxy (prevents both `127.0.0.1` bucket starvation and header-rotation bypass).
      * When `cf-connecting-ip` (Cloudflare edge unforgeable header) is present, it always takes precedence over `x-cosmos-client-ip`.
      * `cloudflare` / `cf` / `cloudflared` / `cloudflare_token` / `workers_dev` / `public_gateway` / `do_gateway` / `gateway` ->
        `cf-connecting-ip`, falling back to forwarded headers only via verified local relay (`x-cosmos-via-tunnel` / `x-cosmos-public-prefix`) or rightmost `x-forwarded-for`.
      * `reverse_proxy` / `nginx` / `caddy` / `vps` / `vps_hub` / `custom` -> `cf-connecting-ip` (when present) else `x-cosmos-client-ip` / `x-real-ip` / rightmost `x-forwarded-for`.
    """
    peer = (peer_host or "").strip()[:80] or "unknown"
    if peer.lower() not in LOOPBACK_PEERS:
        return peer, True

    eff_mode = (
        tunnel_mode
        or os.environ.get("COSMOS_TUNNEL_MODE")
        or os.environ.get("LOCALPC_TUNNEL_MODE")
        or ""
    ).strip().lower()

    has_trusted_local_relay = bool(
        str(headers_map.get("x-cosmos-via-tunnel") or "").strip() == "1"
        or str(headers_map.get("x-cosmos-public-prefix") or "").strip()
    )

    if eff_mode in ("local", "direct", "loopback", "ssh", "ssh_reverse") and not has_trusted_local_relay:
        return peer, False

    if eff_mode == "srv_us":
        ip = _rightmost_header_ip(headers_map, ("x-forwarded-for",))
        if ip:
            return ip, True
        if headers_map.get("cf-ray"):
            cf_ip = _first_header_ip(headers_map, ("cf-connecting-ip",))
            if cf_ip:
                return cf_ip, True
        return peer, False

    cf_ip = _first_header_ip(headers_map, ("cf-connecting-ip",))

    if eff_mode in (
        "cloudflare",
        "cf",
        "cloudflared",
        "cloudflare_token",
        "workers_dev",
        "public_gateway",
        "do_gateway",
        "gateway",
        "cf_workers",
        "cf_do",
    ):
        if cf_ip:
            return cf_ip, True
        if has_trusted_local_relay:
            ip = _rightmost_header_ip(headers_map, ("x-forwarded-for",)) or _first_header_ip(
                headers_map, ("x-cosmos-client-ip", "x-real-ip")
            )
            return (ip, True) if ip else (peer, False)
        ip = _rightmost_header_ip(headers_map, ("x-forwarded-for",)) or _first_header_ip(headers_map, ("x-real-ip",))
        return (ip, True) if ip else (peer, False)

    if eff_mode in ("reverse_proxy", "nginx", "caddy", "vps", "vps_hub", "custom"):
        if cf_ip:
            return cf_ip, True
        ip = _first_header_ip(headers_map, ("x-cosmos-client-ip", "x-real-ip")) or _rightmost_header_ip(
            headers_map, ("x-forwarded-for",)
        )
        return (ip, True) if ip else (peer, False)

    if cf_ip:
        return cf_ip, True

    if has_trusted_local_relay:
        ip = _rightmost_header_ip(headers_map, ("x-forwarded-for",)) or _first_header_ip(
            headers_map, ("x-cosmos-client-ip", "x-real-ip")
        )
        if ip:
            return ip, True

    return peer, False


def resolve_request_client_ip(request: Request, tunnel_mode: str = "") -> Tuple[str, bool]:
    peer = (request.client.host if request.client else "") or "unknown"
    hdr_map = {k.lower(): v for k, v in request.headers.items()}
    return resolve_client_ip_from_headers(hdr_map, peer_host=peer, tunnel_mode=tunnel_mode)


def extract_request_client_ip(request: Request, tunnel_mode: str = "") -> str:
    ip, _ = resolve_request_client_ip(request, tunnel_mode=tunnel_mode)
    return ip


class RegisterGrantCompatASGI:
    """RFC 7591 / RFC 8252 compatibility wrapper filling `refresh_token` when `authorization_code` is registered."""

    def __init__(self, inner_app: Any, tunnel_mode: str = "") -> None:
        self.inner_app = inner_app
        self.tunnel_mode = str(tunnel_mode or "").strip().lower()

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or str(scope.get("method") or "").upper() != "POST":
            await self.inner_app(scope, receive, send)
            return
        chunks: List[bytes] = []
        while True:
            msg = await receive()
            if msg.get("type") == "http.request":
                chunks.append(msg.get("body", b""))
                if not msg.get("more_body", False):
                    break
            else:
                break
        raw_body = b"".join(chunks)
        try:
            doc = json.loads(raw_body.decode("utf-8"))
            if isinstance(doc, dict) and isinstance(doc.get("grant_types"), list):
                gts = doc["grant_types"]
                if "authorization_code" in gts and "refresh_token" not in gts:
                    doc = {**doc, "grant_types": [*gts, "refresh_token"]}
                    raw_body = json.dumps(doc, ensure_ascii=False).encode("utf-8")
        except Exception:
            pass

        sent_once = False

        async def replay_receive() -> Dict[str, Any]:
            nonlocal sent_once
            if not sent_once:
                sent_once = True
                return {"type": "http.request", "body": raw_body, "more_body": False}
            return {"type": "http.disconnect"}

        hdr_map = {k.decode("latin-1").lower(): v.decode("latin-1", errors="replace") for k, v in (scope.get("headers") or [])}
        cli_tuple = scope.get("client")
        peer_ip = str(cli_tuple[0]).strip() if isinstance(cli_tuple, (list, tuple)) and cli_tuple else "unknown"
        gw = _REQUEST_GATEWAY_VAR.get()
        eff_tm = gw.tunnel_mode if (gw is not None and gw.tunnel_mode) else self.tunnel_mode
        raw_ip, _ = resolve_client_ip_from_headers(hdr_map, peer_host=peer_ip, tunnel_mode=eff_tm)
        ip_tok = set_register_client_ip(raw_ip)
        try:
            await self.inner_app(scope, replay_receive, send)
        finally:
            reset_register_client_ip(ip_tok)


_RegisterGrantCompat = RegisterGrantCompatASGI


class OAuthProvider:
    """OAuth 2.1 Authorization Server Provider supporting DCR, PKCE S256, 4-char pair code, and dual-track refresh."""

    def __init__(
        self,
        store: OAuthSQLiteStore,
        base_url: str,
        password_hash: str,
        salt: str,
        redirect_hosts: Optional[Sequence[str]] = None,
        allowed_resources: Optional[Set[str] | Sequence[str]] = None,
        *,
        tier_label: str = "L3 工作区标准开发档",
        issuer: Optional[str] = None,
        tier_key: str = "tier3_workspace_dev",
        toolset_profile: str = "standard",
        exposed_tools: Optional[Sequence[str]] = None,
        tool_prefix: str = "pc",
        valid_scopes: Optional[Sequence[str]] = None,
        default_scopes: Optional[Sequence[str]] = None,
        tunnel_mode: str = "",
        non_rotating_google: bool = True,
        refresh_replay_ttl: int = 3600,
        persistent_replay_only: bool = False,
        max_auth_failures: int = 8,
        local_port: Optional[int] = None,
        trusted_gateways: Optional[Sequence[Any]] = None,
        master_seed: Optional[bytes] = None,
        state_root: Optional[Path] = None,
    ) -> None:
        self.store = store
        self.base_url = base_url.rstrip("/")
        self.issuer = (issuer if issuer is not None else str(AnyHttpUrl(self.base_url))).rstrip("/")
        self.resource = self.base_url + "/mcp"
        self.readonly_resource = self.base_url + "/mcp/readonly"
        self.password_hash = password_hash
        self.salt = salt
        self.redirect_hosts = (
            {h.lower() for h in DEFAULT_REDIRECT_HOSTS}
            | set(OPENAI_REDIRECT_HOSTS)
            | {h.lower() for h in (redirect_hosts or ()) if h}
        )
        self.tier_label = tier_label
        self.tier_key = tier_key
        self.toolset_profile = toolset_profile
        self.exposed_tools: List[str] = list(exposed_tools or ())
        self.tool_prefix: str = normalize_prefix(tool_prefix)
        self.valid_scopes: List[str] = list(valid_scopes) if valid_scopes is not None else list(SCOPES)
        self.default_scopes: List[str] = (
            list(default_scopes) if default_scopes is not None else list(self.valid_scopes)
        )
        eff_tm = (
            tunnel_mode
            or os.environ.get("COSMOS_TUNNEL_MODE", "")
            or os.environ.get("LOCALPC_TUNNEL_MODE", "")
        )
        self.tunnel_mode: str = str(eff_tm or "").strip().lower()
        self.non_rotating_google: bool = bool(non_rotating_google)
        self.refresh_replay_ttl: int = max(0, int(refresh_replay_ttl))
        self.persistent_replay_only: bool = bool(persistent_replay_only)
        self.max_auth_failures: int = max(1, int(max_auth_failures))
        parsed_base = urlsplit(self.base_url)
        inferred_port = (
            int(parsed_base.port)
            if (parsed_base.hostname or "").lower() in ("127.0.0.1", "localhost", "::1") and parsed_base.port
            else 8096
        )
        self.local_port: int = int(local_port) if (local_port is not None and int(local_port) > 0) else inferred_port
        self._state_root: Optional[Path] = Path(state_root).expanduser().resolve() if state_root is not None else None
        self._bridge_boot_secret: bytes = self._derive_or_init_bridge_boot_secret(master_seed=master_seed)
        base_allowed = {
            self.resource.rstrip("/"),
            self.readonly_resource.rstrip("/"),
            self.base_url,
            f"http://127.0.0.1:{self.local_port}",
            f"http://127.0.0.1:{self.local_port}/mcp",
            f"http://127.0.0.1:{self.local_port}/mcp/readonly",
        }
        if allowed_resources:
            base_allowed.update(str(r).rstrip("/") for r in allowed_resources if r)
        self._initial_allowed_resources: Set[str] = set(base_allowed)
        self.allowed_resources: Set[str] = set(base_allowed)
        self.trusted_gateways: Dict[Tuple[str, str], TrustedGatewayEndpoint] = {}
        self._explicit_empty_gateways: bool = False
        self._gateway_sync_listeners: List[Callable[[], None]] = []
        if trusted_gateways is not None:
            self.sync_trusted_gateways(trusted_gateways, primary_base=self.base_url, primary_tunnel_mode=self.tunnel_mode)
        else:
            def_ep = self._default_gateway_endpoint()
            if not def_ep.is_loopback:
                self._insert_trusted_endpoint(self.trusted_gateways, def_ep)

    def _candidate_state_roots(self) -> List[Path]:
        cands: List[Path] = []
        if self._state_root is not None:
            cands.append(self._state_root)
        st_path = getattr(self.store, "path", None) or getattr(self.store, "db_path", None)
        if st_path is not None:
            p = Path(st_path).expanduser().resolve().parent
            if p.name.lower() in ("state", "secrets", "data"):
                cands.extend([p.parent, p])
            else:
                cands.extend([p, p.parent])
        out: List[Path] = []
        seen: Set[str] = set()
        for item in cands:
            k = os.path.normcase(str(item))
            if k not in seen:
                seen.add(k)
                out.append(item)
        return out

    def _derive_or_init_bridge_boot_secret(self, master_seed: Optional[bytes] = None) -> bytes:
        """Derive deterministic `_bridge_boot_secret` from `master_seed` (or persisted state secret) across hot restarts."""
        ctx_tag = f"cosmos-oauth-bridge-boot-secret:v1:{self.tool_prefix}".encode("utf-8")
        if isinstance(master_seed, (bytes, bytearray)) and len(master_seed) >= 16:
            return hmac.new(bytes(master_seed), ctx_tag, hashlib.sha256).digest()

        seed_names = (
            [f"master_seed_{self.tool_prefix}", "master_seed", f"master_seed_{self.tool_prefix}.bin", "master_seed.bin"]
            if self.tool_prefix != "pc"
            else ["master_seed", "master_seed.bin"]
        )
        auth_names = (
            [f"auth_{self.tool_prefix}.json", "auth.json"]
            if self.tool_prefix != "pc"
            else ["auth.json"]
        )
        sec_txt_names = (
            [f"workers_tunnel_secret_{self.tool_prefix}.txt", "workers_tunnel_secret.txt", f"vps_node_secret_{self.tool_prefix}.txt", "vps_node_secret.txt"]
            if self.tool_prefix != "pc"
            else ["workers_tunnel_secret.txt", "vps_node_secret.txt"]
        )

        for root in self._candidate_state_roots():
            sec_dir = root / "secrets"
            if not sec_dir.is_dir():
                continue
            for fn in seed_names:
                sp = sec_dir / fn
                if sp.is_file():
                    try:
                        raw_seed = sp.read_bytes()
                        if len(raw_seed) >= 16:
                            return hmac.new(raw_seed, ctx_tag, hashlib.sha256).digest()
                    except OSError:
                        pass
            for afn in auth_names:
                ap = sec_dir / afn
                if ap.is_file():
                    try:
                        adoc = json.loads(ap.read_text(encoding="utf-8-sig"))
                        if isinstance(adoc, Mapping):
                            loc_tok = str(adoc.get("local_api_token") or "").strip()
                            if len(loc_tok) >= 16:
                                return hmac.new(loc_tok.encode("utf-8"), ctx_tag, hashlib.sha256).digest()
                    except Exception:
                        pass
            for tfn in sec_txt_names:
                tp = sec_dir / tfn
                if tp.is_file():
                    try:
                        tval = tp.read_text(encoding="utf-8", errors="replace").strip()
                        if len(tval) >= 16:
                            return hmac.new(tval.encode("utf-8"), ctx_tag, hashlib.sha256).digest()
                    except OSError:
                        pass
        return secrets.token_bytes(32)

    @staticmethod
    def _insert_trusted_endpoint(
        target_map: Dict[Tuple[str, str], TrustedGatewayEndpoint],
        ep: TrustedGatewayEndpoint,
    ) -> None:
        if ep.is_loopback or not ep.authority:
            return
        target_map[(ep.authority, ep.public_prefix.lower())] = ep
        # Auto-include `a-b-c-d.sslip.io` companion hostname when a bare IPv4 VPS Hub endpoint is registered
        host_only = ep.authority.split(":", 1)[0]
        if _IPV4_HOST_RE.match(host_only) and not host_only.startswith("127."):
            sslip_host = host_only.replace(".", "-") + ".sslip.io"
            port_sfx = ":" + ep.authority.split(":", 1)[1] if ":" in ep.authority else ""
            sslip_auth = f"{sslip_host}{port_sfx}"
            sslip_base = f"{ep.scheme}://{sslip_auth}{ep.public_prefix}"
            sslip_ep = TrustedGatewayEndpoint(
                gateway_id=ep.gateway_id,
                tunnel_mode=ep.tunnel_mode,
                scheme=ep.scheme,
                authority=sslip_auth,
                public_prefix=ep.public_prefix,
                base_url=sslip_base,
                issuer=sslip_base,
                resource=f"{sslip_base}/mcp",
                readonly_resource=f"{sslip_base}/mcp/readonly",
                is_loopback=False,
            )
            target_map.setdefault((sslip_auth, ep.public_prefix.lower()), sslip_ep)

    def _default_gateway_endpoint(self) -> TrustedGatewayEndpoint:
        ep = build_trusted_gateway_endpoint(
            self.base_url,
            gateway_id="default",
            tunnel_mode=self.tunnel_mode,
            local_port=self.local_port,
        )
        if ep is not None:
            return ep
        lb_base = f"http://127.0.0.1:{int(self.local_port)}"
        return TrustedGatewayEndpoint(
            gateway_id="loopback",
            tunnel_mode="local",
            scheme="http",
            authority=f"127.0.0.1:{int(self.local_port)}",
            public_prefix="",
            base_url=lb_base,
            issuer=lb_base,
            resource=f"{lb_base}/mcp",
            readonly_resource=f"{lb_base}/mcp/readonly",
            is_loopback=True,
        )

    def get_active_endpoint_secret(self) -> str:
        eff_p = str(getattr(self, "_eff_prefix", "") or getattr(self, "tool_prefix", "") or "pc").strip() or "pc"
        for cand_sr in self._candidate_state_roots():
            sec = load_endpoint_secret(cand_sr, prefix=eff_p)
            if sec:
                return sec
        return ""

    def get_effective_trusted_gateways(self) -> Dict[Tuple[str, str], TrustedGatewayEndpoint]:
        merged = dict(self.trusted_gateways)
        if not self._explicit_empty_gateways:
            def_ep = self._default_gateway_endpoint()
            if not def_ep.is_loopback and (def_ep.authority, def_ep.public_prefix.lower()) not in merged:
                self._insert_trusted_endpoint(merged, def_ep)
        ep_sec = self.get_active_endpoint_secret()
        if ep_sec:
            sec_pfx = f"/u/{ep_sec}"
            for ep_item in list(merged.values()):
                if not ep_item.is_loopback and ep_item.authority:
                    sec_ep = _with_public_prefix(ep_item, sec_pfx)
                    merged[(sec_ep.authority, sec_pfx)] = sec_ep
                    self.allowed_resources.update(
                        {
                            sec_ep.base_url,
                            sec_ep.resource.rstrip("/"),
                            sec_ep.readonly_resource.rstrip("/"),
                        }
                    )
        return merged

    def current_request_gateway(self) -> TrustedGatewayEndpoint:
        gw = _REQUEST_GATEWAY_VAR.get()
        return gw if gw is not None else self._default_gateway_endpoint()

    def register_gateway_sync_listener(self, callback: Callable[[], None]) -> None:
        if callback not in self._gateway_sync_listeners:
            self._gateway_sync_listeners.append(callback)

    def sync_trusted_gateways(
        self,
        endpoints: Sequence[Union[TrustedGatewayEndpoint, Mapping[str, Any], str]],
        *,
        primary_base: Optional[str] = None,
        primary_tunnel_mode: Optional[str] = None,
        grace_bases: Sequence[str] = (),
        replace_allowed_resources: bool = False,
    ) -> Dict[Tuple[str, str], TrustedGatewayEndpoint]:
        """Atomically synchronize active `trusted_gateways` and `allowed_resources` without dropping live sessions."""
        if primary_tunnel_mode is not None:
            self.tunnel_mode = str(primary_tunnel_mode).strip().lower()
        if primary_base is not None:
            clean_pb = str(primary_base).strip().rstrip("/")
            if clean_pb.startswith(("http://", "https://")):
                self.base_url = clean_pb
                self.issuer = str(AnyHttpUrl(clean_pb)).rstrip("/")
                self.resource = f"{clean_pb}/mcp"
                self.readonly_resource = f"{clean_pb}/mcp/readonly"

        new_map: Dict[Tuple[str, str], TrustedGatewayEndpoint] = {}
        for item in endpoints or ():
            ep_obj: Optional[TrustedGatewayEndpoint] = None
            if isinstance(item, TrustedGatewayEndpoint):
                ep_obj = item
            elif isinstance(item, str):
                ep_obj = build_trusted_gateway_endpoint(
                    item,
                    gateway_id="default",
                    tunnel_mode=self.tunnel_mode,
                    local_port=self.local_port,
                )
            elif isinstance(item, Mapping):
                raw_u = str(item.get("public_url") or item.get("base_url") or item.get("url") or "").strip()
                gw_id = str(item.get("gateway_id") or "default").strip()
                tm = str(item.get("tunnel_mode") or item.get("effective_mode") or item.get("submode") or "").strip()
                if raw_u:
                    ep_obj = build_trusted_gateway_endpoint(
                        raw_u,
                        gateway_id=gw_id,
                        tunnel_mode=tm,
                        local_port=self.local_port,
                    )
            if ep_obj is not None and not ep_obj.is_loopback:
                self._insert_trusted_endpoint(new_map, ep_obj)

        self._explicit_empty_gateways = len(new_map) == 0 and (
            primary_tunnel_mode == "local" or self._default_gateway_endpoint().is_loopback
        )
        if not new_map and not self._explicit_empty_gateways:
            def_ep = self._default_gateway_endpoint()
            if not def_ep.is_loopback:
                self._insert_trusted_endpoint(new_map, def_ep)

        self.trusted_gateways = new_map

        lp = int(self.local_port)
        seed_allowed: Set[str] = set() if replace_allowed_resources else set(self._initial_allowed_resources)
        next_allowed: Set[str] = seed_allowed | {
            self.base_url,
            self.resource.rstrip("/"),
            self.readonly_resource.rstrip("/"),
            f"http://127.0.0.1:{lp}",
            f"http://127.0.0.1:{lp}/mcp",
            f"http://127.0.0.1:{lp}/mcp/readonly",
        }
        for ep in new_map.values():
            next_allowed.update({ep.base_url, ep.resource.rstrip("/"), ep.readonly_resource.rstrip("/")})
            root_origin = f"{ep.scheme}://{ep.authority}"
            next_allowed.update({root_origin, f"{root_origin}/mcp", f"{root_origin}/mcp/readonly"})
        for gb in grace_bases or ():
            clean_gb = str(gb or "").strip().rstrip("/")
            if clean_gb.startswith(("http://", "https://")):
                next_allowed.update({clean_gb, f"{clean_gb}/mcp", f"{clean_gb}/mcp/readonly"})
        if replace_allowed_resources:
            self.allowed_resources.clear()
        self.allowed_resources.update(next_allowed)

        for cb in list(self._gateway_sync_listeners):
            try:
                cb()
            except Exception:
                pass
        return dict(self.trusted_gateways)

    def _ticket_gateway_endpoint(
        self,
        request: Optional[Request] = None,
        pending: Optional[Mapping[str, Any]] = None,
    ) -> TrustedGatewayEndpoint:
        req_gw = _REQUEST_GATEWAY_VAR.get()
        if req_gw is not None and not req_gw.is_loopback:
            return req_gw
        if isinstance(pending, Mapping):
            saved_base = str(pending.get("gateway_base_url") or "").strip().rstrip("/")
            saved_id = str(pending.get("gateway_id") or "default").strip()
            saved_tm = str(pending.get("gateway_tunnel_mode") or "").strip().lower()
            if saved_base:
                eff_map = self.get_effective_trusted_gateways()
                for ep in eff_map.values():
                    if ep.base_url == saved_base:
                        return ep
                cand_ep = build_trusted_gateway_endpoint(
                    saved_base,
                    gateway_id=saved_id,
                    tunnel_mode=saved_tm or self.tunnel_mode,
                    local_port=self.local_port,
                )
                if cand_ep is not None and not cand_ep.is_loopback:
                    if (cand_ep.authority, "") in eff_map or (cand_ep.authority, cand_ep.public_prefix.lower()) in eff_map:
                        return cand_ep
                if cand_ep is not None and saved_base == self.base_url:
                    return cand_ep
        if req_gw is not None:
            return req_gw
        _ = request
        return self._default_gateway_endpoint()

    def _consent_path(self, gw: Optional[TrustedGatewayEndpoint] = None) -> str:
        eff_gw = gw or self.current_request_gateway()
        prefix = urlsplit(eff_gw.base_url).path.rstrip("/")
        return f"{prefix}/consent" if prefix else "/consent"

    def _is_https_issuer(self, gw: Optional[TrustedGatewayEndpoint] = None) -> bool:
        eff_gw = gw or self.current_request_gateway()
        return eff_gw.scheme.lower() == "https"

    def _bridge_hmac_secret(self) -> bytes:
        seed = f"cosmos-oauth-bridge-hmac-v1:{self.salt}:{self.password_hash}:"
        return hmac.new(self._bridge_boot_secret, seed.encode("utf-8"), hashlib.sha256).digest()

    def _allowed_consent_origins(
        self,
        request: Optional[Request] = None,
        gw: Optional[TrustedGatewayEndpoint] = None,
    ) -> Set[str]:
        from cosmos_mcp.protocol import oauth_web as _ow

        origins: Set[str] = set()
        req_gw = gw or (_REQUEST_GATEWAY_VAR.get() if request is not None else None)
        if request is not None and req_gw is not None and not req_gw.is_loopback:
            origins.add(f"{req_gw.scheme.lower()}://{req_gw.authority.lower()}")
        else:
            for ep in self.get_effective_trusted_gateways().values():
                origins.add(f"{ep.scheme.lower()}://{ep.authority.lower()}")
            for cand in (self.base_url, *self.allowed_resources):
                u = urlsplit(str(cand or "").strip())
                if u.scheme and u.netloc:
                    origins.add(f"{u.scheme.lower()}://{u.netloc.lower()}")
        u_base = urlsplit(self.base_url)
        pure_local_req = (
            _ow.is_pure_local_consent_request(request, expected_port=self.local_port)
            if request is not None
            else False
        )
        if (
            request is None
            or (req_gw is not None and req_gw.is_loopback)
            or (u_base.hostname or "").lower() in ("127.0.0.1", "localhost", "::1")
            or pure_local_req
        ):
            lp = int(self.local_port)
            origins.update(
                {
                    f"http://127.0.0.1:{lp}",
                    f"http://localhost:{lp}",
                    f"http://[::1]:{lp}",
                    "http://127.0.0.1",
                    "http://localhost",
                    "http://[::1]",
                }
            )
        return origins

    def _public_complete_url(
        self,
        request: Request,
        pending: Optional[Mapping[str, Any]] = None,
    ) -> str:
        raw_pfx = str(request.headers.get("x-cosmos-public-prefix") or "").strip()
        clean_pfx = "/" + raw_pfx.strip("/") if raw_pfx.strip("/") else ""
        if clean_pfx and (not re.match(r"^/[a-zA-Z0-9._~/-]+$", clean_pfx) or ".." in clean_pfx or "//" in clean_pfx):
            clean_pfx = ""
        ticket_gw = self._ticket_gateway_endpoint(request, pending)
        if not ticket_gw.is_loopback:
            eff_path = clean_pfx or ticket_gw.public_prefix
            return f"{ticket_gw.scheme}://{ticket_gw.authority}{eff_path}/consent/complete"
        u_base = urlsplit(self.base_url)
        if (u_base.hostname or "").lower() not in ("127.0.0.1", "localhost", "::1"):
            eff_path = clean_pfx or (u_base.path or "").rstrip("/")
            return f"{u_base.scheme}://{u_base.netloc}{eff_path}/consent/complete"
        req_u = getattr(request, "url", None)
        req_scheme = str(
            request.headers.get("x-forwarded-proto")
            or getattr(req_u, "scheme", "")
            or u_base.scheme
            or "http"
        ).split(",", 1)[0].strip().lower()
        req_host = str(
            request.headers.get("x-forwarded-host")
            or request.headers.get("host")
            or u_base.netloc
        ).split(",", 1)[0].strip()
        eff_path = clean_pfx or (u_base.path or "").rstrip("/")
        return f"{req_scheme}://{req_host}{eff_path}/consent/complete"

    def _build_consent_csp(self, redirect_uri: str = "", gw: Optional[TrustedGatewayEndpoint] = None) -> str:
        eff_gw = gw or self.current_request_gateway()
        actions = ["'self'", "https:", "http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]
        if eff_gw.scheme.lower() == "http" or urlsplit(self.base_url).scheme.lower() == "http":
            actions.append("http:")
        if redirect_uri:
            r_scheme = (urlsplit(str(redirect_uri)).scheme or "").strip().lower()
            if r_scheme and r_scheme not in ("http", "https") and re.match(r"^[a-z][a-z0-9+.-]*$", r_scheme):
                actions.append(f"{r_scheme}:")
        return f"default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; form-action {' '.join(actions)}"

    def get_dynamic_pair_code(self, now: Optional[float] = None) -> str:
        code = derive_dynamic_pair_code(self.password_hash, self.salt, timestamp=now)
        self._write_latest_dynamic_code(code)
        return code

    def verify_dynamic_code(self, candidate: str, now: Optional[float] = None) -> bool:
        return verify_dynamic_pair_code(candidate, self.password_hash, self.salt, now=now)

    def _pair_code_rel_path(self) -> str:
        return (
            f"state/latest_consent_pair_code_{self.tool_prefix}.txt"
            if self.tool_prefix != "pc"
            else "state/latest_consent_pair_code.txt"
        )

    def _write_latest_pair_code(self, pair_code: str) -> None:
        if not pair_code or pair_code == "----":
            return
        try:
            st_dir = Path(self.store.path).resolve().parent
            st_dir.mkdir(parents=True, exist_ok=True)
            targets = [st_dir / "latest_consent_pair_code.txt"]
            if self.tool_prefix != "pc":
                pref_f = st_dir / f"latest_consent_pair_code_{self.tool_prefix}.txt"
                if pref_f not in targets:
                    targets.append(pref_f)
            for target in targets:
                tmp = st_dir / f".{target.stem}.{secrets.token_hex(4)}.tmp"
                tmp.write_text(f"{pair_code}\n", encoding="utf-8")
                os.replace(tmp, target)
        except Exception as exc:
            LOGGER.warning("failed writing latest_consent_pair_code: %s", exc)

    def _write_latest_dynamic_code(self, dyn_code: str) -> None:
        if not dyn_code or len(dyn_code) != 6:
            return
        try:
            st_dir = Path(self.store.path).resolve().parent
            st_dir.mkdir(parents=True, exist_ok=True)
            targets = [st_dir / "latest_dynamic_pair_code.txt"]
            if self.tool_prefix != "pc":
                pref_f = st_dir / f"latest_dynamic_pair_code_{self.tool_prefix}.txt"
                if pref_f not in targets:
                    targets.append(pref_f)
            for target in targets:
                tmp = st_dir / f".{target.stem}.{secrets.token_hex(4)}.tmp"
                tmp.write_text(f"{dyn_code}\n", encoding="utf-8")
                os.replace(tmp, target)
        except Exception as exc:
            LOGGER.warning("failed writing latest_dynamic_pair_code: %s", exc)

    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        record = self.store.get("client", client_id)
        return OAuthClientInformationFull.model_validate(record) if record else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        reg_ip = (_REGISTER_CLIENT_IP_VAR.get() or "").strip() or "global"
        bucket = f"ip:{reg_ip}" if reg_ip != "global" else "global"
        if not self.store.check_register_rate_limit(bucket_key=bucket):
            raise RegistrationError("invalid_client_metadata", "Too many client registration requests; try again later.")
        if client_info.token_endpoint_auth_method not in ("none", "client_secret_post", "client_secret_basic"):
            raise RegistrationError(
                "invalid_client_metadata",
                "Supported token_endpoint_auth_method values: none, client_secret_post, client_secret_basic",
            )
        for raw in client_info.redirect_uris or []:
            raw_str = str(raw).strip()
            if raw_str in ALLOWED_NATIVE_REDIRECT_URIS:
                continue
            uri = urlsplit(raw_str)
            host = (uri.hostname or "").lower()
            try:
                port_val = uri.port
            except ValueError:
                raise RegistrationError("invalid_redirect_uri", f"Invalid port in redirect_uri `{raw_str}`.")
            is_loopback = (
                uri.scheme in ("http", "https")
                and host in ("127.0.0.1", "localhost", "::1")
                and (port_val is None or (1 <= int(port_val) <= 65535))
            )
            is_https_allowed = (
                uri.scheme == "https"
                and (host in self.redirect_hosts or is_google_oauth_redirect_host(host))
                and port_val in (None, 443)
            )
            if uri.username or uri.password or uri.fragment or not (is_loopback or is_https_allowed):
                raise RegistrationError(
                    "invalid_redirect_uri",
                    f"Callback host `{host}` is not in allowed redirect_hosts.",
                )
            if host == "chatgpt.com":
                segments = uri.path.split("/")
                stable = uri.path == "/connector_platform_oauth_redirect"
                identified = (
                    len(segments) == 4
                    and segments[:3] == ["", "connector", "oauth"]
                    and segments[3]
                    and all(ch.isascii() and (ch.isalnum() or ch in "_-") for ch in segments[3])
                )
                if uri.query or not (stable or identified):
                    raise RegistrationError("invalid_redirect_uri", "Invalid ChatGPT OAuth redirect path.")
            elif host == "claude.ai" and uri.path not in ("/api/mcp/auth_callback", "/oauth/callback"):
                raise RegistrationError("invalid_redirect_uri", "Invalid Claude OAuth redirect path.")
            elif host == "vscode.dev" and uri.path != "/redirect":
                raise RegistrationError("invalid_redirect_uri", "Invalid VS Code OAuth redirect path.")

        if not client_info.scope:
            client_info.scope = " ".join(self.default_scopes)
        elif not set(client_info.scope.split()).issubset(self.valid_scopes):
            raise RegistrationError("invalid_client_metadata", "Unknown or unauthorized permission scope")
        self.store.put("client", client_info.client_id, client_info.model_dump(mode="json"), time.time() + 86400)

    @staticmethod
    def _authz_done_key(client_id: str, state: str, code_challenge: str) -> str:
        return hashlib.sha256(f"{client_id}|{state}|{code_challenge}".encode("utf-8")).hexdigest()[:32]

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        gw = self.current_request_gateway()
        if not gw.is_loopback:
            self.allowed_resources.update({gw.base_url, gw.resource.rstrip("/"), gw.readonly_resource.rstrip("/")})
            root_orig = f"{gw.scheme}://{gw.authority}"
            self.allowed_resources.update({root_orig, f"{root_orig}/mcp", f"{root_orig}/mcp/readonly"})
        if not params.scopes:
            params.scopes = client.scope.split() if client.scope else list(self.default_scopes)
        norm_res = str(params.resource).rstrip("/") if params.resource else None
        if norm_res is not None:
            if norm_res not in self.allowed_resources:
                raise AuthorizeError("invalid_request", "Resource does not identify this MCP server")
            if not gw.is_loopback and _normalize_url_authority(norm_res) != gw.authority:
                raise AuthorizeError("invalid_request", "Requested resource authority does not match active gateway")
        if not params.code_challenge or not set(params.scopes).issubset(self.valid_scopes):
            raise AuthorizeError("invalid_scope", "Known scopes and PKCE S256 are required")
        effective_resource = str(params.resource) if params.resource else gw.resource
        params.scopes = narrow_scopes_for_resource(params.scopes, effective_resource)
        state_str = str(params.state or "").strip()
        recent_done = (
            self.store.get("authz_done", self._authz_done_key(client.client_id, state_str, str(params.code_challenge or "")))
            if state_str
            else None
        )
        ticket = secrets.token_urlsafe(32)
        pair_code = derive_consent_pair_code(ticket)
        self._write_latest_pair_code(pair_code)
        self.get_dynamic_pair_code()
        exp_ts = time.time() + 600
        self.store.put(
            "consent",
            ticket,
            {
                "client_id": client.client_id,
                "params": params.model_dump(mode="json"),
                "effective_resource": effective_resource,
                "gateway_id": gw.gateway_id,
                "gateway_base_url": gw.base_url,
                "gateway_issuer": gw.issuer,
                "gateway_tunnel_mode": gw.tunnel_mode,
                "csrf": secrets.token_urlsafe(32),
                "pair_code": pair_code,
                "already_approved_recent": bool(recent_done),
                "expires_at": exp_ts,
            },
            exp_ts,
        )
        return gw.base_url + "/consent?" + urlencode({"ticket": ticket})

    def authenticate_owner(self, password: str) -> bool:
        return verify_owner_password(password, self.password_hash, self.salt)

    def consent_cookie(self, ticket: str) -> str:
        return "localpc_csrf_" + hashlib.sha256(ticket.encode("utf-8")).hexdigest()[:24]

    @staticmethod
    def _wants_json_only(request: Request) -> bool:
        accept = (request.headers.get("accept") or "").lower()
        return "application/json" in accept and "text/html" not in accept

    def consent_message(
        self,
        request: Request,
        error: str,
        reason: str,
        detail: str,
        status: int,
        headers: Dict[str, str],
    ) -> HTMLResponse | JSONResponse:
        payload = {"error": error, "reason": reason, "detail": detail}
        accept = (request.headers.get("accept") or "").lower()
        if "text/html" not in accept:
            return JSONResponse(payload, status_code=status, headers=headers)
        heading = "授权已提交" if status == 200 else "需要重新连接"
        page = (
            '<!doctype html><html lang="zh-CN"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width"><title>连接状态</title>'
            "<style>body{background:#10171d;color:#edf4f2;font:17px system-ui;max-width:560px;margin:8vh auto;padding:24px}"
            "a{color:#78dec1}p{line-height:1.8}</style>"
            f"<h1>{heading}</h1><p>{html.escape(detail)}</p>"
            '<p><a href="/">返回本地 Studio 控制台</a> · '
            '<a href="https://gemini.google.com/app" rel="noopener noreferrer">返回 Gemini</a> · '
            '<a href="https://chatgpt.com/" rel="noopener noreferrer">返回 ChatGPT</a></p></html>'
        )
        return HTMLResponse(page, status_code=status, headers={**headers, "X-Consent-Result": reason})

    def _has_cross_site_consent_headers(
        self,
        request: Request,
    ) -> Tuple[bool, str, str, str, Set[str], str, str]:
        from cosmos_mcp.protocol import oauth_web as _ow

        allowed_origins = self._allowed_consent_origins(request)
        raw_origin_hdr = str(request.headers.get("origin") or "").strip()
        req_origin = _ow.extract_origin_scheme_netloc(raw_origin_hdr)
        raw_referer_hdr = str(request.headers.get("referer") or "").strip()
        req_referer_origin = _ow.extract_origin_scheme_netloc(raw_referer_hdr)
        sec_fetch_site = str(request.headers.get("sec-fetch-site") or "").strip().lower()

        has_foreign_origin = bool(
            raw_origin_hdr
            and raw_origin_hdr.lower() != "null"
            and (not req_origin or req_origin not in allowed_origins)
        )
        has_foreign_referer = bool(
            raw_referer_hdr
            and raw_referer_hdr.lower() != "null"
            and (not req_referer_origin or req_referer_origin not in allowed_origins)
        )
        is_cross_site = has_foreign_origin or has_foreign_referer or sec_fetch_site == "cross-site"
        return (
            is_cross_site,
            req_origin,
            req_referer_origin,
            sec_fetch_site,
            allowed_origins,
            raw_origin_hdr,
            raw_referer_hdr,
        )

    def _completed_consent_response(
        self,
        request: Request,
        completed: Mapping[str, Any],
        headers: Dict[str, str],
    ) -> RedirectResponse | HTMLResponse | JSONResponse:
        redir_target = str(completed.get("redirect") or "")
        redir_uri = str(completed.get("redirect_uri") or redir_target)
        out_headers = {**headers, "Content-Security-Policy": self._build_consent_csp(redir_uri)}
        if self.store.get("code", str(completed.get("code") or "")) is not None:
            LOGGER.info("duplicate consent submission: resuming same unused authorization code")
            return RedirectResponse(redir_target, status_code=302, headers=out_headers)
        LOGGER.info("duplicate consent submission: authorization code already exchanged or expired")
        return self.consent_message(
            request,
            "already_submitted",
            "authorization_already_submitted",
            "授权已经提交，请回到客户端查看连接状态。如果客户端仍未连接，请从客户端设置重新连接。",
            200,
            out_headers,
        )

    def completed_submission(
        self,
        request: Request,
        ticket: str,
        form: Mapping[str, Any],
        headers: Dict[str, str],
    ) -> Optional[RedirectResponse | HTMLResponse | JSONResponse]:
        from cosmos_mcp.protocol import oauth_web as _ow

        completed = self.store.get("consent_result", ticket) if ticket else None
        if completed is None:
            return None

        is_cross_site, req_origin, req_referer_origin, sec_fetch_site, allowed_origins, raw_origin_hdr, raw_referer_hdr = (
            self._has_cross_site_consent_headers(request)
        )
        if is_cross_site:
            LOGGER.warning(
                "completed consent POST rejected due to cross-site origin/referer: origin=%r referer=%r sec_fetch_site=%r allowed=%r",
                raw_origin_hdr,
                raw_referer_hdr,
                sec_fetch_site,
                sorted(allowed_origins),
            )
            return self.consent_message(
                request,
                "invalid_consent",
                "origin_mismatch",
                "授权请求来源域名校验失败，请从绑定的官方连接地址重新发起。",
                403,
                headers,
            )

        csrf = str(form.get("csrf") or "")
        if not csrf or not hmac.compare_digest(csrf, str(completed.get("csrf") or "")):
            return self.consent_message(
                request,
                "invalid_consent",
                "completed_submission_not_authenticated",
                "这次提交无法确认身份。请重新发起连接。",
                403,
                headers,
            )

        pw_in = str(form.get("password") or "")
        pair_in = str(form.get("pair_code") or form.get("dynamic_code") or "")
        compact_pair_in = re.sub(r"[\s-]+", "", pair_in)
        compact_pw_in = re.sub(r"[\s-]+", "", pw_in)
        authed = (
            self.authenticate_owner(pw_in)
            or self.verify_dynamic_code(pair_in)
            or self.verify_dynamic_code(pw_in)
            or (len(compact_pair_in) == 6 and compact_pair_in.isdigit() and self.verify_dynamic_code(compact_pair_in))
            or (len(compact_pw_in) == 6 and compact_pw_in.isdigit() and self.verify_dynamic_code(compact_pw_in))
        )

        raw_auth_mode = str(form.get("auth_mode") or "").strip().lower()
        raw_decision = str(form.get("decision") or "").strip().lower()
        if (
            not authed
            and (raw_auth_mode == "local_bridge" or _ow.is_verified_local_fast_approve())
            and raw_decision != "deny"
        ):
            has_same_origin = (
                _ow.is_verified_local_fast_approve()
                or _ow.is_pure_local_consent_request(request, expected_port=self.local_port)
                or bool(req_origin and req_origin in allowed_origins)
                or bool(req_referer_origin and req_referer_origin in allowed_origins)
                or sec_fetch_site == "same-origin"
            )
            raw_sess_cookie = _ow.read_consent_session_cookie(request)
            inc_sess_hash = _ow.hash_consent_session_token(raw_sess_cookie)
            comp_sess_hash = str(completed.get("consent_session_hash") or "").strip()
            if (
                has_same_origin
                and comp_sess_hash
                and inc_sess_hash
                and hmac.compare_digest(inc_sess_hash, comp_sess_hash)
            ):
                authed = True

        if not authed:
            return self.consent_message(
                request,
                "invalid_consent",
                "completed_submission_not_authenticated",
                "这次提交无法确认身份。请重新发起连接。",
                403,
                headers,
            )
        return self._completed_consent_response(request, completed, headers)

    @staticmethod
    def _consent_permission_desc_zh(tier_key: str, tier_label: str = "") -> str:
        tk = (tier_key or "").strip().lower()
        lbl = (tier_label or "").strip().upper()
        if tk.startswith("tier1") or lbl.startswith("L1"):
            return "仅允许在授权工作区目录内只读查看文件与检索代码，禁止修改文件或运行命令。"
        if tk.startswith("tier2") or lbl.startswith("L2"):
            return "允许在授权工作区目录内查看、新建、修改文件及移入回收站，禁止运行终端命令或脚本。"
        if tk.startswith("tier4") or lbl.startswith("L4"):
            return "允许跨目录读写文件与运行终端命令或脚本（仍保留回收站保护与密钥目录隔离），请确认客户端来源可信。"
        return "允许在授权工作区目录内读写修改文件、移入回收站，并运行终端命令与 Python 脚本。"

    def _render_consent_html(
        self,
        *,
        client_name: str,
        consent_path: str,
        ticket: str,
        csrf: str,
        nonce: str,
        pair_code: str,
        error_banner: str = "",
        is_readonly_resource: bool = False,
        selected_scope: str = "default",
        selected_ttl: str = "30d",
    ) -> str:
        conn_fn = conn_info_filename_for_prefix(self.tool_prefix)
        perm_desc = self._consent_permission_desc_zh(self.tier_key, self.tier_label)
        return render_consent_template_html(
            tier_key=self.tier_key,
            tier_label=self.tier_label,
            permission_desc_zh=perm_desc,
            pair_code=pair_code,
            pair_code_path=self._pair_code_rel_path(),
            client_name=client_name or "AI 客户端",
            conn_filename=conn_fn,
            consent_path=consent_path,
            ticket=ticket,
            csrf=csrf,
            nonce=nonce,
            error_banner=error_banner,
            is_readonly_resource=is_readonly_resource,
            selected_scope=selected_scope,
            selected_ttl=selected_ttl,
        )

    def _approve_pending_consent(
        self,
        request: Request,
        *,
        ticket: str,
        pending: Mapping[str, Any],
        want_readonly: bool,
        is_temp_2h: bool,
        headers: Dict[str, str],
        is_https_req: bool,
        form: Optional[Mapping[str, Any]] = None,
    ) -> RedirectResponse | HTMLResponse | JSONResponse:
        from cosmos_mcp.protocol import oauth_web as _ow

        ticket_gw = self._ticket_gateway_endpoint(request, pending)
        eff_iss = str(pending.get("gateway_issuer") or ticket_gw.issuer)
        params = AuthorizationParams.model_validate(pending["params"])
        effective_resource = str(pending.get("effective_resource") or params.resource or ticket_gw.resource)
        eff_code_scopes = narrow_scopes_for_resource(
            params.scopes or self.default_scopes,
            effective_resource,
            force_readonly=want_readonly,
        )
        code = AuthorizationCode(
            code=secrets.token_urlsafe(32),
            scopes=eff_code_scopes,
            expires_at=time.time() + 300,
            client_id=pending["client_id"],
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=effective_resource,
            subject="owner",
        )
        redirect = construct_redirect_uri(str(params.redirect_uri), code=code.code, state=params.state, iss=eff_iss)
        code_doc = {
            **code.model_dump(mode="json"),
            "grant_readonly": bool(want_readonly or is_readonly_resource_url(effective_resource)),
            "temporary_session": bool(is_temp_2h),
            "session_ttl_sec": TEMPORARY_SESSION_TTL_SEC if is_temp_2h else None,
            "gateway_id": str(pending.get("gateway_id") or ticket_gw.gateway_id),
            "gateway_base_url": str(pending.get("gateway_base_url") or ticket_gw.base_url),
            "gateway_issuer": eff_iss,
        }
        sess_rec = (
            (self.store.get("consent_sess", f"consent_sess:{ticket}") or self.store.get("consent_sess", ticket) or {})
            if ticket
            else {}
        )
        bound_sess_hash = str(pending.get("consent_session_hash") or sess_rec.get("consent_session_hash") or "").strip()
        if not bound_sess_hash:
            bound_sess_hash = _ow.hash_consent_session_token(_ow.read_consent_session_cookie(request))
        result_doc = {
            "csrf": pending["csrf"],
            "code": code.code,
            "redirect": redirect,
            "client_id": pending["client_id"],
            "consent_session_hash": bound_sess_hash,
            "oauth_state": str(params.state or ""),
            "redirect_uri": str(params.redirect_uri),
            "gateway_base_url": str(pending.get("gateway_base_url") or ticket_gw.base_url),
            "gateway_issuer": eff_iss,
        }
        writes: List[Tuple[str, str, Dict[str, Any], float]] = [
            ("code", code.code, code_doc, code.expires_at),
            ("consent_result", ticket, result_doc, time.time() + 600),
        ]
        state_clean = str(params.state or "").strip()
        if state_clean:
            done_k = self._authz_done_key(str(pending["client_id"]), state_clean, str(params.code_challenge or ""))
            writes.append(("authz_done", done_k, {"client_id": pending["client_id"], "state": state_clean}, time.time() + 600))

        consumed = self.store.consume("consent", ticket, writes=writes)
        if not consumed:
            if form is not None:
                completed = self.completed_submission(request, ticket, form, headers)
                if completed is not None:
                    return completed
            else:
                completed = self.store.get("consent_result", ticket) if ticket else None
                inc_sess_hash = _ow.hash_consent_session_token(_ow.read_consent_session_cookie(request))
                comp_sess_hash = str((completed or {}).get("consent_session_hash") or "").strip()
                if (
                    isinstance(completed, dict)
                    and comp_sess_hash
                    and inc_sess_hash
                    and hmac.compare_digest(inc_sess_hash, comp_sess_hash)
                ):
                    return self._completed_consent_response(request, completed, headers)
            return self.consent_message(
                request,
                "expired_consent",
                "expired_during_submission",
                "授权页在提交期间过期，请从客户端重新发起连接。",
                400,
                headers,
            )
        self.store.consume("consent_sess", f"consent_sess:{ticket}")
        self.store.consume("consent_sess", ticket)
        self.store.extend_client_expiry(str(pending["client_id"]), time.time() + 365 * 86400)
        resp = RedirectResponse(redirect, status_code=302, headers=headers)
        eff_sec = bool(self._is_https_issuer(ticket_gw) and is_https_req)
        resp.delete_cookie(self.consent_cookie(ticket), path="/", secure=eff_sec, httponly=True, samesite="lax")
        return resp

    async def consent(self, request: Request) -> RedirectResponse | HTMLResponse | JSONResponse:
        from cosmos_mcp.protocol import oauth_web as _ow

        peek_ticket = (request.query_params.get("ticket") or "").strip()
        peek_pending = self.store.get("consent", peek_ticket) if peek_ticket else None
        active_gw = self._ticket_gateway_endpoint(request, peek_pending)
        pure_local_req = _ow.is_pure_local_consent_request(request, expected_port=self.local_port)
        eff_gw_tm = "local" if pure_local_req else (active_gw.tunnel_mode or self.tunnel_mode)

        tok_mob = _ow._MOBILE_UA_REQ_VAR.set(_ow.is_mobile_user_agent(getattr(request, "headers", None)))
        tok_rem = _ow._REMOTE_HUB_REQ_VAR.set(
            False if pure_local_req else _ow.is_remote_hub_consent_mode(eff_gw_tm, local_port=self.local_port)
        )
        try:
            base_csp = self._build_consent_csp(gw=active_gw)
            headers = {
                "Cache-Control": "no-store",
                "Content-Security-Policy": base_csp,
                "Referrer-Policy": "no-referrer",
            }
            consent_path = self._consent_path(active_gw)
            is_https_req = _ow.is_https_consent_request(request)
            eff_csrf_secure = bool(self._is_https_issuer(active_gw) and is_https_req)
            req_res = (request.query_params.get("resource") or "").strip().rstrip("/")
            if req_res and req_res not in self.allowed_resources:
                return JSONResponse(
                    {"error": "forbidden_cross_resource", "reason": "resource_mismatch"},
                    status_code=403,
                    headers=headers,
                )

            ip_bucket, has_trusted_ip = resolve_request_client_ip(request, tunnel_mode=eff_gw_tm)

            if has_trusted_ip:
                locked, wait_sec = self.store.check_auth_lockout(bucket_key=ip_bucket)
                if locked:
                    payload = {"error": "rate_limited", "reason": "ip_password_lockout", "retry_after": wait_sec}
                    if "text/html" not in (request.headers.get("accept") or "").lower():
                        return JSONResponse(payload, status_code=429, headers=headers)
                    return HTMLResponse(f"<h1>请求过于频繁</h1><p>请等待 {wait_sec} 秒后重试。</p>", status_code=429, headers=headers)

            if request.method == "GET":
                ticket = (request.query_params.get("ticket") or "").strip()
                if not ticket:
                    return self.consent_message(
                        request,
                        "expired_consent",
                        "missing_ticket",
                        "缺少授权参数，请从客户端连接设置重新发起连接。",
                        400,
                        headers,
                    )
                pending = self.store.get("consent", ticket)
                eff_res_get = ""
                if isinstance(pending, dict):
                    eff_res_get = str(
                        pending.get("effective_resource")
                        or (pending.get("params") or {}).get("resource")
                        or ""
                    ).strip().rstrip("/")
                    if eff_res_get and eff_res_get not in self.allowed_resources:
                        return JSONResponse(
                            {"error": "forbidden_cross_resource", "reason": "resource_mismatch"},
                            status_code=403,
                            headers=headers,
                        )
                if not pending or "csrf" not in pending:
                    already_done = self.store.get("consent_result", ticket)
                    if already_done is not None:
                        return self.consent_message(
                            request,
                            "already_submitted",
                            "authorization_already_submitted",
                            "授权已经提交，请回到客户端查看连接状态。如需重新连接请从客户端设置发起。",
                            200,
                            headers,
                        )
                    LOGGER.warning("consent page unavailable: expired_or_legacy_transaction")
                    return self.consent_message(
                        request,
                        "expired_consent",
                        "expired_or_legacy_transaction",
                        "这张授权页已过期或已经提交。请关闭此页，从客户端连接设置重新发起连接。",
                        400,
                        headers,
                    )
                client = await self.get_client(str(pending["client_id"]))
                if not client:
                    return JSONResponse({"error": "invalid_client"}, status_code=400, headers=headers)
                csrf = str(pending["csrf"])
                pair_code = str(pending.get("pair_code") or derive_consent_pair_code(ticket))
                self._write_latest_pair_code(pair_code)
                self.get_dynamic_pair_code()

                # Step 1: Bind browser consent session cookie (`__Host-cosmos_consent_s` on HTTPS / `cosmos_consent_s` on HTTP)
                inc_sess = _ow.read_consent_session_cookie(request)
                existing_hash = str(pending.get("consent_session_hash") or "")
                if inc_sess and len(inc_sess) >= 32 and (
                    not existing_hash
                    or hmac.compare_digest(_ow.hash_consent_session_token(inc_sess), existing_hash)
                ):
                    sess_raw = inc_sess
                    sess_hash = _ow.hash_consent_session_token(inc_sess)
                else:
                    sess_raw = secrets.token_urlsafe(32)
                    sess_hash = _ow.hash_consent_session_token(sess_raw)
                tkt_exp = float(pending.get("expires_at") or (time.time() + 600))
                rem_ttl = max(60, int(tkt_exp - time.time()))
                pending["consent_session_hash"] = sess_hash
                self.store.put("consent", ticket, pending, tkt_exp)
                sess_doc = {
                    "ticket": ticket,
                    "consent_session_hash": sess_hash,
                    "client_id": str(pending["client_id"]),
                }
                self.store.put("consent_sess", f"consent_sess:{ticket}", sess_doc, tkt_exp)
                self.store.put("consent_sess", ticket, sess_doc, tkt_exp)

                redir_u = str((pending.get("params") or {}).get("redirect_uri") or "")
                dyn_csp = self._build_consent_csp(redir_u)
                nonce = secrets.token_urlsafe(16)
                page_headers = {
                    **headers,
                    "Referrer-Policy": "same-origin",
                    "Content-Security-Policy": f"{dyn_csp}; script-src 'nonce-{nonce}'",
                }
                fallback_banner = (
                    "检测到浏览器代理接管了 127.0.0.1 回环请求，已为您展开下方 6 位动态配对码输入框（在任务栏托盘或本地面板即可查看）"
                    if request.query_params.get("bridge_fallback") == "1"
                    else ""
                )
                page = self._render_consent_html(
                    client_name=client.client_name or "AI 客户端",
                    consent_path=consent_path,
                    ticket=ticket,
                    csrf=csrf,
                    nonce=nonce,
                    pair_code=pair_code,
                    error_banner=fallback_banner,
                    is_readonly_resource=is_readonly_resource_url(eff_res_get),
                    selected_scope=str(pending.get("selected_scope") or "default"),
                    selected_ttl=str(pending.get("selected_ttl") or "30d"),
                )
                resp = HTMLResponse(page, headers=page_headers)
                resp.set_cookie(
                    self.consent_cookie(ticket),
                    csrf,
                    secure=eff_csrf_secure,
                    httponly=True,
                    samesite="lax",
                    max_age=rem_ttl,
                    path="/",
                )
                sess_cookie_name = _ow.CONSENT_SESSION_COOKIE_HTTPS if is_https_req else _ow.CONSENT_SESSION_COOKIE_HTTP
                resp.set_cookie(
                    sess_cookie_name,
                    sess_raw,
                    secure=is_https_req,
                    httponly=True,
                    samesite="lax",
                    max_age=rem_ttl,
                    path="/",
                )
                return resp

            form = await request.form()
            form_res = str(form.get("resource") or "").strip().rstrip("/")
            if form_res and form_res not in self.allowed_resources:
                return JSONResponse(
                    {"error": "forbidden_cross_resource", "reason": "resource_mismatch"},
                    status_code=403,
                    headers=headers,
                )
            ticket = str(form.get("ticket") or request.query_params.get("ticket") or "")
            pending = self.store.get("consent", ticket) if ticket else None
            eff_res_p = ""
            if isinstance(pending, dict):
                active_gw = self._ticket_gateway_endpoint(request, pending)
                consent_path = self._consent_path(active_gw)
                eff_gw_tm = "local" if pure_local_req else (active_gw.tunnel_mode or self.tunnel_mode)
                _ow._REMOTE_HUB_REQ_VAR.set(
                    False if pure_local_req else _ow.is_remote_hub_consent_mode(eff_gw_tm, local_port=self.local_port)
                )
                eff_res_p = str(
                    pending.get("effective_resource")
                    or (pending.get("params") or {}).get("resource")
                    or ""
                ).strip().rstrip("/")
                if eff_res_p and eff_res_p not in self.allowed_resources:
                    return JSONResponse(
                        {"error": "forbidden_cross_resource", "reason": "resource_mismatch"},
                        status_code=403,
                        headers=headers,
                    )
                redir_u_post = str((pending.get("params") or {}).get("redirect_uri") or "")
                base_csp = self._build_consent_csp(redir_u_post, gw=active_gw)
                headers["Content-Security-Policy"] = base_csp
            if pending is None and ticket:
                completed = self.completed_submission(request, ticket, form, headers)
                if completed is not None:
                    return completed

            csrf = str(form.get("csrf") or "")
            cookie_csrf = str(request.cookies.get(self.consent_cookie(ticket), "") or "")
            raw_sess_cookie = _ow.read_consent_session_cookie(request)
            inc_sess_hash = _ow.hash_consent_session_token(raw_sess_cookie)
            sess_rec = (
                (self.store.get("consent_sess", f"consent_sess:{ticket}") or self.store.get("consent_sess", ticket) or {})
                if ticket
                else {}
            )
            exp_sess_hash = str((pending or {}).get("consent_session_hash") or sess_rec.get("consent_session_hash") or "")
            has_valid_sess_cookie = bool(exp_sess_hash and inc_sess_hash and hmac.compare_digest(inc_sess_hash, exp_sess_hash))

            raw_auth_mode = str(form.get("auth_mode") or "").strip().lower()
            raw_decision = str(form.get("decision") or "").strip().lower()
            raw_pw = str(form.get("password") or "")
            raw_pair_in = str(form.get("pair_code") or form.get("dynamic_code") or "")

            failure = ""
            if not pending or "csrf" not in pending:
                failure = "expired_or_legacy_transaction"
            elif not csrf or not hmac.compare_digest(csrf, str(pending["csrf"])):
                failure = "form_csrf_mismatch"
            elif raw_auth_mode == "local_bridge" and not _ow.is_verified_local_fast_approve():
                if not has_valid_sess_cookie:
                    failure = "consent_session_cookie_mismatch"
            elif not (hmac.compare_digest(csrf, cookie_csrf) or has_valid_sess_cookie):
                failure = "cookie_missing_or_mismatched"

            if failure:
                LOGGER.warning("consent rejected: %s", failure)
                detail = (
                    "这张授权页已过期或已经提交。请从客户端连接设置重新发起连接。"
                    if failure == "expired_or_legacy_transaction"
                    else "授权会话校验失败。请在同一浏览器中重新连接，并允许本站使用 Cookie。"
                )
                return self.consent_message(request, "invalid_consent", failure, detail, 403, headers)

            allowed_origins = self._allowed_consent_origins(request)
            raw_origin_hdr = str(request.headers.get("origin") or "").strip()
            req_origin = _ow.extract_origin_scheme_netloc(raw_origin_hdr)
            raw_referer_hdr = str(request.headers.get("referer") or "").strip()
            req_referer_origin = _ow.extract_origin_scheme_netloc(raw_referer_hdr)
            sec_fetch_site = str(request.headers.get("sec-fetch-site") or "").strip().lower()

            has_foreign_origin = bool(
                raw_origin_hdr
                and raw_origin_hdr.lower() != "null"
                and (not req_origin or req_origin not in allowed_origins)
            )
            has_foreign_referer = bool(
                raw_referer_hdr
                and raw_referer_hdr.lower() != "null"
                and (not req_referer_origin or req_referer_origin not in allowed_origins)
            )
            if has_foreign_origin or has_foreign_referer or sec_fetch_site == "cross-site":
                LOGGER.warning(
                    "consent POST rejected due to cross-site origin/referer: origin=%r referer=%r sec_fetch_site=%r allowed=%r",
                    raw_origin_hdr,
                    raw_referer_hdr,
                    sec_fetch_site,
                    sorted(allowed_origins),
                )
                return self.consent_message(
                    request,
                    "invalid_consent",
                    "origin_mismatch",
                    "授权请求来源域名校验失败，请从绑定的官方连接地址重新发起。",
                    403,
                    headers,
                )

            if raw_decision == "deny" or raw_auth_mode == "deny":
                self.store.consume("consent", ticket)
                self.store.consume("consent_sess", f"consent_sess:{ticket}")
                self.store.consume("consent_sess", ticket)
                params = AuthorizationParams.model_validate(pending["params"])
                deny_iss = str(pending.get("gateway_issuer") or active_gw.issuer)
                return RedirectResponse(
                    construct_redirect_uri(str(params.redirect_uri), error="access_denied", state=params.state, iss=deny_iss),
                    status_code=302,
                    headers=headers,
                )

            raw_grant_scope = str(form.get("grant_scope") or form.get("access_mode") or "").strip().lower()
            want_readonly = raw_grant_scope == "readonly" or parse_bool_flag(form.get("readonly_only"), default=False)
            raw_ttl = str(form.get("session_ttl") or form.get("session_duration") or "30d").strip().lower()
            is_temp_2h = raw_ttl in ("2h", "7200", "temp", "temporary")
            sel_scope_str = "readonly" if want_readonly else "default"
            sel_ttl_str = "2h" if is_temp_2h else "30d"
            has_typed_creds = bool(raw_pw.strip() or raw_pair_in.strip())

            async def _rerender_pair_code_prompt(banner_msg: str) -> HTMLResponse:
                tkt_exp_fb = float(pending.get("expires_at") or (time.time() + 600))
                pending["selected_scope"] = sel_scope_str
                pending["selected_ttl"] = sel_ttl_str
                self.store.put("consent", ticket, pending, tkt_exp_fb)
                client_fb = await self.get_client(str(pending["client_id"]))
                nonce_fb = secrets.token_urlsafe(16)
                fb_page_headers = {
                    **headers,
                    "Referrer-Policy": "same-origin",
                    "Content-Security-Policy": f"{base_csp}; script-src 'nonce-{nonce_fb}'",
                }
                page_fb = self._render_consent_html(
                    client_name=(client_fb.client_name if client_fb else "") or "AI 客户端",
                    consent_path=consent_path,
                    ticket=ticket,
                    csrf=csrf,
                    nonce=nonce_fb,
                    pair_code=str(pending.get("pair_code") or derive_consent_pair_code(ticket)),
                    error_banner=banner_msg,
                    is_readonly_resource=is_readonly_resource_url(eff_res_p),
                    selected_scope=sel_scope_str,
                    selected_ttl=sel_ttl_str,
                )
                return HTMLResponse(page_fb, status_code=200, headers=fb_page_headers)

            # Step 2: Public `POST /consent` `auth_mode="local_bridge"` -> top-level `302` to `http://127.0.0.1:{local_port}/oauth/local-bridge`
            if raw_auth_mode == "local_bridge" and not _ow.is_verified_local_fast_approve() and not has_typed_creds:
                if _ow.is_current_request_remote_hub():
                    if "text/html" in (request.headers.get("accept") or "").lower():
                        return await _rerender_pair_code_prompt(
                            "当前为云服务器主站模式，请在下方输入本地 Studio 面板上的 6 位动态配对码或 20 位连接口令完成验证"
                        )
                    return JSONResponse(
                        {"error": "invalid_consent", "reason": "remote_hub_requires_pair_code"},
                        status_code=403,
                        headers=headers,
                    )
                if not req_origin or req_origin not in allowed_origins:
                    LOGGER.warning("local_bridge fallback/rejected due to missing Origin: %r not in %r", req_origin, sorted(allowed_origins))
                    if "text/html" in (request.headers.get("accept") or "").lower():
                        return await _rerender_pair_code_prompt(
                            "检测到浏览器隐私设置隐藏了来源头（Origin），无法使用免密回环快捷通道，请在下方输入 6 位动态配对码或连接口令完成确认"
                        )
                    return self.consent_message(
                        request,
                        "invalid_consent",
                        "origin_mismatch",
                        "本机桥接来源域名校验失败，请从绑定的官方连接地址重新发起。",
                        403,
                        headers,
                    )
                params_lb = AuthorizationParams.model_validate(pending["params"])
                tkt_exp_lb = float(pending.get("expires_at") or (time.time() + 600))
                pending["selected_scope"] = sel_scope_str
                pending["selected_ttl"] = sel_ttl_str
                self.store.put("consent", ticket, pending, tkt_exp_lb)

                pub_complete_url = self._public_complete_url(request, pending)
                bridge_nonce = _ow.mint_signed_local_bridge_token(
                    self._bridge_hmac_secret(),
                    kind="nonce",
                    ticket=ticket,
                    oauth_state=str(params_lb.state or ""),
                    client_id=str(pending["client_id"]),
                    redirect_uri=str(params_lb.redirect_uri),
                )
                self.store.put(
                    "local_bridge_nonce",
                    bridge_nonce,
                    {
                        "ticket": ticket,
                        "public_complete_url": pub_complete_url,
                        "gateway_base_url": active_gw.base_url,
                        "grant_scope": sel_scope_str,
                        "session_ttl": sel_ttl_str,
                        "consent_session_hash": exp_sess_hash,
                        "client_id": str(pending["client_id"]),
                        "oauth_state": str(params_lb.state or ""),
                        "redirect_uri": str(params_lb.redirect_uri),
                    },
                    time.time() + _ow.LOCAL_BRIDGE_TTL_SEC,
                )
                local_bridge_url = (
                    f"http://127.0.0.1:{int(self.local_port)}/oauth/local-bridge?"
                    + urlencode({"ticket": ticket, "nonce": bridge_nonce})
                )
                return RedirectResponse(local_bridge_url, status_code=302, headers=headers)

            eff_decision = (
                "approve"
                if (
                    raw_auth_mode in ("password", "pair_code", "dynamic_code", "local_bridge")
                    or (not raw_decision and has_typed_creds)
                )
                else raw_decision
            )
            if eff_decision != "approve":
                self.store.consume("consent", ticket)
                self.store.consume("consent_sess", f"consent_sess:{ticket}")
                self.store.consume("consent_sess", ticket)
                params = AuthorizationParams.model_validate(pending["params"])
                deny_iss_2 = str(pending.get("gateway_issuer") or active_gw.issuer)
                return RedirectResponse(
                    construct_redirect_uri(str(params.redirect_uri), error="access_denied", state=params.state, iss=deny_iss_2),
                    status_code=302,
                    headers=headers,
                )

            if not req_origin and not _ow.is_verified_local_fast_approve() and not has_typed_creds:
                if "text/html" in (request.headers.get("accept") or "").lower():
                    return await _rerender_pair_code_prompt(
                        "检测到浏览器隐私设置隐藏了来源头（Origin），请在下方输入 6 位动态配对码或连接口令完成确认"
                    )

            expected_pair_code = str(pending.get("pair_code") or derive_consent_pair_code(ticket)).strip().upper()
            compact_pair_in = re.sub(r"[\s-]+", "", raw_pair_in)
            compact_pw_in = re.sub(r"[\s-]+", "", raw_pw)

            glob_locked_pre, glob_wait_pre = self.store.check_global_auth_lockout()
            if glob_locked_pre:
                payload_glob = {
                    "error": "rate_limited",
                    "reason": "global_auth_cooldown",
                    "retry_after": glob_wait_pre,
                }
                if "text/html" not in (request.headers.get("accept") or "").lower():
                    return JSONResponse(payload_glob, status_code=429, headers=headers)
                return HTMLResponse(
                    f"<h1>请求过于频繁</h1><p>口令或配对码连续输错次数过多，请等待 {glob_wait_pre} 秒后重试。</p>",
                    status_code=429,
                    headers=headers,
                )

            # Support 6-digit Studio dynamic pairing code (`pair_code` / `dynamic_code` / 6-digit `password`) OR 20-char owner password
            authed_ok = False
            auth_err_msg = ""
            if raw_auth_mode in ("pair_code", "dynamic_code") or (compact_pair_in and len(compact_pair_in) == 6 and compact_pair_in.isdigit()):
                cand_6 = compact_pair_in or compact_pw_in
                if self.verify_dynamic_code(cand_6):
                    authed_ok = True
                elif not compact_pair_in and raw_pw.strip() and self.authenticate_owner(raw_pw):
                    authed_ok = True
                else:
                    auth_err_msg = "6 位动态配对码不正确或已刷新"
            else:
                if (
                    compact_pair_in
                    and expected_pair_code
                    and expected_pair_code != "----"
                    and not hmac.compare_digest(compact_pair_in.upper(), expected_pair_code)
                ):
                    if "text/html" not in (request.headers.get("accept") or "").lower():
                        return JSONResponse({"error": "pair_code_mismatch"}, status_code=403, headers=headers)
                    client = await self.get_client(str(pending["client_id"]))
                    nonce = secrets.token_urlsafe(16)
                    page_headers = {
                        **headers,
                        "Referrer-Policy": "same-origin",
                        "Content-Security-Policy": f"{base_csp}; script-src 'nonce-{nonce}'",
                    }
                    page = self._render_consent_html(
                        client_name=(client.client_name if client else "") or "AI 客户端",
                        consent_path=consent_path,
                        ticket=ticket,
                        csrf=csrf,
                        nonce=nonce,
                        pair_code=expected_pair_code,
                        error_banner="4 位核对码与当前授权请求不一致，请重新查看 Studio 面板中的实时核对码",
                        is_readonly_resource=is_readonly_resource_url(eff_res_p),
                        selected_scope=sel_scope_str,
                        selected_ttl=sel_ttl_str,
                    )
                    return HTMLResponse(page, status_code=403, headers=page_headers)

                if self.authenticate_owner(raw_pw) or (
                    len(compact_pw_in) == 6 and compact_pw_in.isdigit() and self.verify_dynamic_code(compact_pw_in)
                ):
                    authed_ok = True
                else:
                    auth_err_msg = "连接口令不正确"

            if not authed_ok:
                max_ticket_attempts = 3
                if has_trusted_ip:
                    now_locked, lockout_rem = self.store.record_auth_result(
                        False,
                        bucket_key=ip_bucket,
                        max_failures=self.max_auth_failures,
                    )
                else:
                    now_locked, lockout_rem = False, 0
                glob_now_locked, glob_rem = self.store.record_global_auth_result(
                    False,
                    max_failures=8,
                    window_sec=30,
                    lockout_sec=60,
                )
                attempts = int(pending.get("attempts") or 0) + 1
                pending["attempts"] = attempts
                pending["selected_scope"] = sel_scope_str
                pending["selected_ttl"] = sel_ttl_str
                tkt_exp_f = float(pending.get("expires_at") or (time.time() + 600))
                ticket_invalidated = bool(attempts >= max_ticket_attempts or now_locked or glob_now_locked)
                if ticket_invalidated:
                    self.store.consume("consent", ticket)
                    self.store.consume("consent_sess", f"consent_sess:{ticket}")
                    self.store.consume("consent_sess", ticket)
                else:
                    self.store.put("consent", ticket, pending, tkt_exp_f)
                if now_locked or glob_now_locked:
                    eff_wait = max(int(lockout_rem or 0), int(glob_rem or 0), 1)
                    return JSONResponse(
                        {
                            "error": "rate_limited",
                            "reason": "global_auth_cooldown" if glob_now_locked else "ip_password_lockout",
                            "retry_after": eff_wait,
                            "ticket_invalidated": True,
                        },
                        status_code=429,
                        headers=headers,
                    )
                err_code = "invalid_pair_code" if raw_auth_mode in ("pair_code", "dynamic_code") else "invalid_password"
                if "text/html" not in (request.headers.get("accept") or "").lower() or attempts >= max_ticket_attempts:
                    return JSONResponse(
                        {"error": err_code, "ticket_invalidated": attempts >= max_ticket_attempts, "attempts": attempts},
                        status_code=403,
                        headers=headers,
                    )
                client = await self.get_client(str(pending["client_id"]))
                nonce = secrets.token_urlsafe(16)
                page_headers = {
                    **headers,
                    "Referrer-Policy": "same-origin",
                    "Content-Security-Policy": f"{base_csp}; script-src 'nonce-{nonce}'",
                }
                page = self._render_consent_html(
                    client_name=(client.client_name if client else "") or "AI 客户端",
                    consent_path=consent_path,
                    ticket=ticket,
                    csrf=csrf,
                    nonce=nonce,
                    pair_code=str(pending.get("pair_code") or derive_consent_pair_code(ticket)),
                    error_banner=f"{auth_err_msg}（剩余 {max(0, max_ticket_attempts - attempts)} 次尝试）",
                    is_readonly_resource=is_readonly_resource_url(eff_res_p),
                    selected_scope=sel_scope_str,
                    selected_ttl=sel_ttl_str,
                )
                return HTMLResponse(page, status_code=403, headers=page_headers)

            if has_trusted_ip:
                self.store.record_auth_result(True, bucket_key=ip_bucket, max_failures=self.max_auth_failures)
            self.store.record_global_auth_result(True)
            return self._approve_pending_consent(
                request,
                ticket=ticket,
                pending=pending,
                want_readonly=want_readonly,
                is_temp_2h=is_temp_2h,
                headers=headers,
                is_https_req=is_https_req,
                form=form,
            )
        finally:
            _ow._REMOTE_HUB_REQ_VAR.reset(tok_rem)
            _ow._MOBILE_UA_REQ_VAR.reset(tok_mob)

    async def local_bridge(
        self,
        request: Request,
        *,
        expected_port: Optional[int] = None,
    ) -> RedirectResponse | HTMLResponse | JSONResponse:
        """Step 3a: Strict triple-loopback `GET /oauth/local-bridge` -> consume `nonce` -> mint `local_proof` -> `302` to `/consent/complete`."""
        from cosmos_mcp.protocol import oauth_web as _ow

        headers = {
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
            "Referrer-Policy": "no-referrer",
        }
        eff_port = int(expected_port) if (expected_port is not None and int(expected_port) > 0) else int(self.local_port)
        if not _ow.is_pure_local_consent_request(request, expected_port=eff_port):
            accept_hdr = (request.headers.get("accept") or "").lower()
            if "text/html" in accept_hdr:
                fb_ticket = str(request.query_params.get("ticket") or "").strip()
                fb_nonce = str(request.query_params.get("nonce") or "").strip()
                if fb_ticket and fb_nonce:
                    fb_nonce_doc = self.store.consume("local_bridge_nonce", fb_nonce)
                    fb_pending = self.store.get("consent", fb_ticket) if isinstance(fb_nonce_doc, dict) else None
                    if (
                        isinstance(fb_nonce_doc, dict)
                        and hmac.compare_digest(str(fb_nonce_doc.get("ticket") or ""), fb_ticket)
                        and isinstance(fb_pending, dict)
                        and "params" in fb_pending
                    ):
                        fb_params = AuthorizationParams.model_validate(fb_pending["params"])
                        fb_verified = _ow.verify_signed_local_bridge_token(
                            self._bridge_hmac_secret(),
                            fb_nonce,
                            expected_kind="nonce",
                            expected_ticket=fb_ticket,
                            expected_oauth_state=str(fb_params.state or ""),
                            expected_client_id=str(fb_pending["client_id"]),
                            expected_redirect_uri=str(fb_params.redirect_uri),
                        )
                        pub_complete = str(fb_nonce_doc.get("public_complete_url") or "").strip()
                        pub_origin = _ow.extract_origin_scheme_netloc(pub_complete)
                        u_pub = urlsplit(pub_complete)
                        pub_path = (u_pub.path or "").rstrip("/")
                        if (
                            fb_verified is not None
                            and pub_complete
                            and pub_origin
                            and pub_origin in self._allowed_consent_origins()
                            and pub_path.endswith("/consent/complete")
                        ):
                            fb_consent_path = pub_path[: -len("/consent/complete")] + "/consent"
                            fb_consent_base = urlunsplit((u_pub.scheme, u_pub.netloc, fb_consent_path, u_pub.query, ""))
                            fallback_consent_url = construct_redirect_uri(
                                fb_consent_base,
                                ticket=fb_ticket,
                                bridge_fallback="1",
                            )
                            LOGGER.info(
                                "proxied browser navigation to /oauth/local-bridge detected; redirecting back to %s",
                                fb_consent_path,
                            )
                            return RedirectResponse(fallback_consent_url, status_code=302, headers=headers)
            LOGGER.warning("blocked non-pure-local request to /oauth/local-bridge")
            return JSONResponse(
                {"error": "forbidden_non_loopback", "reason": "pure_local_loopback_required"},
                status_code=403,
                headers=headers,
            )

        ticket = str(request.query_params.get("ticket") or "").strip()
        nonce = str(request.query_params.get("nonce") or "").strip()
        if not ticket or not nonce:
            return self.consent_message(
                request,
                "invalid_bridge_request",
                "missing_bridge_parameters",
                "缺少本机回环校验参数，请重新发起连接。",
                403,
                headers,
            )

        nonce_doc = self.store.consume("local_bridge_nonce", nonce)
        if not isinstance(nonce_doc, dict) or not hmac.compare_digest(str(nonce_doc.get("ticket") or ""), ticket):
            return self.consent_message(
                request,
                "invalid_bridge_nonce",
                "nonce_invalid_or_replayed",
                "本机单次桥接挑战已过期或已被使用，请重新发起连接。",
                403,
                headers,
            )

        pending = self.store.get("consent", ticket)
        if not isinstance(pending, dict) or "params" not in pending:
            completed = self.store.get("consent_result", ticket) if ticket else None
            if isinstance(completed, dict) and completed.get("consent_session_hash"):
                comp_cid = str(completed.get("client_id") or "")
                comp_state = str(completed.get("oauth_state") or "")
                comp_redir = str(completed.get("redirect_uri") or "")
                verified_done_nonce = _ow.verify_signed_local_bridge_token(
                    self._bridge_hmac_secret(),
                    nonce,
                    expected_kind="nonce",
                    expected_ticket=ticket,
                    expected_oauth_state=comp_state if "oauth_state" in completed else None,
                    expected_client_id=comp_cid,
                    expected_redirect_uri=comp_redir,
                )
                pub_complete_done = str(nonce_doc.get("public_complete_url") or "").strip()
                pub_origin_done = _ow.extract_origin_scheme_netloc(pub_complete_done)
                if (
                    verified_done_nonce is not None
                    and pub_complete_done
                    and pub_origin_done
                    and pub_origin_done in self._allowed_consent_origins()
                ):
                    done_proof = _ow.mint_signed_local_bridge_token(
                        self._bridge_hmac_secret(),
                        kind="proof",
                        ticket=ticket,
                        oauth_state=comp_state,
                        client_id=comp_cid,
                        redirect_uri=comp_redir,
                    )
                    done_target = construct_redirect_uri(pub_complete_done, ticket=ticket, proof=done_proof)
                    return RedirectResponse(done_target, status_code=302, headers=headers)
            return self.consent_message(
                request,
                "expired_consent",
                "ticket_expired",
                "授权请求已过期，请从客户端重新发起连接。",
                403,
                headers,
            )

        params = AuthorizationParams.model_validate(pending["params"])
        verified_claims = _ow.verify_signed_local_bridge_token(
            self._bridge_hmac_secret(),
            nonce,
            expected_kind="nonce",
            expected_ticket=ticket,
            expected_oauth_state=str(params.state or ""),
            expected_client_id=str(pending["client_id"]),
            expected_redirect_uri=str(params.redirect_uri),
        )
        if verified_claims is None:
            return self.consent_message(
                request,
                "invalid_bridge_signature",
                "bridge_hmac_verification_failed",
                "本机桥接签名核验未通过，请重新发起连接。",
                403,
                headers,
            )

        pub_complete = str(nonce_doc.get("public_complete_url") or "").strip()
        pub_origin = _ow.extract_origin_scheme_netloc(pub_complete)
        if not pub_complete or not pub_origin or pub_origin not in self._allowed_consent_origins():
            return self.consent_message(
                request,
                "invalid_bridge_target",
                "untrusted_complete_url",
                "回跳目标地址不在受信任网关列表内。",
                403,
                headers,
            )

        local_proof = _ow.mint_signed_local_bridge_token(
            self._bridge_hmac_secret(),
            kind="proof",
            ticket=ticket,
            oauth_state=str(params.state or ""),
            client_id=str(pending["client_id"]),
            redirect_uri=str(params.redirect_uri),
        )
        self.store.put(
            "local_bridge_proof",
            local_proof,
            {
                "ticket": ticket,
                "grant_scope": str(nonce_doc.get("grant_scope") or "default"),
                "session_ttl": str(nonce_doc.get("session_ttl") or "30d"),
                "consent_session_hash": str(nonce_doc.get("consent_session_hash") or ""),
                "client_id": str(pending["client_id"]),
                "oauth_state": str(params.state or ""),
                "redirect_uri": str(params.redirect_uri),
            },
            time.time() + _ow.LOCAL_BRIDGE_TTL_SEC,
        )
        complete_target = construct_redirect_uri(pub_complete, ticket=ticket, proof=local_proof)
        return RedirectResponse(complete_target, status_code=302, headers=headers)

    async def consent_complete(self, request: Request) -> RedirectResponse | HTMLResponse | JSONResponse:
        """Step 3b: Verify browser consent session cookie + single-use HMAC `local_proof` -> issue OAuth `code` -> `302`."""
        from cosmos_mcp.protocol import oauth_web as _ow

        headers = {
            "Cache-Control": "no-store",
            "Content-Security-Policy": self._build_consent_csp(),
            "Referrer-Policy": "no-referrer",
        }
        ticket = str(request.query_params.get("ticket") or "").strip()
        proof = str(request.query_params.get("proof") or "").strip()
        proof_doc = self.store.consume("local_bridge_proof", proof) if proof else None
        pending = self.store.get("consent", ticket) if ticket else None

        if not isinstance(pending, dict) or "params" not in pending:
            completed = self.store.get("consent_result", ticket) if ticket else None
            if isinstance(completed, dict) and ticket and proof:
                verified_done = _ow.verify_signed_local_bridge_token(
                    self._bridge_hmac_secret(),
                    proof,
                    expected_kind="proof",
                    expected_ticket=ticket,
                    expected_oauth_state=str(completed.get("oauth_state") or "") if "oauth_state" in completed else None,
                    expected_client_id=str(completed.get("client_id") or ""),
                    expected_redirect_uri=str(completed.get("redirect_uri") or ""),
                )
                if verified_done is not None:
                    raw_sess_cookie = _ow.read_consent_session_cookie(request)
                    inc_sess_hash = _ow.hash_consent_session_token(raw_sess_cookie)
                    comp_sess_hash = str(completed.get("consent_session_hash") or "").strip()
                    if (
                        comp_sess_hash
                        and inc_sess_hash
                        and hmac.compare_digest(inc_sess_hash, comp_sess_hash)
                    ):
                        return self._completed_consent_response(request, completed, headers)
                    LOGGER.warning("consent_complete retry rejected: consent session cookie missing or mismatched")
                    return self.consent_message(
                        request,
                        "invalid_consent_session",
                        "consent_session_cookie_mismatch",
                        "当前浏览器的授权会话与发起页面不一致，已拒绝代授权请求。",
                        403,
                        headers,
                    )

        if (
            not ticket
            or not proof
            or not isinstance(proof_doc, dict)
            or not hmac.compare_digest(str(proof_doc.get("ticket") or ""), ticket)
        ):
            return self.consent_message(
                request,
                "invalid_bridge_proof",
                "proof_invalid_or_replayed",
                "单次本机确认凭证无效或已被使用，请重新发起连接。",
                403,
                headers,
            )

        if not isinstance(pending, dict) or "params" not in pending:
            return self.consent_message(
                request,
                "expired_consent",
                "ticket_expired",
                "授权请求已过期或已完成，请从客户端查看连接状态。",
                403,
                headers,
            )

        eff_res = str(
            pending.get("effective_resource")
            or (pending.get("params") or {}).get("resource")
            or ""
        ).strip().rstrip("/")
        if eff_res and eff_res not in self.allowed_resources:
            return JSONResponse(
                {"error": "forbidden_cross_resource", "reason": "resource_mismatch"},
                status_code=403,
                headers=headers,
            )

        params = AuthorizationParams.model_validate(pending["params"])
        headers["Content-Security-Policy"] = self._build_consent_csp(str(params.redirect_uri))
        verified_claims = _ow.verify_signed_local_bridge_token(
            self._bridge_hmac_secret(),
            proof,
            expected_kind="proof",
            expected_ticket=ticket,
            expected_oauth_state=str(params.state or ""),
            expected_client_id=str(pending["client_id"]),
            expected_redirect_uri=str(params.redirect_uri),
        )
        if verified_claims is None:
            return self.consent_message(
                request,
                "invalid_bridge_signature",
                "proof_hmac_verification_failed",
                "本机确认凭证签名校验失败，请重新发起连接。",
                403,
                headers,
            )

        # Dual Check #1: Browser session cookie hash MUST match Step 1 `consent_session_hash` (blocks Consent CSRF!)
        raw_sess_cookie = _ow.read_consent_session_cookie(request)
        inc_sess_hash = _ow.hash_consent_session_token(raw_sess_cookie)
        sess_rec = self.store.get("consent_sess", f"consent_sess:{ticket}") or self.store.get("consent_sess", ticket) or {}
        exp_sess_hash = str(pending.get("consent_session_hash") or sess_rec.get("consent_session_hash") or "")
        proof_sess_hash = str(proof_doc.get("consent_session_hash") or "")
        if (
            not exp_sess_hash
            or not proof_sess_hash
            or not inc_sess_hash
            or not hmac.compare_digest(inc_sess_hash, exp_sess_hash)
            or not hmac.compare_digest(inc_sess_hash, proof_sess_hash)
        ):
            LOGGER.warning("consent_complete rejected: consent session cookie missing or mismatched (Consent CSRF blocked)")
            return self.consent_message(
                request,
                "invalid_consent_session",
                "consent_session_cookie_mismatch",
                "当前浏览器的授权会话与发起页面不一致，已拒绝代授权请求。",
                403,
                headers,
            )

        want_readonly = str(proof_doc.get("grant_scope") or "").strip().lower() == "readonly"
        is_temp_2h = str(proof_doc.get("session_ttl") or "").strip().lower() in ("2h", "7200", "temp", "temporary")
        is_https_req = _ow.is_https_consent_request(request)
        return self._approve_pending_consent(
            request,
            ticket=ticket,
            pending=pending,
            want_readonly=want_readonly,
            is_temp_2h=is_temp_2h,
            headers=headers,
            is_https_req=is_https_req,
            form=None,
        )

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> Optional[AuthorizationCode]:
        _ = client
        record = self.store.get("code", authorization_code)
        return AuthorizationCode.model_validate(record) if record else None

    def issue_tokens(
        self,
        client_id: str,
        scopes: List[str],
        resource: Optional[str],
        subject: str = "owner",
        *,
        temporary_session: bool = False,
        session_ttl_sec: Optional[int] = None,
    ) -> OAuthToken:
        now = int(time.time())
        try:
            self.store.prune_expired()
        except Exception:
            pass
        eff_scopes = narrow_scopes_for_resource(scopes, resource)
        if temporary_session or (session_ttl_sec is not None and int(session_ttl_sec) > 0):
            ttl = max(60, int(session_ttl_sec or TEMPORARY_SESSION_TTL_SEC))
            access_exp = now + ttl
            refresh_exp = now + ttl
            expires_in = ttl
            is_temp = True
            max_exp: Optional[int] = refresh_exp
        else:
            access_exp = now + 93600
            refresh_exp = now + 30 * 86400
            expires_in = 86400
            is_temp = False
            max_exp = None

        access = AccessToken(
            token=secrets.token_urlsafe(32),
            client_id=client_id,
            scopes=eff_scopes,
            expires_at=access_exp,
            resource=resource,
            subject=subject,
        )
        refresh = RefreshToken(
            token=secrets.token_urlsafe(32),
            client_id=client_id,
            scopes=eff_scopes,
            expires_at=refresh_exp,
            resource=resource,
            subject=subject,
        )
        access_doc = {
            **access.model_dump(mode="json"),
            "temporary_session": is_temp,
            "max_expires_at": max_exp,
        }
        refresh_doc = {
            **refresh.model_dump(mode="json"),
            "temporary_session": is_temp,
            "max_expires_at": max_exp,
        }
        self.store.put("access", access.token, access_doc, access.expires_at)
        self.store.put("refresh", refresh.token, refresh_doc, refresh.expires_at)
        self.store.extend_client_expiry(client_id, now + (ttl if is_temp else 365 * 86400))
        return OAuthToken(
            access_token=access.token,
            refresh_token=refresh.token,
            expires_in=expires_in,
            scope=" ".join(eff_scopes),
        )

    @staticmethod
    def _strip_mcp_resource_suffix(raw_url: str) -> Tuple[str, str, str]:
        u = urlsplit(str(raw_url or "").strip().rstrip("/"))
        scheme = (u.scheme or "").strip().lower()
        auth = _normalize_url_authority(raw_url)
        p = (u.path or "").rstrip("/")
        if p == "/mcp/readonly":
            p = ""
        elif p.endswith("/mcp/readonly"):
            p = p[: -len("/mcp/readonly")]
        elif p == "/mcp":
            p = ""
        elif p.endswith("/mcp"):
            p = p[: -len("/mcp")]
        return scheme, auth, p.lower()

    def _same_gateway_slot_alias(
        self,
        scheme_a: str,
        auth_a: str,
        pfx_a: str,
        scheme_b: str,
        auth_b: str,
        pfx_b: str,
    ) -> bool:
        if scheme_a == scheme_b and auth_a == auth_b and pfx_a == pfx_b:
            return True
        if pfx_a != pfx_b:
            ep_sec = self.get_active_endpoint_secret()
            if ep_sec and scheme_a == scheme_b and auth_a == auth_b:
                sec_pfx = f"/u/{ep_sec}"
                if (pfx_a == "" and pfx_b == sec_pfx) or (pfx_b == "" and pfx_a == sec_pfx):
                    return True
            return False
        eff_map = self.get_effective_trusted_gateways()
        ep_a = eff_map.get((auth_a, pfx_a)) or eff_map.get((auth_a, ""))
        ep_b = eff_map.get((auth_b, pfx_b)) or eff_map.get((auth_b, ""))
        if ep_a is not None and ep_b is not None:
            gid_a = str(getattr(ep_a, "gateway_id", "") or "").strip()
            gid_b = str(getattr(ep_b, "gateway_id", "") or "").strip()
            if gid_a and gid_a == gid_b and gid_a not in ("default", "grace"):
                return True
        return False

    def mint_personal_access_token(
        self,
        *,
        label: str = "",
        readonly: bool = True,
        ttl_days: int = 30,
    ) -> Dict[str, Any]:
        """Mint a revocable Sites/CLI personal access token backed by `OAuthSQLiteStore`."""
        return self.store.mint_personal_access_token(
            label=label,
            readonly=readonly,
            ttl_days=ttl_days,
        )

    def get_or_mint_oneclick_capability_token(
        self,
        *,
        readonly: bool = False,
        rotate: bool = False,
        ttl_days: int = 90,
    ) -> Dict[str, Any]:
        """Get or mint a revocable high-entropy ChatGPT one-click capability token backed by `OAuthSQLiteStore`."""
        return self.store.get_or_mint_oneclick_capability_token(
            readonly=readonly,
            rotate=rotate,
            ttl_days=ttl_days,
        )

    def revoke_oneclick_tokens(self, *, readonly: Optional[bool] = None) -> Dict[str, Any]:
        """Revoke all ChatGPT one-click capability tokens backed by `OAuthSQLiteStore`."""
        return self.store.revoke_oneclick_tokens(readonly=readonly)

    def is_token_resource_valid_for_current_request(self, tok_res: Optional[str]) -> bool:
        if not tok_res:
            return False
        norm_tok = str(tok_res).strip().rstrip("/")
        if norm_tok in (PAT_FULL_RESOURCE, PAT_READONLY_RESOURCE):
            req_gw = _REQUEST_GATEWAY_VAR.get()
            if req_gw is None or req_gw.is_loopback:
                return True
            eff_map = self.get_effective_trusted_gateways()
            req_pfx = (req_gw.public_prefix or "").lower()
            return (
                (req_gw.authority, req_pfx) in eff_map
                or (req_gw.authority, "") in eff_map
                or any(m_auth == req_gw.authority for (m_auth, _) in eff_map)
            )
        if norm_tok not in self.allowed_resources:
            return False
        req_gw = _REQUEST_GATEWAY_VAR.get()
        if req_gw is None or req_gw.is_loopback:
            return True
        t_scheme, t_auth, t_pfx = self._strip_mcp_resource_suffix(norm_tok)
        _, h_only, _ = _normalize_host_authority(t_auth, default_scheme=t_scheme or "https")
        if h_only in _LOOPBACK_HOSTNAMES:
            return False
        return self._same_gateway_slot_alias(
            t_scheme,
            t_auth,
            t_pfx,
            req_gw.scheme,
            req_gw.authority,
            req_gw.public_prefix.lower(),
        )

    def _resolve_validated_token_resource(
        self,
        bound_resource: Optional[str],
        *,
        force_readonly: bool = False,
    ) -> Optional[str]:
        """Validate explicit `POST /token` `resource` (RFC 8707): allowlist, zero cross-gateway switch, zero readonly->full escalation."""
        raw_req_res = _REQUEST_TOKEN_RESOURCE_VAR.get()
        if raw_req_res is None:
            if not bound_resource:
                return None
            bnd_clean = str(bound_resource).strip().rstrip("/")
            if self.allowed_resources and bnd_clean not in self.allowed_resources:
                raise TokenError("invalid_grant", "Gateway for this refresh token is currently disabled")
            req_gw = _REQUEST_GATEWAY_VAR.get()
            if req_gw is not None and not req_gw.is_loopback:
                b_sc, b_au, b_px = self._strip_mcp_resource_suffix(bnd_clean)
                _, b_host, _ = _normalize_host_authority(b_au, default_scheme=b_sc or "https")
                if b_host not in _LOOPBACK_HOSTNAMES and not self._same_gateway_slot_alias(
                    b_sc, b_au, b_px, req_gw.scheme, req_gw.authority, req_gw.public_prefix.lower()
                ):
                    raise TokenError("invalid_grant", "Refresh token belongs to a different gateway")
            return bnd_clean
        req_res = str(raw_req_res).strip().rstrip("/")
        if not req_res or not req_res.startswith(("http://", "https://")) or req_res not in self.allowed_resources:
            raise TokenError("invalid_request", "Untrusted or unknown token resource indicator")

        req_scheme, req_auth, req_pfx = self._strip_mcp_resource_suffix(req_res)
        req_is_ro = is_readonly_resource_url(req_res)

        if bound_resource:
            bnd_norm = str(bound_resource).strip().rstrip("/")
            bnd_scheme, bnd_auth, bnd_pfx = self._strip_mcp_resource_suffix(bnd_norm)
            if not self._same_gateway_slot_alias(bnd_scheme, bnd_auth, bnd_pfx, req_scheme, req_auth, req_pfx):
                raise TokenError("invalid_request", "Cross-gateway token resource switch is forbidden")
            bnd_is_ro = bool(force_readonly or is_readonly_resource_url(bnd_norm))
            if bnd_is_ro and not req_is_ro:
                raise TokenError("invalid_request", "Readonly grant cannot escalate to full /mcp resource")
            return req_res

        gw = _REQUEST_GATEWAY_VAR.get()
        if gw is not None and not gw.is_loopback and req_auth != gw.authority:
            raise TokenError("invalid_request", "Token resource authority does not match active gateway")
        if force_readonly and not req_is_ro:
            raise TokenError("invalid_request", "Readonly grant cannot escalate to full /mcp resource")
        return req_res

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        peek_doc = self.store.get("code", authorization_code.code)
        if not peek_doc:
            raise TokenError("invalid_grant", "Authorization code already used or expired")
        bound_res = str(authorization_code.resource) if authorization_code.resource else None
        force_ro = bool(peek_doc.get("grant_readonly"))
        eff_res_str = self._resolve_validated_token_resource(bound_res, force_readonly=force_ro)

        consumed_doc = self.store.consume("code", authorization_code.code)
        if not consumed_doc:
            raise TokenError("invalid_grant", "Authorization code already used or expired")
        is_temp = bool(consumed_doc.get("temporary_session"))
        raw_ttl = consumed_doc.get("session_ttl_sec")
        ttl_sec = int(raw_ttl) if isinstance(raw_ttl, (int, float)) and int(raw_ttl) > 0 else None
        eff_scopes = narrow_scopes_for_resource(
            list(authorization_code.scopes),
            eff_res_str,
            force_readonly=force_ro,
        )
        return self.issue_tokens(
            client.client_id,
            eff_scopes,
            eff_res_str,
            authorization_code.subject or "owner",
            temporary_session=is_temp,
            session_ttl_sec=ttl_sec,
        )

    async def load_refresh_token(
        self,
        client: Optional[OAuthClientInformationFull],
        refresh_token: str,
    ) -> Optional[RefreshToken]:
        record = self.store.get("refresh", refresh_token)
        if record is not None:
            record = {**record, "token": refresh_token}
        else:
            replay_record = self.store.get("refresh_replay", refresh_token)
            if replay_record:
                scopes = (
                    replay_record.get("base_scopes")
                    or replay_record.get("scopes")
                    or str(replay_record.get("scope", "")).split()
                    or ["server:read"]
                )
                base_res = (
                    replay_record.get("base_resource")
                    if "base_resource" in replay_record
                    else replay_record.get("resource")
                )
                record = {
                    "token": refresh_token,
                    "client_id": replay_record.get("client_id", client.client_id if client else ""),
                    "scopes": scopes,
                    "expires_at": int(time.time()) + max(300, self.refresh_replay_ttl),
                    "resource": base_res,
                    "subject": replay_record.get("subject", "owner"),
                }
            else:
                return None
        if client is not None and record.get("client_id") != client.client_id:
            orig_client = self.store.get("client", str(record.get("client_id", "")))
            if orig_client:
                orig_auth_method = str(orig_client.get("token_endpoint_auth_method") or "none").strip().lower()
                orig_is_confidential = bool(orig_client.get("client_secret")) or orig_auth_method != "none"
                curr_auth_method = str(getattr(client, "token_endpoint_auth_method", None) or "none").strip().lower()
                curr_is_public = curr_auth_method == "none" or not bool(getattr(client, "client_secret", None))
                if not (orig_is_confidential and curr_is_public):
                    orig_ids = _google_user_bound_ids(orig_client.get("redirect_uris") or [])
                    curr_ids = _google_user_bound_ids([str(u) for u in (client.redirect_uris or [])])
                    if orig_ids and orig_ids == curr_ids:
                        record = {**record, "client_id": client.client_id}
        return RefreshToken.model_validate(record)

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: List[str],
    ) -> OAuthToken:
        now = int(time.time())
        stored_rt = self.store.get("refresh", refresh_token.token) or self.store.get("refresh_replay", refresh_token.token) or {}
        is_temp = bool(stored_rt.get("temporary_session"))
        raw_max_exp = stored_rt.get("max_expires_at")
        max_exp = int(raw_max_exp) if isinstance(raw_max_exp, (int, float)) and int(raw_max_exp) > 0 else None
        if is_temp and max_exp is not None and max_exp <= now:
            raise TokenError("invalid_grant", "Temporary session has expired")

        rt_was_readonly = "workspace" not in (refresh_token.scopes or []) and "server:admin" not in (refresh_token.scopes or [])
        bound_rt_res = str(refresh_token.resource) if refresh_token.resource else None
        eff_access_res = self._resolve_validated_token_resource(bound_rt_res, force_readonly=rt_was_readonly)
        eff_scopes = narrow_scopes_for_resource(
            list(scopes or refresh_token.scopes or self.default_scopes),
            eff_access_res,
            force_readonly=rt_was_readonly,
        )
        rt_scopes = narrow_scopes_for_resource(
            list(refresh_token.scopes or self.default_scopes),
            bound_rt_res,
            force_readonly=rt_was_readonly,
        )
        if not set(eff_scopes).issubset(self.valid_scopes):
            raise TokenError("invalid_scope", "Requested scope exceeds authorized provider scopes")
        client_uris = [str(u) for u in (client.redirect_uris or [])] if client else []
        client_name = str(getattr(client, "client_name", "") or "")

        if is_temp:
            eff_cap = max_exp if max_exp is not None else (int(refresh_token.expires_at or (now + TEMPORARY_SESSION_TTL_SEC)))
            rem_sec = max(1, eff_cap - now)
            access_exp = eff_cap
            next_rt_exp = eff_cap
            expires_in = rem_sec
        else:
            access_exp = now + 93600
            next_rt_exp = now + 30 * 86400
            expires_in = 86400

        access = AccessToken(
            token=secrets.token_urlsafe(32),
            client_id=client.client_id,
            scopes=eff_scopes,
            expires_at=access_exp,
            resource=eff_access_res,
            subject=refresh_token.subject,
        )
        access_doc = {
            **access.model_dump(mode="json"),
            "temporary_session": is_temp,
            "max_expires_at": max_exp,
        }

        # Dual-Track 1: Google Gemini Connected Apps non-rotating extension (when enabled and not temporary)
        if not is_temp and self.non_rotating_google and is_google_gemini_client(client_name, client_uris):
            extended_rt = RefreshToken(
                token=refresh_token.token,
                client_id=client.client_id,
                scopes=rt_scopes,
                expires_at=next_rt_exp,
                resource=refresh_token.resource,
                subject=refresh_token.subject,
            )
            rt_doc = {
                **extended_rt.model_dump(mode="json"),
                "temporary_session": False,
                "max_expires_at": None,
            }
            ok = self.store.extend_refresh_non_rotating(
                refresh_token.token,
                rt_doc,
                extended_rt.expires_at,
                access.token,
                access_doc,
                access.expires_at,
            )
            if not ok:
                raise TokenError("invalid_grant", "Refresh token expired or revoked")
            return OAuthToken(
                access_token=access.token,
                refresh_token=refresh_token.token,
                expires_in=expires_in,
                scope=" ".join(eff_scopes),
            )

        # Dual-Track 2: Single-use atomic rotation + `refresh_replay` grace window
        new_refresh = RefreshToken(
            token=secrets.token_urlsafe(32),
            client_id=client.client_id,
            scopes=rt_scopes,
            expires_at=next_rt_exp,
            resource=refresh_token.resource,
            subject=refresh_token.subject,
        )
        new_rt_doc = {
            **new_refresh.model_dump(mode="json"),
            "temporary_session": is_temp,
            "max_expires_at": max_exp,
        }
        minted = OAuthToken(
            access_token=access.token,
            refresh_token=new_refresh.token,
            expires_in=expires_in,
            scope=" ".join(eff_scopes),
        )
        should_cache_replay = (
            is_persistent_connector_client(client_uris)
            if self.persistent_replay_only
            else (self.refresh_replay_ttl > 0)
        )
        replay_ttl = self.refresh_replay_ttl if should_cache_replay else 0
        if is_temp and max_exp is not None:
            replay_ttl = min(replay_ttl, max(1, max_exp - now)) if replay_ttl > 0 else 0
        writes: List[Tuple[str, str, Dict[str, Any], float]] = [
            ("access", access.token, access_doc, access.expires_at),
            ("refresh", new_refresh.token, new_rt_doc, new_refresh.expires_at),
        ]
        if replay_ttl > 0:
            replay_payload = {
                "token_type": "Bearer",
                "expires_in": expires_in,
                "scope": " ".join(eff_scopes),
                "wrapped_tokens": _wrap_replay_tokens(refresh_token.token, access.token, new_refresh.token),
                "client_id": client.client_id,
                "base_resource": str(refresh_token.resource) if refresh_token.resource else None,
                "base_scopes": list(rt_scopes),
                "issued_resource": eff_access_res,
                "issued_scopes": list(eff_scopes),
                "resource": eff_access_res,
                "subject": refresh_token.subject,
                "scopes": list(eff_scopes),
                "temporary_session": is_temp,
                "max_expires_at": max_exp,
            }
            writes.append(("refresh_replay", refresh_token.token, replay_payload, now + replay_ttl))
        success, cached_replay = self.store.exchange_refresh_atomic(
            refresh_token.token,
            client.client_id,
            writes,
            replay_ttl=replay_ttl,
        )
        if not success:
            raise TokenError("invalid_grant", "Refresh token already used or expired")
        if cached_replay:
            unwrapped = _unwrap_replay_tokens(refresh_token.token, cached_replay)
            if not unwrapped or not unwrapped.get("access_token"):
                raise TokenError("invalid_grant", "Refresh replay cache invalid")
            cached_iss_res = cached_replay.get("issued_resource", cached_replay.get("resource"))
            cached_iss_sc = list(cached_replay.get("issued_scopes") or cached_replay.get("scopes") or [])
            if cached_iss_res == eff_access_res and sorted(cached_iss_sc) == sorted(eff_scopes):
                return OAuthToken(
                    access_token=str(unwrapped["access_token"]),
                    refresh_token=str(unwrapped["refresh_token"]) if unwrapped.get("refresh_token") else None,
                    expires_in=int(cached_replay.get("expires_in") or expires_in),
                    scope=str(cached_replay.get("scope") or " ".join(eff_scopes)),
                )
            self.store.put("access", access.token, access_doc, access.expires_at)
            return OAuthToken(
                access_token=access.token,
                refresh_token=str(unwrapped["refresh_token"]) if unwrapped.get("refresh_token") else None,
                expires_in=expires_in,
                scope=" ".join(eff_scopes),
            )
        return minted

    async def load_access_token(self, token: str) -> Optional[AccessToken]:
        record = self.store.get("access", token)
        if not record:
            return None
        return AccessToken.model_validate({**record, "token": token})

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        self.store.revoke_token_and_related(token.token, token.client_id)


def verify_remote_management_auth(
    store: OAuthSQLiteStore,
    provider: OAuthProvider,
    *,
    owner_password: str = "",
    admin_token: str = "",
    expected_admin_token: str = "",
    client_ip: str = "global",
) -> Dict[str, Any]:
    """Strong owner-password or admin-token validator with per-IP + global brute-force lockout (zero path/username leakage)."""
    bucket = f"remote_admin:{(client_ip or 'global').strip()[:80]}"
    locked, wait_sec = store.check_auth_lockout(bucket_key=bucket)
    if locked:
        return {
            "ok": False,
            "status_code": 429,
            "error": "rate_limited",
            "retry_after": wait_sec,
        }
    glob_locked, glob_wait = store.check_global_auth_lockout()
    if glob_locked:
        return {
            "ok": False,
            "status_code": 429,
            "error": "rate_limited",
            "reason": "global_auth_cooldown",
            "retry_after": glob_wait,
        }

    clean_admin_cand = (admin_token or "").strip()
    clean_admin_exp = (expected_admin_token or "").strip()
    if clean_admin_cand and clean_admin_exp and hmac.compare_digest(clean_admin_cand, clean_admin_exp):
        store.record_auth_result(True, bucket_key=bucket)
        store.record_global_auth_result(True)
        return {"ok": True, "auth_method": "admin_token"}

    clean_pw = (owner_password or "").strip()
    if clean_pw and provider.authenticate_owner(clean_pw):
        store.record_auth_result(True, bucket_key=bucket)
        store.record_global_auth_result(True)
        return {"ok": True, "auth_method": "owner_password"}

    if clean_pw or clean_admin_cand:
        now_locked, rem = store.record_auth_result(False, bucket_key=bucket)
        glob_now_locked, glob_rem = store.record_global_auth_result(
            False,
            max_failures=8,
            window_sec=30,
            lockout_sec=60,
        )
        if now_locked or glob_now_locked:
            return {
                "ok": False,
                "status_code": 429,
                "error": "rate_limited",
                "reason": "global_auth_cooldown" if glob_now_locked else "ip_password_lockout",
                "retry_after": max(int(rem or 0), int(glob_rem or 0), 1),
            }
    return {
        "ok": False,
        "status_code": 403,
        "error": "unauthorized_owner_or_admin_credentials",
    }


def _validate_safe_workspace_candidate(raw_path: str, state_root: Path) -> Path:
    cleaned = (raw_path or "").replace("\r", "").replace("\n", "").strip().strip("\"'")
    if not cleaned or "\x00" in cleaned:
        raise ValueError("Workspace path cannot be empty or contain null bytes.")
    resolved = Path(expand_env_and_tilde(cleaned)).expanduser().resolve()
    cand_norm = Path(os.path.normcase(str(resolved)))
    for forbidden_sub in ("secrets", "state", "config"):
        sec_p = Path(os.path.normcase(str((state_root / forbidden_sub).resolve())))
        if cand_norm == sec_p or cand_norm.is_relative_to(sec_p):
            raise ValueError("Internal MCP state/secrets/config directories cannot be added to workspace_roots.")
    return resolved


_VALID_PYTHON_EXE_NAME_RE = re.compile(r"^python(?:w|3(?:\.\d+)?)?(?:\.exe)?$", re.IGNORECASE)


def _validate_remote_python_path(raw_val: Any) -> str:
    norm = normalize_python_path(raw_val)
    if norm == "":
        return ""
    if "\x00" in norm or norm.startswith(("\\\\", "//")):
        raise ValueError("ERR_INVALID_PYTHON_PATH: UNC or malformed python_path is forbidden.")
    expanded = Path(expand_env_and_tilde(norm)).expanduser()
    if not expanded.is_file():
        raise ValueError("ERR_INVALID_PYTHON_PATH: python_path must point to an existing local Python executable.")
    if not _VALID_PYTHON_EXE_NAME_RE.match(expanded.name):
        raise ValueError("ERR_INVALID_PYTHON_PATH: python_path executable name must be a real Python interpreter.")
    if os.name != "nt" and not os.access(str(expanded), os.X_OK):
        raise ValueError("ERR_INVALID_PYTHON_PATH: python_path is not executable.")
    return str(expanded.resolve())


def validate_and_apply_remote_policy_update(
    policy: LiveRuntimePolicy,
    store: OAuthSQLiteStore,
    provider: OAuthProvider,
    payload: Dict[str, Any],
    *,
    expected_admin_token: str = "",
    admin_token_header: str = "",
    client_ip: str = "global",
) -> Dict[str, Any]:
    """Authenticate via owner password or admin token and hot-apply remote `workspace_roots`, `keep_awake`, `enabled_packs`, or `tier`."""
    if not isinstance(payload, dict):
        return {"ok": False, "status_code": 400, "error": "invalid_payload"}

    pw = str(payload.get("owner_password") or payload.get("password") or "").strip()
    adm_tok = str(admin_token_header or payload.get("admin_token") or "").strip()
    auth_res = verify_remote_management_auth(
        store,
        provider,
        owner_password=pw,
        admin_token=adm_tok,
        expected_admin_token=expected_admin_token,
        client_ip=client_ip,
    )
    if not auth_res.get("ok"):
        return auth_res

    try:
        current_roots: List[Path] = list(policy.workspace_roots)
        mutated_roots: Optional[List[Path]] = None

        if "workspace_roots" in payload and payload["workspace_roots"] is not None:
            raw_list = payload["workspace_roots"]
            if isinstance(raw_list, str):
                raw_items = _split_workspace_string(raw_list)
            elif isinstance(raw_list, list):
                raw_items = [str(x).strip() for x in raw_list if str(x).strip()]
            else:
                raise ValueError("`workspace_roots` must be a non-empty list of directory paths.")
            if not raw_items:
                raise ValueError("`workspace_roots` cannot be empty.")
            mutated_roots = [_validate_safe_workspace_candidate(item, policy.state_root) for item in raw_items]
        elif payload.get("workspace"):
            single_p = _validate_safe_workspace_candidate(str(payload["workspace"]), policy.state_root)
            mutated_roots = [single_p]

        if payload.get("add_workspace_root"):
            added_p = _validate_safe_workspace_candidate(str(payload["add_workspace_root"]), policy.state_root)
            base_r = mutated_roots if mutated_roots is not None else list(current_roots)
            norm_existing = {os.path.normcase(str(p)) for p in base_r}
            if os.path.normcase(str(added_p)) not in norm_existing:
                base_r.append(added_p)
            mutated_roots = base_r

        if payload.get("remove_workspace_root"):
            rem_p = Path(expand_env_and_tilde(str(payload["remove_workspace_root"]).strip())).expanduser().resolve()
            rem_norm = os.path.normcase(str(rem_p))
            base_r = mutated_roots if mutated_roots is not None else list(current_roots)
            filtered_r = [p for p in base_r if os.path.normcase(str(p)) != rem_norm]
            if not filtered_r:
                raise ValueError("Cannot remove the last remaining directory from `workspace_roots`.")
            mutated_roots = filtered_r

        new_tier = ""
        if payload.get("tier") or payload.get("permission_tier"):
            new_tier = parse_strict_tier(str(payload.get("tier") or payload.get("permission_tier")))

        new_toolset = ""
        if payload.get("toolset_profile") or payload.get("toolset"):
            new_toolset = parse_strict_toolset_profile(str(payload.get("toolset_profile") or payload.get("toolset")))

        new_packs: Any = None
        if "enabled_packs" in payload or "enable_pack" in payload:
            raw_pk = payload["enabled_packs"] if "enabled_packs" in payload else payload["enable_pack"]
            new_packs = parse_pack_spec(raw_pk, strict=True)

        new_keep_awake: Optional[bool] = None
        if "keep_awake" in payload:
            new_keep_awake = parse_bool_flag(payload["keep_awake"], default=policy.keep_awake)

        new_popups: Optional[bool] = None
        if "approval_popups" in payload:
            new_popups = parse_bool_flag(payload["approval_popups"], default=policy.approval_popups)

        new_annotation_mode = ""
        if "annotation_mode" in payload and payload["annotation_mode"] is not None and str(payload["annotation_mode"]).strip() != "":
            raw_ann_in = str(payload["annotation_mode"]).strip().lower()
            if raw_ann_in == "compat":
                new_annotation_mode = "seamless"
            elif raw_ann_in == "honest":
                new_annotation_mode = "strict"
            else:
                new_annotation_mode = parse_strict_annotation_mode(payload["annotation_mode"])

        new_python_path: Optional[str] = None
        if "python_path" in payload and payload["python_path"] is not None:
            new_python_path = _validate_remote_python_path(payload["python_path"])

        policy.persist_changes(
            tier_key=new_tier,
            workspace_roots=mutated_roots,
            toolset_profile=new_toolset,
            enabled_packs=new_packs,
            keep_awake=new_keep_awake,
            approval_popups=new_popups,
            annotation_mode=new_annotation_mode,
            python_path=new_python_path,
        )
        provider.tier_key = policy.tier_key
        provider.tier_label = policy.dynamic_tier_label()
        provider.toolset_profile = policy.toolset_profile
    except ValueError as exc:
        return {"ok": False, "status_code": 400, "error": str(exc)}

    return {
        "ok": True,
        "status_code": 200,
        "auth_method": auth_res["auth_method"],
        "permission_tier": policy.tier_key,
        "toolset_profile": policy.toolset_profile,
        "workspace_roots": [str(p) for p in policy.workspace_roots],
        "enabled_packs": list(policy.enabled_packs),
        "keep_awake": policy.keep_awake,
        "annotation_mode": policy.annotation_mode,
        "approval_popups": policy.approval_popups,
        "python_path": policy.python_path,
    }


Store = OAuthSQLiteStore
Provider = OAuthProvider
