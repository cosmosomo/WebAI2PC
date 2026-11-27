"""Apple HIG web `/consent` rendering, top-level `302` loopback bridge, and pure-loopback verification (`oauth_web.py`).

Security invariants:
- Requests arriving through Cloudflare Tunnel, Workers DO gateway, or any reverse proxy also appear with
  `client.host == '127.0.0.1'`, accompanied by forwarding/tunnel headers (`X-Cosmos-Via-Tunnel`,
  `CF-Connecting-IP`, `CF-Ray`, `X-Forwarded-For`, etc.) or a non-loopback `Host` header.
- `is_pure_local_consent_request(request)` NEVER treats a proxied request as local: it requires a loopback peer IP
  (`127.0.0.1` / `::1`), a strict loopback `Host` header (`127.0.0.1(:port)` / `localhost(:port)` / `[::1](:port)`),
  AND complete absence of any proxy or tunnel headers.
- Top-level `302` loopback bridge (`POST /consent` `auth_mode="local_bridge"` -> `GET /oauth/local-bridge` ->
  `GET /consent/complete`) avoids Chromium Local Network Access (LNA) subresource `fetch()` permission prompts while
  enforcing:
  1) Browser-bound `__Host-cosmos_consent_s` / `cosmos_consent_s` `HttpOnly; SameSite=Lax` session cookie hash check
     on both `POST /consent` and `GET /consent/complete` (defeating cross-device Consent CSRF link lures);
  2) Strict `Origin == scheme://netloc` gateway check on `POST /consent` (`auth_mode="local_bridge"`) + server HMAC-SHA256
     signed `{ticket, oauth_state, client_id, redirect_uri}` payload verified at both `/oauth/local-bridge` and
     `/consent/complete` (defeating Clash/proxy loopback spoofing);
  3) Single-use 30s atomic `consume()` on both `local_bridge_nonce` and `local_bridge_proof`.
"""
from __future__ import annotations

import base64
import contextvars
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sys
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional
from urllib.parse import urlencode, urlsplit

from cosmos_mcp.protocol.oauth import (
    derive_dynamic_pair_code,
    get_current_request_gateway,
    load_consent_template_html,
    verify_dynamic_pair_code,
)

CONSENT_SESSION_COOKIE_HTTPS = "__Host-cosmos_consent_s"
CONSENT_SESSION_COOKIE_HTTP = "cosmos_consent_s"
LOCAL_BRIDGE_TTL_SEC = 30

LOCAL_QUICK_SLOT_COMMENT = "<!-- COSMOS_LOCAL_QUICK_SLOT -->"
LOCAL_QUICK_START_COMMENT = "<!-- COSMOS_LOCAL_QUICK_START -->"
LOCAL_QUICK_END_COMMENT = "<!-- COSMOS_LOCAL_QUICK_END -->"
MOBILE_BRIDGE_SLOT_COMMENT = "<!-- COSMOS_MOBILE_BRIDGE_SLOT -->"

_PURE_LOCAL_REQ_VAR: contextvars.ContextVar[bool] = contextvars.ContextVar("_PURE_LOCAL_REQ_VAR", default=False)
_LOCAL_FAST_VERIFIED_VAR: contextvars.ContextVar[bool] = contextvars.ContextVar("_LOCAL_FAST_VERIFIED_VAR", default=False)
_MOBILE_UA_REQ_VAR: contextvars.ContextVar[bool] = contextvars.ContextVar("_MOBILE_UA_REQ_VAR", default=False)
_REMOTE_HUB_REQ_VAR: contextvars.ContextVar[bool] = contextvars.ContextVar("_REMOTE_HUB_REQ_VAR", default=False)

_REMOTE_HUB_MODES = frozenset({"vps_hub", "remote_hub", "server_hub", "headless"})
_HEADLESS_LINUX_SERVER_MODES = frozenset({"reverse_proxy", "nginx", "caddy", "custom"})

_PROXY_EXACT_HEADERS = frozenset(
    {
        "x-cosmos-via-tunnel",
        "x-cosmos-client-ip",
        "x-cosmos-public-prefix",
        "cf-connecting-ip",
        "cf-ray",
        "cf-ipcountry",
        "cf-visitor",
        "cdn-loop",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-port",
        "x-real-ip",
        "forwarded",
        "true-client-ip",
        "via",
        "x-original-host",
        "x-original-url",
        "fastly-client-ip",
    }
)
_PROXY_HEADER_PREFIXES = ("cf-", "x-forwarded-", "x-cosmos-via-")

_STRICT_LOOPBACK_HOST_RE = re.compile(r"^(127\.0\.0\.1|localhost|\[::1\])(?::([1-9][0-9]{0,4}))?$")
_MOBILE_UA_TOKENS = ("android", "iphone", "ipad", "mobile")


def extract_origin_scheme_netloc(url_or_origin: str) -> str:
    """Extract normalized `scheme://netloc` without any path suffix (safe for `/u/<id>` gateway prefixes)."""
    clean = str(url_or_origin or "").strip()
    if not clean or clean.lower() == "null":
        return ""
    parsed = urlsplit(clean)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
    return ""


def _headers_to_lower_dict(headers: Any) -> Dict[str, str]:
    if headers is None:
        return {}
    inner = getattr(headers, "headers", None)
    target = inner if inner is not None and not isinstance(headers, Mapping) else headers
    out: Dict[str, str] = {}
    if hasattr(target, "items"):
        for k, v in target.items():
            ks = k.decode("latin-1", errors="replace") if isinstance(k, (bytes, bytearray)) else str(k)
            vs = v.decode("latin-1", errors="replace") if isinstance(v, (bytes, bytearray)) else str(v)
            out[ks.strip().lower()] = vs.strip()
    elif isinstance(target, (list, tuple)):
        for item in target:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                k, v = item
                ks = k.decode("latin-1", errors="replace") if isinstance(k, (bytes, bytearray)) else str(k)
                vs = v.decode("latin-1", errors="replace") if isinstance(v, (bytes, bytearray)) else str(v)
                out[ks.strip().lower()] = vs.strip()
    return out


def is_mobile_user_agent(headers: Any) -> bool:
    """Detect mobile browsers (`Sec-CH-UA-Mobile: ?1` or `User-Agent` containing Android/iPhone/iPad/Mobile)."""
    hdr_map = _headers_to_lower_dict(headers)
    ch_mob = hdr_map.get("sec-ch-ua-mobile", "").strip().lower()
    if "?1" in ch_mob or ch_mob in ("1", "true"):
        return True
    ua = hdr_map.get("user-agent", "").strip().lower()
    if not ua:
        return False
    return any(tok in ua for tok in _MOBILE_UA_TOKENS)


def is_https_consent_request(request: Any) -> bool:
    """Return True when the external browser session reached `/consent` over HTTPS."""
    url_obj = getattr(request, "url", None)
    scheme = str(getattr(url_obj, "scheme", "") or "").strip().lower()
    if scheme == "https":
        return True
    hdr_map = _headers_to_lower_dict(getattr(request, "headers", None))
    xfp = hdr_map.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
    if xfp == "https":
        return True
    cfv = hdr_map.get("cf-visitor", "").lower()
    if '"https"' in cfv:
        return True
    fwd = hdr_map.get("forwarded", "")
    if fwd and re.search(r'(?:^|[;,\s])proto\s*=\s*"?https"?(?:$|[;,\s])', fwd, re.IGNORECASE):
        return True
    return False


def read_consent_session_cookie(request: Any) -> str:
    """Read the active consent session cookie matching the request transport security level."""
    cookies = getattr(request, "cookies", None) or {}
    if is_https_consent_request(request):
        return str(cookies.get(CONSENT_SESSION_COOKIE_HTTPS) or "").strip()
    return str(
        cookies.get(CONSENT_SESSION_COOKIE_HTTP)
        or cookies.get(CONSENT_SESSION_COOKIE_HTTPS)
        or ""
    ).strip()


def hash_consent_session_token(raw_token: str) -> str:
    """Return hex SHA-256 digest of `raw_token` (empty string when `raw_token` is blank)."""
    clean = str(raw_token or "").strip()
    if not clean:
        return ""
    return hashlib.sha256(clean.encode("utf-8")).hexdigest()


def mint_signed_local_bridge_token(
    secret: bytes,
    *,
    kind: str,
    ticket: str,
    oauth_state: str,
    client_id: str,
    redirect_uri: str,
    jti: str = "",
) -> str:
    """Mint a URL-safe HMAC-SHA256 signed token binding `{kind, jti, ticket, oauth_state, client_id, redirect_uri}`."""
    eff_jti = jti or secrets.token_urlsafe(24)
    claims = {
        "client_id": str(client_id or ""),
        "jti": str(eff_jti),
        "kind": str(kind or ""),
        "oauth_state": str(oauth_state or ""),
        "redirect_uri": str(redirect_uri or ""),
        "ticket": str(ticket or ""),
    }
    raw_json = json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    b64_payload = base64.urlsafe_b64encode(raw_json).decode("ascii").rstrip("=")
    mac = hmac.new(secret, b"cosmos-local-bridge-v1:" + b64_payload.encode("ascii"), hashlib.sha256).digest()
    b64_sig = base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")
    return f"{b64_payload}.{b64_sig}"


def verify_signed_local_bridge_token(
    secret: bytes,
    token: str,
    *,
    expected_kind: str,
    expected_ticket: str = "",
    expected_oauth_state: Optional[str] = None,
    expected_client_id: str = "",
    expected_redirect_uri: str = "",
) -> Optional[Dict[str, str]]:
    """Verify HMAC-SHA256 signature and exact claim bindings of a local bridge `nonce` or `proof` token."""
    clean = str(token or "").strip()
    if not clean or "." not in clean or len(clean) > 4096:
        return None
    b64_payload, b64_sig = clean.split(".", 1)
    if not b64_payload or not b64_sig:
        return None
    exp_mac = hmac.new(secret, b"cosmos-local-bridge-v1:" + b64_payload.encode("ascii"), hashlib.sha256).digest()
    exp_sig = base64.urlsafe_b64encode(exp_mac).decode("ascii").rstrip("=")
    if not hmac.compare_digest(b64_sig, exp_sig):
        return None
    try:
        padded = b64_payload + ("=" * (-len(b64_payload) % 4))
        doc = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    if str(doc.get("kind") or "") != str(expected_kind):
        return None
    if expected_ticket and not hmac.compare_digest(str(doc.get("ticket") or ""), str(expected_ticket)):
        return None
    if expected_oauth_state is not None and str(doc.get("oauth_state") or "") != str(expected_oauth_state):
        return None
    if expected_client_id and str(doc.get("client_id") or "") != str(expected_client_id):
        return None
    if expected_redirect_uri and str(doc.get("redirect_uri") or "") != str(expected_redirect_uri):
        return None
    if not str(doc.get("jti") or ""):
        return None
    return {k: str(v or "") for k, v in doc.items()}


def is_pure_local_consent_request(request: Any, expected_port: Optional[int] = None) -> bool:
    """Return True ONLY for genuine same-machine loopback browser requests with zero proxy/tunnel headers."""
    client = getattr(request, "client", None)
    client_host = str(getattr(client, "host", "") or "").strip().lower() if client else ""
    if client_host not in ("127.0.0.1", "::1"):
        return False

    headers = getattr(request, "headers", None) or {}
    hdr_map = _headers_to_lower_dict(headers)
    for kl in hdr_map.keys():
        if kl in _PROXY_EXACT_HEADERS or kl.startswith(_PROXY_HEADER_PREFIXES):
            return False

    raw_host = hdr_map.get("host", "").strip().lower()
    if not raw_host:
        return False

    m_host = _STRICT_LOOPBACK_HOST_RE.match(raw_host)
    if not m_host:
        return False
    port_str = m_host.group(2)
    if port_str is not None:
        port_num = int(port_str)
        if port_num < 1 or port_num > 65535:
            return False
        if expected_port is not None and int(expected_port) > 0 and port_num != int(expected_port):
            return False

    origin_hdr = hdr_map.get("origin", "").strip().lower()
    if origin_hdr and origin_hdr != "null":
        orig_norm = extract_origin_scheme_netloc(origin_hdr)
        orig_host = (urlsplit(orig_norm).hostname or "").strip().lower() if orig_norm else ""
        if orig_host not in ("127.0.0.1", "localhost", "::1"):
            return False

    return True


def is_current_request_pure_local() -> bool:
    return bool(_PURE_LOCAL_REQ_VAR.get())


def is_current_request_mobile() -> bool:
    return bool(_MOBILE_UA_REQ_VAR.get())


def is_remote_hub_consent_mode(tunnel_mode: str = "", *, local_port: Optional[int] = None) -> bool:
    """Return True when `/consent` runs on a remote VPS hub (`vps_hub`) or headless non-desktop Linux server."""
    eff_mode = (
        str(tunnel_mode or "").strip().lower()
        or os.environ.get("COSMOS_TUNNEL_MODE", "").strip().lower()
        or os.environ.get("LOCALPC_TUNNEL_MODE", "").strip().lower()
    )
    if eff_mode in _REMOTE_HUB_MODES:
        return True
    if (
        sys.platform.startswith("linux")
        and not os.environ.get("DISPLAY", "").strip()
        and not os.environ.get("WAYLAND_DISPLAY", "").strip()
        and (eff_mode in _HEADLESS_LINUX_SERVER_MODES or int(local_port or 0) == 18096)
    ):
        return True
    return False


def is_current_request_remote_hub() -> bool:
    return bool(_REMOTE_HUB_REQ_VAR.get())


def is_verified_local_fast_approve() -> bool:
    return bool(_LOCAL_FAST_VERIFIED_VAR.get())


def mint_local_consent_fast_token(secret: bytes, *, ticket: str, csrf: str) -> str:
    """Mint a short-lived HMAC proof bound to `(ticket, csrf)` for pure loopback same-machine quick confirm."""
    msg = f"cosmos-local-consent-v1:{ticket}:{csrf}".encode("utf-8")
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def verify_local_consent_fast_token(secret: bytes, token: str, *, ticket: str, csrf: str) -> bool:
    clean = (token or "").strip()
    if not clean or not ticket or not csrf:
        return False
    expected = mint_local_consent_fast_token(secret, ticket=ticket, csrf=csrf)
    return hmac.compare_digest(clean, expected)


def build_consent_badge_style(*, tier_key: str, tier_label: str, is_readonly_resource: bool) -> str:
    """Soft Apple HIG semantic badge styling without clashing against the green anti-phishing card."""
    is_l4 = str(tier_key or "").startswith("tier4") or str(tier_label or "").upper().startswith("L4")
    if is_l4 and not is_readonly_resource:
        return "background:#FFF7ED;color:#9A3412;border:1px solid rgba(249,115,22,0.34);"
    if is_readonly_resource or str(tier_key or "").startswith("tier1"):
        return "background:rgba(110,110,115,0.10);color:#3A3A3C;border:1px solid rgba(0,0,0,0.09);"
    return "background:rgba(0,113,227,0.09);color:#0066CC;border:1px solid rgba(0,113,227,0.20);"


def apply_device_consent_layout(
    rendered_html: str,
    *,
    is_mobile: bool,
    has_error: bool,
    local_fast_token: str = "",
    is_remote_hub: bool = False,
) -> str:
    """Adapt `consent.html` across Desktop (loopback bridge), Remote VPS Hub (`vps_hub`), and Mobile (6-digit code)."""
    out = rendered_html
    start_idx = out.find(LOCAL_QUICK_START_COMMENT)
    end_idx = out.find(LOCAL_QUICK_END_COMMENT)

    if local_fast_token and not is_mobile:
        safe_ft = html.escape(local_fast_token, quote=True)
        fast_hero = (
            '<div class="local-bridge-hero" id="local-fast-bar">'
            '<input type="hidden" name="local_fast_token" id="local-fast-token-input" value="' + safe_ft + '">'
            '<button type="submit" class="local-bridge-btn" id="local-bridge-approve-btn" name="auth_mode" value="local_bridge" formnovalidate>'
            "本机一键允许连接（免输口令）"
            "</button>"
            '<div class="local-bridge-caption">已识别本机同机直连，点击即可直接确认连接</div>'
            "</div>"
        )
        if start_idx >= 0 and end_idx > start_idx:
            out = out[:start_idx] + fast_hero + out[end_idx + len(LOCAL_QUICK_END_COMMENT) :]
        else:
            out = out.replace(LOCAL_QUICK_SLOT_COMMENT, fast_hero)
        if has_error:
            out = out.replace(
                '<details class="alt-auth-details" id="alt-auth-details">',
                '<details class="alt-auth-details" id="alt-auth-details" open>',
                1,
            )
        out = out.replace(MOBILE_BRIDGE_SLOT_COMMENT, "")
        out = out.replace(LOCAL_QUICK_SLOT_COMMENT, "")
        return out

    if is_remote_hub:
        if start_idx >= 0 and end_idx > start_idx:
            out = out[:start_idx] + out[end_idx + len(LOCAL_QUICK_END_COMMENT) :]
        out = out.replace(
            '<details class="alt-auth-details" id="alt-auth-details">',
            '<details class="alt-auth-details" id="alt-auth-details" open>',
            1,
        )
        out = re.sub(
            r'(<details[^>]*id="alt-auth-details"[^>]*>\s*)<summary>.*?</summary>',
            r"\1<summary>云服务器主站连接验证：输入 6 位动态配对码或 20 位连接口令</summary>",
            out,
            count=1,
            flags=re.DOTALL,
        )
        out = out.replace(MOBILE_BRIDGE_SLOT_COMMENT, "")
        out = out.replace(LOCAL_QUICK_SLOT_COMMENT, "")
        return out

    if is_mobile:
        if start_idx >= 0 and end_idx > start_idx:
            out = out[:start_idx] + out[end_idx + len(LOCAL_QUICK_END_COMMENT) :]
        out = out.replace(
            '<details class="alt-auth-details" id="alt-auth-details">',
            '<details class="alt-auth-details mobile-primary" id="alt-auth-details" open>',
            1,
        )
        out = re.sub(
            r'(<details[^>]*id="alt-auth-details"[^>]*>\s*)<summary>.*?</summary>',
            r"\1<summary>手机端连接验证：输入 20 位连接口令或 6 位动态配对码</summary>",
            out,
            count=1,
            flags=re.DOTALL,
        )
        mobile_secondary = (
            '<details class="secondary-bridge-details" id="mobile-bridge-details">'
            "<summary>正在电脑端浏览器操作？使用本机一键免输口令桥接</summary>"
            '<div class="alt-auth-body">'
            '<button type="submit" class="local-bridge-btn" id="local-bridge-approve-btn" name="auth_mode" value="local_bridge" formnovalidate>'
            "本机一键允许连接（免输口令）"
            "</button>"
            "</div>"
            "</details>"
        )
        out = out.replace(MOBILE_BRIDGE_SLOT_COMMENT, mobile_secondary)
        out = out.replace(LOCAL_QUICK_SLOT_COMMENT, "")
        return out

    # Desktop public `/consent`: keep primary `local_bridge` CTA on top and `<details>` collapsed below (open on error)
    if start_idx >= 0 and end_idx > start_idx:
        inner = out[start_idx + len(LOCAL_QUICK_START_COMMENT) : end_idx]
        out = out[:start_idx] + inner + out[end_idx + len(LOCAL_QUICK_END_COMMENT) :]
    if has_error:
        out = out.replace(
            '<details class="alt-auth-details" id="alt-auth-details">',
            '<details class="alt-auth-details" id="alt-auth-details" open>',
            1,
        )
    out = out.replace(MOBILE_BRIDGE_SLOT_COMMENT, "")
    out = out.replace(LOCAL_QUICK_SLOT_COMMENT, "")
    return out


def render_web_consent_html(
    *,
    tier_key: str,
    tier_label: str,
    permission_desc_zh: str,
    pair_code: str,
    client_name: str,
    consent_path: str,
    ticket: str,
    csrf: str,
    nonce: str,
    error_banner: str = "",
    is_readonly_resource: bool = False,
    selected_scope: str = "default",
    selected_ttl: str = "30d",
    local_fast_token: str = "",
    is_mobile: Optional[bool] = None,
    is_remote_hub: Optional[bool] = None,
) -> str:
    """Render `protocol/templates/consent.html` with Apple HIG styling and Desktop/VPS/Mobile adaptive auth controls."""
    tpl = load_consent_template_html()
    badge_style = build_consent_badge_style(
        tier_key=tier_key,
        tier_label=tier_label,
        is_readonly_resource=is_readonly_resource,
    )
    err_html = f'<div class="alert" role="alert">{html.escape(error_banner)}</div>' if error_banner else ""
    action_url = f"{consent_path}?{urlencode({'ticket': ticket})}" if ticket else consent_path
    eff_ro = bool(is_readonly_resource or str(selected_scope or "").strip().lower() == "readonly")
    if is_readonly_resource:
        scope_default_attrs = "disabled"
        scope_readonly_attrs = "checked"
        scope_default_sub = "当前为 /mcp/readonly 只读连接端点，固定仅授予只读权限"
    else:
        scope_default_attrs = "" if eff_ro else "checked"
        scope_readonly_attrs = "checked" if eff_ro else ""
        scope_default_sub = "与 Studio 当前安全档位同步开放工作区权限"

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
        "__PAIR_CODE_PATH__": "",
        "__CLIENT_NAME__": html.escape(client_name or "AI 客户端"),
        "__CONN_FILENAME__": "",
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

    eff_mobile = is_current_request_mobile() if is_mobile is None else bool(is_mobile)
    eff_remote_hub = is_current_request_remote_hub() if is_remote_hub is None else bool(is_remote_hub)
    return apply_device_consent_layout(
        rendered,
        is_mobile=eff_mobile,
        has_error=bool(error_banner),
        local_fast_token=local_fast_token,
        is_remote_hub=eff_remote_hub,
    )


async def handle_web_consent_request(
    provider: Any,
    request: Any,
    *,
    super_consent_fn: Callable[[Any], Awaitable[Any]],
    local_fast_secret: bytes,
    expected_port: Optional[int] = None,
) -> Any:
    """Wrap `OAuthProvider.consent` with pure-loopback fast confirmation and VPS/mobile context detection."""
    eff_port = expected_port if expected_port is not None else getattr(provider, "local_port", None)
    pure_local = is_pure_local_consent_request(request, expected_port=eff_port)
    mobile_ua = is_mobile_user_agent(getattr(request, "headers", None))
    gw = get_current_request_gateway()
    eff_tm = "local" if pure_local else ""
    if not eff_tm and gw is not None and not gw.is_loopback and gw.tunnel_mode:
        eff_tm = gw.tunnel_mode
    if not eff_tm:
        q_params = getattr(request, "query_params", None)
        tkt_q = str(q_params.get("ticket") or "").strip() if q_params is not None else ""
        store_obj = getattr(provider, "store", None)
        if tkt_q and store_obj is not None:
            pend_q = store_obj.get("consent", tkt_q)
            if isinstance(pend_q, Mapping) and pend_q.get("gateway_tunnel_mode"):
                eff_tm = str(pend_q.get("gateway_tunnel_mode") or "").strip().lower()
    if not eff_tm:
        eff_tm = str(getattr(provider, "tunnel_mode", "") or "")
    remote_hub = False if pure_local else is_remote_hub_consent_mode(eff_tm, local_port=eff_port)
    fast_verified = False

    if pure_local and str(getattr(request, "method", "GET")).upper() == "POST":
        form = await request.form()
        raw_pw = str(form.get("password") or "").strip()
        raw_pair = str(form.get("pair_code") or "").strip()
        raw_fast_tok = str(form.get("local_fast_token") or "").strip()
        raw_decision = str(form.get("decision") or "").strip().lower()
        raw_auth_mode = str(form.get("auth_mode") or "").strip().lower()
        ticket = str(form.get("ticket") or request.query_params.get("ticket") or "").strip()
        csrf = str(form.get("csrf") or "").strip()
        cookie_csrf = str(request.cookies.get(provider.consent_cookie(ticket), "") or "")
        wants_fast = raw_decision == "approve" or (raw_auth_mode == "local_bridge" and raw_decision != "deny")
        if (
            not raw_pw
            and not raw_pair
            and wants_fast
            and raw_fast_tok
            and ticket
            and csrf
            and hmac.compare_digest(csrf, cookie_csrf)
            and verify_local_consent_fast_token(local_fast_secret, raw_fast_tok, ticket=ticket, csrf=csrf)
        ):
            fast_verified = True

    tok_pure = _PURE_LOCAL_REQ_VAR.set(pure_local)
    tok_mob = _MOBILE_UA_REQ_VAR.set(mobile_ua)
    tok_rem = _REMOTE_HUB_REQ_VAR.set(remote_hub)
    tok_fast = _LOCAL_FAST_VERIFIED_VAR.set(fast_verified)
    try:
        return await super_consent_fn(request)
    finally:
        _LOCAL_FAST_VERIFIED_VAR.reset(tok_fast)
        _REMOTE_HUB_REQ_VAR.reset(tok_rem)
        _MOBILE_UA_REQ_VAR.reset(tok_mob)
        _PURE_LOCAL_REQ_VAR.reset(tok_pure)


async def handle_oauth_local_bridge_request(
    provider: Any,
    request: Any,
    *,
    expected_port: Optional[int] = None,
) -> Any:
    """Standard Starlette handler for `GET /oauth/local-bridge` (reusable in `transport.py` & `studio/routes.py`)."""
    return await provider.local_bridge(request, expected_port=expected_port)


async def handle_consent_complete_request(provider: Any, request: Any) -> Any:
    """Standard Starlette handler for `GET /consent/complete` (reusable in `transport.py` & `studio/routes.py`)."""
    return await provider.consent_complete(request)


__all__ = [
    "CONSENT_SESSION_COOKIE_HTTP",
    "CONSENT_SESSION_COOKIE_HTTPS",
    "LOCAL_BRIDGE_TTL_SEC",
    "LOCAL_QUICK_SLOT_COMMENT",
    "apply_device_consent_layout",
    "build_consent_badge_style",
    "derive_dynamic_pair_code",
    "extract_origin_scheme_netloc",
    "handle_consent_complete_request",
    "handle_oauth_local_bridge_request",
    "handle_web_consent_request",
    "hash_consent_session_token",
    "is_current_request_mobile",
    "is_current_request_pure_local",
    "is_current_request_remote_hub",
    "is_https_consent_request",
    "is_mobile_user_agent",
    "is_pure_local_consent_request",
    "is_remote_hub_consent_mode",
    "is_verified_local_fast_approve",
    "mint_local_consent_fast_token",
    "mint_signed_local_bridge_token",
    "read_consent_session_cookie",
    "render_web_consent_html",
    "verify_dynamic_pair_code",
    "verify_local_consent_fast_token",
    "verify_signed_local_bridge_token",
]
