"""Pure Python >=3.9 standard-library asyncio HTTP JSON-RPC 2.0 transport shell (`jsonrpc_lite.py`)."""
from __future__ import annotations

import asyncio
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import inspect
import json
import logging
import threading
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol, Tuple
from urllib.parse import urlsplit

LOGGER = logging.getLogger("cosmos_mcp.jsonrpc_lite")

SUPPORTED_PROTOCOL_VERSIONS: Tuple[str, ...] = (
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
)


class DispatcherLike(Protocol):
    """Duck-typed protocol matching `KernelDispatcher` without importing non-stdlib modules."""

    @property
    def inflight_count(self) -> int: ...

    def list_tool_dicts(
        self,
        *,
        scopes: Optional[Iterable[str]] = None,
        readonly_only: bool = False,
        session_hint: str = "http",
        zero_popup_annotations: Optional[bool] = None,
        preserve_epoch_snapshot: bool = False,
    ) -> List[Dict[str, Any]]: ...

    async def call_tool_raw(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
        *,
        scopes: Optional[Iterable[str]] = None,
        readonly_only: bool = False,
        session_hint: str = "http",
        client_platform: str = "",
    ) -> Tuple[Any, bool]: ...


def _is_google_ua(user_agent: str) -> bool:
    ua = (user_agent or "").strip().lower()
    return ua == "google" or ua.startswith("google/") or "google-mcp" in ua or "google" in ua


def _format_mcp_content_blocks(raw_payload: Any, *, adapt_google_images: bool = False) -> List[Dict[str, Any]]:
    ext_map = {
        "image/png": "png",
        "image/jpeg": "jpg",
        "image/jpg": "jpg",
        "image/webp": "webp",
        "image/gif": "gif",
        "image/bmp": "bmp",
    }
    if isinstance(raw_payload, (list, tuple)):
        blocks: List[Dict[str, Any]] = []
        img_idx = 0
        for item in raw_payload:
            if hasattr(item, "model_dump"):
                blk = item.model_dump(mode="json", exclude_none=True)
            elif isinstance(item, dict):
                blk = dict(item)
            else:
                blk = {"type": "text", "text": str(item)}
            if (
                adapt_google_images
                and blk.get("type") == "image"
                and isinstance(blk.get("data"), str)
                and blk.get("data")
                and blk.get("mimeType")
            ):
                img_idx += 1
                mime = str(blk["mimeType"]).strip()
                ext = ext_map.get(mime.lower(), "jpg")
                blocks.append(
                    {
                        "type": "resource",
                        "resource": {
                            "uri": f"file:///localpc_capture_{img_idx}.{ext}",
                            "mimeType": mime,
                            "blob": blk["data"],
                        },
                    }
                )
            else:
                blocks.append(blk)
        return blocks if blocks else [{"type": "text", "text": ""}]

    text_out = raw_payload if isinstance(raw_payload, str) else json.dumps(raw_payload, ensure_ascii=False)
    return [{"type": "text", "text": text_out}]


class JsonRpcLiteServer:
    """Zero-dependency Python >=3.9 asyncio HTTP JSON-RPC 2.0 server mounting `KernelDispatcher`."""

    def __init__(
        self,
        dispatcher: DispatcherLike,
        *,
        host: str = "127.0.0.1",
        port: int = 8096,
        auth_secret: str = "",
        bearer_token: str = "",
        server_name: str = "cosmos_jsonrpc_lite",
        server_version: str = "1.2.1",
        readonly_only: bool = False,
        max_body_bytes: int = 4 * 1024 * 1024,
        instructions_fn: Optional[Callable[[bool], str]] = None,
        extra_post_routes: Optional[Dict[str, Callable[[Dict[str, Any]], Any]]] = None,
    ) -> None:
        self.dispatcher = dispatcher
        self.host = host
        self.port = int(port)
        self.auth_secret = auth_secret or bearer_token
        self.server_name = server_name
        self.server_version = server_version
        self.readonly_only = bool(readonly_only)
        self.max_body_bytes = max(4096, int(max_body_bytes))
        self.instructions_fn = instructions_fn
        self.extra_post_routes = dict(extra_post_routes or {})
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._local_inflight = 0

    @property
    def bound_port(self) -> int:
        if self._httpd is not None:
            return int(self._httpd.server_port)
        return self.port

    @property
    def inflight_count(self) -> int:
        disp_in = int(getattr(self.dispatcher, "inflight_count", 0) or 0)
        return max(self._local_inflight, disp_in)

    async def handle_jsonrpc_message(
        self,
        msg: Any,
        *,
        readonly_only: bool = False,
        user_agent: str = "",
        session_hint: str = "jsonrpc-lite",
        scopes: Optional[Iterable[str]] = None,
    ) -> Tuple[int, Optional[Dict[str, Any]]]:
        """Process a decoded JSON-RPC 2.0 request object and return `(http_status, json_body_or_None)`."""
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            return 400, {
                "jsonrpc": "2.0",
                "id": msg.get("id") if isinstance(msg, dict) else None,
                "error": {"code": -32600, "message": "Single JSON-RPC 2.0 request object required"},
            }

        rpc_id = msg.get("id")
        rpc_method = str(msg.get("method") or "")
        eff_ro = bool(self.readonly_only or readonly_only)
        is_google = _is_google_ua(user_agent)

        if rpc_method.startswith("notifications/"):
            return 202, None

        if rpc_method == "initialize":
            params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
            req_ver = str(params.get("protocolVersion") or "2024-11-05")
            chosen_ver = req_ver if req_ver in SUPPORTED_PROTOCOL_VERSIONS else "2024-11-05"
            res_body: Dict[str, Any] = {
                "protocolVersion": chosen_ver,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": self.server_name, "version": self.server_version},
            }
            if self.instructions_fn is not None:
                instr = self.instructions_fn(eff_ro)
                if instr:
                    res_body["instructions"] = instr
            return 200, {"jsonrpc": "2.0", "id": rpc_id, "result": res_body}

        if rpc_method == "ping":
            return 200, {"jsonrpc": "2.0", "id": rpc_id, "result": {}}

        if rpc_method == "tools/list":
            policy_ref = getattr(self.dispatcher, "policy", None)
            ann_mode = str(getattr(policy_ref, "annotation_mode", "") or "").strip().lower()
            if ann_mode in ("seamless", "strict"):
                zero_popup = (ann_mode == "seamless") and not eff_ro
            else:
                popups = bool(getattr(policy_ref, "approval_popups", False)) if policy_ref is not None else False
                zero_popup = bool(not popups and not eff_ro)
            tools = self.dispatcher.list_tool_dicts(
                scopes=scopes,
                readonly_only=eff_ro,
                session_hint=session_hint,
                zero_popup_annotations=zero_popup,
            )
            return 200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": tools}}

        if rpc_method == "tools/call":
            params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
            t_name = str(params.get("name") or "").strip()
            raw_args = params.get("arguments")
            if raw_args is not None and not isinstance(raw_args, dict):
                return 200, {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32602, "message": "`arguments` must be a JSON object"},
                }
            self._local_inflight += 1
            try:
                out_payload, is_err = await self.dispatcher.call_tool_raw(
                    t_name,
                    raw_args or {},
                    scopes=scopes,
                    readonly_only=eff_ro,
                    session_hint=session_hint,
                    client_platform="Google Gemini" if is_google else "JSON-RPC Client",
                )
                blocks = _format_mcp_content_blocks(out_payload, adapt_google_images=is_google)
                return 200, {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "content": blocks,
                        "isError": bool(is_err),
                    },
                }
            finally:
                self._local_inflight = max(0, self._local_inflight - 1)

        return 200, {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "error": {"code": -32601, "message": f"Method not found: {rpc_method}"},
        }

    def _check_auth_header(self, auth_val: str) -> bool:
        if not self.auth_secret:
            return True
        prefix = "bearer "
        if not auth_val or not auth_val.lower().startswith(prefix):
            return False
        cand = auth_val[len(prefix) :].strip()
        return hmac.compare_digest(cand, self.auth_secret)

    def _build_handler_class(self):
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return None

            def _send_json(self, status: int, doc: Optional[Dict[str, Any]], extra: Optional[Dict[str, str]] = None) -> None:
                raw = json.dumps(doc, ensure_ascii=False).encode("utf-8") if doc is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                if extra:
                    for hk, hv in extra.items():
                        self.send_header(hk, hv)
                self.end_headers()
                if raw:
                    self.wfile.write(raw)

            def do_GET(self) -> None:  # noqa: N802
                path = urlsplit(self.path).path or "/"
                if path in ("/healthz", "/health", "/status"):
                    tools_cnt = len(outer.dispatcher.list_tool_dicts(readonly_only=outer.readonly_only))
                    self._send_json(
                        200,
                        {
                            "status": "ok",
                            "service": outer.server_name,
                            "inflight": outer.inflight_count,
                            "version": outer.server_version,
                            "tool_count": tools_cnt,
                        },
                    )
                    return
                if not outer._check_auth_header(self.headers.get("Authorization", "")):
                    self._send_json(401, {"error": "unauthorized"})
                    return
                if path in ("/mcp", "/mcp/readonly"):
                    self._send_json(405, {"error": "method_not_allowed"}, {"Allow": "POST, DELETE"})
                    return
                self._send_json(404, {"error": "not_found"})

            def do_DELETE(self) -> None:  # noqa: N802
                if not outer._check_auth_header(self.headers.get("Authorization", "")):
                    self._send_json(401, {"error": "unauthorized"})
                    return
                path = urlsplit(self.path).path or "/"
                if path in ("/mcp", "/mcp/readonly"):
                    self._send_json(204, None)
                    return
                self._send_json(404, {"error": "not_found"})

            def do_POST(self) -> None:  # noqa: N802
                if not outer._check_auth_header(self.headers.get("Authorization", "")):
                    self._send_json(401, {"error": "unauthorized"})
                    return
                path = urlsplit(self.path).path or "/"
                try:
                    c_len = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    self._send_json(400, {"error": "invalid_content_length"})
                    return
                if c_len > outer.max_body_bytes:
                    self._send_json(413, {"error": "request_too_large"})
                    return
                body_bytes = self.rfile.read(c_len) if c_len > 0 else b""
                loop = outer._loop
                if loop is None:
                    self._send_json(500, {"error": "event_loop_not_running"})
                    return

                if path in outer.extra_post_routes:
                    try:
                        ext_in = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
                    except Exception:
                        self._send_json(400, {"ok": False, "error": "invalid_json"})
                        return
                    fn = outer.extra_post_routes[path]
                    if inspect.iscoroutinefunction(fn):
                        fut = asyncio.run_coroutine_threadsafe(fn(ext_in), loop)
                        out_ext = fut.result(timeout=60.0)
                    else:
                        out_ext = fn(ext_in)
                    st_code = 200 if (isinstance(out_ext, dict) and out_ext.get("ok", True)) else 400
                    self._send_json(st_code, out_ext if isinstance(out_ext, dict) else {"ok": True, "result": out_ext})
                    return

                if path in ("/mcp", "/mcp/readonly"):
                    try:
                        rpc_msg = json.loads(body_bytes.decode("utf-8"))
                    except Exception:
                        self._send_json(
                            400,
                            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error: invalid JSON"}},
                        )
                        return
                    ua = self.headers.get("User-Agent", "")
                    sid = self.headers.get("Mcp-Session-Id", "") or "jsonrpc-lite"
                    fut = asyncio.run_coroutine_threadsafe(
                        outer.handle_jsonrpc_message(
                            rpc_msg,
                            readonly_only=(path == "/mcp/readonly"),
                            user_agent=ua,
                            session_hint=sid,
                        ),
                        loop,
                    )
                    st, resp_obj = fut.result(timeout=130.0)
                    self._send_json(st, resp_obj)
                    return

                self._send_json(404, {"error": "not_found"})

        return _Handler

    async def start(self) -> "JsonRpcLiteServer":
        if self._httpd is not None:
            return self
        self._loop = asyncio.get_running_loop()
        handler_cls = self._build_handler_class()
        self._httpd = ThreadingHTTPServer((self.host, self.port), handler_cls)
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="cosmos-jsonrpc-lite", daemon=True)
        self._thread.start()
        return self

    async def stop(self) -> None:
        httpd = self._httpd
        self._httpd = None
        if httpd is not None:
            await asyncio.to_thread(httpd.shutdown)
            httpd.server_close()
        if self._thread is not None and self._thread.is_alive():
            await asyncio.to_thread(self._thread.join, 2.0)
        self._thread = None
