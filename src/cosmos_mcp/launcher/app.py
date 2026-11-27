"""Standalone ASGI, Stdio & JsonRpcLite Assembly (`app.py`).

Wires `WorkspaceGuard`, `ProcessManager`, `SleepInhibitor`, `LiveRuntimePolicy`, `KernelDispatcher`,
`KillSignalWatchdog`, `build_core_tools`, `build_default_device_packs` (`BrowserPackPlugin`, `CuaWindowPackPlugin`),
`create_protocol_app`, `JsonRpcLiteServer`, `Cosmos Studio 1.0`, and zero-downtime tunnel URL hot-swap.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import contextvars
import errno
import hmac
import inspect
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit
import uuid

try:
    from mcp.server.stdio import stdio_server
except ImportError:
    stdio_server = None  # type: ignore[assignment]

try:
    from pydantic import AnyHttpUrl
except ImportError:
    AnyHttpUrl = str  # type: ignore[assignment,misc]

try:
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
    from starlette.routing import Route, WebSocketRoute
    from starlette.websockets import WebSocket, WebSocketDisconnect
except ImportError:
    Starlette = Any  # type: ignore[assignment,misc]
    Request = Any  # type: ignore[assignment,misc]
    JSONResponse = Any  # type: ignore[assignment,misc]
    Response = Any  # type: ignore[assignment,misc]
    Route = Any  # type: ignore[assignment,misc]
    WebSocketRoute = Any  # type: ignore[assignment,misc]
    WebSocket = Any  # type: ignore[assignment,misc]
    WebSocketDisconnect = Exception  # type: ignore[assignment,misc]

from cosmos_mcp.core import config as _core_cfg_mod
from cosmos_mcp.core.fs_tx import atomic_write_json
from cosmos_mcp.core.guard import WorkspaceGuard
from cosmos_mcp.core.net_power import SleepInhibitor
from cosmos_mcp.core.proc import ProcessManager, append_audit_log
from cosmos_mcp.protocol import tools as ct_mod
from cosmos_mcp import packs as dp_mod
from cosmos_mcp.protocol.dispatcher import KernelDispatcher, VPS_HUB_WORKSPACE_TOOL_BASES
from cosmos_mcp.protocol.jsonrpc_lite import JsonRpcLiteServer

try:
    from cosmos_mcp.protocol.transport import (
        build_allowed_hosts,
        build_allowed_origins,
        create_lowlevel_mcp_server,
        create_protocol_app,
    )
except ImportError:
    build_allowed_hosts = None  # type: ignore[assignment]
    build_allowed_origins = None  # type: ignore[assignment]
    create_lowlevel_mcp_server = None  # type: ignore[assignment]
    create_protocol_app = None  # type: ignore[assignment]

try:
    from cosmos_mcp.protocol.oauth import (
        OAuthSQLiteStore,
        TrustedGatewayEndpoint,
        build_trusted_gateway_endpoint,
        get_current_request_gateway,
    )
except ImportError:
    OAuthSQLiteStore = None  # type: ignore[assignment,misc]
    TrustedGatewayEndpoint = Any  # type: ignore[assignment,misc]
    build_trusted_gateway_endpoint = None  # type: ignore[assignment]
    get_current_request_gateway = None  # type: ignore[assignment]

from cosmos_mcp.core.config import (
    DEFAULT_REDIRECT_HOSTS,
    DEFAULT_TIER,
    PRODUCT_VERSION,
    KillSignalWatchdog,
    LiveRuntimePolicy,
    ensure_initialized,
    normalize_prefix,
    normalize_tier,
    parse_bool_flag,
    register_active_server_pid,
    resolve_device_label,
    resolve_service_cfg_path,
    resolve_state_root,
    to_short_tier_code,
)
from cosmos_mcp.launcher.cf_workers_gateway import (
    FRAME_REQ_BODY,
    FRAME_REQ_END,
    FRAME_REQ_HEAD,
    FRAME_RES_BODY,
    FRAME_RES_END,
    FRAME_RES_HEAD,
    REQ_BODY_CHUNK_BYTES,
    pack_tunnel_frame,
    unpack_tunnel_frame,
)
from cosmos_mcp.launcher.cli import resolve_default_workspace
from cosmos_mcp.launcher.tunnels import vps_node_secret_path
from cosmos_mcp.protocol.skill_renderer import build_server_instructions
from cosmos_mcp.studio.routes import StandaloneOAuthProvider, mount_standalone_status_ui


def _serialize_tool_result_for_rpc(raw_out: Any) -> Any:
    """Ensure tool output (including `mcp.types` content blocks) is JSON-serializable for `/_cosmos_node/exec`."""
    if isinstance(raw_out, (str, int, float, bool)) or raw_out is None:
        return raw_out
    if isinstance(raw_out, dict):
        return {str(k): _serialize_tool_result_for_rpc(v) for k, v in raw_out.items()}
    if isinstance(raw_out, (list, tuple)):
        return [_serialize_tool_result_for_rpc(x) for x in raw_out]
    dump_fn = getattr(raw_out, "model_dump", None)
    if callable(dump_fn):
        with contextlib.suppress(Exception):
            return dump_fn(mode="json")
    return str(raw_out)


class _OfflineRemoteWorkspaceHook:
    """Return structured `ERR_NODE_OFFLINE` when `target='auto'` targets an offline registered child node's workspace."""

    def __init__(self, dispatcher: KernelDispatcher, policy: LiveRuntimePolicy) -> None:
        self.dispatcher = dispatcher
        self.policy = policy

    def before_call(self, ctx: Any) -> Optional[Dict[str, Any]]:
        if str(getattr(ctx, "session_hint", "") or "") == "vps_hub_node":
            return None
        nodes = self.dispatcher.list_remote_nodes()
        if not nodes:
            return None
        args = getattr(ctx, "arguments", None)
        if not isinstance(args, dict):
            args = {}
        cand_paths: List[str] = []
        for pk in ("path", "cwd", "destination"):
            pv = args.get(pk)
            if isinstance(pv, str) and pv.strip() and pv.strip() != ".":
                cand_paths.append(pv.strip())
        if not cand_paths:
            return None
        for cp in cand_paths:
            with contextlib.suppress(Exception):
                if self.policy.is_path_allowed(cp):
                    continue
            cp_norm = cp.replace("\\", "/").rstrip("/").lower()
            m_drv = re.match(r"^([A-Za-z]:)(?:[\\/]|$)", cp)
            drv_low = m_drv.group(1).lower() if m_drv else ""
            for n_info in nodes:
                if n_info.get("online", False):
                    continue
                nid = str(n_info.get("node_id") or "pc")
                for r_ws in n_info.get("workspace_roots") or ():
                    rw_norm = str(r_ws).replace("\\", "/").rstrip("/").lower()
                    if rw_norm and (cp_norm == rw_norm or cp_norm.startswith(rw_norm + "/")):
                        return {
                            "ok": False,
                            "error_code": "ERR_NODE_OFFLINE",
                            "target": nid,
                            "message": f"目标节点 '{nid}' 当前离线或关机，主站服务仍在线运行。",
                        }
                if drv_low and drv_low in (n_info.get("drives") or ()):
                    return {
                        "ok": False,
                        "error_code": "ERR_NODE_OFFLINE",
                        "target": nid,
                        "message": f"目标节点 '{nid}' 当前离线或关机，主站服务仍在线运行。",
                    }
        return None

    def after_call(self, ctx: Any, result: Any, exc: Optional[BaseException], duration_ms: float) -> Any:
        _ = (ctx, exc, duration_ms)
        return result


class _HubChildNodeWsSession:
    """Multiplexes 17-byte binary HTTP frames over a connected `/_cosmos_node` WebSocket."""

    def __init__(self, node_id: str, websocket: Any) -> None:
        self.node_id = node_id
        self.websocket = websocket
        self.send_lock = asyncio.Lock()
        self.pending: Dict[bytes, asyncio.Queue[Tuple[int, bytes]]] = {}
        self.closed = False

    async def request_http(
        self,
        method: str,
        path_qs: str,
        body_bytes: bytes = b"",
        *,
        headers: Optional[Dict[str, str]] = None,
        timeout_sec: float = 90.0,
    ) -> Tuple[int, bytes]:
        if self.closed:
            raise ConnectionError(f"Child node '{self.node_id}' WebSocket is closed")
        req_id = uuid.uuid4().bytes
        q: asyncio.Queue[Tuple[int, bytes]] = asyncio.Queue()
        self.pending[req_id] = q
        try:
            head_bytes = json.dumps(
                {"method": method.upper(), "path_qs": path_qs, "headers": headers or {"content-type": "application/json"}},
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            async with self.send_lock:
                if self.closed:
                    raise ConnectionError(f"Child node '{self.node_id}' WebSocket is closed")
                await self.websocket.send_bytes(pack_tunnel_frame(FRAME_REQ_HEAD, req_id, head_bytes))
                for off in range(0, len(body_bytes), REQ_BODY_CHUNK_BYTES):
                    chunk = body_bytes[off : off + REQ_BODY_CHUNK_BYTES]
                    await self.websocket.send_bytes(pack_tunnel_frame(FRAME_REQ_BODY, req_id, chunk))
                await self.websocket.send_bytes(pack_tunnel_frame(FRAME_REQ_END, req_id, b""))

            status_code = 200
            chunks: List[bytes] = []
            deadline = time.monotonic() + max(1.0, float(timeout_sec))
            while True:
                rem = deadline - time.monotonic()
                if rem <= 0:
                    raise TimeoutError(f"Child node '{self.node_id}' RPC timed out after {timeout_sec}s")
                ft, pl = await asyncio.wait_for(q.get(), timeout=rem)
                if ft == 0xFF:
                    raise ConnectionError(f"Child node '{self.node_id}' disconnected during RPC")
                if ft == FRAME_RES_HEAD:
                    with contextlib.suppress(Exception):
                        meta = json.loads(pl.decode("utf-8"))
                        status_code = int(meta.get("status") or 200)
                elif ft == FRAME_RES_BODY:
                    if pl:
                        chunks.append(pl)
                elif ft == FRAME_RES_END:
                    break
            return status_code, b"".join(chunks)
        except Exception as exc:
            if isinstance(exc, (ConnectionError, TimeoutError, OSError)):
                raise
            raise ConnectionError(str(exc)) from exc
        finally:
            self.pending.pop(req_id, None)

    def mark_closed_and_abort_pending(self) -> None:
        self.closed = True
        for q in list(self.pending.values()):
            with contextlib.suppress(Exception):
                q.put_nowait((0xFF, b""))


def _mount_vps_hub_node_routes(
    app: Starlette,
    *,
    dispatcher: KernelDispatcher,
    policy: LiveRuntimePolicy,
    state_root: Path,
    slot_prefix: str,
) -> None:
    """Mount `/_cosmos_node` WebSocket child-node registration/forwarding + local `/_cosmos_node/{info,exec}`."""
    active_sessions: Dict[str, _HubChildNodeWsSession] = {}
    app.state.cosmos_node_sessions = active_sessions

    def _resolve_expected_node_secret() -> str:
        env_sec = (os.environ.get("COSMOS_NODE_SECRET") or "").strip()
        if env_sec:
            return env_sec
        cfg_p = resolve_service_cfg_path(state_root, slot_prefix)
        if cfg_p.is_file():
            with contextlib.suppress(Exception):
                doc = json.loads(cfg_p.read_text(encoding="utf-8-sig"))
                if isinstance(doc, dict) and str(doc.get("vps_node_secret") or "").strip():
                    return str(doc["vps_node_secret"]).strip()
        for sec_p in (vps_node_secret_path(state_root, prefix=slot_prefix), state_root / "secrets" / "vps_node_secret.txt"):
            if sec_p.is_file():
                with contextlib.suppress(OSError):
                    val = sec_p.read_text(encoding="utf-8", errors="replace").strip()
                    if val:
                        return val
        return ""

    def _verify_local_node_rpc(request: Request) -> bool:
        peer = str((request.client.host if request.client else "") or "").strip().lower()
        if peer not in ("127.0.0.1", "::1", "localhost", "testclient"):
            return False
        if request.headers.get("x-cosmos-via-tunnel"):
            return False
        bb = getattr(app.state, "bearer_backend", None)
        expected_tok = str(getattr(bb, "local_api_token", "") or "").strip()
        if not expected_tok:
            return False
        cand = (request.headers.get("x-cosmos-local-token") or "").strip()
        if not cand:
            auth_h = (request.headers.get("authorization") or "").strip()
            if auth_h.lower().startswith("bearer "):
                cand = auth_h[7:].strip()
        return bool(cand and hmac.compare_digest(cand.encode("utf-8"), expected_tok.encode("utf-8")))

    async def _node_local_info_endpoint(request: Request) -> Response:
        if not _verify_local_node_rpc(request):
            return JSONResponse({"ok": False, "error": "forbidden"}, status_code=403)
        policy.refresh()
        roots = [str(p) for p in policy.workspace_roots]
        drives: List[str] = []
        for ws_s in roots:
            m_drv = re.match(r"^([A-Za-z]:)(?:[\\/]|$)", ws_s)
            if m_drv:
                dl = m_drv.group(1).lower()
                if dl not in drives:
                    drives.append(dl)
        return JSONResponse(
            {
                "ok": True,
                "node_id": getattr(policy, "tool_prefix", policy.eff_prefix),
                "prefix": policy.eff_prefix,
                "device_label": policy.device_label,
                "platform": sys.platform,
                "workspace_roots": roots,
                "drives": drives,
            }
        )

    async def _node_local_exec_endpoint(request: Request) -> Response:
        if not _verify_local_node_rpc(request):
            return JSONResponse({"ok": False, "error": "forbidden"}, status_code=403)
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"ok": False, "error": "invalid_json"}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"ok": False, "error": "invalid_payload"}, status_code=400)
        tool_nm = str(body.get("base_name") or body.get("tool") or "").strip()
        raw_args = body.get("arguments")
        call_args = dict(raw_args) if isinstance(raw_args, dict) else {}
        ro_flag = bool(body.get("readonly_only", False))
        raw_sc = body.get("scopes")
        scopes_arg = [str(s) for s in raw_sc] if isinstance(raw_sc, list) else None
        raw_out, is_err = await dispatcher.call_tool_raw(
            tool_nm,
            call_args,
            scopes=scopes_arg,
            readonly_only=ro_flag,
            session_hint="vps_hub_node",
        )
        return JSONResponse(
            {
                "ok": True,
                "result": _serialize_tool_result_for_rpc(raw_out),
                "is_error": bool(is_err),
            }
        )

    async def _forward_tool_to_remote_node(
        target_node_id: str,
        base_name: str,
        forward_args: Dict[str, Any],
        *,
        tool_name: str = "",
        readonly_only: bool = False,
        scopes: Any = None,
        caller: str = "",
    ) -> Any:
        nid_low = (target_node_id or "").strip().lower()
        sess = active_sessions.get(nid_low)
        if sess is None and len(active_sessions) == 1:
            only_sess = next(iter(active_sessions.values()))
            if not nid_low or nid_low in ("auto", only_sess.node_id):
                sess = only_sess
        if sess is None or sess.closed:
            raise ConnectionError(f"Child node '{target_node_id}' is currently offline")
        payload_bytes = json.dumps(
            {
                "tool": tool_name or base_name,
                "base_name": base_name,
                "arguments": forward_args,
                "readonly_only": bool(readonly_only),
                "scopes": list(scopes) if scopes is not None else None,
                "caller": caller,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        node_auth_hdrs = {
            "content-type": "application/json",
            "authorization": f"Bearer {_resolve_expected_node_secret()}",
        }
        st_code, resp_bytes = await sess.request_http(
            "POST",
            "/_cosmos_node/exec",
            payload_bytes,
            headers=node_auth_hdrs,
            timeout_sec=90.0,
        )
        if st_code >= 500:
            raise ConnectionError(f"Child node '{target_node_id}' upstream status {st_code}")
        doc = json.loads(resp_bytes.decode("utf-8", errors="replace"))
        if isinstance(doc, dict) and "result" in doc:
            return doc["result"]
        return doc

    async def _cosmos_node_http_guard(request: Request) -> Response:
        expected = _resolve_expected_node_secret()
        auth_h = (request.headers.get("authorization") or "").strip()
        tok = auth_h[7:].strip() if auth_h.lower().startswith("bearer ") else ""
        if not expected or not tok or not hmac.compare_digest(tok.encode("utf-8"), expected.encode("utf-8")):
            return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
        return JSONResponse(
            {"ok": False, "error": "upgrade_required", "detail": "Connect via WebSocket (`/_cosmos_node`)."},
            status_code=426,
            headers={"Upgrade": "websocket"},
        )

    async def _cosmos_node_ws_endpoint(websocket: WebSocket) -> None:
        expected = _resolve_expected_node_secret()
        auth_h = (websocket.headers.get("authorization") or "").strip()
        tok = auth_h[7:].strip() if auth_h.lower().startswith("bearer ") else ""
        if not expected or not tok or not hmac.compare_digest(tok.encode("utf-8"), expected.encode("utf-8")):
            await websocket.close(code=4401)
            return

        await websocket.accept()
        raw_alias = (websocket.headers.get("x-cosmos-node-alias") or "pc").strip().lower()
        node_id = normalize_prefix(raw_alias) if raw_alias else "pc"

        meta_roots: List[str] = []
        meta_drives: List[str] = []
        meta_platform = ""
        meta_label = node_id
        raw_meta_b64 = (websocket.headers.get("x-cosmos-node-meta") or "").strip()
        if raw_meta_b64:
            with contextlib.suppress(Exception):
                padded = raw_meta_b64 + ("=" * (-len(raw_meta_b64) % 4))
                meta_doc = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
                if isinstance(meta_doc, dict):
                    meta_roots = [str(x).strip() for x in (meta_doc.get("workspace_roots") or ()) if str(x).strip()]
                    meta_drives = [str(x).strip() for x in (meta_doc.get("drives") or ()) if str(x).strip()]
                    meta_platform = str(meta_doc.get("platform") or "")
                    meta_label = str(meta_doc.get("device_label") or node_id)

        prev_sess = active_sessions.get(node_id)
        if prev_sess is not None and prev_sess is not websocket:
            prev_sess.mark_closed_and_abort_pending()
            with contextlib.suppress(Exception):
                await prev_sess.websocket.close(code=1012)

        session = _HubChildNodeWsSession(node_id=node_id, websocket=websocket)
        active_sessions[node_id] = session
        dispatcher.set_remote_forwarder(_forward_tool_to_remote_node)
        dispatcher.register_remote_node(
            node_id,
            workspace_roots=meta_roots,
            drives=meta_drives,
            online=True,
            platform_name=meta_platform,
            device_label=meta_label,
            forwarder=_forward_tool_to_remote_node,
        )

        async def _sync_live_node_info() -> None:
            with contextlib.suppress(Exception):
                info_hdrs = {
                    "accept": "application/json",
                    "authorization": f"Bearer {_resolve_expected_node_secret()}",
                }
                st_c, body_b = await session.request_http(
                    "GET",
                    "/_cosmos_node/info",
                    b"",
                    headers=info_hdrs,
                    timeout_sec=5.0,
                )
                if st_c == 200 and active_sessions.get(node_id) is session and not session.closed:
                    info_doc = json.loads(body_b.decode("utf-8", errors="replace"))
                    if isinstance(info_doc, dict) and info_doc.get("ok"):
                        dispatcher.register_remote_node(
                            node_id,
                            workspace_roots=info_doc.get("workspace_roots") or meta_roots,
                            drives=info_doc.get("drives") or meta_drives,
                            online=True,
                            platform_name=str(info_doc.get("platform") or meta_platform),
                            device_label=str(info_doc.get("device_label") or meta_label),
                            forwarder=_forward_tool_to_remote_node,
                        )

        sync_task = asyncio.create_task(_sync_live_node_info())
        try:
            while True:
                msg = await websocket.receive()
                msg_type = msg.get("type")
                if msg_type == "websocket.disconnect":
                    break
                raw_bytes = msg.get("bytes")
                if raw_bytes and len(raw_bytes) >= 17:
                    ft, rid, pl = unpack_tunnel_frame(raw_bytes)
                    q = session.pending.get(rid)
                    if q is not None:
                        await q.put((ft, pl))
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            sync_task.cancel()
            session.mark_closed_and_abort_pending()
            if active_sessions.get(node_id) is session:
                active_sessions.pop(node_id, None)
                dispatcher.unregister_remote_node(node_id, keep_offline_record=True)

    if (
        dispatcher.is_vps_hub_active()
        and _resolve_expected_node_secret()
        and not dispatcher.list_remote_nodes()
    ):
        paired_nid = "pc"
        cfg_p_boot = resolve_service_cfg_path(state_root, slot_prefix)
        if cfg_p_boot.is_file():
            with contextlib.suppress(Exception):
                boot_doc = json.loads(cfg_p_boot.read_text(encoding="utf-8-sig"))
                if isinstance(boot_doc, dict):
                    raw_pnid = str(boot_doc.get("paired_node_id") or boot_doc.get("child_node_id") or "").strip()
                    if raw_pnid:
                        paired_nid = normalize_prefix(raw_pnid)
        dispatcher.set_remote_forwarder(_forward_tool_to_remote_node)
        dispatcher.register_remote_node(
            paired_nid,
            online=False,
            forwarder=_forward_tool_to_remote_node,
        )

    app.router.routes[0:0] = [
        WebSocketRoute("/_cosmos_node", endpoint=_cosmos_node_ws_endpoint),
        Route("/_cosmos_node", endpoint=_cosmos_node_http_guard, methods=["GET", "POST"]),
        Route("/_cosmos_node/info", endpoint=_node_local_info_endpoint, methods=["GET"]),
        Route("/_cosmos_node/exec", endpoint=_node_local_exec_endpoint, methods=["POST"]),
    ]


def _clean_public_gateway_url(raw_val: Any) -> str:
    """Validate and normalize a public gateway base URL (rejecting loopback and deprecated dead placeholders)."""
    s = str(raw_val or "").strip().rstrip("/")
    if not s or not s.startswith(("http://", "https://")):
        return ""
    u = urlsplit(s)
    host = (u.hostname or "").strip().lower()
    if not host or host in ("127.0.0.1", "localhost", "::1"):
        return ""
    if host.startswith("gw.cosmos-mcp.") and host.endswith((".org", ".workers.dev")):
        return ""
    return s


def _daemon_status_json_path(state_root: Path, slot_prefix: str) -> Path:
    eff = normalize_prefix(slot_prefix)
    return state_root / "state" / (f"daemon_status_{eff}.json" if eff != "pc" else "daemon_status.json")


def _read_daemon_status_doc(state_root: Path, slot_prefix: str) -> Dict[str, Any]:
    dp = _daemon_status_json_path(state_root, slot_prefix)
    if not dp.is_file():
        return {}
    with contextlib.suppress(Exception):
        loaded = json.loads(dp.read_text(encoding="utf-8-sig"))
        if isinstance(loaded, dict):
            return loaded
    return {}


def _extract_active_gateways_and_grace(
    cfg_doc: Mapping[str, Any],
    d_doc: Mapping[str, Any],
    policy: Optional[LiveRuntimePolicy],
    *,
    port: int,
    explicit_public_url: str = "",
    fallback_tunnel_mode: str = "",
    include_explicit: bool = False,
) -> Tuple[List[Any], str, str, List[str]]:
    """Extract all enabled `TrustedGatewayEndpoint` entries from `service.json` + `daemon_status.json`."""
    d_running = bool(d_doc and str(d_doc.get("status") or "running").strip().lower() not in ("", "stopped"))
    d_gws = d_doc.get("gateways") if (d_running and isinstance(d_doc.get("gateways"), Mapping)) else {}

    raw_cfg_gws = cfg_doc.get("gateways") if isinstance(cfg_doc, Mapping) else None
    if not isinstance(raw_cfg_gws, Mapping) and policy is not None and not cfg_doc:
        pol_gws = getattr(policy, "gateways", None)
        if isinstance(pol_gws, Mapping):
            raw_cfg_gws = pol_gws

    endpoints: List[Any] = []
    seen_ep_keys: set[Tuple[str, str]] = set()
    disabled_urls_low: set[str] = set()

    def _add_ep(url_s: str, gw_id: str, tm: str) -> None:
        if build_trusted_gateway_endpoint is None or not url_s:
            return
        ep_obj = build_trusted_gateway_endpoint(url_s, gateway_id=gw_id, tunnel_mode=tm, local_port=port)
        if ep_obj is not None and not ep_obj.is_loopback:
            key = (ep_obj.authority, ep_obj.public_prefix.lower())
            if key not in seen_ep_keys:
                seen_ep_keys.add(key)
                endpoints.append(ep_obj)

    selected_gw = str((cfg_doc or {}).get("selected_gateway") or "").strip().lower()
    raw_tm = str((cfg_doc or {}).get("tunnel_mode") or (cfg_doc or {}).get("mode") or fallback_tunnel_mode or "local").strip().lower()

    if isinstance(raw_cfg_gws, Mapping) and len(raw_cfg_gws) > 0:
        eff_cfg_gws: Dict[str, Mapping[str, Any]] = {}
        norm_fn = getattr(_core_cfg_mod, "normalize_gateways_config", None)
        if callable(norm_fn):
            with contextlib.suppress(Exception):
                norm_slots, norm_sel = norm_fn(dict(cfg_doc))
                if isinstance(norm_slots, Mapping):
                    for k_s, v_s in norm_slots.items():
                        if isinstance(v_s, Mapping):
                            eff_cfg_gws[str(k_s)] = v_s
                if not selected_gw and norm_sel:
                    selected_gw = str(norm_sel).strip().lower()
        for k_raw, v_raw in raw_cfg_gws.items():
            ks = str(k_raw)
            if isinstance(v_raw, Mapping) and ks not in eff_cfg_gws:
                eff_cfg_gws[ks] = v_raw

        ordered_ids: List[str] = []
        if selected_gw and (selected_gw in eff_cfg_gws or selected_gw in d_gws):
            ordered_ids.append(selected_gw)
        for gid_cand in (*eff_cfg_gws.keys(), *d_gws.keys()):
            gs = str(gid_cand)
            if gs not in ordered_ids:
                ordered_ids.append(gs)

        primary_tm_resolved = ""
        for gid in ordered_ids:
            c_slot = eff_cfg_gws.get(gid)
            d_slot = d_gws.get(gid) if isinstance(d_gws.get(gid), Mapping) else None
            if c_slot is not None and "enabled" in c_slot:
                enabled = parse_bool_flag(c_slot.get("enabled"), default=False)
            elif d_slot is not None and "enabled" in d_slot:
                enabled = (
                    parse_bool_flag(d_slot.get("enabled"), default=False)
                    and str(d_slot.get("phase") or "").strip().lower() != "disabled"
                )
            else:
                enabled = bool(
                    _clean_public_gateway_url((c_slot or {}).get("public_url"))
                    or _clean_public_gateway_url((d_slot or {}).get("public_url"))
                )
            c_url = _clean_public_gateway_url((c_slot or {}).get("public_url"))
            d_slot_off = d_slot is not None and (
                d_slot.get("enabled") is False or str(d_slot.get("phase") or "").strip().lower() == "disabled"
            )
            d_url = "" if d_slot_off else _clean_public_gateway_url((d_slot or {}).get("public_url"))
            extra_slot_urls: List[str] = []
            if gid == "workers_dev":
                wd_raw = _clean_public_gateway_url(
                    (c_slot or {}).get("workers_dev_url") or (cfg_doc or {}).get("workers_dev_url")
                )
                if not wd_raw:
                    w_sc = str((cfg_doc or {}).get("workers_script_name") or (cfg_doc or {}).get("workers_dev_script_name") or "").strip()
                    w_sb = str((cfg_doc or {}).get("workers_subdomain") or (cfg_doc or {}).get("workers_dev_subdomain") or "").strip()
                    if w_sc and w_sb:
                        wd_raw = _clean_public_gateway_url(f"https://{w_sc}.{w_sb}.workers.dev")
                wc_dom_raw = str(
                    (c_slot or {}).get("custom_domain")
                    or (cfg_doc or {}).get("workers_custom_domain")
                    or (cfg_doc or {}).get("workers_dev_custom_domain")
                    or ""
                ).strip()
                if wc_dom_raw and "://" not in wc_dom_raw:
                    wc_dom_raw = f"https://{wc_dom_raw}"
                wc_raw = _clean_public_gateway_url(wc_dom_raw)
                for xu in (wd_raw, wc_raw):
                    if xu and xu not in extra_slot_urls:
                        extra_slot_urls.append(xu)
            elif gid == "self_hosted":
                sh_dom_raw = str((c_slot or {}).get("custom_domain") or "").strip()
                if sh_dom_raw and "://" not in sh_dom_raw:
                    sh_dom_raw = f"https://{sh_dom_raw}"
                sh_dom = _clean_public_gateway_url(sh_dom_raw)
                if sh_dom:
                    extra_slot_urls.append(sh_dom)
            if not enabled:
                for off_u in (c_url, d_url, *extra_slot_urls):
                    if off_u:
                        disabled_urls_low.add(off_u.lower())
                continue
            submode = str(
                (c_slot or {}).get("submode")
                or (c_slot or {}).get("tunnel_mode")
                or (d_slot or {}).get("effective_mode")
                or (d_slot or {}).get("submode")
                or ""
            ).strip().lower()
            if not submode:
                submode = (
                    "public_gateway"
                    if gid == "instant"
                    else ("workers_dev" if gid == "workers_dev" else ("vps_hub" if gid == "self_hosted" else (raw_tm or "custom")))
                )
            if gid == "instant" and submode == "cloudflare":
                if d_url.lower().endswith(".srv.us"):
                    d_url = ""
                if c_url.lower().endswith(".srv.us"):
                    c_url = ""
            slot_primary = d_url or c_url or (extra_slot_urls[0] if extra_slot_urls else "")
            if slot_primary:
                _add_ep(slot_primary, gid, submode)
                if d_url and c_url and d_url.lower() != c_url.lower():
                    _add_ep(c_url, gid, submode)
                for xu in extra_slot_urls:
                    if xu.lower() != slot_primary.lower():
                        _add_ep(xu, gid, submode)
            if not primary_tm_resolved:
                primary_tm_resolved = submode

        if include_explicit and explicit_public_url:
            exp_u = _clean_public_gateway_url(explicit_public_url)
            if exp_u:
                _add_ep(exp_u, "explicit", primary_tm_resolved or fallback_tunnel_mode or "local")

        if endpoints:
            primary_pub = endpoints[0].base_url
            primary_tm = primary_tm_resolved or endpoints[0].tunnel_mode or raw_tm or "public_gateway"
        elif include_explicit and _clean_public_gateway_url(explicit_public_url):
            primary_pub = _clean_public_gateway_url(explicit_public_url)
            primary_tm = fallback_tunnel_mode or raw_tm or "local"
        else:
            primary_pub = f"http://127.0.0.1:{int(port)}"
            primary_tm = primary_tm_resolved or ("local" if raw_tm == "local" else raw_tm) or "local"
    else:
        # Legacy scalar `service.json` fallback (plus `daemon_status.json` gateways if present)
        if raw_tm != "local" and d_gws:
            for gid, d_slot in d_gws.items():
                if not isinstance(d_slot, Mapping):
                    continue
                if not parse_bool_flag(d_slot.get("enabled"), default=False) or str(d_slot.get("phase") or "").strip().lower() == "disabled":
                    du_off = _clean_public_gateway_url(d_slot.get("public_url"))
                    if du_off:
                        disabled_urls_low.add(du_off.lower())
                    continue
                du = _clean_public_gateway_url(d_slot.get("public_url"))
                sm = str(d_slot.get("effective_mode") or d_slot.get("submode") or raw_tm or "public_gateway").strip().lower()
                if du:
                    _add_ep(du, str(gid), sm)

        exp_u = _clean_public_gateway_url(explicit_public_url) if include_explicit else ""
        if exp_u:
            _add_ep(exp_u, "explicit", fallback_tunnel_mode or raw_tm or "local")

        if raw_tm != "local":
            scalar_candidates = [
                _clean_public_gateway_url((cfg_doc or {}).get("public_base") or (cfg_doc or {}).get("public_base_url")),
                _clean_public_gateway_url((cfg_doc or {}).get("public_gateway_url")) if raw_tm in ("public_gateway", "srv_us") else "",
                _clean_public_gateway_url((cfg_doc or {}).get("workers_dev_url")) if raw_tm == "workers_dev" else "",
                _clean_public_gateway_url((cfg_doc or {}).get("vps_hub_url")) if raw_tm in ("vps_hub", "vps") else "",
                _clean_public_gateway_url((d_doc or {}).get("public_url")) if d_running else "",
            ]
            slot_for_tm = "workers_dev" if raw_tm == "workers_dev" else ("self_hosted" if raw_tm in ("vps_hub", "vps", "custom") else "instant")
            for sc_u in scalar_candidates:
                if sc_u:
                    _add_ep(sc_u, slot_for_tm, raw_tm)

        if endpoints:
            primary_pub = exp_u or endpoints[0].base_url
            primary_tm = raw_tm or endpoints[0].tunnel_mode or "local"
        else:
            primary_pub = f"http://127.0.0.1:{int(port)}"
            primary_tm = raw_tm or "local"

    raw_extra_trusted = (cfg_doc or {}).get("extra_trusted_urls")
    if isinstance(raw_extra_trusted, (list, tuple)):
        for et_item in raw_extra_trusted:
            et_u = _clean_public_gateway_url(et_item)
            if et_u and et_u.lower() not in disabled_urls_low:
                _add_ep(et_u, "extra_trusted", "custom")

    grace_bases: List[str] = []
    seen_grace: set[str] = set()
    for list_key in ("previous_public_bases", "pinned_gateway_urls"):
        raw_seq = (cfg_doc or {}).get(list_key)
        if isinstance(raw_seq, (list, tuple)):
            for item in raw_seq:
                gu = _clean_public_gateway_url(item)
                if gu and gu.lower() not in disabled_urls_low and gu.lower() not in seen_grace:
                    seen_grace.add(gu.lower())
                    grace_bases.append(gu)
                    if list_key == "pinned_gateway_urls" and endpoints:
                        gu_low = gu.lower()
                        inst_on = any(getattr(e, "gateway_id", "") == "instant" for e in endpoints)
                        wk_on = any(getattr(e, "gateway_id", "") == "workers_dev" for e in endpoints)
                        if gu_low.endswith(".srv.us") and inst_on:
                            _add_ep(gu, "instant", "srv_us")
                        elif gu_low.endswith(".workers.dev") and wk_on:
                            _add_ep(gu, "workers_dev", "workers_dev")

    return endpoints, primary_pub, primary_tm, grace_bases


def _extract_http_origin(raw_url: str) -> str:
    """Extract canonical browser `Origin` (`scheme://netloc`, without path) via `urlsplit`."""
    u = urlsplit((raw_url or "").strip())
    if u.scheme and u.netloc:
        return f"{u.scheme.lower()}://{u.netloc.lower()}"
    return ""


def _normalize_origin_entries(raw_origins: Sequence[str], extra_urls: Sequence[str] = ()) -> List[str]:
    """Normalize `allowed_origins` entries so path-bearing gateway URLs register `scheme://netloc`."""
    out: List[str] = []
    seen: set[str] = set()
    for item in (*raw_origins, *extra_urls):
        s = str(item or "").strip().rstrip("/")
        if not s:
            continue
        if s.endswith(":*"):
            cand = s.lower()
        else:
            cand = _extract_http_origin(s) or s.lower()
        if cand and cand not in seen:
            seen.add(cand)
            out.append(cand)
    return out


def _collect_all_origin_guards(app_obj: Any, known_guards: Sequence[Any]) -> List[Any]:
    found: List[Any] = []
    seen_ids: set[int] = set()

    def _visit(node: Any, depth: int = 0) -> None:
        if node is None or depth > 8 or id(node) in seen_ids:
            return
        seen_ids.add(id(node))
        if isinstance(getattr(node, "exact_origins", None), set):
            found.append(node)
        for attr in ("app", "inner_app", "inner", "endpoint"):
            inner = getattr(node, attr, None)
            if inner is not None and inner is not node:
                _visit(inner, depth + 1)

    for g in known_guards:
        _visit(g)
    state_guards = getattr(getattr(app_obj, "state", None), "origin_guards", ())
    for g in state_guards or ():
        _visit(g)
    for rt in getattr(getattr(app_obj, "router", None), "routes", ()):
        _visit(getattr(rt, "endpoint", None))
        _visit(getattr(rt, "app", None))
    return found


def _make_workspace_guard(
    *,
    workspace_roots: Any,
    readonly_workspace_roots: Any = None,
    allow_host_global_skills: bool = False,
    restrict_to_workspace: bool = True,
    tier: str = "L3",
    state_root: Optional[Path] = None,
    product_root: Optional[Path] = None,
    tool_prefix: str = "pc",
) -> WorkspaceGuard:
    init_params = inspect.signature(WorkspaceGuard.__init__).parameters
    kwargs: Dict[str, Any] = {
        "workspace_roots": workspace_roots,
        "readonly_workspace_roots": readonly_workspace_roots,
        "restrict_to_workspace": restrict_to_workspace,
        "tier": tier,
        "state_root": state_root,
        "product_root": product_root,
        "tool_prefix": tool_prefix,
    }
    if "allow_host_global_skills" in init_params:
        kwargs["allow_host_global_skills"] = bool(allow_host_global_skills)
    guard = WorkspaceGuard(**kwargs)
    try:
        setattr(guard, "allow_host_global_skills", bool(allow_host_global_skills))
    except Exception:
        pass
    return guard


def _sync_guard_workspace_policy(
    guard: Optional[WorkspaceGuard],
    *,
    workspace_roots: Any,
    restrict_to_workspace: bool,
    tier_key: str,
    readonly_workspace_roots: Any = None,
    allow_host_global_skills: bool = False,
    tool_prefix: str = "",
    state_root: Optional[Path] = None,
    product_root: Optional[Path] = None,
) -> None:
    if guard is None:
        return
    if tool_prefix:
        guard.tool_prefix = normalize_prefix(tool_prefix)
    try:
        setattr(guard, "allow_host_global_skills", bool(allow_host_global_skills))
    except Exception:
        pass
    set_params = inspect.signature(guard.set_workspace_policy).parameters
    call_kw: Dict[str, Any] = {
        "restrict_to_workspace": restrict_to_workspace,
        "tier_key": to_short_tier_code(tier_key, restrict_to_workspace=restrict_to_workspace),
        "readonly_workspace_roots": readonly_workspace_roots,
    }
    if state_root is not None and "state_root" in set_params:
        call_kw["state_root"] = state_root
    if product_root is not None and "product_root" in set_params:
        call_kw["product_root"] = product_root
    if "allow_host_global_skills" in set_params:
        call_kw["allow_host_global_skills"] = bool(allow_host_global_skills)
    guard.set_workspace_policy(workspace_roots, **call_kw)


def _collect_skills_snapshot(policy: LiveRuntimePolicy) -> Dict[str, Any]:
    """Scan workspace `.agents/skills` and managed skills count for `pc_get_status` discovery."""
    try:
        from cosmos_mcp.capabilities.skills.models import SkillsConfig
        from cosmos_mcp.capabilities.skills.parser_and_index import scan_local_skills

        cfg = SkillsConfig(
            workspace_roots=[str(p) for p in policy.workspace_roots],
            state_root=policy.state_root,
            auto_discover_host_roots=bool(getattr(policy, "scan_host_global_skills", False)),
        )
        records = scan_local_skills(cfg, include_disabled=False)
        ws_skills = [
            {"name": r.name, "description": r.description}
            for r in records
            if r.source_scope in ("workspace", "workspace_claude", "project")
        ]
        managed_cnt = sum(
            1
            for r in records
            if r.source_scope in ("managed", "workspace", "workspace_claude", "project")
        )
        return {
            "workspace_skills": ws_skills,
            "workspace_skill_count": len(ws_skills),
            "managed_skill_count": managed_cnt,
        }
    except Exception:
        return {
            "workspace_skills": [],
            "workspace_skill_count": 0,
            "managed_skill_count": 0,
        }


def _mount_l1_capabilities(
    dispatcher: KernelDispatcher,
    policy: LiveRuntimePolicy,
    guard: WorkspaceGuard,
    proc_mgr: ProcessManager,
    *,
    mcp_port: Union[int, Callable[[], int]] = 0,
    mcp_public_url: Union[str, Callable[[], str]] = "",
) -> None:
    def _live_policy_snapshot() -> Dict[str, Any]:
        policy.refresh()
        active_specs = dispatcher.active_tool_specs()
        skills_snap = _collect_skills_snapshot(policy)
        raw_p = mcp_port() if callable(mcp_port) else mcp_port
        try:
            eff_port = int(raw_p or 0)
        except (TypeError, ValueError):
            eff_port = 0
        if eff_port <= 0:
            eff_port = int(getattr(policy, "port", 0) or 8096)
        return {
            "port": eff_port,
            "prefix": policy.eff_prefix,
            "instance_id": getattr(policy, "instance_id", policy.eff_prefix),
            "tool_prefix": getattr(policy, "tool_prefix", policy.eff_prefix),
            "tier": policy.tier_key,
            "workspace": policy.workspace,
            "workspace_roots": [str(p) for p in policy.workspace_roots],
            "readonly_workspace_roots": [str(p) for p in getattr(policy, "readonly_workspace_roots", ())],
            "scan_host_global_skills": bool(getattr(policy, "scan_host_global_skills", False)),
            "tray_enabled": bool(getattr(policy, "tray_enabled", True)),
            "state_root": str(policy.state_root),
            "device_label": policy.device_label,
            "toolset_profile": policy.toolset_profile,
            "prompt_profile": policy.prompt_profile,
            "enabled_packs": list(policy.enabled_packs),
            "keep_awake": policy.keep_awake,
            "python_path": str(getattr(policy, "python_path", "") or ""),
            "annotation_mode": str(getattr(policy, "annotation_mode", "") or ("honest" if policy.approval_popups else "compat")),
            "active_tool_count": len(active_specs),
            "exposed_tools": [sp.base_name for sp in active_specs],
            "version": PRODUCT_VERSION,
            **skills_snap,
        }

    core_specs, core_hooks = ct_mod.build_core_tools(
        guard=guard,
        proc_mgr=proc_mgr,
        policy_getter=_live_policy_snapshot,
    )
    dispatcher.register_tools(core_specs)
    for hk in core_hooks:
        dispatcher.add_execution_hook(hk)

    def _persist_audit_event(ev: Any) -> None:
        append_audit_log(
            policy.state_root / "logs" / "audit.jsonl",
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

    def _is_remote_mcp_session() -> bool:
        with contextlib.suppress(Exception):
            from cosmos_mcp.protocol import transport as _tr_mod

            ctx_var = getattr(_tr_mod, "_REQUEST_TRANSPORT_CTX", None)
            if ctx_var is not None and ctx_var in contextvars.copy_context():
                return bool(getattr(ctx_var.get(), "is_remote", False))
        return False

    try:
        packs_raw = dp_mod.build_default_device_packs(
            guard=guard,
            proc_manager=proc_mgr,
            policy=policy,
            state_root=policy.state_root,
            prefix=policy.eff_prefix,
            mcp_port=mcp_port,
            mcp_public_url=mcp_public_url,
        )
        pack_plugins = list(packs_raw.values()) if isinstance(packs_raw, dict) else list(packs_raw)
        for _pk in pack_plugins:
            if getattr(_pk, "pack_id", "") == "browser" or _pk.__class__.__name__ == "BrowserPackPlugin":
                _pk.is_remote_session_fn = _is_remote_mcp_session  # type: ignore[attr-defined]
    except TypeError:
        pack_plugins = [
            dp_mod.BrowserPackPlugin(
                guard=guard,
                policy=policy,
                state_root=policy.state_root,
                prefix=policy.eff_prefix,
                mcp_port=mcp_port,
                mcp_public_url=mcp_public_url,
                is_remote_session_fn=_is_remote_mcp_session,
            ),
        ]
        if sys.platform == "win32":
            pack_plugins.append(
                dp_mod.CuaWindowPackPlugin(
                    guard=guard,
                    proc_manager=proc_mgr,
                    policy=policy,
                    state_root=policy.state_root,
                    prefix=policy.eff_prefix,
                )
            )
    seen_pack_ids: set[str] = set()
    for pk in pack_plugins:
        pid_key = str(getattr(pk, "pack_id", id(pk)))
        if sys.platform != "win32" and (
            pid_key.lower() in ("cua", "desktop") or pk.__class__.__name__ == "CuaWindowPackPlugin"
        ):
            continue
        if pid_key not in seen_pack_ids:
            seen_pack_ids.add(pid_key)
            dispatcher.register_pack(pk)


class _WinSafeRotatingFileHandler(RotatingFileHandler):
    """RotatingFileHandler that releases its OS file descriptor after each write to avoid WinError 32 locks."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            super().emit(record)
        finally:
            if self.stream is not None:
                try:
                    self.stream.flush()
                    self.stream.close()
                except Exception:
                    pass
                self.stream = None


def _configure_server_file_logging(
    state_root: Path,
    eff_prefix: str,
    *,
    surface: str,
    port: int = 0,
) -> Callable[[], None]:
    """Attach a UTF-8 `RotatingFileHandler` writing to `<state_root>/logs/server.log` (never 0-byte empty)."""
    logs_dir = Path(state_root).expanduser().resolve() / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_name = f"server_{eff_prefix}.log" if eff_prefix != "pc" else "server.log"
    log_path = (logs_dir / log_name).resolve()
    norm_target = os.path.normcase(str(log_path))

    cosmos_logger = logging.getLogger("cosmos_mcp")
    cosmos_logger.setLevel(logging.INFO)
    uvicorn_err_logger = logging.getLogger("uvicorn.error")

    for lgr in (cosmos_logger, uvicorn_err_logger):
        for existing in list(lgr.handlers):
            base_fn = getattr(existing, "baseFilename", "")
            if base_fn and os.path.normcase(str(Path(base_fn).resolve())) == norm_target:
                lgr.removeHandler(existing)
                try:
                    existing.close()
                except Exception:
                    pass

    fh = _WinSafeRotatingFileHandler(
        str(log_path),
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
        delay=True,
    )
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    cosmos_logger.addHandler(fh)
    uvicorn_err_logger.addHandler(fh)

    cosmos_logger.info(
        "Cosmos MCP v%s server ready (surface=%s, prefix=%s, port=%s)",
        PRODUCT_VERSION,
        surface,
        eff_prefix,
        port,
    )
    fh.flush()

    def _cleanup_handler() -> None:
        for lgr in (cosmos_logger, uvicorn_err_logger):
            if fh in lgr.handlers:
                lgr.removeHandler(fh)
        try:
            fh.flush()
            fh.close()
        except Exception:
            pass

    return _cleanup_handler


class _StandaloneRuntimePolicy(LiveRuntimePolicy):
    """Bridge Studio `'honest'`/`'compat'` labels and sync `readonly_workspace_roots`, `scan_host_global_skills`, `tool_prefix`, `tray_enabled`."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._studio_ann_label: str = ""
        raw_ann = str(kwargs.get("annotation_mode") or "").strip().lower()
        if raw_ann in ("honest", "compat"):
            self._studio_ann_label = raw_ann
            kwargs["annotation_mode"] = "strict" if raw_ann == "honest" else "seamless"

        super_init_params = inspect.signature(LiveRuntimePolicy.__init__).parameters
        filtered_kw = {
            k: v
            for k, v in kwargs.items()
            if k in super_init_params
        }
        super().__init__(*args, **filtered_kw)
        self._sync_guard_extended_fields()

    @property
    def annotation_mode(self) -> str:
        return self._studio_ann_label or self._annotation_mode

    @annotation_mode.setter
    def annotation_mode(self, value: Any) -> None:
        s = str(value or "").strip().lower()
        if s == "honest":
            self._studio_ann_label = "honest"
            self._annotation_mode = "strict"
        elif s == "compat":
            self._studio_ann_label = "compat"
            self._annotation_mode = "seamless"
        else:
            self._studio_ann_label = ""
            LiveRuntimePolicy.annotation_mode.fset(self, value)  # type: ignore[misc]

    @property
    def approval_popups(self) -> bool:
        return self._annotation_mode == "strict"

    @approval_popups.setter
    def approval_popups(self, flag: Any) -> None:
        LiveRuntimePolicy.approval_popups.fset(self, flag)  # type: ignore[misc]
        if self._studio_ann_label:
            self._studio_ann_label = "honest" if self._annotation_mode == "strict" else "compat"

    def _sync_guard_extended_fields(self) -> None:
        eff_tp = str(getattr(self, "tool_prefix", "") or self.eff_prefix)
        _sync_guard_workspace_policy(
            self.guard,
            workspace_roots=self.workspace_roots,
            restrict_to_workspace=self.restrict_to_workspace,
            tier_key=self.tier_key,
            readonly_workspace_roots=self.readonly_workspace_roots,
            allow_host_global_skills=bool(getattr(self, "scan_host_global_skills", False)),
            tool_prefix=eff_tp,
            state_root=self.state_root,
            product_root=self._product_root,
        )

    def _notify_workspace_hook(self) -> None:
        self._sync_guard_extended_fields()
        if self._on_ws_change is not None:
            try:
                self._on_ws_change(self.workspace_roots, self.restrict_to_workspace, self.tier_key)
            except Exception:
                pass

    def apply_direct(self, **kwargs: Any) -> Tuple[str, Dict[str, Any], str]:
        notify_listeners = bool(kwargs.pop("_notify_listeners", True))
        raw_ann = str(kwargs.get("annotation_mode") or "").strip().lower()
        alias_after: Optional[str] = None
        if raw_ann in ("honest", "compat"):
            alias_after = raw_ann
            kwargs["annotation_mode"] = "strict" if raw_ann == "honest" else "seamless"
        elif raw_ann:
            alias_after = ""

        super_apply_params = inspect.signature(LiveRuntimePolicy.apply_direct).parameters
        call_kw = {k: v for k, v in kwargs.items() if k in super_apply_params}

        with self._lock:
            res = super().apply_direct(_notify_listeners=False, **call_kw)
            if alias_after is not None:
                self._studio_ann_label = alias_after
            elif kwargs.get("approval_popups") is not None and self._studio_ann_label:
                self._studio_ann_label = "honest" if self._annotation_mode == "strict" else "compat"
            self._sync_guard_extended_fields()
            if notify_listeners:
                self._notify_policy_listeners()
        return res

    def persist_changes(self, **kwargs: Any) -> Tuple[str, Dict[str, Any], str]:
        super_persist_params = inspect.signature(LiveRuntimePolicy.persist_changes).parameters
        call_kw = {k: v for k, v in kwargs.items() if k in super_persist_params}
        with self._lock:
            res = super().persist_changes(**call_kw)
            if self.cfg_path is not None and self.cfg_path.is_file():
                state_svc = self.state_root / "state" / self.cfg_path.name
                if state_svc.is_file():
                    try:
                        doc = json.loads(self.cfg_path.read_text(encoding="utf-8-sig"))
                        if isinstance(doc, dict):
                            atomic_write_json(state_svc, doc)
                    except Exception:
                        pass
        return res

    def refresh(self, force: bool = False) -> Tuple[str, Dict[str, Any], str]:
        res = super().refresh(force=force)
        if self.cfg_path is not None and self.cfg_path.is_file():
            try:
                doc = json.loads(self.cfg_path.read_text(encoding="utf-8-sig"))
                if isinstance(doc, dict):
                    with self._lock:
                        saved_ann = str(doc.get("annotation_mode") or "").strip().lower()
                        if saved_ann == "honest":
                            self._annotation_mode = "strict"
                            self._studio_ann_label = "honest"
                        elif saved_ann == "compat":
                            self._annotation_mode = "seamless"
                            self._studio_ann_label = "compat"
                        self._sync_guard_extended_fields()
            except Exception:
                pass
        return res


def _hydrate_extra_policy_fields(
    policy: LiveRuntimePolicy,
    state_root: Path,
    pre_cfg: Dict[str, Any],
    *,
    overwrite_annotation: bool = True,
) -> None:
    root_cfg_p = state_root / "config.json"
    root_cfg: Dict[str, Any] = {}
    if root_cfg_p.is_file():
        try:
            loaded = json.loads(root_cfg_p.read_text(encoding="utf-8-sig"))
            if isinstance(loaded, dict):
                root_cfg = loaded
        except Exception:
            root_cfg = {}
    py_path = str(
        getattr(policy, "python_path", "")
        or pre_cfg.get("python_path")
        or root_cfg.get("python_path")
        or ""
    ).strip()
    saved_ann = str(pre_cfg.get("annotation_mode") or root_cfg.get("annotation_mode") or "").strip()
    if py_path and not getattr(policy, "python_path", ""):
        try:
            setattr(policy, "python_path", py_path)
        except Exception:
            pass
    if overwrite_annotation and saved_ann in ("honest", "compat", "strict", "seamless"):
        try:
            setattr(policy, "annotation_mode", saved_ann)
        except Exception:
            pass


def create_standalone_app(
    *,
    product_root: Optional[Path] = None, state_dir: str = "", public_url: str = "",
    host: str = "127.0.0.1", port: int = 8096, workspace: str = "", workspace_roots: Any = None,
    readonly_workspace_roots: Any = None, scan_host_global_skills: Optional[bool] = None,
    tray_enabled: Optional[bool] = None, tool_prefix: str = "",
    tier: str = "", reset_password: bool = False, prefix: str = "pc", device_label: str = "",
    toolset_profile: str = "", prompt_profile: str = "", enabled_tools: Any = None,
    disabled_tools: Any = None, approval_popups: Optional[bool] = None,
    enabled_packs: Any = None, keep_awake: Optional[bool] = None,
    tunnel_mode: str = "",
) -> Starlette:
    """Assemble the Standalone Starlette ASGI app (`protocol_app` + `Cosmos Studio` + zero-downtime tunnel hot-swap)."""
    if create_protocol_app is None or OAuthSQLiteStore is None:
        raise RuntimeError(
            "MCP / Starlette runtime dependencies are not installed in this Python interpreter; use --jsonrpc-lite on bare Python 3.9."
        )
    _ = host
    state_root = resolve_state_root(product_root=product_root, cli_state_dir=state_dir)
    slot_prefix = normalize_prefix(prefix or os.environ.get("LOCALPC_TOOL_PREFIX", "pc"))
    cfg_path = resolve_service_cfg_path(state_root, slot_prefix)
    pre_cfg: Dict[str, Any] = json.loads(cfg_path.read_text(encoding="utf-8-sig")) if cfg_path.is_file() else {}
    eff_tool_prefix = normalize_prefix(tool_prefix or str(pre_cfg.get("tool_prefix") or slot_prefix))

    cfg_tm = str(pre_cfg.get("tunnel_mode") or pre_cfg.get("mode") or "").strip().lower()
    arg_tm = (tunnel_mode or "").strip().lower()
    eff_tunnel_mode = (
        arg_tm
        or cfg_tm
        or os.environ.get("LOCALPC_TUNNEL_MODE", "").strip().lower()
        or os.environ.get("COSMOS_TUNNEL_MODE", "").strip().lower()
        or "local"
    )
    pre_daemon_doc = _read_daemon_status_doc(state_root, slot_prefix)
    init_endpoints, eff_pub_init, eff_tunnel_mode_resolved, init_grace_bases = _extract_active_gateways_and_grace(
        pre_cfg,
        pre_daemon_doc,
        None,
        port=port,
        explicit_public_url=(public_url if arg_tm != "local" else ""),
        fallback_tunnel_mode=eff_tunnel_mode,
        include_explicit=(arg_tm != "local"),
    )
    if arg_tm:
        eff_tunnel_mode = arg_tm
    elif eff_tunnel_mode_resolved:
        eff_tunnel_mode = eff_tunnel_mode_resolved
    raw_pub_candidate = "" if eff_pub_init.startswith("http://127.0.0.1:") else eff_pub_init

    eff_tier = tier or str(pre_cfg.get("permission_tier") or DEFAULT_TIER)
    eff_ws = workspace
    if not eff_ws and workspace_roots is None and not pre_cfg.get("workspace_roots") and not pre_cfg.get("workspace"):
        eff_ws = str(resolve_default_workspace(state_root=state_root))

    eff_ro_roots = readonly_workspace_roots if readonly_workspace_roots is not None else pre_cfg.get("readonly_workspace_roots")
    eff_scan_host = (
        parse_bool_flag(scan_host_global_skills, default=False)
        if scan_host_global_skills is not None
        else parse_bool_flag(pre_cfg.get("scan_host_global_skills"), default=False)
    )
    eff_tray = (
        parse_bool_flag(tray_enabled, default=True)
        if tray_enabled is not None
        else parse_bool_flag(pre_cfg.get("tray_enabled"), default=True)
    )

    init_params = inspect.signature(ensure_initialized).parameters
    init_extra: Dict[str, Any] = {}
    for k, v in (
        ("tool_prefix", eff_tool_prefix),
        ("readonly_workspace_roots", eff_ro_roots),
        ("scan_host_global_skills", eff_scan_host),
        ("tray_enabled", eff_tray),
        ("tunnel_mode", eff_tunnel_mode),
    ):
        if k in init_params:
            init_extra[k] = v

    creds = ensure_initialized(
        product_root=state_root, public_url=raw_pub_candidate, port=port, cli_state_dir=str(state_root),
        tier_key=eff_tier, reset_password=reset_password, prefix=slot_prefix, device_label=device_label,
        toolset_profile=toolset_profile, workspace_roots=workspace_roots, workspace=eff_ws,
        enabled_packs=enabled_packs, keep_awake=keep_awake, approval_popups=approval_popups,
        **init_extra,
    )

    sleep_inhibitor = SleepInhibitor(keep_display_on=False)
    guard = _make_workspace_guard(
        workspace_roots=[Path(p) for p in creds["workspace_roots"]],
        readonly_workspace_roots=eff_ro_roots,
        allow_host_global_skills=eff_scan_host,
        restrict_to_workspace=True,
        tier=eff_tier,
        state_root=state_root,
        tool_prefix=eff_tool_prefix,
    )
    proc_mgr = ProcessManager(guard=guard, state_root=state_root)
    policy: LiveRuntimePolicy = _StandaloneRuntimePolicy(
        tier_key=eff_tier, workspace=eff_ws, workspace_roots=workspace_roots,
        readonly_workspace_roots=eff_ro_roots,
        scan_host_global_skills=eff_scan_host,
        tray_enabled=eff_tray,
        tool_prefix=eff_tool_prefix,
        cfg_path=cfg_path, state_root=state_root, auth_path=Path(creds["auth_path"]),
        toolset_profile=toolset_profile, prompt_profile=prompt_profile,
        enabled_tools=enabled_tools, disabled_tools=disabled_tools,
        eff_prefix=slot_prefix, device_label=resolve_device_label(eff_tool_prefix, device_label),
        approval_popups=approval_popups, enabled_packs=enabled_packs, keep_awake=keep_awake,
        guard=guard, sleep_inhibitor=sleep_inhibitor,
        on_workspace_policy_change=lambda roots, restrict, tk: _sync_guard_workspace_policy(
            guard,
            workspace_roots=roots,
            restrict_to_workspace=restrict,
            tier_key=tk,
            readonly_workspace_roots=getattr(policy, "readonly_workspace_roots", ()),
            allow_host_global_skills=bool(getattr(policy, "scan_host_global_skills", False)),
            tool_prefix=getattr(policy, "tool_prefix", eff_tool_prefix),
            state_root=state_root,
        ),
        on_keep_awake_change=lambda flag: sleep_inhibitor.enable() if flag else sleep_inhibitor.disable(),
    )
    _hydrate_extra_policy_fields(policy, state_root, pre_cfg)

    init_cfg_sig: Tuple[int, int] = (0, 0)
    if cfg_path.is_file():
        with contextlib.suppress(OSError):
            st0 = cfg_path.stat()
            init_cfg_sig = (int(st0.st_mtime_ns), int(st0.st_size))

    live_url_box: List[str] = [eff_pub_init]

    def _resolve_live_public_url() -> str:
        if get_current_request_gateway is not None:
            gw = get_current_request_gateway()
            if gw is not None and not gw.is_loopback and gw.base_url:
                return gw.base_url
        return live_url_box[0]

    dispatcher = KernelDispatcher(policy)
    dispatcher.vps_hub_mode = bool(
        eff_tunnel_mode in ("vps_hub", "vps")
        or any(getattr(ep, "tunnel_mode", "") in ("vps_hub", "vps") for ep in init_endpoints)
    )
    dispatcher.add_execution_hook(_OfflineRemoteWorkspaceHook(dispatcher, policy))
    _mount_l1_capabilities(
        dispatcher,
        policy,
        guard,
        proc_mgr,
        mcp_port=port,
        mcp_public_url=_resolve_live_public_url,
    )

    watchdog = KillSignalWatchdog(
        state_root=state_root, eff_prefix=slot_prefix, policy=policy, ignore_same_pid=True,
        on_kill_callbacks=[
            lambda sig_doc: (
                proc_mgr.kill_all_active_commands(
                    str((sig_doc or {}).get("reason") or "kill_signal"),
                    include_persisted_bg=True,
                    prefix_filter=getattr(policy, "tool_prefix", slot_prefix),
                ),
                dispatcher.shutdown_packs(prefix_filter=policy.eff_prefix),
            )
        ],
    )
    watchdog.start()
    close_srv_log = _configure_server_file_logging(state_root, slot_prefix, surface="http", port=port)
    register_active_server_pid(
        state_root, "http", slot_prefix, port=port, workspace_roots=policy.workspace_roots,
        on_exit_cleanup=lambda: (
            watchdog.stop(),
            sleep_inhibitor.disable(),
            dispatcher.shutdown_packs(prefix_filter=policy.eff_prefix),
            proc_mgr.kill_all_active_commands("shutdown", include_persisted_bg=False, prefix_filter=getattr(policy, "tool_prefix", slot_prefix)),
            close_srv_log(),
        ),
    )

    oauth_db = f"oauth_{slot_prefix}.sqlite3" if slot_prefix != "pc" else "oauth.sqlite3"
    store = OAuthSQLiteStore(state_root / "state" / oauth_db)
    allowed_res = {
        eff_pub_init, f"{eff_pub_init}/mcp", f"{eff_pub_init}/mcp/readonly",
        f"http://127.0.0.1:{port}", f"http://127.0.0.1:{port}/mcp", f"http://127.0.0.1:{port}/mcp/readonly",
    }
    for ep0 in init_endpoints:
        allowed_res.update({ep0.base_url, ep0.resource.rstrip("/"), ep0.readonly_resource.rstrip("/")})
    for prev_u in init_grace_bases:
        pu = str(prev_u or "").strip().rstrip("/")
        if pu.startswith(("http://", "https://")):
            allowed_res.update({pu, f"{pu}/mcp", f"{pu}/mcp/readonly"})

    provider = StandaloneOAuthProvider(
        store=store, base_url=eff_pub_init, password_hash=str(creds["password_hash"]), salt=str(creds["salt"]),
        redirect_hosts=pre_cfg.get("redirect_hosts") or DEFAULT_REDIRECT_HOSTS, allowed_resources=allowed_res,
        tier_label=policy.dynamic_tier_label().replace("L3 工作区开发标准档", "L3 工作区标准开发档"),
        issuer=str(AnyHttpUrl(eff_pub_init)).rstrip("/"),
        tier_key=policy.tier_key, toolset_profile=policy.toolset_profile,
        exposed_tools=[dispatcher.prefixed_name(sp.base_name) for sp in dispatcher.active_tool_specs()],
        tool_prefix=getattr(policy, "tool_prefix", slot_prefix),
        tunnel_mode=eff_tunnel_mode,
        local_port=port,
        state_root=state_root,
    )
    app = create_protocol_app(
        dispatcher, policy=policy, store=store, provider=provider, proc_mgr=proc_mgr,
        public_url=eff_pub_init, port=port, local_api_token=str(creds["local_api_token"]),
        tunnel_mode=eff_tunnel_mode,
    )
    app.state.dispatcher = dispatcher

    _, origin_guards, issuer_middlewares = mount_standalone_status_ui(
        app, policy=policy, dispatcher=dispatcher, store=store, provider=provider,
        port=port, get_public_url=_resolve_live_public_url,
        set_public_url=lambda u: live_url_box.__setitem__(0, u),
        local_api_token=str(creds["local_api_token"]),
    )
    _mount_vps_hub_node_routes(
        app,
        dispatcher=dispatcher,
        policy=policy,
        state_root=state_root,
        slot_prefix=slot_prefix,
    )
    app.state.origin_guards = origin_guards

    def _sync_allowed_origins_with_urlsplit(active_pubs: Sequence[str], prev_bases: Sequence[Any]) -> None:
        all_guards = _collect_all_origin_guards(app, origin_guards)
        clean_actives = [str(u or "").strip().rstrip("/") for u in active_pubs if str(u or "").strip()]
        if not clean_actives:
            clean_actives = [f"http://127.0.0.1:{port}"]
        candidate_urls = [*clean_actives, *[str(x or "") for x in prev_bases]]
        bundle = app.state.transport_bundle
        if build_allowed_hosts is not None and build_allowed_origins is not None:
            raw_allowed = build_allowed_origins(port, *clean_actives)
            norm_allowed = _normalize_origin_entries(raw_allowed, extra_urls=candidate_urls)
            for og in all_guards:
                og.allowed_origins = norm_allowed
            for mgr in (bundle.main_session_manager, bundle.readonly_session_manager):
                sec = getattr(mgr, "security_settings", None) or getattr(mgr, "_security_settings", None)
                if sec is not None:
                    sec.allowed_hosts[:] = build_allowed_hosts(port, *clean_actives)
                    sec.allowed_origins[:] = norm_allowed
        else:
            for raw_u in candidate_urls:
                origin_only = _extract_http_origin(raw_u)
                if origin_only:
                    for og in all_guards:
                        og.exact_origins.add(origin_only)

    def _apply_gateway_sync(
        endpoints_list: Sequence[Any],
        primary_pub: str,
        primary_tm: str,
        grace_list: Sequence[str],
    ) -> None:
        eff_pub = primary_pub if primary_pub.startswith(("http://", "https://")) else f"http://127.0.0.1:{port}"
        eff_tm_now = primary_tm or "local"
        live_url_box[0] = eff_pub
        dispatcher.vps_hub_mode = bool(
            eff_tm_now in ("vps_hub", "vps")
            or any(getattr(ep, "tunnel_mode", "") in ("vps_hub", "vps") for ep in endpoints_list)
        )
        for rt in getattr(app.router, "routes", ()):
            ep_rt = getattr(rt, "endpoint", None)
            if ep_rt is not None and hasattr(ep_rt, "tunnel_mode"):
                ep_rt.tunnel_mode = eff_tm_now
        provider.sync_trusted_gateways(
            endpoints_list,
            primary_base=eff_pub,
            primary_tunnel_mode=eff_tm_now,
            grace_bases=grace_list,
            replace_allowed_resources=True,
        )
        bb = getattr(app.state, "bearer_backend", None)
        if bb is not None and hasattr(bb, "allowed_resources"):
            bb.allowed_resources.clear()
            bb.allowed_resources.update(provider.allowed_resources)
        for imw in issuer_middlewares:
            if hasattr(imw, "issuer"):
                imw.issuer = provider.issuer
        active_urls = [eff_pub, *[ep.base_url for ep in endpoints_list]]
        _sync_allowed_origins_with_urlsplit(active_urls, grace_list)

    _apply_gateway_sync(init_endpoints, eff_pub_init, eff_tunnel_mode, init_grace_bases)

    daemon_status_p = _daemon_status_json_path(state_root, slot_prefix)

    def _stat_sig(p: Path) -> Tuple[int, int]:
        if not p.is_file():
            return (0, 0)
        with contextlib.suppress(OSError):
            st = p.stat()
            return (int(st.st_mtime_ns), int(st.st_size))
        return (0, 0)

    last_disk_sig_box: List[Tuple[Tuple[int, int], Tuple[int, int]]] = [
        (_stat_sig(cfg_path), _stat_sig(daemon_status_p))
    ]

    def _sync_public_url_from_cfg(_pol: Optional[LiveRuntimePolicy] = None, *, force: bool = True) -> None:
        cur_cfg_sig = _stat_sig(cfg_path)
        cur_daemon_sig = _stat_sig(daemon_status_p)
        if not force and (cur_cfg_sig, cur_daemon_sig) == last_disk_sig_box[0]:
            return
        last_disk_sig_box[0] = (cur_cfg_sig, cur_daemon_sig)
        doc: Dict[str, Any] = {}
        if cur_cfg_sig != (0, 0):
            try:
                loaded_doc = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
                if isinstance(loaded_doc, dict):
                    doc = loaded_doc
            except Exception:
                return
        if doc:
            _hydrate_extra_policy_fields(policy, state_root, doc, overwrite_annotation=False)
        cur_tp = getattr(policy, "tool_prefix", policy.eff_prefix)
        if hasattr(provider, "tool_prefix") and provider.tool_prefix != cur_tp:
            provider.tool_prefix = cur_tp
        d_doc_now = _read_daemon_status_doc(state_root, slot_prefix)
        keep_explicit = bool(arg_tm != "local" and cur_cfg_sig == init_cfg_sig)
        new_eps, new_pub, new_tm, new_grace = _extract_active_gateways_and_grace(
            doc,
            d_doc_now,
            policy,
            port=port,
            explicit_public_url=(public_url if keep_explicit else ""),
            fallback_tunnel_mode=(arg_tm if keep_explicit else ""),
            include_explicit=keep_explicit,
        )
        _apply_gateway_sync(new_eps, new_pub, new_tm, new_grace)

    if hasattr(app.state, "gateway_sync_hook_box") and isinstance(app.state.gateway_sync_hook_box, list):
        app.state.gateway_sync_hook_box[0] = lambda force=False: _sync_public_url_from_cfg(None, force=bool(force))

    policy.add_policy_listener(_sync_public_url_from_cfg)
    app.state.watchdog = watchdog
    return app


def create_jsonrpc_lite_server(
    *,
    state_dir: str = "", host: str = "127.0.0.1", port: int = 8096,
    workspace: str = "", tier: str = "", prefix: str = "pc", tool_prefix: str = "",
    device_label: str = "", toolset_profile: str = "", enabled_packs: Any = None,
) -> JsonRpcLiteServer:
    """Assemble lightweight stdlib HTTP JSON-RPC 2.0 server (`JsonRpcLiteServer`) over `KernelDispatcher`."""
    state_root = resolve_state_root(cli_state_dir=state_dir)
    slot_prefix = normalize_prefix(prefix or os.environ.get("LOCALPC_TOOL_PREFIX", "pc"))
    cfg_path = resolve_service_cfg_path(state_root, slot_prefix)
    pre_cfg: Dict[str, Any] = json.loads(cfg_path.read_text(encoding="utf-8-sig")) if cfg_path.is_file() else {}
    eff_tool_prefix = normalize_prefix(tool_prefix or str(pre_cfg.get("tool_prefix") or slot_prefix))
    eff_tier = normalize_tier(tier or str(pre_cfg.get("permission_tier") or DEFAULT_TIER))
    eff_ws = workspace
    if not eff_ws and not pre_cfg.get("workspace_roots") and not pre_cfg.get("workspace"):
        eff_ws = str(resolve_default_workspace(state_root=state_root))
    creds = ensure_initialized(
        product_root=state_root, public_url=f"http://{host}:{port}", port=port,
        cli_state_dir=str(state_root), tier_key=eff_tier, prefix=slot_prefix,
        device_label=device_label, toolset_profile=toolset_profile,
        workspace=eff_ws, enabled_packs=enabled_packs,
    )
    eff_scan_host = parse_bool_flag(pre_cfg.get("scan_host_global_skills"), default=False)
    guard = _make_workspace_guard(
        workspace_roots=[Path(p) for p in creds["workspace_roots"]],
        readonly_workspace_roots=pre_cfg.get("readonly_workspace_roots"),
        allow_host_global_skills=eff_scan_host,
        restrict_to_workspace=True,
        tier=eff_tier,
        state_root=state_root,
        tool_prefix=eff_tool_prefix,
    )
    proc_mgr = ProcessManager(guard=guard, state_root=state_root)
    policy: LiveRuntimePolicy = _StandaloneRuntimePolicy(
        tier_key=eff_tier, workspace=eff_ws,
        readonly_workspace_roots=pre_cfg.get("readonly_workspace_roots"),
        scan_host_global_skills=eff_scan_host,
        tray_enabled=parse_bool_flag(pre_cfg.get("tray_enabled"), default=True),
        tool_prefix=eff_tool_prefix,
        cfg_path=cfg_path, state_root=state_root,
        auth_path=Path(creds["auth_path"]), toolset_profile=toolset_profile,
        eff_prefix=slot_prefix, device_label=resolve_device_label(eff_tool_prefix, device_label),
        enabled_packs=enabled_packs, guard=guard,
        on_workspace_policy_change=lambda roots, restrict, tk: _sync_guard_workspace_policy(
            guard,
            workspace_roots=roots,
            restrict_to_workspace=restrict,
            tier_key=tk,
            readonly_workspace_roots=getattr(policy, "readonly_workspace_roots", ()),
            allow_host_global_skills=bool(getattr(policy, "scan_host_global_skills", False)),
            tool_prefix=getattr(policy, "tool_prefix", eff_tool_prefix),
            state_root=state_root,
        ),
    )
    dispatcher = KernelDispatcher(policy)
    _mount_l1_capabilities(dispatcher, policy, guard, proc_mgr, mcp_port=port, mcp_public_url=f"http://{host}:{port}")
    srv_tp = getattr(policy, "tool_prefix", policy.eff_prefix)
    return JsonRpcLiteServer(
        dispatcher,
        host=host,
        port=port,
        auth_secret=str(creds["local_api_token"]),
        server_name=f"cosmos_{srv_tp}_mcp" if srv_tp != "pc" else "cosmos_mcp",
        server_version=PRODUCT_VERSION,
        instructions_fn=lambda ro: build_server_instructions(dispatcher, policy, readonly_only=ro),
    )


def run_stdio_mode(
    *,
    workspace: str = "", tier: str = "", prefix: str = "pc", tool_prefix: str = "",
    device_label: str = "", toolset_profile: str = "", prompt_profile: str = "",
    enabled_tools: Any = None, disabled_tools: Any = None, approval_popups: Optional[bool] = None,
    enabled_packs: Any = None, state_dir: str = "",
) -> None:
    """Run zero-daemon `--stdio` MCP server with 100% pure JSON-RPC on `stdout`."""
    if create_lowlevel_mcp_server is None or stdio_server is None:
        raise RuntimeError("`mcp` SDK is required for --stdio mode.")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING, force=True)

    state_root = resolve_state_root(cli_state_dir=state_dir)
    slot_prefix = normalize_prefix(prefix or os.environ.get("LOCALPC_TOOL_PREFIX", "pc"))
    cfg_path = resolve_service_cfg_path(state_root, slot_prefix)
    pre_cfg: Dict[str, Any] = json.loads(cfg_path.read_text(encoding="utf-8-sig")) if cfg_path.is_file() else {}
    eff_tool_prefix = normalize_prefix(tool_prefix or str(pre_cfg.get("tool_prefix") or slot_prefix))
    eff_ws = workspace
    if not eff_ws and not pre_cfg.get("workspace_roots") and not pre_cfg.get("workspace"):
        eff_ws = str(resolve_default_workspace(state_root=state_root))

    eff_tier = normalize_tier(tier or str(pre_cfg.get("permission_tier") or DEFAULT_TIER))
    eff_scan_host = parse_bool_flag(pre_cfg.get("scan_host_global_skills"), default=False)
    guard = _make_workspace_guard(
        workspace_roots=None,
        readonly_workspace_roots=pre_cfg.get("readonly_workspace_roots"),
        allow_host_global_skills=eff_scan_host,
        restrict_to_workspace=True,
        tier=eff_tier,
        state_root=state_root,
        tool_prefix=eff_tool_prefix,
    )
    proc_mgr = ProcessManager(guard=guard, state_root=state_root)
    policy: LiveRuntimePolicy = _StandaloneRuntimePolicy(
        tier_key=eff_tier,
        workspace=eff_ws,
        readonly_workspace_roots=pre_cfg.get("readonly_workspace_roots"),
        scan_host_global_skills=eff_scan_host,
        tray_enabled=parse_bool_flag(pre_cfg.get("tray_enabled"), default=True),
        tool_prefix=eff_tool_prefix,
        cfg_path=cfg_path, state_root=state_root, auth_path=state_root / "secrets" / "auth.json",
        toolset_profile=toolset_profile, prompt_profile=prompt_profile,
        enabled_tools=enabled_tools, disabled_tools=disabled_tools,
        eff_prefix=slot_prefix, device_label=resolve_device_label(eff_tool_prefix, device_label),
        approval_popups=approval_popups, enabled_packs=enabled_packs,
        guard=guard,
        on_workspace_policy_change=lambda roots, restrict, tk: _sync_guard_workspace_policy(
            guard,
            workspace_roots=roots,
            restrict_to_workspace=restrict,
            tier_key=tk,
            readonly_workspace_roots=getattr(policy, "readonly_workspace_roots", ()),
            allow_host_global_skills=bool(getattr(policy, "scan_host_global_skills", False)),
            tool_prefix=getattr(policy, "tool_prefix", eff_tool_prefix),
            state_root=state_root,
        ),
    )
    dispatcher = KernelDispatcher(policy)
    _mount_l1_capabilities(dispatcher, policy, guard, proc_mgr)

    watchdog = KillSignalWatchdog(
        state_root=state_root, eff_prefix=slot_prefix, policy=policy, ignore_same_pid=True,
        on_kill_callbacks=[
            lambda sig_doc: (
                proc_mgr.kill_all_active_commands(
                    str((sig_doc or {}).get("reason") or "kill_signal"),
                    include_persisted_bg=True,
                    prefix_filter=getattr(policy, "tool_prefix", slot_prefix),
                ),
                dispatcher.shutdown_packs(prefix_filter=policy.eff_prefix),
            )
        ],
    )
    watchdog.start()
    close_stdio_log = _configure_server_file_logging(state_root, slot_prefix, surface="stdio", port=0)
    register_active_server_pid(
        state_root, "stdio", slot_prefix, port=0, workspace_roots=policy.workspace_roots,
        on_exit_cleanup=lambda: (
            watchdog.stop(),
            proc_mgr.kill_all_active_commands("shutdown", include_persisted_bg=False, prefix_filter=getattr(policy, "tool_prefix", slot_prefix)),
            close_stdio_log(),
        ),
    )
    srv = create_lowlevel_mcp_server(dispatcher, readonly_only=False)

    async def _serve() -> None:
        assert stdio_server is not None
        async with stdio_server() as (read_stream, write_stream):
            await srv.run(read_stream, write_stream, srv.create_initialization_options())

    try:
        asyncio.run(_serve())
    finally:
        dispatcher.shutdown_packs(prefix_filter=policy.eff_prefix)
        watchdog.stop()
        close_stdio_log()


TRANSIENT_ACCEPT_WINERRORS: frozenset[int] = frozenset({64, 121, 995, 10054})


def _is_transient_accept_oserror(exc: BaseException) -> bool:
    if not isinstance(exc, OSError):
        return False
    winerr = getattr(exc, "winerror", None)
    if winerr in TRANSIENT_ACCEPT_WINERRORS:
        return True
    return exc.errno in (errno.ECONNRESET, errno.ECONNABORTED)


def install_win32_proactor_accept_guard(proactor_cls: Optional[Any] = None) -> bool:
    """Wrap `IocpProactor.accept` so transient `AcceptEx` resets (`winerror` 64/121/995/10054) never close `:8096`."""
    target_cls = proactor_cls
    if target_cls is None:
        if sys.platform != "win32":
            return False
        try:
            import asyncio.windows_events as _win_ev

            target_cls = getattr(_win_ev, "IocpProactor", None)
        except Exception:
            return False
    if target_cls is None or not hasattr(target_cls, "accept"):
        return False

    orig_accept = getattr(target_cls, "accept")
    if getattr(orig_accept, "_cosmos_accept_guard_installed", False):
        return True

    def _guarded_accept(self: Any, listener: Any) -> Any:
        loop = getattr(self, "_loop", None)
        if loop is None or loop.is_closed():
            return orig_accept(self, listener)

        outer_fut = loop.create_future()
        state: Dict[str, Any] = {"inner": None, "conns": []}

        def _listener_still_open() -> bool:
            if loop.is_closed():
                return False
            stopped = getattr(self, "_stopped_serving", None)
            if stopped is not None and listener in stopped:
                return False
            try:
                return int(listener.fileno()) != -1
            except Exception:
                return False

        def _close_captured_conns() -> None:
            conns = state.get("conns") or []
            state["conns"] = []
            for cs in conns:
                with contextlib.suppress(Exception):
                    cs.close()

        def _on_inner_done(fut: Any) -> None:
            if fut.cancelled():
                _close_captured_conns()
                if not outer_fut.done():
                    outer_fut.cancel()
                return
            exc = fut.exception()
            if exc is not None:
                _close_captured_conns()
                if outer_fut.done():
                    return
                if _is_transient_accept_oserror(exc) and _listener_still_open():
                    logging.getLogger("cosmos_mcp.launcher.accept_guard").debug(
                        "swallowed transient AcceptEx reset (%r) on listener; re-arming accept",
                        exc,
                    )
                    loop.call_soon(_arm_accept)
                    return
                outer_fut.set_exception(exc)
                return
            res = fut.result()
            state["conns"] = []
            if outer_fut.done():
                if isinstance(res, tuple) and len(res) >= 1 and hasattr(res[0], "close"):
                    with contextlib.suppress(Exception):
                        res[0].close()
                return
            outer_fut.set_result(res)

        def _arm_accept() -> None:
            if outer_fut.done():
                return
            if not _listener_still_open():
                outer_fut.cancel()
                return
            captured: List[Any] = []
            orig_get_sock = getattr(self, "_get_accept_socket", None)
            tasks_before: set[Any] = set()
            with contextlib.suppress(Exception):
                tasks_before = set(asyncio.all_tasks(loop))

            if callable(orig_get_sock):
                def _capturing_get_sock(*gs_args: Any, **gs_kwargs: Any) -> Any:
                    s = orig_get_sock(*gs_args, **gs_kwargs)
                    captured.append(s)
                    return s

                setattr(self, "_get_accept_socket", _capturing_get_sock)
            try:
                inner_fut = orig_accept(self, listener)
            except OSError as sync_exc:
                for cs in captured:
                    with contextlib.suppress(Exception):
                        cs.close()
                if _is_transient_accept_oserror(sync_exc) and _listener_still_open():
                    loop.call_later(0.01, _arm_accept)
                    return
                if not outer_fut.done():
                    outer_fut.set_exception(sync_exc)
                return
            except BaseException as fatal_exc:
                for cs in captured:
                    with contextlib.suppress(Exception):
                        cs.close()
                if not outer_fut.done():
                    outer_fut.set_exception(fatal_exc)
                return
            finally:
                if callable(orig_get_sock):
                    with contextlib.suppress(Exception):
                        delattr(self, "_get_accept_socket")

            with contextlib.suppress(Exception):
                for tk in set(asyncio.all_tasks(loop)) - tasks_before:
                    tk.add_done_callback(lambda t: None if t.cancelled() else t.exception())

            state["inner"] = inner_fut
            state["conns"] = captured
            inner_fut.add_done_callback(_on_inner_done)

        def _on_outer_done(of: Any) -> None:
            if of.cancelled():
                cur = state.get("inner")
                if cur is not None and not cur.done():
                    cur.cancel()

        outer_fut.add_done_callback(_on_outer_done)
        _arm_accept()
        return outer_fut

    setattr(_guarded_accept, "_cosmos_accept_guard_installed", True)
    setattr(_guarded_accept, "_cosmos_orig_accept", orig_accept)
    setattr(target_cls, "accept", _guarded_accept)
    return True


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Cosmos MCP Standalone Runtime Entry")
    parser.add_argument("--stdio", action="store_true")
    parser.add_argument("--jsonrpc-lite", action="store_true")
    for flag in ("--state-dir", "--public-url", "--workspace", "--tier", "--device-label", "--toolset", "--tunnel-mode", "--tool-prefix"):
        parser.add_argument(flag, default="")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8096)
    parser.add_argument("--prefix", default="pc")
    parser.add_argument("--enable-pack", default=None)
    parser.add_argument("--reset-password", action="store_true")
    args = parser.parse_args(argv)
    if args.stdio:
        run_stdio_mode(
            workspace=args.workspace, tier=args.tier, prefix=args.prefix, tool_prefix=args.tool_prefix,
            device_label=args.device_label, toolset_profile=args.toolset, enabled_packs=args.enable_pack,
            state_dir=args.state_dir,
        )
        return
    install_win32_proactor_accept_guard()
    if args.jsonrpc_lite:
        async def _serve_lite() -> None:
            lite_srv = create_jsonrpc_lite_server(
                state_dir=args.state_dir, host=args.host, port=args.port,
                workspace=args.workspace, tier=args.tier, prefix=args.prefix, tool_prefix=args.tool_prefix,
                device_label=args.device_label, toolset_profile=args.toolset, enabled_packs=args.enable_pack,
            )
            await lite_srv.start()
            try:
                await asyncio.Event().wait()
            finally:
                await lite_srv.stop()

        asyncio.run(_serve_lite())
        return
    import uvicorn

    asgi_app = create_standalone_app(
        state_dir=args.state_dir, public_url=args.public_url, host=args.host, port=args.port,
        workspace=args.workspace, tier=args.tier, reset_password=args.reset_password,
        prefix=args.prefix, tool_prefix=args.tool_prefix, device_label=args.device_label,
        toolset_profile=args.toolset, enabled_packs=args.enable_pack, tunnel_mode=args.tunnel_mode,
    )
    uvicorn.run(asgi_app, host=args.host, port=args.port, access_log=False, log_level="warning")


if __name__ == "__main__":
    main()
