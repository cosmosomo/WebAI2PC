"""Zero-dependency Cloudflare `workers.dev + SQLite Durable Object` gateway deployer,
`/u/<node_id>/mcp` deterministic master-seed identity + encrypted PNG recovery card,
and local outbound `443 WSS` binary multiplexing tunnel supervisor.

Top-level imports are 100% Python standard library for bare-machine cold-start safety.
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import contextlib
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import select
import socket
import ssl
import stat
import struct
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
import urllib.request
import uuid
import zlib

CLOUDFLARE_TOKEN_TEMPLATE_URL = (
    "https://dash.cloudflare.com/profile/api-tokens"
    "?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D"
    "%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D"
    "%2C%7B%22key%22%3A%22zone%22%2C%22type%22%3A%22read%22%7D"
    "%2C%7B%22key%22%3A%22workers_routes%22%2C%22type%22%3A%22edit%22%7D%5D"
    "&accountId=*&zoneId=all&name=Cosmos-MCP-Gateway"
)

DEFAULT_PUBLIC_GATEWAY_BASE = ""

# 17-byte binary multiplexing frame protocol: [1B frame_type][16B uuid_bytes][payload_bytes]
FRAME_REQ_HEAD = 0x10
FRAME_REQ_BODY = 0x11
FRAME_REQ_END = 0x12
FRAME_REQ_CANCEL = 0x13
FRAME_RES_HEAD = 0x20
FRAME_RES_BODY = 0x21
FRAME_RES_END = 0x22

FRAME_HEADER_LEN = 17
REQ_BODY_CHUNK_BYTES = 128 * 1024  # 128 KiB
RES_BODY_CHUNK_BYTES = 64 * 1024   # 64 KiB
MAX_BUFFERED_REQ_BYTES = 32 * 1024 * 1024  # 32 MiB cap per multiplexed request
RECONNECT_HOLD_WINDOW_SEC = 9.0

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
RECOVERY_PNG_CHUNK_TYPE = b"cMcp"
RECOVERY_AAD = b"cosmos-mcp-recovery-v1"
RECOVERY_AAD_V2 = b"cosmos-mcp-recovery-v2"

_DEFAULT_GENERIC_SCRIPT_NAMES = frozenset({"", "auto", "cosmos-mcp-gateway", "cosmos-mcp-relay"})

_TENANT_PATH_RE = re.compile(r"^/u/([a-z0-9_-]{4,64})(/.*)?$", re.IGNORECASE)
_SCRIPT_SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
)

# ---------------------------------------------------------------------------
# Embedded ES Module Worker + SQLite Hibernation Durable Object (`worker.mjs`)
# ---------------------------------------------------------------------------

WORKER_RELAY_MJS = r"""import { DurableObject } from "cloudflare:workers";

const FRAME_REQ_HEAD = 0x10;
const FRAME_REQ_BODY = 0x11;
const FRAME_REQ_END = 0x12;
const FRAME_REQ_CANCEL = 0x13;
const FRAME_RES_HEAD = 0x20;
const FRAME_RES_BODY = 0x21;
const FRAME_RES_END = 0x22;

const HEADER_BYTES = 17;
const REQ_CHUNK_BYTES = 131072; // 128 KiB
const RECONNECT_HOLD_MS = 9000; // 9s hotspot-switch grace window
const MAX_REPLAY_BYTES = 2097152; // 2 MiB replay buffer for pre-response frames
const REQUEST_TIMEOUT_MS = 95000;

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();
const BYTE_TO_HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));

const TENANT_PREFIX_RE = /^\/u\/([a-z0-9_-]{4,64})(\/.*)?$/i;
const WELL_KNOWN_TENANT_RE = /^(\/\.well-known\/oauth-[^/]+)\/u\/([a-z0-9_-]{4,64})(\/.*)?$/i;

const ALLOWED_EXACT_PATHS = new Set([
  "/mcp",
  "/mcp/",
  "/mcp/readonly",
  "/mcp/readonly/",
  "/register",
  "/authorize",
  "/consent",
  "/consent/complete",
  "/token",
  "/revoke",
  "/mcp-skill.md",
  "/skill",
  "/skill.md",
  "/healthz",
]);

const FORWARDED_HEADER_ALLOWLIST = [
  "cf-connecting-ip",
  "authorization",
  "content-type",
  "accept",
  "accept-language",
  "mcp-session-id",
  "mcp-protocol-version",
  "last-event-id",
  "cookie",
  "user-agent",
  "origin",
  "referer",
  "access-control-request-method",
  "access-control-request-headers",
  "cache-control",
  "if-none-match",
  "if-modified-since",
  "range",
];

const HOP_BY_HOP_RESPONSE_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailers",
  "transfer-encoding",
  "upgrade",
]);

function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || b.length === 0) {
    return false;
  }
  const bufA = TEXT_ENCODER.encode(a);
  const bufB = TEXT_ENCODER.encode(b);
  const maxLen = Math.max(bufA.length, bufB.length);
  let diff = bufA.length ^ bufB.length;
  for (let i = 0; i < maxLen; i++) {
    diff |= (bufA[i] || 0) ^ (bufB[i] || 0);
  }
  return diff === 0;
}

function bytesToHex16(u8, offset = 0) {
  let out = "";
  for (let i = 0; i < 16; i++) {
    out += BYTE_TO_HEX[u8[offset + i]];
  }
  return out;
}

function packFrame(frameType, uuidBytes, payloadBytes) {
  const bodyLen = payloadBytes ? payloadBytes.byteLength : 0;
  const frame = new Uint8Array(HEADER_BYTES + bodyLen);
  frame[0] = frameType & 0xff;
  frame.set(uuidBytes, 1);
  if (bodyLen > 0) {
    frame.set(payloadBytes, HEADER_BYTES);
  }
  return frame;
}

function normalizePathname(rawPath) {
  let p = rawPath || "/";
  try {
    p = decodeURIComponent(p);
  } catch (_) {}
  p = p.replace(/\/{2,}/g, "/");
  return p || "/";
}

function parseTenantRoute(rawPathname) {
  const wkMatch = WELL_KNOWN_TENANT_RE.exec(rawPathname || "");
  if (wkMatch) {
    const nodeId = wkMatch[2].toLowerCase();
    return {
      tenantId: nodeId,
      publicPrefix: "/u/" + nodeId,
      innerPath: wkMatch[1] + (wkMatch[3] || ""),
    };
  }
  const tMatch = TENANT_PREFIX_RE.exec(rawPathname || "");
  if (tMatch) {
    const nodeId = tMatch[1].toLowerCase();
    return {
      tenantId: nodeId,
      publicPrefix: "/u/" + nodeId,
      innerPath: tMatch[2] || "/",
    };
  }
  return {
    tenantId: "default",
    publicPrefix: "",
    innerPath: rawPathname || "/",
  };
}

function isBlockedLocalAdminPath(innerPath) {
  const low = normalizePathname(innerPath).toLowerCase();
  return (
    low === "/studio" ||
    low.startsWith("/studio/") ||
    low === "/api/studio" ||
    low.startsWith("/api/studio/") ||
    low === "/oauth/local-bridge" ||
    low.startsWith("/oauth/local-bridge/")
  );
}

function isAllowedPublicRoute(innerPath) {
  const norm = normalizePathname(innerPath);
  const low = norm.toLowerCase();
  if (ALLOWED_EXACT_PATHS.has(low)) {
    return true;
  }
  return low.startsWith("/.well-known/") || low.startsWith("/preview/");
}

function buildCleanHeaders(request, url, publicPrefix) {
  const out = {};
  for (const name of FORWARDED_HEADER_ALLOWLIST) {
    const val = request.headers.get(name);
    if (val !== null && val !== "") {
      out[name] = val;
    }
  }
  out["x-cosmos-via-tunnel"] = "1";
  out["x-forwarded-proto"] = "https";
  out["x-forwarded-host"] = url.host;
  const cfIp = request.headers.get("cf-connecting-ip");
  if (cfIp) {
    out["x-forwarded-for"] = cfIp;
  }
  if (publicPrefix) {
    out["x-cosmos-public-prefix"] = publicPrefix;
  }
  return out;
}

function offlineHealthzResponse() {
  return new Response('{"status":"tunnel_offline"}', {
    status: 503,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const route = parseTenantRoute(url.pathname);

    // 1. Edge hard-block local management UI & loopback consent bridge
    if (isBlockedLocalAdminPath(route.innerPath)) {
      return new Response("Forbidden", {
        status: 403,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }

    // 2. Device outbound 443 WSS tunnel handshake (`/_cosmos_tunnel` or `/u/<node_id>/_cosmos_tunnel`)
    if (normalizePathname(route.innerPath) === "/_cosmos_tunnel") {
      const upg = (request.headers.get("upgrade") || "").toLowerCase();
      if (upg !== "websocket") {
        return new Response("Upgrade Required", { status: 426 });
      }
      const authHeader = request.headers.get("authorization") || "";
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
      const expectedSecret = String(env.TUNNEL_SECRET || "");
      if (!expectedSecret || !constantTimeEqual(token, expectedSecret)) {
        return new Response("Unauthorized", { status: 401 });
      }
      const doId = env.RELAY_DO.idFromName(route.tenantId);
      return env.RELAY_DO.get(doId).fetch(request);
    }

    // 3. Public MCP & OAuth route allowlist (open to both Google Gemini & OpenAI ChatGPT web connectors)
    if (!isAllowedPublicRoute(route.innerPath)) {
      return new Response("Not Found", {
        status: 404,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }

    const doId = env.RELAY_DO.idFromName(route.tenantId);
    return env.RELAY_DO.get(doId).fetch(request);
  },
};

export class CosmosRelayDO extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.pendingMap = new Map();
    this.reconnectWaiters = [];
    this.lastDisconnectAt = 0;
    this.reconnectGraceTimer = null;
  }

  _getDeviceSocket() {
    const sockets = this.ctx.getWebSockets("device");
    for (let i = sockets.length - 1; i >= 0; i--) {
      const ws = sockets[i];
      if (ws && ws.readyState === 1) {
        return ws;
      }
    }
    return null;
  }

  _waitForReconnect(timeoutMs) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        const idx = this.reconnectWaiters.indexOf(waiter);
        if (idx !== -1) this.reconnectWaiters.splice(idx, 1);
        resolve(null);
      }, Math.max(50, timeoutMs));
      const waiter = (ws) => {
        clearTimeout(timer);
        resolve(ws);
      };
      this.reconnectWaiters.push(waiter);
    });
  }

  _failAllPendingOffline() {
    for (const [reqIdHex, entry] of this.pendingMap.entries()) {
      clearTimeout(entry.timer);
      if (!entry.headResolved) {
        entry.headResolved = true;
        entry.resolveHead(offlineHealthzResponse());
      } else if (entry.controller) {
        try {
          entry.controller.close();
        } catch (_) {}
      }
      this.pendingMap.delete(reqIdHex);
    }
  }

  _onDeviceSocketConnected(newWs) {
    if (this.reconnectGraceTimer !== null) {
      clearTimeout(this.reconnectGraceTimer);
      this.reconnectGraceTimer = null;
    }
    this.lastDisconnectAt = 0;
    while (this.reconnectWaiters.length > 0) {
      const w = this.reconnectWaiters.shift();
      try {
        w(newWs);
      } catch (_) {}
    }
    // Replay buffered pre-response request frames held during the <=9s hotspot switch window
    for (const [reqIdHex, entry] of this.pendingMap.entries()) {
      if (!entry.headResolved && entry.needsReplay && entry.reqEnded && entry.replayFrames) {
        try {
          for (const frame of entry.replayFrames) {
            newWs.send(frame);
          }
          entry.needsReplay = false;
        } catch (_) {
          // Will retry if another socket replaces within remaining window
        }
      }
    }
  }

  async fetch(request) {
    const url = new URL(request.url);
    const route = parseTenantRoute(url.pathname);
    const innerNorm = normalizePathname(route.innerPath);

    if (innerNorm === "/_cosmos_tunnel" && (request.headers.get("upgrade") || "").toLowerCase() === "websocket") {
      const pair = new WebSocketPair();
      const client = pair[0];
      const server = pair[1];
      for (const oldWs of this.ctx.getWebSockets("device")) {
        try {
          oldWs.close(1012, "superseded_by_new_device_connection");
        } catch (_) {}
      }
      this.ctx.acceptWebSocket(server, ["device"]);
      server.serializeAttachment({ role: "device", connectedAt: Date.now() });
      this._onDeviceSocketConnected(server);
      return new Response(null, { status: 101, webSocket: client });
    }

    const isHealthz = innerNorm.toLowerCase() === "/healthz";
    let deviceWs = this._getDeviceSocket();
    if (!deviceWs) {
      if (isHealthz) {
        return offlineHealthzResponse();
      }
      const elapsedSinceDrop = this.lastDisconnectAt > 0 ? Date.now() - this.lastDisconnectAt : Infinity;
      if (elapsedSinceDrop < RECONNECT_HOLD_MS) {
        deviceWs = await this._waitForReconnect(RECONNECT_HOLD_MS - elapsedSinceDrop);
      }
      if (!deviceWs) {
        return offlineHealthzResponse();
      }
    }

    const reqIdBytes = new Uint8Array(16);
    crypto.getRandomValues(reqIdBytes);
    const reqIdHex = bytesToHex16(reqIdBytes, 0);

    let resolveHeadFn;
    const headPromise = new Promise((resolve) => {
      resolveHeadFn = resolve;
    });

    const entry = {
      reqIdBytes,
      reqIdHex,
      isHealthz,
      headResolved: false,
      resolveHead: resolveHeadFn,
      controller: null,
      replayFrames: [],
      replayBytes: 0,
      replayOverflow: false,
      needsReplay: false,
      reqEnded: false,
      timer: null,
    };

    entry.timer = setTimeout(() => {
      if (this.pendingMap.has(reqIdHex)) {
        this.pendingMap.delete(reqIdHex);
        if (!entry.headResolved) {
          entry.headResolved = true;
          entry.resolveHead(
            isHealthz
              ? offlineHealthzResponse()
              : new Response('{"error":"gateway_timeout"}', {
                  status: 504,
                  headers: { "content-type": "application/json; charset=utf-8" },
                })
          );
        } else if (entry.controller) {
          try {
            entry.controller.close();
          } catch (_) {}
        }
      }
    }, REQUEST_TIMEOUT_MS);

    this.pendingMap.set(reqIdHex, entry);

    const sendCancelToDevice = () => {
      if (!this.pendingMap.has(reqIdHex)) return;
      clearTimeout(entry.timer);
      this.pendingMap.delete(reqIdHex);
      const activeWs = this._getDeviceSocket();
      if (activeWs) {
        try {
          activeWs.send(packFrame(FRAME_REQ_CANCEL, reqIdBytes, null));
        } catch (_) {}
      }
    };

    if (request.signal) {
      if (request.signal.aborted) {
        sendCancelToDevice();
        return new Response(null, { status: 499 });
      }
      request.signal.addEventListener("abort", sendCancelToDevice, { once: true });
    }

    const sendOrHoldFrame = (frame) => {
      if (!entry.headResolved && !entry.replayOverflow) {
        if (entry.replayBytes + frame.byteLength <= MAX_REPLAY_BYTES) {
          entry.replayFrames.push(frame);
          entry.replayBytes += frame.byteLength;
        } else {
          entry.replayFrames = null;
          entry.replayOverflow = true;
        }
      }
      const wsNow = this._getDeviceSocket();
      if (wsNow) {
        try {
          wsNow.send(frame);
          return true;
        } catch (_) {}
      }
      entry.needsReplay = true;
      return false;
    };

    const headObj = {
      method: request.method || "GET",
      path_qs: (route.innerPath || "/") + (url.search || ""),
      headers: buildCleanHeaders(request, url, route.publicPrefix),
    };
    sendOrHoldFrame(packFrame(FRAME_REQ_HEAD, reqIdBytes, TEXT_ENCODER.encode(JSON.stringify(headObj))));

    // Stream request body in <= 128 KiB binary slices without Base64 encoding
    (async () => {
      try {
        if (request.body) {
          const reader = request.body.getReader();
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (!this.pendingMap.has(reqIdHex)) {
              try {
                await reader.cancel();
              } catch (_) {}
              return;
            }
            if (value && value.byteLength > 0) {
              for (let off = 0; off < value.byteLength; off += REQ_CHUNK_BYTES) {
                const slice = value.subarray(off, Math.min(off + REQ_CHUNK_BYTES, value.byteLength));
                sendOrHoldFrame(packFrame(FRAME_REQ_BODY, reqIdBytes, slice));
              }
            }
          }
        }
        if (this.pendingMap.has(reqIdHex)) {
          entry.reqEnded = true;
          const sentOk = sendOrHoldFrame(packFrame(FRAME_REQ_END, reqIdBytes, null));
          if (!sentOk && isHealthz) {
            clearTimeout(entry.timer);
            this.pendingMap.delete(reqIdHex);
            if (!entry.headResolved) {
              entry.headResolved = true;
              entry.resolveHead(offlineHealthzResponse());
            }
          }
        }
      } catch (_) {
        if (this.pendingMap.has(reqIdHex) && !entry.headResolved) {
          clearTimeout(entry.timer);
          this.pendingMap.delete(reqIdHex);
          entry.headResolved = true;
          entry.resolveHead(
            isHealthz
              ? offlineHealthzResponse()
              : new Response('{"error":"request_stream_aborted"}', { status: 502 })
          );
        }
      }
    })();

    return headPromise;
  }

  async webSocketMessage(ws, message) {
    let bytes = null;
    if (message instanceof ArrayBuffer) {
      bytes = new Uint8Array(message);
    } else if (ArrayBuffer.isView(message)) {
      bytes = new Uint8Array(message.buffer, message.byteOffset, message.byteLength);
    }
    if (!bytes || bytes.byteLength < HEADER_BYTES) {
      return;
    }

    const frameType = bytes[0];
    const reqIdHex = bytesToHex16(bytes, 1);
    const payload = bytes.subarray(HEADER_BYTES);
    const entry = this.pendingMap.get(reqIdHex);
    if (!entry) {
      return;
    }

    if (frameType === FRAME_RES_HEAD) {
      if (entry.headResolved) return;
      let meta;
      try {
        meta = JSON.parse(TEXT_DECODER.decode(payload));
      } catch (_) {
        clearTimeout(entry.timer);
        this.pendingMap.delete(reqIdHex);
        entry.headResolved = true;
        entry.resolveHead(new Response("Bad Gateway", { status: 502 }));
        return;
      }

      const status = Number(meta.status) || 200;
      const respHeaders = new Headers();
      if (Array.isArray(meta.headers)) {
        for (const pair of meta.headers) {
          if (Array.isArray(pair) && pair.length >= 2) {
            const hk = String(pair[0] || "").trim();
            const hv = String(pair[1] ?? "");
            if (hk && !HOP_BY_HOP_RESPONSE_HEADERS.has(hk.toLowerCase())) {
              respHeaders.append(hk, hv);
            }
          }
        }
      } else if (meta.headers && typeof meta.headers === "object") {
        for (const [hk, hv] of Object.entries(meta.headers)) {
          if (hk && !HOP_BY_HOP_RESPONSE_HEADERS.has(hk.toLowerCase())) {
            respHeaders.append(hk, String(hv ?? ""));
          }
        }
      }

      entry.replayFrames = null;
      entry.needsReplay = false;
      entry.headResolved = true;

      const isNullBody = status === 101 || status === 204 || status === 205 || status === 304;
      if (isNullBody) {
        entry.resolveHead(new Response(null, { status, headers: respHeaders }));
        return;
      }

      const pendingMap = this.pendingMap;
      const selfDo = this;
      const stream = new ReadableStream({
        start(controller) {
          entry.controller = controller;
        },
        cancel() {
          if (pendingMap.has(reqIdHex)) {
            clearTimeout(entry.timer);
            pendingMap.delete(reqIdHex);
            const activeWs = selfDo._getDeviceSocket();
            if (activeWs) {
              try {
                activeWs.send(packFrame(FRAME_REQ_CANCEL, entry.reqIdBytes, null));
              } catch (_) {}
            }
          }
        },
      });
      entry.resolveHead(new Response(stream, { status, headers: respHeaders }));
      return;
    }

    if (frameType === FRAME_RES_BODY) {
      if (entry.controller && payload.byteLength > 0) {
        try {
          entry.controller.enqueue(payload.slice());
        } catch (_) {}
      }
      return;
    }

    if (frameType === FRAME_RES_END) {
      clearTimeout(entry.timer);
      const pendingMap = this.pendingMap;
      pendingMap.delete(reqIdHex);
      if (!entry.headResolved) {
        entry.headResolved = true;
        entry.resolveHead(new Response("", { status: 204 }));
      } else if (entry.controller) {
        try {
          entry.controller.close();
        } catch (_) {}
      }
    }
  }

  _handleSocketDisconnect(ws) {
    if (this._getDeviceSocket() !== null) {
      // Another active replacement device socket is already connected
      return;
    }
    this.lastDisconnectAt = Date.now();
    for (const entry of this.pendingMap.values()) {
      if (!entry.headResolved && !entry.replayOverflow) {
        entry.needsReplay = true;
      }
    }
    if (this.reconnectGraceTimer !== null) {
      clearTimeout(this.reconnectGraceTimer);
    }
    // Hold in-flight requests for 9000ms instead of immediately rejecting with 502/530
    this.reconnectGraceTimer = setTimeout(() => {
      this.reconnectGraceTimer = null;
      if (this._getDeviceSocket() === null) {
        this._failAllPendingOffline();
      }
    }, RECONNECT_HOLD_MS);
  }

  async webSocketClose(ws, code, reason, wasClean) {
    try {
      ws.close(code || 1000, reason || "");
    } catch (_) {}
    this._handleSocketDisconnect(ws);
  }

  async webSocketError(ws, error) {
    this._handleSocketDisconnect(ws);
  }
}
"""


# ---------------------------------------------------------------------------
# Internal Helpers (Atomic File I/O, Shredding, Binary Framing, Proxy)
# ---------------------------------------------------------------------------

def _norm_prefix(prefix: str) -> str:
    val = (prefix or "pc").strip().lower()
    return val if val else "pc"


def _atomic_write_bytes(target: Path, data: bytes, *, mode_override: int = 0o600) -> None:
    target = Path(target).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_p: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=str(target.parent),
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as tf:
            tf.write(data)
            tf.flush()
            with contextlib.suppress(OSError):
                os.fsync(tf.fileno())
            tmp_p = Path(tf.name)
        if sys.platform != "win32" and mode_override is not None:
            with contextlib.suppress(OSError):
                os.chmod(tmp_p, mode_override)
        for att in range(8):
            try:
                os.replace(str(tmp_p), str(target))
                break
            except PermissionError:
                if sys.platform != "win32" or att >= 7:
                    raise
                time.sleep(0.015 * (att + 1))
    finally:
        if tmp_p is not None and tmp_p.exists():
            with contextlib.suppress(OSError):
                tmp_p.unlink()


def _atomic_write_secret_text(target: Path, text: str) -> None:
    try:
        from cosmos_mcp.core.fs_tx import atomic_write_text

        atomic_write_text(Path(target).expanduser().resolve(), text, mode_override=0o600)
    except ImportError:
        _atomic_write_bytes(target, text.encode("utf-8"), mode_override=0o600)


def _shred_secret_file(file_path: Path) -> bool:
    """Zero-overwrite, fsync, truncate(0), and unlink a sensitive credential file."""
    p = Path(file_path)
    if not p.exists() and not p.is_symlink():
        return False
    try:
        if p.is_symlink() or not p.is_file():
            p.unlink(missing_ok=True)
            return True
        with contextlib.suppress(OSError):
            os.chmod(p, 0o600)
        size = max(int(p.stat().st_size), 128)
        zeros = b"\x00" * min(size, 65536)
        with p.open("r+b") as fh:
            fh.seek(0)
            rem = size
            while rem > 0:
                step = min(rem, len(zeros))
                fh.write(zeros[:step])
                rem -= step
            fh.flush()
            with contextlib.suppress(OSError):
                os.fsync(fh.fileno())
            fh.seek(0)
            fh.truncate(0)
            fh.flush()
            with contextlib.suppress(OSError):
                os.fsync(fh.fileno())
        p.unlink(missing_ok=True)
        return True
    except OSError:
        with contextlib.suppress(OSError):
            p.unlink(missing_ok=True)
        return True


def _detect_system_proxy(scheme: str = "https", target_host: str = "") -> str:
    with contextlib.suppress(Exception):
        from cosmos_mcp.core.net_power import detect_configured_proxy

        return detect_configured_proxy(scheme=scheme, target_host=target_host)
    sc = "https" if scheme.lower() in ("https", "wss") else "http"
    for k in (f"{sc.upper()}_PROXY", f"{sc}_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy"):
        v = (os.environ.get(k) or "").strip()
        if v:
            return v
    with contextlib.suppress(Exception):
        proxies = urllib.request.getproxies()
        if not isinstance(proxies, dict):
            proxies = {}
        has_scheme_proxy = any(
            str(proxies.get(pk) or "").strip()
            for pk in ("https", "http", "all", "socks", "socks5", "socks5h")
        )
        if sys.platform == "win32" and not has_scheme_proxy:
            get_reg = getattr(urllib.request, "getproxies_registry", None)
            if callable(get_reg):
                reg_p = get_reg()
                if isinstance(reg_p, dict):
                    merged = dict(reg_p)
                    for ek, ev in proxies.items():
                        if str(ev or "").strip():
                            merged[ek] = ev
                    proxies = merged
        return str(proxies.get(sc) or proxies.get("http") or proxies.get("all") or "").strip()
    return ""


def pack_tunnel_frame(frame_type: int, req_id_bytes: bytes, payload: bytes = b"") -> bytes:
    """Pack a 17-byte binary tunnel frame: `[1B frame_type][16B uuid_bytes][payload]`."""
    if len(req_id_bytes) != 16:
        raise ValueError(f"`req_id_bytes` must be exactly 16 bytes, got {len(req_id_bytes)}")
    return bytes([frame_type & 0xFF]) + req_id_bytes + (payload or b"")


def unpack_tunnel_frame(raw: bytes) -> Tuple[int, bytes, bytes]:
    """Unpack `[1B frame_type][16B uuid_bytes][payload]` from a binary WebSocket message."""
    if len(raw) < FRAME_HEADER_LEN:
        raise ValueError(f"Binary tunnel frame shorter than {FRAME_HEADER_LEN} bytes ({len(raw)})")
    return raw[0], raw[1:17], raw[17:]


def probe_egress_source_ip(target_ip: str = "1.1.1.1", target_port: int = 443) -> str:
    """Zero-packet kernel routing lookup returning current active outbound local IPv4 address."""
    with contextlib.suppress(OSError):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((target_ip, int(target_port)))
            return str(s.getsockname()[0] or "")
    return ""


# ---------------------------------------------------------------------------
# Card 1: Master Seed `/u/<node_id>/mcp` Identity & PNG Recovery Card (`cMcp`)
# ---------------------------------------------------------------------------

def master_seed_secret_path(state_root: Path, prefix: str = "pc") -> Path:
    eff = _norm_prefix(prefix)
    fn = f"master_seed_{eff}.bin" if eff != "pc" else "master_seed.bin"
    return Path(state_root).expanduser().resolve() / "secrets" / fn


def probe_public_gateway_online(base_url: str = "", timeout_sec: float = 1.5) -> Dict[str, Any]:
    """Probe `<base_url>/healthz` via system proxy and verify HTTP 200/503 JSON gateway signature."""
    clean_base = str(base_url or "").strip().rstrip("/")
    if not clean_base:
        return {
            "configured": False,
            "online": False,
            "base_url": "",
            "status_code": 0,
            "reason": "unconfigured",
        }
    if "://" not in clean_base:
        clean_base = f"https://{clean_base}"
    parsed = urlsplit(clean_base)
    host_low = (parsed.hostname or "").strip().lower()
    if not host_low or (host_low.startswith("gw.cosmos-mcp.") and host_low.endswith((".org", ".workers.dev"))):
        return {
            "configured": False,
            "online": False,
            "base_url": "",
            "status_code": 0,
            "reason": "unconfigured",
        }

    target_url = f"{clean_base}/healthz"
    eff_timeout = max(0.2, float(timeout_sec or 1.5))
    ctx = ssl.create_default_context()
    openers: List[urllib.request.OpenerDirector] = []
    if host_low in ("127.0.0.1", "::1", "localhost"):
        openers.append(
            urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ctx),
            )
        )
    else:
        sys_proxy = _detect_system_proxy(parsed.scheme or "https", target_host=host_low)
        if sys_proxy and sys_proxy.lower().startswith(("http://", "https://")):
            openers.append(
                urllib.request.build_opener(
                    urllib.request.ProxyHandler({"http": sys_proxy, "https": sys_proxy}),
                    urllib.request.HTTPSHandler(context=ctx),
                )
            )
        openers.append(urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx)))
        openers.append(
            urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ctx),
            )
        )

    last_reason = "unreachable"
    last_code = 0
    for op in openers:
        req = urllib.request.Request(
            target_url,
            headers={"Accept": "application/json", "User-Agent": "Cosmos-MCP-Gateway-Probe/1.0"},
        )
        code = 0
        raw_body = b""
        try:
            with op.open(req, timeout=eff_timeout) as resp:
                code = int(getattr(resp, "status", 200))
                raw_body = resp.read(16384)
        except HTTPError as he:
            code = int(he.code)
            with contextlib.suppress(Exception):
                raw_body = he.read(16384)
        except Exception as exc:
            last_reason = str(exc)[:200] or type(exc).__name__
            continue

        last_code = code
        if code in (200, 503):
            try:
                doc = json.loads(raw_body.decode("utf-8", errors="replace"))
            except Exception:
                doc = None
            if isinstance(doc, dict) and (
                str(doc.get("status") or "").lower() in ("ok", "tunnel_offline", "hub_online", "online", "ready")
                or doc.get("ok") is True
                or "cosmos" in str(doc.get("service") or "").lower()
            ):
                return {
                    "configured": True,
                    "online": True,
                    "base_url": clean_base,
                    "status_code": code,
                    "reason": "ok",
                }
            last_reason = f"invalid_gateway_json_{code}"
        else:
            last_reason = f"http_status_{code}"
        break

    return {
        "configured": True,
        "online": False,
        "base_url": clean_base,
        "status_code": last_code,
        "reason": last_reason,
    }


def _derive_identity_from_seed(master_seed: bytes, gateway_base: str = "") -> Dict[str, Any]:
    if len(master_seed) != 32:
        raise ValueError("`master_seed` must be exactly 32 bytes.")
    ed_seed = hmac.new(master_seed, b"cosmos-mcp:ed25519-seed:v1", hashlib.sha256).digest()
    crypto_backend = "stdlib-hmac-sha256"
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(ed_seed)
        pub_raw = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        crypto_backend = "cryptography-ed25519"
    except Exception:
        pub_raw = hmac.new(ed_seed, b"cosmos-mcp:ed25519-pub-fallback:v1", hashlib.sha256).digest()

    # Deterministic 12-char lowercase alphanumeric/hex node_id tied to master_seed
    node_id = hmac.new(master_seed, b"cosmos-mcp:node-id:v1", hashlib.sha256).hexdigest()[:12].lower()
    node_secret = hmac.new(master_seed, b"cosmos-mcp:node-tunnel-secret:v1", hashlib.sha256).hexdigest()

    raw_gw = (
        gateway_base
        or os.environ.get("COSMOS_PUBLIC_GATEWAY_BASE")
        or DEFAULT_PUBLIC_GATEWAY_BASE
    ).strip().rstrip("/")
    if raw_gw and "://" not in raw_gw:
        raw_gw = f"https://{raw_gw}"
    gw_host = (urlsplit(raw_gw).hostname or "").strip().lower() if raw_gw else ""
    if gw_host.startswith("gw.cosmos-mcp.") and gw_host.endswith((".org", ".workers.dev")):
        raw_gw = ""

    pub_prefix = f"/u/{node_id}"
    pub_base = f"{raw_gw}{pub_prefix}" if raw_gw else ""
    return {
        "ok": True,
        "node_id": node_id,
        "public_key_hex": pub_raw.hex(),
        "public_key_b64": base64.urlsafe_b64encode(pub_raw).decode("ascii").rstrip("="),
        "private_key_hex": ed_seed.hex(),
        "crypto_backend": crypto_backend,
        "gateway_base": raw_gw,
        "public_prefix": pub_prefix,
        "public_url": pub_base,
        "mcp_url": f"{pub_base}/mcp" if pub_base else "",
        "readonly_mcp_url": f"{pub_base}/mcp/readonly" if pub_base else "",
        "node_tunnel_secret": node_secret,
    }


def ensure_master_seed_identity(
    state_root: Path,
    prefix: str = "pc",
    *,
    gateway_base: str = "",
) -> Dict[str, Any]:
    """Generate or load 32-byte `master_seed[_<prefix>].bin` and derive permanent `/u/<node_id>/mcp` identity."""
    seed_p = master_seed_secret_path(state_root, prefix=prefix)
    seed_bytes = b""
    if seed_p.is_file():
        with contextlib.suppress(OSError):
            raw = seed_p.read_bytes()
            if len(raw) == 32:
                seed_bytes = raw
    if len(seed_bytes) != 32:
        seed_bytes = secrets.token_bytes(32)
        _atomic_write_bytes(seed_p, seed_bytes, mode_override=0o600)

    info = _derive_identity_from_seed(seed_bytes, gateway_base=gateway_base)
    info["seed_path"] = str(seed_p)
    return info


def derive_deterministic_worker_name(state_root: Path, prefix: str = "pc") -> str:
    """Derive deterministic Cloudflare Worker script name `cosmos-mcp-<node_id[:10]>` from `master_seed`."""
    identity = ensure_master_seed_identity(state_root, prefix=prefix)
    node_id = str(identity.get("node_id") or "").strip().lower()
    return f"cosmos-mcp-{node_id[:10]}"


def srvus_ssh_key_paths(state_root: Path, prefix: str = "pc") -> Tuple[Path, Path]:
    """Return `(<state_root>/secrets/srvus_ed25519[_<prefix>], ...pub)` keypair paths."""
    eff = _norm_prefix(prefix)
    stem = f"srvus_ed25519_{eff}" if eff != "pc" else "srvus_ed25519"
    sec_dir = Path(state_root).expanduser().resolve() / "secrets"
    return (sec_dir / stem, sec_dir / f"{stem}.pub")


def _service_cfg_candidate_paths(state_root: Path, prefix: str = "pc") -> Tuple[Path, ...]:
    st_root = Path(state_root).expanduser().resolve()
    eff = _norm_prefix(prefix)
    svc_canonical = st_root / "config" / (f"service_{eff}.json" if eff != "pc" else "service.json")
    svc_alias = st_root / "config" / (f"service_config_{eff}.json" if eff != "pc" else "service_config.json")
    if eff == "pc":
        return (svc_canonical, svc_alias, st_root / "config.json", st_root / "config" / "config.json")
    return (svc_canonical, svc_alias)


def _read_merged_service_config(state_root: Path, prefix: str = "pc") -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for cand in reversed(_service_cfg_candidate_paths(state_root, prefix)):
        if not cand.is_file():
            continue
        with contextlib.suppress(Exception):
            doc = json.loads(cand.read_text(encoding="utf-8-sig"))
            if isinstance(doc, dict):
                for k, v in doc.items():
                    if v is not None and v != "":
                        merged[k] = v
                    elif k not in merged:
                        merged[k] = v
    return merged


def _merge_write_service_configs(state_root: Path, prefix: str, updates: Dict[str, Any]) -> None:
    if not updates:
        return
    st_root = Path(state_root).expanduser().resolve()
    eff = _norm_prefix(prefix)
    svc_name = f"service_{eff}.json" if eff != "pc" else "service.json"
    svc_canonical = st_root / "config" / svc_name
    svc_alias = st_root / "config" / (f"service_config_{eff}.json" if eff != "pc" else "service_config.json")
    state_svc = st_root / "state" / svc_name
    targets: List[Path] = [svc_canonical]
    if svc_alias.is_file():
        targets.append(svc_alias)
    if state_svc.is_file():
        targets.append(state_svc)
    if eff == "pc" and (st_root / "config.json").is_file():
        targets.append(st_root / "config.json")

    now_ts = round(time.time(), 6)
    for cfg_p in targets:
        existing: Dict[str, Any] = {}
        if cfg_p.is_file():
            with contextlib.suppress(Exception):
                loaded = json.loads(cfg_p.read_text(encoding="utf-8-sig"))
                if isinstance(loaded, dict):
                    existing = dict(loaded)
        for k, v in updates.items():
            if v is not None and v != "":
                existing[k] = v
        existing["policy_updated_at"] = max(now_ts, float(existing.get("policy_updated_at") or 0.0) + 0.000001)
        raw_json = (json.dumps(existing, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        _atomic_write_bytes(cfg_p, raw_json, mode_override=0o600)


def _png_pack_chunk(chunk_type: bytes, data: bytes) -> bytes:
    if len(chunk_type) != 4:
        raise ValueError("PNG chunk type must be 4 ASCII bytes.")
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack("!I", len(data)) + chunk_type + data + struct.pack("!I", crc)


def _build_recovery_card_png_bytes(ancillary_payload: bytes, node_id: str) -> bytes:
    """Synthesize a valid RGB PNG image carrying `cMcp` ancillary recovery metadata using stdlib `zlib` + `struct`."""
    width, height = 160, 96
    digest = hashlib.sha256(node_id.encode("utf-8")).digest()
    accent_r, accent_g, accent_b = (40 + (digest[0] % 160), 90 + (digest[1] % 130), 160 + (digest[2] % 90))
    bg_r, bg_g, bg_b = (20, 26, 38)

    scanlines = bytearray()
    for y in range(height):
        scanlines.append(0)  # filter type 0 (None)
        is_banner = y < 14 or y >= (height - 8)
        for x in range(width):
            if is_banner or (16 <= x < 28 and 24 <= y < 72):
                scanlines.extend((accent_r, accent_g, accent_b))
            else:
                # Subtle deterministic visual grid pattern encoding node_id bits
                cell = ((x // 12) + (y // 12) * 14) % 32
                bit_on = bool(digest[cell % len(digest)] & (1 << (cell & 7)))
                if bit_on and 40 <= x < 144 and 24 <= y < 72:
                    scanlines.extend((48, 62, 88))
                else:
                    scanlines.extend((bg_r, bg_g, bg_b))

    ihdr = struct.pack("!IIBBBBB", width, height, 8, 2, 0, 0, 0)
    idat = zlib.compress(bytes(scanlines), level=6)
    return (
        PNG_SIGNATURE
        + _png_pack_chunk(b"IHDR", ihdr)
        + _png_pack_chunk(RECOVERY_PNG_CHUNK_TYPE, ancillary_payload)
        + _png_pack_chunk(b"IDAT", idat)
        + _png_pack_chunk(b"IEND", b"")
    )


def _stdlib_scrypt_stream_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    out = bytearray(len(data))
    offset = 0
    blk_idx = 0
    while offset < len(data):
        msg = (b"enc:" + nonce) if blk_idx == 0 else (b"enc:" + nonce + struct.pack("!I", blk_idx))
        ks = hmac.new(key, msg, hashlib.sha256).digest()
        take = min(32, len(data) - offset)
        for i in range(take):
            out[offset + i] = data[offset + i] ^ ks[i]
        offset += take
        blk_idx += 1
    return bytes(out)


def _encrypt_recovery_bytes_scrypt_aesgcm(
    plaintext: bytes,
    passphrase: str,
    *,
    version: int = 2,
) -> Dict[str, Any]:
    pw_bytes = (passphrase or "").encode("utf-8")
    if not pw_bytes:
        raise ValueError("Passphrase for identity recovery card must not be empty.")
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    n_param, r_param, p_param = 16384, 8, 1
    aad = RECOVERY_AAD if int(version) == 1 else RECOVERY_AAD_V2

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

        kdf = Scrypt(salt=salt, length=32, n=n_param, r=r_param, p=p_param)
        key = kdf.derive(pw_bytes)
        ct = AESGCM(key).encrypt(nonce, plaintext, aad)
        alg = "scrypt-aes-256-gcm"
    except ImportError:
        key = hashlib.scrypt(pw_bytes, salt=salt, n=n_param, r=r_param, p=p_param, dklen=32)
        mac_key = hmac.new(key, b"mac:" + nonce, hashlib.sha256).digest()
        body = _stdlib_scrypt_stream_xor(key, nonce, plaintext)
        tag = hmac.new(mac_key, aad + nonce + body, hashlib.sha256).digest()[:16]
        ct = body + tag
        alg = "scrypt-hmac-sha256"

    return {
        "v": int(version),
        "alg": alg,
        "n": n_param,
        "r": r_param,
        "p": p_param,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }


def _decrypt_recovery_bytes_scrypt_aesgcm(envelope: Dict[str, Any], passphrase: str) -> Tuple[int, bytes]:
    pw_bytes = (passphrase or "").encode("utf-8")
    if not pw_bytes:
        raise ValueError("Passphrase must not be empty.")
    ver = int(envelope.get("v") or 1)
    aad = RECOVERY_AAD if ver == 1 else RECOVERY_AAD_V2
    alg = str(envelope.get("alg") or "scrypt-aes-256-gcm")
    n_param = int(envelope.get("n") or 16384)
    r_param = int(envelope.get("r") or 8)
    p_param = int(envelope.get("p") or 1)
    salt = base64.b64decode(str(envelope["salt"]))
    nonce = base64.b64decode(str(envelope["nonce"]))
    ct = base64.b64decode(str(envelope["ct"]))

    if alg == "scrypt-aes-256-gcm":
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

        key = Scrypt(salt=salt, length=32, n=n_param, r=r_param, p=p_param).derive(pw_bytes)
        try:
            plain = AESGCM(key).decrypt(nonce, ct, aad)
        except Exception as exc:
            raise ValueError("Invalid recovery passphrase or tampered recovery card.") from exc
    elif alg == "scrypt-hmac-sha256":
        if (ver == 1 and len(ct) != 48) or len(ct) < 17:
            raise ValueError("Invalid recovery ciphertext length.")
        key = hashlib.scrypt(pw_bytes, salt=salt, n=n_param, r=r_param, p=p_param, dklen=32)
        mac_key = hmac.new(key, b"mac:" + nonce, hashlib.sha256).digest()
        body, tag = ct[:-16], ct[-16:]
        exp_tag = hmac.new(mac_key, aad + nonce + body, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, exp_tag):
            raise ValueError("Invalid recovery passphrase or tampered recovery card.")
        plain = _stdlib_scrypt_stream_xor(key, nonce, body)
    else:
        raise ValueError(f"Unsupported recovery card cipher `{alg}`.")

    return ver, plain


def _extract_seed_from_v2_bundle(bundle: Dict[str, Any]) -> bytes:
    raw_b64 = str(bundle.get("master_seed_b64") or "").strip()
    if raw_b64:
        try:
            seed = base64.b64decode(raw_b64)
            if len(seed) == 32:
                return seed
        except Exception:
            pass
    raw_hex = str(bundle.get("master_seed_hex") or bundle.get("master_seed") or "").strip()
    if raw_hex:
        try:
            seed = bytes.fromhex(raw_hex)
            if len(seed) == 32:
                return seed
        except Exception:
            pass
    raise ValueError("Recovered master_seed is not 32 bytes.")


def _encrypt_seed_scrypt_aesgcm(master_seed: bytes, passphrase: str) -> Dict[str, Any]:
    return _encrypt_recovery_bytes_scrypt_aesgcm(master_seed, passphrase, version=1)


def _decrypt_seed_scrypt_aesgcm(envelope: Dict[str, Any], passphrase: str) -> bytes:
    ver, plain = _decrypt_recovery_bytes_scrypt_aesgcm(envelope, passphrase)
    if ver == 1:
        if len(plain) != 32:
            raise ValueError("Recovered master_seed is not 32 bytes.")
        return plain
    try:
        doc = json.loads(plain.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Malformed v2 recovery bundle JSON.") from exc
    if not isinstance(doc, dict):
        raise ValueError("Malformed v2 recovery bundle payload.")
    return _extract_seed_from_v2_bundle(doc)


def export_identity_recovery_png(
    state_root: Path,
    passphrase: str,
    prefix: str = "pc",
) -> bytes:
    """Export an encrypted v2 PNG recovery card (`cMcp` chunk, `scrypt + AESGCM`) carrying full fixed-URL credentials."""
    st_root = Path(state_root).expanduser().resolve()
    eff_prefix = _norm_prefix(prefix)
    identity = ensure_master_seed_identity(st_root, prefix=eff_prefix)
    seed_p = Path(identity["seed_path"])
    master_seed = seed_p.read_bytes()

    wt_sec = ""
    wt_p = workers_tunnel_secret_path(st_root, prefix=eff_prefix)
    if wt_p.is_file():
        with contextlib.suppress(OSError):
            wt_sec = wt_p.read_text(encoding="utf-8", errors="replace").strip()

    vps_sec = ""
    vps_sec_fn = f"vps_node_secret_{eff_prefix}.txt" if eff_prefix != "pc" else "vps_node_secret.txt"
    vps_sec_p = st_root / "secrets" / vps_sec_fn
    if vps_sec_p.is_file():
        with contextlib.suppress(OSError):
            vps_sec = vps_sec_p.read_text(encoding="utf-8", errors="replace").strip()

    cfg_doc = _read_merged_service_config(st_root, eff_prefix)
    svc_bundle: Dict[str, Any] = {}
    wd_url = str(cfg_doc.get("workers_dev_url") or "").strip()
    wc_dom = str(cfg_doc.get("workers_custom_domain") or cfg_doc.get("workers_dev_custom_domain") or "").strip()
    t_mode = str(cfg_doc.get("tunnel_mode") or "").strip()
    if wd_url:
        svc_bundle["workers_dev_url"] = wd_url
    if wc_dom:
        svc_bundle["workers_custom_domain"] = wc_dom
    if t_mode:
        svc_bundle["tunnel_mode"] = t_mode
    for extra_k, alias_k in (
        ("workers_script_name", "workers_dev_script_name"),
        ("workers_subdomain", "workers_dev_subdomain"),
        ("workers_account_id", "workers_dev_account_id"),
        ("public_url", "public_base_url"),
        ("vps_hub_url", "vps_hub_url"),
        ("selected_gateway", "selected_gateway"),
    ):
        ev = str(cfg_doc.get(extra_k) or cfg_doc.get(alias_k) or "").strip()
        if ev:
            svc_bundle[extra_k] = ev
    if isinstance(cfg_doc.get("gateways"), dict):
        svc_bundle["gateways"] = cfg_doc["gateways"]
    if isinstance(cfg_doc.get("pinned_gateway_urls"), list):
        svc_bundle["pinned_gateway_urls"] = cfg_doc["pinned_gateway_urls"]
    if isinstance(cfg_doc.get("extra_trusted_urls"), list):
        svc_bundle["extra_trusted_urls"] = cfg_doc["extra_trusted_urls"]

    srvus_bundle: Dict[str, str] = {}
    priv_p, pub_p = srvus_ssh_key_paths(st_root, prefix=eff_prefix)
    if not priv_p.is_file() and eff_prefix != "pc":
        sec_dir = st_root / "secrets"
        if (sec_dir / "srvus_ed25519").is_file():
            priv_p, pub_p = sec_dir / "srvus_ed25519", sec_dir / "srvus_ed25519.pub"
    if priv_p.is_file():
        with contextlib.suppress(OSError):
            raw_priv = priv_p.read_bytes()
            if raw_priv:
                srvus_bundle["private_key_b64"] = base64.b64encode(raw_priv).decode("ascii")
    if pub_p.is_file():
        with contextlib.suppress(OSError):
            raw_pub = pub_p.read_bytes()
            if raw_pub:
                srvus_bundle["public_key_b64"] = base64.b64encode(raw_pub).decode("ascii")

    bundle_doc: Dict[str, Any] = {
        "v": 2,
        "node_id": identity["node_id"],
        "prefix": eff_prefix,
        "master_seed_hex": master_seed.hex(),
        "master_seed_b64": base64.b64encode(master_seed).decode("ascii"),
    }
    if wt_sec:
        bundle_doc["workers_tunnel_secret"] = wt_sec
    if vps_sec:
        bundle_doc["vps_node_secret"] = vps_sec
    if svc_bundle:
        bundle_doc["service_config"] = svc_bundle
    if srvus_bundle:
        bundle_doc["srvus_ed25519"] = srvus_bundle

    bundle_bytes = json.dumps(bundle_doc, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    envelope = _encrypt_recovery_bytes_scrypt_aesgcm(bundle_bytes, passphrase, version=2)
    envelope["node_id"] = identity["node_id"]
    chunk_bytes = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _build_recovery_card_png_bytes(chunk_bytes, identity["node_id"])


def import_identity_recovery_png(
    png_bytes: bytes,
    passphrase: str,
    state_root: Path,
    prefix: str = "pc",
) -> Dict[str, Any]:
    """Decrypt `cMcp` chunk (v1 raw 32B seed or v2 full connection bundle) and restore identity & fixed tunnel state."""
    if not isinstance(png_bytes, (bytes, bytearray)) or len(png_bytes) < 32:
        raise ValueError("Invalid PNG recovery card bytes.")
    raw = bytes(png_bytes)
    if raw[:8] != PNG_SIGNATURE:
        raise ValueError("File is not a valid PNG image.")

    pos = 8
    cmcp_payload: Optional[bytes] = None
    while pos + 8 <= len(raw):
        length = struct.unpack("!I", raw[pos : pos + 4])[0]
        ctype = raw[pos + 4 : pos + 8]
        data_start = pos + 8
        data_end = data_start + length
        crc_end = data_end + 4
        if crc_end > len(raw):
            raise ValueError("Truncated PNG chunk in recovery card.")
        cdata = raw[data_start:data_end]
        expected_crc = struct.unpack("!I", raw[data_end:crc_end])[0]
        actual_crc = zlib.crc32(ctype + cdata) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise ValueError(f"PNG CRC mismatch in chunk `{ctype.decode('latin-1', errors='replace')}`.")
        if ctype == RECOVERY_PNG_CHUNK_TYPE:
            cmcp_payload = cdata
            break
        if ctype == b"IEND":
            break
        pos = crc_end

    if cmcp_payload is None:
        raise ValueError("PNG image does not contain a Cosmos MCP recovery chunk (`cMcp`).")

    try:
        envelope = json.loads(cmcp_payload.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Malformed `cMcp` recovery metadata JSON.") from exc

    st_root = Path(state_root).expanduser().resolve()
    eff_prefix = _norm_prefix(prefix)
    ver, plain_bytes = _decrypt_recovery_bytes_scrypt_aesgcm(envelope, passphrase)

    bundle: Dict[str, Any] = {}
    if ver == 1:
        if len(plain_bytes) != 32:
            raise ValueError("Recovered master_seed is not 32 bytes.")
        recovered_seed = plain_bytes
    else:
        try:
            parsed_bundle = json.loads(plain_bytes.decode("utf-8"))
        except Exception as exc:
            raise ValueError("Malformed v2 recovery bundle JSON.") from exc
        if not isinstance(parsed_bundle, dict):
            raise ValueError("Malformed v2 recovery bundle payload.")
        bundle = parsed_bundle
        recovered_seed = _extract_seed_from_v2_bundle(bundle)

    expected_node = str(envelope.get("node_id") or "").strip().lower()
    derived_preview = _derive_identity_from_seed(recovered_seed)
    if expected_node and derived_preview["node_id"] != expected_node:
        raise ValueError("Recovered seed node_id mismatch.")

    seed_p = master_seed_secret_path(st_root, prefix=eff_prefix)
    _atomic_write_bytes(seed_p, recovered_seed, mode_override=0o600)
    restored = ensure_master_seed_identity(st_root, prefix=eff_prefix)

    wt_sec = str(bundle.get("workers_tunnel_secret") or "").strip()
    if wt_sec:
        wt_p = workers_tunnel_secret_path(st_root, prefix=eff_prefix)
        _atomic_write_secret_text(wt_p, wt_sec + "\n")

    vps_sec_restored = str(bundle.get("vps_node_secret") or "").strip()
    if vps_sec_restored:
        vps_fn = f"vps_node_secret_{eff_prefix}.txt" if eff_prefix != "pc" else "vps_node_secret.txt"
        _atomic_write_secret_text(st_root / "secrets" / vps_fn, vps_sec_restored + "\n")

    srvus_obj = bundle.get("srvus_ed25519")
    has_srvus_key = False
    if isinstance(srvus_obj, dict):
        priv_b64 = str(srvus_obj.get("private_key_b64") or "").strip()
        pub_b64 = str(srvus_obj.get("public_key_b64") or "").strip()
        try:
            priv_bytes = base64.b64decode(priv_b64) if priv_b64 else b""
            pub_bytes = base64.b64decode(pub_b64) if pub_b64 else b""
        except Exception as exc:
            raise ValueError("Malformed `srvus_ed25519` key data in recovery card.") from exc
        priv_p, pub_p = srvus_ssh_key_paths(st_root, prefix=eff_prefix)
        target_pairs: List[Tuple[Path, Path]] = [(priv_p, pub_p)]
        if eff_prefix != "pc":
            base_priv = st_root / "secrets" / "srvus_ed25519"
            base_pub = st_root / "secrets" / "srvus_ed25519.pub"
            if not base_priv.exists():
                target_pairs.append((base_priv, base_pub))
        for tp_priv, tp_pub in target_pairs:
            if priv_bytes:
                _atomic_write_bytes(tp_priv, priv_bytes, mode_override=0o600)
                with contextlib.suppress(OSError):
                    os.chmod(tp_priv, 0o600)
                has_srvus_key = True
            if pub_bytes:
                _atomic_write_bytes(tp_pub, pub_bytes, mode_override=0o600)
                with contextlib.suppress(OSError):
                    os.chmod(tp_pub, 0o600)

    svc_obj = bundle.get("service_config") if isinstance(bundle.get("service_config"), dict) else {}
    restored_workers_url = str(svc_obj.get("workers_dev_url") or bundle.get("workers_dev_url") or "").strip()
    restored_custom_domain = str(
        svc_obj.get("workers_custom_domain")
        or svc_obj.get("workers_dev_custom_domain")
        or bundle.get("workers_custom_domain")
        or ""
    ).strip()
    restored_tunnel_mode = str(svc_obj.get("tunnel_mode") or bundle.get("tunnel_mode") or "").strip()

    cfg_updates: Dict[str, Any] = {}
    if restored_workers_url:
        cfg_updates["workers_dev_url"] = restored_workers_url
    if restored_custom_domain:
        cfg_updates["workers_custom_domain"] = restored_custom_domain
        cfg_updates["workers_dev_custom_domain"] = restored_custom_domain
    if restored_tunnel_mode:
        cfg_updates["tunnel_mode"] = restored_tunnel_mode
    for extra_k, alias_k in (
        ("workers_script_name", "workers_dev_script_name"),
        ("workers_subdomain", "workers_dev_subdomain"),
        ("workers_account_id", "workers_dev_account_id"),
        ("vps_hub_url", "vps_hub_url"),
        ("selected_gateway", "selected_gateway"),
    ):
        ev = str(svc_obj.get(extra_k) or bundle.get(extra_k) or "").strip()
        if ev:
            cfg_updates[extra_k] = ev
            cfg_updates[alias_k] = ev
    if isinstance(svc_obj.get("gateways"), dict):
        cfg_updates["gateways"] = svc_obj["gateways"]
    if isinstance(svc_obj.get("pinned_gateway_urls"), list):
        cfg_updates["pinned_gateway_urls"] = svc_obj["pinned_gateway_urls"]
    if isinstance(svc_obj.get("extra_trusted_urls"), list):
        cfg_updates["extra_trusted_urls"] = svc_obj["extra_trusted_urls"]
    if restored_tunnel_mode == "workers_dev" and (restored_custom_domain or restored_workers_url):
        eff_pub = (
            f"https://{restored_custom_domain}"
            if restored_custom_domain and "://" not in restored_custom_domain
            else (restored_custom_domain or restored_workers_url)
        )
        cfg_updates["public_url"] = eff_pub
        cfg_updates["public_base_url"] = eff_pub

    if cfg_updates:
        _merge_write_service_configs(st_root, eff_prefix, cfg_updates)

    restored["restored"] = True
    restored["recovery_version"] = ver
    restored["workers_dev_url"] = restored_workers_url
    restored["workers_custom_domain"] = restored_custom_domain
    restored["has_srvus_key"] = has_srvus_key
    restored["restored_tunnel_mode"] = restored_tunnel_mode
    return restored


# ---------------------------------------------------------------------------
# Card 2A: Secret Helpers & Cloudflare v4 REST API 4-Step Idempotent Deployer
# ---------------------------------------------------------------------------

def cloudflare_api_token_secret_path(state_root: Path, prefix: str = "pc") -> Path:
    eff = _norm_prefix(prefix)
    fn = f"cloudflare_api_token_{eff}.txt" if eff != "pc" else "cloudflare_api_token.txt"
    return Path(state_root).expanduser().resolve() / "secrets" / fn


def workers_tunnel_secret_path(state_root: Path, prefix: str = "pc") -> Path:
    eff = _norm_prefix(prefix)
    fn = f"workers_tunnel_secret_{eff}.txt" if eff != "pc" else "workers_tunnel_secret.txt"
    return Path(state_root).expanduser().resolve() / "secrets" / fn


def _normalize_api_token(raw: str) -> str:
    s = (raw or "").strip().strip("\"'")
    if s.lower().startswith("bearer "):
        s = s[7:].strip()
    return s


def shred_cloudflare_api_token(state_root: Path, prefix: str = "pc") -> bool:
    """Zero-overwrite and delete any persisted `cloudflare_api_token[_<prefix>].txt` (burn-after-deploy)."""
    st_root = Path(state_root).expanduser().resolve()
    p = cloudflare_api_token_secret_path(st_root, prefix=prefix)
    shredded = _shred_secret_file(p)
    # Also purge any undo/trash copies of cloudflare_api_token for this prefix
    for sub in (".undo_history", "trash", ".trash"):
        v_dir = st_root / sub
        if v_dir.is_dir():
            for cand in list(v_dir.rglob("*cloudflare_api_token*")):
                if cand.is_file() or cand.is_symlink():
                    _shred_secret_file(cand)
    return shredded


def load_cloudflare_api_token(state_root: Path, prefix: str = "pc") -> str:
    """Load Cloudflare API token from `<state_root>/secrets/cloudflare_api_token[_<prefix>].txt` if present."""
    p = cloudflare_api_token_secret_path(state_root, prefix=prefix)
    if p.is_file():
        with contextlib.suppress(OSError):
            return _normalize_api_token(p.read_text(encoding="utf-8", errors="replace"))
    return ""


def load_or_create_workers_tunnel_secret(state_root: Path, prefix: str = "pc") -> str:
    """Load or generate 256-bit `secrets.token_hex(32)` in `workers_tunnel_secret[_<prefix>].txt`."""
    p = workers_tunnel_secret_path(state_root, prefix=prefix)
    if p.is_file():
        with contextlib.suppress(OSError):
            existing = p.read_text(encoding="utf-8", errors="replace").strip()
            if len(existing) >= 32:
                return existing
    secret_val = secrets.token_hex(32)
    _atomic_write_secret_text(p, secret_val + "\n")
    return secret_val


def _build_cf_api_openers(api_base_url: str) -> List[urllib.request.OpenerDirector]:
    host = (urlsplit(api_base_url).hostname or "").strip().lower()
    if host in ("127.0.0.1", "::1", "localhost"):
        return [urllib.request.build_opener(urllib.request.ProxyHandler({}))]
    openers: List[urllib.request.OpenerDirector] = []
    ctx = ssl.create_default_context()
    https_handler = urllib.request.HTTPSHandler(context=ctx)
    proxy = _detect_system_proxy("https", target_host=host)
    if proxy and proxy.lower().startswith(("http://", "https://")):
        openers.append(
            urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy, "https": proxy}),
                https_handler,
            )
        )
    openers.append(urllib.request.build_opener(urllib.request.ProxyHandler({}), https_handler))
    return openers


def _cf_api_call(
    openers: Sequence[urllib.request.OpenerDirector],
    method: str,
    url: str,
    *,
    api_token: str,
    body: Optional[bytes] = None,
    content_type: str = "application/json",
    timeout_sec: float = 35.0,
) -> Tuple[int, Dict[str, Any]]:
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json",
        "User-Agent": "Cosmos-MCP-Gateway/1.0",
    }
    if body is not None:
        headers["Content-Type"] = content_type

    last_exc: Optional[Exception] = None
    for idx, opener in enumerate(openers):
        req = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
        try:
            with opener.open(req, timeout=timeout_sec) as resp:
                status = int(getattr(resp, "status", 200))
                raw = resp.read()
        except HTTPError as he:
            status = int(he.code)
            raw = b""
            with contextlib.suppress(Exception):
                raw = he.read()
        except URLError as ue:
            last_exc = ue
            if idx + 1 < len(openers):
                continue
            raise ConnectionError(f"Cloudflare API connection failed ({url}): {ue}") from ue
        except Exception as exc:
            last_exc = exc
            if idx + 1 < len(openers):
                continue
            raise

        txt = raw.decode("utf-8", errors="replace").strip()
        if not txt:
            return status, {"success": 200 <= status < 300, "result": None, "errors": []}
        try:
            doc = json.loads(txt)
            if isinstance(doc, dict):
                return status, doc
            return status, {"success": 200 <= status < 300, "result": doc, "errors": []}
        except json.JSONDecodeError:
            return status, {"success": False, "result": None, "errors": [{"message": txt[:400]}]}

    raise ConnectionError(f"Cloudflare API call exhausted openers ({url}): {last_exc}")


def _encode_worker_multipart(metadata: Dict[str, Any], worker_mjs: str) -> Tuple[bytes, str]:
    """Build standard RFC 7578 `multipart/form-data` payload for ES Module Worker + Durable Object upload."""
    boundary = f"----CosmosMcpWorkerBoundary{secrets.token_hex(12)}"
    meta_bytes = json.dumps(metadata, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    script_bytes = worker_mjs.encode("utf-8")

    parts = bytearray()
    # Part 1: metadata JSON
    parts.extend(f"--{boundary}\r\n".encode("ascii"))
    parts.extend(b'Content-Disposition: form-data; name="metadata"\r\n')
    parts.extend(b"Content-Type: application/json\r\n\r\n")
    parts.extend(meta_bytes)
    parts.extend(b"\r\n")

    # Part 2: ES Module script (`worker.mjs`)
    parts.extend(f"--{boundary}\r\n".encode("ascii"))
    parts.extend(b'Content-Disposition: form-data; name="worker.mjs"; filename="worker.mjs"\r\n')
    parts.extend(b"Content-Type: application/javascript+module\r\n\r\n")
    parts.extend(script_bytes)
    parts.extend(b"\r\n")

    parts.extend(f"--{boundary}--\r\n".encode("ascii"))
    return bytes(parts), f"multipart/form-data; boundary={boundary}"


def _extract_cf_error_summary(doc: Dict[str, Any], status: int) -> str:
    errs = doc.get("errors")
    if isinstance(errs, list) and errs:
        msgs: List[str] = []
        for item in errs:
            if isinstance(item, dict):
                code = item.get("code")
                msg = str(item.get("message") or "").strip()
                msgs.append(f"[{code}] {msg}" if code is not None else msg)
            else:
                msgs.append(str(item))
        joined = "; ".join(m for m in msgs if m)
        if joined:
            return joined
    return f"HTTP {status}"


def deploy_cloudflare_workers_gateway(
    *,
    api_token: str,
    state_root: Path,
    prefix: str = "pc",
    account_id: str = "",
    script_name: str = "cosmos-mcp-gateway",
    custom_domain: str = "",
    api_base_url: str = "https://api.cloudflare.com/client/v4",
    timeout_sec: float = 35.0,
) -> Dict[str, Any]:
    """4-step idempotent Cloudflare `workers.dev + SQLite Durable Object` deployer with burn-after-deploy token wipe."""
    st_root = Path(state_root).expanduser().resolve()
    eff_prefix = _norm_prefix(prefix)
    tok = _normalize_api_token(api_token) or load_cloudflare_api_token(st_root, prefix=eff_prefix)
    if not tok:
        return {"ok": False, "error": "missing_api_token", "message": "Cloudflare API Token 不能为空。"}

    identity_info = ensure_master_seed_identity(st_root, prefix=eff_prefix)
    node_id_10 = str(identity_info.get("node_id") or "")[:10].lower()

    raw_script_in = (script_name or "").strip().lower()
    if raw_script_in in _DEFAULT_GENERIC_SCRIPT_NAMES:
        existing_cfg = _read_merged_service_config(st_root, eff_prefix)
        hist_script = str(
            existing_cfg.get("workers_script_name")
            or existing_cfg.get("workers_dev_script_name")
            or ""
        ).strip().lower()
        if (
            raw_script_in != "auto"
            and hist_script
            and hist_script not in _DEFAULT_GENERIC_SCRIPT_NAMES
            and _SCRIPT_SLUG_RE.match(hist_script)
        ):
            clean_script = hist_script
        else:
            clean_script = derive_deterministic_worker_name(st_root, prefix=eff_prefix)
    else:
        clean_script = raw_script_in

    if not _SCRIPT_SLUG_RE.match(clean_script):
        return {"ok": False, "error": "invalid_script_name", "message": f"非法 Worker 名称: {script_name!r}"}

    base = (api_base_url or "https://api.cloudflare.com/client/v4").strip().rstrip("/")
    openers = _build_cf_api_openers(base)

    # Step 1: GET /accounts
    try:
        st_acc, doc_acc = _cf_api_call(openers, "GET", f"{base}/accounts", api_token=tok, timeout_sec=timeout_sec)
    except Exception as exc:
        return {"ok": False, "step": "list_accounts", "error": "network_error", "message": str(exc)}

    if st_acc >= 400 or not doc_acc.get("success", False):
        return {
            "ok": False,
            "step": "list_accounts",
            "status_code": st_acc,
            "error": "cloudflare_accounts_query_failed",
            "message": _extract_cf_error_summary(doc_acc, st_acc),
        }

    raw_accounts = doc_acc.get("result")
    accounts: List[Dict[str, str]] = []
    if isinstance(raw_accounts, list):
        for item in raw_accounts:
            if isinstance(item, dict) and item.get("id"):
                aid = str(item["id"]).strip()
                aname = str(item.get("name") or aid).strip()
                accounts.append({"id": aid, "name": aname})

    if not accounts:
        return {
            "ok": False,
            "step": "list_accounts",
            "error": "no_cloudflare_accounts",
            "message": "该 API Token 下未查询到任何 Cloudflare 账号，请确认已勾选 Account Settings: Read 权限。",
        }

    req_acc = (account_id or "").strip()
    if req_acc:
        matched = next((a for a in accounts if a["id"] == req_acc), None)
        if matched is None:
            return {
                "ok": False,
                "step": "list_accounts",
                "error": "account_id_not_found",
                "accounts": accounts,
            }
        acc_id = matched["id"]
    elif len(accounts) == 1:
        acc_id = accounts[0]["id"]
    else:
        return {
            "ok": False,
            "error": "multiple_accounts_select_required",
            "accounts": accounts,
        }

    # Step 2: GET /accounts/{acc_id}/workers/subdomain (register only if missing, avoiding 10036)
    sub_url = f"{base}/accounts/{acc_id}/workers/subdomain"
    st_sub, doc_sub = _cf_api_call(openers, "GET", sub_url, api_token=tok, timeout_sec=timeout_sec)
    subdomain = ""
    if 200 <= st_sub < 300 and doc_sub.get("success") and isinstance(doc_sub.get("result"), dict):
        subdomain = str(doc_sub["result"].get("subdomain") or "").strip().lower()

    if not subdomain:
        reg_err = ""
        for _attempt in range(3):
            candidate = (
                f"cosmos-{node_id_10}"
                if _attempt == 0 and node_id_10
                else f"cosmos-{node_id_10 or 'mcp'}-{secrets.token_hex(2)}"
            )
            put_body = json.dumps({"subdomain": candidate}).encode("utf-8")
            st_put, doc_put = _cf_api_call(
                openers,
                "PUT",
                sub_url,
                api_token=tok,
                body=put_body,
                timeout_sec=timeout_sec,
            )
            if 200 <= st_put < 300 and doc_put.get("success"):
                res_obj = doc_put.get("result")
                subdomain = (
                    str(res_obj.get("subdomain") or candidate).strip().lower()
                    if isinstance(res_obj, dict)
                    else candidate
                )
                break
            reg_err = _extract_cf_error_summary(doc_put, st_put)
            # If error 10036 indicates subdomain was concurrently created, re-GET once
            if "10036" in reg_err:
                st_re, doc_re = _cf_api_call(openers, "GET", sub_url, api_token=tok, timeout_sec=timeout_sec)
                if 200 <= st_re < 300 and isinstance(doc_re.get("result"), dict):
                    subdomain = str(doc_re["result"].get("subdomain") or "").strip().lower()
                    if subdomain:
                        break
        if not subdomain:
            return {
                "ok": False,
                "step": "register_subdomain",
                "error": "subdomain_registration_failed",
                "message": reg_err or "Failed to register workers.dev subdomain",
            }

    # Step 3: Check existing scripts for DO migration tag, then upload ES Module + SQLite DO
    tunnel_secret = load_or_create_workers_tunnel_secret(st_root, prefix=eff_prefix)
    scripts_list_url = f"{base}/accounts/{acc_id}/workers/scripts"
    st_list, doc_list = _cf_api_call(openers, "GET", scripts_list_url, api_token=tok, timeout_sec=timeout_sec)
    has_do_migration = False
    if 200 <= st_list < 300 and doc_list.get("success") and isinstance(doc_list.get("result"), list):
        for s_item in doc_list["result"]:
            if isinstance(s_item, dict) and str(s_item.get("id") or "") == clean_script:
                if s_item.get("migration_tag") or s_item.get("has_durable_objects"):
                    has_do_migration = True
                break

    def _build_metadata(include_migrations: bool) -> Dict[str, Any]:
        meta: Dict[str, Any] = {
            "main_module": "worker.mjs",
            "compatibility_date": "2025-09-01",
            "bindings": [
                {
                    "type": "durable_object_namespace",
                    "name": "RELAY_DO",
                    "class_name": "CosmosRelayDO",
                },
                {
                    "type": "secret_text",
                    "name": "TUNNEL_SECRET",
                    "text": tunnel_secret,
                },
            ],
        }
        if include_migrations:
            meta["migrations"] = {
                "new_tag": "v1",
                "new_sqlite_classes": ["CosmosRelayDO"],
            }
        return meta

    script_put_url = f"{base}/accounts/{acc_id}/workers/scripts/{clean_script}"
    initial_with_mig = not has_do_migration
    mp_body, mp_ctype = _encode_worker_multipart(_build_metadata(initial_with_mig), WORKER_RELAY_MJS)
    st_up, doc_up = _cf_api_call(
        openers,
        "PUT",
        script_put_url,
        api_token=tok,
        body=mp_body,
        content_type=mp_ctype,
        timeout_sec=timeout_sec,
    )
    if (st_up >= 400 or not doc_up.get("success")) and initial_with_mig:
        # Automatic idempotent retry stripping `migrations` if DO class v1 already exists on account
        mp_body2, mp_ctype2 = _encode_worker_multipart(_build_metadata(False), WORKER_RELAY_MJS)
        st_up, doc_up = _cf_api_call(
            openers,
            "PUT",
            script_put_url,
            api_token=tok,
            body=mp_body2,
            content_type=mp_ctype2,
            timeout_sec=timeout_sec,
        )
    elif (st_up >= 400 or not doc_up.get("success")) and not initial_with_mig:
        # Fallback in case script existed without SQLite DO migration yet
        mp_body2, mp_ctype2 = _encode_worker_multipart(_build_metadata(True), WORKER_RELAY_MJS)
        st_up, doc_up = _cf_api_call(
            openers,
            "PUT",
            script_put_url,
            api_token=tok,
            body=mp_body2,
            content_type=mp_ctype2,
            timeout_sec=timeout_sec,
        )

    if st_up >= 400 or not doc_up.get("success"):
        return {
            "ok": False,
            "step": "upload_worker_script",
            "status_code": st_up,
            "error": "worker_script_upload_failed",
            "message": _extract_cf_error_summary(doc_up, st_up),
        }

    # Step 4: Check GET .../scripts/{script_name}/subdomain; enable via POST (strictly POST, never PUT!)
    route_sub_url = f"{base}/accounts/{acc_id}/workers/scripts/{clean_script}/subdomain"
    st_rget, doc_rget = _cf_api_call(openers, "GET", route_sub_url, api_token=tok, timeout_sec=timeout_sec)
    already_enabled = bool(
        200 <= st_rget < 300
        and doc_rget.get("success")
        and isinstance(doc_rget.get("result"), dict)
        and doc_rget["result"].get("enabled") is True
    )
    if not already_enabled:
        st_rpost, doc_rpost = _cf_api_call(
            openers,
            "POST",
            route_sub_url,
            api_token=tok,
            body=json.dumps({"enabled": True}).encode("utf-8"),
            timeout_sec=timeout_sec,
        )
        if st_rpost >= 400 or not doc_rpost.get("success"):
            return {
                "ok": False,
                "step": "enable_workers_dev_route",
                "status_code": st_rpost,
                "error": "enable_subdomain_route_failed",
                "message": _extract_cf_error_summary(doc_rpost, st_rpost),
            }

    workers_dev_url = f"https://{clean_script}.{subdomain}.workers.dev"
    final_public_url = workers_dev_url

    # Optional Custom Domain binding (e.g. anti-DNS-pollution `*.dpdns.org` or user zone in Cloudflare)
    clean_custom = (custom_domain or "").strip().lower()
    if "://" in clean_custom:
        clean_custom = (urlsplit(clean_custom).hostname or clean_custom).strip().lower()
    clean_custom = clean_custom.strip("/")

    if clean_custom:
        q_zones = urlencode({"account.id": acc_id, "status": "active", "per_page": 50})
        st_z, doc_z = _cf_api_call(openers, "GET", f"{base}/zones?{q_zones}", api_token=tok, timeout_sec=timeout_sec)
        if st_z >= 400 or not doc_z.get("success", False):
            err_sum_z = _extract_cf_error_summary(doc_z, st_z)
            perm_hint = (
                "（请确认 API Token 已包含 Zone: Read 与 Workers Routes: Edit 权限）"
                if st_z in (401, 403)
                else ""
            )
            return {
                "ok": False,
                "step": "bind_custom_domain",
                "status_code": st_z,
                "error": "custom_domain_zones_query_failed",
                "message": f"查询自定义域名所属 Cloudflare Zone 失败: {err_sum_z}{perm_hint}",
            }
        matched_zone_id = ""
        best_len = -1
        if 200 <= st_z < 300 and isinstance(doc_z.get("result"), list):
            for z in doc_z["result"]:
                if not isinstance(z, dict):
                    continue
                zn = str(z.get("name") or "").strip().lower()
                zid = str(z.get("id") or "").strip()
                if zn and zid and (clean_custom == zn or clean_custom.endswith("." + zn)):
                    if len(zn) > best_len:
                        best_len = len(zn)
                        matched_zone_id = zid
        if not matched_zone_id:
            return {
                "ok": False,
                "step": "bind_custom_domain",
                "error": "custom_domain_zone_not_found",
                "message": f"未在当前 Cloudflare 账号下找到域名 `{clean_custom}` 所属的活动 Zone。",
            }
        dom_payload = json.dumps(
            {
                "environment": "production",
                "hostname": clean_custom,
                "service": clean_script,
                "zone_id": matched_zone_id,
            }
        ).encode("utf-8")
        st_dom, doc_dom = _cf_api_call(
            openers,
            "PUT",
            f"{base}/accounts/{acc_id}/workers/domains",
            api_token=tok,
            body=dom_payload,
            timeout_sec=timeout_sec,
        )
        if st_dom >= 400 or not doc_dom.get("success"):
            return {
                "ok": False,
                "step": "bind_custom_domain",
                "status_code": st_dom,
                "error": "custom_domain_bind_failed",
                "message": _extract_cf_error_summary(doc_dom, st_dom),
            }
        final_public_url = f"https://{clean_custom}"

    # Burn-after-deploy: zero-fill & delete any plaintext `cloudflare_api_token*.txt` from disk!
    shred_cloudflare_api_token(st_root, prefix=eff_prefix)

    with contextlib.suppress(Exception):
        from cosmos_mcp.launcher.tunnels import hot_refresh_public_url

        hot_refresh_public_url(
            st_root,
            final_public_url,
            prefix=eff_prefix,
            tunnel_mode="workers_dev",
            gateway_id="workers_dev",
        )
    existing_cfg = _read_merged_service_config(st_root, eff_prefix)
    deploy_cfg_updates: Dict[str, Any] = {
        "workers_dev_url": workers_dev_url,
        "workers_account_id": acc_id,
        "workers_subdomain": subdomain,
        "workers_script_name": clean_script,
    }
    with contextlib.suppress(Exception):
        from cosmos_mcp.core.config import collect_pinned_gateway_urls, normalize_gateways_config

        gws_cur, sel_cur = normalize_gateways_config(existing_cfg)
        other_active = any(
            gid != "workers_dev"
            and bool(gws_cur.get(gid, {}).get("enabled"))
            and bool(str(gws_cur.get(gid, {}).get("public_url") or "").strip())
            for gid in gws_cur
        )
        slot_update: Dict[str, Any] = {
            **dict(gws_cur.get("workers_dev") or {}),
            "enabled": True,
            "submode": "workers_dev",
            "public_url": final_public_url,
            "workers_dev_url": workers_dev_url,
        }
        if clean_custom:
            slot_update["custom_domain"] = f"https://{clean_custom}"
        gws_cur["workers_dev"] = slot_update
        if not other_active or not sel_cur or sel_cur == "workers_dev":
            sel_cur = "workers_dev"
            deploy_cfg_updates["tunnel_mode"] = "workers_dev"
            deploy_cfg_updates["_gateways_mirrored_mode"] = "workers_dev"
            deploy_cfg_updates["public_url"] = final_public_url
            deploy_cfg_updates["public_base"] = final_public_url
            deploy_cfg_updates["public_base_url"] = final_public_url
        deploy_cfg_updates["gateways"] = gws_cur
        deploy_cfg_updates["selected_gateway"] = sel_cur
        deploy_cfg_updates["pinned_gateway_urls"] = collect_pinned_gateway_urls(
            gws_cur,
            {**existing_cfg, **deploy_cfg_updates},
        )
    if "tunnel_mode" not in deploy_cfg_updates and "gateways" not in deploy_cfg_updates:
        deploy_cfg_updates["tunnel_mode"] = "workers_dev"
        deploy_cfg_updates["public_url"] = final_public_url
        deploy_cfg_updates["public_base_url"] = final_public_url
    if clean_custom:
        deploy_cfg_updates["workers_custom_domain"] = clean_custom
        deploy_cfg_updates["workers_dev_custom_domain"] = clean_custom
    with contextlib.suppress(Exception):
        _merge_write_service_configs(st_root, eff_prefix, deploy_cfg_updates)

    result: Dict[str, Any] = {
        "ok": True,
        "public_url": final_public_url,
        "workers_dev_url": workers_dev_url,
        "account_id": acc_id,
        "subdomain": subdomain,
        "script_name": clean_script,
        "api_token_shredded": True,
    }
    if clean_custom:
        result["custom_domain"] = clean_custom
    return result


def save_workers_custom_domain_local(
    state_root: Path,
    custom_domain: str,
    *,
    prefix: str = "pc",
) -> Dict[str, Any]:
    """Bind or clear a custom domain locally on an already-deployed Cloudflare Worker without requiring an API token."""
    st_root = Path(state_root).expanduser().resolve()
    eff_prefix = _norm_prefix(prefix)
    sec_p = workers_tunnel_secret_path(st_root, prefix=eff_prefix)
    existing_cfg = _read_merged_service_config(st_root, eff_prefix)
    wd_base = str(existing_cfg.get("workers_dev_url") or "").strip().rstrip("/")
    subd = str(existing_cfg.get("workers_subdomain") or existing_cfg.get("workers_dev_subdomain") or "").strip()
    sc_name = str(existing_cfg.get("workers_script_name") or existing_cfg.get("workers_dev_script_name") or "").strip()
    if (not wd_base or not wd_base.endswith(".workers.dev")) and subd and sc_name:
        wd_base = f"https://{sc_name}.{subd}.workers.dev"
    if not sec_p.is_file() or not wd_base:
        return {
            "ok": False,
            "error": "workers_not_deployed",
            "message": "尚未检测到已部署的 Cloudflare Worker 密钥，请先填入一次性 API Token 完成首次部署。",
        }

    clean_custom = (custom_domain or "").strip().lower()
    if "://" in clean_custom:
        clean_custom = (urlsplit(clean_custom).hostname or clean_custom).strip().lower()
    clean_custom = clean_custom.strip("/")

    active_pub = f"https://{clean_custom}" if clean_custom else wd_base
    from cosmos_mcp.core.config import collect_pinned_gateway_urls, normalize_gateways_config

    gws_cur, sel_cur = normalize_gateways_config(existing_cfg)
    slot_w = dict(gws_cur.get("workers_dev") or {})
    slot_w["enabled"] = True
    slot_w["submode"] = "workers_dev"
    slot_w["public_url"] = active_pub
    slot_w["workers_dev_url"] = wd_base
    if clean_custom:
        slot_w["custom_domain"] = active_pub
    else:
        slot_w.pop("custom_domain", None)
    gws_cur["workers_dev"] = slot_w

    updates: Dict[str, Any] = {
        "workers_dev_url": wd_base,
        "workers_custom_domain": clean_custom,
        "workers_dev_custom_domain": clean_custom,
        "gateways": gws_cur,
        "selected_gateway": sel_cur,
    }
    if sel_cur == "workers_dev":
        updates["public_url"] = active_pub
        updates["public_base"] = active_pub
        updates["public_base_url"] = active_pub
    updates["pinned_gateway_urls"] = collect_pinned_gateway_urls(gws_cur, {**existing_cfg, **updates})
    _merge_write_service_configs(st_root, eff_prefix, updates)
    return {
        "ok": True,
        "public_url": active_pub,
        "workers_dev_url": wd_base,
        "custom_domain": clean_custom,
        "tokenless_local_update": True,
    }


# ---------------------------------------------------------------------------
# Outbound `443 WSS` Multiplexing Supervisor (`WorkersDevRelaySupervisor`)
# ---------------------------------------------------------------------------

def _create_threadsafe_ws_client(
    ws_url: str,
    *,
    timeout: float,
    idle_timeout_sec: float,
    extra_headers: Dict[str, str],
    ssl_context: Optional[ssl.SSLContext] = None,
) -> Any:
    """Instantiate `core.net_power.StdlibWebSocketClient` wrapped with a reentrant `_send_lock` and RX clock."""
    from cosmos_mcp.core.net_power import StdlibWebSocketClient

    class _CompatLockedWebSocketClient(StdlibWebSocketClient):
        def __init__(self) -> None:
            super().__init__(
                ws_url,
                timeout=timeout,
                origin=None,
                extra_headers=extra_headers,
                enforce_public_ssrf=False,
                ssl_context=ssl_context,
                auto_connect=False,
            )
            # Reentrant RLock protects concurrent writers AND avoids deadlock even if base class acquires `_send_lock`
            rlock = threading.RLock()
            self._send_lock = rlock
            if hasattr(self, "_write_lock"):
                self._write_lock = rlock
            self._abort_evt = threading.Event()
            self.idle_timeout_sec = float(idle_timeout_sec)
            self.last_rx_mono = time.monotonic()

        def connect(self, proxy_url: str = "") -> None:
            super().connect(proxy_url=proxy_url)
            self.last_rx_mono = time.monotonic()
            if self.sock is not None:
                with contextlib.suppress(OSError):
                    self.sock.settimeout(max(5.0, float(timeout)))

        def send_frame(self, payload: bytes, opcode: int = 0x1) -> None:
            with self._send_lock:
                super().send_frame(payload, opcode=opcode)

        def _recv_exact(self, n: int) -> bytes:
            if n == 0:
                return b""
            if n > self.max_frame_bytes:
                raise ValueError(f"Requested {n} bytes exceeds max_frame_bytes ({self.max_frame_bytes})")
            while len(self._rx_buf) < n:
                if self.closed or self._abort_evt.is_set():
                    raise ConnectionError("WebSocket closed")
                sock = self.sock
                if sock is None:
                    raise ConnectionError("WebSocket is not connected")

                has_buffered_tls = isinstance(sock, ssl.SSLSocket) and sock.pending() > 0
                if not has_buffered_tls:
                    try:
                        rlist, _, _ = select.select([sock], [], [], 0.2)
                        if not rlist:
                            if self.closed or self._abort_evt.is_set():
                                raise ConnectionError("WebSocket aborted")
                            if (time.monotonic() - self.last_rx_mono) >= self.idle_timeout_sec:
                                raise TimeoutError(f"WebSocket idle > {self.idle_timeout_sec}s without Pong/frame")
                            continue
                    except (ValueError, OSError):
                        if self.closed or self._abort_evt.is_set():
                            raise ConnectionError("WebSocket socket closed")

                need = n - len(self._rx_buf)
                try:
                    chunk = sock.recv(min(65536, max(4096, need)))
                except (socket.timeout, TimeoutError):
                    if (time.monotonic() - self.last_rx_mono) >= self.idle_timeout_sec:
                        raise
                    continue
                if not chunk:
                    raise ConnectionError("WebSocket EOF from remote peer")
                self.last_rx_mono = time.monotonic()
                self._rx_buf.extend(chunk)

            out = bytes(self._rx_buf[:n])
            del self._rx_buf[:n]
            return out

        def force_abort(self) -> None:
            self.closed = True
            self._abort_evt.set()
            sock = self.sock
            self.sock = None
            if sock is not None:
                with contextlib.suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)
                with contextlib.suppress(OSError):
                    sock.close()

    return _CompatLockedWebSocketClient()


class _MultiplexedLocalRequest:
    """Tracks one in-flight multiplexed HTTP request forwarded to `127.0.0.1:<local_port>`."""

    def __init__(
        self,
        req_id: bytes,
        method: str,
        path_qs: str,
        headers: List[Tuple[str, str]],
    ) -> None:
        self.req_id = req_id
        self.method = method
        self.path_qs = path_qs
        self.headers = headers
        self.body_chunks: List[bytes] = []
        self.body_total = 0
        self.dispatched = False
        self.cancelled = False
        self.finished = False
        self.conn: Optional[http.client.HTTPConnection] = None
        self.lock = threading.Lock()

    def attach_conn(self, conn: http.client.HTTPConnection) -> bool:
        with self.lock:
            if self.cancelled:
                return False
            self.conn = conn
            return True

    def cancel(self) -> None:
        with self.lock:
            self.cancelled = True
            conn = self.conn
            self.conn = None
            self.body_chunks.clear()
        if conn is not None:
            with contextlib.suppress(Exception):
                if conn.sock is not None:
                    with contextlib.suppress(OSError):
                        conn.sock.shutdown(socket.SHUT_RDWR)
                conn.close()


MSG_DISCONNECT_PROXY_DEAD_ZH = "检测到本机代理端口未响应，请确认 Clash 等代理软件是否已退出"
MSG_DISCONNECT_NET_OFFLINE_ZH = "检测到本机网络已断开，恢复联网后将自动重连"
MSG_DISCONNECT_REMOTE_UNREACHABLE_ZH = "远端连接网关暂未响应，正在后台自动重连"


def _probe_tcp_open_quick(host: str, port: int, timeout_sec: float = 0.35) -> bool:
    with contextlib.suppress(OSError):
        with socket.create_connection((host, int(port)), timeout=timeout_sec):
            return True
    return False


def classify_wss_disconnect_reason_zh(
    exc: Optional[BaseException],
    *,
    configured_proxy: str = "",
    proxy_exc: Optional[BaseException] = None,
    egress_ip_probe: Optional[Callable[[], str]] = None,
    ws_host: str = "",
) -> str:
    """Classify outbound WSS failure into one of three actionable Chinese human diagnostics."""
    clean_proxy = str(configured_proxy or "").strip()
    if clean_proxy:
        p_parsed = urlsplit(clean_proxy if "://" in clean_proxy else f"http://{clean_proxy}")
        p_host = (p_parsed.hostname or "").strip().lower()
        p_port = p_parsed.port
        if p_host in ("127.0.0.1", "localhost", "::1") and p_port:
            p_err = proxy_exc if proxy_exc is not None else exc
            err_txt = str(p_err or "").lower()
            if (
                isinstance(p_err, (ConnectionRefusedError, TimeoutError, socket.timeout))
                or any(tok in err_txt for tok in ("refused", "10061", "timed out", "timeout"))
                or not _probe_tcp_open_quick(p_host, int(p_port), timeout_sec=0.35)
            ):
                return MSG_DISCONNECT_PROXY_DEAD_ZH

    egress_fn = egress_ip_probe or probe_egress_source_ip
    try:
        egress_ip = str(egress_fn() or "").strip()
    except Exception:
        egress_ip = ""

    if not egress_ip or egress_ip == "0.0.0.0" or egress_ip.startswith("127."):
        return MSG_DISCONNECT_NET_OFFLINE_ZH

    host_low = (ws_host or "").strip().lower()
    exc_txt = str(exc or "").lower()
    if host_low not in ("127.0.0.1", "localhost", "::1") and (
        isinstance(exc, socket.gaierror)
        or any(tok in exc_txt for tok in ("getaddrinfo", "name or service not known", "11001", "10051", "network is unreachable"))
    ):
        if not _probe_tcp_open_quick("223.5.5.5", 53, timeout_sec=0.35) and not _probe_tcp_open_quick("1.1.1.1", 53, timeout_sec=0.35):
            return MSG_DISCONNECT_NET_OFFLINE_ZH

    return MSG_DISCONNECT_REMOTE_UNREACHABLE_ZH


class WorkersDevRelaySupervisor:
    """Supervises outbound `443 WSS` binary multiplexing relay to Cloudflare DO or VPS Hub."""

    def __init__(
        self,
        public_url: str,
        tunnel_secret: str,
        local_port: int,
        state_root: Path,
        prefix: str = "pc",
        *,
        tunnel_endpoint_path: str = "/_cosmos_tunnel",
        extra_ws_headers: Optional[Dict[str, str]] = None,
        proxy_url: Optional[str] = None,
        ping_interval_sec: float = 25.0,
        idle_timeout_sec: float = 45.0,
        backoff_schedule: Sequence[float] = (1.0, 2.0, 5.0, 15.0),
        max_workers: int = 16,
        local_timeout_sec: float = 95.0,
        route_watch_interval_sec: float = 1.0,
        ssl_context: Optional[ssl.SSLContext] = None,
        egress_ip_probe: Optional[Callable[[], str]] = None,
        on_state_change: Optional[Callable[..., Any]] = None,
    ) -> None:
        clean_pub = (public_url or "").strip().rstrip("/")
        if clean_pub.endswith("/mcp"):
            clean_pub = clean_pub[:-4].rstrip("/")
        parsed = urlsplit(clean_pub)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid `public_url` for WSS supervisor: {public_url!r}")

        ws_scheme = "wss" if parsed.scheme.lower() in ("https", "wss") else "ws"
        raw_path = (parsed.path or "").rstrip("/")
        t_match = _TENANT_PATH_RE.match(raw_path) if raw_path else None
        self.public_prefix = f"/u/{t_match.group(1).lower()}" if t_match else ""
        ep_sfx = "/" + (tunnel_endpoint_path or "/_cosmos_tunnel").lstrip("/")
        ws_path = f"{self.public_prefix}{ep_sfx}" if self.public_prefix else ep_sfx

        self.public_url = f"{parsed.scheme}://{parsed.netloc}{self.public_prefix}"
        self.ws_url = f"{ws_scheme}://{parsed.netloc}{ws_path}"
        self._ws_host = (parsed.hostname or "").strip().lower()
        self.tunnel_secret = (tunnel_secret or "").strip()
        if not self.tunnel_secret:
            raise ValueError("`tunnel_secret` must not be empty.")
        self.local_port = int(local_port)
        self.state_root = Path(state_root).expanduser().resolve()
        self.prefix = _norm_prefix(prefix)
        self.extra_ws_headers = dict(extra_ws_headers or {})
        self.proxy_url: Optional[str] = proxy_url
        self.ping_interval_sec = max(0.1, float(ping_interval_sec))
        self.idle_timeout_sec = max(0.3, float(idle_timeout_sec))
        self.backoff_schedule = tuple(float(x) for x in backoff_schedule) or (1.0, 2.0, 5.0, 15.0)
        self.max_workers = max(2, int(max_workers))
        self.local_timeout_sec = max(5.0, float(local_timeout_sec))
        self.route_watch_interval_sec = max(0.05, float(route_watch_interval_sec))
        self.ssl_context = ssl_context
        self._custom_egress_probe = egress_ip_probe is not None
        self._egress_ip_probe = egress_ip_probe or probe_egress_source_ip
        self.on_state_change = on_state_change

        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._connected_event = threading.Event()
        self._immediate_reconnect_event = threading.Event()
        self._ws: Optional[Any] = None
        self._thread: Optional[threading.Thread] = None
        self._executor: Optional[ThreadPoolExecutor] = None
        self._inflight: Dict[bytes, _MultiplexedLocalRequest] = {}
        self._completed_req_ids: Dict[bytes, float] = {}
        self._tx_hold_frames: List[Tuple[float, bytes]] = []
        self._last_error: str = ""
        self.last_reconnect_reason: str = ""
        self._last_configured_proxy: str = ""
        self._last_proxy_exc: Optional[BaseException] = None
        self.consecutive_failures: int = 0
        self.last_disconnect_reason_zh: str = ""
        self.reconnect_count: int = 0

    @property
    def last_error(self) -> str:
        with self._lock:
            return self._last_error

    @property
    def pid(self) -> Optional[int]:
        return os.getpid() if self.is_alive() else None

    def is_alive(self) -> bool:
        th = self._thread
        return bool(th is not None and th.is_alive() and not self._stop_event.is_set())

    # Compatibility alias with `CloudflaredTunnelSupervisor` in `daemon.py`
    def is_process_alive(self) -> bool:
        return self.is_alive()

    def is_connected(self) -> bool:
        with self._lock:
            return bool(self._connected_event.is_set() and self._ws is not None and not self._ws.closed)

    def _fire_state_change(self, connected: bool) -> None:
        cb = self.on_state_change
        if callable(cb):
            with contextlib.suppress(Exception):
                cb(connected)

    def start(
        self,
        wait_connected_timeout_sec: float = 0.0,
        *,
        wait_ready_timeout_sec: float = 0.0,
    ) -> str:
        eff_wait = max(float(wait_connected_timeout_sec or 0.0), float(wait_ready_timeout_sec or 0.0))
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return self.public_url
            self._stop_event.clear()
            self._connected_event.clear()
            self._immediate_reconnect_event.clear()
            self._executor = ThreadPoolExecutor(
                max_workers=self.max_workers,
                thread_name_prefix=f"cosmos-wss-http-{self.prefix}",
            )
            th = threading.Thread(
                target=self._supervisor_loop,
                name=f"cosmos-wss-sup-{self.prefix}",
                daemon=True,
            )
            self._thread = th
            th.start()
        if eff_wait > 0:
            self._connected_event.wait(timeout=eff_wait)
        return self.public_url

    def stop(self, timeout_sec: float = 5.0) -> None:
        self._stop_event.set()
        self._immediate_reconnect_event.set()
        with self._lock:
            ws = self._ws
            self._ws = None
            self._connected_event.clear()
            inflight_vals = list(self._inflight.values())
            self._inflight.clear()
            self._tx_hold_frames.clear()
            ex = self._executor
            self._executor = None
        if ws is not None:
            with contextlib.suppress(Exception):
                ws.close()
            with contextlib.suppress(Exception):
                ws.force_abort()
        for item in inflight_vals:
            item.cancel()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout_sec)
        if ex is not None:
            ex.shutdown(wait=False, cancel_futures=True)

    def _connect_once(self) -> Any:
        headers = {"Authorization": f"Bearer {self.tunnel_secret}"}
        if self.public_prefix:
            headers["X-Cosmos-Public-Prefix"] = self.public_prefix
        headers.update(self.extra_ws_headers)

        candidates: List[str] = [""]
        configured_proxy = ""
        if self.proxy_url is not None:
            explicit_p = self.proxy_url.strip()
            if explicit_p and explicit_p.lower().startswith(("http://", "https://", "socks5://", "socks5h://")):
                configured_proxy = explicit_p
                candidates = [explicit_p, ""]
        elif self._ws_host not in ("127.0.0.1", "::1", "localhost"):
            proxy = _detect_system_proxy("https", target_host=self._ws_host)
            if proxy and proxy.lower().startswith(("http://", "https://", "socks5://", "socks5h://")):
                configured_proxy = proxy
                candidates = [proxy, ""]
        else:
            # Allow explicit proxy testing on loopback only when HTTPS_PROXY/WSS_PROXY is explicitly set
            explicit_env_proxy = (
                os.environ.get("WSS_PROXY")
                or os.environ.get("wss_proxy")
                or os.environ.get("HTTPS_PROXY")
                or os.environ.get("https_proxy")
                or ""
            ).strip()
            if explicit_env_proxy and explicit_env_proxy.lower().startswith(("http://", "https://", "socks5://", "socks5h://")):
                configured_proxy = explicit_env_proxy
                candidates = [explicit_env_proxy, ""]

        self._last_configured_proxy = configured_proxy
        self._last_proxy_exc = None

        last_err: Optional[Exception] = None
        for p_url in candidates:
            ws = _create_threadsafe_ws_client(
                self.ws_url,
                timeout=15.0,
                idle_timeout_sec=self.idle_timeout_sec,
                extra_headers=headers,
                ssl_context=self.ssl_context,
            )
            try:
                ws.connect(proxy_url=p_url)
                return ws
            except Exception as exc:
                if p_url:
                    self._last_proxy_exc = exc
                last_err = exc
                with contextlib.suppress(Exception):
                    ws.force_abort()
        assert last_err is not None
        raise last_err

    def _flush_held_tx_frames(self, ws: Any) -> None:
        now = time.monotonic()
        with self._lock:
            valid = [(ts, frm) for (ts, frm) in self._tx_hold_frames if (now - ts) <= RECONNECT_HOLD_WINDOW_SEC]
            self._tx_hold_frames = []
        for ts, frm in valid:
            try:
                ws.send_frame(frm, opcode=0x2)
            except Exception:
                with self._lock:
                    self._tx_hold_frames.append((ts, frm))
                raise

    def _send_binary_tunnel_frame(self, frame: bytes) -> bool:
        """Send a binary frame over active WS, or buffer up to 9s during hotspot/network switchover."""
        deadline = time.monotonic() + RECONNECT_HOLD_WINDOW_SEC
        while not self._stop_event.is_set():
            with self._lock:
                ws = self._ws
            if ws is not None and not ws.closed:
                try:
                    ws.send_frame(frame, opcode=0x2)
                    return True
                except Exception as exc:
                    with self._lock:
                        self._last_error = str(exc)
                    with contextlib.suppress(Exception):
                        ws.force_abort()
            rem = deadline - time.monotonic()
            if rem <= 0:
                return False
            self._connected_event.wait(timeout=min(0.25, rem))
        return False

    def _heartbeat_and_route_watcher(self, ws: Any, conn_stop: threading.Event) -> None:
        """
        1) Sends RFC 6455 Ping (`0x9`) every `25.0s` and aborts if `>45.0s` without RX/Pong activity.
        2) Polls every `1.0s` for monotonic/wall clock jumps (`>3.0s` OS sleep wake), system proxy toggles
           (Clash on/off `<2s` switchover), and UDP egress IP changes (Wi-Fi <-> mobile hotspot switch),
           forcing immediate reconnect.
        """
        last_ping = time.monotonic()
        prev_mono = last_ping
        prev_wall = time.time()
        prev_proxy = (
            self.proxy_url
            if self.proxy_url is not None
            else _detect_system_proxy("https", target_host=self._ws_host)
        )
        watch_ip = self._custom_egress_probe or not self._ws_host.startswith("127.")
        prev_ip = self._egress_ip_probe() if watch_ip else ""
        tick = min(self.route_watch_interval_sec, self.ping_interval_sec / 2.0, 1.0)

        while not conn_stop.wait(timeout=tick) and not self._stop_event.is_set():
            if ws.closed:
                return
            now_mono = time.monotonic()
            now_wall = time.time()

            # Detect >3s sleep/hibernate wake jump
            mono_delta = now_mono - prev_mono
            wall_delta = now_wall - prev_wall
            prev_mono = now_mono
            prev_wall = now_wall
            if mono_delta > (tick + 3.0) or abs(wall_delta - mono_delta) > 3.0:
                with self._lock:
                    self._last_error = "clock_jump_wakeup_reconnect"
                self._immediate_reconnect_event.set()
                ws.force_abort()
                return

            # Detect system proxy switch (<2s fast reconnect when Clash / system proxy toggles)
            if self.proxy_url is None:
                cur_proxy = _detect_system_proxy("https", target_host=self._ws_host)
                if cur_proxy != prev_proxy:
                    with self._lock:
                        self._last_error = f"system_proxy_changed:{prev_proxy}->{cur_proxy}"
                    self._immediate_reconnect_event.set()
                    ws.force_abort()
                    return

            # Detect active egress interface IP change (hotspot switch or offline->online recovery)
            if watch_ip:
                cur_ip = self._egress_ip_probe()
                if cur_ip and prev_ip and cur_ip != prev_ip:
                    with self._lock:
                        self._last_error = f"egress_ip_changed:{prev_ip}->{cur_ip}"
                    self._immediate_reconnect_event.set()
                    ws.force_abort()
                    return
                if cur_ip and not prev_ip and (now_mono - ws.last_rx_mono) >= max(5.0, self.ping_interval_sec * 0.5):
                    with self._lock:
                        self._last_error = f"egress_ip_recovered:none->{cur_ip}"
                    self._immediate_reconnect_event.set()
                    ws.force_abort()
                    return
                if cur_ip:
                    prev_ip = cur_ip

            # Enforce 45s dead-connection timeout
            if (now_mono - ws.last_rx_mono) >= self.idle_timeout_sec:
                with self._lock:
                    self._last_error = f"idle_timeout_{self.idle_timeout_sec}s"
                ws.force_abort()
                return

            # Send protocol-level Ping (opcode 0x9) every 25.0s
            if (now_mono - last_ping) >= self.ping_interval_sec:
                try:
                    ws.send_frame(struct.pack("!Q", int(now_mono * 1000)), opcode=0x9)
                    last_ping = now_mono
                except Exception as exc:
                    with self._lock:
                        self._last_error = f"ping_send_failed:{exc}"
                    ws.force_abort()
                    return

    def _normalize_req_headers(self, raw_headers: Any) -> List[Tuple[str, str]]:
        pairs: List[Tuple[str, str]] = []
        has_tunnel_flag = False
        has_public_prefix = False
        has_forwarded_host = False
        if isinstance(raw_headers, list):
            for item in raw_headers:
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    k = str(item[0] or "").strip()
                    v = str(item[1] if item[1] is not None else "")
                    if k:
                        kl = k.lower()
                        if kl in _HOP_BY_HOP_HEADERS or kl in ("host", "content-length", "accept-encoding"):
                            continue
                        if kl == "x-cosmos-via-tunnel":
                            has_tunnel_flag = True
                        elif kl == "x-cosmos-public-prefix":
                            has_public_prefix = True
                        elif kl == "x-forwarded-host":
                            has_forwarded_host = True
                        pairs.append((k, v))
        elif isinstance(raw_headers, dict):
            for k_raw, v_raw in raw_headers.items():
                k = str(k_raw or "").strip()
                if not k:
                    continue
                kl = k.lower()
                if kl in _HOP_BY_HOP_HEADERS or kl in ("host", "content-length", "accept-encoding"):
                    continue
                if kl == "x-cosmos-via-tunnel":
                    has_tunnel_flag = True
                elif kl == "x-cosmos-public-prefix":
                    has_public_prefix = True
                elif kl == "x-forwarded-host":
                    has_forwarded_host = True
                pairs.append((k, str(v_raw if v_raw is not None else "")))

        pub_u = str(getattr(self, "public_url", "") or "").strip()
        if pub_u and not has_forwarded_host:
            pub_netloc = urlsplit(pub_u).netloc
            if pub_netloc:
                pairs.append(("x-forwarded-host", pub_netloc))
        if not has_tunnel_flag:
            pairs.append(("x-cosmos-via-tunnel", "1"))
        if getattr(self, "public_prefix", "") and not has_public_prefix:
            pairs.append(("x-cosmos-public-prefix", self.public_prefix))
        return pairs

    def _strip_tenant_prefix_if_present(self, path_qs: str) -> str:
        if not path_qs:
            return "/"
        q_idx = path_qs.find("?")
        p_part = path_qs[:q_idx] if q_idx >= 0 else path_qs
        q_part = path_qs[q_idx:] if q_idx >= 0 else ""
        m = _TENANT_PATH_RE.match(p_part)
        if m:
            stripped = m.group(2) or "/"
            return stripped + q_part
        return (p_part or "/") + q_part

    def _execute_local_http(self, req_state: _MultiplexedLocalRequest, body_bytes: bytes) -> None:
        req_id = req_state.req_id
        conn = http.client.HTTPConnection("127.0.0.1", self.local_port, timeout=self.local_timeout_sec)
        head_sent = False
        try:
            if not req_state.attach_conn(conn):
                return

            target_path_qs = self._strip_tenant_prefix_if_present(req_state.path_qs)
            conn.putrequest(req_state.method, target_path_qs, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", f"127.0.0.1:{self.local_port}")
            conn.putheader("Accept-Encoding", "identity")
            for hk, hv in req_state.headers:
                conn.putheader(hk, hv)
            if body_bytes or req_state.method.upper() in ("POST", "PUT", "PATCH"):
                conn.putheader("Content-Length", str(len(body_bytes)))
            conn.endheaders(body_bytes if body_bytes else None)

            resp = conn.getresponse()
            if req_state.cancelled:
                return

            resp_headers: List[List[str]] = []
            for rk, rv in resp.getheaders():
                rkl = rk.lower()
                if rkl in _HOP_BY_HOP_HEADERS or rkl == "content-length":
                    continue
                resp_headers.append([rk, rv])

            head_json = json.dumps(
                {"status": int(resp.status), "headers": resp_headers},
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            if not self._send_binary_tunnel_frame(pack_tunnel_frame(FRAME_RES_HEAD, req_id, head_json)):
                return
            head_sent = True

            if req_state.method.upper() != "HEAD" and int(resp.status) not in (101, 204, 205, 304):
                read_fn = getattr(resp, "read1", None)
                while not req_state.cancelled and not self._stop_event.is_set():
                    chunk = read_fn(RES_BODY_CHUNK_BYTES) if callable(read_fn) else resp.read(RES_BODY_CHUNK_BYTES)
                    if not chunk:
                        break
                    for off in range(0, len(chunk), RES_BODY_CHUNK_BYTES):
                        sub = chunk[off : off + RES_BODY_CHUNK_BYTES]
                        if not self._send_binary_tunnel_frame(pack_tunnel_frame(FRAME_RES_BODY, req_id, sub)):
                            return

            if not req_state.cancelled:
                self._send_binary_tunnel_frame(pack_tunnel_frame(FRAME_RES_END, req_id, b""))
        except Exception as exc:
            if not req_state.cancelled and not self._stop_event.is_set():
                if not head_sent:
                    err_body = json.dumps(
                        {"ok": False, "error": "local_upstream_error", "detail": str(exc)[:240]},
                        ensure_ascii=False,
                    ).encode("utf-8")
                    err_head = json.dumps(
                        {
                            "status": 502,
                            "headers": [["content-type", "application/json; charset=utf-8"]],
                        }
                    ).encode("utf-8")
                    self._send_binary_tunnel_frame(pack_tunnel_frame(FRAME_RES_HEAD, req_id, err_head))
                    self._send_binary_tunnel_frame(pack_tunnel_frame(FRAME_RES_BODY, req_id, err_body))
                self._send_binary_tunnel_frame(pack_tunnel_frame(FRAME_RES_END, req_id, b""))
        finally:
            req_state.finished = True
            with self._lock:
                self._inflight.pop(req_id, None)
                now = time.monotonic()
                self._completed_req_ids[req_id] = now
                if len(self._completed_req_ids) > 512:
                    cutoff = now - 30.0
                    self._completed_req_ids = {
                        k: ts for k, ts in self._completed_req_ids.items() if ts >= cutoff
                    }
            with contextlib.suppress(Exception):
                conn.close()

    def _handle_inbound_frame(self, raw_msg: bytes) -> None:
        if len(raw_msg) < FRAME_HEADER_LEN:
            return
        ftype, req_id, payload = unpack_tunnel_frame(raw_msg)

        if ftype == FRAME_REQ_HEAD:
            with self._lock:
                existing = self._inflight.get(req_id)
                if (existing is not None and existing.dispatched) or (req_id in self._completed_req_ids):
                    # Deduplicate DO replay if request is already executing or just completed on local server
                    return
            try:
                meta = json.loads(payload.decode("utf-8"))
            except Exception:
                return
            method = str(meta.get("method") or "GET").upper()
            path_qs = str(meta.get("path_qs") or "/")
            headers = self._normalize_req_headers(meta.get("headers"))
            req_state = _MultiplexedLocalRequest(req_id, method, path_qs, headers)
            with self._lock:
                self._inflight[req_id] = req_state
            return

        if ftype == FRAME_REQ_BODY:
            with self._lock:
                req_state = self._inflight.get(req_id)
            if req_state is None or req_state.cancelled or req_state.dispatched:
                return
            if req_state.body_total + len(payload) > MAX_BUFFERED_REQ_BYTES:
                req_state.cancel()
                with self._lock:
                    self._inflight.pop(req_id, None)
                err_head = json.dumps({"status": 413, "headers": [["content-type", "text/plain"]]}).encode("utf-8")
                self._send_binary_tunnel_frame(pack_tunnel_frame(FRAME_RES_HEAD, req_id, err_head))
                self._send_binary_tunnel_frame(pack_tunnel_frame(FRAME_RES_BODY, req_id, b"Payload Too Large"))
                self._send_binary_tunnel_frame(pack_tunnel_frame(FRAME_RES_END, req_id, b""))
                return
            req_state.body_chunks.append(payload)
            req_state.body_total += len(payload)
            return

        if ftype == FRAME_REQ_END:
            with self._lock:
                req_state = self._inflight.get(req_id)
                ex = self._executor
                if req_state is None or req_state.cancelled or req_state.dispatched or ex is None:
                    return
                req_state.dispatched = True
            body_bytes = b"".join(req_state.body_chunks)
            req_state.body_chunks.clear()
            ex.submit(self._execute_local_http, req_state, body_bytes)
            return

        if ftype == FRAME_REQ_CANCEL:
            with self._lock:
                req_state = self._inflight.pop(req_id, None)
            if req_state is not None:
                req_state.cancel()

    def _discard_undispatched_partial_requests(self) -> None:
        with self._lock:
            stale_ids = [rid for rid, st in self._inflight.items() if not st.dispatched]
            for rid in stale_ids:
                st = self._inflight.pop(rid, None)
                if st is not None:
                    st.cancel()

    def _supervisor_loop(self) -> None:
        backoff_idx = 0
        ever_connected = False

        while not self._stop_event.is_set():
            conn_stop = threading.Event()
            hb_thread: Optional[threading.Thread] = None
            ws: Optional[Any] = None
            connected_at = 0.0

            try:
                ws = self._connect_once()
                connected_at = time.monotonic()
                with self._lock:
                    if ever_connected:
                        self.reconnect_count += 1
                        if self._last_error:
                            self.last_reconnect_reason = self._last_error
                    ever_connected = True
                    self._ws = ws
                    self._last_error = ""
                    self.consecutive_failures = 0
                    self.last_disconnect_reason_zh = ""
                    self._connected_event.set()
                self._immediate_reconnect_event.clear()
                self._fire_state_change(True)

                self._flush_held_tx_frames(ws)

                hb_thread = threading.Thread(
                    target=self._heartbeat_and_route_watcher,
                    args=(ws, conn_stop),
                    name=f"cosmos-wss-hb-{self.prefix}",
                    daemon=True,
                )
                hb_thread.start()

                while not self._stop_event.is_set():
                    msg = ws.recv_message_bytes()
                    if msg is None:
                        if not self._stop_event.is_set():
                            raise ConnectionError("WebSocket EOF")
                        break
                    if (time.monotonic() - connected_at) >= 1.0:
                        backoff_idx = 0
                    self._handle_inbound_frame(msg)

            except Exception as exc:
                reason_zh = classify_wss_disconnect_reason_zh(
                    exc,
                    configured_proxy=self._last_configured_proxy,
                    proxy_exc=self._last_proxy_exc,
                    egress_ip_probe=self._egress_ip_probe,
                    ws_host=self._ws_host,
                )
                with self._lock:
                    if connected_at == 0.0:
                        self.consecutive_failures += 1
                    else:
                        self.consecutive_failures = max(1, self.consecutive_failures + 1)
                    self.last_disconnect_reason_zh = reason_zh
                    if not self._last_error:
                        self._last_error = f"{reason_zh} ({exc})"
            finally:
                conn_stop.set()
                notify_drop = False
                with self._lock:
                    was_conn = self._connected_event.is_set()
                    if self._ws is ws:
                        self._ws = None
                    self._connected_event.clear()
                    if was_conn and not self._stop_event.is_set():
                        notify_drop = True
                    elif not was_conn and self.consecutive_failures > 0 and not self._stop_event.is_set():
                        notify_drop = True
                if notify_drop:
                    self._fire_state_change(False)
                if ws is not None:
                    with contextlib.suppress(Exception):
                        ws.force_abort()
                if hb_thread is not None and hb_thread.is_alive():
                    hb_thread.join(timeout=1.5)
                self._discard_undispatched_partial_requests()

            if self._stop_event.is_set():
                break

            if self._immediate_reconnect_event.is_set():
                self._immediate_reconnect_event.clear()
                backoff_idx = 0
                # Hotspot / wake switchover: brief 0.15s yield so OS routing table settles, well under 1.5s budget
                self._stop_event.wait(0.15)
                continue

            if connected_at > 0 and (time.monotonic() - connected_at) >= 5.0:
                backoff_idx = 0

            delay = self.backoff_schedule[min(backoff_idx, len(self.backoff_schedule) - 1)]
            backoff_idx = min(backoff_idx + 1, len(self.backoff_schedule) - 1)
            self._stop_event.wait(delay)


__all__ = [
    "CLOUDFLARE_TOKEN_TEMPLATE_URL",
    "DEFAULT_PUBLIC_GATEWAY_BASE",
    "FRAME_HEADER_LEN",
    "FRAME_REQ_BODY",
    "FRAME_REQ_CANCEL",
    "FRAME_REQ_END",
    "FRAME_REQ_HEAD",
    "FRAME_RES_BODY",
    "FRAME_RES_END",
    "FRAME_RES_HEAD",
    "MSG_DISCONNECT_NET_OFFLINE_ZH",
    "MSG_DISCONNECT_PROXY_DEAD_ZH",
    "MSG_DISCONNECT_REMOTE_UNREACHABLE_ZH",
    "RECOVERY_PNG_CHUNK_TYPE",
    "REQ_BODY_CHUNK_BYTES",
    "RES_BODY_CHUNK_BYTES",
    "WORKER_RELAY_MJS",
    "WorkersDevRelaySupervisor",
    "classify_wss_disconnect_reason_zh",
    "cloudflare_api_token_secret_path",
    "deploy_cloudflare_workers_gateway",
    "derive_deterministic_worker_name",
    "ensure_master_seed_identity",
    "export_identity_recovery_png",
    "import_identity_recovery_png",
    "load_cloudflare_api_token",
    "load_or_create_workers_tunnel_secret",
    "master_seed_secret_path",
    "pack_tunnel_frame",
    "probe_egress_source_ip",
    "probe_public_gateway_online",
    "shred_cloudflare_api_token",
    "srvus_ssh_key_paths",
    "unpack_tunnel_frame",
    "workers_tunnel_secret_path",
]
