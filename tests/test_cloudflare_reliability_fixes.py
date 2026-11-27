"""Deterministic regression tests for the 6 Cloudflare channel reliability fixes."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
import urllib.request

import pytest

from cosmos_mcp.core.fs_tx import atomic_write_json
from cosmos_mcp.core.proc import CREATE_NO_WINDOW
from cosmos_mcp.launcher import cf_workers_gateway, cli, daemon, tunnels


def _popen_no_window_flags() -> int:
    return CREATE_NO_WINDOW if sys.platform == "win32" else 0


def _find_working_node_bin() -> Optional[str]:
    cand = shutil.which("node")
    if not cand:
        return None
    try:
        res = subprocess.run(
            [cand, "-e", "process.exit(typeof ReadableStream === 'function' ? 0 : 1)"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5.0,
            creationflags=_popen_no_window_flags(),
        )
        return cand if res.returncode == 0 else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Fix 1 & Fix 2: `WORKER_RELAY_MJS` zombie replacement replay, client
# `_completed_req_ids` idempotency, and 95s head vs 60s stream-idle timeout
# ---------------------------------------------------------------------------


def test_fix1_and_fix2_worker_relay_mjs_zombie_replay_and_stream_idle_timeout(tmp_path: Path) -> None:
    mjs_src = cf_workers_gateway.WORKER_RELAY_MJS
    assert "const REQUEST_TIMEOUT_MS = 95000;" in mjs_src
    assert "const STREAM_IDLE_TIMEOUT_MS = 60000;" in mjs_src
    assert "!entry.headResolved && !entry.replayOverflow && entry.replayFrames" in mjs_src
    assert "entry.needsReplay = true;" in mjs_src
    assert "entry.armStreamIdleTimer()" in mjs_src

    node_bin = _find_working_node_bin()
    if node_bin is not None:
        transformed_mjs = mjs_src.replace(
            'import { DurableObject } from "cloudflare:workers";',
            "const DurableObject = globalThis.__MockDurableObject;",
        ).replace("export default {", "globalThis.__workerDefault = {").replace(
            "export class CosmosRelayDO",
            "globalThis.__CosmosRelayDO = class CosmosRelayDO",
        )
        worker_js_path = tmp_path / "worker_under_test.js"
        worker_js_path.write_text(transformed_mjs, encoding="utf-8")

        harness_js = r"""
const fs = require("fs");
const crypto = require("crypto");
if (!globalThis.crypto) {
  globalThis.crypto = crypto.webcrypto;
}

let nowMs = 1000;
let nextTimerId = 1;
const timers = new Map();
const origDateNow = Date.now;
Date.now = () => nowMs;
globalThis.setTimeout = (fn, delayMs) => {
  const id = nextTimerId++;
  timers.set(id, { fn, due: nowMs + Math.max(0, Number(delayMs) || 0) });
  return id;
};
globalThis.clearTimeout = (id) => {
  timers.delete(id);
};

async function advanceClock(deltaMs) {
  const target = nowMs + deltaMs;
  while (true) {
    let nextId = null;
    let nextDue = Infinity;
    for (const [id, item] of timers.entries()) {
      if (item.due <= target && item.due < nextDue) {
        nextDue = item.due;
        nextId = id;
      }
    }
    if (nextId === null) break;
    const item = timers.get(nextId);
    timers.delete(nextId);
    nowMs = item.due;
    item.fn();
    await new Promise((r) => setImmediate(r));
  }
  nowMs = target;
  await new Promise((r) => setImmediate(r));
}

class MockSocket {
  constructor() {
    this.readyState = 1;
    this.peer = null;
    this.sentFrames = [];
    this.blackhole = false;
    this.attachment = null;
  }
  send(frame) {
    const copy = new Uint8Array(frame);
    this.sentFrames.push(copy);
  }
  close(code = 1000, reason = "") {
    this.readyState = 3;
    if (this.peer) {
      this.peer.readyState = 3;
    }
  }
  serializeAttachment(obj) {
    this.attachment = obj;
  }
}

globalThis.WebSocketPair = function WebSocketPair() {
  const c = new MockSocket();
  const s = new MockSocket();
  c.peer = s;
  s.peer = c;
  return { 0: c, 1: s };
};

globalThis.__MockDurableObject = class DurableObject {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }
};

class MockCtx {
  constructor() {
    this.sockets = [];
  }
  acceptWebSocket(ws, tags) {
    ws._tags = tags || [];
    this.sockets.push(ws);
  }
  getWebSockets(tag) {
    return this.sockets.filter((s) => !tag || (s._tags && s._tags.includes(tag)));
  }
}

const origResponse = globalThis.Response;
globalThis.Response = class PatchedResponse extends origResponse {
  constructor(body, init) {
    if (init && init.status === 101) {
      const fake = { status: 101, webSocket: init.webSocket, headers: new Headers() };
      return fake;
    }
    super(body, init);
  }
};

const code = fs.readFileSync(process.argv[2], "utf8");
eval(code);

function makeFrame(type, reqIdBytes, payloadBytes) {
  const p = payloadBytes ? new Uint8Array(payloadBytes) : new Uint8Array(0);
  const out = new Uint8Array(17 + p.byteLength);
  out[0] = type;
  out.set(reqIdBytes, 1);
  if (p.byteLength > 0) out.set(p, 17);
  return out;
}

(async () => {
  const ctx = new MockCtx();
  const doInst = new globalThis.__CosmosRelayDO(ctx, { TUNNEL_SECRET: "sec123" });

  // 1) Connect zombie oldWs (stays readyState=1 without TCP RST)
  const upg1 = await doInst.fetch(new Request("https://demo.workers.dev/_cosmos_tunnel", {
    headers: { Upgrade: "websocket" },
  }));
  const serverWs1 = ctx.sockets[0];

  // Dispatch an in-flight POST /mcp request while serverWs1 is silently dead (readyState === 1)
  const reqBody = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  const mcpPromise = doInst.fetch(new Request("https://demo.workers.dev/mcp", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: reqBody,
  }));
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));

  if (serverWs1.sentFrames.length < 2) {
    throw new Error("Expected zombie serverWs1 to receive buffered frames, got " + serverWs1.sentFrames.length);
  }

  // Device reconnects /_cosmos_tunnel -> supersedes serverWs1 and MUST immediately replay onto serverWs2!
  await doInst.fetch(new Request("https://demo.workers.dev/_cosmos_tunnel", {
    headers: { Upgrade: "websocket" },
  }));
  const serverWs2 = ctx.sockets[1];
  if (serverWs1.readyState !== 3) {
    throw new Error("Expected superseded serverWs1 to be closed");
  }
  if (serverWs2.sentFrames.length < 2) {
    throw new Error("Zombie replacement failed to replay frames onto serverWs2: got " + serverWs2.sentFrames.length);
  }
  const replayedHeadType = serverWs2.sentFrames[0][0];
  const replayedEndType = serverWs2.sentFrames[serverWs2.sentFrames.length - 1][0];
  if (replayedHeadType !== 0x10 || replayedEndType !== 0x12) {
    throw new Error("Unexpected replayed frame types: " + replayedHeadType + " .. " + replayedEndType);
  }

  const reqIdBytes = serverWs2.sentFrames[0].slice(1, 17);
  await doInst.webSocketMessage(
    serverWs2,
    makeFrame(0x20, reqIdBytes, Buffer.from(JSON.stringify({ status: 200, headers: [["content-type", "application/json"]] }))).buffer
  );
  await doInst.webSocketMessage(
    serverWs2,
    makeFrame(0x21, reqIdBytes, Buffer.from('{"ok":true}')).buffer
  );
  await doInst.webSocketMessage(
    serverWs2,
    makeFrame(0x22, reqIdBytes, null).buffer
  );
  const mcpResp = await mcpPromise;
  const mcpTxt = await mcpResp.text();
  if (mcpResp.status !== 200 || mcpTxt !== '{"ok":true}') {
    throw new Error("Replayed request failed: " + mcpResp.status + " " + mcpTxt);
  }

  // 2) Long streaming response (>95s total) survives when chunks arrive every 40s (<60,000ms idle)
  const streamPromise = doInst.fetch(new Request("https://demo.workers.dev/mcp", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: '{"stream":1}',
  }));
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));
  const streamReqId = serverWs2.sentFrames[serverWs2.sentFrames.length - 1].slice(1, 17);

  await advanceClock(50000); // t + 50s (<95s): send FRAME_RES_HEAD -> clears 95s timer, arms 60s idle timer
  await doInst.webSocketMessage(
    serverWs2,
    makeFrame(0x20, streamReqId, Buffer.from(JSON.stringify({ status: 200, headers: [["content-type", "text/plain"]] }))).buffer
  );
  const streamResp = await streamPromise;
  const reader = streamResp.body.getReader();
  const chunks = [];

  for (const part of ["partA-", "partB-", "partC"]) {
    await advanceClock(45000); // 3 * 45s + 50s = 185s total (>95s!), each gap 45s (<60s idle)
    await doInst.webSocketMessage(serverWs2, makeFrame(0x21, streamReqId, Buffer.from(part)).buffer);
    const rd = await reader.read();
    if (rd.done) throw new Error("Stream prematurely truncated before FRAME_RES_END!");
    chunks.push(Buffer.from(rd.value).toString("utf8"));
  }
  await doInst.webSocketMessage(serverWs2, makeFrame(0x22, streamReqId, null).buffer);
  const endRd = await reader.read();
  if (!endRd.done || chunks.join("") !== "partA-partB-partC") {
    throw new Error("Stream body mismatch: " + chunks.join(""));
  }
  if (timers.size !== 0) {
    throw new Error("Expected zero leaked timers after FRAME_RES_END, got " + timers.size);
  }

  // 3) Stalled stream with 60,000ms of silence closes cleanly and sends FRAME_REQ_CANCEL (0x13)
  const stallPromise = doInst.fetch(new Request("https://demo.workers.dev/mcp", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: '{"stall":1}',
  }));
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));
  const stallReqId = serverWs2.sentFrames[serverWs2.sentFrames.length - 1].slice(1, 17);
  await doInst.webSocketMessage(
    serverWs2,
    makeFrame(0x20, stallReqId, Buffer.from(JSON.stringify({ status: 200, headers: [] }))).buffer
  );
  const stallResp = await stallPromise;
  const stallReader = stallResp.body.getReader();
  await advanceClock(20000);
  await doInst.webSocketMessage(serverWs2, makeFrame(0x21, stallReqId, Buffer.from("chunk1")).buffer);
  const firstStallChunk = await stallReader.read();
  if (firstStallChunk.done) throw new Error("Expected chunk1 before idle timeout");

  await advanceClock(59999);
  if (!doInst.pendingMap.has(Buffer.from(stallReqId).toString("hex"))) {
    throw new Error("Stream closed too early at 59,999ms!");
  }
  const beforeFrames = serverWs2.sentFrames.length;
  await advanceClock(1); // reaches 60,000ms since chunk1
  const closedRead = await stallReader.read();
  if (!closedRead.done) {
    throw new Error("Expected stream to close after 60,000ms idle timeout");
  }
  const lastFrameSent = serverWs2.sentFrames[serverWs2.sentFrames.length - 1];
  if (serverWs2.sentFrames.length <= beforeFrames || lastFrameSent[0] !== 0x13) {
    throw new Error("Expected FRAME_REQ_CANCEL (0x13) on 60s stream idle timeout");
  }

  console.log("WORKER_MJS_OK");
})();
"""
        harness_path = tmp_path / "run_harness.cjs"
        harness_path.write_text(harness_js, encoding="utf-8")
        proc_res = subprocess.run(
            [node_bin, str(harness_path), str(worker_js_path)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=15.0,
            creationflags=_popen_no_window_flags(),
        )
        assert proc_res.returncode == 0, f"Node DO harness failed: {proc_res.stderr}\n{proc_res.stdout}"
        assert "WORKER_MJS_OK" in proc_res.stdout


def test_fix1_client_completed_req_ids_idempotent_dedup_on_do_replay(tmp_path: Path) -> None:
    """Verify `WorkersDevRelaySupervisor` executes non-idempotent local HTTP call ONCE even if DO replays `req_id`."""
    call_counter = {"count": 0}

    class _CountingHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            _ = self.rfile.read(length) if length > 0 else b""
            call_counter["count"] += 1
            body = json.dumps({"ok": True, "seq": call_counter["count"]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _fmt: str, *_args: Any) -> None:
            return

    httpd = HTTPServer(("127.0.0.1", 0), _CountingHandler)
    local_port = int(httpd.server_address[1])
    srv_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    srv_thread.start()

    sent_batches: List[List[bytes]] = [[], []]

    class _FakeWs:
        def __init__(self, batch_idx: int) -> None:
            self.closed = False
            self._batch_idx = batch_idx

        def send_frame(self, payload: bytes, opcode: int = 0x2) -> None:
            _ = opcode
            sent_batches[self._batch_idx].append(bytes(payload))

        def force_abort(self) -> None:
            self.closed = True

        def close(self) -> None:
            self.closed = True

    sup = cf_workers_gateway.WorkersDevRelaySupervisor(
        public_url="https://cosmos-node.demo.workers.dev",
        tunnel_secret="sec-" + ("x" * 40),
        local_port=local_port,
        state_root=tmp_path / "st_dedup",
    )
    from concurrent.futures import ThreadPoolExecutor

    sup._executor = ThreadPoolExecutor(max_workers=2)
    try:
        ws1 = _FakeWs(0)
        sup._ws = ws1
        sup._connected_event.set()

        req_id = b"\x01\x02\x03\x04" * 4
        head_payload = json.dumps(
            {"method": "POST", "path_qs": "/mcp", "headers": {"content-type": "application/json"}}
        ).encode("utf-8")
        body_payload = b'{"jsonrpc":"2.0","id":1,"method":"tools/call"}'

        f_head = cf_workers_gateway.pack_tunnel_frame(cf_workers_gateway.FRAME_REQ_HEAD, req_id, head_payload)
        f_body = cf_workers_gateway.pack_tunnel_frame(cf_workers_gateway.FRAME_REQ_BODY, req_id, body_payload)
        f_end = cf_workers_gateway.pack_tunnel_frame(cf_workers_gateway.FRAME_REQ_END, req_id, b"")

        sup._handle_inbound_frame(f_head)
        sup._handle_inbound_frame(f_body)
        sup._handle_inbound_frame(f_end)

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and req_id not in sup._completed_req_ids:
            time.sleep(0.02)

        assert req_id in sup._completed_req_ids
        assert call_counter["count"] == 1
        assert len(sent_batches[0]) == 3

        # Simulate zombie socket replacement: DO did not receive ws1's response and replays the exact same req_id on ws2
        ws2 = _FakeWs(1)
        sup._ws = ws2
        sup._handle_inbound_frame(f_head)
        sup._handle_inbound_frame(f_body)
        sup._handle_inbound_frame(f_end)

        deadline2 = time.monotonic() + 3.0
        while time.monotonic() < deadline2 and len(sent_batches[1]) < 3:
            time.sleep(0.02)

        # Local HTTP server MUST NOT be called a second time, while cached response frames are re-delivered on ws2
        assert call_counter["count"] == 1
        assert len(sent_batches[1]) == 3
        res_types = [cf_workers_gateway.unpack_tunnel_frame(frm)[0] for frm in sent_batches[1]]
        assert res_types == [
            cf_workers_gateway.FRAME_RES_HEAD,
            cf_workers_gateway.FRAME_RES_BODY,
            cf_workers_gateway.FRAME_RES_END,
        ]
    finally:
        sup.stop()
        httpd.shutdown()
        httpd.server_close()


# ---------------------------------------------------------------------------
# Fix 3: `WorkersDevRelaySupervisor` 12s/22s/5s timeouts & `*.workers.dev`
# proxy transient failure blocks bare direct fallback to poisoned IP
# ---------------------------------------------------------------------------


def test_fix3_workers_supervisor_tightened_timeouts_and_no_bare_fallback_on_workers_dev(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sup = cf_workers_gateway.WorkersDevRelaySupervisor(
        public_url="https://cosmos-mcp-test123.sub.workers.dev",
        tunnel_secret="sec-" + ("y" * 40),
        local_port=18901,
        state_root=tmp_path / "st_fix3",
    )
    assert sup.ping_interval_sec == 12.0
    assert sup.idle_timeout_sec == 22.0
    assert sup.write_timeout_sec == 5.0

    # Verify socket write timeout is capped to 5.0s after connect (even when handshake timeout=15.0)
    s_client, s_server = socket.socketpair()
    try:
        ws_client = cf_workers_gateway._create_threadsafe_ws_client(
            "ws://127.0.0.1:18901/_cosmos_tunnel",
            timeout=15.0,
            idle_timeout_sec=22.0,
            write_timeout_sec=5.0,
            extra_headers={},
        )
        from cosmos_mcp.core.net_power import StdlibWebSocketClient

        def _fake_base_connect(self_ws: Any, proxy_url: str = "") -> None:
            _ = proxy_url
            self_ws.sock = s_client
            self_ws.sock.settimeout(15.0)
            self_ws.closed = False

        monkeypatch.setattr(StdlibWebSocketClient, "connect", _fake_base_connect)
        ws_client.connect(proxy_url="")
        assert s_client.gettimeout() == 5.0
    finally:
        s_client.close()
        s_server.close()

    # 1) `*.workers.dev` with configured system proxy: transient proxy error MUST retry proxy, NEVER `""` bare direct
    attempted_proxies: List[str] = []

    class _StubWsFailThenVerify:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            _ = (args, kwargs)

        def connect(self, proxy_url: str = "") -> None:
            attempted_proxies.append(proxy_url)
            raise ConnectionRefusedError("simulated Clash port reload")

        def force_abort(self) -> None:
            pass

    monkeypatch.setattr(cf_workers_gateway, "_detect_system_proxy", lambda *_a, **_k: "http://127.0.0.1:7897")
    monkeypatch.setattr(cf_workers_gateway, "_create_threadsafe_ws_client", lambda *_a, **_k: _StubWsFailThenVerify())

    with pytest.raises(ConnectionRefusedError):
        sup._connect_once()

    assert attempted_proxies == ["http://127.0.0.1:7897", "http://127.0.0.1:7897"]
    assert "" not in attempted_proxies

    # 2) `*.workers.dev` when NO proxy is configured at all: direct `""` is still attempted
    attempted_proxies.clear()
    monkeypatch.setattr(cf_workers_gateway, "_detect_system_proxy", lambda *_a, **_k: "")
    with pytest.raises(ConnectionRefusedError):
        sup._connect_once()
    assert attempted_proxies == [""]

    # 3) Custom domain (`https://mcp.example.com`, non-workers.dev) still falls back `[proxy, ""]`
    sup_custom = cf_workers_gateway.WorkersDevRelaySupervisor(
        public_url="https://mcp.example.com",
        tunnel_secret="sec-" + ("z" * 40),
        local_port=18901,
        state_root=tmp_path / "st_fix3_custom",
    )
    attempted_proxies.clear()
    monkeypatch.setattr(cf_workers_gateway, "_detect_system_proxy", lambda *_a, **_k: "http://127.0.0.1:7897")
    with pytest.raises(ConnectionRefusedError):
        sup_custom._connect_once()
    assert attempted_proxies == ["http://127.0.0.1:7897", ""]


# ---------------------------------------------------------------------------
# Fix 4: `daemon.py` `_poll_tunnel_readiness` async `/healthz == 200` check
# for `workers_dev` (catches 1027 quota / 502 / 530 instead of fake green)
# ---------------------------------------------------------------------------


def test_fix4_daemon_workers_dev_async_public_healthz_blocks_fake_green_on_1027_and_502(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    wait_tunnel_probes: Any,
) -> None:
    st_dir = tmp_path / "st_fix4"
    ws_dir = tmp_path / "ws_fix4"
    ws_dir.mkdir()
    cli.ensure_standalone_state(st_dir, port=18904, workspace_roots=[str(ws_dir)], tunnel_mode="workers_dev")

    cfg_p = daemon.service_cfg_path(st_dir, "pc")
    cfg_doc = json.loads(cfg_p.read_text(encoding="utf-8"))
    cfg_doc["workers_dev_url"] = "https://cosmos-node.demo.workers.dev"
    cfg_doc["public_base"] = "https://cosmos-node.demo.workers.dev"
    cfg_doc["selected_gateway"] = "workers_dev"
    cfg_doc["gateways"] = {
        "instant": {"enabled": False, "submode": "public_gateway", "public_url": ""},
        "workers_dev": {
            "enabled": True,
            "submode": "workers_dev",
            "public_url": "https://cosmos-node.demo.workers.dev",
        },
        "self_hosted": {"enabled": False, "submode": "vps_hub", "public_url": ""},
    }
    cfg_doc["policy_updated_at"] = time.time() + 10.0
    atomic_write_json(cfg_p, cfg_doc)

    class _ConnectedWorkersRelay:
        def __init__(self, **kw: Any) -> None:
            self.kw = kw
            self.consecutive_failures = 0
            self.last_disconnect_reason_zh = ""
            self.last_error = ""
            self._alive = True

        def is_alive(self) -> bool:
            return self._alive

        def is_connected(self) -> bool:
            return True

        def start(self, **_kw: Any) -> str:
            return str(self.kw.get("public_url") or "")

        def stop(self) -> None:
            self._alive = False

    probe_plan: Dict[str, Any] = {
        "ok": False,
        "status_code": 429,
        "cf_error_code": 1027,
        "error": "cf_error_1027_http_429",
        "body": "error code: 1027 Worker exceeded daily request limit",
    }
    probe_invocations: List[str] = []

    def _fake_e2e_probe(url: str, *, timeout_sec: float = 8.0) -> Dict[str, Any]:
        _ = timeout_sec
        probe_invocations.append(url)
        return dict(probe_plan)

    monkeypatch.setattr(daemon, "WorkersDevRelaySupervisor", _ConnectedWorkersRelay)
    monkeypatch.setattr(daemon, "load_or_create_workers_tunnel_secret", lambda *_a, **_k: "sec-" + ("a" * 48))
    monkeypatch.setattr(daemon, "probe_public_healthz_end_to_end", _fake_e2e_probe)

    sup = daemon.StandaloneSupervisorLoop(
        state_root=st_dir,
        runtime_python=sys.executable,
        port=18904,
        mode="workers_dev",
        no_tray=True,
        enforce_singleton=False,
    )
    sup._tunnel_reprobe_interval_sec = 0.05
    try:
        # 1) Error 1027 quota exhausted -> MUST NOT mark slot ready even though outbound WSS is connected
        sup._sync_tunnel_from_cfg(initial=True)
        wait_tunnel_probes()
        slot_w = sup._gateway_slots["workers_dev"]
        assert slot_w.ready is False
        assert slot_w.state == "error"
        assert "1027" in slot_w.probe_note
        assert "1027" in slot_w.last_error

        # Subsequent sync ticks MUST NOT wipe out the 1027 error or flip back to fake green
        sup._sync_tunnel_from_cfg(initial=False)
        assert slot_w.ready is False
        assert "1027" in slot_w.last_error
        d_1027 = json.loads(daemon.daemon_status_path(st_dir).read_text(encoding="utf-8"))
        assert d_1027["tunnel_ready"] is False
        assert "1027" in d_1027["gateways"]["workers_dev"]["last_error"]
        assert "1027" in d_1027["gateways"]["workers_dev"]["probe_note"]

        # 2) Edge returns HTTP 530 -> truthfully surfaces 530 in `probe_note` and `last_error`
        probe_plan.clear()
        probe_plan.update({"ok": False, "status_code": 530, "error": "http_error_530", "body": "Origin DNS error"})
        time.sleep(0.06)
        sup._poll_tunnel_readiness()
        wait_tunnel_probes()
        assert slot_w.ready is False
        assert "530" in slot_w.probe_note
        assert "530" in slot_w.last_error

        # 3) Edge returns HTTP 200 `/healthz` -> flips `workers_dev` slot to `ready=True`
        probe_plan.clear()
        probe_plan.update({"ok": True, "status_code": 200, "body": '{"status":"ok"}'})
        time.sleep(0.06)
        sup._poll_tunnel_readiness()
        wait_tunnel_probes()
        assert slot_w.ready is True
        assert slot_w.state == "ready"
        assert slot_w.probe_note == ""
        assert slot_w.last_error == ""
        d_ok = json.loads(daemon.daemon_status_path(st_dir).read_text(encoding="utf-8"))
        assert d_ok["tunnel_ready"] is True
        assert d_ok["gateways"]["workers_dev"]["ready"] is True
        assert len(probe_invocations) >= 3
    finally:
        sup._stop_workers_supervisor()
        sup._sup_logger.removeHandler(sup._sup_log_handler)
        sup._sup_log_handler.close()


# ---------------------------------------------------------------------------
# Fix 5: Proxy 502/503/504/407 fallback to `direct_opener`, healthy subprocess
# transient probe timeout keeps `slot.ready`, and `instant` no-60s-flap
# ---------------------------------------------------------------------------


def test_fix5_probe_proxy_502_fallback_and_healthy_subproc_keeps_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    wait_tunnel_probes: Any,
) -> None:
    # Part A: `probe_public_healthz_end_to_end` falls back to `direct_opener` when local proxy returns 502/503/504/407
    monkeypatch.setattr(tunnels, "detect_configured_proxy", lambda *_a, **_k: "http://127.0.0.1:7897")

    for proxy_err_code in (502, 503, 504, 407):
        built_openers: List[str] = []

        class _FakeResp:
            status = 200

            def read(self) -> bytes:
                return b'{"status":"ok"}'

            def __enter__(self) -> "_FakeResp":
                return self

            def __exit__(self, *_exc: Any) -> None:
                return

        class _FakeOpener:
            def __init__(self, kind: str) -> None:
                self.kind = kind
                built_openers.append(kind)

            def open(self, req: urllib.request.Request, timeout: float = 3.0) -> Any:
                _ = timeout
                if self.kind == "proxy":
                    raise HTTPError(req.full_url, proxy_err_code, "Bad Gateway from local proxy", {}, io.BytesIO(b"proxy_err"))
                return _FakeResp()

        def _fake_build_opener(*handlers: Any) -> _FakeOpener:
            for h in handlers:
                if isinstance(h, urllib.request.ProxyHandler):
                    return _FakeOpener("proxy" if h.proxies else "direct")
            return _FakeOpener("direct")

        monkeypatch.setattr(urllib.request, "build_opener", _fake_build_opener)
        res = tunnels.probe_public_healthz_end_to_end("https://demo-tunnel.trycloudflare.com", timeout_sec=4.0)
        assert res["ok"] is True
        assert res["status_code"] == 200
        assert built_openers == ["proxy", "direct"]

    # If proxy returns 502 AND direct fails with timeout (e.g. poisoned direct IP), original HTTP 502 is preserved
    class _FailDirectOpener:
        def __init__(self, kind: str) -> None:
            self.kind = kind

        def open(self, req: urllib.request.Request, timeout: float = 3.0) -> Any:
            _ = timeout
            if self.kind == "proxy":
                raise HTTPError(req.full_url, 502, "Bad Gateway", {}, io.BytesIO(b"edge 502"))
            raise URLError("direct timed out")

    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *hs: _FailDirectOpener("proxy" if any(isinstance(h, urllib.request.ProxyHandler) and h.proxies for h in hs) else "direct"),
    )
    res_502 = tunnels.probe_public_healthz_end_to_end("https://cosmos-node.demo.workers.dev", timeout_sec=4.0)
    assert res_502["ok"] is False
    assert res_502["status_code"] == 502
    assert res_502["error"] == "http_error_502"

    # Part B: When `cloudflared` subprocess is healthy & alive, >=2 transient local recheck timeouts
    # ONLY record `probe_note` and NEVER flip `slot.ready` back to False!
    st_dir = tmp_path / "st_fix5_keep_ready"
    ws_dir = tmp_path / "ws_fix5_keep_ready"
    ws_dir.mkdir()
    cli.ensure_standalone_state(st_dir, port=18905, workspace_roots=[str(ws_dir)], tunnel_mode="cloudflare")

    cf_holder: Dict[str, Any] = {}

    class _HealthyCf:
        def __init__(self, **kw: Any) -> None:
            self.kw = kw
            self._alive = True
            self.pid = 75501
            cf_holder["inst"] = self

        def is_process_alive(self) -> bool:
            return self._alive

        def start(self, wait_url_timeout_sec: float = 15.0) -> str:
            _ = wait_url_timeout_sec
            return "https://alive-quick-node.trycloudflare.com"

        def stop(self) -> None:
            self._alive = False

    probe_ok = {"val": True}
    monkeypatch.setattr(daemon, "ensure_cloudflared_binary", lambda _b: tmp_path / "cloudflared")
    monkeypatch.setattr(daemon, "CloudflaredTunnelSupervisor", _HealthyCf)
    monkeypatch.setattr(
        daemon,
        "wait_tunnel_dns_and_https_ready",
        lambda u, **_k: (
            {"ok": True, "public_url": u}
            if probe_ok["val"]
            else {"ok": False, "public_url": u, "error": "timeout_waiting_for_tunnel_ready"}
        ),
    )

    sup = daemon.StandaloneSupervisorLoop(
        state_root=st_dir,
        runtime_python=sys.executable,
        port=18905,
        mode="cloudflare",
        no_tray=True,
        enforce_singleton=False,
    )
    try:
        sup._sync_tunnel_from_cfg(initial=True)
        wait_tunnel_probes()
        slot_inst = sup._gateway_slots["instant"]
        assert slot_inst.ready is True

        # Simulate 3 consecutive local recheck timeouts while `cloudflared` process remains alive
        probe_ok["val"] = False
        for _ in range(3):
            slot_inst.next_reprobe_mono = time.monotonic() - 1.0
            sup._poll_tunnel_readiness()
            wait_tunnel_probes()
            assert slot_inst.ready is True
            assert slot_inst.probe_note == "timeout_waiting_for_tunnel_ready"

        d_alive = json.loads(daemon.daemon_status_path(st_dir).read_text(encoding="utf-8"))
        assert d_alive["tunnel_ready"] is True
        assert d_alive["gateways"]["instant"]["ready"] is True
        assert d_alive["gateways"]["instant"]["probe_note"] == "timeout_waiting_for_tunnel_ready"

        # Once `cloudflared` process actually exits, `_poll_tunnel_readiness` immediately clears `ready`
        cf_holder["inst"]._alive = False
        sup._poll_tunnel_readiness()
        assert slot_inst.ready is False
    finally:
        sup._stop_cf_supervisor()
        sup._sup_logger.removeHandler(sup._sup_log_handler)
        sup._sup_log_handler.close()


def test_fix5_instant_slot_does_not_kill_live_quick_tunnel_every_60s(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    wait_tunnel_probes: Any,
) -> None:
    st_dir = tmp_path / "st_fix5_no_flap"
    ws_dir = tmp_path / "ws_fix5_no_flap"
    ws_dir.mkdir()
    cli.ensure_standalone_state(st_dir, port=18906, workspace_roots=[str(ws_dir)], tunnel_mode="public_gateway")

    srvus_online = {"val": False}
    events = {"srvus_starts": 0, "quick_starts": 0, "quick_stops": 0}
    quick_holder: Dict[str, Any] = {}

    class _FlakySrvUs:
        def __init__(self, **kw: Any) -> None:
            self.kw = kw
            self._alive = True
            self.pid = 76601

        def is_process_alive(self) -> bool:
            return self._alive

        def start(self, wait_url_timeout_sec: float = 4.0) -> str:
            _ = wait_url_timeout_sec
            events["srvus_starts"] += 1
            return "https://recovered-fixed.srv.us" if srvus_online["val"] else ""

        def stop(self) -> None:
            self._alive = False

    class _SteadyQuickCf:
        def __init__(self, **kw: Any) -> None:
            self.kw = kw
            self._alive = True
            self.pid = 76602
            self.current_url = "https://steady-fallback.trycloudflare.com"
            quick_holder["inst"] = self

        def is_process_alive(self) -> bool:
            return self._alive

        def start(self, wait_url_timeout_sec: float = 15.0) -> str:
            _ = wait_url_timeout_sec
            events["quick_starts"] += 1
            return self.current_url

        def stop(self) -> None:
            if self._alive:
                events["quick_stops"] += 1
            self._alive = False

    monkeypatch.setattr(daemon, "probe_public_gateway_online", lambda *_a, **_k: {"configured": False, "online": False})
    monkeypatch.setattr(daemon, "SrvUsSshTunnelSupervisor", _FlakySrvUs)
    monkeypatch.setattr(daemon, "ensure_cloudflared_binary", lambda _b: tmp_path / "cloudflared")
    monkeypatch.setattr(daemon, "CloudflaredTunnelSupervisor", _SteadyQuickCf)
    monkeypatch.setattr(daemon, "wait_tunnel_dns_and_https_ready", lambda u, **_k: {"ok": True, "public_url": u})

    sup = daemon.StandaloneSupervisorLoop(
        state_root=st_dir,
        runtime_python=sys.executable,
        port=18906,
        mode="public_gateway",
        no_tray=True,
        enforce_singleton=False,
    )
    try:
        # 1) Initial `srv.us` unavailable -> degrades cleanly to Quick Tunnel `trycloudflare.com`
        sup._sync_tunnel_from_cfg(initial=True)
        wait_tunnel_probes()
        assert sup._instant_fallback_active is True
        assert sup.public_url == "https://steady-fallback.trycloudflare.com"
        assert events == {"srvus_starts": 1, "quick_starts": 1, "quick_stops": 0}

        # 2) 60s cooldown expires and `srv.us` becomes reachable in background, while Quick Tunnel is alive & in use:
        #    MUST NOT preempt or kill the active Quick Tunnel!
        srvus_online["val"] = True
        sup._srvus_retry_not_before = 0.0
        for _ in range(3):
            sup._sync_tunnel_from_cfg(initial=False)
        assert events["srvus_starts"] == 1
        assert events["quick_stops"] == 0
        assert sup.public_url == "https://steady-fallback.trycloudflare.com"
        assert sup._instant_fallback_active is True

        # 3) Explicit user action requesting fixed URL (`srvus_retry_requested_at` updated) switches back to `srv.us`
        cfg_p = daemon.service_cfg_path(st_dir, "pc")
        cfg_doc = json.loads(cfg_p.read_text(encoding="utf-8"))
        cfg_doc["srvus_retry_requested_at"] = time.time() + 50.0
        cfg_doc["policy_updated_at"] = time.time() + 50.0
        atomic_write_json(cfg_p, cfg_doc)

        sup._sync_tunnel_from_cfg(initial=False)
        wait_tunnel_probes()
        assert events["srvus_starts"] == 2
        assert events["quick_stops"] == 1
        assert sup._srvus_fixed_active is True
        assert sup._instant_fallback_active is False
        assert sup.public_url == "https://recovered-fixed.srv.us"
    finally:
        sup._stop_srvus_supervisor()
        sup._stop_cf_supervisor()
        sup._sup_logger.removeHandler(sup._sup_log_handler)
        sup._sup_log_handler.close()


# ---------------------------------------------------------------------------
# Fix 6: `wait_url_timeout_sec=15.0`, `cloudflared` exit tail summary +
# `NO_PROXY=127.0.0.1,localhost,::1`, and `SPARK_ACTIVE_SUBPROCESS_PROXY` strip
# ---------------------------------------------------------------------------


def test_fix6_wait_timeout_15s_cloudflared_exit_log_no_proxy_and_env_sanitization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    wait_tunnel_probes: Any,
) -> None:
    # 1) Verify `daemon.py` passes `wait_url_timeout_sec=15.0` on hot-switch (`initial=False`) as well as `initial=True`
    st_dir = tmp_path / "st_fix6_wait"
    ws_dir = tmp_path / "ws_fix6_wait"
    ws_dir.mkdir()
    cli.ensure_standalone_state(st_dir, port=18907, workspace_roots=[str(ws_dir)], tunnel_mode="local")

    recorded_timeouts: List[float] = []

    class _TimeoutSpyCf:
        def __init__(self, **_kw: Any) -> None:
            self.pid = 77701
            self._alive = True
            self.last_error = "cloudflared exited (rc=1): context deadline exceeded"

        def is_process_alive(self) -> bool:
            return self._alive

        def start(self, wait_url_timeout_sec: float = 25.0) -> str:
            recorded_timeouts.append(float(wait_url_timeout_sec))
            return "https://hot-switched-15s.trycloudflare.com"

        def stop(self) -> None:
            self._alive = False

    monkeypatch.setattr(daemon, "ensure_cloudflared_binary", lambda _b: tmp_path / "cloudflared")
    monkeypatch.setattr(daemon, "CloudflaredTunnelSupervisor", _TimeoutSpyCf)
    monkeypatch.setattr(daemon, "wait_tunnel_dns_and_https_ready", lambda u, **_k: {"ok": True, "public_url": u})

    sup = daemon.StandaloneSupervisorLoop(
        state_root=st_dir,
        runtime_python=sys.executable,
        port=18907,
        mode="local",
        no_tray=True,
        enforce_singleton=False,
    )
    try:
        sup._sync_tunnel_from_cfg(initial=True)
        cfg_p = daemon.service_cfg_path(st_dir, "pc")
        cfg_doc = json.loads(cfg_p.read_text(encoding="utf-8"))
        cfg_doc["tunnel_mode"] = "cloudflare"
        cfg_doc["gateways"] = {
            "instant": {"enabled": True, "submode": "cloudflare", "public_url": ""},
            "workers_dev": {"enabled": False, "submode": "workers_dev", "public_url": ""},
            "self_hosted": {"enabled": False, "submode": "vps_hub", "public_url": ""},
        }
        cfg_doc["policy_updated_at"] = time.time() + 20.0
        atomic_write_json(cfg_p, cfg_doc)

        # Hot-switch (`initial=False`) MUST wait 15.0s instead of 6.0s!
        sup._sync_tunnel_from_cfg(initial=False)
        wait_tunnel_probes()
        assert recorded_timeouts == [15.0]
    finally:
        sup._stop_cf_supervisor()
        sup._sup_logger.removeHandler(sup._sup_log_handler)
        sup._sup_log_handler.close()

    # 2) `CloudflaredTunnelSupervisor` captures exit log tail into `last_error` (with token redaction)
    #    AND injects `NO_PROXY=127.0.0.1,localhost,::1` alongside system HTTP proxy
    captured_envs: List[Dict[str, str]] = []
    secret_tok = "eyJhIjoiZGVtby1zZWNyZXQtdHVubmVsLXRva2VuLTEyMzQ1NiJ9"

    class _CrashingCfProc:
        def __init__(self, env: Dict[str, str], stop_cb: Any) -> None:
            self.pid = 0
            captured_envs.append(dict(env))
            self._stop_cb = stop_cb
            self.stdout = self._lines()

        def _lines(self):
            yield f"2026-11-27T02:28:39Z INF Starting tunnel token={secret_tok}\n"
            yield '2026-11-27T02:28:41Z ERR failed to request quick Tunnel: Post "https://api.trycloudflare.com/tunnel": context deadline exceeded\n'
            yield "2026-11-27T02:28:43Z ERR failed to parse quick Tunnel ID: invalid UUID length: 0\n"

        def poll(self) -> int:
            return 1

        def wait(self, timeout: float = 5.0) -> int:
            _ = timeout
            self._stop_cb()
            return 1

    monkeypatch.setenv("NO_PROXY", ".corp.example.org")
    monkeypatch.setenv("SPARK_ACTIVE_SUBPROCESS_PROXY", "127.0.0.1:7896")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:7896")
    monkeypatch.setattr(tunnels, "detect_configured_proxy", lambda *_a, **_k: "http://127.0.0.1:7897")

    cf_sup = tunnels.CloudflaredTunnelSupervisor(
        cloudflared_bin=Path("cloudflared"),
        local_port=18908,
        state_root=tmp_path / "st_cf_crash",
        tunnel_token=secret_tok,
        fixed_public_url="https://named.example.org",
    )
    cf_sup._popen_factory = lambda _cmd, **kw: _CrashingCfProc(kw["env"], cf_sup._stop_event.set)  # type: ignore[assignment]
    cf_sup._run_loop()

    assert len(captured_envs) == 1
    c_env = captured_envs[0]
    assert "SPARK_ACTIVE_SUBPROCESS_PROXY" not in c_env
    assert c_env["HTTP_PROXY"] == "http://127.0.0.1:7897"
    assert c_env["HTTPS_PROXY"] == "http://127.0.0.1:7897"
    assert c_env["NO_PROXY"].startswith("127.0.0.1,localhost,::1")
    assert ".corp.example.org" in c_env["NO_PROXY"]
    assert "rc=1" in cf_sup.last_error
    assert "context deadline exceeded" in cf_sup.last_error
    assert "invalid UUID length: 0" in cf_sup.last_error
    assert secret_tok not in cf_sup.last_error
    assert "[REDACTED_TUNNEL_TOKEN]" in cf_sup.last_error

    # 3) `daemon.sanitize_daemon_inherited_env` & `StandaloneSupervisorLoop` strip `SPARK_ACTIVE_SUBPROCESS_PROXY`
    dirty_env = {
        "PATH": "/usr/bin",
        "SPARK_ACTIVE_SUBPROCESS_PROXY": "127.0.0.1:7896",
        "HTTP_PROXY": "http://127.0.0.1:7896",
        "HTTPS_PROXY": "http://127.0.0.1:7896",
        "ALL_PROXY": "socks5://127.0.0.1:7896",
        "COSMOS_WMI_CMD": "pythonw -m cosmos_mcp.launcher.daemon",
        "KEEP_USER_VAR": "preserved_ok",
    }
    cleaned_env = daemon.sanitize_daemon_inherited_env(dirty_env)
    assert "SPARK_ACTIVE_SUBPROCESS_PROXY" not in cleaned_env
    assert "HTTP_PROXY" not in cleaned_env
    assert "HTTPS_PROXY" not in cleaned_env
    assert "ALL_PROXY" not in cleaned_env
    assert "COSMOS_WMI_CMD" not in cleaned_env
    assert cleaned_env["KEEP_USER_VAR"] == "preserved_ok"

    # Explicit user proxy when `SPARK_ACTIVE_SUBPROCESS_PROXY` is NOT present stays intact
    user_proxy_env = {"HTTPS_PROXY": "http://127.0.0.1:7897", "PATH": "/usr/bin"}
    assert daemon.sanitize_daemon_inherited_env(dict(user_proxy_env))["HTTPS_PROXY"] == "http://127.0.0.1:7897"

    # `StandaloneSupervisorLoop.__init__` strips `SPARK_ACTIVE_SUBPROCESS_PROXY` from `os.environ` on startup
    monkeypatch.setenv("SPARK_ACTIVE_SUBPROCESS_PROXY", "127.0.0.1:7896")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:7896")
    monkeypatch.setenv("ALL_PROXY", "socks5://127.0.0.1:7896")
    sup_clean = daemon.StandaloneSupervisorLoop(
        state_root=tmp_path / "st_env_strip",
        runtime_python=sys.executable,
        port=18909,
        mode="local",
        no_tray=True,
        enforce_singleton=False,
    )
    try:
        assert "SPARK_ACTIVE_SUBPROCESS_PROXY" not in os.environ
        assert "HTTPS_PROXY" not in os.environ
        assert "ALL_PROXY" not in os.environ
    finally:
        sup_clean._sup_logger.removeHandler(sup_clean._sup_log_handler)
        sup_clean._sup_log_handler.close()
