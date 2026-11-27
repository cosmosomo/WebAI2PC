"""Regression suite for public :8096 channel & supervisor stability hardening (5 pillars)."""
from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import pytest
from starlette.testclient import TestClient

from cosmos_mcp.core import proc
from cosmos_mcp.core.config import LiveRuntimePolicy
from cosmos_mcp.core.guard import CREATE_NO_WINDOW
from cosmos_mcp.launcher import app as launcher_app
from cosmos_mcp.launcher import daemon, tunnels
from cosmos_mcp.protocol.dispatcher import KernelDispatcher
from cosmos_mcp.protocol.oauth import OAuthProvider, OAuthSQLiteStore, OAuthStoreBusyError
from cosmos_mcp.protocol.transport import create_protocol_app


# ---------------------------------------------------------------------------
# 1. Outer JobObject `allow_breakaway=True` & inner breakaway survival
# ---------------------------------------------------------------------------


def test_job_object_allow_breakaway_default_and_daemon_wiring(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sig = proc.assign_win32_job_kill_on_close.__kwdefaults__ or {}
    assert sig.get("allow_breakaway") is False

    captured_calls: List[Dict[str, Any]] = []

    class _DummyPopen:
        pid = 43210
        returncode = None

        def poll(self) -> None:
            return None

    monkeypatch.setattr(daemon.subprocess, "Popen", lambda *a, **kw: _DummyPopen())
    monkeypatch.setattr(daemon, "_is_local_tcp_port_occupied", lambda _p: False)

    def _fake_assign(pid: int, max_mem_mb: int = 0, *, allow_breakaway: bool = False) -> Optional[int]:
        captured_calls.append({"pid": pid, "max_mem_mb": max_mem_mb, "allow_breakaway": allow_breakaway})
        return None

    monkeypatch.setattr(daemon, "assign_win32_job_kill_on_close", _fake_assign)

    sup = daemon.StandaloneSupervisorLoop(
        state_root=tmp_path / "st_jb",
        runtime_python=sys.executable,
        port=18901,
        no_tray=True,
        enforce_singleton=False,
    )
    try:
        sup._spawn_server_child()
        assert len(captured_calls) == 1
        assert captured_calls[0]["pid"] == 43210
        assert captured_calls[0]["allow_breakaway"] is True
    finally:
        sup._sup_logger.removeHandler(sup._sup_log_handler)
        sup._sup_log_handler.close()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows JobObject kernel semantics only")
def test_win32_job_breakaway_child_survives_server_job_close(tmp_path: Path) -> None:
    """Verify default `allow_breakaway=False` blocks breakaway while `allow_breakaway=True` lets inner breakaway survive."""
    py_con = proc.resolve_console_python(sys.executable)
    src_root = str(Path(__file__).resolve().parents[1] / "src")
    out_json = tmp_path / "job_breakaway_probe.json"
    driver_py = tmp_path / "job_breakaway_driver.py"

    driver_py.write_text(
        f"""from __future__ import annotations
import json, os, subprocess, sys, time
from pathlib import Path

sys.path.insert(0, {src_root!r})
from cosmos_mcp.core import proc

py_exe = {py_con!r}
out_file = Path({str(out_json)!r})
res = {{}}

# Negative case: allow_breakaway=False (default) rejects inner CREATE_BREAKAWAY_FROM_JOB and kills normal child
neg_outer_script = (
    "import json, subprocess, sys, time\\n"
    f"py = {{py_exe!r}}\\n"
    "norm = subprocess.Popen([py, '-B', '-c', 'import time; time.sleep(30)'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=0x08000000)\\n"
    "brk_err = None\\n"
    "try:\\n"
    "    b = subprocess.Popen([py, '-B', '-c', 'import time; time.sleep(1)'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=0x08000000 | 0x01000000)\\n"
    "    b.terminate()\\n"
    "except OSError as exc:\\n"
    "    brk_err = getattr(exc, 'winerror', exc.errno)\\n"
    "print(json.dumps({{'norm_pid': norm.pid, 'brk_err': brk_err}}), flush=True)\\n"
    "time.sleep(30)\\n"
)
p_neg = subprocess.Popen(
    [py_exe, "-B", "-c", neg_outer_script],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    creationflags=proc.CREATE_NO_WINDOW,
)
jh_neg = proc.OwnedJobHandle(proc.assign_win32_job_kill_on_close(p_neg.pid, max_mem_mb=0))
neg_line = p_neg.stdout.readline().strip()
neg_info = json.loads(neg_line)
jh_neg.close()
deadline = time.monotonic() + 3.0
while time.monotonic() < deadline and proc.is_raw_pid_alive(neg_info["norm_pid"]):
    time.sleep(0.05)
res["neg_job_bound"] = True
res["neg_breakaway_winerror"] = neg_info["brk_err"]
res["neg_norm_alive_after_close"] = proc.is_raw_pid_alive(neg_info["norm_pid"])

# Positive case: allow_breakaway=True kills outer & normal child on job.close(), while breakaway + detach() children SURVIVE
pos_outer_script = (
    "import json, subprocess, sys, time\\n"
    f"sys.path.insert(0, {src_root!r})\\n"
    "from cosmos_mcp.core import proc\\n"
    f"py = {{py_exe!r}}\\n"
    "norm = subprocess.Popen([py, '-B', '-c', 'import time; time.sleep(30)'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=0x08000000)\\n"
    "brk = subprocess.Popen([py, '-B', '-c', 'import time; time.sleep(30)'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=0x08000000 | 0x01000000)\\n"
    "prom = proc._popen_with_optional_breakaway([py, '-B', '-c', 'import time; time.sleep(30)'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=proc.win32_no_window_flags(new_process_group=True, breakaway=True))\\n"
    "prom_job = proc.OwnedJobHandle(proc.assign_win32_job_kill_on_close(prom.pid, max_mem_mb=0))\\n"
    "prom_job.detach(survive_daemon_exit=True).close()\\n"
    "print(json.dumps({{'norm_pid': norm.pid, 'brk_pid': brk.pid, 'prom_pid': prom.pid}}), flush=True)\\n"
    "time.sleep(30)\\n"
)
p_pos = subprocess.Popen(
    [py_exe, "-B", "-c", pos_outer_script],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    creationflags=proc.CREATE_NO_WINDOW,
)
jh_pos = proc.OwnedJobHandle(proc.assign_win32_job_kill_on_close(p_pos.pid, max_mem_mb=0, allow_breakaway=True))
pos_info = {{}}
try:
    pos_line = p_pos.stdout.readline().strip()
    pos_info = json.loads(pos_line)
    jh_pos.close()
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and (
        proc.is_raw_pid_alive(p_pos.pid) or proc.is_raw_pid_alive(pos_info["norm_pid"])
    ):
        time.sleep(0.05)
    time.sleep(0.15)
    res["pos_outer_alive_after_close"] = proc.is_raw_pid_alive(p_pos.pid)
    res["pos_norm_alive_after_close"] = proc.is_raw_pid_alive(pos_info["norm_pid"])
    res["pos_breakaway_alive_after_close"] = proc.is_raw_pid_alive(pos_info["brk_pid"])
    res["pos_promoted_alive_after_close"] = proc.is_raw_pid_alive(pos_info["prom_pid"])
finally:
    for k_pid in ("brk_pid", "prom_pid"):
        c_pid = int(pos_info.get(k_pid) or 0)
        if c_pid > 0 and proc.is_raw_pid_alive(c_pid):
            proc.terminate_verified_pid_tree(c_pid, expected_create_token=None)

out_file.write_text(json.dumps(res), encoding="utf-8")
""",
        encoding="utf-8",
    )

    # Check if the current pytest runner itself is trapped in an outer non-breakaway JobObject
    can_breakaway_directly = True
    try:
        probe_p = subprocess.Popen(
            [py_con, "-B", "-c", "pass"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW | proc.CREATE_BREAKAWAY_FROM_JOB,
        )
        probe_p.wait(timeout=3.0)
    except OSError:
        can_breakaway_directly = False

    if can_breakaway_directly:
        subprocess.run(
            [py_con, "-B", str(driver_py)],
            check=True,
            timeout=20.0,
            creationflags=CREATE_NO_WINDOW,
        )
    else:
        wmi_pid = daemon._spawn_via_wmi_win32_process(
            [py_con, "-B", "-u", str(driver_py)],
            cwd=tmp_path,
            env=dict(os.environ),
            log_path=tmp_path / "wmi_driver.log",
        )
        assert wmi_pid is not None and wmi_pid > 0
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline and not out_json.is_file():
            time.sleep(0.1)

    assert out_json.is_file(), "JobObject breakaway driver did not produce output"
    doc = json.loads(out_json.read_text(encoding="utf-8"))
    assert doc["neg_breakaway_winerror"] == 5
    assert doc["neg_norm_alive_after_close"] is False
    assert doc["pos_outer_alive_after_close"] is False
    assert doc["pos_norm_alive_after_close"] is False
    assert doc["pos_breakaway_alive_after_close"] is True
    assert doc["pos_promoted_alive_after_close"] is True


# ---------------------------------------------------------------------------
# 2. Supervisor singleton mutex, anti-suicide, 15s status throttle & /healthz deadlock probe
# ---------------------------------------------------------------------------


def test_supervisor_singleton_lock_inproc_crossproc_and_env_bypass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    st_dir = tmp_path / "st_singleton"
    st_dir.mkdir()
    status_p = daemon.daemon_status_path(st_dir, "pc")
    status_p.parent.mkdir(parents=True, exist_ok=True)
    status_p.write_text(json.dumps({"status": "running", "port": 18902}), encoding="utf-8")

    lock1 = daemon.SupervisorSingletonLock(st_dir, "pc")
    assert lock1.acquire() is True
    try:
        # 1) Second in-process supervisor detects conflict and exits WITHOUT clobbering `daemon_status.json`
        sup_dup = daemon.StandaloneSupervisorLoop(
            state_root=st_dir,
            runtime_python=sys.executable,
            port=18902,
            no_tray=True,
            enforce_singleton=True,
        )
        rc = sup_dup.run_forever()
        assert rc == 0
        assert sup_dup.singleton_conflict is True
        saved_doc = json.loads(status_p.read_text(encoding="utf-8"))
        assert saved_doc["status"] == "running"

        # 2) Real cross-process subprocess also fails to acquire the OS-level mutex/flock
        src_root = str(Path(__file__).resolve().parents[1] / "src")
        py_con = proc.resolve_console_python(sys.executable)
        sub_res = subprocess.run(
            [
                py_con,
                "-B",
                "-c",
                (
                    f"import json, sys; sys.path.insert(0, {src_root!r}); "
                    f"from pathlib import Path; from cosmos_mcp.launcher.daemon import SupervisorSingletonLock; "
                    f"lk = SupervisorSingletonLock(Path({str(st_dir)!r}), 'pc'); "
                    f"print(json.dumps({{'acquired': lk.acquire()}}))"
                ),
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10.0,
            creationflags=CREATE_NO_WINDOW,
        )
        assert sub_res.returncode == 0
        assert json.loads(sub_res.stdout.strip())["acquired"] is False

        # 3) Env var bypass allows test instances when `enforce_singleton` is None
        monkeypatch.setenv("COSMOS_DISABLE_SUPERVISOR_MUTEX", "1")
        sup_bypass = daemon.StandaloneSupervisorLoop(
            state_root=st_dir,
            runtime_python=sys.executable,
            port=18903,
            no_tray=True,
        )
        try:
            assert sup_bypass._should_enforce_singleton() is False
        finally:
            sup_bypass._sup_logger.removeHandler(sup_bypass._sup_log_handler)
            sup_bypass._sup_log_handler.close()
    finally:
        lock1.release()

    # After release, a new lock acquires cleanly
    lock2 = daemon.SupervisorSingletonLock(st_dir, "pc")
    assert lock2.acquire() is True
    lock2.release()


def test_supervisor_status_write_dedup_and_15s_throttle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    st_dir = tmp_path / "st_throttle"
    sup = daemon.StandaloneSupervisorLoop(
        state_root=st_dir,
        runtime_python=sys.executable,
        port=18904,
        no_tray=True,
        enforce_singleton=False,
    )
    writes: List[Dict[str, Any]] = []
    orig_write = daemon.atomic_write_json
    fake_now = [1000.0]

    def _spy_write(path: Path, data: Dict[str, Any]) -> None:
        writes.append(dict(data))
        orig_write(path, data)

    monkeypatch.setattr(daemon, "atomic_write_json", _spy_write)
    monkeypatch.setattr(daemon.time, "monotonic", lambda: fake_now[0])

    try:
        sup._write_daemon_status(state_label="running")
        assert len(writes) == 1

        # 10 unchanged ticks within <15s perform zero disk writes
        for i in range(10):
            fake_now[0] = 1000.0 + (i + 1) * 1.2
            sup._write_daemon_status(state_label="running")
        assert len(writes) == 1

        # Immediate write on error/state change even at <15s
        fake_now[0] = 1013.0
        sup._write_daemon_status(state_label="running", last_error="tunnel transient timeout")
        assert len(writes) == 2
        assert writes[-1]["last_error"] == "tunnel transient timeout"

        # Unchanged again <15s -> skipped
        fake_now[0] = 1020.0
        sup._write_daemon_status(state_label="running", last_error="tunnel transient timeout")
        assert len(writes) == 2

        # >=15s elapsed since last write (1013 + 15.5 = 1028.5) -> periodic heartbeat flush occurs
        fake_now[0] = 1028.5
        sup._write_daemon_status(state_label="running", last_error="tunnel transient timeout")
        assert len(writes) == 3
    finally:
        sup._sup_logger.removeHandler(sup._sup_log_handler)
        sup._sup_log_handler.close()


def test_supervisor_inner_loop_survives_exception_and_restarts_deadlocked_healthz(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    st_dir = tmp_path / "st_deadlock"
    cfg_p = daemon.service_cfg_path(st_dir, "pc")
    cfg_p.parent.mkdir(parents=True, exist_ok=True)
    cfg_p.write_text(
        json.dumps(
            {
                "tunnel_mode": "local",
                "keep_awake": False,
                "tray_enabled": False,
                "gateways": {
                    "instant": {"enabled": False},
                    "workers_dev": {"enabled": False},
                    "self_hosted": {"enabled": False},
                },
            }
        ),
        encoding="utf-8",
    )
    sup = daemon.StandaloneSupervisorLoop(
        state_root=st_dir,
        runtime_python=sys.executable,
        port=18905,
        mode="local",
        no_tray=True,
        enforce_singleton=False,
    )
    sup._local_healthz_grace_sec = 0.05
    sup._local_healthz_interval_sec = 0.02
    sup._local_healthz_timeout_sec = 0.2
    sup._local_healthz_max_failures = 6

    spawned_children: List[Any] = []

    class _FakeServerProc:
        def __init__(self, idx: int) -> None:
            self.pid = 55000 + idx
            self.returncode: Optional[int] = None

        def poll(self) -> Optional[int]:
            return self.returncode

        def terminate(self) -> None:
            self.returncode = -15

        def wait(self, timeout: float = 3.0) -> int:
            self.returncode = -15
            return -15

    def _fake_spawn() -> Any:
        child = _FakeServerProc(len(spawned_children) + 1)
        spawned_children.append(child)
        if len(spawned_children) >= 2:
            # Once deadlock self-heal spawns the 2nd server child, trigger clean stop (`STOP:` prefix required)
            daemon.daemon_stop_flag_path(st_dir, "pc").parent.mkdir(parents=True, exist_ok=True)
            daemon.daemon_stop_flag_path(st_dir, "pc").write_text("STOP:test_done", encoding="utf-8")
        return child

    poll_calls = [0]

    def _flaky_poll_readiness() -> None:
        poll_calls[0] += 1
        if poll_calls[0] == 1:
            raise PermissionError("simulated transient antivirus file lock in inner loop")

    hz_calls = [0]

    def _deadlocked_healthz(port: int, timeout_sec: float = 3.5) -> Optional[Dict[str, Any]]:
        hz_calls[0] += 1
        return None

    real_sleep = time.sleep
    monkeypatch.setattr(sup, "_spawn_server_child", _fake_spawn)
    monkeypatch.setattr(sup, "_poll_tunnel_readiness", _flaky_poll_readiness)
    monkeypatch.setattr(daemon, "probe_local_healthz", _deadlocked_healthz)
    monkeypatch.setattr(daemon.time, "sleep", lambda _s: real_sleep(0.01))

    rc = sup.run_forever()
    assert rc == 0
    assert poll_calls[0] >= 2, "Supervisor exited on first inner-loop PermissionError instead of continuing!"
    assert hz_calls[0] >= 6, f"Expected >=6 local /healthz probes before deadlock restart, got {hz_calls[0]}"
    assert len(spawned_children) == 2, "Deadlocked server child was not restarted after 6 failed /healthz probes!"
    assert spawned_children[0].returncode is not None


def test_supervisor_reclaims_stale_python_port_holder(tmp_path: Path) -> None:
    py_con = proc.resolve_console_python(sys.executable)
    ready_file = tmp_path / "port_holder_ready.json"
    holder = subprocess.Popen(
        [
            py_con,
            "-B",
            "-c",
            (
                "import json, socket, time\n"
                "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                "s.bind(('127.0.0.1', 0))\n"
                "s.listen(4)\n"
                f"open({str(ready_file)!r}, 'w').write(json.dumps({{'port': s.getsockname()[1]}}))\n"
                "time.sleep(30)\n"
            ),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=CREATE_NO_WINDOW,
    )
    try:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not ready_file.is_file():
            time.sleep(0.05)
        assert ready_file.is_file()
        held_port = int(json.loads(ready_file.read_text(encoding="utf-8"))["port"])
        assert daemon._is_local_tcp_port_occupied(held_port) is True

        sup = daemon.StandaloneSupervisorLoop(
            state_root=tmp_path / "st_reclaim",
            runtime_python=sys.executable,
            port=held_port,
            no_tray=True,
            enforce_singleton=False,
        )
        try:
            reclaimed = sup._reclaim_stale_python_port_holder()
            assert holder.pid in reclaimed
            assert daemon._is_local_tcp_port_occupied(held_port) is False
        finally:
            sup._sup_logger.removeHandler(sup._sup_log_handler)
            sup._sup_log_handler.close()
    finally:
        if holder.poll() is None:
            holder.terminate()
            holder.wait(timeout=2.0)


# ---------------------------------------------------------------------------
# 3. Windows `IocpProactor.accept` `WinError 64` listener death guard
# ---------------------------------------------------------------------------


def test_win32_proactor_accept_guard_swallows_winerror_64_and_keeps_listener_alive() -> None:
    # 1) Deterministic mock proactor verification across all 4 transient WinError codes (64, 121, 995, 10054)
    class _FakeListener:
        def __init__(self) -> None:
            self.closed = False

        def fileno(self) -> int:
            return -1 if self.closed else 123

        def close(self) -> None:
            self.closed = True

    class _FakeAcceptSocket:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class _FakeProactor:
        def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
            self._loop = loop
            self._stopped_serving: set[Any] = set()
            self.calls = 0
            self.created_conns: List[_FakeAcceptSocket] = []
            self.scripted_winerrors = [64, 121, 995, 10054]

        def _get_accept_socket(self, _family: Any = None) -> _FakeAcceptSocket:
            cs = _FakeAcceptSocket()
            self.created_conns.append(cs)
            return cs

        def accept(self, listener: _FakeListener) -> asyncio.Future[Any]:
            self._get_accept_socket()
            fut: asyncio.Future[Any] = self._loop.create_future()
            idx = self.calls
            self.calls += 1
            if idx < len(self.scripted_winerrors):
                werr = self.scripted_winerrors[idx]
                err = OSError(werr, f"Simulated transient AcceptEx error {werr}")
                setattr(err, "winerror", werr)
                self._loop.call_soon(fut.set_exception, err)
            else:
                self._loop.call_soon(fut.set_result, ("accepted_conn", ("127.0.0.1", 54321)))
            return fut

    assert launcher_app.install_win32_proactor_accept_guard(_FakeProactor) is True
    # Idempotency check
    assert launcher_app.install_win32_proactor_accept_guard(_FakeProactor) is True

    async def _exercise_mock() -> Tuple[Any, _FakeProactor, _FakeListener]:
        loop = asyncio.get_running_loop()
        proactor = _FakeProactor(loop)
        listener = _FakeListener()
        res = await proactor.accept(listener)
        return res, proactor, listener

    result, proactor_inst, listener_inst = asyncio.run(_exercise_mock())
    assert result == ("accepted_conn", ("127.0.0.1", 54321))
    assert proactor_inst.calls == 5
    assert listener_inst.closed is False
    # All 4 failed transient accept sockets were closed (zero socket leak), 5th succeeded
    assert [c.closed for c in proactor_inst.created_conns[:4]] == [True, True, True, True]
    assert proactor_inst.created_conns[4].closed is False

    # 2) Real Windows `IocpProactor` live listener socket survival test under injected WinError 64
    if sys.platform == "win32":
        import asyncio.windows_events as win_ev

        assert launcher_app.install_win32_proactor_accept_guard() is True
        guarded = win_ev.IocpProactor.accept
        orig_raw = getattr(guarded, "_cosmos_orig_accept")
        inject_remaining = [2]

        def _faulty_orig(self_p: Any, listener_sock: Any) -> Any:
            if inject_remaining[0] > 0:
                inject_remaining[0] -= 1
                fut = self_p._loop.create_future()
                err = OSError(64, "The specified network name is no longer available", None, 64)
                self_p._loop.call_soon(fut.set_exception, err)
                return fut
            return orig_raw(self_p, listener_sock)

        setattr(guarded, "_cosmos_orig_accept", _faulty_orig)
        # Re-bind closure cleanly on a temporary subclass or test live server via monkeypatched orig
        async def _live_proactor_test() -> bytes:
            async def _echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                data = await reader.read(64)
                writer.write(b"ALIVE:" + data)
                await writer.drain()
                writer.close()

            srv = await asyncio.start_server(_echo, "127.0.0.1", 0)
            try:
                port = srv.sockets[0].getsockname()[1]
                await asyncio.sleep(0.05)
                assert srv.sockets[0].fileno() != -1
                r, w = await asyncio.open_connection("127.0.0.1", port)
                w.write(b"PING")
                await w.drain()
                reply = await asyncio.wait_for(r.read(64), timeout=3.0)
                w.close()
                return reply
            finally:
                srv.close()
                await srv.wait_closed()

        try:
            # Temporarily install with _faulty_orig as underlying accept
            monkeypatch_cls = win_ev.IocpProactor
            setattr(monkeypatch_cls, "accept", _faulty_orig)
            launcher_app.install_win32_proactor_accept_guard(monkeypatch_cls)
            live_reply = asyncio.run(_live_proactor_test())
            assert live_reply == b"ALIVE:PING"
            assert inject_remaining[0] == 0
        finally:
            setattr(win_ev.IocpProactor, "accept", orig_raw)
            launcher_app.install_win32_proactor_accept_guard(win_ev.IocpProactor)


# ---------------------------------------------------------------------------
# 4. OAuth SQLite lock retry & HTTP 503 (`Retry-After: 1`) instead of 401 kickout
# ---------------------------------------------------------------------------


def test_oauth_sqlite_locked_retries_and_maps_persistent_lock_to_http_503(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_dir = tmp_path / "ws"
    ws_dir.mkdir()
    st_dir = tmp_path / "state_root"
    st_dir.mkdir()
    db_path = st_dir / "state" / "oauth.sqlite3"

    store = OAuthSQLiteStore(db_path)
    valid_token = "tok_live_session_998877"
    exp_ts = time.time() + 3600.0
    public_base = "https://gateway-lock-test.example.com"
    store.put(
        "access",
        valid_token,
        {
            "client_id": "gemini_web_client",
            "scopes": ["mcp:tools"],
            "expires_at": int(exp_ts),
            "resource": f"{public_base}/mcp",
            "subject": "owner",
        },
        exp_ts,
    )

    # 1) Positive recovery: first 2 attempts raise `database is locked`, 3rd succeeds -> returns valid token!
    orig_connect = store.connect
    flaky_attempts = [0]
    slept_backoffs: List[float] = []
    monkeypatch.setattr("cosmos_mcp.protocol.oauth.time.sleep", lambda s: slept_backoffs.append(round(float(s), 3)))

    def _flaky_connect(readonly: bool = False) -> sqlite3.Connection:
        flaky_attempts[0] += 1
        if flaky_attempts[0] <= 2:
            raise sqlite3.OperationalError("database is locked")
        return orig_connect(readonly=readonly)

    monkeypatch.setattr(store, "connect", _flaky_connect)
    rec = store.get("access", valid_token)
    assert rec is not None
    assert rec["client_id"] == "gemini_web_client"
    assert flaky_attempts[0] == 3
    assert slept_backoffs == [0.05, 0.1]

    # 2) Persistent lock exhaustion raises `OAuthStoreBusyError` after 4 retries (0.05, 0.1, 0.2, 0.4)
    slept_backoffs.clear()
    monkeypatch.setattr(store, "connect", lambda readonly=False: (_ for _ in ()).throw(sqlite3.OperationalError("database is locked")))
    with pytest.raises(OAuthStoreBusyError) as exc_info:
        store.get("access", valid_token)
    assert exc_info.value.retry_after == 1
    assert slept_backoffs == [0.05, 0.1, 0.2, 0.4]

    # 3) Full ASGI middleware verification: locked DB returns 503 + `Retry-After: 1` (NEVER 401!)
    pol = LiveRuntimePolicy(state_root=st_dir, workspace_roots=[ws_dir], tier_key="tier3_workspace_dev")
    disp = KernelDispatcher(policy=pol)
    provider = OAuthProvider(
        store=store,
        base_url=public_base,
        password_hash="unused",
        salt="00" * 16,
        allowed_resources={public_base, f"{public_base}/mcp", f"{public_base}/mcp/readonly"},
        issuer=public_base,
    )
    asgi_app = create_protocol_app(
        disp,
        policy=pol,
        store=store,
        provider=provider,
        public_url=public_base,
        port=18909,
    )

    with TestClient(asgi_app, base_url=public_base) as client:
        resp_busy = client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {valid_token}",
                "Accept": "application/json, text/event-stream",
            },
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert resp_busy.status_code == 503, f"Expected 503 on SQLite lock, got {resp_busy.status_code}: {resp_busy.text}"
        assert resp_busy.status_code != 401
        assert resp_busy.headers.get("Retry-After") == "1"
        assert resp_busy.json()["error"] == "temporarily_unavailable"

        # Restore healthy SQLite connection: unknown token still properly returns 401
        monkeypatch.setattr(store, "connect", orig_connect)
        resp_bad = client.post(
            "/mcp",
            headers={
                "Authorization": "Bearer nonexistent_token_xyz",
                "Accept": "application/json, text/event-stream",
            },
            json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
        )
        assert resp_bad.status_code == 401


# ---------------------------------------------------------------------------
# 5. Tunnel >8 MiB log rotation & `VPS_RESIDENT_HUB_PY` WSS drop anti-fake-200
# ---------------------------------------------------------------------------


def test_tunnel_log_rotation_over_8mib_for_srvus_and_cloudflared(tmp_path: Path) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True)

    # 1) Negative control: <= 8 MiB is NOT rotated
    small_log = logs_dir / "srvus.log"
    small_log.write_bytes(b"x" * 1024)
    assert tunnels._rotate_tunnel_log_if_needed(small_log) is False
    assert not (logs_dir / "srvus.log.1").exists()

    # 2) Positive control: > 8 MiB srvus.log rotates to srvus.log.1 before opening new log
    oversized_bytes = tunnels.MAX_TUNNEL_LOG_BYTES + 512
    small_log.write_bytes(b"S" * oversized_bytes)

    class _OneShotProc:
        def __init__(self, line: str, stop_cb: Any) -> None:
            self.pid = 0
            self._stop_cb = stop_cb
            self.stdout = self._gen(line)

        def _gen(self, line: str):
            yield line
            self._stop_cb()

        def poll(self) -> int:
            return 0

        def wait(self, timeout: float = 1.0) -> int:
            return 0

    srv_sup = tunnels.SrvUsSshTunnelSupervisor(
        local_port=18910,
        state_root=tmp_path,
        prefix="pc",
    )
    srv_sup._select_runtime_command = lambda _idx: ["ssh", "-T"]  # type: ignore[method-assign]
    srv_sup._popen_factory = lambda *a, **kw: _OneShotProc(  # type: ignore[assignment]
        "https://demonode123.srv.us\n",
        srv_sup._stop_event.set,
    )
    srv_sup._run_loop()

    assert (logs_dir / "srvus.log.1").is_file()
    assert (logs_dir / "srvus.log.1").stat().st_size == oversized_bytes
    assert (logs_dir / "srvus.log").is_file()
    assert (logs_dir / "srvus.log").stat().st_size < 256

    # 3) Positive control: > 8 MiB cloudflared.log rotates to cloudflared.log.1
    cf_log = logs_dir / "cloudflared.log"
    cf_log.write_bytes(b"C" * oversized_bytes)
    cf_sup = tunnels.CloudflaredTunnelSupervisor(
        cloudflared_bin=Path("cloudflared"),
        local_port=18910,
        state_root=tmp_path,
        prefix="pc",
    )
    cf_sup._popen_factory = lambda *a, **kw: _OneShotProc(  # type: ignore[assignment]
        "INF | https://quick-demo-node.trycloudflare.com |\n",
        cf_sup._stop_event.set,
    )
    cf_sup._run_loop()
    assert (logs_dir / "cloudflared.log.1").is_file()
    assert (logs_dir / "cloudflared.log.1").stat().st_size == oversized_bytes
    assert (logs_dir / "cloudflared.log").stat().st_size < 256


def test_vps_resident_hub_aborts_midstream_response_without_fake_chunked_end() -> None:
    hub_ns: Dict[str, Any] = {}
    exec(compile(tunnels.VPS_RESIDENT_HUB_PY, "<VPS_RESIDENT_HUB_PY>", "exec"), hub_ns)
    HubState = hub_ns["HubState"]
    handle_conn = hub_ns["handle_conn"]
    FRAME_RES_HEAD = hub_ns["FRAME_RES_HEAD"]
    FRAME_RES_BODY = hub_ns["FRAME_RES_BODY"]
    FRAME_RES_END = hub_ns["FRAME_RES_END"]
    FRAME_ERR_ABORT = hub_ns["FRAME_ERR_ABORT"]
    assert FRAME_ERR_ABORT == 0xFF

    def _pack_masked_client_ws(payload: bytes, opcode: int = 0x2) -> bytes:
        mask = b"\x11\x22\x33\x44"
        n = len(payload)
        hdr = bytearray([0x80 | opcode])
        if n < 126:
            hdr.append(0x80 | n)
        elif n < 65536:
            hdr.append(0x80 | 126)
            hdr.extend(struct.pack("!H", n))
        else:
            hdr.append(0x80 | 127)
            hdr.extend(struct.pack("!Q", n))
        hdr.extend(mask)
        masked = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
        return bytes(hdr) + masked

    async def _run_hub_drop_and_complete_cases() -> None:
        secret = "test_hub_secret_8899"
        hub = HubState(secret)
        srv = await asyncio.start_server(lambda r, w: handle_conn(hub, r, w), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]

        try:
            # --- Case A: Mid-stream WSS disconnect MUST NOT write `0\r\n\r\n` ---
            ws_r, ws_w = await asyncio.open_connection("127.0.0.1", port)
            ws_key = base64.b64encode(b"0123456789abcdef").decode("ascii")
            ws_w.write(
                (
                    f"GET /_cosmos_node HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{port}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Authorization: Bearer {secret}\r\n"
                    f"Sec-WebSocket-Key: {ws_key}\r\n"
                    f"Sec-WebSocket-Version: 13\r\n\r\n"
                ).encode("ascii")
            )
            await ws_w.drain()
            hs = await ws_r.readuntil(b"\r\n\r\n")
            assert b"101 Switching Protocols" in hs

            def _blocking_http_request() -> Tuple[Optional[BaseException], bytes]:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
                try:
                    conn.request("POST", "/mcp", body=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}', headers={"Content-Type": "application/json"})
                    resp = conn.getresponse()
                    data = resp.read()
                    return None, data
                except BaseException as exc:
                    partial = getattr(exc, "partial", b"")
                    return exc, partial
                finally:
                    conn.close()

            http_fut = asyncio.get_running_loop().run_in_executor(None, _blocking_http_request)

            # Read FRAME_REQ_HEAD on fake PC node WSS side to get `rid`
            op_h, frame_h = await hub_ns["read_ws_frame"](ws_r)
            assert op_h == 0x2
            rid = frame_h[1:17]
            # Drain body + end frames
            while True:
                _, fr = await hub_ns["read_ws_frame"](ws_r)
                if fr[0] == hub_ns["FRAME_REQ_END"]:
                    break

            # Send HTTP 200 headers + HALF of JSON body, then drop WSS abruptly without FRAME_RES_END!
            head_meta = json.dumps({"status": 200, "headers": [["content-type", "application/json"]]}).encode("utf-8")
            ws_w.write(_pack_masked_client_ws(bytes([FRAME_RES_HEAD]) + rid + head_meta))
            ws_w.write(_pack_masked_client_ws(bytes([FRAME_RES_BODY]) + rid + b'{"jsonrpc":"2.0","par'))
            await ws_w.drain()
            await asyncio.sleep(0.05)
            ws_w.close()
            with contextlib.suppress(Exception):
                await ws_w.wait_closed()

            err_a, partial_a = await asyncio.wait_for(http_fut, timeout=5.0)
            assert isinstance(err_a, http.client.IncompleteRead), (
                f"Truncated WSS stream must raise IncompleteRead (never fake 200 OK), got err={err_a!r} body={partial_a!r}"
            )

            # --- Case B: Healthy WSS node sending FRAME_RES_END completes 200 OK cleanly ---
            ws_r2, ws_w2 = await asyncio.open_connection("127.0.0.1", port)
            ws_w2.write(
                (
                    f"GET /_cosmos_node HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{port}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Authorization: Bearer {secret}\r\n"
                    f"Sec-WebSocket-Key: {ws_key}\r\n"
                    f"Sec-WebSocket-Version: 13\r\n\r\n"
                ).encode("ascii")
            )
            await ws_w2.drain()
            await ws_r2.readuntil(b"\r\n\r\n")

            http_fut2 = asyncio.get_running_loop().run_in_executor(None, _blocking_http_request)
            _, frame_h2 = await hub_ns["read_ws_frame"](ws_r2)
            rid2 = frame_h2[1:17]
            while True:
                _, fr2 = await hub_ns["read_ws_frame"](ws_r2)
                if fr2[0] == hub_ns["FRAME_REQ_END"]:
                    break

            full_payload = b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}'
            ws_w2.write(_pack_masked_client_ws(bytes([FRAME_RES_HEAD]) + rid2 + head_meta))
            ws_w2.write(_pack_masked_client_ws(bytes([FRAME_RES_BODY]) + rid2 + full_payload))
            ws_w2.write(_pack_masked_client_ws(bytes([FRAME_RES_END]) + rid2))
            await ws_w2.drain()

            err_b, body_b = await asyncio.wait_for(http_fut2, timeout=5.0)
            assert err_b is None
            assert body_b == full_payload
            ws_w2.close()
        finally:
            srv.close()
            await srv.wait_closed()

    asyncio.run(_run_hub_drop_and_complete_cases())
