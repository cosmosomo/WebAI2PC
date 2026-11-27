from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from cosmos_mcp.core import proc as proc_mod
from cosmos_mcp.core.guard import WorkspaceGuard
from cosmos_mcp.packs import browser as browser_mod


class _FakeJobHandle:
    def __init__(self, handle: int = 999) -> None:
        self.handle = handle
        self.closed = False
        self.detached = False

    def detach(self, survive_daemon_exit: bool = True) -> "_FakeJobHandle":
        self.detached = True
        return self

    def close(self) -> None:
        self.closed = True
        self.handle = 0


class _FakeFgProc:
    def __init__(self, pid: int, alive: bool = True) -> None:
        self.pid = pid
        self._alive = alive
        self.stdin = None
        self.stdout = None
        self.stderr = None

    def poll(self) -> Any:
        return None if self._alive else 0


class _FakeBrowserWorker:
    def __init__(self, profile_dir: Path, fail_times: int = 0, err_msg: str = "worker stop failed") -> None:
        self.profile_dir = profile_dir
        self.fail_times = fail_times
        self.err_msg = err_msg
        self.stop_calls = 0

    def stop(self) -> None:
        self.stop_calls += 1
        if self.stop_calls <= self.fail_times:
            raise RuntimeError(self.err_msg)


# ---------------------------------------------------------------------------
# L1: _kill_process_tree_win32 / terminate_verified_pid_tree / ledger contract
# ---------------------------------------------------------------------------


def test_l1_kill_process_tree_win32_all_fail_and_still_alive_returns_false(monkeypatch: pytest.MonkeyPatch) -> None:
    target_pid = 43210
    fake_jh = _FakeJobHandle(handle=777)

    monkeypatch.setattr(proc_mod, "verify_pid_alive", lambda pid, tok=None: (True, False))
    monkeypatch.setattr(proc_mod, "get_process_create_token", lambda pid: "tok-43210")
    monkeypatch.setattr(proc_mod, "_collect_descendant_pids_win32", lambda pid, tok=None: [])
    monkeypatch.setattr(proc_mod, "_terminate_win32_job", lambda h, code=1: False)
    monkeypatch.setattr(proc_mod, "_terminate_single_pid_win32", lambda pid: False)
    monkeypatch.setattr(proc_mod, "is_raw_pid_alive", lambda pid: True)
    monkeypatch.setattr(
        proc_mod.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=1, stdout=b"", stderr=b"access denied"),
    )

    diag: Dict[str, Any] = {}
    terminated, reused = proc_mod._kill_process_tree_win32(
        target_pid,
        expected_create_token="tok-43210",
        job_handle=fake_jh,  # type: ignore[arg-type]
        wait_timeout_sec=0.05,
        diagnostics=diag,
    )

    assert terminated is False
    assert reused is False
    assert fake_jh.closed is True
    assert diag["terminated"] is False
    assert diag["still_running"] == [target_pid]
    assert any("TerminateJobObject" in e for e in diag["errors"])
    assert any("taskkill" in e for e in diag["errors"])
    assert any("TerminateProcess" in e for e in diag["errors"])
    assert proc_mod.get_last_kill_diagnostics()["still_running"] == [target_pid]


def test_l1_kill_process_tree_win32_api_ok_but_survivor_alive_returns_false(monkeypatch: pytest.MonkeyPatch) -> None:
    target_pid = 43211

    monkeypatch.setattr(proc_mod, "verify_pid_alive", lambda pid, tok=None: (True, False))
    monkeypatch.setattr(proc_mod, "get_process_create_token", lambda pid: "tok-43211")
    monkeypatch.setattr(proc_mod, "_collect_descendant_pids_win32", lambda pid, tok=None: [])
    monkeypatch.setattr(proc_mod, "_terminate_single_pid_win32", lambda pid: True)
    monkeypatch.setattr(proc_mod, "is_raw_pid_alive", lambda pid: True)
    monkeypatch.setattr(
        proc_mod.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=0, stdout=b"ok", stderr=b""),
    )

    diag: Dict[str, Any] = {}
    terminated, reused = proc_mod._kill_process_tree_win32(
        target_pid,
        expected_create_token="tok-43211",
        wait_timeout_sec=0.05,
        diagnostics=diag,
    )

    assert terminated is False
    assert reused is False
    assert diag["still_running"] == [target_pid]


def test_l1_kill_process_tree_win32_liveness_check_exception_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    target_pid = 43212

    monkeypatch.setattr(proc_mod, "verify_pid_alive", lambda pid, tok=None: (True, False))
    monkeypatch.setattr(proc_mod, "get_process_create_token", lambda pid: "tok-43212")
    monkeypatch.setattr(proc_mod, "_collect_descendant_pids_win32", lambda pid, tok=None: [])
    monkeypatch.setattr(proc_mod, "_terminate_single_pid_win32", lambda pid: False)

    def _boom_alive(pid: int) -> bool:
        raise OSError("cannot query process exit code")

    monkeypatch.setattr(proc_mod, "is_raw_pid_alive", _boom_alive)
    monkeypatch.setattr(
        proc_mod.subprocess,
        "run",
        lambda *a, **kw: (_ for _ in ()).throw(OSError("taskkill unavailable")),
    )

    diag: Dict[str, Any] = {}
    terminated, reused = proc_mod._kill_process_tree_win32(
        target_pid,
        expected_create_token="tok-43212",
        wait_timeout_sec=0.05,
        diagnostics=diag,
    )

    assert terminated is False
    assert reused is False
    assert diag["still_running"] == [target_pid]
    assert any("liveness_check" in e for e in diag["errors"])


def test_l1_kill_process_tree_win32_succeeds_when_killed_and_exited(monkeypatch: pytest.MonkeyPatch) -> None:
    target_pid = 43213
    state = {"alive": True}

    def _fake_terminate_single(pid: int) -> bool:
        state["alive"] = False
        return True

    monkeypatch.setattr(proc_mod, "verify_pid_alive", lambda pid, tok=None: (state["alive"], False))
    monkeypatch.setattr(proc_mod, "get_process_create_token", lambda pid: "tok-43213")
    monkeypatch.setattr(proc_mod, "_collect_descendant_pids_win32", lambda pid, tok=None: [])
    monkeypatch.setattr(proc_mod, "_terminate_single_pid_win32", _fake_terminate_single)
    monkeypatch.setattr(proc_mod, "is_raw_pid_alive", lambda pid: state["alive"])
    monkeypatch.setattr(
        proc_mod.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=1, stdout=b"", stderr=b""),
    )

    diag: Dict[str, Any] = {}
    terminated, reused = proc_mod._kill_process_tree_win32(
        target_pid,
        expected_create_token="tok-43213",
        wait_timeout_sec=0.05,
        diagnostics=diag,
    )

    assert terminated is True
    assert reused is False
    assert diag["terminated"] is True
    assert diag["still_running"] == []


def test_l1_terminate_verified_pid_tree_posix_os_kill_fails_and_alive_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_pid = 54321

    monkeypatch.setattr(proc_mod.sys, "platform", "linux")
    monkeypatch.setattr(proc_mod, "verify_pid_alive", lambda pid, tok=None: (True, False))
    monkeypatch.setattr(proc_mod, "is_raw_pid_alive", lambda pid: True)
    monkeypatch.setattr(proc_mod.os, "getpgid", lambda pid: 9999 if pid == target_pid else 1111, raising=False)

    def _deny(*_args: Any, **_kwargs: Any) -> None:
        raise PermissionError("operation not permitted")

    monkeypatch.setattr(proc_mod.os, "killpg", _deny, raising=False)
    monkeypatch.setattr(proc_mod.os, "kill", _deny)

    diag: Dict[str, Any] = {}
    terminated, reused = proc_mod.terminate_verified_pid_tree(
        target_pid,
        expected_create_token="tok-posix",
        wait_timeout_sec=0.05,
        diagnostics=diag,
    )

    assert terminated is False
    assert reused is False
    assert diag["still_running"] == [target_pid]
    assert any("os.kill(" in e for e in diag["errors"])


def test_l1_manage_bg_command_kill_preserves_running_ledger_on_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = WorkspaceGuard([tmp_path], state_root=tmp_path)
    executor = proc_mod.ProcessManager(guard=guard)
    jid = "bg_stub_1"
    pid = 65432
    log_file = tmp_path / "bg.log"
    log_file.write_text("running...\n", encoding="utf-8")

    with executor._bg_lock:
        executor._persisted_jobs[jid] = {
            "job_id": jid,
            "pid": pid,
            "pgid": None,
            "proc_create_token": "tok-bg-1",
            "tool_prefix": "pc",
            "prefix": "pc",
            "command": "stub",
            "cwd": str(tmp_path),
            "log_path": str(log_file),
            "in_path": "",
            "rc_path": str(tmp_path / "bg.rc"),
            "started_at": time.time(),
            "ended_at": None,
            "exit_code": None,
            "max_ttl_seconds": 600,
            "promoted_from_sync": False,
            "timed_out": False,
        }
        executor._save_persisted_ledger()

    monkeypatch.setattr(proc_mod, "verify_pid_alive", lambda p, tok=None: (True, False))

    def _stub_terminate(p: int, tok: Any = None, job_handle: Any = None, pgid: Any = None, **_kw: Any) -> Any:
        proc_mod._record_kill_diagnostics(
            terminated=False,
            pid_reused=False,
            still_running=[p],
            errors=[f"TerminateProcess({p}) failed"],
        )
        return False, False

    monkeypatch.setattr(proc_mod, "terminate_verified_pid_tree", _stub_terminate)

    res = executor.manage_bg_command(action="kill", job_id=jid)

    assert res["ok"] is False
    assert res["killed"] is False
    assert res["running"] is True
    assert res["still_running"] is True
    assert res["already_exited"] is False
    assert res["exit_code"] is None
    assert res["still_running_pids"] == [pid]
    assert "TerminateProcess(65432) failed" in res["error"]

    with executor._bg_lock:
        stored = executor._persisted_jobs[jid]
        assert stored["exit_code"] is None
        assert stored["ended_at"] is None


def test_l1_kill_all_active_commands_reports_still_running_for_fg_and_bg(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = WorkspaceGuard([tmp_path], state_root=tmp_path)
    executor = proc_mod.ProcessManager(guard=guard)

    fg_pid = 70001
    bg_pid = 70002
    jid = "bg_stub_2"
    log_file = tmp_path / "bg2.log"
    log_file.write_text("still alive\n", encoding="utf-8")

    fake_fg = _FakeFgProc(fg_pid, alive=True)
    with executor._fg_lock:
        executor._active_fg_procs[fg_pid] = (fake_fg, None, "tok-fg", "pc")  # type: ignore[assignment]

    with executor._bg_lock:
        executor._persisted_jobs[jid] = {
            "job_id": jid,
            "pid": bg_pid,
            "pgid": None,
            "proc_create_token": "tok-bg-2",
            "tool_prefix": "pc",
            "prefix": "pc",
            "command": "stub-bg",
            "cwd": str(tmp_path),
            "log_path": str(log_file),
            "in_path": "",
            "rc_path": str(tmp_path / "bg2.rc"),
            "started_at": time.time(),
            "ended_at": None,
            "exit_code": None,
            "max_ttl_seconds": 600,
            "promoted_from_sync": False,
            "timed_out": False,
        }
        executor._save_persisted_ledger()

    monkeypatch.setattr(proc_mod, "cancel_win32_handle_io", lambda _s: None)
    monkeypatch.setattr(proc_mod, "verify_pid_alive", lambda p, tok=None: (True, False))

    def _stub_terminate(p: int, tok: Any = None, job_handle: Any = None, pgid: Any = None, **_kw: Any) -> Any:
        proc_mod._record_kill_diagnostics(
            terminated=False,
            pid_reused=False,
            still_running=[p],
            errors=[f"TerminateProcess({p}) denied"],
        )
        return False, False

    monkeypatch.setattr(proc_mod, "terminate_verified_pid_tree", _stub_terminate)

    res = executor.kill_all_active_commands(reason="revoke", include_persisted_bg=True)

    assert res["ok"] is False
    assert res["fg_killed"] == []
    assert res["bg_killed"] == []
    assert res["still_running"] == [fg_pid, bg_pid]
    assert len(res["errors"]) >= 2
    with executor._fg_lock:
        assert fg_pid in executor._active_fg_procs


# ---------------------------------------------------------------------------
# L2: close_all_browser_sessions / BrowserPackPlugin.shutdown registry contract
# ---------------------------------------------------------------------------


def test_l2_close_all_browser_sessions_retains_failed_worker_and_allows_retry(tmp_path: Path) -> None:
    good_worker = _FakeBrowserWorker(tmp_path / "browser_profile", fail_times=0)
    bad_worker = _FakeBrowserWorker(tmp_path / "pc2", fail_times=1, err_msg="ipc stop hang")

    with browser_mod._GLOBAL_WORKERS_LOCK:
        saved_workers = dict(browser_mod._GLOBAL_WORKERS)
        saved_login = dict(browser_mod._LOGIN_WINDOWS)
        browser_mod._GLOBAL_WORKERS.clear()
        browser_mod._LOGIN_WINDOWS.clear()
        browser_mod._GLOBAL_WORKERS["k_good"] = good_worker  # type: ignore[assignment]
        browser_mod._GLOBAL_WORKERS["k_bad"] = bad_worker  # type: ignore[assignment]

    try:
        errors: List[Dict[str, str]] = []
        closed_first = browser_mod.close_all_browser_sessions(errors_out=errors)

        assert closed_first == 1
        assert good_worker.stop_calls == 1
        assert bad_worker.stop_calls == 1
        with browser_mod._GLOBAL_WORKERS_LOCK:
            assert "k_good" not in browser_mod._GLOBAL_WORKERS
            assert browser_mod._GLOBAL_WORKERS.get("k_bad") is bad_worker
        assert len(errors) == 1
        assert errors[0]["key"] == "k_bad"
        assert errors[0]["error_type"] == "RuntimeError"
        assert "ipc stop hang" in errors[0]["error"]
        assert browser_mod.get_last_close_session_failures() == errors

        # Retry now succeeds and clears the remaining entry from registry
        errors_retry: List[Dict[str, str]] = []
        closed_second = browser_mod.close_all_browser_sessions(errors_out=errors_retry)
        assert closed_second == 1
        assert bad_worker.stop_calls == 2
        assert errors_retry == []
        assert browser_mod.get_last_close_session_failures() == []
        with browser_mod._GLOBAL_WORKERS_LOCK:
            assert browser_mod._GLOBAL_WORKERS == {}
    finally:
        with browser_mod._GLOBAL_WORKERS_LOCK:
            browser_mod._GLOBAL_WORKERS.clear()
            browser_mod._GLOBAL_WORKERS.update(saved_workers)
            browser_mod._LOGIN_WINDOWS.clear()
            browser_mod._LOGIN_WINDOWS.update(saved_login)


def test_l2_close_all_browser_sessions_prefix_filter_retains_failed_and_unmatched(tmp_path: Path) -> None:
    w_pc_fail = _FakeBrowserWorker(tmp_path / "browser_profile", fail_times=1, err_msg="pc stop error")
    w_pc2_ok = _FakeBrowserWorker(tmp_path / "pc2", fail_times=0)
    w_pc3_other = _FakeBrowserWorker(tmp_path / "pc3", fail_times=0)

    with browser_mod._GLOBAL_WORKERS_LOCK:
        saved_workers = dict(browser_mod._GLOBAL_WORKERS)
        saved_login = dict(browser_mod._LOGIN_WINDOWS)
        browser_mod._GLOBAL_WORKERS.clear()
        browser_mod._LOGIN_WINDOWS.clear()
        browser_mod._GLOBAL_WORKERS["k_pc"] = w_pc_fail  # type: ignore[assignment]
        browser_mod._GLOBAL_WORKERS["k_pc2"] = w_pc2_ok  # type: ignore[assignment]
        browser_mod._GLOBAL_WORKERS["k_pc3"] = w_pc3_other  # type: ignore[assignment]

    try:
        closed_pc = browser_mod.close_all_browser_sessions(prefix_filter="pc")
        assert closed_pc == 0
        with browser_mod._GLOBAL_WORKERS_LOCK:
            assert set(browser_mod._GLOBAL_WORKERS.keys()) == {"k_pc", "k_pc2", "k_pc3"}
        failures = browser_mod.get_last_close_session_failures()
        assert len(failures) == 1
        assert failures[0]["key"] == "k_pc"

        closed_pc2 = browser_mod.close_all_browser_sessions(prefix_filter="pc2")
        assert closed_pc2 == 1
        with browser_mod._GLOBAL_WORKERS_LOCK:
            assert set(browser_mod._GLOBAL_WORKERS.keys()) == {"k_pc", "k_pc3"}
        assert browser_mod.get_last_close_session_failures() == []
    finally:
        with browser_mod._GLOBAL_WORKERS_LOCK:
            browser_mod._GLOBAL_WORKERS.clear()
            browser_mod._GLOBAL_WORKERS.update(saved_workers)
            browser_mod._LOGIN_WINDOWS.clear()
            browser_mod._LOGIN_WINDOWS.update(saved_login)


def test_l2_browser_pack_shutdown_retains_failed_worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard = WorkspaceGuard([tmp_path], state_root=tmp_path)
    plugin = browser_mod.BrowserPackPlugin(guard=guard)
    monkeypatch.setattr(browser_mod, "_release_browser_profile_locks_win32", lambda _p: None)

    ok_dir = tmp_path / "ok_prof"
    fail_dir = tmp_path / "fail_prof"
    ok_key = os.path.normcase(str(ok_dir.resolve()))
    fail_key = os.path.normcase(str(fail_dir.resolve()))
    w_ok = _FakeBrowserWorker(ok_dir, fail_times=0)
    w_fail = _FakeBrowserWorker(fail_dir, fail_times=1, err_msg="shutdown stop failure")

    with browser_mod._GLOBAL_WORKERS_LOCK:
        saved_workers = dict(browser_mod._GLOBAL_WORKERS)
        saved_login = dict(browser_mod._LOGIN_WINDOWS)
        browser_mod._GLOBAL_WORKERS.clear()
        browser_mod._LOGIN_WINDOWS.clear()
        browser_mod._GLOBAL_WORKERS[ok_key] = w_ok  # type: ignore[assignment]
        browser_mod._GLOBAL_WORKERS[fail_key] = w_fail  # type: ignore[assignment]
    with plugin._lock:
        plugin._owned_keys.update({ok_key, fail_key})

    try:
        plugin.shutdown()
        with browser_mod._GLOBAL_WORKERS_LOCK:
            assert ok_key not in browser_mod._GLOBAL_WORKERS
            assert browser_mod._GLOBAL_WORKERS.get(fail_key) is w_fail
        with plugin._lock:
            assert ok_key not in plugin._owned_keys
            assert fail_key in plugin._owned_keys
    finally:
        with browser_mod._GLOBAL_WORKERS_LOCK:
            browser_mod._GLOBAL_WORKERS.clear()
            browser_mod._GLOBAL_WORKERS.update(saved_workers)
            browser_mod._LOGIN_WINDOWS.clear()
            browser_mod._LOGIN_WINDOWS.update(saved_login)
