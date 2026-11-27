"""Synchronization and deterministic resource teardown helpers for test suites."""
import contextlib
import threading

import pytest

from cosmos_mcp.core.config import KillSignalWatchdog, _POLICY_SLEEP_INHIBITOR
from cosmos_mcp.core.net_power import SleepInhibitor


@pytest.fixture(autouse=True)
def _cleanup_background_daemons_and_inhibitors(monkeypatch):
    """Ensure per-test `SleepInhibitor` (`caffeinate`/`pmset`) and `KillSignalWatchdog` threads never leak across tests."""
    active_inhibitors = []
    active_watchdogs = []
    orig_enable = SleepInhibitor.enable
    orig_start = KillSignalWatchdog.start

    def _tracked_enable(self, *args, **kwargs):
        active_inhibitors.append(self)
        return orig_enable(self, *args, **kwargs)

    def _tracked_start(self, *args, **kwargs):
        active_watchdogs.append(self)
        return orig_start(self, *args, **kwargs)

    monkeypatch.setattr(SleepInhibitor, "enable", _tracked_enable)
    monkeypatch.setattr(KillSignalWatchdog, "start", _tracked_start)
    try:
        yield
    finally:
        for wd in active_watchdogs:
            with contextlib.suppress(Exception):
                wd.stop()
        for inh in active_inhibitors:
            with contextlib.suppress(Exception):
                inh.disable()
        with contextlib.suppress(Exception):
            _POLICY_SLEEP_INHIBITOR.disable()


@pytest.fixture
def wait_tunnel_probes(monkeypatch):
    """Join real probe workers before reading their atomically replaced files."""
    original_thread = threading.Thread
    workers = []

    class TrackedThread(original_thread):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            if self.name.startswith("cosmos-tunnel-probe-"):
                workers.append(self)

    def wait():
        for worker in workers:
            worker.join(timeout=5.0)
            assert not worker.is_alive(), f"Tunnel probe did not finish: {worker.name}"

    monkeypatch.setattr(threading, "Thread", TrackedThread)
    yield wait
    wait()
