"""Synchronization helpers for asynchronous daemon integration tests."""
import threading

import pytest


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
