"""P0 state-contract regression tests for LiveRuntimePolicy (A1, A2, A3, A4)."""
from __future__ import annotations

import json
from pathlib import Path
import threading
from typing import Any, Dict, List

import pytest

import cosmos_mcp.core.config as cfg_mod
from cosmos_mcp.core.config import LiveRuntimePolicy
from cosmos_mcp.core.guard import WorkspaceGuard


def _make_policy(
    tmp_path: Path,
    *,
    tier_key: str = "tier3_workspace_dev",
    tray_enabled: bool = True,
    cfg_path: Path | None = None,
    write_initial_disk: bool = True,
) -> tuple[LiveRuntimePolicy, WorkspaceGuard, Path, Path]:
    ws = (tmp_path / "ws_main").resolve()
    ws.mkdir(parents=True, exist_ok=True)
    state_root = (tmp_path / "state_root").resolve()
    cfg_dir = state_root / "config"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    eff_cfg = cfg_path if cfg_path is not None else (cfg_dir / "service.json")

    if write_initial_disk and not eff_cfg.is_file():
        initial_doc = {
            "permission_tier": tier_key,
            "previous_non_readonly_tier": "tier3_workspace_dev",
            "tool_prefix": "pc",
            "workspace": str(ws),
            "workspace_roots": [str(ws)],
            "readonly_workspace_roots": [],
            "tray_enabled": tray_enabled,
            "keep_awake": True,
            "enabled_packs": [],
            "annotation_mode": "seamless",
            "approval_popups": False,
        }
        eff_cfg.write_text(json.dumps(initial_doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    guard = WorkspaceGuard()
    policy = LiveRuntimePolicy(
        cfg_path=eff_cfg,
        state_root=state_root,
        guard=guard,
        keep_awake=True,
        on_keep_awake_change=lambda _flag: None,
    )
    return policy, guard, eff_cfg, ws


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


# ---------------------------------------------------------------------------
# A1: CrossProcessFileLock + latest-disk read + patch-only merge
# ---------------------------------------------------------------------------


def test_a1_stale_instance_patch_merge_preserves_downgrade(tmp_path: Path) -> None:
    """Two instances load L3; A downgrades to L1; B disables tray_enabled -> disk keeps L1 + tray_enabled=False."""
    pol_a, guard_a, cfg_path, _ws = _make_policy(tmp_path, tier_key="tier3_workspace_dev", tray_enabled=True)
    pol_b, guard_b, _, _ = _make_policy(
        tmp_path, tier_key="tier3_workspace_dev", tray_enabled=True, cfg_path=cfg_path, write_initial_disk=False
    )

    assert pol_a.tier_key == "tier3_workspace_dev"
    assert pol_b.tier_key == "tier3_workspace_dev"

    # Instance A downgrades to L1
    pol_a.persist_changes(tier_key="L1")
    assert pol_a.tier_key == "tier1_readonly"
    assert guard_a.tier == "L1"
    assert _read_json(cfg_path)["permission_tier"] == "tier1_readonly"

    # Instance B still holds stale L3 in memory and only toggles tray_enabled=False
    pol_b.persist_changes(tray_enabled=False)

    disk_doc = _read_json(cfg_path)
    assert disk_doc["permission_tier"] == "tier1_readonly"
    assert disk_doc["tray_enabled"] is False
    # Instance B also converges its memory & guard to the merged disk state
    assert pol_b.tier_key == "tier1_readonly"
    assert pol_b.tray_enabled is False
    assert guard_b.tier == "L1"


def test_a1_persist_changes_uses_cross_process_lock_and_merges_concurrent_patches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """persist_changes acquires fs_tx CrossProcessFileLock and merges disjoint concurrent writes cleanly."""
    pol_a, _, cfg_path, _ws = _make_policy(tmp_path, tier_key="tier3_workspace_dev", tray_enabled=True)
    pol_b, _, _, _ = _make_policy(
        tmp_path, tier_key="tier3_workspace_dev", tray_enabled=True, cfg_path=cfg_path, write_initial_disk=False
    )

    lock_events: List[str] = []
    real_get_file_lock = cfg_mod.get_file_lock

    class _TrackedLock:
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def __enter__(self) -> Any:
            lock_events.append("enter")
            self._inner.__enter__()
            return self

        def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            try:
                self._inner.__exit__(exc_type, exc_val, exc_tb)
            finally:
                lock_events.append("exit")

    monkeypatch.setattr(cfg_mod, "get_file_lock", lambda p: _TrackedLock(real_get_file_lock(p)))

    barrier = threading.Barrier(2)
    errors: List[BaseException] = []

    def _run_a() -> None:
        try:
            barrier.wait(timeout=5.0)
            pol_a.persist_changes(tier_key="L1")
        except BaseException as exc:
            errors.append(exc)

    def _run_b() -> None:
        try:
            barrier.wait(timeout=5.0)
            pol_b.persist_changes(tray_enabled=False, keep_awake=False)
        except BaseException as exc:
            errors.append(exc)

    t1 = threading.Thread(target=_run_a)
    t2 = threading.Thread(target=_run_b)
    t1.start()
    t2.start()
    t1.join(timeout=10.0)
    t2.join(timeout=10.0)

    assert not errors
    assert lock_events.count("enter") == 2
    assert lock_events.count("exit") == 2

    disk_doc = _read_json(cfg_path)
    assert disk_doc["permission_tier"] == "tier1_readonly"
    assert disk_doc["tray_enabled"] is False
    assert disk_doc["keep_awake"] is False


# ---------------------------------------------------------------------------
# A2: Never escalate memory or guard before durable disk write succeeds
# ---------------------------------------------------------------------------


def test_a2_disk_write_oserror_does_not_escalate_memory_or_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When starting at L1 and requesting L4, an OSError on disk write keeps memory, guard, and disk at L1."""
    pol, guard, cfg_path, _ws = _make_policy(tmp_path, tier_key="tier1_readonly", tray_enabled=True)
    assert pol.tier_key == "tier1_readonly"
    assert guard.tier == "L1"
    assert guard.restrict_to_workspace is True

    guard_calls: List[Any] = []
    orig_set_ws = guard.set_workspace_policy

    def _spy_set_ws(*args: Any, **kwargs: Any) -> None:
        guard_calls.append((args, kwargs))
        orig_set_ws(*args, **kwargs)

    monkeypatch.setattr(guard, "set_workspace_policy", _spy_set_ws)

    def _boom_write(_target: Path, _payload: Any, mode_override: Any = None) -> None:
        raise OSError("simulated disk full")

    monkeypatch.setattr(cfg_mod, "atomic_write_json", _boom_write)

    with pytest.raises(OSError, match="simulated disk full"):
        pol.persist_changes(tier_key="L4", tray_enabled=False)

    # Zero premature guard updates occurred
    assert guard_calls == []
    # Memory stays strictly L1
    assert pol.tier_key == "tier1_readonly"
    assert pol.short_tier_code == "L1"
    assert pol.restrict_to_workspace is True
    assert pol.allow_edit is False
    assert pol.allow_exec is False
    assert pol.allow_host_admin is False
    assert pol.tray_enabled is True
    assert pol.tier_epoch == 0
    # Guard stays strictly L1
    assert guard.tier == "L1"
    assert guard.restrict_to_workspace is True
    # Disk stays strictly L1
    disk_doc = _read_json(cfg_path)
    assert disk_doc["permission_tier"] == "tier1_readonly"
    assert disk_doc["tray_enabled"] is True


# ---------------------------------------------------------------------------
# A3: Guard update exceptions must propagate explicitly (never silent success)
# ---------------------------------------------------------------------------


def test_a3_apply_direct_propagates_guard_exception_and_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If guard.set_workspace_policy raises, apply_direct propagates the exception and rolls back memory."""
    pol, guard, _cfg_path, _ws = _make_policy(tmp_path, tier_key="tier1_readonly", tray_enabled=True)

    def _fail_guard(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("guard update exploded")

    monkeypatch.setattr(guard, "set_workspace_policy", _fail_guard)

    with pytest.raises(RuntimeError, match="guard update exploded"):
        pol.apply_direct(tier_key="L4", tool_prefix="newp", tray_enabled=False)

    assert pol.tier_key == "tier1_readonly"
    assert pol.tool_prefix == "pc"
    assert pol.tray_enabled is True
    assert pol.tier_epoch == 0
    assert guard.tier == "L1"
    assert guard.tool_prefix == "pc"


def test_a3_persist_changes_propagates_guard_exception_and_rolls_back_disk_and_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If guard.set_workspace_policy raises during persist_changes, exception propagates and disk+memory roll back."""
    pol, guard, cfg_path, _ws = _make_policy(tmp_path, tier_key="tier1_readonly", tray_enabled=True)

    def _fail_guard(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("guard sync failed")

    monkeypatch.setattr(guard, "set_workspace_policy", _fail_guard)

    with pytest.raises(RuntimeError, match="guard sync failed"):
        pol.persist_changes(tier_key="L4", tray_enabled=False)

    # Memory rolled back to L1
    assert pol.tier_key == "tier1_readonly"
    assert pol.tray_enabled is True
    assert pol.tier_epoch == 0
    # Guard remains at L1
    assert guard.tier == "L1"
    assert guard.restrict_to_workspace is True
    # Disk rolled back to L1
    disk_doc = _read_json(cfg_path)
    assert disk_doc["permission_tier"] == "tier1_readonly"
    assert disk_doc["tray_enabled"] is True


# ---------------------------------------------------------------------------
# A4: Full upfront pre-validation, zero partial commits
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_kwargs_builder",
    [
        lambda tmp_path: {"tier_key": "L4", "enabled_packs": ["nonexistent_pack"]},
        lambda tmp_path: {
            "tier_key": "L4",
            "workspace_roots": [tmp_path / "uncreated_ws"],
            "toolset_profile": "bogus_profile",
        },
        lambda tmp_path: {
            "tier_key": "L4",
            "readonly_workspace_roots": [tmp_path / "not_mounted_dir"],
        },
        lambda tmp_path: {"tier_key": "L4", "workspace_roots": []},
        lambda tmp_path: {"tier_key": "L4", "annotation_mode": "bogus_mode"},
        lambda tmp_path: {"tier_key": "L4", "prompt_profile": "bogus_prompt"},
        lambda tmp_path: {"tier_key": "L99", "tray_enabled": False},
    ],
)
def test_a4_apply_direct_rejects_invalid_batch_with_zero_partial_mutation(
    tmp_path: Path, bad_kwargs_builder: Any
) -> None:
    """Any invalid field in apply_direct raises ValueError with zero memory, guard, or filesystem mutation."""
    pol, guard, _cfg_path, ws = _make_policy(tmp_path, tier_key="tier1_readonly", tray_enabled=True)
    bad_kwargs = bad_kwargs_builder(tmp_path)

    with pytest.raises(ValueError):
        pol.apply_direct(**bad_kwargs)

    assert pol.tier_key == "tier1_readonly"
    assert pol.workspace_roots == (ws,)
    assert pol.readonly_workspace_roots == ()
    assert pol.enabled_packs == ()
    assert pol.tray_enabled is True
    assert pol.tier_epoch == 0
    assert pol.workspace_epoch == 0
    assert guard.tier == "L1"
    assert guard.restrict_to_workspace is True
    assert not (tmp_path / "uncreated_ws").exists()


def test_a4_persist_changes_rejects_invalid_batch_without_touching_memory_guard_or_disk(
    tmp_path: Path,
) -> None:
    """Any invalid field in persist_changes raises ValueError before touching memory, guard, or disk."""
    pol, guard, cfg_path, ws = _make_policy(tmp_path, tier_key="tier1_readonly", tray_enabled=True)
    before_bytes = cfg_path.read_bytes()
    unmounted = tmp_path / "outside_dir"
    unmounted.mkdir()

    for bad_kwargs in (
        {"tier_key": "L4", "enabled_packs": ["unknown_pack"]},
        {"tier_key": "L4", "readonly_workspace_roots": [unmounted]},
        {"tier_key": "L4", "workspace_roots": [tmp_path / "never_created"], "tool_prefix": "123BAD!"},
    ):
        with pytest.raises(ValueError):
            pol.persist_changes(**bad_kwargs)

        assert pol.tier_key == "tier1_readonly"
        assert pol.workspace_roots == (ws,)
        assert pol.readonly_workspace_roots == ()
        assert pol.enabled_packs == ()
        assert pol.tool_prefix == "pc"
        assert pol.tier_epoch == 0
        assert guard.tier == "L1"
        assert guard.restrict_to_workspace is True
        assert cfg_path.read_bytes() == before_bytes
        assert not (tmp_path / "never_created").exists()
