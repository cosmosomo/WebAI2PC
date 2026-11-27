"""Minimal extension slot for open Agent Skills & Plugins (`capabilities/`)."""
from __future__ import annotations

from pathlib import Path
import threading
from typing import List, Protocol, Sequence, runtime_checkable

from cosmos_mcp.core.contracts import ToolSpec

PROJECT_SKILLS_REL_DIR = Path(".agents") / "skills"
USER_SKILLS_REL_DIR = Path(".agents") / "skills"


@runtime_checkable
class CapabilityProvider(Protocol):
    """Static tool & on-demand capability provider compatible with locked host schemas."""

    name: str

    def build_static_tools(self) -> Sequence[ToolSpec]: ...


_PROVIDER_LOCK = threading.RLock()
_REGISTERED_PROVIDERS: List[CapabilityProvider] = []


def register_capability_provider(provider: CapabilityProvider) -> None:
    """Register an extension `CapabilityProvider` in-process."""
    with _PROVIDER_LOCK:
        for idx, existing in enumerate(_REGISTERED_PROVIDERS):
            if getattr(existing, "name", "") == getattr(provider, "name", ""):
                _REGISTERED_PROVIDERS[idx] = provider
                return
        _REGISTERED_PROVIDERS.append(provider)


def unregister_capability_provider(name: str) -> bool:
    """Remove a registered `CapabilityProvider` by `name`."""
    target = (name or "").strip()
    if not target:
        return False
    with _PROVIDER_LOCK:
        before = len(_REGISTERED_PROVIDERS)
        _REGISTERED_PROVIDERS[:] = [p for p in _REGISTERED_PROVIDERS if getattr(p, "name", "") != target]
        return len(_REGISTERED_PROVIDERS) < before


def clear_registered_providers() -> None:
    """Clear all dynamically registered providers (restoring default 12-tool surface)."""
    with _PROVIDER_LOCK:
        _REGISTERED_PROVIDERS.clear()


def load_registered_providers() -> List[CapabilityProvider]:
    """Return active extension capability providers (empty list by default)."""
    with _PROVIDER_LOCK:
        return list(_REGISTERED_PROVIDERS)
