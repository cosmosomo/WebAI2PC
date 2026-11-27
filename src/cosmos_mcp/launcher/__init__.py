"""Cosmos MCP launcher & cold-start runtime subpackage."""
from __future__ import annotations

from typing import Any

__all__ = [
    "CLI_VERSION",
    "create_desktop_shortcut",
    "create_oneclick_bat",
    "ensure_standalone_state",
    "main",
    "resolve_default_workspace",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        from cosmos_mcp.launcher import cli as _cli

        return getattr(_cli, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

