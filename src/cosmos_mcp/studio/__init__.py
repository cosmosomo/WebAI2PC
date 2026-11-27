"""Cosmos Studio 1.0 local visual control center subpackage."""
from __future__ import annotations

from cosmos_mcp.studio.routes import (
    STUDIO_VERSION,
    StandaloneOAuthProvider,
    handle_local_admin_permissions,
    mount_standalone_status_ui,
    read_asset_text,
)

__all__ = [
    "STUDIO_VERSION",
    "StandaloneOAuthProvider",
    "handle_local_admin_permissions",
    "mount_standalone_status_ui",
    "read_asset_text",
]
