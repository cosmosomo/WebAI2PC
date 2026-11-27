# Contributing to Cosmos MCP

Thank you for helping improve Cosmos MCP! This guide summarizes local setup, architectural boundaries, privacy hygiene, and pre-PR verification gates.

## 1. Development Setup

Requires Python `3.10`–`3.14` on Windows, macOS, or Linux:

```bash
python -m venv .venv
# Windows:
.venv\Scripts\python -m pip install -e ".[docs,dev]"
# macOS / Linux:
.venv/bin/python -m pip install -e ".[docs,dev]"
```

## 2. Core Engineering Boundaries

1. **Four-Layer Unidirectional Imports**:
   - `cosmos_mcp.core` (pure Python standard library; zero third-party runtime imports at top level)
   - `cosmos_mcp.protocol` (OAuth 2.1 + PKCE, RFC 8707 resource indicators, Streamable HTTP MCP transport)
   - `cosmos_mcp.capabilities` & `cosmos_mcp.packs` (skills hub, optional headless browser & offscreen Windows UIA packs)
   - `cosmos_mcp.studio` & `cosmos_mcp.launcher` (local control center, resident supervisor, CLI, diagnostics)
2. **Zero-Popup & Zero-Focus-Steal Guarantee (Windows)**:
   - Every background subprocess spawned on Windows must pass `creationflags=CREATE_NO_WINDOW` (`0x08000000`) and `stdin=subprocess.DEVNULL`.
   - Never open foreground console windows, modal dialogs, or modify the system clipboard without an explicit user click or `--copy-password`.
3. **Recoverable File Safety**:
   - Destructive direct file deletion is avoided across workspace tools and default uninstalls; move retired files into `.undo_history/trash` via `safe_trash_file` unless `--purge` is explicitly requested.
4. **Strict Privacy & Secret Redaction**:
   - Never commit real `.env` files, tunnel tokens, Cloudflare account IDs, personal hostnames, OS usernames, or private local paths.
   - When reporting bugs, generate a redacted diagnostic bundle via `cosmos-mcp doctor --bundle` rather than pasting raw `service.json` or `auth.json` files.

## 3. Pre-Submission Checks

Run the test suite and release hygiene gate before opening a Pull Request:

```bash
python -B -m pytest -p no:cacheprovider -q tests
python -B scripts/build_release.py --check
```

For security vulnerabilities, please follow [`SECURITY.md`](SECURITY.md) and use GitHub Private Vulnerability Reporting rather than opening a public issue.
