# Security Architecture & Policy (SECURITY_EN.md)

> [简体中文](SECURITY.md) · **English** · [Home (README_EN.md)](README_EN.md)

This document describes the authentication architecture, cross-endpoint audience isolation, local state and credential storage boundaries, pre-edit snapshot recovery, on-demand privilege downgrade, and container sandbox isolation in Cosmos MCP `v1.2.1`.

## 1. OAuth 2.1 Authentication & RFC 8707 Cross-Endpoint Audience Isolation

### 1. Web Connector OAuth 2.1 + PKCE & Three-Layer Consent Verification
- Public or remote connections enable the OAuth 2.1 authorization code flow by default, enforcing `PKCE S256` (`code_challenge_method=S256`) and a callback domain allowlist (permitting only trusted official AI platform callback domains and local loopback addresses).
- The consent page (`/consent`) enforces three-layer anti-phishing and tiered presence verification:
  1. **Same-machine top-level `302` loopback passwordless one-click approval**: When clicking "One-Click Local Approve (No Password)" in a browser on the same machine, the flow verifies `POST /consent` -> `GET http://127.0.0.1:<port>/oauth/local-bridge` -> `GET /consent/complete`, simultaneously checking the browser-bound `HttpOnly` session cookie, same-origin `Origin` header, and a single-use 30-second HMAC-SHA256 signed ticket—producing zero browser permission prompts while blocking proxy-forged loopback calls.
  2. **4-digit anti-phishing verification code**: `/consent` prominently displays a live **4-digit anti-phishing verification code** (visual comparison only, no typing required) synced with the local `Cosmos Studio` home page and `cosmos-mcp status` to prevent cross-session phishing links from tricking users into approving unauthorized clients.
  3. **6-digit dynamic pairing code (plus 20-char fallback passphrase) for remote, mobile, or cloud-browser consent**: When authorizing from a phone, a remote PC browser, Web ChatGPT `Work` mode's cloud managed browser (`Take over`), or when a local proxy intercepts `127.0.0.1` loopback requests, the user can complete authorization with the live **6-digit numeric dynamic pairing code** shown in `Cosmos Studio` or the 20-character fixed fallback passphrase.
- The local admin passphrase is stored in `<state_dir>/secrets/auth.json` using `hashlib.scrypt` (`N=16384, r=8, p=1`) with a random 16-byte salt. OAuth access and refresh tokens are stored in SQLite keyed by their SHA-256 hash, with backoff rate-limiting on repeated invalid passphrase or pairing-code attempts.

### 2. [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) Isolation Between `/mcp` and `/mcp/readonly`
- The server mounts both the primary endpoint `/mcp` and the strictly read-only endpoint `/mcp/readonly`, publishing separate Protected Resource Metadata documents (`/.well-known/oauth-protected-resource/mcp` and `/.well-known/oauth-protected-resource/mcp/readonly`).
- Per [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) (OAuth 2.0 Resource Indicators), authorization requests carry and validate the target `resource` URI, binding issued tokens to their specific resource audience; replaying a token across endpoints immediately returns `HTTP 403`.
- `/mcp/readonly` enforces read-only permissions at both tool-listing and tool-invocation layers, exposing only read-only tools (`get_status`, `find_files`, `search_code`, read-only sub-actions of `code_intel`, `read_file`, `batch_probe`, `web_research`, `skill_hub`) and read-only sub-actions of hybrid tools (`manage_files(action="list")`, `bg_command(action="status"|"list")`, `workspace_memory(action="read"|"search")`, `skill_manage(action="list")`), while blocking all write and command-execution requests.

### 3. Local Loopback & Remote Origin Verification
- The local control panel and local management CLI use an independent `local_api_token` (`Authorization: Bearer <token>`). The server simultaneously checks that the TCP source IP is `127.0.0.1`/`::1`, the `Host` header is local loopback, and no reverse-proxy forwarding headers (such as `CF-Connecting-IP` or `X-Forwarded-For`) are present, preventing public tunnels from spoofing loopback requests.
- Local management endpoints enforce same-origin `Origin` checks and HMAC session-scoped CSRF protection. Browser cookie sessions must supply a random `csrf_token`, whereas strict local-loopback CLI or local automation calls authenticated with a constant-time verified `Authorization: Bearer <local_api_token>` do not require a form `csrf_token`.

## 2. State Directory Isolation, Pre-Edit Snapshots & Recoverable Trash

### 1. State Directory & Credential Protection
- Default state root: `%LOCALAPPDATA%\CosmosMCP` on Windows and `~/.cosmos-mcp` on macOS and Linux (first-time unconfigured startup defaults the workspace to `~/CosmosWorkspace` rather than the extracted application directory).
- `WorkspaceGuard` blocks reading or modifying `<state_dir>/secrets`, `<state_dir>/state`, and core protected OS directories across all security tiers (including `L4`), and prevents escaping workspace roots via symlinks or directory junctions.

### 2. Automatic Pre-Edit Snapshots & Recoverable Trash
- **Pre-edit snapshots**: Before `edit_file` or `write_file` modifies or overwrites an existing file, the original file is automatically backed up to the snapshot store and validated in a temporary file for syntax checks before atomic replacement; edits can be reverted via `manage_files(action="undo")` or one click in the console.
- **No raw deletion & trash recovery**: Deletions route through `manage_files(action="trash")` into the recoverable trash bin. Running `cosmos-mcp uninstall` preserves history snapshots and trash data by default (clearing them only when `--purge` is explicitly passed).

## 3. On-Demand Downgrade, Peripheral Boundaries & `sandbox/` Container Isolation

### 1. Live On-Demand Downgrade & Process Lifecycle Management
- Permissions can be tightened in real time via the "Current Permissions" 4-tier bar on the local console home page by selecting `Read-Only` (or via `Settings -> Tools & Extensions`, the system tray right-click menu "Switch to Read-Only Mode"), or `cosmos-mcp permissions --tier L1` (or `L2`). Upon downgrade or `--revoke-all`, `KillSignalWatchdog` terminates all in-flight foreground/background child process trees and closes peripheral sessions within 0.1 seconds.
- On Windows, the background supervisor manages `uvicorn`, `cloudflared`, and `ssh` child processes inside a `JobObject` (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`), reaping child processes cleanly on supervisor exit to prevent orphaned processes from holding ports.

### 2. Peripheral Expansion Packs & OS-Level Sandbox (`sandbox/`)
- **Managed Browser Pack (`browser`)**: Always runs with an isolated `<state_dir>/browser_profile` directory and a built-in synchronous SSRF guard.
- **Desktop Window Automation Pack (`desktop`, Windows only)**: Disabled under `L1`/`L2`, restricted to windows belonging to open workspace directories under `L3`, and equipped with active keyboard/mouse yielding plus unsaved-window close protection under `L4`.
- **OS-level container and sandbox configs (`sandbox/`)**: The default `L1..L4` tiers are application-layer path and command guardrails. For untrusted inputs or stronger isolation, the repository includes ready-to-use `sandbox/Dockerfile`, `sandbox/docker-compose.yml` (non-`root` `uid=1000`, `cap_drop: ALL`), and `sandbox/CosmosMCP_WindowsSandbox.wsb`.

## 4. Reporting Security Issues

If you discover a permission bypass, path traversal, OAuth authentication flaw, or SSRF bypass, please do not post live tokens or unpatched exploit chains in public discussions:
1. Run `cosmos-mcp doctor --bundle` to generate an automatically redacted diagnostic bundle.
2. Submit reproduction steps, impact scope, and remediation suggestions via GitHub Security Advisories (Private Vulnerability Reporting) in this repository.
