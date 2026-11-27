# Privacy Policy & Zero-Telemetry Statement (PRIVACY_EN.md)

> [简体中文](PRIVACY.md) · **English** · [Home (README_EN.md)](README_EN.md)

## 1. Product Scope & Default Zero-Telemetry Statement

Cosmos MCP provides a controlled local workspace connection service for **Web Google Gemini (Task Mode, including the same-account Gemini mobile app)** and **Web ChatGPT (first-time auto-setup via the `Work` mode managed browser or manual local plugin installation; once installed, supports regular `Chat` mode for daily development and `Work` mode for long-running/scheduled tasks; full-featured `/mcp` for Workspace plans and read-only `/mcp/readonly` for personal plans)**.

By default, the software does not collect, aggregate, or upload usage telemetry, device fingerprints, hostnames, directory paths, tool invocation logs, or workspace file contents to the maintainers or any third-party analytics service, and honors the `DO_NOT_TRACK=1` environment variable.

## 2. Optional Multi-Gateway Coexistence & Data Flow by Channel

The project maintainers do not operate a centralized relay server that retains user traffic. The console provides 3 categories of remote HTTPS encrypted gateways that can be toggled independently and run side by side, or disabled altogether for local loopback self-checks:

1. **Option 1: `srv.us` Login-Free Fixed Channel & Quick Fallback (enabled by default on first launch, `--mode public_gateway` and `--mode cloudflare`)**:
   - By default, it uses a locally generated persistent Ed25519 key (`<state_dir>/secrets/srvus_ed25519`) to establish SSH reverse port forwarding to the public tunnel service `srv.us:22`, obtaining a fixed `https://xxxxx.srv.us` HTTPS address that persists across reboots. If outbound port `22` is blocked on the current network, it automatically falls back within `4` seconds to the bundled `cloudflared` client to open a Cloudflare Quick Tunnel (`https://*.trycloudflare.com`).
   - This channel enables registration-free connection to Web Google Gemini and Web ChatGPT. TLS traffic is forwarded through the chosen tunnel to the local listening port, where OAuth 2.1 and [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) resource-audience verification are enforced locally.
2. **Option 2: `Cloudflare Workers` Dedicated Fixed Gateway (`--mode workers_dev`)**:
   - Uses a least-privilege Cloudflare API token provided once by the user to deploy a free SQLite Durable Object hibernation relay gateway under the user's own Cloudflare account (e.g., `https://your-worker.your-subdomain.workers.dev` or a custom domain on the same account). Immediately after deployment, the API token is zero-overwritten and shredded from memory and temporary cache, leaving zero plaintext API token on local disk. During daily operation, the local daemon connects directly to the user's own gateway over outbound port `443` WebSocket and can run concurrently with Option 1 or Option 3.
3. **Option 3: `24h Linux VPS` Always-On Hub & Self-Owned Fixed Domain (`--mode vps_hub`, `vps`, `cloudflare_token`, `custom`)**:
   - Supports one-click deployment of an always-on 24-hour hub on the user's own Linux cloud server via SSH password (used in memory for the single handshake only and never saved to disk) or local SSH private key, attaching the local PC over encrypted WSS; alternatively, forwards directly through the user's own Cloudflare Named Tunnel token or self-hosted reverse-proxy domain (such as `https://mcp.example.com`).
4. **Local Loopback Isolated Self-Check Mode (all public gateway toggles off, or `--mode local`)**:
   - When all 3 public gateway toggles are switched off or `--mode local` is explicitly passed, the server listens exclusively on `127.0.0.1` for local console inspection and automated self-checks. Aside from initial runtime setup and explicit user-triggered `pc_web_research` or `pc_browser_use` calls to public web pages, the server initiates no outbound tunnel connections.
5. **Passphrase Hashing & Zero-Plaintext Token Retention Boundary**:
   - The local admin and authorization passphrase is stored as a `hashlib.scrypt` hash with a random 16-byte salt in `<state_dir>/secrets/auth.json` (permissions `0600`) and verified locally only.
   - Web Google Gemini and Web ChatGPT receive only OAuth 2.1 tokens bound to the active gateway audience (personal ChatGPT bindings to `/mcp/readonly` are physically locked to the `server:read` read-only audience) and never see the local plaintext passphrase. Local `state/oauth.sqlite3` stores only SHA-256 hash digests of access and refresh tokens as primary keys, with zero plaintext OAuth tokens written to disk.

## 3. Locally Stored Files & Complete Removal

To allow the user to inspect audit logs, undo file edits, and restore accidentally deleted files, the program stores the following local data solely inside the local state directory (`%LOCALAPPDATA%\CosmosMCP` by default on Windows, `~/.cosmos-mcp` on macOS and Linux):

- `logs/audit.jsonl`: Records local tool call timestamps, tool names, durations, and execution statuses.
- `logs/server.log` and `logs/supervisor.log`: Local server and background supervisor logs, automatically rotated by file size.
- `history/` and `.undo_history/`: Pre-edit file snapshots and files moved to the recoverable trash bin.
- `secrets/auth.json`, `secrets/master_seed`, `secrets/srvus_ed25519`, `secrets/workers_tunnel_secret.txt`, `secrets/tunnel_token.txt`, and `state/oauth.sqlite3`: Stores the passphrase hash, local deterministic seed, persistent SSH tunnel key, Workers gateway handshake secret, Named Tunnel token, and SHA-256 hashed OAuth token records (no plaintext OAuth access tokens, Cloudflare deployment API tokens, or VPS SSH passwords are stored).

When exporting diagnostics, `cosmos-mcp doctor --bundle` automatically redacts passphrases, tokens, tunnel subdomains, email addresses, and OS home-directory usernames. To stop background processes and purge all local records in the state directory, run:

```bash
cosmos-mcp uninstall --purge --json
```
