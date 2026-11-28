# 02. Web ChatGPT Workspace & Personal Read-Only Connection Guide

> **English** | [简体中文](../02_网页版ChatGPT工作区与个人只读接入教程.md) · [Docs Hub](README.md) · [README_EN](../../README_EN.md)

This tutorial explains how to connect local WebAI2PC (Cosmos MCP `v1.2.1`) to Web ChatGPT, breaking down **1-click `@Plugin Creator` standard OAuth 2.1 setup in `Work` mode** versus **daily post-install execution across `Chat` and `Work` modes**. It covers endpoint selection for Workspace (`/mcp`) vs. Personal `Plus / Pro` (`/mcp/readonly`) accounts, consent page differences between same-machine and cloud browsers, [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) audience isolation, `stateless_http` session persistence, and common error troubleshooting.

## 1. Two-Stage Capability Split: `Work` Mode for 1-Click OAuth Setup, `Chat` Mode First for Daily Execution

According to OpenAI's official documentation ([Controlled Browser](https://learn.chatgpt.com/docs/browser), [Chrome Extension](https://learn.chatgpt.com/docs/chrome-extension), [Using ChatGPT](https://learn.chatgpt.com/docs/use-chatgpt), [Connecting Custom MCP Servers in ChatGPT](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt), and [ChatGPT Work and Codex Quotas](https://help.openai.com/en/articles/20001275-chatgpt-work-and-codex)), `Work` mode and `Chat` mode serve distinct roles during initial connection versus daily tool invocation:

1. **Stage 1: 1-Click Standard OAuth 2.1 Connection via `@Plugin Creator` in `Work` Mode**
   - Once a public HTTPS gateway is ready, open the `Web ChatGPT` tab on your local console home page and click **`Copy 1-Click Setup Prompt (for Work)`** (or **`Copy Read-Only Setup Prompt (for Work)`** for Personal `Plus / Pro`, or `Copy URL Only` / `Copy URL Only`).
   - The console generates a clean `@Plugin Creator` setup prompt pointing directly to the standard OAuth 2.1 endpoint `https://<domain>/mcp` or `https://<domain>/mcp/readonly` (zero pairing codes, passphrases, tokens, or local file paths; no manual Client ID / Secret or external relay service is needed).
   - Paste and send that prompt in Web ChatGPT's **`Work` mode** so `@Plugin Creator` discovers `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server`, registers via Dynamic Client Registration with `PKCE S256`, and installs `WebAI2PC`.
   - **Consent Page Difference (Same-Machine Browser vs. `Work` Cloud Browser)**: When `/consent` opens in a browser on your own PC, it hits the `127.0.0.1` loopback bridge within `800ms` and displays **`"1-Click Local Allow"`** directly. If you click `Take over` inside Web `Work` mode's cloud controlled browser to open `/consent`, that browser runs in OpenAI's cloud rather than on your PC, so expand `Pairing & Connected Sessions` (`Pairing & Active Sessions`) on the local console home page and enter the `6`-digit dynamic pairing code, then click `Return control`.
2. **Stage 2: Daily Tool Invocation After Installation (`Chat` vs. `Work` Mode Split)**
   - Once installed, **`Chat` mode and `Work` mode under the same account share the connector**, and both invoke local MCP tools via `@<your-connector-name>` (default `@WebAI2PC`):
   - **`Chat` mode (Preferred for Daily Local Development)**: Ideal for inspecting and editing local code, format-preserving Word / Excel revisions, running windowless commands, and executing Python tests. It responds fast, uses regular chat limits, and **consumes zero shared `Work / Codex` agent quota**.
   - **`Work` mode (Cross-App Long-Running Deliverables & Scheduled Tasks)**: Ideal when combining the cloud controlled browser with multi-source data across email / Slack / Drive to build multi-step deliverables (PPT / spreadsheets / reports), or configuring `Scheduled Tasks`. Uses `Work / Codex` agent quota.
   - **Where to Store Operational Rules (`Skills` / `Instructions`)**: OpenAI native `Skills` are available on Workspace, Desktop, or plugin bundles; in both Web `Chat` and Web `Work` modes, you can paste the operational rules directly into `Project Instructions` or Custom Instructions.

OpenAI gates write actions on unlisted custom remote MCP servers by **account subscription tier**. Choose the matching endpoint below:

| Web ChatGPT Account Type | Console Button & Standard OAuth Endpoint | Available Tools | OAuth Scope & Platform Policy |
| :- | :- | :- | :- |
| **Workspace Accounts (Team / Business / Enterprise / Edu)** | `Copy 1-Click Setup Prompt (for Work)` -> `https://<domain>/mcp` | All `16` core tools enabled by default (code & text read/write, PDF / `.pptx` extraction, format-preserving `.docx` / `.xlsx` edits, windowless terminal commands, Python execution, and background job management; `browser` and `cua` packs can be hot-enabled in `L3` Workspace Dev and `L4` Full-Disk Dev modes) | Full custom MCP read/write support enabled for Workspaces; supports full local project editing and testing in both `Chat` and `Work` modes |
| **Personal Accounts (Plus / Pro)** | `Copy Read-Only Setup Prompt (for Work)` -> `https://<domain>/mcp/readonly` | Fixed `12` read-only tools total (`7` pure read-only + `5` composite tools narrowed to read-only actions, all declaring `readOnlyHint=True`), hiding the 4 write/exec tools (`pc_edit_file`, `pc_write_file`, `pc_run_command`, `pc_run_python`) | Use when platform policy restricts personal custom remote MCP servers to `read/fetch` only (if your account has write access rolled out, you may try `/mcp` first); OAuth scope locked to `server:read` |
| **Free Personal Account (Free)** | Not yet supported | None | Web custom remote MCP server entry is not currently available |

Under the `/mcp/readonly` endpoint, the server automatically exposes `7` pure read-only query tools (`pc_get_status`, `pc_find_files`, `pc_search_code`, `pc_read_file`, `pc_batch_probe`, `pc_web_research`, `pc_skill_hub`) and projects `5` composite tools down to read-only sub-actions:
1. `pc_code_intel`: Keeps `outline`, `overview`, `repo_map`, `symbol`, `refs`, `diagnostics` (hides `rename_symbol`).
2. `pc_manage_files`: Keeps only `list` to inspect `.trash/` and snapshots (hides move, rename, trash purge, and undo).
3. `pc_bg_command`: Keeps only `status` and `list` to inspect job progress (hides start and kill).
4. `pc_workspace_memory`: Keeps only `read` and `search` to read cross-session handoff notes (hides write).
5. `pc_skill_manage`: Keeps only `list` and `trash_list` to list skills (hides create, install, and toggle).

## 2. 1-Click Setup Walkthrough & Prompt Reference

1. **Wait for Gateway Readiness**: Launch WebAI2PC, open `http://127.0.0.1:8096/`, switch to `Web ChatGPT`, and wait for a live `https://` gateway URL to appear.
2. **Copy the 1-Click Setup Prompt**: Click **`Copy 1-Click Setup Prompt (for Work)`** for Workspace accounts, or **`Copy Read-Only Setup Prompt (for Work)`** for Personal read-only accounts (or click `Copy URL Only` to copy only the HTTPS endpoint).
3. **Paste & Send in ChatGPT `Work` Mode**: Switch to `Work` mode in Web ChatGPT and paste the prompt. The generated prompt instructs `@Plugin Creator` to connect via standard OAuth 2.1 (`/.well-known/oauth-protected-resource` + `/.well-known/oauth-authorization-server`, Dynamic Client Registration + PKCE), prompt you when OAuth `/consent` approval is needed, and run a live `pc_get_status` verification call once installed:
   ```text
   [@Plugin Creator](plugin://plugin-creator@openai-curated-remote?remotePluginId=plugin_connector_1p_e1a10c53223481918a42f1510ec46c1e) Help me connect my local WebAI2PC service to my ChatGPT account and verify the first tool call (run in Work mode; once installed, invoke daily in Chat mode via @WebAI2PC without using Work/Codex quota).

   Plugin Name: WebAI2PC
   MCP URL: https://<your-live-domain>/mcp
   Authentication: Standard OAuth 2.1 (auto-discovered via /.well-known/oauth-protected-resource & /.well-known/oauth-authorization-server with DCR + PKCE; no manual Client ID / Secret needed)
   Verification: After OAuth approval and installation, call pc_get_status once to confirm my computer's hostname and active workspace status.
   ```
4. **Switch Back to `Chat` Mode for Daily Work**: Once `pc_get_status` confirms your hostname and open directories, start a **`Chat` mode** conversation for daily coding, Office revisions, and test runs using `@<your-connector-name>` (default `@WebAI2PC`, zero `Work / Codex` quota usage).
5. **Advanced Option (Local CLI Dedicated Token)**: For headless local CLI tools or scripts needing `Authorization: Bearer` access, expand `Pairing & Connected Sessions -> Advanced: Local CLI Dedicated Token` on `127.0.0.1` to mint a revocable `cmcp_` token, which can be revoked anytime from the session list.

## 3. RFC 8707 Audience Isolation & `stateless_http` Seamless Reconnect

1. **RFC 8707 Dual-Endpoint Audience Isolation**: The server maintains separate session managers and protected resource metadata for `/mcp` and `/mcp/readonly` (`/.well-known/oauth-protected-resource/mcp` and `/.well-known/oauth-protected-resource/mcp/readonly`). Tokens issued for `/mcp/readonly` are locked to the `server:read` scope in `oauth.sqlite3` (storing SHA-256 digests only, zero plaintext on disk). If a client attempts to call `/mcp` with a read-only token, the auth layer immediately returns HTTP `403` (`forbidden_cross_resource`).
2. **`stateless_http` Transport & Concurrent Refresh Replay Grace**: Both endpoints enable `StreamableHTTPSessionManager(stateless=True, json_response=True)` with no reliance on in-memory server session IDs. Built-in atomic refresh-token rotation with a `3600`-second concurrent replay grace cache (`refresh_replay`) allows existing conversations to resume immediately after a local service restart or Cloudflare hibernating gateway wakeup.

## 4. Common Errors & Troubleshooting

| Symptom or HTTP Status | Root Cause | Resolution Steps |
| :- | :- | :- |
| **1-click setup prompt button is disabled / grayed out** | No public HTTPS tunnel is active yet, or the tunnel is still handshaking | Enable the default gateway on the top connection card (or open `#settings/gateways` and toggle any channel); the button unlocks automatically once a live `https://` URL appears |
| **Clicking `Take over` in Web `Work` cloud browser asks for a pairing code on `/consent`** | Web `Work`'s controlled browser runs in OpenAI's cloud, not on your PC, so it cannot reach `127.0.0.1` loopback | Expand `Pairing & Connected Sessions` (`Pairing & Active Sessions`) on the local console home page, enter the `6`-digit dynamic pairing code into the consent page, and click `Return control` |
| **Workspace returns permission error (e.g., `403`) when adding external custom MCP** | Workspace admin has disabled external custom MCP connectors | Ask your workspace admin to enable custom MCP connectors, or connect from a personal account via `/mcp/readonly` |
| **HTTP 401 Unauthorized / prompted to re-authorize** | Clicked "Disconnect All" in the local console, temporary tunnel domain changed (e.g., `*.trycloudflare.com` changed after reboot), or state directory keys were reset | If a temporary domain changed, update the connector URL (upgrading to `*.srv.us` or a permanent Cloudflare `*.workers.dev` gateway is recommended); if the fixed domain is unchanged, re-authorize and click "1-Click Local Allow" |
| **New tools do not appear after enabling an extension pack or changing `tool_prefix`** | ChatGPT cached the tool metadata snapshot from session initialization | Open the connector details and click **Refresh**, then start a **new conversation** and invoke `@<your-connector-name>` (default `@WebAI2PC`) |
| **Personal Plus / Pro account write calls blocked by platform when testing `/mcp`** | Account is restricted by OpenAI platform policy to `read/fetch` tools for custom MCP servers | Use `Copy Read-Only Setup Prompt (for Work)` or bind the read-only endpoint `https://<domain>/mcp/readonly` and complete OAuth authorization once |
| **HTTP 403 `forbidden_cross_resource`** | A read-only token issued for `/mcp/readonly` was sent to `/mcp`, triggering [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) audience mismatch protection | Verify the connector URL suffix matches the authorized endpoint; remove the old connection and re-authorize using the target URL |
| **Returns `ERR_READONLY_WORKSPACE` or `ERR_OFFICE_FILE_LOCKED`** | Target path is inside a read-only reference directory (`readonly_workspace_roots`), or the `.docx` / `.xlsx` file is currently open and locked by local Word / Excel | Set that directory to "Read-Write" in the console's left panel (or switch to `L4` Full-Disk Dev); for Office file locks, save and close the local document window and retry |
