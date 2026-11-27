# 02. Web ChatGPT Workspace & Personal Read-Only Connection Guide

> **English** | [简体中文](../02_网页版ChatGPT工作区与个人只读接入教程.md) · [Docs Hub](README.md) · [README_EN](../../README_EN.md)

This tutorial explains how to connect local WebAI2PC (Cosmos MCP `v1.2.1`) to Web ChatGPT, clearly breaking down the **capability differences between `Work` mode and `Chat` mode across two stages ("first-time assisted setup" vs. "daily post-install execution")**. It covers endpoint selection for Workspace vs. Personal `Plus / Pro` accounts, the console's ready-gated "Copy for Work Mode to Connect" button and delegation boundaries, consent page differences between cloud and local browsers, [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) audience isolation, `stateless_http` session persistence, and common error troubleshooting.

## 1. Two-Stage Capability Split: `Work` Mode for First-Time Assisted Setup, `Chat` Mode First for Daily Execution

According to OpenAI's official documentation ([Controlled Browser](https://learn.chatgpt.com/docs/browser), [Chrome Extension](https://learn.chatgpt.com/docs/chrome-extension), [Using ChatGPT](https://learn.chatgpt.com/docs/use-chatgpt), [Connecting Custom MCP Servers in ChatGPT](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt), and [ChatGPT Work and Codex Quotas](https://help.openai.com/en/articles/20001275-chatgpt-work-and-codex)), `Work` mode and `Chat` mode have distinct roles during initial connection versus daily tool invocation:

1. **Stage 1: Adding / Auto-Filling a New Custom MCP Plugin (Who Can Connect It for You)**
   - **`Chat` mode cannot auto-fill new plugins**: `Chat` mode has no controlled browser (no cloud Browser, and no desktop `@Chrome` extension or Computer Use). Sending a connection prompt to `Chat` mode cannot operate `chatgpt.com/plugins`—it can only reply with text instructions for you to click manually.
   - **Only `Work` mode can operate a browser to fill the configuration**: Web `Work` mode includes a cloud controlled browser that can open the `Plugins` page and fill out the form; when login or `/consent` approval is required, you click `Take over` to act and `Return control` when done. Desktop `Work` mode can also drive your local logged-in tabs via the `@Chrome` / `@Edge` browser extension.
   - **Consent Page Difference (Cloud Browser vs. Local Browser)**: When you click `Take over` inside Web `Work` mode's cloud browser to open `/consent`, that browser runs in OpenAI's cloud—not on your PC—so it cannot reach local `127.0.0.1` loopback and will ask for the `6`-digit dynamic pairing code shown in your local console. When you manually open `Plugins -> + -> Add custom MCP server` in your local browser (or use Desktop `Work` with the local browser extension), `/consent` hits `127.0.0.1` loopback and displays **"1-Click Local Allow"** directly on the first screen.
2. **Stage 2: Daily Tool Invocation After Installation (Who Can Invoke `@WebAI2PC`)**
   - Once the plugin is created in `Plugins` and installed via `Install`, **`Chat` mode and `Work` mode under the same account share the installed plugin**, and both can invoke local MCP tools via `@WebAI2PC`:
   - **`Chat` mode + `@WebAI2PC` (Preferred for Daily Local Development)**: Ideal for inspecting and editing local code, format-preserving Word / Excel revisions, running windowless commands, and executing Python tests. It responds fast, uses regular chat limits, and **consumes zero shared `Work / Codex` agent token quota**.
   - **`Work` mode + `@WebAI2PC` (Cross-App Long-Running Deliverables & Scheduled Tasks)**: Ideal when combining the cloud controlled browser with multi-source data across email / Slack / Drive to build multi-step deliverables (PPT / spreadsheets / reports), or configuring `Scheduled Tasks` (time-based or event-triggered). Uses `Work / Codex` agent quota.
   - **Where to Store Operational Rules (`Skills` / `Instructions`)**: OpenAI native `Skills` are available on Workspace, Desktop, or plugin bundles; in both Web `Chat` and Web `Work` modes, you can paste the operational rules directly into `Project Instructions` or Custom Instructions for persistent reuse.

OpenAI gates write actions (`write actions`) on unlisted custom remote MCP servers by **account subscription tier**. Choose the matching endpoint below before connecting:

| Web ChatGPT Account Type | Connection Endpoint | Available Tools | OAuth Scope & Platform Policy |
| :- | :- | :- | :- |
| **Workspace Accounts (Team / Business / Enterprise / Edu)** | `https://<domain>/mcp` | All `16` core tools enabled by default (code & text read/write, PDF / `.pptx` extraction, format-preserving `.docx` / `.xlsx` edits, windowless terminal commands, Python execution, and background job management; `browser` and `cua` packs can be hot-enabled in `L3` Workspace Dev and `L4` Full-Disk Dev modes) | Full custom MCP read/write support (Full MCP) enabled for Workspaces; supports full local project editing and testing in both `Chat` and `Work` modes |
| **Personal Accounts (Plus / Pro)** | `https://<domain>/mcp/readonly` | Fixed `12` read-only tools (all declaring `readOnlyHint=True`), hiding the 4 write/exec tools (`pc_edit_file`, `pc_write_file`, `pc_run_command`, `pc_run_python`) | Use when platform policy restricts personal custom remote MCP servers to `read/fetch` only (if your account has write access rolled out, you may try `/mcp` first); OAuth scope locked to `server:read` |
| **Free Personal Account (Free)** | Not yet supported | None | Web custom remote MCP server entry is not currently available |

Under the `/mcp/readonly` endpoint, the server automatically exposes `7` pure read-only query tools (`pc_get_status`, `pc_find_files`, `pc_search_code`, `pc_read_file`, `pc_batch_probe`, `pc_web_research`, `pc_skill_hub`) and projects `5` composite tools down to read-only sub-actions:
1. `pc_code_intel`: Keeps `outline`, `overview`, `repo_map`, `symbol`, `refs`, `diagnostics` (hides `rename_symbol`).
2. `pc_manage_files`: Keeps only `list` to inspect `.trash/` and snapshots (hides move, rename, trash purge, and undo).
3. `pc_bg_command`: Keeps only `status` and `list` to inspect job progress (hides start and kill).
4. `pc_workspace_memory`: Keeps only `read` and `search` to read cross-session handoff notes (hides write).
5. `pc_skill_manage`: Keeps only `list` and `trash_list` to list skills (hides create, install, and toggle).

## 2. Two Binding Paths: Assisted Fill in `Work` Mode vs. Manual Local Browser Setup

### Method A: Click "Copy for Work Mode to Connect" Once the Gateway Is Ready & Send in `Work` Mode

In the local console (`http://127.0.0.1:8096/` -> `Web ChatGPT` tab, or Chapter 2 of `/tutorials`), **once a public HTTPS gateway is ready**, the **"Copy for Work Mode to Connect" (`复制给 Work 模式帮我连接`)** button unlocks and auto-populates your live `/mcp` or `/mcp/readonly` URL and target description (example for `Plus / Pro` read-only):

```text
[Please switch to Work mode at the top of ChatGPT before sending; Chat mode has no controlled browser and cannot fill out the Plugins page]
Please help me connect WebAI2PC to my current ChatGPT account and verify the first tool call.
Use your browser to open my ChatGPT Plugins page and fill out the configuration; when I need to sign in or approve authorization, let me Take over or tell me where to click.

Plugin Name: WebAI2PC
MCP URL: https://<your-live-domain>/mcp/readonly
Target: ChatGPT Plus / Pro, Read-Only (once installed, you can switch back to Chat mode or stay in Work mode and invoke via @WebAI2PC)
Authentication: OAuth, automatically negotiated by WebAI2PC
Verification: After authorizing and installing the plugin, call pc_get_status (get_status) to confirm the connection to my computer.
```

**Data Minimization & Dual-Mode Delegation Boundaries**:
- **Zero Sensitive Credentials Outbound**: The copied prompt contains only the live HTTPS URL and configuration instructions—**never pairing codes, passcodes, tokens, or local file paths**.
- **Must Be Sent in `Work` Mode to Drive the Browser**: Web `Work` mode uses its cloud controlled browser to open `Plugins` and fill the form (Desktop `Work` can also drive local tabs via `@Chrome` / `@Edge`). If pasted into `Chat` mode by mistake, `Chat` has no controlled browser and can only output text instructions for manual clicking.
- **User Takeover for Authorization & `Install`**: When account login or `/consent` approval appears, click `Take over` in the Web `Work` cloud browser and enter the `6`-digit dynamic pairing code shown in your local console (since the cloud browser is not on your PC). Click `Return control` afterward, click `Install` to install the plugin, and treat a **successful live `pc_get_status` call** as the completion criterion.

### Method B: Add Manually in Your Local Browser & Approve via 1-Click Local Allow

1. **Copy the Matching Endpoint**: On the `Web ChatGPT` tab of the local console, wait for the gateway to become ready. Click `Copy URL` (`https://<domain>/mcp`) for Workspace accounts, or `Copy Read-Only` (`https://<domain>/mcp/readonly`) for Personal `Plus / Pro` read-only accounts.
2. **Create & Install the Plugin**: In your local browser, open **`Plugins -> + -> Add custom MCP server`** in the left sidebar of Web ChatGPT (legacy `Developer Mode` is no longer required). Set Name to `WebAI2PC`, paste the copied HTTPS URL into `Connection`, keep Authentication as `OAuth` (negotiated automatically via Dynamic Client Registration—no manual Client ID or Secret needed), check the risk acknowledgment box, click **`Create as a plugin`**, and click **`Install`** in the plugin list.
3. **800ms Same-Machine Loopback 1-Click Allow**: When your local browser redirects to `/consent`, it validates a gateway-signed ticket and `Origin` through the `127.0.0.1` loopback bridge (`/oauth/local-bridge`) within `800ms`, displaying **"1-Click Local Allow (No Passcode Required)"** on the first screen. Remote browsers, Web `Work` cloud browsers, or browsers with strict local-network blocking automatically expand the input field so you can enter the `6`-digit dynamic pairing code (or `20`-character backup passcode) shown in the local console.
4. **Switch Back to `Chat` Mode (or Use `Work` Mode as Needed) & Verify with `@WebAI2PC`**: For daily coding and script execution, start a new **`Chat` mode** conversation (zero `Work / Codex` quota burn; use a **`Work` mode** conversation for cross-app deliverables and `Scheduled Tasks`). Type `@WebAI2PC` in the input box, select the plugin, and send a verification prompt:
   ```text
   @WebAI2PC Please call pc_get_status to confirm the connection and inspect the active workspace directory structure.
   ```
   Write operations prompt a confirmation card by default; you can check "remember approval" within the same conversation to avoid repeated prompts. Long-running commands (`> 20` seconds) automatically promote to `pc_bg_command` background jobs and return a `job_id` for incremental polling.

## 3. RFC 8707 Audience Isolation & `stateless_http` Seamless Reconnect

1. **RFC 8707 Dual-Endpoint Audience Isolation**: The server maintains separate session managers and protected resource metadata for `/mcp` and `/mcp/readonly` (`/.well-known/oauth-protected-resource/mcp` and `/.well-known/oauth-protected-resource/mcp/readonly`). Tokens issued for `/mcp/readonly` are locked to the `server:read` scope in `oauth.sqlite3` (storing SHA-256 digests only, zero plaintext on disk). If a client attempts to call `/mcp` with a read-only token, the auth layer immediately returns HTTP `403` (`forbidden_cross_resource`).
2. **`stateless_http` Transport & Concurrent Refresh Replay Grace**: Both endpoints enable `StreamableHTTPSessionManager(stateless=True, json_response=True)` with no reliance on in-memory server session IDs. Built-in atomic refresh-token rotation with a `3600`-second concurrent replay grace cache (`refresh_replay`) allows existing conversations to resume immediately after a local service restart or Cloudflare hibernating gateway wakeup.

## 4. Common Errors & Troubleshooting

| Symptom or HTTP Status | Root Cause | Resolution Steps |
| :- | :- | :- |
| **"Copy for Work Mode to Connect" button is disabled / grayed out** | No public HTTPS tunnel is active yet, or the tunnel is still handshaking | Click "1-Click Start Default Gateway" on the top connection card (or open `#settings/gateways` and toggle any channel); the button unlocks automatically once a live `https://` URL appears |
| **Sending the connection prompt to ChatGPT only returns text steps without filling the form** | You are currently in `Chat` mode (no controlled browser to operate `chatgpt.com/plugins`) | Switch to `Work` mode at the top of ChatGPT and re-send, or follow the text steps to manually add and install via `Plugins -> + -> Add custom MCP server` in your local browser |
| **Clicking `Take over` in Web `Work` cloud browser asks for a pairing code on `/consent`** | Web `Work`'s controlled browser runs in OpenAI's cloud, not on your PC, so it cannot reach `127.0.0.1` loopback | Expand `Pairing & Active Sessions` on the local console home page, copy the `6`-digit dynamic pairing code into the cloud browser consent page, and click `Return control` |
| **HTTP 401 Unauthorized / prompted to re-authorize** | Clicked "Disconnect All" in the local console, temporary tunnel domain changed (e.g., `*.trycloudflare.com` changed after reboot), or state directory keys were reset | If a temporary domain changed, open `WebAI2PC` in `Plugins` and update the URL (upgrading to a permanent Cloudflare `*.workers.dev` gateway is recommended); if the fixed domain is unchanged, re-trigger connect and click "1-Click Local Allow" |
| **New tools do not appear after enabling an extension pack or changing `tool_prefix`** | ChatGPT cached the tool metadata snapshot from plugin creation or session initialization | Open `WebAI2PC` details in `ChatGPT Plugins` and click **Refresh** (for published Workspace apps, an admin refreshes in Workspace plugin settings), then start a **new conversation** and type `@WebAI2PC` |
| **Personal Plus / Pro account write calls blocked by platform when testing `/mcp`** | Account is restricted by OpenAI platform policy to `read/fetch` tools for custom MCP servers | Switch the connection URL to the read-only endpoint `https://<domain>/mcp/readonly`, save, and complete OAuth authorization once |
| **HTTP 403 `forbidden_cross_resource`** | A read-only token issued for `/mcp/readonly` was sent to `/mcp`, triggering [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) audience mismatch protection | Verify the plugin URL suffix matches the authorized endpoint; remove the old connection and re-authorize using the target URL |
| **Returns `ERR_READONLY_WORKSPACE` or `ERR_OFFICE_FILE_LOCKED`** | Target path is inside a read-only reference directory (`readonly_workspace_roots`), or the `.docx` / `.xlsx` file is currently open and locked by local Word / Excel | Set that directory to "Read-Write" in the console's left panel (or switch to `L4` Full-Disk Dev); for Office file locks, save and close the local document window and retry |
