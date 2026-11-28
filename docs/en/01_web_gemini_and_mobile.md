# 01. Web Gemini & Web ChatGPT Connection Guide (Including Mobile Remote Control)

> **English** | [简体中文](../01_网页版Gemini与手机远程连接教程.md) · [Docs Hub](README.md) · [README_EN](../../README_EN.md)

This guide walks you through launching Cosmos MCP, enabling any of the 3 connection tiers to connect **Web Google Gemini (Task Mode, including the same-account mobile Gemini App)** and **Web ChatGPT (use `Work` mode or manual local install for first-time setup; once installed, use `Chat` mode for daily zero-quota coding and `Work` mode for long-running & scheduled tasks)**, as well as first-message wakeups and multi-device orchestration. After starting the local service, you can also open the built-in interactive tutorial page at `http://127.0.0.1:8096/tutorials` to copy your active URL in one click.

## 1. Verify Host & Account Requirements Before Connecting

1. **Web Google Gemini (Task Mode, including Android / iOS Mobile Gemini App)**:
   - Requires an `18+` Google AI Pro or Ultra subscription account, or a Google Workspace account with custom connectors enabled (free personal Google accounts do not currently have access to the web custom connector entry).
   - Bind the primary endpoint `https://<domain>/mcp`. Once bound on your computer, the mobile Gemini App signed in to the same Google account syncs the connector automatically.
2. **Web ChatGPT (Distinguishing First-Time Assisted Setup vs. Daily `Chat` / `Work` Split)**:
   - **Workspace Accounts (Team / Business / Enterprise / Edu)**: Bind the primary endpoint `https://<domain>/mcp` to access all 16 read/write and windowless command execution tools.
   - **Personal Accounts (Plus / Pro)**: When platform policies restrict custom MCP servers to `read/fetch` tools only, bind the read-only endpoint `https://<domain>/mcp/readonly`. Enforced by [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) audience isolation, this endpoint exposes 12 read-only query capabilities and rejects all write and execution requests.
   - **Two-Stage Mode Boundary**: When first connecting Web ChatGPT, click **`Copy 1-Click Setup Prompt (for Work)`** (or the read-only button for Personal Plus / Pro) on the console home page and paste it into **`Work` mode** so `@Plugin Creator` installs `WebAI2PC` over standard OAuth 2.1. Once installed, it is shared across your entire account: use **`Chat` mode** with `@<your-connector-name>` (default `@WebAI2PC`) for daily code inspection, edits, and tests (zero `Work / Codex` agent quota burn), and use **`Work` mode** for cross-app long-running deliverables and `Scheduled Tasks`.

## 2. Bare-Metal Launch & Choosing Among the 3 Connection Channels

Windows users double-click `一键启动_Cosmos_MCP.bat`; macOS and Linux users run `./start_cosmos_mcp.sh`. The launcher prioritizes the bundled `python-embed` zero-install interpreter or an existing `.venv`, automatically skips the Windows 11 default `PATH` Microsoft Store `WindowsApps\python.exe` stub, scans local official Python `3.10`–`3.14`, Conda, and `uv` interpreters, and opens the local `Cosmos Studio` console automatically.

Because Web AI runs in cloud data centers, it reaches your local service over a standard HTTPS port 443 URL. All 3 connection cards in the console have independent toggles in their top-right corners, allowing single or concurrent multi-gateway operation without disconnecting one another. The top connection bar automatically displays the active ready gateway URL:

### Tier 1: One-Click Zero-Login Direct Connect (Out-of-the-Box)

Ideal for first-time trials and quick same-machine verification without registering any cloud account or domain:
- On launch, it prioritizes a persistent local key to connect to a zero-login fixed URL (e.g., `https://xxxxx.srv.us/mcp`, `10`-second startup wait budget, unchanged across reboots), while providing an independent backup switch inside Card 1 for the built-in quick tunnel (`https://*.trycloudflare.com`) that can run concurrently alongside `srv.us` or serve as backup when outbound port `22` is blocked.
- When redirected from Web Gemini or ChatGPT to the consent page in a browser on the **same PC**, the system verifies same-machine identity via a local top-level loopback bridge—simply click **"1-Click Local Allow (No Passcode Required)"** to finish binding without copy-pasting any secret. If you open the consent page via `Take over` inside Web ChatGPT `Work` mode's cloud controlled browser, or on a phone or another computer, enter the 6-digit dynamic pairing code shown in the local console (or paste the backup passcode).
- If the active tunnel is on a temporary `*.trycloudflare.com` URL, the domain changes after a reboot; you can click the card button to retry/restore the zero-login fixed URL, or switch to Tier 2 or Tier 3.

CLI launch example (in intranet or offline environments, you can specify local caches via `COSMOS_CLOUDFLARED_BIN`, `COSMOS_CLOUDFLARED_MIRROR`, and `COSMOS_WHEELHOUSE`):

```bash
cosmos-mcp start --workspace D:\Projects\my-app
```

### Tier 2: Cloudflare Free Permanent URL (3-Second Auto-Deploy)

Ideal for long-term daily use and mobile remote control without owning a server or domain:
1. In the local `Cosmos Studio` console, select the Tier 2 connection card, click the pre-filled least-privilege Cloudflare API token creation link, and sign in.
2. Generate the API token, paste it back into the console input box, and click Deploy.
3. Within ~3 seconds, the backend automatically claims your `*.workers.dev` subdomain, deploys a free SQLite Durable Object hibernating relay gateway, and generates a permanent HTTPS URL (e.g., `https://your-worker.your-subdomain.workers.dev/mcp`). Once deployed, the API token is immediately wiped from memory and never stored in plaintext on disk.
4. Thereafter, toggle the gateway on or off directly from the card's top-right switch without re-entering the token; it can run concurrently alongside Tier 1 or Tier 3. When your PC reboots, wakes from sleep, or switches to a mobile hotspot, the local client automatically reconnects over an outbound port 443 WebSocket using pure standard library code—you never have to update the connector URL in Web Gemini or ChatGPT again.

### Tier 3: Your Own Server & Domain (1-Click 24/7 Hub or Custom Domain)

Ideal for users with a Linux cloud server (VPS) or custom domain, combining two paths:
1. **1-Click 24/7 Hub Deployment via Server IP + SSH Password or Key**:
   - Enter your cloud server's public IP and SSH port in the console. Supports SSH password (used in memory only, never saved to disk), local SSH private key path (e.g., `~/.ssh/id_ed25519`), or checking your machine's default SSH key for passwordless login (optionally enter a domain; if omitted, a public access certificate is issued automatically).
   - Uses a one-time plaintext-free key exchange to deploy a 24/7 hub on the server (automatically adding swap space on lightweight instances with `< 256MB` RAM), managing both server directories and your local PC directories together. While your local PC is powered off, Web AI can still operate on server files, and requests targeting local PC paths return a clear offline status (`ERR_NODE_OFFLINE`).
2. **Bind Your Own Fixed Domain (Cloudflare Named Tunnel or Custom Reverse Proxy)**:
   - If you have a domain managed on Cloudflare, enter your Named Tunnel token in the console or pass `--tunnel-token` via CLI with autostart enabled:
     ```bash
     cosmos-mcp start --mode cloudflare_token --tunnel-token <PASTE_YOUR_TOKEN> --public-url https://mcp.example.com --autostart
     ```
   - If your server already has a reverse proxy or SSH reverse port forwarding configured, use `--mode vps` or enter your own fixed HTTPS URL:
     ```bash
     cosmos-mcp start --mode vps --vps-ssh user@vps.example.com --vps-remote-port 18096 --public-url https://mcp.example.com --autostart
     ```

## 3. Post-Binding Setup & First-Message Wakeup

### 1. Web Google Gemini (Task Mode & Mobile App)

1. Open [Gemini Connectors](https://gemini.google.com/customize/connectors) directly (or click the bottom-left menu -> `Personal Intelligence` -> `Connected Apps` -> top-right `+ Custom`), paste `https://<domain>/mcp` into **`MCP Server URL`** (leave `Additional settings` collapsed, and **never open `/mcp` directly in the browser address bar**), then click `Next`.
2. Enter a connector name (e.g., `WebAI2PC` or `Cosmos`) and approve on the popup `/consent` page ("1-Click Local Allow" on the same PC).
3. **Enable the Master Auto-Approve Switch**: Open your newly added connector in `Connectors` and set the `App actions` master toggle to `Always allow`. Do **not** click individual allow buttons on single tool confirmation cards in the chat stream: per-card approval overrides at the single-tool level and causes remaining tools to fall back to per-call prompts.
4. **Import Operational Rules**: Click **"Copy AI Operational Rules (Recommended for Skills)"** in the console (or copy the full text of `host_skills/SKILL.md`), and save it under `Customize -> Skills` in Web Gemini's left sidebar.
5. **Start Your First Message with `@<your-connector-name>`**: Open a new chat, type `@<your-connector-name>` (e.g., `@WebAI2PC` or `@Cosmos`) at the beginning of the input box, and select the popup connector chip:
   ```text
   @WebAI2PC Show me what files are in my current workspace directory
   ```
   Right after authorization completes, the green connected banner at the top of the console offers a **"1-Click Copy Wakeup Test Prompt"** button (and the Windows tray context menu provides **"Copy Wakeup Prompt"**) for instant copy-and-paste testing.

### 2. Web ChatGPT (`Work` Mode `@Plugin Creator` 1-Click Setup · `Chat` Mode for Daily Zero-Quota Use)

1. **Stage 1 · Copy 1-Click Setup Prompt & Send in `Work` Mode**:
   - On the `Web ChatGPT` tab of the local console, wait until the gateway is ready, then click **`Copy 1-Click Setup Prompt (for Work)`** for Workspace accounts (`/mcp`) or **`Copy Read-Only Setup Prompt (for Work)`** for Personal Plus / Pro accounts (`/mcp/readonly`).
   - Switch to **`Work` mode** at the top of Web ChatGPT and paste the prompt so `@Plugin Creator` connects directly over standard OAuth 2.1 and installs `WebAI2PC`. On same-machine browsers, `/consent` shows **"1-Click Local Allow"** directly; if you click `Take over` inside Web `Work` mode's cloud browser, enter the `6`-digit dynamic pairing code from `Pairing & Connected Sessions` (`Pairing & Active Sessions`) on the console home page.
2. **Stage 2 · Switch Back to `Chat` Mode for Daily Work (Use `Work` for Long-Running & Scheduled Tasks)**: Once installed, the connector is shared across your account. For daily code inspection, editing, Office revisions, and test runs, switch back to **`Chat` mode** and invoke `@<your-connector-name>` (default `@WebAI2PC`) to call `pc_get_status` and confirm connectivity (fast response, uses regular chat limits, zero `Work / Codex` agent quota burn). Switch to **`Work` mode** when you need the controlled browser, cross-app deliverables across email/Slack/Drive, or `Scheduled Tasks`. Operational rules can be saved in native `Skills` on Workspace/Desktop, or pasted into `Project Instructions` / Custom Instructions in both Web `Chat` and `Work` modes.

## 4. Mobile Remote Control, Multi-Device Prefixes & Cross-Machine Routing

1. **Mobile Remote Control & Laptop Power Management**:
   - With the zero-login fixed URL, Tier 2, or Tier 3 permanent URL plus autostart enabled, you can open the same-account mobile Gemini App while away from your desk and send `@<your-connector-name> Run the test suite and report any failures`. Long-running commands automatically promote to `pc_bg_command` background jobs.
   - On Windows laptops, sleep prevention is enabled by default while plugged into AC power to keep the gateway online; when unplugged on battery power, sleep prevention automatically disengages to preserve battery life, and the gateway reconnects within ~1.5 seconds upon lid open or network switch.
2. **Multi-Connector `tool_prefix` & Single-Entry `target="auto"` Cross-Machine Routing**:
   - **Distinguishing Multiple Connectors by Prefix**: Keep the default `pc` for a single computer. When connecting multiple independent computers to the same chat, configure distinct `tool_prefix` values in the console or CLI (e.g., `--tool-prefix desk`, `--tool-prefix laptop`; note that `--prefix` is used for config-slot isolation when running multiple instances on the same PC) so you can call `desk_read_file` and `laptop_run_python` in the same conversation.
   - **Single-Entry Automatic Routing**: When using a Tier 3 self-hosted 24/7 VPS hub with local PC child nodes attached, you only need to bind the single hub connector in Web AI. All tools default to `target="auto"` and route automatically to the server or the matching local PC based on the target path, or accept explicit `target="server"`, `target="local"`, or a specific node name.
