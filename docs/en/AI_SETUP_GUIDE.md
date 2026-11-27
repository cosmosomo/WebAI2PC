# WebAI2PC (Cosmos MCP) Public Setup Guide (Direct-Read Co-Setup for Web Gemini / ChatGPT)

> [简体中文](../AI_SETUP_GUIDE.md) · **English** · [Docs Home](README.md) · [README](../../README_EN.md)

This document uses a fixed English filename so any Web Google Gemini or Web ChatGPT session can fetch it directly and guide users step by step through downloading, first-time binding, and Cloudflare fixed-URL setup:
- GitHub page URL: `https://github.com/cosmosomo/WebAI2PC/blob/main/docs/en/AI_SETUP_GUIDE.md`
- Raw plain-text URL: `https://raw.githubusercontent.com/cosmosomo/WebAI2PC/main/docs/en/AI_SETUP_GUIDE.md`
- Chinese SSOT version: `https://github.com/cosmosomo/WebAI2PC/blob/main/docs/AI_SETUP_GUIDE.md`

## 1. Co-Setup Responsibilities for the Assisting AI

If you are helping a user install or configure WebAI2PC (Cosmos MCP) in chat, follow these interaction rules:
1. **Clarify 3 Basics First**: If the user has not already shared them, ask in a short list: (1) OS—Windows, macOS, or Linux; (2) whether they have already downloaded and extracted the release ZIP; (3) whether they are connecting Web Gemini or Web ChatGPT (Workspace Team/Business/Enterprise/Edu vs. personal Plus/Pro, and whether they are currently in `Chat` mode or `Work` mode).
2. **Teach One Step at a Time**: Based on the user's reply, give only 3 to 5 lines of concrete actions and exact button names for the current step. Wait for "done" or an error screenshot before moving to the next step—never dump the entire guide at once.
3. **State ChatGPT `Work` vs. `Chat` Auto-Setup Boundaries Honestly**: If the user asks you inside ChatGPT to connect for them, explain first that only `Work` mode has a managed browser capable of filling out the `Plugins` page (`Chat` mode has no managed browser and can only guide the user step by step or ask them to switch to `Work` mode at the top). Remind the user never to paste pairing codes, passphrases, tokens, or local paths into chat.
4. **Take Over Directly Once `@Cosmos` or `@WebAI2PC` Is Connected**: As soon as the connector is bound, tell the user they can simply say: `@Cosmos open the gateway settings page on my computer and walk me through setting up a Cloudflare fixed URL` (use `@WebAI2PC` in ChatGPT). The connected AI can call local tools to open the exact settings page in the user's browser and verify live status.

## 2. Choose the Right Package, Extract Fully & Launch

Release downloads: `https://github.com/cosmosomo/WebAI2PC/releases`

1. **Choose by Environment**:
   - **Windows everyday users (Recommended)**: Download the full offline portable bundle `Cosmos-MCP-v1.2.1-win64-full.zip`. It bundles a portable Python 3.12 runtime and all core dependencies—no Python installation required.
   - **Developers with Python 3.10–3.14 installed, or macOS / Linux users**: Download the lightweight package `Cosmos-MCP-v1.2.1.zip`. The launcher automatically detects system Python, Conda, or `uv` and skips Windows Store stubs.
2. **Extract Completely Before Running (Critical)**:
   - Right-click the `.zip` archive and choose "Extract All" to your Desktop or any normal folder. **Never double-click the startup script inside an archive preview window (WinRAR / 7-Zip / Explorer ZIP view).**
3. **Launch the Local Console**:
   - **Windows**: Open the extracted folder and double-click `一键启动_Cosmos_MCP.bat`.
   - **macOS / Linux**: Open a terminal in the extracted folder and run `./start_cosmos_mcp.sh`.
   - The server starts silently in the background with zero terminal popups and opens the local console at `http://127.0.0.1:8096/` (page title: `WebAI2PC · 本地控制台` / `WebAI2PC · Local Console`).

## 3. First-Time Registration-Free Connection to Web Gemini / ChatGPT (3 Steps)

No third-party account registration is needed for your first test connection:

1. **Step 1: Copy the Connection URL from the Local Console**
   - By default, Option 1 ("One-Click Login-Free Direct Connect") is active and generates `https://*.srv.us/mcp` (login-free fixed URL that persists across reboots) or `https://*.trycloudflare.com/mcp` (registration-free quick tunnel).
   - For **Web Gemini**: Keep `Web Gemini` selected at the top and click the blue `Copy Connection URL` button.
   - For **Web ChatGPT**: Switch the top selector to `Web ChatGPT` (buttons unlock once the gateway is ready). If you want `Work` mode's managed browser to fill the form for you, click **"Copy Request for Work Mode Auto-Connect"** (generates a setup prompt containing only the real `/mcp` or `/mcp/readonly` URL—never pairing codes, passphrases, tokens, or local paths). To add it manually in your local browser, click `Copy URL` (full `/mcp` for Team / Business / Enterprise / Edu workspaces) or `Copy Read-Only` (`/mcp/readonly` for personal Plus / Pro accounts).
2. **Step 2: Add the Connector in the Web Client & Approve**
   - **Web Gemini (requires 18+ Google AI Pro / Ultra or enabled Workspace account)**:
     1. Open [Gemini Connectors](https://gemini.google.com/customize/connectors) directly (or bottom-left menu -> `Preferences` -> `Personal Intelligence` -> `Connected Apps` -> top-right `+ Custom`), paste `https://<domain>/mcp` into **`MCP Server URL`** (do **not** open `/mcp` in the browser address bar), and click `Next`.
     2. Enter `Cosmos` as the name, paste the copied `https://.../mcp` URL (leave `Client ID` and `Client Secret` blank), and submit to open the local authorization page.
     3. In the browser on the same PC, click `One-Click Local Approve` to finish binding.
     4. Open the `Cosmos` connector details page and set **`App actions` to `Always allow`** (also click `Copy AI Rules` in the local console and paste them into `Customize -> Skills` in Gemini).
   - **Web ChatGPT (Distinguish `Work` Auto-Setup vs. Local Manual Setup)**:
     1. **Using `Work` mode to fill the form**: Only `Work` mode has a managed browser (Web `Work` provides a cloud managed browser with `Take over`; Desktop `Work` can control local tabs via the `@Chrome` / `@Edge` extension). Switch to `Work` mode at the top of ChatGPT before pasting the auto-connect prompt. `Chat` mode has no managed browser and cannot operate `chatgpt.com/plugins`—it can only output manual click instructions.
     2. **Manual or guided clicks**: Open `Plugins -> + -> Add custom MCP server` in the left sidebar, set Name to `WebAI2PC`, paste the HTTPS URL into `Connection`, choose `OAuth` authentication (auto-negotiated; leave Client ID / Secret blank), check the risk acknowledgment box, click `Create as a plugin`, and click **`Install`** in the plugins list.
     3. **Cloud Browser vs. Local Browser Approval Difference**: When approving in your local browser (or Desktop `Work` via local browser extension), `/consent` hits the `127.0.0.1` loopback and lets you click `One-Click Local Approve`. When clicking `Take over` inside Web `Work`'s cloud browser, `/consent` runs in OpenAI's cloud rather than on your PC, so it asks for the live `6`-digit dynamic pairing code shown under `Pairing & Active Sessions` in your local console; after approving, click `Return control`.
3. **Step 3: First-Message Wake-Up & Verify with `pc_get_status`**
   - **Web Gemini**: Start a new chat (Task Mode recommended) and send `@Cosmos call pc_get_status and check what files are in my current workspace` (select the popped-up connector chip when typing `@Cosmos`). The same-account Gemini mobile app syncs the connector automatically.
   - **Web ChatGPT (Use `Chat` Daily to Save Quota, `Work` for Long Tasks)**: Once `Install` is clicked, the plugin is available across your account. For daily local coding, Office edits, and running windowless commands/tests, switch back to **`Chat` mode** and type `@WebAI2PC` (fast, uses normal chat limits, zero `Work / Codex` agent quota consumption). Switch to **`Work` mode** with `@WebAI2PC` when combining the cloud browser, cross-app deliverables (email/Slack/Drive), or `Scheduled Tasks`. A successful `pc_get_status` (`get_status`) response returning local status and directories confirms setup is complete. Save the operating rules into native `Skills` (Workspace/Desktop) or `Project Instructions` / Custom Instructions (Web `Chat` and `Work`).

## 4. Advanced Setup: Free Permanent Cloudflare Fixed URL (`#settings/gateways` Option 2 in 3 Steps)

If the user wants a free, serverless, permanently fixed HTTPS URL (or wants to bind their own domain), guide them through these 3 steps:

1. **Open Gateway Settings & Expand Card 2**:
   - In the local console, click `Settings` at the top-right -> `Connections & Gateways` on the left (`http://127.0.0.1:8096/#settings/gateways`; if `@Cosmos` is already connected, ask the AI to open this page directly).
   - Locate **Option 2 · Serverless Fixed URL: `Cloudflare Dedicated Fixed Gateway`** and click `Configure ▾` on the right (all 3 gateway cards have independent toggles and run concurrently—deploying Option 2 will not disconnect Option 1).
2. **Deploy in 3 Steps (~3 Seconds)**:
   - **Step 1: Open the prefilled token page**: Click `Step 1: Open Prefilled Cloudflare Token Page (Google Sign-In Supported)`. Sign in to Cloudflare (required Workers permissions are pre-selected), scroll to the bottom, click `Continue to summary` -> `Create Token`, and copy the API token.
   - **Step 2: Paste the token (optional custom domain)**: Return to the local console and paste the token into `Step 2: Paste API Token (Shredded Immediately After Deploy)`. If you have an Active Zone domain under Cloudflare, optionally enter a subdomain in `Optional: Custom Domain (Active Zone)` (e.g., `mcp.yourdomain.dpdns.org`). If your token spans multiple Cloudflare accounts, select the target account from the dropdown.
   - **Step 3: Deploy & replace the URL**: Click the blue `One-Click Deploy & Enable (~3s)` button. The system claims a subdomain if needed, deploys the free Cloudflare Workers + SQLite Durable Object hibernation gateway, and outputs your permanent `https://*.workers.dev/mcp` (and `/mcp/readonly`) URL.
3. **Post-Deploy Token Safety, Channel Dependencies & Regional Proxy Rules**:
   - Immediately upon completion, the Cloudflare API token is zero-overwritten and shredded from memory and disk. Click `Copy This Card URL` (or `Copy Plus/Pro Read-Only` for personal ChatGPT) to update your web connector once; afterward, toggle Card 2 on/off anytime without re-entering a token.
   - **Option 2 (`workers_dev`) Dependencies & Proxy Boundary**: Runs on a pure Python stdlib `443 WSS` client (**zero external binary dependencies**; no `Node.js`, `wrangler`, or `cloudflared`), subject to Cloudflare Workers Free `100,000` req/day cap (Error `1027`) and `125`s default edge read timeout. **Mainland China note**: default `*.workers.dev` suffers full DNS pollution (`100%` unproxied timeout), so without a custom domain your PC **must keep a local HTTP/HTTPS proxy (Clash / Mihomo / v2rayN, or `HTTPS_PROXY` / `WSS_PROXY`) continuously open with rules covering `*.workers.dev`** (`NO_PROXY` preserving `127.0.0.1,localhost,::1`); binding an Active Zone Custom Domain enables proxy-free direct connection in Mainland China.
   - **Contrast with Option 1 & Option 3**: Option 1 default `*.srv.us` needs only OS `ssh` + outbound TCP `22` (proxy-free on typical Mainland home broadband; its `4`s fallback `*.trycloudflare.com` and Option 3 `--mode cloudflare_token` both require `cloudflared`, auto-downloaded from GitHub Releases or `COSMOS_CLOUDFLARED_MIRROR` into `bin/` if absent, where `*.trycloudflare.com` changes URL on reboot, has no SLA, `ha-connections:1` `4–21s` `530`/`1033` gaps, and `200` concurrency limit, while `cloudflare_token` requires Zero Trust forwarding to `http://127.0.0.1:8096` and turning off `Bot Fight Mode`); Option 3 `24h Self-Hosted Cloud Server Hub` (`vps_hub` / `vps`) requires only a Linux server with ports `80`/`443` + local `ssh`, with zero Cloudflare dependency, zero daily cap, zero `125s` timeout, and proxy-free direct connectivity on Mainland/HK/SG servers.

## 5. 4-Tier Security Permissions & Parent Read-Only Layering

In the left column "Open Workspace Directories" card on the local console home page, users can adjust open folders and permission tiers live (takes effect immediately, no restart required):

1. **4 Security Tiers**:
   - **`Read-Only` (`L1`)**: Allows reading files, searching code, and inspecting built-in skills only; blocks all file writes and command execution. The top-right bar also provides a `One-Click Read-Only` emergency button.
   - **`Edit-Only` (`L2`)**: Allows reading and editing code plus `.docx`/`.xlsx` files inside writable workspaces; blocks terminal commands, Python scripts, and peripheral packs.
   - **`Workspace Dev` (`L3`, Recommended Default)**: Allows reading/writing files, moving files to recoverable trash, and running windowless commands/Python inside open writable workspaces; read-only reference directories remain strictly read-only.
   - **`Full-Disk Dev` (`L4`)**: Allows reading, writing, and running commands across any path on the machine while keeping sensitive credential directories isolated and preserving pre-edit snapshots and recoverable trash.
2. **Adding Directories & Parent Read-Only / Child Writable Layering**:
   - Click `Pick Folder` (or paste a path and click `Add`) to add a workspace directory.
   - To let the AI reference an entire monorepo while restricting edits to a single subfolder, check `Add as Read-Only Reference Directory` and add the outer parent folder first, then uncheck it and add the inner subproject folder. Permissions resolve automatically by longest path prefix.
   - Every file edit and cleanup action can be restored from the right column `Live Activity & Undo` (`Edit Undo` with diff preview and `Trash Bin`).

## 6. Asking Connected `@Cosmos` to Open Settings Pages Directly

Once initial binding is done, users no longer need to hunt through menus—they can simply ask `@Cosmos` in chat:
- `@Cosmos open the gateway settings page on my computer and walk me through setting up a Cloudflare fixed URL`
- `@Cosmos open the tools & packs settings page so I can enable the managed browser and desktop window automation`
- `@Cosmos show me which folders are currently open and what security tier is active`

The connected AI will use these built-in helpers:
- `pc_get_status(guide="cloudflare"|"gateways"|"permissions"|"gemini_chatgpt"|"packs_and_skills"|"troubleshooting"|"all", open_page="gateways"|"studio"|"runtime"|"tools"|"skills"|"tutorials")` to open the exact local console page in the user's browser and read live status;
- `pc_skill_hub(action="load", skill="webai2pc-setup-tutorial")` (also available under `L1` Read-Only and `/mcp/readonly`) to load the complete built-in UI button reference tutorial.

## 7. Quick Troubleshooting Reference

1. **Double-clicking the Windows startup script does nothing or reports missing files**:
   - 90% of the time, the script was double-clicked directly inside WinRAR / 7-Zip / Windows ZIP preview. Extract the entire `.zip` to a normal Desktop folder first, then double-click `一键启动_Cosmos_MCP.bat`. On PCs without Python, download `win64-full.zip`.
2. **Authorization page on `*.workers.dev` fails to open or background WSS repeatedly times out in Mainland China**:
   - In Mainland China, `*.workers.dev` suffers full DNS pollution across carrier and public DNS (`100%` unproxied timeout). Without a custom domain, **keep your local HTTP/HTTPS proxy continuously open while running, with routing rules covering `*.workers.dev`** (if rule mode misses `*.workers.dev` during initial `/consent` login, you may temporarily switch to Global mode to approve, **but daily background runtime still requires proxy rules covering `*.workers.dev`**; also keep `127.0.0.1,localhost,::1` in `NO_PROXY` if set). For proxy-free direct connectivity in Mainland China, bind an Active Zone Custom Domain on Card 2 (with `Bot Fight Mode` off), or use Card 1 `*.srv.us` / Card 3 self-hosted server.
3. **One-click approve does not appear, or the consent page asks for a code/passphrase**:
   - This happens when using `Take over` in Web ChatGPT `Work` mode's cloud browser, binding from a phone/remote device, or when a browser privacy extension blocks the `127.0.0.1` loopback redirect. Expand `Pairing & Active Sessions` on the local console home page and enter the live 6-digit dynamic pairing code (or the 20-character fallback passphrase).
4. **Personal ChatGPT Plus / Pro write tools are restricted on `/mcp`**:
   - When OpenAI platform policy limits personal subscriptions to `read/fetch` tools on custom connectors, switch the console top selector to `Web ChatGPT` and click `Copy Read-Only` (or the read-only `Copy Request for Work Mode Auto-Connect` button) to bind `https://<domain>/mcp/readonly`.
5. **Gemini pops up a confirmation card for every tool call**:
   - Go to `Personal Intelligence -> Connected Apps -> Cosmos` (or directly at https://gemini.google.com/customize/connectors) in Gemini's left sidebar and set `App actions` to `Always allow`. Avoid approving individual tool cards in chat (which overrides connector-level auto-approval), and use built-in `pc_web_research` for web lookups inside `@Cosmos` sessions.
6. **Keeping the same fixed URL after migrating to a new PC or reinstalling OS**:
   - On the old PC, open `#settings/gateways` Card 1, click `Export Identity Recovery Card PNG`, and set a passphrase to save the image. On the new PC, click `Import Recovery Card PNG`, upload the image, and enter the passphrase to restore your original fixed URL without rebinding web connectors.
