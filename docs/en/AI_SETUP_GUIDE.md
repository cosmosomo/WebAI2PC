# WebAI2PC (Cosmos MCP) Public Setup Guide (Direct-Read Execution for AI Assistants & Local Agents)

> [简体中文](../AI_SETUP_GUIDE.md) · **English** · [Docs Home](README.md) · [README](../../README_EN.md)

This document uses a fixed filename so **Cursor, Claude Code, Codex, Windsurf, Trae, GitHub Copilot, Cline / Roo Code, Antigravity, Qoder, OpenCode, WorkBuddy, OpenClaw, Manus, Web Google Gemini, Web ChatGPT**, or any other AI assistant can read it directly to install, launch, and bind WebAI2PC:
- GitHub page URL: `https://github.com/cosmosomo/WebAI2PC/blob/main/docs/en/AI_SETUP_GUIDE.md`
- Raw plain-text URL: `https://raw.githubusercontent.com/cosmosomo/WebAI2PC/main/docs/en/AI_SETUP_GUIDE.md`
- Chinese version: `https://github.com/cosmosomo/WebAI2PC/blob/main/docs/AI_SETUP_GUIDE.md`

## 1. Execution Split for the Current AI Assistant / Agent (Check Whether You Have Local Shell Access)

### Mode A: You Have Local File & Terminal Execution Access (Cursor, Claude Code, Codex, Windsurf, Trae, Cline / Roo Code, WorkBuddy, OpenClaw, OpenCode, etc.)
Perform the local source checkout, background launch, and health check directly for the user so they only need 2 final clicks in the browser:
1. **Use Source Installation as the Primary Single Source of Truth (`main`)**: Detect the OS (Windows / macOS / Linux), `git`, and Python `3.10+`:
   - **Primary (Recommended)**: Run `git clone https://github.com/cosmosomo/WebAI2PC.git <target_dir>` (e.g., `D:\WebAI2PC` or `~/WebAI2PC`; if already cloned, run `git pull --ff-only` to stay synced with `main`).
   - **If `git` is absent**: Download the `main` source archive `https://github.com/cosmosomo/WebAI2PC/archive/refs/heads/main.zip` and extract it completely into a regular folder.
   - **Fallback ONLY when a target Windows machine lacks both Python and Git and cannot install them**: Download the offline bundle `*win64-full.zip` (with embedded Python 3.12) from `https://github.com/cosmosomo/WebAI2PC/releases`.
2. **Launch in the Background & Verify Readiness**:
   - **Windows**: Run `一键启动_Cosmos_MCP.bat` in the background inside the repo folder (creates `.venv` and installs dependencies automatically or reuses existing Python).
   - **macOS / Linux**: Run `chmod +x start_cosmos_mcp.sh && ./start_cosmos_mcp.sh`.
   - Poll `http://127.0.0.1:8096/healthz` until ready, then read the generated public `/mcp` (and `/mcp/readonly`) HTTPS URL for the user.
3. **Strict Security Boundaries**:
   - **Never** print the user's 6-digit pairing code, 20-char fallback passphrase, local admin token, or Cloudflare API token in chat logs;
   - Web account sign-in and clicking "One-Click Local Approve" on `/consent` **must be confirmed by the user personally**.
4. **Hand Off the Final Step**: Give the user their `https://<domain>/mcp` URL, **explicitly remind them NOT to paste `/mcp` directly into the browser address bar**, and walk them through Section 3 to bind Web Gemini (`https://gemini.google.com/customize/connectors`) or Web ChatGPT (`Work` mode `@Plugin Creator` standard OAuth 2.1).

### Mode B: You Are a Chat-Only Web AI (No Local Shell Access, e.g., Web Gemini, Web ChatGPT `Chat` Mode)
Follow these step-by-step co-setup rules:
1. **Clarify 3 Basics First**: If not yet stated, ask briefly: (1) OS (Windows, macOS, or Linux); (2) whether `git` / Python `3.10+` is installed or the repo is already cloned; (3) whether they are connecting Web Gemini or Web ChatGPT (Workspace Team/Business/Enterprise/Edu vs. Personal Plus/Pro).
2. **Teach One Step at a Time**: Give only 3 to 5 lines of concrete actions and exact button names for the current step, and wait for the user's confirmation before proceeding.
3. **Take Over Directly Once the Connector Is Bound**: Once bound (e.g., named `@WebAI2PC` or `@Cosmos`), tell the user they can say: `@<your-connector-name> open the gateway settings page on my computer and walk me through setting up a Cloudflare fixed URL`. The connected AI can call `pc_get_status` to open the local settings page directly.

## 2. Source Checkout & Launching the Local Console (`git clone` Primary · Offline ZIP Fallback)

1. **Primary Method: Clone Latest Source from GitHub (Recommended SSOT)**:
   - **With `git` and Python `3.10–3.14` installed (Windows / macOS / Linux)**:
     ```bash
     git clone https://github.com/cosmosomo/WebAI2PC.git
     ```
     (If already cloned, run `git pull --ff-only`.)
   - **Without `git` (Python `3.10+` installed)**: Download `https://github.com/cosmosomo/WebAI2PC/archive/refs/heads/main.zip` and extract it completely into a regular folder (the launcher auto-detects official Python, Conda, or `uv` and skips Windows Store stubs).
2. **Fallback Option: Offline Portable ZIP When Windows Lacks Python/Git and Cannot Install Them**:
   - **Only when a target Windows PC has neither Python nor Git and cannot install them**, download `*win64-full.zip` (includes portable Python 3.12) from `https://github.com/cosmosomo/WebAI2PC/releases` and **extract the entire archive to a normal folder first** (never double-click inside WinRAR / 7-Zip / Explorer ZIP preview).
3. **Launch the Local Console**:
   - **Windows**: Open the repo or extracted folder and double-click `一键启动_Cosmos_MCP.bat`.
   - **macOS / Linux**: Open a terminal in the folder and run `chmod +x start_cosmos_mcp.sh && ./start_cosmos_mcp.sh`.
   - The server starts silently in the background with zero terminal popups and opens `http://127.0.0.1:8096/` (`WebAI2PC · 本地控制台`).

## 3. First-Time Registration-Free Connection to Web Gemini / ChatGPT (3 Steps)

No third-party account registration is needed for your first test connection:

1. **Step 1: Copy the Connection URL or 1-Click Setup Prompt from the Local Console**
   - By default, Option 1 ("One-Click Login-Free Direct Connect") is active: it connects first to the login-free fixed URL `https://*.srv.us/mcp` (`10s` startup wait budget, unchanged across reboots) and provides an independent backup toggle inside the card for `https://*.trycloudflare.com/mcp` (can stay online alongside `srv.us`, or serve as backup if outbound port `22` is blocked).
   - For **Web Gemini**: Keep `网页版 Gemini` (`Web Gemini`) selected at the top and click `复制连接地址` (`Copy Connection URL`).
   - For **Web ChatGPT**: Switch the top selector to `网页版 ChatGPT` (`Web ChatGPT`; buttons unlock once the public gateway is ready). Click **`复制一键配置提示词（发给 Work）` (Copy 1-Click Setup Prompt for Work)** for Team / Business / Enterprise / Edu workspaces (`/mcp`), or **`复制只读配置提示词（发给 Work）` (Copy Read-Only Setup Prompt for Work)** for Personal Plus / Pro read-only accounts (`/mcp/readonly`), or click `仅复制地址` (`Copy URL Only`).
2. **Step 2: Add the Connector in the Web Client & Approve OAuth 2.1**
   - **Web Gemini (requires 18+ Google AI Pro / Ultra or enabled Workspace account)**:
     1. Open [Gemini Connectors](https://gemini.google.com/customize/connectors) directly (or bottom-left menu -> `Personal Intelligence` -> `Connected Apps`, then click top-right `+ Custom`), paste `https://<domain>/mcp` into **`MCP Server URL`** (leave `Additional settings` collapsed, and **never open `/mcp` directly in the browser address bar**), and click `Next`.
     2. In the browser on the same PC, click **`本机一键允许连接` (`One-Click Local Approve`)** to finish binding.
     3. Return to `https://gemini.google.com/customize/connectors`, open your newly added connector, and set **`App actions` to `Always allow`** (also click `复制 AI 守则` in the local console and save it into Gemini `Skills`).
   - **Web ChatGPT (`Work` Mode `@Plugin Creator` Standard OAuth 2.1)**:
     1. **Send the 1-Click Prompt in `Work` Mode**: Switch to **`Work` mode** at the top of Web ChatGPT, paste the copied setup prompt, and send it so `@Plugin Creator` connects directly to `/mcp` or `/mcp/readonly` via standard OAuth 2.1 metadata and installs `WebAI2PC` (no manual Client ID / Secret or external relay service is needed; if your workspace admin restricts external custom MCP servers, ask the admin to enable custom MCP access).
     2. **Approve `/consent`**: When the OAuth consent page opens in your same-machine browser, it hits the `127.0.0.1` loopback and lets you click **`本机一键允许连接` (`One-Click Local Approve`)** directly. If you click `Take over` inside Web `Work` mode's cloud browser to open `/consent`, expand `配对与已连会话` (`Pairing & Active Sessions`) on the local console home page and enter the live `6`-digit dynamic pairing code, then click `Return control`.
3. **Step 3: First-Message Wake-Up & Verify with `pc_get_status`**
   - **Web Gemini**: Start a new chat (Task Mode recommended), type `@<your-connector-name>` (e.g., `@WebAI2PC` or `@Cosmos`), select the popped-up connector chip, and send: `@WebAI2PC call pc_get_status and check what files are in my current workspace`. The same-account Gemini mobile app syncs the connector automatically.
   - **Web ChatGPT (Use `Chat` Daily to Save Quota, `Work` for Long Tasks)**: Once installed, the connector is shared across your account. For daily local coding, Office edits, and running windowless commands/tests, switch back to **`Chat` mode** and invoke `@<your-connector-name>` (default `@WebAI2PC` — fast, uses normal chat limits, zero `Work / Codex` agent quota usage). Switch to **`Work` mode** when combining the cloud browser, cross-app deliverables (email/Slack/Drive), or `Scheduled Tasks`. A successful `pc_get_status` (`get_status`) call returning local status and directories confirms setup is complete. Save the operating rules into native `Skills` (Workspace/Desktop) or `Project Instructions` / Custom Instructions (Web `Chat` and `Work`).

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
   - **Contrast with Option 1 & Option 3**: Option 1 primary `*.srv.us` needs only OS `ssh` + outbound TCP `22` (`10s` startup wait budget, proxy-free on typical Mainland home broadband); its independent backup `*.trycloudflare.com` toggle and Option 3 `--mode cloudflare_token` both require `cloudflared`, auto-downloaded from GitHub Releases or `COSMOS_CLOUDFLARED_MIRROR` into `bin/` if absent (where `*.trycloudflare.com` changes URL on reboot, has no SLA, `ha-connections:1` `4–21s` `530`/`1033` gaps, and `200` concurrency limit, while `cloudflare_token` requires Zero Trust forwarding to `http://127.0.0.1:8096` and turning off `Bot Fight Mode`); Option 3 `24h Self-Hosted Cloud Server Hub` (`vps_hub` / `vps`) requires only a Linux server with ports `80`/`443` + local `ssh`, with zero Cloudflare dependency, zero daily cap, zero `125s` timeout, and proxy-free direct connectivity on Mainland/HK/SG servers.

## 5. 4-Tier Security Permissions & Parent Read-Only Layering

In the left column "Open Workspace Directories" card on the local console home page, users can adjust open folders and permission tiers live (takes effect immediately, no restart required):

1. **4 Security Tiers**:
   - **`Read-Only` (`L1`)**: Allows reading files, searching code, and inspecting built-in skills only; blocks all file writes and command execution. Switch to Read-Only anytime from the home page's `Current Permissions` 4-tier bar or the system tray right-click menu.
   - **`Edit-Only` (`L2`)**: Allows reading and editing code plus `.docx`/`.xlsx` files inside writable workspaces; blocks terminal commands, Python scripts, and peripheral packs.
   - **`Workspace Dev` (`L3`, Recommended Default)**: Allows reading/writing files, moving files to recoverable trash, and running windowless commands/Python inside open writable workspaces; read-only reference directories remain strictly read-only.
   - **`Full-Disk Dev` (`L4`)**: Allows reading, writing, and running commands across any path on the machine while keeping sensitive credential directories isolated and preserving pre-edit snapshots and recoverable trash.
2. **Adding Directories & Parent Read-Only / Child Writable Layering**:
   - Click `Pick Folder` (or paste a path and click `Add`) to add a workspace directory.
   - To let the AI reference an entire monorepo while restricting edits to a single subfolder, check `Add as Read-Only Reference Directory` and add the outer parent folder first, then uncheck it and add the inner subproject folder. Permissions resolve automatically by longest path prefix.
   - Every file edit and cleanup action can be restored from the right column `Live Activity & Undo` (`Edit Undo` with diff preview and `Trash Bin`).

## 6. Asking Your Connected AI to Open Settings Pages Directly

Once initial binding is done, users no longer need to hunt through menus: invoke `@<your-connector-name>` (e.g., `@WebAI2PC` or `@Cosmos`) directly in chat:
- `@WebAI2PC open the gateway settings page on my computer and walk me through setting up a Cloudflare fixed URL`
- `@WebAI2PC open the tools & packs settings page so I can enable the managed browser and desktop window automation`
- `@WebAI2PC show me which folders are currently open and what security tier is active`

The connected AI will use these built-in helpers:
- `pc_get_status(guide="cloudflare"|"gateways"|"permissions"|"gemini_chatgpt"|"packs_and_skills"|"troubleshooting"|"all", open_page="gateways"|"studio"|"runtime"|"tools"|"skills"|"tutorials")` to open the exact local console page in the user's browser and read live status;
- `pc_skill_hub(action="load", skill="webai2pc-setup-tutorial")` (also available under `L1` Read-Only and `/mcp/readonly`) to load the complete built-in UI button reference tutorial.

## 7. Quick Troubleshooting Reference

1. **Double-clicking the Windows startup script does nothing or reports missing files**:
   - Most commonly, the script was double-clicked inside WinRAR / 7-Zip / Windows ZIP preview. Prefer cloning from source via `git clone https://github.com/cosmosomo/WebAI2PC.git` and running `一键启动_Cosmos_MCP.bat` inside the cloned folder; if using a `.zip` archive, extract the entire archive to a normal folder first (use `*win64-full.zip` only as a fallback when the target Windows machine lacks Python and cannot install it).
2. **Authorization page on `*.workers.dev` fails to open or background WSS repeatedly times out in Mainland China**:
   - In Mainland China, `*.workers.dev` suffers full DNS pollution across carrier and public DNS (`100%` unproxied timeout). Without a custom domain, **keep your local HTTP/HTTPS proxy continuously open while running, with routing rules covering `*.workers.dev`** (if rule mode misses `*.workers.dev` during initial `/consent` login, you may temporarily switch to Global mode to approve, **but daily background runtime still requires proxy rules covering `*.workers.dev`**; also keep `127.0.0.1,localhost,::1` in `NO_PROXY` if set). For proxy-free direct connectivity in Mainland China, bind an Active Zone Custom Domain on Card 2 (with `Bot Fight Mode` off), or use Card 1 `*.srv.us` / Card 3 self-hosted server.
3. **One-click approve does not appear, or the consent page asks for a code/passphrase**:
   - This happens when using `Take over` in Web ChatGPT `Work` mode's cloud browser, binding from a phone/remote device, or when a browser privacy extension blocks the `127.0.0.1` loopback redirect. Expand `Pairing & Active Sessions` on the local console home page and enter the live 6-digit dynamic pairing code (or the 20-character fallback passphrase).
4. **Personal ChatGPT Plus / Pro write tools are restricted on `/mcp`**:
   - When OpenAI platform policy limits personal subscriptions to `read/fetch` tools on custom connectors, switch the console top selector to `Web ChatGPT` and click `复制只读配置提示词（发给 Work）` (`Copy Read-Only Setup Prompt for Work`) or copy `https://<domain>/mcp/readonly` to connect in read-only mode.
5. **Gemini pops up a confirmation card for every tool call**:
   - Open https://gemini.google.com/customize/connectors (or `Personal Intelligence -> Connected Apps` in Gemini's bottom-left menu), open your connector, and set `App actions` to `Always allow`. Avoid approving individual tool cards in chat (which overrides connector-level auto-approval), and use built-in `pc_web_research` for web lookups inside active connector sessions.
6. **Keeping the same fixed URL after migrating to a new PC or reinstalling OS**:
   - On the old PC, open `#settings/gateways` Card 1, click `Export Identity Recovery Card PNG`, and set a passphrase to save the image. On the new PC, click `Import Recovery Card PNG`, upload the image, and enter the passphrase to restore your original fixed URL without rebinding web connectors.
