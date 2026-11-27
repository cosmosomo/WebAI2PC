# 04. Gateway Selection & Network Troubleshooting Guide

> [简体中文](../04_三大连接通道选型与网络排障手册.md) · **English** · [Docs Home](README.md) · [README](../../README_EN.md)

Web Google Gemini and Web ChatGPT run in cloud data centers and must reach your local server over a standard HTTPS `443` endpoint with a valid TLS certificate. This guide compares the 3 built-in connection gateways in Cosmos MCP (`v1.2.1`), walks through step-by-step setup for a free Cloudflare SQLite Durable Object fixed gateway and a self-hosted 24-hour Linux VPS hub, and provides a troubleshooting checklist for Windows proxy environment variables, port restrictions, Cloudflare WAF challenges, and sleep/wake reconnection.

## 1. Side-by-Side Comparison & Selection Matrix

On the "Overview & Web Connection" page of the local `Cosmos Studio` console (`http://127.0.0.1:8096`), **all three gateway cards have independent toggles and can stay online simultaneously (for example, running `srv.us` and `Cloudflare Workers` side by side without interrupting each other)**. When multiple gateways are active, every ready domain is accepted by the local OAuth 2.1 allowlist and serves web requests concurrently. Click the gateway switcher bar at the top of the console or open `/tutorials` to switch which gateway URL is displayed and copied:

| Dimension | Option 1: One-Click Instant Start (Default) | Option 2: Free Cloudflare Account Fixed Gateway | Option 3: Self-Hosted Server & Custom Domain |
| :- | :- | :- | :- |
| **Gateway Implementation** | Prioritizes a persistent local Ed25519 key to connect to `https://xxxxx.srv.us/mcp` (`10`-second startup wait budget); Card 1 includes an independent backup toggle to run `https://*.trycloudflare.com/mcp` (`--mode cloudflare`) concurrently or when outbound port `22` is blocked | Automatically deploys a free `Workers + SQLite Durable Object` hibernation relay under your own Cloudflare account (`https://your-worker.your-subdomain.workers.dev/mcp` or a custom domain on the same account) | One-click SSH deployment of an always-on `24`-hour hub (`vps_hub` / `vps`) on your own Linux cloud server with your local PC attached as a child node, or `Cloudflare Named Tunnel` (`--mode cloudflare_token`) / self-hosted reverse-proxy domain |
| **Prerequisites** | Zero account registration, zero cloud setup, double-click to connect | A free Cloudflare account (supports Google sign-in) and one-time copy-paste of a prefilled least-privilege API token (shredded locally right after deploy) | `24h` hub requires a Linux server with ports `80`/`443` open; `Cloudflare Named Tunnel` requires a Cloudflare Zero Trust account, an Active Zone domain, and a Public Hostname route pointing to `http://127.0.0.1:8096` |
| **Local Component Dependencies** | Primary `*.srv.us` uses only the OS built-in OpenSSH (`ssh`) client and outbound TCP port `22`; backup `*.trycloudflare.com` requires the official `cloudflared` binary (if absent from `PATH`, auto-downloaded with SHA-256 verification on first use from [GitHub Releases](https://github.com/cloudflare/cloudflared/releases/latest) or `COSMOS_CLOUDFLARED_MIRROR` HTTPS mirror into state `bin/`, or specified via `COSMOS_CLOUDFLARED_BIN`) | Pure Python standard library `443 WSS` client, **zero external binary dependencies** (no `Node.js`, `wrangler`, or `cloudflared` needed) | `24h` hub (`vps_hub` / `vps`) requires only your local `ssh` client with zero Cloudflare dependency; `Cloudflare Named Tunnel` (`--mode cloudflare_token`) requires the official `cloudflared` binary (same auto-download or `COSMOS_CLOUDFLARED_MIRROR` support) |
| **Network & Proxy Requirements (incl. Mainland China)** | Primary `*.srv.us` typically connects **directly without a proxy** on Mainland China home broadband; if port `22` is blocked and backup `*.trycloudflare.com` is enabled, turn on a system proxy, set `COSMOS_CLOUDFLARED_MIRROR`, or pre-install `cloudflared` when unproxied GitHub downloads are slow, and keep an HTTP proxy enabled on high-loss cross-border links | **Mainland China default `*.workers.dev` strictly requires a continuously open local proxy**: `*.workers.dev` suffers full DNS pollution in Mainland China (`100%` unproxied timeout). Without a custom domain, keep your local HTTP/HTTPS proxy (Clash / Mihomo / v2rayN, or `HTTPS_PROXY` / `WSS_PROXY`) continuously open with rules covering `*.workers.dev` (browser `/consent` login also needs proxying `*.workers.dev`; keep `127.0.0.1,localhost,::1` in `NO_PROXY`). **Mainland proxy-free option**: bind an Active Zone Custom Domain on the same Cloudflare account | Self-hosted Mainland China (with ICP-filed domain) or HK/SG Linux servers connect **100% directly without a proxy**; for `Cloudflare Named Tunnel` custom domains, turn off `Bot Fight Mode` and skip WAF managed challenges on `/mcp*` and OAuth paths |
| **Fixed URL Across Reboots** | `*.srv.us` stays fixed across shutdowns and reboots; backup `*.trycloudflare.com` changes its URL on every restart | Permanently fixed (no need to update the web connector URL after reboots, sleep/wake, or switching to a phone hotspot) | Permanently fixed |
| **Free Quota & Stability Boundaries** | `*.srv.us` is free without signup (`10`s startup wait budget); backup `*.trycloudflare.com` per [Cloudflare Quick Tunnels Docs](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/) has no uptime SLA, single control stream (`ha-connections:1`) with `4–21`s reconnect gaps (HTTP `530`/`1033`), `200` max concurrent requests, and `125`s edge read timeout | Runs on [Cloudflare Workers Free](https://developers.cloudflare.com/workers/platform/limits/) (`100,000` requests/day cap, returning Error `1027` when exceeded; SQLite Durable Object hibernates when idle at `$0`) and [Cloudflare Error 524](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors/error-524/) default `125`s edge read timeout | Self-hosted `24h` VPS hub has **zero daily request cap and zero `125`s edge read timeout**; `Cloudflare Named Tunnel` is free but subject to the default `125`s Cloudflare edge read timeout |
| **Behavior When Local PC Is Off** | Unreachable while off; restores automatically after boot | Gateway reports the local node offline; reconnects automatically in ~`1.5` seconds after boot | The `24`-hour cloud hub remains online for server directories; paths targeting an offline local PC return structured `ERR_NODE_OFFLINE` |
| **Best For** | First-time trial and quick verification of web connector binding | Long-term daily development and remote mobile control without owning a VPS or domain | Users with a Linux VPS who want `24`-hour availability and single-connector management across a server and multiple PCs |

## 2. Option 2 Walkthrough: Deploying a Free Cloudflare SQLite Durable Object Fixed Gateway

Option 2 deploys end-to-end using only the Python standard library against the Cloudflare REST API—no Node.js or `wrangler` CLI is required on your machine.

### Step 1: Create a Least-Privilege API Token Using the Prefilled Template

1. Open the local console at `http://127.0.0.1:8096` and expand **Option 2: Free Cloudflare Account Fixed Gateway** on the "Overview & Web Connection" page.
2. Click **"Open Prefilled Cloudflare Token Page"** and sign in to your Cloudflare account (first-time users can sign up and sign in directly with Google).
3. The page comes prefilled with only the `4` least-privilege permissions required for `Cosmos-MCP-Gateway`—never use your Global API Key:
   - `Account -> Workers Scripts: Edit` (uploads and updates the relay Worker and Durable Object script)
   - `Account -> Account Settings: Read` (reads the account ID and `workers.dev` subdomain status)
   - `Zone -> Zone: Read` and `Zone -> Workers Routes: Edit` (used only when you enter a custom domain on the same account to look up the zone and bind the route)
4. Click `Continue to summary -> Create Token` at the bottom of the page and copy the generated API token string.

### Step 2: 3-Second Auto-Deploy & Immediate Token Shredding

1. Return to the Option 2 card in the local console, paste the API token into the token field (leave the custom domain field empty if you are not binding one yet), and click the one-click deploy button.
2. Within roughly `3` seconds, the backend automatically executes four steps:
   - Queries the Cloudflare Account ID associated with the token;
   - Checks whether a `*.workers.dev` subdomain is enabled on the account and claims one automatically if needed;
   - Generates a deterministic script name `cosmos-mcp-<node_id>` from your local node prefix and uploads the embedded `CosmosRelayDO` module (using a SQLite Hibernation Durable Object and a `17`-byte binary multiplexing frame protocol supporting `32 MiB` streaming request chunks and a `9`-second network-switch replay buffer);
   - Enables the subdomain route and establishes a persistent outbound `443 WSS` connection from your local machine.
3. **One-Time Token Shredding & Independent Toggle**: Once the gateway is deployed and the fixed URL is saved, the system immediately calls `shred_cloudflare_api_token` to overwrite the temporary token with zero bytes, flush to disk (`fsync`), and truncate-remove it—leaving zero plaintext Cloudflare API token on disk. Afterward, you can start or stop this gateway anytime using the toggle at the top-right of the card (no need to re-enter the token), and run it concurrently with Option 1 or Option 3.
4. **Back Up Your Identity Recovery Card (Optional)**: After deployment, you can export an encrypted PNG Identity Recovery Card from the console. When reinstalling your OS or migrating to a new PC, import that PNG image with your local passphrase to restore the same gateway identity.

### Step 3: Mainland China `*.workers.dev` Continuous Proxy Requirement vs. Custom Domain Proxy-Free Setup

Across Mainland China carrier and public DNS resolvers, default `*.workers.dev` domains experience full DNS pollution (unproxied direct connections time out `100%` of the time). Choose one of the two operating modes below:

- **Mode A (Using default `*.workers.dev` without a custom domain)**:
  1. **Keep your local proxy continuously open during runtime**: Keep your system HTTP/HTTPS proxy (such as Clash, Mihomo, or v2rayN, or environment variables `HTTPS_PROXY` / `WSS_PROXY`) active at all times while Cosmos MCP is running, with routing rules covering `*.workers.dev` so the background `443 WSS` tunnel to Cloudflare's edge stays alive.
  2. **Route browser `/consent` authorization via proxy too**: During first-time `/consent` authorization, your browser must also access `*.workers.dev` through the proxy (if rule-based routing misses `*.workers.dev`, you can temporarily switch to Global mode to finish initial authorization, **but daily background operation still requires your proxy rules to cover `*.workers.dev`**—closing the proxy or setting `*.workers.dev` to `DIRECT` drops the background WSS tunnel). If `NO_PROXY` is set, make sure it preserves `127.0.0.1,localhost,::1`.
- **Mode B (Proxy-free direct connection in Mainland China: bind an Active Zone Custom Domain)**:
  1. Add a domain you own (or a free subdomain delegated to Cloudflare) to the same Cloudflare account as an Active Zone.
  2. During Option 2 deployment, enter a subdomain in the "Custom Domain" field (for example, `mcp.example.com`; no manual A or CNAME record is needed beforehand). Clicking deploy binds the domain via `Workers Domains` and issues an edge HTTPS certificate automatically so Mainland China networks connect directly without `workers.dev` DNS pollution (alternatively, use Option 1 default `*.srv.us` or Option 3 self-hosted server).
  3. If you already deployed `*.workers.dev` and the API token has been shredded, open `Workers & Pages -> cosmos-mcp-<node_id> -> Settings -> Domains & Routes` in the Cloudflare dashboard to add a `Custom Domain` manually, then save that domain in the local console (both domains remain trusted; disable `Bot Fight Mode` on custom domains per Section 4.3).

## 3. Option 3 Walkthrough: One-Click 24h Cloud Server Hub & Multi-Device Networking

### 1. One-Click SSH Deployment of a 24-Hour Cloud Hub

1. **Verify Server Prerequisites**: Prepare a mainstream Linux cloud server (such as Debian or Ubuntu) and allow inbound TCP ports `80` and `443` in your cloud provider's security group (overseas and HK/MO/TW servers can issue public IP certificates without a domain; mainland China servers require an ICP-filed domain pointing to that IP due to carrier compliance gateways).
2. **Fill In Parameters & Deploy (SSH Password or Keyless Login)**: Expand **Option 3: Self-Hosted Server & Custom Domain** in the local console, enter the server's public IP, SSH port (default `22`), and username (e.g., `root` or a `sudo`-capable user). Provide either an SSH password (kept in memory for the single session only, never saved to disk), a local SSH private key path (such as `~/.ssh/id_ed25519`), or check "Use default local SSH key for passwordless login". If you have a domain, enter `mcp.example.com` in the domain field and click deploy.
3. **Automated Backend Initialization**: The local launcher connects via windowless `SSH_ASKPASS` (no plaintext echo), checks physical RAM (automatically creating a swap file on lightweight hosts with `< 256MB` RAM to prevent OOM), verifies port `80`/`443` reachability, configures the HTTPS reverse proxy and certificates (persisting the certificate directory to avoid CA weekly rate limits), starts the always-on `24`-hour Cosmos MCP hub, and attaches your local PC as a remote child node over outbound `443 WSS`.

### 2. Binding a Cloudflare Named Tunnel or Self-Hosted Reverse-Proxy Domain

If you already have a Cloudflare Zero Trust Named Tunnel token (`--tunnel-token`) or a self-hosted reverse proxy on your router/server, switch to the Fixed Domain sub-option in Option 3 to save it, or start it from the CLI with login autostart enabled. Before enabling `Cloudflare Named Tunnel` (`--mode cloudflare_token`), verify these prerequisites:

- **Local `cloudflared` binary dependency**: If `cloudflared` is not installed in `PATH` (and `COSMOS_CLOUDFLARED_BIN` is unset), first launch automatically downloads and SHA-256 verifies it from [GitHub Releases](https://github.com/cloudflare/cloudflared/releases/latest) or your `COSMOS_CLOUDFLARED_MIRROR` HTTPS mirror into state `bin/`. On unproxied Mainland China networks where GitHub is slow, enable your system proxy, set `COSMOS_CLOUDFLARED_MIRROR`, or pre-install `cloudflared`.
- **Zero Trust Public Hostname & WAF bypass**: Requires a Cloudflare Zero Trust account, an Active Zone domain, and a Public Hostname route in `Networks -> Tunnels` forwarding to `http://127.0.0.1:8096`, plus disabling `Bot Fight Mode` and skipping WAF managed challenges on `/mcp*` and OAuth endpoints (see Section 4.3).

```bash
# Bind a fixed domain with a Cloudflare Named Tunnel token and enable autostart
cosmos-mcp start --mode cloudflare_token --tunnel-token <PASTE_YOUR_TOKEN> --public-url https://mcp.example.com --autostart

# Connect to a self-hosted reverse-proxy domain via existing VPS SSH reverse port forwarding
cosmos-mcp start --mode vps --vps-ssh ubuntu@203.0.113.10 --vps-remote-port 18096 --public-url https://mcp.example.com --autostart
```

### 3. Multi-Device Networking: Independent `tool_prefix` vs `target="auto"` Routing

When managing multiple PCs and servers at once, choose one of the two architectures below:

1. **Multiple Connectors with Independent `tool_prefix` (for multiple PCs each online via Option 1 or Option 2)**:
   - A single PC can keep the default `pc`. When running multiple devices simultaneously, save the tool prefix as `desk` on your main desktop in the console's "Tools & Security" page (or launch with `--tool-prefix desk`), and `laptop` on your laptop (or `--tool-prefix laptop`; note that `--prefix` isolates configuration slots when running multiple instances on the same PC).
   - Add two connectors—`Cosmos-Desk` and `Cosmos-Laptop`—in Web Gemini or Web ChatGPT.
   - Address each machine directly within the same chat, such as running data processing on your desktop via `desk_run_python` while updating a report on your laptop via `laptop_edit_file`. After hot-changing a prefix in the console, older prefix names already loaded in an active chat continue to route cleanly.
2. **Single-Entry `target="auto"` Routing (for an Option 3 24-hour Cloud Hub with attached local PCs)**:
   - Bind only **one connector** (`https://<hub-domain>/mcp`) in the web client. The tool list stays compact at `16` core tools instead of multiplying the tool schema for every attached device.
   - All `16` tools accept an optional `target="auto"` routing parameter: server workspace paths such as `/srv/api` or `~/projects/demo` execute locally on the cloud hub, while local PC workspace paths such as `D:\Work\my-project` are forwarded over the WSS multiplexing channel to the matching PC before path preflight (you can also explicitly pass `target="server"`, `target="local"`, or a node alias).
   - If your local PC is powered off or offline, the cloud hub stays online `24` hours a day for server tasks and returns `ERR_NODE_OFFLINE` within seconds for calls targeting the offline PC without dropping the web MCP session.

## 4. Real-World Network & Connection Troubleshooting Checklist

### 1. Mainland China `*.workers.dev` Continuous Proxy, `NO_PROXY` & `cloudflared` Mirror Settings

When running local proxy software such as Clash, Mihomo, or v2rayN (commonly listening on `127.0.0.1:7897`) or using Cloudflare channels in Mainland China, verify these three settings:

- **Default `*.workers.dev` Continuous Proxy Requirement & Liveness Probing**: Because `*.workers.dev` suffers full DNS pollution in Mainland China (`100%` unproxied timeout), using `*.workers.dev` without a custom domain requires keeping your local HTTP/HTTPS proxy open continuously with rules covering `*.workers.dev`. The outbound `443 WSS` client reads `WSS_PROXY` -> `HTTPS_PROXY` -> `ALL_PROXY` -> OS proxy settings, polls proxy changes every `1.0` second, and reconnects within `2` seconds. If you quit your proxy app while system proxy or environment variables still point to an inactive `127.0.0.1:7897`, the console and Windows tray display **"Local proxy port is not responding; please check whether Clash or your proxy app has exited"**; restart the proxy app (when using `*.workers.dev`) or bind a Custom Domain / switch to `*.srv.us` before turning off the stale proxy switch.
- **`NO_PROXY` Positive & Negative Boundaries**:
  1. **Must include loopback addresses**: If `NO_PROXY` (or `no_proxy`) is set, ensure it includes `127.0.0.1,localhost,::1`. Without loopback exclusions, the `800ms` local loopback passwordless check for `http://127.0.0.1:8096` or `/consent` is diverted through the external proxy and falls back to manual passphrase entry.
  2. **Do not add public gateway domains to `NO_PROXY`**: When relying on a local proxy to reach Cloudflare, ensure `*`, `*.workers.dev`, and `*.trycloudflare.com` are not in `NO_PROXY`, preventing outbound tunnels from bypassing the proxy into polluted IPs.
- **First-Time `cloudflared` Download & `COSMOS_CLOUDFLARED_MIRROR`**: Option 1 fallback (`*.trycloudflare.com`) and Option 3 Named Tunnel (`--mode cloudflare_token`) require the official `cloudflared` binary (Option 2 `workers_dev` is pure Python and needs no `cloudflared`). If absent from `PATH`, it is auto-downloaded with SHA-256 verification from [GitHub Releases](https://github.com/cloudflare/cloudflared/releases/latest) into state `bin/` on first use; if unproxied GitHub downloads are slow in Mainland China, enable your system proxy, set `COSMOS_CLOUDFLARED_MIRROR` to a trusted HTTPS mirror prefix, or pre-install `cloudflared` (or point `COSMOS_CLOUDFLARED_BIN` to an existing binary).

### 2. Outbound Port `22` Blocked: Independent HTTPS `443` Backup Toggle & Quick Tunnel Limits

- **Symptom**: On university campuses, corporate intranets, or public hotspots, Option 1's primary `*.srv.us` login-free fixed URL does not connect within its `10`-second startup wait budget, or backup `*.trycloudflare.com` intermittently returns HTTP `530` / `1033`.
- **Cause & Fix**: `*.srv.us` relies on OS OpenSSH reverse tunneling (outbound TCP port `22`), which enterprise firewalls may block. Turn on the independent backup switch (`开启备用（可与 srv.us 同时在线）`) inside Option 1 to run the port `443` `*.trycloudflare.com` tunnel (it can also stay online concurrently alongside `srv.us`). Note that per [Cloudflare Quick Tunnels Docs](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/), Quick Tunnels change URLs on every restart, carry no uptime SLA, use a single control stream (`ha-connections:1`) with `4–21`s reconnect windows (returning HTTP `530`/`1033`), and cap concurrent in-flight requests at `200`; enable a local HTTP proxy on lossy cross-border links, or switch to **Option 2** (pure outbound `443 WSS` fixed URL) or **Option 3** (self-hosted `24h` VPS hub / `Cloudflare Named Tunnel`) for permanent daily use.

### 3. Cloudflare WAF / Bot Fight Mode Blocking OAuth Callbacks

- **Symptom**: With a custom domain hosted on Cloudflare (Option 2 custom domain or Option 3), `https://mcp.example.com/healthz` returns normal JSON in your local browser, but binding the connector in Web Gemini or Web ChatGPT fails with "Unable to fetch OAuth metadata", `/register` DCR failure, or `HTTP 403`.
- **Cause**: During connector binding and tool execution, Google and OpenAI cloud backend servers directly call `/.well-known/oauth-protected-resource*`, `/.well-known/oauth-authorization-server*`, `/register`, `/token`, and `/mcp*`. If Cloudflare **Bot Fight Mode** or a global **Managed Challenge / JS Challenge** rule is enabled on the domain, cloud backend requests cannot solve browser JavaScript challenges and are blocked.
- **Fix**:
  1. In the Cloudflare dashboard for that domain, go to `Security -> Bots` and turn off **Bot Fight Mode** (on Pro and higher plans with Super Bot Fight Mode, allow automated traffic for that subdomain).
  2. Go to `Security -> WAF -> Custom rules` and create a rule matching `Hostname equals mcp.example.com` (or URI paths `/.well-known/*`, `/register`, `/authorize`, `/token`, `/mcp*`) with action `Skip`, skipping all remaining custom rules, managed challenges, and rate limiting.
  3. Do not configure an IP allowlist restricted exclusively to Google IPs or exclusively to OpenAI IPs if you plan to use both Web Gemini and Web ChatGPT against the same gateway.

### 4. Reconnect Verification After Sleep/Wake or Hotspot Switching

- **Background Reconnect Mechanism**: When a Windows laptop is plugged into AC power and the console's "Prevent auto-sleep while plugged in" toggle is enabled, the machine stays awake; unplugging to battery power automatically releases the wake lock to preserve battery life. After waking from lid-close sleep (monotonic vs. wall-clock drift `> 3.0` seconds) or switching between Wi-Fi and a phone hotspot (zero-traffic UDP probe detects an egress IP change), `NetworkChangeDetector` proactively rebuilds the gateway connection in ~`1.5` seconds, while the Cloudflare SQLite Durable Object gateway holds in-flight requests for up to `9` seconds.
- **Verification Steps**:
  1. Wait `2` seconds after waking your PC and check whether the Windows system tray dot transitions from orange (reconnecting) back to green or blue, or check the connection status badge at the top-right of `http://127.0.0.1:8096`.
  2. If reconnection fails repeatedly, the tray dot turns red and the tooltip plus the console top banner explain whether the network is down or the local proxy is not running (all reconnection is silent with zero toast popups stealing focus). Restore the network or proxy as indicated.
  3. Return to your existing Web Gemini or Web ChatGPT chat and send `@<your-connector-name> call pc_get_status to confirm the connection is restored` (e.g., `@WebAI2PC` or `@Cosmos`). Receiving your local machine status confirms the channel is back online.
