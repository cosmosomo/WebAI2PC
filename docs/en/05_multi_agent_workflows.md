# 05. Multi-Agent Parallel Subtasks & Practical Workflow Guide

> [简体中文](../05_多智能体并行子任务与实战工作流教程.md) · **English** · [Docs Home](README.md) · [README](../../README_EN.md)

This guide is for users who have connected local Cosmos MCP (`v1.2.1`) to **Web Google Gemini (Task Mode, including the same-account Gemini mobile app)** or **Web ChatGPT (with the `WebAI2PC` plugin installed: use `Chat` mode for daily coding and scripts to save agent quota, and `Work` mode for cross-app long-running or scheduled tasks)**. It covers host operating rules setup, parallel subtask orchestration (`invoke_subagent`), multimodal PDF/image reading and in-place Word/Excel editing, automatic background offloading for long builds/tests, and hot-enabling the managed browser (`browser`) and desktop window automation (`cua`) expansion packs along with their runtime boundaries.

## 1. Importing AI Operating Rules & First-Message Wake-Up

### 1. Save "Copy AI Operating Rules" into Host Skills or Instructions

The local console includes an operating-rules template aligned with your active tool prefix and all `16` core tool contracts (matching `host_skills/SKILL.md` in the repository). Saving it into your host once eliminates repeating safety boundaries and parameter conventions in every chat:

1. Open the local `Cosmos Studio` console (`http://127.0.0.1:8096`), expand "First-Time Binding & Wake-Up Prompts", and click **"Copy AI Rules"** or **"Copy ChatGPT Rules"**.
2. **Web Google Gemini**:
   - In the left sidebar, go to `Customize -> Skills`, create a new custom skill, paste the rules, and save.
   - Also inspect `Personal Intelligence -> Connected Apps -> Cosmos` (or directly at https://gemini.google.com/customize/connectors) and make sure the top `App actions` switch is set to `Always allow`. Avoid clicking allow on individual tool confirmation cards inside a chat stream—single-card approval overrides the connector-level setting per tool and causes other tools on the same connector to fall back to per-call prompts.
3. **Web ChatGPT (`Skills` vs `Instructions` Storage & `Chat` / `Work` Usage)**:
   - **Storing Rules**: In Workspace, desktop, or plugin environments you can save them to native `Skills`; in both web `Chat` mode and `Work` mode you can paste them into `Project Instructions` or Custom Instructions for reuse.
   - **Choosing the Right Mode for `@your-connector`**: For daily local code lookup/edits, format-preserving Word/Excel edits, and running tests, type `@your-connector` in **`Chat` mode** first (fast response, uses regular chat limits, consumes zero `Work / Codex` agent quota). Switch to **`Work` mode** with `@your-connector` when combining the managed browser, multi-step deliverables across email/Slack/Drive, or `Scheduled Tasks`.

### 2. First-Message Connector Wake-Up & External Search Isolation

- **Web Gemini First-Message Wake-Up**: Start every new Task Mode chat with `@<your-connector-name>` (e.g., `@your-connector` or `@your-connector`) and select the popped-up connector chip (or click "Copy First-Message Wake-Up Prompt" in the console banner or the Windows tray menu). Example:
  ```text
  @your-connector first call pc_get_status to check the open workspace directories and workspace skills, then outline the module structure of D:\Work\my-project.
  ```
  When a long conversation triggers automatic context compaction, or a brief follow-up omits the `@<connector-name>` tag and tools are not expanded, the operating rules guide the model to re-expand the required `pc_*` tools before continuing.
- **Route Public Web & GitHub Lookups Through the Local Tool**: When researching external docs, error discussions, or open-source code inside a session with this connector attached, ask the AI to call the local read-only tool `pc_web_research(action="search"|"github_search"|"fetch")` rather than mixing in the host's built-in web search, which can downgrade connector auto-approval state.

## 2. Splitting Parallel Subtasks by Directory in Web Gemini Task Mode (`invoke_subagent`)

When working on medium-to-large codebases or comparing multiple documents, reading 20–30 files sequentially in a single chat quickly fills the main context window and slows responses. Web Gemini Task Mode supports spawning asynchronous subtasks via `invoke_subagent` for parallel execution.

### 1. Ideal Scenarios for Parallel Subtasks

- **Cross-Directory Code Review & Search**: Split `backend/`, `frontend/`, and `tests/` across parallel subtasks to audit API contracts, error handling, or performance bottlenecks simultaneously.
- **Independent Module Verification & Batch Probes**: Each subtask runs read-only `pc_batch_probe` aggregations inside its own directory (pre-injected with `PROJ`, `rg`, `outline`, `list_dir`, and `RESULT`), returning only a compact summary table and exact file/line references to the main chat.
- **Multi-Document or PDF Extraction**: Assign `1` to `2` large PDFs or design docs per subtask, then cross-check the findings in the main chat.

### 2. Dispatch Conventions & Avoiding Concurrent Write Conflicts

1. **Batch Size & Connector Forwarding**: Keep each parallel batch to `2`–`4` subtasks (within the platform's `5`-per-batch concurrency cap; never nest subtasks inside subtasks). Start each subtask prompt with `@<your-connector-name>` (e.g., `@your-connector` or `@your-connector`) and assign a distinct `caller` label (such as `caller="sub-api-check"` or `caller="sub-db-check"`) so each worker is distinguishable in the console audit log.
2. **Avoid Concurrent Writes to the Same File**: Although `pc_edit_file` and `pc_write_file` support `expected_sha256` optimistic locking, two subtasks editing the same file concurrently will trigger hash-mismatch retries or rollbacks. Follow two practical boundaries:
   - **Parallel Read-Only Research + Main-Chat Unified Edits (Recommended Default)**: Subtasks only call `pc_find_files`, `pc_search_code`, `pc_code_intel`, `pc_read_file`, or `pc_batch_probe` to locate exact line numbers and draft fixes; once all subtasks finish, the main chat applies edits in order with `pc_edit_file` and runs tests.
   - **Strictly Disjoint Exclusive Write Shards**: When generating independent unit-test files or separate document chapters in parallel, list each subtask's exclusive target file paths in its dispatch prompt and forbid touching files outside its list.

Reusable parallel-subtask prompt example:

```text
split this audit into 3 parallel subtasks to perform a read-only review of src/auth, src/orders, and src/payments under D:\Work\my-project (use pc_code_intel and pc_read_file to locate unhandled exceptions and missing edge-case tests; do not modify any files inside subtasks). Once all 3 subtasks return line numbers and proposed fixes, apply the edits together in the main chat with pc_edit_file and run the test suite.
```

## 3. Office Documents & Multimodal Workflows (PDF, Images, Word, Excel & One-Click Rollback)

Cosmos MCP includes a pure-Python standard-library document pipeline, allowing direct reading and editing of local Office documents and images without extra C extensions or manual web uploads.

### 1. Direct Reading of Local Images & PDF Documents

- **Native Multimodal Viewing of Local Images**: Calling `pc_read_file(path="D:\\Work\\my-project\\docs\\architecture.png")` on local `.png`, `.jpg`, `.jpeg`, or `.webp` images returns native `EmbeddedResource` image data directly to Web and Mobile Gemini (PNGs `<= 160 KiB` pass through losslessly; oversized images are scaled proportionally, alongside a `30`-minute HMAC-signed read-only preview route), letting the AI inspect UI screenshots or read chart values directly.
- **PDF & Multi-Format Extraction**: `pc_read_file` directly extracts text from `.pdf`, `.docx`, `.xlsx`, `.pptx`, and `.ipynb` files. For Chinese PDFs, it automatically checks `/CIDFont`, `/Identity-H`, `/ToUnicode` glyph mappings and control-character structure so scanned or unmapped-font PDFs do not silently return garbled text as a false success.

### 2. Format-Preserving `.docx` Editing & Cell-Coordinate `.xlsx` Formulas

- **Edit `.docx` Paragraphs & Tables While Preserving Formatting**: Calling `pc_edit_file` on a `.docx` file accepts `old_text` and `new_text` (or an `edits` array / `replace_all=True` for multiple replacements). The underlying XML editor matches text across split `<w:r>` runs in paragraphs and tables, preserving the first run's font, size, bold, italic, and color styling while ensuring whitespace-preservation attributes are intact:
  ```text
  read D:\Work\my-project\docs\acceptance-report.docx, replace "Staging deployment pending" with "Production rollout accepted", and preserve the original heading and table fonts.
  ```
- **Read & Write `.xlsx` Values & Formulas by Cell Coordinate**: Calling `pc_edit_file` on an `.xlsx` workbook uses `SheetName!CellRef` as `old_text` (e.g., `Sheet1!F12`) and the target value or `=`-prefixed Excel formula as `new_text` (or an `edits` list for atomic multi-cell updates):
  ```text
  inspect the headers of D:\Work\my-project\finance\monthly-ledger.xlsx, set Sheet1!D14 to =SUM(D2:D13), and set Sheet1!E14 to =AVERAGE(E2:E13).
  ```

### 3. Open-File Lock Protection & `.undo_history` One-Click Rollback

- **Open-File Lock Protection (`ERR_OFFICE_FILE_LOCKED`)**: If the target `.docx` or `.xlsx` file is currently open for editing in Microsoft Word, Excel, or WPS (a `~$` lock file exists in the same folder or the OS file handle is exclusively locked), `pc_edit_file` aborts immediately and returns `ERR_OFFICE_FILE_LOCKED` to avoid overwriting unsaved desktop work (`pc_read_file` on other unlocked files in the same directory is unaffected). Press `Ctrl+S` in Word/Excel, close the document window, and ask the AI to retry.
- **`.undo_history` Pre-Edit Snapshots & Lossless Undo**: Every code edit and `.docx`/`.xlsx` binary revision performed by `pc_edit_file` or `pc_write_file` saves a full pre-edit snapshot inside the isolated `.undo_history` state directory (never leaving dirty `.bak` files in your project or Git repo). To revert any edit:
  1. Send in chat: `revert the last edit to D:\Work\my-project\finance\monthly-ledger.xlsx` (triggers `pc_manage_files(action="undo", path="...")`);
  2. Or open the local `Cosmos Studio` console, go to "Live Tasks & Undo Recovery", inspect the before/after diff, and click Undo.
- **Recoverable Trash Instead of Raw Deletion**: Clean up old files or temporary directories via `pc_manage_files(action="trash", path="...", reason="...")`, moving them to the `.undo_history` trash bin. Restore anytime with `pc_manage_files(action="restore", trash_id="latest")` or from the console.

## 4. Auto-Offloading Long Builds & Tests to `pc_bg_command`

### 1. Automatic Background Promotion Beyond the 20-Second Sync Cap

Both `pc_run_command` and `pc_run_python` run silently with `CREATE_NO_WINDOW` so no black terminal window pops up to interrupt your work. To balance instant return for quick commands against the `60`–`90`-second web connector timeout:

- The default foreground synchronous wait cap is `20` seconds (`DEFAULT_SYNC_WAIT_CAP_SEC = 20.0`, adjustable per call via `sync_wait_cap_sec` between `0.2` and `60` seconds).
- Commands finishing within `20` seconds return their exit code and stdout immediately; commands still running past `20` seconds (such as full `pytest`, `npm run build`, `cargo test`, or data pipelines) are seamlessly promoted to detached background jobs, immediately returning a `job_id` and the absolute log file path.

### 2. Proactive Background Launch, Virtualenv Selection & Polling/Termination

For builds, training runs, or full regression suites known to take longer, instruct the AI to follow the "Start -> Poll -> Summarize" loop:

1. **Launch in a Specific Environment**: Call `pc_bg_command(action="start", command="pytest tests/ -v", cwd="D:\\Work\\my-project")` to get a `job_id` in `< 50ms`. You can also pass `python_path`, `venv`, or `conda_env` to target a local virtualenv or Conda environment (on Windows, `pythonw.exe` is automatically mapped to windowless `python.exe` so stdout streams completely into the log).
2. **Long-Poll Progress & Tail Logs**: Call `pc_bg_command(action="wait", job_id="<job_id>", wait_seconds=20, tail_lines=80)` (or `pc_get_status(job_id="<job_id>", wait_seconds=20)`) to block up to `20` seconds; if the job finishes in that window, it immediately returns the real `exit_code` and the last `80` log lines; otherwise poll again or inspect the log file.
3. **Kill Runaway Jobs**: Call `pc_bg_command(action="kill", job_id="<job_id>")` to terminate the entire child process tree, or click "Stop All Running Tasks" on the console's "Live Tasks & Undo Recovery" page.

## 5. Hot-Enabling Managed Browser (`browser`) & Desktop Window Automation (`cua`) Packs

### 1. How to Enable & Refresh the Connector Tool Schema

By default, only the `16` core file and terminal tools are exposed. When you want the web AI to verify a locally running web frontend, scrape a dynamically rendered page, or automate a Windows desktop GUI app, hot-enable either or both optional packs:

- **Method A (Console Toggle)**: Open `Cosmos Studio` -> "Tools & Security", confirm you are on `L3` Workspace Dev (or `L4` Full-Disk Dev; peripheral packs are automatically disabled under `L1` Read-Only and `L2` Edit-Only), and toggle on **"Managed Browser Pack"** (registers `pc_browser_use`) and **"Desktop Window Automation Pack"** (registers `pc_cua_window`, Windows only; automatically skipped on macOS/Linux).
- **Method B (CLI)**:
  ```bash
  # Enable both managed browser and desktop window packs (cua and desktop are aliases)
  cosmos-mcp permissions --enable-pack browser,cua

  # Disable packs anytime to return to the compact 16-tool surface
  cosmos-mcp permissions --disable-pack browser,cua
  ```
- **Refreshing the Connector Schema After Toggling**: Both Web Gemini and Web ChatGPT cache the tool schema snapshot when a conversation starts. After hot-enabling or disabling `browser` or `cua`, if an existing chat says `pc_browser_use` or `pc_cua_window` is not found:
  1. Refresh the connector in the web host (in Web ChatGPT, open the connector details and click `Refresh`; in Web Gemini, start a new chat, or toggle the connector once at https://gemini.google.com/customize/connectors);
  2. **Open a new chat** and start with `@<your-connector-name>` (e.g., `@your-connector` or `@your-connector`).

### 2. Zero-Focus-Stealing Background Runtime Boundaries

Both peripheral packs enforce strict zero-focus-stealing and personal-data isolation so you can keep typing and reading on your PC while the AI works in the background:

1. **Managed Browser (`browser` -> `pc_browser_use`) Boundaries**:
   - **Isolated Profile Directory**: Always uses `<state_dir>/browser_profile` (prefers `playwright` when installed, otherwise reuses local Chrome/Edge headless CDP). Never reads, switches, or closes your personal browser windows or tabs.
   - **Visible-Element Filtering & Safe Downloads**: `snapshot`, `click`, `fill`, and `select` verify element and ancestor visibility plus non-zero bounding boxes, filtering out hidden mobile DOM duplicates (returning `ERR_ELEMENT_HIDDEN` if hidden). Downloads land inside the open writable workspace, and a synchronous SSRF guard blocks `file://`, cloud metadata IPs, and local management ports.
   - **Non-Activating Manual Login Window**: When a site requires manual QR/login, `open_login_window` opens the managed window with `SW_SHOWNOACTIVATE` so it never steals focus from the window you are typing in.
2. **Desktop Window Automation (`cua` -> `pc_cua_window`, Windows Only) Boundaries**:
   - **Off-Screen Capture & Background Message Delivery**: Uses `PrintWindow(2)` off-screen capture, UIAutomation control-tree inspection, and background window message synthesis (high-DPI windows with a long edge `> 1440px` automatically record `scale_factor`, and clicks/scrolls under default `coord_space="auto"` map back to exact client pixels). Before and after each call, it verifies that the foreground active window handle, physical mouse cursor position, and system clipboard remain untouched.
   - **Workspace Ownership Fence & Unsaved-Work Protection**: Under default `L3`, it only enumerates and operates on windows tied to open workspace directories or spawned by the current session—never touching unrelated personal chat apps or system settings windows. Locked or black screens return `ERR_SCREEN_LOCKED_OR_BLACK_FRAME`; closing a window whose title contains an unsaved asterisk is blocked automatically (use `send_keys(value="ctrl+s")` to send save shortcuts directly to the target window handle in the background).
