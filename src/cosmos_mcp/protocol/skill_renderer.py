"""Single-source dynamic SKILL.md and server instruction renderer driven directly by KernelDispatcher & LiveRuntimePolicy."""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence

from cosmos_mcp.protocol.dispatcher import KernelDispatcher, SafetyBand, ToolSpec
from cosmos_mcp.core.config import LiveRuntimePolicy, PRODUCT_VERSION, normalize_prefix

_TIER_NAME_ZH: Dict[str, str] = {
    "tier1_readonly": "L1 只读浏览档",
    "tier2_workspace_edit": "L2 工作区读写档",
    "tier3_workspace_dev": "L3 工作区标准开发档",
    "tier4_full_power": "L4 全盘最高权限档",
}

_TOOLSET_NAME_ZH: Dict[str, str] = {
    "standard": "标准开发 16 项",
    "minimal": "精简核心 7 项",
    "symbol": "符号辅助 16 项",
    "hybrid": "混合协作 11 项",
    "full": "完整核心 16 项",
}


def _format_action_clause_zh(spec: ToolSpec, *, tier_allow_edit: bool) -> str:
    actions = spec.effective_action_values(tier_allow_edit=tier_allow_edit)
    if actions:
        joined = "、".join(f'`{spec.action_param}="{a}"`' for a in actions)
        return f"（支持 {joined}）"
    params = [p for p in spec.parameter_names() if p != "caller"][:4]
    if params:
        return "（参数：" + "、".join(f"`{p}`" for p in params) + "）"
    return ""


def _format_action_clause_en(spec: ToolSpec, *, tier_allow_edit: bool) -> str:
    actions = spec.effective_action_values(tier_allow_edit=tier_allow_edit)
    if actions:
        joined = ", ".join(f'`{spec.action_param}="{a}"`' for a in actions)
        return f" (supports {joined})"
    params = [p for p in spec.parameter_names() if p != "caller"][:4]
    if params:
        return " (params: " + ", ".join(f"`{p}`" for p in params) + ")"
    return ""


def render_minimal_public_skill_markdown(prefix: str = "pc", *, lang: str = "bilingual") -> str:
    """Clean, token-free host operational SKILL.md guide safe for direct browser download and Gemini Skill import."""
    eff_p = normalize_prefix(prefix)
    p = f"{eff_p}_" if eff_p else ""
    zh_block = (
        "## 中文操作守则\n"
        "- **宿主唤醒与免审批总开关**：网页版 Gemini 完成 OAuth 连接后，请直接打开 `https://gemini.google.com/customize/connectors`（或左下角菜单 `Personal Intelligence -> Connected Apps`）点开对应连接器，将 `App actions` 总开关设为 `Always allow` 统一开启免审批，**切勿在对话气泡的单张工具确认卡片上单独点击允许**（以免冲掉同连接器下其他工具的免审批权限）；网页版 ChatGPT 在左侧 `Plugins` 创建并 `Install` 安装 `WebAI2PC` 后，普通 `Chat` 模式（日常开发不扣 `Work / Codex` 额度）与 `Work` 模式（长程交付与定时任务）均通过 `@WebAI2PC` 调用。\n"
        f"- **外部资料检索**：在挂载本连接器的主会话中优先调用 `{p}web_research`，避免混调宿主内置联网搜索导致免审批状态被重置。\n"
        f"- **只读定位与查看**：使用 `{p}get_status`、`{p}find_files`、`{p}search_code`、`{p}code_intel`、`{p}read_file`、`{p}batch_probe`、`{p}skill_hub`。\n"
        f"- **安全修改与执行**：使用 `{p}edit_file`、`{p}write_file`、`{p}manage_files`（禁止执行永久物理删除命令）、`{p}run_command`、`{p}run_python`、`{p}bg_command`、`{p}workspace_memory`、`{p}skill_manage`。"
    )
    en_block = (
        "## English Operational Guide\n"
        "- **Host Activation & Master Always-Allow Toggle**: In Web Gemini, open `https://gemini.google.com/customize/connectors` (or bottom-left menu `Personal Intelligence -> Connected Apps`), select your connector, and set `App actions` to `Always allow` and **do NOT click allow on individual in-chat tool confirmation cards** (single-card overrides reset sibling tool permissions); in Web ChatGPT, once `WebAI2PC` is created and installed under `Plugins`, both everyday `Chat` mode (zero `Work / Codex` quota usage) and `Work` mode (multi-app & scheduled tasks) invoke tools via `@WebAI2PC`.\n"
        f"- **External Lookup**: Prefer `{p}web_research` over host built-in web search in active connector sessions.\n"
        f"- **Navigation & Inspection**: Use `{p}get_status`, `{p}find_files`, `{p}search_code`, `{p}code_intel`, `{p}read_file`, `{p}batch_probe`, and `{p}skill_hub`.\n"
        f"- **Safe Edits & Execution**: Use `{p}edit_file`, `{p}write_file`, `{p}manage_files` (recoverable undo/trash vault), `{p}run_command`, `{p}run_python`, `{p}bg_command`, `{p}workspace_memory`, and `{p}skill_manage`."
    )
    low = (lang or "bilingual").strip().lower()
    body = zh_block if low == "zh" else (en_block if low == "en" else f"{zh_block}\n\n{en_block}")
    return (
        "---\n"
        f"name: cosmos-{eff_p}-connector\n"
        "description: Cosmos MCP Connector Operational & Approval Guide\n"
        "---\n\n"
        f"# Cosmos MCP Operational Guide (`v{PRODUCT_VERSION}`)\n\n"
        f"{body}\n"
    )


def build_tool_description(
    spec: ToolSpec,
    active_specs: Sequence[ToolSpec],
    policy: LiveRuntimePolicy,
    *,
    host_label: str = "",
) -> str:
    """Render concise tool description referencing ONLY tools present in `active_specs`."""
    raw_tp = getattr(policy, "tool_prefix", None) or policy.eff_prefix
    eff_p = normalize_prefix(raw_tp)
    prof = policy.prompt_profile
    tier_allow_edit = policy.allow_edit

    base_desc = spec.description or f"Execute {eff_p}_{spec.base_name}."
    act_vals = spec.effective_action_values(tier_allow_edit=tier_allow_edit)
    if act_vals and f"{spec.action_param}=" not in base_desc:
        enum_bar = "|".join(act_vals)
        base_desc = f"{base_desc.rstrip('.')} ({spec.action_param}='{enum_bar}')."

    def _cap_with_period(s: str, cap: int) -> str:
        if len(s) <= cap:
            return s
        trimmed = s[: max(1, cap - 1)].rstrip(" ,;|(")
        return trimmed if trimmed.endswith(".") else (trimmed + ".")

    if prof == "minimal":
        out_min = _strip_unmounted_mentions(base_desc, active_specs, eff_p) if raw_tp else base_desc
        return _cap_with_period(out_min, 240)

    prefer = spec.nudge_prefer.strip()
    merged = f"{base_desc} {prefer}".strip() if prefer else base_desc
    cleaned = _strip_unmounted_mentions(merged, active_specs, eff_p)
    if prof == "detailed" and host_label:
        return _cap_with_period(f"[{host_label} | tier={policy.tier_key}] {cleaned}", 520)
    return _cap_with_period(cleaned, 460)


def _strip_unmounted_mentions(text: str, active_specs: Sequence[ToolSpec], prefix: str) -> str:
    """Ensure no known unmounted tool names leak into descriptions."""
    if not text:
        return text
    active_bases = {sp.base_name for sp in active_specs}
    known_optional = (
        "workspace_memory",
        "batch_probe",
        "skill_hub",
        "skill_manage",
        "browser_use",
        "cua_window",
        "desktop_window",
        "web_research",
        "manage_files",
        "undo_or_trash",
        "trash_file",
        "undo_edit",
        "restore_trash",
        "edit_file",
        "patch_file",
        "replace_lines",
        "multi_patch",
        "run_python",
        "run_command",
        "bg_command",
    )
    out = text
    for cand in known_optional:
        if cand not in active_bases:
            out = out.replace(f"`{prefix}_{cand}`", "exposed tools")
            out = out.replace(f"{prefix}_{cand}", "exposed tools")
            out = out.replace(f"`pc_{cand}`", "exposed tools")
            out = out.replace(f"pc_{cand}", "exposed tools")
    if prefix and prefix != "pc":
        for act_b in sorted(active_bases, key=len, reverse=True):
            out = out.replace(f"`pc_{act_b}`", f"`{prefix}_{act_b}`")
            out = out.replace(f"pc_{act_b}", f"{prefix}_{act_b}")
    return out


def build_server_instructions(
    dispatcher: KernelDispatcher,
    policy: Optional[LiveRuntimePolicy] = None,
    *,
    scopes: Optional[Iterable[str]] = None,
    readonly_only: bool = False,
) -> str:
    """Build single-source MCP `initialize` server instructions from active `ToolSpec`s (zero ghost tools)."""
    pol = policy or dispatcher.policy
    active_specs = dispatcher.active_tool_specs(scopes=scopes, readonly_only=readonly_only)
    raw_tp = getattr(pol, "tool_prefix", None) or getattr(pol, "eff_prefix", None) or dispatcher.prefix
    eff_p = normalize_prefix(raw_tp)
    p = f"{eff_p}_" if eff_p else ""
    by_name = {sp.base_name: sp for sp in active_specs}

    ws_display = ", ".join(str(r) for r in pol.workspace_roots)
    header = (
        f"Cosmos MCP v{PRODUCT_VERSION} [{pol.device_label} · profile={pol.toolset_profile} · "
        f"tier={pol.tier_key}{'(readonly-endpoint)' if readonly_only else ''} · roots={ws_display}]."
    )
    if pol.prompt_profile == "minimal":
        return header

    clauses: List[str] = []
    nav = [f"{p}{n}" for n in ("find_files", "search_code", "code_intel", "read_file") if n in by_name][:3]
    if nav:
        clauses.append(f"locate/read via {', '.join(nav)}")

    edit = [f"{p}{n}" for n in ("edit_file", "write_file") if n in by_name][:2]
    del_tools = [f"{p}{n}" for n in ("manage_files", "undo_or_trash") if n in by_name][:1]
    if edit:
        if del_tools:
            clauses.append(f"edit via {' / '.join(edit)}; file ops/rollback/trash via {del_tools[0]} (never permanent rm/del)")
        else:
            clauses.append(f"edit via {' / '.join(edit)} (never permanent rm/del)")

    exec_t = [f"{p}{n}" for n in ("run_command", "run_python", "bg_command") if n in by_name]
    if exec_t:
        clauses.append(f"execute/verify via {' / '.join(exec_t)}")

    if "web_research" in by_name:
        wr_spec = by_name["web_research"]
        acts = "|".join(wr_spec.effective_action_values(tier_allow_edit=pol.allow_edit))
        act_note = f" ({wr_spec.action_param}='{acts}')" if acts else ""
        clauses.append(f"external docs via {p}web_research{act_note} instead of built-in web search")

    if "workspace_memory" in by_name:
        wm_spec = by_name["workspace_memory"]
        acts = "|".join(wm_spec.effective_action_values(tier_allow_edit=pol.allow_edit and not readonly_only))
        clauses.append(f"cross-client notes via {p}workspace_memory ({wm_spec.action_param}='{acts}')")

    for pk_spec in active_specs:
        if pk_spec.pack in ("browser", "cua"):
            acts = "|".join(pk_spec.effective_action_values(tier_allow_edit=pol.allow_edit))
            clauses.append(f"pack[{pk_spec.pack}] via {p}{pk_spec.base_name}" + (f" ({pk_spec.action_param}='{acts}')" if acts else ""))

    if "get_status" in by_name:
        if readonly_only:
            clauses.append(f"tutorials/Cloudflare/Studio setup guides via {p}get_status(guide='cloudflare'|'permissions'|'all')")
        else:
            clauses.append(
                f"tutorials/Cloudflare/Studio setup & opening local config UI via {p}get_status(guide='cloudflare'|'permissions'|'all', open_page='gateways'|'studio'|'tutorials')"
            )

    if not clauses:
        return header
    numbered = " ".join(f"{idx}) {c}." for idx, c in enumerate(clauses, 1))
    return f"{header} Rules: {numbered}"


def render_skill_markdown(
    dispatcher: KernelDispatcher,
    policy: Optional[LiveRuntimePolicy] = None,
    *,
    scopes: Optional[Iterable[str]] = None,
    readonly_only: bool = False,
    connector_name: str = "Cosmos",
    port: int = 8096,
    lang: str = "bilingual",
    include_frontmatter: bool = True,
) -> str:
    """Unidirectionally synthesize Chinese/English `SKILL.md` strictly from `dispatcher` active tools and `policy`."""
    pol = policy or dispatcher.policy
    active_specs = dispatcher.active_tool_specs(scopes=scopes, readonly_only=readonly_only)
    raw_tp = getattr(pol, "tool_prefix", None) or getattr(pol, "eff_prefix", None) or dispatcher.prefix
    eff_p = normalize_prefix(raw_tp)
    p = f"{eff_p}_" if eff_p else ""
    by_name = {sp.base_name: sp for sp in active_specs}
    prefixed_names = [f"`{p}{sp.base_name}`" for sp in active_specs]
    cnt = len(active_specs)
    tier_allow_edit = pol.allow_edit and not readonly_only
    tier_allow_exec = pol.allow_exec and not readonly_only
    tier_lbl = pol.dynamic_tier_label(tool_count=cnt).replace("L3 工作区开发标准档", "L3 工作区标准开发档")
    preset_zh = _TOOLSET_NAME_ZH.get(pol.toolset_profile, pol.toolset_profile)
    tier_short_zh = _TIER_NAME_ZH.get(pol.tier_key, pol.tier_key)
    clean_conn = (connector_name or "Cosmos").strip().lstrip("@") or "Cosmos"
    eff_port = int(port) if port and int(port) > 0 else 8096

    read_specs = [sp for sp in active_specs if sp.safety_band == SafetyBand.READONLY and sp.base_name != "web_research"]
    write_specs = [sp for sp in active_specs if sp.safety_band == SafetyBand.WORKSPACE_WRITE]
    exec_specs = [sp for sp in active_specs if sp.safety_band in (SafetyBand.WORKSPACE_EXEC, SafetyBand.HOST_ADMIN) and sp.pack is None]
    pack_specs = [sp for sp in active_specs if sp.pack is not None]

    zh_sections: List[str] = [
        f"## 中文操作守则（已开放 {cnt} 项 · 预设：{preset_zh}）",
        "",
        f"- **当前档位**：{tier_lbl}",
        f"- **已开放工具清单（{cnt} 项）**：{', '.join(prefixed_names) if prefixed_names else '（无）'}",
        "- **同步说明**：本守则随当前工作区权限档位、工具配置与外设包开关状态实时生成（不含任何敏感令牌或本地路径）。",
        "",
        "### 1. 宿主唤醒与免审批总开关规范（勿点单张对话确认卡）",
        f"- 网页版 Gemini 首次绑定 `@{clean_conn}` 后，请打开 `https://gemini.google.com/customize/connectors`（或左下角菜单 `Personal Intelligence -> Connected Apps`）点开 `{clean_conn}`，将 `App actions` 总开关设为 `Always allow` 一次性开启免审批；**切勿在聊天流弹出的单张工具确认卡片上单独点击允许**，否则宿主会按单工具粒度覆写权限，冲掉同一连接器下其他工具已生效的 `Always allow` 免审批状态。",
        "- 网页版 ChatGPT 在左侧 `Plugins` 创建并点 `Install` 安装 `WebAI2PC` 后（首次自动代填仅限具备受控浏览器的 `Work` 模式），普通 `Chat` 模式（日常改代码修文档不扣 `Work / Codex` 额度）与 `Work` 模式（跨应用长程交付与定时任务）均通过 `@WebAI2PC` 调用；本守则在工作区/桌面端可存入原生 `Skills`，网页版 `Chat` 与 `Work` 均可粘贴到 `Project Instructions` 或自定义指令。",
    ]

    if "web_research" in by_name:
        wr = by_name["web_research"]
        zh_sections.extend(
            [
                "",
                f"### 2. 外部资料检索优先调用 `{p}web_research`",
                f"- 查阅外部文档、网页或代码仓时直接调用 `{p}web_research`{_format_action_clause_zh(wr, tier_allow_edit=tier_allow_edit)}，不在挂载本连接器的主对话混调宿主内置联网搜索，防止会话免审批状态被重置。",
            ]
        )
    else:
        zh_sections.extend(
            [
                "",
                "### 2. 保持连接器会话免审批连续性",
                "- 在已挂载本连接器的主会话中避免混用未隔离的内置网页搜索，防止会话免审批状态被重置。",
            ]
        )

    zh_sections.extend(
        [
            "",
            "### 3. 代码定位、读取与并发子任务协作",
        ]
    )
    if read_specs:
        read_items_zh = [f"`{p}{sp.base_name}`{_format_action_clause_zh(sp, tier_allow_edit=tier_allow_edit)}" for sp in read_specs]
        zh_sections.append("- 只读导航与查看工具：" + "；".join(read_items_zh) + "。")
    if "get_status" in by_name:
        if readonly_only:
            zh_sections.append(
                f"- 内置教程读取：用户询问如何配置 Cloudflare 固定网址、切换权限或排查连接问题时，调用 `{p}get_status(guide='cloudflare'|'permissions'|'all')` 读取最新界面步骤。"
            )
        else:
            zh_sections.append(
                f"- 内置教程与打开本地设置页：用户询问如何配置 Cloudflare 固定网址、切换权限或调整本地控制台时，调用 `{p}get_status(guide='cloudflare'|'permissions'|'all', open_page='gateways'|'studio'|'tutorials')` 读取步骤并在本机浏览器打开对应页面。"
            )
    zh_sections.append(
        f"- 多步骤跨文件任务可先通过 `retriever:expand_tools` 展开所需 `{p}*` 工具，并在派发 `invoke_subagent` 时于描述开头写明 `@{clean_conn}` 与独立 `caller` 标识。"
    )

    if write_specs or exec_specs:
        zh_sections.extend(["", "### 4. 修改、回滚与执行边界"])
        if write_specs:
            w_items_zh = [f"`{p}{sp.base_name}`{_format_action_clause_zh(sp, tier_allow_edit=tier_allow_edit)}" for sp in write_specs]
            zh_sections.append("- 文件写入与回滚工具：" + "；".join(w_items_zh) + "（禁止执行永久物理删除命令）。")
        elif not tier_allow_edit:
            zh_sections.append("- 当前处于只读模式，一切文件修改与删除操作均已硬拦截。")
        if exec_specs:
            e_items_zh = [f"`{p}{sp.base_name}`{_format_action_clause_zh(sp, tier_allow_edit=tier_allow_edit)}" for sp in exec_specs]
            zh_sections.append("- 命令与代码执行工具：" + "；".join(e_items_zh) + "。")
        elif not tier_allow_exec:
            zh_sections.append("- 当前档位已关闭终端命令与脚本执行权限。")
    else:
        zh_sections.extend(
            [
                "",
                "### 4. 纯只读安全边界",
                "- 当前端点或档位仅开放只读工具，任何文件写入与命令执行调用均会被协议层直接拦截。",
            ]
        )

    optional_zh_lines: List[str] = []
    if "workspace_memory" in by_name:
        wm = by_name["workspace_memory"]
        optional_zh_lines.append(
            f"- 跨端交接记录：`{p}workspace_memory`{_format_action_clause_zh(wm, tier_allow_edit=tier_allow_edit)}。"
        )
    _pack_zh_names = {"browser": "受管独立浏览器扩展包", "cua": "桌面窗口感知与后台截图扩展包"}
    for pk_sp in pack_specs:
        pk_lbl = _pack_zh_names.get(str(pk_sp.pack or ""), f"外设扩展包 `{pk_sp.pack}`")
        optional_zh_lines.append(
            f"- 已启用{pk_lbl}：`{p}{pk_sp.base_name}`{_format_action_clause_zh(pk_sp, tier_allow_edit=tier_allow_edit)}。"
        )
    if optional_zh_lines:
        zh_sections.extend(["", "### 5. 已启用协同与外设扩展能力", *optional_zh_lines])

    en_sections: List[str] = [
        f"## English Operational Rules (Profile `{pol.toolset_profile}` · {cnt} Active Tools)",
        "",
        f"- **Active Tools ({cnt})**: {', '.join(prefixed_names) if prefixed_names else '(none)'}",
        f"- **Permission Tier**: `{pol.tier_key}` (`readonly_endpoint={readonly_only}`)",
        "",
        "### 1. Connector Master Toggle `Always allow` & Host Activation",
        f"- In Web Gemini, open `https://gemini.google.com/customize/connectors` (or bottom-left menu `Personal Intelligence -> Connected Apps`), select `{clean_conn}`, and set `App actions` to `Always allow`, and **do NOT click allow on individual in-chat tool confirmation cards** (single-card clicks overwrite connector-wide settings and strip `Always allow` from sibling tools).",
        "- In Web ChatGPT, once `WebAI2PC` is created and installed under `Plugins` (`Work` mode for browser-assisted setup), both everyday `Chat` mode (zero `Work / Codex` quota usage) and `Work` mode (multi-app & scheduled tasks) invoke tools via `@WebAI2PC`.",
    ]

    if "web_research" in by_name:
        wr = by_name["web_research"]
        en_sections.extend(
            [
                "",
                f"### 2. External Lookup via `{p}web_research`",
                f"- Use `{p}web_research`{_format_action_clause_en(wr, tier_allow_edit=tier_allow_edit)} instead of host built-in web search to preserve connector Always-allow session permissions.",
            ]
        )

    if read_specs:
        read_items_en = [f"`{p}{sp.base_name}`{_format_action_clause_en(sp, tier_allow_edit=tier_allow_edit)}" for sp in read_specs]
        en_sections.extend(["", "### 3. Read & Navigation Tools", "- Available read-only tools: " + "; ".join(read_items_en) + "."])
        if "get_status" in by_name:
            if readonly_only:
                en_sections.append(
                    f"- Inline setup tutorials: call `{p}get_status(guide='cloudflare'|'permissions'|'all')` for step-by-step Studio & Cloudflare setup instructions."
                )
            else:
                en_sections.append(
                    f"- Inline setup tutorials & local Studio UI: call `{p}get_status(guide='cloudflare'|'permissions'|'all', open_page='gateways'|'studio'|'tutorials')` to read step-by-step setup guides and open the local config page."
                )

    if write_specs or exec_specs:
        en_sections.extend(["", "### 4. Write, Rollback & Execution Tools"])
        if write_specs:
            w_items_en = [f"`{p}{sp.base_name}`{_format_action_clause_en(sp, tier_allow_edit=tier_allow_edit)}" for sp in write_specs]
            en_sections.append("- Workspace write/rollback tools: " + "; ".join(w_items_en) + ".")
        if exec_specs:
            e_items_en = [f"`{p}{sp.base_name}`{_format_action_clause_en(sp, tier_allow_edit=tier_allow_edit)}" for sp in exec_specs]
            en_sections.append("- Execution tools: " + "; ".join(e_items_en) + ".")
    else:
        en_sections.extend(["", "### 4. Read-Only Enforcement", "- Non-read-only operations are strictly blocked in the current tier/endpoint."])

    optional_en_lines: List[str] = []
    if "workspace_memory" in by_name:
        wm = by_name["workspace_memory"]
        optional_en_lines.append(
            f"- Shared workspace memory: `{p}workspace_memory`{_format_action_clause_en(wm, tier_allow_edit=tier_allow_edit)}."
        )
    for pk_sp in pack_specs:
        optional_en_lines.append(
            f"- Active peripheral pack `{pk_sp.pack}`: `{p}{pk_sp.base_name}`{_format_action_clause_en(pk_sp, tier_allow_edit=tier_allow_edit)}."
        )
    if optional_en_lines:
        en_sections.extend(["", "### 5. Active Collaboration & Peripheral Packs", *optional_en_lines])

    low_lang = (lang or "bilingual").strip().lower()
    if low_lang == "zh":
        body_md = "\n".join(zh_sections)
    elif low_lang == "en":
        body_md = "\n".join(en_sections)
    else:
        body_md = "\n".join(zh_sections) + "\n\n" + "\n".join(en_sections)

    if not include_frontmatter:
        zh_title = f"# Cosmos MCP 连接与操作说明（{tier_short_zh} · 预设：{preset_zh}）\n\n"
        return (zh_title if low_lang == "zh" else "") + body_md + "\n"

    header_md = (
        "---\n"
        f"name: cosmos-{eff_p or 'mcp'}-guide\n"
        f"description: Cosmos MCP operational guide (profile={pol.toolset_profile}, tier={pol.tier_key}, tools={cnt}).\n"
        "---\n\n"
        f"# Cosmos MCP 操作守则 / Operational Guide (`{pol.toolset_profile}` · {cnt} Tools)\n\n"
    )
    return header_md + body_md + "\n"
