/* WebAI2PC Interactive Tutorials Controller (tutorials.js)
 * Serves /tutorials inside Cosmos Studio (:8096) and supports standalone offline preview.
 * Supports Wave 7 multi-gateway coexistence (/api/studio/state gateways map) and 4 safety tiers (L1-L4).
 */
(function () {
  "use strict";

  var STUDIO_THEME_KEY = "cosmos_studio_theme";
  var LEGACY_THEME_KEY = "webai2pc_theme";
  var PROGRESS_STORAGE_KEY = "webai2pc_tutorial_steps_v1";
  var ACTIVE_MOD_STORAGE_KEY = "webai2pc_tutorial_active_mod_v1";
  var FALLBACK_BASE_URL = "https://xxxxx.srv.us";

  var GATEWAY_ORDER = ["instant", "workers_dev", "self_hosted"];
  var GATEWAY_DEFAULT_LABELS = {
    instant: "方式 1 · 一键上手",
    workers_dev: "方式 2 · Cloudflare 固定网关",
    self_hosted: "方式 3 · 自有服务器/域名"
  };

  var MODULE_ORDER = [
    "mod-gemini",
    "mod-chatgpt",
    "mod-channels",
    "mod-templates",
    "mod-safety",
    "mod-troubleshoot"
  ];

  var MODULE_STEP_MAP = {
    "mod-gemini": ["g1", "g2", "g3", "g4", "g5"],
    "mod-chatgpt": ["c1", "c2", "c3", "c4"],
    "mod-channels": ["ch1", "ch2", "ch3", "ch4"],
    "mod-templates": ["t1", "t2", "t3"],
    "mod-safety": ["s1", "s2", "s3", "s4"],
    "mod-troubleshoot": ["ts1", "ts2", "ts3", "ts4"]
  };

  var SAFETY_TIER_DESCRIPTIONS = {
    readonly: {
      title: "当前查看：只读浏览模式（L1 · 顶栏免口令 0.1 秒急停）",
      desc: "仅允许在已开放工作目录与只读参考目录内读取文件、提取 PDF / .docx / .xlsx / .pptx 文本、查看图片与搜索代码，禁止一切文件写入与命令执行。点击 Studio 顶栏「一键切换只读保护」（或托盘右键菜单）无需输入口令，0.1 秒内立即终止所有在途命令与外设会话，并将受管浏览器包与桌面窗口操控包自动关闭置灰。"
    },
    edit_only: {
      title: "当前查看：仅改文件禁跑命令（L2 · 文档与纯代码编辑围栏）",
      desc: "允许查阅已开放工作目录与只读参考目录，并修改可读写工作目录内的代码文件及 Word (.docx)、Excel (.xlsx) 文档（写前自动生成 .undo_history 快照，只读参考目录仍受保护），禁止运行任何终端命令、Python 脚本及外部操控扩展包。"
    },
    full_dev: {
      title: "当前查看：工作区内顺畅开发（L3 · 默认推荐档位）",
      desc: "仅限在已开放的可读写工作目录内修改代码与 Office 文档、运行无窗口终端命令与 Python 脚本；外层只读参考目录（readonly_workspace_roots）仅允许检索查阅，误写自动返回 ERR_READONLY_WORKSPACE 拦截；支持按需热开启「受管浏览器包」（pc_browser_use）与「桌面窗口操控包」（pc_cua_window）。"
    },
    full_power: {
      title: "当前查看：全盘顺畅开发（不限目录）（L4 · 跨目录读写 + 安全护栏保留）",
      desc: "允许跨本机任意本地目录读写文件与运行命令、Python 脚本（不受工作区目录范围限制）；同时依然保留 .undo_history 写前自动快照、安全回收箱防物理直删（拦截 rm -rf / del / Remove-Item）、只读参考目录保护及本机敏感凭据目录隔离。"
    }
  };

  var DIFF_DEMO_SNIPPETS = {
    py: {
      header: "快照记录 (.undo_history/20261126_config.py)",
      delLine: "- TIMEOUT_SECONDS = 5",
      addLine: "+ TIMEOUT_SECONDS = 20"
    },
    docx: {
      header: "二进制快照 (.undo_history/20261126_项目周报.docx · 保留原段落 <w:r> 字体样式)",
      delLine: "- [表格第2行] 计划交付日期：待定",
      addLine: "+ [表格第2行] 计划交付日期：本周五（Summary!E12 已同步填入 =SUM(E2:E11)）"
    }
  };

  var state = {
    baseUrl: FALLBACK_BASE_URL,
    mcpUrl: FALLBACK_BASE_URL + "/mcp",
    readonlyUrl: FALLBACK_BASE_URL + "/mcp/readonly",
    isLiveSynced: false,
    localServiceDetected: false,
    deviceLabel: "",
    sessionsCount: 0,
    safetyMode: "full_dev",
    safetyLabel: "",
    userSelectedSafetyPill: false,
    statusKind: "offline",
    statusText: "",
    pairCode4: "----",
    pairCode6: "------",
    cfTemplateUrl: "https://dash.cloudflare.com/profile/api-tokens",
    gatewaysMap: null,
    enabledGatewayIds: [],
    readyGatewayIds: [],
    activeGatewayId: "",
    activeGatewayLabel: "",
    userPinnedGatewayId: "",
    lastStateDoc: null,
    activeMod: "mod-gemini",
    showAllModules: false,
    completedSteps: {},
    poseResetTimer: null,
    toastTimer: null,
    restingPose: "turn-right"
  };

  function $(id) {
    return document.getElementById(id);
  }

  function showToast(msg) {
    var banner = $("toast-banner");
    if (!banner) return;
    banner.textContent = msg;
    banner.classList.add("visible");
    if (state.toastTimer) clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(function () {
      banner.classList.remove("visible");
    }, 2200);
  }

  function syncThemeButtonLabel() {
    var cur = document.documentElement.getAttribute("data-theme") || "light";
    var tBtn = $("theme-toggle-btn");
    if (tBtn) {
      tBtn.textContent = cur === "dark" ? "浅色模式" : "深色模式";
    }
  }

  function applyTheme(themeName) {
    var eff = themeName === "dark" ? "dark" : "light";
    if (window.WebAI2PCBrand && typeof window.WebAI2PCBrand.setTheme === "function") {
      try {
        window.WebAI2PCBrand.setTheme(eff);
      } catch (e) {}
    }
    document.documentElement.setAttribute("data-theme", eff);
    try {
      localStorage.setItem(STUDIO_THEME_KEY, eff);
      localStorage.setItem(LEGACY_THEME_KEY, eff);
    } catch (e2) {}
    syncThemeButtonLabel();
  }

  function initTheme() {
    var initial = "light";
    if (window.WebAI2PCBrand && typeof window.WebAI2PCBrand.getState === "function") {
      try {
        var bs = window.WebAI2PCBrand.getState();
        if (bs && (bs.theme === "dark" || bs.theme === "light")) {
          initial = bs.theme;
        }
      } catch (e) {}
    } else {
      try {
        initial =
          localStorage.getItem(STUDIO_THEME_KEY) ||
          localStorage.getItem(LEGACY_THEME_KEY) ||
          document.documentElement.getAttribute("data-theme") ||
          "light";
      } catch (e2) {}
    }
    document.documentElement.setAttribute("data-theme", initial === "dark" ? "dark" : "light");
    syncThemeButtonLabel();

    if (typeof MutationObserver === "function") {
      var obs = new MutationObserver(function () {
        syncThemeButtonLabel();
      });
      obs.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    }

    var tBtn = $("theme-toggle-btn");
    if (tBtn) {
      tBtn.addEventListener("click", function () {
        var cur = document.documentElement.getAttribute("data-theme") || "light";
        applyTheme(cur === "dark" ? "light" : "dark");
      });
    }
  }

  function setBrandPose(poseName) {
    var targetPose = poseName || "turn-right";
    document.body.setAttribute("data-fallback-pose", targetPose);
    if (window.WebAI2PCBrand && typeof window.WebAI2PCBrand.setPose === "function") {
      try {
        window.WebAI2PCBrand.setPose(targetPose);
      } catch (e) {}
    }
    var mount = $("tut-appearance-switcher");
    if (mount) {
      var chips = mount.querySelectorAll("[data-fallback-pose-btn]");
      for (var i = 0; i < chips.length; i++) {
        var isMatch = chips[i].getAttribute("data-fallback-pose-btn") === targetPose;
        chips[i].classList.toggle("active", isMatch);
      }
    }
  }

  function triggerWorkingPose(durationMs) {
    var dur = typeof durationMs === "number" ? durationMs : 1350;
    setBrandPose("working");
    if (state.poseResetTimer) clearTimeout(state.poseResetTimer);
    state.poseResetTimer = setTimeout(function () {
      state.poseResetTimer = null;
      setBrandPose("turn-right");
    }, dur);
  }

  function initBrandAndAppearance() {
    var brandLoaded = false;
    if (window.WebAI2PCBrand && typeof window.WebAI2PCBrand.init === "function") {
      try {
        window.WebAI2PCBrand.init();
        brandLoaded = true;
      } catch (e) {
        brandLoaded = false;
      }
    }

    var switcherMount = $("tut-appearance-switcher");
    if (switcherMount && (!brandLoaded || switcherMount.children.length === 0)) {
      switcherMount.innerHTML =
        '<div class="tut-fallback-pose-bar" role="group" aria-label="IP 转向预览">' +
        '<button type="button" class="tut-pose-chip active" data-fallback-pose-btn="turn-right" title="默认向右朝向终端">朝右联动</button>' +
        '<button type="button" class="tut-pose-chip" data-fallback-pose-btn="front" title="正面注视">正面</button>' +
        '<button type="button" class="tut-pose-chip" data-fallback-pose-btn="working" title="专注执行态">执行态</button>' +
        "</div>";
      var btns = switcherMount.querySelectorAll("[data-fallback-pose-btn]");
      for (var i = 0; i < btns.length; i++) {
        btns[i].addEventListener("click", function (ev) {
          var p = ev.currentTarget.getAttribute("data-fallback-pose-btn") || "turn-right";
          if (p !== "working") {
            state.restingPose = p;
          }
          if (state.poseResetTimer) {
            clearTimeout(state.poseResetTimer);
            state.poseResetTimer = null;
          }
          setBrandPose(p);
        });
      }
    }

    if (!brandLoaded) {
      setBrandPose(state.restingPose);
    }

    var termBoxes = document.querySelectorAll('[data-pose-trigger="terminal"]');
    for (var j = 0; j < termBoxes.length; j++) {
      termBoxes[j].addEventListener("mouseenter", function () {
        triggerWorkingPose(1200);
      });
    }
  }

  function copyTextToClipboard(text, btnEl, toastMsg) {
    if (!text) return;
    triggerWorkingPose(1500);

    function onDone() {
      showToast(toastMsg || "已复制到剪贴板");
      if (btnEl && btnEl.tagName === "BUTTON") {
        var orig = btnEl.getAttribute("data-orig-label");
        if (!orig) {
          orig = btnEl.textContent;
          btnEl.setAttribute("data-orig-label", orig);
        }
        btnEl.textContent = "已复制 ✓";
        setTimeout(function () {
          btnEl.textContent = orig;
        }, 1400);
      }
    }

    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      navigator.clipboard.writeText(text).then(onDone).catch(function () {
        fallbackCopy(text, onDone);
      });
    } else {
      fallbackCopy(text, onDone);
    }
  }

  function fallbackCopy(text, cb) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "readonly");
    ta.style.position = "fixed";
    ta.style.top = "-9999px";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand("copy");
    } catch (e) {}
    document.body.removeChild(ta);
    if (cb) cb();
  }

  function isUsablePublicHttpsUrl(u) {
    if (!u || typeof u !== "string") return false;
    var s = u.trim();
    if (s.indexOf("https://") !== 0) return false;
    var low = s.toLowerCase();
    if (low.indexOf("https://127.0.0.1") === 0 || low.indexOf("https://localhost") === 0) {
      return false;
    }
    return true;
  }

  function normalizeSafetyTierKey(rawMode) {
    var m = String(rawMode || "").trim().toLowerCase();
    if (m === "readonly" || m === "tier1_readonly" || m === "l1") return "readonly";
    if (m === "edit_only" || m === "tier2_workspace_edit" || m === "l2") return "edit_only";
    if (m === "full_power" || m === "tier4_full_power" || m === "l4") return "full_power";
    if (m === "full_dev" || m === "workspace_dev" || m === "tier3_workspace_dev" || m === "l3") return "full_dev";
    return "";
  }

  function selectSafetyTierUI(tierKey) {
    var key = SAFETY_TIER_DESCRIPTIONS[tierKey] ? tierKey : "full_dev";
    var tierBtns = document.querySelectorAll("#safety-tier-bar [data-tier-key]");
    for (var i = 0; i < tierBtns.length; i++) {
      var active = tierBtns[i].getAttribute("data-tier-key") === key;
      tierBtns[i].classList.toggle("active", active);
      tierBtns[i].setAttribute("aria-selected", active ? "true" : "false");
    }
    var info = SAFETY_TIER_DESCRIPTIONS[key] || SAFETY_TIER_DESCRIPTIONS.full_dev;
    if ($("safety-detail-title")) $("safety-detail-title").textContent = info.title;
    if ($("safety-detail-desc")) $("safety-detail-desc").textContent = info.desc;
  }

  function applyGatewaySelectionFromDoc(doc) {
    var conn = (doc && doc.connection) || {};
    var gws =
      conn && conn.gateways && typeof conn.gateways === "object"
        ? conn.gateways
        : doc && doc.gateways && typeof doc.gateways === "object"
          ? doc.gateways
          : null;

    state.gatewaysMap = gws;
    state.enabledGatewayIds = [];
    state.readyGatewayIds = [];
    state.activeGatewayId = "";
    state.activeGatewayLabel = "";

    if (gws) {
      for (var i = 0; i < GATEWAY_ORDER.length; i++) {
        var gid = GATEWAY_ORDER[i];
        var slot = gws[gid];
        if (!slot || typeof slot !== "object") continue;
        if (slot.enabled) {
          state.enabledGatewayIds.push(gid);
          var candSlotUrl = slot.mcp_url || slot.public_url || "";
          if (slot.status === "ready" && slot.public_https_ready !== false && isUsablePublicHttpsUrl(candSlotUrl)) {
            state.readyGatewayIds.push(gid);
          }
        }
      }

      if (state.userPinnedGatewayId && state.readyGatewayIds.indexOf(state.userPinnedGatewayId) === -1) {
        state.userPinnedGatewayId = "";
      }

      var candidates = [
        state.userPinnedGatewayId,
        String(conn.user_selected_gateway || doc.user_selected_gateway || "").trim(),
        String(doc.display_gateway_id || conn.display_gateway_id || "").trim(),
        String(doc.selected_gateway || conn.selected_gateway || "").trim()
      ];
      var chosenId = "";
      for (var c = 0; c < candidates.length; c++) {
        if (candidates[c] && state.readyGatewayIds.indexOf(candidates[c]) !== -1) {
          chosenId = candidates[c];
          break;
        }
      }
      if (!chosenId && state.readyGatewayIds.length > 0) {
        chosenId = state.readyGatewayIds[0];
      }

      if (chosenId && gws[chosenId]) {
        var chosenSlot = gws[chosenId];
        var slotMcp = chosenSlot.mcp_url || "";
        var slotRo = chosenSlot.readonly_mcp_url || chosenSlot.mcp_readonly_url || "";
        var slotPub = chosenSlot.public_url || "";
        state.activeGatewayId = chosenId;
        state.activeGatewayLabel = chosenSlot.label_zh || GATEWAY_DEFAULT_LABELS[chosenId] || chosenId;
        if (isUsablePublicHttpsUrl(slotMcp)) {
          state.mcpUrl = slotMcp.trim();
          state.baseUrl = state.mcpUrl.replace(/\/mcp\/?$/, "");
          state.readonlyUrl = isUsablePublicHttpsUrl(slotRo) ? slotRo.trim() : state.baseUrl + "/mcp/readonly";
          state.isLiveSynced = true;
          return;
        }
        if (isUsablePublicHttpsUrl(slotPub)) {
          state.baseUrl = slotPub.trim().replace(/\/+$/, "");
          state.mcpUrl = state.baseUrl + "/mcp";
          state.readonlyUrl = isUsablePublicHttpsUrl(slotRo) ? slotRo.trim() : state.baseUrl + "/mcp/readonly";
          state.isLiveSynced = true;
          return;
        }
      }
    }

    var rawMcp = (doc && doc.mcp_url) || conn.mcp_url || "";
    var rawRo =
      (doc && (doc.readonly_mcp_url || doc.mcp_readonly_url)) ||
      conn.readonly_mcp_url ||
      conn.mcp_readonly_url ||
      "";
    var rawPub = conn.public_url || (doc && doc.public_url) || "";

    if (isUsablePublicHttpsUrl(rawMcp)) {
      state.mcpUrl = rawMcp.trim();
      state.baseUrl = state.mcpUrl.replace(/\/mcp\/?$/, "");
      state.readonlyUrl = isUsablePublicHttpsUrl(rawRo) ? rawRo.trim() : state.baseUrl + "/mcp/readonly";
      state.isLiveSynced = true;
    } else if (isUsablePublicHttpsUrl(rawPub)) {
      state.baseUrl = rawPub.trim().replace(/\/+$/, "");
      state.mcpUrl = state.baseUrl + "/mcp";
      state.readonlyUrl = isUsablePublicHttpsUrl(rawRo) ? rawRo.trim() : state.baseUrl + "/mcp/readonly";
      state.isLiveSynced = true;
    } else {
      state.baseUrl = FALLBACK_BASE_URL;
      state.mcpUrl = FALLBACK_BASE_URL + "/mcp";
      state.readonlyUrl = FALLBACK_BASE_URL + "/mcp/readonly";
      state.isLiveSynced = false;
    }
  }

  function renderGatewaySwitcherRow() {
    var row = $("live-gateway-switcher-row");
    if (!row) return;
    var gws = state.gatewaysMap;
    if (!gws || state.enabledGatewayIds.length === 0) {
      row.style.display = "none";
      row.innerHTML = "";
      return;
    }

    row.style.display = "flex";
    row.innerHTML = "";

    var labelSpan = document.createElement("span");
    labelSpan.className = "tut-gw-label";
    labelSpan.textContent =
      state.readyGatewayIds.length > 1
        ? "多网关同时在线（点击切换本页注入地址）："
        : "已开启连接通道（支持三类网关独立开关并存）：";
    row.appendChild(labelSpan);

    for (var i = 0; i < state.enabledGatewayIds.length; i++) {
      var gid = state.enabledGatewayIds[i];
      var slot = gws[gid] || {};
      var isReady = state.readyGatewayIds.indexOf(gid) !== -1;
      var isActive = gid === state.activeGatewayId;
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "tut-gw-pill" + (isActive ? " active" : "") + (!isReady ? " is-pending" : "");
      btn.disabled = !isReady;
      var slotTitle = slot.label_zh || GATEWAY_DEFAULT_LABELS[gid] || gid;
      var slotStateZh = slot.status_label_zh || (isReady ? "已连通" : "连接中");
      btn.textContent = slotTitle + " · " + slotStateZh;
      btn.setAttribute("data-tut-gw-id", gid);
      btn.title = isReady
        ? "点击将本页教程地址切换为：" + (slot.mcp_url || slot.public_url || "")
        : "该通道当前状态：" + slotStateZh;
      btn.addEventListener("click", function (ev) {
        var picked = ev.currentTarget.getAttribute("data-tut-gw-id") || "";
        if (!picked || state.readyGatewayIds.indexOf(picked) === -1) return;
        state.userPinnedGatewayId = picked;
        if (state.lastStateDoc) {
          applyGatewaySelectionFromDoc(state.lastStateDoc);
          renderLiveEndpoints();
          showToast("已切换教程示例地址至：" + state.mcpUrl);
        }
      });
      row.appendChild(btn);
    }
  }

  function renderLiveEndpoints() {
    var mcpNodes = document.querySelectorAll('[data-live-url="mcp"]');
    for (var i = 0; i < mcpNodes.length; i++) {
      mcpNodes[i].textContent = state.mcpUrl;
    }
    var roNodes = document.querySelectorAll('[data-live-url="readonly"]');
    for (var j = 0; j < roNodes.length; j++) {
      roNodes[j].textContent = state.readonlyUrl;
    }
    var openCgptBtns = document.querySelectorAll("[data-open-chatgpt-plugins]");
    for (var m = 0; m < openCgptBtns.length; m++) {
      openCgptBtns[m].disabled = !state.isLiveSynced;
    }
    var assistBtns = document.querySelectorAll("[data-copy-chatgpt-assist]");
    for (var k = 0; k < assistBtns.length; k++) {
      assistBtns[k].disabled = !state.isLiveSynced;
    }

    if ($("live-pair-code-4")) {
      $("live-pair-code-4").textContent = state.pairCode4 || "----";
    }
    if ($("live-pair-code-6")) {
      $("live-pair-code-6").textContent = state.pairCode6 || "------";
    }
    if ($("cf-template-link-btn") && state.cfTemplateUrl) {
      $("cf-template-link-btn").setAttribute("href", state.cfTemplateUrl);
    }

    renderGatewaySwitcherRow();

    var statusBadge = $("tut-status-badge");
    var statusDot = $("tut-status-dot");
    var statusText = $("tut-status-text");
    var subtitle = $("tut-brand-subtitle");
    var syncBadge = $("live-sync-badge");
    var deviceMeta = $("live-device-meta");

    if (state.isLiveSynced) {
      var kind = state.statusKind || "online";
      if (statusBadge) statusBadge.className = "status-badge " + kind;
      if (statusDot) statusDot.className = "status-dot " + kind;
      if (statusText) {
        statusText.textContent =
          (state.statusText || "本机服务在线") +
          (state.readyGatewayIds.length > 1 ? " · " + state.readyGatewayIds.length + " 路网关并存" : "") +
          (state.sessionsCount > 0 ? " · 已连 " + state.sessionsCount + " 会话" : "");
      }
      if (subtitle) {
        subtitle.textContent =
          "已同步本机 Studio：" +
          (state.deviceLabel || "本地节点") +
          (state.safetyLabel ? " · " + state.safetyLabel : "");
      }
      if (syncBadge) {
        syncBadge.className = "tag tag-ok";
        syncBadge.textContent = state.activeGatewayLabel ? "已就绪 · " + state.activeGatewayLabel : "已同步本机真实地址";
      }
      if (deviceMeta) {
        deviceMeta.textContent =
          "全页示例已自动替换为当前选中的就绪网关地址（已授权会话：" +
          String(state.sessionsCount) +
          "）；个人版 ChatGPT Plus/Pro 请复制右侧 /mcp/readonly 只读地址。";
      }
    } else {
      if (statusBadge) statusBadge.className = "status-badge offline";
      if (statusDot) statusDot.className = "status-dot offline";
      if (statusText) {
        statusText.textContent = state.localServiceDetected ? "本地未开公网网关" : "离线示例预览";
      }
      if (subtitle) {
        subtitle.textContent = state.localServiceDetected
          ? "已连接本地 Studio（" +
            (state.deviceLabel || "本机") +
            (state.safetyLabel ? " · " + state.safetyLabel : "") +
            "）· 开启任一连接卡片开关后自动替换真实公网地址"
          : "独立预览模式 · 在本地 Studio 打开 /tutorials 自动读取真实连接地址";
      }
      if (syncBadge) {
        syncBadge.className = state.localServiceDetected ? "tag tag-warn" : "tag tag-info";
        syncBadge.textContent = state.localServiceDetected ? "待开启公网 HTTPS" : "示例地址预览";
      }
      if (deviceMeta) {
        deviceMeta.textContent = state.localServiceDetected
          ? "检测到本地 Studio 在线但尚未就绪公网 HTTPS 网关，当前展示示例地址 " +
            FALLBACK_BASE_URL +
            "（个人版 ChatGPT 绑定 /mcp/readonly）。"
          : "当前未连接本地服务接口，展示标准示例地址 " +
            FALLBACK_BASE_URL +
            "（在本地 :8096/tutorials 打开即自动替换）。";
      }
    }
  }

  function syncStudioState(showManualToast) {
    if (typeof window.fetch !== "function") {
      renderLiveEndpoints();
      return;
    }
    var ctrl = typeof AbortController !== "undefined" ? new AbortController() : null;
    var timer = setTimeout(function () {
      if (ctrl) {
        try {
          ctrl.abort();
        } catch (e) {}
      }
    }, 1500);

    var opts = {
      method: "GET",
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    };
    if (ctrl) opts.signal = ctrl.signal;

    window
      .fetch("/api/studio/state", opts)
      .then(function (resp) {
        clearTimeout(timer);
        if (!resp || !resp.ok) throw new Error("http_" + (resp ? resp.status : 0));
        return resp.json();
      })
      .then(function (doc) {
        if (!doc || typeof doc !== "object") throw new Error("invalid_json");
        var conn = doc.connection || {};
        state.lastStateDoc = doc;
        state.localServiceDetected = true;
        state.deviceLabel = doc.device_label || "";
        state.safetyLabel = doc.safety_mode_label || "";
        state.statusKind = doc.status_kind || "online";
        state.statusText = doc.status_text || "本机服务在线";
        state.sessionsCount =
          typeof doc.authorized_sessions_count === "number"
            ? doc.authorized_sessions_count
            : typeof conn.authorized_sessions_count === "number"
              ? conn.authorized_sessions_count
              : 0;
        state.pairCode4 = doc.consent_pair_code || conn.consent_pair_code || conn.pair_code || "----";
        state.pairCode6 = doc.dynamic_pair_code || conn.dynamic_pair_code || "------";
        if (doc.cloudflare_token_template_url || conn.cloudflare_token_template_url) {
          state.cfTemplateUrl = doc.cloudflare_token_template_url || conn.cloudflare_token_template_url;
        }

        var mappedSafety = normalizeSafetyTierKey(doc.safety_mode || conn.safety_mode);
        if (mappedSafety) {
          state.safetyMode = mappedSafety;
          if (!state.userSelectedSafetyPill) {
            selectSafetyTierUI(mappedSafety);
          }
        }

        applyGatewaySelectionFromDoc(doc);
        renderLiveEndpoints();

        if (showManualToast) {
          showToast(
            state.isLiveSynced
              ? "已同步当前就绪网关地址：" + state.mcpUrl
              : "已读取本机状态，开启任一公网网关开关后将自动替换示例地址"
          );
        }
      })
      .catch(function () {
        clearTimeout(timer);
        state.lastStateDoc = null;
        state.localServiceDetected = false;
        state.isLiveSynced = false;
        state.gatewaysMap = null;
        state.enabledGatewayIds = [];
        state.readyGatewayIds = [];
        state.activeGatewayId = "";
        state.activeGatewayLabel = "";
        state.baseUrl = FALLBACK_BASE_URL;
        state.mcpUrl = FALLBACK_BASE_URL + "/mcp";
        state.readonlyUrl = FALLBACK_BASE_URL + "/mcp/readonly";
        renderLiveEndpoints();
        if (showManualToast) {
          showToast("未检测到本地 :8096 服务，当前使用示例地址预览");
        }
      });
  }

  function activateModule(modId, savePref) {
    if (MODULE_ORDER.indexOf(modId) === -1) modId = "mod-gemini";
    state.activeMod = modId;
    if (savePref !== false) {
      try {
        localStorage.setItem(ACTIVE_MOD_STORAGE_KEY, modId);
      } catch (e) {}
    }

    var sideBtns = document.querySelectorAll("#tut-side-nav [data-mod-target]");
    for (var i = 0; i < sideBtns.length; i++) {
      var active = sideBtns[i].getAttribute("data-mod-target") === modId;
      sideBtns[i].classList.toggle("active", active);
      sideBtns[i].setAttribute("aria-selected", active ? "true" : "false");
    }

    var mobPills = document.querySelectorAll("#tut-mobile-seg-nav [data-mod-target]");
    for (var j = 0; j < mobPills.length; j++) {
      var mActive = mobPills[j].getAttribute("data-mod-target") === modId;
      mobPills[j].classList.toggle("active", mActive);
      mobPills[j].setAttribute("aria-selected", mActive ? "true" : "false");
    }

    var panels = document.querySelectorAll(".tut-module");
    for (var k = 0; k < panels.length; k++) {
      panels[k].classList.toggle("active", panels[k].id === modId);
    }

    if (state.showAllModules) {
      var targetEl = $(modId);
      if (targetEl && typeof targetEl.scrollIntoView === "function") {
        targetEl.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }
  }

  function applyGlobalSearch(rawQuery) {
    var q = (rawQuery || "").trim().toLowerCase();
    var deskInput = $("tut-global-search");
    var mobInput = $("tut-mobile-search");
    if (deskInput && deskInput.value !== rawQuery) deskInput.value = rawQuery;
    if (mobInput && mobInput.value !== rawQuery) mobInput.value = rawQuery;

    var clearBtn = $("clear-global-search-btn");
    if (clearBtn) clearBtn.style.display = q ? "inline-flex" : "none";

    var statusBar = $("tut-search-status-bar");
    var statusText = $("tut-search-status-text");
    var panels = document.querySelectorAll(".tut-module");

    if (!q) {
      document.body.classList.toggle("tut-show-all", state.showAllModules);
      for (var i = 0; i < panels.length; i++) {
        panels[i].classList.remove("search-hidden");
      }
      if (statusBar) statusBar.style.display = "none";
      return;
    }

    document.body.classList.add("tut-show-all");
    var hitCount = 0;
    for (var j = 0; j < panels.length; j++) {
      var txt = (panels[j].textContent || "").toLowerCase();
      var matched = txt.indexOf(q) !== -1;
      panels[j].classList.toggle("search-hidden", !matched);
      if (matched) hitCount += 1;
    }

    if (statusBar && statusText) {
      statusBar.style.display = "flex";
      statusText.textContent =
        hitCount > 0
          ? "关键词「" + rawQuery.trim() + "」命中 " + hitCount + " 个教程模块"
          : "未找到包含「" + rawQuery.trim() + "」的教程内容，请尝试更换关键词";
    }
  }

  function loadSavedProgress() {
    try {
      var raw = localStorage.getItem(PROGRESS_STORAGE_KEY);
      if (raw) {
        var parsed = JSON.parse(raw);
        if (parsed && typeof parsed === "object") {
          state.completedSteps = parsed;
        }
      }
    } catch (e) {
      state.completedSteps = {};
    }
  }

  function saveProgress() {
    try {
      localStorage.setItem(PROGRESS_STORAGE_KEY, JSON.stringify(state.completedSteps));
    } catch (e) {}
  }

  function refreshProgressUI() {
    var totalSteps = 0;
    var doneSteps = 0;

    for (var m = 0; m < MODULE_ORDER.length; m++) {
      var modId = MODULE_ORDER[m];
      var ids = MODULE_STEP_MAP[modId] || [];
      var modDone = 0;
      for (var s = 0; s < ids.length; s++) {
        var sid = ids[s];
        totalSteps += 1;
        var isChecked = !!state.completedSteps[sid];
        if (isChecked) {
          doneSteps += 1;
          modDone += 1;
        }
        var chk = document.querySelector('.tut-step-chk[data-step-id="' + sid + '"]');
        if (chk) chk.checked = isChecked;
        var wrap = document.querySelector('[data-step-wrap="' + sid + '"]');
        if (wrap) wrap.classList.toggle("completed", isChecked);
      }

      var badge = document.querySelector('[data-mod-badge="' + modId + '"]');
      if (badge) {
        badge.textContent = modDone + "/" + ids.length;
        badge.classList.toggle("done", modDone === ids.length && ids.length > 0);
      }
    }

    var pct = totalSteps > 0 ? Math.round((doneSteps / totalSteps) * 100) : 0;
    if ($("tut-progress-text")) {
      $("tut-progress-text").textContent = doneSteps + " / " + totalSteps + " 步";
    }
    if ($("tut-progress-fill")) {
      $("tut-progress-fill").style.width = pct + "%";
    }
    if ($("tut-mobile-progress-pill")) {
      $("tut-mobile-progress-pill").textContent = doneSteps + "/" + totalSteps;
    }
  }

  function bindInteractiveWidgets() {
    document.addEventListener("click", function (ev) {
      var liveTarget = ev.target.closest("[data-copy-live]");
      if (liveTarget) {
        var kind = liveTarget.getAttribute("data-copy-live");
        var urlToCopy = kind === "readonly" ? state.readonlyUrl : state.mcpUrl;
        copyTextToClipboard(
          urlToCopy,
          liveTarget,
          kind === "readonly" ? "已复制个人版只读地址（仅限填入本人账号，请勿外发给他人或群聊）：" + urlToCopy : "已复制主连接地址（仅限填入本人账号，请勿外发给他人或群聊）：" + urlToCopy
        );
        return;
      }

      var openCgptTarget = ev.target.closest("[data-open-chatgpt-plugins]");
      if (openCgptTarget) {
        if (!state.isLiveSynced || !isUsablePublicHttpsUrl(state.mcpUrl)) {
          showToast("网关尚未就绪，请先在本地 Studio 开启任一公网 HTTPS 通道后再操作。");
          return;
        }
        var oKind = openCgptTarget.getAttribute("data-open-chatgpt-plugins");
        var oUrl = oKind === "readonly" ? state.readonlyUrl : state.mcpUrl;
        window.open("https://chatgpt.com/plugins", "_blank", "noopener");
        copyTextToClipboard(
          oUrl,
          openCgptTarget,
          "已复制连接地址并打开 ChatGPT 插件页（仅限填入本人账号，请勿外发给他人或群聊）：点 ＋ -> 添加自定义 MCP 服务器，名称填 WebAI2PC，粘贴地址后点「本机一键允许连接」"
        );
        return;
      }

      var assistTarget = ev.target.closest("[data-copy-chatgpt-assist]");
      if (assistTarget) {
        if (!state.isLiveSynced || !isUsablePublicHttpsUrl(state.mcpUrl)) {
          showToast("网关尚未就绪，请先在本地 Studio 开启任一公网 HTTPS 通道后再复制。");
          return;
        }
        var aKind = assistTarget.getAttribute("data-copy-chatgpt-assist") === "readonly" ? "readonly" : "mcp";
        var aUrl = aKind === "readonly" ? state.readonlyUrl : state.mcpUrl;
        var connDoc = (state.lastStateDoc && state.lastStateDoc.connection) || {};
        var rawPfx = String(
          (state.lastStateDoc && state.lastStateDoc.tool_prefix) || connDoc.tool_prefix || "pc"
        )
          .trim()
          .replace(/_+$/, "");
        if (!/^[A-Za-z][A-Za-z0-9_]{0,15}$/.test(rawPfx)) rawPfx = "pc";
        var statusTool = rawPfx + "_get_status";
        var statusHint =
          statusTool === "pc_get_status" || statusTool === "get_status"
            ? "pc_get_status"
            : statusTool + "（或 pc_get_status）";
        var scopeDesc =
          aKind === "readonly"
            ? "只读查看我本地授权目录的文件与状态"
            : "读写我本地授权目录的文件并执行本地开发工具";
        function buildTutOneclickPrompt(effUrl) {
          return [
            "[@Plugin Creator](plugin://plugin-creator@openai-curated-remote?remotePluginId=plugin_connector_1p_e1a10c53223481918a42f1510ec46c1e) 帮我创建一个插件，把我的本地电脑服务 WebAI2PC 接入当前 ChatGPT 账号，并完成首次调用验证（请在 Work 模式下执行；装好后日常可在 Chat 模式通过 @WebAI2PC 直接调用，不扣 Work/Codex 额度）。",
            "",
            "插件名称：WebAI2PC",
            "MCP 地址：" + effUrl,
            "服务说明：标准 Streamable HTTP MCP 服务（JSON-RPC 2.0，采用标准 OAuth 2.0 授权），用于" +
              scopeDesc +
              "；首次验证工具为 " +
              statusHint +
              "。",
            "",
            "执行要求：",
            "1. 请使用 @Plugin Creator 直接接入上述 MCP 地址创建并安装 WebAI2PC 插件，按服务端公布的 OAuth 元数据自动协商认证，需要我点授权确认时提示我操作。",
            "2. 插件就绪后，实际调用一次 " + statusHint + "，确认返回我电脑的主机名与当前工作区状态即可。",
            "",
            "安全提醒：上方包含本机专属连接地址，仅限发给本人登录的 ChatGPT 账号，请勿发往群聊、论坛、公开 Issue 或转给他人（若不慎外发可在本地控制台一键更换作废）。"
          ].join("\n");
        }
        var csrfTok = String((state.lastStateDoc && state.lastStateDoc.csrf_token) || "");
        var finishCopy = function (promptOrUrl, isFullPrompt) {
          var finalTxt = isFullPrompt ? promptOrUrl : buildTutOneclickPrompt(promptOrUrl);
          copyTextToClipboard(
            finalTxt,
            assistTarget,
            "已复制一键配置提示词（请粘贴发给 ChatGPT Work 模式；含本机专属地址，仅限本人账号使用，请勿发往群聊或公开帖子）"
          );
        };
        if (typeof window.fetch === "function" && csrfTok) {
          window
            .fetch("/api/studio/chatgpt-oneclick", {
              method: "POST",
              credentials: "same-origin",
              headers: {
                "Content-Type": "application/json",
                "X-Studio-Csrf": csrfTok
              },
              body: JSON.stringify({ kind: aKind, rotate: false, csrf: csrfTok })
            })
            .then(function (r) {
              return r.ok ? r.json() : null;
            })
            .then(function (d) {
              if (d && d.ok && typeof d.prompt === "string" && d.prompt.trim()) {
                finishCopy(d.prompt.trim(), true);
                return;
              }
              var ocUrl =
                d && d.ok && typeof d.mcp_url === "string" && d.mcp_url.indexOf("https://") === 0
                  ? d.mcp_url
                  : d && d.ok && typeof d.oneclick_url === "string" && d.oneclick_url.indexOf("https://") === 0
                  ? d.oneclick_url
                  : aUrl;
              finishCopy(ocUrl, false);
            })
            .catch(function () {
              finishCopy(aUrl, false);
            });
        } else {
          finishCopy(aUrl, false);
        }
        return;
      }

      var promptBtn = ev.target.closest("[data-copy-prompt]");
      if (promptBtn) {
        var promptText = promptBtn.getAttribute("data-copy-prompt") || "";
        copyTextToClipboard(promptText, promptBtn, "已复制，在 AI 对话框输入 @ 选你的连接器后粘贴即可");
        return;
      }

      var togglePrev = ev.target.closest("[data-toggle-prompt-preview]");
      if (togglePrev) {
        var card = togglePrev.closest(".prompt-card");
        var pre = card ? card.querySelector(".prompt-code-box") : null;
        if (pre) {
          var willShow = pre.hasAttribute("hidden");
          if (willShow) {
            pre.removeAttribute("hidden");
            togglePrev.setAttribute("aria-expanded", "true");
            togglePrev.textContent = "收起提示词";
          } else {
            pre.setAttribute("hidden", "");
            togglePrev.setAttribute("aria-expanded", "false");
            togglePrev.textContent = "查看提示词";
          }
        }
        return;
      }
    });

    if ($("sync-live-state-btn")) {
      $("sync-live-state-btn").addEventListener("click", function () {
        syncStudioState(true);
      });
    }
    if ($("toggle-view-mode-btn")) {
      $("toggle-view-mode-btn").addEventListener("click", function (ev) {
        state.showAllModules = !state.showAllModules;
        document.body.classList.toggle("tut-show-all", state.showAllModules);
        ev.currentTarget.textContent = state.showAllModules ? "切回单章聚焦" : "展开全部 6 章";
      });
    }

    var navBtns = document.querySelectorAll("[data-mod-target]");
    for (var i = 0; i < navBtns.length; i++) {
      navBtns[i].addEventListener("click", function (ev) {
        var targetMod = ev.currentTarget.getAttribute("data-mod-target");
        if (($("tut-global-search") && $("tut-global-search").value) || ($("tut-mobile-search") && $("tut-mobile-search").value)) {
          applyGlobalSearch("");
        }
        activateModule(targetMod, true);
      });
    }

    if ($("tut-global-search")) {
      $("tut-global-search").addEventListener("input", function (ev) {
        applyGlobalSearch(ev.target.value);
      });
    }
    if ($("tut-mobile-search")) {
      $("tut-mobile-search").addEventListener("input", function (ev) {
        applyGlobalSearch(ev.target.value);
      });
    }
    if ($("clear-global-search-btn")) {
      $("clear-global-search-btn").addEventListener("click", function () {
        applyGlobalSearch("");
      });
    }
    if ($("tut-clear-filter-btn")) {
      $("tut-clear-filter-btn").addEventListener("click", function () {
        applyGlobalSearch("");
      });
    }

    var chks = document.querySelectorAll(".tut-step-chk[data-step-id]");
    for (var c = 0; c < chks.length; c++) {
      chks[c].addEventListener("change", function (ev) {
        var sid = ev.currentTarget.getAttribute("data-step-id");
        if (!sid) return;
        if (ev.currentTarget.checked) {
          state.completedSteps[sid] = true;
          triggerWorkingPose(900);
        } else {
          delete state.completedSteps[sid];
        }
        saveProgress();
        refreshProgressUI();
      });
    }
    if ($("reset-progress-btn")) {
      $("reset-progress-btn").addEventListener("click", function () {
        state.completedSteps = {};
        saveProgress();
        refreshProgressUI();
        showToast("已重置全部教程打卡进度");
      });
    }

    var authBtns = document.querySelectorAll("[data-auth-mode]");
    for (var a = 0; a < authBtns.length; a++) {
      authBtns[a].addEventListener("click", function (ev) {
        var mode = ev.currentTarget.getAttribute("data-auth-mode");
        if ($("auth-tab-local")) $("auth-tab-local").classList.toggle("active", mode === "local");
        if ($("auth-tab-mobile")) $("auth-tab-mobile").classList.toggle("active", mode === "mobile");
        if ($("auth-preview-local")) $("auth-preview-local").style.display = mode === "local" ? "block" : "none";
        if ($("auth-preview-mobile")) $("auth-preview-mobile").style.display = mode === "mobile" ? "block" : "none";
        triggerWorkingPose(900);
      });
    }

    var cgptBtns = document.querySelectorAll("[data-cgpt-mode]");
    for (var g = 0; g < cgptBtns.length; g++) {
      cgptBtns[g].addEventListener("click", function (ev) {
        var m = ev.currentTarget.getAttribute("data-cgpt-mode");
        if ($("cgpt-tab-workspace")) $("cgpt-tab-workspace").classList.toggle("active", m === "workspace");
        if ($("cgpt-tab-personal")) $("cgpt-tab-personal").classList.toggle("active", m === "personal");
        if ($("cgpt-card-workspace")) $("cgpt-card-workspace").classList.toggle("recommended", m === "workspace");
        if ($("cgpt-card-personal")) $("cgpt-card-personal").classList.toggle("recommended", m === "personal");
      });
    }

    var painBtns = document.querySelectorAll("[data-channel-pick]");
    for (var p = 0; p < painBtns.length; p++) {
      painBtns[p].addEventListener("click", function (ev) {
        var pick = ev.currentTarget.getAttribute("data-channel-pick") || "1";
        for (var idx = 1; idx <= 3; idx++) {
          var b = $("pain-btn-" + idx);
          var pane = $("channel-pane-" + idx);
          var isCur = String(idx) === pick;
          if (b) {
            b.classList.toggle("active", isCur);
            b.setAttribute("aria-selected", isCur ? "true" : "false");
          }
          if (pane) {
            pane.classList.toggle("active", isCur);
          }
        }
        triggerWorkingPose(1000);
      });
    }

    var tplPills = document.querySelectorAll("#tpl-filter-bar [data-tpl-cat]");
    for (var t = 0; t < tplPills.length; t++) {
      tplPills[t].addEventListener("click", function (ev) {
        var cat = ev.currentTarget.getAttribute("data-tpl-cat") || "all";
        for (var x = 0; x < tplPills.length; x++) {
          tplPills[x].classList.toggle("active", tplPills[x] === ev.currentTarget);
        }
        var cards = document.querySelectorAll("#prompt-cards-grid [data-tpl-item]");
        for (var y = 0; y < cards.length; y++) {
          var itemCat = cards[y].getAttribute("data-tpl-item");
          cards[y].classList.toggle("filtered-out", cat !== "all" && itemCat !== cat);
        }
      });
    }

    var tierBtns = document.querySelectorAll("#safety-tier-bar [data-tier-key]");
    for (var sb = 0; sb < tierBtns.length; sb++) {
      tierBtns[sb].addEventListener("click", function (ev) {
        var key = ev.currentTarget.getAttribute("data-tier-key") || "full_dev";
        state.userSelectedSafetyPill = true;
        selectSafetyTierUI(key);
      });
    }

    var diffBtns = document.querySelectorAll("[data-diff-kind]");
    for (var df = 0; df < diffBtns.length; df++) {
      diffBtns[df].addEventListener("click", function (ev) {
        var kind = ev.currentTarget.getAttribute("data-diff-kind") || "py";
        if ($("diff-demo-py")) $("diff-demo-py").classList.toggle("active", kind === "py");
        if ($("diff-demo-docx")) $("diff-demo-docx").classList.toggle("active", kind === "docx");
        var snip = DIFF_DEMO_SNIPPETS[kind] || DIFF_DEMO_SNIPPETS.py;
        var viewer = $("diff-demo-viewer");
        if (viewer) {
          viewer.innerHTML = "";
          var headDiv = document.createElement("div");
          headDiv.style.color = "#8B949E";
          headDiv.style.marginBottom = "4px";
          headDiv.textContent = snip.header;
          var delSpan = document.createElement("span");
          delSpan.className = "diff-del";
          delSpan.textContent = snip.delLine;
          var addSpan = document.createElement("span");
          addSpan.className = "diff-add";
          addSpan.textContent = snip.addLine;
          viewer.appendChild(headDiv);
          viewer.appendChild(delSpan);
          viewer.appendChild(addSpan);
        }
        triggerWorkingPose(900);
      });
    }

    var activeTsCat = "all";
    function filterTroubleshooting() {
      var kwInput = $("troubleshoot-search-input");
      var kw = kwInput ? kwInput.value.trim().toLowerCase() : "";
      var items = document.querySelectorAll("#ts-items-list .ts-item");
      var visible = 0;
      for (var z = 0; z < items.length; z++) {
        var itemCat = items[z].getAttribute("data-ts-cat") || "";
        var text = (items[z].textContent || "").toLowerCase();
        var catOk = activeTsCat === "all" || itemCat === activeTsCat;
        var kwOk = !kw || text.indexOf(kw) !== -1;
        var show = catOk && kwOk;
        items[z].classList.toggle("filtered-out", !show);
        if (show && kw) items[z].open = true;
        if (show) visible += 1;
      }
      if ($("ts-empty-hint")) {
        $("ts-empty-hint").style.display = visible === 0 ? "block" : "none";
      }
    }

    if ($("troubleshoot-search-input")) {
      $("troubleshoot-search-input").addEventListener("input", filterTroubleshooting);
    }
    var tsPills = document.querySelectorAll("#ts-cat-bar [data-ts-cat]");
    for (var tp = 0; tp < tsPills.length; tp++) {
      tsPills[tp].addEventListener("click", function (ev) {
        activeTsCat = ev.currentTarget.getAttribute("data-ts-cat") || "all";
        for (var r = 0; r < tsPills.length; r++) {
          tsPills[r].classList.toggle("active", tsPills[r] === ev.currentTarget);
        }
        filterTroubleshooting();
      });
    }
  }

  function boot() {
    initBrandAndAppearance();
    initTheme();
    loadSavedProgress();
    refreshProgressUI();

    var savedMod = "mod-gemini";
    var hashMod = (window.location.hash || "").replace(/^#/, "");
    try {
      savedMod = localStorage.getItem(ACTIVE_MOD_STORAGE_KEY) || "mod-gemini";
    } catch (e) {}
    activateModule(MODULE_ORDER.indexOf(hashMod) !== -1 ? hashMod : savedMod, false);

    bindInteractiveWidgets();
    renderLiveEndpoints();
    syncStudioState(false);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
