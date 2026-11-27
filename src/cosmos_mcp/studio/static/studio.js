(function () {
  "use strict";

  var AT_CHAR = String.fromCharCode(64);
  var WAKE_TEST_PROMPT = AT_CHAR + "Cosmos 帮我看看当前工作目录里有哪些文件";

  function buildWakeTestPrompt() {
    var conn = (state && state.connection) || {};
    var rawName = String(conn.connector_name || "Cosmos").trim() || "Cosmos";
    if (rawName.charAt(0) === AT_CHAR) {
      rawName = rawName.slice(1);
    }
    return AT_CHAR + rawName + " 帮我看看当前工作目录里有哪些文件";
  }

  var state = {};
  var currentTreePath = "";
  var activeLogJobId = "";
  var pollTimer = null;
  var lastSessionsSignature = "";
  var prevAuthorizedCount = -1;
  var pendingServiceAction = "";
  var activeDiffTargetPath = "";
  var activeHostScene = "gemini";
  var activeCard3Subtab = "vps_hub";
  var pendingSaveModeOverride = "";
  var userPinnedGateway = "";
  var selectGwReqSeq = 0;
  var GATEWAY_ORDER = ["instant", "workers_dev", "self_hosted"];
  var GATEWAY_SHORT_LABELS = {
    instant: "免登录直连",
    workers_dev: "Cloudflare 网关",
    self_hosted: "自有服务器",
  };
  var discoveredDirsLoaded = false;
  var inFlightMutations = 0;
  var lastMutationAt = 0;
  var toolsSafetyReqSeq = 0;

  // Skills Center state
  var selectedSkillName = "";
  var selectedSkillScope = "";
  var currentPreviewToken = "";
  var currentPreviewFilesMap = {};

  // WebAI2PC Progressive Disclosure & Appearance State (decoupled from 4s pollOnce)
  var userConnExpandOverrides = {}; // {1: true|false, 2: true|false, 3: true|false}
  var lastLiveEnabledMask = "";
  var userPickedCard3Subtab = false;
  var userToggledGeminiGuide = false;
  var userManuallyPickedPose = false;
  var lastAppliedDynamicPose = "";
  var activeCoreToolsFilter = "all";
  var coreToolsCollapsed = false;
  var activeAuditFilter = "all";
  var auditSearchQuery = "";

  function $(id) {
    return document.getElementById(id);
  }

  function syncThemeButtonText(eff) {
    var tBtn = $("theme-toggle-btn");
    if (tBtn) {
      tBtn.textContent = eff === "dark" ? "浅色模式" : "深色模式";
    }
  }

  function applyTheme(themeName) {
    var eff = themeName === "dark" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", eff);
    syncThemeButtonText(eff);
    try {
      localStorage.setItem("cosmos_studio_theme", eff);
      localStorage.setItem("webai2pc_theme", eff);
    } catch (e) {}
    if (window.WebAI2PCBrand && typeof window.WebAI2PCBrand.setTheme === "function") {
      var curBrand = window.WebAI2PCBrand.getState ? window.WebAI2PCBrand.getState() : null;
      if (!curBrand || curBrand.theme !== eff) {
        window.WebAI2PCBrand.setTheme(eff);
      }
    }
  }

  function syncIpWorkingPose(doc) {
    if (userManuallyPickedPose) return;
    var conn = (doc && doc.connection) || state.connection || {};
    var sessArr = (doc && doc.authorized_sessions) || conn.authorized_sessions || [];
    var sessCnt =
      doc && typeof doc.authorized_sessions_count === "number"
        ? doc.authorized_sessions_count
        : typeof conn.authorized_sessions_count === "number"
        ? conn.authorized_sessions_count
        : sessArr.length;
    var tk = (doc && doc.tasks) || state.tasks || {};
    var runJobs = (tk.jobs || []).filter(function (j) {
      return Boolean(j && j.running);
    }).length;
    if (doc && typeof doc.running_tasks_count === "number") {
      runJobs = doc.running_tasks_count;
    }

    var basePose = "turn-right";
    if (window.WebAI2PCBrand && typeof window.WebAI2PCBrand.getState === "function") {
      var bst = window.WebAI2PCBrand.getState();
      if (bst && bst.pose) basePose = bst.pose;
    }
    var wantPose = runJobs > 0 || inFlightMutations > 0 || sessCnt > 0 ? "working" : basePose;
    if (wantPose === lastAppliedDynamicPose) return;
    lastAppliedDynamicPose = wantPose;

    document.documentElement.setAttribute("data-ip-pose", wantPose);
    var hdrLogo = $("header-brand-logo");
    if (hdrLogo) {
      if (wantPose === "working") {
        hdrLogo.setAttribute("data-slot-pose", "working");
      } else {
        hdrLogo.removeAttribute("data-slot-pose");
      }
      if (window.WebAI2PCBrand && typeof window.WebAI2PCBrand.mountAll === "function") {
        window.WebAI2PCBrand.mountAll(hdrLogo);
      }
    }
  }

  function initTheme() {
    var saved = "light";
    try {
      saved =
        localStorage.getItem("cosmos_studio_theme") ||
        localStorage.getItem("webai2pc_theme") ||
        "light";
    } catch (e) {}
    if (window.WebAI2PCBrand && typeof window.WebAI2PCBrand.getState === "function") {
      var st = window.WebAI2PCBrand.getState();
      if (st && (st.theme === "dark" || st.theme === "light")) {
        saved = st.theme;
      }
    }
    applyTheme(saved);
    window.addEventListener("webai2pc:appearance-change", function (ev) {
      var detail = ev && ev.detail ? ev.detail : null;
      var domTheme = (detail && detail.theme) || document.documentElement.getAttribute("data-theme") || "light";
      syncThemeButtonText(domTheme);
      if (!userManuallyPickedPose && lastAppliedDynamicPose === "working") {
        document.documentElement.setAttribute("data-ip-pose", "working");
      }
    });
    document.addEventListener("click", function (ev) {
      var poseBtn = ev.target && ev.target.closest ? ev.target.closest("[data-w2p-pose]") : null;
      if (poseBtn && !poseBtn.disabled) {
        userManuallyPickedPose = true;
        var hdrLogo = $("header-brand-logo");
        if (hdrLogo) hdrLogo.removeAttribute("data-slot-pose");
      }
    });
    var connTopCard = $("host-connection-top-card");
    if (connTopCard) {
      connTopCard.addEventListener("mouseenter", function () {
        document.documentElement.style.setProperty("--ip-gaze-x", "1.8px");
      });
      connTopCard.addEventListener("mouseleave", function () {
        document.documentElement.style.removeProperty("--ip-gaze-x");
      });
    }
  }

  function computeEnabledGroupMap(connObj) {
    var conn = connObj || state.connection || {};
    var gws = conn.gateways || state.gateways || null;
    if (gws && typeof gws === "object") {
      return {
        1: Boolean(gws.instant && gws.instant.enabled),
        2: Boolean(gws.workers_dev && gws.workers_dev.enabled),
        3: Boolean(gws.self_hosted && gws.self_hosted.enabled),
      };
    }
    var m = String(conn.tunnel_mode || state.tunnel_mode || "public_gateway");
    var eff = m === "reverse_proxy" ? "custom" : m;
    return {
      1: ["public_gateway", "srv_us", "cloudflare"].indexOf(eff) >= 0,
      2: eff === "workers_dev",
      3: ["vps_hub", "vps", "cloudflare_token", "custom"].indexOf(eff) >= 0,
    };
  }

  function syncConnCardAccordionDOM(enabledMap) {
    var eMap = enabledMap || computeEnabledGroupMap(state.connection || {});
    var maskNow = [eMap[1] ? "1" : "0", eMap[2] ? "1" : "0", eMap[3] ? "1" : "0"].join("");
    if (lastLiveEnabledMask === "") {
      // Initial load: keep primary enabled card (or Card 1 by default) expanded, keep unconfigured others compact
      if (userConnExpandOverrides[1] === undefined) {
        var anyEnabled = Boolean(eMap[1] || eMap[2] || eMap[3]);
        if (eMap[1] || !anyEnabled) {
          userConnExpandOverrides[1] = true;
        } else if (eMap[2]) {
          userConnExpandOverrides[2] = true;
        } else if (eMap[3]) {
          userConnExpandOverrides[3] = true;
        }
      }
      lastLiveEnabledMask = maskNow;
    } else if (maskNow !== lastLiveEnabledMask) {
      lastLiveEnabledMask = maskNow;
    }

    [1, 2, 3].forEach(function (g) {
      var card = $("conn-card-" + g);
      if (!card) return;
      var shouldOpen =
        userConnExpandOverrides[g] !== undefined
          ? Boolean(userConnExpandOverrides[g])
          : g === 1;
      card.classList.toggle("expanded-card", shouldOpen);
      var hdr = card.querySelector(".conn-card-header-bar");
      if (hdr) hdr.setAttribute("aria-expanded", shouldOpen ? "true" : "false");
      var btn = card.querySelector(".conn-expand-toggle");
      if (btn) {
        btn.textContent = shouldOpen ? "收起详情 ▴" : (eMap[g] ? "查看详情 ▾" : "展开配置 ▾");
      }
    });
  }

  function setConnCardExpanded(groupNum, expandVal) {
    userConnExpandOverrides[groupNum] = Boolean(expandVal);
    syncConnCardAccordionDOM(computeEnabledGroupMap(state.connection || {}));
  }

  function updateTabTelemetryBadges(doc) {
    var conn = (doc && doc.connection) || state.connection || {};
    var effTop = resolveEffectiveTopView(conn);
    var sessArr = (doc && doc.authorized_sessions) || conn.authorized_sessions || [];
    var sessCnt =
      doc && typeof doc.authorized_sessions_count === "number"
        ? doc.authorized_sessions_count
        : typeof conn.authorized_sessions_count === "number"
        ? conn.authorized_sessions_count
        : sessArr.length;
    var bOv = $("tab-badge-overview");
    if (bOv) {
      bOv.textContent = sessCnt > 0 ? "已连 " + sessCnt : effTop.public_https_ready ? "就绪" : "待连";
      bOv.className = "tab-count-pill" + (sessCnt > 0 ? " pill-live-ok" : "");
    }

    var ws = (doc && doc.workspaces) || state.workspaces || {};
    var wsCnt = (ws.roots || []).length;
    if ($("tab-badge-workspace")) {
      $("tab-badge-workspace").textContent = String(wsCnt || 0);
    }

    var sMode = (doc && doc.safety_mode) || state.safety_mode || "full_dev";
    var bTools = $("tab-badge-tools");
    if (bTools) {
      var modeShortMap = { full_dev: "工作区", full_power: "全盘", edit_only: "仅改", readonly: "只读" };
      bTools.textContent = modeShortMap[sMode] || "工作区";
      bTools.className = "tab-count-pill" + (sMode === "readonly" ? " pill-live-warn" : "");
    }

    var tk = (doc && doc.tasks) || state.tasks || {};
    var rec = (doc && doc.recovery) || state.recovery || {};
    var runJobs = (tk.jobs || []).filter(function (j) {
      return Boolean(j && j.running);
    }).length;
    if (doc && typeof doc.running_tasks_count === "number") runJobs = doc.running_tasks_count;
    var snapCnt = (rec.snapshots || []).length;
    var bRec = $("tab-badge-recovery");
    if (bRec) {
      bRec.textContent = runJobs > 0 ? runJobs + " 运行" : String(snapCnt);
      bRec.className = "tab-count-pill" + (runJobs > 0 ? " pill-live-warn" : "");
    }

    var sk = (doc && doc.skills) || state.skills || {};
    var skTotal =
      typeof sk.total_all_count === "number"
        ? sk.total_all_count
        : typeof sk.count === "number"
        ? sk.count
        : typeof sk.total === "number"
        ? sk.total
        : (sk.items || []).length;
    if ($("tab-badge-skills")) {
      $("tab-badge-skills").textContent = String(skTotal || 0);
    }
  }

  function applyCoreToolsFilter() {
    var grid = $("core-tools-grid");
    if (!grid) return;
    grid.classList.toggle("collapsed-grid", coreToolsCollapsed);
    var tgBtn = $("toggle-core-tools-btn");
    if (tgBtn) {
      tgBtn.textContent = coreToolsCollapsed ? "展开列表 ▾" : "收起列表 ▴";
    }
    grid.querySelectorAll(".tool-card").forEach(function (card) {
      var band = card.getAttribute("data-tool-band") || "readonly";
      var match = activeCoreToolsFilter === "all" || band === activeCoreToolsFilter;
      card.classList.toggle("tool-card-filtered-out", !match);
    });
  }

  function applyAuditFilter() {
    var ul = $("audit-events-list");
    if (!ul) return;
    var q = String(auditSearchQuery || "").trim().toLowerCase();
    ul.querySelectorAll(".item-row").forEach(function (li) {
      var isOk = li.getAttribute("data-audit-ok") === "1";
      var hay = (li.getAttribute("data-audit-search") || "").toLowerCase();
      var passStatus = activeAuditFilter === "all" || !isOk;
      var passQuery = !q || hay.indexOf(q) >= 0;
      li.classList.toggle("audit-filtered-out", !(passStatus && passQuery));
    });
  }

  function formatLocalTime(raw) {
    if (raw === null || raw === undefined) return "-";
    var s = String(raw).trim();
    if (!s || s === "-") return "-";
    if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?$/.test(s)) {
      return s;
    }
    var d = null;
    if (/^\d+(\.\d+)?$/.test(s)) {
      var num = parseFloat(s);
      if (num > 1e14) num = num / 1000000;
      else if (num > 1e11) num = num / 1000;
      d = new Date(num * 1000);
    } else {
      d = new Date(s);
    }
    if (!d || isNaN(d.getTime())) {
      return s.slice(0, 19).replace("T", " ");
    }
    function pad(n) {
      return n < 10 ? "0" + n : String(n);
    }
    return (
      d.getFullYear() +
      "-" +
      pad(d.getMonth() + 1) +
      "-" +
      pad(d.getDate()) +
      " " +
      pad(d.getHours()) +
      ":" +
      pad(d.getMinutes()) +
      ":" +
      pad(d.getSeconds())
    );
  }

  function showToast(msg, isErr) {
    var box = $("toast-banner");
    if (!box || !msg) return;
    box.textContent = msg;
    box.className = "toast-banner visible " + (isErr ? "err" : "ok");
    clearTimeout(box._hideTimer);
    box._hideTimer = setTimeout(function () {
      box.className = "toast-banner";
    }, 4500);
  }

  function getTypedPassword() {
    var inp = $("session-pw-input");
    if (inp && inp.value.trim()) return inp.value.trim();
    var rem = $("remote-pw-input");
    if (rem && rem.value.trim()) return rem.value.trim();
    return "";
  }

  function apiFetch(url, opts) {
    var options = opts || {};
    var method = (options.method || "GET").toUpperCase();
    var headers = Object.assign(
      {
        Accept: "application/json",
        "X-Studio-Csrf": state.csrf_token || "",
      },
      options.headers || {}
    );
    var pw = getTypedPassword();
    if (pw) {
      headers["X-Cosmos-Password"] = pw;
    }
    var fetchOpts = {
      method: method,
      headers: headers,
      credentials: "same-origin",
    };
    if (options.body !== undefined) {
      headers["Content-Type"] = "application/json";
      var payload = Object.assign({}, options.body, { csrf: state.csrf_token || "" });
      if (pw && !payload.owner_password) {
        payload.owner_password = pw;
      }
      fetchOpts.body = JSON.stringify(payload);
    }
    var isMutation = method !== "GET";
    if (isMutation) {
      inFlightMutations += 1;
      lastMutationAt = Date.now();
      syncIpWorkingPose(state);
    }
    return fetch(url, fetchOpts).then(
      function (resp) {
        if (isMutation) {
          inFlightMutations = Math.max(0, inFlightMutations - 1);
          lastMutationAt = Date.now();
          syncIpWorkingPose(state);
        }
        return resp
          .json()
          .catch(function () {
            return { ok: false, error: "服务响应解析失败（HTTP " + resp.status + "）" };
          })
          .then(function (doc) {
            doc._httpStatus = resp.status;
            return doc;
          });
      },
      function (err) {
        if (isMutation) {
          inFlightMutations = Math.max(0, inFlightMutations - 1);
          lastMutationAt = Date.now();
          syncIpWorkingPose(state);
        }
        throw err;
      }
    );
  }

  function copyText(text, btn) {
    if (!text) return;
    var orig = btn ? btn.getAttribute("data-orig") || btn.textContent : "";
    if (btn) btn.setAttribute("data-orig", orig);
    function finish(ok) {
      if (btn) {
        btn.setAttribute("data-copying", "1");
        btn.textContent = ok ? "已复制 ✓" : "请手动复制";
        setTimeout(function () {
          btn.removeAttribute("data-copying");
          btn.textContent = btn.getAttribute("data-orig") || orig;
        }, 1500);
      }
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        function () {
          finish(true);
        },
        function () {
          finish(false);
        }
      );
    } else {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try {
        ok = document.execCommand("copy");
      } catch (e) {}
      document.body.removeChild(ta);
      finish(ok);
    }
  }

  function setStatusIndicator(kind, text) {
    var badge = $("service-status-badge");
    var dot = $("service-status-dot");
    var txt = $("service-status-text");
    var validKind = ["online", "editonly", "readonly", "offline"].indexOf(kind) >= 0 ? kind : "online";
    if (badge) badge.className = "status-badge " + validKind;
    if (dot) dot.className = "status-dot " + validKind;
    if (txt && txt.textContent !== (text || "")) txt.textContent = text || "";
  }

  function updateFirstWakeBanner(sessCount) {
    var banner = $("first-wake-banner");
    var cnt = Number(sessCount || 0);
    var dismissed = false;
    try {
      dismissed = localStorage.getItem("cosmos_wake_banner_dismissed") === "1";
    } catch (e) {}
    if (banner) {
      if (cnt >= 1 && !dismissed) {
        banner.style.display = "block";
        if (prevAuthorizedCount === 0) {
          banner.classList.add("just-connected");
        }
      } else {
        banner.style.display = "none";
        banner.classList.remove("just-connected");
      }
    }
    var gDet = $("gemini-https-guide-details");
    var gSumTxt = $("gemini-guide-summary-text");
    if (gDet && !userToggledGeminiGuide) {
      gDet.open = cnt <= 0;
    }
    if (gSumTxt) {
      gSumTxt.textContent = cnt >= 1 ? "Gemini 两步绑定说明（已连接成功）" : "Gemini 两步绑定说明";
    }
    prevAuthorizedCount = cnt;
  }

  function switchHostScene(scene) {
    var target = scene === "chatgpt" ? "chatgpt" : "gemini";
    activeHostScene = target;
    document.querySelectorAll("#host-scene-switcher .host-seg-btn").forEach(function (btn) {
      var active = btn.getAttribute("data-host-scene") === target;
      btn.classList.toggle("active", active);
      btn.setAttribute("aria-selected", active ? "true" : "false");
    });
    if ($("host-panel-gemini")) {
      $("host-panel-gemini").classList.toggle("active", target === "gemini");
    }
    if ($("host-panel-chatgpt")) {
      $("host-panel-chatgpt").classList.toggle("active", target === "chatgpt");
    }
    var conn = (state && state.connection) || {};
    renderConnectionGuides(conn);
    updateConnectionCardsUI(conn.tunnel_mode || state.tunnel_mode || "public_gateway", conn);
  }

  function switchCard3Subtab(subName, modeOverride) {
    activeCard3Subtab = subName === "custom_domain" ? "custom_domain" : "vps_hub";
    if (modeOverride) {
      pendingSaveModeOverride = modeOverride;
    }
    document.querySelectorAll(".card3-subtab-btn").forEach(function (btn) {
      var isAct = btn.getAttribute("data-c3-tab") === activeCard3Subtab;
      btn.classList.toggle("active", isAct);
      btn.setAttribute("aria-selected", isAct ? "true" : "false");
    });
    if ($("c3-pane-vps-hub")) {
      $("c3-pane-vps-hub").classList.toggle("active", activeCard3Subtab === "vps_hub");
    }
    if ($("c3-pane-custom-domain")) {
      $("c3-pane-custom-domain").classList.toggle("active", activeCard3Subtab === "custom_domain");
    }
  }

  function isSafeHttpsUrl(u) {
    var s = String(u || "").trim();
    return s.indexOf("https://") === 0;
  }

  function deriveReadonlyUrl(slot, fallbackMcp) {
    var directRo = slot && (slot.readonly_mcp_url || slot.mcp_readonly_url);
    if (isSafeHttpsUrl(directRo)) {
      return String(directRo).trim();
    }
    if (isSafeHttpsUrl(fallbackMcp)) {
      return String(fallbackMcp).trim().replace(/\/mcp\/?$/, "/mcp/readonly");
    }
    return "";
  }

  function resolveEffectiveTopView(connObj) {
    var conn = connObj || (state && state.connection) || {};
    var gws = conn.gateways || (state && state.gateways) || null;
    if (gws && typeof gws === "object") {
      var enabledIds = [];
      var readyIds = [];
      GATEWAY_ORDER.forEach(function (gid) {
        var sl = gws[gid];
        if (sl && sl.enabled) {
          enabledIds.push(gid);
          if (sl.status === "ready" && sl.public_https_ready && isSafeHttpsUrl(sl.mcp_url)) {
            readyIds.push(gid);
          }
        }
      });

      if (!enabledIds.length) {
        userPinnedGateway = "";
        return {
          hasGateways: true,
          displayId: "",
          slot: null,
          enabledIds: [],
          readyIds: [],
          tunnel_mode: "local",
          public_https_ready: false,
          mcp_url: "",
          readonly_mcp_url: "",
          tunnel_error: "",
        };
      }

      if (userPinnedGateway && enabledIds.indexOf(userPinnedGateway) < 0) {
        userPinnedGateway = "";
      }
      var backendPin = String(conn.user_selected_gateway || "").trim();
      var effPin = userPinnedGateway || (enabledIds.indexOf(backendPin) >= 0 ? backendPin : "");
      var selGw = String(conn.selected_gateway || state.selected_gateway || "").trim();
      var dispCand = String(conn.display_gateway_id || state.display_gateway_id || "").trim();

      var displayId = "";
      if (effPin && enabledIds.indexOf(effPin) >= 0) {
        displayId = effPin;
      } else if (dispCand && readyIds.indexOf(dispCand) >= 0) {
        displayId = dispCand;
      } else if (selGw && readyIds.indexOf(selGw) >= 0) {
        displayId = selGw;
      } else if (readyIds.length > 0) {
        displayId = readyIds[0];
      } else if (dispCand && enabledIds.indexOf(dispCand) >= 0) {
        displayId = dispCand;
      } else if (selGw && enabledIds.indexOf(selGw) >= 0) {
        displayId = selGw;
      } else {
        displayId = enabledIds[0];
      }

      var slot = gws[displayId] || {};
      var slotReady = Boolean(slot.status === "ready" && slot.public_https_ready && isSafeHttpsUrl(slot.mcp_url));
      var effMcp = slotReady ? String(slot.mcp_url).trim() : "";
      var effRo = slotReady ? deriveReadonlyUrl(slot, effMcp) : "";
      return {
        hasGateways: true,
        displayId: displayId,
        slot: slot,
        enabledIds: enabledIds,
        readyIds: readyIds,
        tunnel_mode: String(slot.submode || conn.tunnel_mode || "public_gateway"),
        public_https_ready: slotReady,
        mcp_url: effMcp,
        readonly_mcp_url: effRo,
        tunnel_error: slotReady ? "" : String(slot.last_error || ""),
      };
    }

    var legacyMode = String(conn.tunnel_mode || state.tunnel_mode || "public_gateway");
    var rawMcp = isSafeHttpsUrl(conn.mcp_url) ? String(conn.mcp_url).trim() : "";
    var rawRo = deriveReadonlyUrl(conn, rawMcp);
    var legacyReady = Boolean(conn.public_https_ready && rawMcp);
    return {
      hasGateways: false,
      displayId: "",
      slot: null,
      enabledIds: legacyMode === "local" ? [] : ["instant"],
      readyIds: legacyReady ? ["instant"] : [],
      tunnel_mode: legacyMode,
      public_https_ready: legacyReady,
      mcp_url: legacyReady ? rawMcp : "",
      readonly_mcp_url: legacyReady ? rawRo : "",
      tunnel_error: String(conn.tunnel_error || ""),
    };
  }

  function renderTopGatewaySwitcher(conn, effTop) {
    var bar = $("top-gateway-switcher");
    if (!bar) return;
    var gws = (conn && conn.gateways) || (state && state.gateways) || null;
    if (!gws || !effTop || !effTop.enabledIds || effTop.enabledIds.length === 0) {
      bar.style.display = "none";
      bar.innerHTML = "";
      bar.removeAttribute("data-enabled-key");
      return;
    }
    bar.style.display = "flex";
    var enabledKey = effTop.enabledIds.join(",");
    if (bar.getAttribute("data-enabled-key") !== enabledKey) {
      bar.innerHTML = "";
      bar.setAttribute("data-enabled-key", enabledKey);

      var lbl = document.createElement("span");
      lbl.className = "switcher-label";
      bar.appendChild(lbl);

      effTop.enabledIds.forEach(function (gid) {
        var pill = document.createElement("button");
        pill.type = "button";
        pill.id = "top-gw-tab-" + gid;
        pill.setAttribute("data-select-gw", gid);

        var dot = document.createElement("span");
        dot.className = "gw-tab-dot";
        pill.appendChild(dot);

        var txt = document.createElement("span");
        txt.className = "gw-tab-txt";
        pill.appendChild(txt);

        pill.addEventListener("click", function () {
          var mySeq = ++selectGwReqSeq;
          userPinnedGateway = gid;
          if (state && state.connection) {
            state.connection.user_selected_gateway = gid;
          }
          renderConnectionGuides((state && state.connection) || {});
          apiFetch("/api/studio/connection", {
            method: "POST",
            body: { action: "select_copy_gateway", gateway_id: gid },
          }).then(function (d) {
            if (mySeq !== selectGwReqSeq) return;
            if (d && d.ok) {
              renderAll(d);
            }
          });
        });
        bar.appendChild(pill);
      });
    }

    var lblNode = bar.querySelector(".switcher-label");
    if (lblNode) {
      var wantLbl = effTop.enabledIds.length > 1 ? "连接通道" : "当前通道";
      if (lblNode.textContent !== wantLbl) lblNode.textContent = wantLbl;
    }

    effTop.enabledIds.forEach(function (gid) {
      var sl = gws[gid] || {};
      var st = String(sl.status || "connecting");
      var stLabel = sl.status_label_zh || (st === "ready" ? "已连通" : st === "error" ? "异常" : "连接中");
      var pill = $("top-gw-tab-" + gid);
      if (!pill) return;
      var cls = "gw-tab-pill";
      if (gid === effTop.displayId) cls += " active";
      if (st === "ready") cls += " is-ready";
      else if (st === "error") cls += " is-error";
      if (pill.className !== cls) pill.className = cls;

      var dot = pill.querySelector(".gw-tab-dot");
      if (dot && dot.className !== "gw-tab-dot " + st) {
        dot.className = "gw-tab-dot " + st;
      }
      var txt = pill.querySelector(".gw-tab-txt");
      var baseName = GATEWAY_SHORT_LABELS[gid] || sl.label_zh || gid;
      var wantTxt = st === "ready" ? baseName : baseName + " · " + stLabel;
      pill.title = baseName + "（" + stLabel + "，点击切换上方连接地址）";
      if (txt && txt.textContent !== wantTxt) {
        txt.textContent = wantTxt;
      }
    });
  }

  function renderConnectionGuides(conn) {
    var effTop = resolveEffectiveTopView(conn);
    renderTopGatewaySwitcher(conn, effTop);

    var tMode = effTop.tunnel_mode;
    var rawMcp = effTop.mcp_url;
    var rawRo = effTop.readonly_mcp_url;
    var isHttpsReady = Boolean(effTop.public_https_ready && rawMcp);

    var waitingText =
      tMode === "local" ? "尚未开启公网 HTTPS 连接通道" : "正在建立加密连接通道…";
    var displayMcp = isHttpsReady ? rawMcp : waitingText;
    var displayRo = isHttpsReady && rawRo ? rawRo : waitingText;

    ["mcp-url-box", "chatgpt-full-url-box"].forEach(function (id) {
      var box = $(id);
      if (box) {
        if (box.textContent !== displayMcp) box.textContent = displayMcp;
        box.classList.toggle("https-ready", isHttpsReady);
        box.classList.toggle("loopback-muted", !isHttpsReady);
      }
    });
    var roBox = $("ro-url-box");
    if (roBox) {
      if (roBox.textContent !== displayRo) roBox.textContent = displayRo;
      roBox.classList.toggle("https-ready", isHttpsReady);
      roBox.classList.toggle("loopback-muted", !isHttpsReady);
    }

    [
      "copy-mcp-url-btn",
      "copy-ro-url-btn",
      "copy-chatgpt-full-btn",
      "open-chatgpt-plugins-full-btn",
      "open-chatgpt-plugins-ro-btn",
      "copy-chatgpt-assist-ro-btn",
      "copy-chatgpt-assist-full-btn",
    ].forEach(function (btnId) {
      var b = $(btnId);
      if (b) b.disabled = !isHttpsReady;
    });

    var quickUrlBtn = $("quick-bar-copy-url-btn");
    if (quickUrlBtn) {
      if (isHttpsReady && !state.locked) {
        var shortHost = rawMcp.replace(/^https:\/\//, "");
        if (shortHost.length > 28) {
          shortHost = shortHost.slice(0, 14) + "…" + shortHost.slice(-12);
        }
        quickUrlBtn.style.display = "inline-flex";
        if (!quickUrlBtn.hasAttribute("data-copying")) {
          var qLabel = "复制 " + shortHost;
          quickUrlBtn.textContent = qLabel;
          quickUrlBtn.setAttribute("data-orig", qLabel);
        }
      } else {
        quickUrlBtn.style.display = "none";
      }
    }

    var localGuide = $("local-loopback-guide");
    var geminiGuide = $("gemini-https-guide");
    var cardDesc = $("conn-card-desc");
    var copyMcpBtn = $("copy-mcp-url-btn");

    if (tMode === "local") {
      if (localGuide) localGuide.style.display = "block";
      if (geminiGuide) geminiGuide.style.display = "none";
      if (cardDesc) {
        cardDesc.textContent = "当前未开启公网 HTTPS 通道，点击下方按钮或打开任一网关开关即可连接网页版 Gemini 与 ChatGPT。";
      }
    } else if (isHttpsReady) {
      if (localGuide) localGuide.style.display = "none";
      if (geminiGuide) geminiGuide.style.display = "block";
      if (cardDesc) {
        cardDesc.textContent = "公网 HTTPS 连接地址已就绪，请复制对应地址填入网页版 Gemini 或网页版 ChatGPT。";
      }
      if (copyMcpBtn && !copyMcpBtn.hasAttribute("data-copying")) {
        copyMcpBtn.className = "btn btn-primary";
        copyMcpBtn.textContent = "复制 Gemini 连接地址";
        copyMcpBtn.setAttribute("data-orig", "复制 Gemini 连接地址");
      }
    } else {
      if (localGuide) localGuide.style.display = "none";
      if (geminiGuide) geminiGuide.style.display = "block";
      if (cardDesc) {
        cardDesc.textContent = "正在建立加密连接通道，就绪后自动显示公网 HTTPS 地址（可先查看下方绑定步骤与操作守则）…";
      }
    }

    var cfTplUrl = conn.cloudflare_token_template_url || state.cloudflare_token_template_url || "";
    if (cfTplUrl && $("open-cf-template-btn")) {
      $("open-cf-template-btn").href = cfTplUrl;
    }

    var chErrBox = $("channel-tunnel-error-box");
    if (chErrBox) {
      if (!effTop.hasGateways && effTop.tunnel_error) {
        chErrBox.style.display = "block";
        chErrBox.textContent = "连接通道提示：" + effTop.tunnel_error;
      } else {
        chErrBox.style.display = "none";
        chErrBox.textContent = "";
      }
    }

    var callout = $("overview-channel-callout");
    if (!callout) return;
    if (effTop.tunnel_error) {
      callout.style.display = "block";
      callout.className = "callout callout-danger";
      callout.textContent = "加密通道连接异常：" + effTop.tunnel_error;
    } else if (tMode !== "local" && !isHttpsReady) {
      callout.style.display = "block";
      callout.className = "callout callout-info";
      callout.textContent = "正在建立加密连接通道…（通常需数秒，就绪后上方地址框将自动变为绿色可复制状态）";
    } else {
      callout.style.display = "none";
    }
  }

  function renderSingleGatewayCardSlot(gid, cardEl, slot) {
    if (!slot) return;
    var enabled = Boolean(slot.enabled);
    var st = String(slot.status || (enabled ? "connecting" : "disabled"));
    var stLabel =
      slot.status_label_zh ||
      (st === "ready" ? "已连通" : st === "error" ? "异常" : st === "connecting" ? "连接中" : "未开启");

    var pill = $("gw-pill-" + gid);
    if (pill) {
      pill.className = "gw-status-pill is-" + st;
      pill.textContent = stLabel;
    }
    var sw = $("gw-switch-" + gid);
    if (sw) {
      sw.checked = enabled;
      sw.setAttribute("aria-checked", enabled ? "true" : "false");
    }
    if (cardEl) {
      cardEl.classList.toggle("active-card", enabled);
      cardEl.classList.toggle("is-enabled", enabled);
      cardEl.classList.toggle("is-ready", st === "ready");
      cardEl.classList.toggle("is-error", st === "error");
    }

    var errBox = $("gw-err-" + gid);
    if (errBox) {
      var errTxt = enabled ? String(slot.last_error || "").trim() : "";
      if (errTxt) {
        errBox.style.display = "block";
        errBox.textContent = errTxt;
      } else {
        errBox.style.display = "none";
        errBox.textContent = "";
      }
    }

    var urlRow = $("gw-url-row-" + gid);
    var urlBox = $("gw-url-" + gid);
    var copyBtn = $("gw-copy-" + gid);
    var copyRoBtn = $("gw-copy-ro-" + gid);
    if (urlRow && urlBox && copyBtn) {
      var readyMcp = st === "ready" && isSafeHttpsUrl(slot.mcp_url) ? String(slot.mcp_url).trim() : "";
      var readyRo = readyMcp ? deriveReadonlyUrl(slot, readyMcp) : "";
      var cfgBase = isSafeHttpsUrl(slot.configured_url) ? String(slot.configured_url).trim() : "";
      var isGptScene = activeHostScene === "chatgpt";
      var fullCopyLbl = isGptScene ? "复制 Team 全权限" : "复制此卡地址";

      if (!copyBtn.hasAttribute("data-copying")) {
        copyBtn.textContent = fullCopyLbl;
        copyBtn.setAttribute("data-orig", fullCopyLbl);
      }
      if (copyRoBtn) {
        copyRoBtn.style.display = isGptScene && enabled ? "inline-flex" : "none";
        if (!copyRoBtn.hasAttribute("data-copying")) {
          copyRoBtn.textContent = "复制 Plus/Pro 只读";
          copyRoBtn.setAttribute("data-orig", "复制 Plus/Pro 只读");
        }
      }

      if (enabled) {
        urlRow.style.display = "flex";
        if (readyMcp) {
          urlBox.textContent = readyMcp;
          urlBox.className = "gw-card-url-box is-ready";
          copyBtn.disabled = false;
          copyBtn.setAttribute("data-url", readyMcp);
          if (copyRoBtn) {
            copyRoBtn.disabled = !readyRo;
            copyRoBtn.setAttribute("data-url", readyRo);
          }
        } else {
          urlBox.textContent = cfgBase ? cfgBase + "/mcp（正在连接…）" : "正在建立连接通道…";
          urlBox.className = "gw-card-url-box";
          copyBtn.disabled = true;
          copyBtn.setAttribute("data-url", "");
          if (copyRoBtn) {
            copyRoBtn.disabled = true;
            copyRoBtn.setAttribute("data-url", "");
          }
        }
      } else if (cfgBase) {
        urlRow.style.display = "flex";
        urlBox.textContent = cfgBase + "/mcp（未开启）";
        urlBox.className = "gw-card-url-box";
        copyBtn.disabled = true;
        copyBtn.setAttribute("data-url", "");
        if (copyRoBtn) {
          copyRoBtn.style.display = "none";
          copyRoBtn.disabled = true;
          copyRoBtn.setAttribute("data-url", "");
        }
      } else {
        urlRow.style.display = "none";
        urlBox.textContent = "-";
        copyBtn.disabled = true;
        copyBtn.setAttribute("data-url", "");
        if (copyRoBtn) {
          copyRoBtn.style.display = "none";
          copyRoBtn.disabled = true;
          copyRoBtn.setAttribute("data-url", "");
        }
      }
    }
  }

  function updateConnectionCardsUI(selectedMode, connObj) {
    var conn = connObj || state.connection || {};
    var gws = conn.gateways || state.gateways || null;
    var effMode = selectedMode === "reverse_proxy" ? "custom" : selectedMode || "public_gateway";

    var card1 = $("conn-card-1");
    var card2 = $("conn-card-2");
    var card3 = $("conn-card-3");

    var instSlot = (gws && gws.instant) || {
      enabled: ["public_gateway", "srv_us", "cloudflare"].indexOf(effMode) >= 0,
      submode: effMode === "cloudflare" ? "cloudflare" : "public_gateway",
      status: conn.public_https_ready ? "ready" : conn.tunnel_error ? "error" : "connecting",
      public_https_ready: Boolean(conn.public_https_ready),
      mcp_url: conn.mcp_url || "",
      readonly_mcp_url: conn.readonly_mcp_url || conn.mcp_readonly_url || "",
      configured_url: conn.public_url || "",
      srvus_fixed_active: Boolean(conn.srvus_fixed_active !== undefined ? conn.srvus_fixed_active : state.srvus_fixed_active),
      instant_fallback_active: Boolean(conn.instant_fallback_active !== undefined ? conn.instant_fallback_active : state.instant_fallback_active),
      public_gateway_online: Boolean(conn.public_gateway_online !== undefined ? conn.public_gateway_online : state.public_gateway_online),
      last_error: conn.tunnel_error || "",
    };
    var wdSlot = (gws && gws.workers_dev) || {
      enabled: effMode === "workers_dev",
      submode: "workers_dev",
      status: effMode === "workers_dev" ? (conn.public_https_ready ? "ready" : conn.tunnel_error ? "error" : "connecting") : "disabled",
      public_https_ready: Boolean(effMode === "workers_dev" && conn.public_https_ready),
      mcp_url: effMode === "workers_dev" ? conn.mcp_url || "" : "",
      readonly_mcp_url: effMode === "workers_dev" ? conn.readonly_mcp_url || conn.mcp_readonly_url || "" : "",
      configured_url: conn.workers_dev_url || "",
      last_error: effMode === "workers_dev" ? conn.tunnel_error || "" : "",
    };
    var shSlot = (gws && gws.self_hosted) || {
      enabled: ["vps_hub", "vps", "cloudflare_token", "custom"].indexOf(effMode) >= 0,
      submode: ["vps_hub", "vps", "cloudflare_token", "custom"].indexOf(effMode) >= 0 ? effMode : "vps_hub",
      status:
        ["vps_hub", "vps", "cloudflare_token", "custom"].indexOf(effMode) >= 0
          ? conn.public_https_ready
            ? "ready"
            : conn.tunnel_error
            ? "error"
            : "connecting"
          : "disabled",
      public_https_ready: Boolean(
        ["vps_hub", "vps", "cloudflare_token", "custom"].indexOf(effMode) >= 0 && conn.public_https_ready
      ),
      mcp_url: ["vps_hub", "vps", "cloudflare_token", "custom"].indexOf(effMode) >= 0 ? conn.mcp_url || "" : "",
      readonly_mcp_url: ["vps_hub", "vps", "cloudflare_token", "custom"].indexOf(effMode) >= 0 ? conn.readonly_mcp_url || conn.mcp_readonly_url || "" : "",
      configured_url: conn.vps_hub_url || "",
      last_error:
        ["vps_hub", "vps", "cloudflare_token", "custom"].indexOf(effMode) >= 0 ? conn.tunnel_error || "" : "",
    };

    renderSingleGatewayCardSlot("instant", card1, instSlot);
    renderSingleGatewayCardSlot("workers_dev", card2, wdSlot);
    renderSingleGatewayCardSlot("self_hosted", card3, shSlot);

    syncConnCardAccordionDOM({
      1: Boolean(instSlot.enabled),
      2: Boolean(wdSlot.enabled),
      3: Boolean(shSlot.enabled),
    });

    var instEnabled = Boolean(instSlot.enabled);
    var instSub = String(instSlot.submode || "public_gateway");
    var isExplicitQuick = instEnabled && instSub === "cloudflare";
    var pubGwOnline = Boolean(
      instSlot.public_gateway_online !== undefined ? instSlot.public_gateway_online : conn.public_gateway_online
    );
    var srvusFixed = Boolean(instEnabled && !isExplicitQuick && instSlot.srvus_fixed_active);
    var fallbackActive = Boolean(
      instEnabled && (isExplicitQuick || (!srvusFixed && (instSlot.instant_fallback_active !== undefined ? instSlot.instant_fallback_active : !pubGwOnline)))
    );
    var autoFallbackActive = Boolean(
      instEnabled && !isExplicitQuick && !srvusFixed && !pubGwOnline && fallbackActive
    );

    var b1 = $("card1-status-badge");
    if (b1) {
      if (isExplicitQuick) {
        b1.className = "tag tag-warn";
        b1.textContent = "临时快速通道（重启会变网址）";
      } else if (instEnabled) {
        b1.className = "tag tag-ok";
        b1.textContent = "当前使用中";
      } else {
        b1.className = "tag tag-muted";
        b1.textContent = "零配置可用";
      }
    }
    var actBtn1 = $("activate-card1-btn");
    if (actBtn1) {
      if (!instEnabled) {
        actBtn1.disabled = false;
        actBtn1.className = "btn btn-tonal";
        actBtn1.textContent = "开启一键上手网关";
      } else if (isExplicitQuick) {
        actBtn1.disabled = false;
        actBtn1.className = "btn btn-primary";
        actBtn1.textContent = "恢复免登录固定网址（推荐）";
      } else if (autoFallbackActive) {
        actBtn1.disabled = false;
        actBtn1.className = "btn btn-tonal";
        actBtn1.textContent = "重试连接免登录固定网址";
      } else {
        actBtn1.disabled = true;
        actBtn1.className = "btn btn-tonal";
        actBtn1.textContent = "当前正在使用此方式";
      }
    }
    var quickSwitchBtn = $("switch-card1-quick-btn");
    if (quickSwitchBtn) {
      quickSwitchBtn.style.display =
        instEnabled && instSub === "public_gateway" && (srvusFixed || pubGwOnline) ? "inline-flex" : "none";
    }

    var nodeId = conn.node_id || state.node_id || "-";
    if ($("card1-node-id-text")) $("card1-node-id-text").textContent = nodeId;
    if ($("card1-fixed-gw-box")) {
      $("card1-fixed-gw-box").style.display = instEnabled && !isExplicitQuick && pubGwOnline && !srvusFixed && !fallbackActive ? "block" : "none";
    }
    if ($("card1-srvus-fixed-box")) {
      $("card1-srvus-fixed-box").style.display = srvusFixed ? "block" : "none";
    }
    var fbBox = $("card1-instant-fallback-box");
    if (fbBox) {
      fbBox.style.display = instEnabled && !pubGwOnline && !srvusFixed && fallbackActive ? "block" : "none";
      if (isExplicitQuick) {
        fbBox.className = "callout callout-warn";
        fbBox.innerHTML =
          "当前处于临时快速通道（<code>*.trycloudflare.com</code>，重启会变网址）；点击下方「恢复免登录固定网址（推荐）」可切回固定网址（<code>*.srv.us</code>），或同时开启第 2 类 Cloudflare 网关。";
      } else {
        fbBox.className = "callout callout-ok";
        fbBox.innerHTML =
          "当前为免登录临时网址（<code>*.trycloudflare.com</code>，重启会变）；连上免登录固定网址（<code>*.srv.us</code>）或部署第 2 类 Cloudflare 网关后可导出永久恢复卡。";
      }
    }
    var hasExportableFixedIdentity = Boolean(
      srvusFixed || pubGwOnline || Boolean(conn.workers_dev_url) || Boolean(wdSlot.configured_url) || Boolean(wdSlot.enabled)
    );
    if ($("open-export-id-modal-btn")) {
      $("open-export-id-modal-btn").style.display = hasExportableFixedIdentity ? "inline-flex" : "none";
    }

    var b2 = $("card2-status-badge");
    if (b2) {
      b2.className = "tag " + (wdSlot.enabled ? "tag-ok" : "tag-info");
      b2.textContent = wdSlot.enabled ? "已启用" : "终身固定推荐";
    }
    var savedWdUrl = wdSlot.configured_url || conn.workers_dev_url || "";
    if ($("cf-saved-hint-box")) {
      $("cf-saved-hint-box").style.display = isSafeHttpsUrl(savedWdUrl) && !wdSlot.enabled ? "block" : "none";
    }
    var cfCustomInp = $("cf-custom-domain-input");
    if (conn.workers_dev_custom_domain && cfCustomInp && document.activeElement !== cfCustomInp && !cfCustomInp.value) {
      cfCustomInp.value = conn.workers_dev_custom_domain;
    }

    var b3 = $("card3-status-badge");
    if (b3) {
      b3.className = "tag " + (shSlot.enabled ? "tag-ok" : "tag-muted");
      b3.textContent = shSlot.enabled ? "已启用" : "服务器 / 域名";
    }

    var shSub = String(shSlot.submode || "vps_hub");
    if (shSlot.enabled && !userPickedCard3Subtab && !pendingSaveModeOverride) {
      if (shSub === "vps_hub") {
        switchCard3Subtab("vps_hub");
      } else if (["custom", "cloudflare_token", "vps"].indexOf(shSub) >= 0) {
        switchCard3Subtab("custom_domain", shSub);
      }
    }

    var shCfgBase = isSafeHttpsUrl(shSlot.configured_url || conn.public_base || conn.public_url)
      ? shSlot.configured_url || conn.public_base || conn.public_url
      : "";
    if ($("cf-token-input")) {
      $("cf-token-input").placeholder = conn.tunnel_token_configured
        ? "已保存固定令牌（留空保持不变）"
        : "粘贴 eyJ... 令牌（仅已反代域名可留空）";
    }
    var customUrlInp = $("custom-url-input");
    if (shCfgBase && ["custom", "cloudflare_token"].indexOf(shSub) >= 0 && customUrlInp && document.activeElement !== customUrlInp && !customUrlInp.value) {
      customUrlInp.value = shCfgBase;
    }
    var vpsSshInp = $("vps-ssh-input");
    if (conn.vps_ssh && vpsSshInp && document.activeElement !== vpsSshInp && !vpsSshInp.value) {
      vpsSshInp.value = conn.vps_ssh;
    }
    var vpsKeyInp = $("vps-prov-key-input");
    if (conn.vps_identity_file && vpsKeyInp && document.activeElement !== vpsKeyInp && !vpsKeyInp.value) {
      vpsKeyInp.value = conn.vps_identity_file;
    }
    var vpsPortInp = $("vps-remote-port-input");
    if (conn.vps_remote_port && vpsPortInp && document.activeElement !== vpsPortInp && vpsPortInp.value === "18096") {
      vpsPortInp.value = String(conn.vps_remote_port);
    }
    var vpsPubInp = $("vps-public-url-input");
    if (shCfgBase && shSub === "vps" && vpsPubInp && document.activeElement !== vpsPubInp && !vpsPubInp.value) {
      vpsPubInp.value = shCfgBase;
    }
  }

  function applyToolsSafetyLinkage(safetyMode, tc) {
    var isReadonly = safetyMode === "readonly";
    var isEditOnly = safetyMode === "edit_only";
    var isFullPower = safetyMode === "full_power";
    var execLocked = isReadonly || isEditOnly || Boolean(tc.exec_locked);

    var wsFullPowerBanner = $("workspace-fullpower-banner");
    if (wsFullPowerBanner) {
      wsFullPowerBanner.style.display = isFullPower ? "block" : "none";
    }

    var quickRoBtn = $("quick-readonly-btn");
    if (quickRoBtn) {
      quickRoBtn.style.display = isReadonly ? "none" : "inline-flex";
      quickRoBtn.disabled = isReadonly;
    }
    var quickRestoreBtn = $("quick-restore-dev-btn");
    if (quickRestoreBtn) {
      quickRestoreBtn.style.display = isReadonly ? "inline-flex" : "none";
      quickRestoreBtn.disabled = !isReadonly;
    }

    var popChk = $("chk-confirm-popups");
    var popBox = $("confirm-popups-box");
    var popHint = $("confirm-popups-ro-hint");
    if (popChk) {
      popChk.checked = isReadonly ? false : Boolean(tc.confirm_popups);
      popChk.disabled = isReadonly;
    }
    if (popBox) popBox.classList.toggle("disabled-switch", isReadonly);
    if (popHint) {
      popHint.style.display = isReadonly ? "inline-flex" : "none";
      popHint.textContent = "只读模式下自动关闭";
    }

    var bChk = $("chk-pack-browser");
    var bBox = $("pack-browser-box");
    var bHint = $("pack-browser-ro-hint");
    if (bChk) {
      bChk.checked = execLocked ? false : Boolean(tc.pack_browser);
      bChk.disabled = execLocked;
    }
    if (bBox) bBox.classList.toggle("disabled-switch", execLocked);
    if (bHint) {
      bHint.style.display = execLocked ? "inline-flex" : "none";
      bHint.textContent = isReadonly ? "只读模式下自动关闭" : "禁跑命令模式下自动关闭";
    }

    var dChk = $("chk-pack-desktop");
    var dBox = $("pack-desktop-box");
    var dHint = $("pack-desktop-ro-hint");
    if (dChk) {
      dChk.checked = execLocked ? false : Boolean(tc.pack_desktop);
      dChk.disabled = execLocked;
    }
    if (dBox) dBox.classList.toggle("disabled-switch", execLocked);
    if (dHint) {
      dHint.style.display = execLocked ? "inline-flex" : "none";
      dHint.textContent = isReadonly ? "只读模式下自动关闭" : "禁跑命令模式下自动关闭";
    }

    if ($("chk-scan-host-skills")) {
      var scanVal =
        tc.scan_host_global_skills !== undefined
          ? Boolean(tc.scan_host_global_skills)
          : Boolean(state.scan_host_global_skills);
      $("chk-scan-host-skills").checked = scanVal;
    }
    if ($("chk-tray-enabled")) {
      var trayVal =
        tc.tray_enabled !== undefined
          ? Boolean(tc.tray_enabled)
          : state.tray_enabled !== undefined
          ? Boolean(state.tray_enabled)
          : true;
      $("chk-tray-enabled").checked = trayVal;
    }
    var tpInput = $("tool-prefix-input");
    if (tpInput && document.activeElement !== tpInput) {
      tpInput.value = tc.tool_prefix || state.tool_prefix || "pc";
    }
  }

  function renderAll(doc) {
    if (!doc || typeof doc !== "object") return;
    state = doc;

    if (doc.flash_notice) showToast(doc.flash_notice, false);
    if (doc.flash_error) showToast(doc.flash_error, true);

    setStatusIndicator(doc.status_kind || "online", doc.status_text || "在线运行");
    if (doc.device_label && $("brand-subtitle")) {
      $("brand-subtitle").textContent =
        "本机设备：" + doc.device_label + " · 版本 v" + (doc.product_version || "1.0.0");
    }

    var lockPanel = $("remote-lock-panel");
    var mainContent = $("studio-main-content");
    if (doc.locked) {
      if (lockPanel) lockPanel.style.display = "block";
      if (mainContent) mainContent.style.display = "none";
      return;
    }
    if (lockPanel) lockPanel.style.display = "none";
    if (mainContent) mainContent.style.display = "block";

    var sBar = $("session-unlock-bar");
    var sText = $("session-bar-text");
    var sForm = $("session-unlock-form");
    var sLockBtn = $("session-lock-btn");
    if (sBar) {
      if (doc.unlocked || doc.is_loopback) {
        sBar.className = "session-bar unlocked";
        sBar.style.display = doc.is_loopback ? "none" : "flex";
        if (sText) {
          sText.textContent = doc.is_loopback
            ? "本机直连已自动授权"
            : "远程管理会话已解锁 · 当前窗口所有操作直接生效";
        }
        if (sForm) sForm.style.display = "none";
        if (sLockBtn) sLockBtn.style.display = doc.is_loopback ? "none" : "inline-flex";
        if ($("session-pw-input")) $("session-pw-input").value = "";
      } else {
        sBar.className = "session-bar";
        sBar.style.display = "flex";
        if (sText) sText.textContent = "输入一次管理口令解锁修改权限（整个会话免重复输入）：";
        if (sForm) sForm.style.display = "flex";
        if (sLockBtn) sLockBtn.style.display = "none";
      }
    }

    // Tab 1: Overview, Wake Banner, 2 Hosts & 3 Multi-Gateway Accordion Cards
    var conn = doc.connection || {};
    if (conn.user_selected_gateway !== undefined) {
      userPinnedGateway = conn.user_selected_gateway || "";
    }
    renderConnectionGuides(conn);

    var dynCode = conn.dynamic_pair_code || doc.dynamic_pair_code || "------";
    if ($("dynamic-pair-code-box")) $("dynamic-pair-code-box").textContent = dynCode;
    if ($("copy-dynamic-code-btn")) {
      $("copy-dynamic-code-btn").disabled = !dynCode || dynCode === "------";
    }

    var pCode = conn.consent_pair_code || conn.pair_code || doc.consent_pair_code || "----";
    if ($("pair-code-box")) $("pair-code-box").textContent = pCode;
    if ($("copy-pair-code-btn")) {
      $("copy-pair-code-btn").disabled = !pCode || pCode === "----";
    }

    var sessArr = conn.authorized_sessions || doc.authorized_sessions || [];
    var sessCnt = typeof conn.authorized_sessions_count === "number" ? conn.authorized_sessions_count : sessArr.length;
    if ($("sessions-count")) $("sessions-count").textContent = String(sessCnt);
    if ($("revoke-sessions-btn")) {
      $("revoke-sessions-btn").disabled = sessCnt <= 0;
    }
    updateFirstWakeBanner(sessCnt);

    if ($("chk-keep-awake")) $("chk-keep-awake").checked = !!conn.keep_awake;
    if ($("chk-autostart")) $("chk-autostart").checked = !!conn.autostart_enabled;
    if ($("chk-wake-autostart")) $("chk-wake-autostart").checked = !!conn.autostart_enabled;

    var pwBox = $("conn-pw-box");
    if (pwBox) {
      pwBox.setAttribute("data-secret", conn.connection_password || "");
      if (pwBox.getAttribute("data-shown") === "1") {
        pwBox.textContent = conn.connection_password || "(未记录明文口令)";
      } else {
        pwBox.textContent = "••••••••••••••••••••";
      }
    }

    updateConnectionCardsUI(conn.tunnel_mode || "public_gateway", conn);
    lastSessionsSignature = JSON.stringify({ s: sessArr, m: doc.safety_mode || "full_dev" });
    renderAuthorizedSessions(sessArr);

    // Tab 2: Workspaces & Python
    var ws = doc.workspaces || {};
    renderWorkspaces(ws.roots || [], ws.primary || "", ws.access_modes || {});
    renderPythonCandidates(ws.python_candidates || [], ws.python_path || "");
    if (!discoveredDirsLoaded) {
      discoveredDirsLoaded = true;
      loadDiscoveredWorkspaces();
    }

    // Tab 3: Tools & Safety
    var tc = doc.tools_center || {};
    var sMode = doc.safety_mode || "full_dev";
    renderSafetyCards(sMode);
    applyToolsSafetyLinkage(sMode, tc);

    var coreToolsList = tc.core_tools || [];
    var coreCount = Number(tc.core_count || coreToolsList.length || 16);
    if ($("core-tools-title")) {
      $("core-tools-title").textContent = "默认 " + coreCount + " 项核心工具说明";
    }
    if ($("core-tools-desc")) {
      $("core-tools-desc").textContent =
        "开箱内置覆盖代码阅读、精准编辑、无窗口命令执行、公开资料检索与技能管理的 " +
        coreCount +
        " 项核心工具。";
    }
    renderCoreTools(coreToolsList);

    // Tab 4: Tasks & Recovery
    var tk = doc.tasks || {};
    renderTasks(tk.jobs || []);
    var rec = doc.recovery || {};
    renderRecovery(rec.snapshots || [], rec.trash_items || [], rec.audit_events || []);

    // Tab 5: Skills & Telemetry
    renderSkills(doc.skills || {});
    updateTabTelemetryBadges(doc);
    syncIpWorkingPose(doc);
    if ($("save-python-btn")) $("save-python-btn").classList.remove("is-dirty-unsaved");
    if ($("save-tool-prefix-btn")) $("save-tool-prefix-btn").classList.remove("is-dirty-unsaved");
  }

  function resolveSessionScopeBadge(sess) {
    var scopes = Array.isArray(sess.scopes)
      ? sess.scopes.map(function (x) {
          return String(x || "").toLowerCase();
        })
      : [];
    var isRo = Boolean(
      sess.readonly ||
        scopes.indexOf("readonly") >= 0 ||
        scopes.indexOf("mcp:readonly") >= 0 ||
        scopes.indexOf("read_only") >= 0
    );
    var tempSuffix = sess.temporary_session ? " · 临时会话" : "";
    if (isRo) {
      var roTxt = sess.scope_label && sess.scope_label.indexOf("只读") >= 0 ? sess.scope_label : "仅只读权限" + tempSuffix;
      return { cls: "tag tag-warn", text: roTxt };
    }
    if (scopes.indexOf("edit_only") >= 0 || scopes.indexOf("mcp:edit_only") >= 0) {
      return { cls: "tag tag-info", text: "仅改文件（禁跑命令）" + tempSuffix };
    }
    if (scopes.indexOf("full_power") >= 0 || scopes.indexOf("mcp:full_power") >= 0) {
      return { cls: "tag tag-ok", text: "全盘顺畅开发（不限目录）" + tempSuffix };
    }
    var sMode = String((state && state.safety_mode) || "full_dev");
    if (sess.scope_label && sess.scope_label.indexOf("标准权限") < 0) {
      var lblCls = sMode === "readonly" ? "tag tag-warn" : sMode === "edit_only" ? "tag tag-info" : "tag tag-ok";
      return { cls: lblCls, text: sess.scope_label };
    }
    if (sMode === "readonly") {
      return { cls: "tag tag-warn", text: "仅只读权限" + tempSuffix };
    }
    if (sMode === "edit_only") {
      return { cls: "tag tag-info", text: "仅改文件（禁跑命令）" + tempSuffix };
    }
    if (sMode === "full_power") {
      return { cls: "tag tag-ok", text: "全盘顺畅开发（不限目录）" + tempSuffix };
    }
    return { cls: "tag tag-ok", text: "工作区内顺畅开发" + tempSuffix };
  }

  function renderAuthorizedSessions(sessions) {
    var ul = $("authorized-sessions-list");
    if ($("revoke-sessions-btn")) {
      $("revoke-sessions-btn").disabled = !sessions || sessions.length === 0;
    }
    if (!ul) return;
    ul.innerHTML = "";
    if (!sessions || !sessions.length) {
      var emp = document.createElement("li");
      emp.className = "empty-hint";
      emp.style.padding = "8px 10px";
      emp.textContent = "暂无已连接网页端会话。";
      ul.appendChild(emp);
      return;
    }
    sessions.forEach(function (sess) {
      var li = document.createElement("li");
      li.className = "item-row";
      var left = document.createElement("div");
      left.className = "session-item-info";

      var topLine = document.createElement("div");
      topLine.style.display = "flex";
      topLine.style.flexWrap = "wrap";
      topLine.style.alignItems = "center";
      topLine.style.gap = "6px";

      var platStrong = document.createElement("strong");
      platStrong.style.fontSize = "12.5px";
      var pName = sess.platform || "MCP 客户端";
      var cName = sess.client_name || "";
      platStrong.textContent = cName && cName !== pName ? pName + " · " + cName : pName;
      topLine.appendChild(platStrong);

      var badgeInfo = resolveSessionScopeBadge(sess);
      var scopeTag = document.createElement("span");
      scopeTag.className = badgeInfo.cls;
      scopeTag.textContent = badgeInfo.text;
      topLine.appendChild(scopeTag);

      var meta = document.createElement("div");
      meta.className = "item-meta";
      meta.textContent = "到期：" + (sess.expires_at_text || "-");

      left.appendChild(topLine);
      left.appendChild(meta);

      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn btn-danger btn-sm revoke-client-btn";
      btn.setAttribute("data-client-id", sess.client_id || "");
      btn.textContent = "断开";
      btn.addEventListener("click", function () {
        apiFetch("/api/studio/connection", {
          method: "POST",
          body: { action: "revoke_client", client_id: sess.client_id },
        }).then(function (d) {
          if (!d.ok) return showToast(d.error || "断开客户端失败", true);
          renderAll(d);
          showToast(d.message || "已断开该客户端授权", false);
        });
      });

      li.appendChild(left);
      li.appendChild(btn);
      ul.appendChild(li);
    });
  }

  function renderWorkspaces(roots, primary, accessModes) {
    var ul = $("workspace-roots-list");
    if (!ul) return;
    ul.innerHTML = "";
    var modesMap = accessModes || {};
    var canRemove = roots.length > 1;

    roots.forEach(function (r, idx) {
      var li = document.createElement("li");
      li.className = "ws-row";
      var left = document.createElement("div");
      left.className = "ws-path ws-path-stack";
      var pathEl = document.createElement("div");
      pathEl.className = "ws-path-text";
      pathEl.title = r;
      pathEl.textContent = r;
      var badge = document.createElement("span");
      var isPrimary = idx === 0 || r === primary;
      var curMode = !isPrimary && modesMap[r] === "readonly" ? "readonly" : "readwrite";
      badge.className = "ws-role-meta " + (isPrimary ? "is-primary" : curMode === "readonly" ? "is-ro" : "is-rw");
      badge.textContent = isPrimary ? "主读写目录" : curMode === "readonly" ? "只读父目录" : "读写目录";
      left.appendChild(pathEl);
      left.appendChild(badge);

      var right = document.createElement("div");
      right.className = "ws-actions";

      // Clean RW / Readonly-Parent pill switcher on every row
      var pillGroup = document.createElement("div");
      pillGroup.className = "ws-perm-pill-group";
      var btnRw = document.createElement("button");
      btnRw.type = "button";
      btnRw.className = "ws-perm-pill" + (curMode === "readwrite" ? " active-rw" : "");
      btnRw.textContent = "读写";
      btnRw.addEventListener("click", function () {
        if (curMode === "readwrite") return;
        mutateWorkspace({ action: "set_access", path: r, access: "readwrite" });
      });

      var btnRo = document.createElement("button");
      btnRo.type = "button";
      btnRo.className = "ws-perm-pill" + (curMode === "readonly" ? " active-ro" : "");
      btnRo.textContent = "只读父目录";
      btnRo.addEventListener("click", function () {
        if (curMode === "readonly") return;
        mutateWorkspace({ action: "set_access", path: r, access: "readonly" });
      });

      pillGroup.appendChild(btnRw);
      pillGroup.appendChild(btnRo);
      right.appendChild(pillGroup);

      if (!isPrimary) {
        var permSel = document.createElement("select");
        permSel.className = "ws-perm-select";
        permSel.style.display = "none";
        permSel.setAttribute("aria-label", "工作目录访问权限");
        var optRw = document.createElement("option");
        optRw.value = "readwrite";
        optRw.textContent = "读写";
        var optRo = document.createElement("option");
        optRo.value = "readonly";
        optRo.textContent = "只读父目录";
        if (curMode === "readonly") optRo.selected = true;
        else optRw.selected = true;
        permSel.appendChild(optRw);
        permSel.appendChild(optRo);
        permSel.addEventListener("change", function () {
          mutateWorkspace({ action: "set_access", path: r, access: permSel.value });
        });
        right.appendChild(permSel);

        var priBtn = document.createElement("button");
        priBtn.type = "button";
        priBtn.className = "btn btn-sm";
        priBtn.textContent = "设为主目录";
        priBtn.addEventListener("click", function () {
          mutateWorkspace({ action: "set_primary", path: r });
        });
        right.appendChild(priBtn);
      }

      if (canRemove) {
        var remBtn = document.createElement("button");
        remBtn.type = "button";
        remBtn.className = "btn btn-danger btn-sm";
        remBtn.textContent = "移除";
        remBtn.addEventListener("click", function () {
          mutateWorkspace({ action: "remove", path: r });
        });
        right.appendChild(remBtn);
      }
      li.appendChild(left);
      li.appendChild(right);
      ul.appendChild(li);
    });
  }

  function loadDiscoveredWorkspaces() {
    var box = $("discovered-code-dirs-list");
    if (!box) return;
    apiFetch("/api/studio/workspaces/discover").then(function (doc) {
      if (!doc || !doc.ok) {
        box.innerHTML = '<span class="item-meta">暂未识别到其他常用代码目录。</span>';
        return;
      }
      var dirs = doc.directories || [];
      box.innerHTML = "";
      if (!dirs.length) {
        box.innerHTML = '<span class="item-meta">未扫描到未添加的常用代码目录，可通过上方「选择本地文件夹」添加。</span>';
        return;
      }
      dirs.slice(0, 12).forEach(function (d) {
        var chip = document.createElement("button");
        chip.type = "button";
        chip.className = "discover-chip";
        chip.disabled = Boolean(d.already_added);
        var pSpan = document.createElement("span");
        pSpan.className = "discover-chip-path";
        pSpan.title = d.path;
        pSpan.textContent = d.path;
        chip.appendChild(pSpan);

        var tag = document.createElement("span");
        tag.className = "tag " + (d.already_added ? "tag-ok" : "tag-info");
        if (d.already_added) {
          tag.textContent = "已添加";
        } else if (d.child_repo_count && d.child_repo_count > 1) {
          tag.textContent = "+ 添加父目录 (" + d.child_repo_count + " 仓)";
        } else {
          tag.textContent = "+ 添加";
        }
        chip.appendChild(tag);

        if (!d.already_added) {
          chip.addEventListener("click", function () {
            var isParentHub = Number(d.child_repo_count || 0) >= 2 && d.kind === "code_parent";
            mutateWorkspace({
              action: "add",
              path: d.path,
              access: isParentHub ? "readonly" : "readwrite",
            }).then(function () {
              loadDiscoveredWorkspaces();
            });
          });
        }
        box.appendChild(chip);
      });
    });
  }

  function renderPythonCandidates(cands, savedPath) {
    var sel = $("python-candidates-select");
    if (!sel) return;
    sel.innerHTML = '<option value="">自动识别项目虚拟环境或系统默认解释器</option>';
    cands.forEach(function (c) {
      var opt = document.createElement("option");
      opt.value = c.path;
      opt.textContent = c.label + " (" + c.path + ")";
      if (savedPath && c.path.toLowerCase() === savedPath.toLowerCase()) {
        opt.selected = true;
      }
      sel.appendChild(opt);
    });
    var pyInp = $("python-path-input");
    if (pyInp && document.activeElement !== pyInp) {
      pyInp.value = savedPath || "";
    }
  }

  function renderSafetyCards(modeCode) {
    var hintMap = {
      readonly: "仅读取与搜索，禁止修改与执行",
      edit_only: "可改工作区文件，禁止运行命令",
      full_dev: "工作目录内读写代码与运行命令",
      full_power: "不限目录读写与运行（高权限）",
    };
    if ($("safety-active-hint")) {
      $("safety-active-hint").textContent = hintMap[modeCode] || hintMap.full_dev;
      $("safety-active-hint").setAttribute("data-safety-mode", modeCode || "full_dev");
    }
    document.querySelectorAll("#safety-mode-cards .safety-card").forEach(function (card) {
      var code = card.getAttribute("data-safety");
      var isActive = code === modeCode;
      card.classList.toggle("active", isActive);
      card.setAttribute("aria-pressed", isActive ? "true" : "false");
      card.setAttribute("aria-checked", isActive ? "true" : "false");
      var btn = card.querySelector(".safety-select-btn");
      if (btn) {
        if (isActive) {
          btn.textContent = "当前生效中";
          btn.disabled = true;
          btn.className = "btn safety-select-btn";
        } else {
          btn.disabled = false;
          if (code === "full_dev") {
            btn.className = "btn btn-primary safety-select-btn";
            btn.textContent = "切为工作区内开发";
          } else if (code === "full_power") {
            btn.className = "btn btn-tonal safety-select-btn";
            btn.textContent = "开启全盘顺畅开发";
          } else if (code === "edit_only") {
            btn.className = "btn btn-tonal safety-select-btn";
            btn.textContent = "切为仅改文件";
          } else {
            btn.className = "btn btn-warn safety-select-btn";
            btn.textContent = "切为只读浏览";
          }
        }
      }
    });
  }

  function resolveToolCategoryTagClass(t) {
    if (!t.enabled) return "tag tag-disabled";
    var band = String(t.band || "").toLowerCase();
    var cat = String(t.category || "");
    if (band === "exec" || cat.indexOf("命令") >= 0) return "tag tag-cat-exec";
    if (band === "write" || cat.indexOf("修改") >= 0) return "tag tag-cat-write";
    return "tag tag-cat-readonly";
  }

  function renderCoreTools(tools) {
    var grid = $("core-tools-grid");
    if (!grid) return;
    grid.innerHTML = "";
    tools.forEach(function (t) {
      var card = document.createElement("div");
      card.className = "tool-card" + (t.enabled ? "" : " disabled");
      var rawBand = String(t.band || "").toLowerCase();
      var rawCat = String(t.category || "");
      var normBand =
        rawBand === "exec" || rawCat.indexOf("命令") >= 0
          ? "exec"
          : rawBand === "write" || rawCat.indexOf("修改") >= 0
          ? "write"
          : "readonly";
      card.setAttribute("data-tool-band", normBand);
      card.setAttribute("data-tool-enabled", t.enabled ? "1" : "0");
      var head = document.createElement("div");
      head.className = "tool-card-head";
      var title = document.createElement("span");
      title.className = "tool-card-title";
      title.textContent = t.title;
      var badge = document.createElement("span");
      badge.className = resolveToolCategoryTagClass(t);
      badge.textContent = t.enabled ? t.category : "当前已禁用";
      head.appendChild(title);
      head.appendChild(badge);
      var desc = document.createElement("p");
      desc.className = "tool-card-desc";
      desc.textContent = t.description;
      card.appendChild(head);
      card.appendChild(desc);
      grid.appendChild(card);
    });
    applyCoreToolsFilter();
  }

  function renderTasks(jobs) {
    var runningCnt = (jobs || []).filter(function (j) {
      return Boolean(j && j.running);
    }).length;
    if ($("kill-all-tasks-btn")) {
      $("kill-all-tasks-btn").disabled = runningCnt <= 0;
    }

    var ul = $("tasks-list");
    if (!ul) return;
    ul.innerHTML = "";
    if (!jobs.length) {
      var empty = document.createElement("li");
      empty.className = "empty-hint";
      empty.textContent = "当前没有正在运行或历史记录中的后台任务。";
      ul.appendChild(empty);
      return;
    }
    jobs.forEach(function (j) {
      var li = document.createElement("li");
      li.className = "item-row";
      var left = document.createElement("div");
      left.style.flex = "1 1 240px";
      left.style.minWidth = "0";
      var stTag = document.createElement("span");
      stTag.className = "tag " + (j.running ? "tag-info" : j.exit_code === 0 ? "tag-ok" : "tag-warn");
      stTag.style.marginRight = "8px";
      stTag.textContent = j.running ? "运行中" : "已结束 (退出码 " + j.exit_code + ")";
      var cmdSpan = document.createElement("strong");
      cmdSpan.style.fontSize = "13px";
      cmdSpan.textContent = j.command || j.job_id;
      left.appendChild(stTag);
      left.appendChild(cmdSpan);
      var meta = document.createElement("div");
      meta.className = "item-meta";
      meta.textContent = "耗时 " + (j.elapsed_sec || 0) + " 秒 · 目录：" + (j.cwd || "-");
      left.appendChild(meta);

      var right = document.createElement("div");
      right.className = "ws-actions";
      var logBtn = document.createElement("button");
      logBtn.type = "button";
      logBtn.className = "btn btn-sm";
      logBtn.textContent = "查看实时日志";
      logBtn.addEventListener("click", function () {
        loadTaskLog(j.job_id);
      });
      right.appendChild(logBtn);

      if (j.running) {
        var killBtn = document.createElement("button");
        killBtn.type = "button";
        killBtn.className = "btn btn-danger btn-sm";
        killBtn.textContent = "终止任务";
        killBtn.addEventListener("click", function () {
          apiFetch("/api/studio/tasks", { method: "POST", body: { action: "kill", job_id: j.job_id } }).then(function (d) {
            if (!d.ok) return showToast(d.error || "终止任务失败", true);
            renderAll(d);
            showToast(d.message || "已终止任务", false);
          });
        });
        right.appendChild(killBtn);
      }
      li.appendChild(left);
      li.appendChild(right);
      ul.appendChild(li);
    });
  }

  function loadTaskLog(jobId) {
    activeLogJobId = jobId;
    apiFetch("/api/studio/tasks?job_id=" + encodeURIComponent(jobId)).then(function (doc) {
      if (!doc.ok) return showToast(doc.error || "读取日志失败", true);
      renderTasks(doc.jobs || []);
      var sel = doc.selected;
      if (sel) {
        $("task-log-panel").style.display = "block";
        $("task-log-title").textContent =
          "任务日志（" + sel.job_id + (sel.running ? " · 运行中自动刷新" : " · 已结束") + "）";
        $("task-log-box").textContent = sel.log_tail || "(暂无日志输出)";
      }
    });
  }

  function closeDiffModal() {
    activeDiffTargetPath = "";
    if ($("diff-preview-modal")) {
      $("diff-preview-modal").style.display = "none";
    }
  }

  function openIdentityModal(mode) {
    var modal = $("identity-png-modal");
    if (!modal) return;
    var isImport = mode === "import";
    $("identity-modal-title").textContent = isImport ? "导入节点身份恢复卡 PNG" : "导出节点身份恢复卡 PNG";
    $("identity-export-pane").style.display = isImport ? "none" : "block";
    $("identity-import-pane").style.display = isImport ? "block" : "none";
    modal.style.display = "flex";
  }

  function closeIdentityModal() {
    if ($("identity-png-modal")) {
      $("identity-png-modal").style.display = "none";
    }
  }

  function openSnapshotDiffModal(filePath, fallbackTime) {
    activeDiffTargetPath = filePath;
    apiFetch("/api/studio/recovery/diff?path=" + encodeURIComponent(filePath)).then(function (d) {
      if (!d.ok) return showToast(d.error || "无法加载快照对比", true);
      var fName = d.file_name || String(filePath).split(/[\\/]/).pop() || filePath;
      $("diff-modal-title").textContent = "修改前后对比 · " + fName;

      var rawTime = d.latest_at && d.latest_at !== "-" ? d.latest_at : fallbackTime || "-";
      var timeText = formatLocalTime(rawTime);
      var metaEl = $("diff-modal-meta");
      metaEl.innerHTML = "";
      var statLine = document.createElement("span");
      statLine.textContent =
        "快照时间：" +
        timeText +
        " · 新增 +" +
        (d.added_lines || 0) +
        " 行 / 删除 -" +
        (d.removed_lines || 0) +
        " 行";
      metaEl.appendChild(statLine);

      var pathLine = document.createElement("span");
      pathLine.className = "diff-path-note";
      pathLine.textContent = d.path || filePath;
      metaEl.appendChild(pathLine);

      var bodyEl = $("diff-modal-body");
      bodyEl.innerHTML = "";
      var lines = String(d.diff_text || "").split("\n");
      lines.forEach(function (ln) {
        var row = document.createElement("div");
        var cls = "diff-line";
        if (ln.indexOf("@@") === 0 || ln.indexOf("---") === 0 || ln.indexOf("+++") === 0) {
          cls += " hunk";
        } else if (ln.indexOf("+") === 0) {
          cls += " add";
        } else if (ln.indexOf("-") === 0) {
          cls += " del";
        }
        row.className = cls;
        row.textContent = ln || " ";
        bodyEl.appendChild(row);
      });
      $("diff-preview-modal").style.display = "flex";
      if ($("close-diff-modal-btn")) {
        try {
          $("close-diff-modal-btn").focus({ preventScroll: true });
        } catch (e) {
          $("close-diff-modal-btn").focus();
        }
      }
    });
  }

  function renderRecovery(snapshots, trashItems, auditEvents) {
    var uList = $("undo-snapshots-list");
    if (uList) {
      uList.innerHTML = "";
      if (!snapshots.length) {
        var e1 = document.createElement("li");
        e1.className = "empty-hint";
        e1.textContent = "暂无待撤回的文件修改快照。";
        uList.appendChild(e1);
      } else {
        snapshots.forEach(function (s) {
          var li = document.createElement("li");
          li.className = "item-row";
          var left = document.createElement("div");
          left.style.flex = "1 1 200px";
          left.style.minWidth = "0";
          var pStrong = document.createElement("div");
          pStrong.style.fontWeight = "600";
          pStrong.style.fontSize = "13px";
          pStrong.style.overflowWrap = "anywhere";
          pStrong.textContent = s.rel_path || s.path;

          var snapTime = formatLocalTime(s.latest_at || s.ts || "-");
          var meta = document.createElement("div");
          meta.className = "item-meta";
          meta.appendChild(
            document.createTextNode(
              (s.existed_before ? "修改前快照" : "新建文件记录") + " · 时间：" + snapTime + " · "
            )
          );
          var stepSpan = document.createElement("span");
          stepSpan.className = "nowrap-tok";
          stepSpan.textContent = "可回退 " + (s.snapshot_count || 1) + " 步";
          meta.appendChild(stepSpan);

          left.appendChild(pStrong);
          left.appendChild(meta);

          var right = document.createElement("div");
          right.className = "ws-actions";
          var diffBtn = document.createElement("button");
          diffBtn.type = "button";
          diffBtn.className = "btn btn-sm diff-snapshot-btn";
          diffBtn.textContent = "查看对比 Diff";
          diffBtn.addEventListener("click", function () {
            openSnapshotDiffModal(s.path, snapTime);
          });
          var btn = document.createElement("button");
          btn.type = "button";
          btn.className = "btn btn-tonal btn-sm undo-snapshot-btn";
          btn.textContent = "撤回修改";
          btn.addEventListener("click", function () {
            apiFetch("/api/studio/recovery", { method: "POST", body: { action: "undo", path: s.path } }).then(function (d) {
              if (!d.ok) return showToast(d.error || "撤回修改失败", true);
              renderAll(d);
              showToast(d.message || "已撤回修改", false);
            });
          });
          right.appendChild(diffBtn);
          right.appendChild(btn);
          li.appendChild(left);
          li.appendChild(right);
          uList.appendChild(li);
        });
      }
    }

    var tList = $("trash-items-list");
    if (tList) {
      tList.innerHTML = "";
      if (!trashItems.length) {
        var e2 = document.createElement("li");
        e2.className = "empty-hint";
        e2.textContent = "安全回收箱当前为空。";
        tList.appendChild(e2);
      } else {
        trashItems.forEach(function (t) {
          var li = document.createElement("li");
          li.className = "item-row";
          var left = document.createElement("div");
          left.style.flex = "1 1 200px";
          left.style.minWidth = "0";
          var pStrong = document.createElement("div");
          pStrong.style.fontWeight = "600";
          pStrong.style.fontSize = "13px";
          pStrong.style.overflowWrap = "anywhere";
          pStrong.textContent = t.original_path;
          var meta = document.createElement("div");
          meta.className = "item-meta";
          meta.textContent = "移入时间：" + formatLocalTime(t.trashed_at || "-") + (t.reason ? " · 备注：" + t.reason : "");
          left.appendChild(pStrong);
          left.appendChild(meta);
          var btn = document.createElement("button");
          btn.type = "button";
          btn.className = "btn btn-tonal btn-sm";
          btn.textContent = "一键原位恢复";
          btn.addEventListener("click", function () {
            apiFetch("/api/studio/recovery", {
              method: "POST",
              body: { action: "restore_trash", trash_id: t.trash_id },
            }).then(function (d) {
              if (!d.ok) return showToast(d.error || "恢复失败", true);
              renderAll(d);
              showToast(d.message || "已从安全回收箱恢复", false);
            });
          });
          li.appendChild(left);
          li.appendChild(btn);
          tList.appendChild(li);
        });
      }
    }

    var aList = $("audit-events-list");
    if (aList) {
      aList.innerHTML = "";
      var evs = auditEvents || [];
      if (!evs.length) {
        var e3 = document.createElement("li");
        e3.className = "empty-hint";
        e3.textContent = "暂无最近工具操作记录；AI 调用工具后将在此实时显示。";
        aList.appendChild(e3);
      } else {
        evs.forEach(function (ev) {
          var li = document.createElement("li");
          li.className = "item-row";
          li.setAttribute("data-audit-ok", ev.ok && !ev.blocked ? "1" : "0");
          li.setAttribute(
            "data-audit-search",
            [ev.title_zh || "", ev.tool || "", ev.caller || "", ev.error || ""].join(" ")
          );
          var left = document.createElement("div");
          left.className = "session-item-info";

          var head = document.createElement("div");
          head.style.display = "flex";
          head.style.flexWrap = "wrap";
          head.style.alignItems = "center";
          head.style.gap = "6px";

          var stBadge = document.createElement("span");
          stBadge.className = "tag " + (ev.ok ? "tag-ok" : ev.blocked ? "tag-warn" : "tag-info");
          stBadge.textContent = ev.status_label || (ev.ok ? "正常完成" : "执行异常");
          head.appendChild(stBadge);

          var tStrong = document.createElement("strong");
          tStrong.style.fontSize = "13px";
          if (ev.tool) tStrong.setAttribute("data-tool", ev.tool);
          tStrong.textContent = ev.title_zh || ev.tool || "-";
          head.appendChild(tStrong);

          var meta = document.createElement("div");
          meta.className = "item-meta";
          var metaTxt = "时间：" + (ev.time_text || "-") + " · 耗时 " + (ev.duration_ms || 0) + " ms";
          if (ev.caller) metaTxt += " · 调用方：" + ev.caller;
          if (!ev.ok && ev.error) metaTxt += " · 说明：" + ev.error;
          meta.textContent = metaTxt;

          left.appendChild(head);
          left.appendChild(meta);
          li.appendChild(left);
          aList.appendChild(li);
        });
        applyAuditFilter();
      }
    }
  }

  // ==================== Tab 5: Visual Skills Center ====================

  function clearSkillDetailPanel() {
    selectedSkillName = "";
    selectedSkillScope = "";
    if ($("skill-detail-title")) {
      $("skill-detail-title").textContent = "点击左侧任意技能查看详情与 AST 体检结果";
    }
    if ($("skill-detail-meta")) {
      $("skill-detail-meta").textContent = "未选中技能";
    }
    if ($("skill-detail-actions")) {
      $("skill-detail-actions").innerHTML = "";
    }
    if ($("skill-detail-audit-box")) {
      $("skill-detail-audit-box").style.display = "none";
    }
    if ($("skill-detail-files-bar")) {
      $("skill-detail-files-bar").innerHTML = "";
      $("skill-detail-files-bar").style.display = "none";
    }
    if ($("skill-detail-content")) {
      $("skill-detail-content").textContent = "";
      $("skill-detail-content").style.display = "none";
    }
    document.querySelectorAll("#skills-items-list .item-row").forEach(function (el) {
      el.classList.remove("selected-skill");
    });
  }

  function renderAuditFindingsRows(tbodyEl, findings, onFileClick) {
    if (!tbodyEl) return;
    tbodyEl.innerHTML = "";
    (findings || []).forEach(function (f) {
      var tr = document.createElement("tr");
      var tdSev = document.createElement("td");
      var sev = String(f.severity || "INFO").toUpperCase();
      var badge = document.createElement("span");
      badge.className =
        "tag " + (sev === "BLOCK" ? "tag-danger" : sev === "WARN" ? "tag-warn" : "tag-ok");
      badge.textContent = sev;
      tdSev.appendChild(badge);

      var tdRule = document.createElement("td");
      tdRule.textContent = f.rule_id || "-";

      var tdFile = document.createElement("td");
      var fRel = f.file_rel || "SKILL.md";
      if (onFileClick) {
        var fLink = document.createElement("span");
        fLink.className = "audit-file-link";
        fLink.textContent = fRel;
        fLink.addEventListener("click", function () {
          onFileClick(fRel);
        });
        tdFile.appendChild(fLink);
      } else {
        tdFile.textContent = fRel;
      }

      var tdDet = document.createElement("td");
      tdDet.textContent = (f.detail || "") + (f.remediation ? " （建议：" + f.remediation + "）" : "");

      tr.appendChild(tdSev);
      tr.appendChild(tdRule);
      tr.appendChild(tdFile);
      tr.appendChild(tdDet);
      tbodyEl.appendChild(tr);
    });
  }

  function renderSkills(sk) {
    var items = sk.items || [];
    var totalAll =
      typeof sk.total_all_count === "number"
        ? sk.total_all_count
        : typeof sk.count === "number"
        ? sk.count
        : items.length;
    var matchedCnt = typeof sk.matched_count === "number" ? sk.matched_count : items.length;
    var isFiltered = Boolean(sk.is_filtered || sk.query || (sk.scope && sk.scope !== "all"));
    var enabledCnt = typeof sk.enabled_count === "number" ? sk.enabled_count : totalAll;
    var disabledCnt = typeof sk.disabled_count === "number" ? sk.disabled_count : 0;

    var banner = $("skills-summary-banner");
    if (banner) {
      if (totalAll <= 0 && !isFiltered) {
        banner.textContent = "当前本机检测到 0 项技能，可通过「在线市场与体检安装」或「新建技能」添加。";
      } else if (isFiltered) {
        banner.textContent =
          "共 " +
          totalAll +
          " 项技能（当前匹配 " +
          matchedCnt +
          " 项 · 已启用 " +
          enabledCnt +
          " 项，已禁用 " +
          disabledCnt +
          " 项）";
      } else {
        banner.textContent =
          "共 " +
          totalAll +
          " 项技能（已启用 " +
          enabledCnt +
          " 项，已禁用 " +
          disabledCnt +
          " 项 · 受管技能库：" +
          (sk.managed_store || "-") +
          "）";
      }
    }
    if ($("skills-checked-dirs")) {
      $("skills-checked-dirs").textContent = (sk.checked_dirs || []).join("\n") || "-";
    }

    var ul = $("skills-items-list");
    if (!ul) return;
    ul.innerHTML = "";
    if (!items.length) {
      var empty = document.createElement("li");
      empty.className = "empty-hint";
      empty.textContent = "未检索到匹配的本地技能。";
      ul.appendChild(empty);
      return;
    }

    items.forEach(function (it) {
      var isEnabled = it.enabled !== false;
      var scRaw = String(it.source_scope || "");
      var isProject = scRaw === "workspace" || scRaw === "workspace_claude" || scRaw === "project";
      var isManaged = scRaw === "managed";
      var canTrash = isManaged || isProject;

      var li = document.createElement("li");
      li.className = "item-row" + (selectedSkillName === it.name ? " selected-skill" : "");
      li.setAttribute("data-skill-name", it.name || "");

      var left = document.createElement("div");
      left.className = "session-item-info";
      left.style.cursor = "pointer";
      left.addEventListener("click", function () {
        loadSkillDetail(it.name, "SKILL.md", true);
      });

      var headLine = document.createElement("div");
      headLine.style.display = "flex";
      headLine.style.flexWrap = "wrap";
      headLine.style.alignItems = "center";
      headLine.style.gap = "6px";

      var nm = document.createElement("strong");
      nm.style.fontSize = "13.5px";
      nm.textContent = it.name;
      headLine.appendChild(nm);

      var scBadge = document.createElement("span");
      scBadge.className = "tag " + (isProject ? "tag-info" : isManaged ? "tag-ok" : "tag-muted");
      scBadge.textContent = it.scope_label || scRaw || "本地技能";
      headLine.appendChild(scBadge);

      if (!isEnabled) {
        var disTag = document.createElement("span");
        disTag.className = "tag tag-warn";
        disTag.textContent = "已禁用";
        headLine.appendChild(disTag);
      }
      if (it.has_scripts) {
        var scrTag = document.createElement("span");
        scrTag.className = "tag tag-info";
        scrTag.textContent = "含脚本(" + (it.scripts_count || 1) + ")";
        headLine.appendChild(scrTag);
      }

      var meta = document.createElement("div");
      meta.className = "item-meta";
      meta.textContent = it.description || "无简要说明";

      left.appendChild(headLine);
      left.appendChild(meta);

      var right = document.createElement("div");
      right.className = "ws-actions";

      var toggleLbl = document.createElement("label");
      toggleLbl.className = "chk-inline";
      toggleLbl.title = "启用或禁用此技能";
      var chk = document.createElement("input");
      chk.type = "checkbox";
      chk.className = "skill-enable-toggle apple-switch";
      chk.checked = isEnabled;
      chk.addEventListener("change", function () {
        toggleSkillEnabled(it.name, chk.checked, isProject ? "project" : "managed");
      });
      var chkSpan = document.createElement("span");
      chkSpan.style.fontSize = "12px";
      chkSpan.textContent = isEnabled ? "启用" : "禁用";
      toggleLbl.appendChild(chk);
      toggleLbl.appendChild(chkSpan);
      right.appendChild(toggleLbl);

      var detBtn = document.createElement("button");
      detBtn.type = "button";
      detBtn.className = "btn btn-sm";
      detBtn.textContent = "详情";
      detBtn.addEventListener("click", function () {
        loadSkillDetail(it.name, "SKILL.md", true);
      });
      right.appendChild(detBtn);

      if (canTrash) {
        var delBtn = document.createElement("button");
        delBtn.type = "button";
        delBtn.className = "btn btn-danger btn-sm";
        delBtn.textContent = "移入安全回收箱";
        delBtn.addEventListener("click", function () {
          trashSkill(it.name, isProject ? "project" : "managed", false);
        });
        right.appendChild(delBtn);
      }

      li.appendChild(left);
      li.appendChild(right);
      ul.appendChild(li);
    });
  }

  function refreshLocalSkillsList() {
    var q = $("skill-local-search-input") ? $("skill-local-search-input").value.trim() : "";
    var sc = $("skill-local-scope-select") ? $("skill-local-scope-select").value : "all";
    var url = "/api/studio/skills/local?q=" + encodeURIComponent(q) + "&scope=" + encodeURIComponent(sc);
    return apiFetch(url).then(function (d) {
      if (!d.ok) {
        showToast(d.error || "读取本地技能失败", true);
        return d;
      }
      renderSkills(d);
      return d;
    });
  }

  function toggleSkillEnabled(skillName, wantEnabled, scopeVal) {
    return apiFetch("/api/studio/skills/toggle", {
      method: "POST",
      body: { skill: skillName, enabled: !!wantEnabled, scope: scopeVal || "" },
    }).then(function (d) {
      if (!d.ok) {
        showToast(d.error || "切换技能状态失败", true);
        refreshLocalSkillsList();
        return d;
      }
      showToast("技能 " + skillName + (d.enabled ? " 已启用" : " 已禁用"), false);
      refreshLocalSkillsList();
      if (selectedSkillName === skillName) {
        loadSkillDetail(skillName, "SKILL.md", false);
      }
      return d;
    });
  }

  function trashSkill(skillName, scopeVal, forceDelete) {
    return apiFetch("/api/studio/skills/trash", {
      method: "POST",
      body: { skill: skillName, scope: scopeVal || "managed", force: !!forceDelete },
    }).then(function (d) {
      if (!d.ok) {
        if (d.status === "modified_requires_force" || String(d.error || "").indexOf("force") >= 0) {
          showToast("该技能存在本地修改，请点击详情栏「强制移入安全回收箱」确认移出。", true);
          if (selectedSkillName === skillName) {
            renderForceDeleteButtonInDetail(skillName, scopeVal);
          }
          return d;
        }
        showToast(d.error || "移入安全回收箱失败", true);
        return d;
      }
      if (!selectedSkillName || selectedSkillName.toLowerCase() === String(skillName).toLowerCase()) {
        clearSkillDetailPanel();
      }
      showToast("技能 " + skillName + " 已安全移入安全回收箱", false);
      refreshLocalSkillsList();
      loadSkillTrashList();
      return d;
    });
  }

  function renderForceDeleteButtonInDetail(skillName, scopeVal) {
    var actBox = $("skill-detail-actions");
    if (!actBox || actBox.querySelector(".force-trash-skill-btn")) return;
    var fBtn = document.createElement("button");
    fBtn.type = "button";
    fBtn.className = "btn btn-danger btn-sm force-trash-skill-btn";
    fBtn.textContent = "强制移入安全回收箱";
    fBtn.addEventListener("click", function () {
      trashSkill(skillName, scopeVal, true);
    });
    actBox.appendChild(fBtn);
  }

  function loadSkillDetail(skillName, relFile, scrollOnSelect) {
    var fileArg = relFile || "SKILL.md";
    var url =
      "/api/studio/skills/detail?skill=" +
      encodeURIComponent(skillName) +
      "&file=" +
      encodeURIComponent(fileArg);
    return apiFetch(url).then(function (d) {
      if (!d.ok) {
        showToast(d.error || "读取技能详情失败", true);
        return d;
      }
      selectedSkillName = d.name || skillName;
      var scRaw = String(d.source_scope || "");
      var isProject = scRaw === "workspace" || scRaw === "workspace_claude" || scRaw === "project";
      var isManaged = scRaw === "managed";
      selectedSkillScope = isProject ? "project" : "managed";

      document.querySelectorAll("#skills-items-list .item-row").forEach(function (el) {
        el.classList.toggle("selected-skill", el.getAttribute("data-skill-name") === selectedSkillName);
      });

      $("skill-detail-title").textContent =
        selectedSkillName + (d.enabled === false ? " （当前已禁用）" : "");
      $("skill-detail-meta").textContent =
        "来源：" +
        (d.scope_label || scRaw) +
        " · 当前文件：" +
        (d.file || fileArg) +
        (d.skill_dir ? " · 目录：" + d.skill_dir : "");

      var actBox = $("skill-detail-actions");
      actBox.innerHTML = "";

      var tgBtn = document.createElement("button");
      tgBtn.type = "button";
      tgBtn.className = "btn btn-sm " + (d.enabled === false ? "btn-tonal" : "btn-warn");
      tgBtn.textContent = d.enabled === false ? "启用此技能" : "禁用此技能";
      tgBtn.addEventListener("click", function () {
        toggleSkillEnabled(selectedSkillName, d.enabled === false, selectedSkillScope);
      });
      actBox.appendChild(tgBtn);

      var recheckBtn = document.createElement("button");
      recheckBtn.type = "button";
      recheckBtn.className = "btn btn-sm";
      recheckBtn.textContent = "重新安全体检";
      recheckBtn.addEventListener("click", function () {
        loadSkillDetail(selectedSkillName, d.file || fileArg, true);
      });
      actBox.appendChild(recheckBtn);

      if (isManaged || isProject) {
        var rmBtn = document.createElement("button");
        rmBtn.type = "button";
        rmBtn.className = "btn btn-danger btn-sm skill-detail-trash-btn";
        rmBtn.textContent = "移入安全回收箱";
        rmBtn.addEventListener("click", function () {
          trashSkill(selectedSkillName, selectedSkillScope, false);
        });
        actBox.appendChild(rmBtn);
      }

      var audit = d.audit || {};
      var auditBox = $("skill-detail-audit-box");
      var auditSum = $("skill-detail-audit-summary");
      var fWrap = $("skill-detail-findings-wrap");
      if (audit && audit.verdict) {
        auditBox.style.display = "block";
        var v = String(audit.verdict).toUpperCase();
        auditSum.className =
          "callout " + (v === "BLOCK" ? "callout-danger" : v === "WARN" ? "callout-warn" : "callout-ok");
        var fList = audit.findings || [];
        auditSum.textContent =
          "体检结论：" +
          v +
          " · 检测脚本数：" +
          ((audit.scripts_detected || []).length) +
          " · 风险条目数：" +
          fList.length;
        if (fList.length) {
          fWrap.style.display = "block";
          renderAuditFindingsRows($("skill-detail-findings-tbody"), fList, function (clickedFile) {
            loadSkillDetail(selectedSkillName, clickedFile, false);
          });
        } else {
          fWrap.style.display = "none";
        }
      } else {
        auditBox.style.display = "none";
      }

      var filesBar = $("skill-detail-files-bar");
      filesBar.innerHTML = "";
      var allFiles = ["SKILL.md"]
        .concat(d.scripts || [])
        .concat(d.references || [])
        .concat(d.assets || []);
      if (allFiles.length >= 1) {
        filesBar.style.display = "flex";
        allFiles.slice(0, 16).forEach(function (rf) {
          var fb = document.createElement("button");
          fb.type = "button";
          fb.className = "file-pill" + (rf === (d.file || fileArg) ? " active" : "");
          fb.textContent = rf;
          fb.addEventListener("click", function () {
            loadSkillDetail(selectedSkillName, rf, false);
          });
          filesBar.appendChild(fb);
        });
      } else {
        filesBar.style.display = "none";
      }

      var contentPre = $("skill-detail-content");
      contentPre.style.display = "block";
      contentPre.textContent = d.content || "(空文件)";

      if (scrollOnSelect && $("skill-detail-panel") && $("skill-detail-panel").scrollIntoView) {
        $("skill-detail-panel").scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
      return d;
    });
  }

  function runSkillVetPreview(sourceVal, scopeVal) {
    var cleanSrc = String(sourceVal || "").trim();
    if (!cleanSrc) return showToast("请输入要体检的技能仓库地址或本地路径", true);
    if ($("skill-vet-source-input")) $("skill-vet-source-input").value = cleanSrc;
    if ($("skill-install-error-banner")) {
      $("skill-install-error-banner").style.display = "none";
      $("skill-install-error-banner").textContent = "";
    }

    return apiFetch("/api/studio/skills/vet", {
      method: "POST",
      body: { source: cleanSrc, scope: scopeVal || "managed" },
    }).then(function (d) {
      var reportBox = $("skill-vet-report-box");
      var verdictBanner = $("skill-vet-verdict-banner");
      var findingsWrap = $("skill-vet-findings-wrap");
      var tbody = $("skill-vet-findings-tbody");
      var tabsBar = $("skill-vet-file-tabs");
      var previewPre = $("skill-vet-code-preview");
      var commitBtn = $("skill-commit-install-btn");
      var vetBtn = $("skill-vet-btn");
      var warnWrap = $("skill-confirm-warn-wrap");

      if (!d.ok && !d.verdict) {
        if ($("skill-install-error-banner")) {
          $("skill-install-error-banner").textContent = d.error || "安全体检失败";
          $("skill-install-error-banner").style.display = "block";
        }
        return d;
      }

      reportBox.style.display = "block";
      currentPreviewToken = d.preview_token || "";
      currentPreviewFilesMap = d.file_previews || {};
      if (!currentPreviewFilesMap["SKILL.md"] && d.skill_md_preview) {
        currentPreviewFilesMap["SKILL.md"] = d.skill_md_preview;
      }

      var verdict = String(d.verdict || (d.audit && d.audit.verdict) || "INFO").toUpperCase();
      var findings = (d.audit && d.audit.findings) || d.findings || [];
      verdictBanner.className =
        "callout " +
        (verdict === "BLOCK" ? "callout-danger" : verdict === "WARN" ? "callout-warn" : "callout-ok");
      verdictBanner.textContent =
        "三级 AST 安全体检结论：" +
        verdict +
        " · 技能名称：" +
        (d.skill_name || "-") +
        " · 文件数：" +
        (d.file_count || (d.files || []).length || 1) +
        (verdict === "BLOCK"
          ? " （命中高危供应链阻断规则，已禁止落盘安装）"
          : verdict === "WARN"
          ? " （检测到需人工确认的脚本或网络行为，请核对下方文件后打开确认开关）"
          : " （未发现高危特征，可直接安装）");

      if (findings.length) {
        findingsWrap.style.display = "block";
        renderAuditFindingsRows(tbody, findings, function (fRel) {
          if (currentPreviewFilesMap[fRel] !== undefined) {
            previewPre.textContent = currentPreviewFilesMap[fRel];
          }
        });
      } else {
        findingsWrap.style.display = "none";
        tbody.innerHTML = "";
      }

      tabsBar.innerHTML = "";
      var fKeys = Object.keys(currentPreviewFilesMap);
      fKeys.forEach(function (fk, idx) {
        var b = document.createElement("button");
        b.type = "button";
        b.className = "file-pill" + (idx === 0 ? " active" : "");
        b.textContent = fk;
        b.addEventListener("click", function () {
          tabsBar.querySelectorAll(".file-pill").forEach(function (x) {
            x.classList.remove("active");
          });
          b.classList.add("active");
          previewPre.textContent = currentPreviewFilesMap[fk] || "";
        });
        tabsBar.appendChild(b);
      });
      previewPre.textContent =
        fKeys.length > 0 ? currentPreviewFilesMap[fKeys[0]] : d.skill_md_preview || "(无可预览文本)";

      $("skill-confirm-warn-chk").checked = false;
      warnWrap.style.display = verdict === "WARN" ? "inline-flex" : "none";
      var canInstall = verdict !== "BLOCK" && Boolean(currentPreviewToken);
      commitBtn.disabled = !canInstall;
      commitBtn.className = canInstall ? "btn btn-primary" : "btn";
      if (vetBtn) {
        vetBtn.className = "btn btn-tonal";
      }
      if (reportBox && reportBox.scrollIntoView) {
        reportBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
      return d;
    });
  }

  function resetSkillInstallControls() {
    currentPreviewToken = "";
    if ($("skill-confirm-warn-chk")) $("skill-confirm-warn-chk").checked = false;
    if ($("skill-overwrite-chk")) $("skill-overwrite-chk").checked = false;
    if ($("skill-vet-btn")) $("skill-vet-btn").className = "btn btn-tonal";
    if ($("skill-install-error-banner")) {
      $("skill-install-error-banner").textContent = "";
      $("skill-install-error-banner").style.display = "none";
    }
  }

  function loadSkillTrashList() {
    return apiFetch("/api/studio/skills/trash").then(function (d) {
      var items = d.items || d.trashed_skills || [];
      if ($("skill-trash-badge-count")) {
        $("skill-trash-badge-count").textContent = String(items.length);
      }
      var ul = $("skill-trash-list");
      if (!ul) return d;
      ul.innerHTML = "";
      if (!items.length) {
        var emp = document.createElement("li");
        emp.className = "empty-hint";
        emp.textContent = "安全回收箱当前为空。";
        ul.appendChild(emp);
        return d;
      }
      items.forEach(function (it) {
        var li = document.createElement("li");
        li.className = "item-row";
        var left = document.createElement("div");
        left.className = "session-item-info";
        var nm = document.createElement("strong");
        nm.textContent = it.skill_name || it.name || it.trash_id;
        var rawRemovedAt = it.removed_at_local || it.trashed_at_local || it.removed_at || it.trashed_at || "-";
        var meta = document.createElement("div");
        meta.className = "item-meta";
        meta.textContent =
          "原位置：" +
          (it.original_dir || it.original_path || "-") +
          " · 移入时间：" +
          formatLocalTime(rawRemovedAt);
        left.appendChild(nm);
        left.appendChild(meta);

        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "btn btn-tonal btn-sm skill-restore-btn";
        btn.textContent = "一键原位恢复";
        btn.addEventListener("click", function () {
          apiFetch("/api/studio/skills/restore", {
            method: "POST",
            body: { trash_id: it.trash_id, force: true },
          }).then(function (r) {
            if (!r.ok) return showToast(r.error || "恢复技能失败", true);
            showToast("已原位恢复技能：" + (r.skill_name || it.skill_name || ""), false);
            loadSkillTrashList();
            refreshLocalSkillsList();
          });
        });
        li.appendChild(left);
        li.appendChild(btn);
        ul.appendChild(li);
      });
      return d;
    });
  }

  function mutateWorkspace(payload) {
    return apiFetch("/api/studio/workspace", { method: "POST", body: payload }).then(function (d) {
      if (!d.ok) {
        showToast(d.error || "工作目录更新失败", true);
        return d;
      }
      if (payload && payload.action === "add" && $("chk-add-ws-readonly")) {
        $("chk-add-ws-readonly").checked = false;
      }
      renderAll(d);
      showToast(d.message || "工作目录已更新", false);
      return d;
    });
  }

  function setTreeDrawerOpen(isOpen) {
    var drawer = $("fs-tree-drawer");
    var openBtn = $("open-tree-picker-btn");
    if (drawer) {
      drawer.className = isOpen ? "tree-drawer open" : "tree-drawer";
    }
    if (openBtn) {
      openBtn.textContent = isOpen ? "收起页内目录树" : "打开页内目录树选择文件夹";
    }
  }

  function createTreeEntryIcon(isDrive) {
    var ns = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("class", "tree-icon");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.9");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    if (isDrive) {
      var p1 = document.createElementNS(ns, "rect");
      p1.setAttribute("x", "3");
      p1.setAttribute("y", "6");
      p1.setAttribute("width", "18");
      p1.setAttribute("height", "12");
      p1.setAttribute("rx", "3");
      var l1 = document.createElementNS(ns, "line");
      l1.setAttribute("x1", "7");
      l1.setAttribute("y1", "14");
      l1.setAttribute("x2", "7.01");
      l1.setAttribute("y2", "14");
      svg.appendChild(p1);
      svg.appendChild(l1);
    } else {
      var fp = document.createElementNS(ns, "path");
      fp.setAttribute("d", "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z");
      svg.appendChild(fp);
    }
    return svg;
  }

  function loadFsTree(targetPath) {
    var url = "/api/studio/fs-tree?path=" + encodeURIComponent(targetPath || "");
    return apiFetch(url).then(function (doc) {
      if (!doc.ok) {
        showToast(doc.error || "无法读取目录树。", true);
        return doc;
      }
      setTreeDrawerOpen(true);
      currentTreePath = doc.current_path || "";
      $("tree-current-path").textContent = currentTreePath || "本机磁盘列表（点击盘符进入）";
      $("tree-up-btn").disabled = !currentTreePath;
      $("tree-up-btn").setAttribute("data-parent", doc.parent_path || "");
      $("tree-add-ws-btn").disabled = !currentTreePath;
      $("tree-set-primary-btn").disabled = !currentTreePath;

      var scBar = $("tree-shortcuts-bar");
      scBar.innerHTML = "";
      (doc.shortcuts || []).forEach(function (sc) {
        var b = document.createElement("button");
        b.type = "button";
        b.className = "btn btn-sm";
        b.textContent = sc.label;
        b.addEventListener("click", function () {
          loadFsTree(sc.path);
        });
        scBar.appendChild(b);
      });

      var listEl = $("tree-entries-list");
      listEl.innerHTML = "";
      var entries = doc.entries || [];
      if (!entries.length) {
        var emp = document.createElement("div");
        emp.className = "empty-hint";
        emp.textContent = "该文件夹下没有子文件夹，可直接点击下方「添加当前选中目录」。";
        listEl.appendChild(emp);
      } else {
        entries.forEach(function (ent) {
          var row = document.createElement("div");
          row.className = "tree-item";
          row.setAttribute("data-path", ent.path);
          var leftWrap = document.createElement("div");
          leftWrap.className = "tree-item-left";
          leftWrap.appendChild(createTreeEntryIcon(Boolean(ent.is_drive)));
          var nm = document.createElement("span");
          nm.className = "tree-item-name";
          nm.textContent = ent.name;
          leftWrap.appendChild(nm);

          var enterSpan = document.createElement("span");
          enterSpan.style.fontSize = "12px";
          enterSpan.style.color = "var(--link-accent)";
          enterSpan.style.whiteSpace = "nowrap";
          enterSpan.textContent = "打开 →";
          row.appendChild(leftWrap);
          row.appendChild(enterSpan);
          row.addEventListener("click", function () {
            loadFsTree(ent.path);
          });
          listEl.appendChild(row);
        });
      }
      return doc;
    });
  }

  function promptServiceControl(actionKind) {
    pendingServiceAction = actionKind;
    var bar = $("service-control-confirm-bar");
    var txt = $("service-control-confirm-text");
    var btn = $("confirm-service-action-btn");
    if (!bar || !txt || !btn) return;
    if (actionKind === "stop") {
      txt.textContent = "确认停止后台服务？停止后在途命令将被终止，本页面在重新启动服务前将无法连接。";
      btn.textContent = "确认停止后台服务";
      btn.className = "btn btn-danger btn-sm";
    } else {
      txt.textContent = "确认重启后台服务？在途子进程将被清理并由守护进程自动拉起新实例。";
      btn.textContent = "确认重启后台服务";
      btn.className = "btn btn-primary btn-sm";
    }
    bar.style.display = "flex";
  }

  function switchSkillSubtab(subName) {
    document.querySelectorAll(".skills-subtab-btn").forEach(function (b) {
      var isAct = b.getAttribute("data-skill-subtab") === subName;
      b.classList.toggle("active", isAct);
      b.setAttribute("aria-selected", isAct ? "true" : "false");
    });
    document.querySelectorAll(".skills-subview").forEach(function (v) {
      v.classList.toggle("active", v.id === "skills-subview-" + subName);
    });
    if (subName === "trash") {
      loadSkillTrashList();
    }
  }

  function _extractWorkersDevBase(urlStr) {
    var s = isSafeHttpsUrl(urlStr) ? String(urlStr).trim() : "";
    if (!s) return "";
    var base = s.replace(/\/mcp(?:\/readonly)?\/?$/, "");
    var isWorkersDev = false;
    try {
      var uObj = new URL(base);
      isWorkersDev = /\.workers\.dev$/i.test(uObj.hostname);
    } catch (e) {
      isWorkersDev = base.indexOf(".workers.dev") >= 0;
    }
    return isWorkersDev ? base : "";
  }

  function probeWorkersDevReachabilitySilent() {
    var effTop = resolveEffectiveTopView(state.connection || {});
    var wBase = _extractWorkersDevBase(effTop.mcp_url || "");
    if (!wBase) return;
    var ctrl = typeof AbortController !== "undefined" ? new AbortController() : null;
    var timer = setTimeout(function () {
      if (ctrl) ctrl.abort();
    }, 3200);
    fetch(wBase + "/healthz", {
      method: "GET",
      mode: "no-cors",
      cache: "no-store",
      signal: ctrl ? ctrl.signal : undefined,
    })
      .then(function () {
        clearTimeout(timer);
        if ($("workers-proxy-alert")) $("workers-proxy-alert").style.display = "none";
      })
      .catch(function () {
        clearTimeout(timer);
        if ($("workers-proxy-alert")) $("workers-proxy-alert").style.display = "block";
        showToast("当前浏览器无法直连 *.workers.dev，绑定连接器时请临时切换全局代理 10 秒或配置自定义域名。", true);
      });
  }

  function probeAndOpenGeminiConnectors() {
    var geminiTarget = "https://gemini.google.com/customize/connectors";
    // Immediately open synchronously inside the user click gesture so Safari/Firefox never block the tab
    window.open(geminiTarget, "_blank", "noopener");

    var effTop = resolveEffectiveTopView(state.connection || {});
    var mcpUrl = isSafeHttpsUrl(effTop.mcp_url) ? String(effTop.mcp_url).trim() : "";
    if ($("workers-proxy-alert")) {
      $("workers-proxy-alert").style.display = "none";
    }
    if (!mcpUrl) {
      return;
    }
    var mcpBase = mcpUrl.replace(/\/mcp\/?$/, "");
    var isWorkersDev = Boolean(_extractWorkersDevBase(mcpUrl));

    var ctrl = typeof AbortController !== "undefined" ? new AbortController() : null;
    var timer = setTimeout(function () {
      if (ctrl) ctrl.abort();
    }, 3200);

    fetch(mcpBase + "/healthz", {
      method: "GET",
      mode: "no-cors",
      cache: "no-store",
      signal: ctrl ? ctrl.signal : undefined,
    })
      .then(function () {
        clearTimeout(timer);
        if ($("workers-proxy-alert")) $("workers-proxy-alert").style.display = "none";
      })
      .catch(function () {
        clearTimeout(timer);
        var activeSessions = Number((state && state.authorized_sessions_count) || 0);
        if (isWorkersDev && activeSessions <= 0 && $("workers-proxy-alert")) {
          $("workers-proxy-alert").style.display = "flex";
        }
      });
  }

  var currentSettingsCat = "gateways";

  function switchSettingsCategory(catName) {
    var valid = ["gateways", "runtime", "tools", "skills", "appearance"];
    var target = valid.indexOf(catName) >= 0 ? catName : "gateways";
    currentSettingsCat = target;
    document.querySelectorAll(".settings-nav-btn").forEach(function (btn) {
      var active = btn.getAttribute("data-settings-cat") === target;
      btn.classList.toggle("active", active);
      btn.setAttribute("aria-selected", active ? "true" : "false");
    });
    document.querySelectorAll(".settings-pane").forEach(function (pane) {
      pane.classList.toggle("active", pane.id === "settings-pane-" + target);
    });
    if (target === "skills") {
      loadSkillTrashList();
    }
    try {
      if (window.location.hash !== "#settings/" + target) {
        window.history.replaceState(null, "", "#settings/" + target);
      }
    } catch (e) {}
  }

  function openSettings(catName) {
    var wb = $("workbench-view");
    var sv = $("settings-view");
    if (wb) {
      wb.classList.remove("active");
      wb.style.display = "none";
    }
    if (sv) {
      sv.classList.add("active");
      sv.style.display = "block";
    }
    if ($("open-settings-btn")) $("open-settings-btn").style.display = "none";
    if ($("close-settings-top-btn")) $("close-settings-top-btn").style.display = "inline-flex";
    switchSettingsCategory(catName || currentSettingsCat || "gateways");
    window.scrollTo(0, 0);
  }

  function closeSettings() {
    var wb = $("workbench-view");
    var sv = $("settings-view");
    if (sv) {
      sv.classList.remove("active");
      sv.style.display = "none";
    }
    if (wb) {
      wb.classList.add("active");
      wb.style.display = "";
    }
    if ($("open-settings-btn")) $("open-settings-btn").style.display = "inline-flex";
    if ($("close-settings-top-btn")) $("close-settings-top-btn").style.display = "none";
    try {
      if (window.location.hash && window.location.hash.indexOf("#settings") === 0) {
        window.history.replaceState(null, "", window.location.pathname + window.location.search);
      }
    } catch (e) {}
    window.scrollTo(0, 0);
  }

  function switchActivityPane(paneName) {
    var valid = ["tasks", "undo", "trash", "audit"];
    var target = valid.indexOf(paneName) >= 0 ? paneName : "tasks";
    document.querySelectorAll(".activity-seg-btn").forEach(function (btn) {
      var active = btn.getAttribute("data-activity-pane") === target;
      btn.classList.toggle("active", active);
      btn.setAttribute("aria-selected", active ? "true" : "false");
    });
    document.querySelectorAll(".activity-pane").forEach(function (pane) {
      pane.classList.toggle("active", pane.id === "activity-pane-" + target);
    });
  }

  window.__cosmosStudioNav = {
    openSettings: openSettings,
    closeSettings: closeSettings,
    switchSettingsCategory: switchSettingsCategory,
    switchActivityPane: switchActivityPane
  };

  function bindEvents() {
    // Workbench <-> Unified Settings Center navigation
    if ($("open-settings-btn")) {
      $("open-settings-btn").addEventListener("click", function () {
        openSettings(currentSettingsCat);
      });
    }
    if ($("close-settings-btn")) {
      $("close-settings-btn").addEventListener("click", closeSettings);
    }
    if ($("close-settings-top-btn")) {
      $("close-settings-top-btn").addEventListener("click", closeSettings);
    }
    document.querySelectorAll("[data-open-settings]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        openSettings(btn.getAttribute("data-open-settings") || "gateways");
      });
    });
    document.querySelectorAll(".settings-nav-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        switchSettingsCategory(btn.getAttribute("data-settings-cat"));
      });
    });
    document.querySelectorAll(".activity-seg-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        switchActivityPane(btn.getAttribute("data-activity-pane"));
      });
    });

    document.addEventListener("keydown", function (ev) {
      if ((ev.ctrlKey || ev.metaKey) && ev.key === ",") {
        ev.preventDefault();
        var sv = $("settings-view");
        if (sv && sv.classList.contains("active")) closeSettings();
        else openSettings(currentSettingsCat);
      } else if (ev.key === "Escape") {
        var idModal = $("identity-png-modal");
        var diffModal = $("diff-preview-modal");
        if (idModal && idModal.style.display !== "none") return;
        if (diffModal && diffModal.style.display !== "none") return;
        var sv2 = $("settings-view");
        if (sv2 && sv2.classList.contains("active")) {
          closeSettings();
        }
      }
    });

    // Legacy tab-btn compatibility shim (if any external caller/test triggers)
    document.querySelectorAll(".tab-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var target = btn.getAttribute("data-tab");
        if (target === "overview" || target === "workspace" || target === "recovery") {
          closeSettings();
        } else if (target === "tools" || target === "skills") {
          openSettings(target);
        }
      });
    });

    // 2 Host Scene Segmented Switcher
    document.querySelectorAll("#host-scene-switcher .host-seg-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        switchHostScene(btn.getAttribute("data-host-scene"));
      });
    });

    // First-message `@` Wakeup Copy CTA + Host Skill Guide Copy CTA
    function copyHostSkillGuide(btn, hostKind) {
      var targetToast =
        hostKind === "chatgpt"
          ? "已复制 AI 操作守则：工作区或桌面端可存入 Skills，网页版 Chat 与 Work 模式均可粘贴到 Project（项目）Instructions 或自定义指令"
          : "已复制 AI 操作守则，请粘贴保存到网页版 Gemini 左侧栏 Customize（自定义） -> Skills（技能）";
      var tc = (state && state.tools_center) || {};
      var cachedMd = String(tc.skill_markdown || tc.skill_preview || "").trim();
      if (cachedMd) {
        copyText(cachedMd, btn);
        showToast(targetToast, false);
        return;
      }
      fetch("/skill?lang=zh", { method: "GET", credentials: "same-origin", cache: "no-store" })
        .then(function (r) {
          return r.ok ? r.text() : "";
        })
        .then(function (txt) {
          var md = String(txt || "").trim();
          if (!md) {
            showToast("未能读取操作守则文本，请稍后重试。", true);
            return;
          }
          copyText(md, btn);
          showToast(targetToast, false);
        })
        .catch(function () {
          showToast("读取操作守则失败，请确认本地服务在线。", true);
        });
    }

    if ($("copy-wake-prompt-btn")) {
      $("copy-wake-prompt-btn").addEventListener("click", function () {
        var promptStr = buildWakeTestPrompt();
        copyText(promptStr, $("copy-wake-prompt-btn"));
        showToast("已复制首句唤醒测试词：" + promptStr, false);
      });
    }
    if ($("copy-gemini-guide-wake-btn")) {
      $("copy-gemini-guide-wake-btn").addEventListener("click", function () {
        var promptStr = buildWakeTestPrompt();
        copyText(promptStr, $("copy-gemini-guide-wake-btn"));
        showToast("已复制首句唤醒测试词：" + promptStr, false);
      });
    }
    if ($("copy-host-skill-btn")) {
      $("copy-host-skill-btn").addEventListener("click", function () {
        copyHostSkillGuide($("copy-host-skill-btn"), "gemini");
      });
    }
    if ($("copy-wake-skill-btn")) {
      $("copy-wake-skill-btn").addEventListener("click", function () {
        copyHostSkillGuide($("copy-wake-skill-btn"), "gemini");
      });
    }
    function getEffectiveToolPrefix() {
      var tc = (state && state.tools_center) || {};
      var raw = String(tc.tool_prefix || state.tool_prefix || "pc")
        .trim()
        .replace(/_+$/, "");
      return /^[A-Za-z][A-Za-z0-9_]{0,15}$/.test(raw) ? raw : "pc";
    }

    var SHOWCASE_PROMPTS = {
      blackhole: '在当前工作区写一个纯离线单文件 blackhole_studio.html，用原生 WebGL2（GLSL 300）实时光线步进渲染带发光吸积盘和引力透镜效果的黑洞；加上左键旋转、滚轮缩放，右侧做一个简洁的中文半透明控制面板，支持切换「俯瞰盘面 / 掠过视界 / 穿越光环」三组电影机位，以及黑洞质量、自旋、吸积盘亮度、时间流速四个实时滑块，写完后本地启动检查确认零报错。',
      holo: '在当前工作区写一个纯离线单文件 gemini_holo_cards.html，用原生 WebGL2 和程序化 Canvas 做出 3 张带薄膜干涉金属反光的 3D 全息典藏卡，主题为 Gemini 4 的 06 C（Carbon）、01 H（Hydrogen）、10 Ne（Neon）；支持鼠标悬停弹簧 3D 倾角与视差、点击 180° 翻转看背面、顶部切换「一字排开 / 聚焦单卡」以及三档色温环境光，不依赖任何外部图片和 CDN，写完后帮我本地打开验收。',
      canyon: '在当前工作区新建 neon_canyon 目录，按多文件工程结构（index.html、styles.css、terrain.js、audio.js、game.js）写一个纯离线原生 WebGL2 3D 低空飞行游戏「霓虹峡谷低空飞行」：合成波落日与霓虹线框峡谷、穿越空中能量光环触发加速与连击、躲避赤红能量柱与峡谷绝壁，用 Web Audio 实时合成引擎和穿环音效，支持 WASD/方向键与鼠标自动切换、顶部显示得分/最高分/连击/空速/FPS 与暂停重开按钮，写完后本地运行验收无控制台报错。'
    };

    function buildChatGptConnectPrompt(kind, targetUrl, effTop) {
      var isRo = kind === "readonly";
      var pfx = getEffectiveToolPrefix();
      var statusTool = pfx + "_get_status";
      var statusHint =
        statusTool === "pc_get_status" || statusTool === "get_status"
          ? "pc_get_status 或 get_status"
          : statusTool + "（或 pc_get_status / get_status）";
      var targetDesc = isRo
        ? "ChatGPT Plus / Pro，授权后可在 Chat 和 Work 中通过 @WebAI2PC 使用该服务提供的只读工具。"
        : "ChatGPT Team / Business / Enterprise / Edu 工作区，授权后可在 Chat 和 Work 中通过 @WebAI2PC 使用该服务提供、且工作区允许的读写工具（日常在 Chat 调用不扣 Work / Codex 额度）。";
      var effSlot = (effTop && effTop.slot) || {};
      var effMode = String(effSlot.effective_mode || effSlot.submode || (effTop && (effTop.effective_tunnel_mode || effTop.tunnel_mode)) || "https").trim();
      var gatewayNote = "公网 HTTPS 已就绪（通道：" + effMode + "）";
      if (effTop && effTop.tunnel_error) {
        gatewayNote += "；最近提示：" + String(effTop.tunnel_error).trim();
      }
      return [
        "请帮我把 WebAI2PC 接入我当前选中的 ChatGPT 工作区/账号，并完成首次真实调用。",
        "",
        "插件名称：WebAI2PC",
        "MCP 地址：" + targetUrl,
        "认证方式：OAuth",
        "使用目标：" + targetDesc,
        "本地控制台通道状态：" + gatewayNote,
        "",
        "请按以下顺序执行：",
        "",
        "1. 先检查当前工作区是否已经有指向这个 MCP 地址的 WebAI2PC 连接。有就复用，没有就优先用当前会话可用的插件管理、连接或创建工具接入现有 MCP 服务。不要默认打开云浏览器，也不要新建中转服务。只有原生工具无法完成某一步时，才说明卡点和可用的替代入口（例如让我在已登录本机浏览器打开 https://chatgpt.com/plugins 点 ＋ -> 添加自定义 MCP 服务器，或找管理员开启 Create plugins with MCPs 权限）。",
        "",
        "2. 使用 OAuth，按服务端实际公布的元数据配置认证。如果需要我选择账号、同意授权，或由工作区管理员批准，请先完成你能做的配置，再把我带到需要操作的那一步。不要让我在聊天里粘贴密码、令牌或授权码。如果自动发现失败，告诉我具体失败在哪一步。",
        "",
        "3. 授权并安装后，读取 WebAI2PC 实际公布的工具和参数。找到 " + statusHint + "，用实际参数调用一次，确认是否返回我电脑的主机名和系统。必须通过 WebAI2PC 调用，旧插件的结果或历史状态不能作为这次验收结果。",
        "",
        "4. 最后分别告诉我：连接是否创建或复用、OAuth 是否完成、状态工具是否真实调用成功、在哪个模式完成验证。能分别在 Chat 和 Work 验证就分别验证，无法验证的模式标为未验证。列出已发现的工具和已知权限限制，首次验收只读状态，不改文件或系统设置。",
        "",
        "请直接执行你能完成的步骤。只有遇到必须由我操作的步骤时才暂停，并告诉我在哪个页面、点哪个按钮。最后附上插件链接（如果有）和实际工具调用结果。",
        "",
        "【安全提醒：上方包含本机专属连接地址，仅限粘贴给本人登录的账号使用，请勿发往微信群、论坛、公开 Issue 或转给他人。】",
      ].join("\n");
    }

    if ($("copy-chatgpt-skill-btn")) {
      $("copy-chatgpt-skill-btn").addEventListener("click", function () {
        copyHostSkillGuide($("copy-chatgpt-skill-btn"), "chatgpt");
      });
    }
    if ($("copy-chatgpt-wake-btn")) {
      $("copy-chatgpt-wake-btn").addEventListener("click", function () {
        var statusTool = getEffectiveToolPrefix() + "_get_status";
        var cgptPrompt = "@WebAI2PC 请调用 " + statusTool + " 确认连接状态，并查看当前开放的工作目录与文件结构";
        copyText(cgptPrompt, $("copy-chatgpt-wake-btn"));
        showToast("已复制首句验证词（装好插件后推荐在 Chat 模式粘贴发送，不扣 Work/Codex 额度）：" + cgptPrompt, false);
      });
    }

    // Primary ChatGPT Action: Copy URL & Synchronously Open Logged-In Local Browser `https://chatgpt.com/plugins`
    document.querySelectorAll("[data-open-chatgpt-plugins]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var kind = btn.getAttribute("data-open-chatgpt-plugins");
        var effTop = resolveEffectiveTopView(state.connection || {});
        var targetUrl = kind === "readonly" ? effTop.readonly_mcp_url || "" : effTop.mcp_url || "";
        if (!effTop.public_https_ready || !isSafeHttpsUrl(targetUrl)) {
          showToast("网关尚未就绪，请等待公网 HTTPS 地址生成后再操作。", true);
          return;
        }
        window.open("https://chatgpt.com/plugins", "_blank", "noopener");
        copyText(targetUrl, btn);
        showToast("已复制连接地址并打开 ChatGPT 插件页（仅限填入本人账号，请勿外发给他人或群聊）：点 ＋ -> 添加自定义 MCP 服务器，名称填 WebAI2PC，粘贴地址后点「本机一键允许连接」", false);
        probeWorkersDevReachabilitySilent();
      });
    });

    // Secondary ChatGPT Action: Copy Zero-Secret Diagnostic Prompt when encountering connection/permission issues
    document.querySelectorAll("[data-copy-chatgpt-assist]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var kind = btn.getAttribute("data-copy-chatgpt-assist");
        var effTop = resolveEffectiveTopView(state.connection || {});
        var targetUrl = kind === "readonly" ? effTop.readonly_mcp_url || "" : effTop.mcp_url || "";
        if (!effTop.public_https_ready || !isSafeHttpsUrl(targetUrl)) {
          showToast("网关尚未就绪，请等待公网 HTTPS 地址生成后再复制。", true);
          return;
        }
        var connectPrompt = buildChatGptConnectPrompt(kind, targetUrl, effTop);
        copyText(connectPrompt, btn);
        showToast("已复制 ChatGPT 接入与排障指令（仅限填入本人账号，请勿外发给他人或群聊；不含配对码与本机路径）", false);
      });
    });

    // One-Shot Showcase Prompt Copy Buttons (auto-adapts `@Cosmos` vs `@WebAI2PC` based on active host scene tab)
    document.querySelectorAll("[data-copy-showcase]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var caseKey = btn.getAttribute("data-copy-showcase") || "";
        var bodyText = SHOWCASE_PROMPTS[caseKey] || "";
        if (!bodyText) return;
        var isCgptScene = Boolean($("host-panel-chatgpt") && $("host-panel-chatgpt").classList.contains("active"));
        var prefix = isCgptScene ? "@WebAI2PC " : "@Cosmos ";
        var fullPrompt = prefix + bodyText;
        copyText(fullPrompt, btn);
        showToast(
          isCgptScene
            ? "已复制 " + "@WebAI2PC 实机案例提示词（可直接粘贴到 ChatGPT 普通 Chat 模式运行，零扣 Work/Codex 额度）"
            : "已复制 " + "@Cosmos 实机案例提示词，直接粘贴到网页版 Gemini 发送即可本地生成运行",
          false
        );
      });
    });

    // Top URL Copy Buttons (strictly copies only real `https://` URLs from active displayed gateway)
    document.querySelectorAll("[data-copy-url-kind]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var kind = btn.getAttribute("data-copy-url-kind");
        var effTop = resolveEffectiveTopView(state.connection || {});
        var targetUrl = kind === "readonly" ? effTop.readonly_mcp_url || "" : effTop.mcp_url || "";
        if (!isSafeHttpsUrl(targetUrl)) {
          showToast("加密连接通道正在建立，请稍候复制。", true);
          return;
        }
        copyText(targetUrl, btn);
        showToast("已复制连接地址（仅限填入本人账号，请勿外发给他人或群聊）", false);
      });
    });

    // Per-card independent full-access `/mcp` copy buttons (`#gw-copy-{id}`)
    document.querySelectorAll("[data-gw-copy]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var gid = btn.getAttribute("data-gw-copy");
        var conn = (state && state.connection) || {};
        var gws = conn.gateways || state.gateways || {};
        var sl = gws[gid] || {};
        var targetUrl = sl.status === "ready" && isSafeHttpsUrl(sl.mcp_url) ? String(sl.mcp_url).trim() : "";
        if (!targetUrl) {
          showToast("该网关尚未连通，暂无法复制地址。", true);
          return;
        }
        copyText(targetUrl, btn);
        showToast("已复制连接地址（仅限填入本人账号，请勿外发给他人或群聊）", false);
      });
    });

    // Per-card independent Plus/Pro readonly `/mcp/readonly` copy buttons (`#gw-copy-ro-{id}`)
    document.querySelectorAll("[data-gw-copy-ro]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var gid = btn.getAttribute("data-gw-copy-ro");
        var conn = (state && state.connection) || {};
        var gws = conn.gateways || state.gateways || {};
        var sl = gws[gid] || {};
        var baseMcp = sl.status === "ready" && isSafeHttpsUrl(sl.mcp_url) ? String(sl.mcp_url).trim() : "";
        var targetUrl = baseMcp ? deriveReadonlyUrl(sl, baseMcp) : "";
        if (!targetUrl) {
          showToast("该网关尚未连通，暂无法复制只读地址。", true);
          return;
        }
        copyText(targetUrl, btn);
        showToast("已复制只读连接地址（仅限填入本人账号，请勿外发给他人或群聊）", false);
      });
    });

    // Per-card independent gateway toggle switches (`#gw-switch-{id}` with stopPropagation against accordion header)
    document.querySelectorAll("[data-gw-switch]").forEach(function (sw) {
      sw.addEventListener("click", function (ev) {
        ev.stopPropagation();
      });
      sw.addEventListener("keydown", function (ev) {
        ev.stopPropagation();
      });
      sw.addEventListener("change", function () {
        var gid = sw.getAttribute("data-gw-switch");
        var wantEn = Boolean(sw.checked);
        var conn = (state && state.connection) || {};
        var gws = conn.gateways || state.gateways || {};
        var sl = gws[gid] || {};

        if (wantEn && gid === "workers_dev") {
          var hasSavedWd = isSafeHttpsUrl(sl.configured_url || conn.workers_dev_url);
          var typedCfTok = ($("cf-api-token-input") && $("cf-api-token-input").value.trim()) || "";
          if (!hasSavedWd) {
            setConnCardExpanded(2, true);
            if (typedCfTok && $("deploy-cf-workers-btn")) {
              $("deploy-cf-workers-btn").click();
              return;
            }
            sw.checked = false;
            if ($("cf-api-token-input")) $("cf-api-token-input").focus();
            showToast("首次启用请先粘贴一次 Cloudflare API 令牌完成部署；部署后即可随时直接打开开关。", true);
            return;
          }
        }

        if (wantEn && gid === "self_hosted") {
          var hasSavedSh =
            isSafeHttpsUrl(sl.configured_url || conn.vps_hub_url) ||
            Boolean(conn.tunnel_token_configured) ||
            Boolean(conn.vps_ssh);
          if (!hasSavedSh) {
            setConnCardExpanded(3, true);
            sw.checked = false;
            var hostInp = activeCard3Subtab === "custom_domain" ? $("custom-url-input") : $("vps-prov-host-input");
            if (hostInp) hostInp.focus();
            showToast("首次启用请先部署 24h 主站或填写自有固定域名保存。", true);
            return;
          }
        }

        sw.disabled = true;
        apiFetch("/api/studio/connection", {
          method: "POST",
          body: { action: "toggle_gateway", gateway_id: gid, enabled: wantEn },
        })
          .then(function (d) {
            sw.disabled = false;
            if (!d.ok) {
              sw.checked = !wantEn;
              return showToast(d.error || "切换网关开关失败", true);
            }
            renderAll(d);
            showToast(d.message || (wantEn ? "已开启网关" : "已关闭网关"), false);
          })
          .catch(function () {
            sw.disabled = false;
            sw.checked = !wantEn;
            showToast("网络请求失败，请确认本机服务在线", true);
          });
      });
    });

    // Progressive Disclosure Channel Card Header & Toggle Clicks (ignores direct switch/input clicks)
    document.querySelectorAll(".conn-card-header-bar").forEach(function (hdr) {
      function toggleGroup() {
        var g = Number(hdr.getAttribute("data-toggle-conn-group") || 0);
        if (!g) return;
        var card = $("conn-card-" + g);
        var nowOpen = card ? card.classList.contains("expanded-card") : false;
        setConnCardExpanded(g, !nowOpen);
      }
      hdr.addEventListener("click", function (ev) {
        if (ev.target && ev.target.closest && ev.target.closest("a, input, label, .gw-switch")) return;
        toggleGroup();
      });
      hdr.addEventListener("keydown", function (ev) {
        if (ev.target && ev.target.closest && ev.target.closest("input, .gw-switch")) return;
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          toggleGroup();
        }
      });
    });

    // Open Gemini Connectors Settings with `/healthz` pre-probe
    if ($("open-gemini-connectors-btn")) {
      $("open-gemini-connectors-btn").addEventListener("click", probeAndOpenGeminiConnectors);
    }
    if ($("dismiss-workers-proxy-alert-btn")) {
      $("dismiss-workers-proxy-alert-btn").addEventListener("click", function () {
        if ($("workers-proxy-alert")) $("workers-proxy-alert").style.display = "none";
      });
    }
    if ($("dismiss-wake-banner-btn")) {
      $("dismiss-wake-banner-btn").addEventListener("click", function () {
        if ($("first-wake-banner")) $("first-wake-banner").style.display = "none";
        try {
          localStorage.setItem("cosmos_wake_banner_dismissed", "1");
        } catch (e) {}
      });
    }
    if ($("focus-custom-domain-btn")) {
      $("focus-custom-domain-btn").addEventListener("click", function () {
        if ($("workers-proxy-alert")) $("workers-proxy-alert").style.display = "none";
        openSettings("gateways");
        setConnCardExpanded(2, true);
        var inp = $("cf-custom-domain-input");
        if (inp) {
          setTimeout(function () {
            inp.scrollIntoView({ behavior: "smooth", block: "center" });
            inp.focus();
          }, 60);
        }
      });
    }

    // Tab 5 Subtabs
    document.querySelectorAll(".skills-subtab-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        switchSkillSubtab(btn.getAttribute("data-skill-subtab"));
      });
    });

    // Password input visibility toggles
    document.querySelectorAll("[data-toggle-pw]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var inp = $(btn.getAttribute("data-toggle-pw"));
        if (!inp) return;
        var isPw = inp.type === "password";
        inp.type = isPw ? "text" : "password";
        btn.textContent = isPw ? "隐藏" : "显示";
      });
    });

    // Connection password & dynamic pair code copy
    if ($("toggle-pw-btn")) {
      $("toggle-pw-btn").addEventListener("click", function () {
        var box = $("conn-pw-box");
        var shown = box.getAttribute("data-shown") === "1";
        if (shown) {
          box.setAttribute("data-shown", "0");
          box.textContent = "••••••••••••••••••••";
          $("toggle-pw-btn").textContent = "显示口令";
        } else {
          box.setAttribute("data-shown", "1");
          box.textContent = box.getAttribute("data-secret") || "(未记录明文口令)";
          $("toggle-pw-btn").textContent = "隐藏口令";
        }
      });
    }

    if ($("copy-pw-btn")) {
      $("copy-pw-btn").addEventListener("click", function () {
        var secret = $("conn-pw-box").getAttribute("data-secret") || "";
        copyText(secret, $("copy-pw-btn"));
      });
    }

    if ($("copy-dynamic-code-btn")) {
      $("copy-dynamic-code-btn").addEventListener("click", function () {
        var dynVal = ($("dynamic-pair-code-box") && $("dynamic-pair-code-box").textContent.trim()) || "";
        if (!dynVal || dynVal === "------") return;
        copyText(dynVal, $("copy-dynamic-code-btn"));
      });
    }

    if ($("copy-pair-code-btn")) {
      $("copy-pair-code-btn").addEventListener("click", function () {
        var codeVal = ($("pair-code-box") && $("pair-code-box").textContent.trim()) || "";
        if (!codeVal || codeVal === "----") return;
        copyText(codeVal, $("copy-pair-code-btn"));
      });
    }

    // Quick Enable HTTPS Tunnel CTA when in `local` mode
    if ($("quick-enable-cf-btn")) {
      $("quick-enable-cf-btn").addEventListener("click", function () {
        apiFetch("/api/studio/connection", {
          method: "POST",
          body: { action: "toggle_gateway", gateway_id: "instant", enabled: true },
        }).then(function (d) {
          if (!d.ok) return showToast(d.error || "开启加密通道失败", true);
          renderAll(d);
          showToast(d.message || "已开启默认连接网关，正在获取网页版可用地址…", false);
        });
      });
    }

    // Card 1: Activate Out-of-the-Box Mode + Quick Tunnel Manual Switch + Export/Import Identity Recovery PNG
    if ($("activate-card1-btn")) {
      $("activate-card1-btn").addEventListener("click", function () {
        apiFetch("/api/studio/connection", {
          method: "POST",
          body: {
            action: "save_gateway_config",
            gateway_id: "instant",
            submode: "public_gateway",
            enabled: true,
            retry_fixed: true,
          },
        }).then(function (d) {
          if (!d.ok) return showToast(d.error || "切换连接模式失败", true);
          renderAll(d);
          showToast(d.message || "已开启免登录固定网址模式", false);
        });
      });
    }

    if ($("switch-card1-quick-btn")) {
      $("switch-card1-quick-btn").addEventListener("click", function () {
        apiFetch("/api/studio/connection", {
          method: "POST",
          body: {
            action: "save_gateway_config",
            gateway_id: "instant",
            submode: "cloudflare",
            enabled: true,
          },
        }).then(function (d) {
          if (!d.ok) return showToast(d.error || "切换临时快速通道失败", true);
          renderAll(d);
          showToast(d.message || "第 1 类网关已切换为临时快速通道（重启会变网址）", false);
        });
      });
    }

    if ($("open-export-id-modal-btn")) {
      $("open-export-id-modal-btn").addEventListener("click", function () {
        openIdentityModal("export");
      });
    }
    if ($("open-import-id-modal-btn")) {
      $("open-import-id-modal-btn").addEventListener("click", function () {
        openIdentityModal("import");
      });
    }
    if ($("close-identity-modal-btn")) {
      $("close-identity-modal-btn").addEventListener("click", closeIdentityModal);
    }
    if ($("identity-png-modal")) {
      $("identity-png-modal").addEventListener("click", function (ev) {
        if (ev.target === $("identity-png-modal")) closeIdentityModal();
      });
    }

    if ($("confirm-export-png-btn")) {
      $("confirm-export-png-btn").addEventListener("click", function () {
        var pw = $("identity-export-pw-input").value.trim();
        if (!pw) return showToast("请先输入恢复卡加密口令", true);
        apiFetch("/api/studio/identity/export_png", {
          method: "POST",
          body: { passphrase: pw },
        }).then(function (d) {
          if (!d.ok || !d.png_base64) {
            return showToast(d.error || "导出身份恢复卡失败", true);
          }
          var a = document.createElement("a");
          a.href = "data:image/png;base64," + d.png_base64;
          a.download = d.filename || "cosmos-identity-recovery.png";
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          $("identity-export-pw-input").value = "";
          closeIdentityModal();
          showToast("已导出并下载节点身份恢复卡：" + (d.filename || ""), false);
        });
      });
    }

    if ($("confirm-import-png-btn")) {
      $("confirm-import-png-btn").addEventListener("click", function () {
        var fileInp = $("identity-import-file-input");
        var pw = $("identity-import-pw-input").value.trim();
        if (!fileInp || !fileInp.files || !fileInp.files[0]) {
          return showToast("请选择身份恢复卡 PNG 图片文件", true);
        }
        if (!pw) return showToast("请输入导出该恢复卡时设置的加密口令", true);
        var reader = new FileReader();
        reader.onload = function () {
          apiFetch("/api/studio/identity/import_png", {
            method: "POST",
            body: { png_base64: String(reader.result || ""), passphrase: pw },
          }).then(function (d) {
            if (!d.ok) return showToast(d.error || "恢复身份失败", true);
            $("identity-import-pw-input").value = "";
            fileInp.value = "";
            closeIdentityModal();
            renderAll(d);
            showToast(d.message || "已成功恢复固定节点身份", false);
          });
        };
        reader.readAsDataURL(fileInp.files[0]);
      });
    }

    // Card 2: 1-Click Cloudflare Workers Gateway Deploy (with multi-account select & token wipe)
    if ($("deploy-cf-workers-btn")) {
      $("deploy-cf-workers-btn").addEventListener("click", function () {
        var tok = $("cf-api-token-input").value.trim();
        var cusDom = $("cf-custom-domain-input").value.trim();
        var accSel = $("cf-account-select");
        var accId =
          $("cf-account-select-wrap").style.display !== "none" && accSel ? accSel.value.trim() : "";
        if (!tok) {
          return showToast("请先完成第 1 步并粘贴 Cloudflare API 令牌", true);
        }
        var btn = $("deploy-cf-workers-btn");
        btn.disabled = true;
        btn.textContent = "正在部署固定网关…";
        apiFetch("/api/studio/gateway/cloudflare/deploy", {
          method: "POST",
          body: {
            api_token: tok,
            account_id: accId,
            custom_domain: cusDom,
          },
        }).then(function (d) {
          btn.disabled = false;
          btn.textContent = "一键部署并开启（约 3 秒）";
          if (d.multiple_accounts_select_required || d.error === "multiple_accounts_select_required") {
            var accounts = d.accounts || [];
            if (accSel) {
              accSel.innerHTML = "";
              accounts.forEach(function (a) {
                var opt = document.createElement("option");
                opt.value = a.id;
                opt.textContent = (a.name || a.id) + " (" + a.id.slice(0, 8) + "…)";
                accSel.appendChild(opt);
              });
            }
            $("cf-account-select-wrap").style.display = "block";
            showToast("检测到多个 Cloudflare 账号，请在下拉框选择目标账号后再次点击部署。", false);
            return;
          }
          if (!d.ok) {
            return showToast(d.error || d.message || "部署固定网关失败", true);
          }
          $("cf-api-token-input").value = "";
          $("cf-account-select-wrap").style.display = "none";
          var okNote = $("cf-deploy-ok-note");
          if (okNote) {
            okNote.style.display = "block";
            okNote.textContent = "API 令牌已自动销毁，终身固定网址已生效：" + ((d.deploy_result && d.deploy_result.public_url) || "");
          }
          renderAll(d);
          showToast(d.message || "终身固定网址已生效，API 令牌已自动销毁", false);
        });
      });
    }

    // Card 3 Subtabs & Actions (userPickedCard3Subtab prevents 4s poll from snapping back)
    document.querySelectorAll(".card3-subtab-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var sub = btn.getAttribute("data-c3-tab");
        userPickedCard3Subtab = true;
        pendingSaveModeOverride = "";
        switchCard3Subtab(sub);
      });
    });

    document.querySelectorAll("#channel-selector .channel-option[data-mode]").forEach(function (el) {
      el.addEventListener("click", function () {
        var m = el.getAttribute("data-mode");
        if (m === "vps" || m === "custom" || m === "cloudflare_token") {
          setConnCardExpanded(3, true);
          userPickedCard3Subtab = true;
          switchCard3Subtab("custom_domain", m);
          if (m === "vps" && $("vps-ssh-details")) {
            $("vps-ssh-details").open = true;
          }
        }
      });
    });

    // Card 3 Sub-pane 1: 1-Click 24h VPS Hub Provision (supports SSH key passwordless login)
    if ($("vps-provision-btn")) {
      $("vps-provision-btn").addEventListener("click", function () {
        var host = $("vps-prov-host-input").value.trim();
        var pw = $("vps-prov-pw-input").value;
        var keyPath = $("vps-prov-key-input") ? $("vps-prov-key-input").value.trim() : "";
        var useSshKey = Boolean($("chk-vps-use-ssh-key") && $("chk-vps-use-ssh-key").checked);
        var user = $("vps-prov-user-input").value.trim() || "root";
        var port = $("vps-prov-port-input").value.trim() || "22";
        var dom = $("vps-prov-domain-input").value.trim();
        if (!host) return showToast("请填写服务器公网 IP", true);
        if (!pw && !keyPath && !useSshKey) {
          return showToast("请填写服务器 SSH 密码，或勾选使用本机默认 SSH 密钥 / 填写私钥路径", true);
        }

        var btn = $("vps-provision-btn");
        btn.disabled = true;
        btn.textContent = "正在部署 24h 主站（约 20~45 秒）…";
        apiFetch("/api/studio/gateway/vps/provision", {
          method: "POST",
          body: {
            host: host,
            ssh_password: pw,
            ssh_user: user,
            ssh_port: port,
            identity_file: keyPath,
            use_ssh_key: useSshKey,
            custom_domain: dom,
          },
        }).then(function (d) {
          btn.disabled = false;
          btn.textContent = "一键部署 24h 主站并开启";
          if (!d.ok) {
            return showToast(d.error || d.message || "部署 24h 主站失败", true);
          }
          $("vps-prov-pw-input").value = "";
          renderAll(d);
          showToast(d.message || "自有服务器 24h 主站部署完成并已开启此网关", false);
        });
      });
    }

    // Card 3 Sub-pane 2: Own Fixed Domain / Named Tunnel Token / Existing SSH Reverse Save (non-exclusive save_gateway_config)
    if ($("save-channel-btn")) {
      $("save-channel-btn").addEventListener("click", function () {
        var vpsSsh = $("vps-ssh-input") ? $("vps-ssh-input").value.trim() : "";
        var vpsPub = $("vps-public-url-input") ? $("vps-public-url-input").value.trim() : "";
        var cfTok = $("cf-token-input") ? $("cf-token-input").value.trim() : "";
        var customUrl = $("custom-url-input") ? $("custom-url-input").value.trim() : "";

        var body = { action: "save_gateway_config", gateway_id: "self_hosted", enabled: true };
        if (pendingSaveModeOverride === "vps" || (vpsSsh && (vpsPub || !customUrl))) {
          body.submode = "vps";
          body.vps_ssh = vpsSsh;
          body.vps_remote_port = ($("vps-remote-port-input") && $("vps-remote-port-input").value.trim()) || "18096";
          body.public_url = vpsPub || customUrl;
          body.public_base = body.public_url;
        } else if (cfTok || (state.connection && state.connection.tunnel_token_configured && customUrl)) {
          body.submode = "cloudflare_token";
          body.tunnel_token = cfTok;
          body.public_url = customUrl;
        } else {
          body.submode = "custom";
          body.public_url = customUrl;
        }

        apiFetch("/api/studio/connection", { method: "POST", body: body }).then(function (d) {
          if (!d.ok) return showToast(d.error || "保存固定域名配置失败", true);
          pendingSaveModeOverride = "";
          if ($("cf-token-input")) $("cf-token-input").value = "";
          renderAll(d);
          showToast(d.message || "自有固定域名网关已开启", false);
        });
      });
    }

    // Top Header Service Control
    if ($("top-restart-service-btn")) {
      $("top-restart-service-btn").addEventListener("click", function () {
        promptServiceControl("restart");
      });
    }
    if ($("top-stop-service-btn")) {
      $("top-stop-service-btn").addEventListener("click", function () {
        promptServiceControl("stop");
      });
    }
    $("cancel-service-action-btn").addEventListener("click", function () {
      pendingServiceAction = "";
      $("service-control-confirm-bar").style.display = "none";
    });
    $("confirm-service-action-btn").addEventListener("click", function () {
      if (!pendingServiceAction) return;
      var act = pendingServiceAction;
      $("service-control-confirm-bar").style.display = "none";
      pendingServiceAction = "";
      apiFetch("/api/studio/service-control", {
        method: "POST",
        body: { action: act },
      }).then(function (d) {
        if (!d.ok) return showToast(d.error || "服务控制操作失败", true);
        if (act === "stop") {
          setStatusIndicator("offline", "后台服务已发出停止信号");
        }
        showToast(d.message || "已发出服务控制信号", false);
      });
    });

    // Session unlock / lock
    $("session-unlock-form").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var pw = $("session-pw-input").value.trim();
      apiFetch("/api/studio/unlock", { method: "POST", body: { owner_password: pw } }).then(function (d) {
        if (!d.ok) return showToast(d.error || "口令不正确", true);
        renderAll(d);
        showToast(d.message || "会话已解锁", false);
      });
    });

    $("remote-unlock-form").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var pw = $("remote-pw-input").value.trim();
      if (!pw) return;
      apiFetch("/api/studio/unlock", { method: "POST", body: { owner_password: pw } }).then(function (d) {
        if (!d.ok) return showToast(d.error || "口令不正确", true);
        $("remote-pw-input").value = "";
        renderAll(d);
        showToast(d.message || "已解锁远程管理面板", false);
      });
    });

    $("session-lock-btn").addEventListener("click", function () {
      apiFetch("/api/studio/lock", { method: "POST", body: {} }).then(function () {
        apiFetch("/api/studio/state").then(renderAll);
        showToast("已锁定管理会话", false);
      });
    });

    $("quick-readonly-btn").addEventListener("click", function () {
      var reqSeq = ++toolsSafetyReqSeq;
      apiFetch("/api/studio/tools-safety", { method: "POST", body: { safety_mode: "readonly" } }).then(function (d) {
        if (reqSeq !== toolsSafetyReqSeq) return;
        if (!d.ok) return showToast(d.error || "切换失败", true);
        renderAll(d);
        showToast(d.message || "已切为只读浏览模式", false);
      });
    });

    if ($("quick-restore-dev-btn")) {
      $("quick-restore-dev-btn").addEventListener("click", function () {
        var reqSeq = ++toolsSafetyReqSeq;
        apiFetch("/api/studio/tools-safety", { method: "POST", body: { safety_mode: "full_dev" } }).then(function (d) {
          if (reqSeq !== toolsSafetyReqSeq) return;
          if (!d.ok) return showToast(d.error || "恢复失败", true);
          renderAll(d);
          showToast(d.message || "已恢复工作区内顺畅开发", false);
        });
      });
    }

    // Keep awake & autostart
    function saveRuntimePrefs() {
      apiFetch("/api/studio/connection", {
        method: "POST",
        body: {
          action: "set_runtime_prefs",
          keep_awake: $("chk-keep-awake").checked,
          autostart: $("chk-autostart").checked,
        },
      }).then(function (d) {
        if (!d.ok) {
          showToast(d.error || "更新失败", true);
          apiFetch("/api/studio/state").then(renderAll);
          return;
        }
        renderAll(d);
        showToast(d.message || "设置已更新", false);
      });
    }
    $("chk-keep-awake").addEventListener("change", saveRuntimePrefs);
    $("chk-autostart").addEventListener("change", function () {
      if ($("chk-wake-autostart")) $("chk-wake-autostart").checked = $("chk-autostart").checked;
      saveRuntimePrefs();
    });
    if ($("chk-wake-autostart")) {
      $("chk-wake-autostart").addEventListener("change", function () {
        if ($("chk-autostart")) $("chk-autostart").checked = $("chk-wake-autostart").checked;
        saveRuntimePrefs();
      });
    }

    $("revoke-sessions-btn").addEventListener("click", function () {
      apiFetch("/api/studio/connection", { method: "POST", body: { action: "revoke_sessions" } }).then(function (d) {
        if (!d.ok) return showToast(d.error || "断开会话失败", true);
        renderAll(d);
        showToast(d.message || "已断开全部网页会话", false);
      });
    });

    function currentAddWorkspaceAccess() {
      return $("chk-add-ws-readonly") && $("chk-add-ws-readonly").checked ? "readonly" : "readwrite";
    }

    // Tab 2: Native Folder Picker + Discover Common Code Directories + In-Page Tree
    if ($("pick-local-folder-btn")) {
      $("pick-local-folder-btn").addEventListener("click", function () {
        var btn = $("pick-local-folder-btn");
        btn.disabled = true;
        btn.textContent = "正在打开文件夹选择框…";
        apiFetch("/api/studio/workspaces/pick_native", {
          method: "POST",
          body: { add_immediately: true, access: currentAddWorkspaceAccess() },
        }).then(function (d) {
          btn.disabled = false;
          btn.textContent = "选择本地文件夹";
          if (d.ok && d.added) {
            if ($("chk-add-ws-readonly")) $("chk-add-ws-readonly").checked = false;
            renderAll(d);
            loadDiscoveredWorkspaces();
            showToast(d.message || "已添加所选本地文件夹", false);
            return;
          }
          if (d.cancelled) {
            return;
          }
          if (d.fallback === "in_page_tree") {
            loadFsTree(currentTreePath || "");
            showToast("当前环境不支持系统窗口，已为您展开页内目录树选择。", false);
            return;
          }
          if (d.error) {
            showToast(d.error, true);
          }
        });
      });
    }

    if ($("refresh-discover-dirs-btn")) {
      $("refresh-discover-dirs-btn").addEventListener("click", loadDiscoveredWorkspaces);
    }

    $("open-tree-picker-btn").addEventListener("click", function () {
      var drawer = $("fs-tree-drawer");
      if (drawer && drawer.classList.contains("open")) {
        setTreeDrawerOpen(false);
      } else {
        loadFsTree(currentTreePath || "");
      }
    });
    $("close-tree-btn").addEventListener("click", function () {
      setTreeDrawerOpen(false);
    });
    $("tree-drives-btn").addEventListener("click", function () {
      loadFsTree("");
    });
    $("tree-up-btn").addEventListener("click", function () {
      loadFsTree($("tree-up-btn").getAttribute("data-parent") || "");
    });
    $("tree-add-ws-btn").addEventListener("click", function () {
      if (!currentTreePath) return;
      mutateWorkspace({ action: "add", path: currentTreePath, access: currentAddWorkspaceAccess() }).then(function (d) {
        if (d && d.ok && $("chk-add-ws-readonly")) $("chk-add-ws-readonly").checked = false;
        loadDiscoveredWorkspaces();
      });
    });
    $("tree-set-primary-btn").addEventListener("click", function () {
      if (!currentTreePath) return;
      mutateWorkspace({ action: "set_primary", path: currentTreePath });
    });
    $("tree-mkdir-btn").addEventListener("click", function () {
      var nm = $("tree-mkdir-input").value.trim();
      if (!currentTreePath || !nm) return showToast("请先进入父目录并输入新文件夹名称", true);
      apiFetch("/api/studio/workspace", {
        method: "POST",
        body: { action: "mkdir", parent: currentTreePath, name: nm },
      }).then(function (d) {
        if (!d.ok) return showToast(d.error || "新建文件夹失败", true);
        $("tree-mkdir-input").value = "";
        showToast(d.message || "文件夹已创建", false);
        loadFsTree(d.created_path || currentTreePath);
      });
    });

    $("add-manual-ws-btn").addEventListener("click", function () {
      var val = $("manual-ws-input").value.trim();
      if (!val) return showToast("请输入要添加的文件夹路径", true);
      mutateWorkspace({ action: "add", path: val, access: currentAddWorkspaceAccess() }).then(function (d) {
        if (d && d.ok) {
          $("manual-ws-input").value = "";
          if ($("chk-add-ws-readonly")) $("chk-add-ws-readonly").checked = false;
          loadDiscoveredWorkspaces();
        }
      });
    });

    // Python path
    $("python-candidates-select").addEventListener("change", function () {
      var nextVal = $("python-candidates-select").value || "";
      $("python-path-input").value = nextVal;
      var saved = ((state.workspaces && state.workspaces.python_path) || "").trim();
      if ($("save-python-btn")) {
        $("save-python-btn").classList.toggle("is-dirty-unsaved", nextVal.trim() !== saved);
      }
    });
    $("save-python-btn").addEventListener("click", function () {
      mutateWorkspace({ action: "set_python", python_path: $("python-path-input").value.trim() });
    });

    // Tab 3: Tools, Safety, Host Skills Isolation, Tool Prefix & System Tray
    document.querySelectorAll("[data-target-safety]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var target = btn.getAttribute("data-target-safety");
        if (!target) return;
        var reqSeq = ++toolsSafetyReqSeq;
        apiFetch("/api/studio/tools-safety", { method: "POST", body: { safety_mode: target } }).then(function (d) {
          if (reqSeq !== toolsSafetyReqSeq) return;
          if (!d.ok) return showToast(d.error || "切换安全模式失败", true);
          renderAll(d);
          showToast(d.message || "安全模式已切换", false);
        });
      });
    });

    function pushToolsSafetySwitches(extraBody) {
      var reqSeq = ++toolsSafetyReqSeq;
      apiFetch("/api/studio/tools-safety", { method: "POST", body: extraBody }).then(function (d) {
        if (reqSeq !== toolsSafetyReqSeq) return;
        if (!d.ok) {
          showToast(d.error || "更新开关失败", true);
          apiFetch("/api/studio/state").then(renderAll);
          return;
        }
        renderAll(d);
        showToast(d.message || "设置已生效", false);
      });
    }

    $("chk-confirm-popups").addEventListener("change", function () {
      if ($("chk-confirm-popups").disabled) return;
      pushToolsSafetySwitches({ confirm_popups: $("chk-confirm-popups").checked });
    });

    if ($("chk-scan-host-skills")) {
      $("chk-scan-host-skills").addEventListener("change", function () {
        pushToolsSafetySwitches({ scan_host_global_skills: $("chk-scan-host-skills").checked });
      });
    }

    if ($("chk-tray-enabled")) {
      $("chk-tray-enabled").addEventListener("change", function () {
        pushToolsSafetySwitches({ tray_enabled: $("chk-tray-enabled").checked });
      });
    }

    if ($("save-tool-prefix-btn")) {
      $("save-tool-prefix-btn").addEventListener("click", function () {
        var tp = ($("tool-prefix-input") && $("tool-prefix-input").value.trim()) || "";
        if (!tp) return showToast("请输入合法的工具前缀（例如 pc 或 laptop）", true);
        pushToolsSafetySwitches({ tool_prefix: tp });
      });
    }

    function onPackToggle() {
      if ($("chk-pack-browser").disabled && $("chk-pack-desktop").disabled) return;
      pushToolsSafetySwitches({
        pack_browser: $("chk-pack-browser").checked,
        pack_desktop: $("chk-pack-desktop").checked,
      });
    }
    $("chk-pack-browser").addEventListener("change", onPackToggle);
    $("chk-pack-desktop").addEventListener("change", onPackToggle);

    // Tasks, Recovery & Diff Modal
    $("refresh-tasks-btn").addEventListener("click", function () {
      if (activeLogJobId) {
        loadTaskLog(activeLogJobId);
      } else {
        apiFetch("/api/studio/tasks").then(function (d) {
          if (d.ok) renderTasks(d.jobs || []);
        });
      }
    });

    $("kill-all-tasks-btn").addEventListener("click", function () {
      apiFetch("/api/studio/tasks", { method: "POST", body: { action: "kill_all" } }).then(function (d) {
        if (!d.ok) return showToast(d.error || "终止任务失败", true);
        renderAll(d);
        showToast(d.message || "已终止全部在途任务", false);
      });
    });

    $("close-log-btn").addEventListener("click", function () {
      activeLogJobId = "";
      $("task-log-panel").style.display = "none";
    });

    function refreshRecoveryAndAudit() {
      apiFetch("/api/studio/recovery").then(function (d) {
        if (d.ok) renderRecovery(d.snapshots || [], d.trash_items || [], d.audit_events || []);
      });
    }
    $("refresh-recovery-btn").addEventListener("click", refreshRecoveryAndAudit);
    if ($("refresh-audit-btn")) {
      $("refresh-audit-btn").addEventListener("click", refreshRecoveryAndAudit);
    }

    $("close-diff-modal-btn").addEventListener("click", closeDiffModal);
    $("diff-preview-modal").addEventListener("click", function (ev) {
      if (ev.target === $("diff-preview-modal")) {
        closeDiffModal();
      }
    });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape") {
        var modal = $("diff-preview-modal");
        if (modal && modal.style.display !== "none") {
          ev.preventDefault();
          closeDiffModal();
        }
        var idModal = $("identity-png-modal");
        if (idModal && idModal.style.display !== "none") {
          ev.preventDefault();
          closeIdentityModal();
        }
      }
    });
    $("modal-undo-confirm-btn").addEventListener("click", function () {
      if (!activeDiffTargetPath) return;
      var targetP = activeDiffTargetPath;
      apiFetch("/api/studio/recovery", { method: "POST", body: { action: "undo", path: targetP } }).then(function (d) {
        if (!d.ok) return showToast(d.error || "撤回修改失败", true);
        closeDiffModal();
        renderAll(d);
        showToast(d.message || "已撤回修改", false);
      });
    });

    // Tab 5: Visual Skills Center events
    $("skill-local-search-btn").addEventListener("click", refreshLocalSkillsList);
    $("skill-local-scope-select").addEventListener("change", refreshLocalSkillsList);
    $("skill-local-search-input").addEventListener("keydown", function (ev) {
      if (ev.key === "Enter") {
        ev.preventDefault();
        refreshLocalSkillsList();
      }
    });
    $("skill-refresh-all-btn").addEventListener("click", function () {
      refreshLocalSkillsList();
      loadSkillTrashList();
    });

    $("skill-market-search-btn").addEventListener("click", function () {
      var q = $("skill-market-query-input").value.trim();
      if (!q) return showToast("请输入要搜索的在线技能关键词", true);
      var srcs = [];
      document.querySelectorAll(".market-src-chk:checked").forEach(function (c) {
        srcs.push(c.value);
      });
      var mBtn = $("skill-market-search-btn");
      mBtn.disabled = true;
      mBtn.textContent = "正在检索…";
      var url =
        "/api/studio/skills/market?q=" +
        encodeURIComponent(q) +
        (srcs.length ? "&sources=" + encodeURIComponent(srcs.join(",")) : "");
      apiFetch(url).then(function (d) {
        mBtn.disabled = false;
        mBtn.textContent = "搜索在线市场";
        if (!d.ok) return showToast(d.error || "在线市场搜索失败", true);
        var ul = $("skill-market-results");
        ul.innerHTML = "";
        var cands = d.candidates || d.results || [];
        if (!cands.length) {
          var emp = document.createElement("li");
          emp.className = "empty-hint";
          emp.textContent = "未搜索到匹配的公开技能。";
          ul.appendChild(emp);
          return;
        }
        cands.forEach(function (c) {
          var li = document.createElement("li");
          li.className = "item-row";
          var left = document.createElement("div");
          left.className = "session-item-info";
          var nm = document.createElement("strong");
          nm.textContent = (c.name || c.id) + " [" + (c.source || "market") + "]";
          var meta = document.createElement("div");
          meta.className = "item-meta";
          meta.textContent = (c.summary || "") + " · 引用：" + (c.install_ref || c.source_url || c.id);
          left.appendChild(nm);
          left.appendChild(meta);

          var btn = document.createElement("button");
          btn.type = "button";
          btn.className = "btn btn-tonal btn-sm";
          btn.textContent = "AST 体检并预览";
          btn.addEventListener("click", function () {
            runSkillVetPreview(c.install_ref || c.source_ref || c.source_url || c.id, $("skill-install-scope-select").value);
          });
          li.appendChild(left);
          li.appendChild(btn);
          ul.appendChild(li);
        });
      });
    });

    $("skill-vet-btn").addEventListener("click", function () {
      runSkillVetPreview($("skill-vet-source-input").value.trim(), $("skill-install-scope-select").value);
    });

    $("skill-commit-install-btn").addEventListener("click", function () {
      var errBanner = $("skill-install-error-banner");
      if (errBanner) {
        errBanner.style.display = "none";
        errBanner.textContent = "";
      }
      var body = {
        preview_token: currentPreviewToken,
        source: $("skill-vet-source-input").value.trim(),
        scope: $("skill-install-scope-select").value,
        confirm_warn: $("skill-confirm-warn-chk").checked,
        force: $("skill-overwrite-chk").checked,
      };
      apiFetch("/api/studio/skills/install", { method: "POST", body: body }).then(function (d) {
        if (!d.ok || !d.installed) {
          var errMsg = d.error || d.message || "安装未完成（请核对风险确认项或同名冲突）";
          if (errBanner) {
            errBanner.textContent = errMsg;
            errBanner.style.display = "block";
          }
          showToast(errMsg, true);
          return;
        }
        resetSkillInstallControls();
        $("skill-vet-report-box").style.display = "none";
        $("skill-vet-source-input").value = "";
        showToast("已通过安全门禁并成功安装技能：" + (d.skill_name || ""), false);
        refreshLocalSkillsList();
        switchSkillSubtab("local");
        if (d.skill_name) {
          loadSkillDetail(d.skill_name, "SKILL.md", true);
        }
      });
    });

    $("skill-create-template-btn").addEventListener("click", function () {
      var nm = $("skill-create-name-input").value.trim() || "my-custom-skill";
      $("skill-create-content-input").value =
        "---\nname: " +
        nm +
        "\ndescription: 说明该技能的触发时机与核心执行准则\n---\n\n# " +
        nm +
        "\n\n1. 先读取相关上下文文件，确认边界后再执行修改。\n2. 输出简洁清晰的验证结果。\n";
    });

    $("skill-create-form").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var errBanner = $("skill-create-error-banner");
      errBanner.style.display = "none";
      errBanner.textContent = "";

      var nm = $("skill-create-name-input").value.trim();
      var content = $("skill-create-content-input").value;
      var sc = $("skill-create-scope-select").value;
      if (!nm || !content.trim()) {
        errBanner.textContent = "请填写技能名称与 SKILL.md 内容。";
        errBanner.style.display = "block";
        return;
      }

      apiFetch("/api/studio/skills/create", {
        method: "POST",
        body: {
          skill: nm,
          content: content,
          scope: sc,
          confirm_warn: $("skill-create-warn-chk").checked,
          force: $("skill-create-force-chk").checked,
        },
      }).then(function (d) {
        if (!d.ok || !d.created) {
          var msg = d.error || d.message || "创建技能未通过安全校验";
          errBanner.textContent = msg;
          errBanner.style.display = "block";
          showToast(msg, true);
          return;
        }
        $("skill-create-name-input").value = "";
        $("skill-create-content-input").value = "";
        $("skill-create-warn-chk").checked = false;
        $("skill-create-force-chk").checked = false;
        errBanner.style.display = "none";
        showToast("已新建并校验保存技能：" + (d.skill_name || nm), false);
        refreshLocalSkillsList();
        switchSkillSubtab("local");
        loadSkillDetail(d.skill_name || nm, "SKILL.md", true);
      });
    });

    $("skill-trash-refresh-btn").addEventListener("click", loadSkillTrashList);

    // ==================== WebAI2PC Click · View · Use Enhancements ====================
    if ($("theme-toggle-btn")) {
      $("theme-toggle-btn").addEventListener("click", function () {
        var cur = document.documentElement.getAttribute("data-theme") || "light";
        applyTheme(cur === "dark" ? "light" : "dark");
      });
    }

    if ($("quick-bar-copy-url-btn")) {
      $("quick-bar-copy-url-btn").addEventListener("click", function () {
        var effTop = resolveEffectiveTopView(state.connection || {});
        var targetUrl = effTop.mcp_url || "";
        if (!isSafeHttpsUrl(targetUrl)) {
          showToast("加密连接通道正在建立，请稍候复制。", true);
          return;
        }
        copyText(targetUrl, $("quick-bar-copy-url-btn"));
        showToast("已复制 HTTPS 连接地址（仅限填入本人账号，请勿外发给他人或群聊）", false);
      });
    }

    // Direct Click-to-Copy on URL Boxes & Pairing Code Pills (aligned with multi-gateway switcher)
    [
      { boxId: "mcp-url-box", kind: "mcp" },
      { boxId: "chatgpt-full-url-box", kind: "mcp" },
      { boxId: "ro-url-box", kind: "readonly" },
    ].forEach(function (item) {
      var el = $(item.boxId);
      if (!el) return;
      el.addEventListener("click", function () {
        var effTop = resolveEffectiveTopView(state.connection || {});
        var u = item.kind === "readonly" ? effTop.readonly_mcp_url || "" : effTop.mcp_url || "";
        if (!isSafeHttpsUrl(u)) return;
        copyText(u, null);
        showToast("已复制连接地址（仅限填入本人账号，请勿外发给他人或群聊）：" + u, false);
      });
    });

    if ($("dynamic-pair-code-box")) {
      $("dynamic-pair-code-box").addEventListener("click", function () {
        var v = $("dynamic-pair-code-box").textContent.trim();
        if (!v || v === "------") return;
        copyText(v, $("copy-dynamic-code-btn"));
        showToast("已复制 6 位动态配对码：" + v, false);
      });
    }
    if ($("pair-code-box")) {
      $("pair-code-box").addEventListener("click", function () {
        var v = $("pair-code-box").textContent.trim();
        if (!v || v === "----") return;
        copyText(v, $("copy-pair-code-btn"));
        showToast("已复制 4 位核对码：" + v, false);
      });
    }

    if ($("gemini-https-guide-details")) {
      var gSum = $("gemini-https-guide-details").querySelector("summary");
      if (gSum) {
        gSum.addEventListener("click", function () {
          userToggledGeminiGuide = true;
        });
      }
    }

    // Whole-Card Click & Keyboard Support on 4 Safety Mode Cards
    document.querySelectorAll("#safety-mode-cards .safety-card").forEach(function (card) {
      card.addEventListener("click", function (ev) {
        if (ev.target && ev.target.closest && ev.target.closest(".safety-select-btn")) return;
        var btn = card.querySelector(".safety-select-btn");
        if (btn && !btn.disabled) btn.click();
      });
      card.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter" || ev.key === " ") {
          if (ev.target && ev.target.classList && ev.target.classList.contains("safety-select-btn")) return;
          var btn = card.querySelector(".safety-select-btn");
          if (btn && !btn.disabled) {
            ev.preventDefault();
            btn.click();
          }
        }
      });
    });

    // Keyboard ArrowLeft / ArrowRight / Home / End on Tablists
    [
      { container: ".tabs-nav", item: ".tab-btn" },
      { container: "#host-scene-switcher", item: ".host-seg-btn" },
      { container: ".card3-subtabs", item: ".card3-subtab-btn" },
      { container: ".skills-subtabs", item: ".skills-subtab-btn" },
    ].forEach(function (spec) {
      var nav = document.querySelector(spec.container);
      if (!nav) return;
      nav.addEventListener("keydown", function (ev) {
        if (["ArrowLeft", "ArrowRight", "Home", "End"].indexOf(ev.key) < 0) return;
        var items = Array.prototype.slice.call(nav.querySelectorAll(spec.item));
        var idx = items.indexOf(document.activeElement);
        if (idx < 0) return;
        ev.preventDefault();
        var nextIdx = idx;
        if (ev.key === "ArrowRight") nextIdx = (idx + 1) % items.length;
        else if (ev.key === "ArrowLeft") nextIdx = (idx - 1 + items.length) % items.length;
        else if (ev.key === "Home") nextIdx = 0;
        else if (ev.key === "End") nextIdx = items.length - 1;
        items[nextIdx].focus();
        items[nextIdx].click();
      });
    });

    // Enter Key Submit & Unsaved Dirty Highlights on Inputs
    [
      { inp: "manual-ws-input", btn: "add-manual-ws-btn" },
      { inp: "tree-mkdir-input", btn: "tree-mkdir-btn" },
      { inp: "python-path-input", btn: "save-python-btn" },
      { inp: "tool-prefix-input", btn: "save-tool-prefix-btn" },
      { inp: "cf-api-token-input", btn: "deploy-cf-workers-btn" },
      { inp: "cf-custom-domain-input", btn: "deploy-cf-workers-btn" },
      { inp: "custom-url-input", btn: "save-channel-btn" },
      { inp: "skill-market-query-input", btn: "skill-market-search-btn" },
      { inp: "skill-vet-source-input", btn: "skill-vet-btn" },
    ].forEach(function (pair) {
      var inpEl = $(pair.inp);
      var btnEl = $(pair.btn);
      if (!inpEl || !btnEl) return;
      inpEl.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter") {
          ev.preventDefault();
          if (!btnEl.disabled) btnEl.click();
        }
      });
    });

    if ($("python-path-input") && $("save-python-btn")) {
      $("python-path-input").addEventListener("input", function () {
        var saved = ((state.workspaces && state.workspaces.python_path) || "").trim();
        var cur = $("python-path-input").value.trim();
        $("save-python-btn").classList.toggle("is-dirty-unsaved", cur !== saved);
      });
    }
    if ($("tool-prefix-input") && $("save-tool-prefix-btn")) {
      $("tool-prefix-input").addEventListener("input", function () {
        var saved = ((state.tools_center && state.tools_center.tool_prefix) || state.tool_prefix || "pc").trim();
        var cur = $("tool-prefix-input").value.trim();
        $("save-tool-prefix-btn").classList.toggle("is-dirty-unsaved", Boolean(cur && cur !== saved));
      });
    }

    // Core Tools Category Filter Pills & Collapse Toggle
    document.querySelectorAll("#core-tools-filter-bar [data-tool-filter]").forEach(function (pill) {
      pill.addEventListener("click", function () {
        activeCoreToolsFilter = pill.getAttribute("data-tool-filter") || "all";
        coreToolsCollapsed = false;
        document.querySelectorAll("#core-tools-filter-bar [data-tool-filter]").forEach(function (p) {
          p.classList.toggle("active", p === pill);
        });
        applyCoreToolsFilter();
      });
    });
    if ($("toggle-core-tools-btn")) {
      $("toggle-core-tools-btn").addEventListener("click", function () {
        coreToolsCollapsed = !coreToolsCollapsed;
        applyCoreToolsFilter();
      });
    }

    // Task Log Copy & Audit Event Filter
    if ($("copy-task-log-btn")) {
      $("copy-task-log-btn").addEventListener("click", function () {
        var logTxt = ($("task-log-box") && $("task-log-box").textContent) || "";
        if (!logTxt) return;
        copyText(logTxt, $("copy-task-log-btn"));
        showToast("已复制任务日志输出", false);
      });
    }
    document.querySelectorAll("#audit-filter-bar [data-audit-filter]").forEach(function (pill) {
      pill.addEventListener("click", function () {
        activeAuditFilter = pill.getAttribute("data-audit-filter") || "all";
        document.querySelectorAll("#audit-filter-bar [data-audit-filter]").forEach(function (p) {
          p.classList.toggle("active", p === pill);
        });
        applyAuditFilter();
      });
    });
    if ($("audit-search-input")) {
      $("audit-search-input").addEventListener("input", function () {
        auditSearchQuery = $("audit-search-input").value || "";
        applyAuditFilter();
      });
    }

    // 4-Second Real-Time Poll (strictly preserves userConnExpandOverrides & userPickedCard3Subtab)
    var pendingPollRetryTimer = null;
    function scheduleSettledPoll() {
      if (pendingPollRetryTimer) return;
      pendingPollRetryTimer = setTimeout(function () {
        pendingPollRetryTimer = null;
        pollOnce();
      }, 220);
    }
    function pollOnce() {
      if (state.locked) return;
      if (inFlightMutations > 0) {
        scheduleSettledPoll();
        return;
      }
      if (
        !document.hidden &&
        activeLogJobId &&
        $("workbench-view") &&
        $("workbench-view").classList.contains("active") &&
        $("activity-pane-tasks") &&
        $("activity-pane-tasks").classList.contains("active")
      ) {
        loadTaskLog(activeLogJobId);
      }
      var pollStartedAt = Date.now();
      apiFetch("/api/studio/poll")
        .then(function (d) {
          if (inFlightMutations > 0 || pollStartedAt < lastMutationAt) {
            scheduleSettledPoll();
            return;
          }
          if (!d || !d.ok) {
            if (d && d._httpStatus === 403 && d.locked) {
              apiFetch("/api/studio/state").then(renderAll);
              return;
            }
            throw new Error("poll_failed");
          }
          setStatusIndicator(d.status_kind || "online", d.status_text || "在线运行");
          if (d.safety_mode && d.safety_mode !== state.safety_mode) {
            state.safety_mode = d.safety_mode;
            renderSafetyCards(d.safety_mode);
            var wsFpBanner = $("workspace-fullpower-banner");
            if (wsFpBanner) {
              wsFpBanner.style.display = d.safety_mode === "full_power" ? "block" : "none";
            }
            apiFetch("/api/studio/state").then(renderAll);
          }

          var dynNow = d.dynamic_pair_code || "------";
          if ($("dynamic-pair-code-box") && $("dynamic-pair-code-box").textContent !== dynNow) {
            $("dynamic-pair-code-box").textContent = dynNow;
          }
          if ($("copy-dynamic-code-btn")) {
            $("copy-dynamic-code-btn").disabled = !dynNow || dynNow === "------";
          }

          var latestCode = d.consent_pair_code || d.pair_code || "----";
          var pBox = $("pair-code-box");
          if (pBox && pBox.textContent !== latestCode) {
            pBox.textContent = latestCode;
          }
          if ($("copy-pair-code-btn")) {
            $("copy-pair-code-btn").disabled = !latestCode || latestCode === "----";
          }

          var nextSessions = d.authorized_sessions || [];
          var sessCntNow = typeof d.authorized_sessions_count === "number" ? d.authorized_sessions_count : nextSessions.length;
          if ($("revoke-sessions-btn")) {
            $("revoke-sessions-btn").disabled = sessCntNow <= 0;
          }
          updateFirstWakeBanner(sessCntNow);

          if ($("kill-all-tasks-btn") && typeof d.running_tasks_count === "number") {
            $("kill-all-tasks-btn").disabled = d.running_tasks_count <= 0;
          }

          var nextSig = JSON.stringify({ s: nextSessions, m: d.safety_mode || state.safety_mode || "full_dev" });
          if (nextSig !== lastSessionsSignature) {
            lastSessionsSignature = nextSig;
            if ($("sessions-count")) {
              $("sessions-count").textContent = String(sessCntNow);
            }
            renderAuthorizedSessions(nextSessions);
          }

          state.tunnel_mode = d.tunnel_mode;
          state.effective_tunnel_mode = d.effective_tunnel_mode;
          state.public_https_ready = Boolean(d.public_https_ready);
          state.mcp_url = d.mcp_url;
          state.mcp_readonly_url = d.mcp_readonly_url;
          state.readonly_mcp_url = d.readonly_mcp_url;
          state.srvus_fixed_active = Boolean(d.srvus_fixed_active);
          state.instant_fallback_active = Boolean(d.instant_fallback_active);
          state.public_gateway_online = Boolean(d.public_gateway_online);
          if (d.gateways) state.gateways = d.gateways;
          if (d.selected_gateway !== undefined) state.selected_gateway = d.selected_gateway;
          if (d.display_gateway_id !== undefined) state.display_gateway_id = d.display_gateway_id;
          if (d.ready_gateway_ids !== undefined) state.ready_gateway_ids = d.ready_gateway_ids;

          state.connection = Object.assign({}, state.connection || {}, {
            gateways: d.gateways || (state.connection && state.connection.gateways),
            selected_gateway: d.selected_gateway,
            user_selected_gateway: d.user_selected_gateway,
            display_gateway_id: d.display_gateway_id,
            enabled_gateway_ids: d.enabled_gateway_ids,
            ready_gateway_ids: d.ready_gateway_ids,
            tunnel_mode: d.tunnel_mode,
            effective_tunnel_mode: d.effective_tunnel_mode,
            public_https_ready: d.public_https_ready,
            is_loopback_url: d.is_loopback_url,
            public_url: d.public_url,
            mcp_url: d.mcp_url,
            mcp_readonly_url: d.mcp_readonly_url,
            readonly_mcp_url: d.readonly_mcp_url,
            skill_url: d.skill_url,
            srvus_fixed_active: Boolean(d.srvus_fixed_active),
            instant_fallback_active: Boolean(d.instant_fallback_active),
            public_gateway_online: Boolean(d.public_gateway_online),
            reboot_notice: d.reboot_notice || "",
            tunnel_connecting: d.tunnel_connecting,
            tunnel_error: d.tunnel_error,
            pair_code: latestCode,
            consent_pair_code: latestCode,
            dynamic_pair_code: dynNow,
          });
          renderConnectionGuides(state.connection);
          updateConnectionCardsUI(d.tunnel_mode || "public_gateway", state.connection);
          updateTabTelemetryBadges(d);
          syncIpWorkingPose(d);
        })
        .catch(function () {
          setStatusIndicator("offline", "连接中断 · 本地服务未响应");
        });
    }

    pollTimer = setInterval(pollOnce, 4000);
    document.addEventListener("visibilitychange", function () {
      if (!document.hidden) pollOnce();
    });
    window.addEventListener("focus", pollOnce);
    void pollTimer;
  }

  function boot() {
    initTheme();
    var bootEl = $("studio-boot-data");
    if (bootEl && bootEl.textContent) {
      try {
        var initial = JSON.parse(bootEl.textContent);
        renderAll(initial);
      } catch (e) {}
    }
    bindEvents();
    // Honor URL hash #settings/<category> on initial load
    var h = String(window.location.hash || "");
    if (h.indexOf("#settings") === 0) {
      var parts = h.split("/");
      openSettings(parts[1] || "gateways");
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
