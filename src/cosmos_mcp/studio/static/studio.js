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
    instant: "OpenSSH 免登录直连",
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
  var lastStateRevision = null;
  var stateSyncInFlight = false;
  var authBackupRevealed = false;
  var authBackupPlain = "";
  var authRotateConfirmArmed = false;
  var endpointSecretConfirmTimers = {};

  var PAT_ANTI_LEAK_TOAST =
    "已复制专用密钥！严禁将此专用密钥发进与 AI 的聊天对话框、微信群、论坛或公开 Issue！仅限填入 ChatGPT Sites 后台专用的环境变量（Secrets）输入框或本地 CLI 配置文件；如怀疑泄露请在已授权列表点击『断开』立即作废。";

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
    var eff = m === "reverse_proxy" ? "custom" : m === "trycloudflare" ? "cloudflare" : (m === "cf_workers" || m === "cloudflare_workers") ? "workers_dev" : m;
    return {
      1: ["public_gateway", "openssh", "srv_us", "cloudflare"].indexOf(eff) >= 0,
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
    var onlineWord = $("service-online-word");
    var validKind = ["online", "editonly", "readonly", "offline"].indexOf(kind) >= 0 ? kind : "online";
    if (badge) badge.className = "status-badge " + validKind;
    if (dot) dot.className = "status-dot " + validKind;
    if (onlineWord) onlineWord.textContent = validKind === "offline" ? "离线" : "在线";
    if (txt && txt.textContent !== (text || "")) txt.textContent = text || "";
  }

  var userToggledConnDrawer = false;
  function setConnDrawerOpen(open) {
    var drawer = $("wb-conn-drawer");
    var btn = $("toggle-conn-details-btn");
    if (!drawer) return;
    drawer.classList.toggle("open", Boolean(open));
    if (btn) {
      btn.setAttribute("aria-expanded", open ? "true" : "false");
      btn.textContent = open ? "收起详情 ▴" : "详情与配对 ▾";
    }
  }

  function updateFirstWakeBanner(sessCount) {
    var banner = $("first-wake-banner");
    var cnt = Number(sessCount || 0);
    var chip = $("conn-bar-session-chip");
    var chipNum = $("conn-bar-sessions-num");
    if (chip && chipNum) {
      chipNum.textContent = String(cnt);
      chip.style.display = cnt >= 1 ? "inline-flex" : "none";
    }
    if (!userToggledConnDrawer) {
      var isChatgpt = activeHostScene === "chatgpt";
      setConnDrawerOpen(cnt <= 0 || isChatgpt);
    }
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
        actBtn1.textContent = "启用 OpenSSH 直连";
      } else if (isExplicitQuick) {
        actBtn1.disabled = false;
        actBtn1.className = "btn btn-primary";
        actBtn1.textContent = "恢复 OpenSSH 固定网址（推荐）";
      } else if (autoFallbackActive) {
        actBtn1.disabled = false;
        actBtn1.className = "btn btn-tonal";
        actBtn1.textContent = "重试连接 OpenSSH 固定网址";
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
        fbBox.textContent =
          "当前处于临时快速通道（*.trycloudflare.com，重启会变网址）；点击下方「恢复 OpenSSH 固定网址（推荐）」可切回系统 OpenSSH 固定网址（*.srv.us），或同时开启第 2 类 Cloudflare 网关。";
      } else {
        fbBox.className = "callout callout-ok";
        fbBox.textContent =
          "当前为免登录临时网址（*.trycloudflare.com，重启会变）；连上系统 OpenSSH 固定网址（*.srv.us）或部署 Cloudflare 网关后可导出加密恢复卡。";
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
    var isWorkerDeployed = Boolean(conn.workers_deployed || isSafeHttpsUrl(savedWdUrl));
    if ($("cf-saved-hint-box")) {
      $("cf-saved-hint-box").style.display = isWorkerDeployed && !wdSlot.enabled ? "block" : "none";
    }
    if ($("cf-tokenless-domain-bar")) {
      $("cf-tokenless-domain-bar").style.display = isWorkerDeployed ? "flex" : "none";
    }
    var cfCustomInp = $("cf-custom-domain-input");
    if (cfCustomInp && document.activeElement !== cfCustomInp && conn.workers_dev_custom_domain !== undefined) {
      if (conn.workers_dev_custom_domain || !cfCustomInp.getAttribute("data-user-dirty")) {
        cfCustomInp.value = conn.workers_dev_custom_domain || "";
      }
    }
    if ($("clear-cf-custom-domain-btn")) {
      $("clear-cf-custom-domain-btn").disabled = !Boolean(
        conn.workers_dev_custom_domain || (cfCustomInp && cfCustomInp.value.trim())
      );
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

    var compatChk = $("chk-web-compat-mode");
    var compatBox = $("web-compat-mode-box");
    var compatHint = $("web-compat-ro-hint");
    var webCompatSaved =
      tc.web_compat_mode !== undefined ? Boolean(tc.web_compat_mode) : !Boolean(tc.confirm_popups);
    if (compatChk) {
      compatChk.checked = isReadonly ? true : webCompatSaved;
      compatChk.disabled = isReadonly;
    }
    if (compatBox) compatBox.classList.toggle("disabled-switch", isReadonly);
    if (compatHint) {
      compatHint.style.display = isReadonly ? "inline-flex" : "none";
      compatHint.textContent = "只读模式下自动开启";
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

    var scanVal =
      tc.scan_host_global_skills !== undefined
        ? Boolean(tc.scan_host_global_skills)
        : Boolean(state.scan_host_global_skills);
    if ($("chk-scan-host-skills")) {
      $("chk-scan-host-skills").checked = scanVal;
    }
    if ($("chk-skills-scan-host")) {
      $("chk-skills-scan-host").checked = scanVal;
    }
    var redactVal =
      tc.redact_project_secrets !== undefined
        ? Boolean(tc.redact_project_secrets)
        : Boolean(state.redact_project_secrets);
    if ($("chk-redact-project-secrets")) {
      $("chk-redact-project-secrets").checked = redactVal;
    }
    var autoRulesVal =
      tc.auto_inject_project_rules !== undefined
        ? Boolean(tc.auto_inject_project_rules)
        : state.auto_inject_project_rules !== undefined
        ? Boolean(state.auto_inject_project_rules)
        : true;
    if ($("chk-auto-inject-rules")) {
      $("chk-auto-inject-rules").checked = autoRulesVal;
    }

    var lbChk = $("chk-allow-loopback-dev");
    var lbBox = $("allow-loopback-dev-box");
    var lbHint = $("allow-loopback-dev-ro-hint");
    var lbSaved =
      tc.allow_loopback_dev !== undefined
        ? Boolean(tc.allow_loopback_dev)
        : state.allow_loopback_dev !== undefined
        ? Boolean(state.allow_loopback_dev)
        : true;
    if (lbChk) {
      lbChk.checked = isReadonly ? false : lbSaved;
      lbChk.disabled = isReadonly;
    }
    if (lbBox) lbBox.classList.toggle("disabled-switch", isReadonly);
    if (lbHint) {
      lbHint.style.display = isReadonly ? "inline-flex" : "none";
      lbHint.textContent = "只读模式下自动关闭";
    }

    var envProtChk = $("chk-protect-dotenv");
    var envProtBox = $("protect-dotenv-box");
    var envProtHint = $("protect-dotenv-ro-hint");
    var envProtSaved =
      tc.protect_dotenv_files !== undefined
        ? Boolean(tc.protect_dotenv_files)
        : Boolean(state.protect_dotenv_files);
    if (envProtChk) {
      envProtChk.checked = isReadonly ? true : envProtSaved;
      envProtChk.disabled = isReadonly;
    }
    if (envProtBox) envProtBox.classList.toggle("disabled-switch", isReadonly);
    if (envProtHint) {
      envProtHint.style.display = isReadonly ? "inline-flex" : "none";
      envProtHint.textContent = "只读模式下自动开启";
    }

    var credProtChk = $("chk-protect-credentials");
    if (credProtChk) {
      var credProtSaved =
        tc.protect_host_credentials !== undefined
          ? Boolean(tc.protect_host_credentials)
          : state.protect_host_credentials !== undefined
          ? Boolean(state.protect_host_credentials)
          : true;
      credProtChk.checked = credProtSaved;
    }

    var blkDestChk = $("chk-block-destructive");
    var blkDestBox = $("block-destructive-box");
    var blkDestHint = $("block-destructive-ro-hint");
    var blkDestSaved =
      tc.block_destructive_commands !== undefined
        ? Boolean(tc.block_destructive_commands)
        : state.block_destructive_commands !== undefined
        ? Boolean(state.block_destructive_commands)
        : true;
    if (blkDestChk) {
      blkDestChk.checked = execLocked ? true : blkDestSaved;
      blkDestChk.disabled = execLocked;
    }
    if (blkDestBox) blkDestBox.classList.toggle("disabled-switch", execLocked);
    if (blkDestHint) {
      blkDestHint.style.display = execLocked ? "inline-flex" : "none";
      blkDestHint.textContent = isReadonly ? "只读模式下自动生效" : "禁跑命令模式下自动生效";
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

  function isPatSession(sess) {
    if (!sess || typeof sess !== "object") return false;
    var tk = String(sess.token_kind || "").trim().toLowerCase();
    if (tk === "pat" || tk === "personal_access_token") return true;
    var cid = String(sess.client_id || "").trim();
    if (cid.indexOf("pat_") === 0) return true;
    var plat = String(sess.platform || "");
    return plat.indexOf("专用密钥") >= 0;
  }

  function extractPatSessions(doc) {
    var d = doc || state || {};
    var conn = d.connection && typeof d.connection === "object" ? d.connection : {};
    var sessArr = Array.isArray(d.authorized_sessions)
      ? d.authorized_sessions
      : Array.isArray(conn.authorized_sessions)
      ? conn.authorized_sessions
      : [];
    var matched = sessArr.filter(isPatSession);
    var extraPats = Array.isArray(d.pats)
      ? d.pats
      : Array.isArray(d.personal_access_tokens)
      ? d.personal_access_tokens
      : [];
    if (extraPats.length) {
      var seen = {};
      matched.forEach(function (item) {
        if (item && item.client_id) seen[String(item.client_id)] = true;
      });
      extraPats.forEach(function (p) {
        if (!p || typeof p !== "object") return;
        var pid = String(p.client_id || p.id || "");
        if (pid && seen[pid]) return;
        if (pid) seen[pid] = true;
        matched.push(p);
      });
    }
    return matched;
  }

  function computePatCount(doc, sessArr) {
    var d = doc || state || {};
    var conn = d.connection && typeof d.connection === "object" ? d.connection : {};
    if (typeof d.pat_count === "number") return d.pat_count;
    if (typeof conn.pat_count === "number") return conn.pat_count;
    var baseList = Array.isArray(sessArr)
      ? sessArr
      : Array.isArray(d.authorized_sessions)
      ? d.authorized_sessions
      : Array.isArray(conn.authorized_sessions)
      ? conn.authorized_sessions
      : [];
    return baseList.filter(isPatSession).length;
  }

  function resolvePairCodes(doc) {
    var d = doc || state || {};
    var conn = d.connection && typeof d.connection === "object" ? d.connection : {};
    var rawDyn = String(d.dynamic_pair_code || conn.dynamic_pair_code || "").trim();
    if (rawDyn === "------" || rawDyn === "-") rawDyn = "";
    var rawVer = String(
      d.consent_pair_code || conn.consent_pair_code || d.pair_code || conn.pair_code || ""
    ).trim();
    if (rawVer === "----" || rawVer === "-") rawVer = "";
    return {
      dynamicCode: rawDyn,
      consentCode: rawVer,
    };
  }

  function syncPairCodeDom(dynCode, consentCode) {
    var cleanDyn = dynCode && dynCode !== "------" && dynCode !== "-" ? String(dynCode).trim() : "";
    var cleanVer = consentCode && consentCode !== "----" && consentCode !== "-" ? String(consentCode).trim() : "";
    var dispDyn = cleanDyn || "------";
    var dispVer = cleanVer || "----";

    if ($("dynamic-pair-code-box") && $("dynamic-pair-code-box").textContent !== dispDyn) {
      $("dynamic-pair-code-box").textContent = dispDyn;
    }
    if ($("copy-dynamic-code-btn")) {
      $("copy-dynamic-code-btn").disabled = !cleanDyn;
    }

    if ($("pair-code-box") && $("pair-code-box").textContent !== dispVer) {
      $("pair-code-box").textContent = dispVer;
    }
    if ($("copy-pair-code-btn")) {
      $("copy-pair-code-btn").disabled = !cleanVer;
    }

    if ($("auth-pair-code-val") && $("auth-pair-code-val").textContent !== dispDyn) {
      $("auth-pair-code-val").textContent = dispDyn;
    }
    if ($("auth-copy-pair-btn")) {
      $("auth-copy-pair-btn").disabled = !cleanDyn;
    }

    if ($("auth-verify-code-val") && $("auth-verify-code-val").textContent !== dispVer) {
      $("auth-verify-code-val").textContent = dispVer;
    }
    if ($("auth-copy-verify-btn")) {
      $("auth-copy-verify-btn").disabled = !cleanVer;
    }
  }

  function syncAuthBackupDisplay() {
    var bkEl = $("auth-backup-token-val");
    if (bkEl) {
      bkEl.textContent =
        authBackupRevealed && authBackupPlain ? authBackupPlain : "••••••••••••••••••••";
    }
    var togBtn = $("auth-toggle-backup-btn");
    if (togBtn) {
      togBtn.textContent = authBackupRevealed && authBackupPlain ? "隐藏口令" : "显示 / 隐藏";
    }
  }

  function setAuthRotateConfirmOpen(open) {
    authRotateConfirmArmed = Boolean(open);
    var bar = $("auth-rotate-backup-confirm-bar");
    if (bar) {
      bar.style.display = authRotateConfirmArmed ? "flex" : "none";
    }
    var rotBtn = $("auth-rotate-backup-btn");
    if (rotBtn) {
      rotBtn.textContent = authRotateConfirmArmed ? "再点确认重置" : "重置备用口令";
      rotBtn.classList.toggle("btn-danger", authRotateConfirmArmed);
    }
  }

  function clearPatOnceResult(onlyIfClientId, targetPrefix) {
    var targets = targetPrefix
      ? [targetPrefix]
      : ["pat-once", "auth-pat-once"];
    targets.forEach(function (pfx) {
      var box = $(pfx + "-result-box");
      if (!box) return;
      if (onlyIfClientId && box.getAttribute("data-client-id") !== onlyIfClientId) {
        return;
      }
      box.style.display = "none";
      box.removeAttribute("data-client-id");
      if ($(pfx + "-token-value")) $(pfx + "-token-value").textContent = "";
      if ($(pfx + "-meta-text")) $(pfx + "-meta-text").textContent = "";
    });
  }

  function requestMintPersonalAccessToken(params) {
    return apiFetch("/api/studio/tokens/mint", {
      method: "POST",
      body: params,
    }).then(function (d) {
      if (d && d._httpStatus === 404) {
        return apiFetch("/api/studio/pats", {
          method: "POST",
          body: Object.assign({}, params, {
            scope: params.readonly ? "readonly" : "readwrite",
          }),
        });
      }
      return d;
    });
  }

  function submitPatMintFlow(uiCfg) {
    var mBtn = $(uiCfg.btnId);
    var scopeSel = $(uiCfg.scopeSelectId);
    var ttlSel = $(uiCfg.ttlSelectId);
    var lblInp = $(uiCfg.labelInputId);
    var wantReadonly = !scopeSel || scopeSel.value !== "readwrite";
    var ttlDays = ttlSel ? parseInt(ttlSel.value, 10) || 30 : 30;
    var labelVal = lblInp ? lblInp.value.trim() : "";

    if (mBtn) mBtn.disabled = true;
    return requestMintPersonalAccessToken({
      readonly: wantReadonly,
      ttl_days: ttlDays,
      label: labelVal,
    })
      .then(function (d) {
        if (mBtn) mBtn.disabled = state.is_loopback === false;
        var minted = (d && d.minted_token) || (d && d.token ? d : null);
        if (!d || !d.ok || !minted || !minted.token) {
          showToast((d && (d.message || d.error)) || "生成专用密钥失败", true);
          return;
        }
        var mintedCopy = Object.assign({}, minted);
        if (d.minted_token) {
          delete d.minted_token;
        }
        if (d.gateways || d.workspaces || d.authorized_sessions) {
          renderAll(d);
        } else {
          apiFetch("/api/studio/state").then(renderAll);
        }
        if (lblInp) lblInp.value = "";
        var pfx = uiCfg.oncePrefix;
        var resBox = $(pfx + "-result-box");
        var tokValEl = $(pfx + "-token-value");
        var metaEl = $(pfx + "-meta-text");
        if (tokValEl) tokValEl.textContent = String(mintedCopy.token);
        if (metaEl) {
          var isRo = mintedCopy.readonly !== undefined ? Boolean(mintedCopy.readonly) : wantReadonly;
          var scopeDesc = isRo ? "仅只读权限（限 /mcp/readonly）" : "工作区读写权限（允许 /mcp）";
          metaEl.textContent =
            "已签发：" +
            (mintedCopy.platform || "专用密钥 (Sites / CLI)") +
            " · " +
            (mintedCopy.client_name || labelVal || "专用密钥") +
            " ｜ " +
            scopeDesc +
            " ｜ 到期：" +
            (mintedCopy.expires_at_text || "-");
        }
        if (resBox) {
          resBox.setAttribute("data-client-id", String(mintedCopy.client_id || ""));
          resBox.style.display = "block";
        }
        showToast(
          "已生成专用密钥（仅显示一次）！严禁发进聊天对话框、微信群或公开 Issue，仅限填入 ChatGPT Sites 后台 Secrets 或本地 CLI 配置。",
          true
        );
      })
      .catch(function () {
        if (mBtn) mBtn.disabled = state.is_loopback === false;
        showToast("生成专用密钥失败，请确认本地服务在线", true);
      });
  }

  function revokeAuthorizedClient(clientId, successMsg) {
    var cid = String(clientId || "").trim();
    if (!cid) return Promise.resolve({ ok: false });
    return apiFetch("/api/studio/connection", {
      method: "POST",
      body: { action: "revoke_client", client_id: cid },
    })
      .then(function (d) {
        if (d && d._httpStatus === 404) {
          return apiFetch("/api/studio/revoke", {
            method: "POST",
            body: { client_id: cid },
          });
        }
        return d;
      })
      .then(function (d) {
        if (!d || !d.ok) {
          showToast((d && (d.error || d.message)) || "吊销客户端授权失败", true);
          return d;
        }
        clearPatOnceResult(cid);
        if (d.gateways || d.workspaces || d.authorized_sessions) {
          renderAll(d);
        } else {
          apiFetch("/api/studio/state").then(renderAll);
        }
        showToast(d.message || successMsg || "已吊销该客户端授权", false);
        return d;
      })
      .catch(function () {
        showToast("吊销请求失败，请确认本机服务在线", true);
        return { ok: false };
      });
  }

  function revealConnectionPassword() {
    return apiFetch("/api/studio/connection", {
      method: "POST",
      body: { action: "reveal_password" },
    }).then(function (d) {
      if (!d || !d.ok) {
        return {
          ok: false,
          password: "",
          error: (d && (d.error || d.message)) || "当前仅允许在本机回环浏览器读取备用口令",
        };
      }
      var pw = String(
        d.connection_password || (d.connection && d.connection.connection_password) || ""
      );
      if (!pw) {
        return {
          ok: false,
          password: "",
          error: "本机当前未保存可展示的明文备用口令（可点击旁侧重置重新生成）",
        };
      }
      return { ok: true, password: pw, error: "" };
    });
  }

  function renderInstantSubchannels(connObj, docObj) {
    var doc = docObj || state || {};
    var conn = connObj || (doc && doc.connection) || {};
    var gws = (conn && conn.gateways) || doc.gateways || state.gateways || {};
    var instant = gws.instant || {};
    var subs = instant.subchannels && typeof instant.subchannels === "object" ? instant.subchannels : {};

    var srv = subs.srv_us || {};
    var srvSt = String(
      srv.status ||
        (instant.srvus_fixed_active ? "ready" : instant.enabled ? "connecting" : "disabled")
    );
    var srvPill = $("sub-pill-srv_us");
    if (srvPill) {
      srvPill.className = "gw-status-pill is-" + srvSt;
      srvPill.textContent =
        srvSt === "ready" ? "已连通" : srvSt === "error" ? "异常" : srvSt === "connecting" ? "连接中" : "未开启";
    }
    var srvUrl = String(srv.mcp_url || "").trim();
    var srvUrlEl = $("sub-url-srv_us");
    var srvCopyBtn = $("sub-copy-srv_us");
    if (srvUrlEl) {
      srvUrlEl.textContent =
        srvUrl ||
        (srvSt === "error"
          ? "系统 OpenSSH 通道暂未连通（可点击右侧重连或展开下方排查日志）"
          : "等待系统 OpenSSH（srv.us 中继）分配固定地址…");
      srvUrlEl.className = srvUrl ? "gw-card-url-box is-ready" : "gw-card-url-box";
    }
    if (srvCopyBtn) {
      srvCopyBtn.disabled = !srvUrl;
      srvCopyBtn.setAttribute("data-url", srvUrl);
    }
    var srvErr = $("sub-err-srv_us");
    if (srvErr) {
      var srvErrTxt = String(srv.last_error || "").trim();
      srvErr.style.display = srvErrTxt ? "block" : "none";
      srvErr.textContent = srvErrTxt;
    }

    var cf = subs.trycloudflare || {};
    var cfEnabled = Boolean(cf.enabled || instant.trycloudflare_backup);
    var cfSt = String(cf.status || (cfEnabled ? "connecting" : "disabled"));
    var cfSw = $("instant-sub-trycf-switch");
    if (cfSw) {
      cfSw.checked = Boolean(instant.trycloudflare_backup || cf.enabled);
      cfSw.setAttribute("aria-checked", cfSw.checked ? "true" : "false");
    }
    var cfPill = $("sub-pill-trycloudflare");
    if (cfPill) {
      cfPill.className = "gw-status-pill is-" + cfSt;
      cfPill.textContent =
        cfSt === "ready" ? "已连通" : cfSt === "error" ? "异常" : cfSt === "connecting" ? "连接中" : "未开启";
    }
    var cfUrl = String(cf.mcp_url || "").trim();
    var cfUrlEl = $("sub-url-trycloudflare");
    var cfCopyBtn = $("sub-copy-trycloudflare");
    if (cfUrlEl) {
      cfUrlEl.textContent =
        cfUrl ||
        (cfEnabled
          ? "正在建立 trycloudflare 临时通道…"
          : "未开启（需要时打开上方开关即可与 OpenSSH 固定通道同时显示两个 URL）");
      cfUrlEl.className = cfUrl ? "gw-card-url-box is-ready" : "gw-card-url-box";
    }
    if (cfCopyBtn) {
      cfCopyBtn.disabled = !cfUrl;
      cfCopyBtn.setAttribute("data-url", cfUrl);
    }
    var cfErr = $("sub-err-trycloudflare");
    if (cfErr) {
      var cfErrTxt = String(cf.last_error || "").trim();
      cfErr.style.display = cfErrTxt ? "block" : "none";
      cfErr.textContent = cfErrTxt;
    }
  }

  function renderEndpointSecretControls(connObj, docObj) {
    var doc = docObj || state || {};
    var conn = connObj || (doc && doc.connection) || {};
    var epOn = Boolean(
      doc.endpoint_secret_enabled !== undefined
        ? doc.endpoint_secret_enabled
        : conn.endpoint_secret_enabled
    );
    var epMask = String(
      doc.endpoint_secret_masked ||
        conn.endpoint_secret_masked ||
        (state.connection && state.connection.endpoint_secret_masked) ||
        ""
    );
    var epLabel = epOn ? "已开启（/u/" + (epMask || "••••") + "/mcp）" : "未开启（默认 /mcp）";
    ["gw-endpoint-secret-status-pill", "auth-endpoint-secret-pill"].forEach(function (id) {
      var el = $(id);
      if (el) {
        el.textContent = epLabel;
        el.className = epOn ? "tag tag-ok" : "tag tag-muted";
      }
    });
    ["gw-disable-endpoint-secret-btn", "auth-disable-endpoint-secret-btn"].forEach(function (id) {
      var el = $(id);
      if (el) el.style.display = epOn ? "inline-flex" : "none";
    });
    var pwWiped = Boolean(conn.plaintext_password_wiped);
    var wipeBtn = $("auth-wipe-plaintext-pw-btn");
    if (wipeBtn) {
      wipeBtn.textContent = pwWiped ? "已擦除本地 txt 明文口令" : "擦除本地 txt 明文口令文件";
      wipeBtn.disabled = pwWiped;
    }
    var ocPill = $("auth-oneclick-route-pill");
    if (ocPill) {
      ocPill.textContent = ocOn ? "已开启（注意防外泄）" : "已默认关闭（返回 404）";
      ocPill.className = ocOn ? "tag tag-warn" : "tag tag-muted";
    }
  }

  function renderAuthPatList(patItems, isStrictLoopback) {
    var ul = $("auth-pat-list");
    if (!ul) return;
    ul.innerHTML = "";
    var list = Array.isArray(patItems) ? patItems : [];
    if (!list.length) {
      var emp = document.createElement("li");
      emp.className = "empty-hint";
      emp.style.padding = "8px 10px";
      emp.textContent = "当前暂无已签发的专用密钥。";
      ul.appendChild(emp);
      return;
    }
    list.forEach(function (item) {
      var li = document.createElement("li");
      li.className = "item-row";

      var left = document.createElement("div");
      left.className = "session-item-info";

      var topLine = document.createElement("div");
      topLine.style.display = "flex";
      topLine.style.flexWrap = "wrap";
      topLine.style.alignItems = "center";
      topLine.style.gap = "6px";

      var nameStrong = document.createElement("strong");
      nameStrong.style.fontSize = "12.5px";
      nameStrong.textContent = String(item.client_name || item.label || item.client_id || "专用密钥");
      topLine.appendChild(nameStrong);

      var badgeInfo = resolveSessionScopeBadge(item);
      var scopeTag = document.createElement("span");
      scopeTag.className = badgeInfo.cls;
      scopeTag.textContent = badgeInfo.text;
      topLine.appendChild(scopeTag);

      var meta = document.createElement("div");
      meta.className = "item-meta";
      var cidTxt = item.client_id ? "标识：" + item.client_id + " · " : "";
      meta.textContent = cidTxt + "到期：" + (item.expires_at_text || "-");

      left.appendChild(topLine);
      left.appendChild(meta);

      var revBtn = document.createElement("button");
      revBtn.type = "button";
      revBtn.className = "btn btn-danger btn-sm auth-revoke-pat-btn";
      revBtn.setAttribute("data-client-id", item.client_id || "");
      revBtn.disabled = isStrictLoopback === false && !state.unlocked;
      revBtn.textContent = "吊销";
      revBtn.addEventListener("click", function () {
        revBtn.disabled = true;
        revokeAuthorizedClient(item.client_id, "已吊销该专用密钥").finally(function () {
          revBtn.disabled = false;
        });
      });

      li.appendChild(left);
      li.appendChild(revBtn);
      ul.appendChild(li);
    });
  }

  function renderAuthCredentialsPane(doc) {
    var d = doc || state || {};
    var isStrictLb = d.is_loopback !== false;
    var lbPill = $("auth-local-bridge-pill");
    if (lbPill) {
      lbPill.className = isStrictLb ? "tag tag-ok" : "tag tag-muted";
      lbPill.textContent = isStrictLb
        ? "已启用（仅限本机 127.0.0.1 浏览器）"
        : "当前为非回环访问（仅本机 127.0.0.1 浏览器可用）";
    }

    var codes = resolvePairCodes(d);
    syncPairCodeDom(codes.dynamicCode, codes.consentCode);
    syncAuthBackupDisplay();

    var patItems = extractPatSessions(d);
    var patCnt = computePatCount(d, (d.connection && d.connection.authorized_sessions) || d.authorized_sessions);
    if ($("auth-pat-count-val")) {
      $("auth-pat-count-val").textContent = String(patCnt);
    }
    if ($("auth-mint-pat-btn")) {
      $("auth-mint-pat-btn").disabled = !isStrictLb;
    }
    if ($("auth-pat-loopback-only-hint")) {
      $("auth-pat-loopback-only-hint").style.display = isStrictLb ? "none" : "block";
    }
    renderAuthPatList(patItems, isStrictLb);
  }

  var ENV_LOCK_META_MAP = {
    permission_tier: { label: "权限安全档位", defaultVar: "COSMOS_MCP_PERMISSION_TIER", panes: ["workbench", "tools"] },
    tier_key: { label: "权限安全档位", defaultVar: "COSMOS_MCP_PERMISSION_TIER", panes: ["workbench", "tools"] },
    safety_mode: { label: "权限安全档位", defaultVar: "COSMOS_MCP_PERMISSION_TIER", panes: ["workbench", "tools"] },
    workspace_roots: { label: "开放工作目录", defaultVar: "COSMOS_WORKSPACE_ROOTS", panes: ["workbench"] },
    workspaces: { label: "开放工作目录", defaultVar: "COSMOS_WORKSPACE_ROOTS", panes: ["workbench"] },
    readonly_workspace_roots: { label: "只读工作目录", defaultVar: "COSMOS_READONLY_WORKSPACE_ROOTS", panes: ["workbench"] },
    enabled_packs: { label: "扩展能力包", defaultVar: "COSMOS_ENABLED_PACKS", panes: ["tools"] },
    toolset_profile: { label: "核心工具预设", defaultVar: "COSMOS_TOOLSET_PROFILE", panes: ["tools"] },
    prompt_profile: { label: "提示词预设", defaultVar: "COSMOS_PROMPT_PROFILE", panes: ["tools"] },
    enabled_tools: { label: "启用工具列表", defaultVar: "COSMOS_ENABLED_TOOLS", panes: ["tools"] },
    disabled_tools: { label: "禁用工具列表", defaultVar: "COSMOS_DISABLED_TOOLS", panes: ["tools"] },
    tool_prefix: { label: "多设备工具前缀", defaultVar: "COSMOS_TOOL_PREFIX", panes: ["tools"] },
    python_path: { label: "默认 Python 解释器", defaultVar: "COSMOS_PYTHON_PATH", panes: ["runtime"] },
    keep_awake: { label: "插电防休眠", defaultVar: "COSMOS_KEEP_AWAKE", panes: ["runtime"] },
    tunnel_mode: { label: "连接与网关模式", defaultVar: "COSMOS_TUNNEL_MODE", panes: ["gateways"] },
    public_url: { label: "固定公网地址", defaultVar: "COSMOS_PUBLIC_URL", panes: ["gateways"] },
    gateways: { label: "网关通道配置", defaultVar: "COSMOS_GATEWAYS", panes: ["gateways"] },
    endpoint_secret: { label: "静态防扫描路径", defaultVar: "COSMOS_ENDPOINT_SECRET", panes: ["gateways", "auth"] },
  };

  function normalizeEnvLocks(doc) {
    var d = doc || state || {};
    var raw =
      d.env_locks && typeof d.env_locks === "object" && !Array.isArray(d.env_locks)
        ? d.env_locks
        : d.connection && d.connection.env_locks && typeof d.connection.env_locks === "object"
        ? d.connection.env_locks
        : null;
    var items = [];
    var lockedKeys = {};
    if (!raw) return { items: items, lockedKeys: lockedKeys };

    Object.keys(raw).forEach(function (k) {
      var val = raw[k];
      if (!val) return;
      lockedKeys[k] = true;
      var meta = ENV_LOCK_META_MAP[k] || {
        label: k,
        defaultVar: String(k).toUpperCase(),
        panes: ["workbench", "gateways", "auth", "runtime", "tools"],
      };
      var envVar = meta.defaultVar;
      var customReason = "";
      if (typeof val === "string") {
        envVar = val.trim() || envVar;
      } else if (typeof val === "object") {
        if (val.env_var || val.var || val.name) {
          envVar = String(val.env_var || val.var || val.name).trim();
        }
        if (val.label) {
          meta = { label: String(val.label), defaultVar: envVar, panes: meta.panes };
        }
        if (val.reason) {
          customReason = String(val.reason).trim();
        }
      }
      items.push({
        key: k,
        label: meta.label,
        envVar: envVar,
        reason: customReason,
        panes: meta.panes,
      });
    });
    return { items: items, lockedKeys: lockedKeys };
  }

  function renderEnvLockBanners(doc) {
    var parsed = normalizeEnvLocks(doc);
    var items = parsed.items;
    var lockedKeys = parsed.lockedKeys;

    var bannerMap = {
      workbench: $("wb-env-lock-banner"),
      gateways: $("settings-env-lock-gateways"),
      auth: $("settings-env-lock-auth"),
      runtime: $("settings-env-lock-runtime"),
      tools: $("settings-env-lock-tools"),
    };

    Object.keys(bannerMap).forEach(function (paneKey) {
      var container = bannerMap[paneKey];
      if (!container) return;
      var matched = items.filter(function (it) {
        return it.panes.indexOf(paneKey) >= 0;
      });
      if (!matched.length) {
        container.style.display = "none";
        container.innerHTML = "";
        return;
      }
      container.innerHTML = "";
      matched.forEach(function (it, idx) {
        var line = document.createElement("div");
        if (idx > 0) line.style.marginTop = "4px";
        var strong = document.createElement("strong");
        strong.textContent = it.label + "已锁定（";
        var code = document.createElement("code");
        code.textContent = it.envVar;
        var tail = document.createElement("span");
        var baseNotice = "由启动环境变量锁定，需修改启动环境并重启后更改。";
        var extraReason =
          it.reason && it.reason.indexOf("启动环境") < 0 ? "（" + it.reason + "）" : "";
        tail.textContent = "）：" + baseNotice + extraReason;
        line.appendChild(strong);
        line.appendChild(code);
        line.appendChild(tail);
        container.appendChild(line);
      });
      container.style.display = "block";
    });

    var tierLocked = Boolean(
      lockedKeys.permission_tier || lockedKeys.tier_key || lockedKeys.safety_mode
    );
    document.querySelectorAll("#safety-mode-cards [data-target-safety]").forEach(function (btn) {
      var isAct = btn.classList.contains("active");
      btn.disabled = tierLocked && !isAct;
    });

    var wsLocked = Boolean(lockedKeys.workspace_roots || lockedKeys.workspaces);
    ["manual-ws-input", "add-manual-ws-btn", "pick-local-folder-btn", "tree-add-ws-btn", "tree-set-primary-btn"].forEach(
      function (id) {
        if ($(id)) $(id).disabled = wsLocked;
      }
    );
    document.querySelectorAll("#workspace-roots-list button").forEach(function (btn) {
      if (wsLocked) btn.disabled = true;
    });

    if (lockedKeys.enabled_packs) {
      if ($("chk-pack-browser")) $("chk-pack-browser").disabled = true;
      if ($("chk-pack-desktop")) $("chk-pack-desktop").disabled = true;
    }
    var pyLocked = Boolean(lockedKeys.python_path);
    ["python-candidates-select", "python-path-input", "save-python-btn"].forEach(function (id) {
      if ($(id)) $(id).disabled = pyLocked;
    });
    var tpLocked = Boolean(lockedKeys.tool_prefix);
    ["tool-prefix-input", "save-tool-prefix-btn"].forEach(function (id) {
      if ($(id)) $(id).disabled = tpLocked;
    });
  }

  function loadGatewayDebug(gid) {
    var logEl = $("gw-debug-log-" + gid);
    if (logEl) logEl.textContent = "正在拉取脱敏实时日志…";
    apiFetch("/api/studio/gateway-debug", { method: "GET" })
      .then(function (data) {
        if (!data || !data.gateways) return;
        var g = data.gateways[gid] || {};
        var eng = $("gw-debug-engine-" + gid);
        if (eng) eng.textContent = String(g.effective_mode || g.status || "-");
        var fb = $("gw-debug-fallback-" + gid);
        if (fb) fb.textContent = g.fallback_active ? "是（已降级临时通道）" : "否";
        var err = $("gw-debug-error-" + gid);
        if (err) err.textContent = String(g.last_error || "无");
        var src = $("gw-debug-source-" + gid);
        if (src) src.textContent = "日志来源：" + String(g.log_source || "-");
        if (logEl) {
          var lines = Array.isArray(g.log_tail) ? g.log_tail : [];
          logEl.textContent = lines.length ? lines.join("\n") : "（当前暂无相关日志记录）";
        }
      })
      .catch(function (e) {
        if (logEl) logEl.textContent = "拉取调试日志失败：" + (e && e.message ? e.message : String(e));
      });
  }

  function syncCsrfMetaTag(tok) {
    var clean = String(tok || "").trim();
    if (!clean) return;
    var metaEl = document.querySelector('meta[name="studio-csrf"]');
    if (metaEl) {
      metaEl.setAttribute("content", clean);
    }
  }

  function renderAll(doc) {
    if (!doc || typeof doc !== "object") return;
    state = doc;
    if (doc.csrf_token) {
      syncCsrfMetaTag(doc.csrf_token);
    }
    if (doc.state_revision !== undefined && doc.state_revision !== null) {
      lastStateRevision = String(doc.state_revision);
    }

    if (doc.flash_notice) showToast(doc.flash_notice, false);
    if (doc.flash_error) showToast(doc.flash_error, true);

    setStatusIndicator(doc.status_kind || "online", doc.status_text || "在线运行");
    if (doc.device_label && $("brand-subtitle")) {
      $("brand-subtitle").textContent =
        "本机设备：" + doc.device_label + " · 版本 v" + (doc.product_version || "1.0.0");
    }
    if ($("studio-update-sub")) {
      var curVer = doc.product_version || "1.0.0";
      var lastUpd = doc.last_update_status || {};
      var updSuffix =
        lastUpd && lastUpd.status === "succeeded" && lastUpd.to_version
          ? " · 最近已平滑升级至 v" + lastUpd.to_version
          : " · 支持保留公网隧道平滑升级";
      $("studio-update-sub").textContent = "当前版本 v" + curVer + updSuffix;
    }

    var lockPanel = $("remote-lock-panel");
    var mainContent = $("studio-main-content");
    if (doc.locked) {
      authBackupRevealed = false;
      authBackupPlain = "";
      syncAuthBackupDisplay();
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

    var codes = resolvePairCodes(doc);
    syncPairCodeDom(codes.dynamicCode, codes.consentCode);

    var sessArr = conn.authorized_sessions || doc.authorized_sessions || [];
    var sessCnt = typeof conn.authorized_sessions_count === "number" ? conn.authorized_sessions_count : sessArr.length;
    if ($("sessions-count")) $("sessions-count").textContent = String(sessCnt);
    if ($("revoke-sessions-btn")) {
      $("revoke-sessions-btn").disabled = sessCnt <= 0;
    }
    if ($("mint-pat-btn")) {
      var isStrictLb = doc.is_loopback !== false;
      $("mint-pat-btn").disabled = !isStrictLb;
      if ($("pat-loopback-only-hint")) {
        $("pat-loopback-only-hint").style.display = isStrictLb ? "none" : "block";
      }
    }
    updateFirstWakeBanner(sessCnt);

    if ($("chk-keep-awake")) $("chk-keep-awake").checked = !!conn.keep_awake;
    if ($("chk-autostart")) $("chk-autostart").checked = !!conn.autostart_enabled;
    if ($("chk-wake-autostart")) $("chk-wake-autostart").checked = !!conn.autostart_enabled;

    var pwBox = $("conn-pw-box");
    if (pwBox) {
      pwBox.setAttribute("data-secret", "");
      if (pwBox.getAttribute("data-shown") === "1") {
        if (conn.connection_password) {
          pwBox.textContent = conn.connection_password;
        } else if (authBackupRevealed && authBackupPlain) {
          pwBox.textContent = authBackupPlain;
        }
      } else {
        pwBox.textContent = conn.connection_password_masked || "••••••••••••••••••••";
      }
    }

    updateConnectionCardsUI(conn.tunnel_mode || "public_gateway", conn);
    renderInstantSubchannels(conn, doc);
    renderEndpointSecretControls(conn, doc);
    var patCnt = computePatCount(doc, sessArr);
    lastSessionsSignature = JSON.stringify({ s: sessArr, p: patCnt, m: doc.safety_mode || "full_dev" });
    renderAuthorizedSessions(sessArr);
    renderAuthCredentialsPane(doc);

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
    renderEnvLockBanners(doc);

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
    if (typeof syncOnboardingWizard === "function") syncOnboardingWizard(doc);
    if ($("save-python-btn")) $("save-python-btn").classList.remove("is-dirty-unsaved");
    if ($("save-tool-prefix-btn")) $("save-tool-prefix-btn").classList.remove("is-dirty-unsaved");
  }

  function resolveSessionScopeBadge(sess) {
    var rawScopes = Array.isArray(sess.scopes)
      ? sess.scopes
      : typeof sess.scope === "string" && sess.scope.trim()
      ? sess.scope.trim().split(/[\s,]+/)
      : [];
    var scopes = rawScopes.map(function (x) {
      return String(x || "").toLowerCase();
    });
    var isRo = Boolean(
      sess.readonly ||
        scopes.indexOf("readonly") >= 0 ||
        scopes.indexOf("mcp:readonly") >= 0 ||
        scopes.indexOf("read_only") >= 0
    );
    var tempSuffix = sess.temporary_session ? " · 2小时临时授权" : "";
    if (sess.temporary_session && (!sess.scope_label || sess.scope_label.indexOf("临时") < 0)) {
      tempSuffix = " · 临时会话";
    }
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
        btn.disabled = true;
        revokeAuthorizedClient(sess.client_id, "已断开该客户端授权").finally(function () {
          btn.disabled = false;
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
    var shortPermMap = {
      readonly: "只读",
      edit_only: "仅改文件",
      full_dev: "工作区开发",
      full_power: "全盘开发",
    };
    var permPill = $("header-perm-pill");
    if (permPill) {
      permPill.textContent = shortPermMap[modeCode] || "工作区开发";
      permPill.setAttribute("data-safety-mode", modeCode || "full_dev");
    }
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
    var valid = ["gateways", "auth", "runtime", "tools", "skills", "appearance"];
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

    function buildChatGptConnectPrompt(kind, oneclickUrl) {
      var isRo = kind === "readonly";
      var pfx = getEffectiveToolPrefix();
      var statusTool = pfx + "_get_status";
      var statusHint =
        statusTool === "pc_get_status" || statusTool === "get_status"
          ? "pc_get_status"
          : statusTool + "（或 pc_get_status）";
      var scopeDesc = isRo
        ? "只读查看我本地授权目录的文件与状态"
        : "读写我本地授权目录的文件并执行本地开发工具";
      return [
        "[@Plugin Creator](plugin://plugin-creator@openai-curated-remote?remotePluginId=plugin_connector_1p_e1a10c53223481918a42f1510ec46c1e) 帮我创建一个插件，把我的本地电脑服务 WebAI2PC 接入当前 ChatGPT 账号，并完成首次调用验证（请在 Work 模式下执行；装好后日常可在 Chat 模式通过 @WebAI2PC 直接调用）。",
        "",
        "插件名称：WebAI2PC",
        "MCP 地址：" + oneclickUrl,
        "服务说明：标准 Streamable HTTP MCP 服务（JSON-RPC 2.0，采用标准 OAuth 2.1 认证），用于" +
          scopeDesc +
          "；首次验证工具为 " +
          statusHint +
          "。",
        "",
        "执行步骤：",
        "1. 请使用 @Plugin Creator 直接接入上述标准 OAuth MCP 地址创建并安装 WebAI2PC 插件；按服务端公布的 OAuth 元数据自动协商，需要我点击授权确认时请提示我操作。",
        "2. 插件安装并授权完成后，实际调用一次 " + statusHint + "，确认返回我电脑的主机名与当前工作区状态即可。",
        "3. 若当前工作区策略禁止添加或绑定外部 MCP 插件（例如返回 403 或缺少相应权限），请如实向我汇报该限制即可。",
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

    // Primary ChatGPT Action: Fetch single-source standard OAuth @Plugin Creator prompt for Work mode
    document.querySelectorAll("[data-copy-chatgpt-assist]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var kind = btn.getAttribute("data-copy-chatgpt-assist") === "readonly" ? "readonly" : "mcp";
        var effTop = resolveEffectiveTopView(state.connection || {});
        var targetUrl = kind === "readonly" ? effTop.readonly_mcp_url || "" : effTop.mcp_url || "";
        if (!effTop.public_https_ready || !isSafeHttpsUrl(targetUrl)) {
          showToast("网关尚未就绪，请等待公网 HTTPS 地址生成后再复制。", true);
          return;
        }
        var chosenGwId =
          effTop.displayId ||
          userPinnedGateway ||
          (state.connection && state.connection.user_selected_gateway) ||
          state.display_gateway_id ||
          "";
        apiFetch("/api/studio/chatgpt-oneclick", {
          method: "POST",
          body: { kind: kind, rotate: false, gateway_id: chosenGwId },
        })
          .then(function (d) {
            var connectPrompt = "";
            if (d && d.ok && typeof d.prompt === "string" && d.prompt.trim()) {
              connectPrompt = d.prompt.trim();
            } else {
              var effUrl =
                d && d.ok && isSafeHttpsUrl(d.mcp_url || d.oneclick_url)
                  ? d.mcp_url || d.oneclick_url
                  : targetUrl;
              connectPrompt = buildChatGptConnectPrompt(kind, effUrl);
            }
            copyText(connectPrompt, btn);
            showToast(
              "已复制一键配置提示词（请粘贴发给 ChatGPT Work 模式；含本机专属地址，仅限本人账号使用，请勿发往群聊或公开帖子）",
              false
            );
            probeWorkersDevReachabilitySilent();
          })
          .catch(function () {
            var connectPrompt = buildChatGptConnectPrompt(kind, targetUrl);
            copyText(connectPrompt, btn);
            showToast(
              "已复制一键配置提示词（请粘贴发给 ChatGPT Work 模式；含本机专属地址，仅限本人账号使用，请勿发往群聊或公开帖子）",
              false
            );
          });
      });
    });

    // One-Shot Showcase Prompt Copy Buttons (pure task prompt without guessing connector name)
    document.querySelectorAll("[data-copy-showcase]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var caseKey = btn.getAttribute("data-copy-showcase") || "";
        var bodyText = SHOWCASE_PROMPTS[caseKey] || "";
        if (!bodyText) return;
        copyText(bodyText, btn);
        showToast("已复制，在 AI 对话框输入 @ 选你的连接器后粘贴即可", false);
      });
    });

    // Showcase "查看全文" expandable prompt preview toggles
    document.querySelectorAll("[data-toggle-showcase-prompt]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var caseKey = btn.getAttribute("data-toggle-showcase-prompt") || "";
        var preview = document.querySelector('[data-showcase-preview="' + caseKey + '"]');
        if (!preview) return;
        if (!preview.textContent) {
          preview.textContent = SHOWCASE_PROMPTS[caseKey] || "";
        }
        var willShow = preview.hasAttribute("hidden");
        if (willShow) {
          preview.removeAttribute("hidden");
          btn.setAttribute("aria-expanded", "true");
          btn.textContent = "收起全文";
        } else {
          preview.setAttribute("hidden", "");
          btn.setAttribute("aria-expanded", "false");
          btn.textContent = "查看全文";
        }
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
    if ($("run-conn-check-btn")) {
      $("run-conn-check-btn").addEventListener("click", function () {
        runStudioConnectivityCheck("", "workbench");
      });
    }
    if ($("rerun-conn-check-btn")) {
      $("rerun-conn-check-btn").addEventListener("click", function () {
        runStudioConnectivityCheck(lastWorkbenchConnGwId, "workbench");
      });
    }
    if ($("copy-conn-diag-btn")) {
      $("copy-conn-diag-btn").addEventListener("click", function () {
        copyRedactedConnDiag("workbench", $("copy-conn-diag-btn"));
      });
    }
    if ($("close-conn-check-btn")) {
      $("close-conn-check-btn").addEventListener("click", function () {
        if ($("conn-check-panel")) $("conn-check-panel").style.display = "none";
      });
    }
    if ($("settings-conn-check-btn")) {
      $("settings-conn-check-btn").addEventListener("click", function () {
        runStudioConnectivityCheck("", "settings");
      });
    }
    if ($("settings-rerun-conn-check-btn")) {
      $("settings-rerun-conn-check-btn").addEventListener("click", function () {
        runStudioConnectivityCheck(lastSettingsConnGwId, "settings");
      });
    }
    if ($("settings-copy-conn-diag-btn")) {
      $("settings-copy-conn-diag-btn").addEventListener("click", function () {
        copyRedactedConnDiag("settings", $("settings-copy-conn-diag-btn"));
      });
    }
    if ($("settings-close-conn-check-btn")) {
      $("settings-close-conn-check-btn").addEventListener("click", function () {
        if ($("settings-conn-check-panel")) $("settings-conn-check-panel").style.display = "none";
      });
    }
    document.querySelectorAll("[data-gw-probe]").forEach(function (btn) {
      btn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        var gid = btn.getAttribute("data-gw-probe") || "";
        if (gid) {
          runStudioConnectivityCheck(gid, "settings", btn);
        }
      });
    });
    if ($("toggle-conn-details-btn")) {
      $("toggle-conn-details-btn").addEventListener("click", function () {
        userToggledConnDrawer = true;
        var drawer = $("wb-conn-drawer");
        var isOpen = drawer ? drawer.classList.contains("open") : false;
        setConnDrawerOpen(!isOpen);
      });
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

    if ($("cf-custom-domain-input")) {
      $("cf-custom-domain-input").addEventListener("input", function () {
        $("cf-custom-domain-input").setAttribute("data-user-dirty", "1");
        if ($("clear-cf-custom-domain-btn")) {
          var hasSavedDom = Boolean(state && state.connection && state.connection.workers_dev_custom_domain);
          $("clear-cf-custom-domain-btn").disabled = !Boolean(hasSavedDom || $("cf-custom-domain-input").value.trim());
        }
      });
    }

    if ($("save-cf-custom-domain-btn")) {
      $("save-cf-custom-domain-btn").addEventListener("click", function () {
        var domInp = $("cf-custom-domain-input");
        var domVal = domInp ? domInp.value.trim() : "";
        var sBtn = $("save-cf-custom-domain-btn");
        sBtn.disabled = true;
        apiFetch("/api/studio/connection", {
          method: "POST",
          body: { action: "save_workers_custom_domain", custom_domain: domVal },
        })
          .then(function (d) {
            sBtn.disabled = false;
            if (!d || !d.ok) {
              showToast((d && (d.error || d.message)) || "保存自定义域名失败", true);
              return;
            }
            if (domInp) domInp.removeAttribute("data-user-dirty");
            renderAll(d);
            showToast(d.message || "已更新 Cloudflare 自定义域名", false);
          })
          .catch(function (e) {
            sBtn.disabled = false;
            showToast("保存自定义域名失败：" + (e && e.message ? e.message : e), true);
          });
      });
    }

    if ($("clear-cf-custom-domain-btn")) {
      $("clear-cf-custom-domain-btn").addEventListener("click", function () {
        var domInp = $("cf-custom-domain-input");
        var cBtn = $("clear-cf-custom-domain-btn");
        cBtn.disabled = true;
        apiFetch("/api/studio/connection", {
          method: "POST",
          body: { action: "clear_workers_custom_domain" },
        })
          .then(function (d) {
            cBtn.disabled = false;
            if (!d || !d.ok) {
              showToast((d && (d.error || d.message)) || "清空自定义域名失败", true);
              return;
            }
            if (domInp) {
              domInp.value = "";
              domInp.removeAttribute("data-user-dirty");
            }
            renderAll(d);
            showToast(d.message || "已清空自定义域名并恢复默认网关地址", false);
          })
          .catch(function (e) {
            cBtn.disabled = false;
            showToast("清空自定义域名失败：" + (e && e.message ? e.message : e), true);
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

    if ($("quick-readonly-btn")) {
      $("quick-readonly-btn").addEventListener("click", function () {
        var reqSeq = ++toolsSafetyReqSeq;
        apiFetch("/api/studio/tools-safety", { method: "POST", body: { safety_mode: "readonly" } }).then(function (d) {
          if (reqSeq !== toolsSafetyReqSeq) return;
          if (!d.ok) return showToast(d.error || "切换失败", true);
          renderAll(d);
          showToast(d.message || "已切为只读浏览模式", false);
        });
      });
    }

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
        clearPatOnceResult("");
        renderAll(d);
        showToast(d.message || "已断开全部网页会话", false);
      });
    });

    if ($("open-pat-fallback-btn")) {
      $("open-pat-fallback-btn").addEventListener("click", function () {
        var connDrw = $("wb-conn-drawer");
        if (connDrw) connDrw.classList.add("open");
        var pairDet = $("pairing-sessions-details");
        var patDet = $("pat-mint-details");
        if (pairDet) pairDet.open = true;
        if (patDet) {
          patDet.open = true;
          if (patDet.scrollIntoView) {
            patDet.scrollIntoView({ behavior: "smooth", block: "nearest" });
          }
        }
        if ($("pat-label-input")) {
          $("pat-label-input").focus();
        }
      });
    }

    if ($("mint-pat-btn")) {
      $("mint-pat-btn").addEventListener("click", function () {
        submitPatMintFlow({
          btnId: "mint-pat-btn",
          scopeSelectId: "pat-scope-select",
          ttlSelectId: "pat-ttl-select",
          labelInputId: "pat-label-input",
          oncePrefix: "pat-once",
        });
      });
    }

    if ($("copy-pat-token-btn")) {
      $("copy-pat-token-btn").addEventListener("click", function () {
        var tokEl = $("pat-once-token-value");
        var rawTok = tokEl ? tokEl.textContent.trim() : "";
        if (!rawTok) return;
        copyText(rawTok, $("copy-pat-token-btn"));
        showToast(PAT_ANTI_LEAK_TOAST, true);
      });
    }

    if ($("dismiss-pat-result-btn")) {
      $("dismiss-pat-result-btn").addEventListener("click", function () {
        clearPatOnceResult("", "pat-once");
      });
    }

    // Settings -> Gateways Subchannels, Reconnect, Debug Drawers & Endpoint Secret (/u/<secret>)
    document.querySelectorAll("[data-subchannel-reconnect]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var sub = btn.getAttribute("data-subchannel-reconnect");
        if (!sub) return;
        btn.disabled = true;
        apiFetch("/api/studio/connection", {
          method: "POST",
          body: { action: "reconnect_subchannel", subchannel: sub },
        })
          .then(function (d) {
            if (!d || !d.ok) {
              showToast((d && (d.error || d.message)) || "子通道重连失败", true);
              return;
            }
            if (d.gateways || d.connection) renderAll(d);
            showToast(d.message || "已触发 " + sub + " 独立重连", false);
          })
          .catch(function (e) {
            showToast("重连失败：" + (e && e.message ? e.message : e), true);
          })
          .finally(function () {
            btn.disabled = false;
          });
      });
    });

    document.querySelectorAll("[data-subchannel-copy]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var u = btn.getAttribute("data-url") || "";
        if (!u) return;
        copyText(u, btn);
        showToast("已复制连接地址（请仅用于本人登录的 AI 账号）", false);
      });
    });


    if ($("instant-sub-trycf-switch")) {
      $("instant-sub-trycf-switch").addEventListener("change", function () {
        var cfSw = $("instant-sub-trycf-switch");
        var en = Boolean(cfSw.checked);
        cfSw.disabled = true;
        apiFetch("/api/studio/connection", {
          method: "POST",
          body: { action: "set_trycloudflare_backup", enabled: en },
        })
          .then(function (d) {
            cfSw.disabled = false;
            if (!d || !d.ok) {
              cfSw.checked = !en;
              showToast((d && (d.error || d.message)) || "切换备用通道失败", true);
              return;
            }
            renderAll(d);
            showToast(
              d.message ||
                (en ? "已开启 trycloudflare 备用通道（与 OpenSSH 固定通道并存）" : "已关闭 trycloudflare 备用通道"),
              false
            );
          })
          .catch(function (e) {
            cfSw.disabled = false;
            cfSw.checked = !en;
            showToast("切换备用通道失败：" + (e && e.message ? e.message : e), true);
          });
      });
    }

    document.querySelectorAll("[data-gw-reconnect]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var gid = btn.getAttribute("data-gw-reconnect");
        if (!gid) return;
        btn.disabled = true;
        apiFetch("/api/studio/connection", {
          method: "POST",
          body: { action: "reconnect_gateway", gateway_id: gid },
        })
          .then(function (d) {
            if (!d || !d.ok) {
              showToast((d && (d.error || d.message)) || "重连通道失败", true);
              return;
            }
            if (d.gateways || d.connection) renderAll(d);
            showToast(d.message || "已触发 " + gid + " 通道重连", false);
          })
          .catch(function (e) {
            showToast("重连失败：" + (e && e.message ? e.message : e), true);
          })
          .finally(function () {
            btn.disabled = false;
          });
      });
    });

    document.querySelectorAll("[data-gw-debug]").forEach(function (el) {
      var gid = el.getAttribute("data-gw-debug");
      el.addEventListener("toggle", function () {
        if (el.open && gid) loadGatewayDebug(gid);
      });
    });
    document.querySelectorAll("[data-gw-debug-refresh]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var gid = btn.getAttribute("data-gw-debug-refresh");
        if (gid) loadGatewayDebug(gid);
      });
    });

    function bindTwoStepEndpointSecretBtn(btnId, actionName, armText, armHint, defaultLabel) {
      var btn = $(btnId);
      if (!btn) return;
      btn.addEventListener("click", function () {
        if (btn.getAttribute("data-confirm-armed") !== "1") {
          btn.setAttribute("data-confirm-armed", "1");
          btn.textContent = armText;
          btn.classList.add("btn-danger");
          showToast(armHint, false);
          clearTimeout(endpointSecretConfirmTimers[btnId]);
          endpointSecretConfirmTimers[btnId] = setTimeout(function () {
            btn.removeAttribute("data-confirm-armed");
            btn.textContent = defaultLabel;
            btn.classList.remove("btn-danger");
          }, 6000);
          return;
        }
        clearTimeout(endpointSecretConfirmTimers[btnId]);
        btn.removeAttribute("data-confirm-armed");
        btn.textContent = defaultLabel;
        btn.classList.remove("btn-danger");
        btn.disabled = true;
        var payload =
          actionName === "rotate_endpoint_secret"
            ? { action: "rotate_endpoint_secret", revoke_sessions: false }
            : { action: "disable_endpoint_secret" };
        apiFetch("/api/studio/connection", {
          method: "POST",
          body: payload,
        })
          .then(function (d) {
            btn.disabled = false;
            if (!d || !d.ok) {
              showToast((d && (d.error || d.message)) || "更新静态防扫描路径失败", true);
              return;
            }
            renderAll(d);
            showToast(
              d.message ||
                (actionName === "rotate_endpoint_secret"
                  ? "已更新静态防扫描路径（/u/<secret>）"
                  : "已恢复默认 /mcp 路径"),
              false
            );
          })
          .catch(function (e) {
            btn.disabled = false;
            showToast("操作失败：" + (e && e.message ? e.message : e), true);
          });
      });
    }

    ["gw-rotate-endpoint-secret-btn", "auth-rotate-endpoint-secret-btn"].forEach(function (id) {
      bindTwoStepEndpointSecretBtn(
        id,
        "rotate_endpoint_secret",
        "再点确认更换",
        "提示：开启或更换 /u/<secret> 会变更所有网关 URL，再次点击按钮确认执行。",
        "开启 / 更换路径"
      );
    });
    ["gw-disable-endpoint-secret-btn", "auth-disable-endpoint-secret-btn"].forEach(function (id) {
      bindTwoStepEndpointSecretBtn(
        id,
        "disable_endpoint_secret",
        "再点确认关闭",
        "提示：关闭防扫描路径将恢复默认 /mcp，再次点击按钮确认执行。",
        "关闭并恢复 /mcp"
      );
    });

    // Settings -> Auth & Credentials Pane (`#settings-pane-auth`)
    function copyAuthDynamicPairCode(triggerBtn) {
      var codes = resolvePairCodes(state);
      if (!codes.dynamicCode) return;
      copyText(codes.dynamicCode, triggerBtn || $("auth-copy-pair-btn"));
      showToast("已复制 6 位动态配对码：" + codes.dynamicCode, false);
    }
    function copyAuthConsentCode(triggerBtn) {
      var codes = resolvePairCodes(state);
      if (!codes.consentCode) return;
      copyText(codes.consentCode, triggerBtn || $("auth-copy-verify-btn"));
      showToast("已复制 4 位核对码：" + codes.consentCode, false);
    }

    if ($("auth-copy-pair-btn")) {
      $("auth-copy-pair-btn").addEventListener("click", function () {
        copyAuthDynamicPairCode($("auth-copy-pair-btn"));
      });
    }
    if ($("auth-pair-code-val")) {
      $("auth-pair-code-val").addEventListener("click", function () {
        copyAuthDynamicPairCode($("auth-copy-pair-btn"));
      });
    }
    if ($("auth-copy-verify-btn")) {
      $("auth-copy-verify-btn").addEventListener("click", function () {
        copyAuthConsentCode($("auth-copy-verify-btn"));
      });
    }
    if ($("auth-verify-code-val")) {
      $("auth-verify-code-val").addEventListener("click", function () {
        copyAuthConsentCode($("auth-copy-verify-btn"));
      });
    }

    if ($("auth-refresh-pair-btn")) {
      $("auth-refresh-pair-btn").addEventListener("click", function () {
        var rBtn = $("auth-refresh-pair-btn");
        rBtn.disabled = true;
        apiFetch("/api/studio/connection", {
          method: "POST",
          body: { action: "rotate_pair_code" },
        })
          .then(function (d) {
            rBtn.disabled = false;
            if (!d || !d.ok) {
              showToast((d && (d.error || d.message)) || "刷新配对码失败", true);
              return;
            }
            if (d.gateways || d.workspaces) {
              renderAll(d);
            }
            var nextCodes = resolvePairCodes(d);
            var effDyn = nextCodes.dynamicCode || resolvePairCodes(state).dynamicCode;
            var effVer = nextCodes.consentCode || resolvePairCodes(state).consentCode;
            state.dynamic_pair_code = effDyn;
            state.consent_pair_code = effVer;
            state.pair_code = effVer;
            state.connection = Object.assign({}, state.connection || {}, {
              dynamic_pair_code: effDyn,
              consent_pair_code: effVer,
              pair_code: effVer,
            });
            syncPairCodeDom(effDyn, effVer);
            showToast(d.message || "已刷新 6 位动态配对码与 4 位核对码", false);
          })
          .catch(function () {
            rBtn.disabled = false;
            showToast("刷新配对码失败，请确认本机服务在线", true);
          });
      });
    }

    if ($("auth-wipe-plaintext-pw-btn")) {
      $("auth-wipe-plaintext-pw-btn").addEventListener("click", function () {
        var wBtn = $("auth-wipe-plaintext-pw-btn");
        wBtn.disabled = true;
        apiFetch("/api/studio/connection", {
          method: "POST",
          body: { action: "wipe_plaintext_password" },
        })
          .then(function (d) {
            if (!d || !d.ok) {
              wBtn.disabled = false;
              showToast((d && (d.error || d.message)) || "擦除明文口令文件失败", true);
              return;
            }
            renderAll(d);
            showToast(d.message || "已擦除本地 txt 文件中的明文口令", false);
          })
          .catch(function (e) {
            wBtn.disabled = false;
            showToast("擦除失败：" + (e && e.message ? e.message : e), true);
          });
      });
    }


    var pendingUpdateAllowTunnelRestart = false;
    if ($("check-update-btn")) {
      $("check-update-btn").addEventListener("click", function () {
        var ckBtn = $("check-update-btn");
        var apBtn = $("apply-update-btn");
        var uBox = $("studio-update-status-box");
        ckBtn.disabled = true;
        ckBtn.textContent = "正在检查…";
        apiFetch("/api/studio/update", {
          method: "POST",
          body: { action: "check" },
        })
          .then(function (d) {
            ckBtn.disabled = false;
            ckBtn.textContent = "检查更新";
            if (!uBox) return;
            uBox.style.display = "block";
            if (!d || !d.ok) {
              uBox.className = "callout callout-warn";
              uBox.textContent = (d && (d.message || d.error)) || "检查更新失败，请稍后重试。";
              if (apBtn) apBtn.style.display = "none";
              return;
            }
            if (d.update_available) {
              uBox.className = "callout callout-ok";
              pendingUpdateAllowTunnelRestart = Boolean(d.tunnel_impact && d.tunnel_impact.url_changes_on_full_restart);
              uBox.textContent =
                "发现新版本 v" +
                (d.latest_version || "") +
                "（当前 v" +
                (d.current_version || "") +
                "），点击右侧「一键升级」即可自动校验并平滑更新。";
              if (apBtn) apBtn.style.display = "inline-flex";
            } else {
              uBox.className = "callout callout-info";
              uBox.textContent = "当前已是最新版本（v" + (d.current_version || "") + "）。";
              if (apBtn) apBtn.style.display = "none";
            }
          })
          .catch(function (e) {
            ckBtn.disabled = false;
            ckBtn.textContent = "检查更新";
            if (uBox) {
              uBox.style.display = "block";
              uBox.className = "callout callout-warn";
              uBox.textContent = "检查更新失败：" + (e && e.message ? e.message : e);
            }
          });
      });
    }

    if ($("apply-update-btn")) {
      $("apply-update-btn").addEventListener("click", function () {
        var apBtn = $("apply-update-btn");
        var uBox = $("studio-update-status-box");
        apBtn.disabled = true;
        apBtn.textContent = "正在升级…";
        apiFetch("/api/studio/update", {
          method: "POST",
          body: { action: "apply", allow_tunnel_restart: pendingUpdateAllowTunnelRestart },
        })
          .then(function (d) {
            apBtn.disabled = false;
            apBtn.textContent = "一键升级";
            if (!d || !d.ok) {
              var errTxt = (d && (d.message || d.error)) || "在线升级失败";
              if (uBox) {
                uBox.style.display = "block";
                uBox.className = "callout callout-warn";
                uBox.textContent = errTxt;
              }
              showToast(errTxt, true);
              return;
            }
            apBtn.style.display = "none";
            var okTxt =
              d.message ||
              ("升级包已就绪（目标版本 v" + (d.to_version || "") + "），后台工作进程正在平滑热重载…");
            if (uBox) {
              uBox.style.display = "block";
              uBox.className = "callout callout-ok";
              uBox.textContent = okTxt;
            }
            showToast(okTxt, false);
          })
          .catch(function (e) {
            apBtn.disabled = false;
            apBtn.textContent = "一键升级";
            showToast("升级失败：" + (e && e.message ? e.message : e), true);
          });
      });
    }

    if ($("auth-toggle-backup-btn")) {
      $("auth-toggle-backup-btn").addEventListener("click", function () {
        var tBtn = $("auth-toggle-backup-btn");
        if (authBackupRevealed) {
          authBackupPlain = "";
          authBackupRevealed = false;
          syncAuthBackupDisplay();
          return;
        }
        tBtn.disabled = true;
        revealConnectionPassword()
          .then(function (res) {
            tBtn.disabled = false;
            if (!res.ok) {
              showToast(res.error, true);
              return;
            }
            authBackupPlain = res.password;
            authBackupRevealed = true;
            syncAuthBackupDisplay();
          })
          .catch(function () {
            tBtn.disabled = false;
            showToast("读取备用口令失败，请确认本机服务在线", true);
          });
      });
    }

    if ($("auth-copy-backup-btn")) {
      $("auth-copy-backup-btn").addEventListener("click", function () {
        var cBtn = $("auth-copy-backup-btn");
        if (authBackupRevealed && authBackupPlain) {
          copyText(authBackupPlain, cBtn);
          showToast("已复制 20 位备用口令 · 请妥善保管，切勿发给他人或群聊", false);
          return;
        }
        cBtn.disabled = true;
        revealConnectionPassword()
          .then(function (res) {
            cBtn.disabled = false;
            if (!res.ok) {
              showToast(res.error, true);
              return;
            }
            copyText(res.password, cBtn);
            showToast("已复制 20 位备用口令 · 请妥善保管，切勿发给他人或群聊", false);
          })
          .catch(function () {
            cBtn.disabled = false;
            showToast("读取备用口令失败，请确认本机服务在线", true);
          });
      });
    }

    function executeRotateBackupPassword() {
      var rotBtn = $("auth-rotate-backup-btn");
      var cfmBtn = $("auth-confirm-rotate-backup-btn");
      setAuthRotateConfirmOpen(false);
      if (rotBtn) rotBtn.disabled = true;
      if (cfmBtn) cfmBtn.disabled = true;
      apiFetch("/api/studio/connection", {
        method: "POST",
        body: { action: "rotate_password", revoke_sessions: false },
      })
        .then(function (d) {
          if (rotBtn) rotBtn.disabled = false;
          if (cfmBtn) cfmBtn.disabled = false;
          if (!d || !d.ok) {
            showToast((d && (d.error || d.message)) || "重置备用口令失败", true);
            return;
          }
          var nextPw = String(
            d.connection_password || (d.connection && d.connection.connection_password) || ""
          );
          if (authBackupRevealed) {
            if (nextPw) {
              authBackupPlain = nextPw;
            } else {
              authBackupPlain = "";
              authBackupRevealed = false;
            }
          } else {
            authBackupPlain = "";
          }
          if (d.gateways || d.workspaces || d.connection) {
            renderAll(d);
          }
          syncAuthBackupDisplay();
          showToast(d.message || "已重置 20 位备用口令并加密保存", false);
        })
        .catch(function () {
          if (rotBtn) rotBtn.disabled = false;
          if (cfmBtn) cfmBtn.disabled = false;
          showToast("重置备用口令失败，请确认本机服务在线", true);
        });
    }

    if ($("auth-rotate-backup-btn")) {
      $("auth-rotate-backup-btn").addEventListener("click", function () {
        if (!authRotateConfirmArmed) {
          setAuthRotateConfirmOpen(true);
          return;
        }
        executeRotateBackupPassword();
      });
    }
    if ($("auth-confirm-rotate-backup-btn")) {
      $("auth-confirm-rotate-backup-btn").addEventListener("click", executeRotateBackupPassword);
    }
    if ($("auth-cancel-rotate-backup-btn")) {
      $("auth-cancel-rotate-backup-btn").addEventListener("click", function () {
        setAuthRotateConfirmOpen(false);
      });
    }

    if ($("auth-mint-pat-btn")) {
      $("auth-mint-pat-btn").addEventListener("click", function () {
        submitPatMintFlow({
          btnId: "auth-mint-pat-btn",
          scopeSelectId: "auth-pat-scope-select",
          ttlSelectId: "auth-pat-ttl-select",
          labelInputId: "auth-pat-label-input",
          oncePrefix: "auth-pat-once",
        });
      });
    }
    if ($("auth-copy-pat-token-btn")) {
      $("auth-copy-pat-token-btn").addEventListener("click", function () {
        var tokEl = $("auth-pat-once-token-value");
        var rawTok = tokEl ? tokEl.textContent.trim() : "";
        if (!rawTok) return;
        copyText(rawTok, $("auth-copy-pat-token-btn"));
        showToast(PAT_ANTI_LEAK_TOAST, true);
      });
    }
    if ($("auth-dismiss-pat-result-btn")) {
      $("auth-dismiss-pat-result-btn").addEventListener("click", function () {
        clearPatOnceResult("", "auth-pat-once");
      });
    }

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

    if ($("chk-web-compat-mode")) {
      $("chk-web-compat-mode").addEventListener("change", function () {
        if ($("chk-web-compat-mode").disabled) return;
        pushToolsSafetySwitches({ web_compat_mode: $("chk-web-compat-mode").checked });
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

    if ($("chk-skills-scan-host")) {
      $("chk-skills-scan-host").addEventListener("change", function () {
        pushToolsSafetySwitches({ scan_host_global_skills: $("chk-skills-scan-host").checked });
      });
    }

    if ($("chk-redact-project-secrets")) {
      $("chk-redact-project-secrets").addEventListener("change", function () {
        pushToolsSafetySwitches({ redact_project_secrets: $("chk-redact-project-secrets").checked });
      });
    }

    if ($("chk-auto-inject-rules")) {
      $("chk-auto-inject-rules").addEventListener("change", function () {
        pushToolsSafetySwitches({ auto_inject_project_rules: $("chk-auto-inject-rules").checked });
      });
    }

    if ($("chk-allow-loopback-dev")) {
      $("chk-allow-loopback-dev").addEventListener("change", function () {
        if ($("chk-allow-loopback-dev").disabled) return;
        pushToolsSafetySwitches({ allow_loopback_dev: $("chk-allow-loopback-dev").checked });
      });
    }

    if ($("chk-protect-dotenv")) {
      $("chk-protect-dotenv").addEventListener("change", function () {
        if ($("chk-protect-dotenv").disabled) return;
        pushToolsSafetySwitches({ protect_dotenv_files: $("chk-protect-dotenv").checked });
      });
    }

    if ($("chk-protect-credentials")) {
      $("chk-protect-credentials").addEventListener("change", function () {
        pushToolsSafetySwitches({ protect_host_credentials: $("chk-protect-credentials").checked });
      });
    }

    if ($("chk-block-destructive")) {
      $("chk-block-destructive").addEventListener("change", function () {
        if ($("chk-block-destructive").disabled) return;
        pushToolsSafetySwitches({ block_destructive_commands: $("chk-block-destructive").checked });
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
      { inp: "pat-label-input", btn: "mint-pat-btn" },
      { inp: "auth-pat-label-input", btn: "auth-mint-pat-btn" },
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
    var pendingStateSync = false;
    function triggerFullStateSync() {
      if (stateSyncInFlight) {
        pendingStateSync = true;
        return;
      }
      stateSyncInFlight = true;
      pendingStateSync = false;
      var syncStartedAt = Date.now();
      apiFetch("/api/studio/state")
        .then(function (fullDoc) {
          stateSyncInFlight = false;
          if (inFlightMutations > 0 || syncStartedAt < lastMutationAt) {
            scheduleSettledPoll();
            return;
          }
          if (fullDoc && fullDoc.ok) {
            renderAll(fullDoc);
          }
          if (pendingStateSync) {
            pendingStateSync = false;
            triggerFullStateSync();
          }
        })
        .catch(function () {
          stateSyncInFlight = false;
          if (pendingStateSync) {
            pendingStateSync = false;
            scheduleSettledPoll();
          }
        });
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
              triggerFullStateSync();
              return;
            }
            throw new Error("poll_failed");
          }
          setStatusIndicator(d.status_kind || "online", d.status_text || "在线运行");

          var pollCodes = resolvePairCodes(d);
          var dynNow = pollCodes.dynamicCode || "------";
          var latestCode = pollCodes.consentCode || "----";
          syncPairCodeDom(pollCodes.dynamicCode, pollCodes.consentCode);

          var nextSessions = d.authorized_sessions || [];
          var sessCntNow = typeof d.authorized_sessions_count === "number" ? d.authorized_sessions_count : nextSessions.length;
          var patCntNow = computePatCount(d, nextSessions);
          state.pat_count = patCntNow;
          if ($("auth-pat-count-val") && $("auth-pat-count-val").textContent !== String(patCntNow)) {
            $("auth-pat-count-val").textContent = String(patCntNow);
          }
          if ($("revoke-sessions-btn")) {
            $("revoke-sessions-btn").disabled = sessCntNow <= 0;
          }
          updateFirstWakeBanner(sessCntNow);

          if ($("kill-all-tasks-btn") && typeof d.running_tasks_count === "number") {
            $("kill-all-tasks-btn").disabled = d.running_tasks_count <= 0;
          }

          if (d.env_locks !== undefined) {
            state.env_locks = d.env_locks;
            renderEnvLockBanners(state);
          }

          if (d.state_revision !== undefined && d.state_revision !== null) {
            var nextRev = String(d.state_revision);
            if (lastStateRevision === null) {
              lastStateRevision = nextRev;
            } else if (nextRev !== String(lastStateRevision)) {
              triggerFullStateSync();
              return;
            }
          }

          if (d.safety_mode && d.safety_mode !== state.safety_mode) {
            state.safety_mode = d.safety_mode;
            renderSafetyCards(d.safety_mode);
            var wsFpBanner = $("workspace-fullpower-banner");
            if (wsFpBanner) {
              wsFpBanner.style.display = d.safety_mode === "full_power" ? "block" : "none";
            }
            triggerFullStateSync();
            return;
          }

          var nextSig = JSON.stringify({
            s: nextSessions,
            p: patCntNow,
            m: d.safety_mode || state.safety_mode || "full_dev",
          });
          if (nextSig !== lastSessionsSignature) {
            lastSessionsSignature = nextSig;
            if ($("sessions-count")) {
              $("sessions-count").textContent = String(sessCntNow);
            }
            renderAuthorizedSessions(nextSessions);
            renderAuthPatList(
              extractPatSessions({ authorized_sessions: nextSessions, pats: d.pats }),
              state.is_loopback !== false
            );
          }

          state.dynamic_pair_code = pollCodes.dynamicCode;
          state.consent_pair_code = pollCodes.consentCode;
          state.pair_code = pollCodes.consentCode;
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
            endpoint_secret_enabled:
              d.endpoint_secret_enabled !== undefined
                ? Boolean(d.endpoint_secret_enabled)
                : Boolean(state.connection && state.connection.endpoint_secret_enabled),
            endpoint_secret_masked:
              d.endpoint_secret_masked !== undefined
                ? d.endpoint_secret_masked
                : (state.connection && state.connection.endpoint_secret_masked) || "",
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
            pat_count: patCntNow,
          });
          renderConnectionGuides(state.connection);
          updateConnectionCardsUI(d.tunnel_mode || "public_gateway", state.connection);
          renderInstantSubchannels(state.connection, d);
          renderEndpointSecretControls(state.connection, d);
          updateTabTelemetryBadges(d);
          syncIpWorkingPose(d);
          if (typeof syncOnboardingWizard === "function") syncOnboardingWizard(state);
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

  /* ========================================================================
     First-Entry 3-Step Onboarding Wizard Controller
     ======================================================================== */
  var obState = {
    step: 1,
    host: "gemini",
    chatgptTier: "workspace",
    hasCf: false,
    hasVps: false,
    activeRoute: "instant",
    vpsSubmode: "vps",
    manualOpen: false,
    prevSessions: 0,
  };

  function isOnboardingDismissed() {
    try {
      return localStorage.getItem("webai2pc_onboarding_done") === "1";
    } catch (e) {
      return false;
    }
  }

  function setOnboardingDismissed(val) {
    try {
      if (val) localStorage.setItem("webai2pc_onboarding_done", "1");
      else localStorage.removeItem("webai2pc_onboarding_done");
    } catch (e) {}
  }

  function computeObRoute() {
    if (obState.hasCf && obState.hasVps) {
      if (obState.activeRoute !== "cloudflare" && obState.activeRoute !== "self_hosted") {
        obState.activeRoute = "cloudflare";
      }
      return obState.activeRoute;
    }
    if (obState.hasCf) {
      obState.activeRoute = "cloudflare";
      return "cloudflare";
    }
    if (obState.hasVps) {
      obState.activeRoute = "self_hosted";
      return "self_hosted";
    }
    obState.activeRoute = "instant";
    return "instant";
  }

  function setObStep(stepNum) {
    var s = stepNum === 2 ? 2 : stepNum === 3 ? 3 : stepNum === 4 ? 4 : 1;
    obState.step = s;
    [1, 2, 3, 4].forEach(function (n) {
      var tab = $("ob-step-tab-" + n);
      var pane = $("ob-pane-" + n);
      var numEl = $("ob-step-num-" + n);
      if (tab) {
        tab.classList.toggle("active", n === s);
        tab.classList.toggle("done", n < s);
        tab.setAttribute("aria-selected", n === s ? "true" : "false");
      }
      if (numEl) {
        numEl.textContent = n < s ? "✓" : String(n);
      }
      if (pane) {
        pane.classList.toggle("active", n === s);
      }
    });
    renderObDynamicState();
    if (window.WebAI2PCI18n && window.WebAI2PCI18n.getLang() === "en") {
      window.WebAI2PCI18n.apply("en");
    }
  }

  function getObTargetUrl() {
    var conn = (state && state.connection) || state || {};
    var gws = conn.gateways || state.gateways || {};
    var route = computeObRoute();
    var isRo = obState.host === "chatgpt" && obState.chatgptTier === "personal";
    var gwKey = route === "cloudflare" ? "workers_dev" : route === "self_hosted" ? "self_hosted" : "instant";
    var gwObj = gws[gwKey] || {};
    var baseMcp = "";
    var baseRo = "";
    if (gwObj && gwObj.ready && gwObj.mcp_url) {
      baseMcp = gwObj.mcp_url;
      baseRo = gwObj.readonly_mcp_url || gwObj.mcp_readonly_url || gwObj.mcp_url.replace(/\/mcp\/?$/, "/mcp/readonly");
    } else if (conn.public_https_ready && conn.mcp_url) {
      baseMcp = conn.mcp_url;
      baseRo = conn.readonly_mcp_url || conn.mcp_readonly_url || conn.mcp_url.replace(/\/mcp\/?$/, "/mcp/readonly");
    }
    return {
      ready: Boolean(baseMcp && /^https:\/\//i.test(baseMcp)),
      gwReady: Boolean(gwObj && gwObj.ready && gwObj.mcp_url),
      url: isRo ? baseRo : baseMcp,
      mcpUrl: baseMcp,
      roUrl: baseRo,
      isRo: isRo,
      route: route,
    };
  }

  function renderObDynamicState() {
    var band = $("onboarding-wizard-band");
    if (!band || band.style.display === "none") return;

    // Sync Step 1 Language buttons
    var curLang = (window.WebAI2PCI18n && window.WebAI2PCI18n.getLang()) || "zh";
    document.querySelectorAll("#ob-lang-group [data-ob-lang]").forEach(function (b) {
      b.classList.toggle("active", b.getAttribute("data-ob-lang") === curLang);
    });

    // Sync Step 1 Host cards & ChatGPT sub-tier
    document.querySelectorAll("#ob-host-group [data-ob-host]").forEach(function (b) {
      b.classList.toggle("active", b.getAttribute("data-ob-host") === obState.host);
    });
    if ($("ob-chatgpt-tier-wrap")) {
      $("ob-chatgpt-tier-wrap").style.display = obState.host === "chatgpt" ? "flex" : "none";
    }
    document.querySelectorAll("#ob-chatgpt-tier-wrap [data-ob-cgpt-tier]").forEach(function (b) {
      b.classList.toggle("active", b.getAttribute("data-ob-cgpt-tier") === obState.chatgptTier);
    });

    // Sync Step 1 Resource checkboxes & route summary
    if ($("ob-lbl-has-cf")) $("ob-lbl-has-cf").classList.toggle("checked", obState.hasCf);
    if ($("ob-lbl-has-vps")) $("ob-lbl-has-vps").classList.toggle("checked", obState.hasVps);
    var route = computeObRoute();
    var sumTxt = $("ob-route-summary-text");
    if (sumTxt) {
      if (obState.hasCf && obState.hasVps) {
        sumTxt.textContent = "已勾选两项资源：下一步默认优先使用更省心的「Cloudflare 3 秒固定网关」（443 WSS TLS + 256-bit 隧道密钥 + API 令牌即刻销毁），也可一键切到自有服务器（Caddy TLS 1.3 自有终结）。";
      } else if (obState.hasCf) {
        sumTxt.textContent = "已选 Cloudflare 账号：下一步将引导你 3 秒自动部署终身固定网址（*.workers.dev，443 WSS TLS + 256-bit 隧道密钥 + API 令牌即刻销毁）。";
      } else if (obState.hasVps) {
        sumTxt.textContent = "已选自有云服务器 / 域名：下一步将引导你一键部署 24h 主站（Caddy TLS 1.3 自有终结 + 256-bit WSS / SSHv2）或绑定自有 HTTPS 域名。";
      } else {
        sumTxt.textContent = "未勾选额外资源：默认调用系统内置 OpenSSH 免登录直连（本机 Ed25519 密钥 + SSHv2 / HTTPS 加密），零注册直接生成固定连接网址。";
      }
    }

    // Step 2: Dual route switcher & setup boxes
    if ($("ob-dual-route-bar")) {
      $("ob-dual-route-bar").style.display = obState.hasCf && obState.hasVps ? "flex" : "none";
    }
    document.querySelectorAll("#ob-dual-route-bar [data-ob-route]").forEach(function (b) {
      b.classList.toggle("active", b.getAttribute("data-ob-route") === route);
    });
    if ($("ob-gw-box-cloudflare")) {
      $("ob-gw-box-cloudflare").style.display = route === "cloudflare" ? "block" : "none";
    }
    if ($("ob-gw-box-vps")) {
      $("ob-gw-box-vps").style.display = route === "self_hosted" ? "block" : "none";
    }
    if ($("ob-vps-ip-row")) $("ob-vps-ip-row").style.display = obState.vpsSubmode === "vps" ? "flex" : "none";
    if ($("ob-vps-domain-row")) $("ob-vps-domain-row").style.display = obState.vpsSubmode === "domain" ? "flex" : "none";
    document.querySelectorAll("[data-ob-vps-mode]").forEach(function (b) {
      b.classList.toggle("active", b.getAttribute("data-ob-vps-mode") === obState.vpsSubmode);
    });

    // Sync Cloudflare prefilled template link if available
    var conn = (state && state.connection) || {};
    var cfTpl = conn.cloudflare_token_template_url || state.cloudflare_token_template_url || "";
    if (cfTpl && $("ob-open-cf-tpl-btn")) {
      $("ob-open-cf-tpl-btn").href = cfTpl;
    }

    // Step 2: URL & Host action buttons
    var tInfo = getObTargetUrl();
    if ($("ob-url-badge")) {
      $("ob-url-badge").textContent =
        obState.host === "chatgpt"
          ? tInfo.isRo
            ? "ChatGPT Read-Only"
            : "ChatGPT MCP"
          : "Gemini MCP";
    }
    if ($("ob-target-url-box")) {
      $("ob-target-url-box").textContent = tInfo.ready
        ? tInfo.url
        : route === "cloudflare" && !tInfo.gwReady
        ? "请先完成上方 Cloudflare 3 秒部署以生成固定网址…"
        : route === "self_hosted" && !tInfo.gwReady
        ? "请先完成上方云服务器或固定域名配置…"
        : "正在建立加密连接通道…";
    }
    var mainBtn = $("ob-copy-and-open-btn");
    if (mainBtn) {
      mainBtn.disabled = !tInfo.ready;
      mainBtn.textContent =
        obState.host === "chatgpt" ? "复制地址并打开 ChatGPT 插件页" : "复制地址并打开 Gemini 连接器";
    }
    if ($("ob-only-copy-url-btn")) {
      $("ob-only-copy-url-btn").disabled = !tInfo.ready;
    }
    if ($("ob-steps-gemini")) $("ob-steps-gemini").style.display = obState.host === "gemini" ? "flex" : "none";
    if ($("ob-steps-chatgpt")) $("ob-steps-chatgpt").style.display = obState.host === "chatgpt" ? "flex" : "none";

    var dynCode = conn.dynamic_pair_code || state.dynamic_pair_code || "------";
    if ($("ob-pair-code-inline")) $("ob-pair-code-inline").textContent = dynCode;

    var sessArr = conn.authorized_sessions || state.authorized_sessions || [];
    var sessCnt = typeof conn.authorized_sessions_count === "number" ? conn.authorized_sessions_count : sessArr.length;
    var stBox = $("ob-live-conn-status");
    var stTxt = $("ob-conn-status-text");
    if (stBox && stTxt) {
      if (sessCnt >= 1) {
        stBox.classList.add("connected");
        stTxt.textContent = "已检测到网页端授权成功（已连 " + sessCnt + " 个会话）！请继续第 3 步发送首句测试词。";
      } else {
        stBox.classList.remove("connected");
        stTxt.textContent = "正在等待网页端完成授权连接（点完允许后此处会自动变绿打勾）…";
      }
    }

    // Step 3: Primary workspace & wake prompt
    var ws = (state && state.workspaces) || {};
    var pri = ws.primary || (ws.roots && ws.roots[0]) || "";
    if ($("ob-primary-ws-box")) $("ob-primary-ws-box").textContent = pri || "(默认工作区)";
    var pfx = typeof getEffectiveToolPrefix === "function" ? getEffectiveToolPrefix() : "pc";
    var wakeStr =
      obState.host === "chatgpt"
        ? "@WebAI2PC 请调用 " + pfx + "_get_status 查看我的电脑状态与工作目录"
        : buildWakeTestPrompt();
    if ($("ob-wake-preview-code")) $("ob-wake-preview-code").textContent = wakeStr;

    if (window.WebAI2PCI18n && window.WebAI2PCI18n.getLang() === "en") {
      window.WebAI2PCI18n.apply("en");
    }
  }

  function syncOnboardingWizard(doc) {
    var band = $("onboarding-wizard-band");
    if (!band) return;
    var conn = (doc && doc.connection) || doc || {};
    var sessArr = conn.authorized_sessions || (doc && doc.authorized_sessions) || [];
    var sessCnt =
      typeof conn.authorized_sessions_count === "number"
        ? conn.authorized_sessions_count
        : typeof (doc && doc.authorized_sessions_count) === "number"
        ? doc.authorized_sessions_count
        : sessArr.length;
    var rec = (doc && doc.recovery) || (state && state.recovery) || {};
    var auditCnt = Array.isArray(rec.audit_events) ? rec.audit_events.length : 0;

    // Auto-show when 0 sessions (true first-time setup) and not dismissed, OR when manually opened
    var shouldShow = obState.manualOpen || (!isOnboardingDismissed() && sessCnt <= 0);
    // Keep open if already visible and user just connected their 1st session (advance to Step 3!)
    if (band.style.display !== "none" && !isOnboardingDismissed()) {
      shouldShow = true;
      if (obState.prevSessions === 0 && sessCnt >= 1 && obState.step === 2) {
        setObStep(3);
        showToast("已检测到网页端授权成功！请复制第 3 步首句测试词发送验证。", false);
      }
      // Auto-advance to Step 4 (Live 3D Demos) once first tool call arrives while on Step 3
      if (sessCnt >= 1 && auditCnt >= 1 && !obState.manualOpen && obState.step === 3) {
        setObStep(4);
        showToast("首句调用已跑通！现在可以直接选一个下面的一句话案例体验。", false);
        obState.prevSessions = sessCnt;
        return;
      }
    }
    obState.prevSessions = sessCnt;
    band.style.display = shouldShow ? "block" : "none";
    if (shouldShow) {
      renderObDynamicState();
    }
  }

  var OB_SHOWCASE_PROMPTS = {
    blackhole: "在当前工作区写一个纯离线单文件 blackhole_studio.html，用原生 WebGL2（GLSL 300）实时光线步进渲染带发光吸积盘和引力透镜效果的黑洞；加上左键旋转、滚轮缩放，右侧做一个简洁的中文半透明控制面板，支持切换「俯瞰盘面 / 掠过视界 / 穿越光环」三组电影机位，以及黑洞质量、自旋、吸积盘亮度、时间流速四个实时滑块，写完后本地启动检查确认零报错。",
    holo: "在当前工作区写一个纯离线单文件 gemini_holo_cards.html，用原生 WebGL2 和程序化 Canvas 做出 3 张带薄膜干涉金属反光的 3D 全息典藏卡，主题为 Gemini 4 的 06 C（Carbon）、01 H（Hydrogen）、10 Ne（Neon）；支持鼠标悬停弹簧 3D 倾角与视差、点击 180° 翻转看背面、顶部切换「一字排开 / 聚焦单卡」以及三档色温环境光，不依赖任何外部图片和 CDN，写完后帮我本地打开验收。",
    canyon: "在当前工作区新建 neon_canyon 目录，按多文件工程结构（index.html、styles.css、terrain.js、audio.js、game.js）写一个纯离线原生 WebGL2 3D 低空飞行游戏「霓虹峡谷低空飞行」：合成波落日与霓虹线框峡谷、穿越空中能量光环触发加速与连击、躲避赤红能量柱与峡谷绝壁，用 Web Audio 实时合成引擎和穿环音效，支持 WASD/方向键与鼠标自动切换、顶部显示得分/最高分/连击/空速/FPS 与暂停重开按钮，写完后本地运行验收无控制台报错。"
  };

  function bindOnboardingEvents() {
    var band = $("onboarding-wizard-band");
    if (!band) return;

    // Auto-preselect browser language if user hasn't explicitly chosen yet
    try {
      if (!localStorage.getItem("webai2pc_lang") && /^en\b/i.test(navigator.language || "")) {
        if (window.WebAI2PCI18n) window.WebAI2PCI18n.setLang("en");
      }
    } catch (e) {}

    // Stepper tab clicks
    [1, 2, 3, 4].forEach(function (n) {
      var tab = $("ob-step-tab-" + n);
      if (tab) {
        tab.addEventListener("click", function () {
          setObStep(n);
        });
      }
    });

    // Open / Dismiss wizard
    if ($("open-onboarding-btn")) {
      $("open-onboarding-btn").addEventListener("click", function () {
        obState.manualOpen = true;
        band.style.display = "block";
        setObStep(1);
        window.scrollTo({ top: 0, behavior: "smooth" });
      });
    }
    function closeWizard() {
      obState.manualOpen = false;
      setOnboardingDismissed(true);
      band.style.display = "none";
    }
    if ($("ob-dismiss-btn")) $("ob-dismiss-btn").addEventListener("click", closeWizard);
    if ($("ob-skip-to-console-btn")) $("ob-skip-to-console-btn").addEventListener("click", closeWizard);
    if ($("ob-finish-btn")) $("ob-finish-btn").addEventListener("click", closeWizard);

    // Copy AI Setup Guide prompt
    if ($("ob-copy-ai-guide-btn")) {
      $("ob-copy-ai-guide-btn").addEventListener("click", function () {
        var isEn = window.WebAI2PCI18n && window.WebAI2PCI18n.getLang() === "en";
        var guidePrompt = isEn
          ? "Please act as my WebAI2PC setup wizard. Read https://raw.githubusercontent.com/cosmosomo/WebAI2PC/main/docs/en/AI_SETUP_GUIDE.md and guide me step-by-step (one short step at a time) to connect my local PC console (http://127.0.0.1:8096/) to Web Gemini or Web ChatGPT."
          : "请做我的 WebAI2PC 配置向导，先读取官方配置教程 https://raw.githubusercontent.com/cosmosomo/WebAI2PC/main/docs/AI_SETUP_GUIDE.md ，每次只教当前这一步，带我把本地控制台（http://127.0.0.1:8096/）连上网页版 Gemini 或 ChatGPT。";
        copyText(guidePrompt, $("ob-copy-ai-guide-btn"));
        showToast(isEn ? "Copied AI setup guide prompt!" : "已复制 AI 陪配提示词，直接粘贴给任意网页 AI 即可", false);
      });
    }

    // Step 1: Language choice
    document.querySelectorAll("#ob-lang-group [data-ob-lang]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var l = btn.getAttribute("data-ob-lang") === "en" ? "en" : "zh";
        if (window.WebAI2PCI18n) window.WebAI2PCI18n.setLang(l);
        renderObDynamicState();
      });
    });

    // Step 1: Host choice + sync main workbench host switcher
    document.querySelectorAll("#ob-host-group [data-ob-host]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var h = btn.getAttribute("data-ob-host") === "chatgpt" ? "chatgpt" : "gemini";
        obState.host = h;
        if (typeof switchHostScene === "function") switchHostScene(h);
        renderObDynamicState();
      });
    });
    document.querySelectorAll("#ob-chatgpt-tier-wrap [data-ob-cgpt-tier]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        obState.chatgptTier = btn.getAttribute("data-ob-cgpt-tier") === "personal" ? "personal" : "workspace";
        renderObDynamicState();
      });
    });

    // Step 1: Resource checkboxes
    if ($("ob-chk-has-cf")) {
      $("ob-chk-has-cf").addEventListener("change", function () {
        obState.hasCf = Boolean($("ob-chk-has-cf").checked);
        if (obState.hasCf) obState.activeRoute = "cloudflare";
        renderObDynamicState();
      });
    }
    if ($("ob-chk-has-vps")) {
      $("ob-chk-has-vps").addEventListener("change", function () {
        obState.hasVps = Boolean($("ob-chk-has-vps").checked);
        if (obState.hasVps && !obState.hasCf) obState.activeRoute = "self_hosted";
        renderObDynamicState();
      });
    }

    // Step navigation buttons
    if ($("ob-next-to-2-btn")) {
      $("ob-next-to-2-btn").addEventListener("click", function () {
        var route = computeObRoute();
        if (route === "instant" && $("activate-card1-btn")) {
          var conn = (state && state.connection) || {};
          if (!conn.public_https_ready) $("activate-card1-btn").click();
        }
        setObStep(2);
      });
    }
    if ($("ob-back-to-1-btn")) {
      $("ob-back-to-1-btn").addEventListener("click", function () { setObStep(1); });
    }
    if ($("ob-next-to-3-btn")) {
      $("ob-next-to-3-btn").addEventListener("click", function () { setObStep(3); });
    }
    if ($("ob-back-to-2-btn")) {
      $("ob-back-to-2-btn").addEventListener("click", function () { setObStep(2); });
    }
    if ($("ob-next-to-4-btn")) {
      $("ob-next-to-4-btn").addEventListener("click", function () { setObStep(4); });
    }
    if ($("ob-back-to-3-btn")) {
      $("ob-back-to-3-btn").addEventListener("click", function () { setObStep(3); });
    }

    // Step 4: One-shot 3D showcase cards copy & preview toggle
    document.querySelectorAll("[data-ob-copy-showcase]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var key = btn.getAttribute("data-ob-copy-showcase");
        var promptTxt = OB_SHOWCASE_PROMPTS[key];
        if (!promptTxt) return;
        copyText(promptTxt, btn);
        var isEn = window.WebAI2PCI18n && window.WebAI2PCI18n.getLang() === "en";
        showToast(
          isEn
            ? "Prompt copied! Type @ in chat to select your connector, then paste and send."
            : "已复制提示词！在对话框输入 @ 选中你的连接器，粘贴发送即可体验。",
          false
        );
      });
    });
    document.querySelectorAll("[data-ob-toggle-showcase]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var key = btn.getAttribute("data-ob-toggle-showcase");
        var pre = document.querySelector('[data-ob-showcase-preview="' + key + '"]');
        if (!pre) return;
        var isHidden = pre.hasAttribute("hidden");
        var isEn = window.WebAI2PCI18n && window.WebAI2PCI18n.getLang() === "en";
        if (isHidden) {
          pre.textContent = OB_SHOWCASE_PROMPTS[key] || "";
          pre.removeAttribute("hidden");
          btn.setAttribute("aria-expanded", "true");
          btn.textContent = isEn ? "Hide Prompt" : "收起全文";
        } else {
          pre.setAttribute("hidden", "");
          btn.setAttribute("aria-expanded", "false");
          btn.textContent = isEn ? "View Prompt" : "查看全文";
        }
      });
    });

    // Step 2: Dual route switcher & VPS submode
    document.querySelectorAll("#ob-dual-route-bar [data-ob-route]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        obState.activeRoute = btn.getAttribute("data-ob-route") === "self_hosted" ? "self_hosted" : "cloudflare";
        renderObDynamicState();
      });
    });
    document.querySelectorAll("[data-ob-vps-mode]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        obState.vpsSubmode = btn.getAttribute("data-ob-vps-mode") === "domain" ? "domain" : "vps";
        renderObDynamicState();
      });
    });

    // Step 2: Delegate Cloudflare deploy to existing #deploy-cf-workers-btn
    if ($("ob-deploy-cf-btn")) {
      $("ob-deploy-cf-btn").addEventListener("click", function () {
        var tok = $("ob-cf-token-input") ? $("ob-cf-token-input").value.trim() : "";
        var dom = $("ob-cf-domain-input") ? $("ob-cf-domain-input").value.trim() : "";
        if ($("cf-api-token-input")) $("cf-api-token-input").value = tok;
        if ($("cf-custom-domain-input")) $("cf-custom-domain-input").value = dom;
        if ($("deploy-cf-workers-btn")) $("deploy-cf-workers-btn").click();
        if ($("ob-cf-token-input")) $("ob-cf-token-input").value = "";
      });
    }

    // Step 2: Delegate VPS / Custom Domain to existing settings handlers
    if ($("ob-deploy-vps-btn")) {
      $("ob-deploy-vps-btn").addEventListener("click", function () {
        var ip = $("ob-vps-ip-input") ? $("ob-vps-ip-input").value.trim() : "";
        var pw = $("ob-vps-pw-input") ? $("ob-vps-pw-input").value : "";
        if ($("vps-prov-host-input")) $("vps-prov-host-input").value = ip;
        if ($("vps-prov-pw-input")) $("vps-prov-pw-input").value = pw;
        if (!pw && $("chk-vps-use-ssh-key")) $("chk-vps-use-ssh-key").checked = true;
        if ($("vps-provision-btn")) $("vps-provision-btn").click();
      });
    }
    if ($("ob-save-domain-btn")) {
      $("ob-save-domain-btn").addEventListener("click", function () {
        var u = $("ob-custom-domain-url-input") ? $("ob-custom-domain-url-input").value.trim() : "";
        if (!u) return showToast("请输入完整的 HTTPS 域名地址", true);
        apiFetch("/api/studio/connection", {
          method: "POST",
          body: {
            action: "save_gateway_config",
            gateway_id: "self_hosted",
            submode: "custom",
            public_url: u,
            enabled: true,
          },
        }).then(function (d) {
          if (!d.ok) return showToast(d.error || "保存域名失败", true);
          renderAll(d);
          showToast("自有固定域名网关已启用", false);
        });
      });
    }

    // Step 2: Copy & Open Host
    if ($("ob-copy-and-open-btn")) {
      $("ob-copy-and-open-btn").addEventListener("click", function () {
        var tInfo = getObTargetUrl();
        if (!tInfo.ready) return;
        copyText(tInfo.url, $("ob-copy-and-open-btn"));
        if (obState.host === "chatgpt") {
          window.open("https://chatgpt.com/plugins", "_blank", "noopener,noreferrer");
        } else {
          probeAndOpenGeminiConnectors();
        }
      });
    }
    if ($("ob-only-copy-url-btn")) {
      $("ob-only-copy-url-btn").addEventListener("click", function () {
        var tInfo = getObTargetUrl();
        if (tInfo.ready) copyText(tInfo.url, $("ob-only-copy-url-btn"));
      });
    }
    if ($("ob-target-url-box")) {
      $("ob-target-url-box").addEventListener("click", function () {
        var tInfo = getObTargetUrl();
        if (tInfo.ready) copyText(tInfo.url, $("ob-only-copy-url-btn"));
      });
    }
    if ($("ob-copy-cgpt-work-btn")) {
      $("ob-copy-cgpt-work-btn").addEventListener("click", function () {
        var tInfo = getObTargetUrl();
        var btnTarget = tInfo.isRo ? $("copy-chatgpt-assist-ro-btn") : $("copy-chatgpt-assist-full-btn");
        if (btnTarget && !btnTarget.disabled) {
          btnTarget.click();
        } else if (tInfo.ready) {
          copyText(tInfo.url, $("ob-copy-cgpt-work-btn"));
        }
      });
    }

    // Step 3: Pick folder & Copy wake / skill
    if ($("ob-pick-folder-btn")) {
      $("ob-pick-folder-btn").addEventListener("click", function () {
        if ($("pick-local-folder-btn")) $("pick-local-folder-btn").click();
      });
    }
    if ($("ob-copy-wake-btn")) {
      $("ob-copy-wake-btn").addEventListener("click", function () {
        var codeEl = $("ob-wake-preview-code");
        if (codeEl) {
          copyText(codeEl.textContent, $("ob-copy-wake-btn"));
          showToast("已复制首句测试词，去网页聊天框发送即可验证", false);
        }
      });
    }
    if ($("ob-copy-skill-btn")) {
      $("ob-copy-skill-btn").addEventListener("click", function () {
        var targetSkillBtn = obState.host === "chatgpt" ? $("copy-chatgpt-skill-btn") : $("copy-wake-skill-btn");
        if (targetSkillBtn) targetSkillBtn.click();
      });
    }
  }

  var CONN_CHECK_ZH_TO_EN = {
    "检查连通性": "Check Connectivity",
    "检测中…": "Checking…",
    "重新检测": "Re-check",
    "复制脱敏诊断": "Copy Redacted Report",
    "检活测速": "Probe Speed",
    "测速中…": "Probing…",
    "关闭诊断面板": "Close Diagnostics",
    "正在并发实测本机服务、代理、公网网关与协议握手…": "Probing local service, system proxy, public gateways, and OAuth/MCP handshake…",
    "正在并发实测通道连通性与延迟…": "Probing gateway connectivity and latency…",
    "全部畅通": "All Healthy",
    "部分需注意": "Attention Needed",
    "发现阻断项": "Blocker Detected",
    "正常": "OK",
    "注意": "Warn",
    "阻断": "Error",
    "未开启": "Disabled",
    "跳过": "Skipped",
    "1. 本机回环服务与代理排除": "1. Local Loopback & NO_PROXY",
    "2. 本机系统代理与通道组件": "2. System Proxy & Components",
    "3. 公网 HTTPS 网关可达": "3. Public HTTPS Gateway /healthz",
    "4. 云端 AI 协议握手": "4. Cloud AI Protocol Handshake",
    "5. 当前浏览器授权页直达": "5. Browser Direct Consent Reachability"
  };

  function registerConnCheckI18n() {
    if (window.WebAI2PCI18n && window.WebAI2PCI18n.ZH_TO_EN) {
      try {
        Object.assign(window.WebAI2PCI18n.ZH_TO_EN, CONN_CHECK_ZH_TO_EN);
        if (window.WebAI2PCI18n.getLang && window.WebAI2PCI18n.getLang() === "en") {
          window.WebAI2PCI18n.apply("en");
        }
      } catch (e) {}
    }
  }

  function isUiLangEn() {
    if (window.WebAI2PCI18n && typeof window.WebAI2PCI18n.getLang === "function") {
      return window.WebAI2PCI18n.getLang() === "en";
    }
    return document.documentElement.getAttribute("data-lang") === "en";
  }

  var lastWorkbenchConnGwId = "";
  var lastSettingsConnGwId = "";
  var connCheckResultsBySurface = { workbench: null, settings: null };
  var cardProbeCache = {};
  var connCheckReqSeq = 0;
  var langObserverBound = false;

  function resolveBrowserProbeOrigin(gatewayId) {
    var conn = (state && state.connection) || {};
    var gws = conn.gateways || state.gateways || {};
    var rawCand = "";
    if (gatewayId && gws[gatewayId]) {
      var sl = gws[gatewayId];
      if (sl.enabled) {
        rawCand = sl.mcp_url || sl.public_url || sl.configured_url || "";
      }
    } else {
      var effTop = resolveEffectiveTopView(conn);
      rawCand = effTop.mcp_url || "";
      if (!rawCand && effTop.enabledIds && effTop.enabledIds.length > 0) {
        for (var i = 0; i < effTop.enabledIds.length; i++) {
          var gItem = gws[effTop.enabledIds[i]];
          if (gItem && gItem.enabled && (gItem.mcp_url || gItem.public_url || gItem.configured_url)) {
            rawCand = gItem.mcp_url || gItem.public_url || gItem.configured_url;
            break;
          }
        }
      }
    }
    var s = String(rawCand || "").trim();
    if (!s || s.indexOf("https://") !== 0) return "";
    return s.replace(/\/mcp(?:\/readonly)?\/?$/, "").replace(/\/+$/, "");
  }

  function probeBrowserGatewayDirect(originUrl) {
    if (!originUrl) {
      return Promise.resolve({
        attempted: false,
        status: "skipped",
        latency_ms: null,
        message_zh: "等待公网 HTTPS 网关开启并就绪后检测浏览器直达",
        message_en: "Waiting for an active public HTTPS gateway before testing browser direct reachability."
      });
    }
    var nowFn = function () {
      return typeof performance !== "undefined" && performance.now ? performance.now() : Date.now();
    };
    var t0 = nowFn();
    var ctrl1 = typeof AbortController !== "undefined" ? new AbortController() : null;
    var timer1 = setTimeout(function () {
      if (ctrl1) ctrl1.abort();
    }, 2800);

    return fetch(originUrl + "/healthz", {
      method: "GET",
      mode: "cors",
      cache: "no-store",
      credentials: "omit",
      signal: ctrl1 ? ctrl1.signal : undefined
    })
      .then(function (resp) {
        clearTimeout(timer1);
        var ms = Math.max(1, Math.round(nowFn() - t0));
        if (resp && resp.ok) {
          return {
            attempted: true,
            status: "ok",
            latency_ms: ms,
            message_zh: "浏览器直达正常 · " + ms + "ms",
            message_en: "Browser direct reachability OK · " + ms + "ms"
          };
        }
        var sc = resp ? resp.status : 0;
        return {
          attempted: true,
          status: "warn",
          latency_ms: ms,
          message_zh: "浏览器请求公网 /healthz 返回 HTTP " + sc + "，首次打开授权页若遇拦截可使用 6 位动态配对码",
          message_en: "Browser request to /healthz returned HTTP " + sc + "; use the 6-digit pairing code if consent is blocked."
        };
      })
      .catch(function () {
        clearTimeout(timer1);
        var ctrl2 = typeof AbortController !== "undefined" ? new AbortController() : null;
        var timer2 = setTimeout(function () {
          if (ctrl2) ctrl2.abort();
        }, 1600);
        return fetch(originUrl + "/healthz", {
          method: "GET",
          mode: "no-cors",
          cache: "no-store",
          credentials: "omit",
          signal: ctrl2 ? ctrl2.signal : undefined
        })
          .then(function () {
            clearTimeout(timer2);
            var ms2 = Math.max(1, Math.round(nowFn() - t0));
            return {
              attempted: true,
              status: "ok",
              latency_ms: ms2,
              message_zh: "浏览器直达正常 · " + ms2 + "ms",
              message_en: "Browser direct reachability OK · " + ms2 + "ms"
            };
          })
          .catch(function () {
            clearTimeout(timer2);
            return {
              attempted: true,
              status: "unreachable",
              latency_ms: null,
              message_zh: "",
              message_en: ""
            };
          });
      });
  }

  function formatStatusBadgeMeta(st, isEn) {
    var norm = String(st || "skipped").toLowerCase();
    if (norm === "ok" || norm === "ready") {
      return { cls: "is-ok", text: isEn ? "OK" : "正常" };
    }
    if (norm === "warn" || norm === "connecting") {
      return { cls: "is-warn", text: norm === "connecting" ? (isEn ? "Connecting" : "连接中") : (isEn ? "Warn" : "注意") };
    }
    if (norm === "error") {
      return { cls: "is-error", text: isEn ? "Error" : "阻断" };
    }
    if (norm === "disabled") {
      return { cls: "is-skipped", text: isEn ? "Disabled" : "未开启" };
    }
    return { cls: "is-skipped", text: isEn ? "Skipped" : "跳过" };
  }

  function finalizeBrowserStepWithBackend(browserRaw, backendDoc) {
    if (!browserRaw || browserRaw.status !== "unreachable") {
      return browserRaw;
    }
    var gws = (backendDoc && backendDoc.gateways) || [];
    var backendGwOk = gws.some(function (g) {
      return g && g.enabled && g.status === "ok";
    });
    if (backendGwOk) {
      return {
        attempted: true,
        status: "warn",
        latency_ms: null,
        message_zh: "后端已连通，但当前浏览器无法直达该网关域名（代理分流未覆盖该域名），建议首次点授权临时切全局 10 秒或用 6 位配对码",
        message_en: "Backend is connected, but this browser cannot reach the gateway domain directly (proxy routing rules do not cover it). Switch proxy to Global for 10s during first authorization or use the 6-digit pairing code."
      };
    }
    return {
      attempted: true,
      status: "error",
      latency_ms: null,
      message_zh: "当前浏览器与本机后端均无法连通该公网网关地址",
      message_en: "Neither this browser nor the local backend could reach the public gateway URL."
    };
  }

  function renderConnCheckSurface(surfaceName) {
    var bundle = connCheckResultsBySurface[surfaceName];
    if (!bundle || !bundle.backend) return;
    var isSettings = surfaceName === "settings";
    var panel = $(isSettings ? "settings-conn-check-panel" : "conn-check-panel");
    var badge = $(isSettings ? "settings-conn-check-badge" : "conn-check-badge");
    var sumEl = $(isSettings ? "settings-conn-check-summary" : "conn-check-summary");
    var stepsEl = $(isSettings ? "settings-conn-check-steps" : "conn-check-steps");
    var copyBtn = $(isSettings ? "settings-copy-conn-diag-btn" : "copy-conn-diag-btn");
    if (!panel || !badge || !sumEl || !stepsEl) return;

    var isEn = isUiLangEn();
    var doc = bundle.backend;
    var brStep = bundle.browser;

    var overall = String(doc.overall_status || "warn").toLowerCase();
    var sumTxt = isEn ? (doc.summary_en || doc.summary || "") : (doc.summary_zh || doc.summary || "");
    if (overall === "ok" && brStep && brStep.status === "warn") {
      overall = "warn";
      sumTxt = isEn ? brStep.message_en : brStep.message_zh;
    }

    var dur = typeof doc.duration_ms === "number" ? Math.round(doc.duration_ms) + "ms" : "";
    if (overall === "ok") {
      badge.className = "conn-check-pill is-ok";
      badge.textContent = (isEn ? "All Healthy" : "全部畅通") + (dur ? " · " + dur : "");
    } else if (overall === "error") {
      badge.className = "conn-check-pill is-error";
      badge.textContent = (isEn ? "Blocker Detected" : "发现阻断项") + (dur ? " · " + dur : "");
    } else {
      badge.className = "conn-check-pill is-warn";
      badge.textContent = (isEn ? "Attention Needed" : "部分需注意") + (dur ? " · " + dur : "");
    }
    sumEl.textContent = sumTxt;
    if (copyBtn) copyBtn.disabled = false;

    stepsEl.innerHTML = "";

    function appendStepRow(titleStr, stVal, mainDetailStr, subItems) {
      var row = document.createElement("div");
      row.className = "conn-step-row";
      var main = document.createElement("div");
      main.className = "conn-step-main";

      var tLine = document.createElement("div");
      tLine.className = "conn-step-title-line";
      var tSpan = document.createElement("span");
      tSpan.className = "conn-step-title";
      tSpan.textContent = titleStr;
      tLine.appendChild(tSpan);
      main.appendChild(tLine);

      if (mainDetailStr) {
        var dDiv = document.createElement("div");
        dDiv.className = "conn-step-detail";
        dDiv.textContent = mainDetailStr;
        main.appendChild(dDiv);
      }

      if (subItems && subItems.length > 0) {
        var subWrap = document.createElement("div");
        subWrap.className = "conn-step-sublist";
        subItems.forEach(function (it) {
          var sRow = document.createElement("div");
          sRow.className = "conn-step-subitem";
          var bMeta = formatStatusBadgeMeta(it.status, isEn);
          var tag = document.createElement("span");
          tag.className = "conn-check-pill " + bMeta.cls;
          tag.style.marginRight = "6px";
          tag.style.padding = "1px 7px";
          tag.style.fontSize = "11px";
          tag.textContent = bMeta.text;
          sRow.appendChild(tag);
          if (it.label) {
            var lbl = document.createElement("strong");
            lbl.textContent = it.label + " ";
            sRow.appendChild(lbl);
          }
          if (it.masked_url) {
            var uCode = document.createElement("span");
            uCode.className = "conn-step-url";
            uCode.textContent = "(" + it.masked_url + ") ";
            sRow.appendChild(uCode);
          }
          var msgNode = document.createTextNode(it.text || "");
          sRow.appendChild(msgNode);
          subWrap.appendChild(sRow);
        });
        main.appendChild(subWrap);
      }

      var pillMeta = formatStatusBadgeMeta(stVal, isEn);
      var rightPill = document.createElement("span");
      rightPill.className = "conn-check-pill " + pillMeta.cls;
      rightPill.textContent = pillMeta.text;

      row.appendChild(main);
      row.appendChild(rightPill);
      stepsEl.appendChild(row);
    }

    var ls = doc.local_service || {};
    appendStepRow(
      isEn ? "1. Local Loopback & NO_PROXY" : "1. 本机回环服务与代理排除",
      ls.status || "error",
      isEn ? (ls.message_en || ls.message_zh || "") : (ls.message_zh || "")
    );

    var pd = doc.proxy_and_deps || {};
    appendStepRow(
      isEn ? "2. System Proxy & Components" : "2. 本机系统代理与通道组件",
      pd.status || "ok",
      isEn ? (pd.message_en || pd.message_zh || "") : (pd.message_zh || "")
    );

    var gwArr = doc.gateways || [];
    var enGws = gwArr.filter(function (g) { return Boolean(g && g.enabled); });
    var gwOverall = "warn";
    if (enGws.some(function (g) { return g.status === "ok"; })) {
      gwOverall = enGws.some(function (g) { return g.status !== "ok"; }) ? "warn" : "ok";
    } else if (enGws.some(function (g) { return g.status === "error"; })) {
      gwOverall = "error";
    }
    var gwSubs = gwArr.map(function (g) {
      return {
        status: g.status,
        label: isEn ? (g.label_en || g.gateway_id) : (g.label_zh || g.gateway_id),
        masked_url: g.masked_url || "",
        text: isEn ? (g.message_en || g.message_zh || "") : (g.message_zh || "")
      };
    });
    appendStepRow(
      isEn ? "3. Public HTTPS Gateway /healthz" : "3. 公网 HTTPS 网关可达",
      gwOverall,
      "",
      gwSubs
    );

    var mp = doc.mcp_protocol || {};
    var mpSubs = (mp.items || [])
      .filter(function (it) { return it && it.status !== "skipped"; })
      .map(function (it) {
        return {
          status: it.status,
          label: it.gateway_id || "",
          masked_url: it.masked_url || "",
          text: isEn ? (it.message_en || it.message_zh || "") : (it.message_zh || "")
        };
      });
    appendStepRow(
      isEn ? "4. Cloud AI Protocol Handshake" : "4. 云端 AI 协议握手",
      mp.status || "warn",
      mpSubs.length > 0 ? "" : (isEn ? (mp.message_en || mp.message_zh || "") : (mp.message_zh || "")),
      mpSubs
    );

    if (brStep) {
      appendStepRow(
        isEn ? "5. Browser Direct Consent Reachability" : "5. 当前浏览器授权页直达",
        brStep.status || "skipped",
        isEn ? (brStep.message_en || brStep.message_zh || "") : (brStep.message_zh || "")
      );
    }

    panel.style.display = "block";
  }

  function renderCardProbeInline(gid) {
    var box = $("gw-probe-box-" + gid);
    var bundle = cardProbeCache[gid];
    if (!box || !bundle || !bundle.backend) return;
    var isEn = isUiLangEn();
    var doc = bundle.backend;
    var br = bundle.browser;
    var gwItem = ((doc.gateways || [])[0]) || {};
    var mpItem = (((doc.mcp_protocol || {}).items || [])[0]) || {};

    box.innerHTML = "";
    var meta = formatStatusBadgeMeta(doc.overall_status, isEn);
    var pill = document.createElement("span");
    pill.className = "conn-check-pill " + meta.cls;
    pill.style.marginRight = "8px";
    var durTxt = typeof doc.duration_ms === "number" ? " · " + Math.round(doc.duration_ms) + "ms" : "";
    pill.textContent = meta.text + durTxt;
    box.appendChild(pill);

    var parts = [];
    var gwMsg = isEn ? (gwItem.message_en || gwItem.message_zh) : gwItem.message_zh;
    if (gwMsg) parts.push(gwMsg);
    if (mpItem && mpItem.status && mpItem.status !== "skipped") {
      var mpMsg = isEn ? (mpItem.message_en || mpItem.message_zh) : mpItem.message_zh;
      if (mpMsg) parts.push(mpMsg);
    }
    if (br && br.status && br.status !== "skipped") {
      var brMsg = isEn ? (br.message_en || br.message_zh) : br.message_zh;
      if (brMsg) parts.push(brMsg);
    }
    box.appendChild(document.createTextNode(parts.join(" ｜ ")));
    box.style.display = "block";
  }

  function copyRedactedConnDiag(surfaceName, btnEl) {
    var bundle = connCheckResultsBySurface[surfaceName];
    if (!bundle || !bundle.backend) return;
    var baseShare = String(bundle.backend.redacted_share_text || "").trim();
    if (!baseShare) return;
    var br = bundle.browser;
    var fullShare = baseShare;
    if (br && br.status) {
      fullShare += "\n5. 浏览器直达: [" + String(br.status).toUpperCase() + "] " + (br.message_zh || "");
    }
    copyText(fullShare, btnEl);
    var isEn = isUiLangEn();
    showToast(
      isEn
        ? "Copied redacted diagnostics (real URLs and local paths hidden)"
        : "已复制脱敏诊断摘要（已自动隐藏真实网址与本机路径）",
      false
    );
  }

  function runStudioConnectivityCheck(gatewayId, surfaceName, triggerBtn) {
    var targetSurface = surfaceName === "settings" ? "settings" : "workbench";
    var cleanGw = String(gatewayId || "").trim();
    if (targetSurface === "settings") {
      lastSettingsConnGwId = cleanGw;
    } else {
      lastWorkbenchConnGwId = cleanGw;
      userToggledConnDrawer = true;
      setConnDrawerOpen(true);
    }

    var isEn = isUiLangEn();
    var panel = $(targetSurface === "settings" ? "settings-conn-check-panel" : "conn-check-panel");
    var badge = $(targetSurface === "settings" ? "settings-conn-check-badge" : "conn-check-badge");
    var sumEl = $(targetSurface === "settings" ? "settings-conn-check-summary" : "conn-check-summary");
    var stepsEl = $(targetSurface === "settings" ? "settings-conn-check-steps" : "conn-check-steps");
    var copyBtn = $(targetSurface === "settings" ? "settings-copy-conn-diag-btn" : "copy-conn-diag-btn");

    if (panel) panel.style.display = "block";
    if (badge) {
      badge.className = "conn-check-pill is-checking";
      badge.textContent = isEn ? "Checking…" : "检测中…";
    }
    if (sumEl) {
      sumEl.textContent = isEn
        ? "Probing local service, system proxy, public gateways, and OAuth/MCP handshake…"
        : "正在并发实测本机服务、代理、公网网关与协议握手…";
    }
    if (stepsEl) stepsEl.innerHTML = "";
    if (copyBtn) copyBtn.disabled = true;

    var mainBtn = $(targetSurface === "settings" ? "settings-conn-check-btn" : "run-conn-check-btn");
    if (mainBtn) mainBtn.disabled = true;
    var origTrigTxt = "";
    if (triggerBtn) {
      origTrigTxt = triggerBtn.textContent;
      triggerBtn.disabled = true;
      triggerBtn.textContent = isEn ? "Probing…" : "测速中…";
    }

    var mySeq = ++connCheckReqSeq;
    var probeOrigin = resolveBrowserProbeOrigin(cleanGw);
    var reqBody = cleanGw ? { gateway_id: cleanGw } : {};

    Promise.all([
      apiFetch("/api/studio/connectivity-check", { method: "POST", body: reqBody }),
      probeBrowserGatewayDirect(probeOrigin)
    ])
      .then(function (pair) {
        if (mainBtn) mainBtn.disabled = false;
        if (triggerBtn) {
          triggerBtn.disabled = false;
          triggerBtn.textContent = isEn ? "Probe Speed" : "检活测速";
          if (origTrigTxt && !isEn) triggerBtn.textContent = origTrigTxt;
        }
        if (mySeq !== connCheckReqSeq) return;
        var backendRes = pair[0] || {};
        var browserRaw = pair[1] || null;
        if (backendRes.need_unlock || backendRes._httpStatus === 403 || backendRes._httpStatus === 400) {
          var errStr = backendRes.error || (isEn ? "Connectivity check failed." : "连通性检测请求未通过校验。");
          if (badge) {
            badge.className = "conn-check-pill is-error";
            badge.textContent = isEn ? "Error" : "阻断";
          }
          if (sumEl) sumEl.textContent = errStr;
          showToast(errStr, true);
          return;
        }
        var finalBrowser = finalizeBrowserStepWithBackend(browserRaw, backendRes);
        var bundle = { backend: backendRes, browser: finalBrowser };
        connCheckResultsBySurface[targetSurface] = bundle;
        renderConnCheckSurface(targetSurface);
        if (cleanGw) {
          cardProbeCache[cleanGw] = bundle;
          renderCardProbeInline(cleanGw);
        }
      })
      .catch(function () {
        if (mainBtn) mainBtn.disabled = false;
        if (triggerBtn) {
          triggerBtn.disabled = false;
          triggerBtn.textContent = isEn ? "Probe Speed" : "检活测速";
        }
        if (mySeq !== connCheckReqSeq) return;
        var netErr = isEn
          ? "Local Studio service did not respond. Please check if the local service is running."
          : "无法连接本地 Studio 服务，请确认后台服务正在运行。";
        if (badge) {
          badge.className = "conn-check-pill is-error";
          badge.textContent = isEn ? "Blocker Detected" : "发现阻断项";
        }
        if (sumEl) sumEl.textContent = netErr;
        showToast(netErr, true);
      });
  }

  function bindConnCheckLangObserver() {
    if (langObserverBound || typeof MutationObserver === "undefined") return;
    langObserverBound = true;
    var mo = new MutationObserver(function () {
      if (connCheckResultsBySurface.workbench) renderConnCheckSurface("workbench");
      if (connCheckResultsBySurface.settings) renderConnCheckSurface("settings");
      Object.keys(cardProbeCache).forEach(function (gid) {
        renderCardProbeInline(gid);
      });
    });
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-lang"] });
  }

  function boot() {
    registerConnCheckI18n();
    bindConnCheckLangObserver();
    initTheme();
    bindOnboardingEvents();
    var bootEl = $("studio-boot-data");
    if (bootEl && bootEl.textContent) {
      try {
        var initial = JSON.parse(bootEl.textContent);
        renderAll(initial);
      } catch (e) {}
    }
    bindEvents();
    // Honor URL hash #settings/<category> or #onboarding on initial load
    var h = String(window.location.hash || "");
    if (h.indexOf("#settings") === 0) {
      var parts = h.split("/");
      openSettings(parts[1] || "gateways");
    } else if (h === "#onboarding") {
      obState.manualOpen = true;
      if ($("onboarding-wizard-band")) $("onboarding-wizard-band").style.display = "block";
      setObStep(1);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
