(function (global) {
  "use strict";

  var STORAGE_KEYS = {
    theme: "cosmos_studio_theme",
    legacyTheme: "webai2pc_theme",
    stylePack: "webai2pc_style_pack",
    ipPack: "webai2pc_ip_pack",
    pose: "webai2pc_ip_pose"
  };

  var GEMINI_SPARKLE_PATH =
    "M11.04 19.32Q12 21.51 12 24q0-2.49.93-4.68.96-2.19 2.58-3.81t3.81-2.55Q21.51 12 24 12q-2.49 0-4.68-.93a12.3 12.3 0 0 1-3.81-2.58 12.3 12.3 0 0 1-2.58-3.81Q12 2.49 12 0q0 2.49-.96 4.68-.93 2.19-2.55 3.81a12.3 12.3 0 0 1-3.81 2.58Q2.49 12 0 12q2.49 0 4.68.96 2.19.93 3.81 2.55t2.55 3.81";

  var OPENAI_BLOSSOM_PATH =
    "M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.051 6.051 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 .7806 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.071 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.364 15.1192 7.2a.0757.0757 0 0 1 .071 0l4.8303 2.7913a4.4944 4.4944 0 0 1-.6765 8.1042v-5.6772a.79.79 0 0 0-.407-.667zm2.0107-3.0231l-.142-.0852-4.7735-2.7818a.7759.7759 0 0 0-.7854 0L9.409 9.2297V6.8974a.0662.0662 0 0 1 .0284-.0615l4.8303-2.7866a4.4992 4.4992 0 0 1 6.6802 4.66zM8.3065 12.863l-2.02-1.1638a.0804.0804 0 0 1-.038-.0567V6.0742a4.4992 4.4992 0 0 1 7.3757-3.4537l-.142.0805L8.704 5.459a.7948.7948 0 0 0-.3927.6813zm1.0976-2.3654l2.602-1.4998 2.6069 1.4998v2.9994l-2.5974 1.4997-2.6067-1.4997Z";

  var STYLE_PACKS = [
    {
      id: "warm-paper",
      name: "暖纸松林",
      desc: "温润档案纸底配松林绿与暖琥珀桥接",
      swatches: ["#F7F6F2", "#1F6E58", "#E9A820"]
    },
    {
      id: "obsidian-emerald",
      name: "黑曜石翠绿",
      desc: "深邃暗曜基底配翡翠绿与电光青强调",
      swatches: ["#080D16", "#10B981", "#38BDF8"]
    },
    {
      id: "cupertino-frost",
      name: "清冽原生",
      desc: "通透磨砂浅灰配原生系统蓝与暖橙光标",
      swatches: ["#F5F5F7", "#0066CC", "#FF9F0A"]
    },
    {
      id: "graphite-mono",
      name: "极简石墨",
      desc: "克制单色石墨层级配冷冽金属灰调",
      swatches: ["#F4F4F5", "#27272A", "#71717A"]
    }
  ];

  var BUILTIN_STYLE_TOKENS = {
    "warm-paper": {
      light: {
        "--bg": "#F7F6F2",
        "--surface": "#FFFFFF",
        "--surface-glass": "rgba(247, 246, 242, 0.90)",
        "--surface-alt": "#FAF9F5",
        "--surface-inset": "#EFECE4",
        "--secondary-btn": "#EAE6DC",
        "--secondary-btn-soft": "#F1EFE7",
        "--secondary-btn-hover": "#DFDBD0",
        "--segmented-track": "#EAE6DC",
        "--border": "#E2DFD5",
        "--border-strong": "#CFCBC0",
        "--text": "#14181F",
        "--text-secondary": "#3E4552",
        "--muted": "#5F6775",
        "--primary": "#1F6E58",
        "--primary-hover": "#175644",
        "--link-accent": "#1F6E58",
        "--primary-soft": "rgba(31, 110, 88, 0.09)",
        "--primary-ring": "rgba(31, 110, 88, 0.20)",
        "--brand": "#1F6E58",
        "--accent-bridge": "#E9A820",
        "--bridge-amber": "#E9A820",
        "--bridge-amber-soft": "rgba(233, 168, 32, 0.15)",
        "--ip-ring": "#B8B1A0",
        "--ip-eye": "#FFFFFF",
        "--ip-visor": "rgba(12, 20, 24, 0.20)",
        "--term-bg": "#14181F",
        "--term-fg": "#F0F6FC"
      },
      dark: {
        "--bg": "#0E1116",
        "--surface": "#161B22",
        "--surface-glass": "rgba(14, 17, 22, 0.90)",
        "--surface-alt": "#1C2129",
        "--surface-inset": "#0B0E13",
        "--secondary-btn": "#21262D",
        "--secondary-btn-soft": "#1B2027",
        "--secondary-btn-hover": "#292F38",
        "--segmented-track": "#0B0E13",
        "--border": "#262C36",
        "--border-strong": "#363E4B",
        "--text": "#F0F6FC",
        "--text-secondary": "#C9D1D9",
        "--muted": "#8B949E",
        "--primary": "#2B8A6E",
        "--primary-hover": "#34A080",
        "--link-accent": "#3FB693",
        "--primary-soft": "rgba(52, 160, 128, 0.14)",
        "--primary-ring": "rgba(52, 160, 128, 0.28)",
        "--brand": "#34A080",
        "--accent-bridge": "#F4BE4F",
        "--bridge-amber": "#F4BE4F",
        "--bridge-amber-soft": "rgba(244, 190, 79, 0.16)",
        "--ip-ring": "#6E7681",
        "--ip-eye": "#FFFFFF",
        "--ip-visor": "rgba(6, 14, 12, 0.44)",
        "--term-bg": "#090C10",
        "--term-fg": "#E6EDF3"
      }
    },
    "obsidian-emerald": {
      light: {
        "--bg": "#F2F7F5",
        "--surface": "#FFFFFF",
        "--surface-glass": "rgba(242, 247, 245, 0.90)",
        "--surface-alt": "#F7FBF9",
        "--surface-inset": "#E5EFEA",
        "--secondary-btn": "#DCE9E3",
        "--secondary-btn-soft": "#EAF2EE",
        "--secondary-btn-hover": "#CFE0D9",
        "--segmented-track": "#DCE9E3",
        "--border": "#CEDFD8",
        "--border-strong": "#B6CEC4",
        "--text": "#0B1320",
        "--text-secondary": "#334155",
        "--muted": "#52656E",
        "--primary": "#059669",
        "--primary-hover": "#047857",
        "--link-accent": "#059669",
        "--primary-soft": "rgba(5, 150, 105, 0.10)",
        "--primary-ring": "rgba(5, 150, 105, 0.22)",
        "--brand": "#059669",
        "--accent-bridge": "#0284C7",
        "--bridge-amber": "#0284C7",
        "--bridge-amber-soft": "rgba(2, 132, 199, 0.14)",
        "--ip-ring": "#8FA3B8",
        "--ip-eye": "#FFFFFF",
        "--ip-visor": "rgba(6, 20, 28, 0.38)",
        "--term-bg": "#0B1320",
        "--term-fg": "#F2F6FA"
      },
      dark: {
        "--bg": "#080D16",
        "--surface": "#0F1726",
        "--surface-glass": "rgba(8, 13, 22, 0.90)",
        "--surface-alt": "#141E30",
        "--surface-inset": "#05080F",
        "--secondary-btn": "#192338",
        "--secondary-btn-soft": "#131C2E",
        "--secondary-btn-hover": "#22304A",
        "--segmented-track": "#05080F",
        "--border": "#1E293B",
        "--border-strong": "#334155",
        "--text": "#F2F6FA",
        "--text-secondary": "#CBD5E1",
        "--muted": "#94A3B8",
        "--primary": "#10B981",
        "--primary-hover": "#34D399",
        "--link-accent": "#34D399",
        "--primary-soft": "rgba(16, 185, 129, 0.15)",
        "--primary-ring": "rgba(16, 185, 129, 0.28)",
        "--brand": "#10B981",
        "--accent-bridge": "#38BDF8",
        "--bridge-amber": "#38BDF8",
        "--bridge-amber-soft": "rgba(56, 189, 248, 0.16)",
        "--ip-ring": "#64748B",
        "--ip-eye": "#FFFFFF",
        "--ip-visor": "rgba(5, 12, 22, 0.48)",
        "--term-bg": "#05080F",
        "--term-fg": "#F8FAFC"
      }
    },
    "cupertino-frost": {
      light: {
        "--bg": "#F5F5F7",
        "--surface": "#FFFFFF",
        "--surface-glass": "rgba(245, 245, 247, 0.88)",
        "--surface-alt": "#FAFAFC",
        "--surface-inset": "#E8E8ED",
        "--secondary-btn": "#E5E5EA",
        "--secondary-btn-soft": "#EFEFF4",
        "--secondary-btn-hover": "#D8D8DF",
        "--segmented-track": "#E5E5EA",
        "--border": "#D2D2D7",
        "--border-strong": "#BCBCC4",
        "--text": "#1D1D1F",
        "--text-secondary": "#3A3A3C",
        "--muted": "#6E6E73",
        "--primary": "#0066CC",
        "--primary-hover": "#0052A3",
        "--link-accent": "#0066CC",
        "--primary-soft": "rgba(0, 102, 204, 0.10)",
        "--primary-ring": "rgba(0, 102, 204, 0.22)",
        "--brand": "#0066CC",
        "--accent-bridge": "#FF9F0A",
        "--bridge-amber": "#FF9F0A",
        "--bridge-amber-soft": "rgba(255, 159, 10, 0.16)",
        "--ip-ring": "#8E8E93",
        "--ip-eye": "#FFFFFF",
        "--ip-visor": "rgba(8, 18, 38, 0.36)",
        "--term-bg": "#1C1C1E",
        "--term-fg": "#F5F5F7"
      },
      dark: {
        "--bg": "#090A0D",
        "--surface": "#16171B",
        "--surface-glass": "rgba(14, 15, 19, 0.88)",
        "--surface-alt": "#1E2026",
        "--surface-inset": "#050608",
        "--secondary-btn": "#262830",
        "--secondary-btn-soft": "#1E2028",
        "--secondary-btn-hover": "#31343E",
        "--segmented-track": "#050608",
        "--border": "#2C2E36",
        "--border-strong": "#3E414C",
        "--text": "#F5F5F7",
        "--text-secondary": "#D1D1D6",
        "--muted": "#98989D",
        "--primary": "#2997FF",
        "--primary-hover": "#52ACFF",
        "--link-accent": "#47A8FF",
        "--primary-soft": "rgba(41, 151, 255, 0.16)",
        "--primary-ring": "rgba(41, 151, 255, 0.28)",
        "--brand": "#2997FF",
        "--accent-bridge": "#FFB340",
        "--bridge-amber": "#FFB340",
        "--bridge-amber-soft": "rgba(255, 179, 64, 0.16)",
        "--ip-ring": "#6C6C72",
        "--ip-eye": "#FFFFFF",
        "--ip-visor": "rgba(5, 14, 28, 0.44)",
        "--term-bg": "#050608",
        "--term-fg": "#F5F5F7"
      }
    },
    "graphite-mono": {
      light: {
        "--bg": "#F4F4F5",
        "--surface": "#FFFFFF",
        "--surface-glass": "rgba(244, 244, 245, 0.90)",
        "--surface-alt": "#FAFAFA",
        "--surface-inset": "#E4E4E7",
        "--secondary-btn": "#E4E4E7",
        "--secondary-btn-soft": "#EFEFF1",
        "--secondary-btn-hover": "#D4D4D8",
        "--segmented-track": "#E4E4E7",
        "--border": "#D4D4D8",
        "--border-strong": "#B8B8BE",
        "--text": "#18181B",
        "--text-secondary": "#3F3F46",
        "--muted": "#65656D",
        "--primary": "#27272A",
        "--primary-hover": "#18181B",
        "--link-accent": "#27272A",
        "--primary-soft": "rgba(39, 39, 42, 0.08)",
        "--primary-ring": "rgba(39, 39, 42, 0.20)",
        "--brand": "#27272A",
        "--accent-bridge": "#71717A",
        "--bridge-amber": "#71717A",
        "--bridge-amber-soft": "rgba(113, 113, 122, 0.15)",
        "--ip-ring": "#A1A1AA",
        "--ip-eye": "#FFFFFF",
        "--ip-visor": "rgba(0, 0, 0, 0.36)",
        "--term-bg": "#18181B",
        "--term-fg": "#FAFAFA"
      },
      dark: {
        "--bg": "#09090B",
        "--surface": "#141417",
        "--surface-glass": "rgba(9, 9, 11, 0.90)",
        "--surface-alt": "#1C1C20",
        "--surface-inset": "#050507",
        "--secondary-btn": "#222227",
        "--secondary-btn-soft": "#1A1A1E",
        "--secondary-btn-hover": "#2C2C33",
        "--segmented-track": "#050507",
        "--border": "#27272A",
        "--border-strong": "#3F3F46",
        "--text": "#FAFAFA",
        "--text-secondary": "#D4D4D8",
        "--muted": "#A1A1AA",
        "--primary": "#52525B",
        "--primary-hover": "#71717A",
        "--link-accent": "#D4D4D8",
        "--primary-soft": "rgba(161, 161, 170, 0.14)",
        "--primary-ring": "rgba(161, 161, 170, 0.26)",
        "--brand": "#52525B",
        "--accent-bridge": "#A1A1AA",
        "--bridge-amber": "#A1A1AA",
        "--bridge-amber-soft": "rgba(161, 161, 170, 0.18)",
        "--ip-ring": "#71717A",
        "--ip-eye": "#FFFFFF",
        "--ip-visor": "rgba(9, 9, 11, 0.50)",
        "--term-bg": "#050507",
        "--term-fg": "#F4F4F5"
      }
    }
  };

  var IP_PACKS = [
    {
      id: "orbit-turn",
      name: "星环小代理 · 3/4 转向",
      desc: "3/4 转头凝视右侧本地终端，支持四态视线与专注神态",
      supportsPose: true
    },
    {
      id: "orbit-v2-mask",
      name: "等线星环 · V2 镂空",
      desc: "对齐 V2 标准等线宽星环与 4.5u 净空遮罩箭头版",
      supportsPose: false
    },
    {
      id: "obsidian-peel",
      name: "网页折角 · 双层揭开",
      desc: "左上网页 AI 层折角翻开，露出右下本地终端内核",
      supportsPose: false
    },
    {
      id: "minimal-bridge",
      name: "几何桥接 · 极简工具",
      desc: "去拟人化纯几何符号与本地终端桥接，严肃冷静",
      supportsPose: false
    }
  ];

  var POSES = [
    { id: "turn-right", label: "向右看终端" },
    { id: "front", label: "正视用户" },
    { id: "turn-left", label: "向左回望" },
    { id: "working", label: "专注执行" }
  ];

  var customStyleSpecs = {};
  var customIpRenderers = {};
  var customIpCssVars = {};
  var uidCounter = 0;
  var listenersBound = false;
  var themeObserver = null;
  var applyingDomAttrs = false;
  var activePopoverCloseFn = null;

  var state = {
    theme: "light",
    stylePack: "warm-paper",
    ipPack: "orbit-turn",
    pose: "turn-right"
  };

  function nextUid(prefix) {
    uidCounter = (uidCounter + 1) % 999999;
    return (prefix || "w2p") + "-" + uidCounter;
  }

  function findById(arr, id) {
    for (var i = 0; i < arr.length; i++) {
      if (arr[i] && arr[i].id === id) return arr[i];
    }
    return null;
  }

  function escapeAttr(val) {
    return String(val == null ? "" : val)
      .replace(/&/g, "&amp;")
      .replace(/"/g, "&quot;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function safeStorageGet(key) {
    try {
      if (global.localStorage) {
        return global.localStorage.getItem(key);
      }
    } catch (e) {}
    return null;
  }

  function safeStorageSet(key, val) {
    try {
      if (global.localStorage) {
        global.localStorage.setItem(key, String(val));
      }
    } catch (e) {}
  }

  function serializeCssVars(varsObj) {
    if (!varsObj || typeof varsObj !== "object") return "";
    var out = [];
    var keys = Object.keys(varsObj);
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      var prop = k.indexOf("--") === 0 ? k : "--" + k;
      var val = String(varsObj[k]).replace(/[;{}]/g, "");
      out.push(prop + ":" + val + ";");
    }
    return out.join("");
  }

  function buildBuiltinCssText() {
    var rules = [];
    rules.push(
      ":where(:root){" +
        "--brand:var(--primary,#1F6E58);" +
        "--ip-eye:#FFFFFF;" +
        "--ip-visor:rgba(12,20,24,0.22);" +
        "--ip-gaze-x:0px;" +
        "--ip-gaze-y:0px;" +
        "--ip-ease:cubic-bezier(0.23,1,0.32,1);" +
      "}" +
      ":root,[data-style-pack],[data-theme]{" +
        "--accent-bridge:var(--ip-bridge,var(--bridge-amber,#E9A820));" +
        "--ip-ring:var(--ip-orbit,#94A3B8);" +
      "}"
    );
    var packIds = Object.keys(BUILTIN_STYLE_TOKENS);
    for (var i = 0; i < packIds.length; i++) {
      var pid = packIds[i];
      var spec = BUILTIN_STYLE_TOKENS[pid];
      if (spec.light) {
        rules.push(
          ':where(html[data-style-pack="' + pid + '"]),' +
          ':where(html[data-style-pack="' + pid + '"][data-theme="light"]){' +
            serializeCssVars(spec.light) +
            "--ip-bridge:" + (spec.light["--accent-bridge"] || "#E9A820") + ";" +
            "--ip-orbit:" + (spec.light["--ip-ring"] || "#94A3B8") + ";" +
          "}"
        );
      }
      if (spec.dark) {
        rules.push(
          ':where(html[data-style-pack="' + pid + '"][data-theme="dark"]){' +
            serializeCssVars(spec.dark) +
            "--ip-bridge:" + (spec.dark["--accent-bridge"] || "#F4BE4F") + ";" +
            "--ip-orbit:" + (spec.dark["--ip-ring"] || "#64748B") + ";" +
          "}"
        );
      }
    }

    rules.push(
      ".ip-gaze-layer{" +
        "transform:translate(var(--ip-gaze-x,0px),var(--ip-gaze-y,0px));" +
        "transition:transform 180ms cubic-bezier(0.23,1,0.32,1);" +
        "will-change:transform;" +
      "}" +
      ".ip-visor-track{" +
        "transform:translate(calc(var(--ip-gaze-x,0px)*0.55),calc(var(--ip-gaze-y,0px)*0.45));" +
        "transition:transform 180ms cubic-bezier(0.23,1,0.32,1);" +
      "}" +
      "@keyframes w2pCursorPulse{" +
        "0%,48%{opacity:1;}50%,100%{opacity:0.2;}" +
      "}" +
      "@keyframes w2pWorkingPulse{" +
        "0%,100%{opacity:1;transform:scaleX(1);}50%{opacity:0.35;transform:scaleX(0.86);}" +
      "}" +
      ".brand-mark-svg .cursor-blink,.w2p-svg .cursor-blink{" +
        "animation:w2pCursorPulse 1.15s infinite;" +
      "}" +
      ".brand-mark-svg .cursor-working,.w2p-svg .cursor-working{" +
        "animation:w2pWorkingPulse 0.68s ease-in-out infinite;" +
        "transform-box:fill-box;transform-origin:center;" +
      "}" +
      "@media (prefers-reduced-motion:reduce){" +
        ".ip-gaze-layer,.ip-visor-track,.brand-mark-svg .cursor-blink,.w2p-svg .cursor-blink,.brand-mark-svg .cursor-working,.w2p-svg .cursor-working{" +
          "transition:none !important;animation:none !important;" +
        "}" +
      "}"
    );

    // Compact High-Density Appearance Switcher Popover Styles
    rules.push(
      ".w2p-sw-wrap{position:relative;display:inline-flex;align-items:center;}" +
      ".w2p-sw-trigger{" +
        "display:inline-flex;align-items:center;gap:6px;height:32px;padding:0 10px;" +
        "border-radius:7px;border:1px solid var(--border,#E2DFD5);" +
        "background:var(--surface,#FFFFFF);color:var(--text,#14181F);" +
        "font:600 12.5px/1 var(--font-sans,system-ui,sans-serif);cursor:pointer;" +
        "transition:background-color 120ms ease,border-color 120ms ease;" +
      "}" +
      ".w2p-sw-trigger:hover{background:var(--secondary-btn-soft,#F1EFE7);border-color:var(--border-strong,#CFCBC0);}" +
      ".w2p-sw-trigger:active{transform:scale(0.98);}" +
      ".w2p-sw-dots{display:inline-flex;align-items:center;gap:3px;}" +
      ".w2p-sw-dot{width:8px;height:8px;border-radius:50%;border:1px solid rgba(128,128,128,0.28);}" +
      ".w2p-sw-popover{" +
        "position:absolute;top:calc(100% + 7px);right:0;z-index:1200;" +
        "width:336px;max-width:calc(100vw - 24px);padding:12px;" +
        "border-radius:12px;border:1px solid var(--border-strong,#CFCBC0);" +
        "background:var(--modal-surface,var(--surface,#FFFFFF));color:var(--text,#14181F);" +
        "box-shadow:0 10px 30px rgba(15,20,28,0.16),0 1px 3px rgba(15,20,28,0.08);" +
        "display:none;flex-direction:column;gap:10px;text-align:left;" +
      "}" +
      ".w2p-sw-popover.open{display:flex;}" +
      ".w2p-sw-sec-hd{display:flex;align-items:center;justify-content:space-between;font-size:11.5px;font-weight:700;color:var(--muted,#5F6775);margin-bottom:5px;}" +
      ".w2p-sw-seg{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:4px;background:var(--segmented-track,#EAE6DC);padding:3px;border-radius:8px;}" +
      ".w2p-sw-seg4{grid-template-columns:repeat(4,minmax(0,1fr));}" +
      ".w2p-sw-seg-btn{" +
        "border:none;border-radius:6px;padding:5px 4px;background:transparent;" +
        "color:var(--text-secondary,#3E4552);font:600 11.5px/1.2 var(--font-sans,system-ui,sans-serif);" +
        "cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" +
      "}" +
      ".w2p-sw-seg-btn.active{background:var(--surface,#FFFFFF);color:var(--text,#14181F);box-shadow:0 1px 2px rgba(0,0,0,0.1);}" +
      ".w2p-sw-seg-btn:disabled{opacity:0.45;cursor:not-allowed;}" +
      ".w2p-sw-grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px;}" +
      ".w2p-sw-card{" +
        "display:flex;flex-direction:column;align-items:flex-start;gap:4px;padding:7px 8px;" +
        "border-radius:8px;border:1px solid var(--border,#E2DFD5);" +
        "background:var(--surface-alt,var(--surface,#FFFFFF));color:var(--text,#14181F);" +
        "cursor:pointer;text-align:left;transition:border-color 120ms ease,background-color 120ms ease;" +
      "}" +
      ".w2p-sw-card:hover{border-color:var(--brand,#1F6E58);}" +
      ".w2p-sw-card.active{border-color:var(--brand,#1F6E58);background:var(--primary-soft,rgba(31,110,88,0.09));box-shadow:inset 0 0 0 1px var(--brand,#1F6E58);}" +
      ".w2p-sw-card-top{display:flex;align-items:center;justify-content:space-between;width:100%;gap:4px;}" +
      ".w2p-sw-card-title{font-size:12px;font-weight:700;line-height:1.2;}" +
      ".w2p-sw-card-sub{font-size:10.5px;color:var(--muted,#5F6775);line-height:1.25;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;}" +
      ".w2p-sw-ip-preview{width:100%;height:26px;display:flex;align-items:center;justify-content:center;background:var(--surface,#FFFFFF);border-radius:5px;border:1px solid var(--border,#E2DFD5);padding:2px 4px;}" +
      ".w2p-sw-ip-preview svg{height:21px;width:auto;display:block;}" +
      ".w2p-sw-foot{display:flex;align-items:center;justify-content:space-between;gap:8px;padding-top:8px;border-top:1px solid var(--border,#E2DFD5);}" +
      ".w2p-sw-copy-btn{" +
        "width:100%;padding:6px 10px;border-radius:7px;border:1px solid var(--border,#E2DFD5);" +
        "background:var(--secondary-btn,#EAE6DC);color:var(--text,#14181F);" +
        "font:600 11.5px/1.2 var(--font-mono,monospace);cursor:pointer;" +
      "}" +
      ".w2p-sw-copy-btn:hover{background:var(--secondary-btn-hover,#DFDBD0);}" +
      ".w2p-sw-hint{font-size:10.5px;color:var(--muted,#5F6775);margin-top:3px;}"
    );
    return rules.join("\n");
  }

  function ensureBaseStylesInjected() {
    if (typeof document === "undefined" || !document.head) return;
    var existing = document.getElementById("webai2pc-brand-packs-css");
    if (!existing) {
      existing = document.createElement("style");
      existing.id = "webai2pc-brand-packs-css";
      existing.textContent = buildBuiltinCssText();
      document.head.appendChild(existing);
    }
  }

  function rebuildCustomPackStyles() {
    if (typeof document === "undefined" || !document.head) return;
    var chunks = [];
    var sIds = Object.keys(customStyleSpecs);
    for (var i = 0; i < sIds.length; i++) {
      var sid = sIds[i];
      var sp = customStyleSpecs[sid];
      if (!sp) continue;
      var lightVars = sp.light || sp.cssVars || sp.variables || null;
      var darkVars = sp.dark || sp.darkCssVars || null;
      if (lightVars) {
        chunks.push(
          'html[data-style-pack="' + escapeAttr(sid) + '"],' +
          'html[data-style-pack="' + escapeAttr(sid) + '"][data-theme="light"]{' +
            serializeCssVars(lightVars) +
          "}"
        );
      }
      if (darkVars) {
        chunks.push(
          'html[data-style-pack="' + escapeAttr(sid) + '"][data-theme="dark"]{' +
            serializeCssVars(darkVars) +
          "}"
        );
      }
    }
    var ipIds = Object.keys(customIpCssVars);
    for (var j = 0; j < ipIds.length; j++) {
      var iid = ipIds[j];
      var ivars = customIpCssVars[iid];
      if (ivars) {
        chunks.push(
          'html[data-ip-pack="' + escapeAttr(iid) + '"]{' +
            serializeCssVars(ivars) +
          "}"
        );
      }
    }
    var el = document.getElementById("webai2pc-custom-pack-css");
    if (!chunks.length) {
      if (el && el.parentNode) el.parentNode.removeChild(el);
      return;
    }
    if (!el) {
      el = document.createElement("style");
      el.id = "webai2pc-custom-pack-css";
      document.head.appendChild(el);
    }
    el.textContent = chunks.join("\n");
  }

  // --- SVG Primitive Helpers ---
  function renderGeminiStar(cx, cy, radius, fill) {
    var s = (radius * 2) / 24;
    var tx = (cx - radius).toFixed(2);
    var ty = (cy - radius).toFixed(2);
    return (
      '<g transform="translate(' + tx + " " + ty + ") scale(" + s.toFixed(3) + ')">' +
        '<path d="' + GEMINI_SPARKLE_PATH + '" fill="' + (fill || "#3B82F6") + '"/>' +
      "</g>"
    );
  }

  function renderCompactGptKnot(cx, cy, radius, color) {
    var s = (radius / 10).toFixed(3);
    var col = color || "#10A37F";
    var petals = "";
    for (var a = 0; a < 360; a += 60) {
      petals +=
        '<rect x="-3.4" y="-8.2" width="6.8" height="9.2" rx="3.4" fill="none" stroke="#FFFFFF" stroke-width="1.75" transform="rotate(' +
        a +
        ')"/>';
    }
    return (
      '<g transform="translate(' + cx + "," + cy + ") scale(" + s + ')">' +
        '<circle cx="0" cy="0" r="10.8" fill="' + col + '"/>' +
        '<g transform="scale(0.84)">' + petals + "</g>" +
        '<circle cx="0" cy="0" r="2.2" fill="' + col + '"/>' +
      "</g>"
    );
  }

  function renderFullOpenAiBlossom(cx, cy, radius, color) {
    var s = (radius * 2) / 24;
    var tx = (cx - radius).toFixed(2);
    var ty = (cy - radius).toFixed(2);
    return (
      '<g transform="translate(' + tx + " " + ty + ") scale(" + s.toFixed(3) + ')">' +
        '<path d="' + OPENAI_BLOSSOM_PATH + '" fill="' + (color || "#10A37F") + '"/>' +
      "</g>"
    );
  }

  function renderWordmark580(yPos) {
    var y = yPos || 324;
    return (
      '<text x="290" y="' + y + '" text-anchor="middle" fill="var(--text, #14181F)" ' +
        'font-family="\'Inter\', \'Geist\', \'SF Pro Display\', \'Segoe UI\', system-ui, sans-serif" ' +
        'font-size="88" font-weight="700" letter-spacing="-2.2">' +
        'Web<tspan dx="-1">A</tspan><tspan dx="-1.5">I</tspan>' +
        '<tspan fill="var(--accent-bridge, #E9A820)" font-weight="800" dx="0.5">2</tspan>' +
        '<tspan dx="0.5">P</tspan><tspan dx="-1">C</tspan>' +
      "</text>"
    );
  }

  // --- Pack 1: orbit-turn (3/4 Turn System with 4 poses) ---
  function renderOrbitTurnHead186(pose, uid, useDetailedBlossom) {
    var p = pose || "turn-right";
    var maskId = uid + "-head-m";
    var orbitMaskId = uid + "-orb-m";

    var headX = p === "working" ? 24 : 23;
    var visorMarkup = "";
    var earsMarkup = "";
    var eyesMarkup = "";

    if (p === "front") {
      earsMarkup =
        '<rect x="19.2" y="31" width="4.2" height="10" rx="2.1" fill="var(--ip-ring, #94A3B8)"/>' +
        '<rect x="68.6" y="31" width="4.2" height="10" rx="2.1" fill="var(--ip-ring, #94A3B8)"/>';
      visorMarkup =
        '<rect class="ip-visor-track" x="28" y="23.5" width="36" height="24.5" rx="8" fill="var(--ip-visor, rgba(12, 20, 24, 0.20))"/>';
      eyesMarkup =
        '<ellipse cx="39.5" cy="35.6" rx="4.1" ry="5.1" fill="var(--ip-eye, #FFFFFF)"/>' +
        '<circle cx="40.3" cy="33.4" r="1.1" fill="var(--brand, #1F6E58)" opacity="0.30"/>' +
        '<ellipse cx="52.5" cy="35.6" rx="4.1" ry="5.1" fill="var(--ip-eye, #FFFFFF)"/>' +
        '<circle cx="53.3" cy="33.4" r="1.1" fill="var(--brand, #1F6E58)" opacity="0.30"/>';
    } else if (p === "turn-left") {
      earsMarkup =
        '<rect x="67.5" y="30.2" width="5.6" height="11.4" rx="2.6" fill="var(--accent-bridge, #E9A820)"/>' +
        '<circle cx="71.2" cy="26.2" r="1.7" fill="var(--ip-ring, #94A3B8)"/>';
      visorMarkup =
        '<rect class="ip-visor-track" x="26.2" y="23.5" width="34.5" height="24.5" rx="8" fill="var(--ip-visor, rgba(12, 20, 24, 0.20))"/>';
      eyesMarkup =
        '<ellipse cx="36.0" cy="35.6" rx="4.7" ry="5.4" fill="var(--ip-eye, #FFFFFF)"/>' +
        '<circle cx="34.5" cy="33.2" r="1.2" fill="var(--brand, #1F6E58)" opacity="0.32"/>' +
        '<ellipse cx="49.4" cy="35.6" rx="3.3" ry="5.0" fill="var(--ip-eye, #FFFFFF)"/>' +
        '<circle cx="48.3" cy="33.3" r="1.0" fill="var(--brand, #1F6E58)" opacity="0.32"/>';
    } else if (p === "working") {
      earsMarkup =
        '<rect x="19.6" y="30.2" width="5.6" height="11.4" rx="2.6" fill="var(--accent-bridge, #E9A820)"/>' +
        '<circle cx="21.5" cy="26.0" r="1.8" fill="var(--accent-bridge, #E9A820)"/>';
      visorMarkup =
        '<rect class="ip-visor-track" x="32.2" y="23.5" width="34.5" height="24.5" rx="8" fill="var(--ip-visor, rgba(12, 20, 24, 0.24))"/>';
      eyesMarkup =
        '<path d="M39.8 32.5L45.0 35.6L39.8 38.7" stroke="var(--ip-eye, #FFFFFF)" stroke-width="2.7" stroke-linecap="round" stroke-linejoin="round" fill="none"/>' +
        '<path d="M51.8 31.8L58.6 35.6L51.8 39.4" stroke="var(--ip-eye, #FFFFFF)" stroke-width="3.1" stroke-linecap="round" stroke-linejoin="round" fill="none"/>' +
        '<circle cx="62.2" cy="30.0" r="1.6" fill="var(--accent-bridge, #E9A820)"/>';
    } else {
      // Default: turn-right (3/4 perspective toward right terminal)
      earsMarkup =
        '<rect x="18.8" y="30.2" width="5.6" height="11.4" rx="2.6" fill="var(--accent-bridge, #E9A820)"/>' +
        '<circle cx="20.6" cy="26.2" r="1.7" fill="var(--ip-ring, #94A3B8)"/>';
      visorMarkup =
        '<rect class="ip-visor-track" x="31.3" y="23.5" width="34.5" height="24.5" rx="8" fill="var(--ip-visor, rgba(12, 20, 24, 0.20))"/>';
      eyesMarkup =
        '<ellipse cx="42.6" cy="35.6" rx="3.3" ry="5.0" fill="var(--ip-eye, #FFFFFF)"/>' +
        '<circle cx="43.7" cy="33.3" r="1.0" fill="var(--brand, #1F6E58)" opacity="0.32"/>' +
        '<ellipse cx="56.0" cy="35.6" rx="4.7" ry="5.4" fill="var(--ip-eye, #FFFFFF)"/>' +
        '<circle cx="57.5" cy="33.2" r="1.2" fill="var(--brand, #1F6E58)" opacity="0.32"/>';
    }

    return (
      "<defs>" +
        '<mask id="' + orbitMaskId + '">' +
          '<rect x="-10" y="-10" width="210" height="96" fill="white"/>' +
          '<circle cx="15.5" cy="19.5" r="11.2" fill="black"/>' +
          '<circle cx="78" cy="24" r="11.2" fill="black"/>' +
        "</mask>" +
        '<mask id="' + maskId + '">' +
          '<rect x="-10" y="-10" width="210" height="96" fill="white"/>' +
          '<path d="M84 23.5 A40 15.5 -21 0 1 9 48.5" stroke="black" stroke-width="6.4" stroke-linecap="round" fill="none"/>' +
          '<circle cx="78" cy="24" r="10.8" fill="black"/>' +
        "</mask>" +
      "</defs>" +
      '<g mask="url(#' + orbitMaskId + ')" opacity="0.58">' +
        '<path d="M9 48.5 A40 15.5 -21 0 1 84 23.5" stroke="var(--ip-ring, #94A3B8)" stroke-width="3.1" stroke-linecap="round" fill="none"/>' +
      "</g>" +
      '<g mask="url(#' + maskId + ')">' +
        earsMarkup +
        '<rect x="' + headX + '" y="18.5" width="46" height="35" rx="11.5" fill="var(--brand, #1F6E58)"/>' +
        visorMarkup +
        '<g class="ip-gaze-layer">' + eyesMarkup + "</g>" +
      "</g>" +
      '<g mask="url(#' + orbitMaskId + ')">' +
        '<path d="M84 23.5 A40 15.5 -21 0 1 9 48.5" stroke="var(--ip-ring, #94A3B8)" stroke-width="3.1" stroke-linecap="round" fill="none"/>' +
      "</g>" +
      renderGeminiStar(15.5, 19.5, 9.2, "#3B82F6") +
      (useDetailedBlossom ? renderFullOpenAiBlossom(78, 24, 9.2, "#10A37F") : renderCompactGptKnot(78, 24, 8.6, "#10A37F"))
    );
  }

  function renderBridgeAndTerminal186(pose) {
    var isWorking = pose === "working";
    var cursorCls = isWorking ? "cursor-blink cursor-working" : "cursor-blink";
    var sightTicks =
      pose === "turn-left"
        ? '<line x1="88" y1="36" x2="90.5" y2="36" stroke="var(--ip-ring, #94A3B8)" stroke-width="2" stroke-linecap="round" opacity="0.45"/>'
        : '<line x1="87.5" y1="36" x2="90.5" y2="36" stroke="var(--accent-bridge, #E9A820)" stroke-width="2.2" stroke-linecap="round" opacity="0.85"/>' +
          '<line x1="112" y1="36" x2="115.5" y2="36" stroke="var(--accent-bridge, #E9A820)" stroke-width="2.2" stroke-linecap="round" opacity="0.85"/>';

    return (
      sightTicks +
      '<rect x="92" y="26" width="18" height="20" rx="5.5" fill="var(--accent-bridge, #E9A820)"/>' +
      '<text x="101" y="40.2" text-anchor="middle" fill="#FFFFFF" font-family="ui-monospace, \'Cascadia Mono\', monospace" font-weight="800" font-size="12.5">2</text>' +
      '<rect x="118" y="15" width="54" height="42" rx="10" fill="var(--ip-term-bg, var(--brand, #1F6E58))"/>' +
      '<circle cx="128" cy="24" r="1.9" fill="#EF4444"/>' +
      '<circle cx="134.5" cy="24" r="1.9" fill="#F59E0B"/>' +
      '<circle cx="141" cy="24" r="1.9" fill="#10B981"/>' +
      '<path d="M130 34L139 40.5L130 47" stroke="var(--ip-term-fg, #FFFFFF)" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" fill="none"/>' +
      '<line class="' + cursorCls + '" x1="144" y1="47" x2="158" y2="47" stroke="var(--accent-bridge, #E9A820)" stroke-width="3.2" stroke-linecap="round"/>' +
      '<rect x="172" y="26" width="5.5" height="20" rx="2.2" fill="var(--accent-bridge, #E9A820)"/>'
    );
  }

  function renderOrbitTurnAppIcon64(pose, uid) {
    var p = pose || "turn-right";
    var orbM = uid + "-sq-orb";
    var headM = uid + "-sq-hd";
    var ear = "";
    var visor = "";
    var eyes = "";

    if (p === "front") {
      ear =
        '<rect x="9.5" y="23.5" width="3" height="7" rx="1.5" fill="var(--ip-ring, #94A3B8)"/>' +
        '<rect x="43.5" y="23.5" width="3" height="7" rx="1.5" fill="var(--ip-ring, #94A3B8)"/>';
      visor = '<rect class="ip-visor-track" x="15.5" y="18.5" width="25" height="17" rx="5.5" fill="var(--ip-visor, rgba(12,20,24,0.20))"/>';
      eyes =
        '<ellipse cx="23.5" cy="27" rx="2.8" ry="3.6" fill="var(--ip-eye, #FFFFFF)"/>' +
        '<ellipse cx="32.5" cy="27" rx="2.8" ry="3.6" fill="var(--ip-eye, #FFFFFF)"/>';
    } else if (p === "turn-left") {
      ear = '<rect x="43" y="23" width="4" height="8" rx="2" fill="var(--accent-bridge, #E9A820)"/>';
      visor = '<rect class="ip-visor-track" x="14.2" y="18.5" width="24" height="17" rx="5.5" fill="var(--ip-visor, rgba(12,20,24,0.20))"/>';
      eyes =
        '<ellipse cx="21.0" cy="27" rx="3.2" ry="3.8" fill="var(--ip-eye, #FFFFFF)"/>' +
        '<ellipse cx="30.5" cy="27" rx="2.2" ry="3.5" fill="var(--ip-eye, #FFFFFF)"/>';
    } else if (p === "working") {
      ear = '<rect x="9" y="23" width="4" height="8" rx="2" fill="var(--accent-bridge, #E9A820)"/>';
      visor = '<rect class="ip-visor-track" x="18" y="18.5" width="24" height="17" rx="5.5" fill="var(--ip-visor, rgba(12,20,24,0.24))"/>';
      eyes =
        '<path d="M23 24.8L26.8 27L23 29.2" stroke="var(--ip-eye, #FFFFFF)" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" fill="none"/>' +
        '<path d="M31.2 24.2L35.8 27L31.2 29.8" stroke="var(--ip-eye, #FFFFFF)" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" fill="none"/>';
    } else {
      ear = '<rect x="9" y="23" width="4" height="8" rx="2" fill="var(--accent-bridge, #E9A820)"/>';
      visor = '<rect class="ip-visor-track" x="17.8" y="18.5" width="24" height="17" rx="5.5" fill="var(--ip-visor, rgba(12,20,24,0.20))"/>';
      eyes =
        '<ellipse cx="25.5" cy="27" rx="2.3" ry="3.5" fill="var(--ip-eye, #FFFFFF)"/>' +
        '<circle cx="26.3" cy="25.4" r="0.75" fill="var(--brand, #1F6E58)" opacity="0.32"/>' +
        '<ellipse cx="34.8" cy="27" rx="3.3" ry="3.8" fill="var(--ip-eye, #FFFFFF)"/>' +
        '<circle cx="35.8" cy="25.3" r="0.85" fill="var(--brand, #1F6E58)" opacity="0.32"/>';
    }

    var curCls = p === "working" ? "cursor-blink cursor-working" : "cursor-blink";
    return (
      "<defs>" +
        '<mask id="' + orbM + '">' +
          '<rect width="64" height="64" fill="white"/>' +
          '<circle cx="11" cy="13" r="7.5" fill="black"/>' +
          '<circle cx="49" cy="17" r="7.5" fill="black"/>' +
        "</mask>" +
        '<mask id="' + headM + '">' +
          '<rect width="64" height="64" fill="white"/>' +
          '<path d="M53 16 A26 10 -22 0 1 5 36" stroke="black" stroke-width="4.6" stroke-linecap="round" fill="none"/>' +
        "</mask>" +
      "</defs>" +
      '<rect x="2" y="2" width="60" height="60" rx="14.5" fill="var(--surface, #FFFFFF)" stroke="var(--border, #E2DFD5)" stroke-width="1.5"/>' +
      '<g mask="url(#' + orbM + ')" opacity="0.56">' +
        '<path d="M5 36 A26 10 -22 0 1 53 16" stroke="var(--ip-ring, #94A3B8)" stroke-width="2.4" stroke-linecap="round" fill="none"/>' +
      "</g>" +
      '<g mask="url(#' + headM + ')">' +
        ear +
        '<rect x="12" y="14.5" width="32" height="25" rx="8.5" fill="var(--brand, #1F6E58)"/>' +
        visor +
        '<g class="ip-gaze-layer">' + eyes + "</g>" +
      "</g>" +
      '<g mask="url(#' + orbM + ')">' +
        '<path d="M53 16 A26 10 -22 0 1 5 36" stroke="var(--ip-ring, #94A3B8)" stroke-width="2.4" stroke-linecap="round" fill="none"/>' +
      "</g>" +
      renderGeminiStar(11, 13, 6.2, "#3B82F6") +
      renderCompactGptKnot(49, 17, 5.8, "#10A37F") +
      '<rect x="33.5" y="35.5" width="24.5" height="20" rx="6" fill="var(--term-bg, #14181F)" stroke="var(--surface, #FFFFFF)" stroke-width="2"/>' +
      '<path d="M39.5 42L44.5 45.8L39.5 49.6" stroke="#FFFFFF" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round" fill="none"/>' +
      '<line class="' + curCls + '" x1="47.2" y1="49.6" x2="53.5" y2="49.6" stroke="var(--accent-bridge, #E9A820)" stroke-width="2.4" stroke-linecap="round"/>'
    );
  }

  // --- Pack 2: orbit-v2-mask (V2 unified 4.5u clearance equal-stroke ring + arrow) ---
  function renderOrbitV2Mask186(uid) {
    var hm = uid + "-v2-hm";
    var om = uid + "-v2-om";
    return (
      "<defs>" +
        '<mask id="' + hm + '">' +
          '<rect x="-10" y="-10" width="210" height="96" fill="white"/>' +
          '<g transform="translate(46 36) rotate(-38)">' +
            '<path d="M 42,0 A 42,15 0 0,1 -42,0" stroke="black" stroke-width="6.8" stroke-linecap="round" fill="none"/>' +
          "</g>" +
          '<circle cx="33" cy="58" r="9.5" fill="black"/>' +
        "</mask>" +
        '<mask id="' + om + '">' +
          '<rect x="-10" y="-10" width="210" height="96" fill="white"/>' +
          '<circle cx="60" cy="11" r="9.2" fill="black"/>' +
          '<circle cx="33" cy="58" r="9.5" fill="black"/>' +
        "</mask>" +
      "</defs>" +
      '<g mask="url(#' + om + ')" opacity="0.48">' +
        '<g transform="translate(46 36) rotate(-38)">' +
          '<path d="M -42,0 A 42,15 0 0,1 42,0" stroke="var(--brand, #1F6E58)" stroke-width="3.2" stroke-linecap="round" fill="none"/>' +
        "</g>" +
      "</g>" +
      '<g mask="url(#' + hm + ')">' +
        '<rect x="22" y="18" width="48" height="36" rx="11.5" fill="var(--brand, #1F6E58)"/>' +
        '<ellipse cx="38" cy="36" rx="3.4" ry="4.2" fill="var(--ip-eye, #FFFFFF)"/>' +
        '<ellipse cx="54" cy="36" rx="3.4" ry="4.2" fill="var(--ip-eye, #FFFFFF)"/>' +
      "</g>" +
      '<g mask="url(#' + om + ')">' +
        '<g transform="translate(46 36) rotate(-38)">' +
          '<path d="M 42,0 A 42,15 0 0,1 -42,0" stroke="var(--brand, #1F6E58)" stroke-width="3.2" stroke-linecap="round" fill="none"/>' +
        "</g>" +
      "</g>" +
      renderGeminiStar(60, 11, 7.2, "#3B82F6") +
      renderFullOpenAiBlossom(33, 58, 7.8, "#10A37F") +
      '<g stroke="var(--brand, #1F6E58)" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round" fill="none">' +
        '<line x1="85" y1="36" x2="108" y2="36"/>' +
        '<polyline points="100.5,28.5 108.5,36 100.5,43.5"/>' +
      "</g>" +
      '<rect x="118" y="15" width="56" height="42" rx="10" fill="var(--brand, #1F6E58)"/>' +
      '<polyline points="130,27.5 139,36 130,44.5" fill="none" stroke="var(--ip-eye, #FFFFFF)" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/>' +
      '<rect class="cursor-blink" x="144" y="41.5" width="15" height="3.4" rx="1.7" fill="var(--accent-bridge, #E9A820)"/>'
    );
  }

  function renderOrbitV2Mask64(uid) {
    var hm = uid + "-v2sq-hm";
    var om = uid + "-v2sq-om";
    return (
      "<defs>" +
        '<mask id="' + hm + '">' +
          '<rect width="64" height="64" fill="white"/>' +
          '<g transform="translate(32 32) rotate(-40)">' +
            '<path d="M 27,0 A 27,9.8 0 0,1 -27,0" stroke="black" stroke-width="5.2" fill="none"/>' +
          "</g>" +
          '<circle cx="24" cy="49.5" r="6.8" fill="black"/>' +
        "</mask>" +
        '<mask id="' + om + '">' +
          '<rect width="64" height="64" fill="white"/>' +
          '<circle cx="42.5" cy="13" r="6.5" fill="black"/>' +
          '<circle cx="24" cy="49.5" r="6.8" fill="black"/>' +
        "</mask>" +
      "</defs>" +
      '<rect x="2" y="2" width="60" height="60" rx="14.5" fill="var(--surface, #FFFFFF)" stroke="var(--border, #E2DFD5)" stroke-width="1.5"/>' +
      '<g mask="url(#' + om + ')" opacity="0.48">' +
        '<g transform="translate(32 32) rotate(-40)">' +
          '<path d="M -27,0 A 27,9.8 0 0,1 27,0" stroke="var(--brand, #1F6E58)" stroke-width="2.4" stroke-linecap="round" fill="none"/>' +
        "</g>" +
      "</g>" +
      '<g mask="url(#' + hm + ')">' +
        '<rect x="16" y="18" width="32" height="28" rx="8" fill="var(--brand, #1F6E58)"/>' +
        '<polyline points="23.5,26.5 29,32 23.5,37.5" fill="none" stroke="var(--ip-eye, #FFFFFF)" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>' +
        '<rect class="cursor-blink" x="32" y="35.2" width="9.5" height="2.5" rx="1.25" fill="var(--accent-bridge, #E9A820)"/>' +
      "</g>" +
      '<g mask="url(#' + om + ')">' +
        '<g transform="translate(32 32) rotate(-40)">' +
          '<path d="M 27,0 A 27,9.8 0 0,1 -27,0" stroke="var(--brand, #1F6E58)" stroke-width="2.4" stroke-linecap="round" fill="none"/>' +
        "</g>" +
      "</g>" +
      renderGeminiStar(42.5, 13, 5.2, "#3B82F6") +
      renderFullOpenAiBlossom(24, 49.5, 5.4, "#10A37F")
    );
  }

  // --- Pack 3: obsidian-peel (Web AI Corner Peel Revealing Terminal) ---
  function renderObsidianPeelCard(x, y, size, uid) {
    var clipCard = uid + "-peel-card";
    var clipWeb = uid + "-peel-web";
    var gradCurl = uid + "-peel-curl";
    var s = (size / 172).toFixed(4);
    return (
      '<g transform="translate(' + x + " " + y + ") scale(" + s + ')">' +
        "<defs>" +
          '<clipPath id="' + clipCard + '"><rect x="0" y="0" width="172" height="172" rx="34"/></clipPath>' +
          '<clipPath id="' + clipWeb + '"><path d="M 0,0 L 172,0 L 172,26 C 152,46 70,128 28,172 L 0,172 Z"/></clipPath>' +
          '<linearGradient id="' + gradCurl + '" x1="32" y1="154" x2="168" y2="20" gradientUnits="userSpaceOnUse">' +
            '<stop offset="0%" stop-color="var(--brand, #1F6E58)"/>' +
            '<stop offset="55%" stop-color="#14F1B2"/>' +
            '<stop offset="100%" stop-color="#A7F3D0"/>' +
          "</linearGradient>" +
        "</defs>" +
        '<g clip-path="url(#' + clipCard + ')">' +
          '<rect x="0" y="0" width="172" height="172" rx="34" fill="var(--term-bg, #0B1320)"/>' +
          '<polyline points="86,94 112,118 86,142" fill="none" stroke="#F8FAFC" stroke-width="11" stroke-linecap="round" stroke-linejoin="round"/>' +
          '<rect class="cursor-blink" x="122" y="132" width="36" height="10" rx="5" fill="var(--accent-bridge, #E9A820)"/>' +
          '<g clip-path="url(#' + clipWeb + ')">' +
            '<rect x="0" y="0" width="172" height="172" rx="34" fill="#F4F7FB"/>' +
            '<line x1="0" y1="38" x2="172" y2="38" stroke="#CBD5E1" stroke-width="2"/>' +
            '<circle cx="28" cy="21" r="6.2" fill="var(--brand, #10B981)"/>' +
            '<circle cx="48" cy="21" r="6.2" fill="#94A3B8"/>' +
            '<circle cx="68" cy="21" r="6.2" fill="#CBD5E1"/>' +
            '<rect x="16" y="50" width="96" height="56" rx="14" fill="#DCE7F5" opacity="0.85"/>' +
            renderGeminiStar(42, 78, 14, "#2563EB") +
            renderFullOpenAiBlossom(82, 78, 14, "#059669") +
          "</g>" +
          '<path d="M 26,172 C 68,128 150,46 172,24 L 172,40 C 146,62 72,136 40,172 Z" fill="#000000" opacity="0.35"/>' +
          '<path d="M 26,172 C 60,132 134,60 162,12 C 169,20 172,30 172,40 C 152,34 132,56 100,88 C 70,118 46,146 32,172 Z" fill="url(#' + gradCurl + ')"/>' +
        "</g>" +
        '<rect x="1" y="1" width="170" height="170" rx="33" stroke="var(--ip-ring, #64748B)" stroke-width="2.5" opacity="0.55" fill="none"/>' +
      "</g>"
    );
  }

  function renderObsidianPeel186(uid) {
    return (
      renderObsidianPeelCard(22, 11, 50, uid) +
      '<rect x="88" y="26" width="18" height="20" rx="5.5" fill="var(--accent-bridge, #E9A820)"/>' +
      '<text x="97" y="40.2" text-anchor="middle" fill="#FFFFFF" font-family="ui-monospace, \'Cascadia Mono\', monospace" font-weight="800" font-size="12.5">2</text>' +
      '<rect x="116" y="15" width="56" height="42" rx="10" fill="var(--term-bg, #0E1726)" stroke="var(--brand, #1F6E58)" stroke-width="2"/>' +
      '<circle cx="126.5" cy="24" r="1.9" fill="#EF4444"/>' +
      '<circle cx="133" cy="24" r="1.9" fill="#F59E0B"/>' +
      '<circle cx="139.5" cy="24" r="1.9" fill="#10B981"/>' +
      '<path d="M128.5 34L137.5 40.5L128.5 47" stroke="#FFFFFF" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" fill="none"/>' +
      '<line class="cursor-blink" x1="143" y1="47" x2="158" y2="47" stroke="var(--accent-bridge, #E9A820)" stroke-width="3.2" stroke-linecap="round"/>'
    );
  }

  function renderObsidianPeel64(uid) {
    return (
      '<rect x="2" y="2" width="60" height="60" rx="14.5" fill="var(--term-bg, #0B1320)" stroke="var(--border-strong, #334155)" stroke-width="1.5"/>' +
      renderObsidianPeelCard(8, 8, 48, uid)
    );
  }

  // --- Pack 4: minimal-bridge (Non-anthropomorphic Pure Geometric Bridge) ---
  function renderMinimalBridge186() {
    return (
      '<rect x="18" y="16" width="50" height="40" rx="11" fill="none" stroke="var(--brand, #1F6E58)" stroke-width="3"/>' +
      '<circle cx="35" cy="36" r="8" fill="none" stroke="#3B82F6" stroke-width="2.6"/>' +
      '<circle cx="51" cy="36" r="8" fill="none" stroke="#10A37F" stroke-width="2.6"/>' +
      '<circle cx="43" cy="36" r="2.6" fill="var(--accent-bridge, #E9A820)"/>' +
      '<line x1="74" y1="36" x2="88" y2="36" stroke="var(--ip-ring, #94A3B8)" stroke-width="2.6" stroke-linecap="round"/>' +
      '<rect x="90" y="26" width="18" height="20" rx="5" fill="var(--accent-bridge, #E9A820)"/>' +
      '<text x="99" y="40.2" text-anchor="middle" fill="#FFFFFF" font-family="ui-monospace, \'Cascadia Mono\', monospace" font-weight="800" font-size="12.5">2</text>' +
      '<line x1="110" y1="36" x2="118" y2="36" stroke="var(--ip-ring, #94A3B8)" stroke-width="2.6" stroke-linecap="round"/>' +
      '<rect x="120" y="16" width="52" height="40" rx="10" fill="var(--brand, #1F6E58)"/>' +
      '<path d="M132 30L141 36.5L132 43" stroke="var(--ip-eye, #FFFFFF)" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" fill="none"/>' +
      '<line class="cursor-blink" x1="146" y1="43" x2="160" y2="43" stroke="var(--accent-bridge, #E9A820)" stroke-width="3" stroke-linecap="round"/>'
    );
  }

  function renderMinimalBridge64() {
    return (
      '<rect x="2" y="2" width="60" height="60" rx="14.5" fill="var(--surface, #FFFFFF)" stroke="var(--border, #E2DFD5)" stroke-width="1.5"/>' +
      '<rect x="10" y="12" width="24" height="20" rx="6" fill="none" stroke="var(--brand, #1F6E58)" stroke-width="2.4"/>' +
      '<circle cx="19" cy="22" r="4" stroke="#3B82F6" stroke-width="2" fill="none"/>' +
      '<circle cx="25" cy="22" r="4" stroke="#10A37F" stroke-width="2" fill="none"/>' +
      '<path d="M22 35V42H30" stroke="var(--accent-bridge, #E9A820)" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" fill="none"/>' +
      '<rect x="30" y="31" width="24" height="21" rx="6" fill="var(--brand, #1F6E58)"/>' +
      '<path d="M36 38L41 41.8L36 45.6" stroke="var(--ip-eye, #FFFFFF)" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round" fill="none"/>' +
      '<line class="cursor-blink" x1="43.5" y1="45.6" x2="49" y2="45.6" stroke="var(--accent-bridge, #E9A820)" stroke-width="2.3" stroke-linecap="round"/>'
    );
  }

  // --- 32x32 Favicon Renderer ---
  function renderFavicon32(ipPack, pose) {
    if (ipPack === "minimal-bridge") {
      return (
        '<rect x="1.5" y="1.5" width="29" height="29" rx="7" fill="var(--brand, #1F6E58)"/>' +
        '<circle cx="10.5" cy="11.5" r="4" stroke="#60A5FA" stroke-width="2" fill="none"/>' +
        '<path d="M13 18.5L17.5 22L13 25.5" stroke="#FFFFFF" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" fill="none"/>' +
        '<line x1="20" y1="25.5" x2="25.5" y2="25.5" stroke="var(--accent-bridge, #E9A820)" stroke-width="2.4" stroke-linecap="round"/>'
      );
    }
    var isLeft = ipPack === "orbit-turn" && pose === "turn-left";
    var eyeLeftCx = isLeft ? "9.5" : "11.2";
    var eyeLeftRx = isLeft ? "2.0" : "1.4";
    var eyeRightCx = isLeft ? "14.5" : "16.0";
    var eyeRightRx = isLeft ? "1.4" : "2.0";
    return (
      '<rect x="1" y="1" width="30" height="30" rx="7.5" fill="#132A23" stroke="var(--brand, #2B8A6E)" stroke-width="1.2"/>' +
      renderGeminiStar(6.2, 6.2, 3.8, "#3B82F6") +
      '<rect x="2.2" y="12.2" width="2.8" height="5.4" rx="1.4" fill="var(--accent-bridge, #E9A820)"/>' +
      '<rect x="4.2" y="8" width="16.5" height="13.5" rx="4.8" fill="var(--brand, #1F6E58)"/>' +
      '<rect x="7.4" y="10.2" width="11.8" height="9.2" rx="3" fill="rgba(8, 18, 15, 0.45)"/>' +
      '<ellipse cx="' + eyeLeftCx + '" cy="14.8" rx="' + eyeLeftRx + '" ry="2.3" fill="var(--ip-eye, #FFFFFF)"/>' +
      '<ellipse cx="' + eyeRightCx + '" cy="14.8" rx="' + eyeRightRx + '" ry="2.5" fill="var(--ip-eye, #FFFFFF)"/>' +
      '<rect x="16.2" y="16.5" width="14.2" height="13" rx="3.8" fill="#0B1017" stroke="var(--accent-bridge, #E9A820)" stroke-width="1.5"/>' +
      '<path d="M19.4 20.4L22.6 23L19.4 25.6" stroke="#FFFFFF" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" fill="none"/>' +
      '<line x1="24.4" y1="25.6" x2="28" y2="25.6" stroke="var(--accent-bridge, #E9A820)" stroke-width="2.2" stroke-linecap="round"/>'
    );
  }

  function renderWideInner(ipPack, pose, uid, isHero) {
    if (ipPack === "orbit-v2-mask") return renderOrbitV2Mask186(uid);
    if (ipPack === "obsidian-peel") return renderObsidianPeel186(uid);
    if (ipPack === "minimal-bridge") return renderMinimalBridge186();
    return renderOrbitTurnHead186(pose, uid, Boolean(isHero)) + renderBridgeAndTerminal186(pose);
  }

  function renderMark(slotType, opts) {
    var options = opts || {};
    var slot = slotType || "header-mark";
    var ipPack = options.ipPack || state.ipPack || "orbit-turn";
    var pose = options.pose || state.pose || "turn-right";
    var uid = options.idPrefix ? String(options.idPrefix) : nextUid("w2p");

    // Check custom IP pack renderer first
    if (customIpRenderers[ipPack] && typeof customIpRenderers[ipPack] === "function") {
      var customOut = customIpRenderers[ipPack](slot, {
        ipPack: ipPack,
        pose: pose,
        theme: options.theme || state.theme,
        stylePack: options.stylePack || state.stylePack,
        uid: uid
      });
      if (typeof customOut === "string" && customOut.indexOf("<svg") !== -1) {
        return customOut;
      }
    }

    var viewBox = "0 0 186 72";
    var clsList = ["w2p-svg"];
    if (slot === "header-mark") {
      clsList.push("brand-mark-svg");
      viewBox = "0 0 186 72";
    } else if (slot === "consent-mark") {
      clsList.push("brand-mark-svg", "consent-mark-svg");
      viewBox = "0 0 186 72";
    } else if (slot === "hero-logo") {
      clsList.push("hero-logo-svg");
      viewBox = "0 0 580 360";
    } else if (slot === "app-icon") {
      clsList.push("app-icon-svg");
      viewBox = "0 0 64 64";
    } else if (slot === "favicon") {
      clsList.push("favicon-svg");
      viewBox = "0 0 32 32";
    }
    if (options.className) {
      clsList.push(String(options.className));
    }

    var inlineStyleParts = [];
    if (options.gazeX !== undefined && options.gazeX !== null) {
      inlineStyleParts.push("--ip-gaze-x:" + (typeof options.gazeX === "number" ? options.gazeX + "px" : String(options.gazeX)));
    }
    if (options.gazeY !== undefined && options.gazeY !== null) {
      inlineStyleParts.push("--ip-gaze-y:" + (typeof options.gazeY === "number" ? options.gazeY + "px" : String(options.gazeY)));
    }
    var styleAttr = inlineStyleParts.length ? ' style="' + escapeAttr(inlineStyleParts.join(";")) + '"' : "";
    var sizeAttrs = "";
    if (options.width) sizeAttrs += ' width="' + escapeAttr(options.width) + '"';
    if (options.height) sizeAttrs += ' height="' + escapeAttr(options.height) + '"';

    var body = "";
    if (slot === "favicon") {
      body = renderFavicon32(ipPack, pose);
    } else if (slot === "app-icon") {
      if (ipPack === "orbit-v2-mask") body = renderOrbitV2Mask64(uid);
      else if (ipPack === "obsidian-peel") body = renderObsidianPeel64(uid);
      else if (ipPack === "minimal-bridge") body = renderMinimalBridge64();
      else body = renderOrbitTurnAppIcon64(pose, uid);
    } else if (slot === "hero-logo") {
      body =
        '<g transform="translate(26 16) scale(2.84)">' +
          renderWideInner(ipPack, pose, uid, true) +
        "</g>" +
        renderWordmark580(324);
    } else {
      body = renderWideInner(ipPack, pose, uid);
    }

    return (
      '<svg xmlns="http://www.w3.org/2000/svg" class="' +
      escapeAttr(clsList.join(" ")) +
      '" viewBox="' +
      viewBox +
      '"' +
      sizeAttrs +
      styleAttr +
      ' fill="none" data-rendered-ip="' +
      escapeAttr(ipPack) +
      '" data-rendered-pose="' +
      escapeAttr(pose) +
      '" aria-hidden="true">' +
      body +
      "</svg>"
    );
  }

  // --- State & DOM Synchronization ---
  function getState() {
    return {
      theme: state.theme,
      stylePack: state.stylePack,
      ipPack: state.ipPack,
      pose: state.pose
    };
  }

  function syncRootAttributes() {
    if (typeof document === "undefined" || !document.documentElement) return;
    applyingDomAttrs = true;
    try {
      var root = document.documentElement;
      root.setAttribute("data-theme", state.theme);
      root.setAttribute("data-style-pack", state.stylePack);
      root.setAttribute("data-ip-pack", state.ipPack);
      root.setAttribute("data-ip-pose", state.pose);
      var legacyBtn = document.getElementById("theme-toggle-btn");
      if (legacyBtn) {
        legacyBtn.textContent = state.theme === "dark" ? "浅色模式" : "深色模式";
      }
    } finally {
      applyingDomAttrs = false;
    }
  }

  function persistAll() {
    safeStorageSet(STORAGE_KEYS.theme, state.theme);
    safeStorageSet(STORAGE_KEYS.legacyTheme, state.theme);
    safeStorageSet(STORAGE_KEYS.stylePack, state.stylePack);
    safeStorageSet(STORAGE_KEYS.ipPack, state.ipPack);
    safeStorageSet(STORAGE_KEYS.pose, state.pose);
  }

  function dispatchAppearanceChange() {
    if (typeof global.dispatchEvent !== "function" || typeof global.CustomEvent !== "function") return;
    global.dispatchEvent(
      new global.CustomEvent("webai2pc:appearance-change", {
        detail: getState()
      })
    );
  }

  function refreshAllMountedSwitchers() {
    if (typeof document === "undefined") return;
    var wrappers = document.querySelectorAll(".w2p-sw-wrap");
    for (var i = 0; i < wrappers.length; i++) {
      if (typeof wrappers[i]._w2pRefresh === "function") {
        wrappers[i]._w2pRefresh();
      }
    }
  }

  function applyMutationAndBroadcast() {
    syncRootAttributes();
    persistAll();
    if (typeof document !== "undefined") {
      mountAll(document);
      refreshAllMountedSwitchers();
    }
    dispatchAppearanceChange();
    return getState();
  }

  function setTheme(mode) {
    var next = mode === "toggle" ? (state.theme === "dark" ? "light" : "dark") : mode === "dark" ? "dark" : "light";
    state.theme = next;
    return applyMutationAndBroadcast();
  }

  function setStylePack(packId) {
    if (findById(STYLE_PACKS, packId)) {
      state.stylePack = packId;
    }
    return applyMutationAndBroadcast();
  }

  function setIpPack(ipId) {
    if (findById(IP_PACKS, ipId)) {
      state.ipPack = ipId;
    }
    return applyMutationAndBroadcast();
  }

  function setPose(poseId) {
    if (findById(POSES, poseId)) {
      state.pose = poseId;
    }
    return applyMutationAndBroadcast();
  }

  // --- Extensible Registration API ---
  function registerStylePack(id, spec) {
    if (!id || typeof id !== "string" || !spec || typeof spec !== "object") return false;
    var cleanId = id.trim();
    if (!cleanId) return false;
    var entry = {
      id: cleanId,
      name: String(spec.name || cleanId),
      desc: String(spec.desc || ""),
      swatches: Array.isArray(spec.swatches) && spec.swatches.length >= 3
        ? spec.swatches.slice(0, 3)
        : ["#F7F6F2", "#1F6E58", "#E9A820"]
    };
    var existingIdx = -1;
    for (var i = 0; i < STYLE_PACKS.length; i++) {
      if (STYLE_PACKS[i].id === cleanId) {
        existingIdx = i;
        break;
      }
    }
    if (existingIdx >= 0) STYLE_PACKS[existingIdx] = entry;
    else STYLE_PACKS.push(entry);

    customStyleSpecs[cleanId] = spec;
    ensureBaseStylesInjected();
    rebuildCustomPackStyles();
    refreshAllMountedSwitchers();
    return true;
  }

  function registerIpPack(id, spec) {
    if (!id || typeof id !== "string" || !spec || typeof spec !== "object") return false;
    var cleanId = id.trim();
    if (!cleanId) return false;
    var entry = {
      id: cleanId,
      name: String(spec.name || cleanId),
      desc: String(spec.desc || ""),
      supportsPose: Boolean(spec.supportsPose)
    };
    var existingIdx = -1;
    for (var i = 0; i < IP_PACKS.length; i++) {
      if (IP_PACKS[i].id === cleanId) {
        existingIdx = i;
        break;
      }
    }
    if (existingIdx >= 0) IP_PACKS[existingIdx] = entry;
    else IP_PACKS.push(entry);

    if (typeof spec.render === "function") {
      customIpRenderers[cleanId] = spec.render;
    } else if (spec.svgMap && typeof spec.svgMap === "object") {
      customIpRenderers[cleanId] = function (slotType) {
        return spec.svgMap[slotType] || spec.svgMap["header-mark"] || "";
      };
    }
    if (spec.cssVars || spec.variables) {
      customIpCssVars[cleanId] = spec.cssVars || spec.variables;
    }
    ensureBaseStylesInjected();
    rebuildCustomPackStyles();
    if (state.ipPack === cleanId && typeof document !== "undefined") {
      mountAll(document);
    }
    refreshAllMountedSwitchers();
    return true;
  }

  // --- Promo Video Pipeline StylePack Exporter ---
  function resolvePackTokens(packId, mode) {
    var builtin = BUILTIN_STYLE_TOKENS[packId] || BUILTIN_STYLE_TOKENS["warm-paper"];
    var custom = customStyleSpecs[packId];
    var base = Object.assign({}, builtin[mode] || builtin.light);
    if (custom) {
      var extra = mode === "dark" ? (custom.dark || custom.darkCssVars) : (custom.light || custom.cssVars || custom.variables);
      if (extra && typeof extra === "object") {
        Object.assign(base, extra);
      }
    }
    return base;
  }

  function exportPromoStylePack() {
    var styleEntry = findById(STYLE_PACKS, state.stylePack) || STYLE_PACKS[0];
    var ipEntry = findById(IP_PACKS, state.ipPack) || IP_PACKS[0];
    var lightTokens = resolvePackTokens(styleEntry.id, "light");
    var darkTokens = resolvePackTokens(styleEntry.id, "dark");
    var activeTokens = state.theme === "dark" ? darkTokens : lightTokens;

    return {
      schemaVersion: "1.0",
      product: "WebAI2PC",
      stylePack: {
        id: styleEntry.id,
        name: styleEntry.name,
        desc: styleEntry.desc,
        swatches: styleEntry.swatches.slice()
      },
      activeTheme: state.theme,
      palettes: {
        light: {
          canvas: lightTokens["--bg"],
          surface: lightTokens["--surface"],
          surfaceInset: lightTokens["--surface-inset"],
          border: lightTokens["--border"],
          text: lightTokens["--text"],
          muted: lightTokens["--muted"],
          brand: lightTokens["--brand"],
          accentBridge: lightTokens["--accent-bridge"],
          ipRing: lightTokens["--ip-ring"],
          ipEye: lightTokens["--ip-eye"],
          terminalBg: lightTokens["--term-bg"],
          terminalFg: lightTokens["--term-fg"],
          hostGemini: "#3B82F6",
          hostChatGPT: "#10A37F"
        },
        dark: {
          canvas: darkTokens["--bg"],
          surface: darkTokens["--surface"],
          surfaceInset: darkTokens["--surface-inset"],
          border: darkTokens["--border"],
          text: darkTokens["--text"],
          muted: darkTokens["--muted"],
          brand: darkTokens["--brand"],
          accentBridge: darkTokens["--accent-bridge"],
          ipRing: darkTokens["--ip-ring"],
          ipEye: darkTokens["--ip-eye"],
          terminalBg: darkTokens["--term-bg"],
          terminalFg: darkTokens["--term-fg"],
          hostGemini: "#3B82F6",
          hostChatGPT: "#10A37F"
        }
      },
      activeTokens: activeTokens,
      radii: {
        modal: 14,
        card: 12,
        inner: 8,
        control: 7,
        pill: 999
      },
      motion: {
        gazeDurationMs: 180,
        easing: "cubic-bezier(0.23, 1, 0.32, 1)",
        cubicBezier: [0.23, 1, 0.32, 1],
        highFreqSwitchMs: 120,
        cursorBlinkMs: 1150,
        reducedMotionSupported: true
      },
      ipConfig: {
        ipPack: ipEntry.id,
        name: ipEntry.name,
        supportsPose: ipEntry.supportsPose,
        pose: state.pose,
        viewBoxes: {
          headerMark: "0 0 186 72",
          consentMark: "0 0 186 72",
          heroLogo: "0 0 580 360",
          appIcon: "0 0 64 64",
          favicon: "0 0 32 32"
        }
      }
    };
  }

  // --- Slot & Switcher Mounting ---
  function mountAll(root) {
    if (typeof document === "undefined") return 0;
    var scope = root || document;
    var nodes = [];
    if (scope.nodeType === 1 && scope.hasAttribute && scope.hasAttribute("data-brand-slot")) {
      nodes.push(scope);
    }
    if (scope.querySelectorAll) {
      var found = scope.querySelectorAll("[data-brand-slot]");
      for (var i = 0; i < found.length; i++) {
        nodes.push(found[i]);
      }
    }
    for (var j = 0; j < nodes.length; j++) {
      var el = nodes[j];
      if (el.getAttribute("data-brand-locked") === "v2") continue;
      var slotType = el.getAttribute("data-brand-slot") || "header-mark";
      var slotIp = el.getAttribute("data-slot-ip") || undefined;
      var slotPose = el.getAttribute("data-slot-pose") || undefined;
      var slotCls = el.getAttribute("data-slot-class") || undefined;
      el.innerHTML = renderMark(slotType, {
        ipPack: slotIp,
        pose: slotPose,
        className: slotCls
      });
    }

    if (scope.querySelectorAll) {
      var swContainers = scope.querySelectorAll("[data-appearance-switcher]");
      for (var k = 0; k < swContainers.length; k++) {
        if (!swContainers[k].querySelector(".w2p-sw-wrap")) {
          mountSwitcher(swContainers[k]);
        }
      }
    }
    return nodes.length;
  }

  function bindGlobalPopoverListeners() {
    if (listenersBound || typeof document === "undefined") return;
    listenersBound = true;

    document.addEventListener("click", function (ev) {
      if (!activePopoverCloseFn) return;
      var target = ev.target;
      if (target && target.closest && target.closest(".w2p-sw-wrap")) return;
      activePopoverCloseFn(false);
    });

    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape" && activePopoverCloseFn) {
        activePopoverCloseFn(true);
      }
    });

    if (document.documentElement && typeof MutationObserver === "function" && !themeObserver) {
      themeObserver = new MutationObserver(function () {
        if (applyingDomAttrs) return;
        var domTheme = document.documentElement.getAttribute("data-theme");
        if ((domTheme === "light" || domTheme === "dark") && domTheme !== state.theme) {
          state.theme = domTheme;
          safeStorageSet(STORAGE_KEYS.theme, state.theme);
          safeStorageSet(STORAGE_KEYS.legacyTheme, state.theme);
          refreshAllMountedSwitchers();
          dispatchAppearanceChange();
        }
      });
      themeObserver.observe(document.documentElement, {
        attributes: true,
        attributeFilter: ["data-theme"]
      });
    }
  }

  function copyJsonText(text, onDone) {
    if (global.navigator && global.navigator.clipboard && typeof global.navigator.clipboard.writeText === "function") {
      global.navigator.clipboard.writeText(text).then(
        function () { onDone(true); },
        function () { fallbackCopy(text, onDone); }
      );
      return;
    }
    fallbackCopy(text, onDone);
  }

  function fallbackCopy(text, onDone) {
    try {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "readonly");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      ta.style.pointerEvents = "none";
      document.body.appendChild(ta);
      ta.select();
      var ok = document.execCommand("copy");
      document.body.removeChild(ta);
      onDone(Boolean(ok));
    } catch (e) {
      onDone(false);
    }
  }

  function mountSwitcher(containerEl, opts) {
    if (typeof document === "undefined") return null;
    var host = typeof containerEl === "string" ? document.querySelector(containerEl) : containerEl;
    if (!host) return null;

    ensureBaseStylesInjected();
    bindGlobalPopoverListeners();

    var options = opts || {};
    var isInline = Boolean(options.inline || host.getAttribute("data-appearance-inline") === "1");
    host.innerHTML = "";

    var wrap = document.createElement("div");
    wrap.className = isInline ? "w2p-sw-wrap w2p-sw-inline-wrap" : "w2p-sw-wrap";

    var trigger = document.createElement("button");
    trigger.type = "button";
    trigger.className = "w2p-sw-trigger";
    trigger.setAttribute("aria-haspopup", "dialog");
    trigger.setAttribute("aria-expanded", "false");
    trigger.title = options.title || "切换外观风格、IP 图标包与转向姿态";

    var popover = document.createElement("div");
    popover.className = isInline ? "w2p-sw-inline-panel" : "w2p-sw-popover";
    if (!isInline) {
      popover.setAttribute("role", "dialog");
      popover.setAttribute("aria-label", "外观风格与品牌图标设置");
    }

    function closePopover(restoreFocus) {
      popover.classList.remove("open");
      trigger.setAttribute("aria-expanded", "false");
      if (activePopoverCloseFn === closePopover) {
        activePopoverCloseFn = null;
      }
      if (restoreFocus) {
        try { trigger.focus({ preventScroll: true }); } catch (e) {}
      }
    }

    trigger.addEventListener("click", function (ev) {
      ev.stopPropagation();
      var isOpen = popover.classList.contains("open");
      if (activePopoverCloseFn && activePopoverCloseFn !== closePopover) {
        activePopoverCloseFn(false);
      }
      if (isOpen) {
        closePopover(false);
      } else {
        renderPopoverContents();
        popover.classList.add("open");
        trigger.setAttribute("aria-expanded", "true");
        activePopoverCloseFn = closePopover;
      }
    });

    function renderTriggerContents() {
      var curStyle = findById(STYLE_PACKS, state.stylePack) || STYLE_PACKS[0];
      var sw = curStyle.swatches || ["#F7F6F2", "#1F6E58", "#E9A820"];
      var labelText = options.compactLabel ? "外观" : ("外观 · " + curStyle.name);
      trigger.innerHTML =
        '<span class="w2p-sw-dots" aria-hidden="true">' +
          '<span class="w2p-sw-dot" style="background:' + escapeAttr(sw[1]) + '"></span>' +
          '<span class="w2p-sw-dot" style="background:' + escapeAttr(sw[2]) + '"></span>' +
        "</span>" +
        "<span>" + escapeAttr(labelText) + "</span>";
    }

    function renderPopoverContents() {
      var curIp = findById(IP_PACKS, state.ipPack) || IP_PACKS[0];
      var html = "";

      // 1. Theme Mode
      html +=
        "<div>" +
          '<div class="w2p-sw-sec-hd"><span>明暗主题</span><span>' + (state.theme === "dark" ? "深色工作台" : "浅色工作台") + "</span></div>" +
          '<div class="w2p-sw-seg">' +
            '<button type="button" class="w2p-sw-seg-btn' + (state.theme === "light" ? " active" : "") + '" data-w2p-theme="light">浅色模式</button>' +
            '<button type="button" class="w2p-sw-seg-btn' + (state.theme === "dark" ? " active" : "") + '" data-w2p-theme="dark">深色模式</button>' +
          "</div>" +
        "</div>";

      // 2. Style Packs
      html += '<div><div class="w2p-sw-sec-hd"><span>外观风格包</span><span>' + STYLE_PACKS.length + " 套</span></div><div class=\"w2p-sw-grid2\">";
      for (var i = 0; i < STYLE_PACKS.length; i++) {
        var sp = STYLE_PACKS[i];
        var sw = sp.swatches || ["#F7F6F2", "#1F6E58", "#E9A820"];
        html +=
          '<button type="button" class="w2p-sw-card' + (state.stylePack === sp.id ? " active" : "") + '" data-w2p-style="' + escapeAttr(sp.id) + '">' +
            '<div class="w2p-sw-card-top">' +
              '<span class="w2p-sw-card-title">' + escapeAttr(sp.name) + "</span>" +
              '<span class="w2p-sw-dots">' +
                '<span class="w2p-sw-dot" style="background:' + escapeAttr(sw[0]) + '"></span>' +
                '<span class="w2p-sw-dot" style="background:' + escapeAttr(sw[1]) + '"></span>' +
                '<span class="w2p-sw-dot" style="background:' + escapeAttr(sw[2]) + '"></span>' +
              "</span>" +
            "</div>" +
            '<span class="w2p-sw-card-sub">' + escapeAttr(sp.desc) + "</span>" +
          "</button>";
      }
      html += "</div></div>";

      // 3. IP Packs
      html += '<div><div class="w2p-sw-sec-hd"><span>IP 图标包</span><span>' + IP_PACKS.length + ' 款可选</span></div><div class="w2p-sw-grid2">';
      for (var j = 0; j < IP_PACKS.length; j++) {
        var ip = IP_PACKS[j];
        html +=
          '<button type="button" class="w2p-sw-card' + (state.ipPack === ip.id ? " active" : "") + '" data-w2p-ip="' + escapeAttr(ip.id) + '">' +
            '<div class="w2p-sw-ip-preview">' + renderMark("header-mark", { ipPack: ip.id, pose: state.pose }) + "</div>" +
            '<span class="w2p-sw-card-title">' + escapeAttr(ip.name) + "</span>" +
          "</button>";
      }
      html += "</div></div>";

      // 4. Poses
      html +=
        "<div>" +
          '<div class="w2p-sw-sec-hd"><span>IP 转向姿态</span><span>' + (curIp.supportsPose ? "实时联动" : "仅转向包生效") + "</span></div>" +
          '<div class="w2p-sw-seg w2p-sw-seg4">';
      for (var k = 0; k < POSES.length; k++) {
        var pz = POSES[k];
        html +=
          '<button type="button" class="w2p-sw-seg-btn' +
          (state.pose === pz.id ? " active" : "") +
          '" data-w2p-pose="' +
          escapeAttr(pz.id) +
          '"' +
          (!curIp.supportsPose ? " disabled" : "") +
          ">" +
          escapeAttr(pz.label) +
          "</button>";
      }
      html += "</div>";
      if (!curIp.supportsPose) {
        html += '<div class="w2p-sw-hint">切换至「星环小代理 · 3/4 转向」可调节 4 种视线姿态</div>';
      }
      html += "</div>";

      // 5. Promo StylePack JSON Copy (debug=1 only)
      var showDebugPromo = Boolean(
        global.location && String(global.location.search || "").indexOf("debug=1") !== -1
      );
      if (showDebugPromo) {
        html +=
          '<div class="w2p-sw-foot">' +
            '<button type="button" class="w2p-sw-copy-btn" data-w2p-copy-promo="1">复制宣传片 StylePack JSON</button>' +
          "</div>";
      }

      popover.innerHTML = html;
    }

    popover.addEventListener("click", function (ev) {
      var btn = ev.target && ev.target.closest ? ev.target.closest("button") : null;
      if (!btn) return;
      if (btn.hasAttribute("data-w2p-theme")) {
        setTheme(btn.getAttribute("data-w2p-theme"));
      } else if (btn.hasAttribute("data-w2p-style")) {
        setStylePack(btn.getAttribute("data-w2p-style"));
      } else if (btn.hasAttribute("data-w2p-ip")) {
        setIpPack(btn.getAttribute("data-w2p-ip"));
      } else if (btn.hasAttribute("data-w2p-pose") && !btn.disabled) {
        setPose(btn.getAttribute("data-w2p-pose"));
      } else if (btn.hasAttribute("data-w2p-copy-promo")) {
        var jsonPayload = JSON.stringify(exportPromoStylePack(), null, 2);
        copyJsonText(jsonPayload, function (ok) {
          btn.textContent = ok ? "已复制 StylePack JSON ✓" : "复制失败，请重试";
          setTimeout(function () {
            if (btn.isConnected) btn.textContent = "复制宣传片 StylePack JSON";
          }, 1600);
        });
      }
    });

    wrap._w2pRefresh = function () {
      if (isInline) {
        renderPopoverContents();
        return;
      }
      renderTriggerContents();
      if (popover.classList.contains("open")) {
        renderPopoverContents();
      }
    };

    if (isInline) {
      renderPopoverContents();
      wrap.appendChild(popover);
    } else {
      renderTriggerContents();
      wrap.appendChild(trigger);
      wrap.appendChild(popover);
    }
    host.appendChild(wrap);
    return wrap;
  }

  function hydrateInitialState() {
    var savedTheme = safeStorageGet(STORAGE_KEYS.theme) || safeStorageGet(STORAGE_KEYS.legacyTheme);
    var savedStyle = safeStorageGet(STORAGE_KEYS.stylePack);
    var savedIp = safeStorageGet(STORAGE_KEYS.ipPack);
    var savedPose = safeStorageGet(STORAGE_KEYS.pose);

    if (savedTheme === "dark" || savedTheme === "light") state.theme = savedTheme;
    if (savedStyle && findById(STYLE_PACKS, savedStyle)) state.stylePack = savedStyle;
    if (savedIp && findById(IP_PACKS, savedIp)) state.ipPack = savedIp;
    if (savedPose && findById(POSES, savedPose)) state.pose = savedPose;

    try {
      if (global.location && global.location.search && typeof URLSearchParams === "function") {
        var params = new URLSearchParams(global.location.search);
        var qTheme = params.get("theme");
        var qStyle = params.get("style");
        var qIp = params.get("ip");
        var qPose = params.get("pose");
        if (qTheme === "dark" || qTheme === "light") state.theme = qTheme;
        if (qStyle && findById(STYLE_PACKS, qStyle)) state.stylePack = qStyle;
        if (qIp && findById(IP_PACKS, qIp)) state.ipPack = qIp;
        if (qPose && findById(POSES, qPose)) state.pose = qPose;
      }
    } catch (e) {}
  }

  function init() {
    hydrateInitialState();
    ensureBaseStylesInjected();
    rebuildCustomPackStyles();
    syncRootAttributes();
    persistAll();
    bindGlobalPopoverListeners();
    if (typeof document !== "undefined" && document.body) {
      mountAll(document);
      refreshAllMountedSwitchers();
    }
    return getState();
  }

  // Zero-FOUC early paint bootstrap before body finishes parsing
  if (typeof document !== "undefined" && document.documentElement) {
    hydrateInitialState();
    ensureBaseStylesInjected();
    syncRootAttributes();
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", function () {
        init();
      });
    } else {
      init();
    }
  }

  var api = {
    STYLE_PACKS: STYLE_PACKS,
    IP_PACKS: IP_PACKS,
    POSES: POSES,
    getState: getState,
    setTheme: setTheme,
    setStylePack: setStylePack,
    setIpPack: setIpPack,
    setPose: setPose,
    registerStylePack: registerStylePack,
    registerIpPack: registerIpPack,
    exportPromoStylePack: exportPromoStylePack,
    renderMark: renderMark,
    mountAll: mountAll,
    mountSwitcher: mountSwitcher,
    init: init
  };

  global.WebAI2PCBrand = api;
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof window !== "undefined" ? window : globalThis);
