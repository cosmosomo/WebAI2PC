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

/* ==========================================================================
   WebAI2PC Shared Bilingual i18n Engine (ZH / EN)
   Default: "zh" (preserves canonical Chinese DOM verbatim)
   Toggle:  #lang-toggle-btn in top header (persisted in localStorage)
   ========================================================================== */
(function (global) {
  "use strict";
  if (typeof document === "undefined" || typeof window === "undefined") return;

  var STORAGE_KEY = "webai2pc_lang";
  var ZH_TO_EN = {
    "WebAI2PC · 本地控制台": "WebAI2PC · Local Console",
    "WebAI2PC · 交互式使用教程": "WebAI2PC · Interactive Guides",
    "· 交互式使用教程": "· Interactive Guides",
    "在线": "Online",
    "离线": "Offline",
    "连接中": "Connecting",
    "工作区开发": "Workspace Dev",
    "全盘开发": "Full-Disk Dev",
    "仅改文件": "Edit Files Only",
    "只读": "Read-Only",
    "一键只读": "Read-Only",
    "恢复开发": "Resume Dev",
    "实战教程": "Guides",
    "设置": "Settings",
    "← 返回主控台": "← Back to Console",
    "返回 Studio 控制台": "Back to Console",
    "深色模式": "Dark Mode",
    "浅色模式": "Light Mode",
    "离线示例预览": "Offline Preview",
    "正在检测本地 Studio 服务连接状态…": "Checking local Studio service status…",
    "输入本机连接口令解锁本地应急开关": "Enter Local Passcode to Unlock Controls",
    "安全控制面板默认仅开放本机": "This console defaults to local loopback",
    "访问（公网网关自动拦截外部管理请求）；本机会话失效时可输入口令重新验证本地应急开关。": "access only (public gateways block external admin requests). Re-enter your passcode if the local session expires.",
    "显示": "Show",
    "隐藏": "Hide",
    "验证并解锁": "Verify & Unlock",
    "本机直连已自动授权": "Local loopback auto-authorized",
    "解锁会话": "Unlock Session",
    "复制 /mcp 地址": "Copy /mcp URL",
    "网页版 Gemini": "Web Gemini",
    "网页版 ChatGPT": "Web ChatGPT",
    "已连": "Connected",
    "复制连接地址": "Copy MCP URL",
    "复制 Gemini 连接地址": "Copy Gemini MCP URL",
    "复制 ChatGPT 连接地址": "Copy ChatGPT MCP URL",
    "已复制": "Copied",
    "详情与配对 ▾": "Details & Pairing ▾",
    "收起详情 ▴": "Hide Details ▴",
    "接入向导": "Setup Wizard",
    "首次接入向导": "Quick Setup",
    "3 步连上你的网页端 AI": "Connect Your Web AI in 3 Steps",
    "语言、平台与资源": "Preferences & Assets",
    "生成网址并授权": "Generate URL & Connect",
    "选目录与首句验证": "Folder & First Prompt",
    "让 AI 带我配": "AI-Guided Setup",
    "跳过向导 ×": "Skip ×",
    "1. 界面语言": "1. Interface Language",
    "2. 准备连接哪个网页 AI？": "2. Which Web AI are you connecting?",
    "网页版 Google Gemini": "Web Google Gemini",
    "支持桌面浏览器任务模式与同账号手机端 Gemini App 同步远控": "Works with desktop Gemini Task Mode and mobile Gemini App on the same account",
    "装好后日常用普通 Chat 零智能体额度改代码，长任务用 Work": "Use regular Chat daily with zero agent quota cost, and Work for long tasks",
    "账号类型：": "Account plan:",
    "Team / Business / Edu（全功能）": "Team / Business / Edu (Full R/W)",
    "个人 Plus / Pro（只读）": "Personal Plus / Pro (Read-Only)",
    "3. 勾选你手头已有的资源（可不勾，直接免注册开箱用）": "3. Check any resources you already have (optional — works out-of-the-box without any)",
    "我有 Cloudflare 账号（或愿用 Google 快捷登录）": "I have a Cloudflare account (or can sign in with Google)",
    "粘贴一次令牌，3 秒自动部署免费专属网关（": "Paste a token once to deploy a free permanent gateway (",
    "），关机重启永不变址。": ") in 3s — URL never changes across reboots.",
    "我有自己的云服务器（VPS）或自有固定域名": "I have my own cloud server (VPS) or custom HTTPS domain",
    "一键在云服务器部署 24 小时常驻主站，或接入已有 HTTPS 反代与隧道域名。": "Deploy a 24/7 VPS relay in one click or attach an existing HTTPS domain/tunnel.",
    "未勾选额外资源：将使用「免登录直连固定通道」，零注册直接生成连接网址。": "No extra accounts checked: using Instant No-Login Direct Tunnel out of the box.",
    "已选 Cloudflare 账号：下一步将引导你 3 秒自动部署终身固定网址（*.workers.dev）。": "Cloudflare selected: Step 2 will deploy your permanent *.workers.dev gateway in 3 seconds.",
    "已选自有云服务器 / 域名：下一步将引导你一键部署 24h 主站或绑定自有 HTTPS 域名。": "VPS / Domain selected: Step 2 will set up your 24/7 VPS relay or custom HTTPS domain.",
    "已勾选两项资源：下一步默认优先使用更省心的「Cloudflare 3 秒固定网关」，也可一键切到自有服务器。": "Both checked: defaulting to Cloudflare 3s Fixed Gateway (easiest), with a 1-click switch to your VPS.",
    "所有设置后续随时可在右上角「设置」中更改": "You can change any of these anytime in Settings",
    "下一步：生成连接网址 →": "Next: Generate MCP URL →",
    "你同时勾选了两项资源，当前使用：": "Both assets checked — active route:",
    "Cloudflare 3 秒固定网关（省心推荐）": "Cloudflare 3s Fixed Gateway (Recommended)",
    "自有云服务器 / 域名": "My Cloud Server / Domain",
    "部署 Cloudflare 专属固定网关": "Deploy Cloudflare Fixed Gateway",
    "令牌仅用于本次部署，完成后立即销毁": "Token is used once and wiped immediately after deploy",
    "① 打开 Cloudflare 预填令牌页": "① Open Cloudflare Token Page",
    "② 粘贴生成的 Cloudflare API 令牌": "② Paste Cloudflare API Token",
    "选填：自定义域名（无则留空）": "Optional: Custom domain (leave blank if none)",
    "③ 3 秒部署固定网址": "③ Deploy in 3s",
    "接入自有云服务器或固定域名": "Connect Your VPS or Custom Domain",
    "云服务器一键建主站": "1-Click 24/7 VPS Relay",
    "已有 HTTPS 域名": "Existing HTTPS Domain",
    "服务器公网 IP（如 203.0.113.10）": "Server public IP (e.g. 203.0.113.10)",
    "SSH 密码（已配本机密钥可留空）": "SSH password (leave blank if using local SSH key)",
    "一键部署 24h 主站": "Deploy 24/7 Relay",
    "输入已反代本机端口的完整 HTTPS 域名（如 https://mcp.example.com）": "Full HTTPS domain forwarding to this PC (e.g. https://mcp.example.com)",
    "保存并启用此域名": "Save & Enable Domain",
    "请先完成上方 Cloudflare 3 秒部署以生成固定网址…": "Complete the 3s Cloudflare deploy above to generate your fixed URL…",
    "请先完成上方云服务器或固定域名配置…": "Complete the VPS or custom domain setup above first…",
    "复制地址并打开 Gemini 连接器": "Copy URL & Open Gemini Connectors",
    "复制地址并打开 ChatGPT 插件页": "Copy URL & Open ChatGPT Plugins",
    "仅复制地址": "Copy URL Only",
    "在打开的 Gemini 页面点": "In Gemini Connectors, click",
    "，名称填": ", set Name to",
    "，粘贴上方地址（Client ID / Secret 留空）。": ", and paste the URL above (leave Client ID / Secret blank).",
    "弹出确认页点绿色": "On the consent screen, click",
    "「本机一键允许连接」": "\"Allow from This PC\"",
    "（若用手机绑则核对配对码：": " (or verify code on mobile: ",
    "），随后在连接器详情把": "), then set",
    "设为": "to",
    "在本机已登录的 ChatGPT 左侧点": "In ChatGPT on this PC, open",
    "，粘贴上方地址并选": ", paste the URL above, choose",
    "创建后点": "and click",
    "跳转确认页直接点绿色": "On the consent screen, click",
    "；若想让 ChatGPT Work 模式受控浏览器代填，也可点：": "; or let ChatGPT Work mode fill it for you:",
    "正在等待网页端完成授权连接（点完允许后此处会自动变绿打勾）…": "Waiting for web host authorization (auto-completes once you click Allow)…",
    "正在等待网页端完成授权连接（点完允许后此处会自动打勾）…": "Waiting for web host authorization (auto-completes once you click Allow)…",
    "← 上一步": "← Back",
    "下一步：选目录与发首句 →": "Next: Folder & First Prompt →",
    "1. 确认开放给 AI 的本地工作目录": "1. Confirm Local Workspace Folder",
    "换个文件夹": "Change Folder",
    "AI 默认只在此目录内读写与运行代码；每次修改自动留存快照，可在主控台右栏一键撤回。": "AI reads/writes inside this folder by default. Every file edit saves an instant undo snapshot.",
    "2. 复制第一句测试指令发给网页端 AI": "2. Send Your First Test Prompt in Web AI",
    "复制首句测试词": "Copy Test Prompt",
    "4 步连上并体验你的网页端 AI": "Connect & Try Your Web AI in 4 Steps",
    "连上后立刻体验": "Try 3 Live Demos",
    "下一步：连上后立刻体验 →": "Next: Try 3 Live Demos →",
    "直接进入主控台": "Skip to Console",
    "选一个下面的一句话案例，复制后在对话框里输入": "Pick a one-shot demo below, copy the prompt, type",
    "选中你刚命名的连接器，粘贴发送即可看效果。": "in chat to pick your connector, and paste to run.",
    "完成并进入主控台": "Finish & Enter Console",
    "通道设置": "Gateways",
    "已连上网页端 AI · 首句发送唤醒词即可开始": "Web AI connected · Send the wake word to start",
    "复制首句唤醒测试词": "Copy First Wake Prompt",
    "复制 AI 操作守则（推荐存入 Skills）": "Copy AI Rules (Save to Skills)",
    "开机自启": "Launch at Login",
    "当前未开启公网 HTTPS 通道，网页端 AI 需要公网 HTTPS 地址才能连接。": "No public HTTPS gateway is active. Web AI hosts require an HTTPS endpoint.",
    "一键开启默认连接网关": "Enable Default Gateway",
    "本机浏览器暂未直连 *.workers.dev（首次绑定提示）": "Local browser cannot reach *.workers.dev directly (first-time setup)",
    "若浏览器打开连接器授权页加载缓慢，可在代理软件临时切全局 10 秒完成绑定，或在设置页填写自定义域名。": "If the connector consent page loads slowly, switch your proxy to Global for 10s or configure a custom domain in Settings.",
    "继续打开 Gemini": "Open Gemini Anyway",
    "自定义域名": "Custom Domain",
    "正在建立加密连接通道…": "Establishing encrypted tunnel…",
    "打开 Gemini 连接器": "Open Gemini Connectors",
    "Team / Business / Enterprise / Edu 工作区（全功能读写 · 装好后日常用 Chat 省额度，长任务用 Work）": "Team / Business / Enterprise / Edu Workspace (Full Read/Write · Use Chat daily to save quota, Work for long runs)",
    "Team / Business / Enterprise / Edu 工作区（全功能读写 · Chat 与 Work 通用）": "Team / Business / Enterprise / Edu Workspace (Full Read/Write · Chat & Work)",
    "复制地址": "Copy URL",
    "复制给 Work 模式帮我连接": "Copy for ChatGPT Work Mode Setup",
    "复制给 ChatGPT 帮我连接": "Copy for ChatGPT Setup",
    "个人 Plus / Pro 账号（只读连接 · 平台限制写工具时使用，装好后日常用 Chat 省额度）": "Personal Plus / Pro Account (Read-Only · Use when write tools are restricted)",
    "个人 Plus / Pro 账号（只读连接 · 平台限制写工具时使用）": "Personal Plus / Pro Account (Read-Only · Use when write tools are restricted)",
    "复制只读": "Copy Read-Only",
    "首次绑定步骤与唤醒词": "First-Time Setup & Wake Words",
    "复制唤醒词": "Copy Wake Word",
    "复制 AI 守则": "Copy AI Rules",
    "复制 ChatGPT 首句": "Copy ChatGPT Prompt",
    "复制 ChatGPT 守则": "Copy ChatGPT Rules",
    "图文教程": "Visual Guides",
    "配对与已连会话": "Pairing & Sessions",
    "6位码": "6-Digit Code",
    "核对": "Verify",
    "复制 6 位码": "Copy 6-Digit Code",
    "复制核对码": "Copy Verify Code",
    "20 位固定备用口令（仅回环被拦截时使用）": "20-Char Backup Passcode (only if loopback is blocked)",
    "显示口令": "Show Passcode",
    "复制备用口令": "Copy Backup Passcode",
    "已连接网页会话列表": "Connected Web Sessions",
    "全部断开": "Disconnect All",
    "开放工作目录": "Workspace Folders",
    "当前权限设置": "Permission Tier",
    "点击即生效": "Instant",
    "工作目录内读写与运行": "Read, edit & run inside workspaces",
    "不限目录读写与运行（高权限）": "Full-disk read, edit & run (elevated)",
    "仅查看与搜索，禁止改动": "View & search only, no writes",
    "仅修改文件，禁止运行命令": "Edit files only, no shell commands",
    "当前为「全盘开发（不限目录）」模式，下方列表仅作为未传路径时的默认起始目录。": "Full-Disk Dev mode is active. Folders below serve as default working directories when no path is given.",
    "添加": "Add",
    "选文件夹": "Browse…",
    "以只读参考目录添加": "Add as read-only reference",
    "浏览目录树": "Folder Tree",
    "常用目录快选 ▸": "Quick Picks ▸",
    "自动扫描的本机常见代码目录": "Detected local project directories",
    "刷新": "Refresh",
    "浏览本机盘符与文件夹": "Browse Local Drives & Folders",
    "收起": "Collapse",
    "盘符": "Drives",
    "上一级": "Up",
    "本机磁盘列表": "Local Drives",
    "添加当前目录": "Add Folder",
    "设为主目录": "Set Primary",
    "新建": "New Folder",
    "主读写目录": "Primary Read/Write",
    "只读参考目录": "Read-Only Reference",
    "读写": "Read/Write",
    "只读父目录": "Read-Only Parent",
    "移除": "Remove",
    "实时动态与撤回": "Live Activity & Undo",
    "在途任务": "Running Jobs",
    "修改撤回": "Undo Edits",
    "回收箱": "Trash",
    "调用记录": "Call Log",
    "查看后台命令输出流，可随时终止卡死进程": "Inspect background command streams and stop stuck processes anytime",
    "终止全部": "Stop All",
    "任务实时日志": "Live Job Output",
    "复制日志": "Copy Log",
    "关闭": "Close",
    "查看实时日志": "View Log",
    "写文件前自动留存快照，点「查看对比 Diff」审阅后回退": "Snapshots are saved before every edit. Review the diff and roll back in one click",
    "查看对比 Diff": "View Diff",
    "被清理的文件保存在可恢复安全回收箱，一键原位还原": "Deleted files stay in the recoverable trash for one-click restore",
    "原位还原": "Restore",
    "全部": "All",
    "仅异常": "Errors Only",
    "连接与网关": "Gateways",
    "待连": "Idle",
    "环境与系统": "Environment",
    "工具与扩展": "Tools & Packs",
    "工作区": "Workspace",
    "全盘": "Full-Disk",
    "技能管理": "Skills",
    "外观与图标": "Appearance",
    "支持多网关同时开启；点击任意通道展开配置，右上角开关可独立启停。": "Multiple gateways can run simultaneously. Click any card to configure, or toggle its switch independently.",
    "第 1 类 · 默认免配置": "Tier 1 · Zero-Config Default",
    "一键上手免登录直连": "Instant No-Login Direct Tunnel",
    "免登录直连": "Direct Tunnel",
    "零登录、零输入框，开箱即可复制地址连接，支持导出加密 PNG 身份恢复卡。": "No account or setup required. Copy the URL immediately and optionally export an encrypted PNG recovery card.",
    "当前使用中": "Active",
    "当前正在使用此方式": "Currently Active",
    "已连通": "Connected",
    "配置 ▾": "Configure ▾",
    "复制 Plus/Pro 只读": "Copy Plus/Pro Read-Only",
    "复制此卡地址": "Copy Card URL",
    "使用一键上手模式": "Use Direct Tunnel",
    "改用临时快速通道": "Switch to Quick Tunnel",
    "导出身份恢复卡 PNG": "Export Recovery PNG",
    "导入恢复卡 PNG": "Import Recovery PNG",
    "第 2 类 · 无服务器固定网址": "Tier 2 · Serverless Fixed URL",
    "Cloudflare 专属固定网关": "Cloudflare Fixed Gateway",
    "Cloudflare 网关": "Cloudflare Gateway",
    "支持 Google 快捷登录，粘贴一次 API 令牌 3 秒部署专属休眠网关，终身固定地址。": "Sign in with Google, paste an API token once, and deploy a permanent serverless gateway in 3 seconds.",
    "终身固定推荐": "Recommended",
    "未开启": "Off",
    "已保存固定网关网址，直接打开右上角开关即可连接，无需重填令牌。": "Saved fixed gateway URL found. Toggle the switch above to connect without re-entering a token.",
    "第 1 步：打开 Cloudflare 预填权限页（支持 Google 快捷登录）": "Step 1: Open Cloudflare pre-filled token page (Google login supported)",
    "第 2 步：粘贴 API 令牌（部署后立即销毁）": "Step 2: Paste API token (wiped immediately after deploy)",
    "选填：自定义域名（Active Zone，国内免切代理）": "Optional: Custom domain (Active Zone)",
    "检测到多个 Cloudflare 账号，请选择部署目标账号：": "Multiple Cloudflare accounts detected. Choose a target account:",
    "一键部署并开启（约 3 秒）": "Deploy & Enable (~3s)",
    "第 3 类 · 自有资产合一": "Tier 3 · Self-Hosted",
    "自有云服务器 24h 主站 或 自有固定域名": "Self-Hosted 24/7 VPS or Custom Domain",
    "自有主站": "Custom Server",
    "一键在云服务器建 24h 主站，或接入已有 Cloudflare Tunnel / Caddy / Nginx / FRP 域名。": "Deploy a 24/7 VPS relay in one click or attach your own Cloudflare Tunnel / Caddy / Nginx / FRP domain.",
    "服务器 / 域名": "VPS / Domain",
    "自有服务器建 24h 主站": "Deploy 24/7 VPS Relay",
    "自有固定域名 / 通用 HTTPS 反代": "Custom Domain / Reverse Proxy",
    "服务器公网 IP（必填）": "Server Public IP (required)",
    "SSH 密码（已配密钥可留空，不落盘）": "SSH Password (optional if key-based, never saved)",
    "使用本机默认 SSH 密钥免密登录": "Use default local SSH key",
    "高级项：SSH 私钥路径 / 端口 / 用户名 / 选填域名": "Advanced: SSH Key Path / Port / Username / Optional Domain",
    "一键部署 24h 主站并开启": "Deploy 24/7 Relay & Enable",
    "固定公网 HTTPS 域名": "Fixed Public HTTPS Domain",
    "选填：Cloudflare Named Tunnel 令牌": "Optional: Cloudflare Named Tunnel Token",
    "已有 SSH 免密反向隧道参数（可选）": "Existing SSH Reverse Tunnel Options (optional)",
    "保存并开启此网关": "Save & Enable Gateway",
    "配置默认 Python / Conda 解释器、开机与防休眠选项，以及本地后台服务控制。": "Configure the default Python/Conda runtime, startup & awake behavior, and local daemon controls.",
    "默认 Python / Conda 解释器": "Default Python / Conda Interpreter",
    "检测到的可用解释器": "Detected Interpreters",
    "自动识别项目虚拟环境或系统默认解释器": "Auto-detect project venv or system default",
    "自定义解释器路径（留空自动探测）": "Custom interpreter path (leave blank to auto-detect)",
    "保存路径": "Save Path",
    "系统运行行为": "System Behavior",
    "开机自动启动": "Launch at Login",
    "下次开机自动在后台拉起本地服务与已开启网关": "Start local service and enabled gateways automatically on login",
    "插电防自动休眠": "Prevent Sleep on AC Power",
    "外接电源时阻止系统睡眠（笔记本物理合盖仍会由硬件断网）": "Keep system awake while plugged in (closing a laptop lid still sleeps)",
    "显示系统托盘状态图标": "Show System Tray Icon",
    "在系统右下角显示在线灯，支持右键快速打开控制台或切只读": "Show status indicator in the tray with quick console and read-only actions",
    "服务控制": "Service Control",
    "确认执行后台服务操作？": "Confirm background service action?",
    "确认执行": "Confirm",
    "取消": "Cancel",
    "本地后台服务启停": "Local Daemon Lifecycle",
    "重启服务会短暂中断当前正在执行的工具调用": "Restarting briefly interrupts any in-flight tool calls",
    "锁定远程会话": "Lock Remote Sessions",
    "重启服务": "Restart Service",
    "停止服务": "Stop Service",
    "控制确认策略、可选扩展包、多机工具前缀与 16 项内置核心工具清单。": "Manage confirmation policies, optional extension packs, multi-PC tool prefixes, and the 16 built-in core tools.",
    "安全确认与扩展包": "Confirmations & Extension Packs",
    "写文件与运行命令前向宿主请求确认": "Ask host for confirmation before writes or commands",
    "只读模式自动关闭": "Auto-off in Read-Only",
    "只读模式下自动关闭": "Auto-off in Read-Only",
    "只读模式下自动开启": "Auto-on in Read-Only",
    "只读模式下自动生效": "Always active in Read-Only",
    "关闭时配合宿主 Always allow 保持连贯开发；开启后每次写入或运行命令都会弹确认": "Turn off with Always Allow for smooth flow; turn on to confirm every write/command",
    "关闭时向宿主声明免弹窗兼容注解以支持 Always allow 连贯开发；开启后每次写入或运行命令都会弹确认": "When off, uses compatibility annotations so Always Allow runs smoothly; turn on to prompt before every write/command",
    "操作边界保护（可按需自主开关）": "Configurable Safety Boundaries",
    "允许受管浏览器访问本机开发端口、局域网与本地 HTML": "Allow managed browser to open localhost dev ports, LAN & local HTML",
    "默认开启以便预览 localhost / 127.0.0.1 / 局域网与授权目录内 HTML（自身控制端口与云元数据始终隔离）；关闭后仅访问公网网页": "On by default for localhost/LAN/local HTML previews (control plane & cloud metadata stay isolated); turn off to allow public URLs only",
    "隔离项目 .env 环境变量文件": "Isolate project .env files",
    "默认关闭以便开发时正常读写项目 .env（只读模式下自动开启隔离，自身状态目录密钥始终隔离）；开启后禁止 AI 读写任何 .env 文件": "Off by default for normal .env dev workflows (auto-on in Read-Only; control-plane secrets stay isolated); turn on to block AI access to .env",
    "隔离本机系统凭据目录（.ssh / .aws / 浏览器密码库 / 包仓库令牌）": "Isolate host credential folders (.ssh / .aws / browser vaults / package tokens)",
    "默认开启以防误读本机全局密钥（不影响读取模型权重缓存）；确需管理本机凭据文件时可关闭放行": "On by default to protect global keys (model caches remain readable); turn off if you want AI to manage credential files",
    "拦截高危直删与重置命令（引导移入可恢复回收箱）": "Block destructive delete/reset commands (guide to recoverable Trash)",
    "默认开启，拦截 rm -rf / git reset --hard / format 等不可逆操作并引导走可恢复回收箱；确需执行清理命令时可关闭放行": "On by default to intercept irreversible rm -rf / git reset --hard / format commands in favor of Trash; turn off when running cleanup scripts",
    "受管浏览器包": "Managed Browser Pack",
    "启动独立隔离浏览器完成网页查阅与截图，不触碰个人浏览器窗口": "Launch an isolated browser for web checks and screenshots without touching personal profiles",
    "桌面窗口操控包": "Desktop Automation Pack",
    "提供离屏窗口画面感知与受控界面辅助，检测到键鼠活跃时自动礼让": "Off-screen window perception and guarded UI automation that yields to human input",
    "扫描本机全局技能目录（如 .claude / .codex）": "Scan global local skill folders (.claude / .codex)",
    "默认关闭以保持项目与受管技能库隔离；开启后只读发现本机其他编程工具全局技能": "Off by default for isolation; enable to discover global skills read-only",
    "多设备工具前缀": "Multi-Device Tool Prefix",
    "本机工具前缀（单台电脑保持默认 pc 即可；多电脑同连一个窗口时区分设备，如 desk / laptop）": "Local tool prefix (keep default 'pc' for one machine; use e.g. desk/laptop for multiple PCs)",
    "保存工具前缀": "Save Prefix",
    "默认 16 项核心工具说明": "16 Built-In Core Tools",
    "点击展开速查表": "Expand Reference",
    "开箱内置覆盖代码阅读、精准编辑、无窗口命令执行与技能管理的 16 项核心工具。": "16 built-in tools for code reading, surgical editing, windowless shell runs, and skills.",
    "修改": "Edit",
    "命令": "Run",
    "统一管理工作区与受管技能库，内置三级 AST 供应链安全体检与回收箱。": "Manage workspace and managed skills with 3-tier AST supply-chain scanning and trash recovery.",
    "刷新技能列表": "Refresh Skills",
    "正在读取本机技能库状态…": "Loading local skills…",
    "本机技能与详情": "Local Skills",
    "在线市场与体检安装": "Marketplace & Audit",
    "新建技能": "New Skill",
    "全部来源": "All Sources",
    "当前工作区": "Workspace",
    "受管技能库": "Managed Library",
    "其他本地目录": "Other Local",
    "检索": "Search",
    "点击左侧技能查看详情与 AST 体检结果": "Select a skill on the left to inspect details and AST audit results",
    "未选中技能": "No Skill Selected",
    "本地技能三级 AST 安全体检报告": "3-Tier AST Security Audit Report",
    "级别": "Level",
    "规则": "Rule",
    "文件 (file_rel)": "File (file_rel)",
    "详情说明": "Details",
    "查看已自动扫描的技能目录清单": "View scanned skill directories",
    "在线技能市场聚合检索（skills.sh / ClawHub / GitHub / MCP Registry）": "Federated Skill Search (skills.sh / ClawHub / GitHub / MCP Registry)",
    "搜索在线市场": "Search Market",
    "先体检后安装（三级 AST 供应链安全门禁）": "Audit Before Install (3-Tier AST Gate)",
    "粘贴 GitHub 仓库、ClawHub 标识或本地目录路径，先在内存中扫描再决定是否安装。": "Paste a GitHub repo, ClawHub ID, or local folder path to scan in memory before installing.",
    "主工作区项目": "Primary Workspace",
    "执行 AST 体检": "Run AST Audit",
    "规则编号": "Rule ID",
    "定位文件 (file_rel)": "File (file_rel)",
    "检测说明与修复建议": "Findings & Remediation",
    "我已逐条审阅上述 WARN 风险项与源码文件，确认继续安装": "I have reviewed the WARN items and source files and confirm installation",
    "若存在同名技能，先移入安全回收箱再覆盖": "Move any existing skill with the same name to Trash first",
    "确认安装此技能": "Install Skill",
    "新技能名称（英文/数字/连字符）": "New Skill Name (letters/digits/hyphens)",
    "保存位置范围": "Target Scope",
    "受管技能库（所有工作区共用）": "Managed Library (shared across workspaces)",
    "当前主工作区（.agents/skills/）": "Primary Workspace (.agents/skills/)",
    "填入模板": "Insert Template",
    "SKILL.md 完整内容": "Full SKILL.md Content",
    "若触发 WARN 提示，确认继续保存": "Confirm save if WARN findings occur",
    "若同名技能已存在，先移入回收箱再覆盖": "Move existing skill to Trash before overwriting",
    "安全体检并创建技能": "Audit & Create Skill",
    "移入安全回收箱的技能保留完整目录与哈希，可随时一键恢复。": "Trashed skills retain full folders and hashes for one-click restore.",
    "刷新回收箱": "Refresh Trash",
    "切换浅深模式、4 套主题风格包、4 套 IP 图标与转向姿态，偏好保存在本地浏览器。": "Switch light/dark theme, 4 style packs, and icon sets. Preferences are stored locally in your browser.",
    "节点身份恢复卡 PNG": "Node Identity Recovery Card PNG",
    "通过加密 PNG 图片备份或迁移本机固定节点身份": "Back up or migrate your fixed node identity via an encrypted PNG",
    "设置恢复卡加密口令（恢复时需输入同一口令）": "Set recovery card passphrase (required on restore)",
    "生成并下载身份恢复卡 PNG": "Generate & Download Recovery PNG",
    "选择备份的身份恢复卡 PNG 文件": "Select Recovery PNG File",
    "输入导出时设置的加密口令": "Enter the export passphrase",
    "解密并恢复固定节点身份": "Decrypt & Restore Identity",
    "文件修改前后对比 (Diff)": "File Edit Diff",
    "撤回此修改": "Revert Edit",
    "输入本机连接口令": "Enter local passcode",
    "输入或粘贴管理口令": "Enter or paste admin passcode",
    "输入或粘贴文件夹路径，回车添加": "Type or paste a folder path and press Enter",
    "新子文件夹名": "New subfolder name",
    "筛选工具名…": "Filter tools…",
    "粘贴生成的 Cloudflare API 令牌": "Paste Cloudflare API token",
    "例如 mcp.yourdomain.dpdns.org": "e.g. mcp.yourdomain.dpdns.org",
    "例如 203.0.113.10": "e.g. 203.0.113.10",
    "输入服务器 SSH 密码": "Enter server SSH password",
    "选填 SSH 私钥路径（如 ~/.ssh/id_ed25519）": "Optional SSH key path (e.g. ~/.ssh/id_ed25519)",
    "用户名 (默认 root)": "Username (default root)",
    "端口 22": "Port 22",
    "选填绑定域名（留空自动签发公网 IP 证书）": "Optional domain (leave blank for IP cert)",
    "例如 https://mcp.yourdomain.com": "e.g. https://mcp.yourdomain.com",
    "粘贴 eyJ... 令牌（已反代留空）": "Paste eyJ... token (leave blank if proxied)",
    "SSH 目标（如 root@vps.example.com）": "SSH target (e.g. root@vps.example.com)",
    "远端转发端口（默认 18096）": "Remote forward port (default 18096)",
    "公网 HTTPS 访问地址": "Public HTTPS URL",
    "填写解释器路径或项目 .venv 目录": "Enter interpreter path or project .venv",
    "默认 pc（小写字母、数字与下划线）": "Default: pc (lowercase, digits, underscore)",
    "输入名称或关键词检索技能": "Search skills by name or keyword",
    "输入关键词后按回车或点击搜索，例如 interface-design, pdf": "Type keywords and press Enter, e.g. interface-design, pdf",
    "输入 owner/repo、https://github.com/... 或本地目录路径": "Enter owner/repo, https://github.com/..., or local path",
    "例如 my-workflow-helper": "e.g. my-workflow-helper",
    "输入加密保护口令": "Enter encryption passphrase",
    "输入恢复口令": "Enter recovery passphrase",
    "暂无运行中的后台命令。": "No background jobs running.",
    "暂无待撤回的文件修改快照。": "No file edit snapshots yet.",
    "安全回收箱为空。": "Trash is empty.",
    "暂无工具调用记录。": "No tool calls recorded yet.",
    "暂无已连接网页会话。": "No connected web sessions yet.",
    "全部 6 大交互式实战教程": "All 6 Interactive Guides",
    "快速接入与排障": "Quick Setup & Troubleshooting",
    "工作区账号 Team / Business / Edu（读写全开）": "Workspace Team / Business / Edu (Full Read/Write)",
    "个人 Plus / Pro 账号（只读查阅）": "Personal Plus / Pro Account (Read-Only)",
    "不要把网址直接粘进浏览器地址栏。": "Do not open this URL in the browser address bar.",
    "打开": "Open",
    "（或左下角「Personal Intelligence → Connected Apps」），点右上角「+ Custom」，粘贴到「MCP Server URL」配置栏后点 Next。": " (or 'Personal Intelligence → Connected Apps' at bottom-left), click '+ Custom', paste into 'MCP Server URL', and click Next.",
    "），再回到连接器页把 App actions 设为 Always allow。": " on mobile), then return to Connectors and set App actions to Always allow.",
    "不要把": "Do not open the",
    "地址直接粘进浏览器地址栏。": "URL in the browser address bar.",
    "（或左下角「Personal Intelligence → Connected Apps」），点右上角「+ Custom」，把地址粘贴到「MCP Server URL」配置栏点 Next，确认页点「本机一键允许连接」并将 App actions 设为 Always allow，新建对话输入": " (or 'Personal Intelligence → Connected Apps' at bottom-left), click '+ Custom', paste into 'MCP Server URL' and click Next, approve on the consent screen, set App actions to Always allow, then start a new chat with",
    "开始使用。": "to begin.",
    "ChatGPT：": "ChatGPT:",
    "打开左侧「Plugins → + → Add custom MCP server」，名称填": "Open 'Plugins → + → Add custom MCP server' on the left, set Name to",
    "，粘贴对应地址并选 OAuth，创建后点「本机一键允许连接」并点击 Install（也可点上方「复制给 Work 模式帮我连接」代填）。装好后日常用 Chat 模式发": ", paste the URL with OAuth, click 'Allow from This PC' and Install (or use 'Copy for ChatGPT Work Mode Setup' above). Use Chat mode daily with",
    "写代码不耗智能体额度，长任务用 Work 模式。": "for coding at zero agent quota cost, and Work mode for long tasks.",
    "正在读取本机连接状态…": "Checking local connection status…",
    "离线预览": "Offline Preview",
    "待开启公网网关": "Gateway Off",
    "待开启网关": "Gateway Off",
    "本机真实地址": "Live Local URL",
    "本机已启动 · 开启任一连接通道后自动填入真实网址": "Local service running · Enable any gateway to populate your live URL",
    "离线预览模式 · 在本地控制台打开自动填入真实网址": "Offline preview · Open from your local console to load live URLs",
    "尚未开启公网网关，当前显示示例地址。": "Public gateway is off. Showing sample URLs.",
    "当前显示示例地址，在本地控制台打开即自动替换。": "Showing sample URLs. Open from your local console to auto-fill.",
    "切换浅色与深色模式": "Toggle Light / Dark Mode",
    "示例地址": "Sample URL",
    "已自动填入当前电脑的连接地址，点击即可复制。": "Your computer's live MCP URLs are filled below — click to copy.",
    "刷新本机地址": "Refresh URL",
    "展开全部 6 章": "Show All 6 Guides",
    "切回单章聚焦": "Single-Guide View",
    "主连接地址 · Gemini / ChatGPT 工作区": "Primary URL · Gemini & ChatGPT Workspace",
    "点击复制主连接地址": "Click to copy primary URL",
    "只读地址 · ChatGPT 个人 Plus / Pro": "Read-Only URL · ChatGPT Personal Plus / Pro",
    "点击复制只读地址": "Click to copy read-only URL",
    "复制只读地址": "Copy Read-Only URL",
    "搜索步骤或常见问题…": "Search steps or FAQs…",
    "1. Gemini 接入": "1. Gemini Setup",
    "2. ChatGPT 接入": "2. ChatGPT Setup",
    "3. 通道选型": "3. Gateways",
    "4. 常用指令": "4. Prompts",
    "5. 权限与撤回": "5. Safety & Undo",
    "6. 常见问题": "6. FAQ",
    "完成进度": "Progress",
    "勾选后自动保存": "Saved automatically",
    "重置": "Reset",
    "搜索步骤或问题…": "Search guides…",
    "清空": "Clear",
    "1. Gemini 与手机远控": "1. Gemini & Mobile",
    "2. ChatGPT 接入与分工": "2. ChatGPT Setup",
    "3. 连接通道选型": "3. Gateway Options",
    "4. 常用指令示例": "4. Prompt Examples",
    "5. 权限与修改撤回": "5. Safety & Undo",
    "6. 常见问题速查": "6. Troubleshooting",
    "已按关键词筛选章节": "Filtered guides by keyword",
    "清除筛选": "Clear Filter",
    "教程 1 · Google Gemini 网页版与手机 App": "Guide 1 · Google Gemini Web & Mobile App",
    "接入 Google Gemini（电脑绑定一次，手机自动同步）": "Connect Google Gemini (Set Up Once, Syncs to Mobile)",
    "在电脑浏览器添加一次连接器，登录同账号的 Android / iOS 手机 Gemini App 即可直接使用。": "Add the connector once on desktop — your Android & iOS Gemini App on the same account gets it automatically.",
    "打开 Gemini 连接器页": "Open Gemini Connectors",
    "1. 确认账号支持自定义连接器": "1. Check account eligibility",
    "需使用满 18 周岁的 Google AI Pro / Ultra 订阅账号，或已开启连接器权限的 Workspace 企业与教育账号。": "Requires an 18+ Google AI Pro / Ultra account, or a Workspace Business / Education account with custom connectors enabled.",
    "确认页点绿色": "On the consent screen, click",
    "（手机端输入配对码": " (or enter pairing code ",
    "在本机 ChatGPT 左侧打开「Plugins → + → Add custom MCP server」，名称填": "In ChatGPT on this PC, open 'Plugins → + → Add custom MCP server', set Name to",
    "，粘贴地址并选 OAuth，创建后点 Install。": ", paste the URL, select OAuth, create, and click Install.",
    "弹出确认页点绿色": "On the consent screen, click",
    "即可；也可点右侧按钮让 Work 模式代填：": "; or let Work mode fill it automatically:",
    "Gemini：": "Gemini:",
    "2. 打开 Gemini 连接器页，粘贴地址到 MCP Server URL": "2. Open Gemini Connectors & paste into MCP Server URL",
    "不要把网址直接粘贴到浏览器地址栏打开。": "Do not paste this URL into the browser address bar.",
    "点击右上角按钮访问": "Open",
    "（或在首页左下角依次点「Personal Intelligence → Connected Apps」），点右上角「+ Custom」，把": " (or click 'Personal Intelligence → Connected Apps' at bottom-left), click '+ Custom', paste",
    "粘贴到「MCP Server URL」配置栏（Additional settings 保持折叠），点 Next。": "into 'MCP Server URL' (keep Additional settings collapsed), and click Next.",
    "回到": "Return to",
    "点开刚添加的连接器，将「App actions」设为「Always allow（始终允许）」。也可在主控台复制 AI 操作守则存入 Gemini Skills。": ", open your connector, and set 'App actions' to 'Always allow'. Optionally save the AI Rules into Gemini Skills.",
    "3. 在弹出的确认页允许连接": "3. Approve on the consent screen",
    "本机浏览器": "On This PC",
    "直接点击绿色按钮「本机一键允许连接」即可完成绑定。": "Click the green 'Allow from This PC' button to finish instantly.",
    "手机或异地": "Mobile / Remote",
    "核对页面 4 位确认码后，填入本机控制台显示的 6 位配对码。": "Verify the 4-digit code on screen, then enter the 6-digit pairing code shown in your local console.",
    "4. 开启「Always allow」免每次弹窗确认": "4. Set 'App actions' to 'Always allow'",
    "在连接器列表点开 Cosmos，将「App actions」设为「Always allow（始终允许）」。也可在主控台复制 AI 操作守则存入 Gemini Skills。": "Open Cosmos in Connectors and set 'App actions' to 'Always allow'. Optionally save the AI Rules into Gemini Skills.",
    "5. 新建对话，首句输入 @Cosmos 开始使用": "5. Start a new chat with @Cosmos",
    "开启新对话，输入": "Start a new chat, type",
    "点选弹出的连接器标签，粘贴下方测试句发送即可读取本地目录。": "to select the connector tag, and send the test prompt below.",
    "首句唤醒词与配对码速查": "First Prompt & Pairing Quick View",
    "本机授权": "This PC",
    "手机配对码": "Mobile Code",
    "本机同浏览器点击确认页的「本机一键允许连接」即可，无需输入任何口令。": "On the same PC browser, click 'Allow from This PC' — no passcode required.",
    "手机端请核对 4 位确认码": "On mobile, match the 4-digit check code",
    "，再输入本机 6 位配对码": ", then enter the 6-digit pairing code",
    "复制首句唤醒词": "Copy First Prompt",
    "教程 2 · 网页版 ChatGPT": "Guide 2 · Web ChatGPT",
    "接入网页版 ChatGPT": "Connect Web ChatGPT",
    "安装一次插件后全账号通用：日常写代码用 Chat 模式（不耗智能体额度），长任务用 Work 模式。": "Install once for your whole account: use Chat mode daily for fast coding (zero agent quota used), and Work mode for multi-app tasks.",
    "工作区账号 (/mcp)": "Workspace (/mcp)",
    "个人 Plus/Pro (只读)": "Personal Plus/Pro (Read-Only)",
    "工作区账号（Team / Business / Edu）": "Workspace (Team / Business / Edu)",
    "读写全开": "Full Read/Write",
    "只读查阅": "Read-Only",
    "开放代码读写、Word / Excel 修订与无窗口命令运行。": "Enables file editing, Word/Excel revisions, and windowless command execution.",
    "复制连接配置发给 ChatGPT Work 模式自动代填": "Copy setup instructions for ChatGPT Work mode",
    "个人订阅账号（Plus / Pro）": "Personal Subscription (Plus / Pro)",
    "适配个人版权限规则，开放代码检索、文档提取与看图分析。": "Matches personal plan rules with code search, document reading, and image inspection.",
    "复制只读配置发给 ChatGPT Work 模式自动代填": "Copy read-only setup instructions for ChatGPT Work mode",
    "1. 复制上方对应账号的连接地址": "1. Copy the URL matching your ChatGPT plan",
    "团队工作区账号复制": "Copy",
    "地址；个人 Plus / Pro 账号复制": "for Team / Business / Edu workspaces, or",
    "只读地址。": "for Personal Plus / Pro.",
    "2. 在 ChatGPT 添加并安装插件（二选一）": "2. Add & install the plugin in ChatGPT (pick either way)",
    "本机手动添加（推荐）": "Manual on This PC (Fastest)",
    "打开 ChatGPT 左侧「Plugins → + → Add custom MCP server」，名称填": "Open 'Plugins → + → Add custom MCP server' in ChatGPT, set Name to",
    "，粘贴地址并选 OAuth，创建后点「本机一键允许连接」并点击 Install。": ", paste the URL with OAuth, click 'Allow from This PC', and click Install.",
    "Work 模式代填": "Work Mode Assist",
    "点击上方「复制给 Work 模式帮我连接」，在 ChatGPT 顶部切到 Work 模式发送；弹出云端接管（Take over）提示时输入本机 6 位配对码即可。": "Click 'Copy for ChatGPT Work Mode Setup' above, switch ChatGPT to Work mode, and send. When prompted to Take over, enter your 6-digit pairing code.",
    "3. 日常写代码用 Chat，跨应用长任务用 Work": "3. Use Chat for daily coding, Work for multi-app tasks",
    "Chat 模式": "Chat Mode",
    "输入": "Type",
    "查改本地代码与文档，响应快且不消耗 Work 智能体额度。": "to read/edit local code and Office files quickly without using Work quota.",
    "Work 模式": "Work Mode",
    "处理跨邮件、网盘或定时执行的复杂任务。": "for multi-step workflows across email, cloud drives, or scheduled tasks.",
    "4. 发送首句指令验证连通": "4. Send your first test prompt",
    "新建对话发送下方验证词，AI 调用": "Start a new chat with the prompt below — once AI calls",
    "返回你的电脑名称与工作目录即代表接入成功。": "and returns your computer name and workspace, you're connected.",
    "ChatGPT 首轮验证指令": "First ChatGPT Test Prompt",
    "复制首轮验证词": "Copy Test Prompt",
    "教程 3 · 连接通道选型": "Guide 3 · Gateway Options",
    "按你的网络与资源选择连接通道": "Choose the Right Connection Gateway",
    "三类加密通道可在控制台「设置 → 连接与网关」随时切换，也支持同时开启并存。": "Switch or run multiple HTTPS gateways side-by-side anytime in 'Settings → Gateways'.",
    "通道 1 · 默认开启": "Option 1 · Default",
    "免注册直接用": "Instant No-Login",
    "不注册云账号、不买域名，启动后直接生成连接网址。": "Zero sign-ups or domains — generates a working HTTPS URL on launch.",
    "通道 2 · 长期推荐": "Option 2 · Recommended",
    "免费固定网址": "Free Permanent URL",
    "贴一次 Cloudflare 令牌，3 秒部署专属网关，重启网址不变。": "Paste a Cloudflare token once to deploy a permanent URL in 3 seconds.",
    "通道 3 · 自有资产": "Option 3 · Self-Hosted",
    "自有云服务器或域名": "Your Own VPS or Domain",
    "一键部署 24 小时云服务器主站，或接入已有 HTTPS 域名。": "Deploy a 24/7 VPS hub in one click, or attach an existing HTTPS domain.",
    "通道 1：免登录直连通道（零配置开箱即用）": "Option 1: Instant No-Login Tunnel (Zero Setup)",
    "双击启动程序后默认开启，自动生成固定连接网址；若校园网或公司网限制端口，4 秒内自动切换备用快速通道。": "Enabled by default on launch with a persistent URL, automatically falling back within 4s on restricted networks.",
    "建议在「设置 → 外观与图标」导出加密身份恢复卡 PNG，重装系统或换电脑时可一键恢复原网址。": "Export an encrypted Recovery PNG in 'Settings → Appearance' to keep the same URL if you switch PCs.",
    "通道 2：Cloudflare 免费固定网关（3 秒部署，令牌用后即毁）": "Option 2: Cloudflare Free Fixed Gateway (3s Deploy, Token Wiped)",
    "在控制台打开「设置 → 连接与网关 → Cloudflare 专属固定网关」，点击第 1 步链接打开预填权限页（支持 Google 登录）。": "In 'Settings → Gateways → Cloudflare Fixed Gateway', open the pre-filled token link (Google sign-in supported).",
    "复制生成的 API 令牌粘贴回第 2 步，点击「一键部署并开启」（约 3 秒生成专属固定网址）。": "Paste the API token into Step 2 and click 'Deploy & Enable' (~3s).",
    "部署完成后本机立即销毁令牌，后续电脑重启或休眠唤醒均自动重连。": "The API token is wiped immediately after deployment, and your PC reconnects automatically after sleep or reboot.",
    "打开 Cloudflare 令牌页": "Open Cloudflare Tokens",
    "通道 3：自有云服务器 24h 主站 或 自有域名": "Option 3: 24/7 Cloud Server Hub or Custom HTTPS Domain",
    "云服务器建 24h 主站": "24/7 VPS Hub",
    "：在「设置 → 连接与网关」填入服务器公网 IP 与 SSH 密码（或勾选本机 SSH 密钥）一键部署。电脑关机时仍可操作云端文件，电脑开机后自动接通本地目录。": ": Enter your server IP and SSH credentials in 'Settings → Gateways' for 1-click setup. Manage server files even when your PC is off.",
    "已有固定 HTTPS 域名": "Existing HTTPS Domain",
    "：切换到「自有固定域名 / 通用 HTTPS 反代」，填入完整域名或 Cloudflare Tunnel 令牌保存即可。": ": Switch to 'Custom Domain / Reverse Proxy' and enter your HTTPS URL or Cloudflare Tunnel token.",
    "1. 确认已生成 https 连接地址": "1. Confirm your HTTPS URL is ready",
    "顶部状态显示绿色「在线」，且地址栏出现可复制的": "The top badge shows 'Online' and a copyable",
    "链接。": "link is displayed.",
    "2. 按需开启开机自启与插电防休眠": "2. Enable Launch at Login & Prevent Sleep if needed",
    "需要出门用手机随时远控电脑时，可在「设置 → 环境与系统」打开这两项开关。": "Turn both on in 'Settings → Environment' if you want reliable mobile access while away.",
    "3. 导出身份恢复卡 PNG 备份（选做）": "3. Back up your Recovery Card PNG (optional)",
    "保存一张加密恢复卡图片，换新电脑导入即可沿用原固定网址，无需重绑连接器。": "Import the encrypted PNG on a new PC to keep your fixed URL without re-binding connectors.",
    "4. 确认睡眠唤醒后自动恢复连接": "4. Automatic reconnect after sleep",
    "使用固定网址时，电脑重启或开盖唤醒后约 1～2 秒自动恢复在线。": "With a fixed URL, waking your PC restores the connection in 1–2 seconds.",
    "教程 4 · 常用指令示例": "Guide 4 · Prompt Templates",
    "一键复制可用的实战提示词": "Ready-to-Use Prompt Examples",
    "Gemini 可直接粘贴发送；ChatGPT 将开头的": "Paste directly into Gemini; in ChatGPT, replace",
    "换成": "with",
    "即可。": ".",
    "全部 (6)": "All (6)",
    "代码与测试": "Code & Tests",
    "办公文档与看图": "Office & Vision",
    "多设备协同": "Multi-PC",
    "1. 多目录并行代码审查": "1. Parallel Multi-Folder Code Review",
    "代码审查": "Code Review",
    "拆分并行子任务同时检查不同模块，汇总具体文件路径、行号与修复建议。": "Inspect backend, frontend, and tests in parallel sub-tasks and summarize file paths, lines, and fixes.",
    "复制指令 1": "Copy Prompt 1",
    "2. Word 保格式修订与 Excel 填公式": "2. Format-Preserving Word & Excel Edits",
    "办公文档": "Office Docs",
    "保留原有段落与字体样式更新 Word 文字，并按单元格坐标填写 Excel 汇总公式。": "Update Word text while keeping styles intact, and write Excel formulas by cell coordinates.",
    "复制指令 2": "Copy Prompt 2",
    "3. 读取 PDF 需求并核对本地截图": "3. Compare PDF Specs Against Local Screenshots",
    "看图核对": "PDF + Vision",
    "免上传附件，直接查看本地 PNG / JPG 截图并与 PDF 文档内容逐项比对。": "Read local screenshots and PDFs directly from disk without manual uploads.",
    "复制指令 3": "Copy Prompt 3",
    "4. 后台静默跑完整测试与构建": "4. Run Full Test & Build Suites in Background",
    "后台任务": "Background Job",
    "长耗时编译或全量测试在后台无窗口运行，不弹黑框、不打断你当前打字。": "Run long builds silently in the background with zero popup windows or focus steals.",
    "复制指令 4": "Copy Prompt 4",
    "5. 台式机与笔记本同窗口协同": "5. Coordinate Desktop & Laptop in One Chat",
    "多机协同": "Multi-Device",
    "为不同电脑设置区分前缀（如 desk 与 laptop），在同一对话窗口跨设备核对环境。": "Assign custom prefixes (e.g. desk & laptop) to compare environments across machines.",
    "复制指令 5": "Copy Prompt 5",
    "6. 换机恢复后核对设备与目录": "6. Verify Node & Folders After Migration",
    "迁移核验": "Migration Check",
    "导入身份恢复卡后，一键检查当前电脑名称、权限档位与开放目录是否生效。": "Confirm hostname, permission tier, and workspace roots after importing a recovery card.",
    "复制指令 6": "Copy Prompt 6",
    "1. 复制任意指令卡到网页 AI 试用": "1. Try any prompt card in your web AI",
    "体验免上传直读本地代码、PDF 与图片。": "Read local repositories, PDFs, and screenshots directly without uploading.",
    "2. 在主控台右侧查看实时任务与修改记录": "2. Check live jobs & edit history on the console",
    "后台运行中的命令可随时查看输出流或一键停止。": "Inspect live output or stop background commands anytime.",
    "3. 多台电脑同连时设置不同工具前缀（选做）": "3. Set distinct tool prefixes for multiple PCs (optional)",
    "单台电脑保持默认 pc 即可；多台电脑可在「设置 → 工具与扩展」修改前缀区分设备。": "Keep default 'pc' for one computer, or customize it in 'Settings → Tools & Packs'.",
    "教程 5 · 权限控制与安全恢复": "Guide 5 · Permissions & Undo",
    "四档权限设置、目录隔离与一键撤回": "4 Permission Tiers, Folder Isolation & Instant Undo",
    "顶栏可随时一键切回只读，每次改文件前自动保存快照，删除文件统一进入可还原回收箱。": "Switch to Read-Only in one click, auto-snapshot every file edit, and recover deleted files from Trash.",
    "L1 · 急停保护": "L1 · Instant Lock",
    "仅查看搜索，禁改文件与命令": "Read & search only, no edits or commands",
    "L2 · 纯改文档": "L2 · Edit Only",
    "允许改文件，禁止运行命令": "File edits allowed, shell commands blocked",
    "L3 · 默认推荐": "L3 · Default",
    "仅在开放目录内读写与运行": "Read, edit & run inside workspace folders",
    "L4 · 跨盘操作": "L4 · Full Disk",
    "不限目录读写，保留快照与回收箱": "Unrestricted paths with snapshots & Trash",
    "当前查看：只读（L1 · 顶栏一键急停）": "Viewing: Read-Only (L1 · Instant Emergency Lock)",
    "仅允许在开放目录与只读参考目录内读取文件、提取文档与搜索代码，禁止任何文件写入与命令执行。点击主控台顶栏「一键只读」即可立即切回只读并终止所有正在运行的任务。": "Allows reading files and searching code only — all writes and commands are blocked. Click 'Read-Only' in the top bar anytime to lock immediately and stop running jobs.",
    "当前查看：仅改文件（L2 · 纯代码与文档编辑）": "Viewing: Edit Files Only (L2 · No Shell Commands)",
    "允许查阅目录并修改工作区内的代码及 Word / Excel 文档（每次写前自动留存快照），禁止运行任何终端命令、Python 脚本与外部操控扩展包。": "Allows reading and editing workspace code and Word/Excel files (with automatic undo snapshots), while blocking all shell commands and Python execution.",
    "当前查看：工作区开发（默认推荐）": "Viewing: Workspace Dev (L3 · Default)",
    "当前查看：工作区开发（L3 · 默认推荐）": "Viewing: Workspace Dev (L3 · Default)",
    "AI 只能在已开放的工作目录内读写代码、修订文档与运行命令；点击主控台顶栏「一键只读」可立即切回只读并停止正在运行的任务。": "AI can read, edit, and run commands strictly inside your enabled workspace folders. Click 'Read-Only' in the top bar anytime to pause.",
    "AI 只能在已开放的工作目录内读写代码、修订文档与运行命令；外层只读参考目录仅允许检索查阅，自动拦截误写。": "AI reads, edits, and runs commands strictly inside enabled workspace folders; read-only reference folders block all writes.",
    "当前查看：全盘开发（L4 · 不限目录读写）": "Viewing: Full-Disk Dev (L4 · Unrestricted Paths)",
    "允许跨本机任意目录读写文件与运行命令；同时保留写前自动快照、安全回收箱防误删及本机敏感凭据隔离。": "Allows reading, editing, and running commands across any local folder, while keeping undo snapshots, Trash protection, and credential isolation.",
    "只读参考目录与读写目录分层": "Read-Only Reference vs. Read/Write Folders",
    "可将外层参考代码库（如 D:\\Projects）添加为": "Add a parent folder (e.g. D:\\Projects) as a ",
    "，供 AI 跨项目查代码，同时自动拦截任何写入。": " so AI can search reference code while writes are blocked.",
    "当前正在开发的子目录（如 D:\\Projects\\my-app）设为": "Set your active project subfolder (e.g. D:\\Projects\\my-app) as ",
    "，允许正常修改代码与运行测试。": " for normal coding and testing.",
    "外部技能安全体检": "3-Tier Skill Security Scan",
    "在「设置 → 技能管理」安装外部 GitHub 或市场技能前，系统会先在内存中扫描高危命令与隐私外发行为，确认安全后再落盘启用。": "Before installing external skills in 'Settings → Skills', scripts are scanned in memory for risky commands or data exfiltration.",
    "修改前后对比（Diff）与一键撤回": "Before/After Diff & 1-Click Undo",
    "代码文件快照": "Code Diff",
    "Word / Excel 快照": "Office Diff",
    "修改前快照 · config.py": "Snapshot · config.py",
    "修改前快照 · 项目周报.docx（保留原段落与字体样式）": "Snapshot · Weekly_Report.docx (styles preserved)",
    "删除文件不会直接清空，自动移入回收箱支持原位还原；改错文件可在主控台点「查看对比 Diff → 撤回此修改」。": "Deleted files go to Trash for 1-click restore; review diffs and revert any file edit from the console.",
    "复制撤回指令": "Copy Undo Prompt",
    "1. 认识顶栏「一键只读」按钮": "1. Locate the 'Read-Only' button in the top bar",
    "点击立即切入只读并停止所有在途任务（系统右下角托盘菜单也可一键切换）。": "Switches to Read-Only and stops active tasks immediately (also available from the system tray).",
    "2. 为参考资料库勾选「以只读参考目录添加」": "2. Add reference repos as 'Read-Only Reference'",
    "既能让 AI 查阅历史项目参考实现，又能防止误改旧代码。": "Lets AI search reference code across repos without modifying them.",
    "3. 安装外部技能前先跑安全体检": "3. Run AST security audit before installing external skills",
    "在「设置 → 技能管理」先扫描脚本风险，确认无误再安装启用。": "Review scan findings in 'Settings → Skills' before enabling third-party skills.",
    "4. 在主控台右侧体验修改对比与回收箱还原": "4. Review file diffs and Trash restore on the console",
    "代码与办公文档的改动都支持随时一键回退。": "Both source code and Word/Excel edits can be reverted in one click.",
    "教程 6 · 常见问题速查": "Guide 6 · Troubleshooting",
    "连接与使用常见问题": "Common Questions & Fixes",
    "输入关键词或点击分类查看解决方法，点击任意问题展开详情。": "Filter by keyword or category, and click any question to expand the fix.",
    "搜索问题关键词（如：代理、刷新、Word 占用、休眠、弹窗）…": "Search issues (e.g. proxy, refresh, Word locked, sleep, prompt)…",
    "代理与网络": "Proxy & Network",
    "工具刷新与弹窗": "Refresh & Prompts",
    "Python 与文档占用": "Python & Office Lock",
    "电源与休眠": "Power & Sleep",
    "没有找到匹配的问题，请清空关键词或切回「全部」。": "No matching questions found. Clear the filter or select 'All'.",
    "1. 开启代理软件时，Cloudflare 网关一直显示连接中或打不开授权页": "1. Cloudflare gateway stays 'Connecting' or consent page fails to load under a proxy",
    "原因：": "Cause: ",
    "分流规则将 workers.dev 设为了直连，或系统环境变量 NO_PROXY 范围过宽。": "Split-tunnel rules route workers.dev directly, or NO_PROXY is set too broadly.",
    "解决：": "Fix: ",
    "首次点击绑定时，把代理软件临时切到": "Switch your proxy to ",
    "全局模式 10 秒": "Global Mode for 10s",
    "完成授权（绑好后由云端直连，日常无需开全局）；或在网关设置填入自定义域名。": " during one-time authorization (cloud hosts connect directly afterward), or set a custom domain.",
    "复制自检命令": "Copy Diagnostic Command",
    "2. 开启浏览器/桌面扩展包或改前缀后，AI 对话里看不到新工具": "2. Newly enabled extension packs or renamed prefixes don't show up in chat",
    "工具刷新": "Refresh Tools",
    "Gemini 与 ChatGPT 会在开启对话时缓存工具清单，旧对话不会自动加载新开启的工具。": "Gemini and ChatGPT cache the tool schema when a chat starts, so existing chats won't see newly toggled packs.",
    "在 Gemini 连接器页刷新 Cosmos（或在 ChatGPT 插件页点 Refresh），然后": "Refresh Cosmos in Gemini Connectors (or click Refresh in ChatGPT Plugins), then ",
    "新建一个对话": "start a new chat",
    "即可调用新工具。": " to load the updated tools.",
    "3. Windows 输入 python 弹出应用商店，或想指定项目的 Conda / 虚拟环境": "3. Typing python on Windows opens Microsoft Store, or you want a specific Conda/venv",
    "Python 环境": "Python Env",
    "说明：": "Note: ",
    "启动器会自动跳过微软商店的 WindowsApps 空壳解释器，优先使用内置环境或本机已安装的 Python / Conda。": "WebAI2PC automatically skips the WindowsApps store stub and selects bundled or installed Python/Conda runtimes.",
    "指定环境：": "Custom runtime: ",
    "如需固定某个虚拟环境，打开控制台「设置 → 环境与系统」，在解释器下拉框选择或填入路径保存即可。": "Choose or paste your interpreter path in 'Settings → Environment'.",
    "4. 让 AI 修改 Word 或 Excel 时提示文件正在被占用（ERR_OFFICE_FILE_LOCKED）": "4. Editing Word or Excel returns ERR_OFFICE_FILE_LOCKED",
    "文档保护": "File Lock Guard",
    "该文件正被本地 Word 或 Excel 打开，系统自动拒绝覆盖，防止冲掉你窗口里未保存的手工修改。": "The file is currently open in Word or Excel, so writes are blocked to protect unsaved changes.",
    "先在 Word 或 Excel 按 Ctrl+S 保存并关闭该文档窗口，再让 AI 重试即可。": "Press Ctrl+S and close the document in Word/Excel, then ask AI to retry.",
    "5. 笔记本拔掉电源或合上盖子后，手机端连不上电脑": "5. Mobile app loses connection when laptop is unplugged or lid is closed",
    "笔记本改用电池供电时会自动恢复省电休眠；物理合上屏幕盖子也会触发硬件睡眠断网。": "On battery power, sleep protection yields to save battery; closing the laptop lid also triggers hardware sleep.",
    "外出需要手机远控笔记本时，请保持连接电源、开启「插电防自动休眠」并保持开盖（可将屏幕亮度调低）。": "Keep the laptop plugged into AC power with 'Prevent Sleep on AC Power' enabled and the lid open.",
    "6. Gemini 每次调用工具都弹确认卡，无法连续自动执行": "6. Gemini asks for confirmation on every single tool call",
    "免确认设置": "Auto-Approve",
    "连接器未开启全局允许，只在聊天流单张确认卡上点了单次允许；或控制台打开了写前确认开关。": "The connector isn't set to Always allow globally, or host confirmation is turned on in Settings.",
    "（或左下角「Personal Intelligence → Connected Apps」）点开连接器将「App actions」设为「Always allow」，并在本机「设置 → 工具与扩展」关闭「写文件与运行命令前向宿主请求确认」。": " (or 'Personal Intelligence → Connected Apps' at bottom-left), open the connector and set 'App actions' to 'Always allow', and turn off 'Ask host for confirmation' in 'Settings → Tools & Packs'.",
    "1. 确认控制台顶栏显示绿色「在线」": "1. Check that the top status badge shows 'Online'",
    "若一直显示连接中，先检查本地代理分流规则或切换免登录直连通道。": "If stuck connecting, check proxy rules or switch to Instant Direct Tunnel.",
    "2. 开关扩展包或改前缀后新建对话": "2. Start a new chat after toggling extension packs",
    "新对话会自动拉取最新的工具列表。": "New chats automatically fetch the updated tool list.",
    "3. 让 AI 改文档前先保存关闭本地 Word / Excel": "3. Save and close open Word/Excel files before AI edits",
    "避免触发文件占用保护。": "Prevents file-lock conflicts with unsaved local edits.",
    "4. 手机远控笔记本时保持插电且不合盖": "4. Keep laptops plugged in with lid open for mobile access",
    "插电状态下自动维持系统唤醒不断网。": "Maintains continuous connection while on AC power."
  };

  Object.assign(ZH_TO_EN, {
    // Merged origin/main showcase, ChatGPT plugins & PAT translations
    "Team / Business / Enterprise / Edu 工作区（全功能读写 · 装好后日常用 Chat 省额度，长任务用 Work）": "Team / Business / Enterprise / Edu Workspace (Full Read/Write · Daily Chat saves quota, Work for long tasks)",
    "个人 Plus / Pro 账号（只读连接 · 平台限制写工具时使用，装好后日常用 Chat 省额度）": "Personal Plus / Pro Account (Read-only · Use when write tools are restricted, Chat saves quota)",
    "复制地址并打开 ChatGPT 插件页": "Copy URL & Open ChatGPT Plugins",
    "复制给 ChatGPT 接入 / 排障": "Copy ChatGPT Connect / Debug Prompt",
    "仅复制地址": "Copy URL Only",
    "仅复制只读": "Copy Read-Only",
    "展开 Sites 环境变量 / CLI 专用密钥兜底 ▾": "Expand Sites Secrets / CLI Dedicated Token Fallback ▾",
    "注意：控制台复制出的连接地址与接入指令仅限填入本人登录的 AI 账号，请勿截图或粘贴发到群聊、公开帖子与 Issue。": "Security Note: Copied connection URLs and prompts are for your own signed-in AI account only. Never share them in group chats, public posts, or Issues.",
    "受限工作区 403 免管理员兜底：Sites / CLI 专用密钥": "Restricted Workspace 403 Fallback: Sites / CLI Dedicated Token",
    "仅本机 127.0.0.1 可签发 · 随时一键断开": "Loopback 127.0.0.1 only · Revoke anytime",
    "仅只读（推荐 · 限 /mcp/readonly）": "Read-only (Recommended · /mcp/readonly)",
    "工作区读写（允许 /mcp）": "Workspace Read/Write (/mcp)",
    "有效期 7 天": "Valid for 7 days",
    "有效期 30 天": "Valid for 30 days",
    "有效期 90 天": "Valid for 90 days",
    "本机生成专用密钥": "Mint Dedicated Token Locally",
    "复制专用密钥": "Copy Dedicated Token",
    "关闭并擦除明文": "Close & Wipe Plaintext",
    "一句话实机效果 · 3 个零依赖 WebGL2 案例（看效果 & 一键复制提示词）": "One-Shot Live Demos · 3 Zero-Dependency WebGL2 Showcases (Copy Prompt)",
    "01 · 黑洞引力透镜仿真 (": "01 · Black Hole Gravitational Lensing (",
    "单文件原生 WebGL2 光线步进 · 三组电影机位与 4 项实时物理滑块 · 集显 60fps": "Single-file native WebGL2 raymarching · 3 cinematic cameras & 4 live physics sliders · 60fps on iGPU",
    "单文件 32 KB": "Single file 32 KB",
    "02 · 元素全息金属典藏卡 (": "02 · Holographic Metallic Element Cards (",
    "单文件 54 KB": "Single file 54 KB",
    "03 · 霓虹峡谷 3D 低空飞行 (": "03 · Neon Canyon 3D Low-Altitude Flight (",
    "5 文件本地工程 · 合成波线框峡谷 + Web Audio 实时合成音效 + 键鼠切换": "5-file local project · Synthwave wireframe canyon + Web Audio synth SFX + keyboard/mouse toggle",
    "5 文件工程": "5-file project",
    "复制提示词": "Copy Prompt",
    "全部 (9)": "All (9)",
    "3D 实机效果案例 (3)": "3D Live Showcases (3)",
    "4. 连上后可以试试看": "4. Try After Connecting",
    "第 4 步 · 连上后立刻体验": "Step 4 · Try Right Away",
    "连上电脑后，可以马上试试这些": "Connected? Try These Next",
    "更多体验案例 →": "More Examples →",
    "复制后，在对话框里输入 ": "Type ",
    " 选中你刚命名的连接器，再粘贴发送。": " to pick your connector in chat, then paste and send.",
    "点一下复制，直接发给网页版 Gemini 或 ChatGPT，看它帮你写离线 3D 作品或处理本地文件。复制后，在对话框里输入 ": "Click to copy and send to web Gemini or ChatGPT to build offline 3D demos or edit local files. Type ",
    "3D 作品体验 (3)": "3D Demos (3)",
    "代码审查与后台运行": "Code Review & Background",
    "多电脑与备份": "Multi-PC & Backup",
    "黑洞引力透镜仿真": "Black Hole Lensing Simulation",
    "写一个纯离线 3D 黑洞网页，支持三组电影机位与物理滑块实时调节。": "Build an offline 3D black hole webpage with 3 cinematic cameras and live physics sliders.",
    "纯离线单文件生成带发光吸积盘的 3D 黑洞网页，支持三组电影机位与 4 项物理滑块。": "Single-file offline 3D black hole with glowing accretion disk, 3 cameras & 4 sliders.",
    "元素全息金属典藏卡": "Holographic Element Cards",
    "无外链生成 3 张带金属彩虹反光的 3D 元素卡，支持悬停倾角与翻转。": "Generate 3 metallic iridescent 3D element cards offline with spring tilt & flip.",
    "无外部图片生成 3 张带彩虹金属反光的 3D 元素卡，支持悬停倾角、180° 翻转与色温切换。": "Zero-image procedural 3D holographic cards with spring tilt, 180° flip & lighting modes.",
    "霓虹峡谷 3D 低空飞行": "Neon Canyon 3D Flight",
    "自动建 5 文件本地工程，生成带合成音效的 3D 飞行小游戏并本地运行。": "Create a 5-file local project for a 3D synthwave flight game with Web Audio SFX.",
    "自动新建 5 文件本地工程，写出带 Web Audio 实时合成音效的 3D 低空飞行小游戏。": "Auto-creates a 5-file offline 3D flight game with real-time Web Audio synth SFX.",
    "单文件 3D": "Single-file 3D",
    "全息 3D 卡": "3D Holo Cards",
    "查看全文": "View Full",
    "收起全文": "Hide Full",
    "查看提示词": "View Prompt",
    "收起提示词": "Hide Prompt",
    "跨目录并行代码审查": "Cross-Directory Code Review",
    "Word 保样式改稿 + Excel 填公式": "Word Styled Edit + Excel Formulas",
    "对照 PDF 需求直接看本地截图": "Inspect Local Screenshots vs PDF",
    "后台静默跑测试与打包": "Silent Background Test & Build",
    "多台电脑环境对比": "Multi-PC Environment Diff",
    "换机恢复后的状态核验": "Post-Migration Status Check",
    "查看 4 步实拍截图教程": "View 4-Step Screenshot Guide",
    "点击展开，支持点击放大": "Click to expand & zoom",
  });

  var PATTERNS = [
    [/^本机设备：(.+?)\s*·\s*版本\s*v(.+)$/, "Device: $1 · v$2"],
    [/^本机设备：(.+)$/, "Device: $1"],
    [/^已就绪\s*·\s*(.+)$/, "Ready · $1"],
    [/^已自动填入本机连接地址（已连\s*(\d+)\s*个会话）。$/, "Live MCP URLs loaded ($1 active session(s))."],
    [/^(\d+)\s*\/\s*(\d+)\s*步$/, "$1 / $2 steps"],
    [/^已连\s*(\d+)$/, "$1 connected"],
    [/^已结束（退出码\s*(-?\d+)）$/, "Finished (exit $1)"],
    [/^运行中（PID\s*(\d+)）$/, "Running (PID $1)"],
    [/^耗时\s*([\d.]+)\s*秒\s*·\s*目录：/, "Duration $1s · Dir: "],
    [/^安全回收箱\s*\((\d+)\)$/, "Trash ($1)"],
    [/^免登录直连\s*·\s*已连通$/, "Direct Tunnel · Connected"],
    [/^Cloudflare\s*固定网关\s*·\s*已连通$/, "Cloudflare Gateway · Connected"],
    [/^Cloudflare\s*网关\s*·\s*已连通$/, "Cloudflare Gateway · Connected"],
    [/^自有主站\s*·\s*已连通$/, "Custom Server · Connected"],
    [/^已连接\s*(\d+)\s*个会话$/, "$1 session(s) connected"],
    [/^已检测到网页端授权成功（已连\s*(\d+)\s*个会话）！请继续第\s*3\s*步发送首句测试词。$/, "Web host authorized ($1 session(s) connected)! Continue to Step 3 to send your first test prompt."],
    [/^已连\s*(\d+)\s*个会话$/, "$1 session(s) connected"],
    [/^共\s*(\d+)\s*条记录$/, "$1 entries"],
    [/^共\s*(\d+)\s*项$/, "$1 items"]
  ];

  var origText = new WeakMap();
  var origAttr = new WeakMap();
  var currentLang = "zh";
  var observer = null;
  var isApplying = false;
  var rafId = 0;

  function translateText(raw) {
    if (!raw || !/[\u4e00-\u9fff]/.test(raw)) return raw;
    var lead = raw.match(/^\s*/)[0];
    var trail = raw.match(/\s*$/)[0];
    var core = raw.trim();
    if (!core) return raw;
    if (Object.prototype.hasOwnProperty.call(ZH_TO_EN, core)) {
      return lead + ZH_TO_EN[core] + trail;
    }
    for (var i = 0; i < PATTERNS.length; i++) {
      if (PATTERNS[i][0].test(core)) {
        return lead + core.replace(PATTERNS[i][0], PATTERNS[i][1]) + trail;
      }
    }
    return raw;
  }

  function shouldSkipElement(el) {
    if (!el || el.nodeType !== 1) return false;
    var tag = el.tagName;
    if (tag === "SCRIPT" || tag === "STYLE" || tag === "SVG" || tag === "CODE" || tag === "PRE") return true;
    if (el.id === "lang-toggle-btn" || el.id === "service-status-text") return true;
    if (el.classList && (el.classList.contains("mono-value") || el.classList.contains("lang-toggle-btn"))) return true;
    return false;
  }

  function applyToNode(root, lang) {
    if (!root) return;
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
    var node;
    while ((node = walker.nextNode())) {
      var parent = node.parentElement;
      if (!parent || shouldSkipElement(parent)) continue;
      if (parent.closest && parent.closest("script,style,svg,pre,.lang-toggle-btn,#service-status-text")) continue;
      if (lang === "en") {
        var cur = node.nodeValue;
        if (!origText.has(node)) {
          if (/[\u4e00-\u9fff]/.test(cur)) origText.set(node, cur);
        } else if (/[\u4e00-\u9fff]/.test(cur) && cur !== origText.get(node)) {
          origText.set(node, cur);
        }
        var src = origText.get(node) || cur;
        var next = translateText(src);
        if (next !== cur) node.nodeValue = next;
      } else {
        if (origText.has(node)) {
          var zh = origText.get(node);
          if (node.nodeValue !== zh) node.nodeValue = zh;
        }
      }
    }
    var els = root.querySelectorAll ? root.querySelectorAll("[placeholder],[title]") : [];
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      if (shouldSkipElement(el)) continue;
      var saved = origAttr.get(el);
      if (!saved) {
        saved = {};
        origAttr.set(el, saved);
      }
      ["placeholder", "title"].forEach(function (attr) {
        var val = el.getAttribute(attr);
        if (!val) return;
        if (lang === "en") {
          if (!saved[attr] && /[\u4e00-\u9fff]/.test(val)) saved[attr] = val;
          var tr = translateText(saved[attr] || val);
          if (tr !== val) el.setAttribute(attr, tr);
        } else if (saved[attr] && val !== saved[attr]) {
          el.setAttribute(attr, saved[attr]);
        }
      });
    }
  }

  function updateToggleButtons(lang) {
    var btns = document.querySelectorAll("#lang-toggle-btn, .lang-toggle-btn");
    for (var i = 0; i < btns.length; i++) {
      var opts = btns[i].querySelectorAll("[data-lang-opt]");
      for (var j = 0; j < opts.length; j++) {
        opts[j].classList.toggle("active", opts[j].getAttribute("data-lang-opt") === lang);
      }
      btns[i].setAttribute("aria-pressed", lang === "en" ? "true" : "false");
    }
  }

  function ensureObserver() {
    if (observer || typeof MutationObserver === "undefined") return;
    observer = new MutationObserver(function () {
      if (isApplying || currentLang !== "en") return;
      if (rafId) cancelAnimationFrame(rafId);
      rafId = requestAnimationFrame(function () {
        rafId = 0;
        if (currentLang === "en") apply("en");
      });
    });
    if (document.body) {
      observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    }
  }

  function apply(lang) {
    isApplying = true;
    try {
      currentLang = lang === "en" ? "en" : "zh";
      document.documentElement.lang = currentLang === "en" ? "en" : "zh-CN";
      document.documentElement.setAttribute("data-lang", currentLang);
      if (!origText.has(document)) origText.set(document, document.title);
      document.title = currentLang === "en" ? translateText(origText.get(document)) : origText.get(document);
      if (document.body) applyToNode(document.body, currentLang);
      updateToggleButtons(currentLang);
      if (currentLang === "en") ensureObserver();
    } finally {
      isApplying = false;
    }
  }

  function setLang(lang) {
    var next = lang === "en" ? "en" : "zh";
    try { localStorage.setItem(STORAGE_KEY, next); } catch (_) {}
    apply(next);
    return next;
  }

  function toggleLang() {
    return setLang(currentLang === "en" ? "zh" : "en");
  }

  function getLang() {
    try {
      var saved = localStorage.getItem(STORAGE_KEY);
      if (saved === "en" || saved === "zh") return saved;
    } catch (_) {}
    return "zh";
  }

  function boot() {
    var btns = document.querySelectorAll("#lang-toggle-btn, .lang-toggle-btn");
    for (var i = 0; i < btns.length; i++) {
      if (btns[i].dataset.i18nBound) continue;
      btns[i].dataset.i18nBound = "1";
      btns[i].addEventListener("click", function () { toggleLang(); });
    }
    var initial = getLang();
    updateToggleButtons(initial);
    if (initial === "en") apply("en");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }

  global.WebAI2PCI18n = {
    getLang: getLang,
    setLang: setLang,
    toggleLang: toggleLang,
    apply: apply,
    ZH_TO_EN: ZH_TO_EN
  };
})(typeof window !== "undefined" ? window : globalThis);

(function (global) {
  "use strict";
  if (typeof document === "undefined" || typeof window === "undefined") return;

  var SHOTS = [
    {"zh": "1. 左下角点 Personal Intelligence", "en": "1. Click Personal Intelligence at bottom-left", "src": "/static/tutorials/gemini-step1-personal-intelligence.png"},
    {"zh": "2. 进入 Connected Apps", "en": "2. Open Connected Apps", "src": "/static/tutorials/gemini-step2-connected-apps.png"},
    {"zh": "3. 点右上角 + Custom 添加自定义连接器", "en": "3. Click + Custom at top-right", "src": "/static/tutorials/gemini-step3-connectors-custom.png"},
    {"zh": "4. 粘贴 /mcp 地址到 MCP Server URL 并点 Next", "en": "4. Paste /mcp into MCP Server URL and click Next", "src": "/static/tutorials/gemini-step4-mcp-server-url.png"}
  ];
  var lightboxEl = null;
  var currentIdx = 0;

  function isEn() {
    return (document.documentElement.getAttribute("data-lang") || "zh") === "en";
  }

  function injectStyles() {
    if (document.getElementById("w2p-shot-gallery-style")) return;
    var st = document.createElement("style");
    st.id = "w2p-shot-gallery-style";
    st.textContent = [
      ".tut-shot-fold { margin-top: 10px; border: 1px solid var(--border); border-radius: 9px; background: var(--surface); overflow: hidden; }",
      ".tut-shot-summary { list-style: none; cursor: pointer; display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 8px 12px; font-size: 13px; font-weight: 600; color: var(--primary); user-select: none; transition: background-color 120ms ease; }",
      ".tut-shot-summary::-webkit-details-marker { display: none; }",
      ".tut-shot-summary:hover { background: var(--primary-soft); }",
      ".tut-shot-summary-left { display: inline-flex; align-items: center; gap: 7px; }",
      ".tut-shot-chev { width: 14px; height: 14px; flex-shrink: 0; transition: transform 160ms ease; }",
      ".tut-shot-fold[open] .tut-shot-chev { transform: rotate(90deg); }",
      ".tut-shot-hint { font-size: 11.8px; font-weight: 500; color: var(--muted); }",
      ".tut-shot-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; padding: 12px; border-top: 1px solid var(--border); background: var(--surface-alt); }",
      ".tut-shot-card { display: flex; flex-direction: column; gap: 6px; padding: 8px; border-radius: 8px; border: 1px solid var(--border); background: var(--surface); cursor: zoom-in; text-align: left; transition: border-color 120ms ease, transform 120ms ease; }",
      ".tut-shot-card:hover { border-color: var(--primary); transform: translateY(-1px); }",
      ".tut-shot-thumb-wrap { width: 100%; aspect-ratio: 16 / 10; border-radius: 6px; overflow: hidden; background: var(--surface-inset); border: 1px solid var(--border); display: flex; align-items: center; justify-content: center; }",
      ".tut-shot-thumb { max-width: 100%; max-height: 100%; width: auto; height: auto; object-fit: contain; display: block; }",
      ".tut-shot-cap { font-size: 12.2px; font-weight: 600; color: var(--text-secondary); line-height: 1.4; }",
      ".tut-lb-backdrop { position: fixed; inset: 0; z-index: 12000; background: rgba(10, 14, 20, 0.84); -webkit-backdrop-filter: blur(6px); backdrop-filter: blur(6px); display: none; align-items: center; justify-content: center; padding: 20px; }",
      ".tut-lb-backdrop.open { display: flex; }",
      ".tut-lb-dialog { max-width: min(980px, 96vw); max-height: 92vh; width: auto; background: var(--surface); border: 1px solid var(--border-strong); border-radius: 13px; overflow: hidden; display: flex; flex-direction: column; box-shadow: 0 24px 60px rgba(0,0,0,0.45); }",
      ".tut-lb-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 14px; border-bottom: 1px solid var(--border); background: var(--surface-alt); }",
      ".tut-lb-title { font-size: 13.8px; font-weight: 650; color: var(--text); }",
      ".tut-lb-stage { padding: 14px; display: flex; align-items: center; justify-content: center; background: #0B0E13; min-height: 220px; overflow: auto; }",
      ".tut-lb-img { max-width: 100%; max-height: 70vh; width: auto; height: auto; border-radius: 6px; display: block; }",
      ".tut-lb-foot { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 10px 14px; border-top: 1px solid var(--border); background: var(--surface-alt); }",
      ".tut-lb-counter { font-size: 12.5px; font-weight: 600; color: var(--muted); }",
      "@media (max-width: 680px) { .tut-shot-grid { grid-template-columns: minmax(0, 1fr); } }"
    ].join("\n");
    document.head.appendChild(st);
  }

  function ensureLightbox() {
    if (lightboxEl) return lightboxEl;
    var el = document.createElement("div");
    el.className = "tut-lb-backdrop";
    el.id = "w2p-shot-lightbox";
    el.setAttribute("role", "dialog");
    el.setAttribute("aria-modal", "true");
    el.innerHTML =
      '<div class="tut-lb-dialog">' +
      '  <div class="tut-lb-head">' +
      '    <span class="tut-lb-title" id="w2p-lb-title"></span>' +
      '    <button type="button" class="btn btn-sm" id="w2p-lb-close" aria-label="Close">×</button>' +
      '  </div>' +
      '  <div class="tut-lb-stage"><img class="tut-lb-img" id="w2p-lb-img" alt=""></div>' +
      '  <div class="tut-lb-foot">' +
      '    <button type="button" class="btn btn-sm" id="w2p-lb-prev">← 上一张</button>' +
      '    <span class="tut-lb-counter" id="w2p-lb-counter">1 / 4</span>' +
      '    <button type="button" class="btn btn-primary btn-sm" id="w2p-lb-next">下一张 →</button>' +
      '  </div>' +
      '</div>';
    document.body.appendChild(el);

    el.addEventListener("click", function (ev) {
      if (ev.target === el) closeLightbox();
    });
    el.querySelector("#w2p-lb-close").addEventListener("click", closeLightbox);
    el.querySelector("#w2p-lb-prev").addEventListener("click", function () {
      openLightbox((currentIdx - 1 + SHOTS.length) % SHOTS.length);
    });
    el.querySelector("#w2p-lb-next").addEventListener("click", function () {
      openLightbox((currentIdx + 1) % SHOTS.length);
    });
    document.addEventListener("keydown", function (ev) {
      if (!lightboxEl || !lightboxEl.classList.contains("open")) return;
      if (ev.key === "Escape") closeLightbox();
      else if (ev.key === "ArrowLeft") openLightbox((currentIdx - 1 + SHOTS.length) % SHOTS.length);
      else if (ev.key === "ArrowRight") openLightbox((currentIdx + 1) % SHOTS.length);
    });
    lightboxEl = el;
    return el;
  }

  function openLightbox(idx) {
    currentIdx = Math.max(0, Math.min(SHOTS.length - 1, idx));
    var el = ensureLightbox();
    var item = SHOTS[currentIdx];
    var en = isEn();
    el.querySelector("#w2p-lb-title").textContent = en ? item.en : item.zh;
    var img = el.querySelector("#w2p-lb-img");
    img.src = item.src;
    img.alt = en ? item.en : item.zh;
    el.querySelector("#w2p-lb-counter").textContent = (currentIdx + 1) + " / " + SHOTS.length;
    el.querySelector("#w2p-lb-prev").textContent = en ? "← Prev" : "← 上一张";
    el.querySelector("#w2p-lb-next").textContent = en ? "Next →" : "下一张 →";
    el.classList.add("open");
  }

  function closeLightbox() {
    if (lightboxEl) lightboxEl.classList.remove("open");
  }

  function populateContainer(detailsEl) {
    if (!detailsEl || detailsEl.dataset.shotsMounted === "1") return;
    detailsEl.dataset.shotsMounted = "1";
    var grid = document.createElement("div");
    grid.className = "tut-shot-grid";
    SHOTS.forEach(function (item, idx) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "tut-shot-card";
      btn.setAttribute("data-shot-idx", String(idx));
      btn.innerHTML =
        '<div class="tut-shot-thumb-wrap"><img class="tut-shot-thumb" loading="lazy" alt=""></div>' +
        '<span class="tut-shot-cap"></span>';
      var img = btn.querySelector("img");
      img.src = item.src;
      img.alt = item.zh;
      var cap = btn.querySelector(".tut-shot-cap");
      cap.textContent = item.zh;
      btn.addEventListener("click", function () {
        openLightbox(idx);
      });
      grid.appendChild(btn);
    });
    detailsEl.appendChild(grid);
  }

  function mountAll() {
    injectStyles();
    var nodes = document.querySelectorAll("[data-gemini-shot-gallery]");
    for (var i = 0; i < nodes.length; i++) {
      populateContainer(nodes[i]);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mountAll);
  } else {
    mountAll();
  }

  global.WebAI2PCGeminiShots = {
    SHOTS: SHOTS,
    openLightbox: openLightbox,
    mountAll: mountAll
  };
})(typeof window !== "undefined" ? window : globalThis);
