/* WebAI2PC Secrecy Controls, Anti-Share Copy Guard & One-Click Uninstall UI (security-uninstall.js)
 * Loaded cleanly via studio/routes.py on both / (/studio) and /tutorials without mutating peer-owned templates.
 */
(function () {
  "use strict";

  var ANTI_SHARE_PROMPT_TAIL =
    "\n安全提醒：以上内容含您本机的专属连接地址，仅限粘贴给您本人的 ChatGPT 账号，请勿发往微信群、公开论坛、GitHub Issue 或转给他人（若不慎外发可在本地控制台点击「更换私密地址」作废旧链接）。";
  var ANTI_SHARE_TOAST_SUFFIX = " · 仅限本人账号使用，请勿发往群聊或公开帖子";

  var cachedPasswordPlain = "";
  var cachedCsrf = "";
  var endpointSecretEnabled = false;
  var endpointSecretMasked = "";
  var plaintextPasswordWiped = false;

  function $(id) {
    return document.getElementById(id);
  }

  function decorateCopiedText(raw) {
    var s = String(raw || "");
    if (
      s.indexOf("插件名称：WebAI2PC") >= 0 &&
      s.indexOf("MCP 地址：https://") >= 0 &&
      s.indexOf("安全提醒：") < 0
    ) {
      return s + ANTI_SHARE_PROMPT_TAIL;
    }
    return s;
  }

  function installClipboardAntiShareHook() {
    if (
      typeof navigator !== "undefined" &&
      navigator.clipboard &&
      typeof navigator.clipboard.writeText === "function" &&
      !navigator.clipboard.__cosmosAntiShareWrapped
    ) {
      var origWrite = navigator.clipboard.writeText.bind(navigator.clipboard);
      var wrapped = function (txt) {
        return origWrite(decorateCopiedText(txt));
      };
      wrapped.__cosmosAntiShareWrapped = true;
      try {
        navigator.clipboard.writeText = wrapped;
      } catch (e) {}
    }

    if (typeof document !== "undefined" && typeof document.execCommand === "function" && !document.__cosmosExecCopyWrapped) {
      var origExec = document.execCommand.bind(document);
      document.execCommand = function (cmd) {
        if (String(cmd || "").toLowerCase() === "copy") {
          var active = document.activeElement;
          if (active && active.tagName === "TEXTAREA" && active.hasAttribute("readonly")) {
            active.value = decorateCopiedText(active.value);
          }
        }
        return origExec.apply(document, arguments);
      };
      document.__cosmosExecCopyWrapped = true;
    }

    var toast = $("toast-banner");
    if (toast && typeof MutationObserver === "function") {
      var obs = new MutationObserver(function () {
        var t = String(toast.textContent || "");
        if (!t || t.indexOf("请勿发往") >= 0 || t.indexOf("切勿发往") >= 0) return;
        if (
          t.indexOf("已复制连接地址") >= 0 ||
          t.indexOf("已复制连接请求") >= 0 ||
          t.indexOf("已复制 6 位动态配对码") >= 0 ||
          t.indexOf("已复制 4 位核对码") >= 0 ||
          t === "已复制到剪贴板"
        ) {
          toast.textContent = t + ANTI_SHARE_TOAST_SUFFIX;
        }
      });
      obs.observe(toast, { childList: true, characterData: true, subtree: true });
    }
  }

  function showStudioToast(msg, isErr) {
    var b = $("toast-banner");
    if (!b) return;
    b.textContent = msg;
    b.className = "toast-banner visible" + (isErr ? " toast-err error" : "");
    setTimeout(function () {
      b.classList.remove("visible");
    }, 3400);
  }

  function getLatestCsrf() {
    if (typeof document !== "undefined") {
      var metaEl = document.querySelector('meta[name="studio-csrf"]');
      if (metaEl) {
        var mc = String(metaEl.getAttribute("content") || "").trim();
        if (mc && mc !== "__STUDIO_CSRF__") {
          cachedCsrf = mc;
          return mc;
        }
      }
    }
    return cachedCsrf;
  }

  function readBootMeta() {
    getLatestCsrf();
    var bootEl = $("studio-boot-data");
    if (!bootEl || !bootEl.textContent) return;
    try {
      var doc = JSON.parse(bootEl.textContent);
      if (doc && doc.csrf_token && !cachedCsrf) cachedCsrf = String(doc.csrf_token);
      var conn = (doc && doc.connection) || {};
      endpointSecretEnabled = Boolean(conn.endpoint_secret_enabled);
      endpointSecretMasked = String(conn.endpoint_secret_masked || "");
      plaintextPasswordWiped = Boolean(conn.plaintext_password_wiped);
    } catch (e) {}
  }

  function studioPost(path, payload) {
    var csrfNow = getLatestCsrf();
    var headers = { "Content-Type": "application/json" };
    if (csrfNow) headers["X-Studio-Csrf"] = csrfNow;
    return fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: headers,
      body: JSON.stringify(Object.assign({}, payload, csrfNow ? { csrf_token: csrfNow, csrf: csrfNow } : {}))
    }).then(function (r) {
      return r.json().catch(function () {
        return { ok: false, error: "请求响应解析失败" };
      });
    });
  }

  function syncLatestStudioMeta() {
    if (!$("workbench-view") && !$("studio-main-content")) return Promise.resolve(null);
    return fetch("/api/studio/state", { method: "GET", credentials: "same-origin", cache: "no-store" })
      .then(function (r) {
        return r.ok ? r.json() : null;
      })
      .then(function (doc) {
        if (!doc || !doc.ok) return null;
        if (doc.csrf_token) {
          cachedCsrf = String(doc.csrf_token);
          var metaEl = document.querySelector('meta[name="studio-csrf"]');
          if (metaEl) metaEl.setAttribute("content", cachedCsrf);
        }
        var conn = doc.connection || {};
        endpointSecretEnabled = Boolean(conn.endpoint_secret_enabled);
        endpointSecretMasked = String(conn.endpoint_secret_masked || "");
        plaintextPasswordWiped = Boolean(conn.plaintext_password_wiped);
        scrubDomPasswordAttribute();
        updateSecrecyStripState();
        return doc;
      })
      .catch(function () {
        return null;
      });
  }

  function scrubDomPasswordAttribute() {
    var pwBox = $("conn-pw-box");
    if (!pwBox) return;
    var leaked = pwBox.getAttribute("data-secret") || "";
    if (leaked) {
      cachedPasswordPlain = leaked;
      pwBox.setAttribute("data-secret", "");
    }
  }

  function updateSecrecyStripState() {
    var badge = $("cosmos-ep-secret-badge");
    var rotBtn = $("cosmos-rotate-ep-secret-btn");
    var disBtn = $("cosmos-disable-ep-secret-btn");
    if (badge) {
      badge.textContent = endpointSecretEnabled
        ? "私密路径已开启 (" + (endpointSecretMasked || "24位密钥") + ")"
        : "默认路径 (/mcp)";
    }
    if (rotBtn) {
      rotBtn.textContent = endpointSecretEnabled ? "更换私密地址" : "开启私密地址后缀";
    }
    if (disBtn) {
      disBtn.style.display = endpointSecretEnabled ? "inline-flex" : "none";
    }
    var wipeBtn = $("cosmos-wipe-pw-file-btn");
    if (wipeBtn) {
      wipeBtn.textContent = plaintextPasswordWiped ? "已擦除磁盘明文口令" : "擦除磁盘明文口令";
      wipeBtn.disabled = plaintextPasswordWiped;
    }
    var authWipeBtn = $("auth-wipe-plaintext-pw-btn");
    if (authWipeBtn) {
      authWipeBtn.textContent = plaintextPasswordWiped ? "已擦除本地 txt 明文口令" : "擦除本地 txt 明文口令文件";
      authWipeBtn.disabled = plaintextPasswordWiped;
    }
  }

  function mountAntiShareAndUrlSecrecyStrip() {
    var tutMain = document.querySelector(".tut-main");
    if (tutMain && !$("tut-anti-share-strip")) {
      var tutStrip = document.createElement("div");
      tutStrip.id = "tut-anti-share-strip";
      tutStrip.className = "callout callout-info";
      tutStrip.style.cssText = "margin:0 0 12px;font-size:12.5px;line-height:1.55;";
      tutStrip.textContent =
        "保密提示：点击复制的连接地址、快速配置文本与 6 位配对码仅限粘贴到您本人的 Gemini / ChatGPT 账号，请勿发往微信群、公开论坛、GitHub Issue 或截图外传；如不慎外发，可回控制台点击「更换私密地址」立即作废旧链接。";
      tutMain.insertBefore(tutStrip, tutMain.firstChild);
    }
    updateSecrecyStripState();
  }

  function mountPasswordVaultActions() {
    var pwBox = $("conn-pw-box");
    var toggleBtn = $("toggle-pw-btn");
    var copyPwBtn = $("copy-pw-btn");
    if (!pwBox) return;

    scrubDomPasswordAttribute();
    if (typeof MutationObserver === "function") {
      var pwObs = new MutationObserver(scrubDomPasswordAttribute);
      pwObs.observe(pwBox, { attributes: true, attributeFilter: ["data-secret"] });
    }

    function ensurePasswordLoaded() {
      if (cachedPasswordPlain) return Promise.resolve(cachedPasswordPlain);
      return studioPost("/api/studio/connection", { action: "reveal_password" }).then(function (d) {
        if (d && d.ok && d.connection_password) {
          cachedPasswordPlain = String(d.connection_password);
          return cachedPasswordPlain;
        }
        return "";
      });
    }

    if (toggleBtn) {
      toggleBtn.addEventListener(
        "click",
        function (ev) {
          ev.stopImmediatePropagation();
          var shown = pwBox.getAttribute("data-shown") === "1";
          if (shown) {
            pwBox.setAttribute("data-shown", "0");
            pwBox.textContent = "••••••••••••••••••••";
            toggleBtn.textContent = "显示口令";
            return;
          }
          ensurePasswordLoaded().then(function (pw) {
            pwBox.setAttribute("data-shown", "1");
            pwBox.textContent = pw || "(仅限本机回环控制台查看)";
            toggleBtn.textContent = "隐藏口令";
          });
        },
        true
      );
    }

    if (copyPwBtn) {
      copyPwBtn.addEventListener(
        "click",
        function (ev) {
          ev.stopImmediatePropagation();
          ensurePasswordLoaded().then(function (pw) {
            if (!pw) {
              showStudioToast("当前仅限在本机浏览器复制备用口令", true);
              return;
            }
            if (navigator.clipboard && navigator.clipboard.writeText) {
              navigator.clipboard.writeText(pw);
            }
            showStudioToast("已复制备用口令 · 切勿发给任何他人或群聊", false);
          });
        },
        true
      );
    }

    var btnRow = copyPwBtn && copyPwBtn.parentElement;
    if (btnRow && !$("cosmos-rotate-pw-btn")) {
      var rotPwBtn = document.createElement("button");
      rotPwBtn.type = "button";
      rotPwBtn.id = "cosmos-rotate-pw-btn";
      rotPwBtn.className = "btn btn-sm";
      rotPwBtn.textContent = "重置口令";
      rotPwBtn.title = "重新生成随机口令并写入系统加密保险箱";
      rotPwBtn.addEventListener("click", function () {
        rotPwBtn.disabled = true;
        studioPost("/api/studio/connection", { action: "rotate_password", revoke_sessions: false }).then(function (d) {
          rotPwBtn.disabled = false;
          if (!d || !d.ok) return showStudioToast((d && d.error) || "重置口令失败", true);
          cachedPasswordPlain = String((d.connection && d.connection.connection_password) || d.connection_password || "");
          if (pwBox.getAttribute("data-shown") === "1" && cachedPasswordPlain) {
            pwBox.textContent = cachedPasswordPlain;
          }
          showStudioToast("已重置备用连接口令并加密保存", false);
        });
      });

      var wipeBtn = document.createElement("button");
      wipeBtn.type = "button";
      wipeBtn.id = "cosmos-wipe-pw-file-btn";
      wipeBtn.className = "btn btn-sm";
      wipeBtn.title = "仅保留本机 DPAPI/加密保险箱口令，擦除本地 txt 说明文件中的明文口令";
      wipeBtn.addEventListener("click", function () {
        wipeBtn.disabled = true;
        studioPost("/api/studio/connection", { action: "wipe_plaintext_password" }).then(function (d) {
          if (!d || !d.ok) {
            wipeBtn.disabled = false;
            return showStudioToast((d && d.error) || "擦除明文口令失败", true);
          }
          plaintextPasswordWiped = true;
          updateSecrecyStripState();
          showStudioToast("已擦除磁盘说明文件中的明文口令（本机加密保险箱仍可正常验证）", false);
        });
      });

      btnRow.appendChild(rotPwBtn);
      btnRow.appendChild(wipeBtn);
      updateSecrecyStripState();
    }
  }

  function mountOneClickUninstallCard() {
    var runtimePane = $("settings-pane-runtime");
    if (!runtimePane || $("cosmos-uninstall-group")) return;

    var grp = document.createElement("div");
    grp.id = "cosmos-uninstall-group";
    grp.className = "settings-group settings-danger-group";
    grp.innerHTML =
      '<div class="settings-group-title">一键卸载本机服务</div>' +
      '<div class="setting-row" style="align-items:flex-start;flex-wrap:wrap;gap:12px;">' +
      '  <div class="setting-row-text" style="flex:1 1 280px;">' +
      '    <div class="setting-row-title">清理后台守护进程、开机自启、桌面快捷方式与本地凭据</div>' +
      '    <div class="setting-row-sub">不会触碰或删除您自己工作目录里的任何项目代码文件。也可随时双击解压文件夹内的 <code>一键卸载_Cosmos_MCP.bat</code>（macOS/Linux 运行 <code>./uninstall_cosmos_mcp.sh</code>）或在 Windows「设置 -> 已安装的应用」中卸载。</div>' +
      '    <label class="chk-inline" style="margin-top:8px;font-size:12.5px;display:inline-flex;align-items:center;gap:6px;">' +
      '      <input type="checkbox" id="cosmos-uninstall-purge-chk" checked>' +
      '      <span>同时以 0x00 字节覆写粉碎全部口令/密钥/授权令牌并清空状态目录（推荐）</span>' +
      '    </label>' +
      '    <div style="margin-top:8px;max-width:460px;">' +
      '      <input type="password" id="cosmos-uninstall-cf-token" class="flex-input" style="width:100%;font-size:12px;" placeholder="可选：若曾部署 Cloudflare Worker，填入一次 API 令牌可顺带删除云端脚本" autocomplete="off">' +
      '    </div>' +
      '  </div>' +
      '  <div class="ws-actions">' +
      '    <button type="button" class="btn btn-danger btn-sm" id="cosmos-open-uninstall-confirm-btn">一键卸载…</button>' +
      '  </div>' +
      '</div>' +
      '<div id="cosmos-uninstall-confirm-bar" class="callout callout-danger" style="display:none;margin-top:10px;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;">' +
      '  <span id="cosmos-uninstall-confirm-txt">确认立即停止所有连接通道并卸载本机 WebAI2PC 服务？</span>' +
      '  <div class="ws-actions">' +
      '    <button type="button" class="btn btn-danger btn-sm" id="cosmos-confirm-uninstall-btn">确认彻底卸载</button>' +
      '    <button type="button" class="btn btn-sm" id="cosmos-cancel-uninstall-btn">取消</button>' +
      '  </div>' +
      '</div>';

    runtimePane.appendChild(grp);

    var openBtn = $("cosmos-open-uninstall-confirm-btn");
    var bar = $("cosmos-uninstall-confirm-bar");
    var cancelBtn = $("cosmos-cancel-uninstall-btn");
    var confirmBtn = $("cosmos-confirm-uninstall-btn");
    var purgeChk = $("cosmos-uninstall-purge-chk");

    if (openBtn && bar) {
      openBtn.addEventListener("click", function () {
        var isPurge = !purgeChk || purgeChk.checked;
        if ($("cosmos-uninstall-confirm-txt")) {
          $("cosmos-uninstall-confirm-txt").textContent = isPurge
            ? "确认停止后台服务、移除开机自启与快捷方式，并 0x00 粉碎全部本地凭据与运行目录？（您的项目代码目录完全保留）"
            : "确认停止后台服务并卸载快捷方式与开机自启？（保留 .undo_history 修改撤回快照）";
        }
        if (confirmBtn) confirmBtn.textContent = isPurge ? "确认彻底卸载" : "确认标准卸载";
        bar.style.display = "flex";
      });
    }
    if (cancelBtn && bar) {
      cancelBtn.addEventListener("click", function () {
        bar.style.display = "none";
      });
    }
    if (confirmBtn) {
      confirmBtn.addEventListener("click", function () {
        confirmBtn.disabled = true;
        var isPurge = !purgeChk || purgeChk.checked;
        var cfTok = ($("cosmos-uninstall-cf-token") && $("cosmos-uninstall-cf-token").value.trim()) || "";
        studioPost("/api/studio/uninstall", { purge: isPurge, cf_api_token: cfTok }).then(function (d) {
          if (!d || !d.ok) {
            confirmBtn.disabled = false;
            return showStudioToast((d && d.error) || "仅允许在本机浏览器执行一键卸载", true);
          }
          document.body.innerHTML =
            '<div style="max-width:560px;margin:12vh auto;padding:28px 30px;border-radius:14px;border:1px solid rgba(148,163,184,0.3);font-family:system-ui,-apple-system,sans-serif;line-height:1.65;">' +
            '<h2 style="margin:0 0 10px;font-size:20px;">已完成本机服务卸载与凭据清理</h2>' +
            '<p style="margin:0 0 10px;opacity:0.88;">后台守护进程、连接隧道、开机自启项、桌面快捷方式及全部 OAuth 授权令牌已清理完毕；您工作区内的项目代码文件未受任何影响。</p>' +
            '<p style="margin:0;font-size:13.5px;opacity:0.75;">现在可以直接关闭此浏览器标签页；如需连同初始解压包一起移除，直接将原解压文件夹拖入回收站即可。</p>' +
            "</div>";
        });
      });
    }
  }

  function init() {
    readBootMeta();
    installClipboardAntiShareHook();
    mountAntiShareAndUrlSecrecyStrip();
    mountPasswordVaultActions();
    mountOneClickUninstallCard();
    syncLatestStudioMeta();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
