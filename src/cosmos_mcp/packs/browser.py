from __future__ import annotations

"""Layer 1 Pluggable Isolated Managed Browser Pack (`cosmos_mcp.packs.browser`).

Provides `BrowserPackPlugin` (`pack_id="browser"`, tool `browser_use`):
1. Directly reuses `cosmos_mcp.core.net_power.StdlibWebSocketClient`, `validate_public_url`, and
   `detect_configured_proxy` (zero duplicate RFC 6455 or Fake-IP SSRF code).
2. Dual-engine execution: prefers Playwright when installed, automatically falling back to system
   Edge/Chrome/Chromium (`--headless=new` + isolated `--user-data-dir`, `CREATE_NO_WINDOW`, zero
   `Origin` header to block cross-site takeover, zero touch on user daily browser profiles).
3. Strict DOM visibility filtering across `snapshot`, `click`, `fill`, and `select`: inspects
   computed `display`, `visibility`, `opacity` across ancestors plus `getBoundingClientRect()`
   `width > 0 && height > 0`, automatically picking the first visible interactive match when a
   selector hits hidden mobile + visible desktop duplicates, or returning `ok=False` when all
   matched elements are hidden.
4. Supports `scroll` (with scroll position & total height in `snapshot`), `select` (`<select>` &
   `[role="combobox"]`), multi-tab `list_tabs` / `switch_tab`, workspace file downloads via CDP
   `Browser.setDownloadBehavior`, and `open_login_window` (`SW_SHOWNOACTIVATE` non-activating
   managed profile window for manual QR/2FA login, never touching personal browser windows).
"""

import atexit
import base64
import contextlib
import contextvars
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union
from urllib.parse import urlsplit
import urllib.request

from cosmos_mcp.core.contracts import PackPlugin, SafetyBand, ToolSpec
from cosmos_mcp.core.guard import DEFAULT_GUARD, WorkspaceGuard, canonical_realpath
from cosmos_mcp.core.net_power import (
    BLOCKED_INTERNAL_HOSTNAMES,
    BLOCKED_INTERNAL_SUFFIXES,
    ERR_SSRF_BLOCKED,
    DnsResolverFn,
    StdlibWebSocketClient,
    detect_configured_proxy,
    validate_public_http_url,
    validate_public_url,
)
from cosmos_mcp.core.proc import (
    CREATE_NO_WINDOW,
    OwnedJobHandle,
    assign_win32_job_kill_on_close,
    get_process_create_token,
    terminate_verified_pid_tree,
    verify_pid_alive,
    win32_no_window_flags,
)
from cosmos_mcp.packs.desktop import (
    build_mcp_image_blocks,
    compress_capture_bytes,
    save_optional_capture,
)


def _is_active_remote_transport_ctx() -> bool:
    with contextlib.suppress(Exception):
        from cosmos_mcp.protocol import transport as _tr_mod

        ctx_var = getattr(_tr_mod, "_REQUEST_TRANSPORT_CTX", None)
        if ctx_var is not None and ctx_var in contextvars.copy_context():
            return bool(getattr(ctx_var.get(), "is_remote", False))
    return False


def _private_lan_cdp_block_patterns() -> List[str]:
    pats: List[str] = [
        "http://127.*",
        "https://127.*",
        "http://0.0.0.0*",
        "https://0.0.0.0*",
        "http://localhost*",
        "https://localhost*",
        "http://[::1]*",
        "https://[::1]*",
        "http://10.*",
        "https://10.*",
        "http://192.168.*",
        "https://192.168.*",
    ]
    for oct2 in range(16, 32):
        pats.append(f"http://172.{oct2}.*")
        pats.append(f"https://172.{oct2}.*")
    return pats


def resolve_pack_effective_state_root(explicit_state_root: Optional[Path], policy: Any, guard: WorkspaceGuard) -> Path:
    if explicit_state_root is not None:
        return explicit_state_root
    pol_sr = getattr(policy, "state_root", None) if policy is not None else None
    return canonical_realpath(pol_sr) if pol_sr else guard.effective_state_root()


def resolve_pack_effective_prefix(explicit_prefix: str, policy: Any, guard: WorkspaceGuard, default: str = "pc") -> str:
    if explicit_prefix:
        return explicit_prefix
    if policy is not None:
        pol_p = str(getattr(policy, "eff_prefix", "") or "").strip()
        if pol_p:
            return pol_p
    return guard.tool_prefix or default


def build_single_pack_tool_tuple(
    *,
    base_name: str,
    handler: Callable[..., Any],
    input_schema: Dict[str, Any],
    title: str,
    description: str,
    pack_id: str,
    action_enum: Tuple[str, ...],
    safety_band: SafetyBand = SafetyBand.WORKSPACE_EXEC,
    param_aliases: Optional[Dict[str, str]] = None,
    open_world: bool = False,
) -> Tuple[ToolSpec, ...]:
    return (
        ToolSpec(
            base_name=base_name,
            handler=handler,
            safety_band=safety_band,
            input_schema=input_schema,
            title=title,
            description=description,
            pack=pack_id,
            param_aliases=dict(param_aliases or {}),
            action_param="action",
            action_enum=action_enum,
            open_world=bool(open_world),
        ),
    )


BROWSER_USE_ACTIONS: Tuple[str, ...] = (
    "open",
    "snapshot",
    "click",
    "fill",
    "select",
    "scroll",
    "list_tabs",
    "switch_tab",
    "open_login_window",
    "screenshot",
    "evaluate",
    "close",
)

MANAGED_PROFILE_MARKER = ".cosmos_managed_browser_profile"

# Protected local control plane ports dynamically supplied via `mcp_port` / `blocked_local_ports`
PROTECTED_LOCAL_CONTROL_PORTS: frozenset[int] = frozenset()

_REF_TOKEN_RE = re.compile(r"^e\d+$", re.IGNORECASE)

_DOM_VISIBILITY_HELPERS_JS = """
  const isElementVisible = (el) => {
    if (!el || el.nodeType !== 1) return false;
    if (el.hasAttribute('hidden')) return false;
    const tag = (el.tagName || '').toLowerCase();
    if (tag === 'input' && (el.getAttribute('type') || '').toLowerCase() === 'hidden') {
      return false;
    }
    const styleSelf = window.getComputedStyle(el);
    if (!styleSelf) return false;
    if (
      styleSelf.display === 'none' ||
      styleSelf.visibility === 'hidden' ||
      styleSelf.visibility === 'collapse' ||
      styleSelf.opacity === '0' ||
      parseFloat(styleSelf.opacity === '' ? '1' : styleSelf.opacity) <= 0
    ) {
      return false;
    }
    const rect = el.getBoundingClientRect();
    if (!(rect.width > 0 && rect.height > 0)) {
      return false;
    }
    let cur = el.parentElement;
    while (cur && cur.nodeType === 1) {
      if (cur.hasAttribute('hidden')) return false;
      const st = window.getComputedStyle(cur);
      if (!st) break;
      if (
        st.display === 'none' ||
        st.visibility === 'hidden' ||
        st.visibility === 'collapse' ||
        st.opacity === '0' ||
        parseFloat(st.opacity === '' ? '1' : st.opacity) <= 0
      ) {
        return false;
      }
      cur = cur.parentElement;
    }
    return true;
  };

  const isElementInteractive = (el) => {
    if (!isElementVisible(el)) return false;
    if (el.disabled) return false;
    if ((el.getAttribute('aria-disabled') || '').toLowerCase() === 'true') return false;
    return true;
  };

  const getScrollMetrics = () => {
    const docEl = document.documentElement || document.body || {};
    const scrollY = Math.round(window.scrollY || window.pageYOffset || docEl.scrollTop || 0);
    const scrollX = Math.round(window.scrollX || window.pageXOffset || docEl.scrollLeft || 0);
    const viewportHeight = Math.round(window.innerHeight || docEl.clientHeight || 0);
    const viewportWidth = Math.round(window.innerWidth || docEl.clientWidth || 0);
    const scrollHeight = Math.round(
      Math.max(docEl.scrollHeight || 0, (document.body && document.body.scrollHeight) || 0, viewportHeight)
    );
    const scrollWidth = Math.round(
      Math.max(docEl.scrollWidth || 0, (document.body && document.body.scrollWidth) || 0, viewportWidth)
    );
    const maxScrollY = Math.max(0, scrollHeight - viewportHeight);
    return {
      scroll_x: scrollX,
      scroll_y: scrollY,
      scroll_height: scrollHeight,
      total_height: scrollHeight,
      scroll_width: scrollWidth,
      viewport_height: viewportHeight,
      viewport_width: viewportWidth,
      max_scroll_y: maxScrollY,
      at_bottom: scrollY >= Math.max(0, maxScrollY - 2),
    };
  };
"""

_SNAPSHOT_INJECT_JS = (
    "(limit) => {\n"
    + _DOM_VISIBILITY_HELPERS_JS
    + """
  const cap = Math.max(10, Math.min(300, Number(limit) || 80));
  for (const oldEl of Array.from(document.querySelectorAll('[data-lpc-ref]'))) {
    oldEl.removeAttribute('data-lpc-ref');
  }
  const sel = [
    'a[href]',
    'button',
    'input',
    'textarea',
    'select',
    '[role="button"]',
    '[role="link"]',
    '[role="checkbox"]',
    '[role="combobox"]',
    '[role="option"]',
    '[role="tab"]',
    '[role="menuitem"]',
    '[contenteditable="true"]',
    '[contenteditable=""]',
    '[onclick]'
  ].join(', ');
  const nodes = Array.from(document.querySelectorAll(sel));
  const items = [];
  let seq = 0;
  for (const el of nodes) {
    if (items.length >= cap) break;
    if (!isElementVisible(el)) {
      continue;
    }
    const rect = el.getBoundingClientRect();
    seq += 1;
    const ref = 'e' + seq;
    el.setAttribute('data-lpc-ref', ref);
    const tag = (el.tagName || '').toLowerCase();
    const role = el.getAttribute('role') || '';
    const isEditable = Boolean(el.isContentEditable);
    const text = ((el.innerText || el.textContent || el.getAttribute('aria-label') || el.getAttribute('placeholder') || '') + '')
      .replace(/\\s+/g, ' ').trim().slice(0, 120);
    let bestSel = '[data-lpc-ref="' + ref + '"]';
    if (el.id) {
      const idSel = '#' + CSS.escape(el.id);
      try {
        if (document.querySelectorAll(idSel).length === 1) {
          bestSel = idSel;
        }
      } catch (_e) {}
    }
    const rawVal = ('value' in el && (el.getAttribute('type') || '').toLowerCase() !== 'password')
      ? String(el.value || '').slice(0, 120)
      : (isEditable ? String(el.textContent || '').trim().slice(0, 120) : '');
    const rec = {
      ref: ref,
      id: el.id || '',
      selector: bestSel,
      tag: tag,
      role: role,
      type: el.getAttribute('type') || '',
      name: el.getAttribute('name') || '',
      contenteditable: isEditable,
      text: text,
      value: rawVal,
      bounds: {
        x: Math.round(rect.x),
        y: Math.round(rect.y),
        width: Math.round(rect.width),
        height: Math.round(rect.height),
      },
    };
    if (tag === 'select' && el.options) {
      rec.options = Array.from(el.options).slice(0, 40).map((o, idx) => ({
        index: idx,
        value: String(o.value || ''),
        label: String(o.text || o.label || '').trim(),
        selected: Boolean(o.selected),
      }));
    }
    items.push(rec);
  }
  const metrics = getScrollMetrics();
  const bodyText = ((document.body && document.body.innerText) ? document.body.innerText : '')
    .replace(/\\n{3,}/g, '\\n\\n').trim().slice(0, 4000);
  return {
    url: String(location.href || ''),
    title: String(document.title || ''),
    element_count: items.length,
    elements: items,
    scroll_x: metrics.scroll_x,
    scroll_y: metrics.scroll_y,
    scroll_height: metrics.scroll_height,
    total_height: metrics.total_height,
    viewport_height: metrics.viewport_height,
    max_scroll_y: metrics.max_scroll_y,
    scroll: metrics,
    text_excerpt: bodyText,
  };
}
"""
)

_RESOLVE_AND_CLICK_DOM_JS = (
    "(args) => {\n"
    + _DOM_VISIBILITY_HELPERS_JS
    + """
  let all = [];
  try {
    all = Array.from(document.querySelectorAll(args.sel));
  } catch (err) {
    return {
      ok: false,
      error_code: 'ERR_INVALID_SELECTOR',
      error: 'Invalid CSS selector `' + args.sel + '`: ' + String(err && err.message ? err.message : err),
    };
  }
  if (all.length === 0) {
    return {
      ok: false,
      error_code: 'ERR_ELEMENT_NOT_FOUND',
      matched_count: 0,
      visible_count: 0,
      error: 'Element not found for selector: ' + args.sel,
    };
  }
  const visible = all.filter(isElementVisible);
  if (visible.length === 0) {
    return {
      ok: false,
      error_code: 'ERR_ELEMENT_HIDDEN',
      matched_count: all.length,
      visible_count: 0,
      error: 'Matched ' + all.length + ' element(s) for selector `' + args.sel + '`, but all are hidden or zero-size.',
    };
  }
  const interactive = visible.filter(isElementInteractive);
  if (interactive.length === 0) {
    return {
      ok: false,
      error_code: 'ERR_ELEMENT_DISABLED',
      matched_count: all.length,
      visible_count: visible.length,
      error: 'Matched visible element(s) for selector `' + args.sel + '`, but all are disabled.',
    };
  }
  const el = interactive[0];
  const tok = String(args.clickTok || '');
  if (tok) {
    for (const prev of Array.from(document.querySelectorAll('[data-lpc-click-tok]'))) {
      prev.removeAttribute('data-lpc-click-tok');
    }
    el.setAttribute('data-lpc-click-tok', tok);
  }
  el.scrollIntoView({block: 'center', inline: 'center'});
  if (args.performJsClick) {
    if (typeof el.focus === 'function') el.focus();
    el.click();
  }
  const rect = el.getBoundingClientRect();
  return {
    ok: true,
    matched_count: all.length,
    visible_count: visible.length,
    picked_index_in_dom: all.indexOf(el),
    picked_tag: (el.tagName || '').toLowerCase(),
    picked_id: el.id || '',
    picked_ref: el.getAttribute('data-lpc-ref') || '',
    bounds: {
      x: Math.round(rect.x),
      y: Math.round(rect.y),
      width: Math.round(rect.width),
      height: Math.round(rect.height),
    },
  };
}
"""
)

_SELECT_OR_FILL_DOM_JS = (
    "(args) => {\n"
    + _DOM_VISIBILITY_HELPERS_JS
    + """
  let all = [];
  try {
    all = Array.from(document.querySelectorAll(args.sel));
  } catch (err) {
    return {
      ok: false,
      error_code: 'ERR_INVALID_SELECTOR',
      error: 'Invalid CSS selector `' + args.sel + '`: ' + String(err && err.message ? err.message : err),
    };
  }
  if (all.length === 0) {
    return {
      ok: false,
      error_code: 'ERR_ELEMENT_NOT_FOUND',
      matched_count: 0,
      visible_count: 0,
      error: 'Element not found for selector: ' + args.sel,
    };
  }
  const visible = all.filter(isElementVisible);
  if (visible.length === 0) {
    return {
      ok: false,
      error_code: 'ERR_ELEMENT_HIDDEN',
      matched_count: all.length,
      visible_count: 0,
      error: 'Matched ' + all.length + ' element(s) for selector `' + args.sel + '`, but all are hidden or zero-size.',
    };
  }
  const interactive = visible.filter(isElementInteractive);
  if (interactive.length === 0) {
    return {
      ok: false,
      error_code: 'ERR_ELEMENT_DISABLED',
      matched_count: all.length,
      visible_count: visible.length,
      error: 'Matched visible element(s) for selector `' + args.sel + '`, but all are disabled.',
    };
  }
  const el = interactive[0];
  el.scrollIntoView({block: 'center', inline: 'center'});
  if (typeof el.focus === 'function') el.focus();
  const tag = (el.tagName || '').toLowerCase();
  const role = (el.getAttribute('role') || '').toLowerCase();

  if (tag === 'select' || args.forceSelect) {
    if (tag !== 'select' && role === 'combobox') {
      if ((el.getAttribute('aria-expanded') || '').toLowerCase() !== 'true') {
        el.click();
      }
      const optNodes = Array.from(document.querySelectorAll('[role="option"]')).filter(isElementVisible);
      const hasIdx = typeof args.index === 'number' && args.index >= 0;
      const wantVal = args.value !== undefined && args.value !== null ? String(args.value).trim() : '';
      const wantLbl = args.label !== undefined && args.label !== null ? String(args.label).trim() : '';
      const wantTxt = args.text !== undefined && args.text !== null ? String(args.text).trim() : '';
      let chosenOpt = null;
      let chosenIdx = -1;
      if (hasIdx && args.index < optNodes.length) {
        chosenIdx = args.index;
        chosenOpt = optNodes[chosenIdx];
      } else {
        const query = (wantLbl || wantVal || wantTxt).toLowerCase();
        chosenIdx = optNodes.findIndex(o => {
          const t = String(o.innerText || o.textContent || o.getAttribute('data-value') || '').trim().toLowerCase();
          const dv = String(o.getAttribute('data-value') || o.getAttribute('value') || '').trim().toLowerCase();
          return (query !== '' && (t === query || dv === query));
        });
        if (chosenIdx >= 0) chosenOpt = optNodes[chosenIdx];
      }
      if (!chosenOpt) {
        return {
          ok: false,
          error_code: 'ERR_OPTION_NOT_FOUND',
          error: 'No matching visible [role="option"] found for combobox selector: ' + args.sel,
        };
      }
      const chosenText = String(chosenOpt.innerText || chosenOpt.textContent || '').trim();
      const chosenVal = String(chosenOpt.getAttribute('data-value') || chosenOpt.getAttribute('value') || chosenText);
      chosenOpt.click();
      return {
        ok: true,
        is_select: true,
        role: 'combobox',
        matched_count: all.length,
        visible_count: visible.length,
        picked_index_in_dom: all.indexOf(el),
        selected_index: chosenIdx,
        selected_value: chosenVal,
        selected_label: chosenText,
      };
    }
    if (tag !== 'select') {
      return {
        ok: false,
        error_code: 'ERR_NOT_SELECT_ELEMENT',
        error: 'Target element <' + tag + '> is not a <select> or [role="combobox"] dropdown for selector: ' + args.sel,
      };
    }
    const opts = Array.from(el.options || []);
    let matchedIdx = -1;
    const hasIdx = typeof args.index === 'number' && args.index >= 0;
    const wantVal = args.value !== undefined && args.value !== null ? String(args.value) : '';
    const wantLbl = args.label !== undefined && args.label !== null ? String(args.label).trim() : '';
    const wantTxt = args.text !== undefined && args.text !== null ? String(args.text) : '';
    if (hasIdx && args.index < opts.length) {
      matchedIdx = args.index;
    }
    if (matchedIdx < 0 && wantVal !== '') {
      matchedIdx = opts.findIndex(o => String(o.value) === wantVal);
    }
    if (matchedIdx < 0 && wantLbl !== '') {
      matchedIdx = opts.findIndex(o => String(o.text || o.label || '').trim() === wantLbl);
      if (matchedIdx < 0) {
        const lowL = wantLbl.toLowerCase();
        matchedIdx = opts.findIndex(o => String(o.text || o.label || '').trim().toLowerCase() === lowL);
      }
    }
    if (matchedIdx < 0 && wantTxt !== '') {
      const trimT = wantTxt.trim();
      matchedIdx = opts.findIndex(o => String(o.value) === wantTxt || String(o.value) === trimT);
      if (matchedIdx < 0) {
        matchedIdx = opts.findIndex(o => String(o.text || o.label || '').trim() === trimT);
      }
      if (matchedIdx < 0) {
        const lowT = trimT.toLowerCase();
        matchedIdx = opts.findIndex(o => String(o.value).toLowerCase() === lowT || String(o.text || o.label || '').trim().toLowerCase() === lowT);
      }
    }
    if (matchedIdx < 0) {
      const avail = opts.slice(0, 15).map((o, i) => i + ':' + JSON.stringify(o.value) + '(' + String(o.text || '').trim() + ')').join(', ');
      return {
        ok: false,
        error_code: 'ERR_OPTION_NOT_FOUND',
        error: 'No matching <option> in <select> for value=' + JSON.stringify(wantVal || wantTxt) + ' label=' + JSON.stringify(wantLbl) + ' index=' + args.index + '. Available: [' + avail + ']',
      };
    }
    const chosen = opts[matchedIdx];
    const selProto = window.HTMLSelectElement && window.HTMLSelectElement.prototype;
    const selDesc = selProto ? Object.getOwnPropertyDescriptor(selProto, 'value') : null;
    el.selectedIndex = matchedIdx;
    chosen.selected = true;
    if (selDesc && selDesc.set) {
      selDesc.set.call(el, chosen.value);
    } else {
      el.value = chosen.value;
    }
    el.dispatchEvent(new Event('input', {bubbles: true}));
    el.dispatchEvent(new Event('change', {bubbles: true}));
    return {
      ok: true,
      is_select: true,
      matched_count: all.length,
      visible_count: visible.length,
      picked_index_in_dom: all.indexOf(el),
      selected_index: matchedIdx,
      selected_value: String(chosen.value || ''),
      selected_label: String(chosen.text || chosen.label || '').trim(),
    };
  }

  const valStr = String(args.text !== undefined && args.text !== null ? args.text : (args.value || ''));
  const proto = tag === 'textarea'
    ? (window.HTMLTextAreaElement && window.HTMLTextAreaElement.prototype)
    : (tag === 'input' ? (window.HTMLInputElement && window.HTMLInputElement.prototype) : null);
  const desc = proto ? Object.getOwnPropertyDescriptor(proto, 'value') : null;
  if (desc && desc.set) {
    desc.set.call(el, valStr);
  } else if (el.isContentEditable) {
    el.textContent = valStr;
  } else {
    el.value = valStr;
  }
  el.dispatchEvent(new Event('input', {bubbles: true}));
  el.dispatchEvent(new Event('change', {bubbles: true}));
  return {
    ok: true,
    is_select: false,
    matched_count: all.length,
    visible_count: visible.length,
    picked_index_in_dom: all.indexOf(el),
    picked_id: el.id || '',
    picked_name: el.getAttribute('name') || '',
    filled_length: valStr.length,
  };
}
"""
)

_SCROLL_DOM_JS = (
    "(args) => {\n"
    + _DOM_VISIBILITY_HELPERS_JS
    + """
  const dir = String(args.direction || 'down').toLowerCase();
  const amt = Math.max(1, Math.abs(Number(args.amount) || 600));
  const sel = String(args.sel || '').trim();
  let scrolledTarget = 'window';

  if (sel) {
    let matches = [];
    try {
      matches = Array.from(document.querySelectorAll(sel));
    } catch (err) {
      return {
        ok: false,
        error_code: 'ERR_INVALID_SELECTOR',
        error: 'Invalid CSS selector `' + sel + '`: ' + String(err && err.message ? err.message : err),
      };
    }
    const vis = matches.filter(isElementVisible);
    if (vis.length === 0) {
      return {
        ok: false,
        error_code: 'ERR_ELEMENT_HIDDEN',
        error: matches.length === 0
          ? ('Element not found for scroll selector: ' + sel)
          : ('Matched ' + matches.length + ' element(s) for scroll selector `' + sel + '`, but all are hidden.'),
      };
    }
    const target = vis[0];
    const canScrollV = target.scrollHeight > target.clientHeight + 2;
    const canScrollH = target.scrollWidth > target.clientWidth + 2;
    if (canScrollV || canScrollH) {
      scrolledTarget = 'element';
      if (dir === 'top') target.scrollTop = 0;
      else if (dir === 'bottom') target.scrollTop = target.scrollHeight;
      else if (dir === 'up') target.scrollTop = Math.max(0, target.scrollTop - amt);
      else if (dir === 'down') target.scrollTop = target.scrollTop + amt;
      else if (dir === 'left') target.scrollLeft = Math.max(0, target.scrollLeft - amt);
      else if (dir === 'right') target.scrollLeft = target.scrollLeft + amt;
      const metrics = getScrollMetrics();
      return {
        ok: true,
        scrolled_target: scrolledTarget,
        element_scroll_top: Math.round(target.scrollTop),
        element_scroll_left: Math.round(target.scrollLeft),
        element_scroll_height: Math.round(target.scrollHeight),
        element_client_height: Math.round(target.clientHeight),
        ...metrics,
        scroll: metrics,
      };
    }
    target.scrollIntoView({block: 'center', inline: 'center'});
    scrolledTarget = 'scrollIntoView';
  } else {
    const docEl = document.documentElement || document.body;
    const maxH = Math.max((docEl && docEl.scrollHeight) || 0, (document.body && document.body.scrollHeight) || 0);
    if (dir === 'top') window.scrollTo(window.scrollX || 0, 0);
    else if (dir === 'bottom') window.scrollTo(window.scrollX || 0, maxH);
    else if (dir === 'up') window.scrollBy(0, -amt);
    else if (dir === 'left') window.scrollBy(-amt, 0);
    else if (dir === 'right') window.scrollBy(amt, 0);
    else window.scrollBy(0, amt);
  }
  const metrics = getScrollMetrics();
  return {
    ok: true,
    scrolled_target: scrolledTarget,
    direction: dir,
    amount: amt,
    ...metrics,
    scroll: metrics,
  };
}
"""
)


def _normalize_browser_selector(raw_sel: str) -> str:
    s = (raw_sel or "").strip()
    if _REF_TOKEN_RE.fullmatch(s):
        return f'[data-lpc-ref="{s.lower()}"]'
    return s


def _local_machine_ips() -> Set[str]:
    ips: Set[str] = {"127.0.0.1", "::1", "0.0.0.0", "::"}
    with contextlib.suppress(Exception):
        hn = socket.gethostname()
        if hn:
            for info in socket.getaddrinfo(hn, None):
                addr = str(info[4][0]).split("%", 1)[0]
                if addr:
                    ips.add(addr)
    return ips


def _normalize_proxy_server_for_chromium(raw_proxy: str) -> str:
    """Normalize env/registry proxy string into a format accepted by Chromium `--proxy-server`."""
    p = (raw_proxy or "").strip()
    if not p:
        return ""
    if "=" in p and "://" not in p:
        parts = [seg.strip() for seg in p.split(";") if seg.strip()]
        chosen = ""
        for seg in parts:
            if seg.lower().startswith("https="):
                chosen = seg.split("=", 1)[1].strip()
                break
            if seg.lower().startswith("http=") and not chosen:
                chosen = seg.split("=", 1)[1].strip()
        p = chosen or parts[0]
    if "://" not in p:
        p = f"http://{p}"
    return p


def resolve_browser_proxy_settings(explicit_proxy: Optional[str] = None) -> Dict[str, str]:
    """Detect active HTTP/HTTPS/OS proxy and build Chromium/Playwright bypass lists (`<-loopback>` included)."""
    raw_https = detect_configured_proxy("https", explicit_proxy=explicit_proxy)
    raw_http = detect_configured_proxy("http", explicit_proxy=explicit_proxy)
    chosen = raw_https or raw_http
    server = _normalize_proxy_server_for_chromium(chosen)
    if not server:
        return {"server": "", "bypass_semicolon": "", "bypass_comma": ""}

    bypass_tokens: List[str] = ["<-loopback>", "localhost", "127.0.0.1", "::1"]
    raw_no_proxy = os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""
    for tok in re.split(r"[,;\s]+", raw_no_proxy):
        clean_t = tok.strip()
        if clean_t and clean_t not in bypass_tokens:
            bypass_tokens.append(clean_t)

    return {
        "server": server,
        "bypass_semicolon": ";".join(bypass_tokens),
        "bypass_comma": ",".join(bypass_tokens),
    }


def validate_outbound_http_url(
    raw_url: str,
    *,
    mcp_port: int = 0,
    blocked_local_ports: Iterable[int] = (),
    mcp_public_url: str = "",
    is_remote_session: bool = False,
    allow_loopback_dev: bool = True,
    proxy_url: Optional[str] = None,
    resolver: Optional[DnsResolverFn] = None,
) -> str:
    """Validate `browser_use` navigation/redirect URL using `cosmos_mcp.core.net_power` SSRF primitives."""
    u = (raw_url or "").strip()
    if not u:
        raise ValueError("`url` is required when action='open' (e.g. 'https://example.com' or a local dev HTTP URL).")

    parsed = urlsplit(u)
    scheme = (parsed.scheme or "").lower()
    if not scheme:
        if u.startswith(("/", "\\", ".")) or (len(u) >= 2 and u[1] == ":"):
            raise PermissionError(
                f"[LOCALPC SSRF GUARD] ({ERR_SSRF_BLOCKED}): Local filesystem paths (`file://`) are blocked in `browser_use`."
            )
        u = f"https://{u}"
        parsed = urlsplit(u)
        scheme = "https"

    if scheme == "file":
        raise PermissionError(
            f"[LOCALPC SSRF GUARD] ({ERR_SSRF_BLOCKED}): `file://` URLs are blocked in `browser_use`."
        )
    if scheme not in ("http", "https"):
        raise ValueError(
            f"[LOCALPC SSRF GUARD]: Unsupported URL scheme `{scheme}:` in `browser_use` (only `http://` and `https://` are allowed)."
        )
    if parsed.username or parsed.password:
        raise PermissionError(f"[LOCALPC SSRF GUARD] ({ERR_SSRF_BLOCKED}): Embedded credentials in URL are prohibited.")

    host = (parsed.hostname or "").strip().strip("[]").lower().rstrip(".")
    if not host:
        raise ValueError("Invalid URL: missing hostname.")
    try:
        eff_port = int(parsed.port) if parsed.port is not None else (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("Invalid URL port.") from exc

    if mcp_public_url:
        pub_p = urlsplit(mcp_public_url.strip())
        pub_h = (pub_p.hostname or "").strip().strip("[]").lower().rstrip(".")
        pub_port = int(pub_p.port) if pub_p.port is not None else (443 if (pub_p.scheme or "").lower() == "https" else 80)
        if pub_h and host == pub_h and eff_port == pub_port:
            raise PermissionError(
                f"[LOCALPC SSRF GUARD] ({ERR_SSRF_BLOCKED}): Access to this MCP server's own public endpoint "
                f"(`{pub_h}:{pub_port}`) is blocked in `browser_use`."
            )

    forbidden_ports: Set[int] = set(PROTECTED_LOCAL_CONTROL_PORTS)
    if int(mcp_port or 0) > 0:
        forbidden_ports.add(int(mcp_port))
    for bp in blocked_local_ports:
        if int(bp or 0) > 0:
            forbidden_ports.add(int(bp))

    local_ips = _local_machine_ips()
    is_loopback_host = host in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or host.endswith(".localhost")
    literal_ip: Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = None
    with contextlib.suppress(ValueError):
        literal_ip = ipaddress.ip_address(host.split("%", 1)[0])

    if literal_ip is not None:
        eff_lit = getattr(literal_ip, "ipv4_mapped", None) or literal_ip
        if eff_lit.is_loopback or str(eff_lit) in local_ips:
            is_loopback_host = True

    if is_loopback_host and eff_port in forbidden_ports:
        raise PermissionError(
            f"[LOCALPC SSRF GUARD] ({ERR_SSRF_BLOCKED}): Access to protected local MCP/control port `{eff_port}` "
            "is strictly blocked in `browser_use`."
        )

    if is_remote_session or not allow_loopback_dev:
        return validate_public_http_url(u, proxy_url=proxy_url, resolver=resolver)

    if host in ("localhost",) or host.endswith(".localhost"):
        return u

    if literal_ip is not None:
        eff_ip = getattr(literal_ip, "ipv4_mapped", None) or literal_ip
        if eff_ip.is_link_local or eff_ip.is_unspecified or eff_ip.is_multicast:
            raise PermissionError(
                f"[LOCALPC SSRF GUARD] ({ERR_SSRF_BLOCKED}): Link-local / metadata / unspecified IP `{eff_ip}` is blocked."
            )
        if (eff_ip.is_loopback or eff_ip.is_private) and eff_port not in forbidden_ports:
            return u
        return validate_public_http_url(u, proxy_url=proxy_url, resolver=resolver)

    if host in BLOCKED_INTERNAL_HOSTNAMES or any(host.endswith(sfx) for sfx in BLOCKED_INTERNAL_SUFFIXES):
        raise PermissionError(
            f"[LOCALPC SSRF GUARD] ({ERR_SSRF_BLOCKED}): Internal/metadata hostname `{host}` is blocked."
        )

    validate_public_url(u, proxy_url=proxy_url, allowed_schemes=("http", "https"), resolver=resolver)
    return u


def _validate_browser_url_pair(
    raw_url: str,
    *,
    mcp_port: int = 0,
    blocked_local_ports: Iterable[int] = (),
    mcp_public_url: str = "",
    is_remote_session: bool = False,
    allow_loopback_dev: bool = True,
    proxy_url: Optional[str] = None,
    resolver: Optional[DnsResolverFn] = None,
) -> Tuple[Optional[str], Optional[str]]:
    try:
        clean_u = validate_outbound_http_url(
            raw_url,
            mcp_port=mcp_port,
            blocked_local_ports=blocked_local_ports,
            mcp_public_url=mcp_public_url,
            is_remote_session=is_remote_session,
            allow_loopback_dev=allow_loopback_dev,
            proxy_url=proxy_url,
            resolver=resolver,
        )
        return clean_u, None
    except PermissionError as pexc:
        msg = str(pexc)
        if "[LOCALPC SSRF GUARD]" not in msg:
            msg = f"[LOCALPC SSRF GUARD]: {msg}"
        return None, msg
    except ValueError as vexc:
        return None, str(vexc)
    except Exception as exc:
        return None, f"[LOCALPC SSRF GUARD]: {exc}"


def _ensure_win32_no_window_popen_for_playwright() -> None:
    """Ensure Playwright's Windows node driver subprocess spawns with `CREATE_NO_WINDOW`."""
    if sys.platform != "win32":
        return
    if getattr(subprocess.Popen, "_cosmos_no_window_patched", False):
        return
    orig_init = subprocess.Popen.__init__

    def _patched_init(self: Any, *args: Any, **kwargs: Any) -> None:
        if not getattr(self, "_cosmos_skip_no_window", False) and not kwargs.pop("_cosmos_allow_gui_window", False):
            if not kwargs.get("creationflags"):
                kwargs["creationflags"] = CREATE_NO_WINDOW
            else:
                kwargs["creationflags"] = int(kwargs["creationflags"]) | CREATE_NO_WINDOW
        orig_init(self, *args, **kwargs)

    _patched_init._cosmos_no_window_patched = True  # type: ignore[attr-defined]
    subprocess.Popen.__init__ = _patched_init  # type: ignore[method-assign]


def _mark_managed_profile_dir(profile_dir: Path) -> None:
    profile_dir.mkdir(parents=True, exist_ok=True)
    marker = profile_dir / MANAGED_PROFILE_MARKER
    if not marker.is_file():
        with contextlib.suppress(OSError):
            marker.write_text("cosmos_mcp_isolated_headless_profile\n", encoding="utf-8")


def _release_browser_profile_locks_win32(profile_dir: Path) -> List[int]:
    """Terminate ONLY managed browser / crashpad children whose CommandLine references managed `profile_dir`."""
    if sys.platform != "win32":
        return []
    prof_res = profile_dir.resolve()
    prof_s = str(prof_res)
    if not prof_s or not (prof_res / MANAGED_PROFILE_MARKER).is_file():
        return []
    pwsh = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not pwsh:
        return []
    esc = prof_s.replace("'", "''")
    ps_cmd = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        f"$t = '--user-data-dir={esc}'; "
        "$killed = @(); "
        "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { "
        "$_.CommandLine -and $_.CommandLine.IndexOf($t, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 "
        "-and $_.Name -match '^(chrome|msedge|chromium|headless_shell|chrome_crashpad_handler|msedge_crashpad_handler)' "
        "} | ForEach-Object { "
        "$killed += [int]$_.ProcessId; "
        "Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue "
        "}; "
        "$killed | ConvertTo-Json -Compress"
    )
    enc = base64.b64encode(ps_cmd.encode("utf-16le")).decode("ascii")
    with contextlib.suppress(Exception):
        r = subprocess.run(
            [pwsh, "-NoProfile", "-NonInteractive", "-EncodedCommand", enc],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5.0,
            creationflags=win32_no_window_flags(),
        )
        raw = (r.stdout or "").strip()
        if raw:
            parsed = json.loads(raw)
            if isinstance(parsed, int):
                return [parsed]
            if isinstance(parsed, list):
                return [int(x) for x in parsed if str(x).isdigit()]
    return []


def _is_linux_snap_browser(exe_path: str) -> bool:
    try:
        p = Path(exe_path)
        if "/snap/" in p.resolve().as_posix():
            return True
        if p.is_file() and p.stat().st_size < 16384:
            head = p.read_bytes()[:4096]
            if b"/snap/" in head or b"snap run" in head:
                return True
    except OSError:
        pass
    return False


def find_system_chromium_binary() -> Optional[str]:
    """Locate an installed Edge / Chrome / Chromium executable for zero-dependency CDP fallback."""
    for env_k in ("COSMOS_BROWSER_PATH", "LOCALPC_BROWSER_PATH"):
        env_bin = (os.environ.get(env_k) or "").strip()
        if env_bin and Path(env_bin).is_file():
            return env_bin
    if sys.platform == "win32":
        cands = [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe"),
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        ]
        for c in cands:
            if c and Path(c).is_file():
                return c
        for nm in ("msedge.exe", "chrome.exe", "chromium.exe"):
            w = shutil.which(nm)
            if w:
                return w
    elif sys.platform == "darwin":
        for c in (
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ):
            if Path(c).is_file():
                return c
    else:
        linux_cands: List[str] = []
        for nm in (
            "google-chrome",
            "google-chrome-stable",
            "microsoft-edge",
            "microsoft-edge-stable",
            "chromium",
            "chromium-browser",
        ):
            w = shutil.which(nm)
            if w and w not in linux_cands:
                linux_cands.append(w)
        for cand in linux_cands:
            if not _is_linux_snap_browser(cand):
                return cand
        if linux_cands:
            return linux_cands[0]
    return None


class _CdpRespStub:
    def __init__(self, status: Optional[int] = 200) -> None:
        self.status = status


class _CdpLocatorStub:
    def __init__(self, page: "_HeadlessCdpPage", selector: str) -> None:
        self._page = page
        self._sel = selector
        self.first = self

    def click(self, timeout: int = 15000) -> Dict[str, Any]:
        res = self._page.evaluate(
            _RESOLVE_AND_CLICK_DOM_JS,
            {"sel": self._sel, "clickTok": "", "performJsClick": True},
            timeout_ms=timeout,
        )
        out = res if isinstance(res, dict) else {"ok": False, "error": "Unexpected click evaluation response"}
        if not out.get("ok"):
            raise RuntimeError(str(out.get("error") or f"Element not interactable: {self._sel}"))
        time.sleep(0.15)
        self._page._pump_cdp_events(wait_sec=0.05)
        return out

    def fill(self, value: str, timeout: int = 15000) -> Dict[str, Any]:
        res = self._page.evaluate(
            _SELECT_OR_FILL_DOM_JS,
            {"sel": self._sel, "text": str(value), "value": str(value), "forceSelect": False, "index": -1},
            timeout_ms=timeout,
        )
        out = res if isinstance(res, dict) else {"ok": False, "error": "Unexpected fill evaluation response"}
        if not out.get("ok"):
            raise RuntimeError(str(out.get("error") or f"Element not fillable: {self._sel}"))
        return out


class _HeadlessCdpPage:
    """Playwright-compatible headless page backed by system Chromium/Edge CDP + `StdlibWebSocketClient`."""

    def __init__(
        self,
        profile_dir: Path,
        browser_exe: str,
        *,
        proxy_settings: Optional[Dict[str, str]] = None,
        url_validator: Optional[Callable[[str], Tuple[Optional[str], Optional[str]]]] = None,
        download_dir: Optional[Path] = None,
    ) -> None:
        resolved_prof = profile_dir.resolve()
        if (
            sys.platform.startswith("linux")
            and _is_linux_snap_browser(browser_exe)
            and resolved_prof.as_posix().startswith("/tmp/")
        ):
            snap_safe_base = Path.home() / ".cache" / "cosmos-mcp-snap-cdp"
            resolved_prof = (snap_safe_base / f"{resolved_prof.parent.name}_{resolved_prof.name}").resolve()
            resolved_prof.mkdir(parents=True, exist_ok=True)
        self.profile_dir = resolved_prof
        _mark_managed_profile_dir(self.profile_dir)
        self._url_validator = url_validator
        self._proxy_settings = dict(proxy_settings or resolve_browser_proxy_settings())
        self._download_dir: Optional[Path] = download_dir.resolve() if download_dir else None
        self.recent_downloads: List[Dict[str, Any]] = []
        self._downloads_by_guid: Dict[str, Dict[str, Any]] = {}

        dt_file = self.profile_dir / "DevToolsActivePort"
        if dt_file.is_file():
            with contextlib.suppress(OSError):
                dt_file.write_text("", encoding="utf-8")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ep_sock:
            ep_sock.bind(("127.0.0.1", 0))
            req_port = int(ep_sock.getsockname()[1])
        self.cdp_port: int = req_port

        clean_env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("PYTHON", "CHROME_"))}
        argv: List[str] = [
            browser_exe,
            "--headless=new",
            "--remote-debugging-address=127.0.0.1",
            f"--remote-debugging-port={req_port}",
            f"--user-data-dir={self.profile_dir}",
            "--window-size=1280,800",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-sync",
            "--disable-gpu",
            "--mute-audio",
            "--disable-crash-reporter",
            "--disable-breakpad",
        ]
        if sys.platform.startswith("linux"):
            raw_dbus = clean_env.get("DBUS_SESSION_BUS_ADDRESS", "").strip()
            if not raw_dbus or not raw_dbus.startswith(("unix:", "tcp:")):
                clean_env.pop("DBUS_SESSION_BUS_ADDRESS", None)
            argv.extend(
                [
                    "--disable-dev-shm-usage",
                    "--password-store=basic",
                    "--use-mock-keychain",
                ]
            )
            need_no_sandbox = (
                (hasattr(os, "geteuid") and os.geteuid() == 0)
                or os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
                or os.environ.get("CI", "").lower() == "true"
            )
            if not need_no_sandbox:
                with contextlib.suppress(OSError):
                    need_no_sandbox = (
                        Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
                        .read_text(encoding="utf-8")
                        .strip()
                        == "1"
                    )
            if need_no_sandbox:
                argv.append("--no-sandbox")
        if self._proxy_settings.get("server"):
            argv.append(f"--proxy-server={self._proxy_settings['server']}")
            if self._proxy_settings.get("bypass_semicolon"):
                argv.append(f"--proxy-bypass-list={self._proxy_settings['bypass_semicolon']}")
        argv.append("about:blank")

        self._ws: Optional[StdlibWebSocketClient] = None
        self.target_id: str = ""
        self._event_buffer: List[Dict[str, Any]] = []
        self._rpc_seq = 1
        self._closed = False
        self._last_blocked_patterns: Tuple[str, ...] = ()
        self._last_blocked_args: Optional[Tuple[int, str, Tuple[int, ...], bool, bool]] = None
        self._stderr_path = self.profile_dir / "cdp_stderr.log"
        self._stderr_fp = self._stderr_path.open("wb")
        popen_kwargs: Dict[str, Any] = {}
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = win32_no_window_flags(new_process_group=True)
        else:
            popen_kwargs["start_new_session"] = True

        self._proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=self._stderr_fp,
            env=clean_env,
            **popen_kwargs,
        )
        self._proc_create_token = get_process_create_token(self._proc.pid)
        self._job_handle = OwnedJobHandle(assign_win32_job_kill_on_close(self._proc.pid))

        is_ci_env = (
            os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
            or os.environ.get("CI", "").lower() == "true"
        )
        poll_timeout_sec = 25.0 if is_ci_env else 14.0
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        ws_page_url = ""
        init_target_id = ""
        first_empty_list_at: Optional[float] = None
        deadline = time.monotonic() + poll_timeout_sec
        while time.monotonic() < deadline:
            rc = self._proc.poll()
            if rc is not None and rc != 0:
                self.close()
                err_b = self._stderr_path.read_text(encoding="utf-8", errors="replace") if self._stderr_path.is_file() else ""
                raise RuntimeError(f"Headless browser exited prematurely ({rc}): {err_b[-240:]}")
            cand_ports = [req_port]
            if dt_file.is_file():
                lines = [ln.strip() for ln in dt_file.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
                if lines and lines[0].isdigit() and int(lines[0]) > 0 and int(lines[0]) not in cand_ports:
                    cand_ports.insert(0, int(lines[0]))
            for cp in cand_ports:
                list_http_ok = False
                with contextlib.suppress(Exception):
                    with opener.open(f"http://127.0.0.1:{cp}/json/list", timeout=1.5) as resp:
                        if getattr(resp, "status", 200) == 200:
                            list_http_ok = True
                        targets = json.loads(resp.read().decode("utf-8", errors="replace"))
                        if isinstance(targets, list):
                            list_http_ok = True
                            for t in targets:
                                if isinstance(t, dict) and t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                                    ws_page_url = str(t["webSocketDebuggerUrl"])
                                    init_target_id = str(t.get("id") or "")
                                    self.cdp_port = int(cp)
                                    break
                if ws_page_url:
                    break
                if list_http_ok:
                    now_mono = time.monotonic()
                    if first_empty_list_at is None:
                        first_empty_list_at = now_mono
                    elif (now_mono - first_empty_list_at) >= 2.0:
                        first_empty_list_at = now_mono
                        new_url = f"http://127.0.0.1:{cp}/json/new?about:blank"
                        created_target: Any = None
                        for method_name in ("PUT", "GET"):
                            try:
                                req_new = urllib.request.Request(new_url, method=method_name)
                                with opener.open(req_new, timeout=2.5) as new_resp:
                                    created_target = json.loads(new_resp.read().decode("utf-8", errors="replace"))
                                break
                            except Exception:
                                continue
                        if isinstance(created_target, dict) and created_target.get("webSocketDebuggerUrl"):
                            ws_page_url = str(created_target["webSocketDebuggerUrl"])
                            init_target_id = str(created_target.get("id") or "")
                            self.cdp_port = int(cp)
                            break
            if ws_page_url:
                break
            time.sleep(0.10)

        if not ws_page_url:
            rc = self._proc.poll()
            self.close()
            err_b = self._stderr_path.read_text(encoding="utf-8", errors="replace") if self._stderr_path.is_file() else ""
            raise RuntimeError(f"No page target exposed by headless Chromium CDP (rc={rc}): {err_b[-200:]}")

        self._last_ssrf_block_error: Optional[str] = None
        self._attach_page_ws(ws_page_url, init_target_id)
        if self._download_dir is not None:
            self.configure_download_dir(self._download_dir)

    def _attach_page_ws(self, ws_url: str, target_id: str) -> None:
        if self._ws is not None:
            with contextlib.suppress(Exception):
                self._ws.close()
        self._ws = StdlibWebSocketClient(ws_url, timeout=15.0, origin=None, auto_connect=True)
        self.target_id = target_id
        self._event_buffer.clear()
        self._last_blocked_patterns = ()
        self._cdp_call("Page.enable")
        self._cdp_call("Runtime.enable")
        with contextlib.suppress(Exception):
            self._cdp_call("Page.setLifecycleEventsEnabled", {"enabled": True})
        with contextlib.suppress(Exception):
            self._cdp_call("Network.enable")
        with contextlib.suppress(Exception):
            self._cdp_call(
                "Emulation.setDeviceMetricsOverride",
                {"width": 1280, "height": 800, "deviceScaleFactor": 1, "mobile": False},
            )
        with contextlib.suppress(Exception):
            self._cdp_call(
                "Fetch.enable",
                {"patterns": [{"urlPattern": "*", "resourceType": "Document", "requestStage": "Request"}]},
                timeout=3.0,
                record_events=False,
            )
        if self._last_blocked_args is not None:
            mp, mpub, blp, is_r, allow_lb = self._last_blocked_args
            self.apply_cdp_blocked_urls(
                mp,
                mpub,
                blocked_local_ports=blp,
                is_remote_session=is_r,
                allow_loopback_dev=allow_lb,
            )
        if self._download_dir is not None:
            self.configure_download_dir(self._download_dir)

    @property
    def pid(self) -> int:
        return int(self._proc.pid)

    def configure_download_dir(self, download_dir: Path) -> None:
        resolved = download_dir.resolve()
        resolved.mkdir(parents=True, exist_ok=True)
        self._download_dir = resolved
        ok_browser_dl = False
        if int(getattr(self, "cdp_port", 0) or 0) > 0:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with contextlib.suppress(Exception):
                with opener.open(f"http://127.0.0.1:{self.cdp_port}/json/version", timeout=2.0) as v_resp:
                    v_doc = json.loads(v_resp.read().decode("utf-8", errors="replace"))
                    b_ws_url = str(v_doc.get("webSocketDebuggerUrl") or "")
                    if b_ws_url:
                        b_ws = StdlibWebSocketClient(b_ws_url, timeout=3.0, origin=None, auto_connect=True)
                        try:
                            b_ws.send_json(
                                {
                                    "id": 1,
                                    "method": "Browser.setDownloadBehavior",
                                    "params": {
                                        "behavior": "allow",
                                        "downloadPath": str(resolved),
                                        "eventsEnabled": True,
                                    },
                                }
                            )
                            b_ws.recv_json()
                            ok_browser_dl = True
                        finally:
                            b_ws.close()
        if self._ws is None:
            return
        with contextlib.suppress(Exception):
            self._cdp_call(
                "Browser.setDownloadBehavior",
                {"behavior": "allow", "downloadPath": str(resolved), "eventsEnabled": True},
                timeout=3.0,
                record_events=False,
            )
            ok_browser_dl = True
        if not ok_browser_dl:
            with contextlib.suppress(Exception):
                self._cdp_call(
                    "Page.setDownloadBehavior",
                    {"behavior": "allow", "downloadPath": str(resolved)},
                    timeout=3.0,
                    record_events=False,
                )

    def _record_download_event(self, method: str, params: Dict[str, Any]) -> None:
        dl_dir = self._download_dir
        if method in ("Browser.downloadWillBegin", "Page.downloadWillBegin"):
            guid = str(params.get("guid") or secrets.token_hex(6))
            suggested = Path(str(params.get("suggestedFilename") or "download.bin")).name
            rec: Dict[str, Any] = {
                "guid": guid,
                "url": str(params.get("url") or ""),
                "suggested_filename": suggested,
                "state": "inProgress",
                "download_dir": str(dl_dir) if dl_dir else "",
                "saved_path": str(dl_dir / suggested) if dl_dir else "",
            }
            self._downloads_by_guid[guid] = rec
            self.recent_downloads.append(rec)
            if len(self.recent_downloads) > 50:
                del self.recent_downloads[:25]
        elif method in ("Browser.downloadProgress", "Page.downloadProgress"):
            guid = str(params.get("guid") or "")
            rec2 = self._downloads_by_guid.get(guid)
            if rec2 is not None:
                rec2["state"] = str(params.get("state") or rec2.get("state") or "")
                if params.get("receivedBytes") is not None:
                    rec2["received_bytes"] = int(params["receivedBytes"])
                if params.get("totalBytes") is not None:
                    rec2["total_bytes"] = int(params["totalBytes"])
                if params.get("filePath"):
                    rec2["saved_path"] = str(params["filePath"])

    def _handle_fetch_paused_inline(self, params: Dict[str, Any]) -> None:
        """Synchronously gate every top-level/frame `Document` request & 302 redirect hop BEFORE socket connect."""
        if self._ws is None:
            return
        req_id = str(params.get("requestId") or "")
        if not req_id:
            return
        req_url = str((params.get("request") or {}).get("url") or "")
        err_u: Optional[str] = None
        if req_url and req_url != "about:blank" and self._url_validator is not None:
            _, err_u = self._url_validator(req_url)
        cid = self._rpc_seq
        self._rpc_seq += 1
        with contextlib.suppress(Exception):
            if err_u:
                self._last_ssrf_block_error = err_u
                self._ws.send_json(
                    {
                        "id": cid,
                        "method": "Fetch.failRequest",
                        "params": {"requestId": req_id, "errorReason": "BlockedByClient"},
                    }
                )
            else:
                self._ws.send_json(
                    {
                        "id": cid,
                        "method": "Fetch.continueRequest",
                        "params": {"requestId": req_id},
                    }
                )

    def _cdp_call(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: float = 15.0,
        *,
        record_events: bool = True,
    ) -> Dict[str, Any]:
        """Execute a CDP JSON-RPC command over `StdlibWebSocketClient` while preserving interleaved CDP events."""
        if self._ws is None or self._ws.sock is None:
            raise ConnectionError("CDP WebSocket is not connected")
        eff_timeout = max(0.5, float(timeout))
        self._ws.sock.settimeout(eff_timeout)
        cid = self._rpc_seq
        self._rpc_seq += 1
        self._ws.send_json({"id": cid, "method": method, "params": params or {}})
        deadline = time.monotonic() + eff_timeout
        while time.monotonic() < deadline:
            rem = max(0.05, deadline - time.monotonic())
            self._ws.sock.settimeout(rem)
            doc = self._ws.recv_json()
            if doc is None:
                self._closed = True
                raise ConnectionError("CDP WebSocket closed by browser")
            if doc.get("id") == cid:
                if "error" in doc:
                    raise RuntimeError(f"CDP {method} error: {doc['error']}")
                res = doc.get("result")
                return res if isinstance(res, dict) else {}
            if "method" in doc:
                ev_m = str(doc.get("method") or "")
                ev_p = doc.get("params") or {}
                if ev_m == "Fetch.requestPaused":
                    self._handle_fetch_paused_inline(ev_p)
                    continue
                if ev_m in ("Browser.downloadWillBegin", "Browser.downloadProgress", "Page.downloadWillBegin", "Page.downloadProgress"):
                    self._record_download_event(ev_m, ev_p)
                if record_events:
                    self._event_buffer.append(doc)
                    if len(self._event_buffer) > 512:
                        del self._event_buffer[:256]
        raise TimeoutError(f"CDP {method} timed out after {timeout}s")

    def _pump_cdp_events(self, wait_sec: float = 0.04) -> List[Dict[str, Any]]:
        drained: List[Dict[str, Any]] = list(self._event_buffer)
        self._event_buffer.clear()
        if self._ws is None or self._ws.sock is None:
            return drained
        end_t = time.monotonic() + max(0.005, float(wait_sec))
        while time.monotonic() < end_t:
            rem = max(0.005, end_t - time.monotonic())
            self._ws.sock.settimeout(rem)
            try:
                doc = self._ws.recv_json()
            except (socket.timeout, TimeoutError):
                break
            if doc is None:
                self._closed = True
                break
            if "method" in doc:
                ev_m = str(doc.get("method") or "")
                ev_p = doc.get("params") or {}
                if ev_m == "Fetch.requestPaused":
                    self._handle_fetch_paused_inline(ev_p)
                    continue
                if ev_m in ("Browser.downloadWillBegin", "Browser.downloadProgress", "Page.downloadWillBegin", "Page.downloadProgress"):
                    self._record_download_event(ev_m, ev_p)
                drained.append(doc)
        return drained

    def list_tabs_cdp(self) -> List[Dict[str, Any]]:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        tabs: List[Dict[str, Any]] = []
        with opener.open(f"http://127.0.0.1:{self.cdp_port}/json/list", timeout=2.5) as resp:
            raw_targets = json.loads(resp.read().decode("utf-8", errors="replace"))
        if not isinstance(raw_targets, list):
            return tabs
        idx = 0
        for item in raw_targets:
            if not isinstance(item, dict) or item.get("type") != "page":
                continue
            tid = str(item.get("id") or "")
            tabs.append(
                {
                    "index": idx,
                    "tab_id": tid,
                    "title": str(item.get("title") or ""),
                    "url": str(item.get("url") or ""),
                    "active": bool(tid and tid == self.target_id),
                    "_ws_url": str(item.get("webSocketDebuggerUrl") or ""),
                }
            )
            idx += 1
        return tabs

    def switch_tab_cdp(
        self,
        *,
        tab_id: str = "",
        index: int = -1,
        query: str = "",
    ) -> Dict[str, Any]:
        raw_tabs = self.list_tabs_cdp()
        if not raw_tabs:
            return {"ok": False, "error": "No open page tabs exposed by browser."}
        chosen: Optional[Dict[str, Any]] = None
        clean_tid = (tab_id or "").strip()
        clean_q = (query or "").strip().lower()
        if clean_tid:
            for t in raw_tabs:
                if t["tab_id"] == clean_tid:
                    chosen = t
                    break
            if chosen is None and clean_tid.lower().startswith("tab_") and clean_tid[4:].isdigit():
                idx_alias = int(clean_tid[4:])
                if 0 <= idx_alias < len(raw_tabs):
                    chosen = raw_tabs[idx_alias]
        elif index is not None and int(index) >= 0:
            if int(index) < len(raw_tabs):
                chosen = raw_tabs[int(index)]
        elif clean_q:
            for t in raw_tabs:
                if clean_q in t["url"].lower() or clean_q in t["title"].lower():
                    chosen = t
                    break

        if chosen is None:
            return {
                "ok": False,
                "error": f"No matching tab found for tab_id={clean_tid!r}, index={index}, query={query!r} (tab_count={len(raw_tabs)}).",
                "tabs": [{k: v for k, v in t.items() if not k.startswith("_")} for t in raw_tabs],
            }

        cand_u = str(chosen.get("url") or "")
        if cand_u and cand_u != "about:blank" and self._url_validator is not None:
            _, err_v = self._url_validator(cand_u)
            if err_v:
                return {
                    "ok": False,
                    "blocked_by_guardrail": True,
                    "blocked_by_ssrf_guard": True,
                    "error": err_v,
                }

        ws_u = str(chosen.get("_ws_url") or "")
        if chosen["tab_id"] != self.target_id:
            if not ws_u:
                return {"ok": False, "error": f"Tab `{chosen['tab_id']}` has no attachable CDP WebSocket URL."}
            self._attach_page_ws(ws_u, str(chosen["tab_id"]))
            with contextlib.suppress(Exception):
                self._cdp_call("Target.activateTarget", {"targetId": self.target_id}, timeout=2.0, record_events=False)

        refreshed = [{k: v for k, v in t.items() if not k.startswith("_")} for t in self.list_tabs_cdp()]
        return {
            "ok": True,
            "switched_to": {
                "index": chosen["index"],
                "tab_id": self.target_id,
                "url": self.url,
                "title": self.title(),
            },
            "tab_count": len(refreshed),
            "tabs": refreshed,
        }

    def apply_cdp_blocked_urls(
        self,
        mcp_port: int,
        mcp_public_url: str,
        *,
        blocked_local_ports: Iterable[int] = (),
        is_remote_session: bool = False,
        allow_loopback_dev: bool = True,
    ) -> None:
        blp_tup = tuple(int(x) for x in blocked_local_ports if int(x or 0) > 0)
        self._last_blocked_args = (int(mcp_port or 0), str(mcp_public_url or ""), blp_tup, bool(is_remote_session), bool(allow_loopback_dev))
        if self._ws is None:
            return
        meta_ip = ".".join(("169", "254", "*"))
        ali_meta = ".".join(("100", "100", "100", "200"))
        patterns: List[str] = [
            "file://*",
            f"http://{meta_ip}",
            f"https://{meta_ip}",
            f"http://{ali_meta}*",
            f"https://{ali_meta}*",
        ]
        ports_set: Set[int] = set(PROTECTED_LOCAL_CONTROL_PORTS)
        if int(mcp_port or 0) > 0:
            ports_set.add(int(mcp_port))
        for bp in blp_tup:
            ports_set.add(bp)

        for p in sorted(ports_set):
            patterns.extend(
                [
                    f"http://127.0.0.1:{p}*",
                    f"http://localhost:{p}*",
                    f"http://[::1]:{p}*",
                    f"https://127.0.0.1:{p}*",
                    f"https://localhost:{p}*",
                    f"https://[::1]:{p}*",
                ]
            )
        if is_remote_session or not allow_loopback_dev:
            patterns.extend(_private_lan_cdp_block_patterns())
        if mcp_public_url:
            clean_pub = mcp_public_url.strip().rstrip("/")
            if clean_pub:
                patterns.append(f"{clean_pub}*")
        pat_tup = tuple(patterns)
        if pat_tup != self._last_blocked_patterns:
            with contextlib.suppress(Exception):
                self._cdp_call("Network.setBlockedURLs", {"urls": patterns}, timeout=3.0)
            self._last_blocked_patterns = pat_tup

    def is_closed(self) -> bool:
        if self._closed or self._ws is None or self._ws.closed:
            self._closed = True
            return True
        return False

    def is_cdp_endpoint_alive(self) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", self.cdp_port), timeout=0.25):
                return True
        except OSError:
            return False

    @property
    def url(self) -> str:
        return str(self.evaluate("() => String(location.href || '')") or "")

    def title(self) -> str:
        return str(self.evaluate("() => String(document.title || '')") or "")

    def wait_for_timeout(self, ms: int) -> None:
        if ms > 0:
            end_w = time.monotonic() + min(10.0, ms / 1000.0)
            while time.monotonic() < end_w:
                self._pump_cdp_events(wait_sec=min(0.05, max(0.005, end_w - time.monotonic())))

    def _abort_and_reset_blank(self) -> None:
        with contextlib.suppress(Exception):
            self._cdp_call("Page.stopLoading", timeout=2.0, record_events=False)
        with contextlib.suppress(Exception):
            self._cdp_call("Page.navigate", {"url": "about:blank"}, timeout=3.0, record_events=False)

    def goto(self, target_url: str, wait_until: str = "domcontentloaded", timeout: int = 15000) -> _CdpRespStub:
        """Navigate to `target_url` and wait for `frameId/loaderId` transition + fresh document readiness."""
        t_sec = max(2.0, float(timeout) / 1000.0)
        self._last_ssrf_block_error = None

        ft_pre = self._cdp_call("Page.getFrameTree", timeout=min(4.0, t_sec), record_events=False)
        root_pre = ((ft_pre.get("frameTree") or {}).get("frame")) or {}
        pre_frame_id = str(root_pre.get("id") or "")
        pre_loader_id = str(root_pre.get("loaderId") or "")
        pre_js_marker = f"prev_{secrets.token_hex(6)}"
        with contextlib.suppress(Exception):
            self.evaluate(f"() => {{ window.__cosmos_prev_marker = {json.dumps(pre_js_marker)}; return true; }}")

        self._event_buffer.clear()
        self._last_ssrf_block_error = None

        nav_res = self._cdp_call("Page.navigate", {"url": target_url}, timeout=t_sec, record_events=True)
        if self._last_ssrf_block_error:
            err_msg = self._last_ssrf_block_error
            self._last_ssrf_block_error = None
            self._abort_and_reset_blank()
            raise PermissionError(err_msg)

        def _inspect_events_for_ssrf(ev_list: Sequence[Dict[str, Any]], expected_fid: str) -> None:
            if self._url_validator is None:
                return
            for ev_item in ev_list:
                m_ev = ev_item.get("method")
                p_ev = ev_item.get("params") or {}
                if m_ev == "Network.requestWillBeSent":
                    is_doc = (
                        p_ev.get("type") == "Document"
                        or "redirectResponse" in p_ev
                        or (expected_fid and p_ev.get("frameId") == expected_fid)
                    )
                    if is_doc:
                        r_url = str((p_ev.get("request") or {}).get("url") or "")
                        if r_url and r_url != "about:blank":
                            _, err_u = self._url_validator(r_url)
                            if err_u:
                                self._abort_and_reset_blank()
                                raise PermissionError(err_u)
                elif m_ev == "Page.frameNavigated":
                    fr_ev = p_ev.get("frame") or {}
                    unreach = str(fr_ev.get("unreachableUrl") or "")
                    if unreach and unreach != "about:blank":
                        _, err_u2 = self._url_validator(unreach)
                        if err_u2:
                            self._abort_and_reset_blank()
                            raise PermissionError(err_u2)

        nav_frame_id = str(nav_res.get("frameId") or pre_frame_id)
        if self._event_buffer:
            _inspect_events_for_ssrf(self._pump_cdp_events(wait_sec=0.01), nav_frame_id)

        if nav_res.get("errorText"):
            _inspect_events_for_ssrf(self._pump_cdp_events(wait_sec=0.02), nav_frame_id)
            err_txt = str(nav_res["errorText"])
            if "ERR_BLOCKED_BY_CLIENT" in err_txt or "ERR_ABORTED" in err_txt:
                raise PermissionError(
                    f"[LOCALPC SSRF GUARD]: Navigation to `{target_url}` was blocked by browser SSRF / port isolation policy."
                )
            raise RuntimeError(f"Navigation failed: {err_txt}")

        nav_loader_id = str(nav_res.get("loaderId") or "")
        is_cross_doc = bool(nav_loader_id and nav_loader_id != pre_loader_id)

        committed_loader_id = ""
        saw_load_event = False
        http_status: Optional[int] = None
        deadline = time.monotonic() + t_sec
        soft_complete_cutoff = time.monotonic() + (t_sec * 0.80)

        while time.monotonic() < deadline:
            events = self._pump_cdp_events(wait_sec=0.04)
            if self._last_ssrf_block_error:
                err_msg2 = self._last_ssrf_block_error
                self._last_ssrf_block_error = None
                self._abort_and_reset_blank()
                raise PermissionError(err_msg2)
            for ev in events:
                m_name = ev.get("method")
                params = ev.get("params") or {}

                if m_name == "Network.requestWillBeSent":
                    is_doc_req = params.get("type") == "Document" or ("redirectResponse" in params and params.get("frameId") == nav_frame_id)
                    if is_doc_req and self._url_validator is not None:
                        req_url = str((params.get("request") or {}).get("url") or "")
                        if req_url and req_url != "about:blank":
                            _, u_err = self._url_validator(req_url)
                            if u_err:
                                self._abort_and_reset_blank()
                                raise PermissionError(u_err)

                elif m_name == "Network.responseReceived" and params.get("type") == "Document":
                    resp_obj = params.get("response") or {}
                    if resp_obj.get("status") is not None:
                        http_status = int(resp_obj["status"])

                elif m_name == "Page.frameNavigated":
                    fr = params.get("frame") or {}
                    if not fr.get("parentId") and (not nav_frame_id or fr.get("id") == nav_frame_id):
                        unreachable = str(fr.get("unreachableUrl") or "")
                        if unreachable:
                            if self._url_validator is not None:
                                _, u_err = self._url_validator(unreachable)
                                if u_err:
                                    self._abort_and_reset_blank()
                                    raise PermissionError(u_err)
                            raise PermissionError(
                                f"[LOCALPC SSRF GUARD]: Navigation to `{unreachable}` was blocked or unreachable."
                            )
                        cand_ldr = str(fr.get("loaderId") or "")
                        cand_url = str(fr.get("url") or "")
                        if cand_url and cand_url != "about:blank" and self._url_validator is not None:
                            _, u_err = self._url_validator(cand_url)
                            if u_err:
                                self._abort_and_reset_blank()
                                raise PermissionError(u_err)
                        if cand_ldr and cand_ldr != pre_loader_id:
                            committed_loader_id = cand_ldr

                elif m_name in ("Page.loadEventFired", "Page.domContentEventFired"):
                    if not is_cross_doc or committed_loader_id:
                        if m_name == "Page.loadEventFired":
                            saw_load_event = True

                elif m_name == "Page.lifecycleEvent":
                    if params.get("frameId") == nav_frame_id:
                        ev_ldr = str(params.get("loaderId") or "")
                        ev_nm = str(params.get("name") or "")
                        if ev_ldr and ev_ldr != pre_loader_id:
                            committed_loader_id = ev_ldr
                            if ev_nm == "load":
                                saw_load_event = True

            with contextlib.suppress(Exception):
                ft_now = self._cdp_call("Page.getFrameTree", timeout=2.0, record_events=True)
                fr_now = ((ft_now.get("frameTree") or {}).get("frame")) or {}
                cur_ldr = str(fr_now.get("loaderId") or "")
                cur_frame_url = str(fr_now.get("url") or "")
                if cur_frame_url and cur_frame_url != "about:blank" and self._url_validator is not None:
                    _, u_err = self._url_validator(cur_frame_url)
                    if u_err:
                        self._abort_and_reset_blank()
                        raise PermissionError(u_err)
                if is_cross_doc:
                    if not cur_ldr or cur_ldr == pre_loader_id:
                        continue
                    committed_loader_id = cur_ldr

                state_doc = self.evaluate(
                    "() => ({rs: String(document.readyState || ''), prev: String(window.__cosmos_prev_marker || ''), href: String(location.href || '')})"
                )
                if isinstance(state_doc, dict):
                    rs = str(state_doc.get("rs") or "")
                    prev_m = str(state_doc.get("prev") or "")
                    href_s = str(state_doc.get("href") or "")
                    if is_cross_doc and prev_m == pre_js_marker:
                        continue
                    if href_s and href_s != "about:blank":
                        if rs == "complete":
                            break
                        if wait_until == "domcontentloaded" and rs == "interactive" and (
                            saw_load_event or time.monotonic() >= soft_complete_cutoff
                        ):
                            break

        return _CdpRespStub(http_status if http_status is not None else 200)

    def evaluate(self, expression: str, *args: Any, timeout_ms: int = 15000) -> Any:
        s = (expression or "").strip()
        is_fn = bool(
            re.match(r"^(?:async\s+)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][A-Za-z0-9_$]*\s*=>)", s)
        )
        if args:
            arg_json = ", ".join(json.dumps(a, ensure_ascii=False) for a in args)
            js_expr = f"({s})({arg_json})"
        elif is_fn:
            js_expr = f"({s})()"
        else:
            js_expr = s
        res = self._cdp_call(
            "Runtime.evaluate",
            {"expression": js_expr, "returnByValue": True, "awaitPromise": True},
            timeout=max(2.0, float(timeout_ms) / 1000.0),
        )
        if "exceptionDetails" in res:
            exc_d = res["exceptionDetails"]
            desc = ((exc_d.get("exception") or {}).get("description")) or exc_d.get("text") or "JS evaluation error"
            raise RuntimeError(str(desc))
        robj = res.get("result") or {}
        return robj.get("value")

    def locator(self, selector: str) -> _CdpLocatorStub:
        return _CdpLocatorStub(self, selector)

    def screenshot(self, full_page: bool = False, type: str = "png", timeout: int = 15000) -> bytes:
        _ = type
        params: Dict[str, Any] = {"format": "png"}
        if full_page:
            params["captureBeyondViewport"] = True
        res = self._cdp_call("Page.captureScreenshot", params, timeout=max(3.0, float(timeout) / 1000.0))
        return base64.b64decode(res.get("data") or "")

    def close(self) -> None:
        self._closed = True
        if self._ws is not None:
            with contextlib.suppress(Exception):
                self._cdp_call("Browser.close", timeout=2.5, record_events=False)
            self._ws.close()
            self._ws = None
        terminate_verified_pid_tree(
            self._proc.pid,
            self._proc_create_token,
            job_handle=self._job_handle,
        )
        with contextlib.suppress(Exception):
            self._proc.wait(timeout=2.0)
        if self._stderr_fp is not None:
            with contextlib.suppress(Exception):
                self._stderr_fp.close()
            self._stderr_fp = None
        _release_browser_profile_locks_win32(self.profile_dir)
        end_wait = time.monotonic() + 2.0
        while time.monotonic() < end_wait and self.is_cdp_endpoint_alive():
            time.sleep(0.05)


class _IsolatedBrowserWorker:
    """Single-thread Playwright / CDP persistent-context worker scoped to `<state_root>/browser_profile`."""

    def __init__(self, profile_dir: Path, *, backend_mode: str = "auto", explicit_proxy: Optional[str] = None) -> None:
        self.profile_dir = profile_dir.resolve()
        _mark_managed_profile_dir(self.profile_dir)
        self.backend_mode = (backend_mode or "auto").strip().lower()
        self.explicit_proxy = explicit_proxy
        self._q: "queue.Queue[Optional[Tuple[Callable[[Any], Any], threading.Event, List[Any], List[BaseException]]]]" = queue.Queue()
        self.active_ssrf_ctx: Dict[str, Any] = {
            "mcp_port": 0,
            "blocked_local_ports": (),
            "mcp_public_url": "",
            "is_remote_session": False,
            "allow_loopback_dev": True,
            "download_dir": "",
        }
        self.last_cdp_port: int = 0
        self.last_browser_pid: int = 0
        self.active_backend: str = ""
        self.pw_downloads: List[Dict[str, Any]] = []
        self._route_installed = False
        self._alive = True
        self._thread = threading.Thread(target=self._loop, name=f"cosmos-bw-{self.profile_dir.name}", daemon=True)
        self._thread.start()

    def _validate_from_ctx(self, candidate_url: str) -> Tuple[Optional[str], Optional[str]]:
        sc = self.active_ssrf_ctx
        proxy_cfg = resolve_browser_proxy_settings(self.explicit_proxy)
        return _validate_browser_url_pair(
            candidate_url,
            mcp_port=int(sc.get("mcp_port") or 0),
            blocked_local_ports=sc.get("blocked_local_ports") or (),
            mcp_public_url=str(sc.get("mcp_public_url") or ""),
            is_remote_session=bool(sc.get("is_remote_session", False)),
            allow_loopback_dev=bool(sc.get("allow_loopback_dev", True)),
            proxy_url=proxy_cfg.get("server") or None,
        )

    def _loop(self) -> None:
        pw: Any = None
        ctx: Any = None
        page: Any = None
        last_dl_dir_str: str = ""
        bound_dl_pages: Set[int] = set()

        def _bind_pw_page_download(pw_page: Any) -> None:
            pid_obj = id(pw_page)
            if pid_obj in bound_dl_pages:
                return
            bound_dl_pages.add(pid_obj)

            def _on_download(dl: Any) -> None:
                dl_url = str(getattr(dl, "url", "") or "")
                if dl_url and dl_url != "about:blank":
                    _, dl_err = self._validate_from_ctx(dl_url)
                    if dl_err:
                        with contextlib.suppress(Exception):
                            dl.cancel()
                        return
                dl_root_s = str(self.active_ssrf_ctx.get("download_dir") or "").strip()
                if not dl_root_s:
                    return
                dl_root = Path(dl_root_s).resolve()
                dl_root.mkdir(parents=True, exist_ok=True)
                fname = Path(str(getattr(dl, "suggested_filename", "download.bin") or "download.bin")).name
                dest = dl_root / fname
                rec: Dict[str, Any] = {
                    "url": dl_url,
                    "suggested_filename": fname,
                    "download_dir": str(dl_root),
                    "saved_path": str(dest),
                    "state": "inProgress",
                    "_dl_obj": dl,
                }
                self.pw_downloads.append(rec)

            with contextlib.suppress(Exception):
                pw_page.on("download", _on_download)

        pw_cdp_sessions: Dict[int, Tuple[Any, Tuple[str, ...]]] = {}

        def _sync_pw_page_network_guards(pw_ctx: Any, pw_page: Any) -> None:
            if isinstance(pw_ctx, _HeadlessCdpPage):
                return
            sc_now = self.active_ssrf_ctx
            blp_tup = tuple(int(x) for x in (sc_now.get("blocked_local_ports") or ()) if int(x or 0) > 0)
            mcp_p = int(sc_now.get("mcp_port") or 0)
            mcp_pub_s = str(sc_now.get("mcp_public_url") or "")
            is_rem_b = bool(sc_now.get("is_remote_session", False))
            allow_lb_b = bool(sc_now.get("allow_loopback_dev", True))
            meta_ip = ".".join(("169", "254", "*"))
            ali_meta = ".".join(("100", "100", "100", "200"))
            patterns: List[str] = [
                "file://*",
                f"http://{meta_ip}",
                f"https://{meta_ip}",
                f"http://{ali_meta}*",
                f"https://{ali_meta}*",
            ]
            ports_set: Set[int] = set(PROTECTED_LOCAL_CONTROL_PORTS)
            if mcp_p > 0:
                ports_set.add(mcp_p)
            for bp in blp_tup:
                ports_set.add(bp)
            for p_num in sorted(ports_set):
                patterns.extend(
                    [
                        f"http://127.0.0.1:{p_num}*",
                        f"http://localhost:{p_num}*",
                        f"http://[::1]:{p_num}*",
                        f"https://127.0.0.1:{p_num}*",
                        f"https://localhost:{p_num}*",
                        f"https://[::1]:{p_num}*",
                    ]
                )
            if is_rem_b or not allow_lb_b:
                patterns.extend(_private_lan_cdp_block_patterns())
            if mcp_pub_s.strip():
                patterns.append(f"{mcp_pub_s.strip().rstrip('/')}*")
            pat_tup = tuple(patterns)
            pid_k = id(pw_page)
            prev_entry = pw_cdp_sessions.get(pid_k)
            if prev_entry is not None and prev_entry[1] == pat_tup:
                return
            with contextlib.suppress(Exception):
                sess = prev_entry[0] if prev_entry is not None else pw_ctx.new_cdp_session(pw_page)
                if prev_entry is None:
                    sess.send("Network.enable")
                sess.send("Network.setBlockedURLs", {"urls": patterns})
                pw_cdp_sessions[pid_k] = (sess, pat_tup)

        def _apply_pw_cdp_download_dir(pw_ctx: Any, pw_page: Any, dl_dir: Optional[Path]) -> None:
            nonlocal last_dl_dir_str
            if isinstance(pw_ctx, _HeadlessCdpPage):
                return
            _bind_pw_page_download(pw_page)
            _sync_pw_page_network_guards(pw_ctx, pw_page)
            if dl_dir is None:
                return
            dl_s = str(dl_dir.resolve())
            dl_dir.mkdir(parents=True, exist_ok=True)
            last_dl_dir_str = dl_s

        def _install_pw_route_guard(pw_ctx: Any) -> None:
            if self._route_installed or isinstance(pw_ctx, _HeadlessCdpPage):
                return

            def _on_new_pw_page(new_p: Any) -> None:
                _bind_pw_page_download(new_p)
                _sync_pw_page_network_guards(pw_ctx, new_p)

            with contextlib.suppress(Exception):
                pw_ctx.on("page", _on_new_pw_page)
                self._route_installed = True

        def _set_active_page(new_page: Any) -> None:
            nonlocal page
            page = new_page
            dl_raw = str(self.active_ssrf_ctx.get("download_dir") or "").strip()
            dl_p = Path(dl_raw).resolve() if dl_raw else None
            if ctx is not None and not isinstance(ctx, _HeadlessCdpPage):
                _apply_pw_cdp_download_dir(ctx, page, dl_p)

        def _ensure_page() -> Tuple[Any, Any]:
            nonlocal pw, ctx, page, last_dl_dir_str
            sc = self.active_ssrf_ctx
            dl_raw = str(sc.get("download_dir") or "").strip()
            dl_dir = Path(dl_raw).resolve() if dl_raw else None

            if page is not None and not page.is_closed():
                if isinstance(page, _HeadlessCdpPage):
                    page.apply_cdp_blocked_urls(
                        int(sc.get("mcp_port") or 0),
                        str(sc.get("mcp_public_url") or ""),
                        blocked_local_ports=sc.get("blocked_local_ports") or (),
                        is_remote_session=bool(sc.get("is_remote_session", False)),
                        allow_loopback_dev=bool(sc.get("allow_loopback_dev", True)),
                    )
                    if dl_dir is not None and page._download_dir != dl_dir:
                        page.configure_download_dir(dl_dir)
                else:
                    _apply_pw_cdp_download_dir(ctx, page, dl_dir)
                return ctx, page

            self._route_installed = False
            last_dl_dir_str = ""
            _mark_managed_profile_dir(self.profile_dir)
            proxy_cfg = resolve_browser_proxy_settings(self.explicit_proxy)
            pw_err: Optional[BaseException] = None

            if self.backend_mode != "cdp":
                try:
                    _ensure_win32_no_window_popen_for_playwright()
                    from playwright.sync_api import sync_playwright  # type: ignore

                    if pw is None:
                        pw = sync_playwright().start()
                    if ctx is None:
                        common_args = [
                            "--no-first-run",
                            "--no-default-browser-check",
                            "--disable-background-networking",
                            "--disable-sync",
                            "--disable-gpu",
                            "--mute-audio",
                        ]
                        pw_kwargs: Dict[str, Any] = {
                            "user_data_dir": str(self.profile_dir),
                            "headless": True,
                            "accept_downloads": True,
                            "viewport": {"width": 1280, "height": 800},
                            "args": common_args,
                        }
                        if dl_dir is not None:
                            dl_dir.mkdir(parents=True, exist_ok=True)
                            pw_kwargs["downloads_path"] = str(dl_dir)
                        if proxy_cfg.get("server"):
                            pw_kwargs["proxy"] = {
                                "server": proxy_cfg["server"],
                                "bypass": proxy_cfg["bypass_comma"],
                            }
                        try:
                            ctx = pw.chromium.launch_persistent_context(**pw_kwargs)
                        except Exception:
                            sys_bin = find_system_chromium_binary()
                            if not sys_bin:
                                raise
                            ctx = pw.chromium.launch_persistent_context(executable_path=sys_bin, **pw_kwargs)
                    _install_pw_route_guard(ctx)
                    pages = [p for p in ctx.pages if not p.is_closed()]
                    page = pages[0] if pages else ctx.new_page()
                    _apply_pw_cdp_download_dir(ctx, page, dl_dir)
                    self.active_backend = "playwright"
                    return ctx, page
                except BaseException as exc:
                    pw_err = exc
                    with contextlib.suppress(Exception):
                        if pw is not None:
                            pw.stop()
                    pw = None
                    ctx = None
                    if self.backend_mode == "playwright":
                        raise

            cands_fb: List[str] = []
            first_fb = find_system_chromium_binary()
            if first_fb:
                cands_fb.append(first_fb)
            if sys.platform == "win32":
                for extra_fb in (
                    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                ):
                    if Path(extra_fb).is_file() and extra_fb not in cands_fb:
                        cands_fb.append(extra_fb)

            last_cdp_err: Optional[BaseException] = None
            for bin_cand in cands_fb:
                try:
                    cdp_page = _HeadlessCdpPage(
                        self.profile_dir,
                        bin_cand,
                        proxy_settings=proxy_cfg,
                        url_validator=self._validate_from_ctx,
                        download_dir=dl_dir,
                    )
                    cdp_page.apply_cdp_blocked_urls(
                        int(sc.get("mcp_port") or 0),
                        str(sc.get("mcp_public_url") or ""),
                        blocked_local_ports=sc.get("blocked_local_ports") or (),
                        is_remote_session=bool(sc.get("is_remote_session", False)),
                        allow_loopback_dev=bool(sc.get("allow_loopback_dev", True)),
                    )
                    ctx = cdp_page
                    page = cdp_page
                    self.active_backend = "cdp"
                    self.last_cdp_port = cdp_page.cdp_port
                    self.last_browser_pid = cdp_page.pid
                    return ctx, page
                except BaseException as c_exc:
                    last_cdp_err = c_exc
            raise RuntimeError(f"Neither Playwright nor system Chrome/Edge succeeded (pw={pw_err}; cdp={last_cdp_err})")

        def _shutdown() -> bool:
            nonlocal pw, ctx, page
            had_ctx = (ctx is not None) or (page is not None)
            with contextlib.suppress(Exception):
                if ctx is not None:
                    ctx.close()
            with contextlib.suppress(Exception):
                if page is not None and page is not ctx and hasattr(page, "close"):
                    page.close()
            ctx = None
            page = None
            self._route_installed = False
            with contextlib.suppress(Exception):
                if pw is not None:
                    pw.stop()
            pw = None
            if had_ctx:
                _release_browser_profile_locks_win32(self.profile_dir)
            return had_ctx

        try:
            while True:
                item = self._q.get()
                if item is None:
                    _shutdown()
                    break
                fn, ev, out_box, err_box = item
                try:
                    out_box.append(fn((_ensure_page, _shutdown, _set_active_page)))
                except BaseException as exc:
                    err_box.append(exc)
                finally:
                    ev.set()
        finally:
            _shutdown()
            self._alive = False

    def submit(self, fn: Callable[[Any], Any], timeout_sec: float = 45.0) -> Any:
        if not self._alive:
            raise RuntimeError("Browser worker thread is stopped.")
        ev = threading.Event()
        out_box: List[Any] = []
        err_box: List[BaseException] = []
        self._q.put((fn, ev, out_box, err_box))
        if not ev.wait(timeout=max(2.0, timeout_sec)):
            raise TimeoutError(f"Browser operation timed out after {timeout_sec:.1f}s")
        if err_box:
            raise err_box[0]
        return out_box[0] if out_box else None

    def stop(self) -> None:
        if self._alive:
            self._q.put(None)
            self._thread.join(timeout=5.0)
        _release_browser_profile_locks_win32(self.profile_dir)


_GLOBAL_WORKERS_LOCK = threading.Lock()
_GLOBAL_WORKERS: Dict[str, _IsolatedBrowserWorker] = {}
_LOGIN_WINDOWS: Dict[str, Dict[str, Any]] = {}


def _stop_managed_login_window_unlocked(key: str) -> bool:
    rec = _LOGIN_WINDOWS.pop(key, None)
    if not rec:
        return False
    proc = rec.get("proc")
    tok = rec.get("create_token")
    job_h = rec.get("job_handle")
    prof_dir = rec.get("profile_dir")
    if proc is not None and getattr(proc, "pid", 0):
        with contextlib.suppress(Exception):
            terminate_verified_pid_tree(int(proc.pid), tok, job_handle=job_h)
        with contextlib.suppress(Exception):
            proc.wait(timeout=1.5)
    if isinstance(prof_dir, Path):
        _release_browser_profile_locks_win32(prof_dir)
    return True


def _launch_managed_login_window_non_activating(
    profile_dir: Path,
    browser_exe: str,
    target_url: str,
    *,
    proxy_settings: Optional[Dict[str, str]] = None,
    offscreen: bool = False,
) -> Dict[str, Any]:
    """Launch isolated managed profile in a visible (`SW_SHOWNOACTIVATE`) window without touching personal browsers."""
    prof_res = profile_dir.resolve()
    _mark_managed_profile_dir(prof_res)
    proxy_cfg = dict(proxy_settings or resolve_browser_proxy_settings())
    clean_env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("PYTHON", "CHROME_"))}

    argv: List[str] = [
        browser_exe,
        f"--user-data-dir={prof_res}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-sync",
        "--new-window",
        "--window-size=1100,820",
    ]
    if offscreen:
        argv.append("--window-position=-32000,-32000")
    if proxy_cfg.get("server"):
        argv.append(f"--proxy-server={proxy_cfg['server']}")
        if proxy_cfg.get("bypass_semicolon"):
            argv.append(f"--proxy-bypass-list={proxy_cfg['bypass_semicolon']}")
    argv.append(target_url or "about:blank")

    popen_kwargs: Dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "env": clean_env,
    }
    if sys.platform == "win32":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 0x00000001)
        si.wShowWindow = 4  # SW_SHOWNOACTIVATE (zero foreground focus steal)
        popen_kwargs["startupinfo"] = si
        popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200) | CREATE_NO_WINDOW
        if getattr(subprocess.Popen, "_cosmos_no_window_patched", False):
            popen_kwargs["_cosmos_allow_gui_window"] = True
    else:
        popen_kwargs["start_new_session"] = True

    proc = subprocess.Popen(argv, **popen_kwargs)
    ctok = get_process_create_token(proc.pid)
    job_h = OwnedJobHandle(assign_win32_job_kill_on_close(proc.pid))
    return {
        "proc": proc,
        "pid": int(proc.pid),
        "create_token": ctok,
        "job_handle": job_h,
        "profile_dir": prof_res,
        "url": target_url or "about:blank",
        "offscreen": bool(offscreen),
    }


def close_all_browser_sessions(prefix_filter: str = "") -> int:
    clean_p = (prefix_filter or "").strip()
    closed_login = 0
    with _GLOBAL_WORKERS_LOCK:
        if not clean_p:
            workers = list(_GLOBAL_WORKERS.values())
            _GLOBAL_WORKERS.clear()
            for lk in list(_LOGIN_WINDOWS.keys()):
                if _stop_managed_login_window_unlocked(lk):
                    closed_login += 1
        else:
            workers = []
            for k in list(_GLOBAL_WORKERS.keys()):
                w = _GLOBAL_WORKERS[k]
                is_match = (
                    (w.profile_dir.name == "browser_profile")
                    if clean_p == "pc"
                    else (w.profile_dir.name.lower() == clean_p.lower())
                )
                if is_match:
                    workers.append(_GLOBAL_WORKERS.pop(k))
            for lk in list(_LOGIN_WINDOWS.keys()):
                lrec = _LOGIN_WINDOWS[lk]
                pdir: Path = lrec["profile_dir"]
                is_lmatch = (
                    (pdir.name == "browser_profile")
                    if clean_p == "pc"
                    else (pdir.name.lower() == clean_p.lower())
                )
                if is_lmatch and _stop_managed_login_window_unlocked(lk):
                    closed_login += 1
    for w in workers:
        with contextlib.suppress(Exception):
            w.stop()
    return len(workers) + closed_login


atexit.register(close_all_browser_sessions)


BROWSER_USE_INPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": list(BROWSER_USE_ACTIONS),
            "default": "snapshot",
            "description": "open|snapshot|click|fill|select|scroll|list_tabs|switch_tab|open_login_window|screenshot|evaluate|close",
        },
        "url": {"type": "string", "default": "", "description": "HTTP/HTTPS URL"},
        "selector": {"type": "string", "default": "", "description": "CSS selector or snapshot ref (e.g. e1)"},
        "text": {"type": "string", "default": "", "description": "Fill/select text"},
        "value": {"type": "string", "default": "", "description": "Option value"},
        "label": {"type": "string", "default": "", "description": "Option visible label"},
        "index": {"type": "integer", "default": -1, "description": "0-based option or tab index"},
        "tab_id": {"type": "string", "default": "", "description": "Target tab_id for action='switch_tab'"},
        "direction": {
            "type": "string",
            "default": "down",
            "description": "Scroll direction: down|up|left|right|top|bottom",
        },
        "amount": {"type": "integer", "default": 600, "description": "Scroll pixel distance for action='scroll'"},
        "script": {"type": "string", "default": "", "description": "JavaScript expression or arrow function"},
        "full_page": {"type": "boolean", "default": False, "description": "Full page screenshot"},
        "save_path": {"type": "string", "default": "", "description": "Optional workspace output file or download directory path"},
        "offscreen": {"type": "boolean", "default": False, "description": "Place open_login_window offscreen (-32000,-32000) for zero-intrusion tests"},
        "wait_ms": {"type": "integer", "default": 0, "description": "Settle wait 0..10000ms"},
        "timeout_ms": {"type": "integer", "default": 15000, "description": "Operation timeout ms (1000..60000)"},
        "caller": {"type": "string", "default": "", "description": "Optional caller identifier"},
    },
    "required": [],
}


class BrowserPackPlugin:
    """Layer 1 `PackPlugin` exposing `browser_use` (`pack_id='browser'`)."""

    pack_id: str = "browser"

    def __init__(
        self,
        *,
        guard: Optional[WorkspaceGuard] = None,
        proc_manager: Optional[Any] = None,
        state_root: Optional[Union[str, Path]] = None,
        policy: Optional[Any] = None,
        prefix: str = "",
        mcp_port: Union[int, Callable[[], int]] = 0,
        blocked_local_ports: Iterable[int] = (),
        mcp_public_url: Union[str, Callable[[], str]] = "",
        is_remote_session_fn: Optional[Callable[[], bool]] = None,
        allow_loopback_dev: bool = True,
        backend: str = "auto",
        proxy_url: Optional[str] = None,
    ) -> None:
        self.guard: WorkspaceGuard = guard or DEFAULT_GUARD
        self.proc_manager = proc_manager
        self._explicit_state_root: Optional[Path] = canonical_realpath(state_root) if state_root else None
        self.policy = policy
        self._explicit_prefix = (prefix or "").strip()
        self._mcp_port = mcp_port
        self._blocked_local_ports = tuple(int(p) for p in blocked_local_ports if int(p or 0) > 0)
        self._mcp_public_url = mcp_public_url
        self._is_remote_session_fn = is_remote_session_fn
        self.allow_loopback_dev = bool(allow_loopback_dev)
        self.backend = (backend or "auto").strip().lower()
        self.proxy_url = proxy_url
        self._lock = threading.Lock()
        self._owned_keys: Set[str] = set()

    def _effective_state_root(self) -> Path:
        return resolve_pack_effective_state_root(self._explicit_state_root, self.policy, self.guard)

    def _effective_prefix(self) -> str:
        return resolve_pack_effective_prefix(self._explicit_prefix, self.policy, self.guard, default="pc")

    def _effective_workspace_root(self) -> str:
        if self.policy is not None and hasattr(self.policy, "refresh"):
            with contextlib.suppress(Exception):
                _, _, ws = self.policy.refresh()
                if ws:
                    return str(ws)
        if self.guard.workspace_roots:
            return str(self.guard.workspace_roots[0])
        return str(Path.cwd())

    def _effective_mcp_port(self) -> int:
        if callable(self._mcp_port):
            return int(self._mcp_port() or 0)
        if int(self._mcp_port or 0) > 0:
            return int(self._mcp_port)
        env_p = os.environ.get("COSMOS_MCP_PORT") or os.environ.get("LOCALPC_MCP_PORT") or ""
        return int(env_p) if env_p.strip().isdigit() else 0

    def _effective_public_url(self) -> str:
        if callable(self._mcp_public_url):
            return str(self._mcp_public_url() or "").strip()
        if self._mcp_public_url:
            return str(self._mcp_public_url).strip()
        if self.policy is not None:
            pub = getattr(self.policy, "public_url", "")
            if pub:
                return str(pub).strip()
        return ""

    @property
    def is_remote_session_fn(self) -> Optional[Callable[[], bool]]:
        return self._is_remote_session_fn

    @is_remote_session_fn.setter
    def is_remote_session_fn(self, fn: Optional[Callable[[], bool]]) -> None:
        self._is_remote_session_fn = fn

    def _is_remote_session(self) -> bool:
        if self._is_remote_session_fn is not None:
            return bool(self._is_remote_session_fn())
        return _is_active_remote_transport_ctx()

    def resolve_profile_dir(self, prefix: str = "") -> Path:
        eff_p = (prefix or self._effective_prefix() or "pc").strip()
        sr = self._effective_state_root().resolve()
        return (sr / "browser_profile") if eff_p == "pc" else (sr / "browser_profile" / eff_p)

    def _resolve_download_dir(self, ws_root: str, save_path: str, act: str) -> Tuple[Optional[Path], Optional[str]]:
        base_ws = Path(ws_root).resolve()
        if act != "screenshot" and (save_path or "").strip():
            cand = self.guard.normalize_target_path(save_path.strip(), base_dir=str(base_ws))
            err = self.guard.check_path_access(cand, mode="write", tool_name="browser_use")
            if err:
                return None, err
            target_dir = cand if (not cand.suffix) else cand.parent
            target_dir.mkdir(parents=True, exist_ok=True)
            return target_dir, None
        base_ws.mkdir(parents=True, exist_ok=True)
        return base_ws, None

    def _get_or_create_worker(self, profile_dir: Path) -> _IsolatedBrowserWorker:
        key = os.path.normcase(str(profile_dir.resolve()))
        with _GLOBAL_WORKERS_LOCK:
            # Ensure any manual login window holding the profile lock is closed before headless resume
            _stop_managed_login_window_unlocked(key)
            w = _GLOBAL_WORKERS.get(key)
            if w is None or not w._alive:
                w = _IsolatedBrowserWorker(
                    profile_dir.resolve(),
                    backend_mode=self.backend,
                    explicit_proxy=self.proxy_url,
                )
                _GLOBAL_WORKERS[key] = w
        with self._lock:
            self._owned_keys.add(key)
        return w

    def active_worker_info(self, prefix: str = "") -> Dict[str, Any]:
        prof = self.resolve_profile_dir(prefix)
        key = os.path.normcase(str(prof.resolve()))
        with _GLOBAL_WORKERS_LOCK:
            w = _GLOBAL_WORKERS.get(key)
            login_rec = _LOGIN_WINDOWS.get(key)
        login_alive = False
        if login_rec is not None:
            lpid = int(login_rec.get("pid") or 0)
            login_alive = bool(lpid > 0 and verify_pid_alive(lpid, login_rec.get("create_token"))[0])
        if w is None or not w._alive:
            return {
                "running": login_alive,
                "login_window_active": login_alive,
                "login_pid": int(login_rec["pid"]) if (login_rec and login_alive) else 0,
                "profile_dir": str(prof),
            }
        return {
            "running": True,
            "login_window_active": login_alive,
            "profile_dir": str(prof),
            "backend": w.active_backend,
            "cdp_port": w.last_cdp_port,
            "browser_pid": w.last_browser_pid,
        }

    def browser_use(
        self,
        action: str = "snapshot",
        url: str = "",
        selector: str = "",
        text: str = "",
        value: str = "",
        label: str = "",
        index: int = -1,
        tab_id: str = "",
        direction: str = "down",
        amount: int = 600,
        script: str = "",
        full_page: bool = False,
        save_path: str = "",
        offscreen: bool = False,
        wait_ms: int = 0,
        timeout_ms: int = 15000,
        caller: str = "",
    ) -> Any:
        _ = caller
        eff_prefix = self._effective_prefix()
        ws_root = self._effective_workspace_root()
        act = (action or "snapshot").strip().lower()
        if act not in BROWSER_USE_ACTIONS:
            return {
                "ok": False,
                "pack": "browser",
                "error": f"Unsupported action `{action}` for {eff_prefix}_browser_use (expected {', '.join(BROWSER_USE_ACTIONS)}).",
            }

        has_pw = False
        if self.backend != "cdp":
            try:
                import playwright  # noqa: F401

                has_pw = True
            except ImportError:
                has_pw = False
        sys_browser_bin = find_system_chromium_binary()
        if not has_pw and sys_browser_bin is None:
            return {
                "ok": False,
                "pack": "browser",
                "playwright_missing": True,
                "error": "Neither Playwright nor a local Chromium/Chrome/Edge browser was found on this machine.",
            }

        profile_dir = self.resolve_profile_dir(eff_prefix)
        prof_key = os.path.normcase(str(profile_dir.resolve()))
        eff_timeout_ms = max(1000, min(60000, int(timeout_ms or 15000)))
        eff_wait_ms = max(0, min(10000, int(wait_ms or 0)))

        if act == "close":
            with _GLOBAL_WORKERS_LOCK:
                w = _GLOBAL_WORKERS.pop(prof_key, None)
                had_login = _stop_managed_login_window_unlocked(prof_key)
            with self._lock:
                self._owned_keys.discard(prof_key)
            if w is not None:
                w.stop()
            elif not had_login:
                _release_browser_profile_locks_win32(profile_dir)
            return {
                "ok": True,
                "pack": "browser",
                "action": "close",
                "closed": (w is not None) or had_login,
                "profile_dir": str(profile_dir),
            }

        mcp_port = self._effective_mcp_port()
        mcp_pub = self._effective_public_url()
        is_rem = self._is_remote_session()
        proxy_cfg = resolve_browser_proxy_settings(self.proxy_url)

        if act == "open_login_window":
            if sys_browser_bin is None:
                return {
                    "ok": False,
                    "pack": "browser",
                    "action": "open_login_window",
                    "error": "No system Edge/Chrome/Chromium binary found for open_login_window.",
                }
            login_url = "about:blank"
            if (url or "").strip():
                v_login, u_err = _validate_browser_url_pair(
                    url,
                    mcp_port=mcp_port,
                    blocked_local_ports=self._blocked_local_ports,
                    mcp_public_url=mcp_pub,
                    is_remote_session=is_rem,
                    allow_loopback_dev=self.allow_loopback_dev,
                    proxy_url=proxy_cfg.get("server") or None,
                )
                if u_err or not v_login:
                    is_guard = bool(u_err and ("[LOCALPC " in u_err or ERR_SSRF_BLOCKED in u_err))
                    return {
                        "ok": False,
                        "pack": "browser",
                        "action": "open_login_window",
                        "blocked_by_guardrail": is_guard,
                        "blocked_by_ssrf_guard": is_guard,
                        "error": u_err or "Invalid URL",
                    }
                login_url = v_login

            # Stop headless worker first so the isolated managed profile lock is cleanly released
            with _GLOBAL_WORKERS_LOCK:
                prev_w = _GLOBAL_WORKERS.pop(prof_key, None)
                _stop_managed_login_window_unlocked(prof_key)
            if prev_w is not None:
                prev_w.stop()
            else:
                _release_browser_profile_locks_win32(profile_dir)

            launched = _launch_managed_login_window_non_activating(
                profile_dir,
                sys_browser_bin,
                login_url,
                proxy_settings=proxy_cfg,
                offscreen=bool(offscreen),
            )
            with _GLOBAL_WORKERS_LOCK:
                _LOGIN_WINDOWS[prof_key] = launched
            with self._lock:
                self._owned_keys.add(prof_key)
            if eff_wait_ms > 0:
                time.sleep(min(5.0, eff_wait_ms / 1000.0))
            return {
                "ok": True,
                "pack": "browser",
                "action": "open_login_window",
                "headless": False,
                "show_mode": "SW_SHOWNOACTIVATE",
                "offscreen": bool(offscreen),
                "isolated_managed_profile": True,
                "profile_dir": str(profile_dir),
                "browser_pid": launched["pid"],
                "url": login_url,
                "hint": (
                    "Complete login in the managed browser window, then close it (or call action='close') "
                    "before resuming headless automation so cookies persist in `browser_profile`."
                ),
            }

        validated_url = ""
        if act == "open":
            v_url, u_err = _validate_browser_url_pair(
                url,
                mcp_port=mcp_port,
                blocked_local_ports=self._blocked_local_ports,
                mcp_public_url=mcp_pub,
                is_remote_session=is_rem,
                allow_loopback_dev=self.allow_loopback_dev,
                proxy_url=proxy_cfg.get("server") or None,
            )
            if u_err or not v_url:
                is_guard = bool(u_err and ("[LOCALPC " in u_err or ERR_SSRF_BLOCKED in u_err))
                return {
                    "ok": False,
                    "pack": "browser",
                    "action": "open",
                    "blocked_by_guardrail": is_guard,
                    "blocked_by_ssrf_guard": is_guard,
                    "error": u_err or "Invalid URL",
                }
            validated_url = v_url

        dl_dir, dl_err = self._resolve_download_dir(ws_root, save_path, act)
        if dl_err or dl_dir is None:
            return {
                "ok": False,
                "pack": "browser",
                "action": act,
                "blocked_by_guardrail": True,
                "error": dl_err or "Invalid download directory.",
            }

        worker = self._get_or_create_worker(profile_dir)
        call_ssrf_ctx: Dict[str, Any] = {
            "mcp_port": mcp_port,
            "blocked_local_ports": self._blocked_local_ports,
            "mcp_public_url": mcp_pub,
            "is_remote_session": is_rem,
            "allow_loopback_dev": self.allow_loopback_dev,
            "download_dir": str(dl_dir),
        }
        worker.active_ssrf_ctx = dict(call_ssrf_ctx)

        def _verify_post_nav_url(page: Any) -> Optional[str]:
            cur_u = str(page.url or "").strip()
            if not cur_u or cur_u == "about:blank":
                return None
            _, post_err = _validate_browser_url_pair(
                cur_u,
                mcp_port=mcp_port,
                blocked_local_ports=self._blocked_local_ports,
                mcp_public_url=mcp_pub,
                is_remote_session=is_rem,
                allow_loopback_dev=self.allow_loopback_dev,
                proxy_url=proxy_cfg.get("server") or None,
            )
            if post_err:
                with contextlib.suppress(Exception):
                    if isinstance(page, _HeadlessCdpPage):
                        page._abort_and_reset_blank()
                    else:
                        page.goto("about:blank", timeout=3000)
                return post_err
            return None

        def _collect_downloads_list(page: Any) -> List[Dict[str, Any]]:
            if isinstance(page, _HeadlessCdpPage):
                page._pump_cdp_events(wait_sec=0.06)
                return [dict(d) for d in page.recent_downloads[-10:]]
            with contextlib.suppress(Exception):
                page.wait_for_timeout(50)
            for rec in worker.pw_downloads:
                dl_obj = rec.get("_dl_obj")
                if dl_obj is not None and rec.get("state") != "completed":
                    with contextlib.suppress(Exception):
                        dl_obj.save_as(str(rec["saved_path"]))
                        rec["state"] = "completed"
                        rec.pop("_dl_obj", None)
            return [{k: v for k, v in d.items() if not k.startswith("_")} for d in worker.pw_downloads[-10:]]

        def _task(
            handles: Tuple[Callable[[], Tuple[Any, Any]], Callable[[], bool], Callable[[Any], None]],
        ) -> Dict[str, Any]:
            worker.active_ssrf_ctx = dict(call_ssrf_ctx)
            ensure_page_fn, _, set_active_page_fn = handles
            ctx_obj, page = ensure_page_fn()
            if is_rem and act in ("click", "fill", "select", "scroll"):
                pre_err = _verify_post_nav_url(page)
                if pre_err:
                    return {
                        "ok": False,
                        "pack": "browser",
                        "action": act,
                        "blocked_by_guardrail": True,
                        "blocked_by_ssrf_guard": True,
                        "error": pre_err,
                    }

            if act == "open":
                try:
                    resp = page.goto(validated_url, wait_until="domcontentloaded", timeout=eff_timeout_ms)
                except Exception as nav_exc:
                    nav_s = str(nav_exc)
                    if (
                        isinstance(nav_exc, PermissionError)
                        or "ERR_BLOCKED_BY_CLIENT" in nav_s
                        or "[LOCALPC SSRF GUARD]" in nav_s
                        or ERR_SSRF_BLOCKED in nav_s
                    ):
                        return {
                            "ok": False,
                            "pack": "browser",
                            "action": "open",
                            "blocked_by_guardrail": True,
                            "blocked_by_ssrf_guard": True,
                            "error": nav_s if "[LOCALPC SSRF GUARD]" in nav_s else f"[LOCALPC SSRF GUARD]: {nav_s}",
                        }
                    raise
                post_err = _verify_post_nav_url(page)
                if post_err:
                    return {
                        "ok": False,
                        "pack": "browser",
                        "action": "open",
                        "blocked_by_guardrail": True,
                        "blocked_by_ssrf_guard": True,
                        "error": post_err,
                    }
                if eff_wait_ms > 0:
                    page.wait_for_timeout(eff_wait_ms)
                snap = page.evaluate(_SNAPSHOT_INJECT_JS, 80)
                return {
                    "ok": True,
                    "pack": "browser",
                    "action": "open",
                    "headless": True,
                    "backend": worker.active_backend,
                    "profile_dir": str(profile_dir),
                    "download_dir": str(dl_dir),
                    "proxy_server": proxy_cfg.get("server") or None,
                    "http_status": resp.status if resp is not None else None,
                    **snap,
                }

            if act == "snapshot":
                if eff_wait_ms > 0:
                    page.wait_for_timeout(eff_wait_ms)
                post_err = _verify_post_nav_url(page)
                if post_err:
                    return {
                        "ok": False,
                        "pack": "browser",
                        "action": "snapshot",
                        "blocked_by_guardrail": True,
                        "blocked_by_ssrf_guard": True,
                        "error": post_err,
                    }
                snap = page.evaluate(_SNAPSHOT_INJECT_JS, 80)
                return {
                    "ok": True,
                    "pack": "browser",
                    "action": "snapshot",
                    "headless": True,
                    "backend": worker.active_backend,
                    "profile_dir": str(profile_dir),
                    "download_dir": str(dl_dir),
                    "downloads": _collect_downloads_list(page),
                    **snap,
                }

            if act == "list_tabs":
                if isinstance(page, _HeadlessCdpPage):
                    raw_tabs = page.list_tabs_cdp()
                    clean_tabs = [{k: v for k, v in t.items() if not k.startswith("_")} for t in raw_tabs]
                else:
                    pages_list = [p for p in ctx_obj.pages if not p.is_closed()]
                    clean_tabs = [
                        {
                            "index": i,
                            "tab_id": f"tab_{i}",
                            "title": p.title(),
                            "url": p.url,
                            "active": (p == page),
                        }
                        for i, p in enumerate(pages_list)
                    ]
                return {
                    "ok": True,
                    "pack": "browser",
                    "action": "list_tabs",
                    "backend": worker.active_backend,
                    "tab_count": len(clean_tabs),
                    "tabs": clean_tabs,
                }

            if act == "switch_tab":
                q_str = (url or text or label or "").strip()
                if isinstance(page, _HeadlessCdpPage):
                    sw_res = page.switch_tab_cdp(tab_id=tab_id, index=index, query=q_str)
                    return {"pack": "browser", "action": "switch_tab", "backend": worker.active_backend, **sw_res}

                pages_list = [p for p in ctx_obj.pages if not p.is_closed()]
                if not pages_list:
                    return {"ok": False, "pack": "browser", "action": "switch_tab", "error": "No open tabs available."}
                chosen_p = None
                chosen_i = -1
                clean_tid = (tab_id or "").strip().lower()
                if clean_tid.startswith("tab_") and clean_tid[4:].isdigit():
                    cand_i = int(clean_tid[4:])
                    if 0 <= cand_i < len(pages_list):
                        chosen_i = cand_i
                        chosen_p = pages_list[cand_i]
                elif index is not None and int(index) >= 0 and int(index) < len(pages_list):
                    chosen_i = int(index)
                    chosen_p = pages_list[chosen_i]
                elif q_str:
                    ql = q_str.lower()
                    for idx_p, p_cand in enumerate(pages_list):
                        if ql in str(p_cand.url or "").lower() or ql in str(p_cand.title() or "").lower():
                            chosen_i = idx_p
                            chosen_p = p_cand
                            break
                if chosen_p is None:
                    return {
                        "ok": False,
                        "pack": "browser",
                        "action": "switch_tab",
                        "error": f"No matching tab found for tab_id={tab_id!r}, index={index}, query={q_str!r}.",
                    }
                cand_u = str(chosen_p.url or "")
                if cand_u and cand_u != "about:blank":
                    _, u_err2 = worker._validate_from_ctx(cand_u)
                    if u_err2:
                        return {
                            "ok": False,
                            "pack": "browser",
                            "action": "switch_tab",
                            "blocked_by_guardrail": True,
                            "blocked_by_ssrf_guard": True,
                            "error": u_err2,
                        }
                set_active_page_fn(chosen_p)
                tabs_after = [
                    {
                        "index": i,
                        "tab_id": f"tab_{i}",
                        "title": p.title(),
                        "url": p.url,
                        "active": (p == chosen_p),
                    }
                    for i, p in enumerate(pages_list)
                ]
                return {
                    "ok": True,
                    "pack": "browser",
                    "action": "switch_tab",
                    "backend": worker.active_backend,
                    "switched_to": {
                        "index": chosen_i,
                        "tab_id": f"tab_{chosen_i}",
                        "url": chosen_p.url,
                        "title": chosen_p.title(),
                    },
                    "tab_count": len(tabs_after),
                    "tabs": tabs_after,
                }

            if act == "click":
                norm_sel = _normalize_browser_selector(selector)
                if not norm_sel:
                    return {
                        "ok": False,
                        "pack": "browser",
                        "action": "click",
                        "error": "`selector` (CSS selector or snapshot ref like 'e1') is required for action='click'.",
                    }
                click_tok = f"ct_{secrets.token_hex(5)}"
                is_cdp = isinstance(page, _HeadlessCdpPage)
                dom_clk = page.evaluate(
                    _RESOLVE_AND_CLICK_DOM_JS,
                    {"sel": norm_sel, "clickTok": click_tok, "performJsClick": is_cdp},
                )
                clk_dict = dom_clk if isinstance(dom_clk, dict) else {"ok": False, "error": "Unexpected click evaluation response"}
                if not clk_dict.get("ok"):
                    return {
                        "ok": False,
                        "pack": "browser",
                        "action": "click",
                        "selector": norm_sel,
                        **clk_dict,
                    }
                if not is_cdp:
                    try:
                        page.locator(f'[data-lpc-click-tok="{click_tok}"]').first.click(timeout=min(5000, eff_timeout_ms))
                    except Exception:
                        page.evaluate(
                            "(tok) => { const el = document.querySelector('[data-lpc-click-tok=\"' + tok + '\"]'); if (el) el.click(); }",
                            click_tok,
                        )
                else:
                    time.sleep(0.15)
                    page._pump_cdp_events(wait_sec=0.06)

                if eff_wait_ms > 0:
                    page.wait_for_timeout(eff_wait_ms)
                post_err = _verify_post_nav_url(page)
                if post_err:
                    return {
                        "ok": False,
                        "pack": "browser",
                        "action": "click",
                        "blocked_by_guardrail": True,
                        "blocked_by_ssrf_guard": True,
                        "error": post_err,
                    }
                return {
                    "ok": True,
                    "pack": "browser",
                    "action": "click",
                    "selector": norm_sel,
                    "matched_count": clk_dict.get("matched_count", 1),
                    "visible_count": clk_dict.get("visible_count", 1),
                    "picked_index_in_dom": clk_dict.get("picked_index_in_dom", 0),
                    "url": page.url,
                    "title": page.title(),
                    "downloads": _collect_downloads_list(page),
                    "text_excerpt": (page.evaluate("() => (document.body ? document.body.innerText : '').slice(0, 1200)") or "").strip(),
                }

            if act in ("fill", "select"):
                norm_sel = _normalize_browser_selector(selector)
                if not norm_sel:
                    return {
                        "ok": False,
                        "pack": "browser",
                        "action": act,
                        "error": f"`selector` (CSS selector or snapshot ref like 'e1') is required for action='{act}'.",
                    }
                eff_idx = int(index) if index is not None and int(index) >= 0 else -1
                dom_res = page.evaluate(
                    _SELECT_OR_FILL_DOM_JS,
                    {
                        "sel": norm_sel,
                        "text": str(text or ""),
                        "value": str(value if value != "" else (text if act == "select" and not label and eff_idx < 0 else "")),
                        "label": str(label or ""),
                        "index": eff_idx,
                        "forceSelect": act == "select",
                    },
                )
                dom_dict = dom_res if isinstance(dom_res, dict) else {"ok": False, "error": "Unexpected DOM evaluation response"}
                if not dom_dict.get("ok", True):
                    return {
                        "ok": False,
                        "pack": "browser",
                        "action": act,
                        "selector": norm_sel,
                        **dom_dict,
                    }
                if eff_wait_ms > 0:
                    page.wait_for_timeout(eff_wait_ms)
                out_fill: Dict[str, Any] = {
                    "ok": True,
                    "pack": "browser",
                    "action": act,
                    "selector": norm_sel,
                    "url": page.url,
                    "title": page.title(),
                    **dom_dict,
                }
                if not dom_dict.get("is_select") and "filled_length" not in out_fill:
                    out_fill["filled_length"] = len(str(text or value or ""))
                return out_fill

            if act == "scroll":
                norm_sel = _normalize_browser_selector(selector) if (selector or "").strip() else ""
                eff_dir = (direction or "down").strip().lower()
                if eff_dir not in ("down", "up", "left", "right", "top", "bottom"):
                    return {
                        "ok": False,
                        "pack": "browser",
                        "action": "scroll",
                        "error": f"Unsupported scroll direction `{direction}` (expected down, up, left, right, top, or bottom).",
                    }
                eff_amt = int(amount) if amount is not None and int(amount) != 0 else 600
                sc_res = page.evaluate(
                    _SCROLL_DOM_JS,
                    {"sel": norm_sel, "direction": eff_dir, "amount": eff_amt},
                )
                sc_dict = sc_res if isinstance(sc_res, dict) else {"ok": False, "error": "Unexpected scroll response"}
                if not sc_dict.get("ok"):
                    return {
                        "ok": False,
                        "pack": "browser",
                        "action": "scroll",
                        **sc_dict,
                    }
                if eff_wait_ms > 0:
                    page.wait_for_timeout(eff_wait_ms)
                return {
                    "ok": True,
                    "pack": "browser",
                    "action": "scroll",
                    "url": page.url,
                    "title": page.title(),
                    **sc_dict,
                }

            if act == "evaluate":
                expr = (script or text or "").strip()
                if not expr:
                    return {
                        "ok": False,
                        "pack": "browser",
                        "action": "evaluate",
                        "error": "`script` (JavaScript expression or arrow function) is required for action='evaluate'.",
                    }
                post_err = _verify_post_nav_url(page)
                if post_err:
                    return {
                        "ok": False,
                        "pack": "browser",
                        "action": "evaluate",
                        "blocked_by_guardrail": True,
                        "blocked_by_ssrf_guard": True,
                        "error": post_err,
                    }
                val = page.evaluate(expr)
                try:
                    serialized = json.loads(json.dumps(val, ensure_ascii=False, default=str))
                except Exception:
                    serialized = str(val)[:16000]
                return {
                    "ok": True,
                    "pack": "browser",
                    "action": "evaluate",
                    "url": page.url,
                    "title": page.title(),
                    "result": serialized,
                }

            # act == "screenshot"
            if eff_wait_ms > 0:
                page.wait_for_timeout(eff_wait_ms)
            post_err = _verify_post_nav_url(page)
            if post_err:
                return {
                    "ok": False,
                    "pack": "browser",
                    "action": "screenshot",
                    "blocked_by_guardrail": True,
                    "blocked_by_ssrf_guard": True,
                    "error": post_err,
                }
            png_bytes = page.screenshot(full_page=bool(full_page), type="png", timeout=eff_timeout_ms)
            return {
                "_raw_png": png_bytes,
                "url": page.url,
                "title": page.title(),
            }

        raw_out = worker.submit(_task, timeout_sec=(eff_timeout_ms / 1000.0) + 12.0)
        if act == "screenshot" and isinstance(raw_out, dict) and "_raw_png" in raw_out:
            png_b: bytes = raw_out["_raw_png"]
            comp = compress_capture_bytes(png_b, source_label="browser_use:screenshot")
            saved_p, save_err = save_optional_capture(
                comp["out_bytes"],
                save_path,
                self.guard,
                workspace_root=ws_root,
                tool_name="browser_use",
            )
            if save_err:
                return {"ok": False, "pack": "browser", "blocked_by_guardrail": True, "error": save_err}
            meta = {
                **comp["meta"],
                "pack": "browser",
                "action": "screenshot",
                "headless": True,
                "backend": worker.active_backend,
                "profile_dir": str(profile_dir),
                "url": raw_out.get("url", ""),
                "title": raw_out.get("title", ""),
            }
            if saved_p:
                meta["saved_path"] = saved_p
            return build_mcp_image_blocks(meta, comp["b64_data"], comp["mime"])

        return raw_out

    def get_tools(self) -> Sequence[ToolSpec]:
        return build_single_pack_tool_tuple(
            base_name="browser_use",
            handler=self.browser_use,
            safety_band=SafetyBand.WORKSPACE_EXEC,
            input_schema=BROWSER_USE_INPUT_SCHEMA,
            title="Isolated Headless Browser Pack",
            description=(
                "Isolated managed browser (`state_root/browser_profile`): "
                "`action='open'|'snapshot'|'click'|'fill'|'select'|'scroll'|'list_tabs'|'switch_tab'|'open_login_window'|'screenshot'|'evaluate'|'close'`."
            ),
            pack_id=self.pack_id,
            action_enum=BROWSER_USE_ACTIONS,
            open_world=True,
        )

    def shutdown(self, prefix_filter: str = "") -> None:
        clean_p = (prefix_filter or "").strip()
        with self._lock:
            owned = set(self._owned_keys)
        to_stop: List[_IsolatedBrowserWorker] = []
        with _GLOBAL_WORKERS_LOCK:
            for k in list(_GLOBAL_WORKERS.keys()):
                if owned and k not in owned and clean_p == "":
                    continue
                w = _GLOBAL_WORKERS[k]
                if not clean_p:
                    to_stop.append(_GLOBAL_WORKERS.pop(k))
                else:
                    is_match = (
                        (w.profile_dir.name == "browser_profile")
                        if clean_p == "pc"
                        else (w.profile_dir.name.lower() == clean_p.lower())
                    )
                    if is_match:
                        to_stop.append(_GLOBAL_WORKERS.pop(k))
            for lk in list(_LOGIN_WINDOWS.keys()):
                if owned and lk not in owned and clean_p == "":
                    continue
                lrec = _LOGIN_WINDOWS[lk]
                pdir: Path = lrec["profile_dir"]
                if not clean_p:
                    _stop_managed_login_window_unlocked(lk)
                else:
                    is_lmatch = (
                        (pdir.name == "browser_profile")
                        if clean_p == "pc"
                        else (pdir.name.lower() == clean_p.lower())
                    )
                    if is_lmatch:
                        _stop_managed_login_window_unlocked(lk)
        with self._lock:
            for w in to_stop:
                self._owned_keys.discard(os.path.normcase(str(w.profile_dir.resolve())))
            if not clean_p:
                self._owned_keys.clear()
        for w in to_stop:
            with contextlib.suppress(Exception):
                w.stop()
        if clean_p:
            prof = self.resolve_profile_dir(clean_p)
            _release_browser_profile_locks_win32(prof)


__all__ = [
    "BROWSER_USE_ACTIONS",
    "BROWSER_USE_INPUT_SCHEMA",
    "BrowserPackPlugin",
    "PackPlugin",
    "close_all_browser_sessions",
    "find_system_chromium_binary",
    "resolve_browser_proxy_settings",
    "validate_outbound_http_url",
]
