"use strict";

const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { app, BrowserWindow } = require("electron");

const HOST = "127.0.0.1";
const PORT = 48124;
const diagnostics = [];

function safeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function safeSourceAsset(value) {
  if (typeof value !== "string") return null;
  const source = value.split(/[?#]/, 1)[0];
  const pieces = source.split(/[\\/]/);
  const basename = pieces[pieces.length - 1] || "";
  return basename.length > 0 && basename.length <= 200 ? basename : null;
}

function recordDiagnostic(kind, details = {}) {
  const safe = { kind };
  if (kind === "console") {
    if (Number.isSafeInteger(details.level) && details.level >= 0) safe.level = details.level;
    safe.line = safeInteger(details.line);
    safe.source_asset = safeSourceAsset(details.sourceId);
  } else if (kind === "render-process-gone") {
    const reasons = new Set(["clean-exit", "abnormal-exit", "crashed", "killed", "oom", "launch-failed"]);
    safe.reason = reasons.has(details.reason) ? details.reason : "unknown";
    safe.exit_code = safeInteger(details.exitCode ?? details.exit_code);
  }
  diagnostics.push(safe);
  if (diagnostics.length > 100) diagnostics.shift();
}

function writeJson(response, status, body) {
  response.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  response.end(JSON.stringify(body));
}

function allWindows() {
  return BrowserWindow.getAllWindows().filter((window) => {
    try {
      return !window.isDestroyed();
    } catch {
      return false;
    }
  });
}

function mainWindow() {
  const windows = allWindows().filter((window) => {
    try {
      return window.getBounds().width >= 700;
    } catch {
      return false;
    }
  });
  return windows.find((window) => safeVisible(window)) ?? windows[0];
}

function safeVisible(window) {
  try {
    return window.isVisible();
  } catch {
    return false;
  }
}

function safeLoading(window) {
  try {
    return window.webContents.isLoading();
  } catch {
    return false;
  }
}

function safeWebContentsId(window) {
  try {
    return window.webContents.id;
  } catch {
    return null;
  }
}

function safeBounds(window) {
  try {
    const bounds = window.getBounds();
    return {
      x: bounds.x,
      y: bounds.y,
      width: bounds.width,
      height: bounds.height,
    };
  } catch {
    return null;
  }
}

function safeUrl(window) {
  try {
    const parsed = new URL(window.webContents.getURL());
    return { origin: parsed.origin, pathname: parsed.pathname };
  } catch {
    return null;
  }
}

function emptyRouterFlags() {
  return {
    rendererPatchLoaded: false,
    accountMenuInjected: false,
    accountMenuMounted: false,
    accountsLoaded: false,
    accountCount: 0,
    requestFailed: false,
  };
}

async function readRouterFlags(window) {
  if (!window) return emptyRouterFlags();
  try {
    const flags = await window.webContents.executeJavaScript(`(() => {
      const state=globalThis.__codexMuxAccountMenuState??{};
      return {
        rendererPatchLoaded:globalThis.__codexMuxRendererPatchLoaded===true,
        accountMenuInjected:globalThis.__codexMuxAccountMenuInjected===true,
        accountMenuMounted:globalThis.__codexMuxAccountMenuMounted===true,
        accountsLoaded:state.accountsLoaded===true,
        accountCount:Number.isSafeInteger(state.accountCount)&&state.accountCount>=0?state.accountCount:0,
        requestFailed:state.requestFailed===true,
      };
    })()`);
    return {
      rendererPatchLoaded: flags?.rendererPatchLoaded === true,
      accountMenuInjected: flags?.accountMenuInjected === true,
      accountMenuMounted: flags?.accountMenuMounted === true,
      accountsLoaded: flags?.accountsLoaded === true,
      accountCount:
        Number.isSafeInteger(flags?.accountCount) && flags.accountCount >= 0
          ? flags.accountCount
          : 0,
      requestFailed: flags?.requestFailed === true,
    };
  } catch {
    return emptyRouterFlags();
  }
}

function safeAuthState(value) {
  return value === "AUTHENTICATED" || value === "AUTH_REQUIRED" || value === "UNKNOWN"
    ? value
    : "UNKNOWN";
}

async function readDesktopAuth(window) {
  if (!window) return { state: "UNKNOWN" };
  try {
    const state = await window.webContents.executeJavaScript(`(() => {
      const valid=value=>value==='AUTHENTICATED'||value==='AUTH_REQUIRED'||value==='UNKNOWN';
      const runtime=globalThis.__codexMuxRendererRuntime??{};
      const pathname=typeof globalThis.location?.pathname==='string'?globalThis.location.pathname.toLowerCase():'';
      const authRoute=/(^|\\/)(auth|login|signin|sign-in)(\\/|$)/.test(pathname);
      const body=document.body;
      const root=document.querySelector('#root')||body?.firstElementChild||null;
      const composer=document.querySelector('textarea[placeholder],[contenteditable="true"]');
      const controller=globalThis.__codexMuxProfileMenuControllerReady===true||runtime.profileControllerReady===true;
      let detected='UNKNOWN';
      if(authRoute) detected='AUTH_REQUIRED';
      else if(globalThis.__codexMuxAuthenticatedShellReady===true||(composer&&controller)) detected='AUTHENTICATED';
      else if(document.readyState==='complete'&&root&&!composer&&!controller) detected='AUTH_REQUIRED';
      const saved=valid(globalThis.__codexMuxDesktopAuth)?globalThis.__codexMuxDesktopAuth:'UNKNOWN';
      return {state:detected!=='UNKNOWN'?detected:saved};
    })()`);
    return { state: safeAuthState(state?.state) };
  } catch {
    return { state: "UNKNOWN" };
  }
}

function safeRuntimeDiagnostic(raw) {
  if (!raw || typeof raw !== "object") return null;
  const kinds = new Set(["error", "unhandledrejection", "render-process-gone"]);
  const names = new Set(["Error", "EvalError", "RangeError", "ReferenceError", "SyntaxError", "TypeError", "URIError"]);
  const item = { kind: kinds.has(raw.kind) ? raw.kind : "error" };
  item.name = names.has(raw.name) ? raw.name : "Error";
  item.source_asset = safeSourceAsset(raw.source_asset);
  item.line = safeInteger(raw.line);
  item.column = safeInteger(raw.column);
  if (item.kind === "render-process-gone") {
    const reasons = new Set(["clean-exit", "abnormal-exit", "crashed", "killed", "oom", "launch-failed"]);
    item.reason = reasons.has(raw.reason) ? raw.reason : "unknown";
    item.exit_code = safeInteger(raw.exit_code);
  }
  return item;
}

async function readRendererRuntime(window) {
  const fallback = {
    readyState: "unknown",
    rootPresent: false,
    rootChildCount: 0,
    bodyChildCount: 0,
    buttonCount: 0,
    visibleInteractiveCount: 0,
    composerPresent: false,
    profileControllerReady: false,
    runtimeErrorCount: 0,
    lastSafeRuntimeError: null,
  };
  if (!window) return fallback;
  try {
    const runtime = await window.webContents.executeJavaScript(`(() => {
      const saved=globalThis.__codexMuxRendererRuntime??{};
      const body=document.body;
      const root=document.querySelector('#root')||body?.firstElementChild||null;
      const composer=document.querySelector('textarea[placeholder],[contenteditable="true"]');
      let visible=0;
      for(const element of document.querySelectorAll('button,a,input,textarea,[role="button"],[contenteditable="true"]')){
        const rect=element.getBoundingClientRect();
        if(rect.width>0&&rect.height>0) visible++;
      }
      const errors=Array.isArray(globalThis.__codexMuxRuntimeErrors)?globalThis.__codexMuxRuntimeErrors:[];
      const readyState=['loading','interactive','complete'].includes(document.readyState)?document.readyState:'unknown';
      return {
        readyState,
        rootPresent:root!==null,
        rootChildCount:Number.isSafeInteger(saved.rootChildCount)?saved.rootChildCount:(root?.children?.length??0),
        bodyChildCount:Number.isSafeInteger(saved.bodyChildCount)?saved.bodyChildCount:(body?.children?.length??0),
        buttonCount:Number.isSafeInteger(saved.buttonCount)?saved.buttonCount:document.querySelectorAll('button').length,
        visibleInteractiveCount:Number.isSafeInteger(saved.visibleInteractiveCount)?saved.visibleInteractiveCount:visible,
        composerPresent:composer!==null,
        profileControllerReady:globalThis.__codexMuxProfileMenuControllerReady===true||saved.profileControllerReady===true,
        runtimeErrorCount:errors.length,
        lastSafeRuntimeError:errors.at(-1)??null,
      };
    })()`);
    const output = { ...fallback };
    if (["loading", "interactive", "complete", "unknown"].includes(runtime?.readyState)) output.readyState = runtime.readyState;
    for (const key of ["rootChildCount", "bodyChildCount", "buttonCount", "visibleInteractiveCount", "runtimeErrorCount"]) {
      if (Number.isSafeInteger(runtime?.[key]) && runtime[key] >= 0) output[key] = runtime[key];
    }
    for (const key of ["rootPresent", "composerPresent", "profileControllerReady"]) {
      if (typeof runtime?.[key] === "boolean") output[key] = runtime[key];
    }
    output.lastSafeRuntimeError = safeRuntimeDiagnostic(runtime?.lastSafeRuntimeError);
    return output;
  } catch {
    return fallback;
  }
}

async function readProfileController(window) {
  const fallback = { ready: false, activationAttempted: false, activationSucceeded: false };
  if (!window) return fallback;
  try {
    const controller = await window.webContents.executeJavaScript(`(() => ({
      ready:globalThis.__codexMuxProfileMenuControllerReady===true,
      activationAttempted:globalThis.__codexMuxProfileMenuActivationAttempted===true,
      activationSucceeded:globalThis.__codexMuxProfileMenuActivationSucceeded===true,
    }))()`);
    return {
      ready: controller?.ready === true,
      activationAttempted: controller?.activationAttempted === true,
      activationSucceeded: controller?.activationSucceeded === true,
    };
  } catch {
    return fallback;
  }
}

async function readRuntimeDiagnostics(window) {
  const output = [];
  if (window) {
    try {
      const errors = await window.webContents.executeJavaScript(
        `Array.isArray(globalThis.__codexMuxRuntimeErrors)?globalThis.__codexMuxRuntimeErrors:[]`,
      );
      for (const error of Array.isArray(errors) ? errors : []) {
        const safe = safeRuntimeDiagnostic(error);
        if (safe) output.push(safe);
      }
    } catch {}
  }
  for (const diagnostic of diagnostics) {
    if (diagnostic.kind !== "render-process-gone") continue;
    const safe = safeRuntimeDiagnostic(diagnostic);
    if (safe) output.push(safe);
  }
  return output.slice(-20);
}

async function observationWindow() {
  for (const window of allWindows()) {
    const flags = await readRouterFlags(window);
    if (flags.rendererPatchLoaded) return window;
  }
  return mainWindow();
}

async function windowDiagnostics() {
  const summaries = [];
  for (const window of allWindows()) {
    const flags = await readRouterFlags(window);
    const auth = await readDesktopAuth(window);
    summaries.push({
      webContentsId: safeWebContentsId(window),
      visible: safeVisible(window),
      bounds: safeBounds(window),
      isLoading: safeLoading(window),
      url: safeUrl(window),
      rendererPatchLoaded: flags.rendererPatchLoaded,
      accountMenuInjected: flags.accountMenuInjected,
      desktopAuth: auth.state,
    });
  }
  return summaries;
}

async function runAction(window, action, delayMs) {
  window.show();
  window.focus();
  if (action === "profile-router-open") {
    const auth = await readDesktopAuth(window);
    if (auth.state !== "AUTHENTICATED") {
      throw new Error("Desktop authentication is required before opening the Router profile menu");
    }
    const activated = await window.webContents.executeJavaScript(`(() => {
      globalThis.__codexMuxProfileMenuActivationAttempted = true;
      const open = globalThis.__codexMuxOpenProfileMenuForTest;
      if (typeof open !== 'function') {
        globalThis.__codexMuxProfileMenuActivationSucceeded = false;
        return false;
      }
      const succeeded = open() === true;
      globalThis.__codexMuxProfileMenuActivationSucceeded = succeeded;
      return succeeded;
    })()`);
    if (activated !== true) throw new Error("The native Router profile-menu controller was not ready");
    await new Promise((resolve) => setTimeout(resolve, Math.max(delayMs, 400)));
    return;
  }
  if (action === "profile-toggle") {
    const toggled = await window.webContents.executeJavaScript(`(() => { const target=[...document.querySelectorAll('button[aria-label]')].find(element=>{const label=element.getAttribute('aria-label')||'';return label==='Show combined profile stats'||(label.startsWith('Show ')&&label.endsWith(' profile stats'))}); if(!target)return false; target.click(); return true; })()`);
    if (!toggled) throw new Error("Could not toggle a subscription profile");
    await new Promise((resolve) => setTimeout(resolve, Math.max(delayMs, 1_500)));
    return;
  }
  if (action === "plugins-select-second") {
    const selected = await window.webContents.executeJavaScript(`(() => {
      const accountButtons=[...document.querySelectorAll('button[aria-pressed]')]
        .filter(button=>button.textContent?.includes('Subscription'));
      const target=accountButtons.find(button=>button.textContent?.includes('Subscription 2'))??accountButtons[0];
      if(!target)return false;
      target.click();
      return true;
    })()`);
    if (!selected) throw new Error("Could not select a secondary plugin subscription");
    await new Promise((resolve) => setTimeout(resolve, 750));
    const selectionState = await window.webContents.executeJavaScript(`(() => {
      const target=[...document.querySelectorAll('button[aria-pressed]')]
        .find(button=>button.textContent?.includes('Subscription 2'));
      return {accountId:globalThis.__codexMuxPluginAccountId??null,pressed:target?.getAttribute('aria-pressed')??null};
    })()`);
    if (selectionState.accountId === "primary" || selectionState.pressed !== "true") {
      throw new Error(`Secondary plugin subscription did not remain selected: ${JSON.stringify(selectionState)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, Math.max(delayMs, 1_500)));
    return;
  }
  if (action === "usage-select-second") {
    const selected = await window.webContents.executeJavaScript(`(() => {
      const target=[...document.querySelectorAll('button[aria-pressed]')]
        .find(button=>button.textContent?.includes('Subscription 2'));
      if(!target)return false;
      target.click();
      return true;
    })()`);
    if (!selected) throw new Error("Could not select a secondary reset subscription");
    const selectionState = await window.webContents.executeJavaScript(`new Promise((resolve) => {
      const read=()=>{const target=[...document.querySelectorAll('button[aria-pressed]')]
        .find(button=>button.textContent?.includes('Subscription 2'));
        return {accountId:globalThis.__codexMuxResetAccountId??null,pressed:target?.getAttribute('aria-pressed')??null};};
      const deadline=Date.now()+4000;
      const poll=()=>{const state=read();if(state.accountId&&state.accountId!=="primary"&&state.pressed==="true")resolve(state);else if(Date.now()>=deadline)resolve(state);else setTimeout(poll,100);};
      poll();
    })`);
    if (!selectionState.accountId || selectionState.accountId === "primary" || selectionState.pressed !== "true") {
      throw new Error(`Secondary reset subscription did not remain selected: ${JSON.stringify(selectionState)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, Math.max(delayMs, 1_500)));
    return;
  }
  const settingsSections = {
    "settings-profile": "Profile",
    "settings-plugins": "Plugins",
    "settings-appshots": "Appshots",
    "settings-computer-use": "Computer use",
  };
  if (Object.hasOwn(settingsSections, action)) {
    const section = settingsSections[action];
    const alreadyInSettings = await window.webContents.executeJavaScript(`(() =>
      document.body?.innerText?.includes('Back to app')??false
    )()`);
    if (!alreadyInSettings) {
      const settingsPoint = `(() => { const labels=[...document.querySelectorAll('body *')].filter(element=>element.textContent?.trim()==='Settings'); const label=labels.sort((a,b)=>a.children.length-b.children.length)[0]; const target=label?.closest('button,a,[role="menuitem"],[role="button"]')??label; if(!target)return null; const rect=target.getBoundingClientRect(); return {x:Math.round(rect.x+rect.width/2),y:Math.round(rect.y+rect.height/2)}; })()`;
      let point = await window.webContents.executeJavaScript(settingsPoint);
      if (!point) {
        const profilePoint = await window.webContents.executeJavaScript(`(() => { const target=document.querySelector('button[aria-label="Open profile menu"]'); if(!target)return null; const rect=target.getBoundingClientRect(); return {x:Math.round(rect.x+rect.width/2),y:Math.round(rect.y+rect.height/2)}; })()`);
        if (!profilePoint) throw new Error("Could not find the profile-menu button");
        window.webContents.sendInputEvent({ type: "mouseDown", x: profilePoint.x, y: profilePoint.y, button: "left", clickCount: 1 });
        window.webContents.sendInputEvent({ type: "mouseUp", x: profilePoint.x, y: profilePoint.y, button: "left", clickCount: 1 });
        await new Promise((resolve) => setTimeout(resolve, 800));
        point = await window.webContents.executeJavaScript(settingsPoint);
      }
      if (!point) throw new Error("Could not open Settings");
      window.webContents.sendInputEvent({ type: "mouseDown", x: point.x, y: point.y, button: "left", clickCount: 1 });
      window.webContents.sendInputEvent({ type: "mouseUp", x: point.x, y: point.y, button: "left", clickCount: 1 });
      await new Promise((resolve) => setTimeout(resolve, 750));
    }
    const settingsWindow = mainWindow() ?? window;
    const sectionPoint = await settingsWindow.webContents.executeJavaScript(`(() => { const target=[...document.querySelectorAll('body *')].find(element=>element.children.length===0&&element.textContent?.trim()===${JSON.stringify(section)}); if(!target)return null; const rect=target.getBoundingClientRect(); return {x:Math.round(rect.x+rect.width/2),y:Math.round(rect.y+rect.height/2)}; })()`);
    if (!sectionPoint) throw new Error(`Could not open Settings > ${section}`);
    settingsWindow.webContents.sendInputEvent({ type: "mouseDown", x: sectionPoint.x, y: sectionPoint.y, button: "left", clickCount: 1 });
    settingsWindow.webContents.sendInputEvent({ type: "mouseUp", x: sectionPoint.x, y: sectionPoint.y, button: "left", clickCount: 1 });
    await new Promise((resolve) => setTimeout(resolve, Math.max(delayMs, 1_500)));
    return;
  }
  if (action === "appshots-open") {
    const plusPoint = await window.webContents.executeJavaScript(`(() => {
      const buttons=[...document.querySelectorAll('button')];
      const target=buttons.find(button=>{
        const label=(button.getAttribute('aria-label')??'').toLowerCase();
        const rect=button.getBoundingClientRect();
        return rect.width>0&&rect.height>0&&(label.includes('attach')||label.includes('add'))&&rect.bottom>innerHeight-180;
      });
      if(!target)return null;
      const rect=target.getBoundingClientRect();
      return {x:Math.round(rect.x+rect.width/2),y:Math.round(rect.y+rect.height/2)};
    })()`);
    if (!plusPoint) throw new Error("Could not find the composer attachment button");
    window.webContents.sendInputEvent({ type: "mouseDown", x: plusPoint.x, y: plusPoint.y, button: "left", clickCount: 1 });
    window.webContents.sendInputEvent({ type: "mouseUp", x: plusPoint.x, y: plusPoint.y, button: "left", clickCount: 1 });
    await new Promise((resolve) => setTimeout(resolve, 500));
    let opened = await window.webContents.executeJavaScript(`(() => {
      const target=[...document.querySelectorAll('button,[role="menuitem"]')]
        .find(element=>/appshot/i.test(element.textContent??''));
      if(!target)return false;
      target.click();
      return true;
    })()`);
    if (!opened) {
      const scrolled = await window.webContents.executeJavaScript(`(() => {
        const candidates=[...document.querySelectorAll('body *')]
          .filter(element=>element.scrollHeight>element.clientHeight+20&&element.clientHeight>150)
          .sort((left,right)=>(right.scrollHeight-right.clientHeight)-(left.scrollHeight-left.clientHeight));
        const target=candidates[0];
        if(!target)return false;
        target.scrollTop=target.scrollHeight;
        target.dispatchEvent(new Event('scroll',{bubbles:true}));
        return true;
      })()`);
      if (scrolled) {
        await new Promise((resolve) => setTimeout(resolve, 600));
        opened = await window.webContents.executeJavaScript(`(() => {
          const target=[...document.querySelectorAll('button,[role="menuitem"]')]
            .find(element=>/appshot/i.test(element.textContent??''));
          if(!target)return false;
          target.click();
          return true;
        })()`);
      }
    }
    if (!opened) throw new Error("Could not find Appshots in the attachment menu");
    await new Promise((resolve) => setTimeout(resolve, Math.max(delayMs, 2_000)));
    return;
  }
  if (action === "appshots-hotkey") {
    for (let index = 0; index < 2; index += 1) {
      window.webContents.sendInputEvent({ type: "keyDown", keyCode: "Meta" });
      window.webContents.sendInputEvent({ type: "keyUp", keyCode: "Meta" });
      await new Promise((resolve) => setTimeout(resolve, 90));
    }
    await new Promise((resolve) => setTimeout(resolve, Math.max(delayMs, 3_000)));
    return;
  }
  if (action === "appshots-settings-trigger") {
    const triggered = await window.webContents.executeJavaScript(`(() => {
      const label=[...document.querySelectorAll('body *')]
        .find(element=>element.children.length===0&&element.textContent?.trim()==='Take an appshot to show ChatGPT your frontmost window');
      const target=label?.closest('button,[role="button"]')??label;
      if(!target)return false;
      target.click();
      return true;
    })()`);
    if (!triggered) throw new Error("Could not trigger an Appshot from Settings");
    await new Promise((resolve) => setTimeout(resolve, Math.max(delayMs, 4_000)));
    return;
  }
  if (action === "computer-use-details") {
    const opened = await window.webContents.executeJavaScript(`(() => {
      const label=[...document.querySelectorAll('body *')]
        .find(element=>element.children.length===0&&/^Worked for \d+s/.test(element.textContent?.trim()??''));
      const target=label?.closest('button,[role="button"]')??label;
      if(!target)return false;
      target.click();
      return true;
    })()`);
    if (!opened) throw new Error("Could not expand the Computer Use details");
    await new Promise((resolve) => setTimeout(resolve, Math.max(delayMs, 1_500)));
    return;
  }
  if (action === "usage" || action === "usage-confirm" || action === "usage-confirm-final") {
    const usageVisible = await window.webContents.executeJavaScript(`(() =>
      [...document.querySelectorAll('h1,h2,[role="dialog"]')]
        .some(element => element.textContent?.includes('Usage limit resets'))
    )()`);
    if (!usageVisible) {
      const point = await window.webContents.executeJavaScript(`(() => { const target=document.querySelector('button[aria-label="Open profile menu"]'); if(!target)return null; const rect=target.getBoundingClientRect(); return {x:Math.round(rect.x+rect.width/2),y:Math.round(rect.y+rect.height/2)}; })()`);
      if (!point) throw new Error("Could not find the profile-menu button");
      window.webContents.sendInputEvent({ type: "mouseDown", x: point.x, y: point.y, button: "left", clickCount: 1 });
      window.webContents.sendInputEvent({ type: "mouseUp", x: point.x, y: point.y, button: "left", clickCount: 1 });
      await new Promise((resolve) => setTimeout(resolve, 350));
      const opened = await window.webContents.executeJavaScript(`(() => { const target=[...document.querySelectorAll('button,[role="menuitem"]')].find(element=>element.textContent?.includes('Usage remaining')); if(!target)return false; target.click(); return true; })()`);
      if (!opened) throw new Error("Could not open the Usage sheet");
      await new Promise((resolve) => setTimeout(resolve, 750));
    }
    if (action === "usage-confirm") {
      const confirming = await window.webContents.executeJavaScript(`(() => { const target=[...document.querySelectorAll('button')].find(element=>element.textContent?.trim()==='Use reset'); if(!target)return false; target.click(); return true; })()`);
      if (!confirming) throw new Error("Could not find the Use reset button");
    }
    if (action === "usage-confirm-final") {
      const confirmed = await window.webContents.executeJavaScript(`(() => { const target=[...document.querySelectorAll('button')].find(element=>element.textContent?.trim()==='Confirm'); if(!target)return false; target.click(); return true; })()`);
      if (!confirmed) throw new Error("Could not find the reset confirmation button");
    }
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    return;
  }
  if (action === "submit-computer-use") {
    const isSettings = await window.webContents.executeJavaScript(`document.body?.innerText?.includes('Back to app')??false`);
    if (isSettings) {
      const returned = await window.webContents.executeJavaScript(`(() => { const label=[...document.querySelectorAll('body *')].find(element=>element.textContent?.trim()==='Back to app'); const target=label?.closest('button,a,[role="button"]')??label; if(!target)return false; target.click(); return true; })()`);
      if (!returned) throw new Error("Could not leave Settings for the Computer Use test");
      await new Promise((resolve) => setTimeout(resolve, 1_500));
      window = mainWindow() ?? window;
    }
    const newChatPoint = await window.webContents.executeJavaScript(`(() => { const target=document.querySelector('button[aria-label="New chat"]'); if(!target)return null; const rect=target.getBoundingClientRect(); return {x:Math.round(rect.x+rect.width/2),y:Math.round(rect.y+rect.height/2)}; })()`);
    if (newChatPoint) {
      window.webContents.sendInputEvent({ type: "mouseDown", x: newChatPoint.x, y: newChatPoint.y, button: "left", clickCount: 1 });
      window.webContents.sendInputEvent({ type: "mouseUp", x: newChatPoint.x, y: newChatPoint.y, button: "left", clickCount: 1 });
      await new Promise((resolve) => setTimeout(resolve, 1_000));
    }
    const filled = await window.webContents.executeJavaScript(`(() => {
      const composer=document.querySelector('textarea[placeholder]')??document.querySelector('[contenteditable="true"]');
      if(!composer)return false;
      composer.focus();
      if(composer instanceof HTMLTextAreaElement){Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(composer,${JSON.stringify("Use the Computer controls to open Calculator, then stop.")});}
      else{composer.textContent=${JSON.stringify("Use the Computer controls to open Calculator, then stop.")};}
      composer.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText',data:${JSON.stringify("Use the Computer controls to open Calculator, then stop.")}}));
      return true;
    })()`);
    if (!filled) throw new Error("Could not fill the Computer Use test prompt");
    await new Promise((resolve) => setTimeout(resolve, 250));
    const submitted = await window.webContents.executeJavaScript(`(() => { const target=[...document.querySelectorAll('button')].find(button=>button.getAttribute('aria-label')==='Send'&&!button.disabled); if(!target)return false; target.click(); return true; })()`);
    if (!submitted) throw new Error("Could not submit the Computer Use test prompt");
    await new Promise((resolve) => setTimeout(resolve, 60_000));
    const outcome = await window.webContents.executeJavaScript(`(() => { const text=document.body?.innerText??''; return {fellBack:/osascript|native automation interface/i.test(text),text:text.slice(-4000)}; })()`);
    if (outcome.fellBack) throw new Error("Computer Use fell back to osascript");
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    return;
  }
  if (action === "submit-quota") {
    const filled = await window.webContents.executeJavaScript(`(() => {
      const composer=document.querySelector('textarea[placeholder]')??document.querySelector('[contenteditable="true"]');
      if(!composer)return false;
      composer.focus();
      if(composer instanceof HTMLTextAreaElement){
        const setter=Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set;
        setter.call(composer,'Quota handling preview');
      }else{
        composer.textContent='Quota handling preview';
      }
      composer.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText',data:'Quota handling preview'}));
      return true;
    })()`);
    if (!filled) throw new Error("Could not find the test composer");
    await new Promise((resolve) => setTimeout(resolve, 250));
    const submitted = await window.webContents.executeJavaScript(`(() => {
      const composer=document.querySelector('textarea[placeholder]')??document.querySelector('[contenteditable="true"]');
      if(!composer)return false;
      const target=[...document.querySelectorAll('button')].find(button=>button.getAttribute('aria-label')==='Send'&&!button.disabled);
      if(!target)return false;
      target.click();
      return true;
    })()`);
    if (!submitted) throw new Error("Could not submit the quota test turn");
    await window.webContents.executeJavaScript(`new Promise((resolve) => {
      const visibleQuotaError=()=>[...document.querySelectorAll('[role="alert"],body *')].some(element=>element.textContent?.includes('All connected subscriptions are depleted'));
      if(visibleQuotaError()){resolve(true);return;}
      const observer=new MutationObserver(()=>{if(visibleQuotaError()){observer.disconnect();resolve(true);}});
      observer.observe(document.body,{childList:true,subtree:true,characterData:true});
      setTimeout(()=>{observer.disconnect();resolve(false);},15000);
    })`);
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    return;
  }
  const selector = "button,[role='button'],a";
  let script;
  if (action === "profile") {
    const point = await window.webContents.executeJavaScript(`(() => { const target=document.querySelector('button[aria-label="Open profile menu"]'); if(!target)return null; const rect=target.getBoundingClientRect(); return {x:Math.round(rect.x+rect.width/2),y:Math.round(rect.y+rect.height/2)}; })()`);
    if (!point) throw new Error("Could not find the profile-menu button");
    window.webContents.sendInputEvent({ type: "mouseDown", x: point.x, y: point.y, button: "left", clickCount: 1 });
    window.webContents.sendInputEvent({ type: "mouseUp", x: point.x, y: point.y, button: "left", clickCount: 1 });
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    return;
  } else if (action === "quota-thread") {
    const openQuotaThread = `(() => { const candidates=[...document.querySelectorAll(${JSON.stringify(selector)})]; const target=candidates.find(element=>element.textContent.trim()==="Quota handling preview"); if(!target)return false; target.click(); return true; })()`;
    if (!(await window.webContents.executeJavaScript(openQuotaThread))) {
      const expanded = await window.webContents.executeJavaScript(`(() => { const candidates=[...document.querySelectorAll(${JSON.stringify(selector)})]; const target=candidates.find(element=>element.textContent.trim()==="Show more"); if(!target)return false; target.click(); return true; })()`);
      if (!expanded) throw new Error("Could not expand the recent chats");
      await new Promise((resolve) => setTimeout(resolve, 500));
      if (!(await window.webContents.executeJavaScript(openQuotaThread))) {
        throw new Error("Could not find the quota preview thread");
      }
    }
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    return;
  } else if (action === "first-thread") {
    script = `(() => { const candidates=[...document.querySelectorAll(${JSON.stringify(selector)})]; const target=candidates.find(element=>element.textContent.includes("Codex, we want to modify ChatGPT.app")); if(!target)return false; target.click(); return true; })()`;
  } else {
    script = `(() => { const label=[...document.querySelectorAll('body *')].find(element=>element.textContent?.trim()==="Back to app"); const target=label?.closest('button,a,[role="button"]')??label; if(!target)return false; target.click(); return true; })()`;
  }
  const clicked = await window.webContents.executeJavaScript(script);
  if (!clicked) throw new Error(`Could not perform UI-test action: ${action}`);
  await new Promise((resolve) => setTimeout(resolve, delayMs));
}

async function capture(action, delayMs, includeDebug) {
  let window = action === null ? await observationWindow() : mainWindow();
  if (!window) throw new Error("Codex Subscription Router has no main window");
  if (action !== null) await runAction(window, action, delayMs);
  window = (await observationWindow()) ?? window;
  const image = await window.webContents.capturePage();
  const result = {
    bounds: window.getContentBounds(),
    imageBase64: image.toPNG().toString("base64"),
  };
  if (includeDebug) {
    const routerFlags = await readRouterFlags(window);
    const desktopAuth = await readDesktopAuth(window);
    const rendererRuntime = await readRendererRuntime(window);
    const profileController = await readProfileController(window);
    const runtimeErrors = await readRuntimeDiagnostics(window);
    result.debug = await window.webContents.executeJavaScript(`(() => {
      const composer=document.querySelector('textarea[placeholder]')??document.querySelector('[contenteditable="true"]');
      const describe=element=>{const rect=element.getBoundingClientRect(); const label=element.getAttribute('aria-label'); return {ariaLabel:label==='Open profile menu'||/^Show (combined )?profile stats$/.test(label||'')?label:null,disabled:element.disabled,type:element.type,rect:{x:rect.x,y:rect.y,width:rect.width,height:rect.height}}};
      return {
        readyState: document.readyState,
        composer:composer?describe(composer):null,
        buttons:[...document.querySelectorAll('button')].filter(button=>{const rect=button.getBoundingClientRect();return rect.width>0&&rect.height>0&&rect.bottom>innerHeight-180}).map(describe),
      };
    })()`);
    result.debug.url = safeUrl(window);
    result.debug.router = routerFlags;
    result.debug.desktop_auth = desktopAuth;
    result.debug.renderer_runtime = rendererRuntime;
    result.debug.profile_controller = profileController;
    result.debug.runtime_errors = runtimeErrors;
    result.debug.termination = null;
    result.debug.windows = await windowDiagnostics();
    result.diagnostics = diagnostics.slice(-50);
  }
  return result;
}

function start() {
  if (process.env.CODEX_MUX_UI_TESTS !== "1") return;
  app.on("web-contents-created", (_event, contents) => {
    contents.on("console-message", (_consoleEvent, level, message, line, sourceId) => {
      recordDiagnostic("console", { level, line, sourceId });
    });
    contents.on("render-process-gone", (_goneEvent, details) => {
      recordDiagnostic("render-process-gone", {
        reason: details?.reason,
        exitCode: details?.exitCode,
      });
    });
  });
  const muxHome = process.env.CODEX_MUX_HOME ?? path.join(os.homedir(), ".codex-mux");
  const token = fs
    .readFileSync(path.join(muxHome, "control-token"), "utf8")
    .trim();
  const server = http.createServer(async (request, response) => {
    if (request.headers["x-codex-mux-token"] !== token) {
      writeJson(response, 401, { error: "unauthorized" });
      return;
    }
    const url = new URL(request.url, `http://${HOST}:${PORT}`);
    if (request.method !== "GET" || url.pathname !== "/v1/test/app-state") {
      writeJson(response, 404, { error: "not found" });
      return;
    }
    const action = url.searchParams.get("action");
    if (
      action !== null &&
      action !== "profile" &&
	  action !== "profile-router-open" &&
	  action !== "profile-toggle" &&
	  action !== "settings-profile" &&
	  action !== "settings-plugins" &&
	  action !== "settings-appshots" &&
	  action !== "settings-computer-use" &&
	  action !== "plugins-select-second" &&
	  action !== "usage" &&
	  action !== "usage-confirm" &&
	  action !== "usage-confirm-final" &&
	  action !== "usage-select-second" &&
	  action !== "appshots-open" &&
	  action !== "appshots-hotkey" &&
	  action !== "appshots-settings-trigger" &&
	  action !== "computer-use-details" &&
	  action !== "submit-computer-use" &&
      action !== "quota-thread" &&
      action !== "first-thread" &&
      action !== "back-to-app" &&
      action !== "submit-quota"
    ) {
      writeJson(response, 400, { error: "unsupported action" });
      return;
    }
    const delayMs = Number(url.searchParams.get("delayMs") ?? 400);
    if (!Number.isSafeInteger(delayMs) || delayMs < 0 || delayMs > 5_000) {
      writeJson(response, 400, { error: "delayMs must be between 0 and 5000" });
      return;
    }
    const includeDebug = url.searchParams.get("debug") === "1";
    try {
      writeJson(response, 200, await capture(action, delayMs, includeDebug));
    } catch (error) {
      writeJson(response, 500, { error: error.message });
    }
  });
  server.listen(PORT, HOST);
}

module.exports = { start };
