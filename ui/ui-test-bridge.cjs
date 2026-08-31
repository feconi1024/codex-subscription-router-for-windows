"use strict";

const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { app, BrowserWindow } = require("electron");

const HOST = "127.0.0.1";
const PORT = 48124;
const diagnostics = [];
const STARTUP_STAGES = new Set([
  "NOT_STARTED",
  "LOADER_REACHED",
  "TEST_MODE_CONFIRMED",
  "MODULE_LOAD_STARTED",
  "MODULE_LOADED",
  "START_CALLED",
  "LISTENING",
  "FAILED",
]);
const STARTUP_FAILED_STAGES = new Set(["MODULE_LOAD", "START", "CONTROL_TOKEN_READ", "LISTEN"]);
const STARTUP_ERROR_NAMES = new Set([
  "Error",
  "EvalError",
  "RangeError",
  "ReferenceError",
  "SyntaxError",
  "TypeError",
  "URIError",
]);
const STARTUP_ERROR_CODES = new Set([
  "BRIDGE_EXPORT_INVALID",
  "CONTROL_TOKEN_MISSING",
  "EADDRINUSE",
  "EACCES",
  "ENOENT",
  "EEXIST",
  "ERR_MODULE_NOT_FOUND",
  "ERR_REQUIRE_ESM",
  "MODULE_NOT_FOUND",
  "TOKEN_INVALID_FORMAT",
]);
let startupPromise = null;
let rendererEvaluationInFlight = null;
let stateCaptureInFlight = null;

// Keep the transport probe independent from renderer work. State collection is
// deliberately bounded because a navigating or suspended renderer must not
// make the main-process HTTP server appear dead.
const STATE_EVAL_TIMEOUT_MS = 3_000;
const SCREENSHOT_TIMEOUT_MS = 10_000;
const STATE_RESPONSE_STATUSES = new Set(["OK", "STATE_BUSY", "STATE_TIMEOUT", "STATE_EVALUATION_FAILED"]);

function startupStatusPath() {
  const value = process.env.CODEX_MUX_UI_BRIDGE_STATUS_PATH;
  if (typeof value !== "string" || value.length === 0 || value.length > 1000) return null;
  if (!path.isAbsolute(value)) return null;
  const resolved = path.resolve(value);
  const normalized = resolved.replaceAll("/", "\\").toLowerCase();
  if (normalized.includes("\\windowsapps\\") || normalized.endsWith("\\windowsapps")) return null;
  return resolved;
}

function safeStartupErrorName(error) {
  const name = typeof error === "string" ? error : typeof error?.name === "string" ? error.name : null;
  return STARTUP_ERROR_NAMES.has(name) ? name : "Error";
}

function safeStartupErrorCode(error) {
  const code = typeof error?.code === "string" ? error.code : null;
  return STARTUP_ERROR_CODES.has(code) ? code : null;
}

function writeStartupStatus(stage, details = {}) {
  const statusPath = startupStatusPath();
  if (!statusPath || !STARTUP_STAGES.has(stage)) return false;
  const status = { schema_version: 1, stage };
  if (stage === "FAILED") {
    const failedStage = details.failed_stage;
    if (STARTUP_FAILED_STAGES.has(failedStage)) status.failed_stage = failedStage;
    status.error_name = safeStartupErrorName(details.error ?? details.error_name);
    const errorCode = details.error_code ?? safeStartupErrorCode(details.error);
    if (STARTUP_ERROR_CODES.has(errorCode)) status.error_code = errorCode;
    const token = details.control_token;
    if (token && typeof token === "object") {
      status.control_token = {
        exists: token.exists === true,
        readable: token.readable === true,
        valid_format: token.valid_format === true,
      };
    }
  }
  try {
    fs.writeFileSync(statusPath, `${JSON.stringify(status)}\n`, "utf8");
    return true;
  } catch {
    return false;
  }
}

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

function boundedPromise(promise, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      resolve({ ok: false, status: "TIMEOUT" });
    }, timeoutMs);
    Promise.resolve(promise).then(
      (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({ ok: true, value });
      },
      () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({ ok: false, status: "FAILED" });
      },
    );
  });
}

function executeRendererBounded(window, script, timeoutMs = STATE_EVAL_TIMEOUT_MS) {
  if (rendererEvaluationInFlight !== null) {
    return Promise.resolve({ ok: false, status: "STATE_BUSY" });
  }
  const raw = Promise.resolve().then(() => window.webContents.executeJavaScript(script));
  const tracked = raw.then(
    (value) => ({ ok: true, value }),
    () => ({ ok: false, status: "STATE_EVALUATION_FAILED" }),
  );
  rendererEvaluationInFlight = tracked;
  tracked.then(() => {
    if (rendererEvaluationInFlight === tracked) rendererEvaluationInFlight = null;
  });
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      resolve({ ok: false, status: "STATE_TIMEOUT" });
    }, timeoutMs);
    tracked.then((result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    });
  });
}

const STATE_CAPTURE_SCRIPT = `(() => {
  const authStates = new Set(['AUTHENTICATED','AUTH_REQUIRED','UNKNOWN']);
  const safeAuth = value => authStates.has(value) ? value : 'UNKNOWN';
  const safeCount = value => Number.isSafeInteger(value) && value >= 0 ? value : 0;
  const safeSource = value => {
    if (typeof value !== 'string') return null;
    const pieces = value.split(/[\\\\/]/);
    const basename = pieces[pieces.length - 1] || '';
    return basename.length > 0 && basename.length <= 200 ? basename : null;
  };
  const safeError = value => {
    if (!value || typeof value !== 'object') return null;
    const kinds = new Set(['error','unhandledrejection','render-process-gone']);
    const names = new Set(['Error','EvalError','RangeError','ReferenceError','SyntaxError','TypeError','URIError']);
    const item = {
      kind: kinds.has(value.kind) ? value.kind : 'error',
      name: names.has(value.name) ? value.name : 'Error',
      source_asset: safeSource(value.source_asset),
      line: safeCount(value.line),
      column: safeCount(value.column),
    };
    if (item.kind === 'render-process-gone') {
      const reasons = new Set(['clean-exit','abnormal-exit','crashed','killed','oom','launch-failed']);
      item.reason = reasons.has(value.reason) ? value.reason : 'unknown';
      item.exit_code = safeCount(value.exit_code);
    }
    return item;
  };
  const state = globalThis.__codexMuxAccountMenuState ?? {};
  const savedRuntime = globalThis.__codexMuxRendererRuntime ?? {};
  const body = document.body;
  const root = document.querySelector('#root') || body?.firstElementChild || null;
  const composer = document.querySelector('textarea[placeholder],[contenteditable="true"]');
  let visible = 0;
  for (const element of document.querySelectorAll('button,a,input,textarea,[role="button"],[contenteditable="true"]')) {
    const rect = element.getBoundingClientRect();
    if (rect.width > 0 && rect.height > 0) visible++;
  }
  const pathname = typeof globalThis.location?.pathname === 'string' ? globalThis.location.pathname.toLowerCase() : '';
  const authRoute = /(^|\\/)(auth|login|signin|sign-in)(\\/|$)/.test(pathname);
  const controller = globalThis.__codexMuxProfileMenuControllerReady === true || savedRuntime.profileControllerReady === true;
  let detected = 'UNKNOWN';
  if (authRoute) detected = 'AUTH_REQUIRED';
  else if (globalThis.__codexMuxAuthenticatedShellReady === true || (composer && controller)) detected = 'AUTHENTICATED';
  else if (document.readyState === 'complete' && root && !composer && !controller) detected = 'AUTH_REQUIRED';
  const savedAuth = safeAuth(globalThis.__codexMuxDesktopAuth);
  const errors = Array.isArray(globalThis.__codexMuxRuntimeErrors) ? globalThis.__codexMuxRuntimeErrors : [];
  const readyState = ['loading','interactive','complete'].includes(document.readyState) ? document.readyState : 'unknown';
  const describe = element => {
    const rect = element.getBoundingClientRect();
    const label = element.getAttribute('aria-label');
    const allowedLabel = label === 'Open profile menu' || /^Show (combined )?profile stats$/.test(label || '') ? label : null;
    return {
      ariaLabel: allowedLabel,
      disabled: element.disabled === true,
      type: typeof element.type === 'string' ? element.type : null,
      rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
    };
  };
  const runtime = {
    readyState,
    rootPresent: root !== null,
    rootChildCount: safeCount(savedRuntime.rootChildCount || root?.children?.length),
    bodyChildCount: safeCount(savedRuntime.bodyChildCount || body?.children?.length),
    buttonCount: safeCount(savedRuntime.buttonCount || document.querySelectorAll('button').length),
    visibleInteractiveCount: safeCount(savedRuntime.visibleInteractiveCount || visible),
    composerPresent: composer !== null,
    profileControllerReady: controller,
    runtimeErrorCount: errors.length,
    lastSafeRuntimeError: safeError(errors.at(-1)),
  };
  return {
    state_status: 'OK',
    router: {
      rendererPatchLoaded: globalThis.__codexMuxRendererPatchLoaded === true,
      accountMenuInjected: globalThis.__codexMuxAccountMenuInjected === true,
      accountMenuMounted: globalThis.__codexMuxAccountMenuMounted === true,
      accountsLoaded: state.accountsLoaded === true,
      accountCount: safeCount(state.accountCount),
      requestFailed: state.requestFailed === true,
    },
    desktop_auth: { state: detected !== 'UNKNOWN' ? detected : savedAuth },
    renderer_runtime: runtime,
    profile_controller: {
      ready: globalThis.__codexMuxProfileMenuControllerReady === true,
      activationAttempted: globalThis.__codexMuxProfileMenuActivationAttempted === true,
      activationSucceeded: globalThis.__codexMuxProfileMenuActivationSucceeded === true,
    },
    runtime_errors: errors.slice(-20).map(safeError).filter(Boolean),
    readyState,
    composer: composer ? describe(composer) : null,
    buttons: [...document.querySelectorAll('button')]
      .filter(button => {
        const rect = button.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0 && rect.bottom > innerHeight - 180;
      })
      .map(describe),
  };
})()`;

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

async function requestGracefulDesktopQuit() {
  const window = await observationWindow();
  if (!window) return { ok: false, status: "NO_WINDOW" };
  const auth = await readDesktopAuth(window);
  if (auth.state !== "AUTHENTICATED") {
    return { ok: false, status: auth.state };
  }
  return { ok: true, status: "QUIT_REQUESTED" };
}

function emptyStateDebug() {
  return {
    readyState: "unknown",
    composer: null,
    buttons: [],
    router: emptyRouterFlags(),
    desktop_auth: { state: "UNKNOWN" },
    renderer_runtime: null,
    profile_controller: { ready: false, activationAttempted: false, activationSucceeded: false },
    runtime_errors: [],
    termination: null,
    windows: [],
  };
}

function safeRect(value) {
  if (!value || typeof value !== "object") return null;
  const result = {};
  for (const key of ["x", "y", "width", "height"]) {
    if (typeof value[key] === "number" && Number.isFinite(value[key])) result[key] = value[key];
  }
  return Object.keys(result).length === 4 ? result : null;
}

function safeElementDescription(value) {
  if (!value || typeof value !== "object") return null;
  const label = value.ariaLabel;
  return {
    ariaLabel:
      label === "Open profile menu" || /^Show (combined )?profile stats$/.test(label || "")
        ? label
        : null,
    disabled: value.disabled === true,
    type: typeof value.type === "string" ? value.type : null,
    rect: safeRect(value.rect),
  };
}

function safeStateSnapshot(raw) {
  const stateStatus = raw?.state_status;
  const status = STATE_RESPONSE_STATUSES.has(stateStatus) ? stateStatus : "STATE_EVALUATION_FAILED";
  const debug = emptyStateDebug();
  if (!raw || typeof raw !== "object") return { state_status: status, debug };
  if (["loading", "interactive", "complete", "unknown"].includes(raw.readyState)) {
    debug.readyState = raw.readyState;
  }
  debug.composer = safeElementDescription(raw.composer);
  if (Array.isArray(raw.buttons)) {
    debug.buttons = raw.buttons.map(safeElementDescription).filter(Boolean).slice(-100);
  }
  const router = raw.router;
  if (router && typeof router === "object") {
    debug.router = {
      rendererPatchLoaded: router.rendererPatchLoaded === true,
      accountMenuInjected: router.accountMenuInjected === true,
      accountMenuMounted: router.accountMenuMounted === true,
      accountsLoaded: router.accountsLoaded === true,
      accountCount: safeInteger(router.accountCount) ?? 0,
      requestFailed: router.requestFailed === true,
    };
  }
  const authState = raw.desktop_auth?.state;
  debug.desktop_auth = { state: authState === "AUTHENTICATED" || authState === "AUTH_REQUIRED" || authState === "UNKNOWN" ? authState : "UNKNOWN" };
  const runtime = raw.renderer_runtime;
  if (runtime && typeof runtime === "object") {
    debug.renderer_runtime = {
      readyState: ["loading", "interactive", "complete", "unknown"].includes(runtime.readyState) ? runtime.readyState : "unknown",
      rootPresent: runtime.rootPresent === true,
      rootChildCount: safeInteger(runtime.rootChildCount) ?? 0,
      bodyChildCount: safeInteger(runtime.bodyChildCount) ?? 0,
      buttonCount: safeInteger(runtime.buttonCount) ?? 0,
      visibleInteractiveCount: safeInteger(runtime.visibleInteractiveCount) ?? 0,
      composerPresent: runtime.composerPresent === true,
      profileControllerReady: runtime.profileControllerReady === true,
      runtimeErrorCount: safeInteger(runtime.runtimeErrorCount) ?? 0,
      lastSafeRuntimeError: safeRuntimeDiagnostic(runtime.lastSafeRuntimeError),
    };
  }
  const controller = raw.profile_controller;
  if (controller && typeof controller === "object") {
    debug.profile_controller = {
      ready: controller.ready === true,
      activationAttempted: controller.activationAttempted === true,
      activationSucceeded: controller.activationSucceeded === true,
    };
  }
  if (Array.isArray(raw.runtime_errors)) {
    debug.runtime_errors = raw.runtime_errors
      .map(safeRuntimeDiagnostic)
      .filter(Boolean)
      .slice(-20);
  }
  return { state_status: status, debug };
}

function safeContentBounds(window) {
  try {
    const bounds = window.getContentBounds();
    return safeRect(bounds);
  } catch {
    return safeBounds(window);
  }
}

function stateFallback(status) {
  return { state_status: status, debug: emptyStateDebug() };
}

async function captureStateInternal(action, delayMs, includeDebug) {
  let window = mainWindow();
  if (!window) throw new Error("Codex Subscription Router has no main window");
  if (action !== null) await runAction(window, action, delayMs);
  window = mainWindow() ?? window;
  const evaluated = await executeRendererBounded(window, STATE_CAPTURE_SCRIPT);
  const snapshot = evaluated.ok ? safeStateSnapshot(evaluated.value) : stateFallback(evaluated.status);
  const result = {
    bounds: safeContentBounds(window),
    state_status: snapshot.state_status,
  };
  if (includeDebug) {
    result.debug = snapshot.debug;
    result.debug.url = safeUrl(window);
    result.debug.termination = null;
    result.debug.windows = [
      {
        webContentsId: safeWebContentsId(window),
        visible: safeVisible(window),
        bounds: safeBounds(window),
        isLoading: safeLoading(window),
        url: safeUrl(window),
        rendererPatchLoaded: result.debug.router.rendererPatchLoaded,
        accountMenuInjected: result.debug.router.accountMenuInjected,
        desktopAuth: result.debug.desktop_auth.state,
      },
    ];
    result.diagnostics = diagnostics.slice(-50);
  }
  return result;
}

async function captureState(action, delayMs, includeDebug) {
  if (stateCaptureInFlight !== null) return stateFallback("STATE_BUSY");
  const operation = captureStateInternal(action, delayMs, includeDebug);
  stateCaptureInFlight = operation;
  try {
    return await operation;
  } finally {
    if (stateCaptureInFlight === operation) {
      if (rendererEvaluationInFlight !== null) {
        const pendingEvaluation = rendererEvaluationInFlight;
        pendingEvaluation.then(() => {
          if (stateCaptureInFlight === operation) stateCaptureInFlight = null;
        });
      } else {
        stateCaptureInFlight = null;
      }
    }
  }
}

async function captureScreenshot(action, delayMs, includeDebug) {
  let window = mainWindow();
  if (!window) throw new Error("Codex Subscription Router has no main window");
  if (action !== null) await runAction(window, action, delayMs);
  window = mainWindow() ?? window;
  const captured = await boundedPromise(window.webContents.capturePage(), SCREENSHOT_TIMEOUT_MS);
  if (!captured.ok) throw new Error("screenshot capture timed out");
  const result = {
    bounds: safeContentBounds(window),
    imageBase64: captured.value.toPNG().toString("base64"),
  };
  if (includeDebug) {
    const snapshot = await captureStateSnapshotForScreenshot(window);
    result.debug = snapshot.debug;
  }
  return result;
}

async function captureStateSnapshotForScreenshot(window) {
  const evaluated = await executeRendererBounded(window, STATE_CAPTURE_SCRIPT);
  return evaluated.ok ? safeStateSnapshot(evaluated.value) : stateFallback(evaluated.status);
}

function readControlToken(muxHome) {
  const result = { exists: false, readable: false, valid_format: false };
  const tokenPath = path.join(muxHome, "control-token");
  try {
    result.exists = fs.existsSync(tokenPath);
    if (!result.exists) {
      const error = new Error("control token is missing");
      error.code = "CONTROL_TOKEN_MISSING";
      throw error;
    }
    const token = fs.readFileSync(tokenPath, "utf8").trim();
    result.readable = true;
    result.valid_format = /^[0-9a-f]{64}$/i.test(token);
    if (!result.valid_format) {
      const error = new Error("control token format is invalid");
      error.code = "TOKEN_INVALID_FORMAT";
      throw error;
    }
    return { token, result };
  } catch (error) {
    writeStartupStatus("FAILED", {
      failed_stage: "CONTROL_TOKEN_READ",
      error,
      control_token: result,
    });
    throw error;
  }
}

function start() {
  if (process.env.CODEX_MUX_UI_TESTS !== "1") {
    writeStartupStatus("NOT_STARTED");
    return Promise.resolve({ stage: "NOT_STARTED" });
  }
  if (startupPromise !== null) return startupPromise;
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
  let token;
  try {
    token = readControlToken(muxHome).token;
  } catch (error) {
    return Promise.reject(error);
  }
  const server = http.createServer(async (request, response) => {
    if (request.headers["x-codex-mux-token"] !== token) {
      writeJson(response, 401, { error: "unauthorized" });
      return;
    }
    const url = new URL(request.url, `http://${HOST}:${PORT}`);
    if (request.method === "GET" && url.pathname === "/v1/test/ping") {
      // This endpoint must remain main-process-only. In particular, do not
      // inspect BrowserWindow or touch renderer/credential state here.
      writeJson(response, 200, { ok: true });
      return;
    }
    const isAppState = request.method === "GET" && url.pathname === "/v1/test/app-state";
    const isScreenshot = request.method === "GET" && url.pathname === "/v1/test/screenshot";
    if (!isAppState && !isScreenshot) {
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
      action !== "desktop-auth-graceful-quit" &&
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
      if (action === "desktop-auth-graceful-quit") {
        const outcome = await requestGracefulDesktopQuit();
        if (!outcome.ok) {
          writeJson(response, 409, outcome);
          return;
        }
        writeJson(response, 200, outcome);
        // Let the HTTP response flush before requesting Electron's normal
        // shutdown path. This is deliberately app.quit(), never a process kill.
        setImmediate(() => {
          try {
            app.quit();
          } catch {}
        });
        return;
      }
      writeJson(
        response,
        200,
        isScreenshot
          ? await captureScreenshot(action, delayMs, includeDebug)
          : await captureState(action, delayMs, includeDebug),
      );
    } catch {
      writeJson(response, 500, { error: "internal error" });
    }
  });
  startupPromise = new Promise((resolve, reject) => {
    let settled = false;
    server.once("listening", () => {
      writeStartupStatus("LISTENING");
      settled = true;
      resolve({ stage: "LISTENING" });
    });
    server.once("error", (error) => {
      if (settled) return;
      settled = true;
      writeStartupStatus("FAILED", { failed_stage: "LISTEN", error });
      reject(error);
    });
    try {
      server.listen(PORT, HOST);
    } catch (error) {
      if (settled) return;
      settled = true;
      writeStartupStatus("FAILED", { failed_stage: "LISTEN", error });
      reject(error);
    }
  });
  return startupPromise;
}

module.exports = { start };
