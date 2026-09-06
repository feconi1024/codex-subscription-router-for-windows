const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.resolve(__dirname, '../..');
const menu = fs.readFileSync(path.join(root, 'ui/account-menu.js'), 'utf8');
const bridge = fs.readFileSync(path.join(root, 'ui/ui-test-bridge.cjs'), 'utf8');

function renderer() {
  const root = { children: [{}] };
  return vm.createContext({
    location: { pathname: '/' },
    innerHeight: 800,
    document: {
      readyState: 'complete', body: { children: [root], firstElementChild: root },
      querySelector: selector => selector === '#root' ? root : null,
      querySelectorAll: () => [],
    },
  });
}

test('empty hydrated root is UNKNOWN; menu mount and cached auth cannot authenticate it', async () => {
  const context = renderer();
  vm.runInContext(menu.slice(0, menu.indexOf('async function codexMuxRequest')), context);
  const captureStart = bridge.indexOf('const STATE_CAPTURE_SCRIPT =');
  const captureEnd = bridge.indexOf('\nfunction emptyRouterFlags', captureStart);
  const capture = vm.runInContext(bridge.slice(captureStart, captureEnd) + '\nSTATE_CAPTURE_SCRIPT', vm.createContext({}));
  const readStart = bridge.indexOf('async function readDesktopAuth(');
  const readEnd = bridge.indexOf('\nfunction safeRuntimeDiagnostic', readStart);
  const reader = vm.runInNewContext(bridge.slice(readStart, readEnd) + '\nreadDesktopAuth', { safeAuthState: value => value });
  const window = { webContents: { executeJavaScript: script => vm.runInContext(script, context) } };
  for (const stale of ['AUTHENTICATED', 'AUTH_REQUIRED', 'UNKNOWN']) {
    context.__codexMuxDesktopAuth = stale;
    context.__codexMuxAuthenticatedShellReady = true;
    assert.equal(vm.runInContext('codexMuxDetectDesktopAuth()', context), 'UNKNOWN');
    context.__codexMuxDesktopAuth = stale;
    assert.equal(vm.runInContext(capture, context).desktop_auth.state, 'UNKNOWN');
    assert.equal((await reader(window)).state, 'UNKNOWN');
  }
  context.location.pathname = '/login';
  assert.equal(vm.runInContext('codexMuxDetectDesktopAuth()', context), 'AUTH_REQUIRED');
  assert.equal(vm.runInContext(capture, context).desktop_auth.state, 'AUTH_REQUIRED');
  assert.equal((await reader(window)).state, 'AUTH_REQUIRED');
});

test('native auth changes without opening menu and is cleared on host unmount', () => {
  const context = renderer();
  let cleanup;
  const ref = { current: null };
  context.kXc = {
    useRef: () => ref,
    useEffect: effect => { cleanup?.(); cleanup = effect(); },
  };
  vm.runInContext(menu.slice(0, menu.indexOf('async function codexMuxRequest')), context);
  let opens = 0;
  context.setOpen = () => { opens++; };
  context.auth = { isLoading: true, authMethod: null, requiresAuth: true };
  const renderHost = () => vm.runInContext('CodexMuxUseNativeAuth(auth, setOpen)', context);
  renderHost();
  assert.equal(context.__codexMuxDesktopAuth, 'UNKNOWN');
  // requiresAuth describes the provider requirement and remains true after login.
  context.auth = { isLoading: false, authMethod: 'chatgpt', requiresAuth: true };
  renderHost();
  assert.equal(context.__codexMuxDesktopAuth, 'AUTHENTICATED');
  assert.equal(opens, 0);
  assert.equal(context.__codexMuxAccountMenuMounted, undefined);
  context.location.pathname = '/login';
  assert.equal(vm.runInContext('codexMuxDetectDesktopAuth()', context), 'AUTH_REQUIRED');
  context.location.pathname = '/';
  context.auth = { isLoading: false, authMethod: null, requiresAuth: true, openAIAuth: null };
  renderHost();
  assert.equal(context.__codexMuxDesktopAuth, 'AUTH_REQUIRED');
  cleanup();
  assert.equal(context.__codexMuxDesktopAuth, 'UNKNOWN');
  assert.equal(context.__codexMuxProfileMenuControllerReady, false);
  assert.equal(context.__codexMuxOpenProfileMenuForTest, undefined);
});
