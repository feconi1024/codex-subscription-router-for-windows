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

test('profile plan and native edit controls follow the selected account', () => {
  const context = renderer();
  context.kXc = { useState: init => [init(), () => {}], useEffect: () => {} };
  context.e7 = { jsx: (type, props) => ({ type, props }) };
  // The production helper is in an ES module: its local component names are
  // distinct from the same-named global lazy-chunk factories.
  vm.runInContext(menu.slice(0, menu.indexOf('globalThis.CodexMuxAccountAvatar =')), context);
  context.__codexMuxCombinedProfileAccounts = [
    { id: 'primary', planLabel: 'Plus' }, { id: 'secondary', planLabel: 'Free' },
  ];
  for (const [selected, expected, editable] of [[null, 'Combined profile', false], ['secondary', 'Free', false], ['primary', 'Plus', true]]) {
    context.__codexMuxSelectedProfileAccountId = selected;
    assert.equal(vm.runInContext('CodexMuxProfilePlanBadge().props.children', context), expected);
    assert.equal(vm.runInContext('CodexMuxProfileActions({children:"edit"})', context), editable ? 'edit' : null);
  }
});

test('successful reset redemption refreshes the account selector without retrying the redemption', async () => {
  const context = renderer();
  const events = [];
  context.Event = class { constructor(type) { this.type = type; } };
  context.dispatchEvent = event => events.push(event.type);
  vm.runInContext(menu, context);
  let requests = 0;
  context.result = {code: 'reset'};
  context.request = async () => { requests++; return context.result; };
  vm.runInContext('codexMuxRequest = request', context);
  for (const code of ['reset', 'already_redeemed', 'no_credit']) {
    context.result = {code};
    assert.equal((await vm.runInContext('codexMuxConsumeRateLimitReset("secondary", {redeemRequestId:"test"})', context)).code, code);
  }
  assert.equal(requests, 3);
  assert.deepEqual(events, ['codex-mux-reset-updated', 'codex-mux-reset-updated']);
});

test('cached selector independently loads and refreshes counts, ignoring late responses', async () => {
  const context = renderer();
  const listeners = new Map();
  let effect, cleanup, counts, updates = 0;
  context.kXc = {
    useState: initial => [initial, value => { counts = value; updates++; }],
    useEffect: callback => { effect = callback; },
  };
  context.e7 = { jsx: (type, props) => ({type, props}), jsxs: (type, props) => ({type, props}) };
  context.addEventListener = (name, callback) => listeners.set(name, callback);
  context.removeEventListener = name => listeners.delete(name);
  const pending = [];
  context.request = () => new Promise(resolve => pending.push(resolve));
  vm.runInContext(menu, context);
  vm.runInContext('codexMuxRateLimitResets = request; CodexMuxResetAccountSelector({accounts:[{id:"secondary"}],loading:false,selectedId:"secondary",onSelect:()=>{}})', context);
  cleanup = effect();
  // The parent never renders again, as with the native memoized heading.
  const refresh = listeners.get('codex-mux-reset-updated');
  const redemptionRefresh = refresh();
  pending[1]({available_count: 0});
  await redemptionRefresh;
  assert.equal(counts.secondary, 0);
  pending[0]({available_count: 1});
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(counts.secondary, 0);
  const afterUnmount = refresh();
  cleanup();
  pending[2]({available_count: 9});
  await afterUnmount;
  assert.equal(updates, 1);
  assert.equal(listeners.has('codex-mux-reset-updated'), false);
});

test('only recognized depletion errors are exposed by the pending-task adapter', () => {
  const context = renderer();
  vm.runInContext(menu, context);
  const unknownReset = 'All connected subscriptions are depleted. Add another subscription or wait for usage to reset.';
  const knownReset = 'All connected subscriptions are depleted. Usage resets on Monday, 7 September at 8:30 PM.';
  for (const value of [unknownReset, knownReset]) {
    assert.equal(context.codexMuxDepletionMessage(value), value);
    assert.equal(context.codexMuxDepletionMessage({message: value}), value);
  }
  for (const value of [null, {}, {message: 'private backend details'}, 'All connected subscriptions are depleted.\nprivate data', 'All connected subscriptions are depleted. Unexpected data']) {
    assert.equal(context.codexMuxDepletionMessage(value), null);
  }
});

test('leaving a secondary profile refreshes the shared native profile cache', () => {
  const context = renderer();
  const cleanups = [];
  context.kXc = {
    useState: init => [typeof init === 'function' ? init() : init, () => {}],
    useEffect: effect => { cleanups.push(effect()); },
  };
  vm.runInContext(menu.slice(0, menu.indexOf('globalThis.CodexMuxAccountAvatar =')), context);
  vm.runInContext('codexMuxRequest = () => new Promise(() => {}); codexMuxPublishProfileSelection = id => { globalThis.__codexMuxSelectedProfileAccountId = id; };', context);
  const selections = [];
  context.onSelect = () => selections.push(context.__codexMuxSelectedProfileAccountId);
  vm.runInContext('CodexMuxProfileAvatarStack({onSelect})', context);
  context.__codexMuxSelectedProfileAccountId = 'secondary';
  for (const cleanup of cleanups) cleanup?.();
  assert.equal(context.__codexMuxSelectedProfileAccountId, null);
  assert.deepEqual(selections, [null, null]);
});

test('switching plugin scope cancels old requests before clearing connection caches', async () => {
  const context = renderer();
  vm.runInContext(menu, context);
  const calls = [];
  context.__codexMuxPluginAccountId = 'primary';
  context.client = {
    cancelQueries: async filter => {
      assert.equal(context.__codexMuxPluginAccountId, 'primary');
      for (const root of ['apps', 'plugins', 'mcp']) assert.equal(filter.predicate({queryKey: [root]}), true);
      assert.equal(filter.predicate({queryKey: ['threads']}), false);
      calls.push('cancel');
    },
    resetQueries: async () => {
      assert.equal(context.__codexMuxPluginAccountId, 'secondary');
      calls.push('reset');
    },
  };
  await vm.runInContext('codexMuxChangePluginScope(client, "secondary")', context);
  assert.deepEqual(calls, ['cancel', 'reset']);
});
