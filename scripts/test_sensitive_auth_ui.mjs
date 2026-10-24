import assert from 'node:assert/strict';
import { build } from 'esbuild';
import { JSDOM } from 'jsdom';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const root = path.resolve(import.meta.dirname, '..');
const tmp = fs.mkdtempSync(path.join(root, '.venv', 'auth-ui-'));
const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://localhost/' });
globalThis.window = dom.window;
globalThis.document = dom.window.document;
Object.defineProperty(globalThis, 'navigator', { configurable: true, value: dom.window.navigator });
globalThis.HTMLElement = dom.window.HTMLElement;
globalThis.DOMException = dom.window.DOMException;
globalThis.IS_REACT_ACT_ENVIRONMENT = true;
globalThis.fetch = async (input, init = {}) => {
  const url = String(input);
  if (url.includes('/api/user/2fa/status')) {
    if (globalThis.statusFailure) { globalThis.statusFailure = false; return new Response('fail', { status: 500 }); }
    return Response.json(globalThis.statusValue ?? { enabled: true, totp: false, passkey: true });
  }
  if (url.includes('/api/user/passkey/auth-options')) {
    globalThis.optionsRequest = JSON.parse(init.body ?? '{}');
    if (globalThis.optionsFailure) return Response.json({ code: 'INVALID_CREDENTIALS', message: 'Incorrect password' }, { status: 401 });
    return Response.json({ challengeToken: 'challenge', challenge: 'AQ', credentialIds: [], userVerification: 'preferred' });
  }
  if (url.includes('/api/user/password') || url.includes('/api/user/me')) {
    const raw = JSON.parse(init.body ?? '{}');
    globalThis.finalRequest = { url, method: init.method, body: raw };
    if (globalThis.finalResponse) return new Response(JSON.stringify(globalThis.finalResponse.body), { status: globalThis.finalResponse.status });
    return Response.json({});
  }
  throw new Error(`Unexpected fetch: ${url}`);
};
globalThis.navigator.credentials = { get: async () => { globalThis.webAuthnCalls++; if (globalThis.cancelPasskey) { globalThis.cancelPasskey = false; throw new DOMException('Cancelled', 'NotAllowedError'); } return { type: 'public-key', id: 'credential', rawId: new Uint8Array([1]).buffer, response: { clientDataJSON: new Uint8Array([1]).buffer, authenticatorData: new Uint8Array([2]).buffer, signature: new Uint8Array([3]).buffer, userHandle: null }, getClientExtensionResults: () => ({}) }; } };
globalThis.window.PublicKeyCredential = function() {};

const authAlias = `export const useAuth = () => ({ token: 'test-token', changePassword: (current, newPass, factor) => globalThis.__authService.changePassword('test-token', current, newPass, factor), deleteAccount: (password, factor) => globalThis.__authService.deleteAccount('test-token', password, factor) });`;
const languageAlias = `export const useTranslation = () => ({ t: key => ({'auth.passkey_as_2fa':'Use passkey','auth.totp_code':'Authenticator code','auth.use_backup_code':'Recovery code','auth.factor_retry':'Retry','auth.factor_status_failed':'Could not load authentication methods','auth.factor_cancelled':'Passkey cancelled','btn.save':'Save','account.delete_account':'Delete account','account.current_password':'Current password','account.new_password':'New password','account.confirm_password':'Confirm password','account.enter_password_confirm':'Enter password to confirm','pw.mismatch':'Passwords do not match','pw.too_short':'Password too short','error.generic':'Error'}[key] ?? key) });`;
const plugins = [{ name: 'external-react', setup(b) { for (const name of ['react', 'react-dom', 'lucide-react']) b.onResolve({ filter: new RegExp(`^${name}(?:/|$)`) }, args => { const base = path.join(root, 'node_modules', args.path); const file = fs.existsSync(`${base}.js`) ? `${base}.js` : fs.existsSync(path.join(base, 'index.js')) ? path.join(base, 'index.js') : path.join(base, 'dist', 'cjs', 'lucide-react.js'); return { path: pathToFileURL(file).href, external: true }; }); } }, { name: 'test-context-alias', setup(b) { b.onResolve({ filter: /\.\/contexts\/AuthContext$/ }, () => ({ path: 'auth-context', namespace: 'test' })); b.onResolve({ filter: /\.\/contexts\/LanguageContext$/ }, () => ({ path: 'language-context', namespace: 'test' })); b.onLoad({ filter: /.*/, namespace: 'test' }, args => ({ contents: args.path === 'language-context' ? languageAlias : authAlias, loader: 'js' })); } }];
// Bundle the real pages and their hook, aliasing only the context modules.
await build({ entryPoints: [path.join(root, 'src/pages/ChangePassword.tsx'), path.join(root, 'src/pages/DeleteAccount.tsx')], bundle: true, platform: 'node', format: 'esm', outdir: path.join(tmp, 'esm'), entryNames: '[name]', outExtension: { '.js': '.mjs' }, jsx: 'automatic', loader: { '.tsx': 'tsx' }, define: { 'import.meta.env.VITE_API_ORIGIN': '""' }, external: ['react', 'react-dom'], plugins });
await build({ entryPoints: [path.join(root, 'src/services/auth.ts')], bundle: true, platform: 'node', format: 'esm', outfile: path.join(tmp, 'auth.mjs'), loader: { '.ts': 'ts' }, define: { 'import.meta.env.VITE_API_ORIGIN': '""' } });
const React = await import('react');
globalThis.__authService = (await import(pathToFileURL(path.join(tmp, 'auth.mjs')))).authService;
globalThis.webAuthnCalls = 0;
const { render, fireEvent, screen, waitFor, cleanup } = await import('@testing-library/react');
const ChangePassword = (await import(pathToFileURL(path.join(tmp, 'esm/ChangePassword.mjs')))).default;
const DeleteAccount = (await import(pathToFileURL(path.join(tmp, 'esm/DeleteAccount.mjs')))).default;
let passed = 0;
let total = 0;
const testFetch = globalThis.fetch;
async function test(name, fn) {
  total++;
  try {
    await fn();
    passed++;
    console.log(`PASS ${name}`);
  } catch (error) {
    console.error(`FAIL ${name}\n${error.stack}`);
    process.exitCode = 1;
  } finally {
    cleanup();
    globalThis.fetch = testFetch;
    globalThis.finalRequest = null;
    globalThis.finalResponse = null;
    globalThis.optionsRequest = null;
    globalThis.optionsFailure = false;
    globalThis.webAuthnCalls = 0;
    globalThis.cancelPasskey = false;
    globalThis.statusValue = { enabled: true, totp: false, passkey: true };
    globalThis.statusFailure = false;
  }
}
const inputByLabel = label => screen.getByLabelText(label);
const click = label => fireEvent.click(label === 'Delete account' ? screen.getAllByRole('button', { name: label }).at(-1) : screen.getByRole('button', { name: label }));

await test('password change uses passkey and submits final payload', async () => {
  render(React.createElement(ChangePassword, { onBack() {} }));
  await screen.findByRole('button', { name: 'Use passkey' });
  assert.equal(screen.getByRole('button', { name: 'Use passkey' }).getAttribute('aria-pressed'), 'true');
  assert.equal(screen.queryByRole('textbox'), null);
  fireEvent.change(inputByLabel('Current password'), { target: { value: 'old-secret' } });
  fireEvent.change(inputByLabel('New password'), { target: { value: 'new-secret-123' } });
  fireEvent.change(inputByLabel('Confirm password'), { target: { value: 'new-secret-123' } });
  click('Save');
  await waitFor(() => assert.equal(globalThis.finalRequest?.body.newPassword, 'new-secret-123'));
  assert.equal(globalThis.webAuthnCalls, 1);
  assert.equal(globalThis.finalRequest.body.currentPassword, 'old-secret');
  assert.equal(globalThis.finalRequest.body.passkey.challengeToken, 'challenge');
  assert.deepEqual(globalThis.optionsRequest, { purpose: 'password', password: 'old-secret' });
  assert.equal(globalThis.finalRequest.body.code, undefined);
  assert.equal(globalThis.finalRequest.body.backup_code, undefined);
});
await test('delete account uses passkey and submits final payload', async () => {
  render(React.createElement(DeleteAccount, { onBack() {} }));
  await screen.findByRole('button', { name: 'Use passkey' });
  fireEvent.change(inputByLabel('Enter password to confirm'), { target: { value: 'delete-secret' } });
  click('Delete account');
  await waitFor(() => assert.equal(globalThis.finalRequest?.method, 'DELETE'));
  assert.equal(globalThis.webAuthnCalls, 1);
  assert.equal(globalThis.finalRequest.body.password, 'delete-secret');
  assert.equal(globalThis.finalRequest.body.passkey.challengeToken, 'challenge');
  assert.deepEqual(globalThis.optionsRequest, { purpose: 'delete', password: 'delete-secret' });
  assert.equal(globalThis.finalRequest.body.code, undefined);
});
await test('totp can be selected and submitted without WebAuthn', async () => {
  globalThis.statusValue = { enabled: true, totp: true, passkey: true };
  render(React.createElement(DeleteAccount, { onBack() {} }));
  await screen.findByRole('button', { name: 'Use passkey' });
  click('Authenticator code');
  fireEvent.change(screen.getByLabelText('Authenticator code'), { target: { value: '123456' } });
  fireEvent.change(inputByLabel('Enter password to confirm'), { target: { value: 'pw' } });
  click('Delete account');
  await waitFor(() => assert.equal(globalThis.finalRequest?.body.code, '123456'));
  assert.equal(globalThis.webAuthnCalls, 0);
});
await test('password changes do not repeat status fetch', async () => {
  let calls = 0;
  const original = globalThis.fetch;
  globalThis.fetch = async (...args) => { if (String(args[0]).includes('/api/user/2fa/status')) calls++; return original(...args); };
  render(React.createElement(ChangePassword, { onBack() {} }));
  await screen.findByRole('button', { name: 'Use passkey' });
  for (const val of ['o', 'ol', 'old']) fireEvent.change(inputByLabel('Current password'), { target: { value: val } });
  await new Promise(resolve => setTimeout(resolve, 30));
  assert.equal(calls, 1);
});
await test('ambiguous enabled status is an error, retry recovers', async () => {
  globalThis.statusValue = { enabled: true };
  render(React.createElement(DeleteAccount, { onBack() {} }));
  await screen.findByRole('alert');
  assert.match(screen.getByRole('alert').textContent, /Could not load/);
  globalThis.statusValue = { enabled: true, totp: false, passkey: true };
  click('Retry');
  await screen.findByRole('button', { name: 'Use passkey' });
});
await test('status fetch failure can retry', async () => {
  globalThis.statusFailure = true;
  render(React.createElement(DeleteAccount, { onBack() {} }));
  await screen.findByRole('alert');
  click('Retry');
  await screen.findByRole('button', { name: 'Use passkey' });
});
await test('cancelled passkey reports error and allows retry', async () => {
  globalThis.cancelPasskey = true;
  render(React.createElement(DeleteAccount, { onBack() {} }));
  await screen.findByRole('button', { name: 'Use passkey' });
  fireEvent.change(inputByLabel('Enter password to confirm'), { target: { value: 'pw' } });
  click('Delete account');
  await screen.findByRole('alert');
  assert.match(screen.getByRole('alert').textContent, /Passkey cancelled/);
  assert.equal(globalThis.finalRequest, null);
  click('Delete account');
  await waitFor(() => assert.ok(globalThis.finalRequest));
});
await test('server TWO_FACTOR_REQUIRED metadata renders passkey factor', async () => {
  globalThis.finalResponse = { status: 403, body: { code: 'TWO_FACTOR_REQUIRED', methods: ['passkey'], message: 'required' } };
  render(React.createElement(ChangePassword, { onBack() {} }));
  await screen.findByRole('button', { name: 'Use passkey' });
  fireEvent.change(inputByLabel('Current password'), { target: { value: 'old' } });
  fireEvent.change(inputByLabel('New password'), { target: { value: 'new-password' } });
  fireEvent.change(inputByLabel('Confirm password'), { target: { value: 'new-password' } });
  click('Save');
  await waitFor(() => assert.equal(globalThis.webAuthnCalls, 1));
  await screen.findByRole('button', { name: 'Use passkey' });
});
for (const Page of [ChangePassword, DeleteAccount]) {
  const name = Page === ChangePassword ? 'password change' : 'delete account';
  const submitLabel = Page === ChangePassword ? 'Save' : 'Delete account';
  const fillPasswords = () => {
    if (Page === ChangePassword) {
      fireEvent.change(inputByLabel('Current password'), { target: { value: 'current-password' } });
      fireEvent.change(inputByLabel('New password'), { target: { value: 'replacement-password' } });
      fireEvent.change(inputByLabel('Confirm password'), { target: { value: 'replacement-password' } });
    } else fireEvent.change(inputByLabel('Enter password to confirm'), { target: { value: 'current-password' } });
  };
  await test(`${name}: switching from TOTP to passkey removes the six-digit requirement`, async () => {
    globalThis.statusValue = { enabled: true, totp: true, passkey: true };
    render(React.createElement(Page, { onBack() {} }));
    await screen.findByRole('button', { name: 'Use passkey' });
    click('Use passkey');
    fillPasswords();
    assert.equal(screen.getByRole('button', { name: 'Use passkey' }).getAttribute('aria-pressed'), 'true');
    assert.equal(screen.queryByRole('textbox'), null);
    click(submitLabel);
    await waitFor(() => assert.ok(globalThis.finalRequest?.body.passkey));
    assert.equal(globalThis.finalRequest.body.code, undefined);
  });
  await test(`${name}: recovery code works without invoking WebAuthn`, async () => {
    render(React.createElement(Page, { onBack() {} }));
    await screen.findByRole('button', { name: 'Use passkey' });
    click('Recovery code');
    fireEvent.change(screen.getByLabelText('auth.backup_code_label'), { target: { value: 'RECOVERY-1234' } });
    fillPasswords();
    click(submitLabel);
    await waitFor(() => assert.equal(globalThis.finalRequest?.body.backup_code, 'RECOVERY-1234'));
    assert.equal(globalThis.webAuthnCalls, 0);
  });
  await test(`${name}: wrong password never reaches WebAuthn or the final operation`, async () => {
    globalThis.optionsFailure = true;
    render(React.createElement(Page, { onBack() {} }));
    await screen.findByRole('button', { name: 'Use passkey' });
    fillPasswords();
    click(submitLabel);
    await screen.findByText('Incorrect password');
    assert.equal(globalThis.finalRequest, null);
    assert.equal(globalThis.webAuthnCalls, 0);
    globalThis.optionsFailure = false;
  });
  await test(`${name}: inconsistent factor flags fail closed without inventing TOTP`, async () => {
    globalThis.statusValue = { enabled: true, totp: false, passkey: false };
    render(React.createElement(Page, { onBack() {} }));
    await screen.findByRole('alert');
    assert.equal(screen.queryByRole('button', { name: 'Authenticator code' }), null);
    fillPasswords();
    const buttons = screen.getAllByRole('button', { name: submitLabel });
    assert.equal(buttons.at(-1).disabled, true);
  });
}
console.log(`\n${passed}/${total} sensitive auth UI tests passed`);
fs.rmSync(tmp, { recursive: true, force: true });
dom.window.close();
