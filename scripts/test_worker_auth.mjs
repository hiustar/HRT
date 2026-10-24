// Runtime auth regression tests: node --experimental-sqlite scripts/test_worker_auth.mjs
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createHash, createHmac, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';
import bcrypt from 'bcryptjs';
import { SignJWT, jwtVerify } from 'jose';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const origin = 'https://auth.example.test';
const password = 'Original-Password-427!';
const newPassword = 'Replacement-Password-593!';
const secret = randomBytes(48).toString('hex');
const passwordHash = await bcrypt.hash(password, 10);
const digest = value => createHash('sha256').update(value).digest();
const tokenHash = value => digest(value).toString('hex');
const b64 = value => Buffer.from(value).toString('base64url');
const tests = [];
const test = (name, run) => tests.push({ name, run });
const migrations = await Promise.all((await readdir(join(root, 'migrations')))
  .filter(name => name.endsWith('.sql')).sort()
  .map(async name => ({ name, sql: await readFile(join(root, 'migrations', name), 'utf8') })));

class D1 {
  constructor() {
    this.sqlite = new DatabaseSync(':memory:');
    this.sqlite.exec('PRAGMA foreign_keys = ON');
    for (const migration of migrations) this.sqlite.exec(migration.sql);
  }
  prepare(sql) {
    const sqlite = this.sqlite;
    const make = values => ({
      bind: (...args) => make(args),
      first: async column => {
        const row = sqlite.prepare(sql).get(...values);
        return row ? (column === undefined ? { ...row } : row[column]) : null;
      },
      all: async () => ({ success: true, results: sqlite.prepare(sql).all(...values).map(row => ({ ...row })) }),
      run: async () => {
        const result = sqlite.prepare(sql).run(...values);
        return { success: true, results: [], meta: { changes: Number(result.changes), last_row_id: Number(result.lastInsertRowid) } };
      },
    });
    return make([]);
  }
  async batch(statements) {
    this.sqlite.exec('BEGIN TRANSACTION');
    try {
      const results = [];
      for (const statement of statements) results.push(await statement.run());
      this.sqlite.exec('COMMIT');
      return results;
    } catch (error) {
      this.sqlite.exec('ROLLBACK');
      throw error;
    }
  }
  close() { this.sqlite.close(); }
}

function totp(secretBytes, step = Math.floor(Date.now() / 30000)) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac('sha1', secretBytes).update(counter).digest();
  return String((mac.readUInt32BE(mac.at(-1) & 15) & 0x7fffffff) % 1000000).padStart(6, '0');
}
function base32(bytes) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const byte of bytes) bits += byte.toString(2).padStart(8, '0');
  return bits.match(/.{1,5}/g).map(chunk => alphabet[parseInt(chunk.padEnd(5, '0'), 2)]).join('');
}
function expect(response, status = 200, code) {
  assert.equal(response.status, status, JSON.stringify(response.body));
  if (code) assert.equal(response.body.code, code, JSON.stringify(response.body));
  if (status >= 400) assert.equal(response.body.token, undefined);
  return response.body;
}

let worker;
async function fixture() {
  const db = new D1();
  const deletedAvatars = [];
  const pending = [];
  const env = {
    DB: db, JWT_SECRET: secret,
    ASSETS: { fetch: async () => new Response('asset') },
    AVATAR_BUCKET: { delete: async key => { deletedAvatars.push(key); } },
  };
  for (const limit of [10, 20, 30, 60, 300]) env[`RL_PER_MINUTE_${limit}`] = { limit: async () => ({ success: true }) };
  const ctx = { waitUntil: promise => pending.push(promise) };
  async function api(path, body, token, method = 'POST') {
    const response = await worker.fetch(new Request(`${origin}${path}`, {
      method, headers: { Origin: origin, 'Content-Type': 'application/json', 'CF-Connecting-IP': '192.0.2.1',
        ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }), env, ctx);
    const text = await response.text();
    let parsed;
    try { parsed = JSON.parse(text); } catch { parsed = text; }
    return { status: response.status, body: parsed, headers: response.headers };
  }
  async function user({ pk = false, otp = false, counter = 0 } = {}) {
    const id = randomUUID();
    const username = `u${id.replaceAll('-', '').slice(0, 20)}`;
    await db.prepare('INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)').bind(id, username, passwordHash).run();
    const login = expect(await api('/api/login', { username, password }));
    const second = expect(await api('/api/login', { username, password }));
    const u = { id, username, token: login.token, token2: second.token };
    if (pk) {
      const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const jwk = pair.publicKey.export({ format: 'jwk' });
      Object.assign(u, { privateKey: pair.privateKey, credentialId: b64(randomBytes(32)), keyId: randomUUID() });
      await db.prepare('INSERT INTO passkeys (id, user_id, credential_id, public_key_x, public_key_y, counter) VALUES (?, ?, ?, ?, ?, ?)')
        .bind(u.keyId, id, u.credentialId, jwk.x, jwk.y, counter).run();
    }
    if (otp) {
      u.otpBytes = randomBytes(20);
      await db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').bind(base32(u.otpBytes), id).run();
    }
    return u;
  }
  async function options(u, purpose, token = u.token) {
    const response = purpose === 'direct'
      ? await api('/api/auth/passkey-options', { username: u.username })
      : purpose === 'login'
        ? await api('/api/auth/passkey-options', { username: u.username, password, purpose })
        : await api('/api/user/passkey/auth-options', { purpose, password }, token);
    const result = expect(response);
    assert.equal(result.userVerification, purpose === 'direct' ? 'required' : 'preferred');
    assert.ok(result.credentialIds.includes(u.credentialId));
    assert.equal(result.rpId, new URL(origin).hostname);
    assert.equal(Buffer.from(result.challengeToken, 'base64url').length, 32);
    const stored = await db.prepare('SELECT * FROM auth_challenges WHERE token_hash = ?').bind(tokenHash(result.challengeToken)).first();
    assert.ok(stored);
    assert.ok(!stored.payload_json.includes(result.challengeToken));
    return result;
  }
  function proof(u, opts, { flags = 5, count = 0, client = {}, rp = new URL(origin).hostname, signer = u.privateKey } = {}) {
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: opts.challenge, origin, ...client }));
    const authData = Buffer.alloc(37);
    digest(rp).copy(authData);
    authData[32] = flags;
    authData.writeUInt32BE(count, 33);
    const signature = sign('sha256', Buffer.concat([authData, digest(clientData)]), signer);
    return { challengeToken: opts.challengeToken, credential: { id: u.credentialId, type: 'public-key', response: {
      clientDataJSON: b64(clientData), authenticatorData: b64(authData), signature: b64(signature),
    } } };
  }
  async function submit(u, purpose, passkey, token = u.token, overrides = {}) {
    if (purpose === 'direct') return api('/api/auth/passkey-verify', passkey);
    if (purpose === 'login') return api('/api/login', { username: u.username, password, passkey, ...overrides });
    if (purpose === 'password') return api('/api/user/password', { currentPassword: password, newPassword, passkey, ...overrides }, token);
    return api('/api/user/me', { password, passkey, ...overrides }, token, 'DELETE');
  }
  return { db, api, user, options, proof, submit, deletedAvatars,
    close: async () => { try { await Promise.all(pending); } finally { db.close(); } } };
}

// Each case owns its users, clock-sensitive TOTP state, and in-memory database.
test('D1 batch rolls back every statement on failure', async f => {
  await assert.rejects(f.db.batch([
    f.db.prepare("INSERT INTO users (id, username, password_hash) VALUES ('rollback', 'rollback', 'hash')"),
    f.db.prepare('INSERT INTO nonexistent_table VALUES (1)'),
  ]));
  assert.equal(await f.db.prepare("SELECT id FROM users WHERE id = 'rollback'").first(), null);
});
test('no factor: password login issues a real usable session JWT', async f => {
  const u = await f.user();
  const body = expect(await f.api('/api/login', { username: u.username, password }));
  const { payload } = await jwtVerify(body.token, new TextEncoder().encode(secret));
  assert.equal(payload.sub, u.id);
  assert.ok(payload.sid);
  expect(await f.api('/api/user/2fa/status', undefined, body.token, 'GET'));
  expect(await f.api('/api/login', { username: u.username, password: 'wrong' }), 401, 'INVALID_CREDENTIALS');
});
for (const otp of [false, true]) {
  test(`${otp ? 'TOTP + passkey' : 'passkey only'}: password alone cannot log in`, async f => {
    const u = await f.user({ pk: true, otp });
    const body = expect(await f.api('/api/login', { username: u.username, password }), 401, 'TWO_FACTOR_REQUIRED');
    assert.equal(body.needs2FA, true);
    assert.deepEqual(body.methods, otp ? ['totp', 'passkey'] : ['passkey']);
    assert.equal(body.method, body.methods[0]);
  });
}
for (const method of ['totp', 'passkey']) {
  test(`TOTP + passkey: ${method} alone satisfies the second factor`, async f => {
    const u = await f.user({ pk: true, otp: true });
    const factor = method === 'totp' ? { totp_code: totp(u.otpBytes) }
      : { passkey: f.proof(u, await f.options(u, 'login'), { flags: 1 }) };
    const body = expect(await f.api('/api/login', { username: u.username, password, ...factor }));
    assert.equal(body.user.id, u.id);
  });
}
test('login-purpose options require the correct account password', async f => {
  const u = await f.user({ pk: true });
  expect(await f.api('/api/auth/passkey-options', { purpose: 'login', username: u.username }), 400, 'INVALID_REQUEST');
  expect(await f.api('/api/auth/passkey-options', { purpose: 'login', username: u.username, password: 'wrong' }), 401, 'INVALID_CREDENTIALS');
  expect(await f.api('/api/auth/passkey-options', { purpose: 'login', password }), 400, 'INVALID_REQUEST');
  assert.equal((await f.db.prepare('SELECT COUNT(*) AS n FROM auth_challenges').first()).n, 0);
});
test('direct login requires UV; password-bound login accepts UP without UV', async f => {
  const u = await f.user({ pk: true });
  expect(await f.submit(u, 'direct', f.proof(u, await f.options(u, 'direct'), { flags: 1 })), 401, 'INVALID_CREDENTIALS');
  expect(await f.submit(u, 'direct', f.proof(u, await f.options(u, 'direct'))));
  expect(await f.submit(u, 'login', f.proof(u, await f.options(u, 'login'), { flags: 1 })));
});
test('unknown named account cannot fall back to another discoverable credential', async f => {
  const u = await f.user({ pk: true });
  const opts = expect(await f.api('/api/auth/passkey-options', { username: `missing${randomBytes(6).toString('hex')}` }));
  assert.deepEqual(opts.credentialIds, []);
  expect(await f.submit(u, 'direct', f.proof(u, opts)), 401, 'INVALID_CREDENTIALS');
});
test('failed signature consumes the challenge even when retried with a valid signature', async f => {
  const u = await f.user({ pk: true });
  const other = await f.user({ pk: true });
  const opts = await f.options(u, 'direct');
  expect(await f.submit(u, 'direct', f.proof(u, opts, { signer: other.privateKey })), 401, 'INVALID_CREDENTIALS');
  expect(await f.submit(u, 'direct', f.proof(u, opts)), 401, 'INVALID_CREDENTIALS');
});
test('discoverable direct login without username accepts a UV assertion', async f => {
  const u = await f.user({ pk: true });
  const opts = expect(await f.api('/api/auth/passkey-options', {}));
  assert.deepEqual(opts.credentialIds, []);
  const body = expect(await f.submit(u, 'direct', f.proof(u, opts)));
  assert.equal(body.user.id, u.id);
});
for (const from of ['direct', 'login', 'password', 'delete']) {
  for (const to of ['direct', 'login', 'password', 'delete']) {
    if (from === to) continue;
    test(`purpose isolation: ${from} proof cannot authorize ${to}`, async f => {
      const u = await f.user({ pk: true });
      const passkey = f.proof(u, await f.options(u, from));
      expect(await f.submit(u, to, passkey), 401, to === 'direct' ? 'INVALID_CREDENTIALS' : 'TWO_FACTOR_INVALID');
      assert.equal((await f.db.prepare('SELECT password_hash FROM users WHERE id = ?').bind(u.id).first()).password_hash, passwordHash);
      assert.equal(await f.db.prepare('SELECT token_hash FROM auth_challenges WHERE token_hash = ?').bind(tokenHash(passkey.challengeToken)).first(), null);
    });
  }
}
for (const purpose of ['direct', 'login', 'password', 'delete']) {
  test(`${purpose}: challenge and credential are account-bound`, async f => {
    const a = await f.user({ pk: true });
    const b = await f.user({ pk: true });
    const opts = await f.options(a, purpose);
    expect(await f.submit(a, purpose, f.proof(b, opts)), 401, purpose === 'direct' ? 'INVALID_CREDENTIALS' : 'TWO_FACTOR_INVALID');
    if (purpose !== 'direct') {
      const ownProof = f.proof(a, await f.options(a, purpose));
      expect(await f.submit(b, purpose, ownProof), 401, 'TWO_FACTOR_INVALID');
    }
  });
}
for (const purpose of ['password', 'delete']) {
  test(`${purpose}: proof is session-bound, password and factor both required`, async f => {
    const u = await f.user({ pk: true });
    expect(await f.api('/api/user/passkey/auth-options', { purpose, password: 'wrong' }, u.token), 401, 'INVALID_CREDENTIALS');
    expect(await f.submit(u, purpose, undefined), 401, 'TWO_FACTOR_REQUIRED');
    const opts = await f.options(u, purpose);
    expect(await f.submit(u, purpose, f.proof(u, opts), u.token2), 401, 'TWO_FACTOR_INVALID');
    const passkey = f.proof(u, await f.options(u, purpose), { flags: 1 });
    expect(await f.submit(u, purpose, passkey, u.token, purpose === 'password' ? { currentPassword: 'wrong' } : { password: 'wrong' }), 401, 'INVALID_CREDENTIALS');
    expect(await f.submit(u, purpose, passkey));
    if (purpose === 'password') {
      const row = await f.db.prepare('SELECT password_hash FROM users WHERE id = ?').bind(u.id).first();
      assert.ok(await bcrypt.compare(newPassword, row.password_hash));
      expect(await f.api('/api/user/2fa/status', undefined, u.token, 'GET'));
    } else {
      assert.equal(await f.db.prepare('SELECT id FROM users WHERE id = ?').bind(u.id).first(), null);
      assert.deepEqual(f.deletedAvatars, [`hrt-tracker-user-avatar/${u.id}`]);
    }
    expect(await f.api('/api/user/2fa/status', undefined, u.token2, 'GET'), 401, 'SESSION_INVALID');
  });
}
for (const purpose of ['login', 'password', 'delete']) {
  test(`${purpose}: independent TOTP factor works and cannot be reused`, async f => {
    const u = await f.user({ otp: true });
    const code = totp(u.otpBytes);
    expect(await f.submit(u, purpose, undefined, u.token, { code }));
    if (purpose !== 'delete') {
      expect(await f.api('/api/login', { username: u.username, password: purpose === 'password' ? newPassword : password, code }), 401, 'TWO_FACTOR_INVALID');
    }
  });
}
for (const target of ['login', 'password', 'delete']) {
  test(`recovery: account isolation and one-time consumption via ${target}`, async f => {
    const a = await f.user({ pk: true });
    const b = await f.user({ pk: true });
    const { codes } = expect(await f.api('/api/user/2fa/backup-codes/generate', { password }, a.token));
    assert.ok(codes.length > 0);
    expect(await f.api('/api/login', { username: b.username, password, backup_code: codes[0] }), 401, 'TWO_FACTOR_INVALID');
    expect(await f.submit(a, target, undefined, a.token, { backup_code: codes[0] }));
    if (target !== 'delete') {
      expect(await f.api('/api/login', { username: a.username, password: target === 'password' ? newPassword : password, backup_code: codes[0] }), 401, 'TWO_FACTOR_INVALID');
      assert.notEqual((await f.db.prepare('SELECT used_at FROM backup_codes WHERE user_id = ? AND used_at IS NOT NULL').bind(a.id).first()), null);
    }
  });
}
test('recovery: concurrent spending yields exactly one session', async f => {
  const u = await f.user({ pk: true });
  const { codes } = expect(await f.api('/api/user/2fa/backup-codes/generate', { password }, u.token));
  const responses = await Promise.all(Array.from({ length: 3 }, () => f.api('/api/login', { username: u.username, password, backup_code: codes[0] })));
  assert.deepEqual(responses.map(r => r.status).sort(), [200, 401, 401]);
});
for (const purpose of ['direct', 'login', 'password', 'delete']) {
  test(`${purpose}: expired challenge is rejected at the exact expiry boundary`, async f => {
    const u = await f.user({ pk: true });
    const opts = await f.options(u, purpose);
    await f.db.prepare('UPDATE auth_challenges SET expires_at = ? WHERE token_hash = ?')
      .bind(Math.floor(Date.now() / 1000), tokenHash(opts.challengeToken)).run();
    expect(await f.submit(u, purpose, f.proof(u, opts)), 401, purpose === 'direct' ? 'INVALID_CREDENTIALS' : 'TWO_FACTOR_INVALID');
    await f.options(u, purpose);
    assert.equal(await f.db.prepare('SELECT token_hash FROM auth_challenges WHERE token_hash = ?').bind(tokenHash(opts.challengeToken)).first(), null);
  });
}
for (const purpose of ['direct', 'login']) {
  test(`${purpose}: zero-counter challenge replay is rejected, including concurrent use`, async f => {
    const u = await f.user({ pk: true });
    const passkey = f.proof(u, await f.options(u, purpose));
    const results = await Promise.all([f.submit(u, purpose, passkey), f.submit(u, purpose, passkey)]);
    assert.deepEqual(results.map(r => r.status).sort(), [200, 401]);
    expect(await f.submit(u, purpose, passkey), 401, purpose === 'direct' ? 'INVALID_CREDENTIALS' : 'TWO_FACTOR_INVALID');
  });
}
for (const [name, changes] of [
  ['missing UP', { flags: 4 }], ['wrong origin', { client: { origin: 'https://evil.example' } }],
  ['cross-origin', { client: { crossOrigin: true } }], ['wrong challenge', { client: { challenge: b64(randomBytes(32)) } }],
  ['wrong client type', { client: { type: 'webauthn.create' } }], ['wrong RP hash', { rp: 'evil.example' }],
]) {
  test(`real ES256 assertion rejects ${name}`, async f => {
    const u = await f.user({ pk: true });
    expect(await f.submit(u, 'direct', f.proof(u, await f.options(u, 'direct'), changes)), 401, 'INVALID_CREDENTIALS');
  });
}
test('real ES256 assertion rejects a signature from a different key', async f => {
  const u = await f.user({ pk: true });
  const other = await f.user({ pk: true });
  expect(await f.submit(u, 'direct', f.proof(u, await f.options(u, 'direct'), { signer: other.privateKey })), 401, 'INVALID_CREDENTIALS');
});
test('nonzero authenticator counter must advance and is persisted', async f => {
  const u = await f.user({ pk: true, counter: 7 });
  expect(await f.submit(u, 'direct', f.proof(u, await f.options(u, 'direct'), { count: 7 })), 401, 'INVALID_CREDENTIALS');
  expect(await f.submit(u, 'direct', f.proof(u, await f.options(u, 'direct'), { count: 8 })));
  assert.equal((await f.db.prepare('SELECT counter FROM passkeys WHERE id = ?').bind(u.keyId).first()).counter, 8);
});
test('challenge token cannot act as a session; signed purpose tokens and mismatched sid are rejected', async f => {
  const u = await f.user({ pk: true });
  const other = await f.user();
  const opts = await f.options(u, 'login');
  expect(await f.api('/api/user/2fa/status', undefined, opts.challengeToken, 'GET'), 401, 'SESSION_INVALID');
  const { payload } = await jwtVerify(u.token, new TextEncoder().encode(secret));
  for (const claims of [
    { sub: u.id, sid: payload.sid, purpose: 'passkey-register' },
    { sub: u.id, sid: payload.sid, purpose: 'direct' },
    { sub: u.id }, { sub: other.id, sid: payload.sid },
  ]) {
    const token = await new SignJWT(claims).setProtectedHeader({ alg: 'HS256' }).setIssuedAt().setExpirationTime('5m').sign(new TextEncoder().encode(secret));
    expect(await f.api('/api/user/2fa/status', undefined, token, 'GET'), 401, 'SESSION_INVALID');
  }
  const changed = `${u.token.slice(0, -8)}AAAAAAAA`;
  expect(await f.api('/api/user/2fa/status', undefined, changed, 'GET'), 401, 'SESSION_INVALID');
});
test('migration triggers clear only the affected account on password change and deletion', async f => {
  const a = await f.user({ pk: true });
  const b = await f.user({ pk: true });
  const pending = [];
  for (const purpose of ['direct', 'login', 'password', 'delete']) pending.push(f.proof(a, await f.options(a, purpose)));
  await f.options(b, 'login');
  await f.db.prepare('UPDATE users SET password_hash = password_hash WHERE id = ?').bind(a.id).run();
  assert.equal((await f.db.prepare('SELECT COUNT(*) AS n FROM auth_challenges WHERE user_id = ?').bind(a.id).first()).n, 4);
  await f.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(await bcrypt.hash(newPassword, 10), a.id).run();
  assert.equal((await f.db.prepare('SELECT COUNT(*) AS n FROM auth_challenges WHERE user_id = ?').bind(a.id).first()).n, 0);
  assert.equal((await f.db.prepare('SELECT COUNT(*) AS n FROM auth_challenges WHERE user_id = ?').bind(b.id).first()).n, 1);
  expect(await f.submit(a, 'direct', pending[0]), 401, 'INVALID_CREDENTIALS');
  await f.db.prepare('DELETE FROM users WHERE id = ?').bind(b.id).run();
  assert.equal((await f.db.prepare('SELECT COUNT(*) AS n FROM auth_challenges WHERE user_id = ?').bind(b.id).first()).n, 0);
});
test('runtime password change and account deletion clear pending challenges', async f => {
  const u = await f.user({ pk: true });
  await f.options(u, 'login');
  const pending = f.proof(u, await f.options(u, 'direct'));
  expect(await f.submit(u, 'password', f.proof(u, await f.options(u, 'password'))));
  assert.equal((await f.db.prepare('SELECT COUNT(*) AS n FROM auth_challenges WHERE user_id = ?').bind(u.id).first()).n, 0);
  expect(await f.submit(u, 'direct', pending), 401, 'INVALID_CREDENTIALS');
  const v = await f.user({ pk: true });
  await f.options(v, 'login');
  expect(await f.submit(v, 'delete', f.proof(v, await f.options(v, 'delete'))));
  for (const table of ['users', 'sessions', 'passkeys', 'backup_codes', 'auth_challenges']) {
    const column = table === 'users' ? 'id' : 'user_id';
    assert.equal((await f.db.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE ${column} = ?`).bind(v.id).first()).n, 0, table);
  }
});

for (const purpose of ['login', 'direct', 'password', 'delete']) {
  test(`${purpose}: concurrent password reset cannot authorize the final database write`, async f => {
    const u = await f.user({ pk: true });
    const passkey = f.proof(u, await f.options(u, purpose));
    const originalPrepare = f.db.prepare.bind(f.db);
    let injected = false;
    f.db.prepare = sql => {
      const finalWrite = purpose === 'password' ? /^UPDATE users SET password_hash/.test(sql)
        : purpose === 'delete' ? /^DELETE FROM users WHERE id/.test(sql)
          : /^INSERT INTO sessions/.test(sql);
      if (finalWrite && !injected) {
        injected = true;
        f.db.sqlite.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run('concurrent-reset', u.id);
        f.db.sqlite.prepare('DELETE FROM sessions WHERE user_id = ?').run(u.id);
      }
      return originalPrepare(sql);
    };
    expect(await f.submit(u, purpose, passkey), 401, 'INVALID_CREDENTIALS');
    assert.equal(injected, true);
    const user = f.db.sqlite.prepare('SELECT password_hash FROM users WHERE id = ?').get(u.id);
    assert.equal(user.password_hash, 'concurrent-reset');
    assert.equal(f.db.sqlite.prepare('SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?').get(u.id).n, 0);
  });
}
for (const purpose of ['password', 'delete']) {
  test(`${purpose}: concurrent session revocation prevents the final write`, async f => {
    const u = await f.user({ pk: true });
    const passkey = f.proof(u, await f.options(u, purpose));
    const sid = (await jwtVerify(u.token, new TextEncoder().encode(secret))).payload.sid;
    const originalPrepare = f.db.prepare.bind(f.db);
    let injected = false;
    f.db.prepare = sql => {
      if (!injected && (purpose === 'password' ? /^UPDATE users SET password_hash/.test(sql) : /^DELETE FROM users WHERE id/.test(sql))) {
        injected = true;
        f.db.sqlite.prepare('DELETE FROM sessions WHERE id = ?').run(sid);
      }
      return originalPrepare(sql);
    };
    expect(await f.submit(u, purpose, passkey), 401, 'INVALID_CREDENTIALS');
    assert.equal(injected, true);
    assert.equal(f.db.sqlite.prepare('SELECT password_hash FROM users WHERE id = ?').get(u.id).password_hash, passwordHash);
  });
}

let temp;
let failed = 0;
try {
  temp = await mkdtemp(join(root, '.venv', 'worker-auth-'));
  const sources = await Promise.all(['worker.ts', 'backupPolicy.ts'].map(name => readFile(join(root, name), 'utf8')));
  console.log(`Worker SHA-256: ${tokenHash(sources[0])}; migrations: ${migrations.map(m => m.name).join(', ')}`);
  for (const [index, name] of ['worker', 'backupPolicy'].entries()) {
    const output = ts.transpileModule(sources[index], {
      fileName: `${name}.ts`, compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
      reportDiagnostics: true,
    });
    assert.equal(output.diagnostics?.filter(d => d.category === ts.DiagnosticCategory.Error).length ?? 0, 0);
    await writeFile(join(temp, `${name}.mjs`), output.outputText.replace(/from ['"]\.\/backupPolicy['"]/g, "from './backupPolicy.mjs'"));
  }
  worker = (await import(pathToFileURL(join(temp, 'worker.mjs')).href)).default;
  for (const { name, run } of tests) {
    let f;
    try {
      f = await fixture();
      await run(f);
      console.log(`PASS ${name}`);
    } catch (error) {
      failed++;
      console.error(`FAIL ${name}\n${error.stack ?? error}`);
    } finally {
      if (f) await f.close();
    }
  }
  const current = await readFile(join(root, 'worker.ts'), 'utf8');
  assert.equal(tokenHash(current), tokenHash(sources[0]), 'worker.ts changed during execution; rerun against a stable snapshot');
  console.log(`\n${tests.length - failed}/${tests.length} passed; ${failed} failed.`);
  if (failed) process.exitCode = 1;
} finally {
  if (temp) await rm(temp, { recursive: true, force: true });
}
