const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const jwt = require('jsonwebtoken');

process.env.JWT_SECRET = 'test-secret-only';

// Faux accès base : on teste la logique de révocation sans PostgreSQL (la CI de tests n'en a pas).
const revoked = new Map();
const fakePool = {
  async query(sql, params) {
    // Du plus précis au plus général : "DELETE FROM revoked_tokens" contient aussi "FROM revoked_tokens".
    if (/^\s*INSERT INTO revoked_tokens/i.test(sql)) { revoked.set(params[0], params[1]); return { rows: [] }; }
    if (/^\s*DELETE FROM revoked_tokens/i.test(sql)) return { rows: [] };
    if (/^\s*SELECT 1 FROM revoked_tokens/i.test(sql)) return { rows: revoked.has(params[0]) ? [{ '?column?': 1 }] : [] };
    if (/FROM tasks/i.test(sql)) return { rows: [] };
    throw new Error(`requête inattendue: ${sql}`);
  },
};
const poolPath = require.resolve('../db/pool');
require.cache[poolPath] = { id: poolPath, filename: poolPath, loaded: true, exports: fakePool };

const app = require('../index.js');

const sign = (opts = {}) =>
  jwt.sign({ userId: 1, username: 'alice' }, process.env.JWT_SECRET, { expiresIn: '1h', ...opts });

async function call(port, method, url, token) {
  return fetch(`http://localhost:${port}${url}`, { method, headers: token ? { Authorization: `Bearer ${token}` } : {} });
}

test('logout revokes the token: valid before, refused after', async () => {
  const server = app.listen(0);
  const port = server.address().port;
  try {
    const token = sign({ jwtid: 'jti-logout-test' });

    assert.strictEqual((await call(port, 'GET', '/api/tasks', token)).status, 200, 'accepté avant logout');
    assert.strictEqual((await call(port, 'POST', '/api/auth/logout', token)).status, 200);

    const after = await call(port, 'GET', '/api/tasks', token);
    assert.strictEqual(after.status, 401, 'refusé après logout');
    assert.strictEqual((await after.json()).error, 'Token revoked');
  } finally {
    server.close();
  }
});

test('revoking one token does not affect another token of the same user', async () => {
  const server = app.listen(0);
  const port = server.address().port;
  try {
    const a = sign({ jwtid: 'jti-a' });
    const b = sign({ jwtid: 'jti-b' });
    await call(port, 'POST', '/api/auth/logout', a);
    assert.strictEqual((await call(port, 'GET', '/api/tasks', a)).status, 401);
    assert.strictEqual((await call(port, 'GET', '/api/tasks', b)).status, 200);
  } finally {
    server.close();
  }
});

test('a token without jti is refused (it could never be revoked)', async () => {
  const server = app.listen(0);
  const port = server.address().port;
  try {
    assert.strictEqual((await call(port, 'GET', '/api/tasks', sign())).status, 403);
  } finally {
    server.close();
  }
});

test('a forged or tampered token is refused', async () => {
  const server = app.listen(0);
  const port = server.address().port;
  try {
    const forged = jwt.sign({ userId: 1, username: 'alice' }, 'wrong-secret', { expiresIn: '1h', jwtid: 'x' });
    assert.strictEqual((await call(port, 'GET', '/api/tasks', forged)).status, 403);
    assert.strictEqual((await call(port, 'GET', '/api/tasks')).status, 401);
  } finally {
    server.close();
  }
});
