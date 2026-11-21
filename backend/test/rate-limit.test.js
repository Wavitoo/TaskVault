const test = require('node:test');
const assert = require('node:assert');
const app = require('../index.js');

async function post(port, path, body) {
  return fetch(`http://localhost:${port}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

test('POST /api/auth/login is rate limited after 10 attempts', async () => {
  const server = app.listen(0);
  const port = server.address().port;
  try {
    const statuses = [];
    // Corps vide : la route répond 400 avant tout accès à la base, le test n'a donc pas besoin de PostgreSQL.
    for (let i = 0; i < 12; i++) {
      statuses.push((await post(port, '/api/auth/login', {})).status);
    }
    assert.deepStrictEqual(statuses.slice(0, 10), Array(10).fill(400), 'les 10 premières passent la limite');
    assert.strictEqual(statuses[10], 429, 'la 11e est refusée');
    assert.strictEqual(statuses[11], 429);

    const blocked = await post(port, '/api/auth/login', {});
    assert.strictEqual((await blocked.json()).error, 'Too many attempts, please try again later');
    assert.ok(blocked.headers.get('ratelimit') || blocked.headers.get('ratelimit-policy'), 'en-têtes de limite présents');
  } finally {
    server.close();
  }
});

test('the rate limit does not apply to /health', async () => {
  const server = app.listen(0);
  const port = server.address().port;
  try {
    for (let i = 0; i < 15; i++) {
      const r = await fetch(`http://localhost:${port}/health`);
      assert.strictEqual(r.status, 200);
    }
  } finally {
    server.close();
  }
});
