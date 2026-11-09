import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { createDemoServer } from '../demo/server.js';

let server;
let port;

before(async () => {
  server = createDemoServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  port = server.address().port;
});
after(() => server.close());

// node:http instead of fetch, because fetch won't let us forge the Host header.
function request({ method = 'GET', path = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

const api = (name, payload, headers = {}) =>
  request({ method: 'POST', path: `/api/${name}`, headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(payload) });

test('serves the demo page', async () => {
  const res = await request();
  assert.equal(res.status, 200);
  assert.match(res.headers['content-type'], /text\/html/);
  assert.match(res.body, /nodejs-injection-defense/);
});

const DEFAULTS = {
  command: { name: 'x; echo PWNED' },
  sql: { name: "' OR '1'='1" },
  path: { name: '../secret.txt' },
  prototype: { json: '{"__proto__": {"isAdmin": true}}' },
  redos: { n: 26 },
};

for (const [name, payload] of Object.entries(DEFAULTS)) {
  test(`${name}: default attack exploits unsafe, not safe`, async () => {
    const res = await api(name, payload);
    assert.equal(res.status, 200);
    const { unsafe, safe } = JSON.parse(res.body);
    assert.equal(unsafe.exploited, true, JSON.stringify(unsafe));
    assert.equal(safe.exploited, false, JSON.stringify(safe));
  });
}

test('prototype pollution never leaks into the demo server', async () => {
  await api('prototype', DEFAULTS.prototype);
  assert.equal({}.isAdmin, undefined);
});

test('local-only guards', async () => {
  assert.equal((await request({ headers: { Host: 'evil.example' } })).status, 403);
  assert.equal((await api('sql', DEFAULTS.sql, { Origin: 'https://evil.example' })).status, 403);
  assert.equal((await api('sql', DEFAULTS.sql, { Origin: `http://127.0.0.1:${port}` })).status, 200);
  const textPlain = await request({ method: 'POST', path: '/api/sql', headers: { 'Content-Type': 'text/plain' }, body: '{}' });
  assert.equal(textPlain.status, 415);
  assert.equal((await api('nope', {})).status, 404);
});
