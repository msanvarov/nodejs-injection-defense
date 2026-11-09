// Interactive demo: runs each attack against the unsafe and safe version of the
// same function and returns both results. It executes deliberately vulnerable
// code on this machine, so it only listens on 127.0.0.1 and refuses requests
// that could come from another website (see `guard` below).

import http from 'node:http';
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Worker } from 'node:worker_threads';

import { greetSafe, greetUnsafe } from '../src/command.js';
import { SAFE_QUERY, createDb, findUserSafe, findUserUnsafe, unsafeQuery } from '../src/sql.js';
import { readUploadSafe, readUploadUnsafe } from '../src/path.js';
import { isWordList, isWordListUnsafe } from '../src/regex.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = (file) => pathToFileURL(path.join(HERE, '../src', file)).href;
const MAX_BODY = 64 * 1024;

// Turn a throw from the code under test into a result the UI can show.
async function attempt(fn) {
  try {
    return { output: await fn() };
  } catch (err) {
    return { error: err.message };
  }
}

// Runs `body` in a fresh worker thread: its own JS realm (so prototype
// pollution can't leak into this server) that we can kill if it hangs (ReDoS).
function runInWorker(body, workerData, timeoutMs) {
  return new Promise((resolve) => {
    const worker = new Worker(`const { parentPort, workerData } = require('node:worker_threads');\n${body}`, {
      eval: true,
      workerData,
    });
    const timer = setTimeout(() => {
      worker.terminate();
      resolve({ timedOut: true });
    }, timeoutMs);
    worker.once('message', (msg) => {
      clearTimeout(timer);
      worker.terminate();
      resolve(msg);
    });
    worker.once('error', (err) => {
      clearTimeout(timer);
      resolve({ error: err.message });
    });
  });
}

const isInside = (root, target) => target.startsWith(root + path.sep);

async function makeSandbox() {
  const dir = await mkdtemp(path.join(tmpdir(), 'injection-demo-'));
  await mkdir(path.join(dir, 'uploads'));
  await writeFile(path.join(dir, 'uploads/welcome.txt'), 'Welcome! This file is meant to be public.\n');
  await writeFile(path.join(dir, 'uploads/report.txt'), 'Q3 report: all systems nominal.\n');
  await writeFile(path.join(dir, 'secret.txt'), 'API_KEY=sk_live_demo_not_real\n');
  return dir;
}

const routes = {
  async command({ name = '' }) {
    name = String(name).slice(0, 200);
    const expected = `Hello ${name}\n`;
    const cwd = await mkdtemp(path.join(tmpdir(), 'command-demo-'));
    try {
      const options = { cwd, timeout: 3000 };
      const [unsafe, safe] = await Promise.all([
        attempt(() => greetUnsafe(name, options)),
        attempt(() => greetSafe(name, options)),
      ]);
      return {
        unsafe: { ran: `echo Hello ${name}`, ...unsafe, exploited: unsafe.output !== expected },
        safe: { ran: `execFile('echo', ${JSON.stringify(['Hello', name])})`, ...safe, exploited: safe.output !== expected },
      };
    } finally {
      await rm(cwd, { recursive: true, force: true });
    }
  },

  async sql({ name = '' }) {
    name = String(name).slice(0, 500);
    const db = createDb();
    try {
      const unsafe = await attempt(() => findUserUnsafe(db, name));
      const safe = await attempt(() => findUserSafe(db, name));
      const leaked = (r) => Boolean(r.output?.some((row) => row !== name));
      return {
        unsafe: { ran: unsafeQuery(name), ...unsafe, exploited: leaked(unsafe) },
        safe: { ran: `${SAFE_QUERY}\nparams: ${JSON.stringify([name])}`, ...safe, exploited: leaked(safe) },
      };
    } finally {
      db.close();
    }
  },

  async path({ name = '' }, sandbox) {
    name = String(name).slice(0, 500);
    const uploads = path.join(sandbox, 'uploads');
    const unsafePath = path.join(uploads, name);
    const safePath = path.resolve(uploads, name);

    const unsafe = await attempt(async () => {
      // Demo guard, not part of the lesson: refuse devices (/dev/zero never
      // ends) and big files so a typo can't hang or bloat the demo server.
      const info = await stat(unsafePath);
      if (!info.isFile()) throw new Error('demo guard: not a regular file');
      if (info.size > 1024 * 1024) throw new Error('demo guard: file larger than 1 MB');
      return (await readUploadUnsafe(uploads, name)).slice(0, 2048);
    });
    const safe = await attempt(async () => (await readUploadSafe(uploads, name)).slice(0, 2048));
    // Show the temp folder as /sandbox so paths are short and machine-independent.
    const show = (p) => (p.startsWith(sandbox) ? '/sandbox' + p.slice(sandbox.length) : p);
    return {
      unsafe: { ran: show(unsafePath), ...unsafe, exploited: !isInside(uploads, unsafePath) },
      safe: { ran: show(safePath), ...safe, exploited: !safe.error && !isInside(uploads, safePath) },
    };
  },

  async prototype({ json = '' }) {
    json = String(json);
    try {
      JSON.parse(json);
    } catch (err) {
      const side = { ran: 'JSON.parse(body)', error: `Invalid JSON: ${err.message}`, exploited: false };
      return { unsafe: side, safe: side };
    }
    const worker = `import(workerData.url).then((m) => {
      const merged = m[workerData.fn]({}, JSON.parse(workerData.json));
      parentPort.postMessage({ merged, polluted: Object.fromEntries(Object.entries(Object.prototype)) });
    }).catch((err) => parentPort.postMessage({ error: err.message }));`;
    const run = async (fn) => {
      const msg = await runInWorker(worker, { url: SRC('prototype.js'), fn, json }, 2000);
      const ran = `${fn}({}, JSON.parse(body))`;
      if (msg.timedOut) return { ran, error: 'timed out', exploited: false };
      if (msg.error) return { ran, error: msg.error, exploited: false };
      return { ran, output: msg, exploited: Object.keys(msg.polluted).length > 0 };
    };
    const [unsafe, safe] = await Promise.all([run('mergeUnsafe'), run('mergeSafe')]);
    return { unsafe, safe };
  },

  async redos({ n = 26 }) {
    n = Math.min(32, Math.max(1, Math.trunc(Number(n)) || 26));
    const input = 'a'.repeat(n) + '!';
    const worker = `import(workerData.url).then((m) => {
      const start = performance.now();
      const result = m.isWordListUnsafe(workerData.input);
      parentPort.postMessage({ result, ms: performance.now() - start });
    });`;
    const msg = await runInWorker(worker, { url: SRC('regex.js'), input }, 4000);
    const unsafe = msg.timedOut
      ? { ran: String(isWordListUnsafe), killed: true, ms: 4000, exploited: true }
      : { ran: String(isWordListUnsafe), output: msg.result, ms: msg.ms, exploited: msg.ms > 250 };

    const start = performance.now();
    const result = isWordList(input);
    const ms = performance.now() - start;
    return { input, unsafe, safe: { ran: String(isWordList), output: result, ms, exploited: ms > 250 } };
  },
};

function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff' });
  res.end(JSON.stringify(body));
}

// Only this page may drive the demo. A malicious site could otherwise POST to
// 127.0.0.1 or use DNS rebinding to run commands through it.
function guard(req, port) {
  const allowed = [`127.0.0.1:${port}`, `localhost:${port}`];
  if (!allowed.includes(req.headers.host)) return [403, 'forbidden host'];
  const origin = req.headers.origin;
  if (origin && !allowed.some((h) => origin === `http://${h}`)) return [403, 'forbidden origin'];
  return null;
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw Object.assign(new Error('body too large'), { status: 413 });
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
  } catch {
    throw Object.assign(new Error('invalid JSON'), { status: 400 });
  }
}

export function createDemoServer() {
  const sandbox = makeSandbox();

  const server = http.createServer(async (req, res) => {
    try {
      const blocked = guard(req, server.address().port);
      if (blocked) return send(res, blocked[0], { error: blocked[1] });

      const { pathname } = new URL(req.url, 'http://localhost');
      if (req.method === 'GET' && pathname === '/') {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Security-Policy': "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'",
          'X-Content-Type-Options': 'nosniff',
        });
        return res.end(await readFile(path.join(HERE, 'index.html')));
      }

      const route = req.method === 'POST' && pathname.startsWith('/api/') && Object.hasOwn(routes, pathname.slice(5))
        ? routes[pathname.slice(5)]
        : null;
      if (!route) return send(res, 404, { error: 'not found' });
      if (!req.headers['content-type']?.startsWith('application/json')) {
        return send(res, 415, { error: 'expected application/json' });
      }
      send(res, 200, await route(await readJson(req), await sandbox));
    } catch (err) {
      if (!err.status) console.error(err);
      send(res, err.status ?? 500, { error: err.status ? err.message : 'internal error' });
    }
  });

  server.on('close', () => sandbox.then((dir) => rm(dir, { recursive: true, force: true })));
  return server;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 4101);
  createDemoServer().listen(port, '127.0.0.1', () => {
    console.log(`Injection demo: http://127.0.0.1:${port}`);
    console.log('Warning: this runs deliberately vulnerable code on your machine. Stop it with Ctrl+C when done.');
  });
}
