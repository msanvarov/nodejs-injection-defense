import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { greetUnsafe, greetSafe } from '../src/command.js';
import { createDb, findUserUnsafe, findUserSafe } from '../src/sql.js';
import { readUploadUnsafe, readUploadSafe } from '../src/path.js';
import { mergeUnsafe, mergeSafe } from '../src/prototype.js';
import { isWordListUnsafe, isWordList } from '../src/regex.js';

test('command injection: shell runs the injected command, execFile does not', async () => {
  const attack = 'x; echo PWNED';
  assert.match(await greetUnsafe(attack), /^PWNED$/m);
  assert.equal(await greetSafe(attack), 'Hello x; echo PWNED\n');
});

test('SQL injection: concatenation leaks all rows, placeholder does not', () => {
  const db = createDb();
  const attack = "' OR '1'='1";
  assert.deepEqual(findUserUnsafe(db, attack), ['alice', 'bob']);
  assert.deepEqual(findUserSafe(db, attack), []);
  assert.deepEqual(findUserSafe(db, 'bob'), ['bob']);
});

test('path traversal: ../ and absolute paths are blocked', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'traversal-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const uploads = path.join(dir, 'uploads');
  await mkdir(uploads);
  await writeFile(path.join(uploads, 'ok.txt'), 'public');
  await writeFile(path.join(dir, 'secret.txt'), 'top secret');

  assert.equal(await readUploadUnsafe(uploads, '../secret.txt'), 'top secret');
  assert.equal(await readUploadSafe(uploads, 'ok.txt'), 'public');
  await assert.rejects(readUploadSafe(uploads, '../secret.txt'), /escapes/);
  await assert.rejects(readUploadSafe(uploads, path.join(dir, 'secret.txt')), /escapes/);
  // Sibling folder whose name starts with the same prefix ("uploads-evil").
  await assert.rejects(readUploadSafe(uploads, '../uploads-evil/x'), /escapes/);
});

test('prototype pollution: unsafe merge poisons every object, safe merge does not', () => {
  const payloads = [
    '{"__proto__": {"isAdmin": true}}',
    '{"constructor": {"prototype": {"isAdmin": true}}}',
  ];
  for (const json of payloads) {
    try {
      mergeUnsafe({}, JSON.parse(json));
      assert.equal({}.isAdmin, true, `unsafe merge should pollute with ${json}`);
    } finally {
      delete Object.prototype.isAdmin;
    }
    mergeSafe({}, JSON.parse(json));
    assert.equal({}.isAdmin, undefined, `safe merge must not pollute with ${json}`);
  }
  assert.deepEqual(mergeSafe({ a: { b: 1 } }, { a: { c: 2 }, d: 3 }), { a: { b: 1, c: 2 }, d: 3 });
});

test('ReDoS: safe regex agrees on normal input and stays fast on hostile input', () => {
  for (const s of ['', 'hello', 'hello world', 'a b c']) {
    assert.equal(isWordList(s), isWordListUnsafe(s), s);
  }
  assert.equal(isWordList('hello  world'), false);

  const hostile = 'a'.repeat(900) + '!';
  const start = performance.now();
  assert.equal(isWordList(hostile), false);
  assert.ok(performance.now() - start < 50, 'safe regex should finish instantly');
  // Not run on purpose: isWordListUnsafe(hostile) would hang the test runner.
});
