# nodejs-injection-defense

[![CI](https://github.com/msanvarov/nodejs-injection-defense/actions/workflows/test.yml/badge.svg)](https://github.com/msanvarov/nodejs-injection-defense/actions/workflows/test.yml) ![Node](https://img.shields.io/badge/node-%3E%3D22.13-339933?logo=node.js&logoColor=white) ![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen) ![License: MIT](https://img.shields.io/badge/license-MIT-blue)

Small, runnable examples of the most common injection bugs in Node.js. Each file in `src/` has an **unsafe** version and a **safe** version, and `test/` proves the attack works on one and fails on the other.

No dependencies. Uses only Node built-ins (`node:sqlite`, `node:child_process`, `node:test`).

```bash
npm test
```

> [!WARNING]
> Functions ending in `Unsafe` are **intentionally vulnerable** so the tests can show the attack working. Copy the safe versions, never those.

## Project layout

```text
src/
  command.js     exec() vs execFile()
  sql.js         string concatenation vs placeholders (node:sqlite)
  path.js        path.join vs resolve-and-check
  prototype.js   naive deep merge vs key-filtered merge
  regex.js       catastrophic-backtracking regex vs linear one
test/
  injection.test.js   one test per attack, run against both versions
```

## What's covered

| Bug | File | Attack | Fix |
| --- | --- | --- | --- |
| Command injection | [src/command.js](src/command.js) | `x; rm -rf ~` passed to `exec()` | `execFile()` / `spawn()` with an args array, no shell |
| SQL injection | [src/sql.js](src/sql.js) | `' OR '1'='1` in a concatenated query | Parameterized queries (`?` placeholders) |
| Path traversal | [src/path.js](src/path.js) | `../secret.txt` or `/etc/passwd` | `path.resolve` + check the result stays inside the base dir |
| Prototype pollution | [src/prototype.js](src/prototype.js) | `{"__proto__": {"isAdmin": true}}` | Skip `__proto__`/`constructor`/`prototype`, only own keys |
| ReDoS | [src/regex.js](src/regex.js) | `'a'.repeat(30) + '!'` against `/^(\w+\s?)*$/` | Unambiguous regex + input length cap |

## Mitigations in more detail

### Command injection
- Prefer `execFile` / `spawn` with an argument array. Never build a shell string from input.
- `{ shell: true }` turns `spawn`/`execFile` back into a shell. Avoid it.
- On Windows, running `.bat`/`.cmd` files always goes through `cmd.exe` (see CVE-2024-27980). Keep Node patched.
- Even without a shell, an attacker controlling arguments can pass flags (`--output=/etc/...`). Put `--` before user values when the program supports it, and allowlist values when you can.

### SQL / NoSQL injection
- Always use placeholders. ORMs are safe until you reach for `raw()` / `$queryRawUnsafe`.
- NoSQL has its own version: `{ "password": { "$ne": null } }` in a MongoDB query. Validate that fields are the type you expect (string, not object) before they reach the query.

### Path traversal
- `path.join` and `path.normalize` do **not** protect you.
- Check `target.startsWith(root + path.sep)`, not just `startsWith(root)`, or `/uploads-evil` passes a check for `/uploads`.
- Don't use user input as a filename at all when you can avoid it. Store files under a generated ID and keep the original name in a database.
- If the directory may contain symlinks, `fs.realpath` the result before checking.

### Prototype pollution
- Validate request bodies against a schema (e.g. Zod, Ajv with `additionalProperties: false`) so unexpected keys never reach merge code.
- Use `Map` or `Object.create(null)` for dictionaries keyed by user input.
- Defense in depth: run Node with `--disable-proto=delete`, or `Object.freeze(Object.prototype)` at startup.
- Keep merge/clone libraries (lodash, etc.) updated. Many had CVEs for exactly this.

### ReDoS (regex denial of service)
- Node is single threaded. One slow regex blocks every request.
- Avoid nested quantifiers like `(a+)+`, `(\w+\s?)*`, `(.*,)*`.
- Cap input length before matching.
- Check patterns with a tool such as [recheck](https://makenowjust-labs.github.io/recheck/) or the `eslint-plugin-regexp` / `eslint-plugin-security` rules.

Try it yourself (this will hang for several seconds):

```bash
node -e "console.time('t'); /^(\w+\s?)*$/.test('a'.repeat(28) + '!'); console.timeEnd('t')"
```

### `eval`, `new Function`, `vm`
- Never `eval` input. Parse JSON with `JSON.parse`.
- `node:vm` is **not** a security boundary. Its docs say so. Code inside a `vm` context can escape to the host. For untrusted code, use a separate process with the permission model (see `nodejs-supply-chain-security`), a container, or an isolate library built for it.

## Node.js security series

| Repo | Covers |
| --- | --- |
| **nodejs-injection-defense** (you are here) | Command, SQL, path traversal, prototype pollution, ReDoS |
| [nodejs-http-hardening](https://github.com/msanvarov/nodejs-http-hardening) | Headers, body limits, timeouts, rate limiting, CORS, safe errors |
| [nodejs-supply-chain-security](https://github.com/msanvarov/nodejs-supply-chain-security) | npm config, CI auditing, install-script scanning, permission model |
| [nodejs-crypto-secrets](https://github.com/msanvarov/nodejs-crypto-secrets) | Password hashing, tokens, JWTs, encryption, secrets |

## Running it

Requires Node.js 22.13 or newer. No `npm install` needed.

```bash
git clone https://github.com/msanvarov/nodejs-injection-defense.git
cd nodejs-injection-defense
npm test
```

Found a mistake or want to add an example? Issues and pull requests are welcome.

## License

[MIT](LICENSE)
