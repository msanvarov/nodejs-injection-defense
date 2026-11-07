// UNSAFE: the classic recursive merge found in many old libraries.
// mergeUnsafe({}, JSON.parse('{"__proto__": {"isAdmin": true}}'))
// writes onto Object.prototype, so every object in the process now has isAdmin.
export function mergeUnsafe(target, source) {
  for (const key in source) {
    const value = source[key];
    if (typeof value === 'object' && value !== null) {
      target[key] ??= {};
      mergeUnsafe(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

const BLOCKED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

// SAFE: only own keys, dangerous keys skipped, never recurse into inherited values.
export function mergeSafe(target, source) {
  for (const key of Object.keys(source)) {
    if (BLOCKED_KEYS.has(key)) continue;
    const value = source[key];
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      const current = Object.hasOwn(target, key) ? target[key] : undefined;
      target[key] = current !== null && typeof current === 'object' ? current : {};
      mergeSafe(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}
