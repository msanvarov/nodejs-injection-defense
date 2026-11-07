import { readFile } from 'node:fs/promises';
import path from 'node:path';

// UNSAFE: path.join happily walks out of baseDir with '../' or an absolute path.
export function readUploadUnsafe(baseDir, name) {
  return readFile(path.join(baseDir, name), 'utf8');
}

// SAFE: resolve the final path, then check it is still inside baseDir.
// If baseDir can contain symlinks, run fs.realpath on the result too.
export function resolveInside(baseDir, name) {
  const root = path.resolve(baseDir);
  const target = path.resolve(root, name);
  if (!target.startsWith(root + path.sep)) throw new Error('path escapes base directory');
  return target;
}

export async function readUploadSafe(baseDir, name) {
  return readFile(resolveInside(baseDir, name), 'utf8');
}
