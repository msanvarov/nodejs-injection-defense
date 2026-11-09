import { exec, execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

// UNSAFE: user input is pasted into a shell string.
// greetUnsafe('x; rm -rf ~') runs both commands.
// `options` (cwd, timeout, ...) are passed straight to child_process.
export async function greetUnsafe(name, options = {}) {
  const { stdout } = await execAsync(`echo Hello ${name}`, options);
  return stdout;
}

// SAFE: execFile skips the shell. `name` reaches the program as one argv entry,
// so ; | && $() and backticks are just characters.
// Never pass { shell: true } here, it brings the shell back.
export async function greetSafe(name, options = {}) {
  const { stdout } = await execFileAsync('echo', ['Hello', name], options);
  return stdout;
}
