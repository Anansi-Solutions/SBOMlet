/**
 * Shared subprocess helper: the only place this tool touches
 * node:child_process. Commands are spawned as explicit argv arrays with no
 * command interpreter, so paths and arguments can never be interpolated into
 * a command string — injection is impossible by construction.
 */

import { spawn, type ChildProcess } from "node:child_process";

export interface ExecOptions {
  /** Hard wall-clock limit; the child is killed and the call rejects. */
  timeoutMs: number;
  /** When true, child stdout/stderr chunks pass through to process.stderr verbatim. */
  verbose: boolean;
  /** Working directory for the child process. */
  cwd?: string;
  /**
   * Environment for the child process. `undefined` inherits the parent env
   * (spawn's default). The yarn-plugin adapter passes a scrubbed copy
   * (NODE_ENV deleted, YARN_INSTALL_STATE_PATH redirected).
   */
  env?: NodeJS.ProcessEnv;
}

/**
 * Kill the child's whole process tree, not just the direct child. The
 * production invocation is `bun x cdxgen ...`: the runner is the direct child
 * and cdxgen (plus any helpers it spawns) are grandchildren that a plain
 * child.kill() would orphan.
 *
 * - win32: `taskkill /T /F` walks the tree, spawned as an argv array with no
 *   shell.
 * - POSIX: the child is spawned `detached` (its own process group), so
 *   killing the negative PID signals the entire group.
 */
function killProcessTree(child: ChildProcess): void {
  const pid = child.pid;
  if (pid === undefined) return; // spawn failed; nothing to kill
  if (process.platform === "win32") {
    // An unspawnable taskkill (PATH without System32 in a stripped
    // container) emits 'error' with zero listeners — an uncaught exception
    // that would kill the whole CLI with a confusing ENOENT instead of the
    // already-constructed timeout rejection. Handle it and fall back to a
    // direct kill: the tree is orphaned but the run survives and the timeout
    // error still surfaces.
    spawn("taskkill", ["/pid", String(pid), "/T", "/F"], {
      stdio: "ignore",
    }).on("error", () => child.kill());
  } else {
    try {
      process.kill(-pid, "SIGTERM");
    } catch {
      // Group already gone (or not a group leader): fall back to the child.
      child.kill("SIGTERM");
    }
  }
}

export function execTool(
  cmd: string,
  args: string[],
  opts: ExecOptions,
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: opts.env,
      stdio: ["ignore", "pipe", "pipe"],
      // POSIX: own process group so the timeout can kill the whole tree.
      // win32: detached would allocate a new console; taskkill /T covers it.
      detached: process.platform !== "win32",
    });

    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      killProcessTree(child);
      reject(
        new Error(
          `${cmd} ${args[0] ?? ""} timed out after ${opts.timeoutMs} ms`,
        ),
      );
    }, opts.timeoutMs);

    let stdout = "";
    let stderr = "";

    // setEncoding makes Node buffer partial multibyte sequences across chunk
    // boundaries; naive per-chunk Buffer#toString would decode a split UTF-8
    // sequence to U+FFFD fragments, corrupting the returned text.
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");

    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
      if (opts.verbose) {
        process.stderr.write(chunk);
      }
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
      if (opts.verbose) {
        process.stderr.write(chunk);
      }
    });

    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });

    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (timedOut) {
        // Already rejected with the timeout error; this close is the kill
        // landing (code === null) — never report "exited with code null".
        return;
      }
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        const reason =
          code === null
            ? `was terminated by signal ${signal ?? "unknown"}`
            : `exited with code ${code}`;
        reject(new Error(`${cmd} ${reason}\n${stderr.slice(-2000)}`));
      }
    });
  });
}
