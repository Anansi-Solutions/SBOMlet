/**
 * Behavior tests for the shared subprocess helper.
 *
 * Every test spawns `process.execPath` (the bun executable when running under
 * `bun test`) so the suite is self-contained and OS-independent — no PATH
 * assumptions, no external tools.
 */

import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

import { execTool } from "../src/collectors/exec";

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

describe("execTool", () => {
  test("resolves with captured stdout on exit code 0", async () => {
    const { stdout } = await execTool(process.execPath, ["--version"], {
      timeoutMs: 30000,
      verbose: false,
    });
    expect(stdout).toMatch(/\d+\.\d+\.\d+/);
  });

  test("multibyte UTF-8 split across chunk boundaries decodes intact", async () => {
    // The child writes "é世界" (2+3+3 UTF-8 bytes) in two writes split at
    // byte 3 — mid-sequence inside 世 — separated by a delay so the two
    // writes arrive as separate stream chunks. Naive per-chunk decoding
    // would yield U+FFFD fragments.
    const script =
      'const b = Buffer.from("\\u00e9\\u4e16\\u754c", "utf8");' +
      "process.stdout.write(b.subarray(0, 3));" +
      "setTimeout(() => { process.stdout.write(b.subarray(3)); }, 50);";
    const { stdout } = await execTool(process.execPath, ["-e", script], {
      timeoutMs: 30000,
      verbose: false,
    });
    expect(stdout).toContain("é世界");
    expect(stdout).not.toContain("�");
  });

  test("rejects with the exit code in the message on nonzero exit", async () => {
    expect.assertions(2);
    try {
      await execTool(process.execPath, ["-e", "process.exit(2)"], {
        timeoutMs: 30000,
        verbose: false,
      });
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toContain("2");
    }
  });

  test("rejects with 'timed out' and kills the child when timeoutMs elapses", async () => {
    expect.assertions(2);
    const startedAt = Date.now();
    try {
      await execTool(process.execPath, ["-e", "setTimeout(() => {}, 10000)"], {
        timeoutMs: 250,
        verbose: false,
      });
    } catch (error) {
      expect((error as Error).message).toContain("timed out");
      // The child was killed: we did not wait for its 10s sleep to finish.
      expect(Date.now() - startedAt).toBeLessThan(8000);
    }
  });

  test("timeout kills the whole process tree, not just the direct child", async () => {
    // The child spawns a long-sleeping GRANDCHILD (the `bun x` -> cdxgen
    // shape), records its pid to a file, then sleeps itself. After the
    // timeout rejection, the grandchild must die too — a plain child.kill()
    // would orphan it.
    const pidFile = join(
      mkdtempSync(join(tmpdir(), "licenses-exec-test-")),
      "grandchild.pid",
    );
    const childScript =
      'const { spawn } = require("node:child_process");' +
      'const g = spawn(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], { stdio: "ignore" });' +
      `require("node:fs").writeFileSync(${JSON.stringify(pidFile)}, String(g.pid));` +
      "setTimeout(() => {}, 30000);";

    await expect(
      execTool(process.execPath, ["-e", childScript], {
        timeoutMs: 1500,
        verbose: false,
      }),
    ).rejects.toThrow("timed out");

    // Wait for the pid file (written well before the 1.5s timeout fires).
    for (let i = 0; i < 100 && !existsSync(pidFile); i++) await sleep(100);
    expect(existsSync(pidFile)).toBe(true);
    const grandchildPid = Number(readFileSync(pidFile, "utf-8"));
    expect(Number.isInteger(grandchildPid)).toBe(true);

    // The tree kill is asynchronous (taskkill on win32) — poll until dead.
    let alive = true;
    for (let i = 0; i < 100; i++) {
      alive = isAlive(grandchildPid);
      if (!alive) break;
      await sleep(100);
    }
    expect(alive).toBe(false);
  }, 20000);

  test.if(process.platform === "win32")(
    "win32: an unspawnable taskkill on timeout falls back to child.kill() instead of crashing",
    async () => {
      const pidFile = join(
        mkdtempSync(join(tmpdir(), "licenses-exec-test-")),
        "child.pid",
      );
      const script =
        `require("node:fs").writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));` +
        "setTimeout(() => {}, 30000);";

      // Blank out PATH so killProcessTree's taskkill spawn fails (ENOENT —
      // libuv resolves bare names via cwd + PATH only, never System32
      // implicitly). Pre-fix, that ChildProcess emitted 'error' with zero
      // listeners: an uncaught exception killing the whole process instead
      // of surfacing the timeout rejection. The test child itself needs no
      // PATH because process.execPath is absolute.
      const pathKeys = Object.keys(process.env).filter(
        (key) => key.toUpperCase() === "PATH",
      );
      const saved = pathKeys.map((key) => [key, process.env[key]] as const);
      for (const key of pathKeys) delete process.env[key];
      try {
        await expect(
          execTool(process.execPath, ["-e", script], {
            timeoutMs: 1000,
            verbose: false,
          }),
        ).rejects.toThrow("timed out");
      } finally {
        for (const [key, value] of saved) process.env[key] = value;
      }

      // The fallback child.kill() must still terminate the direct child.
      for (let i = 0; i < 100 && !existsSync(pidFile); i++) await sleep(100);
      expect(existsSync(pidFile)).toBe(true);
      const childPid = Number(readFileSync(pidFile, "utf-8"));
      let alive = true;
      for (let i = 0; i < 100; i++) {
        alive = isAlive(childPid);
        if (!alive) break;
        await sleep(100);
      }
      expect(alive).toBe(false);
    },
    20000,
  );

  test("a provided env reaches the child; an env without the var yields no sentinel", async () => {
    const script =
      'process.stdout.write("sentinel=" + (process.env.LICENSES_TEST_SENTINEL ?? "<unset>"));';

    const withVar = await execTool(process.execPath, ["-e", script], {
      timeoutMs: 30000,
      verbose: false,
      env: { ...process.env, LICENSES_TEST_SENTINEL: "round-trip-9f3a1c" },
    });
    expect(withVar.stdout).toContain("sentinel=round-trip-9f3a1c");

    const withoutVar = await execTool(process.execPath, ["-e", script], {
      timeoutMs: 30000,
      verbose: false,
      // Explicit env WITHOUT the sentinel var (PATH kept so spawn works).
      env: { PATH: process.env.PATH },
    });
    expect(withoutVar.stdout).toContain("sentinel=<unset>");
    expect(withoutVar.stdout).not.toContain("round-trip-9f3a1c");
  });

  test("rejects (instead of hanging) when the executable does not exist", async () => {
    expect.assertions(1);
    try {
      await execTool("definitely-not-a-real-executable-9f3a1c", ["--version"], {
        timeoutMs: 5000,
        verbose: false,
      });
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
    }
  });
});
