/**
 * Subprocess-free orchestration tests for the built-image collection posture
 * (DOCK-01): a locally built, never-pushed image has no RepoDigests
 * (resolveDigest throws by design) and any per-build digest is volatile, so
 * built collection records the stable, digest-less identity
 * {image: <ref>, digest: ""} and never invokes docker inspect/pull.
 *
 * Isolated from dockerOs.test.ts (which stays un-mocked) because this file
 * replaces execTool via mock.module — the cli.test.ts precedent, restored in
 * afterAll so no other suite observes the stub.
 */

import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  mock,
  test,
} from "bun:test";

import * as execModule from "../src/collectors/exec";
import { collectDockerOsSbom } from "../src/collectors/dockerOs";

/** Original exec export captured BEFORE any mock.module call (restore target). */
const REAL_EXEC = { ...execModule };

/** Every recorded execTool invocation: [cmd, ...args]. */
let invocations: string[][] = [];

/**
 * A subprocess-free execTool recorder. For a syft invocation (argv containing
 * a "cyclonedx-json=<file>" option), copies the built-image fixture to the
 * parsed outFile so the collector's read-back succeeds without ever spawning
 * anything. Any other invocation (docker inspect/pull) is just recorded.
 */
function fakeExecTool(
  cmd: string,
  args: string[],
): Promise<{ stdout: string; stderr: string }> {
  invocations.push([cmd, ...args]);
  const cyclonedxArg = args.find((a) => a.startsWith("cyclonedx-json="));
  if (cyclonedxArg !== undefined) {
    const outFile = cyclonedxArg.slice("cyclonedx-json=".length);
    copyFileSync(
      join(__dirname, "fixtures", "syft-built-image-trimmed.json"),
      outFile,
    );
  }
  return Promise.resolve({ stdout: "[]", stderr: "" });
}

describe("collectDockerOsSbom built-image collection posture (DOCK-01)", () => {
  let tempDir: string;

  beforeAll(() => {
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: fakeExecTool,
    }));
  });

  afterAll(() => {
    mock.module("../src/collectors/exec", () => REAL_EXEC);
  });

  afterEach(() => {
    invocations = [];
    if (tempDir !== undefined)
      rmSync(tempDir, { recursive: true, force: true });
  });

  test('records digest-less {image, digest:""} per image, sorted, with NO inspect/pull argv', async () => {
    tempDir = mkdtempSync(join(tmpdir(), "licenses-docker-built-"));
    const { doc } = await collectDockerOsSbom(
      ["local/scan-b", "local/scan-a"],
      { built: true, tempDir },
    );
    const parsed = JSON.parse(doc) as {
      dockerImages: { image: string; digest: string }[];
    };
    expect(parsed.dockerImages).toEqual([
      { image: "local/scan-a", digest: "" },
      { image: "local/scan-b", digest: "" },
    ]);

    const argvStrings = invocations.map((argv) => argv.join(" "));
    expect(argvStrings.some((s) => s.includes("inspect"))).toBe(false);
    expect(argvStrings.some((s) => s.includes("pull"))).toBe(false);
  });

  test("applies fullContents on the built path — components include a pkg:npm purl", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "licenses-docker-built-"));
    const { doc } = await collectDockerOsSbom(["local/scan-a"], {
      built: true,
      tempDir,
    });
    const parsed = JSON.parse(doc) as {
      components: { purl: string }[];
    };
    expect(parsed.components.some((c) => c.purl.startsWith("pkg:npm/"))).toBe(
      true,
    );
  });

  test("built + pull rejects synchronously BEFORE any execTool call", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "licenses-docker-built-"));
    await expect(
      collectDockerOsSbom(["local/scan-a"], {
        built: true,
        pull: true,
        tempDir,
      }),
    ).rejects.toThrow("built images are local-only and cannot be pulled");
    expect(invocations).toEqual([]);
  });
});
