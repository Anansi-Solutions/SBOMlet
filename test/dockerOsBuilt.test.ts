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

import {
  copyFileSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
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
import { runGenerateDockerSbom } from "../src/pipeline/dockerSbom";

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

/**
 * A per-image execTool stub: writes a distinct one-component doc keyed by the
 * scanned image ref (the last argv operand, after the `--` separator), so a
 * shared purl across two images can carry DIFFERENT license claims per image —
 * the adversarial-review Lens 2 probe (09-07). Only the syft invocation (argv
 * carrying "cyclonedx-json=<file>") writes; built collection never calls
 * docker inspect/pull, so every recorded invocation here is a syft scan.
 */
function makePerImageExecTool(
  licenseByImage: Readonly<Record<string, string>>,
): (
  cmd: string,
  args: string[],
) => Promise<{ stdout: string; stderr: string }> {
  return (cmd: string, args: string[]) => {
    invocations.push([cmd, ...args]);
    const cyclonedxArg = args.find((a) => a.startsWith("cyclonedx-json="));
    if (cyclonedxArg !== undefined) {
      const outFile = cyclonedxArg.slice("cyclonedx-json=".length);
      const image = args[args.length - 1] as string;
      const license = licenseByImage[image];
      const doc = {
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        components: [
          {
            type: "library",
            name: "shared",
            version: "1.0.0",
            purl: "pkg:npm/shared@1.0.0",
            licenses: [{ license: { id: license } }],
          },
        ],
      };
      writeFileSync(outFile, JSON.stringify(doc));
    }
    return Promise.resolve({ stdout: "[]", stderr: "" });
  };
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

  // Adversarial review (09-07), Lens 2: two built images sharing a purl with
  // DIFFERENT licenses — is the result order-dependent on the images argument?
  // filterOsComponents dedupes first-wins WITHIN one syft doc, but the
  // cross-image fold in collectDockerOsSbom walks `images` in the CALLER'S
  // order (unlike resolveDiscoveredImages/resolveTargetedDockerfiles, which
  // both compareCodeUnits-sort before scanning) — so the license claim
  // attached to a shared purl must be a pure function of the image SET, never
  // of argv order, for the committed artifact to stay byte-deterministic
  // (D-14) regardless of how a caller lists --built-image refs.
  test("a purl shared between two built images resolves the SAME license regardless of images argument order", async () => {
    const licenseByImage = {
      "local/scan-mit": "MIT",
      "local/scan-gpl": "GPL-3.0-only",
    };
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: makePerImageExecTool(licenseByImage),
    }));

    const tempDirAB = mkdtempSync(join(tmpdir(), "licenses-docker-built-"));
    const { doc: docAB } = await collectDockerOsSbom(
      ["local/scan-mit", "local/scan-gpl"],
      { built: true, tempDir: tempDirAB },
    );
    rmSync(tempDirAB, { recursive: true, force: true });

    const tempDirBA = mkdtempSync(join(tmpdir(), "licenses-docker-built-"));
    const { doc: docBA } = await collectDockerOsSbom(
      ["local/scan-gpl", "local/scan-mit"],
      { built: true, tempDir: tempDirBA },
    );
    rmSync(tempDirBA, { recursive: true, force: true });

    const licenseOf = (doc: string): unknown => {
      const parsed = JSON.parse(doc) as {
        components: {
          purl: string;
          licenses?: { license?: { id?: string } }[];
        }[];
      };
      const shared = parsed.components.find(
        (c) => c.purl === "pkg:npm/shared@1.0.0",
      );
      return shared?.licenses?.[0]?.license?.id;
    };

    expect(licenseOf(docAB)).toBe(licenseOf(docBA));

    // Restore the shared fixture-based stub for every subsequent test in this
    // file (beforeAll only runs once; each test after this one relies on the
    // fixture-copying fakeExecTool, not this test's per-image stub).
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: fakeExecTool,
    }));
  });
});

/**
 * The daemon-free end-to-end write test relocated from the removed
 * pre-made-SBOM ingest orchestrator suite (D-09 ADAPT): the outputPath-write contract
 * now rides the --image lane. A fake execTool copies the syft fixture for the
 * scan and returns a fixed RepoDigest for `docker inspect`, so
 * runGenerateDockerSbom writes a real committed doc with no docker daemon.
 */
describe("runGenerateDockerSbom end-to-end write (daemon-free, --image lane)", () => {
  const DIGEST_REF = "docker.io/library/scan-a@sha256:" + "a".repeat(64);

  function fakeImageExecTool(
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
      return Promise.resolve({ stdout: "", stderr: "" });
    }
    if (args[0] === "inspect") {
      return Promise.resolve({
        stdout: JSON.stringify([DIGEST_REF]),
        stderr: "",
      });
    }
    return Promise.resolve({ stdout: "", stderr: "" });
  }

  beforeAll(() => {
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: fakeImageExecTool,
    }));
  });

  afterAll(() => {
    mock.module("../src/collectors/exec", () => REAL_EXEC);
  });

  afterEach(() => {
    invocations = [];
  });

  test("writes the committed doc via the --image lane, digest-pinned, LF-only", async () => {
    const outDir = mkdtempSync(join(tmpdir(), "licenses-docker-image-e2e-"));
    try {
      await runGenerateDockerSbom({
        images: ["scan-a"],
        dockerOsSbomPath: "docker-os.sbom.json",
        baseDir: outDir,
      });
      const written = readFileSync(join(outDir, "docker-os.sbom.json"), "utf8");
      const parsed = JSON.parse(written) as {
        components: { purl: string }[];
        dockerImages: { image: string; digest: string }[];
      };
      // The outputPath-write contract: a real committed doc lands at the
      // base-dir-resolved path, digest-pinned, LF-only.
      expect(parsed.dockerImages).toEqual([
        { image: "scan-a", digest: DIGEST_REF },
      ]);
      expect(parsed.components.length).toBeGreaterThan(0);
      expect(written.includes("\r")).toBe(false);
    } finally {
      rmSync(outDir, { recursive: true, force: true });
    }
  });
});
