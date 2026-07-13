/**
 * Subprocess-free orchestration tests for the single collection posture: every
 * image scan reads FULL contents, resolves a RepoDigest when present and records
 * digest "" when absent (a local-only / never-pushed image), and pulls only when
 * the ref is not already present locally (probe-first). A locally present ref is
 * never re-pulled — the never-race-the-network determinism posture.
 *
 * Isolated from dockerOs.test.ts (which stays un-mocked) because this file
 * replaces execTool via mock.module — the cli.test.ts precedent, restored in
 * afterAll so no other suite observes the stub.
 */

import {
  copyFileSync,
  mkdirSync,
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
import { imageTag } from "../src/collectors/dockerBuild";
import { compareCodeUnits } from "../src/model/dependencies";

/** Original exec export captured BEFORE any mock.module call (restore target). */
const REAL_EXEC = { ...execModule };

/** The trimmed real-syft capture the scan reads back (apk + npm + pypi). */
const FIXTURE = join(__dirname, "fixtures", "syft-built-trimmed.json");

/** Two-Dockerfile scenario captures: busybox SHARED, musl/zlib image-unique. */
const FIXTURE_A = join(__dirname, "fixtures", "syft-built-imagea-trimmed.json");
const FIXTURE_B = join(__dirname, "fixtures", "syft-built-imageb-trimmed.json");

type ExecResult = { stdout: string; stderr: string };
type ExecFn = (cmd: string, args: string[]) => Promise<ExecResult>;

/** Every recorded execTool invocation: [cmd, ...args]. */
let invocations: string[][] = [];

/** The syft output-target operand a `cyclonedx-json=<file>` argv carries, else undefined. */
function syftOutFile(args: string[]): string | undefined {
  const arg = args.find((a) => a.startsWith("cyclonedx-json="));
  return arg === undefined ? undefined : arg.slice("cyclonedx-json=".length);
}

/**
 * The default recorder: copies the fixture for a syft scan and resolves every
 * docker call with an EMPTY RepoDigests array ("[]") — i.e. the image is present
 * locally (inspect exit 0) but carries no RepoDigests, so the digest resolves to
 * "" (a local-only / never-pushed image). No pull is ever needed.
 */
function fakeExecTool(cmd: string, args: string[]): Promise<ExecResult> {
  invocations.push([cmd, ...args]);
  const outFile = syftOutFile(args);
  if (outFile !== undefined) {
    copyFileSync(FIXTURE, outFile);
    return Promise.resolve({ stdout: "", stderr: "" });
  }
  return Promise.resolve({ stdout: "[]", stderr: "" });
}

/**
 * A recorder that reports the image as present (inspect exit 0) and pins a fixed
 * RepoDigest — the generalized "RepoDigests present" posture.
 */
function makePinnedExec(digestRef: string): ExecFn {
  return (cmd, args) => {
    invocations.push([cmd, ...args]);
    const outFile = syftOutFile(args);
    if (outFile !== undefined) {
      copyFileSync(FIXTURE, outFile);
      return Promise.resolve({ stdout: "", stderr: "" });
    }
    if (args[0] === "inspect") {
      return Promise.resolve({
        stdout: JSON.stringify([digestRef]),
        stderr: "",
      });
    }
    return Promise.resolve({ stdout: "", stderr: "" });
  };
}

/**
 * A stateful recorder: `docker inspect` FAILS (nonzero exit → the probe reads it
 * as absent) until the image has been pulled; after the pull it succeeds and
 * pins the digest. Models an absent ref that the probe-first path must pull
 * before scanning.
 */
function makeAbsentThenPresentExec(digestRef: string): ExecFn {
  const pulled = new Set<string>();
  return (cmd, args) => {
    invocations.push([cmd, ...args]);
    const outFile = syftOutFile(args);
    if (outFile !== undefined) {
      copyFileSync(FIXTURE, outFile);
      return Promise.resolve({ stdout: "", stderr: "" });
    }
    const image = args[args.length - 1] as string;
    if (args[0] === "inspect") {
      if (!pulled.has(image)) {
        return Promise.reject(new Error("docker inspect: No such object"));
      }
      return Promise.resolve({
        stdout: JSON.stringify([digestRef]),
        stderr: "",
      });
    }
    if (args[0] === "pull") {
      pulled.add(image);
      return Promise.resolve({ stdout: "", stderr: "" });
    }
    return Promise.resolve({ stdout: "", stderr: "" });
  };
}

/**
 * A recorder where the ref is absent (inspect fails) AND the implicit pull fails
 * too — nothing can be scanned. The error must surface and
 * digest resolution must never run (no "" masking a typo'd ref).
 */
function makeFailingPullExec(): ExecFn {
  return (cmd, args) => {
    invocations.push([cmd, ...args]);
    if (args[0] === "inspect") {
      return Promise.reject(new Error("docker inspect: No such object"));
    }
    if (args[0] === "pull") {
      return Promise.reject(new Error("docker pull: access denied"));
    }
    return Promise.resolve({ stdout: "", stderr: "" });
  };
}

/**
 * A per-image recorder: writes a distinct one-component doc keyed by the scanned
 * image ref (the last argv operand), so a shared purl across two images can carry
 * DIFFERENT license claims per image — a review probe for silent cross-image claim mixing. Every
 * docker call resolves with "[]" (present, digest "").
 */
function makePerImageExecTool(
  licenseByImage: Readonly<Record<string, string>>,
): ExecFn {
  return (cmd, args) => {
    invocations.push([cmd, ...args]);
    const outFile = syftOutFile(args);
    if (outFile !== undefined) {
      const image = args[args.length - 1] as string;
      const doc = {
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        components: [
          {
            type: "library",
            name: "shared",
            version: "1.0.0",
            purl: "pkg:npm/shared@1.0.0",
            licenses: [{ license: { id: licenseByImage[image] } }],
          },
        ],
      };
      writeFileSync(outFile, JSON.stringify(doc));
      return Promise.resolve({ stdout: "", stderr: "" });
    }
    return Promise.resolve({ stdout: "[]", stderr: "" });
  };
}

/**
 * A per-image FIXTURE recorder for the two-Dockerfile scenario: serves a
 * distinct trimmed syft capture keyed by the scanned image operand (the last
 * argv element), so two built images can carry overlapping-but-different
 * package sets. docker buildx build argvs resolve with empty stdout/stderr;
 * inspects return "[]" (a built image carries no RepoDigests).
 */
function makeFixtureByImageExec(
  fixtureByImage: Readonly<Record<string, string>>,
): ExecFn {
  return (cmd, args) => {
    invocations.push([cmd, ...args]);
    const outFile = syftOutFile(args);
    if (outFile !== undefined) {
      const image = args[args.length - 1] as string;
      const fixture = fixtureByImage[image];
      if (fixture === undefined) {
        return Promise.reject(new Error(`unexpected syft operand: ${image}`));
      }
      copyFileSync(fixture, outFile);
      return Promise.resolve({ stdout: "", stderr: "" });
    }
    if (args[0] === "buildx") {
      return Promise.resolve({ stdout: "", stderr: "" });
    }
    return Promise.resolve({ stdout: "[]", stderr: "" });
  };
}

/** The active recorder for the current test; reset to fakeExecTool after each. */
let currentExec: ExecFn = fakeExecTool;

function dispatchExec(cmd: string, args: string[]): Promise<ExecResult> {
  return currentExec(cmd, args);
}

describe("collectDockerOsSbom one posture (full contents, generalized digest, probe-first pull)", () => {
  let tempDir: string | undefined;

  beforeAll(() => {
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: dispatchExec,
    }));
  });

  afterAll(() => {
    mock.module("../src/collectors/exec", () => REAL_EXEC);
  });

  afterEach(() => {
    invocations = [];
    currentExec = fakeExecTool;
    if (tempDir !== undefined)
      rmSync(tempDir, { recursive: true, force: true });
    tempDir = undefined;
  });

  const argvStrings = (): string[] => invocations.map((argv) => argv.join(" "));

  /** Ref-only scan pairs: the image lane's posture, where source === image. */
  const refs = (...images: string[]): { image: string; source: string }[] =>
    images.map((image) => ({ image, source: image }));

  test('records {image, digest:"", source} for local-only images (absent RepoDigests), sorted, with NO pull argv', async () => {
    tempDir = mkdtempSync(join(tmpdir(), "licenses-docker-posture-"));
    const { doc } = await collectDockerOsSbom(
      refs("local/scan-b", "local/scan-a"),
      {
        tempDir,
      },
    );
    const parsed = JSON.parse(doc) as {
      dockerImages: { image: string; digest: string; source: string }[];
    };
    // Absent RepoDigests → the generalized digest-less identity, sorted by image.
    expect(parsed.dockerImages).toEqual([
      { image: "local/scan-a", digest: "", source: "local/scan-a" },
      { image: "local/scan-b", digest: "", source: "local/scan-b" },
    ]);
    // The present-probe means inspect IS used, but nothing is ever pulled.
    expect(argvStrings().some((s) => s.includes("pull"))).toBe(false);
  });

  test("reads FULL image contents — a pkg:npm component survives alongside apk", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "licenses-docker-posture-"));
    const { doc } = await collectDockerOsSbom(refs("local/scan-a"), {
      tempDir,
    });
    const parsed = JSON.parse(doc) as { components: { purl: string }[] };
    expect(parsed.components.some((c) => c.purl.startsWith("pkg:npm/"))).toBe(
      true,
    );
    expect(parsed.components.some((c) => c.purl.startsWith("pkg:apk/"))).toBe(
      true,
    );
  });

  test("a locally-present image is probed and scanned as-is, never pulled", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "licenses-docker-posture-"));
    await collectDockerOsSbom(refs("local/scan-a"), { tempDir });
    const argv = argvStrings();
    // The presence probe ran (inspect) and the scan ran (syft), but no pull.
    expect(argv.some((s) => s.includes("inspect"))).toBe(true);
    expect(argv.some((s) => s.includes("cyclonedx-json="))).toBe(true);
    expect(argv.some((s) => s.includes("pull"))).toBe(false);
  });

  test("present RepoDigests pin the digest via selectDigest (generalized posture)", async () => {
    const digestRef = "docker.io/library/scan-a@sha256:" + "a".repeat(64);
    currentExec = makePinnedExec(digestRef);
    tempDir = mkdtempSync(join(tmpdir(), "licenses-docker-posture-"));
    const { doc } = await collectDockerOsSbom(
      refs("docker.io/library/scan-a"),
      {
        tempDir,
      },
    );
    const parsed = JSON.parse(doc) as {
      dockerImages: { image: string; digest: string; source: string }[];
    };
    expect(parsed.dockerImages).toEqual([
      {
        image: "docker.io/library/scan-a",
        digest: digestRef,
        source: "docker.io/library/scan-a",
      },
    ]);
    expect(argvStrings().some((s) => s.includes("pull"))).toBe(false);
  });

  test("an absent ref is pulled then scanned (probe-first): pull argv precedes the syft scan", async () => {
    const digestRef = "registry.example.com/absent@sha256:" + "b".repeat(64);
    currentExec = makeAbsentThenPresentExec(digestRef);
    tempDir = mkdtempSync(join(tmpdir(), "licenses-docker-posture-"));
    const { doc } = await collectDockerOsSbom(
      refs("registry.example.com/absent:1"),
      {
        tempDir,
      },
    );
    const argv = argvStrings();
    const firstPull = argv.findIndex((s) => s.includes("pull"));
    const firstScan = argv.findIndex((s) => s.includes("cyclonedx-json="));
    // The pull happened, before the scan (the image is fetched, then inventoried).
    expect(firstPull).toBeGreaterThanOrEqual(0);
    expect(firstScan).toBeGreaterThan(firstPull);
    // After the pull the image is present, so its RepoDigest pins.
    const parsed = JSON.parse(doc) as {
      dockerImages: { image: string; digest: string }[];
    };
    expect(parsed.dockerImages[0]?.digest).toBe(digestRef);
  });

  test("a ref whose implicit pull fails throws before any scan — digest is never reached", async () => {
    currentExec = makeFailingPullExec();
    tempDir = mkdtempSync(join(tmpdir(), "licenses-docker-posture-"));
    await expect(
      collectDockerOsSbom(refs("registry.example.com/typo"), { tempDir }),
    ).rejects.toThrow();
    // The scan never ran, so no "" digest could ever mask a typo'd ref.
    expect(argvStrings().some((s) => s.includes("cyclonedx-json="))).toBe(
      false,
    );
  });

  // Two images sharing a purl with DIFFERENT
  // licenses — the license claim attached to a shared purl must be a pure
  // function of the image SET, never of argument order, for byte-determinism.
  test("a purl shared between two images resolves the SAME license regardless of argument order", async () => {
    const licenseByImage = {
      "local/scan-mit": "MIT",
      "local/scan-gpl": "GPL-3.0-only",
    };
    currentExec = makePerImageExecTool(licenseByImage);

    const dirAB = mkdtempSync(join(tmpdir(), "licenses-docker-posture-"));
    const { doc: docAB } = await collectDockerOsSbom(
      refs("local/scan-mit", "local/scan-gpl"),
      { tempDir: dirAB },
    );
    rmSync(dirAB, { recursive: true, force: true });

    const dirBA = mkdtempSync(join(tmpdir(), "licenses-docker-posture-"));
    const { doc: docBA } = await collectDockerOsSbom(
      refs("local/scan-gpl", "local/scan-mit"),
      { tempDir: dirBA },
    );
    rmSync(dirBA, { recursive: true, force: true });

    const licenseOf = (doc: string): unknown => {
      const parsed = JSON.parse(doc) as {
        components: {
          purl: string;
          licenses?: { license?: { id?: string } }[];
        }[];
      };
      return parsed.components.find((c) => c.purl === "pkg:npm/shared@1.0.0")
        ?.licenses?.[0]?.license?.id;
    };

    expect(licenseOf(docAB)).toBe(licenseOf(docBA));
  });

  // The daemon-free end-to-end write test relocated from the removed
  // pre-made-SBOM ingest suite, adapted: the outputPath-write contract now
  // rides the --image lane through the orchestrator.
  test("runGenerateDockerSbom writes the committed doc via the --image lane, digest-pinned, LF-only", async () => {
    const digestRef = "docker.io/library/scan-a@sha256:" + "c".repeat(64);
    currentExec = makePinnedExec(digestRef);
    const outDir = mkdtempSync(join(tmpdir(), "licenses-docker-image-e2e-"));
    try {
      await runGenerateDockerSbom({
        images: ["docker.io/library/scan-a"],
        dockerSbomPath: "docker.sbom.json",
        baseDir: outDir,
      });
      const written = readFileSync(join(outDir, "docker.sbom.json"), "utf8");
      const parsed = JSON.parse(written) as {
        components: { purl: string }[];
        dockerImages: { image: string; digest: string; source: string }[];
      };
      // Image lane: the source identity is the requested ref VERBATIM.
      expect(parsed.dockerImages).toEqual([
        {
          image: "docker.io/library/scan-a",
          digest: digestRef,
          source: "docker.io/library/scan-a",
        },
      ]);
      expect(parsed.components.length).toBeGreaterThan(0);
      expect(written.includes("\r")).toBe(false);
    } finally {
      rmSync(outDir, { recursive: true, force: true });
    }
  });

  // --- Build lanes: --dockerfile and --repo-root build then scan ---

  test("--dockerfile lane builds each named Dockerfile via buildx and scans the built tags, digest-less and sorted", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "licenses-docker-dockerfile-"));
    writeFileSync(join(tempDir, "a.Dockerfile"), "FROM alpine:3.20\n");
    writeFileSync(join(tempDir, "b.Dockerfile"), "FROM node:22-slim\n");
    const out = join(tempDir, "docker.sbom.json");

    await runGenerateDockerSbom({
      dockerfilePaths: ["a.Dockerfile", "b.Dockerfile"],
      baseDir: tempDir,
      dockerSbomPath: out,
    });

    const argv = argvStrings();
    // Each Dockerfile was built (buildx build -f <path> -t <tag> <context>).
    expect(
      argv.some(
        (s) => s.includes("buildx build") && s.includes("a.Dockerfile"),
      ),
    ).toBe(true);
    expect(
      argv.some(
        (s) => s.includes("buildx build") && s.includes("b.Dockerfile"),
      ),
    ).toBe(true);
    // The two deterministic tags were scanned, digest-less (a built image has
    // no RepoDigests), sorted by image.
    const doc = JSON.parse(readFileSync(out, "utf8")) as {
      dockerImages: { image: string; digest: string; source: string }[];
    };
    // Built posture: each entry's source is the Dockerfile identity the tag
    // was built from — the caller-supplied path string, never the tag itself.
    const expected = [
      { identity: "a.Dockerfile", tag: imageTag("a.Dockerfile") },
      { identity: "b.Dockerfile", tag: imageTag("b.Dockerfile") },
    ]
      .sort((x, y) => compareCodeUnits(x.tag, y.tag))
      .map(({ identity, tag }) => ({
        image: tag,
        digest: "",
        source: identity,
      }));
    expect(doc.dockerImages).toEqual(expected);
  });

  test("--dockerfile lane throws naming a missing path BEFORE any build argv is recorded", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "licenses-docker-dockerfile-"));
    writeFileSync(join(tempDir, "real.Dockerfile"), "FROM alpine:3.20\n");
    const out = join(tempDir, "docker.sbom.json");

    await expect(
      runGenerateDockerSbom({
        dockerfilePaths: ["real.Dockerfile", "missing.Dockerfile"],
        baseDir: tempDir,
        dockerSbomPath: out,
      }),
    ).rejects.toThrow("missing.Dockerfile");
    // Fail-fast: no build ran.
    expect(argvStrings().some((s) => s.includes("buildx"))).toBe(false);
  });

  test("--repo-root lane builds each discovered Dockerfile from its DISCOVERY IDENTITY, then scans (committed-identity stability)", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "licenses-docker-discovery-"));
    mkdirSync(join(tempDir, "svc"), { recursive: true });
    writeFileSync(join(tempDir, "svc", "Dockerfile"), "FROM alpine:3.20\n");
    const out = join(tempDir, "docker.sbom.json");

    await runGenerateDockerSbom({
      repoRoot: tempDir,
      baseDir: tempDir,
      dockerSbomPath: out,
    });

    // The build -f operand is the discovery identity string (forward-slash).
    const argv = argvStrings();
    expect(
      argv.some(
        (s) => s.includes("buildx build") && s.includes("svc/Dockerfile"),
      ),
    ).toBe(true);
    // The tag scanned equals imageTag of the DISCOVERY identity — the exact
    // string that produces today's committed sidecar identity.
    const tag = imageTag("svc/Dockerfile");
    const doc = JSON.parse(readFileSync(out, "utf8")) as {
      dockerImages: { image: string; digest: string; source: string }[];
    };
    // Discovery posture: the source is the repo-relative discovery identity —
    // the exact string --list-dockerfiles prints.
    expect(doc.dockerImages).toEqual([
      { image: tag, digest: "", source: "svc/Dockerfile" },
    ]);
  });

  test("--repo-root lane: a [docker]-ignored Dockerfile NEVER receives a build argv (Q4-new 5)", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "licenses-docker-discovery-"));
    mkdirSync(join(tempDir, "keep"), { recursive: true });
    mkdirSync(join(tempDir, "skip"), { recursive: true });
    writeFileSync(join(tempDir, "keep", "Dockerfile"), "FROM alpine:3.20\n");
    writeFileSync(join(tempDir, "skip", "Dockerfile"), "FROM node:22-slim\n");
    writeFileSync(
      join(tempDir, "policy.toml"),
      '[docker]\nignore = ["skip/**"]\n',
    );
    const out = join(tempDir, "docker.sbom.json");

    await runGenerateDockerSbom({
      repoRoot: tempDir,
      baseDir: tempDir,
      policyPath: "policy.toml",
      dockerSbomPath: out,
    });

    const argv = argvStrings();
    expect(
      argv.some(
        (s) => s.includes("buildx build") && s.includes("keep/Dockerfile"),
      ),
    ).toBe(true);
    // The ignored Dockerfile is never handed to a build.
    expect(argv.some((s) => s.includes("skip/Dockerfile"))).toBe(false);
  });

  test("--repo-root lane throws (loud) when every discovered Dockerfile is [docker]-ignored — empty build set, no build", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "licenses-docker-discovery-"));
    mkdirSync(join(tempDir, "svc"), { recursive: true });
    writeFileSync(join(tempDir, "svc", "Dockerfile"), "FROM alpine:3.20\n");
    writeFileSync(join(tempDir, "policy.toml"), '[docker]\nignore = ["**"]\n');
    const out = join(tempDir, "docker.sbom.json");

    await expect(
      runGenerateDockerSbom({
        repoRoot: tempDir,
        baseDir: tempDir,
        policyPath: "policy.toml",
        dockerSbomPath: out,
      }),
    ).rejects.toThrow(/ignored/);
    expect(argvStrings().some((s) => s.includes("buildx"))).toBe(false);
  });

  test("a build lane write is byte-identical on a double run (determinism, Q4-new 10)", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "licenses-docker-discovery-"));
    mkdirSync(join(tempDir, "svc"), { recursive: true });
    writeFileSync(join(tempDir, "svc", "Dockerfile"), "FROM alpine:3.20\n");
    const out1 = join(tempDir, "one.sbom.json");
    const out2 = join(tempDir, "two.sbom.json");

    await runGenerateDockerSbom({
      repoRoot: tempDir,
      baseDir: tempDir,
      dockerSbomPath: out1,
    });
    await runGenerateDockerSbom({
      repoRoot: tempDir,
      baseDir: tempDir,
      dockerSbomPath: out2,
    });

    const a = readFileSync(out1, "utf8");
    const b = readFileSync(out2, "utf8");
    expect(a).toBe(b);
    expect(a.includes("\r")).toBe(false);
  });

  // The two-Dockerfile scenario, collector half: two Dockerfiles
  // build two images that SHARE busybox while musl/zlib are image-unique. The
  // sidecar must say which image(s) each package is in, and each image's
  // source must be its discovery identity — the substrate that makes "where"
  // expressible for images at all.
  test("two discovered Dockerfiles: shared purls union membership; sources are the discovery identities", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "licenses-docker-two-dockerfiles-"));
    mkdirSync(join(tempDir, "a"), { recursive: true });
    mkdirSync(join(tempDir, "b"), { recursive: true });
    // Runtime-only build inputs — contents irrelevant (the build is faked).
    writeFileSync(join(tempDir, "a", "Dockerfile"), "FROM alpine:3.23\n");
    writeFileSync(join(tempDir, "b", "Dockerfile"), "FROM alpine:3.23\n");
    const tagA = imageTag("a/Dockerfile");
    const tagB = imageTag("b/Dockerfile");
    currentExec = makeFixtureByImageExec({
      [tagA]: FIXTURE_A,
      [tagB]: FIXTURE_B,
    });
    const out = join(tempDir, "docker.sbom.json");

    await runGenerateDockerSbom({
      repoRoot: tempDir,
      baseDir: tempDir,
      dockerSbomPath: out,
    });

    const doc = JSON.parse(readFileSync(out, "utf8")) as {
      components: { name: string; images: string[] }[];
      dockerImages: { image: string; digest: string; source: string }[];
    };
    const membership = (name: string): string[] | undefined =>
      doc.components.find((c) => c.name === name)?.images;
    // busybox is in BOTH images: one row, membership unioned and sorted...
    expect(membership("busybox")).toEqual([tagA, tagB].sort(compareCodeUnits));
    expect(doc.components.filter((c) => c.name === "busybox")).toHaveLength(1);
    // ...while musl/zlib are honestly image-unique.
    expect(membership("musl")).toEqual([tagA]);
    expect(membership("zlib")).toEqual([tagB]);
    // Each built image records its Dockerfile identity as the source (built
    // posture: digest ""), sorted by image.
    const expected = [
      { identity: "a/Dockerfile", tag: tagA },
      { identity: "b/Dockerfile", tag: tagB },
    ]
      .sort((x, y) => compareCodeUnits(x.tag, y.tag))
      .map(({ identity, tag }) => ({
        image: tag,
        digest: "",
        source: identity,
      }));
    expect(doc.dockerImages).toEqual(expected);
  });

  test("pair input order never changes the emitted bytes (sorted-scan determinism with sources)", async () => {
    const imageA = "local/scan-imagea";
    const imageB = "local/scan-imageb";
    currentExec = makeFixtureByImageExec({
      [imageA]: FIXTURE_A,
      [imageB]: FIXTURE_B,
    });
    const pairs = [
      { image: imageA, source: "a/Dockerfile" },
      { image: imageB, source: "b/Dockerfile" },
    ];

    const dirAB = mkdtempSync(join(tmpdir(), "licenses-docker-posture-"));
    const { doc: docAB } = await collectDockerOsSbom(pairs, {
      tempDir: dirAB,
    });
    rmSync(dirAB, { recursive: true, force: true });

    const dirBA = mkdtempSync(join(tmpdir(), "licenses-docker-posture-"));
    const { doc: docBA } = await collectDockerOsSbom([...pairs].reverse(), {
      tempDir: dirBA,
    });
    rmSync(dirBA, { recursive: true, force: true });

    expect(docAB).toBe(docBA);
  });
});
