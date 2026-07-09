import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";

import { imageTag, type ExecFn } from "../src/collectors/dockerBuild";
import {
  buildImages,
  dockerfileListing,
  resolveDiscoveredImages,
  runGenerateDockerSbom,
  safeLiveScanImages,
} from "../src/pipeline/dockerSbom";
import type { ExecOptions } from "../src/collectors/exec";

const tempRoots: string[] = [];

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "licenses-docker-disco-"));
  tempRoots.push(root);
  return root;
}

function writeFile(root: string, rel: string, content: string): void {
  const full = join(root, ...rel.split("/"));
  mkdirSync(join(full, ".."), { recursive: true });
  writeFileSync(full, content);
}

afterEach(() => {
  for (const root of tempRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("resolveDiscoveredImages (discovery build lane, NO docker, NO file reads)", () => {
  test("a [docker]-ignored Dockerfile is NEVER in the build set", () => {
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, "docker/dev/Dockerfile", "FROM ubuntu:24.04\n");

    const { build } = resolveDiscoveredImages(root, {
      dockerIgnore: ["docker/dev/**"],
    });
    // Every discovered (non-ignored) Dockerfile is a build input; the ignored
    // one contributes no build entry (T-13-10 name-pattern-only contract).
    expect(build.map((b) => b.identity)).toEqual(["backend/Dockerfile"]);
    expect(build.map((b) => b.tag)).toEqual([imageTag("backend/Dockerfile")]);
  });

  test("the summary names found Dockerfiles, their build tags, the ignored, and the build set", () => {
    const root = makeTempRoot();
    writeFile(root, "app/Dockerfile", "FROM alpine:3.20\n");
    writeFile(root, "svc/build.dockerfile", "FROM postgres:18\n");
    writeFile(root, "docker/dev/Dockerfile", "FROM ubuntu:24.04\n");

    const { summary } = resolveDiscoveredImages(root, {
      dockerIgnore: ["docker/dev/**"],
    });
    // Found files with their deterministic build tags.
    expect(summary).toContain(
      `app/Dockerfile -> ${imageTag("app/Dockerfile")}`,
    );
    expect(summary).toContain(
      `svc/build.dockerfile -> ${imageTag("svc/build.dockerfile")}`,
    );
    // The ignored dev Dockerfile is named as ignored, never built.
    expect(summary).toContain("docker/dev/Dockerfile");
    expect(summary).toContain("ignored");
    // The build set line enumerates the tags to build.
    expect(summary).toContain("build set (2):");
  });

  test("--exclude prunes a Dockerfile from the build set", () => {
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, "legacy/Dockerfile", "FROM node:18\n");

    const { build } = resolveDiscoveredImages(root, {
      excludes: ["legacy/**"],
    });
    expect(build.map((b) => b.identity)).toEqual(["backend/Dockerfile"]);
  });

  test("an all-ignored tree yields an EMPTY build set, announced in the summary", () => {
    const root = makeTempRoot();
    writeFile(root, "svc/Dockerfile", "FROM alpine:3.20\n");

    const { build, summary } = resolveDiscoveredImages(root, {
      dockerIgnore: ["**"],
    });
    expect(build).toEqual([]);
    expect(summary).toContain("build set is EMPTY");
  });
});

describe("safeLiveScanImages (image-lane ref hardening, #5/#8)", () => {
  test("drops empty/whitespace/dash-prefixed refs before they reach syft", () => {
    expect(
      safeLiveScanImages(["", "   ", "-rf", "--image", "postgres:18"]),
    ).toEqual(["postgres:18"]);
  });

  test("keeps clean refs verbatim and order-stable", () => {
    expect(safeLiveScanImages(["postgres:18", "nginx:stable-alpine"])).toEqual([
      "postgres:18",
      "nginx:stable-alpine",
    ]);
  });

  test("a wholly-unsafe set collapses to empty (loud-skip downstream)", () => {
    expect(safeLiveScanImages(["-x", "--y", "  "])).toEqual([]);
  });
});

describe("dockerfileListing (--list-dockerfiles, NO docker, NO writes)", () => {
  test("returns sorted repo-relative identities, excluding an ignored Dockerfile", () => {
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, "worker/build.dockerfile", "FROM alpine:3.20\n");
    writeFile(root, "ops/Dockerfile", "FROM ubuntu:24.04\n");

    const identities = dockerfileListing(root, {
      dockerIgnore: ["ops/**"],
    });
    expect(identities).toEqual([
      "backend/Dockerfile",
      "worker/build.dockerfile",
    ]);
  });

  test("returns [] for a tree with no Dockerfile name-matches", () => {
    const root = makeTempRoot();
    writeFile(root, "README.md", "nothing here\n");

    expect(dockerfileListing(root)).toEqual([]);
  });
});

describe("runGenerateDockerSbom (--list-dockerfiles API invariant)", () => {
  test("listDockerfiles without repoRoot throws instead of falling through", async () => {
    // The CLI conflict table pairs --list-dockerfiles with --repo-root at the
    // flag surface, but runGenerateDockerSbom is a public export: a
    // programmatic caller passing { listDockerfiles: true } alone must hit the
    // same invariant at the API boundary -- never fall through into a
    // build/scan lane (which would spawn docker/syft and overwrite the
    // committed SBOM). The temp baseDir/output confine any regression to this
    // test's sandbox.
    const root = makeTempRoot();
    await expect(
      runGenerateDockerSbom({
        listDockerfiles: true,
        baseDir: root,
        dockerOsSbomPath: join(root, "docker-os.sbom.json"),
      }),
    ).rejects.toThrow("--list-dockerfiles requires a repo root");
  });
});

describe("buildImages (buildx cwd threading)", () => {
  /** An exec recorder in the ExecFn shape that captures each opts.cwd. */
  function makeCwdRecorder(): {
    cwds: (string | undefined)[];
    exec: ExecFn;
  } {
    const cwds: (string | undefined)[] = [];
    const exec = (
      _cmd: string,
      _args: string[],
      opts: ExecOptions,
    ): Promise<{ stdout: string; stderr: string }> => {
      cwds.push(opts.cwd);
      return Promise.resolve({ stdout: "", stderr: "" });
    };
    return { cwds, exec };
  }

  test("discovery lane anchors every buildx spawn's cwd to the repo root", async () => {
    // The consumer bug: the discovery build lane ran buildx with no cwd, so the
    // repo-relative -f/context resolved against the tool's process cwd. When the
    // caller invokes from a subdir (e.g. tools/sbomlet with --repo-root ..) the
    // build failed with "unable to prepare context: path not found". buildImages
    // must thread the repo root into each spawn's cwd.
    const { cwds, exec } = makeCwdRecorder();
    const tags = await buildImages(
      ["backend/Dockerfile", "svc/build.dockerfile"],
      false,
      "/repo/root",
      exec,
    );
    expect(cwds).toEqual(["/repo/root", "/repo/root"]);
    // Tags remain a pure function of the identity — the cwd never touches argv.
    expect(tags).toEqual([
      imageTag("backend/Dockerfile"),
      imageTag("svc/build.dockerfile"),
    ]);
  });

  test("no cwd (explicit --dockerfile lane) leaves each spawn's cwd unset", async () => {
    // The targeted lane's paths are relative to the caller's own cwd, so
    // buildImages must NOT anchor them — spawn then inherits process.cwd().
    const { cwds, exec } = makeCwdRecorder();
    await buildImages(["a/Dockerfile"], false, undefined, exec);
    expect(cwds).toEqual([undefined]);
  });
});
