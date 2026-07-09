import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";

import { imageTag } from "../src/collectors/dockerBuild";
import { resolveTargetedDockerfiles } from "../src/pipeline/dockerSbom";

const tempRoots: string[] = [];

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "licenses-docker-target-"));
  tempRoots.push(root);
  return root;
}

/** Write `content` at `root/rel` and return the absolute path. */
function writeFile(root: string, rel: string, content: string): string {
  const full = join(root, ...rel.split("/"));
  mkdirSync(join(full, ".."), { recursive: true });
  writeFileSync(full, content);
  return full;
}

afterEach(() => {
  for (const root of tempRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("resolveTargetedDockerfiles (targeted build lane, NO docker, NO file reads)", () => {
  test("builds each named Dockerfile to its own deterministic tag, sorted by identity", () => {
    const root = makeTempRoot();
    // Two files with the SAME FROM: there is no base derivation any more, so
    // each named Dockerfile is a DISTINCT build input (no base dedup).
    const a = writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    const b = writeFile(root, "frontend/Dockerfile", "FROM node:22-slim\n");
    const c = writeFile(root, "db/Dockerfile", "FROM postgres:18\n");

    const { build } = resolveTargetedDockerfiles([
      { identity: "backend/Dockerfile", path: a },
      { identity: "frontend/Dockerfile", path: b },
      { identity: "db/Dockerfile", path: c },
    ]);
    // Sorted by identity; each file → its own imageTag (no base collapse).
    expect(build.map((x) => x.identity)).toEqual([
      "backend/Dockerfile",
      "db/Dockerfile",
      "frontend/Dockerfile",
    ]);
    expect(build.map((x) => x.tag)).toEqual([
      imageTag("backend/Dockerfile"),
      imageTag("db/Dockerfile"),
      imageTag("frontend/Dockerfile"),
    ]);
  });

  test("a repeated identity collapses to a single build (dedup by identity)", () => {
    const root = makeTempRoot();
    const a = writeFile(root, "app/Dockerfile", "FROM alpine:3.20\n");

    const { build } = resolveTargetedDockerfiles([
      { identity: "app/Dockerfile", path: a },
      { identity: "app/Dockerfile", path: a },
    ]);
    expect(build.map((x) => x.identity)).toEqual(["app/Dockerfile"]);
  });

  test("the summary names each targeted file, its build tag, and the build set", () => {
    const root = makeTempRoot();
    const a = writeFile(root, "app/Dockerfile", "FROM alpine:3.20\n");
    const b = writeFile(root, "db/Dockerfile", "FROM postgres:18\n");

    const { summary } = resolveTargetedDockerfiles([
      { identity: "app/Dockerfile", path: a },
      { identity: "db/Dockerfile", path: b },
    ]);
    expect(summary).toContain("building 2 targeted Dockerfile(s):");
    expect(summary).toContain(
      `app/Dockerfile -> ${imageTag("app/Dockerfile")}`,
    );
    expect(summary).toContain(`db/Dockerfile -> ${imageTag("db/Dockerfile")}`);
    expect(summary).toContain("build set (2):");
  });

  test("an empty targeted list yields an empty build set, announced", () => {
    const { build, summary } = resolveTargetedDockerfiles([]);
    expect(build).toEqual([]);
    expect(summary).toContain("build set is EMPTY");
  });

  test("the identity is routed through sanitizeForLog in the per-file line (control char neutralized)", () => {
    // --dockerfile input is caller-supplied, so a crafted identity carrying a
    // control char must not reach the stderr summary verbatim. The path is a
    // real file (fail-fast checks existence); only the identity is crafted.
    const root = makeTempRoot();
    const a = writeFile(root, "app/Dockerfile", "FROM alpine:3.20\n");
    const craftedIdentity = `app${String.fromCharCode(7)}/Dockerfile`; // embedded BEL

    const { summary } = resolveTargetedDockerfiles([
      { identity: craftedIdentity, path: a },
    ]);
    expect(summary).not.toContain(String.fromCharCode(7));
    expect(summary).toContain(
      `app /Dockerfile -> ${imageTag(craftedIdentity)}`,
    );
  });

  test("WR-07: the build-set summary line also routes the identity through sanitizeForLog", () => {
    // Parity with the per-file line above: the `build set (N): ...` line joins
    // the SAME caller-supplied identities, so a control char must not reach
    // stderr verbatim there either.
    const root = makeTempRoot();
    const a = writeFile(root, "app/Dockerfile", "FROM alpine:3.20\n");
    const craftedIdentity = `app${String.fromCharCode(7)}/Dockerfile`; // embedded BEL

    const { summary } = resolveTargetedDockerfiles([
      { identity: craftedIdentity, path: a },
    ]);
    const buildSetLine = summary
      .split("\n")
      .find((l) => l.includes("build set"));
    expect(buildSetLine).toBeDefined();
    expect(buildSetLine).not.toContain(String.fromCharCode(7));
    expect(buildSetLine).toContain("app /Dockerfile");
  });

  test("a missing/unreadable targeted path throws naming the path BEFORE any build (caller typo, fail fast)", () => {
    const root = makeTempRoot();
    const real = writeFile(root, "real/Dockerfile", "FROM alpine:3.20\n");
    const missing = join(root, "nope", "Dockerfile");

    expect(() =>
      resolveTargetedDockerfiles([
        { identity: "real/Dockerfile", path: real },
        { identity: "nope/Dockerfile", path: missing },
      ]),
    ).toThrow(missing);
  });
});
