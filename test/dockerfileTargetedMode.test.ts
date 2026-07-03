import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";

import { MAX_DOCKERFILE_BYTES } from "../src/collectors/dockerfile";
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

describe("resolveTargetedDockerfiles (targeted mode, NO docker)", () => {
  test("derives the shipped base of each named Dockerfile, deduped and sorted", () => {
    const root = makeTempRoot();
    const a = writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    const b = writeFile(root, "frontend/Dockerfile", "FROM node:22-slim\n");
    const c = writeFile(root, "db/Dockerfile", "FROM postgres:18\n");

    const { images } = resolveTargetedDockerfiles([
      { identity: "backend/Dockerfile", path: a },
      { identity: "frontend/Dockerfile", path: b },
      { identity: "db/Dockerfile", path: c },
    ]);
    // node:22-slim deduped across the two Dockerfiles; sorted by code units.
    expect(images).toEqual(["node:22-slim", "postgres:18"]);
  });

  test("explicit --image refs are unioned and deduped with the derived bases", () => {
    const root = makeTempRoot();
    const a = writeFile(root, "app/Dockerfile", "FROM node:22-slim\n");

    const { images } = resolveTargetedDockerfiles(
      [{ identity: "app/Dockerfile", path: a }],
      { extraImages: ["postgres:18", "node:22-slim"] },
    );
    expect(images).toEqual(["node:22-slim", "postgres:18"]);
  });

  test("scratch and unresolved Dockerfiles contribute no image", () => {
    const root = makeTempRoot();
    const a = writeFile(root, "app/Dockerfile", "FROM alpine:3.20\n");
    const s = writeFile(root, "empty/Dockerfile", "FROM scratch\n");
    const u = writeFile(root, "broken/Dockerfile", "FROM ${UNSET}\n");

    const { images } = resolveTargetedDockerfiles([
      { identity: "app/Dockerfile", path: a },
      { identity: "empty/Dockerfile", path: s },
      { identity: "broken/Dockerfile", path: u },
    ]);
    expect(images).toEqual(["alpine:3.20"]);
  });

  test("the summary names each targeted file and its resolved base / scratch / unresolved", () => {
    const root = makeTempRoot();
    const a = writeFile(root, "app/Dockerfile", "FROM alpine:3.20\n");
    const s = writeFile(root, "empty/Dockerfile", "FROM scratch\n");
    const u = writeFile(root, "broken/Dockerfile", "FROM ${UNSET}\n");

    const { summary } = resolveTargetedDockerfiles([
      { identity: "app/Dockerfile", path: a },
      { identity: "empty/Dockerfile", path: s },
      { identity: "broken/Dockerfile", path: u },
    ]);
    expect(summary).toContain("targeted 3 Dockerfile(s):");
    expect(summary).toContain("app/Dockerfile: alpine:3.20");
    expect(summary).toContain("empty/Dockerfile: scratch");
    expect(summary).toContain("broken/Dockerfile: unresolved:");
    expect(summary).toContain("scan set (1): alpine:3.20");
  });

  test("an empty scan set is announced (every file is scratch/unresolved)", () => {
    const root = makeTempRoot();
    const s = writeFile(root, "empty/Dockerfile", "FROM scratch\n");

    const { images, summary } = resolveTargetedDockerfiles([
      { identity: "empty/Dockerfile", path: s },
    ]);
    expect(images).toEqual([]);
    expect(summary).toContain("scan set is EMPTY");
  });

  test("the identity is routed through sanitizeForLog (control char neutralized)", () => {
    // --dockerfile input is caller-supplied, so a crafted identity carrying a
    // control char must not reach the stderr summary verbatim.
    const root = makeTempRoot();
    const a = writeFile(root, "app/Dockerfile", "FROM alpine:3.20\n");
    const craftedIdentity = `app${String.fromCharCode(7)}/Dockerfile`; // embedded BEL

    const { summary } = resolveTargetedDockerfiles([
      { identity: craftedIdentity, path: a },
    ]);
    expect(summary).not.toContain(String.fromCharCode(7));
    expect(summary).toContain("app /Dockerfile: alpine:3.20");
  });

  test("#8: an empty/whitespace/dash-prefixed extraImage is never added to the scan set", () => {
    const root = makeTempRoot();
    const a = writeFile(root, "app/Dockerfile", "FROM alpine:3.20\n");

    const { images } = resolveTargetedDockerfiles(
      [{ identity: "app/Dockerfile", path: a }],
      { extraImages: ["", "   ", "-rf", "--quiet", "postgres:18"] },
    );
    expect(images).toEqual(["alpine:3.20", "postgres:18"]);
  });

  test("a missing/unreadable targeted path throws naming the path (caller typo, fail fast)", () => {
    const root = makeTempRoot();
    const missing = join(root, "nope", "Dockerfile");

    expect(() =>
      resolveTargetedDockerfiles([
        { identity: "nope/Dockerfile", path: missing },
      ]),
    ).toThrow(missing);
  });

  test("an oversized Dockerfile loud-skips as unresolved rather than being parsed", () => {
    const root = makeTempRoot();
    // One byte over the cap — never read, surfaced unresolved in the summary.
    const big = writeFile(
      root,
      "huge/Dockerfile",
      "x".repeat(MAX_DOCKERFILE_BYTES + 1),
    );

    const { images, summary } = resolveTargetedDockerfiles([
      { identity: "huge/Dockerfile", path: big },
    ]);
    expect(images).toEqual([]);
    expect(summary).toContain("huge/Dockerfile: unresolved:");
    expect(summary).toContain("size cap");
  });
});
