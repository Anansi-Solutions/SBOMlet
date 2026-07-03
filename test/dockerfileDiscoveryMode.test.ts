import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";

import {
  dockerfileListing,
  resolveDiscoveredImages,
  safeLiveScanImages,
} from "../src/pipeline/dockerSbom";

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

describe("resolveDiscoveredImages (discovery mode, NO docker)", () => {
  test("a [docker] ignore'd dev Dockerfile contributes NO image; only the app base is scanned", () => {
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, "docker/dev/Dockerfile", "FROM ubuntu:24.04\n");

    const { images } = resolveDiscoveredImages(root, {
      dockerIgnore: ["docker/dev/**"],
    });
    expect(images).toEqual(["node:22-slim"]);
  });

  test("explicit --image refs are unioned and deduped with discovered bases", () => {
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, "frontend/Dockerfile", "FROM node:22-slim\n");

    const { images } = resolveDiscoveredImages(root, {
      extraImages: ["postgres:18", "node:22-slim"],
    });
    // node:22-slim deduped across the two Dockerfiles AND the explicit flag.
    expect(images).toEqual(["node:22-slim", "postgres:18"]);
  });

  test("scratch and unresolved Dockerfiles contribute no image", () => {
    const root = makeTempRoot();
    writeFile(root, "app/Dockerfile", "FROM alpine:3.20\n");
    writeFile(root, "empty/Dockerfile", "FROM scratch\n");
    writeFile(root, "broken/Dockerfile", "FROM ${UNSET}\n");

    const { images } = resolveDiscoveredImages(root);
    expect(images).toEqual(["alpine:3.20"]);
  });

  test("the summary names found, ignored, resolved bases, scratch and unresolved", () => {
    const root = makeTempRoot();
    writeFile(root, "app/Dockerfile", "FROM alpine:3.20\n");
    writeFile(root, "empty/Dockerfile", "FROM scratch\n");
    writeFile(root, "broken/Dockerfile", "FROM ${UNSET}\n");
    writeFile(root, "docker/dev/Dockerfile", "FROM ubuntu:24.04\n");

    const { summary } = resolveDiscoveredImages(root, {
      dockerIgnore: ["docker/dev/**"],
    });
    expect(summary).toContain("app/Dockerfile");
    expect(summary).toContain("alpine:3.20");
    expect(summary).toContain("scratch");
    expect(summary).toContain("unresolved");
    // The ignored dev Dockerfile is named as ignored.
    expect(summary).toContain("docker/dev/Dockerfile");
  });

  test("finding #3: explicit --image refs are routed through sanitizeForLog in the summary", () => {
    // The summary line interpolating the explicit --image refs must sanitize
    // control characters (parity with the repoRoot line, which already uses
    // sanitizeForLog). A crafted ref carrying a control char must not appear
    // verbatim in the summary.
    const root = makeTempRoot();
    writeFile(root, "app/Dockerfile", "FROM alpine:3.20\n");
    const crafted = `evil${String.fromCharCode(7)}:1.0`; // embedded BEL (U+0007)
    const { summary } = resolveDiscoveredImages(root, {
      extraImages: [crafted, "postgres:18"],
    });
    const explicitLine = summary
      .split("\n")
      .find((l) => l.includes("explicit --image"));
    expect(explicitLine).toBeDefined();
    // The explicit --image summary line must NOT contain the raw control char…
    expect(explicitLine).not.toContain(String.fromCharCode(7));
    // …but the sanitized form (control char → space) is present, alongside the
    // clean postgres:18 ref.
    expect(explicitLine).toContain("evil :1.0");
    expect(explicitLine).toContain("postgres:18");
  });

  test("#8: an empty/whitespace/dash-prefixed extraImage is never added to the scan set", () => {
    const root = makeTempRoot();
    writeFile(root, "app/Dockerfile", "FROM alpine:3.20\n");
    // Defense-in-depth: even if a hostile/garbage explicit --image ref reaches
    // here, an empty, whitespace-only, or dash-prefixed ref is dropped — never
    // forwarded to syft as an operand (which could be parsed as a flag).
    const { images } = resolveDiscoveredImages(root, {
      extraImages: ["", "   ", "-rf", "--quiet", "postgres:18"],
    });
    expect(images).toEqual(["alpine:3.20", "postgres:18"]);
  });
});

describe("safeLiveScanImages (PURE live-scan --image hardening, finding #5)", () => {
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
