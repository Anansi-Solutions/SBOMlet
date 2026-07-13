import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";

import {
  discoverDockerfiles,
  isDockerfileName,
} from "../src/collectors/dockerfile";

// Self-contained temp trees only — no reference to any host-project path.
const tempRoots: string[] = [];

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "licenses-dockerfile-"));
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

// ---------------------------------------------------------------------------
// discoverDockerfiles — a listing-only walk that reuses the exact lockfile
// exclusion set. Discovery reads NO file contents; every match is LISTED (built
// or [docker]-ignored), never silently dropped and never parsed.
// ---------------------------------------------------------------------------

describe("discoverDockerfiles", () => {
  test("finds real Dockerfiles at any depth, excludes node_modules/.terraform", () => {
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, "frontend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, "docker/nginx.Dockerfile", "FROM nginx:stable-alpine\n");
    // Vendored / dependency Dockerfiles that must NEVER be found:
    writeFile(
      root,
      "infrastructure/.terraform/modules/x/Dockerfile",
      "FROM ubuntu\n",
    );
    writeFile(
      root,
      "frontend/node_modules/swagger2openapi/Dockerfile",
      "FROM node\n",
    );

    const result = discoverDockerfiles(root);
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "backend/Dockerfile",
      "docker/nginx.Dockerfile",
      "frontend/Dockerfile",
    ]);
  });

  test("matches *.Dockerfile, Dockerfile.*, *.dockerfile basenames (case-insensitive stem)", () => {
    const root = makeTempRoot();
    writeFile(root, "a/Dockerfile", "FROM x\n");
    writeFile(root, "b/app.Dockerfile", "FROM x\n");
    writeFile(root, "c/Dockerfile.prod", "FROM x\n");
    writeFile(root, "d/build.dockerfile", "FROM x\n");
    writeFile(root, "e/notADockerfile.txt", "nope\n");

    const result = discoverDockerfiles(root);
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "a/Dockerfile",
      "b/app.Dockerfile",
      "c/Dockerfile.prod",
      "d/build.dockerfile",
    ]);
  });

  test("isDockerfileName matches name patterns WITHOUT an extension blocklist (#4)", () => {
    // The blocklist is REMOVED: real variants Dockerfile.go/.py/.rs/.sh/.bak
    // must NOT be silently dropped. Name-pattern matching is the only rule; a
    // matched non-Dockerfile is LISTED (never silently dropped). So
    // Dockerfile.<anything> matches.
    expect(isDockerfileName("Dockerfile.go")).toBe(true);
    expect(isDockerfileName("Dockerfile.py")).toBe(true);
    expect(isDockerfileName("Dockerfile.rs")).toBe(true);
    expect(isDockerfileName("Dockerfile.sh")).toBe(true);
    expect(isDockerfileName("Dockerfile.bak")).toBe(true);
    // The tool's own dockerfile.ts now matches by name too — it is excluded
    // from discovery via toolDir, not via a name blocklist.
    expect(isDockerfileName("dockerfile.ts")).toBe(true);
    expect(isDockerfileName("dockerfile.test.ts")).toBe(true);
    // Real build variants still match.
    expect(isDockerfileName("Dockerfile.prod")).toBe(true);
    expect(isDockerfileName("Dockerfile.dev")).toBe(true);
    expect(isDockerfileName("Dockerfile")).toBe(true);
    expect(isDockerfileName("app.Dockerfile")).toBe(true);
    expect(isDockerfileName("build.dockerfile")).toBe(true);
    // A file merely CONTAINING dockerfile is still NOT matched.
    expect(isDockerfileName("notADockerfile.txt")).toBe(false);
    expect(isDockerfileName("readme.md")).toBe(false);
  });

  test("#4: a Dockerfile.go name-match IS listed (the .go suffix is not blocklisted)", () => {
    const root = makeTempRoot();
    // Name-pattern only (.go suffix is not blocklisted), independent of the
    // parent dir. Discovery lists it; the build lane handles it.
    writeFile(root, "ci/Dockerfile.go", "FROM golang:1.22-alpine\n");
    const result = discoverDockerfiles(root);
    expect(result.dockerfiles.map((d) => d.identity)).toContain(
      "ci/Dockerfile.go",
    );
  });

  test("#5: a matched non-Dockerfile is LISTED, never silently dropped (name-pattern-only contract)", () => {
    const root = makeTempRoot();
    writeFile(root, "app/Dockerfile", "FROM alpine:3.20\n");
    // A stray matched name is LISTED (contents are never read); it is a build
    // input that either builds or is [docker]-ignored — never silently dropped.
    writeFile(root, "tools/dockerfile.ts", "export const x = 1;\n");
    const result = discoverDockerfiles(root);
    const identities = result.dockerfiles.map((d) => d.identity);
    expect(identities).toContain("tools/dockerfile.ts");
    expect(identities).toContain("app/Dockerfile");
  });

  test("#6: the tool's OWN directory is excluded when toolDir is set", () => {
    const root = makeTempRoot();
    writeFile(root, "app/Dockerfile", "FROM alpine:3.20\n");
    // Simulate the tool living under src/collectors with its own dockerfile.ts.
    writeFile(
      root,
      "tool/src/collectors/dockerfile.ts",
      "export const x = 1;\n",
    );
    writeFile(root, "tool/src/collectors/dockerfile.test.ts", "test();\n");

    const toolDir = join(root, "tool");
    const result = discoverDockerfiles(root, { toolDir });
    // The tool dir subtree is pruned; only the consumer Dockerfile remains.
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "app/Dockerfile",
    ]);
  });

  test("only dist/ is pruned; build/out/target/vendor Dockerfiles ARE discovered", () => {
    // build/out/target/vendor are generic source names (an earlier over-broad
    // prune was reverted); only the documented dist/ build-output dir stays excluded.
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, "dist/Dockerfile", "FROM node:22\n");
    writeFile(root, "build/Dockerfile", "FROM node:22\n");
    writeFile(root, "out/Dockerfile", "FROM node:22\n");
    writeFile(root, "target/Dockerfile", "FROM node:22\n");
    writeFile(root, "vendor/Dockerfile", "FROM node:22\n");

    const result = discoverDockerfiles(root);
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "backend/Dockerfile",
      "build/Dockerfile",
      "out/Dockerfile",
      "target/Dockerfile",
      "vendor/Dockerfile",
    ]);
  });

  test("#3: a Dockerfile under Node_Modules/ (mixed case) is excluded on Windows", () => {
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, "Node_Modules/dep/Dockerfile", "FROM node\n");
    writeFile(root, "NODE_MODULES/dep/Dockerfile", "FROM node\n");
    writeFile(root, "Dist/Dockerfile", "FROM node\n");

    const result = discoverDockerfiles(root);
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "backend/Dockerfile",
    ]);
  });

  test("#4: Dockerfiles under .docker/ and .devcontainer/ ARE discovered", () => {
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, ".docker/Dockerfile", "FROM alpine:3.20\n");
    writeFile(root, ".devcontainer/Dockerfile", "FROM ubuntu:24.04\n");

    const result = discoverDockerfiles(root);
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      ".devcontainer/Dockerfile",
      ".docker/Dockerfile",
      "backend/Dockerfile",
    ]);
  });

  test("#4: Dockerfiles under .git/.terraform/other dot-dirs are STILL excluded", () => {
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, ".git/Dockerfile", "FROM scratch\n");
    writeFile(root, ".terraform/modules/x/Dockerfile", "FROM ubuntu\n");
    writeFile(root, ".cache/Dockerfile", "FROM busybox\n");

    const result = discoverDockerfiles(root);
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "backend/Dockerfile",
    ]);
  });

  test("a git-SUBMODULE root (.git is a FILE / gitlink) is NOT descended", () => {
    // A submodule root is an ordinary-named directory whose `.git` is a FILE
    // (`gitdir: …` gitlink), not a directory — so EXCLUDED_DIR_NAMES (which names
    // `.git`) never fires and the walk would descend into vendored third-party
    // code. The fix detects the gitlink FILE and skips descent. A SIBLING normal
    // dir with a `.git` DIRECTORY is unaffected (only the gitlink-FILE case
    // prunes).
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    // Submodule root: `.git` is a FILE (gitlink) — its Dockerfile must NOT be found.
    writeFile(root, "vendored/.git", "gitdir: ../.git/modules/vendored\n");
    writeFile(root, "vendored/Dockerfile", "FROM ubuntu:22.04\n");
    writeFile(root, "vendored/nested/Dockerfile", "FROM ubuntu:20.04\n");
    // A normal dir that merely CONTAINS a `.git` DIRECTORY entry (pruned by the
    // dot-dir / EXCLUDED_DIR_NAMES rule) but is itself a real source dir: its own
    // Dockerfile IS still discovered.
    writeFile(root, "normal/.git/HEAD", "ref: refs/heads/main\n");
    writeFile(root, "normal/Dockerfile", "FROM alpine:3.20\n");

    const result = discoverDockerfiles(root);
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "backend/Dockerfile",
      "normal/Dockerfile",
    ]);
  });

  test("[docker] ignore glob excludes a dev Dockerfile entirely", () => {
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, "docker/dev/Dockerfile", "FROM node:22\n");

    const result = discoverDockerfiles(root, {
      dockerIgnore: ["docker/dev/**"],
    });
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "backend/Dockerfile",
    ]);
    // The ignored one is surfaced by name (never silently dropped).
    expect(result.ignored).toEqual(["docker/dev/Dockerfile"]);
  });

  test("--exclude glob is honored", () => {
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, "legacy/Dockerfile", "FROM node:18\n");

    const result = discoverDockerfiles(root, { excludes: ["legacy/**"] });
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "backend/Dockerfile",
    ]);
  });

  test("output is deterministically sorted by repo-relative forward-slash path", () => {
    const root = makeTempRoot();
    writeFile(root, "z/Dockerfile", "FROM x\n");
    writeFile(root, "a/Dockerfile", "FROM x\n");
    writeFile(root, "m/sub/Dockerfile", "FROM x\n");

    const result = discoverDockerfiles(root);
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "a/Dockerfile",
      "m/sub/Dockerfile",
      "z/Dockerfile",
    ]);
  });

  test("each discovered Dockerfile carries its repo-relative identity and absolute path (no file read)", () => {
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");

    const result = discoverDockerfiles(root);
    const entry = result.dockerfiles.find(
      (d) => d.identity === "backend/Dockerfile",
    );
    expect(entry).toBeDefined();
    expect(entry?.path).toBe(join(root, "backend", "Dockerfile"));
    // The entry shape carries identity + path only — no derived base field.
    expect(Object.keys(entry ?? {}).sort()).toEqual(["identity", "path"]);
  });
});
