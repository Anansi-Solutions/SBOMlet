import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";

import { resolveTarget } from "../src/targets/target";

// Self-contained temp trees only — no reference to any host-project path.
const tempRoots: string[] = [];

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "licenses-target-"));
  tempRoots.push(root);
  return root;
}

function makeYarnProject(dir: string): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), '{ "name": "fixture" }\n');
  writeFileSync(join(dir, "yarn.lock"), "# fixture lockfile\n");
}

afterEach(() => {
  for (const root of tempRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("resolveTarget", () => {
  test("returns forward-slash identity relative to the .git directory root", () => {
    const root = makeTempRoot();
    mkdirSync(join(root, ".git"));
    const targetDir = join(root, "libraries", "iframe-rpc");
    makeYarnProject(targetDir);

    const target = resolveTarget(targetDir);

    expect(target.identity).toBe("libraries/iframe-rpc");
    expect(target.identity.includes("\\")).toBe(false);
    expect(target.dir).toBe(targetDir);
  });

  test("treats a .git FILE the same as a .git directory (worktrees)", () => {
    const root = makeTempRoot();
    writeFileSync(join(root, ".git"), "gitdir: /elsewhere/.git/worktrees/x\n");
    const targetDir = join(root, "libraries", "iframe-rpc");
    makeYarnProject(targetDir);

    const target = resolveTarget(targetDir);

    expect(target.identity).toBe("libraries/iframe-rpc");
  });

  test("resolves a relative target argument against the provided cwd", () => {
    const root = makeTempRoot();
    mkdirSync(join(root, ".git"));
    const targetDir = join(root, "libraries", "iframe-rpc");
    makeYarnProject(targetDir);

    const target = resolveTarget(join("libraries", "iframe-rpc"), root);

    expect(target.identity).toBe("libraries/iframe-rpc");
    expect(target.dir).toBe(targetDir);
  });

  test("throws an error naming yarn.lock and the offending path when the lockfile is missing", () => {
    const root = makeTempRoot();
    mkdirSync(join(root, ".git"));
    const targetDir = join(root, "libraries", "no-lockfile");
    mkdirSync(targetDir, { recursive: true });
    writeFileSync(join(targetDir, "package.json"), "{}\n");

    expect(() => resolveTarget(targetDir)).toThrow(/yarn\.lock/);
    expect(() => resolveTarget(targetDir)).toThrow(/no-lockfile/);
  });

  test("a poetry project names the yarn-only expectation and the --repo-root alternative", () => {
    // --target apps/jupyter shape: poetry.lock + pyproject.toml, no yarn
    // files at all. Pre-fix this surfaced "is missing package.json" — a
    // misleading hint that adding a package.json would help. The error must
    // name the actual expectation (yarn-only debug mode) and the way out.
    const root = makeTempRoot();
    mkdirSync(join(root, ".git"));
    const targetDir = join(root, "apps", "pyproj");
    mkdirSync(targetDir, { recursive: true });
    writeFileSync(join(targetDir, "pyproject.toml"), "[project]\n");
    writeFileSync(join(targetDir, "poetry.lock"), '[[package]]\nname = "x"\n');

    expect(() => resolveTarget(targetDir)).toThrow(
      /--target only supports yarn projects/,
    );
    expect(() => resolveTarget(targetDir)).toThrow(
      /use --repo-root for poetry\/uv targets/,
    );
    expect(() => resolveTarget(targetDir)).toThrow(/pyproj/);
  });

  test("throws an error containing the resolved path for a nonexistent directory", () => {
    const root = makeTempRoot();
    const missing = join(root, "does-not-exist");

    expect(() => resolveTarget(missing)).toThrow(/does-not-exist/);
  });

  test("falls back to the directory basename when no .git ancestor exists", () => {
    const root = makeTempRoot();
    const targetDir = join(root, "standalone-project");
    makeYarnProject(targetDir);

    const target = resolveTarget(targetDir);

    expect(target.identity).toBe(basename(targetDir));
    expect(target.identity.includes("/")).toBe(false);
    expect(target.identity.includes("\\")).toBe(false);
  });
});
