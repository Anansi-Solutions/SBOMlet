import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";

import {
  csprojNoLockWarnings,
  discoverTargets,
  discoverTargetsWithWarnings,
  lockfileNameFor,
} from "../src/targets/discover";

// Self-contained temp trees only — no reference to any host-project path (INTG-02).
const tempRoots: string[] = [];

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "licenses-discover-"));
  tempRoots.push(root);
  return root;
}

function makeYarnProject(dir: string): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), '{ "name": "fixture" }\n');
  writeFileSync(join(dir, "yarn.lock"), "# fixture lockfile\n");
}

function makePoetryProject(dir: string): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, "pyproject.toml"),
    '[tool.poetry]\nname = "fixture"\n',
  );
  writeFileSync(join(dir, "poetry.lock"), "# fixture lockfile\n");
}

function makeUvProject(dir: string): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "pyproject.toml"), '[project]\nname = "fixture"\n');
  writeFileSync(join(dir, "uv.lock"), "# fixture lockfile\n");
}

function makeNpmProject(dir: string): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), '{ "name": "fixture" }\n');
  writeFileSync(join(dir, "package-lock.json"), '{ "lockfileVersion": 3 }\n');
}

function makePnpmProject(dir: string): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), '{ "name": "fixture" }\n');
  writeFileSync(join(dir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
}

function makeBunProject(dir: string): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), '{ "name": "fixture" }\n');
  writeFileSync(join(dir, "bun.lock"), '{ "lockfileVersion": 1 }\n');
}

function makeTerraformProject(dir: string): void {
  mkdirSync(dir, { recursive: true });
  // A hidden FILE in the directory: discovery filters hidden DIRS, not files.
  writeFileSync(
    join(dir, ".terraform.lock.hcl"),
    '# fixture lock\nprovider "registry.opentofu.org/hashicorp/aws" {\n  version = "6.42.0"\n}\n',
  );
}

function writeBunLockb(dir: string): void {
  mkdirSync(dir, { recursive: true });
  // Binary placeholder bytes — content is never read, only the name matters.
  writeFileSync(join(dir, "bun.lockb"), Buffer.from([0x00, 0x01, 0x02, 0x03]));
}

function writeCsproj(dir: string, name = "App"): void {
  mkdirSync(dir, { recursive: true });
  // Content is never read — only the *.csproj name PATTERN matters.
  writeFileSync(
    join(dir, `${name}.csproj`),
    '<Project Sdk="Microsoft.NET.Sdk" />\n',
  );
}

function makeNugetProject(dir: string): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, "packages.lock.json"),
    '{ "version": 2, "dependencies": {} }\n',
  );
}

afterEach(() => {
  for (const root of tempRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("discoverTargets", () => {
  test("finds yarn/poetry/uv lockfiles at any depth with sorted forward-slash identities", () => {
    const root = makeTempRoot();
    makeYarnProject(join(root, "a"));
    makeYarnProject(join(root, "a", "b", "c"));
    makePoetryProject(join(root, "py"));
    makeUvProject(join(root, "uv"));

    const targets = discoverTargets(root);

    expect(targets.map((t) => t.identity)).toEqual(["a", "a/b/c", "py", "uv"]);
    expect(targets.map((t) => t.lockfile)).toEqual([
      "yarn",
      "yarn",
      "poetry",
      "uv",
    ]);
  });

  test("skips node_modules, .git, hidden directories, and the configured toolDir", () => {
    const root = makeTempRoot();
    makeYarnProject(join(root, "app"));
    makeYarnProject(join(root, "app", "node_modules", "dep"));
    makeYarnProject(join(root, ".git", "hooks"));
    makeYarnProject(join(root, ".cache", "stuff"));
    const toolDir = join(root, "tools", "licenses");
    makeYarnProject(toolDir);

    const targets = discoverTargets(root, { toolDir });

    expect(targets.map((t) => t.identity)).toEqual(["app"]);
  });

  test("#2 (07-28 revert): build/out/target/vendor are GENERIC source names — lockfiles under them ARE discovered; only dist stays pruned", () => {
    // The 07-26 prune of {build,out,target,vendor} was over-broad: those are
    // routinely legitimate SOURCE/service dir names (a service named `target`, a
    // Go `vendor/` whose contents ship), so pruning them dropped real targets
    // (under-coverage). Reverted: only `dist` (the documented, low-ambiguity
    // build-output dir) and node_modules/.git stay pruned.
    const root = makeTempRoot();
    makeYarnProject(join(root, "app"));
    makeYarnProject(join(root, "build", "pkg"));
    makeYarnProject(join(root, "out", "pkg"));
    makeYarnProject(join(root, "target", "pkg"));
    makeYarnProject(join(root, "vendor", "pkg"));
    // dist stays excluded (documented build-output dir).
    makeYarnProject(join(root, "dist", "pkg"));

    const targets = discoverTargets(root);

    expect(targets.map((t) => t.identity)).toEqual([
      "app",
      "build/pkg",
      "out/pkg",
      "target/pkg",
      "vendor/pkg",
    ]);
  });

  test("#2: node_modules, .git, and dist are STILL pruned after the revert", () => {
    const root = makeTempRoot();
    makeYarnProject(join(root, "app"));
    makeYarnProject(join(root, "node_modules", "dep"));
    makeYarnProject(join(root, ".git", "hooks"));
    makeYarnProject(join(root, "dist", "pkg"));

    const targets = discoverTargets(root);

    expect(targets.map((t) => t.identity)).toEqual(["app"]);
  });

  test("finding #2: a git-SUBMODULE root (.git is a FILE / gitlink) is NOT descended in the lockfile lane", () => {
    // A submodule is vendored third-party code; its lockfiles are not our
    // distribution's. The submodule root is an ordinary-named dir whose `.git`
    // is a FILE (gitlink), so the `.git` name exclusion never fires. The shared
    // shouldDescendDir now detects the gitlink FILE and prunes descent, covering
    // BOTH lanes. A sibling normal dir with a `.git` DIRECTORY is unaffected.
    const root = makeTempRoot();
    makeYarnProject(join(root, "app"));
    // Submodule root: `.git` is a FILE (gitlink) → its lockfile must NOT be found.
    makeYarnProject(join(root, "vendored"));
    writeFileSync(
      join(root, "vendored", ".git"),
      "gitdir: ../.git/modules/vendored\n",
    );
    makeYarnProject(join(root, "vendored", "nested"));
    // A normal dir whose `.git` is a DIRECTORY: its own lockfile IS discovered.
    makeYarnProject(join(root, "normal"));
    mkdirSync(join(root, "normal", ".git"), { recursive: true });
    writeFileSync(
      join(root, "normal", ".git", "HEAD"),
      "ref: refs/heads/main\n",
    );

    const targets = discoverTargets(root);

    expect(targets.map((t) => t.identity)).toEqual(["app", "normal"]);
  });

  test("#3: case-insensitive exclusion prunes Node_Modules / NODE_MODULES / Dist on Windows", () => {
    const root = makeTempRoot();
    makeYarnProject(join(root, "app"));
    makeYarnProject(join(root, "Node_Modules", "dep"));
    makeYarnProject(join(root, "NODE_MODULES", "dep"));
    makeYarnProject(join(root, "Dist", "pkg"));

    const targets = discoverTargets(root);

    expect(targets.map((t) => t.identity)).toEqual(["app"]);
  });

  test("#3 (07-28): --exclude globs match case-INSENSITIVELY (Windows on-disk identity parity)", () => {
    const root = makeTempRoot();
    makeYarnProject(join(root, "app"));
    // A real source dir whose on-disk name differs in case from the glob.
    makeYarnProject(join(root, "Cased", "pkg"));

    // A mis-cased glob `CASED/**` must still exclude the on-disk `Cased/pkg`.
    const excluded = discoverTargets(root, { excludes: ["CASED/**"] });
    expect(excluded.map((t) => t.identity)).toEqual(["app"]);
  });

  test("#4: the lockfile lane STILL prunes ALL dot-dirs (.docker/.devcontainer included)", () => {
    // The Dockerfile-lane dot-dir allowlist must not bleed into lockfile
    // discovery: a lockfile under .docker/ or .devcontainer/ stays excluded.
    const root = makeTempRoot();
    makeYarnProject(join(root, "app"));
    makeYarnProject(join(root, ".docker", "pkg"));
    makeYarnProject(join(root, ".devcontainer", "pkg"));

    const targets = discoverTargets(root);

    expect(targets.map((t) => t.identity)).toEqual(["app"]);
  });

  test("identities never contain a backslash, even on Windows", () => {
    const root = makeTempRoot();
    makeYarnProject(join(root, "deep", "nested", "project"));
    makePoetryProject(join(root, "py", "pkg"));

    const targets = discoverTargets(root);

    expect(targets.length).toBe(2);
    for (const target of targets) {
      expect(target.identity.includes("\\")).toBe(false);
    }
  });

  test("excludes: exact match, single-segment *, and cross-segment **", () => {
    const root = makeTempRoot();
    makeYarnProject(join(root, "a"));
    makeYarnProject(join(root, "a", "b"));
    makeYarnProject(join(root, "a", "b", "c"));

    const exact = discoverTargets(root, { excludes: ["a/b/c"] });
    expect(exact.map((t) => t.identity)).toEqual(["a", "a/b"]);

    // "*" matches within a single path segment: removes "a/b" but NOT "a/b/c".
    const single = discoverTargets(root, { excludes: ["a/*"] });
    expect(single.map((t) => t.identity)).toEqual(["a", "a/b/c"]);

    // "**" crosses segments: removes everything under "a" (but not "a" itself).
    const cross = discoverTargets(root, { excludes: ["a/**"] });
    expect(cross.map((t) => t.identity)).toEqual(["a"]);
  });

  test('a lockfile directly in repoRoot yields identity "."', () => {
    const root = makeTempRoot();
    makeYarnProject(root);

    const targets = discoverTargets(root);

    expect(targets.map((t) => t.identity)).toEqual(["."]);
    expect(targets[0]?.lockfile).toBe("yarn");
  });

  test("a directory with both yarn.lock and poetry.lock yields two targets, sorted by (identity, kind)", () => {
    const root = makeTempRoot();
    const dual = join(root, "dual");
    makeYarnProject(dual);
    makePoetryProject(dual);

    const targets = discoverTargets(root);

    expect(targets.map((t) => t.identity)).toEqual(["dual", "dual"]);
    // "poetry" < "yarn" by codepoint — deterministic tiebreak on lockfile kind.
    expect(targets.map((t) => t.lockfile)).toEqual(["poetry", "yarn"]);
  });

  test("a repoRoot with no lockfiles returns an empty array (CLI owns the zero-targets error)", () => {
    const root = makeTempRoot();
    mkdirSync(join(root, "src"), { recursive: true });
    writeFileSync(join(root, "src", "index.ts"), "export {};\n");

    expect(discoverTargets(root)).toEqual([]);
  });
});

describe("discoverTargets — npm/pnpm/bun lockfile kinds (COLL-06)", () => {
  test("package-lock.json / pnpm-lock.yaml / bun.lock each alone yield one target of the right kind", () => {
    const root = makeTempRoot();
    makeNpmProject(join(root, "npm-app"));
    makePnpmProject(join(root, "pnpm-app"));
    makeBunProject(join(root, "bun-app"));

    const targets = discoverTargets(root);

    expect(targets.map((t) => t.identity)).toEqual([
      "bun-app",
      "npm-app",
      "pnpm-app",
    ]);
    expect(targets.map((t) => t.lockfile)).toEqual(["bun", "npm", "pnpm"]);
  });
});

describe("discoverTargets — terraform lockfile kind (COLL-03)", () => {
  test(".terraform.lock.hcl is discovered (hidden FILE, not a hidden dir)", () => {
    const root = makeTempRoot();
    makeTerraformProject(join(root, "infra"));

    const targets = discoverTargets(root);

    expect(targets.map((t) => t.identity)).toEqual(["infra"]);
    expect(targets.map((t) => t.lockfile)).toEqual(["terraform"]);
  });

  test("a dir with both .terraform.lock.hcl and yarn.lock yields TWO targets (coexist, no collision)", () => {
    const root = makeTempRoot();
    const dir = join(root, "mixed");
    makeTerraformProject(dir);
    makeYarnProject(dir);

    const { targets, warnings } = discoverTargetsWithWarnings(root);

    expect(targets.map((t) => t.identity)).toEqual(["mixed", "mixed"]);
    // "terraform" > "yarn"? "terraform" < "yarn" by codepoint ('t' < 'y').
    expect(targets.map((t) => t.lockfile)).toEqual(["terraform", "yarn"]);
    // terraform never participates in JS precedence — no collision warning.
    expect(warnings).toEqual([]);
  });

  test("lockfileNameFor maps the terraform kind to .terraform.lock.hcl", () => {
    expect(lockfileNameFor("terraform")).toBe(".terraform.lock.hcl");
  });
});

describe("discoverTargetsWithWarnings — same-dir JS collision resolution", () => {
  test("bun.lock + package-lock.json collapse to one bun target with a warning naming both", () => {
    const root = makeTempRoot();
    const dir = join(root, "app");
    makeBunProject(dir);
    makeNpmProject(dir);

    const { targets, warnings } = discoverTargetsWithWarnings(root);

    expect(targets.map((t) => t.lockfile)).toEqual(["bun"]);
    expect(targets.map((t) => t.identity)).toEqual(["app"]);
    expect(warnings).toEqual([
      'target "app" has multiple JS lockfiles — scanning bun.lock (precedence bun > pnpm > yarn > npm); ignoring package-lock.json',
    ]);
  });

  test("pnpm-lock.yaml + package-lock.json collapse to pnpm", () => {
    const root = makeTempRoot();
    const dir = join(root, "app");
    makePnpmProject(dir);
    makeNpmProject(dir);

    const { targets, warnings } = discoverTargetsWithWarnings(root);

    expect(targets.map((t) => t.lockfile)).toEqual(["pnpm"]);
    expect(warnings).toEqual([
      'target "app" has multiple JS lockfiles — scanning pnpm-lock.yaml (precedence bun > pnpm > yarn > npm); ignoring package-lock.json',
    ]);
  });

  test("yarn.lock + package-lock.json collapse to yarn", () => {
    const root = makeTempRoot();
    const dir = join(root, "app");
    makeYarnProject(dir);
    makeNpmProject(dir);

    const { targets, warnings } = discoverTargetsWithWarnings(root);

    expect(targets.map((t) => t.lockfile)).toEqual(["yarn"]);
    expect(warnings).toEqual([
      'target "app" has multiple JS lockfiles — scanning yarn.lock (precedence bun > pnpm > yarn > npm); ignoring package-lock.json',
    ]);
  });

  test("all four JS lockfiles in one dir collapse to bun; warning names every ignored lockfile compareCodeUnits-sorted", () => {
    const root = makeTempRoot();
    const dir = join(root, "app");
    makeBunProject(dir);
    makePnpmProject(dir);
    makeYarnProject(dir);
    makeNpmProject(dir);

    const { targets, warnings } = discoverTargetsWithWarnings(root);

    expect(targets.map((t) => t.lockfile)).toEqual(["bun"]);
    expect(warnings).toEqual([
      'target "app" has multiple JS lockfiles — scanning bun.lock (precedence bun > pnpm > yarn > npm); ignoring package-lock.json, pnpm-lock.yaml, yarn.lock',
    ]);
  });

  test("a JS lockfile and a python lockfile in one dir still yield TWO targets (cross-ecosystem)", () => {
    const root = makeTempRoot();
    const dir = join(root, "dual");
    makeBunProject(dir);
    makePoetryProject(dir);

    const { targets, warnings } = discoverTargetsWithWarnings(root);

    expect(targets.map((t) => t.identity)).toEqual(["dual", "dual"]);
    // "bun" < "poetry" by codepoint — kind tiebreak preserved.
    expect(targets.map((t) => t.lockfile)).toEqual(["bun", "poetry"]);
    expect(warnings).toEqual([]);
  });

  test("collision output stays (identity, kind) sorted across multiple directories", () => {
    const root = makeTempRoot();
    makeBunProject(join(root, "b-app"));
    makeNpmProject(join(root, "b-app"));
    makeYarnProject(join(root, "a-app"));

    const { targets, warnings } = discoverTargetsWithWarnings(root);

    expect(targets.map((t) => t.identity)).toEqual(["a-app", "b-app"]);
    expect(targets.map((t) => t.lockfile)).toEqual(["yarn", "bun"]);
    expect(warnings.length).toBe(1);
  });
});

describe("discoverTargetsWithWarnings — binary bun.lockb handling", () => {
  test("bun.lockb alone yields zero targets plus a warning naming the migration command and identity", () => {
    const root = makeTempRoot();
    writeBunLockb(join(root, "legacy"));

    const { targets, warnings } = discoverTargetsWithWarnings(root);

    expect(targets).toEqual([]);
    expect(warnings).toEqual([
      'target "legacy" has a binary bun.lockb, which is unsupported — run `bun install --save-text-lockfile` in that project to migrate, then re-scan',
    ]);
  });

  test("bun.lockb beside bun.lock proceeds silently with the bun.lock target", () => {
    const root = makeTempRoot();
    const dir = join(root, "migrated");
    makeBunProject(dir);
    writeBunLockb(dir);

    const { targets, warnings } = discoverTargetsWithWarnings(root);

    expect(targets.map((t) => t.lockfile)).toEqual(["bun"]);
    expect(warnings).toEqual([]);
  });

  test("an excluded identity produces neither targets nor bun.lockb warnings", () => {
    const root = makeTempRoot();
    writeBunLockb(join(root, "skipme"));
    makeBunProject(join(root, "skipme"));
    makeNpmProject(join(root, "skipme"));

    const { targets, warnings } = discoverTargetsWithWarnings(root, {
      excludes: ["skipme"],
    });

    expect(targets).toEqual([]);
    expect(warnings).toEqual([]);
  });
});

describe("discoverTargetsWithWarnings — csproj sighted without packages.lock.json (NET-01 near-miss)", () => {
  test("a lockless csproj dir yields zero targets and ONE aggregated warning naming the property, the command, and the directory", () => {
    const root = makeTempRoot();
    writeCsproj(join(root, "App"));

    const { targets, warnings } = discoverTargetsWithWarnings(root);

    expect(targets).toEqual([]);
    expect(warnings).toEqual([
      "1 directory contains a .csproj but no packages.lock.json, which is " +
        'required for .NET scanning ("App") — set ' +
        "RestorePackagesWithLockFile=true in each project, run " +
        "`dotnet restore`, and commit the resulting lockfiles, then re-scan",
    ]);
    // The two migration ingredients the loud-no-lock contract requires (A-02).
    expect(warnings[0]).toContain("RestorePackagesWithLockFile");
    expect(warnings[0]).toContain("dotnet restore");
  });

  test("two lockless dirs AGGREGATE into one summary warning naming both, sorted (never a per-directory wall)", () => {
    const root = makeTempRoot();
    writeCsproj(join(root, "b-lib"), "BLib");
    writeCsproj(join(root, "a-lib"), "ALib");

    const { targets, warnings } = discoverTargetsWithWarnings(root);

    expect(targets).toEqual([]);
    expect(warnings).toEqual([
      "2 directories contain a .csproj but no packages.lock.json, which is " +
        'required for .NET scanning ("a-lib", "b-lib") — set ' +
        "RestorePackagesWithLockFile=true in each project, run " +
        "`dotnet restore`, and commit the resulting lockfiles, then re-scan",
    ]);
  });

  test("past the example limit the aggregate truncates to e.g. plus the --verbose hint", () => {
    const root = makeTempRoot();
    for (const name of ["p1", "p2", "p3", "p4", "p5"]) {
      writeCsproj(join(root, name), "Proj");
    }

    const { warnings } = discoverTargetsWithWarnings(root);

    expect(warnings).toEqual([
      "5 directories contain a .csproj but no packages.lock.json, which is " +
        'required for .NET scanning (e.g. "p1", "p2", "p3") — set ' +
        "RestorePackagesWithLockFile=true in each project, run " +
        "`dotnet restore`, and commit the resulting lockfiles, then re-scan; " +
        "re-run with --verbose to list every directory",
    ]);
  });

  test("verbose emits one warning per directory instead of the aggregate, sorted deterministically", () => {
    const root = makeTempRoot();
    writeCsproj(join(root, "b-lib"), "BLib");
    writeCsproj(join(root, "a-lib"), "ALib");

    const { warnings } = discoverTargetsWithWarnings(root, { verbose: true });

    expect(warnings).toEqual([
      'target "a-lib" has a .csproj but no packages.lock.json, which is ' +
        "required for .NET scanning — set RestorePackagesWithLockFile=true " +
        "in the project and run `dotnet restore`, commit the lockfile, " +
        "then re-scan",
      'target "b-lib" has a .csproj but no packages.lock.json, which is ' +
        "required for .NET scanning — set RestorePackagesWithLockFile=true " +
        "in the project and run `dotnet restore`, commit the lockfile, " +
        "then re-scan",
    ]);
  });

  test("csproj beside packages.lock.json proceeds silently with one nuget target (same-directory suppression)", () => {
    const root = makeTempRoot();
    const dir = join(root, "locked");
    writeCsproj(dir);
    makeNugetProject(dir);

    const { targets, warnings } = discoverTargetsWithWarnings(root);

    expect(targets.map((t) => t.identity)).toEqual(["locked"]);
    expect(targets.map((t) => t.lockfile)).toEqual(["nuget"]);
    expect(warnings).toEqual([]);
  });

  test("suppression is per-directory: a lockless sibling still counts while the locked dir stays silent", () => {
    const root = makeTempRoot();
    writeCsproj(join(root, "locked"));
    makeNugetProject(join(root, "locked"));
    writeCsproj(join(root, "lockless"), "Lib");

    const { targets, warnings } = discoverTargetsWithWarnings(root);

    expect(targets.map((t) => t.identity)).toEqual(["locked"]);
    expect(warnings).toEqual([
      "1 directory contains a .csproj but no packages.lock.json, which is " +
        'required for .NET scanning ("lockless") — set ' +
        "RestorePackagesWithLockFile=true in each project, run " +
        "`dotnet restore`, and commit the resulting lockfiles, then re-scan",
    ]);
  });

  test("multiple csproj files in ONE directory count that directory once", () => {
    const root = makeTempRoot();
    const dir = join(root, "multi");
    writeCsproj(dir, "App");
    writeCsproj(dir, "App.Tests");

    const { warnings } = discoverTargetsWithWarnings(root);

    expect(warnings.length).toBe(1);
    expect(warnings[0]).toMatch(/^1 directory contains/);
  });

  test("an excluded identity produces neither targets nor csproj warnings (bun.lockb parity)", () => {
    const root = makeTempRoot();
    writeCsproj(join(root, "skipme"));

    const { targets, warnings } = discoverTargetsWithWarnings(root, {
      excludes: ["skipme"],
    });

    expect(targets).toEqual([]);
    expect(warnings).toEqual([]);
  });

  test("a Directory.Packages.props-only directory is NOT a trigger (no warning, no target)", () => {
    // CPM's props file is not a project marker: a CPM repo with locks
    // committed would otherwise get a spurious root-level warning (the props
    // file's directory typically holds no lock), and a CPM repo WITHOUT locks
    // already warns via its csproj dirs.
    const root = makeTempRoot();
    const dir = join(root, "cpm");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "Directory.Packages.props"), "<Project />\n");

    const { targets, warnings } = discoverTargetsWithWarnings(root);

    expect(targets).toEqual([]);
    expect(warnings).toEqual([]);
  });

  test("same-dir package-lock.json + packages.lock.json yield TWO targets (cross-ecosystem coexistence, 15-01 precedence decision)", () => {
    const root = makeTempRoot();
    const dir = join(root, "x");
    makeNpmProject(dir);
    makeNugetProject(dir);

    const { targets, warnings } = discoverTargetsWithWarnings(root);

    expect(targets.map((t) => t.identity)).toEqual(["x", "x"]);
    // "npm" < "nuget" by codepoint ("p" < "u") — kind tiebreak preserved;
    // JS_PRECEDENCE never sees nuget, so no collision warning.
    expect(targets.map((t) => t.lockfile)).toEqual(["npm", "nuget"]);
    expect(warnings).toEqual([]);
  });

  test("HOSTILE directory identities are sanitized in BOTH warning shapes (no stderr line forgery)", () => {
    // Directory names are repo-author-controlled and (on POSIX) can carry
    // control characters; the warning prints them to stderr, so a crafted
    // name could forge warning lines (\n) or erase real ones (ANSI ESC[2K).
    // Tested via the exported pure builder — such names cannot be created on
    // every filesystem, but discovery must stay safe where they can.
    const hostile = "evil\u001b[2K\nok: all clear";
    // eslint-disable-next-line no-control-regex -- deliberate control-character class: the forgery probe
    const controlChars = /[\u0000-\u001f\u007f-\u009f]/;
    const [aggregated] = csprojNoLockWarnings([hostile], false);
    const [verbose] = csprojNoLockWarnings([hostile], true);
    expect(aggregated).toBeDefined();
    expect(verbose).toBeDefined();
    expect(aggregated).not.toMatch(controlChars);
    expect(verbose).not.toMatch(controlChars);
    // The sanitized identity is still visibly present (spaces, not deletion).
    expect(aggregated).toContain("evil");
    expect(verbose).toContain("evil");
  });
});

describe("lockfileNameFor", () => {
  test("maps each lockfile kind back to its file name", () => {
    expect(lockfileNameFor("yarn")).toBe("yarn.lock");
    expect(lockfileNameFor("poetry")).toBe("poetry.lock");
    expect(lockfileNameFor("uv")).toBe("uv.lock");
    expect(lockfileNameFor("npm")).toBe("package-lock.json");
    expect(lockfileNameFor("pnpm")).toBe("pnpm-lock.yaml");
    expect(lockfileNameFor("bun")).toBe("bun.lock");
    expect(lockfileNameFor("nuget")).toBe("packages.lock.json");
  });
});
