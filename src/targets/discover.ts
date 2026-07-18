/**
 * Generic lockfile target discovery.
 *
 * Recursively walks `--repo-root` with a hand-rolled `node:fs` walk (zero new
 * dependencies) looking for yarn.lock / package-lock.json / pnpm-lock.yaml /
 * bun.lock / poetry.lock / uv.lock. Universal excludes only — node_modules,
 * .git, hidden directories, and the tool's own directory — with no
 * repository-specific paths anywhere. Discovery output is authoritative over
 * any human-maintained workspace list.
 *
 * Identities are forward-slash repo-relative directory paths, copying
 * target.ts's idiom; results sort deterministically by (identity, lockfile
 * kind) using compareCodeUnits, the only comparator allowed tool-wide.
 *
 * Three pure post-steps over the sorted walk output:
 * - Same-dir JS lockfile collisions collapse to one target by precedence
 *   bun > pnpm > yarn > npm with a warning naming the chosen and every ignored
 *   lockfile; cross-ecosystem pairs (a JS lockfile plus poetry/uv in one
 *   directory) still yield two targets.
 * - Binary bun.lockb is observed during the walk but never becomes a target: a
 *   bun.lockb without a surviving bun.lock target warns naming `bun install
 *   --save-text-lockfile`; beside a bun.lock it is silent (the text lockfile is
 *   authoritative).
 * - `*.csproj` files are likewise observed during the walk but never become
 *   targets: a directory with a csproj sighting and no surviving nuget target
 *   feeds one AGGREGATED warning naming the RestorePackagesWithLockFile=true +
 *   `dotnet restore` migration (per-directory detail under the verbose
 *   option) — a .NET repo never scans to zero targets silently.
 * - `pom.xml` is likewise observed during the walk but never becomes a
 *   target: a directory with a pom.xml sighting and no surviving maven
 *   target feeds one AGGREGATED warning naming the cyclonedx-maven-plugin
 *   adoption recipe (per-directory detail under the verbose option) — a
 *   Maven repo never scans to zero targets silently, the same idiom as the
 *   csproj near-miss above.
 *
 * This module is pure walk + classify: it never exits, never writes to stderr,
 * and returns an empty array for a lockfile-less root — the CLI owns the
 * zero-targets error and prints the warnings returned as data here.
 */

import { readdirSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";

import { compareCodeUnits } from "../model/dependencies";
import { sanitizeForLog } from "../pipeline/summary";
import type { Target } from "./target";

export type LockfileKind =
  | "yarn"
  | "npm"
  | "pnpm"
  | "bun"
  | "poetry"
  | "uv"
  | "terraform"
  | "nuget"
  | "maven";

export interface DiscoveredTarget extends Target {
  /** Which lockfile produced this target. One DiscoveredTarget per lockfile found. */
  lockfile: LockfileKind;
}

export interface DiscoverOptions {
  /** Absolute path of this tool's own directory (excluded from the walk). */
  toolDir?: string;
  /** Repeatable --exclude glob patterns, matched against the identity. */
  excludes?: readonly string[];
  /**
   * Per-directory warning detail (the CLI's --verbose): when true, the
   * csproj-no-lock and pom-no-sidecar near-misses emit one warning per
   * directory instead of the aggregated summary line. Affects warning
   * FORMAT only — never the target set.
   */
  verbose?: boolean;
}

const LOCKFILES = new Map<string, LockfileKind>([
  ["yarn.lock", "yarn"],
  ["package-lock.json", "npm"],
  ["pnpm-lock.yaml", "pnpm"],
  ["bun.lock", "bun"],
  ["poetry.lock", "poetry"],
  ["uv.lock", "uv"],
  [".terraform.lock.hcl", "terraform"],
  ["packages.lock.json", "nuget"],
  ["maven.sbom.json", "maven"],
]);

/**
 * Same-directory JS lockfile precedence: lower rank wins. A stray
 * package-lock.json is the most common accident (npm auto-writes it), so npm
 * ranks last; bun emits a derived yarn.lock for compatibility, so bun outranks
 * yarn; migration tooling leaves the older-generation file behind, so the
 * newest-generation package manager's lockfile is the deliberate artifact.
 */
const JS_PRECEDENCE = new Map<LockfileKind, number>([
  ["bun", 0],
  ["pnpm", 1],
  ["yarn", 2],
  ["npm", 3],
]);

/** Inverse of the discovery map: lockfile kind → file name. */
export function lockfileNameFor(kind: LockfileKind): string {
  for (const [name, k] of LOCKFILES) {
    if (k === kind) {
      return name;
    }
  }
  // Unreachable: LockfileKind is a closed union covered by LOCKFILES.
  throw new Error(`unknown lockfile kind: ${kind}`);
}

const REGEX_SPECIALS = new Set("\\^$.|?+()[]{}");

/**
 * The directories the walk NEVER descends into — the SINGLE source of truth for
 * the universal discovery exclusion set, shared verbatim by lockfile discovery
 * here and Dockerfile discovery (src/collectors/dockerfile.ts) so the two can
 * never drift to divergent skip lists. node_modules and .git are named
 * explicitly; every other dotfile/dot-directory (.terraform, .yarn, .cache, …)
 * is excluded by the leading-"." rule below in {@link shouldDescendDir}.
 * Exported so the reuse is by reference, not by re-hardcoding.
 */
export const EXCLUDED_DIR_NAMES: ReadonlySet<string> = new Set([
  // Dependency trees (shared with Dockerfile discovery).
  "node_modules",
  ".git",
  // Documented BUILD-OUTPUT dir: a generated artifact tree (this
  // repo's documented `dist/`) must never be descended — a Dockerfile or
  // lockfile copied into it is a build product, not a source target. Members are
  // compared CASE-INSENSITIVELY so Windows `Dist`/`NODE_MODULES`
  // (the same on-disk tree) are pruned identically.
  //
  // REVERTED over-pruning: {build, out, target, vendor} were once excluded
  // here too — over-broad. Those are GENERIC names that are routinely legitimate SOURCE /
  // service dirs (a service literally named `target`, a Go `vendor/` whose
  // contents ship in the image), so pruning them silently DROPPED real app
  // Dockerfiles / lockfiles — under-coverage, the inverse of a leak. Only
  // `dist` survives here: it is the documented, low-ambiguity build-output dir.
  "dist",
]);

/**
 * Dot-directories the DOCKERFILE lane is allowed to descend: the
 * conventional homes of real Dockerfiles. The leading-"." prune is right for the
 * lockfile lane (it keeps .terraform/.yarn/.cache out) but wrongly drops these
 * two; the Dockerfile lane opts into them via {@link shouldDescendDir}'s
 * allowlist param while STILL pruning .git/.terraform/every other dot-dir.
 * Compared case-insensitively for Windows parity.
 */
export const DOCKERFILE_DOT_DIR_ALLOWLIST: ReadonlySet<string> = new Set([
  ".docker",
  ".devcontainer",
]);

/**
 * The universal walk descent predicate, shared by lockfile and Dockerfile
 * discovery: skip the {@link EXCLUDED_DIR_NAMES} (node_modules/.git/build-output
 * dirs, matched case-insensitively), every hidden (leading-".")
 * directory (which covers .terraform, .yarn, .cache, …), and the tool's own
 * directory. `sub` is the child path; `name` its basename; `toolDir` (if given)
 * the tool directory in any form — BOTH `sub` and `toolDir` are resolve()'d here
 * before comparison so a caller passing a forward-slash or relative toolDir on
 * Windows still matches (the comparison is canonical, not string-literal).
 *
 * `dotDirAllowlist` decouples the lanes for dot-dirs: when given, a
 * dot-dir whose lower-cased name is in the allowlist (.docker/.devcontainer) is
 * descended even though it starts with "." — the Dockerfile lane passes it; the
 * lockfile lane omits it and keeps pruning ALL dot-dirs unchanged. `.git` is
 * never allowlistable: it is excluded by EXCLUDED_DIR_NAMES BEFORE the dot rule.
 *
 * GIT-SUBMODULE PRUNE: a git-submodule root is an ORDINARY-named
 * directory (its name is not in EXCLUDED_DIR_NAMES and does not start with ".")
 * whose `.git` entry is a FILE (a `gitdir: …` gitlink), not a directory — so none
 * of the rules above fire and the walk would descend into VENDORED third-party
 * code, attributing its lockfiles/Dockerfiles to OUR distribution. A submodule is
 * detected by testing whether `<sub>/.git` exists as a FILE; if so, descent is
 * skipped. This covers nested submodules and needs no `.gitmodules` parsing, and
 * applies to BOTH lanes (the prune is shared). A normal dir whose `.git` is a
 * DIRECTORY (a real nested git repo's root, unusual inside a checkout) is NOT a
 * gitlink and is unaffected by this rule — only the gitlink-FILE case prunes.
 */
export function shouldDescendDir(
  sub: string,
  name: string,
  toolDir?: string,
  dotDirAllowlist?: ReadonlySet<string>,
): boolean {
  const lower = name.toLowerCase();
  if (EXCLUDED_DIR_NAMES.has(name) || EXCLUDED_DIR_NAMES.has(lower)) {
    return false;
  }
  if (name.startsWith(".")) {
    // Lockfile lane (no allowlist): every dot-dir is pruned. Dockerfile lane:
    // descend only the explicitly-allowlisted Dockerfile homes.
    if (dotDirAllowlist === undefined || !dotDirAllowlist.has(lower)) {
      return false;
    }
  }
  if (toolDir !== undefined && resolve(sub) === resolve(toolDir)) return false;
  // Git-submodule prune: a `.git` FILE (gitlink) marks a submodule
  // root — vendored third-party code that is not our distribution. Skip descent.
  if (isGitSubmoduleRoot(sub)) return false;
  return true;
}

/**
 * True iff `dir` is a git-submodule root — i.e. `<dir>/.git` exists and is a
 * FILE (a `gitdir: …` gitlink), as git records for submodule working trees. A
 * `.git` DIRECTORY (a top-level repo / linked worktree) is NOT a gitlink and
 * returns false. statSync is wrapped so a missing `.git` (the common case) and
 * any transient stat error are treated as "not a submodule" — fail-open to
 * descend, since the leak we guard is over-INCLUSION, and a stat failure here
 * never silently DROPS a legitimate source dir.
 */
function isGitSubmoduleRoot(dir: string): boolean {
  try {
    return statSync(join(dir, ".git")).isFile();
  } catch {
    return false;
  }
}

/**
 * Translate one exclude glob into an anchored RegExp over the WHOLE identity.
 *
 * Two wildcard semantics (documented contract for the --exclude flag):
 * - `*`  matches within a single path segment (any run of non-`/` chars):
 *        "a/*" excludes "a/b" but NOT "a/b/c".
 * - `**` matches across segments (any run of chars including `/`):
 *        "a/**" excludes everything under "a" but not "a" itself.
 *
 * All other characters are regex-escaped literally; `**` is translated before
 * the remaining single `*` so the two semantics never overlap. Exported so
 * Dockerfile discovery applies byte-identical glob semantics to --exclude and
 * [docker] ignore globs.
 *
 * The regex is CASE-INSENSITIVE (the `i` flag): the platform is
 * Windows (a case-insensitive filesystem) and the literal dir-name exclusion was
 * already made case-insensitive. A mis-cased `--exclude` / `[docker]
 * ignore` glob (`Dist/**`, `NODE_MODULES/**`) must still match the on-disk
 * identity for consistency across both the lockfile and Dockerfile lanes.
 */
export function globToRegExp(glob: string): RegExp {
  let out = "";
  let i = 0;
  while (i < glob.length) {
    if (glob.startsWith("**", i)) {
      out += ".*";
      i += 2;
    } else if (glob[i] === "*") {
      out += "[^/]*";
      i += 1;
    } else {
      const ch = glob[i] as string;
      out += REGEX_SPECIALS.has(ch) ? `\\${ch}` : ch;
      i += 1;
    }
  }
  return new RegExp(`^${out}$`, "i");
}

export function isExcluded(
  identity: string,
  matchers: readonly RegExp[],
): boolean {
  return matchers.some((re) => re.test(identity));
}

/**
 * How many near-miss directories (lockless csproj, sidecar-less pom.xml) the
 * aggregated warning names verbatim; past this the list truncates to "e.g."
 * plus the --verbose hint. Real monorepos can hold ~100 such directories — a
 * per-directory warning wall is unusable, so the default is one summary
 * line. Shared by both near-miss kinds so their aggregation caps can never
 * drift apart.
 */
const AGGREGATE_EXAMPLE_LIMIT = 3;

/**
 * The csproj-sighted-but-no-lock warning strings: a .NET project without a
 * committed packages.lock.json must be TOLD the migration recipe
 * (RestorePackagesWithLockFile=true + `dotnet restore`), never silently
 * inventoried as zero. One aggregated summary line by default; one line per
 * directory when `verbose` (the CLI's --verbose) is set. `lockless` arrives
 * compareCodeUnits-sorted, so both shapes are deterministic.
 *
 * Identities are repo-author-controlled directory names printed to stderr,
 * so they pass through sanitizeForLog AT RENDER ONLY (a crafted name cannot
 * forge or erase warning lines); the suppression/exclusion matching upstream
 * stays on the raw identities. Exported for direct unit testing — hostile
 * names cannot be created on every filesystem.
 */
export function csprojNoLockWarnings(
  lockless: readonly string[],
  verbose: boolean,
): string[] {
  if (lockless.length === 0) return [];
  if (verbose) {
    return lockless.map(
      (identity) =>
        `target "${sanitizeForLog(identity)}" has a .csproj but no ` +
        "packages.lock.json, which is required for .NET scanning — set " +
        "RestorePackagesWithLockFile=true in the project and run " +
        "`dotnet restore`, commit the lockfile, then re-scan",
    );
  }
  const count = lockless.length;
  const truncated = count > AGGREGATE_EXAMPLE_LIMIT;
  const examples = lockless
    .slice(0, AGGREGATE_EXAMPLE_LIMIT)
    .map((identity) => `"${sanitizeForLog(identity)}"`)
    .join(", ");
  const countPhrase =
    count === 1 ? "1 directory contains" : `${count} directories contain`;
  return [
    `${countPhrase} a .csproj but no packages.lock.json, which is required ` +
      `for .NET scanning (${truncated ? "e.g. " : ""}${examples}) — set ` +
      "RestorePackagesWithLockFile=true in each project, run " +
      "`dotnet restore`, and commit the resulting lockfiles, then re-scan" +
      (truncated ? "; re-run with --verbose to list every directory" : ""),
  ];
}

/**
 * Post-step 3's warning computation: every recorded csproj identity with NO
 * surviving nuget target at that identity (the same-directory suppression —
 * a committed packages.lock.json is authoritative), compareCodeUnits-sorted,
 * rendered by {@link csprojNoLockWarnings}.
 */
function locklessCsprojWarnings(
  csprojIdentities: ReadonlySet<string>,
  targets: readonly DiscoveredTarget[],
  opts?: DiscoverOptions,
): string[] {
  const lockless = [...csprojIdentities]
    .filter(
      (identity) =>
        !targets.some(
          (target) =>
            target.identity === identity && target.lockfile === "nuget",
        ),
    )
    .sort(compareCodeUnits);
  return csprojNoLockWarnings(lockless, opts?.verbose ?? false);
}

/**
 * The pom.xml-sighted-but-no-sidecar warning strings: a Maven project
 * without a committed maven.sbom.json must be TOLD the adoption recipe (run
 * the pinned cyclonedx-maven-plugin's makeBom goal in CI, commit the
 * result), never silently inventoried as zero. One aggregated summary line
 * by default; one line per directory when `verbose` (the CLI's --verbose)
 * is set. `unsidecared` arrives compareCodeUnits-sorted, so both shapes are
 * deterministic.
 *
 * Identities are repo-author-controlled directory names printed to stderr,
 * so they pass through sanitizeForLog AT RENDER ONLY (a crafted name cannot
 * forge or erase warning lines); the suppression/exclusion matching upstream
 * stays on the raw identities. Exported for direct unit testing — hostile
 * names cannot be created on every filesystem.
 */
export function pomNoSidecarWarnings(
  unsidecared: readonly string[],
  verbose: boolean,
): string[] {
  if (unsidecared.length === 0) return [];
  if (verbose) {
    return unsidecared.map(
      (identity) =>
        `target "${sanitizeForLog(identity)}" has a pom.xml but no ` +
        "committed maven.sbom.json, which is required for Maven scanning " +
        "— generate it in CI with the cyclonedx-maven-plugin's makeBom " +
        "goal and commit maven.sbom.json in this directory, then re-scan",
    );
  }
  const count = unsidecared.length;
  const truncated = count > AGGREGATE_EXAMPLE_LIMIT;
  const examples = unsidecared
    .slice(0, AGGREGATE_EXAMPLE_LIMIT)
    .map((identity) => `"${sanitizeForLog(identity)}"`)
    .join(", ");
  const countPhrase =
    count === 1 ? "1 directory contains" : `${count} directories contain`;
  return [
    `${countPhrase} a pom.xml but no committed maven.sbom.json, which is ` +
      `required for Maven scanning (${truncated ? "e.g. " : ""}${examples}) — ` +
      "generate it in CI with the cyclonedx-maven-plugin's makeBom goal and " +
      "commit maven.sbom.json in each directory, then re-scan" +
      (truncated ? "; re-run with --verbose to list every directory" : ""),
  ];
}

/**
 * Post-step 4's warning computation: every recorded pom.xml identity with NO
 * surviving maven target at that identity (the same-directory suppression —
 * a committed maven.sbom.json is authoritative), compareCodeUnits-sorted,
 * rendered by {@link pomNoSidecarWarnings}.
 */
function unsidecaredPomWarnings(
  pomIdentities: ReadonlySet<string>,
  targets: readonly DiscoveredTarget[],
  opts?: DiscoverOptions,
): string[] {
  const unsidecared = [...pomIdentities]
    .filter(
      (identity) =>
        !targets.some(
          (target) =>
            target.identity === identity && target.lockfile === "maven",
        ),
    )
    .sort(compareCodeUnits);
  return pomNoSidecarWarnings(unsidecared, opts?.verbose ?? false);
}

/**
 * The maven.test.sbom.json-without-maven.sbom.json warning strings: the
 * test-inclusive sidecar is optional-additive and never its own discovery
 * trigger (§ LOCKFILES above), so a directory that commits ONLY the test
 * doc — no default `maven.sbom.json` beside it — must be TOLD it never
 * became a target, rather than silently vanishing. One aggregated summary
 * line by default; one line per directory when `verbose` (the CLI's
 * --verbose) is set. `orphaned` arrives compareCodeUnits-sorted, so both
 * shapes are deterministic.
 *
 * Identities are repo-author-controlled directory names printed to stderr,
 * so they pass through sanitizeForLog AT RENDER ONLY (a crafted name cannot
 * forge or erase warning lines); the suppression/exclusion matching upstream
 * stays on the raw identities. Exported for direct unit testing — hostile
 * names cannot be created on every filesystem.
 */
export function mavenTestSbomOrphanWarnings(
  orphaned: readonly string[],
  verbose: boolean,
): string[] {
  if (orphaned.length === 0) return [];
  if (verbose) {
    return orphaned.map(
      (identity) =>
        `target "${sanitizeForLog(identity)}" has a maven.test.sbom.json ` +
        "but no maven.sbom.json — commit maven.sbom.json (the default " +
        "sidecar) beside it; the test-inclusive document is read only " +
        "alongside the default one",
    );
  }
  const count = orphaned.length;
  const truncated = count > AGGREGATE_EXAMPLE_LIMIT;
  const examples = orphaned
    .slice(0, AGGREGATE_EXAMPLE_LIMIT)
    .map((identity) => `"${sanitizeForLog(identity)}"`)
    .join(", ");
  const countPhrase =
    count === 1 ? "1 directory contains" : `${count} directories contain`;
  return [
    `${countPhrase} a maven.test.sbom.json but no maven.sbom.json ` +
      `(${truncated ? "e.g. " : ""}${examples}) — commit maven.sbom.json ` +
      "(the default sidecar) beside each one; the test-inclusive document " +
      "is read only alongside the default one" +
      (truncated ? "; re-run with --verbose to list every directory" : ""),
  ];
}

/**
 * Post-step 5's warning computation: every recorded maven.test.sbom.json
 * identity with NO surviving maven target at that identity (a committed
 * maven.sbom.json is authoritative and suppresses the warning — the same
 * same-directory suppression as post-step 4), compareCodeUnits-sorted,
 * rendered by {@link mavenTestSbomOrphanWarnings}.
 */
function orphanedMavenTestSbomWarnings(
  mavenTestSbomIdentities: ReadonlySet<string>,
  targets: readonly DiscoveredTarget[],
  opts?: DiscoverOptions,
): string[] {
  const orphaned = [...mavenTestSbomIdentities]
    .filter(
      (identity) =>
        !targets.some(
          (target) =>
            target.identity === identity && target.lockfile === "maven",
        ),
    )
    .sort(compareCodeUnits);
  return mavenTestSbomOrphanWarnings(orphaned, opts?.verbose ?? false);
}

/** Discovery output: collision-resolved targets plus warning data. */
export interface DiscoveryResult {
  targets: DiscoveredTarget[];
  /**
   * Deterministic (compareCodeUnits-sorted) warning strings, without any
   * "warning: " prefix — the CLI prefixes and prints them; this module stays
   * pure.
   */
  warnings: string[];
}

/**
 * Walk `repoRoot` and return collision-resolved targets plus warnings:
 *
 * - One DiscoveredTarget per lockfile found, sorted by (identity, lockfile
 *   kind). A directory holding lockfiles of DIFFERENT ecosystems (e.g.
 *   bun.lock and poetry.lock) yields two targets with the same identity
 *   (deterministic via the kind tiebreak).
 * - A directory holding multiple JS lockfiles collapses to exactly one target
 *   by precedence bun > pnpm > yarn > npm, with a warning naming the chosen
 *   lockfile and every ignored one.
 * - A bun.lockb sighting with no surviving bun target in its directory yields a
 *   warning naming the migration command; beside a bun.lock target it is
 *   silent. Excluded identities produce neither targets nor bun.lockb
 *   warnings.
 */
export function discoverTargetsWithWarnings(
  repoRoot: string,
  opts?: DiscoverOptions,
): DiscoveryResult {
  const toolDir =
    opts?.toolDir === undefined ? undefined : resolve(opts.toolDir);
  const matchers = (opts?.excludes ?? []).map(globToRegExp);
  const found: DiscoveredTarget[] = [];
  const bunLockbIdentities = new Set<string>();
  const csprojIdentities = new Set<string>();
  const pomIdentities = new Set<string>();
  const mavenTestSbomIdentities = new Set<string>();

  const identityOf = (dir: string): string =>
    relative(repoRoot, dir).split(sep).join("/") || ".";

  // True when this subdirectory should be descended into: skip node_modules,
  // .git, hidden dirs (.yarn/.cache/...), and the tool's own directory. Shared
  // verbatim with Dockerfile discovery via shouldDescendDir.
  const shouldDescend = (sub: string, name: string): boolean =>
    shouldDescendDir(sub, name, toolDir);

  const recordLockfile = (dir: string, fileName: string): void => {
    // Identity: forward-slash on every platform — raw path.relative output
    // contains backslashes on Windows.
    const identity = identityOf(dir);
    if (isExcluded(identity, matchers)) return;
    found.push({
      dir,
      identity,
      lockfile: LOCKFILES.get(fileName) as LockfileKind,
    });
  };

  const recordBunLockb = (dir: string): void => {
    // Observed, never a target: binary lockfiles are out of scope; the
    // post-step below decides whether the sighting warrants a migration
    // warning.
    const identity = identityOf(dir);
    if (isExcluded(identity, matchers)) return;
    bunLockbIdentities.add(identity);
  };

  const recordCsproj = (dir: string): void => {
    // Observed, never a target (the bun.lockb idiom for .NET): *.csproj is a
    // name PATTERN, so it cannot live in the exact-name LOCKFILES map; the
    // post-step below decides whether the sighting warrants the no-lock
    // migration warning. Directory.Packages.props is deliberately NOT a
    // trigger: it is not a project marker — a CPM repo with locks properly
    // committed would otherwise get a spurious root-level warning (the props
    // file's directory typically holds no lock), while a CPM repo WITHOUT
    // locks already warns once per project via its csproj dirs.
    const identity = identityOf(dir);
    if (isExcluded(identity, matchers)) return;
    csprojIdentities.add(identity);
  };

  const recordPom = (dir: string): void => {
    // Observed, never a target (the bun.lockb/csproj idiom, simplified: the
    // trigger is the exact name "pom.xml", no pattern needed — the
    // committed sidecar is a fixed-name per-module file). The post-step
    // below decides whether the sighting warrants the no-sidecar adoption
    // warning.
    const identity = identityOf(dir);
    if (isExcluded(identity, matchers)) return;
    pomIdentities.add(identity);
  };

  const recordMavenTestSbom = (dir: string): void => {
    // Observed, never a target: maven.test.sbom.json is optional-additive
    // (not in LOCKFILES) — the post-step below decides whether a lone
    // sighting (no maven.sbom.json in the same directory) warrants the
    // orphan warning.
    const identity = identityOf(dir);
    if (isExcluded(identity, matchers)) return;
    mavenTestSbomIdentities.add(identity);
  };

  const walk = (dir: string): void => {
    // Symlinks report isDirectory() === false on Dirent entries, so they are
    // never followed — no cycle traversal, no escape from repoRoot. Do not add
    // a followSymlinks option.
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        const sub = join(dir, entry.name);
        if (shouldDescend(sub, entry.name)) walk(sub);
      } else if (entry.isFile() && LOCKFILES.has(entry.name)) {
        recordLockfile(dir, entry.name);
      } else if (entry.isFile() && entry.name === "bun.lockb") {
        recordBunLockb(dir);
      } else if (entry.isFile() && entry.name.endsWith(".csproj")) {
        recordCsproj(dir);
      } else if (entry.isFile() && entry.name === "pom.xml") {
        recordPom(dir);
      } else if (entry.isFile() && entry.name === "maven.test.sbom.json") {
        recordMavenTestSbom(dir);
      }
    }
  };

  walk(repoRoot);
  const sorted = found.sort(
    (a, b) =>
      compareCodeUnits(a.identity, b.identity) ||
      compareCodeUnits(a.lockfile, b.lockfile),
  );

  const warnings: string[] = [];

  // Post-step 1: collapse same-dir JS lockfile collisions to the single
  // highest-precedence kind. Python kinds in the same directory are untouched —
  // cross-ecosystem pairs remain two targets.
  const jsByIdentity = new Map<string, DiscoveredTarget[]>();
  for (const target of sorted) {
    if (JS_PRECEDENCE.has(target.lockfile)) {
      const group = jsByIdentity.get(target.identity) ?? [];
      group.push(target);
      jsByIdentity.set(target.identity, group);
    }
  }
  const losers = new Set<DiscoveredTarget>();
  for (const [identity, group] of jsByIdentity) {
    if (group.length < 2) {
      continue;
    }
    const winner = group.reduce((best, candidate) =>
      (JS_PRECEDENCE.get(candidate.lockfile) as number) <
      (JS_PRECEDENCE.get(best.lockfile) as number)
        ? candidate
        : best,
    );
    const ignoredNames = group
      .filter((target) => target !== winner)
      .map((target) => lockfileNameFor(target.lockfile))
      .sort(compareCodeUnits);
    for (const target of group) {
      if (target !== winner) {
        losers.add(target);
      }
    }
    warnings.push(
      `target "${identity}" has multiple JS lockfiles — scanning ` +
        `${lockfileNameFor(winner.lockfile)} (precedence bun > pnpm > yarn > npm); ` +
        `ignoring ${ignoredNames.join(", ")}`,
    );
  }
  const targets = sorted.filter((target) => !losers.has(target));

  // Post-step 2: bun.lockb sightings. Silent when a bun.lock target survived in
  // the same directory (the text lockfile is authoritative); otherwise warn
  // naming the migration command.
  for (const identity of bunLockbIdentities) {
    const hasBunTarget = targets.some(
      (target) => target.identity === identity && target.lockfile === "bun",
    );
    if (!hasBunTarget) {
      warnings.push(
        `target "${identity}" has a binary bun.lockb, which is unsupported — ` +
          "run `bun install --save-text-lockfile` in that project to migrate, " +
          "then re-scan",
      );
    }
  }

  // Post-step 3: csproj sightings (the bun.lockb idiom for .NET). Silent when
  // a nuget target survived in the same directory (the committed lock is
  // authoritative); otherwise the directory joins the no-lock warning —
  // aggregated by default, per-directory under the verbose option.
  warnings.push(...locklessCsprojWarnings(csprojIdentities, targets, opts));

  // Post-step 4: pom.xml sightings (the csproj idiom, simplified to a fixed
  // name trigger). Silent when a maven target survived in the same
  // directory (the committed sidecar is authoritative); otherwise the
  // directory joins the no-sidecar warning — aggregated by default,
  // per-directory under the verbose option.
  warnings.push(...unsidecaredPomWarnings(pomIdentities, targets, opts));

  // Post-step 5: maven.test.sbom.json sightings (the pom.xml idiom,
  // suppressed by a surviving maven target in the same directory — a
  // committed maven.sbom.json is authoritative). The test doc is
  // optional-additive and never its own target, so a lone sighting must
  // never scan to zero silently.
  warnings.push(
    ...orphanedMavenTestSbomWarnings(mavenTestSbomIdentities, targets, opts),
  );

  warnings.sort(compareCodeUnits);
  return { targets, warnings };
}

/**
 * Collision-resolved target list only — thin wrapper over
 * discoverTargetsWithWarnings for callers that do not surface warnings.
 */
export function discoverTargets(
  repoRoot: string,
  opts?: DiscoverOptions,
): DiscoveredTarget[] {
  return discoverTargetsWithWarnings(repoRoot, opts).targets;
}
