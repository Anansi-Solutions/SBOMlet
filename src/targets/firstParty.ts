/**
 * First-party member-name set from a target's own yarn lockfile.
 *
 * The exclusion set is built from the lockfile's resolution descriptors — the
 * target's own workspace-member declarations — never from name heuristics.
 * This repo links first-party libraries via the `portal:` protocol, so both
 * `@workspace:` and `@portal:` descriptors count as first-party.
 *
 * The merge layer additionally requires version === "0.0.0-use.local" (the
 * marker both generators emit identically for workspace/portal components)
 * before skipping — belt-and-braces.
 *
 * Pure function: no I/O, no logging (the caller reads the file).
 *
 * This module also hosts the lockfile entry counters the coverage policy
 * consumes: thirdPartyEntryCount (yarn), pythonThirdPartyEntryCount
 * (poetry/uv), npmThirdPartyEntryCount / npmFirstPartyNames
 * (package-lock.json v2/v3, plain JSON), pnpmThirdPartyEntryCount /
 * pnpmImporterNames (pnpm-lock.yaml v6/v9, stateful line scan), and
 * nugetThirdPartyEntryCount (packages.lock.json, plain JSON). It also hosts
 * yarnWorkspaceMembers, the root-lockfile workspace enumeration primitive
 * (resolution-body-line scan, lockfile-authoritative). All keep the same
 * contract: pure text in, data out, never throw on garbage.
 */

import { type } from "arktype";

import { NpmLockDocument } from "../validate/npmLock";
import { NugetLockDocument } from "../validate/nugetLock";
import { recordOf } from "../validate/record";

/**
 * Matches one lockfile descriptor whose protocol is workspace: or portal:,
 * capturing the package name (which may itself contain "@", e.g.
 * "@scratch/foo" — the lazy quantifier extends past the leading scope "@").
 * Linear-time on lockfile lines: the lazy quantifier is bounded by the line
 * and the pattern has no nested quantifiers (ReDoS-resistant).
 */
const FIRST_PARTY_RE = /^"?(.+?)@(?:workspace|portal):/;

/**
 * Scan lockfile entry-header lines (start non-whitespace, end with ":")
 * and collect the names of all workspace/portal-resolved descriptors.
 * Each comma-separated descriptor in a header is tested individually
 * (e.g. `"pkg@npm:^1.0.0, pkg@portal:../libraries/pkg":`). Indented body
 * lines and malformed lines contribute nothing, never throw.
 */
export function firstPartyNames(lockfileText: string): Set<string> {
  const names = new Set<string>();
  for (const rawLine of lockfileText.split("\n")) {
    const line = rawLine.trimEnd(); // tolerate CRLF lockfiles
    if (line.length === 0) continue;
    // Entry headers start in column 0; indented lines are entry bodies.
    if (line[0] === " " || line[0] === "\t") continue;
    if (!line.endsWith(":")) continue;
    for (const descriptor of line.split(", ")) {
      const match = FIRST_PARTY_RE.exec(descriptor);
      const name = match?.[1];
      if (name !== undefined) names.add(name);
    }
  }
  return names;
}

/**
 * Matches one indented `resolution:` body line for a `@workspace:` entry,
 * capturing the member name (lazy quantifier, same scoped-name posture as
 * FIRST_PARTY_RE — extends past a leading "@") and the literal relative
 * path Yarn already resolved (verified Yarn-Berry shape: `resolution:
 * "backend@workspace:backend"`, root as `"proj@workspace:."`). Line-bounded,
 * no nested quantifiers (ReDoS-resistant, same posture as FIRST_PARTY_RE).
 */
const WORKSPACE_RESOLUTION_RE = /^[ \t]+resolution: "(.+?)@workspace:([^"]+)"$/;

/** Matches the entry's own `dependencies:` block header (indented, exact). */
const DEPENDENCIES_BLOCK_RE = /^[ \t]+dependencies:$/;

/**
 * Enumerate a root Yarn-Berry lockfile's workspace members from `resolution:`
 * body lines — NOT entry headers. Headers can carry `workspace:^` /
 * `workspace:*` range descriptors when workspaces depend on each other
 * (those are ranges, not paths); only the resolution line inside an entry's
 * body is the literal path Yarn itself resolved, including glob-form
 * `workspaces` fields (`"libs/*"` resolves to a literal relative path in the
 * lock — zero glob code needed here, ADR-0015 posture).
 *
 * `hasDependencies` is derived from the SAME entry block containing an
 * indented `dependencies:` line — the lockfile-authoritative signal for the
 * per-workspace zero-dependency skip (a member without one is the loud
 * warn+skip case upstream, never a silent drop or hard fail).
 *
 * Path containment is deliberately NOT this parser's job: relPath is
 * returned VERBATIM (including traversal or absolute forms a hostile lock
 * could contain) — the collect loop enforces containment before any
 * subprocess spawn uses it as a cwd.
 *
 * Stateful single-pass line scan (the pnpmThirdPartyEntryCount idiom):
 * column-0 lines flush the current candidate and start a new one; never
 * throws on garbage, CRLF-tolerant via trimEnd.
 */
export function yarnWorkspaceMembers(
  lockfileText: string,
): { name: string; relPath: string; hasDependencies: boolean }[] {
  const members: { name: string; relPath: string; hasDependencies: boolean }[] =
    [];
  let candidate: { name: string; relPath: string } | undefined;
  // Per-BLOCK flag, independent of whether the resolution: line has been
  // seen yet: key order within an entry is not this parser's assumption
  // (a YAML normalizer sorting keys alphabetically emits dependencies:
  // before resolution:), so the flag is recorded whenever the line appears
  // inside the current block and paired with the candidate at flush time.
  let hasDependencies = false;

  const flush = (): void => {
    if (candidate !== undefined) {
      members.push({ ...candidate, hasDependencies });
    }
    candidate = undefined;
    hasDependencies = false;
  };

  for (const rawLine of lockfileText.split("\n")) {
    const line = rawLine.trimEnd(); // tolerate CRLF lockfiles
    if (line.length === 0) continue;
    if (line[0] !== " " && line[0] !== "\t") {
      // Column-0 line: a new entry header — flush the previous candidate.
      flush();
      continue;
    }
    const match = WORKSPACE_RESOLUTION_RE.exec(line);
    if (match !== null) {
      candidate = {
        name: match[1] as string,
        relPath: match[2] as string,
      };
      continue;
    }
    if (DEPENDENCIES_BLOCK_RE.test(line)) {
      hasDependencies = true;
    }
  }
  flush();
  return members;
}

/**
 * Count the lockfile's THIRD-PARTY entry headers: entry headers (same
 * column-0/":"-terminated shape as firstPartyNames) whose descriptors are
 * all NON-workspace/portal, excluding the `__metadata:` block header.
 *
 * A legitimate zero-dependency Yarn-4 workspace has a non-empty yarn.lock
 * (always `__metadata:` plus the project's own `"proj@workspace:."`
 * self-entry) that scans to zero components — a count of 0 here lets the
 * coverage policy take the loud warn+skip branch instead of hard-failing the
 * whole run. Comment-only Yarn-1 placeholder lockfiles also count 0 (they
 * genuinely have zero entries).
 */
export function thirdPartyEntryCount(lockfileText: string): number {
  let count = 0;
  for (const rawLine of lockfileText.split("\n")) {
    const line = rawLine.trimEnd(); // tolerate CRLF lockfiles
    if (line.length === 0) continue;
    if (line[0] === " " || line[0] === "\t") continue;
    if (!line.endsWith(":")) continue;
    if (/^"?__metadata"?:$/.test(line)) continue;
    // A header containing ANY workspace:/portal: descriptor resolves to a
    // first-party member — it is not a third-party entry.
    if (
      line.split(", ").some((descriptor) => FIRST_PARTY_RE.test(descriptor))
    ) {
      continue;
    }
    count += 1;
  }
  return count;
}

/**
 * Count the third-party `[[package]]` tables of a python lockfile (poetry.lock
 * or uv.lock) — the python counterpart of thirdPartyEntryCount.
 *
 * poetry.lock never lists the root project, so every `[[package]]` table
 * counts. uv.lock always lists the root project (and any workspace members) as
 * `[[package]]` entries whose source is local —
 * `source = { virtual = "." }` / `source = { editable = "..." }` — those are
 * first-party and excluded, mirroring the workspace:/portal: rule above.
 *
 * A legitimate dependency-free python target therefore counts 0 here (poetry:
 * metadata block only; uv: just the local self entry) and takes the loud
 * warn+skip branch of the coverage policy instead of hard-failing the entire
 * run. A lockfile with third-party entries that scans to zero components still
 * hard-fails. Same posture as the yarn parser: regex over text lines, no TOML
 * parser, malformed lines contribute nothing and never throw.
 */
export function pythonThirdPartyEntryCount(lockfileText: string): number {
  let count = 0;
  let inPackage = false;
  let isLocal = false;
  const flush = (): void => {
    if (inPackage && !isLocal) count += 1;
  };
  for (const rawLine of lockfileText.split("\n")) {
    const line = rawLine.trimEnd(); // tolerate CRLF lockfiles
    if (/^\[\[package\]\]$/.test(line)) {
      flush();
      inPackage = true;
      isLocal = false;
      continue;
    }
    // A local-source line inside the current [[package]] block marks the
    // entry first-party (uv's root/workspace self entries).
    if (
      inPackage &&
      /^source\s*=\s*\{[^}]*\b(?:virtual|editable)\s*=/.test(line)
    ) {
      isLocal = true;
    }
  }
  flush();
  return count;
}

/**
 * Count the third-party entries of a package-lock.json (v2/v3) — the npm
 * counterpart of thirdPartyEntryCount.
 *
 * package-lock.json is plain JSON, so JSON.parse is exact. The v2/v3
 * `packages` map keys the verified shapes:
 *
 *   "node_modules/express": { "version": "5.2.1", "license": "MIT" }  // third-party
 *   "node_modules/liba": { "resolved": "packages/liba", "link": true } // workspace link
 *   "packages/liba": { "version": "0.1.0" }                            // local dir entry
 *   "": { ... }                                                        // the root project
 *
 * Third-party = keys containing "node_modules" whose entry link !== true.
 *
 * Returns `undefined` (unknown count) — not 0 — when the text is not JSON or
 * there is no object-shaped `packages` key: lockfileVersion 1 has no
 * `packages` map, and a garbage file proves nothing. Unknown routes the target
 * to the scan, so a zero-component result still hard-fails loudly; only a
 * positively-determined zero (a `packages` map with no third-party keys) takes
 * the warn+skip branch. Never throws.
 */
export function npmThirdPartyEntryCount(
  lockfileText: string,
): number | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(lockfileText);
  } catch {
    return undefined;
  }
  // A failed document narrow is the unknown path — same as no packages map.
  const doc = NpmLockDocument(parsed);
  const packages = doc instanceof type.errors ? undefined : doc.packages;
  if (packages === undefined) {
    return undefined;
  }
  let count = 0;
  for (const [key, raw] of Object.entries(packages)) {
    if (!key.includes("node_modules")) {
      continue;
    }
    if (recordOf(raw)?.["link"] === true) {
      continue; // workspace link → first-party
    }
    count += 1;
  }
  return count;
}

/**
 * First-party member-name set from a package-lock.json (v2/v3) — the npm
 * counterpart of firstPartyNames.
 *
 * Two verified lockfile shapes contribute (npm workspace members carry real
 * versions, never 0.0.0-use.local — the yarn-era version guard does not
 * apply):
 *
 * - link entries: keys "node_modules/<name>" with link === true → <name> (the
 *   leading "node_modules/" prefix is stripped, preserving scoped names like
 *   "@scope/liba")
 * - local-path entries: keys k !== "" not containing "node_modules" → the
 *   entry's `name` field, falling back to the path basename
 *
 * The merge layer additionally requires the cdx:npm:isWorkspace="true"
 * component property before skipping (belt-and-braces) — a name collision
 * alone must never drop a third-party package.
 *
 * Garbage or shape-less JSON yields an empty set; never throws.
 */
export function npmFirstPartyNames(lockfileText: string): ReadonlySet<string> {
  const names = new Set<string>();
  let parsed: unknown;
  try {
    parsed = JSON.parse(lockfileText);
  } catch {
    return names;
  }
  const doc = NpmLockDocument(parsed);
  const packages = doc instanceof type.errors ? undefined : doc.packages;
  if (packages === undefined) {
    return names;
  }
  for (const [key, raw] of Object.entries(packages)) {
    const entry = recordOf(raw);
    if (key.startsWith("node_modules/") && entry?.["link"] === true) {
      names.add(key.slice("node_modules/".length));
    } else if (key !== "" && !key.includes("node_modules")) {
      const name = entry?.["name"];
      names.add(
        typeof name === "string" ? name : key.slice(key.lastIndexOf("/") + 1),
      );
    }
  }
  return names;
}

/**
 * Count the third-party entries of a packages.lock.json — the nuget
 * counterpart of npmThirdPartyEntryCount.
 *
 * packages.lock.json is plain strict JSON; the document narrow is
 * single-sourced with the collector (src/validate/nugetLock.ts) so the
 * counter and the collector can never disagree on the same lock. Entries
 * with `type === "Project"` (first-party project references) are excluded —
 * the collector's ONE exclusion, mirrored exactly; every other entry counts,
 * including unknown future types and malformed entries (counting them errs
 * toward the scan, where a zero-component result hard-fails loudly — a
 * crafted lock can never flip the warn+skip branch to hide dependencies).
 * Entries are counted across ALL dependency sections (one per target
 * framework, plus `<tfm>/<rid>` pairs), without dedup — only the strict
 * `=== 0` comparison downstream consumes the value.
 *
 * Returns `undefined` (unknown count) — not 0 — for non-JSON text, a failed
 * document narrow, or a missing dependencies map: a garbage file proves
 * nothing. Unknown routes the target to the scan, so the collector's loud
 * throw or the zero-component hard-fail fires; only a positively-determined
 * zero (every section empty or Project-only) takes the warn+skip branch.
 * Never throws.
 */
export function nugetThirdPartyEntryCount(
  lockfileText: string,
): number | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(lockfileText);
  } catch {
    return undefined;
  }
  // A failed document narrow is the unknown path — same as no dependencies
  // map (the npmThirdPartyEntryCount posture).
  const doc = NugetLockDocument(parsed);
  const dependencies =
    doc instanceof type.errors ? undefined : doc.dependencies;
  if (dependencies === undefined) {
    return undefined;
  }
  let count = 0;
  for (const rawSection of Object.values(dependencies)) {
    const section = recordOf(rawSection);
    if (section === undefined) continue; // non-record section — nothing to count
    for (const rawEntry of Object.values(section)) {
      // Exclusion by type === "Project" ONLY; a malformed (non-record) entry
      // counts too — erring toward the scan, never toward a silent skip.
      if (recordOf(rawEntry)?.["type"] !== "Project") count += 1;
    }
  }
  return count;
}

/**
 * Count the third-party entries of a pnpm-lock.yaml — the pnpm counterpart of
 * thirdPartyEntryCount.
 *
 * Stateful line scan in the pythonThirdPartyEntryCount idiom — no YAML parser
 * (zero-dep constraint), trimEnd tolerates CRLF checkouts. The current
 * top-level section is tracked via column-0 `header:` lines; inside
 * `packages:`, exactly-two-space-indented key lines ending ":" count. Verified
 * key shapes:
 *
 *   v9: "  smol-toml@1.6.1:"          v6: "  /smol-toml@1.6.1:"
 *   quoted: "  '@types/node@1.0.0':"  (single or double quotes)
 *
 * Deeper-indented property lines (resolution:, dependencies:, ...) never match
 * the two-space anchor. An importers-only lockfile (workspace with no external
 * deps — no packages: section) counts 0, the positively-determined
 * zero-third-party warn+skip branch. Malformed lines contribute nothing; never
 * throws (linear-time regexes).
 */
export function pnpmThirdPartyEntryCount(lockfileText: string): number {
  let count = 0;
  let section = "";
  for (const rawLine of lockfileText.split("\n")) {
    const line = rawLine.trimEnd(); // tolerate CRLF lockfiles
    if (line.length === 0) continue;
    if (line[0] !== " " && line[0] !== "\t") {
      // Column-0 line: a new top-level section (importers:, packages:,
      // snapshots:, settings:, lockfileVersion: ...).
      const header = /^([^\s:]+):/.exec(line);
      if (header !== null) section = header[1] as string;
      continue;
    }
    if (section !== "packages") continue;
    if (/^ {2}\S/.test(line) && line.endsWith(":")) {
      count += 1;
    }
  }
  return count;
}

/**
 * First-party member-name set from a pnpm-lock.yaml: the path basenames of all
 * importer keys other than "." (the root importer).
 *
 * Belt-and-braces only: cdxgen already omits pnpm workspace members from
 * components entirely (the member appears only as internal:workspaceRef
 * attribution on its deps), so this set is a defensive second condition in the
 * merge. The merge never drops a package on a name match alone.
 *
 * Importer key shape: two-space-indented "  <path>:" lines inside the
 * importers: section, e.g. "  packages/liba:". Garbage yields an empty set;
 * never throws.
 */
export function pnpmImporterNames(lockfileText: string): ReadonlySet<string> {
  const names = new Set<string>();
  let section = "";
  for (const rawLine of lockfileText.split("\n")) {
    const line = rawLine.trimEnd(); // tolerate CRLF lockfiles
    if (line.length === 0) continue;
    if (line[0] !== " " && line[0] !== "\t") {
      const header = /^([^\s:]+):/.exec(line);
      if (header !== null) section = header[1] as string;
      continue;
    }
    if (section !== "importers") continue;
    const match = /^ {2}(\S+):/.exec(line);
    if (match === null) continue;
    // Strip optional surrounding quotes from the importer path key.
    const key = (match[1] as string).replace(/^['"]|['"]$/g, "");
    if (key === ".") continue; // the root importer is the target itself
    names.add(key.slice(key.lastIndexOf("/") + 1));
  }
  return names;
}
