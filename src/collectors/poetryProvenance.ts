/**
 * Python dependency provenance from poetry.lock + pyproject.toml.
 *
 * @privateRemarks
 * cdxgen --no-install-deps yields no usable graph, so we use the lockfile.
 *
 * The lockfile's `[package.dependencies]` tables are the edges;
 * pyproject declares the roots. Optionality is out of scope by
 * decision — poetry marker semantics were a recurring mislabeling
 * bug source (see docs/explanation/adr/0014-dependency-provenance.md).
 *
 * - Each poetry.lock `[[package]]` carries a `[package.dependencies]` table
 * (the introducer edges);
 * - pyproject gives the declared-direct roots: `[project].dependencies`
 * (PEP 621 `"name (constraint)"`) when present is authoritative, else
 * - the legacy `[tool.poetry.dependencies]` table;
 * + every `[tool.poetry.group.<name>.dependencies]` table, always.
 *
 * Optionality is deliberately ignored. Deriving optionality from poetry
 * markers (`optional = true`, PEP 508 marker variables, extras, multi-variant
 * spec arrays) was a recurring mislabeling bug class.
 * The `optional` distinction is ignored: no required-vs-optional partition.
 */


import { parse as parseToml } from "smol-toml";

import { recordOf, stringOf } from "../validate/record";
import {
  addToSetMap,
  deriveIntroductions,
  sortSetMap,
  type PurlGraph,
} from "./provenanceGraph";
import type { DependencyIntroduction } from "../model/dependencies";

/**
 * PEP 503 name normalization — the exact transform cdxgen applies before
 * emitting a `pkg:pypi/<name>` purl: lowercase, and replace every run of
 * `[-_.]+` with a single hyphen. Shared contract with poetryLock.ts.
 */
function normalizePep503(name: string): string {
  return name.replace(/[-_.]+/g, "-").toLowerCase();
}

/**
 * Add every name key of a poetry dependency TABLE (keyed by name) to the root
 * set, PEP-503 normalized. The conventional `python` key is skipped — it is the
 * interpreter constraint, not a package. Shared by the legacy main table and
 * every dependency-group table.
 */
function addTableNames(
  roots: Set<string>,
  table: Record<string, unknown> | undefined,
): void {
  if (table === undefined) return;
  for (const name of Object.keys(table)) {
    if (name.toLowerCase() === "python") continue; // the interpreter, not a dep
    roots.add(normalizePep503(name));
  }
}

/**
 * Extract the declared-direct ROOT names (PEP-503 normalized) from pyproject.
 *
 * MAIN deps: `[project].dependencies` (PEP 621 array of
 * `"name (constraint)"` strings) is AUTHORITATIVE when present. The legacy
 * `[tool.poetry.dependencies]` table is constraint/source metadata that may
 * list non-top-level names, so it is read as roots ONLY when
 * `[project].dependencies` is ABSENT (legacy-only poetry). Reading both
 * unconditionally let a transitive listed in the legacy table render "direct".
 *
 * GROUP deps: EVERY `[tool.poetry.group.<name>.dependencies]`
 * table contributes roots — a package declared direct in a group (e.g. the
 * conventional dev group) is genuinely direct. Groups are read in BOTH PEP 621
 * and legacy modes (they live under `[tool.poetry.group.*]` regardless of where
 * the main deps come from), independent of the main-deps precedence above.
 *
 * Returns a set of normalized names; garbage input contributes nothing.
 */
function declaredRootNames(pyprojectText: string): Set<string> {
  const roots = new Set<string>();
  let parsed: unknown;
  try {
    parsed = parseToml(pyprojectText);
  } catch {
    return roots;
  }
  const doc = recordOf(parsed);
  if (doc === undefined) return roots;

  // PEP 621: [project].dependencies = ["name (constraint)", ...]
  const project = recordOf(doc["project"]);
  const pep621 = project?.["dependencies"];
  const hasPep621Main = Array.isArray(pep621);
  if (hasPep621Main) {
    for (const raw of pep621) {
      const spec = stringOf(raw);
      if (spec === undefined) continue;
      const name = pep621Name(spec);
      if (name !== undefined) roots.add(normalizePep503(name));
    }
  }

  const poetry = recordOf(recordOf(doc["tool"])?.["poetry"]);

  // The legacy MAIN [tool.poetry.dependencies] table is a root source
  // ONLY when [project].dependencies is ABSENT — when present, PEP 621 is
  // authoritative and the legacy table is mere constraint/source metadata.
  if (!hasPep621Main) {
    addTableNames(roots, recordOf(poetry?.["dependencies"]));
  }

  // EVERY [tool.poetry.group.<name>.dependencies] table is ALWAYS a root
  // source, independent of the main-deps mode/precedence above.
  const groups = recordOf(poetry?.["group"]);
  if (groups !== undefined) {
    for (const groupName of Object.keys(groups)) {
      const group = recordOf(groups[groupName]);
      addTableNames(roots, recordOf(group?.["dependencies"]));
    }
  }

  return roots;
}

/**
 * The package name from a PEP 621 dependency spec: the leading run of
 * name-legal characters before the first space, `(`, `[`, or version operator.
 * E.g. "jupyterlab (>=4.5.0,<4.6.0)" → "jupyterlab"; "anyio[trio]>=4" → "anyio".
 */
function pep621Name(spec: string): string | undefined {
  const match = /^([A-Za-z0-9._-]+)/.exec(spec.trim());
  return match?.[1];
}

/** One lockfile package, narrowed to the fields provenance needs. */
interface LockPackage {
  purl: string;
  /** PEP-503 normalized name → for dependency-edge resolution. */
  normalizedName: string;
  /** Raw `[package.dependencies]` table (name → spec / spec[] / object). */
  dependencies: Record<string, unknown>;
}

/**
 * Parse poetry.lock into the package list (purl + normalized name + dep table).
 * A package missing a string name or version contributes nothing (cannot form a
 * purl). Garbage input yields an empty list.
 */
function parseLockPackages(lockfileText: string): LockPackage[] {
  let parsed: unknown;
  try {
    parsed = parseToml(lockfileText);
  } catch {
    return [];
  }
  const doc = recordOf(parsed);
  const packages = doc?.["package"];
  if (!Array.isArray(packages)) return [];
  const out: LockPackage[] = [];
  for (const raw of packages) {
    const pkg = recordOf(raw);
    if (pkg === undefined) continue;
    const name = stringOf(pkg["name"]);
    const version = stringOf(pkg["version"]);
    if (name === undefined || version === undefined) continue;
    const normalizedName = normalizePep503(name);
    out.push({
      purl: `pkg:pypi/${normalizedName}@${version}`,
      normalizedName,
      dependencies: recordOf(pkg["dependencies"]) ?? {},
    });
  }
  return out;
}

/** The mutable purl-space edge accumulators built per lock package. */
interface EdgeAccumulators {
  edgeSets: Map<string, Set<string>>;
  parentSets: Map<string, Set<string>>;
}

/**
 * Fold one lock package's `[package.dependencies]` edges into the accumulators.
 * A dep NAME (PEP-503 normalized) resolves to a purl ONLY when that name maps to
 * EXACTLY ONE lock purl (the honest residual); a dep naming a multi-version
 * name, or a name absent from the lock, is dropped — no edge fabricated.
 *
 * Optionality is descoped — the dep VALUE (a spec string, a spec object
 * with markers/optional/extras, or an array of conditional variants) is never
 * inspected. Every resolved dependency is just an edge.
 */
function ingestPackageEdges(
  edges: EdgeAccumulators,
  precisePurlByName: ReadonlyMap<string, string>,
  pkg: LockPackage,
): void {
  for (const depName of Object.keys(pkg.dependencies)) {
    const childPurl = precisePurlByName.get(normalizePep503(depName));
    // A name resolving to no purl (absent) OR to MORE THAN ONE purl
    // (multi-version / collision) is ambiguous — fabricate no edge.
    if (childPurl === undefined) continue;
    if (childPurl === pkg.purl) continue;
    addToSetMap(edges.edgeSets, pkg.purl, childPurl);
    addToSetMap(edges.parentSets, childPurl, pkg.purl);
  }
}

/**
 * Build the purl-space PurlGraph from the parsed lock packages + declared roots.
 * Every edge resolves the dependency NAME (PEP-503 normalized) to a lock
 * package's purl; a dependency naming a package absent from the lock is dropped
 * (no purl to point at).
 *
 * HONEST RESIDUAL ON VERSION AMBIGUITY:
 * version is part of the purl, so a dependency NAME alone cannot identify WHICH
 * version of a multi-version package an edge resolved to without PEP-440
 * constraint matching (deliberately out of scope — no new dependency). An
 * earlier draft unioned a name→constraint edge to EVERY purl sharing the name; that
 * conflated the npm same-purl peer-resolution case with the poetry
 * different-version case and produced two defects:
 *   - FABRICATION: `black` requires `click >=8`; a lock with click@7.1.2 +
 *     click@8.1.7 fabricated `black → click@7.1.2` (a chain in no real relation).
 *   - MISLABEL (#1): a declared-root NAME `foo` with foo@1.0.0 (real direct) +
 *     foo@2.0.0 (transitive via `bar`) marked BOTH versions `direct`.
 * The honest fix partitions the name→purl index by VERSION-MULTIPLICITY: a name
 * mapping to EXACTLY ONE lock purl is PRECISE (it resolves edges and, if a
 * declared root, marks that one purl direct); a name mapping to TWO OR MORE
 * lock purls (multi-version, or a genuine PEP-503 name-origin collision) is
 * AMBIGUOUS — it fabricates no edge and blanket-marks no version direct. A
 * multi-version purl still receives precise introducers from a single-version
 * parent whose own resolution is unambiguous; one with neither a precise
 * introducer nor a precise direct is the honest "—" residual.
 *
 * Optionality is descoped — there is no required/optional edge partition
 * and no required-reachability. Every resolved dependency is a plain edge.
 */
function buildPurlGraph(
  packages: readonly LockPackage[],
  rootNames: ReadonlySet<string>,
): PurlGraph {
  // Partition by version-multiplicity: a name → its single purl ONLY when it
  // maps to exactly one lock purl; multi-version names are dropped (ambiguous).
  const purlsByName = new Map<string, Set<string>>();
  const nodes = new Set<string>();
  for (const pkg of packages) {
    addToSetMap(purlsByName, pkg.normalizedName, pkg.purl);
    nodes.add(pkg.purl);
  }
  const precisePurlByName = new Map<string, string>();
  for (const [name, purls] of purlsByName) {
    if (purls.size === 1) precisePurlByName.set(name, [...purls][0]!);
  }

  const edges: EdgeAccumulators = {
    edgeSets: new Map<string, Set<string>>(),
    parentSets: new Map<string, Set<string>>(),
  };
  const rootChildren = new Set<string>();
  for (const pkg of packages) {
    // A declared-root NAME marks a purl direct ONLY when that name maps
    // to exactly one lock purl — a multi-version root name cannot identify WHICH
    // version is the real direct without PEP-440, so none is blanket-marked.
    if (
      rootNames.has(pkg.normalizedName) &&
      precisePurlByName.get(pkg.normalizedName) === pkg.purl
    ) {
      rootChildren.add(pkg.purl);
    }
    ingestPackageEdges(edges, precisePurlByName, pkg);
  }
  const { edgeSets, parentSets } = edges;

  return {
    edges: sortSetMap(edgeSets),
    parents: sortSetMap(parentSets),
    rootChildren,
    nodes,
  };
}

/**
 * Per-purl provenance for every poetry.lock package. The result is keyed by purl
 * (the merge dedup key); the caller threads each entry onto the matching python
 * occurrence. Empty map for garbage input.
 */
export function poetryIntroductions(
  lockfileText: string,
  pyprojectText: string,
): ReadonlyMap<string, DependencyIntroduction> {
  const packages = parseLockPackages(lockfileText);
  if (packages.length === 0) return new Map();
  const rootNames = declaredRootNames(pyprojectText);
  const graph = buildPurlGraph(packages, rootNames);
  return deriveIntroductions(graph);
}
