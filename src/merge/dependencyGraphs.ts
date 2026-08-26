/**
 * Which scanned targets have a dependency graph, and the integrity check that keeps that answer
 * honest.
 *
 * Graphedness is a property of the COLLECTOR LANE, never of the data that happened to arrive: the
 * yarn-plugin and poetry registrations reconstruct a root-anchored graph by construction, every
 * other lane emits a flat inventory. Reading it off the data instead would let a generator
 * regression silently reclassify a target as graphless, and with it flip the reserved `self` parent
 * from "the direct edge" to "every occurrence" - a silent widening of an acceptance nobody rewrote.
 *
 * @privateRemarks
 * The check below is deliberately narrower than "every occurrence of such a target carries an
 * introduction", because neither lane constructs that:
 *  - the npm lane keys its graph on `bom-ref`, so a component carrying a purl but no bom-ref is
 *    absent from it, and the whole lane abstains (empty map) on a BOM whose root cannot be located
 *    or anchored;
 *  - the poetry lane derives its graph from poetry.lock while cdxgen supplies the inventory, so a
 *    component the lock does not carry has no introduction to join onto.
 * What both lanes DO construct is all-or-nothing at target level: a target that produced a usable
 * graph carries introductions for the packages that graph covers. A target that produced none at
 * all is the regression this check catches. A partial gap is handled where the chain is walked: an
 * occurrence without an introduction is covered by no parent, so it is never accepted through one
 * - the fail-closed direction.
 */

import {
  compareCodeUnits,
  type CanonicalDependencies,
  type TargetIdentity,
} from "../model/dependencies";
import type { CollectedSbom } from "./merge";

/** How many package names an integrity failure quotes before summarizing the rest. */
const NAMED_PACKAGE_LIMIT = 3;

/**
 * The identities of the targets whose collector lane derives a dependency graph. Everything
 * downstream that distinguishes a chain-checkable target from a flat inventory reads this one set.
 */
export function targetsWithDependencyGraph(
  inputs: ReadonlyArray<CollectedSbom>,
): ReadonlySet<TargetIdentity> {
  const targets = new Set<TargetIdentity>();

  for (const input of inputs) {
    if (input.derivesDependencyGraph === true) {
      targets.add(input.targetIdentity);
    }
  }

  return targets;
}

/** The quoted package-name list an integrity failure carries, sorted and capped. */
function namedPackages(names: readonly string[]): string {
  const sorted = [...names].sort(compareCodeUnits);
  const quoted = sorted.slice(0, NAMED_PACKAGE_LIMIT).join(", ");
  const rest = sorted.length - NAMED_PACKAGE_LIMIT;

  return rest > 0 ? `${quoted}, and ${rest} more` : quoted;
}

/** Package names occurring at `target`, and how many of them carry an introduction. */
function coverageAt(
  model: CanonicalDependencies,
  target: string,
): { names: string[]; covered: number } {
  const names: string[] = [];
  let covered = 0;

  for (const entry of model.packages) {
    for (const occurrence of entry.occurrences) {
      if (occurrence.target !== target) {
        continue;
      }

      names.push(entry.name);
      if (occurrence.introduction !== undefined) {
        covered += 1;
      }
    }
  }

  return { names, covered };
}

/**
 * Refuse to proceed when a target whose lane derives a dependency graph arrived without one.
 *
 * @throws Error naming the target, how many packages it reported and the first few of them - the
 * tool/config exit path. The alternative would be to treat that target as graphless, which reads
 * every `as-dependency-of` entry as covering every introduction path there: an acceptance widened
 * by a generator regression rather than by a decision.
 */
export function assertDependencyGraphCoverage(
  model: CanonicalDependencies,
  targetsWithGraph: ReadonlySet<string>,
): void {
  for (const target of targetsWithGraph) {
    const { names, covered } = coverageAt(model, target);

    if (names.length === 0 || covered > 0) {
      continue;
    }

    throw new Error(
      `target "${target}" is collected by a lane that derives a dependency graph, but none of its ${names.length} packages carries introduction data (${namedPackages(names)}) - the scan produced no usable graph for it. Re-run the scan for that target: an "as-dependency-of" acceptance cannot be checked without a graph, and the tool never falls back to accepting every introduction path instead.`,
    );
  }
}
