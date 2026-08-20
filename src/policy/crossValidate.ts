/**
 * The policy-against-model pass: everything about a `[[compatible]]` entry that can only be decided
 * once the scan has produced a model, checked BEFORE any verdict is computed.
 *
 * The file parser sees text and nothing else, so it can accept an entry whose `as-dependency-of`
 * names a package no scan ever saw, or scopes a chain-based judgment to a target where no chain
 * exists. Neither can be answered by voiding the entry later: the resulting failures would cite an
 * introduction path that was never checked. They are configuration errors, reported together with
 * the entry, the target and what to write instead.
 *
 * Validity depends on the model, so it can change without the policy changing - adding a first
 * target without a dependency graph can invalidate an entry that was fine yesterday. That is the
 * point: the entry says something the new scan cannot check.
 */

import { dependencyGraphsByTarget, type TargetDependencyGraph } from "./chain";
import { matchesPackage, scopeCoversTarget } from "./packageMatch";
import { PolicyError, SELF_PARENT, type CompatiblePackageRule, type Policy } from "./schema";
import type { CanonicalDependencies, Occurrence, PackageEntry } from "../model/dependencies";

/** One package an entry covers, at one occurrence its `where` scope reaches. */
interface Governed {
  entry: PackageEntry;
  occurrence: Occurrence;
}

/** Every (package, occurrence) pair a package-form entry decides, in model order. */
function governedBy(rule: CompatiblePackageRule, model: CanonicalDependencies): Governed[] {
  const governed: Governed[] = [];

  for (const entry of model.packages) {
    if (!matchesPackage(rule, entry)) {
      continue;
    }

    for (const occurrence of entry.occurrences) {
      if (scopeCoversTarget(rule.where, occurrence.target)) {
        governed.push({ entry, occurrence });
      }
    }
  }

  return governed;
}

/** Does any node of this target's graph go by `name`? */
function graphCarriesName(graph: TargetDependencyGraph | undefined, name: string): boolean {
  for (const nodeName of graph?.names.values() ?? []) {
    if (nodeName === name) {
      return true;
    }
  }

  return false;
}

/**
 * Every parent an entry names must be checkable at every target it governs: a target without a
 * dependency graph has no introduction path to check at all, and a name no node of the graph
 * carries would otherwise void the entry with a reason citing a package that is not there.
 */
function checkParents(
  id: string,
  rule: CompatiblePackageRule,
  governed: readonly Governed[],
  targetsWithGraph: ReadonlySet<string>,
  graphs: ReadonlyMap<string, TargetDependencyGraph>,
  problems: string[],
): void {
  const named = rule.asDependencyOf.filter((parent) => parent !== SELF_PARENT);

  if (named.length === 0) {
    return;
  }

  const reported = new Set<string>();

  for (const { entry, occurrence } of governed) {
    const target = occurrence.target;

    if (reported.has(target)) {
      continue;
    }

    if (!targetsWithGraph.has(target)) {
      reported.add(target);
      problems.push(
        `${id} ("${entry.name}"): "as-dependency-of" names "${named[0] as string}", but target "${target}" has no dependency graph, so no introduction path can be checked there. Narrow "where" to targets that have one, or use "${SELF_PARENT}" - which accepts every occurrence in a target without a graph, and says so.`,
      );
      continue;
    }

    const unresolved = named.find((parent) => !graphCarriesName(graphs.get(target), parent));

    if (unresolved !== undefined) {
      reported.add(target);
      problems.push(
        `${id} ("${entry.name}"): "as-dependency-of" names "${unresolved}", which is not part of target "${target}"'s dependency graph - nothing of that name introduces anything there. Correct the name, or narrow "where" to the targets where it is.`,
      );
    }
  }
}

/**
 * The two rationales the scanned shape can contradict outright. The others state a judgment about
 * how the software is built that no scan observes - overriding what the tool concluded is exactly
 * what they are for - so they are never checked here.
 */
function checkRationale(
  id: string,
  rule: CompatiblePackageRule,
  governed: readonly Governed[],
  problems: string[],
): void {
  if (rule.rationale === "os-package-unmodified") {
    const offender = governed.find(({ entry }) => entry.scope !== "os");

    if (offender !== undefined) {
      problems.push(
        `${id} ("${offender.entry.name}"): rationale "os-package-unmodified" describes a distribution package shipped inside a container image, but this entry governs "${offender.entry.name}" in target "${offender.occurrence.target}", which is not one. Choose the rationale that fits, or narrow "where" to the image layer.`,
      );
    }
  }

  if (rule.rationale === "unused-transitive") {
    const offender = governed.find(({ occurrence }) => occurrence.introduction?.direct === true);

    if (offender !== undefined) {
      problems.push(
        `${id} ("${offender.entry.name}"): rationale "unused-transitive" says the package is pulled in by a dependency, but "${offender.entry.name}" is a direct dependency of target "${offender.occurrence.target}". Choose the rationale that fits, or narrow "where" to the targets where it is transitive.`,
      );
    }
  }
}

/**
 * The reserved token means the project itself, and nothing tells it apart from a real package of
 * the same name - so a model carrying one makes every entry using the token ambiguous. Reported
 * rather than resolved by precedence: either reading would silently decide acceptances.
 */
function checkSelfToken(
  id: string,
  rule: CompatiblePackageRule,
  selfPackage: PackageEntry | undefined,
  problems: string[],
): void {
  if (selfPackage === undefined || !rule.asDependencyOf.includes(SELF_PARENT)) {
    return;
  }

  problems.push(
    `${id}: "as-dependency-of" uses the reserved token "${SELF_PARENT}", but the scan found a real package of that name (${selfPackage.purl}) - nothing tells the two apart. Decide the case by hand: accept this package through a licence-form entry, or narrow "where" to targets that package does not reach.`,
  );
}

/**
 * Check every `[[compatible]]` package entry against the scanned model.
 *
 * @throws PolicyError carrying every problem found, so one run reports them all - the config-error
 * exit path, taken before any verdict exists.
 *
 * @privateRemarks
 * Licence-form entries are not checked here: which packages they decide follows from normalized
 * findings, which this pass runs too early to see. Their scope and pattern are already validated by
 * the schema.
 */
export function crossValidatePolicy(
  model: CanonicalDependencies,
  policy: Policy,
  targetsWithGraph: ReadonlySet<string>,
): void {
  const problems: string[] = [];
  const graphs = dependencyGraphsByTarget(model);
  const selfPackage = model.packages.find((entry) => entry.name === SELF_PARENT);

  policy.compatible.forEach((rule, index) => {
    if (rule.match !== "package") {
      return;
    }

    const id = `compatible[${index}]`;
    const governed = governedBy(rule, model);

    if (governed.length === 0) {
      return; // an entry that decides nothing is the unused-entry report's business, not an error
    }

    checkSelfToken(id, rule, selfPackage, problems);
    checkParents(id, rule, governed, targetsWithGraph, graphs, problems);
    checkRationale(id, rule, governed, problems);
  });

  if (problems.length > 0) {
    throw new PolicyError(problems);
  }
}
