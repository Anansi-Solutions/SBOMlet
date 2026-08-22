/**
 * What a maintainer can do about the clarify entries, read off one scanned model: versions an entry
 * could be extended to, entries nothing needs any more, and imported entries a policy entry decides
 * ahead of. Everything here is offline - the model already carries what the committed caches and
 * the in-depth memo recorded for each package, so a version nothing has been recorded for is
 * reported as unknown rather than looked up.
 *
 * Pure: the caller builds the model and owns any file it writes.
 */

import { annotateFindings, observedSignalBySource } from "../../normalize/normalize";
import { shadowedClarifications, type ShadowedClarification } from "../parse/clarificationsFile";
import { justificationValidity } from "../engine/justificationValidity";
import { matchesPackage, type PackageSelector } from "../engine/match";
import {
  staleDivergence,
  unnecessaryClarifyEntries,
  unusedRuleIds,
  type UnnecessaryClarifyEntry,
} from "../engine/evaluate";
import { clarifyCitation, type ClarifyRule } from "../schema/clarify";
import { emitClarifications } from "./emit";
import type { Policy } from "../schema";

import type {
  CanonicalDependencies,
  LicenseFinding,
  PackageEntry,
  Verdict,
} from "../../model/dependencies";

/**
 * What extending an entry to one uncovered version would mean.
 *
 * `extend` - every recorded detection still holds there, so the version can join the entry's list.
 * `review` - a recorded detection reads differently now, or the entry's stated reason no longer
 * holds at that version. `unknown` - a recorded lane has nothing to say about that version yet.
 * `settled` - that version needs no clarification: the sources already report what the entry says.
 */
export type UpgradeOutcome = "extend" | "review" | "unknown" | "settled";

/** One version an entry does not cover, and what was ascertained about it. */
export interface UpgradeAscertainment {
  /** The entry, cited as every other surface spells it. */
  readonly rule: string;
  /** The scanned package's display name. */
  readonly name: string;
  /** The version the entry says nothing about. */
  readonly version: string;
  readonly outcome: UpgradeOutcome;
  /** What was found, in the words the maintainer reads. */
  readonly detail: string;
}

/** Everything the three lanes have to say about one scanned model. */
export interface RefreshFindings {
  /** Uncovered versions, entry by entry and by package within an entry. */
  readonly upgrades: ReadonlyArray<UpgradeAscertainment>;
  /** Citations of entries that decided nothing at all. */
  readonly unused: ReadonlyArray<string>;
  /** Entries with nothing left to correct. */
  readonly unnecessary: ReadonlyArray<UnnecessaryClarifyEntry>;
  /** Imported entries a policy-file entry stands ahead of. */
  readonly shadowed: ReadonlyArray<ShadowedClarification>;
}

/** The entry's selector with its versions dropped: which packages it is about, at any version. */
function anyVersionOf(rule: ClarifyRule): PackageSelector {
  return {
    ...(rule.name !== undefined ? { name: rule.name } : {}),
    ...(rule.pattern !== undefined ? { pattern: rule.pattern } : {}),
  };
}

/** This package's finding when only these entries are offered to the annotator. */
function findingUnder(
  entry: PackageEntry,
  clarify: ReadonlyArray<ClarifyRule>,
): LicenseFinding | undefined {
  return annotateFindings({ packages: [entry] }, clarify).model.packages[0]?.finding;
}

/**
 * How this version disproves the entry's stated reason, or undefined while the reason still holds.
 * The signal is partitioned off the package's own claims against the finding the sources produce on
 * their own, which is the view the recorded detections were weighed against.
 */
function disprovedReason(
  rule: ClarifyRule,
  entry: PackageEntry,
  base: LicenseFinding,
): string | undefined {
  const validity = justificationValidity(rule, observedSignalBySource(entry.licenseClaims, base));

  return validity.outcome === "invalid" ? validity.reason : undefined;
}

/**
 * Run the entry at one version it does not cover and report what happened. The decision is the
 * engine's own: a copy of the entry scoped to that single version goes through the annotator, and
 * whether it applied, went stale, or found nothing to do is read off the resulting finding. Nothing
 * about the precondition or the fail-closed sweep is re-derived here.
 */
function ascertain(rule: ClarifyRule, entry: PackageEntry): UpgradeAscertainment | undefined {
  const base = findingUnder(entry, []);
  const applied = findingUnder(entry, [{ ...rule, version: [entry.version] }]);
  const row = { rule: clarifyCitation(rule), name: entry.name, version: entry.version };

  if (base === undefined || applied === undefined) {
    return undefined;
  }

  const stale = applied.staleOverride;

  if (stale !== undefined) {
    const nothingRecorded = stale.expected !== false && stale.observed.length === 0;

    return {
      ...row,
      outcome: nothingRecorded ? "unknown" : "review",
      detail: nothingRecorded
        ? `${staleDivergence(stale)} — run generate to record it, with --intensive for the in-depth lane`
        : staleDivergence(stale),
    };
  }

  if (applied.source !== "override") {
    return {
      ...row,
      outcome: "settled",
      detail: `the sources already report "${base.expression ?? "nothing precise"}", which satisfies the recorded expression`,
    };
  }

  const disproved = disprovedReason(rule, entry, base);

  return disproved === undefined
    ? {
        ...row,
        outcome: "extend",
        detail: `every recorded detection still holds at ${entry.version}`,
      }
    : { ...row, outcome: "review", detail: disproved };
}

/**
 * Every version this entry governs the package name of but says nothing about, in the model's own
 * purl order so one entry's rows are stable.
 */
function uncoveredVersions(
  rule: ClarifyRule,
  model: CanonicalDependencies,
): UpgradeAscertainment[] {
  const anyVersion = anyVersionOf(rule);

  return model.packages
    .filter((entry) => matchesPackage(anyVersion, entry) && !matchesPackage(rule, entry))
    .map((entry) => ascertain(rule, entry))
    .filter((row): row is UpgradeAscertainment => row !== undefined);
}

/** The uncovered versions of every entry that pins one - an entry naming none covers them all. */
function upgradeAscertainments(
  model: CanonicalDependencies,
  policy: Policy,
): UpgradeAscertainment[] {
  return policy.clarify
    .filter((rule) => rule.version !== undefined)
    .flatMap((rule) => uncoveredVersions(rule, model));
}

/**
 * The three lanes over one annotated, evaluated model. The verdicts and the used-entry set come
 * from the same run, so an entry reported unused here is one nothing in that run cited.
 */
export function refreshFindings(
  model: CanonicalDependencies,
  policy: Policy,
  verdicts: ReadonlyArray<Verdict>,
  usedClarifyIndices: ReadonlySet<number>,
): RefreshFindings {
  // Unused accounting covers the acceptances too; those are another subcommand's business.
  const clarifyIds = new Set(policy.clarify.map(clarifyCitation));

  return {
    upgrades: upgradeAscertainments(model, policy),
    unused: unusedRuleIds(policy, verdicts, usedClarifyIndices).filter((id) => clarifyIds.has(id)),
    unnecessary: unnecessaryClarifyEntries(model, policy),
    shadowed: shadowedClarifications(model, policy),
  };
}

/** How much here needs a maintainer's attention, counting every lane's rows alike. */
export function suggestionCount(findings: RefreshFindings): number {
  return (
    findings.upgrades.length +
    findings.unused.length +
    findings.unnecessary.length +
    findings.shadowed.length
  );
}

/** Does anything here need a maintainer's attention? The subcommand's exit code rests on this. */
export function anySuggestion(findings: RefreshFindings): boolean {
  return suggestionCount(findings) > 0;
}

/** The new text of the imported file, and which entries it differs from the old one by. */
export interface ClarificationsRewrite {
  /** The complete file, ready to write. */
  readonly text: string;
  /** Citations of the entries dropped, spelled in the numbering the old file had. */
  readonly removed: ReadonlyArray<string>;
  /** Citations of the entries whose version list grew, in that same numbering. */
  readonly extended: ReadonlyArray<string>;
}

/** The entry with `added` appended to its explicit version list - a pinned version never leaves. */
function withVersions(rule: ClarifyRule, added: ReadonlyArray<string>): ClarifyRule {
  const pinned =
    rule.version === undefined
      ? []
      : typeof rule.version === "string"
        ? [rule.version]
        : rule.version;

  return {
    ...rule,
    version: [...pinned, ...added.filter((version) => !pinned.includes(version))],
  };
}

/** The versions each entry was ascertained to cover already, keyed by citation. */
function ascertainedVersions(
  findings: RefreshFindings,
): ReadonlyMap<string, ReadonlyArray<string>> {
  const byRule = new Map<string, string[]>();

  for (const row of findings.upgrades) {
    if (row.outcome === "extend") {
      byRule.set(row.rule, [...(byRule.get(row.rule) ?? []), row.version]);
    }
  }

  return byRule;
}

/**
 * The imported file rewritten to what these findings ascertained, or undefined when they
 * ascertained nothing to change. Only two edits are ever applied without a person: dropping an
 * entry every package it governs says is finished, and adding a version the engine itself accepted
 * under the entry. An entry that merely never matched stays - it may be waiting for a package that
 * is temporarily absent, and only a person can tell which. The policy proper is not passed here at
 * all; it is only ever suggested against.
 *
 * @throws Error when the new text would not read back as the entries it was built from.
 */
export function rewriteClarifications(
  imported: ReadonlyArray<ClarifyRule>,
  findings: RefreshFindings,
): ClarificationsRewrite | undefined {
  const finished = new Set(findings.unnecessary.map((entry) => entry.rule));
  const ascertained = ascertainedVersions(findings);
  const removed: string[] = [];
  const extended: string[] = [];
  const kept: ClarifyRule[] = [];

  for (const rule of imported) {
    const citation = clarifyCitation(rule);
    const added = ascertained.get(citation);

    if (finished.has(citation)) {
      removed.push(citation);
    } else if (added === undefined) {
      kept.push(rule);
    } else {
      extended.push(citation);
      kept.push(withVersions(rule, added));
    }
  }

  if (removed.length === 0 && extended.length === 0) {
    return undefined;
  }

  return { text: emitClarifications(kept), removed, extended };
}
