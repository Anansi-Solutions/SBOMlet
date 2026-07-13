/**
 * Deterministic CanonicalDependencies -> THIRD_PARTY_NOTICES.md renderer — the
 * companion bundle.
 *
 * Pure function: model in, exact LF bytes out. Layout: per-package attribution
 * sections (extracted copyright lines, Author fallback, NOTICE contents,
 * verbatim texts for the non-SPDX population) followed by a canonical
 * license-text appendix carrying one text per SPDX id referenced by any
 * normalized expression — the grouping bounds the file to ~0.5–1 MB at repo
 * scale instead of ~7 MB of repeated verbatim texts.
 *
 * Honesty rules: every canonical appendix entry carries the exact marker
 * "(canonical SPDX text — package-specific copyright not located)" so fallback
 * gaps are auditable, never silent; unknown-license packages are listed with
 * no text and flagged; an author is rendered as "Author:" attribution, never
 * as a fabricated copyright claim.
 *
 * Injection posture: every multi-line untrusted block (NOTICE contents,
 * verbatim texts, canonical texts) renders inside a fenced block whose fence is
 * computed longer than the longest backtick run in the content; every inline
 * position routes through escapeCell.
 *
 * This module deliberately does not fetch anything (the only data source
 * beyond the model is the pinned spdx-license-list data package, imported once
 * at module scope), fabricate copyright lines, or evaluate policy.
 */

import parse from "spdx-expression-parse";
import spdxFullData from "spdx-license-list/full";

import {
  compareCodeUnits,
  comparePackages,
  type CanonicalDependencies,
  type PackageEntry,
} from "../model/dependencies";
import { leafIds, type ExpressionNode } from "../normalize/expression";
import { escapeCell } from "./markdown";

const HEADER_LINE =
  "<!-- AUTO-GENERATED - do not edit. Regenerate with: task generate -->";

const CANONICAL_MARKER =
  "(canonical SPDX text — package-specific copyright not located)";

const PROSE =
  "Attribution is grouped to avoid duplication: the per-package sections below " +
  "reproduce extracted copyright lines, NOTICE file contents, and verbatim " +
  "license texts for packages without a standard SPDX license; the License " +
  "texts appendix then carries one canonical text per referenced SPDX license " +
  'identifier. Every canonical appendix entry is marked "(canonical SPDX text ' +
  '— package-specific copyright not located)" so fallback gaps stay auditable; ' +
  "packages whose license could not be determined are listed separately with " +
  "no text.";

interface SpdxListEntry {
  name: string;
  url: string;
  osiApproved: boolean;
  licenseText: string;
}

// Canonical texts from the pinned, zero-dependency data package — imported
// statically so bundlers can embed the JSON; renderNotices itself performs
// no I/O.
const SPDX_FULL = spdxFullData as Record<string, SpdxListEntry>;

/**
 * Fenced block for untrusted multi-line content: the fence is max(3, longest
 * backtick run + 1) backticks, so the content can never close the fence early
 * and forge document structure. CR normalization is defensive only — intake
 * sanitization and the LF-only canonical texts mean no CR should arrive here.
 */
function fencedBlock(content: string): string[] {
  const normalized = content.replace(/\r\n|\r/g, "\n").replace(/\n+$/, "");
  let longestRun = 0;
  for (const run of normalized.match(/`+/g) ?? []) {
    if (run.length > longestRun) longestRun = run.length;
  }
  const fence = "`".repeat(Math.max(3, longestRun + 1));
  return [fence, ...normalized.split("\n"), fence];
}

/**
 * License label for the section's "License:" line: the full normalized
 * expression when a finding exists; an imprecise finding renders "<family>
 * (imprecise)" (the honest family, never a fabricated id); "unknown" on a
 * null non-imprecise expression; pre-annotation tolerance falls back to the
 * raw-claims dedup join (the markdown.ts licenseCellOf rule).
 */
function licenseLabelOf(pkg: PackageEntry): string {
  if (pkg.finding !== undefined) {
    if (pkg.finding.confidence === "imprecise") {
      return `${pkg.finding.impreciseFamily ?? "unknown"} (imprecise)`;
    }
    return pkg.finding.expression ?? "unknown";
  }
  return pkg.licenseClaims.length === 0
    ? "unknown"
    : [...new Set(pkg.licenseClaims.map((claim) => claim.raw))].join(", ");
}

/**
 * Unknown-license predicate — mirrors the markdown.ts counts rule. An imprecise
 * finding is present, not unknown, so it is excluded.
 */
function isUnknownLicense(pkg: PackageEntry): boolean {
  if (pkg.finding !== undefined) {
    return (
      pkg.finding.confidence !== "imprecise" && pkg.finding.expression === null
    );
  }
  return pkg.licenseClaims.length === 0;
}

/**
 * A package gets a per-package attribution section only when it carries
 * something concrete to attribute: copyright lines, NOTICE texts, an author
 * fallback, or non-standard verbatim texts. Template-only attribution
 * (hasVerbatimText with nothing extracted) renders nothing — honest empty,
 * never fabricated.
 */
function qualifiesForSection(pkg: PackageEntry): boolean {
  const attribution = pkg.attribution;
  if (attribution === undefined) return false;
  return (
    attribution.copyrightLines.length > 0 ||
    attribution.noticeTexts.length > 0 ||
    attribution.author !== undefined ||
    (attribution.verbatimTexts !== undefined &&
      attribution.verbatimTexts.length > 0)
  );
}

/**
 * Attribution body for one qualifying package — copyright/author/notice/
 * verbatim. The already-narrowed attribution is passed in by the sole caller
 * (which guards with qualifiesForSection first), so the invariant lives with
 * the guard instead of a cross-function type assertion.
 */
function packageAttributionLines(
  pkg: PackageEntry,
  attribution: NonNullable<PackageEntry["attribution"]>,
): string[] {
  const lines: string[] = [
    `### ${escapeCell(pkg.name)}@${escapeCell(pkg.version)}`,
    "",
    `License: ${escapeCell(licenseLabelOf(pkg))}`,
    "",
  ];
  if (attribution.copyrightLines.length > 0) {
    for (const line of attribution.copyrightLines) {
      lines.push(`- ${escapeCell(line)}`);
    }
    lines.push("");
  } else if (attribution.author !== undefined) {
    // Author fallback only when no copyright line was located — and it is
    // attribution, never a copyright claim we did not find.
    lines.push(`Author: ${escapeCell(attribution.author)}`, "");
  }
  for (const notice of attribution.noticeTexts) {
    lines.push("NOTICE:", "", ...fencedBlock(notice), "");
  }
  for (const text of attribution.verbatimTexts ?? []) {
    lines.push("Verbatim license text:", "", ...fencedBlock(text), "");
  }
  return lines;
}

/** Per-package attribution sections. */
function renderPackageSections(sorted: readonly PackageEntry[]): string[] {
  const lines: string[] = ["## Package attributions", ""];
  for (const pkg of sorted) {
    const attribution = pkg.attribution;
    if (attribution === undefined || !qualifiesForSection(pkg)) continue;
    lines.push(...packageAttributionLines(pkg, attribution));
  }
  return lines;
}

/**
 * Unknown-license packages — listed with no text, flagged; the section is
 * omitted entirely when empty.
 */
function renderUnknownSection(sorted: readonly PackageEntry[]): string[] {
  const unknown = sorted.filter(isUnknownLicense);
  if (unknown.length === 0) return [];
  const lines: string[] = [
    "## Packages with unknown licenses",
    "",
    "No license could be determined for these packages; no license text is included:",
    "",
  ];
  for (const pkg of unknown) {
    lines.push(
      `- ${escapeCell(pkg.name)}@${escapeCell(pkg.version)} — unknown license, no text included`,
    );
  }
  lines.push("");
  return lines;
}

/** SPDX ids + exceptions referenced by any parsed normalized expression. */
function collectReferencedLicenses(sorted: readonly PackageEntry[]): {
  ids: Set<string>;
  exceptions: Set<string>;
} {
  const ids = new Set<string>();
  const exceptions = new Set<string>();
  for (const pkg of sorted) {
    const expression = pkg.finding?.expression;
    if (expression === undefined || expression === null) continue;
    let node: ExpressionNode;
    try {
      node = parse(expression) as ExpressionNode;
    } catch {
      // Normalized expressions always parse; skip-don't-throw on the tolerance
      // path.
      continue;
    }
    const leaves = leafIds(node);
    for (const id of leaves.ids) ids.add(id);
    for (const exception of leaves.exceptions) exceptions.add(exception);
  }
  return { ids, exceptions };
}

/**
 * Canonical license-text appendix: one text per SPDX id referenced by any
 * parsed normalized expression (decomposed via leafIds), sorted
 * compareCodeUnits. WITH exceptions are flagged separately.
 */
function renderLicenseTextsSection(sorted: readonly PackageEntry[]): string[] {
  const { ids, exceptions } = collectReferencedLicenses(sorted);
  const lines: string[] = ["## License texts", ""];
  for (const id of [...ids].sort(compareCodeUnits)) {
    lines.push(`### ${escapeCell(id)}`, "");
    const entry = SPDX_FULL[id];
    if (entry === undefined) {
      lines.push(
        `Flagged: no canonical text is available for license identifier ${escapeCell(id)}.`,
        "",
      );
      continue;
    }
    lines.push(...fencedBlock(entry.licenseText), "", CANONICAL_MARKER, "");
  }
  for (const exception of [...exceptions].sort(compareCodeUnits)) {
    lines.push(
      `Flagged: license exception ${escapeCell(exception)} is referenced by a package license expression; the SPDX license list carries no exception texts — review the package's license files.`,
      "",
    );
  }
  return lines;
}

export function renderNotices(model: CanonicalDependencies): string {
  // Defensive re-sort: the renderer must not trust input order.
  const sorted = [...model.packages].sort(comparePackages);

  const lines: string[] = [
    "# Third-Party Notices",
    "",
    HEADER_LINE,
    "",
    PROSE,
    "",
    ...renderPackageSections(sorted),
    ...renderUnknownSection(sorted),
    ...renderLicenseTextsSection(sorted),
  ];

  // Single trailing LF: drop trailing blank lines, then join with "\n"
  // literals only (never the platform EOL constant).
  while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  return lines.join("\n") + "\n";
}
