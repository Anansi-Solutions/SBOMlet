/**
 * Deterministic CanonicalDependencies -> Markdown renderer - the full licenses document.
 *
 * Pure function: model (plus an optional policy view) in, exact bytes out. The output is assembled
 * with "\n" literals only (never the platform EOL constant) so the same model produces identical
 * bytes on Windows and Linux. The header carries the regenerate command, never a date.
 *
 * Document order (locked): title, dateless auto-generated header, the target-profile
 * scope-of-assertion line PLUS the compatibility-data attribution/disclaimer line (both generated,
 * both present ONLY when the policy declares an active target lane - PolicyView.targetProfile),
 * author preamble (policy [document].preamble, when configured), policy pointer line (policy runs
 * only), package-counts block, problematic licenses roll-up (policy runs only), copyleft and
 * special notices (policy runs only - container system-package copyleft is excluded as routine, and
 * a package already flagged Problematic never duplicates into this section), target compatibility
 * (policy runs only, and only when the target lane produced a warn or held-internal row - no
 * heading otherwise), imprecise licenses, assessment conflicts, the Containers index
 * (occurrence-derived, rendered with or without a policy view), then Production and
 * Development-only dependencies. Each of those two sections is the app table followed by one "###
 * Container: docker:<source>" subsection per container classified into that half - a container's
 * complete package inventory lists there, grouped by the docker:<source> occurrence identity
 * INDEPENDENT of scope (a package shared with an app workspace lists in both places), with no
 * separate Docker section. Each subsection further splits into a "**System packages**" table (the
 * OS-ecosystem allowlist) and an "**Application packages**" table (everything else), omitting an
 * empty half. The License column shows the full normalized expression when a finding exists - never
 * only the elected branch; election surfaces through copyleft section membership instead. Without a
 * policy view there is no policy pointer and no problematic roll-up or copyleft section, and every
 * container classifies production (the conservative default).
 *
 * This module deliberately does not render the notices companion, emit CycloneDX, or evaluate
 * policy - verdicts and suppressed workspaces arrive pre-computed in the PolicyView projection. The
 * two generated target-lane lines are THIS document's alone - renderNotices (notices.ts) takes no
 * PolicyView and can never carry them, by construction.
 *
 * The normative placement spec is docs/reference/report-placement.md - update both together.
 */

import {
  compareCodeUnits,
  comparePackages,
  DOCKER_IDENTITY_PREFIX,
  purlEcosystem,
  type CanonicalDependencies,
  type DependencyIntroduction,
  type Occurrence,
  type PackageEntry,
  type Verdict,
} from "../model/dependencies";
import {
  formatProfileLabel,
  OSADL_SNAPSHOT_TIMESTAMP,
  SCANCODE_SNAPSHOT_TIMESTAMP,
  TARGET_RULE_BOUNDARY,
  TARGET_RULE_INCOMPATIBLE,
  TARGET_RULE_INTERNAL_USE,
  TARGET_RULE_UNKNOWN_PAIR,
  type TargetProfile,
} from "../policy/compat";
import { OS_PACKAGE_ECOSYSTEMS } from "../policy/engine/osEcosystems";
import { isUnknownLicense } from "./unknownLicense";
import type { AcceptedContainerNotice } from "../policy/engine/evaluate";
import type { SuppressedWorkspace } from "../policy/schema/exemptions";

const HEADER_LINE = "<!-- AUTO-GENERATED - do not edit. Regenerate with: task generate -->";

/**
 * One resolved [[target.workspace]] override for the header line: its declared path, plus its
 * complete resolved profile (per-field inheritance from the project profile already applied).
 */
export interface TargetProfileHeaderOverride {
  /** Repo-relative target-identity prefix this override governs, e.g. "apps/studio". */
  path: string;
  /** The complete, already-inherited profile - never a partial. */
  profile: TargetProfile;
}

/**
 * The resolved target usage profile(s) driving the header's scope-of-assertion line - present ONLY
 * when the policy declares an active [target] lane (pipeline.ts's projectPolicyView threads it from
 * policy.target; absent [target] leaves PolicyView.targetProfile undefined entirely, so a no-target
 * policy renders neither generated line). `project` is absent for a workspaces-only [target] table
 * (no complete project-level profile declared); `workspaces` is every declared [[target.workspace]]
 * entry resolved to its own complete profile, sorted by path for determinism.
 */
export interface TargetProfileSummary {
  /** The complete project-level profile, when the policy declares one. */
  project?: TargetProfile;
  workspaces: ReadonlyArray<TargetProfileHeaderOverride>;
}

/**
 * Policy projection for the document renderer. Verdicts drive copyleft-section membership;
 * suppressed workspaces are rendered as the policy-authored exemption list (every field escaped).
 */
export interface PolicyView {
  /** Path of the policy file, as configured - rendered in the pointer line. */
  policyPath: string;
  suppressedWorkspaces: ReadonlyArray<SuppressedWorkspace>;
  verdicts: ReadonlyArray<Verdict>;
  /**
   * Accepted container AGPL obligations (policy/evaluate.ts): an os-scope package whose AGPL
   * network-copyleft obligation was accepted through a `[[compatible]]` rule rather than failing.
   * Rendered as a non-blocking special notice in the copyleft section instead of vanishing - absent
   * when the pipeline finds none (possibly empty); tests exercising other membership rules may omit
   * the field entirely.
   */
  acceptedContainerNotices?: ReadonlyArray<AcceptedContainerNotice>;
  /**
   * docker:<source> identities marked development-only by a policy `[[docker.development]]` glob,
   * resolved by the pipeline against the analyzed containers (via the same matcher as
   * `[docker].ignore`). Drives the Containers index classification column; every identity absent
   * from this set - including when the whole field is absent - renders "production", the
   * conservative default. A real policy run always supplies it (possibly empty); tests exercising
   * other membership rules may omit it.
   */
  developmentContainers?: ReadonlySet<string>;
  /**
   * Author-supplied document presentation (from the policy [document] table). `title` replaces the
   * default H1; `preamble` renders verbatim as a markdown block below the auto-generated header.
   * Both are author prose at the policy trust boundary - rendered WITHOUT escapeCell (a title is a
   * heading, not a table cell; a preamble is intentional author markdown).
   */
  document?: { title?: string; preamble?: string };
  /**
   * The resolved target profile(s) driving the generated scope-of-assertion + attribution lines
   * - absent renders neither line, so a no-target policy leaves the document unchanged.
   */
  targetProfile?: TargetProfileSummary;
}

/**
 * Markdown-injection mitigation: applied to every interpolated value sourced from SBOM data or the
 * policy file. Backslash is escaped first so later escapes are not doubled; pipes and backticks are
 * escaped to keep table structure and inline code intact; brackets are escaped so
 * attacker-controlled Markdown links ([text](url)) cannot form; angle brackets become HTML entities
 * so inline HTML (<script>, <img onerror=...>) and autolinks (<https://...>) are inert in renderers
 * that allow raw HTML; any CR/LF sequence collapses to a space. Exported for inline positions in
 * notices.ts.
 */
export function escapeCell(value: string): string {
  return value
    .replaceAll("\\", "\\\\")
    .replaceAll("|", "\\|")
    .replaceAll("`", "\\`")
    .replaceAll("[", "\\[")
    .replaceAll("]", "\\]")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replace(/\r\n|\r|\n/g, " ");
}

/** An imprecise finding renders its family token + an explicit marker. */
function isImprecise(pkg: PackageEntry): boolean {
  return pkg.finding?.confidence === "imprecise";
}

/**
 * License cell rule: the full normalized expression when a finding exists; an imprecise finding
 * renders "<family> (imprecise)" (the family, faithfully, never a fabricated precise id); an
 * os-scope PARTIAL finding renders the expression PLUS the surfaced remainder ("<expression> (+
 * tok, tok)") so the known obligation AND the unrecognized tokens are both visible; "unknown" when
 * the expression is null and not imprecise. Packages without a finding (pre-annotation tolerance)
 * fall back to the raw-claims dedup join.
 */
function licenseCellOf(pkg: PackageEntry): string {
  if (pkg.finding !== undefined) {
    // os-scope partial: surface the unrecognized remainder alongside the known signal. The tokens
    // arrive deduped + sorted from normalize; the "(+ ...)" suffix is the fixed, deterministic
    // format. (Each token is escapeCell-escaped by the caller, which runs escapeCell over the whole
    // cell string - the parens/plus/commas added here are not metacharacters.) The suffix applies
    // to BOTH the precise-expression and the imprecise branches - an imprecise os-partial
    // (imprecise family + unknown token) must show the remainder too, not drop it.
    const tokens = pkg.finding.unrecognizedTokens;
    const suffix = tokens !== undefined && tokens.length > 0 ? ` (+ ${tokens.join(", ")})` : "";

    if (pkg.finding.confidence === "imprecise") {
      return `${pkg.finding.impreciseFamily ?? "unknown"} (imprecise)${suffix}`;
    }

    const expression = pkg.finding.expression ?? "unknown";

    return `${expression}${suffix}`;
  }

  // Raw values are deduped here, first-seen order preserved: the model deliberately keeps same-raw
  // claims that differ in kind/source, and a single component's duplicate licenses[] entries are
  // stored verbatim on first creation. Without render-time dedup, either path renders "MIT, MIT".
  return pkg.licenseClaims.length === 0
    ? "unknown"
    : [...new Set(pkg.licenseClaims.map((claim) => claim.raw))].join(", ");
}

/**
 * Cap on the introducer path/set length rendered in a "why" cell. A very deep path or wide
 * multi-parent set is truncated with a stable "(+N more)" so the tables stay legible and
 * deterministic. The cap counts EMITTED purls; the truncation note is appended after them.
 */
const WHY_MAX_ITEMS = 4;

/**
 * Join an introducer chain (path) or set, bounded by WHY_MAX_ITEMS with a stable "(+N more)" tail.
 * The items arrive already deterministic (a tie-broken path or a sorted set); this only truncates
 * for legibility, never reorders.
 */
function boundedJoin(items: readonly string[], separator: string): string {
  if (items.length <= WHY_MAX_ITEMS) {
    return items.join(separator);
  }

  const shown = items.slice(0, WHY_MAX_ITEMS);
  const more = items.length - WHY_MAX_ITEMS;

  return `${shown.join(separator)} (+${more} more)`;
}

/**
 * Per-ROW provenance aggregation rule. A row aggregates a package's occurrences, but introduction
 * is PER-OCCURRENCE, so the cell collapses them deterministically - and ONLY over the occurrences
 * whose target is in `shownTargets`, the SAME set the row's "Used in" cell names.
 *
 * SCOPING: the Why cell and the Used-in cell MUST be computed from the same occurrence subset.
 * Folding over EVERY occurrence (a past bug)
 * lets a row whose Used-in names only the flagged (transitive) workspace borrow
 * "direct" / a concrete path / an introducer from a DIFFERENT, unflagged occurrence - a mislabel
 * (no-mislabeling) or a fabricated chain that does not exist in the flagged workspace
 * (no-fabrication). We fold ONLY over `occurrences.filter(o => shownTargets.has(o.target))`;
 * out-of-scope occurrences never contribute direct/path/introducer evidence.
 *
 * Collapse rule (over the SCOPED subset; optionality is descoped):
 * - if NO in-scope occurrence carries an introduction → " - " (the honest residual for terraform /
 *   Docker OS / bun / graph-less npm, and for a flagged
 *   occurrence with no introduction - never a fabricated or borrowed value);
 * - ORPHAN exclusion: an "orphan" introduction is one with `direct:false` ∧ empty `introducedBy` ∧
 *   no `path` - a node present in the graph but with NO derivable introducer (the honest residual).
 *   Orphans are EXCLUDED from the direct/transitive decision. Without this, a genuine DIRECT
 *   occurrence plus an orphan co-occurrence made `every(direct)` false, then the union was empty →
 *   " - ", HIDING the real direct. With genuine (non-orphan) introductions:
 *     - if the package is DIRECT in EVERY genuine in-scope occurrence → "direct" (bare "direct"
 *       ONLY when nothing transitive is being hidden - a package direct in one flagged occurrence
 *       AND transitive in another must
 *       surface the transitive introducer);
 *     - else (transitive in ≥1 genuine in-scope occurrence) → the introducer: the representative
 *       `path` of the smallest-target occurrence carrying one, or - when none carries a path - the
 *       sorted-union of every in-scope
 *       occurrence's `introducedBy` set;
 * - if ALL in-scope introductions are orphans (no genuine direct, no introducer evidence anywhere)
 *   → the honest " - " residual.
 *
 * Paths/sets are bounded by boundedJoin. The returned string is escapeCell'd by the caller.
 * Optionality is descoped - no ", optional" suffix is ever rendered, and there is no
 * hard-required/optional tier preference.
 */
function whyCellOf(pkg: PackageEntry, shownTargets: ReadonlySet<string>): string {
  // Fold ONLY over the occurrences the row actually shows. The Why cell and the Used-in cell must
  // describe the SAME workspaces.
  const scoped = pkg.occurrences.filter((o) => shownTargets.has(o.target));

  const introductions = scoped
    .map((o) => o.introduction)
    .filter((i): i is DependencyIntroduction => i !== undefined);

  if (introductions.length === 0) {
    return "—";
  }

  // A defined-but-EMPTY `path: []` carries NO chain - it must be treated identically to an absent
  // path. boundedJoin([], …) would render "" (an empty Why cell), and the orphan guard's
  // `path === undefined` check would miss it. A "real" chain is a defined AND non-empty path.
  const hasChain = (i: DependencyIntroduction): boolean =>
    i.path !== undefined && i.path.length > 0;

  // An ORPHAN introduction - direct:false ∧ empty introducedBy ∧ no real-chain path - carries no
  // derivable introducer (the honest residual for a node present but unreachable from any root).
  // Orphans must NOT participate in the direct/transitive decision, or a real DIRECT occurrence
  // co-occurring with an orphan would be hidden behind " - ". (A defined-but-empty path is no
  // chain, so it counts as orphan when introducedBy is also empty.)
  const isOrphan = (i: DependencyIntroduction): boolean =>
    !i.direct && i.introducedBy.length === 0 && !hasChain(i);
  const genuine = introductions.filter((i) => !isOrphan(i));

  // All in-scope introductions are orphans → no genuine direct and no introducer evidence anywhere:
  // the honest " - " residual (no-fabrication).
  if (genuine.length === 0) {
    return "—";
  }

  // Bare "direct" ONLY when EVERY genuine in-scope occurrence is direct. If the package is direct
  // in one flagged occurrence but transitive in another, fall through to the path logic so the
  // transitive introducer is surfaced rather than hidden behind "direct".
  if (genuine.every((i) => i.direct)) {
    return "direct";
  }

  // Transitive in at least one genuine in-scope occurrence. Surface the representative path of the
  // smallest-target occurrence carrying a REAL (defined AND non-empty) chain - deterministic
  // - falling back to the sorted-union of introducer sets. A defined-but-empty path is no chain and
  // is skipped here so it never joins to "".
  const withPath = scoped
    .filter(
      (o): o is Occurrence & { introduction: DependencyIntroduction } =>
        o.introduction !== undefined && hasChain(o.introduction),
    )
    .sort((a, b) => compareCodeUnits(a.target, b.target));

  if (withPath.length > 0) {
    return boundedJoin(withPath[0]!.introduction.path!, " → ");
  }

  // No path in scope - fall back to the sorted-union of every in-scope occurrence's introducer set.
  const union = [...new Set(introductions.flatMap((i) => i.introducedBy))].sort(compareCodeUnits);

  // No path AND no introducer in scope → the honest " - " residual.
  if (union.length === 0) {
    return "—";
  }

  return boundedJoin(union, ", ");
}

/**
 * Package-level dev/prod classification by distribution reality: a package is DEVELOPMENT-ONLY iff
 * it has at least one occurrence AND every occurrence is a dev dependency. A package with ANY
 * production (non-dev) occurrence is PRODUCTION - the conservative side, since a single shipped
 * occurrence carries the distribution obligation. A package with zero occurrences (defensive) is
 * treated as production so it never hides in the dev-only section.
 */
function isDevelopmentOnly(pkg: PackageEntry): boolean {
  return pkg.occurrences.length > 0 && pkg.occurrences.every((o) => o.isDevDependency);
}

/**
 * A package carries at least one docker-image occurrence - the discriminator for "does this package
 * belong under some container's subsection at all", independent of {@link PackageEntry.scope}. A
 * package with BOTH a workspace occurrence and a docker occurrence (shared between an app lockfile
 * and a container) satisfies this and rows in both its app table and the container's subsection
 * - complete inventories, not an exclusive choice.
 */
function hasContainerOccurrence(pkg: PackageEntry): boolean {
  return pkg.occurrences.some((occurrence) => occurrence.target.startsWith(DOCKER_IDENTITY_PREFIX));
}

/**
 * Package-level Container classification: a package whose occurrences are ALL docker-image
 * occurrences (non-empty, and none targets a non-docker workspace) - the discriminator for "this
 * package lives ONLY in container(s)", which excludes it from the app Production/Development-only
 * tables. A package present in both a workspace and a container is NOT a container package by this
 * predicate (it stays in its app table too) even though {@link hasContainerOccurrence} is true for
 * it - the two predicates answer different questions on purpose.
 */
function isContainerPackage(pkg: PackageEntry): boolean {
  return (
    pkg.occurrences.length > 0 &&
    pkg.occurrences.every((occurrence) => occurrence.target.startsWith(DOCKER_IDENTITY_PREFIX))
  );
}

/**
 * The counts-block Development-only predicate - mirrors exactly where the renderer PLACES a
 * package, so the count matches rendered section membership. A package renders development-only
 * when it has no production placement: it is either app-classified development-only ({@link
 * isDevelopmentOnly}) or a pure container package ({@link isContainerPackage}), AND none of its
 * occurrences targets a production (non-dev-marked) container - a single production container
 * occurrence is a production placement regardless of any other occurrence, matching the app-table
 * split's own conservative-to-production rule.
 */
function rendersDevelopmentOnly(
  pkg: PackageEntry,
  developmentContainers: ReadonlySet<string>,
): boolean {
  return (
    pkg.occurrences.length > 0 &&
    (isContainerPackage(pkg) || isDevelopmentOnly(pkg)) &&
    !pkg.occurrences.some(
      (occurrence) =>
        occurrence.target.startsWith(DOCKER_IDENTITY_PREFIX) &&
        !developmentContainers.has(occurrence.target),
    )
  );
}

/** The resolved development-container set for a no-policy render. */
const EMPTY_DEVELOPMENT_CONTAINERS: ReadonlySet<string> = new Set();

const CONTAINERS_HEAD = ["| Container | Classification | Packages |", "| --- | --- | --- |"];

/**
 * The deduped, compareCodeUnits-sorted docker:<source> identities carried by ANY package's
 * occurrences - the one source of truth for "which containers were analyzed", shared by the
 * Containers index and the Production/Development-only container subsections so the two views can
 * never drift apart. Occurrence-keyed, not scope-keyed: a container is discovered from any package
 * that occurs there, regardless of whether that package also carries an app occurrence elsewhere.
 */
function analyzedContainerIdentities(sorted: readonly PackageEntry[]): string[] {
  const identities = new Set<string>();

  for (const pkg of sorted) {
    for (const occurrence of pkg.occurrences) {
      if (occurrence.target.startsWith(DOCKER_IDENTITY_PREFIX)) {
        identities.add(occurrence.target);
      }
    }
  }

  return [...identities].sort(compareCodeUnits);
}

/**
 * The "## Containers" thin index, rendered immediately before Production regardless of policy
 * (occurrence-derived, not policy-gated): one row per analyzed container ({@link
 * analyzedContainerIdentities}) - its docker:<source> identity, production/development
 * classification, and total package count (every package occurring there, system or application).
 * Classification is "development" for an identity present in `developmentContainers`, else the
 * conservative "production" default; a no-policy render passes an empty set, so every container
 * reads "production".
 */
function containersSectionLines(
  sorted: readonly PackageEntry[],
  developmentContainers: ReadonlySet<string>,
): string[] {
  const counts = new Map<string, number>();

  for (const pkg of sorted) {
    for (const occurrence of pkg.occurrences) {
      if (!occurrence.target.startsWith(DOCKER_IDENTITY_PREFIX)) {
        continue;
      }

      counts.set(occurrence.target, (counts.get(occurrence.target) ?? 0) + 1);
    }
  }

  const identities = analyzedContainerIdentities(sorted);
  const heading = "## Containers";

  if (identities.length === 0) {
    return [heading, "", "✅ No containers are currently tracked."];
  }

  const lines: string[] = [heading, "", ...CONTAINERS_HEAD];

  for (const identity of identities) {
    const classification = developmentContainers.has(identity) ? "development" : "production";

    lines.push(
      `| ${escapeCell(identity)} | ${escapeCell(classification)} | ${counts.get(identity)} |`,
    );
  }

  return lines;
}

/**
 * The container-subsection table head: Name/Ecosystem/Version/License only - no "Used in" column,
 * since a single-container table already scopes every row to that one identity (the column would be
 * pure noise).
 */
const CONTAINER_TABLE_HEAD = [
  "| Name | Ecosystem | Version | License |",
  "| --- | --- | --- | --- |",
];

/** One container-subsection row: tableRow's four columns, no Used-in. */
function containerTableRow(pkg: PackageEntry): string {
  return `| ${escapeCell(pkg.name)} | ${escapeCell(purlEcosystem(pkg.purl))} | ${escapeCell(pkg.version)} | ${escapeCell(licenseCellOf(pkg))} |`;
}

/**
 * One labeled sub-table block ("**System packages**" / "**Application packages**") inside a
 * container subsection - the bold label mirrors the "**Package counts:**" idiom used elsewhere in
 * the document. Returns [] when `rows` is empty so an empty partition adds no stray heading or
 * table.
 */
function containerPartitionLines(label: string, rows: readonly PackageEntry[]): string[] {
  if (rows.length === 0) {
    return [];
  }

  const lines: string[] = [`**${label}**`, "", ...CONTAINER_TABLE_HEAD];

  for (const pkg of rows) {
    lines.push(containerTableRow(pkg));
  }

  lines.push("");
  return lines;
}

/**
 * Per-container "### Container: docker:<source>" H3 subsections for ONE classification half (the
 * caller passes either the production or the development-only identity subset of {@link
 * analyzedContainerIdentities}). Each container's inventory is its COMPLETE package set for that
 * identity - every package with an occurrence targeting it, drawn from `containerRows` (every
 * package carrying a docker occurrence, per {@link hasContainerOccurrence} - including one shared
 * with an app workspace) - with NO exclusion (the Copyleft-section dedup does not apply here; a
 * Problematic-escalated container package still rows here). A package occurring in two containers
 * therefore rows in EACH container's own subsection.
 *
 * Each subsection splits its rows into a **System packages** table (the {@link
 * OS_PACKAGE_ECOSYSTEMS} allowlist) and an **Application packages** table (everything else), in
 * that fixed order, so the base-image-vs-installed distinction is visible per container - an empty
 * partition omits its label+table entirely (a base-image-only container shows only System).
 * comparePackages order (the caller's sort) survives the partition filter.
 *
 * The heading text routes the identity through escapeCell so a bracketed path segment can never
 * form a markdown link. Returns [] for an empty identity list - an empty classification adds no
 * stray headings.
 */
function containerSubsectionLines(
  identities: readonly string[],
  containerRows: readonly PackageEntry[],
): string[] {
  const lines: string[] = [];

  for (const identity of identities) {
    const rows = containerRows.filter((pkg) =>
      pkg.occurrences.some((occurrence) => occurrence.target === identity),
    );
    const system = rows.filter((pkg) => OS_PACKAGE_ECOSYSTEMS.has(purlEcosystem(pkg.purl)));
    const application = rows.filter((pkg) => !OS_PACKAGE_ECOSYSTEMS.has(purlEcosystem(pkg.purl)));

    lines.push(`### Container: ${escapeCell(identity)}`, "");
    lines.push(...containerPartitionLines("System packages", system));
    lines.push(...containerPartitionLines("Application packages", application));
  }

  return lines;
}

const TABLE_HEAD = [
  "| Name | Ecosystem | Version | License | Used in |",
  "| --- | --- | --- | --- | --- |",
];

/**
 * One summary section (heading + table) over a pre-classified, already-sorted package list. The
 * heading always renders so the document shape is stable regardless of the dev/prod mix; an EMPTY
 * section renders the heading plus a one-line ✅ message instead of a bare table head - friendlier
 * than a header with no rows, and still deterministic.
 */
function summarySection(
  heading: string,
  packages: readonly PackageEntry[],
  emptyMessage: string,
): string[] {
  if (packages.length === 0) {
    return [heading, "", emptyMessage];
  }

  const lines: string[] = [heading, "", ...TABLE_HEAD];

  for (const pkg of packages) {
    lines.push(tableRow(pkg, pkg.occurrences.map((o) => o.target).join(", ")));
  }

  return lines;
}

function tableRow(pkg: PackageEntry, usedIn: string): string {
  return `| ${escapeCell(pkg.name)} | ${escapeCell(purlEcosystem(pkg.purl))} | ${escapeCell(pkg.version)} | ${escapeCell(licenseCellOf(pkg))} | ${escapeCell(usedIn)} |`;
}

/**
 * The copyleft-table head: the summary columns plus a trailing "Why" column carrying per-row
 * dependency provenance. Distinct from TABLE_HEAD so the summary sections
 * (Production/Development/Docker OS) stay byte-identical at five columns; provenance surfaces only
 * where it answers a compliance question.
 */
const COPYLEFT_HEAD = [
  "| Name | Ecosystem | Version | License | Used in | Why |",
  "| --- | --- | --- | --- | --- | --- |",
];

/**
 * One copyleft-table row: tableRow plus the escapeCell'd "Why" provenance. The Why cell folds over
 * the SAME flagged target set the Used-in cell names - never over the package's out-of-scope
 * occurrences. `shownTargets` is the deduped+sorted flagged-target list whose join is the Used-in
 * cell.
 */
function copyleftRow(pkg: PackageEntry, shownTargets: readonly string[]): string {
  const usedIn = shownTargets.join(", ");
  const scope = new Set(shownTargets);

  return `| ${escapeCell(pkg.name)} | ${escapeCell(purlEcosystem(pkg.purl))} | ${escapeCell(pkg.version)} | ${escapeCell(licenseCellOf(pkg))} | ${escapeCell(usedIn)} | ${escapeCell(whyCellOf(pkg, scope))} |`;
}

/**
 * The dedicated imprecise-licenses review section: every imprecise package, so a maintainer sees
 * exactly what to disambiguate via a `[[clarify]]` override. Empty (omitted) when no package is
 * imprecise. Input is already comparePackages-sorted; every cell routes through escapeCell via
 * tableRow.
 */
function impreciseSectionLines(sorted: readonly PackageEntry[]): string[] {
  const imprecise = sorted.filter(isImprecise);

  if (imprecise.length === 0) {
    return [];
  }

  const lines: string[] = [
    "## Imprecise licenses (review / disambiguate)",
    "",
    "These packages report an ambiguous license family that was NOT guessed to a precise SPDX id. Disambiguate each via a policy `[[clarify]]` override.",
    "",
    ...TABLE_HEAD,
  ];

  for (const pkg of imprecise) {
    lines.push(tableRow(pkg, pkg.occurrences.map((o) => o.target).join(", ")));
  }

  lines.push("");
  return lines;
}

/**
 * The dedicated assessment-conflicts review section: every package whose finding carries a conflict
 * marker is a gate failure until a `[[clarify]]` override records the human's decision. The two
 * independent triggers (ScanCode-vs-quick-check, cross-image claim divergence) get their own
 * sub-table - they compare different things and read better apart. Cells are escaped since an
 * expression string could otherwise break the table. Omitted entirely, not rendered empty, when no
 * package carries that kind of marker (absent-not-empty for golden stability).
 */
function conflictSectionLines(sorted: readonly PackageEntry[]): string[] {
  const scancodeRows: string[] = [];
  const crossImageRows: string[] = [];

  for (const pkg of sorted) {
    const conflict = pkg.finding?.conflict;

    if (conflict === undefined) {
      continue;
    }

    if (conflict.kind === "cross-image-claims") {
      const byImage = conflict.byTarget
        .map(
          (t) =>
            `${t.target}: ${t.claims.length > 0 ? t.claims.join(", ") : "(no declared license)"}`,
        )
        .join("; ");

      crossImageRows.push(`| ${escapeCell(pkg.name)} | ${escapeCell(byImage)} |`);
      continue;
    }

    const usedIn = pkg.occurrences.map((o) => o.target).join(", ");

    scancodeRows.push(
      `| ${escapeCell(pkg.name)} | ${escapeCell(conflict.assessed)} | ${escapeCell(conflict.disagreeing.join(", "))} | ${escapeCell(usedIn)} |`,
    );
  }

  if (scancodeRows.length === 0 && crossImageRows.length === 0) {
    return [];
  }

  const lines: string[] = [
    "## Assessment conflicts",
    "",
    "For these packages a license disagreement was found automatically and needs a human decision. Each is a gate failure until a policy `[[clarify]]` override records it.",
    "",
  ];

  if (scancodeRows.length > 0) {
    lines.push(
      "### ScanCode assessment vs quick check",
      "",
      "The in-depth ScanCode assessment disagrees with the declared/registry quick check — accept the in-depth value, or re-assess.",
      "",
      "| Package | In-depth (ScanCode) | Quick check | Used in |",
      "| --- | --- | --- | --- |",
      ...scancodeRows,
      "",
    );
  }

  if (crossImageRows.length > 0) {
    lines.push(
      "### Cross-image license claims",
      "",
      "Docker occurrences of the same package declared different licenses — decide which is right.",
      "",
      "| Package | Claims by image |",
      "| --- | --- |",
      ...crossImageRows,
      "",
    );
  }

  return lines;
}

/**
 * The package-counts block: total, per-ecosystem (compareCodeUnits-sorted), production /
 * development-only / container / unknown-license counts. Production and Development-only partition
 * the total exactly - every package renders under one or the other, per {@link
 * rendersDevelopmentOnly} - while Container and Unknown license are cross-cutting subtotals: a
 * package can be counted under Container and/or Unknown in addition to its
 * Production/Development-only bucket. Container counts every package with any container occurrence
 * ({@link hasContainerOccurrence}), not only a pure-container package. Input is the already-sorted
 * package list.
 */
function packageCountsLines(
  sorted: readonly PackageEntry[],
  developmentContainers: ReadonlySet<string>,
): string[] {
  const ecosystemCounts = new Map<string, number>();
  let unknownCount = 0;
  let devOnlyCount = 0;
  let containerCount = 0;

  for (const pkg of sorted) {
    const ecosystem = purlEcosystem(pkg.purl);

    ecosystemCounts.set(ecosystem, (ecosystemCounts.get(ecosystem) ?? 0) + 1);
    if (isUnknownLicense(pkg)) {
      unknownCount += 1;
    }

    if (hasContainerOccurrence(pkg)) {
      containerCount += 1;
    }

    if (rendersDevelopmentOnly(pkg, developmentContainers)) {
      devOnlyCount += 1;
    }
  }

  const prodCount = sorted.length - devOnlyCount;
  const lines: string[] = ["**Package counts:**", "", `- Total packages: ${sorted.length}`];

  for (const [ecosystem, count] of [...ecosystemCounts.entries()].sort(([a], [b]) =>
    compareCodeUnits(a, b),
  )) {
    lines.push(`- ${escapeCell(ecosystem)}: ${count}`);
  }

  lines.push(
    `- Production packages: ${prodCount}`,
    `- Development-only packages: ${devOnlyCount}`,
    `- Container packages: ${containerCount}`,
    `- Unknown license: ${unknownCount}`,
    "",
  );
  return lines;
}

const DEFAULT_TITLE = "Third-Party Licenses";

/**
 * Document H1: the author-supplied [document].title when present, else the fixed default. A title
 * is a HEADING, not a table cell - it is NOT escapeCell'd (author prose may legitimately carry
 * markdown); any CR/LF is collapsed to a single space and the result trimmed so the heading stays
 * on one line and the output carries no CR (determinism).
 */
function documentTitle(policyView?: PolicyView): string {
  const raw = policyView?.document?.title;

  if (raw === undefined) {
    return DEFAULT_TITLE;
  }

  return raw.replace(/\r\n|\r|\n/g, " ").trim();
}

/**
 * The blocking-table head for the "## Problematic licenses" roll-up. Distinct from TABLE_HEAD: it
 * carries Severity + Rule + Reason around the package columns so the section is a self-contained
 * gate report.
 */
const PROBLEMATIC_HEAD = [
  "| Severity | Rule | Name | Ecosystem | Version | License | Used in | Why | Reason |",
  "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
];

/** A grouped blocking verdict: one group = one (purl, rule, reason) triple. */
interface BlockingGroup {
  purl: string;
  rule: string;
  reason: string;
  targets: string[];
}

/**
 * Coarse warn category derived from a verdict rule (non-blocking roll-up): copyleft
 * (default:copyleft / default:imprecise-copyleft), target (the target-compatibility lane's own warn
 * rules - a reviewer must see these are license-compatibility findings, not vague "other" noise,
 * especially since they land right after a Copyleft section a governed tree usually renders empty),
 * unknown (default:unknown / default:imprecise), deny (rule starts with "deny"), else other.
 * Deterministic and total over the rule string.
 */
function warnCategory(rule: string): "copyleft" | "target" | "unknown" | "deny" | "other" {
  if (rule === "default:copyleft" || rule === "default:imprecise-copyleft") {
    return "copyleft";
  }

  if (
    rule === TARGET_RULE_BOUNDARY ||
    rule === TARGET_RULE_UNKNOWN_PAIR ||
    rule === TARGET_RULE_INCOMPATIBLE
  ) {
    return "target";
  }

  if (rule === "default:unknown" || rule === "default:imprecise") {
    return "unknown";
  }

  if (rule.startsWith("deny")) {
    return "deny";
  }

  return "other";
}

/**
 * The sections a warn's package can be pointed to, in the order they appear in the document - the
 * fixed order the roll-up lists them in.
 */
const WARN_DESTINATION_ORDER: readonly string[] = [
  "Problematic licenses",
  "Copyleft and special notices",
  "Target compatibility",
  "Imprecise licenses",
  "the package tables",
];

/**
 * Where a warn verdict's package is actually shown, so the non-blocking roll-up can point the
 * reader at it instead of at a section that turns out empty. Mirrors those sections' own membership
 * rules: a purl that also fails rows in the Problematic table; an os-scope copyleft warn and every
 * warn with no dedicated flagged list (unknown, source-available exemption, deny) appear only in
 * the package tables; the rest land in their named section.
 *
 * @returns one entry of {@link WARN_DESTINATION_ORDER}.
 */
function warnDestinationSection(
  verdict: Verdict,
  pkg: PackageEntry | undefined,
  isProblematic: boolean,
): string {
  if (isProblematic) {
    return "Problematic licenses";
  }

  if (verdict.rule === "default:copyleft") {
    return pkg?.scope === "os" ? "the package tables" : "Copyleft and special notices";
  }

  if (verdict.rule === "default:imprecise-copyleft" || verdict.rule === "default:imprecise") {
    return "Imprecise licenses";
  }

  if (
    verdict.rule === TARGET_RULE_BOUNDARY ||
    verdict.rule === TARGET_RULE_UNKNOWN_PAIR ||
    verdict.rule === TARGET_RULE_INCOMPATIBLE
  ) {
    return "Target compatibility";
  }

  return "the package tables";
}

/**
 * One blocking-table row for a (purl, rule, reason) group. Name/Ecosystem/ Version/License come
 * from the looked-up PackageEntry; every cell (reason and rule especially) routes through
 * escapeCell. The Used-in cell is the group's deduped, compareCodeUnits-sorted targets joined ", ".
 */
function problematicRow(group: BlockingGroup, pkg: PackageEntry): string {
  // The Why cell folds over the SAME flagged target set the Used-in cell names - never over the
  // package's out-of-scope occurrences.
  const shownTargets = new Set(group.targets);
  const targets = [...shownTargets].sort(compareCodeUnits).join(", ");

  return `| ${escapeCell("fail")} | ${escapeCell(group.rule)} | ${escapeCell(pkg.name)} | ${escapeCell(purlEcosystem(pkg.purl))} | ${escapeCell(pkg.version)} | ${escapeCell(licenseCellOf(pkg))} | ${escapeCell(targets)} | ${escapeCell(whyCellOf(pkg, shownTargets))} | ${escapeCell(group.reason)} |`;
}

/**
 * The "## Problematic licenses" roll-up section - rendered AFTER the counts block and BEFORE the
 * copyleft section, on a policy run only. The BLOCKING table is every fail verdict, grouped by
 * (purl, rule, reason) into one row with deduped+sorted targets; rows are sorted by rule, then
 * package (comparePackages on the looked-up entry), then the joined targets. The NON-BLOCKING line
 * summarizes warn verdicts by coarse category. The heading always renders; the empty state is the ✅
 * line.
 */
function problematicSectionLines(
  sorted: readonly PackageEntry[],
  verdicts: ReadonlyArray<Verdict>,
): string[] {
  const byPurl = new Map<string, PackageEntry>();

  for (const pkg of sorted) {
    byPurl.set(pkg.purl, pkg);
  }

  // Group fail verdicts by (purl, rule, reason). A fail whose purl has no package entry is
  // defensively skipped (it can carry no name/version/license).
  const groups = new Map<string, BlockingGroup>();

  for (const verdict of verdicts) {
    if (verdict.status !== "fail") {
      continue;
    }

    if (!byPurl.has(verdict.purl)) {
      continue;
    }

    const key = `${verdict.purl} ${verdict.rule} ${verdict.reason}`;
    const existing = groups.get(key);

    if (existing === undefined) {
      groups.set(key, {
        purl: verdict.purl,
        rule: verdict.rule,
        reason: verdict.reason,
        targets: [verdict.occurrenceTarget],
      });
    } else {
      existing.targets.push(verdict.occurrenceTarget);
    }
  }

  const lines: string[] = ["## Problematic licenses", ""];

  if (groups.size === 0) {
    lines.push("✅ No blocking policy violations.", "");
  } else {
    // Sort: rule, then package (comparePackages on the looked-up entry), then the joined
    // deduped+sorted targets. Every grouped purl is in byPurl.
    const ordered = [...groups.values()].sort((a, b) => {
      const byRule = compareCodeUnits(a.rule, b.rule);

      if (byRule !== 0) {
        return byRule;
      }

      const pkgA = byPurl.get(a.purl)!;
      const pkgB = byPurl.get(b.purl)!;
      const byPkg = comparePackages(pkgA, pkgB);

      if (byPkg !== 0) {
        return byPkg;
      }

      const targetsA = [...new Set(a.targets)].sort(compareCodeUnits).join(", ");
      const targetsB = [...new Set(b.targets)].sort(compareCodeUnits).join(", ");

      return compareCodeUnits(targetsA, targetsB);
    });

    lines.push(...PROBLEMATIC_HEAD);
    for (const group of ordered) {
      lines.push(problematicRow(group, byPurl.get(group.purl)!));
    }

    lines.push("");
  }

  // Non-blocking roll-up: count warn verdicts by coarse category AND record the section that shows
  // each one, so the closing pointer names where the warnings actually are - never "see below" at a
  // section that renders empty. Omitted entirely when zero warns exist.
  const problematicPurls = new Set(
    verdicts.filter((verdict) => verdict.status === "fail").map((verdict) => verdict.purl),
  );
  const warnCounts = new Map<string, number>();
  const destinations = new Set<string>();
  let warnTotal = 0;

  for (const verdict of verdicts) {
    if (verdict.status !== "warn") {
      continue;
    }

    warnTotal += 1;
    const category = warnCategory(verdict.rule);

    warnCounts.set(category, (warnCounts.get(category) ?? 0) + 1);
    destinations.add(
      warnDestinationSection(verdict, byPurl.get(verdict.purl), problematicPurls.has(verdict.purl)),
    );
  }

  if (warnTotal > 0) {
    const order: ReadonlyArray<"copyleft" | "target" | "unknown" | "deny" | "other"> = [
      "copyleft",
      "target",
      "unknown",
      "deny",
      "other",
    ];
    const parts = order
      .filter((category) => (warnCounts.get(category) ?? 0) > 0)
      .map((category) => `${warnCounts.get(category)} ${category} warning(s)`);
    const shownIn = WARN_DESTINATION_ORDER.filter((section) => destinations.has(section));

    lines.push(
      `_Non-blocking: ${parts.join(", ")} (dev/os-downgraded or suppressed). Detailed under ` +
        `${shownIn.join(", ")}._`,
      "",
    );
  }

  return lines;
}

/**
 * The "## Copyleft and special notices" section - policy runs only. Membership is at least one
 * fail/warn verdict whose rule is exactly "default:copyleft" (the engine's only copyleft-flagging
 * rule), on an APP-scope package not already carrying a fail verdict of any rule - the
 * copyleft-only dedup: a package already named in the Problematic roll-up must never also duplicate
 * into this section, though its inventory row, its Imprecise-review row, and its
 * Assessment-conflicts row are untouched. Container system-package copyleft is routine base-image
 * noise and is excluded here regardless of its verdict status, EXCEPT an accepted AGPL obligation
 * (policyView.acceptedContainerNotices): a failing AGPL container package still escalates to
 * Problematic through the same dedup, but an ACCEPTED one renders here as a non-blocking special
 * notice instead of vanishing - it is neither counted in the warning roll-up above (its verdict
 * status is "ok") nor duplicated when the same purl already carries a fail elsewhere. The Used-in
 * cell lists only the flagged occurrence targets; the Why column carries the per-row provenance.
 * Returns the full section (heading, suppressed-workspaces list, accepted-notices list, table or
 * the ✅ empty state) for the caller to push.
 */
function copyleftSectionLines(sorted: readonly PackageEntry[], policyView: PolicyView): string[] {
  // Group verdicts by purl once - the renderer stays a pure function of its arguments.
  const verdictsByPurl = new Map<string, Verdict[]>();

  for (const verdict of policyView.verdicts) {
    const list = verdictsByPurl.get(verdict.purl);

    if (list === undefined) {
      verdictsByPurl.set(verdict.purl, [verdict]);
    } else {
      list.push(verdict);
    }
  }

  // Purls carrying at least one fail verdict - excluded from Copyleft membership ONLY (the dedup is
  // copyleft-scoped, not global).
  const problematicPurls = new Set(
    policyView.verdicts
      .filter((verdict) => verdict.status === "fail")
      .map((verdict) => verdict.purl),
  );

  // Collect the flagged rows first so the EMPTY state can be a ✅ line rather than a bare table
  // head.
  const copyleftRows: string[] = [];

  for (const pkg of sorted) {
    if (pkg.scope === "os") {
      continue;
    }

    if (problematicPurls.has(pkg.purl)) {
      continue;
    }

    const flagged = (verdictsByPurl.get(pkg.purl) ?? []).filter(
      (verdict) =>
        (verdict.status === "fail" || verdict.status === "warn") &&
        verdict.rule === "default:copyleft",
    );

    if (flagged.length === 0) {
      continue;
    }

    const targets = [...new Set(flagged.map((verdict) => verdict.occurrenceTarget))].sort(
      compareCodeUnits,
    );

    copyleftRows.push(copyleftRow(pkg, targets));
  }

  const lines: string[] = ["## Copyleft and special notices", ""];

  // Suppressed-workspaces list: every field is policy-authored and routes through escapeCell.
  // Sorted by path (compareCodeUnits) for determinism regardless of policy-file order. Shown
  // whenever configured - it explains the suppression even when nothing leaks.
  const suppressed = [...policyView.suppressedWorkspaces].sort((a, b) =>
    compareCodeUnits(a.path, b.path),
  );

  if (suppressed.length > 0) {
    lines.push(
      "Workspaces that are themselves distributed under a copyleft license are suppressed by policy:",
      "",
    );
    for (const workspace of suppressed) {
      lines.push(
        `- ${escapeCell(workspace.path)} (${escapeCell(workspace.license)}) — ${escapeCell(workspace.description)}`,
      );
    }

    lines.push("");
  }

  // Accepted-AGPL container notices: candidates from policy/evaluate.ts, deduped against the SAME
  // problematicPurls set the flagged rows above use - a purl already failing anywhere is never also
  // shown as an accepted notice. Sorted by purl already (acceptedContainerNotices' contract).
  const notices = (policyView.acceptedContainerNotices ?? []).filter(
    (notice) => !problematicPurls.has(notice.purl),
  );

  if (notices.length > 0) {
    lines.push(
      "A container system package's AGPL network-copyleft obligation was accepted by policy configuration — recorded here as a non-blocking notice, not counted toward the copyleft warning total:",
      "",
    );
    for (const notice of notices) {
      lines.push(
        `- ${escapeCell(notice.name)}@${escapeCell(notice.version)} (${escapeCell(notice.license)}) in ${escapeCell(notice.targets.join(", "))} — accepted via ${escapeCell(notice.rule)}: ${escapeCell(notice.reason)}`,
      );
    }

    lines.push("");
  }

  if (copyleftRows.length > 0) {
    lines.push(
      "The packages listed below carry copyleft or special license obligations in at least one non-suppressed workspace.",
      "",
      ...COPYLEFT_HEAD,
      ...copyleftRows,
      "",
    );
  } else if (notices.length === 0) {
    lines.push("✅ No package carries copyleft or special license obligations.", "");
  }

  return lines;
}

/** The target-lane warn rule ids that row in the flagged table (never a bare `target:ok`). */
const TARGET_WARN_RULES: ReadonlySet<string> = new Set([
  TARGET_RULE_BOUNDARY,
  TARGET_RULE_UNKNOWN_PAIR,
  TARGET_RULE_INCOMPATIBLE,
]);

/**
 * The "## Target compatibility" section - policy runs only, rendered after Copyleft and special
 * notices, and ONLY when at least one target:* warn or held-internal row exists (unlike the
 * Copyleft section, an absent lane renders no heading at all - no blank-line drift on a no-target
 * document). Two parts, in order:
 *   - a flagged table (the copyleft-section row shape) for every target:boundary,
 *     target:unknown-pair, or dev-downgraded target:incompatible (status "warn") verdict;
 *   - a "Held for internal use" bullet list for every target:internal-use (status "ok") verdict
 *     - the usage profile takes the obligation out of scope, but the row stays enumerable for the
 *     day the profile flips (the internal-use hold's own repudiation mitigation).
 * The Problematic dedup applies ONLY to the flagged table (a purl carrying a fail verdict anywhere
 * never rows there, matching the Copyleft section's own dedup) - the held list is exempt by design.
 * A held-internal verdict names one SPECIFIC occurrence's out-of-scope obligation; a fail elsewhere
 * on the same purl describes an unrelated occurrence entirely, and the hold's whole purpose (an
 * exposure staying visible for the day the profile flips) breaks if a sibling occurrence's fail can
 * make it vanish with no trace anywhere in the document. Deterministic sort: comparePackages order,
 * already the caller's `sorted` order.
 */
function targetSectionLines(sorted: readonly PackageEntry[], policyView: PolicyView): string[] {
  const verdictsByPurl = new Map<string, Verdict[]>();

  for (const verdict of policyView.verdicts) {
    const list = verdictsByPurl.get(verdict.purl);

    if (list === undefined) {
      verdictsByPurl.set(verdict.purl, [verdict]);
    } else {
      list.push(verdict);
    }
  }

  const problematicPurls = new Set(
    policyView.verdicts
      .filter((verdict) => verdict.status === "fail")
      .map((verdict) => verdict.purl),
  );

  const warnRows: string[] = [];
  const heldLines: string[] = [];

  for (const pkg of sorted) {
    const relevant = verdictsByPurl.get(pkg.purl) ?? [];

    if (!problematicPurls.has(pkg.purl)) {
      const warns = relevant.filter(
        (verdict) => verdict.status === "warn" && TARGET_WARN_RULES.has(verdict.rule),
      );

      if (warns.length > 0) {
        const targets = [...new Set(warns.map((verdict) => verdict.occurrenceTarget))].sort(
          compareCodeUnits,
        );

        warnRows.push(copyleftRow(pkg, targets));
      }
    }

    const held = relevant
      .filter((verdict) => verdict.status === "ok" && verdict.rule === TARGET_RULE_INTERNAL_USE)
      .sort((a, b) => compareCodeUnits(a.occurrenceTarget, b.occurrenceTarget));

    for (const verdict of held) {
      heldLines.push(
        `- ${escapeCell(pkg.name)}@${escapeCell(pkg.version)} in ${escapeCell(verdict.occurrenceTarget)} — ${escapeCell(verdict.reason)}`,
      );
    }
  }

  if (warnRows.length === 0 && heldLines.length === 0) {
    return [];
  }

  const lines: string[] = ["## Target compatibility", ""];

  if (warnRows.length > 0) {
    lines.push(
      "The packages listed below need review against the declared target profile.",
      "",
      ...COPYLEFT_HEAD,
      ...warnRows,
      "",
    );
  }

  if (heldLines.length > 0) {
    lines.push(
      "Held out of scope for internal use - visible for the day the distribution profile flips:",
      "",
      ...heldLines,
      "",
    );
  }

  return lines;
}

/**
 * One profile rendered in reader's words for the header lines - {@link formatProfileLabel} escaped
 * for markdown, optionally prefixed by its governing workspace path (also escaped; a project-level
 * profile has none).
 */
function profileDescriptor(profile: TargetProfile, path?: string): string {
  const label = escapeCell(formatProfileLabel(profile));

  return path === undefined ? label : `${escapeCell(path)} (${label})`;
}

/**
 * The scope-of-assertion statement: the header line is NOT decorative metadata - it is the primary
 * honesty mechanism for the whole target-license feature, stating plainly that the document was
 * audited against the declared profile and that its verdicts assert validity ONLY against that
 * profile and configuration. A project-level profile names itself, plus every declared
 * [[target.workspace]] override (already sorted by path); a workspaces-only [target] table (no
 * complete project profile) names its per-workspace profiles as the audited-against subject
 * directly, since there is no single project-wide target to lead with.
 */
function scopeOfAssertionLine(summary: TargetProfileSummary): string {
  // Defensive re-sort: mirrors renderMarkdown's own package sort and copyleftSectionLines'
  // suppressed-workspace sort - the renderer must not trust caller order for determinism.
  const overrides = [...summary.workspaces]
    .sort((a, b) => compareCodeUnits(a.path, b.path))
    .map((entry) => profileDescriptor(entry.profile, entry.path));

  if (summary.project !== undefined) {
    const overridesClause =
      overrides.length > 0 ? ` Per-workspace overrides: ${overrides.join(", ")}.` : "";

    return (
      `This report was audited against the declared target: ${profileDescriptor(summary.project)}.` +
      `${overridesClause} Its findings assert license validity against that target and the ` +
      `declared configuration only.`
    );
  }

  if (overrides.length === 0) {
    // schema.ts's validateTarget already rejects a [target] table that resolves to neither a
    // project profile nor any [[target.workspace]] entry (a dead activation switch), so a real
    // policy can never reach this branch - guarded anyway so a future caller can never render the
    // dangling "targets: ." sentence this shape would otherwise produce.
    throw new Error(
      "scopeOfAssertionLine: a workspaces-only TargetProfileSummary must carry at least one " +
        "workspace override",
    );
  }

  return (
    `This report was audited against the declared per-workspace targets: ${overrides.join(", ")}. ` +
    `Its findings assert license validity against those targets and the declared configuration only.`
  );
}

/**
 * The attribution/disclaimer line: names the two vetted compatibility data sources with their
 * snapshot timestamps - the one place this document carries that retrieval metadata at all; every
 * per-package verdict reason cites only the source value (e.g. "OSADL: No"), never a timestamp or
 * URL. Timestamps read exclusively from data.ts's vendored-data constants, never the clock - no
 * per-run drift.
 */
function attributionLine(): string {
  return (
    `Compatibility verdicts draw on the OSADL compatibility matrix and copyleft class table ` +
    `(snapshot ${OSADL_SNAPSHOT_TIMESTAMP}, osadl.org) and the ScanCode LicenseDB category index ` +
    `(snapshot ${SCANCODE_SNAPSHOT_TIMESTAMP}, scancode-licensedb.aboutcode.org) - this is ` +
    `automated, data-driven output, not legal advice.`
  );
}

/**
 * The two generated lines directly after HEADER_LINE when the target lane is active: the
 * scope-of-assertion statement, then the attribution/disclaimer line - fixed at exactly two lines
 * (the ADR records the decision). This licenses document is the only place either line renders:
 * callers gate this on PolicyView.targetProfile, and renderNotices never receives a PolicyView at
 * all.
 */
function targetHeaderLines(summary: TargetProfileSummary): string[] {
  return [scopeOfAssertionLine(summary), attributionLine()];
}

export function renderMarkdown(model: CanonicalDependencies, policyView?: PolicyView): string {
  // Defensive re-sort: the renderer must not trust input order.
  const sorted = [...model.packages].sort(comparePackages);

  const lines: string[] = [`# ${documentTitle(policyView)}`, "", HEADER_LINE];

  // The scope-of-assertion + attribution lines land directly after the auto-generated header
  // comment, BEFORE the author preamble - generated content groups with the generated header.
  // Absent PolicyView.targetProfile, nothing is pushed here and the output stays byte-identical to
  // a document rendered with no [target] table declared.
  const targetProfile = policyView?.targetProfile;

  if (targetProfile !== undefined) {
    lines.push(...targetHeaderLines(targetProfile));
  }

  lines.push("");

  // Author preamble: verbatim markdown block after the auto-generated header comment and BEFORE the
  // policy pointer / counts. CRLF/CR normalized to "\n" (determinism); rendered as-is - NOT
  // escapeCell'd: it is intentional author markdown at the same trust boundary as the policy file.
  // A trailing blank line separates it from what follows.
  const preamble = policyView?.document?.preamble;

  if (preamble !== undefined) {
    lines.push(preamble.replace(/\r\n|\r/g, "\n"), "");
  }

  // Policy pointer line - policy runs only. The path is policy-authored config and routes through
  // escapeCell.
  if (policyView !== undefined) {
    lines.push(`Copyleft notice rules are configured in ${escapeCell(policyView.policyPath)}.`, "");
  }

  // Containers index - scope-derived, so it renders with or without a policy view (a no-policy
  // render passes the empty set; every container reads "production"). Resolved once, above the
  // counts block, so the Production/Development-only counts can classify a container package by the
  // same set the Containers index and the container subsections use.
  const developmentContainers = policyView?.developmentContainers ?? EMPTY_DEVELOPMENT_CONTAINERS;

  lines.push(...packageCountsLines(sorted, developmentContainers));

  // Problematic licenses roll-up - policy runs only. Rendered AFTER the counts block and BEFORE the
  // copyleft section so the gate-blocking findings sit at the top of the document.
  if (policyView !== undefined) {
    lines.push(...problematicSectionLines(sorted, policyView.verdicts));
  }

  // Copyleft and special notices - policy runs only.
  if (policyView !== undefined) {
    lines.push(...copyleftSectionLines(sorted, policyView));
  }

  // Target compatibility - policy runs only, and only when the lane produced a warn/held-internal
  // row (targetSectionLines returns [] otherwise - no heading, no blank-line drift).
  if (policyView !== undefined) {
    lines.push(...targetSectionLines(sorted, policyView));
  }

  // Imprecise-licenses review section - finding-level (rendered with or without a policy view).
  lines.push(...impreciseSectionLines(sorted));

  // Assessment-conflicts review section - finding-level, mirrors the imprecise section: absent when
  // no package carries a conflict marker so zero-conflict documents stay byte-identical.
  lines.push(...conflictSectionLines(sorted));

  // Containers index - resolved above, placed immediately before Production.
  lines.push(...containersSectionLines(sorted, developmentContainers));
  lines.push("");

  // Production and Development-only, each the app table plus its half's container subsections.
  // Fixed order - production before development-only - for determinism; each app-table heading
  // always renders (a ✅ line replaces the table when empty). The Used-in cell stays the full
  // occurrence-target list; the split is by package classification, not per-occurrence. A
  // container-only package ({@link isContainerPackage}) is excluded from both app tables (the
  // dev/prod split is an app concept) - it renders in its container's own subsection instead (there
  // is no standalone Docker section). A package shared with a workspace stays in its app table AND
  // rows in the container subsection ({@link hasContainerOccurrence} feeds the subsection
  // candidates, a strict superset of the excluded set). Lockfile-only scans carry no licenses
  // - "unknown" is correct pre-annotation behavior, not a rendering defect.
  const appPackages = sorted.filter((pkg) => !isContainerPackage(pkg));
  const containerRows = sorted.filter(hasContainerOccurrence);
  const developmentOnly = appPackages.filter(isDevelopmentOnly);
  const production = appPackages.filter((pkg) => !isDevelopmentOnly(pkg));
  const containerIdentities = analyzedContainerIdentities(sorted);
  const productionContainers = containerIdentities.filter(
    (identity) => !developmentContainers.has(identity),
  );
  const developmentContainerIds = containerIdentities.filter((identity) =>
    developmentContainers.has(identity),
  );

  lines.push(
    ...summarySection("## Production dependencies", production, "✅ No production dependencies."),
  );
  lines.push("");
  lines.push(...containerSubsectionLines(productionContainers, containerRows));
  lines.push(
    ...summarySection(
      "## Development-only dependencies",
      developmentOnly,
      "✅ No development-only dependencies.",
    ),
  );
  lines.push("");
  lines.push(...containerSubsectionLines(developmentContainerIds, containerRows));

  // Defensive trailing-blank trim: a non-empty final container subsection owns its own trailing
  // separator (matching every other section-lines helper), which would otherwise leave a blank line
  // at end-of-file. Strip it so the document keeps its single-trailing-LF convention regardless of
  // which section renders last.
  while (lines.length > 0 && lines[lines.length - 1] === "") {
    lines.pop();
  }

  return lines.join("\n") + "\n";
}
