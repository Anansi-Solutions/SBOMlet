/**
 * Deterministic CanonicalDependencies -> Markdown renderer — the full
 * licenses document.
 *
 * Pure function: model (plus an optional policy view) in, exact bytes out. The
 * output is assembled with "\n" literals only (never the platform EOL constant)
 * so the same model produces identical bytes on Windows and Linux. The header
 * carries the regenerate command, never a date.
 *
 * Document order (locked): title, dateless auto-generated header, policy
 * pointer line (policy runs only), package-counts block, copyleft and special
 * notices (policy runs only), full summary table. The License column shows the
 * full normalized expression when a finding exists — never only the elected
 * branch; election surfaces through copyleft section membership instead.
 * Without a policy view there is no policy pointer and no copyleft section.
 *
 * This module deliberately does not render the notices companion, emit
 * CycloneDX, or evaluate policy — verdicts and suppressed workspaces arrive
 * pre-computed in the PolicyView projection.
 */

import {
  compareCodeUnits,
  comparePackages,
  type CanonicalDependencies,
  type DependencyIntroduction,
  type Occurrence,
  type PackageEntry,
  type Verdict,
} from "../model/dependencies";
import type { SuppressedWorkspace } from "../policy/schema";

const HEADER_LINE =
  "<!-- AUTO-GENERATED - do not edit. Regenerate with: task generate -->";

/**
 * Policy projection for the document renderer. Verdicts drive copyleft-section
 * membership; suppressed workspaces are rendered as the policy-authored
 * exemption list (every field escaped).
 */
export interface PolicyView {
  /** Path of the policy file, as configured — rendered in the pointer line. */
  policyPath: string;
  suppressedWorkspaces: ReadonlyArray<SuppressedWorkspace>;
  verdicts: ReadonlyArray<Verdict>;
  /**
   * Author-supplied document presentation (07-09, from the policy [document]
   * table). `title` replaces the default H1; `preamble` renders verbatim as a
   * markdown block below the auto-generated header. Both are author prose at the
   * policy trust boundary — rendered WITHOUT escapeCell (a title is a heading,
   * not a table cell; a preamble is intentional author markdown).
   */
  document?: { title?: string; preamble?: string };
}

/**
 * Markdown-injection mitigation: applied to every interpolated value sourced
 * from SBOM data or the policy file. Backslash is escaped first so later
 * escapes are not doubled; pipes and backticks are escaped to keep table
 * structure and inline code intact; brackets are escaped so
 * attacker-controlled Markdown links ([text](url)) cannot form; angle brackets
 * become HTML entities so inline HTML (<script>, <img onerror=...>) and
 * autolinks (<https://...>) are inert in renderers that allow raw HTML; any
 * CR/LF sequence collapses to a space. Exported for inline positions in
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
 * License cell rule: the full normalized expression when a finding exists; an
 * imprecise finding renders "<family> (imprecise)" (INV-04 — the family,
 * faithfully, never a fabricated precise id); an os-scope PARTIAL finding
 * (07-06) renders the expression PLUS the surfaced remainder
 * ("<expression> (+ tok, tok)") so the known obligation AND the unrecognized
 * tokens are both visible; "unknown" when the expression is null and not
 * imprecise. Packages without a finding (pre-annotation tolerance) fall back to
 * the raw-claims dedup join.
 */
function licenseCellOf(pkg: PackageEntry): string {
  if (pkg.finding !== undefined) {
    // os-scope partial (07-06): surface the unrecognized remainder alongside the
    // known signal. The tokens arrive deduped + sorted from normalize; the
    // "(+ ...)" suffix is the locked, deterministic format. (Each token is
    // escapeCell-escaped by the caller, which runs escapeCell over the whole
    // cell string — the parens/plus/commas added here are not metacharacters.)
    // #8: the suffix applies to BOTH the precise-expression and the imprecise
    // branches — an imprecise os-partial (#2: imprecise family + unknown token)
    // must show the remainder too, not drop it.
    const tokens = pkg.finding.unrecognizedTokens;
    const suffix =
      tokens !== undefined && tokens.length > 0
        ? ` (+ ${tokens.join(", ")})`
        : "";
    if (pkg.finding.confidence === "imprecise") {
      return `${pkg.finding.impreciseFamily ?? "unknown"} (imprecise)${suffix}`;
    }
    const expression = pkg.finding.expression ?? "unknown";
    return `${expression}${suffix}`;
  }
  // Raw values are deduped here, first-seen order preserved: the model
  // deliberately keeps same-raw claims that differ in kind/source, and a
  // single component's duplicate licenses[] entries are stored verbatim on
  // first creation. Without render-time dedup, either path renders "MIT, MIT".
  return pkg.licenseClaims.length === 0
    ? "unknown"
    : [...new Set(pkg.licenseClaims.map((claim) => claim.raw))].join(", ");
}

/**
 * Cap on the introducer path/set length rendered in a "why" cell (07-13). A very
 * deep path or wide multi-parent set is truncated with a stable "(+N more)" so
 * the tables stay legible and deterministic. The cap counts EMITTED purls; the
 * truncation note is appended after them.
 */
const WHY_MAX_ITEMS = 4;

/**
 * Join an introducer chain (path) or set, bounded by WHY_MAX_ITEMS with a stable
 * "(+N more)" tail. The items arrive already deterministic (a tie-broken path or
 * a sorted set); this only truncates for legibility, never reorders.
 */
function boundedJoin(items: readonly string[], separator: string): string {
  if (items.length <= WHY_MAX_ITEMS) return items.join(separator);
  const shown = items.slice(0, WHY_MAX_ITEMS);
  const more = items.length - WHY_MAX_ITEMS;
  return `${shown.join(separator)} (+${more} more)`;
}

/**
 * Per-ROW provenance aggregation rule (07-13, target-scoped 07-17). A row
 * aggregates a package's occurrences, but introduction is PER-OCCURRENCE, so the
 * cell collapses them deterministically — and ONLY over the occurrences whose
 * target is in `shownTargets`, the SAME set the row's "Used in" cell names.
 *
 * SCOPING (07-17, #2/#3/#5): the Why cell and the Used-in cell MUST be computed
 * from the same occurrence subset. Folding over EVERY occurrence (the 07-13 bug)
 * lets a row whose Used-in names only the flagged (transitive) workspace borrow
 * "direct" / a concrete path / an introducer from a DIFFERENT, unflagged
 * occurrence — a mislabel (no-mislabeling) or a fabricated chain that does not
 * exist in the flagged workspace (no-fabrication). We fold ONLY over
 * `occurrences.filter(o => shownTargets.has(o.target))`; out-of-scope
 * occurrences never contribute direct/path/introducer evidence.
 *
 * Collapse rule (over the SCOPED subset, 07-19 optionality descoped):
 * - if NO in-scope occurrence carries an introduction → "—" (the honest
 *   residual for terraform / Docker OS / bun / graph-less npm, and for a flagged
 *   occurrence with no introduction — never a fabricated or borrowed value);
 * - ORPHAN exclusion (Fix 2, review #3): an "orphan" introduction is one with
 *   `direct:false` ∧ empty `introducedBy` ∧ no `path` — a node present in the
 *   graph but with NO derivable introducer (the honest residual). Orphans are
 *   EXCLUDED from the direct/transitive decision. Without this, a genuine DIRECT
 *   occurrence plus an orphan co-occurrence made `every(direct)` false, then the
 *   union was empty → "—", HIDING the real direct. With genuine (non-orphan)
 *   introductions:
 *     - if the package is DIRECT in EVERY genuine in-scope occurrence → "direct"
 *       (07-18: bare "direct" ONLY when nothing transitive is being hidden — a
 *       package direct in one flagged occurrence AND transitive in another must
 *       surface the transitive introducer);
 *     - else (transitive in ≥1 genuine in-scope occurrence) → the introducer:
 *       the representative `path` of the smallest-target occurrence carrying one,
 *       or — when none carries a path — the sorted-union of every in-scope
 *       occurrence's `introducedBy` set;
 * - if ALL in-scope introductions are orphans (no genuine direct, no introducer
 *   evidence anywhere) → the honest "—" residual.
 *
 * Paths/sets are bounded by boundedJoin. The returned string is escapeCell'd by
 * the caller. 07-19: optionality is descoped — no ", optional" suffix is ever
 * rendered, and there is no hard-required/optional tier preference.
 */
function whyCellOf(
  pkg: PackageEntry,
  shownTargets: ReadonlySet<string>,
): string {
  // 07-17: fold ONLY over the occurrences the row actually shows. The Why cell
  // and the Used-in cell must describe the SAME workspaces.
  const scoped = pkg.occurrences.filter((o) => shownTargets.has(o.target));

  const introductions = scoped
    .map((o) => o.introduction)
    .filter((i): i is DependencyIntroduction => i !== undefined);
  if (introductions.length === 0) return "—";

  // Fix 4 (07-20): a defined-but-EMPTY `path: []` carries NO chain — it must be
  // treated identically to an absent path. boundedJoin([], …) would render ""
  // (an empty Why cell), and the orphan guard's `path === undefined` check would
  // miss it. A "real" chain is a defined AND non-empty path.
  const hasChain = (i: DependencyIntroduction): boolean =>
    i.path !== undefined && i.path.length > 0;

  // Fix 2 (review #3): an ORPHAN introduction — direct:false ∧ empty
  // introducedBy ∧ no real-chain path — carries no derivable introducer (the
  // honest residual for a node present but unreachable from any root). Orphans
  // must NOT participate in the direct/transitive decision, or a real DIRECT
  // occurrence co-occurring with an orphan would be hidden behind "—". (Fix 4: a
  // defined-but-empty path is no chain, so it counts as orphan when
  // introducedBy is also empty.)
  const isOrphan = (i: DependencyIntroduction): boolean =>
    !i.direct && i.introducedBy.length === 0 && !hasChain(i);
  const genuine = introductions.filter((i) => !isOrphan(i));

  // All in-scope introductions are orphans → no genuine direct and no introducer
  // evidence anywhere: the honest "—" residual (no-fabrication).
  if (genuine.length === 0) return "—";

  // 07-18: bare "direct" ONLY when EVERY genuine in-scope occurrence is direct.
  // If the package is direct in one flagged occurrence but transitive in
  // another, fall through to the path logic so the transitive introducer is
  // surfaced rather than hidden behind "direct".
  if (genuine.every((i) => i.direct)) return "direct";

  // Transitive in at least one genuine in-scope occurrence. Surface the
  // representative path of the smallest-target occurrence carrying a REAL
  // (defined AND non-empty, Fix 4) chain — deterministic — falling back to the
  // sorted-union of introducer sets. A defined-but-empty path is no chain and is
  // skipped here so it never joins to "".
  const withPath = scoped
    .filter(
      (o): o is Occurrence & { introduction: DependencyIntroduction } =>
        o.introduction !== undefined && hasChain(o.introduction),
    )
    .sort((a, b) => compareCodeUnits(a.target, b.target));
  if (withPath.length > 0) {
    return boundedJoin(withPath[0]!.introduction.path!, " → ");
  }

  // No path in scope — fall back to the sorted-union of every in-scope
  // occurrence's introducer set.
  const union = [...new Set(introductions.flatMap((i) => i.introducedBy))].sort(
    compareCodeUnits,
  );
  // No path AND no introducer in scope → the honest "—" residual.
  if (union.length === 0) return "—";
  return boundedJoin(union, ", ");
}

/** Ecosystem = the purl type segment between "pkg:" and the first "/". */
function ecosystemOf(purl: string): string {
  const rest = purl.startsWith("pkg:") ? purl.slice(4) : purl;
  const slash = rest.indexOf("/");
  return slash === -1 ? rest : rest.slice(0, slash);
}

/**
 * Unknown-license predicate for the counts block: a finding with a null
 * expression, or — pre-annotation — no finding and zero claims. An imprecise
 * finding (confidence "imprecise") is PRESENT, not unknown (INV-04), so it is
 * excluded — the counts stay honest (imprecise is its own thing, surfaced in the
 * dedicated review section).
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
 * Package-level dev/prod classification by distribution reality (POL-08,
 * D-POL-08): a package is DEVELOPMENT-ONLY iff it has at least one occurrence
 * AND every occurrence is a dev dependency. A package with ANY production
 * (non-dev) occurrence is PRODUCTION — the conservative side, since a single
 * shipped occurrence carries the distribution obligation. A package with zero
 * occurrences (defensive) is treated as production so it never hides in the
 * dev-only section.
 */
function isDevelopmentOnly(pkg: PackageEntry): boolean {
  return (
    pkg.occurrences.length > 0 &&
    pkg.occurrences.every((o) => o.isDevDependency)
  );
}

/**
 * Package-level Docker image-package classification (COLL-04): an OS package is
 * one whose scope is "os" (a row threaded in from the committed docker-os.sbom.json,
 * now covering full generated-image contents, not only base-image OS packages).
 * OS packages render in their OWN section and are excluded from the prod/dev app
 * sections — the dev/prod split is an app-scope concept.
 */
function isOsPackage(pkg: PackageEntry): boolean {
  return pkg.scope === "os";
}

const TABLE_HEAD = [
  "| Name | Ecosystem | Version | License | Used in |",
  "| --- | --- | --- | --- | --- |",
];

/**
 * One summary section (heading + table) over a pre-classified, already-sorted
 * package list. The heading always renders so the document shape is stable
 * regardless of the dev/prod mix; an EMPTY section renders the heading plus a
 * one-line ✅ message instead of a bare table head — friendlier than a header
 * with no rows, and still deterministic.
 */
function summarySection(
  heading: string,
  packages: readonly PackageEntry[],
  emptyMessage: string,
): string[] {
  if (packages.length === 0) return [heading, "", emptyMessage];
  const lines: string[] = [heading, "", ...TABLE_HEAD];
  for (const pkg of packages) {
    lines.push(tableRow(pkg, pkg.occurrences.map((o) => o.target).join(", ")));
  }
  return lines;
}

function tableRow(pkg: PackageEntry, usedIn: string): string {
  return `| ${escapeCell(pkg.name)} | ${escapeCell(ecosystemOf(pkg.purl))} | ${escapeCell(pkg.version)} | ${escapeCell(licenseCellOf(pkg))} | ${escapeCell(usedIn)} |`;
}

/**
 * The copyleft-table head (07-13): the summary columns plus a trailing "Why"
 * column carrying per-row dependency provenance. Distinct from TABLE_HEAD so the
 * summary sections (Production/Development/Docker OS) stay byte-identical at five
 * columns; provenance surfaces only where it answers a compliance question.
 */
const COPYLEFT_HEAD = [
  "| Name | Ecosystem | Version | License | Used in | Why |",
  "| --- | --- | --- | --- | --- | --- |",
];

/**
 * One copyleft-table row: tableRow plus the escapeCell'd "Why" provenance. The
 * Why cell folds over the SAME flagged target set the Used-in cell names
 * (07-17) — never over the package's out-of-scope occurrences. `shownTargets` is
 * the deduped+sorted flagged-target list whose join is the Used-in cell.
 */
function copyleftRow(
  pkg: PackageEntry,
  shownTargets: readonly string[],
): string {
  const usedIn = shownTargets.join(", ");
  const scope = new Set(shownTargets);
  return `| ${escapeCell(pkg.name)} | ${escapeCell(ecosystemOf(pkg.purl))} | ${escapeCell(pkg.version)} | ${escapeCell(licenseCellOf(pkg))} | ${escapeCell(usedIn)} | ${escapeCell(whyCellOf(pkg, scope))} |`;
}

/**
 * The dedicated imprecise-licenses review section (INV-04): every imprecise
 * package, so a maintainer sees exactly what to disambiguate via a `[[clarify]]`
 * override. Empty (omitted) when no package is imprecise. Input is already
 * comparePackages-sorted; every cell routes through escapeCell via tableRow.
 */
function impreciseSectionLines(sorted: readonly PackageEntry[]): string[] {
  const imprecise = sorted.filter(isImprecise);
  if (imprecise.length === 0) return [];
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
 * The dedicated assessment-conflicts review section (SCAN-05): every package
 * whose in-depth ScanCode assessment disagrees with the declared/registry quick
 * check carries a conflict marker (set by applyScancodeAssessment), and each is
 * a gate failure until a `[[clarify]]` override records the human's decision.
 * The section names, per package, the in-depth (ScanCode) value, the
 * disagreeing quick-check value(s), and where the package is used — mirroring
 * the imprecise-section precedent. Empty (omitted) when no package carries a
 * conflict marker (absent-not-empty for golden stability). Input is already
 * comparePackages-sorted; every cell routes through escapeCell so a hostile
 * expression string cannot break the table (T-12-04).
 */
function conflictSectionLines(sorted: readonly PackageEntry[]): string[] {
  const rows: string[] = [];
  for (const pkg of sorted) {
    const conflict = pkg.finding?.conflict;
    if (conflict === undefined) continue;
    const usedIn = pkg.occurrences.map((o) => o.target).join(", ");
    rows.push(
      `| ${escapeCell(pkg.name)} | ${escapeCell(conflict.assessed)} | ${escapeCell(conflict.disagreeing.join(", "))} | ${escapeCell(usedIn)} |`,
    );
  }
  if (rows.length === 0) return [];
  return [
    "## Assessment conflicts (in-depth scan vs quick check)",
    "",
    "For these packages the in-depth ScanCode assessment disagrees with the declared/registry quick check. Each is a gate failure until a policy `[[clarify]]` override records the decision — accept the in-depth value, or re-assess.",
    "",
    "| Package | In-depth (ScanCode) | Quick check | Used in |",
    "| --- | --- | --- | --- |",
    ...rows,
    "",
  ];
}

/**
 * The package-counts block: total, per-ecosystem (compareCodeUnits-sorted),
 * production / development-only / Docker-OS / unknown-license counts. App-scope
 * packages feed the prod/dev split (an app concept); os-scope packages are
 * counted separately as Docker base-image packages so the three buckets
 * (production + development-only + Docker OS) partition the total. Input is the
 * already-sorted package list.
 */
function packageCountsLines(sorted: readonly PackageEntry[]): string[] {
  const ecosystemCounts = new Map<string, number>();
  let unknownCount = 0;
  let devOnlyCount = 0;
  let osCount = 0;
  for (const pkg of sorted) {
    const ecosystem = ecosystemOf(pkg.purl);
    ecosystemCounts.set(ecosystem, (ecosystemCounts.get(ecosystem) ?? 0) + 1);
    if (isUnknownLicense(pkg)) unknownCount += 1;
    if (isOsPackage(pkg)) osCount += 1;
    else if (isDevelopmentOnly(pkg)) devOnlyCount += 1;
  }
  const prodCount = sorted.length - devOnlyCount - osCount;
  const lines: string[] = [
    "**Package counts:**",
    "",
    `- Total packages: ${sorted.length}`,
  ];
  for (const [ecosystem, count] of [...ecosystemCounts.entries()].sort(
    ([a], [b]) => compareCodeUnits(a, b),
  )) {
    lines.push(`- ${escapeCell(ecosystem)}: ${count}`);
  }
  lines.push(
    `- Production packages: ${prodCount}`,
    `- Development-only packages: ${devOnlyCount}`,
    `- Docker image packages: ${osCount}`,
    `- Unknown license: ${unknownCount}`,
    "",
  );
  return lines;
}

const DEFAULT_TITLE = "Third-Party Licenses";

/**
 * Document H1 (07-09): the author-supplied [document].title when present, else
 * the locked default. A title is a HEADING, not a table cell — it is NOT
 * escapeCell'd (author prose may legitimately carry markdown); any CR/LF is
 * collapsed to a single space and the result trimmed so the heading stays on one
 * line and the output carries no CR (determinism).
 */
function documentTitle(policyView?: PolicyView): string {
  const raw = policyView?.document?.title;
  if (raw === undefined) return DEFAULT_TITLE;
  return raw.replace(/\r\n|\r|\n/g, " ").trim();
}

/**
 * The blocking-table head for the "## Problematic licenses" roll-up (07-09).
 * Distinct from TABLE_HEAD: it carries Severity + Rule + Reason around the
 * package columns so the section is a self-contained gate report.
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
 * Coarse warn category derived from a verdict rule (07-09 non-blocking roll-up):
 * copyleft (default:copyleft / default:imprecise-copyleft), unknown
 * (default:unknown / default:imprecise), deny (rule starts with "deny"), else
 * other. Deterministic and total over the rule string.
 */
function warnCategory(rule: string): "copyleft" | "unknown" | "deny" | "other" {
  if (rule === "default:copyleft" || rule === "default:imprecise-copyleft") {
    return "copyleft";
  }
  if (rule === "default:unknown" || rule === "default:imprecise") {
    return "unknown";
  }
  if (rule.startsWith("deny")) return "deny";
  return "other";
}

/**
 * One blocking-table row for a (purl, rule, reason) group. Name/Ecosystem/
 * Version/License come from the looked-up PackageEntry; every cell (reason and
 * rule especially) routes through escapeCell. The Used-in cell is the group's
 * deduped, compareCodeUnits-sorted targets joined ", ".
 */
function problematicRow(group: BlockingGroup, pkg: PackageEntry): string {
  // 07-17: the Why cell folds over the SAME flagged target set the Used-in cell
  // names — never over the package's out-of-scope occurrences.
  const shownTargets = new Set(group.targets);
  const targets = [...shownTargets].sort(compareCodeUnits).join(", ");
  return `| ${escapeCell("fail")} | ${escapeCell(group.rule)} | ${escapeCell(pkg.name)} | ${escapeCell(ecosystemOf(pkg.purl))} | ${escapeCell(pkg.version)} | ${escapeCell(licenseCellOf(pkg))} | ${escapeCell(targets)} | ${escapeCell(whyCellOf(pkg, shownTargets))} | ${escapeCell(group.reason)} |`;
}

/**
 * The "## Problematic licenses" roll-up section (07-09) — rendered AFTER the
 * counts block and BEFORE the copyleft section, on a policy run only. The
 * BLOCKING table is every fail verdict, grouped by (purl, rule, reason) into one
 * row with deduped+sorted targets; rows are sorted by rule, then package
 * (comparePackages on the looked-up entry), then the joined targets. The
 * NON-BLOCKING line summarizes warn verdicts by coarse category. The heading
 * always renders; the empty state is the ✅ line.
 */
function problematicSectionLines(
  sorted: readonly PackageEntry[],
  verdicts: ReadonlyArray<Verdict>,
): string[] {
  const byPurl = new Map<string, PackageEntry>();
  for (const pkg of sorted) byPurl.set(pkg.purl, pkg);

  // Group fail verdicts by (purl, rule, reason). A fail whose purl has no
  // package entry is defensively skipped (it can carry no name/version/license).
  const groups = new Map<string, BlockingGroup>();
  for (const verdict of verdicts) {
    if (verdict.status !== "fail") continue;
    if (!byPurl.has(verdict.purl)) continue;
    const key = `${verdict.purl} ${verdict.rule} ${verdict.reason}`;
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
    // Sort: rule, then package (comparePackages on the looked-up entry), then
    // the joined deduped+sorted targets. Every grouped purl is in byPurl.
    const ordered = [...groups.values()].sort((a, b) => {
      const byRule = compareCodeUnits(a.rule, b.rule);
      if (byRule !== 0) return byRule;
      const pkgA = byPurl.get(a.purl)!;
      const pkgB = byPurl.get(b.purl)!;
      const byPkg = comparePackages(pkgA, pkgB);
      if (byPkg !== 0) return byPkg;
      const targetsA = [...new Set(a.targets)]
        .sort(compareCodeUnits)
        .join(", ");
      const targetsB = [...new Set(b.targets)]
        .sort(compareCodeUnits)
        .join(", ");
      return compareCodeUnits(targetsA, targetsB);
    });
    lines.push(...PROBLEMATIC_HEAD);
    for (const group of ordered) {
      lines.push(problematicRow(group, byPurl.get(group.purl)!));
    }
    lines.push("");
  }

  // Non-blocking roll-up: count warn verdicts by coarse category; render ONE
  // line naming every non-zero category in a fixed order. Omitted entirely when
  // there are zero warns.
  const warnCounts = new Map<string, number>();
  let warnTotal = 0;
  for (const verdict of verdicts) {
    if (verdict.status !== "warn") continue;
    warnTotal += 1;
    const category = warnCategory(verdict.rule);
    warnCounts.set(category, (warnCounts.get(category) ?? 0) + 1);
  }
  if (warnTotal > 0) {
    const order: ReadonlyArray<"copyleft" | "unknown" | "deny" | "other"> = [
      "copyleft",
      "unknown",
      "deny",
      "other",
    ];
    const parts = order
      .filter((category) => (warnCounts.get(category) ?? 0) > 0)
      .map((category) => `${warnCounts.get(category)} ${category} warning(s)`);
    lines.push(
      `_Non-blocking: ${parts.join(", ")} (dev/os-downgraded or suppressed). See the sections below._`,
      "",
    );
  }

  return lines;
}

export function renderMarkdown(
  model: CanonicalDependencies,
  policyView?: PolicyView,
): string {
  // Defensive re-sort: the renderer must not trust input order.
  const sorted = [...model.packages].sort(comparePackages);

  const lines: string[] = [
    `# ${documentTitle(policyView)}`,
    "",
    HEADER_LINE,
    "",
  ];

  // Author preamble (07-09): verbatim markdown block after the auto-generated
  // header comment and BEFORE the policy pointer / counts. CRLF/CR normalized to
  // "\n" (determinism); rendered as-is — NOT escapeCell'd: it is intentional
  // author markdown at the same trust boundary as the policy file. A trailing
  // blank line separates it from what follows.
  const preamble = policyView?.document?.preamble;
  if (preamble !== undefined) {
    lines.push(preamble.replace(/\r\n|\r/g, "\n"), "");
  }

  // Policy pointer line — policy runs only. The path is policy-authored config
  // and routes through escapeCell.
  if (policyView !== undefined) {
    lines.push(
      `Copyleft notice rules are configured in ${escapeCell(policyView.policyPath)}.`,
      "",
    );
  }

  lines.push(...packageCountsLines(sorted));

  // Problematic licenses roll-up (07-09) — policy runs only. Rendered AFTER the
  // counts block and BEFORE the copyleft section so the gate-blocking findings
  // sit at the top of the document.
  if (policyView !== undefined) {
    lines.push(...problematicSectionLines(sorted, policyView.verdicts));
  }

  // Copyleft and special notices — policy runs only.
  if (policyView !== undefined) {
    // Group verdicts by purl once — the renderer stays a pure function of its
    // arguments.
    const verdictsByPurl = new Map<string, Verdict[]>();
    for (const verdict of policyView.verdicts) {
      const list = verdictsByPurl.get(verdict.purl);
      if (list === undefined) verdictsByPurl.set(verdict.purl, [verdict]);
      else list.push(verdict);
    }

    // Collect the flagged copyleft rows first so the EMPTY state can be a ✅ line
    // rather than a bare table head. Membership = at least one fail/warn verdict
    // whose rule is exactly "default:copyleft" (the engine's only copyleft-
    // flagging rule). The Used-in cell lists only the flagged occurrence targets
    // — how the elected branch surfaces: the non-suppressed leaking workspaces
    // are named. The Why column (07-13) carries the per-row provenance.
    const copyleftRows: string[] = [];
    for (const pkg of sorted) {
      const flagged = (verdictsByPurl.get(pkg.purl) ?? []).filter(
        (verdict) =>
          (verdict.status === "fail" || verdict.status === "warn") &&
          verdict.rule === "default:copyleft",
      );
      if (flagged.length === 0) continue;
      const targets = [
        ...new Set(flagged.map((verdict) => verdict.occurrenceTarget)),
      ].sort(compareCodeUnits);
      copyleftRows.push(copyleftRow(pkg, targets));
    }

    lines.push("## Copyleft and special notices", "");

    // Suppressed-workspaces list: every field is policy-authored and routes
    // through escapeCell. Sorted by path (compareCodeUnits) for determinism
    // regardless of policy-file order. Shown whenever configured — it explains
    // the suppression even when nothing leaks.
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

    if (copyleftRows.length > 0) {
      lines.push(
        "The packages listed below carry copyleft or special license obligations in at least one non-suppressed workspace.",
        "",
        ...COPYLEFT_HEAD,
        ...copyleftRows,
        "",
      );
    } else {
      lines.push(
        "✅ No package carries copyleft or special license obligations.",
        "",
      );
    }
  }

  // Imprecise-licenses review section — finding-level (rendered with or without
  // a policy view).
  lines.push(...impreciseSectionLines(sorted));

  // Assessment-conflicts review section (SCAN-05) — finding-level, mirrors
  // the imprecise section: absent when no package carries a conflict marker so
  // zero-conflict documents stay byte-identical (D-06).
  lines.push(...conflictSectionLines(sorted));

  // Summary tables, split by package-level dev/prod classification (POL-08) for
  // APP-scope packages, then a dedicated Docker image packages section (COLL-04).
  // Fixed order — production, development-only, then Docker image packages — for
  // determinism; each section always renders its heading (a ✅ line replaces the
  // table when empty). The Used-in cell stays the full occurrence-target list; the split is
  // by package classification, not per-occurrence. OS packages are excluded from
  // both app sections (the dev/prod split is an app concept). Lockfile-only
  // scans carry no licenses — "unknown" is correct pre-annotation behavior, not
  // a rendering defect.
  const appPackages = sorted.filter((pkg) => !isOsPackage(pkg));
  const osPackages = sorted.filter(isOsPackage);
  const developmentOnly = appPackages.filter(isDevelopmentOnly);
  const production = appPackages.filter((pkg) => !isDevelopmentOnly(pkg));
  lines.push(
    ...summarySection(
      "## Production dependencies",
      production,
      "✅ No production dependencies.",
    ),
  );
  lines.push("");
  lines.push(
    ...summarySection(
      "## Development-only dependencies",
      developmentOnly,
      "✅ No development-only dependencies.",
    ),
  );
  lines.push("");
  lines.push(
    ...summarySection(
      "## Docker image packages",
      osPackages,
      "✅ No Docker images are currently tracked.",
    ),
  );

  return lines.join("\n") + "\n";
}
