/**
 * Canonical model — the hub module.
 *
 * Every other module imports types from here and never from each other. The
 * model deliberately reserves fields so later work is purely additive:
 * provenance layers, scope taxonomy for Docker, and the dev/prod marker.
 */

/**
 * Provenance of a license claim. "generator" is the source produced by the
 * collectors; "registry" is appended by the enrichment stage when a registry
 * (PyPI/npm) JSON response supplies a license for an otherwise-unknown package,
 * so a registry-sourced finding is auditable in the dump and rendered output.
 * "scancode" is appended by the enrichment stage when the intensive ScanCode
 * collector supplies a license the registry could not (or only imprecisely) —
 * see Phase 10; it replays from the committed cache exactly like "registry"
 * does, so it is auditable the same way. "corrected" / "curated" / "override"
 * are reserved.
 */
export type LicenseClaimSource =
  | "generator"
  | "corrected"
  | "curated"
  | "override"
  | "registry"
  | "scancode";

export type LicenseClaimKind = "spdx-id" | "name" | "expression";

export interface LicenseClaim {
  raw: string;
  kind: LicenseClaimKind;
  source: LicenseClaimSource;
}

/**
 * Confidence of a normalized license finding.
 *
 * - "exact": the raw value parsed as a valid SPDX expression verbatim.
 * - "corrected": spdx-correct fixed a sloppy-but-precise value (e.g. "Apache
 *   License, Version 2.0" → Apache-2.0).
 * - "none": genuinely unknown — no license could be determined (expression null,
 *   impreciseFamily absent).
 * - "imprecise": an ambiguous license FAMILY label was observed ("BSD", "BSD
 *   License", "Apache Software License") that carries no clause/version, so it
 *   is NOT guessed to a precise SPDX id (INV-04). It is present-but-needs-clarify:
 *   `expression` stays null because a bare family is not a valid SPDX expression,
 *   and the faithful family string is carried on {@link LicenseFinding.impreciseFamily}.
 *   Distinct from "none" — an imprecise finding IS a license, just an
 *   under-specified one a `[[clarify]]` override can disambiguate.
 */
export type FindingConfidence = "exact" | "corrected" | "none" | "imprecise";

/**
 * Normalized license conclusion for one package. Produced by the normalization
 * layer; provenance is mandatory for auditability.
 */
export interface LicenseFinding {
  /**
   * Full normalized SPDX expression; null = unknown OR imprecise (an imprecise
   * family is not a valid SPDX expression and must never be emitted as one —
   * see {@link FindingConfidence}).
   */
  expression: string | null;
  /** Elected branch as rendered canonical string; null = unknown or imprecise. */
  elected: string | null;
  /** "generator" (exact parse or unknown), "corrected", "registry" (enrichment-appended), "override" (clarify); "curated" reserved. */
  source: LicenseClaimSource;
  confidence: FindingConfidence;
  /**
   * The faithful ambiguous family label (e.g. "BSD", "Apache") — present ONLY
   * when confidence is "imprecise". It is what the render layer surfaces and
   * what the policy could-be-copyleft check matches against the literal
   * COULD_BE_COPYLEFT_FAMILIES token set (INV-04).
   */
  impreciseFamily?: string;
  /**
   * Distinct audit citation for a TOOL-LEVEL builtin override that decided this
   * finding (POL-07). Present ONLY when a shipped BUILTIN_OVERRIDES entry (not a
   * project [[clarify]]) replaced the finding — e.g. "override:builtin[3]". A
   * project clarify keeps its existing "clarify[i]" citation via the policy
   * engine's clarifyIndexFor lookup, so this field is absent for those. The
   * engine cites this instead of plain "default:ok" so a tool-level
   * disambiguation stays auditable (closes the default:ok-fallthrough gap).
   */
  overrideRule?: string;
  /**
   * A STALE override (POL-07): an override (project clarify or tool-level
   * builtin) carried an `expects` precondition that NO LONGER matches the
   * package's pre-override observed signal. The asserted expression is NOT
   * applied (this finding keeps its un-overridden value); instead the engine
   * emits a loud fail verdict naming the package, the expected value, and the
   * now-observed value — a stale override must never silently mask a relicense.
   */
  staleOverride?: StaleOverride;
  /**
   * A senior-assessment disagreement (SCAN-05): the in-depth ScanCode answer
   * conflicts with at least one quick-check claim (declared metadata or a
   * registry answer). Set by applyScancodeAssessment on the UN-OVERRIDDEN
   * base finding — the base stands in full and the disagreement is surfaced,
   * never absorbed in either direction — and cleared when an override
   * (project clarify or tool-level builtin) DECIDES the finding: an applied
   * override is the human resolution, so it never carries the marker. Absent
   * when no scancode claim exists or the assessment agrees (absent-not-empty
   * for golden stability).
   */
  conflict?: AssessmentConflict;
  /**
   * The PRE-OVERRIDE observed SPDX expression (C#1: deny terminal over
   * overrides). Set by annotateFindings from the un-overridden base finding
   * BEFORE an override may rewrite `expression`. The deny terminal consults
   * BOTH this observed expression AND the (possibly-overridden) `expression`:
   * if EITHER is denied, deny fires — a denied OBSERVED license can never be
   * licensed back in by any override (deny is terminal over overrides). Absent
   * when no override ran (the un-overridden finding's `expression` already IS
   * the observed value) or when the base finding had no parseable expression.
   */
  observedExpression?: string;
  /**
   * The SET of EVERY observed per-claim normalized PRECISE expression (#1/#5/#11:
   * deny must see every observed claim, not only the lossy COMBINED expression).
   * Produced by annotateFindings by running normalizeRaw over each license claim
   * and collecting the non-null precise results (deduped, sorted by
   * {@link compareCodeUnits}). Genuinely-unknown and imprecise-family claims
   * contribute nothing (they carry no precise license to deny).
   *
   * WHY: combineKnown elects an imprecise family / collapses to unknown BEFORE a
   * precise non-copyleft DENIED member (BUSL-1.1, Elastic-2.0 — source-available,
   * NOT copyleft) when an imprecise family token ("GPL") or an unknown token
   * co-exists, so the combined `expression` is null/imprecise and the deny
   * terminal — reading only the combined expression — never sees the denied
   * member. The deny terminal also consults THIS set: if ANY observed precise
   * expression is denied, deny fires regardless of how combine rendered the
   * finding (precise / imprecise / unknown), in every scope. Deny stays
   * terminal-0; this only changes what deny CAN SEE, never what combine renders.
   *
   * Absent when no claim normalized to a precise expression (nothing to carry).
   */
  observedExpressions?: readonly string[];
  /**
   * Surfaced non-normalizable raw claim tokens for a NON-GATING `os`-scope
   * PARTIAL finding (07-06). Set ONLY when an os-scope package's claim set mixes
   * ≥1 normalizable SPDX member with ≥1 genuinely-unknown ("none") token: the
   * finding is built from the normalizable members (so the KNOWN GPL/BSD
   * obligations are not hidden by the all-or-nothing → unknown rule) AND the
   * remaining unparseable tokens are surfaced here — deduped, sorted by
   * {@link compareCodeUnits}, raw-but-trimmed — for review and rendering rather
   * than silently dropped.
   *
   * SAFETY: this is os-scope ONLY. App/dev/prod (gating) scopes keep the strict
   * all-or-nothing → unknown invariant and NEVER carry this field. The
   * surfaced tokens are advisory: they never enter `expression` and never gate
   * the policy verdict (os is non-gating; deny stays terminal over the KNOWN
   * member). Absent for every finding that is not an os-scope partial.
   */
  unrecognizedTokens?: readonly string[];
}

/** A stale-override condition surfaced to the policy engine (POL-07). */
export interface StaleOverride {
  /** "clarify" (project) or "builtin" (shipped tool-level) — for the message. */
  level: "clarify" | "builtin";
  /** The value the override expected to still observe. */
  expected: string;
  /** The package's now-observed signal members (the relicensed values). */
  observed: ReadonlyArray<string>;
}

/** A senior-assessment disagreement surfaced to the policy engine (SCAN-05). */
export interface AssessmentConflict {
  /**
   * The in-depth assessed value: the ScanCode-elected normalized SPDX
   * expression, or the bare family token when the assessment itself is
   * imprecise.
   */
  assessed: string;
  /**
   * The disagreeing quick-check signal members — normalized where precise,
   * the family token / trimmed raw otherwise — deduped and sorted.
   */
  disagreeing: ReadonlyArray<string>;
}

export type VerdictStatus = "ok" | "warn" | "fail" | "suppressed";

/** One policy decision per (package x occurrence). */
export interface Verdict {
  purl: string;
  occurrenceTarget: string;
  status: VerdictStatus;
  /** Machine-readable deciding rule: "compatible[1]", "clarify[0]", "workspace.copyleft_suppressed[0]", "default:copyleft", "default:unknown", "default:imprecise", "default:imprecise-copyleft", "default:ok". */
  rule: string;
  reason: string;
}

/** "os" is reserved for Docker image scanning. */
export type ScopeTaxonomy = "app" | "os";

/**
 * Dependency provenance — "why is this dependency here?" — derived per-target
 * at collect time from the lockfile/BOM dependency graph (07-13). Introduction
 * is PER-TARGET (per BOM): the same purl can be a direct dependency in one
 * workspace and a transitive one in another, so this rides on the Occurrence,
 * not the package.
 *
 * Two collect-time lanes populate it (the only graphs the research found
 * usable):
 * - npm via yarn-plugin-cyclonedx: the BOM carries a complete root-anchored
 *   `dependencies` graph. `direct`/`introducedBy`/`path` are derived.
 * - python via poetry.lock + pyproject: the lockfile `[package.dependencies]`
 *   tables + the declared roots give `direct`/`introducedBy`/`path`.
 *
 * Every OTHER source (terraform, Docker image packages, bun, any npm BOM lacking a
 * graph) leaves `introduction` ABSENT — the render layer shows an honest "—"
 * rather than a fabricated value.
 *
 * 07-19 DESCOPE — OPTIONALITY IS OUT OF SCOPE. There is intentionally no
 * `optional` field. The npm lane never carried optional (the BOM has no
 * optional/peer information); the python lane formerly derived it from poetry
 * markers (`optional = true`, PEP 508 marker variables, extras, multi-variant
 * spec arrays), but that marker parsing was a recurring mislabeling bug class
 * (a critical/warning in 3 of 4 adversarial-review rounds) and was removed.
 * Markers and extras are NOT parsed; every dependency edge is a plain edge.
 */
export interface DependencyIntroduction {
  /** True iff the purl is a declared-direct dependency of this target/BOM root. */
  direct: boolean;
  /**
   * Sorted-unique SET of direct-parent purls that pull this package in for this
   * target. A union: a package reached through multiple parents (or a duplicated
   * purl) carries every real introducer here. Empty for a direct dependency.
   */
  introducedBy: readonly string[];
  /**
   * Deterministic representative root→component purl chain (one shortest path).
   * Omitted for a direct dependency (the chain would be just the package
   * itself). The tie-break is the smallest child purl at each BFS level (the
   * smallest-introducer-at-each-level order), NOT a whole-path lexicographic
   * minimum. The npm lane computes this chain on the REAL bom-ref graph so it is
   * always a single concrete dependency chain (never a fabricated hop between
   * dup-purl variants); the python lane computes it on the lockfile purl graph.
   * HONEST CAVEAT: a multi-parent transitive package has several real introducer
   * chains — `introducedBy` is the complete set, `path` is one representative
   * chosen by the deterministic BFS tie-break.
   */
  path?: readonly string[];
}

/**
 * One consuming target of a package. Dev/prod scope is occurrence-level, not
 * package-level: the same package can legally be a dev dependency in one
 * workspace and a prod dependency in another, and both flags must be recorded
 * independently.
 */
export interface Occurrence {
  /** Target identity, e.g. "apps/scratch". Forward-slash, never backslash. */
  target: string;
  /** Scope of this package in this target (dev in docs, prod in frontend is legal). */
  isDevDependency: boolean;
  /**
   * Dependency provenance for this target (07-13) — direct-vs-transitive plus
   * the introducer path. Absent when the source carries no usable dependency
   * graph (terraform / Docker OS / bun / graph-less npm), so goldens that
   * predate provenance stay byte-identical where it is absent.
   */
  introduction?: DependencyIntroduction;
}

/**
 * Per-package attribution extracted from CycloneDX evidence at merge time.
 * Holds extracted artifacts only: raw decoded license texts never enter the
 * model — except `verbatimTexts`, retained exclusively for packages with no
 * spdx-id/expression-kind claim, where the verbatim file is the only license
 * statement we have. All stored text is control-character-sanitized at intake.
 */
export interface PackageAttribution {
  /** Concrete copyright lines extracted from evidence texts (deduped, capped at 20, never fabricated). */
  copyrightLines: string[];
  /** Decoded NOTICE file contents (Apache section 4(d) input), sanitized verbatim. */
  noticeTexts: string[];
  /** component.author when string-typed — secondary "Author:" attribution, never a copyright claim. */
  author?: string;
  /** True when at least one non-NOTICE license file was decoded for this package. */
  hasVerbatimText: boolean;
  /** Decoded license-file texts — only for packages with zero spdx-id/expression claims. */
  verbatimTexts?: string[];
}

export interface PackageEntry {
  /** Dedup key, kept verbatim from the SBOM (URL-encoding like %40 intact). */
  purl: string;
  /** Display name including group, e.g. "@ampproject/remapping". */
  name: string;
  version: string;
  /** Consuming targets with per-occurrence scope, sorted by target. */
  occurrences: Occurrence[];
  licenseClaims: LicenseClaim[];
  scope: ScopeTaxonomy;
  /** Raw generator scope (e.g. cdxgen's unreliable yarn scope), recorded verbatim. */
  rawScope?: string;
  /**
   * Normalized license conclusion — set only by a policy run. Absent without
   * `--policy`, so existing dump-model goldens stay byte-identical.
   */
  finding?: LicenseFinding;
  /**
   * Evidence-derived attribution — set only when the component carried at
   * least one usable evidence entry. Absent (never empty) for evidence-less
   * packages, so existing dump-model and render goldens stay byte-identical.
   */
  attribution?: PackageAttribution;
}

/** Invariant: `packages` is sorted by {@link comparePackages}. */
export interface CanonicalDependencies {
  packages: PackageEntry[];
}

/** Dump-model shape when a policy run happened (sortedKeyReplacer handles it untouched). */
export interface EvaluatedDependencies extends CanonicalDependencies {
  verdicts: Verdict[];
}

/**
 * UTF-16 code-unit comparison — the only string comparator in this tool. The
 * `<`/`>` operators order strings by UTF-16 code unit (not Unicode codepoint;
 * the surrogate-pair edge differs), which is platform-invariant.
 *
 * WHY: locale-aware string comparison (the locale-sensitive compare method on
 * String) is ICU-dependent and produces different orderings across
 * Windows/Linux and across runtimes, silently breaking byte-identity of
 * generated output. Code-unit comparison is platform-invariant and is
 * therefore mandatory tool-wide.
 */
export const compareCodeUnits = (a: string, b: string): number =>
  a < b ? -1 : a > b ? 1 : 0;

/** Stable total order over packages: (name, version, purl). */
export function comparePackages(a: PackageEntry, b: PackageEntry): number {
  return (
    compareCodeUnits(a.name, b.name) ||
    compareCodeUnits(a.version, b.version) ||
    compareCodeUnits(a.purl, b.purl)
  );
}

/**
 * JSON.stringify replacer that sorts object keys (arrays untouched) by
 * {@link compareCodeUnits}. Exported so the committed enrichment cache shares
 * the exact tool-wide sorted-key serialization contract — there must be one
 * sorter, not two.
 */
export function sortedKeyReplacer(_key: string, value: unknown): unknown {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
        compareCodeUnits(a, b),
      ),
    );
  }
  return value;
}

/**
 * Deterministic JSON serialization for any on-disk artifact: object keys sorted
 * (arrays untouched), indent 2, trailing newline. JSON.stringify never emits
 * `\r`, so the result is LF-only by construction. The committed enrichment
 * cache reuses this so its bytes follow the identical contract.
 */
export function toSortedJson(value: unknown): string {
  return JSON.stringify(value, sortedKeyReplacer, 2) + "\n";
}

/**
 * Deterministic JSON dump of the canonical model. Delegates to
 * {@link toSortedJson} — same sorted-key/LF/indent-2 bytes. Used by
 * `--dump-model` and golden-file tests.
 */
export function toSortedDependenciesJson(model: CanonicalDependencies): string {
  return toSortedJson(model);
}
