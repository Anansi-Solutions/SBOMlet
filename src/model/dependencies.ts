/**
 * Canonical model - the hub module.
 *
 * Every other module imports types from here and never from each other. The model deliberately
 * reserves fields so later work is purely additive: provenance layers, scope taxonomy for Docker,
 * and the dev/prod marker.
 */
import { isAbsolute } from "node:path";

import { type } from "arktype";

/**
 * Untrusted, unresolved license text exactly as it entered the tool - a collector-read license
 * string, a registry answer, a ScanCode raw. It is what {@link canonicalizeExpression} consumes;
 * nothing downstream may treat it as resolved. Minted at the raw-claim origins via {@link
 * asRawLicense} - the one place a plain string becomes a RawLicense.
 */
const _rawLicenseBrand = type("string").brand("RawLicense");

export type RawLicense = typeof _rawLicenseBrand.infer;

/**
 * The single resolved-and-canonical SPDX state: there is no intermediate "normalized but not yet
 * canonical" license anywhere in the model. Everything resolved is canonical. Minted ONLY by
 * canonicalizeExpression (normalize/expression.ts) - the sole boundary that turns raw text into a
 * canonical expression.
 */
const _canonicalLicenseBrand = type("string").brand("CanonicalLicense");

export type CanonicalLicense = typeof _canonicalLicenseBrand.infer;

/**
 * The minimal package-URL shape a {@link Purl} must satisfy: a `pkg:` scheme, a non-empty type, a
 * slash, and a non-empty name. Deliberately permissive about qualifiers and subpaths - it gates the
 * gross shape, not the full purl grammar, so a real `pkg:npm/...` / `pkg:deb/...` always passes.
 */
const PURL_SHAPE = /^pkg:[^/]+\/.+/;

/**
 * A package URL (`pkg:<type>/<name>@<version>`), the tool-wide dedup and cache key. The brand is
 * VALIDATED: a value must match {@link PURL_SHAPE} (a `pkg:` scheme, a type, a slash, a name), so a
 * plainly non-purl string can never enter the type. Minted at purl construction and at the {@link
 * parsePurl} boundary via {@link asPurl}; kept verbatim thereafter (URL-encoding intact).
 */
const _purlBrand = type("string")
  .narrow((value, ctx) => PURL_SHAPE.test(value) || ctx.reject("a pkg: package URL"))
  .brand("Purl");

export type Purl = typeof _purlBrand.infer;

/**
 * An absolute filesystem path (a `path.resolve`/`join` result, or a base/repo root the CLI resolved
 * to absolute). The brand is VALIDATED: a value must satisfy node:path's {@link isAbsolute}, so a
 * relative string can never enter the type. Minted via {@link asAbsolutePath} at the resolution
 * boundary - every current call site passes a `resolve`/`join` result, so the check catches a real
 * bug (a non-absolute leak) rather than ever firing in practice.
 */
const _absolutePathBrand = type("string")
  .narrow((value, ctx) => isAbsolute(value) || ctx.reject("an absolute path"))
  .brand("AbsolutePath");

export type AbsolutePath = typeof _absolutePathBrand.infer;

/**
 * A non-empty repo-relative path (forward-slash), as it lands in a committed artifact - never an
 * absolute machine path. The brand is VALIDATED: a value must be non-empty AND not satisfy
 * node:path {@link isAbsolute}, so an empty or absolute string can never enter the type. Minted via
 * {@link asRelativePath} where such a path is established (the report's policy-pointer line).
 */
const _relativePathBrand = type("string")
  .narrow(
    (value, ctx) =>
      (value.length > 0 && !isAbsolute(value)) || ctx.reject("a non-empty relative path"),
  )
  .brand("RelativePath");

export type RelativePath = typeof _relativePathBrand.infer;

/**
 * A tool-minted target identity: a repo-relative forward-slash path ("libraries/iframe-rpc") OR a
 * docker occurrence identity ("docker:" + source). The brand is VALIDATED: non-empty, no backslash,
 * and NOT node:path {@link isAbsolute}, so an absolute machine path (an {@link AbsolutePath}) or a
 * Windows-separated path can never enter the type - the abs/rel fence that keeps a target's machine
 * `dir` and its `identity` from ever being confused. Minted via {@link asTargetIdentity} at the
 * three identity origins (target resolution, discovery, the docker fan-out). The reserved
 * "docker:"-namespace guard for non-os inputs (assertNotReservedIdentity) is enforced separately at
 * the merge boundary; the brand admits the shape an app path and a docker identity share.
 */
const _targetIdentityBrand = type("string")
  .narrow(
    (value, ctx) =>
      (value.length > 0 && !value.includes("\\") && !isAbsolute(value)) ||
      ctx.reject("a repo-relative or docker: target identity"),
  )
  .brand("TargetIdentity");

export type TargetIdentity = typeof _targetIdentityBrand.infer;

/**
 * A dependency's display name (`@scope/pkg`, `busybox`, an `<ns>/<name>` terraform address). The
 * brand is VALIDATED non-blank, so a blank name can never identify a package. Minted via {@link
 * asDependencyName} where a package name is CONSTRUCTED (a collector building a component, the
 * merge deriving a display name); a distinct value that is not specifically a dependency name (a
 * policy pattern, a family token, a display label) stays a plain string.
 */
const _dependencyNameBrand = type("string")
  .narrow((value, ctx) => value.trim().length > 0 || ctx.reject("a non-blank dependency name"))
  .brand("DependencyName");

export type DependencyName = typeof _dependencyNameBrand.infer;

/**
 * A dependency's resolved version string, kept verbatim from its source (never parsed). The brand
 * is VALIDATED non-blank, so a blank version can never identify a package. Minted via {@link
 * asDependencyVersion} at the same construction sites as {@link DependencyName}.
 */
const _dependencyVersionBrand = type("string")
  .narrow((value, ctx) => value.trim().length > 0 || ctx.reject("a non-blank dependency version"))
  .brand("DependencyVersion");

export type DependencyVersion = typeof _dependencyVersionBrand.infer;

/**
 * Mint a {@link RawLicense} from untrusted license text - the one cast that admits a plain string
 * into the raw-license state, used at the claim origins (collector, enrichment, ScanCode) and by
 * canonicalization's own input path.
 */
export function asRawLicense(text: string): RawLicense {
  return text as RawLicense;
}

/**
 * Mint a {@link Purl} from a constructed or parsed package-URL string - used at every purl
 * CONSTRUCTION site (a collector building `pkg:...`) and at trusted disk-key sites, where the value
 * is a purl by construction.
 *
 * @throws if `text` is not a {@link PURL_SHAPE} package URL. Safe at those sites because the value
 * is valid by construction; the EXTERNAL SBOM boundary uses {@link tryAsPurl} instead so a malformed
 * component purl is tolerantly dropped rather than crashing the run.
 */
export function asPurl(text: string): Purl {
  return _purlBrand.assert(text) as Purl;
}

/**
 * Tolerantly mint a {@link Purl} at an EXTERNAL boundary (a parsed SBOM component / metadata purl).
 *
 * @returns the branded purl, or undefined when `text` is not a {@link PURL_SHAPE} package URL - the
 * caller then treats the purl as absent (the component drops via the existing skip path), matching
 * the skip-don't-throw posture the tool holds over untrusted SBOM data.
 */
export function tryAsPurl(text: string): Purl | undefined {
  const result = _purlBrand(text);

  return result instanceof type.errors ? undefined : result;
}

/**
 * Mint an {@link AbsolutePath} at the point a path is resolved to absolute.
 *
 * @throws if `path` is not absolute per node:path's {@link isAbsolute}. Every call site passes a
 * `resolve`/`join` result, so this never fires in practice but catches a non-absolute leak.
 */
export function asAbsolutePath(path: string): AbsolutePath {
  return _absolutePathBrand.assert(path) as AbsolutePath;
}

/**
 * Mint a {@link RelativePath} where a repo-relative path is established for a committed artifact.
 *
 * @throws if `path` is empty or absolute per node:path's {@link isAbsolute}. Fires on a bug that
 * would otherwise leak an absolute machine path into committed bytes.
 */
export function asRelativePath(path: string): RelativePath {
  return _relativePathBrand.assert(path) as RelativePath;
}

/**
 * Mint a {@link TargetIdentity} at an identity origin (target resolution, discovery, the docker
 * fan-out).
 *
 * @throws if `value` is empty, contains a backslash, or is absolute per node:path {@link isAbsolute}
 * - a machine path or a Windows-separated string can never become a target identity.
 */
export function asTargetIdentity(value: string): TargetIdentity {
  return _targetIdentityBrand.assert(value) as TargetIdentity;
}

/**
 * Mint a {@link DependencyName} where a package name is constructed.
 *
 * @throws if `name` is blank. Fires on a bug (or malformed input not filtered upstream) that would
 * otherwise let a blank string identify a package.
 */
export function asDependencyName(name: string): DependencyName {
  return _dependencyNameBrand.assert(name) as DependencyName;
}

/**
 * Mint a {@link DependencyVersion} where a package version is constructed.
 *
 * @throws if `version` is blank, for the same reason as {@link asDependencyName}.
 */
export function asDependencyVersion(version: string): DependencyVersion {
  return _dependencyVersionBrand.assert(version) as DependencyVersion;
}

/**
 * Provenance of a license claim. "generator" is the source produced by the collectors; "registry"
 * is appended by the enrichment stage when a registry (PyPI/npm) JSON response supplies a license
 * for an otherwise-unknown package, so a registry-sourced finding is auditable in the dump and
 * rendered output. "scancode" is appended by the enrichment stage when the intensive ScanCode
 * collector supplies a license the registry could not (or only imprecisely) - see Phase 10; it
 * replays from the committed cache exactly like "registry" does, so it is auditable the same way.
 * "corrected" / "curated" / "override" are reserved.
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
  raw: RawLicense;
  kind: LicenseClaimKind;
  source: LicenseClaimSource;
}

/**
 * Confidence of a normalized license finding.
 *
 * - "exact": the raw value parsed as a valid SPDX expression verbatim.
 * - "corrected": spdx-correct fixed a sloppy-but-precise value (e.g. "Apache License, Version 2.0"
 *   → Apache-2.0).
 * - "none": genuinely unknown - no license could be determined (expression null, impreciseFamily
 *   absent).
 * - "imprecise": an ambiguous license FAMILY label was observed ("BSD", "BSD License", "Apache
 *   Software License") that carries no clause/version, so it is NOT guessed to a precise SPDX id.
 *   It is present-but-needs-clarify: `expression` stays null because a bare family is not a valid
 *   SPDX expression, and the faithful family string is carried on {@link
 *   LicenseFinding.impreciseFamily}. Distinct from "none" - an imprecise finding IS a license, just
 *   an under-specified one a `[[clarify]]` override can disambiguate.
 */
export type FindingConfidence = "exact" | "corrected" | "none" | "imprecise";

/**
 * Normalized license conclusion for one package. Produced by the normalization layer; provenance is
 * mandatory for auditability.
 */
export interface LicenseFinding {
  /**
   * Full canonical SPDX expression; null = unknown OR imprecise (an imprecise family is not a valid
   * SPDX expression and must never be emitted as one - see {@link FindingConfidence}).
   */
  expression: CanonicalLicense | null;
  /** Elected branch as canonical expression; null = unknown or imprecise. */
  elected: CanonicalLicense | null;
  /**
   * "generator" (exact parse or unknown), "corrected", "registry" (enrichment-appended), "override"
   * (clarify); "curated" reserved.
   */
  source: LicenseClaimSource;
  confidence: FindingConfidence;
  /**
   * The faithful ambiguous family label (e.g. "BSD", "Apache") - present ONLY when confidence is
   * "imprecise". It is what the render layer surfaces and what the policy could-be-copyleft check
   * matches against the literal COULD_BE_COPYLEFT_FAMILIES token set.
   */
  impreciseFamily?: string;
  /**
   * Distinct audit citation for a TOOL-LEVEL builtin override that decided this finding. Present
   * ONLY when a shipped BUILTIN_OVERRIDES entry (not a project [[clarify]]) replaced the finding
   * - e.g. "override:builtin[3]". A project clarify keeps its existing "clarify[i]" citation via
   * the policy engine's clarifyIndexFor lookup, so this field is absent for those. The engine cites
   * this instead of plain "default:ok" so a tool-level disambiguation stays auditable (closes the
   * default:ok-fallthrough gap).
   */
  overrideRule?: string;
  /**
   * A STALE override: an override (project clarify or tool-level builtin) recorded a detection that
   * its source NO LONGER reports. The asserted expression is NOT applied (this finding keeps its
   * un-overridden value); instead the engine emits a loud fail verdict naming the package, the
   * source, the recorded value, and what that source reports now - a stale override must never
   * silently mask a relicense.
   */
  staleOverride?: StaleOverride;
  /**
   * A conflict marker: either a ScanCode-vs-quick-check disagreement (see applyScancodeAssessment)
   * or a cross-image license-claim divergence (see withCrossImageConflict), sharing evaluate.ts's
   * one gate lane. Absent when neither source fires (absent-not-empty for golden stability).
   */
  conflict?: AssessmentConflict;
  /**
   * The PRE-OVERRIDE observed SPDX expression. Set by annotateFindings from the un-overridden base
   * finding BEFORE an override may rewrite `expression`. The deny terminal consults BOTH this
   * observed expression AND the (possibly-overridden) `expression`: if EITHER is denied, deny fires
   * - a denied OBSERVED license can never be licensed back in by any override (deny is terminal
   * over overrides). Absent when no override ran (the un-overridden finding's `expression` already
   * IS the observed value) or when the base finding had no parseable expression.
   */
  observedExpression?: CanonicalLicense;
  /**
   * The SET of EVERY observed per-claim normalized PRECISE expression (deny must see every observed
   * claim, not only the lossy COMBINED expression). Produced by annotateFindings by running
   * normalizeRaw over each license claim and collecting the non-null precise results (deduped,
   * sorted by {@link compareCodeUnits}). Genuinely-unknown and imprecise-family claims contribute
   * nothing (they carry no precise license to deny).
   *
   * WHY: combineKnown elects an imprecise family / collapses to unknown BEFORE a precise
   * non-copyleft DENIED member (BUSL-1.1, Elastic-2.0 - source-available, NOT copyleft) when an
   * imprecise family token ("GPL") or an unknown token co-exists, so the combined `expression` is
   * null/imprecise and the deny terminal - reading only the combined expression - never sees the
   * denied member. The deny terminal also consults THIS set: if ANY observed precise expression is
   * denied, deny fires regardless of how combine rendered the finding (precise / imprecise /
   * unknown), in every scope. Deny stays terminal-0; this only changes what deny CAN SEE, never
   * what combine renders.
   *
   * Absent when no claim normalized to a precise expression (nothing to carry).
   */
  observedExpressions?: readonly CanonicalLicense[];
  /**
   * Surfaced non-normalizable raw claim tokens for a NON-GATING `os`-scope PARTIAL finding. Set
   * ONLY when an os-scope package's claim set mixes ≥1 normalizable SPDX member with ≥1
   * genuinely-unknown ("none") token: the finding is built from the normalizable members (so the
   * KNOWN GPL/BSD obligations are not hidden by the all-or-nothing → unknown rule) AND the
   * remaining unparseable tokens are surfaced here - deduped, sorted by {@link compareCodeUnits},
   * raw-but-trimmed - for review and rendering rather than silently dropped.
   *
   * SAFETY: this is os-scope ONLY. App/dev/prod (gating) scopes keep the strict all-or-nothing →
   * unknown invariant and NEVER carry this field. The surfaced tokens are advisory: they never
   * enter `expression` and never gate the policy verdict (os is non-gating; deny stays terminal
   * over the KNOWN member). Absent for every finding that is not an os-scope partial.
   */
  unrecognizedTokens?: readonly string[];
}

/** A stale-override condition surfaced to the policy engine. */
export interface StaleOverride {
  /** "clarify" (project) or "builtin" (shipped tool-level) - for the message. */
  level: "clarify" | "builtin";
  /** Where the divergence was found: one producing lane, or the observed signal as a whole. */
  source: "registry" | "intensive" | "observed";
  /** What the override recorded for that lane; `false` recorded that the lane detects nothing. */
  expected?: string | false;
  /** What that lane reports now - the relicensed values; empty when it reports nothing. */
  observed: ReadonlyArray<string>;
  /**
   * A reported license the override's expression does not account for; set instead of `expected`.
   */
  unaccounted?: string;
}

/** A ScanCode-vs-quick-check disagreement surfaced to the policy engine. */
export interface ScancodeAssessmentConflict {
  kind: "scancode";
  /**
   * The in-depth assessed value: the ScanCode-elected normalized SPDX expression, or the bare
   * family token when the assessment itself is imprecise.
   */
  assessed: string;
  /**
   * The disagreeing quick-check signal members - normalized where precise, the family token /
   * trimmed raw otherwise - deduped and sorted.
   */
  disagreeing: ReadonlyArray<string>;
}

/**
 * A cross-image license-claim divergence: two or more docker occurrences of the SAME purl declared
 * different license claims.
 */
export interface CrossImageClaimDivergence {
  kind: "cross-image-claims";
  /**
   * Every docker occurrence of this purl, sorted by target. `claims` are that image's own raw
   * declared license strings (deduped, sorted); empty when the image declared no license claim for
   * this purl at all.
   */
  byTarget: ReadonlyArray<{ target: TargetIdentity; claims: readonly string[] }>;
}

/**
 * The two peer conflict sources sharing evaluate.ts's conflict lane and the finding's `conflict`
 * slot.
 */
export type AssessmentConflict = ScancodeAssessmentConflict | CrossImageClaimDivergence;

export type VerdictStatus = "ok" | "warn" | "fail" | "suppressed";

/** One policy decision per (package x occurrence). */
export interface Verdict {
  purl: Purl;
  occurrenceTarget: TargetIdentity;
  status: VerdictStatus;
  /**
   * Machine-readable deciding rule: "compatible[1]", "clarify[0]",
   * "workspace.copyleft_suppressed[0]", "default:copyleft", "default:unknown", "default:imprecise",
   * "default:imprecise-copyleft", "default:agpl-container", "default:ok".
   */
  rule: string;
  reason: string;
}

/** "os" is reserved for Docker image scanning. */
export type ScopeTaxonomy = "app" | "os";

/**
 * The prefix of every docker image occurrence identity ("docker:<source>"). RESERVED for scope:"os"
 * inputs - on a POSIX filesystem a directory can be literally named "docker:whatever", so without
 * the reserved-namespace guard in merge.ts (assertNotReservedIdentity) a crafted workspace path
 * could impersonate a docker image occurrence and inherit `where`-scoped acceptances reviewed for
 * the image layer. Lives on the model hub - every other module imports from here - because the
 * render layer needs it too (Containers section identities), not only merge/pipeline.
 */
export const DOCKER_IDENTITY_PREFIX = "docker:";

/**
 * Segment-aware identity-prefix match: `target` matches `path` only when it IS `path` or sits under
 * it as a whole path segment - "apps/studio-helper" never matches "apps/studio". The one prefix
 * comparison every policy-surface matcher shares (copyleft suppression paths, `[[compatible]]`
 * `where` scopes, target-profile resolution) so a crafted narrower/wider path can never
 * accidentally match the wrong side. `target` is a branded {@link TargetIdentity}; `pattern` stays
 * a plain string, so the two arguments can never be passed swapped - a pattern-vs-pattern overlap
 * uses {@link identityPathsOverlap} instead. Both directions matter: the scope "docker:a" covers
 * every target under it ("docker:a/Dockerfile"), while the scope "docker:a/Dockerfile" never covers
 * the shorter target "docker:a" (the fail-safe direction).
 */
export function matchesIdentityPrefix(target: TargetIdentity, pattern: string): boolean {
  return isSegmentPrefix(target, pattern);
}

/**
 * The shared segment-aware prefix rule behind {@link matchesIdentityPrefix} and {@link
 * identityPathsOverlap} - `value` IS `prefix` or sits under it as a whole path segment. One prefix
 * comparison, never two.
 */
function isSegmentPrefix(value: string, prefix: string): boolean {
  return value === prefix || value.startsWith(prefix + "/");
}

/**
 * Whether two identity PATTERNS overlap as a prefix chain: either one is the other or sits under
 * it. Both sides are policy patterns (a `[[workspace.copyleft_suppressed]]` path, a
 * `[[target.workspace]]` path), so neither is a branded identity - the symmetric peer of {@link
 * matchesIdentityPrefix}, sharing its one {@link isSegmentPrefix} rule.
 */
export function identityPathsOverlap(a: string, b: string): boolean {
  return isSegmentPrefix(a, b) || isSegmentPrefix(b, a);
}

/**
 * Dependency provenance - "why is this dependency here?" - derived per-target at collect time from
 * the lockfile/BOM dependency graph. Introduction is PER-TARGET (per BOM): the same purl can be a
 * direct dependency in one workspace and a transitive one in another, so this rides on the
 * Occurrence, not the package.
 *
 * Two collect-time lanes populate it (the only graphs the research found usable):
 * - npm via yarn-plugin-cyclonedx: the BOM carries a complete root-anchored `dependencies` graph.
 *   `direct`/`introducedBy`/`path` are derived.
 * - python via poetry.lock + pyproject: the lockfile `[package.dependencies]` tables + the declared
 *   roots give `direct`/`introducedBy`/`path`.
 *
 * Every OTHER source (terraform, Docker image packages, bun, any npm BOM lacking a graph) leaves
 * `introduction` ABSENT - the render layer shows an honest " - " rather than a fabricated value.
 *
 * OPTIONALITY IS OUT OF SCOPE: no `optional` field is defined, intentionally. The npm lane never
 * carried optional (the BOM has no optional/peer information); the python lane formerly derived it
 * from poetry markers (`optional = true`, PEP 508 marker variables, extras, multi-variant spec
 * arrays), but that marker parsing was a recurring mislabeling bug class and was removed. Markers
 * and extras are NOT parsed; every dependency edge is a plain edge.
 */
export interface DependencyIntroduction {
  /** True iff the purl is a declared-direct dependency of this target/BOM root. */
  direct: boolean;
  /**
   * Sorted-unique SET of direct-parent purls that pull this package in for this target. A union: a
   * package reached through multiple parents (or a duplicated purl) carries every real introducer
   * here. Empty for a direct dependency.
   */
  introducedBy: readonly Purl[];
  /**
   * Deterministic representative root→component purl chain (one shortest path). Omitted for a
   * direct dependency (the chain would be just the package itself).
   *
   * @privateRemarks
   * BFS with ties broken on the smallest child purl at each level, not
   * whole-path order. A multi-parent package has several real chains:
   * `introducedBy` is complete, `path` is one representative.
   */
  path?: readonly Purl[];
}

/**
 * One consuming target of a package. Dev/prod scope is occurrence-level, not package-level: the
 * same package can legally be a dev dependency in one workspace and a prod dependency in another,
 * and both flags must be recorded independently.
 */
export interface Occurrence {
  /** Target identity, e.g. "apps/scratch". Forward-slash, never backslash. */
  target: TargetIdentity;
  /** Scope of this package in this target (dev in docs, prod in frontend is legal). */
  isDevDependency: boolean;
  /**
   * Dependency provenance for this target - direct-vs-transitive plus the introducer path. Absent
   * when the source carries no usable dependency graph (terraform / Docker OS / bun / graph-less
   * npm), so goldens that predate provenance stay byte-identical where it is absent.
   */
  introduction?: DependencyIntroduction;
}

/**
 * Per-package attribution extracted from CycloneDX evidence at merge time. Holds extracted
 * artifacts only: raw decoded license texts never enter the model - except `verbatimTexts`,
 * retained exclusively for packages with no spdx-id/expression-kind claim, where the verbatim file
 * is the only license statement we have. All stored text is control-character-sanitized at intake.
 */
export interface PackageAttribution {
  /**
   * Concrete copyright lines extracted from evidence texts (deduped, capped at 20, never
   * fabricated).
   */
  copyrightLines: string[];
  /** Decoded NOTICE file contents (Apache section 4(d) input), sanitized verbatim. */
  noticeTexts: string[];
  /**
   * component.author when string-typed - secondary "Author:" attribution, never a copyright claim.
   */
  author?: string;
  /** True when at least one non-NOTICE license file was decoded for this package. */
  hasVerbatimText: boolean;
  /** Decoded license-file texts - only for packages with zero spdx-id/expression claims. */
  verbatimTexts?: string[];
}

export interface PackageEntry {
  /** Dedup key, kept verbatim from the SBOM (URL-encoding like %40 intact). */
  purl: Purl;
  /** Display name including group, e.g. "@ampproject/remapping". */
  name: DependencyName;
  version: DependencyVersion;
  /** Consuming targets with per-occurrence scope, sorted by target. */
  occurrences: Occurrence[];
  licenseClaims: LicenseClaim[];
  scope: ScopeTaxonomy;
  /** Raw generator scope (e.g. cdxgen's unreliable yarn scope), recorded verbatim. */
  rawScope?: string;
  /**
   * Normalized license conclusion - set only by a policy run. Absent without `--policy`, so
   * existing dump-model goldens stay byte-identical.
   */
  finding?: LicenseFinding;
  /**
   * Evidence-derived attribution - set only when the component carried at least one usable evidence
   * entry. Absent (never empty) for evidence-less packages, so existing dump-model and render
   * goldens stay byte-identical.
   */
  attribution?: PackageAttribution;
  /**
   * cross-image license claim divergence for this package
   */
  dockerClaimDivergence?: CrossImageClaimDivergence;
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
 * UTF-16 code-unit comparison - the only string comparator in this tool. The
 * `<`/`>` operators order strings by UTF-16 code unit (not Unicode codepoint;
 * the surrogate-pair edge differs), which is platform-invariant.
 *
 * WHY: locale-aware string comparison (the locale-sensitive compare method on String) is
 * ICU-dependent and produces different orderings across Windows/Linux and across runtimes, silently
 * breaking byte-identity of generated output. Code-unit comparison is platform-invariant and is
 * therefore mandatory tool-wide.
 */
export const compareCodeUnits = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Stable total order over packages: (name, version, purl). */
export function comparePackages(a: PackageEntry, b: PackageEntry): number {
  return (
    compareCodeUnits(a.name, b.name) ||
    compareCodeUnits(a.version, b.version) ||
    compareCodeUnits(a.purl, b.purl)
  );
}

/**
 * The purl TYPE segment - everything between "pkg:" and the first "/". Shared hub helper: the
 * render layer's ecosystem column and the container system-vs-application discriminator (the
 * OS-package allowlist) both key on this exact extraction, so there is one purl-parsing rule, not
 * two.
 */
export function purlEcosystem(purl: string): string {
  const rest = purl.startsWith("pkg:") ? purl.slice(4) : purl;
  const slash = rest.indexOf("/");

  return slash === -1 ? rest : rest.slice(0, slash);
}

/**
 * The display name a purl carries: its namespace and name, percent-decoded and joined with a slash
 * ("pkg:npm/%40acme/ui@0.0.0-use.local" -> "@acme/ui"). Qualifiers and subpaths are dropped.
 *
 * @returns undefined for anything that is not a `pkg:<type>/<name>@<version>` purl.
 *
 * @privateRemarks
 * The composition matches the display name the merge builds from a component's group and name, so
 * the two agree for the ecosystems whose collectors reconstruct a dependency graph. It is a
 * fallback for graph nodes the merged model carries no package for - a first-party workspace member
 * that the merge excluded - where there is no recorded name to prefer.
 */
export function purlDisplayName(purl: string): string | undefined {
  const rest = purl.startsWith("pkg:") ? purl.slice(4) : undefined;
  const slash = rest?.indexOf("/") ?? -1;

  if (rest === undefined || slash === -1) {
    return undefined;
  }

  const nameAtVersion = rest.slice(slash + 1).split(/[?#]/, 1)[0] as string;
  const at = nameAtVersion.lastIndexOf("@");
  const name = at > 0 ? nameAtVersion.slice(0, at) : nameAtVersion;

  if (name === "") {
    return undefined;
  }

  try {
    return name.split("/").map(decodeURIComponent).join("/");
  } catch {
    return name; // a malformed percent escape is kept verbatim rather than dropped
  }
}

/**
 * JSON.stringify replacer that sorts object keys (arrays untouched) by {@link compareCodeUnits}.
 * Exported so the committed enrichment cache shares the exact tool-wide sorted-key serialization
 * contract - there must be one sorter, not two.
 */
export function sortedKeyReplacer(_key: string, value: unknown): unknown {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).sort(([a], [b]) => compareCodeUnits(a, b)),
    );
  }

  return value;
}

/**
 * Deterministic JSON serialization for any on-disk artifact: object keys sorted (arrays untouched),
 * indent 2, trailing newline. JSON.stringify never emits `\r`, so the result is LF-only by
 * construction. The committed enrichment cache reuses this so its bytes follow the identical
 * contract.
 */
export function toSortedJson(value: unknown): string {
  return JSON.stringify(value, sortedKeyReplacer, 2) + "\n";
}

/**
 * Deterministic JSON dump of the canonical model. Delegates to {@link toSortedJson} - same
 * sorted-key/LF/indent-2 bytes. Used by `--dump-model` and golden-file tests.
 */
export function toSortedDependenciesJson(model: CanonicalDependencies): string {
  return toSortedJson(model);
}
