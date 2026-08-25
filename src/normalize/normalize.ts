/**
 * Raw license claim → LicenseFinding with mandatory provenance.
 *
 * Pipeline per claim: raw → exact SPDX parse → spdx-correct fixup → unknown. No substring matching
 * anywhere; correct() never sees already-valid input, so exact generator values are preserved
 * verbatim and only genuinely fixed values carry source "corrected".
 *
 * License strings are third-party-controlled data. Hostile or malformed input degrades to an
 * unknown finding - the run never crashes (skip-don't-throw). The UNLICENSED/SEE-LICENSE-IN guard
 * runs before correct() so "proprietary, do not use" can never be rewritten to the public-domain
 * Unlicense.
 *
 * Pure functions: no I/O, no logging - the CLI owns stderr.
 */
import parse from "spdx-expression-parse";
import correct from "spdx-correct";
import satisfies from "spdx-satisfies";

import {
  asRawLicense,
  compareCodeUnits,
  type CanonicalDependencies,
  type CanonicalLicense,
  type CrossImageClaimDivergence,
  type LicenseClaim,
  type LicenseClaimSource,
  type LicenseFinding,
  type PackageEntry,
  type RawLicense,
  type ScopeTaxonomy,
  type StaleOverride,
} from "../model/dependencies";
import { COULD_BE_COPYLEFT_FAMILIES } from "../policy/engine/copyleftFamily";
import { matchesPackage } from "../policy/engine/match";
import {
  canonicalizeExpression,
  elect,
  isCopyleft,
  leafIds,
  renderNode,
  type ExpressionNode,
} from "./expression";

/**
 * Raw values that must never reach correct(): npm's "UNLICENSED" means proprietary (correct() maps
 * it to public-domain "Unlicense"), and "SEE LICENSE IN <file>" is a pointer, not a license.
 */
const NEVER_CORRECT = [/^UNLICENSED$/i, /^SEE LICEN[CS]E IN /i];

/**
 * Ambiguous license FAMILY labels: a bare family with no clause count or version that spdx-correct
 * would otherwise GUESS to a precise variant (correct("BSD")/correct("BSD License") → BSD-2-Clause;
 * correct("Apache Software License")/correct("Apache") → Apache-2.0). We intercept these BEFORE
 * correct() and represent them faithfully as the imprecise family, never the guess. The key is the
 * case-folded trimmed raw; the value is the family token carried on the finding.
 *
 * Small, reviewable, literal - the copyleft.ts / trove.ts idiom. Labels that carry a version
 * ("Apache License, Version 2.0") are deliberately ABSENT: their spdx-correct result (Apache-2.0)
 * is precise and correct, not a guess.
 */
const AMBIGUOUS_FAMILY: ReadonlyMap<string, string> = new Map([
  ["bsd", "BSD"],
  ["bsd license", "BSD"],
  ["apache", "Apache"],
  ["apache software license", "Apache"],
  // Bare GNU-family labels: correct() GUESSES these to a precise variant (correct("GPL") →
  // GPL-3.0-or-later) - a confident-but-wrong copyleft id. Represented faithfully as the imprecise
  // family so the policy engine routes them to the could-be-copyleft review lane
  // (COULD_BE_COPYLEFT_FAMILIES) rather than a fabricated copyleft fail.
  ["gpl", "GPL"],
  ["gpl license", "GPL"],
  ["agpl", "AGPL"],
  ["agpl license", "AGPL"],
  ["lgpl", "LGPL"],
  ["lgpl license", "LGPL"],
  // Spelled-out GNU family names, both spellings: all carry no version, and correct() guesses a
  // precise id from every one - including a family FLIP for the British "GNU Lesser General Public
  // Licence" (→ GPL-3.0-or-later, dropping "Lesser"). Real Maven POMs carry exactly these labels.
  ["gnu general public license", "GPL"],
  ["gnu general public licence", "GPL"],
  ["gnu lesser general public license", "LGPL"],
  ["gnu lesser general public licence", "LGPL"],
  ["gnu affero general public license", "AGPL"],
  ["gnu affero general public licence", "AGPL"],
  // Bare EUPL: EUPL is STRONG copyleft, but spdx-correct cross-maps the bare label to the
  // PERMISSIVE "UPL-1.0" (Universal Permissive License) - a copyleft→permissive mis-guess that
  // would silently pass the gate (default:ok). Intercept it as the imprecise copyleft family so it
  // routes to the could-be-copyleft review lane (COULD_BE_COPYLEFT_FAMILIES). Verified the ONLY
  // copyleft family correct() crosses to a permissive id: MPL/CDDL/SSPL/Sleepycat/QPL/MS-RL/CPAL
  // stay copyleft (precise path), OSL/CeCILL/EPL/CC-BY-SA/GFDL/RPL/APSL correct() to null (unknown,
  // gated).
  ["eupl", "EUPL"],
  ["eupl license", "EUPL"],
]);

/**
 * Precise label fixups spdx-correct MISSES (correct() returns null) that ARE unambiguously
 * resolvable to a single SPDX id - the "ISC license"/"ISC License" suffix false-negative that
 * dropped pexpect to unknown (bare "ISC"
 * already parses). Keyed by case-folded trimmed raw. Kept tiny and reviewable;
 * adding a family-ambiguous label here would re-introduce a false guess, so only unambiguous
 * single-id labels belong.
 */
const PRECISE_LABEL_FIXUP: ReadonlyMap<string, string> = new Map([
  ["isc license", "ISC"],
  // MySQL's standard license label: it states BOTH the version (v2) and the exception, and each has
  // an exact SPDX spelling - correct() instead resolved the label to GPL-3.0-or-later,
  // contradicting the stated v2 and dropping the exception clause.
  [
    "the gnu general public license, v2 with universal foss exception, v1.0",
    "GPL-2.0-only WITH Universal-FOSS-exception-1.0",
  ],
]);

/**
 * Debian/DEP-5 copyright SHORT-NAME → canonical SPDX id.
 *
 * syft fills ~98% of OS-package licenses, but Debian's machine-readable copyright (DEP-5) declares
 * licenses with copyright SHORTHANDS - "Expat" for MIT, "GPL-2+" for GPL-2.0-or-later,
 * "BSD-3-clause" for BSD-3-Clause - that are NOT valid SPDX ids. Those tokens fail the exact
 * `parse()` and reach spdx-correct, whose FUZZY matcher then either drops them to unknown OR
 * produces a CONFIDENTLY-WRONG guess (verified 2026-06-16 against spdx-correct:
 * correct("GPL-2+") → "GPL-2.0-only", silently dropping the `+`/or-later;
 * correct("GPL-3") → "GPL-3.0-or-later", the wrong clause). This authoritative map intercepts the
 * WELL-KNOWN UNAMBIGUOUS DEP-5 shorthands BEFORE correct() can see them, mapping each to the
 * precise SPDX id Debian actually means.
 *
 * The copyleftFamily.ts / copyleft.ts literal-reviewable-data idiom: a small, enumerated,
 * test-asserted map - never a runtime prefix/fuzzy inference. Every VALUE is validated against
 * spdx-license-ids in the tests, so a typo'd target cannot silently re-create the unknown it is
 * meant to resolve.
 *
 * Keys are CASE-FOLDED exact shorthand tokens (Debian is inconsistent - "BSD-3-clause" vs
 * "BSD-3-Clause"); matching is EXACT-token only, NEVER substring (a custom name like
 * "BSD-3-clause-Berkeley" or "LGPL-2.1+-with-link-exception" must NOT match - it stays on the
 * correct() path / unknown). The keys are deliberately VERSIONED ("gpl-2", "gpl-3"): bare
 * "GPL"/"LGPL"/"AGPL" are ABSENT so they still route to the could-be-copyleft imprecise family lane
 * (AMBIGUOUS_FAMILY) - a bare "GPL" could be any GPL variant and must never be guessed to a precise
 * id here.
 *
 * Genuinely-unknown Debian tokens (custom / public-domain with no SPDX id / sha256-hash fallbacks /
 * "BSD-like" / per-package custom short names) are DELIBERATELY ABSENT - they stay unknown. The
 * conservative all-or-nothing unknown invariant is preserved: only cleanly-mappable shorthands lift
 * a row.
 */
const DEBIAN_SHORTHAND: ReadonlyMap<string, string> = new Map([
  ["expat", "MIT"], // Debian's name for the MIT/Expat license
  ["mit/x11", "MIT"], // ncurses' DEP-5 "MIT/X11" Debian-ism
  ["gpl-2", "GPL-2.0-only"],
  ["gpl-2+", "GPL-2.0-or-later"],
  ["gpl-3", "GPL-3.0-only"],
  ["gpl-3+", "GPL-3.0-or-later"],
  ["lgpl-2", "LGPL-2.0-only"],
  ["lgpl-2+", "LGPL-2.0-or-later"],
  ["lgpl-2.1", "LGPL-2.1-only"],
  ["lgpl-2.1+", "LGPL-2.1-or-later"],
  ["lgpl-3", "LGPL-3.0-only"],
  ["lgpl-3+", "LGPL-3.0-or-later"],
  ["bsd-2-clause", "BSD-2-Clause"],
  ["bsd-3-clause", "BSD-3-Clause"],
]);

/**
 * Bare SPDX CONNECTIVE tokens. syft tokenizes a compound license ("GPL-2.0-only AND MIT") into
 * SEPARATE component license entries - INCLUDING the bare connective words "AND"/"OR"/"WITH". Those
 * are SYNTAX artifacts, not licenses: they neither normalize nor identify anything, so they must be
 * dropped before claim processing (never an unrecognized token, never forcing the all-or-nothing
 * unknown collapse). Case-insensitive, exact-token only (a real license like "AND-1.0"
 * - hypothetical - would not be a bare "AND"). (Full OR/AND expression RECONSTRUCTION is out of
 * scope; we only drop the bare connectives so they stop polluting the OS render.)
 */
const SPDX_CONNECTIVES: ReadonlySet<string> = new Set(["and", "or", "with"]);

/** True when a raw claim is a bare connective syntax artifact. */
function isBareConnective(raw: string): boolean {
  return SPDX_CONNECTIVES.has(raw.trim().toLowerCase());
}

/**
 * True when a comma-bearing raw value is a list of licenses - every comma-separated part is
 * independently license-like (parses or corrects). Such lists must never reach correct():
 * correct("MIT,Apache-2.0") returns "Apache-2.0", silently dropping MIT. A comma inside a single
 * license name ("Apache License, Version 2.0") is not a list - its parts ("Version 2.0") are not
 * license-like - and stays correctable.
 */
function isCommaLicenseList(value: string): boolean {
  if (!value.includes(",")) {
    return false;
  }

  return value.split(",").every((part) => {
    const candidate = part.trim();

    if (candidate === "") {
      return false;
    }

    try {
      parse(candidate);
      return true;
    } catch {
      /* not an exact id/expression - try correction */
    }

    return correct(candidate) !== null;
  });
}

/**
 * Result of normalizing one raw license string. An imprecise result carries `imprecise: true` +
 * `impreciseFamily` with `expression` null: an ambiguous family label is present-but-imprecise,
 * never a guessed precise id and never silently unknown.
 */
export interface NormalizeResult {
  expression: CanonicalLicense | null;
  source: "generator" | "corrected";
  imprecise?: true;
  impreciseFamily?: string;
}

/**
 * Normalize one raw license string: exact parse first, an imprecise-family intercept, a
 * precise-label fixup for the cases correct() misses, then
 * a guarded spdx-correct fixup, else unknown. Comma lists are never correctable;
 * `[[clarify]]` is the escape hatch.
 *
 * Every non-null result is CANONICAL: the resolved text flows through {@link
 * canonicalizeExpression} before it leaves, so there is no intermediate verbatim-normalized state
 * - a compound claim exits flattened/deduped/absorbed/sorted, a single id verbatim. Callers
 * therefore receive the single resolved-and-canonical license state directly.
 */
export function normalizeRaw(raw: RawLicense): NormalizeResult {
  const trimmed = raw.trim();

  if (trimmed === "" || NEVER_CORRECT.some((re) => re.test(trimmed))) {
    return { expression: null, source: "generator" }; // unknown
  }

  try {
    parse(trimmed);
    return { expression: canonicalizeExpression(asRawLicense(trimmed)), source: "generator" }; // exact
  } catch {
    /* fall through */
  }

  const folded = trimmed.toLowerCase();
  // Intercept an ambiguous family label BEFORE correct() can fabricate a clause count.
  // Present-but-imprecise - never the guess, never unknown.
  const family = AMBIGUOUS_FAMILY.get(folded);

  if (family !== undefined) {
    return {
      expression: null,
      source: "generator",
      imprecise: true,
      impreciseFamily: family,
    };
  }

  // Unambiguous label correct() misses (e.g. "ISC license" → ISC).
  const fixup = PRECISE_LABEL_FIXUP.get(folded);

  if (fixup !== undefined) {
    return { expression: canonicalizeExpression(asRawLicense(fixup)), source: "corrected" };
  }

  // Debian/DEP-5 copyright shorthands → canonical SPDX. MUST run BEFORE correct(): correct() either
  // drops these to unknown or mis-guesses them (e.g. "GPL-2+" → "GPL-2.0-only", dropping the
  // or-later). Exact-token only,
  // case-folded; bare GPL/LGPL/AGPL already returned above via AMBIGUOUS_FAMILY.
  const debian = DEBIAN_SHORTHAND.get(folded);

  if (debian !== undefined) {
    return { expression: canonicalizeExpression(asRawLicense(debian)), source: "corrected" };
  }

  if (isCommaLicenseList(trimmed)) {
    return { expression: null, source: "generator" }; // unknown
  }

  const fixed = correct(trimmed); // never throws on non-empty input

  if (fixed !== null) {
    try {
      parse(fixed); // belt-and-braces: corrected output must parse
      return { expression: canonicalizeExpression(asRawLicense(fixed)), source: "corrected" };
    } catch {
      /* corrected output unparseable - treat as unknown */
    }
  }

  return { expression: null, source: "generator" }; // unknown
}

const UNKNOWN_FINDING: LicenseFinding = {
  expression: null,
  elected: null,
  source: "generator",
  confidence: "none",
};

/**
 * Combine a package's claims into one finding. Claims are deduped by (kind, raw) - duplicates
 * within one component's licenses[] array (e.g. ["MIT","MIT"]) must not become "MIT AND MIT".
 * Distinct normalized expressions AND-combine (conservative: all asserted obligations apply); any
 * non-normalizable claim makes the whole finding unknown - partial knowledge must not hide an
 * obligation.
 *
 * SCOPE-AWARE EXCEPTION: for the NON-GATING `os` scope ONLY, a claim set that mixes ≥1 normalizable
 * SPDX member with ≥1 genuinely-unknown ("none") token is NOT forced to unknown. Instead the
 * finding is built from the normalizable members and the unparseable tokens are surfaced on
 * `unrecognizedTokens` for review/rendering - the known GPL/BSD obligation is shown rather than
 * hidden, and the os scope is non-gating so this is safe. Every NON-os scope keeps the strict
 * all-or-nothing → unknown invariant.
 */
function findingFromClaims(
  claims: ReadonlyArray<LicenseClaim>,
  scope: ScopeTaxonomy = "app",
): LicenseFinding {
  const seen = new Set<string>();
  const distinct: LicenseClaim[] = [];

  for (const c of claims) {
    // Drop bare connective syntax artifacts ("AND"/"OR"/"WITH") - they are syft compound-license
    // tokenization noise, never a license claim.
    if (isBareConnective(c.raw)) {
      continue;
    }

    const key = `${c.kind}\0${c.raw}`; // NUL-joined: no concatenation ambiguity

    if (!seen.has(key)) {
      seen.add(key);
      distinct.push(c);
    }
  }

  if (distinct.length === 0) {
    return UNKNOWN_FINDING;
  }

  const results = distinct.map((c) => normalizeRaw(c.raw));
  // A genuinely-unknown claim is expression null AND not imprecise (an imprecise family is its own
  // present-but-needs-clarify lane, never an "unrecognized token"). Pair each genuinely-unknown
  // result with its trimmed raw so the os-partial path can surface the faithful token.
  const unknownTokens = distinct
    .map((c, i) => ({ raw: c.raw.trim(), result: results[i]! }))
    .filter(({ result }) => result.expression === null && result.imprecise !== true)
    .map(({ raw }) => raw)
    .filter((raw) => raw !== "");

  if (unknownTokens.length > 0) {
    const hasNormalizable = results.some((r) => r.expression !== null);
    const hasImprecise = results.some((r) => r.imprecise === true);

    // os-scope partial: build the KNOWN signal (precise OR imprecise) and surface the rest.
    // Requires ≥1 KNOWN member - a precise license OR an imprecise copyleft/permissive family, so
    // the could-be-copyleft review hint survives rather than flattening to plain unknown. An os
    // package with ZERO known members (only public-domain/custom/hash) stays unknown (nothing to
    // stand on) - exactly the app-scope behavior.
    if (scope === "os" && (hasNormalizable || hasImprecise)) {
      const surfaced = [...new Set(unknownTokens)].sort(compareCodeUnits);

      return { ...combineKnown(results), unrecognizedTokens: surfaced };
    }

    // Every non-os scope (and os with zero known members): conservative all-or-nothing - a
    // genuinely-unknown claim makes the whole finding unknown so partial knowledge can never hide
    // an obligation.
    return UNKNOWN_FINDING;
  }

  return combineKnown(results);
}

/**
 * Combine the KNOWN (normalizable + imprecise) signal of a result set into one finding, applying
 * copyleft dominance. Genuinely-unknown results (expression null AND not imprecise) are inert here
 * - they are filtered out of `preciseResults` and ignored by electImpreciseFamily - so this is safe
 * to call with a result set that still contains the os-partial surfaced tokens.
 *
 * A copyleft signal - precise OR imprecise - must dominate a permissive sibling, never be discarded
 * by a "first imprecise wins" short-circuit (which downgraded a hard copyleft gate to a non-gating
 * warn and made the could-be-copyleft lane claim-order-dependent):
 *   1. If a PRECISE copyleft id is present, AND-combine ALL precise claims into a copyleft finding
 *      (the precise copyleft survives; permissive imprecise siblings are dropped - they cannot
 *      weaken a known copyleft obligation).
 *   2. Else if any imprecise family is present, the finding is imprecise - preferring a
 *      COULD_BE_COPYLEFT family over a permissive one regardless of claim order, so the
 *      could-be-copyleft review lane is reached order-independently.
 *   3. Else AND-combine the (all-permissive) precise claims.
 */
function combineKnown(results: ReadonlyArray<NormalizeResult>): LicenseFinding {
  const preciseExpressions = results
    .map((r) => r.expression)
    .filter((expression): expression is CanonicalLicense => expression !== null);
  const anyCorrected = results.some((r) => r.expression !== null && r.source === "corrected");
  const hasPreciseCopyleft = preciseExpressions.some(expressionIsCopyleft);

  if (hasPreciseCopyleft) {
    return combinePrecise(preciseExpressions, anyCorrected);
  }

  const impreciseFamily = electImpreciseFamily(results);

  if (impreciseFamily !== undefined) {
    return {
      expression: null,
      elected: null,
      source: "generator",
      confidence: "imprecise",
      impreciseFamily,
    };
  }

  return combinePrecise(preciseExpressions, anyCorrected);
}

/** True if a parseable SPDX expression elects a copyleft branch (defensive). */
function expressionIsCopyleft(expression: CanonicalLicense): boolean {
  try {
    return isCopyleft(elect(parse(expression) as ExpressionNode));
  } catch {
    return false;
  }
}

/**
 * Pick the dominant imprecise family across results: a COULD_BE_COPYLEFT family (GPL/AGPL/LGPL)
 * wins over a permissive one regardless of claim order, so two conflicting imprecise families route
 * to the could-be-copyleft review lane deterministically. Returns undefined when no imprecise
 * family is present.
 */
function electImpreciseFamily(results: ReadonlyArray<NormalizeResult>): string | undefined {
  let permissive: string | undefined;

  for (const r of results) {
    if (r.imprecise !== true || r.impreciseFamily === undefined) {
      continue;
    }

    if (COULD_BE_COPYLEFT_FAMILIES.has(r.impreciseFamily)) {
      return r.impreciseFamily; // copyleft family dominates
    }

    permissive ??= r.impreciseFamily;
  }

  return permissive;
}

/**
 * The elected branch of a canonical node, rendered and re-minted through {@link
 * canonicalizeExpression} - the sole CanonicalLicense mint - so `elected` carries the same resolved
 * canonical state as `expression`. Idempotent on an already-canonical rendering.
 */
function electedOf(node: ExpressionNode): CanonicalLicense {
  return canonicalizeExpression(asRawLicense(renderNode(elect(node))));
}

/** AND-combine the precise (already-canonical) claim expressions into one finding. */
function combinePrecise(
  preciseExpressions: ReadonlyArray<CanonicalLicense>,
  anyCorrected: boolean,
): LicenseFinding {
  // Dedupe expressions: an spdx-id claim and a name claim may normalize to the same expression.
  const expressions = [...new Set(preciseExpressions)];

  let node = parse(expressions[0]!) as ExpressionNode;

  if (expressions.length > 1) {
    for (const next of expressions.slice(1)) {
      node = {
        left: node,
        conjunction: "and",
        right: parse(next) as ExpressionNode,
      };
    }
  }

  // Canonicalize the combined expression HERE, at formation, so finding.expression is a MODEL
  // invariant rather than a property of which claims happened to combine - never distribute, per
  // canonicalizeExpression's own contract: idempotent, round-trip safe, conservative
  // (flatten/dedupe/absorb/sort only). Each claim expression is already canonical; the AND-join of
  // several is re-canonicalized so the combined form is flattened/sorted too. `elected` is
  // re-derived from the CANONICAL node so it never names a branch an absorption dissolved out of
  // `expression`.
  const expression = canonicalizeExpression(asRawLicense(renderNode(node)));
  const canonicalNode = parse(expression) as ExpressionNode;

  return {
    expression,
    elected: electedOf(canonicalNode),
    source: anyCorrected ? "corrected" : "generator",
    confidence: anyCorrected ? "corrected" : "exact",
  };
}

/**
 * What each producing lane reported for a package, as an override records it. The counterpart of
 * {@link ObservedSignal}: the two name the same lanes, and an override applies only while each lane
 * it records still reports what is written here.
 */
export interface DetectedSignal {
  /**
   * The collector metadata and registry enrichment lane; `false` records that it reports nothing.
   */
  registry?: string | false;
  /** The intensive source scan; `false` records that it reports nothing. */
  intensive?: string | false;
}

/**
 * Inline structural type for project clarify rules - no import from policy/ (the validated policy
 * is structurally compatible). `expression` is a canonical SPDX expression: the policy schema
 * validates and canonicalizes it eagerly before evaluation. `detected` is the staleness
 * precondition; the selector is the same one {@link matchesPackage} reads everywhere else.
 */
export interface ClarifyInput {
  name?: string;
  pattern?: string;
  version?: string | readonly string[];
  detected: DetectedSignal;
  expression: CanonicalLicense;
}

/**
 * The shipped TOOL-LEVEL override set's input shape, structurally compatible with
 * BUILTIN_OVERRIDES. Identical to a project clarify entry by design: the shipped defaults and a
 * consumer's own entries run through one preconditioned-override mechanism, not two.
 */
export type BuiltinOverrideInput = ClarifyInput;

export interface AnnotatedFindings {
  model: CanonicalDependencies;
  usedClarifyIndices: ReadonlySet<number>;
}

/**
 * The lanes a license claim can come from. The registry lane is the quick answer: what the
 * collector read from package metadata, plus what registry enrichment added. The intensive lane is
 * the source scan. The reserved claim sources sit in neither lane and surface only in the union.
 */
const REGISTRY_CLAIM_SOURCES: ReadonlySet<LicenseClaimSource> = new Set(["generator", "registry"]);

const INTENSIVE_CLAIM_SOURCES: ReadonlySet<LicenseClaimSource> = new Set(["scancode"]);

/** A package's PRE-OVERRIDE observed signal, per producing lane and as a whole. */
export interface ObservedSignal {
  /** Members the collector metadata and registry enrichment produced. */
  registry: readonly string[];
  /** Members the intensive source scan produced. */
  intensive: readonly string[];
  /** Every member, whichever lane produced it. */
  union: readonly string[];
}

/** Trimmed, non-empty raw claim values, in claim order. */
function rawSignalValues(claims: ReadonlyArray<LicenseClaim>): string[] {
  return claims.map((c) => c.raw.trim()).filter((raw) => raw !== "");
}

/** True when this claim on its own normalizes to the family token the finding carries. */
function yieldsFamily(claim: LicenseClaim, family: string): boolean {
  const result = normalizeRaw(claim.raw);

  return result.imprecise === true && result.impreciseFamily === family;
}

/** One lane's view: its own claims, plus the family token when a claim of that lane yields it. */
function laneSignal(
  claims: ReadonlyArray<LicenseClaim>,
  sources: ReadonlySet<LicenseClaimSource>,
  family: string | undefined,
): string[] {
  const lane = claims.filter((c) => sources.has(c.source));
  const signal = new Set(rawSignalValues(lane));

  if (family !== undefined && lane.some((c) => yieldsFamily(c, family))) {
    signal.add(family);
  }

  return [...signal];
}

/**
 * The set of normalized raw claim strings (each claim's trimmed raw value) UNION the un-overridden
 * finding's impreciseFamily token, split by the lane that produced each member. Each recorded
 * detection is compared against the lane view that would produce it; the UNION carries the members
 * no lane owns, and is what the fail-closed guard sweeps.
 */
export function observedSignalBySource(
  claims: ReadonlyArray<LicenseClaim>,
  baseFinding: LicenseFinding,
): ObservedSignal {
  const family = baseFinding.impreciseFamily;
  const union = new Set(rawSignalValues(claims));

  if (family !== undefined) {
    union.add(family);
  }

  return {
    registry: laneSignal(claims, REGISTRY_CLAIM_SOURCES, family),
    intensive: laneSignal(claims, INTENSIVE_CLAIM_SOURCES, family),
    union: [...union],
  };
}

/**
 * Every observed per-claim normalized PRECISE expression. Runs normalizeRaw over each claim and
 * collects the non-null precise results, deduped and sorted by compareCodeUnits. Genuinely-unknown
 * and imprecise-family claims contribute nothing (no precise license to deny). The deny terminal
 * consults this set so a denied member is seen even when combineKnown elects an imprecise family /
 * collapses to unknown and drops it from the combined expression. Empty → caller omits the field.
 */
function observedExpressions(claims: ReadonlyArray<LicenseClaim>): readonly CanonicalLicense[] {
  const seen = new Set<CanonicalLicense>();

  for (const c of claims) {
    const precise = normalizeRaw(c.raw).expression;

    if (precise !== null) {
      seen.add(precise);
    }
  }

  return [...seen].sort(compareCodeUnits);
}

/** Case-insensitive, trimmed equality of a recorded value against any signal member. */
function signalMatches(signal: ReadonlyArray<string>, recorded: string): boolean {
  const want = recorded.trim().toLowerCase();

  return signal.some((s) => s.trim().toLowerCase() === want);
}

/**
 * {@link signalMatches}, canonicalized first: the recorded value and each signal member run through
 * {@link canonicalizeExpression} before the same case-insensitive, trimmed equality, so a
 * boolean-algebra re-spelling of the same license set (`MIT AND CC0-1.0` read back as `CC0-1.0 AND
 * MIT`, a duplicated conjunct, an absorbable branch) never counts as a divergence. Canonicalization
 * runs FIRST because it is the coarser, structural normalization; layering it under trim/lowercase
 * keeps the text normalization doing its job unchanged - canonicalizeExpression's contract returns
 * unparseable input verbatim, so a non-expression claim reaches signalMatches's own comparison as
 * it would have anyway.
 */
function signalMatchesCanonical(signal: ReadonlyArray<string>, recorded: string): boolean {
  return signalMatches(
    signal.map((s) => canonicalizeExpression(asRawLicense(s))),
    canonicalizeExpression(asRawLicense(recorded)),
  );
}

/**
 * Fail-closed staleness guard: the first member of the observed signal that is not itself recorded
 * in `detected` and carries a PRECISE license the asserted `expression` does not account for, or
 * undefined when none does.
 *
 * Matching the recorded detections alone is fail-OPEN - a lingering obsolete label (`BSD`) sitting
 * beside a co-present new precise copyleft claim (`GPL-3.0-only`) would license the copyleft out
 * during a relicense, the exact masking this guard exists to prevent. The sweep runs over the UNION
 * signal so a claim source that belongs to neither lane is covered too, and skips the recorded
 * values under the same canonicalization the lane checks use, so a re-spelling of a recorded value
 * is not swept as if it were something new.
 *
 * Each swept member is re-derived through the normalizer. A precise one the assertion does not
 * account for makes the override stale. So does an IMPRECISE one whose family the entry never
 * recorded and the assertion is no part of: a bare `AGPL` appended beside a still-matching recorded
 * `MIT` names an obligation the assertion answers for nowhere, and sweeping past it is how an
 * appended copyleft gets absorbed. Recording the family is what tells the two apart - a recorded
 * `BSD` label upgraded by an assertion of `BSD-3-Clause` is the ordinary disambiguation, passed
 * over by the family check exactly as it is by the recorded-value check above. A member the
 * normalizer reads as no license AND no family - a proprietary/UNLICENSED marker, or any other
 * genuinely-unknown claim - is unaccounted too: it is not one of the recorded values, and it names
 * an obligation a permissive assertion answers for nowhere, so licensing it out would mask exactly
 * the kind of claim the base combiner poisons the whole finding to unknown on.
 */
function unaccountedMember(
  signal: ReadonlyArray<string>,
  recorded: ReadonlyArray<string>,
  expression: CanonicalLicense,
): string | undefined {
  const fold = (value: string): string =>
    canonicalizeExpression(asRawLicense(value)).trim().toLowerCase();
  const wanted = new Set(recorded.map(fold));

  for (const member of signal) {
    if (wanted.has(fold(member))) {
      continue;
    }

    const read = normalizeRaw(asRawLicense(member));

    if (read.expression === null) {
      const family = read.impreciseFamily;

      // No family at all: a proprietary/UNLICENSED marker or other genuinely-unknown claim not
      // recorded in `detected`. It contradicts a permissive assertion - fail closed.
      if (family === undefined) {
        return member;
      }

      // A family label is accounted only when the entry recorded that family or the assertion falls
      // within it; otherwise the appended family obligation is unaccounted.
      if (!wanted.has(fold(family)) && !expressionInFamily(expression, family)) {
        return member;
      }

      continue;
    }

    if (!accountsFor(expression, read.expression)) {
      return member;
    }
  }

  return undefined;
}

/**
 * True when the asserted expression accounts for an observed precise license.
 *
 * spdx-satisfies answers this directly whenever the assertion can be an allowlist entry. An
 * assertion carrying an AND cannot be one, so its conjuncts are compared as ids instead: `MIT AND
 * CC-BY-3.0` accounts for an observed `MIT` while a `GPL-3.0-only` that appeared beside it is still
 * unaccounted for. Any throw leaves the license unaccounted for - fail closed.
 */
export function accountsFor(expression: string, precise: string): boolean {
  try {
    return satisfies(precise, [expression]);
  } catch {
    /* an AND assertion cannot be an allowlist entry - compare its conjuncts below */
  }

  try {
    const asserted = new Set(leafIds(parse(expression) as ExpressionNode).ids);

    return leafIds(parse(precise) as ExpressionNode).ids.every((id) => asserted.has(id));
  } catch {
    return false; // unparseable against the assertion → fail closed
  }
}

/**
 * True when the un-overridden finding ALREADY carries a precise expression that SATISFIES the
 * asserted override expression (the redundancy path). When the registry upgrades an imprecise label
 * to the exact precise license the override asserts (PyPI now reports ipython/ipykernel/
 * jupyter-core as the precise "BSD-3-Clause" a recorded "BSD" was disambiguating TO), the override
 * has nothing to do: the observed precise finding already satisfies the assertion, so it is
 * REDUNDANT - not stale, not applied - and the observed finding stands unchanged. This is
 * fail-safe: a base that does NOT satisfy the assertion (a real relicense to MIT/GPL) is NOT
 * redundant and falls through to the stale-fail path. spdx-satisfies is defensive - any throw is
 * treated as NOT satisfying (fail closed).
 */
function baseSatisfiesAssertion(base: LicenseFinding, expression: string): boolean {
  if (base.expression === null) {
    return false;
  } // imprecise/unknown: not redundant

  try {
    return satisfies(base.expression, [expression]);
  } catch {
    return false; // unparseable against the assertion → not redundant, fail closed
  }
}

/** Build the override finding from a validated canonical SPDX expression. */
function overrideFinding(
  expression: CanonicalLicense,
  overrideRule: string | undefined,
): LicenseFinding {
  const node = parse(expression) as ExpressionNode;

  return {
    expression,
    elected: electedOf(node),
    source: "override",
    confidence: "exact",
    ...(overrideRule !== undefined ? { overrideRule } : {}),
  };
}

/** Attach a stale-override marker to the un-overridden finding. */
function withStaleOverride(base: LicenseFinding, stale: StaleOverride): LicenseFinding {
  return { ...base, staleOverride: stale };
}

/** The lanes an override records, checked in this order so a reported divergence is stable. */
export const DETECTED_LANES = ["registry", "intensive"] as const;

/** The recorded detections, for the guard that sweeps everything the entry did NOT write down. */
function recordedValues(detected: DetectedSignal): string[] {
  return DETECTED_LANES.map((lane) => detected[lane]).filter(
    (value): value is string => typeof value === "string",
  );
}

/**
 * The first recorded lane that no longer reports what the override wrote down, or undefined when
 * every one of them still does.
 *
 * A recorded value holds while that lane - and only that lane - still carries it, compared through
 * {@link signalMatchesCanonical} so a boolean-algebra re-spelling of the same license set is not a
 * divergence. A recorded `false` holds only while the lane reports nothing, and a lane that reports
 * nothing can never satisfy a recorded value: an override whose evidence has disappeared is stale,
 * never a vacuous match.
 */
function firstUnmetDetection(
  detected: DetectedSignal,
  signal: ObservedSignal,
): Omit<StaleOverride, "level"> | undefined {
  for (const source of DETECTED_LANES) {
    const expected = detected[source];

    if (expected === undefined) {
      continue;
    }

    const observed = signal[source];
    const met =
      expected === false ? observed.length === 0 : signalMatchesCanonical(observed, expected);

    if (!met) {
      return { source, expected, observed };
    }
  }

  return undefined;
}

/** Where in the observed signal an unaccounted license was reported, for the stale message. */
function laneOf(member: string, signal: ObservedSignal): StaleOverride["source"] {
  if (signalMatches(signal.registry, member)) {
    return "registry";
  }

  return signalMatches(signal.intensive, member) ? "intensive" : "observed";
}

/**
 * Apply one preconditioned override to a package, given its un-overridden finding and observed
 * signal. Returns the override finding when the precondition holds, the UNCHANGED base finding when
 * the override has become redundant, and a stale-marked finding otherwise.
 *
 * The decision on the observed signal S and the asserted expression E:
 *
 *   IF every recorded detection still holds ({@link firstUnmetDetection}):
 *     IF S carries a precise license E does not account for ({@link unaccountedMember})
 *        → STALE → fail closed [the relicense-metadata-lag mask].
 *     ELSE → APPLY E [normal disambiguation].
 *   ELSE (a recorded detection diverged):
 *     IF a recorded VALUE diverged and the observed finding already carries a precise expression
 *        that SATISFIES E → REDUNDANT: do NOT apply, do NOT fail - let the precise observed finding
 *        stand unchanged [the source upgraded its imprecise label to the exact license the override
 *        asserts, so there is nothing left to disambiguate].
 *     ELSE → STALE → fail closed [genuine drift: relicensed to a different or non-satisfying
 *        license, or still ambiguous-but-different].
 *
 * A recorded `false` proven wrong is always STALE, never redundant: the override asserted that a
 * source says nothing, and a source that has started speaking is new evidence a person must read,
 * whether or not it happens to agree.
 *
 * Fail-safe: the only non-failing path on a divergence is the co-equal/satisfying precise
 * observation. A relicense to anything that does not satisfy E still fails.
 */
function applyOverride(
  detected: DetectedSignal,
  expression: CanonicalLicense,
  overrideRule: string | undefined,
  level: StaleOverride["level"],
  base: LicenseFinding,
  signal: ObservedSignal,
): LicenseFinding {
  const unmet = firstUnmetDetection(detected, signal);

  if (unmet === undefined) {
    const unaccounted = unaccountedMember(signal.union, recordedValues(detected), expression);

    if (unaccounted === undefined) {
      return overrideFinding(expression, overrideRule);
    }

    return withStaleOverride(base, {
      level,
      source: laneOf(unaccounted, signal),
      observed: signal.union,
      unaccounted,
    });
  }

  if (unmet.expected !== false && baseSatisfiesAssertion(base, expression)) {
    return base;
  }

  return withStaleOverride(base, { level, ...unmet });
}

/** First override (project clarify, then tool-level builtin) for a package, and what it decided. */
interface ResolvedOverride {
  finding: LicenseFinding;
  /** True when the deciding entry recorded the intensive lane, either as a value or as `false`. */
  coversIntensive: boolean;
}

function resolveOverride(
  entry: PackageEntry,
  clarify: ReadonlyArray<ClarifyInput>,
  builtins: ReadonlyArray<BuiltinOverrideInput>,
  base: LicenseFinding,
  signal: ObservedSignal,
  usedClarifyIndices: Set<number>,
): ResolvedOverride | undefined {
  // Project clarify FIRST (project-wins-on-conflict).
  const clarifyIndex = clarify.findIndex((rule) => matchesPackage(rule, entry));

  if (clarifyIndex !== -1) {
    usedClarifyIndices.add(clarifyIndex);
    const rule = clarify[clarifyIndex] as ClarifyInput;

    return {
      /**
       * A project clarify keeps its clarify[i] citation in evaluate, so it carries no rule id here.
       */
      finding: applyOverride(rule.detected, rule.expression, undefined, "clarify", base, signal),
      coversIntensive: "intensive" in rule.detected,
    };
  }

  // Tool-level builtin set, version-agnostic (overrides survive bumps).
  const builtinIndex = builtins.findIndex((o) => matchesPackage(o, entry));

  if (builtinIndex !== -1) {
    const o = builtins[builtinIndex] as BuiltinOverrideInput;

    return {
      finding: applyOverride(
        o.detected,
        o.expression,
        `override:builtin[${builtinIndex}]`,
        "builtin",
        base,
        signal,
      ),
      coversIntensive: "intensive" in o.detected,
    };
  }

  return undefined;
}

/**
 * True when every leaf id of a parsed precise SPDX expression is consistent with an imprecise
 * family (leaf === family, OR leaf starts with `family + "-"` - e.g. family "BSD" matches leaf
 * "BSD-3-Clause" but NEVER "0BSD", and family "GPL" matches "GPL-3.0-only" but NEVER
 * "LGPL-2.1-only": a bare character-prefix match without the "-" boundary would wrongly accept an
 * unrelated or a narrower/wider copyleft family). Any leaf that fails the check makes the whole
 * expression inconsistent - a single out-of-family leaf in a compound expression is enough to
 * reject (fail closed, mirroring signalContradicts/baseSatisfiesAssertion's posture: every member
 * must agree, not just some).
 */
function everyLeafInFamily(node: ExpressionNode, family: string): boolean {
  const { ids } = leafIds(node);

  return ids.every((id) => id === family || id.startsWith(`${family}-`));
}

/**
 * True when a PRECISE SPDX expression's every leaf id is consistent with an imprecise family
 * ({@link everyLeafInFamily}). Parsing an already-normalized expression should never throw, but the
 * walk is wrapped defensively anyway - the stale-override fail-closed idiom
 * (baseSatisfiesAssertion, signalContradicts): ANY throw is treated as inconsistent, never as a
 * crash, never a silent pass.
 */
function expressionInFamily(expression: string, family: string): boolean {
  try {
    return everyLeafInFamily(parse(expression) as ExpressionNode, family);
  } catch {
    return false; // unparseable against the family check → fail closed
  }
}

/**
 * The quick-check comparands for the senior assessment: every DISTINCT non-scancode claim, deduped
 * by (kind, raw) exactly like findingFromClaims, with bare connective artifacts and empty raws
 * dropped - they are tokenization noise, never a license statement to agree or disagree with.
 */
function quickCheckClaims(claims: ReadonlyArray<LicenseClaim>): LicenseClaim[] {
  const seen = new Set<string>();
  const distinct: LicenseClaim[] = [];

  for (const c of claims) {
    if (c.source === "scancode") {
      continue;
    }

    if (c.raw.trim() === "" || isBareConnective(c.raw)) {
      continue;
    }

    const key = `${c.kind}\0${c.raw}`;

    if (!seen.has(key)) {
      seen.add(key);
      distinct.push(c);
    }
  }

  return distinct;
}

/**
 * True when one quick-check claim AGREES with the precise in-depth expression. A precise member P
 * agrees iff canonicalize(P) === canonicalize(S) (spelling-blind equality, the first check) or
 * satisfies(P, [S]) holds - satisfies is wrapped defensively for the spdx-satisfies allowlist edge
 * (a compound S throws for the AND/OR operators alike): ANY throw = disagree, fail closed, so a
 * compound assessment can only agree via the canonical-equality check. P and S are two independent
 * spellings of the same underlying claim (a registry's declared metadata, ScanCode's in-depth
 * read), so comparing them canonicalized means a boolean-algebra reordering never manufactures a
 * conflict the raw claims themselves would not have. The satisfies() call stays on the raw pair
 * deliberately: it already treats an OR expression as a set of alternatives independent of operand
 * order, so canonicalizing first would not change its verdict, only add redundant work. An
 * imprecise family agrees iff every leaf of S is in the family. A genuinely-unknown claim with a
 * non-empty raw DISAGREES: a garbage/proprietary declaration contradicted by a precise assessment
 * must become a visible conflict, never be silently decided in either direction.
 */
function claimAgreesWithAssessment(claim: LicenseClaim, assessed: CanonicalLicense): boolean {
  const result = normalizeRaw(claim.raw);

  if (result.expression !== null) {
    if (canonicalizeExpression(result.expression) === canonicalizeExpression(assessed)) {
      return true;
    }

    try {
      return satisfies(result.expression, [assessed]);
    } catch {
      return false; // compound/unparseable allowlist entry → fail closed
    }
  }

  if (result.imprecise === true && result.impreciseFamily !== undefined) {
    return expressionInFamily(assessed, result.impreciseFamily);
  }

  return false; // genuinely-unknown non-empty claim: a human must look
}

/**
 * The disagreeing-member label carried on the conflict marker: normalized where precise, the family
 * token where imprecise, the trimmed raw otherwise - the most faithful reviewable value each claim
 * can offer.
 */
function disagreeingLabel(claim: LicenseClaim): string {
  const result = normalizeRaw(claim.raw);

  if (result.expression !== null) {
    return result.expression;
  }

  if (result.imprecise === true && result.impreciseFamily !== undefined) {
    return result.impreciseFamily;
  }

  return claim.raw.trim();
}

/**
 * The in-depth answer is PRECISE: agreement is tested against every quick-check comparand; zero
 * comparands is vacuous agreement. ALL agree → the assessed expression becomes the finding
 * (elected, source "scancode", confidence "exact"). ANY disagree → the base finding STANDS in full
 * with the conflict marker attached, its members deduped and sorted for determinism.
 */
function assessPrecise(
  assessed: CanonicalLicense,
  claims: ReadonlyArray<LicenseClaim>,
  base: LicenseFinding,
): LicenseFinding {
  const disagreeing = quickCheckClaims(claims)
    .filter((c) => !claimAgreesWithAssessment(c, assessed))
    .map(disagreeingLabel);

  if (disagreeing.length > 0) {
    const members = [...new Set(disagreeing)].sort(compareCodeUnits);

    return {
      ...base,
      conflict: { kind: "scancode", assessed, disagreeing: members },
    };
  }

  // Canonicalize explicitly rather than trusting the scancode claim's raw to already be canonical:
  // the invariant belongs HERE, at finding formation - election.ts/cache.ts already canonicalize
  // before a scancode claim ever exists, but a finding must never depend on a caller's own
  // diligence to stay a model invariant.
  const expression = canonicalizeExpression(assessed);
  const node = parse(expression) as ExpressionNode;

  return {
    expression,
    elected: electedOf(node),
    source: "scancode",
    confidence: "exact",
  };
}

/**
 * The in-depth answer is IMPRECISE (a bare family): it never upgrades anything. A precise base
 * whose leaves are out-of-family is a
 * conflict (fail closed - a disagreement in any direction is surfaced);
 * everything else stands unchanged, including an out-of-family imprecise base (nothing precise on
 * either side to weigh).
 */
function assessImprecise(family: string, base: LicenseFinding): LicenseFinding {
  if (base.expression !== null && !expressionInFamily(base.expression, family)) {
    return {
      ...base,
      conflict: {
        kind: "scancode",
        assessed: family,
        disagreeing: [base.expression],
      },
    };
  }

  return base;
}

/**
 * Apply the ScanCode SENIOR ASSESSMENT to a package's base finding. The model: the in-depth result
 * outranks the quick check (declared metadata, registry answers) where they agree - the finding
 * becomes the assessed expression - and a disagreement is surfaced as a first-class conflict marker
 * on the UNCHANGED base finding, never absorbed in either direction. Overrides stay on top: this
 * runs BEFORE resolveOverride, and an APPLIED override (the human's decision) clears the marker
 * because the marker lives on the base finding only.
 *
 * Steps:
 *   1. No scancode claim → base returned unchanged (same reference): a repository with no ScanCode
 *      results behaves byte-identically to one where this function does not exist.
 *   2. The scancode raw normalizes PRECISE → {@link assessPrecise}.
 *   3. The scancode raw normalizes IMPRECISE → {@link assessImprecise}.
 *   4. The scancode raw is genuinely unknown (the election rejects these before a claim exists) →
 *      base unchanged, defensively.
 *
 * Pure function of (claims, base finding) ONLY - no mode flag, no cache handle, no clock: an
 * offline check run replays the identical claims from the committed cache and reproduces the
 * identical finding byte-for-byte, so an intensive generate and a later check never diverge.
 */
export function applyScancodeAssessment(
  claims: ReadonlyArray<LicenseClaim>,
  base: LicenseFinding,
): LicenseFinding {
  const scancode = claims.find((c) => c.source === "scancode");

  if (scancode === undefined) {
    return base;
  }

  const result = normalizeRaw(scancode.raw);

  if (result.expression !== null) {
    return assessPrecise(result.expression, claims, base);
  }

  if (result.imprecise === true && result.impreciseFamily !== undefined) {
    return assessImprecise(result.impreciseFamily, base);
  }

  return base;
}

/**
 * Overlay a cross-image claim divergence recorded at merge time onto a finding with no ScanCode
 * conflict yet - a ScanCode disagreement always keeps the slot. No-op (same reference) otherwise.
 */
function withCrossImageConflict(
  divergence: CrossImageClaimDivergence | undefined,
  finding: LicenseFinding,
): LicenseFinding {
  if (divergence === undefined || finding.conflict !== undefined) {
    return finding;
  }

  return { ...finding, conflict: divergence };
}

/**
 * Carry an unsettled ScanCode disagreement onto an applied override's finding.
 *
 * An override settles the disagreement only when it recorded what the intensive lane reports: that
 * is the entry stating which side of the disagreement the maintainer stands behind. An entry that
 * recorded the registry lane alone says nothing about the scan, so the disagreement stays on the
 * finding and the gate keeps asking for a decision.
 */
function withUnsettledConflict(
  base: LicenseFinding,
  finding: LicenseFinding,
  coversIntensive: boolean,
): LicenseFinding {
  if (coversIntensive || finding.conflict !== undefined || base.conflict?.kind !== "scancode") {
    return finding;
  }

  return { ...finding, conflict: base.conflict };
}

/**
 * Attach a LicenseFinding to every package (including the zero-claim population - expression null).
 * The two-level, staleness-guarded override chain runs in precedence order: project clarify FIRST
 * (project-wins), then the shipped tool-level builtins. An override applies ONLY while every lane
 * its `detected` table records still reports what was written down; a divergence does NOT apply the
 * assertion and instead marks the finding stale so the engine fails the gate loudly. A tool-level
 * override that decides carries a distinct override:builtin[i] citation; a project clarify keeps
 * its clarify[i] citation via the engine. Returns new entries via object spread - the input model
 * is never mutated. Pure: no I/O, never throws on a stale override.
 */
export function annotateFindings(
  model: CanonicalDependencies,
  clarify: ReadonlyArray<ClarifyInput>,
  builtins: ReadonlyArray<BuiltinOverrideInput> = [],
): AnnotatedFindings {
  const usedClarifyIndices = new Set<number>();

  const packages = model.packages.map((rawEntry: PackageEntry): PackageEntry => {
    // dockerClaimDivergence is a merge-time-only carrier (see PackageEntry): folded into
    // finding.conflict below and never left standing on the returned entry.
    const { dockerClaimDivergence, ...entry } = rawEntry;
    const unrefinedBase = findingFromClaims(entry.licenseClaims, entry.scope);

    // The ScanCode assessment runs BEFORE overrides (clarify/builtin decide last).
    const scancodeAssessed = applyScancodeAssessment(entry.licenseClaims, unrefinedBase);

    // Cross-image divergence overlays LAST so a later scancode/registry stage can never mask it
    // - it only ever ADDS the marker when scancode did not already claim the conflict slot.
    const base = withCrossImageConflict(dockerClaimDivergence, scancodeAssessed);

    const signal = observedSignalBySource(entry.licenseClaims, base);
    const resolved = resolveOverride(entry, clarify, builtins, base, signal, usedClarifyIndices);
    const overridden =
      resolved === undefined
        ? undefined
        : withUnsettledConflict(base, resolved.finding, resolved.coversIntensive);
    const finding = overridden ?? base;

    // Deny terminal over overrides: preserve the PRE-OVERRIDE observed expression whenever an
    // override REWROTE it (overridden has a different expression than the un-overridden base). The
    // deny terminal in evaluate consults this so a denied observed license can never be licensed
    // back in.
    const rewroteExpression =
      overridden !== undefined &&
      base.expression !== null &&
      overridden.expression !== base.expression;

    // Deny needs every observed claim, not only the combined expression combineKnown may collapse
    // - independent of observedExpression above; both feed deny.
    const observed = observedExpressions(entry.licenseClaims);

    return {
      ...entry,
      finding: {
        ...finding,
        ...(rewroteExpression ? { observedExpression: base.expression! } : {}),
        ...(observed.length > 0 ? { observedExpressions: observed } : {}),
      },
    };
  });

  return { model: { packages }, usedClarifyIndices };
}
