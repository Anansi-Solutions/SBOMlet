/**
 * Raw license claim → LicenseFinding with mandatory provenance.
 *
 * Pipeline per claim: raw → exact SPDX parse → spdx-correct fixup → unknown.
 * No substring matching anywhere; correct() never sees already-valid input, so
 * exact generator values are preserved verbatim and only genuinely fixed values
 * carry source "corrected".
 *
 * License strings are third-party-controlled data. Hostile or malformed input
 * degrades to an unknown finding — the run never crashes (skip-don't-throw).
 * The UNLICENSED/SEE-LICENSE-IN guard runs before correct() so "proprietary,
 * do not use" can never be rewritten to the public-domain Unlicense.
 *
 * Pure functions: no I/O, no logging — the CLI owns stderr.
 */
import parse from "spdx-expression-parse";
import correct from "spdx-correct";
import satisfies from "spdx-satisfies";

import {
  compareCodeUnits,
  type CanonicalDependencies,
  type LicenseClaim,
  type LicenseFinding,
  type PackageEntry,
  type ScopeTaxonomy,
  type StaleOverride,
} from "../model/dependencies";
import { COULD_BE_COPYLEFT_FAMILIES } from "../policy/copyleftFamily";
import {
  elect,
  isCopyleft,
  leafIds,
  renderNode,
  type ExpressionNode,
} from "./expression";

/**
 * Raw values that must never reach correct(): npm's "UNLICENSED" means
 * proprietary (correct() maps it to public-domain "Unlicense"), and "SEE
 * LICENSE IN <file>" is a pointer, not a license.
 */
const NEVER_CORRECT = [/^UNLICENSED$/i, /^SEE LICEN[CS]E IN /i];

/**
 * Ambiguous license FAMILY labels: a bare family with no clause count
 * or version that spdx-correct would otherwise GUESS to a precise variant
 * (correct("BSD")/correct("BSD License") → BSD-2-Clause; correct("Apache
 * Software License")/correct("Apache") → Apache-2.0). We intercept these BEFORE
 * correct() and represent them faithfully as the imprecise family, never the
 * guess. The key is the case-folded trimmed raw; the value is the family token
 * carried on the finding.
 *
 * Small, reviewable, literal — the copyleft.ts / trove.ts idiom. Labels that
 * carry a version ("Apache License, Version 2.0") are deliberately ABSENT: their
 * spdx-correct result (Apache-2.0) is precise and correct, not a guess.
 */
const AMBIGUOUS_FAMILY: ReadonlyMap<string, string> = new Map([
  ["bsd", "BSD"],
  ["bsd license", "BSD"],
  ["apache", "Apache"],
  ["apache software license", "Apache"],
  // Bare GNU-family labels: correct() GUESSES these to a precise variant
  // (correct("GPL") → GPL-3.0-or-later) — a confident-but-wrong copyleft id.
  // Represented faithfully as the imprecise family so the policy engine routes
  // them to the could-be-copyleft review lane (COULD_BE_COPYLEFT_FAMILIES)
  // rather than a fabricated copyleft fail.
  ["gpl", "GPL"],
  ["gpl license", "GPL"],
  ["agpl", "AGPL"],
  ["agpl license", "AGPL"],
  ["lgpl", "LGPL"],
  ["lgpl license", "LGPL"],
  // Bare EUPL (W1 correction): EUPL is STRONG copyleft, but spdx-correct
  // cross-maps the bare label to the PERMISSIVE "UPL-1.0" (Universal Permissive
  // License) — a copyleft→permissive mis-guess that would silently pass the
  // gate (default:ok). Intercept it as the imprecise copyleft family so it
  // routes to the could-be-copyleft review lane (COULD_BE_COPYLEFT_FAMILIES).
  // Verified the ONLY copyleft family correct() crosses to a permissive id:
  // MPL/CDDL/SSPL/Sleepycat/QPL/MS-RL/CPAL stay copyleft (precise path),
  // OSL/CeCILL/EPL/CC-BY-SA/GFDL/RPL/APSL correct() to null (unknown, gated).
  ["eupl", "EUPL"],
  ["eupl license", "EUPL"],
]);

/**
 * Precise label fixups spdx-correct MISSES (correct() returns null) that ARE
 * unambiguously resolvable to a single SPDX id — the "ISC license"/"ISC License"
 * suffix false-negative that dropped pexpect to unknown (bare "ISC"
 * already parses). Keyed by case-folded trimmed raw. Kept tiny and reviewable;
 * adding a family-ambiguous label here would re-introduce a false guess, so only
 * unambiguous single-id labels belong.
 */
const PRECISE_LABEL_FIXUP: ReadonlyMap<string, string> = new Map([
  ["isc license", "ISC"],
]);

/**
 * Debian/DEP-5 copyright SHORT-NAME → canonical SPDX id.
 *
 * syft fills ~98% of OS-package licenses, but Debian's machine-readable
 * copyright (DEP-5) declares licenses with copyright SHORTHANDS — "Expat" for
 * MIT, "GPL-2+" for GPL-2.0-or-later, "BSD-3-clause" for BSD-3-Clause — that are
 * NOT valid SPDX ids. Those tokens fail the exact `parse()` and reach
 * spdx-correct, whose FUZZY matcher then either drops them to unknown OR
 * produces a CONFIDENTLY-WRONG guess (verified 2026-06-16 against spdx-correct:
 * correct("GPL-2+") → "GPL-2.0-only", silently dropping the `+`/or-later;
 * correct("GPL-3") → "GPL-3.0-or-later", the wrong clause). This authoritative
 * map intercepts the WELL-KNOWN UNAMBIGUOUS DEP-5 shorthands BEFORE correct()
 * can see them, mapping each to the precise SPDX id Debian actually means.
 *
 * The copyleftFamily.ts / copyleft.ts literal-reviewable-data idiom: a small,
 * enumerated, test-asserted map — never a runtime prefix/fuzzy inference. Every
 * VALUE is validated against spdx-license-ids in the tests, so a typo'd target
 * cannot silently re-create the unknown it is meant to resolve.
 *
 * Keys are CASE-FOLDED exact shorthand tokens (Debian is inconsistent —
 * "BSD-3-clause" vs "BSD-3-Clause"); matching is EXACT-token only, NEVER
 * substring (a custom name like "BSD-3-clause-Berkeley" or
 * "LGPL-2.1+-with-link-exception" must NOT match — it stays on the correct()
 * path / unknown). The keys are deliberately VERSIONED ("gpl-2", "gpl-3"): bare
 * "GPL"/"LGPL"/"AGPL" are ABSENT so they still route to the could-be-copyleft
 * imprecise family lane (AMBIGUOUS_FAMILY) — a bare "GPL" could be any
 * GPL variant and must never be guessed to a precise id here.
 *
 * Genuinely-unknown Debian tokens (custom / public-domain with no SPDX id /
 * sha256-hash fallbacks / "BSD-like" / per-package custom short names) are
 * DELIBERATELY ABSENT — they stay unknown. The conservative all-or-nothing
 * unknown invariant is preserved: only cleanly-mappable shorthands lift a row.
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
 * Bare SPDX CONNECTIVE tokens (#3/#10). syft tokenizes a compound license
 * ("GPL-2.0-only AND MIT") into SEPARATE component license entries — INCLUDING
 * the bare connective words "AND"/"OR"/"WITH". Those are SYNTAX artifacts, not
 * licenses: they neither normalize nor identify anything, so they must be
 * dropped before claim processing (never an unrecognized token, never forcing
 * the all-or-nothing unknown collapse). Case-insensitive, exact-token only
 * (a real license like "AND-1.0" — hypothetical — would not be a bare "AND").
 * (Full OR/AND expression RECONSTRUCTION is out of scope; we only drop the bare
 * connectives so they stop polluting the OS render.)
 */
const SPDX_CONNECTIVES: ReadonlySet<string> = new Set(["and", "or", "with"]);

/** True when a raw claim is a bare connective syntax artifact (#3/#10). */
function isBareConnective(raw: string): boolean {
  return SPDX_CONNECTIVES.has(raw.trim().toLowerCase());
}

/**
 * True when a comma-bearing raw value is a list of licenses — every
 * comma-separated part is independently license-like (parses or corrects).
 * Such lists must never reach correct(): correct("MIT,Apache-2.0") returns
 * "Apache-2.0", silently dropping MIT. A comma inside a single license name
 * ("Apache License, Version 2.0") is not a list — its parts ("Version 2.0")
 * are not license-like — and stays correctable.
 */
function isCommaLicenseList(value: string): boolean {
  if (!value.includes(",")) return false;
  return value.split(",").every((part) => {
    const candidate = part.trim();
    if (candidate === "") return false;
    try {
      parse(candidate);
      return true;
    } catch {
      /* not an exact id/expression — try correction */
    }
    return correct(candidate) !== null;
  });
}

/**
 * Result of normalizing one raw license string. An imprecise result carries
 * `imprecise: true` + `impreciseFamily` with `expression` null: an
 * ambiguous family label is present-but-imprecise, never a guessed precise id
 * and never silently unknown.
 */
export interface NormalizeResult {
  expression: string | null;
  source: "generator" | "corrected";
  imprecise?: true;
  impreciseFamily?: string;
}

/**
 * Normalize one raw license string: exact parse first, an imprecise-family
 * intercept, a precise-label fixup for the cases correct() misses, then
 * a guarded spdx-correct fixup, else unknown. Comma lists are never correctable;
 * `[[clarify]]` is the escape hatch.
 */
export function normalizeRaw(raw: string): NormalizeResult {
  const trimmed = raw.trim();
  if (trimmed === "" || NEVER_CORRECT.some((re) => re.test(trimmed))) {
    return { expression: null, source: "generator" }; // unknown
  }
  try {
    parse(trimmed);
    return { expression: trimmed, source: "generator" }; // exact
  } catch {
    /* fall through */
  }
  const folded = trimmed.toLowerCase();
  // Intercept an ambiguous family label BEFORE correct() can fabricate
  // a clause count. Present-but-imprecise — never the guess, never unknown.
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
    return { expression: fixup, source: "corrected" };
  }
  // Debian/DEP-5 copyright shorthands → canonical SPDX. MUST run BEFORE
  // correct(): correct() either drops these to unknown or mis-guesses them
  // (e.g. "GPL-2+" → "GPL-2.0-only", dropping the or-later). Exact-token only,
  // case-folded; bare GPL/LGPL/AGPL already returned above via AMBIGUOUS_FAMILY.
  const debian = DEBIAN_SHORTHAND.get(folded);
  if (debian !== undefined) {
    return { expression: debian, source: "corrected" };
  }
  if (isCommaLicenseList(trimmed)) {
    return { expression: null, source: "generator" }; // unknown
  }
  const fixed = correct(trimmed); // never throws on non-empty input
  if (fixed !== null) {
    try {
      parse(fixed); // belt-and-braces: corrected output must parse
      return { expression: fixed, source: "corrected" };
    } catch {
      /* corrected output unparseable — treat as unknown */
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
 * Combine a package's claims into one finding. Claims are deduped by
 * (kind, raw) — duplicates within one component's licenses[] array (e.g.
 * ["MIT","MIT"]) must not become "MIT AND MIT". Distinct normalized
 * expressions AND-combine (conservative: all asserted obligations apply); any
 * non-normalizable claim makes the whole finding unknown — partial knowledge
 * must not hide an obligation.
 *
 * SCOPE-AWARE EXCEPTION: for the NON-GATING `os` scope ONLY, a claim set
 * that mixes ≥1 normalizable SPDX member with ≥1 genuinely-unknown ("none")
 * token is NOT forced to unknown. Instead the finding is built from the
 * normalizable members and the unparseable tokens are surfaced on
 * `unrecognizedTokens` for review/rendering — the known GPL/BSD obligation is
 * shown rather than hidden, and the os scope is non-gating so this is safe.
 * Every NON-os scope keeps the strict all-or-nothing → unknown invariant.
 */
function findingFromClaims(
  claims: ReadonlyArray<LicenseClaim>,
  scope: ScopeTaxonomy = "app",
): LicenseFinding {
  const seen = new Set<string>();
  const distinct: LicenseClaim[] = [];
  for (const c of claims) {
    // #3/#10: drop bare connective syntax artifacts ("AND"/"OR"/"WITH") — they
    // are syft compound-license tokenization noise, never a license claim.
    if (isBareConnective(c.raw)) continue;
    const key = `${c.kind}\0${c.raw}`; // NUL-joined: no concatenation ambiguity
    if (!seen.has(key)) {
      seen.add(key);
      distinct.push(c);
    }
  }
  if (distinct.length === 0) return UNKNOWN_FINDING;

  const results = distinct.map((c) => normalizeRaw(c.raw));
  // A genuinely-unknown claim is expression null AND not imprecise (an imprecise
  // family is its own present-but-needs-clarify lane, never an "unrecognized
  // token"). Pair each genuinely-unknown result with its trimmed raw so the
  // os-partial path can surface the faithful token.
  const unknownTokens = distinct
    .map((c, i) => ({ raw: c.raw.trim(), result: results[i]! }))
    .filter(
      ({ result }) => result.expression === null && result.imprecise !== true,
    )
    .map(({ raw }) => raw)
    .filter((raw) => raw !== "");
  if (unknownTokens.length > 0) {
    const hasNormalizable = results.some((r) => r.expression !== null);
    const hasImprecise = results.some((r) => r.imprecise === true);
    // os-scope partial: build the KNOWN signal (precise OR imprecise) and surface
    // the rest. Requires ≥1 KNOWN member — a precise license OR (#2) an imprecise
    // copyleft/permissive family, so the could-be-copyleft review hint survives
    // rather than flattening to plain unknown. An os package with ZERO known
    // members (only public-domain/custom/hash) stays unknown (nothing to stand
    // on) — exactly the app-scope behavior.
    if (scope === "os" && (hasNormalizable || hasImprecise)) {
      const surfaced = [...new Set(unknownTokens)].sort(compareCodeUnits);
      return { ...combineKnown(results), unrecognizedTokens: surfaced };
    }
    // Every non-os scope (and os with zero known members): conservative
    // all-or-nothing — a genuinely-unknown claim makes the whole finding unknown
    // so partial knowledge can never hide an obligation.
    return UNKNOWN_FINDING;
  }

  return combineKnown(results);
}

/**
 * Combine the KNOWN (normalizable + imprecise) signal of a result set into one
 * finding, applying copyleft dominance (C2/W2). Genuinely-unknown results
 * (expression null AND not imprecise) are inert here — they are filtered out of
 * `preciseResults` and ignored by electImpreciseFamily — so this is safe to call
 * with a result set that still contains the os-partial surfaced tokens.
 *
 * A copyleft signal — precise OR imprecise — must dominate a permissive sibling,
 * never be discarded by a "first imprecise wins" short-circuit (which downgraded
 * a hard copyleft gate to a non-gating warn and made the could-be-copyleft lane
 * claim-order-dependent):
 *   1. If a PRECISE copyleft id is present, AND-combine ALL precise claims into a
 *      copyleft finding (the precise copyleft survives; permissive imprecise
 *      siblings are dropped — they cannot weaken a known copyleft obligation). C2.
 *   2. Else if any imprecise family is present, the finding is imprecise —
 *      preferring a COULD_BE_COPYLEFT family over a permissive one regardless of
 *      claim order, so the could-be-copyleft review lane is reached
 *      order-independently. W2.
 *   3. Else AND-combine the (all-permissive) precise claims.
 */
function combineKnown(results: ReadonlyArray<NormalizeResult>): LicenseFinding {
  const preciseResults = results.filter((r) => r.expression !== null);
  const hasPreciseCopyleft = preciseResults.some((r) =>
    expressionIsCopyleft(r.expression as string),
  );
  if (hasPreciseCopyleft) return combinePrecise(preciseResults);

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

  return combinePrecise(preciseResults);
}

/** True if a parseable SPDX expression elects a copyleft branch (defensive). */
function expressionIsCopyleft(expression: string): boolean {
  try {
    return isCopyleft(elect(parse(expression) as ExpressionNode));
  } catch {
    return false;
  }
}

/**
 * Pick the dominant imprecise family across results: a COULD_BE_COPYLEFT family
 * (GPL/AGPL/LGPL) wins over a permissive one regardless of claim order (W2), so
 * two conflicting imprecise families route to the could-be-copyleft review lane
 * deterministically. Returns undefined when no imprecise family is present.
 */
function electImpreciseFamily(
  results: ReadonlyArray<NormalizeResult>,
): string | undefined {
  let permissive: string | undefined;
  for (const r of results) {
    if (r.imprecise !== true || r.impreciseFamily === undefined) continue;
    if (COULD_BE_COPYLEFT_FAMILIES.has(r.impreciseFamily)) {
      return r.impreciseFamily; // copyleft family dominates
    }
    permissive ??= r.impreciseFamily;
  }
  return permissive;
}

/** AND-combine the precise (non-null) normalize results into one finding. */
function combinePrecise(
  preciseResults: ReadonlyArray<NormalizeResult>,
): LicenseFinding {
  // Dedupe expression strings: an spdx-id claim and a name claim may
  // normalize to the same expression.
  const expressions: string[] = [];
  const seenExpressions = new Set<string>();
  for (const r of preciseResults) {
    const expression = r.expression as string;
    if (!seenExpressions.has(expression)) {
      seenExpressions.add(expression);
      expressions.push(expression);
    }
  }

  let node = parse(expressions[0] as string) as ExpressionNode;
  let expression = expressions[0] as string; // single claim: raw preserved verbatim
  if (expressions.length > 1) {
    for (const next of expressions.slice(1)) {
      node = {
        left: node,
        conjunction: "and",
        right: parse(next) as ExpressionNode,
      };
    }
    expression = renderNode(node); // compound operands parenthesized
  }

  const anyCorrected = preciseResults.some((r) => r.source === "corrected");
  return {
    expression,
    elected: renderNode(elect(node)),
    source: anyCorrected ? "corrected" : "generator",
    confidence: anyCorrected ? "corrected" : "exact",
  };
}

/**
 * Inline structural type for project clarify rules — no import from policy/
 * (the validated policy is structurally compatible). `expression` must be a
 * valid SPDX expression: policy schema validation parses it eagerly before
 * evaluation. `expects` is the OPTIONAL staleness precondition: when
 * present, the override applies only while the package's pre-override observed
 * signal still matches it; absent = blind apply (backward-compat).
 */
export interface ClarifyInput {
  name: string;
  version?: string;
  expects?: string;
  expression: string;
}

/**
 * Inline structural type for the shipped TOOL-LEVEL override set,
 * structurally compatible with BUILTIN_OVERRIDES. `expects` is always present
 * (every shipped default is a preconditioned assertion); version-agnostic.
 */
export interface BuiltinOverrideInput {
  name: string;
  version?: string;
  expects: string;
  expression: string;
}

export interface AnnotatedFindings {
  model: CanonicalDependencies;
  usedClarifyIndices: ReadonlySet<number>;
}

/**
 * The package's PRE-OVERRIDE observed signal: the set of normalized
 * raw claim strings (each claim's trimmed raw value) UNION the un-overridden
 * finding's impreciseFamily token. An override's `expects` is compared
 * (case-insensitive, trimmed equality) against the members of this set.
 */
function observedSignal(
  claims: ReadonlyArray<LicenseClaim>,
  baseFinding: LicenseFinding,
): string[] {
  const signal = new Set<string>();
  for (const c of claims) {
    const trimmed = c.raw.trim();
    if (trimmed !== "") signal.add(trimmed);
  }
  if (baseFinding.impreciseFamily !== undefined) {
    signal.add(baseFinding.impreciseFamily);
  }
  return [...signal];
}

/**
 * Every observed per-claim normalized PRECISE expression (#1/#5/#11). Runs
 * normalizeRaw over each claim and collects the non-null precise results,
 * deduped and sorted by compareCodeUnits. Genuinely-unknown and imprecise-family
 * claims contribute nothing (no precise license to deny). The deny terminal
 * consults this set so a denied member is seen even when combineKnown elects an
 * imprecise family / collapses to unknown and drops it from the combined
 * expression. Empty → caller omits the field.
 */
function observedExpressions(
  claims: ReadonlyArray<LicenseClaim>,
): readonly string[] {
  const seen = new Set<string>();
  for (const c of claims) {
    const precise = normalizeRaw(c.raw).expression;
    if (precise !== null) seen.add(precise);
  }
  return [...seen].sort(compareCodeUnits);
}

/** Case-insensitive, trimmed equality of `expects` against any signal member. */
function signalMatches(
  signal: ReadonlyArray<string>,
  expects: string,
): boolean {
  const want = expects.trim().toLowerCase();
  return signal.some((s) => s.trim().toLowerCase() === want);
}

/**
 * Fail-closed staleness guard: an override may apply ONLY when no
 * non-`expects` member of the observed signal carries a PRECISE license that
 * the asserted `expression` does not account for. The any-member `expects`
 * match alone is fail-OPEN — a lingering obsolete label (`BSD`) would license
 * out a co-present new precise copyleft claim (`GPL-3.0-only`) during a
 * relicense — the exact masking the staleness guard exists to prevent.
 *
 * For each signal member that is NOT `expects`, we re-derive a precise
 * expression via the normalizer. A member that normalizes to a precise id which
 * the asserted expression does not SATISFY contradicts the assertion → the
 * override is stale (fail closed). Imprecise / unknown members carry no precise
 * contradicting license and never block the apply. spdx-satisfies is defensive:
 * any throw is treated as a contradiction (fail closed).
 */
function signalContradicts(
  signal: ReadonlyArray<string>,
  expects: string,
  expression: string,
): boolean {
  const want = expects.trim().toLowerCase();
  for (const member of signal) {
    if (member.trim().toLowerCase() === want) continue;
    const precise = normalizeRaw(member).expression;
    if (precise === null) continue; // imprecise/unknown: no precise contradiction
    let ok: boolean;
    try {
      ok = satisfies(precise, [expression]);
    } catch {
      ok = false; // unparseable against the assertion → fail closed
    }
    if (!ok) return true;
  }
  return false;
}

/**
 * True when the un-overridden finding ALREADY carries a precise expression that
 * SATISFIES the asserted override expression (the redundancy
 * path). When the registry upgrades an imprecise label to the exact
 * precise license the override asserts (PyPI now reports ipython/ipykernel/
 * jupyter-core as the precise "BSD-3-Clause" the "expects: BSD" override
 * disambiguates TO), the override has nothing to do: the observed precise
 * finding already satisfies the assertion, so it is REDUNDANT — not stale, not
 * applied — and the observed finding stands unchanged. This is fail-safe: a base
 * that does NOT satisfy the assertion (a real relicense to MIT/GPL) is NOT
 * redundant and falls through to the stale-fail path. spdx-satisfies is
 * defensive — any throw is treated as NOT satisfying (fail closed).
 */
function baseSatisfiesAssertion(
  base: LicenseFinding,
  expression: string,
): boolean {
  if (base.expression === null) return false; // imprecise/unknown: not redundant
  try {
    return satisfies(base.expression, [expression]);
  } catch {
    return false; // unparseable against the assertion → not redundant, fail closed
  }
}

/** Build the override finding from a validated SPDX expression. */
function overrideFinding(
  expression: string,
  overrideRule: string | undefined,
): LicenseFinding {
  const node = parse(expression) as ExpressionNode;
  return {
    expression,
    elected: renderNode(elect(node)),
    source: "override",
    confidence: "exact",
    ...(overrideRule !== undefined ? { overrideRule } : {}),
  };
}

/** Attach a stale-override marker to the un-overridden finding. */
function withStaleOverride(
  base: LicenseFinding,
  stale: StaleOverride,
): LicenseFinding {
  return { ...base, staleOverride: stale };
}

/**
 * Apply one preconditioned override to a package, given its un-overridden
 * finding and observed signal. Returns the override finding on a match, the
 * UNCHANGED base finding on a redundant match (the gap fix below), a
 * stale-marked finding on a genuine mismatch, or undefined when this override
 * does not apply (no `expects` blind path is the only undefined caller path).
 *
 * `expects` undefined → blind apply (backward-compat). `expects` present →
 * decision tree on the observed signal S and the asserted expression E:
 *
 *   IF expects ∈ S (signalMatches):
 *     IF a non-`expects` precise member contradicts E (signalContradicts)
 *        → STALE → fail closed [C1 — the relicense-metadata-lag mask].
 *     ELSE → APPLY E [normal disambiguation].
 *   ELSE (expects ∉ S):
 *     IF the observed finding already carries a precise expression that
 *        SATISFIES E → REDUNDANT: do NOT apply, do NOT fail — let the precise
 *        observed finding stand unchanged [GAP FIX — the registry upgraded the
 *        imprecise label to the exact license the override asserts].
 *     ELSE → STALE → fail closed [genuine drift: relicensed to a different or
 *        non-satisfying license, or still ambiguous-but-different].
 *
 * Fail-safe: the ONLY non-failing path added is the co-equal/satisfying precise
 * observation. A relicense to anything that does not satisfy E still fails.
 */
function applyOverride(
  expects: string | undefined,
  expression: string,
  overrideRule: string | undefined,
  level: StaleOverride["level"],
  base: LicenseFinding,
  signal: ReadonlyArray<string>,
): LicenseFinding {
  if (expects === undefined) return overrideFinding(expression, overrideRule);
  if (signalMatches(signal, expects)) {
    if (!signalContradicts(signal, expects, expression)) {
      return overrideFinding(expression, overrideRule);
    }
  } else if (baseSatisfiesAssertion(base, expression)) {
    // The registry upgraded the imprecise label to the precise license the
    // override asserts (or a satisfying one): nothing is masked — leave the
    // observed precise finding untouched (redundant, not stale).
    return base;
  }
  return withStaleOverride(base, {
    level,
    expected: expects,
    observed: signal,
  });
}

/** First override (project clarify, then tool-level builtin) for a package. */
function resolveOverride(
  entry: PackageEntry,
  clarify: ReadonlyArray<ClarifyInput>,
  builtins: ReadonlyArray<BuiltinOverrideInput>,
  base: LicenseFinding,
  signal: ReadonlyArray<string>,
  usedClarifyIndices: Set<number>,
): LicenseFinding | undefined {
  // Project clarify FIRST (project-wins-on-conflict).
  const clarifyIndex = clarify.findIndex(
    (rule) =>
      rule.name === entry.name &&
      (rule.version === undefined || rule.version === entry.version),
  );
  if (clarifyIndex !== -1) {
    usedClarifyIndices.add(clarifyIndex);
    const rule = clarify[clarifyIndex] as ClarifyInput;
    return applyOverride(
      rule.expects,
      rule.expression,
      undefined, // project clarify keeps its clarify[i] citation in evaluate
      "clarify",
      base,
      signal,
    );
  }
  // Tool-level builtin set, version-agnostic (overrides survive bumps).
  const builtinIndex = builtins.findIndex((o) => o.name === entry.name);
  if (builtinIndex !== -1) {
    const o = builtins[builtinIndex] as BuiltinOverrideInput;
    return applyOverride(
      o.expects,
      o.expression,
      `override:builtin[${builtinIndex}]`,
      "builtin",
      base,
      signal,
    );
  }
  return undefined;
}

/**
 * True when every leaf id of a parsed precise SPDX expression is consistent
 * with an imprecise family (leaf === family, OR leaf starts with
 * `family + "-"` — e.g. family "BSD" matches leaf "BSD-3-Clause" but NEVER
 * "0BSD", and family "GPL" matches "GPL-3.0-only" but NEVER "LGPL-2.1-only":
 * a bare character-prefix match without the "-" boundary would wrongly
 * accept an unrelated or a narrower/wider copyleft family). Any leaf that
 * fails the check makes the whole expression inconsistent — a single
 * out-of-family leaf in a compound expression is enough to reject (fail
 * closed, mirroring signalContradicts/baseSatisfiesAssertion's posture:
 * every member must agree, not just some).
 */
function everyLeafInFamily(node: ExpressionNode, family: string): boolean {
  const { ids } = leafIds(node);
  return ids.every((id) => id === family || id.startsWith(`${family}-`));
}

/**
 * True when a PRECISE SPDX expression's every leaf id is consistent with an
 * imprecise family ({@link everyLeafInFamily}). Parsing an already-normalized
 * expression should never throw, but the walk is wrapped defensively anyway —
 * the stale-override fail-closed idiom (baseSatisfiesAssertion,
 * signalContradicts):
 * ANY throw is treated as inconsistent, never as a crash, never a silent
 * pass.
 */
function expressionInFamily(expression: string, family: string): boolean {
  try {
    return everyLeafInFamily(parse(expression) as ExpressionNode, family);
  } catch {
    return false; // unparseable against the family check → fail closed
  }
}

/**
 * The quick-check comparands for the senior assessment: every DISTINCT
 * non-scancode claim, deduped by (kind, raw) exactly like findingFromClaims,
 * with bare connective artifacts and empty raws dropped — they are
 * tokenization noise, never a license statement to agree or disagree with.
 */
function quickCheckClaims(claims: ReadonlyArray<LicenseClaim>): LicenseClaim[] {
  const seen = new Set<string>();
  const distinct: LicenseClaim[] = [];
  for (const c of claims) {
    if (c.source === "scancode") continue;
    if (c.raw.trim() === "" || isBareConnective(c.raw)) continue;
    const key = `${c.kind}\0${c.raw}`;
    if (!seen.has(key)) {
      seen.add(key);
      distinct.push(c);
    }
  }
  return distinct;
}

/**
 * True when one quick-check claim AGREES with the precise in-depth
 * expression. A precise member P agrees iff P === S (normalized exact
 * equality, cheap first check) or satisfies(P, [S]) holds — satisfies is
 * wrapped defensively for the spdx-satisfies allowlist edge (a compound S
 * throws for the AND/OR operators alike): ANY throw = disagree, fail closed, so a
 * compound assessment can only agree via exact equality. An imprecise
 * family agrees iff every leaf of S is in the family. A genuinely-unknown
 * claim with a non-empty raw DISAGREES: a garbage/proprietary declaration
 * contradicted by a precise assessment must become a visible conflict,
 * never be silently decided in either direction.
 */
function claimAgreesWithAssessment(
  claim: LicenseClaim,
  assessed: string,
): boolean {
  const result = normalizeRaw(claim.raw);
  if (result.expression !== null) {
    if (result.expression === assessed) return true;
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
 * The disagreeing-member label carried on the conflict marker: normalized
 * where precise, the family token where imprecise, the trimmed raw otherwise
 * — the most faithful reviewable value each claim can offer.
 */
function disagreeingLabel(claim: LicenseClaim): string {
  const result = normalizeRaw(claim.raw);
  if (result.expression !== null) return result.expression;
  if (result.imprecise === true && result.impreciseFamily !== undefined) {
    return result.impreciseFamily;
  }
  return claim.raw.trim();
}

/**
 * The in-depth answer is PRECISE: agreement is tested against every
 * quick-check comparand; zero comparands is vacuous agreement. ALL agree →
 * the assessed expression becomes the finding (elected, source "scancode",
 * confidence "exact"). ANY disagree → the base finding STANDS in full with
 * the conflict marker attached, its members deduped and sorted for
 * determinism.
 */
function assessPrecise(
  assessed: string,
  claims: ReadonlyArray<LicenseClaim>,
  base: LicenseFinding,
): LicenseFinding {
  const disagreeing = quickCheckClaims(claims)
    .filter((c) => !claimAgreesWithAssessment(c, assessed))
    .map(disagreeingLabel);
  if (disagreeing.length > 0) {
    const members = [...new Set(disagreeing)].sort(compareCodeUnits);
    return { ...base, conflict: { assessed, disagreeing: members } };
  }
  const node = parse(assessed) as ExpressionNode;
  return {
    expression: assessed,
    elected: renderNode(elect(node)),
    source: "scancode",
    confidence: "exact",
  };
}

/**
 * The in-depth answer is IMPRECISE (a bare family): it never upgrades
 * anything. A precise base whose leaves are out-of-family is a
 * conflict (fail closed — a disagreement in any direction is surfaced);
 * everything else stands unchanged, including an out-of-family imprecise
 * base (nothing precise on either side to weigh).
 */
function assessImprecise(family: string, base: LicenseFinding): LicenseFinding {
  if (
    base.expression !== null &&
    !expressionInFamily(base.expression, family)
  ) {
    return {
      ...base,
      conflict: { assessed: family, disagreeing: [base.expression] },
    };
  }
  return base;
}

/**
 * Apply the ScanCode SENIOR ASSESSMENT to a package's base finding. The
 * model: the in-depth result outranks the quick check
 * (declared metadata, registry answers) where they agree — the finding
 * becomes the assessed expression — and a disagreement is surfaced as a
 * first-class conflict marker on the UNCHANGED base finding, never absorbed
 * in either direction. Overrides stay on top: this runs BEFORE
 * resolveOverride, and an APPLIED override (the human's decision) clears the
 * marker because the marker lives on the base finding only.
 *
 * Steps:
 *   1. No scancode claim → base returned unchanged (same reference): a
 *      repository with no ScanCode results behaves byte-identically to one
 *      where this function does not exist.
 *   2. The scancode raw normalizes PRECISE → {@link assessPrecise}.
 *   3. The scancode raw normalizes IMPRECISE → {@link assessImprecise}.
 *   4. The scancode raw is genuinely unknown (the election rejects these
 *      before a claim exists) → base unchanged, defensively.
 *
 * Pure function of (claims, base finding) ONLY — no mode flag, no cache
 * handle, no clock: an offline check run replays the identical claims from
 * the committed cache and reproduces the identical finding byte-for-byte,
 * so an intensive generate and a later check never diverge.
 */
export function applyScancodeAssessment(
  claims: ReadonlyArray<LicenseClaim>,
  base: LicenseFinding,
): LicenseFinding {
  const scancode = claims.find((c) => c.source === "scancode");
  if (scancode === undefined) return base;
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
 * Attach a LicenseFinding to every package (including the zero-claim
 * population — expression null). The two-level, staleness-guarded override
 * chain runs in precedence order: project clarify FIRST (project-wins), then
 * the shipped tool-level builtins. A preconditioned override (`expects`
 * present) applies ONLY when the package's pre-override observed signal still
 * matches `expects`; a MISMATCH does NOT apply the assertion and instead marks
 * the finding stale so the engine fails the gate loudly. A no-`expects`
 * override applies blindly (backward-compat). A tool-level override that decides
 * carries a distinct override:builtin[i] citation; a project clarify keeps its
 * clarify[i] citation via the engine. Returns new entries via object spread —
 * the input model is never mutated. Pure: no I/O, never throws on a stale
 * override.
 */
export function annotateFindings(
  model: CanonicalDependencies,
  clarify: ReadonlyArray<ClarifyInput>,
  builtins: ReadonlyArray<BuiltinOverrideInput> = [],
): AnnotatedFindings {
  const usedClarifyIndices = new Set<number>();
  const packages = model.packages.map((entry: PackageEntry): PackageEntry => {
    const unrefinedBase = findingFromClaims(entry.licenseClaims, entry.scope);
    // The scancode SENIOR ASSESSMENT runs BEFORE overrides see the
    // finding (clarify/builtin still decide last). An APPLIED override's
    // finding never carries the conflict marker: the marker lives on this
    // base only, and overrideFinding builds a fresh object.
    const base = applyScancodeAssessment(entry.licenseClaims, unrefinedBase);
    const signal = observedSignal(entry.licenseClaims, base);
    const overridden = resolveOverride(
      entry,
      clarify,
      builtins,
      base,
      signal,
      usedClarifyIndices,
    );
    const finding = overridden ?? base;
    // C#1 — deny terminal over overrides: preserve the PRE-OVERRIDE observed
    // expression whenever an override REWROTE it (overridden has a different
    // expression than the un-overridden base). The deny terminal in evaluate
    // consults this so a denied observed license can never be licensed back in.
    const rewroteExpression =
      overridden !== undefined &&
      base.expression !== null &&
      overridden.expression !== base.expression;
    // #1/#5/#11 — deny sees EVERY observed claim: carry every per-claim precise
    // expression so the deny terminal fires on a denied member combineKnown
    // dropped (imprecise-family election / unknown collapse). Independent of the
    // C#1 single observedExpression (override-rewrite) above — both feed deny.
    const observed = observedExpressions(entry.licenseClaims);
    return {
      ...entry,
      finding: {
        ...finding,
        ...(rewroteExpression
          ? { observedExpression: base.expression as string }
          : {}),
        ...(observed.length > 0 ? { observedExpressions: observed } : {}),
      },
    };
  });
  return { model: { packages }, usedClarifyIndices };
}
