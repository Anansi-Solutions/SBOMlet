/**
 * Pure policy engine: evaluate(model, policy) → Verdict[].
 *
 * Pure fold over the model — no I/O, no fs/process, no logging, no CycloneDX
 * knowledge; the CLI owns file reads and stderr. Identical model + policy
 * always produce the identical Verdict[], sorted compareCodeUnits on (purl,
 * occurrenceTarget).
 *
 * Precondition: model.packages carry `finding` (annotateFindings ran). A
 * missing finding is treated as unknown — defensive, never throws.
 *
 * Precedence per (package × occurrence), highest → lowest:
 *   0. DENY (POL-09) — denyRuleFor matches the finding's expression (license
 *      mode, OR-election over the UNION of all license deny allowlists so an OR
 *      across SEPARATE deny entries is denied — C#6; an OR finding with a branch
 *      electable out of the union is NOT denied) or the package name (name mode,
 *      for non-SPDX use-restriction riders like Commons-Clause) → fail,
 *      denied[i], TERMINAL. Deny ALSO consults the PRE-OVERRIDE observed
 *      expression (finding.observedExpression — C#1): if EITHER the observed or
 *      the possibly-overridden finding expression is denied, deny fires, so a
 *      denied OBSERVED license can never be licensed back in by an override that
 *      rewrites it. Deny sits above EVERY accept lever AND above the
 *      stale-override lane: a use-restricted / source-available license can
 *      never be licensed back in by a compatible rule, a workspace suppression,
 *      the dev-scope downgrade, a stale override, OR a successfully-applied
 *      override. Name-mode deny does not require a parseable expression, so an
 *      unknown-finding rider still fails.
 *   1. compatible match="package" (exact name, exact version when the rule
 *      pins one) → ok, compatible[i] — excluded from copyleft flagging
 *      everywhere.
 *   2. compatible match="license": satisfies(finding.expression,
 *      rule.allowlist) against the pre-decomposed allowlist from schema
 *      validation → ok, compatible[i].
 *   3. copyleft-flagged (isCopyleft on the elected branch — an OR with a
 *      permissive branch elects the permissive branch and is not copyleft) and
 *      the occurrence target is or is under a suppressed path and the
 *      suppression is family-justified (the elected expression satisfies the
 *      workspace's declared license, or every copyleft leaf in it is in a
 *      finding-family the workspace license family ABSORBS per the literal
 *      WORKSPACE_ABSORBS relation — an AGPL-3.0 workspace absorbs GNU-family
 *      GPL/LGPL deps AND MPL deps it bundles, but never SSPL or CC-BY-SA) →
 *      suppressed, workspace.copyleft_suppressed[i]. A path match without family
 *      justification falls through to the normal default chain.
 *   4. Defaults: copyleft → fail (default:copyleft, reason names the elected
 *      expression and the occurrence target); unknown finding →
 *      policy.unknownHandling as warn or fail (default:unknown); otherwise ok
 *      (default:ok).
 *   Clarify sits above all of these by having already replaced the finding in
 *   annotateFindings; a clarified package whose verdict falls through to
 *   default:ok cites clarify[i] instead, so usage stays visible.
 *
 * Every verdict-affecting match is exact-ID or satisfies-based — package rules
 * compare name/version by string equality, license rules go through
 * spdx-satisfies on validated allowlists (never re-parsed, never
 * substring-matched), suppression paths match segment-aware
 * (`target === path || target.startsWith(path + "/")`), and every verdict
 * carries a machine-readable rule id plus a reason naming the deciding input.
 */
import parseSpdx from "spdx-expression-parse";
import satisfies from "spdx-satisfies";

import {
  compareCodeUnits,
  type CanonicalDependencies,
  type Occurrence,
  type PackageEntry,
  type Verdict,
} from "../model/dependencies";
import {
  copyleftLeafIds,
  elect,
  isCopyleft,
  renderNode,
  type ExpressionNode,
} from "../normalize/expression";
import { BUILTIN_DENY_RULE_ID } from "./builtinDenylist";
import { COPYLEFT_FAMILY } from "./copyleft";
import {
  COULD_BE_COPYLEFT_FAMILIES,
  WORKSPACE_ABSORBS,
} from "./copyleftFamily";
import { denyRuleFor, type IndexedDenyRule } from "./denylist";
import type {
  CompatibleLicenseRule,
  CompatiblePackageRule,
  Policy,
  SuppressedWorkspace,
} from "./schema";

/** Per-package facts computed once before the per-occurrence walk. */
interface Assessment {
  /** Full normalized expression; null = unknown OR imprecise (incl. defensive parse failure). */
  expression: string | null;
  /** Rendered elected branch; null when unknown/imprecise. */
  elected: string | null;
  /** Elected AST node (suppression walks its copyleft leaves). */
  electedNode: ExpressionNode | null;
  /** isCopyleft on the elected node — the elected branch decides. */
  copyleft: boolean;
  /**
   * The imprecise family token (INV-04) when the finding is imprecise, else
   * undefined. An imprecise finding has expression null so it never reaches
   * satisfies(); this field routes it to the present-but-needs-clarify lane.
   */
  impreciseFamily?: string;
}

const UNKNOWN_ASSESSMENT: Assessment = {
  expression: null,
  elected: null,
  electedNode: null,
  copyleft: false,
};

/**
 * Parse the finding's expression once and derive election + copyleft flag.
 * The expression was produced by the normalizer (or validated policy schema
 * via clarify), so it parses by construction; the defensive catch keeps the
 * never-throws posture by degrading to unknown instead of crashing the run.
 *
 * An imprecise finding (confidence "imprecise", expression null) branches out
 * BEFORE the null-expression unknown fallback so its family is carried to the
 * present-but-needs-clarify lane — it must never be conflated with genuine
 * unknown and never reach satisfies() (it has no valid expression).
 */
function assessPackage(entry: PackageEntry): Assessment {
  const finding = entry.finding;
  if (finding?.confidence === "imprecise") {
    return { ...UNKNOWN_ASSESSMENT, impreciseFamily: finding.impreciseFamily };
  }
  const expression = finding?.expression ?? null;
  if (expression === null) return UNKNOWN_ASSESSMENT;
  try {
    const node = parseSpdx(expression) as ExpressionNode;
    const electedNode = elect(node);
    return {
      expression,
      elected: renderNode(electedNode),
      electedNode,
      copyleft: isCopyleft(electedNode),
    };
  } catch {
    return UNKNOWN_ASSESSMENT;
  }
}

interface IndexedRule<T> {
  index: number;
  rule: T;
}

/** First compatible package rule matching exact name (+ version when pinned). */
function packageRuleFor(
  entry: PackageEntry,
  policy: Policy,
): IndexedRule<CompatiblePackageRule> | undefined {
  for (const [index, rule] of policy.compatible.entries()) {
    if (
      rule.match === "package" &&
      rule.name === entry.name &&
      (rule.version === undefined || rule.version === entry.version)
    ) {
      return { index, rule };
    }
  }
  return undefined;
}

/**
 * First compatible license rule whose pre-decomposed allowlist satisfies the
 * finding's expression. The allowlist was validated and decomposed by the
 * schema — the pattern is never re-parsed here; the catch is purely defensive
 * (never-throws posture).
 */
function licenseRuleFor(
  expression: string,
  policy: Policy,
): IndexedRule<CompatibleLicenseRule> | undefined {
  for (const [index, rule] of policy.compatible.entries()) {
    if (rule.match !== "license") continue;
    let matched: boolean;
    try {
      matched = satisfies(expression, [...rule.allowlist]);
    } catch {
      matched = false;
    }
    if (matched) return { index, rule };
  }
  return undefined;
}

/**
 * Segment-aware suppression match: a target matches a suppressed path only when
 * it is the path or sits under it as a whole segment — "apps/scratch-helper"
 * never matches "apps/scratch". This is the only prefix comparison in the
 * engine; license values are never substring-matched anywhere.
 */
function suppressionFor(
  target: string,
  policy: Policy,
): IndexedRule<SuppressedWorkspace> | undefined {
  for (const [index, rule] of policy.suppressedWorkspaces.entries()) {
    if (target === rule.path || target.startsWith(rule.path + "/")) {
      return { index, rule };
    }
  }
  return undefined;
}

/**
 * Family-aware suppression justification: a path match alone is not enough —
 * the finding's copyleft obligations must be ABSORBABLE by the workspace's own
 * declared license. Returns the verified-relationship text for the audit-trail
 * reason, or undefined when suppression is unjustified (the verdict then falls
 * through the normal default chain).
 *
 * Minimal sound rule, two branches:
 *   (a) the elected expression satisfies the workspace license itself
 *       (spdx-satisfies against the single-ID allowlist [rule.license]);
 *   (b) ABSORB-ALL (revision F): every copyleft leaf of the elected expression
 *       is in a finding-family the workspace's license family ABSORBS, per the
 *       literal WORKSPACE_ABSORBS relation (COPYLEFT_FAMILY exact-ID lookups,
 *       never substring). A workspace re-released under strong copyleft absorbs
 *       the inbound-compatible weaker copyleft it bundles — an AGPL-3.0-only
 *       (GNU-family) workspace absorbs GNU (GPL/LGPL/AGPL) AND MPL findings, but
 *       the SAFETY FLOOR (absence from the absorbed set) still excludes SSPL and
 *       CC-BY-SA. Absorption is directional/declared, not symmetric: a non-AGPL
 *       workspace family absorbs only what WORKSPACE_ABSORBS declares for it.
 * The catches are defensive (never-throws posture); rule.license was validated
 * as a single SPDX ID by the schema.
 */
function suppressionJustification(
  electedNode: ExpressionNode,
  elected: string,
  rule: SuppressedWorkspace,
): string | undefined {
  try {
    if (satisfies(elected, [rule.license])) {
      return `elected "${elected}" satisfies the workspace license ${rule.license}`;
    }
  } catch {
    // defensive: fall through to the family check
  }
  let workspaceLeaf: string | undefined;
  try {
    const node = parseSpdx(rule.license) as ExpressionNode;
    if ("license" in node) workspaceLeaf = node.license;
  } catch {
    workspaceLeaf = undefined;
  }
  if (workspaceLeaf === undefined) return undefined;
  const workspaceFamily = COPYLEFT_FAMILY.get(workspaceLeaf);
  if (workspaceFamily === undefined) return undefined;
  const absorbed = WORKSPACE_ABSORBS.get(workspaceFamily);
  if (absorbed === undefined) return undefined;
  const leaves = copyleftLeafIds(electedNode);
  if (leaves.length === 0) return undefined;
  const leafFamilies = leaves.map((id) => COPYLEFT_FAMILY.get(id));
  if (
    !leafFamilies.every(
      (family) => family !== undefined && absorbed.has(family),
    )
  ) {
    return undefined;
  }
  if (leafFamilies.every((family) => family === workspaceFamily)) {
    return (
      `every copyleft obligation in elected "${elected}" is in the same ` +
      `${workspaceFamily} family as the workspace license ${rule.license}`
    );
  }
  return (
    `every copyleft obligation in elected "${elected}" is in an ` +
    `inbound-compatible family absorbed by the ${workspaceFamily} workspace ` +
    `license ${rule.license}`
  );
}

/** Same matching as annotateFindings: first clarify rule for this package. */
function clarifyIndexFor(entry: PackageEntry, policy: Policy): number {
  return policy.clarify.findIndex(
    (rule) =>
      rule.name === entry.name &&
      (rule.version === undefined || rule.version === entry.version),
  );
}

/**
 * Verdict for an imprecise finding (INV-04). It never reached satisfies() (null
 * expression) and is never default:copyleft (no parseable leaf). Routing is by
 * the LITERAL COULD_BE_COPYLEFT_FAMILIES token set — NOT a COPYLEFT_FAMILY
 * lookup, which is keyed by exact SPDX ids and returns undefined for a bare
 * family token (silently mis-classifying it as permissive):
 *   - family IN the set (bare GPL/AGPL/LGPL) → flagged-for-review, a warn that
 *     surfaces, rule "default:imprecise-copyleft". Conservative: an imprecise
 *     copyleft family is never silently passed.
 *   - family NOT in the set (a known-permissive family like BSD) → a non-gating
 *     warn, rule "default:imprecise". Surfaced for optional `[[clarify]]`
 *     disambiguation, but never a hard fail purely for being imprecise.
 * Both are status "warn": visible in the summary, non-gating by default.
 */
function impreciseVerdict(
  base: { purl: string; occurrenceTarget: string },
  target: string,
  family: string,
): Verdict {
  if (COULD_BE_COPYLEFT_FAMILIES.has(family)) {
    return {
      ...base,
      status: "warn",
      rule: "default:imprecise-copyleft",
      reason: `imprecise license family "${family}" in "${target}" could carry a copyleft obligation — disambiguate via a [[clarify]] override (not silently passed)`,
    };
  }
  return {
    ...base,
    status: "warn",
    rule: "default:imprecise",
    reason: `imprecise license family "${family}" in "${target}" is present but under-specified — disambiguate the precise SPDX id via a [[clarify]] override`,
  };
}

/**
 * A STALE override (POL-07) FAILS the gate loudly before any other lane: the
 * override's `expects` precondition no longer matches the package's observed
 * signal, so an old assertion could be masking a relicense. The reason names
 * the package, the expected value, and the now-observed value; the rule id is
 * distinct and actionable ("override:stale[clarify|builtin]") telling the
 * maintainer to update or remove the override. Mapped to exit 1 (a
 * compliance-relevant gate failure) via the violations → exitCodeFor mapping —
 * the stale assertion is NEVER applied.
 */
function staleVerdict(
  base: { purl: string; occurrenceTarget: string },
  entry: PackageEntry,
  stale: NonNullable<PackageEntry["finding"]>["staleOverride"],
): Verdict {
  const s = stale as NonNullable<typeof stale>;
  const observed = s.observed.length > 0 ? s.observed.join(", ") : "(unknown)";
  return {
    ...base,
    status: "fail",
    rule: `override:stale[${s.level}]`,
    reason:
      `STALE override on "${entry.name}@${entry.version}": expected to ` +
      `observe "${s.expected}" but now observes "${observed}" — the ` +
      `disambiguation was NOT applied (a stale override could mask a ` +
      `relicense). Update or remove the ${s.level} override.`,
  };
}

/**
 * Citation for an override that fell through to the default:ok lane (POL-07).
 * A project clarify (clarifyIndexFor !== -1) keeps its "clarify[i]" citation; a
 * tool-level builtin (no clarify entry) cites the distinct "override:builtin[i]"
 * rule id it carries — never plain default:ok, so a shipped disambiguation
 * stays auditable. Returns undefined when this is not an override-decided
 * verdict (the caller then falls through to default:ok).
 */
function overrideCitation(
  entry: PackageEntry,
  base: { purl: string; occurrenceTarget: string },
  target: string,
  expression: string | null,
  policy: Policy,
): Verdict | undefined {
  if (entry.finding?.source !== "override") return undefined;
  const clarifyIndex = clarifyIndexFor(entry, policy);
  if (clarifyIndex !== -1) {
    const rule = policy.clarify[clarifyIndex];
    if (rule !== undefined) {
      return {
        ...base,
        status: "ok",
        rule: `clarify[${clarifyIndex}]`,
        reason: `clarified to "${expression}": ${rule.reason}`,
      };
    }
  }
  const overrideRule = entry.finding.overrideRule;
  if (overrideRule !== undefined) {
    return {
      ...base,
      status: "ok",
      rule: overrideRule,
      reason: `disambiguated to "${expression}" by a shipped tool-level override in "${target}"`,
    };
  }
  return undefined;
}

/**
 * Per-occurrence dev-scope downgrade (POL-08), applied ONLY to a verdict that
 * would otherwise be a default FAIL (default:copyleft, or default:unknown when
 * unknownHandling="fail"). Keyed STRICTLY on occurrence.isDevDependency:
 *   - a PRODUCTION occurrence → the fail is returned UNCHANGED (the load-bearing
 *     safety property — a shipped copyleft/unknown can never be dev-downgraded).
 *   - a DEV occurrence branches on policy.devDependencies:
 *       "fail"   → no downgrade (gate dev exactly like prod, pre-POL-08).
 *       "warn"   → status "warn", reason appends the auditable dev-only cause,
 *                  rule id PRESERVED so the origin stays traceable.
 *       "ignore" → status "ok", reason names the explicit dev-only opt-out.
 * Higher-precedence lanes (suppression, compatible, clarify, stale, imprecise)
 * never reach this helper — it sits at the would-be default-FAIL terminals only.
 */
function applyDevScope(
  failVerdict: Verdict,
  occurrence: Occurrence,
  policy: Policy,
): Verdict {
  if (!occurrence.isDevDependency) return failVerdict;
  const handling = policy.devDependencies;
  if (handling === "fail") return failVerdict;
  if (handling === "ignore") {
    return {
      ...failVerdict,
      status: "ok",
      reason: `${failVerdict.reason} — dev-only occurrence ignored (dev_dependencies=ignore)`,
    };
  }
  return {
    ...failVerdict,
    status: "warn",
    reason: `${failVerdict.reason} — downgraded to warn: dev-only occurrence (dev_dependencies=warn)`,
  };
}

/**
 * Package-level os-scope downgrade (COLL-04), applied ONLY to a verdict that
 * would otherwise be a default FAIL (default:copyleft, or default:unknown when
 * unknownHandling="fail"). Keyed STRICTLY on the PACKAGE-level entry.scope ===
 * "os" (distinct from applyDevScope's occurrence-level isDevDependency):
 *   - an APP-scope package → the fail is returned UNCHANGED (the os knob never
 *     touches app dependencies).
 *   - an OS-scope package branches on policy.osDependencies:
 *       "fail"   → no downgrade (an os-scope copyleft gates like an app one).
 *       "warn"   → status "warn", reason appends the auditable os-scope cause,
 *                  rule id PRESERVED so the origin stays traceable.
 *       "ignore" → status "ok", reason names the explicit os-only opt-out.
 * Deny is terminal-0 above this helper (denyVerdict returns first in
 * verdictFor), so a denied OS package is never reached here.
 */
function applyOsScope(
  failVerdict: Verdict,
  entry: PackageEntry,
  policy: Policy,
): Verdict {
  if (entry.scope !== "os") return failVerdict;
  const handling = policy.osDependencies;
  if (handling === "fail") return failVerdict;
  if (handling === "ignore") {
    return {
      ...failVerdict,
      status: "ok",
      reason: `${failVerdict.reason} — os-scope base-image package ignored (os_dependencies=ignore)`,
    };
  }
  return {
    ...failVerdict,
    status: "warn",
    reason: `${failVerdict.reason} — downgraded to warn: os-scope base-image package (os_dependencies=warn)`,
  };
}

/**
 * Compose the two scope downgraders at a would-be-default-FAIL terminal. The os
 * lane runs FIRST so an os-scope package is owned by os_dependencies; the dev
 * lane runs on the result, but the two never interact: an os-scope package is
 * never a dev OCCURRENCE in the app sense, and an app package never routes
 * through the os lane. Applying os-then-dev keeps an os-scope copyleft at warn
 * even under dev_dependencies=fail (W1): once os downgrades the fail to warn,
 * applyDevScope's "fail" branch returns that warn unchanged.
 */
function applyScopeDowngrades(
  failVerdict: Verdict,
  entry: PackageEntry,
  occurrence: Occurrence,
  policy: Policy,
): Verdict {
  return applyDevScope(
    applyOsScope(failVerdict, entry, policy),
    occurrence,
    policy,
  );
}

/**
 * Terminal-0 deny resolution (POL-09 + C#1 + #1/#5/#11). Returns the first
 * matching deny rule, checking, in order:
 *   1. the COMBINED assessment expression (name-mode also matches entry.name) —
 *      OR-election over the union of license deny allowlists;
 *   2. the PRE-OVERRIDE observedExpression (C#1) — a denied observed license an
 *      override rewrote can never be licensed back in;
 *   3. EVERY observed per-claim precise expression (#1/#5/#11) — a denied member
 *      combineKnown dropped via imprecise-family election / unknown collapse is
 *      still seen, in every scope.
 * Checks 2–3 pass null as the name so they consult the LICENSE allowlist only
 * (name-mode already had its chance against entry.name in check 1) — a per-claim
 * expression must never re-trigger a name-mode rule. Defensive: a finding with no
 * observed expressions simply skips check 3.
 */
function firstDeny(
  policy: Policy,
  entry: PackageEntry,
  expression: string | null,
): IndexedDenyRule | undefined {
  const combined = denyRuleFor(policy, expression, entry.name);
  if (combined !== undefined) return combined;
  const observed = entry.finding?.observedExpression;
  if (observed !== undefined) {
    const hit = denyRuleFor(policy, observed, entry.name);
    if (hit !== undefined) return hit;
  }
  for (const obs of entry.finding?.observedExpressions ?? []) {
    const hit = denyRuleFor(policy, obs, entry.name);
    if (hit !== undefined) return hit;
  }
  return undefined;
}

/**
 * Terminal-0 deny verdict (POL-09). A matched deny rule force-fails the package
 * with the `denied[i]` rule id and a reason naming the matched license/pattern
 * and the source-available rationale. It is a `fail` → mapped to a violation
 * (exit 1) by the existing violations → exitCodeFor mapping. This sits ABOVE
 * every other lane (incl. stale), so applyDevScope is never reached for a denied
 * verdict — a dev-only occurrence of a denied license still FAILS.
 */
function denyVerdict(
  base: { purl: string; occurrenceTarget: string },
  denyRule: IndexedDenyRule,
): Verdict {
  const { ruleId, rule } = denyRule;
  const what =
    rule.match === "license"
      ? `license pattern "${rule.pattern}"`
      : `package name "${rule.pattern}"`;
  return {
    ...base,
    status: "fail",
    rule: ruleId,
    reason:
      `DENIED by ${what}: ${rule.reason} — a use-restricted / ` +
      `source-available license cannot be redistributed in client-shipped ` +
      `artifacts, so no compatible rule, workspace suppression, dev-scope ` +
      `downgrade, or override can license it back in (deny is terminal).`,
  };
}

/**
 * Source-available exemption (ADR-0021). When the terminal-0 deny that matched is
 * a SHIPPED source-available default (cited default:source-available — NOT the
 * consumer's own [[deny]]) AND the consumer listed that licence under
 * [[allow_source_available]], the package is NOT force-failed: it surfaces as a
 * WARN citing the exemption, so an accepted source-available licence stays visible
 * rather than silently passing. An explicit [[deny]] still wins — denyRuleFor
 * attributes a policy deny first (policy-first order), so denyRule is never the
 * builtin id when the consumer also denied the licence themselves.
 */
function sourceAvailableExemption(
  policy: Policy,
  denyRule: IndexedDenyRule,
): { index: number; license: string; reason: string } | undefined {
  if (
    denyRule.ruleId !== BUILTIN_DENY_RULE_ID ||
    denyRule.rule.match !== "license"
  ) {
    return undefined;
  }
  const license = denyRule.rule.pattern;
  const index = policy.allowSourceAvailable.findIndex(
    (entry) => entry.license === license,
  );
  if (index === -1) return undefined;
  return { index, license, reason: policy.allowSourceAvailable[index]!.reason };
}

/** Warn verdict for an exempted source-available licence (ADR-0021). */
function exemptionVerdict(
  base: { purl: string; occurrenceTarget: string },
  exemption: { index: number; license: string; reason: string },
): Verdict {
  return {
    ...base,
    status: "warn",
    rule: `allow_source_available[${exemption.index}]`,
    reason:
      `source-available license "${exemption.license}" is ALLOWED by an ` +
      `explicit policy exemption: ${exemption.reason} — surfaced as a warning ` +
      `because it is source-available and would otherwise fail by default.`,
  };
}

/**
 * Terminal-0 verdict for a matched deny: a force-fail, UNLESS the match is a
 * shipped source-available default the consumer exempted (ADR-0021), which
 * surfaces as a warn instead. An explicit [[deny]] is never the builtin id (it is
 * attributed first), so this never softens a deny the consumer authored.
 */
function denyOrExemptVerdict(
  base: { purl: string; occurrenceTarget: string },
  policy: Policy,
  denyRule: IndexedDenyRule,
): Verdict {
  const exemption = sourceAvailableExemption(policy, denyRule);
  if (exemption !== undefined) return exemptionVerdict(base, exemption);
  return denyVerdict(base, denyRule);
}

/**
 * Default:unknown verdict for a null-expression finding. The dev-scope
 * downgrade applies ONLY to a would-be FAIL: a default:unknown already "warn"
 * (unknownHandling="warn") is non-gating and is never downgraded.
 */
function unknownVerdict(
  base: { purl: string; occurrenceTarget: string },
  entry: PackageEntry,
  occurrence: Occurrence,
  policy: Policy,
): Verdict {
  const verdict: Verdict = {
    ...base,
    status: policy.unknownHandling,
    rule: "default:unknown",
    reason: `license of "${entry.name}@${entry.version}" is unknown in "${occurrence.target}" ([unknown] handling = "${policy.unknownHandling}")`,
  };
  return policy.unknownHandling === "fail"
    ? applyScopeDowngrades(verdict, entry, occurrence, policy)
    : verdict;
}

/** Walk the precedence chain for one (package × occurrence). */
function verdictFor(
  entry: PackageEntry,
  occurrence: Occurrence,
  assessment: Assessment,
  packageRule: IndexedRule<CompatiblePackageRule> | undefined,
  licenseRule: IndexedRule<CompatibleLicenseRule> | undefined,
  denyRule: IndexedDenyRule | undefined,
  policy: Policy,
): Verdict {
  const target = occurrence.target;
  const base = { purl: entry.purl, occurrenceTarget: target };

  // Terminal-0: a denied license/rider can never be licensed back in — UNLESS the
  // matched deny is a shipped source-available default the consumer exempted via
  // [[allow_source_available]] (ADR-0021), which surfaces as a warn instead.
  if (denyRule !== undefined) {
    return denyOrExemptVerdict(base, policy, denyRule);
  }

  const stale = entry.finding?.staleOverride;
  if (stale !== undefined) return staleVerdict(base, entry, stale);

  if (packageRule !== undefined) {
    const { index, rule } = packageRule;
    const pin = rule.version === undefined ? "" : `@${rule.version}`;
    return {
      ...base,
      status: "ok",
      rule: `compatible[${index}]`,
      reason: `package "${rule.name}${pin}" accepted by compatible package rule: ${rule.reason}`,
    };
  }

  if (licenseRule !== undefined) {
    const { index, rule } = licenseRule;
    return {
      ...base,
      status: "ok",
      rule: `compatible[${index}]`,
      reason: `"${assessment.expression}" satisfies compatible license pattern "${rule.pattern}": ${rule.reason}`,
    };
  }

  if (assessment.copyleft) {
    const suppression = suppressionFor(target, policy);
    if (
      suppression !== undefined &&
      assessment.electedNode !== null &&
      assessment.elected !== null
    ) {
      const { index, rule } = suppression;
      const justification = suppressionJustification(
        assessment.electedNode,
        assessment.elected,
        rule,
      );
      if (justification !== undefined) {
        return {
          ...base,
          status: "suppressed",
          rule: `workspace.copyleft_suppressed[${index}]`,
          reason: `copyleft "${assessment.elected}" suppressed in "${target}": ${justification} — workspace "${rule.path}" (${rule.description})`,
        };
      }
    }
    return applyScopeDowngrades(
      {
        ...base,
        status: "fail",
        rule: "default:copyleft",
        reason: `copyleft license "${assessment.elected}" (from "${assessment.expression}") is not allowed in "${target}" and no compatible rule or workspace suppression applies`,
      },
      entry,
      occurrence,
      policy,
    );
  }

  if (assessment.impreciseFamily !== undefined) {
    return impreciseVerdict(base, target, assessment.impreciseFamily);
  }

  if (assessment.expression === null) {
    return unknownVerdict(base, entry, occurrence, policy);
  }

  const citation = overrideCitation(
    entry,
    base,
    target,
    assessment.expression,
    policy,
  );
  if (citation !== undefined) return citation;

  return {
    ...base,
    status: "ok",
    rule: "default:ok",
    reason: `"${assessment.expression}" (elected "${assessment.elected}") carries no copyleft obligation in "${target}"`,
  };
}

/**
 * Pure. Precondition: model.packages carry `finding` (annotateFindings ran); a
 * missing finding is treated as unknown — defensive, documented. Returns one
 * verdict per (package × occurrence), sorted compareCodeUnits on (purl,
 * occurrenceTarget).
 */
export function evaluate(
  model: CanonicalDependencies,
  policy: Policy,
): Verdict[] {
  const verdicts: Verdict[] = [];
  for (const entry of model.packages) {
    const assessment = assessPackage(entry);
    // Per-package matches computed once; they apply to every occurrence
    // (a compatible rule accepts the package everywhere).
    const packageRule = packageRuleFor(entry, policy);
    const licenseRule =
      packageRule === undefined && assessment.expression !== null
        ? licenseRuleFor(assessment.expression, policy)
        : undefined;
    // Terminal-0 deny match computed once per package: license-mode reads the
    // assessment expression (OR-election), name-mode the package name (works
    // even when the expression is null — the use-restriction rider case).
    //
    // C#1 — deny terminal OVER overrides: an override may have rewritten a
    // denied OBSERVED license (e.g. BUSL-1.1 → MIT) into the assessment
    // expression. Deny must ALSO consult the PRE-OVERRIDE observed expression;
    // if EITHER the observed or the (possibly-overridden) finding expression is
    // denied, deny fires. A denied observed license can never be licensed back
    // in by any override (deny is terminal over overrides).
    //
    // #1/#5/#11 — deny sees EVERY observed claim: combineKnown elects an
    // imprecise family / collapses to unknown BEFORE a precise non-copyleft
    // DENIED member (BUSL-1.1, Elastic-2.0 — source-available) when an imprecise
    // family token or an unknown token co-exists, so the combined expression is
    // null/imprecise and the two checks above never see the denied member. Deny
    // therefore ALSO consults the SET of every observed per-claim precise
    // expression (finding.observedExpressions): if ANY observed expression is
    // denied, deny fires — regardless of how combine rendered the finding
    // (precise/imprecise/unknown), in EVERY scope. Name-mode (passed null here)
    // is inert per observed expression — it already matched via entry.name above.
    const denyRule = firstDeny(policy, entry, assessment.expression);
    for (const occurrence of entry.occurrences) {
      verdicts.push(
        verdictFor(
          entry,
          occurrence,
          assessment,
          packageRule,
          licenseRule,
          denyRule,
          policy,
        ),
      );
    }
  }
  return verdicts.sort(
    (a, b) =>
      compareCodeUnits(a.purl, b.purl) ||
      compareCodeUnits(a.occurrenceTarget, b.occurrenceTarget),
  );
}

/**
 * Rule ids of compatible/clarify entries that never decided anything —
 * stale-policy hygiene. Compatible usage is read from cited verdict rules;
 * clarify usage comes from annotateFindings' usedClarifyIndices (a clarify rule
 * is "used" when it replaced a finding, even if a higher-precedence compatible
 * rule decided the final verdict). Suppression entries are never reported.
 * Returned in TOML array order: compatible first, then clarify.
 */
export function unusedRuleIds(
  policy: Policy,
  verdicts: ReadonlyArray<Verdict>,
  usedClarifyIndices: ReadonlySet<number>,
): string[] {
  const cited = new Set(verdicts.map((v) => v.rule));
  const unused: string[] = [];
  policy.compatible.forEach((_, index) => {
    const id = `compatible[${index}]`;
    if (!cited.has(id)) unused.push(id);
  });
  policy.clarify.forEach((_, index) => {
    if (!usedClarifyIndices.has(index)) unused.push(`clarify[${index}]`);
  });
  return unused;
}
