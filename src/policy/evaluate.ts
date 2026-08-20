/**
 * Pure policy engine: evaluate(model, policy) → Verdict[].
 *
 * Pure fold over the model - no I/O, no fs/process, no logging, no CycloneDX knowledge; the CLI
 * owns file reads and stderr. Identical model + policy always produce the identical Verdict[],
 * sorted compareCodeUnits on (purl, occurrenceTarget).
 *
 * Precondition: model.packages carry `finding` (annotateFindings ran). A missing finding is treated
 * as unknown - defensive, never throws.
 *
 * Precedence per (package × occurrence), highest → lowest:
 *   0. Deny - denyRuleFor matches the finding's expression (license mode, electing over the union
 *      of all license deny allowlists - see docs/glossary.md#election - so an OR across separate
 *      deny entries is denied; an OR finding with a branch electable out of the union is not
 *      denied) or the package name (name mode, for non-SPDX use-restriction riders like
 *      Commons-Clause) → fail, denied[i], terminal. Deny also consults the pre-override observed
 *      expression (finding.observedExpression): if either the observed or the possibly-overridden
 *      finding expression is denied, deny fires, so a denied observed license can never be licensed
 *      back in by an override that rewrites it. Deny sits above every accept lever, and above the
 *      stale-override lane: a use-restricted / source-available license can never be licensed back
 *      in by a compatible rule, a workspace suppression, the dev-scope downgrade, a stale override,
 *      or a successfully-applied override. Name-mode deny does not require a parseable expression,
 *      so an unknown-finding rider still fails.
 *   1. compatible match="package" (exact name, exact version when the rule pins one) → ok,
 *      compatible[i] - excluded from copyleft flagging everywhere.
 *   2. compatible match="license": satisfies(finding.expression, rule.allowlist) against the
 *      pre-decomposed allowlist from schema validation → ok, compatible[i].
 *   3. The target-compatibility lane (targetLaneVerdict / targetVerdict, wiring policy/target.ts's
 *      resolveTargetProfile into compat/classify.ts's classifyExpression) - active only when BOTH a
 *      governing target profile resolves for this occurrence AND the finding has a parseable
 *      (non-imprecise, non-null) expression; os-scope packages never enter this lane. Five
 *      outcomes: compatible → overrideCitation ?? target:ok; held-internal (a
 *      copyleft/AGPL obligation the usage profile takes out of scope) → ok target:internal-use;
 *      boundary → warn target:boundary; incompatible → fail target:incompatible (dev-downgraded via
 *      applyDevScope); a matrix-uncovered pair → the unknown_pair knob (warn/fail, fail also
 *      dev-downgraded). A ref-carrying elected branch (under the target-aware election) instead
 *      falls through to the unchanged unknown lane below, never target:ok. Absent a governing
 *      profile, or on an imprecise/null finding, this lane is a no-op and today's walk is
 *      byte-identical.
 *   4. copyleft-flagged (isCopyleft on the elected branch - an OR with a permissive branch elects
 *      the permissive branch and is not copyleft) and the occurrence target is or is under a
 *      suppressed path and the suppression is family-justified (the elected expression satisfies
 *      the workspace's declared license, or every copyleft leaf in it is in a finding-family the
 *      workspace license family absorbs per the literal WORKSPACE_ABSORBS relation - an AGPL-3.0
 *      workspace absorbs GNU-family GPL/LGPL deps and MPL deps it bundles, but never SSPL or
 *      CC-BY-SA) → suppressed, workspace.copyleft_suppressed[i]. A path match without family
 *      justification falls through to the normal default chain. A target-governed occurrence never
 *      reaches this tier at all (tier 3 above decides it first), so a suppression entry a target
 *      governs is effectively dead there - see policy/target.ts's suppressionOverlapNotices.
 *   5. Defaults: copyleft → fail (default:copyleft, reason names the elected expression and the
 *      occurrence target; an os-scope AGPL leaf escalates to default:agpl-container unless a
 *      complete project target profile declares network = false, which demotes it to the routine
 *      would-be default:copyleft fail instead, the reason naming the declared basis); unknown
 *      finding → policy.unknownHandling as warn or fail (default:unknown); elected content that
 *      still carries a LicenseRef-/DocumentRef- leaf after election (a bare ref, or an AND that
 *      keeps one alongside a known conjunct) → same default:unknown handling, never default:ok
 *      - its content is unknowable to the tool; otherwise ok (default:ok).
 *   Clarify sits above all of these by having already replaced the finding in annotateFindings; a
 *   clarified package whose verdict falls through to
 *   default:ok cites clarify[i] instead, so usage stays visible.
 *
 * Every verdict-affecting match is exact-ID or satisfies-based - package rules compare name/version
 * by string equality, license rules go through spdx-satisfies on validated allowlists (never
 * re-parsed, never substring-matched), suppression paths match segment-aware (`target === path ||
 * target.startsWith(path + "/")`), and every verdict carries a machine-readable rule id plus a
 * reason naming the deciding input.
 *
 * The normative decision tree is docs/reference/dependency-classification.md - update both
 * together.
 */
import parseSpdx from "spdx-expression-parse";
import satisfies from "spdx-satisfies";

import {
  compareCodeUnits,
  matchesIdentityPrefix,
  type AssessmentConflict,
  type CanonicalDependencies,
  type Occurrence,
  type PackageEntry,
  type StaleOverride,
  type Verdict,
} from "../model/dependencies";
import {
  copyleftLeafIds,
  elect,
  hasRefLeaf,
  isCopyleft,
  renderNode,
  type ExpressionNode,
} from "../normalize/expression";
import { BUILTIN_DENY_RULE_ID } from "./builtinDenylist";
import {
  classifyExpression,
  formatProfileLabel,
  targetBoundaryReason,
  targetIncompatibleReason,
  targetInternalUseReason,
  targetOkReason,
  targetUnknownPairReason,
  TARGET_RULE_BOUNDARY,
  TARGET_RULE_INCOMPATIBLE,
  TARGET_RULE_INTERNAL_USE,
  TARGET_RULE_OK,
  TARGET_RULE_UNKNOWN_PAIR,
  type ReasonContext,
  type TargetProfile,
} from "./compat";
import { AGPL_IDS, COPYLEFT_FAMILY } from "./copyleft";
import { COULD_BE_COPYLEFT_FAMILIES, WORKSPACE_ABSORBS } from "./copyleftFamily";
import { denyRuleFor, type IndexedDenyRule } from "./denylist";
import { matchesPackage } from "./packageMatch";
import { resolveTargetProfile } from "./target";
import {
  EVERYWHERE_SCOPE,
  ruleReason,
  type CompatibleLicenseRule,
  type CompatiblePackageRule,
  type CompatibleRule,
  type Policy,
  type SuppressedWorkspace,
} from "./schema";

/** Per-package facts computed once before the per-occurrence walk. */
interface Assessment {
  /** Full normalized expression; null = unknown OR imprecise (incl. defensive parse failure). */
  expression: string | null;
  /** Rendered elected branch; null when unknown/imprecise. */
  elected: string | null;
  /**
   * Elected AST node (suppression walks its copyleft leaves; the verdict walk also checks it for a
   * surviving LicenseRef-/DocumentRef- leaf).
   */
  electedNode: ExpressionNode | null;
  /**
   * The PRE-election parsed node - null exactly when `electedNode` is null. The target lane's
   * classifyExpression needs the raw tree, never the already-elected branch: elect()'s own
   * non-target-aware preference can discard the branch a target-aware election would have picked
   * (the Apache-2.0-vs-GPL-2.0-only counterexample - see compat/classify.ts's module doc), so
   * feeding it the post-election node would silently pre-discard what the lane exists to recover.
   * Inert when no target is declared - nothing else reads it.
   */
  rawNode: ExpressionNode | null;
  /** isCopyleft on the elected node - the elected branch decides. */
  copyleft: boolean;
  /**
   * The imprecise family token when the finding is imprecise, else undefined. An imprecise finding
   * has expression null so it never reaches satisfies(); this field routes it to the
   * present-but-needs-clarify lane.
   */
  impreciseFamily?: string;
}

const UNKNOWN_ASSESSMENT: Assessment = {
  expression: null,
  elected: null,
  electedNode: null,
  rawNode: null,
  copyleft: false,
};

/**
 * Parse the finding's expression once and derive election + copyleft flag. The expression was
 * produced by the normalizer (or validated policy schema via clarify), so it parses by
 * construction; the defensive catch keeps the never-throws posture by degrading to unknown instead
 * of crashing the run.
 *
 * An imprecise finding (confidence "imprecise", expression null) branches out before the
 * null-expression unknown fallback so its family is carried to the present-but-needs-clarify lane
 * - it must never be conflated with genuine unknown and never reach satisfies() (it has no valid
 * expression).
 */
function assessPackage(entry: PackageEntry): Assessment {
  const finding = entry.finding;

  if (finding?.confidence === "imprecise") {
    return { ...UNKNOWN_ASSESSMENT, impreciseFamily: finding.impreciseFamily };
  }

  const expression = finding?.expression ?? null;

  if (expression === null) {
    return UNKNOWN_ASSESSMENT;
  }

  try {
    const node = parseSpdx(expression) as ExpressionNode;
    const electedNode = elect(node);

    return {
      expression,
      elected: renderNode(electedNode),
      electedNode,
      rawNode: node,
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

/**
 * A compatible rule applies at a target iff some `where` entry is the everywhere token, or some
 * `where` entry covers the target as an identity prefix.
 */
function appliesAt(rule: CompatibleRule, target: string): boolean {
  return rule.where.some(
    (path) => path === EVERYWHERE_SCOPE || matchesIdentityPrefix(target, path),
  );
}

/**
 * First compatible package rule whose selector covers the package and whose `where` scope covers
 * the occurrence target.
 */
function packageRuleFor(
  entry: PackageEntry,
  target: string,
  policy: Policy,
): IndexedRule<CompatiblePackageRule> | undefined {
  for (const [index, rule] of policy.compatible.entries()) {
    if (rule.match === "package" && matchesPackage(rule, entry) && appliesAt(rule, target)) {
      return { index, rule };
    }
  }

  return undefined;
}

/**
 * First compatible license rule whose pre-decomposed allowlist satisfies the finding's expression
 * and whose `where` scope covers the occurrence target. The allowlist was validated and decomposed
 * by the schema - the pattern is never re-parsed here; the catch is purely defensive (never-throws
 * posture).
 */
function licenseRuleFor(
  expression: string,
  target: string,
  policy: Policy,
): IndexedRule<CompatibleLicenseRule> | undefined {
  for (const [index, rule] of policy.compatible.entries()) {
    if (rule.match !== "license" || !appliesAt(rule, target)) {
      continue;
    }

    let matched: boolean;

    try {
      matched = satisfies(expression, [...rule.allowlist]);
    } catch {
      matched = false;
    }

    if (matched) {
      return { index, rule };
    }
  }

  return undefined;
}

/**
 * Segment-aware suppression match (delegates to matchesIdentityPrefix - the same comparison
 * compatible `where` scopes use).
 */
function suppressionFor(
  target: string,
  policy: Policy,
): IndexedRule<SuppressedWorkspace> | undefined {
  for (const [index, rule] of policy.suppressedWorkspaces.entries()) {
    if (matchesIdentityPrefix(target, rule.path)) {
      return { index, rule };
    }
  }

  return undefined;
}

/**
 * Family-aware suppression justification: a path match alone is not enough - the finding's copyleft
 * obligations must be absorbable by the workspace's own declared license. Returns the
 * verified-relationship text for the audit-trail reason, or undefined when suppression is
 * unjustified (the verdict then falls through the normal default chain).
 *
 * Minimal sound rule, two branches:
 *   (a) the elected expression satisfies the workspace license itself
 *       (spdx-satisfies against the single-ID allowlist [rule.license]);
 *   (b) absorb-all: every copyleft leaf of the elected expression
 *       is in a finding-family the workspace's license family absorbs, per the literal
 *       WORKSPACE_ABSORBS relation (COPYLEFT_FAMILY exact-ID lookups, never substring). A workspace
 *       re-released under strong copyleft absorbs the inbound-compatible weaker copyleft it bundles
 *       - an AGPL-3.0-only (GNU-family) workspace absorbs GNU (GPL/LGPL/AGPL) and MPL findings, but
 *       the safety floor (absence from the absorbed set) still excludes SSPL and CC-BY-SA.
 *       Absorption is directional/declared, not symmetric: a non-AGPL workspace family absorbs only
 *       what WORKSPACE_ABSORBS declares for it.
 * The catches are defensive (never-throws posture); rule.license was validated as a single SPDX ID
 * by the schema.
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

    if ("license" in node) {
      workspaceLeaf = node.license;
    }
  } catch {
    workspaceLeaf = undefined;
  }

  if (workspaceLeaf === undefined) {
    return undefined;
  }

  const workspaceFamily = COPYLEFT_FAMILY.get(workspaceLeaf);

  if (workspaceFamily === undefined) {
    return undefined;
  }

  const absorbed = WORKSPACE_ABSORBS.get(workspaceFamily);

  if (absorbed === undefined) {
    return undefined;
  }

  const leaves = copyleftLeafIds(electedNode);

  if (leaves.length === 0) {
    return undefined;
  }

  const leafFamilies = leaves.map((id) => COPYLEFT_FAMILY.get(id));

  if (!leafFamilies.every((family) => family !== undefined && absorbed.has(family))) {
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
  return policy.clarify.findIndex((rule) => matchesPackage(rule, entry));
}

/**
 * Verdict for an imprecise finding. It never reached satisfies() (null expression) and is never
 * default:copyleft (no parseable leaf). Routing is by the literal COULD_BE_COPYLEFT_FAMILIES token
 * set, not a COPYLEFT_FAMILY lookup, which is keyed by exact SPDX ids and returns undefined for a
 * bare family token (silently mis-classifying it as permissive):
 *   - os-scope (a container system package, the OS-ecosystem allowlist) and family is the bare
 *     "AGPL" token → fail, rule "default:agpl-container" (checked first - the imprecise mirror of
 *     the elected-AGPL escalation in copyleftVerdict; a bare AGPL label could carry the same
 *     network-copyleft obligation and must never be parked at a warn). An application-ecosystem
 *     container package is scope "app" here (re-keyed upstream) and falls through to the next
 *     branch instead.
 *   - family in the set (bare GPL/AGPL/LGPL) → flagged-for-review, a warn that surfaces, rule
 *     "default:imprecise-copyleft". Conservative: an imprecise copyleft family is never silently
 *     passed.
 *   - family not in the set (a known-permissive family like BSD) → a non-gating warn, rule
 *     "default:imprecise". Surfaced for optional `[[clarify]]` disambiguation, but never a hard
 *     fail purely for being imprecise.
 * The latter two are status "warn": visible in the summary, non-gating by default.
 */
/**
 * The declared-network basis clause appended to a demoted AGPL-container reason: a complete project
 * target profile's `network` flag now OWNS the "containers are network-deployed" applicability fact
 * the AGPL-container heuristic used to guess (the container-design reconciliation) - `network =
 * false` takes the AGPL section-13 obligation out of scope, and the routine os-scope copyleft
 * treatment decides from there.
 */
function declaredNetworkFalseBasis(): string {
  return (
    "the declared target profile's network = false takes the AGPL section-13 obligation out of " +
    "scope (not network-deployed per the declaration) — treated as routine base-image copyleft"
  );
}

/**
 * The imprecise mirror of {@link demotedAgplContainerVerdict}: a bare-`AGPL` os-scope package under
 * a complete project profile with `network = false` demotes to the routine would-be
 * default:copyleft fail (through {@link applyScopeDowngrades}, i.e. `[os_dependencies]`) instead
 * of the escalation, the reason naming the declared basis.
 */
function demotedImpreciseAgplVerdict(
  base: { purl: string; occurrenceTarget: string },
  entry: PackageEntry,
  occurrence: Occurrence,
  target: string,
  policy: Policy,
): Verdict {
  const failVerdict: Verdict = {
    ...base,
    status: "fail",
    rule: "default:copyleft",
    reason: `imprecise license family "AGPL" in container system package "${target}" would normally escalate to the network-copyleft obligation, but ${declaredNetworkFalseBasis()}`,
  };

  return applyScopeDowngrades(failVerdict, entry, occurrence, policy);
}

function impreciseVerdict(
  base: { purl: string; occurrenceTarget: string },
  entry: PackageEntry,
  occurrence: Occurrence,
  family: string,
  policy: Policy,
): Verdict {
  const target = occurrence.target;

  if (entry.scope === "os" && family === "AGPL") {
    const profile = policy.target?.profile;

    if (profile !== undefined && !profile.network) {
      return demotedImpreciseAgplVerdict(base, entry, occurrence, target, policy);
    }

    return {
      ...base,
      status: "fail",
      rule: "default:agpl-container",
      reason: `imprecise license family "AGPL" in container system package "${target}" could carry the AGPL network-copyleft obligation (section 13 reaches server-side use) — disambiguate via a [[clarify]] override, or add a scoped [[compatible]] rule if the container is accepted`,
    };
  }

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

/** What the override recorded and what is seen instead - the fact half of {@link staleVerdict}. */
function staleDivergence(stale: StaleOverride): string {
  const observed = stale.observed.length > 0 ? stale.observed.join(", ") : "(nothing)";

  if (stale.unaccounted !== undefined) {
    return `the ${stale.source} signal reports "${stale.unaccounted}", which the recorded expression does not account for`;
  }

  if (stale.expected === false) {
    return `it recorded no ${stale.source} detection, but ${stale.source} now reports "${observed}"`;
  }

  return stale.observed.length === 0
    ? `it recorded the ${stale.source} detection "${stale.expected}", but there is no current ${stale.source} detection`
    : `it recorded the ${stale.source} detection "${stale.expected}", but ${stale.source} now reports "${observed}"`;
}

/**
 * A stale override fails the gate loudly before any other lane: what the override recorded is no
 * longer what the package shows, so an old assertion could be masking a relicense. The reason names
 * the package and the divergence; the rule id is distinct and actionable
 * ("override:stale[clarify|builtin]") telling the maintainer to update or remove the override.
 * Mapped to exit 1 (a compliance-relevant gate failure) via the violations → exitCodeFor mapping
 * - the stale assertion is never applied.
 */
function staleVerdict(
  base: { purl: string; occurrenceTarget: string },
  entry: PackageEntry,
  stale: NonNullable<PackageEntry["finding"]>["staleOverride"],
): Verdict {
  const s = stale as NonNullable<typeof stale>;

  return {
    ...base,
    status: "fail",
    rule: `override:stale[${s.level}]`,
    reason:
      `STALE override on "${entry.name}@${entry.version}": ${staleDivergence(s)} — the ` +
      `disambiguation was NOT applied (a stale override could mask a ` +
      `relicense). Update or remove the ${s.level} override.`,
  };
}

/**
 * An unresolved ScanCode-vs-quick-check disagreement fails the gate - a warn would recreate the
 * silent-absorption failure mode this verdict exists to prevent. The reason names the package, the
 * in-depth assessed expression, the disagreeing quick-check values, and the [[clarify]] remedy.
 */
function scancodeConflictVerdict(
  base: { purl: string; occurrenceTarget: string },
  entry: PackageEntry,
  conflict: Extract<AssessmentConflict, { kind: "scancode" }>,
): Verdict {
  const disagreeing = conflict.disagreeing.length > 0 ? conflict.disagreeing.join(", ") : "(none)";

  return {
    ...base,
    status: "fail",
    rule: "conflict:scancode",
    reason:
      `ASSESSMENT CONFLICT on "${entry.name}@${entry.version}": the in-depth ` +
      `ScanCode assessment found "${conflict.assessed}" but the declared/registry ` +
      `answer says "${disagreeing}" — resolve via a [[clarify]] override ` +
      `recording your decision (question the quick check, or re-assess).`,
  };
}

/**
 * A cross-image license-claim divergence fails the gate exactly like a ScanCode disagreement - a
 * human must record which image's claim is right. The reason names every diverging image and its
 * claim set (or "no declared license"), and the [[clarify]] remedy.
 */
function crossImageConflictVerdict(
  base: { purl: string; occurrenceTarget: string },
  entry: PackageEntry,
  conflict: Extract<AssessmentConflict, { kind: "cross-image-claims" }>,
): Verdict {
  const perImage = conflict.byTarget
    .map(
      (t) => `${t.target}: ${t.claims.length > 0 ? t.claims.join(", ") : "(no declared license)"}`,
    )
    .join("; ");

  return {
    ...base,
    status: "fail",
    rule: "conflict:cross-image-claims",
    reason:
      `CROSS-IMAGE LICENSE CONFLICT on "${entry.name}@${entry.version}": docker ` +
      `images disagree on its declared license — ${perImage} — resolve via a ` +
      `[[clarify]] override recording your decision.`,
  };
}

/**
 * Dispatch to the matching conflict verdict builder. Both conflict sources share this one gate slot
 * (see verdictFor) - a fail, not a warn, because either kind needs a human decision.
 */
function conflictVerdict(
  base: { purl: string; occurrenceTarget: string },
  entry: PackageEntry,
  conflict: AssessmentConflict,
): Verdict {
  return conflict.kind === "cross-image-claims"
    ? crossImageConflictVerdict(base, entry, conflict)
    : scancodeConflictVerdict(base, entry, conflict);
}

/**
 * Citation for an override that fell through to the default:ok lane. A project clarify
 * (clarifyIndexFor !== -1) keeps its "clarify[i]" citation; a tool-level builtin (no clarify entry)
 * cites the distinct "override:builtin[i]" rule id it carries - never plain default:ok, so a
 * shipped disambiguation stays auditable. Returns undefined when this is not an override-decided
 * verdict (the caller then falls through to default:ok).
 */
function overrideCitation(
  entry: PackageEntry,
  base: { purl: string; occurrenceTarget: string },
  target: string,
  expression: string | null,
  policy: Policy,
): Verdict | undefined {
  if (entry.finding?.source !== "override") {
    return undefined;
  }

  const clarifyIndex = clarifyIndexFor(entry, policy);

  if (clarifyIndex !== -1) {
    const rule = policy.clarify[clarifyIndex];

    if (rule !== undefined) {
      return {
        ...base,
        status: "ok",
        rule: `clarify[${clarifyIndex}]`,
        reason: `clarified to "${expression}": ${ruleReason(rule.justification, rule.comment)}`,
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
 * Per-occurrence dev-scope downgrade, applied only to a verdict that would otherwise be a default
 * fail (default:copyleft, or default:unknown when unknownHandling="fail"). Keyed strictly on
 * occurrence.isDevDependency:
 *   - a production occurrence → the fail is returned unchanged (the load-bearing safety property
 *     - a shipped copyleft/unknown can never be dev-downgraded).
 *   - a dev occurrence branches on policy.devDependencies:
 *       "fail"   → no downgrade (gate dev exactly like prod).
 *       "warn"   → status "warn", reason appends the auditable dev-only cause,
 *                  rule id preserved so the origin stays traceable.
 *       "ignore" → status "ok", reason names the explicit dev-only opt-out.
 * Higher-precedence lanes (suppression, compatible, clarify, stale, imprecise) never reach this
 * helper - it sits at the would-be default-fail terminals only.
 */
function applyDevScope(failVerdict: Verdict, occurrence: Occurrence, policy: Policy): Verdict {
  if (!occurrence.isDevDependency) {
    return failVerdict;
  }

  const handling = policy.devDependencies;

  if (handling === "fail") {
    return failVerdict;
  }

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
 * Package-level os-scope downgrade, applied only to a verdict that would otherwise be a default
 * fail (default:copyleft, or default:unknown when unknownHandling="fail"). Keyed strictly on the
 * package-level entry.scope === "os" (distinct from applyDevScope's occurrence-level
 * isDevDependency) - the container re-scope transform (pipeline.ts) keeps this "os" iff the package
 * is on the OS-ecosystem allowlist, so this check is now ecosystem-accurate: a container system
 * package, never an application dependency baked into an image:
 *   - an app-scope package → the fail is returned unchanged (the os knob never touches app
 *     dependencies, container or not).
 *   - an os-scope package branches on policy.osDependencies:
 *       "fail"   → no downgrade (an os-scope copyleft gates like an app one).
 *       "warn"   → status "warn", reason appends the auditable os-scope cause,
 *                  rule id preserved so the origin stays traceable.
 *       "ignore" → status "ok", reason names the explicit os-only opt-out.
 * Deny is terminal-0 above this helper (denyVerdict returns first in verdictFor), so a denied os
 * package is never reached here.
 */
function applyOsScope(failVerdict: Verdict, entry: PackageEntry, policy: Policy): Verdict {
  if (entry.scope !== "os") {
    return failVerdict;
  }

  const handling = policy.osDependencies;

  if (handling === "fail") {
    return failVerdict;
  }

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
 * Compose the two scope downgraders at a would-be-default-fail terminal. The os lane runs first so
 * an os-scope package is owned by os_dependencies; the dev lane runs on the result, but the two
 * never interact: an os-scope package is never a dev occurrence in the app sense, and an app
 * package never routes through the os lane. Applying os-then-dev keeps an os-scope copyleft at warn
 * even under dev_dependencies=fail: once os downgrades the fail to warn, applyDevScope's "fail"
 * branch returns that warn unchanged.
 */
function applyScopeDowngrades(
  failVerdict: Verdict,
  entry: PackageEntry,
  occurrence: Occurrence,
  policy: Policy,
): Verdict {
  return applyDevScope(applyOsScope(failVerdict, entry, policy), occurrence, policy);
}

/**
 * Terminal-0 deny resolution. Returns the first matching deny rule, checking, in order:
 *   1. the combined assessment expression (name-mode also matches entry.name) -
 *      electing over the union of license deny allowlists;
 *   2. the pre-override observedExpression - a denied observed license an
 *      override rewrote can never be licensed back in;
 *   3. every observed per-claim precise expression - a denied member combineKnown dropped via
 *      imprecise-family election / unknown collapse is still seen, in every scope.
 * Checks 2–3 pass null as the name so they consult the license allowlist only (name-mode already
 * had its chance against entry.name in check 1) - a per-claim expression must never re-trigger a
 * name-mode rule. Defensive: a finding with no observed expressions simply skips check 3.
 */
function firstDeny(
  policy: Policy,
  entry: PackageEntry,
  expression: string | null,
): IndexedDenyRule | undefined {
  const combined = denyRuleFor(policy, expression, entry.name);

  if (combined !== undefined) {
    return combined;
  }

  const observed = entry.finding?.observedExpression;

  if (observed !== undefined) {
    const hit = denyRuleFor(policy, observed, entry.name);

    if (hit !== undefined) {
      return hit;
    }
  }

  for (const obs of entry.finding?.observedExpressions ?? []) {
    const hit = denyRuleFor(policy, obs, entry.name);

    if (hit !== undefined) {
      return hit;
    }
  }

  return undefined;
}

/**
 * Terminal-0 deny verdict. A matched deny rule force-fails the package with the `denied[i]` rule id
 * and a reason naming the matched license/pattern and the source-available rationale. It is a
 * `fail` → mapped to a violation (exit 1) by the existing violations → exitCodeFor mapping. This
 * sits above every other lane (incl. stale), so applyDevScope is never reached for a denied verdict
 * - a dev-only occurrence of a denied license still fails.
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
 * Source-available exemption (ADR-0013). When the terminal-0 deny that matched is a shipped
 * source-available default (cited default:source-available - not the consumer's own [[deny]]) and
 * the consumer listed that licence under [[allow_source_available]], the package is not
 * force-failed: it surfaces as a warn citing the exemption, so an accepted source-available licence
 * stays visible rather than silently passing. An explicit [[deny]] still wins - denyRuleFor
 * attributes a policy deny first (policy-first order), so denyRule is never the builtin id when the
 * consumer also denied the licence themselves.
 */
function sourceAvailableExemption(
  policy: Policy,
  denyRule: IndexedDenyRule,
): { index: number; license: string; reason: string } | undefined {
  if (denyRule.ruleId !== BUILTIN_DENY_RULE_ID || denyRule.rule.match !== "license") {
    return undefined;
  }

  const license = denyRule.rule.pattern;
  const index = policy.allowSourceAvailable.findIndex((entry) => entry.license === license);

  if (index === -1) {
    return undefined;
  }

  return { index, license, reason: policy.allowSourceAvailable[index]!.reason };
}

/** Warn verdict for an exempted source-available licence (ADR-0013). */
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
 * Terminal-0 verdict for a matched deny: a force-fail, unless the match is a shipped
 * source-available default the consumer exempted (ADR-0013), which surfaces as a warn instead. An
 * explicit [[deny]] is never the builtin id (it is attributed first), so this never softens a deny
 * the consumer authored.
 */
function denyOrExemptVerdict(
  base: { purl: string; occurrenceTarget: string },
  policy: Policy,
  denyRule: IndexedDenyRule,
): Verdict {
  const exemption = sourceAvailableExemption(policy, denyRule);

  if (exemption !== undefined) {
    return exemptionVerdict(base, exemption);
  }

  return denyVerdict(base, denyRule);
}

/**
 * Default:unknown verdict for elected content that still carries a LicenseRef-/DocumentRef- leaf
 * after election. The OR tie-break in elect() already prefers a known assessable branch when one
 * exists (an ordinary "MIT OR LicenseRef-x" elects MIT and never reaches this function) - a ref
 * surviving election means either the finding is the ref, or an AND kept it alongside a known
 * conjunct. Reuses the "default:unknown" rule id and [unknown] handling verbatim: the reference's
 * content is unknowable to the tool, so a confident default:ok would misrepresent an assessment
 * that never happened. Same dev/os downgrade semantics as unknownVerdict.
 */
function refUnknownVerdict(
  base: { purl: string; occurrenceTarget: string },
  entry: PackageEntry,
  occurrence: Occurrence,
  assessment: Assessment,
  policy: Policy,
): Verdict {
  const verdict: Verdict = {
    ...base,
    status: policy.unknownHandling,
    rule: "default:unknown",
    reason: `elected "${assessment.elected}" for "${entry.name}@${entry.version}" in "${occurrence.target}" carries an unassessed LicenseRef/DocumentRef reference whose content is unknowable to the tool ([unknown] handling = "${policy.unknownHandling}")`,
  };

  return policy.unknownHandling === "fail"
    ? applyScopeDowngrades(verdict, entry, occurrence, policy)
    : verdict;
}

/**
 * Default:unknown verdict for a null-expression finding. The dev-scope downgrade applies only to a
 * would-be fail: a default:unknown already "warn" (unknownHandling="warn") is non-gating and is
 * never downgraded.
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

/**
 * Container AGPL escalation: an os-scope system package (the OS-ecosystem allowlist - an
 * application-ecosystem container package is re-keyed to scope "app" upstream and never reaches
 * this branch) whose elected expression carries an AGPL leaf is a real fail, never the routine
 * os-downgraded warn - network copyleft (AGPL section 13) applies to server-side container use, so
 * it must not be softened by os_dependencies="warn"/"ignore" the way ordinary base-image GPL/LGPL
 * is. Bypasses applyScopeDowngrades entirely (both the os and dev lanes); the reason names the
 * elected expression, the container target, the network-interaction rationale, and the scoped
 * `[[compatible]]` remedy.
 */
function agplContainerVerdict(
  base: { purl: string; occurrenceTarget: string },
  target: string,
  elected: string,
): Verdict {
  return {
    ...base,
    status: "fail",
    rule: "default:agpl-container",
    reason: `AGPL leaf in elected "${elected}" is a network-copyleft obligation (AGPL section 13 reaches server-side use) in container system package "${target}" — not routine base-image copyleft; add a scoped [[compatible]] rule if this container is accepted`,
  };
}

/**
 * A complete project target profile's `network = false` demotes the precise AGPL-container
 * escalation to the routine would-be default:copyleft fail (through {@link applyScopeDowngrades},
 * i.e. `[os_dependencies]`), the reason naming the declared basis - the explicit flag now owns the
 * applicability fact the escalation used to guess (the container-design reconciliation).
 */
function demotedAgplContainerVerdict(
  base: { purl: string; occurrenceTarget: string },
  entry: PackageEntry,
  occurrence: Occurrence,
  target: string,
  elected: string,
  policy: Policy,
): Verdict {
  const failVerdict: Verdict = {
    ...base,
    status: "fail",
    rule: "default:copyleft",
    reason: `copyleft license "${elected}" in container system package "${target}" carries an AGPL leaf that would normally escalate to the network-copyleft obligation, but ${declaredNetworkFalseBasis()}`,
  };

  return applyScopeDowngrades(failVerdict, entry, occurrence, policy);
}

/**
 * Copyleft lane: a copyleft elected branch is suppressed when its occurrence sits in a
 * family-justified suppressed workspace; otherwise an os-scope package whose elected expression
 * carries an AGPL leaf escalates to a real fail (agplContainerVerdict, checked before the scope
 * downgraders so os_dependencies can never soften it); otherwise it is a would-be
 * default:copyleft fail routed through the scope downgraders.
 * Split out of verdictFor to keep the precedence walk within the complexity budget; the behavior is
 * unchanged - it runs only when assessment.copyleft is true, below compatible and above the
 * imprecise/unknown lanes.
 */
function copyleftVerdict(
  base: { purl: string; occurrenceTarget: string },
  entry: PackageEntry,
  occurrence: Occurrence,
  assessment: Assessment,
  policy: Policy,
): Verdict {
  const target = occurrence.target;
  const suppression = suppressionFor(target, policy);

  if (suppression !== undefined && assessment.electedNode !== null && assessment.elected !== null) {
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

  if (
    entry.scope === "os" &&
    assessment.electedNode !== null &&
    assessment.elected !== null &&
    copyleftLeafIds(assessment.electedNode).some((id) => AGPL_IDS.has(id))
  ) {
    const profile = policy.target?.profile;

    if (profile !== undefined && !profile.network) {
      return demotedAgplContainerVerdict(
        base,
        entry,
        occurrence,
        target,
        assessment.elected,
        policy,
      );
    }

    return agplContainerVerdict(base, target, assessment.elected);
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

/**
 * The target-compatibility lane: decides a governed, parseable (non-imprecise, non-null) occurrence
 * against its resolved {@link TargetProfile} via the pure compatibility engine (compat/classify.ts
 * + compat/profile.ts), returning undefined when the lane should NOT decide - the caller then
 * falls through to today's copyleft/imprecise/unknown walk unchanged. Two cases return undefined:
 * the elected branch still carries a LicenseRef-/DocumentRef- leaf after the TARGET-AWARE election
 * (an opaque reference's content is unknowable to the tool, so it routes to the existing [unknown]
 * handling, never `target:ok`); and a defensive `unassessed-ref` fallthrough that can never
 * actually be reached given the check above (the modulated class is only ever `unassessed-ref` when
 * a ref leaf survives into `result.elected`).
 *
 * Maps classifyExpression's five ModulatedClass outcomes: `compatible` → `overrideCitation` first
 * (a clarified package landing target:ok keeps citing `clarify[i]`), else `target:ok`;
 * `held-internal` → ok `target:internal-use` (never overrideCitation - the distinct id must always
 * stay visible, even for a clarified package, per the internal-use hold's own repudiation
 * mitigation); `boundary` → warn `target:boundary`; `incompatible` → fail `target:incompatible`,
 * composed with `applyDevScope` (a dev-only occurrence downgrades exactly like `default:copyleft`
 * does); `residual` → the `unknown_pair` knob (warn by default), a `fail` position also composed
 * with `applyDevScope`. `os` never reaches this lane at all (the caller gates on `entry.scope !==
 * "os"` before calling) - the os reconciliation lives in copyleftVerdict/impreciseVerdict instead,
 * so `applyDevScope` alone (never the os leg of `applyScopeDowngrades`) is the correct, and only,
 * downgrade here.
 */
function targetVerdict(
  base: { purl: string; occurrenceTarget: string },
  entry: PackageEntry,
  occurrence: Occurrence,
  assessment: Assessment,
  profile: TargetProfile,
  policy: Policy,
): Verdict | undefined {
  if (assessment.rawNode === null) {
    return undefined;
  }

  const result = classifyExpression(profile, assessment.rawNode);

  if (hasRefLeaf(result.elected)) {
    return undefined;
  }

  const ctx: ReasonContext = {
    elected: renderNode(result.elected),
    occurrenceTarget: occurrence.target,
    profileLabel: formatProfileLabel(profile),
    source: result.sources.join("; "),
  };

  switch (result.class) {
    case "compatible": {
      const citation = overrideCitation(
        entry,
        base,
        occurrence.target,
        assessment.expression,
        policy,
      );

      return (
        citation ?? { ...base, status: "ok", rule: TARGET_RULE_OK, reason: targetOkReason(ctx) }
      );
    }

    case "held-internal":
      return {
        ...base,
        status: "ok",
        rule: TARGET_RULE_INTERNAL_USE,
        reason: targetInternalUseReason(ctx),
      };
    case "boundary":
      return {
        ...base,
        status: "warn",
        rule: TARGET_RULE_BOUNDARY,
        reason: targetBoundaryReason(ctx),
      };
    case "incompatible":
      return applyDevScope(
        {
          ...base,
          status: "fail",
          rule: TARGET_RULE_INCOMPATIBLE,
          reason: targetIncompatibleReason(ctx),
        },
        occurrence,
        policy,
      );
    case "residual": {
      const knob = policy.target?.unknownPair ?? "warn";
      const verdict: Verdict = {
        ...base,
        status: knob,
        rule: TARGET_RULE_UNKNOWN_PAIR,
        reason: targetUnknownPairReason(ctx),
      };

      return knob === "fail" ? applyDevScope(verdict, occurrence, policy) : verdict;
    }

    case "unassessed-ref":
      return undefined;
  }
}

/** How a package-form rule names what it governs, quoted for the verdict reason. */
function packageRuleSubject(rule: CompatiblePackageRule): string {
  const selector = rule.name ?? (rule.pattern as string);

  if (rule.version === undefined) {
    return `"${selector}"`;
  }

  const versions = typeof rule.version === "string" ? rule.version : rule.version.join(", ");

  return `"${selector}@${versions}"`;
}

/**
 * Tier 1/2 compatible-rule verdict (package form pinned before license form, mirroring the caller's
 * own selection order), split out of verdictFor to keep the precedence walk within the complexity
 * budget. Returns undefined when neither rule matched, so the caller falls through to the lanes
 * below.
 */
function compatibleRuleVerdict(
  base: { purl: string; occurrenceTarget: string },
  assessment: Assessment,
  packageRule: IndexedRule<CompatiblePackageRule> | undefined,
  licenseRule: IndexedRule<CompatibleLicenseRule> | undefined,
): Verdict | undefined {
  if (packageRule !== undefined) {
    const { index, rule } = packageRule;

    return {
      ...base,
      status: "ok",
      rule: `compatible[${index}]`,
      reason: `package ${packageRuleSubject(rule)} accepted by compatible package rule: ${ruleReason(rule.rationale, rule.comment)}`,
    };
  }

  if (licenseRule !== undefined) {
    const { index, rule } = licenseRule;

    return {
      ...base,
      status: "ok",
      rule: `compatible[${index}]`,
      reason: `"${assessment.expression}" satisfies compatible license pattern "${rule.pattern}": ${ruleReason(rule.rationale, rule.comment)}`,
    };
  }

  return undefined;
}

/**
 * Activation gate for {@link targetVerdict}, split out of verdictFor to keep the precedence walk
 * within the complexity budget: os-scope never activates the lane (the AGPL-container/network
 * reconciliation lives in copyleftVerdict/impreciseVerdict instead, gated on entry.scope === "os"
 * there); an imprecise/null finding (no rawNode) never activates it either; otherwise a governing
 * profile is resolved once per occurrence and, when present, targetVerdict decides.
 */
function targetLaneVerdict(
  base: { purl: string; occurrenceTarget: string },
  entry: PackageEntry,
  occurrence: Occurrence,
  assessment: Assessment,
  policy: Policy,
): Verdict | undefined {
  if (entry.scope === "os" || assessment.rawNode === null) {
    return undefined;
  }

  const profile = resolveTargetProfile(occurrence.target, policy);

  if (profile === undefined) {
    return undefined;
  }

  return targetVerdict(base, entry, occurrence, assessment, profile, policy);
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

  // Terminal-0: a denied license/rider can never be licensed back in - unless the matched deny is a
  // shipped source-available default the consumer exempted via [[allow_source_available]]
  // (ADR-0013), which surfaces as a warn instead.
  if (denyRule !== undefined) {
    return denyOrExemptVerdict(base, policy, denyRule);
  }

  const stale = entry.finding?.staleOverride;

  if (stale !== undefined) {
    return staleVerdict(base, entry, stale);
  }

  // conflict:scancode sits directly below stale and above compatible - a fail, not a warn, because
  // human involvement is necessary and a warn is ignorable (rationale on conflictVerdict). A stale
  // override is strictly more urgent so it fires first; no compatible rule may auto-absorb a
  // disputed answer, so this precedes the compatible lanes.
  const conflict = entry.finding?.conflict;

  if (conflict !== undefined) {
    return conflictVerdict(base, entry, conflict);
  }

  const compatibleDecided = compatibleRuleVerdict(base, assessment, packageRule, licenseRule);

  if (compatibleDecided !== undefined) {
    return compatibleDecided;
  }

  // The target-compatibility lane: below deny/stale/conflict/compatible, above copyleft/imprecise/
  // unknown. targetLaneVerdict returns undefined when the lane should not decide (no governing
  // profile, an imprecise/null finding, os-scope, or a ref-carrying elected branch), so the walk
  // falls through to the unchanged copyleft/imprecise/unknown lanes below.
  const targetDecided = targetLaneVerdict(base, entry, occurrence, assessment, policy);

  if (targetDecided !== undefined) {
    return targetDecided;
  }

  if (assessment.copyleft) {
    return copyleftVerdict(base, entry, occurrence, assessment, policy);
  }

  if (assessment.impreciseFamily !== undefined) {
    return impreciseVerdict(base, entry, occurrence, assessment.impreciseFamily, policy);
  }

  if (assessment.expression === null) {
    return unknownVerdict(base, entry, occurrence, policy);
  }

  const citation = overrideCitation(entry, base, target, assessment.expression, policy);

  if (citation !== undefined) {
    return citation;
  }

  // A LicenseRef-/DocumentRef- leaf that survived election is unassessed content, not a clean
  // permissive finding - route it through the same [unknown] handling as a genuine unknown rather
  // than a confident
  // default:ok. elect()'s OR tie-break already moved a known branch out from
  // under a sibling ref when one was electable, so anything reaching here either is the ref or is
  // an AND that keeps one alongside a known conjunct.
  if (assessment.electedNode !== null && hasRefLeaf(assessment.electedNode)) {
    return refUnknownVerdict(base, entry, occurrence, assessment, policy);
  }

  return {
    ...base,
    status: "ok",
    rule: "default:ok",
    reason: `"${assessment.expression}" (elected "${assessment.elected}") carries no copyleft obligation in "${target}"`,
  };
}

/**
 * Pure. Precondition: model.packages carry `finding` (annotateFindings ran); a missing finding is
 * treated as unknown - defensive, documented. Returns one verdict per (package × occurrence),
 * sorted compareCodeUnits on (purl, occurrenceTarget).
 */
export function evaluate(model: CanonicalDependencies, policy: Policy): Verdict[] {
  const verdicts: Verdict[] = [];

  for (const entry of model.packages) {
    const assessment = assessPackage(entry);
    // Terminal-0 deny match computed once per package: license-mode reads the assessment
    // expression, electing over the deny allowlists (see docs/glossary.md#election); name-mode
    // reads the package name (works even when the expression is null - the use-restriction rider
    // case).
    //
    // Deny is terminal over overrides: an override may have rewritten a denied observed license
    // (e.g. BUSL-1.1 → MIT) into the assessment
    // expression. Deny must also consult the pre-override observed expression;
    // if either the observed or the (possibly-overridden) finding expression is denied, deny fires.
    // A denied observed license can never be licensed back in by any override (deny is terminal
    // over overrides).
    //
    // Deny sees every observed claim: combineKnown elects an imprecise family, or collapses to
    // unknown, before a precise non-copyleft denied member (BUSL-1.1, Elastic-2.0
    // - source-available) when an imprecise family token or an unknown token co-exists, so the
    // combined expression is null/imprecise and the two checks above never see the denied member.
    // Deny therefore also consults the set of every observed per-claim precise expression
    // (finding.observedExpressions): if any observed expression is denied, deny fires - regardless
    // of how combine rendered the finding (precise/imprecise/unknown), in every scope. Name-mode
    // (passed null here) is inert per observed expression - it already matched via entry.name
    // above.
    const denyRule = firstDeny(policy, entry, assessment.expression);

    for (const occurrence of entry.occurrences) {
      // Compatible matches are per occurrence: an unscoped rule accepts the package at every
      // occurrence; a `where`-scoped rule only at the occurrences its identity prefixes cover.
      // First match in TOML order wins per occurrence, package form before license form.
      const packageRule = packageRuleFor(entry, occurrence.target, policy);
      const licenseRule =
        packageRule === undefined && assessment.expression !== null
          ? licenseRuleFor(assessment.expression, occurrence.target, policy)
          : undefined;

      verdicts.push(
        verdictFor(entry, occurrence, assessment, packageRule, licenseRule, denyRule, policy),
      );
    }
  }

  return verdicts.sort(
    (a, b) =>
      compareCodeUnits(a.purl, b.purl) || compareCodeUnits(a.occurrenceTarget, b.occurrenceTarget),
  );
}

/**
 * One accepted-AGPL container obligation: an os-scope (container system package) occurrence whose
 * elected license carries the AGPL network-copyleft obligation (precise: an AGPL_IDS leaf in the
 * elected expression; imprecise: the bare "AGPL" family token, the same predicates
 * agplContainerVerdict and impreciseVerdict already gate on) but whose verdict at that occurrence
 * is an acceptance - status "ok" via a `[[compatible]]` rule - rather than the
 * default:agpl-container fail. Surfaced as a non-blocking special notice
 * (render/markdown.ts) instead of vanishing: the obligation is accepted, not absent.
 */
export interface AcceptedContainerNotice {
  readonly purl: string;
  readonly name: string;
  readonly version: string;
  /** Elected SPDX id for a precise finding; the bare "AGPL" family token otherwise. */
  readonly license: string;
  /** Deduped, compareCodeUnits-sorted occurrence targets accepted at. */
  readonly targets: ReadonlyArray<string>;
  /** The accepting `compatible[i]` rule id (citation, mirrors Verdict.rule). */
  readonly rule: string;
  /** The accepting verdict's reason (citation, mirrors Verdict.reason). */
  readonly reason: string;
}

/**
 * An assessment carries the AGPL network-copyleft obligation - precise (an AGPL_IDS leaf in the
 * elected expression) or imprecise (the bare "AGPL" family token) - the exact two predicates
 * agplContainerVerdict and impreciseVerdict already gate os-scope escalation on, reused here so
 * detection can never drift from the escalation itself.
 */
function carriesAgplObligation(assessment: Assessment): boolean {
  if (
    assessment.electedNode !== null &&
    copyleftLeafIds(assessment.electedNode).some((id) => AGPL_IDS.has(id))
  ) {
    return true;
  }

  return assessment.impreciseFamily === "AGPL";
}

/**
 * True for a verdict rule that ACCEPTS an AGPL obligation without a real fail: a `[[compatible]]`
 * rule (the only lever above the AGPL-container escalation in the precedence walk), or the
 * network=false-demoted `default:copyleft` outcome landing "ok" via `os_dependencies = "ignore"`
 * - a demoted-ok row must never go silent, so it gets the same notice-style visibility (the "AGPL
 * obligation never silently absent" invariant holds regardless of the profile feature). Both
 * require status "ok" at the call site; this only narrows which rule ids qualify.
 */
function acceptsAgplObligation(rule: string): boolean {
  return rule.startsWith("compatible[") || rule === "default:copyleft";
}

/**
 * Accepted-AGPL container notices: one entry per os-scope package carrying the AGPL obligation with
 * at least one occurrence whose verdict is an acceptance - status "ok" via {@link
 * acceptsAgplObligation}. A package with no accepted occurrence contributes nothing; a package also
 * carrying a fail elsewhere is still returned here - the render layer applies the Problematic
 * dedup, matching how the flagged-copyleft rows dedup today. Sorted by purl (compareCodeUnits) for
 * determinism; each notice's targets are deduped and sorted the same way.
 */
export function acceptedContainerNotices(
  model: CanonicalDependencies,
  verdicts: ReadonlyArray<Verdict>,
): AcceptedContainerNotice[] {
  const verdictByKey = new Map<string, Verdict>();

  for (const verdict of verdicts) {
    verdictByKey.set(`${verdict.purl}\u0000${verdict.occurrenceTarget}`, verdict);
  }

  const notices: AcceptedContainerNotice[] = [];

  for (const entry of model.packages) {
    if (entry.scope !== "os") {
      continue;
    }

    const assessment = assessPackage(entry);

    if (!carriesAgplObligation(assessment)) {
      continue;
    }

    const targets: string[] = [];
    let rule: string | undefined;
    let reason: string | undefined;

    for (const occurrence of entry.occurrences) {
      const verdict = verdictByKey.get(`${entry.purl}\u0000${occurrence.target}`);

      if (
        verdict === undefined ||
        verdict.status !== "ok" ||
        !acceptsAgplObligation(verdict.rule)
      ) {
        continue;
      }

      targets.push(occurrence.target);
      if (rule === undefined) {
        rule = verdict.rule;
        reason = verdict.reason;
      }
    }

    if (targets.length === 0 || rule === undefined || reason === undefined) {
      continue;
    }

    notices.push({
      purl: entry.purl,
      name: entry.name,
      version: entry.version,
      license: assessment.elected ?? "AGPL",
      targets: [...new Set(targets)].sort(compareCodeUnits),
      rule,
      reason,
    });
  }

  return notices.sort((a, b) => compareCodeUnits(a.purl, b.purl));
}

/**
 * Rule ids of compatible/clarify entries that never decided anything -
 * stale-policy hygiene. Compatible usage is read from cited verdict rules;
 * clarify usage comes from annotateFindings' usedClarifyIndices (a clarify rule is "used" when it
 * replaced a finding, even if a higher-precedence compatible rule decided the final verdict).
 * Suppression entries are never reported. Returned in TOML array order: compatible first, then
 * clarify.
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

    if (!cited.has(id)) {
      unused.push(id);
    }
  });
  policy.clarify.forEach((_, index) => {
    if (!usedClarifyIndices.has(index)) {
      unused.push(`clarify[${index}]`);
    }
  });
  return unused;
}
