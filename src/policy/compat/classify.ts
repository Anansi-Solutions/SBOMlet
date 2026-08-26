/**
 * License-axis classification: target license x dependency leaf, through the four-tier fallback
 * chain (OSADL matrix cell -> OSADL copyleft class -> ScanCode LicenseDB category -> SBOMlet's
 * literal copyleft sets), plus profile-aware SPDX expression composition.
 *
 * Tier order decides the axis class: the first tier that covers the leaf wins, exactly mirroring
 * the "first-tier-wins" runtime posture consistency.ts documents for the underlying data. The
 * obligation tag is a SEPARATE, tier-order-independent read of the same three datasets (never
 * guessed) - see {@link classifyLeaf}'s doc for the exact priority. classifyExpression modulates
 * every leaf through the usage-profile scope gate (profile.ts) before combining leaves with AND/OR
 * dominance; it never imports or calls the no-target `elect()` in normalize/expression.ts, so that
 * election path stays byte-unchanged by construction.
 *
 * See ADR-0025 (docs/explanation/adr/0025-target-license-compatibility-lane.md) for why this tier
 * chain replaces hand-authored accept-lists, the scope-gating principle, and the rejected
 * alternatives.
 */
import {
  asSpdxLicenseLeaf,
  compareCodeUnits,
  type SpdxLicenseLeaf,
} from "../../model/dependencies";
import { hasRefLeaf, renderNode, type ExpressionNode } from "../../normalize/expression";
import { AGPL_IDS, COPYLEFT_IDS } from "../engine/copyleft";
import {
  OSADL_COPYLEFT_CLASS,
  OSADL_MATRIX,
  SCANCODE_CATEGORY,
  type OsadlCopyleftClass,
  type OsadlMatrixCell,
} from "./data";
import { applyUsageProfile, type ModulatedClass, type TargetProfile } from "./profile";
import type { AxisClass, AxisResult, ObligationClass, TargetLicense } from "./classification";

/** True for a LicenseRef-/DocumentRef- id - SPDX grammar syntax, not a license-id comparison. */
function isRefLeaf(id: string): boolean {
  return id.startsWith("LicenseRef-") || id.startsWith("DocumentRef-");
}

/**
 * The base id of a rendered leaf: strips a trailing ` WITH exception` clause, then a trailing `+`.
 * The one conservative fallback direction this module uses for both WITH and `plus` leaves the
 * vetted data does not model exactly - `X WITH e` and `X+` both read as "at least as restrictive as
 * X" (@privateRemarks: an exception only narrows obligations, `plus` only widens the accepted
 * version range, so falling back to the bare id is safe, never permissive-by-omission).
 */
function baseLeafId(rendered: string): string {
  const withoutException = rendered.replace(/ WITH .+$/, "");

  return withoutException.endsWith("+") ? withoutException.slice(0, -1) : withoutException;
}

/** Lookup keys for a rendered leaf, exact form first, then its base id (deduped when equal). */
function leafKeys(leaf: string): readonly SpdxLicenseLeaf[] {
  const base = baseLeafId(leaf);

  return base === leaf
    ? [asSpdxLicenseLeaf(leaf)]
    : [asSpdxLicenseLeaf(leaf), asSpdxLicenseLeaf(base)];
}

/** Maps a raw OSADL matrix cell to an axis class (OSS targets only - proprietary has no rows). */
function classifyMatrixCell(cell: OsadlMatrixCell): AxisClass {
  switch (cell) {
    case "Same":
    case "Yes":
      return "compatible";
    case "No":
      return "incompatible";
    case "Unknown":
    case "Check dependency":
      return "residual";
  }
}

/**
 * Tier 1 (OSS targets only): the target's own matrix row, tried under both lookup keys. Returns
 * undefined when the target itself is not a matrix row, or the leaf is uncovered by that row - the
 * vetted-pairwise-data-only posture for OSS: only an actual cell may decide `incompatible`.
 */
function matrixTier(
  target: TargetLicense,
  keys: readonly string[],
): { class: AxisClass; source: string } | undefined {
  if (target.kind !== "oss") {
    return undefined;
  }

  const row = OSADL_MATRIX.get(target.id);

  if (row === undefined) {
    return undefined;
  }

  for (const key of keys) {
    const cell = row.get(key);

    if (cell !== undefined) {
      return { class: classifyMatrixCell(cell), source: `OSADL: ${cell}` };
    }
  }

  return undefined;
}

/**
 * Maps an OSADL copyleft class to an axis class. Proprietary targets get a real boundary tier (`No`
 * -> compatible, `Yes (restricted)` -> boundary, `Yes` -> incompatible, `Questionable` ->
 * residual); OSS targets falling back to this tier have no pairwise data, so every class is an
 * honest `residual` - only the tier-1 matrix (Same/Yes) decides `compatible` for an OSS target, and
 * no coarse copyleft class is ever read as one.
 */
function classifyOsadlClass(kind: TargetLicense["kind"], cls: OsadlCopyleftClass): AxisClass {
  if (kind === "proprietary") {
    switch (cls) {
      case "No":
        return "compatible";
      case "Yes (restricted)":
        return "boundary";
      case "Yes":
        return "incompatible";
      case "Questionable":
        return "residual";
    }
  }

  return "residual";
}

/** Tier 2: the leaf's own OSADL copyleft class, tried under both lookup keys. */
function osadlClassTier(
  target: TargetLicense,
  keys: readonly string[],
): { class: AxisClass; source: string } | undefined {
  for (const key of keys) {
    const cls = OSADL_COPYLEFT_CLASS.get(key);

    if (cls !== undefined) {
      return {
        class: classifyOsadlClass(target.kind, cls),
        source: `OSADL copyleft class: ${cls}`,
      };
    }
  }

  return undefined;
}

/**
 * Maps a ScanCode LicenseDB category to an axis class. For an OSS target this tier has no pairwise
 * data, so every category is an honest `residual` - a coarse "Permissive"/"Public Domain" bucket
 * holds GPL-incompatible ids too, so only the tier-1 matrix decides `compatible` for OSS. A
 * proprietary target keeps its boundary tier: Permissive/Public Domain compatible, Copyleft Limited
 * boundary, Copyleft incompatible, every other category residual.
 */
function classifyScancodeCategory(kind: TargetLicense["kind"], category: string): AxisClass {
  if (kind !== "proprietary") {
    return "residual";
  }

  if (category === "Permissive" || category === "Public Domain") {
    return "compatible";
  }

  if (category === "Copyleft Limited") {
    return "boundary";
  }

  return category === "Copyleft" ? "incompatible" : "residual";
}

/** Tier 3: the leaf's own ScanCode LicenseDB category, tried under both lookup keys. */
function scancodeTier(
  target: TargetLicense,
  keys: readonly string[],
): { class: AxisClass; source: string } | undefined {
  for (const key of keys) {
    const category = SCANCODE_CATEGORY.get(key);

    if (category !== undefined) {
      return {
        class: classifyScancodeCategory(target.kind, category),
        source: `ScanCode LicenseDB: ${category}`,
      };
    }
  }

  return undefined;
}

/**
 * Tier 4, the exhaustive fallback (never undefined): SBOMlet's own literal copyleft sets. A member
 * is an honest `residual` - vetted data does not cover it, but it is a known copyleft license, so
 * it is never silently `compatible`; a non-member keeps today's `default:ok` semantics.
 */
function literalSetTier(keys: readonly SpdxLicenseLeaf[]): { class: AxisClass; source: string } {
  if (keys.some((key) => COPYLEFT_IDS.has(key))) {
    return {
      class: "residual",
      source: "SBOMlet's literal copyleft set (no vetted compatibility data)",
    };
  }

  return { class: "compatible", source: "not a known copyleft license" };
}

/**
 * The obligation tag: a positively-determined read of the leaf's OWN data (never the matrix cell
 * that decided the axis class above), independent of tier order. Priority: an AGPL_IDS member is
 * `agpl`; failing that, any of COPYLEFT_IDS membership / OSADL class Yes(-restricted) / ScanCode
 * Copyleft(-Limited) is `copyleft`; failing that, any of OSADL class No / ScanCode Permissive-or-
 * Public-Domain / no data anywhere for a non-copyleft id is `none`; otherwise `unknown` - never
 * guessed from a Questionable class or an absent dataset entry alone.
 */
function obligationFor(keys: readonly SpdxLicenseLeaf[]): ObligationClass {
  if (keys.some((key) => AGPL_IDS.has(key))) {
    return "agpl";
  }

  const copyleftSignal =
    keys.some((key) => COPYLEFT_IDS.has(key)) ||
    keys.some((key) => {
      const cls = OSADL_COPYLEFT_CLASS.get(key);

      return cls === "Yes" || cls === "Yes (restricted)";
    }) ||
    keys.some((key) => {
      const category = SCANCODE_CATEGORY.get(key);

      return category === "Copyleft" || category === "Copyleft Limited";
    });

  if (copyleftSignal) {
    return "copyleft";
  }

  const hasAnyTierData = keys.some(
    (key) => OSADL_COPYLEFT_CLASS.has(key) || SCANCODE_CATEGORY.has(key),
  );
  const permissiveSignal =
    keys.some((key) => OSADL_COPYLEFT_CLASS.get(key) === "No") ||
    keys.some((key) => {
      const category = SCANCODE_CATEGORY.get(key);

      return category === "Permissive" || category === "Public Domain";
    }) ||
    !hasAnyTierData;

  return permissiveSignal ? "none" : "unknown";
}

/**
 * Classifies one leaf against a target license through the four-tier chain: the first tier that
 * covers the leaf decides its axis class; the obligation tag is derived separately from the SAME
 * tier data (see {@link obligationFor}). A `LicenseRef-`/`DocumentRef-` leaf is the one exception
 * to tier order - it uses matrix tier data when an exact matrix row covers it (the one class of
 * `LicenseRef-scancode-*` ids the OSADL matrix models), and `unassessed-ref` (obligation `unknown`)
 * otherwise, never falling through to the class/category/literal-set tiers a ref cannot honestly
 * satisfy honestly.
 */
export function classifyLeaf(target: TargetLicense, leaf: string): AxisResult {
  const keys = leafKeys(leaf);
  const matrixHit = matrixTier(target, keys);

  if (matrixHit !== undefined) {
    return { ...matrixHit, obligation: obligationFor(keys) };
  }

  if (isRefLeaf(keys[0]!)) {
    return {
      class: "unassessed-ref",
      source: "unassessed LicenseRef/DocumentRef reference",
      obligation: "unknown",
    };
  }

  const hit = osadlClassTier(target, keys) ?? scancodeTier(target, keys) ?? literalSetTier(keys);

  return { ...hit, obligation: obligationFor(keys) };
}

/**
 * One leaf's modulated classification, carrying its own citation forward for the composition walk's
 * `sources` accumulation.
 */
interface LeafVerdict {
  readonly class: ModulatedClass;
  readonly elected: ExpressionNode;
  readonly sources: readonly string[];
}

/** Dominance order, worst to best - AND takes the lowest index present, OR prefers the highest. */
const DOMINANCE_ORDER: readonly ModulatedClass[] = [
  "incompatible",
  "unassessed-ref",
  "residual",
  "boundary",
  "held-internal",
  "compatible",
];

/** AND's dominant class: the worst (lowest-indexed) of the two conjuncts' classes. */
function dominantOf(a: ModulatedClass, b: ModulatedClass): ModulatedClass {
  return DOMINANCE_ORDER.indexOf(a) <= DOMINANCE_ORDER.indexOf(b) ? a : b;
}

/**
 * OR's preferred branch: the best (highest-indexed) class wins; a tie breaks exactly like the
 * no-target `elect()` in normalize/expression.ts - no-ref-leaves first, then `compareCodeUnits` on
 * the rendered elected form - so an OR of two equally-classed branches stays as order-independent
 * as the untouched no-target election.
 */
function preferredBranch(left: LeafVerdict, right: LeafVerdict): LeafVerdict {
  const leftRank = DOMINANCE_ORDER.indexOf(left.class);
  const rightRank = DOMINANCE_ORDER.indexOf(right.class);

  if (leftRank !== rightRank) {
    return leftRank > rightRank ? left : right;
  }

  const leftRef = hasRefLeaf(left.elected);
  const rightRef = hasRefLeaf(right.elected);

  if (leftRef !== rightRef) {
    return leftRef ? right : left;
  }

  return compareCodeUnits(renderNode(left.elected), renderNode(right.elected)) <= 0 ? left : right;
}

/** Renders a leaf node's `id[+][ WITH exception]` text for {@link classifyLeaf}'s string input. */
function leafText(node: Extract<ExpressionNode, { license: string }>): string {
  return renderNode(node);
}

/** Recursive composition walk shared by both operators, over already-profile-modulated leaves. */
function walk(profile: TargetProfile, node: ExpressionNode): LeafVerdict {
  if ("license" in node) {
    const axis = classifyLeaf(profile.license, leafText(node));
    const modulated = applyUsageProfile(axis, profile);

    return { class: modulated.class, elected: node, sources: [modulated.source] };
  }

  const left = walk(profile, node.left);
  const right = walk(profile, node.right);

  if (node.conjunction === "and") {
    return {
      class: dominantOf(left.class, right.class),
      elected: { left: left.elected, conjunction: "and", right: right.elected },
      sources: [...left.sources, ...right.sources],
    };
  }

  return preferredBranch(left, right);
}

/** One SPDX expression's profile-modulated, target-aware classification. */
export interface ExpressionResult {
  readonly class: ModulatedClass;
  /**
   * The elected branch (AND keeps both sides; OR keeps the winning branch) - WITH never stripped.
   */
  readonly elected: ExpressionNode;
  /** Per-leaf citations of the elected subtree, in left-to-right leaf order (not deduped). */
  readonly sources: readonly string[];
}

/**
 * Classifies a whole SPDX expression against a target profile: every leaf is modulated through
 * {@link applyUsageProfile} before combining. AND requires every conjunct (dominance: the worst
 * class wins, keeping both sides elected - every obligation applies); OR elects the best-class
 * branch (the inverse preference), ties breaking exactly as `elect()` does. Never imports or calls
 * `elect()` - the no-target election path stays byte-unchanged by construction.
 *
 * @remarks The Apache-2.0 OR GPL-2.0-only case is the one concrete example worth carrying: under
 * a `GPL-2.0-only` target, `elect()`'s own non-copyleft preference would pick the Apache-2.0 branch
 * even though the matrix rejects it (`GPL-2.0-only` -> `Apache-2.0` = `No`) while the GPL branch is
 * the target's own diagonal (`Same`) - this walk's target-aware preference picks the GPL branch
 * instead, in both operand orders.
 */
export function classifyExpression(profile: TargetProfile, node: ExpressionNode): ExpressionResult {
  return walk(profile, node);
}
