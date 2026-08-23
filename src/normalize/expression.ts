/**
 * SPDX expression AST walker: render, copyleft avoidance, branch election.
 *
 * Election (see docs/glossary.md#election) is the OR operator's own meaning - it lets the consumer
 * pick whichever branch they want to rely on. `elect()` below makes that pick deterministic;
 * `isCopyleft` and the deny walk ask the mirror question, whether an electable branch avoids the
 * obligation or the deny rule. No library exposes "which OR branch passed" - spdx-satisfies cannot
 * test individual branches and throws on expression-valued allowlists - so branch semantics over
 * the parsed AST are owned here. Copyleft membership is an exact Set lookup on parsed leaf ids
 * only; no substring or prefix matching on license ids anywhere.
 *
 * Pure functions, no I/O, no logging - the CLI owns stderr. Inputs are structurally-typed parse
 * output; the only spdx-expression-parse import here is the parser itself (isCompoundClaim), cast
 * straight to this file's own ExpressionNode shape - the library's internal types stay unused.
 */
import parseSpdx from "spdx-expression-parse";

import {
  compareCodeUnits,
  type CanonicalExpression,
  type NormalizedLicense,
} from "../model/dependencies";
import { COPYLEFT_IDS } from "../policy/engine/copyleft";

export type ExpressionNode =
  | { license: string; plus?: true; exception?: string }
  | { left: ExpressionNode; conjunction: "or" | "and"; right: ExpressionNode };

/**
 * A parsed leaf: `id[+][ WITH exception]`, shared by {@link renderNode} and canonicalization below.
 */
type Leaf = Extract<ExpressionNode, { license: string }>;

/** Leaf rendering: `id[+][ WITH exception]` - the one leaf format, never duplicated. */
function renderLeaf(leaf: Leaf): string {
  const plus = leaf.plus === true ? "+" : "";
  const withPart = leaf.exception !== undefined ? ` WITH ${leaf.exception}` : "";

  return `${leaf.license}${plus}${withPart}`;
}

/**
 * Canonical rendering: leaf = `id[+][ WITH exception]`; compound child operands are parenthesized,
 * the top level is not.
 */
export function renderNode(node: ExpressionNode): string {
  if ("license" in node) {
    return renderLeaf(node);
  }

  const operand = (child: ExpressionNode): string =>
    "license" in child ? renderLeaf(child) : `(${renderNode(child)})`;
  const conj = node.conjunction === "or" ? "OR" : "AND";

  return `${operand(node.left)} ${conj} ${operand(node.right)}`;
}

/**
 * A finding is copyleft if its expression cannot avoid a copyleft branch: leaf = exact-ID
 * membership (exception does not clear copyleft; a `plus` leaf matches via its base id); AND = any
 * copyleft conjunct taints; OR = copyleft only if both branches are.
 */
export function isCopyleft(node: ExpressionNode): boolean {
  if ("license" in node) {
    return COPYLEFT_IDS.has(node.license);
  }

  if (node.conjunction === "and") {
    return isCopyleft(node.left) || isCopyleft(node.right);
  }

  return isCopyleft(node.left) && isCopyleft(node.right);
}

/**
 * License ids of every copyleft leaf in the tree: the obligations a suppression decision must
 * verify against the workspace's own license. Exact COPYLEFT_IDS membership per leaf - a `plus`
 * leaf reports its base id (same convention as isCopyleft); non-copyleft leaves are omitted.
 */
export function copyleftLeafIds(node: ExpressionNode): string[] {
  if ("license" in node) {
    return COPYLEFT_IDS.has(node.license) ? [node.license] : [];
  }

  return [...copyleftLeafIds(node.left), ...copyleftLeafIds(node.right)];
}

/**
 * Every leaf of the tree, decomposed for the notices appendix: `ids` collects each leaf's base
 * license id (a `plus` leaf reports its base id - the copyleftLeafIds convention); `exceptions`
 * collects WITH exception names separately, because spdx-license-list covers licenses, not
 * exceptions - the renderer flags them. No dedup, no sort: callers own set semantics and ordering.
 */
export function leafIds(node: ExpressionNode): {
  ids: string[];
  exceptions: string[];
} {
  if ("license" in node) {
    return {
      ids: [node.license],
      exceptions: node.exception !== undefined ? [node.exception] : [],
    };
  }

  const left = leafIds(node.left);
  const right = leafIds(node.right);

  return {
    ids: [...left.ids, ...right.ids],
    exceptions: [...left.exceptions, ...right.exceptions],
  };
}

/**
 * True if any leaf is a LicenseRef-/DocumentRef- reference. This is SPDX grammar syntax detection
 * (anchored prefix per spec), not license-id matching.
 */
export function hasRefLeaf(node: ExpressionNode): boolean {
  if ("license" in node) {
    return node.license.startsWith("LicenseRef-") || node.license.startsWith("DocumentRef-");
  }

  return hasRefLeaf(node.left) || hasRefLeaf(node.right);
}

/**
 * True when EVERY leaf is a LicenseRef-/DocumentRef- reference - distinct from hasRefLeaf's
 * ANY-leaf check.
 */
export function allLeavesAreRefs(node: ExpressionNode): boolean {
  if ("license" in node) {
    return hasRefLeaf(node);
  }

  return allLeavesAreRefs(node.left) && allLeavesAreRefs(node.right);
}

/**
 * Deterministic elected branch: AND keeps both sides (all obligations apply);
 * OR prefers, in order: (a) the non-copyleft branch, (b) among equals the branch with no
 * LicenseRef-/DocumentRef- leaves, (c) code-unit-lexicographic rendered string. WITH leaves are
 * elected as a unit - the exception is never stripped. Order-independent by construction.
 */
export function elect(node: ExpressionNode): ExpressionNode {
  if ("license" in node) {
    return node;
  }

  const left = elect(node.left);
  const right = elect(node.right);

  if (node.conjunction === "and") {
    return { left, conjunction: "and", right };
  }

  const leftCopyleft = isCopyleft(left);
  const rightCopyleft = isCopyleft(right);

  if (leftCopyleft !== rightCopyleft) {
    return leftCopyleft ? right : left;
  }

  const leftRef = hasRefLeaf(left);
  const rightRef = hasRefLeaf(right);

  if (leftRef !== rightRef) {
    return leftRef ? right : left;
  }

  return compareCodeUnits(renderNode(left), renderNode(right)) <= 0 ? left : right;
}

/**
 * Rendered leaves of a pure-OR tree, sorted compareCodeUnits - the decomposition primitive for
 * spdx-satisfies allowlists (its entries must be single ids, optionally WITH). Returns null the
 * moment ANY "and" conjunction appears anywhere in the tree.
 */
export function orLeaves(node: ExpressionNode): string[] | null {
  const leaves: string[] = [];
  const walk = (n: ExpressionNode): boolean => {
    if ("license" in n) {
      leaves.push(renderNode(n));
      return true;
    }

    if (n.conjunction === "and") {
      return false;
    }

    return walk(n.left) && walk(n.right);
  };

  if (!walk(node)) {
    return null;
  }

  return leaves.sort(compareCodeUnits);
}

/**
 * True when `text` parses as a valid SPDX expression carrying an AND/OR conjunction at any level. A
 * free-form label ("Dual License"), a single license ID or an unparseable string return false.
 */
export function isCompoundClaim(text: string): boolean {
  try {
    return "conjunction" in (parseSpdx(text) as ExpressionNode);
  } catch {
    return false;
  }
}

/**
 * Canonicalization's own shape: a leaf is {@link Leaf}; a compound is an n-ary set of same-operator
 * siblings rather than one binary split, so FLATTEN and the set-wide laws below operate on a whole
 * group at once. A canonical node never nests same-operator compounds - {@link canonicalizeNode}
 * flattens them away on construction - so any compound member is always the OPPOSITE operator of
 * its parent set.
 */
type CanonicalNode = Leaf | { op: "and" | "or"; items: CanonicalNode[] };

/**
 * Bare serialization of a canonical node - no outer parens, a compound member parenthesized only
 * when embedded in its parent's join (the one case a canonical tree ever nests a compound, since
 * FLATTEN already ruled out same-operator nesting). Doubles as the structural-equality key for
 * dedupe/absorption below and the sort key for COMMUTATIVITY, mirroring {@link elect}'s existing
 * rendered-string tie-break.
 */
function serializeCanonical(node: CanonicalNode): string {
  if ("license" in node) {
    return renderLeaf(node);
  }

  const operand = (child: CanonicalNode): string =>
    "license" in child ? renderLeaf(child) : `(${serializeCanonical(child)})`;
  const conj = node.op === "or" ? "OR" : "AND";

  return node.items.map(operand).join(` ${conj} `);
}

/**
 * ABSORPTION, both directions, applied simultaneously against the original set so dropping one
 * member never starves another: an AND-sibling `(X OR ...)` is dropped when one of its OR-branches
 * structurally equals another AND-sibling (`A AND (A OR B)` -> `A`); the mirror OR-sibling
 * `(X AND ...)` is dropped when one of its AND-conjuncts structurally equals another OR-sibling (`A
 * OR (A AND B)` -> `A`, the textbook law: choosing A alone already satisfies the OR).
 */
function absorb(op: "and" | "or", items: CanonicalNode[]): CanonicalNode[] {
  const oppositeOp = op === "and" ? "or" : "and";
  const digests = items.map(serializeCanonical);

  return items.filter((item, index) => {
    if ("license" in item || item.op !== oppositeOp) {
      return true;
    }

    const siblingDigests = digests.filter((_, i) => i !== index);

    return !item.items.some((member) => siblingDigests.includes(serializeCanonical(member)));
  });
}

/**
 * Builds one canonical AND/OR level from its already-canonical children: IDEMPOTENCE (dedupe by
 * structural digest, first occurrence wins), then {@link absorb}, then COMMUTATIVITY (sort by
 * rendered form via {@link compareCodeUnits}). A set reduced to one member collapses to that member
 * bare - the recursive base case that lets a whole expression serialize without redundant parens.
 */
function buildSet(op: "and" | "or", rawItems: CanonicalNode[]): CanonicalNode {
  const deduped = new Map<string, CanonicalNode>();

  for (const item of rawItems) {
    const digest = serializeCanonical(item);

    if (!deduped.has(digest)) {
      deduped.set(digest, item);
    }
  }

  const items = absorb(op, [...deduped.values()]).sort((a, b) =>
    compareCodeUnits(serializeCanonical(a), serializeCanonical(b)),
  );

  return items.length === 1 ? items[0]! : { op, items };
}

/**
 * Canonicalizes one parsed node bottom-up: a leaf passes through untouched; a compound FLATTENs any
 * same-operator child into its own item set (`A AND (B AND C)` becomes one AND over {A, B, C})
 * before {@link buildSet} applies dedupe, absorption, and sort. Conservative by construction
 * - FLATTEN, IDEMPOTENCE, ABSORPTION, COMMUTATIVITY only, never distribution or any other
 * cross-operator rewrite.
 */
function canonicalizeNode(node: ExpressionNode): CanonicalNode {
  if ("license" in node) {
    return node;
  }

  const op = node.conjunction;
  const items: CanonicalNode[] = [];

  for (const child of [canonicalizeNode(node.left), canonicalizeNode(node.right)]) {
    if (!("license" in child) && child.op === op) {
      items.push(...child.items);
    } else {
      items.push(child);
    }
  }

  return buildSet(op, items);
}

/**
 * Simplifies a noisy SPDX expression - ScanCode's boolean-algebra redundancy is the motivating
 * case - by the conservative laws in {@link canonicalizeNode}: flatten, dedupe, absorb, and sort,
 * never distribute. Idempotent (canonicalizing the output again is a no-op) and round-trip safe
 * (the output always reparses). Unparseable input is returned UNCHANGED - this never throws and
 * never guesses, the honest-residual posture the rest of this module follows. A comparison built on
 * this output is spelling-blind under reordering, duplication, and absorption noise, but never
 * under re-factoring - `(A OR B) AND (A OR C)` and `A OR (B AND C)` stay distinct - so that
 * direction fails safe as a visible conflict instead of a silently-accepted rewrite.
 */
export function canonicalizeExpression(text: NormalizedLicense | string): CanonicalExpression {
  let parsed: ExpressionNode;

  try {
    parsed = parseSpdx(text) as ExpressionNode;
  } catch {
    // Unparseable input is canonical by the idempotence/round-trip contract - returned verbatim.
    return text as CanonicalExpression;
  }

  return serializeCanonical(canonicalizeNode(parsed)) as CanonicalExpression;
}
