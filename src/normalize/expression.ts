/**
 * SPDX expression AST walker: render, copyleft avoidance, OR-branch election.
 *
 * No library exposes "which OR branch passed" — spdx-satisfies cannot test
 * individual branches and throws on expression-valued allowlists — so branch
 * semantics over the parsed AST are owned here. Copyleft membership is an exact
 * Set lookup on parsed leaf ids only; no substring or prefix matching on
 * license ids anywhere.
 *
 * Pure functions, no I/O, no logging — the CLI owns stderr. Inputs are
 * structurally-typed parse output (spdx-expression-parse internals are never
 * imported).
 */
import { compareCodeUnits } from "../model/dependencies";
import { COPYLEFT_IDS } from "../policy/copyleft";

export type ExpressionNode =
  | { license: string; plus?: true; exception?: string }
  | { left: ExpressionNode; conjunction: "or" | "and"; right: ExpressionNode };

/**
 * Canonical rendering: leaf = `id[+][ WITH exception]`; compound child
 * operands are parenthesized, the top level is not.
 */
export function renderNode(node: ExpressionNode): string {
  if ("license" in node) {
    const plus = node.plus === true ? "+" : "";
    const withPart =
      node.exception !== undefined ? ` WITH ${node.exception}` : "";
    return `${node.license}${plus}${withPart}`;
  }
  const operand = (child: ExpressionNode): string =>
    "license" in child ? renderNode(child) : `(${renderNode(child)})`;
  const conj = node.conjunction === "or" ? "OR" : "AND";
  return `${operand(node.left)} ${conj} ${operand(node.right)}`;
}

/**
 * A finding is copyleft if its expression cannot avoid a copyleft branch:
 * leaf = exact-ID membership (exception does not clear copyleft; a `plus` leaf
 * matches via its base id); AND = any copyleft conjunct taints; OR = copyleft
 * only if both branches are.
 */
export function isCopyleft(node: ExpressionNode): boolean {
  if ("license" in node) return COPYLEFT_IDS.has(node.license);
  if (node.conjunction === "and")
    return isCopyleft(node.left) || isCopyleft(node.right);
  return isCopyleft(node.left) && isCopyleft(node.right);
}

/**
 * License ids of every copyleft leaf in the tree: the obligations a
 * suppression decision must verify against the workspace's own license. Exact
 * COPYLEFT_IDS membership per leaf — a `plus` leaf reports its base id (same
 * convention as isCopyleft); non-copyleft leaves are omitted.
 */
export function copyleftLeafIds(node: ExpressionNode): string[] {
  if ("license" in node) {
    return COPYLEFT_IDS.has(node.license) ? [node.license] : [];
  }
  return [...copyleftLeafIds(node.left), ...copyleftLeafIds(node.right)];
}

/**
 * Every leaf of the tree, decomposed for the notices appendix: `ids` collects
 * each leaf's base license id (a `plus` leaf reports its base id — the
 * copyleftLeafIds convention); `exceptions` collects WITH exception names
 * separately, because spdx-license-list covers licenses, not exceptions — the
 * renderer flags them. No dedup, no sort: callers own set semantics and
 * ordering.
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
 * True if any leaf is a LicenseRef-/DocumentRef- reference. This is SPDX
 * grammar syntax detection (anchored prefix per spec), not license-id
 * matching — election tie-break 2b prefers branches without opaque refs.
 */
function hasRefLeaf(node: ExpressionNode): boolean {
  if ("license" in node)
    return (
      node.license.startsWith("LicenseRef-") ||
      node.license.startsWith("DocumentRef-")
    );
  return hasRefLeaf(node.left) || hasRefLeaf(node.right);
}

/**
 * Deterministic elected branch: AND keeps both sides (all obligations apply);
 * OR prefers, in order: (a) the non-copyleft branch, (b) among equals the
 * branch with no LicenseRef-/DocumentRef- leaves, (c) code-unit-lexicographic
 * rendered string. WITH leaves are elected as a unit — the exception is never
 * stripped. Order-independent by construction.
 */
export function elect(node: ExpressionNode): ExpressionNode {
  if ("license" in node) return node;
  const left = elect(node.left);
  const right = elect(node.right);
  if (node.conjunction === "and") return { left, conjunction: "and", right };
  const leftCopyleft = isCopyleft(left);
  const rightCopyleft = isCopyleft(right);
  if (leftCopyleft !== rightCopyleft) return leftCopyleft ? right : left;
  const leftRef = hasRefLeaf(left);
  const rightRef = hasRefLeaf(right);
  if (leftRef !== rightRef) return leftRef ? right : left;
  return compareCodeUnits(renderNode(left), renderNode(right)) <= 0
    ? left
    : right;
}

/**
 * Rendered leaves of a pure-OR tree, sorted compareCodeUnits — the decomposition
 * primitive for spdx-satisfies allowlists (its entries must be single ids,
 * optionally WITH). Returns null the moment ANY "and" conjunction appears
 * anywhere in the tree.
 */
export function orLeaves(node: ExpressionNode): string[] | null {
  const leaves: string[] = [];
  const walk = (n: ExpressionNode): boolean => {
    if ("license" in n) {
      leaves.push(renderNode(n));
      return true;
    }
    if (n.conjunction === "and") return false;
    return walk(n.left) && walk(n.right);
  };
  if (!walk(node)) return null;
  return leaves.sort(compareCodeUnits);
}
