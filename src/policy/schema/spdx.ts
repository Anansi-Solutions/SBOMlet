/**
 * Shared arktype building blocks for the SPDX-valued policy fields.
 *
 * Every license pattern, clarify expression, and workspace license is parsed eagerly at validation
 * so evaluation never meets an unparseable rule. These morphs carry that parse into the declarative
 * layer: a field typed {@link spdxExpression} rejects unparseable text in place, and {@link
 * withLicenseAllowlist} enriches a license-mode entry with its pre-decomposed satisfies allowlist,
 * rejecting an AND pattern up front (satisfies allowlists cannot hold AND expressions).
 */
import { type, type Traversal } from "arktype";

import parseSpdx from "spdx-expression-parse";
import { orLeaves, type ExpressionNode } from "../../normalize/expression";

/** Parse an SPDX expression, or undefined when it does not parse. */
export function parseSpdxNode(value: string): ExpressionNode | undefined {
  try {
    return parseSpdx(value) as ExpressionNode;
  } catch {
    return undefined;
  }
}

/**
 * A string field that must be a parseable SPDX expression. The value flows through unchanged - the
 * parse validates, it does not rewrite - so the field stays the verbatim text the policy wrote.
 */
export const spdxExpression = type("string").pipe((value, ctx) =>
  parseSpdxNode(value) === undefined
    ? ctx.reject({ message: `"${value}" is not a valid SPDX expression` })
    : value,
);

/**
 * Enrich a license-mode entry with the OR-leaf satisfies allowlist decomposed from its `pattern`.
 * Rejects at `pattern` when the text does not parse, or when it carries an AND - a satisfies
 * allowlist holds single ids (optionally WITH), never AND expressions. Shared by the
 * `[[compatible]]` and `[[deny]]` license forms, which decompose their pattern identically.
 */
export function withLicenseAllowlist<T extends { readonly pattern: string }>(
  entry: T,
  ctx: Traversal,
): (T & { allowlist: ReadonlyArray<string> }) | false {
  const node = parseSpdxNode(entry.pattern);

  if (node === undefined) {
    return ctx.reject({
      relativePath: ["pattern"],
      message: `"${entry.pattern}" is not a valid SPDX expression`,
    });
  }

  const allowlist = orLeaves(node);

  if (allowlist === null) {
    return ctx.reject({
      relativePath: ["pattern"],
      message: `"${entry.pattern}" must be a license ID or an OR of license IDs (AND is not allowed — satisfies allowlists cannot hold AND expressions)`,
    });
  }

  return { ...entry, allowlist };
}
