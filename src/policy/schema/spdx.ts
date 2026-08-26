/**
 * Shared building blocks for the SPDX-valued policy fields.
 *
 * Every license pattern, clarify expression, and workspace license is parsed eagerly at validation
 * so evaluation never meets an unparseable rule. {@link spdxExpression} carries that parse into the
 * declarative layer - a field typed with it rejects unparseable text in place - while {@link
 * licenseAllowlist} decomposes a license pattern into the satisfies allowlist the evaluator reads,
 * rejecting an AND pattern up front (satisfies allowlists cannot hold AND expressions).
 */
import { type } from "arktype";

import parseSpdx from "spdx-expression-parse";
import {
  asRawLicense,
  type CanonicalLicense,
  type SpdxLicenseLeaf,
} from "../../model/dependencies";
import { canonicalizeExpression, orLeaves, type ExpressionNode } from "../../normalize/expression";

/** Parse an SPDX expression, or undefined when it does not parse. */
export function parseSpdxNode(value: string): ExpressionNode | undefined {
  try {
    return parseSpdx(value) as ExpressionNode;
  } catch {
    return undefined;
  }
}

/**
 * A field that must be a parseable SPDX expression, canonicalized to the tool-wide {@link
 * CanonicalLicense} state on the way through. The parse validates; {@link canonicalizeExpression}
 * then resolves the value into the single canonical form the rest of the model carries, so a policy
 * expression is minted the same way every other resolved license is - there is no verbatim-policy
 * intermediate.
 */
export const spdxExpression = type("string").pipe(
  (value, ctx): CanonicalLicense =>
    parseSpdxNode(value) === undefined
      ? (ctx.reject({ message: `"${value}" is not a valid SPDX expression` }) as never)
      : canonicalizeExpression(asRawLicense(value)),
);

/**
 * The OR-leaf satisfies allowlist decomposed from a license pattern, or the one fault that ruled it
 * out: an unparseable pattern, or an AND pattern (a satisfies allowlist holds single ids,
 * optionally WITH, never AND expressions). Shared by the `[[compatible]]` and `[[deny]]` license
 * forms, which decompose their pattern identically.
 */
export function licenseAllowlist(pattern: string): {
  allowlist?: ReadonlyArray<SpdxLicenseLeaf>;
  problem?: string;
} {
  const node = parseSpdxNode(pattern);

  if (node === undefined) {
    return { problem: `"${pattern}" is not a valid SPDX expression` };
  }

  const allowlist = orLeaves(node);

  if (allowlist === null) {
    return {
      problem: `"${pattern}" must be a license ID or an OR of license IDs (AND is not allowed — satisfies allowlists cannot hold AND expressions)`,
    };
  }

  return { allowlist };
}
