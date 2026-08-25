/**
 * Brand helpers for tests: mint branded values from literals through the production mints, and one
 * widening helper for comparing a branded value against a plain string literal.
 *
 * Tests never reach for `as` to cross a brand boundary - they mint through the same functions
 * production does ({@link asRawLicense}, {@link asPurl}, {@link asAbsolutePath}, and {@link canon}
 * for a canonical license) and widen back with {@link widen}.
 */
import {
  asAbsolutePath,
  asPurl,
  asRawLicense,
  asRelativePath,
  type CanonicalLicense,
  type Purl,
} from "../src/model/dependencies";
import { canonicalizeExpression } from "../src/normalize/expression";

export { asAbsolutePath, asPurl, asRawLicense, asRelativePath };
export type { Purl };

/**
 * Mint a {@link CanonicalLicense} from a test literal by routing it through the production mint
 * ({@link canonicalizeExpression}); a canonical literal is returned verbatim, a non-canonical one is
 * canonicalized.
 */
export const canon = (text: string): CanonicalLicense => canonicalizeExpression(asRawLicense(text));

/** Widen a branded value back to a plain string for a literal assertion. */
export function widen(value: string): string;
export function widen(value: string | null): string | null;
export function widen(value: string | undefined): string | undefined;
export function widen(value: readonly string[]): readonly string[];
export function widen(
  value: string | null | undefined | readonly string[],
): string | null | undefined | readonly string[] {
  return value;
}
