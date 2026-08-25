/**
 * The licence a recorded detection value states, read through the normalizer.
 *
 * A leaf shared by the clarify schema (its license-not-found cross-check) and the justification
 * predicates, so neither has to import the other - the edge that would otherwise close a cycle.
 */
import { normalizeRaw } from "../normalize/normalize";
import type { CanonicalLicense, RawLicense } from "../model/dependencies";

/**
 * The licence a recorded value states, or null when it only labels one - the normalizer reads "MIT
 * License" as MIT, and "Public Domain" as no licence at all.
 */
export function statedLicense(value: RawLicense): CanonicalLicense | null {
  return normalizeRaw(value).expression;
}
