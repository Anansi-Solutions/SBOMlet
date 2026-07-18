/**
 * deps.dev v3 GAV license resolution: the fixed-host URL builder and the
 * honest-sentinel resolver for the Maven miss route.
 *
 * License lookup is a SINGLE fetch against the deps.dev v3 host's per-version
 * JSON (the npm/pypi shape, not nuget's two-step hop): one GET per GAV returns a
 * `licenses` array that is already deps.dev's OWN reading of the effective
 * POM model — a registry claim, not ground truth, so every entry still flows
 * through normalizeRaw downstream (the single SPDX authority) rather than
 * being trusted as pre-resolved.
 *
 * Maven purls carry a `?type=jar` (and sometimes `&classifier=...`) qualifier
 * tail glued onto the version by parsePurl's last-`@` split — the FIRST bug a
 * naive maven arm ships. This module strips it before URL-building while the
 * purl itself stays verbatim everywhere else (cache key, merge key).
 *
 * `"non-standard"` is deps.dev's own honest sentinel for "we could not
 * classify this" — it is dropped, never promoted to a fabricated SPDX id. A
 * `licenses` array with more than one usable entry stays MULTIPLE raw claims:
 * each one normalizes on its own, never concatenated into a synthesized
 * compound expression that deps.dev never asserted.
 */
import { compareCodeUnits } from "../model/dependencies";
import { narrowDepsDevVersion } from "../validate/registry";

/** The deps.dev v3 API base — a FIXED host (the NUGET_API_HOST/SSRF idiom). */
export const DEPS_DEV_API_HOST = "https://api.deps.dev";

/** deps.dev's own "could not classify" sentinel — an honest unknown, never a guess. */
const NON_STANDARD_SENTINEL = "non-standard";

/**
 * Strip a purl qualifier tail (`?type=jar`, `&classifier=...`) from a Maven
 * version segment (Pitfall 1: parsePurl's last-`@` split leaves it glued on).
 * A version with no `?` is returned unchanged.
 */
export function mavenVersionWithoutQualifiers(version: string): string {
  const qmark = version.indexOf("?");
  return qmark === -1 ? version : version.slice(0, qmark);
}

/**
 * Build the deps.dev version-lookup URL for a purl-derived `group/artifact`
 * name and version. Both parts are decoded from their purl encoding,
 * qualifiers are stripped from the version first, and the WHOLE `group:artifact`
 * pair is re-encoded as a SINGLE path segment — so a decoded "/" (or any other
 * purl-embedded separator) can never introduce a real path boundary. The host
 * is a literal; an attacker-shaped purl (extra slashes, "@", odd percent-
 * escapes) can change neither the host nor the path root — SSRF impossible by
 * construction, the nuget.ts idiom.
 */
export function depsDevVersionUrl(
  encodedName: string,
  version: string,
): string {
  const slash = encodedName.indexOf("/");
  const groupEncoded = slash === -1 ? encodedName : encodedName.slice(0, slash);
  const artifactEncoded = slash === -1 ? "" : encodedName.slice(slash + 1);
  const group = decodeURIComponent(groupEncoded);
  const artifact = decodeURIComponent(artifactEncoded);
  const gav = encodeURIComponent(`${group}:${artifact}`);
  const versionOnly = mavenVersionWithoutQualifiers(version);
  const ver = encodeURIComponent(decodeURIComponent(versionOnly));
  return `${DEPS_DEV_API_HOST}/v3/systems/MAVEN/packages/${gav}/versions/${ver}`;
}

/** A resolved deps.dev answer: one or more raw license claims, never synthesized. */
export interface MavenResolution {
  raws: readonly string[];
  via: "deps-dev-licenses";
  confidence: "high";
}

/**
 * Resolve a deps.dev version document's `licenses` array into individual raw
 * claims — the pure resolver (narrow-first, null never throw, the nuget/pypi
 * shape). Each entry is trimmed and kept SEPARATE; `"non-standard"` entries
 * (case-insensitive) are dropped as deps.dev's own honest unknown. Returns
 * null when the document is malformed, carries no `licenses` field, or every
 * entry was dropped (an all-non-standard or genuinely empty answer) — the
 * caller records the SAME governed negative as a definitive 404.
 */
export function resolveMavenLicenses(doc: unknown): MavenResolution | null {
  const parsed = narrowDepsDevVersion(doc);
  if (parsed === undefined || parsed.licenses === undefined) return null;

  const raws = [
    ...new Set(
      parsed.licenses
        .map((license) => license.trim())
        .filter(
          (license) =>
            license !== "" && license.toLowerCase() !== NON_STANDARD_SENTINEL,
        ),
    ),
  ].sort(compareCodeUnits);
  if (raws.length === 0) return null;
  return { raws, via: "deps-dev-licenses", confidence: "high" };
}
