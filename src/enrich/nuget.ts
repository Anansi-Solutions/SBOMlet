/**
 * NuGet registration-API license resolution: the fixed-host URL builder, the
 * catalogEntry host pin, and the pure metadata-class ladder.
 *
 * License lookup is a TWO-STEP fetch against static, versioned CDN blobs: the
 * registration leaf `/v3/registration5-gz-semver2/{id}/{version}.json`
 * carries a `catalogEntry` URL, and THAT document carries the license fields.
 * Casing is load-bearing: the leaf URL 404s unless BOTH the id and the
 * version are lowercased — while the purl (the cache key) stays VERBATIM, so
 * lowercasing happens ONLY inside the URL builder here, never upstream.
 *
 * A clean 404 on the leaf means "not on nuget.org" — a common, legitimate
 * private-feed reality — and the orchestrator (enrich.ts) classifies it as a
 * definitive negative: the package stays honestly unknown, generate never
 * hard-fails on it, and no guess is ever recorded.
 */
import { narrowNugetCatalogEntry, narrowNugetLeaf } from "../validate/registry";

/** The NuGet V3 API base — a FIXED host (the SSRF control, the GITHUB_API_HOST idiom). */
export const NUGET_API_HOST = "https://api.nuget.org";

/** The licenses.nuget.org prefix whose URL PATH is the SPDX expression itself. */
const LICENSES_NUGET_ORG_PREFIX = "https://licenses.nuget.org/";

/**
 * The registration leaf URL for a purl-derived id + version. BOTH path parts
 * are decoded from their purl encoding, LOWERCASED (the registry 404s a
 * mixed-case path — verified differential), and re-encoded per segment. The
 * host is a literal; an attacker-controlled host is impossible by
 * construction (T-15-10).
 */
export function nugetRegistrationLeafUrl(
  encodedName: string,
  version: string,
): string {
  const id = encodeURIComponent(decodeURIComponent(encodedName).toLowerCase());
  const ver = encodeURIComponent(decodeURIComponent(version).toLowerCase());
  return `${NUGET_API_HOST}/v3/registration5-gz-semver2/${id}/${ver}.json`;
}

/**
 * The catalogEntry URL from a registration leaf, HOST-PINNED: only a string
 * that starts with the `https://api.nuget.org/` prefix (trailing slash
 * INCLUDED, so `api.nuget.org.evil.example` can never pass) is returned. A
 * missing field, a non-string, or ANY other host yields undefined — the
 * caller treats that as malformed (a clean negative, no request ever made to
 * a foreign host), closing the response-derived SSRF hole (T-15-09).
 */
export function catalogEntryUrlOf(leaf: unknown): string | undefined {
  const url = narrowNugetLeaf(leaf)?.catalogEntry;
  if (url === undefined || !url.startsWith(`${NUGET_API_HOST}/`)) {
    return undefined;
  }
  return url;
}

/** A resolved raw license: the string, which metadata class won, and a confidence. */
export interface NugetResolution {
  raw: string;
  via: "license-expression" | "license-url-spdx";
  confidence: "high";
}

/**
 * Resolve a raw license from a NuGet catalogEntry document — the pure
 * four-class metadata ladder (the pypi.ts shape: narrow-first, null never
 * throw). Each class maps to an HONEST outcome; this module never guesses,
 * and normalizeRaw downstream stays the single SPDX resolution authority:
 *
 *   1. `licenseExpression` non-empty → the expression verbatim, HIGH.
 *   2. `licenseFile` present (embedded file) → NULL. The license TEXT lives
 *      inside the nupkg, out of reach here — an honest unknown, never a
 *      guess. Checked BEFORE `licenseUrl` so the `aka.ms/deprecateLicenseUrl`
 *      sentinel that accompanies embedded files can never be misread as a
 *      real URL.
 *   3. `licenseUrl` beginning `https://licenses.nuget.org/` → the URL PATH
 *      IS the SPDX expression, URL-encoded: strip the prefix and decode,
 *      HIGH. An empty or undecodable remainder → null.
 *   4. Any other `licenseUrl` (the pre-2019 url-only class) or no license
 *      fields at all → NULL — honest unknown.
 */
export function resolveNugetCatalogLicense(
  doc: unknown,
): NugetResolution | null {
  const entry = narrowNugetCatalogEntry(doc);
  if (entry === undefined) return null;

  const expression = entry.licenseExpression?.trim();
  if (expression !== undefined && expression !== "") {
    return { raw: expression, via: "license-expression", confidence: "high" };
  }

  // Embedded file BEFORE licenseUrl: the aka.ms sentinel never reads as a URL.
  if (entry.licenseFile !== undefined && entry.licenseFile !== "") return null;

  const url = entry.licenseUrl;
  if (url !== undefined && url.startsWith(LICENSES_NUGET_ORG_PREFIX)) {
    const decoded = decodeSpdxPath(url.slice(LICENSES_NUGET_ORG_PREFIX.length));
    if (decoded !== undefined && decoded !== "") {
      return { raw: decoded, via: "license-url-spdx", confidence: "high" };
    }
  }
  return null; // url-only (pre-2019) or nothing — honest unknown, never a guess
}

/** decodeURIComponent that yields undefined on a malformed escape (never throws). */
function decodeSpdxPath(path: string): string | undefined {
  try {
    return decodeURIComponent(path);
  } catch {
    return undefined;
  }
}
