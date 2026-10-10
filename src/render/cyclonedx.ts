/**
 * Deterministic CanonicalDependencies -> CycloneDX 1.6 JSON emitter.
 *
 * Pure function: model (plus optional verdicts) in, exact LF bytes out. Hand-rolled against the
 * official bom-1.6.schema.json: the only required top-level fields are `bomFormat` and
 * `specVersion` - `serialNumber`, `version`, and all of `metadata` (including `timestamp`) are
 * optional, so the no-serial/no-timestamp document emitted here is schema-valid by construction.
 * Components require only `type` + `name`; licenseChoice is EITHER an array of `{license}` entries
 * OR a single-item tuple whose object is `additionalProperties: false` (only
 * `expression`/`acknowledgement`/`bom-ref` allowed), never a mix - so an os-scope token that an
 * expression cannot name travels as a property instead; property objects are `{name, value}` where
 * duplicate names are explicitly spec-legal, which carries one `licenses-tool:used-in` property per
 * occurrence cleanly.
 *
 * Determinism: the document object is built with keys already in the intended emission order and
 * serialized with a single JSON.stringify - deliberately not via sortedKeyReplacer, which would
 * reorder bomFormat after specVersion alphabetically. Components are defensively sorted by purl via
 * compareCodeUnits; JSON.stringify never emits CR, so the output is LF-only by
 * construction; JSON.stringify is also the only encoder - no string
 * concatenation ever builds a JSON fragment.
 *
 * This module deliberately does not validate against a schema library (structural tests only),
 * embed attribution or evidence texts (verbatim texts are the notices file's job; embedding here
 * would add ~5-7 MB), or evaluate policy (verdicts arrive pre-computed and pre-sorted).
 */

import {
  compareCodeUnits,
  type CanonicalDependencies,
  type PackageEntry,
  type Verdict,
} from "../model/dependencies";

type CdxLicense = { expression: string } | { license: { name: string } };

interface CdxProperty {
  name: string;
  value: string;
}

interface CdxComponent {
  type: "library";
  name: string;
  version: string;
  purl: string;
  "bom-ref": string;
  licenses?: CdxLicense[];
  properties?: CdxProperty[];
}

/** The finding's unrecognized os-scope tokens, as normalize left them (deduped, sorted). */
function unrecognizedTokensOf(pkg: PackageEntry): readonly string[] {
  return pkg.finding?.unrecognizedTokens ?? [];
}

/**
 * License dispatch, honoring licenseChoice's XOR (named entries, or exactly one expression entry):
 * a normalized expression emits the single expression tuple, its unrecognized tokens going to
 * properties instead; otherwise the raw claims plus unrecognized tokens emit named entries, deduped
 * in first-seen order; with neither, the key is omitted.
 */
function licensesOf(pkg: PackageEntry): CdxLicense[] | undefined {
  if (pkg.finding !== undefined && pkg.finding.expression !== null) {
    return [{ expression: pkg.finding.expression }];
  }

  const names = new Set<string>([
    ...pkg.licenseClaims.map((claim) => claim.raw),
    ...unrecognizedTokensOf(pkg),
  ]);

  return names.size === 0 ? undefined : [...names].map((name) => ({ license: { name } }));
}

/**
 * Unrecognized tokens that {@link licensesOf} could not name because an expression took the
 * licenses key: one `licenses-tool:unrecognized-license` property per token.
 */
function unrecognizedLicenseProperties(pkg: PackageEntry): CdxProperty[] {
  if (pkg.finding === undefined || pkg.finding.expression === null) {
    return [];
  }

  return unrecognizedTokensOf(pkg).map((value) => ({
    name: "licenses-tool:unrecognized-license",
    value,
  }));
}

/**
 * Provenance + verdict properties, deterministic order: one `licenses-tool:used-in` per occurrence
 * (stored order is already target-sorted), then one `licenses-tool:scope:<target>` per occurrence,
 * then the unrecognized-license tokens, then - only when verdicts are provided - per matching
 * verdict in given (already sorted) order the `licenses-tool:verdict:` and `licenses-tool:rule:`
 * pair. Empty arrays are omitted, never emitted.
 */
function propertiesOf(
  pkg: PackageEntry,
  verdicts: ReadonlyArray<Verdict> | undefined,
): CdxProperty[] | undefined {
  const properties: CdxProperty[] = [];

  for (const occurrence of pkg.occurrences) {
    properties.push({
      name: "licenses-tool:used-in",
      value: occurrence.target,
    });
  }

  for (const occurrence of pkg.occurrences) {
    properties.push({
      name: `licenses-tool:scope:${occurrence.target}`,
      value: occurrence.isDevDependency ? "dev" : "prod",
    });
  }

  properties.push(...unrecognizedLicenseProperties(pkg));

  if (verdicts !== undefined) {
    for (const verdict of verdicts) {
      if (verdict.purl !== pkg.purl) {
        continue;
      }

      properties.push({
        name: `licenses-tool:verdict:${verdict.occurrenceTarget}`,
        value: verdict.status,
      });
      properties.push({
        name: `licenses-tool:rule:${verdict.occurrenceTarget}`,
        value: verdict.rule,
      });
    }
  }

  return properties.length === 0 ? undefined : properties;
}

function toComponent(
  pkg: PackageEntry,
  verdicts: ReadonlyArray<Verdict> | undefined,
): CdxComponent {
  const licenses = licensesOf(pkg);
  const properties = propertiesOf(pkg, verdicts);

  // Keys in the intended emission order; optional keys spread in conditionally so absent values
  // OMIT the key rather than emit null.
  return {
    type: "library",
    name: pkg.name,
    version: pkg.version,
    purl: pkg.purl,
    "bom-ref": pkg.purl,
    ...(licenses === undefined ? {} : { licenses }),
    ...(properties === undefined ? {} : { properties }),
  };
}

/**
 * Emit the merged, policy-annotated inventory as deterministic CycloneDX 1.6 JSON. No serialNumber,
 * no timestamp, components purl-sorted (defensive - the emitter never trusts input order), indent
 * 2, exactly one trailing LF.
 */
export function renderCyclonedx(
  model: CanonicalDependencies,
  verdicts?: ReadonlyArray<Verdict>,
): string {
  const sorted = [...model.packages].sort((a, b) => compareCodeUnits(a.purl, b.purl));
  const doc = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    metadata: {
      tools: {
        components: [{ type: "application", name: "licenses-tool" }],
      },
    },
    components: sorted.map((pkg) => toComponent(pkg, verdicts)),
  };

  return JSON.stringify(doc, null, 2) + "\n";
}
