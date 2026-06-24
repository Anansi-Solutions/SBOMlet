/**
 * Deterministic CanonicalDependencies -> CycloneDX 1.6 JSON emitter.
 *
 * Pure function: model (plus optional verdicts) in, exact LF bytes out.
 * Hand-rolled against the official bom-1.6.schema.json: the only required
 * top-level fields are `bomFormat` and `specVersion` — `serialNumber`,
 * `version`, and all of `metadata` (including `timestamp`) are optional, so the
 * no-serial/no-timestamp document emitted here is schema-valid by construction.
 * Components require only `type` + `name`; the expression form of licenseChoice
 * is a single-item tuple whose object is `additionalProperties: false` (only
 * `expression`/`acknowledgement`/`bom-ref` allowed — a stray id/name key
 * invalidates the document); property objects are `{name, value}` where
 * duplicate names are explicitly spec-legal, which carries one
 * `licenses-tool:used-in` property per occurrence cleanly.
 *
 * Determinism: the document object is built with keys already in the intended
 * emission order and serialized with a single JSON.stringify — deliberately not
 * via sortedKeyReplacer, which would reorder bomFormat after specVersion
 * alphabetically. Components are defensively sorted by purl via
 * compareCodeUnits; JSON.stringify never emits CR, so the output is LF-only by
 * construction; JSON.stringify is also the only encoder — no string
 * concatenation ever builds a JSON fragment.
 *
 * This module deliberately does not validate against a schema library
 * (structural tests only), embed attribution or evidence texts (verbatim texts
 * are the notices file's job; embedding here would add ~5-7 MB), or evaluate
 * policy (verdicts arrive pre-computed and pre-sorted).
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

/**
 * #9: os-scope partial unrecognized tokens as named license entries. The
 * tokens arrive deduped + sorted from normalize; each becomes a spec-legal
 * {license:{name}} entry so the machine-readable inventory matches the Markdown
 * render (which surfaces them in the "(+ ...)" suffix). Empty → [].
 */
function unrecognizedLicenses(pkg: PackageEntry): CdxLicense[] {
  const tokens = pkg.finding?.unrecognizedTokens;
  if (tokens === undefined || tokens.length === 0) return [];
  return tokens.map((name) => ({ license: { name } }));
}

/**
 * License dispatch: a normalized expression wins and emits the single-item
 * expression tuple carrying only the expression key; otherwise non-empty raw
 * claims emit named entries deduped by raw in first-seen order; otherwise the
 * licenses key is omitted entirely (valid per schema — components require only
 * type + name).
 *
 * #9: os-scope partial unrecognizedTokens are appended as additional named
 * entries in EVERY branch (after the expression tuple, or alongside the imprecise
 * null-expression finding) so the CycloneDX inventory never silently drops what
 * the Markdown render shows.
 */
function licensesOf(pkg: PackageEntry): CdxLicense[] | undefined {
  const extra = unrecognizedLicenses(pkg);
  if (pkg.finding !== undefined && pkg.finding.expression !== null) {
    return [{ expression: pkg.finding.expression }, ...extra];
  }
  if (pkg.licenseClaims.length > 0) {
    const raws = [...new Set(pkg.licenseClaims.map((claim) => claim.raw))];
    return [...raws.map((raw) => ({ license: { name: raw } })), ...extra];
  }
  // No expression and no raw claims: an imprecise os-partial may still carry
  // surfaced tokens (expression null, claims empty after connective filtering).
  return extra.length > 0 ? extra : undefined;
}

/**
 * Provenance + verdict properties, deterministic order: one
 * `licenses-tool:used-in` per occurrence (stored order is already
 * target-sorted), then one `licenses-tool:scope:<target>` per occurrence, then
 * — only when verdicts are provided — per matching verdict in given (already
 * sorted) order the `licenses-tool:verdict:` and `licenses-tool:rule:` pair.
 * Empty arrays are omitted, never emitted.
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
  if (verdicts !== undefined) {
    for (const verdict of verdicts) {
      if (verdict.purl !== pkg.purl) continue;
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
  // Keys in the intended emission order; optional keys spread in
  // conditionally so absent values OMIT the key rather than emit null.
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
 * Emit the merged, policy-annotated inventory as deterministic CycloneDX 1.6
 * JSON. No serialNumber, no timestamp, components purl-sorted (defensive — the
 * emitter never trusts input order), indent 2, exactly one trailing LF.
 */
export function renderCyclonedx(
  model: CanonicalDependencies,
  verdicts?: ReadonlyArray<Verdict>,
): string {
  const sorted = [...model.packages].sort((a, b) =>
    compareCodeUnits(a.purl, b.purl),
  );
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
