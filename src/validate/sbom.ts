/**
 * arktype boundary for the consumed CycloneDX SBOM subset (tolerant posture).
 * Undeclared keys are ignored (arktype's default) — the volatile-field
 * tolerance. A failed narrow takes the caller's existing skip path: malformed
 * documents and entries are skipped, never thrown on.
 */
import { type } from "arktype";

/**
 * Whole-document subset: ONLY the components array is a document-level drop
 * gate. The root purl is NOT declared here — a malformed `metadata` (the JSON
 * generators emit `metadata: null` freely for absent fields) must never drop
 * the whole components array. The root purl is extracted by the separate
 * tolerant SbomRootPurl narrow below, matching the pre-refactor per-field
 * walk: a non-string/absent root purl is simply ABSENT while every component
 * still walks and emits.
 */
export const SbomDocument = type({
  "components?": "unknown[]",
  // The CycloneDX dependency graph (07-13 provenance). Tolerant: a non-array
  // (or a present-but-malformed) value is simply absent — never a document
  // drop. Per-edge narrowing happens entry-by-entry via SbomDependencyEdge.
  "dependencies?": "unknown[]",
});

/**
 * Tolerant root-purl extraction, independent of the document narrow: the
 * metadata/component/purl path is read field-by-field, and any deviation
 * (metadata: null, component: 5, purl: <number>) coerces the result to
 * undefined — the package-exclusion root is simply absent, never a document
 * drop. Mirrors the old rootComponentPurl semantics exactly.
 */
const SbomRootPurl = type({
  "metadata?": { "component?": { "purl?": "string" } },
}).pipe((doc) => doc.metadata?.component?.purl);

/** The root component purl, or undefined for any absent/malformed metadata. */
export function rootPurlOf(sbom: unknown): string | undefined {
  const result = SbomRootPurl(sbom);
  return result instanceof type.errors ? undefined : result;
}

/**
 * A string field that coerces a present-but-wrong-typed value to undefined
 * (the field is then omitted) instead of failing the whole-component narrow.
 * This restores the pre-refactor per-field leniency: only purl/name/version
 * gate a component; every other optional is lenient.
 */
const StringOrAbsent = type("string")
  .or("unknown")
  .pipe((value) => (typeof value === "string" ? value : undefined));

/** An array field that coerces a present-but-non-array value to undefined. */
const ArrayOrAbsent = type("unknown[]")
  .or("unknown")
  .pipe((value) => (Array.isArray(value) ? value : undefined));

/**
 * The evidence field: coerces any non-record value to undefined, and inside a
 * record coerces a non-array `licenses` to undefined — so a wrong-typed
 * evidence (or evidence.licenses) is treated as absent, never a package drop.
 * Written as a single unknown→morph (an object-shape union with an inner morph
 * is indeterminate in arktype).
 */
const EvidenceOrAbsent = type("unknown").pipe(
  (value): { licenses?: unknown[] } | undefined => {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return undefined;
    }
    const licenses = (value as { licenses?: unknown }).licenses;
    return Array.isArray(licenses) ? { licenses } : {};
  },
);

/**
 * One CycloneDX dependency-graph edge (07-13 provenance): a `ref` bom-ref and
 * its `dependsOn` bom-ref list. Both optional + tolerant, mirroring the
 * component posture: a missing/mistyped `ref` or `dependsOn` coerces to
 * undefined so the edge is skipped, never thrown on. `dependsOn` items stay
 * unknown[] — the per-item string filter is explicit in the collector.
 */
export const SbomDependencyEdge = type({
  "ref?": StringOrAbsent,
  "dependsOn?": ArrayOrAbsent,
});

/**
 * Per-entry component subset, applied entry-by-entry (filter-after-parse
 * preserves skip-don't-throw). Only the purl/name/version triple is a drop
 * gate (enforced explicitly in merge.ts) — every OTHER field is lenient: a
 * present-but-wrong-typed group/scope/author/licenses/properties/evidence
 * coerces to undefined and is treated as absent, never dropping the package.
 * licenses/properties/evidence.licenses entries stay unknown[] because the
 * per-entry leniency over their items remains explicit code in merge.ts.
 */
export const SbomComponent = type({
  "purl?": "string",
  "name?": "string",
  "version?": "string",
  // CycloneDX bom-ref (07-13 provenance): the graph edges key on bom-ref, so the
  // collector builds a bomRef→purl join from this. Tolerant — a mistyped/absent
  // bom-ref is simply absent, never a package drop.
  "bom-ref?": StringOrAbsent,
  "group?": StringOrAbsent,
  "scope?": StringOrAbsent,
  "author?": StringOrAbsent,
  "licenses?": ArrayOrAbsent,
  "properties?": ArrayOrAbsent,
  "evidence?": EvidenceOrAbsent,
});

export type SbomComponentShape = typeof SbomComponent.infer;

// The three CycloneDX license claim shapes, tried in this order —
// expression, then license.id, then license.name (the merge.ts
// fall-through contract; a mistyped field falls through to the next shape).
export const SbomExpressionClaim = type({ expression: "string" });
export const SbomIdClaim = type({ license: { id: "string" } });
export const SbomNameClaim = type({ license: { name: "string" } });

/** One usable evidence attachment; any other shape is skipped by the caller. */
export const SbomEvidenceEntry = type({
  license: {
    name: "string",
    text: { content: "string", encoding: "'base64'" },
  },
});

/** properties[] entry — name/value compared verbatim by the consumers. */
export const SbomPropertyEntry = type({
  "name?": "unknown",
  "value?": "unknown",
});
