/**
 * arktype boundary for the consumed CycloneDX SBOM subset (tolerant posture). Undeclared keys are
 * ignored (arktype's default) - the volatile-field tolerance. A failed narrow takes the caller's
 * existing skip path: malformed documents and entries are skipped, never thrown on.
 */
import { type } from "arktype";

import {
  asPurl,
  asRawLicense,
  encodePurlSegment,
  tryAsPurl,
  type Purl,
} from "../model/dependencies";
import { ArrayOrAbsent, recordOf } from "./record";

/**
 * The external SBOM is the parse boundary for its purls and license claims, so both are branded
 * here at first validation - {@link tryAsPurl} / {@link asRawLicense} - rather than one step
 * downstream in merge. A component purl becomes a {@link Purl}; a CycloneDX license-claim string
 * becomes a RawLicense.
 *
 * TOLERANT purl: an SBOM is untrusted, so a component whose purl is not a `pkg:` package URL has
 * the purl coerced to undefined (the field is then absent) rather than throwing - the component
 * drops via merge's existing purl/name/version gate, matching the {@link StringOrAbsent} posture
 * the rest of this file uses for wrong-typed fields.
 */
const SbomPurl = type("string").pipe((value) => tryAsPurl(value));
const SbomRawLicense = type("string").pipe((value) => asRawLicense(value));

/**
 * Whole-document subset: ONLY the components array is a document-level drop gate. The root purl is
 * NOT declared here - a malformed `metadata` (the JSON generators emit `metadata: null` freely for
 * absent fields) must never drop the whole components array. The root purl is extracted by the
 * separate tolerant SbomRootPurl narrow below, matching the pre-refactor per-field walk: a
 * non-string/absent root purl is simply ABSENT while every component still walks and emits.
 */
export const SbomDocument = type({
  "components?": "unknown[]",
  /**
   * The CycloneDX dependency graph (provenance input). Tolerant: a non-array (or a
   * present-but-malformed) value is simply absent - never a document drop. Per-edge narrowing
   * happens entry-by-entry via SbomDependencyEdge.
   */
  "dependencies?": ArrayOrAbsent,
});

/**
 * Tolerant root-purl extraction, independent of the document narrow: the metadata/component/purl
 * path is read field-by-field, and any deviation (metadata: null, component: 5, purl: <number>)
 * coerces the result to undefined - the package-exclusion root is simply absent, never a document
 * drop. Mirrors the old rootComponentPurl semantics exactly.
 */
const SbomRootPurl = type({
  "metadata?": { "component?": { "purl?": "string" } },
}).pipe((doc) => {
  const purl = doc.metadata?.component?.purl;

  return purl === undefined ? undefined : tryAsPurl(purl);
});

/** The root component purl, or undefined for any absent/malformed metadata. */
export function rootPurlOf(sbom: unknown): Purl | undefined {
  const result = SbomRootPurl(sbom);

  return result instanceof type.errors ? undefined : result;
}

/**
 * A string field that coerces a present-but-wrong-typed value to undefined (the field is then
 * omitted) instead of failing the whole-component narrow. This restores the pre-refactor per-field
 * leniency: only purl/name/version gate a component; every other optional is lenient.
 */
const StringOrAbsent = type("string")
  .or("unknown")
  .pipe((value) => (typeof value === "string" ? value : undefined));

/**
 * The evidence field: coerces any non-record value to undefined, and inside a record coerces a
 * non-array `licenses` to undefined - so a wrong-typed evidence (or evidence.licenses) is treated
 * as absent, never a package drop. Written as a single unknown→morph (an object-shape union with an
 * inner morph is indeterminate in arktype).
 */
const EvidenceOrAbsent = type("unknown").pipe((value): { licenses?: unknown[] } | undefined => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }

  const licenses = (value as { licenses?: unknown }).licenses;

  return Array.isArray(licenses) ? { licenses } : {};
});

/**
 * One CycloneDX dependency-graph edge (provenance input): a `ref` bom-ref and its `dependsOn`
 * bom-ref list. Both optional + tolerant, mirroring the component posture: a missing/mistyped `ref`
 * or `dependsOn` coerces to undefined so the edge is skipped, never thrown on. `dependsOn` items
 * stay unknown[] - the per-item string filter is explicit in the collector.
 */
export const SbomDependencyEdge = type({
  "ref?": StringOrAbsent,
  "dependsOn?": ArrayOrAbsent,
});

/**
 * Per-entry component subset, applied entry-by-entry (filter-after-parse preserves
 * skip-don't-throw). Only the purl/name/version triple is a drop gate (enforced explicitly in
 * merge.ts) - every OTHER field is lenient: a present-but-wrong-typed
 * group/scope/author/licenses/properties/evidence coerces to undefined and is treated as absent,
 * never dropping the package. licenses/properties/evidence.licenses entries stay unknown[] because
 * the per-entry leniency over their items remains explicit code in merge.ts.
 */
export const SbomComponent = type({
  "purl?": SbomPurl,
  "name?": "string",
  "version?": "string",
  /**
   * CycloneDX bom-ref (provenance input): the graph edges key on bom-ref, so the collector builds a
   * bomRef→purl join from this. Tolerant - a mistyped/absent bom-ref is simply absent, never a
   * package drop.
   */
  "bom-ref?": StringOrAbsent,
  "group?": StringOrAbsent,
  "scope?": StringOrAbsent,
  "author?": StringOrAbsent,
  "licenses?": ArrayOrAbsent,
  "properties?": ArrayOrAbsent,
  "evidence?": EvidenceOrAbsent,
});

export type SbomComponentShape = typeof SbomComponent.infer;

/**
 * Every entry of a components array in document pre-order, descending into each entry's own
 * `components` array (CycloneDX nests sub-components there). Entries are returned unnarrowed.
 *
 * @privateRemarks Iterative and spread-free, so neither a deeply nested nor a very wide crafted
 * document can overflow the stack.
 */
export function componentTreeOf(components: ReadonlyArray<unknown>): unknown[] {
  const walked: unknown[] = [];
  const pending = [...components].reverse();

  while (pending.length > 0) {
    const raw = pending.pop();
    const children: unknown = recordOf(raw)?.["components"];

    walked.push(raw);

    if (Array.isArray(children)) {
      const siblings: readonly unknown[] = children;

      for (let index = siblings.length - 1; index >= 0; index--) {
        pending.push(siblings[index]);
      }
    }
  }

  return walked;
}

/** One narrowed component of a document, and how its purl was obtained. */
export interface DocumentComponent {
  component: SbomComponentShape;
  /** The document carried no usable purl, so one was minted from group/name/version. */
  purlMinted: boolean;
}

/**
 * Whether the document is a Maven module's BOM, read from its root purl type.
 *
 * @privateRemarks
 * Keyed on document content rather than a tag from the collector, so every reader of the same bytes
 * (the merge, the prod purl set, the coverage count) reaches the same verdict, and the merge stays
 * free of collector knowledge.
 */
export function isMavenModuleRoot(rootPurl: Purl | undefined): boolean {
  return rootPurl?.startsWith("pkg:maven/") === true;
}

/**
 * The `pkg:maven/<group>/<name>@<version>` purl for a Maven row without one, such as a
 * `system`-scoped or hand-added jar.
 *
 * @returns undefined when any of the three coordinates is absent or blank.
 * @privateRemarks
 * No `?type=` qualifier: the packaging of a hand-added row is unknown, so the minted purl never
 * folds with a plugin-emitted `?type=jar` purl of the same coordinates.
 */
function mintedMavenPurlOf(component: SbomComponentShape): Purl | undefined {
  const { group, name, version } = component;

  if (group === undefined || name === undefined || version === undefined) {
    return undefined;
  }

  if ([group, name, version].some((coordinate) => coordinate.trim() === "")) {
    return undefined;
  }

  return asPurl(
    `pkg:maven/${encodePurlSegment(group)}/${encodePurlSegment(name)}@${encodePurlSegment(version)}`,
  );
}

/**
 * Narrow one raw component, minting its purl when the document is a Maven module's BOM (see {@link
 * isMavenModuleRoot}) and the component carries no usable purl.
 *
 * @returns `"malformed"` when the component narrow fails.
 */
export function documentComponentOf(
  raw: unknown,
  mintsMavenPurls: boolean,
): DocumentComponent | "malformed" {
  const component = SbomComponent(raw);

  if (component instanceof type.errors) {
    return "malformed";
  }

  const minted =
    mintsMavenPurls && component.purl === undefined ? mintedMavenPurlOf(component) : undefined;

  return minted === undefined
    ? { component, purlMinted: false }
    : { component: { ...component, purl: minted }, purlMinted: true };
}

/**
 * Every component of a document, nested ones included, in document pre-order, through {@link
 * documentComponentOf}. Empty for a malformed document or one without components.
 */
export function documentComponentsOf(sbom: unknown): Array<DocumentComponent | "malformed"> {
  const doc = SbomDocument(sbom);

  if (doc instanceof type.errors) {
    return [];
  }

  const mintsMavenPurls = isMavenModuleRoot(rootPurlOf(sbom));

  return componentTreeOf(doc.components ?? []).map((raw) =>
    documentComponentOf(raw, mintsMavenPurls),
  );
}

// The three CycloneDX license claim shapes, tried in this order - expression, then license.id, then
// license.name (the merge.ts fall-through contract; a mistyped field falls through to the next
// shape).
export const SbomExpressionClaim = type({ expression: SbomRawLicense });
export const SbomIdClaim = type({ license: { id: SbomRawLicense } });
export const SbomNameClaim = type({ license: { name: SbomRawLicense } });

/** One usable evidence attachment; any other shape is skipped by the caller. */
export const SbomEvidenceEntry = type({
  license: {
    name: "string",
    text: { content: "string", encoding: "'base64'" },
  },
});

/** properties[] entry - name/value compared verbatim by the consumers. */
export const SbomPropertyEntry = type({
  "name?": "unknown",
  "value?": "unknown",
});
