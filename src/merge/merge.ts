/**
 * Purl-keyed merge of CycloneDX documents into the canonical model.
 *
 * The consumed subset is narrowed by the shared arktype boundary in
 * src/validate/sbom.ts — the official JS library is serialize-only and cannot
 * deserialize CycloneDX JSON. Every unknown field is tolerated and ignored;
 * the volatile document-level fields are never declared, so they can never
 * leak into compared content. A failed narrow is a skip, never a throw.
 *
 * Pure function: no I/O, no logging (the CLI owns stderr).
 */

import { type } from "arktype";

import { extractCopyrightLines } from "../extract/copyright";
import {
  compareCodeUnits,
  comparePackages,
  type CanonicalDependencies,
  type DependencyIntroduction,
  type LicenseClaim,
  type Occurrence,
  type PackageAttribution,
  type PackageEntry,
  type ScopeTaxonomy,
} from "../model/dependencies";
import {
  rootPurlOf,
  SbomComponent,
  SbomDocument,
  SbomEvidenceEntry,
  SbomExpressionClaim,
  SbomIdClaim,
  SbomNameClaim,
  SbomPropertyEntry,
  type SbomComponentShape,
} from "../validate/sbom";

export interface CollectedSbom {
  /** Parsed CycloneDX JSON document, treated as an untrusted shape. */
  sbom: unknown;
  /** Forward-slash repo-relative target identity, e.g. "libraries/iframe-rpc". */
  targetIdentity: string;
  /**
   * Purl set of the --production run. When present (plugin targets), the
   * dual-run diff is authoritative: occurrence dev = !prodPurlSet.has(purl).
   * When absent, the property-based markers apply. Built from an untrusted
   * document via purlSetOf, same tolerance posture as sbom.
   */
  prodPurlSet?: ReadonlySet<string>;
  /**
   * First-party names from the target's own lockfile (firstPartyNames() /
   * npmFirstPartyNames()). Components matching by display name and carrying a
   * second first-party signal are skipped. Two second signals are accepted:
   * the yarn/plugin local-version marker (version === "0.0.0-use.local") or
   * the cdxgen npm workspace property (cdx:npm:isWorkspace === "true") — npm
   * members carry their real versions, so the yarn version guard must never be
   * reused for them. Both conditions are always required: a name collision
   * alone can never drop a third-party package, and a crafted marker alone can
   * never drop one either.
   */
  firstPartyNames?: ReadonlySet<string>;
  /**
   * Package-level scope taxonomy for every component this input contributes.
   * Absent defaults to "app" (the JS/Python/Terraform targets). The Docker
   * OS-package merge input sets "os" so its pkg:deb/pkg:apk rows are
   * routed through the [os_dependencies] policy lane and rendered in the
   * dedicated Docker base-image section.
   */
  scope?: ScopeTaxonomy;
  /**
   * Per-purl dependency provenance for THIS target (07-13), keyed by purl. When
   * present (the npm/yarn and python lanes), each component's occurrence gets the
   * matching introduction; a purl absent from the map gets none (the honest
   * residual). Absent entirely for graph-less sources (terraform / Docker OS /
   * bun) — every occurrence then carries no introduction and goldens stay
   * byte-identical. Introduction is PER-TARGET, so it is attached at occurrence
   * creation and rides through the merge unchanged (no cross-purl
   * reconciliation).
   */
  introductions?: ReadonlyMap<string, DependencyIntroduction>;
}

/** Property name cdxgen uses to mark JS dev dependencies. */
const DEV_PROPERTY = "cdx:npm:package:development";

/**
 * Property name cdxgen pairs with DEV_PROPERTY on optional-prod components.
 * Optional always appears together with development=true in cdxgen output, so
 * without the guard those prod binaries vanish into the dev column.
 */
const OPTIONAL_PROPERTY = "cdx:npm:package:optional";

/**
 * Property name cdxgen emits for poetry group membership. Only the
 * conventional "dev" group maps to dev scope; custom groups and group-less
 * components stay prod (conservative).
 */
const PYPROJECT_GROUP_PROPERTY = "cdx:pyproject:group";

/** License claim extraction (all three CycloneDX shapes). */
function licenseClaimsOf(component: SbomComponentShape): LicenseClaim[] {
  const licenses = component.licenses;
  if (licenses === undefined) return [];
  return licenses.flatMap((raw): LicenseClaim[] => {
    // The three claim shapes are tried in order; a mistyped field falls
    // through to the next shape, and an entry matching none is skipped.
    const expression = SbomExpressionClaim(raw);
    if (!(expression instanceof type.errors)) {
      return [
        { raw: expression.expression, kind: "expression", source: "generator" },
      ];
    }
    const id = SbomIdClaim(raw);
    if (!(id instanceof type.errors)) {
      return [{ raw: id.license.id, kind: "spdx-id", source: "generator" }];
    }
    const name = SbomNameClaim(raw);
    if (!(name instanceof type.errors)) {
      return [{ raw: name.license.name, kind: "name", source: "generator" }];
    }
    return [];
  });
}

/**
 * Cap on the decoded size of one evidence entry: a multi-MB base64 blob in a
 * crafted SBOM must not balloon the model. Checked before decoding (byte count
 * is derivable from the base64 length), so the blob is never even decoded.
 */
const MAX_EVIDENCE_DECODED_BYTES = 1024 * 1024;

/** Cap on evidence entries folded per component. */
const MAX_EVIDENCE_ENTRIES = 8;

/** Cap on copyright lines per package, matching the extractor's cap. */
const MAX_COPYRIGHT_LINES = 20;

/**
 * Replace every C0 control character except \n and \t, plus DEL (0x7F) and the
 * C1 range (0x80-0x9F), with a space — the sanitizeForLog class minus the
 * \n/\t exemption, applied at intake so no renderer downstream ever sees raw
 * control bytes (ANSI erase sequences and header forgeries die here). Line
 * endings are normalized first (\r\n and bare \r become \n): without that
 * pass, \r (0x0D, inside the control class) would become a space, so every
 * CRLF-origin "verbatim" license/NOTICE text would gain a trailing space per
 * line — a quiet mutation of text the document presents as verbatim.
 *
 * Contract: stored evidence text is byte-faithful modulo line endings
 * (normalized to LF) and control characters (flattened to spaces) — the model,
 * the dump goldens, and the rendered notices all carry LF-only text.
 */
export function sanitizeEvidenceText(value: string): string {
  return value.replace(/\r\n|\r/g, "\n").replace(
    // eslint-disable-next-line no-control-regex -- deliberate control-character class: sanitizer
    /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g,
    " ",
  );
}

/** One decoded evidence file: basename + sanitized utf8 text. */
interface EvidenceAttachment {
  fileName: string;
  text: string;
}

/**
 * Evidence attachment extraction — the licenseClaimsOf tolerant walk applied
 * to `component.evidence.licenses[]`. Evidence entries are never folded into
 * licenseClaims: their `name` is "file: <basename>" and would corrupt
 * normalization.
 *
 * Per verified shape: entry.license = { name: "file: <basename>",
 * text: { content: <base64>, encoding: "base64" } }. Anything else is skipped,
 * never thrown on. Caps enforced before storing.
 */
function evidenceAttachmentsOf(
  component: SbomComponentShape,
): EvidenceAttachment[] {
  const licenses = component.evidence?.licenses;
  if (licenses === undefined) return [];
  const out: EvidenceAttachment[] = [];
  for (const raw of licenses) {
    if (out.length >= MAX_EVIDENCE_ENTRIES) break;
    // Any deviation from the exact verified shape skips the entry — the
    // same continue every failed step of the old guard chain took.
    const entry = SbomEvidenceEntry(raw);
    if (entry instanceof type.errors) continue;
    const { name, text } = entry.license;
    const fileName = name.startsWith("file: ")
      ? name.slice("file: ".length)
      : name;
    const content = text.content;
    // Decoded byte count from the base64 length (3 bytes per 4 chars, minus
    // padding) — over-cap entries are skipped without decoding.
    const padding = content.endsWith("==") ? 2 : content.endsWith("=") ? 1 : 0;
    const decodedBytes = Math.floor((content.length * 3) / 4) - padding;
    if (decodedBytes > MAX_EVIDENCE_DECODED_BYTES) continue;
    const decoded = Buffer.from(content, "base64").toString("utf8");
    out.push({ fileName, text: sanitizeEvidenceText(decoded) });
  }
  return out;
}

/**
 * NOTICE-file classifier: stem "notice" plus an optional single extension,
 * case-insensitive — NOTICE, NOTICE.txt, NOTICE.md, NOTICE.markdown all
 * classify as NOTICE files. This mirrors the yarn plugin's own gather
 * semantics (it collects by ^NOTICE filename prefix and emits the basename
 * verbatim), so an extension variant can never fall into the license-text
 * branch — where, for any package with a parseable claim, its body would be
 * dropped from the legal document entirely (Apache-2.0 §4(d) requires
 * reproducing NOTICE contents).
 */
const NOTICE_FILE_RE = /^notice(\.[a-z0-9]+)?$/i;

/**
 * Fold decoded attachments into the per-package attribution: extracted
 * artifacts only — copyright lines, NOTICE contents, the hasVerbatimText flag
 * — with full verbatim texts retained only when the component has zero
 * spdx-id/expression-kind claims (the non-SPDX case where the file is the
 * license statement). NOTICE contents are never claims-gated: they reach the
 * rendered notices for packages with parseable claims too. Returns undefined
 * when there is nothing to attribute, so evidence-less packages serialize
 * without the key and existing goldens stay byte-identical.
 */
function attributionOf(
  component: SbomComponentShape,
  claims: ReadonlyArray<LicenseClaim>,
): PackageAttribution | undefined {
  const attachments = evidenceAttachmentsOf(component);
  if (attachments.length === 0) return undefined;

  const copyright = new Set<string>();
  const noticeTexts: string[] = [];
  const licenseTexts: string[] = [];
  let hasVerbatimText = false;
  for (const attachment of attachments) {
    if (NOTICE_FILE_RE.test(attachment.fileName)) {
      noticeTexts.push(attachment.text);
    } else {
      hasVerbatimText = true;
      licenseTexts.push(attachment.text);
    }
    for (const line of extractCopyrightLines(attachment.text)) {
      if (copyright.size >= MAX_COPYRIGHT_LINES) break;
      copyright.add(line);
    }
  }

  const attribution: PackageAttribution = {
    copyrightLines: [...copyright],
    noticeTexts,
    hasVerbatimText,
  };
  const author = component.author;
  if (author !== undefined) attribution.author = author;
  const hasParseableClaim = claims.some(
    (claim) => claim.kind === "spdx-id" || claim.kind === "expression",
  );
  if (!hasParseableClaim && licenseTexts.length > 0) {
    attribution.verbatimTexts = licenseTexts;
  }
  return attribution;
}

/**
 * Dev marker from cdxgen properties — not from scope (empirically unreliable).
 *
 * JS: dev iff development === "true" and not optional === "true". The optional
 * guard exists because cdxgen marks optional-prod dependencies with
 * development=true too; without the guard their prod license obligations are
 * silently understated. The guard is order-independent (both properties are
 * collected before deciding) and applies to every property-marked kind —
 * npm/pnpm/bun by symmetry, since the bun collector emits the same
 * cdx:npm:package:development property. cdxgen only ever pairs optional with
 * development.
 *
 * Python: cdx:pyproject:group === "dev" — an independent branch, untouched by
 * the JS guard. Plugin targets never reach this function — they carry no
 * properties at all and use the dual-run prod diff instead (prodPurlSet).
 */
function propertyDevMarker(component: SbomComponentShape): boolean {
  const properties = component.properties;
  if (properties === undefined) return false;
  let jsDevelopment = false;
  let jsOptional = false;
  let pyprojectDev = false;
  for (const raw of properties) {
    const property = SbomPropertyEntry(raw);
    if (property instanceof type.errors) continue;
    if (property.name === DEV_PROPERTY && property.value === "true") {
      jsDevelopment = true;
    } else if (
      property.name === OPTIONAL_PROPERTY &&
      property.value === "true"
    ) {
      jsOptional = true;
    } else if (
      property.name === PYPROJECT_GROUP_PROPERTY &&
      property.value === "dev"
    ) {
      pyprojectDev = true;
    }
  }
  return pyprojectDev || (jsDevelopment && !jsOptional);
}

/**
 * Property name cdxgen sets on npm workspace members. The member is emitted at
 * its real version (never 0.0.0-use.local), so this property is the npm-side
 * second signal for the first-party skip — always paired with the
 * lockfile-derived name set, never authoritative alone.
 */
const IS_WORKSPACE_PROPERTY = "cdx:npm:isWorkspace";

/** True iff the component carries cdx:npm:isWorkspace=true (same per-entry tolerance as propertyDevMarker). */
function hasWorkspaceMarker(component: SbomComponentShape): boolean {
  const properties = component.properties;
  if (properties === undefined) return false;
  return properties.some((raw) => {
    const property = SbomPropertyEntry(raw);
    return (
      !(property instanceof type.errors) &&
      property.name === IS_WORKSPACE_PROPERTY &&
      property.value === "true"
    );
  });
}

/**
 * Every string purl in components[], for the dual-run prod diff. Same tolerant
 * walk as mergeSboms: malformed entries are skipped, never thrown on.
 */
export function purlSetOf(sbom: unknown): Set<string> {
  const purls = new Set<string>();
  const doc = SbomDocument(sbom);
  if (doc instanceof type.errors) return purls;
  for (const raw of doc.components ?? []) {
    const component = SbomComponent(raw);
    if (component instanceof type.errors) continue;
    if (component.purl !== undefined) purls.add(component.purl);
  }
  return purls;
}

/**
 * Structural identity of a claim: value AND shape AND provenance. NUL-joined
 * so distinct fields can never collide by concatenation ambiguity.
 */
function claimKey(claim: LicenseClaim): string {
  return `${claim.kind}\0${claim.source}\0${claim.raw}`;
}

/**
 * #7: deterministically reconcile two introductions for the SAME target+purl
 * (a same-target occurrence fold). Order-independent by construction:
 * - `direct` is ORed (a direct contributor wins — mirrors the prod-wins /
 *   "direct in ANY" posture);
 * - `introducedBy` is the sorted-unique UNION;
 * - `path` is taken from the contributor with the lexicographically-smallest
 *   path (compareCodeUnits over the joined chain), so neither input order nor
 *   which side arrived first decides the representative chain.
 * Absent on both sides → absent; present on one → that one (cloned).
 *
 * 07-21 DIRECT-CONSISTENCY (Fix 2): when the reconciled result is `direct:true`,
 * `introducedBy` is cleared to [] and `path` is dropped. ORing `direct` while
 * UNIONing introducedBy / keeping a path produced the contradictory
 * {direct:true, introducedBy:[mid], path:[mid,leaf]} when a DIRECT intro folded
 * with a TRANSITIVE one; whyCellOf then rendered bare "direct" and HID the (now
 * meaningless) introducer. A direct dependency is introduced by the root itself
 * — it has no parent chain — so a direct reconciliation carries no introducer
 * and no path.
 *
 * 07-19: optionality is descoped — there is no `optional` field to reconcile.
 */
function reconcileIntroductions(
  a: DependencyIntroduction | undefined,
  b: DependencyIntroduction | undefined,
): DependencyIntroduction | undefined {
  if (a === undefined) return b === undefined ? undefined : { ...b };
  if (b === undefined) return { ...a };

  // Fix 2: a direct dep has no introducer chain — clear introducedBy + drop path.
  if (a.direct || b.direct) {
    return { direct: true, introducedBy: [] };
  }

  const introducedBy = [
    ...new Set([...a.introducedBy, ...b.introducedBy]),
  ].sort(compareCodeUnits);
  const reconciled: DependencyIntroduction = {
    direct: false,
    introducedBy,
  };

  // Smallest path by compareCodeUnits over the joined chain (NUL-joined so a
  // shorter prefix can never tie a longer chain by concatenation ambiguity).
  const paths = [a.path, b.path].filter(
    (p): p is readonly string[] => p !== undefined,
  );
  if (paths.length > 0) {
    reconciled.path = paths.reduce((best, candidate) =>
      compareCodeUnits(candidate.join("\0"), best.join("\0")) < 0
        ? candidate
        : best,
    );
  }

  return reconciled;
}

function mergeInto(existing: PackageEntry, incoming: PackageEntry): void {
  // Union occurrences by target, sorted. The same target seen twice for one
  // purl (e.g. a bun transitive reached via BOTH a prod and a dev parent at the
  // same version, or a cdxgen document emitting the purl twice with divergent
  // dev markers) folds the dev flags PROD-WINS: an occurrence is dev-only iff
  // EVERY contributing component for that target is dev; a single production
  // contribution forces the whole occurrence to production. This is the
  // safety-bearing direction — a shipped occurrence carries the distribution
  // obligation, so it must never be masked to dev (POL-08). It matches the
  // package-level rule in render/markdown.ts isDevelopmentOnly. Distinct targets
  // keep their flags independently.
  const byTarget = new Map<string, Occurrence>();
  for (const occurrence of [...existing.occurrences, ...incoming.occurrences]) {
    const present = byTarget.get(occurrence.target);
    if (present === undefined) {
      byTarget.set(occurrence.target, { ...occurrence });
    } else {
      present.isDevDependency =
        present.isDevDependency && occurrence.isDevDependency;
      // #7: reconcile `introduction` DETERMINISTICALLY on a same-target fold
      // rather than first-wins (the only order-dependent path in the otherwise
      // sorted provenance code). Currently unreachable (target identities are
      // unique), but latent — a deterministic fold keeps the invariant airtight.
      present.introduction = reconcileIntroductions(
        present.introduction,
        occurrence.introduction,
      );
    }
  }
  existing.occurrences = [...byTarget.values()].sort((a, b) =>
    compareCodeUnits(a.target, b.target),
  );
  // Union claims, deduped structurally — the same purl listed twice (e.g.
  // once from yarn.lock, once from package.json) must not render "MIT, MIT".
  // First-seen order is preserved; provenance stays intact because the dedup
  // key includes kind AND source, so a generator claim never swallows a
  // curated/override claim with the same raw value.
  const seen = new Set(existing.licenseClaims.map(claimKey));
  for (const claim of incoming.licenseClaims) {
    const key = claimKey(claim);
    if (!seen.has(key)) {
      seen.add(key);
      existing.licenseClaims.push(claim);
    }
  }
  // Reconcile scope on a purl collision — the GATING "app" scope WINS over
  // the non-gating "os" scope. Without this, a purl shared between an app input
  // and an os input is silently demoted to "os" purely by merge order (the os
  // input arriving first), moving a real dependency OUT of the policy gate.
  // Defense-in-depth: a shared dependency must never be demoted out of gating.
  if (existing.scope === "os" && incoming.scope === "app") {
    existing.scope = "app";
  }
  if (existing.rawScope === undefined && incoming.rawScope !== undefined) {
    existing.rawScope = incoming.rawScope;
  }
  // First-seen attribution wins, matching the claims posture: the same purl
  // from two targets carries identical tarball contents, so re-folding would
  // only duplicate lines. A stored attribution is never mutated by a later
  // target.
  if (
    existing.attribution === undefined &&
    incoming.attribution !== undefined
  ) {
    existing.attribution = incoming.attribution;
  }
}

/**
 * The prefix of every docker image occurrence identity ("docker:<source>").
 * RESERVED for scope:"os" inputs — on a POSIX filesystem a directory can be
 * literally named "docker:whatever", so without the guard below a crafted
 * workspace path could impersonate a docker image occurrence and inherit
 * `where`-scoped acceptances reviewed for the image layer.
 */
export const DOCKER_IDENTITY_PREFIX = "docker:";

/**
 * Throw when a non-os input mints an identity in the reserved namespace.
 * Identity strings are tool-minted (repo-relative discovery paths), not
 * document content, so a collision is a crafted layout — refused loudly,
 * never a tolerant skip.
 */
function assertNotReservedIdentity(input: CollectedSbom): void {
  if ((input.scope ?? "app") === "os") return;
  const id = input.targetIdentity;
  if (id.startsWith(DOCKER_IDENTITY_PREFIX)) {
    throw new Error(
      `target "${id}" collides with the reserved docker occurrence namespace "${DOCKER_IDENTITY_PREFIX}*" — rename or exclude the directory; a workspace can never impersonate a docker image occurrence`,
    );
  }
}

/**
 * Build the canonical model from one or more CycloneDX documents.
 *
 * Multi-input signature so multi-target merge and per-workspace provenance are
 * additive, never a retrofit. The internal Map is keyed by purl verbatim
 * (URL-encoding like %40 intact; never bom-ref).
 */
export function mergeSboms(
  inputs: ReadonlyArray<CollectedSbom>,
): CanonicalDependencies {
  const byPurl = new Map<string, PackageEntry>();

  // Reserved-namespace integrity before any component walks (see
  // assertNotReservedIdentity — a loud throw, never a skip).
  for (const input of inputs) assertNotReservedIdentity(input);

  for (const input of inputs) {
    // A malformed document is skipped, never thrown on.
    const doc = SbomDocument(input.sbom);
    if (doc instanceof type.errors) continue;
    // The scanned root's purl excludes first-party leaks — read via an
    // independent tolerant narrow, so malformed metadata leaves the root
    // simply absent (every component still walks and emits).
    const rootPurl = rootPurlOf(input.sbom);
    const components = doc.components;
    if (components === undefined) continue;

    for (const raw of components) {
      const component = SbomComponent(raw);
      if (component instanceof type.errors) continue;
      const entry = packageEntryOf(input, component, rootPurl);
      if (entry === undefined) continue;

      const existing = byPurl.get(entry.purl);
      if (existing === undefined) {
        byPurl.set(entry.purl, entry);
      } else {
        mergeInto(existing, entry);
      }
    }
  }

  return { packages: [...byPurl.values()].sort(comparePackages) };
}

/**
 * First-party workspace/portal members never reach the inventory. Both
 * conditions required — the name must be in the target's own lockfile member
 * set and the component must carry a second first-party signal: the
 * yarn/plugin local-version marker, or the cdxgen npm isWorkspace property (npm
 * members carry real versions). A name collision, a crafted version, or a
 * crafted marker alone can never drop a third-party package.
 */
function isFirstPartyMember(
  input: CollectedSbom,
  component: SbomComponentShape,
  displayName: string,
  version: string,
): boolean {
  return (
    input.firstPartyNames?.has(displayName) === true &&
    (version === "0.0.0-use.local" || hasWorkspaceMarker(component))
  );
}

/** One narrowed component → its PackageEntry, or undefined for every skip. */
function packageEntryOf(
  input: CollectedSbom,
  component: SbomComponentShape,
  rootPurl: string | undefined,
): PackageEntry | undefined {
  const { purl, name, version } = component;
  // Malformed entries are skipped, never thrown on — the required
  // purl/name/version triple gate stays explicit.
  if (purl === undefined || name === undefined || version === undefined) {
    return undefined;
  }
  // The scanned root never appears in the inventory.
  if (rootPurl !== undefined && purl === rootPurl) return undefined;

  const group = component.group;
  // cdxgen emits group: "" for ungrouped npm packages; treating the empty
  // string as a real group would compose leading-slash names like "/abab", so
  // an empty-string group is treated as absent.
  const displayName =
    group !== undefined && group !== "" ? `${group}/${name}` : name;
  if (isFirstPartyMember(input, component, displayName, version)) {
    return undefined;
  }
  const occurrence: Occurrence = {
    target: input.targetIdentity,
    // Per-target scope source: when the dual-run prod purl set exists
    // (plugin targets), it is authoritative; otherwise the generator's own
    // property markers apply.
    isDevDependency:
      input.prodPurlSet !== undefined
        ? !input.prodPurlSet.has(purl)
        : propertyDevMarker(component),
  };
  // Provenance (07-13): the per-target introduction for this purl, when the
  // source supplied a graph. Attached at occurrence creation so it is PER-TARGET
  // and rides through mergeInto unchanged (no cross-purl reconciliation). A purl
  // absent from the map (or no map at all) leaves introduction undefined — the
  // honest residual — so goldens predating provenance stay byte-identical.
  const introduction = input.introductions?.get(purl);
  if (introduction !== undefined) occurrence.introduction = introduction;
  const entry: PackageEntry = {
    purl,
    name: displayName,
    version,
    occurrences: [occurrence],
    licenseClaims: licenseClaimsOf(component),
    scope: input.scope ?? "app", // per-input scope; the docker sidecar inputs set "os"
  };
  const rawScope = component.scope;
  if (rawScope !== undefined) entry.rawScope = rawScope;
  // Evidence-derived attribution — set only when at least one usable evidence
  // entry survived the caps (absent, never empty).
  const attribution = attributionOf(component, entry.licenseClaims);
  if (attribution !== undefined) entry.attribution = attribution;
  return entry;
}
