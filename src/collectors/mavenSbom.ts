/**
 * In-process maven.sbom.json collector — a conscious exception to
 * orchestrate-don't-parse, because Maven has no native lockfile: `pom.xml`
 * declares directs only, and only a build-side plugin can resolve the real
 * closure (parent BOMs, dependencyManagement, conflict mediation). Every
 * scan-time candidate that avoids running Maven inside the target fails the
 * robust bar instead — cdxgen either shells out to `mvn` in the scanned repo
 * (the exact side effect this tool forbids) or, without Maven on PATH,
 * silently emits an 8% fraction with version-less purls; syft sees pom
 * directs only and fabricates identity from stale local jars.
 *
 * The design that survives is the docker.sbom.json pattern generalized into
 * a lockfile kind: the consumer's own CI runs the pinned, ecosystem-standard
 * cyclonedx-maven-plugin and commits its per-module CycloneDX output under
 * the fixed name `maven.sbom.json`; this reader consumes those committed
 * bytes offline, no subprocess, no Maven toolchain anywhere in SBOMlet.
 *
 * The committed document is already canonical — components, purls, and
 * license claims are the effective-model truth the plugin resolved inside
 * the build. When no test-inclusive sidecar sits beside it, this reader
 * rewrites NOTHING: it validates the document's shape (bomFormat, a
 * components array, a `pkg:maven/` metadata.component.purl) and then copies
 * the exact committed bytes into the per-run temp dir, never re-serializing
 * them — a rewrite risks silently reordering or dropping fields this reader
 * does not even declare. Purl casing (groupId/artifactId) is never touched:
 * Maven coordinates are case-sensitive and the plugin already emits
 * registry-canonical casing.
 */
/**
 * A consumer MAY additionally commit `maven.test.sbom.json` — the same
 * module built with `-DincludeTestScope=true` (a superset that also carries
 * test-only dependencies, indistinguishable from production ones by any
 * field the plugin emits — ADR-0023). When present,
 * this reader composes the inventory from the test doc (the superset) plus
 * any default-doc component whose purl the test doc dropped — a mediation
 * residual, never a hand-rebuilt document — and derives `prodPurlSet` from
 * the default doc's own purls via merge.ts's `purlSetOf`. The merge then
 * classifies any inventory purl outside that set as dev (the yarn dual-run /
 * poetry precedent). Without the test doc, behavior is unchanged: no
 * `prodPurlSet`, every component classifies prod.
 *
 * First-party exclusion for multi-module reactors (a sibling module
 * appearing as a plain component in a dependent module's BOM) is cross-target
 * knowledge that belongs to the collect loop, not this reader; each
 * document's OWN root purl is already excluded by the merge.
 *
 * Fully in-process — no subprocess, no eval, no cwd change; a
 * MAX_MAVEN_SBOM_BYTES stat gate bounds memory before any read/parse; a
 * missing file, an oversized file, non-JSON text, a non-CycloneDX document,
 * and a document whose root purl is not `pkg:maven/` all throw loudly — a
 * committed artifact under either fixed name must never silently misparse.
 */

import { createHash } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  statSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { type } from "arktype";

import { purlSetOf } from "../merge/merge";
import { MavenSbomDocument } from "../validate/mavenSbom";
import { recordOf } from "../validate/record";
import { computeCacheKey, type CollectorSbomFile } from "./cdxgen";
import { manifestFilesFor } from "./dispatch";
import type { Target } from "../targets/target";

/**
 * Collector identity (the CLI prints `${name}@${version}`). Version bumps
 * when the parse or validation semantics change — it is hashed into the
 * cache key, so a bump invalidates cache entries on purpose. Bumped to "2"
 * for the dual-document composed inventory: the emission semantics changed
 * (a maven.test.sbom.json sidecar, when present, now changes what a target
 * emits) even though a target without one still emits byte-identical bytes.
 */
export const MAVEN_COLLECTOR_TOOL = {
  name: "maven-sbom-reader",
  version: "2",
} as const;

/**
 * DoS bound: the research fixture's real per-module BOM is ~1.5 MB; 32 MiB is
 * generous headroom. The stat gate fires before any read or parse so a
 * hostile file can never balloon memory. Shared by both the default and the
 * test-inclusive sidecar — a committed artifact under either fixed name must
 * clear the same bound before anything touches its bytes.
 */
export const MAX_MAVEN_SBOM_BYTES = 32 * 1024 * 1024;

/**
 * Stat-gate a maven sidecar path against MAX_MAVEN_SBOM_BYTES before any
 * read or parse. Shared by collectWithMavenSbom (for both the default and
 * the optional test-inclusive sidecar), the pipeline pre-pass, and the CLI
 * loop — every entry point that touches either file must honor the same
 * single-sourced cap and loud message.
 */
export function assertMavenSbomSize(sbomPath: string): void {
  const size = statSync(sbomPath).size;
  if (size > MAX_MAVEN_SBOM_BYTES) {
    throw new Error(
      `maven.sbom.json at ${sbomPath} is ${size} bytes, over the ` +
        `${MAX_MAVEN_SBOM_BYTES}-byte cap — refusing to parse it ` +
        `(real per-module Maven BOMs are well under 2 MB)`,
    );
  }
}

/**
 * The constant pseudo-argv hashed into the cache key. There is no real
 * subprocess invocation to hash — this sentinel plays the role
 * cdxgenCacheArgs plays for cdxgen targets, and changes only when the
 * collector's observable behavior changes (alongside the tool version). A
 * present maven.test.sbom.json appends one more domain-tagged entry (its
 * own content hash) so a changed test doc invalidates the key while an
 * absent one leaves this base array — and therefore the key framing for a
 * default-doc-only target — untouched.
 */
const MAVEN_CACHE_ARGS = ["maven-sbom-reader-v1"];

/**
 * Manifest files hashed into the cache key — derived from the single source
 * (dispatch.ts) so the collector's cache-key framing can never drift from
 * the dispatch table's maven entry. Deliberately NEVER includes
 * maven.test.sbom.json: computeCacheKey throws on a missing manifest, and
 * the test doc is optional-additive (manifestFilesFor("maven") stays the
 * single source of truth for the REQUIRED file only).
 */
const MAVEN_MANIFEST_FILES = manifestFilesFor("maven");

/** The optional test-inclusive sidecar's fixed name (mirrors maven.sbom.json). */
const MAVEN_TEST_SBOM_FILENAME = "maven.test.sbom.json";

/** Options mirror the cdxgen adapter's per-run temp-dir injection point. */
export interface MavenCollectOptions {
  /** Per-run temp directory; defaults to a fresh mkdtemp under os tmpdir. */
  tempDir?: string;
}

/** collectWithMavenSbom's return shape: the base contract plus the optional dual-doc prod signal. */
export interface MavenCollectResult extends CollectorSbomFile {
  /**
   * Purl set of the DEFAULT doc's components — set ONLY when a
   * maven.test.sbom.json sidecar is also present. Threaded into
   * CollectedSbom.prodPurlSet by the registry; merge.ts then derives
   * occurrence dev = not in this set (the yarn dual-run / poetry precedent).
   * Absent when only maven.sbom.json exists — every component classifies
   * prod and the committed bytes pass through unchanged.
   */
  prodPurlSet?: ReadonlySet<string>;
}

/**
 * sha256 hex digest of a sidecar's raw text — the cache-key ingredient for a
 * present maven.test.sbom.json.
 */
function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/**
 * Parse and validate one committed Maven CycloneDX sidecar — the loud ladder
 * shared by the default and the optional test-inclusive doc: JSON parse, the
 * MavenSbomDocument narrow, bomFormat, and a `pkg:maven/` root purl. A
 * committed artifact under either fixed name has exactly one honest shape;
 * `label` (the file's own name) appears in every error message so a failure
 * always names which of the two sidecars misparsed.
 */
function readAndNarrowMavenSbom(
  sbomPath: string,
  label: string,
): { text: string; parsed: unknown; rootPurl: string } {
  const text = readFileSync(sbomPath, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(
      `${label} at ${sbomPath} is not valid JSON: ${String(error)}`,
      { cause: error },
    );
  }

  const narrowed = MavenSbomDocument(parsed);
  if (narrowed instanceof type.errors) {
    throw new Error(
      `${label} at ${sbomPath} does not match the expected ` +
        `CycloneDX shape: ${narrowed.summary}`,
    );
  }
  if (narrowed.bomFormat !== "CycloneDX") {
    throw new Error(
      `${label} at ${sbomPath} is not a CycloneDX document ` +
        `(bomFormat: ${JSON.stringify(narrowed.bomFormat)}, expected "CycloneDX")`,
    );
  }
  const rootPurl = narrowed.metadata?.component?.purl;
  if (rootPurl === undefined || !rootPurl.startsWith("pkg:maven/")) {
    throw new Error(
      `${label} at ${sbomPath} has metadata.component.purl ` +
        `${JSON.stringify(rootPurl)}, expected a "pkg:maven/" purl — a ` +
        "committed artifact under this name must be a Maven module's BOM",
    );
  }
  return { text, parsed, rootPurl };
}

/**
 * Compose the dual-document inventory: the test doc's own components PLUS
 * any default-doc component whose purl is absent from the test doc's purl
 * set (the mediation residual — guarantees a version Maven mediated
 * differently between the two builds is never silently dropped). Every
 * other envelope field is taken from the test doc; every surviving
 * component, from either source, passes through completely untouched. A
 * shallow spread over the test doc — the excludeMavenFirstParty new-doc
 * pattern — never a hand-rebuilt document that could drop a field neither
 * narrow declares.
 */
function composeMavenInventory(
  testParsed: unknown,
  defaultParsed: unknown,
): unknown {
  const testDoc = recordOf(testParsed);
  if (testDoc === undefined) return testParsed;
  const testComponents = Array.isArray(testDoc["components"])
    ? (testDoc["components"] as unknown[])
    : [];
  const testPurls = new Set<string>();
  for (const raw of testComponents) {
    const purl = recordOf(raw)?.["purl"];
    if (typeof purl === "string") testPurls.add(purl);
  }

  const defaultDoc = recordOf(defaultParsed);
  const defaultComponents =
    defaultDoc !== undefined && Array.isArray(defaultDoc["components"])
      ? (defaultDoc["components"] as unknown[])
      : [];
  const residual = defaultComponents.filter((raw) => {
    const purl = recordOf(raw)?.["purl"];
    return typeof purl !== "string" || !testPurls.has(purl);
  });

  return { ...testDoc, components: [...testComponents, ...residual] };
}

/**
 * Read a target's maven.sbom.json (no subprocess, no cwd change) and emit
 * the inventory the merge consumes. When no maven.test.sbom.json sidecar
 * sits beside it, the committed bytes are copied VERBATIM (never
 * re-serialized). When a test
 * doc IS present, the two are composed (see {@link composeMavenInventory})
 * and `prodPurlSet` is derived from the default doc's own purls, both
 * carried on the returned {@link MavenCollectResult}.
 *
 * Async for interface symmetry with collectWithCdxgen (keeps a future
 * generator swap cheap).
 *
 * Failure modes (all loud — a committed artifact under either fixed name
 * must never silently misparse):
 * - missing maven.sbom.json → target.ts-shaped error;
 * - either sidecar over MAX_MAVEN_SBOM_BYTES → loud error naming path,
 *   size, cap, before any read or parse;
 * - non-JSON text in either sidecar → loud error naming the path;
 * - a document whose bomFormat is not "CycloneDX" → loud error naming the
 *   expectation;
 * - a document whose metadata.component.purl is not `pkg:maven/...` → loud
 *   error naming both the found purl and the expected prefix (a deliberate
 *   wrong-ecosystem file committed under this name);
 * - a test doc whose root purl differs from the default doc's → loud error
 *   naming both roots (a stale or wrong-module pair must never compose).
 *
 * maven.test.sbom.json is entirely optional-additive: its absence changes
 * nothing about the default doc's failure ladder or output bytes.
 */
export async function collectWithMavenSbom(
  target: Target,
  opts: MavenCollectOptions = {},
): Promise<MavenCollectResult> {
  const sbomPath = join(target.dir, "maven.sbom.json");
  if (!existsSync(sbomPath)) {
    throw new Error(
      `target "${target.identity}" is missing maven.sbom.json: expected ${sbomPath}`,
    );
  }

  // Size gate FIRST — before read, before parse (the DoS bound above).
  assertMavenSbomSize(sbomPath);
  const {
    text,
    parsed: defaultParsed,
    rootPurl: defaultRootPurl,
  } = readAndNarrowMavenSbom(sbomPath, "maven.sbom.json");

  const testSbomPath = join(target.dir, MAVEN_TEST_SBOM_FILENAME);
  const hasTestDoc = existsSync(testSbomPath);

  let outputText = text;
  let prodPurlSet: ReadonlySet<string> | undefined;
  let cacheArgs: string[] = MAVEN_CACHE_ARGS;

  if (hasTestDoc) {
    assertMavenSbomSize(testSbomPath);
    const {
      text: testText,
      parsed: testParsed,
      rootPurl: testRootPurl,
    } = readAndNarrowMavenSbom(testSbomPath, MAVEN_TEST_SBOM_FILENAME);

    // The pair must be two builds of the SAME module. The merge excludes the
    // inventory component matching a document's own root purl, so a test doc
    // whose root names a real dependency (a stale, wrong-module, or crafted
    // file) would silently drop that dependency from the inventory.
    if (testRootPurl !== defaultRootPurl) {
      throw new Error(
        `${MAVEN_TEST_SBOM_FILENAME} at ${testSbomPath} has root purl ` +
          `${JSON.stringify(testRootPurl)} but the maven.sbom.json beside ` +
          `it has ${JSON.stringify(defaultRootPurl)} — the pair must be ` +
          "two builds of the same module; regenerate both sidecars together",
      );
    }

    // Composing builds a NEW document object (the shallow-spread pattern
    // above), so — unlike the default-doc-only verbatim path — this is a
    // deliberate re-serialization: JSON.stringify over that new object.
    outputText = JSON.stringify(
      composeMavenInventory(testParsed, defaultParsed),
    );
    prodPurlSet = purlSetOf(defaultParsed);
    cacheArgs = [
      ...MAVEN_CACHE_ARGS,
      `maven-test-sbom-sha256:${sha256Hex(testText)}`,
    ];
  }

  // Verbatim pass-through in the common (no test doc) case: the committed
  // bytes are copied UNCHANGED into the per-run temp dir — never
  // JSON.stringify(parsed), which would re-serialize and risk silently
  // reordering or dropping fields this reader does not even declare. The
  // committed artifact is already canonical; rewriting it here would only
  // risk data loss.
  const tempDir = opts.tempDir ?? mkdtempSync(join(tmpdir(), "licenses-"));
  const outPath = join(tempDir, "bom.json");
  writeFileSync(outPath, outputText);

  return {
    sbomPath: outPath,
    // Shared cache-key framing contract — reused, never duplicated.
    cacheKey: computeCacheKey(
      target,
      MAVEN_COLLECTOR_TOOL,
      cacheArgs,
      MAVEN_MANIFEST_FILES,
    ),
    tool: MAVEN_COLLECTOR_TOOL,
    ...(prodPurlSet !== undefined ? { prodPurlSet } : {}),
  };
}

/**
 * Extract a maven.sbom.json sidecar's own root purl (metadata.component.purl)
 * without validating anything else about the document — the pre-pass primitive
 * behind the reactor first-party purl set. Only the pipeline
 * sees every discovered target, so cross-target sibling knowledge is gathered
 * HERE, before any target is collected, and threaded into
 * {@link excludeMavenFirstParty} at the post-collect step.
 *
 * Tolerant by design: garbage, non-JSON, non-CycloneDX, and purl-less text all
 * yield undefined rather than throwing. The pre-pass must never abort the
 * whole run over one target's bad sidecar — that target's OWN collect call
 * fails loud later, on its own turn, via collectWithMavenSbom's ladder.
 *
 * @returns The root purl, or undefined when the text cannot be read as a
 * CycloneDX document with one.
 */
export function mavenRootPurlOf(text: string): string | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return undefined;
  }
  const narrowed = MavenSbomDocument(parsed);
  if (narrowed instanceof type.errors) return undefined;
  if (narrowed.bomFormat !== "CycloneDX") return undefined;
  return narrowed.metadata?.component?.purl;
}

/**
 * Filter a maven.sbom.json document's components by an exact-purl-match
 * first-party set, returning a NEW document — the input is never mutated.
 * Purl-string equality is the only comparison: both sides come from the same
 * cyclonedx-maven-plugin producer with the same `?type=jar` qualifier shape,
 * so a version-qualified exact match is safe.
 *
 * A STALE sibling reference (the module bumped its version, the sibling's
 * sidecar was not regenerated) deliberately does NOT match — it surfaces as
 * an ordinary third-party component instead of silently vanishing, the
 * loud direction a mismatched exclusion should take (Pitfall 8).
 *
 * Every field other than `components` — and every field of a surviving
 * component — passes through completely untouched. A document this function
 * cannot recognize as a record with a components array is returned as-is:
 * the collector's own loud ladder owns malformed-sidecar failures, not this
 * pure filter.
 */
export function excludeMavenFirstParty(
  sbom: unknown,
  purls: ReadonlySet<string>,
): unknown {
  const doc = recordOf(sbom);
  if (doc === undefined) return sbom;
  const components = doc["components"];
  if (!Array.isArray(components)) return sbom;
  const filtered = components.filter((component) => {
    const purl = recordOf(component)?.["purl"];
    return typeof purl !== "string" || !purls.has(purl);
  });
  return { ...doc, components: filtered };
}
