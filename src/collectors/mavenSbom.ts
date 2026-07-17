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
 * the build. This reader therefore rewrites NOTHING: it validates the
 * document's shape (bomFormat, a components array, a `pkg:maven/`
 * metadata.component.purl) and then copies the exact committed bytes into
 * the per-run temp dir, never re-serializing them — a rewrite risks
 * silently reordering or dropping fields this reader does not even declare.
 * Purl casing (groupId/artifactId) is never touched: Maven coordinates are
 * case-sensitive and the plugin already emits registry-canonical casing.
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
 * committed artifact under this fixed name must never silently misparse.
 */

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

import { MavenSbomDocument } from "../validate/mavenSbom";
import { computeCacheKey, type CollectorSbomFile } from "./cdxgen";
import { manifestFilesFor } from "./dispatch";
import type { Target } from "../targets/target";

/**
 * Collector identity (the CLI prints `${name}@${version}`). Version bumps
 * when the parse or validation semantics change — it is hashed into the
 * cache key, so a bump invalidates cache entries on purpose.
 */
export const MAVEN_COLLECTOR_TOOL = {
  name: "maven-sbom-reader",
  version: "1",
} as const;

/**
 * DoS bound: the research fixture's real per-module BOM is ~1.5 MB; 32 MiB is
 * generous headroom. The stat gate fires before any read or parse so a
 * hostile file can never balloon memory.
 */
export const MAX_MAVEN_SBOM_BYTES = 32 * 1024 * 1024;

/**
 * Stat-gate a maven.sbom.json path against MAX_MAVEN_SBOM_BYTES before any
 * read or parse. Shared by collectWithMavenSbom and the CLI loop — the CLI
 * reads the full sidecar text for the coverage counter before the collector
 * ever runs, so every entry point that touches the file must honor the same
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
 * collector's observable behavior changes (alongside the tool version).
 */
const MAVEN_CACHE_ARGS = ["maven-sbom-reader-v1"];

/**
 * Manifest files hashed into the cache key — derived from the single source
 * (dispatch.ts) so the collector's cache-key framing can never drift from
 * the dispatch table's maven entry.
 */
const MAVEN_MANIFEST_FILES = manifestFilesFor("maven");

/** Options mirror the cdxgen adapter's per-run temp-dir injection point. */
export interface MavenCollectOptions {
  /** Per-run temp directory; defaults to a fresh mkdtemp under os tmpdir. */
  tempDir?: string;
}

/**
 * Read a target's maven.sbom.json (no subprocess, no cwd change) and copy
 * the committed bytes VERBATIM into the per-run temp dir — the existing SBOM
 * parse path consumes it unchanged.
 *
 * Async for interface symmetry with collectWithCdxgen (keeps a future
 * generator swap cheap).
 *
 * Failure modes (all loud — a committed artifact under this fixed name must
 * never silently misparse):
 * - missing maven.sbom.json → target.ts-shaped error;
 * - sidecar over MAX_MAVEN_SBOM_BYTES → loud error naming path, size, cap,
 *   before any read or parse;
 * - non-JSON text → loud error naming the path;
 * - a document whose bomFormat is not "CycloneDX" → loud error naming the
 *   expectation;
 * - a document whose metadata.component.purl is not `pkg:maven/...` → loud
 *   error naming both the found purl and the expected prefix (a deliberate
 *   wrong-ecosystem file committed under this name).
 */
export async function collectWithMavenSbom(
  target: Target,
  opts: MavenCollectOptions = {},
): Promise<CollectorSbomFile> {
  const sbomPath = join(target.dir, "maven.sbom.json");
  if (!existsSync(sbomPath)) {
    throw new Error(
      `target "${target.identity}" is missing maven.sbom.json: expected ${sbomPath}`,
    );
  }

  // Size gate FIRST — before read, before parse (the DoS bound above).
  assertMavenSbomSize(sbomPath);

  const text = readFileSync(sbomPath, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(
      `maven.sbom.json at ${sbomPath} is not valid JSON: ${String(error)}`,
      { cause: error },
    );
  }

  // Loud narrow: unlike the tolerant lockfile collectors, a committed
  // artifact under this fixed name has exactly one honest shape — a failed
  // narrow (a present-but-wrong-typed metadata/component/purl chain) is
  // itself evidence of a wrong file, so it throws rather than falling back
  // to an empty-map skip.
  const narrowed = MavenSbomDocument(parsed);
  if (narrowed instanceof type.errors) {
    throw new Error(
      `maven.sbom.json at ${sbomPath} does not match the expected ` +
        `CycloneDX shape: ${narrowed.summary}`,
    );
  }
  if (narrowed.bomFormat !== "CycloneDX") {
    throw new Error(
      `maven.sbom.json at ${sbomPath} is not a CycloneDX document ` +
        `(bomFormat: ${JSON.stringify(narrowed.bomFormat)}, expected "CycloneDX")`,
    );
  }
  const rootPurl = narrowed.metadata?.component?.purl;
  if (rootPurl === undefined || !rootPurl.startsWith("pkg:maven/")) {
    throw new Error(
      `maven.sbom.json at ${sbomPath} has metadata.component.purl ` +
        `${JSON.stringify(rootPurl)}, expected a "pkg:maven/" purl — a ` +
        "committed artifact under this name must be a Maven module's BOM",
    );
  }

  // Verbatim pass-through: the committed bytes are copied UNCHANGED into the
  // per-run temp dir — never JSON.stringify(parsed), which would
  // re-serialize and risk silently reordering or dropping fields this
  // narrow does not even declare. The committed artifact is already
  // canonical; rewriting it here would only risk data loss.
  const tempDir = opts.tempDir ?? mkdtempSync(join(tmpdir(), "licenses-"));
  const outPath = join(tempDir, "bom.json");
  writeFileSync(outPath, text);

  return {
    sbomPath: outPath,
    // Shared cache-key framing contract — reused, never duplicated.
    cacheKey: computeCacheKey(
      target,
      MAVEN_COLLECTOR_TOOL,
      MAVEN_CACHE_ARGS,
      MAVEN_MANIFEST_FILES,
    ),
    tool: MAVEN_COLLECTOR_TOOL,
  };
}
