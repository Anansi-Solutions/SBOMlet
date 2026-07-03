/**
 * The dedicated `generate-docker-sbom` orchestrator: the ONLY path in the tool
 * that touches the docker daemon / syft. It pulls (and, for app images, builds)
 * the configured image set, scans each with the 07-01 syft collector
 * (collectDockerOsSbom), digest-pins it, and writes the deterministic committed
 * `docker-os.sbom.json` at the base-dir-resolved output path.
 *
 * DECISION (Open Question 1, LOCKED): this is a SEPARATE subcommand, not a
 * `--scan-docker` flag on `generate` — the everyday generate/check stay
 * daemon-free and fully offline, reading the committed bytes this command
 * produces as a scope:"os" merge input (07-02). The blast radius of the
 * docker/network side-effect is confined to this one path.
 *
 * INDEPENDENCE CONSTRAINT: the documented default image set are the DOCUMENTED DEFAULT
 * (DEFAULT_IMAGES, this module) — they are NEVER hardcoded in
 * src/collectors or src/pipeline/pipeline.ts. A consumer repo overrides the set
 * via repeatable `--image <ref>` (cli.ts) or the IMAGES Taskfile var. The image
 * list is a pure operand list flowing through execTool's argv array; no ref is
 * ever interpolated into a command string (T-07-08).
 *
 * The single writeFileSync lives here (mirroring runGenerate's writer-owns-bytes
 * posture at pipeline.ts:328-329) so the collector stays write-free and a
 * double-run from the same images is byte-identical by construction (toSortedJson
 * via emitDockerOsDoc).
 */

import { readFileSync, statSync } from "node:fs";

import {
  collectDockerOsSbom,
  consumeDockerOsSbom,
} from "../collectors/dockerOs";
import {
  type DerivedBase,
  deriveBaseImage,
  discoverDockerfiles,
  MAX_DOCKERFILE_BYTES,
} from "../collectors/dockerfile";
import { compareCodeUnits } from "../model/dependencies";
import { parsePolicy } from "../policy/schema";
import { resolveFrom, writeArtifact } from "./paths";
import { DOCKER_OS_SBOM_FILE, resolveCacheDir } from "./pipeline";
import { sanitizeForLog } from "./summary";

/**
 * The DOCUMENTED DEFAULT image set: a documented default image set. This is
 * the dogfood default and lives HERE (the dogfood subcommand layer), never in
 * core — a consumer repo overrides it with --image / the IMAGES Taskfile var
 * (the project-independence constraint). The base images backing the app
 * containers (node:22-*-slim) are the documented fallback when a full app build
 * is infeasible — see the 07-03 plan BUILD-FEASIBILITY FALLBACK.
 */
export const DEFAULT_IMAGES = [
  "postgres:18",
  "nginx:stable-alpine",
  "redis:7-alpine",
  "node:22-slim",
] as const;

/**
 * Defense-in-depth ref guard (#8): an image operand forwarded to syft must never
 * be empty/whitespace-only (a no-op operand) nor dash-prefixed (a token syft
 * could parse as a flag). The resolveStage validation already keeps these out of
 * a Dockerfile's derived base; this ALSO guards the explicit --image
 * (extraImages) path, which bypasses Dockerfile resolution entirely.
 */
function isSafeImageRef(ref: string): boolean {
  if (ref.trim() === "") return false;
  if (ref.startsWith("-")) return false;
  return true;
}

/**
 * Filter a PURE live-scan image set (the `--image` set forwarded WITHOUT
 * --repo-root) through {@link isSafeImageRef} before it reaches syft/docker
 * (finding #5). The discovery path already guards extraImages via isSafeImageRef;
 * the pure live-scan path bypassed Dockerfile resolution and forwarded
 * opts.images verbatim, so this restores the symmetry. Order-stable; an
 * empty/whitespace-only/dash-prefixed ref is dropped rather than handed to syft
 * as an operand it could parse as a flag.
 */
export function safeLiveScanImages(images: readonly string[]): string[] {
  return images.filter(isSafeImageRef);
}

/**
 * Resolve the PURE live-scan image set: the explicit --image set filtered
 * through {@link safeLiveScanImages} (finding #5), or the documented dogfood
 * default when none was given. Throws when every explicit ref was unsafe — such
 * tokens must never reach syft/docker as an operand. Extracted from
 * runGenerateDockerSbom to keep that orchestrator under the complexity bound.
 */
function resolveLiveScanImages(images: string[] | undefined): string[] {
  if (images === undefined || images.length === 0) {
    return [...DEFAULT_IMAGES];
  }
  const safe = safeLiveScanImages(images);
  if (safe.length === 0) {
    throw new Error(
      "no safe --image refs to scan — every explicit --image ref was empty, " +
        "whitespace-only, or dash-prefixed (such tokens are rejected so they " +
        "can never be parsed by syft/docker as a flag)",
    );
  }
  return safe;
}

/** Options for the pure discovery-mode image-set resolution (07-23). */
export interface ResolveDiscoveredImagesOptions {
  /** Repeatable --exclude globs forwarded to discovery. */
  excludes?: readonly string[];
  /** The `[docker] ignore` globs from the policy. */
  dockerIgnore?: readonly string[];
  /** Explicit --image refs, unioned + deduped with the discovered bases. */
  extraImages?: readonly string[];
  /** This tool's own directory, excluded from the walk. */
  toolDir?: string;
}

/** The result of discovery-mode image resolution: the scan set + a stderr summary. */
export interface ResolveDiscoveredImagesResult {
  /** The deduped, compareCodeUnits-sorted image refs to scan. */
  images: string[];
  /** A concise human-readable summary (multi-line, no trailing newline). */
  summary: string;
}

/**
 * PURE discovery-mode resolution (NO docker, NO syft): walk `repoRoot`, derive
 * each Dockerfile's shipped base (07-23 dockerfile.ts), and build the image set
 * to scan — the UNION of every RESOLVED `image` base and the explicit
 * `extraImages`, deduped and compareCodeUnits-sorted. scratch and unresolved
 * Dockerfiles contribute NO image (scratch has no OS packages; unresolved is
 * loud-skipped — never guessed). Also returns a concise summary naming, in
 * sorted order, every Dockerfile found and its disposition (the resolved base
 * ref, "scratch", or "unresolved: <reason>") plus the ignored ones.
 *
 * Extracted as a pure function so the discovery → scan-set computation is fully
 * testable offline; runGenerateDockerSbom feeds `images` into the existing syft
 * path.
 */
export function resolveDiscoveredImages(
  repoRoot: string,
  opts: ResolveDiscoveredImagesOptions = {},
): ResolveDiscoveredImagesResult {
  const dockerIgnore = opts.dockerIgnore ?? [];
  const { dockerfiles, ignored } = discoverDockerfiles(repoRoot, {
    ...(opts.toolDir !== undefined ? { toolDir: opts.toolDir } : {}),
    ...(opts.excludes !== undefined ? { excludes: opts.excludes } : {}),
    dockerIgnore,
  });

  // Defense-in-depth (#8): NEVER add an empty/whitespace/dash-prefixed ref to
  // the scan set — such a token must never reach syft as an operand (where it
  // could be parsed as a flag). The resolveStage validation already keeps these
  // out of df.base.ref; this also guards the explicit extraImages path, which
  // bypasses Dockerfile resolution.
  const imageSet = new Set<string>(
    (opts.extraImages ?? []).filter(isSafeImageRef),
  );
  const lines: string[] = [];
  for (const df of dockerfiles) {
    if (df.base.kind === "image") {
      imageSet.add(df.base.ref);
      lines.push(`  ${df.identity}: ${df.base.ref}`);
    } else if (df.base.kind === "scratch") {
      lines.push(`  ${df.identity}: scratch (no OS packages, skipped)`);
    } else {
      lines.push(`  ${df.identity}: unresolved: ${df.base.reason} (skipped)`);
    }
  }

  const images = [...imageSet].sort(compareCodeUnits);

  const summaryParts = [
    `discovered ${dockerfiles.length} Dockerfile(s) under ${sanitizeForLog(repoRoot)}:`,
    ...lines,
  ];
  for (const id of ignored) {
    summaryParts.push(`  ${id}: ignored ([docker] ignore)`);
  }
  if (opts.extraImages !== undefined && opts.extraImages.length > 0) {
    // Finding #3: route the explicit --image refs through sanitizeForLog (parity
    // with the repoRoot line above) so a control char in a crafted ref can never
    // reach the stderr summary verbatim.
    const sanitized = opts.extraImages.map(sanitizeForLog).join(", ");
    summaryParts.push(`  (explicit --image: ${sanitized})`);
  }
  summaryParts.push(
    images.length > 0
      ? `scan set (${images.length}): ${images.join(", ")}`
      : "scan set is EMPTY (no resolvable external base images)",
  );

  return { images, summary: summaryParts.join("\n") };
}

/** One explicitly targeted Dockerfile: its display identity + absolute path. */
export interface TargetedDockerfile {
  /** The path as the caller gave it — used (sanitized) in the stderr summary. */
  identity: string;
  /** Absolute, base-dir-resolved path the base is derived from. */
  path: string;
}

/** Options for the pure targeted-Dockerfile image-set resolution. */
export interface ResolveTargetedDockerfilesOptions {
  /** Explicit --image refs, unioned + deduped with the derived bases. */
  extraImages?: readonly string[];
}

/** The result of targeted resolution: the scan set + a stderr summary. */
export interface ResolveTargetedDockerfilesResult {
  /** The deduped, compareCodeUnits-sorted image refs to scan. */
  images: string[];
  /** A concise human-readable summary (multi-line, no trailing newline). */
  summary: string;
}

/**
 * Derive the shipped base of ONE explicitly targeted Dockerfile. Reuses the same
 * size gate and honest-residual {@link deriveBaseImage} the discovery walk does,
 * so a targeted Dockerfile resolves identically to how it would when discovered.
 * A MISSING/unreadable path THROWS (unlike discovery's walked-and-therefore-
 * present files, an explicitly named path that is absent is a caller typo — fail
 * fast rather than silently drop the image it stands for); an oversized file
 * loud-skips as unresolved, exactly as discovery does.
 */
function deriveTargetedBase(path: string): DerivedBase {
  let size: number;
  try {
    size = statSync(path).size;
  } catch {
    throw new Error(
      `--dockerfile path is missing or unreadable: expected ${path}`,
    );
  }
  if (size > MAX_DOCKERFILE_BYTES) {
    return {
      kind: "unresolved",
      reason:
        `exceeds the ${MAX_DOCKERFILE_BYTES}-byte size cap — not parsed; ` +
        `pin the base via --image if this is a real Dockerfile`,
    };
  }
  return deriveBaseImage(readFileSync(path, "utf8"));
}

/**
 * PURE targeted-mode resolution (NO docker, NO syft): derive each EXPLICITLY
 * named Dockerfile's shipped base (07-23 dockerfile.ts) and build the image set
 * to scan — the UNION of every RESOLVED `image` base and the explicit
 * `extraImages`, deduped and compareCodeUnits-sorted. This is the file-list
 * counterpart to {@link resolveDiscoveredImages}: same derivation and honest
 * residual, but over a caller-supplied Dockerfile list instead of a repo walk.
 * scratch and unresolved Dockerfiles contribute NO image (scratch has no OS
 * packages; unresolved is loud-skipped — never guessed). The summary names, in
 * sorted order, every targeted Dockerfile and its disposition. Identities are
 * routed through sanitizeForLog because they originate in `--dockerfile` input.
 */
export function resolveTargetedDockerfiles(
  dockerfiles: readonly TargetedDockerfile[],
  opts: ResolveTargetedDockerfilesOptions = {},
): ResolveTargetedDockerfilesResult {
  const sorted = [...dockerfiles].sort((a, b) =>
    compareCodeUnits(a.identity, b.identity),
  );

  // Defense-in-depth (#8): NEVER add an empty/whitespace/dash-prefixed ref to
  // the scan set — mirrors the discovery extraImages guard.
  const imageSet = new Set<string>(
    (opts.extraImages ?? []).filter(isSafeImageRef),
  );
  const lines: string[] = [];
  for (const df of sorted) {
    const base = deriveTargetedBase(df.path);
    const id = sanitizeForLog(df.identity);
    if (base.kind === "image") {
      imageSet.add(base.ref);
      lines.push(`  ${id}: ${base.ref}`);
    } else if (base.kind === "scratch") {
      lines.push(`  ${id}: scratch (no OS packages, skipped)`);
    } else {
      lines.push(`  ${id}: unresolved: ${base.reason} (skipped)`);
    }
  }

  const images = [...imageSet].sort(compareCodeUnits);

  const summaryParts = [
    `targeted ${dockerfiles.length} Dockerfile(s):`,
    ...lines,
  ];
  if (opts.extraImages !== undefined && opts.extraImages.length > 0) {
    const sanitized = opts.extraImages.map(sanitizeForLog).join(", ");
    summaryParts.push(`  (explicit --image: ${sanitized})`);
  }
  summaryParts.push(
    images.length > 0
      ? `scan set (${images.length}): ${images.join(", ")}`
      : "scan set is EMPTY (no resolvable external base images)",
  );

  return { images, summary: summaryParts.join("\n") };
}

/** Read + parse a policy file's `[docker] ignore` globs; [] when absent/unset. */
function dockerIgnoreFromPolicy(
  policyPath: string,
  baseDir: string | undefined,
): readonly string[] {
  const policyFile = resolveFrom(baseDir, policyPath);
  let policyText: string;
  try {
    policyText = readFileSync(policyFile, "utf8");
  } catch {
    throw new Error(
      `policy file is missing or unreadable: expected ${policyFile}`,
    );
  }
  // parsePolicy throws TomlError/PolicyError verbatim — same fail-fast posture
  // as the generate path; an invalid policy aborts before any scan.
  return parsePolicy(policyText).docker?.ignore ?? [];
}

export interface GenerateDockerSbomOptions {
  /**
   * The configurable image set to scan with the live syft+docker path. Defaults
   * to the documented default image set (DEFAULT_IMAGES) when the caller
   * passes NEITHER --image NOR --from-sbom — the documented dogfood default,
   * overridable per consumer repo. Mutually combinable with fromSbomPaths is
   * NOT supported: a run is either a live scan or a pre-made ingest.
   */
  images?: string[];
  /**
   * Pre-made syft/CycloneDX SBOM file paths to INGEST instead of scanning live
   * (the CI-attestation consumer path, base-dir-resolved). When set, the tool
   * runs NO docker/syft — it reads these committed/attested SBOMs, filters to
   * deb/apk, preserves licenses, and extracts each image's digest. Mutually
   * exclusive with `images` (validated in the CLI: at least one of
   * --image/--from-sbom, never both).
   */
  fromSbomPaths?: string[];
  /**
   * Discovery mode (07-23): walk this repo root for Dockerfiles, derive each
   * shipped base image, and scan the resolved bases (union+dedup with any
   * explicit --image refs) via the same syft path. scratch/unresolved/ignored
   * Dockerfiles contribute no image. When unset, behaviour is exactly today's
   * (explicit --image set or the documented default). Base-dir-resolved.
   */
  repoRoot?: string;
  /**
   * Targeted mode: derive + scan the shipped base of each EXPLICITLY named
   * Dockerfile (base-dir-resolved), rather than walking a repo. The file-list
   * counterpart to `repoRoot` discovery — same derivation, honest residual, and
   * `--image` union. When `repoRoot` is ALSO set it is used only as the cache-dir
   * anchor, never as a discovery root: the explicit list wins. Mutually exclusive
   * with `fromSbomPaths` (a pre-made ingest is not a live derive+scan).
   */
  dockerfilePaths?: string[];
  /** --exclude globs forwarded to Dockerfile discovery (discovery mode only). */
  excludes?: string[];
  /**
   * Policy file to read the `[docker] ignore` globs from (discovery mode only).
   * Validated via parsePolicy — an invalid policy aborts before any scan.
   * Base-dir-resolved.
   */
  policyPath?: string;
  /**
   * Optional override for the committed OS-SBOM output path. When unset it
   * defaults to DOCKER_OS_SBOM_FILE inside the resolved cache dir (the policy
   * `[cache] dir`, or DEFAULT_CACHE_DIR), the same file generate and check read.
   */
  dockerOsSbomPath?: string;
  /**
   * Base directory for resolving relative paths — same anchoring as runGenerate.
   * The default output lands in the resolved cache dir (repo-root-anchored)
   * alongside the other committed artifacts.
   */
  baseDir?: string;
  /**
   * This tool's OWN directory, excluded from the discovery walk (discovery mode
   * only). Wired exactly as the lockfile discovery path does (targets.ts:53
   * computes `join(import.meta.dir, "..", "..")`): cli.ts populates it so the
   * tool's own dockerfile.ts/.test.ts are pruned by shouldDescendDir rather than
   * relying on a name blocklist (findings #4/#6). Forwarded to
   * resolveDiscoveredImages → discoverDockerfiles.
   */
  toolDir?: string;
  /**
   * `docker pull` each resolved image before scanning it (opt-in, live paths
   * only — targeted/discovery/live-scan; never the daemon-free `fromSbomPaths`
   * ingest). Off by default so the standard maintainer path fails loudly on an
   * absent image; the GitHub Action turns it on because it derives its base set
   * only at runtime and cannot pre-pull.
   */
  pull?: boolean;
  /** Pass syft/docker child stdout/stderr through to process.stderr. */
  verbose?: boolean;
}

/**
 * CONSUMER PATH: ingest pre-made syft/CycloneDX SBOMs — NO docker, NO syft.
 * This is the CI-attestation flow: the build pipeline produces the SBOM by
 * registry digest, this command consumes it. Extracted from
 * runGenerateDockerSbom to keep that orchestrator under the complexity bound.
 */
async function runIngestMode(
  opts: GenerateDockerSbomOptions,
  outputPath: string,
): Promise<void> {
  const fromSbomPaths = opts.fromSbomPaths ?? [];
  const resolved = fromSbomPaths.map((p) => resolveFrom(opts.baseDir, p));
  const { doc } = await consumeDockerOsSbom(resolved, {
    verbose: opts.verbose ?? false,
  });
  writeArtifact(outputPath, doc);
  process.stderr.write(
    `wrote ${sanitizeForLog(outputPath)} ` +
      `(${resolved.length} pre-made SBOM(s) consumed, no docker)\n`,
  );
}

/**
 * TARGETED PATH: derive + scan the shipped base of an EXPLICIT Dockerfile list
 * (--dockerfile), rather than walking a repo. --repo-root, if also given,
 * serves only as the cache-dir anchor (outputPath, resolved by the caller) and
 * is NOT a discovery root here — the explicit list wins. The summary prints to
 * stderr BEFORE the scan so the resolved set is visible even if a later scan
 * fails. Extracted from runGenerateDockerSbom to keep that orchestrator under
 * the complexity bound.
 */
async function runTargetedMode(
  opts: GenerateDockerSbomOptions,
  outputPath: string,
): Promise<void> {
  const dockerfilePaths = opts.dockerfilePaths ?? [];
  const targeted = dockerfilePaths.map((p) => ({
    identity: p,
    path: resolveFrom(opts.baseDir, p),
  }));
  const { images: derived, summary } = resolveTargetedDockerfiles(targeted, {
    ...(opts.images !== undefined ? { extraImages: opts.images } : {}),
  });
  process.stderr.write(`${summary}\n`);
  if (derived.length === 0) {
    throw new Error(
      "the targeted Dockerfile(s) resolved no external base images to scan " +
        "— every one is scratch, unresolved, or oversized (pass --image to " +
        "add an explicit base)",
    );
  }
  const { doc } = await collectDockerOsSbom(derived, {
    verbose: opts.verbose ?? false,
    pull: opts.pull ?? false,
  });
  writeArtifact(outputPath, doc);
  process.stderr.write(
    `wrote ${sanitizeForLog(outputPath)} ` +
      `(${derived.length} targeted base image(s) scanned)\n`,
  );
}

/**
 * DISCOVERY PATH (07-23): walk --repo-root for Dockerfiles, derive each
 * shipped base, and scan the resolved bases (union+dedup with explicit
 * --image). The summary is printed to stderr BEFORE the scan so the
 * discovered set is visible even if a later scan step fails. Extracted from
 * runGenerateDockerSbom to keep that orchestrator under the complexity bound;
 * repoRootOpt is threaded as its own (non-optional) parameter rather than
 * read off opts, since the dispatch guard narrows opts.repoRoot only at the
 * call site, not across the function boundary.
 */
async function runDiscoveryMode(
  opts: GenerateDockerSbomOptions,
  outputPath: string,
  repoRootOpt: string,
): Promise<void> {
  const repoRoot = resolveFrom(opts.baseDir, repoRootOpt);
  const dockerIgnore =
    opts.policyPath !== undefined
      ? dockerIgnoreFromPolicy(opts.policyPath, opts.baseDir)
      : [];
  const { images: discovered, summary } = resolveDiscoveredImages(repoRoot, {
    ...(opts.toolDir !== undefined ? { toolDir: opts.toolDir } : {}),
    ...(opts.excludes !== undefined ? { excludes: opts.excludes } : {}),
    dockerIgnore,
    ...(opts.images !== undefined ? { extraImages: opts.images } : {}),
  });
  process.stderr.write(`${summary}\n`);
  if (discovered.length === 0) {
    throw new Error(
      "discovery resolved no external base images to scan — every " +
        "Dockerfile is scratch, unresolved, or ignored (pass --image to " +
        "scan an explicit set, or check the [docker] ignore globs)",
    );
  }
  const { doc } = await collectDockerOsSbom(discovered, {
    verbose: opts.verbose ?? false,
    pull: opts.pull ?? false,
  });
  writeArtifact(outputPath, doc);
  process.stderr.write(
    `wrote ${sanitizeForLog(outputPath)} ` +
      `(${discovered.length} discovered base image(s) scanned)\n`,
  );
}

/**
 * LIVE-SCAN PATH: spawn the pinned syft + docker over the image set. The
 * explicit --image set is routed through safeLiveScanImages (finding #5) so a
 * hostile/garbage dash-prefixed or empty ref is dropped before it reaches
 * syft/docker as an operand — symmetry with the discovery extraImages guard.
 * Extracted from runGenerateDockerSbom to keep that orchestrator under the
 * complexity bound.
 */
async function runLiveScanMode(
  opts: GenerateDockerSbomOptions,
  outputPath: string,
): Promise<void> {
  const requested = resolveLiveScanImages(opts.images);

  const { doc } = await collectDockerOsSbom(requested, {
    verbose: opts.verbose ?? false,
    pull: opts.pull ?? false,
  });

  writeArtifact(outputPath, doc);
  process.stderr.write(
    `wrote ${sanitizeForLog(outputPath)} (${requested.length} images scanned)\n`,
  );
}

/**
 * Build/pull, scan, digest-pin, and write the committed Docker OS-SBOM.
 *
 * The images MUST already be present locally (pulled or built) — collectDockerOsSbom
 * scans them with the pinned syft and resolves each platform RepoDigest via
 * `docker inspect`, which hard-fails with an actionable message on an absent
 * image. The Taskfile / maintainer pulls postgres:18 + nginx:stable-alpine and
 * builds (or base-image-falls-back) the app images before invoking this; this
 * orchestrator does not silently pull, so a missing image surfaces loudly rather
 * than racing a network fetch into the determinism contract.
 *
 * Kept to outputPath resolution + a dispatch ladder — each mode's logic lives
 * in its own extracted helper (runIngestMode/runTargetedMode/runDiscoveryMode/
 * runLiveScanMode) so this orchestrator stays under the complexity bound.
 */
export async function runGenerateDockerSbom(
  opts: GenerateDockerSbomOptions,
): Promise<void> {
  // Default output: DOCKER_OS_SBOM_FILE inside the resolved cache dir (the policy
  // `[cache] dir`, or the default, anchored to the scanned repo), so the file this
  // command WRITES is exactly the one generate and check READ; --docker-os-sbom
  // overrides it.
  const outputPath =
    opts.dockerOsSbomPath !== undefined
      ? resolveFrom(opts.baseDir, opts.dockerOsSbomPath)
      : resolveFrom(
          resolveCacheDir({
            baseDir: opts.baseDir,
            repoRoot: opts.repoRoot,
            policyPath: opts.policyPath,
          }),
          DOCKER_OS_SBOM_FILE,
        );

  // CONSUMER PATH takes priority when set.
  if (opts.fromSbomPaths !== undefined && opts.fromSbomPaths.length > 0) {
    return runIngestMode(opts, outputPath);
  }

  // TARGETED PATH.
  if (opts.dockerfilePaths !== undefined && opts.dockerfilePaths.length > 0) {
    return runTargetedMode(opts, outputPath);
  }

  // DISCOVERY PATH (07-23).
  if (opts.repoRoot !== undefined) {
    return runDiscoveryMode(opts, outputPath, opts.repoRoot);
  }

  // LIVE-SCAN PATH (the default when none of the above modes apply).
  return runLiveScanMode(opts, outputPath);
}
