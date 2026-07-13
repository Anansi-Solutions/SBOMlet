/**
 * The dedicated `generate-docker-sbom` orchestrator: the ONLY path in the tool
 * that touches the docker daemon / syft / buildx. It resolves ONE of three
 * mutually exclusive lanes, builds when the lane calls for it, scans each
 * resulting image with the single-posture collector (collectDockerOsSbom), and
 * writes the deterministic committed `docker.sbom.json` at the base-dir-
 * resolved output path.
 *
 * THE THREE LANES (pairwise mutually exclusive):
 *   1. --dockerfile <path>...  build each explicitly named Dockerfile to a
 *      deterministic tag, then scan the built image;
 *   2. --repo-root <dir>       discover the repo's Dockerfiles, build each,
 *      then scan;
 *   3. --image <ref>...        scan pre-existing image refs (pull when absent).
 * There is NO default image set: a bare invocation is a usage error (the CLI
 * names the lanes). Dockerfiles are BUILD INPUTS, never objects of analysis —
 * their contents are never read here.
 *
 * This is deliberately a SEPARATE subcommand, not a
 * `--scan-docker` flag on `generate` — the everyday generate/check stay
 * daemon-free and fully offline, reading the committed bytes this command
 * produces as a scope:"os" merge input. The blast radius of the
 * docker/network side-effect is confined to this one path.
 *
 * The single writeFileSync lives here (mirroring runGenerate's writer-owns-bytes
 * posture) so the collector stays write-free and a
 * double-run from the same inputs is byte-identical by construction (toSortedJson
 * via emitDockerOsDoc).
 */

import { readFileSync, statSync } from "node:fs";

import { buildImage, imageTag, type ExecFn } from "../collectors/dockerBuild";
import { collectDockerOsSbom, type ScanImage } from "../collectors/dockerOs";
import { discoverDockerfiles } from "../collectors/dockerfile";
import { execTool } from "../collectors/exec";
import { compareCodeUnits } from "../model/dependencies";
import { parsePolicy } from "../policy/schema";
import { resolveFrom, writeArtifact } from "./paths";
import { DOCKER_SBOM_FILE, resolveCacheDir } from "./pipeline";
import { sanitizeForLog } from "./summary";

/**
 * Defense-in-depth ref guard: an image operand forwarded to syft must never
 * be empty/whitespace-only (a no-op operand) nor dash-prefixed (a token syft
 * could parse as a flag). Guards the --image lane, whose refs
 * are passed straight through to syft/docker as operands.
 */
function isSafeImageRef(ref: string): boolean {
  if (ref.trim() === "") return false;
  if (ref.startsWith("-")) return false;
  return true;
}

/**
 * Filter an image-lane ref set through {@link isSafeImageRef} before it reaches
 * syft/docker as an operand. Order-stable; an empty/whitespace-only/dash-
 * prefixed ref is dropped rather than handed to syft as a token it could parse
 * as a flag.
 */
export function safeLiveScanImages(images: readonly string[]): string[] {
  return images.filter(isSafeImageRef);
}

/** Options for the pure discovery-lane build-set resolution. */
export interface ResolveDiscoveredImagesOptions {
  /** Repeatable --exclude globs forwarded to discovery. */
  excludes?: readonly string[];
  /** The `[docker] ignore` globs from the policy. */
  dockerIgnore?: readonly string[];
  /** This tool's own directory, excluded from the walk. */
  toolDir?: string;
}

/** One Dockerfile in the discovery/target build set: its identity + build tag. */
export interface DockerfileBuild {
  /** Repo-relative (discovery) / caller-supplied (targeted) identity string. */
  identity: string;
  /** Absolute filesystem path. */
  path: string;
  /** The deterministic image tag this Dockerfile builds to (imageTag(identity)). */
  tag: string;
}

/** The result of discovery-lane resolution: the build set + a stderr summary. */
export interface ResolveDiscoveredImagesResult {
  /** The Dockerfiles to build (post [docker] ignore + --exclude), sorted. */
  build: DockerfileBuild[];
  /** Repo-relative identities excluded by a `[docker] ignore` glob, sorted. */
  ignored: string[];
  /** A concise human-readable summary (multi-line, no trailing newline). */
  summary: string;
}

/**
 * PURE discovery-lane resolution (NO docker, NO syft, NO file reads): walk
 * `repoRoot` for Dockerfiles and build the set to build+scan. Discovery is
 * LISTING-ONLY — no Dockerfile is read; every discovered (non-ignored,
 * non-excluded) Dockerfile is a build input whose deterministic tag is
 * imageTag(identity). The build tag is a pure function of the DISCOVERY IDENTITY
 * STRING, which is exactly what produces today's committed sidecar identity —
 * any path-shape change would churn the committed artifact.
 *
 * The summary names, in sorted order, every discovered Dockerfile and its build
 * tag, plus the `[docker]`-ignored ones. Identities and repoRoot are routed
 * through sanitizeForLog before reaching stderr.
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

  const build: DockerfileBuild[] = dockerfiles.map((df) => ({
    identity: df.identity,
    path: df.path,
    tag: imageTag(df.identity),
  }));

  const summaryParts = [
    `discovered ${build.length} Dockerfile(s) under ${sanitizeForLog(repoRoot)}:`,
    ...build.map((b) => `  ${sanitizeForLog(b.identity)} -> ${b.tag}`),
  ];
  for (const id of ignored) {
    summaryParts.push(`  ${sanitizeForLog(id)}: ignored ([docker] ignore)`);
  }
  summaryParts.push(
    build.length > 0
      ? `build set (${build.length}): ${build
          .map((b) => sanitizeForLog(b.identity))
          .join(", ")}`
      : "build set is EMPTY (every discovered Dockerfile is [docker]-ignored or --excluded)",
  );

  return { build, ignored, summary: summaryParts.join("\n") };
}

/** Options for the pure --list-dockerfiles resolution. */
export interface DockerfileListingOptions {
  /** This tool's own directory, excluded from the walk. */
  toolDir?: string;
  /** Repeatable --exclude globs forwarded to discovery. */
  excludes?: readonly string[];
  /** The `[docker] ignore` globs from the policy. */
  dockerIgnore?: readonly string[];
}

/**
 * PURE --list-dockerfiles resolution (NO docker, NO syft, NO writes): walk
 * `repoRoot` and return every discovered Dockerfile's repo-relative identity,
 * sorted (discoverDockerfiles already sorts the walk). This is the CI
 * workflow's discovery surface, so the build set is the tool's own
 * policy-aware walk, never a shell find. Ignored (by `[docker] ignore`)
 * identities are deliberately excluded — a policy-ignored Dockerfile must
 * never be built by CI.
 */
export function dockerfileListing(
  repoRoot: string,
  opts: DockerfileListingOptions = {},
): string[] {
  const { dockerfiles } = discoverDockerfiles(repoRoot, {
    ...(opts.toolDir !== undefined ? { toolDir: opts.toolDir } : {}),
    ...(opts.excludes !== undefined ? { excludes: opts.excludes } : {}),
    dockerIgnore: opts.dockerIgnore ?? [],
  });
  return dockerfiles.map((d) => d.identity);
}

/** One explicitly targeted Dockerfile: its display identity + absolute path. */
export interface TargetedDockerfile {
  /** The path as the caller gave it — used (sanitized) in the stderr summary. */
  identity: string;
  /** Absolute, base-dir-resolved path. */
  path: string;
}

/** The result of targeted-lane resolution: the build set + a stderr summary. */
export interface ResolveTargetedDockerfilesResult {
  /** The Dockerfiles to build, deduped by identity and sorted. */
  build: DockerfileBuild[];
  /** A concise human-readable summary (multi-line, no trailing newline). */
  summary: string;
}

/**
 * PURE targeted-lane resolution (NO docker, NO syft, NO file reads): take the
 * EXPLICITLY named Dockerfile list, sort + dedup by identity, and build the set
 * to build+scan. Each Dockerfile's deterministic tag is imageTag(identity),
 * where the identity is the caller's path string verbatim.
 *
 * A MISSING/unreadable named path THROWS before any build runs — an explicitly
 * named path that is absent is a caller typo, so we fail fast rather than
 * silently drop the image it stands for (unlike a walked-and-therefore-present
 * discovery file). The summary names, in sorted order, every targeted Dockerfile
 * and its build tag; identities are routed through sanitizeForLog because they
 * originate in `--dockerfile` input.
 */
export function resolveTargetedDockerfiles(
  dockerfiles: readonly TargetedDockerfile[],
): ResolveTargetedDockerfilesResult {
  const sorted = [...dockerfiles].sort((a, b) =>
    compareCodeUnits(a.identity, b.identity),
  );

  // Fail-fast on a missing/unreadable named path — a caller typo must surface
  // loudly BEFORE any build argv is spawned, never silently drop an image.
  for (const df of sorted) {
    try {
      statSync(df.path);
    } catch {
      throw new Error(
        `--dockerfile path is missing or unreadable: expected ${df.path}`,
      );
    }
  }

  const seen = new Set<string>();
  const build: DockerfileBuild[] = [];
  for (const df of sorted) {
    if (seen.has(df.identity)) continue;
    seen.add(df.identity);
    build.push({
      identity: df.identity,
      path: df.path,
      tag: imageTag(df.identity),
    });
  }

  const summaryParts = [
    `building ${build.length} targeted Dockerfile(s):`,
    ...build.map((b) => `  ${sanitizeForLog(b.identity)} -> ${b.tag}`),
  ];
  summaryParts.push(
    build.length > 0
      ? `build set (${build.length}): ${build
          .map((b) => sanitizeForLog(b.identity))
          .join(", ")}`
      : "build set is EMPTY (no Dockerfiles named)",
  );

  return { build, summary: summaryParts.join("\n") };
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
   * IMAGE LANE (--image): scan pre-existing image refs with the live syft+docker
   * path (pull when a ref is absent locally). One of the three ways in; mutually
   * exclusive with repoRoot/dockerfilePaths (validated in the CLI).
   */
  images?: string[];
  /**
   * DISCOVERY BUILD LANE (--repo-root): walk this repo root for Dockerfiles,
   * build each to its deterministic tag, and scan the built images. Discovery
   * reads no Dockerfile contents — every discovered (non-ignored, non-excluded)
   * Dockerfile is a build input. Base-dir-resolved; mutually exclusive with the
   * other lanes.
   */
  repoRoot?: string;
  /**
   * TARGETED BUILD LANE (--dockerfile): build each EXPLICITLY named Dockerfile
   * (base-dir-resolved) to its deterministic tag and scan the built image. The
   * file-list counterpart to `repoRoot` discovery; a missing named path fails
   * fast. Mutually exclusive with the other lanes.
   */
  dockerfilePaths?: string[];
  /** --exclude globs forwarded to Dockerfile discovery (discovery lane only). */
  excludes?: string[];
  /**
   * Policy file to read the `[docker] ignore` globs from (discovery lane only).
   * Validated via parsePolicy — an invalid policy aborts before any build.
   * Base-dir-resolved.
   */
  policyPath?: string;
  /**
   * Optional override for the committed OS-SBOM output path. When unset it
   * defaults to DOCKER_SBOM_FILE inside the resolved cache dir (the policy
   * `[cache] dir`, or DEFAULT_CACHE_DIR), the same file generate and check read.
   */
  dockerSbomPath?: string;
  /**
   * Base directory for resolving relative paths — same anchoring as runGenerate.
   * The default output lands in the resolved cache dir (repo-root-anchored)
   * alongside the other committed artifacts.
   */
  baseDir?: string;
  /**
   * This tool's OWN directory, excluded from the discovery walk (discovery lane
   * only). Wired exactly as the lockfile discovery path does (targets.ts
   * computes `join(import.meta.dir, "..", "..")`): cli.ts populates it so the
   * tool's own dockerfile.ts/.test.ts are pruned by shouldDescendDir rather than
   * relying on a name blocklist.
   */
  toolDir?: string;
  /** Pass syft/docker/buildx child stdout/stderr through to process.stderr. */
  verbose?: boolean;
  /**
   * --list-dockerfiles: print the policy-aware discovered Dockerfile identities
   * to stdout, one per line, and return before any build or write. This is the
   * CI workflow's discovery surface, so the build set comes from the tool's
   * own walk, never a hand-rolled shell find. Requires repoRoot (validated in
   * the CLI).
   */
  listDockerfiles?: boolean;
}

/**
 * Build a set of Dockerfiles (by identity string) to their deterministic tags
 * via the injected exec seam, returning the built tags in order. The identity
 * string is passed to buildImage verbatim so imageTag(identity) — the committed
 * sidecar identity — is stable (the discovery/targeted lanes hand this the exact
 * string the listing prints).
 *
 * `cwd` is the buildx working directory: buildImageArgs is repo-relative, so the
 * `-f` value and build context resolve against `cwd`. The DISCOVERY lane anchors
 * it to the repo root (its identities are repo-relative); the TARGETED lane
 * leaves it undefined so a caller's `--dockerfile` path resolves against their
 * own process cwd. `exec` is injectable so the lane wiring is testable without a
 * docker daemon; it defaults to the real execTool seam.
 */
export async function buildImages(
  identities: readonly string[],
  verbose: boolean,
  cwd?: string,
  exec: ExecFn = execTool,
): Promise<string[]> {
  const tags: string[] = [];
  for (const identity of identities) {
    tags.push(await buildImage(identity, exec, { verbose, cwd }));
  }
  return tags;
}

/**
 * Scan an already-resolved image set with the single-posture collector, write
 * the committed doc, and narrate to stderr. Shared by all three lanes so the
 * output-path resolution and byte-identity contract are identical whatever the
 * lane. Each entry pairs the image ref with its SOURCE identity — the
 * Dockerfile identity for the build lanes, the requested ref verbatim for the
 * image lane — so the emitted sidecar records where every image came from.
 */
async function scanAndWrite(
  images: ScanImage[],
  outputPath: string,
  verbose: boolean,
): Promise<void> {
  const { doc } = await collectDockerOsSbom(images, { verbose });
  writeArtifact(outputPath, doc);
  process.stderr.write(
    `wrote ${sanitizeForLog(outputPath)} (${images.length} image(s) scanned)\n`,
  );
}

/**
 * TARGETED BUILD LANE (--dockerfile): resolve the named Dockerfiles (sorted,
 * deduped, fail-fast on a missing path), build each to its deterministic tag,
 * and scan the built images. The summary prints to stderr BEFORE the build so
 * the resolved set is visible even if a later build/scan fails.
 */
async function runTargetedBuildLane(
  opts: GenerateDockerSbomOptions,
  outputPath: string,
): Promise<void> {
  const dockerfilePaths = opts.dockerfilePaths ?? [];
  const targeted = dockerfilePaths.map((p) => ({
    identity: p,
    path: resolveFrom(opts.baseDir, p),
  }));
  const { build, summary } = resolveTargetedDockerfiles(targeted);
  process.stderr.write(`${summary}\n`);
  // No cwd: an explicit --dockerfile path is relative to the caller's own cwd,
  // so the build must resolve it against process.cwd(), not any repo anchor.
  await buildImages(
    build.map((b) => b.identity),
    opts.verbose ?? false,
  );
  // Each built tag is scanned with its Dockerfile identity as the source —
  // the DockerfileBuild records already hold the identity→tag mapping.
  await scanAndWrite(
    build.map((b) => ({ image: b.tag, source: b.identity })),
    outputPath,
    opts.verbose ?? false,
  );
}

/**
 * DISCOVERY BUILD LANE (--repo-root): walk the repo for Dockerfiles, build each
 * from its DISCOVERY IDENTITY STRING (the committed-identity input), and scan
 * the built images. A build set emptied by `[docker] ignore` / --exclude is a
 * loud error, matching the old script's exit-1 posture. repoRootOpt is threaded
 * as its own parameter since the dispatch guard narrows opts.repoRoot only at
 * the call site.
 */
async function runDiscoveryBuildLane(
  opts: GenerateDockerSbomOptions,
  outputPath: string,
  repoRootOpt: string,
): Promise<void> {
  const repoRoot = resolveFrom(opts.baseDir, repoRootOpt);
  const dockerIgnore =
    opts.policyPath !== undefined
      ? dockerIgnoreFromPolicy(opts.policyPath, opts.baseDir)
      : [];
  const { build, ignored, summary } = resolveDiscoveredImages(repoRoot, {
    ...(opts.toolDir !== undefined ? { toolDir: opts.toolDir } : {}),
    ...(opts.excludes !== undefined ? { excludes: opts.excludes } : {}),
    dockerIgnore,
  });
  process.stderr.write(`${summary}\n`);
  if (build.length === 0) {
    throw new Error(
      `discovery found no Dockerfiles to build under ${sanitizeForLog(repoRoot)} ` +
        `— every discovered Dockerfile is [docker]-ignored or --excluded ` +
        `(${ignored.length} ignored); nothing to scan`,
    );
  }
  // Anchor the buildx cwd to the resolved repo root: discovery identities are
  // repo-relative, so the repo-relative -f/context in buildImageArgs resolve
  // against repoRoot regardless of the tool's process cwd. Without this a
  // consumer invoking from a subdir (e.g. tools/sbomlet) hits
  // "unable to prepare context: path not found".
  await buildImages(
    build.map((b) => b.identity),
    opts.verbose ?? false,
    repoRoot,
  );
  // Each built tag is scanned with its repo-relative discovery identity as
  // the source — the exact string --list-dockerfiles prints.
  await scanAndWrite(
    build.map((b) => ({ image: b.tag, source: b.identity })),
    outputPath,
    opts.verbose ?? false,
  );
}

/**
 * IMAGE LANE (--image): scan pre-existing image refs. The refs are guarded
 * through safeLiveScanImages before reaching syft/docker as operands;
 * the whole set being unsafe is a loud throw, never a silent empty scan. The
 * collector probes local presence and pulls only when a ref is absent (a
 * locally-present built tag is scanned as-is). The summary prints to stderr
 * BEFORE the scan.
 */
async function runImageLane(
  opts: GenerateDockerSbomOptions,
  outputPath: string,
): Promise<void> {
  const requested = safeLiveScanImages(opts.images ?? []);
  if (requested.length === 0) {
    throw new Error(
      "no safe image refs to scan — every --image ref was empty, " +
        "whitespace-only, or dash-prefixed (such tokens are rejected so they " +
        "can never be parsed by syft/docker as a flag)",
    );
  }
  process.stderr.write(
    `scanning ${requested.length} image(s): ${requested.map(sanitizeForLog).join(", ")}\n`,
  );
  // Image lane: the source identity is the requested ref VERBATIM (source ===
  // image) — the pinned digest stays in dockerImages[].digest, never in a
  // source, so a re-pin can never churn an identity.
  await scanAndWrite(
    requested.map((ref) => ({ image: ref, source: ref })),
    outputPath,
    opts.verbose ?? false,
  );
}

/**
 * Resolve ONE of the three lanes, build when the lane calls for it, scan, and
 * write the committed Docker OS-SBOM. Kept to the listing short-circuit +
 * outputPath resolution + a three-lane dispatch ladder — each lane's logic lives
 * in its own extracted helper so this orchestrator stays under the complexity
 * bound.
 */
export async function runGenerateDockerSbom(
  opts: GenerateDockerSbomOptions,
): Promise<void> {
  // LISTING PATH (--list-dockerfiles): returns BEFORE any outputPath
  // resolution or artifact write — this mode scans nothing and writes
  // nothing, it only prints the tool's own policy-aware Dockerfile walk to
  // stdout (the machine channel) for the CI workflow's build loop to consume.
  if (opts.listDockerfiles === true) {
    // The CLI conflict table pairs --list-dockerfiles with --repo-root at the
    // flag surface; hold the same invariant at this public API boundary so a
    // programmatic caller can never fall through into a build/scan lane.
    if (opts.repoRoot === undefined) {
      throw new Error("--list-dockerfiles requires a repo root");
    }
    const repoRoot = resolveFrom(opts.baseDir, opts.repoRoot);
    const dockerIgnore =
      opts.policyPath !== undefined
        ? dockerIgnoreFromPolicy(opts.policyPath, opts.baseDir)
        : [];
    const identities = dockerfileListing(repoRoot, {
      ...(opts.toolDir !== undefined ? { toolDir: opts.toolDir } : {}),
      ...(opts.excludes !== undefined ? { excludes: opts.excludes } : {}),
      dockerIgnore,
    });
    for (const identity of identities) {
      process.stdout.write(`${identity}\n`);
    }
    return;
  }

  // Default output: DOCKER_SBOM_FILE inside the resolved cache dir (the policy
  // `[cache] dir`, or the default, anchored to the scanned repo), so the file this
  // command WRITES is exactly the one generate and check READ; --docker-sbom
  // overrides it. resolveCacheDir already handles repoRoot: undefined (the
  // --dockerfile / --image lanes have no repo root).
  const outputPath =
    opts.dockerSbomPath !== undefined
      ? resolveFrom(opts.baseDir, opts.dockerSbomPath)
      : resolveFrom(
          resolveCacheDir({
            baseDir: opts.baseDir,
            repoRoot: opts.repoRoot,
            policyPath: opts.policyPath,
          }),
          DOCKER_SBOM_FILE,
        );

  // LANE 1 — targeted build (--dockerfile).
  if (opts.dockerfilePaths !== undefined && opts.dockerfilePaths.length > 0) {
    return runTargetedBuildLane(opts, outputPath);
  }

  // LANE 2 — discovery build (--repo-root).
  if (opts.repoRoot !== undefined) {
    return runDiscoveryBuildLane(opts, outputPath, opts.repoRoot);
  }

  // LANE 3 — image scan (--image).
  if (opts.images !== undefined && opts.images.length > 0) {
    return runImageLane(opts, outputPath);
  }

  // No lane selected. The CLI already guards this at the flag surface, but the
  // public API holds the same invariant — there is no default image set, so a
  // bare invocation is never a silent scan.
  throw new Error(
    "generate-docker-sbom requires one lane: --dockerfile <path>... (build " +
      "named Dockerfiles), --repo-root <dir> (discover + build), or --image " +
      "<ref>... (scan pre-existing images)",
  );
}
