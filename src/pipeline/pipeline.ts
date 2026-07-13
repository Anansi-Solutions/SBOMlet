/**
 * The write-free pipeline core shared by generate and check: buildOutputs
 * renders everything in memory and never writes; runGenerate holds the only
 * writeFileSync calls, so check can never overwrite the files it gates on.
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { basename, relative } from "node:path";

import { assertSyftSbomSize } from "../collectors/dockerOs";
import { assessPackages } from "../enrich/assess";
import { enrichUnknowns } from "../enrich/enrich";
import { type IntensiveOptions } from "../enrich/scancode";
import {
  DOCKER_OS_IDENTITY,
  mergeSboms,
  type CollectedSbom,
} from "../merge/merge";
import {
  toSortedDependenciesJson,
  type EvaluatedDependencies,
  type Verdict,
} from "../model/dependencies";
import { annotateFindings } from "../normalize/normalize";
import { BUILTIN_OVERRIDES } from "../policy/builtinOverrides";
import { evaluate } from "../policy/evaluate";
import { parsePolicy, type Policy } from "../policy/schema";
import { alignTables } from "../render/alignTables";
import { renderCyclonedx } from "../render/cyclonedx";
import { renderMarkdown, type PolicyView } from "../render/markdown";
import { renderNotices } from "../render/notices";
import { resolveFrom } from "./paths";
import { sanitizeForLog, writePolicySummary } from "./summary";
import { collectTargets } from "./targets";

/**
 * The default directory for tool-generated committed artifacts — the enrichment
 * cache and the Docker OS SBOM. It resolves against the SCANNED repo (--repo-root;
 * --base-dir only in single-target mode), so the generated state binds to the repo
 * being scanned, never the invocation dir: the CLI, in-process callers, and the
 * GitHub Action all read the same committed files. A policy `[cache] dir` overrides
 * the subdirectory (validated repo-relative, so it can never escape); the anchor
 * stays the repo root. Collecting the artifacts in one hidden dir — instead of
 * scattering dotfiles across the repo root — is the whole point of the [cache] table.
 */
export const DEFAULT_CACHE_DIR = ".sbomlet.cache";

/** The enrichment cache filename inside the resolved cache dir. */
export const ENRICHMENT_CACHE_FILE = "licenses.cache.json";

/**
 * The dedicated ScanCode analysis memo filename inside the resolved cache dir
 * (D-04, SCAN-06): a COMMITTED cache with a lifecycle separate from the registry
 * enrichment cache — the intensive ScanCode lane results live here, not in
 * {@link ENRICHMENT_CACHE_FILE}, so the two caches version and invalidate
 * independently. Resolved via the same {@link cacheDir}, so a policy `[cache]
 * dir` steers both to the same directory.
 */
export const SCANCODE_CACHE_FILE = "scancode.cache.json";

/**
 * The committed Docker image SBOM filename inside the cache dir (COLL-04): a
 * deterministic emitter's output, committed and consumed as a scope:"os" MERGE
 * INPUT, never scanned per-run. A MISSING file is the enrichment-cache-miss
 * equivalent (NO os entries, NO docker, NO syft, fully offline). What POPULATES it
 * is the dedicated generate-docker-sbom subcommand, which builds or pulls a real
 * image and scans its full contents; generate and check read the same committed
 * bytes, so determinism is trivial.
 */
export const DOCKER_OS_SBOM_FILE = "docker-os.sbom.json";

export interface GenerateOptions {
  /** Single-target debug mode; mutually exclusive with repoRoot. */
  targetArg?: string;
  /** Discovery-mode root; defaults to the current working directory. */
  repoRoot?: string;
  /** Repeatable --exclude globs, matched against target identities. */
  excludes?: string[];
  outputPath: string;
  /**
   * THIRD_PARTY_NOTICES.md companion output path: generate always writes the
   * companion; main() defaults this to THIRD_PARTY_NOTICES.md in the same
   * directory as the output path when --notices is absent.
   */
  noticesPath: string;
  /**
   * Optional CycloneDX 1.6 export path: rendered and written only when
   * configured; check byte-compares it when set.
   */
  cyclonedxPath?: string;
  dumpModelPath?: string;
  /**
   * generate --intensive: opt-in ScanCode assessment over the FULL package set
   * (every package with locally-present sources not already in the analysis
   * memo). Absent-not-false (own-property gated at the assessPackages call site
   * below) so a default generate never constructs {@link IntensiveOptions} and
   * stays structurally scan-free. check REJECTS this flag outright
   * (gate/check.ts, the dump-model precedent) — the shared optionsFrom parses
   * it, but only runGenerate ever threads it through as true.
   */
  intensive?: boolean;
  /**
   * Optional TOML policy file: loaded + validated before any scan; verdicts
   * evaluated after the merge and rendered into the PolicyView document.
   * Findings are annotated unconditionally — the absent flag only removes the
   * policy-gated surfaces (pointer line, copyleft section, verdicts). The
   * document is always written even with failing verdicts — the CI gate is
   * check mode, not generate.
   */
  policyPath?: string;
  /**
   * Base directory for resolving every user-supplied relative path option
   * (--target, --repo-root, --policy, --output, --notices, --cyclonedx,
   * --dump-model). Defaults to the current working directory, so direct CLI
   * invocations resolve relative to cwd. The Taskfile passes the task
   * invocation directory ({{.USER_WORKING_DIR}}): tasks run inside
   * tools/sbomlet (the include `dir`, mandated by the mise bun pin), so
   * without this anchor a `task generate POLICY=.sbomlet.policy.toml` would
   * look for tools/sbomlet/.sbomlet.policy.toml — and a relative CYCLONEDX would
   * silently write (then "verify") the export inside tools/sbomlet. Display
   * surfaces keep the raw path: the policy pointer line in the rendered
   * document must stay deterministic across machines, never embedding an
   * absolute machine-specific path.
   */
  baseDir?: string;
  /**
   * Optional override for the enrichment cache path (--enrichment-cache). When
   * unset it defaults to {@link ENRICHMENT_CACHE_FILE} inside the resolved cache
   * dir ({@link DEFAULT_CACHE_DIR}, or the policy `[cache] dir`).
   */
  enrichmentCachePath?: string;
  /**
   * Optional override for the ScanCode memo path (--scancode-cache), symmetric
   * with --enrichment-cache. When unset it defaults to {@link
   * SCANCODE_CACHE_FILE} inside the resolved cache dir. Threaded through for the
   * ScanCode replay stage to consume; the memo module owns the read/write.
   */
  scancodeCachePath?: string;
  /**
   * Optional override for the committed Docker OS SBOM path (--docker-os-sbom).
   * When unset it defaults to {@link DOCKER_OS_SBOM_FILE} inside the resolved cache
   * dir. When the file exists it is size-gated, parsed, and threaded into the merge
   * as a scope:"os" input (COLL-04); when absent there are no os entries (the
   * offline cache-miss equivalent, never a live docker/syft scan).
   */
  dockerOsSbomPath?: string;
  /**
   * generate may fetch+write the enrichment cache; check NEVER fetches or
   * writes — a miss-needing-enrichment is a stale condition (exit 2), never a
   * network call. buildOutputs stays write-free regardless: the cache write
   * lives inside enrichUnknowns gated on generate mode. runGenerate forces
   * "generate"; runCheck forces "check". Absent defaults to the hermetic
   * "check" so a direct buildOutputs call never silently fetches.
   */
  mode?: "generate" | "check";
  verbose: boolean;
}

/**
 * Everything buildOutputs renders in memory, plus the data check needs to
 * gate on. Optional keys are present only when their input was configured
 * (cyclonedxPath) or loaded (policy), via conditional spread — "absent" stays
 * observable, never undefined-but-present.
 */
export interface BuiltOutputs {
  /** Rendered THIRD_PARTY_LICENSES.md — renderer-owned bytes. */
  licensesMd: string;
  /** Rendered THIRD_PARTY_NOTICES.md companion — always built. */
  noticesMd: string;
  /** CycloneDX 1.6 export — present only when cyclonedxPath is set. */
  cyclonedxJson?: string;
  /**
   * Sorted-key dump JSON: the EvaluatedDependencies (findings + verdicts) on a
   * policy run, the annotated model otherwise.
   */
  dumpJson: string;
  /** Verdict stream — present ONLY when a policy was loaded. */
  verdicts?: Verdict[];
  /** The parsed policy — present ONLY when policyPath was given. */
  policy?: Policy;
  /** Merged package count, for the generate progress line. */
  packageCount: number;
  /**
   * Purls of unknowns the enrichment stage could not satisfy from the committed
   * cache in check mode (no entry, no fetch allowed). Empty in generate mode
   * (generate fetches on a miss). check maps these to stale (exit 2).
   */
  staleUnknowns: string[];
}

/**
 * The write-free pipeline core shared by generate and check: validate policy
 * (when given) -> resolve/discover targets -> per-target dispatch+scan -> one
 * merged model -> unconditional annotation -> evaluate + stderr summary (when
 * a policy is loaded) -> render every configured output in memory. This
 * function never calls writeFileSync — generate writes the returned strings,
 * check byte-compares them against the committed files, so check can never
 * overwrite the files it is gating on.
 */
/**
 * The one-line stderr hint printed when the committed sidecar reads as the
 * aggregate (old or malformed shape) while the policy scopes a compatible rule
 * strictly under docker:os-packages (a bare-prefix scope still matches the
 * aggregate target and needs no hint). The scoped rule can never match the aggregate
 * target (the fail-safe matcher direction), which is safe but confusing right
 * after the user wrote the rule — name the actual cause and the fix.
 */
const SIDECAR_REGENERATE_HINT =
  "docker-os.sbom.json predates per-image attribution — scoped compatible rules cannot match docker occurrences; regenerate via generate-docker-sbom";

/** A sidecar component narrowed to its attribution: non-empty string images. */
interface AttributedSidecarComponent extends Record<string, unknown> {
  images: string[];
}

/** A narrowed v2 sidecar: the parsed doc plus typed components and images. */
interface AttributedSidecar {
  doc: Record<string, unknown>;
  components: AttributedSidecarComponent[];
  images: ReadonlyArray<{ image: string; source: string }>;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/**
 * dockerImages → unique {image, source} entries, or undefined on any flaw: a
 * non-array, a non-object entry, a missing/empty image or source, or a
 * duplicate image name (which would make a membership's source ambiguous).
 */
function narrowSidecarImages(
  value: unknown,
): Array<{ image: string; source: string }> | undefined {
  if (!Array.isArray(value)) return undefined;
  const entries: Array<{ image: string; source: string }> = [];
  const seen = new Set<string>();
  for (const raw of value) {
    if (typeof raw !== "object" || raw === null) return undefined;
    const { image, source } = raw as { image?: unknown; source?: unknown };
    if (!isNonEmptyString(image) || !isNonEmptyString(source)) return undefined;
    if (seen.has(image)) return undefined;
    seen.add(image);
    entries.push({ image, source });
  }
  return entries;
}

/**
 * components → attributed components, or undefined on any flaw: a non-array, a
 * non-object entry, a missing/empty/non-string-array `images`, or a membership
 * naming an image absent from dockerImages. An EMPTY membership is a flaw too —
 * it would drop the component from every fan-out input, and dropped inventory
 * is the one failure the degradation path exists to prevent.
 */
function narrowSidecarComponents(
  value: unknown,
  listed: ReadonlySet<string>,
): AttributedSidecarComponent[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const components: AttributedSidecarComponent[] = [];
  for (const raw of value) {
    if (typeof raw !== "object" || raw === null) return undefined;
    const images = (raw as { images?: unknown }).images;
    if (!Array.isArray(images) || images.length === 0) return undefined;
    const memberships: string[] = [];
    for (const entry of images) {
      if (!isNonEmptyString(entry) || !listed.has(entry)) return undefined;
      memberships.push(entry);
    }
    components.push({
      ...(raw as Record<string, unknown>),
      images: memberships,
    });
  }
  return components;
}

/**
 * All-or-nothing v2 detection (skip-not-throw): the typed sidecar when EVERY
 * component and EVERY dockerImages entry narrows cleanly, undefined otherwise
 * — the caller then takes the aggregate compat path for the WHOLE sidecar,
 * never a partial per-image model. Detection is structural (field presence),
 * not versioned: a component without `images` or an image entry without
 * `source` is the old shape by definition.
 */
function narrowAttributedSidecar(
  parsed: unknown,
): AttributedSidecar | undefined {
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return undefined;
  }
  const doc = parsed as Record<string, unknown>;
  const images = narrowSidecarImages(doc["dockerImages"]);
  if (images === undefined) return undefined;
  const listed = new Set(images.map((entry) => entry.image));
  const components = narrowSidecarComponents(doc["components"], listed);
  if (components === undefined) return undefined;
  return { doc, components, images };
}

/**
 * True when some compatible rule is docker-scoped in a way an aggregate-shape
 * sidecar can never satisfy: at least one `where` entry sits STRICTLY under
 * docker:os-packages while no entry equals the bare aggregate identity. A
 * bare-prefix scope covers the aggregate target itself (the locked matcher
 * direction), so such a rule still matches and needs no hint.
 */
function hasAggregateBlockedCompatible(policy: Policy | undefined): boolean {
  if (policy === undefined) return false;
  return policy.compatible.some((rule) => {
    const where = rule.where ?? [];
    return (
      where.some((path) => path.startsWith(`${DOCKER_OS_IDENTITY}/`)) &&
      !where.includes(DOCKER_OS_IDENTITY)
    );
  });
}

/**
 * Read the committed Docker OS-package SBOM as scope:"os" merge inputs, or
 * undefined when it does not exist (the offline cache-miss equivalent — no os
 * entries, never a live scan). The default path is {@link DOCKER_OS_SBOM_FILE}
 * inside the resolved cache `dir` (repo-root-anchored), so the Action — running
 * from its own directory — reads the consumer repo's committed SBOM, not a stray
 * file beside the action; an explicit --docker-os-sbom overrides it. The file is
 * size-gated BEFORE any read (DoS
 * bound, T-07-04, reusing the collector's assertSyftSbomSize), then parsed. The
 * parse is tolerant: a malformed committed file yields no os entries rather than
 * aborting the whole pipeline (mergeSboms's arktype narrow already skips
 * malformed components; a non-JSON file would throw on JSON.parse, which is the
 * correct loud failure for a tampered committed artifact).
 *
 * A fully well-formed ATTRIBUTED sidecar (v2: every component carries a
 * non-empty `images` membership naming listed images, every dockerImages entry
 * carries a source) FANS OUT to one input per image with targetIdentity
 * "docker:os-packages/" + source, so a purl shared across images gets one
 * occurrence per image through the untouched mergeSboms — exactly like a
 * package shared across two workspaces. Anything less reads as today's single
 * aggregate input: identities derive ONLY from listed sources, degradation is
 * whole-sidecar, and no component is ever dropped. The fan-out iterates the
 * sidecar's stored order (the emitter sorts dockerImages by image), so
 * repeated reads are byte-identical. When the aggregate path is taken while
 * the policy carries a compatible rule the aggregate target cannot satisfy
 * (scoped strictly under docker:os-packages), ONE stderr hint line names the
 * cause; the reader stays a pure read — stderr only, no writes, no exit-code
 * change, no new pipeline state.
 */
function readCommittedDockerOsSbom(
  opts: GenerateOptions,
  dir: string,
  policy: Policy | undefined,
): CollectedSbom[] | undefined {
  const osSbomPath =
    opts.dockerOsSbomPath !== undefined
      ? resolveFrom(
          resolvedRepoRoot(opts) ?? opts.baseDir,
          opts.dockerOsSbomPath,
        )
      : resolveFrom(dir, DOCKER_OS_SBOM_FILE);
  if (!existsSync(osSbomPath)) return undefined;
  // Size gate BEFORE read (DoS bound, T-07-04).
  assertSyftSbomSize(osSbomPath);
  const parsed: unknown = JSON.parse(readFileSync(osSbomPath, "utf8"));
  const attributed = narrowAttributedSidecar(parsed);
  if (attributed === undefined) {
    if (hasAggregateBlockedCompatible(policy)) {
      process.stderr.write(`${SIDECAR_REGENERATE_HINT}\n`);
    }
    return [
      {
        sbom: parsed,
        targetIdentity: DOCKER_OS_IDENTITY,
        scope: "os",
      },
    ];
  }
  return attributed.images.map(({ image, source }) => ({
    sbom: {
      ...attributed.doc,
      components: attributed.components.filter((component) =>
        component.images.includes(image),
      ),
    },
    targetIdentity: `${DOCKER_OS_IDENTITY}/${source}`,
    scope: "os",
  }));
}

/**
 * The policy path as it lands in the committed document's pointer line:
 * repo-root-relative and forward-slash, so the bytes are identical on every
 * checkout and never leak an absolute machine path. (Using the raw --policy value
 * broke determinism when an absolute path was passed — e.g. from the GitHub
 * Action, which must run from its own directory, not the repo root.)
 */
function policyPointerPath(opts: GenerateOptions): string {
  const policyFile = resolveFrom(opts.baseDir, opts.policyPath!);
  const repoRoot = resolvedRepoRoot(opts);
  if (repoRoot === undefined) return basename(policyFile);
  return relative(repoRoot, policyFile).replaceAll("\\", "/");
}

/**
 * The scanned repo's absolute root, or undefined in single-target mode (no
 * --repo-root). Committed artifacts — the cache dir and the policy pointer line —
 * anchor here so they bind to the repo being scanned, not the invocation
 * directory (--base-dir), which diverges for in-process callers and the Action.
 */
function resolvedRepoRoot(opts: GenerateOptions): string | undefined {
  return opts.repoRoot === undefined
    ? undefined
    : resolveFrom(opts.baseDir, opts.repoRoot);
}

/**
 * The resolved cache directory: where tool-generated committed artifacts live
 * (the enrichment cache, the Docker OS SBOM). It anchors to the SCANNED repo
 * (--repo-root; --base-dir in single-target mode), so it binds to the repo being
 * scanned, not the invocation dir — which diverges for in-process callers and the
 * GitHub Action. A policy `[cache] dir` overrides the subdirectory (validated
 * repo-relative, so it can never escape); DEFAULT_CACHE_DIR otherwise.
 */
function cacheDir(opts: GenerateOptions, policy: Policy | undefined): string {
  return resolveFrom(
    resolvedRepoRoot(opts) ?? opts.baseDir,
    policy?.cache?.dir ?? DEFAULT_CACHE_DIR,
  );
}

/**
 * Resolve the cache directory for a caller that has NOT already parsed the policy
 * (verify-cache, generate-docker-sbom). Reads the policy file — when given and
 * present — for its `[cache] dir`, then anchors to the scanned repo exactly as the
 * in-process {@link cacheDir} does. A malformed policy throws PolicyError, the same
 * exit-3 config error the gate raises, so the audit never runs against a half-read
 * policy.
 */
export function resolveCacheDir(opts: {
  baseDir?: string;
  repoRoot?: string;
  policyPath?: string;
}): string {
  const repoRoot =
    opts.repoRoot === undefined
      ? undefined
      : resolveFrom(opts.baseDir, opts.repoRoot);
  let dirSetting: string | undefined;
  if (opts.policyPath !== undefined) {
    const file = resolveFrom(opts.baseDir, opts.policyPath);
    if (existsSync(file)) {
      dirSetting = parsePolicy(readFileSync(file, "utf8")).cache?.dir;
    }
  }
  return resolveFrom(repoRoot ?? opts.baseDir, dirSetting ?? DEFAULT_CACHE_DIR);
}

/**
 * The committed enrichment cache path: {@link ENRICHMENT_CACHE_FILE} inside the
 * cache `dir`, unless --enrichment-cache overrides it (resolved against the repo
 * root, as before). check reads it offline; generate may write it on a miss.
 */
function enrichmentCachePath(opts: GenerateOptions, dir: string): string {
  return opts.enrichmentCachePath !== undefined
    ? resolveFrom(
        resolvedRepoRoot(opts) ?? opts.baseDir,
        opts.enrichmentCachePath,
      )
    : resolveFrom(dir, ENRICHMENT_CACHE_FILE);
}

/**
 * The committed ScanCode memo path: {@link SCANCODE_CACHE_FILE} inside the cache
 * `dir`, unless --scancode-cache overrides it (resolved against the repo root,
 * symmetric with the enrichment cache path). Exported for direct testing and for
 * the ScanCode replay stage — buildOutputs threads it into assessPackages.
 */
export function scancodeCachePath(opts: GenerateOptions, dir: string): string {
  return opts.scancodeCachePath !== undefined
    ? resolveFrom(
        resolvedRepoRoot(opts) ?? opts.baseDir,
        opts.scancodeCachePath,
      )
    : resolveFrom(dir, SCANCODE_CACHE_FILE);
}

/**
 * Construct {@link IntensiveOptions} for the enrichUnknowns call — ONLY when
 * mode is "generate" AND opts.intensive is true (D-07's opt-in boundary,
 * SCAN-03): check never reaches this function with mode "generate" (runCheck
 * forces "check"), and a default generate call has opts.intensive absent, so
 * the common case returns undefined and the intensive lane is never even
 * constructed, let alone invoked. targetDirs comes from the SAME collect loop
 * this run already walked — never a fresh discovery — so the assessment
 * scan's candidate roots can never drift from what generate actually scanned.
 */
function intensiveOptionsFor(
  mode: "generate" | "check",
  opts: GenerateOptions,
  targetDirs: string[],
): IntensiveOptions | undefined {
  if (mode !== "generate" || opts.intensive !== true) return undefined;
  return { targetDirs };
}

/**
 * Project the PolicyView the document renderer consumes. The policy pointer path
 * is repo-root-relative (policyPointerPath) so the committed bytes stay stable
 * across platforms. 07-09: the author-supplied [document] title + preamble flow
 * into the licenses-document renderer only (never the notices companion), via
 * conditional spread so "absent" stays observable.
 */
function projectPolicyView(
  policy: Policy,
  policyPath: string,
  verdicts: ReadonlyArray<Verdict>,
): PolicyView {
  return {
    policyPath,
    suppressedWorkspaces: policy.suppressedWorkspaces,
    verdicts,
    ...(policy.document !== undefined ? { document: policy.document } : {}),
  };
}

export async function buildOutputs(
  opts: GenerateOptions,
): Promise<BuiltOutputs> {
  // Load + validate the policy before any target resolution or scan: an
  // invalid policy must abort through the exit-3 config-error path
  // immediately, never after minutes of scanning. TomlError (caret-annotated
  // syntax message) and PolicyError (aggregated table-path problems) propagate
  // verbatim to main()'s catch → fail().
  let policy: Policy | undefined;
  if (opts.policyPath !== undefined) {
    // Read from the base-dir-resolved path and name the resolved absolute path
    // on failure — a relative path in the error would read as repo-root-
    // relative while the file was searched elsewhere.
    const policyFile = resolveFrom(opts.baseDir, opts.policyPath);
    let policyText: string;
    try {
      policyText = readFileSync(policyFile, "utf8");
    } catch {
      // ENOENT and friends → the target.ts error idiom naming the path.
      throw new Error(
        `policy file is missing or unreadable: expected ${policyFile}`,
      );
    }
    policy = parsePolicy(policyText);
  }

  // The committed-artifact directory (the enrichment cache + Docker OS SBOM),
  // resolved once from the parsed policy's `[cache] dir` (or the default) so the
  // cache read and the Docker-SBOM read below agree on one location.
  const dir = cacheDir(opts, policy);

  // The collect loop owns the per-target stderr lines; the sink is provided
  // here so the pipeline stays the single place wiring stderr.
  const { inputs, targetDirs } = await collectTargets(opts, (line): void => {
    process.stderr.write(`${line}\n`);
  });

  // COLL-04/SCP-02: thread the committed Docker OS-package SBOM into the merge
  // when it exists — one scope:"os" input per attributed image (v2 fan-out) or
  // the single aggregate input (old/malformed shape). A missing file is the
  // offline cache-miss equivalent — no os entries, no docker, no syft.
  const osInputs = readCommittedDockerOsSbom(opts, dir, policy);
  if (osInputs !== undefined) inputs.push(...osInputs);

  // One merged model from all targets: shared packages appear once with every
  // consumer in their occurrences.
  const model = mergeSboms(inputs);

  // ENRICH stage — runs BEFORE annotate so an appended source:"registry" claim
  // flows through the SAME normalizeRaw as a generator claim (one SPDX path),
  // and clarify > registry > generator precedence holds for free. generate may
  // fetch on a cache miss and write the committed cache; check NEVER fetches or
  // writes — a miss-needing-enrichment surfaces as a stale unknown (exit 2).
  const mode = opts.mode ?? "check";
  const intensive = intensiveOptionsFor(mode, opts, targetDirs);
  const { model: enriched, staleUnknowns } = await enrichUnknowns(model, {
    mode,
    cachePath: enrichmentCachePath(opts, dir),
    verbose: opts.verbose,
  });

  // ScanCode ASSESSMENT stage — a peer stage, not a subordinate lane inside
  // enrichUnknowns. It runs AFTER registry enrichment so that, for each
  // package, both the quick-check answer and the in-depth answer exist: the
  // registry lane keeps its own cache/negative semantics untouched, and
  // conflicts stay detectable downstream. It replays the committed ScanCode
  // memo for EVERY package in both modes and, under generate --intensive only,
  // analyzes the full package set. Consciously accepted: a package whose ONLY
  // answer is a memoized ScanCode claim is still registry-fetched on the next
  // generate (it is zero-claim entering this stage) — desired, because both
  // assessments must exist for a disagreement to surface.
  const { model: assessed } = await assessPackages(enriched, {
    mode,
    memoPath: scancodeCachePath(opts, dir),
    verbose: opts.verbose,
    ...(intensive !== undefined ? { intensive } : {}),
  });

  // Normalization runs unconditionally: annotateFindings with an empty clarify
  // list when no policy is loaded, so the License column shows normalized
  // expressions and the notices appendix can decompose them without --policy.
  // The no-policy dump equals the annotated model. The shipped tool-level
  // BUILTIN_OVERRIDES set is always threaded in (POL-07): it is imported config
  // (pure — no I/O in the engine), staleness-guarded, and project [[clarify]]
  // wins over it on conflict.
  const { model: annotated, usedClarifyIndices } = annotateFindings(
    assessed,
    policy?.clarify ?? [],
    BUILTIN_OVERRIDES,
  );

  // Policy stage: pure engine calls — evaluate verdicts, surface the summary
  // on stderr, and project the PolicyView for the document renderer. Policy-
  // authored strings reaching the .md route through escapeCell inside the
  // renderers.
  let verdicts: Verdict[] | undefined;
  let policyView: PolicyView | undefined;
  if (policy !== undefined && opts.policyPath !== undefined) {
    verdicts = evaluate(annotated, policy);
    writePolicySummary(policy, verdicts, usedClarifyIndices);
    policyView = projectPolicyView(policy, policyPointerPath(opts), verdicts);
  }

  // Dump surface: with a policy run the dump is the EvaluatedDependencies
  // (findings + verdicts); without one it is the annotated model.
  const evaluated: EvaluatedDependencies | undefined =
    verdicts === undefined
      ? undefined
      : { packages: annotated.packages, verdicts };
  const dumpJson = toSortedDependenciesJson(evaluated ?? annotated);

  return {
    licensesMd: alignTables(renderMarkdown(annotated, policyView)),
    noticesMd: renderNotices(annotated),
    ...(opts.cyclonedxPath !== undefined
      ? { cyclonedxJson: renderCyclonedx(annotated, verdicts) }
      : {}),
    dumpJson,
    ...(verdicts !== undefined ? { verdicts } : {}),
    ...(policy !== undefined ? { policy } : {}),
    packageCount: annotated.packages.length,
    staleUnknowns,
  };
}

/**
 * generate = buildOutputs + the only writeFileSync calls in the
 * cli/pipeline/gate trio: the licenses document, the notices companion
 * (always), the CycloneDX export when configured, and the optional dump-model
 * JSON, each written verbatim with one "wrote" stderr line per rendered
 * document. Returns the rendered licenses markdown so tests can reuse it
 * directly (the e2e double-generate test compares two returned strings
 * byte-for-byte).
 */
export async function runGenerate(opts: GenerateOptions): Promise<string> {
  // generate is the only mode allowed to fetch + write the enrichment cache.
  const outputs = await buildOutputs({ ...opts, mode: "generate" });

  // Every write path anchors to --base-dir: the stderr "wrote" lines name the
  // resolved paths so the user sees where the files landed.
  if (opts.dumpModelPath !== undefined) {
    // Sorted-key JSON debug surface for golden-file tests.
    writeFileSync(
      resolveFrom(opts.baseDir, opts.dumpModelPath),
      outputs.dumpJson,
    );
  }

  // Write the exact rendered strings — the renderers own the bytes.
  const outputPath = resolveFrom(opts.baseDir, opts.outputPath);
  writeFileSync(outputPath, outputs.licensesMd);
  process.stderr.write(
    `wrote ${sanitizeForLog(outputPath)} (${outputs.packageCount} packages)\n`,
  );
  const noticesPath = resolveFrom(opts.baseDir, opts.noticesPath);
  writeFileSync(noticesPath, outputs.noticesMd);
  process.stderr.write(`wrote ${sanitizeForLog(noticesPath)}\n`);
  if (opts.cyclonedxPath !== undefined && outputs.cyclonedxJson !== undefined) {
    const cyclonedxPath = resolveFrom(opts.baseDir, opts.cyclonedxPath);
    writeFileSync(cyclonedxPath, outputs.cyclonedxJson);
    process.stderr.write(`wrote ${sanitizeForLog(cyclonedxPath)}\n`);
  }
  return outputs.licensesMd;
}
