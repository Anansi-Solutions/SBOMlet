/**
 * The write-free pipeline core shared by generate and check: buildOutputs
 * renders everything in memory and never writes; runGenerate holds the only
 * writeFileSync calls, so check can never overwrite the files it gates on.
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { basename, relative } from "node:path";

import { assertSyftSbomSize } from "../collectors/dockerOs";
import { enrichUnknowns } from "../enrich/enrich";
import { mergeSboms, type CollectedSbom } from "../merge/merge";
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
 * The committed Docker OS-package SBOM filename inside the cache dir (COLL-04):
 * 07-01's deterministic emitter output, committed and consumed as a scope:"os"
 * MERGE INPUT, never scanned per-run. A MISSING file is the enrichment-cache-miss
 * equivalent (NO os entries, NO docker, NO syft, fully offline). The live scan that
 * POPULATES it is the dedicated generate-docker-sbom subcommand; generate and check
 * read the same committed bytes, so determinism is trivial.
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
   * without this anchor a `task generate POLICY=.sbomlet.toml` would
   * look for tools/sbomlet/.sbomlet.toml — and a relative CYCLONEDX would
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
 * Read the committed Docker OS-package SBOM as a scope:"os" merge input, or
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
 */
function readCommittedDockerOsSbom(
  opts: GenerateOptions,
  dir: string,
): CollectedSbom | undefined {
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
  return {
    sbom: parsed,
    targetIdentity: "docker:os-packages",
    scope: "os",
  };
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
  const inputs: CollectedSbom[] = await collectTargets(opts, (line): void => {
    process.stderr.write(`${line}\n`);
  });

  // COLL-04: thread the committed Docker OS-package SBOM (07-01's emitter
  // output) into the merge as a scope:"os" input when it exists. A missing file
  // is the offline cache-miss equivalent — no os entries, no docker, no syft.
  const osInput = readCommittedDockerOsSbom(opts, dir);
  if (osInput !== undefined) inputs.push(osInput);

  // One merged model from all targets: shared packages appear once with every
  // consumer in their occurrences.
  const model = mergeSboms(inputs);

  // ENRICH stage — runs BEFORE annotate so an appended source:"registry" claim
  // flows through the SAME normalizeRaw as a generator claim (one SPDX path),
  // and clarify > registry > generator precedence holds for free. generate may
  // fetch on a cache miss and write the committed cache; check NEVER fetches or
  // writes — a miss-needing-enrichment surfaces as a stale unknown (exit 2).
  const mode = opts.mode ?? "check";
  const { model: enriched, staleUnknowns } = await enrichUnknowns(model, {
    mode,
    cachePath: enrichmentCachePath(opts, dir),
    verbose: opts.verbose,
  });

  // Normalization runs unconditionally: annotateFindings with an empty clarify
  // list when no policy is loaded, so the License column shows normalized
  // expressions and the notices appendix can decompose them without --policy.
  // The no-policy dump equals the annotated model. The shipped tool-level
  // BUILTIN_OVERRIDES set is always threaded in (POL-07): it is imported config
  // (pure — no I/O in the engine), staleness-guarded, and project [[clarify]]
  // wins over it on conflict.
  const { model: annotated, usedClarifyIndices } = annotateFindings(
    enriched,
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
