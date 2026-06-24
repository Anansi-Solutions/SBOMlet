/**
 * The write-free pipeline core shared by generate and check: buildOutputs
 * renders everything in memory and never writes; runGenerate holds the only
 * writeFileSync calls, so check can never overwrite the files it gates on.
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";

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
import { renderCyclonedx } from "../render/cyclonedx";
import { renderMarkdown, type PolicyView } from "../render/markdown";
import { renderNotices } from "../render/notices";
import { resolveFrom } from "./paths";
import { sanitizeForLog, writePolicySummary } from "./summary";
import { collectTargets } from "./targets";

/**
 * The committed enrichment cache filename, resolved against --base-dir like
 * every other relative path (resolveFrom(opts.baseDir, ...)). The Taskfile sets
 * --base-dir to the INVOCATION directory (USER_WORKING_DIR), so for the
 * dogfood run the cache resolves to the REPO ROOT
 * (`<repo-root>/enrichment-cache.json`, committed, NOT gitignored) — NOT to
 * tools/licenses. That repo-root cache is the canonical one `check` reads to
 * regenerate fully offline. (There is no tool-root cache: a stale
 * tools/licenses/enrichment-cache.json was a pre-dogfood orphan, deleted in
 * 06-06 — I#5/#7.)
 */
export const DEFAULT_ENRICHMENT_CACHE = "enrichment-cache.json";

/**
 * The committed Docker OS-package SBOM filename (COLL-04), resolved against
 * --base-dir exactly like {@link DEFAULT_ENRICHMENT_CACHE}. It is 07-01's
 * deterministic emitter output, committed at the repo root and consumed here as
 * a scope:"os" MERGE INPUT — never scanned per-run. A MISSING file is the
 * enrichment-cache-miss equivalent: NO os entries, NO docker, NO syft, fully
 * offline. The live scan that POPULATES this file is the dedicated 07-03
 * subcommand; both generate and check read the same committed bytes, so
 * determinism is trivial.
 */
const DEFAULT_DOCKER_OS_SBOM = "docker-os-sbom.json";

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
   * tools/licenses (the include `dir`, mandated by the mise bun pin), so
   * without this anchor a `task licenses:generate POLICY=policy.toml` would
   * look for tools/licenses/policy.toml — and a relative CYCLONEDX would
   * silently write (then "verify") the export inside tools/licenses. Display
   * surfaces keep the raw path: the policy pointer line in the rendered
   * document must stay deterministic across machines, never embedding an
   * absolute machine-specific path.
   */
  baseDir?: string;
  /**
   * The committed enrichment cache path (base-dir-resolved). Defaults to
   * {@link DEFAULT_ENRICHMENT_CACHE} at the base dir; overridable via
   * --enrichment-cache.
   */
  enrichmentCachePath?: string;
  /**
   * The committed Docker OS-package SBOM path (base-dir-resolved). Defaults to
   * {@link DEFAULT_DOCKER_OS_SBOM} at the base dir. When the file exists it is
   * size-gated, parsed, and threaded into the merge as a scope:"os" input
   * (COLL-04); when absent there are no os entries (the offline cache-miss
   * equivalent — never a live docker/syft scan).
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
 * entries, never a live scan). The file is size-gated BEFORE any read (DoS
 * bound, T-07-04, reusing the collector's assertSyftSbomSize), then parsed. The
 * parse is tolerant: a malformed committed file yields no os entries rather than
 * aborting the whole pipeline (mergeSboms's arktype narrow already skips
 * malformed components; a non-JSON file would throw on JSON.parse, which is the
 * correct loud failure for a tampered committed artifact).
 */
function readCommittedDockerOsSbom(
  opts: GenerateOptions,
): CollectedSbom | undefined {
  const osSbomPath = resolveFrom(
    opts.baseDir,
    opts.dockerOsSbomPath ?? DEFAULT_DOCKER_OS_SBOM,
  );
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
 * Project the PolicyView the document renderer consumes. The raw user-supplied
 * policyPath is used verbatim (never the base-dir-resolved one): the pointer
 * line lands in the committed document, and an absolute machine-specific path
 * would make the bytes differ per checkout. 07-09: the author-supplied
 * [document] title + preamble flow into the licenses-document renderer only
 * (never the notices companion), via conditional spread so "absent" stays
 * observable.
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

  // The collect loop owns the per-target stderr lines; the sink is provided
  // here so the pipeline stays the single place wiring stderr.
  const inputs: CollectedSbom[] = await collectTargets(opts, (line): void => {
    process.stderr.write(`${line}\n`);
  });

  // COLL-04: thread the committed Docker OS-package SBOM (07-01's emitter
  // output) into the merge as a scope:"os" input when it exists. A missing file
  // is the offline cache-miss equivalent — no os entries, no docker, no syft.
  const osInput = readCommittedDockerOsSbom(opts);
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
    cachePath: resolveFrom(
      opts.baseDir,
      opts.enrichmentCachePath ?? DEFAULT_ENRICHMENT_CACHE,
    ),
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
    policyView = projectPolicyView(policy, opts.policyPath, verdicts);
  }

  // Dump surface: with a policy run the dump is the EvaluatedDependencies
  // (findings + verdicts); without one it is the annotated model.
  const evaluated: EvaluatedDependencies | undefined =
    verdicts === undefined
      ? undefined
      : { packages: annotated.packages, verdicts };
  const dumpJson = toSortedDependenciesJson(evaluated ?? annotated);

  return {
    licensesMd: renderMarkdown(annotated, policyView),
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
