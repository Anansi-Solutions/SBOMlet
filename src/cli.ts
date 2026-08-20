/**
 * Single CLI entry point: `generate` and `check` subcommands parsed with node:util parseArgs - no
 * CLI framework (dependency-footprint constraint). This module is the only place that owns process
 * exit codes.
 *
 * Generate modes:
 * - `--repo-root <path>` (default: cwd) - discovery mode: every lockfile target under the root is
 *   scanned sequentially in sorted identity order and folded into one merged document.
 * - `--target <path>` - single-target debugging; flows through the same dispatch loop, so a Yarn-4
 *   target produces identical rows either way.
 * - `--exclude <glob>` - repeatable; matched against target identities.
 * - `--policy <path>` - optional TOML policy: validated before any scan (fail-fast), verdicts
 *   surfaced on stderr, in the dump-model output, and in the rendered PolicyView document; the
 *   document is always written whatever the verdicts say - the CI gate is check, never generate.
 * - `--notices <path>` - the THIRD_PARTY_NOTICES.md companion is always written; defaults to
 *   THIRD_PARTY_NOTICES.md beside the output.
 * - `--cyclonedx <path>` - optional CycloneDX 1.6 export.
 *
 * Architecture: the write-free pipeline core lives in src/pipeline/ (buildOutputs renders in
 * memory; runGenerate holds the only file-write calls in the cli/pipeline/gate trio); the check
 * comparison and its exit mapping live in src/gate/check.ts.
 *
 * Exit-code taxonomy:
 *   0 success / check clean 1 check: at least one policy fail verdict (priority over stale). Warn
 *      verdicts and unused-policy-entry warnings print but never gate - only fail verdicts reach
 *      this code.
 *   2 check: at least one stale or missing committed output 3 tool/config error (>2): unknown
 *   subcommand, conflicting flags, pipeline
 *      failure, coverage assertion, invalid policy file (TomlError/PolicyError messages printed
 *      verbatim), --dump-model on check. Codes 1 and 2 come only from check's structured-result
 *      mapping - exceptions can never surface as 0/1/2.
 *   refresh-clarifications reads the same way as check's 0/1: 0 nothing to suggest, 1 suggestions
 *      exist or were applied, 3 a config error or a write it refused to make.
 */

import { existsSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";

import { runGenerateDockerSbom, type GenerateDockerSbomOptions } from "./pipeline/dockerSbom";
import { exitCodeFor, runCheck, type CheckResult } from "./gate/check";
import { defaultNoticesPath, resolveFrom } from "./pipeline/paths";
import { runGenerate, type GenerateOptions } from "./pipeline/pipeline";
import {
  runRefreshClarifications,
  type RefreshClarificationsResult,
} from "./pipeline/refreshClarifications";
import { sanitizeForLog } from "./pipeline/summary";
import { suggestionCount } from "./maintain/refreshClarifications";
import { runVerifyCache, type VerifyCacheResult } from "./pipeline/verifyCache";

const USAGE =
  "usage: sbomlet <generate|check|verify-cache|refresh-clarifications|" +
  "generate-docker-sbom> [options]\n" +
  "  generate [--repo-root <path> | --target <path>] [--exclude <glob>]... " +
  "[--policy <path>] [--output <path>] [--notices <path>] " +
  "[--cyclonedx <path>] [--dump-model <path>] [--base-dir <path>] " +
  "[--enrichment-cache <path>] [--scancode-cache <path>] [--intensive] " +
  "[--package-timeout-mins <minutes>] [--verbose]\n" +
  "           --intensive: assess the FULL package set with ScanCode, an " +
  "in-depth source scan that outranks the registry answer where present and " +
  "flags any disagreement as a conflict to resolve; skips versions already " +
  "in the memo and packages whose sources are not locally present (generate-" +
  "only; meant for occasional runs, not the default fast path). A per-package " +
  "scan that times out or otherwise fails is skipped and reported, never " +
  "aborting the rest of the run, and is retried on the next scan.\n" +
  "           --package-timeout-mins <minutes>: per-package wall-clock limit " +
  "for each ScanCode invocation under --intensive (default: 10).\n" +
  "  check    same flags as generate (minus --dump-model, minus --intensive) — regenerates in " +
  "memory and byte-compares every configured output; writes nothing\n" +
  "           exit codes: 0 clean, 1 policy violation (beats stale), " +
  "2 stale/missing output, 3+ tool/config error (warns print, never gate)\n" +
  "  verify-cache [--enrichment-cache <path>] [--base-dir <path>] [--verbose]\n" +
  "           ONLINE integrity audit — re-resolves every committed " +
  "enrichment-cache entry against its registry and reports any divergence from " +
  "the stored license (run before a release/audit, or when the cache changes).\n" +
  "           exit codes: 0 all match, 1 at least one mismatch, 3 tool/network " +
  "error\n" +
  "  refresh-clarifications [--repo-root <path>] [--target <path>] " +
  "[--policy <path>] [--write] " +
  "[--base-dir <path>] [--enrichment-cache <path>] [--scancode-cache <path>] " +
  "[--verbose]\n" +
  "           OFFLINE maintainer audit of the [[clarify]] entries — versions an " +
  "entry could be extended to, entries nothing needs any more, and imported " +
  "entries a policy entry decides ahead of. It reads the committed caches only, " +
  "so a version they say nothing about is reported unknown, never fetched (run " +
  "generate, or generate --intensive, to record one).\n" +
  "           --write: apply the removals and the version extensions to the " +
  "clarifications file the policy declares, and to nothing else — the policy " +
  "proper is only ever suggested against, and a pinned version never leaves.\n" +
  "           exit codes: 0 nothing to suggest, 1 suggestions exist or were " +
  "applied, 3 tool/config error or a refused write\n" +
  "  generate-docker-sbom (--dockerfile <path>... | " +
  "--repo-root <dir> [--policy <file>] [--exclude <glob>]... | " +
  "--image <ref>... | --list-dockerfiles --repo-root <dir>) " +
  "[--docker-sbom <path>] [--base-dir <path>] [--verbose]\n" +
  "           Writes the committed docker.sbom.json. MAINTAINER-ONLY, " +
  "REQUIRES A DOCKER DAEMON. THREE mutually exclusive lanes:\n" +
  "           --dockerfile <path>...: build each explicitly named Dockerfile " +
  "to a deterministic tag, then scan the built image (full contents).\n" +
  "           --repo-root <dir>: discover the repo's Dockerfiles (policy-aware, " +
  "[docker] ignore + --exclude honored), build each, then scan.\n" +
  "           --image <ref>...: scan pre-existing image refs with the pinned " +
  "syft, pulling any ref that is absent locally and digest-pinning each.\n" +
  "           --list-dockerfiles --repo-root <dir>: print the discovered " +
  "Dockerfile paths (policy-aware) one per line and exit — scans nothing, " +
  "writes nothing; the Docker-scan workflow's default build set.\n" +
  "           generate/check NEVER touch docker — they read the committed bytes " +
  "this writes (offline contract).\n";

function fail(message: string): never {
  process.stderr.write(message);
  process.exit(3);
}

/**
 * Print the cache-integrity audit to stderr (the tool's message channel; the exit code is the
 * machine signal). Each mismatch names the purl, the committed value, the registry's current
 * answer, and why they diverge. Always closes with the ScanCode memo line: like the audited-entry
 * count above, it reports its count unconditionally (0 included) rather than appearing/disappearing
 * with the memo's existence: an empty and an absent memo mean the same thing to a reader here.
 */
export function reportVerifyCache(result: VerifyCacheResult): void {
  const line = (text: string): void => {
    process.stderr.write(`${text}\n`);
  };
  const noun = result.audited === 1 ? "entry" : "entries";

  if (result.mismatches.length === 0) {
    line(
      `verify-cache: audited ${result.audited} cache ${noun} — ` +
        `all audited entries match upstream`,
    );
  } else {
    for (const mismatch of result.mismatches) {
      line(`MISMATCH  ${mismatch.purl}`);
      line(`  committed: ${mismatch.cached ?? "(none)"}`);
      line(`  registry:  ${mismatch.current ?? "(none)"}`);
      line(`  ${mismatch.reason}`);
    }

    const verb = result.mismatches.length === 1 ? "diverges from" : "diverge from";

    line(
      `verify-cache: ${result.mismatches.length} of ${result.audited} audited cache ${noun} ` +
        `${verb} upstream — investigate before release`,
    );
  }

  const memoNoun = result.scancodeMemoEntries === 1 ? "entry" : "entries";

  line(
    `scancode memo: ${result.scancodeMemoEntries} ${memoNoun} ` +
      `(not audited: local scan results have no upstream to verify against)`,
  );
}

/** "1 entry" / "2 entries" - a count with the noun it belongs to, never a bare "1 entries". */
function counted(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}

/** The closing line: what was written, or what is left for a person and where to apply it. */
function refreshSummary(result: RefreshClarificationsResult): string {
  const lead = "refresh-clarifications:";

  if (result.refused !== undefined) {
    return `${lead} nothing written — ${result.refused}`;
  }

  if (result.applied !== undefined) {
    return (
      `${lead} rewrote ${result.clarificationsPath} — ` +
      `${counted(result.applied.removed.length, "entry", "entries")} removed, ` +
      `${counted(result.applied.extended.length, "entry", "entries")} extended`
    );
  }

  const total = suggestionCount(result.findings);

  if (total === 0) {
    return `${lead} nothing to suggest`;
  }

  const suggestions = counted(total, "suggestion", "suggestions");

  if (result.writeRequested) {
    return `${lead} ${suggestions}, none of them applicable without a person`;
  }

  return result.clarificationsPath === undefined
    ? `${lead} ${suggestions} — the policy holds its own entries, which are never rewritten; ` +
        `apply these by hand`
    : `${lead} ${suggestions} — --write applies the removals and the version extensions in ` +
        `${result.clarificationsPath}`;
}

/**
 * Print the maintainer audit to stderr (the tool's message channel; the exit code is the machine
 * signal). Each row leads with what it is and the entry's citation, then the finding underneath, in
 * the deterministic order the lanes produced. Every value is policy- or model-derived, so it routes
 * through sanitizeForLog exactly as the policy summary's lines do.
 */
export function reportRefreshClarifications(result: RefreshClarificationsResult): void {
  const heading = (tag: string, text: string): void => {
    process.stderr.write(`${tag.padEnd(8)} ${sanitizeForLog(text)}\n`);
  };
  const detail = (text: string): void => {
    process.stderr.write(`  ${sanitizeForLog(text)}\n`);
  };

  for (const row of result.findings.upgrades) {
    heading(row.outcome.toUpperCase(), `${row.rule}  ${row.name}@${row.version}`);
    detail(row.detail);
  }

  for (const id of result.findings.unused) {
    heading("UNUSED", id);
    detail("decided nothing in this scan — remove it once its package is gone for good");
  }

  for (const entry of result.findings.unnecessary) {
    heading("FINISHED", entry.rule);
    detail(entry.reason);
  }

  for (const pair of result.findings.shadowed) {
    heading("SHADOWED", pair.shadowed);
    detail(`${pair.shadowing} decides ahead of it`);
  }

  process.stderr.write(`${sanitizeForLog(refreshSummary(result))}\n`);
}

/**
 * A run that could not do what it was asked is a tool error; otherwise the exit code says only
 * whether anything needs a maintainer, which is what a script wants to branch on.
 */
export function exitCodeForRefresh(result: RefreshClarificationsResult): number {
  if (result.refused !== undefined) {
    return 3;
  }

  return suggestionCount(result.findings) === 0 ? 0 : 1;
}

/** The parseArgs value shape every subcommand reads its flags out of. */
interface CliValues {
  target?: string;
  "repo-root"?: string;
  exclude?: string[];
  policy?: string;
  output?: string;
  notices?: string;
  cyclonedx?: string;
  "dump-model"?: string;
  "base-dir"?: string;
  "enrichment-cache"?: string;
  /**
   * Optional override for the ScanCode memo path (--scancode-cache), symmetric
   * with --enrichment-cache. Threaded into GenerateOptions.scancodeCachePath;
   * check reads it exactly as generate does (both go through optionsFrom).
   */
  "scancode-cache"?: string;
  verbose?: boolean;
  /** Repeatable --image refs for generate-docker-sbom (the image lane). */
  image?: string[];
  /**
   * Repeatable --dockerfile paths for generate-docker-sbom (the targeted build lane): build the
   * shipped image of each named Dockerfile and scan it. Base-dir-resolved.
   */
  dockerfile?: string[];
  /** generate-docker-sbom output path; base-dir-resolved like every artifact. */
  "docker-sbom"?: string;
  /**
   * generate-docker-sbom --list-dockerfiles: print the tool policy-aware discovered Dockerfile
   * identities to stdout, one per line, and exit -- scans nothing, writes nothing. Requires
   * --repo-root.
   */
  "list-dockerfiles"?: boolean;
  /**
   * generate --intensive: opt-in ScanCode assessment over the FULL package set - the in-depth
   * source scan that outranks the registry answer where present, memo-gated so an already-analysed
   * version is never re-scanned. GENERATE-ONLY - check rejects it outright (gate/check.ts). No
   * `default` here: absent must stay absent, never coerced to false, so optionsFrom's own-property
   * spread can gate the intensive lane on mere presence.
   */
  intensive?: boolean;
  /**
   * generate --intensive's per-package wall-clock timeout, in MINUTES (the CLI's unit; converted to
   * milliseconds in optionsFrom for GenerateOptions.packageTimeoutMs, matching
   * IntensiveOptions.timeoutMs / DEFAULT_SCAN_TIMEOUT_MS internally). Minutes, not milliseconds, to
   * match this repo's own `timeout-minutes` convention (intensive-scan.yml) rather than exposing an
   * internal millisecond unit at the operator boundary. Named for the operator's mental model
   * (running an intensive scan of packages), not the scanner behind it. Inert without --intensive:
   * check never scans, so passing it there is accepted but unread.
   */
  "package-timeout-mins"?: string;
  /**
   * refresh-clarifications --write: apply what the run ascertained to the clarifications file the
   * policy declares. Inert on every other subcommand.
   */
  write?: boolean;
}

/**
 * The recommended default policy file. When --policy is omitted, a .sbomlet.policy.toml at the repo
 * root is adopted automatically; an absent default is silently skipped (no policy means no gate).
 * An explicit --policy always wins, and errors if its file is missing. The anchor is the repo root
 * (not --base-dir), so the default is found in the scanned repo, including from the GitHub Action,
 * which runs from its own directory.
 */
const DEFAULT_POLICY = ".sbomlet.policy.toml";

function discoverDefaultPolicy(values: CliValues): string | undefined {
  const anchor = resolveFrom(values["base-dir"], values["repo-root"] ?? ".");
  const candidate = resolveFrom(anchor, DEFAULT_POLICY);

  return existsSync(candidate) ? candidate : undefined;
}

/**
 * Parse --package-timeout-mins's minutes string into milliseconds, or undefined when the flag is
 * absent - own-property-gated the same way --intensive is, so a default generate never sets
 * GenerateOptions.packageTimeoutMs and the tool default (DEFAULT_SCAN_TIMEOUT_MS) applies
 * untouched. A non-positive or unparseable value is a config error (exit 3), same posture as the
 * mutually-exclusive-flags check above - caught before any target resolution or scan, never a
 * confusing failure minutes into a scan.
 */
function parsePackageTimeoutMs(raw: string | undefined): number | undefined {
  if (raw === undefined) {
    return undefined;
  }

  const minutes = Number(raw);

  if (!Number.isFinite(minutes) || minutes <= 0) {
    fail(
      `--package-timeout-mins must be a positive number of minutes, got ${JSON.stringify(raw)}\n${USAGE}`,
    );
  }

  return minutes * 60_000;
}

/**
 * Validate the shared flag constraints and assemble the pipeline options - generate and check parse
 * the same flags, so the comparison set is exactly the configured output set.
 */
export function optionsFrom(values: CliValues): GenerateOptions {
  if (values.target !== undefined && values["repo-root"] !== undefined) {
    fail(`--target and --repo-root are mutually exclusive — pass at most one\n${USAGE}`);
  }

  const outputPath = values.output ?? "THIRD_PARTY_LICENSES.md";
  const packageTimeoutMs = parsePackageTimeoutMs(values["package-timeout-mins"]);

  return {
    targetArg: values.target,
    repoRoot: values["repo-root"],
    excludes: values.exclude,
    outputPath,
    noticesPath: values.notices ?? defaultNoticesPath(outputPath),
    cyclonedxPath: values.cyclonedx,
    dumpModelPath: values["dump-model"],
    policyPath: values.policy ?? discoverDefaultPolicy(values),
    baseDir: values["base-dir"],
    enrichmentCachePath: values["enrichment-cache"],
    scancodeCachePath: values["scancode-cache"],
    verbose: values.verbose ?? false,
    // Absent-not-false: own-property spread so a default generate never sets this key at all, and
    // check's runCheck rejection reads opts.intensive === true, never a coerced false.
    ...(values.intensive === true ? { intensive: true } : {}),
    ...(packageTimeoutMs !== undefined ? { packageTimeoutMs } : {}),
  };
}

/**
 * Compute the first generate-docker-sbom mode-conflict message, or undefined when the requested
 * lane combination is valid. THE THREE LANES ARE PAIRWISE MUTUALLY EXCLUSIVE: exactly one of
 * --dockerfile (build named Dockerfiles) / --repo-root (discover + build) / --image (scan
 * pre-existing images). --list-dockerfiles is discovery-listing support: it never combines with a
 * build/scan lane and REQUIRES --repo-root (the walk root the listing reads). A bare invocation
 * - no lane, no listing - is a usage error naming the three lanes: there is no default image set.
 * Pair checks are walked as a table rather than an if-ladder to keep this function under the
 * complexity bound. Extracted from dockerSbomOptionsFrom to keep that function under the complexity
 * bound.
 */
export function dockerSbomModeConflict(values: CliValues): string | undefined {
  const hasImage = values.image !== undefined && values.image.length > 0;
  const hasRepoRoot = values["repo-root"] !== undefined;
  const hasDockerfile = values.dockerfile !== undefined && values.dockerfile.length > 0;
  const hasListDockerfiles = values["list-dockerfiles"] === true;
  const pairs: Array<[boolean, boolean, string]> = [
    // --list-dockerfiles never combines with a build/scan lane (checked first so the message names
    // --list-dockerfiles even when --repo-root is also set as its required walk root).
    [hasListDockerfiles, hasImage, "--list-dockerfiles and --image are mutually exclusive"],
    [
      hasListDockerfiles,
      hasDockerfile,
      "--list-dockerfiles and --dockerfile are mutually exclusive",
    ],
    // The three lanes are pairwise mutually exclusive - choose one way in.
    [
      hasDockerfile,
      hasRepoRoot,
      "--dockerfile (build named Dockerfiles) and --repo-root (discover + " +
        "build) are mutually exclusive — choose one lane",
    ],
    [
      hasDockerfile,
      hasImage,
      "--dockerfile (build named Dockerfiles) and --image (scan pre-existing " +
        "images) are mutually exclusive — choose one lane",
    ],
    [
      hasRepoRoot,
      hasImage,
      "--repo-root (discover + build) and --image (scan pre-existing images) " +
        "are mutually exclusive — choose one lane",
    ],
  ];

  for (const [left, right, message] of pairs) {
    if (left && right) {
      return message;
    }
  }

  if (hasListDockerfiles && !hasRepoRoot) {
    return "--list-dockerfiles requires --repo-root <dir>";
  }

  // No lane and no listing - there is no default image set, so a bare invocation is a usage error
  // naming the three ways in.
  if (!hasImage && !hasRepoRoot && !hasDockerfile && !hasListDockerfiles) {
    return (
      "generate-docker-sbom requires one lane: --dockerfile <path>... (build " +
      "named Dockerfiles), --repo-root <dir> (discover + build), or --image " +
      "<ref>... (scan pre-existing images)"
    );
  }

  return undefined;
}

/** True iff a repeatable string-array flag was passed with at least one value. */
function hasValues(list: string[] | undefined): boolean {
  return list !== undefined && list.length > 0;
}

/**
 * Assemble the generate-docker-sbom options for one of the three lanes. The lane exclusivity is
 * validated first via {@link dockerSbomModeConflict} (a bad combination, or a bare no-lane
 * invocation, exits 3 with the usage). Mode-flag computation is routed through {@link hasValues} to
 * keep this function under the complexity bound.
 */
export function dockerSbomOptionsFrom(values: CliValues): GenerateDockerSbomOptions {
  const conflict = dockerSbomModeConflict(values);

  if (conflict !== undefined) {
    fail(`${conflict}\n${USAGE}`);
  }

  const hasImage = hasValues(values.image);
  const hasRepoRoot = values["repo-root"] !== undefined;
  const hasDockerfile = hasValues(values.dockerfile);
  // Discover the policy even without --policy so its `[cache] dir` steers the committed-SBOM output
  // to the same cache dir generate/check read from.
  const policyPath = values.policy ?? discoverDefaultPolicy(values);

  return {
    ...(hasImage ? { images: values.image } : {}),
    ...(hasRepoRoot ? { repoRoot: values["repo-root"] } : {}),
    ...(hasDockerfile ? { dockerfilePaths: values.dockerfile } : {}),
    ...(values["list-dockerfiles"] === true ? { listDockerfiles: true } : {}),
    ...(values.exclude !== undefined ? { excludes: values.exclude } : {}),
    ...(policyPath !== undefined ? { policyPath } : {}),
    /**
     * The tool's OWN directory, so Dockerfile discovery prunes it from the walk exactly as lockfile
     * discovery does (targets.ts). cli.ts lives in src/, so one level up is the tool root. Computed
     * with zero hardcoded paths.
     */
    toolDir: join(import.meta.dir, ".."),
    dockerSbomPath: values["docker-sbom"],
    baseDir: values["base-dir"],
    verbose: values.verbose ?? false,
  };
}

/** Run `generate`; a failure maps to exit 3 (a tool error, never a verdict). */
async function runGenerateCommand(values: CliValues): Promise<void> {
  try {
    await runGenerate(optionsFrom(values));
  } catch (error) {
    fail(`${error instanceof Error ? error.message : String(error)}\n`);
  }
}

/**
 * Run `generate-docker-sbom`. MAINTAINER-ONLY: requires a docker daemon. The only subcommand that
 * touches docker/syft; a scan/build/daemon failure is a tool error (exit 3), never a gate verdict.
 */
async function runGenerateDockerSbomCommand(values: CliValues): Promise<void> {
  try {
    await runGenerateDockerSbom(dockerSbomOptionsFrom(values));
  } catch (error) {
    fail(`${error instanceof Error ? error.message : String(error)}\n`);
  }
}

/**
 * Run `check`, the CI gate. Exit codes 1 and 2 come ONLY from the structured result via exitCodeFor
 * - never from a throw (an exception stays on 3+).
 */
async function runCheckCommand(values: CliValues): Promise<never> {
  let result: CheckResult;

  try {
    result = await runCheck(optionsFrom(values));
  } catch (error) {
    fail(`${error instanceof Error ? error.message : String(error)}\n`);
  }

  process.exit(exitCodeFor(result));
}

/**
 * Run `verify-cache`, the online integrity audit. Like check, the gate verdict (exit 1) comes ONLY
 * from the structured result; a network or malformed-cache failure stays on the 3+ throw path,
 * never a false "all match".
 */
async function runVerifyCacheCommand(values: CliValues): Promise<never> {
  let result: VerifyCacheResult;

  try {
    result = await runVerifyCache({
      baseDir: values["base-dir"],
      repoRoot: values["repo-root"],
      policyPath: values.policy ?? discoverDefaultPolicy(values),
      enrichmentCachePath: values["enrichment-cache"],
      verbose: values.verbose ?? false,
    });
  } catch (error) {
    fail(`${error instanceof Error ? error.message : String(error)}\n`);
  }

  reportVerifyCache(result);
  process.exit(result.mismatches.length === 0 ? 0 : 1);
}

/**
 * Run `refresh-clarifications`, the offline maintainer audit. Like check, the "there is something
 * to do" code comes ONLY from the structured result; a missing policy, an invalid one, or a write
 * the run refused stays on 3.
 */
async function runRefreshClarificationsCommand(values: CliValues): Promise<never> {
  let result: RefreshClarificationsResult;

  try {
    result = await runRefreshClarifications({
      baseDir: values["base-dir"],
      repoRoot: values["repo-root"],
      targetArg: values.target,
      excludes: values.exclude,
      policyPath: values.policy ?? discoverDefaultPolicy(values),
      enrichmentCachePath: values["enrichment-cache"],
      scancodeCachePath: values["scancode-cache"],
      verbose: values.verbose ?? false,
      write: values.write ?? false,
    });
  } catch (error) {
    fail(`${error instanceof Error ? error.message : String(error)}\n`);
  }

  reportRefreshClarifications(result);
  process.exit(exitCodeForRefresh(result));
}

async function main(argv: string[]): Promise<void> {
  const [subcommand, ...rest] = argv;

  let values: CliValues;

  try {
    ({ values } = parseArgs({
      args: rest,
      options: {
        target: { type: "string" },
        "repo-root": { type: "string" },
        exclude: { type: "string", multiple: true },
        policy: { type: "string" },
        output: { type: "string", default: "THIRD_PARTY_LICENSES.md" },
        notices: { type: "string" },
        cyclonedx: { type: "string" },
        "dump-model": { type: "string" },
        "base-dir": { type: "string" },
        "enrichment-cache": { type: "string" },
        "scancode-cache": { type: "string" },
        verbose: { type: "boolean", default: false },
        image: { type: "string", multiple: true },
        dockerfile: { type: "string", multiple: true },
        "docker-sbom": { type: "string" },
        "list-dockerfiles": { type: "boolean", default: false },
        intensive: { type: "boolean" },
        "package-timeout-mins": { type: "string" },
        write: { type: "boolean", default: false },
      },
      allowPositionals: true,
    }));
  } catch (error) {
    fail(`${error instanceof Error ? error.message : String(error)}\n${USAGE}`);
  }

  switch (subcommand) {
    case "generate":
      await runGenerateCommand(values);
      return;
    case "generate-docker-sbom":
      await runGenerateDockerSbomCommand(values);
      return;
    case "check":
      await runCheckCommand(values);
      return;
    case "verify-cache":
      await runVerifyCacheCommand(values);
      return;
    case "refresh-clarifications":
      await runRefreshClarificationsCommand(values);
      return;
    default:
      fail(`unknown subcommand: ${subcommand ?? "(none)"}\n${USAGE}`);
  }
}

// import.meta.main is true only when this file is the process entry point,
// so tests can import the pipeline without triggering the CLI. Supported by Bun natively; the
// repo-root mise pins node 24, where import.meta.main also exists (Node >=22.16) for the
// Node-fallback reader.
if (import.meta.main) {
  await main(process.argv.slice(2));
}
