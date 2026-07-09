/**
 * Single CLI entry point: `generate` and `check` subcommands parsed with
 * node:util parseArgs — no CLI framework (dependency-footprint constraint).
 * This module is the only place that owns process exit codes.
 *
 * Generate modes:
 * - `--repo-root <path>` (default: cwd) — discovery mode: every lockfile
 *   target under the root is scanned sequentially in sorted identity order and
 *   folded into one merged document.
 * - `--target <path>` — single-target debugging; flows through the same
 *   dispatch loop, so a Yarn-4 target produces identical rows either way.
 * - `--exclude <glob>` — repeatable; matched against target identities.
 * - `--policy <path>` — optional TOML policy: validated before any scan
 *   (fail-fast), verdicts surfaced on stderr, in the dump-model output, and in
 *   the rendered PolicyView document; the document is always written whatever
 *   the verdicts say — the CI gate is check, never generate.
 * - `--notices <path>` — the THIRD_PARTY_NOTICES.md companion is always
 *   written; defaults to THIRD_PARTY_NOTICES.md beside the output.
 * - `--cyclonedx <path>` — optional CycloneDX 1.6 export.
 *
 * Architecture: the write-free pipeline core lives in src/pipeline/
 * (buildOutputs renders in memory; runGenerate holds the only file-write calls
 * in the cli/pipeline/gate trio); the check comparison and its exit mapping
 * live in src/gate/check.ts.
 *
 * Exit-code taxonomy:
 *   0  success / check clean
 *   1  check: at least one policy fail verdict (priority over stale). Warn
 *      verdicts and unused-policy-entry warnings print but never gate — only
 *      fail verdicts reach this code.
 *   2  check: at least one stale or missing committed output
 *   3  tool/config error (>2): unknown subcommand, conflicting flags, pipeline
 *      failure, coverage assertion, invalid policy file (TomlError/PolicyError
 *      messages printed verbatim), --dump-model on check. Codes 1 and 2 come
 *      only from check's structured-result mapping — exceptions can never
 *      surface as 0/1/2.
 */

import { existsSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";

import {
  runGenerateDockerSbom,
  type GenerateDockerSbomOptions,
} from "./pipeline/dockerSbom";
import { exitCodeFor, runCheck, type CheckResult } from "./gate/check";
import { defaultNoticesPath, resolveFrom } from "./pipeline/paths";
import { runGenerate, type GenerateOptions } from "./pipeline/pipeline";
import { runVerifyCache } from "./pipeline/verifyCache";
import type { VerifyResult } from "./enrich/verify";

const USAGE =
  "usage: sbomlet <generate|check|verify-cache|generate-docker-sbom> [options]\n" +
  "  generate [--repo-root <path> | --target <path>] [--exclude <glob>]... " +
  "[--policy <path>] [--output <path>] [--notices <path>] " +
  "[--cyclonedx <path>] [--dump-model <path>] [--base-dir <path>] " +
  "[--enrichment-cache <path>] [--scancode-cache <path>] [--intensive] " +
  "[--verbose]\n" +
  "           --intensive: assess the FULL package set with ScanCode, an " +
  "in-depth source scan that outranks the registry answer where present and " +
  "flags any disagreement as a conflict to resolve; skips versions already " +
  "in the memo and packages whose sources are not locally present (generate-" +
  "only; meant for occasional runs, not the default fast path).\n" +
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
  "  generate-docker-sbom (--image <ref>... | " +
  "--built-image <ref>... | --list-dockerfiles --repo-root <dir> | " +
  "--repo-root <dir> [--policy <file>] [--exclude <glob>]... [--image <ref>]... | " +
  "--dockerfile <path>... [--image <ref>]...) " +
  "[--docker-os-sbom <path>] [--base-dir <path>] [--verbose]\n" +
  "           Writes the committed docker-os.sbom.json. FOUR modes:\n" +
  "           --image <ref>...: MAINTAINER-ONLY, REQUIRES A DOCKER DAEMON — " +
  "scans the image set (default: the documented image set) with the pinned " +
  "syft and digest-pins each.\n" +
  "           --repo-root <dir>: DISCOVERY — walks the repo for Dockerfiles, " +
  "derives each shipped FROM base image, and scans the resolved bases (union " +
  "with any explicit --image). --policy reads [docker] ignore globs; scratch/" +
  "unresolved/ignored Dockerfiles contribute no image. Derives the BASE image's " +
  "OS packages only (not the Dockerfile's own RUN apt/apk installs).\n" +
  "           --dockerfile <path>...: TARGETED — same derive+scan as discovery " +
  "but over an explicit Dockerfile list instead of a repo walk (union with any " +
  "explicit --image). --repo-root, if also given, is only the cache-dir anchor.\n" +
  "           --built-image <ref>...: BUILT-IMAGE — scans locally built, " +
  "never-pushed images (full contents: application + OS layers); records " +
  'each ref digest-less in the sidecar ({image, digest: ""}); local ' +
  "tags only.\n" +
  "           --list-dockerfiles --repo-root <dir>: print the discovered " +
  "Dockerfile paths (policy-aware, [docker] ignore honored) one per line " +
  "and exit — scans nothing, writes nothing; the Docker-scan workflow's " +
  "default build set.\n" +
  "           generate/check NEVER touch docker — they read the committed bytes " +
  "this writes (offline contract).\n";

function fail(message: string): never {
  process.stderr.write(message);
  process.exit(3);
}

/**
 * Print the cache-integrity audit to stderr (the tool's message channel; the
 * exit code is the machine signal). Each mismatch names the purl, the committed
 * value, the registry's current answer, and why they diverge.
 */
function reportVerifyCache(result: VerifyResult): void {
  const line = (text: string): void => {
    process.stderr.write(`${text}\n`);
  };
  const noun = result.audited === 1 ? "entry" : "entries";
  if (result.mismatches.length === 0) {
    line(
      `verify-cache: audited ${result.audited} cache ${noun} — ` +
        `all audited entries match upstream`,
    );
    return;
  }
  for (const mismatch of result.mismatches) {
    line(`MISMATCH  ${mismatch.purl}`);
    line(`  committed: ${mismatch.cached ?? "(none)"}`);
    line(`  registry:  ${mismatch.current ?? "(none)"}`);
    line(`  ${mismatch.reason}`);
  }
  const verb =
    result.mismatches.length === 1 ? "diverges from" : "diverge from";
  line(
    `verify-cache: ${result.mismatches.length} of ${result.audited} audited cache ${noun} ` +
      `${verb} upstream — investigate before release`,
  );
}

/** The parseArgs value shape shared by both subcommands. */
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
  /** Repeatable --image refs for generate-docker-sbom (the live-scan set). */
  image?: string[];
  /**
   * Repeatable --dockerfile paths for generate-docker-sbom (targeted mode):
   * derive + scan the shipped base of each named Dockerfile instead of walking
   * the repo. Base-dir-resolved.
   */
  dockerfile?: string[];
  /** generate-docker-sbom output path; base-dir-resolved like every artifact. */
  "docker-os-sbom"?: string;
  /**
   * Repeatable --built-image refs for generate-docker-sbom: BUILT-IMAGE mode.
   * Scans locally built, never-pushed tags full-contents and digest-less (the
   * built posture); the Docker-scan CI workflow is the consumer. Local tags
   * only.
   */
  "built-image"?: string[];
  /**
   * generate-docker-sbom --list-dockerfiles: print the tool policy-aware
   * discovered Dockerfile identities to stdout, one per line, and exit --
   * scans nothing, writes nothing. Requires --repo-root.
   */
  "list-dockerfiles"?: boolean;
  /**
   * generate --intensive: opt-in ScanCode assessment over the FULL package
   * set — the in-depth source scan that outranks the registry answer where
   * present, memo-gated so an already-analysed version is never re-scanned.
   * GENERATE-ONLY — check rejects it outright (gate/check.ts). No `default`
   * here: absent must stay absent, never coerced to false, so optionsFrom's
   * own-property spread can gate the intensive lane on mere presence.
   */
  intensive?: boolean;
}

/**
 * The recommended default policy file. When --policy is omitted, a
 * .sbomlet.policy.toml at the repo root is adopted automatically; an absent
 * default is silently skipped (no policy means no gate). An explicit --policy
 * always wins, and errors if its file is missing. The anchor is the repo root
 * (not --base-dir), so the default is found in the scanned repo, including from
 * the GitHub Action, which runs from its own directory.
 */
const DEFAULT_POLICY = ".sbomlet.policy.toml";

function discoverDefaultPolicy(values: CliValues): string | undefined {
  const anchor = resolveFrom(values["base-dir"], values["repo-root"] ?? ".");
  const candidate = resolveFrom(anchor, DEFAULT_POLICY);
  return existsSync(candidate) ? candidate : undefined;
}

/**
 * Validate the shared flag constraints and assemble the pipeline options —
 * generate and check parse the same flags, so the comparison set is exactly
 * the configured output set.
 */
export function optionsFrom(values: CliValues): GenerateOptions {
  if (values.target !== undefined && values["repo-root"] !== undefined) {
    fail(
      `--target and --repo-root are mutually exclusive — pass at most one\n${USAGE}`,
    );
  }
  const outputPath = values.output ?? "THIRD_PARTY_LICENSES.md";
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
    // Absent-not-false (D-07): own-property spread so a default generate
    // never sets this key at all, and check's runCheck rejection reads
    // opts.intensive === true, never a coerced false.
    ...(values.intensive === true ? { intensive: true } : {}),
  };
}

/**
 * Compute the first generate-docker-sbom mode-conflict message, or undefined
 * when the requested mode combination is valid. EXACTLY one of --image (live
 * scan) / --built-image (built posture) may be active. --dockerfile MAY
 * combine with --repo-root (the latter then serves only as the cache-dir
 * anchor) and with --image (union). --built-image is EXPLICIT and stand-alone:
 * never combined with --image or --dockerfile; it MAY combine with --repo-root
 * (anchor degradation, same as --dockerfile).
 * --list-dockerfiles never combines with any scan mode and REQUIRES
 * --repo-root (the walk root the listing reads). Pair checks are walked as a
 * table rather than an if-ladder to keep this function under the complexity
 * bound as the mode count grows. Extracted from dockerSbomOptionsFrom to keep
 * that function under the complexity bound.
 */
export function dockerSbomModeConflict(values: CliValues): string | undefined {
  const hasImage = values.image !== undefined && values.image.length > 0;
  const hasRepoRoot = values["repo-root"] !== undefined;
  const hasDockerfile =
    values.dockerfile !== undefined && values.dockerfile.length > 0;
  const hasBuiltImage =
    values["built-image"] !== undefined && values["built-image"].length > 0;
  const hasListDockerfiles = values["list-dockerfiles"] === true;
  const pairs: Array<[boolean, boolean, string]> = [
    [
      hasBuiltImage,
      hasImage,
      "--built-image (built) and --image (live scan) are mutually exclusive",
    ],
    [
      hasBuiltImage,
      hasDockerfile,
      "--built-image (built) and --dockerfile (targeted) are mutually exclusive",
    ],
    [
      hasListDockerfiles,
      hasImage,
      "--list-dockerfiles and --image are mutually exclusive",
    ],
    [
      hasListDockerfiles,
      hasDockerfile,
      "--list-dockerfiles and --dockerfile are mutually exclusive",
    ],
    [
      hasListDockerfiles,
      hasBuiltImage,
      "--list-dockerfiles and --built-image are mutually exclusive",
    ],
  ];
  for (const [left, right, message] of pairs) {
    if (left && right) return message;
  }
  if (hasListDockerfiles && !hasRepoRoot) {
    return "--list-dockerfiles requires --repo-root <dir>";
  }
  return undefined;
}

/** True iff a repeatable string-array flag was passed with at least one value. */
function hasValues(list: string[] | undefined): boolean {
  return list !== undefined && list.length > 0;
}

/**
 * Assemble the generate-docker-sbom options. The repeatable --image flags are
 * the configurable image set; when none are passed, runGenerateDockerSbom
 * falls back to its documented default image set (the defaults live in
 * the dogfood layer, never in core — the independence constraint). Mode-flag
 * computation is routed through {@link hasValues} (rather than an inline
 * `!== undefined && .length > 0` per flag) to keep this function under the
 * complexity bound as the mode count grows.
 */
export function dockerSbomOptionsFrom(
  values: CliValues,
): GenerateDockerSbomOptions {
  const conflict = dockerSbomModeConflict(values);
  if (conflict !== undefined) {
    fail(`${conflict}\n${USAGE}`);
  }
  const hasImage = hasValues(values.image);
  const hasRepoRoot = values["repo-root"] !== undefined;
  const hasDockerfile = hasValues(values.dockerfile);
  const hasBuiltImage = hasValues(values["built-image"]);
  // Discover the policy even without --policy so its `[cache] dir` steers the
  // committed-SBOM output to the same cache dir generate/check read from.
  const policyPath = values.policy ?? discoverDefaultPolicy(values);
  return {
    ...(hasImage ? { images: values.image } : {}),
    ...(hasRepoRoot ? { repoRoot: values["repo-root"] } : {}),
    ...(hasDockerfile ? { dockerfilePaths: values.dockerfile } : {}),
    ...(hasBuiltImage ? { builtImages: values["built-image"] } : {}),
    ...(values["list-dockerfiles"] === true ? { listDockerfiles: true } : {}),
    ...(values.exclude !== undefined ? { excludes: values.exclude } : {}),
    ...(policyPath !== undefined ? { policyPath } : {}),
    // The tool's OWN directory, so Dockerfile discovery prunes it from the walk
    // exactly as lockfile discovery does (targets.ts:53). cli.ts lives in src/,
    // so one level up is the tool root. Computed with zero hardcoded paths.
    toolDir: join(import.meta.dir, ".."),
    dockerOsSbomPath: values["docker-os-sbom"],
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
 * Run `generate-docker-sbom`. MAINTAINER-ONLY: requires a docker daemon. The
 * only subcommand that touches docker/syft; a scan/build/daemon failure is a
 * tool error (exit 3), never a gate verdict.
 */
async function runGenerateDockerSbomCommand(values: CliValues): Promise<void> {
  try {
    await runGenerateDockerSbom(dockerSbomOptionsFrom(values));
  } catch (error) {
    fail(`${error instanceof Error ? error.message : String(error)}\n`);
  }
}

/**
 * Run `check`, the CI gate. Exit codes 1 and 2 come ONLY from the structured
 * result via exitCodeFor — never from a throw (an exception stays on 3+).
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
 * Run `verify-cache`, the online integrity audit. Like check, the gate verdict
 * (exit 1) comes ONLY from the structured result; a network or malformed-cache
 * failure stays on the 3+ throw path, never a false "all match".
 */
async function runVerifyCacheCommand(values: CliValues): Promise<never> {
  let result: VerifyResult;
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
        "docker-os-sbom": { type: "string" },
        "built-image": { type: "string", multiple: true },
        "list-dockerfiles": { type: "boolean", default: false },
        intensive: { type: "boolean" },
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
    default:
      fail(`unknown subcommand: ${subcommand ?? "(none)"}\n${USAGE}`);
  }
}

// import.meta.main is true only when this file is the process entry point,
// so tests can import the pipeline without triggering the CLI. Supported by
// Bun natively; the repo-root mise pins node 24, where import.meta.main
// also exists (Node >=22.16) for the Node-fallback reader.
if (import.meta.main) {
  await main(process.argv.slice(2));
}
