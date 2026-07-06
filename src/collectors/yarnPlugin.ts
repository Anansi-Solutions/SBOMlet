/**
 * yarn-plugin-cyclonedx adapter for Yarn >=4 targets: a dual-run,
 * non-persistent `yarn dlx` invocation behind the same narrow swappable
 * generator interface as the cdxgen adapter. It gives 99.6-99.8% offline
 * license fill on real Yarn-4 targets vs cdxgen's 0.0%. The plugin is never
 * installed into any project — `yarn dlx` executes the exact pinned version
 * from yarn's global cache in a throwaway temp project.
 *
 * Evidence mode: the full run additionally passes `--gather-license-texts`,
 * which emits each package's verbatim LICENSE/NOTICE file contents as base64
 * under `component.evidence.licenses[]` (byte-identical double runs with
 * `--output-reproducible`, zero repo side effects). The prod run exists solely
 * for the purl set, so it never carries the flag — doubling it would double
 * I/O for nothing. The argv flows into computeCacheKey automatically, so the
 * full-run cache key changes with this flag.
 *
 * What this module deliberately does not do:
 * - No `yarn plugin import` / `yarn add` (would write into the scanned repo).
 * - No network license enrichment (the enrichment env toggle stays unset
 *   everywhere — nondeterministic).
 * - No per-component dev marker parsing: the plugin emits none; dev scope is
 *   derived downstream as full-set minus prod-set from the two SBOMs this
 *   adapter returns.
 */

import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  computeCacheKey,
  type CollectOptions,
  type ManifestEntry,
} from "./cdxgen";
import { execTool } from "./exec";
import type { Target } from "../targets/target";

/**
 * The argv pair hashed into the dual-run cache key: both run argvs (so a flag
 * change in either run invalidates the cached pair) with the volatile `-o`
 * operands replaced by the constant "<out>" sentinel. The real output files
 * live under a fresh mkdtemp directory whose name is random per run and
 * machine-dependent — hashing them would make the key change on every
 * invocation, so the cache could never hit. The manifest bytes (yarn.lock,
 * package.json) pin the target's content.
 */
export function yarnPluginCacheArgs(): string[] {
  return [...yarnPluginArgs("<out>", false), ...yarnPluginArgs("<out>", true)];
}

/**
 * Generator identity. The exact-version tag inside the argv is the pin —
 * floating tags are forbidden.
 */
export const YARN_PLUGIN_TOOL = {
  name: "@cyclonedx/yarn-plugin-cyclonedx",
  version: "3.3.1",
} as const;

/**
 * The verified `yarn dlx` argv tail for the runner (`mise x -- yarn dlx ...`).
 *
 * - `-q`: suppress dlx's own progress output (keeps stdout parseable).
 * - `--short-PURLs`: strips the `?vcs_url=...` qualifiers so plugin purls are
 *   exact-string matches with cdxgen's purl format. Required for
 *   cross-generator merge-key consistency.
 * - `--output-reproducible`: byte-identical double runs; no
 *   serialNumber/timestamp emitted at all.
 * - `-o` must be absolute: cwd is the target dir — a relative path would write
 *   into the scanned repo.
 * - `--production` (prod run only): inserted immediately before `-o`. Dev
 *   scope = full-set minus prod-set, computed downstream per target.
 * - `--gather-license-texts` (full run only): verbatim license and NOTICE
 *   texts as evidence. Never on the prod run.
 */
export function yarnPluginArgs(outFile: string, production: boolean): string[] {
  // Literal pin on purpose (not assembled from YARN_PLUGIN_TOOL): the exact
  // version tag must be grep-detectable in this file, and the pin-consistency
  // test asserts it matches YARN_PLUGIN_TOOL.
  return [
    "x",
    "--",
    "yarn",
    "dlx",
    "-q",
    "@cyclonedx/yarn-plugin-cyclonedx@3.3.1",
    "--short-PURLs",
    "--output-reproducible",
    ...(production ? ["--production"] : ["--gather-license-texts"]),
    "-o",
    outFile,
  ];
}

/**
 * Scrubbed child environment. Exactly two documented mutations on a copy of
 * `base`; everything else passes through (scrubbing the whole env would break
 * corepack/mise resolution):
 *
 * - `NODE_ENV` deleted: `--production` silently defaults true under
 *   NODE_ENV=production — CI commonly sets it, which would make the "full" run
 *   silently lose dev deps.
 * - `YARN_INSTALL_STATE_PATH` redirected into the per-run temp dir: keeps the
 *   scanned target pristine (zero files created).
 */
export function pluginEnv(
  tempDir: string,
  base: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  const env = { ...base };
  delete env.NODE_ENV;
  env.YARN_INSTALL_STATE_PATH = join(tempDir, "install-state.gz");
  return env;
}

export interface YarnPluginScanResult {
  /** SBOM of the full (dev+prod) run. */
  sbomPath: string;
  /** SBOM of the --production run; dev set = full minus prod, per target. */
  prodSbomPath: string;
  cacheKey: string;
  tool: { name: string; version: string };
}

/**
 * Validate one plugin output file exactly like the cdxgen adapter does:
 * existence, JSON parse (read outside the try — an I/O failure must surface as
 * itself, not as a misleading "not valid JSON"), and specVersion === "1.6".
 * Every error names the full invocation.
 */
function validatePluginOutput(outFile: string, invocation: string): void {
  if (!existsSync(outFile)) {
    throw new Error(
      `yarn-plugin-cyclonedx produced no output file at ${outFile}\n` +
        `invocation: ${invocation}`,
    );
  }
  const rawOutput = readFileSync(outFile, "utf8");
  let specVersion: unknown;
  try {
    const parsed: unknown = JSON.parse(rawOutput);
    specVersion = (parsed as { specVersion?: unknown }).specVersion;
  } catch (error) {
    throw new Error(
      `yarn-plugin-cyclonedx output at ${outFile} is not valid JSON: ${String(error)}\n` +
        `invocation: ${invocation}`,
      { cause: error },
    );
  }
  if (specVersion !== "1.6") {
    throw new Error(
      `yarn-plugin-cyclonedx output specVersion is ${JSON.stringify(specVersion)}, expected "1.6" — ` +
        `wrong generator version or flags?\ninvocation: ${invocation}`,
    );
  }
}

/**
 * The cache-key manifest list for a target: the exact string pair when the
 * target has no lockfileDir (every existing target); a unit-shaped list of
 * explicit {file, dir} entries when it does (workspace-unit expansion) —
 * root yarn.lock, the unit's own package.json, and root package.json, in
 * that order.
 */
function manifestEntriesFor(target: Target): readonly ManifestEntry[] {
  if (target.lockfileDir === undefined) {
    return ["yarn.lock", "package.json"];
  }
  return [
    { file: "yarn.lock", dir: target.lockfileDir },
    { file: "package.json", dir: target.dir },
    { file: "package.json", dir: target.lockfileDir },
  ];
}

/**
 * Dual-run scan: one call performs the full (dev+prod) run AND the
 * --production run and returns both SBOM paths. The runner defaults to
 * "mise" (`mise x -- yarn ...`): mise.exe is a real executable, verified
 * shell-free spawnable on Windows; corepack resolves the target's pinned
 * yarn from its packageManager field.
 */
export async function collectWithYarnPlugin(
  target: Target,
  opts: CollectOptions,
): Promise<YarnPluginScanResult> {
  const runner = opts.runner ?? "mise";
  const tempDir = opts.tempDir ?? mkdtempSync(join(tmpdir(), "licenses-"));
  const env = pluginEnv(tempDir);

  const fullPath = join(tempDir, "full.json");
  const prodPath = join(tempDir, "prod.json");
  const fullArgs = yarnPluginArgs(fullPath, false);
  const prodArgs = yarnPluginArgs(prodPath, true);

  for (const [args, outFile] of [
    [fullArgs, fullPath],
    [prodArgs, prodPath],
  ] as const) {
    const invocation = `${runner} ${args.join(" ")}`;
    await execTool(runner, args, {
      timeoutMs: opts.timeoutMs,
      verbose: opts.verbose,
      cwd: target.dir,
      env,
    });
    validatePluginOutput(outFile, invocation);
  }

  return {
    sbomPath: fullPath,
    prodSbomPath: prodPath,
    // Reuses the shared cache-key framing contract; hashes both argv arrays
    // (sentinel-normalized) so a flag change in either run invalidates the
    // cached pair while per-run temp paths never enter the key. A unit-shaped
    // target (workspace expansion, target.lockfileDir set) hashes the
    // ROOT yarn.lock + the WORKSPACE package.json + the ROOT package.json (root
    // resolutions/overrides can change the resolved tree even when the
    // workspace's own manifest is untouched); every other target keeps the
    // exact pair, resolved from target.dir.
    cacheKey: computeCacheKey(
      target,
      YARN_PLUGIN_TOOL,
      yarnPluginCacheArgs(),
      manifestEntriesFor(target),
    ),
    tool: YARN_PLUGIN_TOOL,
  };
}
