/**
 * cdxgen adapter behind the narrow swappable generator interface.
 *
 * The argv built here is locked byte-for-byte by test/cdxgen.test.ts —
 * changing any flag must consciously break that test and invalidate goldens.
 *
 * The raw SBOM, with its volatile fields (serialNumber, metadata.timestamp,
 * annotations), lands in a per-run temp directory and never travels past it —
 * callers parse it, but the canonical model never carries those fields. The
 * network license-enrichment env toggle stays unset: enrichment is
 * nondeterministic and belongs to a later phase.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { execTool } from "./exec";
import type { Target } from "../targets/target";

/**
 * Generator identity. The exact-version tag inside the argv is the pin —
 * floating tags are forbidden.
 */
export const CDXGEN_TOOL = {
  name: "@cyclonedx/cdxgen",
  version: "12.5.1",
} as const;

/**
 * Generator target ecosystem: cdxgen scans Python (poetry/uv) targets via
 * `-t python` and JS targets via `-t js`.
 */
export type Ecosystem = "js" | "python";

export interface CollectOptions {
  timeoutMs: number;
  verbose: boolean;
  /**
   * Executable that runs the pinned generator. Defaults to "bun" (`bun x`
   * resolves as a real executable on Windows, where npx is npx.cmd and not
   * directly spawnable). Kept as a parameter so the Node fallback path (npx)
   * stays possible.
   */
  runner?: string;
  /** Per-run temp directory; defaults to a fresh mkdtemp under os tmpdir. */
  tempDir?: string;
  /** Generator target ecosystem. Defaults to "js". */
  ecosystem?: Ecosystem;
  /**
   * Manifest files hashed into the cache key, relative to the target dir.
   * Defaults to the JS pair; poetry targets pass
   * ["poetry.lock", "pyproject.toml"], uv targets ["uv.lock", "pyproject.toml"].
   */
  manifestFiles?: readonly string[];
}

export interface CollectorSbomFile {
  sbomPath: string;
  cacheKey: string;
  tool: { name: string; version: string };
}

/**
 * The verified argv tail for the runner.
 *
 * - `--no-install-deps` is critical: the default (--install-deps=true) would
 *   run a package manager inside the scanned target — a side effect this tool
 *   must never have.
 * - `--no-recurse`: single-target scanning.
 * - `--spec-version 1.6`: cdxgen 12 defaults to 1.7.
 * - `-t <ecosystem>` is the only parameterized flag.
 */
export function cdxgenArgs(
  targetDir: string,
  outFile: string,
  ecosystem: Ecosystem,
): string[] {
  // Literal pin on purpose (not assembled from CDXGEN_TOOL): the exact version
  // tag must be grep-detectable in this file, and the exact-array test asserts
  // it matches CDXGEN_TOOL.
  return [
    "x",
    "@cyclonedx/cdxgen@12.5.1",
    "-t",
    ecosystem,
    "--no-install-deps",
    "--no-recurse",
    "--spec-version",
    "1.6",
    "-o",
    outFile,
    targetDir,
  ];
}

/**
 * The argv hashed into the cache key: the verified invocation shape with its
 * two volatile path operands replaced by constant sentinels — the per-run
 * mkdtemp output file ("<out>") and the absolute target directory
 * ("<target>"). Hashing the real paths would make the key change on every run
 * (random mkdtemp name, machine-dependent tmpdir) and differ per checkout
 * (absolute targetDir), so the cache could never hit and keys would never be
 * portable. The manifest bytes already pin the target's content, and any real
 * flag change still flows through this argv and invalidates the key.
 */
export function cdxgenCacheArgs(ecosystem: Ecosystem): string[] {
  return cdxgenArgs("<target>", "<out>", ecosystem);
}

/**
 * One manifest entry hashed into the cache key: a plain string resolves from
 * the target's own dir (today's exact behavior, byte-unchanged); an object
 * form resolves from an explicit `dir` — the yarn workspace-unit path,
 * where the root yarn.lock and root package.json live in a different
 * directory than the workspace's own package.json. The hashed label is
 * ALWAYS the bare file name in both forms — content-relative, never
 * path-relative — so the two-dirs-same-bytes-same-key lock
 * (test/yarnPlugin.test.ts) keeps holding for object entries too.
 */
export type ManifestEntry = string | { file: string; dir: string };

/**
 * Content-hash cache key. Hashes the raw bytes of the target's manifest files
 * (no text decoding — immune to EOL differences) plus the tool identity and
 * the full argv (callers pass the sentinel-normalized cache argv — never an
 * argv carrying per-run temp paths).
 *
 * Every segment is domain-tagged and length-prefixed (files) or NUL-terminated
 * (strings) so distinct inputs can never collide by concatenation ambiguity:
 * bytes cannot move across a manifest-file boundary, name/version cannot blend,
 * and ["a b"] hashes differently from ["a", "b"]. The framing is part of the
 * cache contract and must not change silently. The manifest list is
 * caller-supplied: yarn targets hash ["yarn.lock", "package.json"], poetry
 * targets ["poetry.lock", "pyproject.toml"], uv targets
 * ["uv.lock", "pyproject.toml"]. A yarn WORKSPACE UNIT instead passes
 * explicit {file, dir} entries (root yarn.lock, workspace package.json, root
 * package.json) since its manifests are NOT all in target.dir.
 *
 * When `target.workspacePath` is set, one additional
 * domain-tagged segment enters the hash AFTER the file loop and BEFORE the
 * tool segment — a stale-cache poisoning guard so two workspaces that happen
 * to share byte-identical manifests (rare but possible with generated
 * package.json content) can never collide on the same key. Targets without
 * workspacePath (every existing target, every existing test) carry no such
 * segment and hash byte-identically to before this addition.
 */
export function computeCacheKey(
  target: Target,
  tool: { name: string; version: string },
  args: string[],
  manifestFiles: readonly ManifestEntry[],
): string {
  const hash = createHash("sha256");
  for (const entry of manifestFiles) {
    const file = typeof entry === "string" ? entry : entry.file;
    const dir = typeof entry === "string" ? target.dir : entry.dir;
    const path = join(dir, file);
    // Python targets bypass resolveTarget's yarn-manifest validation, so a
    // missing pyproject.toml first surfaces here — name the target identity
    // and the expected absolute path.
    if (!existsSync(path)) {
      throw new Error(
        `target "${target.identity}" is missing ${file}: expected ${path}`,
      );
    }
    const bytes = readFileSync(path);
    hash.update(`file:${file}:${bytes.length}\0`).update(bytes);
  }
  if (target.workspacePath !== undefined) {
    hash.update(`workspace:${target.workspacePath}\0`);
  }
  hash.update(`tool:${tool.name}\0${tool.version}\0`);
  for (const arg of args) {
    hash.update(`arg:${arg}\0`);
  }
  return hash.digest("hex");
}

/**
 * The narrow swappable generator interface: a generator is swapped by adding
 * one file satisfying this signature.
 */
export async function collectWithCdxgen(
  target: Target,
  opts: CollectOptions,
): Promise<CollectorSbomFile> {
  const runner = opts.runner ?? "bun";
  const tempDir = opts.tempDir ?? mkdtempSync(join(tmpdir(), "licenses-"));
  const ecosystem = opts.ecosystem ?? "js";
  const manifestFiles = opts.manifestFiles ?? ["yarn.lock", "package.json"];
  const outFile = join(tempDir, "bom.json");
  const args = cdxgenArgs(target.dir, outFile, ecosystem);
  const invocation = `${runner} ${args.join(" ")}`;

  await execTool(runner, args, {
    timeoutMs: opts.timeoutMs,
    verbose: opts.verbose,
  });

  // Generator identity assertion: the @12.5.1 argv tag pins what we asked for;
  // asserting the output parses with specVersion 1.6 pins what we actually
  // got. Failures name the full invocation so they are actionable.
  if (!existsSync(outFile)) {
    throw new Error(
      `cdxgen produced no output file at ${outFile}\n` +
        `invocation: ${invocation}`,
    );
  }
  // Read outside the parse try: an I/O failure (permissions, transient Windows
  // lock) must surface as itself, not as a misleading "not valid JSON"
  // message.
  const rawOutput = readFileSync(outFile, "utf8");
  let specVersion: unknown;
  try {
    const parsed: unknown = JSON.parse(rawOutput);
    specVersion = (parsed as { specVersion?: unknown }).specVersion;
  } catch (error) {
    throw new Error(
      `cdxgen output at ${outFile} is not valid JSON: ${String(error)}\n` +
        `invocation: ${invocation}`,
      { cause: error },
    );
  }
  if (specVersion !== "1.6") {
    throw new Error(
      `cdxgen output specVersion is ${JSON.stringify(specVersion)}, expected "1.6" — ` +
        `wrong generator version or flags?\ninvocation: ${invocation}`,
    );
  }

  return {
    sbomPath: outFile,
    // Sentinel-normalized argv: identical inputs hash to the same key across
    // runs, machines, and checkout locations.
    cacheKey: computeCacheKey(
      target,
      CDXGEN_TOOL,
      cdxgenCacheArgs(ecosystem),
      manifestFiles,
    ),
    tool: CDXGEN_TOOL,
  };
}
