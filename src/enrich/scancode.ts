/**
 * ScanCode-toolkit collector — the syft-parity composite (07/dockerOs.ts) for
 * deep source-level license + copyright detection, orchestrated behind the
 * `--intensive` lane (SCAN-01). Two responsibilities live in this module:
 *
 *  1. `sourceDirFor` — a purl → locally-present source-dir mapper (no
 *     registry/collector analog exists for this; see PATTERNS "No Analog
 *     Found"). npm: the decoded package name under `<targetDir>/node_modules`,
 *     with the installed `package.json` version MANDATORILY equal to the
 *     purl's version (Pitfall 8 — a stale node_modules must never poison the
 *     cache with the wrong version's license). pypi: an in-project `.venv`'s
 *     site-packages, keyed by the PEP-503 structural fold of the dist-info
 *     dir name (ADR-0015: the dir name IS the signal, no PEP-440/508 parsing).
 *     Everything else, or any structural mismatch, returns undefined — an
 *     honest skip, never a fabricated guess. A `..`-shaped or
 *     absolute-path-shaped decoded name can never escape the target's
 *     `node_modules` root (resolve + strict prefix-check, T-10-06).
 *
 *  2. `scanPackageSources` — orchestrates the pinned `scancode-toolkit` CLI
 *     through `execTool` (the tool's only child_process seam; dockerOs.ts
 *     idiom): spawn → exists-check → size-gate BEFORE read → parse → runtime
 *     version-assert against {@link SCANCODE_TOOL} from the output's own
 *     headers (T-10-08, a substituted/drifted binary is caught). Expression
 *     election follows research Pattern 2 — ScanCode's own root-level
 *     legal-file detection wins, the package manifest is the fallback,
 *     anything else (or an unparseable multi-file AND-combine) is an honest
 *     no-answer; any expression containing a `LicenseRef-scancode-` id is
 *     rejected outright (T-10-09, ADR-0007 no-fabrication) because it cannot
 *     resolve to an SPDX id downstream and would only add cache noise.
 *
 * This module NEVER performs SPDX correction or interpretation — the raw
 * expression string is returned verbatim (`{raw, via, copyrights} | null`,
 * the same shape the registry resolvers return at enrich.ts's
 * resolveFromDocument), and `normalizeRaw` stays the single SPDX authority
 * downstream. It never spawns outside `execTool`, and it never writes the
 * cache itself — the single write site stays in enrich.ts.
 */
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve, sep } from "node:path";

import { execTool } from "../collectors/exec";
import { sanitizeEvidenceText } from "../merge/merge";
import { compareCodeUnits } from "../model/dependencies";
import { parsePurl } from "./enrich";

/**
 * Collector tool identity. The literal version is the pin — it lives in the
 * intensive workflow's pipx line (`pipx install "scancode-toolkit[full]==32.5.0"`,
 * NOT mise.toml — D-01/research verdict: an opt-in-occasional tool must not be
 * pulled by every `mise install`) and is asserted at runtime from the scan
 * output's own `headers[0].tool_version` (the SYFT_TOOL comment voice,
 * dockerOs.ts:41-48) so a version bump — or a substituted binary — must be
 * conscious, never silent (T-10-08).
 */
export const SCANCODE_TOOL = {
  name: "scancode-toolkit",
  version: "32.5.0",
} as const;

/**
 * DoS bound: real scancode `--json-pp` output for a single npm package tree is
 * well under a MiB even for large packages; 64 MiB is generous headroom,
 * matching MAX_SYFT_SBOM_BYTES's stat-gate-before-read posture (T-10-07,
 * ASVS V12). The gate fires before any read/parse.
 */
export const MAX_SCANCODE_OUTPUT_BYTES = 64 * 1024 * 1024;

/**
 * Wall-clock timeout per package scan (D-03 planner discretion). ScanCode's
 * OWN per-file `--timeout` stays at its 120s default — deliberately not
 * passed here, since it bounds a single file's matching, not the whole run.
 * 10 minutes is generous headroom for even a large vendored bundle.
 */
export const DEFAULT_SCAN_TIMEOUT_MS = 10 * 60 * 1000;

/**
 * The verified scancode-toolkit 32.5.0 argv. Options first, then a `--`
 * END-OF-OPTIONS separator, then the scanned directory OPERAND last — the
 * dockerOs.ts syftArgs idiom (T-09-06): the source dir is always an argv
 * operand, never a shell string, so command injection is impossible by
 * construction, and the `--` is defense-in-depth against a dash-prefixed
 * path being parsed as a flag. `--license --copyright` requests both
 * detection families; `--json-pp <outFile>` writes deterministic
 * pretty-printed JSON to the per-run temp file. Locked byte-for-byte by an
 * exact-array test — any flag change must consciously break that test.
 */
export function scancodeArgs(outFile: string, sourceDir: string): string[] {
  return ["--license", "--copyright", "--json-pp", outFile, "--", sourceDir];
}

/** A `pkg:npm`/`pkg:pypi` purl's ecosystem-relevant fields, from parsePurl. */
interface EcosystemPurl {
  type: string;
  encodedName: string;
  version: string;
}

/**
 * decodeURIComponent wrapped so a malformed percent-encoding (e.g. "%ZZ" in
 * a crafted SBOM purl — SBOM documents are an untrusted shape) is an honest
 * undefined, never a URIError that would kill the whole intensive run
 * (the mapper contract: undefined on ANY structural mismatch).
 */
function safeDecode(encoded: string): string | undefined {
  try {
    return decodeURIComponent(encoded);
  } catch {
    return undefined;
  }
}

/**
 * Decode + validate an npm purl's encoded name against a candidate
 * `node_modules` root, requiring the installed package.json `version` field
 * to equal the purl version (Pitfall 8, mandatory — never optional). Returns
 * the resolved source dir, or undefined on ANY structural mismatch: dir
 * absent, package.json absent/unparseable (a garbage node_modules must never
 * throw and kill the run — honest skip), version mismatch, or a decoded name
 * that would escape the node_modules root (T-10-06 — resolve + strict
 * prefix-check, test-locked, not best-effort).
 */
function npmSourceDir(
  purl: EcosystemPurl,
  targetDir: string,
): string | undefined {
  // The decode exactly mirrors npmPackumentUrl's scoped-name decode
  // (enrich.ts npmPackumentUrl): "%40scope/pkg" -> "@scope/pkg" (A6 locked).
  const name = safeDecode(purl.encodedName);
  if (name === undefined) return undefined;

  const nodeModulesRoot = resolve(targetDir, "node_modules");
  const candidate = resolve(nodeModulesRoot, name);

  // Strict prefix-check under the RESOLVED node_modules root: a ".."-shaped
  // or absolute-path-shaped decoded name can never produce a non-null result
  // outside it. A path-separator-suffixed prefix guards against a
  // sibling-directory false-positive (e.g. "node_modules-evil").
  const rootWithSep = nodeModulesRoot.endsWith(sep)
    ? nodeModulesRoot
    : `${nodeModulesRoot}${sep}`;
  if (candidate !== nodeModulesRoot && !candidate.startsWith(rootWithSep)) {
    return undefined;
  }

  const packageJsonPath = join(candidate, "package.json");
  if (!existsSync(packageJsonPath)) return undefined;

  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(packageJsonPath, "utf8"));
  } catch {
    // Unparseable package.json -> honest skip, never a throw (a garbage
    // node_modules must not kill the run).
    return undefined;
  }
  const version = (parsed as { version?: unknown }).version;
  if (typeof version !== "string" || version !== purl.version) {
    return undefined;
  }

  return candidate;
}

/**
 * readdirSync wrapped so a missing/unreadable directory is an honest empty
 * list rather than a throw (a garbage or absent venv/node_modules tree must
 * never kill the run).
 */
function safeReaddir(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

/**
 * The PEP-503 structural fold used ONLY to match a dist-info directory name —
 * literal lower-case + every run of `-`/`_`/`.` collapsed to a single `_`
 * (ADR-0015: abstain over fragile PEP-440/508 parsing; the dist-info dir name
 * IS the structural signal, nothing is parsed out of it).
 */
function pep503Fold(value: string): string {
  return value.toLowerCase().replace(/[-_.]+/g, "_");
}

/** Find the first `lib/pythonX.Y/site-packages` dir under a POSIX venv. */
function posixSitePackagesDir(venvDir: string): string {
  const libDir = join(venvDir, "lib");
  const fallback = join(libDir, "site-packages");
  if (!existsSync(libDir)) return fallback;

  const pythonDirs = safeReaddir(libDir)
    .filter((e) => e.startsWith("python"))
    .sort(compareCodeUnits);
  const chosen = pythonDirs[0];
  return chosen === undefined
    ? fallback
    : join(libDir, chosen, "site-packages");
}

/** The platform-appropriate site-packages path under a project `.venv`. */
function sitePackagesDir(venvDir: string): string {
  return process.platform === "win32"
    ? join(venvDir, "Lib", "site-packages")
    : posixSitePackagesDir(venvDir);
}

/**
 * Resolve a pypi purl to its locally-present source dir via an in-project
 * `.venv`'s site-packages: the dist-info dir name is the PEP-503 structural
 * fold of `<name>-<version>` (literal lower-case + `-`/`_`/`.` folded), and
 * its `top_level.txt` (sorted, first entry that exists as a sibling dir)
 * names the actual package dir to scan. Absent venv, absent dist-info,
 * absent/empty top_level.txt, or no existing named sibling -> undefined
 * (honest skip, never a fabricated guess). top_level.txt content is fully
 * controlled by the installed package, so a `..`-shaped or
 * absolute-path-shaped line can never name a directory outside
 * site-packages (resolve + strict prefix-check, the npmSourceDir guard).
 */
function pypiSourceDir(
  purl: EcosystemPurl,
  targetDir: string,
): string | undefined {
  const venvDir = join(targetDir, ".venv");
  // Resolved once up front so both sides of the containment check below
  // compare canonical absolute paths.
  const sitePackages = resolve(sitePackagesDir(venvDir));
  if (!existsSync(sitePackages)) return undefined;

  const name = safeDecode(purl.encodedName);
  if (name === undefined) return undefined;
  const folded = pep503Fold(`${name}-${purl.version}`);

  const entries = safeReaddir(sitePackages);
  const distInfoDir = entries.find(
    (e) =>
      e.endsWith(".dist-info") &&
      pep503Fold(e.slice(0, -".dist-info".length)) === folded,
  );
  if (distInfoDir === undefined) return undefined;

  const topLevelPath = join(sitePackages, distInfoDir, "top_level.txt");
  if (!existsSync(topLevelPath)) return undefined;

  let topLevelRaw: string;
  try {
    topLevelRaw = readFileSync(topLevelPath, "utf8");
  } catch {
    return undefined;
  }
  const candidates = topLevelRaw
    .split(/\r\n|\r|\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .sort(compareCodeUnits);

  // Strict prefix-check under the RESOLVED site-packages root: an
  // attacker-controlled top_level.txt line can never produce a non-null
  // result outside it (or site-packages itself). The separator-suffixed
  // prefix guards against a sibling false-positive ("site-packages-evil").
  const rootWithSep = sitePackages.endsWith(sep)
    ? sitePackages
    : `${sitePackages}${sep}`;
  for (const candidate of candidates) {
    const packageDir = resolve(sitePackages, candidate);
    if (!packageDir.startsWith(rootWithSep)) continue; // escape attempt: skip
    if (existsSync(packageDir)) return packageDir;
  }
  return undefined;
}

/**
 * Map a purl to its locally-present source dir across a set of candidate
 * target dirs (probed in {@link compareCodeUnits}-sorted order, first
 * structural match wins — determinism regardless of caller-supplied order).
 * npm and pypi are the only supported ecosystems (Pattern 4); every other
 * type — including an unparseable purl — returns undefined with zero fs
 * probes beyond the initial parse.
 */
export function sourceDirFor(
  purl: string,
  targetDirs: string[],
): string | undefined {
  const parsed = parsePurl(purl);
  if (parsed === undefined) return undefined;
  if (parsed.type !== "npm" && parsed.type !== "pypi") return undefined;

  const sortedDirs = [...targetDirs].sort(compareCodeUnits);
  for (const targetDir of sortedDirs) {
    const found =
      parsed.type === "npm"
        ? npmSourceDir(parsed, targetDir)
        : pypiSourceDir(parsed, targetDir);
    if (found !== undefined) return found;
  }
  return undefined;
}

// --- Invocation lane -------------------------------------------------------

/**
 * Options threading the `--intensive` lane through enrichUnknowns (10-04).
 * Present ONLY on `generate --intensive`: check never receives it, and a
 * default generate call never constructs it (the intensive lane is
 * additionally gated on this field's mere presence — enrich.ts). Mirrors the
 * default-to-production/override-in-tests idiom used throughout this tool
 * (EnrichOptions.now?, ScancodeScanOptions.scancodeBin?).
 */
export interface IntensiveOptions {
  /** Candidate roots probed by {@link sourceDirFor} (compareCodeUnits-sorted, first match wins). */
  targetDirs: string[];
  /** Executable that runs the pinned scancode binary. Defaults to "scancode". */
  scancodeBin?: string;
  /** Hard wall-clock limit per spawn; defaults to {@link DEFAULT_SCAN_TIMEOUT_MS}. */
  timeoutMs?: number;
  /** Per-run temp directory; defaults to a fresh mkdtemp under os tmpdir. */
  tempDir?: string;
}

export interface ScancodeScanOptions {
  /** Hard wall-clock limit per spawn; defaults to {@link DEFAULT_SCAN_TIMEOUT_MS}. */
  timeoutMs?: number;
  /** Pass child stdout/stderr through to process.stderr. */
  verbose?: boolean;
  /** Executable that runs the pinned scancode binary. Defaults to "scancode". */
  scancodeBin?: string;
  /** Per-run temp directory; defaults to a fresh mkdtemp under os tmpdir. */
  tempDir?: string;
}

/** A resolved scancode result: the raw expression, its election lane, and copyrights. */
export interface ScancodeResolution {
  raw: string;
  via: string;
  copyrights: string[];
}

/** Cap on copyright lines returned per scanned package (extractor-cap parity). */
const MAX_SCANCODE_COPYRIGHT_LINES = 20;

/** A root-level legal file basename ScanCode's election treats as authoritative. */
const LEGAL_FILE_PATTERN = /^(LICENSE|LICENCE|COPYING|NOTICE)(\..*)?$/i;

/** A package-manifest basename — the election fallback. */
const MANIFEST_FILE_PATTERN = /^(package\.json|METADATA)$/i;

/** True when an elected SPDX expression is ScanCode's own unresolvable-noise id. */
function isLicenseRefNoise(expression: string): boolean {
  return expression.includes("LicenseRef-scancode-");
}

/** One narrowed `files[]` entry we read from scancode's `--json-pp` output. */
interface RawScancodeFile {
  path?: unknown;
  detected_license_expression_spdx?: unknown;
  copyrights?: unknown;
}

/** A narrowed scancode output — only the fields this module reads. */
interface RawScancodeOutput {
  headers?: unknown;
  files?: unknown;
}

/** Stat-gate a scancode output path BEFORE any read or parse (T-10-07). */
export function assertScancodeOutputSize(path: string): void {
  const size = statSync(path).size;
  if (size > MAX_SCANCODE_OUTPUT_BYTES) {
    throw new Error(
      `scancode output at ${path} is ${size} bytes, over the ` +
        `${MAX_SCANCODE_OUTPUT_BYTES}-byte cap — refusing to parse it`,
    );
  }
}

/** Assert the parsed output's headers[0].tool_version matches the pin, naming the invocation on drift. */
function assertScancodeVersion(parsed: unknown, invocation: string): void {
  const headers = (parsed as RawScancodeOutput).headers;
  const toolVersion =
    Array.isArray(headers) && headers.length > 0
      ? (headers[0] as { tool_version?: unknown } | undefined)?.tool_version
      : undefined;
  if (toolVersion !== SCANCODE_TOOL.version) {
    throw new Error(
      `scancode output tool_version is ${JSON.stringify(toolVersion)}, ` +
        `expected ${JSON.stringify(SCANCODE_TOOL.version)} — wrong scancode ` +
        `version?\ninvocation: ${invocation}`,
    );
  }
}

/** Parse + version-assert scancode's `--json-pp` output, naming the invocation on failure. */
function parseScancodeOutput(
  rawOutput: string,
  outFile: string,
  invocation: string,
): RawScancodeOutput {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawOutput);
  } catch (error) {
    throw new Error(
      `scancode output at ${outFile} is not valid JSON: ${String(error)}\n` +
        `invocation: ${invocation}`,
      { cause: error },
    );
  }
  assertScancodeVersion(parsed, invocation);
  return parsed as RawScancodeOutput;
}

/** True iff a raw files[] entry is a well-shaped object we can read fields from. */
function isRawScancodeFile(raw: unknown): raw is RawScancodeFile {
  return typeof raw === "object" && raw !== null;
}

/**
 * True iff a scancode `files[].path` sits directly inside the scanned
 * tree's own root — never a nested/vendored/bundled subdirectory. ScanCode's
 * `--json-pp` paths are forward-slash-separated and always prefixed with
 * the scanned directory's OWN basename (verified live, Plan 02's capture:
 * `ajv/LICENSE`, `ajv/dist/ajv.bundle.js`), so a root-level file has
 * EXACTLY two `/`-segments: `<scanRootBasename>/<filename>`.
 * Backslash-separated paths are defensively rejected too (scancode never
 * emits them; fail closed rather than trust an unexpected separator as
 * root-level).
 *
 * 10-07 adversarial-review finding (Lens 5): election previously matched on
 * `basename(path)` alone with no depth check, so a deeply-nested
 * vendored/bundled dependency's LICENSE — carrying a DIFFERENT, potentially
 * copyleft license — could silently outrank the scanned package's own root
 * license purely by `files[]` array order (scancode's own walk order is
 * not guaranteed root-first). This closes that gap.
 */
function isRootLevelPath(path: string): boolean {
  if (path.includes("\\")) return false;
  return path.split("/").length === 2;
}

/** Elect the first ROOT-LEVEL file entry matching a basename pattern with a non-null, non-noise expression. */
function electFromPattern(
  entries: RawScancodeFile[],
  pattern: RegExp,
  lane: string,
): { raw: string; via: string } | undefined {
  for (const entry of entries) {
    const path = entry.path;
    if (typeof path !== "string") continue;
    if (!isRootLevelPath(path)) continue;
    if (!pattern.test(basename(path))) continue;
    const expression = entry.detected_license_expression_spdx;
    if (typeof expression !== "string" || expression.length === 0) continue;
    if (isLicenseRefNoise(expression)) continue;
    return {
      raw: expression,
      via: `${SCANCODE_TOOL.name}@${SCANCODE_TOOL.version}/${lane}`,
    };
  }
  return undefined;
}

/**
 * Elect ONE raw SPDX expression from the scanned files: a root-level legal
 * file (basename matches {@link LEGAL_FILE_PATTERN}) with a non-null,
 * non-noise expression wins; else the first package-manifest entry
 * ({@link MANIFEST_FILE_PATTERN}) with a non-null, non-noise expression;
 * else undefined (Pattern 2 — never an AND-combine across files). An
 * elected expression containing `LicenseRef-scancode-` is rejected within
 * each lane (treated as no answer there, T-10-09/ADR-0007) rather than
 * accepted as noise — the caller falls through to the next lane, or to a
 * clean no-answer if both lanes reject.
 */
export function electExpression(
  files: unknown,
): { raw: string; via: string } | undefined {
  if (!Array.isArray(files)) return undefined;
  const entries = files.filter(isRawScancodeFile);

  const legal = electFromPattern(entries, LEGAL_FILE_PATTERN, "license-file");
  if (legal !== undefined) return legal;

  return electFromPattern(entries, MANIFEST_FILE_PATTERN, "manifest");
}

/** One narrowed copyrights[] entry. */
interface RawCopyrightEntry {
  copyright?: unknown;
}

/**
 * Collect the union of all `copyrights[].copyright` strings across every
 * scanned file, sanitized via the same control-char intake rule evidence
 * text uses ({@link sanitizeEvidenceText}, merge.ts), deduped,
 * {@link compareCodeUnits}-sorted, and capped at
 * {@link MAX_SCANCODE_COPYRIGHT_LINES}.
 */
export function electCopyrights(files: unknown): string[] {
  if (!Array.isArray(files)) return [];
  const seen = new Set<string>();
  for (const raw of files) {
    if (!isRawScancodeFile(raw)) continue;
    const copyrights = (raw as { copyrights?: unknown }).copyrights;
    if (!Array.isArray(copyrights)) continue;
    for (const entry of copyrights) {
      // Tolerant narrowing, matching the rest of this parse path: a null or
      // mistyped element is skipped, never a TypeError mid-scan.
      if (typeof entry !== "object" || entry === null) continue;
      const text = (entry as RawCopyrightEntry).copyright;
      if (typeof text !== "string" || text.length === 0) continue;
      seen.add(sanitizeEvidenceText(text));
    }
  }
  return [...seen]
    .sort(compareCodeUnits)
    .slice(0, MAX_SCANCODE_COPYRIGHT_LINES);
}

/** True iff an error looks like a spawn-time ENOENT (missing tool binary). */
function isEnoentError(error: unknown): boolean {
  if (error instanceof Error && "code" in error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT";
  }
  return false;
}

/**
 * Run the pinned scancode binary against one source dir, returning the
 * parsed + version-asserted output. Extracted from scanPackageSources to
 * keep that orchestrator under the complexity bound (dockerOs.ts's
 * scanImage/parseSyftOutput split).
 */
async function runScancode(
  sourceDir: string,
  outFile: string,
  scancodeBin: string,
  opts: { timeoutMs: number; verbose: boolean },
): Promise<RawScancodeOutput> {
  const args = scancodeArgs(outFile, sourceDir);
  const invocation = `${scancodeBin} ${args.join(" ")}`;

  try {
    await execTool(scancodeBin, args, opts);
  } catch (error) {
    if (isEnoentError(error)) {
      throw new Error(
        `scancode binary not found on PATH — install it with ` +
          `pipx install "scancode-toolkit[full]==32.5.0"\ninvocation: ${invocation}`,
        { cause: error },
      );
    }
    throw error;
  }

  if (!existsSync(outFile)) {
    throw new Error(
      `scancode produced no output file at ${outFile}\ninvocation: ${invocation}`,
    );
  }
  // Size gate BEFORE read (DoS bound, T-10-07).
  assertScancodeOutputSize(outFile);

  // Read outside the parse try: an I/O failure must surface as itself, not
  // as a misleading "not valid JSON" message (dockerOs.ts idiom).
  const rawOutput = readFileSync(outFile, "utf8");
  return parseScancodeOutput(rawOutput, outFile, invocation);
}

/**
 * Scan one locally-present source dir with the pinned scancode-toolkit CLI
 * and return its elected result, or null on a clean no-answer. Mirrors
 * dockerOs.ts's scanImage/parseSyftOutput skeleton: spawn via execTool (the
 * tool's only child_process seam) -> exists-check -> size-gate BEFORE
 * read -> read -> parse + version-assert -> election. A spawn ENOENT
 * (missing tool) is mapped to the D-01 loud install-command error; any other
 * rejection (non-zero exit, timeout) propagates as-is.
 */
export async function scanPackageSources(
  sourceDir: string,
  opts: ScancodeScanOptions = {},
): Promise<ScancodeResolution | null> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_SCAN_TIMEOUT_MS;
  const verbose = opts.verbose ?? false;
  const scancodeBin = opts.scancodeBin ?? "scancode";
  const tempDir =
    opts.tempDir ?? mkdtempSync(join(tmpdir(), "licenses-scancode-"));
  const outFile = join(tempDir, "scancode-output.json");

  const parsed = await runScancode(sourceDir, outFile, scancodeBin, {
    timeoutMs,
    verbose,
  });

  const elected = electExpression(parsed.files);
  if (elected === undefined) return null;

  return {
    raw: elected.raw,
    via: elected.via,
    copyrights: electCopyrights(parsed.files),
  };
}
