/**
 * Orchestrates the pinned `scancode-toolkit` CLI through `execTool` (the tool's only child_process
 * seam; dockerOs.ts idiom): spawn → exists-check → size-gate BEFORE read → parse → runtime
 * version-assert against {@link SCANCODE_TOOL} from the output's own headers (a substituted/drifted
 * binary is caught). Expression election is two-lane; see {@link electExpression} for the
 * legal-file/manifest precedence and the ADR-0007 no-fabrication rejection.
 *
 * This module NEVER performs SPDX correction or interpretation - the raw expression string is
 * returned verbatim (`{raw, via, copyrights} | null`, the same shape the registry resolvers return
 * at enrich.ts's resolveFromDocument), and `normalizeRaw` stays the single SPDX authority
 * downstream. It never spawns outside `execTool`, and it never writes the cache itself - the single
 * write site stays in enrich.ts.
 */
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { execTool } from "../../collectors/exec";
import { electCopyrights, electExpression } from "./election";
import { SCANCODE_TOOL } from "./tool";

/**
 * DoS bound: real scancode `--json-pp` output for a single npm package tree is well under a MiB
 * even for large packages; 64 MiB is generous headroom, matching MAX_SYFT_SBOM_BYTES's
 * stat-gate-before-read posture. The gate fires before any read/parse.
 */
export const MAX_SCANCODE_OUTPUT_BYTES = 64 * 1024 * 1024;

/**
 * Wall-clock timeout per package scan. ScanCode's OWN per-file `--timeout` stays at its 120s
 * default - deliberately not passed here, since it bounds a single file's matching, not the whole
 * run. 10 minutes is generous headroom for even a large vendored bundle.
 */
export const DEFAULT_SCAN_TIMEOUT_MS = 10 * 60 * 1000;

/**
 * The verified scancode-toolkit 32.5.0 argv. Options first, then a `--` END-OF-OPTIONS separator,
 * then the scanned directory OPERAND last - the dockerOs.ts syftArgs idiom: the source dir is
 * always an argv operand, never a shell string, so command injection is impossible by
 * construction, and the `--` is defense-in-depth against a dash-prefixed
 * path being parsed as a flag. `--license --copyright` requests both detection families;
 * `--json-pp <outFile>` writes deterministic pretty-printed JSON to the per-run temp file. Locked
 * byte-for-byte by an exact-array test - any flag change must consciously break that test.
 */
export function scancodeArgs(outFile: string, sourceDir: string): string[] {
  return ["--license", "--copyright", "--json-pp", outFile, "--", sourceDir];
}

/**
 * Options threading the `--intensive` lane through enrichUnknowns. Present ONLY on
 * `generate --intensive`: check never receives it, and a default generate call never constructs it
 * (the intensive lane is additionally gated on this field's mere presence - enrich.ts). Mirrors the
 * default-to-production/override-in-tests idiom used throughout this tool (EnrichOptions.now?,
 * ScancodeScanOptions.scancodeBin?).
 */
export interface IntensiveOptions {
  /**
   * Candidate roots probed by {@link sourceDirsFor} (compareCodeUnits-sorted, first match wins).
   */
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

/** A narrowed scancode output - only the fields this module reads. */
interface RawScancodeOutput {
  headers?: unknown;
  files?: unknown;
}

/** Stat-gate a scancode output path BEFORE any read or parse (DoS bound). */
export function assertScancodeOutputSize(path: string): void {
  const size = statSync(path).size;
  if (size > MAX_SCANCODE_OUTPUT_BYTES) {
    throw new Error(
      `scancode output at ${path} is ${size} bytes, over the ` +
        `${MAX_SCANCODE_OUTPUT_BYTES}-byte cap — refusing to parse it`,
    );
  }
}

/**
 * Assert the parsed output's headers[0].tool_version matches the pin, naming the invocation on
 * drift.
 */
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

/** True iff an error looks like a spawn-time ENOENT (missing tool binary). */
function isEnoentError(error: unknown): boolean {
  if (error instanceof Error && "code" in error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT";
  }
  return false;
}

/**
 * Run the pinned scancode binary against one source dir, returning the parsed + version-asserted
 * output. Extracted from scanPackageSources to keep that orchestrator under the complexity bound
 * (dockerOs.ts's scanImage/parseSyftOutput split).
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
        `scancode binary not found on PATH — run mise install\ninvocation: ${invocation}`,
        { cause: error },
      );
    }
    // ScanCode exits NON-ZERO when SOME files fail to scan - an undecodable or oversized bundled
    // data file (a vendored full license-list JSON, say) -
    // yet still writes a COMPLETE, well-formed result for the rest of the tree;
    // the file that failed carries no detected expression and is inert to election. Tolerate that
    // ONLY when an output file was produced: the exists-check, the size gate, and the tool_version
    // assertion below are the integrity gate, so a substituted/wrong binary, a truncated write, or
    // a catastrophic failure that left no parseable, correctly-versioned output still throws. With
    // NO output file the failure is real - rethrow the original error unchanged (its stderr tail is
    // the diagnostic).
    if (!existsSync(outFile)) throw error;
  }

  if (!existsSync(outFile)) {
    throw new Error(
      `scancode produced no output file at ${outFile}\ninvocation: ${invocation}`,
    );
  }
  // Size gate BEFORE read (DoS bound).
  assertScancodeOutputSize(outFile);

  // Read outside the parse try: an I/O failure must surface as itself, not as a misleading "not
  // valid JSON" message (dockerOs.ts idiom).
  const rawOutput = readFileSync(outFile, "utf8");
  return parseScancodeOutput(rawOutput, outFile, invocation);
}

/**
 * Scan one locally-present source dir with the pinned scancode-toolkit CLI and return its elected
 * result, or null on a clean no-answer. Mirrors dockerOs.ts's scanImage/parseSyftOutput skeleton:
 * spawn via execTool (the tool's only child_process seam) -> exists-check -> size-gate BEFORE read
 * -> read -> parse + version-assert -> election. A spawn ENOENT (missing tool) is mapped to the
 * loud install-command error; any other

 * rejection (non-zero exit, timeout) propagates as-is.
 *
 * Output-file hygiene: any stale out file is removed BEFORE the spawn, so with a caller-shared
 * tempDir a PREVIOUS scan's output can never masquerade as this scan's result (the exists-check
 * really proves scancode wrote output). Afterwards the out file is removed again - and when this
 * function created the temp dir itself, the whole dir is removed, never leaked one per scanned
 * package per run.
 */
export async function scanPackageSources(
  sourceDir: string,
  opts: ScancodeScanOptions = {},
): Promise<ScancodeResolution | null> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_SCAN_TIMEOUT_MS;
  const verbose = opts.verbose ?? false;
  const scancodeBin = opts.scancodeBin ?? "scancode";
  const ownsTempDir = opts.tempDir === undefined;
  const tempDir =
    opts.tempDir ?? mkdtempSync(join(tmpdir(), "licenses-scancode-"));
  const outFile = join(tempDir, "scancode-output.json");
  rmSync(outFile, { force: true });

  try {
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
  } finally {
    if (ownsTempDir) rmSync(tempDir, { recursive: true, force: true });
    else rmSync(outFile, { force: true });
  }
}
