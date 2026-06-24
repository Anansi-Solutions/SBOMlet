/**
 * The check CI gate: the same write-free pipeline as generate, byte-compared
 * against the committed files instead of written. exitCodeFor's
 * violation-beats-stale mapping is the only producer of exit codes 1 and 2.
 */

import { readFileSync } from "node:fs";

import { resolveFrom } from "../pipeline/paths";
import { buildOutputs, type GenerateOptions } from "../pipeline/pipeline";
import { sanitizeForLog } from "../pipeline/summary";

/** Structured check outcome — the only source of exit codes 1 and 2. */
export interface CheckResult {
  /** Count of fail verdicts (zero when no policy was loaded). */
  violations: number;
  /** Configured output paths whose committed bytes are stale or missing. */
  staleFiles: string[];
}

/**
 * check = the same write-free pipeline as generate, compared instead of
 * written: buildOutputs renders every configured output in memory, then each
 * committed file is read once, defensively CRLF->LF normalized (unpinned
 * consumer checkouts with core.autocrlf=true hand us CRLF on read), and
 * byte-compared against the in-memory render. Both comparison sides come from
 * one buildOutputs call — the in-memory string is what generate would write —
 * so there is no regenerate/compare TOCTOU window and nothing fresh is ever
 * round-tripped through disk.
 *
 * A missing/unreadable committed file is stale (a never-generated output is
 * stale by definition) — consciously diverging from the policy-file read
 * idiom, which throws: a missing policy is a config error (3), a missing
 * output is exactly what exit 2 reports.
 *
 * runCheck never writes files: --dump-model is rejected as a config error, so
 * the gate cannot overwrite the files it verifies.
 */
export async function runCheck(opts: GenerateOptions): Promise<CheckResult> {
  if (opts.dumpModelPath !== undefined) {
    throw new Error(
      "check performs no writes — --dump-model is only valid on generate",
    );
  }
  // Force check mode so the ENRICH stage NEVER fetches or writes: a miss that
  // needs enrichment is a stale condition (exit 2), never a network call. This
  // is the GATE-02 zero-network clause — buildOutputs stays hermetic against
  // the committed cache. (runGenerate forces generate; the shared optionsFrom
  // stays mode-neutral, so the subcommand decides.)
  const outputs = await buildOutputs({ ...opts, mode: "check" });

  // The comparison set reads the same base-dir-resolved paths generate writes:
  // a relative CYCLONEDX var must never make check "verify" a file at a
  // different location than the one the user committed.
  const pairs: Array<[path: string, rendered: string]> = [
    [resolveFrom(opts.baseDir, opts.outputPath), outputs.licensesMd],
    [resolveFrom(opts.baseDir, opts.noticesPath), outputs.noticesMd],
  ];
  if (opts.cyclonedxPath !== undefined && outputs.cyclonedxJson !== undefined) {
    pairs.push([
      resolveFrom(opts.baseDir, opts.cyclonedxPath),
      outputs.cyclonedxJson,
    ]);
  }

  // Locked stderr report shapes; every path through sanitizeForLog.
  const staleFiles: string[] = [];
  for (const [path, rendered] of pairs) {
    let committed: string;
    try {
      committed = readFileSync(path, "utf8");
    } catch {
      staleFiles.push(path);
      process.stderr.write(`check stale: ${sanitizeForLog(path)} is missing\n`);
      continue;
    }
    // Normalize the committed text only: the in-memory render is LF by
    // construction and never touches disk on the comparison path.
    if (committed.replaceAll("\r\n", "\n") !== rendered) {
      staleFiles.push(path);
      process.stderr.write(
        `check stale: ${sanitizeForLog(path)} differs from generated output\n`,
      );
    }
  }

  // A miss-needing-enrichment with no committed cache entry is stale by the
  // same logic as a missing output: check cannot fetch it, so the committed
  // cache is out of date. Name the purl and the regenerate remedy (Pitfall 2 /
  // GATE-02). These join staleFiles so exitCodeFor maps them to exit 2.
  for (const purl of outputs.staleUnknowns) {
    staleFiles.push(purl);
    process.stderr.write(
      `check stale: ${sanitizeForLog(purl)} needs enrichment — ` +
        `run task licenses:generate to refresh the committed cache\n`,
    );
  }

  // Fail-verdict count (zero without a policy): warn/suppressed/ok never gate;
  // the policy summary printed inside buildOutputs already carries the
  // fail/warn/unused-entry lines.
  const violations = (outputs.verdicts ?? []).filter(
    (verdict) => verdict.status === "fail",
  ).length;

  if (staleFiles.length === 0) {
    process.stderr.write(`check: ok (${pairs.length} outputs verified)\n`);
  }
  return { violations, staleFiles };
}

/**
 * The only mapping from a check outcome to exit codes 1 and 2: any fail
 * verdict beats stale; exceptions never reach this function — they propagate
 * to main's catch -> fail() -> 3.
 */
export function exitCodeFor(result: CheckResult): number {
  if (result.violations > 0) return 1;
  if (result.staleFiles.length > 0) return 2;
  return 0;
}
