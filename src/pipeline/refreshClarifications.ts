/**
 * The refresh-clarifications run wrapper. Builds the model exactly as check does - offline, no
 * fetch, no cache write - reads the three maintainer lanes off it, and, when asked, rewrites the
 * imported clarifications file and nothing else. The policy proper is never touched: a droppable
 * entry written there comes back as a suggestion for a person to act on.
 *
 * The write is guarded twice. A file carrying `#` comments is left alone, because the parser
 * discarded them before the entries were ever seen and the rewrite could not put them back - a
 * guard raised only where there is a rewrite to raise it over. The new text must also read back as
 * the entries it was built from, or {@link emitClarifications} raises before anything reaches the
 * disk.
 */
import { readFileSync, writeFileSync } from "node:fs";

import {
  refreshFindings,
  rewriteClarifications,
  type ClarificationsRewrite,
  type RefreshFindings,
} from "../maintain/refreshClarifications";
import { rewriteWouldDropText } from "../maintain/tomlEmit";
import { buildOutputs, clarificationsFilePath } from "./pipeline";
import { defaultNoticesPath } from "./paths";

import type { ClarifyRule } from "../policy/schema";

/** Where the licenses document would go; nothing is written, but the renderer names a path. */
const UNWRITTEN_OUTPUT = "THIRD_PARTY_LICENSES.md";

export interface RefreshClarificationsOptions {
  /** Base dir for resolving the repo root and the policy path. */
  baseDir?: string;
  /** Scanned repo root - anchors target discovery and the clarifications path. */
  repoRoot?: string;
  /** Single-target debugging, exactly as generate reads it. */
  targetArg?: string;
  excludes?: string[];
  /** The policy to refresh; required, since the entries live in it. */
  policyPath?: string;
  enrichmentCachePath?: string;
  scancodeCachePath?: string;
  verbose: boolean;
  /** Apply what was ascertained to the imported file, rather than only reporting it. */
  write: boolean;
}

export interface RefreshClarificationsResult {
  readonly findings: RefreshFindings;
  /** Whether the run was asked to apply what it found, which decides how the report closes. */
  readonly writeRequested: boolean;
  /** The imported file, when the policy declares one. */
  readonly clarificationsPath?: string;
  /** What was applied, when the run was asked to write and had something to write. */
  readonly applied?: ClarificationsRewrite;
  /** Why a requested write was refused; the file is untouched. */
  readonly refused?: string;
}

/** The entries that came from the imported file, in the order it wrote them. */
function importedEntries(clarify: ReadonlyArray<ClarifyRule>): ClarifyRule[] {
  return clarify.filter((rule) => rule.identity.space === "clarifications");
}

/**
 * Apply the findings to the imported file, or leave it alone. A policy declaring no imported file
 * has nothing machine-owned to rewrite, so its entries stay suggestions; a file carrying prose
 * outside the entries is refused, because the rewrite could not put that prose back.
 *
 * The rewrite is computed first, so the refusal is raised only over a rewrite there is. A run with
 * nothing to apply would otherwise report a refusal - and exit 3 - for a file it was never going to
 * touch, which reads as a failure where the entries are simply up to date.
 */
function applyToFile(
  path: string | undefined,
  imported: ReadonlyArray<ClarifyRule>,
  findings: RefreshFindings,
): Pick<RefreshClarificationsResult, "applied" | "refused"> {
  if (path === undefined) {
    return {};
  }

  const rewrite = rewriteClarifications(imported, findings);

  if (rewrite === undefined) {
    return {};
  }

  if (rewriteWouldDropText(readFileSync(path, "utf8"), imported)) {
    return {
      refused:
        `${path} carries # comments a rewrite would destroy — move that prose into an entry's ` +
        "comment or evidence field first",
    };
  }

  writeFileSync(path, rewrite.text);
  return { applied: rewrite };
}

/**
 * @throws Error when no policy was given or found - there would be no entries to refresh - and
 * whatever the pipeline raises for an unreadable or invalid one.
 */
export async function runRefreshClarifications(
  opts: RefreshClarificationsOptions,
): Promise<RefreshClarificationsResult> {
  if (opts.policyPath === undefined) {
    throw new Error(
      "refresh-clarifications needs a policy: pass --policy <path>, or keep a " +
        ".sbomlet.policy.toml at the repo root",
    );
  }

  const outputs = await buildOutputs({
    targetArg: opts.targetArg,
    repoRoot: opts.repoRoot,
    excludes: opts.excludes,
    outputPath: UNWRITTEN_OUTPUT,
    noticesPath: defaultNoticesPath(UNWRITTEN_OUTPUT),
    policyPath: opts.policyPath,
    baseDir: opts.baseDir,
    enrichmentCachePath: opts.enrichmentCachePath,
    scancodeCachePath: opts.scancodeCachePath,
    verbose: opts.verbose,
  });
  const policy = outputs.policy;

  if (policy === undefined) {
    throw new Error(`policy file produced no policy: ${opts.policyPath}`);
  }

  const findings = refreshFindings(
    outputs.model,
    policy,
    outputs.verdicts ?? [],
    outputs.usedClarifyIndices,
  );
  const path = clarificationsFilePath(opts, policy);

  return {
    findings,
    writeRequested: opts.write,
    ...(path !== undefined ? { clarificationsPath: path } : {}),
    ...(opts.write ? applyToFile(path, importedEntries(policy.clarify), findings) : {}),
  };
}
