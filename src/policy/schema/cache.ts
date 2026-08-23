import { type } from "arktype";

import { recordOf } from "../../validate/record";

import { collectArkProblems, formatProblems } from "./arkAdapter";
import { checkKeys } from "./diagnostics";
import { nonEmptyString } from "./scalars";
import { pathProblems } from "./scope";

export interface CacheConfig {
  /** Repo-root-relative dir for committed artifacts; default applies when absent. */
  dir?: string;
}

/** The optional, non-empty `dir`; its path segments are checked separately. */
const cacheShape = type({ "dir?": nonEmptyString });

/**
 * Parse the optional [cache] table: an absent table yields undefined; a non-table rejects; a
 * present table with no `dir` yields {} (the default applies later). `dir`, when present, must be a
 * non-empty repo-root-relative forward-slash path (no "..", no leading/trailing slash), so a
 * committed artifact directory can never escape the repo. A malformed `dir` drops to {} after
 * recording the aggregated PolicyError naming cache.dir.
 */
export function validateCache(
  root: Record<string, unknown>,
  problems: string[],
): CacheConfig | undefined {
  if (!("cache" in root)) {
    return undefined;
  }

  const table = recordOf(root["cache"]);

  if (table === undefined) {
    problems.push("cache: must be a table ([cache])");
    return undefined;
  }

  checkKeys(table, ["dir"], "cache", problems);

  const result = cacheShape(table);

  if (result instanceof type.errors) {
    problems.push(...collectArkProblems(result, "cache"));
    return {};
  }

  if (result.dir === undefined) {
    return {};
  }

  const dirProblems = pathProblems(result.dir).map((message) => ({ path: ["dir"], message }));

  if (dirProblems.length > 0) {
    problems.push(...formatProblems("cache", dirProblems));
    return {};
  }

  return { dir: result.dir };
}
