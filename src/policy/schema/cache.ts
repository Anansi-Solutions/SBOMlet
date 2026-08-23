import { type } from "arktype";

import { recordOf } from "../../validate/record";

import { collectArkProblems, nonBlankString } from "./arkAdapter";
import { checkKeys } from "./diagnostics";
import { repoRelativePath } from "./scope";

export interface CacheConfig {
  /** Repo-root-relative dir for committed artifacts; default applies when absent. */
  dir?: string;
}

/**
 * The optional, non-empty `dir`: a repo-root-relative forward-slash path (no "..", no
 * leading/trailing slash), so a committed artifact directory can never escape the repo. The path
 * rules ride the shared {@link repoRelativePath} morph.
 */
const cacheShape = type({ "dir?": nonBlankString.to(repoRelativePath) });

/**
 * Parse the optional [cache] table: an absent table yields undefined; a non-table rejects; a
 * present table with no `dir` yields {} (the default applies later). A malformed `dir` drops to {}
 * after recording the aggregated PolicyError naming cache.dir.
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

  return result.dir === undefined ? {} : { dir: result.dir };
}
