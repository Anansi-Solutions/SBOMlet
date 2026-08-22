import { recordOf } from "../../validate/record";

import { checkKeys, requireText } from "./diagnostics";
import { validatePath } from "./scope";

export interface CacheConfig {
  /** Repo-root-relative dir for committed artifacts; default applies when absent. */
  dir?: string;
}

/**
 * Parse the optional [cache] table: an absent table yields undefined; a non-table rejects; a
 * present table with no `dir` yields {} (the default applies later). `dir`, when present, must be a
 * non-empty repo-root-relative forward-slash path (validatePath: no "..", no leading/trailing
 * slash), so a committed artifact directory can never escape the repo. A malformed `dir` drops to
 * {} after recording the aggregated PolicyError naming cache.dir.
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
  if (!("dir" in table)) {
    return {};
  }

  const dir = requireText(table, "dir", "cache", problems);

  if (dir === undefined) {
    return {};
  }

  const before = problems.length;

  validatePath(dir, "cache.dir", problems);
  if (problems.length !== before) {
    return {};
  }

  return { dir };
}
