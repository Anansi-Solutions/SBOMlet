import { type } from "arktype";

import { recordOf } from "../../validate/record";

import { collectArkProblems, nonBlankString } from "./arkAdapter";
import { checkKeys } from "./diagnostics";
import { repoRelativePath, repoRelativePathRejectingDocker } from "./scope";

/**
 * One [[docker.development]] entry: marks every container whose Dockerfile identity matches
 * `source` as development-only (never shipped).
 */
export interface DockerDevelopmentEntry {
  /**
   * Repo-relative glob over Dockerfile identities, in the EXACT same dialect as `[docker].ignore`
   * (globToRegExp in targets/discover.ts: `*` within a segment, `**` across segments,
   * case-insensitive, anchored - a literal path is a valid glob). Here the pattern is only
   * validated and stored verbatim; matching against discovered containers happens where the report
   * is rendered. A matching container's packages are listed under Development-only in the report
   * - placement only, it never affects a verdict.
   */
  source: string;
  /** Mandatory documentation: why this container never ships. */
  reason: string;
}

/**
 * The optional [docker] table: Dockerfile-discovery exclusion globs plus per-container development
 * marking. When `generate-docker-sbom --repo-root` discovers Dockerfiles, every Dockerfile whose
 * repo-relative forward-slash identity matches an `ignore` glob is EXCLUDED ENTIRELY - its base
 * image is never derived, never scanned. `ignore` defaults to [] when the [docker] table is present
 * without the key, and the whole table is undefined when absent. Each glob is validated with the
 * SAME posture as suppression paths (forward slashes only, no ".." segments, no leading/trailing
 * slash) so a crafted glob can never escape the repo namespace. `development` defaults to [] the
 * same way; every analyzed container is production unless a `[[docker.development]]` entry's
 * `source` glob matches it - the conservative default.
 */
export interface DockerConfig {
  /** Repo-relative forward-slash globs; a matching Dockerfile is excluded. */
  ignore: ReadonlyArray<string>;
  /** Per-container development marking; absent key defaults to []. */
  development: ReadonlyArray<DockerDevelopmentEntry>;
}

/**
 * The two required fields of a `[[docker.development]]` entry. `source` rides the shared
 * repo-relative-path morph, additionally forbidding a "docker:" prefix (the table already scopes
 * the Dockerfile identity; the prefix would double up and could never match); `reason` is mandatory
 * documentation. A duplicate `source` is caught cross-entry against `seen`, not here.
 */
const developmentEntry = type({
  source: nonBlankString.to(
    repoRelativePathRejectingDocker(
      (source) =>
        `source "${source}" must not start with "docker:" (the table already scopes the Dockerfile identity; the prefix would double up and could never match)`,
    ),
  ),
  reason: nonBlankString,
});

/**
 * Parse one [[docker.development]] entry: its declarative shape validates `source` and `reason`;
 * `seen` collects already-accepted source strings so a duplicate pattern - silently dead, since
 * only the first entry could ever decide anything - is rejected cross-entry.
 */
function validateDockerDevelopmentEntry(
  rawEntry: unknown,
  where: string,
  seen: Set<string>,
  problems: string[],
): DockerDevelopmentEntry | undefined {
  const entry = recordOf(rawEntry);

  if (entry === undefined) {
    problems.push(`${where}: must be a table`);
    return undefined;
  }

  checkKeys(entry, ["source", "reason"], where, problems);

  const envelope = developmentEntry(entry);

  if (envelope instanceof type.errors) {
    problems.push(...collectArkProblems(envelope, where));
    return undefined;
  }

  const { source, reason } = envelope;

  if (seen.has(source)) {
    problems.push(
      `${where}: source "${source}" duplicates an earlier [[docker.development]] entry (the first match wins; the duplicate would be dead)`,
    );
    return undefined;
  }

  seen.add(source);
  return { source, reason };
}

/**
 * Parse the optional `development` array inside [docker]: each entry marks a glob-matched container
 * as development-only. Absent → []. Every malformed
 * entry pushes the aggregated PolicyError message naming docker.development[i];
 * only fully-valid entries materialize.
 */
function validateDockerDevelopment(
  table: Record<string, unknown>,
  problems: string[],
): DockerDevelopmentEntry[] {
  if (!("development" in table)) {
    return [];
  }

  const raw = table["development"];

  if (!Array.isArray(raw)) {
    problems.push("docker.development: must be an array of tables ([[docker.development]])");
    return [];
  }

  const development: DockerDevelopmentEntry[] = [];
  const seen = new Set<string>();

  raw.forEach((rawEntry, index) => {
    const entry = validateDockerDevelopmentEntry(
      rawEntry,
      `docker.development[${index}]`,
      seen,
      problems,
    );

    if (entry !== undefined) {
      development.push(entry);
    }
  });
  return development;
}

/**
 * Each `ignore` glob: a non-empty repo-relative forward-slash path, checked by the shared morph.
 */
const ignoreGlobs = nonBlankString.to(repoRelativePath).array();

export function validateDocker(
  root: Record<string, unknown>,
  problems: string[],
): DockerConfig | undefined {
  if (!("docker" in root)) {
    return undefined;
  }

  const table = recordOf(root["docker"]);

  if (table === undefined) {
    problems.push("docker: must be a table ([docker])");
    return undefined;
  }

  checkKeys(table, ["ignore", "development"], "docker", problems);
  const development = validateDockerDevelopment(table, problems);

  if (!("ignore" in table)) {
    return { ignore: [], development };
  }

  const raw = table["ignore"];

  if (!Array.isArray(raw)) {
    problems.push("docker.ignore: must be an array of strings");
    return { ignore: [], development };
  }

  const result = ignoreGlobs(raw);

  if (result instanceof type.errors) {
    problems.push(...collectArkProblems(result, "docker.ignore"));
    return { ignore: [], development };
  }

  return { ignore: [...result], development };
}
