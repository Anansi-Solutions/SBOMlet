/**
 * Resolves the exception a license label states (`with the Classpath Exception`) to the one
 * registered SPDX exception id it names, from the words of the registered ids themselves.
 */
import { CANONICAL_EXCEPTION_ID } from "./spdxCasing";

/** What a registered exception id names: `GCC-exception-3.1` is the word gcc at version 3.1. */
export interface RegisteredExceptionTerms {
  /** The id's lowercased words other than `exception` and its version: `u-boot` is u and boot. */
  words: readonly string[];
  /** The exception's version without trailing `.0`; absent when the id states none. */
  version?: string;
}

/** A version token: `2.0`, `v1.0`, `2005`. */
const VERSION_TOKEN = /^v?(\d+(?:\.\d+)*)$/;

/** One word or version of a label: `Exception,` is exception, `v1.0` is v1.0. */
const LABEL_TOKEN = /[a-z0-9]+(?:\.\d+)*/g;

/** A version token without its `v` and trailing `.0` (`v2.0` is 2), or undefined for a word. */
function versionOf(token: string): string | undefined {
  return VERSION_TOKEN.exec(token)?.[1]?.replace(/(?:\.0)+$/, "");
}

/**
 * The words and version a registered exception id names. The version is the number right after
 * `exception`, else a trailing number; any other number is a word (`389-exception` is the word 389,
 * `GPL-3.0-linking-exception` the words gpl, 3 and linking).
 */
export function registeredExceptionTerms(id: string): RegisteredExceptionTerms {
  const tokens = id.toLowerCase().split("-");
  const marker = tokens.indexOf("exception");
  const versionAt = [marker + 1, tokens.length - 1].find(
    (at) => at > 0 && versionOf(tokens[at] ?? "") !== undefined,
  );
  const words = tokens
    .filter((token, at) => token !== "exception" && at !== versionAt)
    .map((token) => versionOf(token) ?? token);
  const version = versionAt === undefined ? undefined : versionOf(tokens[versionAt]!);

  return version === undefined ? { words } : { words, version };
}

const wordsKey = (words: readonly string[]): string => [...words].sort().join(" ");

const REGISTERED_EXCEPTIONS = [...new Set(CANONICAL_EXCEPTION_ID.values())].map((id) => ({
  id,
  ...registeredExceptionTerms(id),
}));

/** How many registered ids share each set of words: two for gcc (2.0 and 3.1), one for llvm. */
const IDS_SHARING_WORDS = REGISTERED_EXCEPTIONS.reduce(
  (counts, { words }) => counts.set(wordsKey(words), (counts.get(wordsKey(words)) ?? 0) + 1),
  new Map<string, number>(),
);

/**
 * The one registered exception id `phrase` names, or undefined when it names none or several. An id
 * matches when the phrase holds all its words and, if the phrase states a version, that version is
 * the id's; with no stated version, an id matches only when no other id has its words, so an
 * unversioned GCC exception names neither GCC-exception-2.0 nor GCC-exception-3.1.
 */
export function registeredExceptionNamedBy(phrase: string): string | undefined {
  const tokens = new Set(
    Array.from(phrase.toLowerCase().matchAll(LABEL_TOKEN), ([token]) => versionOf(token) ?? token),
  );
  const versions = [...tokens].filter((token) => versionOf(token) !== undefined);
  const matches = REGISTERED_EXCEPTIONS.filter(({ words, version }) => {
    const stated = versions.filter((v) => !words.includes(v));

    if (!words.every((word) => tokens.has(word))) {
      return false;
    }

    return stated.length > 0
      ? version !== undefined && stated.includes(version)
      : IDS_SHARING_WORDS.get(wordsKey(words)) === 1;
  });

  return matches.length === 1 ? matches[0]!.id : undefined;
}
