/**
 * The separate clarifications file: TOML text holding `[[clarify]]` tables and nothing else, parsed
 * through the policy's own clarify validator so an entry means there exactly what it means in the
 * policy proper. Its entries are cited in their own id space, numbered within this file, and they
 * are appended AFTER the policy's own, which decides shadowing: every consumer takes the first
 * matching entry, so a policy-file entry wins over an imported one governing the same package.
 *
 * Pure, like parsePolicy: text in, entries out. The caller reads the file and names it.
 */
import { parse as parseToml } from "smol-toml";

import { recordOf } from "../../validate/record";
import { matchesPackage } from "../engine/match";
import { clarifyCitation, validateClarifyTables, type ClarifyRule } from "../schema/clarify";
import { PolicyError } from "../schema/diagnostics";
import type { Policy } from "../schema";

import type { CanonicalDependencies } from "../../model/dependencies";

/** The one table a clarifications file may carry. */
const CLARIFY_TABLE = "clarify";

/**
 * Parse clarifications TOML text into entries carrying the `clarifications` citation space.
 *
 * @throws PolicyError with every semantic problem, including one naming each top-level key that is
 * not `[[clarify]]` - a file that also carried acceptances or knobs would split the policy in two
 * places, and the maintainer tooling that rewrites this file wholesale would drop them.
 */
export function parseClarifications(text: string): ClarifyRule[] {
  const root = recordOf(parseToml(text)) ?? {};
  const problems: string[] = [];

  for (const key of Object.keys(root)) {
    if (key !== CLARIFY_TABLE) {
      problems.push(
        `unknown top-level key "${key}": a clarifications file holds [[clarify]] tables and nothing else`,
      );
    }
  }

  const rules = validateClarifyTables(root[CLARIFY_TABLE], "clarifications", problems);

  if (problems.length > 0) {
    throw new PolicyError(problems);
  }

  return rules;
}

/**
 * {@link parseClarifications} with `path` prefixed onto every problem, including the TOML syntax
 * message: two files are in play, and a problem that names neither leaves the reader guessing which
 * one to open.
 */
export function parseClarificationsAt(path: string, text: string): ClarifyRule[] {
  try {
    return parseClarifications(text);
  } catch (error) {
    if (error instanceof PolicyError) {
      throw new PolicyError(error.problems.map((problem) => `${path}: ${problem}`));
    }

    throw new Error(`${path}: ${(error as Error).message}`, { cause: error });
  }
}

/** An imported entry a policy-file entry decides ahead of, both named by their citations. */
export interface ShadowedClarification {
  /** The policy-file entry that decides. */
  readonly shadowing: string;
  /** The imported entry it leaves nothing for. */
  readonly shadowed: string;
}

/**
 * Imported entries a policy-file entry takes precedence over on some scanned package. Reported
 * rather than rejected: the same imported entry may still decide other packages, and a maintainer
 * comparing the two citations is the one who can say which was meant. The scanned model arrives
 * purl-sorted, so the pairs come out in a stable order.
 */
export function shadowedClarifications(
  model: CanonicalDependencies,
  policy: Policy,
): ShadowedClarification[] {
  const pairs = new Map<string, ShadowedClarification>();

  for (const entry of model.packages) {
    const matching = policy.clarify.filter((rule) => matchesPackage(rule, entry));
    const deciding = matching[0];

    if (deciding === undefined || deciding.identity.space !== "clarify") {
      continue;
    }

    for (const rule of matching.slice(1)) {
      if (rule.identity.space === "clarifications") {
        const pair = { shadowing: clarifyCitation(deciding), shadowed: clarifyCitation(rule) };

        pairs.set(`${pair.shadowing}\u0000${pair.shadowed}`, pair);
      }
    }
  }

  return [...pairs.values()];
}

/** The policy with `imported` appended after its own entries - the order shadowing rests on. */
export function withImportedClarifications(
  policy: Policy,
  imported: ReadonlyArray<ClarifyRule>,
): Policy {
  return { ...policy, clarify: [...policy.clarify, ...imported] };
}
