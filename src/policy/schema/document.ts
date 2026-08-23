import { type } from "arktype";

import { recordOf } from "../../validate/record";

import { collectArkProblems } from "./arkAdapter";
import { checkKeys } from "./diagnostics";
import { nonEmptyString } from "./scalars";

/**
 * The optional [document] table: author-supplied presentation prose for the LICENSES document only
 * (never the notices companion). Both keys are OPTIONAL; when present each must be a non-empty
 * string. The render layer treats `title` as a heading and `preamble` as verbatim author markdown
 * - both at the policy-file trust boundary, so neither is escapeCell'd.
 */
export interface DocumentConfig {
  /** Replaces the default "Third-Party Licenses" H1 when present. */
  title?: string;
  /** Verbatim markdown block rendered below the auto-generated header. */
  preamble?: string;
}

/** Both keys optional; each, when present, a non-empty string. */
const documentShape = type({ "title?": nonEmptyString, "preamble?": nonEmptyString });

/**
 * Parse the optional [document] table: an absent table yields undefined; a non-table value rejects;
 * an empty table yields {}; title/preamble are each OPTIONAL but, when present, must be a non-empty
 * string. Unknown keys reject via checkKeys. Only present-and-valid keys are materialized so the
 * "absent key" state stays observable.
 */
export function validateDocument(
  root: Record<string, unknown>,
  problems: string[],
): DocumentConfig | undefined {
  if (!("document" in root)) {
    return undefined;
  }

  const table = recordOf(root["document"]);

  if (table === undefined) {
    problems.push("document: must be a table ([document])");
    return undefined;
  }

  checkKeys(table, ["title", "preamble"], "document", problems);

  const result = documentShape(table);

  if (result instanceof type.errors) {
    problems.push(...collectArkProblems(result, "document"));
    return {};
  }

  return {
    ...(result.title !== undefined ? { title: result.title } : {}),
    ...(result.preamble !== undefined ? { preamble: result.preamble } : {}),
  };
}
