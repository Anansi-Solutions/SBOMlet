import { recordOf } from "../../validate/record";

import { checkKeys, optionalText } from "./diagnostics";

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

/**
 * Parse the optional [document] table: an absent table yields undefined;
 * a non-table value rejects; an empty table yields {}; title/preamble are each OPTIONAL but, when
 * present, must be a non-empty string (optionalText). Unknown keys reject via checkKeys. Only
 * present-and-valid keys are materialized so the "absent key" state stays observable.
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
  const title = optionalText(table, "title", "document", problems);
  const preamble = optionalText(table, "preamble", "document", problems);

  return {
    ...(title !== undefined ? { title } : {}),
    ...(preamble !== undefined ? { preamble } : {}),
  };
}
