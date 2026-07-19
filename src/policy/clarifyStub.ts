/**
 * Deterministic, fully-commented `[[clarify]]` stub renderer for url-only
 * honest-unknown packages (see pipeline/suggestClarifications.ts, the
 * read-only caller). One entry per DISTINCT observed licenseUrl, packages
 * sorted by name then version, groups sorted by url — every line is a
 * TOML comment, so pasting the output verbatim into a policy changes nothing
 * until a human uncomments it and fills in `expression`/`reason` (parsePolicy's
 * existing requireText then enforces that loudly). `runtime.*` packages (a
 * structural name-prefix, never a curated list) split into their own
 * "review separately" entry per url group, after the likely-library entry.
 * `evidence_url` is pre-filled ONLY when the group's own observed url already
 * parses as an immutable GitHub blob permalink — otherwise a fill-me
 * placeholder, mirroring the schema's own permalink instruction text. The
 * tool states facts (name, version, the verbatim observed url); it never
 * fabricates or auto-decides a license.
 */
import { compareCodeUnits } from "../model/dependencies";
import { parseGithubBlobPermalink } from "../validate/githubPermalink";

/** One url-only honest-unknown candidate: name/version plus its verbatim observed licenseUrl. */
export interface ClarifyStubCandidate {
  name: string;
  version: string;
  /** The verbatim registry-observed licenseUrl — never redirected or altered. */
  url: string;
}

/** The structural native-asset prefix (never a curated package list). */
const RUNTIME_PREFIX = "runtime.";

/** Any C0/C1 control character — the injection-guard posture used tool-wide. */
// eslint-disable-next-line no-control-regex -- deliberate control-character class: reject, never emit
const CONTROL_CHAR = /[\x00-\x1f\x7f]/;

/**
 * Reject any candidate whose name/version/url carries a control character —
 * loud, nothing emitted — before any output is built.
 */
function assertNoControlChars(
  candidates: ReadonlyArray<ClarifyStubCandidate>,
): void {
  for (const candidate of candidates) {
    for (const field of [candidate.name, candidate.version, candidate.url]) {
      if (CONTROL_CHAR.test(field)) {
        throw new Error(
          `clarify stub candidate carries a control character in ${JSON.stringify(field)} — refusing to emit`,
        );
      }
    }
  }
}

/** Escape a value as a TOML basic string body (backslash, then quote). */
function tomlString(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function comparePackage(
  a: ClarifyStubCandidate,
  b: ClarifyStubCandidate,
): number {
  return (
    compareCodeUnits(a.name, b.name) || compareCodeUnits(a.version, b.version)
  );
}

/** Group candidates by their verbatim observed url, insertion order within each group. */
function groupByUrl(
  candidates: ReadonlyArray<ClarifyStubCandidate>,
): Map<string, ClarifyStubCandidate[]> {
  const groups = new Map<string, ClarifyStubCandidate[]>();
  for (const candidate of candidates) {
    const members = groups.get(candidate.url) ?? [];
    members.push(candidate);
    groups.set(candidate.url, members);
  }
  return groups;
}

/**
 * One fully-commented `[[clarify]]` block for ONE bucket (library or
 * wraps-native-code) of ONE url group. Every line is prefixed `# ` so a
 * human can activate the whole block by stripping that exact prefix; the
 * observed-url reference line is double-commented (`# # `) so it survives
 * activation as a plain TOML comment rather than becoming live syntax.
 */
function renderEntry(
  url: string,
  packages: ReadonlyArray<ClarifyStubCandidate>,
  banner: string | undefined,
): string {
  const evidenceUrl = parseGithubBlobPermalink(url) !== null ? url : undefined;
  const lines: string[] = [];
  if (banner !== undefined) lines.push(`# ${banner}`);
  lines.push("# [[clarify]]");
  lines.push("# packages = [");
  for (const pkg of [...packages].sort(comparePackage)) {
    lines.push(
      `#   { name = ${tomlString(pkg.name)}, version = ${tomlString(pkg.version)} },`,
    );
  }
  lines.push("# ]");
  lines.push(`# # observed licenseUrl (verbatim, unfollowed): ${url}`);
  lines.push(
    "# # expression: read the evidence at the url above and set the SPDX expression yourself — this tool never decides a license",
  );
  lines.push('# expression = "FILL-ME-IN"');
  lines.push("# # reason: cite exactly what you read and where");
  lines.push('# reason = "FILL-ME-IN"');
  if (evidenceUrl === undefined) {
    lines.push(
      '# # evidence_url: an immutable GitHub blob permalink — open the file on github.com and press "y" to get one',
    );
    lines.push('# evidence_url = "FILL-ME-IN"');
  } else {
    lines.push(
      "# # evidence_url: the observed url is already an immutable GitHub blob permalink",
    );
    lines.push(`# evidence_url = ${tomlString(evidenceUrl)}`);
  }
  return lines.join("\n");
}

/**
 * Render the fully-commented, deterministic `[[clarify]]` stub set for a
 * candidate list. Empty input yields an empty string (the caller decides
 * what "nothing to suggest" means for its own channel).
 *
 * @throws if any candidate's name/version/url carries a control character.
 */
export function renderClarifyStubs(
  candidates: ReadonlyArray<ClarifyStubCandidate>,
): string {
  assertNoControlChars(candidates);
  const groups = [...groupByUrl(candidates)].sort((a, b) =>
    compareCodeUnits(a[0], b[0]),
  );
  const entries: string[] = [];
  for (const [url, members] of groups) {
    const library = members.filter((m) => !m.name.startsWith(RUNTIME_PREFIX));
    const native = members.filter((m) => m.name.startsWith(RUNTIME_PREFIX));
    if (library.length > 0) entries.push(renderEntry(url, library, undefined));
    if (native.length > 0) {
      entries.push(
        renderEntry(
          url,
          native,
          "wraps native code — review separately, package by package",
        ),
      );
    }
  }
  if (entries.length === 0) return "";
  return entries.join("\n\n") + "\n";
}
