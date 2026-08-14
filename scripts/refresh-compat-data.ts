/**
 * Maintainer-only refresh for the vendored license-compatibility snapshots.
 *
 * Run via `task compat:data:refresh` (never CI, never `task check`). Downloads the three fixed
 * upstream files, validates them with the SAME narrows the loader (src/policy/compat/data.ts) uses
 * - so a file this script accepts is guaranteed to load - plus the structural assertions and size
 * gates below, runs the inter-tier disagreement gate, prints a diff summary against the currently
 * committed snapshots, and only then overwrites the committed files and regenerates PROVENANCE.md.
 * A validation failure at any step leaves every committed file untouched: this script writes
 * nothing until all three downloads have separately passed every check.
 *
 * The pure validation/diff/render functions below are exported and exercised directly by
 * test/compatData.test.ts; only the network fetch and the file writes are untested shell.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  narrowOsadlCopyleftClass,
  narrowOsadlMatrix,
  narrowScancodeCategory,
  OSADL_COPYLEFT_CLASS,
  OSADL_MATRIX,
  OSADL_SNAPSHOT_TIMESTAMP,
  SCANCODE_CATEGORY,
  type OsadlCopyleftClass,
  type OsadlMatrixCell,
} from "../src/policy/compat/data";
import { interTierDisagreements } from "../src/policy/compat/consistency";

const OSADL_TIMESTAMP_URL = "https://www.osadl.org/fileadmin/checklists/timestamp";
const OSADL_MATRIX_URL = "https://www.osadl.org/fileadmin/checklists/matrix.json";
const OSADL_COPYLEFT_URL = "https://www.osadl.org/fileadmin/checklists/copyleft.json";
const SCANCODE_INDEX_URL = "https://scancode-licensedb.aboutcode.org/index.json";

const COMPAT_DIR = join(import.meta.dir, "..", "src", "policy", "compat");
const MATRIX_PATH = join(COMPAT_DIR, "osadl-matrix.json");
const COPYLEFT_PATH = join(COMPAT_DIR, "osadl-copyleft.json");
const SCANCODE_PATH = join(COMPAT_DIR, "scancode-licensedb-index.json");
const PROVENANCE_PATH = join(COMPAT_DIR, "PROVENANCE.md");
const DATA_TS_PATH = join(COMPAT_DIR, "data.ts");

const compareCodeUnits = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Byte-length acceptance window for a downloaded file - a truncated fetch or an HTML error page
 * (a maintenance banner, a 404 page) never overwrites a committed snapshot. */
export interface SizeGate {
  readonly label: string;
  readonly minBytes: number;
  readonly maxBytes: number;
}

export const SIZE_GATES = {
  matrix: { label: "osadl-matrix.json", minBytes: 100_000, maxBytes: 1_000_000 },
  copyleft: { label: "osadl-copyleft.json", minBytes: 1_000, maxBytes: 50_000 },
  scancode: { label: "scancode-licensedb-index.json", minBytes: 100_000, maxBytes: 5_000_000 },
} as const satisfies Record<string, SizeGate>;

/** Throw if a downloaded file's byte length falls outside its size gate. */
export function assertWithinSizeGate(byteLength: number, gate: SizeGate): void {
  if (byteLength < gate.minBytes || byteLength > gate.maxBytes) {
    throw new Error(
      `${gate.label}: downloaded ${byteLength} bytes, outside the expected ` +
        `${gate.minBytes}-${gate.maxBytes} byte range - refusing to write (truncated download, or ` +
        `an HTML error page instead of the JSON payload?)`,
    );
  }
}

/**
 * Structural assertions (A5) on the DOWNLOADED, already-narrowed data: a matrix that stopped being
 * square, or a row/entry count outside the expected range, means the upstream FORMAT changed - this
 * must fail the refresh loudly rather than silently reshape the loader's contract.
 */
export function assertStructuralShape(
  matrix: ReadonlyMap<string, ReadonlyMap<string, OsadlMatrixCell>>,
  copyleftClass: ReadonlyMap<string, OsadlCopyleftClass>,
  scancodeCategory: ReadonlyMap<string, string>,
): void {
  if (matrix.size < 100 || matrix.size > 200) {
    throw new Error(`osadl-matrix.json: ${matrix.size} rows, outside the expected 100-200 range`);
  }

  const rowIds = new Set(matrix.keys());

  for (const [leading, row] of matrix) {
    if (row.size !== rowIds.size || [...row.keys()].some((id) => !rowIds.has(id))) {
      throw new Error(`osadl-matrix.json: row "${leading}" is not square with the other rows`);
    }
  }

  if (copyleftClass.size < 100 || copyleftClass.size > 300) {
    throw new Error(
      `osadl-copyleft.json: ${copyleftClass.size} entries, outside the expected 100-300 range`,
    );
  }

  if (scancodeCategory.size <= 500) {
    throw new Error(
      `scancode-licensedb-index.json: only ${scancodeCategory.size} mapped SPDX keys, expected ` +
        `above 500`,
    );
  }
}

/** One matrix cell's before/after summary, deterministic and rendered for human review. */
export interface MatrixDiff {
  readonly added: number;
  readonly removed: number;
  readonly changed: number;
  readonly sampleFlips: readonly string[];
}

/** Diff two matrix snapshots deterministically, capping the named-flip sample at 20 lines. */
export function diffMatrix(
  previous: ReadonlyMap<string, ReadonlyMap<string, OsadlMatrixCell>>,
  next: ReadonlyMap<string, ReadonlyMap<string, OsadlMatrixCell>>,
): MatrixDiff {
  const leads = [...new Set([...previous.keys(), ...next.keys()])].sort(compareCodeUnits);
  let added = 0;
  let removed = 0;
  let changed = 0;
  const sampleFlips: string[] = [];

  for (const leading of leads) {
    const prevRow = previous.get(leading);
    const nextRow = next.get(leading);
    const subs = [...new Set([...(prevRow?.keys() ?? []), ...(nextRow?.keys() ?? [])])].sort(
      compareCodeUnits,
    );

    for (const subordinate of subs) {
      const prevCell = prevRow?.get(subordinate);
      const nextCell = nextRow?.get(subordinate);

      if (prevCell === nextCell) {
        continue;
      }

      if (prevCell === undefined) {
        added++;
      } else if (nextCell === undefined) {
        removed++;
      } else {
        changed++;
      }

      if (sampleFlips.length < 20) {
        sampleFlips.push(
          `${leading}→${subordinate}: ${prevCell ?? "(new)"} → ${nextCell ?? "(removed)"}`,
        );
      }
    }
  }

  return { added, removed, changed, sampleFlips };
}

/** Diff two flat id→value snapshots (the class table or the ScanCode category map). */
export function diffEntries(
  previous: ReadonlyMap<string, string>,
  next: ReadonlyMap<string, string>,
): readonly string[] {
  const ids = [...new Set([...previous.keys(), ...next.keys()])].sort(compareCodeUnits);
  const lines: string[] = [];

  for (const id of ids) {
    const prevValue = previous.get(id);
    const nextValue = next.get(id);

    if (prevValue !== nextValue) {
      lines.push(`${id}: ${prevValue ?? "(new)"} → ${nextValue ?? "(removed)"}`);
    }
  }

  return lines;
}

/**
 * The inter-tier gate (A3): compare the DOWNLOADED pair's disagreements against the CURRENTLY
 * COMMITTED pair's disagreements (computed live via the same enumerator, never a separately
 * maintained literal - the test file's pinned list and this comparison can never drift apart from
 * each other because both read the one committed snapshot). A newly introduced disagreement must
 * abort the refresh; a resolved one is reported only, since removing a disagreement is always safe.
 */
export interface InterTierGateResult {
  readonly newEntries: readonly string[];
  readonly resolvedEntries: readonly string[];
}

export function compareInterTierDisagreements(
  committed: readonly string[],
  downloaded: readonly string[],
): InterTierGateResult {
  const committedSet = new Set(committed);
  const downloadedSet = new Set(downloaded);

  return {
    newEntries: downloaded.filter((entry) => !committedSet.has(entry)).sort(compareCodeUnits),
    resolvedEntries: committed.filter((entry) => !downloadedSet.has(entry)).sort(compareCodeUnits),
  };
}

/** Inputs for one PROVENANCE.md source-file section. */
export interface ProvenanceEntry {
  readonly retrievalUrl: string;
  readonly retrievedAt: string;
  readonly upstreamTimestamp: string;
  readonly sha256: string;
}

/**
 * Render PROVENANCE.md in full from the three sections' current values - a complete re-render
 * rather than a patch, so the committed file and this function can never silently diverge in
 * wording. Mirrors the file this script overwrites; keep the two in sync by hand if the prose
 * changes.
 */
export function renderProvenance(entries: {
  matrix: ProvenanceEntry;
  copyleft: ProvenanceEntry;
  scancode: ProvenanceEntry;
}): string {
  return `# Provenance: vendored license-compatibility data

The three JSON files in this directory are unmodified, verbatim snapshots of
third-party data. SBOMlet does not edit, reformat, or recompute any part of
them - each is committed byte-for-byte as downloaded, and this file records
where each came from, when, and under what license, so the retrieval
provenance travels with the code rather than living only in a commit message
or a person's memory. Refresh them with the maintainer-only
\`compat:data:refresh\` task (\`task compat:data:refresh --summary\` explains its
checks); nothing in the automated test or build pipeline fetches these files
over the network.

## osadl-matrix.json

- **Retrieval URL:** ${entries.matrix.retrievalUrl}
- **Retrieval timestamp:** ${entries.matrix.retrievedAt}
- **Upstream data timestamp:** ${entries.matrix.upstreamTimestamp} (the file's own
  top-level \`timestamp\` field)
- **sha256:** \`${entries.matrix.sha256}\`
- **Data license:** Creative Commons Attribution 4.0 International
  (CC-BY-4.0), as stated for all OSADL checklist raw data at
  https://www.osadl.org/Access-to-raw-data.oss-compliance-raw-data-access.0.html
- **Attribution:** matrix.json carries no embedded attribution text of its
  own; the OSADL checklist project's required attribution string is the one
  embedded in osadl-copyleft.json below, and applies to this file equally
  (both are published by the same OSADL checklist project under the same
  license).
- **Modifications:** none - committed byte-identical to the download.

Pairwise absorption verdicts between 119 SPDX-parseable license ids: for a
leading license T and a subordinate license L, the cell answers "can a work
under L be integrated into a combined work distributed under T." Values are
\`Same\`, \`Yes\`, \`No\`, \`Unknown\`, or \`Check dependency\` (a condition, such as an
\`-or-later\` upgrade clause, can resolve the pair - SBOMlet's loader routes
this to the same honest-residual handling as \`Unknown\`, never a guess).

## osadl-copyleft.json

- **Retrieval URL:** ${entries.copyleft.retrievalUrl}
- **Retrieval timestamp:** ${entries.copyleft.retrievedAt}
- **Upstream data timestamp:** ${entries.copyleft.upstreamTimestamp} (the file's own
  top-level \`timestamp\` field)
- **sha256:** \`${entries.copyleft.sha256}\`
- **Data license:** Creative Commons Attribution 4.0 International
  (CC-BY-4.0) - the file's own embedded \`license\` field reads "Creative
  Commons Attribution 4.0 International license (CC-BY-4.0)".
- **Attribution (verbatim, embedded in the file's \`attribution\` field):**
  "A project by the Open Source Automation Development Lab (OSADL) eG. For
  further information about the project see the description at
  www.osadl.org/checklists."
- **Copyright (verbatim, embedded in the file's \`copyright\` field):**
  "(C) 2017 - 2024 Open Source Automation Development Lab (OSADL) eG and
  contributors, info@osadl.org"
- **Disclaimer (verbatim, embedded in the file's \`disclaimer\` field):** "The
  checklists and particularly the copyleft data have been assembled with
  maximum diligence and care; however, the authors do not warrant nor can be
  held liable in any way for its correctness, usefulness, merchantibility or
  fitness for a particular purpose as far as permissible by applicable law.
  Anyone who uses the information does this on his or her sole
  responsibility. For any individual legal advice, it is recommended to
  contact a lawyer."
- **Modifications:** none - committed byte-identical to the download.

Per-license copyleft class for 125 SPDX-parseable license ids, under the
top-level \`copyleft\` key. Values are \`No\`, \`Yes\`, \`Yes (restricted)\`, or
\`Questionable\`. This is the axis a proprietary target uses: a permissive
dependency classes \`No\`, a strong/network copyleft dependency classes \`Yes\`,
a boundary-dependent weak copyleft (MPL/LGPL/EPL-2.0-shaped) classes
\`Yes (restricted)\`, and an unsettled case classes \`Questionable\`.

## scancode-licensedb-index.json

- **Retrieval URL:** ${entries.scancode.retrievalUrl}
- **Retrieval timestamp:** ${entries.scancode.retrievedAt}
- **Upstream data timestamp:** ${entries.scancode.upstreamTimestamp} (the HTTP \`Last-Modified\`
  response header observed at retrieval time - the index itself carries no
  embedded timestamp field, unlike the two OSADL files above)
- **sha256:** \`${entries.scancode.sha256}\`
- **Data license:** Creative Commons Attribution 4.0 International
  (CC-BY-4.0), as stated at https://scancode-licensedb.aboutcode.org/help.html
- **Attribution:** ScanCode LicenseDB, part of the AboutCode project
  (https://scancode-licensedb.aboutcode.org/).
- **Modifications:** none - committed byte-identical to the download.

Per-license category for 2,733 entries (AboutCode's own curated license list,
broader than the OSADL tables but pairwise-uncovered): \`Permissive\`,
\`Copyleft\`, \`Copyleft Limited\`, \`Proprietary Free\`, \`Source-available\`, and
several narrower categories. SBOMlet uses this as the breadth fallback tier
when a dependency's license id is absent from both OSADL tables.
`;
}

/**
 * Rewrite the SCANCODE_SNAPSHOT_TIMESTAMP literal in data.ts's source text, naming it if the
 * expected declaration is not found (an upstream refactor of data.ts must not silently leave a
 * stale timestamp behind).
 */
export function withUpdatedScancodeTimestamp(dataTsSource: string, newTimestamp: string): string {
  const pattern = /export const SCANCODE_SNAPSHOT_TIMESTAMP = "[^"]*";/;

  if (!pattern.test(dataTsSource)) {
    throw new Error(
      "data.ts: SCANCODE_SNAPSHOT_TIMESTAMP declaration not found - refusing to edit",
    );
  }

  return dataTsSource.replace(
    pattern,
    `export const SCANCODE_SNAPSHOT_TIMESTAMP = "${newTimestamp}";`,
  );
}

interface Downloaded {
  readonly text: string;
  readonly retrievedAt: string;
  readonly lastModified: string | null;
}

/** Fetch a fixed URL, rejecting a redirect that lands on a different host (T-20-02). */
async function fetchVerbatim(url: string): Promise<Downloaded> {
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`${url}: HTTP ${response.status}`);
  }

  const requestHost = new URL(url).host;
  const finalHost = new URL(response.url).host;

  if (finalHost !== requestHost) {
    throw new Error(`${url}: redirected to a different host (${finalHost}) - refusing to follow`);
  }

  return {
    text: await response.text(),
    retrievedAt: new Date().toISOString(),
    lastModified: response.headers.get("last-modified"),
  };
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));

  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** One successfully validated download, ready to write. */
export interface ValidatedDownload {
  readonly matrix: ReadonlyMap<string, ReadonlyMap<string, OsadlMatrixCell>>;
  readonly copyleftClass: ReadonlyMap<string, OsadlCopyleftClass>;
  readonly scancodeCategory: ReadonlyMap<string, string>;
  readonly interTierGate: InterTierGateResult;
}

/**
 * Every check this script runs BEFORE it is allowed to write anything: size gates, the loader's own
 * shape narrows, the A5 structural assertions, and the A3 inter-tier gate. A pure function with no
 * filesystem access - by construction, nothing this script writes can be reached until this
 * function has returned successfully, so a validation failure at any step leaves every committed
 * file untouched.
 */
export function validateDownloadedSnapshots(downloads: {
  matrixText: string;
  copyleftText: string;
  scancodeText: string;
}): ValidatedDownload {
  assertWithinSizeGate(Buffer.byteLength(downloads.matrixText, "utf8"), SIZE_GATES.matrix);
  assertWithinSizeGate(Buffer.byteLength(downloads.copyleftText, "utf8"), SIZE_GATES.copyleft);
  assertWithinSizeGate(Buffer.byteLength(downloads.scancodeText, "utf8"), SIZE_GATES.scancode);

  const matrix = narrowOsadlMatrix(JSON.parse(downloads.matrixText), "downloaded matrix.json");
  const copyleftClass = narrowOsadlCopyleftClass(
    JSON.parse(downloads.copyleftText),
    "downloaded copyleft.json",
  );
  const scancodeCategory = narrowScancodeCategory(
    JSON.parse(downloads.scancodeText),
    "downloaded scancode index.json",
  );

  assertStructuralShape(matrix, copyleftClass, scancodeCategory);

  const committedDisagreements = interTierDisagreements(OSADL_MATRIX, OSADL_COPYLEFT_CLASS);
  const downloadedDisagreements = interTierDisagreements(matrix, copyleftClass);
  const interTierGate = compareInterTierDisagreements(
    committedDisagreements,
    downloadedDisagreements,
  );

  if (interTierGate.newEntries.length > 0) {
    throw new Error(
      `inter-tier gate: the download introduces ${interTierGate.newEntries.length} NEW ` +
        `disagreement(s) not in the committed allowlist:\n` +
        `${interTierGate.newEntries.map((entry) => `  - ${entry}`).join("\n")}\n` +
        `Review these by hand (update the pinned allowlist in test/compatData.test.ts if they are ` +
        `accepted) before re-running the refresh.`,
    );
  }

  return { matrix, copyleftClass, scancodeCategory, interTierGate };
}

async function main(): Promise<void> {
  console.log(`probing ${OSADL_TIMESTAMP_URL} for freshness...`);
  const probe = await fetch(OSADL_TIMESTAMP_URL);
  const upstreamTimestamp = probe.ok ? (await probe.text()).trim() : null;

  console.log(
    `  upstream: ${upstreamTimestamp ?? "(probe failed, HTTP " + String(probe.status) + ")"}`,
  );
  console.log(`  committed: ${OSADL_SNAPSHOT_TIMESTAMP}`);

  console.log(
    "downloading osadl-matrix.json, osadl-copyleft.json, scancode-licensedb-index.json...",
  );
  const [matrixDl, copyleftDl, scancodeDl] = await Promise.all([
    fetchVerbatim(OSADL_MATRIX_URL),
    fetchVerbatim(OSADL_COPYLEFT_URL),
    fetchVerbatim(SCANCODE_INDEX_URL),
  ]);

  const {
    matrix: downloadedMatrix,
    copyleftClass: downloadedCopyleft,
    scancodeCategory: downloadedScancode,
    interTierGate,
  } = validateDownloadedSnapshots({
    matrixText: matrixDl.text,
    copyleftText: copyleftDl.text,
    scancodeText: scancodeDl.text,
  });

  if (interTierGate.resolvedEntries.length > 0) {
    console.log(
      `inter-tier gate: ${interTierGate.resolvedEntries.length} previously pinned disagreement(s) ` +
        `no longer reproduce - update the pinned allowlist in test/compatData.test.ts:\n` +
        interTierGate.resolvedEntries.map((entry) => `  - ${entry}`).join("\n"),
    );
  }

  const matrixDiff = diffMatrix(OSADL_MATRIX, downloadedMatrix);

  console.log(
    `osadl-matrix.json diff: ${matrixDiff.added} added, ${matrixDiff.removed} removed, ` +
      `${matrixDiff.changed} changed cells`,
  );

  for (const flip of matrixDiff.sampleFlips) {
    console.log(`  ${flip}`);
  }

  const copyleftDiff = diffEntries(OSADL_COPYLEFT_CLASS, downloadedCopyleft);

  console.log(`osadl-copyleft.json diff: ${copyleftDiff.length} changed entries`);

  for (const entry of copyleftDiff) {
    console.log(`  ${entry}`);
  }

  const scancodeDiff = diffEntries(SCANCODE_CATEGORY, downloadedScancode);

  console.log(
    `scancode-licensedb-index.json diff: ${scancodeDiff.length} changed category entries`,
  );

  for (const entry of scancodeDiff.slice(0, 20)) {
    console.log(`  ${entry}`);
  }

  const matrixSha = await sha256Hex(matrixDl.text);
  const copyleftSha = await sha256Hex(copyleftDl.text);
  const scancodeSha = await sha256Hex(scancodeDl.text);

  writeFileSync(MATRIX_PATH, matrixDl.text);
  writeFileSync(COPYLEFT_PATH, copyleftDl.text);
  writeFileSync(SCANCODE_PATH, scancodeDl.text);

  const matrixTimestamp = (JSON.parse(matrixDl.text) as { timestamp?: string }).timestamp ?? "?";
  const copyleftTimestamp =
    (JSON.parse(copyleftDl.text) as { timestamp?: string }).timestamp ?? "?";

  writeFileSync(
    PROVENANCE_PATH,
    renderProvenance({
      matrix: {
        retrievalUrl: OSADL_MATRIX_URL,
        retrievedAt: matrixDl.retrievedAt,
        upstreamTimestamp: matrixTimestamp,
        sha256: matrixSha,
      },
      copyleft: {
        retrievalUrl: OSADL_COPYLEFT_URL,
        retrievedAt: copyleftDl.retrievedAt,
        upstreamTimestamp: copyleftTimestamp,
        sha256: copyleftSha,
      },
      scancode: {
        retrievalUrl: SCANCODE_INDEX_URL,
        retrievedAt: scancodeDl.retrievedAt,
        upstreamTimestamp: scancodeDl.lastModified ?? "(no Last-Modified header observed)",
        sha256: scancodeSha,
      },
    }),
  );

  if (scancodeDl.lastModified !== null) {
    const dataTsSource = readFileSync(DATA_TS_PATH, "utf8");

    writeFileSync(
      DATA_TS_PATH,
      withUpdatedScancodeTimestamp(dataTsSource, scancodeDl.lastModified),
    );
  }

  console.log("wrote osadl-matrix.json, osadl-copyleft.json, scancode-licensedb-index.json");
  console.log("wrote PROVENANCE.md");
  console.log(
    "Run the full suite now (task quality && task test && task check). A pinning test failure " +
      "means a reviewed verdict flipped - update the pin only after confirming the new value by hand.",
  );
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}
