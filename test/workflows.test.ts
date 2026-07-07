import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "bun:test";

const WORKFLOWS_DIR = join(import.meta.dir, "..", ".github", "workflows");
const GITHUB_DIR = join(import.meta.dir, "..", ".github");

/** Every YAML file directly under .github/workflows/, name + raw text + parsed doc. */
function loadWorkflows(dir: string): {
  file: string;
  text: string;
  doc: Record<string, unknown>;
}[] {
  return readdirSync(dir)
    .filter((name) => name.endsWith(".yml") || name.endsWith(".yaml"))
    .map((name) => {
      const text = readFileSync(join(dir, name), "utf8");
      return {
        file: name,
        text,
        doc: Bun.YAML.parse(text) as Record<string, unknown>,
      };
    });
}

/** One extracted run-step body: its source file, the 1-based line the key starts on, and its raw text. */
interface RunBlock {
  file: string;
  line: number;
  body: string;
}

/**
 * Pulls every run-step body out of a workflow's raw text by indentation --
 * no YAML-scalar-folding semantics needed, just "is this line part of the
 * block that started at the run key". Handles both the single-line form
 * (`run: cmd`) and the block-scalar form (`run: |` / `run: >`), delegating
 * the latter to collectBlockScalarBody to keep nesting flat.
 *
 * Deliberately independent of sibling env:/with: keys -- we anchor on the
 * "<indent>run:" step-key shape, which is what YAML requires for a step body.
 */
function extractRunBlocks(file: string, text: string): RunBlock[] {
  const lines = text.split("\n");
  const blocks: RunBlock[] = [];
  const runKeyPattern = /^(\s*)run:(.*)$/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    const match = runKeyPattern.exec(line);
    if (!match) continue;

    const indent = match[1]?.length ?? 0;
    const inline = (match[2] ?? "").trim();
    const isSingleLineForm =
      inline !== "" &&
      inline !== "|" &&
      inline !== ">" &&
      !inline.startsWith("#");
    // Single-line form (`run: cmd`): the whole body is on this line.
    // Block-scalar form (`run: |` / `run: >`): body is the following
    // more-indented lines, collected by collectBlockScalarBody below.
    const bodyLines = isSingleLineForm
      ? [inline]
      : collectBlockScalarBody(lines, i + 1, indent);

    blocks.push({ file, line: i + 1, body: bodyLines.join("\n") });
  }

  return blocks;
}

/**
 * Collects a block-scalar run body: every line after `startIndex` indented
 * deeper than `keyIndent`, stopping at the first line that dedents back to
 * (or past) the key's own indentation. Blank lines inside the block don't
 * end it. Split out of `extractRunBlocks` to keep nesting within the lint
 * budget.
 */
function collectBlockScalarBody(
  lines: string[],
  startIndex: number,
  keyIndent: number,
): string[] {
  const bodyLines: string[] = [];
  for (let j = startIndex; j < lines.length; j++) {
    const next = lines[j] ?? "";
    if (next.trim() === "") {
      bodyLines.push(next);
      continue;
    }
    const nextIndent = next.length - next.trimStart().length;
    if (nextIndent <= keyIndent) break;
    bodyLines.push(next);
  }
  return bodyLines;
}

const INTERP_MARKER = "$" + "{{";

/** Interpolation markers anywhere in a run body, run-block by run-block, naming file:line. */
function findRunBodyInterpolations(
  workflows: { file: string; text: string }[],
): { file: string; line: number }[] {
  const offenders: { file: string; line: number }[] = [];
  for (const { file, text } of workflows) {
    for (const block of extractRunBlocks(file, text)) {
      if (block.body.includes(INTERP_MARKER)) {
        offenders.push({ file, line: block.line });
      }
    }
  }
  return offenders;
}

/** Word-boundary, case-insensitive scan for internal-tooling names in a text blob. */
function findToolingNames(text: string): string[] {
  const found: string[] = [];
  for (const name of ["gsd", "claude", "anthropic"]) {
    const re = new RegExp("\\b" + name + "\\b", "i");
    if (re.test(text)) found.push(name);
  }
  return found;
}

/** Recursively collect every file under a directory (relative paths, POSIX-joined). */
function collectFiles(dir: string, base = dir): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectFiles(full, base));
    } else {
      out.push(full.slice(base.length + 1).replaceAll("\\", "/"));
    }
  }
  return out;
}

interface JobShape {
  "runs-on"?: unknown;
  "timeout-minutes"?: unknown;
  permissions?: { contents?: string } | string;
  steps?: { uses?: string; with?: Record<string, unknown> }[];
}

function jobsOf(doc: Record<string, unknown>): Record<string, JobShape> {
  return (doc.jobs ?? {}) as Record<string, JobShape>;
}

/**
 * Checks a single job for the contents: write invariant pair: job-scoped
 * permissions, and persist-credentials: false on every checkout step.
 * Extracted out of the test body to keep the per-job checks at one nesting
 * level instead of four.
 */
function checkContentsWriteJob(
  file: string,
  jobName: string,
  job: JobShape,
): string[] {
  const perms = job.permissions;
  const contentsWrite =
    typeof perms === "object" && perms !== null && perms.contents === "write";
  if (!contentsWrite) return [];

  const checkoutSteps = (job.steps ?? []).filter((s) =>
    (s.uses ?? "").startsWith("actions/checkout@"),
  );
  if (checkoutSteps.length === 0) {
    return [`${file}:${jobName} (contents:write, no checkout step found)`];
  }

  return checkoutSteps
    .filter((step) => step.with?.["persist-credentials"] !== false)
    .map(
      () =>
        `${file}:${jobName} (contents:write checkout missing persist-credentials: false)`,
    );
}

const workflows = loadWorkflows(WORKFLOWS_DIR);

describe("workflow authoring invariants (.github/workflows/*.yml)", () => {
  test("at least one workflow file exists to enforce invariants over", () => {
    expect(workflows.length).toBeGreaterThan(0);
  });

  test("every workflow file parses as YAML", () => {
    for (const { file, text } of workflows) {
      expect(() => Bun.YAML.parse(text), file).not.toThrow();
    }
  });

  test("no interpolation markers inside any run-step body (injection surface -- use env: indirection)", () => {
    const offenders = findRunBodyInterpolations(workflows);
    expect(
      offenders,
      offenders.map((o) => `${o.file}:${o.line}`).join(", "),
    ).toEqual([]);
  });

  test("no internal-tooling names under .github/ (gsd, claude, anthropic)", () => {
    const offenders: { file: string; names: string[] }[] = [];
    for (const relPath of collectFiles(GITHUB_DIR)) {
      const full = join(GITHUB_DIR, relPath);
      const text = readFileSync(full, "utf8");
      const names = findToolingNames(text);
      if (names.length > 0)
        offenders.push({ file: `.github/${relPath}`, names });
    }
    expect(
      offenders,
      offenders.map((o) => `${o.file}: ${o.names.join(", ")}`).join("; "),
    ).toEqual([]);
  });

  test("push triggers with paths: filters also declare branches: (tag-push trap)", () => {
    const offenders: string[] = [];
    for (const { file, doc } of workflows) {
      const on = doc.on as Record<string, unknown> | undefined;
      const push = on?.push as Record<string, unknown> | undefined;
      if (!push) continue;
      if ("paths" in push && !("branches" in push)) {
        offenders.push(file);
      }
    }
    expect(offenders, offenders.join(", ")).toEqual([]);
  });

  test("every job with contents: write has job-scoped permissions and persist-credentials: false on checkout", () => {
    const offenders: string[] = [];
    for (const { file, doc } of workflows) {
      for (const [jobName, job] of Object.entries(jobsOf(doc))) {
        offenders.push(...checkContentsWriteJob(file, jobName, job));
      }
    }
    expect(offenders, offenders.join("; ")).toEqual([]);
  });

  test("timeout-minutes present on every job", () => {
    const offenders: string[] = [];
    for (const { file, doc } of workflows) {
      for (const [jobName, job] of Object.entries(jobsOf(doc))) {
        if (job["timeout-minutes"] === undefined) {
          offenders.push(`${file}:${jobName}`);
        }
      }
    }
    expect(offenders, offenders.join(", ")).toEqual([]);
  });
});

describe("workflow invariant sensitivity (extraction helpers actually catch violations)", () => {
  test("run-block extraction flags an interpolation marker inside a block-scalar run body", () => {
    const hostile = [
      "jobs:",
      "  demo:",
      "    steps:",
      "      - name: dangerous",
      "        run: |",
      "          echo " + INTERP_MARKER + " github.event.issue.title }}",
      "          echo done",
    ].join("\n");
    const offenders = findRunBodyInterpolations([
      { file: "inline.yml", text: hostile },
    ]);
    expect(offenders.length).toBe(1);
    expect(offenders[0]?.line).toBe(5);
  });

  test("run-block extraction flags an interpolation marker inside a single-line run body", () => {
    const hostile = [
      "jobs:",
      "  demo:",
      "    steps:",
      "      - name: dangerous",
      "        run: echo " + INTERP_MARKER + " inputs.thing }}",
    ].join("\n");
    const offenders = findRunBodyInterpolations([
      { file: "inline.yml", text: hostile },
    ]);
    expect(offenders.length).toBe(1);
    expect(offenders[0]?.line).toBe(5);
  });

  test("run-block extraction does NOT flag an interpolation marker in a sibling env: or with: key", () => {
    const benign = [
      "jobs:",
      "  demo:",
      "    steps:",
      "      - name: fine",
      "        env:",
      "          THING: " + INTERP_MARKER + " inputs.thing }}",
      "        with:",
      "          value: " + INTERP_MARKER + " inputs.other }}",
      "        run: |",
      "          echo $THING",
    ].join("\n");
    const offenders = findRunBodyInterpolations([
      { file: "inline.yml", text: benign },
    ]);
    expect(offenders).toEqual([]);
  });

  test("run-block extraction stops at dedent -- a later step's interpolation is not attributed to an earlier run body", () => {
    const mixed = [
      "jobs:",
      "  demo:",
      "    steps:",
      "      - name: clean",
      "        run: |",
      "          echo clean",
      "      - name: uses-interp",
      "        env:",
      "          THING: " + INTERP_MARKER + " inputs.thing }}",
      "        run: echo $THING",
    ].join("\n");
    const offenders = findRunBodyInterpolations([
      { file: "inline.yml", text: mixed },
    ]);
    expect(offenders).toEqual([]);
  });

  test("tooling-name scan flags gsd/claude/anthropic as whole words, not substrings like 'contain'", () => {
    expect(findToolingNames("this step must contain the artifact")).toEqual([]);
    expect(findToolingNames("run gsd-tools next")).toEqual(["gsd"]);
    expect(findToolingNames("ask Claude for help")).toEqual(["claude"]);
    expect(findToolingNames("built with anthropic's SDK")).toEqual([
      "anthropic",
    ]);
  });

  test("branches: sensitivity -- a push trigger with paths: and no branches: is flagged, mutate-and-restore on a temp copy", () => {
    const dir = mkdtempSync(join(tmpdir(), "workflow-invariant-"));
    try {
      const hostilePath = join(dir, "hostile.yml");
      writeFileSync(
        hostilePath,
        [
          "on:",
          "  push:",
          "    paths:",
          "      - 'src/**'",
          "jobs:",
          "  demo:",
          "    runs-on: ubuntu-latest",
          "    timeout-minutes: 5",
          "    steps: []",
        ].join("\n"),
      );
      const { doc } = loadWorkflows(dir)[0] as { doc: Record<string, unknown> };
      const on = doc.on as Record<string, unknown>;
      const push = on.push as Record<string, unknown>;
      expect("paths" in push && !("branches" in push)).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("permissions sensitivity -- contents: write without persist-credentials: false is flagged, mutate-and-restore on a temp copy", () => {
    const dir = mkdtempSync(join(tmpdir(), "workflow-invariant-"));
    try {
      const hostilePath = join(dir, "hostile.yml");
      writeFileSync(
        hostilePath,
        [
          "jobs:",
          "  demo:",
          "    runs-on: ubuntu-latest",
          "    timeout-minutes: 5",
          "    permissions:",
          "      contents: write",
          "    steps:",
          "      - name: checkout",
          "        uses: actions/checkout@v6",
        ].join("\n"),
      );
      const { doc } = loadWorkflows(dir)[0] as { doc: Record<string, unknown> };
      const job = jobsOf(doc).demo as JobShape;
      const checkoutStep = job.steps?.[0];
      expect(checkoutStep?.with?.["persist-credentials"]).not.toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
