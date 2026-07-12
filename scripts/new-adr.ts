/**
 * Scaffold a new architecture decision record from the MADR template.
 *
 * Run via `task adr:new TITLE="..."`. The title arrives as argv[2]; Task passes
 * it through `| q` (shellQuote), so it is one inert argument, never re-parsed by
 * the shell. The next ADR number is
 * the highest existing NNNN plus one; the slug is the lower-cased title with
 * non-alphanumeric runs collapsed to single dashes.
 */
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const ADR_DIR = join(import.meta.dir, "..", "docs", "explanation", "adr");
const TEMPLATE = join(ADR_DIR, "0000-template.md");

const title = (process.argv[2] ?? "").trim();
if (title === "") {
  console.error(
    'A title is required: task adr:new TITLE="Short decision title"',
  );
  process.exit(2);
}

const NUMBERED = /^(\d{4})-.*\.md$/;
const highest = readdirSync(ADR_DIR)
  .map((name) => NUMBERED.exec(name))
  .filter((m): m is RegExpExecArray => m !== null)
  .map((m) => Number.parseInt(m[1], 10))
  .reduce((max, n) => Math.max(max, n), 0);

const number = String(highest + 1).padStart(4, "0");
const slug = title
  .toLowerCase()
  .replace(/[^a-z0-9]+/g, "-")
  .replace(/^-+|-+$/g, "");
const filePath = join(ADR_DIR, `${number}-${slug}.md`);

const date = new Date().toISOString().slice(0, 10);
const body = readFileSync(TEMPLATE, "utf8")
  .replace(/^# ADR-0000: .*$/m, `# ADR-${number}: ${title}`)
  .replace(/^- \*\*Date:\*\* .*$/m, `- **Date:** ${date}`);

writeFileSync(filePath, body);
console.log(`Wrote ${filePath}`);
console.log(
  `Next: write it, set Status to Accepted, and add a row to the index.`,
);
