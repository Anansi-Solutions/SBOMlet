// Measure comment density over src/**/*.ts.
//
// Two ratios, both against non-blank lines / word tokens:
//   - comment lines: lines whose non-whitespace content is entirely comment
//   - comment words: alphanumeric tokens inside comment text
//
// Comments are located with the TypeScript parser, so `//` inside string
// literals or regexes never counts. Run directly (`bun scripts/comment-metrics.ts`)
// for a per-file table; import `measureComments` for the test gate.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import ts from "typescript";

/** Ceiling for comment lines as a share of non-blank lines in src/. */
export const MAX_COMMENT_LINE_RATIO = 0.43;
/** Ceiling for comment words as a share of word tokens in src/. */
export const MAX_COMMENT_WORD_RATIO = 0.7;

export interface CommentMetrics {
  /** Non-blank lines in the measured files. */
  totalLines: number;
  /** Non-blank lines consisting only of comment text. */
  commentLines: number;
  /** Word tokens (containing an alphanumeric) in the measured files. */
  totalWords: number;
  /** Word tokens inside comments, trailing comments included. */
  commentWords: number;
}

interface FileMetrics extends CommentMetrics {
  file: string;
}

function commentRanges(text: string): Array<{ pos: number; end: number }> {
  const sourceFile = ts.createSourceFile(
    "f.ts",
    text,
    ts.ScriptTarget.Latest,
    true,
  );
  const seen = new Set<number>();
  const ranges: Array<{ pos: number; end: number }> = [];
  const collect = (candidates: ts.CommentRange[] | undefined): void => {
    for (const range of candidates ?? []) {
      if (!seen.has(range.pos)) {
        seen.add(range.pos);
        ranges.push({ pos: range.pos, end: range.end });
      }
    }
  };
  const visit = (node: ts.Node): void => {
    collect(ts.getLeadingCommentRanges(text, node.getFullStart()));
    collect(ts.getTrailingCommentRanges(text, node.getEnd()));
    node.forEachChild(visit);
  };
  visit(sourceFile);
  return ranges.sort((a, b) => a.pos - b.pos);
}

function countWords(text: string): number {
  return (text.match(/\S+/g) ?? []).filter((token) => /[A-Za-z0-9]/.test(token))
    .length;
}

export function measureFile(text: string): CommentMetrics {
  const ranges = commentRanges(text);
  // Blank out comment spans (preserving newlines) to see what code remains.
  let codeOnly = text;
  let commentText = "";
  for (const { pos, end } of ranges) {
    const span = text.slice(pos, end);
    commentText += ` ${span}`;
    codeOnly =
      codeOnly.slice(0, pos) +
      span.replace(/[^\n]/g, " ") +
      codeOnly.slice(end);
  }
  const lines = text.split("\n");
  const codeLines = codeOnly.split("\n");
  let totalLines = 0;
  let commentLines = 0;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i]!.trim() === "") continue;
    totalLines++;
    if (codeLines[i]!.trim() === "") commentLines++;
  }
  const strippedComment = commentText.replace(
    /\/\*+|\*+\/|^\s*\*+|\/\//gm,
    " ",
  );
  return {
    totalLines,
    commentLines,
    totalWords: countWords(text),
    commentWords: countWords(strippedComment),
  };
}

function listSourceFiles(dir: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...listSourceFiles(path));
    else if (entry.name.endsWith(".ts")) files.push(path);
  }
  return files.sort();
}

export function measureComments(root = "src"): CommentMetrics & {
  files: FileMetrics[];
} {
  const files: FileMetrics[] = [];
  const total: CommentMetrics = {
    totalLines: 0,
    commentLines: 0,
    totalWords: 0,
    commentWords: 0,
  };
  for (const file of listSourceFiles(root)) {
    const metrics = measureFile(readFileSync(file, "utf8"));
    files.push({ file, ...metrics });
    total.totalLines += metrics.totalLines;
    total.commentLines += metrics.commentLines;
    total.totalWords += metrics.totalWords;
    total.commentWords += metrics.commentWords;
  }
  return { ...total, files };
}

const pct = (part: number, whole: number): string =>
  whole === 0 ? "0.0%" : `${((100 * part) / whole).toFixed(1)}%`;

if (import.meta.main) {
  const checkOnly = process.argv.includes("--check");
  const { files, ...total } = measureComments();
  if (!checkOnly) {
    for (const f of files) {
      console.log(
        `${pct(f.commentLines, f.totalLines).padStart(6)} lines  ` +
          `${pct(f.commentWords, f.totalWords).padStart(6)} words  ` +
          `(${String(f.commentLines).padStart(4)}/${String(f.totalLines).padEnd(4)})  ${f.file}`,
      );
    }
  }
  console.log(
    `comment density: ${pct(total.commentLines, total.totalLines)} lines ` +
      `(${total.commentLines}/${total.totalLines}, budget ` +
      `${(100 * MAX_COMMENT_LINE_RATIO).toFixed(0)}%), ` +
      `${pct(total.commentWords, total.totalWords)} words ` +
      `(${total.commentWords}/${total.totalWords}, budget ` +
      `${(100 * MAX_COMMENT_WORD_RATIO).toFixed(0)}%)`,
  );
  const overBudget =
    total.commentLines > MAX_COMMENT_LINE_RATIO * total.totalLines ||
    total.commentWords > MAX_COMMENT_WORD_RATIO * total.totalWords;
  if (overBudget) {
    console.error("comment density exceeds the budget");
    process.exit(1);
  }
}
