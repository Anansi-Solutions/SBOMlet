/**
 * Post-process pass that aligns the columns of every GFM table in a rendered
 * document, so the committed THIRD_PARTY_LICENSES.md reads cleanly as raw text.
 *
 * Runs AFTER renderMarkdown, on the pipeline's single output-production point, so
 * generate and check both align identically and the byte-compare gate stays
 * consistent. The renderer itself stays unaligned — its golden and inline tests
 * are unaffected.
 *
 * Bounded, NOT a general markdown parser: it only re-pads blocks that are
 * unambiguously GFM tables (a row immediately followed by a `| --- | --- |`
 * separator), leaves fenced code blocks untouched, and splits cells on UNESCAPED
 * pipes only (the renderer escapes a literal `|` in a cell to `\|`). Deterministic
 * and idempotent.
 */

const FENCE = /^\s*```/;

/** A line that could be a table row: starts (after optional whitespace) with a pipe. */
function isTableRow(line: string): boolean {
  return /^\s*\|/.test(line);
}

/** Split a table row into trimmed cells, honoring escaped pipes (`\|`). */
function splitCells(row: string): string[] {
  const inner = row.trim().replace(/^\|/, "").replace(/\|$/, "");
  return inner.split(/(?<!\\)\|/).map((cell) => cell.trim());
}

/** A separator row: every cell is GFM dashes (optionally colon-aligned). */
function isSeparatorRow(line: string): boolean {
  if (!isTableRow(line)) return false;
  const cells = splitCells(line);
  return cells.length > 0 && cells.every((cell) => /^:?-+:?$/.test(cell));
}

/** Re-pad one table block (header, separator, rows…) to aligned column widths. */
function formatTable(block: readonly string[]): string[] {
  const rows = block.map(splitCells);
  const columns = Math.max(...rows.map((cells) => cells.length));
  const widths: number[] = [];
  for (let column = 0; column < columns; column += 1) {
    let width = 3; // a separator needs at least "---"
    rows.forEach((cells, rowIndex) => {
      // the separator row is regenerated, never measured
      if (rowIndex !== 1) width = Math.max(width, (cells[column] ?? "").length);
    });
    widths.push(width);
  }
  return rows.map((cells, rowIndex) => {
    const padded = widths.map((width, column) => {
      if (rowIndex === 1) return "-".repeat(width);
      const cell = cells[column] ?? "";
      return cell + " ".repeat(width - cell.length);
    });
    return `| ${padded.join(" | ")} |`;
  });
}

/** Align every GFM table in `markdown`; non-table content passes through verbatim. */
export function alignTables(markdown: string): string {
  const lines = markdown.split("\n");
  const out: string[] = [];
  let inFence = false;
  let i = 0;
  while (i < lines.length) {
    const line = lines[i]!;
    if (FENCE.test(line)) {
      inFence = !inFence;
      out.push(line);
      i += 1;
      continue;
    }
    const next = lines[i + 1];
    if (
      !inFence &&
      isTableRow(line) &&
      next !== undefined &&
      isSeparatorRow(next)
    ) {
      const block: string[] = [];
      while (
        i < lines.length &&
        !FENCE.test(lines[i]!) &&
        isTableRow(lines[i]!)
      ) {
        block.push(lines[i]!);
        i += 1;
      }
      out.push(...formatTable(block));
      continue;
    }
    out.push(line);
    i += 1;
  }
  return out.join("\n");
}
