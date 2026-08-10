/**
 * The `refill` rule: reflow comment paragraphs to a configured column width.
 *
 * A comment (a JSDoc-style block, or a run of consecutive own-line `//`
 * lines) is split into paragraph groups at the boundaries documented in the
 * README, then each group is rejoined and rewrapped to `maxLength`. Groups
 * that already match their canonical reflow are left untouched; groups that
 * differ are reported and fixed independently, so a single comment can carry
 * several unrelated fixes.
 */

const LIST_MARKER_RE = /^([-*+\u2022]|\d+[.)])(?:(\s+)(.*))?$/;
const TAG_LINE_RE = /^@[A-Za-z]/;
/**
 * Structural directives read by a tool other than a human: ESLint's own
 * `eslint-*` comments, TypeScript's `@ts-*` comments, `prettier-ignore`, and
 * a shebang. These are never reflowed, not even wrapped or refilled with a
 * neighbor: ESLint parses `eslint-disable(-next-line)?`/`eslint-enable`
 * comments as single-line directives, and moving their `-- justification`
 * text onto a second physical line was observed to corrupt unrelated code
 * when combined with ESLint's own "unused directive" autofix. Isolating the
 * whole line is the only reflow-safe choice.
 */
const STRUCTURAL_DIRECTIVE_RE = /^(eslint-[A-Za-z-]+|@ts-[A-Za-z-]+|prettier-ignore|#!)/;
/**
 * A short label followed by a colon and a space: `TODO:`, `FIXME:`, a
 * platform/ecosystem name in a parallel clause list (`POSIX:`, `win32:`,
 * `npm:`), or any other one-to-sixteen-character word doing the same job.
 * Non-structural: it starts a new group but does reflow within it, just
 * like the semantic prefixes it generalizes.
 */
const LABEL_RE = /^[A-Za-z@][\w./+-]{0,15}:\s/;
const FENCE_RE = /^```/;

/** Splits leading whitespace from a content string. */
function splitIndent(text) {
  const match = /^(\s*)([\s\S]*)$/.exec(text);
  return { indent: match[1], text: match[2] };
}

/** True for a line with an odd number of backticks (an unbalanced code span). */
function hasUnbalancedBacktick(text) {
  const count = (text.match(/`/g) ?? []).length;
  return count % 2 !== 0;
}

/** True for a line carrying 3+ consecutive interior spaces: aligned layout, not prose. */
function isAlignedTable(text) {
  return /\S {3,}\S/.test(text);
}

/**
 * True for a line whose swapped-em-dash `-` is immediately followed by an
 * interior run of 2+ spaces and then `//` or `*`: a neighboring comment's
 * own marker, accidentally swallowed into this line by a join that forgot
 * to strip it (the em-dash sweep incident this rule guards against).
 * `isAlignedTable` alone would otherwise misread the same whitespace run
 * as a deliberately aligned column and mark the whole line `no-touch`,
 * permanently hiding the corruption from every future reflow pass.
 * Anchored on the preceding `-` (rather than any non-space character) so a
 * genuinely aligned code example — e.g. a JSON literal followed by a
 * right-padded `// comment` column — is never misread as this artifact:
 * real alignment tables in this codebase never happen to end their
 * left-hand column in a bare hyphen. Checked ahead of `isAlignedTable` so
 * this shape always wins and reaches reflow instead.
 */
function hasSwallowedCommentPrefix(text) {
  return /-\s{2,}(\/\/|\*)(?:\s|$)/.test(text);
}

/**
 * Conservative, documented heuristic for a commented-out code line: it ends
 * in a statement terminator/brace, or opens with a code keyword/token.
 */
function looksLikeCode(text) {
  if (/[;{}]\s*$/.test(text)) return true;
  if (/^[}\])]/.test(text)) return true;
  if (
    /^(function|const|let|var|if\s*\(|for\s*\(|while\s*\(|return\b|import\b|export\b|class\b|switch\s*\(|case\b|default:|catch\s*\(|try\b|else\b)/.test(
      text,
    )
  ) {
    return true;
  }
  return false;
}

/** True for a line whose (indent-stripped) text opens a TSDoc/JSDoc `@tag`. */
function isTagLine(text) {
  return TAG_LINE_RE.test(text);
}

/** True for a structural tool directive: isolated, never reflowed at all. */
function isStructuralDirective(text) {
  return STRUCTURAL_DIRECTIVE_RE.test(text);
}

/** True for lines that must start a fresh group but still reflow within it. */
function isLabelLine(text) {
  return LABEL_RE.test(text);
}

/** Matches a markdown list marker at the start of a line's text. */
function matchListMarker(text) {
  const match = LIST_MARKER_RE.exec(text);
  if (!match) return null;
  const marker = match[1];
  const spacing = match[2] ?? "";
  const rest = match[3] ?? "";
  return {
    marker,
    spacing,
    rest,
    prefixLength: marker.length + (spacing.length || 1),
  };
}

/**
 * Splits one comment's physical lines into paragraph groups.
 *
 * Each input line is `{ sourceLine, content }`, where `content` already has
 * the comment marker (`//` or `*`) and its mandatory separating space
 * removed. Returns groups tagged with a `reflow` flag: only `reflow: true`
 * groups are ever compared against their canonical form or rewritten.
 */
function splitParagraphGroups(lines) {
  const groups = [];
  let current = null;
  let fenceGroup = null;
  let skipGroup = null;

  for (const line of lines) {
    const { indent, text } = splitIndent(line.content);

    if (skipGroup) {
      skipGroup.lines.push(line);
      continue;
    }

    if (text === "") {
      groups.push({ type: "blank", reflow: false, lines: [line] });
      current = null;
      continue;
    }

    if (fenceGroup) {
      fenceGroup.lines.push(line);
      if (FENCE_RE.test(text)) fenceGroup = null;
      continue;
    }

    if (FENCE_RE.test(text)) {
      fenceGroup = { type: "fence", reflow: false, lines: [line] };
      groups.push(fenceGroup);
      current = null;
      continue;
    }

    if (
      hasUnbalancedBacktick(text) ||
      (isAlignedTable(text) && !hasSwallowedCommentPrefix(text)) ||
      looksLikeCode(text)
    ) {
      groups.push({ type: "no-touch", reflow: false, lines: [line] });
      current = null;
      continue;
    }

    if (isTagLine(text)) {
      skipGroup = { type: "skip", reflow: false, lines: [line] };
      groups.push(skipGroup);
      current = null;
      continue;
    }

    if (isStructuralDirective(text)) {
      groups.push({ type: "no-touch", reflow: false, lines: [line] });
      current = null;
      continue;
    }

    const marker = matchListMarker(text);
    const label = !marker && isLabelLine(text);

    let canContinue = false;
    if (current && current.type === "prose") {
      if (current.bulleted) {
        canContinue = !marker && !label && indent.length > current.baseIndent.length;
      } else {
        canContinue = !marker && !label && indent.length === current.baseIndent.length;
      }
    }

    if (canContinue) {
      current.lines.push(line);
      continue;
    }

    current = {
      type: "prose",
      reflow: true,
      bulleted: Boolean(marker),
      marker: marker ?? null,
      baseIndent: indent,
      lines: [line],
    };
    groups.push(current);
  }

  return groups;
}

/**
 * Tokenizes text into words, keeping a balanced inline code span as one
 * unit. Punctuation glued directly onto a span, with no space in between
 * (a trailing colon or closing paren, most often), stays glued to it: the
 * span match also consumes any immediately-following non-space characters,
 * so it round-trips exactly instead of gaining a space where none was.
 */
function tokenize(text) {
  const matches = text.match(/`[^`]*`[^\s]*|\S+/g);
  return matches ?? [];
}

const WORD_ISH_RE = /^[A-Za-z0-9]+$/;

/**
 * True when `left` is a source line's final token from a genuine mid-word
 * hyphenated line-break, wrapping into `right` as the next line's first
 * token — `schema-` followed by `version`, from a paragraph that was
 * originally wrapped at the hyphen inside `schema-version`. Both the stem
 * before `left`'s trailing hyphen and all of `right` must be plain word-ish
 * (letters/digits), so a deliberate ` - ` separator never qualifies: its
 * hyphen is tokenized on its own (nothing precedes it directly), leaving an
 * empty, non-word-ish stem.
 */
function isHyphenWrapJoin(left, right) {
  if (!left.endsWith("-")) return false;
  return WORD_ISH_RE.test(left.slice(0, -1)) && WORD_ISH_RE.test(right);
}

/**
 * Tokenizes a paragraph's physical lines, rejoining a hyphenated line-break
 * split across two of them back into the single token it started as.
 * Without this, `tokenize` runs per line and never sees that a trailing
 * `schema-` and a following `version` were one word before the paragraph
 * wrapped; flattening them as separate tokens then re-joining with a space
 * (see `wrapWords`) turns `schema-version` into `schema- version`. Only the
 * boundary between one line's last token and the next line's first token is
 * ever a merge candidate — same-line adjacency (`pre-` and `and` in
 * "pre- and post-processing") is left alone, so a suffix enumeration is
 * never mistaken for a wrapped compound.
 */
function tokenizeLines(lineTexts) {
  const words = [];
  for (const lineText of lineTexts) {
    const lineWords = tokenize(lineText);
    if (lineWords.length === 0) continue;
    const [first, ...rest] = lineWords;
    const prev = words[words.length - 1];
    if (prev !== undefined && isHyphenWrapJoin(prev, first)) {
      words[words.length - 1] = prev + first;
    } else {
      words.push(first);
    }
    words.push(...rest);
  }
  return words;
}

/**
 * A bare `-`, `*`, or `//` token is never wrapped onto a line by itself: a
 * `-` is a spaced separator whose word belongs at the START of what
 * follows (never a trailing artifact of a line-final em-dash swap gone
 * wrong, see refill's README point on the em-dash sweep incident); a lone
 * `*` or `//` is never legitimate prose content and, left as a line's sole
 * leftover token, would be misread as a bullet marker (`*`) on the next
 * reflow, or silently mask a swallowed neighboring comment (`//`). All
 * three travel with the token immediately after them as one unbreakable
 * unit.
 */
const STICKY_SEPARATOR_RE = /^(?:[-*]|\/\/)$/;

/** Greedy fill: packs words onto lines no wider than `width`, one overlong word per line. */
function wrapWords(words, width) {
  const lines = [];
  let current = [];
  let length = 0;
  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    const glueNext = STICKY_SEPARATOR_RE.test(word) && i + 1 < words.length ? words[i + 1] : null;
    const unit = glueNext === null ? word : `${word} ${glueNext}`;
    const nextLength = current.length === 0 ? unit.length : length + 1 + unit.length;
    if (current.length > 0 && nextLength > width) {
      lines.push(current.join(" "));
      current = [word];
      length = word.length;
    } else {
      current.push(word);
      length = current.length === 1 ? word.length : length + 1 + word.length;
    }
  }
  if (current.length > 0) lines.push(current.join(" "));
  return lines;
}

/**
 * Renders a `prose` group to its canonical physical lines, given the fixed
 * structural prefix (indent + marker, e.g. `"// "` or `" * "`). The group's
 * own `baseIndent` — extra indentation relative to that structural prefix,
 * for a hanging or definition-list-style paragraph that is not itself a
 * bullet — is preserved on every line of the group, not just its first.
 */
function renderProseGroup(group, prefix, maxLength) {
  const linePrefix = prefix + group.baseIndent;
  const availableWidth = Math.max(1, maxLength - linePrefix.length);

  if (!group.bulleted) {
    const words = tokenizeLines(group.lines.map((line) => splitIndent(line.content).text));
    if (words.length === 0) return [linePrefix.replace(/\s+$/, "")];
    return wrapWords(words, availableWidth).map((text) => linePrefix + text);
  }

  const { marker, rest } = group.marker;
  const markerLiteral = `${marker} `;
  const hang = " ".repeat(markerLiteral.length);
  const hangWidth = Math.max(1, availableWidth - markerLiteral.length);

  const words = tokenizeLines([
    rest,
    ...group.lines.slice(1).map((line) => splitIndent(line.content).text),
  ]);

  if (words.length === 0) {
    // A lone "*" (or "-"/"+") bullet marker with no list content at all would
    // otherwise render as a bare trailing asterisk stacked on the structural
    // prefix (e.g. " * *"), indistinguishable from the doubled-marker
    // corruption this rule guards against elsewhere. Fall back to the plain
    // structural prefix instead of emitting that degenerate shape.
    if (marker === "*") return [linePrefix.replace(/\s+$/, "")];
    return [(linePrefix + markerLiteral).replace(/\s+$/, "")];
  }

  const wrapped = wrapWords(words, hangWidth);
  return wrapped.map((text, index) =>
    index === 0 ? linePrefix + markerLiteral + text : linePrefix + hang + text,
  );
}

/** Reads the original full-text lines for a group, for the before/after comparison. */
function actualLines(sourceCode, group) {
  return group.lines.map((line) => sourceCode.lines[line.sourceLine - 1]);
}

/** Reports and fixes one group when its canonical reflow differs from its source text. */
function checkGroup(context, sourceCode, group, canonical) {
  const actual = actualLines(sourceCode, group);
  if (canonical.length === actual.length && canonical.every((text, i) => text === actual[i])) {
    return;
  }

  const firstLine = group.lines[0].sourceLine;
  const lastLine = group.lines[group.lines.length - 1].sourceLine;
  const start = sourceCode.getIndexFromLoc({ line: firstLine, column: 0 });
  const end = sourceCode.getIndexFromLoc({
    line: lastLine,
    column: sourceCode.lines[lastLine - 1].length,
  });

  context.report({
    loc: {
      start: { line: firstLine, column: 0 },
      end: { line: lastLine, column: sourceCode.lines[lastLine - 1].length },
    },
    messageId: "reflow",
    data: { maxLength: String(context.options[0].maxLength) },
    fix(fixer) {
      return fixer.replaceTextRange([start, end], canonical.join("\n"));
    },
  });
}

/**
 * Strips an accidentally-doubled structural marker from the start of a
 * line's content, once its own real prefix has already been removed: a
 * bare leading `* ` for a block line, or `// ` for a line comment. A join
 * that forgets to strip a joined-in physical line's own marker before
 * folding it into flat paragraph text leaves that marker as a literal
 * leading token; left alone, `splitParagraphGroups` then misreads it as a
 * fresh bullet (`matchListMarker` matches a leading `*` or `-`) instead of
 * the corruption artifact it is. Content legitimately starting with a bare
 * marker character immediately followed by whitespace is vanishingly rare
 * in house prose, so this normalization is applied unconditionally.
 */
function stripDoubledMarker(text, kind) {
  const re = kind === "block" ? /^\s*\*\s+/ : /^\s*\/\/\s*/;
  const match = re.exec(text);
  return match ? text.slice(match[0].length) : text;
}

/** Extracts `{ sourceLine, content }` for each line of a run of own-line `//` comments. */
function lineRunToPhysical(sourceCode, tokens) {
  return tokens.map((token) => {
    const lineText = sourceCode.lines[token.loc.start.line - 1];
    const indentLength = /^\s*/.exec(lineText)[0].length;
    let rest = lineText.slice(indentLength + 2);
    if (rest.startsWith(" ")) rest = rest.slice(1);
    rest = stripDoubledMarker(rest, "line");
    return {
      sourceLine: token.loc.start.line,
      content: rest.replace(/\s+$/, ""),
    };
  });
}

/** Parses a multi-line block comment's opening/closing lines and inner `* ` lines. */
function parseBlockLines(sourceCode, token) {
  const startLine = token.loc.start.line;
  const endLine = token.loc.end.line;
  const firstLineText = sourceCode.lines[startLine - 1];
  const lastLineText = sourceCode.lines[endLine - 1];
  const openMatch = /^(\s*)(\/\*\*?)\s*$/.exec(firstLineText);
  const closeMatch = /^(\s*)\*\/\s*$/.exec(lastLineText);
  if (!openMatch || !closeMatch) return null;

  const starIndent = `${openMatch[1]} `;
  const middleLines = [];
  for (let ln = startLine + 1; ln <= endLine - 1; ln++) {
    const text = sourceCode.lines[ln - 1];
    const starMatch = /^(\s*)\*(.*)$/.exec(text);
    if (starMatch) {
      let rest = starMatch[2];
      if (rest.startsWith(" ")) rest = rest.slice(1);
      rest = stripDoubledMarker(rest, "block");
      middleLines.push({ sourceLine: ln, content: rest.replace(/\s+$/, "") });
    } else {
      const raw = /^\s*([\s\S]*)$/.exec(text);
      middleLines.push({
        sourceLine: ln,
        content: (raw[1] ?? "").replace(/\s+$/, ""),
      });
    }
  }
  return { starIndent, middleLines };
}

/** Checks one run of consecutive own-line `//` comments. */
function checkLineRun(context, sourceCode, tokens, maxLength) {
  const physical = lineRunToPhysical(sourceCode, tokens);
  const groups = splitParagraphGroups(physical);
  const indentLength = /^\s*/.exec(sourceCode.lines[tokens[0].loc.start.line - 1])[0].length;
  const sourceIndent = " ".repeat(indentLength);

  for (const group of groups) {
    if (!group.reflow) continue;
    const prefix = `${sourceIndent}// `;
    const canonical = renderProseGroup(group, prefix, maxLength);
    checkGroup(context, sourceCode, group, canonical);
  }
}

/** Checks a single-physical-line block comment (JSDoc-style or plain). */
function checkSingleLineBlock(context, sourceCode, token, maxLength) {
  const lineNumber = token.loc.start.line;
  const raw = sourceCode.lines[lineNumber - 1];
  const match = /^(\s*)(\/\*\*?)\s*([\s\S]*?)\s*\*\/\s*$/.exec(raw);
  if (!match) return;
  const [, indent, markerStyle, inner] = match;

  const singleLine = inner ? `${indent}${markerStyle} ${inner} */` : `${indent}${markerStyle} */`;

  if (singleLine.length <= maxLength) {
    checkGroup(context, sourceCode, { lines: [{ sourceLine: lineNumber }] }, [singleLine]);
    return;
  }

  const starIndent = `${indent} `;
  const words = tokenize(inner);
  const availableWidth = Math.max(1, maxLength - (starIndent.length + 2));
  const contentLines =
    words.length === 0
      ? []
      : wrapWords(words, availableWidth).map((text) => `${starIndent}* ${text}`);
  const canonical = [`${indent}${markerStyle}`, ...contentLines, `${starIndent}*/`];
  checkGroup(context, sourceCode, { lines: [{ sourceLine: lineNumber }] }, canonical);
}

/** Checks a multi-line block comment's inner paragraph groups. */
function checkMultiLineBlock(context, sourceCode, token, maxLength) {
  const parsed = parseBlockLines(sourceCode, token);
  if (!parsed) return;
  const { starIndent, middleLines } = parsed;
  const groups = splitParagraphGroups(middleLines);

  for (const group of groups) {
    if (!group.reflow) continue;
    const prefix = `${starIndent}* `;
    const canonical = renderProseGroup(group, prefix, maxLength);
    checkGroup(context, sourceCode, group, canonical);
  }
}

/** True when nothing but whitespace precedes the comment on its start line. */
function isOwnLine(sourceCode, comment) {
  const lineText = sourceCode.lines[comment.loc.start.line - 1];
  return lineText.slice(0, comment.loc.start.column).trim() === "";
}

/** Groups the file's comments into blocks and maximal runs of own-line `//` lines. */
function buildRuns(sourceCode, comments) {
  const runs = [];
  let i = 0;
  while (i < comments.length) {
    const comment = comments[i];
    if (!isOwnLine(sourceCode, comment)) {
      i += 1;
      continue;
    }
    if (comment.type === "Block") {
      runs.push({ kind: "block", token: comment });
      i += 1;
      continue;
    }
    const group = [comment];
    let j = i + 1;
    while (
      j < comments.length &&
      comments[j].type === "Line" &&
      isOwnLine(sourceCode, comments[j]) &&
      comments[j].loc.start.line === group[group.length - 1].loc.end.line + 1
    ) {
      group.push(comments[j]);
      j += 1;
    }
    runs.push({ kind: "lines", tokens: group });
    i = j;
  }
  return runs;
}

export const refillRule = {
  meta: {
    type: "layout",
    fixable: "code",
    docs: {
      description:
        "reflow comment paragraphs to a configured width, wrapping and refilling both directions",
    },
    schema: {
      type: "array",
      minItems: 1,
      maxItems: 1,
      items: [
        {
          type: "object",
          properties: {
            maxLength: { type: "integer", minimum: 1 },
          },
          required: ["maxLength"],
          additionalProperties: false,
        },
      ],
    },
    messages: {
      reflow:
        "comment paragraph does not match its canonical reflow at {{maxLength}} columns; run --fix to reflow it",
    },
  },
  create(context) {
    const options = context.options[0];
    if (!options || typeof options.maxLength !== "number") {
      throw new Error("comment-refill/refill requires a { maxLength } option; none was provided");
    }
    const maxLength = options.maxLength;
    const sourceCode = context.sourceCode ?? context.getSourceCode();

    return {
      Program() {
        const comments = sourceCode.getAllComments();
        const runs = buildRuns(sourceCode, comments);
        for (const run of runs) {
          if (run.kind === "lines") {
            checkLineRun(context, sourceCode, run.tokens, maxLength);
          } else if (run.token.loc.start.line === run.token.loc.end.line) {
            checkSingleLineBlock(context, sourceCode, run.token, maxLength);
          } else {
            checkMultiLineBlock(context, sourceCode, run.token, maxLength);
          }
        }
      },
    };
  },
};

export {
  splitParagraphGroups,
  wrapWords,
  tokenize,
  tokenizeLines,
  matchListMarker,
  isAlignedTable,
  hasSwallowedCommentPrefix,
  hasUnbalancedBacktick,
  looksLikeCode,
  isTagLine,
  isLabelLine,
  isStructuralDirective,
  stripDoubledMarker,
};
