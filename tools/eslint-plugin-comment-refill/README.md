# eslint-plugin-comment-refill

An ESLint plugin with one rule, `refill`, that reflows comment paragraphs to
a configured column width. It wraps lines that overflow the width and joins
lines that are under-filled, in both directions, while leaving markdown-like
structure (lists, tables, fenced code, tag blocks) alone.

It exists because the alternative, `eslint-plugin-comment-length`'s
`compact` mode, has no list-marker awareness: it breaks a block only on
blank lines or indentation changes, so it merges a markdown bullet list
straight into the surrounding prose. `refill` treats a bullet marker, a
fenced code block, an aligned table, and a handful of other shapes as hard
paragraph boundaries that a reflow can never cross.

The package has no dependencies of its own beyond ESLint as a peer, and
nothing outside `index.mjs` and `rules/refill.mjs` is required to run it.
It is written to be lifted into its own repository unchanged.

## Usage

```js
// eslint.config.mjs
import commentRefill from "./path/to/eslint-plugin-comment-refill/index.mjs";

export default [
  {
    plugins: { "comment-refill": commentRefill },
    rules: {
      "comment-refill/refill": ["error", { maxLength: 100 }],
    },
  },
];
```

## Option

`refill` takes exactly one option: an object with a required `maxLength`.

```js
{ maxLength: 100 }
```

`maxLength` is the column budget for a fully rendered comment line, prefix
included — the leading indent, the `//` or ` * ` marker, and the mandatory
separating space all count against it. There is no default: the rule's
schema requires the options object and requires `maxLength` on it, so a
configuration that omits either is rejected by ESLint before any file is
linted, rather than silently falling back to a guessed width.

## What gets reflowed

The rule looks at two shapes of comment, and only when each owns its own
line (nothing but whitespace precedes it on the source line):

- A `/** ... */` or `/* ... */` block comment.
- A maximal run of consecutive `//` line comments on adjacent source lines.

A trailing comment — anything with code before it on the same line — is
never touched.

A qualifying comment is split into paragraph groups, and each group is
compared against its own canonical reflow independently. A single comment
can report and fix several unrelated groups; a group that already matches
its canonical form is left alone, so tightly-filled prose is never rewrapped
for no reason.

## Paragraph-group boundaries

A group never merges across any of the following. Each one is exercised by
a fixture in `rules/refill.test.ts`.

1. **Blank comment lines.** An empty `//` or ` *` line is a paragraph
   separator and is preserved exactly as written; it never merges with the
   text before or after it.
2. **Markdown list markers.** A line starting with `-`, `*`, `+`, `•`,
   `1.`, or `1)` (after its indent) always starts a new group, even right
   after a plain-prose line ending in a colon. A bullet's continuation
   lines — lines indented deeper than the marker line itself — belong to
   that bullet's group and refill within it, using a hanging indent equal to
   the marker's own width, so wrapped continuation text lines up under the
   bullet's first word rather than under the marker.
3. **TSDoc/JSDoc `@tag` lines.** A line opening with `@word` stops reflow
   for the remainder of the comment: everything from that line to the
   closing `*/` is left exactly as written, tag continuation lines included.
   The description above the first `@tag` line still reflows normally. This
   is a deliberate v1 limitation: `@param`/`@returns`/`@example` bodies vary
   too much in how a project indents their own continuation lines to reflow
   safely without more structure than this rule tracks, so v1 leaves the
   whole tag section alone rather than guess.
4. **Fenced code and inline code spans.** A ```` ``` ```` line toggles a
   no-touch fence: everything up to the matching closing fence is left
   exactly as written, whitespace included. Outside a fence, a line with an
   odd number of backticks (an inline code span left open at end of line)
   is isolated into its own untouched group and never merges with a
   neighbor. A line with balanced backticks reflows normally, but a wrap
   point is never placed inside a `` `code span` `` — a span with an
   internal space is kept on one line as a single unit. Punctuation glued
   directly onto a span with no space in between (a trailing colon or a
   closing paren, most often) stays glued to it in the output too.
5. **Aligned layout.** A line with three or more consecutive interior
   spaces (for example an arrow-aligned mapping table) is treated as
   layout, not prose, and is excluded from reflow entirely — unless that
   whitespace run sits right after a bare `-` and is immediately followed
   by `//` or `*` (a neighboring comment's own marker, swallowed into this
   line by an upstream join that forgot to strip it). That shape is never
   a deliberately aligned column in this codebase, so it is forced back
   into reflow instead of being permanently hidden; see point 11.
6. **Commented-out code.** A conservative, deliberately narrow heuristic —
   a line ending in `;`, `{`, or `}`, opening with `}`, `)`, or `]`, or
   opening with a common statement keyword (`const`, `return`, `if (`, and
   so on) — excludes that line from reflow. It is isolated the same way an
   aligned-layout line is. This is a known, accepted trade-off: ordinary
   prose that happens to end a semicolon-separated list item with `);`
   (for example a bullet's continuation line ending "...defeats the
   denial);") also matches, and is left exactly as written rather than
   refilled with the rest of its bullet. That is the conservative
   direction to fail in — the alternative is under-catching real
   commented-out code, which is a worse mistake for a linter to make.
7. **Structural tool directives.** A line opening with `eslint-` (covering
   `eslint-disable`, `eslint-disable-next-line`, and `eslint-enable`),
   `@ts-` (`@ts-ignore`, `@ts-expect-error`), `prettier-ignore`, or a
   shebang is isolated exactly like an aligned-layout line: left untouched,
   never merged with a neighbor, never wrapped even past `maxLength`. These
   are read structurally by another tool, not by a person, and reflowing
   one — specifically, wrapping an `eslint-disable-next-line` comment's `--`
   justification onto a second physical line — was observed to corrupt
   unrelated code a few lines later, by way of a fix conflict with ESLint's
   own "unused disable directive" cleanup. Isolating the whole line is the
   only reflow-safe choice.
8. **Labeled clauses.** A line opening with a short label — one to sixteen
   word characters (letters, digits, `_`, `.`, `/`, `+`, `-`), starting with
   a letter or `@`, followed by `:` and a space — always starts a new group,
   exactly like a structural directive, but does reflow normally within that
   group together with its own continuation lines. `TODO:` and `FIXME:` are
   the single-word case of this; the same rule covers a run of parallel
   clauses (`POSIX:` / `win32:`, or `npm:` / `pypi:` / `maven:`), each on its
   own line, so reflow can never fold a later clause up into an earlier
   one's line even when the combined length would fit `maxLength`.
9. **A single word longer than `maxLength`.** Most commonly a URL. It is
   never split, sits alone on its own line, and is accepted as-is: a group
   whose canonical form contains such a line is not reported for exceeding
   `maxLength`, because there is nothing shorter to reflow it to.
10. **An indentation change.** For plain prose, any change in the line's own
    indent starts a new group. For a bulleted group, the equivalent rule is
    the continuation depth described in point 2: a line back at, or
    shallower than, the marker's own indent leaves the bullet's group.

## Block-comment structural limits

A multi-line block comment is only reflowed when its opening line is
exactly `/**` or `/*` (nothing else on that line) and its closing line is
exactly `*/` (nothing else on that line, aside from its own indent). Both of
those structural lines are left untouched — reflow only ever rewrites the
`* `-prefixed lines between them. A block that does not match this shape
(trailing text on the opening or closing line) is left alone entirely: this
is a second, narrower v1 limitation, chosen because guessing where such an
irregular block's real paragraph boundaries are would be more likely to
produce a wrong reflow than no reflow at all.

A single-line block comment (`/** text */` on one physical line) stays
single-line when its canonical form still fits within `maxLength`. When it
does not fit, it is promoted to the standard multi-line form (`/**`, one or
more `* ` lines, `*/`) — but a multi-line block is never collapsed back down
to a single line purely because it has become short enough to fit on one;
the author's choice of block shape is preserved, only its interior content
is rewrapped.

## Hardening against a bad join: the em-dash sweep incident

A prior mechanical find/replace across this codebase (swapping em dashes for
plain hyphens, then re-wrapping by hand in a few spots) manually joined
physical comment lines without stripping the joined-in line's own `* ` or
`// ` marker first. The leftover marker rode along as ordinary text and
landed wherever the greedy line-packer happened to put it: doubled against
the real prefix (`* *`), trailing a swapped hyphen (`- *`), or — for
single-line `//` comments — never re-wrapped at all, left merged mid-line
(`// one // two`) and permanently invisible to this rule because the
swallowed marker's surrounding whitespace looked exactly like an aligned
table column (point 5).

`refill` now guards all three failure modes structurally, so it can never
reproduce them and self-heals the first two on the next `--fix` pass:

11. **Doubled markers self-heal.** Parsing a block or line-comment's
    physical lines strips one accidentally-doubled leading marker (a bare
    `* ` or `// ` immediately following the line's own real prefix) before
    the text ever reaches paragraph-group splitting, so it can never be
    misread as a fresh bullet.
12. **A lone `*` bullet never stacks onto the structural prefix.** A
    bulleted group whose marker has no rest and no continuation renders as
    a plain blank continuation line instead of a bare trailing asterisk.
13. **A standalone `-`, `*`, or `//` token never ends a wrapped line.** The
    greedy packer treats each of these as glued to the token immediately
    after it, so a join can never leave one stranded at a line boundary
    for a later corruption to land beside.

## Determinism

Running the fixer's own output back through the rule always reports zero
problems. Every fixture in `rules/refill.test.ts` that the rule rewrites has
a companion case that feeds the rewritten text back in and asserts exactly
that.
