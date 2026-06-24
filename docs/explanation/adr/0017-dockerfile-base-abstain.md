# ADR-0017: Dockerfile base derivation abstains on ambiguity

- **Status:** Accepted
- **Date:** 2026-06-19

## Context and problem

Docker discovery walks a repository, finds its Dockerfiles, and derives the
shipped base image each one declares — the last `FROM`'s reference, with
`--platform` stripped, `ARG` defaults substituted, and stage aliases followed.
That base feeds the OS-package scan, so deriving the wrong one means scanning the
wrong image and reporting OS-package obligations the shipped image never carried.

The first derivation read the Dockerfile closely enough to do this well on
ordinary files. The trouble was the inputs that are valid Dockerfiles but do not
match the shape a small parser assumes. Heredocs (`RUN <<EOF … EOF`) carry a body
that can itself contain a `FROM` line. The `# escape=` parser directive remaps
the line-continuation character, so on a Windows Dockerfile a trailing backslash
in a path like `C:\dist\` is a literal, not a continuation. A `\` in the wrong
place merges two physical lines and swallows the final `FROM`. Each of these,
mishandled, made the tokenizer return an *earlier* build-stage base as if it were
the shipped one — a confident wrong answer, the exact failure this tool exists to
avoid.

Four review rounds each found a new valid shape that produced a wrong base, and
each fix to the body-and-continuation machinery invited the next: a fd-prefixed
heredoc opener (`0<<EOF`) the boundary check missed, an indented terminator that
closed a non-dash heredoc early, the Windows escape directive, a dangling
continuation before the final `FROM`.

## Decision drivers

- **Never a wrong base.** A wrong shipped base is silently scanned and silently
  wrong. This is worse than no answer, because nothing flags it. For a compliance
  tool, this property outranks always producing an answer.
- **Stop the recurring bug class.** Each round closed one shape and the next round
  found another. The cost was not any single fix but the open-ended series of
  them.
- **Minimal dependencies.** The tool audits dependency trees, so it does not pull
  in a full Dockerfile parser to answer one narrow question.

## Considered options

1. **Keep hardening the tokenizer** — track heredoc terminators correctly, remap
   the escape character, handle each continuation shape, patch each wrong-base
   shape as a reviewer finds it.
2. **Add a real Dockerfile / BuildKit parser dependency** — let a maintained
   library resolve the final `FROM` correctly.
3. **Resolve only when the structure is plainly intact; abstain otherwise** — do
   not parse heredoc bodies or honor the escape directive at all. Detect that an
   ambiguous construct is *present* and return `unresolved`, which the caller
   loud-skips with a note to pin the base with `--image`.

## Decision

We resolve only when we are certain, and abstain otherwise. `deriveBaseImage`
returns a real base only for a Dockerfile whose `FROM` structure survives
tokenization intact and which uses no heredoc and no escape directive; anything
ambiguous returns `{kind: "unresolved"}`, which is warned and skipped rather than
guessed at. The user then pins that image's base with `--image`.

The shift was to stop *classifying* the hard constructs and instead detect their
*presence*. The heredoc machinery — body consumption, terminator matching,
open-at-EOF tracking — was deleted; in its place a single check abstains whenever
any heredoc opener token appears anywhere in the file. Because no body is ever
parsed, a `FROM` sitting inside a heredoc body can never be mistaken for a stage
and returned as the base — by construction, not by a net that has to catch every
opener shape. The same move handles the rest: a leading `# escape=` directive
abstains rather than re-implementing Docker's escape-char remapping, and a
structural check abstains when comment and continuation processing changed the
`FROM` count between the raw and the tokenized lines, or left an `AS` alias
stranded on its own line.

Comparing on the driver that decided it:

- **Hardening the tokenizer** keeps the wrong-base class alive. Four rounds in,
  the evidence was that the next valid shape was always out there, and a wrong
  base is the failure we cannot tolerate. Rejected on the never-a-wrong-base
  driver.
- **A real parser dependency** would resolve correctly, but it adds a substantial
  dependency to a tool that keeps its own footprint small, for a question that
  abstention answers safely without one. Rejected on the dependency-footprint
  driver.
- **Abstain on ambiguity** forecloses the whole class: the constructs that
  produced every wrong base now produce `unresolved` instead. It is deliberate
  over-abstention — a Dockerfile that merely *contains* a heredoc abstains even
  when its final `FROM` is plain — and that is the trade we want. A loud skip the
  user resolves with `--image` is recoverable; a silent wrong base is not.

One narrower gap was closed rather than abstained on, because resolving it is
unambiguous: a `FROM <N>` whose reference is a bare integer is a hop to the build
stage at that index (the same index space as `COPY --from=0`), so it is followed
like a named alias rather than emitted as a literal image called `0`.

## Consequences

- **Good:** the wrong-base class is gone by construction, not by patching. A
  Dockerfile-body `FROM`, a Windows escape directive, and a continuation that eats
  the final `FROM` all abstain instead of producing a confident wrong answer. No
  Dockerfile parser dependency was added, and removing the body machinery cut
  roughly 70 lines of source.
- **Bad / cost:** the tool over-abstains. A Dockerfile whose shipped base is
  perfectly clear but which happens to contain a heredoc anywhere, or opens with
  an escape directive, yields no derived base. Those cases are recovered by
  pinning the base with `--image`, which is the same path used for any image the
  daemon-free walk cannot resolve.
- **Neutral:** the same honest-residual posture governs the ordinary resolution
  path — an unresolvable `ARG`, a malformed reference, a leading-dash token, or a
  missing `FROM` all abstain rather than emit a guessed base. This is the
  Docker-base instance of the project-wide honest-residual rule: an ambiguous
  answer is surfaced, never guessed. The discovery walk's deliberate exclusion
  limits — generic build-output directory names are not auto-pruned, only
  gitlink-file submodules are skipped — are documented in the collector header,
  not changed here.

## See also

- Plan summaries: `.planning/phases/07-docker-os-packages/07-23-dockerfile-discovery-SUMMARY.md`,
  `07-25-dockerfile-parser-hardening-SUMMARY.md`,
  `07-28-heredoc-structural-safety-SUMMARY.md`,
  `07-29-heredoc-abstain-submodule-prune-SUMMARY.md`,
  `07-30-from-integrity-invariant-SUMMARY.md`,
  `07-31-numeric-stage-index-SUMMARY.md`
- Code: `collectors/dockerfile.ts` (`deriveBaseImage`, `containsHeredocOpener`,
  `escapeDirectivePresent`)
