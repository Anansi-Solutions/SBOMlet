# ADR-0015: Abstain rather than parse a fragile grammar (Terraform, Dockerfile)

- **Status:** Accepted
- **Date:** 2026-06-17 (Terraform); 2026-06-19 (Dockerfile); consolidates the former
  Terraform-gate and Dockerfile-base records

## Context and problem

Two collectors had to answer a narrow question by reading a permissive grammar, and
both started with a hand-rolled parser that adversarial review kept breaking.

The **Terraform** collector reads providers from `.terraform.lock.hcl` and external
modules from `.terraform/modules/modules.json`. `modules.json` exists only after
`tofu init`/`tofu get` has run, so when it is absent the collector must decide: did
init run and find no modules (collect providers, move on), or did init never run
(fail and tell the user to run it)? The first answer scanned the `.tf` files for
`module "..." {` blocks. Finding module blocks means lexing HCL, and four review
rounds each found a valid HCL shape the scanner mis-tokenized — a nested `source`
key, `${...}` interpolation with nested quotes, CR-only line endings, a comment
between `module` and its name — each dropping a module silently.

The **Dockerfile** collector derives the shipped base image: the last `FROM`, with
`--platform` stripped, `ARG` defaults substituted, stage aliases followed. That base
feeds the OS-package scan, so a wrong base scans the wrong image. Here too a close
reader of the file broke on valid inputs: heredocs (`RUN <<EOF … EOF`) whose body
contains a `FROM`, the `# escape=` directive that remaps the continuation character,
a `\` that merges two lines and swallows the final `FROM`. Four rounds each found a
new shape that returned an earlier build-stage base as if it were shipped.

In both cases a mis-parse produces a confident wrong answer that nothing flags, and
each fix invited the next shape.

## Decision drivers

- **Never a silent wrong answer.** A dropped module or a wrong base is scanned and
  reported as if correct. For a compliance tool this outranks always producing an
  answer.
- **Stop the recurring bug class.** The cost was not any single fix but the
  open-ended series of them.
- **Minimal dependencies.** No full HCL or Dockerfile/BuildKit parser to answer one
  narrow question.

## Considered options

1. **Keep hardening the hand-rolled scanner** — patch each mis-tokenization as a
   reviewer finds it.
2. **Add a real parser dependency** — let a maintained library lex correctly.
3. **Stop parsing the grammar** — read a structural signal instead, and abstain when
   the structure is not plainly intact.

## Decision

Both collectors stopped parsing the grammar.

**Terraform reads a filesystem fact.** The real question was never "what is in the
`.tf` files?" but "did `tofu init` run?", and the answer is on disk. `.terraform/` is
gitignored and absent until init materializes it; a providers-only run leaves
`.terraform/providers/` and no `.terraform/modules/`; a run that processes any module
call writes `modules.json` the instant it does so. So `modules.json` absence means
"no module calls" whenever init has run, and init having run is a directory check. No
source is read, so the mis-tokenization class is gone by construction — and about 650
lines of scanner went with it. A later pass tightened the providers-only branch to
fire only on the exact artifact shape a real providers-only init leaves, and fail
loud on every incoherent shape.

**Dockerfile detects the hard constructs' presence and abstains.** `deriveBaseImage`
returns a base only for a file whose `FROM` structure survives tokenization intact
and which uses no heredoc and no escape directive; anything ambiguous returns
`{kind: "unresolved"}`, which is warned and skipped, and the user pins the base with
`--image`. The shift was to stop classifying the hard constructs and detect their
presence: the heredoc machinery was deleted and replaced by a check that abstains
whenever any heredoc opener appears, so a `FROM` inside a heredoc body can never be
read as a stage; a leading `# escape=` abstains rather than re-implementing the
remap; a structural check abstains when comment and continuation processing changed
the `FROM` count or stranded an `AS` alias. Removing the body machinery cut ~70
lines.

Hardening the scanner keeps the bug class alive — four rounds in, the next valid
shape was always out there. A real parser would lex correctly but adds a substantial
dependency to answer a single-token question the structure answers for free. Reading
the signal forecloses the whole class.

Two narrow cases resolve rather than abstain, because they are unambiguous: a
`FROM <N>` whose reference is a bare integer is a hop to the build stage at that
index (like `COPY --from=0`), followed like a named alias; and the Terraform
providers-only branch is a precise artifact-shape match, not a guess.

## Consequences

- **Good:** the silent-wrong-answer class is gone by construction in both collectors,
  not patched shape by shape. No HCL or Dockerfile parser dependency was added, and
  the two collectors shed roughly 650 and 70 lines.
- **Bad / cost:** the Dockerfile side over-abstains — a file whose shipped base is
  plain but which contains a heredoc anywhere, or opens with an escape directive,
  yields no base and is recovered with `--image`. Terraform leaves one window: a
  directory init'd providers-only whose `.tf` later gains a module without re-running
  init presents the providers-only shape and omits the new module. That is delegated
  to `tofu plan`/`validate`/`get` in CI, which hard-error on exactly that state.
- **Neutral:** this is the collector face of the honest-residual rule (ADR-0007) — an
  ambiguous answer is surfaced or abstained on, never guessed. A Terraform mtime
  freshness check was considered for that window and left out, because CI often
  cache-restores `.terraform/` with an older mtime than the checked-out `.tf`, which
  would false-positive on clean runs.

## See also

- Plan summaries:
  `.planning/phases/07-docker-os-packages/07-14-terraform-init-signal-SUMMARY.md`,
  `.planning/phases/07-docker-os-packages/07-28-heredoc-structural-safety-SUMMARY.md`
- Related: [ADR-0007](0007-honest-residual.md) (the honest-residual principle this
  applies), [ADR-0002](0002-orchestrate-standard-generators.md) (Terraform is the
  parse-not-orchestrate exception), [ADR-0012](0012-docker-os-via-syft.md) (the OS
  scan the Dockerfile base feeds)
- Code: `collectors/terraform.ts` (`absentModulesJsonShouldFail`),
  `collectors/dockerfile.ts` (`deriveBaseImage`, `containsHeredocOpener`,
  `escapeDirectivePresent`)
