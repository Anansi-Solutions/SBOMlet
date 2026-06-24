# ADR-0013: The Terraform gate keys on the .terraform/ filesystem signal, not HCL parsing

- **Status:** Accepted
- **Date:** 2026-06-17

## Context and problem

The Terraform collector reads two committed or materialized artifacts —
`.terraform.lock.hcl` for providers and `.terraform/modules/modules.json` for
external modules — and emits a CycloneDX document like every other collector.
`modules.json` only exists once `tofu init`/`tofu get` has run, so when it is
absent the collector has to answer one question: did init run and find no
modules (collect providers and move on), or did init never run (fail loud and
tell the user to run it)? Getting this wrong in the silent direction is the
exact failure the tool exists to prevent — an inventory that looks complete but
quietly omits a module.

The first answer was a hand-written HCL scanner. It read the `.tf` files and
looked for `module "..." { ... }` declarations: if the source declared modules
but `modules.json` was missing, init clearly had not run. The trouble is that
"find the module blocks" means lexing HCL, and HCL has more shapes than a small
scanner can hold. Four consecutive adversarial reviews each found a new, valid
HCL shape the scanner mis-tokenized, and each time the result was a silently
dropped module: a nested `source` key used as a decoy, `${...}` interpolation
with nested quotes, CR-only line endings, and a comment sitting between the
`module` keyword and its quoted name. Every round closed one hole and invited
the next.

## Decision drivers

- **Correctness we cannot give up:** a missing module must never pass silently.
  A scanner that drops a module on an unusual-but-valid input fails the one
  property that matters here.
- **Minimal dependencies:** the tool audits dependency trees, so it keeps its
  own footprint small. Pulling in a full HCL parser to answer one yes/no
  question is a poor trade.
- **Maintenance cost:** a hand-rolled lexer that needed a fix every review round
  is a standing liability, not a settled component.

## Considered options

1. **Keep hardening the hand-written scanner** — patch each mis-tokenization as
   a reviewer finds it.
2. **Add a real HCL parser dependency** — let a maintained library do the lexing
   correctly.
3. **Drop HCL entirely and read a filesystem fact** — `.terraform/` exists if
   and only if init has run, and `modules.json` then answers whether there were
   modules.

## Decision

We read the filesystem fact. The gate's real question was never "what is in the
`.tf` files?" — it was "did `tofu init` run?", and the answer is sitting on disk.
The whole `.terraform/` directory is gitignored and absent until init
materializes it. A providers-only run leaves `.terraform/providers/` and no
`.terraform/modules/`; a run that processes any module call writes
`.terraform/modules/modules.json` the instant it processes the call, before the
provider phase and even when the later download fails. So `modules.json` absence
reliably means "no module calls" whenever init has run, and init having run is
itself a directory check. No source is read, so the entire mis-tokenization bug
class disappears by construction rather than being patched one shape at a time.

Comparing on the driver that decided it:

- **Hardening the scanner** keeps the bug class alive. Four rounds in, the
  evidence was that the next valid shape was always out there. Rejected on
  correctness.
- **An HCL parser dependency** would lex correctly, but it adds a dependency to
  answer a question the filesystem already answers for free, and it would still
  be heavier than the problem. Rejected on the dependency-footprint driver.
- **The filesystem signal** answers the actual question with `existsSync` and
  `statSync`, needs no parsing and no new dependency, and made the silent-drop
  failure structurally impossible. It also deleted roughly 650 lines of scanner
  and its tests.

A later hardening pass tightened the "collect providers-only" branch to fire
only on the exact artifact shape a real providers-only init leaves
(`.terraform/providers/` present, `.terraform/modules/` absent) and to fail loud
on every incoherent shape — an empty or fabricated `.terraform/`, or a
`.terraform/modules/` directory with no `modules.json`. That kept the approach
intact while closing the cheap, no-parsing gaps the final review raised.

## Consequences

- **Good:** the silent-module-drop failure is gone by construction, not by
  patching. No HCL is parsed, no parser dependency was added, and the collector
  shed about 650 lines. The same shared check backs both the collector and the
  coverage policy, so the two cannot drift apart.
- **Bad / cost:** one window stays open. A directory that was init'd
  providers-only and whose `.tf` is later edited to add a module *without*
  re-running init still presents the providers-only shape, so it collects
  providers only and omits the new module. This is delegated to `tofu plan` /
  `tofu validate` / `tofu get` in CI, all of which hard-error "Module not
  installed; run tofu init" on exactly this state — consistent with the tool's
  init-before-generate contract.
- **Neutral:** an mtime freshness check (`.tf` newer than `.terraform/`) was
  considered for that window and deliberately left out. In CI `.terraform/` is
  commonly cache-restored with an older mtime than the freshly checked-out `.tf`,
  which would make the check false-positive and fail clean runs.

## See also

- Plan summaries: `.planning/phases/07-docker-os-packages/07-14-terraform-init-signal-SUMMARY.md`,
  `.planning/phases/07-docker-os-packages/07-15-gate-hardening-SUMMARY.md`
- Code: `collectors/terraform.ts` (`absentModulesJsonShouldFail`)
