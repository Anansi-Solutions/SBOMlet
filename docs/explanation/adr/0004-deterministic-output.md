# ADR-0004: Deterministic, timestamp-free output as the foundation of the gate

- **Status:** Accepted
- **Date:** 2026-06-10

## Context and problem

The CI gate works by regenerating the licence documents and comparing them
against the committed copies. If they differ, the committed inventory is stale
and the build fails. That whole idea rests on one property: the same inputs must
produce the same bytes, every time, on every machine. The moment two runs of the
same model can disagree on a single byte, the gate fires on noise and people
learn to ignore it.

Most SBOM and attribution tooling makes this hard for itself. The CycloneDX spec
recommends a unique `serialNumber` and a `metadata.timestamp` per document, and
the common habit is a "Generated on …" header. Each of those changes on every
run by design, so a regenerate-and-diff gate against them is stale the instant
it passes — every regeneration is a diff, and the gate stops meaning anything.
This is a real failure mode in the ecosystem, not a hypothetical: the CycloneDX
Maven and Cargo plugins both had to retrofit reproducible-output modes for
exactly this reason.

We are also a Windows-host project where `core.autocrlf` is commonly on, so line
endings are a second, quieter source of false staleness.

## Decision drivers

- **The gate cannot work without it.** Byte-comparison is only honest if the
  generator is a deterministic function of its inputs. This is a correctness
  property, not a nicety.
- **No false positives.** A gate that fails on the clock ticking, or on a CRLF
  round-trip, trains people to ignore it — which defeats the point of having it.
- **Legitimate diffs stay legible.** When output does change, the change should
  be reviewable: a new dependency, a corrected licence, a pinned tool version —
  never churn no one can explain.

## Considered options

1. **Emit timestamps and serial numbers, mask them at compare time** — keep the
   conventional fields, teach the gate to ignore the lines that always move.
2. **Fingerprint the inputs** — write a hash of the inputs into a footer and have
   the gate compare the hash rather than regenerating and diffing the bytes.
3. **Emit no nondeterministic fields at all** — sorted keys, LF only, no
   timestamps, so the committed file *is* the comparison and a plain byte-compare
   is the whole gate.

## Decision

We emit nothing that varies between runs, so the committed file is the
comparison and `check` is a byte-compare with no special cases.

Every document is a pure function from the canonical model to exact bytes.
Ordering is a stable total order computed by the tool, never the order a
generator happened to emit: packages by (name, version, purl), occurrences by
target, object keys sorted by code unit through one shared serializer. Output is
assembled with `"\n"` literals only — never the platform newline — and the
generated files are pinned to LF in `.gitattributes`, so the same model produces
the same bytes on Windows and Linux. On the comparison side, `check`
normalizes CRLF to LF on the committed text it reads, which absorbs an unpinned
consumer checkout without ever weakening the byte-for-byte test.

Nothing carries a timestamp. The Markdown header records *how to regenerate the
file* — `task licenses:generate` — in place of a date, which only changes when
the command does. The CycloneDX export omits the two fields the spec would
otherwise fill with run-specific values, the document serial number and the
metadata timestamp; both are optional, so the document stays schema-valid by
construction. The Docker SBOM pins each image by content digest, which is stable,
rather than by scan time. Tool versions may appear in output, but only because
mise pins them — a version bump is then a real, reviewable diff, not noise.

On the driver that decided it:

- **Masking timestamps at compare time** keeps the unstable fields and pushes the
  complexity into the gate: a diff filter that has to be kept in step with the
  output format, and that quietly hides any real change living on a masked line.
  Rejected — it makes the gate trust-based instead of exact.
- **Fingerprinting the inputs** is faster but dishonest. A footer hash passes
  whenever the inputs are unchanged, including when the *rendering code* changed
  and the committed file was never regenerated. The thing the gate most needs to
  catch — stale output — is the thing a fingerprint cannot see. At this scale
  (~4,300 packages, milliseconds to render) a full regenerate is cheap enough
  that there is no reason to trade the honest check for the fast one.
- **Emitting nothing nondeterministic** makes the committed bytes the single
  source of truth. The gate is then a plain string comparison with no format
  knowledge, no mask to maintain, and no way for a real change to slip through.

## Consequences

- **Good:** The gate is a byte-compare and nothing more — it needs no awareness
  of Markdown or CycloneDX structure, so the renderer can change freely without
  touching it. Every diff in the committed output is a genuine change a reviewer
  can read. The same determinism makes the `--dump-model` output byte-stable, so
  the model itself is diffable in tests.
- **Bad / cost:** Determinism is a discipline the whole output path has to hold,
  not a feature switched on once. Every renderer must sort before it emits and
  must never reach for the platform newline, the wall clock, or a generator's
  incidental ordering. A single unsorted map or a stray `Date.now()` reintroduces
  the false-staleness the gate exists to avoid, and the cost of a slip lands on
  whoever next runs CI.
- **Neutral:** The license-text source is pinned by version in config for the
  same reason, so texts don't drift between machines. Reproducibility here is a
  property of *our* output; the external generators run upstream of the canonical
  model, and their raw documents are intermediate artifacts we normalize, never
  diff.

## See also

- Research: `.planning/research/ARCHITECTURE.md` (Determinism; Anti-Pattern 2)
- Plan summaries: `.planning/phases/01-pipeline-spine/01-01-SUMMARY.md`,
  `.planning/phases/04-ci-gate-full-attribution/04-06-SUMMARY.md`
- Code: `src/render/markdown.ts`, `src/render/cyclonedx.ts`,
  `src/model/dependencies.ts` (`compareCodeUnits`, `sortedKeyReplacer`),
  `src/gate/check.ts`
- Related: [ADR-0006](0006-policy-emits-verdicts.md) (renderer and gate are pure
  consumers), [ADR-0009](0009-offline-check-committed-cache.md) (offline `check`)
