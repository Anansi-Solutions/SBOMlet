# ADR-0004: Deterministic, timestamp-free output as the foundation of the gate

- **Status:** Accepted
- **Date:** 2026-06-10

## Context and problem

The CI gate regenerates the licence documents and compares them against the
committed copies; if they differ, the committed inventory is stale and the build
fails. That rests on one property: the same inputs produce the same bytes on every
machine. If two runs disagree on a single byte, the gate fails on noise.

Most SBOM tooling makes this hard. The CycloneDX spec recommends a unique
`serialNumber` and a `metadata.timestamp` per document, and the common habit is a
"Generated on …" header. Each changes on every run, so a regenerate-and-diff gate
against them is stale as soon as it passes. The CycloneDX Maven and Cargo plugins
both added reproducible-output modes for this reason. On a Windows host with
`core.autocrlf` on, line endings are a second source of false staleness.

## Decision drivers

- **The gate depends on it.** Byte-comparison is meaningful only if the generator
  is a deterministic function of its inputs.
- **No false positives.** A gate that fails on the clock or a CRLF round-trip gets
  ignored.
- **Legitimate diffs stay legible.** A real change should read as a new dependency,
  a corrected licence, or a pinned version.

## Considered options

1. **Emit timestamps and serial numbers, mask them at compare time** — keep the
   conventional fields, teach the gate to ignore the lines that always move.
2. **Fingerprint the inputs** — write a hash of the inputs into a footer and
   compare the hash instead of regenerating and diffing the bytes.
3. **Emit nothing nondeterministic** — sorted keys, LF only, no timestamps, so the
   committed file is the comparison and a plain byte-compare is the whole gate.

## Decision

We emit nothing that varies between runs, so the committed file is the comparison
and `check` is a byte-compare with no special cases.

Every document is a pure function from the canonical model to exact bytes. Ordering
is a stable total order the tool computes — packages by (name, version, purl),
occurrences by target, object keys sorted by code unit through one shared
serializer — not the order a generator emitted. Output uses `"\n"` literals only,
and the generated files are pinned to LF in `.gitattributes`, so the same model
produces the same bytes on Windows and Linux. `check` normalizes CRLF to LF on the
committed text it reads, which absorbs an unpinned checkout without weakening the
byte comparison.

Nothing carries a timestamp. The Markdown header records how to regenerate
(`task generate`) instead of a date. The CycloneDX export omits the document serial
number and metadata timestamp, both optional. The Docker SBOM pins each image by
content digest, not scan time. Tool versions appear only because mise pins them, so
a version bump is a real diff.

Masking the unstable fields at compare time keeps them and moves the complexity
into the gate — a diff filter to maintain, which also hides any real change that
lands on a masked line. Fingerprinting is faster but passes whenever the inputs are
unchanged, including when the rendering code changed and the file was never
regenerated; it misses stale output, which is what the gate is for. At ~4,300
packages and milliseconds to render, a full regenerate is cheap.

## Consequences

- **Good:** the gate is a byte-compare with no knowledge of Markdown or CycloneDX
  structure, so the renderer can change freely. Every diff in the committed output
  is a real change. `--dump-model` is byte-stable too, so the model is diffable in
  tests.
- **Bad / cost:** determinism is a discipline the whole output path holds. Every
  renderer sorts before it emits and never uses the platform newline, the wall
  clock, or a generator's incidental ordering. A single unsorted map or stray
  `Date.now()` brings back false staleness.
- **Neutral:** the licence-text source is pinned by version for the same reason.
  Determinism is a property of our output; the external generators run upstream of
  the canonical model, and their raw documents are normalized, never diffed.

## See also

- Research: `.planning/research/ARCHITECTURE.md`
- Related: [ADR-0006](0006-policy-emits-verdicts.md) (renderer and gate consume one
  model), [ADR-0008](0008-offline-check-committed-cache.md) (the offline `check`
  this byte-compare underpins)
- Code: `src/render/markdown.ts`, `src/render/cyclonedx.ts`,
  `src/model/dependencies.ts` (`compareCodeUnits`, `sortedKeyReplacer`),
  `src/gate/check.ts`
