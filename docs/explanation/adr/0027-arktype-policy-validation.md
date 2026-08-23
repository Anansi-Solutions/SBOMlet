# ADR-0027: Validate policy shape with arktype, hand-roll the domain rules

- **Status:** Accepted
- **Date:** 2026-08-23

## Context

The policy validator turns a TOML file into a typed `Policy`, or rejects it with
every fault named by table path and key. It hand-wrote every check as one tangle:
field presence, types, closed vocabularies, SPDX parseability, and cross-field
consistency such as a clarify entry whose stated justification contradicts what it
records the sources detected.

Two kinds of check lived in that tangle with no line between them. Mechanical shape
checks — is the key present, is it a string, is it one of five allowed values — are
what any schema library does. Domain checks read the whole entry and encode a rule
the library cannot express. arktype already backed the top-level table shape; the
open question was how far to take it.

## Decision

Split validation by data dependency, not by "shape versus contents".

- **arktype owns everything declarative:** field shape, primitive types, closed
  enums, and SPDX parsing expressed as a morph (a parse-as-you-validate step that
  hands back the typed value). Structural cross-field rules that fit a union go
  here too — version-required-except-for-a-container-os-scope is one shape or the
  other. Parsed, typed data flows straight out.
- **Pure functions own the imperative residue:** the self-contained,
  multi-fault cross-field checks — justification-versus-detected is the archetype
  — written as plain functions returning a list of faults. A small adapter turns
  arktype's own error set into the same `table[i]: <problem>` lines those functions
  produce, so a construct reports both through one contract.
- **Model-dependent checks stay in the pipeline.** As-dependency-of resolution and
  detected-versus-scan need the scan, not the policy text; they were never schema
  concerns and do not move.

The split falls where the data does. The parse-heavy forms — a `[[compatible]]` or
`[[deny]]` licence, a `[[clarify]]` expression — become a clean declarative shape.
The imperative forms — the package selector's exactly-one-of-three, `[target]`'s
all-or-nothing profile — keep a hand-rolled core, with arktype validating only
their declarative envelope. That residue is the design working as intended, not a
gap in it.

Error messages need only be semantically equivalent to the old ones, not
byte-identical. That relaxation is what made the rewrite affordable.

## Consequences

- Each construct reads as a declarative shape plus a thin, named domain function.
  The generated report is unchanged — the byte-exact `check` gate proves it —
  while the negative-case tests move to arktype's phrasing.
- Normalized-licence branding becomes reachable later: the parse morph is the one
  place a raw string becomes a canonical licence, so it can be made the sole mint
  point of a branded type.
- arktype is now load-bearing for parsing. A contributor extending the schema
  learns its morph-and-narrow model, where before they only read plain functions.

## See also

- Related: [ADR-0026](0026-chain-scoped-policy-schema.md) (the entry shapes these
  checks validate)
- Code: `src/policy/schema/` (`arkAdapter.ts`, `spdx.ts`, `scalars.ts`, and the
  per-construct modules)
