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

- **arktype owns every single-field check:** field shape, primitive types, closed
  enums, SPDX parsing, and every content rule on one field — a repo-relative path,
  a `where` scope element, a target or workspace licence id, a name-glob pattern,
  a `detected` lane's value — each expressed as a keyword, a union, or a morph (a
  parse-as-you-validate step that hands back the typed value). A field that needs
  several distinct diagnostics for one scalar (a path is absolute AND back-slashed)
  is a morph that rejects each on its own disambiguated sub-path, since arktype's
  scalar refinements short-circuit at the first failure. Parsed, typed data flows
  straight out.
- **Pure functions own the cross-field residue only:** rules that relate two or
  more fields of an entry — justification-versus-detected, version-required-unless-
  the-`where`-is-entirely-a-container-os-scope, the `name`/`pattern`/`packages`
  exactly-one-of selector, `[target]`'s all-or-nothing profile — plus cross-entry
  duplicate detection. A small adapter turns arktype's own error set into the same
  `table[i]: <problem>` lines those functions produce, so a construct reports both
  through one contract.
- **Model-dependent checks stay in the pipeline.** As-dependency-of resolution and
  detected-versus-scan need the scan, not the policy text; they were never schema
  concerns and do not move.

The split falls where the data does. Anything that reads one field — its type, its
closed set, its parseability, its path or glob or licence-id form — is declarative.
Only a rule that reads two or more fields together keeps a hand-rolled core, with
arktype validating every leaf around it. That residue is the design working as
intended, not a gap in it.

Error messages need only be semantically equivalent to the old ones, not
byte-identical. That relaxation is what made the rewrite affordable.

## Consequences

- Each construct reads as a declarative shape plus a thin, named domain function.
  The generated report is unchanged — the byte-exact `check` gate proves it —
  while the negative-case tests move to arktype's phrasing.
- Normalized-licence branding becomes reachable later: the parse morph is the one
  place a raw string becomes a canonical licence, so it can be made the sole mint
  point of a branded type.
- arktype is now load-bearing for parsing and for every single-field rule. A
  contributor extending the schema learns its morph model (a validating parse that
  may reject on disambiguated sub-paths), where before they only read plain
  functions.

## See also

- Related: [ADR-0026](0026-chain-scoped-policy-schema.md) (the entry shapes these
  checks validate)
- Code: `src/policy/schema/` (`arkAdapter.ts`, `spdx.ts`, and the per-construct
  modules)
