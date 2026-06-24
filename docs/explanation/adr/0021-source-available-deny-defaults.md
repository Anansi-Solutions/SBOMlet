# ADR-0021: Source-available licences ship as deny defaults

- **Status:** Accepted
- **Date:** 2026-06-24

## Context and problem

[ADR-0015](0015-source-available-deny-list.md) gave the engine a terminal deny
lane and named the licences it exists for — BUSL, SSPL, Elastic. But the actual
deny ENTRIES lived only in `policy.example.toml`, as boilerplate a consumer
copies. A repository that adopts the tool and writes its own `policy.toml` — or
never copies those entries — got ZERO source-available protection.

That is backwards. A source-available licence is the one exposure the gate should
be strictest about: it carries use restrictions (no production use until a change
date, no resale, no managed-service competition) that make the component
unredistributable in a client-shipped artifact AT ALL. A licence-compliance tool
whose out-of-the-box behaviour PASSES such a licence has its defaults inverted —
the highest-risk case was opt-in, while ordinary copyleft was handled by default.

## Decision drivers

- **Correct by default.** The protection that matters most must not depend on a
  consumer copying boilerplate.
- **Compose with consumer policy, don't replace it.** A consumer's own `[[deny]]`
  entries must still work and keep their citations.
- **Minimal surface.** Reuse the deny machinery and the SPDX-satisfies path — no
  new dependency, no new precedence lane.
- **No silent failure.** The shipped patterns join a combined satisfies allowlist;
  one bad id there must not be able to disable the whole lane unnoticed.

## Considered options

1. **Keep them policy-authored** (the status quo).
2. **Ship the well-known source-available licences as engine defaults.**
3. **Ship a broader set** (PolyForm, Confluent, …) as defaults too.

## Decision

We chose option 2. BUSL-1.1, SSPL-1.0, and Elastic-2.0 ship as engine-default
license-mode deny rules (`builtinDenylist.ts`), mirroring the shipped copyleft
families (`copyleft.ts`) and clarify overrides (`builtinOverrides.ts`). The
effective deny set is the consumer's policy denies FIRST, then these defaults; the
OR-election union spans both, so they compose. Attribution is policy-first: a
licence a consumer also lists keeps its `denied[i]` citation, a default-only catch
is cited `default:source-available`.

Only registered SPDX ids ship, and a test asserts it against `spdx-license-ids`.
That guard is load-bearing, not hygiene: the patterns join the combined satisfies
allowlist, and a single non-SPDX id makes `spdx-satisfies` throw — which the
engine's defensive catch turns into "deny nothing" for the ENTIRE union. We found
this the hard way: PolyForm ids, which are not SPDX-registered, silently disabled
every licence deny until the test caught them. That is why option 3 is deferred —
the broader source-available licences have no registered SPDX id (PolyForm) or are
name-only, so they cannot ship as license-mode defaults today.

The non-SPDX riders — Commons-Clause, the Redis RSAL — stay name-mode opt-ins in
the consumer policy. A name-mode default would have to GUESS encumbered package
names, which the matcher must never do.

## Consequences

- **Good:** a source-available licence fails the gate the moment the tool is
  adopted, no policy required. The verdict cites `default:source-available`, names
  the licence, and states the rationale.
- **Good:** no new dependency and no new lane — the defaults are reviewable data
  run through the existing deny election.
- **Cost / known gap:** a consumer cannot currently opt OUT of a builtin
  source-available deny (deny is terminal, above compatible). That is deliberate —
  these licences genuinely cannot ship in a redistributed artifact — but a
  documented, audited opt-out is the obvious follow-up if a legitimate exception
  arises (an internal-only, non-distributed tool, say).
- **Neutral:** `policy.example.toml`'s BUSL/SSPL/Elastic entries are now redundant
  with the defaults; they were removed, leaving the name-mode riders as the worked
  example of the `[[deny]]` syntax.

## See also

- [ADR-0015](0015-source-available-deny-list.md) established the deny lane, its
  terminal precedence, and the OR-election semantics. What THIS record changes is
  that the source-available set now SHIPS rather than being hand-authored.
- Code: `src/policy/builtinDenylist.ts`, `src/policy/denylist.ts`
  (`effectiveDenyRules`), `test/builtinDenylist.test.ts`.
