# Reading the output

This guide is for the person whose gate just ran — locally, or in CI — and needs
to decide what to do about it. It doesn't describe every column and section;
that's [output-format.md](../reference/output-format.md), the full reference.
This page routes you from what you see to the fix. If you're setting the tool
up for the first time, start with [`getting-started.md`](../getting-started.md)
instead.

A `generate` run writes two documents:

- `THIRD_PARTY_LICENSES.md` is the inventory and the gate report. This is the
  one you read.
- `THIRD_PARTY_NOTICES.md` is the attribution companion: copyright lines and
  license texts you look up per package, not read through — see
  [The notices companion](#the-notices-companion) below.

## Read it in this order

The document's own section order isn't the triage order — Copyleft comes
before Imprecise, for instance, because that's how
[output-format.md](../reference/output-format.md) lays the page out. Triage a
red gate in this order instead:

1. **Problematic licenses** — what's actually failing the build.
2. **Assessment conflicts** — always a failure too, resolved with a specific
   override.
3. **Imprecise licenses** — not a failure by itself, but flagged for you to
   pin down.
4. **Copyleft and special notices** — the obligations you might owe, failing
   or not.
5. **Target compatibility** — only when you declare a `[target]` profile:
   what that profile decided short of a failure.

Package counts and the Production/Development-only inventory are context for
the rows above, not findings of their own — see
[Counts and inventories](#counts-and-inventories) below.

### 1. Problematic licenses: what's failing the build

Every row here carries a `fail` verdict; this is why `check` exits non-zero.
**Rule** names the policy lane that decided it and **Reason** is that lane's
explanation — read those two first, then **Why** to see how the package got
in. What to do depends on the rule:

- `denied[N]` — the license or package is on your deny list. Deny is
  terminal: nothing else can un-fail it, so don't reach for `[[compatible]]`.
  See
  [Deny a source-available licence or a named package](./writing-policy.md#deny-a-source-available-licence-or-a-named-package)
  to see why, or to find and remove the entry if it's yours to remove.
- `override:stale[clarify]` or `override:stale[builtin]` — a clarification
  recorded what a source reported, and that source now reports something
  else, so the recorded expression is not applied. Read the new value and
  update or retire the entry:
  [Correct a wrongly-detected or imprecise licence](./writing-policy.md#correct-a-wrongly-detected-or-imprecise-licence).
- `clarify:invalid[N]`, or `clarifications:invalid[N]` for an entry in the
  separate clarifications file — every detection the entry recorded still
  holds, but the reason it gives for preferring its expression is one the
  current signal disproves. The failure names where the entry can go
  instead; re-file it under that justification.
- `compatible:voided[N]` — a `[[compatible]]` package entry names whose use
  of a package it judged, and something it accepts arrives through a chain
  passing none of them. The entry then accepts nothing at that target, so
  every package it governs there fails, not only the one that arrives
  around it:
  [Split an acceptance the chains contradict](./writing-policy.md#split-an-acceptance-the-chains-contradict).
- `default:copyleft` — an unaccepted copyleft dependency. Accept it with
  [Allow a licence pattern or an exact package](./writing-policy.md#allow-a-licence-pattern-or-an-exact-package),
  scope that acceptance to where you actually reviewed it with
  [Accept a package only where you reviewed it](./writing-policy.md#accept-a-package-only-where-you-reviewed-it),
  or, if the whole workspace ships under that copyleft family, suppress it with
  [Allow a copyleft dependency inside a copyleft workspace](./writing-policy.md#allow-a-copyleft-dependency-inside-a-copyleft-workspace).
- `default:agpl-container` — an AGPL base-image package. It fails even when
  your other container copyleft is only a warning, because AGPL's
  network-copyleft obligation reaches server-side use. Accept it the same way,
  ideally scoped to the one image you reviewed:
  [Accept a package only where you reviewed it](./writing-policy.md#accept-a-package-only-where-you-reviewed-it).
- `target:incompatible` — a declared `[target]` profile governs this
  occurrence, and combining this dependency's license into a work distributed
  under the target license does not discharge the dependency's obligations.
  Drop or replace the dependency, change the profile if it no longer describes
  your software, or — for a pairing you have examined more closely than the
  matrix can — accept it with
  [Accept a package only where you reviewed it](./writing-policy.md#accept-a-package-only-where-you-reviewed-it).
  See [Adopting a target](./writing-policy.md#adopting-a-target).
- `target:unknown-pair` — no vetted data covers this license pair and you set
  `[target]` `unknown_pair = "fail"`. It is a residual, not a judgment: pin the
  dependency's license down with
  [Correct a wrongly-detected or imprecise licence](./writing-policy.md#correct-a-wrongly-detected-or-imprecise-licence)
  if it is imprecise, or accept the package explicitly. On the default `warn`
  it lands in Target compatibility below instead.
- `conflict:scancode` — this row also appears in Assessment conflicts below;
  resolve it there.
- `default:unknown` — only shows here once you've set `[unknown]` to `fail`.
  See
  [Set how unknown, dev, and OS dependencies are handled](./writing-policy.md#set-how-unknown-dev-and-os-dependencies-are-handled).

### 2. Assessment conflicts: the in-depth scan disagrees

A row here means the in-depth ScanCode assessment read a different license
than the declared or registry quick check. It's always a gate failure —
ScanCode's reading takes priority once both exist, but the tool won't
silently pick a side when they disagree. Decide which reading to trust and
record it:
[Correct a wrongly-detected or imprecise licence](./writing-policy.md#correct-a-wrongly-detected-or-imprecise-licence).

### 3. Imprecise licenses: pin the family down

A row here means the source only named a license family — `BSD`, `Apache` —
with no clause, so the tool won't guess which precise SPDX id you mean. It's
not a failure by itself, but it stays open until you resolve it. State the
precise id with a `[[clarify]]` entry, the same lane as Assessment
conflicts:
[Correct a wrongly-detected or imprecise licence](./writing-policy.md#correct-a-wrongly-detected-or-imprecise-licence).

### 4. Copyleft and special notices: the obligation you might owe

Two different things live in this section. Most rows are `warn` copyleft
findings the policy chose to surface rather than block — read and resolve them
the same way as a `default:copyleft` failure above. An **accepted-AGPL
container notice**, by contrast, is the record of a past decision, not a new
finding: someone already accepted that obligation with `[[compatible]]`.
There's nothing to do with it.

### 5. Target compatibility: what the declared profile decided

This section exists only on a run whose `[target]` profile governs at least
one occurrence, and only for the outcomes that are not already failing above.
It has two parts:

- A flagged table, for `target:boundary`, a warning `target:unknown-pair`, and
  a `target:incompatible` that a development-only occurrence downgraded to a
  warning. A `target:boundary` row is weak copyleft under a proprietary
  target: it is usable behind a compliant linking boundary and nowhere else,
  so confirm the boundary and record that you did with
  [Accept a package only where you reviewed it](./writing-policy.md#accept-a-package-only-where-you-reviewed-it).
  The other two are the same fixes as their failing forms above, at a lower
  volume.
- A "held for internal use" list, for `target:internal-use`: a copyleft or
  AGPL obligation your profile's `distribution = "internal"` (or
  `network = false`) takes out of scope. These pass, and there is nothing to
  do while the profile holds. Read the list the day you flip either flag —
  every entry on it becomes a live obligation again. See
  [The declared profile must be true](./writing-policy.md#the-declared-profile-must-be-true).

## Counts and inventories

The package counts and the Production/Development-only tables are context,
not findings — read them to sanity-check a run, not to triage it. Production
and Development-only always add up to the total; Container and Unknown
license are separate, cross-cutting subtotals, so a package can land in one of
those and still count toward Production or Development-only. A large Unknown
count is a candidate for
[Set how unknown, dev, and OS dependencies are handled](./writing-policy.md#set-how-unknown-dev-and-os-dependencies-are-handled)
once you've burned it down enough to consider `fail`.

If a whole container's findings are false alarms because the image never
ships — a CI-only lint runner, say — don't chase each row individually. Tell
the tool the image never ships:
[Mark a container development-only](./writing-policy.md#mark-a-container-development-only).

## Reading the Why column

Where a **Why** column appears, in Problematic and Copyleft, it answers how a
package got into the workspaces named in **Used in**:

- `direct` — you declared it yourself; drop or swap it there.
- a chain, for example
  `pkg:pypi/copier@9.11.3 → pkg:pypi/jinja2-ansible-filters@1.3.2` — it's
  transitive, and the chain names the parent you'd upgrade or replace to get
  rid of it.
- `—` — no provenance is available for this package (the expected value for
  container packages, Terraform, and Bun). Investigate manually; regenerating
  won't tell you more.

## The exit code

`check`'s exit code is the signal CI acts on: only `0` is a pass. `1` means a
policy fail verdict — everything in Problematic licenses above. `2` means the
committed documents are stale or missing, regardless of policy; a fail verdict
takes priority over staleness, so a real violation still reads `1` even when
the documents are also out of date. See
[cli.md](../reference/cli.md#exit-codes) for the full table, including the
tool-error codes.

## The notices companion

`THIRD_PARTY_NOTICES.md` is the attribution bundle: copyright lines, `NOTICE`
file contents, and license texts, grouped rather than repeated per package.
Open it for one package when you need an obligation's actual wording, and ship
it alongside `THIRD_PARTY_LICENSES.md` at release. See
[output-format.md](../reference/output-format.md#third_party_noticesmd) for
its exact shape.

## Where to go next

- [writing-policy.md](./writing-policy.md) — the recipes this page points at,
  and what to do once nothing in `THIRD_PARTY_LICENSES.md` is left unresolved.
- [output-format.md](../reference/output-format.md) — every column, section,
  and ordering rule, in full.
- [getting-started.md](../getting-started.md) — the first-run walkthrough, the
  exit codes, and the CI wiring.
- [glossary.md](../glossary.md) — the definitions behind the terms used here.
