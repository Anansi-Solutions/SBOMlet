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
precise id with a `[[clarify]]` `expects` override, the same lane as Assessment
conflicts:
[Correct a wrongly-detected or imprecise licence](./writing-policy.md#correct-a-wrongly-detected-or-imprecise-licence).

### 4. Copyleft and special notices: the obligation you might owe

Two different things live in this section. Most rows are `warn` copyleft
findings the policy chose to surface rather than block — read and resolve them
the same way as a `default:copyleft` failure above. An **accepted-AGPL
container notice**, by contrast, is the record of a past decision, not a new
finding: someone already accepted that obligation with `[[compatible]]`.
There's nothing to do with it.

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
