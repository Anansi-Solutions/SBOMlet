# Notices placement

This page is for the renderer and anyone changing it. It is the normative
placement specification for `THIRD_PARTY_NOTICES.md` — for any
[package entry](../glossary.md#package-entry), whether it gets an entry, what
that entry contains, and which packages land in the unknown-licenses section.
`src/render/notices.ts` is the implementation; a behavior change to it updates
this page in the same commit. `THIRD_PARTY_LICENSES.md` has its own placement
page, [report-placement.md](./report-placement.md) — the two documents are
verified never to disagree by the cross-document tests in
`test/reportPlacement.test.ts`.

## What the document is for

`THIRD_PARTY_NOTICES.md` is shipped attribution: the copyright lines, `NOTICE`
file contents, and license texts a distributed artifact carries alongside it.
It exists separately from `THIRD_PARTY_LICENSES.md` because attribution is
verbose — repeating a full license text under every package that uses it would
cost several megabytes at repository scale — so this document groups it
instead: attribution once per package that has any, license texts once per
distinct SPDX identifier referenced anywhere in the inventory.

## Section order

Three sections, always in this order: Package attributions, Packages with
unknown licenses, License texts. The second is omitted entirely when no
package qualifies for it; the other two always render (a heading with no rows
below it, for an inventory with nothing to say there).

## Package attributions

A package gets a `###` section only when it has something concrete to
attribute: an extracted copyright line, a `NOTICE` file's contents, an author
(only used when no copyright line was found), or a verbatim license text for a
package with no standard SPDX license. A package with none of these gets no
section — an honest empty, never a fabricated copyright line.

Each section states the package as `name@version`, a `License:` line, then
whatever it has to attribute:

| Field | Source |
| --- | --- |
| `License:` | The package's [license finding](../glossary.md#license-finding): the full expression when exact; `<family> (imprecise)` for an imprecise finding; `unknown` for a null, non-imprecise finding; before annotation, the deduplicated raw [license claims](../glossary.md#license-claim) joined by comma. |
| Copyright lines | Extracted copyright statements, one per bullet. |
| `Author:` | Rendered only when no copyright line was extracted — an attribution, never a copyright claim the tool didn't find. |
| `NOTICE:` | Every extracted `NOTICE` file's contents, each in its own fenced block. |
| Verbatim license text | Rendered for a package with no standard SPDX license, each in its own fenced block. |

Every fenced block's fence is computed longer than the longest run of
backticks already in the content, so untrusted text can never close the fence
early and forge document structure.

## Packages with unknown licenses

Every package for which no license could be determined is listed here by
`name@version`, with no text and a note saying so. Membership is decided by
the SAME `isUnknownLicense` predicate (`src/render/unknownLicense.ts`) that
`THIRD_PARTY_LICENSES.md`'s package-counts block uses for its Unknown license
subtotal. The predicate is a single shared function, not two implementations
kept in sync by hand, precisely so the two documents can never disagree about
which packages are unknown: a package with a null-expression finding, a
finding whose elected branch is composed entirely of `LicenseRef-`/
`DocumentRef-` leaves, or — before annotation — a package with zero license
claims, all count as unknown. An imprecise finding (a bare family like `BSD`
with no clause count) is present, not unknown, and never appears here.

## License texts

One `###` entry per SPDX license identifier referenced by any package's
[license finding](../glossary.md#license-finding), decomposed from the parsed
expression down to its leaves (an `AND`/`OR` compound contributes every leaf it
names) and sorted. Each entry carries the canonical text from the pinned
`spdx-license-list` data package, followed by the marker `(canonical SPDX
text — package-specific copyright not located)` so every fallback to the
generic text is auditable rather than silent. An identifier with no canonical
text available, and any `WITH` exception referenced by a finding, are each
flagged with a line pointing the reader at the package's own license files —
the SPDX license list carries no exception texts.

## Ordering and determinism

Packages are sorted before rendering — a defensive re-sort, so the renderer
never trusts its input's order. The document ends with a single trailing
newline; rendering the same model twice produces byte-identical output.

See also: [output-format.md](./output-format.md#third_party_noticesmd) for the
rendered shape of each section, and
[dependency-classification.md](./dependency-classification.md) for how a
license finding is decided in the first place.

Source: `src/render/notices.ts` (`renderNotices` and its section helpers),
`src/render/unknownLicense.ts` (`isUnknownLicense`).
