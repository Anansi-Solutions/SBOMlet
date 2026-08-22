# Provenance: vendored license-compatibility data

The three JSON files in this directory are unmodified, verbatim snapshots of
third-party data. SBOMlet does not edit, reformat, or recompute any part of
them - each is committed byte-for-byte as downloaded, and this file records
where each came from, when, and under what license, so the retrieval
provenance travels with the code rather than living only in a commit message
or a person's memory. Update them with the maintainer-only
`compat:data:update` task (`task compat:data:update --summary` explains its
checks); nothing in the automated test or build pipeline fetches these files
over the network.

## osadl-matrix.json

- **Retrieval URL:** https://www.osadl.org/fileadmin/checklists/matrix.json
- **Retrieval timestamp:** 2026-08-14T00:10:00Z
- **Upstream data timestamp:** 2026-08-04T15:39:00+0000 (the file's own
  top-level `timestamp` field)
- **sha256:** `c5e8b4be3aac00681432ee9ccfd95c532db48b87f304e0fd28a4834b86109477`
- **Data license:** Creative Commons Attribution 4.0 International
  (CC-BY-4.0), as stated for all OSADL checklist raw data at
  https://www.osadl.org/Access-to-raw-data.oss-compliance-raw-data-access.0.html
- **Attribution:** matrix.json carries no embedded attribution text of its
  own; the OSADL checklist project's required attribution string is the one
  embedded in osadl-copyleft.json below, and applies to this file equally
  (both are published by the same OSADL checklist project under the same
  license).
- **Modifications:** none - committed byte-identical to the download.

Pairwise absorption verdicts between 119 SPDX-parseable license ids: for a
leading license T and a subordinate license L, the cell answers "can a work
under L be integrated into a combined work distributed under T." Values are
`Same`, `Yes`, `No`, `Unknown`, or `Check dependency` (a condition, such as an
`-or-later` upgrade clause, can resolve the pair - SBOMlet's loader routes
this to the same honest-residual handling as `Unknown`, never a guess).

## osadl-copyleft.json

- **Retrieval URL:** https://www.osadl.org/fileadmin/checklists/copyleft.json
- **Retrieval timestamp:** 2026-08-14T00:10:00Z
- **Upstream data timestamp:** 2026-08-04T15:39:00+0000 (the file's own
  top-level `timestamp` field)
- **sha256:** `285b8268c219abdd04daf6ca1e44004ea9fd986a96ace5fc44d48c5c1af33098`
- **Data license:** Creative Commons Attribution 4.0 International
  (CC-BY-4.0) - the file's own embedded `license` field reads "Creative
  Commons Attribution 4.0 International license (CC-BY-4.0)".
- **Attribution (verbatim, embedded in the file's `attribution` field):**
  "A project by the Open Source Automation Development Lab (OSADL) eG. For
  further information about the project see the description at
  www.osadl.org/checklists."
- **Copyright (verbatim, embedded in the file's `copyright` field):**
  "(C) 2017 - 2024 Open Source Automation Development Lab (OSADL) eG and
  contributors, info@osadl.org"
- **Disclaimer (verbatim, embedded in the file's `disclaimer` field):** "The
  checklists and particularly the copyleft data have been assembled with
  maximum diligence and care; however, the authors do not warrant nor can be
  held liable in any way for its correctness, usefulness, merchantibility or
  fitness for a particular purpose as far as permissible by applicable law.
  Anyone who uses the information does this on his or her sole
  responsibility. For any individual legal advice, it is recommended to
  contact a lawyer."
- **Modifications:** none - committed byte-identical to the download.

Per-license copyleft class for 125 SPDX-parseable license ids, under the
top-level `copyleft` key. Values are `No`, `Yes`, `Yes (restricted)`, or
`Questionable`. This is the axis a proprietary target uses: a permissive
dependency classes `No`, a strong/network copyleft dependency classes `Yes`,
a boundary-dependent weak copyleft (MPL/LGPL/EPL-2.0-shaped) classes
`Yes (restricted)`, and an unsettled case classes `Questionable`.

## scancode-licensedb-index.json

- **Retrieval URL:** https://scancode-licensedb.aboutcode.org/index.json
- **Retrieval timestamp:** 2026-08-14T00:11:42Z
- **Upstream data timestamp:** 2026-08-10T16:21:01Z (the HTTP `Last-Modified`
  response header observed at retrieval time - the index itself carries no
  embedded timestamp field, unlike the two OSADL files above)
- **sha256:** `af662e3b47f3c8ad76009a5581196ab7c36d796628e1eb463bbfcbccfc39a30a`
- **Data license:** Creative Commons Attribution 4.0 International
  (CC-BY-4.0), as stated at https://scancode-licensedb.aboutcode.org/help.html
- **Attribution:** ScanCode LicenseDB, part of the AboutCode project
  (https://scancode-licensedb.aboutcode.org/).
- **Modifications:** none - committed byte-identical to the download.

Per-license category for 2,733 entries (AboutCode's own curated license list,
broader than the OSADL tables but pairwise-uncovered): `Permissive`,
`Copyleft`, `Copyleft Limited`, `Proprietary Free`, `Source-available`, and
several narrower categories. SBOMlet uses this as the breadth fallback tier
when a dependency's license id is absent from both OSADL tables.
