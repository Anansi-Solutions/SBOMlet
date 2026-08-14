import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

import { mergeSboms } from "../src/merge/merge";
import {
  toSortedDependenciesJson,
  type CanonicalDependencies,
  type PackageEntry,
  type Verdict,
} from "../src/model/dependencies";
import { annotateFindings } from "../src/normalize/normalize";
import { renderMarkdown, type PolicyView, type TargetProfileSummary } from "../src/render/markdown";
import { renderNotices } from "../src/render/notices";
import type { TargetProfile } from "../src/policy/compat";

const TARGET = "libraries/iframe-rpc";
const SYNTHETIC_TARGET = "apps/synthetic";

function loadFixture(name: string): unknown {
  return JSON.parse(readFileSync(join(import.meta.dir, "fixtures", name), "utf-8"));
}

function golden(name: string): string {
  return readFileSync(join(import.meta.dir, "golden", name), "utf-8");
}

const shapesModel = mergeSboms([
  {
    sbom: loadFixture("license-shapes.json"),
    targetIdentity: SYNTHETIC_TARGET,
  },
]);
const trimmedModel = mergeSboms([
  { sbom: loadFixture("iframe-rpc-trimmed.json"), targetIdentity: TARGET },
]);

// The document goldens lock behavior with unconditional annotation: fixture
// models are annotated with an empty clarify list so License cells show
// normalized expressions. The dump-model golden stays on the raw model.
const annotatedShapes = annotateFindings(shapesModel, []).model;
const annotatedTrimmed = annotateFindings(trimmedModel, []).model;

/**
 * Hand-built policy view for the policy-run golden: the verdict rule strings
 * drive copyleft-table membership — they are not real policy output.
 * pipe|tick`pkg is the flagged package on purpose, locking name-escaping inside
 * the copyleft table; mit-pkg carries a suppressed verdict to lock its
 * omission; the suppressed-workspace description carries every
 * escaping-relevant character class.
 */
const goldenPolicyView: PolicyView = {
  policyPath: "policy.toml",
  suppressedWorkspaces: [
    {
      path: "apps/scratch",
      license: "AGPL-3.0-only",
      description:
        "Scratch fork is itself AGPL-distributed | upstream `scratch-gui` [GPL-compatible]",
    },
  ],
  verdicts: [
    {
      purl: "pkg:npm/pipe-tick-pkg@1.0.0",
      occurrenceTarget: SYNTHETIC_TARGET,
      status: "fail",
      rule: "default:copyleft",
      reason: "synthetic copyleft flag for the golden",
    },
    {
      purl: "pkg:npm/mit-pkg@1.0.0",
      occurrenceTarget: SYNTHETIC_TARGET,
      status: "suppressed",
      rule: "workspace.copyleft_suppressed[0]",
      reason: "suppressed by workspace rule",
    },
    {
      purl: "pkg:npm/expr-pkg@3.0.0",
      occurrenceTarget: SYNTHETIC_TARGET,
      status: "ok",
      rule: "default:ok",
      reason: "no copyleft obligations",
    },
  ],
};

describe("renderMarkdown — golden byte equality", () => {
  test("license-shapes fixture matches its golden byte-for-byte", () => {
    expect(renderMarkdown(annotatedShapes)).toBe(golden("license-shapes.md"));
  });

  test("iframe-rpc-trimmed fixture matches its golden byte-for-byte", () => {
    expect(renderMarkdown(annotatedTrimmed)).toBe(golden("iframe-rpc-trimmed.md"));
  });

  test("license-shapes + hand-built policy view matches the policy golden byte-for-byte", () => {
    expect(renderMarkdown(annotatedShapes, goldenPolicyView)).toBe(
      golden("license-shapes-policy.md"),
    );
  });

  test("toSortedDependenciesJson matches the dump-model golden byte-for-byte", () => {
    expect(toSortedDependenciesJson(shapesModel)).toBe(golden("license-shapes.model.json"));
  });
});

describe("renderMarkdown — determinism contract", () => {
  test("output contains no CR, ends with exactly one trailing LF, and carries no date", () => {
    for (const output of [renderMarkdown(shapesModel), renderMarkdown(trimmedModel)]) {
      expect(output.includes("\r")).toBe(false);
      expect(output.endsWith("\n")).toBe(true);
      expect(output.endsWith("\n\n")).toBe(false);
      expect(/\b20\d\d\b.*generated/i.test(output)).toBe(false);
    }
  });

  test("header carries the regenerate command, never a date", () => {
    // The title is line 1; the dateless auto-generated comment follows,
    // naming `task generate` as the regenerate command.
    const lines = renderMarkdown(shapesModel).split("\n");

    expect(lines[0]).toBe("# Third-Party Licenses");
    expect(lines[2]).toBe("<!-- AUTO-GENERATED - do not edit. Regenerate with: task generate -->");
  });
});

describe("renderMarkdown — cell escaping", () => {
  test("a name containing | and ` renders with both escaped", () => {
    const output = renderMarkdown(shapesModel);

    expect(output.includes("pipe\\|tick\\`pkg")).toBe(true);
    // the raw unescaped name must not appear anywhere
    expect(output.includes("pipe|tick`pkg")).toBe(false);
  });

  test("inline HTML and Markdown link syntax are neutralized", () => {
    const output = renderMarkdown(shapesModel);

    expect(output.includes("evil&lt;img src=x&gt;\\[click me\\](https://evil.example)pkg")).toBe(
      true,
    );
    // no raw HTML tag and no live Markdown link survives anywhere
    expect(output.includes("<img")).toBe(false);
    expect(output.includes("[click me](")).toBe(false);
  });
});

// A package whose in-depth ScanCode assessment (MIT) disagrees with
// the declared quick check (Apache-2.0). annotateFindings attaches the conflict
// marker exactly as the live pipeline does.
function conflictModel(): CanonicalDependencies {
  return annotateFindings(
    {
      packages: [
        {
          purl: "pkg:npm/disputed-pkg@1.0.0",
          name: "disputed-pkg",
          version: "1.0.0",
          occurrences: [{ target: SYNTHETIC_TARGET, isDevDependency: false }],
          licenseClaims: [
            { raw: "Apache-2.0", kind: "expression", source: "generator" },
            { raw: "MIT", kind: "expression", source: "scancode" },
          ],
          scope: "app",
        },
      ],
    },
    [],
  ).model;
}

describe("renderMarkdown — assessment conflicts section", () => {
  test("a conflicted package renders the dedicated section naming the in-depth value, the quick-check value, and where it is used", () => {
    const out = renderMarkdown(conflictModel());

    expect(out.includes("## Assessment conflicts")).toBe(true);
    expect(out.includes("### ScanCode assessment vs quick check")).toBe(true);
    // row shape: Package | In-depth (ScanCode) | Quick check | Used in
    expect(out.includes("| disputed-pkg | MIT | Apache-2.0 | apps/synthetic |")).toBe(true);
    // the cross-image sub-table never appears when there is no such conflict
    expect(out.includes("### Cross-image license claims")).toBe(false);
  });

  test("the same conflict also surfaces as a row in the Problematic licenses table (free, via the fail-verdict grouping) — no separate wiring", () => {
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        {
          purl: "pkg:npm/disputed-pkg@1.0.0",
          occurrenceTarget: SYNTHETIC_TARGET,
          status: "fail",
          rule: "conflict:scancode",
          reason: "assessment conflict — resolve via [[clarify]]",
        },
      ],
    };
    const problematic = renderMarkdown(conflictModel(), view).slice(
      renderMarkdown(conflictModel(), view).indexOf("## Problematic licenses"),
    );

    expect(problematic.includes("conflict:scancode")).toBe(true);
    expect(problematic.includes("disputed-pkg")).toBe(true);
  });

  test("zero conflicts → the section is ABSENT entirely (absent-not-empty; the shapes goldens stay byte-identical)", () => {
    expect(renderMarkdown(shapesModel).includes("## Assessment conflicts")).toBe(false);
    expect(renderMarkdown(annotatedShapes).includes("## Assessment conflicts")).toBe(false);
  });

  test("hostile expression strings in the conflict cells are escaped via escapeCell — pipes and backticks cannot break the table", () => {
    const hostile: CanonicalDependencies = {
      packages: [
        {
          purl: "pkg:npm/evil-pkg@1.0.0",
          name: "evil-pkg",
          version: "1.0.0",
          occurrences: [{ target: SYNTHETIC_TARGET, isDevDependency: false }],
          licenseClaims: [],
          scope: "app",
          finding: {
            expression: "MIT",
            elected: "MIT",
            source: "generator",
            confidence: "exact",
            conflict: {
              kind: "scancode",
              assessed: "MIT | `evil`",
              disagreeing: ["Apache-2.0 | `x`"],
            },
          },
        },
      ],
    };
    const out = renderMarkdown(hostile);

    expect(out.includes("MIT \\| \\`evil\\`")).toBe(true);
    // the raw unescaped pipe+backtick payload never appears
    expect(out.includes("MIT | `evil`")).toBe(false);
  });

  test("determinism: two renders of a conflicted model are byte-identical, conflict section included", () => {
    const model = conflictModel();

    expect(renderMarkdown(model)).toBe(renderMarkdown(model));
  });

  test("determinism: two renders of a cross-image conflicted model are byte-identical", () => {
    const model: CanonicalDependencies = {
      packages: [
        {
          purl: "pkg:apk/alpine/busybox@1.37.0-r20",
          name: "busybox",
          version: "1.37.0-r20",
          occurrences: [
            { target: "docker:image-a", isDevDependency: false },
            { target: "docker:image-b", isDevDependency: false },
          ],
          licenseClaims: [],
          scope: "os",
          finding: {
            expression: "MIT AND Apache-2.0",
            elected: "MIT AND Apache-2.0",
            source: "generator",
            confidence: "exact",
            conflict: {
              kind: "cross-image-claims",
              byTarget: [
                { target: "docker:image-a", claims: ["MIT"] },
                { target: "docker:image-b", claims: ["Apache-2.0"] },
              ],
            },
          },
        },
      ],
    };

    expect(renderMarkdown(model)).toBe(renderMarkdown(model));
  });

  test("a cross-image claim divergence renders its own sub-table naming every diverging image and its own claims", () => {
    const model: CanonicalDependencies = {
      packages: [
        {
          purl: "pkg:apk/alpine/busybox@1.37.0-r20",
          name: "busybox",
          version: "1.37.0-r20",
          occurrences: [
            { target: "docker:image-a", isDevDependency: false },
            { target: "docker:image-b", isDevDependency: false },
          ],
          licenseClaims: [],
          scope: "os",
          finding: {
            expression: "MIT AND Apache-2.0",
            elected: "MIT AND Apache-2.0",
            source: "generator",
            confidence: "exact",
            conflict: {
              kind: "cross-image-claims",
              byTarget: [
                { target: "docker:image-a", claims: ["MIT"] },
                { target: "docker:image-b", claims: ["Apache-2.0"] },
              ],
            },
          },
        },
      ],
    };
    const out = renderMarkdown(model);

    expect(out.includes("## Assessment conflicts")).toBe(true);
    expect(out.includes("### Cross-image license claims")).toBe(true);
    expect(out.includes("| busybox | docker:image-a: MIT; docker:image-b: Apache-2.0 |")).toBe(
      true,
    );
    // the ScanCode sub-table never appears when there is no such conflict
    expect(out.includes("### ScanCode assessment vs quick check")).toBe(false);
  });

  test("a cross-image image with no declared claim renders as '(no declared license)', never a blank cell", () => {
    const model: CanonicalDependencies = {
      packages: [
        {
          purl: "pkg:apk/alpine/busybox@1.37.0-r20",
          name: "busybox",
          version: "1.37.0-r20",
          occurrences: [
            { target: "docker:image-a", isDevDependency: false },
            { target: "docker:image-b", isDevDependency: false },
          ],
          licenseClaims: [],
          scope: "os",
          finding: {
            expression: null,
            elected: null,
            source: "generator",
            confidence: "none",
            conflict: {
              kind: "cross-image-claims",
              byTarget: [
                { target: "docker:image-a", claims: [] },
                { target: "docker:image-b", claims: ["MIT"] },
              ],
            },
          },
        },
      ],
    };
    const out = renderMarkdown(model);

    expect(
      out.includes("| busybox | docker:image-a: (no declared license); docker:image-b: MIT |"),
    ).toBe(true);
  });
});

describe("renderMarkdown — table content", () => {
  test("a package with zero licenseClaims renders License cell 'unknown'", () => {
    const output = renderMarkdown(trimmedModel);

    expect(output.includes("| acorn | npm | 8.11.3 | unknown | libraries/iframe-rpc |")).toBe(true);
  });

  test("rows are ordered by (name, version, purl) codepoint ascending within each section", () => {
    // The summary table split into prod + dev-only sections. Each
    // section is independently comparePackages-sorted. dup-pkg has a production
    // twin in the fixture, so the prod-wins merge places it in the production
    // section (between apache-name-pkg and empty-group-pkg) and the
    // development-only section is empty.
    const output = renderMarkdown(shapesModel);
    const prodStart = output.indexOf("## Production dependencies");
    const devStart = output.indexOf("## Development-only dependencies");
    const namesIn = (section: string): (string | undefined)[] =>
      section
        .split("\n")
        .filter((line) => line.startsWith("| ") && !line.startsWith("| ---"))
        .map((line) => line.split(" | ")[0]?.slice(2))
        .filter((name) => name !== "Name");

    expect(namesIn(output.slice(prodStart, devStart))).toEqual([
      "apache-name-pkg",
      "dup-pkg",
      "empty-group-pkg",
      "evil&lt;img src=x&gt;\\[click me\\](https://evil.example)pkg",
      "expr-pkg",
      "mit-pkg",
      "no-license-pkg",
      "pipe\\|tick\\`pkg",
    ]);
    expect(namesIn(output.slice(devStart))).toEqual([]);
  });

  test("Used in column shows occurrences joined by ', '", () => {
    const multi = mergeSboms([
      { sbom: loadFixture("iframe-rpc-trimmed.json"), targetIdentity: TARGET },
      {
        sbom: loadFixture("iframe-rpc-trimmed.json"),
        targetIdentity: "apps/example",
      },
    ]);
    const output = renderMarkdown(multi);

    expect(
      output.includes("| acorn | npm | 8.11.3 | unknown | apps/example, libraries/iframe-rpc |"),
    ).toBe(true);
  });

  test("a two-occurrence package renders Used-in as comma-joined identities", () => {
    // Direct-model test against the Occurrence contract: the rendered string
    // is byte-identical to the Phase-1 string output for the same targets.
    const model: CanonicalDependencies = {
      packages: [
        {
          purl: "pkg:npm/two-target-pkg@1.0.0",
          name: "two-target-pkg",
          version: "1.0.0",
          occurrences: [
            { target: "apps/a", isDevDependency: true },
            { target: "apps/b", isDevDependency: false },
          ],
          licenseClaims: [],
          scope: "app",
        },
      ],
    };
    const output = renderMarkdown(model);

    expect(output.includes("| two-target-pkg | npm | 1.0.0 | unknown | apps/a, apps/b |")).toBe(
      true,
    );
  });

  test("same raw value under different claim kinds renders once", () => {
    // The model keeps both claims on purpose (provenance: claim identity is
    // kind + source + raw) — the RENDERED cell must still dedup the text.
    const model: CanonicalDependencies = {
      packages: [
        {
          purl: "pkg:npm/dual-kind-pkg@1.0.0",
          name: "dual-kind-pkg",
          version: "1.0.0",
          occurrences: [{ target: "apps/a", isDevDependency: false }],
          licenseClaims: [
            { raw: "MIT", kind: "spdx-id", source: "generator" },
            { raw: "MIT", kind: "name", source: "generator" },
          ],
          scope: "app",
        },
      ],
    };
    const output = renderMarkdown(model);

    expect(output.includes("| dual-kind-pkg | npm | 1.0.0 | MIT | apps/a |")).toBe(true);
    expect(output.includes("MIT, MIT")).toBe(false);
  });

  test("duplicate entries inside one component's claims dedup preserving first-seen order", () => {
    // A single component's licenses[] is stored verbatim at entry creation
    // (merge dedup only runs for SUBSEQUENT inputs), so duplicates can reach
    // the renderer directly. Distinct values keep first-appearance order.
    const model: CanonicalDependencies = {
      packages: [
        {
          purl: "pkg:npm/dup-claims-pkg@1.0.0",
          name: "dup-claims-pkg",
          version: "1.0.0",
          occurrences: [{ target: "apps/a", isDevDependency: false }],
          licenseClaims: [
            { raw: "Apache-2.0", kind: "spdx-id", source: "generator" },
            { raw: "MIT", kind: "spdx-id", source: "generator" },
            { raw: "Apache-2.0", kind: "spdx-id", source: "generator" },
          ],
          scope: "app",
        },
      ],
    };
    const output = renderMarkdown(model);

    expect(output.includes("| dup-claims-pkg | npm | 1.0.0 | Apache-2.0, MIT | apps/a |")).toBe(
      true,
    );
  });

  test("renderer re-sorts defensively even when given an unsorted model", () => {
    const reversed = { packages: [...shapesModel.packages].reverse() };

    expect(renderMarkdown(reversed)).toBe(renderMarkdown(shapesModel));
  });
});

// ---------------------------------------------------------------------------
// Full document format. Models and policy views are hand-built: the renderer
// is tested against the model contract, independent of mergeSboms/normalize.
// ---------------------------------------------------------------------------

/** Hand-built PackageEntry with sensible defaults for contract tests. */
function entry(
  partial: Partial<PackageEntry> & Pick<PackageEntry, "name" | "version" | "purl">,
): PackageEntry {
  return {
    occurrences: [{ target: "apps/a", isDevDependency: false }],
    licenseClaims: [],
    scope: "app",
    ...partial,
  };
}

const sharpEntry = entry({
  purl: "pkg:npm/sharp@0.33.0",
  name: "sharp",
  version: "0.33.0",
  occurrences: [
    { target: "docs", isDevDependency: false },
    { target: "frontend", isDevDependency: false },
  ],
  licenseClaims: [{ raw: "LGPL-3.0-or-later", kind: "spdx-id", source: "generator" }],
  finding: {
    expression: "LGPL-3.0-or-later",
    elected: "LGPL-3.0-or-later",
    source: "generator",
    confidence: "exact",
  },
});

const policyModel: CanonicalDependencies = { packages: [sharpEntry] };

const basicView: PolicyView = {
  policyPath: "policy.toml",
  suppressedWorkspaces: [
    {
      path: "apps/scratch",
      license: "AGPL-3.0-only",
      description: "Scratch fork is itself AGPL-distributed",
    },
  ],
  verdicts: [
    {
      purl: "pkg:npm/sharp@0.33.0",
      occurrenceTarget: "frontend",
      status: "fail",
      rule: "default:copyleft",
      reason: 'copyleft license "LGPL-3.0-or-later"',
    },
    {
      purl: "pkg:npm/sharp@0.33.0",
      occurrenceTarget: "docs",
      status: "suppressed",
      rule: "workspace.copyleft_suppressed[0]",
      reason: "suppressed by workspace rule",
    },
  ],
};

describe("renderMarkdown — the full document", () => {
  test("Test 1: policy render emits the fixed section order with no date", () => {
    const output = renderMarkdown(policyModel, basicView);
    const lines = output.split("\n");

    expect(lines[0]).toBe("# Third-Party Licenses");

    // Document order: header comment with the regenerate command, policy
    // pointer, counts block, copyleft section, summary table.
    const markers = [
      "task generate",
      "Copyleft notice rules are configured in policy.toml.",
      "**Package counts:**",
      "## Copyleft and special notices",
      // The single summary table split into prod + dev-only sections,
      // production first for determinism.
      "## Production dependencies",
      "## Development-only dependencies",
    ];
    const positions = markers.map((marker) => output.indexOf(marker));

    for (const position of positions) {
      expect(position).toBeGreaterThan(-1);
    }

    expect(positions).toEqual([...positions].sort((a, b) => a - b));

    // No date string anywhere.
    expect(/\b20\d\d-\d\d-\d\d\b/.test(output)).toBe(false);
    expect(/\b20\d\d\b.*generated/i.test(output)).toBe(false);
  });

  test("Test 2: no-policy render has no policy pointer and no copyleft section", () => {
    const output = renderMarkdown(policyModel);

    expect(output.includes("Copyleft notice rules")).toBe(false);
    expect(output.includes("## Copyleft and special notices")).toBe(false);
    // ...but the header, counts block, and summary are all present.
    expect(output.includes("task generate")).toBe(true);
    expect(output.includes("**Package counts:**")).toBe(true);
    // Both summary sections render even without a policy view.
    expect(output.includes("## Production dependencies")).toBe(true);
    expect(output.includes("## Development-only dependencies")).toBe(true);
  });

  test("Test 3: counts block — total, per-ecosystem compareCodeUnits, unknown count", () => {
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:npm/a-pkg@1.0.0",
          name: "a-pkg",
          version: "1.0.0",
          finding: {
            expression: "MIT",
            elected: "MIT",
            source: "generator",
            confidence: "exact",
          },
        }),
        entry({
          purl: "pkg:npm/b-pkg@1.0.0",
          name: "b-pkg",
          version: "1.0.0",
          finding: {
            expression: null,
            elected: null,
            source: "generator",
            confidence: "none",
          },
        }),
        entry({
          purl: "pkg:pypi/c-pkg@2.0.0",
          name: "c-pkg",
          version: "2.0.0",
          finding: {
            expression: "Apache-2.0",
            elected: "Apache-2.0",
            source: "generator",
            confidence: "exact",
          },
        }),
      ],
    };
    const output = renderMarkdown(model);

    expect(output.includes("- Total packages: 3")).toBe(true);
    expect(output.includes("- npm: 2")).toBe(true);
    expect(output.includes("- pypi: 1")).toBe(true);
    expect(output.includes("- Unknown license: 1")).toBe(true);
    // Ecosystem lines sorted compareCodeUnits: npm before pypi.
    expect(output.indexOf("- npm: 2")).toBeLessThan(output.indexOf("- pypi: 1"));
  });

  test("Test 4: License column — full expression, unknown on null, raw-claims fallback", () => {
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:npm/expr@1.0.0",
          name: "expr",
          version: "1.0.0",
          licenseClaims: [
            {
              raw: "MIT OR Apache-2.0",
              kind: "expression",
              source: "generator",
            },
          ],
          finding: {
            expression: "MIT OR Apache-2.0",
            elected: "Apache-2.0",
            source: "generator",
            confidence: "exact",
          },
        }),
        entry({
          purl: "pkg:npm/legacy@1.0.0",
          name: "legacy",
          version: "1.0.0",
          licenseClaims: [
            { raw: "ISC", kind: "spdx-id", source: "generator" },
            { raw: "ISC", kind: "name", source: "generator" },
          ],
        }),
        entry({
          purl: "pkg:npm/mystery@1.0.0",
          name: "mystery",
          version: "1.0.0",
          licenseClaims: [{ raw: "Custom License", kind: "name", source: "generator" }],
          finding: {
            expression: null,
            elected: null,
            source: "generator",
            confidence: "none",
          },
        }),
      ],
    };
    const output = renderMarkdown(model);

    // Full normalized expression — NEVER only the elected branch.
    expect(output.includes("| expr | npm | 1.0.0 | MIT OR Apache-2.0 | apps/a |")).toBe(true);
    expect(output.includes("| expr | npm | 1.0.0 | Apache-2.0 |")).toBe(false);
    // Null expression renders "unknown" even though a raw claim exists.
    expect(output.includes("| mystery | npm | 1.0.0 | unknown | apps/a |")).toBe(true);
    // No finding at all → existing raw-claims dedup join (pre-annotation
    // tolerance).
    expect(output.includes("| legacy | npm | 1.0.0 | ISC | apps/a |")).toBe(true);
  });

  test("Test 5: copyleft membership + copyleft-only dedup — a fail verdict of ANY rule excludes the purl from Copyleft entirely; a warn-only default:copyleft package stays a member; Used-in lists only flagged targets", () => {
    const warnOnlyCopyleft = entry({
      purl: "pkg:npm/warn-only-copyleft@1.0.0",
      name: "warn-only-copyleft",
      version: "1.0.0",
      occurrences: [
        { target: "backend", isDevDependency: false },
        { target: "frontend", isDevDependency: false },
      ],
      licenseClaims: [{ raw: "LGPL-3.0-or-later", kind: "spdx-id", source: "generator" }],
      finding: {
        expression: "LGPL-3.0-or-later",
        elected: "LGPL-3.0-or-later",
        source: "generator",
        confidence: "exact",
      },
    });
    const model: CanonicalDependencies = {
      packages: [
        sharpEntry,
        warnOnlyCopyleft,
        entry({
          purl: "pkg:npm/suppressed-only@1.0.0",
          name: "suppressed-only",
          version: "1.0.0",
          occurrences: [{ target: "apps/scratch", isDevDependency: false }],
          licenseClaims: [{ raw: "GPL-3.0-only", kind: "spdx-id", source: "generator" }],
          finding: {
            expression: "GPL-3.0-only",
            elected: "GPL-3.0-only",
            source: "generator",
            confidence: "exact",
          },
        }),
        entry({
          purl: "pkg:npm/unknown-pkg@1.0.0",
          name: "unknown-pkg",
          version: "1.0.0",
          finding: {
            expression: null,
            elected: null,
            source: "generator",
            confidence: "none",
          },
        }),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        // sharp carries BOTH a fail (frontend) and a warn (backend) verdict for
        // the SAME rule -- the observed duplication defect this dedup fixes:
        // the purl has a fail verdict, so it is excluded from Copyleft
        // entirely, even though a warn default:copyleft verdict also exists.
        {
          purl: "pkg:npm/sharp@0.33.0",
          occurrenceTarget: "frontend",
          status: "fail",
          rule: "default:copyleft",
          reason: 'copyleft license "LGPL-3.0-or-later"',
        },
        {
          purl: "pkg:npm/sharp@0.33.0",
          occurrenceTarget: "backend",
          status: "warn",
          rule: "default:copyleft",
          reason: 'copyleft license "LGPL-3.0-or-later"',
        },
        {
          purl: "pkg:npm/sharp@0.33.0",
          occurrenceTarget: "docs",
          status: "suppressed",
          rule: "workspace.copyleft_suppressed[0]",
          reason: "suppressed by workspace rule",
        },
        // warn-only-copyleft carries ONLY warn default:copyleft verdicts, no
        // fail anywhere -- it stays a Copyleft member.
        {
          purl: "pkg:npm/warn-only-copyleft@1.0.0",
          occurrenceTarget: "backend",
          status: "warn",
          rule: "default:copyleft",
          reason: 'copyleft license "LGPL-3.0-or-later"',
        },
        {
          purl: "pkg:npm/warn-only-copyleft@1.0.0",
          occurrenceTarget: "frontend",
          status: "warn",
          rule: "default:copyleft",
          reason: 'copyleft license "LGPL-3.0-or-later"',
        },
        {
          purl: "pkg:npm/unknown-pkg@1.0.0",
          occurrenceTarget: "apps/a",
          status: "warn",
          rule: "default:unknown",
          reason: "no license could be determined",
        },
        {
          purl: "pkg:npm/suppressed-only@1.0.0",
          occurrenceTarget: "apps/scratch",
          status: "suppressed",
          rule: "workspace.copyleft_suppressed[0]",
          reason: "suppressed by workspace rule",
        },
      ],
    };
    const output = renderMarkdown(model, view);
    const copyleftStart = output.indexOf("## Copyleft and special notices");
    const summaryStart = output.indexOf("## Production dependencies");

    expect(copyleftStart).toBeGreaterThan(-1);
    const copyleftSection = output.slice(copyleftStart, summaryStart);

    // Dedup: sharp has a fail verdict for its purl, so it is excluded from
    // Copyleft entirely -- the observed duplication defect is gone.
    expect(copyleftSection.includes("sharp")).toBe(false);
    // Membership stands for a warn-only default:copyleft package; Used-in
    // lists ONLY the flagged targets, compareCodeUnits-sorted.
    expect(
      copyleftSection.includes(
        "| warn-only-copyleft | npm | 1.0.0 | LGPL-3.0-or-later | backend, frontend | — |",
      ),
    ).toBe(true);
    // default:unknown warns and suppressed-only packages are omitted.
    expect(copyleftSection.includes("unknown-pkg")).toBe(false);
    expect(copyleftSection.includes("suppressed-only")).toBe(false);
    // Inventory completeness: sharp is EXCLUDED from Copyleft but STILL rows
    // in its Production/Development table (the dedup never drops inventory).
    const summary = output.slice(summaryStart);

    expect(summary.includes("| sharp | npm | 0.33.0 |")).toBe(true);
    expect(summary.includes("| unknown-pkg |")).toBe(true);
    expect(summary.includes("| suppressed-only |")).toBe(true);
  });

  test("Test 5b: container system-package copyleft is routine and never surfaces in Copyleft, whatever its verdict status; the same warn on an APP package still surfaces", () => {
    const osCopyleft = entry({
      purl: "pkg:deb/debian/libssl@3.0",
      name: "libssl",
      version: "3.0",
      occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
      licenseClaims: [{ raw: "GPL-3.0-only", kind: "spdx-id", source: "generator" }],
      finding: {
        expression: "GPL-3.0-only",
        elected: "GPL-3.0-only",
        source: "generator",
        confidence: "exact",
      },
      scope: "os",
    });
    const appCopyleft = entry({
      purl: "pkg:npm/app-copyleft@1.0.0",
      name: "app-copyleft",
      version: "1.0.0",
      occurrences: [{ target: "backend", isDevDependency: false }],
      licenseClaims: [{ raw: "GPL-3.0-only", kind: "spdx-id", source: "generator" }],
      finding: {
        expression: "GPL-3.0-only",
        elected: "GPL-3.0-only",
        source: "generator",
        confidence: "exact",
      },
    });
    const model: CanonicalDependencies = {
      packages: [osCopyleft, appCopyleft],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        {
          purl: "pkg:deb/debian/libssl@3.0",
          occurrenceTarget: "docker:img/Dockerfile",
          status: "warn",
          rule: "default:copyleft",
          reason: "os-downgraded copyleft",
        },
        {
          purl: "pkg:npm/app-copyleft@1.0.0",
          occurrenceTarget: "backend",
          status: "warn",
          rule: "default:copyleft",
          reason: 'copyleft license "GPL-3.0-only"',
        },
      ],
    };
    const output = renderMarkdown(model, view);
    const copyleftStart = output.indexOf("## Copyleft and special notices");
    const copyleftSection = output.slice(copyleftStart, output.indexOf("## Containers"));

    // Container copyleft is routine — excluded from the detailed table
    // regardless of its warn status.
    expect(copyleftSection.includes("libssl")).toBe(false);
    // The app copyleft obligation is never dropped.
    expect(
      copyleftSection.includes("| app-copyleft | npm | 1.0.0 | GPL-3.0-only | backend | — |"),
    ).toBe(true);
  });

  test("Test 5c: an accepted-AGPL container notice (PolicyView.acceptedContainerNotices) renders as a special-notice bullet, distinct from the flagged copyleft table, and is deduped when the same purl also carries a fail verdict elsewhere", () => {
    const model: CanonicalDependencies = { packages: [] };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        {
          purl: "pkg:deb/debian/agpl-also-failing@2.0.0",
          occurrenceTarget: "docker:img/Dockerfile",
          status: "fail",
          rule: "default:agpl-container",
          reason: "fails elsewhere",
        },
      ],
      acceptedContainerNotices: [
        {
          purl: "pkg:deb/debian/agpl-daemon@1.0.0",
          name: "agpl-daemon",
          version: "1.0.0",
          license: "AGPL-3.0-only",
          targets: ["docker:img/Dockerfile"],
          rule: "compatible[0]",
          reason: 'package "agpl-daemon" accepted by compatible package rule: reviewed',
        },
        // This purl ALSO carries a fail verdict above — must be excluded
        // from the notice list (the same Problematic dedup the flagged
        // copyleft rows already apply).
        {
          purl: "pkg:deb/debian/agpl-also-failing@2.0.0",
          name: "agpl-also-failing",
          version: "2.0.0",
          license: "AGPL-3.0-only",
          targets: ["docker:img/Dockerfile"],
          rule: "compatible[1]",
          reason: 'package "agpl-also-failing" accepted by compatible package rule: reviewed',
        },
      ],
    };
    const output = renderMarkdown(model, view);
    const copyleftStart = output.indexOf("## Copyleft and special notices");
    const copyleftSection = output.slice(copyleftStart, output.indexOf("## Containers"));

    expect(copyleftSection.includes("agpl-daemon@1.0.0")).toBe(true);
    expect(copyleftSection.includes("accepted via compatible\\[0\\]")).toBe(true);
    // Deduped: the purl with a fail verdict elsewhere never surfaces as a notice.
    expect(copyleftSection.includes("agpl-also-failing")).toBe(false);
    // Never a row in the flagged copyleft TABLE (that table is scoped to
    // rule === "default:copyleft" fail/warn verdicts, not notices).
    expect(copyleftSection.includes("| agpl-daemon | deb |")).toBe(false);
  });

  test("Test 5d: an accepted-AGPL notice alone (no flagged copyleft rows) makes the section non-empty — the ✅ empty-state line is suppressed", () => {
    const model: CanonicalDependencies = { packages: [] };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [],
      acceptedContainerNotices: [
        {
          purl: "pkg:deb/debian/agpl-daemon@1.0.0",
          name: "agpl-daemon",
          version: "1.0.0",
          license: "AGPL-3.0-only",
          targets: ["docker:img/Dockerfile"],
          rule: "compatible[0]",
          reason: "accepted",
        },
      ],
    };
    const output = renderMarkdown(model, view);
    const copyleftStart = output.indexOf("## Copyleft and special notices");
    const copyleftSection = output.slice(copyleftStart, output.indexOf("## Containers"));

    expect(copyleftSection.includes("agpl-daemon")).toBe(true);
    expect(
      copyleftSection.includes("✅ No package carries copyleft or special license obligations."),
    ).toBe(false);
  });

  test("Test 6: suppressed workspaces render path + license + description escaped", () => {
    const view: PolicyView = {
      policyPath: "configs/policy|v2.toml",
      suppressedWorkspaces: [
        {
          path: "apps/scratch",
          license: "AGPL-3.0-only",
          description: "fork | of `scratch-gui`\nAGPL upstream",
        },
      ],
      verdicts: [],
    };
    const output = renderMarkdown(policyModel, view);

    // One list line per entry: escaped path, escaped license in parentheses,
    // em-dash, escaped description (newline flattened to a space).
    expect(
      output.includes(
        "- apps/scratch (AGPL-3.0-only) — fork \\| of \\`scratch-gui\\` AGPL upstream",
      ),
    ).toBe(true);
    // The raw pipe/backtick forms never reach the document.
    expect(output.includes("fork | of")).toBe(false);
    expect(output.includes("`scratch-gui`")).toBe(false);
    // The policy pointer path routes through escapeCell too.
    expect(
      output.includes("Copyleft notice rules are configured in configs/policy\\|v2.toml."),
    ).toBe(true);
  });

  test("Test 7: determinism — no CR, single trailing LF, defensive re-sort (policy render)", () => {
    const twoPkg: CanonicalDependencies = {
      packages: [sharpEntry, entry({ purl: "pkg:npm/aaa@1.0.0", name: "aaa", version: "1.0.0" })],
    };
    const reversed: CanonicalDependencies = {
      packages: [...twoPkg.packages].reverse(),
    };
    const a = renderMarkdown(twoPkg, basicView);
    const b = renderMarkdown(reversed, basicView);

    expect(a).toBe(b);
    expect(a.includes("## Production dependencies")).toBe(true);
    expect(a.includes("\r")).toBe(false);
    expect(a.endsWith("\n")).toBe(true);
    expect(a.endsWith("\n\n")).toBe(false);
  });

  test("Test 8: imprecise findings — License cell marker, review section, not unknown", () => {
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:pypi/jinja2@3.1.0",
          name: "jinja2",
          version: "3.1.0",
          finding: {
            expression: null,
            elected: null,
            source: "registry",
            confidence: "imprecise",
            impreciseFamily: "BSD",
          },
        }),
        entry({
          purl: "pkg:npm/a-mit@1.0.0",
          name: "a-mit",
          version: "1.0.0",
          finding: {
            expression: "MIT",
            elected: "MIT",
            source: "generator",
            confidence: "exact",
          },
        }),
        entry({
          purl: "pkg:npm/z-unknown@1.0.0",
          name: "z-unknown",
          version: "1.0.0",
          finding: {
            expression: null,
            elected: null,
            source: "generator",
            confidence: "none",
          },
        }),
      ],
    };
    const output = renderMarkdown(model);

    // License cell carries the family + an explicit imprecise marker (never a
    // fabricated precise id, never bare "unknown").
    expect(output.includes("BSD (imprecise)")).toBe(true);
    expect(output.includes("| jinja2 | pypi | 3.1.0 | BSD (imprecise) | apps/a |")).toBe(true);
    // Imprecise is NOT counted as an Unknown license (it is present) — only the
    // genuinely-unknown z-unknown counts.
    expect(output.includes("- Unknown license: 1")).toBe(true);
    // A dedicated imprecise review section lists the package.
    expect(output.includes("## Imprecise licenses (review / disambiguate)")).toBe(true);
    const sectionStart = output.indexOf("## Imprecise licenses (review / disambiguate)");
    const summaryStart = output.indexOf("## Production dependencies");
    const section = output.slice(sectionStart, summaryStart);

    expect(section.includes("jinja2")).toBe(true);
    expect(section.includes("BSD")).toBe(true);
    // Non-imprecise packages do not appear in the review section.
    expect(section.includes("a-mit")).toBe(false);
    expect(section.includes("z-unknown")).toBe(false);
  });

  test("Test 9: the imprecise review section is omitted when no package is imprecise", () => {
    const output = renderMarkdown(policyModel);

    expect(output.includes("## Imprecise licenses (review / disambiguate)")).toBe(false);
  });

  test("Test 10: imprecise review section is deterministically sorted and cell-escaped", () => {
    const imp = (name: string, family: string): PackageEntry =>
      entry({
        purl: `pkg:pypi/${name}@1.0.0`,
        name,
        version: "1.0.0",
        finding: {
          expression: null,
          elected: null,
          source: "registry",
          confidence: "imprecise",
          impreciseFamily: family,
        },
      });
    const model: CanonicalDependencies = {
      packages: [imp("zeta", "BSD"), imp("alpha", "Apache"), imp("pipe|x", "BSD")],
    };
    const output = renderMarkdown(model);
    const start = output.indexOf("## Imprecise licenses (review / disambiguate)");
    const section = output.slice(start, output.indexOf("## Production dependencies"));

    // Sorted by name (comparePackages): alpha < pipe|x < zeta.
    expect(section.indexOf("alpha")).toBeLessThan(section.indexOf("pipe"));
    expect(section.indexOf("pipe")).toBeLessThan(section.indexOf("zeta"));
    // The pipe in the name is escaped (escapeCell), the raw pipe never appears.
    expect(section.includes("pipe\\|x")).toBe(true);
  });

  test("escapeCell is exported for notices.ts", async () => {
    const mod = (await import("../src/render/markdown")) as Record<string, unknown>;

    expect(typeof mod["escapeCell"]).toBe("function");
  });
});

describe("renderMarkdown — prod/dev document split", () => {
  /** A package with the given per-occurrence dev flags. */
  const pkgWith = (
    name: string,
    occ: ReadonlyArray<{ target: string; dev: boolean }>,
  ): PackageEntry => ({
    purl: `pkg:npm/${name}@1.0.0`,
    name,
    version: "1.0.0",
    occurrences: occ.map((o) => ({
      target: o.target,
      isDevDependency: o.dev,
    })),
    licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
    scope: "app",
  });

  test("a package with ANY production occurrence lands in Production (distribution reality)", () => {
    const model: CanonicalDependencies = {
      packages: [
        pkgWith("mixed", [
          { target: "apps/a", dev: true },
          { target: "apps/b", dev: false },
        ]),
        pkgWith("dev-only", [{ target: "apps/a", dev: true }]),
      ],
    };
    const output = renderMarkdown(model);
    const prod = output.slice(
      output.indexOf("## Production dependencies"),
      output.indexOf("## Development-only dependencies"),
    );
    const dev = output.slice(output.indexOf("## Development-only dependencies"));

    // The Used-in cell stays the FULL occurrence list even in Production.
    expect(prod.includes("| mixed | npm | 1.0.0 | MIT | apps/a, apps/b |")).toBe(true);
    expect(prod.includes("dev-only")).toBe(false);
    expect(dev.includes("| dev-only | npm | 1.0.0 | MIT | apps/a |")).toBe(true);
    expect(dev.includes("mixed")).toBe(false);
  });

  test("the counts block carries both production and development-only counts", () => {
    const model: CanonicalDependencies = {
      packages: [
        pkgWith("p1", [{ target: "apps/a", dev: false }]),
        pkgWith("p2", [{ target: "apps/a", dev: false }]),
        pkgWith("d1", [{ target: "apps/a", dev: true }]),
      ],
    };
    const output = renderMarkdown(model);

    expect(output.includes("- Total packages: 3")).toBe(true);
    expect(output.includes("- Production packages: 2")).toBe(true);
    expect(output.includes("- Development-only packages: 1")).toBe(true);
  });

  test("both sections render even when one is empty (stable document shape)", () => {
    const allProd: CanonicalDependencies = {
      packages: [pkgWith("p1", [{ target: "apps/a", dev: false }])],
    };
    const output = renderMarkdown(allProd);

    expect(output.includes("## Production dependencies")).toBe(true);
    expect(output.includes("## Development-only dependencies")).toBe(true);
    expect(output.includes("- Development-only packages: 0")).toBe(true);
  });
});

describe("renderMarkdown — per-container Production/Development grouping", () => {
  const appProd = entry({
    purl: "pkg:npm/app-prod@1.0.0",
    name: "app-prod",
    version: "1.0.0",
    licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
  });
  const appDev = entry({
    purl: "pkg:npm/app-dev@1.0.0",
    name: "app-dev",
    version: "1.0.0",
    occurrences: [{ target: "apps/a", isDevDependency: true }],
    licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
  });
  const osDeb = entry({
    purl: "pkg:deb/debian/libc6@2.36-9",
    name: "libc6",
    version: "2.36-9",
    occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
    licenseClaims: [{ raw: "LGPL-2.1-or-later", kind: "spdx-id", source: "generator" }],
    scope: "os",
  });
  const osApk = entry({
    purl: "pkg:apk/alpine/musl@1.2.4-r2",
    name: "musl",
    version: "1.2.4-r2",
    occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
    licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
    scope: "os",
  });

  const HEADING = "### Container: docker:img/Dockerfile";
  const OLD_HEADING = "## Docker image packages";

  test("the standalone Docker section never renders — with or without a policy view", () => {
    const model: CanonicalDependencies = { packages: [appProd, osDeb, osApk] };

    expect(renderMarkdown(model).includes(OLD_HEADING)).toBe(false);
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [],
    };

    expect(renderMarkdown(model, view).includes(OLD_HEADING)).toBe(false);
  });

  test("OS packages render under a per-container subsection, by default under Production", () => {
    const model: CanonicalDependencies = { packages: [appProd, osDeb, osApk] };
    const output = renderMarkdown(model);
    const prod = output.slice(
      output.indexOf("## Production dependencies"),
      output.indexOf("## Development-only dependencies"),
    );

    expect(prod.includes(HEADING)).toBe(true);
    const containerSection = output.slice(output.indexOf(HEADING));

    expect(containerSection.includes("| libc6 | deb | 2.36-9 | LGPL-2.1-or-later |")).toBe(true);
    expect(containerSection.includes("| musl | apk | 1.2.4-r2 | MIT |")).toBe(true);
    // No Used-in column: the container heading already scopes every row.
    expect(containerSection.includes("| Name | Ecosystem | Version | License |")).toBe(true);
  });

  test("OS packages are EXCLUDED from the app Production and Development-only tables", () => {
    const model: CanonicalDependencies = {
      packages: [appProd, appDev, osDeb, osApk],
    };
    const output = renderMarkdown(model);
    const prodTable = output.slice(
      output.indexOf("## Production dependencies"),
      output.indexOf(HEADING),
    );
    const dev = output.slice(output.indexOf("## Development-only dependencies"));

    // OS rows never leak into the app tables.
    expect(prodTable.includes("libc6")).toBe(false);
    expect(prodTable.includes("musl")).toBe(false);
    expect(dev.includes("libc6")).toBe(false);
    expect(dev.includes("musl")).toBe(false);
    // The app packages stay in their app tables.
    expect(prodTable.includes("| app-prod | npm | 1.0.0 |")).toBe(true);
    expect(dev.includes("| app-dev | npm | 1.0.0 |")).toBe(true);
  });

  test("empty container set: Production/Development render exactly the app tables, no stray headings", () => {
    const model: CanonicalDependencies = { packages: [appProd] };
    const output = renderMarkdown(model);

    expect(output.includes("### Container:")).toBe(false);
    expect(output.includes(OLD_HEADING)).toBe(false);
  });

  test("section order is fixed/deterministic: Production (+ its containers), then Development-only (+ its containers)", () => {
    const model: CanonicalDependencies = {
      packages: [appProd, appDev, osDeb],
    };
    const output = renderMarkdown(model);
    const prodPos = output.indexOf("## Production dependencies");
    const devPos = output.indexOf("## Development-only dependencies");
    const containerPos = output.indexOf(HEADING);

    expect(prodPos).toBeGreaterThan(-1);
    expect(prodPos).toBeLessThan(containerPos);
    expect(containerPos).toBeLessThan(devPos);
  });

  test("container heading text routes the identity through escapeCell", () => {
    const evilOs = entry({
      purl: "pkg:deb/debian/evil@1.0.0",
      name: "evil-pkg",
      version: "1.0.0",
      occurrences: [{ target: "docker:evil|pkg`x/Dockerfile", isDevDependency: false }],
      licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
      scope: "os",
    });
    const output = renderMarkdown({ packages: [evilOs] });

    expect(output.includes("docker:evil\\|pkg\\`x/Dockerfile")).toBe(true);
    expect(output.includes("docker:evil|pkg`x/Dockerfile")).toBe(false);
  });

  test("OS row cells route through escapeCell (markdown-injection-safe)", () => {
    const evilOs = entry({
      purl: "pkg:deb/debian/evil@1.0.0",
      name: "evil|pkg`x",
      version: "1.0.0",
      occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
      licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
      scope: "os",
    });
    const output = renderMarkdown({ packages: [evilOs] });

    expect(output.includes("evil\\|pkg\\`x")).toBe(true);
    expect(output.includes("evil|pkg`x")).toBe(false);
  });

  test("the counts block carries a Container packages count", () => {
    const model: CanonicalDependencies = {
      packages: [appProd, osDeb, osApk],
    };
    const output = renderMarkdown(model);

    expect(output.includes("- Container packages: 2")).toBe(true);
    // Total still counts every package across scopes.
    expect(output.includes("- Total packages: 3")).toBe(true);
  });

  test("a package shared by two production containers rows in EACH container's own subsection", () => {
    const osShared = entry({
      purl: "pkg:apk/alpine/busybox@1.37.0-r19",
      name: "busybox",
      version: "1.37.0-r19",
      occurrences: [
        { target: "docker:a/Dockerfile", isDevDependency: false },
        { target: "docker:b/Dockerfile", isDevDependency: false },
      ],
      licenseClaims: [{ raw: "GPL-2.0-only", kind: "spdx-id", source: "generator" }],
      scope: "os",
    });
    const output = renderMarkdown({ packages: [osShared] });
    // Deterministic container order: docker:a/Dockerfile before docker:b/Dockerfile.
    const aPos = output.indexOf("### Container: docker:a/Dockerfile");
    const bPos = output.indexOf("### Container: docker:b/Dockerfile");

    expect(aPos).toBeGreaterThan(-1);
    expect(bPos).toBeGreaterThan(aPos);
    // ONE row of the 4-column shape in EACH container's own subsection — never
    // a single row with a joined Used-in cell (there is no Used-in column).
    const aSection = output.slice(aPos, bPos);
    const bSection = output.slice(bPos);

    expect(aSection.includes("| busybox | apk | 1.37.0-r19 | GPL-2.0-only |")).toBe(true);
    expect(bSection.includes("| busybox | apk | 1.37.0-r19 | GPL-2.0-only |")).toBe(true);
  });

  test("a container classified development renders its subsection under Development-only", () => {
    const model: CanonicalDependencies = { packages: [appProd, osDeb] };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [],
      developmentContainers: new Set(["docker:img/Dockerfile"]),
    };
    const output = renderMarkdown(model, view);
    const prod = output.slice(
      output.indexOf("## Production dependencies"),
      output.indexOf("## Development-only dependencies"),
    );
    const dev = output.slice(output.indexOf("## Development-only dependencies"));

    expect(prod.includes(HEADING)).toBe(false);
    expect(dev.includes(HEADING)).toBe(true);
    expect(dev.includes("| libc6 | deb | 2.36-9 | LGPL-2.1-or-later |")).toBe(true);
  });

  test("leak target: a package shared by a production container and a development container stays visible under BOTH", () => {
    const shared = entry({
      purl: "pkg:apk/alpine/shared-lib@1.0.0",
      name: "shared-lib",
      version: "1.0.0",
      occurrences: [
        { target: "docker:a/Dockerfile", isDevDependency: false },
        { target: "docker:b/Dockerfile", isDevDependency: false },
      ],
      licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
      scope: "os",
    });
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [],
      developmentContainers: new Set(["docker:b/Dockerfile"]),
    };
    const output = renderMarkdown({ packages: [shared] }, view);
    const prod = output.slice(
      output.indexOf("## Production dependencies"),
      output.indexOf("## Development-only dependencies"),
    );
    const dev = output.slice(output.indexOf("## Development-only dependencies"));

    // Container A (production) still shows the package — marking B development
    // moved nothing of A's.
    expect(prod.includes("### Container: docker:a/Dockerfile")).toBe(true);
    expect(prod.includes("| shared-lib | apk | 1.0.0 | MIT |")).toBe(true);
    // Container B (development) shows it too.
    expect(dev.includes("### Container: docker:b/Dockerfile")).toBe(true);
    expect(dev.includes("| shared-lib | apk | 1.0.0 | MIT |")).toBe(true);
  });

  test("a package whose ONLY occurrence targets a container lists in that container's subsection regardless of its scope field", () => {
    // Grouping is occurrence-keyed, not scope-keyed: this package's scope
    // defaults to "app", but its sole occurrence is a docker: target, so it
    // is a Container package by inventory, not by scope.
    const appAtDockerTarget = entry({
      purl: "pkg:npm/app-at-docker-target@1.0.0",
      name: "app-at-docker-target",
      version: "1.0.0",
      occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
      licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
    });
    const output = renderMarkdown({ packages: [appAtDockerTarget, osDeb] });
    const containerSection = output.slice(output.indexOf(HEADING));

    expect(containerSection.includes("app-at-docker-target")).toBe(true);
    // It is EXCLUDED from the app Production table — it has no workspace
    // occurrence of its own.
    const prodTable = output.slice(
      output.indexOf("## Production dependencies"),
      output.indexOf(HEADING),
    );

    expect(prodTable.includes("app-at-docker-target")).toBe(false);
    // Counted as a Container package (npm 1 + deb 1 = 2).
    expect(output.includes("- Container packages: 2")).toBe(true);
  });

  test("a package with BOTH a workspace occurrence and a docker occurrence lists in BOTH its app table and the container subsection", () => {
    const shared = entry({
      purl: "pkg:npm/shared-app-and-container@1.0.0",
      name: "shared-app-and-container",
      version: "1.0.0",
      occurrences: [
        { target: "apps/a", isDevDependency: false },
        { target: "docker:img/Dockerfile", isDevDependency: false },
      ],
      licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
    });
    const output = renderMarkdown({ packages: [shared, osDeb] });
    const prodTable = output.slice(
      output.indexOf("## Production dependencies"),
      output.indexOf(HEADING),
    );

    expect(prodTable.includes("shared-app-and-container")).toBe(true);
    const containerSection = output.slice(output.indexOf(HEADING));

    expect(containerSection.includes("shared-app-and-container")).toBe(true);
    // Container is the cross-cutting hasContainerOccurrence count, so a
    // package with a non-docker occurrence still counts there once it also
    // carries a docker occurrence: shared-app-and-container plus osDeb — 2.
    expect(output.includes("- Container packages: 2")).toBe(true);
  });

  test("a package with ONLY workspace occurrences never appears in a container subsection and is never counted as Container", () => {
    const workspaceOnly = entry({
      purl: "pkg:npm/workspace-only@1.0.0",
      name: "workspace-only",
      version: "1.0.0",
      licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
    });
    const output = renderMarkdown({ packages: [workspaceOnly, osDeb] });
    const containerSection = output.slice(output.indexOf(HEADING));

    expect(containerSection.includes("workspace-only")).toBe(false);
    expect(output.includes("- Container packages: 1")).toBe(true);
  });

  test("counts partition invariant: Production + Development-only equals Total (Container is a cross-cutting subtotal, not summed in)", () => {
    const containerOnly = entry({
      purl: "pkg:pypi/container-only@1.0.0",
      name: "container-only",
      version: "1.0.0",
      occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
      licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
    });
    const model: CanonicalDependencies = {
      packages: [appProd, appDev, containerOnly, osDeb, osApk],
    };
    const output = renderMarkdown(model);
    const total = Number(/- Total packages: (\d+)/.exec(output)![1]);
    const prod = Number(/- Production packages: (\d+)/.exec(output)![1]);
    const devOnly = Number(/- Development-only packages: (\d+)/.exec(output)![1]);
    const container = Number(/- Container packages: (\d+)/.exec(output)![1]);

    expect(prod + devOnly).toBe(total);
    // Container is the cross-cutting hasContainerOccurrence count —
    // containerOnly, osDeb, osApk — still 3, and every one of the three is
    // ALSO folded into Production (no dev-marked container in this
    // no-policy render, the conservative default): the subtotal overlaps
    // the partition rather than being subtracted from it.
    expect(container).toBe(3);
    expect(container).toBeLessThanOrEqual(total);
  });

  describe("Production/Development-only counts match the container's OWN classification (the undercount regression)", () => {
    const PROD_CONTAINER = "docker:prod-img/Dockerfile";
    const DEV_CONTAINER = "docker:dev-img/Dockerfile";

    /** A pure-container, application-ecosystem package (golang is not on the OS allowlist). */
    const prodContainerAppPkg = entry({
      purl: "pkg:golang/prod-container-app@1.0.0",
      name: "prod-container-app",
      version: "1.0.0",
      occurrences: [{ target: PROD_CONTAINER, isDevDependency: false }],
      licenseClaims: [{ raw: "AGPL-3.0-only", kind: "spdx-id", source: "generator" }],
    });

    const devContainerPkg = entry({
      purl: "pkg:golang/dev-container-only@1.0.0",
      name: "dev-container-only",
      version: "1.0.0",
      occurrences: [{ target: DEV_CONTAINER, isDevDependency: false }],
      licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
    });

    test("an application-ecosystem package baked into a PRODUCTION container counts as Production, not siloed under Container", () => {
      const view: PolicyView = {
        policyPath: "policy.toml",
        suppressedWorkspaces: [],
        verdicts: [],
        developmentContainers: new Set(),
      };
      const output = renderMarkdown({ packages: [prodContainerAppPkg] }, view);

      expect(output.includes("- Production packages: 1")).toBe(true);
      expect(output.includes("- Development-only packages: 0")).toBe(true);
      // Still a cross-cutting Container subtotal — the fix does not remove
      // it from that count, only stops subtracting it from Production.
      expect(output.includes("- Container packages: 1")).toBe(true);
      const prodSection = output.slice(output.indexOf("## Production dependencies"));

      expect(prodSection.includes("prod-container-app")).toBe(true);
    });

    test("a package whose ONLY occurrence targets a dev-marked container counts as Development-only", () => {
      const view: PolicyView = {
        policyPath: "policy.toml",
        suppressedWorkspaces: [],
        verdicts: [],
        developmentContainers: new Set([DEV_CONTAINER]),
      };
      const output = renderMarkdown({ packages: [devContainerPkg] }, view);

      expect(output.includes("- Production packages: 0")).toBe(true);
      expect(output.includes("- Development-only packages: 1")).toBe(true);
      expect(output.includes("- Container packages: 1")).toBe(true);
      const devSection = output.slice(output.indexOf("## Development-only dependencies"));

      expect(devSection.includes("dev-container-only")).toBe(true);
    });

    test("count/section alignment: Production equals the distinct packages under Production (app table + its production container subsections), and likewise Development-only", () => {
      const prodApp = entry({
        purl: "pkg:npm/prod-app@1.0.0",
        name: "prod-app",
        version: "1.0.0",
        licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
      });
      const devApp = entry({
        purl: "pkg:npm/dev-app@1.0.0",
        name: "dev-app",
        version: "1.0.0",
        occurrences: [{ target: "apps/a", isDevDependency: true }],
        licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
      });
      // No package straddles both containers here, so every package renders
      // under exactly one of Production/Development-only — the count and the
      // distinct rendered package set line up exactly.
      const model: CanonicalDependencies = {
        packages: [prodApp, devApp, prodContainerAppPkg, devContainerPkg],
      };
      const view: PolicyView = {
        policyPath: "policy.toml",
        suppressedWorkspaces: [],
        verdicts: [],
        developmentContainers: new Set([DEV_CONTAINER]),
      };
      const output = renderMarkdown(model, view);
      const prodCount = Number(/- Production packages: (\d+)/.exec(output)![1]);
      const devOnlyCount = Number(/- Development-only packages: (\d+)/.exec(output)![1]);

      const prodSection = output.slice(
        output.indexOf("## Production dependencies"),
        output.indexOf("## Development-only dependencies"),
      );
      const devSection = output.slice(output.indexOf("## Development-only dependencies"));
      const namesIn = (text: string, names: readonly string[]): number =>
        names.filter((name) => text.includes(name)).length;

      expect(prodCount).toBe(2);
      expect(namesIn(prodSection, ["prod-app", "prod-container-app"])).toBe(prodCount);
      expect(devOnlyCount).toBe(2);
      expect(namesIn(devSection, ["dev-app", "dev-container-only"])).toBe(devOnlyCount);
    });
  });
});

// ---------------------------------------------------------------------------
// Per-container System/Application table split: each "### Container:"
// subsection partitions its rows into a System packages table (the
// OS_PACKAGE_ECOSYSTEMS allowlist) and an Application packages table
// (everything else), omitting an empty partition.
// ---------------------------------------------------------------------------

describe("renderMarkdown — per-container System/Application split", () => {
  const HEADING = "### Container: docker:img/Dockerfile";

  const systemPkg = entry({
    purl: "pkg:deb/debian/libc6@2.36-9",
    name: "libc6",
    version: "2.36-9",
    occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
    licenseClaims: [{ raw: "LGPL-2.1-or-later", kind: "spdx-id", source: "generator" }],
    scope: "os",
  });
  const applicationPkg = entry({
    purl: "pkg:npm/app-in-container@1.0.0",
    name: "app-in-container",
    version: "1.0.0",
    occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
    licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
  });

  test("a container with both system and application rows emits System THEN Application, each labeled and 4-column", () => {
    const output = renderMarkdown({ packages: [systemPkg, applicationPkg] });
    const section = output.slice(output.indexOf(HEADING));
    const systemPos = section.indexOf("**System packages**");
    const applicationPos = section.indexOf("**Application packages**");

    expect(systemPos).toBeGreaterThan(-1);
    expect(applicationPos).toBeGreaterThan(systemPos);
    // Every row is in exactly one partition (exhaustive, non-overlapping).
    const systemBlock = section.slice(systemPos, applicationPos);
    const applicationBlock = section.slice(applicationPos);

    expect(systemBlock.includes("libc6")).toBe(true);
    expect(systemBlock.includes("app-in-container")).toBe(false);
    expect(applicationBlock.includes("app-in-container")).toBe(true);
    expect(applicationBlock.includes("libc6")).toBe(false);
    // Both labeled tables share the 4-column container head.
    const headCount = section
      .split("\n")
      .filter((line) => line === "| Name | Ecosystem | Version | License |").length;

    expect(headCount).toBe(2);
  });

  test("a base-image-only container (system rows only) shows just the System table — no empty Application block", () => {
    const output = renderMarkdown({ packages: [systemPkg] });
    const section = output.slice(output.indexOf(HEADING));

    expect(section.includes("**System packages**")).toBe(true);
    expect(section.includes("**Application packages**")).toBe(false);
  });

  test("an all-application container shows just the Application table — no empty System block", () => {
    const output = renderMarkdown({ packages: [applicationPkg] });
    const section = output.slice(output.indexOf(HEADING));

    expect(section.includes("**Application packages**")).toBe(true);
    expect(section.includes("**System packages**")).toBe(false);
  });

  test("the partition is exhaustive: every row in the container's inventory appears in exactly one sub-table", () => {
    const rpmPkg = entry({
      purl: "pkg:rpm/fedora/glibc@2.38",
      name: "glibc",
      version: "2.38",
      occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
      licenseClaims: [{ raw: "LGPL-2.1-only", kind: "spdx-id", source: "generator" }],
      scope: "os",
    });
    const alpmPkg = entry({
      purl: "pkg:alpm/arch/pacman@6.1.0",
      name: "pacman",
      version: "6.1.0",
      occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
      licenseClaims: [{ raw: "GPL-2.0-only", kind: "spdx-id", source: "generator" }],
      scope: "os",
    });
    const pypiPkg = entry({
      purl: "pkg:pypi/app-py@1.0.0",
      name: "app-py",
      version: "1.0.0",
      occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
      licenseClaims: [{ raw: "Apache-2.0", kind: "spdx-id", source: "generator" }],
    });
    const output = renderMarkdown({
      packages: [systemPkg, rpmPkg, alpmPkg, applicationPkg, pypiPkg],
    });
    const section = output.slice(output.indexOf(HEADING));
    const systemPos = section.indexOf("**System packages**");
    const applicationPos = section.indexOf("**Application packages**");
    const systemBlock = section.slice(systemPos, applicationPos);
    const applicationBlock = section.slice(applicationPos);

    for (const name of ["libc6", "glibc", "pacman"]) {
      expect(systemBlock.includes(name)).toBe(true);
      expect(applicationBlock.includes(name)).toBe(false);
    }

    for (const name of ["app-in-container", "app-py"]) {
      expect(applicationBlock.includes(name)).toBe(true);
      expect(systemBlock.includes(name)).toBe(false);
    }
  });

  test("byte-neutrality of the grouping half: when scope==='os' exactly coincides with pure-container, the split changes only layout, never membership", () => {
    // Every package here is either pure-app (never a container row) or
    // pure-container with an OS-allowlist ecosystem — the pre-correction
    // reality this task must not disturb.
    const appOnly = entry({
      purl: "pkg:npm/app-only@1.0.0",
      name: "app-only",
      version: "1.0.0",
      licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
    });
    const output = renderMarkdown({ packages: [appOnly, systemPkg] });
    const section = output.slice(output.indexOf(HEADING));

    // Only System renders (both are OS-ecosystem-only here); no Application
    // block and no leakage of the app-only package into the container.
    expect(section.includes("**System packages**")).toBe(true);
    expect(section.includes("**Application packages**")).toBe(false);
    expect(section.includes("app-only")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The Containers index: a thin, occurrence-derived section listing every
// analyzed container's identity, prod/dev classification, and package count,
// rendered immediately before Production regardless of policy.
// ---------------------------------------------------------------------------

describe("renderMarkdown — Containers index", () => {
  const HEADING = "## Containers";

  const osPkg = (name: string, purl: string, targets: readonly string[]): PackageEntry =>
    entry({
      purl,
      name,
      version: "1.0.0",
      occurrences: targets.map((target) => ({
        target,
        isDevDependency: false,
      })),
      licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
      scope: "os",
    });

  test("two containers render a sorted 3-column index, placed immediately before Production", () => {
    const model: CanonicalDependencies = {
      packages: [
        osPkg("busybox", "pkg:apk/alpine/busybox@1.0.0", ["docker:b/Dockerfile"]),
        osPkg("musl", "pkg:apk/alpine/musl@1.0.0", ["docker:a/Dockerfile"]),
        osPkg("zlib", "pkg:apk/alpine/zlib@1.0.0", ["docker:a/Dockerfile"]),
      ],
    };
    const output = renderMarkdown(model);

    expect(output.includes(HEADING)).toBe(true);
    const containersSection = output.slice(
      output.indexOf(HEADING),
      output.indexOf("## Production dependencies"),
    );

    expect(containersSection.includes("| Container | Classification | Packages |")).toBe(true);
    // compareCodeUnits-sorted: "docker:a/Dockerfile" before "docker:b/Dockerfile".
    expect(containersSection.indexOf("docker:a/Dockerfile")).toBeLessThan(
      containersSection.indexOf("docker:b/Dockerfile"),
    );
    // Package counts are each container's full os-package inventory.
    expect(containersSection.includes("| docker:a/Dockerfile | production | 2 |")).toBe(true);
    expect(containersSection.includes("| docker:b/Dockerfile | production | 1 |")).toBe(true);
    // Placed immediately before Production.
    expect(output.indexOf(HEADING)).toBeLessThan(output.indexOf("## Production dependencies"));
  });

  test("classification is development for identities in developmentContainers, else production", () => {
    const model: CanonicalDependencies = {
      packages: [
        osPkg("musl", "pkg:apk/alpine/musl@1.0.0", ["docker:a/Dockerfile"]),
        osPkg("zlib", "pkg:apk/alpine/zlib@1.0.0", ["docker:b/Dockerfile"]),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [],
      developmentContainers: new Set(["docker:a/Dockerfile"]),
    };
    const output = renderMarkdown(model, view);
    const containersSection = output.slice(
      output.indexOf(HEADING),
      output.indexOf("## Production dependencies"),
    );

    expect(containersSection.includes("| docker:a/Dockerfile | development | 1 |")).toBe(true);
    expect(containersSection.includes("| docker:b/Dockerfile | production | 1 |")).toBe(true);
  });

  test("without a policy view every container classifies production", () => {
    const model: CanonicalDependencies = {
      packages: [osPkg("musl", "pkg:apk/alpine/musl@1.0.0", ["docker:a/Dockerfile"])],
    };
    const output = renderMarkdown(model);
    const containersSection = output.slice(
      output.indexOf(HEADING),
      output.indexOf("## Production dependencies"),
    );

    expect(containersSection.includes("| docker:a/Dockerfile | production | 1 |")).toBe(true);
  });

  test("empty state renders the heading plus a stable message when there are no os packages", () => {
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:npm/app-only@1.0.0",
          name: "app-only",
          version: "1.0.0",
          licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
        }),
      ],
    };
    const output = renderMarkdown(model);

    expect(output.includes(HEADING)).toBe(true);
    const containersSection = output.slice(output.indexOf(HEADING));

    expect(containersSection.includes("✅ No containers are currently tracked.")).toBe(true);
    expect(containersSection.includes("| Container | Classification | Packages |")).toBe(false);
  });

  test("identity cells route through escapeCell", () => {
    const model: CanonicalDependencies = {
      packages: [osPkg("evil", "pkg:apk/alpine/evil@1.0.0", ["docker:evil|pkg`x/Dockerfile"])],
    };
    const output = renderMarkdown(model);

    expect(output.includes("docker:evil\\|pkg\\`x/Dockerfile")).toBe(true);
    expect(output.includes("docker:evil|pkg`x/Dockerfile")).toBe(false);
  });
});

// ===========================================================================
// Os-scope partial-license rendering. A finding carrying
// `unrecognizedTokens` renders the expression PLUS the surfaced remainder in a
// locked, deterministic, escapeCell-safe format. App-scope rows (never carry
// unrecognizedTokens) render identically to before.
// ===========================================================================
describe("renderMarkdown — os-scope partial-license cell", () => {
  const osPartial = entry({
    purl: "pkg:deb/debian/os-partial@1.0",
    name: "os-partial",
    version: "1.0",
    occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
    licenseClaims: [
      { raw: "GPL-2.0-only", kind: "spdx-id", source: "generator" },
      { raw: "BSD-3-Clause", kind: "spdx-id", source: "generator" },
      { raw: "public-domain", kind: "name", source: "generator" },
    ],
    scope: "os",
    finding: {
      expression: "GPL-2.0-only AND BSD-3-Clause",
      elected: "GPL-2.0-only AND BSD-3-Clause",
      source: "generator",
      confidence: "exact",
      unrecognizedTokens: ["public-domain"],
    },
  });

  const HEADING = "### Container: docker:img/Dockerfile";

  test("LOCKED FORMAT: expression (+ remainder) in the License cell", () => {
    const output = renderMarkdown({ packages: [osPartial] });
    const osSection = output.slice(output.indexOf(HEADING));

    expect(
      osSection.includes(
        "| os-partial | deb | 1.0 | GPL-2.0-only AND BSD-3-Clause (+ public-domain) |",
      ),
    ).toBe(true);
  });

  test("multiple unrecognized tokens are comma-joined in order", () => {
    const multi = entry({
      purl: "pkg:deb/debian/os-multi@1.0",
      name: "os-multi",
      version: "1.0",
      occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
      licenseClaims: [],
      scope: "os",
      finding: {
        expression: "MIT",
        elected: "MIT",
        source: "generator",
        confidence: "exact",
        unrecognizedTokens: ["Artistic", "public-domain"],
      },
    });
    const output = renderMarkdown({ packages: [multi] });

    expect(output.includes("| MIT (+ Artistic, public-domain) |")).toBe(true);
  });

  test("unrecognized tokens route through escapeCell (injection-safe)", () => {
    const evil = entry({
      purl: "pkg:deb/debian/os-evil@1.0",
      name: "os-evil",
      version: "1.0",
      occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
      licenseClaims: [],
      scope: "os",
      finding: {
        expression: "MIT",
        elected: "MIT",
        source: "generator",
        confidence: "exact",
        unrecognizedTokens: ["evil|tok`x"],
      },
    });
    const output = renderMarkdown({ packages: [evil] });

    expect(output.includes("MIT (+ evil\\|tok\\`x)")).toBe(true);
    expect(output.includes("evil|tok`x")).toBe(false);
  });

  test("#8: an IMPRECISE finding with unrecognizedTokens appends the (+ remainder) suffix", () => {
    // After #2, an os-partial finding can be confidence "imprecise" (an
    // imprecise copyleft family + a genuinely-unknown token). The imprecise
    // branch of licenseCellOf must surface the remainder too — not drop it.
    const imprecisePartial = entry({
      purl: "pkg:deb/debian/os-imprecise-partial@1.0",
      name: "os-imprecise-partial",
      version: "1.0",
      occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
      licenseClaims: [],
      scope: "os",
      finding: {
        expression: null,
        elected: null,
        source: "generator",
        confidence: "imprecise",
        impreciseFamily: "GPL",
        unrecognizedTokens: ["some-custom-token"],
      },
    });
    const output = renderMarkdown({ packages: [imprecisePartial] });

    expect(output.includes("GPL (imprecise) (+ some-custom-token)")).toBe(true);
  });

  test("#8: an imprecise finding WITHOUT unrecognizedTokens still renders the plain family marker", () => {
    const impreciseOnly = entry({
      purl: "pkg:npm/imprecise-only@1.0",
      name: "imprecise-only",
      version: "1.0",
      licenseClaims: [],
      finding: {
        expression: null,
        elected: null,
        source: "generator",
        confidence: "imprecise",
        impreciseFamily: "BSD",
      },
    });
    const output = renderMarkdown({ packages: [impreciseOnly] });

    expect(output.includes("BSD (imprecise)")).toBe(true);
    expect(output.includes("(+ ")).toBe(false);
  });

  test("a finding WITHOUT unrecognizedTokens renders the plain expression (app-scope unchanged)", () => {
    const plain = entry({
      purl: "pkg:npm/plain@1.0",
      name: "plain",
      version: "1.0",
      licenseClaims: [],
      finding: {
        expression: "MIT AND Apache-2.0",
        elected: "MIT AND Apache-2.0",
        source: "generator",
        confidence: "exact",
      },
    });
    const output = renderMarkdown({ packages: [plain] });

    expect(output.includes("| plain | npm | 1.0 | MIT AND Apache-2.0 |")).toBe(true);
    expect(output.includes("(+")).toBe(false);
  });
});

// ===========================================================================
// The Ecosystem column — the raw purl type segment rendered
// immediately after Name in EVERY table, routed through escapeCell. A mixed-
// ecosystem model locks the per-row type across npm + pypi + deb + apk +
// terraform, so the column reflects each package's own purl, not a single one.
// ===========================================================================
describe("renderMarkdown — Ecosystem column", () => {
  const mixed: CanonicalDependencies = {
    packages: [
      entry({
        purl: "pkg:npm/npm-pkg@1.0.0",
        name: "npm-pkg",
        version: "1.0.0",
        finding: {
          expression: "MIT",
          elected: "MIT",
          source: "generator",
          confidence: "exact",
        },
      }),
      entry({
        purl: "pkg:pypi/pypi-pkg@2.0.0",
        name: "pypi-pkg",
        version: "2.0.0",
        finding: {
          expression: "Apache-2.0",
          elected: "Apache-2.0",
          source: "generator",
          confidence: "exact",
        },
      }),
      entry({
        purl: "pkg:terraform/tf-pkg@3.0.0",
        name: "tf-pkg",
        version: "3.0.0",
        finding: {
          expression: "MPL-2.0",
          elected: "MPL-2.0",
          source: "generator",
          confidence: "exact",
        },
      }),
      entry({
        purl: "pkg:deb/debian/deb-pkg@4.0",
        name: "deb-pkg",
        version: "4.0",
        occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
        licenseClaims: [{ raw: "GPL-2.0-only", kind: "spdx-id", source: "generator" }],
        scope: "os",
        finding: {
          expression: "GPL-2.0-only",
          elected: "GPL-2.0-only",
          source: "generator",
          confidence: "exact",
        },
      }),
      entry({
        purl: "pkg:apk/alpine/apk-pkg@5.0",
        name: "apk-pkg",
        version: "5.0",
        occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
        licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
        scope: "os",
        finding: {
          expression: "MIT",
          elected: "MIT",
          source: "generator",
          confidence: "exact",
        },
      }),
    ],
  };

  test("every table head carries the Ecosystem column after Name", () => {
    const output = renderMarkdown(mixed);
    // The 5-column app TABLE_HEAD renders once (Production; Development-only
    // is empty here, so it shows a checkmark line instead), and the
    // 4-column container-subsection head (no Used-in) renders once too.
    const headCount = output
      .split("\n")
      .filter((line) => line === "| Name | Ecosystem | Version | License | Used in |").length;

    expect(headCount).toBe(1);
    const containerHeadCount = output
      .split("\n")
      .filter((line) => line === "| Name | Ecosystem | Version | License |").length;

    expect(containerHeadCount).toBe(1);
    // The OLD 4-column APP head (pre-Ecosystem-column) must never survive
    // anywhere.
    expect(output.includes("| Name | Version | License | Used in |")).toBe(false);
  });

  test("each row's Ecosystem cell is its own raw purl type", () => {
    const output = renderMarkdown(mixed);

    // App-scope rows render in the Production table; os rows in their
    // container's own subsection. Each carries its own purl type verbatim.
    expect(output.includes("| npm-pkg | npm | 1.0.0 | MIT |")).toBe(true);
    expect(output.includes("| pypi-pkg | pypi | 2.0.0 | Apache-2.0 |")).toBe(true);
    expect(output.includes("| tf-pkg | terraform | 3.0.0 | MPL-2.0 |")).toBe(true);
    expect(output.includes("| deb-pkg | deb | 4.0 | GPL-2.0-only |")).toBe(true);
    expect(output.includes("| apk-pkg | apk | 5.0 | MIT |")).toBe(true);
  });

  test("the Ecosystem cell routes through escapeCell", () => {
    // A purl whose type segment carries a pipe/backtick must be escaped like
    // every other SBOM-sourced cell (defensive — real purl types are tame, but
    // the renderer must not trust the input).
    const evil = entry({
      purl: "pkg:ev|il`type/x@1.0.0",
      name: "evil-eco",
      version: "1.0.0",
      finding: {
        expression: "MIT",
        elected: "MIT",
        source: "generator",
        confidence: "exact",
      },
    });
    const output = renderMarkdown({ packages: [evil] });

    expect(output.includes("| evil-eco | ev\\|il\\`type | 1.0.0 | MIT |")).toBe(true);
    expect(output.includes("ev|il`type")).toBe(false);
  });
});

// ===========================================================================
// The [document] title + preamble. The title replaces the H1
// (default "Third-Party Licenses"); the preamble renders verbatim as a markdown
// block AFTER the auto-generated comment and BEFORE the policy pointer / counts.
// Neither is escapeCell'd — both are author prose at the policy trust boundary.
// ===========================================================================
describe("renderMarkdown — [document] title + preamble", () => {
  const model: CanonicalDependencies = {
    packages: [
      entry({
        purl: "pkg:npm/a@1.0.0",
        name: "a",
        version: "1.0.0",
        finding: {
          expression: "MIT",
          elected: "MIT",
          source: "generator",
          confidence: "exact",
        },
      }),
    ],
  };

  const viewWith = (document?: { title?: string; preamble?: string }): PolicyView => ({
    policyPath: "policy.toml",
    suppressedWorkspaces: [],
    verdicts: [],
    ...(document !== undefined ? { document } : {}),
  });

  test("a custom title replaces the default H1", () => {
    const output = renderMarkdown(model, viewWith({ title: "Example — TPL" }));
    const lines = output.split("\n");

    expect(lines[0]).toBe("# Example — TPL");
    expect(output.includes("# Third-Party Licenses")).toBe(false);
  });

  test("the default H1 stands when no [document] (policy run) or no policy", () => {
    expect(renderMarkdown(model, viewWith()).split("\n")[0]).toBe("# Third-Party Licenses");
    expect(renderMarkdown(model).split("\n")[0]).toBe("# Third-Party Licenses");
  });

  test("a CR/LF in the title collapses to a single space and trims (heading, not a cell)", () => {
    const output = renderMarkdown(model, viewWith({ title: "  Multi\r\nLine  Title  " }));

    // CRLF collapses to one space; surrounding whitespace trimmed; the interior
    // double-space is preserved verbatim (only the line break is normalized).
    expect(output.split("\n")[0]).toBe("# Multi Line  Title");
    expect(output.includes("\r")).toBe(false);
  });

  test("the title is NOT escapeCell'd (author prose may contain markdown)", () => {
    const output = renderMarkdown(model, viewWith({ title: "Licenses | v2 `x`" }));

    // A pipe/backtick in a TITLE survives verbatim — it is a heading, not a
    // table cell.
    expect(output.split("\n")[0]).toBe("# Licenses | v2 `x`");
  });

  test("the preamble renders verbatim after the header comment, before the pointer/counts", () => {
    const preamble = "First line.\n\nSecond paragraph with **bold**.";
    const output = renderMarkdown(model, viewWith({ preamble }));
    const headerIdx = output.indexOf(
      "<!-- AUTO-GENERATED - do not edit. Regenerate with: task generate -->",
    );
    const preambleIdx = output.indexOf("First line.");
    const pointerIdx = output.indexOf("Copyleft notice rules are configured");
    const countsIdx = output.indexOf("**Package counts:**");

    expect(headerIdx).toBeGreaterThan(-1);
    expect(preambleIdx).toBeGreaterThan(headerIdx);
    expect(preambleIdx).toBeLessThan(pointerIdx);
    expect(pointerIdx).toBeLessThan(countsIdx);
    // Verbatim markdown — bold/blank-line structure preserved, NOT escaped.
    expect(output.includes("**bold**")).toBe(true);
    expect(output.includes("First line.\n\nSecond paragraph")).toBe(true);
  });

  test("preamble CRLF/CR is normalized to LF with a trailing blank line", () => {
    const output = renderMarkdown(model, viewWith({ preamble: "alpha\r\nbeta\rgamma" }));

    expect(output.includes("alpha\nbeta\ngamma")).toBe(true);
    expect(output.includes("\r")).toBe(false);
    // A blank line separates the preamble block from what follows.
    expect(output.includes("alpha\nbeta\ngamma\n\n")).toBe(true);
  });

  test("a pipe/backtick in the preamble is NOT escaped (intentional author markdown)", () => {
    const output = renderMarkdown(model, viewWith({ preamble: "see `code` and a | pipe" }));

    expect(output.includes("see `code` and a | pipe")).toBe(true);
  });

  test("no policy view → default title, no preamble, output still has no CR / single trailing LF", () => {
    const output = renderMarkdown(model);

    expect(output.split("\n")[0]).toBe("# Third-Party Licenses");
    expect(output.includes("\r")).toBe(false);
    expect(output.endsWith("\n")).toBe(true);
    expect(output.endsWith("\n\n")).toBe(false);
  });
});

// ===========================================================================
// The generated scope-of-assertion + attribution lines: directly after the
// auto-generated header comment, BEFORE the author preamble - present only
// when PolicyView.targetProfile is set (the policy declares an active
// [target] lane). NOTICES never carries either line (it takes no PolicyView
// at all). Absent [target] renders neither line - the no-target byte-identity
// contract the existing golden-byte-equality tests already lock.
// ===========================================================================
describe("renderMarkdown - target-profile header lines (scope-of-assertion + attribution)", () => {
  const model: CanonicalDependencies = {
    packages: [
      entry({
        purl: "pkg:npm/a@1.0.0",
        name: "a",
        version: "1.0.0",
        finding: { expression: "MIT", elected: "MIT", source: "generator", confidence: "exact" },
      }),
    ],
  };

  const proprietaryProfile: TargetProfile = {
    license: { kind: "proprietary" },
    network: true,
    distribution: "external",
  };
  const mitProfile: TargetProfile = {
    license: { kind: "oss", id: "MIT" },
    network: false,
    distribution: "internal",
  };

  const viewWith = (targetProfile?: TargetProfileSummary): PolicyView => ({
    policyPath: "policy.toml",
    suppressedWorkspaces: [],
    verdicts: [],
    ...(targetProfile !== undefined ? { targetProfile } : {}),
  });

  test("absent PolicyView.targetProfile renders neither line - byte-identical to a no-target render", () => {
    const withField = renderMarkdown(model, viewWith());
    const withoutField = renderMarkdown(model, {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [],
    });

    expect(withField).toBe(withoutField);
    expect(withField.includes("audited against")).toBe(false);
    expect(withField.includes("OSADL")).toBe(false);
  });

  test("a project-level profile renders the exact scope-of-assertion line, naming all three profile elements", () => {
    const output = renderMarkdown(model, viewWith({ project: proprietaryProfile, workspaces: [] }));
    const lines = output.split("\n");

    expect(lines[3]).toBe(
      "This report was audited against the declared target: proprietary, network-deployed, " +
        "distributed externally. Its findings assert license validity against that target and the " +
        "declared configuration only.",
    );
  });

  test("the attribution/disclaimer line follows immediately, naming both data sources and their snapshot timestamps", () => {
    const output = renderMarkdown(model, viewWith({ project: mitProfile, workspaces: [] }));
    const lines = output.split("\n");

    expect(lines[4]).toBe(
      "Compatibility verdicts draw on the OSADL compatibility matrix and copyleft class table " +
        "(snapshot 2026-08-04T15:39:00+0000, osadl.org) and the ScanCode LicenseDB category index " +
        "(snapshot 2026-08-10T16:21:01Z, scancode-licensedb.aboutcode.org) - this is automated, " +
        "data-driven output, not legal advice.",
    );
    expect(output.includes("not legal advice")).toBe(true);
  });

  test("locked order: header comment, then the target line, then the attribution line, then the author preamble", () => {
    const output = renderMarkdown(model, {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [],
      targetProfile: { project: mitProfile, workspaces: [] },
      document: { preamble: "Author preamble text." },
    });
    const headerIdx = output.indexOf(
      "<!-- AUTO-GENERATED - do not edit. Regenerate with: task generate -->",
    );
    const targetIdx = output.indexOf("This report was audited against");
    const attributionIdx = output.indexOf("Compatibility verdicts draw on the OSADL");
    const preambleIdx = output.indexOf("Author preamble text.");

    expect(headerIdx).toBeGreaterThan(-1);
    expect(targetIdx).toBeGreaterThan(headerIdx);
    expect(attributionIdx).toBeGreaterThan(targetIdx);
    expect(preambleIdx).toBeGreaterThan(attributionIdx);
  });

  test("per-workspace overrides append to the project-level line, deterministically sorted by path regardless of input order", () => {
    const output = renderMarkdown(
      model,
      viewWith({
        project: mitProfile,
        workspaces: [
          { path: "apps/z", profile: proprietaryProfile },
          { path: "apps/a", profile: mitProfile },
        ],
      }),
    );
    const line = output.split("\n")[3]!;

    expect(line).toBe(
      "This report was audited against the declared target: MIT, not network-deployed, internal " +
        "use only. Per-workspace overrides: apps/a (MIT, not network-deployed, internal use only), " +
        "apps/z (proprietary, network-deployed, distributed externally). Its findings assert " +
        "license validity against that target and the declared configuration only.",
    );
  });

  test("a workspaces-only profile (no complete project profile) names the per-workspace targets directly as the audited-against subject", () => {
    const output = renderMarkdown(
      model,
      viewWith({
        workspaces: [{ path: "apps/studio", profile: proprietaryProfile }],
      }),
    );
    const line = output.split("\n")[3]!;

    expect(line).toBe(
      "This report was audited against the declared per-workspace targets: apps/studio " +
        "(proprietary, network-deployed, distributed externally). Its findings assert license " +
        "validity against those targets and the declared configuration only.",
    );
  });

  test("a workspace path is escapeCell'd (markdown-injection mitigation, same trust boundary as every other policy-authored string)", () => {
    const output = renderMarkdown(
      model,
      viewWith({
        workspaces: [{ path: "apps/[evil](x)", profile: proprietaryProfile }],
      }),
    );

    expect(output.includes("apps/[evil](x)")).toBe(false);
    expect(output.includes("apps/\\[evil\\](x)")).toBe(true);
  });

  test("renderNotices NEVER carries either generated line - it takes no PolicyView and cannot, by construction", () => {
    const notices = renderNotices(model);

    expect(notices.includes("audited against")).toBe(false);
    expect(notices.includes("OSADL")).toBe(false);
    expect(notices.includes("ScanCode LicenseDB")).toBe(false);
  });
});

// ===========================================================================
// The "## Problematic licenses" roll-up - rendered after the
// counts block, before the copyleft section, ONLY on a policy run. A BLOCKING
// table of every fail verdict (grouped by purl+rule+reason), plus a one-line
// non-blocking warn roll-up. Empty state renders the ✅ line.
// ===========================================================================
describe("renderMarkdown — Problematic licenses summary", () => {
  const denied = entry({
    purl: "pkg:npm/denied-pkg@1.0.0",
    name: "denied-pkg",
    version: "1.0.0",
    occurrences: [{ target: "backend", isDevDependency: false }],
    finding: {
      expression: "BUSL-1.1",
      elected: "BUSL-1.1",
      source: "generator",
      confidence: "exact",
    },
  });
  const copyleftFail = entry({
    purl: "pkg:pypi/gpl-pkg@2.0.0",
    name: "gpl-pkg",
    version: "2.0.0",
    occurrences: [
      { target: "backend", isDevDependency: false },
      { target: "frontend", isDevDependency: false },
    ],
    finding: {
      expression: "GPL-3.0-only",
      elected: "GPL-3.0-only",
      source: "generator",
      confidence: "exact",
    },
  });
  const unknownFail = entry({
    purl: "pkg:npm/unk-pkg@3.0.0",
    name: "unk-pkg",
    version: "3.0.0",
    occurrences: [{ target: "backend", isDevDependency: false }],
    finding: {
      expression: null,
      elected: null,
      source: "generator",
      confidence: "none",
    },
  });
  const warnOnly = entry({
    purl: "pkg:npm/warn-pkg@4.0.0",
    name: "warn-pkg",
    version: "4.0.0",
    finding: {
      expression: "LGPL-3.0-or-later",
      elected: "LGPL-3.0-or-later",
      source: "generator",
      confidence: "exact",
    },
  });

  const HEADING = "## Problematic licenses";

  const slice = (output: string): string =>
    output.slice(output.indexOf(HEADING), output.indexOf("## Copyleft and special notices"));

  test("(a) mixed fails across deny + copyleft + unknown: grouping, sort, reason", () => {
    const model: CanonicalDependencies = {
      packages: [denied, copyleftFail, unknownFail],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        {
          purl: "pkg:npm/denied-pkg@1.0.0",
          occurrenceTarget: "backend",
          status: "fail",
          rule: "deny:license[0]",
          reason: "BUSL-1.1 is source-available",
        },
        // Two occurrences of the SAME (purl, rule, reason) group → ONE row with
        // deduped+sorted targets joined ", ".
        {
          purl: "pkg:pypi/gpl-pkg@2.0.0",
          occurrenceTarget: "frontend",
          status: "fail",
          rule: "default:copyleft",
          reason: 'copyleft license "GPL-3.0-only"',
        },
        {
          purl: "pkg:pypi/gpl-pkg@2.0.0",
          occurrenceTarget: "backend",
          status: "fail",
          rule: "default:copyleft",
          reason: 'copyleft license "GPL-3.0-only"',
        },
        {
          purl: "pkg:npm/unk-pkg@3.0.0",
          occurrenceTarget: "backend",
          status: "fail",
          rule: "default:unknown",
          reason: "no license could be determined",
        },
      ],
    };
    const output = renderMarkdown(model, view);
    const section = slice(output);

    expect(section.includes(HEADING)).toBe(true);
    // The blocking table head with the fixed column order — now carries the
    // Why column between Used-in and Reason.
    expect(
      section.includes(
        "| Severity | Rule | Name | Ecosystem | Version | License | Used in | Why | Reason |",
      ),
    ).toBe(true);
    // One row per group. Sort: by rule (compareCodeUnits) then package.
    //   default:copyleft < default:unknown < deny:license[0]
    // escapeCell does NOT touch double-quotes (they are inert in a table cell),
    // so the reason's quotes survive verbatim. These entries carry no
    // introduction, so the Why cell is the honest residual "—".
    expect(
      section.includes(
        '| fail | default:copyleft | gpl-pkg | pypi | 2.0.0 | GPL-3.0-only | backend, frontend | — | copyleft license "GPL-3.0-only" |',
      ),
    ).toBe(true);
    expect(
      section.includes(
        "| fail | default:unknown | unk-pkg | npm | 3.0.0 | unknown | backend | — | no license could be determined |",
      ),
    ).toBe(true);
    expect(
      section.includes(
        "| fail | deny:license\\[0\\] | denied-pkg | npm | 1.0.0 | BUSL-1.1 | backend | — | BUSL-1.1 is source-available |",
      ),
    ).toBe(true);
    // Rule-sorted ordering inside the table.
    expect(section.indexOf("default:copyleft")).toBeLessThan(section.indexOf("default:unknown"));
    expect(section.indexOf("default:unknown")).toBeLessThan(section.indexOf("deny:license"));
    // The gpl-pkg group folded two occurrences into ONE row.
    expect(section.match(/\| gpl-pkg \|/g)!.length).toBe(1);
  });

  test("(b) zero-fail-with-warns → ✅ line + non-blocking roll-up", () => {
    const model: CanonicalDependencies = { packages: [warnOnly] };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        {
          purl: "pkg:npm/warn-pkg@4.0.0",
          occurrenceTarget: "apps/a",
          status: "warn",
          rule: "default:copyleft",
          reason: "dev-downgraded copyleft",
        },
      ],
    };
    const section = slice(renderMarkdown(model, view));

    expect(section.includes("✅ No blocking policy violations.")).toBe(true);
    expect(section.includes("_Non-blocking:")).toBe(true);
    expect(section.includes("copyleft")).toBe(true);
    // No blocking table head when there are zero fails.
    expect(section.includes("| Severity |")).toBe(false);
  });

  test("(c) zero-fail-zero-warn → ✅ line only, no roll-up line", () => {
    const model: CanonicalDependencies = { packages: [warnOnly] };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        {
          purl: "pkg:npm/warn-pkg@4.0.0",
          occurrenceTarget: "apps/a",
          status: "ok",
          rule: "default:ok",
          reason: "no obligations",
        },
      ],
    };
    const section = slice(renderMarkdown(model, view));

    expect(section.includes("✅ No blocking policy violations.")).toBe(true);
    expect(section.includes("_Non-blocking:")).toBe(false);
  });

  test("non-blocking roll-up groups warns by coarse category", () => {
    const model: CanonicalDependencies = {
      packages: [warnOnly, unknownFail, denied],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        {
          purl: "pkg:npm/warn-pkg@4.0.0",
          occurrenceTarget: "apps/a",
          status: "warn",
          rule: "default:copyleft",
          reason: "x",
        },
        {
          purl: "pkg:npm/warn-pkg@4.0.0",
          occurrenceTarget: "apps/b",
          status: "warn",
          rule: "default:imprecise-copyleft",
          reason: "y",
        },
        {
          purl: "pkg:npm/unk-pkg@3.0.0",
          occurrenceTarget: "apps/a",
          status: "warn",
          rule: "default:unknown",
          reason: "z",
        },
        {
          purl: "pkg:npm/denied-pkg@1.0.0",
          occurrenceTarget: "apps/a",
          status: "warn",
          rule: "deny:license[0]",
          reason: "w",
        },
      ],
    };
    const section = slice(renderMarkdown(model, view));

    // 2 copyleft (copyleft + imprecise-copyleft), 1 unknown, 1 deny.
    expect(section.includes("2 copyleft warning(s)")).toBe(true);
    expect(section.includes("1 unknown warning(s)")).toBe(true);
    expect(section.includes("1 deny warning(s)")).toBe(true);
  });

  test("(d) the summary sits ABOVE the detailed copyleft section; a fail-flagged package is excluded from it by the copyleft-only dedup", () => {
    const model: CanonicalDependencies = { packages: [copyleftFail] };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        {
          purl: "pkg:pypi/gpl-pkg@2.0.0",
          occurrenceTarget: "backend",
          status: "fail",
          rule: "default:copyleft",
          reason: 'copyleft license "GPL-3.0-only"',
        },
      ],
    };
    const output = renderMarkdown(model, view);
    const problIdx = output.indexOf("## Problematic licenses");
    const countsIdx = output.indexOf("**Package counts:**");
    const copyleftIdx = output.indexOf("## Copyleft and special notices");

    expect(countsIdx).toBeLessThan(problIdx);
    expect(problIdx).toBeLessThan(copyleftIdx);
    // gpl-pkg carries a fail verdict, so the copyleft-only dedup excludes it
    // from the detailed copyleft table entirely — it stays in Problematic
    // (asserted above by the section ordering) and in its inventory row.
    const copyleftSection = output.slice(copyleftIdx, output.indexOf("## Production dependencies"));

    expect(copyleftSection.includes("gpl-pkg")).toBe(false);
    expect(
      copyleftSection.includes("✅ No package carries copyleft or special license obligations."),
    ).toBe(true);
  });

  test("(e) no-policy run → the section is omitted entirely", () => {
    const output = renderMarkdown({ packages: [copyleftFail] });

    expect(output.includes("## Problematic licenses")).toBe(false);
  });

  test("a fail verdict whose purl has no package entry is defensively skipped", () => {
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        {
          purl: "pkg:npm/ghost@9.9.9",
          occurrenceTarget: "backend",
          status: "fail",
          rule: "deny:license[0]",
          reason: "orphan verdict",
        },
      ],
    };
    const section = slice(renderMarkdown({ packages: [warnOnly] }, view));

    // No package entry for the ghost purl → no row, and zero real fails → ✅.
    expect(section.includes("ghost")).toBe(false);
    expect(section.includes("✅ No blocking policy violations.")).toBe(true);
  });

  test("the section heading always renders on a policy run, output stays CR-free", () => {
    const output = renderMarkdown(
      { packages: [warnOnly] },
      {
        policyPath: "policy.toml",
        suppressedWorkspaces: [],
        verdicts: [],
      },
    );

    expect(output.includes("## Problematic licenses")).toBe(true);
    expect(output.includes("\r")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Dependency provenance "Why" column — problematic table + copyleft
// section. The per-row aggregation rule (optionality descoped): "—" when
// no in-scope occurrence carries an introduction OR all in-scope introductions
// are orphans (direct:false ∧ empty introducedBy ∧ no path); "direct" when ≥1
// genuine (non-orphan) in-scope occurrence is direct and the rest are orphans;
// else the representative path of the smallest-target occurrence carrying one
// (joined " → "), or the sorted-union of introducedBy sets; paths/sets bounded
// with "(+N more)". No ", optional" suffix is ever rendered.
// ---------------------------------------------------------------------------

describe("renderMarkdown — provenance Why column", () => {
  /**
   * A copyleft-flagging verdict for a given purl + target. Status is "warn",
   * never "fail": a fail verdict of ANY rule excludes its purl from Copyleft
   * membership entirely (the copyleft-only dedup), which would defeat every
   * Why-cell assertion in this block — these tests exercise Why-cell
   * computation, not the dedup itself.
   */
  const copyleftVerdict = (purl: string, target: string): Verdict => ({
    purl,
    occurrenceTarget: target,
    status: "warn",
    rule: "default:copyleft",
    reason: "copyleft",
  });

  /** Render a model+view and slice the copyleft section. */
  function copyleftSectionOf(model: CanonicalDependencies, view: PolicyView): string {
    const output = renderMarkdown(model, view);
    const start = output.indexOf("## Copyleft and special notices");
    const end = output.indexOf("## Production dependencies");

    return output.slice(start, end);
  }

  test("direct in any occurrence → 'direct' in the copyleft Why cell", () => {
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:npm/direct-pkg@1.0.0",
          name: "direct-pkg",
          version: "1.0.0",
          occurrences: [
            {
              target: "apps/a",
              isDevDependency: false,
              introduction: { direct: true, introducedBy: [] },
            },
          ],
          finding: {
            expression: "GPL-3.0-only",
            elected: "GPL-3.0-only",
            source: "generator",
            confidence: "exact",
          },
        }),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [copyleftVerdict("pkg:npm/direct-pkg@1.0.0", "apps/a")],
    };

    expect(
      copyleftSectionOf(model, view).includes(
        "| direct-pkg | npm | 1.0.0 | GPL-3.0-only | apps/a | direct |",
      ),
    ).toBe(true);
  });

  test("transitive → the tie-broken path joined by ' → '", () => {
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:npm/trans-pkg@1.0.0",
          name: "trans-pkg",
          version: "1.0.0",
          occurrences: [
            {
              target: "apps/a",
              isDevDependency: false,
              introduction: {
                direct: false,
                introducedBy: ["pkg:npm/parent@2.0.0"],
                path: ["pkg:npm/parent@2.0.0", "pkg:npm/trans-pkg@1.0.0"],
              },
            },
          ],
          finding: {
            expression: "GPL-3.0-only",
            elected: "GPL-3.0-only",
            source: "generator",
            confidence: "exact",
          },
        }),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [copyleftVerdict("pkg:npm/trans-pkg@1.0.0", "apps/a")],
    };

    expect(
      copyleftSectionOf(model, view).includes(
        "| trans-pkg | npm | 1.0.0 | GPL-3.0-only | apps/a | pkg:npm/parent@2.0.0 → pkg:npm/trans-pkg@1.0.0 |",
      ),
    ).toBe(true);
  });

  test("a python transitive renders its path with NO ', optional' suffix", () => {
    // Optionality is descoped — a python transitive is just a path, never
    // suffixed ", optional". (Was: "optional (python) → annotated".)
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:pypi/opt-pkg@1.0.0",
          name: "opt-pkg",
          version: "1.0.0",
          occurrences: [
            {
              target: "apps/py",
              isDevDependency: false,
              introduction: {
                direct: false,
                introducedBy: ["pkg:pypi/host@2.0.0"],
                path: ["pkg:pypi/host@2.0.0", "pkg:pypi/opt-pkg@1.0.0"],
              },
            },
          ],
          finding: {
            expression: "GPL-3.0-only",
            elected: "GPL-3.0-only",
            source: "generator",
            confidence: "exact",
          },
        }),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [copyleftVerdict("pkg:pypi/opt-pkg@1.0.0", "apps/py")],
    };
    const section = copyleftSectionOf(model, view);

    expect(
      section.includes(
        "| opt-pkg | pypi | 1.0.0 | GPL-3.0-only | apps/py | pkg:pypi/host@2.0.0 → pkg:pypi/opt-pkg@1.0.0 |",
      ),
    ).toBe(true);
    expect(section.includes(", optional")).toBe(false);
  });

  test("introduction absent → honest '—' (never fabricated)", () => {
    // APP-scope, not os-scope: an os-scope package is excluded from Copyleft
    // regardless of verdict (container copyleft is routine, not surfaced
    // here), which would defeat this assertion — the test's real subject is
    // the Why-cell honest-residual behavior, orthogonal to scope.
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:pypi/libssl-bindings@3.0",
          name: "libssl-bindings",
          version: "3.0",
          occurrences: [{ target: "apps/py", isDevDependency: false }],
          finding: {
            expression: "GPL-3.0-only",
            elected: "GPL-3.0-only",
            source: "generator",
            confidence: "exact",
          },
        }),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [copyleftVerdict("pkg:pypi/libssl-bindings@3.0", "apps/py")],
    };

    expect(
      copyleftSectionOf(model, view).includes(
        "| libssl-bindings | pypi | 3.0 | GPL-3.0-only | apps/py | — |",
      ),
    ).toBe(true);
  });

  test("bare 'direct' ONLY when EVERY in-scope occurrence is direct", () => {
    // direct in apps/a AND apps/b, both flagged + in-scope → bare "direct".
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:npm/all-direct@1.0.0",
          name: "all-direct",
          version: "1.0.0",
          occurrences: [
            {
              target: "apps/a",
              isDevDependency: false,
              introduction: { direct: true, introducedBy: [] },
            },
            {
              target: "apps/b",
              isDevDependency: false,
              introduction: { direct: true, introducedBy: [] },
            },
          ],
          finding: {
            expression: "GPL-3.0-only",
            elected: "GPL-3.0-only",
            source: "generator",
            confidence: "exact",
          },
        }),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        copyleftVerdict("pkg:npm/all-direct@1.0.0", "apps/a"),
        copyleftVerdict("pkg:npm/all-direct@1.0.0", "apps/b"),
      ],
    };
    const section = copyleftSectionOf(model, view);

    expect(section.includes("| all-direct |")).toBe(true);
    expect(section.includes(" | direct |")).toBe(true);
  });

  test("direct in ONE flagged occurrence + transitive in another → surfaces the TRANSITIVE introducer, not bare 'direct' (no-hiding)", () => {
    // mixed-pkg is direct in flagged occ apps/b BUT transitive (via p) in flagged
    // occ apps/a. The earlier `.some(i => i.direct)` short-circuit collapsed to
    // bare "direct", HIDING the prod-transitive introducer in apps/a. The fix
    // renders "direct" ONLY when EVERY in-scope occurrence is direct; otherwise
    // it falls through to the tier/path logic and surfaces the transitive chain.
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:npm/mixed-pkg@1.0.0",
          name: "mixed-pkg",
          version: "1.0.0",
          occurrences: [
            {
              target: "apps/a",
              isDevDependency: false,
              introduction: {
                direct: false,
                introducedBy: ["pkg:npm/p@2.0.0"],
                path: ["pkg:npm/p@2.0.0", "pkg:npm/mixed-pkg@1.0.0"],
              },
            },
            {
              target: "apps/b",
              isDevDependency: false,
              introduction: { direct: true, introducedBy: [] },
            },
          ],
          finding: {
            expression: "GPL-3.0-only",
            elected: "GPL-3.0-only",
            source: "generator",
            confidence: "exact",
          },
        }),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        copyleftVerdict("pkg:npm/mixed-pkg@1.0.0", "apps/a"),
        copyleftVerdict("pkg:npm/mixed-pkg@1.0.0", "apps/b"),
      ],
    };
    const section = copyleftSectionOf(model, view);

    expect(section.includes("| mixed-pkg |")).toBe(true);
    // The transitive introducer from apps/a is surfaced...
    expect(section.includes("pkg:npm/p@2.0.0 → pkg:npm/mixed-pkg@1.0.0")).toBe(true);
    // ...and the row is NOT collapsed to bare "direct".
    expect(section.includes(" | direct |")).toBe(false);
  });

  test("a very long path is bounded with a stable (+N more)", () => {
    const longPath = [
      "pkg:npm/p1@1",
      "pkg:npm/p2@1",
      "pkg:npm/p3@1",
      "pkg:npm/p4@1",
      "pkg:npm/p5@1",
      "pkg:npm/deep@1",
    ];
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:npm/deep@1",
          name: "deep",
          version: "1",
          occurrences: [
            {
              target: "apps/a",
              isDevDependency: false,
              introduction: {
                direct: false,
                introducedBy: ["pkg:npm/p5@1"],
                path: longPath,
              },
            },
          ],
          finding: {
            expression: "GPL-3.0-only",
            elected: "GPL-3.0-only",
            source: "generator",
            confidence: "exact",
          },
        }),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [copyleftVerdict("pkg:npm/deep@1", "apps/a")],
    };
    const section = copyleftSectionOf(model, view);

    // First WHY_MAX_ITEMS (4) purls shown, then a stable "(+2 more)" tail.
    expect(section.includes("(+2 more)")).toBe(true);
    expect(
      section.includes("pkg:npm/p1@1 → pkg:npm/p2@1 → pkg:npm/p3@1 → pkg:npm/p4@1 (+2 more)"),
    ).toBe(true);
  });

  test("problematic table Why cell carries provenance for a blocking fail", () => {
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:npm/blocked@1.0.0",
          name: "blocked",
          version: "1.0.0",
          occurrences: [
            {
              target: "apps/a",
              isDevDependency: false,
              introduction: {
                direct: false,
                introducedBy: ["pkg:npm/intro@2.0.0"],
                path: ["pkg:npm/intro@2.0.0", "pkg:npm/blocked@1.0.0"],
              },
            },
          ],
          finding: {
            expression: "BUSL-1.1",
            elected: "BUSL-1.1",
            source: "generator",
            confidence: "exact",
          },
        }),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        {
          purl: "pkg:npm/blocked@1.0.0",
          occurrenceTarget: "apps/a",
          status: "fail",
          rule: "deny:license[0]",
          reason: "BUSL-1.1 denied",
        },
      ],
    };
    const output = renderMarkdown(model, view);

    expect(
      output.includes(
        "| fail | deny:license\\[0\\] | blocked | npm | 1.0.0 | BUSL-1.1 | apps/a | pkg:npm/intro@2.0.0 → pkg:npm/blocked@1.0.0 | BUSL-1.1 denied |",
      ),
    ).toBe(true);
  });

  test("absent introduction → render is byte-identical to a no-introduction model except… nothing (residual is '—')", () => {
    // A model whose occurrences carry NO introduction must render exactly as it
    // did before provenance — every Why cell is "—", and the rest of the
    // document is unchanged. Double-generate is byte-identical.
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:npm/plain@1.0.0",
          name: "plain",
          version: "1.0.0",
          occurrences: [{ target: "apps/a", isDevDependency: false }],
          finding: {
            expression: "GPL-3.0-only",
            elected: "GPL-3.0-only",
            source: "generator",
            confidence: "exact",
          },
        }),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [copyleftVerdict("pkg:npm/plain@1.0.0", "apps/a")],
    };
    const first = renderMarkdown(model, view);
    const second = renderMarkdown(model, view);

    expect(first).toBe(second); // determinism
    expect(first.includes("| plain | npm | 1.0.0 | GPL-3.0-only | apps/a | — |")).toBe(true);
  });

  test("a genuinely-DIRECT occurrence is NOT hidden behind '—' by an orphan co-occurrence", () => {
    // Two in-scope occurrences of one purl: one genuinely DIRECT (apps/a), one an
    // ORPHAN ({direct:false, introducedBy:[], no path} — a node with no derivable
    // introducer, the honest residual). The pre-fix `every(direct)` was false
    // (the orphan is direct:false), then the tier/path union was empty → "—",
    // HIDING the real direct. FIX: orphan introductions are EXCLUDED from the
    // direct/transitive decision, so the genuine direct wins → "direct".
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:pypi/realdirect@1.0.0",
          name: "realdirect",
          version: "1.0.0",
          occurrences: [
            {
              target: "ws-a",
              isDevDependency: false,
              introduction: { direct: true, introducedBy: [] },
            },
            {
              target: "ws-b",
              isDevDependency: false,
              introduction: { direct: false, introducedBy: [] },
            },
          ],
          finding: {
            expression: "GPL-3.0-only",
            elected: "GPL-3.0-only",
            source: "generator",
            confidence: "exact",
          },
        }),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        copyleftVerdict("pkg:pypi/realdirect@1.0.0", "ws-a"),
        copyleftVerdict("pkg:pypi/realdirect@1.0.0", "ws-b"),
      ],
    };
    const section = copyleftSectionOf(model, view);

    // The genuine direct is surfaced, NOT hidden behind "—".
    expect(
      section.includes("| realdirect | pypi | 1.0.0 | GPL-3.0-only | ws-a, ws-b | direct |"),
    ).toBe(true);
  });

  test("ALL-orphan in-scope occurrences render '—' (only all-orphan/empty is the residual)", () => {
    // Two in-scope occurrences, BOTH orphans → "—". Excluding orphans from the
    // decision must NOT promote an all-orphan row to "direct"/transitive; with no
    // genuine direct and no introducer evidence anywhere, the honest residual
    // stays "—".
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:pypi/allorphan@1.0.0",
          name: "allorphan",
          version: "1.0.0",
          occurrences: [
            {
              target: "ws-a",
              isDevDependency: false,
              introduction: { direct: false, introducedBy: [] },
            },
            {
              target: "ws-b",
              isDevDependency: false,
              introduction: { direct: false, introducedBy: [] },
            },
          ],
          finding: {
            expression: "GPL-3.0-only",
            elected: "GPL-3.0-only",
            source: "generator",
            confidence: "exact",
          },
        }),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        copyleftVerdict("pkg:pypi/allorphan@1.0.0", "ws-a"),
        copyleftVerdict("pkg:pypi/allorphan@1.0.0", "ws-b"),
      ],
    };

    expect(
      copyleftSectionOf(model, view).includes(
        "| allorphan | pypi | 1.0.0 | GPL-3.0-only | ws-a, ws-b | — |",
      ),
    ).toBe(true);
  });

  test("a genuine TRANSITIVE occurrence is surfaced even alongside an orphan co-occurrence", () => {
    // One genuine transitive (has an introducer/path) + one orphan → the
    // transitive introducer is surfaced (NOT swallowed to "—" by the orphan, and
    // NOT promoted to "direct").
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:pypi/transorphan@1.0.0",
          name: "transorphan",
          version: "1.0.0",
          occurrences: [
            {
              target: "ws-a",
              isDevDependency: false,
              introduction: {
                direct: false,
                introducedBy: ["pkg:pypi/host@2.0.0"],
                path: ["pkg:pypi/host@2.0.0", "pkg:pypi/transorphan@1.0.0"],
              },
            },
            {
              target: "ws-b",
              isDevDependency: false,
              introduction: { direct: false, introducedBy: [] },
            },
          ],
          finding: {
            expression: "GPL-3.0-only",
            elected: "GPL-3.0-only",
            source: "generator",
            confidence: "exact",
          },
        }),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        copyleftVerdict("pkg:pypi/transorphan@1.0.0", "ws-a"),
        copyleftVerdict("pkg:pypi/transorphan@1.0.0", "ws-b"),
      ],
    };
    const section = copyleftSectionOf(model, view);

    expect(section.includes("pkg:pypi/host@2.0.0 → pkg:pypi/transorphan@1.0.0")).toBe(true);
    expect(section.includes("| transorphan | pypi | 1.0.0 | GPL-3.0-only")).toBe(true);
  });

  test("orphan transitive (no introducer evidence) renders '—', not 'transitive' (#5)", () => {
    // introduction { direct:false, introducedBy:[], no path } — present in the
    // graph but unreachable from any root. The cell is the honest residual "—",
    // never a confident "transitive" with no introducer.
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:npm/orphan@1.0.0",
          name: "orphan",
          version: "1.0.0",
          occurrences: [
            {
              target: "apps/a",
              isDevDependency: false,
              introduction: { direct: false, introducedBy: [] },
            },
          ],
          finding: {
            expression: "GPL-3.0-only",
            elected: "GPL-3.0-only",
            source: "generator",
            confidence: "exact",
          },
        }),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [copyleftVerdict("pkg:npm/orphan@1.0.0", "apps/a")],
    };

    expect(
      copyleftSectionOf(model, view).includes(
        "| orphan | npm | 1.0.0 | GPL-3.0-only | apps/a | — |",
      ),
    ).toBe(true);
  });

  test("a defined-but-EMPTY path renders '—', not an empty Why cell", () => {
    // INFO (latent): whyCellOf's orphan guard checks `path === undefined`, so a
    // defined-but-EMPTY `path: []` bypasses it; the transitive branch then
    // selected the occurrence on `path !== undefined` and boundedJoin([], …)
    // joined to "" → an empty Why cell `| … | |`. FIX: treat a defined-but-empty
    // path as carrying no chain — fold it into the orphan/no-path handling so it
    // renders "—" (here introducedBy is empty too → the honest residual).
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:npm/emptypath@1.0.0",
          name: "emptypath",
          version: "1.0.0",
          occurrences: [
            {
              target: "apps/a",
              isDevDependency: false,
              introduction: { direct: false, introducedBy: [], path: [] },
            },
          ],
          finding: {
            expression: "GPL-3.0-only",
            elected: "GPL-3.0-only",
            source: "generator",
            confidence: "exact",
          },
        }),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [copyleftVerdict("pkg:npm/emptypath@1.0.0", "apps/a")],
    };
    const section = copyleftSectionOf(model, view);

    expect(section.includes("| emptypath | npm | 1.0.0 | GPL-3.0-only | apps/a | — |")).toBe(true);
    // No empty Why cell: the row must NOT end in "| |".
    expect(section.includes("| apps/a |  |")).toBe(false);
  });

  test("a defined-but-empty path falls through to the introducedBy union when one exists", () => {
    // An empty `path` with a NON-empty introducedBy must surface the introducer
    // union (not "" and not "—"): the empty path carries no chain, but the
    // introducer evidence still stands.
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:npm/emptypathintro@1.0.0",
          name: "emptypathintro",
          version: "1.0.0",
          occurrences: [
            {
              target: "apps/a",
              isDevDependency: false,
              introduction: {
                direct: false,
                introducedBy: ["pkg:npm/host@2.0.0"],
                path: [],
              },
            },
          ],
          finding: {
            expression: "GPL-3.0-only",
            elected: "GPL-3.0-only",
            source: "generator",
            confidence: "exact",
          },
        }),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [copyleftVerdict("pkg:npm/emptypathintro@1.0.0", "apps/a")],
    };
    const section = copyleftSectionOf(model, view);

    expect(
      section.includes(
        "| emptypathintro | npm | 1.0.0 | GPL-3.0-only | apps/a | pkg:npm/host@2.0.0 |",
      ),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Why-cell target scoping — the Why cell MUST fold ONLY over the
// occurrences whose target is in the row's shown/flagged set. The Why cell and
// the Used-in cell are computed from the SAME occurrence subset, so the Why
// cell never mislabels (a direct-in-an-unflagged-workspace occurrence cannot
// turn a transitive flagged row into "direct") and never fabricates (a flagged
// occurrence with no introduction cannot borrow a path/introducer from a
// DIFFERENT, out-of-scope occurrence).
// ---------------------------------------------------------------------------

describe("renderMarkdown — Why-cell target scoping", () => {
  /** Slice the problematic section out of a full document render. */
  function problematicSectionOf(model: CanonicalDependencies, view: PolicyView): string {
    const output = renderMarkdown(model, view);
    const start = output.indexOf("## Problematic licenses");
    const end = output.indexOf("## Copyleft and special notices");

    return output.slice(start, end);
  }

  /** Slice the copyleft section out of a full document render. */
  function copyleftSectionOf(model: CanonicalDependencies, view: PolicyView): string {
    const output = renderMarkdown(model, view);
    const start = output.indexOf("## Copyleft and special notices");
    const end = output.indexOf("## Production dependencies");

    return output.slice(start, end);
  }

  test("(a) problematic row: flagged-target is transitive, but DIRECT in an unflagged workspace → Why shows the TRANSITIVE path, NOT 'direct' (#2/#3/#5 no-mislabeling)", () => {
    // agpllib is DIRECT in tooling/devkit (dev, unflagged) and TRANSITIVE in
    // apps/prod-shipped (prod, flagged by a deny verdict). The row is scoped to
    // apps/prod-shipped only — the Why cell must reflect THAT occurrence's
    // transitive chain, never borrow "direct" from tooling/devkit.
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:npm/agpllib@1.0.0",
          name: "agpllib",
          version: "1.0.0",
          occurrences: [
            {
              target: "tooling/devkit",
              isDevDependency: true,
              introduction: { direct: true, introducedBy: [] },
            },
            {
              target: "apps/prod-shipped",
              isDevDependency: false,
              introduction: {
                direct: false,
                introducedBy: ["pkg:npm/deep@9.9.9"],
                path: ["pkg:npm/deep@9.9.9", "pkg:npm/agpllib@1.0.0"],
              },
            },
          ],
          finding: {
            expression: "AGPL-3.0-only",
            elected: "AGPL-3.0-only",
            source: "generator",
            confidence: "exact",
          },
        }),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        {
          purl: "pkg:npm/agpllib@1.0.0",
          occurrenceTarget: "apps/prod-shipped",
          status: "fail",
          rule: "deny:license[0]",
          reason: "AGPL-3.0-only denied",
        },
      ],
    };
    const section = problematicSectionOf(model, view);

    // The flagged-scoped Why is the transitive path through deep@9.9.9.
    expect(
      section.includes("| apps/prod-shipped | pkg:npm/deep@9.9.9 → pkg:npm/agpllib@1.0.0 |"),
    ).toBe(true);
    // It must NOT borrow the unflagged tooling/devkit occurrence's "direct".
    expect(section.includes(" | direct |")).toBe(false);
  });

  test("(b) copyleft row: flagged occurrence has NO introduction → Why is '—', NOT a borrowed chain from an unflagged occurrence (#2/#3/#5 no-fabrication)", () => {
    // shared is flagged in apps/flagged (prod, NO introduction) and present in
    // tooling/other (prod, transitive via via@2.0.0, NOT flagged). The copyleft
    // row is scoped to apps/flagged only, so the Why cell is the honest "—"; it
    // must NOT borrow the via@2.0.0 chain from the out-of-scope occurrence.
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:npm/shared@1.0.0",
          name: "shared",
          version: "1.0.0",
          occurrences: [
            { target: "apps/flagged", isDevDependency: false },
            {
              target: "tooling/other",
              isDevDependency: false,
              introduction: {
                direct: false,
                introducedBy: ["pkg:npm/via@2.0.0"],
                path: ["pkg:npm/via@2.0.0", "pkg:npm/shared@1.0.0"],
              },
            },
          ],
          finding: {
            expression: "GPL-3.0-only",
            elected: "GPL-3.0-only",
            source: "generator",
            confidence: "exact",
          },
        }),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        {
          purl: "pkg:npm/shared@1.0.0",
          occurrenceTarget: "apps/flagged",
          status: "warn",
          rule: "default:copyleft",
          reason: "copyleft",
        },
      ],
    };
    const section = copyleftSectionOf(model, view);

    expect(section.includes("| shared | npm | 1.0.0 | GPL-3.0-only | apps/flagged | — |")).toBe(
      true,
    );
    // The out-of-scope via@2.0.0 chain must NEVER leak into the flagged row.
    expect(section.includes("pkg:npm/via@2.0.0")).toBe(false);
  });

  test("(B) the smallest-target occurrence carrying a path wins; no ', optional' suffix ever appears", () => {
    // Within the scoped (flagged) subset: occurrence 'a' carries a path via
    // pathparent; occurrence 'b' carries only an introducer set. With
    // optionality descoped there is no tier preference — the representative path
    // of the smallest-target occurrence carrying one is surfaced (deterministic),
    // and no ", optional" suffix is ever rendered.
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:pypi/hr-pkg@1.0.0",
          name: "hr-pkg",
          version: "1.0.0",
          occurrences: [
            {
              target: "a",
              isDevDependency: false,
              introduction: {
                direct: false,
                introducedBy: ["pkg:pypi/pathparent@2.0.0"],
                path: ["pkg:pypi/pathparent@2.0.0", "pkg:pypi/hr-pkg@1.0.0"],
              },
            },
            {
              target: "b",
              isDevDependency: false,
              introduction: {
                direct: false,
                introducedBy: ["pkg:pypi/setparent@3.0.0"],
              },
            },
          ],
          finding: {
            expression: "GPL-3.0-only",
            elected: "GPL-3.0-only",
            source: "generator",
            confidence: "exact",
          },
        }),
      ],
    };
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        {
          purl: "pkg:pypi/hr-pkg@1.0.0",
          occurrenceTarget: "a",
          status: "warn",
          rule: "default:copyleft",
          reason: "copyleft",
        },
        {
          purl: "pkg:pypi/hr-pkg@1.0.0",
          occurrenceTarget: "b",
          status: "warn",
          rule: "default:copyleft",
          reason: "copyleft",
        },
      ],
    };
    const section = copyleftSectionOf(model, view);

    // The smallest-target occurrence carrying a path is surfaced.
    expect(section.includes("pkg:pypi/pathparent@2.0.0 → pkg:pypi/hr-pkg@1.0.0")).toBe(true);
    // No ", optional" suffix is ever rendered after the descope.
    expect(section.includes(", optional")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Target compatibility section - policy runs only, rendered after Copyleft and
// special notices, only when the lane produced a warn/held-internal row.
// ---------------------------------------------------------------------------

describe("renderMarkdown — Target compatibility section", () => {
  test("absent when no target:* row exists at all - no heading, no blank-line drift", () => {
    const output = renderMarkdown(policyModel, basicView);

    expect(output.includes("## Target compatibility")).toBe(false);
  });

  test("absent when the only target:* verdict is a clean target:ok", () => {
    const pkg = entry({
      purl: "pkg:npm/target-ok-only@1.0.0",
      name: "target-ok-only",
      version: "1.0.0",
      licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
      finding: { expression: "MIT", elected: "MIT", source: "generator", confidence: "exact" },
    });
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        {
          purl: "pkg:npm/target-ok-only@1.0.0",
          occurrenceTarget: "apps/a",
          status: "ok",
          rule: "target:ok",
          reason: "compatible",
        },
      ],
    };
    const output = renderMarkdown({ packages: [pkg] }, view);

    expect(output.includes("## Target compatibility")).toBe(false);
  });

  test("renders after Copyleft and special notices, before Imprecise licenses", () => {
    const boundaryPkg = entry({
      purl: "pkg:npm/boundary-pkg@1.0.0",
      name: "boundary-pkg",
      version: "1.0.0",
      licenseClaims: [{ raw: "LGPL-2.1-only", kind: "spdx-id", source: "generator" }],
      finding: {
        expression: "LGPL-2.1-only",
        elected: "LGPL-2.1-only",
        source: "generator",
        confidence: "exact",
      },
    });
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        {
          purl: "pkg:npm/boundary-pkg@1.0.0",
          occurrenceTarget: "apps/a",
          status: "warn",
          rule: "target:boundary",
          reason: "weak copyleft under a proprietary target",
        },
      ],
    };
    const output = renderMarkdown({ packages: [boundaryPkg] }, view);
    const copyleftIdx = output.indexOf("## Copyleft and special notices");
    const targetIdx = output.indexOf("## Target compatibility");

    expect(copyleftIdx).toBeGreaterThan(-1);
    expect(targetIdx).toBeGreaterThan(copyleftIdx);
  });

  test("flagged table rows target:boundary, target:unknown-pair, and dev-downgraded target:incompatible", () => {
    const boundaryPkg = entry({
      purl: "pkg:npm/boundary-pkg@1.0.0",
      name: "boundary-pkg",
      version: "1.0.0",
      licenseClaims: [{ raw: "LGPL-2.1-only", kind: "spdx-id", source: "generator" }],
      finding: {
        expression: "LGPL-2.1-only",
        elected: "LGPL-2.1-only",
        source: "generator",
        confidence: "exact",
      },
    });
    const residualPkg = entry({
      purl: "pkg:npm/residual-pkg@1.0.0",
      name: "residual-pkg",
      version: "1.0.0",
      licenseClaims: [{ raw: "QPL-1.0", kind: "spdx-id", source: "generator" }],
      finding: {
        expression: "QPL-1.0",
        elected: "QPL-1.0",
        source: "generator",
        confidence: "exact",
      },
    });
    const devDowngradedPkg = entry({
      purl: "pkg:npm/dev-downgraded-pkg@1.0.0",
      name: "dev-downgraded-pkg",
      version: "1.0.0",
      occurrences: [{ target: "apps/a", isDevDependency: true }],
      licenseClaims: [{ raw: "GPL-3.0-only", kind: "spdx-id", source: "generator" }],
      finding: {
        expression: "GPL-3.0-only",
        elected: "GPL-3.0-only",
        source: "generator",
        confidence: "exact",
      },
    });
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        {
          purl: "pkg:npm/boundary-pkg@1.0.0",
          occurrenceTarget: "apps/a",
          status: "warn",
          rule: "target:boundary",
          reason: "weak copyleft under a proprietary target",
        },
        {
          purl: "pkg:npm/residual-pkg@1.0.0",
          occurrenceTarget: "apps/a",
          status: "warn",
          rule: "target:unknown-pair",
          reason: "no vetted compatibility data",
        },
        {
          purl: "pkg:npm/dev-downgraded-pkg@1.0.0",
          occurrenceTarget: "apps/a",
          status: "warn",
          rule: "target:incompatible",
          reason: "incompatible, downgraded to warn: dev-only occurrence",
        },
      ],
    };
    const output = renderMarkdown({ packages: [boundaryPkg, residualPkg, devDowngradedPkg] }, view);
    const start = output.indexOf("## Target compatibility");
    const end = output.indexOf("## Imprecise licenses");
    const section = output.slice(start, end === -1 ? undefined : end);

    expect(section.includes("boundary-pkg")).toBe(true);
    expect(section.includes("residual-pkg")).toBe(true);
    expect(section.includes("dev-downgraded-pkg")).toBe(true);
  });

  test("held-for-internal-use list rows every target:internal-use verdict", () => {
    const heldPkg = entry({
      purl: "pkg:npm/held-pkg@1.0.0",
      name: "held-pkg",
      version: "1.0.0",
      licenseClaims: [{ raw: "GPL-3.0-only", kind: "spdx-id", source: "generator" }],
      finding: {
        expression: "GPL-3.0-only",
        elected: "GPL-3.0-only",
        source: "generator",
        confidence: "exact",
      },
    });
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        {
          purl: "pkg:npm/held-pkg@1.0.0",
          occurrenceTarget: "apps/a",
          status: "ok",
          rule: "target:internal-use",
          reason: "held out of scope for internal use",
        },
      ],
    };
    const output = renderMarkdown({ packages: [heldPkg] }, view);
    const section = output.slice(output.indexOf("## Target compatibility"));

    expect(section.includes("held-pkg@1.0.0 in apps/a")).toBe(true);
    expect(section.includes("held out of scope for internal use")).toBe(true);
  });

  test("Problematic dedup: a purl carrying a fail verdict anywhere never rows here", () => {
    const dedupedPkg = entry({
      purl: "pkg:npm/deduped-pkg@1.0.0",
      name: "deduped-pkg",
      version: "1.0.0",
      occurrences: [
        { target: "apps/a", isDevDependency: false },
        { target: "apps/b", isDevDependency: false },
      ],
      licenseClaims: [{ raw: "GPL-3.0-only", kind: "spdx-id", source: "generator" }],
      finding: {
        expression: "GPL-3.0-only",
        elected: "GPL-3.0-only",
        source: "generator",
        confidence: "exact",
      },
    });
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        {
          purl: "pkg:npm/deduped-pkg@1.0.0",
          occurrenceTarget: "apps/a",
          status: "fail",
          rule: "target:incompatible",
          reason: "incompatible",
        },
        {
          purl: "pkg:npm/deduped-pkg@1.0.0",
          occurrenceTarget: "apps/b",
          status: "ok",
          rule: "target:internal-use",
          reason: "held out of scope",
        },
      ],
    };
    const output = renderMarkdown({ packages: [dedupedPkg] }, view);
    const problematicStart = output.indexOf("## Problematic licenses");
    const problematicEnd = output.indexOf("## Copyleft and special notices");

    expect(output.includes("## Target compatibility")).toBe(false);
    expect(output.slice(problematicStart, problematicEnd).includes("deduped-pkg")).toBe(true);
  });
});
