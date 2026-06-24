import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import parse from "spdx-expression-parse";

import { mergeSboms } from "../src/merge/merge";
import {
  type CanonicalDependencies,
  type LicenseFinding,
  type PackageAttribution,
  type PackageEntry,
} from "../src/model/dependencies";
import { leafIds, type ExpressionNode } from "../src/normalize/expression";
import { annotateFindings } from "../src/normalize/normalize";
import { renderNotices } from "../src/render/notices";

// ---------------------------------------------------------------------------
// Notices renderer. Models are hand-built: the renderer is tested against the
// model contract, independent of mergeSboms/annotateFindings.
// ---------------------------------------------------------------------------

const MARKER = "(canonical SPDX text — package-specific copyright not located)";

/** Hand-built PackageEntry with sensible defaults for contract tests. */
function entry(
  partial: Partial<PackageEntry> &
    Pick<PackageEntry, "name" | "version" | "purl">,
): PackageEntry {
  return {
    occurrences: [{ target: "apps/a", isDevDependency: false }],
    licenseClaims: [],
    scope: "app",
    ...partial,
  };
}

function exactFinding(expression: string): LicenseFinding {
  return {
    expression,
    elected: expression,
    source: "generator",
    confidence: "exact",
  };
}

const UNKNOWN_FINDING: LicenseFinding = {
  expression: null,
  elected: null,
  source: "generator",
  confidence: "none",
};

function attribution(partial: Partial<PackageAttribution>): PackageAttribution {
  return {
    copyrightLines: [],
    noticeTexts: [],
    hasVerbatimText: false,
    ...partial,
  };
}

/**
 * Heading lines OUTSIDE fenced blocks. Fence state toggles on backtick-only
 * lines: the first one opens with its exact run; only the identical line
 * closes — shorter backtick runs inside a longer fence are inert content
 * (CommonMark closing-fence rule, sufficient for our computed fences).
 */
function headingsOutsideFences(output: string): string[] {
  const result: string[] = [];
  let openFence: string | null = null;
  for (const line of output.split("\n")) {
    if (/^`{3,}$/.test(line)) {
      if (openFence === null) openFence = line;
      else if (line === openFence) openFence = null;
      continue;
    }
    if (openFence === null && line.startsWith("#")) result.push(line);
  }
  return result;
}

describe("renderNotices — appendix dedup and expression decomposition", () => {
  const model: CanonicalDependencies = {
    packages: [
      entry({
        purl: "pkg:npm/a-mit@1.0.0",
        name: "a-mit",
        version: "1.0.0",
        finding: exactFinding("MIT"),
      }),
      entry({
        purl: "pkg:npm/b-mit@1.0.0",
        name: "b-mit",
        version: "1.0.0",
        finding: exactFinding("MIT"),
      }),
      entry({
        purl: "pkg:npm/c-dual@1.0.0",
        name: "c-dual",
        version: "1.0.0",
        finding: exactFinding("MIT OR Apache-2.0"),
      }),
    ],
  };

  test("two MIT packages produce exactly ONE '### MIT' appendix entry with the canonical text", () => {
    const output = renderNotices(model);
    const lines = output.split("\n");
    expect(lines.filter((line) => line === "### MIT").length).toBe(1);
    // Distinctive canonical-MIT substring from spdx-license-list/full.
    expect(
      output.includes("Permission is hereby granted, free of charge"),
    ).toBe(true);
  });

  test("an 'MIT OR Apache-2.0' package contributes BOTH ids to the appendix, sorted compareCodeUnits", () => {
    const output = renderNotices(model);
    const lines = output.split("\n");
    expect(lines.filter((line) => line === "### Apache-2.0").length).toBe(1);
    // Distinctive canonical-Apache substring.
    expect(output.includes("Version 2.0, January 2004")).toBe(true);
    const appendixStart = output.indexOf("## License texts");
    expect(appendixStart).toBeGreaterThan(-1);
    expect(output.indexOf("### Apache-2.0", appendixStart)).toBeLessThan(
      output.indexOf("### MIT", appendixStart),
    );
  });

  test("leafIds decomposes an OR expression into both leaf ids (no exceptions)", () => {
    const result = leafIds(parse("MIT OR Apache-2.0") as ExpressionNode);
    expect([...result.ids].sort()).toEqual(["Apache-2.0", "MIT"]);
    expect(result.exceptions).toEqual([]);
  });
});

describe("renderNotices — canonical marker honesty", () => {
  const model: CanonicalDependencies = {
    packages: [
      entry({
        purl: "pkg:npm/acme-pkg@1.0.0",
        name: "acme-pkg",
        version: "1.0.0",
        finding: exactFinding("MIT"),
        attribution: attribution({
          copyrightLines: ["Copyright (c) 2020 Acme Corp"],
          hasVerbatimText: true,
        }),
      }),
      entry({
        purl: "pkg:npm/bare-pkg@1.0.0",
        name: "bare-pkg",
        version: "1.0.0",
        finding: exactFinding("Apache-2.0"),
      }),
    ],
  };

  test("every canonical appendix entry carries the exact marker as its own line", () => {
    const output = renderNotices(model);
    const lines = output.split("\n");
    // Two referenced ids (Apache-2.0, MIT) → two canonical entries → two
    // standalone marker lines.
    expect(lines.filter((line) => line === MARKER).length).toBe(2);
  });

  test("a package with copyrightLines gets a per-package section instead of relying silently on the appendix", () => {
    const output = renderNotices(model);
    expect(output.includes("### acme-pkg@1.0.0")).toBe(true);
    expect(output.includes("- Copyright (c) 2020 Acme Corp")).toBe(true);
    // The attribution-less package gets NO section.
    expect(output.includes("### bare-pkg@1.0.0")).toBe(false);
  });
});

describe("renderNotices — per-package sections", () => {
  const model: CanonicalDependencies = {
    packages: [
      entry({
        purl: "pkg:npm/copyright-pkg@1.0.0",
        name: "copyright-pkg",
        version: "1.0.0",
        finding: exactFinding("MIT"),
        attribution: attribution({
          copyrightLines: ["Copyright (c) 2020 Pipe|Corp"],
          hasVerbatimText: true,
        }),
      }),
      entry({
        purl: "pkg:npm/author-pkg@1.0.0",
        name: "author-pkg",
        version: "1.0.0",
        finding: exactFinding("ISC"),
        attribution: attribution({ author: "Sam Solo" }),
      }),
      entry({
        purl: "pkg:npm/notice-pkg@2.0.0",
        name: "notice-pkg",
        version: "2.0.0",
        finding: exactFinding("Apache-2.0"),
        attribution: attribution({
          noticeTexts: ["Notice Product\nCopyright 2024 Notice Foundation"],
        }),
      }),
      // Template-only attribution (hasVerbatimText, but nothing extracted):
      // honest empty — no section.
      entry({
        purl: "pkg:npm/template-pkg@3.0.0",
        name: "template-pkg",
        version: "3.0.0",
        finding: exactFinding("Apache-2.0"),
        attribution: attribution({ hasVerbatimText: true }),
      }),
      // No attribution at all — no section.
      entry({
        purl: "pkg:npm/plain-pkg@4.0.0",
        name: "plain-pkg",
        version: "4.0.0",
        finding: exactFinding("MIT"),
      }),
    ],
  };

  test("only packages with copyright lines, NOTICE texts, author, or verbatim texts get sections", () => {
    const output = renderNotices(model);
    expect(output.includes("### author-pkg@1.0.0")).toBe(true);
    expect(output.includes("### copyright-pkg@1.0.0")).toBe(true);
    expect(output.includes("### notice-pkg@2.0.0")).toBe(true);
    expect(output.includes("### template-pkg@3.0.0")).toBe(false);
    expect(output.includes("### plain-pkg@4.0.0")).toBe(false);
  });

  test("sections are sorted by comparePackages", () => {
    const output = renderNotices(model);
    const author = output.indexOf("### author-pkg@1.0.0");
    const copyright = output.indexOf("### copyright-pkg@1.0.0");
    const notice = output.indexOf("### notice-pkg@2.0.0");
    expect(author).toBeLessThan(copyright);
    expect(copyright).toBeLessThan(notice);
  });

  test("copyright lines render as escaped bullet lines", () => {
    const output = renderNotices(model);
    expect(output.includes("- Copyright (c) 2020 Pipe\\|Corp")).toBe(true);
    expect(output.includes("Pipe|Corp")).toBe(false);
  });

  test("a package with NO copyright lines but an author renders 'Author: ' — never the word Copyright", () => {
    const output = renderNotices(model);
    const start = output.indexOf("### author-pkg@1.0.0");
    const end = output.indexOf("### ", start + 1);
    const section = output.slice(start, end);
    expect(section.includes("Author: Sam Solo")).toBe(true);
    expect(/copyright/i.test(section)).toBe(false);
  });

  test("NOTICE contents render inside a fenced block introduced by a 'NOTICE:' line", () => {
    const output = renderNotices(model);
    const start = output.indexOf("### notice-pkg@2.0.0");
    const end = output.indexOf("\n## ", start);
    const section = output.slice(start, end);
    expect(section.includes("NOTICE:")).toBe(true);
    const noticeAt = section.indexOf("NOTICE:");
    const fenceAt = section.indexOf("```", noticeAt);
    expect(fenceAt).toBeGreaterThan(noticeAt);
    expect(section.indexOf("Notice Product")).toBeGreaterThan(fenceAt);
  });
});

describe("renderNotices — injection-proof fencing", () => {
  const model: CanonicalDependencies = {
    packages: [
      entry({
        purl: "pkg:npm/fence-pkg@1.0.0",
        name: "fence-pkg",
        version: "1.0.0",
        finding: UNKNOWN_FINDING,
        attribution: attribution({
          hasVerbatimText: true,
          verbatimTexts: [
            "## Fake heading\nsome text\n`````\nafter the five-tick run",
          ],
        }),
      }),
    ],
  };

  test("a 5-backtick run renders inside a fence of at least 6 backticks", () => {
    const output = renderNotices(model);
    const openFence = output.split("\n").find((line) => /^`{3,}$/.test(line));
    expect(openFence).toBeDefined();
    expect((openFence as string).length).toBeGreaterThanOrEqual(6);
  });

  test("a crafted '## Fake heading' stays inside the fence — the document's own heading set is unchanged", () => {
    const output = renderNotices(model);
    const outside = headingsOutsideFences(output);
    expect(outside.includes("## Fake heading")).toBe(false);
    expect(outside).toEqual([
      "# Third-Party Notices",
      "## Package attributions",
      "### fence-pkg@1.0.0",
      "## Packages with unknown licenses",
      "## License texts",
    ]);
  });
});

describe("renderNotices — unknown-license packages", () => {
  test("a package with a null-expression finding and no claims appears flagged with no text", () => {
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:npm/mystery-pkg@1.0.0",
          name: "mystery-pkg",
          version: "1.0.0",
          finding: UNKNOWN_FINDING,
        }),
        entry({
          purl: "pkg:npm/known-pkg@1.0.0",
          name: "known-pkg",
          version: "1.0.0",
          finding: exactFinding("MIT"),
        }),
      ],
    };
    const output = renderNotices(model);
    expect(output.includes("## Packages with unknown licenses")).toBe(true);
    expect(
      output.includes(
        "- mystery-pkg@1.0.0 — unknown license, no text included",
      ),
    ).toBe(true);
    expect(output.includes("- known-pkg@")).toBe(false);
  });

  test("the unknown section is omitted entirely when every package has a known license", () => {
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:npm/known-pkg@1.0.0",
          name: "known-pkg",
          version: "1.0.0",
          finding: exactFinding("MIT"),
        }),
      ],
    };
    const output = renderNotices(model);
    expect(output.includes("## Packages with unknown licenses")).toBe(false);
  });
});

describe("renderNotices — WITH exceptions and unlisted ids (Test 6, A3)", () => {
  const model: CanonicalDependencies = {
    packages: [
      entry({
        purl: "pkg:npm/with-pkg@1.0.0",
        name: "with-pkg",
        version: "1.0.0",
        finding: exactFinding("GPL-2.0-only WITH Classpath-exception-2.0"),
      }),
      entry({
        purl: "pkg:npm/ref-pkg@1.0.0",
        name: "ref-pkg",
        version: "1.0.0",
        finding: exactFinding("LicenseRef-custom-thing"),
      }),
    ],
  };

  test("a WITH expression renders the license-part canonical text plus a flagged note naming the exception", () => {
    const output = renderNotices(model);
    expect(output.includes("### GPL-2.0-only")).toBe(true);
    expect(output.includes("GNU GENERAL PUBLIC LICENSE")).toBe(true);
    const lines = output.split("\n");
    expect(
      lines.some(
        (line) =>
          line.startsWith("Flagged: license exception") &&
          line.includes("Classpath-exception-2.0"),
      ),
    ).toBe(true);
  });

  test("an id absent from spdx-license-list yields a flagged 'no canonical text' note instead of a crash", () => {
    const output = renderNotices(model);
    expect(output.includes("### LicenseRef-custom-thing")).toBe(true);
    const lines = output.split("\n");
    expect(
      lines.some(
        (line) =>
          line.includes("no canonical text") &&
          line.includes("LicenseRef-custom-thing"),
      ),
    ).toBe(true);
  });
});

describe("renderNotices — imprecise label honesty (INV-04)", () => {
  const impreciseFinding: LicenseFinding = {
    expression: null,
    elected: null,
    source: "registry",
    confidence: "imprecise",
    impreciseFamily: "BSD",
  };

  test("an imprecise package shows the family + imprecise marker, never a fabricated id, and is NOT listed as unknown", () => {
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:pypi/jinja2@3.1.0",
          name: "jinja2",
          version: "3.1.0",
          finding: impreciseFinding,
          attribution: attribution({
            copyrightLines: ["Copyright (c) 2007 Pallets"],
            hasVerbatimText: true,
          }),
        }),
      ],
    };
    const output = renderNotices(model);
    // The per-package License line is honest: family + marker, never BSD-2-Clause.
    expect(output.includes("License: BSD (imprecise)")).toBe(true);
    expect(output.includes("BSD-2-Clause")).toBe(false);
    // Imprecise is present, NOT unknown — it must not appear in the unknown
    // section (and the section is omitted when nothing else is unknown).
    expect(output.includes("## Packages with unknown licenses")).toBe(false);
    expect(output.includes("jinja2@3.1.0 — unknown license")).toBe(false);
  });
});

describe("renderNotices — golden byte equality (04-04 Task 2, INV-03)", () => {
  test("evidence-fixture model matches the notices golden byte-for-byte", () => {
    // The evidence fixture, annotated with an empty clarify list so findings
    // exist — the appendix needs normalized expressions.
    const evidenceDoc = JSON.parse(
      readFileSync(
        join(import.meta.dir, "fixtures", "plugin-evidence.json"),
        "utf-8",
      ),
    ) as unknown;
    const model = mergeSboms([
      { sbom: evidenceDoc, targetIdentity: "libraries/evidence-target" },
    ]);
    const annotated = annotateFindings(model, []).model;
    const golden = readFileSync(
      join(import.meta.dir, "golden", "notices.md"),
      "utf-8",
    );
    expect(renderNotices(annotated)).toBe(golden);
  });
});

describe("renderNotices — determinism contract", () => {
  const model: CanonicalDependencies = {
    packages: [
      entry({
        purl: "pkg:npm/zzz-pkg@1.0.0",
        name: "zzz-pkg",
        version: "1.0.0",
        finding: exactFinding("MIT"),
        attribution: attribution({
          copyrightLines: ["Copyright (c) 2019 Zzz"],
          hasVerbatimText: true,
        }),
      }),
      entry({
        purl: "pkg:npm/aaa-pkg@1.0.0",
        name: "aaa-pkg",
        version: "1.0.0",
        finding: exactFinding("ISC"),
      }),
    ],
  };

  test("double render is byte-identical and defensively re-sorted", () => {
    const reversed: CanonicalDependencies = {
      packages: [...model.packages].reverse(),
    };
    const a = renderNotices(model);
    const b = renderNotices(reversed);
    expect(a).toBe(b);
    expect(renderNotices(model)).toBe(a);
  });

  test("no CR, exactly one trailing LF, dateless header", () => {
    const output = renderNotices(model);
    expect(output.includes("\r")).toBe(false);
    expect(output.endsWith("\n")).toBe(true);
    expect(output.endsWith("\n\n")).toBe(false);
    const lines = output.split("\n");
    expect(lines[0]).toBe("# Third-Party Notices");
    expect(lines[2]).toBe(
      "<!-- AUTO-GENERATED - do not edit. Regenerate with: task licenses:generate -->",
    );
    expect(/\b20\d\d\b.*generated/i.test(output)).toBe(false);
  });
});
