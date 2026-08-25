import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import parse from "spdx-expression-parse";

import { mergeSboms } from "../src/merge/merge";
import {
  asRawLicense,
  type CanonicalDependencies,
  type LicenseFinding,
  type PackageAttribution,
  type PackageEntry,
  asTargetIdentity,
} from "../src/model/dependencies";
import { canonicalizeExpression, leafIds, type ExpressionNode } from "../src/normalize/expression";
import { annotateFindings } from "../src/normalize/normalize";
import { renderMarkdown } from "../src/render/markdown";
import { renderNotices } from "../src/render/notices";
import { canon, asPurl, asDependencyName, asDependencyVersion } from "./brandTestSupport";

// ---------------------------------------------------------------------------
// Notices renderer. Models are hand-built: the renderer is tested against the
// model contract, independent of mergeSboms/annotateFindings.
// ---------------------------------------------------------------------------

const MARKER = "(canonical SPDX text — package-specific copyright not located)";

/** Hand-built PackageEntry with sensible defaults for contract tests. */
function entry(
  partial: Partial<PackageEntry> & Pick<PackageEntry, "name" | "version" | "purl">,
): PackageEntry {
  return {
    occurrences: [{ target: asTargetIdentity("apps/a"), isDevDependency: false }],
    licenseClaims: [],
    scope: "app",
    ...partial,
  };
}

function exactFinding(expression: string): LicenseFinding {
  const canonical = canon(expression);

  return {
    expression: canonical,
    elected: canonical,
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
      if (openFence === null) {
        openFence = line;
      } else if (line === openFence) {
        openFence = null;
      }

      continue;
    }

    if (openFence === null && line.startsWith("#")) {
      result.push(line);
    }
  }

  return result;
}

describe("renderNotices — appendix dedup and expression decomposition", () => {
  const model: CanonicalDependencies = {
    packages: [
      entry({
        purl: asPurl("pkg:npm/a-mit@1.0.0"),
        name: asDependencyName("a-mit"),
        version: asDependencyVersion("1.0.0"),
        finding: exactFinding("MIT"),
      }),
      entry({
        purl: asPurl("pkg:npm/b-mit@1.0.0"),
        name: asDependencyName("b-mit"),
        version: asDependencyVersion("1.0.0"),
        finding: exactFinding("MIT"),
      }),
      entry({
        purl: asPurl("pkg:npm/c-dual@1.0.0"),
        name: asDependencyName("c-dual"),
        version: asDependencyVersion("1.0.0"),
        finding: exactFinding("MIT OR Apache-2.0"),
      }),
    ],
  };

  test("two MIT packages produce exactly ONE '### MIT' appendix entry with the canonical text", () => {
    const output = renderNotices(model);
    const lines = output.split("\n");

    expect(lines.filter((line) => line === "### MIT").length).toBe(1);
    // Distinctive canonical-MIT substring from spdx-license-list/full.
    expect(output.includes("Permission is hereby granted, free of charge")).toBe(true);
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
        purl: asPurl("pkg:npm/acme-pkg@1.0.0"),
        name: asDependencyName("acme-pkg"),
        version: asDependencyVersion("1.0.0"),
        finding: exactFinding("MIT"),
        attribution: attribution({
          copyrightLines: ["Copyright (c) 2020 Acme Corp"],
          hasVerbatimText: true,
        }),
      }),
      entry({
        purl: asPurl("pkg:npm/bare-pkg@1.0.0"),
        name: asDependencyName("bare-pkg"),
        version: asDependencyVersion("1.0.0"),
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
        purl: asPurl("pkg:npm/copyright-pkg@1.0.0"),
        name: asDependencyName("copyright-pkg"),
        version: asDependencyVersion("1.0.0"),
        finding: exactFinding("MIT"),
        attribution: attribution({
          copyrightLines: ["Copyright (c) 2020 Pipe|Corp"],
          hasVerbatimText: true,
        }),
      }),
      entry({
        purl: asPurl("pkg:npm/author-pkg@1.0.0"),
        name: asDependencyName("author-pkg"),
        version: asDependencyVersion("1.0.0"),
        finding: exactFinding("ISC"),
        attribution: attribution({ author: "Sam Solo" }),
      }),
      entry({
        purl: asPurl("pkg:npm/notice-pkg@2.0.0"),
        name: asDependencyName("notice-pkg"),
        version: asDependencyVersion("2.0.0"),
        finding: exactFinding("Apache-2.0"),
        attribution: attribution({
          noticeTexts: ["Notice Product\nCopyright 2024 Notice Foundation"],
        }),
      }),
      // Template-only attribution (hasVerbatimText, but nothing extracted):
      // honest empty — no section.
      entry({
        purl: asPurl("pkg:npm/template-pkg@3.0.0"),
        name: asDependencyName("template-pkg"),
        version: asDependencyVersion("3.0.0"),
        finding: exactFinding("Apache-2.0"),
        attribution: attribution({ hasVerbatimText: true }),
      }),
      // No attribution at all — no section.
      entry({
        purl: asPurl("pkg:npm/plain-pkg@4.0.0"),
        name: asDependencyName("plain-pkg"),
        version: asDependencyVersion("4.0.0"),
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
        purl: asPurl("pkg:npm/fence-pkg@1.0.0"),
        name: asDependencyName("fence-pkg"),
        version: asDependencyVersion("1.0.0"),
        finding: UNKNOWN_FINDING,
        attribution: attribution({
          hasVerbatimText: true,
          verbatimTexts: ["## Fake heading\nsome text\n`````\nafter the five-tick run"],
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
          purl: asPurl("pkg:npm/mystery-pkg@1.0.0"),
          name: asDependencyName("mystery-pkg"),
          version: asDependencyVersion("1.0.0"),
          finding: UNKNOWN_FINDING,
        }),
        entry({
          purl: asPurl("pkg:npm/known-pkg@1.0.0"),
          name: asDependencyName("known-pkg"),
          version: asDependencyVersion("1.0.0"),
          finding: exactFinding("MIT"),
        }),
      ],
    };
    const output = renderNotices(model);

    expect(output.includes("## Packages with unknown licenses")).toBe(true);
    expect(output.includes("- mystery-pkg@1.0.0 — unknown license, no text included")).toBe(true);
    expect(output.includes("- known-pkg@")).toBe(false);
  });

  test("the unknown section is omitted entirely when every package has a known license", () => {
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: asPurl("pkg:npm/known-pkg@1.0.0"),
          name: asDependencyName("known-pkg"),
          version: asDependencyVersion("1.0.0"),
          finding: exactFinding("MIT"),
        }),
      ],
    };
    const output = renderNotices(model);

    expect(output.includes("## Packages with unknown licenses")).toBe(false);
  });
});

describe("renderNotices/renderMarkdown agreement — LicenseRef-only unknown lane", () => {
  test("a LicenseRef-only package rows in NOTICES' unknown section and counts under LICENSES' Unknown license line", () => {
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: asPurl("pkg:npm/ref-only-pkg@1.0.0"),
          name: asDependencyName("ref-only-pkg"),
          version: asDependencyVersion("1.0.0"),
          finding: exactFinding("LicenseRef-proprietary-eula"),
        }),
      ],
    };
    const notices = renderNotices(model);
    const licenses = renderMarkdown(model);

    expect(notices.includes("## Packages with unknown licenses")).toBe(true);
    expect(notices.includes("- ref-only-pkg@1.0.0 — unknown license, no text included")).toBe(true);
    expect(licenses.includes("- Unknown license: 1")).toBe(true);
  });
});

describe("renderNotices — WITH exceptions and unlisted ids (Test 6, A3)", () => {
  const model: CanonicalDependencies = {
    packages: [
      entry({
        purl: asPurl("pkg:npm/with-pkg@1.0.0"),
        name: asDependencyName("with-pkg"),
        version: asDependencyVersion("1.0.0"),
        finding: exactFinding("GPL-2.0-only WITH Classpath-exception-2.0"),
      }),
      entry({
        purl: asPurl("pkg:npm/ref-pkg@1.0.0"),
        name: asDependencyName("ref-pkg"),
        version: asDependencyVersion("1.0.0"),
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
          line.startsWith("Flagged: license exception") && line.includes("Classpath-exception-2.0"),
      ),
    ).toBe(true);
  });

  test("an id absent from spdx-license-list yields a flagged 'no canonical text' note instead of a crash", () => {
    const output = renderNotices(model);

    expect(output.includes("### LicenseRef-custom-thing")).toBe(true);
    const lines = output.split("\n");

    expect(
      lines.some(
        (line) => line.includes("no canonical text") && line.includes("LicenseRef-custom-thing"),
      ),
    ).toBe(true);
  });
});

describe("renderNotices — imprecise label honesty", () => {
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
          purl: asPurl("pkg:pypi/jinja2@3.1.0"),
          name: asDependencyName("jinja2"),
          version: asDependencyVersion("3.1.0"),
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

describe("renderNotices — canonical license display", () => {
  const NOISY_EXPRESSION = "(MIT OR Apache-2.0) AND (Apache-2.0 AND MIT)";
  const CANONICAL_EXPRESSION = canonicalizeExpression(asRawLicense(NOISY_EXPRESSION));

  test("a noisy declared claim's normalized expression renders canonical in the per-package License line", () => {
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: asPurl("pkg:npm/noisy-pkg@1.0.0"),
          name: asDependencyName("noisy-pkg"),
          version: asDependencyVersion("1.0.0"),
          finding: exactFinding(NOISY_EXPRESSION),
          attribution: attribution({
            copyrightLines: ["Copyright (c) 2020 Someone"],
          }),
        }),
      ],
    };
    const output = renderNotices(model);

    expect(output.includes(`License: ${CANONICAL_EXPRESSION}`)).toBe(true);
    expect(output.includes(`License: ${NOISY_EXPRESSION}`)).toBe(false);
  });

  // An unparseable claim must round-trip verbatim - canonicalization passes it through.
  const UNPARSEABLE_EXPRESSION = "not a real spdx expression !!";

  test("an unparseable expression and an imprecise family token pass through the License line unchanged", () => {
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: asPurl("pkg:npm/unparseable-pkg@1.0.0"),
          name: asDependencyName("unparseable-pkg"),
          version: asDependencyVersion("1.0.0"),
          finding: {
            expression: canon(UNPARSEABLE_EXPRESSION),
            elected: null,
            source: "generator",
            confidence: "exact",
          },
          attribution: attribution({ copyrightLines: ["Copyright (c) 2020 Someone"] }),
        }),
      ],
    };
    const output = renderNotices(model);

    expect(output.includes(`License: ${UNPARSEABLE_EXPRESSION}`)).toBe(true);
  });
});

describe("renderNotices — golden byte equality", () => {
  test("evidence-fixture model matches the notices golden byte-for-byte", () => {
    // The evidence fixture, annotated with an empty clarify list so findings
    // exist — the appendix needs normalized expressions.
    const evidenceDoc = JSON.parse(
      readFileSync(join(import.meta.dir, "fixtures", "plugin-evidence.json"), "utf-8"),
    ) as unknown;
    const model = mergeSboms([
      { sbom: evidenceDoc, targetIdentity: asTargetIdentity("libraries/evidence-target") },
    ]);
    const annotated = annotateFindings(model, []).model;
    const golden = readFileSync(join(import.meta.dir, "golden", "notices.md"), "utf-8");

    expect(renderNotices(annotated)).toBe(golden);
  });
});

describe("renderNotices — determinism contract", () => {
  const model: CanonicalDependencies = {
    packages: [
      entry({
        purl: asPurl("pkg:npm/zzz-pkg@1.0.0"),
        name: asDependencyName("zzz-pkg"),
        version: asDependencyVersion("1.0.0"),
        finding: exactFinding("MIT"),
        attribution: attribution({
          copyrightLines: ["Copyright (c) 2019 Zzz"],
          hasVerbatimText: true,
        }),
      }),
      entry({
        purl: asPurl("pkg:npm/aaa-pkg@1.0.0"),
        name: asDependencyName("aaa-pkg"),
        version: asDependencyVersion("1.0.0"),
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
    expect(lines[2]).toBe("<!-- AUTO-GENERATED - do not edit. Regenerate with: task generate -->");
    expect(/\b20\d\d\b.*generated/i.test(output)).toBe(false);
  });
});
