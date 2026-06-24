/**
 * Behavior lock for the pure copyright-line extraction heuristic. The five
 * blocks below drive the contract: concrete lines extracted, template
 * placeholders and prose rejected, dedup + cap, CRLF tolerance. This module
 * extracts existing claims only — fabricating a copyright line from an author
 * string is forbidden.
 */

import { describe, expect, test } from "bun:test";

import { extractCopyrightLines } from "../src/extract/copyright";

describe("extractCopyrightLines — concrete lines", () => {
  test("an MIT text with a concrete (c) line yields exactly that trimmed line", () => {
    const text = [
      "MIT License",
      "",
      "Copyright (c) 2015 Jane Doe",
      "",
      "Permission is hereby granted, free of charge, to any person obtaining",
    ].join("\n");

    expect(extractCopyrightLines(text)).toEqual([
      "Copyright (c) 2015 Jane Doe",
    ]);
  });

  test("a © line without '(c)' or the word 'copyright' matches via the year/© test", () => {
    // The © sign IS the copyright claim marker — legally equivalent to the
    // word; the concreteness gate is satisfied by the year and the sign.
    const text = "Some Library\n© 2020 Acme Corp\nAll rights reserved.\n";

    expect(extractCopyrightLines(text)).toEqual(["© 2020 Acme Corp"]);
  });
});

describe("extractCopyrightLines — template filtering", () => {
  test("the bare Apache-2.0 template yields ZERO lines (honest template-only case)", () => {
    // Rendering a template-only file empty is honest; fabricating a line is a
    // legal claim we cannot make.
    const text = [
      "                                 Apache License",
      "                           Version 2.0, January 2004",
      "",
      "   Copyright [yyyy] [name of copyright owner]",
      "",
      '   Licensed under the Apache License, Version 2.0 (the "License");',
    ].join("\n");

    expect(extractCopyrightLines(text)).toEqual([]);
  });

  test("MIT template placeholders <year> <copyright holders> yield ZERO lines", () => {
    const text = "MIT License\n\nCopyright (c) <year> <copyright holders>\n";

    expect(extractCopyrightLines(text)).toEqual([]);
  });

  test("the GitHub/choosealicense MIT template 'Copyright (c) [year] [fullname]' yields ZERO lines", () => {
    // The most widely distributed MIT template: the line passes the claim
    // marker and the concreteness gate ("(c)"), so without the placeholder
    // filter it would be published as a fabricated concrete copyright claim.
    const text = "MIT License\n\nCopyright (c) [year] [fullname]\n";

    expect(extractCopyrightLines(text)).toEqual([]);
  });

  test("bracket and angle name variants — [name of author], <name>, <name of author> — yield ZERO lines", () => {
    const text = [
      "Copyright (c) 2004 [name of author]",
      "Copyright (c) <year> <name>",
      "Copyright (c) 1998 <name of author>",
    ].join("\n");

    expect(extractCopyrightLines(text)).toEqual([]);
  });

  test("a real attribution with an email starting in 'name' is NOT filtered", () => {
    const text = "Copyright (c) 2015 Jane Doe <nameless@example.com>\n";

    expect(extractCopyrightLines(text)).toEqual([
      "Copyright (c) 2015 Jane Doe <nameless@example.com>",
    ]);
  });
});

describe("extractCopyrightLines — prose filtering", () => {
  test("a 'copyright' line with no year/©/(c) marker is not extracted", () => {
    const text = [
      "This work is protected under the copyright law of the United States.",
      "Refer to your local copyright office for details.",
    ].join("\n");

    expect(extractCopyrightLines(text)).toEqual([]);
  });
});

describe("extractCopyrightLines — dedup and cap", () => {
  test("duplicate copyright lines collapse to one", () => {
    const text = [
      "Copyright (c) 2015 Jane Doe",
      "some body text",
      "Copyright (c) 2015 Jane Doe",
    ].join("\n");

    expect(extractCopyrightLines(text)).toEqual([
      "Copyright (c) 2015 Jane Doe",
    ]);
  });

  test("a pathological file with 50 distinct copyright lines caps at 20", () => {
    const lines: string[] = [];
    for (let i = 0; i < 50; i++) {
      lines.push(`Copyright (c) ${1970 + i} Holder ${i}`);
    }
    const result = extractCopyrightLines(lines.join("\n"));

    expect(result.length).toBe(20);
    expect(result[0]).toBe("Copyright (c) 1970 Holder 0");
    expect(result[19]).toBe("Copyright (c) 1989 Holder 19");
  });

  test("duplicates never consume the cap: 30 repeats of one line followed by 5 distinct holders yield all 6", () => {
    // The concatenated/bundled-license shape: one per-section header line
    // repeated dozens of times before the distinct holder list. Without
    // dedup-while-collecting the duplicates fill the 20-line cap and the
    // distinct lines are dropped.
    const lines: string[] = [];
    for (let i = 0; i < 30; i++) {
      lines.push("Copyright (c) 2015 Repeated Header Corp");
    }
    for (let i = 0; i < 5; i++) {
      lines.push(`Copyright (c) ${2000 + i} Distinct Holder ${i}`);
    }
    const result = extractCopyrightLines(lines.join("\n"));

    expect(result.length).toBe(6);
    expect(result[0]).toBe("Copyright (c) 2015 Repeated Header Corp");
    expect(result).toContain("Copyright (c) 2000 Distinct Holder 0");
    expect(result).toContain("Copyright (c) 2004 Distinct Holder 4");
  });
});

describe("extractCopyrightLines — CRLF tolerance", () => {
  test("the same text with \\r\\n line ends yields identical output to the \\n version", () => {
    const body = [
      "MIT License",
      "Copyright (c) 2018 Example Org",
      "Copyright (c) 2019 Another Org",
      "Permission is hereby granted...",
    ];

    expect(extractCopyrightLines(body.join("\r\n"))).toEqual(
      extractCopyrightLines(body.join("\n")),
    );
    expect(extractCopyrightLines(body.join("\r\n"))).toEqual([
      "Copyright (c) 2018 Example Org",
      "Copyright (c) 2019 Another Org",
    ]);
  });
});
