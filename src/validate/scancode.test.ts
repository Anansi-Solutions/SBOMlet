import { describe, expect, test } from "bun:test";

import { scancodeFilesOf } from "./scancode";

describe("scancodeFilesOf", () => {
  test("a non-array files value is no entries", () => {
    expect(scancodeFilesOf({ path: "pkg/LICENSE" })).toEqual([]);
  });

  test("a non-object entry is skipped and its neighbors are kept", () => {
    expect(scancodeFilesOf([null, 5, "pkg/LICENSE", { path: "pkg/LICENSE" }])).toEqual([
      { path: "pkg/LICENSE" },
    ]);
  });

  test("a numeric path is absent", () => {
    const [file] = scancodeFilesOf([{ path: 7 }]);

    expect(file?.path).toBeUndefined();
  });

  test("a null or empty expression is absent", () => {
    const files = scancodeFilesOf([
      { path: "pkg/LICENSE", detected_license_expression_spdx: null },
      { path: "pkg/LICENSE", detected_license_expression_spdx: "" },
    ]);

    expect(files.map((file) => file.detected_license_expression_spdx)).toEqual([
      undefined,
      undefined,
    ]);
  });

  test("scan_errors keeps an array as is and drops a non-array", () => {
    const files = scancodeFilesOf([
      { scan_errors: [] },
      { scan_errors: ["ERROR: Processing interrupted"] },
      { scan_errors: "ERROR: Processing interrupted" },
    ]);

    expect(files.map((file) => file.scan_errors)).toEqual([
      [],
      ["ERROR: Processing interrupted"],
      undefined,
    ]);
  });

  test("a copyrights entry without a non-empty string copyright is skipped", () => {
    const [file] = scancodeFilesOf([
      {
        copyrights: [
          { copyright: 5 },
          { copyright: "" },
          null,
          { copyright: "Copyright (c) 2020 Example Author" },
        ],
      },
    ]);

    expect(file?.copyrights).toEqual(["Copyright (c) 2020 Example Author"]);
  });

  test("a non-array copyrights is absent", () => {
    const [file] = scancodeFilesOf([{ copyrights: "Copyright (c) 2020 Example Author" }]);

    expect(file?.copyrights).toBeUndefined();
  });
});
