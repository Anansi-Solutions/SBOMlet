import { join } from "node:path";

import { describe, expect, test } from "bun:test";

import {
  MAX_COMMENT_LINE_RATIO,
  MAX_COMMENT_WORD_RATIO,
  measureComments,
} from "../scripts/comment-metrics";

const SRC_DIR = join(import.meta.dir, "..", "src");

describe.skip("comment density budget", () => {
  const total = measureComments(SRC_DIR);

  test("comment lines stay under the line budget", () => {
    expect(total.commentLines).toBeLessThanOrEqual(
      MAX_COMMENT_LINE_RATIO * total.totalLines,
    );
  });

  test("comment words stay under the word budget", () => {
    expect(total.commentWords).toBeLessThanOrEqual(
      MAX_COMMENT_WORD_RATIO * total.totalWords,
    );
  });
});
