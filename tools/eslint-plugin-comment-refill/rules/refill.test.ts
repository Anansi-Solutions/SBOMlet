import { describe, it } from "bun:test";
import { Linter, RuleTester } from "eslint";

import { refillRule } from "./refill.mjs";

RuleTester.describe = describe;
RuleTester.it = it;

const ruleTester = new RuleTester({
  languageOptions: { ecmaVersion: 2022, sourceType: "module" },
});

/**
 * Fixture names prefixed `probe-` are the counterexamples that sank
 * eslint-plugin-comment-length's `compact` mode during evaluation: it has no
 * list-marker awareness, so it merges markdown bullets into prose. Each one
 * here is asserted to keep its bullets, or its colon-then-bullets shape,
 * intact.
 *
 * Every fixture that the rule actually rewrites also has a companion `valid`
 * case (named "... (idempotent on its own output)") that feeds the rule's own
 * output back in and asserts zero problems: the fixer is idempotent.
 */
ruleTester.run("refill", refillRule, {
  valid: [
    {
      name: "code-span-glued-to-trailing-punctuation (idempotent on its own output)",
      code: "// The cache dir (e.g. `.sbomlet.cache/`) need not exist on the first generate, and writeFileSync\n// does not create parents.\n",
      options: [{ maxLength: 100 }],
    },
    {
      name: "plain-prose-refill (idempotent on its own output)",
      code: "// This is one. This is two. This is\n// three.\n",
      options: [{ maxLength: 40 }],
    },
    {
      name: "overlong-wrap (idempotent on its own output)",
      code: "// This is a single comment line that is\n// much too long to fit on one line.\n",
      options: [{ maxLength: 40 }],
    },
    {
      name: "probe-bullet-list-denylist (idempotent on its own output)",
      code: "/**\n * - leaf \u2192 denied iff the leaf satisfies at least one deny predicate and none\n *   of the allow predicates override it.\n * - branch \u2192 denied iff every child is denied.\n */\n",
      options: [{ maxLength: 78 }],
    },
    {
      name: "probe-colon-then-bullets-terraform",
      code: "// Two inputs, two authorities:\n// - Providers come from the root module's required_providers block.\n// - Consumers come from every module block's source attribute.\n",
      options: [{ maxLength: 78 }],
    },
    {
      name: "probe-aligned-arrow-table-untouched",
      code: "/**\n * leaf       \u2192 denied iff the leaf satisfies a predicate\n * branch     \u2192 denied iff every child is denied\n */\n",
      options: [{ maxLength: 60 }],
    },
    {
      name: "probe-dependencies-merge-colon-bullets",
      code: "// Two dependency sources feed the merge:\n// - direct dependencies declared in the manifest file itself.\n// - transitive dependencies resolved from the lockfile.\n",
      options: [{ maxLength: 78 }],
    },
    {
      name: "numbered-list-wraps-with-hang (idempotent on its own output)",
      code: "// 1. First item that needs to wrap onto a\n//    second continuation line here.\n// 2. Second item that is short.\n",
      options: [{ maxLength: 45 }],
    },
    {
      name: "tag-block-untouched-after-description-reflows (idempotent on its own output)",
      code: "/**\n * Loads the file and returns its parsed contents\n * from disk.\n * @param path The file path to read from disk right here.\n * @returns The parsed contents of the file.\n */\n",
      options: [{ maxLength: 50 }],
    },
    {
      name: "fence-block-untouched",
      code: "/**\n * Example:\n * ```\n * const   x   =   1;\n * ```\n */\n",
      options: [{ maxLength: 40 }],
    },
    {
      name: "unbalanced-backtick-no-merge",
      code: "// A short line.\n// This has an unmatched ` tick.\n// Another line.\n",
      options: [{ maxLength: 100 }],
    },
    {
      name: "url-overlong-accepted (idempotent on its own output)",
      code: "// See\n// https://example.com/a/very/long/path/that/will/not/fit/on/one/line\n// for more.\n",
      options: [{ maxLength: 40 }],
    },
    {
      name: "line-run-refill (idempotent on its own output)",
      code: "// alpha beta gamma delta epsilon zeta eta theta\n// iota kappa\n",
      options: [{ maxLength: 50 }],
    },
    {
      name: "trailing-comment-untouched",
      code: "const x = 1; // this trailing comment is quite long and would overflow badly\n",
      options: [{ maxLength: 20 }],
    },
    {
      name: "blank-line-paragraphs-preserved",
      code: "/**\n * First paragraph.\n *\n * Second paragraph.\n */\n",
      options: [{ maxLength: 60 }],
    },
    {
      name: "bullet-continuation-refilled-within-item (idempotent on its own output)",
      code: "// - leaf: denied when the leaf itself satisfies at least\n//   one deny predicate.\n",
      options: [{ maxLength: 60 }],
    },
    {
      name: "single-line-block-fits-stays-single-line",
      code: "/** Ceiling for comment lines as a share of total lines. */\n",
      options: [{ maxLength: 60 }],
    },
    {
      name: "single-line-block-promoted-to-multi-line (idempotent on its own output)",
      code: "/**\n * Ceiling for comment lines as a share\n * of non-blank lines in src.\n */\n",
      options: [{ maxLength: 40 }],
    },
    {
      name: "code-looking-line-excluded",
      code: "// Example:\n// const result = doThing();\n// Above returns a promise.\n",
      options: [{ maxLength: 100 }],
    },
    {
      name: "semantic-comment-own-group",
      code: "// Plain prose line here.\n// TODO: fix this rough edge soon.\n",
      options: [{ maxLength: 100 }],
    },
  ],
  invalid: [
    {
      name: "plain-prose-refill",
      code: "// This is one.\n// This is two.\n// This is three.\n",
      options: [{ maxLength: 40 }],
      output: "// This is one. This is two. This is\n// three.\n",
      errors: 1,
    },
    {
      name: "overlong-wrap",
      code: "// This is a single comment line that is much too long to fit on one line.\n",
      options: [{ maxLength: 40 }],
      output:
        "// This is a single comment line that is\n// much too long to fit on one line.\n",
      errors: 1,
    },
    {
      name: "probe-bullet-list-denylist",
      code: "/**\n * - leaf \u2192 denied iff the leaf satisfies at least one deny predicate and\n *   none of the allow predicates override it.\n * - branch \u2192 denied iff every child is denied.\n */\n",
      options: [{ maxLength: 78 }],
      output:
        "/**\n * - leaf \u2192 denied iff the leaf satisfies at least one deny predicate and none\n *   of the allow predicates override it.\n * - branch \u2192 denied iff every child is denied.\n */\n",
      errors: 1,
    },
    {
      name: "numbered-list-wraps-with-hang",
      code: "// 1. First item that needs to wrap onto a second continuation line here.\n// 2. Second item that is short.\n",
      options: [{ maxLength: 45 }],
      output:
        "// 1. First item that needs to wrap onto a\n//    second continuation line here.\n// 2. Second item that is short.\n",
      errors: 1,
    },
    {
      name: "tag-block-untouched-after-description-reflows",
      code: "/**\n * Loads the file and returns its parsed contents from disk.\n * @param path The file path to read from disk right here.\n * @returns The parsed contents of the file.\n */\n",
      options: [{ maxLength: 50 }],
      output:
        "/**\n * Loads the file and returns its parsed contents\n * from disk.\n * @param path The file path to read from disk right here.\n * @returns The parsed contents of the file.\n */\n",
      errors: 1,
    },
    {
      name: "url-overlong-accepted",
      code: "// See https://example.com/a/very/long/path/that/will/not/fit/on/one/line for more.\n",
      options: [{ maxLength: 40 }],
      output:
        "// See\n// https://example.com/a/very/long/path/that/will/not/fit/on/one/line\n// for more.\n",
      errors: 1,
    },
    {
      name: "line-run-refill",
      code: "// alpha\n// beta\n// gamma delta epsilon zeta eta theta iota kappa\n",
      options: [{ maxLength: 50 }],
      output:
        "// alpha beta gamma delta epsilon zeta eta theta\n// iota kappa\n",
      errors: 1,
    },
    {
      name: "bullet-continuation-refilled-within-item",
      code: "// - leaf: denied when the leaf itself satisfies at least\n//   one\n//   deny\n//   predicate.\n",
      options: [{ maxLength: 60 }],
      output:
        "// - leaf: denied when the leaf itself satisfies at least\n//   one deny predicate.\n",
      errors: 1,
    },
    {
      name: "single-line-block-promoted-to-multi-line",
      code: "/** Ceiling for comment lines as a share of non-blank lines in src. */\n",
      options: [{ maxLength: 40 }],
      output:
        "/**\n * Ceiling for comment lines as a share\n * of non-blank lines in src.\n */\n",
      errors: 1,
    },
    {
      // Regression: a code span glued to trailing punctuation, with no
      // space in between, used to gain a space when a wrap merged its
      // line with a neighbor. The span and its punctuation must stay glued.
      name: "code-span-glued-to-trailing-punctuation",
      code: "// The cache dir (e.g. `.sbomlet.cache/`) need not exist on the first\n// generate, and writeFileSync does not create parents.\n",
      options: [{ maxLength: 100 }],
      output:
        "// The cache dir (e.g. `.sbomlet.cache/`) need not exist on the first generate, and writeFileSync\n// does not create parents.\n",
      errors: 1,
    },
  ],
});

describe("comment-refill/refill option schema", () => {
  it("rejects configuration with no options object at all", () => {
    const linter = new Linter();
    let threw = false;
    try {
      linter.verify("// a\n", {
        languageOptions: { ecmaVersion: 2022, sourceType: "module" },
        plugins: { refill: { rules: { refill: refillRule } } },
        rules: { "refill/refill": "error" },
      });
    } catch {
      threw = true;
    }
    if (!threw) {
      throw new Error(
        "expected a configuration error when maxLength is omitted entirely",
      );
    }
  });

  it("rejects configuration with an options object missing maxLength", () => {
    const linter = new Linter();
    let threw = false;
    try {
      linter.verify("// a\n", {
        languageOptions: { ecmaVersion: 2022, sourceType: "module" },
        plugins: { refill: { rules: { refill: refillRule } } },
        rules: { "refill/refill": ["error", {}] },
      });
    } catch {
      threw = true;
    }
    if (!threw) {
      throw new Error(
        "expected a configuration error when maxLength is missing from the options object",
      );
    }
  });

  it("accepts configuration with maxLength provided", () => {
    const linter = new Linter();
    const messages = linter.verify("// a\n", {
      languageOptions: { ecmaVersion: 2022, sourceType: "module" },
      plugins: { refill: { rules: { refill: refillRule } } },
      rules: { "refill/refill": ["error", { maxLength: 80 }] },
    });
    const fatal = messages.find((m) => m.fatal);
    if (fatal) {
      throw new Error(`did not expect a fatal error, got: ${fatal.message}`);
    }
  });
});

describe("comment-refill/refill leaves structural tool directives alone", () => {
  it("never rewrites an eslint-disable-next-line comment, even when it overflows maxLength", () => {
    const linter = new Linter();
    const code =
      "function decodeSpdxPath(path) {\n" +
      "  let decoded;\n" +
      "  try {\n" +
      "    decoded = decodeURIComponent(path);\n" +
      "  } catch {\n" +
      "    return undefined;\n" +
      "  }\n" +
      "\n" +
      "  // eslint-disable-next-line no-control-regex -- deliberate control-character class: reject, never resolve\n" +
      "  if (/[\u0000-\u001f\u007f-\u009f]/.test(decoded)) return undefined;\n" +
      "  return decoded.trim();\n" +
      "}\n";
    const configs = {
      languageOptions: { ecmaVersion: 2022, sourceType: "module" },
      plugins: { refill: { rules: { refill: refillRule } } },
      rules: {
        "refill/refill": ["error", { maxLength: 100 }],
        "no-control-regex": "error",
      },
    };
    const out = linter.verifyAndFix(code, configs, "test.js");
    if (out.output !== code) {
      throw new Error(
        `expected the eslint-disable comment and the code around it to be byte-identical, got:\n${out.output}`,
      );
    }
    if (out.messages.length !== 0) {
      throw new Error(
        `expected zero remaining messages, got: ${JSON.stringify(out.messages)}`,
      );
    }
  });
});
