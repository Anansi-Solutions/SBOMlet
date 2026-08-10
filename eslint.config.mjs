import js from "@eslint/js";
import tseslint from "typescript-eslint";
import importX from "eslint-plugin-import-x";
import tsdoc from "eslint-plugin-tsdoc";
import commentLength from "eslint-plugin-comment-length";
import writeGoodComments from "eslint-plugin-write-good-comments-2";
import noCommentSlop from "eslint-plugin-no-comment-slop";
import eslintPluginPrettierRecommended from "eslint-plugin-prettier/recommended";
import commentRefill from "./tools/eslint-plugin-comment-refill/index.mjs";

/**
 * Vocabulary banned from src/ comments: process/workflow shorthand that means
 * nothing to a developer reading the code. Each pattern is a form with no
 * legitimate reading in a comment here; anything it flags gets rewritten in
 * plain words (docs/contributing.md, quality gates).
 */
const bannedCommentTokens = [
  { pattern: /\brelock/i, label: '"relock"' },
  { pattern: /\bred-first\b/i, label: '"red-first"' },
  { pattern: /\bwave \d/i, label: '"wave N"' },
  { pattern: /\bD-\d\d\b/, label: '"D-##"' },
  { pattern: /\bT-\d\d\b/, label: '"T-##"' },
  { pattern: /\bSC-\d\b/, label: '"SC-#"' },
  { pattern: /\badversarial\b/i, label: '"adversarial"' },
  { pattern: /\bplan-checker\b/i, label: '"plan-checker"' },
  { pattern: /\bthe locked\b/i, label: '"the locked"' },
  { pattern: /\bgsd\b/i, label: '"gsd"' },
  { pattern: /\bhonest caveat\b/i, label: '"honest caveat"' },
  { pattern: /\breview rounds?\b/i, label: '"review round"' },
];

/** Error on banned vocabulary anywhere in a comment (line, block, or jsdoc). */
const noCommentJargon = {
  meta: {
    type: "problem",
    docs: {
      description: "ban process shorthand from comments",
    },
    schema: [],
    messages: {
      jargon:
        "comment contains process shorthand {{label}} — rewrite it in plain " +
        "words a reader of this codebase knows",
    },
  },
  create(context) {
    return {
      Program() {
        for (const comment of context.sourceCode.getAllComments()) {
          for (const { pattern, label } of bannedCommentTokens) {
            if (pattern.test(comment.value)) {
              context.report({
                loc: comment.loc,
                messageId: "jargon",
                data: { label },
              });
            }
          }
        }
      },
    };
  },
};

export default tseslint.config(
  {
    // Goldens and fixtures are contract bytes — lint must never see them.
    ignores: [".cache/", "test/golden/", "test/fixtures/", "node_modules/"],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.ts"],
    plugins: { "import-x": importX },
    rules: {
      "@typescript-eslint/explicit-function-return-type": "error",
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
      "import-x/no-duplicates": ["error", { "prefer-inline": true }],
      "import-x/order": [
        "error",
        {
          groups: [
            "builtin",
            "external",
            "internal",
            "parent",
            "sibling",
            "index",
            "object",
            "type",
          ],
        },
      ],
      "max-depth": ["error", 3],
      complexity: ["error", 15],
    },
  },
  {
    // Shipped-source comments carry the strictest vocabulary bar; tests and
    // config narrate their own mechanics and are not checked.
    files: ["src/**/*.ts"],
    plugins: {
      sbomlet: { rules: { "no-comment-jargon": noCommentJargon } },
      tsdoc,
      "comment-length": commentLength,
      "comment-refill": commentRefill,
      "write-good-comments": writeGoodComments,
      "no-comment-slop": noCommentSlop,
    },
    rules: {
      // Division of labor across the comment-quality plugins: no-comment-slop
      // catches generated-comment tells (banners, jargon, foreign syntax);
      // write-good-comments checks prose quality (repeated words, clichés);
      // sbomlet/no-comment-jargon bans this codebase's own planning shorthand.
      // tsdoc/syntax and comment-length/comment-refill are a separate axis
      // (syntax correctness, width budget) and apply to every comment shape.
      "sbomlet/no-comment-jargon": "error",
      "tsdoc/syntax": "warn",
      // 100 is the comment width: paragraphs fill toward it and wrap at it.
      // comment-refill/refill owns reflow for the shapes it understands
      // (prose, markdown lists, // runs) — it wraps overlong lines and
      // refills under-filled ones, list markers and bullet continuations
      // intact. comment-length is kept alongside it, in its default
      // overflow-only mode, purely as a ceiling backstop for the shapes
      // refill deliberately skips (TSDoc @tag bodies, aligned tables,
      // fenced/commented-out code, irregular blocks): overflow-only only
      // ever wraps a single overlong line, never merges paragraphs, so it
      // cannot fight refill's canonical reflow on the lines refill does
      // touch. Both target the same maxLength.
      "comment-refill/refill": ["error", { maxLength: 100 }],
      "comment-length/limit-single-line-comments": [
        "error",
        { maxLength: 100 },
      ],
      "comment-length/limit-multi-line-comments": ["error", { maxLength: 100 }],
      // Kept checks: illusion (repeated words), thereIs, cliches.
      "write-good-comments/write-good-comments": [
        "error",
        {
          // Off: docs here describe what happens to inputs ("malformed
          // entries are skipped") — active voice would obscure the actor.
          passive: false,
          // Off: "only"/"exactly"/"several" are precision words in a
          // spec, not hedges.
          weasel: false,
          // Off: "silently"/"loudly" name failure-mode semantics in this
          // codebase; deleting them changes meaning.
          adverb: false,
          // Off: its dictionary rewrites domain vocabulary (evaluate,
          // satisfy, validate, minimum) into vaguer verbs.
          tooWordy: false,
          // Off: a line-wrapped mid-sentence "so" reads as a sentence
          // start and false-positives on every wrapped comment.
          so: false,
        },
      ],
      // On, zero or near-zero flags on the current tree: free future-guards.
      "no-comment-slop/no-banner-comment": "error",
      "no-comment-slop/prefer-jsdoc-for-exports": "error",
      "no-comment-slop/no-foreign-syntax": "error",
      "no-comment-slop/no-jargon": "error",
      // Off: rationale paragraphs intentionally run long; the density
      // budget (task quality) already caps volume in aggregate.
      "no-comment-slop/max-comment-lines": "off",
      // Off: short trailing clarifiers ("// malformed entry — tolerant
      // skip") are a deliberate house idiom, longer than this rule allows.
      "no-comment-slop/no-trailing-comment": "off",
      "no-comment-slop/prefer-jsdoc-for-members": "error",
      // Off: floods interface-heavy modules with dozens of partially
      // documented interfaces; backfilling those is a deliberate project,
      // not a lint default.
      "no-comment-slop/require-member-docs": "off",
      // Off: house comments are full sentences and end with a period.
      "no-comment-slop/no-trailing-period": "off",
      "no-comment-slop/no-em-dash": "error",
    },
  },
  {
    // github-script step bodies: plain CommonJS Node, not part of the bundled
    // TypeScript tool, so they use require/module.exports directly. The
    // .cjs extension forces CommonJS regardless of this repo's own
    // package.json "type": "module".
    files: [".github/scripts/**/*.cjs"],
    languageOptions: {
      globals: { require: "readonly", module: "writable", process: "readonly" },
    },
    rules: {
      "@typescript-eslint/no-require-imports": "off",
    },
  },
  // Last — disables ESLint's own formatting rules (eslint-config-prettier) and
  // reports Prettier differences as `prettier/prettier` errors, so `lint` is the
  // single formatting gate and `lint:fix` rewrites.
  eslintPluginPrettierRecommended,
);
