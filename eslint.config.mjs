import js from "@eslint/js";
import tseslint from "typescript-eslint";
import importX from "eslint-plugin-import-x";
import tsdoc from "eslint-plugin-tsdoc";
import commentLength from "eslint-plugin-comment-length";
import eslintPluginPrettierRecommended from "eslint-plugin-prettier/recommended";

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
    },
    rules: {
      "sbomlet/no-comment-jargon": "error",
      "tsdoc/syntax": "warn",
      // Auto-wrap comment lines that exceed 100 cols — the hard ceiling for
      // comment width (~80 stays the prose target by convention). Default
      // mode reflows only the overflowing line and skips URLs and
      // code-bearing comments, enforcing the ceiling without rewriting
      // legitimate content.
      "comment-length/limit-single-line-comments": [
        "error",
        { maxLength: 100 },
      ],
      "comment-length/limit-multi-line-comments": ["error", { maxLength: 100 }],
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
