import js from "@eslint/js";
import tseslint from "typescript-eslint";
import importX from "eslint-plugin-import-x";
import eslintPluginPrettierRecommended from "eslint-plugin-prettier/recommended";

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
