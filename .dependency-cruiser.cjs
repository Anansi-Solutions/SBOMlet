/**
 * Architecture-governance rules for SBOMlet's own source.
 *
 * These are proposed default rules, not (yet) part of the blocking gate. Run
 * them with `task arch:check`; regenerate the directory graph with
 * `task arch:graph`. The rules encode the layering the code follows today: a
 * dependency-free domain model and validation foundation, collectors that
 * gather raw inventory without knowing about policy or rendering, and a
 * rendering layer that consumes the evaluated model rather than reaching back
 * into data production. `pipeline` is the orchestrator and may depend on every
 * layer; `cli` is the entry point. See docs/explanation/module-dependencies.md.
 *
 * @type {import('dependency-cruiser').IConfiguration}
 */
module.exports = {
  forbidden: [
    {
      name: "no-circular",
      comment:
        "Modules should not form dependency cycles. Kept at warn for now: the " +
        "tree still has type-only cycles to untangle (deny/schema, compat, " +
        "pipeline/targets) - each closes through an import type that TypeScript " +
        "erases, so none is a runtime cycle. The genuine policy/normalize runtime " +
        "cycle is resolved. Promote to error once the type-only cycles are gone, " +
        "or once the rule is scoped to ignore type-only edges. See " +
        "docs/explanation/module-dependencies.md.",
      severity: "warn",
      from: {},
      to: { circular: true },
    },
    {
      name: "no-orphans",
      comment:
        "A module imported by nothing is usually dead code or a leftover after " +
        "a refactor. The CLI entry point and type declaration files are " +
        "expected orphans and are exempt.",
      severity: "warn",
      from: {
        orphan: true,
        pathNot: [
          "[.]d[.]ts$",
          "(^|/)tsconfig[.]json$",
          "(^|/)[.][^/]+[.](?:js|cjs|mjs|ts)$",
          "^src/cli[.]ts$",
        ],
      },
      to: {},
    },
    {
      name: "not-to-test",
      comment:
        "Production code under src/ must never import from test/. A test-only " +
        "helper leaking into production is both a packaging bug and a layering " +
        "violation.",
      severity: "error",
      from: { path: "^src/", pathNot: "[.](spec|test)[.]ts$" },
      to: { path: "^test/" },
    },
    {
      name: "not-to-unresolvable",
      comment:
        "Do not import a module that cannot be resolved — a dangling or " +
        "misspelled path, or a dependency that is not installed.",
      severity: "error",
      from: {},
      to: { couldNotResolve: true },
    },
    {
      name: "no-deprecated-core",
      comment:
        "Do not depend on deprecated Node.js core modules; they can vanish in a " +
        "future runtime.",
      severity: "error",
      from: {},
      to: {
        dependencyTypes: ["core"],
        path: [
          "^v8/tools/codemap$",
          "^v8/tools/consarray$",
          "^v8/tools/csvparser$",
          "^v8/tools/logreader$",
          "^v8/tools/profile_view$",
          "^v8/tools/profile$",
          "^v8/tools/SourceMap$",
          "^v8/tools/splaytree$",
          "^v8/tools/tickprocessor-driver$",
          "^v8/tools/tickprocessor$",
          "^node-inspect/lib/_inspect$",
          "^node-inspect/lib/internal/inspect_client$",
          "^node-inspect/lib/internal/inspect_repl$",
          "^async_hooks$",
          "^punycode$",
          "^domain$",
          "^constants$",
          "^sys$",
          "^_linklist$",
          "^_stream_wrap$",
        ],
      },
    },
    {
      name: "foundation-is-dependency-free",
      comment:
        "The domain model (src/model) and validation primitives (src/validate) " +
        "are the foundation every other layer builds on, so they must not " +
        "import any other own-code layer. Keeping them free of upward " +
        "dependencies is what lets everything else depend on them safely.",
      severity: "error",
      from: { path: "^src/(model|validate)/" },
      to: { path: "^src/", pathNot: "^src/(model|validate)/" },
    },
    {
      name: "collectors-below-policy-and-render",
      comment:
        "Collectors gather raw package inventory. They sit upstream of policy " +
        "evaluation and report rendering and must not import either — inventory " +
        "collection cannot depend on how findings are later judged or printed.",
      severity: "error",
      from: { path: "^src/collectors/" },
      to: { path: "^src/(policy|render)/" },
    },
    {
      name: "render-consumes-not-collects",
      comment:
        "Rendering turns the already-evaluated model into output. It must not " +
        "reach back into the data-production layers (collectors, enrich, merge, " +
        "targets); if render needs a value, it belongs in the model handed to " +
        "it, not fetched from a collector.",
      severity: "error",
      from: { path: "^src/render/" },
      to: { path: "^src/(collectors|enrich|merge|targets)/" },
    },
  ],
  options: {
    doNotFollow: { path: ["node_modules"] },
    exclude: {
      path: [
        "^test/",
        "^scripts/",
        "^tools/",
        "^dist/",
        "node_modules",
        // Vendored license-compatibility data, not own code.
        "^src/policy/compat/[^/]+[.]json$",
      ],
    },
    tsConfig: { fileName: "tsconfig.json" },
    tsPreCompilationDeps: true,
    enhancedResolveOptions: {
      extensions: [".ts", ".mts", ".cts", ".js", ".mjs", ".cjs", ".json"],
      mainFields: ["module", "main", "types", "typings"],
      conditionNames: ["import", "require", "node", "default", "types"],
    },
  },
};
