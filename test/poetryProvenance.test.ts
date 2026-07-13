/**
 * Python dependency provenance from poetry.lock + pyproject.toml.
 *
 * The lockfile `[package.dependencies]` tables give the introducer edges;
 * pyproject `[project].dependencies` (PEP 621 `"name (constraint)"`) and/or
 * `[tool.poetry.dependencies]` (legacy `name = "constraint"` table) give the
 * declared-direct roots. DERIVE: direct-vs-transitive + introducer set +
 * a representative tie-broken path. PEP-503 name normalization makes every node
 * a `pkg:pypi/<name>@<version>` purl matching the existing prod/dev derivation.
 *
 * DESCOPE: optionality (poetry `optional = true`, PEP 508 markers, extras,
 * multi-variant spec arrays) is OUT OF SCOPE. Deriving it from markers was a
 * recurring mislabeling bug class. Every `[package.dependencies]` entry is now just an edge; there is no
 * optional distinction, no `optional` field, and "required-reachability"
 * collapses to plain reachability from a declared root via the introducer graph.
 *
 * Locked properties:
 * - direct = package whose name ∈ declared roots AND that name maps to EXACTLY
 *   ONE lock purl (a multi-version root name is the honest residual — version is
 *   part of the purl and a name alone cannot pick the version without PEP-440);
 * - introducedBy = sorted-unique SET of direct-parent purls, emitted ONLY for
 *   edges whose dependency NAME resolves to exactly one lock purl (a
 *   name→multi-version mapping fabricates no edge);
 * - path = deterministic tie-broken representative shortest root→purl chain;
 * - multi-parent transitive carries the FULL introducer set, one path;
 * - names PEP-503 normalized to match cdxgen's pypi purls;
 * - NO `optional` field is ever emitted (descoped, marker semantics not parsed);
 * - garbage / missing input yields an empty map, never throws.
 */

import { describe, expect, test } from "bun:test";

import { poetryIntroductions } from "../src/collectors/poetryProvenance";

/**
 * Synthetic poetry.lock: root declares a + b (via pyproject); c is a shared
 * transitive under a AND b (multi-parent); d is under c; e is a dependency of a
 * declared with a marker/optional spec object — such an edge is now just
 * a plain edge (optionality descoped), so e is a normal transitive of a.
 */
const POETRY_LOCK = [
  "[[package]]",
  'name = "a-pkg"',
  'version = "1.0.0"',
  'groups = ["main"]',
  "[package.dependencies]",
  'c-pkg = ">=3.0"',
  'e-pkg = {version = ">=5.0", optional = true, markers = "extra == \\"opt\\""}',
  "",
  "[[package]]",
  'name = "b-pkg"',
  'version = "2.0.0"',
  'groups = ["main"]',
  "[package.dependencies]",
  'c-pkg = ">=3.0"',
  "",
  "[[package]]",
  'name = "c-pkg"',
  'version = "3.0.0"',
  'groups = ["main"]',
  "[package.dependencies]",
  'd-pkg = ">=4.0"',
  "",
  "[[package]]",
  'name = "d-pkg"',
  'version = "4.0.0"',
  'groups = ["main"]',
  "",
  "[[package]]",
  'name = "e-pkg"',
  'version = "5.0.0"',
  'groups = ["main"]',
  "",
].join("\n");

/** PEP 621 declared roots: "name (constraint)" entries, plus a normalize case. */
const PYPROJECT_PEP621 = [
  "[project]",
  'name = "root"',
  'dependencies = ["a-pkg (>=1.0)", "b-pkg (>=2.0)"]',
  "",
].join("\n");

/** Legacy declared roots: [tool.poetry.dependencies] table. */
const PYPROJECT_LEGACY = [
  "[tool.poetry.dependencies]",
  'python = "^3.11"',
  'a-pkg = "^1.0"',
  'b-pkg = "^2.0"',
  "",
].join("\n");

describe("poetryIntroductions (PEP 621 roots)", () => {
  const intro = poetryIntroductions(POETRY_LOCK, PYPROJECT_PEP621);

  test("declared roots are direct with empty introducedBy and no path", () => {
    const a = intro.get("pkg:pypi/a-pkg@1.0.0");
    expect(a).toBeDefined();
    expect(a!.direct).toBe(true);
    expect(a!.introducedBy).toEqual([]);
    expect(a!.path).toBeUndefined();
  });

  test("multi-parent transitive carries the sorted-unique introducer SET", () => {
    const c = intro.get("pkg:pypi/c-pkg@3.0.0");
    expect(c!.direct).toBe(false);
    expect(c!.introducedBy).toEqual([
      "pkg:pypi/a-pkg@1.0.0",
      "pkg:pypi/b-pkg@2.0.0",
    ]);
  });

  test("transitive path is a deterministic tie-broken representative chain", () => {
    const c = intro.get("pkg:pypi/c-pkg@3.0.0");
    expect(c!.path).toEqual(["pkg:pypi/a-pkg@1.0.0", "pkg:pypi/c-pkg@3.0.0"]);
    const d = intro.get("pkg:pypi/d-pkg@4.0.0");
    expect(d!.path).toEqual([
      "pkg:pypi/a-pkg@1.0.0",
      "pkg:pypi/c-pkg@3.0.0",
      "pkg:pypi/d-pkg@4.0.0",
    ]);
  });

  test("a dependency declared with a marker/optional spec object is a plain transitive (optionality descoped)", () => {
    const e = intro.get("pkg:pypi/e-pkg@5.0.0");
    expect(e!.direct).toBe(false);
    expect(e!.introducedBy).toEqual(["pkg:pypi/a-pkg@1.0.0"]);
    // No `optional` field is ever emitted.
    expect("optional" in e!).toBe(false);
  });

  test("no introduction ever carries an `optional` field", () => {
    for (const i of intro.values()) {
      expect("optional" in i).toBe(false);
    }
  });

  test("every lockfile package gets an entry (root not in lock)", () => {
    expect(intro.size).toBe(5); // a, b, c, d, e
  });
});

describe("poetryIntroductions (legacy [tool.poetry] roots)", () => {
  test("legacy declared roots are recognized as direct", () => {
    const intro = poetryIntroductions(POETRY_LOCK, PYPROJECT_LEGACY);
    expect(intro.get("pkg:pypi/a-pkg@1.0.0")!.direct).toBe(true);
    expect(intro.get("pkg:pypi/b-pkg@2.0.0")!.direct).toBe(true);
    expect(intro.get("pkg:pypi/c-pkg@3.0.0")!.direct).toBe(false);
  });
});

describe("poetryIntroductions — PEP 503 normalization", () => {
  test("a dep name with underscores/dots/case maps to the normalized purl edge", () => {
    const lock = [
      "[[package]]",
      'name = "Parent_Pkg"',
      'version = "1.0.0"',
      'groups = ["main"]',
      "[package.dependencies]",
      '"Child.Dep_Name" = ">=1.0"',
      "",
      "[[package]]",
      'name = "child-dep-name"',
      'version = "2.0.0"',
      'groups = ["main"]',
      "",
    ].join("\n");
    const pyproject = '[project]\ndependencies = ["Parent_Pkg (>=1.0)"]\n';
    const intro = poetryIntroductions(lock, pyproject);
    expect(intro.get("pkg:pypi/parent-pkg@1.0.0")!.direct).toBe(true);
    const child = intro.get("pkg:pypi/child-dep-name@2.0.0");
    expect(child!.introducedBy).toEqual(["pkg:pypi/parent-pkg@1.0.0"]);
  });
});

describe("poetryIntroductions — determinism", () => {
  test("double-derive is byte-identical from the same lock + pyproject", () => {
    const serialize = (m: ReadonlyMap<string, unknown>): string =>
      JSON.stringify([...m.entries()].sort());
    expect(serialize(poetryIntroductions(POETRY_LOCK, PYPROJECT_PEP621))).toBe(
      serialize(poetryIntroductions(POETRY_LOCK, PYPROJECT_PEP621)),
    );
  });
});

describe("poetryIntroductions — optionality descoped", () => {
  // DESCOPE: poetry `optional`/marker/extras semantics produced a
  // recurring mislabeling bug class. Rather than
  // keep patching PEP 508 marker / extras / multi-variant parsing, optionality
  // is removed entirely. Every `[package.dependencies]` edge — regardless of
  // marker/optional/extras decoration — is now just an edge; reachability from a
  // declared root via that graph is the only derivation.

  test("a multi-variant dep (one python_version variant + one `extra ==` variant) is a plain edge — no optional", () => {
    // A poetry dep value MAY be an ARRAY of conditional spec variants. The pre-
    // fix `edgeIsOptional` used `.some` (any variant optional → optional), which
    // mislabeled this. Now it is simply an edge; no optional anything.
    const lock = [
      "[[package]]",
      'name = "host-pkg"',
      'version = "1.0.0"',
      'groups = ["main"]',
      "[package.dependencies]",
      "multi-pkg = [",
      '  {version = ">=2.0", markers = "python_version >= \\"3.11\\""},',
      '  {version = ">=1.0", markers = "extra == \\"opt\\""},',
      "]",
      "",
      "[[package]]",
      'name = "multi-pkg"',
      'version = "2.0.0"',
      'groups = ["main"]',
      "",
    ].join("\n");
    const pyproject = '[project]\ndependencies = ["host-pkg (>=1.0)"]\n';
    const intro = poetryIntroductions(lock, pyproject);
    const m = intro.get("pkg:pypi/multi-pkg@2.0.0");
    expect(m!.direct).toBe(false);
    expect(m!.introducedBy).toEqual(["pkg:pypi/host-pkg@1.0.0"]);
    expect(m!.path).toEqual([
      "pkg:pypi/host-pkg@1.0.0",
      "pkg:pypi/multi-pkg@2.0.0",
    ]);
    expect("optional" in m!).toBe(false);
  });

  test("a marker using `extra` as a comparison VALUE (not the variable) carries no optional anything", () => {
    // The pre-fix `specIsOptional` used `/\bextra\b/`, which matched `extra` as a
    // marker VALUE (`platform_machine == "extra"`) and mislabeled the edge
    // optional. Markers are not parsed at all — plain edge.
    const lock = [
      "[[package]]",
      'name = "host-pkg"',
      'version = "1.0.0"',
      'groups = ["main"]',
      "[package.dependencies]",
      'value-pkg = {version = ">=1.0", markers = "platform_machine == \\"extra\\""}',
      "",
      "[[package]]",
      'name = "value-pkg"',
      'version = "1.0.0"',
      'groups = ["main"]',
      "",
    ].join("\n");
    const pyproject = '[project]\ndependencies = ["host-pkg (>=1.0)"]\n';
    const intro = poetryIntroductions(lock, pyproject);
    const v = intro.get("pkg:pypi/value-pkg@1.0.0");
    expect(v!.direct).toBe(false);
    expect(v!.introducedBy).toEqual(["pkg:pypi/host-pkg@1.0.0"]);
    expect("optional" in v!).toBe(false);
  });

  test("a dep declared `optional = true` is still a plain reachable edge (no optional field)", () => {
    const lock = [
      "[[package]]",
      'name = "a-pkg"',
      'version = "1.0.0"',
      'groups = ["main"]',
      "[package.dependencies]",
      'c-pkg = {version = ">=3.0", optional = true, markers = "extra == \\"opt\\""}',
      "",
      "[[package]]",
      'name = "c-pkg"',
      'version = "3.0.0"',
      'groups = ["main"]',
      "",
    ].join("\n");
    const pyproject = '[project]\ndependencies = ["a-pkg (>=1.0)"]\n';
    const intro = poetryIntroductions(lock, pyproject);
    const c = intro.get("pkg:pypi/c-pkg@3.0.0");
    expect(c!.direct).toBe(false);
    expect(c!.introducedBy).toEqual(["pkg:pypi/a-pkg@1.0.0"]);
    expect(c!.path).toEqual(["pkg:pypi/a-pkg@1.0.0", "pkg:pypi/c-pkg@3.0.0"]);
    expect("optional" in c!).toBe(false);
  });
});

describe("poetryIntroductions — honest residual on multi-version names", () => {
  // PIVOT: the earlier "union the edge to ALL colliding purls" posture
  // FABRICATED edges and MISLABELED versions when a PEP-503 normalized name maps
  // to MORE THAN ONE lock purl (routine in poetry: marker-conditioned /
  // multiple-constraint deps, or a genuine name-origin collision). A
  // name→constraint edge cannot pick WHICH version it resolved to without
  // PEP-440 (out of scope, no new deps), so the honest answer is: emit NO edge
  // and NO blanket-direct for a multi-version name. Such purls receive
  // introducers ONLY from a parent whose own resolution is unambiguous.

  // (#2 FABRICATION) black@23 requires click >=8; lock has click@7.1.2 AND
  // click@8.1.7 (multi-version "click"). A name→multi edge must NOT fabricate
  // black → click@7.1.2 (a chain in no real dependency relationship).
  const MULTI_VERSION_CLICK = [
    "[[package]]",
    'name = "black"',
    'version = "23.0.0"',
    'groups = ["main"]',
    "[package.dependencies]",
    'click = ">=8.0.0"',
    "",
    "[[package]]",
    'name = "click"',
    'version = "7.1.2"',
    'groups = ["main"]',
    "",
    "[[package]]",
    'name = "click"',
    'version = "8.1.7"',
    'groups = ["main"]',
    "",
  ].join("\n");

  test("(#2) a name→multi-version edge fabricates NO edge to ANY colliding purl", () => {
    const pyproject = '[project]\ndependencies = ["black (>=23)"]\n';
    const intro = poetryIntroductions(MULTI_VERSION_CLICK, pyproject);
    const click7 = intro.get("pkg:pypi/click@7.1.2");
    const click8 = intro.get("pkg:pypi/click@8.1.7");
    // No fabricated black → click@7.1.2 edge (the wrong-version chain).
    expect(click7!.introducedBy).not.toContain("pkg:pypi/black@23.0.0");
    // And not even the "right" version: name→multi is ambiguous → honest
    // residual for BOTH, no edge fabricated to either.
    expect(click8!.introducedBy).not.toContain("pkg:pypi/black@23.0.0");
    // Multi-version click with no precise introducer + not a precise direct →
    // the honest "—" residual: not direct, no introducer, no path.
    expect(click7!.direct).toBe(false);
    expect(click7!.introducedBy).toEqual([]);
    expect(click7!.path).toBeUndefined();
    expect(click8!.direct).toBe(false);
    expect(click8!.introducedBy).toEqual([]);
    expect(click8!.path).toBeUndefined();
  });

  // (#1 MISLABEL) pyproject roots foo + bar; lock has foo@1.0.0 (the real
  // direct) AND foo@2.0.0 (a transitive pulled in via bar). A version-agnostic
  // root-direct mark wrongly renders BOTH "direct"; the honest answer marks
  // NEITHER blanket-direct (multi-version root name).
  const MULTI_VERSION_ROOT = [
    "[[package]]",
    'name = "foo"',
    'version = "1.0.0"',
    'groups = ["main"]',
    "",
    "[[package]]",
    'name = "foo"',
    'version = "2.0.0"',
    'groups = ["main"]',
    "",
    "[[package]]",
    'name = "bar"',
    'version = "1.0.0"',
    'groups = ["main"]',
    "[package.dependencies]",
    'foo = ">=2.0.0"',
    "",
  ].join("\n");

  test("(#1) a transitive version of a declared-root NAME is NOT mislabeled direct", () => {
    const pyproject =
      '[project]\ndependencies = ["foo (>=1.0)", "bar (>=1.0)"]\n';
    const intro = poetryIntroductions(MULTI_VERSION_ROOT, pyproject);
    // foo is a multi-version declared-root name → NEITHER version is
    // blanket-marked direct (version-agnostic direct would mislabel foo@2.0.0).
    expect(intro.get("pkg:pypi/foo@2.0.0")!.direct).toBe(false);
    expect(intro.get("pkg:pypi/foo@1.0.0")!.direct).toBe(false);
    // bar is single-version declared root → still precisely direct.
    expect(intro.get("pkg:pypi/bar@1.0.0")!.direct).toBe(true);
  });

  // (baseline) the COMMON case — every name single-version — must be UNCHANGED:
  // a single-version declared root is direct, and a single-version chain
  // resolves precise introducers.
  const SINGLE_VERSION_BASELINE = [
    "[[package]]",
    'name = "foo"',
    'version = "1.0.0"',
    'groups = ["main"]',
    "",
    "[[package]]",
    'name = "bar"',
    'version = "1.0.0"',
    'groups = ["main"]',
    "[package.dependencies]",
    'baz = ">=1.0"',
    "",
    "[[package]]",
    'name = "baz"',
    'version = "1.0.0"',
    'groups = ["main"]',
    "",
  ].join("\n");

  test("(baseline) single-version names keep precise direct + precise introducer", () => {
    const pyproject =
      '[project]\ndependencies = ["foo (>=1.0)", "bar (>=1.0)"]\n';
    const intro = poetryIntroductions(SINGLE_VERSION_BASELINE, pyproject);
    expect(intro.get("pkg:pypi/foo@1.0.0")!.direct).toBe(true);
    expect(intro.get("pkg:pypi/bar@1.0.0")!.direct).toBe(true);
    const baz = intro.get("pkg:pypi/baz@1.0.0");
    expect(baz!.direct).toBe(false);
    expect(baz!.introducedBy).toEqual(["pkg:pypi/bar@1.0.0"]);
    expect(baz!.path).toEqual(["pkg:pypi/bar@1.0.0", "pkg:pypi/baz@1.0.0"]);
  });

  test("(baseline) a single-version parent precisely introduces its single-version child even amid OTHER multi-version names", () => {
    // click is multi-version (ambiguous), but bar→baz is a clean single-version
    // chain that must still resolve precisely — multi-version names elsewhere
    // do not poison unrelated unambiguous edges.
    const lock = [MULTI_VERSION_CLICK, SINGLE_VERSION_BASELINE].join("\n");
    const pyproject =
      '[project]\ndependencies = ["black (>=23)", "bar (>=1.0)"]\n';
    const intro = poetryIntroductions(lock, pyproject);
    const baz = intro.get("pkg:pypi/baz@1.0.0");
    expect(baz!.introducedBy).toEqual(["pkg:pypi/bar@1.0.0"]);
    // click stays the honest residual.
    expect(intro.get("pkg:pypi/click@8.1.7")!.introducedBy).toEqual([]);
  });

  test("an asymmetric permutation of multi-version packages yields identical output (order-independent)", () => {
    const serialize = (m: ReadonlyMap<string, unknown>): string =>
      JSON.stringify([...m.entries()].sort());
    const pyproject =
      '[project]\ndependencies = ["foo (>=1.0)", "bar (>=1.0)"]\n';
    const blocks = [
      [
        "[[package]]",
        'name = "foo"',
        'version = "1.0.0"',
        'groups = ["main"]',
        "",
      ].join("\n"),
      [
        "[[package]]",
        'name = "foo"',
        'version = "2.0.0"',
        'groups = ["main"]',
        "",
      ].join("\n"),
      [
        "[[package]]",
        'name = "bar"',
        'version = "1.0.0"',
        'groups = ["main"]',
        "[package.dependencies]",
        'foo = ">=2.0.0"',
        "",
      ].join("\n"),
    ];
    const order1 = blocks.join("\n");
    // asymmetric permutation (rotate, not reverse): [bar, foo@1, foo@2]
    const order2 = [blocks[2], blocks[0], blocks[1]].join("\n");
    expect(serialize(poetryIntroductions(order1, pyproject))).toBe(
      serialize(poetryIntroductions(order2, pyproject)),
    );
  });
});

describe("poetryIntroductions — dependency-group roots", () => {
  // WARNING (dogfood-exercised): declaredRootNames read roots from
  // [project].dependencies and [tool.poetry.dependencies] but NOT from
  // [tool.poetry.group.<name>.dependencies]. A package declared direct in a
  // group (the conventional dev group) was absent from rootNames → if nothing
  // else depended on it, it derived as an orphan → rendered "—" instead of
  // "direct". REAL dogfood case: apps/jupyter/pyproject.toml declares `copier`
  // under [tool.poetry.group.dev.dependencies]. FIX: also union EVERY
  // [tool.poetry.group.<name>.dependencies] table's names into the root set.

  const GROUP_LOCK = [
    "[[package]]",
    'name = "copier"',
    'version = "9.0.0"',
    'groups = ["dev"]',
    "",
    "[[package]]",
    'name = "runtime-pkg"',
    'version = "1.0.0"',
    'groups = ["main"]',
    "",
  ].join("\n");

  test("a package declared ONLY under [tool.poetry.group.dev.dependencies], depended on by nothing, is direct (was orphan '—')", () => {
    const pyproject = [
      "[project]",
      'name = "root"',
      'dependencies = ["runtime-pkg (>=1.0)"]',
      "",
      "[tool.poetry.group.dev.dependencies]",
      'copier = "^9.0"',
      "",
    ].join("\n");
    const intro = poetryIntroductions(GROUP_LOCK, pyproject);
    const copier = intro.get("pkg:pypi/copier@9.0.0");
    expect(copier).toBeDefined();
    expect(copier!.direct).toBe(true);
    expect(copier!.introducedBy).toEqual([]);
    expect(copier!.path).toBeUndefined();
    // the PEP 621 main dep is still direct
    expect(intro.get("pkg:pypi/runtime-pkg@1.0.0")!.direct).toBe(true);
  });

  test("group roots are read in LEGACY mode too (no [project], main deps from [tool.poetry.dependencies])", () => {
    const pyproject = [
      "[tool.poetry.dependencies]",
      'python = "^3.11"',
      'runtime-pkg = "^1.0"',
      "",
      "[tool.poetry.group.dev.dependencies]",
      'copier = "^9.0"',
      "",
    ].join("\n");
    const intro = poetryIntroductions(GROUP_LOCK, pyproject);
    expect(intro.get("pkg:pypi/copier@9.0.0")!.direct).toBe(true);
    expect(intro.get("pkg:pypi/runtime-pkg@1.0.0")!.direct).toBe(true);
  });

  test("the conventional `python` key inside a group table is skipped (interpreter, not a dep)", () => {
    const lock = [
      "[[package]]",
      'name = "python"',
      'version = "3.11.0"',
      'groups = ["dev"]',
      "",
      "[[package]]",
      'name = "tool-pkg"',
      'version = "1.0.0"',
      'groups = ["dev"]',
      "",
    ].join("\n");
    const pyproject = [
      "[project]",
      'name = "root"',
      "dependencies = []",
      "",
      "[tool.poetry.group.dev.dependencies]",
      'python = "^3.11"',
      'tool-pkg = "^1.0"',
      "",
    ].join("\n");
    const intro = poetryIntroductions(lock, pyproject);
    // python is the interpreter — never a declared-direct root.
    expect(intro.get("pkg:pypi/python@3.11.0")!.direct).toBe(false);
    expect(intro.get("pkg:pypi/tool-pkg@1.0.0")!.direct).toBe(true);
  });

  test("MULTIPLE groups (dev + docs) all contribute roots", () => {
    const lock = [
      "[[package]]",
      'name = "dev-pkg"',
      'version = "1.0.0"',
      'groups = ["dev"]',
      "",
      "[[package]]",
      'name = "docs-pkg"',
      'version = "2.0.0"',
      'groups = ["docs"]',
      "",
    ].join("\n");
    const pyproject = [
      "[project]",
      'name = "root"',
      "dependencies = []",
      "",
      "[tool.poetry.group.dev.dependencies]",
      'dev-pkg = "^1.0"',
      "",
      "[tool.poetry.group.docs.dependencies]",
      'docs-pkg = "^2.0"',
      "",
    ].join("\n");
    const intro = poetryIntroductions(lock, pyproject);
    expect(intro.get("pkg:pypi/dev-pkg@1.0.0")!.direct).toBe(true);
    expect(intro.get("pkg:pypi/docs-pkg@2.0.0")!.direct).toBe(true);
  });
});

describe("poetryIntroductions — legacy main-deps precedence", () => {
  // WARNING: declaredRootNames UNIONed [project].dependencies AND
  // [tool.poetry.dependencies] unconditionally. In PEP 621 mode
  // [project].dependencies is authoritative; the legacy table is
  // constraint/source metadata that may list NON-top-level names → a transitive
  // dep listed there rendered "direct". FIX: read the MAIN
  // [tool.poetry.dependencies] table as roots ONLY when [project].dependencies
  // is ABSENT. (Groups are ALWAYS read — separate table.)

  const PRECEDENCE_LOCK = [
    "[[package]]",
    'name = "app"',
    'version = "1.0.0"',
    'groups = ["main"]',
    "[package.dependencies]",
    'leftover = ">=1.0"',
    "",
    "[[package]]",
    'name = "leftover"',
    'version = "1.0.0"',
    'groups = ["main"]',
    "",
  ].join("\n");

  test("with [project].dependencies present, the legacy [tool.poetry.dependencies] table is NOT a root source", () => {
    // app is the authoritative PEP 621 root; `leftover` is a TRANSITIVE of app
    // that the legacy table also lists (constraint/source metadata). It must
    // render transitive (app → leftover), NOT direct.
    const pyproject = [
      "[project]",
      'name = "root"',
      'dependencies = ["app (>=1)"]',
      "",
      "[tool.poetry.dependencies]",
      'app = "^1.0"',
      'leftover = "^1.0"',
      "",
    ].join("\n");
    const intro = poetryIntroductions(PRECEDENCE_LOCK, pyproject);
    expect(intro.get("pkg:pypi/app@1.0.0")!.direct).toBe(true);
    const leftover = intro.get("pkg:pypi/leftover@1.0.0");
    expect(leftover!.direct).toBe(false);
    expect(leftover!.introducedBy).toEqual(["pkg:pypi/app@1.0.0"]);
    expect(leftover!.path).toEqual([
      "pkg:pypi/app@1.0.0",
      "pkg:pypi/leftover@1.0.0",
    ]);
  });

  test("legacy-only baseline (no [project]) — the legacy main table IS still used as roots", () => {
    const pyproject = [
      "[tool.poetry.dependencies]",
      'python = "^3.11"',
      'app = "^1.0"',
      'leftover = "^1.0"',
      "",
    ].join("\n");
    const intro = poetryIntroductions(PRECEDENCE_LOCK, pyproject);
    // No [project] → legacy table authoritative; BOTH app and leftover direct.
    expect(intro.get("pkg:pypi/app@1.0.0")!.direct).toBe(true);
    expect(intro.get("pkg:pypi/leftover@1.0.0")!.direct).toBe(true);
  });

  test("groups are read even WITH [project] present (independent of main-deps precedence)", () => {
    const lock = [
      "[[package]]",
      'name = "app"',
      'version = "1.0.0"',
      'groups = ["main"]',
      "",
      "[[package]]",
      'name = "grouponly"',
      'version = "1.0.0"',
      'groups = ["dev"]',
      "",
    ].join("\n");
    const pyproject = [
      "[project]",
      'name = "root"',
      'dependencies = ["app (>=1)"]',
      "",
      "[tool.poetry.dependencies]",
      'transitive-listed = "^1.0"',
      "",
      "[tool.poetry.group.dev.dependencies]",
      'grouponly = "^1.0"',
      "",
    ].join("\n");
    const intro = poetryIntroductions(lock, pyproject);
    // group root honored despite [project] being present (legacy main table NOT)
    expect(intro.get("pkg:pypi/grouponly@1.0.0")!.direct).toBe(true);
  });
});

describe("poetryIntroductions — introducedBy ⊆ root-reachable", () => {
  // CRITICAL: the SHARED deriveIntroductions set introducedBy directly
  // from the purl-space parent SET and only gated `path` on shortestPath. So a
  // transitive whose ONLY parent is itself disconnected from every declared root
  // got {direct:false, introducedBy:[<disconnected-parent>], path:undefined};
  // whyCellOf then saw a non-empty introducedBy (not an orphan), found no chain,
  // and rendered the disconnected parent as a FABRICATED introducer. The npm lane
  // dodged this with a LOCAL Fix-3 guard, but poetry relied on the shared
  // function and had no equivalent. FIX (central): deriveIntroductions computes
  // the root-reachable purl set (BFS over the introducer graph) ONCE and
  // INTERSECTS every node's introducedBy with it — making the bad state
  // unrepresentable for BOTH lanes.

  // A declared-root `app` (no deps); `orphanparent` is NOT a root and nothing
  // depends on it; `orphanparent` requires `child`. child's only parent is
  // root-disconnected → introducedBy must collapse to [] (a true orphan), never
  // name the disconnected orphanparent.
  const ORPHAN_PARENT_LOCK = [
    "[[package]]",
    'name = "app"',
    'version = "1.0.0"',
    'groups = ["main"]',
    "",
    "[[package]]",
    'name = "orphanparent"',
    'version = "1.0.0"',
    'groups = ["main"]',
    "[package.dependencies]",
    'child = ">=1.0"',
    "",
    "[[package]]",
    'name = "child"',
    'version = "1.0.0"',
    'groups = ["main"]',
    "",
  ].join("\n");

  test("a transitive whose only parent is root-disconnected has introducedBy [] (not the disconnected parent)", () => {
    const pyproject = [
      "[project]",
      'name = "root"',
      'dependencies = ["app (>=1)"]',
      "",
    ].join("\n");
    const intro = poetryIntroductions(ORPHAN_PARENT_LOCK, pyproject);
    const child = intro.get("pkg:pypi/child@1.0.0");
    expect(child).toBeDefined();
    // Was ['pkg:pypi/orphanparent@1.0.0'] — now [] (orphanparent is unreachable).
    expect(child!.introducedBy).toEqual([]);
    expect(child!.path).toBeUndefined();
    expect(child!.direct).toBe(false);
    // app (the real root) is unaffected.
    expect(intro.get("pkg:pypi/app@1.0.0")!.direct).toBe(true);
    // orphanparent itself is also a root-disconnected orphan: not direct, no
    // introducer.
    expect(intro.get("pkg:pypi/orphanparent@1.0.0")!.introducedBy).toEqual([]);
  });

  test("legacy→PEP-621 migration: a top-level declared only in legacy [tool.poetry] is NOT a root, so its child renders orphan (main-deps precedence × reachability)", () => {
    // pyproject has [project].dependencies (partial PEP 621 migration) listing
    // `other`, AND a real top-level `realroot` declared ONLY in the legacy
    // [tool.poetry.dependencies] table. Per Fix-2 precedence, with [project]
    // present the legacy table is NOT a root source → realroot is root-
    // disconnected → dep's only parent (realroot) is disconnected → dep must
    // render orphan, NOT name a fabricated 'pkg:pypi/realroot'.
    const lock = [
      "[[package]]",
      'name = "other"',
      'version = "1.0.0"',
      'groups = ["main"]',
      "",
      "[[package]]",
      'name = "realroot"',
      'version = "1.0.0"',
      'groups = ["main"]',
      "[package.dependencies]",
      'dep = ">=1.0"',
      "",
      "[[package]]",
      'name = "dep"',
      'version = "1.0.0"',
      'groups = ["main"]',
      "",
    ].join("\n");
    const pyproject = [
      "[project]",
      'name = "root"',
      'dependencies = ["other (>=1)"]',
      "",
      "[tool.poetry.dependencies]",
      'python = "^3.11"',
      'realroot = "^1.0"',
      "",
    ].join("\n");
    const intro = poetryIntroductions(lock, pyproject);
    // realroot is NOT a root → realroot is root-disconnected → dep's
    // only parent is disconnected → dep is an orphan.
    expect(intro.get("pkg:pypi/realroot@1.0.0")!.direct).toBe(false);
    const dep = intro.get("pkg:pypi/dep@1.0.0");
    expect(dep!.direct).toBe(false);
    expect(dep!.introducedBy).toEqual([]); // NOT ['pkg:pypi/realroot@1.0.0']
    expect(dep!.path).toBeUndefined();
    // the genuine PEP 621 root is direct.
    expect(intro.get("pkg:pypi/other@1.0.0")!.direct).toBe(true);
  });

  test("a mix of reachable + disconnected parents keeps ONLY the reachable ones", () => {
    // `child` is required by BOTH a reachable parent (`app`, a declared root) AND
    // a disconnected parent (`orphanparent`). introducedBy must keep app, drop
    // orphanparent.
    const lock = [
      "[[package]]",
      'name = "app"',
      'version = "1.0.0"',
      'groups = ["main"]',
      "[package.dependencies]",
      'child = ">=1.0"',
      "",
      "[[package]]",
      'name = "orphanparent"',
      'version = "1.0.0"',
      'groups = ["main"]',
      "[package.dependencies]",
      'child = ">=1.0"',
      "",
      "[[package]]",
      'name = "child"',
      'version = "1.0.0"',
      'groups = ["main"]',
      "",
    ].join("\n");
    const pyproject = [
      "[project]",
      'name = "root"',
      'dependencies = ["app (>=1)"]',
      "",
    ].join("\n");
    const intro = poetryIntroductions(lock, pyproject);
    const child = intro.get("pkg:pypi/child@1.0.0");
    // Only the reachable parent survives.
    expect(child!.introducedBy).toEqual(["pkg:pypi/app@1.0.0"]);
    expect(child!.path).toEqual(["pkg:pypi/app@1.0.0", "pkg:pypi/child@1.0.0"]);
  });

  test("reachability filter is order-independent (asymmetric permutation byte-identical)", () => {
    const pyproject = [
      "[project]",
      'name = "root"',
      'dependencies = ["app (>=1)"]',
      "",
    ].join("\n");
    const serialize = (m: ReadonlyMap<string, unknown>): string =>
      JSON.stringify([...m.entries()].sort());
    const blocks = [
      [
        "[[package]]",
        'name = "app"',
        'version = "1.0.0"',
        'groups = ["main"]',
        "",
      ].join("\n"),
      [
        "[[package]]",
        'name = "orphanparent"',
        'version = "1.0.0"',
        'groups = ["main"]',
        "[package.dependencies]",
        'child = ">=1.0"',
        "",
      ].join("\n"),
      [
        "[[package]]",
        'name = "child"',
        'version = "1.0.0"',
        'groups = ["main"]',
        "",
      ].join("\n"),
    ];
    const order1 = blocks.join("\n");
    // asymmetric permutation (rotate): [child, app, orphanparent]
    const order2 = [blocks[2], blocks[0], blocks[1]].join("\n");
    expect(serialize(poetryIntroductions(order1, pyproject))).toBe(
      serialize(poetryIntroductions(order2, pyproject)),
    );
  });
});

describe("poetryIntroductions — tolerance", () => {
  test("garbage / empty input yields an empty map, never throws", () => {
    expect(poetryIntroductions("garbage }{", "garbage }{").size).toBe(0);
    expect(poetryIntroductions("", "").size).toBe(0);
  });

  test("a lock with no roots declared yields all-transitive entries", () => {
    // No pyproject roots → nothing is direct, but the lock entries still emit.
    const intro = poetryIntroductions(POETRY_LOCK, "");
    expect(intro.get("pkg:pypi/a-pkg@1.0.0")!.direct).toBe(false);
    expect(intro.size).toBe(5);
  });
});
