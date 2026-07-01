# ADR-0017: Committed artifacts live in one configurable cache directory

- **Status:** Accepted
- **Date:** 2026-06-28

## Context and problem

The artifacts the tool commits so `check` runs offline — the registry-resolved
licence cache and the Docker base-image OS SBOM — sat as separate dotfiles at the
repo root (`.sbomlet.cache.json`, `docker-os-sbom.json`), beside the policy file
(`.sbomlet.toml`). Three problems pushed against that:

- **Root clutter, no lever.** Every adopting repo gained two (eventually more)
  tool-owned files at its root, with no way to relocate them. A team with a
  convention for generated state (a .NET shop's `eng/`, a `.cache/` dir) could not
  honour it.
- **Input and output looked alike.** `.sbomlet.toml` (hand-authored) was, by name,
  indistinguishable from `.sbomlet.cache.json` (tool-generated). One you edit; one
  you must never hand-edit.
- **A per-artifact anchoring seam.** The enrichment cache and policy pointer anchored
  to `--repo-root`, but the committed Docker SBOM read anchored to `--base-dir` — a
  divergence that silently skipped a consumer's SBOM under the GitHub Action until it
  was fixed.

## Decision drivers

- One home for every tool-generated committed artifact, present and future.
- A consumer can move that home off the repo root by configuration, without losing
  the offline-`check` guarantee.
- Relocation cannot break determinism: the directory stays inside the scanned repo
  (so it is committable), and every entry point resolves it identically.
- Hand-authored config stays visibly distinct from generated state.

## Considered options

1. **Prefix the files** (`.sbomlet.docker-cache.json`, …) — tidier names, but still N
   dotfiles at the root, no relocation, same input/output blur.
2. **A fixed `.sbomlet.cache/` directory** — one home, but the location is baked in.
3. **A directory whose location the policy declares** (chosen) — one home, plus a
   repo-relative `[cache] dir` override.

## Decision

Committed artifacts live in one directory, default `.sbomlet.cache/`, holding
`licenses.cache.json` (the registry-resolved licence cache) and `docker-os.sbom.json`
(the base-image OS SBOM). Files inside need no `.sbomlet.` prefix — the directory
carries it, and the `.cache.`/`.sbom.` segment names each file's kind.

A policy `[cache] dir` chooses the location, validated exactly like a suppression
path (forward slashes, no `..`, no leading or trailing slash), so the directory
cannot escape the repo; a .NET shop sets `dir = "eng/.sbomlet.cache"`. The directory
anchors to the scanned repo (`--repo-root`; `--base-dir` only in single-target mode),
so the CLI, in-process callers, and the GitHub Action resolve the same files. One
resolver — `cacheDir`/`resolveCacheDir` — is the single source of that rule; generate,
check, verify-cache, and generate-docker-sbom all call it. A shared `writeArtifact`
creates the directory before the first write.

The policy file is renamed `.sbomlet.toml` → `.sbomlet.policy.toml`, so the
hand-authored config (`.sbomlet.policy.toml`, you edit) and the generated cache
(`.sbomlet.cache/`, the tool owns) read as the input/output pair they are.

## Consequences

- **Good:** a tidy root (one config file plus one cache dir), a relocation lever for
  teams that want one, and a self-documenting input/output split.
- **Good:** one anchoring rule for every entry point — the base-dir-vs-repo-root
  divergence that bit the Docker read cannot recur per-artifact.
- **Good:** forward-compatible — a future committed artifact drops into the same
  directory with no new root dotfile.
- **Cost / breaking:** a pre-release rename. Existing adopters move `.sbomlet.toml` →
  `.sbomlet.policy.toml` and their cache files into `.sbomlet.cache/`, then
  regenerate; the `.gitattributes` LF pin shifts to `.sbomlet.cache/**`.
- **Neutral:** `[cache] dir` resolves against the repo root and is rejected at
  validation if it would escape, so an out-of-repo location fails loudly rather than
  silently going un-committed.

## See also

- Related: [ADR-0008](0008-offline-check-committed-cache.md) (the
  offline-`check`/committed-cache contract this organizes),
  [ADR-0012](0012-docker-os-via-syft.md) (the committed Docker OS SBOM that now lives
  here)
- Code: `src/policy/schema.ts` (`validateCache`), `src/pipeline/pipeline.ts`
  (`cacheDir`, `resolveCacheDir`), `src/pipeline/paths.ts` (`writeArtifact`)
