/**
 * Per-occurrence target-profile resolution, plus the two pure notice builders for the target lane's
 * adoption and shadowing hygiene. policy/evaluate.ts's lane calls resolveTargetProfile once per
 * occurrence; pipeline/pipeline.ts prints the notice builders' output beside the existing policy
 * summary. Both builders are pure (no I/O) so they stay unit-testable without stderr capture - the
 * CLI owns stderr, matching every other pure engine module in this package.
 */
import {
  DOCKER_IDENTITY_PREFIX,
  matchesIdentityPrefix,
  type CanonicalDependencies,
} from "../model/dependencies";
import type { TargetProfile } from "./compat";
import type { Policy, TargetWorkspaceEntry } from "./schema";

/**
 * The governing target profile for one occurrence, or undefined when nothing governs it.
 *
 * A docker occurrence resolves ONLY the project profile - a container ships the project's software,
 * and a workspace override never governs it (the container-design resolution,
 * 20-00-PLAN-OVERVIEW.md: `[[target.workspace]]` entries are ungoverned for docker occurrences by
 * construction). A workspace occurrence resolves the most-specific covering `[[target.workspace]]`
 * entry - longest path wins, segment-aware via {@link matchesIdentityPrefix}, the same comparison
 * copyleft suppression paths and `[[compatible]]` `where` scopes use - inheriting any field the
 * entry omits from a complete project profile. Failing a workspace match, the project profile
 * itself; failing both, undefined (today's walk, untouched).
 */
export function resolveTargetProfile(
  occurrenceTarget: string,
  policy: Policy,
): TargetProfile | undefined {
  const target = policy.target;

  if (target === undefined) {
    return undefined;
  }

  if (occurrenceTarget.startsWith(DOCKER_IDENTITY_PREFIX)) {
    return target.profile;
  }

  let best: TargetWorkspaceEntry | undefined;

  for (const entry of target.workspaces) {
    if (!matchesIdentityPrefix(occurrenceTarget, entry.path)) {
      continue;
    }

    if (best === undefined || entry.path.length > best.path.length) {
      best = entry;
    }
  }

  if (best === undefined) {
    return target.profile;
  }

  const network = best.network ?? target.profile?.network;
  const distribution = best.distribution ?? target.profile?.distribution;

  // Invariant enforced by schema.ts's validateTargetWorkspaceEntry: an entry declared under an
  // incomplete project profile always carries its own network/distribution, so this branch is
  // unreachable in practice - defensive, never-throws posture only.
  if (network === undefined || distribution === undefined) {
    return undefined;
  }

  return { license: best.license, network, distribution };
}

/**
 * One `[[target.workspace]]` entry whose path covers no occurrence in this run - a dead scoped
 * rule, the same posture `[[docker.development]]` and the unused compatible/clarify rules already
 * get. Absent [target] table, or one declaring no workspace entries, yields [].
 */
export function unusedWorkspaceTargetWarnings(
  model: CanonicalDependencies,
  policy: Policy,
): string[] {
  const target = policy.target;

  if (target === undefined || target.workspaces.length === 0) {
    return [];
  }

  const occurrenceTargets = new Set<string>();

  for (const pkg of model.packages) {
    for (const occurrence of pkg.occurrences) {
      if (!occurrence.target.startsWith(DOCKER_IDENTITY_PREFIX)) {
        occurrenceTargets.add(occurrence.target);
      }
    }
  }

  const warnings: string[] = [];

  for (const entry of target.workspaces) {
    const covered = [...occurrenceTargets].some((occurrenceTarget) =>
      matchesIdentityPrefix(occurrenceTarget, entry.path),
    );

    if (!covered) {
      warnings.push(`[[target.workspace]] "${entry.path}" matches no occurrence in this run`);
    }
  }

  return warnings;
}

/**
 * One `[[workspace.copyleft_suppressed]]` entry a declared target governs: the target lane
 * supersedes a governed occurrence's suppression entirely (policy/evaluate.ts's lane runs above the
 * suppression check in the precedence walk), so the suppression entry is effectively dead there
 * - surfaced as an info notice naming both, never silently. "Governed" is either a complete project
 * profile (which governs every workspace occurrence) or a `[[target.workspace]]` entry whose path
 * covers or is covered by the suppression path (either direction overlaps: a suppression nested
 * under a narrower target override, or a target override nested under a broader suppression).
 * Absent [target] table yields [].
 */
export function suppressionOverlapNotices(policy: Policy): string[] {
  const target = policy.target;

  if (target === undefined) {
    return [];
  }

  const notices: string[] = [];

  for (const rule of policy.suppressedWorkspaces) {
    if (target.profile !== undefined) {
      notices.push(
        `[[workspace.copyleft_suppressed]] "${rule.path}" is governed by the declared project target profile — the target lane decides every occurrence there, not the suppression`,
      );
      continue;
    }

    const overlapping = target.workspaces.find(
      (entry) =>
        matchesIdentityPrefix(rule.path, entry.path) ||
        matchesIdentityPrefix(entry.path, rule.path),
    );

    if (overlapping !== undefined) {
      notices.push(
        `[[workspace.copyleft_suppressed]] "${rule.path}" overlaps the [[target.workspace]] entry "${overlapping.path}" — the target lane decides every occurrence there, not the suppression`,
      );
    }
  }

  return notices;
}
