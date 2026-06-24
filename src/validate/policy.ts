/**
 * arktype boundary for the parsed-TOML policy root (reject posture).
 *
 * Unlike the tolerant SBOM/bun.lock boundaries, policy is semi-trusted config:
 * unknown top-level keys are rejected ("+": "reject"). arktype narrows the root
 * shape only — every user-facing problem string stays hand-written in
 * schema.ts (arktype's text differs from the PolicyError contract). The
 * per-table entry shapes are walked with the shared recordOf/stringOf narrows,
 * not arktype types, so each malformed field maps onto its existing
 * byte-identical message.
 */
import { type } from "arktype";

/**
 * The accepted top-level policy keys — the SINGLE source of truth shared by
 * PolicyRoot (the reject-posture narrow) and schema.ts's hand-written
 * unknown-key loop, so the two can never drift to different key lists.
 */
export const TOP_LEVEL_KEYS = [
  "workspace",
  "compatible",
  "clarify",
  "deny",
  "unknown",
  "dev_dependencies",
  "os_dependencies",
  "document",
  "docker",
] as const;

/**
 * Top-level table presence derived from TOP_LEVEL_KEYS; "+": "reject" flags
 * unknown keys. Built programmatically so the key list lives in exactly one
 * place.
 */
export const PolicyRoot = type(
  Object.fromEntries(TOP_LEVEL_KEYS.map((key) => [`${key}?`, "unknown"])),
).onUndeclaredKey("reject");
