/**
 * Shared plain-record narrow for the validation boundary.
 *
 * JSON/TOML maps are plain objects — arrays must not pass (arktype's Record
 * accepts them, but they carry index keys only and would silently widen the
 * tolerant walks).
 */
import { type } from "arktype";

export const UnknownRecord = type("Record<string, unknown>").narrow(
  (value) => !Array.isArray(value),
);

/**
 * Option-returning form of UnknownRecord for per-entry tolerant walks:
 * a failed narrow yields undefined — the callers' existing skip path.
 */
export function recordOf(value: unknown): Record<string, unknown> | undefined {
  const result = UnknownRecord(value);
  return result instanceof type.errors ? undefined : result;
}

/** Option-returning string narrow — a non-string yields undefined. */
export function stringOf(value: unknown): string | undefined {
  const result = type("string")(value);
  return result instanceof type.errors ? undefined : result;
}
