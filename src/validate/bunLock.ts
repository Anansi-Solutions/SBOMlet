/**
 * arktype boundary for the bun.lock document, post-JSONC-strip (tolerant
 * posture). A failed narrow takes the caller's existing
 * record-narrow-undefined path; per-entry spec extraction (specOf, splitSpec)
 * stays explicit code in the collector.
 */
import { type } from "arktype";

import { UnknownRecord } from "./record";

/**
 * Only the `packages` map is a document-level field here, narrowed exactly as
 * the npm sibling (validate/npmLock.ts) declares its own. `lockfileVersion` is
 * consumed nowhere, and `workspaces` is read independently with recordOf in
 * the collector — declaring either here would narrow them atomically, so a
 * string lockfileVersion or an array workspaces would fail the whole-document
 * narrow and zero a valid packages map (a clean run → fatal exit 3).
 */
export const BunLockDocument = type({
  "packages?": UnknownRecord,
});
