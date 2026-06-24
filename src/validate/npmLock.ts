/**
 * arktype boundary for package-lock.json v2/v3 (tolerant posture): only the
 * packages map is consumed. A failed narrow takes the callers' existing
 * unknown/empty path — counters return undefined (route to scan), name sets
 * stay empty; never a throw.
 */
import { type } from "arktype";

import { UnknownRecord } from "./record";

export const NpmLockDocument = type({
  "packages?": UnknownRecord,
});
