/**
 * arktype boundary for packages.lock.json (tolerant posture): only the lock
 * format version and the dependencies map are consumed; unknown extra fields
 * are ignored by construction. A failed narrow takes the caller's empty-map
 * path (zero components → the loud zero-component hard fail downstream),
 * never a throw here.
 */
import { type } from "arktype";

import { UnknownRecord } from "./record";

export const NugetLockDocument = type({
  "version?": "number",
  "dependencies?": UnknownRecord,
});
