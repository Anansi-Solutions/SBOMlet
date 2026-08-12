/**
 * ScanCode-toolkit collector - the syft-parity composite (dockerOs.ts) for deep source-level
 * license + copyright detection, orchestrated behind the `--intensive` lane: locate a package's
 * sources ({@link sourceDirsFor}), run the pinned tool and elect a result ({@link
 * scanPackageSources}), memoize the answer in the committed cache. The detail behind each step
 * lives in this module's own files: sources.ts, election.ts, invocation.ts, cache.ts.
 */
export { sourceDirsFor, type NpmSourceIndex, type NpmSourceIndexCache } from "./sources";
export { electCopyrights, electExpression } from "./election";
export {
  scancodeArgs,
  scanPackageSources,
  ScancodeEnvironmentError,
  type IntensiveOptions,
  type ScancodeResolution,
  type ScancodeScanOptions,
} from "./invocation";
export { SCANCODE_TOOL } from "./tool";
export {
  getMemoEntry,
  putMemoEntry,
  readScancodeMemo,
  serializeScancodeMemo,
  type ScancodeMemoEntry,
} from "./cache";
