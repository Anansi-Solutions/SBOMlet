/**
 * License-compatibility data - vendored OSADL matrix + copyleft class table, ScanCode LicenseDB
 * category fallback, the shared inter-tier disagreement enumerator, the pure license-axis
 * leaf/expression classifier, the usage-profile scope gate, and the target-lane rule ids/reason
 * builders. See PROVENANCE.md beside this file for retrieval provenance and CC-BY-4.0 attribution;
 * data.ts's module doc explains the loader shape.
 */
export {
  narrowOsadlCopyleftClass,
  narrowOsadlMatrix,
  narrowScancodeCategory,
  OSADL_COPYLEFT_CLASS,
  OSADL_MATRIX,
  OSADL_SNAPSHOT_TIMESTAMP,
  SCANCODE_CATEGORY,
  SCANCODE_SNAPSHOT_TIMESTAMP,
  type OsadlCopyleftClass,
  type OsadlMatrixCell,
} from "./data";
export { interTierDisagreements } from "./consistency";
export { classifyExpression, classifyLeaf, type ExpressionResult } from "./classify";
export type { AxisClass, AxisResult, ObligationClass, TargetLicense } from "./classification";
export {
  applyUsageProfile,
  type ModulatedClass,
  type ModulatedResult,
  type TargetProfile,
} from "./profile";
export {
  formatProfileLabel,
  targetBoundaryReason,
  targetIncompatibleReason,
  targetInternalUseReason,
  targetOkReason,
  targetUnknownPairReason,
  TARGET_RULE_BOUNDARY,
  TARGET_RULE_INCOMPATIBLE,
  TARGET_RULE_INTERNAL_USE,
  TARGET_RULE_OK,
  TARGET_RULE_UNKNOWN_PAIR,
  type ReasonContext,
} from "./reasons";
