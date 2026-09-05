export { classifyCommand } from "./policy.ts"
export { scanShell } from "./scanner.ts"
export { createInstallGate, applyInstallGate } from "./install-gate.ts"
export { createNpmRegistry, parseNpmMetadata } from "./install-registry.ts"
export { extractInstallRequest, parsePackageSpec } from "./install-parser.ts"
export { levenshtein, similarNpmName } from "./install-similarity.ts"
export { KNOWN_MALICIOUS_NPM } from "./install-known-malicious.ts"
export { formatInstallReview } from "./install-warnings.ts"
export { createKiloReviewPublisher } from "./kilo-review.ts"
export type { KiloReviewInput, KiloReviewReceipt, KiloReviewPublisher } from "./kilo-review.ts"
export type { InstallGate, InstallReport, PackageEvidence, RegistryProvider, KnownMaliciousRecord, MaliciousEvidence, InstallWarning } from "./install-types.ts"
export { appendAuditRecord, defaultAuditPath, hashCommand, redactCommand } from "./audit.ts"
export { confirmInTerminal, guardedExec, runWithSystemShell, sanitizeEnvironment } from "./guarded-exec.ts"
export {
  createKiloCommandGateHook,
  createKiloCommandGatePlugin,
  createKiloPermissionReplier,
  detectKiloMode,
  KiloCommandBlockedError,
} from "./kilo-plugin.ts"
export type {
  ApprovalOutcome,
  AuditRecord,
  AuditWriter,
  DecisionAuditRecord,
  ExecutionAuditRecord,
  GateAction,
  PermissionAuditRecord,
  PermissionOutcome,
  ReviewAuditRecord,
} from "./audit.ts"
export type {
  ConfirmationProvider,
  ExecutionOutcome,
  GuardedExecDependencies,
  GuardedExecOptions,
  GuardedExecResult,
  GuardStatus,
  ShellRunner,
} from "./guarded-exec.ts"
export type {
  KiloCommandGateDependencies,
  KiloCommandGateHookOptions,
  KiloCommandGatePluginHooks,
  KiloEventHookInput,
  KiloPermissionHookOutput,
  KiloPermissionReply,
  KiloToolAfterHookInput,
  KiloToolAfterHookOutput,
  KiloToolHookInput,
  KiloToolHookOutput,
  PermissionReplier,
} from "./kilo-plugin.ts"
export type {
  Classification,
  CommandContext,
  CommandFinding,
  Decision,
  EffectiveDecision,
  Mode,
  ReasonCode,
  Route,
  ScanResult,
  SimpleCommand,
} from "./types.ts"
