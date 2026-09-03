export { classifyCommand } from "./policy.ts"
export { scanShell } from "./scanner.ts"
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
