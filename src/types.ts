import type { InstallReasonCode, InstallReport } from "./install-types.ts"

export type Decision = "ALLOW" | "ASK" | "DENY"
export type EffectiveDecision = Decision
export type Route = "COMMAND_GATE" | "INSTALL_GATE" | "COMPOSITE"
export type Mode = "interactive" | "headless"

export type ReasonCode =
  | InstallReasonCode
  | "READ_ONLY_COMMAND"
  | "READ_ONLY_GIT"
  | "VERSION_QUERY"
  | "UNKNOWN_COMMAND"
  | "EMPTY_COMMAND"
  | "PARSE_ERROR"
  | "DYNAMIC_SHELL"
  | "BACKGROUND_EXECUTION"
  | "OUTPUT_REDIRECTION"
  | "SENSITIVE_PATH_READ"
  | "SENSITIVE_PATH_WRITE"
  | "SECRET_ACCESS"
  | "FILESYSTEM_WRITE"
  | "FILESYSTEM_DELETE"
  | "CATASTROPHIC_DELETE"
  | "DISK_DESTRUCTION"
  | "PRIVILEGE_ESCALATION"
  | "PROCESS_CONTROL"
  | "SYSTEM_CONTROL"
  | "GIT_STATE_CHANGE"
  | "GIT_DESTRUCTIVE"
  | "GIT_REMOTE_WRITE"
  | "NETWORK_ACCESS"
  | "DATA_EXFILTRATION"
  | "REMOTE_CODE_EXECUTION"
  | "LOCAL_CODE_EXECUTION"
  | "PROJECT_CODE_EXECUTION"
  | "PACKAGE_INSTALL"
  | "PACKAGE_PUBLISH"
  | "UNSUPPORTED_PACKAGE_MANAGER"
  | "EXTERNAL_SIDE_EFFECT"
  | "POLICY_TAMPERING"
  | "UNSUPPORTED_SHELL_SYNTAX"

export interface CommandContext {
  mode?: Mode
  cwd?: string
  workspaceRoot?: string
  sandboxed?: boolean
}

export interface Redirection {
  operator: string
  target?: string
}

export interface SimpleCommand {
  raw: string
  argv: string[]
  redirections: Redirection[]
}

export interface ScanResult {
  commands: SimpleCommand[]
  connectors: string[]
  hasDynamicExpansion: boolean
  hasBackgroundExecution: boolean
  hasUnsupportedSyntax: boolean
  errors: string[]
}

export interface CommandFinding {
  command: string
  executable?: string
  decision: Decision
  route: Route
  reasonCodes: ReasonCode[]
  detail?: string
}

export interface Classification {
  command: string
  decision: Decision
  effectiveDecision: EffectiveDecision
  route: Route
  reasonCodes: ReasonCode[]
  findings: CommandFinding[]
  parseErrors: string[]
  installGate?: InstallReport
}
