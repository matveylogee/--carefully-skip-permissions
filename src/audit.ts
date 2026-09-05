import { createHash } from "node:crypto"
import { constants } from "node:fs"
import { lstat, mkdir, open } from "node:fs/promises"
import path from "node:path"
import type { Decision, ReasonCode, Route } from "./types.ts"
import type { InstallReport } from "./install-types.ts"

export type ApprovalOutcome =
  | "NOT_REQUIRED"
  | "APPROVED"
  | "REJECTED"
  | "UNAVAILABLE"
  | "POLICY_DENIED"
  | "HEADLESS_DENIED"
  | "DRY_RUN"

export type GateAction = "EXECUTE" | "AUTO_APPROVE_HOST" | "REQUEST_HOST_PERMISSION" | "BLOCK" | "DRY_RUN"

export type PermissionOutcome =
  | "AUTO_APPROVAL_REQUESTED"
  | "AUTO_APPROVED"
  | "AUTO_APPROVAL_FAILED"
  | "APPROVED_ONCE"
  | "APPROVED_ALWAYS"
  | "REJECTED"

interface AuditBase {
  schemaVersion: 2
  eventId: string
  timestamp: string
  cwd: string
  commandSha256: string
  commandPreview: string
  enforcementPoint?: "GUARDED_EXEC" | "KILO_PLUGIN"
  sessionID?: string
  callID?: string
}

export interface DecisionAuditRecord extends AuditBase {
  type: "decision"
  policyDecision: Decision
  effectiveDecision: Decision
  route: Route
  reasonCodes: ReasonCode[]
  approval?: ApprovalOutcome
  /** True means CommandGate handed the call to the next control; it does not claim a process started. */
  gatePassed: boolean
  gateAction: GateAction
  installGate?: InstallReport
}

export interface PermissionAuditRecord extends AuditBase {
  type: "permission_result"
  requestID: string
  permission: string
  outcome: PermissionOutcome
  reply?: "once" | "always" | "reject"
  permissionError?: string
}

export interface ExecutionAuditRecord extends AuditBase {
  type: "execution_result"
  /** Presence of this record means the executor returned after a real invocation. */
  outcome: "COMPLETED" | "RUNNER_ERROR"
  exitCode?: number
  signal?: NodeJS.Signals
  durationMs?: number
  executionError?: string
}

export interface ReviewAuditRecord extends AuditBase {
  type: "review_result"
  /** Publication to the host's UI data is not proof that a person read it. */
  outcome: "PUBLISHED_TO_HOST" | "FAILED"
  surface: "KILO_TOOL_INPUT"
  messageID?: string
  partID?: string
  reviewError?: string
}

export type AuditRecord = DecisionAuditRecord | PermissionAuditRecord | ExecutionAuditRecord | ReviewAuditRecord
export type AuditWriter = (auditPath: string, record: AuditRecord) => Promise<void>

const SENSITIVE_OPTION = /((?:--?|\/)(?:api[-_]?key|password|secret|token|access[-_]?token|client[-_]?secret))(?:=|\s+)([^\s]+)/gi
const SENSITIVE_ASSIGNMENT = /((?:[A-Za-z0-9_]*(?:API_KEY|PASSWORD|SECRET|TOKEN|PRIVATE_KEY)[A-Za-z0-9_]*)=)([^\s]+)/gi
const AUTHORIZATION_HEADER = /(authorization\s*:\s*(?:bearer|basic)\s+)([^\s"']+)/gi
const URL_CREDENTIALS = /(https?:\/\/[^\s/:@]+:)([^\s/@]+)(@)/gi

export function redactCommand(command: string): string {
  const redacted = command
    .replace(AUTHORIZATION_HEADER, "$1<redacted>")
    .replace(SENSITIVE_OPTION, "$1=<redacted>")
    .replace(SENSITIVE_ASSIGNMENT, "$1<redacted>")
    .replace(URL_CREDENTIALS, "$1<redacted>$3")

  return redacted.length <= 512 ? redacted : `${redacted.slice(0, 509)}...`
}

export function hashCommand(command: string): string {
  return createHash("sha256").update(command).digest("hex")
}

export function defaultAuditPath(cwd: string): string {
  return path.join(cwd, ".command-gate", "audit.jsonl")
}

async function ensureAuditDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 })
  const metadata = await lstat(directory)
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error("audit directory must be a real directory, not a symlink")
  }
  if ((metadata.mode & 0o022) !== 0) {
    throw new Error("audit directory must not be writable by group or others")
  }
}

export const appendAuditRecord: AuditWriter = async (auditPath, record) => {
  const directory = path.dirname(auditPath)
  await ensureAuditDirectory(directory)

  const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0
  const handle = await open(
    auditPath,
    constants.O_APPEND | constants.O_CREAT | constants.O_WRONLY | noFollow,
    0o600,
  )
  try {
    const metadata = await handle.stat()
    if (!metadata.isFile() || metadata.nlink !== 1) {
      throw new Error("audit target must be a regular file with exactly one hard link")
    }
    await handle.chmod(0o600)
    await handle.appendFile(`${JSON.stringify(record)}\n`, "utf8")
    await handle.sync()
  } finally {
    await handle.close()
  }
}
