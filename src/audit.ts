import { createHash } from "node:crypto"
import { constants } from "node:fs"
import { lstat, mkdir, open } from "node:fs/promises"
import path from "node:path"
import type { Decision, ReasonCode, Route } from "./types.ts"

export type ApprovalOutcome =
  | "NOT_REQUIRED"
  | "APPROVED"
  | "REJECTED"
  | "UNAVAILABLE"
  | "POLICY_DENIED"
  | "HEADLESS_DENIED"
  | "DRY_RUN"

interface AuditBase {
  schemaVersion: 1
  eventId: string
  timestamp: string
  cwd: string
  commandSha256: string
  commandPreview: string
}

export interface DecisionAuditRecord extends AuditBase {
  type: "decision"
  policyDecision: Decision
  effectiveDecision: Decision
  route: Route
  reasonCodes: ReasonCode[]
  approval: ApprovalOutcome
  willExecute: boolean
}

export interface ExecutionAuditRecord extends AuditBase {
  type: "execution_result"
  exitCode: number
  signal?: NodeJS.Signals
  durationMs: number
  executionError?: string
}

export type AuditRecord = DecisionAuditRecord | ExecutionAuditRecord
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
