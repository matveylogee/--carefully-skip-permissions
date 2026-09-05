import { randomUUID } from "node:crypto"
import { spawn } from "node:child_process"
import path from "node:path"
import { createInterface } from "node:readline/promises"
import {
  appendAuditRecord,
  defaultAuditPath,
  hashCommand,
  redactCommand,
  type ApprovalOutcome,
  type AuditRecord,
  type AuditWriter,
} from "./audit.ts"
import { classifyCommand } from "./policy.ts"
import { applyInstallGate, createInstallGate, denyInstallCheck } from "./install-gate.ts"
import { formatInstallReview } from "./install-warnings.ts"
import type { InstallGate } from "./install-types.ts"
import type { Classification, Mode } from "./types.ts"

export type GuardStatus = "EXECUTED" | "BLOCKED" | "REJECTED" | "DRY_RUN" | "AUDIT_ERROR"

export interface ExecutionOutcome {
  exitCode: number
  signal?: NodeJS.Signals
  error?: string
}

export type ShellRunner = (
  command: string,
  options: { cwd: string; environment: NodeJS.ProcessEnv },
) => Promise<ExecutionOutcome>

export type ConfirmationProvider = (
  command: string,
  classification: Classification,
) => Promise<"APPROVED" | "REJECTED" | "UNAVAILABLE">

export interface GuardedExecOptions {
  mode?: Mode
  cwd?: string
  dryRun?: boolean
  auditPath?: string
  /** Set only when an injected runner really enforces a sandbox. */
  sandboxed?: boolean
}

export interface GuardedExecDependencies {
  run?: ShellRunner
  confirm?: ConfirmationProvider
  writeAudit?: AuditWriter
  log?: (message: string) => void
  now?: () => number
  newEventId?: () => string
  environment?: NodeJS.ProcessEnv
  installGate?: InstallGate
}

export interface GuardedExecResult {
  status: GuardStatus
  exitCode: number
  classification: Classification
  approval: ApprovalOutcome
  auditPath: string
  executed: boolean
  signal?: NodeJS.Signals
  durationMs?: number
  error?: string
}

const BLOCKED_ENVIRONMENT_KEYS = new Set([
  "BASH_ENV",
  "CDPATH",
  "ENV",
  "GIT_CONFIG_COUNT",
  "GIT_CONFIG_GLOBAL",
  "GIT_CONFIG_SYSTEM",
  "GIT_EXEC_PATH",
  "GIT_EXTERNAL_DIFF",
  "GIT_TEMPLATE_DIR",
  "IFS",
  "LD_LIBRARY_PATH",
  "LD_PRELOAD",
  "NODE_OPTIONS",
  "NODE_PATH",
  "PERL5LIB",
  "PERL5OPT",
  "PROMPT_COMMAND",
  "PS4",
  "PYTHONINSPECT",
  "PYTHONPATH",
  "PYTHONSTARTUP",
  "RUBYLIB",
  "RUBYOPT",
  "SHELLOPTS",
  "ZDOTDIR",
])

export function sanitizeEnvironment(source: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const result: NodeJS.ProcessEnv = {}
  for (const [key, value] of Object.entries(source)) {
    if (BLOCKED_ENVIRONMENT_KEYS.has(key)) continue
    if (key.startsWith("BASH_FUNC_") || key.startsWith("DYLD_")) continue
    result[key] = value
  }
  result.GIT_PAGER = "cat"
  result.GIT_TERMINAL_PROMPT = "0"
  result.PAGER = "cat"
  return result
}

export const runWithSystemShell: ShellRunner = async (command, options) => {
  if (process.platform === "win32") {
    throw new Error("guarded-exec prototype currently supports POSIX systems only")
  }

  return await new Promise<ExecutionOutcome>((resolve) => {
    let settled = false
    const finish = (outcome: ExecutionOutcome) => {
      if (settled) return
      settled = true
      resolve(outcome)
    }
    const child = spawn("/bin/sh", ["-c", command], {
      cwd: options.cwd,
      env: sanitizeEnvironment(options.environment),
      stdio: "inherit",
      shell: false,
    })
    child.once("error", (error: NodeJS.ErrnoException) => {
      finish({ exitCode: 127, error: error.code ? `${error.code}: ${error.message}` : error.message })
    })
    child.once("close", (code, signal) => {
      finish({ exitCode: code ?? 1, signal: signal ?? undefined })
    })
  })
}

export const confirmInTerminal: ConfirmationProvider = async (command, classification) => {
  if (!process.stdin.isTTY || !process.stderr.isTTY) return "UNAVAILABLE"

  const terminal = createInterface({ input: process.stdin, output: process.stderr })
  try {
    process.stderr.write(`\nCommand: ${JSON.stringify(command)}\n`)
    process.stderr.write(`Reasons: ${classification.reasonCodes.join(", ")}\n`)
    if (classification.installGate) process.stderr.write(`${formatInstallReview(classification.installGate)}\n`)
    const answer = await terminal.question('Type "EXECUTE" to approve this command once: ')
    return answer === "EXECUTE" ? "APPROVED" : "REJECTED"
  } finally {
    terminal.close()
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function resolveAuditPath(cwd: string, requestedPath?: string): string {
  const auditPath = requestedPath ? path.resolve(cwd, requestedPath) : defaultAuditPath(cwd)
  const relative = path.relative(cwd, auditPath)
  if (relative === "" || relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error("audit path must stay inside the working directory")
  }
  if (path.extname(auditPath) !== ".jsonl") throw new Error("audit path must use the .jsonl extension")
  return auditPath
}

export async function guardedExec(
  command: string,
  options: GuardedExecOptions = {},
  dependencies: GuardedExecDependencies = {},
): Promise<GuardedExecResult> {
  if (command.trim() === "") throw new Error("command must not be empty")

  const cwd = path.resolve(options.cwd ?? process.cwd())
  const mode = options.mode ?? "interactive"
  const auditPath = resolveAuditPath(cwd, options.auditPath)
  const installGate = dependencies.installGate ?? createInstallGate({ directory: cwd }, { environment: dependencies.environment })
  let classification = await applyInstallGate(classifyCommand(command, {
    mode,
    cwd,
    workspaceRoot: cwd,
    sandboxed: options.sandboxed ?? false,
  }), installGate, { mode, cwd })
  const log = dependencies.log ?? ((message: string) => console.error(message))
  const confirm = dependencies.confirm ?? confirmInTerminal
  const writeAudit = dependencies.writeAudit ?? appendAuditRecord
  const run = dependencies.run ?? runWithSystemShell
  const now = dependencies.now ?? Date.now
  const eventId = (dependencies.newEventId ?? randomUUID)()
  const commandSha256 = hashCommand(command)
  const commandPreview = redactCommand(command)
  const timestamp = new Date(now()).toISOString()

  log(
    `[CommandGate] policy=${classification.decision} effective=${classification.effectiveDecision} route=${classification.route}`,
  )
  log(`[CommandGate] reasons=${classification.reasonCodes.join(",")}`)

  let approval: ApprovalOutcome
  let status: GuardStatus
  let shouldExecute = false

  if (options.dryRun) {
    approval = "DRY_RUN"
    status = "DRY_RUN"
  } else if (classification.decision === "DENY") {
    approval = "POLICY_DENIED"
    status = "BLOCKED"
  } else if (classification.effectiveDecision === "DENY") {
    approval = "HEADLESS_DENIED"
    status = "BLOCKED"
  } else if (classification.decision === "ASK") {
    const response = await confirm(command, classification)
    approval = response
    shouldExecute = response === "APPROVED"
    status = shouldExecute ? "EXECUTED" : response === "REJECTED" ? "REJECTED" : "BLOCKED"
  } else {
    approval = "NOT_REQUIRED"
    shouldExecute = true
    status = "EXECUTED"
  }

  if (shouldExecute && classification.installGate) {
    let unchanged = false
    try { unchanged = await installGate.unchanged(classification.installGate) } catch { /* fail closed */ }
    if (!unchanged) {
      classification = denyInstallCheck(classification, "IG_PROJECT_CHANGED")
      approval = "POLICY_DENIED"
      shouldExecute = false
      status = "BLOCKED"
      log("[InstallGate] project changed while waiting for approval; command was not executed")
    }
  }

  const decisionRecord: AuditRecord = {
    schemaVersion: 2,
    type: "decision",
    eventId,
    timestamp,
    cwd,
    commandSha256,
    commandPreview,
    policyDecision: classification.decision,
    effectiveDecision: classification.effectiveDecision,
    route: classification.route,
    reasonCodes: classification.reasonCodes,
    approval,
    gatePassed: shouldExecute,
    gateAction: options.dryRun ? "DRY_RUN" : shouldExecute ? "EXECUTE" : "BLOCK",
    enforcementPoint: "GUARDED_EXEC",
    ...(classification.installGate ? { installGate: classification.installGate } : {}),
  }

  try {
    await writeAudit(auditPath, decisionRecord)
  } catch (error) {
    const message = `audit write failed; command was not executed: ${errorMessage(error)}`
    log(`[CommandGate] ${message}`)
    return {
      status: "AUDIT_ERROR",
      exitCode: 125,
      classification,
      approval,
      auditPath,
      executed: false,
      error: message,
    }
  }

  if (!shouldExecute) {
    const explanation = options.dryRun ? "dry-run: command was not executed" : "command was blocked before spawn"
    log(`[CommandGate] ${explanation}`)
    return {
      status,
      exitCode: options.dryRun ? 0 : 126,
      classification,
      approval,
      auditPath,
      executed: false,
    }
  }

  log("[CommandGate] executing command")
  const startedAt = now()
  let outcome: ExecutionOutcome
  try {
    outcome = await run(command, {
      cwd,
      environment: dependencies.environment ?? process.env,
    })
  } catch (error) {
    outcome = { exitCode: 127, error: errorMessage(error) }
  }
  const durationMs = Math.max(0, now() - startedAt)

  const executionRecord: AuditRecord = {
    schemaVersion: 2,
    type: "execution_result",
    eventId,
    timestamp: new Date(now()).toISOString(),
    cwd,
    commandSha256,
    commandPreview,
    outcome: outcome.error ? "RUNNER_ERROR" : "COMPLETED",
    exitCode: outcome.exitCode,
    signal: outcome.signal,
    durationMs,
    executionError: outcome.error,
    enforcementPoint: "GUARDED_EXEC",
  }

  let auditError: string | undefined
  try {
    await writeAudit(auditPath, executionRecord)
  } catch (error) {
    auditError = `could not record execution result: ${errorMessage(error)}`
    log(`[CommandGate] ${auditError}`)
  }

  log(`[CommandGate] finished exit=${outcome.exitCode} duration_ms=${durationMs}`)
  return {
    status: "EXECUTED",
    exitCode: outcome.exitCode,
    classification,
    approval,
    auditPath,
    executed: true,
    signal: outcome.signal,
    durationMs,
    error: outcome.error ?? auditError,
  }
}
