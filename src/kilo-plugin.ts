import { randomUUID } from "node:crypto"
import path from "node:path"
import type { Plugin } from "@kilocode/plugin"
import {
  appendAuditRecord,
  defaultAuditPath,
  hashCommand,
  redactCommand,
  type ApprovalOutcome,
  type AuditWriter,
  type DecisionAuditRecord,
  type ExecutionAuditRecord,
  type GateAction,
  type PermissionAuditRecord,
  type PermissionOutcome,
} from "./audit.ts"
import { classifyCommand } from "./policy.ts"
import { applyInstallGate, createInstallGate } from "./install-gate.ts"
import { formatInstallReview } from "./install-warnings.ts"
import { createKiloReviewPublisher, type KiloReviewPublisher, type KiloReviewReceipt } from "./kilo-review.ts"
import type { InstallGate } from "./install-types.ts"
import type { Classification, Mode } from "./types.ts"

export interface KiloToolHookInput {
  tool: string
  sessionID: string
  callID: string
}

export interface KiloToolHookOutput {
  args: unknown
}

export interface KiloToolAfterHookInput extends KiloToolHookInput {
  args: unknown
}

export interface KiloToolAfterHookOutput {
  title?: string
  output?: string
  metadata?: unknown
}

export interface KiloEventHookInput {
  event: {
    id?: string
    type: string
    properties?: unknown
  }
}

export interface KiloPermissionHookOutput {
  status: "ask" | "deny" | "allow"
}

export interface KiloPermissionReply {
  sessionID: string
  requestID: string
  reply: "once" | "always" | "reject"
}

export type PermissionReplier = (input: KiloPermissionReply) => Promise<unknown>

export interface KiloCommandGateDependencies {
  classify?: typeof classifyCommand
  writeAudit?: AuditWriter
  replyPermission?: PermissionReplier
  publishReview?: KiloReviewPublisher
  now?: () => number
  newEventId?: () => string
  onBackgroundError?: (error: unknown) => void
  installGate?: InstallGate
}

export interface KiloCommandGateHookOptions {
  directory: string
  mode?: Mode
}

export interface KiloCommandGatePluginHooks {
  "tool.execute.before": (input: KiloToolHookInput, output: KiloToolHookOutput) => Promise<void>
  "tool.execute.after": (input: KiloToolAfterHookInput, output: KiloToolAfterHookOutput) => Promise<void>
  "permission.ask": (input: unknown, output: KiloPermissionHookOutput) => Promise<void>
  event: (input: KiloEventHookInput) => Promise<void>
}

interface PendingCall {
  sessionID: string
  callID: string
  command: string
  cwd: string
  commandSha256: string
  commandPreview: string
  classification: Classification
}

interface PermissionRequestLink {
  callKey: string
  autoManaged: boolean
}

interface PermissionRequest {
  id: string
  sessionID: string
  permission: string
  callID?: string
  command?: string
}

const CALL_TTL_MS = 10 * 60 * 1000
const MAX_PENDING_CALLS = 1_000

export class KiloCommandBlockedError extends Error {
  readonly classification: Classification

  constructor(classification: Classification) {
    const reasons = classification.reasonCodes.join(",") || "UNSPECIFIED"
    super(
      [
        "[CommandGate] blocked before spawn",
        `policy=${classification.decision}`,
        `effective=${classification.effectiveDecision}`,
        `route=${classification.route}`,
        `reasons=${reasons}`,
        ...(classification.installGate ? [
          formatInstallReview(classification.installGate),
          ...(classification.decision === "ASK" ? ["No human approval is available in headless mode; the package is not automatically labelled malicious"] : []),
        ] : []),
        "No process was started. Choose a read-only alternative or ask the user for a different action.",
      ].join("; "),
    )
    this.name = "KiloCommandBlockedError"
    this.classification = classification
  }
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message
  if (typeof error === "string") return error
  try {
    return JSON.stringify(error)
  } catch {
    return String(error)
  }
}

function blockedApproval(classification: Classification): ApprovalOutcome | undefined {
  if (classification.decision === "DENY") return "POLICY_DENIED"
  if (classification.effectiveDecision === "DENY") return "HEADLESS_DENIED"
  return undefined
}

function gateAction(classification: Classification): GateAction {
  if (classification.effectiveDecision === "DENY") return "BLOCK"
  if (classification.decision === "ASK") return "REQUEST_HOST_PERMISSION"
  return "AUTO_APPROVE_HOST"
}

function objectArgs(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {}
  return value as Record<string, unknown>
}

/**
 * Kilo 7.5.9 injects the legacy `@kilocode/sdk` client into server plugins.
 * Its permission endpoint is a root-level generated method, while the newer
 * SDK exposes `client.permission.reply`. Keep the transport detail behind one
 * adapter so the policy/enforcement code does not depend on either SDK shape.
 */
export function createKiloPermissionReplier(client: unknown): PermissionReplier {
  const candidate = objectArgs(client)
  const legacyReply = candidate.postSessionIdPermissionsPermissionId
  if (typeof legacyReply === "function") {
    return async ({ sessionID, requestID, reply }) =>
      await legacyReply.call(candidate, {
        path: { id: sessionID, permissionID: requestID },
        body: { response: reply },
      })
  }

  const permission = objectArgs(candidate.permission)
  const namespacedReply = permission.reply
  if (typeof namespacedReply === "function") {
    return async ({ requestID, reply }) => await namespacedReply.call(permission, { requestID, reply })
  }

  return async () => {
    throw new Error("Kilo client does not expose a supported permission reply API")
  }
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined
}

function commandCwd(directory: string, args: Record<string, unknown>): string {
  const workdir = args.workdir
  if (typeof workdir !== "string" || workdir.trim() === "") return directory
  return path.resolve(directory, workdir)
}

function malformedClassification(command: string): Classification {
  return {
    command,
    decision: "DENY",
    effectiveDecision: "DENY",
    route: "COMMAND_GATE",
    reasonCodes: ["EMPTY_COMMAND"],
    findings: [
      {
        command,
        decision: "DENY",
        route: "COMMAND_GATE",
        reasonCodes: ["EMPTY_COMMAND"],
        detail: "Kilo bash tool call did not contain a non-empty command string",
      },
    ],
    parseErrors: [],
  }
}

function callKey(sessionID: string, callID: string): string {
  return `${sessionID}\u0000${callID}`
}

function parsePermissionRequest(value: unknown): PermissionRequest | undefined {
  const properties = objectArgs(value)
  const id = stringValue(properties.id)
  const sessionID = stringValue(properties.sessionID)
  const permission = stringValue(properties.permission)
  if (!id || !sessionID || !permission) return undefined

  const tool = objectArgs(properties.tool)
  const metadata = objectArgs(properties.metadata)
  return {
    id,
    sessionID,
    permission,
    callID: stringValue(tool.callID),
    command: stringValue(metadata.command),
  }
}

function parsePermissionReply(value: unknown):
  | { requestID: string; sessionID?: string; reply: "once" | "always" | "reject" }
  | undefined {
  const properties = objectArgs(value)
  const requestID = stringValue(properties.requestID)
  const reply = properties.reply
  if (!requestID || (reply !== "once" && reply !== "always" && reply !== "reject")) return undefined
  return { requestID, sessionID: stringValue(properties.sessionID), reply }
}

function permissionOutcome(reply: "once" | "always" | "reject"): PermissionOutcome {
  if (reply === "reject") return "REJECTED"
  if (reply === "always") return "APPROVED_ALWAYS"
  return "APPROVED_ONCE"
}

function numericExitCode(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isInteger(value)) return value
  if (typeof value === "string" && /^-?\d+$/.test(value)) return Number(value)
  return undefined
}

/**
 * Detect the CLI shape conservatively. An explicit override is useful for hosts
 * which embed Kilo and do not preserve its original argv.
 */
export function detectKiloMode(
  argv: readonly string[] = process.argv,
  environment: NodeJS.ProcessEnv = process.env,
): Mode {
  const override = environment.KILO_COMMAND_GATE_MODE
  if (override === "interactive" || override === "headless") return override
  if (override !== undefined) return "headless"

  const args = argv.slice(1)
  if (args.some((arg) => arg === "run" || arg === "--auto" || arg.startsWith("--auto="))) return "headless"
  return "interactive"
}

/**
 * Build the complete Kilo bridge. `tool.execute.before` is the mandatory veto
 * point. In Kilo 7.5.9, a safe command is auto-approved by correlating the
 * subsequent `permission.asked` event to the exact session, call and command.
 * ASK is left to Kilo's native UI in interactive mode and is denied in headless
 * mode. `tool.execute.after` is the first hook that can honestly prove that the
 * executor returned after a real invocation.
 */
export function createKiloCommandGatePlugin(
  options: KiloCommandGateHookOptions,
  dependencies: KiloCommandGateDependencies = {},
): KiloCommandGatePluginHooks {
  const directory = path.resolve(options.directory)
  const mode = options.mode ?? detectKiloMode()
  const classify = dependencies.classify ?? classifyCommand
  const installGate = dependencies.installGate ?? createInstallGate({ directory })
  const writeAudit = dependencies.writeAudit ?? appendAuditRecord
  const replyPermission = dependencies.replyPermission
  const now = dependencies.now ?? Date.now
  const newEventId = dependencies.newEventId ?? randomUUID
  const onBackgroundError =
    dependencies.onBackgroundError ??
    ((error: unknown) => console.error(`[CommandGate] background hook failed: ${errorMessage(error)}`))
  const auditPath = defaultAuditPath(directory)
  const calls = new Map<string, { value: PendingCall; createdAt: number }>()
  const permissionRequests = new Map<string, PermissionRequestLink>()

  function pruneCalls(): void {
    const cutoff = now() - CALL_TTL_MS
    for (const [key, entry] of calls) {
      if (entry.createdAt < cutoff) calls.delete(key)
    }
    while (calls.size >= MAX_PENDING_CALLS) {
      const oldest = calls.keys().next().value as string | undefined
      if (!oldest) break
      calls.delete(oldest)
    }
  }

  function findCall(request: PermissionRequest): { key: string; call: PendingCall } | undefined {
    if (!request.callID) return undefined
    const key = callKey(request.sessionID, request.callID)
    const entry = calls.get(key)
    if (!entry) return undefined
    if (!request.command || hashCommand(request.command) !== entry.value.commandSha256) return undefined
    return { key, call: entry.value }
  }

  async function writePermissionRecord(
    call: PendingCall,
    requestID: string,
    permission: string,
    outcome: PermissionOutcome,
    extra: Pick<PermissionAuditRecord, "reply" | "permissionError"> = {},
  ): Promise<void> {
    const record: PermissionAuditRecord = {
      schemaVersion: 2,
      type: "permission_result",
      eventId: newEventId(),
      timestamp: new Date(now()).toISOString(),
      cwd: call.cwd,
      commandSha256: call.commandSha256,
      commandPreview: call.commandPreview,
      enforcementPoint: "KILO_PLUGIN",
      sessionID: call.sessionID,
      callID: call.callID,
      requestID,
      permission,
      outcome,
      ...extra,
    }
    await writeAudit(auditPath, record)
  }

  const before = async (input: KiloToolHookInput, output: KiloToolHookOutput): Promise<void> => {
    // Complete the startup snapshot even before non-shell edits can change package.json.
    await installGate.ready
    if (input.tool !== "bash") return
    pruneCalls()

    const args = objectArgs(output.args)
    const command = typeof args.command === "string" ? args.command : ""
    const cwd = commandCwd(directory, args)
    const commandClassification =
      command.trim() === ""
        ? malformedClassification(command)
        : classify(command, {
            mode,
            cwd,
            workspaceRoot: directory,
            // The pre-hook cannot prove that Kilo's optional OS sandbox is active.
            sandboxed: false,
          })
    const classification = await applyInstallGate(commandClassification, installGate, { mode, cwd })
    let review: KiloReviewReceipt | undefined
    let reviewError: string | undefined
    if (classification.installGate && classification.effectiveDecision === "ASK") {
      args.description = formatInstallReview(classification.installGate, 2_000)
      try {
        if (!dependencies.publishReview) throw new Error("Kilo review publisher is unavailable")
        review = await dependencies.publishReview({
          sessionID: input.sessionID, callID: input.callID, command, description: args.description as string,
        })
      } catch (error) {
        reviewError = errorMessage(error)
      }
    }
    const action = reviewError ? "BLOCK" : gateAction(classification)
    const passed = action !== "BLOCK"
    const approval = blockedApproval(classification)
    const record: DecisionAuditRecord = {
      schemaVersion: 2,
      type: "decision",
      eventId: newEventId(),
      timestamp: new Date(now()).toISOString(),
      cwd,
      commandSha256: hashCommand(command),
      commandPreview: redactCommand(command),
      policyDecision: classification.decision,
      effectiveDecision: classification.effectiveDecision,
      route: classification.route,
      reasonCodes: classification.reasonCodes,
      ...(approval ? { approval } : {}),
      gatePassed: passed,
      gateAction: action,
      enforcementPoint: "KILO_PLUGIN",
      sessionID: input.sessionID,
      callID: input.callID,
      ...(classification.installGate ? { installGate: classification.installGate } : {}),
    }

    // Fail closed: a missing decision audit prevents Kilo from reaching permission or spawn.
    await writeAudit(auditPath, record)
    if (review || reviewError) {
      await writeAudit(auditPath, {
        schemaVersion: 2, type: "review_result", eventId: newEventId(), timestamp: new Date(now()).toISOString(),
        cwd, commandSha256: record.commandSha256, commandPreview: record.commandPreview,
        enforcementPoint: "KILO_PLUGIN", sessionID: input.sessionID, callID: input.callID,
        surface: "KILO_TOOL_INPUT", outcome: reviewError ? "FAILED" : "PUBLISHED_TO_HOST",
        ...(review ?? {}), ...(reviewError ? { reviewError } : {}),
      })
    }
    if (reviewError) {
      throw new Error(`[InstallGate] Could not publish the risk review to Kilo: ${reviewError}. No process was started. Restart Kilo with a compatible plugin before retrying. This is a UI integration failure, not a malware verdict.`)
    }
    if (!passed) throw new KiloCommandBlockedError(classification)

    calls.set(callKey(input.sessionID, input.callID), {
      createdAt: now(),
      value: {
        sessionID: input.sessionID,
        callID: input.callID,
        command,
        cwd,
        commandSha256: record.commandSha256,
        commandPreview: record.commandPreview,
        classification,
      },
    })
  }

  const after = async (input: KiloToolAfterHookInput, output: KiloToolAfterHookOutput): Promise<void> => {
    if (input.tool !== "bash") return

    const key = callKey(input.sessionID, input.callID)
    const pending = calls.get(key)?.value
    const args = objectArgs(input.args)
    const command = pending?.command ?? (typeof args.command === "string" ? args.command : "")
    const cwd = pending?.cwd ?? commandCwd(directory, args)
    const metadata = objectArgs(output.metadata)
    const exitCode = numericExitCode(metadata.exit)
    const executionError = stringValue(metadata.error)
    const record: ExecutionAuditRecord = {
      schemaVersion: 2,
      type: "execution_result",
      eventId: newEventId(),
      timestamp: new Date(now()).toISOString(),
      cwd,
      commandSha256: pending?.commandSha256 ?? hashCommand(command),
      commandPreview: pending?.commandPreview ?? redactCommand(command),
      enforcementPoint: "KILO_PLUGIN",
      sessionID: input.sessionID,
      callID: input.callID,
      outcome: executionError ? "RUNNER_ERROR" : "COMPLETED",
      ...(exitCode === undefined ? {} : { exitCode }),
      ...(executionError ? { executionError } : {}),
    }

    try {
      // This runs only after Kilo's real bash executor returned.
      await writeAudit(auditPath, record)
    } finally {
      calls.delete(key)
      for (const [requestID, link] of permissionRequests) {
        if (link.callKey === key) permissionRequests.delete(requestID)
      }
    }
  }

  async function handlePermissionAsked(properties: unknown): Promise<void> {
    const request = parsePermissionRequest(properties)
    if (!request || request.permission !== "bash") return
    const found = findCall(request)
    if (!found) return

    const shouldAutoApprove = found.call.classification.decision === "ALLOW" && replyPermission !== undefined
    // Start as a manual request. It becomes auto-managed only after the
    // pre-release audit succeeds, so an audit failure leaves an honest prompt.
    permissionRequests.set(request.id, { callKey: found.key, autoManaged: false })
    if (!shouldAutoApprove || !replyPermission) return

    // Audit intent before sending the approval which can release the executor.
    await writePermissionRecord(found.call, request.id, request.permission, "AUTO_APPROVAL_REQUESTED", {
      reply: "once",
    })
    permissionRequests.set(request.id, { callKey: found.key, autoManaged: true })
    try {
      const response = await replyPermission({
        sessionID: request.sessionID,
        requestID: request.id,
        reply: "once",
      })
      const responseObject = objectArgs(response)
      if (responseObject.error) throw new Error(errorMessage(responseObject.error))
      await writePermissionRecord(found.call, request.id, request.permission, "AUTO_APPROVED", { reply: "once" })
    } catch (error) {
      permissionRequests.set(request.id, { callKey: found.key, autoManaged: false })
      try {
        await writePermissionRecord(found.call, request.id, request.permission, "AUTO_APPROVAL_FAILED", {
          reply: "once",
          permissionError: errorMessage(error),
        })
      } catch (auditError) {
        onBackgroundError(auditError)
      }
      onBackgroundError(error)
    }
  }

  async function handlePermissionReplied(properties: unknown): Promise<void> {
    const reply = parsePermissionReply(properties)
    if (!reply) return
    const link = permissionRequests.get(reply.requestID)
    if (!link) return
    permissionRequests.delete(reply.requestID)

    // Auto-managed replies are already recorded by handlePermissionAsked.
    if (link.autoManaged) return
    const pending = calls.get(link.callKey)?.value
    if (!pending) return
    await writePermissionRecord(pending, reply.requestID, "bash", permissionOutcome(reply.reply), {
      reply: reply.reply,
    })
    if (reply.reply === "reject") calls.delete(link.callKey)
  }

  const event = async (input: KiloEventHookInput): Promise<void> => {
    try {
      if (input.event.type === "permission.asked") {
        await handlePermissionAsked(input.event.properties)
        return
      }
      if (input.event.type === "permission.replied") await handlePermissionReplied(input.event.properties)
    } catch (error) {
      // Kilo 7.5.9 dispatches event hooks in the background. Never create an
      // unhandled rejection; an ALLOW auto-approval is simply withheld on error.
      onBackgroundError(error)
    }
  }

  const permissionAsk = async (input: unknown, output: KiloPermissionHookOutput): Promise<void> => {
    const request = parsePermissionRequest(input)
    if (!request || request.permission !== "bash") return
    const found = findCall(request)
    if (!found) return

    if (found.call.classification.decision === "ALLOW") {
      await writePermissionRecord(found.call, request.id, request.permission, "AUTO_APPROVED", { reply: "once" })
      output.status = "allow"
      return
    }
    if (found.call.classification.effectiveDecision === "DENY") {
      output.status = "deny"
      return
    }
    output.status = "ask"
  }

  return {
    "tool.execute.before": before,
    "tool.execute.after": after,
    "permission.ask": permissionAsk,
    event,
  }
}

/** Backwards-compatible factory for tests and hosts that need only the veto hook. */
export function createKiloCommandGateHook(
  options: KiloCommandGateHookOptions,
  dependencies: KiloCommandGateDependencies = {},
) {
  return createKiloCommandGatePlugin(options, dependencies)["tool.execute.before"]
}

const server: Plugin = async ({ directory, client }) => {
  const installGate = createInstallGate({ directory })
  await installGate.ready
  const hooks = createKiloCommandGatePlugin(
    { directory, mode: detectKiloMode() },
    {
      replyPermission: createKiloPermissionReplier(client),
      publishReview: createKiloReviewPublisher(client),
      installGate,
    },
  )
  return hooks
}

export default {
  id: "carefully-skip-permissions-command-gate",
  server,
}
