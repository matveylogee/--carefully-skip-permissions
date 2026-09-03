import assert from "node:assert/strict"
import { mkdtemp, readFile, rm } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import test from "node:test"
import type {
  AuditRecord,
  DecisionAuditRecord,
  ExecutionAuditRecord,
  PermissionAuditRecord,
} from "../src/audit.ts"
import { classifyCommand as productionClassify } from "../src/policy.ts"
import kiloPlugin from "../src/kilo-plugin.ts"
import {
  createKiloCommandGatePlugin,
  createKiloPermissionReplier,
  detectKiloMode,
  KiloCommandBlockedError,
  type KiloCommandGateDependencies,
  type KiloPermissionReply,
} from "../src/kilo-plugin.ts"

function state(options: { failAuditAt?: number; replyError?: unknown } = {}) {
  const records: AuditRecord[] = []
  const replies: KiloPermissionReply[] = []
  const backgroundErrors: unknown[] = []
  let classifications = 0
  let auditAttempts = 0
  let eventIDs = 0
  let clock = Date.parse("2026-09-03T16:00:00.000Z")
  const dependencies: KiloCommandGateDependencies = {
    writeAudit: async (_auditPath, record) => {
      auditAttempts += 1
      if (options.failAuditAt === auditAttempts) throw new Error("simulated audit failure")
      records.push(record)
    },
    replyPermission: async (reply) => {
      replies.push(reply)
      return options.replyError === undefined ? { data: true } : { error: options.replyError }
    },
    onBackgroundError: (error) => backgroundErrors.push(error),
    newEventId: () => `kilo-event-${++eventIDs}`,
    now: () => (clock += 5),
    classify: (command, context) => {
      classifications += 1
      return productionClassify(command, context)
    },
  }
  return {
    dependencies,
    records,
    replies,
    backgroundErrors,
    classifications: () => classifications,
  }
}

const input = { tool: "bash", sessionID: "session-1", callID: "call-1" }

function permissionAsked(command: string, overrides: Record<string, unknown> = {}) {
  return {
    event: {
      type: "permission.asked",
      properties: {
        id: "permission-1",
        sessionID: "session-1",
        permission: "bash",
        patterns: [command],
        metadata: { command },
        tool: { callID: "call-1" },
        ...overrides,
      },
    },
  }
}

test("mode detection distinguishes TUI, run --auto and explicit overrides", () => {
  assert.equal(detectKiloMode(["kilo"], {}), "interactive")
  assert.equal(detectKiloMode(["kilo", "run", "task"], {}), "headless")
  assert.equal(detectKiloMode(["kilo", "run", "--auto", "task"], {}), "headless")
  assert.equal(detectKiloMode(["kilo"], { KILO_COMMAND_GATE_MODE: "headless" }), "headless")
  assert.equal(detectKiloMode(["kilo", "run"], { KILO_COMMAND_GATE_MODE: "interactive" }), "interactive")
  assert.equal(detectKiloMode(["kilo"], { KILO_COMMAND_GATE_MODE: "invalid" }), "headless")
})

test("Kilo 7.5.9 permission adapter calls the legacy root endpoint", async () => {
  const calls: unknown[] = []
  const reply = createKiloPermissionReplier({
    async postSessionIdPermissionsPermissionId(options: unknown) {
      calls.push(options)
      return { data: true }
    },
  })

  const response = await reply({
    sessionID: "session-1",
    requestID: "permission-1",
    reply: "once",
  })

  assert.deepEqual(calls, [
    {
      path: { id: "session-1", permissionID: "permission-1" },
      body: { response: "once" },
    },
  ])
  assert.deepEqual(response, { data: true })
})

test("permission adapter also supports the newer namespaced SDK", async () => {
  const calls: unknown[] = []
  const reply = createKiloPermissionReplier({
    permission: {
      async reply(input: unknown) {
        calls.push(input)
        return { data: true }
      },
    },
  })

  await reply({ sessionID: "session-1", requestID: "permission-1", reply: "once" })

  assert.deepEqual(calls, [{ requestID: "permission-1", reply: "once" }])
})

test("missing permission SDK stays fail-safe with an actionable error", async () => {
  const reply = createKiloPermissionReplier({})

  await assert.rejects(
    reply({ sessionID: "session-1", requestID: "permission-1", reply: "once" }),
    /does not expose a supported permission reply API/,
  )
})

test("default Kilo plugin wires the 7.5.9 client into the permission adapter", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "kilo-command-gate-server-"))
  t.after(async () => await rm(directory, { recursive: true, force: true }))
  const calls: unknown[] = []
  const hooks = await kiloPlugin.server({
    directory,
    client: {
      async postSessionIdPermissionsPermissionId(options: unknown) {
        calls.push(options)
        return { data: true }
      },
    },
  } as never)

  const command = "git status --short"
  await hooks["tool.execute.before"]?.(input, { args: { command } })
  await hooks.event?.(permissionAsked(command))

  assert.deepEqual(calls, [
    {
      path: { id: "session-1", permissionID: "permission-1" },
      body: { response: "once" },
    },
  ])
})

test("non-shell tools pass through without classification or audit", async () => {
  const current = state()
  const hooks = createKiloCommandGatePlugin({ directory: "/tmp/project", mode: "interactive" }, current.dependencies)

  await hooks["tool.execute.before"]({ ...input, tool: "read" }, { args: { filePath: "README.md" } })

  assert.equal(current.classifications(), 0)
  assert.deepEqual(current.records, [])
})

test("ALLOW is honestly recorded as a gate pass, not as execution", async () => {
  const current = state()
  const hooks = createKiloCommandGatePlugin({ directory: "/tmp/project", mode: "interactive" }, current.dependencies)

  await hooks["tool.execute.before"](input, { args: { command: "git status --short" } })

  assert.equal(current.records.length, 1)
  const record = current.records[0] as DecisionAuditRecord
  assert.equal(record.policyDecision, "ALLOW")
  assert.equal(record.effectiveDecision, "ALLOW")
  assert.equal(record.gatePassed, true)
  assert.equal(record.gateAction, "AUTO_APPROVE_HOST")
  assert.equal("willExecute" in record, false)
  assert.equal(record.enforcementPoint, "KILO_PLUGIN")
})

test("an exact ALLOW permission is auto-approved once and audited before release", async () => {
  const current = state()
  const hooks = createKiloCommandGatePlugin({ directory: "/tmp/project", mode: "interactive" }, current.dependencies)
  const command = "git status --short"

  await hooks["tool.execute.before"](input, { args: { command } })
  await hooks.event(permissionAsked(command))

  assert.deepEqual(current.replies, [
    { sessionID: "session-1", requestID: "permission-1", reply: "once" },
  ])
  assert.deepEqual(current.records.map((record) => record.type), [
    "decision",
    "permission_result",
    "permission_result",
  ])
  assert.deepEqual(
    current.records.slice(1).map((record) => (record as PermissionAuditRecord).outcome),
    ["AUTO_APPROVAL_REQUESTED", "AUTO_APPROVED"],
  )
  assert.deepEqual(current.backgroundErrors, [])
})

test("auto-approval requires the exact session, call and command", async () => {
  const current = state()
  const hooks = createKiloCommandGatePlugin({ directory: "/tmp/project", mode: "interactive" }, current.dependencies)
  await hooks["tool.execute.before"](input, { args: { command: "git status --short" } })

  await hooks.event(permissionAsked("git status --short", { sessionID: "other-session" }))
  await hooks.event(permissionAsked("git status --short", { tool: { callID: "other-call" } }))
  await hooks.event(permissionAsked("git status"))

  assert.deepEqual(current.replies, [])
  assert.equal(current.records.length, 1)
})

test("non-bash permissions are never auto-approved", async () => {
  const current = state()
  const hooks = createKiloCommandGatePlugin({ directory: "/tmp/project", mode: "interactive" }, current.dependencies)
  const command = "git status --short"
  await hooks["tool.execute.before"](input, { args: { command } })

  await hooks.event(permissionAsked(command, { permission: "external_directory" }))

  assert.deepEqual(current.replies, [])
})

test("interactive ASK reaches Kilo's native permission prompt", async () => {
  const current = state()
  const hooks = createKiloCommandGatePlugin({ directory: "/tmp/project", mode: "interactive" }, current.dependencies)
  const command = "touch ask-canary.txt"

  await hooks["tool.execute.before"](input, { args: { command } })
  await hooks.event(permissionAsked(command))

  const decision = current.records[0] as DecisionAuditRecord
  assert.equal(decision.policyDecision, "ASK")
  assert.equal(decision.effectiveDecision, "ASK")
  assert.equal(decision.gatePassed, true)
  assert.equal(decision.gateAction, "REQUEST_HOST_PERMISSION")
  assert.deepEqual(current.replies, [])

  await hooks.event({
    event: {
      type: "permission.replied",
      properties: { requestID: "permission-1", sessionID: "session-1", reply: "reject" },
    },
  })
  const permission = current.records.at(-1) as PermissionAuditRecord
  assert.equal(permission.outcome, "REJECTED")
})

test("headless ASK fails closed before Kilo can auto-approve it", async () => {
  const current = state()
  const hooks = createKiloCommandGatePlugin({ directory: "/tmp/project", mode: "headless" }, current.dependencies)

  await assert.rejects(
    hooks["tool.execute.before"](input, { args: { command: "touch ask-canary.txt" } }),
    (error: unknown) =>
      error instanceof KiloCommandBlockedError &&
      error.classification.decision === "ASK" &&
      error.classification.effectiveDecision === "DENY",
  )

  const record = current.records[0] as DecisionAuditRecord
  assert.equal(record.approval, "HEADLESS_DENIED")
  assert.equal(record.gatePassed, false)
  assert.equal(record.gateAction, "BLOCK")
})

test("DENY is audited and blocked in every mode", async () => {
  const current = state()
  const hooks = createKiloCommandGatePlugin({ directory: "/tmp/project", mode: "interactive" }, current.dependencies)

  await assert.rejects(
    hooks["tool.execute.before"](input, { args: { command: "echo evil > .npmrc" } }),
    KiloCommandBlockedError,
  )

  const record = current.records[0] as DecisionAuditRecord
  assert.equal(record.policyDecision, "DENY")
  assert.equal(record.approval, "POLICY_DENIED")
  assert.equal(record.gatePassed, false)
})

test("tool.execute.after records the actual executor result", async () => {
  const current = state()
  const hooks = createKiloCommandGatePlugin({ directory: "/tmp/project", mode: "interactive" }, current.dependencies)

  await hooks["tool.execute.before"](input, { args: { command: "pwd" } })
  await hooks["tool.execute.after"](
    { ...input, args: { command: "pwd" } },
    { title: "pwd", output: "/tmp/project", metadata: { exit: 0 } },
  )

  assert.deepEqual(current.records.map((record) => record.type), ["decision", "execution_result"])
  const execution = current.records[1] as ExecutionAuditRecord
  assert.equal(execution.outcome, "COMPLETED")
  assert.equal(execution.exitCode, 0)
  assert.equal(execution.commandPreview, "pwd")
})

test("real JSONL audit captures decision, permission and execution lifecycle", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "kilo-command-gate-plugin-"))
  t.after(async () => await rm(directory, { recursive: true, force: true }))
  const replies: KiloPermissionReply[] = []
  const hooks = createKiloCommandGatePlugin(
    { directory, mode: "interactive" },
    {
      replyPermission: async (reply) => {
        replies.push(reply)
        return { data: true }
      },
    },
  )
  const command = "git status --short"

  await hooks["tool.execute.before"](input, { args: { command } })
  await hooks.event(permissionAsked(command))
  await hooks["tool.execute.after"](
    { ...input, args: { command } },
    { output: "", metadata: { exit: 0 } },
  )

  const records = (await readFile(path.join(directory, ".command-gate", "audit.jsonl"), "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as AuditRecord)
  assert.deepEqual(replies, [{ sessionID: "session-1", requestID: "permission-1", reply: "once" }])
  assert.deepEqual(records.map((record) => record.type), [
    "decision",
    "permission_result",
    "permission_result",
    "execution_result",
  ])
  assert.equal((records[0] as DecisionAuditRecord).gatePassed, true)
  assert.equal((records.at(-1) as ExecutionAuditRecord).exitCode, 0)
})

test("forward-compatible permission.ask hook mirrors the cached exact decision", async () => {
  const current = state()
  const hooks = createKiloCommandGatePlugin({ directory: "/tmp/project", mode: "interactive" }, current.dependencies)
  const command = "git status --short"
  await hooks["tool.execute.before"](input, { args: { command } })
  const output = { status: "ask" as const }

  await hooks["permission.ask"](
    {
      id: "permission-direct",
      sessionID: "session-1",
      permission: "bash",
      metadata: { command },
      tool: { callID: "call-1" },
    },
    output,
  )

  assert.equal(output.status, "allow")
  assert.equal((current.records.at(-1) as PermissionAuditRecord).outcome, "AUTO_APPROVED")
})

test("auto-approval is withheld when its pre-release audit fails", async () => {
  const current = state({ failAuditAt: 2 })
  const hooks = createKiloCommandGatePlugin({ directory: "/tmp/project", mode: "interactive" }, current.dependencies)
  const command = "git status --short"
  await hooks["tool.execute.before"](input, { args: { command } })

  await hooks.event(permissionAsked(command))

  assert.deepEqual(current.replies, [])
  assert.equal(current.backgroundErrors.length, 1)

  await hooks.event({
    event: {
      type: "permission.replied",
      properties: { requestID: "permission-1", sessionID: "session-1", reply: "reject" },
    },
  })
  assert.equal((current.records.at(-1) as PermissionAuditRecord).outcome, "REJECTED")
})

test("a failed SDK permission reply stays fail-safe and is audited", async () => {
  const current = state({ replyError: { message: "permission endpoint unavailable" } })
  const hooks = createKiloCommandGatePlugin({ directory: "/tmp/project", mode: "interactive" }, current.dependencies)
  const command = "git status --short"
  await hooks["tool.execute.before"](input, { args: { command } })

  await hooks.event(permissionAsked(command))

  assert.equal(current.replies.length, 1)
  assert.equal((current.records.at(-1) as PermissionAuditRecord).outcome, "AUTO_APPROVAL_FAILED")
  assert.equal(current.backgroundErrors.length, 1)
})

test("malformed bash arguments fail closed", async () => {
  const current = state()
  const hooks = createKiloCommandGatePlugin({ directory: "/tmp/project", mode: "interactive" }, current.dependencies)

  await assert.rejects(hooks["tool.execute.before"](input, { args: {} }), KiloCommandBlockedError)

  const record = current.records[0] as DecisionAuditRecord
  assert.equal(record.policyDecision, "DENY")
  assert.ok(record.reasonCodes.includes("EMPTY_COMMAND"))
})

test("a decision audit failure prevents an otherwise allowed shell call", async () => {
  const current = state({ failAuditAt: 1 })
  const hooks = createKiloCommandGatePlugin({ directory: "/tmp/project", mode: "interactive" }, current.dependencies)

  await assert.rejects(
    hooks["tool.execute.before"](input, { args: { command: "pwd" } }),
    /simulated audit failure/,
  )
})

test("relative Kilo workdir is resolved from the session directory", async () => {
  const current = state()
  const hooks = createKiloCommandGatePlugin({ directory: "/tmp/project", mode: "interactive" }, current.dependencies)

  await hooks["tool.execute.before"](input, { args: { command: "pwd", workdir: "packages/app" } })

  assert.equal((current.records[0] as DecisionAuditRecord).cwd, "/tmp/project/packages/app")
})
