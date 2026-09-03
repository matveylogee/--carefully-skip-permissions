import assert from "node:assert/strict"
import { mkdtemp, readFile, rm, stat } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import test from "node:test"
import {
  appendAuditRecord,
  redactCommand,
  type AuditRecord,
  type DecisionAuditRecord,
} from "../src/audit.ts"
import {
  guardedExec,
  sanitizeEnvironment,
  type ConfirmationProvider,
  type GuardedExecDependencies,
  type ShellRunner,
} from "../src/guarded-exec.ts"

function testDependencies(options: {
  confirmation?: Awaited<ReturnType<ConfirmationProvider>>
  executionExitCode?: number
  failAuditAt?: number
} = {}) {
  const auditRecords: AuditRecord[] = []
  const executedCommands: string[] = []
  let confirmations = 0
  let auditAttempts = 0
  let clock = Date.parse("2026-09-03T12:00:00.000Z")

  const run: ShellRunner = async (command) => {
    assert.equal(auditRecords[0]?.type, "decision", "decision must be audited before spawn")
    executedCommands.push(command)
    return { exitCode: options.executionExitCode ?? 0 }
  }
  const confirm: ConfirmationProvider = async () => {
    confirmations += 1
    return options.confirmation ?? "UNAVAILABLE"
  }
  const dependencies: GuardedExecDependencies = {
    run,
    confirm,
    writeAudit: async (_auditPath, record) => {
      auditAttempts += 1
      if (options.failAuditAt === auditAttempts) throw new Error("simulated audit failure")
      auditRecords.push(record)
    },
    log: () => {},
    newEventId: () => "event-1",
    now: () => {
      clock += 5
      return clock
    },
    environment: { PATH: "/usr/bin:/bin" },
  }

  return {
    dependencies,
    auditRecords,
    executedCommands,
    confirmations: () => confirmations,
  }
}

test("ALLOW is audited before exactly one execution", async () => {
  const state = testDependencies()
  const result = await guardedExec("pwd", {}, state.dependencies)

  assert.equal(result.status, "EXECUTED")
  assert.equal(result.executed, true)
  assert.equal(result.exitCode, 0)
  assert.deepEqual(state.executedCommands, ["pwd"])
  assert.equal(state.confirmations(), 0)
  assert.deepEqual(state.auditRecords.map((record) => record.type), ["decision", "execution_result"])
  assert.equal((state.auditRecords[0] as DecisionAuditRecord).willExecute, true)
})

test("DENY never asks and never reaches the runner", async () => {
  const state = testDependencies({ confirmation: "APPROVED" })
  const result = await guardedExec("rm -rf /", {}, state.dependencies)

  assert.equal(result.status, "BLOCKED")
  assert.equal(result.exitCode, 126)
  assert.equal(result.executed, false)
  assert.equal(state.confirmations(), 0)
  assert.deepEqual(state.executedCommands, [])
  assert.equal((state.auditRecords[0] as DecisionAuditRecord).approval, "POLICY_DENIED")
})

test("ASK executes only after the exact confirmation provider approves", async () => {
  const state = testDependencies({ confirmation: "APPROVED" })
  const result = await guardedExec("touch demo.txt", {}, state.dependencies)

  assert.equal(result.status, "EXECUTED")
  assert.equal(result.approval, "APPROVED")
  assert.equal(state.confirmations(), 1)
  assert.deepEqual(state.executedCommands, ["touch demo.txt"])
})

test("rejected ASK is audited and not executed", async () => {
  const state = testDependencies({ confirmation: "REJECTED" })
  const result = await guardedExec("touch demo.txt", {}, state.dependencies)

  assert.equal(result.status, "REJECTED")
  assert.equal(result.exitCode, 126)
  assert.equal(result.executed, false)
  assert.deepEqual(state.executedCommands, [])
  assert.equal((state.auditRecords[0] as DecisionAuditRecord).approval, "REJECTED")
})

test("headless ASK fails closed without invoking confirmation", async () => {
  const state = testDependencies({ confirmation: "APPROVED" })
  const result = await guardedExec("curl https://example.com", { mode: "headless" }, state.dependencies)

  assert.equal(result.status, "BLOCKED")
  assert.equal(result.approval, "HEADLESS_DENIED")
  assert.equal(state.confirmations(), 0)
  assert.deepEqual(state.executedCommands, [])
})

test("dry-run never spawns, even when the policy says ALLOW", async () => {
  const state = testDependencies({ confirmation: "APPROVED" })
  const result = await guardedExec("pwd", { dryRun: true }, state.dependencies)

  assert.equal(result.status, "DRY_RUN")
  assert.equal(result.exitCode, 0)
  assert.equal(result.approval, "DRY_RUN")
  assert.deepEqual(state.executedCommands, [])
  assert.equal(state.confirmations(), 0)
})

test("failure to write the decision audit blocks execution", async () => {
  const state = testDependencies({ failAuditAt: 1 })
  const result = await guardedExec("pwd", {}, state.dependencies)

  assert.equal(result.status, "AUDIT_ERROR")
  assert.equal(result.exitCode, 125)
  assert.equal(result.executed, false)
  assert.deepEqual(state.executedCommands, [])
})

test("audit paths outside the working directory are rejected", async () => {
  const state = testDependencies()
  await assert.rejects(
    guardedExec("pwd", { cwd: "/tmp/project", auditPath: "../audit.jsonl" }, state.dependencies),
    /must stay inside the working directory/,
  )
  assert.deepEqual(state.executedCommands, [])
})

test("the child exit code is propagated", async () => {
  const state = testDependencies({ executionExitCode: 23 })
  const result = await guardedExec("pwd", {}, state.dependencies)

  assert.equal(result.status, "EXECUTED")
  assert.equal(result.exitCode, 23)
  assert.equal(result.executed, true)
})

test("dangerous interpreter and loader environment variables are removed", () => {
  const sanitized = sanitizeEnvironment({
    PATH: "/usr/bin:/bin",
    HOME: "/tmp/example",
    BASH_ENV: "/tmp/inject.sh",
    NODE_OPTIONS: "--require=/tmp/inject.js",
    LD_PRELOAD: "/tmp/inject.so",
    DYLD_INSERT_LIBRARIES: "/tmp/inject.dylib",
    "BASH_FUNC_git%%": "() { echo injected; }",
  })

  assert.equal(sanitized.PATH, "/usr/bin:/bin")
  assert.equal(sanitized.HOME, "/tmp/example")
  assert.equal(sanitized.BASH_ENV, undefined)
  assert.equal(sanitized.NODE_OPTIONS, undefined)
  assert.equal(sanitized.LD_PRELOAD, undefined)
  assert.equal(sanitized.DYLD_INSERT_LIBRARIES, undefined)
  assert.equal(sanitized["BASH_FUNC_git%%"], undefined)
  assert.equal(sanitized.GIT_PAGER, "cat")
  assert.equal(sanitized.GIT_TERMINAL_PROMPT, "0")
})

test("audit preview redacts common inline credentials", () => {
  const preview = redactCommand(
    "API_TOKEN=top-secret curl -H 'Authorization: Bearer bearer-secret' https://user:url-secret@example.com --password cli-secret",
  )

  assert.equal(preview.includes("top-secret"), false)
  assert.equal(preview.includes("bearer-secret"), false)
  assert.equal(preview.includes("url-secret"), false)
  assert.equal(preview.includes("cli-secret"), false)
  assert.match(preview, /<redacted>/)
})

test("default audit writer creates append-only JSONL with private permissions", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "command-gate-audit-"))
  t.after(async () => await rm(directory, { recursive: true, force: true }))
  const auditPath = path.join(directory, ".command-gate", "audit.jsonl")
  const record: DecisionAuditRecord = {
    schemaVersion: 1,
    type: "decision",
    eventId: "event-1",
    timestamp: "2026-09-03T12:00:00.000Z",
    cwd: directory,
    commandSha256: "abc",
    commandPreview: "pwd",
    policyDecision: "ALLOW",
    effectiveDecision: "ALLOW",
    route: "COMMAND_GATE",
    reasonCodes: ["READ_ONLY_COMMAND"],
    approval: "NOT_REQUIRED",
    willExecute: true,
  }

  await appendAuditRecord(auditPath, record)
  await appendAuditRecord(auditPath, { ...record, eventId: "event-2" })

  const lines = (await readFile(auditPath, "utf8")).trim().split("\n").map((line) => JSON.parse(line))
  assert.deepEqual(lines.map((line) => line.eventId), ["event-1", "event-2"])
  if (process.platform !== "win32") {
    assert.equal((await stat(auditPath)).mode & 0o777, 0o600)
  }
})
