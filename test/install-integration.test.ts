import assert from "node:assert/strict"
import { mkdtemp, realpath, writeFile, rm } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import test from "node:test"
import { createInstallGate } from "../src/install-gate.ts"
import { guardedExec } from "../src/guarded-exec.ts"
import { createKiloCommandGatePlugin, KiloCommandBlockedError } from "../src/kilo-plugin.ts"
import { FIXTURE_NOW, fixtureRegistry } from "../fixtures/install-registry.ts"
import type { AuditRecord, DecisionAuditRecord } from "../src/audit.ts"

async function setup(t: { after: (fn: () => Promise<void>) => void }) {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "install-gate-integration-")))
  t.after(() => rm(directory, { recursive: true, force: true }))
  await writeFile(path.join(directory, "package.json"), JSON.stringify({ name: "lab", dependencies: {} }))
  const installGate = createInstallGate({ directory }, { registry: fixtureRegistry, now: () => FIXTURE_NOW, environment: { HOME: directory } })
  await installGate.ready
  return { directory, installGate }
}

for (const mode of ["interactive", "headless"] as const) {
  test(`InstallGate DENY in ${mode} reaches neither standalone confirmation nor runner`, async (t) => {
    const { directory, installGate } = await setup(t)
    const records: AuditRecord[] = []
    const result = await guardedExec("npm install eslint-scope@3.7.2", { cwd: directory, mode }, {
      installGate, log: () => {}, writeAudit: async (_, record) => { records.push(record) },
      confirm: async () => { assert.fail("blocked installs must not ask") },
      run: async () => { assert.fail("blocked installs must never run") },
    })
    assert.equal(result.executed, false)
    assert.equal(result.status, "BLOCKED")
    assert.equal((records[0] as DecisionAuditRecord).installGate?.decision, "DENY")
    assert.equal((records[0] as DecisionAuditRecord).gatePassed, false)
  })
}

test("a clean metadata result still requires confirmation in standalone", async (t) => {
  const { directory, installGate } = await setup(t)
  let asks = 0
  const result = await guardedExec("npm install react@1.0.0", { cwd: directory }, {
    installGate, log: () => {}, writeAudit: async () => {},
    confirm: async () => { asks++; return "REJECTED" }, run: async () => { assert.fail("rejected") },
  })
  assert.equal(asks, 1)
  assert.equal(result.status, "REJECTED")
})

test("a manifest change during standalone human confirmation prevents execution", async (t) => {
  const { directory, installGate } = await setup(t)
  const result = await guardedExec("npm install react@1.0.0", { cwd: directory }, {
    installGate, log: () => {}, writeAudit: async () => {},
    confirm: async () => {
      await writeFile(path.join(directory, "package.json"), JSON.stringify({ dependencies: { "fresh-widget": "1.0.0" } }))
      return "APPROVED"
    },
    run: async () => { assert.fail("project changed") },
  })
  assert.equal(result.executed, false)
  assert.ok(result.classification.reasonCodes.includes("IG_PROJECT_CHANGED"))
})

test("Kilo plugin blocks a reviewed malicious version before host permissions and audits the source", async (t) => {
  const { directory, installGate } = await setup(t)
  const records: AuditRecord[] = []
  const hooks = createKiloCommandGatePlugin({ directory, mode: "interactive" }, {
    installGate, writeAudit: async (_, record) => { records.push(record) },
    replyPermission: async () => { assert.fail("DENY must never issue an approval") },
  })
  await assert.rejects(hooks["tool.execute.before"](
    { tool: "bash", sessionID: "install-session", callID: "install-call" },
    { args: { command: "npm install local@npm:eslint-scope@3.7.2" } },
  ), (error: unknown) => error instanceof KiloCommandBlockedError && error.classification.reasonCodes.includes("IG_KNOWN_MALICIOUS"))
  const record = records[0] as DecisionAuditRecord
  assert.equal(record.gateAction, "BLOCK")
  assert.equal(record.installGate?.packages[0].name, "eslint-scope")
  assert.equal(record.installGate?.packages[0].maliciousEvidence?.[0].recordId, "ESLINT-2018-SCOPE")
  assert.equal(records.length, 1)
})

test("Kilo clean npm install stays native ASK, never auto-approved like read-only commands", async (t) => {
  const { directory, installGate } = await setup(t)
  const records: AuditRecord[] = []
  const hooks = createKiloCommandGatePlugin({ directory, mode: "interactive" }, {
    installGate, writeAudit: async (_, record) => { records.push(record) },
    replyPermission: async () => { assert.fail("installs are never auto-approved") },
    publishReview: async () => ({ messageID: "m", partID: "part" }),
  })
  const command = "npm install react@1.0.0"
  const output = { args: { command, description: "Install react" } }
  await hooks["tool.execute.before"]({ tool: "bash", sessionID: "s", callID: "c" }, output)
  await hooks.event({ event: { type: "permission.asked", properties: {
    id: "p", sessionID: "s", permission: "bash", tool: { callID: "c" }, metadata: { command },
  } } })
  assert.equal((records[0] as DecisionAuditRecord).gateAction, "REQUEST_HOST_PERMISSION")
  assert.equal(output.args.command, command)
  assert.ok(output.args.description.includes("InstallGate"))
})

test("Kilo headless clean install remains blocked, and no execution result is fabricated", async (t) => {
  const { directory, installGate } = await setup(t)
  const records: AuditRecord[] = []
  const hooks = createKiloCommandGatePlugin({ directory, mode: "headless" }, {
    installGate, writeAudit: async (_, record) => { records.push(record) },
  })
  await assert.rejects(hooks["tool.execute.before"]({ tool: "bash", sessionID: "s", callID: "c" }, {
    args: { command: "npm install react@1.0.0" },
  }), KiloCommandBlockedError)
  assert.equal((records[0] as DecisionAuditRecord).approval, "HEADLESS_DENIED")
  assert.equal(records.length, 1)
})
