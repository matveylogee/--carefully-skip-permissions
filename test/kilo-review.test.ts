import assert from "node:assert/strict"
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import test from "node:test"
import { createKiloReviewPublisher } from "../src/kilo-review.ts"
import { createKiloCommandGatePlugin } from "../src/kilo-plugin.ts"
import { createInstallGate } from "../src/install-gate.ts"
import { FIXTURE_NOW, fixtureRegistry } from "../fixtures/install-registry.ts"
import type { AuditRecord, DecisionAuditRecord } from "../src/audit.ts"

const input = { sessionID: "s", callID: "c", command: "npm install l3ft-pad@1.0.0", description: "[InstallGate] ASK: Name resembles left-pad" }

function host(options: { failPatch?: boolean; discardPatch?: boolean; changeCommand?: boolean } = {}) {
  let part = {
    id: "p", messageID: "m", sessionID: "s", type: "tool", tool: "bash", callID: "c",
    state: { status: "running", input: { command: input.command, description: "Agent description", timeout: 1000 }, time: { start: 123 }, metadata: { approval: "preserve" } },
  }
  let reads = 0
  let patches = 0
  const client = { _client: {
    async get(request: { url: string }) {
      reads++
      if (reads > 1 && options.changeCommand) part.state.input.command = "npm install different"
      if (request.url === "/session/s/message") return { data: [{ parts: [structuredClone(part)] }] }
      assert.equal(request.url, "/session/s/message/m")
      return { data: { parts: [structuredClone(part)] } }
    },
    async patch(request: { url: string; body: typeof part }) {
      patches++
      assert.equal(request.url, "/session/s/message/m/part/p")
      if (options.failPatch) return { error: { message: "write failed" } }
      const updated = structuredClone(request.body)
      if (!options.discardPatch) part = updated
      return { data: updated }
    },
  } }
  return { client, part: () => part, patches: () => patches }
}

test("review publisher updates the stored tool input, preserving the exact command and all executor state", async () => {
  const current = host()
  const original = structuredClone(current.part())
  const receipt = await createKiloReviewPublisher(current.client)(input)
  assert.deepEqual(receipt, { messageID: "m", partID: "p" })
  assert.deepEqual(current.part(), {
    ...original, state: { ...original.state, input: { ...original.state.input, description: input.description } },
  })
  assert.equal(current.patches(), 1)
})

for (const mode of ["failPatch", "discardPatch"] as const) {
  test(`review publisher refuses to report publication when host ${mode}`, async () => {
    await assert.rejects(createKiloReviewPublisher(host({ [mode]: true }).client)(input))
  })
}

test("review publisher does not write after the stored command changes", async () => {
  const current = host({ changeCommand: true })
  await assert.rejects(createKiloReviewPublisher(current.client)(input), /changed during review/)
  assert.equal(current.patches(), 0)
})

test("review publisher fails explicitly when the injected legacy transport is unavailable", async () => {
  await assert.rejects(createKiloReviewPublisher({})(input), /transport unavailable/)
})

test("review update failure blocks the pre-hook and is audited separately from the package ASK verdict", async (t) => {
  // macOS temporary paths can contain /var -> /private/var symlinks.
  // Match the gate's canonical-directory contract, as other install tests do.
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "gate-review-")))
  t.after(() => rm(directory, { recursive: true, force: true }))
  await writeFile(path.join(directory, "package.json"), '{"name":"lab"}')
  const records: AuditRecord[] = []
  const hooks = createKiloCommandGatePlugin({ directory, mode: "interactive" }, {
    installGate: createInstallGate({ directory }, { registry: fixtureRegistry, now: () => FIXTURE_NOW, environment: {} }),
    publishReview: async () => { throw new Error("UI unavailable") },
    writeAudit: async (_, record) => { records.push(record) },
    replyPermission: async () => { assert.fail("no approval on UI failure") },
  })
  await assert.rejects(hooks["tool.execute.before"]({ tool: "bash", sessionID: "s", callID: "c" }, { args: { command: input.command } }), /Could not publish the risk review/)
  const decision = records[0] as DecisionAuditRecord
  assert.equal(decision.policyDecision, "ASK")
  assert.equal(decision.gatePassed, false)
  assert.equal(decision.gateAction, "BLOCK")
  assert.equal(records[1].type, "review_result")
  assert.ok(records[1].type === "review_result" && records[1].outcome === "FAILED")
  assert.equal(records.length, 2)
})
