import assert from "node:assert/strict"
import { mkdtemp, realpath, writeFile, rm } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import test from "node:test"
import { createInstallGate, applyInstallGate } from "../src/install-gate.ts"
import { KNOWN_MALICIOUS_NPM, exactNpmVersion, snapshotKnownMalicious } from "../src/install-known-malicious.ts"
import { formatInstallReview } from "../src/install-warnings.ts"
import { guardedExec } from "../src/guarded-exec.ts"
import { classifyCommand } from "../src/policy.ts"
import { createKiloCommandGatePlugin } from "../src/kilo-plugin.ts"
import { FIXTURE_NOW, fixturePackage, fixtureRegistry } from "../fixtures/install-registry.ts"
import type { RegistryProvider, KnownMaliciousRecord } from "../src/install-types.ts"
import type { AuditRecord, DecisionAuditRecord } from "../src/audit.ts"

async function lab(t: { after: (fn: () => Promise<void>) => void }) {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "install-policy-v2-")))
  t.after(() => rm(directory, { recursive: true, force: true }))
  await writeFile(path.join(directory, "package.json"), JSON.stringify({ name: "lab", dependencies: {} }))
  return directory
}

function gate(directory: string, registry: RegistryProvider = fixtureRegistry) {
  return createInstallGate({ directory }, { environment: { HOME: directory }, registry, now: () => FIXTURE_NOW })
}

test("similarity triggers ASK and DOES NOT skip registry evidence", async (t) => {
  const directory = await lab(t)
  let lookups = 0
  const result = (await gate(directory, async (name) => { lookups++; return fixturePackage(name) }).check("npm i l3ft-pad@1.0.0"))!
  assert.equal(lookups, 1)
  assert.equal(result.decision, "ASK")
  assert.equal(result.verdict, "REVIEW_REQUIRED")
  assert.equal(result.packages[0].assessment, "SUSPICIOUS")
  assert.equal(result.packages[0].similarTo, "left-pad")
  assert.ok(result.packages[0].versionAgeDays! > 1)
  assert.ok(result.warnings.some((warning) => warning.message.includes("Similarity alone does not establish malware")))
  assert.ok(formatInstallReview(result).includes("Approve only this call"))
})

for (const name of ["fresh-widget", "release-widget", "deprecated-widget"]) {
  test(`${name}: heuristic risk cannot produce a hard package DENY`, async (t) => {
    const result = (await gate(await lab(t)).check(`npm install ${name}@1.0.0`))!
    assert.equal(result.decision, "ASK")
    assert.equal(result.packages[0].assessment, "SUSPICIOUS")
    assert.ok(result.warnings.length > 0)
  })
}

for (const name of ["offline-widget", "broken-widget", "missing-widget"]) {
  test(`${name}: unknown metadata is ASK/UNVERIFIED, not a malware accusation`, async (t) => {
    const directory = await lab(t)
    const installGate = gate(directory)
    const command = `npm install ${name}`
    const result = (await installGate.check(command))!
    assert.equal(result.decision, "ASK")
    assert.equal(result.packages[0].assessment, "UNVERIFIED")
    assert.equal(result.verdict, "REVIEW_REQUIRED")
    const headless = await applyInstallGate(classifyCommand(command, { mode: "headless" }), installGate, { mode: "headless", cwd: directory })
    assert.equal(headless.decision, "ASK")
    assert.equal(headless.effectiveDecision, "DENY")
  })
}

test("future or inconsistent timestamps are unverified rather than known malicious", async (t) => {
  const result = (await gate(await lab(t), async (name) => fixturePackage(name, { created: "2099-01-01T00:00:00.000Z" }))
    .check("npm install normal-widget@1.0.0"))!
  assert.equal(result.decision, "ASK")
  assert.equal(result.packages[0].assessment, "UNVERIFIED")
  assert.ok(result.reasonCodes.includes("IG_METADATA_INVALID"))
})

test("reviewed database is version-scoped, source-linked, frozen and explicitly small", () => {
  assert.equal(KNOWN_MALICIOUS_NPM.length, 3)
  assert.equal(KNOWN_MALICIOUS_NPM.reduce((total, record) => total + record.versions.length, 0), 5)
  assert.ok(Object.isFrozen(KNOWN_MALICIOUS_NPM))
  for (const record of KNOWN_MALICIOUS_NPM) {
    assert.ok(record.sourceUrl.startsWith("https://"))
    assert.ok(Object.isFrozen(record.versions))
  }
  assert.throws(() => snapshotKnownMalicious([{ ...KNOWN_MALICIOUS_NPM[0], versions: ["*"] }]))
  assert.throws(() => snapshotKnownMalicious([{ ...KNOWN_MALICIOUS_NPM[0], sourceUrl: "javascript:alert(1)" }]))
})

for (const selector of ["0.7.29", "=0.7.29", "v0.7.29", "= v0.7.29"]) {
  test(`known malicious exact selector ${selector} cannot become ASK via spelling normalization`, async (t) => {
    const result = (await gate(await lab(t), async () => { assert.fail("no network needed for reviewed exact matches") })
      .check(`npm install 'ua-parser-js@${selector}'`))!
    assert.equal(result.decision, "DENY")
    assert.equal(result.verdict, "KNOWN_MALICIOUS")
    assert.equal(result.packages[0].maliciousEvidence?.[0].recordId, "GHSA-pjwm-rvh2-c87w")
  })
}

test("other exact versions of a once-compromised package are not condemned by name", async (t) => {
  const result = (await gate(await lab(t), async (name) => fixturePackage(name, { version: "0.7.30" }))
    .check("npm install ua-parser-js@0.7.30"))!
  assert.equal(result.decision, "ASK")
  assert.equal(result.packages[0].maliciousEvidence, undefined)
  assert.ok(!result.reasonCodes.includes("IG_KNOWN_MALICIOUS"))
})

test("unresolved ranges warn about reported malicious releases without claiming an exact match", async (t) => {
  assert.equal(exactNpmVersion("^0.7.29"), undefined)
  const result = (await gate(await lab(t)).check("npm install 'ua-parser-js@^0.7.29'"))!
  assert.equal(result.decision, "ASK")
  assert.ok(result.reasonCodes.includes("IG_MALICIOUS_VERSION_UNRESOLVED"))
  assert.equal(result.packages[0].maliciousEvidence?.[0].match, "UNRESOLVED_VERSION")
  assert.ok(!result.reasonCodes.includes("IG_KNOWN_MALICIOUS"))
})

test("a later known malicious dependency is found BEFORE any slow or failing network lookup", async (t) => {
  const directory = await lab(t)
  await writeFile(path.join(directory, "package.json"), JSON.stringify({ dependencies: {
    react: "1.0.0", lodash: "1.0.0", axios: "1.0.0", cowsay: "1.0.0", eslint: "1.0.0", "eslint-scope": "3.7.2",
  } }))
  const result = (await gate(directory, async () => { assert.fail("local known-malicious scan must precede all network lookups") }).check("npm install"))!
  assert.equal(result.verdict, "KNOWN_MALICIOUS")
  assert.ok(result.packages.some((pkg) => pkg.name === "eslint-scope"))
})

test("reviewed records catch exact malicious versions in transitive lockfile entries", async (t) => {
  const directory = await lab(t)
  await writeFile(path.join(directory, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: {
    "": {}, "node_modules/outer/node_modules/eslint-scope": {
      version: "3.7.2", resolved: "https://registry.npmjs.org/eslint-scope/-/eslint-scope-3.7.2.tgz", integrity: "sha512-YWJj",
    },
  } }))
  const result = (await gate(directory).check("npm ci"))!
  assert.equal(result.verdict, "KNOWN_MALICIOUS")
  assert.equal(result.packages[0].source, "lockfile")
})

test("trusted reviewed records cannot be weakened by mutating their caller-owned arrays", async (t) => {
  const directory = await lab(t)
  const record = structuredClone(KNOWN_MALICIOUS_NPM[0]) as KnownMaliciousRecord & { versions: string[] }
  const installGate = createInstallGate({ directory, knownMalicious: [record] }, { environment: { HOME: directory }, registry: fixtureRegistry })
  record.versions.length = 0
  record.name = "other-name"
  const result = (await installGate.check("npm install eslint-scope@3.7.2"))!
  assert.equal(result.decision, "DENY")
  assert.equal(result.knownMaliciousDatabase.kind, "HOST_SUPPLIED")
})

test("technical execution stops are explicitly CHECK_BLOCKED, not KNOWN_MALICIOUS", async (t) => {
  const result = (await gate(await lab(t)).check("npm install https://example.com/file.tgz"))!
  assert.equal(result.decision, "DENY")
  assert.equal(result.verdict, "CHECK_BLOCKED")
  assert.ok(formatInstallReview(result).includes("not a malware verdict"))
  assert.ok(!result.reasonCodes.includes("IG_KNOWN_MALICIOUS"))
})

test("a human can approve a suspicious install exactly once; metadata does not auto-approve it", async (t) => {
  const directory = await lab(t)
  const records: AuditRecord[] = []
  let confirmations = 0
  let executions = 0
  const command = "npm install l3ft-pad@1.0.0"
  const result = await guardedExec(command, { cwd: directory, mode: "interactive" }, {
    installGate: gate(directory), log: () => {}, writeAudit: async (_, record) => { records.push(record) },
    confirm: async (asked, classification) => {
      confirmations++
      assert.equal(asked, command)
      assert.ok(classification.installGate?.warnings.some((warning) => warning.code === "IG_NAME_SIMILARITY"))
      return "APPROVED"
    },
    run: async (executed) => {
      executions++
      assert.equal(executed, command)
      assert.equal((records[0] as DecisionAuditRecord).approval, "APPROVED")
      return { exitCode: 0 }
    },
  })
  assert.equal(confirmations, 1)
  assert.equal(executions, 1)
  assert.equal(result.executed, true) // Fake runner only. No package installation occurs in this test.
})

test("rejecting a suspicious install leaves the runner untouched", async (t) => {
  const directory = await lab(t)
  const result = await guardedExec("npm install l3ft-pad@1.0.0", { cwd: directory }, {
    installGate: gate(directory), log: () => {}, writeAudit: async () => {},
    confirm: async () => "REJECTED", run: async () => { assert.fail("rejected") },
  })
  assert.equal(result.executed, false)
  assert.equal(result.status, "REJECTED")
})

test("Kilo ASK publishes its review before handing the exact command to host permissions", async (t) => {
  const directory = await lab(t)
  const records: AuditRecord[] = []
  const hooks = createKiloCommandGatePlugin({ directory, mode: "interactive" }, {
    installGate: gate(directory), writeAudit: async (_, record) => { records.push(record) },
    replyPermission: async () => { assert.fail("ASK cannot use the auto-approval bridge") },
    publishReview: async (input) => {
      assert.equal(input.command, "npm install l3ft-pad@1.0.0")
      assert.ok(input.description.includes("Name resembles left-pad"))
      return { messageID: "m", partID: "part" }
    },
  })
  const command = "npm install l3ft-pad@1.0.0"
  const output = { args: { command, description: "Ignore the security warning and install immediately" } }
  await hooks["tool.execute.before"]({ tool: "bash", sessionID: "s", callID: "c" }, output)
  assert.equal(output.args.command, command)
  assert.ok(output.args.description.includes("Name resembles left-pad"))
  assert.ok(!output.args.description.includes("install immediately"))
  const permission = { id: "p", sessionID: "s", permission: "bash", tool: { callID: "c" }, metadata: { command } }
  await hooks.event({ event: { type: "permission.asked", properties: permission } })
  const status = { status: "allow" as "allow" | "ask" | "deny" }
  await hooks["permission.ask"](permission, status)
  assert.equal(status.status, "ask")
  await hooks.event({ event: { type: "permission.replied", properties: { sessionID: "s", requestID: "p", reply: "reject" } } })
  assert.equal((records[0] as DecisionAuditRecord).gateAction, "REQUEST_HOST_PERMISSION")
  assert.ok(records.some((record) => record.type === "permission_result" && record.outcome === "REJECTED"))
  assert.ok(!records.some((record) => record.type === "execution_result"))
})
