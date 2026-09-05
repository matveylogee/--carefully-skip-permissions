import assert from "node:assert/strict"
import { mkdtemp, realpath, readFile, writeFile, rm, symlink } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import test from "node:test"
import { createInstallGate, applyInstallGate } from "../src/install-gate.ts"
import { classifyCommand } from "../src/policy.ts"
import { extractInstallRequest, parsePackageSpec } from "../src/install-parser.ts"
import { levenshtein, similarNpmName } from "../src/install-similarity.ts"
import { FIXTURE_NOW, fixturePackage, fixtureRegistry } from "../fixtures/install-registry.ts"
import type { RegistryProvider } from "../src/install-types.ts"
import type { Mode } from "../src/types.ts"

async function project(t: { after: (fn: () => Promise<void>) => void }) {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "install-gate-test-")))
  t.after(() => rm(directory, { recursive: true, force: true }))
  await writeFile(path.join(directory, "package.json"), JSON.stringify({ name: "lab", version: "1.0.0", dependencies: {} }))
  return directory
}

function gate(directory: string, registry: RegistryProvider = fixtureRegistry) {
  return createInstallGate({ directory }, { registry, now: () => FIXTURE_NOW, environment: { HOME: directory } })
}

const cases = (await readFile(new URL("../fixtures/install-cases.jsonl", import.meta.url), "utf8"))
  .trim().split("\n").map((line) => JSON.parse(line))

test("InstallGate corpus has unique ids and explicitly synthetic registry metadata", () => {
  assert.equal(new Set(cases.map((item) => item.id)).size, cases.length)
  assert.equal(cases.length, 51)
})

for (const item of cases) {
  test(`${item.id}: ${item.command}`, async (t) => {
    const directory = await project(t)
    const installGate = gate(directory)
    const context = { cwd: directory, mode: (item.mode ?? "interactive") as Mode }
    const result = await applyInstallGate(classifyCommand(item.command, context), installGate, context)
    assert.equal(result.effectiveDecision, item.expected, JSON.stringify(result))
    for (const reason of item.reasons) assert.ok(result.reasonCodes.includes(reason), JSON.stringify(result))
  })
}

test("Levenshtein, transpositions and digit/separator confusables are signals, not malware labels", () => {
  assert.equal(levenshtein("react", "react"), 0)
  assert.equal(levenshtein("express", "expres"), 1)
  assert.equal(similarNpmName("lodahs")?.name, "lodash")
  assert.equal(similarNpmName("l3ft-pad")?.name, "left-pad")
  assert.equal(similarNpmName("react"), undefined)
})

test("npm aliases expose the actual package and reject nested aliases", () => {
  assert.deepEqual(parsePackageSpec("local@npm:@types/node@1.0.0").spec, {
    name: "@types/node", selector: "1.0.0", alias: "local", source: "command",
  })
  assert.ok(parsePackageSpec("a@npm:b@npm:c").reason)
  assert.equal(extractInstallRequest("npm exec --package=eslint@1.0.0 -- eslint --fix .").specs[0].name, "eslint")
})

test("npm exec reads package flags after the binary, unlike npx", async (t) => {
  const directory = await project(t)
  const installGate = gate(directory)
  const result = await installGate.check("npm exec eslint --package=fresh-widget@1.0.0")
  assert.equal(result?.decision, "ASK")
  assert.ok(result?.reasonCodes.includes("IG_FRESH_PACKAGE"))
  assert.equal(result?.packages[0].name, "fresh-widget")
  assert.equal(extractInstallRequest("npx eslint --package=fresh-widget").specs[0].name, "eslint")
})

test("unrecognized npm options cannot hide an install subcommand", async (t) => {
  const directory = await project(t)
  for (const command of ["npm --cafile ca.pem install react", "npm audit fix", "npm x react"]) {
    assert.equal((await gate(directory).check(command))?.decision, "DENY", command)
  }
})

test("baseline is frozen before the agent adds a manifest dependency", async (t) => {
  const directory = await project(t)
  const installGate = gate(directory)
  await installGate.ready
  await writeFile(path.join(directory, "package.json"), JSON.stringify({ dependencies: { "fresh-widget": "1.0.0" } }))
  const result = await installGate.check("npm install")
  assert.equal(result?.decision, "ASK")
  assert.ok(result?.reasonCodes.includes("IG_BASELINE_CHANGED"))
  assert.ok(result?.reasonCodes.includes("IG_FRESH_PACKAGE"))
  assert.equal(result?.packages[0].presentAtStartup, false)
})

test("baseline membership never makes an old package or scripts automatically safe", async (t) => {
  const directory = await project(t)
  await writeFile(path.join(directory, "package.json"), JSON.stringify({ dependencies: { react: "1.0.0" } }))
  const result = await gate(directory).check("npm install --ignore-scripts")
  assert.equal(result?.decision, "ASK")
  assert.equal(result?.packages[0].presentAtStartup, true)
})

test("explicit npm install also checks other existing manifest dependencies", async (t) => {
  const directory = await project(t)
  await writeFile(path.join(directory, "package.json"), JSON.stringify({ devDependencies: { "missing-widget": "*" } }))
  const result = await gate(directory).check("npm install react")
  assert.equal(result?.decision, "ASK")
  assert.ok(result?.reasonCodes.includes("IG_PACKAGE_NOT_FOUND"))
})

test("npm ci checks transitive lockfile entries, not just CLI arguments", async (t) => {
  const directory = await project(t)
  await writeFile(path.join(directory, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: {
    "": {}, "node_modules/normal-widget/node_modules/fresh-widget": {
      version: "1.0.0", resolved: "https://registry.npmjs.org/fresh-widget/-/fresh-widget-1.0.0.tgz", integrity: "sha512-YWJj",
    },
  } }))
  const result = await gate(directory).check("npm ci")
  assert.equal(result?.decision, "ASK")
  assert.ok(result?.reasonCodes.includes("IG_FRESH_PACKAGE"))
  assert.equal(result?.packages[0].source, "lockfile")
})

for (const fixture of [
  { name: "workspace", file: "package.json", data: { workspaces: ["packages/*"] }, reason: "IG_UNSUPPORTED_WORKSPACES" },
  { name: "override", file: "package.json", data: { overrides: { react: "npm:lodahs" } }, reason: "IG_UNSUPPORTED_SOURCE" },
  { name: "URL dependency", file: "package.json", data: { dependencies: { react: "https://example.com/react.tgz" } }, reason: "IG_UNSUPPORTED_SOURCE" },
  { name: "old lockfile", file: "package-lock.json", data: { lockfileVersion: 1, dependencies: {} }, reason: "IG_UNSUPPORTED_LOCKFILE" },
  { name: "shrinkwrap", file: "npm-shrinkwrap.json", data: {}, reason: "IG_UNSUPPORTED_LOCKFILE" },
]) {
  test(`${fixture.name} fails closed instead of skipping unknown dependency resolution`, async (t) => {
    const directory = await project(t)
    await writeFile(path.join(directory, fixture.file), JSON.stringify(fixture.data))
    const result = await gate(directory).check("npm install react")
    assert.equal(result?.decision, "DENY")
    assert.ok(result?.reasonCodes.includes(fixture.reason as never))
  })
}

test("scoped registry in npmrc is rejected before any registry request", async (t) => {
  const directory = await project(t)
  await writeFile(path.join(directory, ".npmrc"), "@example:registry=https://private.example\n//private.example/:_authToken=NOT_A_REAL_TOKEN\n")
  let lookups = 0
  const result = await gate(directory, async () => { lookups++; return { status: "not_found" } }).check("npm i @example/normal-widget")
  assert.equal(result?.decision, "DENY")
  assert.ok(result?.reasonCodes.includes("IG_CUSTOM_REGISTRY"))
  assert.equal(lookups, 0)
  assert.ok(!JSON.stringify(result).includes("NOT_A_REAL_TOKEN"))
})

test("custom registry from host environment fails closed", async (t) => {
  const directory = await project(t)
  const result = await createInstallGate({ directory }, {
    registry: fixtureRegistry, environment: { HOME: directory, NPM_CONFIG_REGISTRY: "https://private.example" },
  }).check("npm i react")
  assert.ok(result?.reasonCodes.includes("IG_CUSTOM_REGISTRY"))
})

test("changed manifest during registry lookup is not passed to the executor", async (t) => {
  const directory = await project(t)
  const result = await gate(directory, async (name) => {
    await writeFile(path.join(directory, "package.json"), JSON.stringify({ dependencies: { "fresh-widget": "1.0.0" } }))
    return fixturePackage(name)
  }).check("npm i react@1.0.0")
  assert.equal(result?.decision, "DENY")
  assert.ok(result?.reasonCodes.includes("IG_PROJECT_CHANGED"))
})

test("a trusted reviewed record denies only its exact malicious version without registry access", async (t) => {
  const directory = await project(t)
  let lookups = 0
  const result = await createInstallGate({ directory, knownMalicious: [{
    id: "SYNTHETIC-TEST-ONLY", name: "normal-widget", registry: "https://registry.npmjs.org",
    versions: ["1.0.0"], sourceUrl: "https://example.invalid/synthetic-test-record", reviewedAt: "2026-09-05",
  }] }, {
    environment: { HOME: directory }, registry: async () => { lookups++; return fixturePackage("normal-widget") },
  }).check("npm i normal-widget@1.0.0")
  assert.equal(result?.decision, "DENY")
  assert.ok(result?.reasonCodes.includes("IG_KNOWN_MALICIOUS"))
  assert.equal(lookups, 0)
})

test("manifest symlinks and malformed JSON fail closed", async (t) => {
  const directory = await project(t)
  await writeFile(path.join(directory, "package.json"), "{")
  assert.equal((await gate(directory).check("npm i react"))?.decision, "DENY")
  await rm(path.join(directory, "package.json"))
  await writeFile(path.join(directory, "other.json"), "{}")
  await symlink(path.join(directory, "other.json"), path.join(directory, "package.json"))
  assert.ok((await gate(directory).check("npm i react"))?.reasonCodes.includes("IG_PROJECT_UNVERIFIED"))
})

test("missing lockfile in ci and workdirs outside the baseline fail closed", async (t) => {
  const directory = await project(t)
  const installGate = gate(directory)
  assert.ok((await installGate.check("npm ci"))?.reasonCodes.includes("IG_MANIFEST_REQUIRED"))
  assert.ok((await installGate.check("npm i react", path.dirname(directory)))?.reasonCodes.includes("IG_PROJECT_UNVERIFIED"))
})
