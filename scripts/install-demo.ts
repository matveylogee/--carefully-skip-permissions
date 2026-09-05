import { mkdtemp, realpath, writeFile, rm } from "node:fs/promises"
import path from "node:path"
import os from "node:os"
import { createInstallGate, applyInstallGate } from "../src/install-gate.ts"
import { classifyCommand } from "../src/policy.ts"
import { fixtureRegistry, FIXTURE_NOW } from "../fixtures/install-registry.ts"
import { formatInstallReview } from "../src/install-warnings.ts"

const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "install-gate-demo-")))
try {
  await writeFile(path.join(directory, "package.json"), JSON.stringify({ name: "lab", dependencies: {} }))
  const gate = createInstallGate({ directory }, { registry: fixtureRegistry, now: () => FIXTURE_NOW, environment: { HOME: directory } })
  console.log("OFFLINE DEMO: synthetic registry metadata + reviewed malicious-version records. No package is installed; no shell command is executed.\n")
  for (const command of [
    "npm install react@1.0.0", "npm install l3ft-pad", "npm install missing-widget",
    "npm install fresh-widget@1.0.0", "npm install local@npm:lodahs", "npm install eslint-scope@3.7.2", "npm install https://example.com/code.tgz",
  ]) {
    const result = await applyInstallGate(classifyCommand(command), gate, { cwd: directory })
    console.log(`${result.decision.padEnd(4)}  ${command}  [${result.installGate?.verdict}]`)
    console.log(`      ${result.installGate?.reasonCodes.join(", ")}\n`)
    if (command === "npm install l3ft-pad") console.log(formatInstallReview(result.installGate!) + "\n")
  }
  await writeFile(path.join(directory, "package.json"), JSON.stringify({ dependencies: { "fresh-widget": "1.0.0" } }))
  const result = await gate.check("npm install")
  console.log(`${result?.decision}  manifest changed by agent -> npm install`)
  console.log(`      ${result?.reasonCodes.join(", ")}`)
} finally { await rm(directory, { recursive: true, force: true }) }
