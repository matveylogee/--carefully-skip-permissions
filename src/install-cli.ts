#!/usr/bin/env node
import { createInstallGate, applyInstallGate } from "./install-gate.ts"
import { classifyCommand } from "./policy.ts"
import type { Mode } from "./types.ts"

const args = process.argv.slice(2)
let mode: Mode = "interactive"
if (args[0] === "--mode") {
  if (args[1] !== "interactive" && args[1] !== "headless") {
    console.error("--mode must be interactive or headless")
    process.exit(2)
  }
  mode = args[1]
  args.splice(0, 2)
}
if (args[0] === "--") args.shift()
if (args.length !== 1 || !args[0].trim()) {
  console.error('usage: npm run install-check -- [--mode interactive|headless] "COMMAND"\nRead-only metadata check; the command is NEVER executed.')
  process.exit(2)
}
const cwd = process.cwd()
const result = await applyInstallGate(classifyCommand(args[0], { mode, cwd }), createInstallGate({ directory: cwd }), { mode, cwd })
console.log(JSON.stringify({ ...result, executed: false }, null, 2))
process.exitCode = result.effectiveDecision === "DENY" ? 126 : 0
