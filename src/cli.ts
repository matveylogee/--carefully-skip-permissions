#!/usr/bin/env node
import { classifyCommand } from "./policy.ts"
import type { Mode } from "./types.ts"

const args = process.argv.slice(2)
const modeFlag = args.indexOf("--mode")
let mode: Mode = "interactive"
if (modeFlag >= 0) {
  const value = args[modeFlag + 1]
  if (value !== "interactive" && value !== "headless") {
    console.error("--mode must be interactive or headless")
    process.exit(2)
  }
  mode = value
  args.splice(modeFlag, 2)
}

const sandboxedFlag = args.indexOf("--sandboxed")
const sandboxed = sandboxedFlag >= 0
if (sandboxedFlag >= 0) args.splice(sandboxedFlag, 1)

const command = args.join(" ")
if (!command) {
  console.error('usage: npm run classify -- [--mode interactive|headless] [--sandboxed] "COMMAND"')
  process.exit(2)
}

console.log(JSON.stringify(classifyCommand(command, { mode, sandboxed }), null, 2))
