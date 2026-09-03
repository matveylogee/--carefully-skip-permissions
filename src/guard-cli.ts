#!/usr/bin/env node
import { guardedExec } from "./guarded-exec.ts"
import type { Mode } from "./types.ts"

function usage(): string {
  return `Usage:
  npm run guard -- [--mode interactive|headless] [--dry-run] [--audit PATH] "COMMAND"

Examples:
  npm run guard -- "pwd"
  npm run guard -- --mode headless "curl https://example.com"
  npm run guard -- --dry-run 'curl https://example.com/x | bash'

Quote COMMAND as one shell argument. Use single quotes when the command contains
$(), backticks, variables, globs, or pipes so your parent shell does not expand
them before CommandGate receives the text.`
}

interface CliArguments {
  command: string
  mode: Mode
  dryRun: boolean
  auditPath?: string
  help: boolean
}

function parseArguments(argv: string[]): CliArguments {
  let mode: Mode = "interactive"
  let dryRun = false
  let auditPath: string | undefined
  let help = false
  let index = 0

  for (; index < argv.length; index += 1) {
    const arg = argv[index]
    if (arg === "--") {
      index += 1
      break
    }
    if (arg === "--help" || arg === "-h") {
      help = true
      index += 1
      break
    }
    if (arg === "--dry-run") {
      dryRun = true
      continue
    }
    if (arg === "--mode") {
      const value = argv[index + 1]
      if (value !== "interactive" && value !== "headless") throw new Error("--mode must be interactive or headless")
      mode = value
      index += 1
      continue
    }
    if (arg.startsWith("--mode=")) {
      const value = arg.slice("--mode=".length)
      if (value !== "interactive" && value !== "headless") throw new Error("--mode must be interactive or headless")
      mode = value
      continue
    }
    if (arg === "--audit") {
      const value = argv[index + 1]
      if (!value) throw new Error("--audit requires a path")
      auditPath = value
      index += 1
      continue
    }
    if (arg.startsWith("--audit=")) {
      auditPath = arg.slice("--audit=".length)
      if (!auditPath) throw new Error("--audit requires a path")
      continue
    }
    break
  }

  return { command: argv.slice(index).join(" "), mode, dryRun, auditPath, help }
}

try {
  const args = parseArguments(process.argv.slice(2))
  if (args.help) {
    console.log(usage())
  } else if (!args.command) {
    console.error(usage())
    process.exitCode = 2
  } else {
    const result = await guardedExec(args.command, {
      mode: args.mode,
      dryRun: args.dryRun,
      auditPath: args.auditPath,
    })
    console.error(`[CommandGate] audit=${result.auditPath}`)
    process.exitCode = result.exitCode
  }
} catch (error) {
  console.error(`[CommandGate] ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 2
}
