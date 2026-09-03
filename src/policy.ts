import path from "node:path"
import { scanShell } from "./scanner.ts"
import type {
  Classification,
  CommandContext,
  CommandFinding,
  Decision,
  ReasonCode,
  Route,
  SimpleCommand,
} from "./types.ts"

const DECISION_RANK: Record<Decision, number> = { ALLOW: 0, ASK: 1, DENY: 2 }

const READ_ONLY_COMMANDS = new Set([
  "basename",
  "cat",
  "cut",
  "date",
  "df",
  "dirname",
  "du",
  "echo",
  "false",
  "file",
  "grep",
  "head",
  "id",
  "jq",
  "ls",
  "pwd",
  "printf",
  "readlink",
  "realpath",
  "rg",
  "sort",
  "stat",
  "tail",
  "test",
  "tree",
  "true",
  "tr",
  "type",
  "uname",
  "uniq",
  "wc",
  "which",
  "whereis",
])

const VERSIONABLE_COMMANDS = new Set([
  "bash",
  "bun",
  "cargo",
  "deno",
  "git",
  "go",
  "java",
  "node",
  "npm",
  "pnpm",
  "python",
  "python3",
  "ruby",
  "rustc",
  "tsc",
  "yarn",
])

const INTERPRETERS = new Set([
  "bash",
  "dash",
  "deno",
  "fish",
  "node",
  "perl",
  "php",
  "python",
  "python3",
  "ruby",
  "sh",
  "zsh",
])

const PROJECT_EXECUTORS = new Set([
  "cargo",
  "go",
  "gradle",
  "gradlew",
  "make",
  "mvn",
  "pytest",
  "vitest",
])

const NETWORK_COMMANDS = new Set([
  "curl",
  "ftp",
  "nc",
  "netcat",
  "rsync",
  "scp",
  "sftp",
  "ssh",
  "telnet",
  "wget",
])

const REMOTE_SOURCE_COMMANDS = new Set(["curl", "wget"])
const PRIVILEGE_COMMANDS = new Set(["doas", "pkexec", "su", "sudo"])
const SYSTEM_CONTROL_COMMANDS = new Set(["halt", "poweroff", "reboot", "shutdown"])
const SERVICE_CONTROL_COMMANDS = new Set(["launchctl", "service", "systemctl"])
const DISK_DESTRUCTION_COMMANDS = new Set([
  "badblocks",
  "fdisk",
  "mkfs",
  "mkfs.btrfs",
  "mkfs.ext2",
  "mkfs.ext3",
  "mkfs.ext4",
  "mkfs.xfs",
  "parted",
  "shred",
  "wipefs",
])

const FILESYSTEM_WRITERS = new Set([
  "cp",
  "install",
  "ln",
  "mkdir",
  "mv",
  "patch",
  "rmdir",
  "tee",
  "touch",
  "truncate",
  "unlink",
])

const CLOUD_AND_DEPLOY_COMMANDS = new Set([
  "ansible",
  "aws",
  "az",
  "docker",
  "flyctl",
  "gcloud",
  "gh",
  "helm",
  "heroku",
  "kubectl",
  "pulumi",
  "terraform",
  "vercel",
])

function unique<T>(items: T[]): T[] {
  return [...new Set(items)]
}

function maxDecision(decisions: Decision[]): Decision {
  return decisions.reduce<Decision>(
    (highest, next) => (DECISION_RANK[next] > DECISION_RANK[highest] ? next : highest),
    "ALLOW",
  )
}

function executableName(value: string): string {
  const normalized = value.replaceAll("\\", "/")
  return path.posix.basename(normalized).toLowerCase()
}

function isAssignment(value: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*=.*/.test(value)
}

function unwrap(argv: string[]): { argv: string[]; wrappers: string[] } {
  let rest = [...argv]
  const wrappers: string[] = []

  while (rest.length > 0 && isAssignment(rest[0])) rest.shift()

  for (;;) {
    const executable = rest[0] ? executableName(rest[0]) : ""
    if (executable === "command" || executable === "builtin") {
      wrappers.push(executable)
      rest = rest.slice(1)
      while (rest[0]?.startsWith("-")) rest.shift()
      continue
    }
    if (executable === "env") {
      wrappers.push(executable)
      rest = rest.slice(1)
      while (rest.length > 0) {
        if (rest[0] === "--") {
          rest.shift()
          break
        }
        if (rest[0].startsWith("-") || isAssignment(rest[0])) {
          rest.shift()
          continue
        }
        break
      }
      continue
    }
    if (executable === "time" || executable === "nohup" || executable === "nice") {
      wrappers.push(executable)
      rest = rest.slice(1)
      if (executable === "nice" && rest[0] === "-n") rest = rest.slice(2)
      else while (rest[0]?.startsWith("-")) rest.shift()
      continue
    }
    break
  }

  return { argv: rest, wrappers }
}

function finding(
  command: SimpleCommand,
  decision: Decision,
  reasonCodes: ReasonCode[],
  route: Route = "COMMAND_GATE",
  detail?: string,
): CommandFinding {
  const normalized = unwrap(command.argv).argv
  return {
    command: command.raw,
    executable: normalized[0] ? executableName(normalized[0]) : undefined,
    decision,
    route,
    reasonCodes: unique(reasonCodes),
    detail,
  }
}

function hasFlag(args: string[], ...flags: string[]): boolean {
  return args.some((arg) => flags.includes(arg))
}

function hasShortFlag(args: string[], flag: string): boolean {
  return args.some((arg) => /^-[^-]/.test(arg) && arg.slice(1).includes(flag))
}

function isVersionQuery(args: string[]): boolean {
  return args.length === 1 && ["--version", "-version", "-V", "-v"].includes(args[0])
}

function isSensitivePath(value: string): boolean {
  const normalized = value
    .toLowerCase()
    .replaceAll("\\", "/")
    .replace(/^--[^=]+=/, "")
    .replace(/^.*=@/, "")
    .replace(/^@/, "")
  if (/(^|\/)\.env\.example$/.test(normalized)) return false
  return [
    /(^|\/)\.env(?:\.|$)/,
    /(^|\/)\.npmrc$/,
    /(^|\/)\.netrc$/,
    /(^|\/)\.pypirc$/,
    /(^|\/)\.ssh(?:\/|$)/,
    /(^|\/)\.aws\/credentials$/,
    /(^|\/)\.config\/gcloud(?:\/|$)/,
    /(^|\/)\.kube\/config$/,
    /(^|\/)id_(?:rsa|dsa|ecdsa|ed25519)(?:\.|$)/,
    /(^|\/)credentials(?:\.|$)/,
    /(^|\/)secrets?(?:\.|$)/,
    /\.pem$/,
    /\.key$/,
    /^\/etc\/shadow$/,
    /^\/proc\/(?:self|\d+)\/environ$/,
  ].some((pattern) => pattern.test(normalized))
}

function isProtectedPolicyPath(value: string): boolean {
  const normalized = value.toLowerCase().replaceAll("\\", "/")
  return [
    /(^|\/)\.kilo(?:code)?\/.*policy/,
    /(^|\/)command-gate(?:\/|\.|$)/,
    /(^|\/)install-gate(?:\/|\.|$)/,
    /(^|\/)\.npmrc$/,
  ].some((pattern) => pattern.test(normalized))
}

function containsSecretName(value: string): boolean {
  return /(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|github[_-]?token|openai[_-]?api[_-]?key|password|private[_-]?key|secret[_-]?access[_-]?key)/i.test(
    value,
  )
}

function isCatastrophicTarget(value: string): boolean {
  const normalized = value.replace(/\/+$/, "") || "/"
  return new Set([
    "/",
    "/*",
    ".",
    "./*",
    "..",
    "../*",
    "~",
    "~/*",
    "$HOME",
    "$HOME/*",
    "${HOME}",
    "${HOME}/*",
  ]).has(normalized)
}

function classifyGit(command: SimpleCommand, args: string[]): CommandFinding {
  const normalized: string[] = []
  let riskyGlobalConfig = false
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]
    if (arg === "-C") {
      index += 1
      continue
    }
    if (arg.startsWith("-C") && arg.length > 2) continue
    if (["--no-pager", "--no-replace-objects", "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs"].includes(arg)) continue
    if (arg === "-c" || arg.startsWith("-c") || arg.startsWith("--exec-path")) {
      riskyGlobalConfig = true
      if (arg === "-c") index += 1
      continue
    }
    normalized.push(...args.slice(index))
    break
  }
  if (riskyGlobalConfig) {
    return finding(command, "ASK", ["LOCAL_CODE_EXECUTION"], "COMMAND_GATE", "per-command git config may enable helpers or aliases")
  }

  const subcommand = normalized[0]
  const rest = normalized.slice(1)
  if (!subcommand || subcommand === "help" || subcommand === "--help") {
    return finding(command, "ALLOW", ["READ_ONLY_GIT"])
  }
  if (["status", "log", "show", "rev-parse", "grep", "blame", "ls-files", "ls-tree", "describe"].includes(subcommand)) {
    if (hasFlag(rest, "--ext-diff")) {
      return finding(command, "ASK", ["LOCAL_CODE_EXECUTION"], "COMMAND_GATE", "git external diff may execute a helper")
    }
    return finding(command, "ALLOW", ["READ_ONLY_GIT"])
  }
  if (subcommand === "diff") {
    if (hasFlag(rest, "--ext-diff")) return finding(command, "ASK", ["LOCAL_CODE_EXECUTION"])
    return finding(command, "ALLOW", ["READ_ONLY_GIT"])
  }
  if (subcommand === "branch") {
    if (rest.length === 0 || rest.every((arg) => ["--list", "-l", "-a", "-r", "--show-current", "-v", "-vv"].includes(arg))) {
      return finding(command, "ALLOW", ["READ_ONLY_GIT"])
    }
    return finding(command, "ASK", ["GIT_STATE_CHANGE"])
  }
  if (subcommand === "tag") {
    if (rest.length === 0 || hasFlag(rest, "--list", "-l")) return finding(command, "ALLOW", ["READ_ONLY_GIT"])
    return finding(command, "ASK", ["GIT_STATE_CHANGE"])
  }
  if (subcommand === "remote" && (rest.length === 0 || hasFlag(rest, "-v", "--verbose") || rest[0] === "get-url")) {
    return finding(command, "ALLOW", ["READ_ONLY_GIT"])
  }
  if (subcommand === "clean") {
    if (hasFlag(rest, "-n", "--dry-run")) return finding(command, "ALLOW", ["READ_ONLY_GIT"])
    return finding(command, "ASK", ["GIT_DESTRUCTIVE", "FILESYSTEM_DELETE"])
  }
  if (subcommand === "reset" && (hasFlag(rest, "--hard", "--merge", "--keep") || hasShortFlag(rest, "h"))) {
    return finding(command, "ASK", ["GIT_DESTRUCTIVE"], "COMMAND_GATE", "may discard local changes")
  }
  if (subcommand === "push") {
    const reasons: ReasonCode[] = ["GIT_REMOTE_WRITE", "EXTERNAL_SIDE_EFFECT"]
    if (hasFlag(rest, "--force", "-f", "--force-with-lease") || hasShortFlag(rest, "f")) reasons.push("GIT_DESTRUCTIVE")
    return finding(command, "ASK", reasons)
  }
  if (["fetch", "pull", "clone"].includes(subcommand)) {
    return finding(command, "ASK", ["NETWORK_ACCESS", "GIT_STATE_CHANGE"])
  }
  if (
    [
      "add",
      "am",
      "checkout",
      "cherry-pick",
      "commit",
      "merge",
      "mv",
      "rebase",
      "reset",
      "restore",
      "revert",
      "rm",
      "stash",
      "switch",
      "worktree",
    ].includes(subcommand)
  ) {
    return finding(command, "ASK", ["GIT_STATE_CHANGE"])
  }
  return finding(command, "ASK", ["UNKNOWN_COMMAND"], "COMMAND_GATE", `unclassified git subcommand: ${subcommand}`)
}

function classifyNpm(command: SimpleCommand, args: string[], sandboxed: boolean): CommandFinding {
  const normalized: string[] = []
  const optionsWithValues = new Set(["--cache", "--loglevel", "--prefix", "--registry", "--userconfig", "--workspace", "-w"])
  const optionsWithoutValues = new Set(["--global", "--ignore-scripts", "--silent", "--yes", "-g", "-s", "-y"])
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]
    if (optionsWithValues.has(arg)) {
      index += 1
      continue
    }
    if (optionsWithoutValues.has(arg) || [...optionsWithValues].some((option) => arg.startsWith(`${option}=`))) continue
    normalized.push(...args.slice(index))
    break
  }

  const subcommand = normalized[0]
  const subcommandArgs = normalized.slice(1)
  if (!subcommand || subcommand === "help") return finding(command, "ALLOW", ["READ_ONLY_COMMAND"])
  if (["install", "i", "add", "ci", "uninstall", "remove", "rm", "update", "up"].includes(subcommand)) {
    return finding(command, "ASK", ["PACKAGE_INSTALL"], "INSTALL_GATE", "requires dependency evidence before a final decision")
  }
  if (subcommand === "exec") {
    return finding(command, "ASK", ["PACKAGE_INSTALL", "LOCAL_CODE_EXECUTION"], "INSTALL_GATE")
  }
  if (["test", "t", "start", "stop", "restart", "run", "run-script"].includes(subcommand)) {
    return finding(command, sandboxed ? "ALLOW" : "ASK", ["PROJECT_CODE_EXECUTION"])
  }
  if (["view", "info", "show", "search", "list", "ls", "outdated", "config"].includes(subcommand)) {
    if (subcommand === "config" && ["set", "delete", "rm"].includes(subcommandArgs[0])) {
      const policyChange = subcommandArgs.some((arg) => /registry|ignore-scripts|userconfig/i.test(arg))
      return finding(command, policyChange ? "DENY" : "ASK", [policyChange ? "POLICY_TAMPERING" : "EXTERNAL_SIDE_EFFECT"])
    }
    return finding(command, "ALLOW", ["READ_ONLY_COMMAND"])
  }
  if (["publish", "unpublish", "deprecate", "dist-tag", "owner", "access", "token", "login", "logout", "whoami"].includes(subcommand)) {
    return finding(command, "ASK", ["PACKAGE_PUBLISH", "EXTERNAL_SIDE_EFFECT"])
  }
  return finding(command, "ASK", ["UNKNOWN_COMMAND"], "COMMAND_GATE", `unclassified npm subcommand: ${subcommand}`)
}

function classifySimple(command: SimpleCommand, context: Required<Pick<CommandContext, "sandboxed">>, depth: number): CommandFinding {
  const rawArgv = [...command.argv]
  if (rawArgv.length === 0) return finding(command, "ALLOW", ["EMPTY_COMMAND"])

  const rawExecutable = executableName(rawArgv.find((arg) => !isAssignment(arg)) ?? rawArgv[0])
  if (PRIVILEGE_COMMANDS.has(rawExecutable)) {
    return finding(command, "DENY", ["PRIVILEGE_ESCALATION"])
  }

  const { argv, wrappers } = unwrap(rawArgv)
  if (argv.length === 0) {
    return finding(command, "ASK", [wrappers.includes("env") ? "SECRET_ACCESS" : "UNKNOWN_COMMAND"])
  }

  const executable = executableName(argv[0])
  const args = argv.slice(1)
  if (PRIVILEGE_COMMANDS.has(executable)) {
    return finding(command, "DENY", ["PRIVILEGE_ESCALATION"])
  }

  if ((executable === "busybox" || executable === "toybox") && args.length > 0 && depth < 3) {
    const nested = classifySimple({ ...command, argv: args }, context, depth + 1)
    return { ...nested, command: command.raw, detail: `${executable} applet recursively classified` }
  }
  const sensitiveArgs = args.filter(isSensitivePath)
  const policyArgs = args.filter(isProtectedPolicyPath)

  if (containsSecretName(argv.join(" "))) {
    return finding(command, "ASK", ["SECRET_ACCESS"])
  }

  if (VERSIONABLE_COMMANDS.has(executable) && isVersionQuery(args)) {
    return finding(command, "ALLOW", ["VERSION_QUERY"])
  }

  if (SYSTEM_CONTROL_COMMANDS.has(executable)) return finding(command, "DENY", ["SYSTEM_CONTROL"])
  if (SERVICE_CONTROL_COMMANDS.has(executable)) return finding(command, "ASK", ["SYSTEM_CONTROL"])
  if (DISK_DESTRUCTION_COMMANDS.has(executable) || executable.startsWith("mkfs.")) {
    return finding(command, "DENY", ["DISK_DESTRUCTION"])
  }

  if (executable === "dd") return finding(command, "DENY", ["DISK_DESTRUCTION"])
  if (executable === "kill" || executable === "killall" || executable === "pkill") {
    if (args.includes("-1") || args.includes("1") || args.includes("-9") && args.includes("-1")) {
      return finding(command, "DENY", ["PROCESS_CONTROL", "SYSTEM_CONTROL"])
    }
    return finding(command, "ASK", ["PROCESS_CONTROL"])
  }

  if (executable === "rm") {
    const recursive = hasFlag(args, "--recursive", "-r", "-R") || hasShortFlag(args, "r") || hasShortFlag(args, "R")
    const forced = hasFlag(args, "--force", "-f") || hasShortFlag(args, "f")
    const targets = args.filter((arg) => !arg.startsWith("-"))
    if (recursive && forced && targets.some(isCatastrophicTarget)) {
      return finding(command, "DENY", ["CATASTROPHIC_DELETE", "FILESYSTEM_DELETE"])
    }
    if (policyArgs.length > 0) return finding(command, "DENY", ["POLICY_TAMPERING", "FILESYSTEM_DELETE"])
    return finding(command, "ASK", ["FILESYSTEM_DELETE"])
  }

  if (executable === "chmod" || executable === "chown" || executable === "chgrp") {
    const recursive = hasFlag(args, "--recursive", "-R") || hasShortFlag(args, "R")
    const rootTarget = args.some(isCatastrophicTarget)
    if (recursive && rootTarget) return finding(command, "DENY", ["SYSTEM_CONTROL", "FILESYSTEM_WRITE"])
    return finding(command, "ASK", ["FILESYSTEM_WRITE"])
  }

  if (executable === "git") return classifyGit(command, args)
  if (executable === "npm") return classifyNpm(command, args, context.sandboxed)
  if (executable === "npx") return finding(command, "ASK", ["PACKAGE_INSTALL", "LOCAL_CODE_EXECUTION"], "INSTALL_GATE")

  if (["pnpm", "yarn", "bun"].includes(executable)) {
    const installLike = ["add", "install", "i", "remove", "rm", "update", "up", "x", "dlx"].includes(args[0])
    if (installLike) return finding(command, "ASK", ["PACKAGE_INSTALL", "UNSUPPORTED_PACKAGE_MANAGER"])
    if (["test", "run", "start"].includes(args[0])) return finding(command, "ASK", ["PROJECT_CODE_EXECUTION"])
  }

  if (["pip", "pip3", "poetry", "uv", "gem", "composer"].includes(executable)) {
    const installLike = args.some((arg) => ["install", "add", "sync", "update"].includes(arg))
    if (installLike) return finding(command, "ASK", ["PACKAGE_INSTALL", "UNSUPPORTED_PACKAGE_MANAGER"])
  }
  if (["apt", "apt-get", "brew", "dnf", "pacman", "yum"].includes(executable)) {
    return finding(command, "ASK", ["PACKAGE_INSTALL", "UNSUPPORTED_PACKAGE_MANAGER"])
  }
  if ((executable === "cargo" && args[0] === "add") || (executable === "go" && args[0] === "get")) {
    return finding(command, "ASK", ["PACKAGE_INSTALL", "UNSUPPORTED_PACKAGE_MANAGER"])
  }

  if (INTERPRETERS.has(executable)) {
    const cIndex = args.findIndex((arg) => arg === "-c" || arg === "--command")
    if (cIndex >= 0 && args[cIndex + 1] !== undefined && depth < 3 && ["bash", "dash", "fish", "sh", "zsh"].includes(executable)) {
      const nested = classifyCommand(args[cIndex + 1], { mode: "interactive", sandboxed: context.sandboxed }, depth + 1)
      return finding(
        command,
        nested.decision,
        nested.reasonCodes,
        nested.route,
        "literal shell command recursively classified",
      )
    }
    return finding(command, "ASK", ["LOCAL_CODE_EXECUTION"])
  }

  if (["eval", "source", ".", "exec", "xargs"].includes(executable)) {
    return finding(command, "ASK", ["DYNAMIC_SHELL", "LOCAL_CODE_EXECUTION"])
  }

  if (executable === "find") {
    if (args.some((arg) => ["-delete", "-exec", "-execdir", "-ok", "-okdir"].includes(arg))) {
      return finding(command, "ASK", ["FILESYSTEM_DELETE", "LOCAL_CODE_EXECUTION"])
    }
    return sensitiveArgs.length > 0
      ? finding(command, "ASK", ["SENSITIVE_PATH_READ"])
      : finding(command, "ALLOW", ["READ_ONLY_COMMAND"])
  }

  if (executable === "sed") {
    if (args.some((arg) => arg === "-i" || arg.startsWith("-i"))) {
      if (policyArgs.length > 0) return finding(command, "DENY", ["POLICY_TAMPERING", "FILESYSTEM_WRITE"])
      return finding(command, "ASK", ["FILESYSTEM_WRITE"])
    }
    return finding(command, "ASK", ["LOCAL_CODE_EXECUTION"], "COMMAND_GATE", "sed programs can execute or write depending on dialect")
  }

  if (executable === "awk" || executable === "gawk") {
    return finding(command, "ASK", ["LOCAL_CODE_EXECUTION"], "COMMAND_GATE", "awk programs may invoke system()")
  }

  if (executable === "rg" && args.some((arg) => arg === "--pre" || arg.startsWith("--pre="))) {
    return finding(command, "ASK", ["LOCAL_CODE_EXECUTION"])
  }

  if (NETWORK_COMMANDS.has(executable)) {
    const uploadsData = args.some((arg) =>
      ["-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "-F", "--form", "-T", "--upload-file"].some(
        (flag) => arg === flag || arg.startsWith(`${flag}=`),
      ),
    )
    if ((uploadsData || ["scp", "sftp", "rsync"].includes(executable)) && sensitiveArgs.length > 0) {
      return finding(command, "DENY", ["DATA_EXFILTRATION", "SENSITIVE_PATH_READ", "NETWORK_ACCESS"])
    }
    return finding(command, "ASK", [uploadsData ? "DATA_EXFILTRATION" : "NETWORK_ACCESS"])
  }

  if (FILESYSTEM_WRITERS.has(executable)) {
    if (policyArgs.length > 0) return finding(command, "DENY", ["POLICY_TAMPERING", "FILESYSTEM_WRITE"])
    return finding(command, "ASK", ["FILESYSTEM_WRITE"])
  }

  if (PROJECT_EXECUTORS.has(executable)) {
    return finding(command, context.sandboxed ? "ALLOW" : "ASK", ["PROJECT_CODE_EXECUTION"])
  }

  if (executable === "printenv" || executable === "env" || executable === "set") {
    if (args.length === 1 && !containsSecretName(args[0])) return finding(command, "ALLOW", ["READ_ONLY_COMMAND"])
    return finding(command, "ASK", ["SECRET_ACCESS"])
  }

  if (CLOUD_AND_DEPLOY_COMMANDS.has(executable)) {
    return finding(command, "ASK", ["EXTERNAL_SIDE_EFFECT"])
  }

  if (READ_ONLY_COMMANDS.has(executable)) {
    if (sensitiveArgs.length > 0) return finding(command, "ASK", ["SENSITIVE_PATH_READ"])
    return finding(command, "ALLOW", ["READ_ONLY_COMMAND"])
  }

  return finding(command, "ASK", ["UNKNOWN_COMMAND"])
}

function applyRedirections(base: CommandFinding, command: SimpleCommand): CommandFinding {
  const reasons = [...base.reasonCodes]
  let decision = base.decision

  for (const redirection of command.redirections) {
    const target = redirection.target
    if (!target) {
      decision = maxDecision([decision, "ASK"])
      reasons.push("PARSE_ERROR")
      continue
    }
    const writes = redirection.operator.includes(">") && !redirection.operator.includes(">&")
    const reads = redirection.operator.includes("<") && !redirection.operator.includes("<&")
    if (writes && target !== "/dev/null") {
      if (isProtectedPolicyPath(target)) {
        decision = "DENY"
        reasons.push("POLICY_TAMPERING")
      } else if (isSensitivePath(target)) {
        decision = "DENY"
        reasons.push("SENSITIVE_PATH_WRITE")
      } else {
        decision = maxDecision([decision, "ASK"])
        reasons.push("OUTPUT_REDIRECTION")
      }
    }
    if (reads && isSensitivePath(target)) {
      decision = maxDecision([decision, "ASK"])
      reasons.push("SENSITIVE_PATH_READ")
    }
  }

  return { ...base, decision, reasonCodes: unique(reasons) }
}

function routeFor(findings: CommandFinding[]): Route {
  const routes = new Set(findings.map((item) => item.route))
  if (routes.size === 1) return findings[0]?.route ?? "COMMAND_GATE"
  return "COMPOSITE"
}

function isRemoteInterpreterPipeline(commands: SimpleCommand[], connectors: string[]): boolean {
  for (let index = 0; index < connectors.length; index += 1) {
    if (connectors[index] !== "|" && connectors[index] !== "|&") continue
    const left = unwrap(commands[index]?.argv ?? []).argv[0]
    const right = unwrap(commands[index + 1]?.argv ?? []).argv[0]
    if (!left || !right) continue
    if (REMOTE_SOURCE_COMMANDS.has(executableName(left)) && INTERPRETERS.has(executableName(right))) return true
  }
  return false
}

export function classifyCommand(input: string, context: CommandContext = {}, depth = 0): Classification {
  const mode = context.mode ?? "interactive"
  const normalizedContext = { sandboxed: context.sandboxed ?? false }
  const scan = scanShell(input)
  const findings = scan.commands.map((command) => applyRedirections(classifySimple(command, normalizedContext, depth), command))

  if (/\(\)\s*\{[^}]*:\s*\|\s*:\s*&/s.test(input)) {
    findings.push({
      command: input,
      decision: "DENY",
      route: "COMMAND_GATE",
      reasonCodes: ["SYSTEM_CONTROL"],
      detail: "fork-bomb pattern",
    })
  }

  if (isRemoteInterpreterPipeline(scan.commands, scan.connectors)) {
    findings.push({
      command: input,
      decision: "DENY",
      route: "COMMAND_GATE",
      reasonCodes: ["REMOTE_CODE_EXECUTION", "NETWORK_ACCESS"],
      detail: "network response is piped directly to an interpreter",
    })
  }

  if (scan.hasDynamicExpansion) {
    findings.push({
      command: input,
      decision: "ASK",
      route: "COMMAND_GATE",
      reasonCodes: ["DYNAMIC_SHELL"],
      detail: "runtime expansion prevents a complete static decision",
    })
  }
  if (scan.hasBackgroundExecution) {
    findings.push({
      command: input,
      decision: "ASK",
      route: "COMMAND_GATE",
      reasonCodes: ["BACKGROUND_EXECUTION"],
    })
  }
  if (scan.hasUnsupportedSyntax) {
    findings.push({
      command: input,
      decision: "ASK",
      route: "COMMAND_GATE",
      reasonCodes: ["UNSUPPORTED_SHELL_SYNTAX"],
    })
  }
  if (scan.errors.length > 0) {
    findings.push({
      command: input,
      decision: "ASK",
      route: "COMMAND_GATE",
      reasonCodes: ["PARSE_ERROR"],
      detail: scan.errors.join("; "),
    })
  }
  if (findings.length === 0) {
    findings.push({ command: input, decision: "ALLOW", route: "COMMAND_GATE", reasonCodes: ["EMPTY_COMMAND"] })
  }

  const decision = maxDecision(findings.map((item) => item.decision))
  const effectiveDecision: Decision = mode === "headless" && decision === "ASK" ? "DENY" : decision
  const reasonCodes = unique(findings.flatMap((item) => item.reasonCodes))

  return {
    command: input,
    decision,
    effectiveDecision,
    route: routeFor(findings),
    reasonCodes,
    findings,
    parseErrors: scan.errors,
  }
}
