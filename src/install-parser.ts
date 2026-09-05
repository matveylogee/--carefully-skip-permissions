import path from "node:path"
import { scanShell } from "./scanner.ts"
import type { InstallReasonCode, InstallRequest, PackageSpec } from "./install-types.ts"

const INSTALL = new Set(["install", "i", "add", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall"])
const NON_INSTALL = new Set([
  "help", "view", "info", "show", "search", "list", "ls", "outdated", "config", "get", "set",
  "test", "t", "start", "stop", "restart", "run", "run-script", "publish", "unpublish",
  "deprecate", "dist-tag", "owner", "access", "token", "login", "logout", "whoami", "root", "prefix",
])
const FLAGS = new Set([
  "--save", "--no-save", "--save-dev", "--save-prod", "--save-optional", "--save-peer", "--save-exact",
  "--ignore-scripts", "--no-audit", "--no-fund", "--yes", "--no", "--silent", "--dry-run",
  "-D", "-P", "-O", "-E", "-y", "-s",
])
const SOURCE_PROTOCOL = /^(?:[a-z][a-z+.-]*:|[./~]|[A-Za-z]:\\)/i
const NAME_PART = /^[a-z0-9][a-z0-9._-]*$/

export function validNpmName(name: string): boolean {
  if (name.length > 214 || name === "node_modules" || name === "favicon.ico") return false
  const parts = name.startsWith("@") ? name.slice(1).split("/") : [name]
  return parts.length === (name.startsWith("@") ? 2 : 1) && parts.every((part) => NAME_PART.test(part))
}

/** Only registry names/selectors and a single npm alias are accepted; URLs are never fetched. */
export function parsePackageSpec(
  value: string,
  source: PackageSpec["source"] = "command",
): { spec?: PackageSpec; reason?: InstallReasonCode } {
  if (value.length > 512 || /[\u0000-\u001f\u007f]/.test(value)) return { reason: "IG_INVALID_PACKAGE" }
  if (SOURCE_PROTOCOL.test(value)) return { reason: "IG_UNSUPPORTED_SOURCE" }
  const separator = value.indexOf("@", value.startsWith("@") ? 1 : 0)
  const name = separator < 0 ? value : value.slice(0, separator)
  const selector = separator < 0 ? "*" : value.slice(separator + 1)
  if (!validNpmName(name)) {
    return { reason: name.includes("/") && !name.startsWith("@") ? "IG_UNSUPPORTED_SOURCE" : "IG_INVALID_PACKAGE" }
  }
  if (selector.startsWith("npm:")) {
    const target = parsePackageSpec(selector.slice(4), source)
    if (!target.spec || target.spec.alias) return { reason: target.reason ?? "IG_UNSUPPORTED_SOURCE" }
    return { spec: { ...target.spec, alias: name } }
  }
  if (!selector || /[:/\\@]/.test(selector)) return { reason: "IG_UNSUPPORTED_SOURCE" }
  // Selectors are NOT resolved here. Ranges/tags stay ASK, never "verified version".
  if (!/^[a-zA-Z0-9.*+^~<>=| -]+$/.test(selector)) return { reason: "IG_INVALID_PACKAGE" }
  return { spec: { name, selector, source } }
}

function executable(value: string): string {
  return path.posix.basename(value)
}

function unwrap(words: string[]): { words: string[]; unsafe: boolean } {
  const result = [...words]
  let unsafe = false
  const assignments = () => {
    while (/^[A-Za-z_][A-Za-z0-9_]*=/.test(result[0] ?? "")) {
      // Only locale assignments have known semantics. In particular PATH/NPM_CONFIG_* are not ignored.
      if (!/^(?:LC_ALL|LANG|LC_CTYPE)=[A-Za-z0-9_.@-]+$/.test(result[0])) unsafe = true
      result.shift()
    }
  }
  assignments()
  for (let count = 0; count < 12; count += 1) {
    const name = executable(result[0] ?? "")
    if (name === "env") {
      result.shift()
      if (result[0] === "--") result.shift()
      assignments()
    } else if (["command", "builtin", "exec", "nohup"].includes(name)) {
      result.shift()
      if (result[0] === "--") result.shift()
    } else if (name === "nice" || name === "time") {
      result.shift()
      if (result[0] === "-n") result.splice(0, 2)
      else if (result[0]?.startsWith("-")) { result.shift(); unsafe = true }
    } else break
  }
  return { words: result, unsafe }
}

export function extractInstallRequest(command: string, depth = 0): InstallRequest {
  const scan = scanShell(command)
  const result: InstallRequest = { detected: false, specs: [], reasonCodes: [] }
  for (const simple of scan.commands) {
    const { words, unsafe } = unwrap(simple.argv)
    const name = executable(words[0] ?? "")
    if (["sh", "bash", "dash", "zsh"].includes(name) && depth < 3) {
      const cIndex = words.indexOf("-c")
      if (cIndex < 0 || !words[cIndex + 1]) continue
      const nested = extractInstallRequest(words[cIndex + 1], depth + 1)
      if (!nested.detected) continue
      Object.assign(result, nested)
      if (words.length !== 3 || cIndex !== 1 || unsafe) result.reasonCodes.push("IG_UNSUPPORTED_SHELL")
      continue
    }
    if (name !== "npm" && name !== "npx") continue
    const args = words.slice(1)
    let subcommand: string | undefined = name === "npx" ? "exec" : undefined
    const specs: string[] = []
    const packages: string[] = []
    const reasons: InstallReasonCode[] = []
    let afterDash = false
    let execBinarySeen = false
    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index]
      if (!afterDash && arg === "--") { afterDash = true; continue }
      // After the executable, flags belong to that executable, not npm/npx.
      // npx stops parsing at its first positional argument. npm exec keeps
      // accepting npm options until --, even after the binary name.
      if (subcommand === "exec" && execBinarySeen && (name === "npx" || afterDash)) continue
      if (!afterDash && arg.startsWith("-")) {
        if (FLAGS.has(arg) || /^--(?:ignore-scripts|save|save-dev|save-exact)=(?:true|false)$/.test(arg)) continue
        const equals = arg.indexOf("=")
        const key = equals < 0 ? arg : arg.slice(0, equals)
        if (["--registry", "--prefix", "--package", "-p"].includes(key)) {
          const value = equals < 0 ? args[++index] : arg.slice(equals + 1)
          if (!value) { reasons.push("IG_UNSUPPORTED_OPTION"); continue }
          if (key === "--registry") {
            if (!/^https:\/\/registry\.npmjs\.org\/?$/.test(value)) reasons.push("IG_CUSTOM_REGISTRY")
          } else if (key === "--prefix") {
            if (value !== "." && value !== "./") reasons.push("IG_PROJECT_UNVERIFIED")
          } else {
            packages.push(value)
          }
          continue
        }
        reasons.push("IG_UNSUPPORTED_OPTION")
        continue
      }
      if (!subcommand) { subcommand = arg; continue }
      if (subcommand === "exec" && execBinarySeen) continue
      specs.push(arg)
      if (subcommand === "exec") execBinarySeen = true
    }
    if (name === "npm" && subcommand && NON_INSTALL.has(subcommand)) continue
    if (name === "npm" && !subcommand && (args.length === 0 || args.length === 1 && ["--version", "-v", "--help", "-h"].includes(args[0]))) continue
    result.detected = true
    result.kind = subcommand === "ci" ? "ci" : ["exec", "x"].includes(subcommand) ? "exec" : "install"
    if (!subcommand || !(INSTALL.has(subcommand) || ["ci", "exec"].includes(subcommand))) reasons.push("IG_UNSUPPORTED_NPM")
    if (unsafe || simple.redirections.length > 0) reasons.push("IG_UNSUPPORTED_SHELL")
    if (result.kind === "ci" && specs.length > 0) reasons.push("IG_UNSUPPORTED_OPTION")
    if (result.kind !== "exec" && packages.length > 0) reasons.push("IG_UNSUPPORTED_OPTION")
    if (result.kind === "exec" && specs.length === 0) reasons.push("IG_UNSUPPORTED_NPM")
    const targets = result.kind === "exec" && packages.length ? packages : specs
    for (const target of targets) {
      const parsed = parsePackageSpec(target)
      if (parsed.spec) result.specs.push(parsed.spec)
      else reasons.push(parsed.reason!)
    }
    result.reasonCodes.push(...reasons)
  }
  if (result.detected && (scan.commands.length !== 1 || scan.connectors.length > 0 || scan.hasDynamicExpansion ||
    scan.hasUnsupportedSyntax || scan.hasBackgroundExecution || scan.errors.length > 0)) {
    result.reasonCodes.push("IG_UNSUPPORTED_SHELL")
  }
  result.reasonCodes = [...new Set(result.reasonCodes)]
  return result
}
