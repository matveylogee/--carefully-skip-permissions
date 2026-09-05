import { createHash } from "node:crypto"
import { lstat, open, realpath } from "node:fs/promises"
import { constants } from "node:fs"
import os from "node:os"
import path from "node:path"
import { parsePackageSpec, validNpmName } from "./install-parser.ts"
import type { InstallReasonCode, PackageSpec } from "./install-types.ts"

export interface ProjectSnapshot {
  sha256: string
  specs: PackageSpec[]
  manifest: boolean
  lockfile: boolean
  reasonCodes: InstallReasonCode[]
}

const DEPENDENCY_FIELDS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]
const MAX_FILE_BYTES = 4 * 1024 * 1024
const MAX_PACKAGES = 256

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined
}

async function readStaticFile(filename: string): Promise<string | undefined> {
  try {
    const entry = await lstat(filename)
    if (!entry.isFile() || entry.isSymbolicLink() || entry.size > MAX_FILE_BYTES) throw new Error("unverified project file")
    const handle = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0))
    try {
      const stat = await handle.stat()
      if (!stat.isFile() || stat.size > MAX_FILE_BYTES) throw new Error("unverified project file")
      const buffer = Buffer.alloc(MAX_FILE_BYTES + 1)
      let offset = 0
      for (;;) {
        const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, null)
        offset += bytesRead
        if (offset > MAX_FILE_BYTES) throw new Error("project file size limit")
        if (!bytesRead) break
      }
      return buffer.toString("utf8", 0, offset)
    } finally { await handle.close() }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined
    throw error
  }
}

function registryValue(value: string): boolean {
  return /^https:\/\/registry\.npmjs\.org\/?$/.test(value.trim().replace(/^["']|["']$/g, ""))
}

function inspectNpmrc(text: string, reasons: InstallReasonCode[]): void {
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*(?:[#;]|$)/.test(line)) continue
    const equals = line.indexOf("=")
    if (equals < 0) { reasons.push("IG_CONFIG_UNVERIFIED"); continue }
    const key = line.slice(0, equals).trim().toLowerCase().replaceAll("_", "-")
    const value = line.slice(equals + 1).trim()
    if ((key === "registry" || key.endsWith(":registry")) && !registryValue(value)) reasons.push("IG_CUSTOM_REGISTRY")
    if (["prefix", "global", "location", "userconfig", "globalconfig", "workspace", "workspaces", "script-shell", "tag", "before"].includes(key)) {
      reasons.push("IG_CONFIG_UNVERIFIED")
    }
  }
}

/** Read bounded JSON/config as data. Never invoke npm, execute scripts, or trust project policy files. */
export async function snapshotNpmProject(directory: string, environment: NodeJS.ProcessEnv = process.env): Promise<ProjectSnapshot> {
  const specs: PackageSpec[] = []
  const reasons: InstallReasonCode[] = []
  const contents = new Map<string, string | undefined>()
  const manifestFile = path.join(directory, "package.json")
  const lockFile = path.join(directory, "package-lock.json")
  const homeDirectory = path.resolve(environment.HOME ?? os.homedir())
  const userConfig = path.join(homeDirectory, ".npmrc")
  const globalConfig = path.resolve(path.dirname(process.execPath), "..", "etc", "npmrc")
  const configs = new Set([userConfig, globalConfig])
  for (let at = directory;; at = path.dirname(at)) {
    configs.add(path.join(at, ".npmrc"))
    if (path.dirname(at) === at) break
  }
  const envFingerprint: Array<[string, string]> = []
  for (const [key, value] of Object.entries(environment)) {
    if (value === undefined || !/^npm_config_/i.test(key)) continue
    const option = key.replace(/^npm_config_/i, "").toLowerCase().replaceAll("_", "-")
    envFingerprint.push([option, value])
    if (option === "registry" && !registryValue(value)) reasons.push("IG_CUSTOM_REGISTRY")
    if (option === "userconfig" || option === "globalconfig") {
      // npm run exports its effective config paths. Inspect them, don't silently ignore them.
      if (!path.isAbsolute(value)) reasons.push("IG_CONFIG_UNVERIFIED")
      else configs.add(value)
    }
    if (["prefix", "global", "location", "workspace", "workspaces", "script-shell", "tag", "before"].includes(option)) {
      if (!(option === "prefix" && path.resolve(value) === path.resolve(path.dirname(process.execPath), ".."))) {
        reasons.push("IG_CONFIG_UNVERIFIED")
      }
    }
  }
  try {
    if (await realpath(directory) !== directory) reasons.push("IG_PROJECT_UNVERIFIED")
  } catch { reasons.push("IG_PROJECT_UNVERIFIED") }

  for (const filename of [manifestFile, lockFile, path.join(directory, "npm-shrinkwrap.json"), path.join(directory, "yarn.lock"), ...configs]) {
    try { contents.set(filename, await readStaticFile(filename)) }
    catch { contents.set(filename, "<unreadable>"); reasons.push("IG_PROJECT_UNVERIFIED") }
  }
  for (const filename of configs) {
    const text = contents.get(filename)
    if (text !== undefined && text !== "<unreadable>") inspectNpmrc(text, reasons)
  }
  if (contents.get(path.join(directory, "npm-shrinkwrap.json")) !== undefined || contents.get(path.join(directory, "yarn.lock")) !== undefined) {
    reasons.push("IG_UNSUPPORTED_LOCKFILE")
  }

  function add(name: string, value: unknown, source: PackageSpec["source"]): void {
    if (typeof value !== "string" || !validNpmName(name)) { reasons.push("IG_INVALID_PACKAGE"); return }
    const parsed = parsePackageSpec(`${name}@${value}`, source)
    if (parsed.spec) specs.push(parsed.spec)
    else reasons.push(parsed.reason!)
  }

  const manifest = contents.get(manifestFile)
  if (manifest !== undefined) {
    try {
      const data = object(JSON.parse(manifest))
      if (!data) throw new Error("manifest shape")
      if (data.workspaces !== undefined) reasons.push("IG_UNSUPPORTED_WORKSPACES")
      // Overrides require a resolver; don't pretend top-level dependency names cover them.
      if (data.overrides !== undefined || data.bundleDependencies !== undefined || data.bundledDependencies !== undefined) {
        reasons.push("IG_UNSUPPORTED_SOURCE")
      }
      for (const field of DEPENDENCY_FIELDS) {
        if (data[field] === undefined) continue
        const dependencies = object(data[field])
        if (!dependencies) throw new Error("dependency map")
        for (const [name, value] of Object.entries(dependencies)) add(name, value, "manifest")
      }
    } catch { reasons.push("IG_PROJECT_UNVERIFIED") }
  }

  const lock = contents.get(lockFile)
  if (lock !== undefined) {
    try {
      const data = object(JSON.parse(lock))
      const packages = object(data?.packages)
      if (!data || ![2, 3].includes(data.lockfileVersion as number) || !packages) throw new Error("lock shape")
      for (const [location, raw] of Object.entries(packages)) {
        if (location === "") continue
        const entry = object(raw)
        const matched = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/.exec(location)
        if (!entry || !matched || entry.link === true) { reasons.push("IG_UNSUPPORTED_LOCKFILE"); continue }
        const name = typeof entry.name === "string" ? entry.name : matched[1]
        if (typeof entry.resolved !== "string" || typeof entry.integrity !== "string" || !/^sha(?:256|384|512)-[A-Za-z0-9+/=]+$/.test(entry.integrity)) {
          reasons.push("IG_UNSUPPORTED_LOCKFILE")
        } else {
          const url = new URL(entry.resolved)
          if (url.origin !== "https://registry.npmjs.org" || url.username || url.password || url.hash || url.search) reasons.push("IG_CUSTOM_REGISTRY")
          if (!decodeURIComponent(url.pathname).startsWith(`/${name}/-/`)) reasons.push("IG_UNSUPPORTED_LOCKFILE")
        }
        add(name, entry.version, "lockfile")
      }
    } catch { reasons.push("IG_UNSUPPORTED_LOCKFILE") }
  }
  if (specs.length > MAX_PACKAGES) reasons.push("IG_PACKAGE_LIMIT")
  const sha256 = createHash("sha256").update(JSON.stringify([
    [...contents.entries()].sort(([a], [b]) => a.localeCompare(b)), envFingerprint.sort(([a], [b]) => a.localeCompare(b)),
  ])).digest("hex")
  return {
    sha256, specs: specs.slice(0, MAX_PACKAGES), manifest: manifest !== undefined,
    lockfile: lock !== undefined, reasonCodes: [...new Set(reasons)],
  }
}
