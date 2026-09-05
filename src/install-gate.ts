import path from "node:path"
import { extractInstallRequest } from "./install-parser.ts"
import { snapshotNpmProject } from "./install-project.ts"
import { createNpmRegistry, NPM_REGISTRY } from "./install-registry.ts"
import { REFERENCE_NPM_NAMES, similarNpmName } from "./install-similarity.ts"
import { exactNpmVersion, KNOWN_MALICIOUS_NPM, knownMaliciousEvidence, knownMaliciousFingerprint, snapshotKnownMalicious } from "./install-known-malicious.ts"
import { installWarnings } from "./install-warnings.ts"
import type { Classification, CommandContext } from "./types.ts"
import type {
  InstallGate, InstallReasonCode, InstallReport, KnownMaliciousRecord, PackageEvidence, PackageSpec, RegistryProvider,
} from "./install-types.ts"

const DAY_MS = 86_400_000

export interface InstallGateOptions {
  directory: string
  /** Trusted host settings only: never loaded from agent-writable files or natural language. */
  minPackageAgeDays?: number
  minVersionAgeDays?: number
  referenceNames?: readonly string[]
  /** Human-reviewed malicious releases, with exact versions and provenance; NOT name similarity. */
  knownMalicious?: readonly KnownMaliciousRecord[]
}

export interface InstallGateDependencies {
  registry?: RegistryProvider
  environment?: NodeJS.ProcessEnv
  now?: () => number
}

function unique<T>(items: T[]): T[] { return [...new Set(items)] }

function identity(spec: PackageSpec): string {
  return JSON.stringify([spec.name, spec.selector, spec.alias ?? null])
}

/** Heuristics/incomplete metadata -> ASK. Reviewed malicious versions -> DENY. Never auto-ALLOW. */
export function createInstallGate(options: InstallGateOptions, dependencies: InstallGateDependencies = {}): InstallGate {
  const directory = path.resolve(options.directory)
  const environment = { ...(dependencies.environment ?? process.env) }
  const now = dependencies.now ?? Date.now
  const registry = dependencies.registry ?? createNpmRegistry()
  const minPackageAgeDays = options.minPackageAgeDays ?? 7
  const minVersionAgeDays = options.minVersionAgeDays ?? 1
  if (![minPackageAgeDays, minVersionAgeDays].every((n) => Number.isFinite(n) && n >= 0)) {
    throw new Error("InstallGate age thresholds must be finite and nonnegative")
  }
  const references = Object.freeze([...(options.referenceNames ?? REFERENCE_NPM_NAMES)])
  const knownMalicious = snapshotKnownMalicious(options.knownMalicious ?? KNOWN_MALICIOUS_NPM)
  const database = {
    kind: options.knownMalicious === undefined ? "BUNDLED_REVIEWED" as const : "HOST_SUPPLIED" as const,
    recordCount: knownMalicious.length, sha256: knownMaliciousFingerprint(knownMalicious),
  }
  // Created immediately, not at the first npm invocation after the agent could have edited a manifest.
  const baselinePromise = snapshotNpmProject(directory, environment)
  const ready = baselinePromise.then(() => {})

  async function inspectPackage(spec: PackageSpec, baselineIDs: Set<string>): Promise<PackageEvidence> {
    const reasons: InstallReasonCode[] = []
    const presentAtStartup = baselineIDs.has(identity(spec))
    if (!presentAtStartup) reasons.push("IG_NEW_DEPENDENCY")
    const result: PackageEvidence = { ...spec, decision: "ASK", assessment: "NO_KNOWN_RISK", reasonCodes: reasons, presentAtStartup }
    const evidence = knownMaliciousEvidence(spec, knownMalicious)
    if (evidence.length) result.maliciousEvidence = evidence
    if (evidence.some((item) => item.match === "EXACT_VERSION")) {
      reasons.push("IG_KNOWN_MALICIOUS")
      result.decision = "DENY"
      result.assessment = "KNOWN_MALICIOUS"
      return result // A known revoked malicious release need not still exist in the live registry.
    }
    if (evidence.length) {
      reasons.push("IG_MALICIOUS_VERSION_UNRESOLVED")
      result.assessment = "SUSPICIOUS"
    }
    const similarity = similarNpmName(spec.name, references)
    // Aliases never hide the underlying package. Vocabulary entries themselves aren't allowlisted.
    if (similarity) {
      result.similarTo = similarity.name
      result.editDistance = similarity.distance
      reasons.push("IG_NAME_SIMILARITY")
      result.assessment = "SUSPICIOUS"
    }
    // Similar names still go through metadata lookup; never invent a malware verdict from spelling.

    let lookup: Awaited<ReturnType<RegistryProvider>>
    try { lookup = await registry(spec.name) }
    catch { lookup = { status: "unavailable" } }
    if (lookup.status !== "found") {
      reasons.push(lookup.status === "not_found" ? "IG_PACKAGE_NOT_FOUND" :
        lookup.status === "invalid" ? "IG_METADATA_INVALID" : "IG_REGISTRY_UNAVAILABLE")
      result.assessment = "UNVERIFIED"
      return result
    }
    const created = Date.parse(lookup.metadata.created)
    if (lookup.metadata.name !== spec.name || !Number.isFinite(created) || created > now()) {
      reasons.push("IG_METADATA_INVALID"); result.assessment = "UNVERIFIED"; return result
    }
    result.packageAgeDays = Math.floor((now() - created) / DAY_MS)
    if (now() - created < minPackageAgeDays * DAY_MS) { reasons.push("IG_FRESH_PACKAGE"); result.assessment = "SUSPICIOUS" }
    const exactVersion = exactNpmVersion(spec.selector)
    if (exactVersion) {
      const version = Object.hasOwn(lookup.metadata.versions, exactVersion) ? lookup.metadata.versions[exactVersion] : undefined
      if (!version) { reasons.push("IG_VERSION_NOT_FOUND"); result.assessment = "UNVERIFIED" }
      else {
        const published = Date.parse(version.published)
        if (!Number.isFinite(published) || published > now() || published < created) {
          reasons.push("IG_METADATA_INVALID"); result.assessment = "UNVERIFIED"
        } else {
          result.versionAgeDays = Math.floor((now() - published) / DAY_MS)
          if (now() - published < minVersionAgeDays * DAY_MS) { reasons.push("IG_FRESH_VERSION"); result.assessment = "SUSPICIOUS" }
        }
        if (version.deprecated) {
          reasons.push("IG_DEPRECATED")
          if (result.assessment === "NO_KNOWN_RISK") result.assessment = "SUSPICIOUS"
        }
      }
    } else {
      // Do not guess npm's range/tag/engine/lockfile resolution or claim a latest version was verified.
      reasons.push("IG_UNPINNED_VERSION")
      if (result.assessment === "NO_KNOWN_RISK") result.assessment = "UNVERIFIED"
    }
    return result
  }

  return {
    ready,
    async unchanged(report) {
      return (await snapshotNpmProject(directory, environment)).sha256 === report.snapshotSha256
    },
    async check(command, cwd = directory) {
      const request = extractInstallRequest(command)
      if (!request.detected) return undefined
      const startedAt = now()
      const baseline = await baselinePromise
      const current = await snapshotNpmProject(directory, environment)
      const reasons = [...request.reasonCodes, ...baseline.reasonCodes, ...current.reasonCodes]
      if (path.resolve(cwd) !== directory) reasons.push("IG_PROJECT_UNVERIFIED")
      if (request.kind === "ci" && (!current.manifest || !current.lockfile)) reasons.push("IG_MANIFEST_REQUIRED")
      if (request.kind === "install" && request.specs.length === 0 && !current.manifest) reasons.push("IG_MANIFEST_REQUIRED")
      const specs = [...request.specs, ...current.specs]
      const distinct = [...new Map(specs.map((spec) => [identity(spec), spec])).values()]
      if (distinct.length > 256) reasons.push("IG_PACKAGE_LIMIT")
      const baselineIDs = new Set(baseline.specs.map(identity))
      const report: InstallReport = {
        policyVersion: "npm-v2", registry: NPM_REGISTRY, decision: reasons.length ? "DENY" : "ASK",
        verdict: reasons.length ? "CHECK_BLOCKED" : "REVIEW_REQUIRED", knownMaliciousDatabase: { ...database }, warnings: [],
        reasonCodes: unique(reasons), packages: [], baselineSha256: baseline.sha256,
        snapshotSha256: current.sha256, checkedAt: new Date(now()).toISOString(), durationMs: 0,
        coverage: "npm-metadata-and-reviewed-records",
      }
      if (baseline.sha256 !== current.sha256) report.reasonCodes.push("IG_BASELINE_CHANGED")
      if (report.decision !== "DENY") {
        // Scan ALL extracted specs locally first: network timeouts/limits must not hide a later known bad version.
        const knownBad = distinct.filter((spec) => knownMaliciousEvidence(spec, knownMalicious).some((item) => item.match === "EXACT_VERSION"))
        if (knownBad.length) {
          report.packages = await Promise.all(knownBad.map((spec) => inspectPackage(spec, baselineIDs)))
          report.decision = "DENY"
          report.verdict = "KNOWN_MALICIOUS"
        }
      }
      if (report.decision !== "DENY") {
        // Four bounded network requests at a time; no npm subprocess or package scripts are invoked.
        const deadline = Date.now() + 15_000
        for (let at = 0; at < distinct.length; at += 4) {
          if (Date.now() >= deadline) {
            // Incomplete verification is surfaced to the human, not called 'malware'. Headless remains blocked.
            report.reasonCodes.push("IG_REGISTRY_UNAVAILABLE")
            break
          }
          const batch = await Promise.all(distinct.slice(at, at + 4).map((spec) => inspectPackage(spec, baselineIDs)))
          report.packages.push(...batch)
          if (batch.some((pkg) => pkg.decision === "DENY")) {
            report.decision = "DENY"
            report.verdict = "KNOWN_MALICIOUS"
          }
        }
        if ((await snapshotNpmProject(directory, environment)).sha256 !== current.sha256) {
          report.decision = "DENY"
          if (report.verdict !== "KNOWN_MALICIOUS") report.verdict = "CHECK_BLOCKED"
          report.reasonCodes.push("IG_PROJECT_CHANGED")
        }
      }
      report.reasonCodes = unique([...report.reasonCodes, ...report.packages.flatMap((pkg) => pkg.reasonCodes)])
      if (report.decision === "ASK") report.reasonCodes.push("IG_INSTALL_REQUIRES_APPROVAL")
      report.warnings = installWarnings(report)
      report.durationMs = Math.max(0, now() - startedAt)
      return report
    },
  }
}

export function denyInstallCheck(base: Classification, reason: InstallReasonCode): Classification {
  const report: InstallReport | undefined = base.installGate ? {
    ...base.installGate, decision: "DENY", verdict: "CHECK_BLOCKED", reasonCodes: unique([...base.installGate.reasonCodes, reason]),
  } : undefined
  if (report) report.warnings = installWarnings(report)
  return {
    ...base, decision: "DENY", effectiveDecision: "DENY",
    reasonCodes: unique([...base.reasonCodes, reason]),
    findings: [...base.findings, { command: base.command, decision: "DENY", route: "INSTALL_GATE", reasonCodes: [reason],
      detail: "check/approval could not be completed; this is not a malware verdict" }],
    ...(report ? { installGate: report } : {}),
  }
}

export async function applyInstallGate(base: Classification, gate: InstallGate, context: CommandContext = {}): Promise<Classification> {
  // A CommandGate hard DENY remains authoritative; don't send its arguments to the registry.
  if (base.decision === "DENY") return base
  let report: InstallReport | undefined
  try { report = await gate.check(base.command, context.cwd) }
  catch { return denyInstallCheck(base, "IG_CHECK_FAILED") }
  if (!report) {
    // The first layer recognised an install but the npm extractor couldn't prove its shape.
    return base.findings.some((finding) => finding.route === "INSTALL_GATE")
      ? denyInstallCheck(base, "IG_UNSUPPORTED_NPM") : base
  }
  const decision = report.decision
  return {
    ...base, decision, effectiveDecision: decision === "ASK" && context.mode === "headless" ? "DENY" : decision,
    route: base.route === "COMMAND_GATE" ? "COMPOSITE" : base.route,
    reasonCodes: unique([...base.reasonCodes, ...report.reasonCodes]),
    findings: [...base.findings, {
      command: base.command, decision, route: "INSTALL_GATE", reasonCodes: report.reasonCodes,
      detail: report.verdict === "KNOWN_MALICIOUS" ? "exact match in reviewed malicious-version records" :
        report.verdict === "CHECK_BLOCKED" ? "check could not be completed; not a malware verdict" :
          "review the warnings; metadata checks do not certify safety; approval is required",
    }],
    installGate: report,
  }
}
