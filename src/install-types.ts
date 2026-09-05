export type InstallReasonCode =
  | "IG_CHECK_FAILED"
  | "IG_UNSUPPORTED_SHELL"
  | "IG_UNSUPPORTED_NPM"
  | "IG_UNSUPPORTED_OPTION"
  | "IG_UNSUPPORTED_SOURCE"
  | "IG_INVALID_PACKAGE"
  | "IG_CUSTOM_REGISTRY"
  | "IG_CONFIG_UNVERIFIED"
  | "IG_PROJECT_UNVERIFIED"
  | "IG_PROJECT_CHANGED"
  | "IG_BASELINE_CHANGED"
  | "IG_NEW_DEPENDENCY"
  | "IG_MANIFEST_REQUIRED"
  | "IG_UNSUPPORTED_WORKSPACES"
  | "IG_UNSUPPORTED_LOCKFILE"
  | "IG_PACKAGE_LIMIT"
  | "IG_REGISTRY_UNAVAILABLE"
  | "IG_METADATA_INVALID"
  | "IG_PACKAGE_NOT_FOUND"
  | "IG_VERSION_NOT_FOUND"
  | "IG_FRESH_PACKAGE"
  | "IG_FRESH_VERSION"
  | "IG_NAME_SIMILARITY"
  | "IG_KNOWN_MALICIOUS"
  | "IG_MALICIOUS_VERSION_UNRESOLVED"
  | "IG_DEPRECATED"
  | "IG_UNPINNED_VERSION"
  | "IG_INSTALL_REQUIRES_APPROVAL"

export interface PackageSpec {
  name: string
  selector: string
  /** The local install name when npm alias syntax is used. */
  alias?: string
  source: "command" | "manifest" | "lockfile"
}

export interface InstallRequest {
  detected: boolean
  kind?: "install" | "ci" | "exec"
  specs: PackageSpec[]
  reasonCodes: InstallReasonCode[]
}

export interface PackageMetadata {
  name: string
  created: string
  versions: Record<string, { published: string; deprecated: boolean }>
}

export type RegistryLookup =
  | { status: "found"; metadata: PackageMetadata }
  | { status: "not_found" }
  | { status: "unavailable" | "invalid" }

export type RegistryProvider = (name: string) => Promise<RegistryLookup>

export interface PackageEvidence extends PackageSpec {
  decision: "ASK" | "DENY"
  assessment: "NO_KNOWN_RISK" | "SUSPICIOUS" | "UNVERIFIED" | "KNOWN_MALICIOUS"
  reasonCodes: InstallReasonCode[]
  presentAtStartup: boolean
  packageAgeDays?: number
  versionAgeDays?: number
  similarTo?: string
  editDistance?: number
  maliciousEvidence?: MaliciousEvidence[]
}

/** Human-reviewed host data, never loaded from the agent's project or a registry description. */
export interface KnownMaliciousRecord {
  id: string
  name: string
  registry: "https://registry.npmjs.org"
  versions: readonly string[]
  sourceUrl: string
  reviewedAt: string
}

export interface MaliciousEvidence {
  recordId: string
  sourceUrl: string
  reviewedAt: string
  affectedVersions: string[]
  match: "EXACT_VERSION" | "UNRESOLVED_VERSION"
}

export interface InstallWarning {
  code: InstallReasonCode
  package?: string
  message: string
}

export interface InstallReport {
  policyVersion: "npm-v2"
  registry: "https://registry.npmjs.org"
  decision: "ASK" | "DENY"
  /** CHECK_BLOCKED is an execution/check failure, not an accusation against a package. */
  verdict: "REVIEW_REQUIRED" | "KNOWN_MALICIOUS" | "CHECK_BLOCKED"
  knownMaliciousDatabase: { kind: "BUNDLED_REVIEWED" | "HOST_SUPPLIED"; recordCount: number; sha256: string }
  reasonCodes: InstallReasonCode[]
  warnings: InstallWarning[]
  packages: PackageEvidence[]
  baselineSha256: string
  snapshotSha256: string
  checkedAt: string
  durationMs: number
  /** No tarball or scripts were executed; this is metadata evidence, not a malware verdict. */
  coverage: "npm-metadata-and-reviewed-records"
}

export interface InstallGate {
  /** Snapshot starts when the gate is created, before the first agent tool call. */
  ready: Promise<void>
  check(command: string, cwd?: string): Promise<InstallReport | undefined>
  unchanged(report: InstallReport): Promise<boolean>
}
