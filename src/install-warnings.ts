import type { InstallReasonCode, InstallReport, InstallWarning } from "./install-types.ts"

const MESSAGES: Partial<Record<InstallReasonCode, string>> = {
  IG_NEW_DEPENDENCY: "New dependency: it was not present in the startup snapshot.",
  IG_FRESH_PACKAGE: "Recently published package; age is a risk signal, not proof of malware.",
  IG_FRESH_VERSION: "Recently published version; age is a risk signal, not proof of malware.",
  IG_PACKAGE_NOT_FOUND: "The public registry returned 404. Existence and safety are unverified; check the package name.",
  IG_VERSION_NOT_FOUND: "The exact version was not found in registry metadata. Check the requested version.",
  IG_REGISTRY_UNAVAILABLE: "Registry verification could not finish. No safety conclusion can be drawn; retry or review manually.",
  IG_METADATA_INVALID: "Registry metadata is invalid or inconsistent. This is not a malware verdict.",
  IG_UNPINNED_VERSION: "The exact installed version is unresolved; version-specific checks are incomplete.",
  IG_DEPRECATED: "The requested version is deprecated. Review the dependency before approving.",
  IG_BASELINE_CHANGED: "Project dependency/configuration files differ from the startup snapshot.",
  IG_PROJECT_CHANGED: "Project files changed during review. This approval is no longer valid; a new check is required.",
}

export function installWarnings(report: InstallReport): InstallWarning[] {
  const warnings: InstallWarning[] = []
  for (const pkg of report.packages) {
    const target = `${pkg.name}@${pkg.selector}`
    for (const code of pkg.reasonCodes) {
      let message = MESSAGES[code]
      if (code === "IG_NAME_SIMILARITY") message = `Name resembles ${pkg.similarTo} (edit distance ${pkg.editDistance}). Similarity alone does not establish malware.`
      if (code === "IG_KNOWN_MALICIOUS") message = "This exact version matches a reviewed malicious-release record. Installation is denied."
      if (code === "IG_MALICIOUS_VERSION_UNRESOLVED") message = "This package has reported malicious releases, but the requested version is unresolved. Pin and review an exact version."
      if (message) warnings.push({ code, package: target, message })
    }
  }
  const packageCodes = new Set(report.packages.flatMap((pkg) => pkg.reasonCodes))
  for (const code of report.reasonCodes) {
    if (packageCodes.has(code) || code === "IG_INSTALL_REQUIRES_APPROVAL") continue
    warnings.push({ code, message: MESSAGES[code] ?? "This check cannot safely handle the requested action; this is not a malware verdict." })
  }
  return warnings
}

/** Deterministic human-readable text; no package README/description/author text is displayed. */
export function formatInstallReview(report: InstallReport, maxChars = 8_000): string {
  const header = report.verdict === "KNOWN_MALICIOUS"
    ? "[InstallGate] DENY: exact match in reviewed malicious-version records."
    : report.verdict === "CHECK_BLOCKED"
      ? "[InstallGate] CHECK BLOCKED: the action could not be verified; this is not a malware verdict."
      : "[InstallGate] ASK: review package risks before approving ONCE. This is not a safety certificate."
  const lines = [header]
  // Put material risks before routine 'new dependency' notices so a bounded UI retains the reason.
  const warnings = [...report.warnings].sort((a, b) => Number(a.code === "IG_NEW_DEPENDENCY") - Number(b.code === "IG_NEW_DEPENDENCY"))
  for (const warning of warnings) lines.push(`${warning.package ? `${warning.package}: ` : ""}${warning.message} [${warning.code}]`)
  for (const pkg of report.packages) {
    for (const evidence of pkg.maliciousEvidence ?? []) {
      lines.push(`${pkg.name}: ${evidence.recordId}; affected versions ${evidence.affectedVersions.join(", ")}; source ${evidence.sourceUrl}; reviewed ${evidence.reviewedAt}`)
    }
  }
  if (report.verdict === "REVIEW_REQUIRED") lines.push("Approve only this call if you accept the risks, or Reject. Do not grant a wildcard/Always permission.")
  const result = lines.join("\n")
  const suffix = "\n[TRUNCATED: inspect the full installGate audit before approving.]"
  return result.length <= maxChars ? result : result.slice(0, Math.max(header.length, maxChars - suffix.length)) + suffix
}
