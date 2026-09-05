import { createHash } from "node:crypto"
import { validNpmName } from "./install-parser.ts"
import type { KnownMaliciousRecord, MaliciousEvidence, PackageSpec } from "./install-types.ts"

export const EXACT_NPM_VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/

/** Only syntactically exact versions; never resolve a tag, range, engine constraint or lockfile. */
export function exactNpmVersion(selector: string): string | undefined {
  const value = selector.trim().replace(/^=\s*/, "").replace(/^v/, "")
  return EXACT_NPM_VERSION.test(value) ? value : undefined
}

// Small, manually reviewed seed: 3 packages / 5 versions, NOT a live malware database.
// No payloads or tarballs are stored or downloaded. Sources were checked on 2026-09-05.
const SEED: KnownMaliciousRecord[] = [
  {
    id: "ESLINT-2018-SCOPE", name: "eslint-scope", registry: "https://registry.npmjs.org",
    versions: ["3.7.2"], reviewedAt: "2026-09-05",
    sourceUrl: "https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/",
  },
  {
    id: "ESLINT-2018-CONFIG", name: "eslint-config-eslint", registry: "https://registry.npmjs.org",
    versions: ["5.0.2"], reviewedAt: "2026-09-05",
    sourceUrl: "https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/",
  },
  {
    id: "GHSA-pjwm-rvh2-c87w", name: "ua-parser-js", registry: "https://registry.npmjs.org",
    versions: ["0.7.29", "0.8.0", "1.0.0"], reviewedAt: "2026-09-05",
    sourceUrl: "https://github.com/advisories/GHSA-pjwm-rvh2-c87w",
  },
]

/** Validate provenance fields and snapshot trusted policy. This is not automatic source verification. */
export function snapshotKnownMalicious(records: readonly KnownMaliciousRecord[]): readonly KnownMaliciousRecord[] {
  const ids = new Set<string>()
  return Object.freeze(records.map((record) => {
    const url = new URL(record.sourceUrl)
    if (!/^[A-Za-z0-9._-]{1,128}$/.test(record.id) || ids.has(record.id) || !validNpmName(record.name) ||
      record.registry !== "https://registry.npmjs.org" || !Array.isArray(record.versions) || !record.versions.length ||
      !record.versions.every((version) => typeof version === "string" && EXACT_NPM_VERSION.test(version)) ||
      url.protocol !== "https:" || url.username || url.password || /[\u0000-\u0020\u007f]/.test(record.sourceUrl) ||
      !/^\d{4}-\d\d-\d\d$/.test(record.reviewedAt) || !Number.isFinite(Date.parse(record.reviewedAt))) {
      throw new Error("Known-malicious records require exact npm versions, a source URL and a review date")
    }
    ids.add(record.id)
    return Object.freeze({ ...record, versions: Object.freeze([...new Set(record.versions)]) })
  }))
}

export const KNOWN_MALICIOUS_NPM = snapshotKnownMalicious(SEED)

export function knownMaliciousFingerprint(records: readonly KnownMaliciousRecord[]): string {
  return createHash("sha256").update(JSON.stringify(records)).digest("hex")
}

/** A compromised release does not condemn all past/future versions under the same name. */
export function knownMaliciousEvidence(spec: PackageSpec, records: readonly KnownMaliciousRecord[]): MaliciousEvidence[] {
  const exact = exactNpmVersion(spec.selector)
  return records.filter((record) => record.name === spec.name && (!exact || record.versions.includes(exact)))
    .map((record) => ({
      recordId: record.id, sourceUrl: record.sourceUrl, reviewedAt: record.reviewedAt,
      affectedVersions: [...record.versions], match: exact ? "EXACT_VERSION" : "UNRESOLVED_VERSION",
    }))
}
