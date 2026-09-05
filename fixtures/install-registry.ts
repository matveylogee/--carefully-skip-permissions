import type { RegistryLookup, RegistryProvider } from "../src/install-types.ts"

// Entirely synthetic metadata, even for names of real packages. Never query or install these fixtures.
export const FIXTURE_NOW = Date.parse("2026-09-05T12:00:00.000Z")
export const OLD_CREATED = "2020-01-01T00:00:00.000Z"
export const OLD_RELEASE = "2025-01-01T00:00:00.000Z"

export function fixturePackage(name: string, overrides: { created?: string; published?: string; version?: string; deprecated?: boolean } = {}): RegistryLookup {
  return {
    status: "found",
    metadata: {
      name, created: overrides.created ?? OLD_CREATED,
      versions: { [overrides.version ?? "1.0.0"]: { published: overrides.published ?? OLD_RELEASE, deprecated: overrides.deprecated ?? false } },
    },
  }
}

export const fixtureRegistry: RegistryProvider = async (name) => {
  if (name === "missing-widget") return { status: "not_found" }
  if (name === "offline-widget") return { status: "unavailable" }
  if (name === "broken-widget") return { status: "invalid" }
  if (name === "fresh-widget") return fixturePackage(name, { created: "2026-09-05T00:00:00.000Z", published: "2026-09-05T01:00:00.000Z" })
  if (name === "release-widget") return fixturePackage(name, { published: "2026-09-05T01:00:00.000Z" })
  if (name === "deprecated-widget") return fixturePackage(name, { deprecated: true })
  if (["react", "eslint", "cowsay", "axios", "@types/node", "@example/normal-widget", "normal-widget", "lodash", "l3ft-pad", "expres", "lodahs"].includes(name)) {
    return fixturePackage(name)
  }
  return { status: "not_found" }
}
