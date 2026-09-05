import { validNpmName } from "./install-parser.ts"
import type { PackageMetadata, RegistryLookup, RegistryProvider } from "./install-types.ts"

export const NPM_REGISTRY = "https://registry.npmjs.org" as const

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined
}

function date(value: unknown): value is string {
  return typeof value === "string" && /^\d{4}-\d\d-\d\dT/.test(value) && Number.isFinite(Date.parse(value))
}

/** Drop README, scripts, links, author names and every other natural-language field. */
export function parseNpmMetadata(name: string, raw: unknown): RegistryLookup {
  const pack = object(raw)
  const times = object(pack?.time)
  const versions = object(pack?.versions)
  if (!pack || pack.name !== name || !times || !date(times.created) || !versions || Object.keys(versions).length === 0) {
    return { status: "invalid" }
  }
  const metadata: PackageMetadata = { name, created: times.created, versions: Object.create(null) }
  for (const [version, rawVersion] of Object.entries(versions)) {
    const entry = object(rawVersion)
    if (!date(times[version]) || !entry || entry.name !== name || entry.version !== version) continue
    metadata.versions[version] = {
      published: times[version] as string,
      deprecated: typeof entry.deprecated === "string" && entry.deprecated.length > 0,
    }
  }
  if (Object.keys(metadata.versions).length === 0) return { status: "invalid" }
  return { status: "found", metadata }
}

export interface RegistryOptions {
  fetch?: typeof globalThis.fetch
  timeoutMs?: number
  maxBytes?: number
  cacheTtlMs?: number
  now?: () => number
}

/** Fixed public host, no credentials, no redirects, no tarballs, bounded response and cache. */
export function createNpmRegistry(options: RegistryOptions = {}): RegistryProvider {
  const fetchMetadata = options.fetch ?? globalThis.fetch
  const timeoutMs = options.timeoutMs ?? 8_000
  const maxBytes = options.maxBytes ?? 16 * 1024 * 1024
  const cacheTtlMs = options.cacheTtlMs ?? 60_000
  const now = options.now ?? Date.now
  const cache = new Map<string, { expires: number; result: RegistryLookup }>()
  const inflight = new Map<string, Promise<RegistryLookup>>()

  async function query(name: string): Promise<RegistryLookup> {
    const abort = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    const operation = async (): Promise<RegistryLookup> => {
      try {
        const response = await fetchMetadata(`${NPM_REGISTRY}/${encodeURIComponent(name)}`, {
          method: "GET",
          headers: { Accept: "application/json" },
          credentials: "omit",
          redirect: "error",
          signal: abort.signal,
        })
        if (response.status === 404) { await response.body?.cancel(); return { status: "not_found" } }
        if (!response.ok) { await response.body?.cancel(); return { status: "unavailable" } }
        if (Number(response.headers.get("content-length")) > maxBytes || !response.body) {
          await response.body?.cancel()
          return { status: "unavailable" }
        }
        const reader = response.body.getReader()
        const chunks: Uint8Array[] = []
        let length = 0
        try {
          for (;;) {
            const { done, value } = await reader.read()
            if (done) break
            length += value.byteLength
            if (length > maxBytes) { await reader.cancel(); return { status: "unavailable" } }
            chunks.push(value)
          }
        } finally { reader.releaseLock() }
        try { return parseNpmMetadata(name, JSON.parse(Buffer.concat(chunks).toString("utf8"))) }
        catch { return { status: "invalid" } }
      } catch {
        return { status: "unavailable" }
      }
    }
    try {
      return await Promise.race([
        operation(),
        new Promise<RegistryLookup>((resolve) => {
          timer = setTimeout(() => { abort.abort(); resolve({ status: "unavailable" }) }, timeoutMs)
        }),
      ])
    } finally { clearTimeout(timer) }
  }

  return async (name) => {
    if (!validNpmName(name)) return { status: "invalid" }
    const cached = cache.get(name)
    if (cached && cached.expires > now()) return structuredClone(cached.result)
    if (!inflight.has(name)) {
      const pending = query(name).then((result) => {
        // Do not turn a transient failure into a persistent negative cache.
        if (result.status === "found") {
          if (cache.size >= 128) cache.delete(cache.keys().next().value!)
          cache.set(name, { expires: now() + cacheTtlMs, result })
        }
        return result
      }).finally(() => inflight.delete(name))
      inflight.set(name, pending)
    }
    return structuredClone(await inflight.get(name)!)
  }
}
