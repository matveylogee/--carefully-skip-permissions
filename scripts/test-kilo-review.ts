/** Optional contract smoke: real Kilo 7.5.9 + local scripted model/registry, no package install. */
import assert from "node:assert/strict"
import { spawn } from "node:child_process"
import { once } from "node:events"
import { mkdtemp, realpath, readFile, rm, writeFile } from "node:fs/promises"
import { createServer } from "node:http"
import os from "node:os"
import path from "node:path"
import { setTimeout as delay } from "node:timers/promises"
import { fileURLToPath, pathToFileURL } from "node:url"

const binary = process.argv[2]
if (!binary) throw new Error("Usage: node scripts/test-kilo-review.ts /absolute/path/to/kilo")
const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "kilo-review-smoke-")))
const root = fileURLToPath(new URL("../", import.meta.url))
const command = "npm install --dry-run --ignore-scripts l3ft-pad"
let address = ""
let log = ""
let child: ReturnType<typeof spawn> | undefined
const events: Record<string, any>[] = []
const requests: string[] = []
const controller = new AbortController()
const timer = setTimeout(() => controller.abort(new Error("Kilo review smoke exceeded 45 seconds")), 45_000)
const model = createServer(async (request, response) => {
  try {
    const chunks: Buffer[] = []
    for await (const chunk of request) chunks.push(chunk)
    const body = JSON.parse(Buffer.concat(chunks).toString())
    requests.push(`${request.url} tools=${body.tools?.length ?? 0}`)
    const tool = body.tools?.some((entry: { function?: { name?: string } }) => entry.function?.name === "bash")
      && !body.messages?.some((message: { role?: string }) => message.role === "tool")
    const message = tool
      ? { role: "assistant", content: null, tool_calls: [{ id: "call-review-smoke", type: "function", function: { name: "bash", arguments: JSON.stringify({ command, description: "Original model description" }) } }] }
      : { role: "assistant", content: "Stopped after rejection." }
    const base = { id: "chatcmpl-review-fixture", created: 1, model: "fixture" }
    if (body.stream) {
      response.writeHead(200, { "Content-Type": "text/event-stream" })
      const delta = tool ? { ...message, tool_calls: message.tool_calls!.map((call) => ({ index: 0, ...call })) } : message
      response.write(`data: ${JSON.stringify({ ...base, object: "chat.completion.chunk", choices: [{ index: 0, delta, finish_reason: null }] })}\n\n`)
      response.write(`data: ${JSON.stringify({ ...base, object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: tool ? "tool_calls" : "stop" }] })}\n\n`)
      response.end("data: [DONE]\n\n")
    } else {
      response.writeHead(200, { "Content-Type": "application/json" })
      response.end(JSON.stringify({ ...base, object: "chat.completion", choices: [{ index: 0, message, finish_reason: tool ? "tool_calls" : "stop" }] }))
    }
  } catch (error) {
    response.writeHead(500).end(String(error))
  }
})

async function api(endpoint: string, body?: unknown) {
  const response = await fetch(`${address}${endpoint}`, {
    ...(body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
    signal: controller.signal,
  })
  const text = await response.text()
  assert.ok(response.ok, `${endpoint}: ${response.status} ${text}`)
  return text ? JSON.parse(text) : undefined
}

try {
  model.listen(0, "127.0.0.1")
  await once(model, "listening")
  const port = (model.address() as { port: number }).port
  // Only the evidence provider is synthetic. Hooks, storage/permission transport,
  // Kilo's processor and HTTP/SSE path are the production implementations.
  const imports = (file: string) => JSON.stringify(pathToFileURL(path.join(root, "src", file)).href)
  const plugin = `import { createInstallGate } from ${imports("install-gate.ts")};
import { createKiloCommandGatePlugin, createKiloPermissionReplier } from ${imports("kilo-plugin.ts")};
import { createKiloReviewPublisher } from ${imports("kilo-review.ts")};
export default { id: "review-smoke", server: async ({ directory, client }) => createKiloCommandGatePlugin({ directory, mode: "interactive" }, {
  installGate: createInstallGate({ directory }, { registry: async () => ({ status: "not_found" }), environment: {} }),
  publishReview: createKiloReviewPublisher(client), replyPermission: createKiloPermissionReplier(client)
}) };`
  await writeFile(path.join(directory, "plugin.ts"), plugin)
  await writeFile(path.join(directory, "package.json"), '{"name":"review-lab","private":true}')
  await writeFile(path.join(directory, "kilo.json"), JSON.stringify({
    permission: { bash: { "*": "ask" } },
    model: "gate-fixture/fixture", small_model: "gate-fixture/fixture",
    enabled_providers: ["gate-fixture"],
    provider: { "gate-fixture": { name: "Local fixture", npm: "@ai-sdk/openai-compatible", options: { baseURL: `http://127.0.0.1:${port}/v1`, apiKey: "local-fixture" }, models: { fixture: { name: "fixture", limit: { context: 16000, output: 1000 } } } } },
    plugin: [pathToFileURL(path.join(directory, "plugin.ts")).href],
  }))
  child = spawn(binary, ["serve", "--hostname", "127.0.0.1", "--port", "0"], {
    cwd: directory, stdio: ["ignore", "pipe", "pipe"],
    env: { PATH: process.env.PATH, XDG_CONFIG_HOME: path.join(directory, "config"), XDG_DATA_HOME: path.join(directory, "data"), XDG_STATE_HOME: path.join(directory, "state"), XDG_CACHE_HOME: path.join(directory, "cache"), KILO_COMMAND_GATE_MODE: "interactive", KILO_DISABLE_MODELS_FETCH: "true", KILO_DISABLE_DEFAULT_PLUGINS: "true" },
  })
  for (const stream of [child.stdout!, child.stderr!]) stream.on("data", (data) => {
    log += data.toString()
    address = log.match(/http:\/\/127\.0\.0\.1:\d+/)?.[0] ?? address
  })
  child.on("error", (error) => controller.abort(error))
  while (!address) await delay(50, undefined, { signal: controller.signal })
  const session = await api("/session", {})
  const stream = await fetch(`${address}/event`, { signal: controller.signal })
  const listening = (async () => {
    let buffered = ""
    for await (const chunk of stream.body!) {
      buffered += new TextDecoder().decode(chunk)
      const blocks = buffered.split("\n\n")
      buffered = blocks.pop()!
      for (const block of blocks) {
        const raw = block.split("\n").find((line) => line.startsWith("data: "))
        if (raw) {
          const event = JSON.parse(raw.slice(6))
          // 7.5.9 uses sync envelopes for durable message parts and plain events
          // for permissions. Apply the same unwrapping as the host's UI store.
          events.push(event.type === "sync" ? {
            type: event.syncEvent.type.replace(/\.\d+$/, ""), properties: event.syncEvent.data,
          } : event)
        }
      }
    }
  })().catch((error) => { if (!controller.signal.aborted) throw error })
  await api(`/session/${session.id}/prompt_async`, { model: { providerID: "gate-fixture", modelID: "fixture" }, parts: [{ type: "text", text: "Run the exact dry-run fixture command once, stop if rejected." }] })
  let asked: Record<string, any> | undefined
  while (!asked) {
    const failure = events.find((event) => event.type === "session.error")
    if (failure) throw new Error(JSON.stringify(failure))
    if (events.some((event) => event.type === "session.idle")) throw new Error("Session ended without the expected permission request")
    asked = events.find((event) => event.type === "permission.asked")
    await delay(25, undefined, { signal: controller.signal })
  }
  const request = asked.properties
  assert.equal(request.permission, "bash")
  assert.equal(request.metadata.command, command)
  // This is exactly the persisted input read by PermissionPrompt in Kilo 7.5.9.
  const before = events.slice(0, events.indexOf(asked)).filter((event) => event.type === "message.part.updated" && event.properties.part?.callID === request.tool.callID)
  const part = before.at(-1)?.properties.part
  assert.ok(part, "tool part must reach the UI before permission.asked")
  assert.match(part.state.input.description, /Name resembles left-pad/)
  assert.equal(part.state.input.command, command)
  assert.doesNotMatch(part.state.input.description, /Original model description/)
  const stored = await api(`/session/${session.id}/message/${request.tool.messageID}`)
  assert.match(stored.parts.find((entry: { callID?: string }) => entry.callID === request.tool.callID).state.input.description, /Name resembles left-pad/)
  await api(`/session/${session.id}/permissions/${request.id}`, { response: "reject" })
  let audit = ""
  while (!audit.includes('"outcome":"REJECTED"')) {
    audit = await readFile(path.join(directory, ".command-gate", "audit.jsonl"), "utf8")
    await delay(25, undefined, { signal: controller.signal })
  }
  assert.match(audit, /"outcome":"PUBLISHED_TO_HOST"/)
  assert.doesNotMatch(audit, /"type":"execution_result"/)
  console.log("PASS: real Kilo publishes the risk text to the permission UI input before permission.asked; Reject is audited; no execution_result.")
  controller.abort()
  await listening
} catch (error) {
  console.error(log.slice(-4000))
  console.error("Model requests:", requests)
  console.error("Recent events:", events.slice(-5))
  try { console.error(await readFile(path.join(directory, ".command-gate", "audit.jsonl"), "utf8")) }
  catch { console.error("No audit was written") }
  throw error
} finally {
  clearTimeout(timer)
  controller.abort()
  child?.kill("SIGTERM")
  model.closeAllConnections()
  model.close()
  await rm(directory, { recursive: true, force: true })
}
