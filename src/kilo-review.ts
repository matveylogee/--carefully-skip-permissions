import { setTimeout as delay } from "node:timers/promises"

export interface KiloReviewInput {
  sessionID: string
  callID: string
  command: string
  description: string
}

export interface KiloReviewReceipt {
  messageID: string
  partID: string
}

export type KiloReviewPublisher = (input: KiloReviewInput) => Promise<KiloReviewReceipt>

function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : {}
}

function data(response: unknown): unknown {
  const result = object(response)
  if (result.error !== undefined) throw new Error("Kilo rejected the review update")
  if (object(result.response).ok === false) throw new Error("Kilo review request failed")
  if (result.data === undefined) throw new Error("Kilo returned no review data")
  return result.data
}

function matches(part: Record<string, unknown>, input: KiloReviewInput): boolean {
  return part.type === "tool" && part.tool === "bash" && part.sessionID === input.sessionID
    && part.callID === input.callID && object(object(part.state).input).command === input.command
}

/**
 * Kilo 7.5.9's permission dock reads the stored tool part's state.input,
 * not the mutable executor args. Publish before tool.execute.before returns:
 * changing permission.asked metadata would be too late and lose to that input.
 *
 * The injected legacy SDK has no generated part.update method. Its underlying
 * HTTP client carries Kilo's in-process fetch, directory and auth configuration;
 * reuse it for the existing part PATCH route (never open a separate localhost
 * connection or write Kilo's database). This adapter is version-specific.
 */
export function createKiloReviewPublisher(client: unknown): KiloReviewPublisher {
  const transport = object(object(client)._client)
  const get = transport.get
  const patch = transport.patch

  return async (input) => {
    if (typeof get !== "function" || typeof patch !== "function") {
      throw new Error("Kilo review transport unavailable; this adapter requires Kilo CLI 7.5.9")
    }
    const signal = AbortSignal.timeout(5_000)
    const session = encodeURIComponent(input.sessionID)
    // Registration may still be pending when the AI SDK enters the pre-hook.
    // Wait only for this exact call to become running; never edit another call.
    let selected: Record<string, unknown> | undefined
    for (let attempt = 0; attempt < 20; attempt++) {
      signal.throwIfAborted()
      const messages = data(await get.call(transport, {
        url: `/session/${session}/message`, query: { limit: 8 }, signal,
      }))
      if (!Array.isArray(messages)) throw new Error("Invalid Kilo messages response")
      const parts = messages.flatMap((message) => {
        const value = object(message).parts
        return Array.isArray(value) ? value.map(object) : []
      }).filter((part) => matches(part, input) && object(part.state).status === "running")
      if (parts.length > 1) throw new Error("Ambiguous Kilo tool call; review was not published")
      if (parts.length === 1) { selected = parts[0]; break }
      await delay(25, undefined, { signal })
    }
    if (!selected || typeof selected.messageID !== "string" || typeof selected.id !== "string") {
      throw new Error("Exact running Kilo tool call was not found; review was not published")
    }

    const receipt = { messageID: selected.messageID, partID: selected.id }
    const url = `/session/${session}/message/${encodeURIComponent(receipt.messageID)}`
    async function readPart(): Promise<Record<string, unknown>> {
      const message = object(data(await get.call(transport, { url, signal })))
      const parts = Array.isArray(message.parts) ? message.parts.map(object) : []
      const part = parts.find((part) => part.id === receipt.partID)
      if (!part || !matches(part, input) || part.messageID !== receipt.messageID || object(part.state).status !== "running") {
        throw new Error("Kilo tool call changed during review; no permission was granted")
      }
      return part
    }

    const part = await readPart()
    const state = object(part.state)
    const updated = { ...part, state: { ...state, input: { ...object(state.input), description: input.description } } }
    data(await patch.call(transport, {
      url: `${url}/part/${encodeURIComponent(receipt.partID)}`,
      headers: { "Content-Type": "application/json" },
      body: updated, signal,
    }))
    const saved = await readPart()
    if (object(object(saved.state).input).description !== input.description) {
      throw new Error("Kilo did not retain the review text; no permission was granted")
    }
    return receipt
  }
}
