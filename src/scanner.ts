import type { Redirection, ScanResult, SimpleCommand } from "./types.ts"

type Token =
  | { type: "word"; value: string; start: number; end: number }
  | { type: "connector" | "redir"; value: string; start: number; end: number }

const CONNECTORS = ["&&", "||", "|&", ";", "|", "&"] as const
const REDIRECTIONS = [">>", "<<", "<>", ">&", "<&", ">", "<"] as const

function startsWithAny(input: string, offset: number, values: readonly string[]) {
  return values.find((value) => input.startsWith(value, offset))
}

/**
 * Conservative shell scanner for the standalone prototype.
 *
 * Kilo integration must feed the policy from Kilo's tree-sitter shell AST.
 * Anything this scanner cannot represent is marked unsupported and therefore
 * never reaches ALLOW in headless mode.
 */
export function scanShell(input: string): ScanResult {
  const tokens: Token[] = []
  const errors: string[] = []
  let word = ""
  let wordStart = -1
  let state: "normal" | "single" | "double" = "normal"
  let hasDynamicExpansion = false
  let hasBackgroundExecution = false
  let hasUnsupportedSyntax = false

  const beginWord = (at: number) => {
    if (wordStart === -1) wordStart = at
  }

  const flushWord = (end: number) => {
    if (wordStart === -1) return
    tokens.push({ type: "word", value: word, start: wordStart, end })
    word = ""
    wordStart = -1
  }

  for (let index = 0; index < input.length; index += 1) {
    const char = input[index]
    const next = input[index + 1]

    if (state === "single") {
      if (char === "'") state = "normal"
      else word += char
      continue
    }

    if (state === "double") {
      if (char === '"') {
        state = "normal"
        continue
      }
      if (char === "\\" && next !== undefined) {
        word += next
        index += 1
        continue
      }
      if (char === "`" || (char === "$" && next === "(")) {
        hasDynamicExpansion = true
      } else if (char === "$" && next !== undefined) {
        hasDynamicExpansion = true
      }
      word += char
      continue
    }

    if (char === "\\" && next !== undefined) {
      beginWord(index)
      word += next
      index += 1
      continue
    }
    if (char === "'") {
      beginWord(index)
      state = "single"
      continue
    }
    if (char === '"') {
      beginWord(index)
      state = "double"
      continue
    }
    if (char === "`" || (char === "$" && next === "(")) {
      beginWord(index)
      hasDynamicExpansion = true
      word += char
      continue
    }
    if (char === "$" && next !== undefined) {
      beginWord(index)
      hasDynamicExpansion = true
      word += char
      continue
    }
    if ((char === "(" || char === ")" || char === "{" || char === "}") && wordStart === -1) {
      hasUnsupportedSyntax = true
      beginWord(index)
      word += char
      continue
    }
    if (char === "#" && wordStart === -1) {
      while (index + 1 < input.length && input[index + 1] !== "\n") index += 1
      continue
    }
    if (/\s/.test(char)) {
      flushWord(index)
      if (char === "\n") {
        tokens.push({ type: "connector", value: ";", start: index, end: index + 1 })
      }
      continue
    }

    const connector = startsWithAny(input, index, CONNECTORS)
    if (connector) {
      flushWord(index)
      tokens.push({ type: "connector", value: connector, start: index, end: index + connector.length })
      if (connector === "&") hasBackgroundExecution = true
      index += connector.length - 1
      continue
    }

    const redirection = startsWithAny(input, index, REDIRECTIONS)
    if (redirection) {
      let operator = redirection
      if (/^\d+$/.test(word)) {
        operator = `${word}${operator}`
        word = ""
        wordStart = -1
      } else {
        flushWord(index)
      }
      tokens.push({ type: "redir", value: operator, start: index, end: index + redirection.length })
      if (redirection === "<<") hasUnsupportedSyntax = true
      index += redirection.length - 1
      continue
    }

    beginWord(index)
    word += char
  }

  flushWord(input.length)
  if (state !== "normal") errors.push(`unclosed ${state} quote`)

  const commands: SimpleCommand[] = []
  const connectors: string[] = []
  let argv: string[] = []
  let redirections: Redirection[] = []
  let commandStart = 0

  const flushCommand = (end: number) => {
    if (argv.length === 0 && redirections.length === 0) return
    commands.push({
      raw: input.slice(commandStart, end).trim(),
      argv,
      redirections,
    })
    argv = []
    redirections = []
  }

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]
    if (token.type === "connector") {
      flushCommand(token.start)
      connectors.push(token.value)
      commandStart = token.end
      continue
    }
    if (token.type === "redir") {
      const target = tokens[index + 1]
      if (!target || target.type !== "word") {
        errors.push(`redirection ${token.value} has no static target`)
        redirections.push({ operator: token.value })
        continue
      }
      redirections.push({ operator: token.value, target: target.value })
      index += 1
      continue
    }
    argv.push(token.value)
  }
  flushCommand(input.length)

  if (commands.length === 0 && input.trim() !== "") errors.push("no executable command found")

  return {
    commands,
    connectors,
    hasDynamicExpansion,
    hasBackgroundExecution,
    hasUnsupportedSyntax,
    errors,
  }
}
