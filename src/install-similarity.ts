/** Comparison vocabulary, NOT an allowlist and NOT an endorsement of these packages. */
export const REFERENCE_NPM_NAMES: readonly string[] = Object.freeze([
  "react", "react-dom", "express", "lodash", "axios", "typescript", "eslint", "prettier",
  "next", "vite", "vitest", "webpack", "rollup", "esbuild", "zod", "jest", "mocha", "chai",
  "commander", "chalk", "debug", "dotenv", "left-pad", "moment", "dayjs", "date-fns",
  "yargs", "minimist", "semver", "uuid", "nanoid", "ws", "socket.io", "node-fetch",
  "ts-node", "tsx", "tailwindcss", "postcss", "autoprefixer", "nodemon", "cowsay",
  "@types/node", "@types/react", "@babel/core", "@vitejs/plugin-react", "@playwright/test",
])

export function levenshtein(left: string, right: string): number {
  let row = Array.from({ length: right.length + 1 }, (_, index) => index)
  for (let i = 0; i < left.length; i += 1) {
    const next = [i + 1]
    for (let j = 0; j < right.length; j += 1) {
      next.push(Math.min(next[j] + 1, row[j + 1] + 1, row[j] + (left[i] === right[j] ? 0 : 1)))
    }
    row = next
  }
  return row[right.length]
}

function skeleton(name: string): string {
  return name.replace(/[._-]/g, "").replace(/[01357]/g, (ch) => ({ "0": "o", "1": "l", "3": "e", "5": "s", "7": "t" })[ch]!)
}

function transposition(left: string, right: string): boolean {
  if (left.length !== right.length) return false
  const differences = [...left].flatMap((char, index) => char === right[index] ? [] : [index])
  return differences.length === 2 && differences[1] === differences[0] + 1 &&
    left[differences[0]] === right[differences[1]] && left[differences[1]] === right[differences[0]]
}

export function similarNpmName(name: string, references: readonly string[] = REFERENCE_NPM_NAMES):
  { name: string; distance: number } | undefined {
  if (references.includes(name)) return undefined
  const matches = references.filter((reference) => reference.length >= 4).map((reference) => {
    const distance = levenshtein(name, reference)
    const suspicious = distance === 1 || transposition(name, reference) || skeleton(name) === skeleton(reference)
    return { name: reference, distance, suspicious }
  }).filter((item) => item.suspicious)
  matches.sort((left, right) => left.distance - right.distance || left.name.localeCompare(right.name))
  return matches[0]
}
