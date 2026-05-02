import { readFile } from "node:fs/promises"
import path from "node:path"

export async function loadEnvFiles(mode: "development" | "production" = "development") {
  const files =
    mode === "production"
      ? [".env", ".env.production", ".env.production.local", ".vercel/.env.production.local"]
      : [".env", ".env.development", ".env.local", ".env.development.local", ".vercel/.env.development.local"]

  for (const file of files) {
    const contents = await readText(file)
    if (!contents) continue

    for (const line of contents.split(/\r?\n/)) {
      const trimmed = line.trim()
      if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) continue

      const index = trimmed.indexOf("=")
      const key = trimmed.slice(0, index).trim()
      const value = unquoteEnvValue(trimmed.slice(index + 1).trim())

      if (!key || key in process.env) continue
      process.env[key] = value
    }
  }
}

async function readText(relativePath: string) {
  try {
    return await readFile(path.join(process.cwd(), relativePath), "utf8")
  } catch {
    return ""
  }
}

function unquoteEnvValue(value: string) {
  const quoted =
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))

  return quoted ? value.slice(1, -1) : value
}
