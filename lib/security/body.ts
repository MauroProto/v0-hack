import "server-only"

import { assertContentLengthAllowed, SecurityError } from "@/lib/security/quota"

export async function readJsonBodyWithLimit(request: Request, maxBytes: number): Promise<unknown> {
  assertContentLengthAllowed(request, maxBytes)

  const text = await readTextBodyWithLimit(request, maxBytes)
  if (!text.trim()) {
    throw new SecurityError("Request body is required.", 400, "empty_request_body")
  }

  try {
    return JSON.parse(text) as unknown
  } catch {
    throw new SecurityError("Invalid JSON body.", 400, "invalid_json_body")
  }
}

async function readTextBodyWithLimit(request: Request, maxBytes: number) {
  if (!request.body) return ""

  const reader = request.body.getReader()
  const decoder = new TextDecoder()
  let total = 0
  let text = ""

  while (true) {
    const { value, done } = await reader.read()
    if (done) break
    if (!value) continue

    total += value.byteLength
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined)
      throw new SecurityError(`Request is too large. Maximum is ${maxBytes} bytes.`, 413, "request_too_large")
    }

    text += decoder.decode(value, { stream: true })
  }

  text += decoder.decode()
  return text
}
