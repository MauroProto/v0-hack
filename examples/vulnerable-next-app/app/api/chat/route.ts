import { streamText } from "ai"

export async function POST(req: Request) {
  const body = await req.json()

  const result = streamText({
    model: "openai/gpt-5.2-mini",
    prompt: body.message,
    tools: {},
  })

  return result.toTextStreamResponse()
}
