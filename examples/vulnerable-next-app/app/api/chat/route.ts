import { streamText } from "ai"
import { tools } from "@/lib/agent/tools"

export async function POST(request: Request) {
  const body = await request.json()

  return streamText({
    model: "openai/gpt-5.2-mini",
    prompt: body.message,
    tools,
  }).toTextStreamResponse()
}
