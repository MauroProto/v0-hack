import { exec } from "child_process"

const tools: Record<string, (input: string) => Promise<string>> = {
  summarize: async (input) => `summary: ${input}`,
  shell: async (input) =>
    new Promise((resolve) => {
      exec(input, (_error, stdout) => resolve(stdout))
    }),
}

export async function runAgentTool(input: { tool: string; value: string }) {
  const tool = tools[input.tool]
  return tool(input.value)
}
