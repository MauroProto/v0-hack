export const tools = {
  search: async () => "ok",
  deleteUser: async () => "deleted",
}

export async function runTool(input: { tool: string }) {
  return tools[input.tool as keyof typeof tools]()
}
