import { spawnSync } from "node:child_process"

type Step = {
  id: string
  command: string[]
  required: boolean
}

const STEPS: Step[] = [
  { id: "scanner_smoke", command: ["pnpm", "run", "scanner:smoke"], required: true },
  { id: "typecheck", command: ["pnpm", "exec", "tsc", "--noEmit", "--incremental", "false"], required: true },
  { id: "lint", command: ["pnpm", "run", "lint"], required: true },
  { id: "build", command: ["pnpm", "run", "build"], required: true },
  { id: "diff_check", command: ["git", "diff", "--check"], required: true },
  { id: "production_readiness", command: ["pnpm", "run", "prod:check"], required: true },
  { id: "supabase_live", command: ["pnpm", "run", "supabase:verify"], required: true },
  { id: "vercel_live", command: ["pnpm", "run", "vercel:verify"], required: true },
]

function main() {
  const results: Array<{ id: string; status: "ok" | "fail"; code: number | null }> = []

  console.log("Badger release verification")
  console.log("No secret values are intentionally printed by these checks.")

  for (const step of STEPS) {
    console.log("")
    console.log(`== ${step.id} ==`)

    const [command, ...args] = step.command
    const result = spawnSync(command, args, {
      cwd: process.cwd(),
      env: process.env,
      stdio: "inherit",
      shell: false,
    })

    const code = result.status
    results.push({ id: step.id, status: code === 0 ? "ok" : "fail", code })
  }

  const failures = results.filter((result) => result.status === "fail")

  console.log("")
  console.log("Release verification summary")
  for (const result of results) {
    console.log(`[${result.status}] ${result.id}${result.code === null ? "" : ` exit=${result.code}`}`)
  }

  if (failures.length > 0) {
    process.exitCode = 1
  }
}

main()
