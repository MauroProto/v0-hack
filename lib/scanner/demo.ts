import path from "node:path"
import { extractProjectFromDirectory } from "./extract"
import { scanProject } from "./scan"
import { getScanReport, saveScanReport } from "./store"
import type { ScanReport } from "./types"

export async function getOrCreateDemoReport(): Promise<ScanReport> {
  const existing = await getScanReport("demo")
  if (existing) return existing

  const rootDir = path.join(process.cwd(), "examples", "vulnerable-next-app")
  const extracted = await extractProjectFromDirectory(rootDir, "vulnerable-next-app")
  const report = scanProject({
    ...extracted,
    sourceType: "demo",
    sourceLabel: "Bundled vulnerable Next.js demo",
  })

  const demoReport = {
    ...report,
    id: "demo",
  }

  await saveScanReport(demoReport)
  return demoReport
}
