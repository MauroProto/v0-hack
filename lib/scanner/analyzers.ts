import { scanDependencies, type DependencyScanResult } from "./dependencies"
import { buildRepoInventory } from "./inventory"
import { scanInterfileTaint } from "./interfileTaint"
import { collectRuleFindings, type RuleScanResult } from "./rules"
import type { ProjectFile, RepoInventory, ScanFinding } from "./types"

export type AnalyzerId =
  | "repo_inventory"
  | "deterministic_rules"
  | "dependency_osv"
  | "ast_rules"
  | "taint"
  | "nextjs"
  | "ai_endpoint"
  | "supabase"
  | "github_actions"
  | "hardening"

export interface Analyzer<TOutput = unknown> {
  id: AnalyzerId
  name: string
  run(files: ProjectFile[], context: AnalyzerContext): Promise<TOutput> | TOutput
}

export interface AnalyzerContext {
  framework?: string
}

export interface HybridAnalyzerResult {
  findings: Array<Omit<ScanFinding, "id">>
  ruleResult: RuleScanResult
  dependencyResult: DependencyScanResult
  interfileFindings: Array<Omit<ScanFinding, "id">>
  repoInventory: RepoInventory
}

export const analyzerRegistry: Analyzer[] = [
  { id: "deterministic_rules", name: "Deterministic security rules", run: collectRuleFindings },
  { id: "taint", name: "Inter-file taint analysis", run: scanInterfileTaint },
  { id: "dependency_osv", name: "OSV dependency intelligence", run: scanDependencies },
  { id: "repo_inventory", name: "Repository inventory", run: (files, context) => buildRepoInventory(files, context.framework) },
]

export async function runHybridAnalyzers(files: ProjectFile[]): Promise<HybridAnalyzerResult> {
  const ruleResult = collectRuleFindings(files)
  const interfileFindings = scanInterfileTaint(files)
  const dependencyResult = await scanDependencies(files)
  const repoInventory = buildRepoInventory(files, ruleResult.signals.framework)

  return {
    findings: [...ruleResult.findings, ...interfileFindings, ...dependencyResult.findings],
    ruleResult,
    dependencyResult,
    interfileFindings,
    repoInventory,
  }
}
