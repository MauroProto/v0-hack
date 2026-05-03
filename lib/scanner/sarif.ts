import { redactSecrets } from "./rules"
import type { ScanFinding, ScanReport, Severity } from "./types"

type SarifLevel = "error" | "warning" | "note"

export function generateSarif(report: ScanReport) {
  const findings = report.findings.filter((finding) => !finding.suppressed && (finding.kind === "vulnerability" || !finding.kind))
  const rules = [...new Map(findings.map((finding) => [finding.ruleId ?? finding.category, finding])).values()]

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "Badger",
            informationUri: "https://github.com/MauroProto/badger",
            semanticVersion: report.scannerVersion ?? "badger-hybrid-0.3",
            rules: rules.map(toRule),
          },
        },
        results: findings.map(toResult),
        properties: {
          scanId: report.id,
          projectName: report.projectName,
          source: report.sourceLabel,
          riskScore: report.riskScore,
        },
      },
    ],
  }
}

function toRule(finding: ScanFinding) {
  const id = finding.ruleId ?? finding.category
  return {
    id,
    name: finding.title,
    shortDescription: {
      text: finding.title,
    },
    fullDescription: {
      text: finding.description,
    },
    help: {
      text: finding.recommendation,
    },
    properties: {
      category: finding.category,
      kind: finding.kind ?? "vulnerability",
      severity: finding.severity,
      confidence: finding.confidence,
      cwe: finding.cwe,
      owasp: finding.owasp,
      asvs: finding.asvs,
    },
  }
}

function toResult(finding: ScanFinding) {
  return {
    ruleId: finding.ruleId ?? finding.category,
    level: levelForSeverity(finding.severity),
    message: {
      text: redactSecrets(`${finding.title}: ${finding.description}`),
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: finding.filePath,
          },
          region: {
            startLine: finding.lineStart ?? 1,
            endLine: finding.lineEnd ?? finding.lineStart ?? 1,
          },
        },
      },
    ],
    partialFingerprints: {
      primaryLocationLineHash: finding.fingerprint ?? `${finding.filePath}:${finding.lineStart ?? 1}:${finding.title}`,
    },
    properties: {
      category: finding.category,
      kind: finding.kind ?? "vulnerability",
      confidence: finding.confidence,
      confidenceReason: finding.confidenceReason,
      reachability: finding.reachability,
      exploitability: finding.exploitability,
      evidence: redactSecrets(finding.evidence ?? ""),
      triage: finding.triage
        ? {
            ...finding.triage,
            reason: redactSecrets(finding.triage.reason),
            attackScenario: finding.triage.attackScenario ? redactSecrets(finding.triage.attackScenario) : undefined,
          }
        : undefined,
      evidenceTrace: finding.evidenceTrace?.map((step) => ({
        ...step,
        code: step.code ? redactSecrets(step.code) : undefined,
      })),
    },
  }
}

function levelForSeverity(severity: Severity): SarifLevel {
  if (severity === "critical" || severity === "high") return "error"
  if (severity === "medium" || severity === "low") return "warning"
  return "note"
}
