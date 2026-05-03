export type ScanCreditMode = "rules" | "normal" | "max"

export function scanCreditCostForMode(mode: ScanCreditMode | undefined) {
  return mode === "max" ? 2 : 1
}
