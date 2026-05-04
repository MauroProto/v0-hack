import type { ScanMode } from "@/lib/scanner/types"
import type { RequestIdentity } from "./request"
import { SecurityError } from "./errors"

export function assertScanModeAllowed(identity: RequestIdentity, mode: ScanMode) {
  if (mode !== "max" || identity.kind !== "anonymous") return

  throw new SecurityError(
    "Sign in to run Max review. Normal public scans are available without an account.",
    401,
    "max_login_required",
  )
}
