import { badgerEnv } from "@/lib/config/env"

const DEFAULT_CODELOAD_MAX_ARCHIVE_BYTES = 15_000_000
const DEFAULT_CODELOAD_MAX_TAR_BYTES = 50_000_000

export function getCodeloadLimits() {
  return {
    maxArchiveBytes: readPositiveInt(badgerEnv("GITHUB_CODELOAD_MAX_ARCHIVE_BYTES"), DEFAULT_CODELOAD_MAX_ARCHIVE_BYTES),
    maxTarBytes: readPositiveInt(badgerEnv("GITHUB_CODELOAD_MAX_TAR_BYTES"), DEFAULT_CODELOAD_MAX_TAR_BYTES),
  }
}

function readPositiveInt(value: string | undefined, fallback: number) {
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback
  return Math.floor(parsed)
}
