const LEGACY_ENV_PREFIX = ["VIBE", "SHIELD"].join("")

export function badgerEnv(name: string) {
  const normalized = name.replace(/^BADGER_/, "")
  return process.env[`BADGER_${normalized}`]?.trim() || process.env[`${LEGACY_ENV_PREFIX}_${normalized}`]?.trim()
}

export function badgerEnvOr(name: string, fallback: string | undefined) {
  return badgerEnv(name) || fallback
}
