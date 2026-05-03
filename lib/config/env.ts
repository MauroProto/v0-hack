export function badgerEnv(name: string) {
  const normalized = name.replace(/^(BADGER_|VIBESHIELD_)/, "")
  return process.env[`BADGER_${normalized}`]?.trim() || process.env[`VIBESHIELD_${normalized}`]?.trim()
}

export function badgerEnvOr(name: string, fallback: string | undefined) {
  return badgerEnv(name) || fallback
}
