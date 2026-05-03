import { createClient, type SupabaseClient } from "@supabase/supabase-js"
import { BADGER_SUPABASE_EXPECTED_TABLES, BADGER_SUPABASE_QUOTA_RPC, BADGER_SUPABASE_TABLES } from "../lib/supabase/schema"
import { loadEnvFiles } from "./lib/env"

async function main() {
  const production = process.argv.includes("--production")
  await loadEnvFiles(production ? "production" : "development")

  const url = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY

  console.log("Badger Supabase verification")

  if (!url || !serviceKey) {
    console.log("[fail] supabase_credentials: server-side Supabase URL or service credential is missing")
    process.exitCode = 1
    return
  }

  const supabase = createClient(url, serviceKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
    global: {
      headers: {
        "X-Client-Info": "badger-supabase-verify",
      },
    },
  })

  let failed = 0
  for (const table of BADGER_SUPABASE_EXPECTED_TABLES) {
    const { error } = await supabase.from(table).select("*", { count: "exact", head: true })
    if (error) {
      failed += 1
      console.log(`[fail] ${table}: ${sanitizeSupabaseError(error.message)}`)
    } else {
      console.log(`[ok] ${table}: reachable with server-side credentials`)
    }
  }

  if (failed > 0) {
    process.exitCode = 1
    return
  }

  failed += await verifyQuotaRpc(supabase)

  if (production && !anonKey) {
    console.log("[fail] supabase_anon_key: NEXT_PUBLIC_SUPABASE_ANON_KEY is missing")
    process.exitCode = 1
    return
  }

  if (anonKey) {
    failed += await verifyClientRolesDenied(url, anonKey)
  }

  if (failed > 0) {
    process.exitCode = 1
    return
  }

  console.log("[ok] supabase_connection: all Badger tables are reachable")
  if (anonKey) console.log("[ok] supabase_client_access: anon client cannot read Badger tables directly")
  console.log("No secret values were printed.")
}

type RpcResult = {
  error: { message: string } | null
}

async function verifyQuotaRpc(supabase: SupabaseClient) {
  const testSubjectHash = "0".repeat(64)
  const windowStart = new Date().toISOString().slice(0, 7) + "-01"
  const callRpc = supabase.rpc.bind(supabase) as unknown as (fn: string, args: Record<string, unknown>) => Promise<RpcResult>

  const { error } = await callRpc(BADGER_SUPABASE_QUOTA_RPC, {
    p_subject_hash: testSubjectHash,
    p_window_start: windowStart,
    p_limit: 10,
    p_cost: 2,
  })

  await supabase
    .from(BADGER_SUPABASE_TABLES.usage)
    .delete()
    .eq("subject_hash", testSubjectHash)
    .eq("window_start", windowStart)

  if (error) {
    console.log(`[fail] ${BADGER_SUPABASE_QUOTA_RPC}: ${sanitizeSupabaseError(error.message)}`)
    console.log("[hint] run the latest scan credit quota migration so Max scans can consume 2 credits atomically")
    return 1
  }

  console.log(`[ok] ${BADGER_SUPABASE_QUOTA_RPC}: cost-aware quota RPC is callable with service-role credentials`)
  return 0
}

async function verifyClientRolesDenied(url: string, anonKey: string) {
  const anon = createClient(url, anonKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
    global: {
      headers: {
        "X-Client-Info": "badger-supabase-verify-anon",
      },
    },
  })

  let failed = 0
  for (const table of BADGER_SUPABASE_EXPECTED_TABLES) {
    const { error } = await anon.from(table).select("*", { count: "exact", head: true })
    if (error) {
      console.log(`[ok] ${table}: denied to anon client`)
    } else {
      failed += 1
      console.log(`[fail] ${table}: readable by anon client`)
    }
  }

  return failed
}

function sanitizeSupabaseError(message: string) {
  return message
    .replace(/https:\/\/[^\s)]+/g, "https://...redacted")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "...redacted-jwt")
    .slice(0, 240)
}

main().catch((error) => {
  console.error(error instanceof Error ? sanitizeSupabaseError(error.message) : "Supabase verification failed")
  process.exitCode = 1
})
