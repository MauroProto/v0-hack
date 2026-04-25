import "server-only"

import { createClient, type SupabaseClient } from "@supabase/supabase-js"

type SupabaseGlobal = typeof globalThis & {
  __vibeshieldSupabaseService?: SupabaseClient
}

const supabaseGlobal = globalThis as SupabaseGlobal

export function isSupabaseConfigured() {
  return Boolean(getSupabaseUrl() && getSupabaseServiceKey())
}

export function getSupabaseServiceClient() {
  const url = getSupabaseUrl()
  const serviceKey = getSupabaseServiceKey()

  if (!url || !serviceKey) return null

  if (!supabaseGlobal.__vibeshieldSupabaseService) {
    supabaseGlobal.__vibeshieldSupabaseService = createClient(url, serviceKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
      global: {
        headers: {
          "X-Client-Info": "vibeshield-mvp",
        },
      },
    })
  }

  return supabaseGlobal.__vibeshieldSupabaseService
}

function getSupabaseUrl() {
  return process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL
}

function getSupabaseServiceKey() {
  return process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY
}
