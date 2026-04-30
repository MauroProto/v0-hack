import "server-only"

import { createClient, type SupabaseClient } from "@supabase/supabase-js"
import { getSupabaseServiceKey, getSupabaseUrl, isSupabaseConfigured } from "./config"

type SupabaseGlobal = typeof globalThis & {
  __vibeshieldSupabaseService?: SupabaseClient
}

const supabaseGlobal = globalThis as SupabaseGlobal

export { isSupabaseConfigured }

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
