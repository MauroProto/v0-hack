import "server-only"

import { createClient, type SupabaseClient } from "@supabase/supabase-js"
import { getSupabaseServiceKey, getSupabaseUrl, isSupabaseConfigured } from "./config"

type SupabaseGlobal = typeof globalThis & {
  __badgerSupabaseService?: SupabaseClient
}

const supabaseGlobal = globalThis as SupabaseGlobal

export { isSupabaseConfigured }

export function getSupabaseServiceClient() {
  const url = getSupabaseUrl()
  const serviceKey = getSupabaseServiceKey()

  if (!url || !serviceKey) return null

  if (!supabaseGlobal.__badgerSupabaseService) {
    supabaseGlobal.__badgerSupabaseService = createClient(url, serviceKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
      global: {
        headers: {
          "X-Client-Info": "badger",
        },
      },
    })
  }

  return supabaseGlobal.__badgerSupabaseService
}
