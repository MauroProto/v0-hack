import { NextResponse } from "next/server"
import { getSystemHealth } from "@/lib/system/health"
import { apiHeaders } from "@/lib/security/headers"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

export async function GET() {
  return NextResponse.json(getSystemHealth(), { headers: apiHeaders() })
}
