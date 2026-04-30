import { NextResponse } from "next/server"

export async function GET() {
  const users = [{ id: "u_1", email: "admin@example.com", role: "admin" }]
  return NextResponse.json({ users })
}
