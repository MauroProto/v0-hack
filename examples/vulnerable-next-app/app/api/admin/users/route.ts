import { NextResponse } from "next/server"

const users = [
  { id: "usr_1", email: "founder@example.com", role: "owner" },
  { id: "usr_2", email: "buyer@example.com", role: "customer" },
]

export async function GET() {
  return NextResponse.json({ users })
}
