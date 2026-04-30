import { prisma } from "@/lib/db"

export async function POST(request: Request) {
  const body = await request.json()
  const rows = await prisma.$queryRawUnsafe(`select * from users where email = '${body.email}'`)

  return Response.json({ rows })
}
