"use server"

import { prisma } from "@/lib/db"

export async function deleteUser(formData: FormData) {
  const userId = String(formData.get("userId"))
  await prisma.user.delete({ where: { id: userId } })
}
