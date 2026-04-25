"use client"

const mockCustomers = [
  {
    customerEmail: "buyer@example.com",
    creditCard: "4242 4242 4242 4242",
    token: "demo-session-token",
    password: "not-a-real-password",
  },
]

export default function DashboardPage() {
  return (
    <main>
      <h1>Dashboard</h1>
      <pre>{JSON.stringify(mockCustomers, null, 2)}</pre>
    </main>
  )
}
