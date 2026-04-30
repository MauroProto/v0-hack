"use client"

const mockCustomer = {
  customerEmail: "ceo@customer.example",
  token: "live_customer_token_12345",
}

export default function DashboardPage() {
  return <pre>{JSON.stringify(mockCustomer, null, 2)}</pre>
}
