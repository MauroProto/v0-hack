"use client"

import { Show, SignInButton, SignUpButton, UserButton } from "@clerk/nextjs"

export function ClerkAuthControls() {
  const clerkEnabled = Boolean(process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY)

  if (!clerkEnabled) return null

  return (
    <div className="clerk-auth-controls" aria-label="Account">
      <Show when="signed-out">
        <SignInButton mode="modal">
          <button className="clerk-auth-link" type="button">
            Sign in
          </button>
        </SignInButton>
        <SignUpButton mode="modal">
          <button className="clerk-auth-link clerk-auth-link-primary" type="button">
            Sign up
          </button>
        </SignUpButton>
      </Show>
      <Show when="signed-in">
        <UserButton />
      </Show>
    </div>
  )
}
