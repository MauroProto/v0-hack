"use client"

import { useEffect, useState, type ReactNode } from "react"
import { SignInButton, SignUpButton, useUser } from "@clerk/nextjs"
import { useRouter } from "next/navigation"
import {
  ensureGuestSession,
  useGuestSession,
} from "@/lib/client/guest-session"

type AccessControlProps = {
  href?: string
  className?: string
  children: ReactNode
}

export function GuestAccessButton({ href = "/scan", className, children }: AccessControlProps) {
  const access = useGuestAccess(href)

  return (
    <>
      <button type="button" className={className} onClick={access.open}>
        {children}
      </button>
      <GuestAccessDialog {...access.dialogProps} />
    </>
  )
}

export function GuestAccessTextLink({ href = "/scan", className, children }: AccessControlProps) {
  const access = useGuestAccess(href)

  return (
    <>
      <button type="button" className={className ?? "footer-action-link"} onClick={access.open}>
        {children}
      </button>
      <GuestAccessDialog {...access.dialogProps} />
    </>
  )
}

export function GuestModeBadge() {
  const guest = useGuestSession()
  const access = useGuestAccess("/scan")
  const { isLoaded, isSignedIn } = useUser()

  if (!guest || !isLoaded || isSignedIn) return null

  return (
    <>
      <button type="button" className="guest-mode-badge" onClick={access.showDialog} title="Guest mode is active">
        <span
          className="guest-mode-dot"
          style={{ background: `linear-gradient(135deg, ${guest.colorA}, ${guest.colorB})` }}
        />
        <span>Guest mode</span>
      </button>
      <GuestAccessDialog {...access.dialogProps} />
    </>
  )
}

function useGuestAccess(href: string) {
  const router = useRouter()
  const { isLoaded, isSignedIn } = useUser()
  const [open, setOpen] = useState(false)
  const guest = useGuestSession()

  useEffect(() => {
    if (!open || !isLoaded || !isSignedIn) return
    router.push(href)
  }, [href, isLoaded, isSignedIn, open, router])

  function enter() {
    if (guest || isSignedIn) {
      router.push(href)
      return
    }

    setOpen(true)
  }

  function continueAsGuest() {
    ensureGuestSession()
    setOpen(false)
    router.push(href)
  }

  return {
    open: enter,
    showDialog: () => setOpen(true),
    dialogProps: {
      open,
      onClose: () => setOpen(false),
      onGuest: continueAsGuest,
    },
  }
}

function GuestAccessDialog({
  open,
  onClose,
  onGuest,
}: {
  open: boolean
  onClose: () => void
  onGuest: () => void
}) {
  if (!open) return null

  return (
    <div className="guest-gate-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="guest-gate"
        role="dialog"
        aria-modal="true"
        aria-labelledby="guest-gate-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button type="button" className="guest-gate-close" aria-label="Close" onClick={onClose}>
          ×
        </button>
        <div className="guest-gate-mark" aria-hidden="true">
          BG
        </div>
        <p className="guest-gate-eyebrow">Choose how to enter</p>
        <h2 id="guest-gate-title">Open Badger with an account or as a guest.</h2>
        <p className="guest-gate-copy">
          Guest mode scans public GitHub repos without connecting your GitHub account. Sign in only if you want a saved identity and cleaner history across devices.
        </p>

        <div className="guest-gate-options">
          <button type="button" className="guest-option guest-option-primary" onClick={onGuest}>
            <span className="guest-option-kicker">No GitHub needed</span>
            <b>Continue as guest</b>
            <em>Badger assigns a local guest profile for this browser.</em>
          </button>

          <div className="guest-option guest-option-account">
            <span className="guest-option-kicker">Saved workspace</span>
            <b>Sign in</b>
            <em>Use an account for persistent identity. GitHub authorization stays separate.</em>
            <div className="guest-auth-actions">
              <SignInButton mode="modal">
                <button type="button">Sign in</button>
              </SignInButton>
              <SignUpButton mode="modal">
                <button type="button">Create account</button>
              </SignUpButton>
            </div>
          </div>
        </div>

        <p className="guest-gate-note">
          Public scans read public repository files server-side. They do not fork repos or use your GitHub account unless you explicitly connect GitHub later.
        </p>
      </section>
    </div>
  )
}
