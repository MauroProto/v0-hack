"use client"

import { useEffect, useState, type ReactNode } from "react"
import { useUser } from "@clerk/nextjs"
import { ArrowRight, Github, X } from "lucide-react"
import Image from "next/image"
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

  function signInWithGitHub() {
    const params = new URLSearchParams({ returnTo: href })
    window.location.assign(`/api/auth/github/start?${params.toString()}`)
  }

  return {
    open: enter,
    showDialog: () => setOpen(true),
    dialogProps: {
      open,
      onClose: () => setOpen(false),
      onGuest: continueAsGuest,
      onSignIn: signInWithGitHub,
    },
  }
}

function GuestAccessDialog({
  open,
  onClose,
  onGuest,
  onSignIn,
}: {
  open: boolean
  onClose: () => void
  onGuest: () => void
  onSignIn: () => void
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
          <X aria-hidden="true" />
        </button>
        <Image className="guest-gate-mark" src="/badger-mark.webp" alt="" width={72} height={72} aria-hidden="true" />
        <h2 id="guest-gate-title">Welcome to Badger</h2>
        <p className="guest-gate-copy">Scan public GitHub repos in seconds. No account needed to start.</p>

        <button type="button" className="guest-gate-primary" onClick={onGuest}>
          <span>Continue as guest</span>
          <ArrowRight aria-hidden="true" />
        </button>

        <div className="guest-gate-separator" aria-hidden="true">
          <span />
          <b>OR</b>
          <span />
        </div>

        <button type="button" className="guest-gate-secondary" onClick={onSignIn}>
          <Github aria-hidden="true" />
          <span>Sign in with GitHub</span>
        </button>
        <p className="guest-gate-powered">
          <span>by</span>
          <a href="https://clerk.com/" target="_blank" rel="noreferrer">
            Clerk
          </a>
        </p>

        <div className="guest-gate-rule" aria-hidden="true" />
        <p className="guest-gate-note">Public scans read repos server-side. Nothing is stored without an account.</p>
      </section>
    </div>
  )
}
