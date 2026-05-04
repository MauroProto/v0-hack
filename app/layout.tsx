import type { Metadata, Viewport } from "next"
import { ClerkProvider } from "@clerk/nextjs"
import { Geist, Geist_Mono, Instrument_Serif } from "next/font/google"
import { Analytics } from "@vercel/analytics/next"
import "./globals.css"

const geistSans = Geist({
  subsets: ["latin"],
  variable: "--font-geist-sans",
})

const geistMono = Geist_Mono({
  subsets: ["latin"],
  variable: "--font-geist-mono",
})

const instrumentSerif = Instrument_Serif({
  subsets: ["latin"],
  weight: "400",
  style: ["normal", "italic"],
  variable: "--font-instrument-serif",
})

const clerkPublishableKey = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY
const showVercelAnalytics = process.env.VERCEL === "1"

export const metadata: Metadata = {
  title: "Badger — Security review for AI-built apps",
  description:
    "Badger turns AI-built GitHub repositories into evidence-based AppSec reports, helping teams review secrets, auth gaps, AI endpoints, agent tools and supply-chain posture before shipping.",
  keywords: ["security", "scanner", "AI", "vulnerability", "vibe coding", "v0", "cursor", "bolt", "lovable"],
  icons: {
    icon: "/icon.svg",
    apple: "/apple-icon.png",
  },
  generator: "v0.app",
}

export const viewport: Viewport = {
  themeColor: "#09090B",
  width: "device-width",
  initialScale: 1,
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  const page = (
    <>
      {children}
      {showVercelAnalytics && <Analytics />}
    </>
  )

  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} ${instrumentSerif.variable}`}
    >
      <body>
        {clerkPublishableKey ? (
          <ClerkProvider publishableKey={clerkPublishableKey} telemetry={{ disabled: true }}>
            {page}
          </ClerkProvider>
        ) : (
          page
        )}
      </body>
    </html>
  )
}
