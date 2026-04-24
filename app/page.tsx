import { LandingHero } from "@/components/landing/landing-hero"
import { LandingTools } from "@/components/landing/landing-tools"
import { LandingFeatures } from "@/components/landing/landing-features"
import { LandingHowItWorks } from "@/components/landing/landing-how-it-works"
import { LandingReport } from "@/components/landing/landing-report"
import { LandingCta } from "@/components/landing/landing-cta"
import { LandingNav } from "@/components/landing/landing-nav"
import { LandingFooter } from "@/components/landing/landing-footer"

export default function LandingPage() {
  return (
    <main className="min-h-screen bg-background text-foreground antialiased">
      <LandingNav />
      <LandingHero />
      <LandingTools />
      <LandingReport />
      <LandingFeatures />
      <LandingHowItWorks />
      <LandingCta />
      <LandingFooter />
    </main>
  )
}
