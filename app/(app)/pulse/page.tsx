import Link from "next/link"
import { Icon } from "@/app/(app)/_components/icons"
import { LiveSecurityPulse } from "@/components/scan/LiveSecurityPulse"

export default function PulsePage() {
  return (
    <>
      <div className="app-topbar">
        <div className="crumbs">
          <span>VibeShield</span>
          <span className="sep">/</span>
          <span>
            <b>Live pulse</b>
          </span>
        </div>
        <div className="actions">
          <Link className="btn btn-accent" href="/scan">
            <Icon.bolt style={{ width: 14, height: 14 }} /> <span>Start new scan</span>
          </Link>
        </div>
      </div>

      <div className="page-pad pulse-page">
        <LiveSecurityPulse />
      </div>
    </>
  )
}
