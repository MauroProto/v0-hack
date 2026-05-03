import Link from "next/link"
import { LiveSecurityPulse } from "@/components/scan/LiveSecurityPulse"

export default function PulsePage() {
  return (
    <>
      <div className="app-topbar">
        <div className="crumbs">
          <span>Badger</span>
          <span className="sep">/</span>
          <span>
            <b>Live pulse</b>
          </span>
        </div>
        <div className="actions">
          <Link className="btn btn-accent btn-shine" href="/scan">
            <span>Start new scan</span>
          </Link>
        </div>
      </div>

      <div className="page-pad pulse-page">
        <LiveSecurityPulse />
      </div>
    </>
  )
}
