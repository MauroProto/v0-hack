import { RealScanUploader } from "@/components/scan/RealScanUploader"
import { Icon } from "../_components/icons"
import Link from "next/link"

export default function ScanPage() {
  return (
    <>
      <div className="app-topbar">
        <div className="crumbs">
          <span>VibeShield</span>
          <span className="sep">/</span>
          <span>
            <b>New scan</b>
          </span>
        </div>
        <div className="actions">
          <Link className="btn btn-outline" href="/report/demo">
            <Icon.scan style={{ width: 14, height: 14 }} /> <span>Demo report</span>
          </Link>
        </div>
      </div>

      <div className="page-pad">
        <RealScanUploader />
      </div>
    </>
  )
}
