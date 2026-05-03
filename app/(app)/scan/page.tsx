import { RealScanUploader } from "@/components/scan/RealScanUploader"

export default function ScanPage() {
  return (
    <>
      <div className="app-topbar">
        <div className="crumbs">
          <span>Badger</span>
          <span className="sep">/</span>
          <span>
            <b>New scan</b>
          </span>
        </div>
        <div className="actions" />
      </div>

      <div className="page-pad">
        <RealScanUploader />
      </div>
    </>
  )
}
