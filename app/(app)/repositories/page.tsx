import { RealScanUploader } from "@/components/scan/RealScanUploader"

export default function RepositoriesPage() {
  return (
    <>
      <div className="app-topbar">
        <div className="crumbs">
          <span>Badger</span>
          <span className="sep">/</span>
          <span>
            <b>GitHub repositories</b>
          </span>
        </div>
      </div>

      <div className="page-pad">
        <RealScanUploader initialMode="github" />
      </div>
    </>
  )
}
