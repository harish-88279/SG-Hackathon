import React, { useState } from 'react'
import { UploadCloud } from 'lucide-react'
import { api } from '../api.js'
import { sev, cx, Note, RISK_LABEL } from '../lib.jsx'
import { Panel, Meta, Figure, Skeleton, Err, Table, TH, TD, TR } from '../components/ui.jsx'

export default function UploadView() {
  const [over, setOver] = useState(false)
  const [busy, setBusy] = useState(false)
  const [r, setR] = useState(null)
  const [err, setErr] = useState(null)

  const send = async (file) => {
    if (!file) return
    setBusy(true); setErr(null); setR(null)
    try { setR(await api.upload(file)) } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }

  return (
    <Panel
      title="Ingest an SBOM"
      sub="Reads real CycloneDX and SPDX — the formats syft, cdxgen and Trivy actually produce."
    >
      <Note>
        An SBOM is your software's ingredients list. Most tools built for this challenge will only read the one
        sample file provided. <strong className="font-semibold text-ink">This reads the industry standards</strong> —
        point it at a genuine production app this afternoon and it works. And it reads the dependency{' '}
        <em className="not-italic text-ink">tree</em> inside the file, not just the flat list, which is the only way
        to catch something buried three levels down.
      </Note>

      <label
        onDragOver={(e) => { e.preventDefault(); setOver(true) }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => { e.preventDefault(); setOver(false); send(e.dataTransfer.files[0]) }}
        className={cx(
          'mt-6 block cursor-pointer rounded-xl border-2 border-dashed px-6 py-14 text-center transition-all duration-200',
          over
            ? 'scale-[1.01] border-sg/70 bg-sg/[0.05] shadow-[0_0_70px_-22px_rgba(255,122,61,.5)]'
            : 'border-edge hover:border-dim hover:bg-ink/[0.02]'
        )}
      >
        <input type="file" accept=".json,.csv,.xml" className="hidden" onChange={(e) => send(e.target.files[0])} />
        <div className={cx(
          'mx-auto mb-5 grid h-14 w-14 place-items-center rounded-full border transition-all duration-200',
          over ? 'border-sg/50 bg-sg/[0.09] shadow-glow' : 'border-line bg-ink/[0.04]'
        )}>
          <UploadCloud size={22} strokeWidth={1.5} className={over ? 'text-sg' : 'text-dim'} />
        </div>
        <p className="text-base text-muted">Drop an SBOM here, or click to choose</p>
        <p className="mt-1.5 text-sm text-faint">CycloneDX JSON · SPDX JSON · CSV</p>
        <p className="mt-4 font-mono text-xs text-faint">examples/real-cyclonedx-sample.json</p>
      </label>

      {busy && <div className="mt-6"><Skeleton rows={5} /></div>}
      {err && <div className="mt-6"><Err error={err} /></div>}

      {r && (
        <div className="mt-7">
          <div className="flex flex-wrap gap-x-10 gap-y-5 border-y border-line py-5">
            <Figure size="sm" tone="ok"   value={r.format_detected} label="format detected" />
            <Figure size="sm"             value={r.components_parsed} label="components" />
            <Figure size="sm" tone="info" value={r.transitive} label="hidden" />
            <Figure size="sm"             value={r.max_depth} label="max depth" />
            <Figure size="sm" tone="crit" value={r.stats.at_risk} label="at risk" />
            <Figure size="sm" tone="high" value={r.stats.unique_cves} label="cves" />
          </div>

          <p className="py-5 text-sm leading-relaxed text-muted">{r.note}</p>

          <Table>
            <thead>
              <tr>
                <TH className="w-[84px]">priority</TH>
                <TH>component</TH>
                <TH>problem</TH>
                <TH>cve</TH>
              </tr>
            </thead>
            <tbody>
              {r.top_findings.slice(0, 12).map((f) => (
                <TR key={f.dependency_id}>
                  <TD className={cx('tnum text-md font-semibold', sev(f.risk_band).fg)}>{f.priority_score}</TD>
                  <TD>
                    <span className="flex items-center gap-2">
                      <span className="font-mono text-sm text-ink">{f.library.split(':').pop()}</span>
                      <span className="font-mono text-xs text-faint">{f.version}</span>
                      {f.dependency_type === 'transitive' && <Meta tone="info">hidden</Meta>}
                    </span>
               