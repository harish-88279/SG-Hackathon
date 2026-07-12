import React, { useEffect, useState } from 'react'
import { X, Download } from 'lucide-react'
import { api } from '../api.js'
import { sev, cx, Note, RISK_LABEL } from '../lib.jsx'
import { Panel, Sev, Meta, Field, Skeleton, Blank, Table, TH, TD, TR, Term } from '../components/ui.jsx'
import { Dial } from '../components/Charts.jsx'
import Chain from '../components/Chain.jsx'

export default function Findings({ summary }) {
  const [f, setF] = useState({ app_id: '', risk_type: '', band: '' })
  const [rows, setRows] = useState(null)
  const [total, setTotal] = useState(0)
  const [open, setOpen] = useState(null)

  useEffect(() => {
    setRows(null)
    api.findings({ ...f, limit: 150 }).then((d) => { setRows(d.findings); setTotal(d.total) })
  }, [f])

  const set = (k) => (e) => setF((p) => ({ ...p, [k]: e.target.value }))

  return (
    <>
      <Panel
        title="Priority queue"
        sub="Two numbers, deliberately. Flaw is how bad the bug is. Priority is how bad it is for you."
        flush
        actions={
          <a href="/api/export/csv"
             className="inline-flex items-center gap-1.5 rounded border border-line bg-raised px-3 py-1.5 text-sm text-muted transition-colors hover:border-edge hover:text-ink">
            <Download size={13} /> CSV
          </a>
        }
      >
        <div className="px-6">
          <Note accent>
            Everyone else sorts by CVSS. But CVSS knows nothing about you — not whether the broken code is ever run,
            not whether the app faces the internet, not whether it touches payment data. Sorting by it sends an
            engineer to patch an <Term k="reachable"><em className="not-italic text-ink">unreachable</em></Term> 9.8 in
            a test tool while a weaponised 7.5 sits live in the payments path.
          </Note>
        </div>

        <div className="mt-5 flex flex-wrap gap-2 px-6 pb-4">
          <Field value={f.app_id} onChange={set('app_id')}>
            <option value="">All applications</option>
            {summary.applications.map((a) => <option key={a.app_id} value={a.app_id}>{a.app_name}</option>)}
          </Field>
          <Field value={f.risk_type} onChange={set('risk_type')}>
            <option value="">All problems</option>
            <option value="vulnerable_dependency">Direct vulnerability</option>
            <option value="transitive_vulnerability">Hidden dependency</option>
            <option value="license_conflict">Licence conflict</option>
            <option value="unmaintained">Unmaintained</option>
          </Field>
          <Field value={f.band} onChange={set('band')}>
            <option value="">All severities</option>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((b) => <option key={b} value={b}>{b}</option>)}
          </Field>
        </div>

        {!rows && <div className="px-6 pb-6"><Skeleton rows={8} /></div>}
        {rows?.length === 0 && <Blank>No findings match these filters.</Blank>}

        {rows?.length > 0 && (
          <div className="px-3 pb-3">
            <Table>
              <thead>
                <tr>
                  <TH className="w-[92px]"><Term k="priority">priority</Term></TH>
                  <TH className="w-[62px]"><Term k="flaw">flaw</Term></TH>
                  <TH>component</TH>
                  <TH>application</TH>
                  <TH>problem</TH>
                  <TH className="w-[62px]"><Term k="depth">depth</Term></TH>
                  <TH>cve</TH>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <TR key={r.dependency_id} onClick={() => setOpen(r.dependency_id)}>
                    <TD>
                      <span className="flex items-center gap-2.5">
                        <span className={cx('h-[5px] w-[5px] rounded-full', sev(r.risk_band).dot)} />
                        <span className={cx('tnum text-md font-semibold', sev(r.risk_band).fg)}>{r.priority_score}</span>
                      </span>
                    </TD>
                    <TD className="tnum text-sm text-faint">{r.risk_score}</TD>
                    <TD>
                      <span className="flex items-center gap-2">
                        <span className="font-mono text-sm text-ink">{r.library.split(':').pop()}</span>
                        <span className="font-mono text-xs text-faint">{r.version}</span>
                        {r.dependency_type === 'transitive' && <Meta tone="info">hidden</Meta>}
                      </span>
                    </TD>
                    <TD className="text-sm text-muted">{r.app_name}</TD>
                    <TD className="text-sm text-dim">{RISK_LABEL[r.primary_risk] || r.primary_risk}</TD>
                    <TD className="tnum text-sm text-dim">{r.true_depth}</TD>
                    <TD className="font-mono text-xs text-faint">
                      {(r.cve_ids || []).slice(0, 1).join('') || '—'}
                      {(r.cve_ids || []).length > 1 && <span className="text-faint"> +{r.cve_ids.length - 1}</span>}
                    </TD>
                  </TR>
                ))}
              </tbody>
            </Table>
            <p className="px-3 pt-4 text-sm text-faint">
              {rows.length} of {total} · click any row for the full analysis
            </p>
          </div>
        )}
      </Panel>

      {open && <Drawer id={open} onClose={() => setOpen(null)} />}
    </>
  )
}

/* ═══════════════════════════════════════════════════════ drawer */
function Drawer({ id, onClose }) {
  const [d, setD] = useState(null)
  const [n, setN] = useState(null)

  useEffect(() => {
    setD(null); setN(null)
    api.finding(id).then(setD)
    api.narrative(id).then(setN)
  }, [id])

  useEffect(() => {
    const esc = (e) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', esc)
    return () => window.removeEventListener('keydown', esc)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-[2px]" onClick={onClose}>
      <div
        onClick={(e) => e.stopPropagation()}
        className="h-full w-full max-w-[680px] overflow-y-auto border-l border-edge bg-surface shadow-pop animate-slide"
      >
        <header className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-line bg-surface/95 px-7 py-5 backdrop-blur">
          <div className="min-w-0">
            <h2 className="truncate font-mono text-md font-semibold text-ink">
              {d?.library}<span className="text-faint"> {d?.version}</span>
            </h2>
            <p className="mt-1 truncate text-sm text-dim">
              {d ? [d.app_name, d.team, d.owner].filter(Boolean).join(' · ') : ' '}
            </p>
          </div>
          <button onClick={onClose} className="rounded p-1.5 text-faint transition-colors hover:bg-hover hover:text-ink">
            <X size={16} />
          </button>
        </header>

        {!d && <div className="p-7"><Skeleton rows={7} /></div>}

        {d && (
          <div className="space-y-8 px-7 py-7">
            {/* the two numbers, side by side. The gap IS the argument. */}
            <div className="flex items-center justify-around rounded-md border border-line bg-raised py-6">
              <Dial value={d.priority_score} label="priority" note="fix first?" color={sev(d.risk_band).hex} />
              <div className="flex flex-col items-center px-2">
                <div className="tnum text-md font-semibold text-info">×{d.context_multiplier}</div>
                <div className="label mt-2">your context</div>
                <div className="mt-0.5 text-[10.5px] text-faint">the difference</div>
              </div>
              <Dial value={d.risk_score} label="flaw" note="how bad?" color="#63636f" />
            </div>

            <Note>
              <strong className="font-semibold text-ink">Flaw {d.risk_score}</strong> is how dangerous this bug is in
              the abstract. <strong className="font-semibold text-ink">Priority {d.priority_score}</strong> is how
              dangerous it is <em className="not-italic text-ink">here</em> — multiplied by{' '}
              <strong className="font-semibold text-info">×{d.context_multiplier}</strong> for the reasons listed
              below. Every part of that multiplier is itemised. Nothing is a black box.
            </Note>

            {d.paths?.[0] && (
              <Sec label="how it gets in">
                <Chain chain={d.paths[0].chain} vuln={d.library} />
              </Sec>
            )}

            <Sec label="analyst narrative">
              {!n && <Skeleton rows={4} />}
              {n && (
                <>
                  <div className="whitespace-pre-wrap text-base leading-[1.8] text-muted">{n.narrative}</div>
                  <p className="mt-4 font-mono text-[10.5px] text-faint">{n.generated_by} · {n.model}</p>
                </>
              )}
            </Sec>

            {d.drivers?.length > 0 && (
              <Sec label="why this score">
                <ul className="space-y-2">
                  {d.drivers.map((x, i) => (
                    <li key={i} className="border-l border-line pl-3.5 text-sm leading-relaxed text-muted">{x}</li>
                  ))}
                </ul>
              </Sec>
            )}

            {d.suppressed_cves?.length > 0 && (
              <div className="rounded-md border border-ok/25 bg-ok/[0.05] px-4 py-3.5 text-sm leading-relaxed text-muted">
                <strong className="font-semibold text-ok">False alarms deliberately muted. </strong>
                <span className="font-mono text-ok/80">{d.suppressed_cves.join(', ')}</span> technically match this
                version — but the build we actually ship already contains the fix. A naive scanner would have
                screamed about every one.
              </div>
            )}

            {d.compliance?.length > 0 && (
              <Sec label="compliance mapping">
                <ul className="space-y-2">
                  {d.compliance.map((c, i) => (
                    <li key={i} className="border-l border-line pl-3.5 text-sm text-muted">
                      <span className="font-medium text-ink">{c.framework} {c.control}</span>
                      <span className="text-dim"> — {c.description}</span>
                    </li>
                  ))}
                </ul>
              </Sec>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

const Sec = ({ label, children }) => (
  <section>
    <div className="label mb-3">{label}</div>
    {children}
  </section>
)
