import React, { useEffect, useState } from 'react'
import { Terminal } from 'lucide-react'
import { api } from '../api.js'
import { cx, Note } from '../lib.jsx'
import { Panel, Field, Btn, Skeleton, Err, Meta } from '../components/ui.jsx'

const POLICIES = [
  ['permissive', 'Permissive — blocks only active exploits'],
  ['default',    'Default — balanced'],
  ['strict',     'Strict — low tolerance'],
  ['pci',        'PCI — card-data scope'],
]

export default function Gate() {
  const [p, setP] = useState('default')
  const [r, setR] = useState(null)
  const [busy, setBusy] = useState(true)
  const [err, setErr] = useState(null)

  const run = async (pol) => {
    setBusy(true); setErr(null)
    try { setR(await api.gate(pol)) } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }
  useEffect(() => { run(p) }, [p])

  return (
    <Panel
      title="Build gate"
      sub="Everything else here reports on risk. Reports do not stop risk being merged. This does."
      flush
      actions={
        <>
          <Field value={p} onChange={(e) => setP(e.target.value)} className="max-w-[260px]">
            {POLICIES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </Field>
          <Btn onClick={() => run(p)}>Run</Btn>
        </>
      }
    >
      <div className="px-6">
        <Note accent>
          Log4Shell did not get into those codebases because nobody had a scanner. It got in because{' '}
          <strong className="font-semibold text-ink">nothing in the pipeline had the authority to say no.</strong> This
          returns a UNIX exit code — drop it into CI and a dangerous dependency simply{' '}
          <em className="not-italic text-ink">cannot be merged</em>.
        </Note>
      </div>

      {busy && <div className="px-6 py-6"><Skeleton rows={5} /></div>}
      {err && <div className="px-6 pb-6"><Err error={err} /></div>}

      {!busy && r && (
        <>
          {/* the verdict, as a terminal would print it */}
          <div className={cx('mt-6 flex items-center gap-4 border-y px-6 py-4 font-mono text-sm',
            r.passed ? 'border-ok/25 bg-ok/[0.05] text-ok' : 'border-crit/25 bg-crit/[0.05] text-crit')}>
            <span className="font-semibold">{r.passed ? '✓' : '✕'}</span>
            <span className="flex-1">{r.verdict}</span>
            <span className="rounded-xs bg-black/40 px-2 py-0.5 text-xs">exit {r.exit_code}</span>
          </div>

          {r.blocks?.length > 0 && (
            <>
              <div className="label px-6 pb-3 pt-6">blocking the build · {r.block_count}</div>
              {r.blocks.slice(0, 10).map((b, i) => <V key={i} v={b} blocking />)}
            </>
          )}

          {r.warnings?.length > 0 && (
            <>
              <div className="label px-6 pb-3 pt-6">warnings · {r.warning_count} · reported, not blocking</div>
              {r.warnings.slice(0, 5).map((w, i) => <V key={i} v={w} />)}
            </>
          )}

          <details className="mx-6 my-6 rounded-md border border-line bg-raised">
            <summary className="flex cursor-pointer items-center gap-2 px-4 py-3 text-sm text-muted transition-colors hover:text-ink">
              <Terminal size={13} /> Drop this into GitHub Actions
            </summary>
            <pre className="overflow-x-auto border-t border-line px-4 py-3.5 font-mono text-[11.5px] leading-[1.7] text-dim">
              {r.ci_snippet}
            </pre>
          </details>
        </>
      )}
    </Panel>
  )
}

function V({ v, blocking }) {
  return (
    <div className="flex gap-4 border-t border-line px-6 py-3.5 first:border-t-0">
      <span className={cx('mt-1.5 h-[5px] w-[5px] shrink-0 rounded-full', blocking ? 'bg-crit' : 'bg-med')} />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-sm text-ink">{v.library}</span>
          <span className="font-mono text-xs text-faint">{v.version}</span>
          <span className="text-xs text-dim">in {v.app_name}</span>
          <Meta tone={blocking ? 'crit' : undefined}>{v.rule.replace(/_/g, ' ')}</Meta>
        </div>
        <p className="mt-1.5 text-sm leading-relaxed text-muted">{v.message}</p>
        <p className="mt-1 text-sm text-ok">→ {v.remediation}</p>
      </div>
    </div>
  )
}
