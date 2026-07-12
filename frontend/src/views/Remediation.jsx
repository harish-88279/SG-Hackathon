import React from 'react'
import { AlertTriangle, ShieldHalf } from 'lucide-react'
import { api } from '../api.js'
import { cx, Note, useAsync } from '../lib.jsx'
import { Panel, Skeleton, Err, Meta } from '../components/ui.jsx'

const U = {
  IMMEDIATE:   { bar: 'bg-crit', fg: 'text-crit', label: 'today' },
  THIS_WEEK:   { bar: 'bg-high', fg: 'text-high', label: 'this week' },
  THIS_SPRINT: { bar: 'bg-med',  fg: 'text-med',  label: 'this sprint' },
  BACKLOG:     { bar: 'bg-faint',fg: 'text-dim',  label: 'backlog' },
}

export default function Remediation() {
  const { loading, data, error } = useAsync(api.remediation, [])
  if (loading) return <Panel title="Fix plan"><Skeleton rows={8} /></Panel>
  if (error) return <Err error={error} />
  const s = data.summary

  return (
    <Panel
      title="Fix plan"
      sub="Not a list of problems. A list of actions, in order, with the exact commands to type."
      flush
    >
      <div className="px-6">
        <Note accent>
          <strong className="font-semibold text-ink">{s.findings_collapsed} problems became {s.total_actions} actions.</strong>{' '}
          They collapse because one upgrade often fixes the same flaw across several apps at once — patching Log4j
          once clears it in four applications. Nobody works a {s.findings_collapsed}-item list; a list that long is a
          reason to give up. <strong className="font-semibold text-crit">{s.immediate} need doing today.</strong>
        </Note>
      </div>

      <div className="mt-6">
        {data.actions.map((a, i) => {
          const u = U[a.urgency] || U.BACKLOG
          return (
            <article key={a.action_id} className={cx('flex gap-5 px-6 py-5', i !== 0 && 'border-t border-line')}>
              <div className={cx('mt-1 w-[2px] shrink-0 rounded-full', u.bar)} />

              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-baseline justify-between gap-3">
                  <h3 className="text-base font-medium text-ink">{a.title}</h3>
                  <div className="flex shrink-0 items-center gap-2.5">
                    <span className={cx('text-micro uppercase', u.fg)}>{u.label}</span>
                    <span className="text-micro uppercase text-faint">{a.action_type.replace(/_/g, ' ')}</span>
                  </div>
                </div>

                <p className="mt-2 max-w-[92ch] text-sm leading-relaxed text-muted">{a.rationale}</p>

                {a.commands?.length > 0 && (
                  <pre className="mt-3.5 overflow-x-auto rounded border border-line bg-canvas px-4 py-3 font-mono text-[11.5px] leading-[1.7] text-dim">
                    {a.commands.join('\n')}
                  </pre>
                )}

                {a.caveats?.map((c, k) => (
                  <p key={k} className="mt-3 flex gap-2.5 text-sm leading-relaxed text-high/85">
                    <AlertTriangle size={13} className="mt-[3px] shrink-0" />{c}
                  </p>
                ))}

                {a.compensating_control && (
                  <p className="mt-3 flex gap-2.5 rounded border border-info/25 bg-info/[0.05] px-3.5 py-2.5 text-sm leading-relaxed text-muted">
                    <ShieldHalf size={13} className="mt-[3px] shrink-0 text-info" />
                    <span><strong className="font-semibold text-info">Hold the line meanwhile. </strong>{a.compensating_control}</span>
                  </p>
                )}

                <p className="mt-3 text-xs text-faint">
                  {a.affected_apps.join(' · ')}
                  {a.cve_ids?.length > 0 && <span className="font-mono"> · {a.cve_ids.slice(0, 3).join(' ')}</span>}
                </p>
              </div>
            </article>
          )
        })}
      </div>
    </Panel>
  )
}
