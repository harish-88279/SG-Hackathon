import React, { useState } from 'react'
import { AlertTriangle, ShieldHalf, Copy, Check } from 'lucide-react'
import { api } from '../api.js'
import { cx, Note, useAsync } from '../lib.jsx'
import { Panel, Skeleton, Err } from '../components/ui.jsx'

const U = {
  IMMEDIATE:   { bar: 'bg-crit', fg: 'text-crit', hex: '#ff5d5d', label: 'today' },
  THIS_WEEK:   { bar: 'bg-high', fg: 'text-high', hex: '#ffa14d', label: 'this week' },
  THIS_SPRINT: { bar: 'bg-med',  fg: 'text-med',  hex: '#f2c94c', label: 'this sprint' },
  BACKLOG:     { bar: 'bg-faint',fg: 'text-dim',  hex: '#544e44', label: 'backlog' },
}

/** Commands you can lift straight off the screen. */
function CommandBlock({ commands }) {
  const [ok, setOk] = useState(false)
  const text = commands.join('\n')
  const copy = () => {
    navigator.clipboard?.writeText(text)
    setOk(true)
    setTimeout(() => setOk(false), 1400)
  }
  return (
    <div className="group/code relative mt-3.5">
      <pre className="overflow-x-auto rounded-md border border-line bg-black/30 px-4 py-3 pr-20 font-mono text-[11.5px] leading-[1.7] text-muted">
        {text}
      </pre>
      <button
        onClick={copy}
        className={cx(
          'absolute right-2 top-2 inline-flex items-center gap-1.5 rounded border border-line bg-black/50 px-2 py-1',
          'text-[10px] font-semibold uppercase tracking-wide backdrop-blur-sm transition-all',
          ok ? 'text-ok' : 'text-dim opacity-0 hover:text-ink group-hover/code:opacity-100'
        )}
      >
        {ok ? <Check size={11} /> : <Copy size={11} />}
        {ok ? 'copied' : 'copy'}
      </button>
    </div>
  )
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

      <div className="mt-6 space-y-4 px-6 pb-6">
        {data.actions.map((a, i) => {
          const u = U[a.urgency] || U.BACKLOG
          return (
            <article
              key={a.action_id}
              style={{ animationDelay: `${Math.min(i, 12) * 40}ms` }}
              className="raised relative animate-rise overflow-hidden p-5 pl-6"
            >
              {/* urgency edge, glowing with its own heat */}
              <span
                className={cx('absolute left-0 top-0 h-full w-[3px]', u.bar)}
                style={{ boxShadow: `0 0 14px ${u.hex}66` }}
              />

              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex min-w-0 items-center gap-3">
                  <span className="tnum grid h-7 w-7 shrink-0 place-items-center rounded-md border border-line bg-ink/[0.04] font-display text-sm font-semibold text-muted">
                    {i + 1}
                  </span>
                  <h3 className="min-w-0 font-display text-md font-semibold tracking-tight text-ink">{a.title}</h3>
                </div>
                <div className="flex shrink-0 items-center gap-2.5">
         