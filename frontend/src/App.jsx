import React, { useCallback, useState } from 'react'
import {
  Crosshair, ListOrdered, GitBranch, Hammer, Sparkles,
  Scale, ShieldBan, FileUp, Award, Command,
} from 'lucide-react'
import { ExplainProvider, useExplain, useAsync, useHotkey, cx } from './lib.jsx'
import { api } from './api.js'
import { Skeleton, Err } from './components/ui.jsx'
import Palette from './components/Palette.jsx'

import Overview     from './views/Overview.jsx'
import Findings     from './views/Findings.jsx'
import GraphView    from './views/GraphView.jsx'
import Remediation  from './views/Remediation.jsx'
import Intelligence from './views/Intelligence.jsx'
import Compliance   from './views/Compliance.jsx'
import Gate         from './views/Gate.jsx'
import UploadView   from './views/UploadView.jsx'
import Proof        from './views/Proof.jsx'

const NAV = [
  { g: 'Respond', items: [
    { id: 'overview',    label: 'War room',     icon: Crosshair },
    { id: 'findings',    label: 'Priority',     icon: ListOrdered },
    { id: 'graph',       label: 'Graph',        icon: GitBranch },
    { id: 'remediation', label: 'Fix plan',     icon: Hammer },
  ]},
  { g: 'Understand', items: [
    { id: 'intelligence', label: 'Intelligence', icon: Sparkles },
    { id: 'compliance',   label: 'Compliance',   icon: Scale },
  ]},
  { g: 'Enforce', items: [
    { id: 'gate',   label: 'Build gate',  icon: ShieldBan },
    { id: 'upload', label: 'Ingest SBOM', icon: FileUp },
    { id: 'proof',  label: 'Scorecard',   icon: Award },
  ]},
]

const VIEWS = {
  overview: Overview, findings: Findings, graph: GraphView, remediation: Remediation,
  intelligence: Intelligence, compliance: Compliance, gate: Gate, upload: UploadView, proof: Proof,
}
const TITLES = {
  overview: ['War room', 'A CVE just dropped. Who is hit?'],
  findings: ['Priority', 'What to fix first — and why'],
  graph: ['Graph', 'How it got in'],
  remediation: ['Fix plan', 'Exactly what to type'],
  intelligence: ['Intelligence', 'Patterns, leverage, early warning'],
  compliance: ['Compliance', 'Evidence, not verdicts'],
  gate: ['Build gate', 'The authority to say no'],
  upload: ['Ingest SBOM', 'CycloneDX · SPDX · CSV'],
  proof: ['Scorecard', 'Measured against ground truth'],
}

function Shell() {
  const [tab, setTab] = useState('overview')
  const [cve, setCve] = useState(null)   // the estate picks its own headline CVE
  const [palette, setPalette] = useState(false)
  const { on, toggle } = useExplain()
  const { loading, data, error } = useAsync(api.summary, [])

  useHotkey('k', () => setPalette(true))

  const pick = useCallback((id) => { setCve(id); setTab('overview') }, [])
  const View = VIEWS[tab]
  const [title, sub] = TITLES[tab]
  const s = data?.stats

  return (
    <div className="grain flex min-h-screen">
      <Palette open={palette} onClose={() => setPalette(false)} onPick={pick} />

      {/* ══════════════════════════════════════════════ rail */}
      <aside className="sticky top-3 m-3 mr-0 flex h-[calc(100vh-24px)] w-[214px] shrink-0 flex-col
                        rounded-2xl border border-line bg-surface/80 shadow-card backdrop-blur-xl">
        <div className="flex items-center gap-3 px-5 pb-6 pt-6">
          <span className="btn-amber relative grid h-9 w-9 shrink-0 place-items-center rounded-xl">
            <svg width="17" height="17" viewBox="0 0 20 20" fill="none">
              <path d="M10 1.6L3.4 4.3v5c0 4.1 2.8 7.5 6.6 8.7 3.8-1.2 6.6-4.6 6.6-8.7v-5L10 1.6z"
                    stroke="#2a1405" strokeWidth="1.7" strokeLinejoin="round" />
              <path d="M10 6.6v4.1M10 13.4v.7"
                    stroke="#2a1405" strokeWidth="2" strokeLinecap="round" />
            </svg>
          </span>
          <div className="min-w-0 leading-none">
            <div className="font-display text-[15px] font-semibold tracking-[-0.02em] text-ink">SBOMGuard</div>
            <div className="mt-1.5 text-[10.5px] tracking-[0.03em] text-faint">Supply chain risk</div>
          </div>
        </div>

        <nav className="flex-1 space-y-6 px-2.5">
          {NAV.map(({ g, items }) => (
            <div key={g}>
              <div className="label px-2.5 pb-2">{g}</div>
              <div className="space-y-px">
                {items.map(({ id, label, icon: Icon }) => {
                  const active = tab === id
                  return (
                    <button
                      key={id}
                      onClick={() => setTab(id)}
                      className={cx(
                        'group relative flex w-full items-center gap-2.5 rounded px-2.5 py-[7px] text-left text-base transition-colors duration-100',
                        active ? 'bg-hover text-ink' : 'text-dim hover:bg-hover/50 hover:text-muted'
                      )}
                    >
                      {active && <span className="absolute left-0 top-1/2 h-4 w-[2px] -translate-y-1/2 rounded-r-full bg-amber" />}
                      <Icon size={14} strokeWidth={1.9} className={cx('shrink-0', active ? 'text-amber' : 'text-faint group-hover:text-dim')} />
                      <span className="truncate">{label}</span>
                    </button>
                  )
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="space-y-1 border-t border-line p-2.5">
          <button
            onClick={() => setPalette(true)}
            className="flex w-full items-center gap-2.5 rounded px-2.5 py-[7px] text-base text-dim transition-colors hover:bg-hover/50 hover:text-muted"
          >
            <Command size={14} strokeWidth={1.9} className="shrink-0 text-faint" />
            <span className="flex-1 text-left">Search CVE</span>
            <kbd className="kbd">⌘K</kbd>
          </button>

          <button
            onClick={toggle}
            className="flex w-full items-center gap-2.5 rounded px-2.5 py-[7px] text-base text-dim transition-colors hover:bg-hover/50 hover:text-muted"
          >
            <span className={cx('h-[5px] w-[5px] shrink-0 rounded-full transition-colors', on ? 'bg-ok' : 'bg-faint')} />
            <span className="flex-1 text-left">Plain English</span>
            <span className={cx('text-[10px] font-semibold uppercase tracking-wide', on ? 'text-ok' : 'text-faint')}>
              {on ? 'on' : 'off'}
            </span>
          </button>
        </div>
      </aside>

      {/* ══════════════════════════════════════════════ main */}
      <div className="relative z-10 flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 bg-canvas/70 backdrop-blur-xl">
          <div className="flex h-[58px] items-center justify-between gap-8 px-8">
            <div className="flex items-baseline gap-3">
              <h1 className="font-display text-md font-semibold tracking-tight text-ink">{title}</h1>
              <span className="text-sm text-faint">{sub}</span>
            </div>
            {s && (
              <div className="hidden items-center gap-px lg:flex">
                <Tick v={s.total_dependencies} l="components" />
                <Tick v={s.at_risk} l="at risk" c="text-crit" />
                <Tick v={s.unique_cves} l="cves" c="text-high" />
                <Tick v={s.known_exploited_cves} l="exploited" c="text-info" />
                <Tick v={s.suppressed_false_positives} l="muted" c="text-ok" last />
              </div>
            )}
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1500px] flex-1 px-7 py-6">
          {loading && <Skeleton rows={7} />}
          {error && <Err error={error} />}
          {data && <View summary={data} cve={cve} setCve={setCve} goto={setTab} openPalette={() => setPalette(true)} />}
        </main>
      </div>
    </div>
  )
}

function Tick({ v, l, c = 'text-ink', last }) {
  return (
    <div className={cx('px-4 text-right', !last && 'border-r border-line')}>
      <div className={cx('tnum text-md font-semibold leading-none', c)}>{v}</div>
      <div className="label mt-1.5">{l}</div>
    </div>
  )
}

export default function App() {
  return <ExplainProvider><Shell /></ExplainProvider>
}
