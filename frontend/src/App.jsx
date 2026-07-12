import React, { useCallback, useEffect, useRef, useState } from 'react'
import gsap from 'gsap'
import {
  Crosshair, ListOrdered, GitBranch, Hammer, Sparkles,
  Scale, ShieldBan, FileUp, Award, Command,
} from 'lucide-react'
import { ExplainProvider, useExplain, useAsync, useHotkey, useCountUp, cx } from './lib.jsx'
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

/* The living warmth every pane of glass sits on. Three embers, kept faint. */
function Aurora() {
  return (
    <>
      <div className="aurora-blob animate-drift1 -top-40 right-[-10%] h-[520px] w-[520px] bg-sg/[0.07]" />
      <div className="aurora-blob animate-drift2 bottom-[-15%] left-[-8%] h-[620px] w-[620px] bg-[#d65d28]/[0.05]" />
      <div className="aurora-blob animate-drift3 left-[38%] top-[30%] h-[380px] w-[380px] bg-gold/[0.03]" />
    </>
  )
}

/* A thin line of ember under the header, tracking how deep you've read. */
function ScrollProgress() {
  const [p, setP] = useState(0)
  useEffect(() => {
    const h = () => {
      const d = document.documentElement
      const max = d.scrollHeight - d.clientHeight
      setP(max > 0 ? Math.min(window.scrollY / max, 1) : 0)
    }
    h()
    window.addEventListener('scroll', h, { passive: true })
    window.addEventListener('resize', h)
    return () => { window.removeEventListener('scroll', h); window.removeEventListener('resize', h) }
  }, [])
  return (
    <div className="pointer-events-none absolute bottom-[-1px] left-0 h-[2px] w-full">
      <div
        className="h-full bg-gradient-to-r from-sg to-gold transition-[width] duration-150 ease-out"
        style={{ width: `${p * 100}%`, boxShadow: p > 0.01 ? '0 0 10px rgba(255,122,61,.55)' : 'none' }}
      />
    </div>
  )
}

function Shell() {
  const [tab, setTab] = useState('overview')
  const [cve, setCve] = useState('CVE-2021-44228')
  const [palette, setPalette] = useState(false)
  const { on, toggle } = useExplain()
  const { loading, data, error } = useAsync(api.summary, [])
  const rail = useRef(null)

  useHotkey('k', () => setPalette(true))

  /* the rail wakes up: items cascade in from the left */
  useEffect(() => {
    if (!rail.current || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    const ctx = gsap.context(() => {
      gsap.fromTo('.nav-item',
        { opacity: 0, x: -16 },
        { opacity: 1, x: 0, duration: 0.35, stagger: 0.035, ease: 'power3.out', delay: 0.1 })
    }, rail)
    return () => ctx.revert()
  }, [])

  const pick = useCallback((id) => { setCve(id); setTab('overview') }, [])
  const View = VIEWS[tab]
  const [title, sub] = TITLES[tab]
  const s = data?.stats

  return (
    <div className="aurora grain flex min-h-screen">
      <Aurora />
      <Palette open={palette} onClose={() => setPalette(false)} onPick={pick} />

      {/* ══════════════════════════════════════════════ floating glass rail */}
      <aside ref={rail} className="sticky top-0 z-20 hidden h-screen w-[236px] shrink-0 p-3 pr-0 md:block">
        <div className="surface flex h-full flex-col !rounded-xl">
          <div className="flex items-center gap-2.5 px-5 pb-6 pt-6">
            <div className="relative grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-gradient-to-br from-[#ff8b52] to-[#e0501a] shadow-glow">
              <svg width="18" height="18" viewBox="0 0 20 20" fill="none">
                <path d="M10 1L2.5 4v5.5c0 4.5 3.2 8.2 7.5 9.5 4.3-1.3 7.5-5 7.5-9.5V4L10 1z"
                      stroke="#fff" strokeWidth="1.5" strokeLinejoin="round" />
                <path d="M10 6.5v4M10 13.2v.6" stroke="#fff" strokeWidth="1.7" strokeLinecap="round" />
              </svg>
            </div>
            <div className="min-w-0 leading-none">
              <div className="font-display text-[15px] font-semibold tracking-tight text-ink">SBOMGuard</div>
              <div className="mt-1 text-[10.5px] tracking-[0.04em] text-dim">Supply chain risk</div>
            </div>
          </div>

          <nav className="flex-1 space-y-6 overflow-y-auto px-2.5">
            {NAV.map(({ g, items }) => (
              <div key={g}>
                <div className="label px-3 pb-2">{g}</div>
                <div className="space-y-0.5">
                  {items.map(({ id, label, icon: Icon }) => {
                    const active = tab === id
                    return (
                      <button
                        key={id}
                        onClick={() => setTab(id)}
                        className={cx(
                          'nav-item group relative flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-left text-base',
                          'transition-all duration-150',
                          active
                            ? 'bg-gradient-to-r from-sg/[0.13] to-transparent text-ink shadow-[inset_0_1px_0_rgba(255,255,255,.07),0_0_20px_-8px_rgba(255,122,61,.35)]'
                            : 'text-dim hover:bg-ink/[0.04] hover:pl-4 hover:text-muted'
                        )}
                      >
                        <span className={cx(
                          'absolute left-0 top-1/2 h-4 w-[2.5px] -translate-y-1/2 rounded-r-full bg-gradient-to-b from-sg to-gold',
                          'transition-all duration-300',
                          active ? 'opacity-100' : 'opacity-0'
                        )} />
                        <Icon size={14} strokeWidth={1.9}
                              className={cx('shrink-0 transition-colors', active ? 'text-sg' : 'text-faint group-hover:text-dim')} />
                        <span className="truncate">{label}</span>
                      </button>
                    )
                  })}
                </div>
              </div>
            ))}
          </nav>

          <div className="space-y-1 border-t border-line/60 p-2.5">
            <button
              onClick={() => setPalette(true)}
              className="flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-base text-dim transition-colors hover:bg-ink/[0.04] hover:text-muted"
            >
              <Command size={14} strokeWidth={1.9} className="shrink-0 text-faint" />
              <span className="flex-1 text-left">Search CVE</span>
              <kbd className="kbd">⌘K</kbd>
            </button>

            <button
              onClick={toggle}
              classNam