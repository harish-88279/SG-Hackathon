import React, { createContext, useContext, useEffect, useState } from 'react'

/* ═══════════════════════════════════════════════════════ severity tokens
   Colour is SIGNAL. It is never decoration. A component only gets a colour
   if that colour tells you something you would otherwise have to read. */
export const SEV = {
  CRITICAL:   { fg: 'text-crit', bg: 'bg-crit/10',  bd: 'border-crit/25',  dot: 'bg-crit', hex: '#ff5d5d' },
  HIGH:       { fg: 'text-high', bg: 'bg-high/10',  bd: 'border-high/25',  dot: 'bg-high', hex: '#ffa14d' },
  MEDIUM:     { fg: 'text-med',  bg: 'bg-med/10',   bd: 'border-med/25',   dot: 'bg-med',  hex: '#f2c94c' },
  LOW:        { fg: 'text-low',  bg: 'bg-low/10',   bd: 'border-low/25',   dot: 'bg-low',  hex: '#82b4e8' },
  MINIMAL:    { fg: 'text-ok',   bg: 'bg-ok/10',    bd: 'border-ok/25',    dot: 'bg-ok',   hex: '#5fcf9a' },
  NONE:       { fg: 'text-ok',   bg: 'bg-ok/10',    bd: 'border-ok/25',    dot: 'bg-ok',   hex: '#5fcf9a' },
  SUPPRESSED: { fg: 'text-dim',  bg: 'bg-dim/10',   bd: 'border-dim/25',   dot: 'bg-dim',  hex: '#847c6f' },
}
export const sev = (s) => SEV[s] || SEV.MINIMAL

export const RISK_LABEL = {
  vulnerable_dependency:    'Direct vulnerability',
  transitive_vulnerability: 'Hidden dependency',
  license_conflict:         'Licence conflict',
  unmaintained:             'Unmaintained',
  none:                     'Clean',
}

/* ═══════════════════════════════════════════════════════ glossary */
export const GLOSSARY = {
  cve: 'A publicly catalogued security flaw. A bug with a police record.',
  cvss: 'Scores how dangerous a flaw is in the abstract, 0–10. It knows nothing about your system.',
  transitive:
    'A library your app never asked for — your library needed it, so it came along too. This is where Log4Shell hid.',
  reachable:
    'Whether the broken code is ever actually run by your app. A flaw you never call is a liability, not an emergency.',
  copyleft:
    'Some licences (GPL, AGPL) require you to publish your own source code if you use them a certain way. A legal problem, not a technical one.',
  priority:
    'What to fix first — the flaw seen through your context: reachable? internet-facing? touching payment data?',
  flaw: 'How bad the vulnerability is on its own, ignoring your situation. Comparable to CVSS.',
  blast: 'Everything that breaks if this one component is compromised.',
  depth: 'How many layers down it sits. 1 = you chose it. 3 = it arrived uninvited.',
}

/* ═══════════════════════════════════════════════════════ explain mode */
const Ctx = createContext({ on: true, toggle: () => {} })
export const useExplain = () => useContext(Ctx)

export function ExplainProvider({ children }) {
  const [on, setOn] = useState(true)
  return <Ctx.Provider value={{ on, toggle: () => setOn((v) => !v) }}>{children}</Ctx.Provider>
}

/** A margin note. Deliberately quiet — it sits BESIDE the data, never on top of it. */
export function Note({ children, accent = false }) {
  const { on } = useExplain()
  if (!on) return null
  return (
    <aside
      className={cx(
        'relative py-1 pl-4 text-sm leading-[1.7] text-muted animate-rise',
        'before:absolute before:left-0 before:top-1 before:bottom-1 before:w-[2px] before:rounded-full',
        accent ? 'before:bg-amber' : 'before:bg-edge'
      )}
    >
      {children}
    </aside>
  )
}

/* ═══════════════════════════════════════════════════════ helpers */
export const cx = (...a) => a.filter(Boolean).join(' ')

export function useAsync(fn, deps = []) {
  const [s, set] = useState({ loading: true, data: null, error: null })
  useEffect(() => {
    let alive = true
    set({ loading: true, data: null, error: null })
    Promise.resolve(fn())
      .then((d) => alive && set({ loading: false, data: d, error: null }))
      .catch((e) => alive && set({ loading: false, data: null, error: e.message }))
    return () => { alive = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  return s
}

/** ⌘K / Ctrl+K */
export function useHotkey(key, fn, meta = true) {
  useEffect(() => {
    const h = (e) => {
      if (e.key.toLowerCase() === key && (!meta || e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        fn()
      }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [key, fn, meta])
}
