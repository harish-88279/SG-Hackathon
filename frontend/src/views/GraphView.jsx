import React, { useEffect, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import { Plus, Minus, Maximize2, X } from 'lucide-react'
import { api } from '../api.js'
import { sev, cx, Note } from '../lib.jsx'
import { Panel, Field, Btn, Sev } from '../components/ui.jsx'

const short = (s = '') => (s.includes(':') ? s.split(':').pop() : s)

/* ═══════════════════════════════════════════════════════ the starburst
   We do NOT let the layout engine guess. Positions are computed by hand:
   the app at the origin; ring 1 sorted by severity so danger gathers into
   one hot arc; every deeper component fans out around its parent's bearing,
   so families stay together and every edge points cleanly outward. */
const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, MINIMAL: 4, NONE: 4, SUPPRESSED: 5 }
const rnd = (i) => ((i * 9301 + 49297) % 233280) / 233280

function starburst(nodes, edges) {
  const app = nodes.find((n) => n.data.kind === 'application')
  const libs = nodes.filter((n) => n.data.kind === 'library')
  if (!app) return {}

  const parent = {}
  edges.forEach((e) => { if (!(e.data.target in parent)) parent[e.data.target] = e.data.source })

  const maxD = Math.max(1, ...libs.map((n) => n.data.depth || 1))
  const ringR = (d) => 170 + (d - 1) * 150

  const byDepth = {}
  libs.forEach((n) => {
    const d = Math.min(Math.max(n.data.depth || 1, 1), maxD)
    ;(byDepth[d] = byDepth[d] || []).push(n)
  })

  const angle = {}
  const pos = { [app.data.id]: { x: 0, y: 0 } }

  const d1 = (byDepth[1] || []).sort(
    (a, b) => (SEV_ORDER[a.data.risk_band] ?? 4) - (SEV_ORDER[b.data.risk_band] ?? 4)
  )
  d1.forEach((n, i) => {
    const a = (i / Math.max(d1.length, 1)) * Math.PI * 2 - Math.PI / 2
    angle[n.data.id] = a
    const r = ringR(1) + rnd(i) * 30 - 15
    pos[n.data.id] = { x: Math.cos(a) * r, y: Math.sin(a) * r }
  })

  for (let d = 2; d <= maxD; d++) {
    const ring = byDepth[d] || []
    const fam = {}
    ring.forEach((n) => {
      const p = parent[n.data.id]
      ;(fam[p] = fam[p] || []).push(n)
    })
    const spread = d === 2 ? 0.085 : 0.05
    let orphan = 0
    Object.entries(fam).forEach(([p, kids]) => {
      const pa = angle[p]
      kids.forEach((n, i) => {
        const a = pa == null
          ? (orphan++ / Math.max(ring.length, 1)) * Math.PI * 2
          : pa + (i - (kids.length - 1) / 2) * spread
        angle[n.data.id] = a
        const r = ringR(d) + rnd(i + d * 31) * 36 - 18
        pos[n.data.id] = { x: Math.cos(a) * r, y: Math.sin(a) * r }
      })
    })
  }
  return pos
}

export default function GraphView({ summary, cve }) {
  const box = useRef(null)
  const cy = useRef(null)
  const [app, setApp] = useState(summary.applications[0]?.app_id)
  const [hi, setHi] = useState(cve || 'CVE-2021-44228')
  const [sel, setSel] = useState(null)
  const [st, setSt] = useState(null)

  const draw = async () => {
    const d = await api.graph({ app_id: app, ...(hi.trim() ? { highlight_cve: hi.trim() } : {}) })
    setSt(d.stats)
    setSel(null)
    cy.current?.destroy()

    const positions = starburst(d.nodes, d.edges)
    const elements = [
      ...d.nodes.map((n) => ({ ...n, position: positions[n.data.id] })),
      ...d.edges,
    ]

    const hot = (b) => b === 'CRITICAL' || b === 'HIGH'

    const g = cytoscape({
      container: box.current,
      elements,
      wheelSensitivity: 0.25,
      layout: { name: 'preset', padding: 50 },
      style: [
        { selector: 'core', style: { 'active-bg-opacity': 0 } },

        { selector: 'node[kind="application"]', style: {
            'background-color': '#151310',
            'border-width': 1.5, 'border-color': '#82b4e8',
            'underlay-color': '#82b4e8', 'underlay-opacity': 0.22, 'underlay-padding': 16,
            label: 'data(label)', color: '#f2eee7',
            'font-size': 14, 'font-weight': 700,
            'font-family': 'Bricolage Grotesque Variable, sans-serif',
            shape: 'round-rectangle', width: 'label', height: 38, padding: '12px',
            'text-valign': 'center', 'text-halign': 'center', 'z-index': 100,
        }},

        { selector: 'node[kind="library"]', style: {
            'background-color': (n) => sev(n.data('risk_band')).hex,
            'background-opacity': (n) => (n.data('risk_band') === 'MINIMAL' ? 0.7 : 1),
            'underlay-color': (n) => sev(n.data('risk_band')).hex,
            'underlay-opacity': (n) => (hot(n.data('risk_band')) ? 0.26 : 0.08),
            'underlay-padding': (n) => (hot(n.data('risk_band')) ? 7 : 4),
            'border-width': 0,
            label: (n) => short(n.data('library') || ''),
            color: '#847c6f', 'font-size': 9, 'min-zoomed-font-size': 11,
            'font-family': 'JetBrains Mono Variable, monospace',
            width: (n) => 10 + (n.data('risk_score') || 0) / 5,
            height: (n) => 10 + (n.data('risk_score') || 0) / 5,
            'text-valign': 'bottom', 'text-margin-y': 4,
        }},

        /* hover: the node warms up and names itself, whatever the zoom */
        { selector: 'node.hot', style: {
            'min-zoomed-font-size': 0, 'font-size': 10, color: '#f2eee7',
            'underlay-opacity': 0.35, 'z-index': 99,
        }},

        /* the searched flaw: a hot ember, always labelled */
        { selector: 'node[?highlighted]', style: {
            'background-color': '#ff5d5d', 'background-opacity': 1,
            'underlay-color': '#ff5d5d', 'underlay-opacity': 0.32, 'underlay-padding': 12,
            color: '#ff5d5d', 'font-size': 11, 'font-weight': 700, 'min-zoomed-font-size': 0,
            width: 20, height: 20, 'z-index': 99,
        }},

        /* spokes tinted by the danger they lead to */
        { selector: 'edge', style: {
            width: (e) => (hot(e.target().data('risk_band')) ? 1.4 : 1),
            'line-color': (e) => (hot(e.target().data('risk_band')) ? sev(e.target().data('risk_band')).hex : '#575047'),
            'line-opacity': (e) => (hot(e.target().data('risk_band')) ? 0.5 : 0.3),
            'curve-style': 'straight', 'target-arrow-shape': 'none',
        }},

        /* the traced infection path, root → flaw, drawn in heat */
        { selector: 'edge.path', style: {
            width: 2.2, 'line-color': '#ff5d5d', 'line-opacity': 1,
            'target-arrow-shape': 'triangle', 'target-arrow-color': '#ff5d5d', 'arrow-scale': 0.75,
            'z-index': 98,
        }},
        { selector: 'node.path', style: { 'underlay-opacity': 0.35 } },
      ],
    })

    /* click any node → inspect it, trace how it gets in, glide the camera to the path */
    g.on('tap', 'node', (e) => {
      g.elements('.path').removeClass('path')
      const n = e.target
      setSel(n.data())
      if (n.data('kind') !== 'application') {
        const path = n.predecessors().addClass('path')
        g.animate({ fit: { eles: path.union(n), padding: 110 } }, { duration: 450, easing: 'ease-out' })
      }
    })
    g.on('tap', (e) => {
      if (e.target === g) {
        g.elements('.path').removeClass('path')
        setSel(null)
        g.animate({ fit: { padding: 50 } }, { duration: 450, easing: 'ease-out' })
      }
    })
    g.on('mouseover', 'node', (e) => e.target.addClass('hot'))
    g.on('mouseout', 'node', (e) => e.target.removeClass('hot'))

    /* the searched CVE arrives pre-traced, and its ember pulses on the radar */
    g.ready(() => {
      const flaws = g.nodes('[?highlighted]')
      flaws.forEach((n) => n.predecessors().addClass('path'))
      if (flaws.length) {
        let grow = false
        const iv = setInterval(() => {
          if (g.destroyed()) { clearInterval(iv); return }
          grow = !grow
          flaws.animate(
            { style: { 'underlay-padding': grow ? 22 : 12, 'underlay-opacity': grow ? 0.1 : 0.32 } },
            { duration: 850, easing: 'ease-in-out' }
          )
        }, 900)
      }
    })

    cy.current = g
  }

  useEffect(() => { draw(); return () => cy.current?.destroy() }, [app])

  const zoom = (f) => cy.current?.animate({ zoom: cy.current.zoom() * f }, { duration: 180 })
  const fit = () => cy.current?.animate({ fit: { padding: 50 } }, { duration: 300 })

  return (
    <Panel
      title="Dependency graph"
      sub="Everything an application reaches — including what nobody chose."
      actions={
        <>
          <Field value={app} onChange={(e) => setApp(e.target.value)}>
            {summary.applications.map((a) => <option key={a.app_id} value={a.app_id}>{a.app_name}</option>)}
          </Field>
          <input
            value={hi}
            onChange={(e) => setHi(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && draw()}
            placeholder="Highlight CVE"
            className="raised h-8 w-[150px] px-2.5 font-mono text-sm text-muted outline-none transition-colors focus:border-edge focus:text-ink"
          />
          <Btn onClick={draw}>Highlight</Btn>
        </>
      }
    >
      <Note>
        The centre is your application. Ring one is code someone chose; every ring beyond it arrived{' '}
        <em className="not-italic text-ink">uninvited</em>. Danger gathers into the hot arc, and the searched flaw
        burns at the edge with its infection path already traced — <strong className="font-semibold text-ink">that
        distance from the centre is why nobody found Log4Shell for four days.</strong> Click any node to trace it.
      </Note>

      <div className="mt-5 flex items-center gap-5 pb-3 text-xs text-faint">
        {[['#82b4e8', 'app'], ['#ff5d5d', 'critical'], ['#ffa14d', 'high'], ['#f2c94c', 'medium'], ['#5fcf9a', 'clean']].map(([c, l]) => (
          <span key={l} className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: c, boxShadow: `0 0 6px ${c}88` }} />{l}
          </span>
        ))}
        <span className="ml-auto">scroll to zoom · drag to pan · click a node to trace it</span>
      </div>

      {/* ════════════════════ the radar ════════════════════ */}
      <div className="relative">
        <div
          ref={box}
          className="h-[640px] w-full rounded-md border border-line"
          style={{
            background: [
              'radial-gradient(circle at 50% 50%, rgba(255,122,61,.035), transparent 55%)',
              'repeating-radial-gradient(circle at 50% 50%, rgba(255,255,255,.04) 0 1px, transparent 1px 92px)',
              'rgba(0,0,0,.32)',
            ].join(', '),
          }}
        />

        {/* stats, floating on the glass */}
        {st && (
          <div className="pointer-events-none absolute left-3 top-3 flex gap-2">
            {[[st.library_nodes, 'components'], [st.edges, 'links'], [st.max_depth, 'rings deep']].map(([v, l]) => (
              <span key={l} className="raised px-2.5 py-1.5 text-xs text-muted">
                <span className="tnum font-semibold text-ink">{v}</span> <span className="text-dim">{l}</span>
              </span>
            ))}
          </div>
        )}

        {/* zoom controls */}
        <div className="absolute bottom-3 right-3 flex flex-col gap-1.5">
          {[[Plus, () => zoom(1.35), 'Zoom in'], [Minus, () => zoom(0.74), 'Zoom out'], [Maximize2, fit, 'Fit']].map(([Icon, fn, t]) => (
            <button
              key={t} onClick={fn} title={t}
              className="raised grid h-8 w-8 place-items-center text-dim transition-all hover:border-edge hover:text-ink"
            >
              <Icon size={13} strokeWidth={2} />
            </button>
          ))}
        </div>

        {/* inspector: the selected node, on a floating pane of glass */}
        {sel && (
          <div className="raised absolute bottom-3 left-3 w-[300px] p-4 shadow-pop animate-pop">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="truncate font-mono text-sm font-semibold text-ink">
                  {sel.kind === 'application' ? sel.label : short(sel.library || '')}
                </div>
                {sel.kind === 'library' && sel.version && (
                  <div className="mt-0.5 font-mono text-xs text-faint">{sel.version}</div>
                )}
              </div>
              <button onClick={() => { setSel(null); cy.current?.elements('.path').removeClass('path') }}
                      className="shrink-0 rounded p-1 text-faint transition-colors hover:text-ink">
                <X size={13} />
              </button>
            </div>

            {sel.kind === 'application' ? (
              <p className="mt-2 text-sm text-dim">Application root — everything on this radar ships inside it.</p>
            ) : (
              <>
    