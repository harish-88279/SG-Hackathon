import React, { useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api.js'
import { sev, cx, Note } from '../lib.jsx'
import { Panel, Field, Btn, Sev, Skeleton } from '../components/ui.jsx'

/**
 * The orbital graph.
 *
 * A left-to-right tree is the obvious way to draw a dependency graph, and it is the wrong
 * one: it makes depth look like *distance along a page*, which is meaningless, and it
 * spreads 500 nodes into a smear nobody can read.
 *
 * So we draw it as ORBITS. The application sits at the centre. Ring one is code somebody
 * on the team actually chose. Every ring beyond it arrived uninvited. Now depth is
 * literally RADIUS — and the single most important fact about a supply-chain flaw, that it
 * is *far from anything you decided*, becomes something you can see from across a room.
 *
 * Two further decisions do the real work:
 *
 *   THE HOT ARC. Within each ring, nodes are ordered by severity rather than by name. The
 *   dangerous ones therefore collect into a contiguous burning arc instead of being
 *   sprinkled evenly around the circle. A uniform sprinkle of red reads as "everything is
 *   a bit bad" — which is how a security dashboard teaches people to ignore it. An arc
 *   reads as "look HERE".
 *
 *   THE TRACE. The searched CVE is pulled clear of its ring, lit, and its infection path
 *   back to the centre is drawn through every hop that carried it. That line is the whole
 *   argument of the product, drawn in one stroke.
 */
const RING_GAP = 118
const NODE_R = 5.5

export default function GraphView({ summary, cve }) {
  const [appId, setAppId] = useState(summary.applications[0]?.app_id)
  const [hi, setHi] = useState(cve || summary.featured_cves?.[0]?.cve_id || '')
  const [data, setData] = useState(null)
  const [sel, setSel] = useState(null)

  // viewport
  const [view, setView] = useState({ x: 0, y: 0, k: 1 })
  const drag = useRef(null)
  const svgRef = useRef(null)

  const load = async (highlight = hi) => {
    setData(null); setSel(null)
    const q = { app_id: appId }
    if (highlight?.trim()) q.highlight_cve = highlight.trim()
    setData(await api.graph(q))
    setView({ x: 0, y: 0, k: 1 })
  }
  useEffect(() => { load() }, [appId])

  /* ── layout ─────────────────────────────────────────────────────────────── */
  const layout = useMemo(() => {
    if (!data) return null

    const app = data.nodes.find((n) => n.data.kind === 'application')
    const libs = data.nodes.filter((n) => n.data.kind === 'library')
    if (!app) return null

    const RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, MINIMAL: 4, SUPPRESSED: 5 }
    const pos = new Map()
    pos.set(app.data.id, { x: 0, y: 0, ...app.data })

    const rings = new Map()
    libs.forEach((n) => {
      const d = Math.max(1, Math.min(n.data.depth || 1, 5))
      if (!rings.has(d)) rings.set(d, [])
      rings.get(d).push(n)
    })

    const depths = [...rings.keys()].sort((a, b) => a - b)
    depths.forEach((d) => {
      const ns = rings.get(d)
      // THE HOT ARC — severity first, then score. Danger clumps; it does not sprinkle.
      ns.sort((a, b) =>
        (RANK[a.data.risk_band] ?? 9) - (RANK[b.data.risk_band] ?? 9) ||
        (b.data.risk_score || 0) - (a.data.risk_score || 0)
      )
      const r = RING_GAP * d
      // start the arc at ~11 o'clock so the hot side reads top-right
      const start = -Math.PI * 0.62
      ns.forEach((n, i) => {
        const t = start + (i / ns.length) * Math.PI * 2
        pos.set(n.data.id, {
          x: Math.cos(t) * r, y: Math.sin(t) * r, ring: d, angle: t, ...n.data,
        })
      })
    })

    // the traced node is lifted clear of its ring so the path is legible
    const hot = libs.filter((n) => n.data.highlighted).map((n) => n.data.id)
    hot.forEach((id) => {
      const p = pos.get(id)
      if (!p) return
      const r = RING_GAP * (p.ring || 1) + 96
      pos.set(id, { ...p, x: Math.cos(p.angle) * r, y: Math.sin(p.angle) * r, lifted: true })
    })

    const edges = data.edges
      .map((e) => ({ s: pos.get(e.data.source), t: pos.get(e.data.target) }))
      .filter((e) => e.s && e.t)

    // the infection path: every edge that lies on a route to a traced node
    const parent = new Map()
    data.edges.forEach((e) => parent.set(e.data.target, e.data.source))
    const traced = new Set()
    hot.forEach((id) => {
      let cur = id
      for (let i = 0; i < 12 && parent.has(cur); i++) {
        traced.add(`${parent.get(cur)}->${cur}`)
        cur = parent.get(cur)
      }
    })

    const maxR = RING_GAP * (depths[depths.length - 1] || 1) + 140
    return { pos, edges, traced, hot, app: pos.get(app.data.id), depths, maxR }
  }, [data])

  /* ── interaction ────────────────────────────────────────────────────────── */
  const onWheel = (e) => {
    e.preventDefault()
    setView((v) => ({ ...v, k: Math.min(4, Math.max(0.35, v.k * (e.deltaY < 0 ? 1.12 : 0.89))) }))
  }
  const onDown = (e) => { drag.current = { x: e.clientX, y: e.clientY, ...view } }
  const onMove = (e) => {
    if (!drag.current) return
    const d = drag.current
    setView({ ...d, x: d.x0 ?? d.x, y: d.y0 ?? d.y, ...{ x: d.x + (e.clientX - d.x) * 0, y: 0 } })
  }
  // simpler, correct pan
  const onMove2 = (e) => {
    if (!drag.current) return
    const d = drag.current
    setView((v) => ({ ...v, x: d.px + (e.clientX - d.x) / v.k, y: d.py + (e.clientY - d.y) / v.k }))
  }
  const onDown2 = (e) => { drag.current = { x: e.clientX, y: e.clientY, px: view.x, py: view.y } }
  const onUp = () => { drag.current = null }

  const VB = 900
  const half = VB / 2

  return (
    <Panel
      title="Dependency graph"
      sub="Everything an application reaches — including what nobody chose."
      actions={
        <>
          <Field value={appId} onChange={(e) => setAppId(e.target.value)}>
            {summary.applications.map((a) => (
              <option key={a.app_id} value={a.app_id}>{a.app_name}</option>
            ))}
          </Field>
          <input
            value={hi}
            onChange={(e) => setHi(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && load(hi)}
            placeholder="Trace a CVE"
            className="h-8 w-[152px] rounded border border-line bg-raised px-2.5 font-mono text-sm text-muted outline-none transition-colors focus:border-edge focus:text-ink"
          />
          <Btn onClick={() => load(hi)}>Trace</Btn>
        </>
      }
    >
      <Note>
        The centre is your application. <strong className="font-semibold text-ink">Ring one</strong> is code someone
        chose; every ring beyond it <strong className="font-semibold text-ink">arrived uninvited</strong>. Danger
        gathers into the hot arc, and the traced flaw burns at the edge with its infection path already drawn —{' '}
        <strong className="font-semibold text-ink">that distance from the centre is why nobody found Log4Shell for
        four days.</strong> Click any node to inspect it.
      </Note>

      <div className="mt-5 flex flex-wrap items-center gap-5 pb-3 text-xs text-faint">
        {[['#5a9de8', 'app'], ['#f4485f', 'critical'], ['#f2894a', 'high'],
          ['#dfb13f', 'medium'], ['#40b98c', 'clean']].map(([c, l]) => (
          <span key={l} className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: c }} />{l}
          </span>
        ))}
        <span className="ml-auto">scroll to zoom · drag to pan · click a node to inspect</span>
      </div>

      <div className="relative overflow-hidden rounded-md border border-line bg-canvas">
        {!data && <div className="p-6"><Skeleton rows={9} /></div>}

        {data && layout && (
          <>
            {/* floating stats */}
            <div className="pointer-events-none absolute left-4 top-4 z-10 flex gap-2">
              {[[data.stats.library_nodes, 'components'],
                [data.stats.edges, 'links'],
                [data.stats.max_depth, 'rings deep']].map(([v, l]) => (
                <span key={l} className="rounded border border-line bg-surface/85 px-2.5 py-1 text-xs text-dim backdrop-blur">
                  <b className="tnum font-semibold text-ink">{v}</b> {l}
                </span>
              ))}
            </div>

            <svg
              ref={svgRef}
              viewBox={`${-half} ${-half} ${VB} ${VB}`}
              className="h-[600px] w-full cursor-grab active:cursor-grabbing select-none"
              onWheel={onWheel}
              onMouseDown={onDown2}
              onMouseMove={onMove2}
              onMouseUp={onUp}
              onMouseLeave={onUp}
            >
              <defs>
                <radialGradient id="core" cx="50%" cy="50%">
                  <stop offset="0%" stopColor="#5a9de8" stopOpacity=".22" />
                  <stop offset="100%" stopColor="#5a9de8" stopOpacity="0" />
                </radialGradient>
                <filter id="burn" x="-260%" y="-260%" width="620%" height="620%">
                  <feGaussianBlur stdDeviation="7" result="b" />
                  <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
                </filter>
              </defs>

              <g transform={`scale(${view.k}) translate(${view.x} ${view.y})`}>
                {/* orbit guides */}
                {layout.depths.map((d) => (
                  <circle key={d} cx={0} cy={0} r={RING_GAP * d}
                          fill="none" stroke="#1e1e23" strokeWidth={1} />
                ))}
                <circle cx={0} cy={0} r={92} fill="url(#core)" />

                {/* edges */}
                {layout.edges.map((e, i) => {
                  const key = `${e.s.id}->${e.t.id}`
                  const hot = layout.traced.has(key)
                  return (
                    <line
                      key={i}
                      x1={e.s.x} y1={e.s.y} x2={e.t.x} y2={e.t.y}
                      stroke={hot ? '#f4485f' : '#1e1e23'}
                      strokeWidth={hot ? 1.4 : 0.6}
                      strokeOpacity={hot ? 0.85 : 1}
                    />
                  )
                })}

                {/* nodes */}
                {[...layout.pos.values()].filter((n) => n.kind === 'library').map((n) => {
                  const s = sev(n.risk_band)
                  const clean = n.risk_band === 'MINIMAL'
                  const r = n.lifted ? 8 : NODE_R + (n.risk_score || 0) / 34
                  return (
                    <g key={n.id} onClick={(e) => { e.stopPropagation(); setSel(n) }}
                       className="cursor-pointer">
                      <circle
                        cx={n.x} cy={n.y} r={r}
                        fill={s.hex}
                        fillOpacity={clean ? 0.5 : 1}
                        filter={n.lifted ? 'url(#burn)' : undefined}
                        stroke={sel?.id === n.id ? '#ededf0' : 'none'}
                        strokeWidth={1.5}
                      />
                      {n.lifted && (
                        <text x={n.x} y={n.y + 21} textAnchor="middle"
                              className="fill-crit font-mono" style={{ fontSize: 9, fontWeight: 700 }}>
                          {n.library}
                        </text>
                      )}
                    </g>
                  )
                })}

                {/* the application, at the centre of its own world */}
                <g>
                  <rect x={-72} y={-19} width={144} height={38} rx={6}
                        fill="#0a0a0b" stroke="#5a9de8" strokeWidth={1.4} />
                  <text x={0} y={5} textAnchor="middle"
                        className="fill-ink" style={{ fontSize: 12, fontWeight: 600 }}>
                    {layout.app?.label}
                  </text>
                </g>
              </g>
            </svg>
          </>
        )}
      </div>

      <div className="mt-4 flex min-h-[20px] items-center text-sm">
        {!sel && <span className="text-faint">Click any node to inspect it.</span>}
        {sel && (
          <span className="flex flex-wrap items-center gap-3">
            <span className="font-mono text-ink">{sel.library}</span>
            <span className="font-mono text-faint">{sel.version}</span>
            <Sev level={sel.risk_band} />
            <span className="text-dim">
              {sel.license} · ring {sel.ring} · priority {sel.risk_score}
            </span>
            {sel.ring > 1 && (
              <span className="text-info">arrived uninvited — nobody on the team chose this</span>
            )}
          </span>
        )}
      </div>
    </Panel>
  )
}
