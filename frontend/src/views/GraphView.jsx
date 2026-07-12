import React, { useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api.js'
import { sev, cx, RISK_LABEL, Note } from '../lib.jsx'
import { Panel, Field, Btn, Sev, Skeleton, Blank } from '../components/ui.jsx'

/**
 * The dependency tree.
 *
 * The first version of this drew the estate as concentric orbits, on the theory that depth
 * ought to be radius. It was a nice theory. In practice it produced five hundred unlabelled
 * dots on a circle: you could see that something was wrong and never once see WHAT, because
 * a ring gives a label nowhere to live. A picture you cannot read is not a picture.
 *
 * So: columns. Depth is the x-axis, one column per hop. The application is the only thing in
 * column zero. Column one is code somebody on this team actually chose. Everything right of
 * that arrived uninvited, and the further right it sits, the fewer people knew it was there
 * at all. Labels now sit beside their node, horizontally, always on -- which is the entire
 * reason to prefer this layout to a prettier one.
 *
 * Three decisions do the real work:
 *
 *   IT DOES NOT DRAW EVERYTHING. Five hundred nodes is not a visualisation, it is a texture.
 *   The default view keeps only components that carry risk, plus the hops required to reach
 *   them -- because those hops ARE the answer to "how did this get in". Everything clean is
 *   one click away and, deliberately, not the first thing you see.
 *
 *   IT IS A TREE, NOT A HAIRBALL. We take a spanning tree from the application, so every
 *   component has exactly one drawn route home and the picture stays readable. The routes we
 *   dropped are not hidden -- they come back as faint dashed arcs, because a library
 *   reachable two ways must be fixed two ways, and concealing that is how a "patched"
 *   dependency quietly stays vulnerable.
 *
 *   THE TRACE. The searched CVE lights its path back to the application through every hop
 *   that carried it. That single red line is the whole argument of the product.
 */

const COL_W = 236
const ROW = 26
const PAD = { x: 40, y: 30 }
const LABEL_W = 200
const HEAD_H = 30

const RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, MINIMAL: 4, NONE: 5 }
const rank = (b) => (RANK[b] === undefined ? 5 : RANK[b])
const isRisky = (b) => rank(b) <= RANK.LOW
const clip = (s, n = 24) => (!s ? '' : s.length > n ? s.slice(0, n - 1) + '…' : s)
const push = (m, k, v) => { const a = m.get(k); if (a) a.push(v); else m.set(k, [v]) }

export default function GraphView({ summary, cve }) {
  const [appId, setAppId] = useState(summary.applications[0]?.app_id)
  const [hi, setHi] = useState(cve || summary.featured_cves?.[0]?.cve_id || '')
  const [showClean, setShowClean] = useState(false)
  const [data, setData] = useState(null)
  const [sel, setSel] = useState(null)
  const [hover, setHover] = useState(null)

  const [view, setView] = useState({ x: 0, y: 0, k: 1 })
  const drag = useRef(null)

  const load = async (highlight = hi) => {
    setData(null); setSel(null); setHover(null)
    const q = { app_id: appId }
    if (highlight && highlight.trim()) q.highlight_cve = highlight.trim()
    setData(await api.graph(q))
    setView({ x: 0, y: 0, k: 1 })
  }
  useEffect(() => { load() }, [appId])

  /* -- layout: spanning tree from the app, tidy y, x = depth -------------- */
  const L = useMemo(() => {
    if (!data) return null
    const appNode = data.nodes.find((n) => n.data.kind === 'application')
    if (!appNode) return null

    const N = new Map(data.nodes.map((n) => [n.data.id, n.data]))
    const out = new Map()
    for (const e of data.edges) {
      if (N.has(e.data.source) && N.has(e.data.target)) push(out, e.data.source, e.data.target)
    }

    const root = appNode.id !== undefined ? appNode.data.id : appNode.data.id
    const parent = new Map([[root, null]])
    const depth = new Map([[root, 0]])
    const kids = new Map()
    const extra = []
    const q = [root]
    while (q.length) {
      const u = q.shift()
      for (const v of out.get(u) || []) {
        if (!parent.has(v)) {
          parent.set(v, u); depth.set(v, depth.get(u) + 1); push(kids, u, v); q.push(v)
        } else if (parent.get(v) !== u) {
          extra.push([u, v])
        }
      }
    }

    // Keep a node if it carries risk, or if it is on the route to something that does.
    // That route is the story.
    const keep = new Set([root])
    if (showClean) {
      for (const id of parent.keys()) keep.add(id)
    } else {
      for (const [id, d] of N) {
        if (!parent.has(id)) continue
        if (d.kind === 'library' && (isRisky(d.risk_band) || d.highlighted)) {
          for (let c = id; c != null && !keep.has(c); c = parent.get(c)) keep.add(c)
        }
      }
    }

    const byWorst = (a, b) => {
      const A = N.get(a), B = N.get(b)
      const r = rank(A.risk_band) - rank(B.risk_band); if (r) return r
      const s = (B.risk_score || 0) - (A.risk_score || 0); if (s) return s
      return (A.library || '').localeCompare(B.library || '')
    }

    const Y = new Map()
    let cursor = 0
    const place = (n) => {
      const ch = (kids.get(n) || []).filter((c) => keep.has(c)).sort(byWorst)
      if (!ch.length) { Y.set(n, cursor); cursor += 1; return Y.get(n) }
      const ys = ch.map(place)
      const y = (ys[0] + ys[ys.length - 1]) / 2
      Y.set(n, y); return y
    }
    place(root)

    const pos = (id) => ({ x: PAD.x + depth.get(id) * COL_W, y: PAD.y + Y.get(id) * ROW })

    const nodes = [...keep].map((id) => ({ id, d: N.get(id), depth: depth.get(id), ...pos(id) }))
    const links = [...keep]
      .filter((id) => parent.get(id) != null && keep.has(parent.get(id)))
      .map((id) => ({ id, from: pos(parent.get(id)), to: pos(id), d: N.get(id) }))
    const dia = extra
      .filter(([u, v]) => keep.has(u) && keep.has(v))
      .map(([u, v]) => ({ key: u + '|' + v, from: pos(u), to: pos(v) }))

    const chain = (id) => { const p = []; for (let c = id; c != null; c = parent.get(c)) p.push(c); return p }
    const traced = new Set()
    for (const n of nodes) if (n.d.highlighted) for (const c of chain(n.id)) traced.add(c)

    const maxD = nodes.reduce((m, n) => Math.max(m, n.depth), 0)
    const counts = { total: 0, risky: 0, hidden: 0 }
    for (const n of nodes) {
      if (n.d.kind !== 'library') continue
      counts.total += 1
      if (isRisky(n.d.risk_band)) counts.risky += 1
      if (n.depth > 1) counts.hidden += 1
    }
    const allLibs = [...N.values()].filter((d) => d.kind === 'library').length

    return {
      nodes, links, dia, chain, traced, counts, maxD,
      h: PAD.y + Math.max(0, cursor - 1) * ROW + PAD.y,
      app: appNode.data,
      dropped: showClean ? 0 : allLibs - counts.total,
    }
  }, [data, showClean])

  const lit = useMemo(() => (hover && L ? new Set(L.chain(hover)) : null), [hover, L])

  const zoom = (f) => setView((v) => ({ ...v, k: Math.min(2, Math.max(0.5, v.k * f)) }))
  const reset = () => setView({ x: 0, y: 0, k: 1 })
  const down = (e) => { drag.current = { ...view, mx: e.clientX, my: e.clientY } }
  const move = (e) => {
    if (!drag.current) return
    const d = drag.current
    setView({ k: d.k, x: d.x + (e.clientX - d.mx), y: d.y + (e.clientY - d.my) })
  }
  const up = () => { drag.current = null }

  const edge = (a, b) => {
    const mx = (a.x + b.x) / 2
    return `M${a.x},${a.y} C${mx},${a.y} ${mx},${b.y} ${b.x},${b.y}`
  }

  return (
    <div className="space-y-4">
      <Panel
        title="How it got in"
        sub="Depth is the x-axis. Column one is code you chose; everything right of it arrived uninvited."
        flush
        actions={
          <div className="flex items-center gap-1.5">
            <Btn onClick={() => zoom(1 / 1.2)} className="h-8 w-8 justify-center p-0">&minus;</Btn>
            <Btn onClick={() => zoom(1.2)} className="h-8 w-8 justify-center p-0">+</Btn>
            <Btn onClick={reset} className="h-8">Fit</Btn>
          </div>
        }
      >
        {!data || !L ? <div className="p-6"><Skeleton rows={8} /></div> : (
          <>
            {/* the controls get a row of their own. Crammed into the header slot they
                overflowed, and an overflowing control is an unusable one. */}
            <div className="flex flex-wrap items-center gap-2 border-b border-line px-5 py-3">
              <label className="label mr-1 text-faint">Application</label>
              <select
                value={appId} onChange={(e) => setAppId(e.target.value)}
                className="h-9 min-w-[190px] rounded-lg border border-line bg-raised px-3 text-sm text-ink outline-none focus:border-amber/60"
              >
                {summary.applications.map((a) => (
                  <option key={a.app_id} value={a.app_id} className="bg-raised text-ink">
                    {a.app_name || a.name || a.app_id}
                  </option>
                ))}
              </select>

              <span className="mx-1 h-5 w-px bg-line" />

              <label className="label mr-1 text-faint">Trace</label>
              <Field
                value={hi} onChange={(e) => setHi(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && load(e.target.value)}
                placeholder="CVE-2021-44228" spellCheck={false}
                className="h-9 w-[180px] font-mono text-sm"
              />
              <Btn kind="solid" onClick={() => load()} className="h-9">Trace</Btn>

              <div className="ml-auto flex rounded-lg border border-line bg-raised p-0.5">
                {[['At risk', false], ['Everything', true]].map(([lbl, val]) => (
                  <button
                    key={lbl} onClick={() => setShowClean(val)}
                    className={cx('rounded-md px-3 py-1.5 text-xs transition-colors',
                      showClean === val ? 'bg-amber/15 text-amber' : 'text-dim hover:text-ink')}
                  >{lbl}</button>
                ))}
              </div>
            </div>

            {/* these numbers describe THIS PICTURE, not the estate */}
            <div className="flex flex-wrap items-center gap-2 border-b border-line px-5 py-3">
              <Chip n={L.counts.total} of="components drawn" />
              <Chip n={L.counts.risky} of="at risk" tone="text-crit" />
              <Chip n={L.counts.hidden} of="nobody chose" tone="text-amber" />
              <Chip n={L.maxD} of={L.maxD === 1 ? 'hop deep' : 'hops deep'} />
              {L.dropped > 0 && (
                <span className="ml-auto text-xs text-faint">
                  {L.dropped} clean components hidden{' · '}
                  <button onClick={() => setShowClean(true)}
                    className="text-dim underline decoration-dotted underline-offset-2 hover:text-ink">
                    show everything
                  </button>
                </span>
              )}
            </div>

            {L.counts.total === 0 ? (
              <div className="p-8">
                <Blank>Nothing in this application carries risk. Switch to &ldquo;Everything&rdquo; to see its clean tree.</Blank>
              </div>
            ) : (
              <div
                className="relative overflow-hidden bg-deep/40"
                style={{ height: HEAD_H + 10 + L.h * view.k + 14, cursor: drag.current ? 'grabbing' : 'grab' }}
                onMouseDown={down} onMouseMove={move}
                onMouseUp={up} onMouseLeave={() => { up(); setHover(null) }}
              >
                {/* Headers ride the SAME transform as the nodes. Anything else drifts. */}
                <div className="pointer-events-none absolute inset-x-0 top-0 z-10 h-[30px] overflow-hidden border-b border-line bg-surface/85 backdrop-blur">
                  {Array.from({ length: L.maxD + 1 }, (_, d) => (
                    <div key={d} className="absolute top-0 whitespace-nowrap py-2"
                      style={{ left: view.x + (PAD.x - 22 + d * COL_W) * view.k }}>
                      <span className="label text-[9.5px] text-faint">
                        {d === 0 ? 'the application' : d === 1 ? 'you chose this' : `hop ${d} · uninvited`}
                      </span>
                    </div>
                  ))}
                </div>

                <svg className="h-full w-full select-none">
                  <defs>
                    <filter id="gglow" x="-140%" y="-140%" width="380%" height="380%">
                      <feGaussianBlur stdDeviation="4" result="b" />
                      <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
                    </filter>
                  </defs>

                  <g transform={`translate(${view.x},${view.y + HEAD_H + 10}) scale(${view.k})`}>
                    {/* one band per hop, so a column is a place and not just a coincidence */}
                    {Array.from({ length: L.maxD + 1 }, (_, d) => (
                      <rect key={'b' + d} x={PAD.x - 22 + d * COL_W} y={-6} width={COL_W - 8} height={L.h}
                        rx={10} fill={d === 0 ? '#ff7a3d' : '#fffaf0'} opacity={d === 0 ? 0.035 : 0.015} />
                    ))}

                    {/* the routes the spanning tree could not draw */}
                    {L.dia.map((e) => (
                      <path key={e.key} d={edge(e.from, e.to)} fill="none" stroke="#847c6f"
                        strokeWidth="1" strokeDasharray="2 4" opacity={lit ? 0.05 : 0.18} />
                    ))}

                    {L.links.map((e) => {
                      const on = lit ? lit.has(e.id) : true
                      const hot = L.traced.size > 1 && L.traced.has(e.id)
                      return (
                        <path key={e.id} d={edge(e.from, e.to)} fill="none"
                          stroke={hot ? '#ff5d5d' : sev(e.d.risk_band).hex}
                          strokeWidth={hot ? 2 : 1.2}
                          opacity={on ? (hot ? 0.95 : isRisky(e.d.risk_band) ? 0.5 : 0.2) : 0.05}
                          filter={hot ? 'url(#gglow)' : undefined} />
                      )
                    })}

                    {L.nodes.map((n) => {
                      const on = lit ? lit.has(n.id) : true
                      if (n.d.kind === 'application') {
                        const w = Math.max(100, (n.d.label || '').length * 7.2 + 24)
                        return (
                          <g key={n.id} opacity={on ? 1 : 0.3}>
                            <rect x={n.x - 10} y={n.y - 13} rx={7} width={w} height={26}
                              fill="#1e1b18" stroke="#ff7a3d" strokeWidth="1.2" />
                            <text x={n.x + 2} y={n.y} dy=".33em" fill="#f2eee7"
                              style={{ fontSize: 11.5, fontWeight: 600 }}>{n.d.label}</text>
                          </g>
                        )
                      }
                      const hot = !!n.d.highlighted
                      const risky = isRisky(n.d.risk_band) || hot
                      const c = sev(n.d.risk_band).hex
                      return (
                        <g key={n.id} opacity={on ? 1 : 0.16} style={{ cursor: 'pointer' }}
                          onMouseEnter={() => setHover(n.id)}
                          onClick={(e) => { e.stopPropagation(); setSel(n.d) }}>
                          {hot && <circle cx={n.x} cy={n.y} r="9" fill={c} opacity=".22" filter="url(#gglow)" />}
                          <circle cx={n.x} cy={n.y} r={hot ? 5.5 : risky ? 4.5 : 3} fill={c}
                            stroke={sel && sel.id === n.id ? '#f2eee7' : 'none'} strokeWidth="1.5" />
                          <text x={n.x + 11} y={n.y} dy=".33em"
                            style={{ fontSize: 10.5, fontFamily: "'JetBrains Mono Variable', monospace" }}
                            fill={hot ? '#ff5d5d' : risky ? '#f2eee7' : '#847c6f'}>
                            {clip(n.d.library)}
                            <tspan fill="#5a5349">{'  '}{n.d.version}</tspan>
                          </text>
                        </g>
                      )
                    })}
                  </g>
                </svg>

                <div className="pointer-events-none absolute bottom-3 left-4 flex flex-wrap items-center gap-3 text-[10.5px] text-faint">
                  {[['#ff7a3d', 'app'], ['#ff5d5d', 'critical'], ['#ffa14d', 'high'],
                    ['#f2c94c', 'medium'], ['#82b4e8', 'low'], ['#5fcf9a', 'clean']].map(([h, l]) => (
                    <span key={l} className="flex items-center gap-1.5">
                      <i className="h-1.5 w-1.5 rounded-full" style={{ background: h }} />{l}
                    </span>
                  ))}
                  <span className="flex items-center gap-1.5 border-l border-line pl-3">
                    <i className="inline-block h-px w-4 border-t border-dashed border-dim" /> reachable two ways
                  </span>
                </div>
                <div className="pointer-events-none absolute bottom-3 right-4 text-[10.5px] text-faint">
                  drag to pan {'·'} hover to light a component's route home {'·'} click to inspect
                </div>
              </div>
            )}
          </>
        )}
      </Panel>

      {sel && <Inspect d={sel} onClose={() => setSel(null)} />}

      {L && L.traced.size > 1 && (
        <Note>
          The red line is the route <span className="font-mono text-ink">{hi}</span> took into{' '}
          <span className="text-ink">{L.app.label}</span>. Nobody chose the component at the end of it. They chose
          the one at the start, and everything after that came along for the ride {'—'} which is what a
          supply-chain vulnerability <em>is</em>, and why an inventory that stops at direct dependencies cannot
          see one.
        </Note>
      )}
    </div>
  )
}

function Chip({ n, of, tone = 'text-ink' }) {
  return (
    <span className="rounded-lg border border-line bg-raised/70 px-2.5 py-1 text-xs text-dim">
      <b className={cx('tnum font-semibold', tone)}>{n}</b> {of}
    </span>
  )
}

function Inspect({ d, onClose }) {
  return (
    <Panel
      title={<span className="font-mono">{d.library} <span className="text-dim">{d.version}</span></span>}
      sub={d.depth > 1
        ? `Reached at hop ${d.depth} — nobody chose this directly`
        : 'A direct dependency — somebody on the team chose this'}
      actions={<Btn onClick={onClose} className="h-8">Close</Btn>}
    >
      <div className="grid gap-5 sm:grid-cols-4">
        <Cell k="Risk band"><Sev level={d.risk_band} /></Cell>
        <Cell k="Risk score">
          <span className="tnum text-lg font-semibold text-ink">{Math.round(d.risk_score || 0)}</span>
        </Cell>
        <Cell k="Why"><span className="text-sm text-ink">{RISK_LABEL[d.risk_type] || 'Clean'}</span></Cell>
        <Cell k="Licence"><span className="font-mono text-sm text-ink">{d.license}</span></Cell>
      </div>
    </Panel>
  )
}

const Cell = ({ k, children }) => (
  <div><div className="label mb-1.5">{k}</div>{children}</div>
)
