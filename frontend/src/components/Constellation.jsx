import React, { useMemo } from 'react'

/**
 * The hero's dependency constellation.
 *
 * It is decorative, and it is also the argument: a scatter of components, most of them
 * quiet, a few of them burning, wired together by links nobody drew on purpose. That is
 * what a dependency tree actually looks like from above — and it is why "which apps are
 * affected?" is a hard question.
 *
 * Deterministic (seeded), so it never flickers between renders.
 */
export default function Constellation({ width = 520, height = 300 }) {
  const { nodes, links } = useMemo(() => {
    let seed = 20260712
    const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff

    const N = 58
    const nodes = Array.from({ length: N }, (_, i) => {
      const r = 0.18 + rnd() * 0.82
      const t = rnd() * Math.PI * 2
      const heat = rnd()
      return {
        id: i,
        x: width / 2 + Math.cos(t) * r * (width * 0.46),
        y: height / 2 + Math.sin(t) * r * (height * 0.46),
        rr: 1.1 + rnd() * 2.4,
        // most components are fine. A handful are not. That ratio is the point.
        c: heat > 0.93 ? '#ff5d5d' : heat > 0.84 ? '#ff7a3d' : heat > 0.74 ? '#ffc46b' : '#6b625a',
        o: 0.25 + rnd() * 0.75,
      }
    })

    const links = []
    for (let i = 0; i < N; i++) {
      for (let j = i + 1; j < N; j++) {
        const d = Math.hypot(nodes[i].x - nodes[j].x, nodes[i].y - nodes[j].y)
        if (d < 62 && links.length < 74) links.push({ a: nodes[i], b: nodes[j], d })
      }
    }
    return { nodes, links }
  }, [width, height])

  return (
    <svg
      width={width} height={height} viewBox={`0 0 ${width} ${height}`}
      className="pointer-events-none select-none" aria-hidden
    >
      <defs>
        <radialGradient id="cfade" cx="50%" cy="50%">
          <stop offset="55%" stopColor="#fff" stopOpacity="1" />
          <stop offset="100%" stopColor="#fff" stopOpacity="0" />
        </radialGradient>
        <mask id="cmask">
          <rect width={width} height={height} fill="url(#cfade)" />
        </mask>
      </defs>

      <g mask="url(#cmask)">
        {links.map((l, i) => (
          <line
            key={i}
            x1={l.a.x} y1={l.a.y} x2={l.b.x} y2={l.b.y}
            stroke="#f2eee7" strokeOpacity={0.07 * (1 - l.d / 62)} strokeWidth={0.7}
          />
        ))}
        {nodes.map((n) => (
          <circle key={n.id} cx={n.x} cy={n.y} r={n.rr} fill={n.c} fillOpacity={n.o} />
        ))}
      </g>
    </svg>
  )
}
