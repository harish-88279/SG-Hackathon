import React from 'react'
import { cx } from '../lib.jsx'

/* Hand-drawn SVG. Thin strokes, no fills, no gridlines, no legends inside the
   plot. Maximum data, minimum ink — a project about dependency bloat has no
   business shipping a 200 kB charting library. */

export function Ring({ data, size = 168, thickness = 10, center }) {
  const total = data.reduce((s, d) => s + d.value, 0) || 1
  const r = (size - thickness) / 2
  const C = 2 * Math.PI * r
  const GAP = 2.5      // a real gap between arcs. Touching arcs look like a pie chart.
  let offset = 0

  return (
    <div className="relative grid shrink-0 place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90 overflow-visible">
        {data.map((d, i) => {
          const len = Math.max((d.value / total) * C - GAP, 0)
          const el = (
            <circle
              key={i} cx={size / 2} cy={size / 2} r={r} fill="none"
              stroke={d.color} strokeWidth={thickness} strokeLinecap="butt"
              strokeDasharray={`${len} ${C - len}`} strokeDashoffset={-offset}
              className="transition-all duration-1000 ease-out"
            />
          )
          offset += len + GAP
          return el
        })}
      </svg>
      {center && (
        <div className="absolute grid place-items-center">
          <div className="tnum text-xl font-semibold text-ink">{center.value}</div>
          <div className="label mt-1">{center.label}</div>
        </div>
      )}
    </div>
  )
}

export function Key({ data, total }) {
  return (
    <ul className="min-w-0 flex-1 space-y-2.5">
      {data.map((d) => (
        <li key={d.label} className="group flex items-center gap-3">
          <span className="h-2 w-2 shrink-0 rounded-[1px]" style={{ background: d.color }} />
          <span className="flex-1 truncate text-sm text-muted">{d.label}</span>
          <span className="tnum text-sm font-medium text-ink">{d.value}</span>
          {total ? (
            <span className="tnum w-9 text-right text-xs text-faint">
              {Math.round((d.value / total) * 100)}%
            </span>
          ) : null}
        </li>
      ))}
    </ul>
  )
}

export function Bars({ rows, color = '#8b7ff0', fmt = (v) => v.toFixed(3) }) {
  const max = Math.max(...rows.map((r) => r.value), 1e-9)
  return (
    <ul className="space-y-2">
      {rows.map((r) => (
        <li key={r.label} className="flex items-center gap-3">
          <span className="w-[136px] shrink-0 truncate font-mono text-[11px] text-dim">{r.label}</span>
          <span className="h-[3px] flex-1 overflow-hidden rounded-full bg-line">
            <span
              className="block h-full rounded-full transition-[width] duration-1000 ease-out"
              style={{ width: `${(r.value / max) * 100}%`, background: color }}
            />
          </span>
          <span className="tnum w-11 shrink-0 text-right text-xs text-faint">{fmt(r.value)}</span>
        </li>
      ))}
    </ul>
  )
}

/** Two scores, one arc each, shown as a single dial. The gap between them IS the story. */
export function Dial({ value, label, note, color = '#f4485f', size = 96 }) {
  const r = (size - 7) / 2
  const C = 2 * Math.PI * r
  const dash = (Math.min(value, 100) / 100) * C
  return (
    <div className="flex flex-col items-center">
      <div className="relative grid place-items-center" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1e1e23" strokeWidth={5} />
          <circle
            cx={size / 2} cy={size / 2} r={r} fill="none"
            stroke={color} strokeWidth={5} strokeLinecap="round"
            strokeDasharray={`${dash} ${C - dash}`}
            className="transition-all duration-[1100ms] ease-out"
          />
        </svg>
        <span className="tnum absolute text-lg font-semibold text-ink">{value.toFixed(0)}</span>
      </div>
      <div className="label mt-2.5">{label}</div>
      {note && <div className="mt-0.5 text-[10.5px] text-faint">{note}</div>}
    </div>
  )
}
