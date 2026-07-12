import React, { useState } from 'react'
import { sev, cx, GLOSSARY } from '../lib.jsx'

/* ─────────────────────────────────────────────────────── Panel
   No shadows, no gradients. A hairline, a slightly lifted surface, and space.  */
export function Panel({ title, sub, actions, children, flush = false, className = '' }) {
  return (
    <section className={cx('panel animate-rise', className)}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-6 px-6 pb-4 pt-5">
          <div className="min-w-0">
            {title && <h2 className="font-display text-md font-semibold tracking-tight text-ink">{title}</h2>}
            {sub && <p className="mt-1 max-w-[70ch] text-sm text-dim">{sub}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={flush ? '' : 'px-6 pb-6'}>{children}</div>
    </section>
  )
}

/* ─────────────────────────────────────────────────────── Sev
   A dot and a word. Not a pill. Pills everywhere is what makes a UI look cheap. */
export function Sev({ level, className = '' }) {
  const s = sev(level)
  return (
    <span className={cx('inline-flex items-center gap-1.5 text-micro uppercase', s.fg, className)}>
      <span className={cx('h-[5px] w-[5px] rounded-full', s.dot)} />
      {level}
    </span>
  )
}

/** For the rare thing that genuinely must shout. */
export function Alarm({ children }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-xs bg-crit px-1.5 py-[3px] text-[10px] font-bold uppercase tracking-wide text-white">
      {children}
    </span>
  )
}

/** Neutral metadata. No colour — because it carries no signal. */
export function Meta({ children, tone }) {
  return (
    <span className={cx(
      'inline-flex items-center rounded-xs border px-1.5 py-[2px] text-[10px] font-medium uppercase tracking-wide',
      tone === 'crit' ? 'border-crit/25 text-crit'
        : tone === 'info' ? 'border-info/25 text-info'
        : 'border-line text-dim'
    )}>
      {children}
    </span>
  )
}

/* ─────────────────────────────────────────────────────── Term
   A dotted underline, not a "?" bubble. Reads like a footnote, not a chatbot. */
export function Term({ k, children, text }) {
  const [open, setOpen] = useState(false)
  const body = text || GLOSSARY[k]
  if (!body) return children
  return (
    <span
      className="relative cursor-help border-b border-dotted border-faint"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
    >
      {children}
      {open && (
        <span className="absolute bottom-full left-1/2 z-50 mb-2 w-[260px] -translate-x-1/2 rounded-md border border-edge bg-raised px-3 py-2 text-xs font-normal normal-case leading-relaxed tracking-normal text-muted shadow-pop animate-pop">
          {body}
        </span>
      )}
    </span>
  )
}

/* ─────────────────────────────────────────────────────── Figure
   A number and its unit. Big, tabular, tight. This is the workhorse. */
export function Figure({ value, of, label, tone, size = 'md' }) {
  const sizes = { sm: 'text-lg', md: 'text-2xl', lg: 'text-3xl', xl: 'text-4xl' }
  const tones = {
    crit: 'text-crit', high: 'text-high', med: 'text-med',
    low: 'text-low', ok: 'text-ok', info: 'text-info', ink: 'text-ink',
  }
  return (
    <div>
      <div className={cx('tnum font-semibold', sizes[size], tones[tone] || 'text-ink')}>
        {value}
        {of != null && <span className="text-dim font-normal">/{of}</span>}
      </div>
      <div className="label mt-1.5">{label}</div>
    </div>
  )
}

/* ─────────────────────────────────────────────────────── controls */
export function Btn({ children, kind = 'ghost', className = '', ...p }) {
  const k = {
    solid: 'btn-amber',
    ghost: 'bg-raised text-muted border border-line hover:border-edge hover:text-ink',
    bare:  'text-dim hover:text-ink',
  }[kind]
  return (
    <button
      className={cx('inline-flex items-center justify-center gap-1.5 rounded-md px-3.5 py-1.5 text-sm font-medium transition-all duration-150 disabled:opacity-40', k, className)}
      {...p}
    >
      {children}
    </button>
  )
}

export function Field({ className = '', ...p }) {
  return (
    <select
      className={cx('h-8 cursor-pointer rounded-md border border-line bg-raised px-2.5 text-sm text-muted transition-colors hover:border-edge focus:border-edge focus:text-ink', className)}
      {...p}
    />
  )
}

/* ─────────────────────────────────────────────────────── Skeleton
   Never a spinner. A spinner says "wait". A skeleton says "here is the shape
   of what is coming" — it is the difference between a toy and a product. */
export function Skeleton({ rows = 5, className = '' }) {
  return (
    <div className={cx('space-y-2.5', className)}>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="relative h-9 overflow-hidden rounded-md bg-raised">
          <div className="absolute inset-0 animate-sweep bg-gradient-to-r from-transparent via-white/[0.035] to-transparent" />
        </div>
      ))}
    </div>
  )
}

export function Err({ error }) {
  return (
    <div className="rounded-md border border-crit/25 bg-crit/[0.06] px-4 py-3 text-sm text-crit">
      {error}
    </div>
  )
}

export function Blank({ children = 'Nothing here.' }) {
  return <div className="py-16 text-center text-sm text-faint">{children}</div>
}

/* ─────────────────────────────────────────────────────── Rail
   A thin vertical meter. Replaces the ubiquitous chunky progress bar. */
export function Rail({ value, level, className = '' }) {
  return (
    <div className={cx('h-[3px] w-full overflow-hidden rounded-full bg-line', className)}>
      <div
        className={cx('h-full rounded-full transition-[width] duration-[900ms] ease-out', sev(level).dot)}
        style={{ width: `${Math.max(2, value)}%` }}
      />
    </div>
  )
}

/* ─────────────────────────────────────────────────────── Table primitives
   Full-bleed. No vertical rules. Rows separated by a hairline, nothing more. */
export const Table = ({ children }) => (
  <table className="w-full border-collapse text-base">{children}</table>
)
export const TH = ({ children, className = '' }) => (
  <th className={cx('label border-b border-line px-3 py-2.5 text-left font-medium', className)}>{children}</th>
)
export const TD = ({ children, className = '' }) => (
  <td className={cx('border-b border-line/70 px-3 py-3 align-middle', className)}>{children}</td>
)
export const TR = ({ children, onClick, className = '' }) => (
  <tr
    onClick={onClick}
    className={cx('transition-colors duration-100', onClick && 'cursor-pointer hover:bg-hover', className)}
  >
    {children}
  </tr>
)
