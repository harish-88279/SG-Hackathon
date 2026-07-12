import React, { useRef, useState } from 'react'
import gsap from 'gsap'
import { sev, cx, GLOSSARY, useReveal, useCountUp } from '../lib.jsx'

/* ─────────────────────────────────────────────────────── Panel
   A pane of dark glass. It surfaces as you scroll to it, carries its own
   light, and a warm spotlight follows your cursor across it. */
export function Panel({ title, sub, actions, children, flush = false, className = '', delay = 0 }) {
  const [ref, inView] = useReveal()
  const track = (e) => {
    const r = e.currentTarget.getBoundingClientRect()
    e.currentTarget.style.setProperty('--mx', `${e.clientX - r.left}px`)
    e.currentTarget.style.setProperty('--my', `${e.clientY - r.top}px`)
  }
  return (
    <section
      ref={ref}
      onMouseMove={track}
      style={{ '--reveal-delay': `${delay}ms` }}
      className={cx('surface reveal spotlight relative overflow-hidden', inView && 'reveal-in', className)}
    >
      {/* one candle per pane. Barely there. */}
      <div className="pointer-events-none absolute -right-24 -top-24 h-56 w-56 rounded-full bg-sg/[0.035] blur-[70px]" />
      {(title || actions) && (
        <header className="relative flex items-start justify-between gap-6 px-6 pb-4 pt-5">
          <div className="min-w-0">
            {title && <h2 className="font-display text-md font-semibold tracking-tight text-ink">{title}</h2>}
            {sub && <p className="mt-1 max-w-[70ch] text-sm text-dim">{sub}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cx('relative', !flush && 'px-6 pb-6')}>{children}</div>
    </section>
  )
}

/* ─────────────────────────────────────────────────────── Sev
   A glowing dot and a word. The dot carries its own heat. */
export function Sev({ level, className = '' }) {
  const s = sev(level)
  return (
    <span className={cx('inline-flex items-center gap-1.5 text-micro uppercase', s.fg, className)}>
      <span
        className={cx('h-[5px] w-[5px] rounded-full', s.dot)}
        style={{ boxShadow: `0 0 10px 1px ${s.hex}` }}
      />
      {level}
    </span>
  )
}

/** For the rare thing that genuinely must shout. */
export function Alarm({ children }) {
  return (
    <span className="inline-flex animate-breathe items-center gap-1 rounded-xs bg-gradient-to-r from-crit to-[#ff7a3d] px-2 py-[3px] text-[10px] font-bold uppercase tracking-wide text-white shadow-[0_0_18px_-2px_rgba(255,93,93,.55)]">
      {children}
    </span>
  )
}

/** Neutral metadata. No colour — because it carries no signal. */
export function Meta({ children, tone }) {
  return (
    <span className={cx(
      'inline-flex items-center rounded-full border px-2 py-[2px] text-[10px] font-medium uppercase tracking-wide backdrop-blur-sm',
      tone === 'crit' ? 'border-crit/30 bg-crit/[0.07] text-crit'
        : tone === 'info' ? 'border-info/30 bg-info/[0.07] text-info'
        : 'border-line bg-ink/[0.03] text-dim'
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
        <span className="raised absolute bottom-full left-1/2 z-50 mb-2 w-[260px] -translate-x-1/2 px-3 py-2 text-xs font-normal normal-case leading-relaxed tracking-normal text-muted shadow-pop animate-pop">
          {body}
        </span>
      )}
    </span>
  )
}

/* ─────────────────────────────────────────────────────── Figure
   A number and its unit. It counts up into place. The workhorse. */
export function Figure({ value, of, label, tone, size = 'md' }) {
  const sizes = { sm: 'text-lg', md: 'text-2xl', lg: 'text-3xl', xl: 'text-4xl' }
  const tones = {
    crit: 'text-crit', high: 'text-high', med: 'text-med',
    low: 'text-low', ok: 'text-ok', info: 'text-info', ink: 'text-ink',
  }
  const shown = useCountUp(value)
  return (
    <div>
      <div className={cx('tnum font-semibold', sizes[size], tones[tone] || 'text-ink')}>
        {shown}
        {of != null && <span className="text-dim font-normal">/{of}</span>}
      </div>
      <div className="label mt-1.5">{label}</div>
    </div>
  )
}

/* ─────────────────────────────────────────────────────── controls
   Solid buttons are MAGNETIC: they lean toward the cursor and snap back
   with an elastic release. Small, physical, memorable. */
export function Btn({ children, kind = 'ghost', className = '', ...p }) {
  const ref = useRef(null)
  const magnet = kind === 'solid'
  const pull = (e) => {
    if (!magnet || !ref.current) return
    const r = ref.current.getBoundingClientRect()
    gsap.to(ref.current, {
      x: (e.clientX - r.left - r.width / 2) * 0.18,
      y: (e.clientY - r.top - r.height / 2) * 0.35,
      duration: 0.25, ease: 'power2.out',
    })
  }
  const release = () => {
    if (!magnet || !ref.current) return
    gsap.to(ref.current, { x: 0, y: 0, duration: 0.5, ease: 'elastic.out(1, .45)' })
  }
  const k = {
    solid: 'bg-gradient-to-b from-[#ff8b52] to-[#f26526] text-white shadow-glow hover:from-[#ffa470] hover:to-[#ff7a3d]',
    ghost: 'raised text-muted hover:text-ink hover:border-edge',
    bare:  'text-dim hover:text-ink',
  }[kind]
  return (
    <button
      ref={ref}
      onMouseMove={pull}
      onMouseLeave={release}
      className={cx(
        'inline-flex items-center justify-center gap-1.5 rounded-md px-3.5 py-1.5 text-sm font-medium',
        'transition-colors duration-150 disabled:opacity-40', k, className
      )}
      {...p}
    >
      {children}
    </button>
  )
}

export function Field({ className = '', ...p }) {
  return (
    <select
      className={cx(
        'raised h-8 cursor-pointer px-2.5 text-sm text-muted transition-colors hover:border-edge focus:border-edge focus:text-ink',
        className
      )}
      {...p}
    />
  )
}

/* ─────────────────────────────────────────────────────── Skeleton
   Never a spinner. A skeleton says "here is the shape of what is coming". */
export function Skeleton({ rows = 5, className = '' }) {
  return (
    <div className={cx('space-y-2.5', className)}>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="relative h-9 overflow-hidden rounded-md bg-ink/[0.035]">
          <div className="absolute inset-0 animate-sweep bg-gradient-to-r from-transparent via-ink/[0.05] to-transparent" />
        </div>
      ))}
    </div>
  )
}

export function Err({ error }) {
  return (
    <div className="rounded-md border border-crit/25 bg-crit/[0.07] px-4 py-3 text-sm text-crit backdrop-blur-md">
      {error}
    </div>
  )
}

export fu