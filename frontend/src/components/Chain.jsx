import React from 'react'
import { cx } from '../lib.jsx'

/**
 * The signature element of this product.
 *
 * Every other tool renders a dependency path as a string of text with arrows.
 * We draw it as an actual chain — nodes on a rail, the vulnerable one blown out
 * at the end. The visual DISTANCE from the application to the red node IS the
 * argument: that gap is why nobody found Log4Shell for four days.
 */
export default function Chain({ chain, vuln, compact = false }) {
  if (!chain) {
    return <span className="text-sm text-faint">direct dependency — no chain</span>
  }

  const hops = chain.split(' -> ').map((h) => {
    const at = h.lastIndexOf('@')
    return at > 0 ? { name: h.slice(0, at), ver: h.slice(at + 1) } : { name: h, ver: null }
  })

  return (
    <ol className={cx('flex flex-wrap items-stretch', compact ? 'gap-0' : 'gap-0')}>
      {hops.map((h, i) => {
        const isApp = i === 0
        const isVuln = vuln && h.name === vuln
        const short = h.name.includes(':') ? h.name.split(':').pop() : h.name

        return (
          <li key={i} className="flex items-stretch">
            {i > 0 && (
              <div className="flex items-center px-2" aria-hidden>
                <svg width="20" height="9" viewBox="0 0 20 9" className={isVuln ? 'text-crit' : 'text-faint'}>
                  <path d="M0 4.5h14" stroke="currentColor" strokeWidth="1" strokeDasharray={isVuln ? '0' : '2 2'} />
                  <path d="M13 1.5l4 3-4 3" stroke="currentColor" strokeWidth="1" fill="none" />
                </svg>
              </div>
            )}

            <div
              className={cx(
                'flex flex-col justify-center rounded-md border px-2.5 py-1.5 backdrop-blur-sm transition-colors',
                isApp   && 'border-low/35 bg-low/[0.08]',
                isVuln  && 'border-crit/45 bg-crit/[0.1] shadow-[0_0_20px_-4px_rgba(255,93,93,.4)]',
                !isApp && !isVuln && 'border-line bg-ink/[0.035]'
              )}
            >
              <span className={cx(
                'font-mono text-[11.5px] leading-none',
                isApp ? 'font-semibold text-low' : isVuln ? 'font-semibold text-crit' : 'text-muted'
              )}>
                {short}
              </span>
              {h.ver && (
                <span className={cx('mt-1 font-mono text-[9.5px] leading-none', isVuln ? 'text-crit/60' : 'text-faint')}>
                  {h.ver}
                </span>
              )}
              {!compact && (
                <span className={cx('mt-1 text-[8.5px] uppercase leading-none tracking-[0.09em]',
                  isApp ? 'text-low/60' : isVuln ? 'text-crit/70' : 'text-faint')}>
                  {isApp ? 'your app' : isVuln ? 'the flaw' : `depth ${i}`}
                </span>
              )}
     