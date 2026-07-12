import React, { useEffect, useRef, useState } from 'react'
import gsap from 'gsap'
import { Search, ArrowRight, Check } from 'lucide-react'
import { api } from '../api.js'
import { sev, cx, Note } from '../lib.jsx'
import { Panel, Sev, Alarm, Meta, Figure, Skeleton, Err, Rail, Btn, Term } from '../components/ui.jsx'
import { Ring, Key } from '../components/Charts.jsx'
import Chain from '../components/Chain.jsx'
import EmberField from '../components/EmberField.jsx'

export default function Overview({ summary, cve, setCve, goto, openPalette }) {
  const [q, setQ] = useState(cve)
  const [data, setData] = useState(null)
  const [busy, setBusy] = useState(true)
  const [err, setErr] = useState(null)

  const run = async (id) => {
    if (!id?.trim()) return
    setBusy(true); setErr(null); setQ(id)
    try { setData(await api.cve(id.trim())) }
    catch (e) { setErr(e.message); setData(null) }
    finally { setBusy(false) }
  }

  useEffect(() => { run(cve) }, [cve])

  const st = summary.stats
  const t = st.by_risk_type || {}
  const ring = [
    { label: 'Direct vulnerability', value: t.vulnerable_dependency || 0,    color: '#ff5d5d' },
    { label: 'Hidden dependency',    value: t.transitive_vulnerability || 0, color: '#c9a6f7' },
    { label: 'Licence conflict',     value: t.license_conflict || 0,         color: '#ffa14d' },
    { label: 'Unmaintained',         value: t.unmaintained || 0,             color: '#f2c94c' },
    { label: 'Clean',                value: st.clean,                        color: '#5fcf9a' },
  ]

  const hero = useRef(null)
  useEffect(() => {
    if (!hero.current || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    const ctx = gsap.context(() => {
      gsap.fromTo('.hero-el',
        { opacity: 0, y: 22 },
        { opacity: 1, y: 0, duration: 0.5, stagger: 0.07, ease: 'power3.out' })
    }, hero)
    return () => ctx.revert()
  }, [])

  return (
    <div className="space-y-7">
      {/* ══════════════════════════════════════════ the question */}
      <section ref={hero} className="surface relative overflow-hidden animate-rise">
        {/* one warm light source, top-left. The ember behind the question. */}
        <div className="pointer-events-none absolute -left-40 -top-40 h-[420px] w-[420px] rounded-full bg-sg/[0.06] blur-[110px]" />
        <div className="pointer-events-none absolute -bottom-32 right-10 h-[280px] w-[280px] rounded-full bg-gold/[0.03] blur-[90px]" />

        {/* the live dependency web. It leans toward your cursor;
            the red ember pulsing inside it is the flaw nobody chose. */}
        <EmberField />

        <div className="relative grid gap-10 p-9 lg:grid-cols-[1fr_auto]">
          <div className="min-w-0 max-w-[58ch]">
            <p className="hero-el label mb-4 text-sg">December 2021 · four days to answer</p>
            <h2 className="hero-el font-display text-3xl font-semibold tracking-tight text-ink">
              A critical vulnerability just dropped.
            </h2>
            <h2 className="hero-el font-display text-3xl font-semibold tracking-tight">
              <span className="ember-text">Which of our applications are affected?</span>
            </h2>
            <p className="hero-el mt-5 text-base leading-[1.75] text-muted">
              Not one organisation could answer that quickly — not because Log4Shell was hard to understand,
              but because nobody knew what was actually <em className="not-italic text-ink">inside</em> their own
              software. Answered here by walking the dependency graph, in milliseconds, including through
              components nobody ever chose.
            </p>
          </div>

          <div className="flex w-full flex-col justify-center gap-2.5 lg:w-[340px]">
            <div className="hero-el group relative">
              <Search size={14} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-faint" />
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && run(q)}
                spellCheck={false}
                className="h-11 w-full rounded-md border border-line bg-black/30 pl-9 pr-3 font-mono text-md text-ink outline-none backdrop-blur-md transition-all placeholder:text-faint focus:border-sg/60 focus:shadow-[0_0_24px_-6px_rgba(255,122,61,.35)]"
              />
            </div>
            <div className="hero-el">
              <Btn kind="solid" onClick={() => run(q)} className="h-11 w-full animate-glowpulse text-base">
                Find the blast radius <ArrowRight size={14} />
              </Btn>
            </div>
            <button
              onClick={openPalette}
              className="hero-el flex items-center justify-center gap-2 py-1 text-sm text-faint transition-colors hover:text-muted"
            >
              or browse all {st.unique_cves} CVEs <kbd className="kbd">⌘K</kbd>
            </button>
          </div>
        </div>
      </section>

      {/* ══════════════════════════════════════════ result */}
      {busy && <div className="surface p-6"><Skeleton rows={6} /></div>}
      {err && <Err error={err} />}
      {!busy && data && <Blast d={data} total={summary.applications.length} />}

      {/* ══════════════════════════════════════════ estate */}
      <div className="grid gap-7 xl:grid-cols-[1.65fr_1fr]">
        <Panel
          title="Applications, by worst component"
          sub="Never by an average. Averaging is how one catastrophic flaw hides behind forty-nine healthy libraries."
          flush
        >
          <Note>
            An app is only as safe as the <em className="not-italic text-ink">worst</em> thing in it. Average the
            scores and a ten-out-of-ten emergency sitting among clean libraries comes out looking like a two — the
            dashboard glows green while the bank burns.
          </Note>

          <div className="mt-5">
            {summary.applications.map((a, i) => (
              <button
                key={a.app_id}
                onClick={() => goto('findings')}
                style={{ animationDelay: `${Math.min(i, 10) * 35}ms` }}
                className={cx(
                  'group flex w-full animate-rise items-center gap-5 px-6 py-3.5 text-left transition-all duration-200 hover:bg-ink/[0.04] hover:pl-7',
                  i !== 0 && 'border-t border-line/60'
                )}
              >
                <span
                  className={cx('h-6 w-[2.5px] shrink-0 rounded-full', sev(a.risk_band).dot)}
                  style={{ boxShadow: `0 0 10px ${sev(a.risk_band).hex}66` }}
                />

                <span className="min-w-0 flex-1">
                  <span className="flex items-center gap-2">
                    <span className="truncate text-base font-medium text-ink">{a.app_name}</span>
                    {a.handles_cardholder_data && <Meta tone="crit">card data</Meta>}
                    {a.internet_facing && <Meta>internet</Meta>}
                  </span>
                  <span className="mt-1 block text-sm text-dim">
                    <span className="text-muted">{a.at_risk_count}</span> of {a.total_dependencies} at risk
                    <span className="mx-1.5 text-faint">·</span>
                    <span className="text-info">{a.transitive_vuln_count}</span> hidden
                    <span className="mx-1.5 text-faint">·</span>
                    {a.license_conflict_count} legal
                  </span>
                </span>

                <span className="w-[92px] shrink-0">
                  <span className={cx('tnum block text-right text-md font-semibold', sev(a.risk_band).fg)}>
                    {a.risk_score}
                  </span>
                  <Rail value={a.risk_score} level={a.risk_band} className="mt-2" />
                </span>
              </button>
            ))}
          </div>
        </Panel>

        <Panel title="What we are carrying" sub="Every component, by its primary problem.">
          <div className="flex items-center gap-7">
            <Ring data={ring} center={{ value: st.at_risk, label: 'at risk' }} />
            <Key data={ring} total={st.total_dependencies} />
          </div>
          <div className="mt-6 border-t border-line pt-5">
            <Note>
              The <strong className="font-semibold text-ok">{st.suppressed_false_positives} false alarms we muted</strong>{' '}
              matter as much as what we found. A scanner that flags everything is technically perfect and completely
              useless — it gets switched off in week two.
            </Note>
          </div>
        </Panel>
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════ blast radius */
function Blast({ d, total }) {
  if (!d.found) {
    return (
      <div className="flex items-start gap-3.5 rounded-lg border border-ok/25 bg-ok/[0.06] px-6 py-5 backdrop-blur-md animate-rise">
        <Check size={17} className="mt-0.5 shrink-0 text-ok" />
        <div>
          <h3 className="text-md font-semibold text-ok">{d.cve_id} — not exposed</h3>
          <p className="mt-1 text-base text-muted">{d.message}</p>
        </div>
      </div>
    )
  }

  return (
    <section className="surface overflow-hidden animate-rise">
      {/* ── header ── */}
      <div className="flex flex-wrap items-start justify-between gap-6 border-b border-line px-8 py-6">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <h3 className="font-mono text-lg font-semibold text-ink">{d.cve_id}</h3>
            {d.name && <span className="text-md text-muted">{d.name}</span>}
            <Sev level={d.severity} />
            {d.known_exploited && <Alarm>exploited in the wild</Alarm>}
            {!d.patch_available && <Meta tone="crit">no patch exists</Meta>}
          </div>
          <p className="mt-3 max-w-[78ch] text-base leading-relaxed text-muted">{d.summary}</p>
        </div>

        <div className="shrink-0 text-right">
          <div className="tnum text-4xl font-semibold text-crit [text-shadow:0_0_32px_rgba(255,93,93,.45)]">{d.cvss_score}</div>
          <div className="label mt-1.5"><Term k="cvss">cvss</Term></div>
        </div>
      </div>

      {/* ── the number that matters ── */}
      <div className="grid gap-8 border-b border-line px-8 py-6 lg:grid-cols-[auto_1fr] lg:items-center">
        <div className="flex flex-wrap gap-x-10 gap-y-5">
          <Figure value={d.affected_app_count} of={total} label="apps affected" tone="crit" size="lg" />
          <Figure value={d.transitive_only_count} label="hidden only" tone="info" size="lg" />
          <Figure value={d.internet_facing_count} label="internet-facing" tone="high" size="lg" />
          <Figure value={d.cardholder_data_count} label="card data" tone="crit" size="lg" />
        </div>
        <p className="max-w-[62ch] text-base leading-[1.75] text-muted lg:border-l lg:border-line lg:pl-8">
          {d.headline}
        </p>
      </div>

      {/* ── the fix ── */}
      <div className={cx(
        'flex items-start gap-3 border-b border-line px-8 py-4 text-base',
        d.patch_available ? 'bg-ok/[0.04]' : 'bg-med/[0.04]'
      )}>
        {d.patch_available ? (
          <>
            <Check size={15} className="mt-[3px] shrink-0 text-ok" />
            <p className="text-muted">
              <strong className="font-semibold text-ok">One fix, whole estate. </strong>
              {d.single_fix || `Upgrade to ${d.patched_version}.`}
            </p>
          </>
        ) : (
          <p className="text-muted">
            <strong className="font-semibold text-med">There is no patch. </strong>
            You cannot fix this by bumping a version number. The library must be <em className="not-italic text-ink">replaced</em> —
            a project, not a ticket. Apply a compensating control today; the exposure stays open until it ships.
          </p>
        )}
      </div>

      {/* ── chains ── */}
      <div className="px-8 py-6">
        <div className="label mb-5">how it actually gets in</div>

        <div className="space-y-6">
          {d.applications.map((a, i) => (
            <div key={a.app_id}
                 style={{ animationDelay: `${Math.min(i, 8) * 45}ms` }}
                 className="grid animate-rise gap-5 lg:grid-cols-[1fr_auto] lg:items-start">
              <div className="min-w-0">
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <span className="text-base font-medium text-ink">{a.app_name}</span>
                  <Sev level={a.business_criticality} />
                  {a.handles_cardholder_data && <Meta tone="crit">card data</Meta>}
                  {a.internet_facing && <Meta>internet</Meta>}
                  {a.components.every((c) => c.dependency_type === 'transitive') && (
                    <Meta tone="info">nobody chose this</Meta>
                  )}
                </div>

                {a.components.map((c) => (
                  <div key={c.dependency_id} className="mb-3">
                    <Chain chain={c.chain} vuln={c.library} />
                    <p className="mt-2.5 text-sm text-dim">
                      {c.reachable
                        ? <><span className="text-crit">The broken code is actually run by this app.</span> The flaw is live.</>
                        : <><span className="text-ok">The broken code is never run here.</span> A liability, not an emergency.</>}
                    </p>
                  </div>
                ))}
              </div>

              <div className="shrink-0 text-right lg:w-[110px]">
                <div className={cx('tnum text-xl font-semibold',
                  a.max_priority >= 80 ? 'text-crit' : 'text-high')}>
                  {a.max_priority}
                </div>
                <div className="label mt-1"><Term k="priority">priority</Term></div>
                <div className="mt-2 truncate text-xs text-faint">{a.owner?.split('@')[0]}</div>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-7 border-t border-line pt-5">
          <Note accent>
            Look at those priority scores — they are all <em className="not-italic text-ink">different</em>, for the{' '}
            <em className="not-italic text-ink">same</em> flaw. That is the whole idea. The identical vulnerability is a
            five-alarm fire in the payments system and a scheduled chore in an internal document service. A tool that
            gives them the same number sends your engineers to the wrong fire.
          </Note>
        </div>
      </div>
    </section>
  )
}
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            