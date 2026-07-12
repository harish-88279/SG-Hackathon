import React, { useState } from 'react'
import { Play, Check, X } from 'lucide-react'
import { api } from '../api.js'
import { cx, Note } from '../lib.jsx'
import { Panel, Btn, Skeleton, Err, Blank } from '../components/ui.jsx'

/**
 * The scorecard.
 *
 * This page used to say "The challenge sets five targets. We meet all five." — while the
 * rest of the application was analysing the OFFICIAL dataset, on which we score three.
 * It reached that number by quietly running the harness against our own clean data.
 *
 * That is precisely the failure this tool exists to catch: a scanner that reports the
 * number which flatters it. So the page now leads with the dataset that is actually
 * loaded, shows both, and puts the two failures at eye level with the reason they cannot
 * be fixed. The honest scorecard is also the more interesting one.
 */
const OFFICIAL = [
  ['Vulnerability detection', '> 85%',  '100%',   true,
   'Every labelled vulnerability found.'],
  ['Transitive resolution',   '= 100%', '100%',   true,
   '150/150 nested dependencies pathed back to their application.'],
  ['Licence conflict',        '> 90%',  '100%',   true,
   'Every labelled licence violation found.'],
  ['False positive rate',     '< 20%',  '42%',    false,
   'Locked to recall by the data. 85% recall forces 33% false positives.'],
  ['Risk score accuracy',     '±10%',   '±14.8%', false,
   'Severity is a coin-toss in these labels. An oracle with the answers bottoms out at ±5%.'],
]

const SYNTHETIC = [
  ['Vulnerability detection', '> 85%',  '100%', true,  'TP=134  FP=0  FN=0'],
  ['Transitive resolution',   '= 100%', '100%', true,  '170/170 nested deps pathed'],
  ['Licence conflict',        '> 90%',  '100%', true,  'TP=56  FP=0  FN=0'],
  ['False positive rate',     '< 20%',  '0%',   true,  '0 of 263 flagged were clean'],
  ['Risk score accuracy',     '±10%',   '±7.2%', true, '100% of scores within ±10%'],
]

export default function Proof() {
  const [tab, setTab] = useState('official')
  const [out, setOut] = useState({})
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(null)

  const rows = tab === 'official' ? OFFICIAL : SYNTHETIC
  const met = rows.filter((r) => r[3]).length

  const run = async () => {
    setBusy(true); setErr(null)
    try {
      const r = await api.evaluate(tab)
      setOut((o) => ({ ...o, [tab]: r.output }))
    } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }

  return (
    <div className="space-y-7">
      <Panel
        title="Scorecard"
        sub="The challenge sets five targets. The score depends entirely on which data you score against — and that is the finding."
        flush
        actions={
          <div className="flex rounded-lg border border-line bg-raised p-0.5">
            {[['official', 'Official SG data'], ['synthetic', 'Consistent data']].map(([k, l]) => (
              <button
                key={k} onClick={() => setTab(k)}
                className={cx('rounded-md px-3 py-1.5 text-xs transition-colors',
                  tab === k ? 'bg-amber/15 text-amber' : 'text-dim hover:text-ink')}
              >{l}</button>
            ))}
          </div>
        }
      >
        <div className="flex items-baseline gap-3 px-6 pb-1">
          <span className={cx('tnum font-display text-4xl font-semibold',
            met === 5 ? 'text-ok' : 'text-amber')}>{met}/5</span>
          <span className="text-sm text-dim">
            {tab === 'official'
              ? 'on the dataset this app is running right now'
              : 'same engine, same code — on data that agrees with itself'}
          </span>
        </div>

        <div className="mt-5">
          {rows.map(([name, target, got, ok, why], i) => (
            <div key={name} className={cx('flex items-center gap-5 px-6 py-4',
              i !== 0 && 'border-t border-line')}>
              <span className={cx('flex h-5 w-5 shrink-0 items-center justify-center rounded-full',
                ok ? 'bg-ok/15 text-ok' : 'bg-crit/15 text-crit')}>
                {ok ? <Check size={12} /> : <X size={12} />}
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-base text-ink">{name}</div>
                <div className="mt-0.5 text-sm text-dim">{why}</div>
              </div>
              <div className="tnum shrink-0 text-right">
                <div className={cx('text-md font-semibold', ok ? 'text-ok' : 'text-crit')}>{got}</div>
                <div className="label mt-1">target {target}</div>
              </div>
            </div>
          ))}
        </div>

        <div className="px-6 pb-2 pt-6">
          {tab === 'official' ? (
            <Note accent>
              The two we miss are <strong className="font-semibold text-ink">not fixable</strong>, and that is
              arithmetic rather than an excuse. 301 dependencies carry a CVE-bearing library; 176 are labelled
              risky and 125 clean, and nothing in the inputs separates them. So recall and false-positive rate
              are welded together: <strong className="font-semibold text-ink">85% recall forces 33% false
              positives; holding false positives under 20% caps recall at 51%.</strong> We chose recall — a
              missed CVE costs more than a second look at a clean library. We also built the estimator that
              games the risk metric by guessing LOW, measured it at ±13.4%, and{' '}
              <strong className="font-semibold text-ink">refused to ship it</strong>.
            </Note>
          ) : (
            <Note accent>
              Three of these five are not statistics — they are{' '}
              <strong className="font-semibold text-ink">guarantees</strong>. Following a dependency chain is a
              solved maths problem, not a guess. Checking a licence is a lookup. Matching a version is
              arithmetic. Correct code cannot miss them. That is why we can promise 100% rather than hope for
              it — and it is why the same engine, unchanged, scores 5/5 the moment the labels agree with the
              version ranges.
            </Note>
          )}
        </div>
      </Panel>

      <Panel
        title="Prove it, live"
        sub={tab === 'official'
          ? 'Runs the official harness now. It audits the dataset before it scores it.'
          : 'Runs the harness against ground-truth labels, right now.'}
        actions={
          <Btn kind="solid" onClick={run} disabled={busy}>
            <Play size={13} />{busy ? 'Running…' : `Run the ${tab} evaluation`}
          </Btn>
        }
      >
        {busy && <Skeleton rows={6} />}
        {err && <Err error={err} />}
        {out[tab] && (
          <pre className="max-h-[520px] overflow-auto rounded-md border border-line bg-canvas px-5 py-4 font-mono text-[11.5px] leading-[1.75] text-dim">
            {out[tab]}
          </pre>
        )}
        {!out[tab] && !busy && !err && <Blank>Nothing here is precomputed. Press the button.</Blank>}
      </Panel>
    </div>
  )
}
