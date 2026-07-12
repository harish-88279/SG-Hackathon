import React from 'react'
import { api } from '../api.js'
import { Note, useAsync, cx } from '../lib.jsx'
import { Panel, Skeleton, Err, Figure, Table, TH, TD, TR } from '../components/ui.jsx'
import { Bars } from '../components/Charts.jsx'

export default function Intelligence() {
  const cl = useAsync(api.clusters, [])
  const ml = useAsync(api.model, [])
  const co = useAsync(api.correlation, [])

  return (
    <div className="space-y-7">
      <div className="grid gap-7 xl:grid-cols-2">
        {/* ═══════════════════════════ archetypes */}
        <Panel title="Risk archetypes" sub="263 findings are not 263 problems. They are a few repeating patterns." flush>
          <div className="px-6">
            <Note>
              Rather than handing you hundreds of tickets, we group findings by what they actually have in common.
              Each group becomes <strong className="font-semibold text-ink">one campaign, one owner, one decision</strong> —
              the difference between a report and a plan.
            </Note>
          </div>
          {cl.loading && <div className="px-6 pb-6 pt-5"><Skeleton rows={4} /></div>}
          {cl.error && <div className="px-6 pb-6"><Err error={cl.error} /></div>}
          <div className="mt-5">
            {cl.data?.clusters?.map((c, i) => (
              <div key={c.cluster_id}
                   style={{ animationDelay: `${i * 45}ms` }}
                   className={cx('animate-rise px-6 py-4 transition-colors hover:bg-ink/[0.03]', i !== 0 && 'border-t border-line')}>
                <div className="flex items-baseline justify-between gap-3">
                  <h3 className="text-base font-medium text-ink">{c.name}</h3>
                  <span className="tnum shrink-0 text-sm text-dim">{c.size}</span>
                </div>
                <p className="mt-1.5 text-sm leading-relaxed text-muted">{c.remediation_strategy}</p>
                <p className="mt-2 truncate font-mono text-[11px] text-faint">{c.example_components.join('  ·  ')}</p>
              </div>
            ))}
          </div>
        </Panel>

        {/* ═══════════════════════════ model */}
        <Panel title="Early warning" sub="A second opinion, deliberately blind to the vulnerability database.">
          <Note accent>
            Our rules can only find bugs that are <em className="not-italic text-ink">already known</em>. So we also
            trained a model that never looks at the bug list at all — it studies the{' '}
            <strong className="font-semibold text-ink">shape</strong> of a component: how old, how abandoned, how
            deeply buried, how exposed. When the rules say "fine" and the model says "dangerous", you are looking at
            something that looks exactly like the components that get breached.{' '}
            <strong className="font-semibold text-crit">Log4j was on that list in November 2021 — before any CVE existed.</strong>
          </Note>

          {ml.loading && <div className="pt-5"><Skeleton rows={5} /></div>}
          {ml.error && <Err error={ml.error} />}
          {ml.data && (
            <>
              <div className="mt-6 flex gap-9 border-y border-line py-5">
                <Figure size="sm" tone="ok"   value={(ml.data.report.roc_auc * 100).toFixed(1) + '%'} label="roc-auc" />
                <Figure size="sm"             value={(ml.data.report.precision * 100).toFixed(1) + '%'} label="precision" />
                <Figure size="sm"             value={(ml.data.report.recall * 100).toFixed(1) + '%'} label="recall" />
                <Figure size="sm" tone="info" value={ml.data.report.n_test} label="held out" />
              </div>

              <div className="label mb-3 mt-5">what the model keys on</div>
              <Bars rows={ml.data.report.feature_importance.slice(0, 6).map((f) => ({ label: f.feature, value: f.importance }))} />

              {ml.data.divergences?.early_warning?.length > 0 && (
                <>
                  <div className="label mb-3 mt-6">no known bug — but the profile of one</div>
                  <ul className="space-y-2.5">
                    {ml.data.divergences.early_warning.slice(0, 4).map((e) => (
                      <li key={e.dependency_id} className="border-l border-info/40 pl-3.5">
                        <div className="flex items-baseline gap-2">
                          <span className="tnum text-sm font-semibold text-info">p={e.model_risk_probability}</span>
                          <span className="truncate font-mono text-sm text-muted">{e.library}</span>
                        </div>
                        <div className="mt-0.5 text-xs text-faint">{e.why}</div>
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </>
          )}
        </Panel>
      </div>

      {/* ═══════════════════════════ leverage */}
      <Panel title="Fix by leverage" sub="Patching the same library ten times in ten repos is ten times the work for the same outcome." flush>
        {co.loading && <div className="px-6 pb-6"><Skeleton rows={6} /></div>}
        {co.error && <div className="px-6 pb-6"><Err error={co.error} /></div>}
        {co.data && (
          <>
            <div className="px-6"><Note>{co.data.correlation.interpretation}</Note></div>
            <div className="mt-5 px-3 pb-3">
              <Table>
                <thead>
                  <tr>
                    <TH>component</TH>
                    <TH className="w-[60px]">apps</TH>
                    <TH>exposure</TH>
                    <TH>one fix clears</TH>
                    <TH className="w-[92px] !text-right">leverage</TH>
                  </tr>
                </thead>
                <tbody>
                  {co.data.correlation.shared_components.slice(0, 12).map((s) => (
                    <TR key={s.library}>
                      <TD>
                        <span className="font-mono text-sm text-ink">{s.library}</span>
                        {s.version_fragmentation > 1 && (
                          <span className="ml-2 text-xs text-faint">{s.version_fragmentation} versions</span>
                        )}
                      </TD>
                      <TD className="tnum text-sm text-muted">{s.affected_app_count}</TD>
                      <TD className="text-sm text-dim">
                        {[
                          s.internet_facing_apps && `${s.internet_facing_apps} internet`,
                          s.cardholder_data_apps && `${s.cardholder_data_apps} card`,
                          s.transitive_in && `${s.transitive_in} hidden`,
                        ].filter(Boolean).join(' · ') || '—'}
                      </TD>
                      <TD className="max-w-[380px] text-sm text-dim">{s.one_fix_clears}</TD>
                      <TD className="tnum text-right text-sm font-semibold text-high">{s.leverage_score}</TD>
                    </TR>
               