/* SBOMGuard — dashboard logic. Vanilla JS, no build step. */

const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const api = async (p, o) => (await fetch(p, o)).json();
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

const bandColor = (b) => ({
  CRITICAL: 'var(--red)', HIGH: 'var(--orange)', MEDIUM: 'var(--yellow)',
  LOW: 'var(--blue)', MINIMAL: 'var(--green)', SUPPRESSED: 'var(--dim)',
}[b] || 'var(--dim)');

const badge = (b) => `<span class="badge b-${String(b).toLowerCase()}">${esc(b)}</span>`;

const RISK_LABEL = {
  vulnerable_dependency: 'Direct vulnerability',
  transitive_vulnerability: 'Transitive vulnerability',
  license_conflict: 'License conflict',
  unmaintained: 'Unmaintained',
  none: 'Clean',
};

let STATE = { summary: null, apps: [] };

/* ================================================================= tabs */
$$('.tab').forEach(t => t.onclick = () => {
  $$('.tab').forEach(x => x.classList.remove('active'));
  $$('.panel').forEach(x => x.classList.remove('active'));
  t.classList.add('active');
  $('#' + t.dataset.tab).classList.add('active');
  LOADERS[t.dataset.tab]?.();
});

/* ================================================================= boot */
(async function boot() {
  const s = await api('/api/summary');
  STATE.summary = s;
  STATE.apps = s.applications;

  const st = s.stats;
  $('#headerStats').innerHTML = `
    <div class="hstat"><b>${st.total_dependencies}</b><span>components</span></div>
    <div class="hstat"><b style="color:var(--red)">${st.at_risk}</b><span>at risk</span></div>
    <div class="hstat"><b style="color:var(--orange)">${st.unique_cves}</b><span>CVEs</span></div>
    <div class="hstat"><b style="color:var(--purple)">${st.known_exploited_cves}</b><span>exploited</span></div>
    <div class="hstat"><b style="color:var(--green)">${st.suppressed_false_positives}</b><span>FPs suppressed</span></div>`;

  renderApps();
  renderDonut();
  populateSelects();
  loadCVE('CVE-2021-44228');   // land on the money shot
})();

/* ================================================================= war room */
function renderApps() {
  $('#appRanking').innerHTML = STATE.apps.map(a => `
    <div class="app-row" data-app="${esc(a.app_id)}">
      <div>
        <div class="app-name">
          ${esc(a.app_name)} ${badge(a.risk_band)}
          ${a.internet_facing ? '<span class="badge b-low">internet</span>' : ''}
          ${a.handles_cardholder_data ? '<span class="badge b-critical">PCI</span>' : ''}
        </div>
        <div class="app-meta">
          ${a.at_risk_count}/${a.total_dependencies} at risk &middot;
          ${a.transitive_vuln_count} hidden transitive &middot;
          ${a.license_conflict_count} license &middot; ${esc(a.team || '')}
        </div>
      </div>
      <div class="app-score">
        <b style="color:${bandColor(a.risk_band)}">${a.risk_score}</b>
        <div class="bar"><i style="width:${a.risk_score}%;background:${bandColor(a.risk_band)}"></i></div>
      </div>
    </div>`).join('');

  $$('.app-row').forEach(r => r.onclick = () => {
    $('#filterApp').value = r.dataset.app;
    $$('.tab').forEach(x => x.classList.remove('active'));
    $$('.panel').forEach(x => x.classList.remove('active'));
    $('[data-tab="queue"]').classList.add('active');
    $('#queue').classList.add('active');
    loadQueue();
  });
}

function renderDonut() {
  const t = STATE.summary.stats.by_risk_type;
  const clean = STATE.summary.stats.clean;
  const rows = [
    ['Direct vulnerability', t.vulnerable_dependency || 0, '#ff4d5e'],
    ['Transitive vulnerability', t.transitive_vulnerability || 0, '#a78bfa'],
    ['License conflict', t.license_conflict || 0, '#ff9640'],
    ['Unmaintained', t.unmaintained || 0, '#ffd23f'],
    ['Clean', clean, '#3ddc84'],
  ];
  new Chart($('#riskDonut'), {
    type: 'doughnut',
    data: {
      labels: rows.map(r => r[0]),
      datasets: [{
        data: rows.map(r => r[1]),
        backgroundColor: rows.map(r => r[2]),
        borderColor: '#151a26', borderWidth: 3,
      }],
    },
    options: {
      cutout: '62%',
      plugins: { legend: { display: false } },
      maintainAspectRatio: false,
    },
  });
  $('#riskLegend').innerHTML = rows.map(r =>
    `<span><i style="background:${r[2]}"></i>${r[0]} <b>${r[1]}</b></span>`).join('');
}

/* ---- THE demo ---- */
$('#cveGo').onclick = () => loadCVE($('#cveInput').value);
$('#cveInput').onkeydown = (e) => { if (e.key === 'Enter') loadCVE(e.target.value); };
$$('.chip').forEach(c => c.onclick = (e) => {
  e.preventDefault();
  $('#cveInput').value = c.dataset.cve;
  loadCVE(c.dataset.cve);
});

async function loadCVE(cve) {
  if (!cve || !cve.trim()) return;
  $('#cveInput').value = cve.trim();
  $('#cveResult').innerHTML = '<div class="loading">Traversing the dependency graph&hellip;</div>';

  const d = await api('/api/cve/' + encodeURIComponent(cve.trim()));

  if (!d.found) {
    $('#cveResult').innerHTML = `
      <div class="blast clean">
        <div class="blast-title">${esc(d.cve_id)} &mdash; not exposed</div>
        <p class="blast-sum">${esc(d.message)}</p>
      </div>`;
    return;
  }

  const chains = d.applications.map(a => `
    <div class="chain-app-row">
      <div style="flex:1;min-width:0">
        <div style="font-weight:600;font-size:13.5px;margin-bottom:5px">
          ${esc(a.app_name)} ${badge(a.business_criticality)}
          ${a.internet_facing ? '<span class="badge b-low">internet</span>' : ''}
          ${a.handles_cardholder_data ? '<span class="badge b-critical">PCI</span>' : ''}
          ${a.components.every(c => c.dependency_type === 'transitive')
            ? '<span class="badge b-transitive">transitive only</span>' : ''}
        </div>
        ${a.components.map(c => `
          <div class="chain">${renderChain(c.chain, c.library)}</div>
          <div style="font-size:11.5px;color:var(--dim);margin:-2px 0 8px 2px">
            depth ${c.depth} &middot;
            ${c.reachable
              ? '<span style="color:var(--red)">vulnerable function IS reachable from our code</span>'
              : '<span style="color:var(--green)">vulnerable function not reachable &mdash; liability, not emergency</span>'}
          </div>`).join('')}
      </div>
      <div style="text-align:right">
        <b class="num" style="font-size:19px;color:${bandColor(a.max_priority >= 80 ? 'CRITICAL' : 'HIGH')}">${a.max_priority}</b>
        <div style="font-size:10.5px;color:var(--dim)">PRIORITY</div>
        <div style="font-size:11px;color:var(--dim);margin-top:4px">${esc(a.owner || '')}</div>
      </div>
    </div>`).join('');

  $('#cveResult').innerHTML = `
    <div class="blast">
      <div class="blast-head">
        <div style="flex:1">
          <div class="blast-title">
            ${esc(d.cve_id)}
            ${d.name ? `<span style="color:var(--muted);font-weight:500;font-size:15px">${esc(d.name)}</span>` : ''}
            ${badge(d.severity)}
            ${d.known_exploited ? '<span class="badge b-kev">exploited in the wild</span>' : ''}
            ${!d.patch_available ? '<span class="badge b-nopatch">no patch exists</span>' : ''}
          </div>
          <p class="blast-sum">${esc(d.summary)}</p>
        </div>
        <div style="text-align:right">
          <b style="font-size:30px;font-weight:800;color:var(--red)">${d.cvss_score}</b>
          <div style="font-size:10.5px;color:var(--dim)">CVSS</div>
        </div>
      </div>

      <div class="blast-headline">${esc(d.headline)}</div>

      <div class="blast-metrics">
        <div class="bm"><b style="color:var(--red)">${d.affected_app_count}</b><span>apps affected</span></div>
        <div class="bm"><b style="color:var(--purple)">${d.transitive_only_count}</b><span>transitive only</span></div>
        <div class="bm"><b style="color:var(--orange)">${d.internet_facing_count}</b><span>internet-facing</span></div>
        <div class="bm"><b style="color:var(--red)">${d.cardholder_data_count}</b><span>cardholder data</span></div>
        <div class="bm"><b>${d.critical_app_count}</b><span>business-critical</span></div>
      </div>

      ${d.patch_available
        ? `<div class="fix-box"><strong>One fix, whole estate.</strong>
             ${esc(d.single_fix || `Upgrade to ${d.patched_version}.`)}</div>`
        : `<div class="fix-box nofix"><strong>There is no patch.</strong>
             This cannot be fixed by bumping a version &mdash; the library must be
             <em>replaced</em>, which is a project, not a ticket. Apply a compensating
             control today: the exposure window stays open until the replacement ships.</div>`}

      <div class="chain-list">
        <div style="font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;margin-bottom:10px">
          How it actually gets in
        </div>
        ${chains}
      </div>
    </div>`;
}

function renderChain(chain, vulnLib) {
  if (!chain) return '<span class="hop">direct dependency</span>';
  const parts = chain.split(' -> ');
  return parts.map((p, i) => {
    const cls = i === 0 ? 'app' : (p.startsWith(vulnLib) ? 'vuln' : 'hop');
    return `<span class="${cls}">${esc(p)}</span>`;
  }).join('<span class="arrow">&rarr;</span>');
}

/* ================================================================= queue */
function populateSelects() {
  const opts = STATE.apps.map(a =>
    `<option value="${esc(a.app_id)}">${esc(a.app_name)}</option>`).join('');
  $('#filterApp').innerHTML = '<option value="">All applications</option>' + opts;
  $('#graphApp').innerHTML = opts;
  ['#filterApp', '#filterType', '#filterBand'].forEach(s => $(s).onchange = loadQueue);
}

async function loadQueue() {
  $('#queueTable').innerHTML = '<div class="loading">Loading&hellip;</div>';
  const q = new URLSearchParams({
    app_id: $('#filterApp').value, risk_type: $('#filterType').value,
    band: $('#filterBand').value, limit: 150,
  });
  const d = await api('/api/findings?' + q);

  if (!d.findings.length) {
    $('#queueTable').innerHTML = '<div class="empty">No findings match these filters.</div>';
    return;
  }

  $('#queueTable').innerHTML = `
    <table>
      <thead><tr>
        <th style="width:70px">Priority</th><th style="width:56px">Flaw</th>
        <th>Component</th><th>Application</th><th>Risk</th>
        <th style="width:64px">Depth</th><th>CVEs</th><th style="width:80px">Band</th>
      </tr></thead>
      <tbody>
        ${d.findings.map(f => `
          <tr data-id="${esc(f.dependency_id)}">
            <td class="num" style="color:${bandColor(f.risk_band)};font-size:15px">${f.priority_score}</td>
            <td class="num" style="color:var(--dim)">${f.risk_score}</td>
            <td class="lib">
              ${esc(f.library)}<small>@${esc(f.version)}</small>
              ${f.dependency_type === 'transitive'
                ? '<span class="badge b-transitive">transitive</span>' : ''}
            </td>
            <td>${esc(f.app_name)}</td>
            <td style="font-size:12.5px;color:var(--muted)">${RISK_LABEL[f.primary_risk] || f.primary_risk}</td>
            <td class="num">${f.true_depth}</td>
            <td class="lib" style="font-size:11.5px;color:var(--muted)">
              ${(f.cve_ids || []).slice(0, 2).join(', ') || '&mdash;'}
              ${(f.cve_ids || []).length > 2 ? ` +${f.cve_ids.length - 2}` : ''}
            </td>
            <td>${badge(f.risk_band)}</td>
          </tr>`).join('')}
      </tbody>
    </table>
    <div style="margin-top:12px;font-size:12px;color:var(--dim)">
      Showing ${d.findings.length} of ${d.total}. Click any row for the full analyst narrative.
    </div>`;

  $$('#queueTable tbody tr').forEach(r => r.onclick = () => openFinding(r.dataset.id));
}

/* ================================================================= modal */
async function openFinding(id) {
  $('#modalBody').innerHTML = '<div class="loading">Composing the analyst narrative&hellip;</div>';
  $('#modal').classList.add('open');

  const [f, n] = await Promise.all([
    api(`/api/finding/${id}`),
    api(`/api/intel/narrative/${id}`, { method: 'POST' }),
  ]);

  const b = f.blast_radius || {};
  $('#modalBody').innerHTML = `
    <h2>${esc(f.library)}<span style="color:var(--dim)">@${esc(f.version)}</span></h2>
    <div style="font-size:13px;color:var(--muted);margin-bottom:14px">
      in ${esc(f.app_name)} &middot; ${esc(f.team || '')} &middot; owner ${esc(f.owner || 'unassigned')}
    </div>

    <div class="metric-row">
      <div class="metric"><b style="color:${bandColor(f.risk_band)}">${f.priority_score}</b><span>priority (fix first?)</span></div>
      <div class="metric"><b>${f.risk_score}</b><span>flaw (how bad?)</span></div>
      <div class="metric"><b style="color:var(--purple)">&times;${f.context_multiplier}</b><span>our context</span></div>
      <div class="metric"><b>${f.true_depth}</b><span>depth</span></div>
      <div class="metric"><b style="color:var(--red)">${b.affected_app_count || 1}</b><span>apps holding this</span></div>
    </div>

    <div class="narrative">${esc(n.narrative)}</div>
    <div class="narrative-src">generated by: ${esc(n.generated_by)} &middot; ${esc(n.model)}
      ${n.provider_note ? `<br>${esc(n.provider_note)}` : ''}</div>

    <div style="margin-top:20px">
      <div style="font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px">
        Why this score
      </div>
      ${(f.drivers || []).map(d => `<div class="driver">${esc(d)}</div>`).join('')}
    </div>

    ${f.suppressed_cves && f.suppressed_cves.length ? `
      <div style="margin-top:18px;padding:12px 14px;background:rgba(61,220,132,.06);
                  border:1px solid rgba(61,220,132,.22);border-radius:8px;font-size:12.5px">
        <strong style="color:var(--green)">False positives suppressed:</strong>
        ${esc(f.suppressed_cves.join(', '))} match this version range, but the shipped build
        carries a backported fix. A naive version-matching scanner would flag every one of them.
      </div>` : ''}

    ${(f.compliance || []).length ? `
      <div style="margin-top:18px">
        <div style="font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px">
          Compliance mapping
        </div>
        ${f.compliance.map(c => `<div class="driver">
          <strong>${esc(c.framework)} ${esc(c.control)}</strong> &mdash; ${esc(c.description)}
        </div>`).join('')}
      </div>` : ''}`;
}

$('.modal-close').onclick = () => $('#modal').classList.remove('open');
$('#modal').onclick = (e) => { if (e.target.id === 'modal') $('#modal').classList.remove('open'); };
document.onkeydown = (e) => { if (e.key === 'Escape') $('#modal').classList.remove('open'); };

/* ================================================================= graph */
let cy = null;
async function loadGraph() {
  const appId = $('#graphApp').value || STATE.apps[0]?.app_id;
  const cve = $('#graphCve').value.trim();
  const q = new URLSearchParams({ app_id: appId });
  if (cve) q.set('highlight_cve', cve);
  const d = await api('/api/graph?' + q);

  if (cy) cy.destroy();
  cy = cytoscape({
    container: $('#cy'),
    elements: [...d.nodes, ...d.edges],
    layout: { name: 'breadthfirst', directed: true, spacingFactor: 1.25, padding: 30 },
    style: [
      {
        selector: 'node[kind="application"]',
        style: {
          'background-color': '#4aa8ff', label: 'data(label)', color: '#fff',
          'font-size': 13, 'font-weight': 700, width: 58, height: 58,
          'text-valign': 'center', 'text-halign': 'center', shape: 'round-rectangle',
          'text-outline-width': 2, 'text-outline-color': '#0b0e14',
        },
      },
      {
        selector: 'node[kind="library"]',
        style: {
          'background-color': (n) => ({
            CRITICAL: '#ff4d5e', HIGH: '#ff9640', MEDIUM: '#ffd23f', LOW: '#4aa8ff',
          }[n.data('risk_band')] || '#39415a'),
          label: 'data(library)', color: '#8b95ab', 'font-size': 8,
          width: (n) => 14 + (n.data('risk_score') || 0) / 6,
          height: (n) => 14 + (n.data('risk_score') || 0) / 6,
          'text-valign': 'bottom', 'text-margin-y': 3,
        },
      },
      {
        selector: 'node[?highlighted]',
        style: {
          'border-width': 4, 'border-color': '#fff',
          'background-color': '#ff4d5e', color: '#fff',
          'font-size': 11, 'font-weight': 700, width: 34, height: 34,
        },
      },
      {
        selector: 'edge',
        style: {
          width: 1, 'line-color': '#232b3d', 'curve-style': 'bezier',
          'target-arrow-shape': 'triangle', 'target-arrow-color': '#232b3d',
          'arrow-scale': .6,
        },
      },
    ],
  });

  cy.on('tap', 'node', (e) => {
    const n = e.target.data();
    if (n.kind === 'application') {
      $('#nodeDetail').innerHTML = `<strong>${esc(n.label)}</strong> &mdash; application root`;
      return;
    }
    $('#nodeDetail').innerHTML = `
      <strong>${esc(n.library)}@${esc(n.version)}</strong>
      ${badge(n.risk_band)} &middot; ${esc(n.license)} &middot; depth ${n.depth}
      &middot; priority ${n.risk_score}
      ${n.dependency_id ? ` &middot; <a href="#" style="color:var(--blue)"
        onclick="openFinding('${esc(n.dependency_id)}');return false">full analysis &rarr;</a>` : ''}`;
  });

  $('#nodeDetail').innerHTML =
    `${d.stats.library_nodes} components, ${d.stats.edges} edges, max depth ${d.stats.max_depth}.`;
}
$('#graphGo').onclick = loadGraph;
$('#graphApp').onchange = loadGraph;

/* ================================================================= playbook */
async function loadPlaybook() {
  $('#playbookList').innerHTML = '<div class="loading">Building the plan&hellip;</div>';
  const d = await api('/api/remediation');
  const s = d.summary;

  $('#playbookSummary').innerHTML = `
    <strong>${s.findings_collapsed} findings collapse into ${s.total_actions} actions</strong>
    (${s.collapse_ratio}&times;) &mdash; because one dependency bump often fixes the same flaw
    in several applications at once. ${s.immediate} need doing today.`;

  $('#playbookList').innerHTML = d.actions.map(a => `
    <div class="action ${esc(a.urgency)}">
      <div class="action-head">
        <div class="action-title">${esc(a.title)}</div>
        <div style="text-align:right;white-space:nowrap">
          ${badge(a.urgency.replace('_', ' '))}
          <div style="font-size:11px;color:var(--dim);margin-top:4px">
            ${esc(a.action_type)} &middot; priority ${a.max_priority}
          </div>
        </div>
      </div>
      <div class="action-rat">${esc(a.rationale)}</div>
      ${a.commands?.length ? `<pre>${esc(a.commands.join('\n'))}</pre>` : ''}
      ${(a.caveats || []).map(c => `<div class="caveat">${esc(c)}</div>`).join('')}
      ${a.compensating_control
        ? `<div class="compensating"><strong>Compensating control:</strong> ${esc(a.compensating_control)}</div>` : ''}
      <div class="apps-tag">
        ${a.affected_apps.length} app(s): ${esc(a.affected_apps.join(', '))}
        ${a.cve_ids.length ? ` &middot; ${esc(a.cve_ids.slice(0, 4).join(', '))}` : ''}
      </div>
    </div>`).join('');
}

/* ================================================================= intel */
async function loadIntel() {
  $('#clusterList').innerHTML = '<div class="loading">Clustering&hellip;</div>';
  $('#modelReport').innerHTML = '<div class="loading">Training on a held-out split&hellip;</div>';
  $('#correlationList').innerHTML = '<div class="loading">Correlating&hellip;</div>';

  const [cl, m, co] = await Promise.all([
    api('/api/intel/clusters'), api('/api/intel/model'), api('/api/correlation'),
  ]);

  $('#clusterList').innerHTML = cl.clusters.map(c => `
    <div class="cluster">
      <div class="cluster-head">
        <div class="cluster-name">${esc(c.name)}</div>
        <div class="cluster-size">${c.size} findings</div>
      </div>
      <div class="cluster-strat">${esc(c.remediation_strategy)}</div>
      <div class="cluster-ex">${esc(c.example_components.join('  ·  '))}</div>
    </div>`).join('') +
    `<div style="font-size:12px;color:var(--dim);margin-top:10px">${esc(cl.interpretation)}</div>`;

  const r = m.report;
  const ew = m.divergences.early_warning;
  $('#modelReport').innerHTML = `
    <div class="metric-row">
      <div class="metric"><b>${(r.roc_auc * 100).toFixed(1)}%</b><span>ROC-AUC</span></div>
      <div class="metric"><b>${(r.precision * 100).toFixed(1)}%</b><span>precision</span></div>
      <div class="metric"><b>${(r.recall * 100).toFixed(1)}%</b><span>recall</span></div>
      <div class="metric"><b>${r.n_test}</b><span>held out</span></div>
    </div>
    <div style="font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;margin:14px 0 8px">
      What the model keys on
    </div>
    ${r.feature_importance.slice(0, 6).map(f => `
      <div class="feat">
        <span class="feat-name">${esc(f.feature)}</span>
        <span class="feat-bar"><i style="width:${Math.min(100, f.importance * 220)}%"></i></span>
        <span style="width:44px;text-align:right;color:var(--dim)">${f.importance.toFixed(3)}</span>
      </div>`).join('')}
    ${ew.length ? `
      <div style="font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;margin:16px 0 8px">
        Early warning &mdash; no CVE, but the profile of one
      </div>
      ${ew.slice(0, 5).map(e => `
        <div class="driver">
          <strong style="color:var(--purple)">p=${e.model_risk_probability}</strong>
          ${esc(e.library)}@${esc(e.version)} in ${esc(e.app_name)}<br>
          <span style="color:var(--dim)">${esc(e.why)}</span>
        </div>`).join('')}` : ''}`;

  const c = co.correlation;
  $('#correlationList').innerHTML = `
    <div style="font-size:13px;color:var(--muted);margin-bottom:14px">${esc(c.interpretation)}</div>
    <table>
      <thead><tr>
        <th>Component</th><th style="width:60px">Apps</th><th>Exposure</th>
        <th>One fix clears</th><th style="width:80px">Leverage</th>
      </tr></thead>
      <tbody>
        ${c.shared_components.slice(0, 12).map(s => `
          <tr>
            <td class="lib">${esc(s.library)}
              ${s.version_fragmentation > 1
                ? `<small> · ${s.version_fragmentation} versions</small>` : ''}</td>
            <td class="num">${s.affected_app_count}</td>
            <td style="font-size:12px;color:var(--muted)">
              ${s.internet_facing_apps ? `${s.internet_facing_apps} internet` : ''}
              ${s.cardholder_data_apps ? ` · ${s.cardholder_data_apps} PCI` : ''}
              ${s.transitive_in ? ` · ${s.transitive_in} transitive` : ''}
            </td>
            <td style="font-size:12px;color:var(--muted)">${esc(s.one_fix_clears)}</td>
            <td class="num" style="color:var(--orange)">${s.leverage_score}</td>
          </tr>`).join('')}
      </tbody>
    </table>`;
}

/* ================================================================= compliance */
async function loadCompliance() {
  $('#complianceList').innerHTML = '<div class="loading">Assessing&hellip;</div>';
  const d = await api('/api/compliance');
  const rep = d.report;

  $('#complianceList').innerHTML = `
    <div class="metric-row">
      <div class="metric"><b>${rep.estate.mean_compliance_score}%</b><span>estate mean</span></div>
      <div class="metric"><b style="color:var(--red)">${rep.estate.total_control_failures}</b><span>control failures</span></div>
      <div class="metric"><b>${rep.estate.fully_compliant_apps}/${rep.estate.total_apps}</b><span>fully compliant</span></div>
    </div>
    <div style="font-size:12.5px;color:var(--muted);margin-bottom:18px">${esc(rep.interpretation)}</div>
    ${rep.applications.map(a => `
      <div class="card" style="background:var(--bg);margin-bottom:12px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
          <div>
            <strong>${esc(a.app_name)}</strong> ${badge(a.business_criticality)}
            <div style="font-size:11.5px;color:var(--dim);margin-top:2px">
              ${esc(a.team)} &middot; ${esc(a.owner)}
            </div>
          </div>
          <div style="text-align:right">
            <b style="font-size:22px;color:${a.compliance_score >= 70 ? 'var(--green)' : a.compliance_score >= 45 ? 'var(--yellow)' : 'var(--red)'}">${a.compliance_score}%</b>
            <div style="font-size:11px;color:var(--dim)">${a.controls_passed}/${a.controls_total} passing</div>
          </div>
        </div>
        ${a.controls.map(c => `
          <div class="control">
            <div class="control-head">
              <div class="control-name">${esc(c.framework)} ${esc(c.control_id)} &mdash; ${esc(c.name)}</div>
              <div class="st-${esc(c.status)}" style="font-weight:700;font-size:12px">${esc(c.status)}</div>
            </div>
            <div class="control-ev">${esc(c.evidence)}</div>
          </div>`).join('')}
        ${a.exception_count ? `
          <div style="margin-top:10px;font-size:12px;color:var(--dim)">
            ${a.exception_count} documented exception(s) &mdash; accepted risks with a recorded basis,
            not silent omissions.
          </div>` : ''}
      </div>`).join('')}`;
}

/* ================================================================= gate */
$('#gateRun').onclick = loadGate;
async function loadGate() {
  $('#gateResult').innerHTML = '<div class="loading">Evaluating policy&hellip;</div>';
  const d = await api('/api/gate', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ policy: $('#policySelect').value }),
  });

  $('#gateResult').innerHTML = `
    <div class="verdict ${d.passed ? 'pass' : 'fail'}">
      ${d.passed ? '&#10003;' : '&#10007;'} ${esc(d.verdict)}
      <span class="exit-code">exit ${d.exit_code}</span>
    </div>
    ${d.blocks.length ? `
      <div style="font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;margin:16px 0 8px">
        Blocking (${d.block_count})
      </div>
      ${d.blocks.slice(0, 12).map(b => `
        <div class="warn-item">
          <div><strong>${esc(b.library)}@${esc(b.version)}</strong>
            <span style="color:var(--dim)">in ${esc(b.app_name)}</span>
            <span class="badge b-critical">${esc(b.rule)}</span></div>
          <div class="warn-msg">${esc(b.message)}</div>
          <div class="warn-fix">&rarr; ${esc(b.remediation)}</div>
        </div>`).join('')}` : ''}
    ${d.warnings.length ? `
      <div style="font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;margin:16px 0 8px">
        Warnings (${d.warning_count}) &mdash; reported, not blocking
      </div>
      ${d.warnings.slice(0, 6).map(w => `
        <div class="warn-item WARN">
          <div><strong>${esc(w.library)}@${esc(w.version)}</strong>
            <span style="color:var(--dim)">in ${esc(w.app_name)}</span></div>
          <div class="warn-msg">${esc(w.message)}</div>
        </div>`).join('')}` : ''}`;

  if (!$('#ciSnippet').textContent) $('#ciSnippet').textContent = d.ci_snippet;
}

/* ================================================================= upload */
const dz = $('#dropzone'), fi = $('#fileInput');
['dragover', 'dragenter'].forEach(e =>
  dz.addEventListener(e, (ev) => { ev.preventDefault(); dz.classList.add('over'); }));
['dragleave', 'drop'].forEach(e =>
  dz.addEventListener(e, () => dz.classList.remove('over')));
dz.addEventListener('drop', (ev) => {
  ev.preventDefault();
  if (ev.dataTransfer.files[0]) uploadSbom(ev.dataTransfer.files[0]);
});
fi.onchange = () => { if (fi.files[0]) uploadSbom(fi.files[0]); };

async function uploadSbom(file) {
  $('#uploadResult').innerHTML = '<div class="loading">Parsing and analysing&hellip;</div>';
  const fd = new FormData();
  fd.append('file', file);
  const res = await fetch('/api/upload', { method: 'POST', body: fd });
  const d = await res.json();

  if (!res.ok) {
    $('#uploadResult').innerHTML =
      `<div class="warn-item" style="margin-top:16px">${esc(d.detail || 'Upload failed.')}</div>`;
    return;
  }

  $('#uploadResult').innerHTML = `
    <div class="card" style="background:var(--bg);margin-top:18px">
      <div class="metric-row">
        <div class="metric"><b style="color:var(--green)">${esc(d.format_detected)}</b><span>format detected</span></div>
        <div class="metric"><b>${d.components_parsed}</b><span>components</span></div>
        <div class="metric"><b style="color:var(--purple)">${d.transitive}</b><span>transitive</span></div>
        <div class="metric"><b>${d.max_depth}</b><span>max depth</span></div>
        <div class="metric"><b style="color:var(--red)">${d.stats.at_risk}</b><span>at risk</span></div>
        <div class="metric"><b style="color:var(--orange)">${d.stats.unique_cves}</b><span>CVEs</span></div>
      </div>
      <div style="font-size:12.5px;color:var(--muted);margin-bottom:16px">${esc(d.note)}</div>
      <table>
        <thead><tr><th style="width:70px">Priority</th><th>Component</th><th>Risk</th><th>CVEs</th></tr></thead>
        <tbody>
          ${d.top_findings.slice(0, 15).map(f => `
            <tr>
              <td class="num" style="color:${bandColor(f.risk_band)}">${f.priority_score}</td>
              <td class="lib">${esc(f.library)}<small>@${esc(f.version)}</small>
                ${f.dependency_type === 'transitive'
                  ? '<span class="badge b-transitive">transitive</span>' : ''}</td>
              <td style="font-size:12.5px;color:var(--muted)">${RISK_LABEL[f.primary_risk] || f.primary_risk}</td>
              <td class="lib" style="font-size:11.5px">${(f.cve_ids || []).slice(0, 2).join(', ') || '&mdash;'}</td>
            </tr>`).join('')}
        </tbody>
      </table>
    </div>`;
}

/* ================================================================= proof */
$('#runEval').onclick = async () => {
  $('#evalOutput').textContent = 'Running the evaluation harness against the ground-truth labels...';
  const d = await api('/api/eval');
  $('#evalOutput').textContent = d.output;
};

/* ================================================================= loaders */
const LOADERS = {
  queue: loadQueue,
  graph: loadGraph,
  playbook: loadPlaybook,
  intel: loadIntel,
  compliance: loadCompliance,
  gate: loadGate,
};

window.openFinding = openFinding;
