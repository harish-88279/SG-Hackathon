/**
 * Builds the SBOMGuard submission deck.
 *
 *   node docs/build_deck.js
 *
 * Dark and warm on purpose: the deck is the same colour as the product, so the slides and
 * the live demo read as one artefact rather than two. Amber is reserved for the single
 * thing you should be looking at on each slide, exactly as it is in the dashboard.
 *
 * Every number in here is measured against the running system. Nothing is rounded up.
 */
const Pptx = require('pptxgenjs')

/* ── palette ─────────────────────────────────────────────────────────────── */
const BG    = '12100F'   // warm near-black. Dominates.
const PANEL = '1C1917'
const RAISE = '272220'
const INK   = 'F2EEE7'
const MUTED = 'A89F92'
const DIM   = '7E766A'
const AMBER = 'FF7A3D'   // the accent. Used sparingly, and only for the point.
const GOLD  = 'FFC46B'
const CRIT  = 'FF5D5D'
const OK    = '5FCF9A'

const HEAD = 'Cambria'   // safe-list serif — editorial weight
const BODY = 'Calibri'   // safe-list sans
const MONO = 'Courier New'

const pres = new Pptx()
pres.layout = 'LAYOUT_WIDE'          // 13.3 x 7.5 — MUST be set before any slide
pres.author = 'Harish HJ'
pres.title  = 'SBOMGuard — SG GRC Hackathon PB-10'

const slide = (bg = BG) => { const s = pres.addSlide(); s.background = { color: bg }; return s }

/** Section heading + optional deck. Never an underline rule — that's AI-slide tell #1. */
function heading(s, kicker, title, y = 0.5) {
  if (kicker) s.addText(kicker.toUpperCase(), {
    x: 0.6, y, w: 12.1, h: 0.28, margin: 0,
    fontFace: BODY, fontSize: 11, bold: true, color: AMBER, charSpacing: 2,
  })
  s.addText(title, {
    x: 0.6, y: y + 0.32, w: 12.1, h: 0.75, margin: 0,
    fontFace: HEAD, fontSize: 34, bold: true, color: INK,
  })
}

/** The motif: a numbered amber disc. Repeated on every content slide. */
function disc(s, n, x, y, size = 0.42, fill = AMBER, fg = '2A1405') {
  s.addShape(pres.ShapeType.ellipse, {
    x, y, w: size, h: size, fill: { color: fill },
  })
  s.addText(String(n), {
    x, y, w: size, h: size, margin: 0,
    fontFace: BODY, fontSize: 13, bold: true, color: fg,
    align: 'center', valign: 'middle',
  })
}

function card(s, x, y, w, h, fill = PANEL) {
  s.addShape(pres.ShapeType.roundRect, {
    x, y, w, h, rectRadius: 0.08, fill: { color: fill },
  })
}

/* ═══════════════════════════════════════════════ 1 · title ════════════════ */
{
  const s = slide()
  s.addShape(pres.ShapeType.ellipse, { x: -1.6, y: -1.9, w: 6.2, h: 6.2, fill: { color: AMBER, transparency: 92 } })

  s.addText('SBOMGuard', {
    x: 0.9, y: 1.75, w: 8.4, h: 1.0, margin: 0,
    fontFace: HEAD, fontSize: 54, bold: true, color: INK,
  })
  s.addText('A critical vulnerability just dropped.', {
    x: 0.9, y: 2.85, w: 9.6, h: 0.5, margin: 0,
    fontFace: HEAD, fontSize: 25, color: MUTED,
  })
  s.addText('Which of our applications are affected?', {
    x: 0.9, y: 3.35, w: 9.6, h: 0.5, margin: 0,
    fontFace: HEAD, fontSize: 25, bold: true, color: AMBER,
  })

  s.addText('Almost no organisation can answer that quickly — not because the flaw is hard to understand,\nbut because nobody knows what is actually inside their own software.', {
    x: 0.9, y: 4.2, w: 9.9, h: 0.8, margin: 0,
    fontFace: BODY, fontSize: 14, color: DIM, lineSpacing: 22,
  })

  s.addText('Société Générale GRC Hackathon  ·  PB-10  ·  Software Supply Chain Risk Analyzer', {
    x: 0.9, y: 6.3, w: 11.5, h: 0.3, margin: 0,
    fontFace: BODY, fontSize: 12, color: DIM,
  })
  s.addText('Harish HJ   ·   github.com/harish-88279/SG-Hackathon', {
    x: 0.9, y: 6.65, w: 11.5, h: 0.3, margin: 0,
    fontFace: BODY, fontSize: 12, bold: true, color: MUTED,
  })
  s.addNotes('December 2021. Log4Shell drops on a Friday. Every security team on earth is asked one question — which of our applications are affected? — and almost none of them can answer it. That question is what this is built to answer.')
}

/* ═══════════════════════════════════════════ 2 · the problem ══════════════ */
{
  const s = slide()
  heading(s, 'The problem', 'Listing an SBOM is easy. That is not the problem.')

  const items = [
    ['Reachability, not presence', 'A CVE in your dependency file is not a vulnerability in your product. It matters only if it is reachable — and reachability is a property of the GRAPH, not of the list.', AMBER],
    ['The thing nobody chose', '96 of our 500 components carry a transitive vulnerability. Those teams could audit every dependency they deliberately added, come up clean, and still be exposed.', CRIT],
    ['Suppression is the hard half', 'Finding CVEs is arithmetic. Deciding which ones a human should spend Tuesday on is the job. A scanner that cries wolf gets switched off — worse than no scanner.', GOLD],
  ]
  items.forEach(([t, d, c], i) => {
    const y = 1.85 + i * 1.62
    card(s, 0.6, y, 12.1, 1.4)
    disc(s, i + 1, 0.95, y + 0.28, 0.46, c, '2A1405')
    s.addText(t, {
      x: 1.6, y: y + 0.18, w: 10.8, h: 0.34, margin: 0,
      fontFace: BODY, fontSize: 16, bold: true, color: INK,
    })
    s.addText(d, {
      x: 1.6, y: y + 0.55, w: 10.8, h: 0.7, margin: 0,
      fontFace: BODY, fontSize: 12.5, color: MUTED, lineSpacing: 17,
    })
  })
  s.addNotes('The difficulty is not where people assume. Everyone can print the list.')
}

/* ═════════════════════════════════════ 3 · the answer (money slide) ═══════ */
{
  const s = slide()
  heading(s, 'What it does', 'It answers the question. In 0.08 milliseconds.')

  card(s, 0.6, 1.85, 12.1, 1.95, RAISE)
  s.addText('CVE-2024-1060', {
    x: 1.0, y: 2.08, w: 4, h: 0.35, margin: 0,
    fontFace: MONO, fontSize: 14, bold: true, color: GOLD,
  })
  s.addText('“6 of 10 applications are affected. 1 of them is exposed ONLY through transitive\ndependencies — no engineer on those teams ever chose this library, and no review of\ndirect dependencies would have found it.”', {
    x: 1.0, y: 2.5, w: 11.3, h: 1.1, margin: 0,
    fontFace: HEAD, fontSize: 16, color: INK, lineSpacing: 25,
  })

  s.addText('That last clause is the whole problem. A list cannot tell you this. Only a graph can.', {
    x: 0.6, y: 4.0, w: 12.1, h: 0.35, margin: 0,
    fontFace: BODY, fontSize: 14, italic: true, color: AMBER,
  })

  const stats = [
    ['500', 'components'],
    ['347', 'at risk'],
    ['96', 'nobody chose'],
    ['46 ms', 'full estate scan'],
  ]
  stats.forEach(([v, l], i) => {
    const x = 0.6 + i * 3.06
    card(s, x, 4.65, 2.86, 1.5)
    s.addText(v, {
      x, y: 4.82, w: 2.86, h: 0.62, margin: 0,
      fontFace: HEAD, fontSize: 32, bold: true, color: i === 1 ? CRIT : (i === 2 ? AMBER : INK),
      align: 'center',
    })
    s.addText(l.toUpperCase(), {
      x, y: 5.5, w: 2.86, h: 0.28, margin: 0,
      fontFace: BODY, fontSize: 10, bold: true, color: DIM, align: 'center', charSpacing: 1,
    })
  })
  s.addNotes('Read the headline verbatim, then stop talking for a beat. This sentence is the demo.')
}

/* ═══════════════════════════════════════════ 4 · architecture ═════════════ */
{
  const s = slide()
  heading(s, 'Architecture', 'One process. No database. The graph is the load-bearing wall.')

  const boxes = [
    ['INGEST',   'CSV · JSON\nCycloneDX · SPDX', DIM],
    ['AUDIT',    'Does the data\nagree with itself?', AMBER],
    ['GRAPH',    'networkx DiGraph\ndepth by traversal', GOLD],
    ['DETECT',   'vuln · licence\nmaintenance', DIM],
    ['SCORE',    'risk + priority\nsuppression', DIM],
  ]
  boxes.forEach(([t, d, c], i) => {
    const x = 0.6 + i * 2.47
    card(s, x, 2.05, 2.2, 1.55, i === 1 ? RAISE : PANEL)
    s.addText(t, {
      x, y: 2.25, w: 2.2, h: 0.3, margin: 0,
      fontFace: BODY, fontSize: 12, bold: true, color: c, align: 'center', charSpacing: 1,
    })
    s.addText(d, {
      x, y: 2.62, w: 2.2, h: 0.8, margin: 0,
      fontFace: MONO, fontSize: 9.5, color: MUTED, align: 'center', lineSpacing: 14,
    })
    if (i < 4) s.addText('▸', {
      x: x + 2.2, y: 2.05, w: 0.27, h: 1.55, margin: 0,
      fontFace: BODY, fontSize: 14, color: DIM, align: 'center', valign: 'middle',
    })
  })

  s.addText('The audit step is not standard, and it is the reason this submission exists. See slide 8.', {
    x: 0.6, y: 3.8, w: 12.1, h: 0.3, margin: 0,
    fontFace: BODY, fontSize: 12, italic: true, color: AMBER,
  })

  const facts = [
    ['46 ms', 'full analysis of 500 components, 200 CVEs, 10 apps'],
    ['191 MB', 'resident set — including running both eval harnesses live'],
    ['31 / 41', 'API endpoints  ·  passing tests'],
    ['0', 'API keys required to run any part of this'],
  ]
  facts.forEach(([v, l], i) => {
    const y = 4.4 + i * 0.62
    s.addText(v, {
      x: 0.6, y, w: 1.6, h: 0.34, margin: 0,
      fontFace: HEAD, fontSize: 17, bold: true, color: i === 3 ? OK : INK, align: 'right',
    })
    s.addText(l, {
      x: 2.35, y: y + 0.04, w: 10.3, h: 0.32, margin: 0,
      fontFace: BODY, fontSize: 13, color: MUTED,
    })
  })
  s.addNotes('The graph is built once at startup and held in memory. That is why the war-room question is answered instantly rather than by a scan.')
}

/* ═══════════════════════════════════════ 5 · algorithms ═══════════════════ */
{
  const s = slide()
  heading(s, 'Analysis algorithms', 'Three decisions that most home-grown tools get wrong.')

  const cols = [
    ['Versions are not strings',
     '"2.9.9" > "2.9.10"\n\nTrue lexicographically.\nFalse in reality.',
     'A naive string compare marks a VULNERABLE component clean. This is the most common bug in home-grown SBOM tooling.\n\nfixed = None means no fix ever shipped — affected forever. Not "unknown". 47 findings have no patch.'],
    ['Depth is never trusted',
     'true_depth()\nby traversal',
     'The SBOM\'s own depth column is an assertion by whoever generated the file. The graph is the evidence.\n\nDiamonds — components reachable two ways — must be fixed twice. Patch one route and the "patched" library stays vulnerable.'],
    ['Two scores, two questions',
     'risk  ±8% clamp\npriority  ×0.4–3.0',
     'A CRITICAL cannot be talked down into a MEDIUM by a flattering context multiplier. That is enforced by the clamp.\n\nBut a MEDIUM on an internet-facing payment system outranks a CRITICAL in a dead batch job — and it should.'],
  ]
  cols.forEach(([t, code, d], i) => {
    const x = 0.6 + i * 4.13
    card(s, x, 1.85, 3.85, 4.55)
    disc(s, i + 1, x + 0.3, 2.1, 0.42)
    s.addText(t, {
      x: x + 0.3, y: 2.65, w: 3.25, h: 0.6, margin: 0,
      fontFace: BODY, fontSize: 15, bold: true, color: INK,
    })
    card(s, x + 0.3, 3.3, 3.25, 0.95, RAISE)
    s.addText(code, {
      x: x + 0.42, y: 3.4, w: 3.0, h: 0.78, margin: 0,
      fontFace: MONO, fontSize: 9.5, color: GOLD, lineSpacing: 13,
    })
    s.addText(d, {
      x: x + 0.3, y: 4.42, w: 3.25, h: 1.8, margin: 0,
      fontFace: BODY, fontSize: 11, color: MUTED, lineSpacing: 15,
    })
  })
  s.addNotes('Licence analysis is a legal question, not a grep: GPL in a non-distributed app is not a violation. AGPL in the same app is.')
}

/* ═══════════════════════════════════════ 6 · UI design ═══════════════════ */
{
  const s = slide()
  heading(s, 'Interface design', 'We deleted the beautiful graph.')

  card(s, 0.6, 1.9, 5.95, 3.4)
  s.addText('✕   The elegant one', {
    x: 0.95, y: 2.15, w: 5.3, h: 0.35, margin: 0,
    fontFace: BODY, fontSize: 14, bold: true, color: CRIT,
  })
  s.addText('Concentric orbits. Depth as radius. The application at the centre, the estate around it.\n\nIt produced 500 unlabelled dots on a circle. You could see that something was burning and never once see WHAT — because a ring gives a label nowhere to live.\n\nA picture you cannot read is not a picture.', {
    x: 0.95, y: 2.62, w: 5.3, h: 2.5, margin: 0,
    fontFace: BODY, fontSize: 12, color: MUTED, lineSpacing: 17,
  })

  card(s, 6.75, 1.9, 5.95, 3.4, RAISE)
  s.addText('✓   The readable one', {
    x: 7.1, y: 2.15, w: 5.3, h: 0.35, margin: 0,
    fontFace: BODY, fontSize: 14, bold: true, color: OK,
  })
  s.addText('Columns. Depth is the x-axis.\n\nColumn one is code somebody on the team actually CHOSE. Everything right of it ARRIVED UNINVITED — and the further right, the fewer people knew it was there.\n\nLabels sit beside their node. Always on. That is the entire reason to prefer this to the prettier one.', {
    x: 7.1, y: 2.62, w: 5.3, h: 2.5, margin: 0,
    fontFace: BODY, fontSize: 12, color: MUTED, lineSpacing: 17,
  })

  const notes = [
    ['It does not draw everything.', '500 nodes is a texture, not a visualisation. It draws what carries risk, plus the hops needed to reach it — because those hops ARE the answer to "how did this get in".'],
    ['Plain English is a first-class mode.', 'GRC work is done by risk officers, not only engineers. A tool only engineers can read produces tickets nobody trusts.'],
  ]
  notes.forEach(([t, d], i) => {
    const y = 5.55 + i * 0.72
    s.addShape(pres.ShapeType.ellipse, { x: 0.62, y: y + 0.09, w: 0.12, h: 0.12, fill: { color: AMBER } })
    s.addText(t, {
      x: 0.95, y, w: 3.5, h: 0.3, margin: 0,
      fontFace: BODY, fontSize: 12, bold: true, color: INK,
    })
    s.addText(d, {
      x: 4.5, y, w: 8.2, h: 0.62, margin: 0,
      fontFace: BODY, fontSize: 11, color: DIM, lineSpacing: 14,
    })
  })
  s.addNotes('Also removed scroll-to-zoom: it hijacked page scrolling and silently shrank the graph to a smear. A control that fires when you were not aiming at it is not a feature.')
}

/* ═══════════════════════════════════ 7 · suppression ═════════════════════ */
{
  const s = slide()
  heading(s, 'The hard half', 'Detection is arithmetic. Suppression is judgement.')

  s.addText('A scanner that cries wolf gets switched off — which is strictly worse than having no scanner at all.\nSo a finding is suppressed only when it is genuinely not actionable:', {
    x: 0.6, y: 1.85, w: 12.1, h: 0.7, margin: 0,
    fontFace: BODY, fontSize: 14, color: MUTED, lineSpacing: 20,
  })

  const rules = [
    ['patched_in_build', 'The build carries a backported fix. The version matches the CVE range and is not vulnerable.'],
    ['vulnerable_function_used = false', 'The flawed code path is never called. The library is present; the vulnerability is not.'],
    ['unreachable', 'No path from any entry point. It cannot be exploited because it cannot be reached.'],
  ]
  rules.forEach(([code, d], i) => {
    const y = 2.85 + i * 0.95
    card(s, 0.6, y, 12.1, 0.78)
    s.addText(code, {
      x: 0.95, y: y + 0.22, w: 3.5, h: 0.34, margin: 0,
      fontFace: MONO, fontSize: 11, bold: true, color: GOLD,
    })
    s.addText(d, {
      x: 4.7, y: y + 0.22, w: 7.7, h: 0.34, margin: 0,
      fontFace: BODY, fontSize: 12, color: MUTED,
    })
  })

  card(s, 0.6, 5.8, 12.1, 1.0, RAISE)
  s.addText('19 / 19', {
    x: 0.95, y: 6.0, w: 1.7, h: 0.6, margin: 0,
    fontFace: HEAD, fontSize: 28, bold: true, color: OK, align: 'center', valign: 'middle',
  })
  s.addText('false-positive traps defused on the synthetic corpus — versions that match a CVE range but carry a\nbackported patch — while missing zero true positives.', {
    x: 2.9, y: 6.0, w: 9.5, h: 0.6, margin: 0,
    fontFace: BODY, fontSize: 12.5, color: MUTED, valign: 'middle', lineSpacing: 17,
  })
  s.addNotes('Getting suppression wrong in either direction destroys the tool.')
}

/* ═══════════════════════════════ 8 · THE FINDING ═════════════════════════ */
{
  const s = slide()
  heading(s, 'The finding', 'We audited your dataset. It contradicts itself.')

  s.addText('Our data-quality control fires BEFORE any scoring. On the official PB-10 data it fired immediately:\nstrict version-range matching recovers only 25.6% of the vulnerabilities the labels themselves declare.', {
    x: 0.6, y: 1.8, w: 12.1, h: 0.7, margin: 0,
    fontFace: BODY, fontSize: 13.5, color: MUTED, lineSpacing: 19,
  })

  card(s, 0.6, 2.7, 12.1, 2.75, RAISE)
  s.addText('log4j-api      CVE-2022-1041 affects  [ 4.7.0 .. 4.10.1 )', {
    x: 0.95, y: 2.9, w: 11.4, h: 0.32, margin: 0,
    fontFace: MONO, fontSize: 12, bold: true, color: GOLD,
  })

  const rows = [
    ['v2.3.3', 'outside the affected range', 'VULNERABLE', CRIT],
    ['v4.8.3', 'INSIDE  the affected range', 'CLEAN', OK],
    ['v5.1.3', 'outside the affected range', 'VULNERABLE', CRIT],
    ['v5.11.1', 'outside the affected range', 'VULNERABLE', CRIT],
  ]
  rows.forEach(([v, where, lab, c], i) => {
    const y = 3.35 + i * 0.42
    s.addText(v, {
      x: 1.15, y, w: 1.2, h: 0.32, margin: 0,
      fontFace: MONO, fontSize: 11.5, color: INK,
    })
    s.addText(where, {
      x: 2.45, y, w: 3.6, h: 0.32, margin: 0,
      fontFace: MONO, fontSize: 11.5, color: i === 1 ? GOLD : DIM,
    })
    s.addText('→   labelled ' + lab, {
      x: 6.3, y, w: 4.5, h: 0.32, margin: 0,
      fontFace: MONO, fontSize: 11.5, bold: i === 1, color: c,
    })
  })
  s.addText('Every version INSIDE the range is clean. Every version OUTSIDE it is vulnerable.', {
    x: 1.15, y: 5.05, w: 11.2, h: 0.3, margin: 0,
    fontFace: BODY, fontSize: 13, bold: true, color: AMBER,
  })

  s.addText('The version predicate is not approximately wrong — it is running exactly BACKWARDS. No monotone predicate on\nversions can be false inside an interval and true outside it. So the labels are not a function of the version at all:\nthey were generated from the library NAME. Fifteen libraries show the same pattern.', {
    x: 0.6, y: 5.65, w: 12.1, h: 0.9, margin: 0,
    fontFace: BODY, fontSize: 12.5, color: MUTED, lineSpacing: 18,
  })
  s.addText('SBOMGuard detects this on load, adapts, and puts it on the front page — rather than silently scoring 26%.', {
    x: 0.6, y: 6.6, w: 12.1, h: 0.35, margin: 0,
    fontFace: BODY, fontSize: 13, bold: true, italic: true, color: INK,
  })
  s.addNotes('Read the table aloud, then stop. This is the strongest thirty seconds in the deck.')
}

/* ═════════════════════════ 9 · why two criteria cannot both be met ═══════ */
{
  const s = slide()
  heading(s, 'The consequence', 'Two of the five criteria are mutually unsatisfiable.')

  s.addText('301 dependencies carry a CVE-bearing library. 176 are labelled risky, 125 clean — and NOTHING in the inputs\nseparates them. So flagging a fraction f gives recall = f and false-positive rate = f × 0.39. They are welded.', {
    x: 0.6, y: 1.8, w: 12.1, h: 0.7, margin: 0,
    fontFace: BODY, fontSize: 13, color: MUTED, lineSpacing: 19,
  })

  s.addChart(pres.ChartType.line, [
    {
      name: 'False-positive rate',
      labels: ['0%', '20%', '40%', '51%', '60%', '85%', '100%'],
      values: [0, 7.8, 15.6, 20, 23.4, 33.2, 39],
    },
  ], {
    x: 0.6, y: 2.7, w: 7.4, h: 3.9,
    chartColors: [AMBER],
    lineSize: 3,
    showTitle: true,
    title: 'To get more recall, you must accept more false positives',
    titleColor: MUTED, titleFontSize: 12, titleFontFace: BODY,
    showLegend: false,
    catAxisTitle: 'Recall achieved', showCatAxisTitle: true,
    catAxisTitleColor: DIM, catAxisTitleFontSize: 11,
    valAxisTitle: 'False-positive rate', showValAxisTitle: true,
    valAxisTitleColor: DIM, valAxisTitleFontSize: 11,
    catAxisLabelColor: DIM, valAxisLabelColor: DIM,
    catAxisLabelFontSize: 10, valAxisLabelFontSize: 10,
    valGridLine: { color: '2E2925', size: 1 },
    catGridLine: { style: 'none' },
    valAxisMaxVal: 40,
  })

  const box = [
    ['Target: recall > 85%', 'forces  33.2%  false positives', CRIT],
    ['Target: false positives < 20%', 'caps recall at  51.2%', CRIT],
  ]
  box.forEach(([t, d, c], i) => {
    const y = 2.95 + i * 1.15
    card(s, 8.3, y, 4.4, 0.95)
    s.addText(t, {
      x: 8.6, y: y + 0.13, w: 3.9, h: 0.3, margin: 0,
      fontFace: BODY, fontSize: 12, bold: true, color: INK,
    })
    s.addText(d, {
      x: 8.6, y: y + 0.45, w: 3.9, h: 0.32, margin: 0,
      fontFace: MONO, fontSize: 11.5, color: c,
    })
  })

  card(s, 8.3, 5.35, 4.4, 1.25, RAISE)
  s.addText('You may have one.\nYou may not have both.', {
    x: 8.6, y: 5.5, w: 3.9, h: 0.6, margin: 0,
    fontFace: HEAD, fontSize: 15, bold: true, color: AMBER, lineSpacing: 21,
  })
  s.addText('We chose recall. A missed CVE costs\nmore than a second look at a clean library.', {
    x: 8.6, y: 6.05, w: 3.9, h: 0.5, margin: 0,
    fontFace: BODY, fontSize: 10.5, color: MUTED, lineSpacing: 14,
  })
  s.addNotes('This is arithmetic, not an excuse. Deliver it as a result, because it is one.')
}

/* ═══════════════════════════════════ 10 · scorecard ══════════════════════ */
{
  const s = slide()
  heading(s, 'Evaluation', 'Same engine. Same code. Only the data changes.')

  s.addChart(pres.ChartType.bar, [
    { name: 'Official SG data', labels: ['Vuln detection', 'Transitive', 'Licence', 'False positives', 'Risk accuracy'], values: [5, 5, 5, 1, 2] },
    { name: 'Consistent data',  labels: ['Vuln detection', 'Transitive', 'Licence', 'False positives', 'Risk accuracy'], values: [5, 5, 5, 5, 5] },
  ], {
    x: 0.6, y: 1.85, w: 7.5, h: 4.15,
    barDir: 'col',
    chartColors: [AMBER, OK],
    showTitle: true,
    title: 'Criteria met  (5 = target met, low = missed)',
    titleColor: MUTED, titleFontSize: 12, titleFontFace: BODY,
    showLegend: true, legendPos: 'b', legendColor: MUTED, legendFontSize: 11,
    catAxisLabelColor: DIM, valAxisLabelColor: DIM,
    catAxisLabelFontSize: 9.5, valAxisLabelFontSize: 10,
    valGridLine: { color: '2E2925', size: 1 },
    catGridLine: { style: 'none' },
    valAxisMaxVal: 5,
    valAxisMajorUnit: 1,
  })

  card(s, 8.4, 1.95, 2.05, 1.5, RAISE)
  s.addText('3/5', { x: 8.4, y: 2.1, w: 2.05, h: 0.7, margin: 0, fontFace: HEAD, fontSize: 34, bold: true, color: AMBER, align: 'center' })
  s.addText('OFFICIAL DATA', { x: 8.4, y: 2.85, w: 2.05, h: 0.3, margin: 0, fontFace: BODY, fontSize: 9, bold: true, color: DIM, align: 'center', charSpacing: 1 })

  card(s, 10.65, 1.95, 2.05, 1.5, RAISE)
  s.addText('5/5', { x: 10.65, y: 2.1, w: 2.05, h: 0.7, margin: 0, fontFace: HEAD, fontSize: 34, bold: true, color: OK, align: 'center' })
  s.addText('CONSISTENT DATA', { x: 10.65, y: 2.85, w: 2.05, h: 0.3, margin: 0, fontFace: BODY, fontSize: 8.5, bold: true, color: DIM, align: 'center', charSpacing: 1 })

  s.addText('The gap is not the engine.\nIt is the dataset — and we are\nthe only ones who checked.', {
    x: 8.4, y: 3.75, w: 4.3, h: 0.95, margin: 0,
    fontFace: HEAD, fontSize: 15, bold: true, color: INK, lineSpacing: 21,
  })

  s.addText('On risk accuracy: severity in these labels is a coin-toss — each dependency is scored against a CVE drawn AT RANDOM from its library\'s set. An oracle allowed to pick any score per library, WITH FULL KNOWLEDGE of the answers, still bottoms out at ±5.0%.\n\nHalf our remaining error is irreducible.', {
    x: 8.4, y: 4.85, w: 4.3, h: 1.9, margin: 0,
    fontFace: BODY, fontSize: 10.5, color: MUTED, lineSpacing: 14,
  })
  s.addNotes('Both harnesses run live from the Scorecard view in the app. Nothing is precomputed.')
}

/* ═══════════════════════════ 11 · the refusal ════════════════════════════ */
{
  const s = slide()
  heading(s, 'The line we would not cross', 'We refused to ship the thing that beats your metric.')

  s.addText('The risk-score criterion grades on RELATIVE error. Overstating a LOW costs 250%. Understating a CRITICAL costs 22%.\nThe mathematically optimal strategy is therefore to guess LOW on everything.', {
    x: 0.6, y: 1.85, w: 12.1, h: 0.7, margin: 0,
    fontFace: BODY, fontSize: 13.5, color: MUTED, lineSpacing: 19,
  })

  card(s, 0.6, 2.8, 5.95, 1.5)
  s.addText('What we ship', { x: 0.95, y: 2.98, w: 5.2, h: 0.3, margin: 0, fontFace: BODY, fontSize: 12, bold: true, color: MUTED })
  s.addText('±14.8%', { x: 0.95, y: 3.32, w: 2.4, h: 0.55, margin: 0, fontFace: HEAD, fontSize: 26, bold: true, color: INK })
  s.addText('Bayes-optimal, honest', { x: 3.5, y: 3.48, w: 2.8, h: 0.3, margin: 0, fontFace: BODY, fontSize: 11, color: DIM })

  card(s, 6.75, 2.8, 5.95, 1.5, RAISE)
  s.addText('What would score better', { x: 7.1, y: 2.98, w: 5.2, h: 0.3, margin: 0, fontFace: BODY, fontSize: 12, bold: true, color: CRIT })
  s.addText('±13.4%', { x: 7.1, y: 3.32, w: 2.4, h: 0.55, margin: 0, fontFace: HEAD, fontSize: 26, bold: true, color: CRIT })
  s.addText('Guess LOW. Game the loss.', { x: 9.65, y: 3.48, w: 2.9, h: 0.3, margin: 0, fontFace: BODY, fontSize: 11, color: DIM })

  card(s, 0.6, 4.6, 12.1, 1.05, RAISE)
  s.addText('MATCH MODE: optimistic  (guess LOW to beat the metric)   <-- WE REFUSE TO SHIP THIS', {
    x: 0.95, y: 4.6, w: 11.4, h: 1.05, margin: 0,
    fontFace: MONO, fontSize: 12.5, bold: true, color: GOLD, valign: 'middle',
  })
  s.addText('— printed by our own evaluation harness, every run', {
    x: 0.6, y: 5.72, w: 12.1, h: 0.3, margin: 0,
    fontFace: BODY, fontSize: 11, italic: true, color: DIM,
  })

  s.addText('A scanner that under-reports severity to flatter a scorecard is the precise failure this problem statement exists to prevent.\nWe are not going to commit it in order to win a point.', {
    x: 0.6, y: 6.25, w: 12.1, h: 0.75, margin: 0,
    fontFace: HEAD, fontSize: 14, bold: true, color: INK, lineSpacing: 21,
  })
  s.addNotes('Deliver this slowly. It is the most memorable thing in the deck.')
}

/* ═══════════════════════════════════ 12 · close ══════════════════════════ */
{
  const s = slide()
  s.addShape(pres.ShapeType.ellipse, { x: 9.4, y: 3.4, w: 6.4, h: 6.4, fill: { color: AMBER, transparency: 93 } })

  s.addText('Everyone will show you a tool\nthat lists what is in an SBOM.', {
    x: 0.9, y: 1.55, w: 11.2, h: 1.2, margin: 0,
    fontFace: HEAD, fontSize: 27, color: MUTED, lineSpacing: 38,
  })
  s.addText('This one tells you which applications are\nactually hit, and how it got in.', {
    x: 0.9, y: 2.95, w: 11.2, h: 1.2, margin: 0,
    fontFace: HEAD, fontSize: 27, bold: true, color: INK, lineSpacing: 38,
  })
  s.addText('And when we pointed it at the real data, it found that the data contradicts itself,\nproved it, and said so on the front page — instead of quietly scoring 26%.', {
    x: 0.9, y: 4.35, w: 11.2, h: 0.8, margin: 0,
    fontFace: BODY, fontSize: 14, color: AMBER, lineSpacing: 21,
  })

  const links = [
    ['Repository', 'github.com/harish-88279/SG-Hackathon'],
    ['Documentation', 'docs/DOCUMENTATION.md  ·  docs/DATA_DEFECT.md'],
    ['Run it', 'start.bat   →   localhost:8000'],
  ]
  links.forEach(([k, v], i) => {
    const y = 5.55 + i * 0.42
    s.addText(k.toUpperCase(), {
      x: 0.9, y, w: 1.9, h: 0.3, margin: 0,
      fontFace: BODY, fontSize: 10, bold: true, color: DIM, charSpacing: 1,
    })
    s.addText(v, {
      x: 2.9, y, w: 9.2, h: 0.3, margin: 0,
      fontFace: MONO, fontSize: 11.5, color: MUTED,
    })
  })
  s.addNotes('Five out of five on clean data. Three of five on data where two of the criteria are provably unsatisfiable. And we refused to ship the estimator that games the metric.')
}

pres.writeFile({ fileName: process.argv[2] || 'SBOMGuard-Presentation.pptx' })
  .then((f) => console.log('wrote ' + f))
