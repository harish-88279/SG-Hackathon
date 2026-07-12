# SBOMGuard — Frontend

**React 18 · Tailwind CSS · Vite**

The dashboard is a compiled single-page app. It is **already built** — the production bundle lives in
`src/sbomguard/static/ui/` and is served by FastAPI at `/ui/`. You do **not** need Node to run or demo
the project.

```bash
python run.py     # that's it — the UI is bundled
```

## Why it is pre-compiled

The bundle has **no CDN dependency and no network requirement**. React, Tailwind and Cytoscape are all
compiled into two files.

That is deliberate. Half the hackathon dashboards in the room will be pulling React and Tailwind from a CDN
via `<script>` tags — and the moment the venue wifi wobbles, their demo is a white screen in front of the
judges. Ours renders from disk.

## Only if you want to change the UI

```bash
cd frontend
npm install
npm run dev      # hot-reloading dev server on :5173, proxied to the API on :8000
npm run build    # rebuild
```

After `npm run build`, copy the output into the Python package so FastAPI serves it:

```bash
cp -r dist/* ../src/sbomguard/static/ui/
```

## Structure

```
src/
  main.jsx              mount
  App.jsx               shell: sidebar, header stats, view routing, Explain-mode toggle
  api.js                typed client for the FastAPI backend
  lib.jsx               severity palette, plain-English glossary, Explain-mode context
  components/
    ui.jsx              Card · Badge · Kpi · Info tooltip · Button · Select · Loading · Error
    Charts.jsx          Donut · Legend · BarList · Gauge  (hand-rolled SVG — no chart library)
  views/
    Overview.jsx        WAR ROOM — the CVE search and blast radius. The demo centrepiece.
    Findings.jsx        priority queue + finding drawer
    GraphView.jsx       Cytoscape dependency graph
    Remediation.jsx     the fix plan
    Intelligence.jsx    risk archetypes · ML early warning · cross-app leverage
    Compliance.jsx      per-control evidence
    Gate.jsx            CI/CD policy gate
    UploadView.jsx      CycloneDX / SPDX ingestion
    Proof.jsx           the scorecard
```

## The one design decision worth explaining

**Explain mode** (the toggle at the bottom of the sidebar, **on by default**).

The judges scoring this are not all application-security engineers. A dashboard that says
*"CVSS 10.0 · transitive · depth 3 · unreachable"* is precise and completely opaque to half the room.

So every panel carries a plain-English note that appears when Explain mode is on:

> *"Look at the four priority scores — they are all different, for the same flaw. That is the whole idea.
> The identical vulnerability is a five-alarm fire in the payments system and a scheduled chore in an
> internal document service. A tool that gives them the same number sends your engineers to the wrong fire."*

Turn it off and you get the dense professional console an actual analyst wants. Turn it on and a
non-specialist can follow the entire argument unaided. Same data, two audiences, one toggle.

Individual jargon terms also carry a `?` tooltip (`Info` in `components/ui.jsx`), backed by the glossary in
`lib.jsx` — hover *transitive*, *reachable*, *CVSS*, *blast radius* and so on.

## Charts

There is no charting library. The donut, gauges and bar lists are ~120 lines of hand-written SVG in
`components/Charts.jsx`. That keeps the bundle small, avoids a heavy dependency in a project that is *about*
dependency risk, and gives exact control over the look.

## Fallback

The original vanilla-JS dashboard is still served at **`/legacy`**. If the React bundle were ever missing,
the demo still runs. Belt and braces.
