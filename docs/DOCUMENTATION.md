# SBOMGuard — Detailed Documentation

**Société Générale GRC Hackathon · PB-10 · Software Supply Chain Risk Analyzer**

**Submitted by**

| Name | Roll number |
|---|---|
| Harish HJ | 23PC19 |
| S Murali Krishna | 23PC31 |

Repository: <https://github.com/harish-88279/SG-Hackathon>

This is the submission document required by the brief. It covers the three things the brief
names: **the platform's architecture**, **the analysis algorithms**, and **the user
interface design** — in that order, followed by the evaluation and the one finding that
matters more than any of them.

Deeper treatments live alongside this file and are linked from each section, so nothing
below is repeated twice.

---

## Contents

1. [The problem, stated precisely](#1-the-problem-stated-precisely)
2. [Architecture](#2-architecture)
3. [Analysis algorithms](#3-analysis-algorithms)
4. [User interface design](#4-user-interface-design)
5. [The AI/ML layer](#5-the-aiml-layer)
6. [The data-quality control, and what it found](#6-the-data-quality-control-and-what-it-found)
7. [Evaluation](#7-evaluation)
8. [Running and deploying it](#8-running-and-deploying-it)
9. [What we deliberately did not do](#9-what-we-deliberately-did-not-do)

---

## 1. The problem, stated precisely

In December 2021, Log4Shell landed. Every security team on earth was asked one question —
*which of our applications are affected?* — and almost none could answer it inside a week.
Not because the vulnerability was hard to understand. Because **nobody knew what was
actually inside their own software.**

That is the problem PB-10 sets, and it is worth being precise about why it is hard, because
the difficulty is not where people assume.

Listing the contents of an SBOM is trivial. Every submission will do it. The hard parts are:

**Reachability, not presence.** A CVE in your dependency file is not a vulnerability in your
product. It matters only if it is *reachable* — and reachability is a property of the
dependency **graph**, not of the dependency **list**. A flat list cannot answer "which of my
applications are affected", because the affected component may be four hops away from
anything a human chose.

**The thing nobody chose.** In our estate, 96 of 500 components carry a transitive
vulnerability. Those teams could audit every dependency they deliberately added, come up
clean, and still be exposed. This is what a supply-chain attack *is*, and it is precisely
what an inventory that stops at direct dependencies cannot see.

**Suppression is harder than detection.** Finding CVEs is easy. Deciding which ones a human
should actually spend Tuesday on is the entire job — and a scanner that cries wolf gets
switched off, which is worse than having no scanner at all.

SBOMGuard is built around those three facts.

---

## 2. Architecture

### 2.1 Shape

A single Python process. No database, no message queue, no external service required to
start. The estate is loaded, the graph is built once, and everything after that is a
traversal.

```
                    ┌─────────────────────────────────────────────┐
   CSV / JSON  ───► │  ingest.py                                  │
   CycloneDX   ───► │  parse, normalise, sniff format             │
   SPDX        ───► │  walk dependencies[] / relationships[]      │
                    └──────────────────┬──────────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────────┐
                    │  official.py — DATA-QUALITY CONTROL         │
                    │  Does affected_versions agree with the      │
                    │  labels? If not, say so and adapt.          │
                    └──────────────────┬──────────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────────┐
                    │  graph.py — networkx DiGraph                │
                    │  true_depth() by traversal, never trusted   │
                    │  paths_to() · blast_radius() · diamonds()   │
                    └──────────────────┬──────────────────────────┘
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        ▼                              ▼                              ▼
  ┌───────────┐              ┌──────────────┐              ┌────────────────┐
  │ detectors │              │  scoring.py  │              │  intel/        │
  │ vuln      │              │  risk_score  │              │  classifier    │
  │ licence   │─────────────►│  priority    │◄─────────────│  clustering    │
  │ maintain. │              │  suppression │              │  narrative     │
  └───────────┘              └──────┬───────┘              │  OSV.dev       │
                                    │                      └────────────────┘
                    ┌───────────────▼─────────────────────────────┐
                    │  api.py — FastAPI, 31 endpoints             │
                    │  + the pre-built SPA at /ui                 │
                    └─────────────────────────────────────────────┘
```

### 2.2 Modules

| Module | Lines | Responsibility |
|---|---:|---|
| `versions.py` | 140 | Tolerant version parsing; half-open range membership |
| `graph.py` | 362 | The dependency DiGraph. Paths, depth, blast radius, diamonds |
| `detectors.py` | 356 | Vulnerability, licence and maintenance detection |
| `scoring.py` | 526 | The two-score model, suppression, application roll-up |
| `official.py` | 325 | Adapter for the real SG data + the data-quality control |
| `ingest.py` | 546 | CSV / JSON / CycloneDX / SPDX parsing |
| `analyzer.py` | 302 | Orchestration; picks the matcher based on the data audit |
| `api.py` | 787 | HTTP surface; serves the SPA |
| `intel/` | — | Classifier, clustering, narratives, OSV, policy gate |

~6,500 lines of Python, ~2,450 of JSX, 41 tests.

### 2.3 Performance

Measured on the 500-component estate, not estimated:

| Operation | Time |
|---|---:|
| Full estate analysis (500 deps, 200 CVEs, 10 apps) | **46 ms** |
| One blast-radius query | **0.08 ms** |
| 100 path traversals | 61 ms |

The graph is built once at startup and held in memory. This is why the war-room question is
answered instantly rather than by a scan — and it is why the container runs in **191MB**,
including the live evaluation harnesses.

Deeper: [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## 3. Analysis algorithms

### 3.1 Version matching, and the trap in it

A CVE affects a **half-open interval**: `[introduced, fixed)`. The fix version itself is not
vulnerable — that is the entire point of a fix.

```python
def in_range(version, introduced, fixed) -> bool:
    if introduced and Version(version) < Version(introduced): return False
    if fixed      and Version(version) >= Version(fixed):     return False
    return True
```

Two details do real work here:

**`fixed is None` means "no fix has ever shipped"** — affected *forever* — not "unknown".
Treating it as unknown silently drops the most dangerous class of finding: the vulnerability
with no patch. In our estate there are 47 of those.

**Versions are not strings.** `"2.9.9" > "2.9.10"` is `True` lexicographically and `False`
in reality. A naive string comparison marks a vulnerable component clean. This is the single
most common bug in home-grown SBOM tooling, and it is why `versions.py` exists at all rather
than a one-line comparison.

### 3.2 The graph

A `networkx.DiGraph`. Nodes are namespaced per application — `lib::APP-001::lodash@4.17.15`
— so the same library at the same version in two applications is two nodes. It has to be:
its *reachability* and therefore its *risk* differ per application.

Four operations carry the product:

- **`true_depth()`** — recomputed by traversal from the application root. **The SBOM's own
  depth column is never trusted.** It is an assertion by whoever generated the file; the
  graph is the evidence.
- **`paths_to(library)`** — every route a component took into an application. This is the
  answer to *how did it get in*.
- **`blast_radius(library)`** — every application reachable to a component. This is the
  answer to *who is hit*.
- **`diamonds()`** — components reachable by **more than one path** inside a single
  application. This is compounded *remediation cost*, not compounded severity: you must fix
  every route, and fixing one parent silently leaves the other in place. That is how a
  "patched" library quietly stays vulnerable.

### 3.3 Two scores, because there are two questions

Most scanners emit one number, which then has to answer two incompatible questions. We emit
two.

**`risk_score` — how bad is this thing?** Anchored on severity, and *clamped* so context can
only nudge it:

```python
SEVERITY_ANCHOR = {CRITICAL: 90, HIGH: 70, MEDIUM: 45, LOW: 20}
RISK_CLAMP = (0.92, 1.08)          # context may move it +/-8%. No more.
```

A CRITICAL cannot be talked down into a MEDIUM by a flattering context multiplier. That is a
*property of the model*, enforced by the clamp, not a hope.

**`priority_score` — should I do this on Tuesday?** Free to move a long way, because that is
what triage means:

```python
PRIORITY_CLAMP = (0.40, 3.00)
```

It multiplies in: internet-facing, cardholder data, business criticality, known-exploited
(KEV), reachability, fix availability, blast radius. A MEDIUM on an internet-facing
payment system outranks a CRITICAL in an unreachable internal batch job — **and it should.**

Application scores never average:

```python
app_score = 0.70 * worst_component + 0.30 * saturating_volume
```

Averaging is how one catastrophic component gets diluted into an amber sea by forty healthy
ones. The worst thing dominates, and volume is a bounded tail term.

### 3.4 Licence analysis, which is a legal question and not a string match

The naive version — "GPL is bad" — is wrong, and confidently wrong is worse than silent.

- **GPL in a non-distributed internal app is *not* a violation.** Copyleft attaches on
  *distribution*. An internal service is not distributed.
- **AGPL in the same app *is* a violation.** Network copyleft attaches on *use over a
  network*, which is exactly what an internal service does.
- **LGPL, dynamically linked and unmodified, is fine.** Statically linked, or modified, is
  not.
- **UNKNOWN is treated as worst-case.** An unknown licence grants **no rights at all**. It
  is not a gap in the data to be shrugged at; it is a component you have no legal right to
  ship.

The distinction between the first two bullets is the difference between a legal opinion and
a `grep`.

### 3.5 Suppression — the part that decides whether anyone uses this

A finding is suppressed when it is genuinely not actionable:

- the build carries a **backported fix** (`patched_in_build`),
- the **vulnerable function is never called** (`vulnerable_function_used = false`),
- the component is unreachable from any entry point.

On the synthetic corpus this defuses **19 of 19 planted false-positive traps** — versions
that match a CVE range but carry a backported patch — while missing zero true positives.

This is the hard half of the problem. Detection is arithmetic. **Suppression is judgement,
and getting it wrong in either direction destroys the tool**: cry wolf and it gets switched
off; over-suppress and it is worse than useless.

---

## 4. User interface design

The brief asks explicitly for the interface design, so here is the reasoning, not just a
screenshot list.

### 4.1 The organising principle

**The dashboard is built around a question, not around the data.** The landing view is
called the **War room**, and it asks the only question that matters at 2am: *a CVE just
dropped — who is hit?*

Almost every security dashboard instead opens with a table of everything, sorted by
severity, and leaves the human to do the reasoning. That is a data dump wearing a dashboard's
clothes. Ours opens with a text box and a button that says **Find the blast radius**.

### 4.2 The nine views, grouped by what you are trying to do

| Group | View | Answers |
|---|---|---|
| **Respond** | War room | A CVE dropped. Who is hit? |
| | Priority | What do I do first? |
| | Graph | How did it get in? |
| | Fix plan | What single action removes the most risk? |
| **Understand** | Intelligence | What patterns run across the estate? |
| | Compliance | What is our legal exposure? |
| **Enforce** | Build gate | Should this merge be blocked? |
| | Ingest SBOM | Score *my* SBOM, not the demo's. |
| | Scorecard | Prove any of this. |

The grouping is deliberate: **Respond → Understand → Enforce** is the order of urgency, and
therefore the order of the sidebar.

### 4.3 Colour is signal, never decoration

A component gets a colour only if that colour tells you something you would otherwise have
to read. Severity has a fixed palette (critical → clean); everything else is neutral. The
single accent — amber — is reserved for *the thing you should touch next*.

The failure mode this avoids: a uniform sprinkle of red reads as "everything is a bit bad,"
which is how a security dashboard teaches people to ignore it.

### 4.4 The graph: why columns, and not the beautiful thing

The first version drew the estate as **concentric orbits** — the application at the centre,
depth as radius. It was elegant, and it was wrong. It produced 500 unlabelled dots on a
circle: you could see that something was burning and never once see *what*, because **a ring
gives a label nowhere to live.** A picture you cannot read is not a picture.

It is now **columns**. Depth is the x-axis. Column zero is the application. Column one is
code somebody on the team actually **chose**. Everything to the right of that **arrived
uninvited**, and the further right it sits, the fewer people knew it was there at all.
Labels sit beside their node, horizontally, always on — which is the entire reason to prefer
this layout to the prettier one.

Three further decisions:

- **It does not draw everything.** 500 nodes is a texture, not a visualisation. The default
  view draws only components that carry risk *plus the hops needed to reach them* — because
  those hops **are** the answer to "how did this get in". Clean components are one click
  away and, deliberately, not the first thing you see.
- **It is a tree, not a hairball.** A spanning tree gives every component exactly one drawn
  route home. The routes that were dropped come back as faint **dashed arcs** — because a
  library reachable two ways must be fixed two ways, and hiding that is how a "patched"
  dependency stays vulnerable.
- **Scroll-to-zoom was removed.** It hijacked page scrolling: scrolling *down the page* with
  the pointer over the canvas silently shrank the graph to a smear. A control that fires when
  the user was not aiming at it is not a feature. Zoom is three explicit buttons.

### 4.5 Plain English, as a first-class mode

A toggle in the sidebar rewrites the interface for a non-specialist. "Transitive dependency"
becomes "a component nobody on your team chose." This is not a tooltip afterthought — GRC
work is done by risk officers and auditors as much as by engineers, and a tool only they
cannot read is a tool that generates tickets nobody trusts.

### 4.6 Everything is computed, nothing is hardcoded

The headline CVEs on the war room are derived from **the estate that is actually loaded**.
Swap the dataset and the front page changes. There is no demo path with a special case in
it, and this is checkable: upload your own SBOM and the whole dashboard follows.

The front end is a **pre-built React + Tailwind SPA** served from the Python process. It
needs neither Node nor a CDN at runtime. A demo that can be taken down by someone else's
outage is not a demo — a point worth making out loud in a *supply-chain* project.

---

## 5. The AI/ML layer

Three components, and an honest account of what each is worth.

**The classifier** (`RandomForest` / `GradientBoosting`) is a *second opinion*, not the
adjudicator. The rules decide; the model is asked whether it agrees, and disagreement is
surfaced rather than hidden. A model that silently overrides a deterministic CVE match would
be a downgrade, not an upgrade.

**Clustering** (`KMeans` over TF-IDF features) turns 263 individual findings into a handful
of **campaigns** — "these 40 findings are one Spring upgrade" — because a human fixes
campaigns, not rows.

**Narratives** run on Groq or Gemini free tiers when a key is present, and fall back to a
**deterministic offline template engine** when there is none. Offline is the *default*, not
the fallback of last resort: a governance tool whose explanations vary between runs is not
auditable, and a demo that depends on someone else's rate limit is not a demo.

**OSV.dev** provides live CVE enrichment and requires **no API key at all**.

Deeper: [`AI_ML_APPROACH.md`](AI_ML_APPROACH.md).

---

## 6. The data-quality control, and what it found

**This is the most important section in this document.**

Before scoring anything, SBOMGuard audits its own input. On the official SG dataset, that
control fired: **strict version-range matching recovers only 25.6% of the vulnerabilities
the dataset's own labels declare.**

So we asked why. One library settles it:

```
log4j-api   (CVE-2022-1041 affects [4.7.0 .. 4.10.1))

  v2.3.3     outside the affected range   ->   labelled VULNERABLE
  v4.8.3     INSIDE  the affected range   ->   labelled CLEAN
  v5.1.3     outside the affected range   ->   labelled VULNERABLE
  v5.11.1    outside the affected range   ->   labelled VULNERABLE
```

Every version **inside** the affected range is labelled clean. Every version **outside** it
is labelled vulnerable. The version predicate is not approximately wrong — it is running
exactly **backwards**, and no monotone predicate on versions can be false inside an interval
and true outside it.

**Therefore the labels are not a function of the version at all.** They were generated from
the library *name*, and the version column was filled in independently. Fifteen libraries
show the same pattern. Statistically, `version_in_range` shifts P(vulnerable) by 0.05
against a base rate of 0.585 — noise.

SBOMGuard detects this **on load**, falls back to library-name matching so the scan still
runs, and **puts it on the front page** rather than silently scoring 26% and pretending.

Noticing that your input contradicts itself is the governance job.

Deeper: [`DATA_DEFECT.md`](DATA_DEFECT.md).

---

## 7. Evaluation

Two harnesses. Both run live from the **Scorecard** view — nothing is precomputed.

| Criterion | Target | Official SG data | Consistent data |
|---|---|---|---|
| Vulnerability detection | > 85% | **100%** ✓ | **100%** ✓ |
| Transitive resolution | = 100% | **100%** ✓ | **100%** ✓ |
| Licence conflict detection | > 90% | **100%** ✓ | **100%** ✓ |
| False-positive rate | < 20% | **42%** ✗ | **0%** ✓ |
| Risk-score accuracy | ±10% | **±14.8%** ✗ | **±7.2%** ✓ |
| | | **3 / 5** | **5 / 5** |

Same engine. Same code. The only variable is whether the data agrees with itself.

### The two failures are arithmetically unreachable, not unfixed

301 dependencies carry a CVE-bearing library. 176 are labelled risky, 125 clean — and
**nothing in the inputs separates them**. So flagging a fraction *f* gives `recall = f` and
`FP rate = f × 0.39`:

- to reach **85% recall** → false positives hit **33%** (target: < 20%)
- to hold **20% false positives** → recall drops to **51%** (target: > 85%)

**You may have one. You may not have both.** We chose recall, because in security a missed
CVE costs more than a second look at a clean library.

On risk-score accuracy: each dependency is labelled against a CVE drawn *at random* from its
library's set, so severity is a coin-toss. An **oracle** — allowed to pick any score per
library, *with full knowledge of the answers* — bottoms out at **±5.0%**. Half our remaining
error is irreducible.

### The estimator we refused to ship

The risk metric grades on **relative** error. Overstating a LOW costs 250%; understating a
CRITICAL costs 22%. The mathematically optimal strategy is therefore to **guess low on
everything**.

We built it. We measured it: **±13.4% — better than what we ship.** It is in `scoring.py`,
quarantined, with a comment saying it must never ship, and our own evaluation harness prints:

```
MATCH MODE: optimistic  (guess LOW to beat the metric)  <-- WE REFUSE TO SHIP THIS
```

A scanner that under-reports severity to flatter a scorecard is the precise failure this
problem statement exists to prevent. We are not going to commit it in order to win a point.

---

## 8. Running and deploying it

**Locally** — `start.bat`, then <http://localhost:8000>. No API key, no signup, no network.

**Docker** — `docker build -t sbomguard . && docker run -p 8000:8000 sbomguard`

**Hosted** — Render free tier. See [`DEPLOY.md`](DEPLOY.md).

**Tests** — `pytest tests/` (41 passing).
**Evaluation** — `python eval/evaluate_official.py` and `python eval/self_evaluate.py`.

Everything is free by construction. OSV.dev needs no key at all; the LLM providers are
free-tier and optional. **No credit card is required anywhere in this project.**

---

## 9. What we deliberately did not do

Stating the road not taken is part of an honest architecture document.

- **We did not fit the risk model harder to close the ±14.8% gap.** Past a point you are
  fitting noise, and the noise here is a coin-toss by construction.
- **We did not let the ML model override deterministic detection.** A CVE range match is
  arithmetic. A model that "corrects" arithmetic is a downgrade wearing a lab coat.
- **We did not make the LLM load-bearing.** Explanations that vary between runs are not
  auditable, and this is a governance tool.
- **We did not ship the optimistic estimator**, even though it scores better.

---

*SBOMGuard — Société Générale GRC Hackathon, PB-10.*
*Everything in this document is measured against the running system. Nothing is estimated.*
