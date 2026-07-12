# SBOMGuard — demo video script

**Target: 5:00.** A 3:00 cut is marked with ✂ — drop those sections and it still lands.

Everything below is a real number from the running system. Nothing here is a claim you
can't put on screen.

---

## Before you record

```
D:\SG hackathon\restart.bat
```

Wait for the browser to open at `localhost:8000/ui`. Then:

- **Browser zoom to 100%** (Ctrl+0). At any other zoom the graph columns look cramped.
- **Close every other tab.** The tab bar is in frame.
- Have a second tab ready on `localhost:8000/docs` (the API surface — one flash of it at the
  end is worth more than a sentence about it).
- Have a terminal ready in `D:\SG hackathon` for the eval runs.
- Record at 1080p minimum. The graph labels are 10.5px; below 1080 they mush.

**Do not narrate the UI.** Never say "here you can see the dashboard." Say what the number
*means*. The judges can see that it's a dashboard.

---

## The spine of the story

There is one argument, and every section is a beat in it:

> Everyone can list what's in an SBOM. Almost nobody can say **which of our applications are
> actually affected, and how the thing got in.** That's a graph problem, not a list problem —
> and when we ran it against the real supplied data, the data turned out to contradict itself,
> which is a *finding*, not an excuse.

If you only have three minutes, that's the whole video: **blast radius → the path → the defect.**

---

## 0:00 – 0:35 · The question

*Land on the War room. Do not touch anything yet.*

> "December 2021. Log4Shell drops on a Friday. Every security team on earth is asked one
> question — *which of our applications are affected?* — and almost none of them can answer it,
> because nobody knows what's actually inside their own software.
>
> That question is what this is built to answer. Not 'what packages do we have' — everyone can
> print that list. **Which apps are hit, and how did it get in.**"

*Gesture at the header strip: **500 components · 347 at risk · 200 CVEs**.*

> "Ten applications, five hundred components, two hundred CVEs. Let's ask it."

---

## 0:35 – 1:30 · Blast radius — the money shot

*The CVE is already in the box. Click **Find the blast radius**.*

Read the headline off the screen. **This sentence is the demo.** Don't paraphrase it:

> **"6 of 10 applications are affected. 1 of them is exposed ONLY through transitive
> dependencies — no engineer on those teams ever chose this library, and no review of direct
> dependencies would have found it."**

Then stop talking for a beat. Let that sit.

> "That last clause is the whole problem. That team could audit every dependency they
> deliberately added and come up clean — and still be vulnerable. A list can't tell you this.
> Only a graph can."

*Point out that these headline CVEs are **computed from the loaded estate** — nothing is
hardcoded. If a judge swaps the data, the front page changes.*

---

## 1:30 – 2:30 · How it got in — the graph

*Click **Graph** in the sidebar.*

> "Same question, drawn. Depth is the x-axis. The application on the left. Column one is code
> somebody on this team actually **chose**. Everything to the right of that **arrived
> uninvited** — and the further right it sits, the fewer people knew it was there at all."

*Hover a red node at hop 2. Its route home lights up.*

> "Hover anything and it lights the route it took to get in. That red line is the answer to
> 'how'."

Three things to say while it's on screen — each is a real engineering decision, and judges
notice them:

1. **"It doesn't draw everything."** 500 nodes is a texture, not a picture. It draws the
   components that carry risk plus the hops needed to reach them — because *those hops are the
   answer*. Clean components are one click away (*click **Everything**, then click back*).
2. **The dashed arcs** — a library reachable by two different paths. It has to be fixed in
   both. Patch one and the "patched" library is quietly still vulnerable.
3. **Depth is recomputed by traversal**, never trusted from the SBOM's own depth column.

✂ *If cutting to 3:00, keep the hover and point 1. Drop 2 and 3.*

---

## 2:30 – 3:20 · The finding — where this stops being a normal submission

*Scroll back to the War room. Land on the amber banner.*

> "Now the part I actually want you to look at.
>
> We ran this against **your** supplied dataset. And on load, our data-quality control fired."

Read the banner. Then give the proof — **say the specific numbers, not 'the data was messy'**:

> "Strict version-range matching recovers only **25.6%** of the vulnerabilities this dataset's
> own labels declare. So we checked why.
>
> `log4j-api`'s CVE affects versions **4.7.0 to 4.10.0**. Version **4.8.3 — inside that range —
> is labelled CLEAN**. Versions **2.3.3 and 5.11.1 — both outside it — are labelled
> VULNERABLE**.
>
> A clean version sits strictly *between* two vulnerable ones. **No version-based rule of any
> kind can reproduce that.** Fifteen libraries show the same pattern. Those labels were
> generated by library *name*, not by version."

> "We didn't discover that by staring at CSVs. The tool found it, told us, adapted its matcher,
> and put it on the front page — rather than silently scoring 26% and pretending.
>
> **Noticing that your input contradicts itself is the governance job.**"

---

## 3:20 – 4:10 · The scores, and the honest part

*Cut to the terminal.*

```
python eval\self_evaluate.py
```

> "Against internally-consistent data — same engine, no changes — **five out of five**."

```
python eval\evaluate_official.py
```

> "Against the supplied data: **three of five**. And I want to be precise about the two that
> fail, because they **cannot both be satisfied**. That's arithmetic, not an excuse.
>
> 301 dependencies carry a CVE. 176 are labelled risky, 125 clean — and *nothing distinguishes
> them*. So recall and false-positive rate are welded together: **85% recall forces 33% false
> positives. Holding false positives under 20% caps recall at 51%.**
>
> We chose recall. In security, a missed CVE costs more than a re-checked one."

**The line that wins the room** — deliver it slowly:

> "The risk-score metric grades on *relative* error. Which means the mathematically optimal
> strategy is to **guess LOW on everything**. We built that estimator. We measured it. It scores
> better. It's in the repo, quarantined, with a comment saying it must never ship.
>
> **We refused to ship the thing that beats your metric.**"

---

## 4:10 – 4:45 · It's a product, not a demo ✂

*Fast. Three clicks, ~10 seconds each. Don't linger.*

- **Fix plan** — "Not a sorted table. Ordered by what actually reduces risk per unit of work."
- **Build gate** — "Same engine in CI. `strict`, `balanced`, `permissive`. This blocks a merge."
- **Ingest SBOM** — "Drop in CycloneDX or SPDX. It walks the `dependencies` and `relationships`
  graph, not the flat component list — which is the reason it finds transitive flaws at all."

*Flash the `/docs` tab for two seconds.*

> "29 endpoints. 41 tests. And every API here is **free-tier — no credit card anywhere**.
> OSV.dev needs no key at all. The narratives run on Groq or Gemini's free tier, and fall back
> to a deterministic offline engine when there's no key — so the demo never depends on somebody
> else's uptime."

---

## 4:45 – 5:00 · Close

> "Every team in this room will show you a tool that lists what's in an SBOM.
>
> This one tells you **which applications are actually hit, and how it got in** — and when we
> pointed it at the real data, it found that the data contradicts itself, proved it, and said so
> on the front page instead of quietly scoring 26%.
>
> **Five out of five on clean data. Three of five on data where two of the criteria are provably
> unsatisfiable. And we refused to ship the estimator that games the metric.**
>
> That's SBOMGuard."

---

## What NOT to do

- **Don't** walk through every screen. Six screens shown shallowly beats nothing; three shown
  *deeply* beats six.
- **Don't** apologise for 3/5. You are not defending a low score — you are presenting a finding.
  Tone matters more than words here. Say it like a result, because it is one.
- **Don't** say "as you can see." Say the number.
- **Don't** scroll while talking. Land, stop, speak, move.
- **Don't** demo the AI/ML tab unless asked. It's real (RandomForest + KMeans), but it is the
  least differentiated thing here, and it will eat the time the *finding* needs.

## If a judge asks "why only 3/5?"

> "Because two of your five criteria are mutually unsatisfiable on your data, and I can show you
> the arithmetic in thirty seconds. Same engine gets 5/5 the moment the labels agree with the
> version ranges. The gap isn't the engine — it's the dataset, and we're the only ones who
> checked."
