# SBOMGuard — Demo Script

**Five minutes.** Judges score what they can see. Every beat below earns its time.

Setup: `python run.py` → `http://localhost:8000`. Have a terminal open in a second window.

> **Rehearse three times.** Record a fallback video. If the live demo dies, you show the video and keep talking — you do not debug in front of judges.

---

## 0:00 — The hook (30 seconds)

> *"In December 2021, Log4Shell dropped. Every organisation on earth asked the same question:*
>
> ***'Which of our applications are affected?'***
>
> *For most of them, that took **four days** to answer. Not because Log4Shell was hard to understand — it was public within hours. It took four days because **nobody knew what was actually inside their own software.***
>
> *Watch."*

**Type `CVE-2021-44228` into the War Room box. Hit enter.**

*(Land on this screen. Do not narrate the UI. Let it sit for two seconds.)*

---

## 0:30 — The blast radius (60 seconds)

The screen now shows:

- **4 of 10 applications affected**
- **4 of them transitive-only**
- 2 internet-facing · 1 handling cardholder data
- The exact chains

> *"Four of our ten applications. And look at this line —"*

**Point at the chain:**

```
Payments-API → spring-boot-starter-web@2.5.4
             → spring-boot-starter-logging@2.5.4
             → log4j-core@2.14.1
```

> *"Log4j is **three levels down**. Nobody on the payments team ever chose it. It is in no `pom.xml` that any engineer has ever read. If you grep the manifest for 'log4j', you get **zero results**.*
>
> *This is why it took four days. Every tool that treats dependencies as a **flat list** finds nothing here. We model them as a **graph**, so we find it by reachability — and reachability is **decidable**. If the edges are right, the answer is right. Every time."*

**Point at the green box:**

> *"And one fix — bump log4j to 2.17.1 — clears the CVE across all four applications. That is **one** action, not four tickets."*

---

## 1:30 — The thesis: why CVSS is the wrong number (75 seconds)

**Point at the four priority scores: 99.3 / 98.1 / 97.4 / 96.4**

> *"Same CVE. Same CVSS 10.0. **Four different priorities.** Why?*
>
> *Because CVSS answers 'how bad is this flaw **in the abstract**'. It knows nothing about you. It does not know if the vulnerable function is even called, whether the app is on the public internet, or whether an exploit exists in the wild.*
>
> *So we emit **two** numbers."*

**Click the top finding to open the modal.**

> *"**Flaw: 97.** How bad is this vulnerability — comparable to CVSS, comparable to our ground truth.*
>
> ***Priority: 99.3.** What should I fix **first** — the same flaw, seen through **our** context. Internet-facing. Cardholder data. Exploit weaponised. Vulnerable function reachable.*
>
> *And the multiplier between them — ×2.28 — is **fully itemised** right here."*

**Scroll to the drivers list. Then go to the Priority Queue tab.**

> *"Now look at row five."*

**Point at netty-handler — a HIGH, priority 98.3, outranking several CRITICALs.**

> *"That is a **HIGH**, outranking **CRITICALs**. Because it is weaponised, actively exploited, internet-facing, and reachable.*
>
> *A tool that sorts by CVSS sends an engineer to patch an **unreachable 9.8 in a dev tool** while **that** sits in the payments path. That is the entire thesis of this project, and it is working on screen."*

---

## 2:45 — What we DON'T flag (45 seconds)

> *"The hard part of a scanner is not detecting things. A scanner that flags everything scores **100% recall** and is **worthless** — it gets switched off in week two.*
>
> *The problem statement sets a false-positive target of under 20%. **We are at zero.**"*

**Open a finding with suppressed CVEs (green box in the modal).**

> *"This version sits **inside** a published CVE range. But the build we actually ship carries a **backported fix** — which Debian and Red Hat do constantly. A naive version-matching scanner flags it. We suppress it — **and we still show it**, with the reason.*
>
> *There is a real difference between a tool that lets you **suppress** risk and one that lets you **hide** it."*

**Go to Compliance. Point at a GPL exception.**

> *"Same idea in licensing. A naive matrix says 'GPL equals HIGH RISK' and fires. **It is wrong.** Copyleft attaches on **distribution**. This is an internal-only tool. It never distributes. There is no violation — and we say so.*
>
> *But **AGPL** in the same tool **would** be a violation, because AGPL triggers on **network use**, not distribution. That is the trap that catches teams reasoning by analogy from the GPL. We get it right."*

---

## 3:30 — From findings to a plan (45 seconds)

**Go to the Remediation Playbook tab.**

> *"263 findings. Nobody works a 263-item queue — a list that long is a reason to give up.*
>
> *So we **collapse** it. Group by the **fix** rather than by the finding, and 263 findings become **130 actions** — because one dependency bump fixes the same flaw across several apps at once. The top one clears Log4Shell in four applications at a stroke."*

**Scroll to a REPLACE action with a compensating control.**

> *"And this one matters. **47 of our findings have no upstream patch at all.** There is nothing to upgrade to.*
>
> *Most tools would still say 'upgrade'. That is worse than saying nothing — it burns an engineer's time and their trust. We say **REPLACE**, we name concrete alternatives, and we issue a **compensating control** to hold the line until the replacement ships."*

---

## 4:15 — Teeth (30 seconds)

**Switch to the terminal.**

```bash
python -m sbomguard.cli gate --policy strict
```

*(It prints BLOCK entries and exits 1.)*

```bash
echo $?
# 1
```

> *"Everything I have shown you so far **reports** on risk. Reports do not stop risk from being merged.*
>
> *Log4Shell did not get into those codebases because nobody had a scanner. It got in because **nothing in the pipeline had the authority to say no**.*
>
> *This returns a **UNIX exit code**. Drop it in CI and it **fails the build**."*

---

## 4:45 — The proof (15 seconds)

**Go to the Proof tab. Click "Run the evaluation."**

```
Vulnerability Detection      100.0%   target > 85%      [PASS]
Transitive Resolution        100.0%   target = 100%     [PASS]
License Conflict Detection   100.0%   target > 90%      [PASS]
False Positive Rate            0.0%   target < 20%      [PASS]
Risk Score Accuracy          100.0%   target ±10%       [PASS]

OVERALL: ALL SUCCESS CRITERIA MET
```

> *"All five criteria, measured against the ground-truth labels, reproducible with one command.*
>
> *And three of them are **algorithmic, not statistical**. Transitive resolution is graph reachability. License conflicts are a matrix lookup. Vulnerability detection is a version-range join. **Correct code guarantees them.** We do not hope to hit these numbers — we cannot miss them."*

**Stop. Do not add anything.**

---

## Questions you will get, and the honest answers

**"You generated your own data — isn't that circular?"**

> *"Fair challenge, and it's why we designed it the way we did. We never wrote a label by hand. We built a **world** — libraries with real licenses and dates, CVEs with real version ranges — and then **derived** the labels by observing it. So the labels encode real reasoning, including the nuances: a patched build inside a CVE range is labelled **clean**, and our engine has to work that out independently. The traps are in the data precisely so we can't fake the result. We defuse 19 of 19."*
>
> *"And the alternative was worse. The problem statement's own `sample_data` section is copy-pasted from a different problem — it lists Okta and Azure AD files. There was nothing to use."*

**"Why is your ML model only 94.7% when your rules are 100%?"**

> *"Because they're doing different jobs, and we were careful not to pretend otherwise. The model **never sees the CVE table**. If we fed it 'number of matching CVEs' it would learn `has_cve → risky`, score 100%, and tell us nothing.*
>
> *It predicts risk from the component's **profile** — age, maintainers, depth, exposure. Its value isn't accuracy; it's the **disagreement**. Where the rules see nothing and the model sees danger, you have a component with no CVE that looks exactly like the ones that get breached.*
>
> ***Log4j was on that list in November 2021.** No CVE. Perfect profile."*

**"Does this need an API key?"**

> *"No. Not one. It runs fully offline. Live CVE enrichment uses **OSV.dev** — free, no key, not even a signup. The analyst narratives you saw were composed by a deterministic engine from structured evidence, with no LLM at all. A live LLM call in a demo is a liability, so it's an **optional** enrichment layer — Groq or Gemini, both free tier, both no credit card — and if it fails for any reason we fall back silently."*

**"Would this work on a real codebase?"**

> *"Today. It ingests real **CycloneDX** and **SPDX** JSON — the formats `syft`, `cdxgen` and Trivy actually emit — and walks their dependency **graphs**, not just their component lists. `syft . -o cyclonedx-json | sbomguard gate` works with no translation step."*

**"What would you do with more time?"**

> *"Three things. Real reachability analysis via static call-graph extraction instead of a build-system flag. EPSS scores for exploit **probability** rather than just maturity. And a Slack bot that fires the blast-radius query the moment a KEV CVE is published — because the four days isn't the analysis, it's the time before anyone thinks to ask."*
