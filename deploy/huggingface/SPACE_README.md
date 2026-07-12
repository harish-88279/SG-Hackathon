---
title: SBOMGuard
emoji: 🛡️
colorFrom: red
colorTo: yellow
sdk: docker
app_port: 7860
pinned: false
license: mit
short_description: Which of our applications are actually affected, and how did it get in?
---

# SBOMGuard

**Société Générale GRC Hackathon — PB-10, Software Supply Chain Risk Analyzer.**

A critical vulnerability just dropped. *Which of our applications are affected?* Almost no
organisation can answer that quickly — not because the flaw is hard to understand, but
because nobody knows what is actually inside their own software.

SBOMGuard answers it by walking the dependency **graph**, in milliseconds, including through
components nobody ever chose.

## Start here

1. **War room** — type a CVE, get the blast radius. The headline CVEs are computed from the
   loaded estate; nothing is hardcoded.
2. **Graph** — how it got in. Depth is the x-axis: column one is code somebody chose,
   everything right of it arrived uninvited.
3. **Scorecard** — the five success criteria, scored live against both datasets.

## The finding

We ran this against the official supplied dataset, and our data-quality control fired on
load: strict version-range matching recovers only **25.6%** of the vulnerabilities the
dataset's own labels declare.

The proof takes one library:

```
log4j-api   (CVE-2022-1041 affects [4.7.0 .. 4.10.1))

  v2.3.3     outside the affected range   ->   labelled VULNERABLE
  v4.8.3     INSIDE  the affected range   ->   labelled CLEAN
  v5.1.3     outside the affected range   ->   labelled VULNERABLE
  v5.11.1    outside the affected range   ->   labelled VULNERABLE
```

Every version *inside* the affected range is clean; every version *outside* it is
vulnerable. The version predicate is not approximately wrong — it is running exactly
**backwards**, which no monotone predicate on versions can do. So the labels were not
generated from the versions at all. Fifteen libraries show the same pattern.

**Score: 3/5 on the official data, 5/5 on internally-consistent data — same engine,
unchanged.** And two of those five criteria are *provably* unsatisfiable together on the
supplied data: 176 risky and 125 clean dependencies carry a CVE-bearing library with nothing
separating them, so recall and false-positive rate are welded together. 85% recall forces 33%
false positives.

We also built the estimator that games the risk-score metric by guessing LOW (its loss is
*relative*, so under-reporting pays). We measured it. It scores better. **It is in the repo,
quarantined, and we refused to ship it.**

Noticing that your input contradicts itself is the governance job.

## Free by construction

No API key is required to run any part of this. OSV.dev needs no key at all; the LLM
narratives use Groq or Gemini free tiers when a key is present and fall back to a
deterministic offline engine when it is not. No credit card, anywhere.

Source: <https://github.com/harish-88279/SG-Hackathon>
