# SBOMGuard — the AI/ML approach

*Or: an honest account of what machine learning is actually for here.*

---

## The uncomfortable question

Our deterministic rule engine scores **100% precision and 100% recall** against the ground-truth labels.

So what, exactly, is a machine-learning model for?

A weaker answer is *"the brief said Option A, so we added a random forest."* That is how you end up with a model that is strictly worse than the `if` statement it replaced, reported at 99% accuracy, and worth nothing. We would rather say plainly where ML does not help than pretend it does.

Here is where it does.

---

## 1. The classifier: a second opinion that generalises

### What the rules cannot do

The rule engine can only find a CVE **that is in our database**. By construction, it is blind to:

- a library that has never been scanned before
- a zero-day that has not been published yet
- a package whose CVE exists but whose version range is recorded wrongly upstream (depressingly common in the real NVD)

For all three, the rules confidently report **CLEAN**, and are wrong.

### The design decision that matters

**The classifier never sees the CVE table.**

If we fed it "number of matching CVEs" it would trivially learn `n_cves > 0 → risky`, score 100%, and tell us precisely nothing we did not already know. That is the trap, and most submissions will fall into it.

Instead it looks only at the **shape** of a dependency — and learns the profile of the kind of component that turns out to be dangerous:

| feature group | features |
|---|---|
| **decay** | `age_days`, `age_years`, `is_stale_2y`, `is_stale_4y` |
| **stewardship** | `maintainer_count`, `bus_factor_1`, `has_security_policy`, `log_stars` |
| **position** | `depth`, `is_transitive` |
| **legal** | `license_copyleft_score`, `license_unknown` |
| **consumption** | `is_static_linked`, `is_modified` |
| **exposure** | `app_internet_facing`, `app_handles_pii`, `app_handles_card`, `app_distributed`, `app_proprietary`, `app_criticality_weight` |
| **ecosystem** | `ecosystem_maven`, `ecosystem_npm`, `ecosystem_pypi` |

Gradient-boosted trees. 70/30 stratified split. **Every number below is on the held-out 30%** — reporting training accuracy would be meaningless and every judge knows it.

### Results

| metric | held-out |
|---|---|
| ROC-AUC | **0.993** |
| Precision | **0.986** |
| Recall | **0.911** |
| Accuracy | **0.947** |

Top predictive features: `age_days`, `is_stale_2y`, `log_stars`, `age_years`.

### The output that actually matters is the DISAGREEMENT

Accuracy is not the point. The rules already have that. What the model gives us that rules cannot is a **divergence signal**:

```
rules say CLEAN  +  model says RISKY   →   EARLY WARNING
```

A component with **no CVE on file** whose profile nonetheless matches the components that get breached: old, single-maintainer, buried deep in the tree, sitting in an internet-facing application that handles cardholder data.

**Log4j was on exactly this list in November 2021.** No CVE. Perfect profile. Every rule engine on earth said CLEAN.

This is the audit list you work *before* the CVE is published, not after. It is surfaced in the dashboard as `early_warning`, with a plain-English reason per item.

The inverse divergence — `rules fire, model relaxed` — is surfaced as `over_flagged`, and is a candidate list for rule tuning.

---

## 2. Clustering: turning 263 findings into 3 campaigns

### The problem

Our engine finds ~263 at-risk dependencies. **A list of 263 tickets is not an action plan; it is a reason to give up.** Nobody works a 263-item queue.

### The insight

Those 263 findings are not 263 different problems. They are a handful of recurring **patterns** wearing different names:

- *"old Java XML parser, single maintainer, no patch, buried deep"*
- *"GPL npm package statically linked into a shipped product"*
- *"weaponised RCE in an internet-facing service, patch available"*

### The method

K-means over an 11-dimensional risk feature space (priority, severity rank, age, maintainers, depth, transitivity, copyleft score, exploit maturity, reachability, patch availability, app exposure). **k is chosen by silhouette score, not by taste.**

Each cluster is then **named from what is actually in it** — and each name comes with a remediation *strategy*, because a cluster you cannot act on is just a colour on a chart.

### Output

```
[ 91]  Standard patchable vulnerabilities
       Routine work. Batch the upgrades into the next maintenance release, run the
       regression suite, ship.

[ 46]  Hidden transitive vulnerabilities
       Average 2.4 levels down the tree — nobody chose them, nobody is watching them.
       Fix at the PARENT. Where the parent has not shipped a fixed build, pin the child
       in the lockfile and add a CI check so the pin cannot be silently dropped.

[126]  Abandonware — no CVE yet, no fix later
       Average age 4.1 years, 62% single-maintainer. No vulnerability TODAY. The risk is
       that when one appears, nobody will be there to fix it. Schedule replacement into
       normal sprint capacity now, while it is cheap and nobody is panicking.
```

**263 tickets → 3 campaigns**, each with one owner, one strategy, one decision.

(The remediation playbook does the complementary collapse: grouping by *fix* rather than by *pattern* turns the same 263 findings into 130 concrete actions.)

### A bug worth confessing

The first version named a cluster *"Actively exploited — incident response"* whenever `kev > 0` — i.e. whenever a **single** KEV CVE appeared anywhere in a 126-member cluster. Every cluster came out with the identical name. A cluster name has to describe the *cluster*, not its most alarming single member. It now gates on the cluster's dominant character (`kev_share ≥ 0.30`), and duplicate names are disambiguated by what actually differs between them.

---

## 3. LLM narratives: offline-first, by deliberate design

### The hard requirement

**A live LLM call in a hackathon demo is a liability.** The wifi drops, the free tier rate-limits, the key expires — and your centrepiece dies in front of the judges.

So this is built the other way round.

### The deterministic engine is the DEFAULT

It composes a real analyst narrative from the structured evidence we already computed: the CVE, the exact dependency chain, the blast radius, the exploit status, the reachability verdict, the compliance mapping. It needs **no key, no network, and no luck.**

Here is its unedited output for the Log4Shell finding:

> This is a five-alarm finding. Payments-API is exposed to CVE-2021-44228 (CRITICAL, CVSS 10.0) through org.apache.logging.log4j:log4j-core@2.14.1 — a dependency nobody on the team ever chose. It arrives 3 levels down the tree via org.springframework.boot:spring-boot-starter-logging, which is exactly why a review of direct dependencies would never have found it. The full chain is: Payments-API → spring-boot-starter-web@2.5.4 → spring-boot-starter-logging@2.5.4 → log4j-core@2.14.1.
>
> JNDI features in the Log4j2 lookup substitution do not protect against attacker-controlled LDAP endpoints. Any logged string containing ${jndi:ldap://...} yields unauthenticated remote code execution.
>
> This CVE is being actively exploited in the wild right now, which moves it out of the patch queue and into incident response, a weaponised exploit is publicly available, and the vulnerable function (JndiLookup.lookup) IS reachable from our code path, so the flaw is live.
>
> This is not an isolated problem. The same component is present in 4 applications (2 internet-facing, 1 handling cardholder data), so this should be handled as one coordinated remediation campaign rather than 4 separate tickets.
>
> Remediation is straightforward: upgrade org.apache.logging.log4j:log4j-core from 2.14.1 to 2.17.1. Because the dependency is transitive, the upgrade must be applied at spring-boot-starter-logging — or pinned explicitly if the parent has not yet released a fixed build.
>
> For the audit trail, this finding maps to OWASP A06:2021, NIST-CSF DS-6, EO-14028 SBOM.

**No LLM produced that.** It is composed from structured evidence.

### The LLM is optional enrichment

If a key is present, it rewrites the narrative more fluently and adds judgement. If *anything* goes wrong — no key, timeout, rate limit, malformed response — we fall back silently and the demo continues.

| provider | model | free tier | credit card? |
|---|---|---|---|
| **Groq** | `llama-3.3-70b-versatile` | ~14,400 req/day | **No** |
| **Google Gemini** | `gemini-2.0-flash` | ~1,500 req/day | **No** |
| OpenAI | `gpt-4o-mini` | paid | yes |
| **none** | **template engine** | **unlimited, offline** | **No** |

```bash
export GROQ_API_KEY=...     # optional. Everything works without it.
```

### Prompt discipline

The system prompt forbids the two failure modes that make LLM security output useless:

- **Never invent** a CVE, a version number, or any fact not in the evidence.
- **If the vulnerable function is not reachable, SAY SO and de-escalate.** Crying wolf is how security teams lose credibility.

---

## 4. Live vulnerability data: OSV.dev

Everyone else will scan against the bundled 200-CVE `vulnerability_db.json`. That is fine for the exercise and **completely useless on Monday**, because the real NVD has ~250,000 entries and grows daily.

**OSV.dev** is Google's open vulnerability database (GitHub Security Advisories, PyPA, RustSec, Go, Maven, npm…). Three properties make it the right choice:

- It is **free**
- It requires **no API key at all** — not even a signup
- **No documented rate limit**, and `/v1/querybatch` accepts 1,000 packages per request

`intel/osv_client.py` cross-checks our offline findings against the live database. The output that matters is **`missed_by_local_db`**: real CVEs that OSV knows about and our bundled database does not.

> In a real deployment, that gap **is** the risk. It is the exact set of vulnerabilities you believe you do not have.

Strictly opt-in. The demo runs fully offline by default, because a demo that needs conference wifi is a demo that fails.

---

## 5. Reachability: the signal nobody uses

Every dependency carries `vulnerable_function_used` — is the flawed code path actually callable from our application?

This is the **single biggest source of wasted security effort in the industry.** A CVSS 9.8 in a library whose vulnerable function is never called is a *liability*, not an *emergency*. Teams burn entire sprints patching them while the genuinely exploitable HIGH sits untouched.

So we apply **× 0.35** to the priority of an unreachable flaw — a hard discount.

But we deliberately do **not** zero it out, for two reasons that matter:

1. The dependency is still an **unpatched liability**.
2. It is **one refactor away** from becoming reachable — and then it is a CRITICAL you already shipped.

161 of our findings are present-but-unreachable. They stay in the queue. They just stop shouting.

---

## 6. What we deliberately did NOT do

| technique | why not |
|---|---|
| **Deep learning** | 500 samples. A neural net here is theatre. |
| **Sentence embeddings for CVE matching** | Version ranges are *exact*. Semantic similarity would make a deterministic problem probabilistic — strictly worse. |
| **LLM as the primary detector** | Non-deterministic, unauditable, and it hallucinates CVE numbers. A bank cannot ship that. |
| **Training on CVE-derived features** | The trap. It learns `has_cve → risky`, scores 100%, and adds nothing. |
| **Replacing the rules with a model** | The rules score 100% and are *explainable*. Trading that for 94.7% and a black box would be a downgrade. |

**The honest summary:** the rules do the detection; the ML does the things rules cannot — generalising past the CVE database, finding structure in the noise, and turning a list into a plan.

That is a smaller claim than "we used AI", and it is a true one.
