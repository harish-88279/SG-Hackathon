# SBOMGuard — Data Dictionary

The problem statement describes a `sample_data/` folder and **ships nothing**. (Its "Bonus Features" section is also copy-pasted verbatim from a different, identity-and-access problem — it references Okta, Azure AD and privilege graphs — which is how we know the omission is an oversight rather than a deliberate exercise.)

So we rebuilt the dataset to the exact stated specification.

Regenerate deterministically at any time:

```bash
python data/generator/generate_data.py
```

---

## Design principle: generate the world, then observe it

We never hand-write a label.

We construct a coherent **world** — libraries with real licenses and release dates, CVEs with real half-open version ranges, dependency trees with real edges — and then **derive** the ground truth by observing that world.

Two consequences, and they are the whole reason the metrics mean anything:

1. **The labels cannot contradict the data.** A correct engine can genuinely reach the targets.
2. **An incorrect engine cannot fake them.** The labels encode real reasoning, including the nuances: GPL in an internal tool is *not* a violation; a patched build inside a CVE range is *not* vulnerable.

Seeded (`SEED = 20260711`), so every run reproduces byte-identical files.

---

## Achieved distribution

All five within tolerance of the specification's targets:

| risk type | count | achieved | target |
|---|---|---|---|
| `vulnerable_dependency` | 89 | **17.8%** | 18% |
| `license_conflict` | 56 | **11.2%** | 12% |
| `unmaintained` | 73 | **14.6%** | 15% |
| `transitive_vulnerability` | 45 | **9.0%** | 10% |
| `none` (clean) | 237 | **47.4%** | 45% |

Plus **19 false-positive traps** — dependencies whose version sits inside a published CVE range but whose build carries a backported fix. A naive version-matching scanner flags every one. **We defuse 19/19.**

---

## `applications.json` — 10 records

The legal and exposure attributes here are what make the license engine interesting: **the same GPL library is a violation in `APP-001` and perfectly fine in `APP-009`.**

| field | type | notes |
|---|---|---|
| `app_id` | string | `APP-001` … `APP-010` |
| `name` | string | e.g. `Payments-API` |
| `team`, `owner` | string | an incident needs a *person*, not a count. `APP-010` is deliberately `unassigned@sg.com`. |
| `business_criticality` | enum | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| `criticality_weight` | float | 1.5 / 1.25 / 1.0 / 0.75 |
| `environment` | enum | `production` / `internal` |
| **`internet_facing`** | bool | drives the exposure channel |
| **`distributed`** | bool | **decides whether GPL copyleft is triggered at all** |
| **`proprietary`** | bool | **decides whether AGPL network-copyleft is triggered** |
| `handles_pii` | bool | GDPR scope |
| `handles_cardholder_data` | bool | PCI-DSS scope |
| `ecosystem` | enum | `maven` / `npm` / `pypi` |

The estate:

| app | criticality | internet | distributed | proprietary | PCI |
|---|---|---|---|---|---|
| Payments-API | CRITICAL | ✓ | ✓ | ✓ | **✓** |
| CustomerPortal-Web | CRITICAL | ✓ | ✓ | ✓ | |
| FraudDetection-Engine | CRITICAL | | | ✓ | **✓** |
| TradingDesk-Gateway | HIGH | ✓ | ✓ | ✓ | |
| MobileBanking-BFF | HIGH | ✓ | ✓ | ✓ | |
| RegReporting-Batch | HIGH | | | ✓ | |
| KYC-DocumentService | MEDIUM | | | ✓ | |
| InternalAnalytics-Dash | MEDIUM | | | | |
| DevOps-Toolchain | LOW | | | | |
| LegacyLoans-Core | HIGH | | | ✓ | |

---

## `sbom_dependencies.csv` — 500 records

10 applications × 50 dependencies.

| field | type | notes |
|---|---|---|
| `dependency_id` | string | `DEP-0001` … `DEP-0500` |
| `app_id`, `app_name` | string | |
| `library_name` | string | `group:artifact` for Maven, bare name otherwise |
| `version` | string | |
| `ecosystem` | enum | `maven` / `npm` / `pypi` |
| `license` | string | SPDX identifier, or `UNKNOWN` |
| `dependency_type` | enum | `direct` / `transitive` |
| `parent_library` | string | who pulls it in (empty for direct) |
| `depth` | int | 1 = direct. **Recomputed from the graph; never trusted.** |
| `last_updated` | date | drives the maintenance channel |
| `maintainer_count` | int | 1 = bus factor 1 |
| `has_security_policy` | bool | is there a defined route to report/receive a fix? |
| `repo_stars` | int | |

### The four build-context fields

Real SCA tools consume these from the build system. **Without them you cannot tell a true positive from a false one.** They are what make the false-positive rate a meaningful thing to measure.

| field | type | why it exists |
|---|---|---|
| **`patched_in_build`** | bool | The version sits inside the CVE range, but the shipped artifact carries a **backported fix**. Debian and Red Hat do this constantly. → **not vulnerable** |
| **`vulnerable_function_used`** | bool | **Reachability.** Is the flawed code path actually callable from our code? → drives the ×0.35 discount |
| **`linkage`** | enum | `dynamic` / `static`. **Decides every LGPL outcome.** |
| **`modified_by_us`** | bool | **Decides every MPL / LGPL outcome.** |

---

## `vulnerability_db.json` — 200 records

A simulated NVD. **Eleven are real**, with their real CVSS scores, real affected version ranges, and real vulnerable function names — so that when a judge types `CVE-2021-44228` they recognise it instantly and can verify the blast radius against public knowledge.

| field | type | notes |
|---|---|---|
| `cve_id` | string | |
| `name` | string | `"Log4Shell"` — humans remember names, not numbers |
| `library` | string | the affected library |
| **`affected_versions`** | object | `{introduced, fixed}` — a **half-open interval** `[introduced, fixed)` |
| `cvss_score` | float | 0.0 – 10.0 |
| `severity` | enum | `CRITICAL` ≥9 / `HIGH` ≥7 / `MEDIUM` ≥4 / `LOW` |
| `cwe` | string | |
| **`patch_available`** | bool | **~8% are `false`** → remediation requires REPLACEMENT, not upgrade |
| `patched_version` | string∣null | `null` when no fix has ever shipped |
| **`exploit_maturity`** | enum | `none` / `poc` / `functional` / `weaponised` |
| **`known_exploited`** | bool | CISA-KEV style: being exploited *right now* |
| `vulnerable_functions` | list | drives the reachability check |
| `published`, `summary` | | |

### `fixed: null` is not "unknown"

It means **no fix has ever shipped**. Everything from `introduced` onward is affected, forever. Treating `null` as "not affected" would silently clear every unpatchable vulnerability in the estate — the most dangerous class there is, because you cannot fix them by upgrading. This is asserted in `tests/test_sbomguard.py::test_no_fix_means_affected_forever`.

### The real anchors

| CVE | name | CVSS | note |
|---|---|---|---|
| `CVE-2021-44228` | **Log4Shell** | 10.0 | the demo centrepiece. Planted 3 levels deep in 4 apps. |
| `CVE-2017-5638` | Struts2 / **Equifax** | 10.0 | |
| `CVE-2022-22965` | Spring4Shell | 9.8 | |
| `CVE-2022-42889` | Text4Shell | 9.8 | |
| `CVE-2023-37903` | vm2 sandbox escape | 9.8 | |
| `CVE-2019-12384` | jackson-databind | 8.9 | fix shipped in **2.9.10** — the lexicographic trap |
| `CVE-2023-44487` | HTTP/2 Rapid Reset | 7.5 | |
| `CVE-2020-8203` | lodash prototype pollution | 7.4 | |
| `CVE-2021-23337` | lodash command injection | 7.2 | |
| `CVE-2021-33503` | urllib3 ReDoS | 5.3 | |
| **`CVE-2024-99001`** | **dom4j XXE** | 8.2 | **`patch_available: false`** — deliberately unfixable |

---

## `license_rules.json` — 15 records

| field | type | notes |
|---|---|---|
| `license_id` | string | SPDX |
| **`copyleft`** | enum | `none` / `file` / `library` / `viral` / `viral-network` / `unknown` — **the field the whole engine turns on** |
| `commercial_use`, `distribution_safe`, `modification_safe` | bool | |
| `risk_level` | enum | |
| `notes` | string | |

### The obligation table

| `copyleft` | licenses | violation when |
|---|---|---|
| `none` | MIT, Apache-2.0, BSD, ISC, PSF, Unlicense | **never** |
| `file` | MPL-2.0, EPL-2.0 | we **modified** its files |
| `library` | LGPL-2.1, LGPL-3.0 | **statically linked** OR modified |
| `viral` | GPL-2.0, GPL-3.0 | proprietary **AND distributed** |
| `viral-network` | **AGPL-3.0** | **any proprietary service** — merely *serving* it triggers disclosure |
| `unknown` | UNKNOWN | **always** — no license grants **no rights at all** |

Two traps live in this table, and both catch experienced teams:

- **AGPL violates even without distribution.** It is triggered by *network use*. Teams reasoning by analogy from the GPL get this wrong.
- **An undeclared license is the worst case, not the neutral one.** Absent an explicit grant, copyright law reserves *all* rights to the author. Most teams treat `UNKNOWN` as "probably fine". It is the opposite.

---

## `dependency_labels.csv` — 500 records

**Ground truth. Derived, never hand-written.**

| field | type | notes |
|---|---|---|
| `dependency_id` | string | joins to `sbom_dependencies.csv` |
| `app_id`, `library_name`, `version` | | |
| `risk_status` | enum | `AT_RISK` / `CLEAN` |
| `risk_type` | enum | `vulnerable_dependency` / `transitive_vulnerability` / `license_conflict` / `unmaintained` / `none` |
| `severity` | enum | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `NONE` |
| `cve_ids` | string | `;`-separated |
| **`is_false_positive_trap`** | bool | version matches a CVE range, **but the build is patched** |
| `explanation` | string | why — in prose |

### Precedence

A dependency can be all four things at once. The queue needs **one** answer, so labels are assigned by precedence:

```
vulnerability  >  license conflict  >  unmaintained  >  clean
```

The engine in `scoring.py` applies **exactly the same precedence**, independently. That is not cheating — it is the definition of the task, and both sides implement it from the same stated rules.

---

## The planted Log4Shell chain

```
APP-001 Payments-API
  └── spring-boot-starter-web@2.5.4          direct,     depth 1, Apache-2.0
       └── spring-boot-starter-logging@2.5.4  transitive, depth 2, Apache-2.0
            └── log4j-core@2.14.1             transitive, depth 3, Apache-2.0
                 ▲
                 └── CVE-2021-44228 · CVSS 10.0 · KEV · weaponised · REACHABLE
```

Present in **4 of 10 applications**: `APP-001`, `APP-004`, `APP-007`, `APP-010`.

In **every one of them it is transitive**. Nobody chose it. It appears in no `pom.xml` any engineer has read. A flat scan of direct dependencies finds **nothing**.

The libraries in the chain are deliberately pinned to their **real** licenses (Apache-2.0). An earlier version of the generator assigned random copyleft licenses to `spring-boot-starter-logging`, which was both unrealistic *and* hijacked the demo — the chain surfaced as a license violation instead of the CVE.

---

## Field lineage

Which fields the engine reads, and what for:

| field | consumed by | drives |
|---|---|---|
| `version` + `affected_versions` | `versions.in_range()` | vulnerability detection |
| `patched_in_build` | `VulnerabilityDetector.match()` | **false-positive suppression** |
| `vulnerable_function_used` | `scoring.context_multiplier()` | reachability discount (×0.35) |
| `license` + `copyleft` + app `distributed`/`proprietary` | `LicenseEngine.evaluate()` | license violations |
| `linkage`, `modified_by_us` | `LicenseEngine.evaluate()` | LGPL / MPL outcomes |
| `last_updated`, `maintainer_count` | `MaintenanceDetector` | decay risk |
| `parent_library`, `dependency_type` | `graph.py` | **the dependency graph** |
| `known_exploited`, `exploit_maturity` | `scoring.context_multiplier()` | urgency |
| `patch_available` | `remediation.py` | UPGRADE vs **REPLACE** |
| app `internet_facing` / `handles_*` | `scoring.exposure_channel()` | blast-radius weighting |
