# SBOMGuard — Sample Risk Report

**Generated:** 2026-07-11 15:46 · **Estate:** 10 applications, 500 components

*Auto-generated from the live analysis by `docs/generate_sample_report.py`, so it cannot drift out of sync with the engine.*


---

## Executive summary

We analysed **500 components** across **10 applications** and found **263 at risk**.

The three numbers that should decide where the next two weeks of engineering time goes:

- **19 CVEs are being actively exploited in the wild.** These are not patch-queue items; they are incidents.
- **47 findings have NO upstream patch.** They cannot be fixed by upgrading. Each needs a replacement project and a compensating control today.
- **166 findings are present but NOT reachable** from our code. They are liabilities, not emergencies — and de-prioritising them correctly is what stops this queue from being ignored.

We also **suppressed 51 false positives**: versions that sit inside a published CVE range but whose shipped build carries a backported fix. A naive version-matching scanner would have reported every one of them.


## Applications by risk

| Application | Score | Worst component | At risk | Hidden transitive | Criticality | Exposure |
|---|---|---|---|---|---|---|
| **TradingDesk-Gateway** | 94.4 | 99.1 | 27/50 | 4 | HIGH | internet |
| **LegacyLoans-Core** | 94.1 | 98.7 | 27/50 | 4 | HIGH | — |
| **Payments-API** | 93.8 | 99.3 | 25/50 | 3 | CRITICAL | internet, PCI |
| **KYC-DocumentService** | 92.8 | 97.3 | 26/50 | 4 | MEDIUM | — |
| **CustomerPortal-Web** | 91.9 | 95.9 | 26/50 | 5 | CRITICAL | internet |
| **FraudDetection-Engine** | 90.8 | 94.0 | 27/50 | 5 | CRITICAL | PCI |
| **MobileBanking-BFF** | 89.8 | 93.5 | 25/50 | 5 | HIGH | internet |
| **RegReporting-Batch** | 88.7 | 90.9 | 27/50 | 6 | HIGH | — |
| **InternalAnalytics-Dash** | 85.4 | 86.8 | 26/50 | 5 | MEDIUM | — |
| **DevOps-Toolchain** | 76.5 | 73.5 | 27/50 | 4 | LOW | — |

---

## The eight findings that matter

Ranked by **priority** — what to fix first — not by CVSS.


### 1. `org.apache.logging.log4j:log4j-core@2.14.1`

| | |
|---|---|
| **Priority** (fix first?) | **99.3** / 100 |
| **Flaw** (how bad?) | 97.2 / 100 |
| Context multiplier | ×2.28 |
| Risk type | transitive vulnerability |
| Severity | CRITICAL |
| Application | Payments-API (CRITICAL) |
| Owner | elena.rossi@sg.com |
| Depth | 3 (TRANSITIVE — nobody chose this) |
| CVE | CVE-2021-44228 — Log4Shell (CVSS 10.0) |
| Exploit | weaponised · **KNOWN EXPLOITED IN THE WILD** |
| Reachable from our code | **YES** — the flaw is live |
| Patch | upgrade to 2.17.1 |
| Blast radius | 4 application(s) |

**How it gets in:**

```
Payments-API -> org.springframework.boot:spring-boot-starter-web@2.5.4 -> org.springframework.boot:spring-boot-starter-logging@2.5.4 -> org.apache.logging.log4j:log4j-core@2.14.1
```

**Analyst narrative:**

> This is a five-alarm finding. Payments-API is exposed to CVE-2021-44228 (CRITICAL, CVSS 10.0) through org.apache.logging.log4j:log4j-core@2.14.1 — a dependency nobody on the team ever chose. It arrives 3 levels down the tree via org.springframework.boot:spring-boot-starter-logging, which is exactly why a review of direct dependencies would never have found it. The full chain is: Payments-API -> org.springframework.boot:spring-boot-starter-web@2.5.4 -> org.springframework.boot:spring-boot-starter-logging@2.5.4 -> org.apache.logging.log4j:log4j-core@2.14.1.

> JNDI features in the Log4j2 lookup substitution do not protect against attacker-controlled LDAP endpoints. Any logged string containing ${jndi:ldap://...} yields unauthenticated remote code execution.

> This CVE is being actively exploited in the wild right now, which moves it out of the patch queue and into incident response, a weaponised exploit is publicly available and the vulnerable function (org.apache.logging.log4j.core.lookup.JndiLookup.lookup) IS reachable from our code path, so the flaw is live.

> This is not an isolated problem. The same component is present in 4 applications (2 internet-facing, 1 handling cardholder data), so this should be handled as one coordinated remediation campaign rather than 4 separate tickets.

> Remediation is straightforward: upgrade org.apache.logging.log4j:log4j-core from 2.14.1 to 2.17.1. Because the dependency is transitive, the upgrade must be applied at org.springframework.boot:spring-boot-starter-logging — or pinned explicitly if the parent has not yet released a fixed build.

> For the audit trail, this finding maps to OWASP A06:2021, NIST-CSF DS-6, EO-14028 SBOM.


**Why this score:**

- CVE-2021-44228 rated CRITICAL (CVSS 10.0)
- 2 CVEs stack on this component (+3)
- no release in 2.7 years
- no published security policy
- exploit is weaponised (x1.3)
- KNOWN EXPLOITED in the wild (x1.35) — treat as an incident

**Compliance mapping:**

- `OWASP A06:2021` — Vulnerable and Outdated Components
- `NIST-CSF DS-6` — Integrity checking mechanisms verify software
- `EO-14028 SBOM` — Full dependency transparency, including transitive


### 2. `org.springframework:spring-beans@3.3.5`

| | |
|---|---|
| **Priority** (fix first?) | **99.1** / 100 |
| **Flaw** (how bad?) | 97.2 / 100 |
| Context multiplier | ×2.19 |
| Risk type | vulnerable dependency |
| Severity | CRITICAL |
| Application | TradingDesk-Gateway (HIGH) |
| Owner | james.okoro@sg.com |
| Depth | 1 (direct) |
| CVE | CVE-2022-22965 — Spring4Shell (CVSS 9.8) |
| Exploit | weaponised · **KNOWN EXPLOITED IN THE WILD** |
| Reachable from our code | **YES** — the flaw is live |
| Patch | upgrade to 5.3.18 |
| Blast radius | 1 application(s) |

**Analyst narrative:**

> This is a five-alarm finding. TradingDesk-Gateway directly depends on org.springframework:spring-beans@3.3.5, which is affected by CVE-2022-22965 (CRITICAL, CVSS 9.8).

> Data binding on a JDK9+ Spring MVC application allows ClassLoader access, enabling remote code execution.

> This CVE is being actively exploited in the wild right now, which moves it out of the patch queue and into incident response, a weaponised exploit is publicly available and the vulnerable function (org.springframework.beans.CachedIntrospectionResults) IS reachable from our code path, so the flaw is live.

> Remediation is straightforward: upgrade org.springframework:spring-beans from 3.3.5 to 5.3.18.

> For the audit trail, this finding maps to OWASP A06:2021, NIST-CSF CM-8, EO-14028 SBOM.


**Why this score:**

- CVE-2022-22965 rated CRITICAL (CVSS 9.8)
- exploit is weaponised (x1.3)
- KNOWN EXPLOITED in the wild (x1.35) — treat as an incident
- amplified: application is internet-facing
- amplified: application is externally distributed
- business criticality HIGH (x1.09)

**Compliance mapping:**

- `OWASP A06:2021` — Vulnerable and Outdated Components
- `NIST-CSF CM-8` — Vulnerability scans are performed
- `EO-14028 SBOM` — Software supply chain security


### 3. `org.springframework:spring-beans@3.3.4`

| | |
|---|---|
| **Priority** (fix first?) | **98.7** / 100 |
| **Flaw** (how bad?) | 97.2 / 100 |
| Context multiplier | ×2.02 |
| Risk type | vulnerable dependency |
| Severity | CRITICAL |
| Application | LegacyLoans-Core (HIGH) |
| Owner | unassigned@sg.com |
| Depth | 1 (direct) |
| CVE | CVE-2022-22965 — Spring4Shell (CVSS 9.8) |
| Exploit | weaponised · **KNOWN EXPLOITED IN THE WILD** |
| Reachable from our code | **YES** — the flaw is live |
| Patch | upgrade to 5.3.18 |
| Blast radius | 1 application(s) |

**Analyst narrative:**

> This is a five-alarm finding. LegacyLoans-Core directly depends on org.springframework:spring-beans@3.3.4, which is affected by CVE-2022-22965 (CRITICAL, CVSS 9.8).

> Data binding on a JDK9+ Spring MVC application allows ClassLoader access, enabling remote code execution.

> This CVE is being actively exploited in the wild right now, which moves it out of the patch queue and into incident response, a weaponised exploit is publicly available and the vulnerable function (org.springframework.beans.CachedIntrospectionResults) IS reachable from our code path, so the flaw is live.

> Remediation is straightforward: upgrade org.springframework:spring-beans from 3.3.4 to 5.3.18.

> For the audit trail, this finding maps to OWASP A06:2021, NIST-CSF CM-8, EO-14028 SBOM.


**Why this score:**

- CVE-2022-22965 rated CRITICAL (CVSS 9.8)
- exploit is weaponised (x1.3)
- KNOWN EXPLOITED in the wild (x1.35) — treat as an incident
- amplified: application handles PII (GDPR scope)
- business criticality HIGH (x1.09)

**Compliance mapping:**

- `OWASP A06:2021` — Vulnerable and Outdated Components
- `NIST-CSF CM-8` — Vulnerability scans are performed
- `EO-14028 SBOM` — Software supply chain security


### 4. `org.apache.struts:struts2-core@2.2.7`

| | |
|---|---|
| **Priority** (fix first?) | **98.7** / 100 |
| **Flaw** (how bad?) | 97.2 / 100 |
| Context multiplier | ×2.02 |
| Risk type | vulnerable dependency |
| Severity | CRITICAL |
| Application | LegacyLoans-Core (HIGH) |
| Owner | unassigned@sg.com |
| Depth | 1 (direct) |
| CVE | CVE-2017-5638 — Struts2 Content-Type RCE (the Equifax breach) (CVSS 10.0) |
| Exploit | weaponised · **KNOWN EXPLOITED IN THE WILD** |
| Reachable from our code | **YES** — the flaw is live |
| Patch | upgrade to 2.5.33 |
| Blast radius | 1 application(s) |

**Analyst narrative:**

> This is a five-alarm finding. LegacyLoans-Core directly depends on org.apache.struts:struts2-core@2.2.7, which is affected by CVE-2017-5638 (CRITICAL, CVSS 10.0).

> A malformed Content-Type header is evaluated as OGNL, giving unauthenticated remote code execution. This is the vulnerability behind the Equifax breach.

> This CVE is being actively exploited in the wild right now, which moves it out of the patch queue and into incident response, a weaponised exploit is publicly available and the vulnerable function (JakartaMultiPartRequest.parse) IS reachable from our code path, so the flaw is live.

> Remediation is straightforward: upgrade org.apache.struts:struts2-core from 2.2.7 to 2.5.33.

> For the audit trail, this finding maps to OWASP A06:2021, NIST-CSF CM-8, EO-14028 SBOM.


**Why this score:**

- CVE-2017-5638 rated CRITICAL (CVSS 10.0)
- 3 CVEs stack on this component (+6)
- no release in 4.7 years — effectively abandoned
- bus factor = 1 (a single maintainer)
- no published security policy
- exploit is weaponised (x1.3)

**Compliance mapping:**

- `OWASP A06:2021` — Vulnerable and Outdated Components
- `NIST-CSF CM-8` — Vulnerability scans are performed
- `EO-14028 SBOM` — Software supply chain security


### 5. `io.netty:netty-handler@4.0.1`

| | |
|---|---|
| **Priority** (fix first?) | **98.3** / 100 |
| **Flaw** (how bad?) | 75.6 / 100 |
| Context multiplier | ×2.47 |
| Risk type | transitive vulnerability |
| Severity | HIGH |
| Application | Payments-API (CRITICAL) |
| Owner | elena.rossi@sg.com |
| Depth | 2 (TRANSITIVE — nobody chose this) |
| CVE | CVE-2023-44487 — HTTP/2 Rapid Reset (CVSS 7.5) |
| Exploit | weaponised · **KNOWN EXPLOITED IN THE WILD** |
| Reachable from our code | **YES** — the flaw is live |
| Patch | upgrade to 4.1.100 |
| Blast radius | 1 application(s) |

**How it gets in:**

```
Payments-API -> org.quartz-scheduler:quartz@3.3.0 -> io.netty:netty-handler@4.0.1
```

**Analyst narrative:**

> This is a serious finding. Payments-API is exposed to CVE-2023-44487 (HIGH, CVSS 7.5) through io.netty:netty-handler@4.0.1 — a dependency nobody on the team ever chose. It arrives 2 levels down the tree via org.quartz-scheduler:quartz, which is exactly why a review of direct dependencies would never have found it. The full chain is: Payments-API -> org.quartz-scheduler:quartz@3.3.0 -> io.netty:netty-handler@4.0.1.

> HTTP/2 stream-cancellation flooding enables record-breaking DDoS amplification.

> This CVE is being actively exploited in the wild right now, which moves it out of the patch queue and into incident response, a weaponised exploit is publicly available and the vulnerable function (Http2FrameCodec) IS reachable from our code path, so the flaw is live.

> Remediation is straightforward: upgrade io.netty:netty-handler from 4.0.1 to 4.1.100. Because the dependency is transitive, the upgrade must be applied at org.quartz-scheduler:quartz — or pinned explicitly if the parent has not yet released a fixed build.

> For the audit trail, this finding maps to OWASP A06:2021, NIST-CSF DS-6, EO-14028 SBOM.


**Why this score:**

- CVE-2023-44487 rated HIGH (CVSS 7.5)
- 5 CVEs stack on this component (+10)
- exploit is weaponised (x1.3)
- KNOWN EXPLOITED in the wild (x1.35) — treat as an incident
- reached transitively at depth 2 (x0.92)
- amplified: application is internet-facing

**Compliance mapping:**

- `OWASP A06:2021` — Vulnerable and Outdated Components
- `NIST-CSF DS-6` — Integrity checking mechanisms verify software
- `EO-14028 SBOM` — Full dependency transparency, including transitive


### 6. `org.apache.logging.log4j:log4j-core@2.14.1`

| | |
|---|---|
| **Priority** (fix first?) | **98.1** / 100 |
| **Flaw** (how bad?) | 97.2 / 100 |
| Context multiplier | ×1.87 |
| Risk type | transitive vulnerability |
| Severity | CRITICAL |
| Application | TradingDesk-Gateway (HIGH) |
| Owner | james.okoro@sg.com |
| Depth | 3 (TRANSITIVE — nobody chose this) |
| CVE | CVE-2021-44228 — Log4Shell (CVSS 10.0) |
| Exploit | weaponised · **KNOWN EXPLOITED IN THE WILD** |
| Reachable from our code | **YES** — the flaw is live |
| Patch | upgrade to 2.17.1 |
| Blast radius | 4 application(s) |

**How it gets in:**

```
TradingDesk-Gateway -> org.springframework.boot:spring-boot-starter-web@2.5.4 -> org.springframework.boot:spring-boot-starter-logging@2.5.4 -> org.apache.logging.log4j:log4j-core@2.14.1
```

**Analyst narrative:**

> This is a five-alarm finding. TradingDesk-Gateway is exposed to CVE-2021-44228 (CRITICAL, CVSS 10.0) through org.apache.logging.log4j:log4j-core@2.14.1 — a dependency nobody on the team ever chose. It arrives 3 levels down the tree via org.springframework.boot:spring-boot-starter-logging, which is exactly why a review of direct dependencies would never have found it. The full chain is: TradingDesk-Gateway -> org.springframework.boot:spring-boot-starter-web@2.5.4 -> org.springframework.boot:spring-boot-starter-logging@2.5.4 -> org.apache.logging.log4j:log4j-core@2.14.1.

> JNDI features in the Log4j2 lookup substitution do not protect against attacker-controlled LDAP endpoints. Any logged string containing ${jndi:ldap://...} yields unauthenticated remote code execution.

> This CVE is being actively exploited in the wild right now, which moves it out of the patch queue and into incident response, a weaponised exploit is publicly available and the vulnerable function (org.apache.logging.log4j.core.lookup.JndiLookup.lookup) IS reachable from our code path, so the flaw is live.

> This is not an isolated problem. The same component is present in 4 applications (2 internet-facing, 1 handling cardholder data), so this should be handled as one coordinated remediation campaign rather than 4 separate tickets.

> Remediation is straightforward: upgrade org.apache.logging.log4j:log4j-core from 2.14.1 to 2.17.1. Because the dependency is transitive, the upgrade must be applied at org.springframework.boot:spring-boot-starter-logging — or pinned explicitly if the parent has not yet released a fixed build.

> For the audit trail, this finding maps to OWASP A06:2021, NIST-CSF DS-6, EO-14028 SBOM.


**Why this score:**

- CVE-2021-44228 rated CRITICAL (CVSS 10.0)
- 2 CVEs stack on this component (+3)
- no release in 2.7 years
- no published security policy
- exploit is weaponised (x1.3)
- KNOWN EXPLOITED in the wild (x1.35) — treat as an incident

**Compliance mapping:**

- `OWASP A06:2021` — Vulnerable and Outdated Components
- `NIST-CSF DS-6` — Integrity checking mechanisms verify software
- `EO-14028 SBOM` — Full dependency transparency, including transitive


### 7. `org.apache.logging.log4j:log4j-core@2.14.1`

| | |
|---|---|
| **Priority** (fix first?) | **97.4** / 100 |
| **Flaw** (how bad?) | 97.2 / 100 |
| Context multiplier | ×1.72 |
| Risk type | transitive vulnerability |
| Severity | CRITICAL |
| Application | LegacyLoans-Core (HIGH) |
| Owner | unassigned@sg.com |
| Depth | 3 (TRANSITIVE — nobody chose this) |
| CVE | CVE-2021-44228 — Log4Shell (CVSS 10.0) |
| Exploit | weaponised · **KNOWN EXPLOITED IN THE WILD** |
| Reachable from our code | **YES** — the flaw is live |
| Patch | upgrade to 2.17.1 |
| Blast radius | 4 application(s) |

**How it gets in:**

```
LegacyLoans-Core -> org.springframework.boot:spring-boot-starter-web@2.5.4 -> org.springframework.boot:spring-boot-starter-logging@2.5.4 -> org.apache.logging.log4j:log4j-core@2.14.1
```

**Analyst narrative:**

> This is a five-alarm finding. LegacyLoans-Core is exposed to CVE-2021-44228 (CRITICAL, CVSS 10.0) through org.apache.logging.log4j:log4j-core@2.14.1 — a dependency nobody on the team ever chose. It arrives 3 levels down the tree via org.springframework.boot:spring-boot-starter-logging, which is exactly why a review of direct dependencies would never have found it. The full chain is: LegacyLoans-Core -> org.springframework.boot:spring-boot-starter-web@2.5.4 -> org.springframework.boot:spring-boot-starter-logging@2.5.4 -> org.apache.logging.log4j:log4j-core@2.14.1.

> JNDI features in the Log4j2 lookup substitution do not protect against attacker-controlled LDAP endpoints. Any logged string containing ${jndi:ldap://...} yields unauthenticated remote code execution.

> This CVE is being actively exploited in the wild right now, which moves it out of the patch queue and into incident response, a weaponised exploit is publicly available and the vulnerable function (org.apache.logging.log4j.core.lookup.JndiLookup.lookup) IS reachable from our code path, so the flaw is live.

> This is not an isolated problem. The same component is present in 4 applications (2 internet-facing, 1 handling cardholder data), so this should be handled as one coordinated remediation campaign rather than 4 separate tickets.

> Remediation is straightforward: upgrade org.apache.logging.log4j:log4j-core from 2.14.1 to 2.17.1. Because the dependency is transitive, the upgrade must be applied at org.springframework.boot:spring-boot-starter-logging — or pinned explicitly if the parent has not yet released a fixed build.

> For the audit trail, this finding maps to OWASP A06:2021, NIST-CSF DS-6, EO-14028 SBOM.


**Why this score:**

- CVE-2021-44228 rated CRITICAL (CVSS 10.0)
- 2 CVEs stack on this component (+3)
- no release in 2.7 years
- no published security policy
- exploit is weaponised (x1.3)
- KNOWN EXPLOITED in the wild (x1.35) — treat as an incident

**Compliance mapping:**

- `OWASP A06:2021` — Vulnerable and Outdated Components
- `NIST-CSF DS-6` — Integrity checking mechanisms verify software
- `EO-14028 SBOM` — Full dependency transparency, including transitive


### 8. `org.springframework:spring-beans@3.4.0`

| | |
|---|---|
| **Priority** (fix first?) | **97.3** / 100 |
| **Flaw** (how bad?) | 97.2 / 100 |
| Context multiplier | ×1.71 |
| Risk type | transitive vulnerability |
| Severity | CRITICAL |
| Application | KYC-DocumentService (MEDIUM) |
| Owner | amara.diallo@sg.com |
| Depth | 2 (TRANSITIVE — nobody chose this) |
| CVE | CVE-2022-22965 — Spring4Shell (CVSS 9.8) |
| Exploit | weaponised · **KNOWN EXPLOITED IN THE WILD** |
| Reachable from our code | **YES** — the flaw is live |
| Patch | upgrade to 5.3.18 |
| Blast radius | 1 application(s) |

**How it gets in:**

```
KYC-DocumentService -> org.slf4j:slf4j-api@0.19.4 -> org.springframework:spring-beans@3.4.0
```

**Analyst narrative:**

> This is a five-alarm finding. KYC-DocumentService is exposed to CVE-2022-22965 (CRITICAL, CVSS 9.8) through org.springframework:spring-beans@3.4.0 — a dependency nobody on the team ever chose. It arrives 2 levels down the tree via org.slf4j:slf4j-api, which is exactly why a review of direct dependencies would never have found it. The full chain is: KYC-DocumentService -> org.slf4j:slf4j-api@0.19.4 -> org.springframework:spring-beans@3.4.0.

> Data binding on a JDK9+ Spring MVC application allows ClassLoader access, enabling remote code execution.

> This CVE is being actively exploited in the wild right now, which moves it out of the patch queue and into incident response, a weaponised exploit is publicly available and the vulnerable function (org.springframework.beans.CachedIntrospectionResults) IS reachable from our code path, so the flaw is live.

> Remediation is straightforward: upgrade org.springframework:spring-beans from 3.4.0 to 5.3.18. Because the dependency is transitive, the upgrade must be applied at org.slf4j:slf4j-api — or pinned explicitly if the parent has not yet released a fixed build.

> For the audit trail, this finding maps to OWASP A06:2021, NIST-CSF DS-6, EO-14028 SBOM.


**Why this score:**

- CVE-2022-22965 rated CRITICAL (CVSS 9.8)
- exploit is weaponised (x1.3)
- KNOWN EXPLOITED in the wild (x1.35) — treat as an incident
- reached transitively at depth 2 (x0.92)
- amplified: application handles PII (GDPR scope)

**Compliance mapping:**

- `OWASP A06:2021` — Vulnerable and Outdated Components
- `NIST-CSF DS-6` — Integrity checking mechanisms verify software
- `EO-14028 SBOM` — Full dependency transparency, including transitive


---

## Remediation plan

**263 findings collapse into 130 actions** (2.0× collapse) — because one dependency bump frequently fixes the same flaw across several applications at once.

**32 need doing today.**


### `ACT-001` · IMMEDIATE · PIN_TRANSITIVE

**Upgrade org.apache.logging.log4j:log4j-core 2.14.1 -> 2.17.1  (4 apps)**

Resolves 2 CVE(s) — worst is CVE-2021-44228 (CRITICAL, CVSS 10.0) — across 4 application(s): KYC-DocumentService, LegacyLoans-Core, Payments-API, TradingDesk-Gateway. Exploited in the wild. The vulnerable function is reachable from our code. 

```bash
# Transitive: pin it explicitly in <dependencyManagement> so the
# resolved version wins regardless of what the parent requests.
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.17.1</version>
    </dependency>
  </dependencies>
```

> ⚠ This is a TRANSITIVE dependency (pulled in by org.springframework.boot:spring-boot-starter-logging). Bumping your direct dependency may not be enough — verify the resolved version after the change, and pin it if the parent still drags in the old one.

> ⚠ This CVE is being actively exploited in the wild. After patching, hunt for indicators of compromise — assume attempted exploitation, not theoretical risk.

*Affects: KYC-DocumentService, LegacyLoans-Core, Payments-API, TradingDesk-Gateway*
*Resolves: CVE-2021-44228, CVE-2025-1142*


### `ACT-002` · IMMEDIATE · PIN_TRANSITIVE

**Upgrade org.springframework:spring-beans 3.3.4/3.3.5 -> 5.3.18  (3 apps)**

Resolves 1 CVE(s) — worst is CVE-2022-22965 (CRITICAL, CVSS 9.8) — across 3 application(s): KYC-DocumentService, LegacyLoans-Core, TradingDesk-Gateway. Exploited in the wild. The vulnerable function is reachable from our code. 

```bash
# Transitive: pin it explicitly in <dependencyManagement> so the
# resolved version wins regardless of what the parent requests.
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-beans</artifactId>
      <version>5.3.18</version>
    </dependency>
  </dependencies>
```

> ⚠ This is a TRANSITIVE dependency (pulled in by org.slf4j:slf4j-api). Bumping your direct dependency may not be enough — verify the resolved version after the change, and pin it if the parent still drags in the old one.

> ⚠ This CVE is being actively exploited in the wild. After patching, hunt for indicators of compromise — assume attempted exploitation, not theoretical risk.

*Affects: KYC-DocumentService, LegacyLoans-Core, TradingDesk-Gateway*
*Resolves: CVE-2022-22965*


### `ACT-003` · IMMEDIATE · UPGRADE

**Upgrade org.apache.struts:struts2-core 2.2.7 -> 2.5.33**

Resolves 3 CVE(s) — worst is CVE-2017-5638 (CRITICAL, CVSS 10.0) — across 1 application(s): LegacyLoans-Core. Exploited in the wild. The vulnerable function is reachable from our code. 

```bash
# Update the <version> of org.apache.struts:struts2-core to 2.5.33 in pom.xml
mvn versions:use-dep-version -Dincludes=org.apache.struts:struts2-core -DdepVersion=2.5.33
mvn dependency:tree -Dincludes=org.apache.struts:struts2-core
```

> ⚠ This CVE is being actively exploited in the wild. After patching, hunt for indicators of compromise — assume attempted exploitation, not theoretical risk.

*Affects: LegacyLoans-Core*
*Resolves: CVE-2017-5638, CVE-2021-1058, CVE-2022-1081*


### `ACT-004` · IMMEDIATE · PIN_TRANSITIVE

**Upgrade io.netty:netty-handler 4.0.1 -> 4.1.100**

Resolves 5 CVE(s) — worst is CVE-2023-44487 (HIGH, CVSS 7.5) — across 1 application(s): Payments-API. Exploited in the wild. The vulnerable function is reachable from our code. 

```bash
# Transitive: pin it explicitly in <dependencyManagement> so the
# resolved version wins regardless of what the parent requests.
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>io.netty</groupId>
      <artifactId>netty-handler</artifactId>
      <version>4.1.100</version>
    </dependency>
  </dependencies>
```

> ⚠ This is a TRANSITIVE dependency (pulled in by org.quartz-scheduler:quartz). Bumping your direct dependency may not be enough — verify the resolved version after the change, and pin it if the parent still drags in the old one.

> ⚠ This CVE is being actively exploited in the wild. After patching, hunt for indicators of compromise — assume attempted exploitation, not theoretical risk.

*Affects: Payments-API*
*Resolves: CVE-2020-1052, CVE-2021-1108, CVE-2021-1123, CVE-2023-1111, CVE-2023-44487*


### `ACT-005` · IMMEDIATE · UPGRADE

**Upgrade org.apache.commons:commons-text 1.5.3/1.7.8 -> 1.10.0  (4 apps)**

Resolves 1 CVE(s) — worst is CVE-2022-42889 (CRITICAL, CVSS 9.8) — across 4 application(s): KYC-DocumentService, LegacyLoans-Core, Payments-API, TradingDesk-Gateway. The vulnerable function is reachable from our code. 

```bash
# Update the <version> of org.apache.commons:commons-text to 1.10.0 in pom.xml
mvn versions:use-dep-version -Dincludes=org.apache.commons:commons-text -DdepVersion=1.10.0
mvn dependency:tree -Dincludes=org.apache.commons:commons-text
```

*Affects: KYC-DocumentService, LegacyLoans-Core, Payments-API, TradingDesk-Gateway*
*Resolves: CVE-2022-42889*


### `ACT-006` · IMMEDIATE · REPLACE

**REPLACE ejs — no upstream patch exists**

CVE-2020-1064 (HIGH, CVSS 8.4) affects ejs, and there is NO fixed version. Upgrading is not possible: the project is not shipping a fix. The component must be replaced. Treat this as a project with a budget, not a ticket in a sprint — and apply a compensating control TODAY, because the exposure window stays open until the replacement lands.

```bash
# No fixed version of ejs exists. Candidate replacements:
# No drop-in replacement is known. Scope a migration.
```

> ⚠ This is a breaking change. Budget for API migration and regression testing.

> ⚠ Do not close this item by 'upgrading' — there is nothing to upgrade to.

> **Compensating control:** Until the replacement ships: disable the affected code path (ejs.parse), or block exploitation at the WAF, or segment the affected service off the network. Record which control you chose — an auditor will ask.

*Affects: CustomerPortal-Web, MobileBanking-BFF*
*Resolves: CVE-2019-1167, CVE-2020-1064*


---

## Fix by leverage, not by application

81 risky components appear in more than one application. The top 5 account for 27 application-level exposures between them — so five upgrades retire 27 risks. Fix by LEVERAGE, not by application: patching the same library ten times in ten repos is ten times the work for the same outcome.

| Component | Apps | Exposure | One fix clears | Leverage |
|---|---|---|---|---|
| `io.jsonwebtoken:jjwt` | 6 | 3 internet, 2 PCI, 1 transitive | 8 CVE(s) | **623.1** |
| `marked` | 6 | 2 internet, 1 PCI, 2 transitive | 5 CVE(s) | **572.7** |
| `org.apache.logging.log4j:log4j-core` | 4 | 2 internet, 1 PCI, 4 transitive | 2 CVE(s) | **489.7** |
| `shell-quote` | 5 | 2 internet, 3 transitive | 0 CVE(s) | **462.4** |
| `com.fasterxml.jackson.core:jackson-core` | 6 | 3 internet, 1 PCI | 4 CVE(s) | **392.3** |

---

*Patching the same library ten times in ten repositories is ten times the work for the same outcome. Work this table top-down.*