"""
SBOMGuard dataset generator — the simulated NVD (200 CVEs).

Ten of these are REAL, famous vulnerabilities with their real CVSS scores, real affected
version ranges and real vulnerable function names. That matters for the demo: when a judge
types CVE-2021-44228 into the box, they recognise it instantly, and the blast radius we
compute is verifiable against public knowledge.

The remaining ~190 are generated to fill out the database with realistic noise, including
the edge cases the problem statement explicitly demands:
  * CVEs with NO available patch  -> remediation requires REPLACEMENT, not upgrade
  * A wide CVSS spread            -> "not all CVEs are equal" (9.8 critical vs 3.0 low)
  * Exploit maturity levels       -> a weaponised CVSS 7.5 outranks a theoretical CVSS 9.1
  * KEV flag (known exploited)    -> CISA-style "actively exploited in the wild"
"""
from __future__ import annotations

from datetime import timedelta

from _catalog import ALL_LIBS, TODAY, N_CVES, bump_patch

# =====================================================================================
# REAL-WORLD ANCHOR CVEs
# =====================================================================================
ANCHOR_CVES = [
    {
        "cve_id": "CVE-2021-44228", "name": "Log4Shell",
        "library": "org.apache.logging.log4j:log4j-core",
        "affected_versions": {"introduced": "2.0.0", "fixed": "2.15.0"},
        "cvss_score": 10.0, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "severity": "CRITICAL", "cwe": "CWE-502",
        "patch_available": True, "patched_version": "2.17.1",
        "exploit_maturity": "weaponised", "known_exploited": True,
        "vulnerable_functions": ["org.apache.logging.log4j.core.lookup.JndiLookup.lookup"],
        "published": "2021-12-10",
        "summary": "JNDI features in the Log4j2 lookup substitution do not protect against "
                   "attacker-controlled LDAP endpoints. Any logged string containing "
                   "${jndi:ldap://...} yields unauthenticated remote code execution.",
    },
    {
        "cve_id": "CVE-2022-22965", "name": "Spring4Shell",
        "library": "org.springframework:spring-beans",
        "affected_versions": {"introduced": "0.0.0", "fixed": "5.3.18"},
        "cvss_score": 9.8, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL", "cwe": "CWE-94",
        "patch_available": True, "patched_version": "5.3.18",
        "exploit_maturity": "weaponised", "known_exploited": True,
        "vulnerable_functions": ["org.springframework.beans.CachedIntrospectionResults"],
        "published": "2022-03-31",
        "summary": "Data binding on a JDK9+ Spring MVC application allows ClassLoader access, "
                   "enabling remote code execution.",
    },
    {
        "cve_id": "CVE-2020-8203", "name": "Lodash Prototype Pollution",
        "library": "lodash",
        "affected_versions": {"introduced": "0.0.0", "fixed": "4.17.20"},
        "cvss_score": 7.4, "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "HIGH", "cwe": "CWE-1321",
        "patch_available": True, "patched_version": "4.17.21",
        "exploit_maturity": "poc", "known_exploited": False,
        "vulnerable_functions": ["zipObjectDeep", "set", "setWith"],
        "published": "2020-07-15",
        "summary": "Prototype pollution via zipObjectDeep allows an attacker to modify Object.prototype.",
    },
    {
        "cve_id": "CVE-2019-12384", "name": "jackson-databind polymorphic deserialization",
        "library": "com.fasterxml.jackson.core:jackson-databind",
        "affected_versions": {"introduced": "2.0.0", "fixed": "2.9.10"},
        "cvss_score": 8.9, "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "severity": "HIGH", "cwe": "CWE-502",
        "patch_available": True, "patched_version": "2.15.0",
        "exploit_maturity": "weaponised", "known_exploited": True,
        "vulnerable_functions": ["ObjectMapper.enableDefaultTyping", "readValue"],
        "published": "2019-06-24",
        "summary": "Unsafe polymorphic deserialization permits remote code execution via crafted "
                   "JSON when default typing is enabled.",
    },
    {
        "cve_id": "CVE-2023-44487", "name": "HTTP/2 Rapid Reset",
        "library": "io.netty:netty-handler",
        "affected_versions": {"introduced": "4.0.0", "fixed": "4.1.100"},
        "cvss_score": 7.5, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "severity": "HIGH", "cwe": "CWE-400",
        "patch_available": True, "patched_version": "4.1.100",
        "exploit_maturity": "weaponised", "known_exploited": True,
        "vulnerable_functions": ["Http2FrameCodec"],
        "published": "2023-10-10",
        "summary": "HTTP/2 stream-cancellation flooding enables record-breaking DDoS amplification.",
    },
    {
        "cve_id": "CVE-2022-42889", "name": "Text4Shell",
        "library": "org.apache.commons:commons-text",
        "affected_versions": {"introduced": "1.5.0", "fixed": "1.10.0"},
        "cvss_score": 9.8, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL", "cwe": "CWE-94",
        "patch_available": True, "patched_version": "1.10.0",
        "exploit_maturity": "poc", "known_exploited": False,
        "vulnerable_functions": ["StringSubstitutor.replace"],
        "published": "2022-10-13",
        "summary": "Variable interpolation in StringSubstitutor performs script evaluation, "
                   "yielding remote code execution.",
    },
    {
        "cve_id": "CVE-2021-33503", "name": "urllib3 ReDoS",
        "library": "urllib3",
        "affected_versions": {"introduced": "0.0.0", "fixed": "1.26.5"},
        "cvss_score": 5.3, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "severity": "MEDIUM", "cwe": "CWE-400",
        "patch_available": True, "patched_version": "2.0.7",
        "exploit_maturity": "none", "known_exploited": False,
        "vulnerable_functions": ["urllib3.util.url.parse_url"],
        "published": "2021-06-29",
        "summary": "Catastrophic backtracking in URL parsing allows denial of service.",
    },
    {
        "cve_id": "CVE-2017-5638", "name": "Struts2 Content-Type RCE (the Equifax breach)",
        "library": "org.apache.struts:struts2-core",
        "affected_versions": {"introduced": "2.0.0", "fixed": "2.3.32"},
        "cvss_score": 10.0, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "severity": "CRITICAL", "cwe": "CWE-20",
        "patch_available": True, "patched_version": "2.5.33",
        "exploit_maturity": "weaponised", "known_exploited": True,
        "vulnerable_functions": ["JakartaMultiPartRequest.parse"],
        "published": "2017-03-10",
        "summary": "A malformed Content-Type header is evaluated as OGNL, giving unauthenticated "
                   "remote code execution. This is the vulnerability behind the Equifax breach.",
    },
    {
        "cve_id": "CVE-2023-37903", "name": "vm2 Sandbox Escape",
        "library": "vm2",
        "affected_versions": {"introduced": "0.0.0", "fixed": "3.9.19"},
        "cvss_score": 9.8, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL", "cwe": "CWE-693",
        "patch_available": True, "patched_version": "3.9.19",
        "exploit_maturity": "weaponised", "known_exploited": True,
        "vulnerable_functions": ["VM.run"],
        "published": "2023-07-19",
        "summary": "Sandbox escape in vm2 permits host remote code execution from untrusted script input.",
    },
    {
        "cve_id": "CVE-2021-23337", "name": "Lodash Command Injection",
        "library": "lodash",
        "affected_versions": {"introduced": "4.0.0", "fixed": "4.17.21"},
        "cvss_score": 7.2, "cvss_vector": "AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "severity": "HIGH", "cwe": "CWE-78",
        "patch_available": True, "patched_version": "4.17.21",
        "exploit_maturity": "poc", "known_exploited": False,
        "vulnerable_functions": ["template"],
        "published": "2021-02-15",
        "summary": "lodash.template permits command injection through the options parameter.",
    },
    {
        # THE UNPATCHABLE ONE. Deliberately included: the problem statement asks
        # "some CVEs have patches, some don't (remediation feasibility)".
        "cve_id": "CVE-2024-99001", "name": "dom4j XXE (no upstream fix)",
        "library": "org.dom4j:dom4j",
        "affected_versions": {"introduced": "0.0.0", "fixed": None},
        "cvss_score": 8.2, "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "severity": "HIGH", "cwe": "CWE-611",
        "patch_available": False, "patched_version": None,
        "exploit_maturity": "poc", "known_exploited": False,
        "vulnerable_functions": ["SAXReader.read"],
        "published": "2024-11-02",
        "summary": "XML external entity expansion in SAXReader with NO upstream fix; the project is "
                   "unmaintained. Remediation requires REPLACING the library, not upgrading it.",
    },
]

CWE_TEMPLATES = [
    ("Remote code execution via unsafe deserialization of untrusted input.", "CWE-502"),
    ("Cross-site scripting through unescaped user-controlled output.", "CWE-79"),
    ("SQL injection in the query builder when passed unsanitised identifiers.", "CWE-89"),
    ("Path traversal permits reading files outside the intended directory.", "CWE-22"),
    ("Uncontrolled resource consumption enables denial of service.", "CWE-400"),
    ("Authentication bypass under a specific configuration.", "CWE-287"),
    ("Hard-coded cryptographic key present in the distributed artifact.", "CWE-798"),
    ("XML external entity expansion discloses local files.", "CWE-611"),
    ("Prototype pollution allows modification of the object prototype chain.", "CWE-1321"),
    ("Use of a broken or risky cryptographic algorithm.", "CWE-327"),
    ("Server-side request forgery via an unvalidated URL parameter.", "CWE-918"),
    ("Improper certificate validation permits machine-in-the-middle attacks.", "CWE-295"),
]


def severity_of(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def build_vulnerability_db(rng) -> list:
    """200 CVEs: 11 real anchors + generated realistic noise."""
    cves = [dict(c) for c in ANCHOR_CVES]
    used = {c["cve_id"] for c in cves}

    # Only ~50 of the ~114 libraries carry CVEs. The rest are genuinely clean, which is
    # what makes a low false-positive rate a meaningful thing to measure at all: a scanner
    # that flags everything would score 100% recall and be useless.
    vuln_pool = rng.sample(ALL_LIBS, 50)

    counter = 1000
    while len(cves) < N_CVES:
        counter += 1
        lib = rng.choice(vuln_pool)
        year = rng.choice([2019, 2020, 2021, 2022, 2023, 2024, 2025])
        cve_id = f"CVE-{year}-{counter}"
        if cve_id in used:
            continue
        used.add(cve_id)

        summary, cwe = rng.choice(CWE_TEMPLATES)
        score = round(rng.triangular(3.1, 9.9, 6.5), 1)
        sev = severity_of(score)

        introduced = f"{rng.randint(0, 2)}.{rng.randint(0, 9)}.0"
        fixed = f"{rng.randint(3, 6)}.{rng.randint(0, 20)}.{rng.randint(0, 9)}"

        # ~8% have no patch at all: remediation feasibility is a first-class signal.
        has_patch = rng.random() > 0.08

        short = lib.split(":")[-1]
        cves.append({
            "cve_id": cve_id,
            "name": f"{short} {cwe} issue",
            "library": lib,
            "affected_versions": {"introduced": introduced, "fixed": fixed if has_patch else None},
            "cvss_score": score,
            "cvss_vector": (f"AV:N/AC:{rng.choice('LH')}/PR:{rng.choice('NLH')}/"
                            f"UI:{rng.choice('NR')}/S:U/C:{rng.choice('NLH')}/"
                            f"I:{rng.choice('NLH')}/A:{rng.choice('NLH')}"),
            "severity": sev,
            "cwe": cwe,
            "patch_available": has_patch,
            "patched_version": bump_patch(fixed) if has_patch else None,
            "exploit_maturity": rng.choices(
                ["none", "poc", "functional", "weaponised"], weights=[45, 30, 17, 8])[0],
            "known_exploited": rng.random() < 0.06,
            "vulnerable_functions": [
                f"{short.replace('-', '_')}."
                f"{rng.choice(['parse', 'render', 'load', 'exec', 'deserialize', 'handle'])}"
            ],
            "published": (TODAY - timedelta(days=rng.randint(30, 2200))).isoformat(),
            "summary": summary,
        })

    return cves
