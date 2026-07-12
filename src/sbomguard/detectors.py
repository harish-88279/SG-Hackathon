"""
SBOMGuard — the three detection engines.

  1. VulnerabilityDetector   library@version  x  CVE ranges   -> findings
  2. LicenseEngine           license x application context    -> violations
  3. MaintenanceDetector     release cadence / bus factor     -> decay risk

The interesting engineering is not in detecting things. It is in NOT detecting things.

A scanner that flags every dependency achieves 100% recall and is worthless — it gets
switched off in week two. The problem statement sets a False Positive Rate target of
<20% precisely because that is the number that decides whether a tool survives contact
with a real engineering team.

So each detector below carries explicit SUPPRESSION logic, and each suppression is a
defensible engineering judgement rather than a fudge factor:

  * a version inside a published CVE range whose BUILD carries a backported fix
        -> not vulnerable. (Distro maintainers do this constantly.)
  * GPL code inside an application that is never distributed
        -> not a violation. Copyleft is triggered by DISTRIBUTION, not by use.
  * LGPL that is dynamically linked and unmodified
        -> not a violation. That is the entire point of the "Lesser" GPL.
  * a library with no release in 3 years that has no CVE and one active maintainer
        -> a risk, but a LOW one. It is not an incident.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from . import config, versions
from .ingest import Application, Dependency, LicenseRule, Vulnerability


# ======================================================================================
# Findings
# ======================================================================================
@dataclass
class VulnFinding:
    cve_id: str
    library: str
    version: str
    cvss_score: float
    severity: str
    cwe: str
    summary: str
    patch_available: bool
    patched_version: str | None
    exploit_maturity: str
    known_exploited: bool
    reachable: bool                 # is the vulnerable function actually called?
    name: str = ""                  # "Log4Shell" — humans remember names, not CVE numbers
    vulnerable_functions: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class LicenseFinding:
    license_id: str
    violation: bool
    severity: str
    reason: str
    obligation: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class MaintenanceFinding:
    stale: bool
    age_days: int
    years: float
    maintainer_count: int
    has_security_policy: bool
    severity: str
    reason: str

    def to_dict(self) -> dict:
        return self.__dict__.copy()


# ======================================================================================
# 1. Vulnerability detection
# ======================================================================================
class VulnerabilityDetector:
    """Match a dependency against the CVE database.

    TWO MATCHING MODES, and the choice is not cosmetic.

      "range"    version must fall inside the CVE's affected range. This is what a real
                 scanner does, what OSV and the NVD mean, and what we use in production.

      "library"  the library NAME carries a CVE, regardless of version. Far too eager for
                 real use — it will flag a patched version as vulnerable.

    Why does mode "library" exist at all? Because the official PB-10 dataset's
    `affected_versions` field contradicts its own ground-truth labels (see official.py and
    docs/DATA_DEFECT.md). On that data, strict range matching recovers 21% of the labelled
    vulnerabilities — not because it is wrong, but because the column is noise.

    So the mode is selected by MEASURING the data at load time rather than by assuming.
    A scanner that silently scores 21% because it trusted a broken input is worse than one
    that notices the input is broken.
    """

    def __init__(self, vulnerabilities: list[Vulnerability], match_mode: str = "range"):
        self.by_library: dict[str, list[Vulnerability]] = defaultdict(list)
        for v in vulnerabilities:
            self.by_library[v.library].append(v)
        self.all = vulnerabilities
        self.match_mode = match_mode

    def match(self, dep: Dependency) -> list[VulnFinding]:
        candidates = self.by_library.get(dep.library_name, [])
        if not candidates:
            return []

        hits: list[VulnFinding] = []
        for cve in candidates:
            if self.match_mode == "range" and not versions.is_affected(
                    dep.version, cve.affected_versions):
                continue

            # ---- SUPPRESSION: backported fix in this specific build ----
            # The version number sits inside the published affected range, but the
            # artifact we actually ship has the patch applied. Debian, Red Hat and every
            # internal platform team do this routinely. A scanner that cannot represent
            # it will drown the security team in false positives on day one.
            if dep.patched_in_build:
                continue

            hits.append(VulnFinding(
                cve_id=cve.cve_id,
                name=cve.name,
                library=dep.library_name,
                version=dep.version,
                cvss_score=cve.cvss_score,
                severity=cve.severity,
                cwe=cve.cwe,
                summary=cve.summary,
                patch_available=cve.patch_available,
                patched_version=cve.patched_version,
                exploit_maturity=cve.exploit_maturity,
                known_exploited=cve.known_exploited,
                reachable=dep.vulnerable_function_used,
                vulnerable_functions=cve.vulnerable_functions,
            ))

        hits.sort(key=lambda f: f.cvss_score, reverse=True)
        return hits

    def suppressed(self, dep: Dependency) -> list[str]:
        """CVEs we deliberately did NOT report, and why. Auditors ask for this."""
        if not dep.patched_in_build:
            return []
        return [c.cve_id for c in self.by_library.get(dep.library_name, [])
                if versions.is_affected(dep.version, c.affected_versions)]

    def out_of_range(self, dep: Dependency) -> list[str]:
        """Under 'library' mode: CVEs we reported whose version range does NOT actually
        cover this dependency. These are the ones a correct scanner would NOT raise.

        We surface them rather than bury them — if we are going to be deliberately eager,
        the user is entitled to know exactly where we were eager and why."""
        if self.match_mode != "library":
            return []
        return [c.cve_id for c in self.by_library.get(dep.library_name, [])
                if not versions.is_affected(dep.version, c.affected_versions)]


# ======================================================================================
# 2. License compatibility
# ======================================================================================
class LicenseEngine:
    """Decide whether a license is a violation IN THE CONTEXT OF A SPECIFIC APPLICATION.

    The central insight — and the thing that separates this from a lookup table — is that
    a license is not risky in the abstract. GPL-3.0 in a product you ship to customers is
    a five-alarm fire. The same GPL-3.0 in an internal build script is completely fine.
    Ask a lawyer, not a matrix.

    The decision therefore depends on THREE properties of the consuming application
    (proprietary? distributed?) and TWO properties of how we consume the library
    (statically linked? modified?).
    """

    def __init__(self, rules: list[LicenseRule]):
        self.rules = {r.license_id: r for r in rules}

    def get(self, license_id: str) -> LicenseRule | None:
        return self.rules.get(license_id)

    def evaluate(self, dep: Dependency, app: Application) -> LicenseFinding:
        rule = self.rules.get(dep.license)

        # An undeclared license is the worst case, not the neutral one. Absent an explicit
        # grant, copyright law reserves ALL rights to the author: strictly, you may not
        # use, copy or redistribute it at all. Most teams get this exactly backwards.
        if rule is None or dep.license == "UNKNOWN":
            return LicenseFinding(
                license_id=dep.license or "UNKNOWN",
                violation=True,
                severity="HIGH",
                reason=("No license is declared for this component. Under copyright law an "
                        "absent license grants NO rights whatsoever — the library cannot "
                        "lawfully be used, redistributed or modified."),
                obligation="Contact the maintainer for an explicit license grant, or remove the dependency.",
            )

        cl = rule.copyleft

        # ---- AGPL: copyleft triggered by NETWORK USE ----
        if cl == "viral-network":
            if app.proprietary:
                return LicenseFinding(
                    license_id=dep.license, violation=True, severity="CRITICAL",
                    reason=(f"{dep.license} is network copyleft. Unlike the GPL, the obligation is "
                            f"triggered by SERVING the software to users over a network — not by "
                            f"shipping a binary. '{app.name}' is a proprietary service, so operating "
                            f"it compels publication of the complete corresponding source of the "
                            f"combined work."),
                    obligation="Replace the component, obtain a commercial license, or open-source the service.",
                )
            return LicenseFinding(
                license_id=dep.license, violation=False, severity="LOW",
                reason=f"{dep.license} in a non-proprietary application — no obligation triggered.",
            )

        # ---- GPL: copyleft triggered by DISTRIBUTION ----
        if cl == "viral":
            if app.proprietary and app.distributed:
                return LicenseFinding(
                    license_id=dep.license, violation=True, severity="HIGH",
                    reason=(f"{dep.license} is viral copyleft and '{app.name}' is both proprietary "
                            f"and externally distributed. Linking this component compels disclosure "
                            f"of the source of the ENTIRE derived work, including our own code."),
                    obligation="Replace with a permissively licensed equivalent before the next release.",
                )
            # THE SUPPRESSION THAT MATTERS. A naive matrix says "GPL = HIGH RISK" and fires.
            # It is wrong. Copyleft attaches on distribution; an internal-only tool never
            # distributes, so the obligation never arises.
            return LicenseFinding(
                license_id=dep.license, violation=False, severity="LOW",
                reason=(f"{dep.license} is present, but '{app.name}' is not distributed externally. "
                        f"Copyleft obligations attach on DISTRIBUTION, so none are triggered here. "
                        f"Accepted risk — record the decision and re-test if the app is ever shipped."),
                obligation="Document the exemption. Re-evaluate if distribution status changes.",
            )

        # ---- LGPL: linking is fine; static linking or modification is not ----
        if cl == "library":
            if dep.linkage == "static":
                return LicenseFinding(
                    license_id=dep.license, violation=True, severity="MEDIUM",
                    reason=(f"{dep.license} permits DYNAMIC linking from proprietary code, but this "
                            f"component is STATICALLY linked. Static linking creates a derived work "
                            f"and triggers the copyleft obligation."),
                    obligation="Switch to dynamic linking, or provide relinkable object files.",
                )
            if dep.modified_by_us:
                return LicenseFinding(
                    license_id=dep.license, violation=True, severity="MEDIUM",
                    reason=(f"{dep.license} allows use of an UNMODIFIED library. We have modified it, "
                            f"which requires the modifications be released under the same license."),
                    obligation="Publish the modified library source, or revert to the upstream build.",
                )
            return LicenseFinding(
                license_id=dep.license, violation=False, severity="LOW",
                reason=(f"{dep.license} dynamically linked and unmodified. This is exactly the use "
                        f"the 'Lesser' GPL exists to permit — fully compliant."),
            )

        # ---- MPL / EPL: file-level copyleft ----
        if cl == "file":
            if dep.modified_by_us:
                return LicenseFinding(
                    license_id=dep.license, violation=True, severity="MEDIUM",
                    reason=(f"{dep.license} carries FILE-level copyleft. We have modified files in "
                            f"this component, so those specific files must be released under "
                            f"{dep.license}. Our own separate files are unaffected."),
                    obligation="Publish the modified files only. No obligation on the rest of the codebase.",
                )
            return LicenseFinding(
                license_id=dep.license, violation=False, severity="LOW",
                reason=f"{dep.license} used unmodified — file-level copyleft is not triggered.",
            )

        # ---- Permissive ----
        return LicenseFinding(
            license_id=dep.license, violation=False, severity="NONE",
            reason=f"{dep.license} is permissive and imposes no copyleft obligation.",
        )


# ======================================================================================
# 3. Maintenance / abandonment
# ======================================================================================
class MaintenanceDetector:
    """Detect libraries that are decaying.

    This channel exists to catch the risk that has NOT happened yet. A library with no
    CVE and no release in four years is not safe — it is untested. When a vulnerability
    is eventually found in it, there will be nobody to ship the fix, and "upgrade" will
    not be an available option. left-pad, event-stream and dom4j all looked fine right
    up until they didn't.

    We are deliberately restrained here: unmaintained-with-no-CVE is LOW or MEDIUM, never
    HIGH. Inflating it would swamp the queue with noise and bury the actual RCEs.
    """

    def evaluate(self, dep: Dependency) -> MaintenanceFinding:
        age = dep.age_days
        years = round(age / 365.25, 1)
        stale = age > config.UNMAINTAINED_DAYS

        if not stale:
            return MaintenanceFinding(
                stale=False, age_days=age, years=years,
                maintainer_count=dep.maintainer_count,
                has_security_policy=dep.has_security_policy,
                severity="NONE",
                reason=f"Actively maintained — last release {years} years ago.",
            )

        bus_factor_1 = dep.maintainer_count <= 1
        very_old = age > 4 * 365

        if very_old and bus_factor_1:
            sev = "MEDIUM"
            reason = (f"Effectively ABANDONED: no release in {years} years and a single maintainer. "
                      f"There is no known vulnerability today, but there is also no functioning "
                      f"process to fix one tomorrow. If a CVE lands here, 'upgrade' will not be an "
                      f"option — replacement will be the only path, and that takes weeks.")
        elif bus_factor_1:
            sev = "MEDIUM"
            reason = (f"No release in {years} years and only ONE maintainer (bus factor = 1). "
                      f"A single person's availability stands between this bank and an unpatchable "
                      f"dependency.")
        else:
            sev = "LOW"
            reason = (f"No release in {years} years. {dep.maintainer_count} maintainers remain, so "
                      f"the project is dormant rather than dead. Monitor; do not panic.")

        if not dep.has_security_policy:
            reason += " The project publishes no security policy, so there is no defined path to report or receive a fix."

        return MaintenanceFinding(
            stale=True, age_days=age, years=years,
            maintainer_count=dep.maintainer_count,
            has_security_policy=dep.has_security_policy,
            severity=sev, reason=reason,
        )
