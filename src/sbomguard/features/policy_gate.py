"""
SBOMGuard — the CI/CD policy gate.

THE FEATURE THAT GIVES THE TOOL TEETH
=====================================
Everything else in this project REPORTS on risk. Reports do not stop risk from being
merged. Log4Shell did not enter those codebases because nobody had a scanner; it entered
because nothing in the pipeline had the authority to say NO.

This module is that authority. It returns a UNIX exit code, so it can sit in a CI pipeline
and FAIL A BUILD.

    exit 0   ->  policy satisfied, ship it
    exit 1   ->  policy violated, the merge is blocked

The policy is declarative and lives beside the code it governs, so it can be reviewed,
diffed and argued about in a pull request like any other engineering decision.

DESIGN NOTE — why the default policy is not "block everything"
--------------------------------------------------------------
A gate that fails 80% of builds gets bypassed within a week, and then you have neither a
gate nor a report. So the default policy blocks only what is genuinely indefensible:

    * an actively-exploited CVE that is reachable from our code
    * a CRITICAL, reachable, patchable vulnerability in an internet-facing app
    * a copyleft violation in something we actually ship
    * a component with no license at all

Everything else WARNS. The gate is credible precisely because it is narrow: when it fires,
everyone knows something is really wrong.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..analyzer import AnalysisResult, Finding


@dataclass
class Policy:
    """A declarative supply-chain policy. Ships as code, reviewed in a PR."""

    name: str = "default"

    # ---- Hard blocks: fail the build ----
    block_known_exploited: bool = True          # a CVE exploited in the wild, reachable
    block_critical_reachable: bool = True       # CRITICAL + reachable + a patch exists
    block_license_violation: bool = True        # copyleft violation in a shipped product
    block_undeclared_license: bool = True       # no license = no rights
    max_priority_score: float = 85.0            # anything above this fails

    # ---- Warnings: report, do not block ----
    warn_unmaintained: bool = True
    warn_unreachable_critical: bool = True
    warn_no_patch: bool = True

    # ---- Scope ----
    only_internet_facing: bool = False          # apply hard blocks only to exposed apps
    exempt_apps: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class Violation:
    severity: str            # BLOCK | WARN
    rule: str
    app_name: str
    library: str
    version: str
    message: str
    remediation: str
    cve_ids: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def evaluate(result: AnalysisResult, policy: Policy | None = None,
             app_id: str | None = None) -> dict:
    """Run the policy. Returns a verdict plus an exit code you can hand to CI."""
    policy = policy or Policy()

    findings = result.for_app(app_id) if app_id else result.findings
    blocks: list[Violation] = []
    warns: list[Violation] = []

    for f in findings:
        if not f.score.at_risk:
            continue
        app = f.application
        if app.app_id in policy.exempt_apps:
            continue

        dep = f.dependency
        in_scope = (not policy.only_internet_facing) or app.internet_facing
        worst = max(f.vulns, key=lambda v: v.cvss_score) if f.vulns else None

        # ---------------- HARD BLOCKS ----------------
        if worst and policy.block_known_exploited and worst.known_exploited and worst.reachable and in_scope:
            blocks.append(Violation(
                "BLOCK", "block_known_exploited", app.name, dep.library_name, dep.version,
                f"{worst.cve_id} is being ACTIVELY EXPLOITED in the wild and the vulnerable "
                f"function is reachable from this application's code. This is not a "
                f"vulnerability, it is an open door.",
                (f"Upgrade to {worst.patched_version} before merging."
                 if worst.patch_available else
                 "No patch exists. This component must be removed before this can merge."),
                [worst.cve_id],
            ))
            continue

        if (worst and policy.block_critical_reachable and worst.severity == "CRITICAL"
                and worst.reachable and worst.patch_available and in_scope):
            blocks.append(Violation(
                "BLOCK", "block_critical_reachable", app.name, dep.library_name, dep.version,
                f"{worst.cve_id} is CRITICAL (CVSS {worst.cvss_score}), the vulnerable "
                f"function is reachable from our code, AND a fix is available. There is no "
                f"defensible reason to ship this.",
                f"Upgrade {dep.library_name} {dep.version} -> {worst.patched_version}.",
                [worst.cve_id],
            ))
            continue

        if (policy.block_undeclared_license and dep.license in ("UNKNOWN", "", None)):
            blocks.append(Violation(
                "BLOCK", "block_undeclared_license", app.name, dep.library_name, dep.version,
                "This component declares NO license. Absent an explicit grant, copyright law "
                "reserves all rights to the author — we have no legal right to use it at all.",
                "Obtain an explicit license grant from the maintainer, or remove the dependency.",
            ))
            continue

        if (policy.block_license_violation and f.license and f.license.violation
                and app.proprietary and (app.distributed or dep.license == "AGPL-3.0")):
            blocks.append(Violation(
                "BLOCK", "block_license_violation", app.name, dep.library_name, dep.version,
                f"{dep.license}: {f.license.reason}",
                f.license.obligation or "Replace with a permissively licensed equivalent.",
            ))
            continue

        if policy.max_priority_score and f.score.priority_score > policy.max_priority_score and in_scope:
            blocks.append(Violation(
                "BLOCK", "max_priority_score", app.name, dep.library_name, dep.version,
                f"Priority score {f.score.priority_score:.0f} exceeds the policy ceiling of "
                f"{policy.max_priority_score:.0f}. Drivers: {'; '.join(f.score.drivers[:2])}",
                "Reduce the risk or file a documented, time-boxed exception.",
                [v.cve_id for v in f.vulns],
            ))
            continue

        # ---------------- WARNINGS ----------------
        if worst and policy.warn_unreachable_critical and worst.severity == "CRITICAL" and not worst.reachable:
            warns.append(Violation(
                "WARN", "warn_unreachable_critical", app.name, dep.library_name, dep.version,
                f"{worst.cve_id} is CRITICAL but its vulnerable function is NOT reachable from "
                f"our code. Not blocking the build — but this is one refactor away from "
                f"becoming reachable, and then it is a CRITICAL you already shipped.",
                f"Schedule the upgrade to {worst.patched_version} this sprint.",
                [worst.cve_id],
            ))

        if worst and policy.warn_no_patch and not worst.patch_available:
            warns.append(Violation(
                "WARN", "warn_no_patch", app.name, dep.library_name, dep.version,
                f"{worst.cve_id} has NO upstream fix. Not blocking, because blocking would "
                f"mean this build can never pass — but the exposure is permanent until the "
                f"component is replaced.",
                "Scope a replacement. Apply a compensating control in the meantime.",
                [worst.cve_id],
            ))

        if policy.warn_unmaintained and f.score.primary_risk == "unmaintained":
            warns.append(Violation(
                "WARN", "warn_unmaintained", app.name, dep.library_name, dep.version,
                f"No release in {f.maintenance.years} years, "
                f"{dep.maintainer_count} maintainer(s). No CVE today — but no fix tomorrow.",
                "Add a replacement to the backlog while it is still cheap.",
            ))

    passed = len(blocks) == 0

    return {
        "policy": policy.name,
        "passed": passed,
        "exit_code": 0 if passed else 1,
        "verdict": "PASS — policy satisfied" if passed
                   else f"FAIL — {len(blocks)} policy violation(s) block this build",
        "blocks": [v.to_dict() for v in sorted(blocks, key=lambda v: v.rule)],
        "warnings": [v.to_dict() for v in warns[:30]],
        "block_count": len(blocks),
        "warning_count": len(warns),
        "policy_config": policy.to_dict(),
        "ci_snippet": _ci_snippet(),
    }


def _ci_snippet() -> str:
    return """# .github/workflows/supply-chain.yml
name: Supply Chain Gate
on: [pull_request]

jobs:
  sbomguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Generate a REAL SBOM from the repository
      - name: Generate SBOM
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          syft . -o cyclonedx-json > sbom.json

      # SBOMGuard ingests CycloneDX natively, so no translation step is needed.
      - name: Enforce supply-chain policy
        run: |
          python -m sbomguard.cli gate --sbom sbom.json --policy strict
        # exit 1 fails the job, which blocks the merge.
"""


# ======================================================================================
# Predefined policies
# ======================================================================================
POLICIES = {
    "default": Policy(name="default"),

    "strict": Policy(
        name="strict",
        block_known_exploited=True,
        block_critical_reachable=True,
        block_license_violation=True,
        block_undeclared_license=True,
        max_priority_score=70.0,
    ),

    "permissive": Policy(
        name="permissive",
        block_known_exploited=True,      # even the loosest policy blocks an active exploit
        block_critical_reachable=False,
        block_license_violation=False,
        block_undeclared_license=False,
        max_priority_score=95.0,
        only_internet_facing=True,
    ),

    "pci": Policy(
        name="pci",
        # For anything in PCI-DSS scope, the bar is simply higher. There is no version of
        # "we shipped a reachable critical to a cardholder-data system" that survives an
        # assessment.
        block_known_exploited=True,
        block_critical_reachable=True,
        block_license_violation=True,
        block_undeclared_license=True,
        max_priority_score=60.0,
    ),
}
