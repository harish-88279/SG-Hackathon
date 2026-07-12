"""
SBOMGuard — the remediation playbook.

A LIST OF FINDINGS IS NOT A PLAN
================================
Every SCA tool ends with a sorted table and considers the job done. It is not done. The
engineer now has to work out, from 265 rows, what to actually type — and in what order,
and which fixes collapse into one another.

This module does that work. It converts findings into an ORDERED, DEDUPLICATED, EXECUTABLE
plan, and it makes three moves that a sorted table cannot:

1. IT COLLAPSES. One `log4j-core -> 2.17.1` bump resolves the same CVE in four
   applications. That is ONE action, not four tickets. We group by (library, fix) and
   report the fix once, with its full blast radius attached.

2. IT SEQUENCES. Fix order is not the same as risk order. You patch the actively-exploited
   internet-facing RCE before the unreachable CVSS 9.8 in a batch job, and you do the
   dependency bumps that unblock other fixes first.

3. IT KNOWS WHEN "UPGRADE" IS A LIE. Where no patch exists, the plan says so, and issues a
   REPLACEMENT action with a compensating control to hold the line meanwhile — rather than
   telling an engineer to upgrade to a version that does not exist.

Output is per-ecosystem and copy-pasteable: real Maven/npm/pip commands.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ..analyzer import AnalysisResult, Finding


@dataclass
class Action:
    action_id: str
    action_type: str          # UPGRADE | REPLACE | PIN_TRANSITIVE | LEGAL_REVIEW | ACCEPT_RISK
    urgency: str              # IMMEDIATE | THIS_WEEK | THIS_SPRINT | BACKLOG
    library: str
    current_versions: list
    target_version: str | None
    ecosystem: str

    title: str
    rationale: str
    commands: list = field(default_factory=list)
    caveats: list = field(default_factory=list)

    affected_apps: list = field(default_factory=list)
    cve_ids: list = field(default_factory=list)
    max_priority: float = 0.0
    finding_count: int = 0
    compensating_control: str = ""

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "urgency": self.urgency,
            "library": self.library,
            "current_versions": self.current_versions,
            "target_version": self.target_version,
            "ecosystem": self.ecosystem,
            "title": self.title,
            "rationale": self.rationale,
            "commands": self.commands,
            "caveats": self.caveats,
            "affected_apps": self.affected_apps,
            "cve_ids": self.cve_ids,
            "max_priority": round(self.max_priority, 1),
            "finding_count": self.finding_count,
            "compensating_control": self.compensating_control,
        }


# ======================================================================================
# Ecosystem-specific commands
# ======================================================================================
def _upgrade_commands(ecosystem: str, library: str, target: str,
                      transitive: bool, parent: str = "") -> list[str]:
    eco = (ecosystem or "").lower()

    if eco == "maven":
        group, _, artifact = library.partition(":")
        if transitive:
            return [
                "# Transitive: pin it explicitly in <dependencyManagement> so the",
                "# resolved version wins regardless of what the parent requests.",
                "<dependencyManagement>",
                "  <dependencies>",
                "    <dependency>",
                f"      <groupId>{group}</groupId>",
                f"      <artifactId>{artifact}</artifactId>",
                f"      <version>{target}</version>",
                "    </dependency>",
                "  </dependencies>",
                "</dependencyManagement>",
                "",
                f"mvn dependency:tree -Dincludes={group}:{artifact}   # verify the pin took effect",
            ]
        return [
            f"# Update the <version> of {library} to {target} in pom.xml",
            f"mvn versions:use-dep-version -Dincludes={library} -DdepVersion={target}",
            f"mvn dependency:tree -Dincludes={library}",
        ]

    if eco == "npm":
        if transitive:
            return [
                "# Transitive: force resolution via the overrides block in package.json",
                "{",
                '  "overrides": {',
                f'    "{library}": "{target}"',
                "  }",
                "}",
                "",
                "npm install",
                f"npm ls {library}   # confirm every path now resolves to {target}",
            ]
        return [
            f"npm install {library}@{target} --save",
            f"npm ls {library}",
        ]

    if eco == "pypi":
        if transitive:
            return [
                f"# Transitive: pin the child explicitly in requirements.txt / constraints.txt",
                f"{library}=={target}",
                "",
                "pip install -r requirements.txt --upgrade",
                f"pip show {library}",
            ]
        return [
            f"pip install --upgrade '{library}=={target}'",
            f"# then pin it: {library}=={target}   in requirements.txt",
        ]

    return [f"# Upgrade {library} to {target} using your package manager"]


def _replacement_suggestions(library: str) -> list[str]:
    """Concrete, named alternatives for the libraries we know are dead."""
    known = {
        "org.dom4j:dom4j": ["jakarta.xml.bind (JAXB)", "org.w3c.dom (JDK built-in)",
                            "com.fasterxml.woodstox:woodstox-core"],
        "xerces:xercesImpl": ["The JDK's built-in JAXP parser (no third-party dependency needed)"],
        "org.apache.struts:struts2-core": ["Spring MVC", "Jakarta REST (JAX-RS)"],
        "request": ["axios", "node-fetch", "undici (built into modern Node)"],
        "moment": ["date-fns", "dayjs", "Temporal (native, stage 3)"],
        "left-pad": ["String.prototype.padStart (native since ES2017)"],
        "pycrypto": ["cryptography", "pycryptodome"],
        "underscore": ["lodash-es", "native ES2015+ array/object methods"],
        "event-stream": ["Node streams (native)", "through2"],
        "vm2": ["isolated-vm", "a separate OS process with seccomp"],
        "xmldom": ["@xmldom/xmldom (the maintained fork)", "fast-xml-parser"],
        "commons-collections:commons-collections": [
            "org.apache.commons:commons-collections4", "Guava", "the JDK Collections API"],
    }
    return known.get(library, [])


# ======================================================================================
# Playbook construction
# ======================================================================================
def build_playbook(result: AnalysisResult, limit: int = 40) -> dict:
    risky = result.at_risk()

    # ---- 1. COLLAPSE: group findings by the FIX, not by the finding ----
    # The key insight. Four apps with the same vulnerable log4j is ONE upgrade.
    groups: dict[tuple, list[Finding]] = defaultdict(list)
    for f in risky:
        if f.score.primary_risk in ("vulnerable_dependency", "transitive_vulnerability"):
            worst = max(f.vulns, key=lambda v: v.cvss_score)
            target = worst.patched_version if worst.patch_available else None
            key = ("VULN", f.dependency.library_name, target)
        elif f.score.primary_risk == "license_conflict":
            key = ("LICENSE", f.dependency.library_name, f.dependency.license)
        else:
            key = ("MAINT", f.dependency.library_name, None)
        groups[key].append(f)

    actions: list[Action] = []
    for i, (key, members) in enumerate(groups.items(), start=1):
        kind, library, target = key
        actions.append(_build_action(f"ACT-{i:03d}", kind, library, target, members))

    # ---- 2. SEQUENCE ----
    urgency_rank = {"IMMEDIATE": 0, "THIS_WEEK": 1, "THIS_SPRINT": 2, "BACKLOG": 3}
    actions.sort(key=lambda a: (urgency_rank.get(a.urgency, 9), -a.max_priority))

    # Report the TRUE collapse ratio over every group, not just the ones we display.
    total_actions_before_limit = len(actions)
    total_findings = sum(a.finding_count for a in actions)
    actions = actions[:limit]

    for i, a in enumerate(actions, start=1):
        a.action_id = f"ACT-{i:03d}"

    # ---- 3. Summarise ----
    by_urgency = defaultdict(int)
    for a in actions:
        by_urgency[a.urgency] += 1

    return {
        "actions": [a.to_dict() for a in actions],
        "summary": {
            "total_actions": total_actions_before_limit,
            "actions_shown": len(actions),
            "findings_collapsed": total_findings,
            "collapse_ratio": (round(total_findings / total_actions_before_limit, 1)
                               if total_actions_before_limit else 0),
            "by_urgency": dict(by_urgency),
            "immediate": by_urgency.get("IMMEDIATE", 0),
        },
        "interpretation": (
            f"{total_findings} individual findings collapse into {total_actions_before_limit} "
            f"distinct ACTIONS, because one dependency bump frequently fixes the same flaw "
            f"across several applications at once. Work the list top-down: it is ordered by "
            f"urgency, then by the worst finding each action resolves."
        ),
    }


def _build_action(action_id: str, kind: str, library: str,
                  target: str | None, members: list[Finding]) -> Action:
    apps = sorted({f.application.name for f in members})
    versions = sorted({f.dependency.version for f in members})
    ecosystem = members[0].dependency.ecosystem
    max_priority = max(f.score.priority_score for f in members)
    transitive = any(f.dependency.dependency_type == "transitive" for f in members)
    parent = next((f.dependency.parent_library for f in members
                   if f.dependency.parent_library), "")

    # ---------------- VULNERABILITY ----------------
    if kind == "VULN":
        all_v = [v for f in members for v in f.vulns]
        worst = max(all_v, key=lambda v: v.cvss_score)
        cves = sorted({v.cve_id for v in all_v})
        kev = any(v.known_exploited for v in all_v)
        reachable = any(v.reachable for v in all_v)

        # ---- Urgency: not the same thing as severity ----
        if kev and reachable:
            urgency = "IMMEDIATE"
        elif kev or (worst.severity == "CRITICAL" and reachable):
            urgency = "IMMEDIATE"
        elif worst.severity in ("CRITICAL", "HIGH") and reachable:
            urgency = "THIS_WEEK"
        elif worst.severity in ("CRITICAL", "HIGH"):
            urgency = "THIS_SPRINT"
        else:
            urgency = "BACKLOG"

        # ---- NO PATCH: "upgrade" would be a lie ----
        if not worst.patch_available:
            alts = _replacement_suggestions(library)
            return Action(
                action_id=action_id, action_type="REPLACE",
                urgency="IMMEDIATE" if worst.severity in ("CRITICAL", "HIGH") else "THIS_SPRINT",
                library=library, current_versions=versions, target_version=None,
                ecosystem=ecosystem,
                title=f"REPLACE {library} — no upstream patch exists",
                rationale=(
                    f"{worst.cve_id} ({worst.severity}, CVSS {worst.cvss_score}) affects "
                    f"{library}, and there is NO fixed version. Upgrading is not possible: the "
                    f"project is not shipping a fix. The component must be replaced. Treat this "
                    f"as a project with a budget, not a ticket in a sprint — and apply a "
                    f"compensating control TODAY, because the exposure window stays open until "
                    f"the replacement lands."
                ),
                commands=(
                    [f"# No fixed version of {library} exists. Candidate replacements:"]
                    + [f"#   - {a}" for a in alts]
                    + ([f"# Then remove {library} from the build entirely."] if alts
                       else ["# No drop-in replacement is known. Scope a migration."])
                ),
                caveats=[
                    "This is a breaking change. Budget for API migration and regression testing.",
                    "Do not close this item by 'upgrading' — there is nothing to upgrade to.",
                ],
                compensating_control=(
                    f"Until the replacement ships: disable the affected code path "
                    f"({', '.join(worst.vulnerable_functions[:1]) or 'the vulnerable function'}), "
                    f"or block exploitation at the WAF, or segment the affected service off the "
                    f"network. Record which control you chose — an auditor will ask."
                ),
                affected_apps=apps, cve_ids=cves, max_priority=max_priority,
                finding_count=len(members),
            )

        # ---- Normal upgrade path ----
        cmds = _upgrade_commands(ecosystem, library, worst.patched_version, transitive, parent)
        caveats = []
        if transitive:
            caveats.append(
                f"This is a TRANSITIVE dependency (pulled in by {parent or 'a parent library'}). "
                f"Bumping your direct dependency may not be enough — verify the resolved version "
                f"after the change, and pin it if the parent still drags in the old one."
            )
        if not reachable:
            caveats.append(
                "The vulnerable function is not currently reachable from your code, so this is "
                "not an emergency. It IS still an unpatched liability, and one refactor away "
                "from becoming reachable. Fix it on the normal cadence."
            )
        if kev:
            caveats.append(
                "This CVE is being actively exploited in the wild. After patching, hunt for "
                "indicators of compromise — assume attempted exploitation, not theoretical risk."
            )

        title = f"Upgrade {library} {'/'.join(versions[:2])} -> {worst.patched_version}"
        if len(apps) > 1:
            title += f"  ({len(apps)} apps)"

        return Action(
            action_id=action_id, action_type="PIN_TRANSITIVE" if transitive else "UPGRADE",
            urgency=urgency, library=library, current_versions=versions,
            target_version=worst.patched_version, ecosystem=ecosystem,
            title=title,
            rationale=(
                f"Resolves {len(cves)} CVE(s) — worst is {worst.cve_id} ({worst.severity}, "
                f"CVSS {worst.cvss_score}) — across {len(apps)} application(s): "
                f"{', '.join(apps)}. "
                + ("Exploited in the wild. " if kev else "")
                + ("The vulnerable function is reachable from our code. " if reachable
                   else "The vulnerable function is NOT reachable from our code, so this is "
                        "scheduled work rather than an incident. ")
            ),
            commands=cmds, caveats=caveats, affected_apps=apps, cve_ids=cves,
            max_priority=max_priority, finding_count=len(members),
        )

    # ---------------- LICENSE ----------------
    if kind == "LICENSE":
        lic = target or members[0].dependency.license
        worst_f = max(members, key=lambda f: f.score.priority_score)
        reason = worst_f.license.reason if worst_f.license else ""
        obligation = worst_f.license.obligation if worst_f.license else ""
        sev = worst_f.score.severity

        return Action(
            action_id=action_id, action_type="LEGAL_REVIEW",
            urgency="THIS_WEEK" if sev == "CRITICAL" else "THIS_SPRINT",
            library=library, current_versions=versions, target_version=None,
            ecosystem=ecosystem,
            title=f"Legal review: {library} is {lic}",
            rationale=reason or f"{library} is licensed under {lic}, which conflicts with how "
                                f"{', '.join(apps)} is shipped.",
            commands=[
                f"# This is a LEGAL decision, not an engineering one. Do not let it be made",
                f"# by whoever picks up the ticket.",
                f"#",
                f"# 1. Route {library} ({lic}) to counsel with the usage context:",
                f"#    apps: {', '.join(apps)}",
                f"#    linkage: {worst_f.dependency.linkage}, "
                f"modified: {worst_f.dependency.modified_by_us}",
                f"# 2. Decide: REPLACE with a permissive equivalent / obtain a commercial",
                f"#    license / accept and document.",
                f"# 3. Record the decision in the SBOM attestation.",
            ],
            caveats=[obligation] if obligation else [],
            affected_apps=apps, cve_ids=[], max_priority=max_priority,
            finding_count=len(members),
        )

    # ---------------- MAINTENANCE ----------------
    worst_f = max(members, key=lambda f: f.score.priority_score)
    m = worst_f.maintenance
    alts = _replacement_suggestions(library)

    return Action(
        action_id=action_id, action_type="REPLACE",
        urgency="BACKLOG" if m.severity == "LOW" else "THIS_SPRINT",
        library=library, current_versions=versions, target_version=None,
        ecosystem=ecosystem,
        title=f"Plan replacement of {library} (unmaintained, {m.years}y)",
        rationale=(
            f"{library} has had no release in {m.years} years and has "
            f"{m.maintainer_count} maintainer(s). There is NO vulnerability today. The risk "
            f"is that when one is published — and for a package this old it will be — there "
            f"will be nobody to fix it, and upgrading will not be an option. Replace it now, "
            f"while it is cheap and nobody is panicking."
        ),
        commands=(
            [f"# {library} is dormant. Candidate replacements:"]
            + [f"#   - {a}" for a in alts]
            if alts else
            [f"# No obvious drop-in replacement for {library}.",
             f"# Options: fork and maintain it internally, vendor it, or scope a migration.",
             f"# Whichever you choose, make it an explicit, recorded decision."]
        ),
        caveats=[
            "Deliberately low urgency. Inflating abandonware to CRITICAL is how a security "
            "queue becomes noise and gets ignored. Schedule it; do not page anyone."
        ],
        affected_apps=apps, cve_ids=[], max_priority=max_priority,
        finding_count=len(members),
    )
