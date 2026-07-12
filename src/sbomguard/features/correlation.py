"""
SBOMGuard — cross-application correlation.

THE LOG4SHELL QUESTION
======================
In December 2021 the question that mattered was not "is log4j vulnerable" — everyone knew
that within an hour. The question that took organisations DAYS to answer was:

    "Which of OUR applications actually contain it?"

They could not answer it because dependency data lived in ten different build systems, and
because nobody tracked transitive dependencies at all.

This module answers that question in one graph traversal, and then answers the follow-up
question that a good CISO asks next: "if I fix ONE thing today, what buys me the most?"

Two outputs:

    shared_risk       components present in multiple applications. Sorted by leverage —
                      a single upgrade that clears a CVE in four apps is worth four times
                      one that clears it in one.

    systemic_risk     components so widespread that they are effectively part of the
                      bank's infrastructure. A flaw in one of these is not an application
                      problem, it is an organisational one.
"""
from __future__ import annotations

from collections import defaultdict

from ..analyzer import AnalysisResult


def correlate(result: AnalysisResult) -> dict:
    # library -> findings across every application
    by_library: dict[str, list] = defaultdict(list)
    for f in result.findings:
        by_library[f.dependency.library_name].append(f)

    shared = []
    for library, findings in by_library.items():
        apps = {f.dependency.app_id for f in findings}
        if len(apps) < 2:
            continue

        risky = [f for f in findings if f.score.at_risk]
        if not risky:
            continue

        all_cves = sorted({v.cve_id for f in risky for v in f.vulns})
        worst = max(risky, key=lambda f: f.score.priority_score)

        app_detail = []
        for f in risky:
            app_detail.append({
                "app_id": f.dependency.app_id,
                "app_name": f.application.name,
                "version": f.dependency.version,
                "business_criticality": f.application.business_criticality,
                "internet_facing": f.application.internet_facing,
                "handles_cardholder_data": f.application.handles_cardholder_data,
                "depth": f.true_depth,
                "dependency_type": f.dependency.dependency_type,
                "priority_score": round(f.score.priority_score, 1),
            })
        app_detail.sort(key=lambda d: d["priority_score"], reverse=True)

        versions = sorted({f.dependency.version for f in risky})
        patched = None
        for f in risky:
            for v in f.vulns:
                if v.patch_available and v.patched_version:
                    patched = v.patched_version
                    break
            if patched:
                break

        # LEVERAGE: how much risk does ONE fix retire?
        # Sum of priority across every app it appears in, weighted by app criticality.
        leverage = sum(f.score.priority_score * f.application.criticality_weight
                       for f in risky)

        shared.append({
            "library": library,
            "ecosystem": worst.dependency.ecosystem,
            "affected_app_count": len({f.dependency.app_id for f in risky}),
            "total_app_count": len(apps),
            "versions_in_use": versions,
            "version_fragmentation": len(versions),
            "cve_ids": all_cves,
            "worst_severity": worst.score.severity,
            "max_priority": round(worst.score.priority_score, 1),
            "leverage_score": round(leverage, 1),
            "single_fix_version": patched,
            "internet_facing_apps": sum(1 for d in app_detail if d["internet_facing"]),
            "cardholder_data_apps": sum(1 for d in app_detail if d["handles_cardholder_data"]),
            "critical_apps": sum(1 for d in app_detail
                                 if d["business_criticality"] == "CRITICAL"),
            "transitive_in": sum(1 for d in app_detail if d["dependency_type"] == "transitive"),
            "applications": app_detail,
            "one_fix_clears": (
                f"Upgrading {library} to {patched} clears {len(all_cves)} CVE(s) across "
                f"{len({f.dependency.app_id for f in risky})} applications in a single change."
                if patched else
                f"No single upgrade fixes this — {library} has no available patch, so each "
                f"application needs a replacement plan."
            ),
        })

    shared.sort(key=lambda s: s["leverage_score"], reverse=True)

    # Systemic: present in half or more of the estate
    n_apps = len(result.applications)
    systemic = [s for s in shared if s["affected_app_count"] >= max(3, n_apps // 2)]

    total_findings_cleared = sum(s["affected_app_count"] for s in shared[:5])

    return {
        "shared_components": shared[:30],
        "shared_count": len(shared),
        "systemic_components": systemic,
        "systemic_count": len(systemic),
        "top_leverage": shared[:5],
        "interpretation": (
            f"{len(shared)} risky components appear in more than one application. The top 5 "
            f"account for {total_findings_cleared} application-level exposures between them — "
            f"so five upgrades retire {total_findings_cleared} risks. Fix by LEVERAGE, not by "
            f"application: patching the same library ten times in ten repos is ten times the "
            f"work for the same outcome."
        )
        if shared else "No components are shared between applications.",
    }


def version_drift(result: AnalysisResult) -> dict:
    """The same library pinned at different versions across the estate.

    Fragmentation is a risk multiplier in its own right: when the CVE lands, you are not
    performing one upgrade, you are performing N different upgrades with N different
    regression profiles — and you will miss one.
    """
    by_library: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for f in result.findings:
        by_library[f.dependency.library_name][f.dependency.version].append(
            f.application.name
        )

    drift = []
    for library, versions in by_library.items():
        if len(versions) < 2:
            continue
        drift.append({
            "library": library,
            "version_count": len(versions),
            "versions": {v: sorted(set(apps)) for v, apps in versions.items()},
            "app_count": len({a for apps in versions.values() for a in apps}),
        })

    drift.sort(key=lambda d: d["version_count"], reverse=True)

    return {
        "drifted_libraries": drift[:25],
        "drift_count": len(drift),
        "interpretation": (
            f"{len(drift)} libraries are pinned at inconsistent versions across the estate. "
            f"Each is a latent incident: when a CVE is published, you will be performing "
            f"several different upgrades under time pressure instead of one, and the odds of "
            f"missing a copy rise with every extra version."
        ) if drift else "No version drift detected.",
    }
