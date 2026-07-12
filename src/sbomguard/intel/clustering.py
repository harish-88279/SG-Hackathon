"""
SBOMGuard — behavioural clustering of risk (Level-2 bonus).

THE PROBLEM THIS SOLVES
=======================
Our engine finds ~265 at-risk dependencies across 10 applications. A list of 265 tickets
is not an action plan; it is a reason to give up. Nobody works a 265-item queue.

But those 265 findings are not 265 different problems. They are a handful of recurring
PATTERNS wearing different names:

    "old Java XML parser, single maintainer, no patch, buried deep"
    "GPL-licensed npm package statically linked into a shipped product"
    "weaponised RCE in an internet-facing service, patch available"

Cluster the findings by their behavioural profile and 265 tickets collapse into ~6
REMEDIATION CAMPAIGNS, each with a single owner, a single strategy, and one decision to
make. That is the difference between a report and a plan.

We use K-means over the risk feature space, choose k by silhouette score rather than by
taste, then NAME each cluster from the features that actually characterise it.
"""
from __future__ import annotations

from collections import Counter

import numpy as np
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler

from ..analyzer import AnalysisResult


CLUSTER_FEATURES = [
    "priority_score", "severity_rank", "age_years", "maintainer_count",
    "depth", "is_transitive", "copyleft_score", "exploit_rank",
    "reachable", "patch_available", "app_exposure",
]

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
_EXPLOIT_RANK = {"weaponised": 3, "functional": 2, "poc": 1, "none": 0}
_COPYLEFT = {
    "MIT": 0, "Apache-2.0": 0, "BSD-3-Clause": 0, "BSD-2-Clause": 0, "ISC": 0,
    "PSF-2.0": 0, "Unlicense": 0, "MPL-2.0": 4, "EPL-2.0": 4,
    "LGPL-2.1": 5, "LGPL-3.0": 5, "GPL-2.0": 8, "GPL-3.0": 9,
    "AGPL-3.0": 10, "UNKNOWN": 7,
}


def _vector(f) -> list[float]:
    dep, app, score = f.dependency, f.application, f.score
    worst = max(f.vulns, key=lambda v: v.cvss_score) if f.vulns else None

    exposure = (
        (40 if app.internet_facing else 0)
        + (30 if app.handles_cardholder_data else 0)
        + (20 if app.handles_pii else 0)
        + (10 if app.distributed else 0)
    )

    return [
        score.priority_score,
        _SEV_RANK.get(score.severity, 0) * 25,
        dep.age_days / 365.25,
        min(dep.maintainer_count, 30),
        f.true_depth,
        1.0 if dep.dependency_type == "transitive" else 0.0,
        _COPYLEFT.get(dep.license, 5),
        _EXPLOIT_RANK.get(worst.exploit_maturity, 0) * 25 if worst else 0.0,
        (1.0 if worst.reachable else 0.0) * 50 if worst else 0.0,
        (1.0 if worst.patch_available else 0.0) * 30 if worst else 30.0,
        exposure,
    ]


def cluster_risks(result: AnalysisResult, k: int | None = None,
                  k_range=(3, 8)) -> dict:
    """Group at-risk findings into remediation campaigns."""
    risky = result.at_risk()
    if len(risky) < 10:
        return {"clusters": [], "note": "too few findings to cluster meaningfully"}

    X = np.asarray([_vector(f) for f in risky], dtype=float)
    Xs = StandardScaler().fit_transform(X)

    # Choose k by silhouette score, not by preference.
    if k is None:
        best_k, best_s = k_range[0], -1.0
        for kk in range(k_range[0], min(k_range[1], len(risky) - 1) + 1):
            km = KMeans(n_clusters=kk, n_init=10, random_state=42)
            lab = km.fit_predict(Xs)
            if len(set(lab)) < 2:
                continue
            s = silhouette_score(Xs, lab)
            if s > best_s:
                best_k, best_s = kk, s
        k = best_k
        silhouette = best_s
    else:
        silhouette = None

    km = KMeans(n_clusters=k, n_init=10, random_state=42)
    labels = km.fit_predict(Xs)
    if silhouette is None and len(set(labels)) > 1:
        silhouette = silhouette_score(Xs, labels)

    clusters = []
    for cid in range(k):
        members = [f for f, l in zip(risky, labels) if l == cid]
        if not members:
            continue
        clusters.append(_describe(cid, members))

    clusters.sort(key=lambda c: c["mean_priority"], reverse=True)

    # Two clusters with the same name is a UX bug: the whole point is that each is a
    # DISTINCT campaign. If the namer collides, disambiguate by what actually differs.
    seen: dict[str, int] = {}
    for c in clusters:
        base = c["name"]
        if base in seen:
            seen[base] += 1
            qualifier = (
                f"depth {c['mean_depth']:.0f}" if c["transitive_share"] > 50
                else f"{c['mean_age_years']:.0f}y old" if c["mean_age_years"] > 2
                else f"priority {c['mean_priority']:.0f}"
            )
            c["name"] = f"{base} ({qualifier})"
        else:
            seen[base] = 1

    for i, c in enumerate(clusters, start=1):
        c["rank"] = i

    return {
        "k": k,
        "silhouette_score": round(float(silhouette), 3) if silhouette else None,
        "total_findings": len(risky),
        "clusters": clusters,
        "interpretation": (
            f"{len(risky)} individual findings collapse into {len(clusters)} remediation "
            f"campaigns. Each campaign shares one root cause and one fix strategy, so it "
            f"can be assigned to one owner and closed as one piece of work."
        ),
    }


def _describe(cid: int, members: list) -> dict:
    """Name and characterise a cluster from what is actually in it."""
    n = len(members)
    mean_priority = float(np.mean([f.score.priority_score for f in members]))
    mean_age = float(np.mean([f.dependency.age_days for f in members])) / 365.25
    mean_depth = float(np.mean([f.true_depth for f in members]))

    risk_types = Counter(f.score.primary_risk for f in members)
    dominant = risk_types.most_common(1)[0][0]

    severities = Counter(f.score.severity for f in members)
    ecosystems = Counter(f.dependency.ecosystem for f in members)
    apps = Counter(f.application.name for f in members)
    licenses = Counter(f.dependency.license for f in members)

    all_vulns = [v for f in members for v in f.vulns]
    reachable = sum(1 for v in all_vulns if v.reachable)
    patchable = sum(1 for v in all_vulns if v.patch_available)
    kev = sum(1 for v in all_vulns if v.known_exploited)
    unpatchable = len(all_vulns) - patchable

    single_maint = sum(1 for f in members if f.dependency.maintainer_count <= 1)
    transitive = sum(1 for f in members if f.dependency.dependency_type == "transitive")

    # ---- Name it ----
    name, strategy = _name_cluster(
        dominant, mean_age, mean_depth, transitive / n, kev,
        unpatchable, single_maint / n, licenses, n, len(all_vulns),
    )

    return {
        "cluster_id": cid,
        "name": name,
        "size": n,
        "mean_priority": round(mean_priority, 1),
        "dominant_risk": dominant,
        "severity_mix": dict(severities),
        "mean_age_years": round(mean_age, 1),
        "mean_depth": round(mean_depth, 1),
        "transitive_share": round(100.0 * transitive / n, 1),
        "single_maintainer_share": round(100.0 * single_maint / n, 1),
        "known_exploited_cves": kev,
        "unpatchable_cves": unpatchable,
        "reachable_cves": reachable,
        "ecosystems": dict(ecosystems),
        "top_licenses": dict(licenses.most_common(3)),
        "affected_apps": dict(apps.most_common(5)),
        "remediation_strategy": strategy,
        "example_components": [
            f"{f.dependency.library_name}@{f.dependency.version}"
            for f in sorted(members, key=lambda x: x.score.priority_score, reverse=True)[:4]
        ],
    }


def _name_cluster(dominant, mean_age, mean_depth, transitive_share,
                  kev, unpatchable, single_maint_share, licenses, n,
                  total_vulns) -> tuple[str, str]:
    # NOTE: these tests are ordered by URGENCY and gated on the cluster's DOMINANT
    # character, not on the presence of a single member. An earlier version fired the
    # "actively exploited" name whenever kev > 0, which meant one KEV CVE anywhere in a
    # 126-member cluster renamed the whole thing — and every cluster came out identical.
    # A cluster name has to describe the cluster, not its most alarming single member.
    # Normalise by the CVE count, not the finding count: a finding can carry several CVEs,
    # so kev/n could exceed 1 and made the thresholds meaningless.
    kev_share = kev / max(total_vulns, 1)
    unpatchable_share = unpatchable / max(total_vulns, 1)

    # Unpatchable is checked FIRST when it dominates: "you cannot fix this by upgrading"
    # is a more actionable statement than "some of these are being exploited", because it
    # changes what work you schedule.
    if unpatchable_share >= 0.45:
        return (
            "Unpatchable — requires replacement",
            f"{unpatchable} of these vulnerabilities have NO upstream fix. Upgrading is not "
            f"an option. Each needs a replacement library, which is a project rather than a "
            f"ticket — budget it now, and apply a compensating control (WAF rule, network "
            f"segmentation, or disable the code path) to hold the line until it lands.",
        )

    if kev_share >= 0.30:
        return (
            "Actively exploited — incident response",
            f"STOP. {kev} of these CVEs are being exploited in the wild right now. This is "
            f"not a patch queue item, it is an incident. Patch today, then hunt for "
            f"indicators of compromise in the affected applications.",
        )

    if dominant == "transitive_vulnerability" or transitive_share > 0.6:
        return (
            "Hidden transitive vulnerabilities",
            f"These sit an average of {mean_depth:.1f} levels down the tree — nobody chose "
            f"them and nobody is watching them. Fix at the PARENT: bump the direct dependency "
            f"that pulls them in. Where the parent has not shipped a fixed build, pin the "
            f"child version explicitly in the lockfile and add a CI check so the pin cannot "
            f"be silently dropped.",
        )

    if dominant == "license_conflict":
        top = ", ".join(list(licenses.keys())[:3])
        return (
            "Copyleft / licensing exposure",
            f"A legal problem, not a security one, and it belongs with Legal — not with the "
            f"on-call engineer. Dominated by {top}. Route these to counsel as ONE review, "
            f"decide replace-vs-relicense-vs-accept per component, and record the decision. "
            f"Do not let engineers make copyleft calls on a Friday afternoon.",
        )

    if dominant == "unmaintained" or (mean_age > 3 and single_maint_share > 0.5):
        return (
            "Abandonware — no CVE yet, no fix later",
            f"Average age {mean_age:.1f} years, and {single_maint_share*100:.0f}% have a "
            f"single maintainer. There is no vulnerability here TODAY. The risk is that when "
            f"one appears, nobody will be there to fix it. Schedule replacement work into "
            f"normal sprint capacity now, while it is cheap and nobody is panicking.",
        )

    return (
        "Standard patchable vulnerabilities",
        f"{n} findings with an available upstream patch and no evidence of active "
        f"exploitation. This is routine work: batch the upgrades into the next maintenance "
        f"release, run the regression suite, ship.",
    )
