"""
SBOMGuard — Self-Evaluation Harness
===================================

This is the most important file in the repository.

The problem statement sets five success criteria. This script measures all five against
the ground-truth labels and prints a pass/fail table. It is the difference between
claiming the system works and demonstrating it.

    Vulnerability Detection      > 85%    recall on CVE-carrying dependencies
    Transitive Resolution        = 100%   every nested dependency resolved
    License Conflict Detection   > 90%    recall on license violations
    False Positive Rate          < 20%    of everything we flagged, how much was noise
    Risk Score Accuracy          ±10%     against the labelled severity

Run:  python eval/self_evaluate.py
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sbomguard import config                                  # noqa: E402
from sbomguard.analyzer import Analyzer                       # noqa: E402
from sbomguard.ingest import load_labels                      # noqa: E402


# ======================================================================================
# Metric primitives
# ======================================================================================
def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return precision, recall, f1


VULN_TYPES = {"vulnerable_dependency", "transitive_vulnerability"}

# Map our severity labels onto the same 0-100 scale the labels use, so that
# "risk score accuracy" is a meaningful comparison rather than a units mismatch.
SEVERITY_TO_SCORE = {"CRITICAL": 90.0, "HIGH": 70.0, "MEDIUM": 45.0, "LOW": 20.0, "NONE": 0.0}


def main() -> int:
    print("=" * 78)
    print("  SBOMGuard — Self-Evaluation against ground-truth labels")
    print("=" * 78)

    result = Analyzer().run()
    labels = load_labels()
    findings = {f.dependency.dependency_id: f for f in result.findings}

    missing = set(labels) - set(findings)
    if missing:
        print(f"  WARNING: {len(missing)} labelled dependencies were not analysed at all.")

    # ==================================================================================
    # 1. VULNERABILITY DETECTION  (target > 85% recall)
    # ==================================================================================
    tp = fp = fn = tn = 0
    for dep_id, lab in labels.items():
        f = findings.get(dep_id)
        if not f:
            continue
        truth = lab["risk_type"] in VULN_TYPES
        pred = f.score.primary_risk in VULN_TYPES
        if truth and pred:
            tp += 1
        elif pred and not truth:
            fp += 1
        elif truth and not pred:
            fn += 1
        else:
            tn += 1

    v_prec, v_rec, v_f1 = prf(tp, fp, fn)

    # ==================================================================================
    # 2. TRANSITIVE RESOLUTION  (target = 100%)
    # A transitive dependency is "resolved" when the graph can prove a concrete path from
    # the application root down to it. This is reachability, so it is decidable — and
    # therefore a metric we can hit exactly rather than approximately.
    # ==================================================================================
    transitive_total = 0
    transitive_resolved = 0
    transitive_vuln_total = 0
    transitive_vuln_found = 0

    for dep_id, lab in labels.items():
        f = findings.get(dep_id)
        if not f:
            continue
        dep = f.dependency
        if dep.dependency_type == "transitive":
            transitive_total += 1
            path = result.graph.shortest_path_to(dep.app_id, dep.library_name, dep.version)
            if path and path.depth >= 1:
                transitive_resolved += 1

        if lab["risk_type"] == "transitive_vulnerability":
            transitive_vuln_total += 1
            if f.score.primary_risk == "transitive_vulnerability":
                transitive_vuln_found += 1

    t_res = 100.0 * transitive_resolved / transitive_total if transitive_total else 100.0
    t_vuln = (100.0 * transitive_vuln_found / transitive_vuln_total
              if transitive_vuln_total else 100.0)

    # ==================================================================================
    # 3. LICENSE CONFLICT DETECTION  (target > 90% recall)
    # ==================================================================================
    ltp = lfp = lfn = 0
    for dep_id, lab in labels.items():
        f = findings.get(dep_id)
        if not f:
            continue
        truth = lab["risk_type"] == "license_conflict"
        pred = f.score.primary_risk == "license_conflict"
        if truth and pred:
            ltp += 1
        elif pred and not truth:
            lfp += 1
        elif truth and not pred:
            lfn += 1

    l_prec, l_rec, l_f1 = prf(ltp, lfp, lfn)

    # ==================================================================================
    # 4. OVERALL FALSE POSITIVE RATE  (target < 20%)
    # Of everything we raised an alarm about, what fraction was actually clean?
    # This is the metric that decides whether a security team keeps using the tool.
    # ==================================================================================
    flagged = 0
    flagged_wrong = 0
    for dep_id, lab in labels.items():
        f = findings.get(dep_id)
        if not f:
            continue
        if f.score.at_risk:
            flagged += 1
            if lab["risk_status"] != "AT_RISK":
                flagged_wrong += 1

    fpr = 100.0 * flagged_wrong / flagged if flagged else 0.0

    # The traps: dependencies whose VERSION matches a published CVE range but whose BUILD
    # carries a backported fix. A naive version-matching scanner flags every one of them.
    traps = [d for d, l in labels.items() if l["is_false_positive_trap"]]
    traps_caught = sum(
        1 for d in traps
        if findings.get(d) and findings[d].score.primary_risk not in VULN_TYPES
    )
    trap_rate = 100.0 * traps_caught / len(traps) if traps else 100.0

    # ==================================================================================
    # 5. RISK SCORE ACCURACY  (target: within ±10% of the labelled severity)
    # ==================================================================================
    # We compare the ANCHORED `risk_score` ("how bad is this flaw"), which lives on the
    # same scale as the labelled severity. The contextual `priority_score` ("what do I fix
    # first") deliberately does NOT live on that scale — it is measured below by rank
    # correlation, which is the correct way to evaluate a prioritisation queue.
    deltas = []
    for dep_id, lab in labels.items():
        f = findings.get(dep_id)
        if not f or lab["risk_status"] != "AT_RISK":
            continue
        expected = SEVERITY_TO_SCORE.get(lab["severity"], 0.0)
        actual = f.score.risk_score
        if expected > 0:
            deltas.append(abs(actual - expected) / expected)

    mean_dev = 100.0 * (sum(deltas) / len(deltas)) if deltas else 0.0
    within_10 = 100.0 * sum(1 for d in deltas if d <= 0.10) / len(deltas) if deltas else 100.0
    within_25 = 100.0 * sum(1 for d in deltas if d <= 0.25) / len(deltas) if deltas else 100.0

    # Rank correlation is the honest measure of a PRIORITISATION tool. A queue only has
    # to put the worst thing first; it does not have to guess an absolute number.
    _at_risk_ids = [d for d in labels
                    if findings.get(d) and labels[d]["risk_status"] == "AT_RISK"]
    rank_corr = _spearman(
        [SEVERITY_TO_SCORE.get(labels[d]["severity"], 0.0) for d in _at_risk_ids],
        [findings[d].score.priority_score for d in _at_risk_ids],
    )
    severity_agreement = (
        100.0 * sum(1 for d in _at_risk_ids
                    if findings[d].score.severity == labels[d]["severity"]) / len(_at_risk_ids)
        if _at_risk_ids else 100.0
    )

    # ==================================================================================
    # Report
    # ==================================================================================
    def row(name, value, target, ok, extra=""):
        status = "PASS" if ok else "FAIL"
        print(f"  {name:<30} {value:>8}   target {target:<12} [{status}]  {extra}")

    print("\n  SUCCESS CRITERIA")
    print("  " + "-" * 74)
    row("Vulnerability Detection", f"{100*v_rec:.1f}%", "> 85%", v_rec > 0.85,
        f"precision {100*v_prec:.1f}%  F1 {100*v_f1:.1f}%")
    row("Transitive Resolution", f"{t_res:.1f}%", "= 100%", t_res >= 99.99,
        f"{transitive_resolved}/{transitive_total} nested deps pathed")
    row("License Conflict Detection", f"{100*l_rec:.1f}%", "> 90%", l_rec > 0.90,
        f"precision {100*l_prec:.1f}%")
    row("False Positive Rate", f"{fpr:.1f}%", "< 20%", fpr < 20.0,
        f"{flagged_wrong}/{flagged} flagged were clean")
    row("Risk Score Accuracy", f"{within_10:.1f}%", "in +/-10%", within_10 >= 90.0,
        f"mean deviation {mean_dev:.1f}% from labelled severity")

    all_pass = (v_rec > 0.85 and t_res >= 99.99 and l_rec > 0.90 and fpr < 20.0
                and within_10 >= 90.0)

    print("\n  SUPPORTING EVIDENCE")
    print("  " + "-" * 74)
    print(f"  Transitive VULNERABILITIES found    {t_vuln:.1f}%  "
          f"({transitive_vuln_found}/{transitive_vuln_total})")
    print(f"  False-positive traps defused        {trap_rate:.1f}%  "
          f"({traps_caught}/{len(traps)}) — version matched a CVE range,")
    print(f"                                      but the build carried a backported fix")
    print(f"  Severity agreement (exact match)    {severity_agreement:.1f}%  "
          f"(our severity == labelled severity)")
    print(f"  Priority-queue rank correlation     {rank_corr:.3f}  "
          f"(Spearman rho, priority_score vs severity)")
    print(f"  Mean |risk_score - label| deviation {mean_dev:.1f}%  "
          f"(within +/-25%: {within_25:.1f}%)")
    print(f"  Vulnerability confusion matrix      TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"  License confusion matrix            TP={ltp} FP={lfp} FN={lfn}")

    print("\n  CORPUS")
    print("  " + "-" * 74)
    s = result.stats
    print(f"  Dependencies analysed               {s['total_dependencies']}")
    print(f"  Flagged at risk                     {s['at_risk']}")
    print(f"  Unique CVEs matched                 {s['unique_cves']}")
    print(f"  Known-exploited (KEV) CVEs          {s['known_exploited_cves']}")
    print(f"  Findings with NO available patch    {s['unpatchable_findings']}")
    print(f"  CVEs present but NOT reachable      {s['unreachable_findings']}")
    print(f"  False positives actively suppressed {s['suppressed_false_positives']}")
    g = s["graph"]
    print(f"  Graph                               {g['library_nodes']} nodes, {g['edges']} edges, "
          f"max depth {g['max_depth']}")

    print("\n  " + "=" * 74)
    print(f"  OVERALL: {'ALL SUCCESS CRITERIA MET' if all_pass else 'SOME CRITERIA NOT MET'}")
    print("  " + "=" * 74 + "\n")

    return 0 if all_pass else 1


def _spearman(a: list[float], b: list[float]) -> float:
    """Spearman rank correlation, without pulling in scipy."""
    n = len(a)
    if n < 2:
        return 0.0

    def ranks(xs):
        order = sorted(range(len(xs)), key=lambda i: xs[i])
        r = [0.0] * len(xs)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and xs[order[j + 1]] == xs[order[i]]:
                j += 1
            avg = (i + j) / 2 + 1
            for k in range(i, j + 1):
                r[order[k]] = avg
            i = j + 1
        return r

    ra, rb = ranks(a), ranks(b)
    ma, mb = sum(ra) / n, sum(rb) / n
    num = sum((x - ma) * (y - mb) for x, y in zip(ra, rb))
    da = sum((x - ma) ** 2 for x in ra) ** 0.5
    db = sum((y - mb) ** 2 for y in rb) ** 0.5
    return num / (da * db) if da and db else 0.0


if __name__ == "__main__":
    sys.exit(main())
