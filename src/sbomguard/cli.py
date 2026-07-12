"""
SBOMGuard — command line interface.

The CI-facing surface. This is what makes the tool enforceable rather than merely
informative: `sbomguard gate` returns a non-zero exit code and fails a build.

    python -m sbomguard.cli scan                       # analyse the sample estate
    python -m sbomguard.cli cve CVE-2021-44228         # blast radius for a CVE
    python -m sbomguard.cli gate --policy strict       # CI gate; exit 1 blocks the merge
    python -m sbomguard.cli plan                       # the remediation playbook
    python -m sbomguard.cli scan --sbom my-sbom.json   # scan a real CycloneDX/SPDX file
    python -m sbomguard.cli eval                       # prove it against the labels
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sbomguard.analyzer import Analyzer, analyze                    # noqa: E402
from sbomguard.features import compliance, correlation, policy_gate, remediation  # noqa: E402
from sbomguard.ingest import parse_any                              # noqa: E402
from sbomguard.intel import narrative                               # noqa: E402
from sbomguard.intel.clustering import cluster_risks                # noqa: E402


C = {
    "red": "\033[91m", "orange": "\033[93m", "green": "\033[92m",
    "blue": "\033[94m", "purple": "\033[95m", "dim": "\033[90m",
    "bold": "\033[1m", "off": "\033[0m",
}


def col(text, c):
    return f"{C.get(c, '')}{text}{C['off']}"


def band_colour(band):
    return {"CRITICAL": "red", "HIGH": "orange", "MEDIUM": "orange",
            "LOW": "blue", "MINIMAL": "green"}.get(band, "dim")


def _load(sbom: str | None):
    if not sbom:
        return analyze()
    raw = Path(sbom).read_text(encoding="utf-8")
    deps, fmt = parse_any(raw, filename=sbom)
    print(col(f"  Parsed {len(deps)} components from {sbom} as {fmt}\n", "dim"))
    base = Analyzer()
    return Analyzer(applications=base.applications, dependencies=deps,
                    vulnerabilities=base.vulnerabilities,
                    license_rules=base.license_rules).run()


# ======================================================================================
def cmd_scan(args):
    r = _load(args.sbom)
    s = r.stats

    print(col("\n  SBOMGuard — supply chain scan\n", "bold"))
    print(f"  components        {s['total_dependencies']}")
    print(f"  at risk           {col(s['at_risk'], 'red')}")
    print(f"  clean             {col(s['clean'], 'green')}")
    print(f"  unique CVEs       {s['unique_cves']}")
    print(f"  known exploited   {col(s['known_exploited_cves'], 'red')}")
    print(f"  no patch exists   {col(s['unpatchable_findings'], 'purple')}")
    print(f"  not reachable     {col(s['unreachable_findings'], 'green')}  "
          f"{col('(present, but not exploitable)', 'dim')}")
    print(f"  FPs suppressed    {col(s['suppressed_false_positives'], 'green')}")
    g = s["graph"]
    print(f"  graph             {g['library_nodes']} nodes, {g['edges']} edges, "
          f"max depth {g['max_depth']}")

    print(col("\n  APPLICATIONS BY RISK\n", "bold"))
    for a in r.app_scores:
        bar = "#" * int(a["risk_score"] / 4)
        score = f"{a['risk_score']:5.1f}"
        coloured_bar = col(bar, band_colour(a["risk_band"]))
        pad = " " * max(0, 30 - len(bar))
        print(f"  {score}  {coloured_bar}{pad} {a['app_name']:<24} "
              f"{a['at_risk_count']:>3} at risk")

    print(col("\n  TOP FINDINGS\n", "bold"))
    for f in r.ranked(12):
        d = f.dependency
        cves = ", ".join(f.score.cve_ids[:2]) or "-"
        print(f"  {col(f'{f.score.priority_score:5.1f}', band_colour(f.score.risk_band))}  "
              f"{d.library_name.split(':')[-1][:28]:<28} @{d.version:<9} "
              f"{f.application.name[:20]:<20} d{f.true_depth}  {cves}")
    print()
    return 0


def cmd_cve(args):
    r = _load(args.sbom)
    cve = args.cve_id.upper()

    hits = [f for f in r.findings if any(v.cve_id.upper() == cve for v in f.vulns)]
    if not hits:
        print(col(f"\n  {cve}: no application in the estate uses an affected version.\n",
                  "green"))
        return 0

    worst = max((v for f in hits for v in f.vulns if v.cve_id.upper() == cve),
                key=lambda v: v.cvss_score)
    apps = sorted({f.application.name for f in hits})

    print(col(f"\n  {cve}  {worst.name}", "bold"))
    print(f"  {col(worst.severity, band_colour(worst.severity))}  CVSS {worst.cvss_score}"
          + (col("  [EXPLOITED IN THE WILD]", "red") if worst.known_exploited else "")
          + (col("  [NO PATCH]", "purple") if not worst.patch_available else ""))
    print(f"\n  {worst.summary}\n")

    print(col(f"  BLAST RADIUS: {len(apps)} of {len(r.applications)} applications\n", "bold"))
    for f in sorted(hits, key=lambda x: x.score.priority_score, reverse=True):
        path = r.graph.shortest_path_to(
            f.dependency.app_id, f.dependency.library_name, f.dependency.version)
        tag = col("[transitive]", "purple") if f.dependency.dependency_type == "transitive" else ""
        print(f"  {col(f'{f.score.priority_score:5.1f}', band_colour(f.score.risk_band))}  "
              f"{f.application.name}  {tag}")
        if path:
            print(f"         {col(path.as_chain(), 'dim')}")

    if worst.patch_available:
        print(col(f"\n  ONE FIX: upgrade to {worst.patched_version} — clears this CVE across "
                  f"all {len(apps)} applications.\n", "green"))
    else:
        print(col("\n  NO PATCH EXISTS. This library must be REPLACED, not upgraded.\n",
                  "purple"))
    return 0


def cmd_gate(args):
    r = _load(args.sbom)
    pol = policy_gate.POLICIES.get(args.policy)
    if not pol:
        print(f"Unknown policy '{args.policy}'. Available: {list(policy_gate.POLICIES)}")
        return 2

    res = policy_gate.evaluate(r, pol, args.app)

    print(col(f"\n  SBOMGuard policy gate — '{args.policy}'\n", "bold"))
    if res["passed"]:
        print(col(f"  PASS  {res['verdict']}", "green"))
    else:
        print(col(f"  FAIL  {res['verdict']}", "red"))

    for b in res["blocks"][:15]:
        where = col(f"({b['app_name']})", "dim")
        print(f"\n  {col('BLOCK', 'red')}  {b['library']}@{b['version']}  {where}")
        print(f"         {b['message']}")
        print(f"         {col('-> ' + b['remediation'], 'green')}")

    if res["warning_count"]:
        print(col(f"\n  {res['warning_count']} warning(s) — reported, not blocking.", "orange"))

    print(f"\n  exit code: {res['exit_code']}\n")
    return res["exit_code"]


def cmd_plan(args):
    r = _load(args.sbom)
    pb = remediation.build_playbook(r, limit=args.limit)
    s = pb["summary"]

    print(col("\n  SBOMGuard — remediation playbook\n", "bold"))
    print(f"  {s['findings_collapsed']} findings -> {s['total_actions']} actions "
          f"({s['collapse_ratio']}x collapse)")
    print(f"  {col(str(s['immediate']) + ' need doing today', 'red')}\n")

    for a in pb["actions"][:args.limit]:
        urg = {"IMMEDIATE": "red", "THIS_WEEK": "orange",
               "THIS_SPRINT": "orange", "BACKLOG": "dim"}[a["urgency"]]
        print(f"  {col('[' + a['urgency'] + ']', urg)}  {col(a['title'], 'bold')}")
        print(f"     {col(a['rationale'][:150], 'dim')}")
        if a["commands"]:
            for line in a["commands"][:3]:
                print(f"       {col(line, 'blue')}")
        print()
    return 0


def cmd_clusters(args):
    r = _load(args.sbom)
    cl = cluster_risks(r)
    print(col("\n  RISK ARCHETYPES\n", "bold"))
    for c in cl["clusters"]:
        size = col(f"[{c['size']:>3}]", "purple")
        print(f"  {size} {col(c['name'], 'bold')}")
        print(f"        {col(c['remediation_strategy'][:160], 'dim')}\n")
    return 0


def cmd_compliance(args):
    r = _load(args.sbom)
    rep = compliance.compliance_report(r, args.app)
    print(col("\n  COMPLIANCE POSTURE\n", "bold"))
    for a in rep["applications"]:
        score = a["compliance_score"]
        c = "green" if score >= 70 else "orange" if score >= 45 else "red"
        print(f"  {col(f'{score:5.1f}%', c)}  {a['app_name']:<26} "
              f"{a['controls_passed']}/{a['controls_total']} controls passing")
    print()
    return 0


def cmd_eval(args):
    import subprocess
    root = Path(__file__).resolve().parents[2]
    return subprocess.run([sys.executable, str(root / "eval" / "self_evaluate.py")]).returncode


def cmd_explain(args):
    r = _load(args.sbom)
    f = r.by_dependency_id().get(args.dependency_id)
    if not f:
        print(f"No such dependency: {args.dependency_id}")
        return 1
    blast = r.graph.blast_radius(f.dependency.library_name, f.dependency.version)
    n = narrative.generate(f, blast, force_offline=args.offline)
    print(col(f"\n  {f.dependency.library_name}@{f.dependency.version}\n", "bold"))
    print("  " + n["narrative"].replace("\n", "\n  "))
    print(col(f"\n  [{n['generated_by']}]\n", "dim"))
    return 0


# ======================================================================================
def main() -> int:
    p = argparse.ArgumentParser(
        prog="sbomguard",
        description="SBOMGuard — software supply chain risk scorer.",
    )
    p.add_argument("--sbom", help="Path to a CycloneDX/SPDX/CSV SBOM. "
                                  "Omit to use the bundled sample estate.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scan", help="Analyse the estate").set_defaults(fn=cmd_scan)

    c = sub.add_parser("cve", help="Blast radius for one CVE")
    c.add_argument("cve_id")
    c.set_defaults(fn=cmd_cve)

    g = sub.add_parser("gate", help="CI policy gate (exit 1 blocks the build)")
    g.add_argument("--policy", default="default",
                   choices=list(policy_gate.POLICIES))
    g.add_argument("--app", help="Limit the gate to one application")
    g.set_defaults(fn=cmd_gate)

    pl = sub.add_parser("plan", help="Remediation playbook")
    pl.add_argument("--limit", type=int, default=12)
    pl.set_defaults(fn=cmd_plan)

    sub.add_parser("clusters", help="Risk archetypes").set_defaults(fn=cmd_clusters)

    cp = sub.add_parser("compliance", help="Compliance posture")
    cp.add_argument("--app")
    cp.set_defaults(fn=cmd_compliance)

    sub.add_parser("eval", help="Prove it against the ground-truth labels"
                   ).set_defaults(fn=cmd_eval)

    e = sub.add_parser("explain", help="Analyst narrative for one finding")
    e.add_argument("dependency_id")
    e.add_argument("--offline", action="store_true")
    e.set_defaults(fn=cmd_explain)

    args = p.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
