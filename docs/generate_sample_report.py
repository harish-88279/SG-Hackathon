"""
Generate the sample risk report deliverable.

The problem statement asks for "a sample risk report with 5-10 detected risky
dependencies including compliance mappings and remediation steps". This produces it
directly from the live analysis, so it can never drift out of sync with the code.

    python docs/generate_sample_report.py
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sbomguard.analyzer import analyze                      # noqa: E402
from sbomguard.features import correlation, remediation     # noqa: E402
from sbomguard.intel import narrative                       # noqa: E402

OUT = ROOT / "docs" / "SAMPLE_RISK_REPORT.md"


def main() -> None:
    r = analyze(dataset="synthetic")
    top = r.ranked(8)
    pb = remediation.build_playbook(r)
    co = correlation.correlate(r)
    s = r.stats

    L: list[str] = []
    add = L.append

    add("# SBOMGuard — Sample Risk Report\n")
    add(f"**Generated:** {datetime.now():%Y-%m-%d %H:%M} · "
        f"**Estate:** {len(r.applications)} applications, "
        f"{s['total_dependencies']} components\n")
    add("*Auto-generated from the live analysis by `docs/generate_sample_report.py`, so it "
        "cannot drift out of sync with the engine.*\n")
    add("\n---\n")

    # ---------------------------------------------------------------- executive summary
    add("## Executive summary\n")
    add(f"We analysed **{s['total_dependencies']} components** across "
        f"**{len(r.applications)} applications** and found **{s['at_risk']} at risk**.\n")
    add("The three numbers that should decide where the next two weeks of engineering time "
        "goes:\n")
    add(f"- **{s['known_exploited_cves']} CVEs are being actively exploited in the wild.** "
        f"These are not patch-queue items; they are incidents.")
    add(f"- **{s['unpatchable_findings']} findings have NO upstream patch.** They cannot be "
        f"fixed by upgrading. Each needs a replacement project and a compensating control "
        f"today.")
    add(f"- **{s['unreachable_findings']} findings are present but NOT reachable** from our "
        f"code. They are liabilities, not emergencies — and de-prioritising them correctly "
        f"is what stops this queue from being ignored.\n")
    add(f"We also **suppressed {s['suppressed_false_positives']} false positives**: versions "
        f"that sit inside a published CVE range but whose shipped build carries a backported "
        f"fix. A naive version-matching scanner would have reported every one of them.\n")

    # ---------------------------------------------------------------- applications
    add("\n## Applications by risk\n")
    add("| Application | Score | Worst component | At risk | Hidden transitive | "
        "Criticality | Exposure |")
    add("|---|---|---|---|---|---|---|")
    for a in r.app_scores:
        exp = []
        if a.get("internet_facing"):
            exp.append("internet")
        if a.get("handles_cardholder_data"):
            exp.append("PCI")
        add(f"| **{a['app_name']}** | {a['risk_score']} | {a['worst_component_score']} | "
            f"{a['at_risk_count']}/{a['total_dependencies']} | {a['transitive_vuln_count']} | "
            f"{a['business_criticality']} | {', '.join(exp) or '—'} |")

    # ---------------------------------------------------------------- top findings
    add("\n---\n")
    add("## The eight findings that matter\n")
    add("Ranked by **priority** — what to fix first — not by CVSS.\n")

    for i, f in enumerate(top, start=1):
        d, app, sc = f.dependency, f.application, f.score
        blast = r.graph.blast_radius(d.library_name, d.version)
        worst = max(f.vulns, key=lambda v: v.cvss_score) if f.vulns else None

        add(f"\n### {i}. `{d.library_name}@{d.version}`\n")

        add(f"| | |")
        add(f"|---|---|")
        add(f"| **Priority** (fix first?) | **{sc.priority_score:.1f}** / 100 |")
        add(f"| **Flaw** (how bad?) | {sc.risk_score:.1f} / 100 |")
        add(f"| Context multiplier | ×{sc.context_multiplier:.2f} |")
        add(f"| Risk type | {sc.primary_risk.replace('_', ' ')} |")
        add(f"| Severity | {sc.severity} |")
        add(f"| Application | {app.name} ({app.business_criticality}) |")
        add(f"| Owner | {app.owner} |")
        add(f"| Depth | {f.true_depth} "
            f"{'(TRANSITIVE — nobody chose this)' if f.true_depth > 1 else '(direct)'} |")
        if worst:
            add(f"| CVE | {worst.cve_id} — {worst.name or 'n/a'} (CVSS {worst.cvss_score}) |")
            add(f"| Exploit | {worst.exploit_maturity}"
                f"{' · **KNOWN EXPLOITED IN THE WILD**' if worst.known_exploited else ''} |")
            add(f"| Reachable from our code | "
                f"{'**YES** — the flaw is live' if worst.reachable else 'no — liability, not emergency'} |")
            add(f"| Patch | "
                f"{'upgrade to ' + str(worst.patched_version) if worst.patch_available else '**NONE — must be REPLACED**'} |")
        add(f"| Blast radius | {blast['affected_app_count']} application(s) |")

        if f.paths:
            add(f"\n**How it gets in:**\n")
            add(f"```\n{f.paths[0].as_chain()}\n```")

        n = narrative.generate(f, blast, force_offline=True)
        add(f"\n**Analyst narrative:**\n")
        for para in n["narrative"].split("\n\n"):
            add(f"> {para}\n")

        add(f"\n**Why this score:**\n")
        for drv in sc.drivers[:6]:
            add(f"- {drv}")

        comp = f.to_dict().get("compliance", [])
        if comp:
            add(f"\n**Compliance mapping:**\n")
            for c in comp:
                add(f"- `{c['framework']} {c['control']}` — {c['description']}")

        if f.suppressed_cves:
            add(f"\n**Suppressed (false positives):** {', '.join(f.suppressed_cves)} match "
                f"this version range, but the shipped build carries a backported fix.")

        add("")

    # ---------------------------------------------------------------- remediation
    add("\n---\n")
    add("## Remediation plan\n")
    sm = pb["summary"]
    add(f"**{sm['findings_collapsed']} findings collapse into {sm['total_actions']} actions** "
        f"({sm['collapse_ratio']}× collapse) — because one dependency bump frequently fixes "
        f"the same flaw across several applications at once.\n")
    add(f"**{sm['immediate']} need doing today.**\n")

    for a in pb["actions"][:6]:
        add(f"\n### `{a['action_id']}` · {a['urgency']} · {a['action_type']}\n")
        add(f"**{a['title']}**\n")
        add(f"{a['rationale']}\n")
        if a["commands"]:
            add("```bash")
            for line in a["commands"][:10]:
                add(line)
            add("```")
        for c in a["caveats"]:
            add(f"\n> ⚠ {c}")
        if a["compensating_control"]:
            add(f"\n> **Compensating control:** {a['compensating_control']}")
        add(f"\n*Affects: {', '.join(a['affected_apps'])}*")
        if a["cve_ids"]:
            add(f"*Resolves: {', '.join(a['cve_ids'][:6])}*")
        add("")

    # ---------------------------------------------------------------- leverage
    add("\n---\n")
    add("## Fix by leverage, not by application\n")
    add(f"{co['interpretation']}\n")
    add("| Component | Apps | Exposure | One fix clears | Leverage |")
    add("|---|---|---|---|---|")
    for c in co["top_leverage"]:
        exp = []
        if c["internet_facing_apps"]:
            exp.append(f"{c['internet_facing_apps']} internet")
        if c["cardholder_data_apps"]:
            exp.append(f"{c['cardholder_data_apps']} PCI")
        if c["transitive_in"]:
            exp.append(f"{c['transitive_in']} transitive")
        add(f"| `{c['library']}` | {c['affected_app_count']} | {', '.join(exp) or '—'} | "
            f"{len(c['cve_ids'])} CVE(s) | **{c['leverage_score']}** |")

    add("\n---\n")
    add("*Patching the same library ten times in ten repositories is ten times the work for "
        "the same outcome. Work this table top-down.*")

    body = "\n".join(L)
    OUT.write_text(body, encoding="utf-8")
    print(f"Wrote {OUT}")
    print(f"  {len(body):,} chars, {len(top)} findings detailed, "
          f"{len(pb['actions'])} remediation actions")


if __name__ == "__main__":
    main()
