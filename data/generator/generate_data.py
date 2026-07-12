"""
SBOMGuard — Synthetic Dataset Generator (assembly + emit)
=========================================================

PB-10 describes a `sample_data/` folder but ships none. This rebuilds it to the exact
specification:

    applications.json       10 records
    sbom_dependencies.csv   500 records   (10 apps x 50 dependencies)
    vulnerability_db.json   200 records   (simulated NVD)
    license_rules.json      15 records
    dependency_labels.csv   500 records   (GROUND TRUTH)

DESIGN PRINCIPLE — "generate the world, then observe it"
--------------------------------------------------------
We never hand-write a label. We construct a coherent world (libraries with licenses and
release dates, CVEs with real version ranges, dependency trees with real edges) and then
DERIVE the ground truth by observing that world. Two consequences:

  1. The labels cannot contradict the data, so a correct engine can genuinely reach the
     target metrics.
  2. An incorrect engine cannot fake them — the labels encode real reasoning, including
     the nuances (GPL in an internal tool is NOT a violation; a patched build inside a
     CVE range is NOT vulnerable).

Deterministic: seeded, so every run reproduces byte-identical files.

Run:  python data/generator/generate_data.py
"""
from __future__ import annotations

import csv
import json
import random
import sys
from collections import defaultdict
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _catalog import (  # noqa: E402
    ALL_LIBS, APPLICATIONS, CONFLICTING, DEPS_PER_APP, ECOSYSTEM_LIBS, ECOSYSTEM_OF,
    KNOWN_ABANDONED, LICENSE_BY_ID, LICENSE_RULES, PERMISSIVE, RISK_PLAN, SEED, TODAY,
    UNMAINTAINED_DAYS, WEAK_COPYLEFT, make_version, vtuple,
)
from _cves import build_vulnerability_db  # noqa: E402

OUT_DIR = Path(__file__).resolve().parents[1] / "sample_data"


# =====================================================================================
# Library catalogue — every library gets ONE canonical license and release date
# =====================================================================================
def build_library_catalogue(rng: random.Random) -> dict:
    catalogue = {}
    for lib in ALL_LIBS:
        if lib in KNOWN_ABANDONED:
            age_days = rng.randint(760, 2200)          # 2-6 years stale
            maintainers = 1                             # bus factor = 1
        else:
            # ~40% of libraries have not shipped in over 2 years. That is not pessimism:
            # it is roughly what real enterprise dependency trees look like.
            age_days = rng.choice([
                rng.randint(5, 180), rng.randint(5, 180),
                rng.randint(180, 700),
                rng.randint(760, 1400), rng.randint(760, 2000),   # the tail of neglect
            ])
            maintainers = rng.randint(2, 25)

        catalogue[lib] = {
            "library_name": lib,
            "ecosystem": ECOSYSTEM_OF[lib],
            "license": rng.choice(PERMISSIVE),          # overridden below
            "last_updated": (TODAY - timedelta(days=age_days)).isoformat(),
            "age_days": age_days,
            "maintainer_count": maintainers,
            "has_security_policy": maintainers > 3 and age_days < 730,
            "repo_stars": rng.randint(50, 60000),
        }

    # Some libraries have licenses everybody in the room already knows. Assigning a random
    # copyleft license to spring-boot would be both wrong and distracting — and it would
    # hijack the Log4Shell demo, since the chain would surface as a license violation
    # rather than as the CVE. Pin the real ones.
    REAL_LICENSES = {
        "org.springframework.boot:spring-boot-starter-web": "Apache-2.0",
        "org.springframework.boot:spring-boot-starter-logging": "Apache-2.0",
        "org.apache.logging.log4j:log4j-core": "Apache-2.0",
        "org.apache.logging.log4j:log4j-api": "Apache-2.0",
        "org.springframework:spring-core": "Apache-2.0",
        "org.springframework:spring-web": "Apache-2.0",
        "org.springframework:spring-beans": "Apache-2.0",
        "com.fasterxml.jackson.core:jackson-databind": "Apache-2.0",
        "org.apache.commons:commons-text": "Apache-2.0",
        "io.netty:netty-handler": "Apache-2.0",
        "lodash": "MIT",
        "vm2": "MIT",
        "urllib3": "MIT",
        "org.apache.struts:struts2-core": "Apache-2.0",
    }
    for lib, lic in REAL_LICENSES.items():
        if lib in catalogue:
            catalogue[lib]["license"] = lic

    # Plant strong-copyleft / unknown licenses on a deliberate subset of the REST.
    pool = [l for l in ALL_LIBS
            if l not in KNOWN_ABANDONED and l not in REAL_LICENSES]
    for i, lib in enumerate(rng.sample(pool, 28)):
        catalogue[lib]["license"] = CONFLICTING[i % len(CONFLICTING)]

    # Plant weak-copyleft (the nuanced "it depends how you link it" cases)
    permissive_now = [l for l in ALL_LIBS
                      if catalogue[l]["license"] in PERMISSIVE and l not in REAL_LICENSES]
    for i, lib in enumerate(rng.sample(permissive_now, 20)):
        catalogue[lib]["license"] = WEAK_COPYLEFT[i % len(WEAK_COPYLEFT)]

    return catalogue


# =====================================================================================
# Assembly
# =====================================================================================
def build_dataset():
    rng = random.Random(SEED)
    catalogue = build_library_catalogue(rng)
    cves = build_vulnerability_db(rng)

    cve_by_lib = defaultdict(list)
    for c in cves:
        cve_by_lib[c["library"]].append(c)

    def version_in_range(version: str, spec: dict) -> bool:
        v = vtuple(version)
        intro = vtuple(spec["introduced"]) if spec.get("introduced") else (0, 0, 0)
        fixed = spec.get("fixed")
        if v < intro:
            return False
        if fixed is None:
            return True                    # no fix exists -> affected forever
        return v < vtuple(fixed)

    def cves_for(lib: str, version: str) -> list:
        return [c for c in cve_by_lib.get(lib, [])
                if version_in_range(version, c["affected_versions"])]

    def pick_vulnerable_version(lib: str):
        """A version guaranteed to land INSIDE at least one CVE range."""
        cands = cve_by_lib.get(lib, [])
        if not cands:
            return None
        c = rng.choice(cands)
        intro = vtuple(c["affected_versions"]["introduced"])
        fixed = c["affected_versions"]["fixed"]
        if fixed is None:
            return f"{intro[0]}.{intro[1] + rng.randint(0, 3)}.{rng.randint(0, 5)}"
        fx = vtuple(fixed)
        if fx[0] > intro[0]:
            major = rng.randint(intro[0], fx[0] - 1)
            return f"{major}.{rng.randint(0, 15)}.{rng.randint(0, 9)}"
        if fx[1] > intro[1]:
            return f"{intro[0]}.{rng.randint(intro[1], fx[1] - 1)}.{rng.randint(0, 9)}"
        if fx[2] > intro[2]:
            return f"{intro[0]}.{intro[1]}.{rng.randint(intro[2], fx[2] - 1)}"
        return None

    def pick_safe_version(lib: str):
        """A version guaranteed to sit OUTSIDE every CVE range. None if impossible."""
        cands = cve_by_lib.get(lib, [])
        if not cands:
            return make_version(rng)
        highest = (0, 0, 0)
        for c in cands:
            f = c["affected_versions"]["fixed"]
            if f is None:
                return None                # every version is vulnerable
            highest = max(highest, vtuple(f))
        return f"{highest[0]}.{highest[1] + rng.randint(1, 4)}.{rng.randint(0, 6)}"

    # ---- Pools by property ----
    libs_with_cves = [l for l in ALL_LIBS if cve_by_lib.get(l)]
    # A library is only usable in the "vulnerable" slot if we can actually construct a
    # version inside one of its CVE ranges.
    libs_with_cves = [l for l in libs_with_cves if pick_vulnerable_version(l) is not None]
    libs_unmaintained_clean = [
        l for l in ALL_LIBS
        if catalogue[l]["age_days"] > UNMAINTAINED_DAYS
        and not cve_by_lib.get(l)
        and catalogue[l]["license"] not in CONFLICTING
    ]
    libs_clean = [
        l for l in ALL_LIBS
        if not cve_by_lib.get(l)
        and catalogue[l]["license"] not in CONFLICTING
        and catalogue[l]["age_days"] <= UNMAINTAINED_DAYS
    ]

    dep_rows = []
    dep_id = 0

    def add_row(app, lib, version, dtype, parent, depth,
                patched_in_build=False, vuln_func_used=None,
                linkage="dynamic", modified=False):
        nonlocal dep_id
        dep_id += 1
        meta = catalogue[lib]
        dep_rows.append({
            "dependency_id": f"DEP-{dep_id:04d}",
            "app_id": app["app_id"],
            "app_name": app["name"],
            "library_name": lib,
            "version": version,
            "ecosystem": meta["ecosystem"],
            "license": meta["license"],
            "dependency_type": dtype,               # direct | transitive
            "parent_library": parent or "",
            "depth": depth,                          # 1 = direct
            "last_updated": meta["last_updated"],
            "maintainer_count": meta["maintainer_count"],
            "has_security_policy": meta["has_security_policy"],
            "repo_stars": meta["repo_stars"],
            # --- signals the engine must actually reason about ---
            "patched_in_build": patched_in_build,    # backported fix -> FALSE-POSITIVE TRAP
            "vulnerable_function_used": (vuln_func_used if vuln_func_used is not None
                                         else rng.random() < 0.55),
            "linkage": linkage,                      # dynamic | static  (LGPL hinges on this)
            "modified_by_us": modified,              # MPL/LGPL hinge on this
        })

    # ---------- The planted Log4Shell chain: the demo centrepiece ----------
    # App -> spring-boot-starter-web -> spring-boot-starter-logging -> log4j-core 2.14.1
    # Depth 3. Completely invisible to direct-dependency review. Present in 4 of 10 apps.
    LOG4J_APPS = {"APP-001", "APP-004", "APP-007", "APP-010"}

    def plant_log4shell(app):
        add_row(app, "org.springframework.boot:spring-boot-starter-web", "2.5.4",
                "direct", "", 1, vuln_func_used=False)
        add_row(app, "org.springframework.boot:spring-boot-starter-logging", "2.5.4",
                "transitive", "org.springframework.boot:spring-boot-starter-web", 2,
                vuln_func_used=False)
        add_row(app, "org.apache.logging.log4j:log4j-core", "2.14.1",
                "transitive", "org.springframework.boot:spring-boot-starter-logging", 3,
                vuln_func_used=True)
        add_row(app, "org.apache.logging.log4j:log4j-api", "2.14.1",
                "transitive", "org.springframework.boot:spring-boot-starter-logging", 3,
                vuln_func_used=False)
        return 4

    for app in APPLICATIONS:
        eco = app["ecosystem"]
        used_libs = set()
        count = 0

        if app["app_id"] in LOG4J_APPS:
            count += plant_log4shell(app)
            used_libs |= {
                "org.springframework.boot:spring-boot-starter-web",
                "org.springframework.boot:spring-boot-starter-logging",
                "org.apache.logging.log4j:log4j-core",
                "org.apache.logging.log4j:log4j-api",
            }

        plan = dict(RISK_PLAN)
        if app["app_id"] in LOG4J_APPS:
            plan["transitive_vuln"] = max(0, plan["transitive_vuln"] - 2)
            plan["clean"] = max(0, plan["clean"] - 2)

        def choose(pool, prefer_eco=True):
            """Pick an unused library FROM THE GIVEN POOL.

            Critically, the fallback stays INSIDE the pool. An earlier version fell back to
            ALL_LIBS when a pool ran dry, which silently contaminated the 'clean' and
            'unmaintained' slots with conflicting-license libraries and blew the target
            distribution. If the pool is exhausted we return None and the caller skips.
            """
            cands = [l for l in pool if l not in used_libs]
            if prefer_eco:
                eco_c = [l for l in cands if ECOSYSTEM_OF[l] == eco]
                if eco_c:
                    cands = eco_c
            if not cands:
                return None
            lib = rng.choice(cands)
            used_libs.add(lib)
            return lib

        # ---- 1. DIRECT VULNERABLE ----
        for _ in range(plan["vulnerable"]):
            lib = choose(libs_with_cves)
            if lib is None:
                continue
            v = pick_vulnerable_version(lib)
            if v is None:
                continue
            # ~10% are FALSE-POSITIVE TRAPS: inside the CVE range, but the distributed
            # build carries a backported fix. A naive scanner flags these. Ours must not.
            trap = rng.random() < 0.10
            add_row(app, lib, v, "direct", "", 1, patched_in_build=trap)
            count += 1

        # ---- 2. LICENSE CONFLICT ----
        # A planted conflict must ACTUALLY violate THIS app's legal profile:
        #   UNKNOWN  -> always (no rights granted under copyright law)
        #   AGPL-3.0 -> any proprietary app (network copyleft: serving it triggers disclosure)
        #   GPL-2/3  -> only if proprietary AND distributed
        #   LGPL/MPL -> only if statically linked or modified
        violating = ["UNKNOWN"]
        if app["proprietary"]:
            violating.append("AGPL-3.0")
            if app["distributed"]:
                violating += ["GPL-2.0", "GPL-3.0"]
        violating += ["LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EPL-2.0"]

        for _ in range(plan["license_conflict"]):
            target = rng.choice(violating)
            pool = [l for l in ALL_LIBS
                    if catalogue[l]["license"] == target and l not in used_libs]
            if not pool:
                pool = [l for l in ALL_LIBS
                        if catalogue[l]["license"] in CONFLICTING and l not in used_libs]
            if not pool:
                continue
            lib = rng.choice(pool)
            used_libs.add(lib)
            v = pick_safe_version(lib) or make_version(rng)
            meta = LICENSE_BY_ID[catalogue[lib]["license"]]

            if meta["copyleft"] in ("library", "file"):
                linkage, modified = "static", True     # force the trigger condition
            else:
                linkage = rng.choice(["dynamic", "static"])
                modified = rng.random() < 0.3

            add_row(app, lib, v, rng.choice(["direct", "direct", "transitive"]),
                    "", 1, linkage=linkage, modified=modified)
            count += 1

        # ---- 2b. LICENSE NUANCE CASE (must NOT be flagged) ----
        # GPL inside a NON-distributed internal tool. A naive matrix-lookup scanner
        # screams "GPL VIOLATION". It is not one. This is how we prove low FP rate.
        if not (app["proprietary"] and app["distributed"]):
            gpl_pool = [l for l in ALL_LIBS
                        if catalogue[l]["license"] in ("GPL-2.0", "GPL-3.0")
                        and l not in used_libs]
            if gpl_pool:
                lib = rng.choice(gpl_pool)
                used_libs.add(lib)
                v = pick_safe_version(lib) or make_version(rng)
                add_row(app, lib, v, "direct", "", 1, linkage="dynamic", modified=False)
                count += 1

        # ---- 3. UNMAINTAINED (no CVE, clean license -> the risk is MAINTENANCE) ----
        for _ in range(plan["unmaintained"]):
            lib = choose(libs_unmaintained_clean)
            if lib is None:
                continue
            add_row(app, lib, make_version(rng), rng.choice(["direct", "transitive"]), "", 1)
            count += 1

        # ---- 4. TRANSITIVE VULNERABILITY (safe parent -> vulnerable child) ----
        for _ in range(plan["transitive_vuln"]):
            parent = choose(libs_clean)
            child = choose(libs_with_cves)
            if parent is None or child is None:
                continue
            pv = pick_safe_version(parent)
            cv = pick_vulnerable_version(child)
            if pv is None or cv is None:
                continue
            add_row(app, parent, pv, "direct", "", 1, vuln_func_used=False)
            add_row(app, child, cv, "transitive", parent, 2)
            count += 2

        # ---- 5. CLEAN — fill the remainder to exactly DEPS_PER_APP ----
        guard = 0
        while count < DEPS_PER_APP and guard < 2000:
            guard += 1
            lib = choose(libs_clean)
            if lib is None:
                # Pool exhausted for this app. Fall back to OTHER clean libs only
                # (never to conflicting/vulnerable ones — that is what broke the
                # distribution before). Reuse a clean lib at a different version.
                spare = [l for l in libs_clean]
                if not spare:
                    break
                lib = rng.choice(spare)
            v = pick_safe_version(lib)
            if v is None:
                continue
            add_row(app, lib, v, rng.choice(["direct", "direct", "transitive"]), "", 1)
            count += 1

    # =================================================================================
    # DERIVE the ground truth by OBSERVING the world we just built
    # =================================================================================
    app_by_id = {a["app_id"]: a for a in APPLICATIONS}
    labels = []

    for row in dep_rows:
        app = app_by_id[row["app_id"]]
        lib, ver = row["library_name"], row["version"]
        lic = LICENSE_BY_ID[row["license"]]

        matched = cves_for(lib, ver)
        # The trap: version matches the published range, but THIS build is patched.
        effective = [] if row["patched_in_build"] else matched

        is_transitive = row["dependency_type"] == "transitive"
        age_days = (TODAY - date.fromisoformat(row["last_updated"])).days
        unmaintained = age_days > UNMAINTAINED_DAYS

        # ---- License violation: nuanced, context-dependent ----
        violation, reason = False, ""
        if row["license"] == "UNKNOWN":
            violation = True
            reason = ("No license is declared. Under copyright law that grants NO rights at all — "
                      "the library may not lawfully be used, redistributed or modified.")
        elif lic["copyleft"] == "viral-network":
            if app["proprietary"]:
                violation = True
                reason = ("AGPL-3.0 is network copyleft: merely SERVING this proprietary application "
                          "to users triggers the obligation to publish the complete source of the "
                          "combined work.")
        elif lic["copyleft"] == "viral":
            if app["proprietary"] and app["distributed"]:
                violation = True
                reason = (f"{row['license']} is viral copyleft, and this application is proprietary "
                          f"AND distributed. Linking it compels disclosure of the entire work.")
            else:
                reason = (f"{row['license']} is present, but this application is not distributed "
                          f"externally, so copyleft is never triggered. Accepted risk — document it.")
        elif lic["copyleft"] == "library":
            if row["linkage"] == "static" or row["modified_by_us"]:
                violation = True
                trigger = "statically linked" if row["linkage"] == "static" else "modified"
                reason = (f"{row['license']} permits dynamic linking from proprietary code, but this "
                          f"dependency is {trigger} — which triggers the copyleft obligation.")
            else:
                reason = f"{row['license']} dynamically linked and unmodified — fully compliant."
        elif lic["copyleft"] == "file":
            if row["modified_by_us"]:
                violation = True
                reason = (f"{row['license']} carries file-level copyleft: because we modified its "
                          f"files, those files must be released under the same license.")

        # ---- Primary risk type, by precedence ----
        if effective:
            worst = max(effective, key=lambda c: c["cvss_score"])
            risk_type = "transitive_vulnerability" if is_transitive else "vulnerable_dependency"
            severity = worst["severity"]
            status = "AT_RISK"
            cve_ids = sorted(c["cve_id"] for c in effective)
            expl = (f"{lib}@{ver} is affected by {len(effective)} known vulnerability(ies); the worst "
                    f"is {worst['cve_id']} (CVSS {worst['cvss_score']}, {worst['severity']}). ")
            if is_transitive:
                expl += (f"It is reached TRANSITIVELY via {row['parent_library']}, so it is invisible "
                         f"to any review of direct dependencies. ")
            expl += ("A patch is available." if worst["patch_available"]
                     else "NO upstream patch exists — this library must be REPLACED, not upgraded.")
        elif violation:
            risk_type = "license_conflict"
            severity = lic["risk_level"]
            status = "AT_RISK"
            cve_ids = []
            expl = reason
        elif unmaintained:
            risk_type = "unmaintained"
            severity = "MEDIUM" if row["maintainer_count"] <= 1 else "LOW"
            status = "AT_RISK"
            cve_ids = []
            expl = (f"{lib} has had no release in {age_days} days (~{age_days // 365} years) and has "
                    f"{row['maintainer_count']} maintainer(s). There is no known CVE today, but there "
                    f"is no process to fix one tomorrow. This is bus-factor risk.")
        else:
            risk_type = "none"
            severity = "NONE"
            status = "CLEAN"
            cve_ids = []
            if matched and row["patched_in_build"]:
                ids = ",".join(sorted(c["cve_id"] for c in matched))
                expl = (f"{lib}@{ver} falls inside the published affected range for {ids}, BUT this "
                        f"build carries a backported fix. A naive version-matching scanner raises a "
                        f"FALSE POSITIVE here; it is not vulnerable.")
            elif violation is False and reason:
                expl = reason          # e.g. GPL in an internal tool: explicitly not a violation
            else:
                expl = "No known vulnerabilities, compatible license, actively maintained."

        labels.append({
            "dependency_id": row["dependency_id"],
            "app_id": row["app_id"],
            "library_name": lib,
            "version": ver,
            "risk_status": status,                    # AT_RISK | CLEAN
            "risk_type": risk_type,
            "severity": severity,
            "cve_ids": ";".join(cve_ids),
            "is_false_positive_trap": row["patched_in_build"] and bool(matched),
            "explanation": expl,
        })

    return {
        "applications": APPLICATIONS,
        "dependencies": dep_rows,
        "vulnerabilities": cves,
        "license_rules": LICENSE_RULES,
        "labels": labels,
    }


# =====================================================================================
# Emit
# =====================================================================================
def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ds = build_dataset()

    (OUT_DIR / "applications.json").write_text(
        json.dumps(ds["applications"], indent=2), encoding="utf-8")
    (OUT_DIR / "vulnerability_db.json").write_text(
        json.dumps(ds["vulnerabilities"], indent=2), encoding="utf-8")
    (OUT_DIR / "license_rules.json").write_text(
        json.dumps(ds["license_rules"], indent=2), encoding="utf-8")

    with (OUT_DIR / "sbom_dependencies.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(ds["dependencies"][0].keys()))
        w.writeheader()
        w.writerows(ds["dependencies"])

    with (OUT_DIR / "dependency_labels.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(ds["labels"][0].keys()))
        w.writeheader()
        w.writerows(ds["labels"])

    dist = defaultdict(int)
    for l in ds["labels"]:
        dist[l["risk_type"]] += 1
    total = len(ds["labels"])

    print(f"Wrote dataset to {OUT_DIR}\n")
    print(f"  applications.json      {len(ds['applications']):>4} records")
    print(f"  sbom_dependencies.csv  {len(ds['dependencies']):>4} records")
    print(f"  vulnerability_db.json  {len(ds['vulnerabilities']):>4} records")
    print(f"  license_rules.json     {len(ds['license_rules']):>4} records")
    print(f"  dependency_labels.csv  {len(ds['labels']):>4} records\n")

    targets = {
        "vulnerable_dependency": 18, "license_conflict": 12, "unmaintained": 15,
        "transitive_vulnerability": 10, "none": 45,
    }
    print("Achieved risk distribution vs the specification's target:")
    for k, t in targets.items():
        pct = 100.0 * dist[k] / total
        flag = "ok " if abs(pct - t) <= 3.5 else "OFF"
        print(f"  {k:<28} {dist[k]:>4}  {pct:5.1f}%   [target {t}%]  {flag}")

    traps = sum(1 for l in ds["labels"] if l["is_false_positive_trap"])
    print(f"\n  false-positive traps planted: {traps} "
          f"(inside a published CVE range, but the build carries a backported fix)")
    log4j = sum(1 for r in ds["dependencies"]
                if r["library_name"] == "org.apache.logging.log4j:log4j-core")
    print(f"  Log4Shell blast radius:      {log4j} applications (depth-3 transitive chain)")
    per_app = defaultdict(int)
    for r in ds["dependencies"]:
        per_app[r["app_id"]] += 1
    bad = {k: v for k, v in per_app.items() if v != DEPS_PER_APP}
    print(f"  deps per app all == {DEPS_PER_APP}: {'YES' if not bad else 'NO ' + str(bad)}")


if __name__ == "__main__":
    main()
