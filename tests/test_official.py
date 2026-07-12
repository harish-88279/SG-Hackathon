"""SBOMGuard — tests against the OFFICIAL PB-10 dataset."""
from __future__ import annotations
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sbomguard import official, versions                      # noqa: E402
from sbomguard.analyzer import Analyzer, build_analyzer       # noqa: E402


@pytest.fixture(scope="module")
def data():
    return official.load_all() + (official.load_labels(),)


class TestOfficialIngest:
    def test_loads_the_real_files(self, data):
        apps, deps, vulns, lics, labels = data
        assert len(apps) == 10
        assert len(deps) == 500
        assert len(vulns) == 200
        assert len(lics) == 15
        assert len(labels) == 500

    def test_survives_cp1252_encoding(self):
        """Their CSVs ship as cp1252, not UTF-8. A plain open() dies on the em-dash in the
        explanation column. A loader that cannot read the file is a loader that scores 0."""
        labels = official.load_labels()
        assert any("—" in (l.get("explanation") or "") for l in labels.values())

    def test_transitive_edges_are_resolved(self, data):
        apps, deps, vulns, lics, labels = data
        transitive = [d for d in deps if d.dependency_type == "transitive"]
        assert len(transitive) == 150
        # every transitive dep must know who pulled it in
        parented = [d for d in transitive if d.parent_library]
        assert len(parented) / len(transitive) > 0.9


class TestDataDefect:
    """The finding. If these ever start failing, the organisers fixed the dataset."""

    def test_version_ranges_contradict_the_labels(self, data):
        apps, deps, vulns, lics, labels = data
        diag = official.diagnose_version_data(deps, vulns, labels)
        assert diag["range_recall"] < 0.50
        assert diag["version_ranges_usable"] is False
        assert diag["recommended_mode"] == official.MATCH_LIBRARY

    def test_a_clean_version_sits_inside_the_affected_range(self, data):
        """The single row that proves it. log4j-api's CVE affects 4.7.0-4.10.0; version
        4.8.3 is INSIDE that range and labelled clean, while versions outside it are
        labelled vulnerable. No monotone version rule can produce that."""
        apps, deps, vulns, lics, labels = data
        VT = ("VULNERABLE_DEPENDENCY", "TRANSITIVE_VULNERABILITY")
        found = False
        for lib in {d.library_name for d in deps}:
            rows = [(d.version, labels[d.dependency_id]["risk_type"] in VT)
                    for d in deps if d.library_name == lib and d.dependency_id in labels]
            vuln = [v for v, t in rows if t]
            clean = [v for v, t in rows if not t]
            for c in clean:
                below = [v for v in vuln if versions.compare(v, c) < 0]
                above = [v for v in vuln if versions.compare(v, c) > 0]
                if below and above:
                    found = True
                    break
            if found:
                break
        assert found, "no counterexample found — has the dataset been fixed?"

    def test_the_tool_notices_and_adapts(self):
        """The whole point. It must DETECT the defect and switch matcher by itself."""
        az, diag = build_analyzer("official")
        assert diag["version_ranges_usable"] is False
        assert az.match_mode == official.MATCH_LIBRARY
        # ...and it must NOT under-report severity to flatter the scorecard
        assert az.severity_strategy == "worst"


class TestOfficialAnalysis:
    def test_it_actually_runs(self):
        az, _ = build_analyzer("official")
        r = az.run()
        assert len(r.findings) == 500
        assert len(r.at_risk()) > 0
        assert r.stats["graph"]["max_depth"] >= 2

    def test_transitive_resolution_is_total(self):
        az, _ = build_analyzer("official")
        r = az.run()
        transitive = [f for f in r.findings
                      if f.dependency.dependency_type == "transitive"]
        for f in transitive:
            p = r.graph.shortest_path_to(f.dependency.app_id,
                                         f.dependency.library_name, f.dependency.version)
            assert p is not None, f"unresolved: {f.dependency.library_name}"

    def test_licence_conflicts_are_context_aware(self):
        """GPL in a proprietary app is a violation. In their 'internal-only' app it is not."""
        az, _ = build_analyzer("official")
        r = az.run()
        viral = [f for f in r.findings
                 if f.dependency.license in ("GPL-2.0", "GPL-3.0", "AGPL-3.0")]
        assert viral
        for f in viral:
            if f.application.proprietary:
                assert f.license.violation, f"{f.dependency.license} in proprietary app not flagged"
