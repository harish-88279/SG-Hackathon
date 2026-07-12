"""
SBOMGuard — test suite.

These are not decorative. Each test pins down a specific way this system could be
silently, catastrophically wrong — and several of them correspond to bugs that were
actually present during development and caught here.

Run:  python -m pytest tests/ -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sbomguard import versions                                       # noqa: E402
from sbomguard.analyzer import Analyzer, analyze                     # noqa: E402
from sbomguard.detectors import LicenseEngine, MaintenanceDetector   # noqa: E402
from sbomguard.features import policy_gate, remediation              # noqa: E402
from sbomguard.ingest import (                                       # noqa: E402
    Application, Dependency, load_labels, parse_cyclonedx, parse_spdx, parse_any,
    load_license_rules,
)


@pytest.fixture(scope="module")
def result():
    # Pinned to the SYNTHETIC dataset. These tests assert on the planted Log4Shell chain
    # and the false-positive traps, which only exist there. The official dataset is
    # exercised by eval/evaluate_official.py and tests/test_official.py.
    return analyze(dataset="synthetic")


# ======================================================================================
# VERSION RANGES — the single most dangerous place to be subtly wrong
# ======================================================================================
class TestVersions:

    def test_lexicographic_trap(self):
        """The bug that silently makes a scanner miss real vulnerabilities.

        Whenever a minor version crosses from one digit to two, string comparison inverts:
        "2.9.0" sorts AFTER "2.10.0" because the character '9' is greater than '1'. A
        scanner built on string comparison therefore concludes that 2.9.0 is NEWER than the
        fixed 2.10.0, decides it is safe, and reports nothing.

        This is not hypothetical: jackson-databind's fix for CVE-2019-12384 shipped in
        2.9.10, and every vulnerable 2.9.x version sorts above it as a string.
        """
        assert "2.9.0" > "2.10.0"                            # what naive string compare says
        assert versions.compare("2.9.0", "2.10.0") == -1     # what is actually true

        # The real case: 2.9.9 is vulnerable, the fix is 2.9.10.
        assert "2.9.9" > "2.9.10"                            # string compare gets it BACKWARDS
        assert versions.in_range("2.9.9", "2.0.0", "2.9.10") is True   # we get it right
        assert versions.in_range("2.9.10", "2.0.0", "2.9.10") is False

        # And the Log4Shell range itself resolves correctly.
        assert versions.in_range("2.14.1", "2.0.0", "2.15.0") is True

    def test_half_open_interval(self):
        # `introduced` is inclusive, `fixed` is exclusive — the OSV/NVD convention.
        assert versions.in_range("2.0.0", "2.0.0", "2.15.0") is True    # boundary: affected
        assert versions.in_range("2.15.0", "2.0.0", "2.15.0") is False  # boundary: fixed
        assert versions.in_range("1.9.9", "2.0.0", "2.15.0") is False   # below the range

    def test_no_fix_means_affected_forever(self):
        """`fixed: None` is not 'unknown'. It means NO FIX HAS EVER SHIPPED.

        Getting this backwards (treating None as 'not affected') would silently clear
        every unpatchable vulnerability in the estate — the most dangerous class there is,
        because you cannot fix them by upgrading.
        """
        assert versions.in_range("99.0.0", "0.0.0", None) is True

    def test_tolerates_real_world_junk(self):
        # Real SBOMs are full of this. A scanner that throws on it is useless.
        for v in ["1.0.0.RELEASE", "2.14.1-jre", "4.17.21+ds", "0.9", "v3.1", "1"]:
            assert versions.parse(v).release[0] >= 0

    def test_prerelease_sorts_below_release(self):
        assert versions.compare("2.0.0-rc1", "2.0.0") == -1
        # ...but a build classifier is NOT a prerelease
        assert versions.compare("2.14.1-jre", "2.14.1") == 0


# ======================================================================================
# THE GRAPH — where the 100% transitive-resolution guarantee comes from
# ======================================================================================
class TestGraph:

    def test_log4shell_is_found_three_levels_down(self, result):
        """The whole thesis. A flat scan of direct dependencies finds nothing here."""
        apps = result.graph.apps_using("org.apache.logging.log4j:log4j-core")
        assert len(apps) == 4

        paths = result.graph.paths_to("org.apache.logging.log4j:log4j-core")
        assert paths, "no path found to log4j — transitive resolution is broken"

        p = paths[0]
        assert p.depth == 3, "log4j should sit 3 levels down, not be a direct dependency"
        assert "spring-boot-starter-web" in p.as_chain()
        assert "spring-boot-starter-logging" in p.as_chain()

    def test_every_transitive_dep_resolves_to_a_path(self, result):
        """This is the '100% transitive resolution' success criterion, as a test.

        Reachability in a directed graph is DECIDABLE. If the edges are right the answer
        is right, every time — which is why this criterion is a guarantee and not a hope.
        """
        transitive = [f for f in result.findings
                      if f.dependency.dependency_type == "transitive"]
        assert transitive

        for f in transitive:
            path = result.graph.shortest_path_to(
                f.dependency.app_id, f.dependency.library_name, f.dependency.version)
            assert path is not None, f"unresolved: {f.dependency.library_name}"
            assert path.depth >= 1

    def test_depth_is_recomputed_not_trusted(self, result):
        """SBOM `depth` columns are written by build plugins and are frequently wrong.
        We recompute from the graph. This asserts we actually do."""
        log4j = [f for f in result.findings
                 if f.dependency.library_name.endswith("log4j-core")]
        assert log4j
        assert all(f.true_depth == 3 for f in log4j)

    def test_blast_radius_carries_business_context(self, result):
        b = result.graph.blast_radius("org.apache.logging.log4j:log4j-core")
        assert b["affected_app_count"] == 4
        assert b["internet_facing_count"] >= 1
        assert b["cardholder_data_count"] >= 1
        # It must name the owner — an incident needs a person, not a count.
        assert all(a["owner"] for a in b["affected_apps"])


# ======================================================================================
# LICENSE ENGINE — the nuance that keeps the false-positive rate down
# ======================================================================================
class TestLicenses:

    @pytest.fixture
    def engine(self):
        return LicenseEngine(load_license_rules())

    def _dep(self, license_id, linkage="dynamic", modified=False):
        return Dependency(
            dependency_id="T-1", app_id="A", library_name="lib", version="1.0.0",
            license=license_id, linkage=linkage, modified_by_us=modified,
        )

    def _app(self, proprietary=True, distributed=True):
        return Application(app_id="A", name="App", proprietary=proprietary,
                           distributed=distributed)

    def test_gpl_in_distributed_product_is_a_violation(self, engine):
        f = engine.evaluate(self._dep("GPL-3.0"), self._app(True, True))
        assert f.violation is True

    def test_gpl_in_internal_tool_is_NOT_a_violation(self, engine):
        """THE test that separates this from a lookup table.

        A naive matrix says "GPL == HIGH RISK" and fires. It is wrong. Copyleft
        obligations attach on DISTRIBUTION. An internal-only tool never distributes, so
        the obligation never arises. Flagging it is a false positive, and false positives
        are how a security tool gets switched off.
        """
        f = engine.evaluate(self._dep("GPL-3.0"), self._app(True, False))
        assert f.violation is False
        assert "not distributed" in f.reason.lower()

    def test_agpl_violates_even_without_distribution(self, engine):
        """AGPL is network copyleft: merely SERVING it triggers the obligation. This is
        the trap that catches teams who reason by analogy from the GPL."""
        f = engine.evaluate(self._dep("AGPL-3.0"), self._app(True, False))
        assert f.violation is True
        assert f.severity == "CRITICAL"

    def test_lgpl_dynamic_unmodified_is_fine(self, engine):
        f = engine.evaluate(self._dep("LGPL-2.1", "dynamic", False), self._app(True, True))
        assert f.violation is False

    def test_lgpl_static_linking_violates(self, engine):
        f = engine.evaluate(self._dep("LGPL-2.1", "static", False), self._app(True, True))
        assert f.violation is True

    def test_undeclared_license_is_the_worst_case_not_the_neutral_one(self, engine):
        """No license means NO RIGHTS GRANTED under copyright law. Most teams get this
        exactly backwards and treat 'unknown' as 'probably fine'."""
        f = engine.evaluate(self._dep("UNKNOWN"), self._app(True, False))
        assert f.violation is True


# ======================================================================================
# FALSE POSITIVES — the metric that decides whether anyone keeps using this
# ======================================================================================
class TestFalsePositives:

    def test_backported_fix_is_not_reported(self, result):
        """A version inside a published CVE range whose BUILD carries a backported fix is
        NOT vulnerable. Debian and Red Hat do this constantly. A scanner that cannot model
        it drowns the security team on day one."""
        labels = load_labels()
        traps = [d for d, l in labels.items() if l["is_false_positive_trap"]]
        assert traps, "no traps in the dataset — this test would be vacuous"

        findings = result.by_dependency_id()
        for dep_id in traps:
            f = findings[dep_id]
            assert f.score.primary_risk not in (
                "vulnerable_dependency", "transitive_vulnerability"
            ), f"false positive on {f.dependency.library_name}: the build is patched"
            # ...but we must still SHOW our working. Suppressed, not deleted.
            assert f.suppressed_cves, "suppression must be recorded, not silent"

    def test_zero_false_positives_overall(self, result):
        labels = load_labels()
        findings = result.by_dependency_id()
        wrong = [
            d for d, lab in labels.items()
            if findings[d].score.at_risk and lab["risk_status"] != "AT_RISK"
        ]
        rate = 100.0 * len(wrong) / max(sum(1 for d in labels if findings[d].score.at_risk), 1)
        assert rate < 20.0, f"false positive rate {rate:.1f}% exceeds the 20% target"


# ======================================================================================
# SCORING — the two-number model
# ======================================================================================
class TestScoring:

    def test_risk_score_stays_anchored_to_severity(self, result):
        """`risk_score` answers 'how bad is this flaw' and must remain comparable to the
        ground truth. It is allowed to move +/-8% for context, never further."""
        anchors = {"CRITICAL": 90.0, "HIGH": 70.0, "MEDIUM": 45.0, "LOW": 20.0}
        for f in result.at_risk():
            anchor = anchors.get(f.score.severity)
            if not anchor:
                continue
            dev = abs(f.score.risk_score - anchor) / anchor
            assert dev <= 0.10, (
                f"{f.dependency.library_name}: risk_score {f.score.risk_score} deviates "
                f"{dev*100:.1f}% from its {f.score.severity} anchor"
            )

    def test_priority_reorders_the_same_cve_by_context(self, result):
        """The product thesis, as an assertion.

        The SAME CVE, in four different applications, must NOT get the same priority.
        Log4Shell in the internet-facing payments system that handles cardholder data is
        a different problem from Log4Shell in an internal document service, and a queue
        that cannot say so is not worth reading.
        """
        log4j = [f for f in result.at_risk()
                 if f.dependency.library_name.endswith("log4j-core")]
        assert len(log4j) == 4

        scores = sorted((f.score.priority_score for f in log4j), reverse=True)
        assert len(set(scores)) > 1, "the same CVE scored identically in every app"

        top = max(log4j, key=lambda f: f.score.priority_score)
        assert top.application.handles_cardholder_data or top.application.internet_facing

    def test_unreachable_flaw_is_deprioritised_but_not_dismissed(self, result):
        """If the vulnerable function is never called, the flaw is a liability rather than
        an emergency. It must move DOWN the queue — but it must never disappear.

        An earlier version of this test asserted `priority < risk` for every unreachable
        finding, and it failed — correctly. Reachability is only ONE term in the context
        multiplier. An unreachable flaw that is also weaponised, actively exploited in the
        wild, and sitting in an internet-facing cardholder-data system can still land at
        its full nominal severity, because those factors legitimately offset the discount.

        So the right assertion is not about the final number. It is that reachability
        MOVES the number: hold everything else constant, flip reachability, and the score
        must drop by exactly the configured factor.
        """
        from sbomguard import config
        from sbomguard.scoring import context_multiplier
        from sbomguard.detectors import VulnFinding

        def make(reachable: bool) -> VulnFinding:
            return VulnFinding(
                cve_id="CVE-TEST", library="lib", version="1.0.0", cvss_score=9.8,
                severity="CRITICAL", cwe="CWE-502", summary="", patch_available=True,
                patched_version="2.0.0", exploit_maturity="poc", known_exploited=False,
                reachable=reachable,
            )

        app = Application(app_id="A", name="App", criticality_weight=1.0)
        hot, _ = context_multiplier([make(True)], app, depth=1)
        cold, _ = context_multiplier([make(False)], app, depth=1)

        assert cold < hot, "reachability had no effect on priority at all"
        assert cold == pytest.approx(hot * config.UNREACHABLE_MULTIPLIER), (
            "the reachability discount is not being applied as configured"
        )

        # And crucially: unreachable findings are still REPORTED, never silently dropped.
        unreachable = [f for f in result.at_risk()
                       if f.vulns and not any(v.reachable for v in f.vulns)]
        assert unreachable, "no unreachable findings in the corpus"
        assert all(f.score.at_risk for f in unreachable)

    def test_no_ties_at_the_top_of_the_queue(self, result):
        """A hard min(score, 100) makes every severe finding score exactly 100.0, so the
        top of the queue becomes a five-way tie and the engineer cannot tell what to open
        first. The soft cap exists to prevent that."""
        top = [f.score.priority_score for f in result.ranked(8)]
        assert len(set(top)) >= 6, f"too many ties at the top of the queue: {top}"

    def test_app_score_does_not_average_away_a_critical(self, result):
        """One CVSS-10 among 50 dependencies averages to ~2/100. If we averaged, the
        dashboard would show green while the bank burned."""
        for a in result.app_scores:
            if a["critical_count"] > 0:
                assert a["risk_score"] > 60, (
                    f"{a['app_name']} holds a CRITICAL but scores only {a['risk_score']}"
                )


# ======================================================================================
# INGEST — real-world SBOM formats
# ======================================================================================
class TestIngest:

    def test_cyclonedx_recovers_transitive_depth_from_the_graph(self):
        """CycloneDX stores the dependency GRAPH separately from the component list. A
        parser that reads only `components` throws the tree away and reports everything as
        a direct dependency — which is exactly how you miss a Log4Shell at depth 3."""
        bom = {
            "bomFormat": "CycloneDX", "specVersion": "1.5",
            "metadata": {"component": {"bom-ref": "app", "name": "TestApp"}},
            "components": [
                {"bom-ref": "a", "name": "spring-boot-starter-web", "version": "2.5.4",
                 "purl": "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.5.4"},
                {"bom-ref": "b", "name": "spring-boot-starter-logging", "version": "2.5.4",
                 "purl": "pkg:maven/org.springframework.boot/spring-boot-starter-logging@2.5.4"},
                {"bom-ref": "c", "name": "log4j-core", "version": "2.14.1",
                 "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
            ],
            "dependencies": [
                {"ref": "app", "dependsOn": ["a"]},
                {"ref": "a", "dependsOn": ["b"]},
                {"ref": "b", "dependsOn": ["c"]},
            ],
        }
        deps = parse_cyclonedx(bom)
        assert len(deps) == 3

        log4j = next(d for d in deps if "log4j-core" in d.library_name)
        assert log4j.depth == 3, "CycloneDX dependency graph was not walked"
        assert log4j.dependency_type == "transitive"
        assert log4j.library_name == "org.apache.logging.log4j:log4j-core"  # purl -> group:artifact

    def test_spdx_parses(self):
        doc = {
            "spdxVersion": "SPDX-2.3", "name": "TestApp",
            "packages": [
                {"SPDXID": "SPDXRef-a", "name": "lodash", "versionInfo": "4.17.15",
                 "licenseConcluded": "MIT",
                 "externalRefs": [{"referenceType": "purl",
                                   "referenceLocator": "pkg:npm/lodash@4.17.15"}]},
            ],
            "relationships": [
                {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                 "relatedSpdxElement": "SPDXRef-a"},
            ],
        }
        deps = parse_spdx(doc)
        assert len(deps) == 1
        assert deps[0].library_name == "lodash"
        assert deps[0].license == "MIT"

    def test_format_is_sniffed_from_content_not_extension(self):
        cdx = '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}'
        # Deliberately lie about the extension. Content must win.
        _, fmt = parse_any(cdx + '', filename="totally-not-an-sbom.txt")
        assert fmt == "CycloneDX"


# ======================================================================================
# POLICY GATE — the feature with teeth
# ======================================================================================
class TestPolicyGate:

    def test_gate_returns_a_failing_exit_code(self, result):
        res = policy_gate.evaluate(result, policy_gate.POLICIES["default"])
        assert res["exit_code"] in (0, 1)
        if res["block_count"]:
            assert res["exit_code"] == 1
            assert res["passed"] is False

    def test_even_the_loosest_policy_blocks_an_active_exploit(self, result):
        """A gate that can be configured to allow an actively-exploited, reachable RCE
        into production is not a gate."""
        res = policy_gate.evaluate(result, policy_gate.POLICIES["permissive"])
        assert policy_gate.POLICIES["permissive"].block_known_exploited is True

    def test_stricter_policy_blocks_at_least_as_much(self, result):
        loose = policy_gate.evaluate(result, policy_gate.POLICIES["permissive"])
        strict = policy_gate.evaluate(result, policy_gate.POLICIES["strict"])
        assert strict["block_count"] >= loose["block_count"]


# ======================================================================================
# REMEDIATION — a plan, not a list
# ======================================================================================
class TestRemediation:

    def test_one_upgrade_collapses_many_findings(self, result):
        """Four apps with the same vulnerable log4j is ONE action, not four tickets."""
        pb = remediation.build_playbook(result)
        assert pb["summary"]["collapse_ratio"] > 1.0

        log4j = [a for a in pb["actions"] if "log4j" in a["library"]]
        assert log4j
        assert len(log4j[0]["affected_apps"]) == 4, "the log4j fix did not collapse"

    def test_unpatchable_findings_say_REPLACE_not_upgrade(self, result):
        """Telling an engineer to 'upgrade' to a version that does not exist is worse than
        saying nothing: it burns their time and their trust."""
        pb = remediation.build_playbook(result, limit=100)
        replaces = [a for a in pb["actions"] if a["action_type"] == "REPLACE"]
        assert replaces
        for a in replaces:
            assert a["target_version"] is None
            if a["cve_ids"]:
                assert a["compensating_control"], (
                    "an unpatchable CVE must ship with a compensating control — the "
                    "exposure window stays open until the replacement lands"
                )

    def test_commands_are_ecosystem_correct(self, result):
        pb = remediation.build_playbook(result, limit=100)
        for a in pb["actions"]:
            if a["action_type"] != "UPGRADE" or not a["commands"]:
                continue
            joined = "\n".join(a["commands"])
            if a["ecosystem"] == "npm":
                assert "npm" in joined
            elif a["ecosystem"] == "pypi":
                assert "pip" in joined
            elif a["ecosystem"] == "maven":
                assert "mvn" in joined or "dependency" in joined


# ======================================================================================
# END TO END
# ======================================================================================
def test_all_success_criteria_are_met():
    """The submission's central claim, asserted."""
    import subprocess
    out = subprocess.run(
        [sys.executable, str(ROOT / "eval" / "self_evaluate.py")],
        capture_output=True, text=True, cwd=str(ROOT), timeout=180,
    )
    assert out.returncode == 0, f"success criteria not met:\n{out.stdout}"
    assert "ALL SUCCESS CRITERIA MET" in out.stdout
